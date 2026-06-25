from __future__ import annotations
import re
import json
import base64
from pathlib import Path
from typing import Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from backend.config import get_settings
from backend.models import PRInfo, PRFile, DiffHunk, Language

settings = get_settings()

DEPENDENCY_FILES = {
    "requirements.txt", "requirements-dev.txt", "requirements-prod.txt",
    "Pipfile", "Pipfile.lock", "pyproject.toml", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock",
    "go.mod", "go.sum", "pom.xml", "build.gradle",
    "Gemfile", "Gemfile.lock", "Cargo.toml", "Cargo.lock",
}

LANGUAGE_MAP: dict[str, Language] = {
    ".py":  Language.PYTHON,
    ".js":  Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".ts":  Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".go":  Language.GO,
    ".java": Language.JAVA,
}


def _headers() -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if settings.github_token:
        h["Authorization"] = f"Bearer {settings.github_token}"
    return h


def detect_language(filename: str) -> Language:
    return LANGUAGE_MAP.get(Path(filename).suffix.lower(), Language.UNKNOWN)


class GitHubClient:
    def __init__(self):
        self._client = httpx.AsyncClient(
            base_url=settings.github_api_base,
            headers=_headers(),
            timeout=settings.github_request_timeout,
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self._client.aclose()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10), reraise=True)
    async def _get(self, path: str, params: dict | None = None) -> dict | list:
        resp = await self._client.get(path, params=params)
        resp.raise_for_status()
        return resp.json()

    async def _paginate(self, path: str) -> list[dict]:
        results, page = [], 1
        while True:
            page_data = await self._get(path, params={"per_page": 100, "page": page})
            if not page_data:
                break
            results.extend(page_data)
            if len(page_data) < 100:
                break
            page += 1
        return results

    async def _file_content(self, owner: str, repo: str, path: str, ref: str) -> str:
        data = await self._get(f"/repos/{owner}/{repo}/contents/{path}", params={"ref": ref})
        if isinstance(data, dict) and data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return ""

    async def get_pr(self, owner: str, repo: str, number: int) -> PRInfo:
        pr_data = await self._get(f"/repos/{owner}/{repo}/pulls/{number}")
        files_data = await self._paginate(f"/repos/{owner}/{repo}/pulls/{number}/files")
        head_sha = pr_data["head"]["sha"]

        pr_files: list[PRFile] = []
        dep_filenames: list[str] = []

        for f in files_data:
            fname = f["filename"]
            pr_files.append(PRFile(
                filename=fname,
                status=f["status"],
                additions=f.get("additions", 0),
                deletions=f.get("deletions", 0),
                patch=f.get("patch"),
                language=detect_language(fname),
            ))
            if Path(fname).name in DEPENDENCY_FILES:
                dep_filenames.append(fname)

        # Fetch raw content of each dependency manifest at head commit
        raw_content: dict[str, str] = {}
        for dep_file in dep_filenames:
            try:
                raw_content[dep_file] = await self._file_content(owner, repo, dep_file, head_sha)
            except Exception:
                pass

        return PRInfo(
            owner=owner,
            repo=repo,
            number=number,
            title=pr_data["title"],
            author=pr_data["user"]["login"],
            base_branch=pr_data["base"]["ref"],
            head_branch=pr_data["head"]["ref"],
            files=pr_files,
            dependency_files=dep_filenames,
            raw_dependencies=parse_all_dependencies(raw_content),
        )

    async def get_file_at_ref(self, owner: str, repo: str, path: str, ref: str) -> Optional[str]:
        try:
            return await self._file_content(owner, repo, path, ref)
        except Exception:
            return None


def parse_diff_hunks(pr_files: list[PRFile]) -> list[DiffHunk]:
    hunks: list[DiffHunk] = []
    for f in pr_files:
        if f.patch:
            hunks.extend(_parse_patch(f.filename, f.patch))
    return hunks


def _parse_patch(filename: str, patch: str) -> list[DiffHunk]:
    """Parse a unified diff patch into structured hunk objects"""
    hunks: list[DiffHunk] = []
    current: Optional[DiffHunk] = None

    for line in patch.splitlines():
        if line.startswith("@@"):
            if current:
                hunks.append(current)
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if m:
                start = int(m.group(1))
                length = int(m.group(2) or 1)
                current = DiffHunk(
                    filename=filename,
                    start_line=start,
                    end_line=start + length - 1,
                )
        elif current:
            if line.startswith("+") and not line.startswith("+++"):
                current.added_lines.append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                current.removed_lines.append(line[1:])

    if current:
        hunks.append(current)
    return hunks


def parse_all_dependencies(raw_files: dict[str, str]) -> dict[str, str]:
    """Merge dependency versions from all manifest files into one flat dict"""
    deps: dict[str, str] = {}
    for filename, content in raw_files.items():
        name = Path(filename).name
        if name in {"requirements.txt", "requirements-dev.txt", "requirements-prod.txt"}:
            deps.update(_parse_requirements_txt(content))
        elif name == "package.json":
            deps.update(_parse_package_json(content))
        elif name == "Pipfile":
            deps.update(_parse_pipfile(content))
        elif name == "go.mod":
            deps.update(_parse_go_mod(content))
    return deps


def _parse_requirements_txt(content: str) -> dict[str, str]:
    deps = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = re.sub(r"\[.*?\]", "", line)  # strip extras like requests[security]
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([=<>!~]+\s*[\d\.\*]+)?", line)
        if m:
            pkg = m.group(1).lower()
            ver_spec = m.group(2) or ""
            ver_m = re.search(r"[\d\.]+", ver_spec)
            deps[pkg] = ver_m.group(0) if ver_m else "unknown"
    return deps


def _parse_package_json(content: str) -> dict[str, str]:
    deps = {}
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for pkg, ver in data.get(section, {}).items():
                deps[pkg.lower()] = re.sub(r"^[\^~>=<]", "", ver).strip()
    except json.JSONDecodeError:
        pass
    return deps


def _parse_pipfile(content: str) -> dict[str, str]:
    deps = {}
    in_packages = False
    for line in content.splitlines():
        line = line.strip()
        if line in ("[packages]", "[dev-packages]"):
            in_packages = True
        elif line.startswith("["):
            in_packages = False
        elif in_packages and "=" in line:
            pkg, _, ver = line.partition("=")
            deps[pkg.strip().strip('"').lower()] = ver.strip().strip('"').replace("*", "unknown")
    return deps


def _parse_go_mod(content: str) -> dict[str, str]:
    deps = {}
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
        elif in_require and line == ")":
            in_require = False
        elif in_require or line.startswith("require "):
            m = re.match(r"(?:require\s+)?(\S+)\s+(v[\d\.]+)", line)
            if m:
                pkg = m.group(1).split("/")[-1].lower()
                deps[pkg] = m.group(2).lstrip("v")
    return deps