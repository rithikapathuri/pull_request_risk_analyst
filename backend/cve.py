from __future__ import annotations
import asyncio
from pathlib import Path

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from backend.config import get_settings
from backend.models import CVERecord, DependencyRisk, RiskLevel

settings = get_settings()

# OSV ecosystem name per manifest filename
ECOSYSTEM_BY_FILE: dict[str, str] = {
    "requirements.txt":     "PyPI",
    "requirements-dev.txt": "PyPI",
    "requirements-prod.txt":"PyPI",
    "Pipfile":              "PyPI",
    "pyproject.toml":       "PyPI",
    "setup.py":             "PyPI",
    "package.json":         "npm",
    "package-lock.json":    "npm",
    "yarn.lock":            "npm",
    "go.mod":               "Go",
    "Gemfile":              "RubyGems",
    "Cargo.toml":           "crates.io",
    "pom.xml":              "Maven",
}

# Fallback severity mapping when CVSS score is absent
_TEXT_TO_LEVEL: dict[str, RiskLevel] = {
    "CRITICAL": RiskLevel.CRITICAL,
    "HIGH":     RiskLevel.HIGH,
    "MEDIUM":   RiskLevel.MEDIUM,
    "LOW":      RiskLevel.LOW,
}


def _cvss_to_level(score: float) -> RiskLevel:
    if score >= 9.0: return RiskLevel.CRITICAL
    if score >= 7.0: return RiskLevel.HIGH
    if score >= 4.0: return RiskLevel.MEDIUM
    if score > 0:    return RiskLevel.LOW
    return RiskLevel.INFO


def _extract_cvss(vuln: dict) -> float:
    """
    OSV records can carry severity in several different places depending on
    source database -> check all and return highest score found
    """
    best = 0.0

    # OSV severity array entries have a CVSS vector string —> parse base score from it
    for entry in vuln.get("severity", []):
        score_str = entry.get("score", "")
        # CVSS v3 vectors embed the base score as the first numeric segment after "CVSS:3.x/"
        # Some OSV entries use a plain float string instead
        try:
            best = max(best, float(score_str))
        except ValueError:
            pass

    # database_specific blocks vary by source (GitHub, OSV, NVD) —> check common keys
    db = vuln.get("database_specific", {})
    if isinstance(db, dict):
        for k, v in db.items():
            if "cvss" in k.lower() and isinstance(v, (int, float)):
                best = max(best, float(v))
            elif k in ("severity", "cvss_score") and isinstance(v, str):
                level = _TEXT_TO_LEVEL.get(v.upper())
                if level:
                    score_map = {
                        RiskLevel.CRITICAL: 9.5,
                        RiskLevel.HIGH:     8.0,
                        RiskLevel.MEDIUM:   5.5,
                        RiskLevel.LOW:      2.0,
                    }
                    best = max(best, score_map.get(level, 0.0))

    return best


def _extract_cve_id(vuln: dict) -> str:
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "UNKNOWN")


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=8), reraise=True)
async def _query_osv(client: httpx.AsyncClient, package: str, version: str, ecosystem: str) -> list[dict]:
    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem},
    }
    resp = await client.post(f"{settings.osv_api_base}/query", json=payload)
    if resp.status_code == 200:
        return resp.json().get("vulns", [])
    return []


async def _check_one(
    client: httpx.AsyncClient,
    package: str,
    version: str,
    ecosystem: str,
) -> DependencyRisk:
    if version == "unknown":
        return DependencyRisk(package=package, version=version)

    try:
        vulns = await _query_osv(client, package, version, ecosystem)
    except Exception:
        return DependencyRisk(package=package, version=version)

    cve_records: list[CVERecord] = []
    for vuln in vulns:
        cvss = _extract_cvss(vuln)
        cve_records.append(CVERecord(
            cve_id=_extract_cve_id(vuln),
            package=package,
            installed_version=version,
            severity=_cvss_to_level(cvss),
            cvss_score=cvss,
            description=vuln.get("summary", ""),
        ))

    max_cvss = max((c.cvss_score for c in cve_records), default=0.0)

    return DependencyRisk(
        package=package,
        version=version,
        cves=cve_records,
        effective_risk_score=round(min(max_cvss * 10, 100), 2),
    )


async def check_dependencies(
    raw_dependencies: dict[str, str],
    dep_filenames: list[str] | None = None,
) -> list[DependencyRisk]:
    """
    Queries OSV.dev for every dependency in raw_dependencies.
    Runs all queries concurrently -> a PR with 50 deps takes roughly the
    same time as one with 5
    Ecosystem is inferred from the manifest filename if provided,
    defaulting to PyPI when unknown
    """
    # Infer ecosystem from the first recognised manifest filename
    ecosystem = "PyPI"
    if dep_filenames:
        for fname in dep_filenames:
            eco = ECOSYSTEM_BY_FILE.get(Path(fname).name)
            if eco:
                ecosystem = eco
                break

    async with httpx.AsyncClient(timeout=15) as client:
        tasks = [
            _check_one(client, pkg, ver, ecosystem)
            for pkg, ver in raw_dependencies.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    deps: list[DependencyRisk] = []
    for pkg, result in zip(raw_dependencies.keys(), results):
        if isinstance(result, Exception):
            deps.append(DependencyRisk(package=pkg, version=raw_dependencies[pkg]))
        else:
            deps.append(result)

    return deps