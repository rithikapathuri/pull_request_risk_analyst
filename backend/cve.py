from __future__ import annotations
import asyncio
from pathlib import Path
from typing import Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from backend.config import get_settings
from backend.models import CVERecord, DependencyRisk, RiskLevel

settings = get_settings()

# throttle NVD API requests to prevent 429 Too Many Requests errors
_NVD_SEMAPHORE = asyncio.Semaphore(5)

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
    best = 0.0
    for entry in vuln.get("severity", []):
        score_str = entry.get("score", "")
        try:
            best = max(best, float(score_str))
        except ValueError:
            pass

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

@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
async def _query_nvd(client: httpx.AsyncClient, cve_id: str) -> Optional[dict]:
    if not settings.nvd_api_key:
        return None
        
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": settings.nvd_api_key}
    
    # Restrict concurrent outgoing calls using the semaphore lock
    async with _NVD_SEMAPHORE:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return vulns[0].get("cve", {})
    return None

def _enrich_from_nvd(cve_record: CVERecord, nvd_data: dict) -> None:
    metrics = nvd_data.get("metrics", {})
    best_score = cve_record.cvss_score
    
    for metric_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(metric_version, [])
        if metric_list:
            data = metric_list[0].get("cvssData", {})
            score = data.get("baseScore")
            if score and score > best_score:
                best_score = score
                cve_record.cvss_score = score
            break
            
    descriptions = nvd_data.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            cve_record.description = desc.get("value", cve_record.description)
            break

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
    cve_ids_to_enrich = []
    for vuln in vulns:
        cvss = _extract_cvss(vuln)
        cve_id = _extract_cve_id(vuln)
        record = CVERecord(
            cve_id=cve_id,
            package=package,
            installed_version=version,
            severity=_cvss_to_level(cvss),
            cvss_score=cvss,
            description=vuln.get("summary", ""),
        )
        cve_records.append(record)
        if cve_id.startswith("CVE-") and settings.nvd_api_key:
            cve_ids_to_enrich.append(record)

    # Concurrently enrich all valid CVEs via the NVD to acquire accurate base scores
    if cve_ids_to_enrich:
        enrich_tasks = [_query_nvd(client, c.cve_id) for c in cve_ids_to_enrich]
        nvd_results = await asyncio.gather(*enrich_tasks, return_exceptions=True)
        for record, nvd_res in zip(cve_ids_to_enrich, nvd_results):
            if isinstance(nvd_res, dict):
                _enrich_from_nvd(record, nvd_res)

    max_cvss = max((c.cvss_score for c in cve_records), default=0.0)
    for c in cve_records:
        c.severity = _cvss_to_level(c.cvss_score)

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

COMMON_PACKAGES = {
    "requests", "numpy", "pandas", "flask", "django", "fastapi",
    "sqlalchemy", "boto3", "pytest", "pydantic", "httpx", "celery",
    "redis", "pillow", "cryptography", "paramiko", "urllib3",
    "express", "lodash", "react", "axios", "webpack", "babel",
}

def _typosquatting_score(package: str) -> float:
    def _edit_distance(a: str, b: str) -> int:
        m, n = len(a), len(b)
        dp = list(range(n + 1))
        for i in range(1, m + 1):
            prev = dp[:]
            dp[0] = i
            for j in range(1, n + 1):
                dp[j] = prev[j - 1] if a[i-1] == b[j-1] else 1 + min(prev[j], dp[j-1], prev[j-1])
        return dp[n]

    best = 0.0
    for known in COMMON_PACKAGES:
        if package == known:
            return 0.0
        longer = max(len(package), len(known))
        if longer == 0:
            continue
        similarity = 1.0 - (_edit_distance(package, known) / longer)
        best = max(best, similarity)
    return best

async def check_new_dependencies(
    new_packages: list[str],
    all_deps: dict[str, str],
    dep_filenames: list[str] | None = None,
) -> list[DependencyRisk]:
    if not new_packages:
        return []

    ecosystem = "PyPI"
    if dep_filenames:
        for fname in dep_filenames:
            eco = ECOSYSTEM_BY_FILE.get(Path(fname).name)
            if eco:
                ecosystem = eco
                break

    results: list[DependencyRisk] = []

    async with httpx.AsyncClient(timeout=15) as client:
        for pkg in new_packages:
            version = all_deps.get(pkg, "unknown")
            dep = await _check_one(client, pkg, version, ecosystem)
            dep.is_new = True

            typo_score = _typosquatting_score(pkg)
            if typo_score > 0.82 and not dep.cves:
                dep.cves.append(CVERecord(
                    cve_id="SUSPICIOUS-TYPOSQUAT",
                    package=pkg,
                    installed_version=version,
                    severity=RiskLevel.HIGH,
                    cvss_score=7.5,
                    description=f"Package name '{pkg}' is highly similar to a well-known package (similarity={typo_score:.2f}). Possible typosquatting.",
                ))
                dep.effective_risk_score = 75.0

            results.append(dep)

    return results