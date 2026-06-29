from __future__ import annotations

from backend.config import get_settings
from backend.models import (
    PRInfo, ParseResult, BlastRadius, DependencyRisk,
    RiskBreakdown, RiskLevel, SecuritySignal,
)

settings = get_settings()

SIGNAL_WEIGHTS: dict[str, float] = {
    "eval_usage":            95,
    "exec_usage":            95,
    "hardcoded_secret":      90,
    "hardcoded_token":       90,
    "raw_sql":               80,
    "deserialization":       80,
    "xxe":                   80,
    "path_traversal":        75,
    "ssrf":                  75,
    "subprocess":            70,
    "os_system":             70,
    "weak_hash":             65,
    "compile_usage":         65,
    "template_injection":    65,
    "weak_cipher":           60,
    "insecure_cookie":       55,
    "open_redirect":         50,
    "weak_random":           50,
    "crypto_modified":       30,
    "auth_modified":         30,
    "globals_usage":         25,
    "auth_check_removed":    95,
    "security_control_removed": 75,
    "iac_privileged_container": 80,
    "iac_root_user":         80,
    "iac_secret_in_env":     95,
    "iac_dangerous_workflow": 85,
    "iac_exposed_port":      45,
}

SENSITIVE_PATH_KEYWORDS = {
    "auth", "login", "logout", "oauth", "jwt", "session",
    "payment", "billing", "checkout", "crypto", "cipher",
    "encrypt", "password", "secret", "token", "admin",
    "permission", "role", "privilege", "sql", "db", "database",
}


def _is_sensitive_path(filename: str) -> bool:
    low = filename.lower()
    return any(kw in low for kw in SENSITIVE_PATH_KEYWORDS)


def _change_severity(pr_info: PRInfo) -> float:
    total = 0.0
    for f in pr_info.files:
        lines = f.additions + f.deletions
        weight = 2.5 if _is_sensitive_path(f.filename) else 1.0
        total += lines * weight
    return round(min(total / 6.0, 100), 2)


def _blast_radius_score(blast: BlastRadius) -> float:
    return round(min(blast.weighted_score * 4.0, 100), 2)


def _security_signal_score(signals: list[SecuritySignal]) -> float:
    if not signals:
        return 0.0

    deletion_signals = [s for s in signals if s.is_deletion]
    addition_signals = [s for s in signals if not s.is_deletion]

    # Deletion signals score separately and take the max weight directly —
    # removing a security control is a definitive finding, not averaged down
    deletion_score = 0.0
    if deletion_signals:
        max_deletion_weight = max(SIGNAL_WEIGHTS.get(s.signal_type, 40) for s in deletion_signals)
        # Scale up with count: each additional deletion signal adds 5%, capped at 2x
        count_factor = min(1.0 + (len(deletion_signals) - 1) * 0.05, 2.0)
        deletion_score = min(max_deletion_weight * count_factor, 100)

    # Addition signals use averaging with diminishing returns
    addition_score = 0.0
    if addition_signals:
        weights = [SIGNAL_WEIGHTS.get(s.signal_type, 40) for s in addition_signals]
        avg = sum(weights) / len(weights)
        count_factor = min(1.0 + (len(addition_signals) - 1) * 0.08, 1.5)
        addition_score = min(avg * count_factor, 100)

    # Take whichever is higher — don't let addition signals dilute a clear deletion finding
    return round(max(deletion_score, addition_score), 2)


def _dependency_risk_score(dep_risks: list[DependencyRisk]) -> float:
    scores: list[float] = []
    for dep in dep_risks:
        for cve in dep.cves:
            base = cve.cvss_score * 10
            if cve.is_reachable is False and not dep.is_new:
                base *= settings.reachability_discount
            scores.append(base)
    return round(min(max(scores, default=0.0), 100), 2)


def _to_risk_level(score: float, has_critical_deletion: bool = False) -> RiskLevel:
    # Any confirmed auth check removal forces at least HIGH regardless of score
    if has_critical_deletion and score < 60:
        return RiskLevel.HIGH
    if score >= 80: return RiskLevel.CRITICAL
    if score >= 60: return RiskLevel.HIGH
    if score >= 35: return RiskLevel.MEDIUM
    if score >= 15: return RiskLevel.LOW
    return RiskLevel.INFO


def compute_risk_score(
    pr_info: PRInfo,
    parse_result: ParseResult,
    blast_radius: BlastRadius,
    dependency_risks: list[DependencyRisk],
) -> RiskBreakdown:
    cs = _change_severity(pr_info)
    br = _blast_radius_score(blast_radius)
    ss = _security_signal_score(parse_result.security_signals)
    dr = _dependency_risk_score(dependency_risks)

    final = round(
        settings.weight_change_severity  * cs +
        settings.weight_blast_radius     * br +
        settings.weight_security_signals * ss +
        settings.weight_dependency_risk  * dr,
        2,
    )
    final = min(final, 100)

    # If any auth check was removed, apply a score floor of 65 (HIGH territory)
    has_critical_deletion = any(
        s.signal_type == "auth_check_removed" and s.is_deletion
        for s in parse_result.security_signals
    )
    if has_critical_deletion:
        final = max(final, 65.0)

    return RiskBreakdown(
        change_severity=cs,
        blast_radius=br,
        security_signals=ss,
        dependency_risk=dr,
        final_score=final,
        risk_level=_to_risk_level(final, has_critical_deletion),
    )