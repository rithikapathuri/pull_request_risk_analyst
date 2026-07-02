from __future__ import annotations
import logging
from typing import Optional
from pydantic import BaseModel

from google import genai
from google.genai import types
from tenacity import retry, stop_after_attempt, wait_exponential

from backend.config import get_settings
from backend.models import (
    PRInfo, ParseResult, BlastRadius, DependencyRisk, RiskBreakdown,
    SecuritySignalSummary, LLMTriage, LLMExplanation, LLMRecommendations,
)

settings = get_settings()
log = logging.getLogger(__name__)

_client: genai.Client | None = None

def _get_client() -> genai.Client:
    global _client
    if _client is None:
        _client = genai.Client(api_key=settings.gemini_api_key)
    return _client


CATEGORY_FOCUS: dict[str, str] = {
    "injection":      "Focus on injection vectors: SQL, command, code, template",
    "auth":           "Focus on auth bypass, session management, token handling",
    "supply_chain":   "Focus on vulnerable deps, transitive risks, version pinning, typosquatting",
    "crypto":         "Focus on weak algorithms, key management, insecure randomness",
    "access_control": "Focus on privilege escalation, IDOR, missing authorization checks",
    "data_exposure":  "Focus on PII leakage, secret logging, unencrypted storage",
    "config":         "Focus on insecure defaults, hardcoded credentials, IaC misconfigurations",
    "logic":          "Focus on business logic flaws, race conditions, state bugs",
    "low_risk":       "Confirm why this is low risk and what to watch for anyway",
}


def _build_context(
    pr: PRInfo,
    parse_result: ParseResult,
    blast: BlastRadius,
    dep_risks: list[DependencyRisk],
    breakdown: RiskBreakdown,
) -> str:
    cve_lines = [
        f"  {d.package}@{d.version}{'  [NEW PACKAGE]' if d.is_new else ''}: "
        f"{c.cve_id} ({c.severity.value}, CVSS {c.cvss_score:.1f}, reachable={c.is_reachable})"
        for d in dep_risks for c in d.cves
    ]
    signal_lines = [
        f"  {'[DELETION]' if s.is_deletion else '[ADDITION]'} "
        f"{s.signal_type} in {s.filename}:{s.line} -> {s.snippet[:80]}"
        for s in parse_result.security_signals
    ]
    new_deps = pr.new_dependencies
    dep_section = f"New packages added by this PR: {new_deps}\n" if new_deps else ""

    # Include up to 3 file diffs so LLM sees actual removed/added code
    diff_section = ""
    if parse_result.file_patches:
        diff_lines = []
        for filename, patch in list(parse_result.file_patches.items())[:3]:
            diff_lines.append(f"--- {filename} ---")
            diff_lines.append(patch[:1500])
        diff_section = "\nDiff context (analyze deletions carefully for removed security controls):\n" + "\n".join(diff_lines)

    return (
        f"PR: {pr.owner}/{pr.repo} #{pr.number} - {pr.title}\n"
        f"Author: {pr.author} | {len(pr.files)} files changed\n"
        f"Additions: {sum(f.additions for f in pr.files)} "
        f"Deletions: {sum(f.deletions for f in pr.files)}\n"
        f"{dep_section}\n"
        f"Risk scores:\n"
        f"  change_severity={breakdown.change_severity} "
        f"blast_radius={breakdown.blast_radius} "
        f"security_signals={breakdown.security_signals} "
        f"dependency_risk={breakdown.dependency_risk}\n"
        f"  FINAL: {breakdown.final_score} ({breakdown.risk_level.value.upper()})\n\n"
        f"Blast radius:\n"
        f"  critical={blast.critical_impact}\n"
        f"  secondary={blast.secondary_impact}\n\n"
        f"CVE findings:\n" + ("\n".join(cve_lines) if cve_lines else "  none") + "\n\n"
        f"Security signals (DELETION signals mean a security control was removed):\n"
        + ("\n".join(signal_lines) if signal_lines else "  none")
        + diff_section
    )


@retry(stop=stop_after_attempt(settings.llm_max_retries), wait=wait_exponential(min=2, max=12), reraise=True)
async def _triage(context: str) -> Optional[LLMTriage]:
    prompt = (
        "You are a senior security engineer reviewing a pull request.\n\n"
        f"{context}\n\n"
        "Classify the PRIMARY risk category. Pay special attention to [DELETION] signals — "
        "removing a security control is often more dangerous than adding bad code.\n"
        "Also check for supply chain risks if new packages were added."
    )
    try:
        response = await _get_client().aio.models.generate_content(
            model=settings.gemini_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=LLMTriage,
                temperature=0.1,
            ),
        )
        return response.parsed
    except Exception as e:
        log.error("triage failed: %s", e)
        return None


@retry(stop=stop_after_attempt(settings.llm_max_retries), wait=wait_exponential(min=2, max=12), reraise=True)
async def _explain(context: str, category: str) -> Optional[LLMExplanation]:
    focus = CATEGORY_FOCUS.get(category, "Explain the security implications")
    prompt = (
        "You are a senior security engineer writing a concise PR review.\n\n"
        f"{context}\n\n"
        f"{focus}\n\n"
        "If the diff shows deleted lines, specifically address what security guarantee "
        "was lost by removing that code and what an attacker could now do."
    )
    try:
        response = await _get_client().aio.models.generate_content(
            model=settings.gemini_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=LLMExplanation,
                temperature=0.1,
            ),
        )
        return response.parsed
    except Exception as e:
        log.error("explanation failed: %s", e)
        return None


@retry(stop=stop_after_attempt(settings.llm_max_retries), wait=wait_exponential(min=2, max=12), reraise=True)
async def _recommend(
    context: str,
    explanation: Optional[LLMExplanation],
) -> Optional[LLMRecommendations]:
    summary = explanation.summary if explanation else "See analysis above"
    prompt = (
        "You are a senior security engineer giving actionable fix recommendations.\n\n"
        f"{context}\n\n"
        f"Risk summary: {summary}\n\n"
        "For any removed security controls, recommend either restoring them or "
        "providing an equivalent mitigation. Set safe_to_merge to true only if final_score < 35."
    )
    try:
        response = await _get_client().aio.models.generate_content(
            model=settings.gemini_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=LLMRecommendations,
                temperature=0.1,
            ),
        )
        return response.parsed
    except Exception as e:
        log.error("recommendations failed: %s", e)
        return None


class SignalVerdict(BaseModel):
    confirmed_risky: bool
    verdict: str


@retry(stop=stop_after_attempt(settings.llm_max_retries), wait=wait_exponential(min=2, max=12), reraise=True)
async def _review_ambiguous(
    summaries: list[SecuritySignalSummary],
    context: str,
) -> list[SecuritySignalSummary]:
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ambiguous = [item for item in summaries if item.signal.is_ambiguous]
    ambiguous.sort(key=lambda x: SEVERITY_ORDER.get(x.signal.severity.value, 5))

    for item in ambiguous[:3]:
        sig = item.signal
        deletion_note = (
            "This signal came from a DELETED line. Assess whether removing this "
            "code weakens the security posture even if it looks innocuous."
            if sig.is_deletion else
            "Assess whether this added code is actually exploitable in context."
        )
        prompt = (
            "You are a security code reviewer.\n\n"
            f"PR context:\n{context}\n\n"
            f"Flagged pattern: {sig.signal_type}\n"
            f"File: {sig.filename}, line {sig.line}\n"
            f"Code: {sig.snippet}\n\n"
            f"{deletion_note}"
        )
        try:
            response = await _get_client().aio.models.generate_content(
                model=settings.gemini_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=SignalVerdict,
                    temperature=0.1,
                ),
            )
            data = response.parsed
            if data:
                item.confirmed_risky = data.confirmed_risky
                item.llm_verdict = data.verdict
        except Exception as e:
            log.error("signal review failed for %s: %s", sig.signal_type, e)
            item.confirmed_risky = True

    return summaries


async def run_llm_chain(
    pr_info: PRInfo,
    parse_result: ParseResult,
    blast_radius: BlastRadius,
    dependency_risks: list[DependencyRisk],
    risk_breakdown: RiskBreakdown,
    signal_summaries: list[SecuritySignalSummary],
) -> tuple[
    Optional[LLMTriage],
    Optional[LLMExplanation],
    Optional[LLMRecommendations],
    list[SecuritySignalSummary],
]:
    if not settings.gemini_api_key:
        log.warning("GEMINI_API_KEY not set -> skipping LLM chain")
        return None, None, None, signal_summaries

    ctx = _build_context(pr_info, parse_result, blast_radius, dependency_risks, risk_breakdown)

    triage          = await _triage(ctx)
    category        = triage.primary_risk_category if triage else "low_risk"
    explanation     = await _explain(ctx, category)
    recommendations = await _recommend(ctx, explanation)
    signal_summaries = await _review_ambiguous(signal_summaries, ctx)

    return triage, explanation, recommendations, signal_summaries