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

client = None
if settings.gemini_api_key:
    client = genai.Client(api_key=settings.gemini_api_key)

# Category-specific guidance injected into the explanation prompt
CATEGORY_FOCUS: dict[str, str] = {
    "injection":      "Focus on injection vectors: SQL, command, code, template",
    "auth":           "Focus on auth bypass, session management, token handling",
    "supply_chain":   "Focus on vulnerable deps, transitive risks, version pinning",
    "crypto":         "Focus on weak algorithms, key management, insecure randomness",
    "access_control": "Focus on privilege escalation, IDOR, missing authorization",
    "data_exposure":  "Focus on PII leakage, secret logging, unencrypted storage",
    "config":         "Focus on insecure defaults, hardcoded credentials, env exposure",
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
        f"  {d.package}@{d.version}: {c.cve_id} ({c.severity.value}, CVSS {c.cvss_score:.1f}, reachable={c.is_reachable})"
        for d in dep_risks for c in d.cves
    ]
    signal_lines = [
        f"  {s.signal_type} in {s.filename}:{s.line} → {s.snippet[:80]}"
        for s in parse_result.security_signals
    ]
    return (
        f"PR: {pr.owner}/{pr.repo} #{pr.number} — {pr.title}\n"
        f"Author: {pr.author} | {len(pr.files)} files changed\n"
        f"Additions: {sum(f.additions for f in pr.files)} "
        f"Deletions: {sum(f.deletions for f in pr.files)}\n\n"
        f"Risk scores:\n"
        f"  change_severity={breakdown.change_severity}  "
        f"blast_radius={breakdown.blast_radius}  "
        f"security_signals={breakdown.security_signals}  "
        f"dependency_risk={breakdown.dependency_risk}\n"
        f"  FINAL: {breakdown.final_score} ({breakdown.risk_level.value.upper()})\n\n"
        f"Blast radius:\n"
        f"  critical={blast.critical_impact}\n"
        f"  secondary={blast.secondary_impact}\n\n"
        f"CVE findings:\n" + ("\n".join(cve_lines) if cve_lines else "  none") + "\n\n"
        f"Security signals:\n" + ("\n".join(signal_lines) if signal_lines else "  none")
    )


@retry(stop=stop_after_attempt(settings.llm_max_retries), wait=wait_exponential(min=2, max=12), reraise=True)
async def _triage(context: str) -> Optional[LLMTriage]:
    prompt = (
        "You are a senior security engineer reviewing a pull request analysis.\n\n"
        f"{context}\n\n"
        "Classify the PRIMARY risk category."
    )
    try:
        response = await client.aio.models.generate_content(
            model=settings.gemini_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=LLMTriage,
            )
        )
        return response.parsed
    except Exception as e:
        log.warning("triage failed: %s", e)
        return None


@retry(stop=stop_after_attempt(settings.llm_max_retries), wait=wait_exponential(min=2, max=12), reraise=True)
async def _explain(context: str, category: str) -> Optional[LLMExplanation]:
    focus = CATEGORY_FOCUS.get(category, "Explain the security implications")
    prompt = (
        "You are a senior security engineer writing a code review.\n\n"
        f"{context}\n\n"
        f"{focus}\n"
    )
    try:
        response = await client.aio.models.generate_content(
            model=settings.gemini_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=LLMExplanation,
            )
        )
        return response.parsed
    except Exception as e:
        log.warning("explanation failed: %s", e)
        return None


@retry(stop=stop_after_attempt(settings.llm_max_retries), wait=wait_exponential(min=2, max=12), reraise=True)
async def _recommend(context: str, explanation: Optional[LLMExplanation]) -> Optional[LLMRecommendations]:
    summary = explanation.summary if explanation else "See analysis"
    prompt = (
        "You are a senior security engineer giving actionable fix advice.\n\n"
        f"{context}\n\n"
        f"Risk summary: {summary}\n\n"
        "Set safe_to_merge to true only if final_score < 35"
    )
    try:
        response = await client.aio.models.generate_content(
            model=settings.gemini_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=LLMRecommendations,
            )
        )
        return response.parsed
    except Exception as e:
        log.warning("recommendations failed: %s", e)
        return None


# Inline model to capture the ambiguous signal check natively
class SignalVerdict(BaseModel):
    confirmed_risky: bool
    verdict: str


@retry(stop=stop_after_attempt(settings.llm_max_retries), wait=wait_exponential(min=2, max=12), reraise=True)
async def _review_ambiguous(
    summaries: list[SecuritySignalSummary],
    context: str,
) -> list[SecuritySignalSummary]:
    for item in summaries:
        if not item.signal.is_ambiguous:
            continue
        sig = item.signal
        prompt = (
            "You are a security code reviewer.\n\n"
            f"PR context:\n{context}\n\n"
            f"Flagged pattern: {sig.signal_type}\n"
            f"File: {sig.filename}, line {sig.line}\n"
            f"Code: {sig.snippet}\n\n"
            "Is this actually exploitable in context?"
        )
        try:
            response = await client.aio.models.generate_content(
                model=settings.gemini_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=SignalVerdict,
                )
            )
            data = response.parsed
            if data:
                item.confirmed_risky = data.confirmed_risky
                item.llm_verdict = data.verdict
        except Exception as e:
            log.warning("signal review failed for %s: %s", sig.signal_type, e)
            item.confirmed_risky = True  # conservative default

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
    if not settings.gemini_api_key or not client:
        log.warning("GEMINI_API_KEY not set — skipping LLM chain")
        return None, None, None, signal_summaries

    ctx = _build_context(pr_info, parse_result, blast_radius, dependency_risks, risk_breakdown)

    triage = await _triage(ctx)
    category = triage.primary_risk_category if triage else "low_risk"
    explanation = await _explain(ctx, category)
    recommendations = await _recommend(ctx, explanation)
    signal_summaries = await _review_ambiguous(signal_summaries, ctx)

    return triage, explanation, recommendations, signal_summaries