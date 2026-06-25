from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.config import get_settings
from backend.models import PRInfo, PRAnalysisResult, SecuritySignalSummary
from backend.github import GitHubClient, parse_diff_hunks
from backend.parser import parse_pr
from backend.graph import build_graphs, graph_summary
from backend.reachability import analyze_reachability
from backend.cve import check_dependencies, check_new_dependencies
from backend.scorer import compute_risk_score
from backend.llm import run_llm_chain

settings = get_settings()

app = FastAPI(
    title="PR Risk Autopilot",
    description="Analyzes GitHub pull requests for security risk, blast radius, and CVE exposure",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    owner: str
    repo: str
    pr_number: int
    run_llm: bool = True


async def run_analysis(
    owner: str,
    repo: str,
    pr_number: int,
    run_llm: bool = True,
) -> PRAnalysisResult:
    """
    Full pipeline —> called by the API route and the benchmark runner.

    1  Fetch PR metadata, files, diffs, dependency manifests from GitHub
    2  Parse changed hunks with AST (Python) or regex (JS/TS)
    3  Build file dependency graph + function call graph with NetworkX
    4  Check every dependency against OSV.dev concurrently
    5  Run call-graph DFS to test whether vulnerable functions are reachable
    6  Compute weighted risk score deterministically
    7  Run three-step Gemini chain for human-readable output (optional)
    """
    async with GitHubClient() as gh:
        pr_info = await gh.get_pr(owner, repo, pr_number)

    if not pr_info.files:
        raise ValueError("PR has no changed files")

    hunks        = parse_diff_hunks(pr_info.files)
    parse_result = parse_pr(pr_info.files, hunks)
    graphs       = build_graphs(parse_result, pr_info.files)
    blast_radius = graphs.compute_blast_radius(parse_result.changed_function_names)
    dep_risks      = await check_dependencies(pr_info.raw_dependencies, pr_info.dependency_files)
    new_dep_risks  = await check_new_dependencies(pr_info.new_dependencies, pr_info.raw_dependencies)
    # Merge new dep results in —> new packages appear in both lists but new_dep_risks
    # has the is_new=True flag and typosquatting checks applied
    existing_pkgs  = {d.package for d in dep_risks}
    dep_risks      = dep_risks + [d for d in new_dep_risks if d.package not in existing_pkgs]
    dep_risks      = analyze_reachability(dep_risks, parse_result, graphs.call_graph)
    risk         = compute_risk_score(pr_info, parse_result, blast_radius, dep_risks)

    signal_summaries = [SecuritySignalSummary(signal=s) for s in parse_result.security_signals]
    triage = explanation = recommendations = None

    if run_llm and settings.gemini_api_key:
        triage, explanation, recommendations, signal_summaries = await run_llm_chain(
            pr_info, parse_result, blast_radius, dep_risks, risk, signal_summaries,
        )

    return PRAnalysisResult(
        pr=pr_info,
        parse_result=parse_result,
        blast_radius=blast_radius,
        dependency_risks=dep_risks,
        risk_breakdown=risk,
        security_signal_summaries=signal_summaries,
        triage=triage,
        explanation=explanation,
        recommendations=recommendations,
    )


@app.post("/api/v1/analyze", response_model=PRAnalysisResult)
async def analyze(req: AnalyzeRequest) -> PRAnalysisResult:
    try:
        return await run_analysis(req.owner, req.repo, req.pr_number, req.run_llm)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")


@app.get("/api/v1/pr/{owner}/{repo}/{pr_number}", response_model=PRInfo)
async def get_pr(owner: str, repo: str, pr_number: int) -> PRInfo:
    """Fetch PR metadata only — no analysis. Useful for previewing before submitting"""
    try:
        async with GitHubClient() as gh:
            return await gh.get_pr(owner, repo, pr_number)
    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e))


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "env": settings.app_env,
        "llm_enabled": bool(settings.gemini_api_key),
    }