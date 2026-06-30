from __future__ import annotations
import asyncio

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
    title="PR Risk Analyst",
    description="Analyzes GitHub pull requests for security risk, blast radius, and CVE exposure",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "https://pr-risk-autopilot.vercel.app"],
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
    Full pipeline — called by the API route and the benchmark runner.
    """
    async with GitHubClient() as gh:
        pr_info = await gh.get_pr(owner, repo, pr_number)

        # Fetch full file contents for modified/added files at head_sha to ensure AST integrity
        full_sources: dict[str, str] = {}
        fetch_tasks = []
        fetch_filenames = []
        for f in pr_info.files:
            if f.status != "removed":
                fetch_tasks.append(gh.get_file_at_ref(owner, repo, f.filename, pr_info.head_sha))
                fetch_filenames.append(f.filename)
        
        contents = await asyncio.gather(*fetch_tasks, return_exceptions=True)
        for fname, content in zip(fetch_filenames, contents):
            if isinstance(content, str):
                full_sources[fname] = content

    if not pr_info.files:
        raise ValueError("PR has no changed files")

    hunks        = parse_diff_hunks(pr_info.files)
    parse_result = parse_pr(pr_info.files, hunks, full_sources)
    graphs       = build_graphs(parse_result, pr_info.files)
    blast_radius = graphs.compute_blast_radius(parse_result.changed_function_names)
    dep_risks      = await check_dependencies(pr_info.raw_dependencies, pr_info.dependency_files)
    new_dep_risks  = await check_new_dependencies(pr_info.new_dependencies, pr_info.raw_dependencies)
    
    # Merge new dep results in
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
    """Fetch PR metadata only —> no analysis, useful for previewing before submitting"""
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


@app.post("/api/v1/graph")
async def get_graph_data(req: AnalyzeRequest) -> dict:
    async with GitHubClient() as gh:
        pr_info = await gh.get_pr(req.owner, req.repo, req.pr_number)
        
        # We also need full sources for graph preview consistency
        full_sources: dict[str, str] = {}
        fetch_tasks = []
        fetch_filenames = []
        for f in pr_info.files:
            if f.status != "removed":
                fetch_tasks.append(gh.get_file_at_ref(req.owner, req.repo, f.filename, pr_info.head_sha))
                fetch_filenames.append(f.filename)
        contents = await asyncio.gather(*fetch_tasks, return_exceptions=True)
        for fname, content in zip(fetch_filenames, contents):
            if isinstance(content, str):
                full_sources[fname] = content

    hunks        = parse_diff_hunks(pr_info.files)
    parse_result = parse_pr(pr_info.files, hunks, full_sources)
    graphs       = build_graphs(parse_result, pr_info.files)

    use_call_graph = graphs.call_graph.number_of_nodes() > 0
    g = graphs.call_graph if use_call_graph else graphs.file_graph

    nodes = []
    for node_id, data in g.nodes(data=True):
        if use_call_graph:
            label = node_id.split("::")[-1] if "::" in node_id else node_id
            filename = data.get("filename", "")
        else:
            label = node_id.split("/")[-1]
            filename = node_id

        nodes.append({
            "data": {
                "id": node_id,
                "label": label,
                "filename": filename,
                "is_changed": data.get("is_changed", False),
                "sensitivity": data.get("sensitivity", "low"),
            }
        })

    edges = []
    for src, dst, data in g.edges(data=True):
        edges.append({
            "data": {
                "id": f"{src}->{dst}",
                "source": src,
                "target": dst,
            }
        })

    return {"nodes": nodes, "edges": edges, "type": "call" if use_call_graph else "file"}