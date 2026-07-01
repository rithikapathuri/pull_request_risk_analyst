import argparse
import asyncio
import subprocess
from pathlib import Path
import networkx as nx
import json

from backend.models import PRInfo, PRFile, BlastRadius, SecuritySignalSummary

from backend.parser import parse_pr, _extract_imports
from backend.github import parse_diff_hunks, detect_language, DEPENDENCY_FILES, parse_all_dependencies
from backend.cve import check_dependencies, check_new_dependencies
from backend.reachability import analyze_reachability
from backend.scorer import compute_risk_score
from backend.llm import run_llm_chain
from backend.graph import build_graphs

def get_local_diff(repo_path: Path, target_branch: str) -> list[PRFile]:
    """Uses local git commands to extract changed files and patches"""
    try:
        # Get list of changed files
        cmd = ["git", "diff", "--name-status", target_branch]
        result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Git error: Ensure '{target_branch}' exists and you are in a git repo.\n{e}")
        return []

    pr_files = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        parts = line.split("\t")
        status_code = parts[0][0]
        filename = parts[1]
        
        status_map = {"A": "added", "M": "modified", "D": "removed", "R": "renamed"}
        status = status_map.get(status_code, "modified")

        patch = ""
        if status != "removed":
            patch_cmd = ["git", "diff", target_branch, "--", filename]
            patch_result = subprocess.run(patch_cmd, cwd=repo_path, capture_output=True, text=True)
            patch = patch_result.stdout

        pr_files.append(PRFile(
            filename=filename,
            status=status,
            additions=patch.count("\n+ ") if patch else 0,
            deletions=patch.count("\n- ") if patch else 0,
            patch=patch,
            language=detect_language(filename)
        ))
        
    return pr_files

def calculate_global_centrality(repo_path: Path, changed_files: list[PRFile]) -> float:
    """Builds a global import graph of the local repo to calculate true blast radius"""
    global_graph = nx.DiGraph()
    print("[*] Building global repository graph for Blast Radius...")
    
    ignore_dirs = {".git", "node_modules", "venv", "__pycache__", "dist", "build"}
    
    for file_path in repo_path.rglob("*"):
        if file_path.suffix in {".py", ".js", ".ts", ".mjs", ".tsx"}:
            if any(part in ignore_dirs for part in file_path.parts):
                continue
            
            try:
                content = file_path.read_text(encoding="utf-8")
                rel_path = file_path.relative_to(repo_path).as_posix()
                imports = _extract_imports(rel_path, content)
                
                global_graph.add_node(rel_path)
                
                for imp in imports:
                    global_graph.add_edge(rel_path, imp)
            except Exception:
                continue

    if global_graph.number_of_nodes() == 0:
        return 0.0

    # Calculate True Graph Centrality
    centrality = nx.in_degree_centrality(global_graph)
    
    # Aggregate centrality for all changed files
    total_centrality = 0.0
    for f in changed_files:
        if f.status != "removed":
            total_centrality += centrality.get(f.filename, 0.0)

    # Scale to 100 -> highly central file will naturally cap out
    # Multiplying by an arbitrary scaler (e.g., 500) to convert strict decimal into readable score
    return min(total_centrality * 500, 100.0)


async def run_local_analysis(repo_path: Path, target_branch: str, run_llm: bool):
    pr_files = get_local_diff(repo_path, target_branch)
    if not pr_files:
        print("No changes found or invalid branch.")
        return

    # Fetch full local sources for AST integrity
    full_sources = {}
    dep_filenames = []
    for f in pr_files:
        if f.status != "removed":
            try:
                full_sources[f.filename] = (repo_path / f.filename).read_text(encoding="utf-8")
            except Exception:
                pass
        if Path(f.filename).name in DEPENDENCY_FILES:
            dep_filenames.append(f.filename)

    # Calculate Blast Radius via Graph Centrality
    centrality_score = calculate_global_centrality(repo_path, pr_files)
    
    # Mock PRInfo since we bypass the GitHub API
    pr_info = PRInfo(
        owner="local", repo=repo_path.name, number=0, title="Local Analysis",
        author="local-user", base_branch=target_branch, head_branch="HEAD", head_sha="local",
        files=pr_files, dependency_files=dep_filenames, raw_dependencies={}, new_dependencies=[]
    )

    print("[*] Parsing AST and checking CVEs...")
    hunks = parse_diff_hunks(pr_files)
    parse_result = parse_pr(pr_files, hunks, full_sources)
    
    # Local graphs still built for reachability logic
    graphs = build_graphs(parse_result, pr_files)
    
    # Inject our mathematically perfect centrality score
    blast_radius = BlastRadius(override_score=centrality_score)
    
    dep_risks = await check_dependencies(pr_info.raw_dependencies, dep_filenames)
    dep_risks = analyze_reachability(dep_risks, parse_result, graphs.call_graph)
    
    risk = compute_risk_score(pr_info, parse_result, blast_radius, dep_risks)
    
    signal_summaries = [SecuritySignalSummary(signal=s) for s in parse_result.security_signals]
    triage = explanation = recommendations = None

    if run_llm:
        print("[*] Synthesizing context via LLM...")
        triage, explanation, recommendations, signal_summaries = await run_llm_chain(
            pr_info, parse_result, blast_radius, dep_risks, risk, signal_summaries,
        )

    print("\n" + "="*50)
    print(f"FINAL RISK SCORE: {risk.final_score}/100 ({risk.risk_level.value.upper()})")
    print(f"Global Centrality Blast Radius: {centrality_score:.1f}/100")
    print("="*50)
    
    if triage:
        print(f"\n[AI TRIAGE]: {triage.primary_risk_category.upper()}")
        print(f"Reasoning: {triage.reasoning}")
        print(f"\n[RECOMMENDATIONS]:")
        for rec in recommendations.immediate_fixes:
            print(f" - {rec}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run PR Risk Analyst Locally")
    parser.add_argument("--repo", type=str, default=".", help="Path to local repository")
    parser.add_argument("--branch", type=str, default="main", help="Target branch to diff against (e.g., main)")
    parser.add_argument("--llm", action="store_true", help="Enable Gemini synthesis")
    
    args = parser.parse_args()
    asyncio.run(run_local_analysis(Path(args.repo).resolve(), args.branch, args.llm))