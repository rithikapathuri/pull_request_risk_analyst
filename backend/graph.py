from __future__ import annotations
from pathlib import Path

import networkx as nx

from backend.models import ParseResult, PRFile, BlastRadius, FunctionNode

# Files touching these keywords are treated as security-critical nodes
CRITICAL_KEYWORDS = {
    "auth", "login", "logout", "oauth", "jwt", "session",
    "payment", "billing", "checkout", "crypto", "cipher",
    "encrypt", "decrypt", "password", "secret", "token",
    "admin", "privilege", "permission", "role",
}

SECONDARY_KEYWORDS = {
    "user", "account", "profile", "order", "cart",
    "email", "notification", "webhook", "api",
}


def _sensitivity(filename: str) -> str:
    """Classify a file as critical / secondary / low based on its path."""
    low = filename.lower()
    if any(k in low for k in CRITICAL_KEYWORDS):
        return "critical"
    if any(k in low for k in SECONDARY_KEYWORDS):
        return "secondary"
    return "low"


class GraphBundle:
    """
    Holds the three graphs built from a PR and exposes blast-radius computation.

    file_graph  — directed edges represent imports between files
    call_graph  — directed edges represent function call relationships
    sens_graph  — undirected edges connect files that share a security domain
    """

    def __init__(self):
        self.file_graph: nx.DiGraph   = nx.DiGraph()
        self.call_graph: nx.DiGraph   = nx.DiGraph()
        self.sens_graph: nx.DiGraph   = nx.DiGraph()

    def compute_blast_radius(self, changed_functions: list[str]) -> BlastRadius:
        """
        BFS from each changed function through the call graph.
        Classifies every reachable node into critical / secondary / low
        based on the filename it belongs to.
        """
        if not changed_functions or self.call_graph.number_of_nodes() == 0:
            return BlastRadius()

        reachable: set[str] = set()
        for fn in changed_functions:
            if fn in self.call_graph:
                reachable |= nx.descendants(self.call_graph, fn)
                reachable.add(fn)

        critical, secondary, low = [], [], []
        for node in reachable:
            # Node names are "filename::function_name"
            filename = node.split("::")[0] if "::" in node else node
            s = _sensitivity(filename)
            if s == "critical":
                critical.append(node)
            elif s == "secondary":
                secondary.append(node)
            else:
                low.append(node)

        return BlastRadius(
            critical_impact=critical,
            secondary_impact=secondary,
            low_impact=low,
            total_affected=len(reachable),
        )

    def affected_files(self, changed_files: list[str]) -> set[str]:
        """BFS on file_graph from each changed file."""
        affected: set[str] = set()
        for f in changed_files:
            if f in self.file_graph:
                affected |= nx.descendants(self.file_graph, f)
                affected.add(f)
        return affected


def build_graphs(parse_result: ParseResult, files: list[PRFile]) -> GraphBundle:
    """
    Builds all three graphs from the parse result.

    File graph:   one node per file, edges from import relationships
    Call graph:   one node per "file::function", edges from call lists
    Sensitivity:  connects files that share a security-sensitive keyword domain
    """
    bundle = GraphBundle()

    # File graph — nodes first
    for f in files:
        if f.status != "removed":
            sensitivity = _sensitivity(f.filename)
            bundle.file_graph.add_node(
                f.filename,
                language=f.language.value,
                sensitivity=sensitivity,
                additions=f.additions,
                deletions=f.deletions,
            )

    # File graph — edges from import data
    # imports dict: {filename: [module_names]}
    # We map module names back to files where possible
    file_stems = {
        Path(f.filename).stem.lower(): f.filename
        for f in files
        if f.status != "removed"
    }
    for filename, imported_modules in parse_result.imports.items():
        for mod in imported_modules:
            target = file_stems.get(mod.lower())
            if target and target != filename:
                bundle.file_graph.add_edge(filename, target, edge_type="import")

    # Call graph — one node per qualified function name
    fn_by_name: dict[str, str] = {}  # bare_name -> qualified name (last wins, good enough)
    for fn in parse_result.functions:
        qualified = f"{fn.filename}::{fn.name}"
        bundle.call_graph.add_node(
            qualified,
            filename=fn.filename,
            start_line=fn.start_line,
            end_line=fn.end_line,
            is_changed=fn.is_changed,
            sensitivity=_sensitivity(fn.filename),
        )
        fn_by_name[fn.name] = qualified

    # Call graph — edges from call lists
    for fn in parse_result.functions:
        caller = f"{fn.filename}::{fn.name}"
        for called_name in fn.calls:
            callee = fn_by_name.get(called_name)
            if callee and callee != caller:
                bundle.call_graph.add_edge(caller, callee, edge_type="call")

    # Sensitivity graph — connect files sharing a security domain
    # Groups files by the first matching critical keyword in their path
    domain_files: dict[str, list[str]] = {}
    for f in files:
        if f.status == "removed":
            continue
        low = f.filename.lower()
        for kw in CRITICAL_KEYWORDS:
            if kw in low:
                domain_files.setdefault(kw, []).append(f.filename)
                break

    for domain, members in domain_files.items():
        for i, a in enumerate(members):
            for b in members[i + 1:]:
                bundle.sens_graph.add_edge(a, b, domain=domain)

    return bundle


def graph_summary(bundle: GraphBundle) -> dict:
    """Returns a compact summary dict for the LLM context and API response."""
    return {
        "file_nodes": bundle.file_graph.number_of_nodes(),
        "file_edges": bundle.file_graph.number_of_edges(),
        "call_nodes": bundle.call_graph.number_of_nodes(),
        "call_edges": bundle.call_graph.number_of_edges(),
        "changed_nodes": [
            n for n, d in bundle.call_graph.nodes(data=True) if d.get("is_changed")
        ],
        "critical_files": [
            n for n, d in bundle.file_graph.nodes(data=True)
            if d.get("sensitivity") == "critical"
        ],
    }