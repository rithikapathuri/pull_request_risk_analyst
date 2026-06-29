from __future__ import annotations
from pathlib import Path

import networkx as nx

from backend.models import ParseResult, PRFile, BlastRadius

CRITICAL_KEYWORDS = {
    "auth", "login", "logout", "oauth", "jwt", "session",
    "payment", "billing", "checkout", "crypto", "cipher",
    "encrypt", "decrypt", "password", "secret", "token",
    "admin", "privilege", "permission", "role",
    "sql", "db", "database", "query", "store",
}

SECONDARY_KEYWORDS = {
    "user", "account", "profile", "order", "cart",
    "email", "notification", "webhook", "api", "handler",
    "server", "service", "controller", "middleware",
}


def _sensitivity(filename: str) -> str:
    low = filename.lower()
    if any(k in low for k in CRITICAL_KEYWORDS):
        return "critical"
    if any(k in low for k in SECONDARY_KEYWORDS):
        return "secondary"
    return "low"


class GraphBundle:
    def __init__(self):
        self.file_graph: nx.DiGraph = nx.DiGraph()
        self.call_graph: nx.DiGraph = nx.DiGraph()
        self.sens_graph: nx.DiGraph = nx.DiGraph()

    def compute_blast_radius(self, changed_functions: list[str]) -> BlastRadius:
        # Try call graph first (Python/JS only —> needs parsed functions)
        if changed_functions and self.call_graph.number_of_nodes() > 0:
            return self._blast_from_call_graph(changed_functions)

        # Fall back to file graph —> works for all languages including Go
        # Uses all changed files as starting points instead of functions
        return self._blast_from_file_graph()

    def _blast_from_call_graph(self, changed_functions: list[str]) -> BlastRadius:
        reachable: set[str] = set()
        for fn in changed_functions:
            if fn in self.call_graph:
                reachable |= nx.descendants(self.call_graph, fn)
                reachable.add(fn)

        critical, secondary, low = [], [], []
        for node in reachable:
            filename = node.split("::")[0] if "::" in node else node
            s = _sensitivity(filename)
            if s == "critical":      critical.append(node)
            elif s == "secondary":   secondary.append(node)
            else:                    low.append(node)

        return BlastRadius(
            critical_impact=critical,
            secondary_impact=secondary,
            low_impact=low,
            total_affected=len(reachable),
        )

    def _blast_from_file_graph(self) -> BlastRadius:
        # Start BFS from every changed file and find what they connect to
        changed_files = [
            n for n, d in self.file_graph.nodes(data=True)
            if d.get("is_changed", False)
        ]

        if not changed_files:
            # If no import edges were found, just classify the changed files themselves
            changed_files = list(self.file_graph.nodes)

        reachable: set[str] = set()
        for f in changed_files:
            if f in self.file_graph:
                reachable |= nx.descendants(self.file_graph, f)
                reachable.add(f)

        # If no edges exist (no import relationships detected), still report
        # the changed files themselves as affected
        if not reachable:
            reachable = set(self.file_graph.nodes)

        critical, secondary, low = [], [], []
        for node in reachable:
            s = _sensitivity(node)
            if s == "critical":     critical.append(node)
            elif s == "secondary":  secondary.append(node)
            else:                   low.append(node)

        return BlastRadius(
            critical_impact=critical,
            secondary_impact=secondary,
            low_impact=low,
            total_affected=len(reachable),
        )

    def affected_files(self, changed_files: list[str]) -> set[str]:
        affected: set[str] = set()
        for f in changed_files:
            if f in self.file_graph:
                affected |= nx.descendants(self.file_graph, f)
                affected.add(f)
        return affected


def build_graphs(parse_result: ParseResult, files: list[PRFile]) -> GraphBundle:
    bundle = GraphBundle()

    for f in files:
        if f.status != "removed":
            bundle.file_graph.add_node(
                f.filename,
                language=f.language.value,
                sensitivity=_sensitivity(f.filename),
                additions=f.additions,
                deletions=f.deletions,
                is_changed=(f.additions + f.deletions) > 0,
            )

    # File import edges (Python/JS only —> others have no import data)
    file_stems = {
        Path(f.filename).stem.lower(): f.filename
        for f in files if f.status != "removed"
    }
    for filename, imported_modules in parse_result.imports.items():
        for mod in imported_modules:
            target = file_stems.get(mod.lower())
            if target and target != filename:
                bundle.file_graph.add_edge(filename, target, edge_type="import")

    # Call graph nodes
    fn_by_name: dict[str, str] = {}
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

    # Call graph edges
    for fn in parse_result.functions:
        caller = f"{fn.filename}::{fn.name}"
        for called_name in fn.calls:
            callee = fn_by_name.get(called_name)
            if callee and callee != caller:
                bundle.call_graph.add_edge(caller, callee, edge_type="call")

    # Sensitivity graph
    domain_files: dict[str, list[str]] = {}
    for f in files:
        if f.status == "removed":
            continue
        for kw in CRITICAL_KEYWORDS:
            if kw in f.filename.lower():
                domain_files.setdefault(kw, []).append(f.filename)
                break

    for domain, members in domain_files.items():
        for i, a in enumerate(members):
            for b in members[i + 1:]:
                bundle.sens_graph.add_edge(a, b, domain=domain)

    return bundle


def graph_summary(bundle: GraphBundle) -> dict:
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