from __future__ import annotations
from pathlib import Path

import networkx as nx

from backend.models import ParseResult, PRFile, BlastRadius

CRITICAL_IMPORTS = {
    "bcrypt", "cryptography", "jsonwebtoken", "sqlalchemy", "pg", 
    "sqlite3", "stripe", "boto3", "jwt", "oauth2"
}
SECONDARY_IMPORTS = {
    "flask", "express", "django", "fastapi", "requests", "axios", 
    "urllib", "httpx"
}

CRITICAL_OPERATIONS = {
    "execute", "query", "encrypt", "decrypt", "hash", 
    "verify", "authenticate", "login", "sign", "commit"
}
SECONDARY_OPERATIONS = {
    "fetch", "request", "get", "post", "put", "delete", 
    "render", "send", "dispatch"
}


class GraphBundle:
    def __init__(self):
        self.file_graph: nx.DiGraph = nx.DiGraph()
        self.call_graph: nx.DiGraph = nx.DiGraph()
        self.sens_graph: nx.DiGraph = nx.DiGraph()

    def compute_blast_radius(self, changed_functions: list[str]) -> BlastRadius:
        if changed_functions and self.call_graph.number_of_nodes() > 0:
            return self._blast_from_call_graph(changed_functions)

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
            # Rely on the sensitivity already calculated and stored in the node data
            s = self.file_graph.nodes.get(filename, {}).get("sensitivity", "low")
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
        changed_files = [
            n for n, d in self.file_graph.nodes(data=True)
            if d.get("is_changed", False)
        ]

        if not changed_files:
            changed_files = list(self.file_graph.nodes)

        reachable: set[str] = set()
        for f in changed_files:
            if f in self.file_graph:
                reachable |= nx.descendants(self.file_graph, f)
                reachable.add(f)

        if not reachable:
            reachable = set(self.file_graph.nodes)

        critical, secondary, low = [], [], []
        for node in reachable:
            s = self.file_graph.nodes.get(node, {}).get("sensitivity", "low")
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

    # Pre-map all operations (function definitions and calls) to their respective files
    # O(1) lookup time when determining file sensitivity
    file_ops: dict[str, set[str]] = {}
    for fn in parse_result.functions:
        ops = file_ops.setdefault(fn.filename, set())
        ops.add(fn.name.lower())
        for call in fn.calls:
            ops.add(call.lower())

    def _behavioral_sensitivity(filename: str) -> str:
        # Check Imports
        imports = parse_result.imports.get(filename, [])
        for imp in imports:
            imp_lower = imp.lower()
            if any(kw in imp_lower for kw in CRITICAL_IMPORTS):
                return "critical"
            if any(kw in imp_lower for kw in SECONDARY_IMPORTS):
                return "secondary"

        # Check Operations
        ops = file_ops.get(filename, set())
        for op in ops:
            if any(kw in op for kw in CRITICAL_OPERATIONS):
                return "critical"
            if any(kw in op for kw in SECONDARY_OPERATIONS):
                return "secondary"

        return "low"

    for f in files:
        if f.status != "removed":
            bundle.file_graph.add_node(
                f.filename,
                language=f.language.value,
                sensitivity=_behavioral_sensitivity(f.filename), # Powered purely by behavior
                additions=f.additions,
                deletions=f.deletions,
                is_changed=(f.additions + f.deletions) > 0,
            )

    # File import edges
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
            sensitivity=_behavioral_sensitivity(fn.filename),
        )
        fn_by_name[fn.name] = qualified

    # Call graph edges
    for fn in parse_result.functions:
        caller = f"{fn.filename}::{fn.name}"
        for called_name in fn.calls:
            callee = fn_by_name.get(called_name)
            if callee and callee != caller:
                bundle.call_graph.add_edge(caller, callee, edge_type="call")

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