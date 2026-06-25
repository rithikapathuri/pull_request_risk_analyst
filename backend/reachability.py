from __future__ import annotations

import networkx as nx

from backend.config import get_settings
from backend.models import DependencyRisk, ParseResult

settings = get_settings()

# Known vulnerable functions per package — built from public CVE disclosures
# Format: package_name -> list of function names that were vulnerable
KNOWN_VULNERABLE_FUNCTIONS: dict[str, list[str]] = {
    "lodash":        ["merge", "set", "setWith", "defaultsDeep"],  # prototype pollution
    "pyyaml":        ["load"],                                      # unsafe deserialization
    "PyYAML":        ["load"],
    "requests":      ["get", "post", "request", "send"],           # older SSRF / header leak
    "django":        ["raw", "extra", "execute"],                   # SQL injection surfaces
    "flask":         ["make_response", "redirect"],                 # open redirect / cookie
    "jinja2":        ["from_string", "Environment"],                # SSTI
    "pillow":        ["open"],                                      # image bomb / overflow
    "cryptography":  ["encrypt", "decrypt"],
    "paramiko":      ["connect", "exec_command"],
    "urllib3":       ["request", "urlopen"],
    "werkzeug":      ["check_password_hash", "generate_password_hash"],
    "sqlalchemy":    ["execute", "text"],                           # raw SQL via text()
}


def _get_vulnerable_functions(package: str) -> list[str]:
    """
    Returns known vulnerable function names for a package.
    Normalises casing — PyPI names are case-insensitive.
    """
    return (
        KNOWN_VULNERABLE_FUNCTIONS.get(package)
        or KNOWN_VULNERABLE_FUNCTIONS.get(package.lower())
        or []
    )


def _is_reachable(
    call_graph: nx.DiGraph,
    changed_functions: list[str],
    vulnerable_fns: list[str],
) -> bool:
    """
    DFS from each changed function node.
    Returns True if any path reaches a node whose bare function name
    matches one of the vulnerable function names.

    Node names in call_graph are "filename::function_name".
    """
    if not changed_functions or not vulnerable_fns:
        return True

    # No graph data at all — stay conservative
    if call_graph.number_of_nodes() == 0:
        return True

    vuln_set = set(vulnerable_fns)

    for start_name in changed_functions:
        matching_nodes = [
            n for n in call_graph.nodes
            if n.endswith(f"::{start_name}") or n == start_name
        ]
        for start_node in matching_nodes:
            reachable = nx.descendants(call_graph, start_node)
            reachable.add(start_node)
            for node in reachable:
                bare = node.split("::")[-1] if "::" in node else node
                if bare in vuln_set:
                    return True

    return False


def analyze_reachability(
    dependency_risks: list[DependencyRisk],
    parse_result: ParseResult,
    call_graph: nx.DiGraph,
) -> list[DependencyRisk]:
    """
    For each CVE, determines whether a known-vulnerable function is
    reachable from the changed code via the call graph.

    If not reachable, the CVE's contribution to the risk score is
    multiplied by settings.reachability_discount (default 0.15) in scorer.py
    rather than dropped entirely — the dep is still present in the codebase.
    """
    changed_fns = parse_result.changed_function_names

    for dep in dependency_risks:
        vuln_fns = _get_vulnerable_functions(dep.package)

        for cve in dep.cves:
            # Prefer CVE-specific function list if we have it, fall back to package-level
            fns_to_check = cve.vulnerable_functions or vuln_fns

            if not fns_to_check:
                # No function-level data for this CVE — stay conservative
                cve.is_reachable = True
                continue

            cve.vulnerable_functions = fns_to_check
            cve.is_reachable = _is_reachable(call_graph, changed_fns, fns_to_check)

    return dependency_risks