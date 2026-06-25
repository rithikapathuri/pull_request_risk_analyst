import pytest
import networkx as nx
from backend.scorer import (
    _change_severity, _blast_radius_score, _security_signal_score,
    _dependency_risk_score, _to_risk_level, compute_risk_score,
)
from backend.graph import build_graphs, GraphBundle
from backend.reachability import analyze_reachability, _is_reachable
from backend.models import (
    PRInfo, PRFile, ParseResult, BlastRadius, DependencyRisk,
    CVERecord, SecuritySignal, FunctionNode, RiskLevel, Language,
)


def make_pr(*filenames_and_counts: tuple[str, int, int]) -> PRInfo:
    files = [
        PRFile(filename=fn, status="modified", additions=add, deletions=rem)
        for fn, add, rem in filenames_and_counts
    ]
    return PRInfo(owner="o", repo="r", number=1, title="t", author="a",
                  base_branch="main", head_branch="feat", files=files)


def make_signal(signal_type: str, severity: RiskLevel = RiskLevel.HIGH) -> SecuritySignal:
    return SecuritySignal(filename="f.py", line=1, signal_type=signal_type,
                          snippet="...", severity=severity)


def make_cve(cvss: float, reachable: bool | None = True) -> CVERecord:
    return CVERecord(cve_id="CVE-2024-1", package="pkg", installed_version="1.0",
                     severity=RiskLevel.HIGH, cvss_score=cvss, is_reachable=reachable)


class TestChangeSeverity:
    def test_zero_lines(self):
        assert _change_severity(make_pr(("readme.md", 0, 0))) == 0.0

    def test_sensitive_path_scores_higher(self):
        normal = _change_severity(make_pr(("utils.py", 100, 0)))
        auth   = _change_severity(make_pr(("auth/login.py", 100, 0)))
        assert auth > normal

    def test_caps_at_100(self):
        assert _change_severity(make_pr(("auth.py", 10000, 10000))) == 100.0


class TestBlastRadius:
    def test_empty(self):
        assert _blast_radius_score(BlastRadius()) == 0.0

    def test_critical_outweighs_low(self):
        c = _blast_radius_score(BlastRadius(critical_impact=["a"], total_affected=1))
        l = _blast_radius_score(BlastRadius(low_impact=["a"], total_affected=1))
        assert c > l

    def test_caps_at_100(self):
        br = BlastRadius(critical_impact=[f"s{i}" for i in range(100)], total_affected=100)
        assert _blast_radius_score(br) == 100.0


class TestSignalScore:
    def test_no_signals(self):
        assert _security_signal_score([]) == 0.0

    def test_high_severity_signal(self):
        assert _security_signal_score([make_signal("eval_usage")]) >= 80

    def test_multiple_signals_bounded(self):
        sigs = [make_signal(t) for t in ("eval_usage", "raw_sql", "subprocess")]
        assert _security_signal_score(sigs) <= 100.0

    def test_count_factor_raises_score(self):
        one  = _security_signal_score([make_signal("raw_sql")])
        many = _security_signal_score([make_signal("raw_sql")] * 5)
        assert many > one


class TestDependencyRisk:
    def test_no_deps(self):
        assert _dependency_risk_score([]) == 0.0

    def test_reachable_full_score(self):
        dep = DependencyRisk(package="p", version="1.0", cves=[make_cve(9.0, True)])
        assert _dependency_risk_score([dep]) == 90.0

    def test_unreachable_discounted(self):
        reach   = DependencyRisk(package="p", version="1.0", cves=[make_cve(9.0, True)])
        unreach = DependencyRisk(package="p", version="1.0", cves=[make_cve(9.0, False)])
        assert _dependency_risk_score([unreach]) < _dependency_risk_score([reach])

    def test_none_reachability_is_conservative(self):
        dep = DependencyRisk(package="p", version="1.0", cves=[make_cve(7.0, None)])
        assert _dependency_risk_score([dep]) == 70.0


class TestRiskLevel:
    def test_thresholds(self):
        assert _to_risk_level(85) == RiskLevel.CRITICAL
        assert _to_risk_level(65) == RiskLevel.HIGH
        assert _to_risk_level(40) == RiskLevel.MEDIUM
        assert _to_risk_level(20) == RiskLevel.LOW
        assert _to_risk_level(5)  == RiskLevel.INFO


class TestComputeRiskScore:
    def test_clean_pr(self):
        result = compute_risk_score(
            make_pr(("readme.md", 3, 1)), ParseResult(), BlastRadius(), []
        )
        assert result.final_score < 35

    def test_risky_pr(self):
        signals = [make_signal("eval_usage", RiskLevel.CRITICAL)]
        cve = make_cve(9.8, True)
        dep = DependencyRisk(package="django", version="3.2", cves=[cve])
        blast = BlastRadius(critical_impact=["auth", "payment"], total_affected=5)
        result = compute_risk_score(
            make_pr(("auth/login.py", 300, 100)),
            ParseResult(security_signals=signals),
            blast,
            [dep],
        )
        assert result.final_score >= 60
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


class TestGraphBuilder:
    def _make_parse_result(self) -> ParseResult:
        return ParseResult(
            functions=[
                FunctionNode(name="login", filename="auth.py",
                             start_line=1, end_line=10, calls=["check_password"], is_changed=True),
                FunctionNode(name="check_password", filename="auth.py",
                             start_line=12, end_line=20, calls=[], is_changed=False),
            ],
            imports={"auth.py": ["hashlib", "models"]},
            changed_function_names=["login"],
        )

    def test_call_graph_nodes(self):
        pr = make_pr(("auth.py", 10, 2))
        graphs = build_graphs(self._make_parse_result(), pr.files)
        assert graphs.call_graph.number_of_nodes() == 2

    def test_call_graph_edge(self):
        pr = make_pr(("auth.py", 10, 2))
        graphs = build_graphs(self._make_parse_result(), pr.files)
        assert graphs.call_graph.number_of_edges() == 1

    def test_blast_radius_follows_calls(self):
        pr = make_pr(("auth.py", 10, 2))
        graphs = build_graphs(self._make_parse_result(), pr.files)
        # call graph nodes are "filename::function_name"
        blast = graphs.compute_blast_radius(["auth.py::login"])
        assert blast.total_affected >= 1

    def test_empty_parse_result(self):
        pr = make_pr(("utils.py", 5, 0))
        graphs = build_graphs(ParseResult(), pr.files)
        blast = graphs.compute_blast_radius([])
        assert blast.total_affected == 0


class TestReachability:
    def _make_graph(self) -> nx.DiGraph:
        g = nx.DiGraph()
        g.add_edge("app.py::route", "auth.py::login")
        g.add_edge("auth.py::login", "db.py::execute")
        return g

    def test_reachable(self):
        g = self._make_graph()
        assert _is_reachable(g, ["route"], ["execute"]) is True

    def test_not_reachable(self):
        g = self._make_graph()
        assert _is_reachable(g, ["route"], ["unrelated_fn"]) is False

    def test_empty_graph_conservative(self):
        # No call graph data —> should return True (conservative)
        assert _is_reachable(nx.DiGraph(), ["anything"], ["vuln_fn"]) is True

    def test_analyze_reachability_sets_flag(self):
        g = self._make_graph()
        cve = CVERecord(cve_id="CVE-x", package="pkg", installed_version="1.0",
                        severity=RiskLevel.HIGH, cvss_score=8.0)
        dep = DependencyRisk(package="pkg", version="1.0", cves=[cve],
                             effective_risk_score=80.0)
        parse_result = ParseResult(changed_function_names=["route"])
        # pkg not in KNOWN_VULNERABLE_FUNCTIONS -> is_reachable stays True (conservative)
        result = analyze_reachability([dep], parse_result, g)
        assert result[0].cves[0].is_reachable is True