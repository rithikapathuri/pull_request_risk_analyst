from __future__ import annotations
import asyncio
import json
import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

from backend.models import BenchmarkCase, BenchmarkResult, RiskLevel

console = Console()

GROUND_TRUTH = Path(__file__).parent.parent / "data/benchmark/ground_truth.json"

RISK_ORDER = {
    RiskLevel.INFO:     0,
    RiskLevel.LOW:      1,
    RiskLevel.MEDIUM:   2,
    RiskLevel.HIGH:     3,
    RiskLevel.CRITICAL: 4,
}


def load_cases(limit: int | None = None) -> list[BenchmarkCase]:
    with open(GROUND_TRUTH) as f:
        return [BenchmarkCase(**c) for c in json.load(f)][:limit]


def _correct(predicted: RiskLevel, expected: RiskLevel) -> bool:
    # Within one severity level counts as correct —> reflects real-world tool tolerance
    return abs(RISK_ORDER[predicted] - RISK_ORDER[expected]) <= 1


async def _run_case(case: BenchmarkCase, run_llm: bool) -> BenchmarkResult:
    from backend.main import run_analysis

    try:
        result = await run_analysis(case.owner, case.repo, case.pr_number, run_llm=run_llm)
        predicted = result.risk_breakdown.risk_level
        return BenchmarkResult(
            case=case,
            predicted_risk_level=predicted,
            predicted_score=result.risk_breakdown.final_score,
            correct=_correct(predicted, case.expected_risk_level),
            analysis=result,
        )
    except Exception as e:
        console.print(f"[red]  failed {case.owner}/{case.repo}#{case.pr_number}: {e}[/red]")
        return BenchmarkResult(
            case=case,
            predicted_risk_level=RiskLevel.INFO,
            predicted_score=0.0,
            correct=False,
        )


async def run(limit: int | None = None, run_llm: bool = False) -> None:
    cases = load_cases(limit)
    console.print(f"\n[bold]Benchmark — {len(cases)} PRs[/bold]\n")

    results: list[BenchmarkResult] = []
    for case in cases:
        console.print(f"  {case.owner}/{case.repo}#{case.pr_number}  ({case.cve_id})")
        r = await _run_case(case, run_llm)
        results.append(r)
        tick = "[green]✓[/green]" if r.correct else "[red]✗[/red]"
        console.print(
            f"  {tick}  predicted={r.predicted_risk_level.value}  "
            f"expected={r.case.expected_risk_level.value}  score={r.predicted_score:.1f}"
        )

    total   = len(results)
    correct = sum(1 for r in results if r.correct)

    high_predicted = sum(
        1 for r in results
        if RISK_ORDER[r.predicted_risk_level] >= RISK_ORDER[RiskLevel.HIGH]
        and RISK_ORDER[r.case.expected_risk_level] >= RISK_ORDER[RiskLevel.HIGH]
    )
    high_actual = sum(
        1 for r in results
        if RISK_ORDER[r.case.expected_risk_level] >= RISK_ORDER[RiskLevel.HIGH]
    )

    precision = correct / total if total else 0.0
    recall    = high_predicted / high_actual if high_actual else 0.0

    table = Table(box=box.SIMPLE, header_style="bold")
    table.add_column("PR")
    table.add_column("CVE")
    table.add_column("Expected")
    table.add_column("Predicted")
    table.add_column("Score", justify="right")
    table.add_column("")

    for r in results:
        table.add_row(
            f"{r.case.owner}/{r.case.repo}#{r.case.pr_number}",
            r.case.cve_id,
            r.case.expected_risk_level.value,
            r.predicted_risk_level.value,
            f"{r.predicted_score:.1f}",
            "[green]✓[/green]" if r.correct else "[red]✗[/red]",
        )

    console.print(table)
    console.print(f"[bold]Precision:[/bold] {precision:.0%}  ({correct}/{total})")
    console.print(f"[bold]Recall:[/bold]    {recall:.0%}  ({high_predicted}/{high_actual} high-risk caught)\n")

    out = Path("data/benchmark/latest_results.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(
        [r.model_dump(exclude={"analysis"}) for r in results],
        indent=2, default=str,
    ))
    console.print(f"results → [dim]{out}[/dim]\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=int, default=None)
    parser.add_argument("--llm",   action="store_true")
    args = parser.parse_args()
    asyncio.run(run(limit=args.cases, run_llm=args.llm))