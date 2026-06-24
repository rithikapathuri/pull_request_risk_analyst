from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class ImpactCategory(str, Enum):
    CRITICAL  = "critical"   # auth, payment, crypto
    SECONDARY = "secondary"  # services that touch critical
    LOW       = "low"        # UI, logging, tests


class Language(str, Enum):
    PYTHON     = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO         = "go"
    JAVA       = "java"
    UNKNOWN    = "unknown"


# Ingestion

class PRFile(BaseModel):
    filename: str
    status: str               # added | modified | removed | renamed
    additions: int
    deletions: int
    patch: Optional[str] = None
    language: Language = Language.UNKNOWN


class PRInfo(BaseModel):
    owner: str
    repo: str
    number: int
    title: str
    author: str
    base_branch: str
    head_branch: str
    files: list[PRFile] = []
    dependency_files: list[str] = []
    raw_dependencies: dict[str, str] = {}  # {package: version}


class DiffHunk(BaseModel):
    filename: str
    start_line: int
    end_line: int
    added_lines: list[str] = []
    removed_lines: list[str] = []


# Parsing

class FunctionNode(BaseModel):
    name: str
    filename: str
    start_line: int
    end_line: int
    calls: list[str] = []     # function/method names this function calls
    is_changed: bool = False   # overlaps with at least one diff hunk


class SecuritySignal(BaseModel):
    filename: str
    line: int
    signal_type: str           # matches keys in scorer.py SIGNAL_WEIGHTS
    snippet: str
    severity: RiskLevel
    is_ambiguous: bool = False  # True = send to Gemini for second-pass review


class ParseResult(BaseModel):
    functions: list[FunctionNode] = []
    security_signals: list[SecuritySignal] = []
    changed_function_names: list[str] = []
    imports: dict[str, list[str]] = {}  # {filename: [imported module names]}


# CVE / dependencies

class CVERecord(BaseModel):
    cve_id: str
    package: str
    installed_version: str
    severity: RiskLevel
    cvss_score: float = 0.0
    description: str = ""
    vulnerable_functions: list[str] = []
    is_reachable: Optional[bool] = None  # set by reachability module


class DependencyRisk(BaseModel):
    package: str
    version: str
    cves: list[CVERecord] = []
    effective_risk_score: float = 0.0


# Graph / blast radius

class BlastRadius(BaseModel):
    critical_impact: list[str] = []
    secondary_impact: list[str] = []
    low_impact: list[str] = []
    total_affected: int = 0

    @property
    def weighted_score(self) -> float:
        return (
            len(self.critical_impact)  * 1.0 +
            len(self.secondary_impact) * 0.5 +
            len(self.low_impact)       * 0.1
        )


# Risk scores

class RiskBreakdown(BaseModel):
    change_severity:  float = Field(ge=0, le=100)
    blast_radius:     float = Field(ge=0, le=100)
    security_signals: float = Field(ge=0, le=100)
    dependency_risk:  float = Field(ge=0, le=100)
    final_score:      float = Field(ge=0, le=100)
    risk_level:       RiskLevel


class SecuritySignalSummary(BaseModel):
    signal: SecuritySignal
    llm_verdict: Optional[str] = None
    confirmed_risky: bool = True


# LLM outputs

class LLMTriage(BaseModel):
    primary_risk_category: str   # injection | auth | supply_chain | crypto | etc.
    confidence: str              # high | medium | low
    reasoning: str


class LLMExplanation(BaseModel):
    summary: str
    what_could_break: list[str] = []
    attack_surface: str
    severity_justification: str


class LLMRecommendations(BaseModel):
    immediate_fixes: list[str] = []
    longer_term: list[str] = []
    safe_to_merge: bool


# Final result

class PRAnalysisResult(BaseModel):
    pr: PRInfo
    parse_result: ParseResult
    blast_radius: BlastRadius
    dependency_risks: list[DependencyRisk] = []
    risk_breakdown: RiskBreakdown
    security_signal_summaries: list[SecuritySignalSummary] = []
    triage: Optional[LLMTriage] = None
    explanation: Optional[LLMExplanation] = None
    recommendations: Optional[LLMRecommendations] = None


# Benchmark

class BenchmarkCase(BaseModel):
    owner: str
    repo: str
    pr_number: int
    cve_id: str
    expected_risk_level: RiskLevel
    notes: str = ""


class BenchmarkResult(BaseModel):
    case: BenchmarkCase
    predicted_risk_level: RiskLevel
    predicted_score: float
    correct: bool
    analysis: Optional[PRAnalysisResult] = None