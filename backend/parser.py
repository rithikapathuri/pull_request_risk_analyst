from __future__ import annotations
import ast
import re
from pathlib import Path

from backend.models import (
    PRFile, DiffHunk, ParseResult, FunctionNode, SecuritySignal, RiskLevel,
)


SIGNAL_SEVERITY: dict[str, tuple[RiskLevel, bool]] = {
    # (severity, is_ambiguous)
    "eval_usage":            (RiskLevel.CRITICAL, False),
    "exec_usage":            (RiskLevel.CRITICAL, False),
    "compile_usage":         (RiskLevel.HIGH,     False),
    "raw_sql":               (RiskLevel.HIGH,     True),
    "subprocess":            (RiskLevel.HIGH,     True),
    "os_system":             (RiskLevel.HIGH,     False),
    "deserialization":       (RiskLevel.HIGH,     False),
    "path_traversal":        (RiskLevel.HIGH,     True),
    "hardcoded_secret":      (RiskLevel.CRITICAL, False),
    "hardcoded_token":       (RiskLevel.CRITICAL, False),
    "weak_hash":             (RiskLevel.HIGH,     False),
    "weak_random":           (RiskLevel.HIGH,     False),
    "xxe":                   (RiskLevel.HIGH,     False),
    "ssrf":                  (RiskLevel.HIGH,     True),
    "template_injection":    (RiskLevel.HIGH,     True),
    "insecure_cookie":       (RiskLevel.MEDIUM,   False),
    "open_redirect":         (RiskLevel.MEDIUM,   True),
    "crypto_modified":       (RiskLevel.MEDIUM,   True),
    "auth_modified":         (RiskLevel.MEDIUM,   True),
    "weak_cipher":           (RiskLevel.HIGH,     False),
    "globals_usage":         (RiskLevel.MEDIUM,   True),
    # Deletion signals —> security controls being removed
    "security_control_removed": (RiskLevel.HIGH,  False),
    "auth_check_removed":       (RiskLevel.CRITICAL, False),
    # IaC signals
    "iac_privileged_container": (RiskLevel.HIGH,  False),
    "iac_root_user":            (RiskLevel.HIGH,  False),
    "iac_secret_in_env":        (RiskLevel.CRITICAL, False),
    "iac_dangerous_workflow":   (RiskLevel.HIGH,  True),
    "iac_exposed_port":         (RiskLevel.MEDIUM, True),
}

REGEX_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(
        r'(?:password|passwd|pwd|secret|api_key|apikey|token|auth_token)\s*=\s*["\'][^"\']{6,}["\']',
        re.IGNORECASE,
    ), "hardcoded_secret"),
    (re.compile(r'Bearer\s+[A-Za-z0-9\-_.]{20,}', re.IGNORECASE), "hardcoded_token"),
    (re.compile(
        r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s.*?(?:%s|%\(|\+\s*[a-zA-Z]|\.format\(|f["\'].*?\{)',
        re.IGNORECASE,
    ), "raw_sql"),
    (re.compile(r'cursor\.execute\s*\(\s*["\'].*?%[sd]', re.IGNORECASE), "raw_sql"),
    (re.compile(r'subprocess\.\w+\s*\(.*?shell\s*=\s*True', re.IGNORECASE | re.DOTALL), "subprocess"),
    (re.compile(r'os\.system\s*\(', re.IGNORECASE), "os_system"),
    (re.compile(r'pickle\.loads?\s*\(', re.IGNORECASE), "deserialization"),
    (re.compile(r'yaml\.load\s*\([^,)]+\)', re.IGNORECASE), "deserialization"),
    (re.compile(r'marshal\.loads?\s*\(', re.IGNORECASE), "deserialization"),
    (re.compile(r'jsonpickle\.decode\s*\(', re.IGNORECASE), "deserialization"),
    (re.compile(r'hashlib\.(?:md5|sha1)\s*\(', re.IGNORECASE), "weak_hash"),
    (re.compile(r'(?:MD5|SHA1)\s*\(', re.IGNORECASE), "weak_hash"),
    (re.compile(r'\brandom\.(?:random|randint|choice|seed)\b'), "weak_random"),
    (re.compile(r'\b(?:DES|RC4|Blowfish|ArcFour)\b', re.IGNORECASE), "weak_cipher"),
    (re.compile(r'(?:etree|ElementTree|minidom|expat).*?parse\s*\(', re.IGNORECASE), "xxe"),
    (re.compile(r'os\.path\.join\s*\(.*?(?:request\.|input\.|param|user_)', re.IGNORECASE | re.DOTALL), "path_traversal"),
    (re.compile(r'\bopen\s*\(.*?(?:request\.|input\.|param|user_)', re.IGNORECASE | re.DOTALL), "path_traversal"),
    (re.compile(r'render_template_string\s*\(.*?\+', re.IGNORECASE), "template_injection"),
    (re.compile(r'Environment\s*\(.*?BaseLoader', re.IGNORECASE | re.DOTALL), "template_injection"),
    (re.compile(r'(?:requests|httpx|urllib)\.\w+\s*\(.*?(?:request\.|input\.|param|user_)', re.IGNORECASE | re.DOTALL), "ssrf"),
    (re.compile(r'document\.cookie\s*=(?!.*(?:Secure|HttpOnly))', re.IGNORECASE), "insecure_cookie"),
    (re.compile(r'res\.cookie\s*\([^)]+\)(?!.*(?:secure\s*:|httpOnly\s*:))', re.IGNORECASE), "insecure_cookie"),
    (re.compile(r'\bimport\s+(?:cryptography|Crypto|nacl|bcrypt)\b', re.IGNORECASE), "crypto_modified"),
]

# Function names that indicate removal of security control when deleted
AUTH_CHECK_PATTERNS = re.compile(
    r'\b(?:check_permission|require_auth|login_required|permission_required|'
    r'verify_token|authenticate|authorize|check_auth|enforce_policy|'
    r'validate_token|is_authenticated|has_permission|check_access|'
    r'verify_signature|csrf_protect|rate_limit)\s*[\(\.]',
    re.IGNORECASE,
)

SECURITY_CONTROL_PATTERNS = re.compile(
    r'\b(?:validate|sanitize|escape|encode|filter|check|verify|assert_|'
    r'require|enforce|guard|protect|secure)\w*\s*\(',
    re.IGNORECASE,
)

SENSITIVE_AUTH_PATHS = {
    "auth", "login", "logout", "signin", "signup", "oauth",
    "jwt", "session", "password", "credential", "permission",
    "role", "privilege", "admin", "token",
}

# IaC patterns —> applied to YAML, Dockerfile, and GitHub Actions files
IAC_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'privileged\s*:\s*true', re.IGNORECASE), "iac_privileged_container"),
    (re.compile(r'runAsUser\s*:\s*0\b'), "iac_root_user"),
    (re.compile(r'USER\s+root\b', re.IGNORECASE), "iac_root_user"),
    (re.compile(r'--privileged'), "iac_privileged_container"),
    (re.compile(
        r'(?:AWS_SECRET|GITHUB_TOKEN|API_KEY|SECRET_KEY|PRIVATE_KEY)\s*[=:]\s*\S+',
        re.IGNORECASE,
    ), "iac_secret_in_env"),
    (re.compile(r'curl\s+.*?\|\s*(?:bash|sh)\b', re.IGNORECASE), "iac_dangerous_workflow"),
    (re.compile(r'wget\s+.*?-O\s*-\s*\|\s*(?:bash|sh)\b', re.IGNORECASE), "iac_dangerous_workflow"),
    (re.compile(r'run:\s*\|?\s*\n?\s*(?:curl|wget).*?\|\s*(?:bash|sh)', re.IGNORECASE | re.DOTALL), "iac_dangerous_workflow"),
    (re.compile(r'EXPOSE\s+(?:22|23|3389|5900)\b'), "iac_exposed_port"),
]

IAC_EXTENSIONS = {".yml", ".yaml", ".dockerfile", ".tf", ".toml"}
IAC_FILENAMES = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}


def _make_signal(
    filename: str,
    line: int,
    signal_type: str,
    snippet: str,
    is_deletion: bool = False,
) -> SecuritySignal:
    severity, ambiguous = SIGNAL_SEVERITY.get(signal_type, (RiskLevel.MEDIUM, False))
    return SecuritySignal(
        filename=filename,
        line=line,
        signal_type=signal_type,
        snippet=snippet[:120],
        severity=severity,
        is_ambiguous=ambiguous,
        is_deletion=is_deletion,
    )


def _line_in_hunks(lineno: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= lineno <= end for start, end in ranges)


def _scan_deleted_lines(filename: str, hunks: list[DiffHunk]) -> list[SecuritySignal]:
    """
    Scans removed lines for security controls being deleted
    A deleted auth check or validation call is high-risk even when
    no new dangerous code is added
    """
    signals: list[SecuritySignal] = []
    seen: set[tuple[int, str]] = set()

    for hunk in hunks:
        for i, line in enumerate(hunk.removed_lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            line_num = hunk.start_line + i

            if AUTH_CHECK_PATTERNS.search(stripped):
                key = (line_num, "auth_check_removed")
                if key not in seen:
                    signals.append(_make_signal(filename, line_num, "auth_check_removed", stripped, is_deletion=True))
                    seen.add(key)
            elif SECURITY_CONTROL_PATTERNS.search(stripped):
                key = (line_num, "security_control_removed")
                if key not in seen:
                    signals.append(_make_signal(filename, line_num, "security_control_removed", stripped, is_deletion=True))
                    seen.add(key)

    return signals


def _scan_iac(filename: str, hunks: list[DiffHunk]) -> list[SecuritySignal]:
    """
    Scans YAML, Dockerfile, and Terraform added lines for insecure configurations
    These files are invisible to AST parsers but carry serious risk
    """
    signals: list[SecuritySignal] = []
    seen: set[tuple[int, str]] = set()

    for hunk in hunks:
        for i, line in enumerate(hunk.added_lines):
            stripped = line.strip()
            if not stripped:
                continue
            line_num = hunk.start_line + i
            for pattern, signal_type in IAC_PATTERNS:
                if pattern.search(stripped):
                    key = (line_num, signal_type)
                    if key not in seen:
                        signals.append(_make_signal(filename, line_num, signal_type, stripped))
                        seen.add(key)
                    break

    return signals


class PythonASTParser(ast.NodeVisitor):
    def __init__(self, filename: str, source_lines: list[str], hunk_ranges: list[tuple[int, int]]):
        self.filename = filename
        self.source_lines = source_lines
        self.hunk_ranges = hunk_ranges
        self.functions: list[FunctionNode] = []
        self.signals: list[SecuritySignal] = []
        self._current_fn: FunctionNode | None = None

    def _snippet(self, lineno: int) -> str:
        idx = lineno - 1
        return self.source_lines[idx].strip() if 0 <= idx < len(self.source_lines) else ""

    def _in_hunk(self, lineno: int) -> bool:
        return _line_in_hunks(lineno, self.hunk_ranges)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        fn = FunctionNode(
            name=node.name,
            filename=self.filename,
            start_line=node.lineno,
            end_line=node.end_lineno or node.lineno,
            is_changed=any(
                start <= node.lineno <= end or start <= (node.end_lineno or node.lineno) <= end
                for start, end in self.hunk_ranges
            ),
        )
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    fn.calls.append(child.func.attr)
                elif isinstance(child.func, ast.Name):
                    fn.calls.append(child.func.id)

        prev = self._current_fn
        self._current_fn = fn
        self.functions.append(fn)
        self.generic_visit(node)
        self._current_fn = prev

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call):
        if not self._in_hunk(node.lineno):
            self.generic_visit(node)
            return

        lineno = node.lineno
        snippet = self._snippet(lineno)

        if isinstance(node.func, ast.Name):
            name = node.func.id
            if name == "eval":
                self.signals.append(_make_signal(self.filename, lineno, "eval_usage", snippet))
            elif name == "exec":
                self.signals.append(_make_signal(self.filename, lineno, "exec_usage", snippet))
            elif name == "compile":
                self.signals.append(_make_signal(self.filename, lineno, "compile_usage", snippet))

        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            obj = node.func.value.id if isinstance(node.func.value, ast.Name) else ""

            if obj == "pickle" and attr in ("loads", "load"):
                self.signals.append(_make_signal(self.filename, lineno, "deserialization", snippet))
            elif obj == "marshal" and attr in ("loads", "load"):
                self.signals.append(_make_signal(self.filename, lineno, "deserialization", snippet))
            elif obj == "yaml" and attr == "load":
                if not any(kw.arg == "Loader" for kw in node.keywords):
                    self.signals.append(_make_signal(self.filename, lineno, "deserialization", snippet))
            elif obj == "os" and attr == "system":
                self.signals.append(_make_signal(self.filename, lineno, "os_system", snippet))
            elif obj == "subprocess":
                shell_true = any(
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                    for kw in node.keywords
                )
                if shell_true:
                    self.signals.append(_make_signal(self.filename, lineno, "subprocess", snippet))
            elif obj == "hashlib" and attr in ("md5", "sha1"):
                self.signals.append(_make_signal(self.filename, lineno, "weak_hash", snippet))
            elif obj == "random" and attr in ("random", "randint", "choice", "seed"):
                self.signals.append(_make_signal(self.filename, lineno, "weak_random", snippet))

        self.generic_visit(node)


def _parse_python(
    filename: str,
    source: str,
    hunk_ranges: list[tuple[int, int]],
) -> tuple[list[FunctionNode], list[SecuritySignal]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [], []

    lines = source.splitlines()
    visitor = PythonASTParser(filename, lines, hunk_ranges)
    visitor.visit(tree)

    signals = list(visitor.signals)
    seen = {(s.line, s.signal_type) for s in signals}

    for lineno, raw_line in enumerate(lines, start=1):
        if not _line_in_hunks(lineno, hunk_ranges):
            continue
        if raw_line.strip().startswith("#"):
            continue
        for pattern, signal_type in REGEX_PATTERNS:
            if pattern.search(raw_line):
                key = (lineno, signal_type)
                if key not in seen:
                    signals.append(_make_signal(filename, lineno, signal_type, raw_line.strip()))
                    seen.add(key)
                break

    return visitor.functions, signals


def _parse_js_ts(
    filename: str,
    source: str,
    hunk_ranges: list[tuple[int, int]],
) -> tuple[list[FunctionNode], list[SecuritySignal]]:
    lines = source.splitlines()
    functions: list[FunctionNode] = []
    signals: list[SecuritySignal] = []
    seen: set[tuple[int, str]] = set()

    fn_pattern = re.compile(
        r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[\w]+)\s*=>|\b(\w+)\s*\([^)]*\)\s*\{)',
    )

    for lineno, line in enumerate(lines, start=1):
        m = fn_pattern.search(line)
        if m:
            name = m.group(1) or m.group(2) or m.group(3)
            if name and name not in {"if", "for", "while", "switch", "catch"}:
                functions.append(FunctionNode(
                    name=name,
                    filename=filename,
                    start_line=lineno,
                    end_line=lineno,
                    is_changed=_line_in_hunks(lineno, hunk_ranges),
                ))

        if not _line_in_hunks(lineno, hunk_ranges):
            continue
        if line.strip().startswith(("//", "*")):
            continue

        for pattern, signal_type in REGEX_PATTERNS:
            if pattern.search(line):
                key = (lineno, signal_type)
                if key not in seen:
                    signals.append(_make_signal(filename, lineno, signal_type, line.strip()))
                    seen.add(key)
                break

    return functions, signals


def _extract_imports(filename: str, source: str) -> list[str]:
    imports: list[str] = []
    ext = Path(filename).suffix.lower()

    if ext == ".py":
        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.append(node.module.split(".")[0])
        except SyntaxError:
            pass
    else:
        for m in re.finditer(r'(?:require\s*\(\s*["\']|from\s+["\'])([^"\']+)', source):
            mod = m.group(1).split("/")[0].lstrip("@").strip()
            if mod:
                imports.append(mod)

    return list(set(imports))


def _is_iac_file(filename: str) -> bool:
    p = Path(filename)
    return p.suffix.lower() in IAC_EXTENSIONS or p.name in IAC_FILENAMES or "github/workflows" in filename.lower()


def parse_pr(files: list[PRFile], hunks: list[DiffHunk]) -> ParseResult:
    """
    Parses changed files and extracts:
    - Function nodes and call relationships (for call graph)
    - Security signals from ADDED lines (new vulnerabilities introduced)
    - Security signals from DELETED lines (security controls being removed)
    - IaC signals from config/workflow files
    - Raw patches per file passed through to the LLM for full diff context
    """
    all_functions: list[FunctionNode] = []
    all_signals: list[SecuritySignal] = []
    all_imports: dict[str, list[str]] = {}
    changed_fn_names: list[str] = []
    file_patches: dict[str, str] = {}

    for f in files:
        if not f.patch:
            continue

        # Always store the raw patch so the LLM gets full diff context
        file_patches[f.filename] = f.patch

        file_hunks = [h for h in hunks if h.filename == f.filename]
        hunk_ranges = [(h.start_line, h.end_line) for h in file_hunks]

        # Scan deleted lines for removed security controls —> applies to all file types
        if f.status != "added":
            deletion_signals = _scan_deleted_lines(f.filename, file_hunks)
            all_signals.extend(deletion_signals)

        # IaC files get their own scanner
        if _is_iac_file(f.filename):
            all_signals.extend(_scan_iac(f.filename, file_hunks))
            continue

        ext = Path(f.filename).suffix.lower()
        if ext not in {".py", ".js", ".ts", ".mjs", ".tsx"}:
            if any(kw in f.filename.lower() for kw in SENSITIVE_AUTH_PATHS):
                all_signals.append(_make_signal(f.filename, 0, "auth_modified", f.filename))
            continue

        if f.status == "removed":
            continue

        # Build partial source from added lines for AST/regex analysis
        partial_source = "\n".join(
            line for h in file_hunks for line in h.added_lines
        )
        if not partial_source.strip():
            continue

        if ext == ".py":
            fns, sigs = _parse_python(f.filename, partial_source, hunk_ranges)
        else:
            fns, sigs = _parse_js_ts(f.filename, partial_source, hunk_ranges)

        if any(kw in f.filename.lower() for kw in SENSITIVE_AUTH_PATHS):
            sigs.append(_make_signal(f.filename, 0, "auth_modified", f.filename))

        all_functions.extend(fns)
        all_signals.extend(sigs)
        all_imports[f.filename] = _extract_imports(f.filename, partial_source)
        changed_fn_names.extend(fn.name for fn in fns if fn.is_changed)

    # Deduplicate by (filename, line, type, is_deletion)
    seen: set[tuple[str, int, str, bool]] = set()
    unique_signals: list[SecuritySignal] = []
    for s in all_signals:
        key = (s.filename, s.line, s.signal_type, s.is_deletion)
        if key not in seen:
            unique_signals.append(s)
            seen.add(key)

    return ParseResult(
        functions=all_functions,
        security_signals=unique_signals,
        changed_function_names=list(set(changed_fn_names)),
        imports=all_imports,
        file_patches=file_patches,
    )