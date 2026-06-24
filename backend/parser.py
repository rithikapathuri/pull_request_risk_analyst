from __future__ import annotations
import ast
import re
from pathlib import Path

from backend.models import (
    PRFile, DiffHunk, ParseResult, FunctionNode, SecuritySignal, RiskLevel, Language,
)


SIGNAL_SEVERITY: dict[str, tuple[RiskLevel, bool]] = {
    # (severity, is_ambiguous)
    "eval_usage":         (RiskLevel.CRITICAL, False),
    "exec_usage":         (RiskLevel.CRITICAL, False),
    "compile_usage":      (RiskLevel.HIGH,     False),
    "raw_sql":            (RiskLevel.HIGH,     True),
    "subprocess":         (RiskLevel.HIGH,     True),
    "os_system":          (RiskLevel.HIGH,     False),
    "deserialization":    (RiskLevel.HIGH,     False),
    "path_traversal":     (RiskLevel.HIGH,     True),
    "hardcoded_secret":   (RiskLevel.CRITICAL, False),
    "hardcoded_token":    (RiskLevel.CRITICAL, False),
    "weak_hash":          (RiskLevel.HIGH,     False),
    "weak_random":        (RiskLevel.HIGH,     False),
    "xxe":                (RiskLevel.HIGH,     False),
    "ssrf":               (RiskLevel.HIGH,     True),
    "template_injection": (RiskLevel.HIGH,     True),
    "insecure_cookie":    (RiskLevel.MEDIUM,   False),
    "open_redirect":      (RiskLevel.MEDIUM,   True),
    "crypto_modified":    (RiskLevel.MEDIUM,   True),
    "auth_modified":      (RiskLevel.MEDIUM,   True),
    "weak_cipher":        (RiskLevel.HIGH,     False),
    "globals_usage":      (RiskLevel.MEDIUM,   True),
}

# Regex patterns applied line by line to raw source
# Ordered most-specific first to avoid double-flagging one line
REGEX_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Hardcoded secrets
    (re.compile(
        r'(?:password|passwd|pwd|secret|api_key|apikey|token|auth_token)\s*=\s*["\'][^"\']{6,}["\']',
        re.IGNORECASE,
    ), "hardcoded_secret"),
    (re.compile(r'Bearer\s+[A-Za-z0-9\-_.]{20,}', re.IGNORECASE), "hardcoded_token"),

    # Raw SQL via string formatting
    (re.compile(
        r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s.*?(?:%s|%\(|\+\s*[a-zA-Z]|\.format\(|f["\'].*?\{)',
        re.IGNORECASE,
    ), "raw_sql"),
    (re.compile(r'cursor\.execute\s*\(\s*["\'].*?%[sd]', re.IGNORECASE), "raw_sql"),

    # subprocess / shell injection
    (re.compile(r'subprocess\.\w+\s*\(.*?shell\s*=\s*True', re.IGNORECASE | re.DOTALL), "subprocess"),
    (re.compile(r'os\.system\s*\(', re.IGNORECASE), "os_system"),

    # Unsafe deserialization
    (re.compile(r'pickle\.loads?\s*\(', re.IGNORECASE), "deserialization"),
    (re.compile(r'yaml\.load\s*\([^,)]+\)', re.IGNORECASE), "deserialization"),  # no Loader= arg
    (re.compile(r'marshal\.loads?\s*\(', re.IGNORECASE), "deserialization"),
    (re.compile(r'jsonpickle\.decode\s*\(', re.IGNORECASE), "deserialization"),

    # Weak crypto
    (re.compile(r'hashlib\.(?:md5|sha1)\s*\(', re.IGNORECASE), "weak_hash"),
    (re.compile(r'(?:MD5|SHA1)\s*\(', re.IGNORECASE), "weak_hash"),
    (re.compile(r'\brandom\.(?:random|randint|choice|seed)\b'), "weak_random"),
    (re.compile(r'DES|RC4|Blowfish|ArcFour', re.IGNORECASE), "weak_cipher"),

    # XML external entity
    (re.compile(r'(?:etree|ElementTree|minidom|expat).*?parse\s*\(', re.IGNORECASE), "xxe"),

    # Path traversal
    (re.compile(r'os\.path\.join\s*\(.*?(?:request\.|input\.|param|user_)', re.IGNORECASE | re.DOTALL), "path_traversal"),
    (re.compile(r'\bopen\s*\(.*?(?:request\.|input\.|param|user_)', re.IGNORECASE | re.DOTALL), "path_traversal"),

    # Server-side template injection
    (re.compile(r'render_template_string\s*\(.*?\+', re.IGNORECASE), "template_injection"),
    (re.compile(r'Environment\s*\(.*?BaseLoader', re.IGNORECASE | re.DOTALL), "template_injection"),

    # SSRF
    (re.compile(r'(?:requests|httpx|urllib)\.\w+\s*\(.*?(?:request\.|input\.|param|user_)', re.IGNORECASE | re.DOTALL), "ssrf"),

    # Insecure cookies (JS/TS)
    (re.compile(r'document\.cookie\s*=(?!.*(?:Secure|HttpOnly))', re.IGNORECASE), "insecure_cookie"),
    (re.compile(r'res\.cookie\s*\([^)]+\)(?!.*(?:secure\s*:|httpOnly\s*:))', re.IGNORECASE), "insecure_cookie"),

    # Crypto imports in changed file
    (re.compile(r'\bimport\s+(?:cryptography|Crypto|nacl|bcrypt)\b', re.IGNORECASE), "crypto_modified"),
]

SENSITIVE_AUTH_PATHS = {
    "auth", "login", "logout", "signin", "signup", "oauth",
    "jwt", "session", "password", "credential", "permission",
    "role", "privilege", "admin", "token",
}


def _make_signal(filename: str, line: int, signal_type: str, snippet: str) -> SecuritySignal:
    severity, ambiguous = SIGNAL_SEVERITY.get(signal_type, (RiskLevel.MEDIUM, False))
    return SecuritySignal(
        filename=filename,
        line=line,
        signal_type=signal_type,
        snippet=snippet[:120],
        severity=severity,
        is_ambiguous=ambiguous,
    )


def _hunk_line_ranges(hunks: list[DiffHunk], filename: str) -> list[tuple[int, int]]:
    return [(h.start_line, h.end_line) for h in hunks if h.filename == filename]


def _line_in_hunks(lineno: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= lineno <= end for start, end in ranges)


class PythonASTParser(ast.NodeVisitor):
    """
    Walks a Python AST and collects function nodes and security signals.
    Only emits signals for lines that overlap with changed diff hunks.
    """

    def __init__(self, filename: str, source_lines: list[str], hunk_ranges: list[tuple[int, int]]):
        self.filename = filename
        self.source_lines = source_lines
        self.hunk_ranges = hunk_ranges
        self.functions: list[FunctionNode] = []
        self.signals: list[SecuritySignal] = []
        self._current_fn: Optional[FunctionNode] = None

    def _snippet(self, lineno: int) -> str:
        idx = lineno - 1
        if 0 <= idx < len(self.source_lines):
            return self.source_lines[idx].strip()
        return ""

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
        # Collect calls made inside this function
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

        # eval() / exec() / compile()
        if isinstance(node.func, ast.Name):
            if node.func.id == "eval":
                self.signals.append(self._make(lineno, "eval_usage", snippet))
            elif node.func.id == "exec":
                self.signals.append(self._make(lineno, "exec_usage", snippet))
            elif node.func.id == "compile":
                self.signals.append(self._make(lineno, "compile_usage", snippet))

        # Attribute calls: pickle.loads, yaml.load, os.system, subprocess.*, etc
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            obj = node.func.value.id if isinstance(node.func.value, ast.Name) else ""

            if obj == "pickle" and attr in ("loads", "load"):
                self.signals.append(self._make(lineno, "deserialization", snippet))
            elif obj == "marshal" and attr in ("loads", "load"):
                self.signals.append(self._make(lineno, "deserialization", snippet))
            elif obj == "yaml" and attr == "load":
                # yaml.load(x) without Loader= kwarg is unsafe
                has_loader = any(
                    kw.arg == "Loader" for kw in node.keywords
                )
                if not has_loader:
                    self.signals.append(self._make(lineno, "deserialization", snippet))
            elif obj == "os" and attr == "system":
                self.signals.append(self._make(lineno, "os_system", snippet))
            elif obj == "subprocess":
                # Flag only when shell=True is passed
                shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                if shell_true:
                    self.signals.append(self._make(lineno, "subprocess", snippet))
            elif obj == "hashlib" and attr in ("md5", "sha1"):
                self.signals.append(self._make(lineno, "weak_hash", snippet))
            elif obj == "random" and attr in ("random", "randint", "choice", "seed"):
                self.signals.append(self._make(lineno, "weak_random", snippet))

        self.generic_visit(node)

    def _make(self, line: int, signal_type: str, snippet: str) -> SecuritySignal:
        return _make_signal(self.filename, line, signal_type, snippet)


def _parse_python(filename: str, source: str, hunk_ranges: list[tuple[int, int]]) -> tuple[list[FunctionNode], list[SecuritySignal]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [], []

    lines = source.splitlines()
    visitor = PythonASTParser(filename, lines, hunk_ranges)
    visitor.visit(tree)

    # Regex pass on changed lines only — catches patterns AST misses
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
                break  # one signal per line to avoid noise

    return visitor.functions, signals


def _parse_js_ts(filename: str, source: str, hunk_ranges: list[tuple[int, int]]) -> tuple[list[FunctionNode], list[SecuritySignal]]:
    """
    JS/TS parser using regex — no AST library required.
    Extracts function names and applies security signal patterns to changed lines.
    """
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
                in_hunk = _line_in_hunks(lineno, hunk_ranges)
                functions.append(FunctionNode(
                    name=name,
                    filename=filename,
                    start_line=lineno,
                    end_line=lineno,
                    is_changed=in_hunk,
                ))

        if not _line_in_hunks(lineno, hunk_ranges):
            continue
        if line.strip().startswith("//") or line.strip().startswith("*"):
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
    """Extract imported module names from Python or JS/TS source."""
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
        # JS/TS: match require() and import statements
        for m in re.finditer(r'(?:require\s*\(\s*["\']|from\s+["\'])([^"\']+)', source):
            mod = m.group(1).split("/")[0].lstrip("@").strip()
            if mod:
                imports.append(mod)

    return list(set(imports))


def parse_pr(files: list[PRFile], hunks: list[DiffHunk]) -> ParseResult:
    """
    Entry point for the parsing pipeline.

    For each changed file:
      1. Reconstruct source from diff hunks (added lines only — we don't
         have full file content here, only the patch)
      2. Run AST parser (Python) or regex parser (JS/TS)
      3. Collect security signals only from changed line ranges
      4. Mark functions whose body overlaps with any changed hunk
    """
    all_functions: list[FunctionNode] = []
    all_signals: list[SecuritySignal] = []
    all_imports: dict[str, list[str]] = {}
    changed_fn_names: list[str] = []

    for f in files:
        if f.status == "removed" or not f.patch:
            continue

        ext = Path(f.filename).suffix.lower()
        if ext not in {".py", ".js", ".ts", ".mjs", ".tsx"}:
            # Check for auth_modified signal based on filename alone
            path_lower = f.filename.lower()
            if any(kw in path_lower for kw in SENSITIVE_AUTH_PATHS):
                all_signals.append(_make_signal(f.filename, 0, "auth_modified", f.filename))
            continue

        # Reconstruct approximate source from added lines in the patch
        file_hunks = [h for h in hunks if h.filename == f.filename]
        hunk_ranges = [(h.start_line, h.end_line) for h in file_hunks]

        # Build a partial source from what we have in the patch for analysis
        # We use all added lines joined —> enough for AST patterns on changed code
        # Graph builder uses full file content
        partial_source = "\n".join(
            line
            for h in file_hunks
            for line in h.added_lines
        )

        if not partial_source.strip():
            continue

        if ext == ".py":
            fns, sigs = _parse_python(f.filename, partial_source, hunk_ranges)
        else:
            fns, sigs = _parse_js_ts(f.filename, partial_source, hunk_ranges)

        imports = _extract_imports(f.filename, partial_source)

        # Auth-modified signal based on filename
        path_lower = f.filename.lower()
        if any(kw in path_lower for kw in SENSITIVE_AUTH_PATHS):
            sigs.append(_make_signal(f.filename, 0, "auth_modified", f.filename))

        all_functions.extend(fns)
        all_signals.extend(sigs)
        all_imports[f.filename] = imports
        changed_fn_names.extend(fn.name for fn in fns if fn.is_changed)

    # Deduplicate signals by (filename, line, type)
    seen: set[tuple[str, int, str]] = set()
    unique_signals: list[SecuritySignal] = []
    for s in all_signals:
        key = (s.filename, s.line, s.signal_type)
        if key not in seen:
            unique_signals.append(s)
            seen.add(key)

    return ParseResult(
        functions=all_functions,
        security_signals=unique_signals,
        changed_function_names=list(set(changed_fn_names)),
        imports=all_imports,
    )