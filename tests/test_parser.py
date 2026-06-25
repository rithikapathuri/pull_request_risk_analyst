import pytest
from backend.parser import parse_pr, _parse_python, _parse_js_ts, _extract_imports
from backend.github import parse_diff_hunks
from backend.models import PRFile, DiffHunk, Language


def make_file(filename: str, patch: str, status: str = "modified") -> PRFile:
    lang_map = {".py": Language.PYTHON, ".js": Language.JAVASCRIPT, ".ts": Language.TYPESCRIPT}
    from pathlib import Path
    lang = lang_map.get(Path(filename).suffix, Language.UNKNOWN)
    additions = sum(1 for l in patch.splitlines() if l.startswith("+") and not l.startswith("+++"))
    return PRFile(filename=filename, status=status, additions=additions, deletions=0, patch=patch, language=lang)


def make_hunk(filename: str, start: int, lines: list[str]) -> DiffHunk:
    return DiffHunk(filename=filename, start_line=start, end_line=start + len(lines), added_lines=lines)


class TestPythonParser:
    def test_detects_eval(self):
        source = "def run(x):\n    return eval(x)\n"
        hunks = [(1, 3)]
        fns, sigs = _parse_python("test.py", source, hunks)
        types = [s.signal_type for s in sigs]
        assert "eval_usage" in types

    def test_detects_pickle(self):
        source = "import pickle\ndef load(data):\n    return pickle.loads(data)\n"
        fns, sigs = _parse_python("test.py", source, [(1, 4)])
        assert any(s.signal_type == "deserialization" for s in sigs)

    def test_yaml_load_without_loader(self):
        source = "import yaml\ndef parse(s):\n    return yaml.load(s)\n"
        fns, sigs = _parse_python("test.py", source, [(1, 4)])
        assert any(s.signal_type == "deserialization" for s in sigs)

    def test_yaml_load_with_loader_is_safe(self):
        source = "import yaml\ndef parse(s):\n    return yaml.load(s, Loader=yaml.SafeLoader)\n"
        fns, sigs = _parse_python("test.py", source, [(1, 4)])
        assert not any(s.signal_type == "deserialization" for s in sigs)

    def test_subprocess_shell_true(self):
        source = "import subprocess\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
        fns, sigs = _parse_python("test.py", source, [(1, 4)])
        assert any(s.signal_type == "subprocess" for s in sigs)

    def test_subprocess_no_shell_is_safe(self):
        source = "import subprocess\ndef run():\n    subprocess.run(['ls', '-la'])\n"
        fns, sigs = _parse_python("test.py", source, [(1, 4)])
        assert not any(s.signal_type == "subprocess" for s in sigs)

    def test_weak_hash(self):
        source = "import hashlib\nhashlib.md5(data)\n"
        fns, sigs = _parse_python("test.py", source, [(1, 3)])
        assert any(s.signal_type == "weak_hash" for s in sigs)

    def test_only_changed_lines_flagged(self):
        # Signal is on line 5, hunk only covers lines 1-3
        source = "def safe():\n    pass\n\ndef unsafe():\n    eval(x)\n"
        fns, sigs = _parse_python("test.py", source, [(1, 3)])
        assert not any(s.signal_type == "eval_usage" for s in sigs)

    def test_function_extraction(self):
        source = "def foo():\n    bar()\n\ndef bar():\n    pass\n"
        fns, _ = _parse_python("mod.py", source, [(1, 6)])
        names = [f.name for f in fns]
        assert "foo" in names
        assert "bar" in names

    def test_call_tracking(self):
        source = "def foo():\n    bar()\n    baz()\n"
        fns, _ = _parse_python("mod.py", source, [(1, 4)])
        foo = next(f for f in fns if f.name == "foo")
        assert "bar" in foo.calls
        assert "baz" in foo.calls

    def test_hardcoded_secret_regex(self):
        source = 'password = "supersecret123"\n'
        fns, sigs = _parse_python("config.py", source, [(1, 2)])
        assert any(s.signal_type == "hardcoded_secret" for s in sigs)

    def test_no_duplicate_signals(self):
        # Same line should only generate one signal of each type
        source = "eval(user_input)\neval(user_input)\n"
        fns, sigs = _parse_python("test.py", source, [(1, 3)])
        eval_sigs = [s for s in sigs if s.signal_type == "eval_usage"]
        assert len(eval_sigs) == len({s.line for s in eval_sigs})


class TestJSParser:
    def test_detects_insecure_cookie(self):
        source = "document.cookie = 'user=admin';\n"
        fns, sigs = _parse_js_ts("app.js", source, [(1, 2)])
        assert any(s.signal_type == "insecure_cookie" for s in sigs)

    def test_function_extraction(self):
        source = "function fetchUser(id) {\n  return db.get(id);\n}\n"
        fns, _ = _parse_js_ts("api.js", source, [(1, 4)])
        assert any(f.name == "fetchUser" for f in fns)

    def test_arrow_function(self):
        source = "const getUser = async (id) => {\n  return fetch(id);\n};\n"
        fns, _ = _parse_js_ts("api.js", source, [(1, 4)])
        assert any(f.name == "getUser" for f in fns)


class TestImportExtraction:
    def test_python_imports(self):
        source = "import os\nimport sys\nfrom pathlib import Path\n"
        imports = _extract_imports("mod.py", source)
        assert "os" in imports
        assert "pathlib" in imports

    def test_js_require(self):
        source = "const express = require('express');\nconst path = require('path');\n"
        imports = _extract_imports("app.js", source)
        assert "express" in imports
        assert "path" in imports


class TestAuthModifiedSignal:
    def test_auth_file_flagged(self):
        files = [make_file("backend/auth/login.py", "@@ -1,2 +1,3 @@\n+def login(): pass")]
        hunks = parse_diff_hunks(files) if files[0].patch else []
        result = parse_pr(files, hunks)
        assert any(s.signal_type == "auth_modified" for s in result.security_signals)

    def test_non_auth_file_not_flagged(self):
        files = [make_file("utils/helpers.py", "@@ -1,1 +1,2 @@\n+x = 1")]
        hunks = parse_diff_hunks(files) if files[0].patch else []
        result = parse_pr(files, hunks)
        assert not any(s.signal_type == "auth_modified" for s in result.security_signals)