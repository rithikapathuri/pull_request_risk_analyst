import pytest
from backend.github import (
    _parse_patch, parse_diff_hunks, parse_all_dependencies,
    _parse_requirements_txt, _parse_package_json, _parse_go_mod, _parse_pipfile,
)
from backend.models import PRFile, Language


class TestPatchParsing:
    def test_single_hunk(self):
        patch = "@@ -10,6 +10,7 @@ def foo():\n context\n+added line\n more context"
        hunks = _parse_patch("foo.py", patch)
        assert len(hunks) == 1
        assert hunks[0].start_line == 10
        assert "added line" in hunks[0].added_lines

    def test_multiple_hunks(self):
        patch = "@@ -1,3 +1,4 @@\n+first\n line\n@@ -20,3 +21,4 @@\n+second\n other"
        hunks = _parse_patch("bar.py", patch)
        assert len(hunks) == 2
        assert hunks[1].start_line == 21

    def test_removed_lines_captured(self):
        patch = "@@ -5,4 +5,3 @@\n-removed\n kept"
        hunks = _parse_patch("x.py", patch)
        assert "removed" in hunks[0].removed_lines

    def test_empty_patch(self):
        assert _parse_patch("empty.py", "") == []

    def test_skips_files_without_patch(self):
        files = [
            PRFile(filename="a.py", status="modified", additions=1, deletions=0, patch=None),
            PRFile(filename="b.py", status="modified", additions=1, deletions=0,
                   patch="@@ -1,1 +1,2 @@\n+new line"),
        ]
        hunks = parse_diff_hunks(files)
        assert len(hunks) == 1
        assert hunks[0].filename == "b.py"


class TestRequirementsTxt:
    def test_pinned(self):
        deps = _parse_requirements_txt("requests==2.28.0\nflask==2.3.1\n")
        assert deps["requests"] == "2.28.0"
        assert deps["flask"] == "2.3.1"

    def test_range(self):
        deps = _parse_requirements_txt("django>=4.0,<5.0\n")
        assert deps["django"] == "4.0"

    def test_comments_ignored(self):
        deps = _parse_requirements_txt("# comment\nrequests==2.28.0\n")
        assert list(deps.keys()) == ["requests"]

    def test_no_version(self):
        deps = _parse_requirements_txt("flask\n")
        assert deps["flask"] == "unknown"

    def test_extras_stripped(self):
        deps = _parse_requirements_txt("requests[security]==2.28.0\n")
        assert "requests" in deps

    def test_dash_r_ignored(self):
        deps = _parse_requirements_txt("-r base.txt\nflask==2.0.0\n")
        assert "flask" in deps
        assert len(deps) == 1


class TestPackageJson:
    def test_basic(self):
        deps = _parse_package_json('{"dependencies": {"lodash": "^4.17.21"}}')
        assert deps["lodash"] == "4.17.21"

    def test_dev_deps(self):
        deps = _parse_package_json('{"devDependencies": {"jest": "^29.0.0"}}')
        assert "jest" in deps

    def test_invalid_json(self):
        assert _parse_package_json("not json") == {}

    def test_no_deps_section(self):
        assert _parse_package_json('{"name": "my-app"}') == {}


class TestGoMod:
    def test_require_block(self):
        content = "require (\n    github.com/gin-gonic/gin v1.9.1\n)\n"
        deps = _parse_go_mod(content)
        assert "gin" in deps
        assert deps["gin"] == "1.9.1"

    def test_single_require(self):
        deps = _parse_go_mod("require github.com/pkg/errors v0.9.1\n")
        assert deps["errors"] == "0.9.1"