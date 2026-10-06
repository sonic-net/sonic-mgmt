#!/usr/bin/env python3
"""Unit tests for flake8-diff-filter.py."""

import collections
import importlib.util
import os
import shutil
import subprocess

import pytest

_spec = importlib.util.spec_from_file_location(
    'flake8_diff_filter', os.path.join(os.path.dirname(__file__), 'flake8-diff-filter.py'))
fdf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fdf)

needs_flake8 = pytest.mark.skipif(shutil.which('flake8') is None, reason='flake8 not installed')


class TestParseChangedLines:
    def test_count_omitted_means_one_line(self):
        assert fdf.parse_changed_lines('@@ -3 +4 @@ foo\n') == {4}

    def test_range(self):
        assert fdf.parse_changed_lines('@@ -3,2 +10,3 @@\n') == {10, 11, 12}

    def test_pure_deletion_adds_nothing(self):
        assert fdf.parse_changed_lines('@@ -5,2 +4,0 @@\n') == set()

    def test_multiple_hunks_and_non_hunk_lines(self):
        diff = ('diff --git a/x.py b/x.py\n'
                '--- a/x.py\n'
                '+++ b/x.py\n'
                '@@ -1 +1 @@\n'
                '-old\n'
                '+new\n'
                '@@ -10,0 +11,2 @@ def f():\n'
                '+a\n'
                '+b\n')
        assert fdf.parse_changed_lines(diff) == {1, 11, 12}


class TestFlake8Failure:
    def test_clean(self):
        assert fdf.flake8_failure('', '', 0) is None

    def test_lint_findings(self):
        assert fdf.flake8_failure('a.py:1:1: F401 unused\n', '', 1) is None

    def test_traceback_with_exit_1(self):
        report = fdf.flake8_failure('', 'Traceback (most recent call last):\nBoom\n', 1)
        assert report[0] == 'flake8 failed to run (exit status 1):'
        assert 'Boom' in report

    def test_execution_error(self):
        report = fdf.flake8_failure('', 'bad option\n', 2)
        assert report == ['flake8 failed to run (exit status 2):', 'bad option']

    def test_killed_by_signal(self):
        report = fdf.flake8_failure('a.py:1:1: F401 unused\n', '', -9)
        assert report[0] == 'flake8 failed to run (exit status -9):'


class TestFilterViolations:
    SOURCE = ['import os', '', 'x = foo', 'y = bar']

    def _filter(self, output, changed, base):
        return fdf.filter_violations(
            output,
            changed=lambda path: changed,
            base_keys=lambda path: collections.Counter(base),
            source_lines=lambda path: self.SOURCE,
        )

    def test_violation_on_changed_line_is_kept(self):
        out = "a.py:3:5: F821 undefined name 'foo'"
        assert self._filter(out, {3}, []) == ([out], [])

    def test_preexisting_violation_on_unchanged_line_is_dropped(self):
        out = "a.py:1:1: F401 'os' imported but unused"
        base = [('a.py', "F401 'os' imported but unused", 'import os')]
        assert self._filter(out, set(), base) == ([], [])

    def test_new_violation_on_unchanged_line_is_kept(self):
        # e.g. the change removed the import that defined `foo`.
        out = "a.py:3:5: F821 undefined name 'foo'"
        assert self._filter(out, set(), []) == ([out], [])

    def test_each_base_violation_absorbs_only_one(self):
        out = "a.py:1:1: E999 dup\na.py:1:1: E999 dup"
        base = [('a.py', 'E999 dup', 'import os')]
        assert self._filter(out, set(), base) == (['a.py:1:1: E999 dup'], [])

    def test_non_violation_output_is_kept(self):
        assert self._filter('some fatal error', set(), []) == (['some fatal error'], [])

    def test_base_failure_keeps_violation_and_is_reported(self):
        out = "a.py:1:1: F401 'os' imported but unused"
        result = fdf.filter_violations(
            out,
            changed=lambda path: set(),
            base_keys=lambda path: ['flake8 failed to run (exit status 2):'],
            source_lines=lambda path: self.SOURCE,
        )
        assert result == ([out], [['flake8 failed to run (exit status 2):']])


@needs_flake8
class TestEndToEnd:
    @pytest.fixture
    def repo(self, tmp_path, monkeypatch):
        def git(*args):
            subprocess.run(['git'] + list(args), cwd=tmp_path, check=True, capture_output=True)

        git('init', '-q')
        git('config', 'user.email', 'test@example.com')
        git('config', 'user.name', 'test')
        monkeypatch.chdir(tmp_path)

        def commit(files):
            for name, content in files.items():
                path = tmp_path / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            git('add', '-A')
            git('commit', '-q', '-m', 'commit')
            return subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=tmp_path, check=True,
                                  capture_output=True, text=True).stdout.strip()
        return commit

    def test_preexisting_dropped_and_induced_error_reported(self, repo, capsys):
        base = repo({'a.py': 'import os\nimport sys\n\n\nprint(sys.argv)\n'})
        # Remove `import sys`: the pre-existing F401 on `import os` moves up a
        # line but must stay hidden, while the F821 lands on an unchanged line.
        repo({'a.py': 'import os\n\n\nprint(sys.argv)\n'})
        assert fdf.main(['--base', base, 'a.py']) == 1
        out = capsys.readouterr().out
        assert "F821 undefined name 'sys'" in out
        assert 'F401' not in out

    def test_new_file_reports_everything(self, repo, capsys):
        base = repo({'a.py': 'x = 1\n'})
        repo({'b.py': 'import os\n'})
        assert fdf.main(['--base', base, 'b.py']) == 1
        assert "F401 'os' imported but unused" in capsys.readouterr().out

    def test_clean_change(self, repo, capsys):
        base = repo({'a.py': 'import os\n'})
        repo({'a.py': 'import os\nx = 1\n'})
        assert fdf.main(['--base', base, 'a.py']) == 0
        assert capsys.readouterr().out == ''

    def test_all_reports_preexisting_and_skips_common2(self, repo, capsys):
        repo({'a.py': 'import os\n', 'tests/common2/c.py': 'import sys\n'})
        assert fdf.main(['--all']) == 1
        out = capsys.readouterr().out
        assert "a.py:1:1: F401 'os' imported but unused" in out
        assert 'common2' not in out

    def test_base_required_without_all(self):
        with pytest.raises(SystemExit):
            fdf.main(['a.py'])
