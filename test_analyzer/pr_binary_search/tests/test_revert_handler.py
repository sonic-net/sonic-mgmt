"""
Unit tests for revert_handler.py.

All GitHub API calls, Kusto calls, and git subprocess calls are mocked —
no real network or git operations are performed.

Run with:
    cd <repo_root>
    pytest test_analyzer/pr_binary_search/tests/test_revert_handler.py -v
"""

import os
import sys
import pytest
from unittest.mock import MagicMock, patch

# Make pr_binary_search package importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import revert_handler  # noqa: E402
from revert_handler import (  # noqa: E402
    _is_submodule_bump,
    _revert_branch_name,
    _validate_repo_format,
    check_already_reverted,
    create_revert_pr,
    fetch_bad_commit_results,
    find_pr_for_commit,
    process_results,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mock_response(status_code, json_data):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.text = str(json_data)
    return resp


# ── _validate_repo_format ────────────────────────────────────────────────────


class TestValidateRepoFormat:
    def test_valid_repo(self):
        _validate_repo_format("sonic-net/sonic-buildimage")  # no exception

    def test_valid_repo_with_dots(self):
        _validate_repo_format("org.name/repo.name")

    def test_invalid_repo_no_slash(self):
        with pytest.raises(ValueError):
            _validate_repo_format("invalid-repo")

    def test_invalid_repo_with_spaces(self):
        with pytest.raises(ValueError):
            _validate_repo_format("org/repo name")

    def test_invalid_repo_kql_injection(self):
        with pytest.raises(ValueError):
            _validate_repo_format('org/repo" | drop table')


# ── _revert_branch_name ──────────────────────────────────────────────────────


class TestRevertBranchName:
    def test_prefix_is_auto_revert(self):
        name = _revert_branch_name("abc1234")
        assert name.startswith("auto-revert/")

    def test_contains_commit_short(self):
        name = _revert_branch_name("deadbee")
        assert "deadbee" in name

    def test_deterministic(self):
        assert _revert_branch_name("abc") == _revert_branch_name("abc")


# ── _is_submodule_bump ───────────────────────────────────────────────────────


class TestIsSubmoduleBump:
    def test_empty_files_returns_false(self):
        assert not _is_submodule_bump({"files": []})

    def test_no_files_key_returns_false(self):
        assert not _is_submodule_bump({})

    def test_gitmodules_change_is_bump(self):
        commit_data = {"files": [{"filename": ".gitmodules", "type": "blob"}]}
        assert _is_submodule_bump(commit_data)

    def test_submodule_type_is_bump(self):
        commit_data = {"files": [{"filename": "src/submod", "type": "submodule"}]}
        assert _is_submodule_bump(commit_data)

    def test_large_pr_with_submodule_not_bump(self):
        # More than 3 files — heuristic should not trigger
        files = [{"filename": f"file{i}.py", "type": "blob"} for i in range(5)]
        files.append({"filename": "sub", "type": "submodule"})
        assert not _is_submodule_bump({"files": files})

    def test_regular_py_file_not_bump(self):
        commit_data = {"files": [
            {"filename": "tests/test_foo.py", "type": "blob", "blob_url": "http://x"}
        ]}
        assert not _is_submodule_bump(commit_data)

    def test_blob_url_empty_does_not_trigger_bump(self):
        # Old heuristic used blob_url == ""; deleted files also have empty blob_url.
        # The fix uses type == "submodule" instead.
        commit_data = {"files": [{"filename": "deleted.py", "type": "blob", "blob_url": ""}]}
        assert not _is_submodule_bump(commit_data)


# ── find_pr_for_commit ───────────────────────────────────────────────────────


class TestFindPrForCommit:
    def test_returns_merged_pr_on_master(self):
        pr = {"merged_at": "2024-01-01T00:00:00Z",
              "base": {"ref": "master"}, "number": 42}
        with patch("revert_handler.requests.get",
                   return_value=_mock_response(200, [pr])):
            result = find_pr_for_commit("owner", "repo", "abc123", "token")
        assert result == pr

    def test_returns_none_when_not_merged(self):
        pr = {"merged_at": None, "base": {"ref": "master"}, "number": 1}
        with patch("revert_handler.requests.get",
                   return_value=_mock_response(200, [pr])):
            result = find_pr_for_commit("owner", "repo", "abc123", "token")
        assert result is None

    def test_returns_none_on_http_error(self):
        with patch("revert_handler.requests.get",
                   return_value=_mock_response(404, {})):
            result = find_pr_for_commit("owner", "repo", "abc123", "token")
        assert result is None

    def test_skips_non_default_branch(self):
        pr = {"merged_at": "2024-01-01T00:00:00Z",
              "base": {"ref": "feature-branch"}, "number": 5}
        with patch("revert_handler.requests.get",
                   return_value=_mock_response(200, [pr])):
            result = find_pr_for_commit("owner", "repo", "abc123", "token")
        assert result is None

    def test_accepts_main_branch(self):
        pr = {"merged_at": "2024-01-01T00:00:00Z",
              "base": {"ref": "main"}, "number": 7}
        with patch("revert_handler.requests.get",
                   return_value=_mock_response(200, [pr])):
            result = find_pr_for_commit("owner", "repo", "abc123", "token")
        assert result == pr


# ── check_already_reverted ───────────────────────────────────────────────────


class TestCheckAlreadyReverted:
    def test_existing_pr_on_branch_returns_true(self):
        pr = {"html_url": "https://github.com/owner/repo/pull/99"}
        with patch("revert_handler.requests.get",
                   return_value=_mock_response(200, [pr])):
            result = check_already_reverted(
                "owner", "repo", 42, "abc1234", "master", "token")
        assert result is True

    def test_no_existing_pr_search_returns_false(self):
        empty = _mock_response(200, [])
        search_empty = _mock_response(200, {"items": []})
        with patch("revert_handler.requests.get",
                   side_effect=[empty, search_empty]):
            result = check_already_reverted(
                "owner", "repo", 42, "abc1234", "master", "token")
        assert result is False

    def test_search_finds_existing_pr(self):
        no_branch_pr = _mock_response(200, [])
        search_result = _mock_response(200, {
            "items": [{"html_url": "https://github.com/owner/repo/pull/55"}]
        })
        with patch("revert_handler.requests.get",
                   side_effect=[no_branch_pr, search_result]):
            result = check_already_reverted(
                "owner", "repo", 42, "abc1234", "master", "token")
        assert result is True


# ── fetch_bad_commit_results ─────────────────────────────────────────────────


class TestFetchBadCommitResults:
    def test_returns_list_of_dicts(self):
        mock_row = {
            "SourceRepo": "sonic-net/sonic-buildimage",
            "Branch": "master",
            "BadCommit": "deadbeef",
            "CheckerType": "test",
            "FilePath": "tests/foo.py",
            "ModulePath": "module",
            "TestCase": "test_bar",
            "AnalyzerRunId": "run-1",
            "SearchRunId": "search-1",
            "UploadTime": "2024-01-01",
        }
        mock_row_obj = MagicMock()
        mock_row_obj.__getitem__ = lambda self, key: mock_row[key]

        mock_result = MagicMock()
        mock_result.primary_results = [[mock_row_obj]]
        mock_client = MagicMock()
        mock_client.execute.return_value = mock_result

        rows = fetch_bad_commit_results(mock_client, 48,
                                        "sonic-net/sonic-buildimage")
        assert len(rows) == 1
        assert rows[0]["BadCommit"] == "deadbeef"

    def test_validates_source_repo_format(self):
        mock_client = MagicMock()
        with pytest.raises(ValueError):
            fetch_bad_commit_results(mock_client, 48, "bad repo name!")


# ── create_revert_pr ─────────────────────────────────────────────────────────


class TestCreateRevertPr:
    def _make_pr(self, number=42, title="Fix bug", merge_sha="merge001",
                 url="https://github.com/o/r/pull/42"):
        return {
            "number": number, "title": title,
            "merge_commit_sha": merge_sha,
            "html_url": url,
            "base": {"ref": "master"},
            "merged_at": "2024-01-01T00:00:00Z",
        }

    def test_skips_repo_not_in_allowed(self):
        result = create_revert_pr(
            "other-org", "other-repo", "master",
            "deadbeef", {}, "token")
        assert result["status"] == "skipped"
        assert result["reason"] == "repo_not_allowed"

    def test_skips_when_no_merged_pr_found(self):
        with patch("revert_handler.find_pr_for_commit", return_value=None):
            result = create_revert_pr(
                "sonic-net", "sonic-buildimage", "master",
                "deadbeef", {}, "token")
        assert result["status"] == "skipped"
        assert result["reason"] == "no_merged_pr_found"

    def test_skips_when_already_reverted(self):
        with patch("revert_handler.find_pr_for_commit",
                   return_value=self._make_pr()), \
             patch("revert_handler.check_already_reverted", return_value=True):
            result = create_revert_pr(
                "sonic-net", "sonic-buildimage", "master",
                "deadbeef", {}, "token")
        assert result["status"] == "skipped"
        assert result["reason"] == "already_reverted"

    def test_skips_submodule_bump(self):
        commit_data = {"files": [{"filename": ".gitmodules", "type": "blob"}]}
        with patch("revert_handler.find_pr_for_commit",
                   return_value=self._make_pr()), \
             patch("revert_handler.check_already_reverted", return_value=False), \
             patch("revert_handler._get_commit", return_value=commit_data):
            result = create_revert_pr(
                "sonic-net", "sonic-buildimage", "master",
                "deadbeef", {}, "token")
        assert result["status"] == "skipped"
        assert result["reason"] == "submodule_bump"

    def test_skips_too_many_files(self):
        files = [{"filename": f"f{i}.py", "type": "blob"} for i in range(60)]
        commit_data = {"files": files}
        with patch("revert_handler.find_pr_for_commit",
                   return_value=self._make_pr()), \
             patch("revert_handler.check_already_reverted", return_value=False), \
             patch("revert_handler._get_commit", return_value=commit_data):
            result = create_revert_pr(
                "sonic-net", "sonic-buildimage", "master",
                "deadbeef", {}, "token")
        assert result["status"] == "skipped"
        assert result["reason"] == "too_many_files"

    def test_skips_on_revert_conflict(self):
        commit_data = {"files": [{"filename": "foo.py", "type": "blob"}]}
        with patch("revert_handler.find_pr_for_commit",
                   return_value=self._make_pr()), \
             patch("revert_handler.check_already_reverted", return_value=False), \
             patch("revert_handler._get_commit", return_value=commit_data), \
             patch("revert_handler._clone_and_revert", return_value=None):
            result = create_revert_pr(
                "sonic-net", "sonic-buildimage", "master",
                "deadbeef", {}, "token")
        assert result["status"] == "skipped"
        assert result["reason"] == "revert_conflict"

    def test_creates_pr_successfully(self):
        commit_data = {"files": [{"filename": "foo.py", "type": "blob"}]}
        with patch("revert_handler.find_pr_for_commit",
                   return_value=self._make_pr()), \
             patch("revert_handler.check_already_reverted", return_value=False), \
             patch("revert_handler._get_commit", return_value=commit_data), \
             patch("revert_handler._clone_and_revert",
                   return_value="revertsha001"), \
             patch("revert_handler._open_pull_request",
                   return_value="https://github.com/sonic-net/sonic-buildimage/pull/100"):
            result = create_revert_pr(
                "sonic-net", "sonic-buildimage", "master",
                "deadbeef", {}, "token")
        assert result["status"] == "created"
        assert "revert_pr_url" in result
        assert result["revert_commit"] == "revertsha001"

    def test_fails_when_pr_creation_fails(self):
        commit_data = {"files": [{"filename": "foo.py", "type": "blob"}]}
        with patch("revert_handler.find_pr_for_commit",
                   return_value=self._make_pr()), \
             patch("revert_handler.check_already_reverted", return_value=False), \
             patch("revert_handler._get_commit", return_value=commit_data), \
             patch("revert_handler._clone_and_revert",
                   return_value="revertsha001"), \
             patch("revert_handler._open_pull_request", return_value=None):
            result = create_revert_pr(
                "sonic-net", "sonic-buildimage", "master",
                "deadbeef", {}, "token")
        assert result["status"] == "failed"
        assert result["reason"] == "cannot_create_pr"


# ── process_results ───────────────────────────────────────────────────────────


class TestProcessResults:
    def _row(self, repo="sonic-net/sonic-buildimage",
             commit="deadbeef001122", branch="master"):
        return {"SourceRepo": repo, "BadCommit": commit, "Branch": branch}

    def test_dry_run_does_not_create_prs(self):
        rows = [self._row()]
        with patch("revert_handler.create_revert_pr") as mock_create:
            results = process_results(rows, "token", dry_run=True)
        mock_create.assert_not_called()
        assert results[0]["status"] == "dry_run"

    def test_deduplicates_same_commit(self):
        rows = [self._row(), self._row()]  # same repo+commit twice
        with patch("revert_handler.create_revert_pr",
                   return_value={"status": "created"}) as mock_create:
            results = process_results(rows, "token")
        assert mock_create.call_count == 1
        assert len(results) == 1

    def test_skips_invalid_repo_format(self):
        rows = [{"SourceRepo": "bad repo!", "BadCommit": "abc", "Branch": "master"}]
        with patch("revert_handler.create_revert_pr") as mock_create:
            results = process_results(rows, "token")
        mock_create.assert_not_called()
        assert results == []

    def test_skips_missing_fields(self):
        rows = [{"SourceRepo": "", "BadCommit": "abc", "Branch": "master"}]
        with patch("revert_handler.create_revert_pr") as mock_create:
            process_results(rows, "token")
        mock_create.assert_not_called()

    def test_error_in_one_does_not_affect_others(self):
        rows = [
            self._row(commit="commit001"),
            self._row(commit="commit002"),
        ]

        def side_effect(owner, repo, branch, commit, meta, token):
            if commit == "commit001":
                raise RuntimeError("network error")
            return {"status": "created"}

        with patch("revert_handler.create_revert_pr",
                   side_effect=side_effect):
            results = process_results(rows, "token")

        statuses = {r["commit"]: r["status"] for r in results}
        assert statuses["commit001"] == "error"
        assert statuses["commit002"] == "created"


# ── _clone_and_revert (shallow clone fallback) ───────────────────────────────


class TestCloneAndRevert:
    """Test that _clone_and_revert falls back to --unshallow when needed."""

    def _make_run_result(self, returncode=0, stdout="", stderr=""):
        r = MagicMock()
        r.returncode = returncode
        r.stdout = stdout
        r.stderr = stderr
        return r

    def test_unshallow_triggered_when_fetch_fails(self):
        """When the commit fetch fails, unshallow should be attempted."""
        call_log = []

        def fake_run_git(args, cwd, check=True):
            call_log.append(args[0] if args else "")
            # fail the specific-commit fetch
            if args[0] == "fetch" and len(args) > 2 and "merge001" in args:
                if check:
                    raise RuntimeError("not reachable")
                return self._make_run_result(returncode=1, stderr="not found")
            # cat-file to detect merge commit
            if args[0] == "cat-file":
                return self._make_run_result(stdout="parent abc\n")
            # revert returns conflict
            if args[0] == "revert":
                return self._make_run_result(returncode=1, stderr="conflict")
            return self._make_run_result()

        with patch("revert_handler._run_git", side_effect=fake_run_git), \
             patch("tempfile.mkdtemp", return_value="/tmp/fake-dir"), \
             patch("shutil.rmtree"):
            revert_handler._clone_and_revert(
                "owner", "repo", "master", "merge001abc",
                "auto-revert/abc1234", "Revert msg", "token")

        # unshallow must have been called
        assert "fetch" in call_log
        unshallow_calls = [
            args for args in call_log if args == "fetch"
        ]
        assert len(unshallow_calls) >= 2  # at least normal fetch + unshallow
