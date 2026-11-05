import argparse
import subprocess
from pathlib import Path
from typing import List, Optional, Set

import pytest

from tools.skip_expiry.skip_issue_expiry_impl import cli
from tools.skip_expiry.skip_issue_expiry_impl.config import SkipExpiryConfig
from tools.skip_expiry.skip_issue_expiry_impl.issue_close_guard import collect_issues_from_branches
from tools.skip_expiry.skip_issue_expiry_impl.models import IssueRef

MARK_DIR = "tests/common/plugins/conditional_mark"


class FakeManager:
    def __init__(self) -> None:
        self.released = []

    def release_unreferenced_issue(self, issue_ref: IssueRef) -> None:
        self.released.append(issue_ref)


class FakeLabelApiClient:
    def __init__(self, labelled, fail: bool = False):
        self.labelled = labelled
        self.fail = fail

    def list_open_issues_with_label(self, owner, repo, label):
        if self.fail:
            raise RuntimeError("GitHub API unavailable")
        return self.labelled


def _issue(number: int) -> IssueRef:
    return IssueRef(owner="sonic-net", repo="sonic-mgmt", number=number)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def _mark_yaml(*numbers: int) -> str:
    conditions = "".join(f"      - https://github.com/sonic-net/sonic-mgmt/issues/{n}\n" for n in numbers)
    return f"test_a.py:\n  skip:\n    reason: test\n    conditions:\n{conditions}"


def _write_marks(repo: Path, content: str) -> None:
    mark_dir = repo / MARK_DIR
    mark_dir.mkdir(parents=True, exist_ok=True)
    (mark_dir / "tests_mark_conditions.yaml").write_text(content, encoding="utf-8")


def _commit_all(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", message)


def test_release_unreferenced_issues_only_releases_issues_no_branch_references() -> None:
    manager = FakeManager()
    api = FakeLabelApiClient([_issue(1), _issue(2), _issue(3)])

    had_errors = cli._release_unreferenced_issues(api, manager, "sonic-net/sonic-mgmt", {_issue(1), _issue(3)})

    assert had_errors is False
    assert manager.released == [_issue(2)]


def test_release_unreferenced_issues_keeps_every_label_when_nothing_is_tracked() -> None:
    manager = FakeManager()
    api = FakeLabelApiClient([_issue(1), _issue(2)])

    had_errors = cli._release_unreferenced_issues(api, manager, "sonic-net/sonic-mgmt", set())

    assert had_errors is True
    assert manager.released == []


def test_release_unreferenced_issues_reports_a_failed_label_listing_as_an_error() -> None:
    manager = FakeManager()
    api = FakeLabelApiClient([], fail=True)

    had_errors = cli._release_unreferenced_issues(api, manager, "sonic-net/sonic-mgmt", {_issue(1)})

    assert had_errors is True
    assert manager.released == []


@pytest.fixture
def shallow_clone(tmp_path: Path) -> Path:
    """A shallow single-branch clone of master from an origin that also has a 202411 release branch."""
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "master")
    _write_marks(origin, _mark_yaml(1))
    _commit_all(origin, "master marks")
    _git(origin, "checkout", "-q", "-b", "202411")
    _write_marks(origin, _mark_yaml(2))
    _commit_all(origin, "release marks")
    _git(origin, "checkout", "-q", "master")

    work = tmp_path / "work"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", "--single-branch", "--branch", "master", origin.as_uri(), str(work)],
        check=True,
        capture_output=True,
    )
    return work


def test_branch_scan_reads_release_branches_of_a_shallow_clone_without_touching_the_checkout(
    shallow_clone: Path,
) -> None:
    mark_file = shallow_clone / MARK_DIR / "tests_mark_conditions.yaml"
    mark_file.write_text(_mark_yaml(1, 99), encoding="utf-8")  # an uncommitted local edit
    head_before = _git(shallow_clone, "rev-parse", "HEAD")

    issues = collect_issues_from_branches(shallow_clone, MARK_DIR, ["master", "202411"])

    assert issues == {_issue(1), _issue(2)}
    assert _git(shallow_clone, "rev-parse", "HEAD") == head_before
    assert _git(shallow_clone, "symbolic-ref", "--short", "HEAD") == "master"
    assert mark_file.read_text(encoding="utf-8") == _mark_yaml(1, 99)


def test_branch_scan_accepts_an_absolute_mark_dir(shallow_clone: Path) -> None:
    issues = collect_issues_from_branches(shallow_clone, str(shallow_clone / MARK_DIR), ["202411"])

    assert issues == {_issue(2)}


def test_branch_scan_fails_when_a_mark_file_does_not_parse(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "master")
    _write_marks(repo, "test_a.py: [unclosed\n")
    _commit_all(repo, "broken marks")
    _git(repo, "remote", "add", "origin", repo.as_uri())

    with pytest.raises(ValueError, match="Failed to parse"):
        collect_issues_from_branches(repo, MARK_DIR, ["master"])


class FakeRunApiClient:
    def __init__(self, labelled: List[IssueRef]) -> None:
        self.labelled = labelled

    def list_open_issues_with_label(self, owner, repo, label):
        return list(self.labelled)


class FakeRunManager:
    instance: Optional["FakeRunManager"] = None

    def __init__(self, **kwargs) -> None:
        self.processed: List[IssueRef] = []
        self.released: List[IssueRef] = []
        FakeRunManager.instance = self

    def process_issue(self, issue_ref: IssueRef):
        self.processed.append(issue_ref)
        return None

    def release_unreferenced_issue(self, issue_ref: IssueRef) -> None:
        self.released.append(issue_ref)


def _run_cli(tmp_path: Path, monkeypatch, scan_result: Optional[Set[IssueRef]], labelled: List[IssueRef]):
    """Run cli.run() with the current checkout referencing issue 1 and the branch scan returning `scan_result`.

    A None `scan_result` makes the branch scan raise.
    """
    _write_marks(tmp_path, _mark_yaml(1))
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.delenv("PROJECT_ID", raising=False)
    monkeypatch.setattr(
        cli,
        "_parse_args",
        lambda: argparse.Namespace(
            repo_root=str(tmp_path),
            config="config.yaml",
            conditional_mark_dir=MARK_DIR,
            log_level="INFO",
            no_op=False,
            target_repo="sonic-net/sonic-mgmt",
        ),
    )
    monkeypatch.setattr(
        cli, "load_skip_expiry_config", lambda path: SkipExpiryConfig(maintainers=["maintainer"], expiry_days=90)
    )
    monkeypatch.setattr(cli, "GitHubApiClient", lambda token: FakeRunApiClient(labelled))
    monkeypatch.setattr(cli, "SkipExpiryManager", FakeRunManager)
    monkeypatch.setattr(cli, "create_reporter_from_env", lambda **kwargs: None)

    def fake_collect_tracked_issues(**kwargs):
        if scan_result is None:
            raise RuntimeError("branch scan failed")
        return scan_result

    monkeypatch.setattr(cli, "collect_tracked_issues", fake_collect_tracked_issues)
    rc = cli.run()
    return rc, FakeRunManager.instance


def test_run_evaluates_release_only_issues_and_releases_unreferenced_ones(tmp_path: Path, monkeypatch) -> None:
    rc, manager = _run_cli(
        tmp_path, monkeypatch, scan_result={_issue(1), _issue(2)}, labelled=[_issue(1), _issue(2), _issue(3)]
    )

    assert rc == 0
    assert manager.processed == [_issue(1), _issue(2)]
    assert manager.released == [_issue(3)]


def test_run_keeps_every_label_when_the_branch_scan_fails(tmp_path: Path, monkeypatch) -> None:
    rc, manager = _run_cli(tmp_path, monkeypatch, scan_result=None, labelled=[_issue(2), _issue(3)])

    assert rc == 1
    assert manager.processed == [_issue(1)]
    assert manager.released == []


def test_run_keeps_every_label_when_the_branch_scan_finds_nothing(tmp_path: Path, monkeypatch) -> None:
    rc, manager = _run_cli(tmp_path, monkeypatch, scan_result=set(), labelled=[_issue(2), _issue(3)])

    assert rc == 1
    assert manager.processed == [_issue(1)]
    assert manager.released == []
