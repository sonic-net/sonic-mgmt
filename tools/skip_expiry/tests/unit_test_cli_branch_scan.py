import subprocess
from pathlib import Path

from tools.skip_expiry.skip_issue_expiry_impl import cli
from tools.skip_expiry.skip_issue_expiry_impl.config import SkipExpiryConfig
from tools.skip_expiry.skip_issue_expiry_impl.models import IssueRef


class FakeManager:
    def __init__(self) -> None:
        self.released = []

    def release_unreferenced_issue(self, issue_ref: IssueRef) -> None:
        self.released.append(issue_ref)


class FakeLabelApiClient:
    def __init__(self, labelled):
        self.labelled = labelled

    def list_open_issues_with_label(self, owner, repo, label):
        return self.labelled


def _issue(number: int) -> IssueRef:
    return IssueRef(owner="sonic-net", repo="sonic-mgmt", number=number)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


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


def test_branch_scan_restores_the_original_checkout(tmp_path: Path, monkeypatch) -> None:
    _git(tmp_path, "init", "-q", "-b", "master")
    _git(tmp_path, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "one")
    _git(tmp_path, "branch", "202411")
    _git(tmp_path, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "two")

    def fake_collect_tracked_issues(**kwargs):
        _git(kwargs["repo_root"], "checkout", "-q", "--detach", "202411")
        return {_issue(5)}

    monkeypatch.setattr(cli, "collect_tracked_issues", fake_collect_tracked_issues)

    tracked = cli._collect_tracked_issues_across_branches(
        api_client=None,
        config=SkipExpiryConfig(maintainers=["maintainer"], expiry_days=90),
        repo_root=tmp_path,
        conditional_mark_dir="tests/common/plugins/conditional_mark",
        target_repo="sonic-net/sonic-mgmt",
    )

    assert tracked == {_issue(5)}
    assert _git(tmp_path, "symbolic-ref", "--short", "HEAD") == "master"
