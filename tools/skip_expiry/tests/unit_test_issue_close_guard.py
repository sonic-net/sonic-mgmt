import json
from pathlib import Path

from tools.skip_expiry.skip_issue_expiry_impl.config import SkipExpiryConfig
from tools.skip_expiry.skip_issue_expiry_impl.issue_close_guard import MANUAL_CLOSE_COMMENT
from tools.skip_expiry.skip_issue_expiry_impl.issue_close_guard import build_branches_to_scan
from tools.skip_expiry.skip_issue_expiry_impl.issue_close_guard import enforce_issue_close_guard
from tools.skip_expiry.skip_issue_expiry_impl.issue_close_guard import load_closed_issue_from_event
from tools.skip_expiry.skip_issue_expiry_impl.issue_close_guard import resolve_release_branches
from tools.skip_expiry.skip_issue_expiry_impl.issue_close_guard import run_issue_close_guard
from tools.skip_expiry.skip_issue_expiry_impl.models import IssueRef


class FakeGuardApiClient:
    def __init__(self, branches):
        self.branches = branches
        self.reopened = []
        self.comments = []

    def list_repo_branches(self, owner, repo):
        return self.branches

    def reopen_issue(self, issue):
        self.reopened.append(issue)

    def create_comment(self, issue, body):
        self.comments.append((issue, body))


def test_resolve_release_branches_applies_regex_and_exact_excludes() -> None:
    all_branches = ["master", "202205", "202305", "202405", "202411", "feature/test"]

    selected = resolve_release_branches(
        all_branches=all_branches,
        include_patterns=[r"^202\d{3}$"],
        exclude_names=["202205", "202305"],
    )

    assert selected == ["202405", "202411"]


def test_build_branches_to_scan_always_includes_master_once() -> None:
    assert build_branches_to_scan(["master", "202411", "202405", "202405"]) == ["master", "202405", "202411"]


def test_load_closed_issue_from_event_returns_issue_ref(tmp_path: Path) -> None:
    event_file = tmp_path / "event.json"
    event_file.write_text(
        json.dumps(
            {
                "action": "closed",
                "repository": {"full_name": "sonic-net/sonic-mgmt"},
                "issue": {"number": 88},
            }
        ),
        encoding="utf-8",
    )

    issue = load_closed_issue_from_event(event_file, "sonic-net/sonic-mgmt")

    assert issue == IssueRef(owner="sonic-net", repo="sonic-mgmt", number=88)


def test_enforce_issue_close_guard_reopens_and_comments_when_tracked() -> None:
    api = FakeGuardApiClient(branches=[])
    issue = IssueRef(owner="sonic-net", repo="sonic-mgmt", number=77)

    did_reopen = enforce_issue_close_guard(api, issue, {issue})

    assert did_reopen is True
    assert api.reopened == [issue]
    assert api.comments == [(issue, MANUAL_CLOSE_COMMENT)]


def test_run_issue_close_guard_reopens_tracked_closed_issue(tmp_path: Path, monkeypatch) -> None:
    event_file = tmp_path / "event.json"
    event_file.write_text(
        json.dumps(
            {
                "action": "closed",
                "repository": {"full_name": "sonic-net/sonic-mgmt"},
                "issue": {"number": 77},
            }
        ),
        encoding="utf-8",
    )

    tracked_issue = IssueRef(owner="sonic-net", repo="sonic-mgmt", number=77)
    cross_repo_issue = IssueRef(owner="other-org", repo="other-repo", number=99)

    monkeypatch.setattr(
        "tools.skip_expiry.skip_issue_expiry_impl.issue_close_guard.collect_issues_from_branches",
        lambda **kwargs: {tracked_issue, cross_repo_issue},
    )

    api = FakeGuardApiClient(branches=["master", "202305", "202405", "feature/abc"])
    config = SkipExpiryConfig(
        maintainers=["maintainer"],
        expiry_days=90,
        release_includes=[r"^202\d{3}$"],
        release_excludes=["202305"],
    )

    did_reopen = run_issue_close_guard(
        api_client=api,
        config=config,
        repo_root=tmp_path,
        conditional_mark_dir="tests/common/plugins/conditional_mark",
        target_repo="sonic-net/sonic-mgmt",
        event_path=event_file,
    )

    assert did_reopen is True
    assert api.reopened == [tracked_issue]
    assert api.comments == [(tracked_issue, MANUAL_CLOSE_COMMENT)]
