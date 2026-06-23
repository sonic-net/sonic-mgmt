import pytest

from tools.skip_expiry.skip_issue_expiry_impl.cli import _filter_same_repo_issues, _normalize_repo_name
from tools.skip_expiry.skip_issue_expiry_impl.models import IssueRef


def test_filter_same_repo_issues_excludes_cross_repo_entries() -> None:
    issues = [
        IssueRef(owner="sonic-net", repo="sonic-mgmt", number=1),
        IssueRef(owner="sonic-net", repo="sonic-buildimage", number=2),
        IssueRef(owner="other-org", repo="other-repo", number=3),
    ]

    included, skipped = _filter_same_repo_issues(issues, "sonic-net/sonic-mgmt")

    assert included == [IssueRef(owner="sonic-net", repo="sonic-mgmt", number=1)]
    assert skipped == [
        IssueRef(owner="sonic-net", repo="sonic-buildimage", number=2),
        IssueRef(owner="other-org", repo="other-repo", number=3),
    ]


def test_normalize_repo_name_requires_owner_repo_format() -> None:
    with pytest.raises(ValueError):
        _normalize_repo_name("sonic-mgmt")

    with pytest.raises(ValueError):
        _normalize_repo_name("sonic-net/")

    with pytest.raises(ValueError):
        _normalize_repo_name("/sonic-mgmt")
