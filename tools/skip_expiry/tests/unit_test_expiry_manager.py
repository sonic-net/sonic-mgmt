from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from tools.skip_expiry.skip_issue_expiry_impl.config import SkipExpiryConfig
from tools.skip_expiry.skip_issue_expiry_impl.expiry import ACTIVE_MARKER, EXPIRED_LABEL
from tools.skip_expiry.skip_issue_expiry_impl.expiry import EXPIRED_MARKER, SkipExpiryManager
from tools.skip_expiry.skip_issue_expiry_impl.models import IssueRef


class FakeApiClient:
    def __init__(
        self,
        issue_payload: Dict[str, object],
        timeline_payload: Optional[List[Dict[str, object]]] = None,
        comments_payload: Optional[List[Dict[str, object]]] = None,
    ) -> None:
        self.issue_payload = issue_payload
        self.timeline_payload = timeline_payload or []
        self.comments_payload = comments_payload or []

        self.get_issue_timeline_calls = 0
        self.get_issue_comments_calls = 0

        self.added_labels: List[str] = []
        self.removed_labels: List[str] = []
        self.created_comments: List[str] = []

    def get_issue(self, issue: IssueRef) -> Dict[str, object]:
        return self.issue_payload

    def get_issue_timeline(self, issue: IssueRef) -> List[Dict[str, object]]:
        self.get_issue_timeline_calls += 1
        return self.timeline_payload

    def get_issue_comments(self, issue: IssueRef) -> List[Dict[str, object]]:
        self.get_issue_comments_calls += 1
        return self.comments_payload

    def add_label(self, issue: IssueRef, label: str) -> None:
        self.added_labels.append(label)

    def remove_label(self, issue: IssueRef, label: str) -> None:
        self.removed_labels.append(label)

    def create_comment(self, issue: IssueRef, body: str) -> None:
        self.created_comments.append(body)


def _iso_utc(days_ago: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.isoformat().replace("+00:00", "Z")


def _manager(api_client: FakeApiClient, expiry_days: int) -> SkipExpiryManager:
    config = SkipExpiryConfig(maintainers=["maintainer1"], expiry_days=expiry_days)
    return SkipExpiryManager(api_client=api_client, config=config, bot_login="github-actions[bot]")


def _issue_ref() -> IssueRef:
    return IssueRef(owner="sonic-net", repo="sonic-mgmt", number=12345)


def test_closed_issue_is_skipped_without_mutation() -> None:
    api = FakeApiClient(
        issue_payload={
            "state": "closed",
            "created_at": _iso_utc(120),
            "labels": [],
        }
    )

    _manager(api, expiry_days=90).process_issue(_issue_ref())

    assert api.get_issue_timeline_calls == 0
    assert api.get_issue_comments_calls == 0
    assert api.added_labels == []
    assert api.removed_labels == []
    assert api.created_comments == []


def test_open_not_expired_issue_takes_no_action() -> None:
    api = FakeApiClient(
        issue_payload={
            "state": "open",
            "created_at": _iso_utc(10),
            "labels": [],
        }
    )

    _manager(api, expiry_days=90).process_issue(_issue_ref())

    assert api.get_issue_timeline_calls == 1
    assert api.get_issue_comments_calls == 1
    assert api.added_labels == []
    assert api.removed_labels == []
    assert api.created_comments == []


def test_policy_increase_to_120_days_reactivates_previous_expired_issue() -> None:
    api = FakeApiClient(
        issue_payload={
            "state": "open",
            "created_at": _iso_utc(100),
            "labels": [{"name": EXPIRED_LABEL}],
        },
        timeline_payload=[
            {
                "event": "labeled",
                "actor": {"login": "github-actions[bot]"},
                "label": {"name": EXPIRED_LABEL},
                "created_at": _iso_utc(2),
            }
        ],
    )

    _manager(api, expiry_days=120).process_issue(_issue_ref())

    assert api.added_labels == []
    assert api.removed_labels == [EXPIRED_LABEL]
    assert len(api.created_comments) == 1
    assert ACTIVE_MARKER in api.created_comments[0]


def test_policy_decrease_to_30_days_marks_issue_expired() -> None:
    api = FakeApiClient(
        issue_payload={
            "state": "open",
            "created_at": _iso_utc(100),
            "labels": [],
        }
    )

    _manager(api, expiry_days=30).process_issue(_issue_ref())

    assert api.added_labels == [EXPIRED_LABEL]
    assert api.removed_labels == []
    assert len(api.created_comments) == 1
    assert EXPIRED_MARKER in api.created_comments[0]
