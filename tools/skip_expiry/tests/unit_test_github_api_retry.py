from typing import Any, Dict, List, Optional

import pytest
import requests

from tools.skip_expiry.skip_issue_expiry_impl.github_api import GitHubApiClient
from tools.skip_expiry.skip_issue_expiry_impl.models import IssueRef


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        json_payload: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self._json_payload = json_payload or {}
        self.headers = headers or {}
        self.text = text

    def json(self) -> Dict[str, Any]:
        return self._json_payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


def _issue_ref() -> IssueRef:
    return IssueRef(owner="sonic-net", repo="sonic-mgmt", number=100)


def test_get_issue_retries_on_429_with_retry_after(monkeypatch: pytest.MonkeyPatch) -> None:
    client = GitHubApiClient(token="token", max_retries=2, backoff_factor=0.1)
    responses: List[FakeResponse] = [
        FakeResponse(429, headers={"Retry-After": "2"}, text="rate limited"),
        FakeResponse(200, json_payload={"number": 100}),
    ]
    sleep_calls: List[float] = []

    monkeypatch.setattr(client.session, "request", lambda *args, **kwargs: responses.pop(0))
    monkeypatch.setattr(
        "tools.skip_expiry.skip_issue_expiry_impl.github_api.time.sleep",
        lambda seconds: sleep_calls.append(seconds),
    )

    issue = client.get_issue(_issue_ref())

    assert issue["number"] == 100
    assert sleep_calls == [2.0]


def test_get_issue_retries_on_5xx_with_exponential_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    client = GitHubApiClient(token="token", max_retries=2, backoff_factor=0.5)
    responses: List[FakeResponse] = [
        FakeResponse(503, text="temporary failure"),
        FakeResponse(200, json_payload={"number": 100}),
    ]
    sleep_calls: List[float] = []

    monkeypatch.setattr(client.session, "request", lambda *args, **kwargs: responses.pop(0))
    monkeypatch.setattr(
        "tools.skip_expiry.skip_issue_expiry_impl.github_api.time.sleep",
        lambda seconds: sleep_calls.append(seconds),
    )

    issue = client.get_issue(_issue_ref())

    assert issue["number"] == 100
    assert sleep_calls == [0.5]


def test_get_issue_retries_on_request_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    client = GitHubApiClient(token="token", max_retries=2, backoff_factor=0.25)
    sleep_calls: List[float] = []

    request_attempts: List[Any] = [
        requests.ConnectionError("connection reset"),
        FakeResponse(200, json_payload={"number": 100}),
    ]

    def fake_request(*args, **kwargs):
        value = request_attempts.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(client.session, "request", fake_request)
    monkeypatch.setattr(
        "tools.skip_expiry.skip_issue_expiry_impl.github_api.time.sleep",
        lambda seconds: sleep_calls.append(seconds),
    )

    issue = client.get_issue(_issue_ref())

    assert issue["number"] == 100
    assert sleep_calls == [0.25]


def test_list_open_issues_with_label_filters_by_label_and_drops_pull_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = GitHubApiClient(token="token")
    requests_made: List[Dict[str, Any]] = []
    payload = [
        {"number": 7},
        {"number": 8, "pull_request": {"url": "https://api.github.com/repos/sonic-net/sonic-mgmt/pulls/8"}},
    ]

    def fake_request(method, url, **kwargs):
        requests_made.append({"method": method, "url": url, "params": kwargs.get("params")})
        return FakeResponse(200, json_payload=payload)

    monkeypatch.setattr(client.session, "request", fake_request)

    issues = client.list_open_issues_with_label("sonic-net", "sonic-mgmt", "skip-wf-issue-expired")

    assert issues == [IssueRef(owner="sonic-net", repo="sonic-mgmt", number=7)]
    assert len(requests_made) == 1
    assert requests_made[0]["method"] == "GET"
    assert requests_made[0]["url"] == "https://api.github.com/repos/sonic-net/sonic-mgmt/issues"
    assert requests_made[0]["params"]["state"] == "open"
    assert requests_made[0]["params"]["labels"] == "skip-wf-issue-expired"
