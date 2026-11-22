import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests


MODULE_PATH = Path(__file__).with_name("test_plan.py")
SPEC = importlib.util.spec_from_file_location(
    "pipeline_test_plan",
    MODULE_PATH,
)
test_plan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(test_plan)


def _response(payload=None, status_code=200):
    response = Mock(status_code=status_code)
    response.json.return_value = payload
    if status_code >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(
            response=response,
        )
    return response


def _executing_response():
    return _response({
        "success": True,
        "data": {
            "status": "EXECUTING",
            "result": None,
            "runtime": {},
        },
    })


def _finished_response():
    return _response({
        "success": True,
        "data": {
            "status": "FINISHED",
            "result": "SUCCESS",
            "runtime": {
                "steps": [
                    {
                        "step": "EXECUTING",
                        "status": "FINISHED",
                    },
                ],
            },
        },
    })


@pytest.fixture
def manager(monkeypatch):
    """Create a test-plan manager without invoking Azure CLI."""
    manager = test_plan.TestPlanManager(
        scheduler_url="https://scheduler.example",
        frontend_url="https://frontend.example",
        client_id="client-id",
        managed_identity_id="managed-identity-id",
    )
    manager.get_token = Mock(return_value="token")
    monkeypatch.setattr(test_plan.time, "sleep", Mock())
    return manager


def test_success_resets_consecutive_poll_failures(manager, monkeypatch):
    """Verify successful polling resets the consecutive failure budget."""
    timeout = requests.ReadTimeout("status request timed out")
    responses = (
        [timeout] * (test_plan.MAX_POLL_RETRY_TIMES - 1)
        + [_executing_response()]
        + [timeout] * (test_plan.MAX_POLL_RETRY_TIMES - 1)
        + [_finished_response()]
    )
    get = Mock(side_effect=responses)
    monkeypatch.setattr(test_plan.requests, "get", get)

    manager.poll("test-plan-id", interval=0, expected_state="EXECUTING")

    assert get.call_count == len(responses)
    assert all(
        call.kwargs["timeout"] == (
            test_plan.POLL_CONNECT_TIMEOUT_SECONDS,
            test_plan.POLL_READ_TIMEOUT_SECONDS,
        )
        for call in get.call_args_list
    )


def test_read_timeout_does_not_refresh_token(manager, monkeypatch):
    """Verify a read timeout retries without refreshing the access token."""
    get = Mock(side_effect=[
        requests.ReadTimeout("status request timed out"),
        _finished_response(),
    ])
    monkeypatch.setattr(test_plan.requests, "get", get)

    manager.poll("test-plan-id", interval=0, expected_state="EXECUTING")

    manager.get_token.assert_called_once_with()


def test_consecutive_poll_failures_exhaust_retry_budget(manager, monkeypatch):
    """Verify consecutive failures still stop polling at the retry limit."""
    get = Mock(side_effect=[
        requests.ReadTimeout("status request timed out")
        for _ in range(test_plan.MAX_POLL_RETRY_TIMES)
    ])
    monkeypatch.setattr(test_plan.requests, "get", get)

    with pytest.raises(
        Exception,
        match="maximum number of consecutive retries",
    ):
        manager.poll("test-plan-id", interval=0, expected_state="EXECUTING")

    assert get.call_count == test_plan.MAX_POLL_RETRY_TIMES
    manager.get_token.assert_called_once_with()


def test_unauthorized_response_refreshes_token(manager, monkeypatch):
    """Verify an unauthorized response refreshes the access token."""
    manager.get_token.side_effect = ["initial-token", "refreshed-token"]
    get = Mock(side_effect=[
        _response(status_code=requests.codes.unauthorized),
        _finished_response(),
    ])
    monkeypatch.setattr(test_plan.requests, "get", get)

    manager.poll("test-plan-id", interval=0, expected_state="EXECUTING")

    assert manager.get_token.call_count == 2
    assert (
        get.call_args_list[1].kwargs["headers"]["Authorization"]
        == "Bearer refreshed-token"
    )
