import importlib.util
from pathlib import Path
from unittest.mock import Mock, call

import pytest


SPEC = importlib.util.spec_from_file_location(
    "trigger_secureboot_build", Path(__file__).with_name("trigger_secureboot_build.py")
)
trigger = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trigger)


def test_buildimage_source_is_the_exact_pr_merge_revision():
    """Pass the original repository/ref so commits need not exist in the pipeline fork."""
    assert trigger.source_parameters({
        "BUILD_REPOSITORY_NAME": "sonic-net/sonic-buildimage",
        "BUILD_REPOSITORY_URI": "https://github.com/sonic-net/sonic-buildimage",
        "BUILD_SOURCEBRANCH": "refs/pull/30156/merge",
        "BUILD_SOURCEVERSION": "a" * 40,
    }) == {
        "SOURCE_REPOSITORY": "https://github.com/sonic-net/sonic-buildimage",
        "SOURCE_REF": "refs/pull/30156/merge",
        "SOURCE_COMMIT": "a" * 40,
    }


def test_mgmt_pr_does_not_replace_the_image_source_with_test_code():
    """Keep the dedicated image branch for management-only changes."""
    assert trigger.source_parameters({"BUILD_REPOSITORY_NAME": "sonic-net/sonic-mgmt"}) == {}


@pytest.mark.parametrize("changes", [
    {"BUILD_REPOSITORY_NAME": "sonic-net/sonic-utilities"},
    {"BUILD_REPOSITORY_URI": "https://dev.azure.com/org/project/_git/sonic-buildimage"},
    {"BUILD_SOURCEVERSION": ""},
    {"BUILD_SOURCEBRANCH": ""},
])
def test_invalid_or_unsupported_source_is_rejected(changes):
    """Never silently build unrelated code for an unsupported PR source."""
    environ = {
        "BUILD_REPOSITORY_NAME": "sonic-net/sonic-buildimage",
        "BUILD_REPOSITORY_URI": "https://github.com/sonic-net/sonic-buildimage",
        "BUILD_SOURCEBRANCH": "refs/pull/30156/merge",
        "BUILD_SOURCEVERSION": "a" * 40,
    }
    environ.update(changes)
    with pytest.raises(ValueError):
        trigger.source_parameters(environ)


@pytest.fixture
def api(monkeypatch):
    """Mock all Azure requests and avoid sleeping or starting real builds."""
    api = Mock()
    monkeypatch.setattr(trigger, "request", api)
    monkeypatch.setattr(trigger.time, "sleep", Mock())
    return api


def test_queue_wait_and_publish_only_successful_child_build(api, capsys):
    """Submit the source parameters and publish the child ID only after success."""
    api.side_effect = [
        {"id": 456},
        {"status": "inProgress"},
        {"status": "completed", "result": "succeeded"},
    ]
    parameters = {"SOURCE_COMMIT": "a" * 40}
    assert trigger.trigger_build("token", 3442, "refs/heads/infra", parameters) == 456
    assert api.call_args_list == [
        call("POST", f"{trigger.BUILD_API}/pipelines/3442/runs?api-version=7.1", "token", {
            "resources": {"repositories": {"self": {"refName": "refs/heads/infra"}}},
            "templateParameters": parameters,
        }),
        call("GET", f"{trigger.BUILD_API}/build/builds/456?api-version=7.1", "token"),
        call("GET", f"{trigger.BUILD_API}/build/builds/456?api-version=7.1", "token"),
    ]
    assert "##vso[task.setvariable variable=BUILD_ID;isOutput=true]456" in capsys.readouterr().out


@pytest.mark.parametrize("result", ["failed", "canceled", "partiallySucceeded"])
def test_unsuccessful_build_never_publishes_an_image(api, capsys, result):
    """Require full success before any test job can consume the child build ID."""
    api.side_effect = [{"id": 456}, {"status": "completed", "result": result}]
    with pytest.raises(RuntimeError, match=result):
        trigger.trigger_build("token", 3442, "refs/heads/infra", {})
    assert "task.setvariable" not in capsys.readouterr().out
    assert api.call_count == 2


def test_timeout_cancels_child_and_does_not_publish_build(api, capsys):
    """Stop the queued child if the wait budget expires."""
    api.side_effect = [{"id": 456}, {}]
    with pytest.raises(TimeoutError):
        trigger.trigger_build("token", 3442, "refs/heads/infra", {}, timeout=0)
    assert api.call_args == call(
        "PATCH", f"{trigger.BUILD_API}/build/builds/456?api-version=7.1", "token", {"status": "cancelling"}
    )
    assert "task.setvariable" not in capsys.readouterr().out


@pytest.mark.parametrize("failure", [KeyboardInterrupt(), OSError("poll failed")])
def test_interrupted_wait_cancels_child(api, failure):
    """Cancel the child on an agent cancellation signal or failed polling request."""
    api.side_effect = [{"id": 456}, failure, {}]
    with pytest.raises(type(failure)):
        trigger.trigger_build("token", 3442, "refs/heads/infra", {})
    assert api.call_args.args[0] == "PATCH"


@pytest.mark.parametrize("token", ["", "$(System.AccessToken)"])
def test_missing_oauth_token_cannot_queue_a_build(api, token):
    """Fail clearly before contacting Azure if the job token is unavailable."""
    with pytest.raises(ValueError, match="System.AccessToken"):
        trigger.trigger_build(token, 3442, "refs/heads/infra", {})
    api.assert_not_called()
