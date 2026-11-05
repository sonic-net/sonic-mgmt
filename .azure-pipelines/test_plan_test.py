import importlib.util
import json
import runpy
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests
import yaml


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


@pytest.mark.parametrize(
    "options, expected",
    [([], False), (["--secure-boot"], True), (["--secure-boot", "True"], True), (["--secure-boot", "False"], False)],
)
def test_create_cli_sends_secure_boot_as_an_image_boolean(monkeypatch, options, expected):
    """Preserve default BIOS mode and transmit explicit Secure Boot choices in the image."""
    for name, value in {
        "ELASTICTEST_SCHEDULER_BACKEND_URL": "https://scheduler.example",
        "ELASTICTEST_MSAL_CLIENT_ID": "client-id",
        "SONIC_AUTOMATION_UMI": "managed-identity-id",
        "BUILD_BUILDID": "123",
        "BUILD_REPOSITORY_NAME": "sonic-net/sonic-buildimage",
        "BUILD_REASON": "PullRequest",
        "SYSTEM_PULLREQUEST_TARGETBRANCH": "master",
    }.items():
        monkeypatch.setenv(name, value)
    process = Mock(returncode=0)
    process.communicate.return_value = (b'{"accessToken": "test-token"}', b"")
    monkeypatch.setattr(test_plan.subprocess, "Popen", Mock(return_value=process))
    post = Mock(return_value=_response({"success": True, "data": "test-plan-id"}))
    monkeypatch.setattr(test_plan.requests, "post", post)
    monkeypatch.setattr(test_plan.sys, "argv", [
        str(MODULE_PATH), "create", "--test-plan-type", "NIGHTLY",
        "--topology", "t0", "--platform", "kvm", "--asic-type", "vs",
    ] + options)

    with pytest.raises(SystemExit) as exit_status:
        runpy.run_path(str(MODULE_PATH), run_name="__main__")

    assert exit_status.value.code == 0
    post.assert_called_once()
    image = json.loads(post.call_args.kwargs["data"])["test_option"]["image"]
    assert image["secure_boot"] is expected
    assert image["kvm_image_build_id"] == "123"
    assert image["kvm_image_branch"] == ""


def test_pr_template_requests_secure_boot_only_for_secure_boot_checker():
    """Wire Secure Boot into its checker without changing other PR checkers' mode."""
    template = yaml.safe_load(MODULE_PATH.with_name("run-test-elastictest-template.yml").read_text())
    defaults = {param["name"]: param.get("default") for param in template["parameters"]}
    assert defaults["SECURE_BOOT"] is False
    trigger = next(step for step in template["steps"] if step.get("displayName") == "Trigger Test")
    assert "--secure-boot ${{ parameters.SECURE_BOOT }}" in trigger["script"]

    pipeline = yaml.safe_load(MODULE_PATH.with_name("pr_test_template.yml").read_text())
    secure_boot_jobs = []
    for job in pipeline["jobs"]:
        for step in job.get("steps", []):
            if step.get("template") != "run-test-elastictest-template.yml":
                continue
            params = step["parameters"]
            if params.get("SECURE_BOOT", defaults["SECURE_BOOT"]):
                secure_boot_jobs.append(job["job"])
                assert params["ADD_TOPO_PARAMS"] == "-e use_uefi=true"
    assert secure_boot_jobs == ["impacted_area_secureboot_t0_elastictest"]


def test_secure_boot_checker_uses_regular_pr_execution_gates():
    """Allow shared builds while retaining impact, inclusion, success and cancellation gates."""
    pipeline = yaml.safe_load(MODULE_PATH.with_name("pr_test_template.yml").read_text())
    jobs = {job["job"]: job for job in pipeline["jobs"]}
    regular = jobs["impacted_area_t0_elastictest"]
    secure_boot = jobs["impacted_area_secureboot_t0_elastictest"]

    assert secure_boot["condition"] == regular["condition"].replace("t0_checker", "secureboot_checker")
    assert "SECURE_BOOT_IMAGE_AVAILABLE" not in secure_boot["variables"]


def test_secure_boot_checker_uses_shared_build_unless_a_dedicated_source_is_requested():
    """Preserve pipeline-only overrides without mixing them with a regular build ID."""
    pipeline = yaml.safe_load(MODULE_PATH.with_name("pr_test_template.yml").read_text())
    jobs = {job["job"]: job for job in pipeline["jobs"]}
    submissions = {
        name: next(
            step["parameters"] for step in job["steps"]
            if step.get("template") == "run-test-elastictest-template.yml"
        )
        for name, job in jobs.items()
        if name in ("impacted_area_t0_elastictest", "impacted_area_secureboot_t0_elastictest")
    }
    regular = submissions["impacted_area_t0_elastictest"]
    secure_boot = submissions["impacted_area_secureboot_t0_elastictest"]
    dedicated_condition = (
        "${{ if or(ne(parameters.SECURE_BOOT_KVM_BUILD_ID, ''), "
        "ne(parameters.SECURE_BOOT_KVM_IMAGE_BUILD_PIPELINE_ID, '')) }}"
    )

    assert secure_boot["KVM_IMAGE_BRANCH"] == regular["KVM_IMAGE_BRANCH"]
    assert secure_boot["${{ else }}"]["KVM_BUILD_ID"] == regular["KVM_BUILD_ID"]
    assert secure_boot[dedicated_condition]["KVM_BUILD_ID"] == "${{ parameters.SECURE_BOOT_KVM_BUILD_ID }}"
    assert secure_boot["KVM_IMAGE_BUILD_PIPELINE_ID"] == "${{ parameters.SECURE_BOOT_KVM_IMAGE_BUILD_PIPELINE_ID }}"


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
