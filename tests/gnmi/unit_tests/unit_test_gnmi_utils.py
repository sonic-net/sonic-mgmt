"""Unit tests for gNMI telemetry container recovery."""

import ast
import types
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "common"
    / "helpers"
    / "gnmi_utils.py"
)
FUNCTION_NAMES = {
    "_check_monit_container_checker",
    "_check_telemetry_health",
    "recover_telemetry_container",
}
CONSTANT_NAMES = {"TELEMETRY_CONTAINER"}


def _load_target_module():
    """Load only the telemetry recovery code and replace external helpers."""
    tree = ast.parse(MODULE_PATH.read_text())
    selected_nodes = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in FUNCTION_NAMES:
            selected_nodes.append(node)
        elif isinstance(node, ast.Assign):
            target_names = {
                target.id
                for target in node.targets
                if isinstance(target, ast.Name)
            }
            if target_names & CONSTANT_NAMES:
                selected_nodes.append(node)

    module = types.ModuleType("unit_target_gnmi_utils")
    module.logger = MagicMock()
    module.check_container_state = MagicMock()
    module.wait_until = MagicMock()
    code = compile(
        ast.Module(body=selected_nodes, type_ignores=[]),
        str(MODULE_PATH),
        "exec",
    )
    exec(code, module.__dict__)
    return module


@pytest.fixture
def gnmi_utils():
    return _load_target_module()


@pytest.mark.parametrize(
    "feature_status",
    [
        {},
        {"telemetry": "disabled"},
        {"telemetry": "always_disabled"},
    ],
)
def test_recover_telemetry_skips_disabled_or_absent_feature(
        gnmi_utils, feature_status):
    duthost = MagicMock()
    duthost.get_feature_status.return_value = (feature_status, True)

    assert gnmi_utils.recover_telemetry_container(duthost)

    gnmi_utils.check_container_state.assert_not_called()
    gnmi_utils.wait_until.assert_not_called()
    duthost.shell.assert_not_called()


def test_recover_telemetry_returns_false_when_restart_fails(gnmi_utils):
    duthost = MagicMock()
    duthost.get_feature_status.return_value = (
        {"telemetry": "enabled"},
        True,
    )
    duthost.shell.return_value = {
        "rc": 1,
        "stderr": "Unit telemetry.service not found",
    }
    gnmi_utils.check_container_state.return_value = False

    assert not gnmi_utils.recover_telemetry_container(duthost)

    gnmi_utils.wait_until.assert_not_called()


def test_recover_telemetry_verifies_successful_restart_and_monit(gnmi_utils):
    duthost = MagicMock()
    duthost.get_feature_status.return_value = (
        {"telemetry": "enabled"},
        True,
    )
    duthost.get_monit_services_status.return_value = {
        "container_checker": {"service_status": "Status ok"}
    }
    duthost.shell.return_value = {"rc": 0}
    gnmi_utils.check_container_state.side_effect = [False, True, True]
    gnmi_utils.wait_until.side_effect = (
        lambda timeout, interval, delay, condition, *args: condition(*args)
    )

    assert gnmi_utils.recover_telemetry_container(duthost)

    duthost.shell.assert_called_once_with(
        "sudo systemctl restart telemetry",
        module_ignore_errors=True,
    )
    assert gnmi_utils.wait_until.call_args_list == [
        call(
            120,
            10,
            0,
            gnmi_utils.check_container_state,
            duthost,
            "telemetry",
            True,
        ),
        call(
            120,
            10,
            30,
            gnmi_utils._check_telemetry_health,
            duthost,
        ),
    ]
