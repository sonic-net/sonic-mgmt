"""Unit tests for SONiC image-upgrade device helpers."""

import ast
from pathlib import Path
from unittest.mock import Mock

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[3]
    / "ansible" / "devutil" / "devices" / "sonic.py"
)


class RunAnsibleModuleFailed(Exception):
    pass


def _load_functions(*names, **namespace):
    tree = ast.parse(MODULE_PATH.read_text())
    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    module = ast.Module(body=functions, type_ignores=[])
    exec(compile(module, str(MODULE_PATH), "exec"), namespace)
    return namespace


@pytest.fixture
def post_upgrade_actions():
    patch_rsyslog = Mock()
    logger = Mock()
    wait_for_ssh = Mock()
    namespace = _load_functions(
        "post_upgrade_actions",
        RunAnsibleModuleFailed=RunAnsibleModuleFailed,
        logger=logger,
        patch_rsyslog=patch_rsyslog,
        wait_for_ssh=wait_for_ssh,
    )
    return (
        namespace["post_upgrade_actions"],
        patch_rsyslog,
        wait_for_ssh,
        logger,
    )


def test_post_upgrade_wait_uses_host_connection(post_upgrade_actions):
    function, patch_rsyslog, wait_for_ssh, _ = post_upgrade_actions
    sonichosts = Mock()
    sonichosts.hostnames = ["dut"]
    localhost = Mock()

    assert function(sonichosts, localhost, 50)

    wait_for_ssh.assert_called_once()
    assert wait_for_ssh.call_args.args[0] is sonichosts
    localhost.wait_for.assert_not_called()
    localhost.pause.assert_called_once_with(
        seconds=60,
        prompt="Wait for SONiC initialization",
    )
    patch_rsyslog.assert_called_once()
    assert patch_rsyslog.call_args.args[0] is sonichosts


def test_wait_for_ssh_uses_configured_connection():
    function = _load_functions("wait_for_ssh")["wait_for_ssh"]
    sonichosts = Mock()

    function(sonichosts)

    sonichosts.wait_for_connection.assert_called_once_with(
        delay=180,
        timeout=600,
        module_attrs={"changed_when": False},
    )


def test_wait_for_ssh_limits_target_hosts():
    function = _load_functions("wait_for_ssh")["wait_for_ssh"]
    sonichosts = Mock()

    function(sonichosts, ["dut"])

    sonichosts.wait_for_connection.assert_called_once_with(
        delay=180,
        timeout=600,
        module_attrs={"changed_when": False},
        target_hosts=["dut"],
    )


def test_post_upgrade_wait_failure_is_reported(post_upgrade_actions):
    function, _, wait_for_ssh, logger = post_upgrade_actions
    sonichosts = Mock()
    sonichosts.hostnames = ["dut"]
    wait_for_ssh.side_effect = RunAnsibleModuleFailed("not reachable")

    assert not function(sonichosts, Mock(), 50)
    logger.error.assert_called_once()
