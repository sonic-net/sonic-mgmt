"""Unit tests for the image-upgrade device helpers.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_sonic_upgrade.py -v
"""

import ast
from pathlib import Path
from unittest.mock import Mock

import pytest


MODULE_PATH = Path(__file__).resolve().parents[3] / "ansible" / "devutil" / "devices" / "sonic.py"


class RunAnsibleModuleFailed(Exception):
    pass


@pytest.fixture
def post_upgrade_actions():
    tree = ast.parse(MODULE_PATH.read_text())
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "post_upgrade_actions"
    )
    namespace = {
        "RunAnsibleModuleFailed": RunAnsibleModuleFailed,
        "logger": Mock(),
        "patch_rsyslog": Mock(),
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace["post_upgrade_actions"]


def test_post_upgrade_waits_through_inventory_connection(post_upgrade_actions):
    sonichosts = Mock()
    localhost = Mock()

    assert post_upgrade_actions(sonichosts, localhost, 50)

    sonichosts.wait_for_connection.assert_called_once_with(delay=180, timeout=600)
    localhost.wait_for.assert_not_called()


def test_post_upgrade_returns_false_when_connection_wait_fails(post_upgrade_actions):
    sonichosts = Mock()
    sonichosts.wait_for_connection.side_effect = RunAnsibleModuleFailed("DUT unavailable")
    localhost = Mock()

    assert not post_upgrade_actions(sonichosts, localhost, 50)

    localhost.pause.assert_not_called()
