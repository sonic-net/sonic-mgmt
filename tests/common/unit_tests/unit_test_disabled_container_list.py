"""Exercise container exclusions without importing testbed dependencies.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_disabled_container_list.py -v
"""

import ast
from pathlib import Path
from unittest.mock import Mock

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "helpers" / "dut_utils.py"


def _assert(condition, message):
    assert condition, message


@pytest.fixture
def get_disabled_container_list():
    # Load the real helper without the Ansible/console dependency tree.
    tree = ast.parse(MODULE_PATH.read_text())
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "get_disabled_container_list"
    )
    namespace = {"pytest_assert": _assert}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace["get_disabled_container_list"]


@pytest.mark.parametrize("status", [None, "enabled", "always_enabled", "disabled", "always_disabled"])
def test_frr_bmp_always_excluded_once(get_disabled_container_list, status):
    features = {
        "bgp": "enabled",
        "bmp": "enabled",
        "pmon": "always_enabled",
        "lldp": "disabled",
        "mux": "always_disabled",
    }
    if status is not None:
        features["frr_bmp"] = status
    duthost = Mock()
    duthost.get_feature_status.return_value = (features, True)

    result = get_disabled_container_list(duthost)

    assert set(result) == {"frr_bmp", "lldp", "mux"}
    assert len(result) == 3
    duthost.get_feature_status.assert_called_once_with()


@pytest.mark.parametrize("status", [None, "enabled", "always_enabled", "disabled", "always_disabled"])
def test_real_container_excluded_only_when_disabled(get_disabled_container_list, status):
    features = {}
    if status is not None:
        features["bmp"] = status
    duthost = Mock()
    duthost.get_feature_status.return_value = (features, True)

    result = get_disabled_container_list(duthost)

    expected = {"frr_bmp"}
    if status in ("disabled", "always_disabled"):
        expected.add("bmp")
    assert set(result) == expected
    assert len(result) == len(expected)


def test_feature_query_failure_is_not_masked(get_disabled_container_list):
    duthost = Mock()
    duthost.get_feature_status.return_value = (None, False)

    with pytest.raises(AssertionError, match="Failed to get status"):
        get_disabled_container_list(duthost)


def test_feature_query_exception_propagates(get_disabled_container_list):
    duthost = Mock()
    duthost.get_feature_status.side_effect = RuntimeError("FEATURE query failed")

    with pytest.raises(RuntimeError, match="FEATURE query failed"):
        get_disabled_container_list(duthost)
