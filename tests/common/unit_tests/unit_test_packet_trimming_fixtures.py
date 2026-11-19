"""Check trimming fixture isolation without importing testbed dependencies.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_packet_trimming_fixtures.py -v
"""

import ast
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "packet_trimming" / "conftest.py"
CONFIG_MODULES = [
    "tests.packet_trimming.test_packet_trimming_config_symmetric",
    "tests.packet_trimming.test_packet_trimming_config_asymmetric",
]


@pytest.fixture
def trimming_fixtures():
    tree = ast.parse(MODULE_PATH.read_text())
    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in ("setup_trimming", "clear_counters")
    ]
    namespace = {"pytest": pytest, "logger": logging.getLogger(__name__)}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace


def make_request(module_name):
    return SimpleNamespace(module=SimpleNamespace(__name__=module_name), getfixturevalue=Mock())


@pytest.mark.parametrize("module_name", CONFIG_MODULES)
def test_config_setup_does_not_require_dataplane_fixtures(trimming_fixtures, module_name):
    """GCU config tests must not resolve test ports or QoS maps before their guard."""
    duthost = Mock()
    request = make_request(module_name)
    setup = trimming_fixtures["setup_trimming"].__wrapped__(duthost=duthost, request=request)

    assert list(setup) == [None]
    request.getfixturevalue.assert_not_called()
    assert duthost.mock_calls == []


@pytest.mark.parametrize("failing_fixture", ["test_params", "trim_counter_params"])
def test_dataplane_setup_still_requires_parameters(trimming_fixtures, failing_fixture):
    """Do not hide missing dataplane prerequisites for normal trimming tests."""
    request = make_request("tests.packet_trimming.test_packet_trimming")

    def resolve(name):
        if name == failing_fixture:
            raise RuntimeError(name)
        return {}

    request.getfixturevalue.side_effect = resolve
    setup = trimming_fixtures["setup_trimming"].__wrapped__(duthost=Mock(), request=request)
    with pytest.raises(RuntimeError, match=failing_fixture):
        next(setup)
    expected = [call("test_params")]
    if failing_fixture == "trim_counter_params":
        expected.append(call("trim_counter_params"))
    assert request.getfixturevalue.call_args_list == expected


@pytest.mark.parametrize("module_name", CONFIG_MODULES)
def test_config_does_not_clear_counters(trimming_fixtures, module_name):
    """The moved GCU tests do not need to reset dataplane counters."""
    duthost = Mock()
    trimming_fixtures["clear_counters"].__wrapped__(duthost, make_request(module_name))
    duthost.shell.assert_not_called()


def test_dataplane_counters_are_still_cleared(trimming_fixtures):
    """Preserve counter resets for non-GCU packet trimming modules."""
    duthost = Mock()
    request = make_request("tests.packet_trimming.test_packet_trimming")
    trimming_fixtures["clear_counters"].__wrapped__(duthost, request)
    assert duthost.shell.call_args_list == [
        call("sonic-clear counters"),
        call("sonic-clear queuecounters"),
        call("sonic-clear switchcounters"),
    ]
