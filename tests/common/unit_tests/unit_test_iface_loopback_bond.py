"""Offline regressions for loopback PTF setup and neighbor restoration."""

import ast
import inspect
from pathlib import Path
from unittest.mock import Mock

import pytest


LOOPBACK_DIR = Path(__file__).resolve().parents[2] / "iface_loopback_action"


@pytest.fixture
def helpers():
    namespace = {"logger": Mock()}
    for filename, names in [
        ("iface_loopback_action_helper.py", ["add_ptf_bond"]),
        ("conftest.py", ["setup"]),
    ]:
        path = LOOPBACK_DIR / filename
        tree = ast.parse(path.read_text())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        for function in functions:
            function.decorator_list = []
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


@pytest.mark.parametrize("failed_command", [1, 3, 5])
def test_ptf_bond_setup_failure_propagates(helpers, failed_command):
    """Stop immediately on creation, member attachment, or link configuration failure."""
    ptfhost = Mock()
    ptfhost.shell.side_effect = [{}] * (failed_command - 1) + [RuntimeError("PTF setup failed")]

    with pytest.raises(RuntimeError, match="PTF setup failed"):
        helpers["add_ptf_bond"](ptfhost, "eth26", 52, "11.2.0.10/24")

    assert ptfhost.shell.call_count == failed_command


@pytest.mark.parametrize("fail_setup", [False, True])
def test_neighbor_ports_restored_after_ptf_setup(helpers, fail_setup):
    """Restore the neighbor ports even when PTF configuration aborts the fixture."""
    peer = Mock()
    helpers["get_portchannel_peer_port_map"] = Mock(return_value={peer: ["Ethernet1", "Ethernet2"]})
    helpers["remove_orig_dut_port_config"] = Mock()
    helpers["apply_config"] = Mock()
    if fail_setup:
        helpers["apply_config"].side_effect = RuntimeError("PTF setup failed")

    setup = helpers["setup"]
    arguments = {name: Mock() for name in inspect.signature(setup).parameters}
    arguments["is_sonic_mlnx_leaf_fanout"] = False
    fixture = setup(**arguments)
    if fail_setup:
        with pytest.raises(RuntimeError, match="PTF setup failed"):
            next(fixture)
    else:
        next(fixture)
        peer.no_shutdown.assert_not_called()
        with pytest.raises(StopIteration):
            next(fixture)

    for port in ["Ethernet1", "Ethernet2"]:
        peer.shutdown.assert_any_call(port)
        peer.no_shutdown.assert_any_call(port)
