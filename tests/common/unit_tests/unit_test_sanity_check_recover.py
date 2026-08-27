"""Unit tests for sanity-check neighbor VM recovery dispatch."""

import ast
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest


MODULE_PATH = (Path(__file__).resolve().parents[1] /
               "plugins/sanity_check/recover.py")


def _load_neighbor_vm_restore():
    """Load neighbor_vm_restore without importing integration dependencies."""
    tree = ast.parse(MODULE_PATH.read_text())
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "neighbor_vm_restore"
    )
    namespace = {
        "json": json,
        "logger": MagicMock(),
        "parallel_run": MagicMock(return_value={}),
        "_make_results_serializable": lambda value: value,
        "_neighbor_vm_recover_bgpd": MagicMock(),
        "_neighbor_vm_recover_config": MagicMock(),
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]),
                 str(MODULE_PATH), "exec"), namespace)
    return namespace


@pytest.fixture
def recover_namespace():
    """Provide a fresh recovery function namespace for each test."""
    return _load_neighbor_vm_restore()


def test_bgp_failure_recovers_all_neighbor_vms(recover_namespace):
    """BGP sanity failures must restore neighbor interfaces and BGP."""
    duthost = MagicMock()
    duthost.get_extended_minigraph_facts.return_value = {
        "minigraph_neighbors": {"Ethernet0": {"name": "ARISTA01T0"}}
    }
    nbrhosts = {
        "ARISTA01T0": MagicMock(),
        "ARISTA02T0": MagicMock(),
    }

    action = recover_namespace["neighbor_vm_restore"](
        duthost,
        nbrhosts,
        {},
        {"check_item": "bgp"},
    )

    assert action == "config_reload"
    recover_namespace["parallel_run"].assert_called_once_with(
        recover_namespace["_neighbor_vm_recover_bgpd"],
        (),
        {},
        list(nbrhosts.values()),
        timeout=300,
    )


def test_missing_result_recovers_all_neighbor_vms(recover_namespace):
    """Legacy callers without a result must retain full BGP recovery."""
    duthost = MagicMock()
    duthost.get_extended_minigraph_facts.return_value = {
        "minigraph_neighbors": {"Ethernet0": {"name": "ARISTA01T0"}}
    }
    nbrhosts = {"ARISTA01T0": MagicMock()}

    recover_namespace["neighbor_vm_restore"](duthost, nbrhosts, {})

    recover_namespace["parallel_run"].assert_called_once_with(
        recover_namespace["_neighbor_vm_recover_bgpd"],
        (),
        {},
        list(nbrhosts.values()),
        timeout=300,
    )


def test_macsec_failure_recovers_only_unhealthy_neighbors(recover_namespace):
    """MACsec failures must reload only neighbors identified as unhealthy."""
    duthost = MagicMock()
    duthost.get_extended_minigraph_facts.return_value = {
        "minigraph_neighbors": {"Ethernet0": {"name": "ARISTA01T0"}}
    }
    unhealthy_host = MagicMock()
    nbrhosts = {
        "ARISTA01T0": MagicMock(),
        "ARISTA02T0": unhealthy_host,
    }

    recover_namespace["neighbor_vm_restore"](
        duthost,
        nbrhosts,
        {},
        {
            "check_item": "neighbor_macsec_empty",
            "unhealthy_nbrs": ["ARISTA02T0"],
        },
    )

    recover_namespace["parallel_run"].assert_called_once_with(
        recover_namespace["_neighbor_vm_recover_config"],
        (),
        {},
        [unhealthy_host],
        timeout=300,
    )
