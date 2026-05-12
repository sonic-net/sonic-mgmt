import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest


MODULE_PATH = (Path(__file__).resolve().parents[3] /
               "common/fixtures/conn_graph_facts.py")


def _load_target_module():
    """Load the target module with pytest fixture stub."""
    if "pytest" not in sys.modules:
        pytest_stub = types.ModuleType("pytest")
        fixture_decorator = (lambda *a, **k: a[0] if a and callable(a[0])
                             else lambda f: f)
        pytest_stub.fixture = fixture_decorator
        sys.modules["pytest"] = pytest_stub

    spec = importlib.util.spec_from_file_location(
        "unit_target_conn_graph_facts", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def conn_graph_facts_module():
    """Load and return the conn_graph_facts target module."""
    return _load_target_module()


def _make_dut(conn_graph_facts_module, sources):
    """Create a mock DUT host with inventory sources."""
    dut = MagicMock()
    inventory_manager = MagicMock()
    inventory_manager._sources = sources
    dut.host.options = {"inventory_manager": inventory_manager}
    return dut


def _expected_filepath(conn_graph_facts_module):
    """Get the expected ansible/files path."""
    module_dir = conn_graph_facts_module.os.path.dirname(
        conn_graph_facts_module.os.path.realpath(
            conn_graph_facts_module.__file__))
    return conn_graph_facts_module.os.path.join(
        module_dir, "../../../ansible/files/")


@pytest.mark.parametrize(
    "sources, expected_group",
    [
        (["/tmp/snappi_mytestbed_trim_tmp"], "snappi"),
        (["/tmp/snappi"], "snappi"),
        (["/tmp/snappi_mytestbed"], None),
    ],
)
def test_get_graph_facts_matches_graph_group_for_trim_and_non_trim_inventory(
        conn_graph_facts_module, sources, expected_group):
    """Test that trim_inv and non-trim inventory names match graph groups."""
    dut = _make_dut(conn_graph_facts_module, sources)
    sonic_mgmt_host = MagicMock()
    sonic_mgmt_host.conn_graph_facts.return_value = {
        "ansible_facts": {"device_conn": {2: {"peerdevice": "fanout-2"}}}
    }

    graph_groups_yaml = "---\n- veos\n- snappi\n"
    with patch.object(conn_graph_facts_module.os.path, "isfile",
                      return_value=True), \
            patch("builtins.open", mock_open(read_data=graph_groups_yaml)):
        result = conn_graph_facts_module.get_graph_facts(
            dut, sonic_mgmt_host, ["dut-a", "dut-b"])

    # Verify conn_graph_facts was called exactly once with the correct args
    assert sonic_mgmt_host.conn_graph_facts.call_count == 1
    call_kwargs = sonic_mgmt_host.conn_graph_facts.call_args.kwargs
    expected_filepath = _expected_filepath(conn_graph_facts_module)
    expected_call_kwargs = {
        "filepath": expected_filepath,
        "hosts": ["dut-a", "dut-b"],
    }
    if expected_group:
        expected_call_kwargs["group"] = expected_group

    assert call_kwargs == expected_call_kwargs

    # Verify the result device_conn keys were converted to strings
    assert result["device_conn"] == {"2": {"peerdevice": "fanout-2"}}
