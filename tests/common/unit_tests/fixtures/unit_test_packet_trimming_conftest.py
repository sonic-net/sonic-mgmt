"""Unit tests for topology-specific trimming profiles.

For isolated collection, use --noconftest, --import-mode=importlib, and set
--confcutdir and --rootdir to tests/common/unit_tests/fixtures.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


MODULE_PATH = Path(__file__).resolve().parents[3] / "packet_trimming" / "conftest.py"


@pytest.fixture
def trimming_conftest():
    stubs = {
        name: MagicMock()
        for name in (
            "tests.common.config_reload",
            "tests.common.plugins.allure_wrapper",
            "tests.common.utilities",
            "tests.common.helpers.ptf_tests_helper",
            "tests.common.mellanox_data",
            "tests.common.helpers.srv6_helper",
            "tests.packet_trimming.constants",
            "tests.packet_trimming.packet_trimming_config",
            "tests.packet_trimming.packet_trimming_helper",
        )
    }
    with patch.dict(sys.modules, stubs):
        spec = importlib.util.spec_from_file_location("unit_target_trimming_conftest", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

    module.DEFAULT_DSCP = 10
    module.PacketTrimmingConfig.get_counter_dscp.return_value = 16
    module.get_queue_id_by_dscp.side_effect = lambda dscp, *_: 0 if dscp == 10 else 1
    module.get_interface_peer_addresses.return_value = ("192.0.2.1", "2001:db8::1")
    module.get_test_ports.return_value = {
        "ingress_port": {"Ethernet0": {"ptf_port_id": 0}},
        "egress_port_1": {"PortChannel001": {"ptf_port_id": 1, "dut_members": ["Ethernet4"]}},
        "egress_port_2": {"PortChannel002": {"ptf_port_id": 2, "dut_members": ["Ethernet8"]}},
    }
    return module


@pytest.mark.parametrize("topology,directions", [
    ("t0", ["uplink"]),
    ("t1", ["uplink", "downlink"]),
])
def test_profiles_match_selected_egress_directions(trimming_conftest, topology, directions):
    params = trimming_conftest.test_params.__wrapped__(
        None, None, None, None, None, None, {"topo": {"type": topology}})
    counter_params = trimming_conftest.trim_counter_params.__wrapped__(None, params, None)

    assert len(params["egress_ports"]) == len(directions)
    assert params["trim_buffer_profiles"] == {
        direction: f"queue0_{direction}_lossy_profile" for direction in directions
    }
    assert counter_params["trim_buffer_profiles"] == {
        direction: f"queue1_{direction}_lossy_profile" for direction in directions
    }
    assert params["block_queue"] == 0
    assert counter_params["block_queue"] == 1
