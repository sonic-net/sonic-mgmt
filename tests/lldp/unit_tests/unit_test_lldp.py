"""Focused tests for converged EOS neighbor LLDP facts."""

import json
from pathlib import Path
import sys
from unittest.mock import Mock

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from lldp.test_lldp import _neighbor_lldp_facts  # noqa: E402


@pytest.mark.parametrize("as_json,legacy_id", [(False, False), (True, False), (False, True)])
def test_converged_eos_preserves_all_lldp_assertion_fields(as_json, legacy_id):
    port = {"interfaceId": '"etp1"', "interfaceDescription": "peer:Ethernet1"}
    if not legacy_id:
        port["interfaceId_v2"] = "etp1"
    output = {"lldpNeighbors": {"Ethernet93": {"lldpNeighborInfo": [
        {"systemName": "previous-device"},
        {
            "systemName": "dut",
            "systemDescription": "SONiC test image",
            "chassisId": "AABB.CCDD.EEFF",
            "neighborInterfaceInfo": port,
        },
    ]}}}
    host = Mock()
    host.eos_command.return_value = {"stdout": [json.dumps(output) if as_json else output]}
    localhost = Mock()

    result = _neighbor_lldp_facts(localhost, None, "test-community", "Ethernet93", "dut", host)

    assert result == {"ansible_lldp_facts": {"Ethernet93": {
        "neighbor_sys_name": "dut",
        "neighbor_sys_desc": "SONiC test image",
        "neighbor_chassis_id": "0xaabbccddeeff",
        "neighbor_port_id": "etp1",
        "neighbor_port_desc": "peer:Ethernet1",
    }}}
    localhost.lldp_facts.assert_not_called()


@pytest.mark.parametrize("neighbors", [{}, {"Ethernet93": {"lldpNeighborInfo": [{"systemName": "other"}]}}])
def test_missing_or_unrelated_neighbor_is_not_a_valid_dut_entry(neighbors):
    host = Mock()
    host.eos_command.return_value = {"stdout": [{"lldpNeighbors": neighbors}]}
    assert _neighbor_lldp_facts(
        Mock(), None, "test-community", "Ethernet93", "dut", host) == {"ansible_lldp_facts": {}}


def test_ordinary_neighbors_keep_snmp_facts():
    localhost = Mock()
    localhost.lldp_facts.return_value = {"ansible_facts": {"ansible_lldp_facts": {"Ethernet1": {"original": True}}}}

    result = _neighbor_lldp_facts(localhost, "192.0.2.1", "test-community", "Ethernet1", "dut")

    assert result == {"ansible_lldp_facts": {"Ethernet1": {"original": True}}}
    localhost.lldp_facts.assert_called_once_with(host="192.0.2.1", version="v2c", community="test-community")


def test_unexpected_interface_is_not_interpolated_into_an_eos_command():
    host = Mock()
    with pytest.raises(pytest.fail.Exception, match="Unexpected EOS LLDP interface name"):
        _neighbor_lldp_facts(Mock(), None, None, "Ethernet1; show version", "dut", host)
    host.eos_command.assert_not_called()
