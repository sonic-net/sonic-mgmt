"""Unit tests for cSONiC's userspace-OVS LAG helper."""

import importlib.util
import os
from unittest.mock import call, patch


HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(os.path.dirname(HERE), "csonic_ovs_lag.py")
SPEC = importlib.util.spec_from_file_location("csonic_ovs_lag", MODULE_PATH)
OVS_LAG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OVS_LAG)


def _tables(vrf="VrfARISTA02T1"):
    base = {"vrf_name": vrf} if vrf else {}
    return {
        "portchannels": {"PortChannel2": {"mtu": "9100", "min_links": "1"}},
        "members": {("PortChannel2", "Ethernet2"): {}},
        "interfaces": {
            "PortChannel2": base,
            ("PortChannel2", "10.0.0.59/31"): {},
        },
    }


def test_portchannel_vrf_reads_base_interface_attributes():
    assert OVS_LAG.portchannel_vrf(_tables(), "PortChannel2") == "VrfARISTA02T1"
    assert OVS_LAG.portchannel_vrf(_tables(vrf=None), "PortChannel2") is None


def test_wait_for_link_uses_exit_status_not_error_text():
    missing = type("Result", (), {"returncode": 1})()
    present = type("Result", (), {"returncode": 0})()
    with patch.object(OVS_LAG.subprocess, "run",
                      side_effect=[missing, present]) as run, \
            patch.object(OVS_LAG.time, "sleep"):
        OVS_LAG.wait_for_link("VrfARISTA02T1", timeout=2)
    assert run.call_count == 2


def test_apply_restores_vrf_master_before_addresses():
    tables = _tables()
    with patch.object(OVS_LAG, "config_db_tables", return_value=tables), \
            patch.object(OVS_LAG, "stop_teamd"), \
            patch.object(OVS_LAG, "start_ovs"), \
            patch.object(OVS_LAG, "ovs_portchannel"), \
            patch.object(OVS_LAG, "wait_for_link") as wait_for_link, \
            patch.object(OVS_LAG, "check_portchannels"), \
            patch.object(OVS_LAG, "call", return_value="") as run:
        OVS_LAG.apply()

    wait_for_link.assert_called_once_with("VrfARISTA02T1")
    assert call(["ip", "link", "set", "PortChannel2", "master", "VrfARISTA02T1"]) in run.call_args_list
    assert call(["ip", "address", "replace", "10.0.0.59/31", "dev", "PortChannel2"]) in run.call_args_list
    master_index = run.call_args_list.index(
        call(["ip", "link", "set", "PortChannel2", "master", "VrfARISTA02T1"]))
    address_index = run.call_args_list.index(
        call(["ip", "address", "replace", "10.0.0.59/31", "dev", "PortChannel2"]))
    assert master_index < address_index


def test_apply_leaves_stock_portchannel_without_vrf_master():
    tables = _tables(vrf=None)
    with patch.object(OVS_LAG, "config_db_tables", return_value=tables), \
            patch.object(OVS_LAG, "stop_teamd"), \
            patch.object(OVS_LAG, "start_ovs"), \
            patch.object(OVS_LAG, "ovs_portchannel"), \
            patch.object(OVS_LAG, "wait_for_link") as wait_for_link, \
            patch.object(OVS_LAG, "check_portchannels"), \
            patch.object(OVS_LAG, "call", return_value="") as run:
        OVS_LAG.apply()

    wait_for_link.assert_not_called()
    assert not [args for args in run.call_args_list
                if args.args and args.args[0][:5] ==
                ["ip", "link", "set", "PortChannel2", "master"]]
