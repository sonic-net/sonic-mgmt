import contextlib
from unittest.mock import MagicMock, patch

import pytest

from tests.common.helpers import pfcwd_helper
from tests.common.helpers.pfc_storm import PFCStorm
from tests.pfcwd import test_pfcwd_all_port_storm as all_port_storm
from tests.pfcwd.test_pfcwd_all_port_storm import configure_vlan_neighbors


def test_background_traffic_is_stopped_after_test_failure():
    dut = MagicMock()
    ptfhost = MagicMock()

    with patch.object(pfcwd_helper, "is_mellanox_device", return_value=True), \
            patch.object(pfcwd_helper, "_prepare_background_traffic_params", return_value={}), \
            patch.object(pfcwd_helper, "_send_background_traffic", return_value="/tmp/pfc_test.log"), \
            patch.object(pfcwd_helper, "_stop_background_traffic") as stop:
        with pytest.raises(RuntimeError, match="test failure"):
            with pfcwd_helper.send_background_traffic(dut, ptfhost, None, [], {}):
                raise RuntimeError("test failure")

    stop.assert_called_once_with(ptfhost, "/tmp/pfc_test.log")


def test_background_traffic_params_normalize_scalar_queue():
    dut = MagicMock()
    dut.get_dut_iface_mac.return_value = "00:11:22:33:44:55"
    params = pfcwd_helper._prepare_background_traffic_params(
        dut, 3, ["Ethernet0"], {
            "Ethernet0": {
                "rx_port_id": [4],
                "test_port_id": 0,
                "test_neighbor_addr": "10.0.0.1",
                "rx_neighbor_addr": "10.0.0.5",
            },
        }, 500)

    assert params["queues"] == [3]


def test_background_traffic_waits_for_start_marker():
    ptfhost = MagicMock()
    ptfhost.shell.side_effect = [
        {"rc": 1, "stdout_lines": []},
        {"rc": 0, "stdout_lines": []},
    ]

    with patch.object(pfcwd_helper, "ptf_runner") as runner, \
            patch.object(pfcwd_helper.time, "sleep") as sleep:
        log_file = pfcwd_helper._send_background_traffic(ptfhost, {})

    assert log_file.startswith(
        "/tmp/pfc_wd_background_traffic.PfcWdBackgroundTrafficTest.")
    assert runner.call_args.kwargs["log_file"] == log_file
    assert runner.call_args.kwargs["async_mode"] is True
    assert ptfhost.shell.call_count == 2
    sleep.assert_called_once_with(1)


def test_background_traffic_cleans_up_when_start_probe_raises():
    ptfhost = MagicMock()
    ptfhost.shell.side_effect = RuntimeError("probe failed")

    with patch.object(pfcwd_helper, "ptf_runner"), \
            patch.object(pfcwd_helper, "_stop_background_traffic") as stop:
        with pytest.raises(RuntimeError, match="probe failed"):
            pfcwd_helper._send_background_traffic(ptfhost, {})

    assert stop.call_count == 1


def test_stop_background_traffic_uses_self_safe_pattern():
    ptfhost = MagicMock()
    ptfhost.shell.side_effect = [
        {"rc": 0, "stdout_lines": ["101", "102"]},
        {"rc": 0},
        {"rc": 0},
        {"rc": 1, "stdout_lines": []},
    ]

    pfcwd_helper._stop_background_traffic(
        ptfhost, "/tmp/pfc_wd_background_traffic.test.log")

    assert "'/tmp/[p]fc_wd_background_traffic.test.log'" in \
        ptfhost.shell.call_args_list[0].args[0]
    assert ptfhost.shell.call_args_list[1].args[0] == "kill -9 101"
    assert ptfhost.shell.call_args_list[2].args[0] == "kill -9 102"
    assert "pgrep -f" in ptfhost.shell.call_args_list[3].args[0]


def test_configure_vlan_neighbors_assigns_and_cleans_unique_addresses():
    duthost = MagicMock()
    duthost.facts = {"asic_type": "mellanox"}
    duthost.get_ip_in_range.return_value = {
        "ansible_facts": {
            "generated_ips": ["192.168.0.3/21", "192.168.0.4/21"],
        },
    }
    ptfhost = MagicMock()
    test_ports = {
        "Ethernet24": _vlan_port_info(6),
        "Ethernet28": _vlan_port_info(7),
    }
    vlan = {"addr": "192.168.0.1", "prefix": 21, "dev": "Vlan1000"}

    with configure_vlan_neighbors(duthost, ptfhost, test_ports, vlan, "IPv4"):
        assert test_ports["Ethernet24"]["test_neighbor_addr"] == "192.168.0.3"
        assert test_ports["Ethernet28"]["test_neighbor_addr"] == "192.168.0.4"

    commands = [call.args[0] for call in ptfhost.command.call_args_list]
    assert "ip address replace 192.168.0.3/21 dev eth6" in commands
    assert "arping -i eth6 -S 192.168.0.3 -c 3 -w 5 192.168.0.1" in commands
    assert "ip address del 192.168.0.3/21 dev eth6" in commands
    assert "ip neigh del 192.168.0.1 dev eth6" in commands
    dut_commands = [call.args[0] for call in duthost.command.call_args_list]
    assert "ip neigh del 192.168.0.3 dev Vlan1000" in dut_commands
    assert "ip neigh del 192.168.0.4 dev Vlan1000" in dut_commands
    assert test_ports["Ethernet24"]["test_neighbor_addr"] == "192.168.0.2"
    assert test_ports["Ethernet28"]["test_neighbor_addr"] == "192.168.0.2"


def test_configure_vlan_neighbors_preserves_unique_destination():
    duthost = MagicMock()
    duthost.facts = {"asic_type": "mellanox"}
    duthost.get_ip_in_range.return_value = {
        "ansible_facts": {
            "generated_ips": ["192.168.0.4/21", "192.168.0.5/21"],
        },
    }
    ptfhost = MagicMock()
    test_ports = {
        "Ethernet24": _vlan_port_info(6),
        "Ethernet28": _vlan_port_info(7),
        "Ethernet32": {
            **_vlan_port_info(8),
            "test_neighbor_addr": "192.168.0.3",
        },
    }
    vlan = {"addr": "192.168.0.1", "prefix": 21, "dev": "Vlan1000"}

    with configure_vlan_neighbors(duthost, ptfhost, test_ports, vlan, "IPv4"):
        assert test_ports["Ethernet32"]["test_neighbor_addr"] == "192.168.0.3"

    commands = [call.args[0] for call in ptfhost.command.call_args_list]
    assert all("eth8" not in command for command in commands)


def test_configure_vlan_neighbors_cleans_single_unique_destination():
    duthost = MagicMock()
    duthost.facts = {"asic_type": "mellanox"}
    ptfhost = MagicMock()
    test_ports = {
        "Ethernet24": _vlan_port_info(6),
        "Ethernet28": {
            **_vlan_port_info(7),
            "test_neighbor_addr": "192.168.0.3",
        },
    }
    vlan = {"addr": "192.168.0.1", "prefix": 21, "dev": "Vlan1000"}

    with configure_vlan_neighbors(duthost, ptfhost, test_ports, vlan, "IPv4"):
        pass

    commands = [call.args[0] for call in ptfhost.command.call_args_list]
    assert "ip address replace 192.168.0.2/21 dev eth6" in commands
    assert "ip address del 192.168.0.2/21 dev eth6" in commands
    assert all("eth7" not in command for command in commands)


def test_configure_vlan_neighbors_configures_every_unique_cisco_port():
    duthost = MagicMock()
    duthost.facts = {"asic_type": "cisco-8000"}
    ptfhost = MagicMock()
    test_ports = {
        "Ethernet24": _vlan_port_info(6),
        "Ethernet28": {
            **_vlan_port_info(7),
            "test_neighbor_addr": "192.168.0.3",
        },
    }
    vlan = {"addr": "192.168.0.1", "prefix": 21, "dev": "Vlan1000"}

    with configure_vlan_neighbors(duthost, ptfhost, test_ports, vlan, "IPv4"):
        pass

    commands = [call.args[0] for call in ptfhost.command.call_args_list]
    assert "ip address replace 192.168.0.2/21 dev eth6" in commands
    assert "ip address replace 192.168.0.3/21 dev eth7" in commands
    assert "ip address del 192.168.0.2/21 dev eth6" in commands
    assert "ip address del 192.168.0.3/21 dev eth7" in commands
    assert "sysctl -w net.ipv4.conf.all.arp_ignore=1" in commands
    assert "sysctl -w net.ipv4.conf.all.arp_ignore=0" in commands
    duthost.get_ip_in_range.assert_not_called()
    assert not any("ip neigh del" in call.args[0]
                   for call in duthost.command.call_args_list)


def test_configure_vlan_neighbors_uses_explicit_ipv6_source_and_cleans_up():
    duthost = MagicMock()
    duthost.facts = {"asic_type": "mellanox"}
    duthost.get_ip_in_range.return_value = {
        "ansible_facts": {
            "generated_ips": ["fc02:1000::3/64", "fc02:1000::4/64"],
        },
    }
    ptfhost = MagicMock()
    test_ports = {
        "Ethernet24": _vlan_port_info(6, "fc02:1000::2"),
        "Ethernet28": _vlan_port_info(7, "fc02:1000::2"),
    }
    vlan = {"addr": "fc02:1000::1", "prefix": 64, "dev": "Vlan1000"}

    with configure_vlan_neighbors(duthost, ptfhost, test_ports, vlan, "IPv6"):
        pass

    commands = [call.args[0] for call in ptfhost.command.call_args_list]
    assert "ip -6 address replace fc02:1000::3/64 dev eth6 nodad" in commands
    assert "ping -6 -I eth6 -I fc02:1000::3 -c 3 -W 2 fc02:1000::1" in commands
    assert "ip -6 address del fc02:1000::3/64 dev eth6" in commands
    assert "ip -6 neigh del fc02:1000::1 dev eth6" in commands
    dut_commands = [call.args[0] for call in duthost.command.call_args_list]
    assert "ip -6 neigh del fc02:1000::3 dev Vlan1000" in dut_commands


def test_configure_vlan_neighbors_cleans_up_after_arp_failure():
    duthost = MagicMock()
    duthost.facts = {"asic_type": "mellanox"}
    duthost.get_ip_in_range.return_value = {
        "ansible_facts": {
            "generated_ips": ["192.168.0.3/21", "192.168.0.4/21"],
        },
    }
    ptfhost = MagicMock()
    ptfhost.command.side_effect = lambda command, **_kwargs: (
        (_ for _ in ()).throw(RuntimeError("ARP failed"))
        if command.startswith("arping ") else None)
    test_ports = {
        "Ethernet24": _vlan_port_info(6),
        "Ethernet28": _vlan_port_info(7),
    }
    vlan = {"addr": "192.168.0.1", "prefix": 21, "dev": "Vlan1000"}

    with pytest.raises(RuntimeError, match="ARP failed"):
        with configure_vlan_neighbors(duthost, ptfhost, test_ports, vlan, "IPv4"):
            pass

    commands = [call.args[0] for call in ptfhost.command.call_args_list]
    assert "ip address del 192.168.0.3/21 dev eth6" in commands
    assert "ip neigh del 192.168.0.1 dev eth6" in commands
    assert test_ports["Ethernet24"]["test_neighbor_addr"] == "192.168.0.2"


def test_all_port_storm_selects_ports_from_every_fanout():
    dut = MagicMock()
    dut.facts = {"asic_type": "mellanox"}
    storm = MagicMock()
    storm.peer_params = {
        "fanout-1": {"intfs": "Ethernet1"},
        "fanout-2": {"intfs": "Ethernet2"},
    }
    storm.fanout_graph = {
        "fanout-1": {"device_conn": {"Ethernet1": {"peerport": "Ethernet0"}}},
        "fanout-2": {"device_conn": {"Ethernet2": {"peerport": "Ethernet4"}}},
    }
    storm.storm_handle = {
        "fanout-1": MagicMock(pfc_queue_idx=3),
        "fanout-2": MagicMock(pfc_queue_idx=3),
    }
    setup = {
        "test_ports": {"Ethernet0": {}, "Ethernet4": {}},
        "vlan": None,
        "ip_version": "IPv4",
    }
    test = all_port_storm.TestPfcwdAllPortStorm()

    with patch.object(all_port_storm, "configure_vlan_neighbors",
                      return_value=contextlib.nullcontext()), \
            patch.object(all_port_storm, "send_background_traffic",
                         return_value=contextlib.nullcontext()) as traffic, \
            patch.object(test, "run_test") as run_test:
        test.test_all_port_storm_restore(
            {"dut": dut}, "dut", storm, setup, MagicMock(),
            None, None, None, {})

    assert traffic.call_args.args[3] == ["Ethernet0", "Ethernet4"]
    assert run_test.call_args_list[0].kwargs["selected_test_ports"] == [
        "Ethernet0", "Ethernet4"]


def test_arista_backpressure_stop_waits_for_generator_cleanup():
    storm = PFCStorm.__new__(PFCStorm)
    storm.pfc_gen_chip_name = "Tomahawk2"
    storm.pfc_gen_file = "pfc_gen_brcm_xgs.py"
    storm.pfc_queue_idx = 3
    storm.ip_addr = "10.3.146.96"
    storm.peer_info = {
        "peerdevice": "fanout-1",
        "pfc_fanout_interface": "Ethernet1/1,Ethernet2/1",
    }
    storm.peer_device = MagicMock()
    storm.peer_device.os = "eos"
    storm.peer_device.shell.return_value = {"rc": 0}

    storm.stop_storm()

    command = storm.peer_device.shell.call_args.args[0]
    assert "sudo -n pkill -TERM" in command
    assert "sudo -n timeout 120" in command
    assert "case $rc in 0) sleep 1 ;; 1) exit 0 ;; *) exit $rc" in command
    assert r"python3\ pfc_gen_brcm_xgs\.py\ \-c\ Tomahawk2\ \-p\ 8" in command


def test_deferred_arista_storm_uses_pid_and_waits_for_cleanup():
    storm = _arista_storm()
    storm.pfc_storm_defer_time = 5
    storm.pfc_storm_stop_defer_time = 7
    storm._pfc_gen_id = "test-id"
    storm._pfc_gen_pid_file = "/tmp/pfc_storm_test.pid"
    storm._prepare_start_template = MagicMock()
    storm.peer_device.shell.side_effect = [{"rc": 0}, {"rc": 0}, {"rc": 0}]

    storm.start_storm()
    start_command = storm.peer_device.shell.call_args_list[0].args[0]
    assert "PFC_STORM_ID=test-id nohup" in start_command
    assert "sleep 5 && exec python3" in start_command
    assert "echo $! > /tmp/pfc_storm_test.pid" in start_command

    storm.stop_storm()
    stop_command = storm.peer_device.shell.call_args_list[1].args[0]
    assert "pid=$(cat /tmp/pfc_storm_test.pid" in stop_command
    assert "sleep 7" in stop_command
    assert "grep -Fqx" in stop_command
    assert "PFC_STORM_ID=test-id" in stop_command
    assert "kill -TERM" in stop_command
    assert "nohup sh -c" in stop_command

    storm.wait_for_deferred_storm_stop()
    wait_command = storm.peer_device.shell.call_args_list[2].args[0]
    assert "while [ -e /tmp/pfc_storm_test.pid ]" in wait_command
    assert storm._pfc_gen_uses_pid is False
    assert storm._pfc_gen_stop_scheduled is False


def test_deferred_arista_storm_retries_cleanup_after_wait_timeout():
    storm = _arista_storm()
    storm.pfc_storm_stop_defer_time = 7
    storm._pfc_gen_id = "test-id"
    storm._pfc_gen_pid_file = "/tmp/pfc_storm_test.pid"
    storm._pfc_gen_uses_pid = True
    storm._pfc_gen_stop_scheduled = True
    storm.peer_device.shell.side_effect = [{"rc": 124}, {"rc": 0}]

    storm.wait_for_deferred_storm_stop()

    retry_command = storm.peer_device.shell.call_args_list[1].args[0]
    assert "sleep 7" not in retry_command
    assert "kill -TERM" in retry_command
    assert "nohup sh -c" not in retry_command
    assert storm._pfc_gen_uses_pid is False
    assert storm._pfc_gen_stop_scheduled is False


def _arista_storm():
    storm = PFCStorm.__new__(PFCStorm)
    storm.asic_type = "mellanox"
    storm.pfc_gen_chip_name = "Tomahawk2"
    storm.pfc_gen_file = "pfc_gen_brcm_xgs.py"
    storm.pfc_queue_idx = 3
    storm.ip_addr = "10.3.146.96"
    storm.peer_info = {
        "peerdevice": "fanout-1",
        "pfc_fanout_interface": "Ethernet1/1,Ethernet2/1",
    }
    storm.peer_device = MagicMock()
    storm.peer_device.os = "eos"
    storm._pfc_gen_uses_pid = False
    storm._pfc_gen_stop_scheduled = False
    return storm


def _vlan_port_info(port_id, neighbor="192.168.0.2"):
    return {
        "test_port_type": "vlan",
        "test_neighbor_addr": neighbor,
        "test_port_id": port_id,
    }
