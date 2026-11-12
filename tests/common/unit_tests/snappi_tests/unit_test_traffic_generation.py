"""Hardware-independent regressions for shared Snappi traffic generation."""

import ast
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


MODULE_PATH = Path(__file__).resolve().parents[3] / "common/snappi_tests/traffic_generation.py"
FLOW_MODE = SimpleNamespace(FIXED_DURATION="duration", FIXED_PACKETS="packets")


def _pytest_assert(condition, message):
    assert condition, message


def _load(*names, **dependencies):
    nodes = [node for node in ast.parse(MODULE_PATH.read_text()).body
             if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = {"pytest_assert": _pytest_assert, "traffic_flow_mode": FLOW_MODE, "re": re}
    namespace.update(dependencies)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace


@pytest.mark.parametrize("macsec", [False, True])
@pytest.mark.parametrize("mode", [FLOW_MODE.FIXED_PACKETS, FLOW_MODE.FIXED_DURATION, None])
def test_background_flow_duration_and_packet_count(macsec, mode):
    eth, ip, udp = MagicMock(), MagicMock(), MagicMock()
    flow = MagicMock()
    flow.packet.ethernet.return_value.ipv4.return_value.udp.return_value = (eth, ip, udp)
    flow.packet.__getitem__.side_effect = lambda index: ip if index == -1 else eth
    flow.duration = SimpleNamespace(
        fixed_packets=SimpleNamespace(packets=None, delay=SimpleNamespace(nanoseconds=None)),
        fixed_seconds=SimpleNamespace(seconds=None, delay=SimpleNamespace(nanoseconds=None)))
    config = MagicMock()
    config.flows.flow.return_value = [flow]
    bg_config = {
        "flow_name": "Background Flow", "flow_rate_percent": 8, "flow_pkt_size": 1000,
        "flow_pkt_count": 1234, "flow_dur_sec": None if mode == FLOW_MODE.FIXED_PACKETS else 2,
        "flow_delay_sec": 1.5,
    }
    if mode is not None:
        bg_config["flow_traffic_type"] = mode
    params = SimpleNamespace(
        base_flow_config_list=[], flow_name_prio_map={},
        base_flow_config={
            "tx_port_name": "Port 1", "rx_port_name": "Port 0",
            "tx_mac": "00:00:00:00:00:01", "rx_mac": "00:00:00:00:00:02",
            "tx_port_config": SimpleNamespace(ip="192.0.2.1"),
            "rx_port_config": SimpleNamespace(ip="192.0.2.2"),
        },
        traffic_flow_config=SimpleNamespace(background_flow_config=bg_config))
    generate = _load(
        "generate_background_flows", sys=SimpleNamespace(argv=["--snappi_macsec"] if macsec else []),
        random=SimpleNamespace(choice=lambda values: values[0]), pfc_queue_group_size=lambda: 8,
        gen_data_flow_dest_ip=lambda address: address, sec_to_nanosec=lambda seconds: seconds * 1e9,
        UDP_PORT_START=5000)["generate_background_flows"]

    generate(config, [3], {3: [24]}, params)

    if mode == FLOW_MODE.FIXED_PACKETS:
        assert flow.duration.fixed_packets.packets == 1234
        assert flow.duration.fixed_packets.delay.nanoseconds == 1500000000
        assert flow.duration.fixed_seconds.seconds is None
    else:
        assert flow.duration.fixed_seconds.seconds == 2
        assert flow.duration.fixed_seconds.delay.nanoseconds == 1500000000
        assert flow.duration.fixed_packets.packets is None


@pytest.mark.parametrize("background", [False, True])
@pytest.mark.parametrize(
    "mode, expected", [(FLOW_MODE.FIXED_PACKETS, 1000), (FLOW_MODE.FIXED_DURATION, 20000), (None, 20000)])
def test_generic_flow_verifiers_check_packet_count_or_duration(background, mode, expected):
    flow_name = "Background Flow" if background else "Test Flow"
    flow_config = {
        "flow_name": flow_name, "flow_rate_percent": 8 if background else {3: 8},
        "flow_pkt_size": 1000, "flow_pkt_count": 1000,
        "flow_dur_sec": None if mode == FLOW_MODE.FIXED_PACKETS else 2,
    }
    if mode is not None:
        flow_config["flow_traffic_type"] = mode
    params = SimpleNamespace(traffic_flow_config=SimpleNamespace(
        data_flow_config=flow_config, background_flow_config=flow_config))
    name = "verify_background_flow" if background else "verify_basic_test_flow"
    verify = _load(name)[name]
    arguments = {"speed_gbps": 1, "tolerance": 0.05, "snappi_extra_params": params}
    if not background:
        arguments["test_flow_pause"] = False
    metric = SimpleNamespace(name=flow_name + " Prio 3", frames_tx=expected, frames_rx=expected)

    verify([metric], **arguments)
    metric.frames_tx = metric.frames_rx = int(expected * 0.8)
    with pytest.raises(AssertionError, match="should receive"):
        verify([metric], **arguments)


def _macsec_run_context(stop_before, poll_device_runtime=False, traffic_state="started"):
    api = MagicMock()
    ixnet = api._ixnetwork
    ixnet.Topology.find.return_value = []
    ixnet.Traffic.TrafficItem.find.return_value = [
        MagicMock(Name="Test Flow Prio 3"), MagicMock(Name="Pause Storm")]
    ixnet.Traffic.State = traffic_state
    host = MagicMock()
    host.facts = {"num_asic": 1}
    config = SimpleNamespace(ports=[SimpleNamespace(name="Port 0")], devices=[
        SimpleNamespace(ethernets=[SimpleNamespace(mac="00:00:00:00:00:01")])])
    params = SimpleNamespace(
        reboot_type=None, poll_device_runtime=poll_device_runtime, packet_capture_type=0,
        stop_data_flows_before_final_stats=stop_before, flow_name_prio_map={"Test Flow Prio 3": 3},
        multi_dut_params=SimpleNamespace(ingress_duthosts=[], egress_duthosts=[], multi_dut_ports=[]),
        base_flow_config={
            "dut_port_config": {"Tx": [{"Ethernet12": [3]}]},
            "tx_port_config": SimpleNamespace(peer_port="Ethernet12"),
            "rx_port_config": SimpleNamespace(peer_port="Ethernet8"),
            "tx_port_name": "Port 1", "rx_port_name": "Port 0",
        })
    early = [{"Tx Port": "Port 1", "Rx Port": "Port 0", "PGID": "3", "Tx Frames": "100", "Rx Frames": "0"}]
    late = [dict(early[0], **{"Tx Frames": "200", "Rx Frames": "1"})]
    final = [dict(late[0], **{"Rx Frames": "200", "Tx Frame Rate": "0"})]
    events = []
    snapshots = iter([early, late])

    def capture(*args, **kwargs):
        events.append("capture")
        return next(snapshots)

    def stop():
        events.append("stop")
        ixnet.Traffic.State = "stopped"

    ixnet.Traffic.StopStatelessTrafficBlocking.side_effect = stop
    dependencies = {
        "sys": SimpleNamespace(argv=["--snappi_macsec"]), "logger": MagicMock(),
        "time": SimpleNamespace(sleep=lambda seconds: events.append(("sleep", seconds))),
        "packet_capture": SimpleNamespace(NO_CAPTURE=0),
        "StatViewAssistant": MagicMock(return_value=SimpleNamespace(Rows=[])),
        "_capture_in_flight_tgen_stats": MagicMock(side_effect=capture),
        "fetch_flow_metrics_for_macsec": MagicMock(return_value=SimpleNamespace(Rows=final)),
        "get_egress_queue_count": MagicMock(return_value=(0, 0)),
        "SNAPPI_POLL_DELAY_SEC": 2, "ANSIBLE_POLL_DELAY_SEC": 4,
    }
    for name in ("clear_macsec_counters", "wait", "_configure_macsec_dut_sci_macs",
                 "clear_dut_interface_counters", "clear_dut_que_counters", "clear_dut_pfc_counters",
                 "_apply_ixnetwork_traffic", "_log_in_flight_stats", "check_for_crc_errors"):
        dependencies[name] = MagicMock()
    namespace = _load("run_traffic", "_stop_macsec_data_flows", "verify_test_flow_stats_for_macsec", **dependencies)
    return namespace, api, host, config, params, events, late


@pytest.mark.parametrize("failed_counter", ["Sessions Down", "Sessions Not Started"])
def test_macsec_protocol_failure_reports_the_protocol_and_all_session_counts(failed_counter):
    """Keep the failing protocol and complete readiness snapshot in diagnostics."""
    namespace, api, host, config, params, _, _ = _macsec_run_context(False)
    protocol_rows = [
        {"Protocol Type": protocol, "Sessions Total": "1", "Sessions Up": "1",
         "Sessions Down": "0", "Sessions Not Started": "0"}
        for protocol in ("IPv4", "MKA", "Static MACsec")
    ]
    protocol_rows[1]["Sessions Up"] = "0"
    protocol_rows[1][failed_counter] = "1"
    namespace["StatViewAssistant"].return_value.Rows = protocol_rows

    with pytest.raises(AssertionError, match="MKA"):
        namespace["run_traffic"](
            host, api, config, ["Test Flow Prio 3"], ["Test Flow Prio 3", "Pause Storm"], 15, params)

    namespace["logger"].info.assert_any_call("MACsec protocol session statistics: %s", protocol_rows)


@pytest.mark.parametrize("poll_device_runtime", [False, True])
def test_macsec_pause_snapshot_is_captured_immediately_before_single_stop(poll_device_runtime):
    namespace, api, host, config, params, events, late = _macsec_run_context(True, poll_device_runtime)

    final, _, in_flight = namespace["run_traffic"](
        host, api, config, ["Test Flow Prio 3"], ["Test Flow Prio 3", "Pause Storm"], 15, params)

    assert in_flight is late
    assert final[0]["Rx Frames"] == "200"
    stop_index = events.index("stop")
    assert events[stop_index - 1] == "capture"
    assert events[stop_index - 2][0] == "sleep"
    api._ixnetwork.Traffic.StopStatelessTrafficBlocking.assert_called_once()
    params.traffic_flow_config = SimpleNamespace(data_flow_config={"flow_name": "Test Flow"})
    with pytest.raises(AssertionError, match="should be paused"):
        namespace["verify_test_flow_stats_for_macsec"](in_flight, 1, 0.05, True, params)


@pytest.mark.parametrize("state, stop_count", [("stopped", 0), ("stoppedWaitingForStats", 0), ("started", 1)])
def test_macsec_final_stop_respects_existing_traffic_state(state, stop_count):
    namespace, api, host, config, params, _, _ = _macsec_run_context(False, traffic_state=state)

    namespace["run_traffic"](
        host, api, config, ["Test Flow Prio 3"], ["Test Flow Prio 3", "Pause Storm"], 15, params)

    assert api._ixnetwork.Traffic.StopStatelessTrafficBlocking.call_count == stop_count
