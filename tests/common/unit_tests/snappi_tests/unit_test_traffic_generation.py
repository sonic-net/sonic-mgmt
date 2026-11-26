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
    config = SimpleNamespace(lags=[], ports=[SimpleNamespace(name="Port 0")], devices=[
        SimpleNamespace(ethernets=[SimpleNamespace(mac="00:00:00:00:00:01")])])
    params = SimpleNamespace(
        reboot_type=None, poll_device_runtime=poll_device_runtime, packet_capture_type=0,
        stop_data_flows_before_final_stats=stop_before, flow_name_prio_map={"Test Flow Prio 3": 3},
        flow_name_stats_identity_map={},
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


MACSEC_IDENTITY_MAP = {
    'Test Flow 1 -> 0': ('Port 1', 'Port 0', 3),
    'Test Flow 2 -> 0': ('Port 2', 'Port 0', 11),
}


def _macsec_stats_row(port='Port 1', pgid='3', tx='100', rx='100', tx_rate='0', rx_rate='0'):
    return {
        'Tx Port': port,
        'Rx Port': 'Port 0',
        'PGID': pgid,
        'Tx Frames': tx,
        'Rx Frames': rx,
        'Tx Frame Rate': tx_rate,
        'Rx Frame Rate': rx_rate,
    }


def _macsec_stats_snapshot(**kwargs):
    return [_macsec_stats_row(**kwargs), _macsec_stats_row(port='Port 2', pgid='11')]


@pytest.fixture
def stats_waiter():
    """Load final-statistics polling without integration-test dependencies."""
    fetch = MagicMock()
    sleep = MagicMock()
    namespace = _load(
        '_macsec_row_identity', '_wait_for_macsec_flow_statistics',
        fetch_flow_metrics_for_macsec=fetch, time=SimpleNamespace(sleep=sleep),
        SNAPPI_POLL_DELAY_SEC=2, logger=MagicMock(), _log_macsec_counter_diagnostics=MagicMock())
    api = MagicMock()
    api._ixnetwork.Traffic.State = 'stopped'
    return namespace['_wait_for_macsec_flow_statistics'], fetch, sleep, api


def test_waits_for_stale_tx_counters(stats_waiter):
    """Reproduce RX exceeding the earlier TX snapshot, then let TX catch up."""
    wait, fetch, sleep, api = stats_waiter
    stale = _macsec_stats_snapshot(tx='136656369', rx='167624521')
    settled = _macsec_stats_snapshot(tx='167624521', rx='167624521')
    fetch.side_effect = [SimpleNamespace(Rows=rows) for rows in (stale, settled, settled)]

    assert wait(api, MACSEC_IDENTITY_MAP) is settled
    assert fetch.call_count == 3
    assert sleep.call_count == 2


@pytest.mark.parametrize('first', [
    _macsec_stats_snapshot(tx=''),
    _macsec_stats_snapshot(rx=''),
    _macsec_stats_snapshot(tx_rate=''),
    _macsec_stats_snapshot(rx_rate=''),
    _macsec_stats_snapshot(tx_rate='nan'),
    _macsec_stats_snapshot(rx_rate='inf'),
    _macsec_stats_snapshot(tx_rate='-1'),
    _macsec_stats_snapshot(tx='0', rx='0'),
    _macsec_stats_snapshot(rx='-1'),
    _macsec_stats_snapshot()[:1],
    [],
])
def test_waits_for_all_flows_and_complete_stopped_counters(stats_waiter, first):
    """Reject partial rows, missing flows, and invalid counters or frame rates."""
    wait, fetch, _, api = stats_waiter
    settled = _macsec_stats_snapshot()
    fetch.side_effect = [SimpleNamespace(Rows=rows) for rows in (first, settled, settled)]

    assert wait(api, MACSEC_IDENTITY_MAP) is settled
    assert fetch.call_count == 3


def test_waits_for_stable_counts(stats_waiter):
    """Zero frame rates alone do not mean counters have finished updating."""
    wait, fetch, _, api = stats_waiter
    settled = _macsec_stats_snapshot(tx='120', rx='120')
    fetch.side_effect = [
        SimpleNamespace(Rows=rows) for rows in (_macsec_stats_snapshot(), settled, settled)
    ]

    assert wait(api, MACSEC_IDENTITY_MAP) is settled
    assert fetch.call_count == 3


def test_preserves_real_packet_loss(stats_waiter):
    """Return genuine positive loss unchanged for the existing flow verifier."""
    wait, fetch, _, api = stats_waiter
    rows = _macsec_stats_snapshot(rx='90')
    fetch.return_value = SimpleNamespace(Rows=rows)

    assert wait(api, MACSEC_IDENTITY_MAP) is rows
    assert rows[0]['Rx Frames'] == '90'
    assert fetch.call_count == 2


def test_ignores_unregistered_rows(stats_waiter):
    """Unrelated or egress-only rows must not block registered flows."""
    wait, fetch, _, api = stats_waiter
    rows = _macsec_stats_snapshot() + [
        _macsec_stats_row(port='', tx=''), _macsec_stats_row(port='Port 3', pgid='17', tx_rate='100'),
    ]
    fetch.return_value = SimpleNamespace(Rows=rows)

    assert wait(api, MACSEC_IDENTITY_MAP) is rows


@pytest.mark.parametrize('rows, message', [
    (_macsec_stats_snapshot(rx='101'), 'RX=101'),
    (_macsec_stats_snapshot()[:1], 'Missing statistics'),
    (_macsec_stats_snapshot() + [_macsec_stats_row()], 'duplicate statistics rows'),
])
def test_fails_explicitly_when_statistics_do_not_settle(stats_waiter, rows, message):
    """Fail persistent invalid statistics with diagnostics, not as packet loss."""
    wait, fetch, sleep, api = stats_waiter
    fetch.return_value = SimpleNamespace(Rows=rows)

    with pytest.raises(AssertionError, match=message):
        wait(api, MACSEC_IDENTITY_MAP, max_attempts=3)
    assert fetch.call_count == 3
    assert sleep.call_count == 2


def test_times_out_if_counters_keep_changing(stats_waiter):
    """Bound polling even when every individual snapshot is otherwise valid."""
    wait, fetch, _, api = stats_waiter
    fetch.side_effect = [
        SimpleNamespace(Rows=_macsec_stats_snapshot(tx=str(count), rx=str(count)))
        for count in (100, 101, 102)
    ]

    with pytest.raises(AssertionError, match='counters are still changing'):
        wait(api, MACSEC_IDENTITY_MAP, max_attempts=3)


@pytest.mark.parametrize('state', ['stopped', 'stoppedWaitingForStats'])
@pytest.mark.parametrize('tx_rate, rx_rate', [
    ('15561971.602', '15561971.602'), ('0.1', '0'), ('0', '0.1'),
])
def test_completed_engine_accepts_stable_counters_with_retained_rates(stats_waiter, state, tx_rate, rx_rate):
    """Completed Quick Flow Groups can retain nonzero rate cells despite stable final counts."""
    wait, fetch, _, api = stats_waiter
    api._ixnetwork.Traffic.State = state
    rows = _macsec_stats_snapshot(tx='167624521', rx='167624521', tx_rate=tx_rate, rx_rate=rx_rate)
    fetch.return_value = SimpleNamespace(Rows=rows)

    assert wait(api, MACSEC_IDENTITY_MAP) is rows
    assert fetch.call_count == 2
    wait.__globals__['logger'].warning.assert_called_once()
    assert rows[0]['Tx Frame Rate'] == tx_rate
    assert rows[0]['Rx Frame Rate'] == rx_rate


@pytest.mark.parametrize('state', ['started', 'stopping', ''])
@pytest.mark.parametrize('rate', ['0', '0.1'])
def test_stable_counters_never_override_incomplete_engine_state(stats_waiter, state, rate):
    """Even zero rates and stable counters cannot establish traffic-engine completion."""
    wait, fetch, _, api = stats_waiter
    api._ixnetwork.Traffic.State = state
    fetch.return_value = SimpleNamespace(Rows=_macsec_stats_snapshot(tx_rate=rate, rx_rate=rate))

    with pytest.raises(AssertionError, match='Traffic engine has not stopped'):
        wait(api, MACSEC_IDENTITY_MAP, max_attempts=3)
    assert fetch.call_count == 3


def test_counter_stability_is_checked_after_engine_completion(stats_waiter):
    """Do not count snapshots collected while the traffic engine is still running as final."""
    wait, fetch, sleep, api = stats_waiter
    api._ixnetwork.Traffic.State = 'started'
    rows = _macsec_stats_snapshot(tx_rate='100', rx_rate='100')
    fetch.return_value = SimpleNamespace(Rows=rows)
    sleep.side_effect = lambda _: setattr(api._ixnetwork.Traffic, 'State', 'stoppedWaitingForStats')

    assert wait(api, MACSEC_IDENTITY_MAP) is rows
    assert fetch.call_count == 3


def test_retained_rates_do_not_hide_loss_or_changing_counters(stats_waiter):
    """Wait for stability and preserve genuine packet loss even when rate cells stay nonzero."""
    wait, fetch, _, api = stats_waiter
    changing = _macsec_stats_snapshot(tx='110', rx='100', tx_rate='100', rx_rate='100')
    final = _macsec_stats_snapshot(tx='120', rx='100', tx_rate='100', rx_rate='100')
    fetch.side_effect = [SimpleNamespace(Rows=rows) for rows in (changing, final, final)]

    assert wait(api, MACSEC_IDENTITY_MAP) is final
    assert final[0]['Tx Frames'] == '120'
    assert final[0]['Rx Frames'] == '100'
    assert fetch.call_count == 3


@pytest.mark.parametrize("state", ["stopped", "stoppedWaitingForStats"])
def test_run_traffic_waits_for_registered_final_macsec_statistics(state):
    """Finalize traffic before polling counters and use the settled snapshot unchanged."""
    namespace, api, host, config, params, events, _ = _macsec_run_context(False, traffic_state=state)
    params.flow_name_stats_identity_map = MACSEC_IDENTITY_MAP
    namespace.update(_load('_macsec_row_identity', '_to_number'))
    settled = _macsec_stats_snapshot()

    def wait_for_stats(*args):
        events.append("final statistics")
        assert api._ixnetwork.Traffic.State in ('stopped', 'stoppedWaitingForStats')
        return settled

    waiter = MagicMock(side_effect=wait_for_stats)
    namespace['_wait_for_macsec_flow_statistics'] = waiter

    final, _, _ = namespace["run_traffic"](
        host, api, config, ["Test Flow Prio 3"], ["Test Flow Prio 3", "Pause Storm"], 15, params)

    assert final is settled
    waiter.assert_called_once_with(api, MACSEC_IDENTITY_MAP)
    api._ixnetwork.Traffic.StopStatelessTrafficBlocking.assert_not_called()
    namespace['_capture_in_flight_tgen_stats'].assert_not_called()
    namespace['fetch_flow_metrics_for_macsec'].assert_not_called()


def test_macsec_statistics_failure_does_not_skip_blocking_stop():
    """A statistics timeout must not prevent the traffic shutdown operation."""
    namespace, api, host, config, params, _, _ = _macsec_run_context(True)
    params.flow_name_stats_identity_map = MACSEC_IDENTITY_MAP
    namespace.update(_load('_macsec_row_identity', '_to_number'))

    def fail_statistics(*args):
        api._ixnetwork.Traffic.StopStatelessTrafficBlocking.assert_called_once()
        raise AssertionError("statistics did not settle")

    namespace['_wait_for_macsec_flow_statistics'] = fail_statistics

    with pytest.raises(AssertionError, match="statistics did not settle"):
        namespace["run_traffic"](
            host, api, config, ["Test Flow Prio 3"], ["Test Flow Prio 3", "Pause Storm"], 15, params)


def test_registered_macsec_flows_preserve_pause_snapshot_without_double_stop():
    """Keep pause-time verification data while final statistics use stopped traffic."""
    namespace, api, host, config, params, _, late = _macsec_run_context(True)
    params.flow_name_stats_identity_map = MACSEC_IDENTITY_MAP
    waiter = MagicMock(return_value=_macsec_stats_snapshot())
    namespace['_wait_for_macsec_flow_statistics'] = waiter

    _, _, in_flight = namespace["run_traffic"](
        host, api, config, ["Test Flow Prio 3"], ["Test Flow Prio 3", "Pause Storm"], 15, params)

    assert in_flight is late
    api._ixnetwork.Traffic.StopStatelessTrafficBlocking.assert_called_once()
    waiter.assert_called_once_with(api, MACSEC_IDENTITY_MAP)


def test_macsec_blocking_stop_failure_prevents_final_statistics():
    """Do not read final counters when IxNetwork has not actually stopped traffic."""
    namespace, api, host, config, params, _, _ = _macsec_run_context(True)
    params.flow_name_stats_identity_map = MACSEC_IDENTITY_MAP
    namespace.update(_load('_macsec_row_identity', '_to_number'))
    api._ixnetwork.Traffic.StopStatelessTrafficBlocking.side_effect = None
    waiter = MagicMock()
    namespace['_wait_for_macsec_flow_statistics'] = waiter

    with pytest.raises(AssertionError, match="IxNetwork traffic did not stop; current state"):
        namespace["run_traffic"](
            host, api, config, ["Test Flow Prio 3"], ["Test Flow Prio 3", "Pause Storm"], 15, params)

    waiter.assert_not_called()


@pytest.mark.parametrize("poll_device_runtime", [False, True])
@pytest.mark.parametrize("completed_state", ["stopped", "stoppedWaitingForStats"])
def test_deferred_macsec_first_read_waits_for_engine_completion(poll_device_runtime, completed_state):
    """Do not sample Quick Flow Group counters until traffic-engine completion."""
    namespace, api, host, config, params, events, _ = _macsec_run_context(False, poll_device_runtime)
    params.flow_name_stats_identity_map = MACSEC_IDENTITY_MAP
    settled = _macsec_stats_snapshot()

    def sleep(seconds):
        events.append(("sleep", seconds))
        if seconds == 2:
            events.append("engine completed")
            api._ixnetwork.Traffic.State = completed_state

    def final_statistics(*args):
        events.append("first statistics read")
        assert api._ixnetwork.Traffic.State == completed_state
        return settled

    namespace['time'] = SimpleNamespace(sleep=sleep)
    namespace['_wait_for_macsec_flow_statistics'] = MagicMock(side_effect=final_statistics)

    final, _, in_flight = namespace["run_traffic"](
        host, api, config, ["Test Flow Prio 3"], ["Test Flow Prio 3", "Pause Storm"], 15, params)

    assert final is settled
    assert in_flight is None
    assert events.index("engine completed") < events.index("first statistics read")
    namespace['_capture_in_flight_tgen_stats'].assert_not_called()
    namespace['fetch_flow_metrics_for_macsec'].assert_not_called()
    namespace['_log_in_flight_stats'].assert_not_called()


def test_deferred_macsec_engine_timeout_never_reads_counters():
    """A running traffic engine must time out explicitly without triggering a statistics snapshot."""
    namespace, api, host, config, params, _, _ = _macsec_run_context(False)
    params.flow_name_stats_identity_map = MACSEC_IDENTITY_MAP
    waiter = MagicMock()
    namespace['_wait_for_macsec_flow_statistics'] = waiter

    with pytest.raises(AssertionError, match="traffic engine did not finish after 20 completion checks"):
        namespace["run_traffic"](
            host, api, config, ["Test Flow Prio 3"], ["Test Flow Prio 3", "Pause Storm"], 15, params)

    waiter.assert_not_called()
    namespace['_capture_in_flight_tgen_stats'].assert_not_called()
    namespace['fetch_flow_metrics_for_macsec'].assert_not_called()


def test_statistics_timeout_collects_diagnostics_before_failing(stats_waiter):
    """Retain the original assertion while collecting independent counter snapshots."""
    wait, fetch, _, api = stats_waiter
    rows = _macsec_stats_snapshot(rx='101')
    fetch.return_value = SimpleNamespace(Rows=rows)
    diagnostics = wait.__globals__['_log_macsec_counter_diagnostics']

    with pytest.raises(AssertionError, match='RX=101'):
        wait(api, MACSEC_IDENTITY_MAP, max_attempts=2)

    diagnostics.assert_called_once_with(api, rows)


def test_macsec_counter_diagnostics_capture_raw_independent_views():
    """Log raw flow, traffic-item, and port counters without changing any values."""
    api = MagicMock()
    flow_rows = SimpleNamespace(Columns=['Tx Frames', 'Rx Frames'], RawData=[['90', '100']])
    item_rows = SimpleNamespace(Columns=['Traffic Item', 'Tx Frames'], RawData=[['Test Flow', '100']])
    port_rows = SimpleNamespace(Columns=['Port', 'Frames Tx.'], RawData=[['Port 1', '100']])
    assistant = MagicMock(side_effect=[
        SimpleNamespace(Rows=item_rows), SimpleNamespace(Rows=port_rows),
    ])
    formatter = MagicMock(return_value='counter table')
    logger = MagicMock()
    namespace = _load(
        '_log_macsec_counter_diagnostics', StatViewAssistant=assistant,
        tabulate=formatter, logger=logger, IxNetworkError=RuntimeError)

    namespace['_log_macsec_counter_diagnostics'](api, flow_rows)

    assert [call.args[1] for call in assistant.call_args_list] == [
        'Traffic Item Statistics', 'Port Statistics',
    ]
    assert [call.args[0] for call in formatter.call_args_list] == [
        flow_rows.RawData, item_rows.RawData, port_rows.RawData,
    ]
    assert logger.error.call_count == 3
    assert flow_rows.RawData == [['90', '100']]


@pytest.mark.parametrize('sdk_error', [False, True])
def test_missing_diagnostic_view_does_not_replace_statistics_failure(sdk_error):
    """Unavailable views and explicit SDK errors are logged rather than hiding the timeout."""
    api = MagicMock()
    api._ixnetwork.Statistics.View.find.return_value = [MagicMock()] if sdk_error else []
    assistant = MagicMock(side_effect=RuntimeError('view unavailable'))
    logger = MagicMock()
    namespace = _load(
        '_log_macsec_counter_diagnostics', StatViewAssistant=assistant,
        tabulate=MagicMock(), logger=logger, IxNetworkError=RuntimeError)
    rows = SimpleNamespace(Columns=[], RawData=[])

    namespace['_log_macsec_counter_diagnostics'](api, rows)

    if sdk_error:
        assert logger.exception.call_count == 2
    else:
        assert logger.error.call_count == 3
        assistant.assert_not_called()
