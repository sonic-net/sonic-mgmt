# This helper re-exports common snappi/QoS fixtures via `import *` so test files can
# pull fixtures + helpers from this one module; F403/F401/F405 are expected for that
# pattern and intentionally ignored here.
# flake8: noqa: F403, F401, F405
"""
Self-contained RoCEv2 data-plane test library.

This module is standalone - it depends only on the common snappi/QoS fixtures,
not on other rocev2 test helpers. It bundles everything a data-plane test needs
so the test file itself stays small and expresses only its *intent*:
    * which queues / priorities it drives, and the traffic config
    * the checks to assert

Everything else (build topology -> run traffic -> sample steady-state rates ->
pull DUT queue counters + scheduler config -> build the per-flow and aggregate
DataFrames the checks run against) lives here.

Layers in this file:
    1. Fixture re-exports + base config helpers (snappi_dut_port_mapping,
       configure_rocev2_topology).
    2. Traffic control + metrics (start_stop, get_stats, sample_flow_rates,
       run_rocev2_step).
    3. DUT-side data (scheduler_weights, queue_counters, queue_stats).
    4. Analysis (dwrr_expected_rates) + check runner (make_check, assert_queries).
    5. High-level glue (derive_priority_to_dscp, build_pairwise_topology, the
       aggregate builders, and collect_rocev2_dp_stats -> Rocev2DpStats).
"""
import random
import logging
import json
import time
import collections
from dataclasses import dataclass

import pandas as pd
from tabulate import tabulate
from ixnetwork_restpy.assistants.statistics.statviewassistant import StatViewAssistant

from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.utilities import wait_until, wait

# Fixtures re-exported so a test can `from ...files.helper import *` and pull
# everything (incl. fixtures) from this one module.
from tests.common.fixtures.conn_graph_facts import (
    conn_graph_facts,
    fanout_graph_facts,
    fanout_graph_facts_multidut,
)
from tests.common.snappi_tests.snappi_fixtures import (
    snappi_api_serv_ip,
    snappi_api_serv_port,
    snappi_api,
    snappi_testbed_config,
    get_snappi_ports_single_dut,
    get_snappi_ports_multi_dut,
    get_snappi_ports,
    snappi_dut_base_config,
)
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map

logger = logging.getLogger(__name__)

# Latency thresholds are in NANOSECONDS. snappi/IxNetwork report RoCEv2 per-QP
# latency in ns (the schema carries no unit); e.g. observed ~930-980 ns for small
# messages on a no-congestion run, so the 5 us / 50 us caps below are generous.
LATENCY_SPECS = {
    "avg_latency_max": 5000,     # ns  (= 5 us)
    "max_latency_max": 50000,    # ns  (= 50 us)
}
LATENCY_PROFILES = {
    "ai": LATENCY_SPECS,
    "storage": LATENCY_SPECS,
}


# ===========================================================================
# 1. Base config helpers
# ===========================================================================
def snappi_dut_port_mapping(snappi_ports):
    dut_tg_port_map = collections.defaultdict(list)
    for intf in snappi_ports:
        dut_tg_port_map[intf["duthost"]].append((intf["peer_port"], f"Port {intf['port_id']}"))
    return {duthost: dict(ports) for duthost, ports in dut_tg_port_map.items()}


def configure_rocev2_topology(config, port_config_list, topology):
    """
    Apply a RoCEv2 topology onto a snappi config. Each topology entry is keyed
    by tx port id and may carry: peers (required), mtu, qp_configs, cnp,
    connection_type, dcqcn_settings, rocev2_port_config. Missing keys fall back
    to the defaults below.
    """
    default_qp_configs = [
        {"qp_num": 33, "dscp": 3, "ecn": "non_ect", "message_size_unit": "mb", "message_size": 1},
        {"qp_num": 34, "dscp": 4, "ecn": "non_ect", "message_size_unit": "mb", "message_size": 1},
        {"qp_num": 35, "dscp": 0, "ecn": "non_ect", "message_size_unit": "mb", "message_size": 1},
        {"qp_num": 36, "dscp": 1, "ecn": "non_ect", "message_size_unit": "mb", "message_size": 1},
        {"qp_num": 37, "dscp": 5, "ecn": "non_ect", "message_size_unit": "mb", "message_size": 1},
        {"qp_num": 38, "dscp": 46, "ecn": "non_ect", "message_size_unit": "mb", "message_size": 1},
        {"qp_num": 39, "dscp": 48, "ecn": "non_ect", "message_size_unit": "mb", "message_size": 1},
    ]
    default_cnp_config = {"choice": "ip_dscp", "ip_dscp": 0, "ecn_value": "non_ect", "cnp_delay_timer": 111}
    default_connection_type_config = {
        "choice": "reliable_connection",
        "reliable_connection": {
            "ack": {"choice": "ip_dscp", "ip_dscp": 48, "ecn_value": "non_ect"},
            "enable_retransmission_timeout": True,
            "retransmission_timeout_value": 5000,
            "retransmission_retry_count": 254
        },
    }
    default_dcqcn_settings_config = {"enable_dcqcn": True, "alpha_g": 1020, "initial_alpha": 1000,
                                     "maximum_rate_decrement_at_time": 12}
    default_rocev2_port_config = {"transmit_type": "target_line_rate", "target_line_rate": 100}

    port_to_dev_ip = {pc.id: {"device": None, "ip": pc.ip} for pc in port_config_list if pc.ip}
    for dev in config.devices:
        if (name := getattr(dev, "name", "")) and name.startswith("Device Port "):
            try:
                port_to_dev_ip[int(name.split()[-1])]["device"] = dev
            except (ValueError, KeyError):
                continue

    qps_objs = {}
    for tx_port_id, topo_entry in topology.items():
        pytest_assert(
            isinstance(topo_entry.get("peers"), list),
            f"configure_rocev2_topology: tx port {tx_port_id} missing required key 'peers' "
            f"(must be a list; an empty list is allowed for a receive-only node).")
        tx_info = port_to_dev_ip.get(tx_port_id)
        if not tx_info or not tx_info["device"]:
            continue

        tx_dev = tx_info["device"]
        ethernet = tx_dev.ethernets[0]
        ethernet.mtu = topology[tx_port_id].get("mtu", 1500)
        ipv4_stack = ethernet.ipv4_addresses[0]

        rocev2 = getattr(tx_dev, "rocev2", None)
        rocev2_int = rocev2.ipv4_interfaces.add()
        rocev2_int.ib_mtu = topology[tx_port_id].get("mtu", 1500)
        rocev2_int.ipv4_name = ipv4_stack.name

        peers_ids = topo_entry["peers"]
        # Fail fast on multi-peer tx ports: QPs are created once after the peer loop
        # and would attach only to the last peer. Single peer (or none, for an rx-only
        # node) is supported today. TODO: to support multi-peer, move QP creation inside
        # the peer loop with per-peer-unique peer/QP names.
        pytest_assert(
            len(peers_ids) <= 1,
            f"configure_rocev2_topology: tx port {tx_port_id} has {len(peers_ids)} peers; "
            f"multi-peer per tx port is not supported yet (QPs attach only to the last peer). "
            f"Use one peer per tx port, or extend the helper to create QPs per peer."
        )
        # Fail fast on unknown peers (no configured IP/device) so misconfig surfaces
        # here rather than as silently-dropped destinations downstream.
        for pid in peers_ids:
            pytest_assert(
                pid in port_to_dev_ip,
                f"configure_rocev2_topology: tx port {tx_port_id} peer {pid} has no configured "
                f"IP/device; known ports: {sorted(port_to_dev_ip)}.")

        qp_cfgs = topo_entry.get("qp_configs", default_qp_configs)
        pytest_assert(
            isinstance(qp_cfgs, list) and all(isinstance(q, dict) for q in qp_cfgs),
            f"configure_rocev2_topology: tx port {tx_port_id} 'qp_configs' must be a list of dicts "
            f"(individual keys like dscp/message_size are optional and fall back to defaults).")
        cnp_cfg = topo_entry.get("cnp", default_cnp_config)
        conn_type_cfg = topo_entry.get("connection_type", default_connection_type_config)
        dcqcn_settings_cfg = topo_entry.get("dcqcn_settings", default_dcqcn_settings_config)
        port_cfg = topo_entry.get("rocev2_port_config", default_rocev2_port_config)

        dest_port_ips = [port_to_dev_ip[port_id]["ip"] for port_id in peers_ids if port_id in port_to_dev_ip]
        logger.info(f"RoCEv2 {tx_port_id}, Dest Ports: {peers_ids}, Dest IPs: {dest_port_ips}")

        peer_ips = dest_port_ips or ["0.0.0.0"]
        for dest_ip in peer_ips:
            peer = rocev2_int.peers.add()
            peer.name = f"RoCEv2 {tx_port_id}"
            peer.destination_ip_address = dest_ip

        qps_objs[tx_port_id] = []
        for indx, qp_cfg in enumerate(qp_cfgs):
            qp = peer.qps.add()
            qp.qp_name = f"QP{tx_port_id}_{indx}"
            qps_objs[tx_port_id].append((f"QP{tx_port_id}_{indx}", qp_cfg))
            qp.connection_type.choice = "reliable_connection"
            rc = qp.connection_type.reliable_connection
            rc.source_qp_number = qp_cfg.get("qp_num", default_qp_configs[indx]["qp_num"])
            rc.dscp = qp_cfg.get("dscp", default_qp_configs[indx]["dscp"])
            rc.ecn = qp_cfg.get("ecn", default_qp_configs[indx]["ecn"])

        stf_peer = config.stateful_flows.rocev2.add()
        tx_port = stf_peer.tx_ports.add()
        tx_port.port_name = 'Port {}'.format(tx_port_id)
        tx_port.transmit_type.target_line_rate.value = port_cfg.get("target_line_rate", 100)
        tx_port.transmit_type.choice = port_cfg.get("transmit_type", "target_line_rate")

        for qps_name, qp_cfg in qps_objs[tx_port_id]:
            logger.info(f"Configured QPs: {qps_name}")
            stf_peer_flow = tx_port.transmit_type.target_line_rate.flows.add()
            stf_peer_flow.tx_endpoint = qps_name
            stf_peer_flow.name = qps_name
            stf_peer_flow.rocev2_verb.choice = "send_with_immediate"
            stf_peer_flow.rocev2_verb.send_with_immediate.immediate_data = "bb"
            stf_peer_flow.message_size_unit = qp_cfg.get("message_size_unit", "kb")
            stf_peer_flow.message_size = qp_cfg.get("message_size", 128)

        logger.info(f"Configured RoCEv2 Protocol Port Settings Port {tx_port_id}")
        logger.info(f"Configured RoCEv2 Protocol Port Settings CNP: {cnp_cfg}")
        per_port_option = config.options.per_port_options.add()
        per_port_option.port_name = 'Port {}'.format(tx_port_id)
        protocol = per_port_option.protocols.add()
        protocol.choice = "rocev2"
        protocol.rocev2.cnp.choice = cnp_cfg.get("choice", "ip_dscp")
        protocol.rocev2.cnp.ip_dscp.value = cnp_cfg.get("ip_dscp", 0)
        protocol.rocev2.cnp.ecn_value = cnp_cfg.get("ecn_value", "ect_0")
        protocol.rocev2.cnp.cnp_delay_timer = cnp_cfg.get("cnp_delay_timer", 111)

        cchoice = conn_type_cfg.get("choice", "reliable_connection")
        protocol.rocev2.connection_type.choice = cchoice
        logger.info(f"Configured RoCEv2 Protocol Port Settings Connection Type: {conn_type_cfg}")
        rc_conn = protocol.rocev2.connection_type.reliable_connection

        ack_cfg = conn_type_cfg.get(cchoice, {}).get("ack", {})
        if ack_cfg:
            rc_conn.ack.choice = ack_cfg.get("choice", "ip_dscp")
            rc_conn.ack.ip_dscp.value = ack_cfg.get("ip_dscp", 48)
            rc_conn.ack.ecn_value = ack_cfg.get("ecn_value", "ect_0")

        nak_cfg = conn_type_cfg.get(cchoice, {}).get("nak", {})
        if nak_cfg:
            rc_conn.nak.choice = nak_cfg.get("choice", "ip_dscp")
            rc_conn.nak.ip_dscp.value = nak_cfg.get("ip_dscp", 48)
            rc_conn.nak.ecn_value = nak_cfg.get("ecn_value", "non_ect")

        rc_conn.enable_retransmission_timeout = conn_type_cfg.get(cchoice, {}).get(
            "enable_retransmission_timeout", False)
        rc_conn.retransmission_timeout_value = conn_type_cfg.get(cchoice, {}).get(
            "retransmission_timeout_value", 5000)
        rc_conn.retransmission_retry_count = conn_type_cfg.get(cchoice, {}).get("retransmission_retry_count", 254)
        dcqcn = protocol.rocev2.dcqcn_settings
        dcqcn.enable_dcqcn = dcqcn_settings_cfg.get("enable_dcqcn", True)
        dcqcn.alpha_g = dcqcn_settings_cfg.get("alpha_g", 1020)
        dcqcn.initial_alpha = dcqcn_settings_cfg.get("initial_alpha", 1000)
        dcqcn.maximum_rate_decrement_at_time = dcqcn_settings_cfg.get("maximum_rate_decrement_at_time", 12)

    return config


# ===========================================================================
# 2. Traffic control + metrics
# ===========================================================================
def wait_with_message(message, duration):
    """Display a 1-second countdown for `duration` seconds."""
    for remaining in range(duration, 0, -1):
        logger.info(f"{message} {remaining} seconds remaining.")
        time.sleep(1)
    logger.info("")


def is_traffic_running(api, flow_names=None):
    request = api.metrics_request()
    request.rocev2_flow.choice = "per_qp"
    request.rocev2_flow.per_qp.column_names = flow_names if flow_names else []
    stats = api.get_metrics(request).rocev2_flow_per_qp_metrics
    return any(float(fs.data_tx_rate) > 0 for fs in stats)


def is_traffic_stopped(api, flow_names=None):
    request = api.metrics_request()
    request.rocev2_flow.choice = "per_qp"
    request.rocev2_flow.per_qp.column_names = flow_names if flow_names else []
    stats = api.get_metrics(request).rocev2_flow_per_qp_metrics
    return all(float(fs.data_tx_rate) == 0 for fs in stats)


def start_stop(api, operation="start", op_type="protocols", waittime=10):
    logger.info("%s %s", operation.capitalize(), op_type)
    cs = api.control_state()
    state_map = {
        ("protocols", "start"): cs.protocol.all.START,
        ("protocols", "stop"): cs.protocol.all.STOP,
        ("traffic", "start"): cs.traffic.flow_transmit.START,
        ("traffic", "stop"): cs.traffic.flow_transmit.STOP,
    }
    if (op_type, operation) not in state_map:
        raise ValueError(f"Invalid combination: op_type={op_type}, operation={operation}")
    if op_type == "protocols":
        cs.protocol.all.state = state_map[(op_type, operation)]
    elif op_type == "traffic":
        cs.traffic.flow_transmit.state = state_map[(op_type, operation)]
    api.set_control_state(cs)
    if op_type == "traffic" and operation == "stop":
        wait_until(180, 10, 0, is_traffic_stopped, api)
    elif op_type == "traffic" and operation == "start":
        wait_until(180, 10, 0, is_traffic_running, api)
    else:
        wait(waittime, f"For {op_type} To {operation}")


def get_stats(api, stat_name, columns=None, return_type='stat_obj'):
    def deep_getattr(obj, attr, default=None):
        try:
            for part in attr.split('.'):
                obj = getattr(obj, part)
            return obj
        except AttributeError:
            return default

    # Per-QP and per-peer metrics have DIFFERENT schemas, so each stat_name reads
    # its own response object AND its own column set.
    per_qp_columns = [
        "flow_name", "port_tx", "port_rx", "src_qp", "dest_qp", "src_ipv4", "dest_ipv4",
        "data_frames_tx", "data_frames_rx", "frame_delta", "data_frames_retransmitted",
        "frame_sequence_error", "tx_bytes", "rx_bytes", "data_tx_rate", "data_rx_rate",
        "message_tx", "message_complete_rx", "message_fail", "flow_completion_time",
        "avg_latency", "min_latency", "max_latency", "ecn_ce_rx", "cnp_tx", "cnp_rx",
        "ack_tx", "ack_rx", "nak_tx", "nak_rx", "first_timestamp", "last_timestamp",
    ]
    per_peer_columns = [
        "name", "qp_configured", "qp_up", "qp_down",
        "connect_request_tx", "connect_request_rx", "connect_reply_tx", "connect_reply_rx",
        "ready_tx", "ready_rx", "disconnect_request_tx", "disconnect_request_rx",
        "disconnect_reply_tx", "disconnect_reply_rx", "reject_tx", "unknown_msg_rx",
    ]

    stat_obj = None
    column_headers = None
    req = api.metrics_request()
    if stat_name == "per_qp":
        req.rocev2_flow.choice = "per_qp"
        req.rocev2_flow.per_qp.column_names = []
        stat_obj = api.get_metrics(req).rocev2_flow_per_qp_metrics
        column_headers = per_qp_columns
    elif stat_name == "per_peer":
        req.rocev2_ipv4.choice = "per_peer"
        req.rocev2_ipv4.per_peer.column_names = []
        stat_obj = api.get_metrics(req).rocev2_ipv4_per_peer_metrics
        column_headers = per_peer_columns
    elif stat_name == "Port Statistics":
        ixnet = api._ixnetwork
        dp_metrics = StatViewAssistant(ixnet, stat_name)
        df = pd.DataFrame(dp_metrics.Rows.RawData, columns=dp_metrics.ColumnHeaders)
        df = df[columns] if columns else df
        if return_type == 'print':
            logger.info("\n%s" % tabulate(df, headers="keys", tablefmt="psql"))
            return
        elif return_type == 'df':
            return df
    if stat_obj is None:
        raise ValueError(f"Unsupported stat_name: {stat_name}")
    rows = [[deep_getattr(stat, column, None) for column in column_headers] for stat in stat_obj]
    tdf = pd.DataFrame(rows, columns=column_headers)
    df = tdf[columns] if columns else tdf[column_headers]
    if return_type == 'print':
        logger.info("\n%s" % tabulate(df, headers="keys", tablefmt="psql"))
    elif return_type == 'df':
        return df
    else:
        return stat_obj


def sample_flow_rates(api, n=3, gap=2):
    """
    Take `n` snapshots of per-QP flow metrics, `gap` seconds apart, and return
    the MEAN data_tx_rate / data_rx_rate per flow.

    Call DURING steady-state traffic so the rates reflect sustained,
    simultaneously-backlogged behaviour (what DWRR weights govern). A whole-run
    average (rx_bytes / duration) is skewed when queues finish their fixed-size
    transfers at different times.
    """
    cols = ["flow_name", "port_tx", "port_rx", "data_tx_rate", "data_rx_rate"]
    samples = []
    for i in range(n):
        snap = get_stats(api, stat_name="per_qp", columns=cols, return_type='df')
        for c in ("data_tx_rate", "data_rx_rate"):
            snap[c] = pd.to_numeric(snap[c], errors="coerce")
        samples.append(snap)
        logger.info(f"Rate sample {i + 1}/{n}:\n{tabulate(snap, headers='keys', tablefmt='psql')}")
        if i < n - 1:
            wait(gap, f"between rate samples ({i + 1}/{n})")
    return (pd.concat(samples, ignore_index=True)
              .groupby(["flow_name", "port_tx", "port_rx"], as_index=False)
              [["data_tx_rate", "data_rx_rate"]].mean())


def run_rocev2_step(api, base_config, port_config_list, topology, *, traffic_duration,
                    duthosts=None, sample_rates=False, sample_start=3, sample_count=3, sample_gap=2,
                    config_name=None):
    config = configure_rocev2_topology(base_config, port_config_list, topology)
    api.set_config(config)
    if config_name:
        # Save the IxNetwork config under the (sanitized) test name + parameters
        # for later replay/debug, e.g. test_rocev2_pfc_congestion_ai[q3_single].ixncfg
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in config_name)
        api._ixnetwork.SaveConfig(Arg1=f"{safe}.ixncfg")
        logger.info(f"Saved IxNetwork config: {safe}.ixncfg")
    start_stop(api, operation="start", op_type="protocols")
    for duthost in duthosts:
        duthost.command("sonic-clear queuecounters")
        duthost.command("sonic-clear pfccounters")
    start_stop(api, operation="start", op_type="traffic")

    live_rate_df = None
    if sample_rates:
        wait(sample_start, "For traffic to reach steady state before rate sampling")
        live_rate_df = sample_flow_rates(api, n=sample_count, gap=sample_gap)
        remaining = int(traffic_duration - sample_start - max(0, sample_count - 1) * sample_gap)
        if remaining > 0:
            wait_with_message("Waiting for traffic completion...", remaining)
    else:
        wait_with_message("Waiting for traffic completion...", traffic_duration)

    start_stop(api, operation="stop", op_type="traffic")

    streams = api._ixnetwork.Traffic.find().RoceV2Traffic.find().RoceV2Stream.find()
    dscp_by_qp = {s.Name: int(s.IpDscp) for s in streams}

    df = get_stats(api, stat_name="per_qp", return_type='df')
    df.insert(df.columns.get_loc('port_rx') + 1, 'ip_dscp', df['flow_name'].map(dscp_by_qp))

    if live_rate_df is not None:
        live = live_rate_df.rename(columns={"data_tx_rate": "data_tx_rate_live",
                                            "data_rx_rate": "data_rx_rate_live"})
        df = df.merge(live[["flow_name", "data_tx_rate_live", "data_rx_rate_live"]],
                      on="flow_name", how="left")

    #logger.info(f"Traffic Stats:\n{tabulate(df, headers='keys', tablefmt='psql')}")
    logger.info(f"Traffic Stats:\n{tabulate(df.set_index('flow_name').T, headers='keys', tablefmt='psql')}")

    ps_df = get_stats(api, stat_name="Port Statistics", return_type='df')
    pfc_cols = [f"Rx Pause Priority Group {q} Frames"
                for q in range(8) if f"Rx Pause Priority Group {q} Frames" in ps_df.columns]
    ps_df[pfc_cols] = ps_df[pfc_cols].apply(pd.to_numeric, errors='coerce')
    return df, ps_df


# ===========================================================================
# 3. DUT-side data (counters + scheduler config)
# ===========================================================================
def scheduler_weights(snappi_dut_port_map, queue_ids=None, asic_index=0):
    """
    Per (dut, interface, snappi_port) egress scheduler bound to each queue and
    that scheduler's weight, read from DUT CONFIG_DB (QUEUE + SCHEDULER).
    queue_ids accepts plain ints or "UC<q>" strings; None includes every queue.
    Columns per queue: "UC<q> scheduler / type / weight / wred_profile".
    """
    def _q_num(q):
        digits = "".join(ch for ch in str(q) if ch.isdigit())
        return int(digits) if digits else None

    want_specific = queue_ids is not None
    queue_ids = [] if queue_ids is None else [n for n in map(_q_num, queue_ids) if n is not None]
    all_rows = []
    for duthost, dut_snappi_ports_map in snappi_dut_port_map.items():
        dut_name = getattr(duthost, "hostname", str(duthost))
        cfg = duthost.config_facts(host=duthost.hostname, asic_index=asic_index,
                                   source="running")["ansible_facts"]
        queue_cfg = cfg.get("QUEUE", {})
        sched_cfg = cfg.get("SCHEDULER", {})
        for dut_interface, snappi_port in dut_snappi_ports_map.items():
            row = {"dut": dut_name, "dut_interface": dut_interface, "snappi_port": snappi_port}
            for q_str, q_val in queue_cfg.get(dut_interface, {}).items():
                try:
                    q = int(q_str)
                except (ValueError, TypeError):
                    continue
                if want_specific and q not in queue_ids:
                    continue
                sched_name = q_val.get("scheduler")
                sched = sched_cfg.get(sched_name, {}) if sched_name else {}
                weight = sched.get("weight")
                row[f"UC{q} scheduler"] = sched_name
                row[f"UC{q} weight"] = int(weight) if isinstance(weight, str) and weight.isdigit() else weight
                row[f"UC{q} type"] = sched.get("type")
                row[f"UC{q} wred_profile"] = q_val.get("wred_profile")
            all_rows.append(row)

    df = pd.DataFrame(all_rows)
    if not df.empty:
        key_cols = ["dut", "dut_interface", "snappi_port"]
        other = [c for c in df.columns if c not in key_cols]
        df = df[key_cols + sorted(other)]
    return df


def _q_nums(queues):
    """Normalize a queue list (ints or 'UC3'-style) to a sorted list of ints."""
    return sorted({int("".join(c for c in str(q) if c.isdigit())) for q in queues})


def disable_wred(snappi_dut_port_map, queues):
    """
    Remove the WRED/ECN profile from the given egress queues on EVERY DUT
    interface used by the test (all interfaces in snappi_dut_port_map).

    WRED on a lossless queue drops non-ECT traffic (it can only ECN-mark ECT),
    which pre-empts PFC; removing it lets congestion drive PFC pause instead -
    required for a pure PFC test. Only queues that currently carry a
    wred_profile are touched; each removal is verified in CONFIG_DB.

    queues: ints or 'UC<q>' strings (only those the test uses).
    Returns a restore map for restore_wred(): {duthost: {(intf, q): profile}}.
    """
    qnums = _q_nums(queues)
    saved = {}
    for duthost, ports in snappi_dut_port_map.items():
        saved[duthost] = {}
        for intf in ports:                       # ports == {interface: snappi_port}
            for q in qnums:
                key = f"QUEUE|{intf}|{q}"
                prof = duthost.shell(f'sonic-db-cli CONFIG_DB hget "{key}" wred_profile',
                                     module_ignore_errors=True)["stdout"].strip()
                if not prof:
                    continue
                saved[duthost][(intf, q)] = prof
                duthost.shell(f'sonic-db-cli CONFIG_DB hdel "{key}" wred_profile')
                left = duthost.shell(f'sonic-db-cli CONFIG_DB hget "{key}" wred_profile',
                                     module_ignore_errors=True)["stdout"].strip()
                pytest_assert(not left, f"WRED still set on {duthost.hostname} {key} after hdel")
                logger.info(f"WRED disabled on {duthost.hostname} {key} (was {prof})")
    return saved


def restore_wred(saved):
    """Re-attach the WRED profiles removed by disable_wred()."""
    for duthost, items in (saved or {}).items():
        for (intf, q), prof in items.items():
            duthost.shell(f'sonic-db-cli CONFIG_DB hset "QUEUE|{intf}|{q}" wred_profile "{prof}"')
            logger.info(f"WRED restored on {duthost.hostname} QUEUE|{intf}|{q} -> {prof}")


def pfc_counters(snappi_dut_port_map, direction="Tx"):
    """
    Per (dut, interface) PFC pause-frame counts per priority, parsed from
    `show pfc counters`. This is the AUTHORITATIVE PFC signal - the snappi-side
    "Rx Pause Priority Group N Frames" port stat is unreliable on IxNetwork
    (reads 0 even when PFC is demonstrably pacing the senders).

    direction: "Tx" (pause GENERATED by the DUT - what a PFC test wants) or "Rx".
    Returns a DataFrame: dut, dut_interface, snappi_port, PFC0..PFC7.
    Clear with `sonic-clear pfccounters` before the run (run_rocev2_step does).
    """
    rows = []
    for duthost, ports in snappi_dut_port_map.items():
        dut_name = getattr(duthost, "hostname", str(duthost))
        out = duthost.shell("show pfc counters")["stdout"]
        section, counts = None, {}
        for line in out.splitlines():
            s = line.strip()
            if not s:
                continue
            low = s.lower()
            if low.startswith("port rx"):
                section = "Rx"; continue
            if low.startswith("port tx"):
                section = "Tx"; continue
            parts = s.split()
            if section == direction and parts and parts[0].startswith("Ethernet"):
                vals = []
                for p in parts[1:9]:
                    try:
                        vals.append(int(p.replace(",", "")))
                    except ValueError:
                        vals.append(0)
                counts[parts[0]] = vals
        for intf, snappi_port in ports.items():
            vals = counts.get(intf, [0] * 8)
            row = {"dut": dut_name, "dut_interface": intf, "snappi_port": snappi_port}
            row.update({f"PFC{p}": (vals[p] if p < len(vals) else 0) for p in range(8)})
            rows.append(row)
    return pd.DataFrame(rows)


def queue_counters(snappi_dut_port_map, queue_ids=None, queue_cols=None):
    """
    Per (dut, interface, snappi_port) live queue counters from
    `show queue counters --json`. queue_ids like ["UC3","UC5"]; queue_cols like
    ["totalpacket"]. Columns: "UC<q> <col>".
    """
    want_specific_queues = queue_ids is not None
    queue_ids = [] if queue_ids is None else queue_ids
    queue_cols = [] if queue_cols is None else queue_cols
    all_rows = []
    for duthost, dut_snappi_ports_map in snappi_dut_port_map.items():
        dut_name = getattr(duthost, "hostname", str(duthost))
        json_output = duthost.shell("show queue counters --json")["stdout"]
        queuecounters = json.loads(json_output)
        queuecounters = {port: {q: v for q, v in counters.items() if q != 'time'}
                         for port, counters in queuecounters.items()}
        for dut_interface, snappi_port in dut_snappi_ports_map.items():
            row = {"dut": dut_name, "dut_interface": dut_interface, "snappi_port": snappi_port}
            int_queue_counters = queuecounters[dut_interface]
            for queue_id, queue_vals in int_queue_counters.items():
                if want_specific_queues and queue_id not in queue_ids:
                    continue
                cols_to_take = list(queue_vals.keys()) if not queue_cols else queue_cols
                for col in cols_to_take:
                    try:
                        row[f"{queue_id} {col}"] = int(queue_vals.get(col, "0").replace(",", ""))
                    except (ValueError, TypeError):
                        row[f"{queue_id} {col}"] = queue_vals.get(col, "0")
            all_rows.append(row)

    df = pd.DataFrame(all_rows)
    if not df.empty:
        key_cols = ["dut", "dut_interface", "snappi_port"]
        queue_cols_all = [c for c in df.columns if c not in key_cols]
        df = df[key_cols + sorted(queue_cols_all)]
    return df


def queue_stats(flow_df, snappi_dut_port_map, prio_dscp_map=None,
                queue_ids=None, queue_cols=None, egress_port_col="port_rx", strict=False):
    """
    Merge live queue counters onto the flow df (on port_tx) and, if prio_dscp_map
    is given, attach a single scalar per flow: `tc` (ip_dscp -> tc) and `weight`
    (the egress scheduler weight of that queue only, looked up on egress_port_col).
    Returns (merged_df, dut_queue_df, sched_df).

    strict=True: fail fast if any flow's ip_dscp has no DSCP->TC mapping, or its
    queue has no scheduler weight on the egress port (otherwise these stay silent
    None/NaN that surface later as confusing check failures). Opt-in, because
    control queues (e.g. strict-priority ACK/CNP) may legitimately have no weight.
    """
    dut_queue_df = queue_counters(snappi_dut_port_map, queue_ids=queue_ids, queue_cols=queue_cols)
    sched_df = scheduler_weights(snappi_dut_port_map, queue_ids=queue_ids)
    merged_df = flow_df.merge(dut_queue_df, left_on="port_tx", right_on="snappi_port", how="left")

    if prio_dscp_map is not None:
        dscp_to_tc = {d: tc for tc, dscps in prio_dscp_map.items() for d in dscps}
        weight_by_port_tc = {
            (row["snappi_port"], int(col.split()[0][2:])): row[col]
            for _, row in sched_df.iterrows()
            for col in sched_df.columns
            if col.startswith("UC") and col.endswith(" weight")
        }
        merged_df["tc"] = merged_df["ip_dscp"].map(dscp_to_tc)
        merged_df["weight"] = merged_df.apply(
            lambda r: weight_by_port_tc.get((r[egress_port_col], int(r["tc"])))
                      if pd.notna(r["tc"]) else None,
            axis=1)

        if strict:
            no_tc = merged_df[merged_df["tc"].isna()]
            pytest_assert(
                no_tc.empty,
                f"queue_stats(strict): no DSCP->TC mapping for ip_dscp(s) "
                f"{sorted(no_tc['ip_dscp'].unique())} on flows {no_tc['flow_name'].tolist()}")
            no_w = merged_df[merged_df["weight"].isna()]
            pytest_assert(
                no_w.empty,
                f"queue_stats(strict): no scheduler weight on egress port for "
                f"{no_w[[egress_port_col, 'tc']].drop_duplicates().to_dict('records')} "
                f"on flows {no_w['flow_name'].tolist()}")

    return merged_df, dut_queue_df, sched_df


# ===========================================================================
# 4. Analysis + check runner
# ===========================================================================
def dwrr_expected_rates(capacity, queues):
    """
    Expected per-queue egress rate under DWRR via iterative water-filling: a
    backlogged queue's fair share is capacity*weight/sum(weights); a queue
    offered less than its share is satisfied and its unused share is
    redistributed among the rest. queues={id:(weight, offered)}; offered=None or
    inf means backlogged. Returns {id: rate}.
    """
    remaining = {q: (float(w), float("inf") if off is None else float(off))
                 for q, (w, off) in queues.items()}
    result = {}
    cap = float(capacity)
    while remaining:
        wsum = sum(w for w, _ in remaining.values())
        if wsum <= 0 or cap <= 0:
            result.update({q: 0.0 for q in remaining})
            break
        newly_satisfied = {q: off for q, (w, off) in remaining.items() if off <= cap * w / wsum}
        if not newly_satisfied:
            result.update({q: cap * w / wsum for q, (w, _) in remaining.items()})
            break
        for q, off in newly_satisfied.items():
            result[q] = off
            cap -= off
            del remaining[q]
    return result


def make_check(expr, cols, desc, msg=None, override_df=None):
    return {"expr": expr, "cols": cols, "desc": desc, "msg": msg or desc, "override_df": override_df}


def assert_queries(stat_df, checks):
    failures = []
    for i, check in enumerate(checks, 1):
        check_df = stat_df if check.get("override_df") is None else check["override_df"]
        expr = check["expr"]
        desc = check["desc"]
        cols = check.get("cols")
        msg = check.get("msg", desc)
        logger.info(f"[Check {i}] {desc} – running query: {expr}")
        bad = check_df.query(expr)
        show = bad[cols] if cols else bad
        if bad.empty:
            table = tabulate(check_df[cols], headers='keys', tablefmt='psql')
            logger.info(f"[Check {i}][DATA] {msg} – rows checked:\n{table}")
            logger.info(f"[Check {i}][PASS] {msg} – no offending rows")
            continue
        table = tabulate(show, headers='keys', tablefmt='psql')
        logger.info(f"[Check {i}][DATA] {msg} – rows checked:\n{table}")
        logger.error(f"[Check {i}][FAIL] {msg}")
        # Compact sample (first 3 offending rows) carried into the raised error.
        sample = tabulate(show.head(3), headers='keys', tablefmt='psql')
        failures.append(f"{i}. {msg} ({len(show)} offending row(s)):\n{sample}")
    if failures:
        logger.error(f"\nchecks failed: {len(failures)}/{len(checks)}")
        summary = "\n".join(failures[:3])
        if len(failures) > 3:
            summary += f"\n... and {len(failures) - 3} more failed check(s); see log."
        raise AssertionError(f"{len(failures)}/{len(checks)} checks failed:\n{summary}")
    logger.info("*** ALL CHECKS PASSED ***")


# ===========================================================================
# 5. High-level glue: topology + aggregates + one-call orchestration
# ===========================================================================
def derive_priority_to_dscp(prio_dscp_map):
    """
    Collapse {tc: [dscps]} (the prio_dscp_map fixture, from DSCP_TO_TC_MAP) to a
    single representative DSCP per TC: prefer DSCP == TC when it maps to the TC,
    else the smallest DSCP mapping to it (TC0->8, TC2->5, ...).
    """
    return {tc: (tc if tc in dscps else min(dscps)) for tc, dscps in prio_dscp_map.items()}


def build_pairwise_topology(port_ids, common_cfg, last_pair_qp_configs=None, last_pair_cfg=None):
    """
    Bidirectional topology pairing the first half of port_ids with the second.
    Every port gets common_cfg. The last pair (both directions) can be customised:
      - last_pair_cfg:        full per-port cfg dict used verbatim for the last
                              pair, letting it differ from common_cfg in
                              connection_type, cnp, mtu, dcqcn_settings, etc.
      - last_pair_qp_configs: shorthand to override ONLY qp_configs on the last
                              pair (all other fields inherited from common_cfg).
    last_pair_cfg takes precedence when both are given.
    """
    pairs = list(zip(port_ids[:len(port_ids) // 2], port_ids[len(port_ids) // 2:]))
    last_pair = pairs[-1]
    topology = {}
    for tx, rx in pairs:
        if (tx, rx) == last_pair and last_pair_cfg is not None:
            cfg = last_pair_cfg
        elif (tx, rx) == last_pair and last_pair_qp_configs is not None:
            cfg = {**common_cfg, "qp_configs": last_pair_qp_configs}
        else:
            cfg = common_cfg
        for port, peer in ((tx, rx), (rx, tx)):
            topology[port] = {"peers": [peer], **cfg}
    return topology


def build_incast_topology(port_ids, lossless_cfg_fn, lossless_spec, lossy_cfg=None,
                          rx=None, last_tx=None):
    """
    Unidirectional N:1 incast: one Rx (receive only) and every other port a Tx.
    The remaining Tx ports cycle through lossless_spec, each entry passed to
    lossless_cfg_fn(*entry). If lossy_cfg is given, the LAST Tx uses it instead
    (a lossy sender); if lossy_cfg is None, ALL Tx are lossless.

    Args:
        port_ids (list): all snappi port ids.
        lossless_cfg_fn (callable): entry -> per-Tx cfg dict, called as
            lossless_cfg_fn(*entry) (e.g. entry=(queue, size_kb)).
        lossless_spec (list): entries cycled across the lossless Tx ports.
        lossy_cfg (dict, optional): per-Tx cfg for the last (lossy) Tx port;
            None => no lossy sender, every Tx is lossless.
        rx (optional): receiver port id; default random.choice(port_ids).
        last_tx (optional): the lossy Tx port id; default the last Tx port.

    Returns:
        (topology, rx, last_tx, used_lossless) where used_lossless is the list
        of lossless_spec entries actually assigned (in order). last_tx is None
        when lossy_cfg is None.
    """
    rx = rx if rx is not None else random.choice(port_ids)
    tx_ports = [p for p in port_ids if p != rx]
    if lossy_cfg is not None:
        last_tx = last_tx if last_tx is not None else tx_ports[-1]
    else:
        last_tx = None

    topology = {rx: {"peers": [], **lossless_cfg_fn(*lossless_spec[0])}}   # Rx only receives
    used = []
    li = 0
    for tx in tx_ports:
        if lossy_cfg is not None and tx == last_tx:
            topology[tx] = {"peers": [rx], **lossy_cfg}
        else:
            entry = lossless_spec[li % len(lossless_spec)]
            used.append(entry)
            topology[tx] = {"peers": [rx], **lossless_cfg_fn(*entry)}
            li += 1
    return topology, rx, last_tx, used


def build_ack_aggregate(flow_df, dut_queue_df, lossy_dsps, ack_q_col):
    """Per-port sum of lossy ack_tx (grouped by port_tx) joined to the DUT ACK queue counter."""
    dut_idx = dut_queue_df.set_index("snappi_port")
    lossy = flow_df[flow_df["ip_dscp"].isin(lossy_dsps)]
    df = lossy.groupby("port_tx", as_index=False)["ack_tx"].sum()
    df[ack_q_col] = df["port_tx"].map(dut_idx[ack_q_col])
    return df


def build_lossy_data_aggregate(flow_df, dut_queue_df, priority_to_dscp, lossy_queues):
    """One row per (port, lossy queue): expected data (grouped by port_rx) vs DUT UC<q> totalpacket."""
    dut_idx = dut_queue_df.set_index("snappi_port")
    lossy_dsps = [priority_to_dscp[q] for q in lossy_queues]
    lossy = flow_df[flow_df["ip_dscp"].isin(lossy_dsps)]
    rows = []
    for q in lossy_queues:
        d = priority_to_dscp[q]
        exp = (lossy[lossy["ip_dscp"] == d]
               .groupby("port_rx", as_index=False)["data_frames_rx"].sum()
               .rename(columns={"port_rx": "snappi_port", "data_frames_rx": "expected_pkts"}))
        exp["queue"] = f"UC{q}"
        exp["actual_pkts"] = exp["snappi_port"].map(dut_idx[f"UC{q} totalpacket"])
        rows.append(exp)
    return pd.concat(rows, ignore_index=True)


def build_rate_fairness(merged_df, rate_col="data_rx_rate_live", egress_port_col="port_rx"):
    """
    Per egress port, distribute the measured steady-state throughput among its
    data queues by DWRR weight (water-filling) and compute each flow's deviation
    from its expected weight-proportional share. Columns: flow_name, port_rx,
    ip_dscp, weight, rx_rate, expected_rate, pct_err.
    """
    rate_df = merged_df[["flow_name", "port_tx", "port_rx", "ip_dscp", "tc",
                         "weight", rate_col]].copy()
    rate_df = rate_df[rate_df["weight"].notna()]
    rate_df["rx_rate"] = pd.to_numeric(rate_df[rate_col], errors="coerce")
    rows = []
    for port, grp in rate_df.groupby(egress_port_col):
        cap = grp["rx_rate"].sum()
        queues = {r["flow_name"]: (r["weight"], float("inf")) for _, r in grp.iterrows()}
        expected = dwrr_expected_rates(cap, queues)
        for _, r in grp.iterrows():
            exp = expected[r["flow_name"]]
            rows.append({
                "flow_name": r["flow_name"], "port_rx": port, "ip_dscp": r["ip_dscp"],
                "weight": r["weight"], "rx_rate": round(r["rx_rate"], 3),
                "expected_rate": round(exp, 3),
                "pct_err": round(abs(r["rx_rate"] - exp) / exp * 100, 2) if exp else float("nan"),
            })
    return pd.DataFrame(rows)


def build_rate_fairness_by_queue(merged_df, rate_col="data_rx_rate_live",
                                 offered_col="data_tx_rate_live", egress_port_col="port_rx"):
    """
    DWRR rate fairness aggregated per QUEUE - use this when several flows can
    share one queue on the egress port (e.g. an N:1 incast where multiple Tx
    ports drive the same lossless queue). DWRR schedules per queue, not per
    flow, so we:
        1. sum each flow's steady-state rx (achieved) and tx (offered) rate into
           its queue (port_rx, tc),
        2. water-fill the port's measured throughput across the QUEUES by DWRR
           weight, capping each queue at its OFFERED rate (offered-aware), and
        3. report each queue's deviation from that expected share.

    Offered-aware matters: a high-weight queue that is offered-limited (e.g. when
    several QPs share one Tx port, so each offers only ~line_rate/N) cannot use
    its full weight share, and its slack redistributes to the others. Assuming
    offered=inf would wrongly expect it to take its full weighted share.

    Prefer build_rate_fairness() (per-flow) only when every contending flow is a
    distinct queue. Columns: port_rx, tc, weight, n_flows, flows, offered,
    rx_rate, expected_rate, pct_err.
    """
    df = merged_df[[egress_port_col, "tc", "weight", "flow_name", rate_col, offered_col]].copy()
    df = df[df["weight"].notna() & df["tc"].notna()]
    df["rx_rate"] = pd.to_numeric(df[rate_col], errors="coerce")
    df["offered"] = pd.to_numeric(df[offered_col], errors="coerce")

    grouped = (df.groupby([egress_port_col, "tc"], as_index=False)
                 .agg(weight=("weight", "first"),
                      n_flows=("flow_name", "nunique"),
                      flows=("flow_name", lambda s: ",".join(sorted(set(s)))),
                      rx_rate=("rx_rate", "sum"),
                      offered=("offered", "sum")))

    rows = []
    for port, grp in grouped.groupby(egress_port_col):
        cap = grp["rx_rate"].sum()
        queues = {int(r["tc"]): (r["weight"], r["offered"]) for _, r in grp.iterrows()}
        expected = dwrr_expected_rates(cap, queues)
        for _, r in grp.iterrows():
            exp = expected[int(r["tc"])]
            rows.append({
                "port_rx": port, "tc": int(r["tc"]), "weight": r["weight"],
                "n_flows": int(r["n_flows"]), "flows": r["flows"],
                "offered": round(r["offered"], 3),
                "rx_rate": round(r["rx_rate"], 3), "expected_rate": round(exp, 3),
                "pct_err": round(abs(r["rx_rate"] - exp) / exp * 100, 2) if exp else float("nan"),
            })
    return pd.DataFrame(rows)


def build_rank_fairness(merged_df, dsps=None, by="port_tx", rate_col="data_rx_rate_live"):
    """
    Aggregate steady-state rate per sender (`by`, default port_tx == a rank) over
    the given DSCPs and report the spread, to validate fair sharing between
    QPs/ranks under DCQCN.

    Returns (summary_df, per_rank_df):
        summary_df: one row - n_ranks, min_rate, max_rate, mean_rate, deviation_pct
                    where deviation_pct = (max-min)/max*100.
        per_rank_df: one row per sender - <by>, rx_rate.
    """
    df = merged_df if dsps is None else merged_df[merged_df["ip_dscp"].isin(dsps)]
    per = (df.assign(_r=pd.to_numeric(df[rate_col], errors="coerce"))
             .groupby(by, as_index=False)["_r"].sum().rename(columns={"_r": "rx_rate"}))
    rmax = float(per["rx_rate"].max()) if len(per) else 0.0
    rmin = float(per["rx_rate"].min()) if len(per) else 0.0
    dev = round((rmax - rmin) / rmax * 100, 2) if rmax else 0.0
    summary = pd.DataFrame([{"n_ranks": len(per), "min_rate": round(rmin, 3),
                             "max_rate": round(rmax, 3),
                             "mean_rate": round(float(per["rx_rate"].mean()) if len(per) else 0.0, 3),
                             "deviation_pct": dev}])
    return summary, per


@dataclass
class Rocev2DpStats:
    """Everything a data-plane check might run against, in one object."""
    flow_df: object
    merged_df: object
    dut_queue_df: object
    sched_df: object
    ack_agg_df: object
    data_queue_df: object
    rate_check_df: object
    port_stats_df: object
    priority_to_dscp: dict
    dsps: list
    lossy_dsps: list
    ack_q_col: str


def collect_flow_queue_stats(*, snappi_api, duthosts, plist, tconfig, snappi_dut_port_map,
                             topology, prio_dscp_map, queue_ids, traffic_duration,
                             queue_cols=("totalpacket",), sample_rates=True,
                             sample_start=3, sample_count=3, sample_gap=2, log=True,
                             config_name=None):
    """
    Universal collector for ANY topology: run one traffic step and merge live
    queue counters + per-flow scheduler weight onto the flow stats. Unlike
    collect_rocev2_dp_stats it makes NO lossless/lossy assumptions and builds no
    aggregates - the test creates whatever aggregates/checks it needs. Use this
    for congestion / incast / custom layouts.

    sample_start/sample_count/sample_gap tune the steady-state rate sampling
    window - raise sample_start for control loops (e.g. DCQCN) that need time to
    converge before the rates are representative.

    Returns: (merged_df, flow_df, dut_queue_df, sched_df, port_stats_df)
    """
    flow_df, port_stats_df = run_rocev2_step(
        api=snappi_api, base_config=tconfig, port_config_list=plist, topology=topology,
        traffic_duration=traffic_duration, duthosts=duthosts, sample_rates=sample_rates,
        sample_start=sample_start, sample_count=sample_count, sample_gap=sample_gap,
        config_name=config_name)
    merged_df, dut_queue_df, sched_df = queue_stats(
        flow_df, snappi_dut_port_map, prio_dscp_map=prio_dscp_map,
        queue_ids=list(queue_ids), queue_cols=list(queue_cols))
    if log:
        merged_display_df = merged_df.set_index('flow_name').T if len(merged_df) <= 10 else merged_df
        for name, d in (("DUT Queue Counters", dut_queue_df),
                        ("Scheduler Weights", sched_df),
                        ("Traffic and DUT Stats", merged_display_df)):
            logger.info(f"{name}:\n{tabulate(d, headers='keys', tablefmt='psql')}")
    return merged_df, flow_df, dut_queue_df, sched_df, port_stats_df


def collect_rocev2_dp_stats(*, snappi_api, duthosts, plist, tconfig, snappi_dut_port_map,
                            topology, prio_dscp_map, lossless_queue, lossy_queues,
                            lossy_queue_ack_nak, traffic_duration, sample_rates=True,
                            queue_cols=("totalpacket",), rate_by_queue=False, log=True,
                            config_name=None):
    """
    Run one RoCEv2 data-plane step and build every analysis DataFrame a check
    needs. The test supplies topology + queue/priority intent; this returns a
    Rocev2DpStats bundle. No assertions here - the test owns the checks.

    rate_by_queue selects how rate_check_df is built:
      * False (default): per-flow (build_rate_fairness) - correct when every
        contending flow is a distinct queue (e.g. the no-congestion pairs).
      * True: per-queue (build_rate_fairness_by_queue) - correct when several
        flows share a queue on the egress port (e.g. an N:1 incast).
    """
    priority_to_dscp = derive_priority_to_dscp(prio_dscp_map)
    qids = [f"UC{lossless_queue}", f"UC{lossy_queue_ack_nak}"] + [f"UC{q}" for q in lossy_queues]

    flow_df, port_stats_df = run_rocev2_step(
        api=snappi_api, base_config=tconfig, port_config_list=plist, topology=topology,
        traffic_duration=traffic_duration, duthosts=duthosts, sample_rates=sample_rates,
        config_name=config_name)

    merged_df, dut_queue_df, sched_df = queue_stats(
        flow_df, snappi_dut_port_map, prio_dscp_map=prio_dscp_map,
        queue_ids=qids, queue_cols=list(queue_cols))

    dsps = [priority_to_dscp[q] for q in [lossless_queue]]
    lossy_dsps = [priority_to_dscp[q] for q in lossy_queues]
    ack_q_col = f"UC{lossy_queue_ack_nak} totalpacket"

    ack_agg_df = build_ack_aggregate(flow_df, dut_queue_df, lossy_dsps, ack_q_col)
    data_queue_df = build_lossy_data_aggregate(flow_df, dut_queue_df, priority_to_dscp, lossy_queues)
    rate_check_df = (build_rate_fairness_by_queue(merged_df) if rate_by_queue
                     else build_rate_fairness(merged_df))

    if log:
        merged_display_df = merged_df.set_index('flow_name').T if len(merged_df) <= 10 else merged_df
        for name, d in (("DUT Queue Counters", dut_queue_df),
                        ("Scheduler Weights", sched_df),
                        ("Traffic and DUT Stats", merged_display_df),
                        ("Lossy ACK aggregate", ack_agg_df),
                        ("Lossy data-queue aggregate", data_queue_df),
                        ("DWRR rate fairness", rate_check_df)):
            logger.info(f"{name}:\n{tabulate(d, headers='keys', tablefmt='psql')}")

    return Rocev2DpStats(
        flow_df=flow_df, merged_df=merged_df, dut_queue_df=dut_queue_df, sched_df=sched_df,
        ack_agg_df=ack_agg_df, data_queue_df=data_queue_df, rate_check_df=rate_check_df,
        port_stats_df=port_stats_df, priority_to_dscp=priority_to_dscp,
        dsps=dsps, lossy_dsps=lossy_dsps, ack_q_col=ack_q_col)
