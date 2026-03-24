import pytest
import random
import logging
import pandas as pd
import time
from tabulate import tabulate
from ixnetwork_restpy.assistants.statistics.statviewassistant import StatViewAssistant
from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.utilities import wait_until, wait


# flake8: noqa: F403, F401, F405

# ==============================
#  SONiC & Fanout Topology
# ==============================
from tests.common.fixtures.conn_graph_facts import (
    conn_graph_facts,
    fanout_graph_facts,
    fanout_graph_facts_multidut,
)   # noqa: F403, F401, F405

# ==============================
#  Snappi Fixtures (Testbed, Ports, API)
# ==============================
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

from tests.common.helpers.assertions import pytest_require, pytest_assert   # noqa: F403, F401, F405

logger = logging.getLogger(__name__)

LATENCY_SPECS = {
    "avg_latency_max": 5000,
    "max_latency_max": 50000,
}

priority_to_dscp = {
    0: 0,
    1: 8,
    2: 16,
    3: 24,
    4: 32,
    5: 40,
    6: 48,
    7: 56
}


def configure_rocev2_topology(config, port_config_list, topology):
    '''
    topology = {
                0:{
                    "peers": [2],
                    "cnp": {"choice": "ip_dscp", "ip_dscp": 30, "ecn_value": "non_ect", "cnp_delay_timer": 111},
                    "connection_type": {
                                        "choice": "reliable_connection",
                                        "reliable_connection": {
                                                                "ack": {
                                                                        "choice": "ip_dscp",
                                                                        "ip_dscp": 48,
                                                                        "ecn_value": "non_ect"
                                                                        },
                                                                "enable_retransmission_timeout": False,
                                                                "retransmission_timeout_value": 10
                                                            }
                                        },
                    "dcqcn_settings": {"alpha_g": 1020, "initial_alpha": 1000, "maximum_rate_decrement_at_time": 12},
                    "rocev2_port_config":{"target_line_rate": 60}
                    },
                1:{
                    "peers": [0],
                    "cnp": {"choice": "ip_dscp", "ip_dscp": 31, "ecn_value": "non_ect", "cnp_delay_timer": 102},
                    "connection_type": {
                                        "choice": "reliable_connection",
                                        "reliable_connection": {
                                                                "ack": {
                                                                        "choice": "ip_dscp",
                                                                        "ip_dscp": 60,
                                                                        "ecn_value": "non_ect"
                                                                        },
                                                                "enable_retransmission_timeout": True,
                                                                "retransmission_timeout_value": 20
                                                            }
                                        },
                    "dcqcn_settings": {"alpha_g": 1021, "initial_alpha": 1001, "maximum_rate_decrement_at_time": 13},
                    # transmit_type can be either "target_line_rate" or "inter_batch_period".
                    "rocev2_port_config" : {"transmit_type": "target_line_rate", "target_line_rate": 70}
                    },
                2:{
                    "peers": [3],
                    "cnp": {"choice": "ip_dscp", "ip_dscp": 32, "ecn_value": "non_ect", "cnp_delay_timer": 103},
                    "connection_type": {
                                        "choice": "reliable_connection",
                                        "reliable_connection": {
                                                                "ack": {"choice": "ip_dscp",
                                                                        "ip_dscp": 61,
                                                                        "ecn_value": "non_ect"
                                                                        },
                                                                "enable_retransmission_timeout": True,
                                                                "retransmission_timeout_value": 30
                                                            }
                                        },
                    "dcqcn_settings": {"alpha_g": 1022, "initial_alpha": 1002, "maximum_rate_decrement_at_time": 14},
                    "rocev2_port_config": {"target_line_rate": 80}
                    },
                3:{
                    "peers": [1],
                    "cnp": {"choice": "ip_dscp", "ip_dscp": 44, "ecn_value": "non_ect", "cnp_delay_timer": 104},
                    "connection_type": {
                                        "choice": "reliable_connection",
                                        "reliable_connection": {
                                                                "ack": {"choice": "ip_dscp",
                                                                        "ip_dscp": 62,
                                                                        "ecn_value": "non_ect"
                                                                        },
                                                                "enable_retransmission_timeout": True,
                                                                "retransmission_timeout_value": 40
                                                            }
                                        },
                    "dcqcn_settings": {"alpha_g": 1023, "initial_alpha": 1003, "maximum_rate_decrement_at_time": 15},
                    "rocev2_port_config": {"target_line_rate": 100}
                }
    }
    '''

    # Required: peers list
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
            "enable_retransmission_timeout": False,
            "retransmission_timeout_value": 10
        }
    }
    default_dcqcn_settings_config = {"alpha_g": 1020, "initial_alpha": 1000, "maximum_rate_decrement_at_time": 12}
    default_rocev2_port_config = {"transmit_type": "target_line_rate", "target_line_rate": 100}

    # Build port lookup (unchanged)
    port_to_dev_ip = {pc.id: {"device": None, "ip": pc.ip} for pc in port_config_list if pc.ip}
    for dev in config.devices:
        if (name := getattr(dev, "name", "")) and name.startswith("Device Port "):
            try:
                port_to_dev_ip[int(name.split()[-1])]["device"] = dev
            except (ValueError, KeyError):
                continue

    qps_objs = {}
    for tx_port_id, topo_entry in topology.items():
        # VALIDATE: peers is REQUIRED
        if "peers" not in topo_entry:
            logger.error(f"Missing required 'peers' key for port {tx_port_id}. Skipping.")
            continue

        tx_info = port_to_dev_ip.get(tx_port_id)
        if not tx_info or not tx_info["device"]:
            continue

        tx_dev = tx_info["device"]
        ethernet = tx_dev.ethernets[0]
        # Default MTU, can be adjusted if needed
        # Hack: Set MTU for Ethernet interface to higher value to accommodate larger RoCEv2 packets.
        # If the MTU is too low, RoCEv2 ib_mtu cant be set to high.
        ethernet.mtu = topology[tx_port_id].get("mtu", 1500)
        ipv4_stack = ethernet.ipv4_addresses[0]

        # CREATE RoCEv2 interface (unchanged)
        rocev2 = getattr(tx_dev, "rocev2", None)
        rocev2_int = rocev2.ipv4_interfaces.add()
        # Set MTU for RoCEv2 interface
        rocev2_int.ib_mtu = topology[tx_port_id].get("mtu", 1500)
        rocev2_int.ipv4_name = ipv4_stack.name

        # SAFE DEFAULTS: Use .get() with defaults for all optional keys
        peers_ids = topo_entry["peers"]  # Required, already validated
        qp_cfgs = topo_entry.get("qp_configs", default_qp_configs)
        cnp_cfg = topo_entry.get("cnp", default_cnp_config)
        conn_type_cfg = topo_entry.get("connection_type", default_connection_type_config)
        dcqcn_settings_cfg = topo_entry.get("dcqcn_settings", default_dcqcn_settings_config)
        port_cfg = topo_entry.get("rocev2_port_config", default_rocev2_port_config)

        # DEST IPS from peers (unchanged)
        dest_port_ips = [port_to_dev_ip[port_id]["ip"] for port_id in peers_ids if port_id in port_to_dev_ip]
        logger.info(f"RoCEv2 {tx_port_id}, Dest Ports: {peers_ids}, Dest IPs: {dest_port_ips}")

        # CREATE peers + QPs (unchanged)
        peer = rocev2_int.peers.add()
        peer.name = f"RoCEv2 {tx_port_id}"
        peer.destination_ip_address = dest_port_ips if dest_port_ips else []

        qps_objs[tx_port_id] = []
        for indx, qp_cfg in enumerate(qp_cfgs):
            qp = peer.qps.add()
            qp.qp_name = f"QP{tx_port_id}_{indx}"
            qps_objs[tx_port_id].append((f"QP{tx_port_id}_{indx}", qp_cfg))
            qp.connection_type.choice = "reliable_connection"
            rc = qp.connection_type.reliable_connection
            # rc.source_qp_number = qp_cfg["qp_num"]
            # rc.dscp = qp_cfg["dscp"]
            # rc.ecn = qp_cfg["ecn"]

            rc.source_qp_number = qp_cfg.get("qp_num", default_qp_configs[indx]["qp_num"])
            rc.dscp = qp_cfg.get("dscp", default_qp_configs[indx]["dscp"])
            rc.ecn = qp_cfg.get("ecn", default_qp_configs[indx]["ecn"])

        # Stateful flows (unchanged)
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

        # Protocol port settings with SAFE DEFAULTS
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

        # Connection type - SAFE ACCESS
        cchoice = conn_type_cfg.get("choice", "reliable_connection")
        protocol.rocev2.connection_type.choice = cchoice
        logger.info(f"Configured RoCEv2 Protocol Port Settings Connection Type: {conn_type_cfg}")

        rc_conn = protocol.rocev2.connection_type.reliable_connection

        # Safe ack config
        ack_cfg = conn_type_cfg.get(cchoice, {}).get("ack", {})
        if ack_cfg:
            rc_conn.ack.choice = ack_cfg.get("choice", "ip_dscp")
            rc_conn.ack.ip_dscp.value = ack_cfg.get("ip_dscp", 59)
            rc_conn.ack.ecn_value = ack_cfg.get("ecn_value", "ect_0")

        # Safe nak config (if present in your user input)
        nak_cfg = conn_type_cfg.get(cchoice, {}).get("nak", {})
        if nak_cfg:
            rc_conn.nak.choice = nak_cfg.get("choice", "ip_dscp")
            rc_conn.nak.ip_dscp.value = nak_cfg.get("ip_dscp", 48)
            rc_conn.nak.ecn_value = nak_cfg.get("ecn_value", "non_ect")

        # Rest unchanged
        rc_conn.enable_retransmission_timeout = conn_type_cfg.get(cchoice, {}).get(
                                                                                    "enable_retransmission_timeout",
                                                                                    False
                                                                                   )
        rc_conn.retransmission_timeout_value = conn_type_cfg.get(cchoice, {}).get("retransmission_timeout_value", 10)
        dcqcn = protocol.rocev2.dcqcn_settings
        dcqcn.alpha_g = dcqcn_settings_cfg.get("alpha_g", 1020)
        dcqcn.initial_alpha = dcqcn_settings_cfg.get("initial_alpha", 1000)
        dcqcn.maximum_rate_decrement_at_time = dcqcn_settings_cfg.get("maximum_rate_decrement_at_time", 12)

    return config  # Return for later use


def wait_for(func, condition_str, interval_seconds=None, timeout_seconds=None):
    """
    Keeps calling the `func` until it returns true or `timeout_seconds` occurs
    every `interval_seconds`. `condition_str` should be a constant string
    implying the actual condition being tested.
    Usage
    -----
    If we wanted to poll for current seconds to be divisible by `n`, we would
    implement something similar to following:
    ```
    import time
    def wait_for_seconds(n, **kwargs):
        condition_str = 'seconds to be divisible by %d' % n
        def condition_satisfied():
            return int(time.time()) % n == 0
        poll_until(condition_satisfied, condition_str, **kwargs)
    ```
    """
    if interval_seconds is None:
        interval_seconds = 10
    if timeout_seconds is None:
        timeout_seconds = 180
    start_seconds = int(time.time())

    logger.info("Waiting for %s ..." % condition_str)
    while True:
        res = func()
        if res:
            logger.info("Done waiting for %s" % condition_str)
            break
        if res is None:
            raise Exception("Wait aborted for %s" % condition_str)
        if timed_out(start_seconds, timeout_seconds):
            msg = "Time out occurred while waiting for %s" % condition_str
            raise Exception(msg)

        time.sleep(interval_seconds)


def wait_with_message(message, duration):
    """Displays a countdown while waiting."""
    for remaining in range(duration, 0, -1):
        logger.info(f"{message} {remaining} seconds remaining.")
        # sys.stdout.flush()
        time.sleep(1)
    logger.info("")  # Ensure line break after countdown.


def seconds_elapsed(start_seconds):
    return int(round(time.time() - start_seconds))


def timed_out(start_seconds, timeout):
    return seconds_elapsed(start_seconds) > timeout


def is_traffic_running(api, flow_names=[]):
    """
    Returns true if traffic in start state
    """
    request = api.metrics_request()
    request.rocev2_flow.choice = "per_qp"
    request.rocev2_flow.per_qp.column_names = flow_names
    rocev2_flow_stats = api.get_metrics(request).rocev2_flow_per_qp_metrics
    # return all([int(fs.data_tx_rate) > 0 for fs in rocev2_flow_stats])
    return any(int(fs.data_tx_rate) > 0 for fs in rocev2_flow_stats)


def is_traffic_stopped(api, flow_names=[]):
    """
    Returns true if traffic in stop state
    """
    request = api.metrics_request()
    request.rocev2_flow.choice = "per_qp"
    request.rocev2_flow.per_qp.column_names = flow_names
    rocev2_flow_stats = api.get_metrics(request).rocev2_flow_per_qp_metrics
    return all([int(fs.data_tx_rate) == 0 for fs in rocev2_flow_stats])


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
        wait_for(lambda: is_traffic_stopped(api), "Traffic to Stop", interval_seconds=1, timeout_seconds=180)
    elif op_type == "traffic" and operation == "start":
        wait_for(lambda: is_traffic_running(api), "Traffic to Start", interval_seconds=10, timeout_seconds=180)
    else:
        wait(waittime, f"For {op_type} To {operation}")


def compute_tx_rates_single_rx(topology, total_rate=100, overhead=10):
    """
    Update topology in-place with integer TX rates using base+remainder distribution.

    Args:
        topology (dict): {port_id: {'peers': [rx_id]}, ...} where keys are TX ports,
                        one RX port has empty peers list
        total_rate (int): Base total rate to distribute (default: 100)
        overhead (int): Extra units to distribute across all TX ports (default: 10)

    Returns:
        dict: topology (updated in-place)

    Algorithm:
        1. Find active TX ports (those with non-empty 'peers' list)
        2. total = total_rate + overhead
        3. base = total // n_active (floor division)
        4. rem = total % n_active (remainder)
        5. First `rem` TX ports get `base + 1`, others get `base`

    This ensures perfect integer distribution with exact total overhead.

    Example:
        topology = {0: {'peers': [3]}, 1: {'peers': [3]}, 2: {'peers': [3]}, 3: {'peers': []}}
        total_rate=100, overhead=10, n_active=3
        total=110, base=36, rem=2
        Results: TX0=37, TX1=37, TX2=36 (sum=110 ✓)

        topology[0]['rocev2_port_config']['target_line_rate'] = 37
        topology[1]['rocev2_port_config']['target_line_rate'] = 37
        topology[2]['rocev2_port_config']['target_line_rate'] = 36
    """
    # Active TX ports: those that have at least one peer
    active_txs = [tx for tx, info in topology.items() if info.get("peers")]
    n_active = len(active_txs)
    if not n_active:
        return topology

    total = total_rate + overhead  # e.g. 110
    base = total // n_active       # integer division
    rem = total % n_active        # leftover to distribute

    # Give `base` to everyone, and +1 to the first `rem` ports
    for i, tx in enumerate(active_txs):
        rate = base + (1 if i < rem else 0)
        topology[tx].setdefault("rocev2_port_config", {})["target_line_rate"] = rate

    return topology


def get_stats(api, stat_name, columns=None, return_type='stat_obj'):
    """
    Args:
        api (pytest fixture): Snappi API
    """
    def deep_getattr(obj, attr, default=None):
        try:
            for part in attr.split('.'):
                obj = getattr(obj, part)
            return obj
        except AttributeError:
            return default

    column_headers = [
                        "flow_name", "port_tx", "port_rx", "src_qp", "dest_qp", "src_ipv4", "dest_ipv4",
                        "data_frames_tx", "data_frames_rx", "frame_delta", "data_frames_retransmitted",
                        "frame_sequence_error", "tx_bytes", "rx_bytes", "data_tx_rate", "data_rx_rate",
                        "message_tx", "message_complete_rx", "message_fail", "flow_completion_time",
                        "avg_latency", "min_latency", "max_latency", "ecn_ce_rx", "cnp_tx", "cnp_rx",
                        "ack_tx", "ack_rx", "nak_tx", "nak_rx", "first_timestamp", "last_timestamp",
                    ]

    req = api.metrics_request()
    if stat_name == "per_qp":
        req.rocev2_flow.choice = "per_qp"
        req.rocev2_flow.per_qp.column_names = []
        stat_obj = api.get_metrics(req).rocev2_flow_per_qp_metrics

    elif stat_name == "per_peer":
        req.rocev2_ipv4.choice = "per_peer"
        req.rocev2_ipv4.per_peer.column_names = []
        stat_obj = api.get_metrics(req).rocev2_flow_per_qp_metrics

    elif stat_name == "Port Statistics":

        '''
        req.port.port_names = []
        stat_obj = api.get_metrics(req).port_metrics
        column_headers = [
            "bytes_rx", "bytes_rx_rate", "bytes_tx", "bytes_tx_rate", "capture", "frames_rx", "frames_rx_rate",
            "frames_tx", "frames_tx_rate", "link", "location", "name"]
        '''
        ixnet = api._ixnetwork
        dp_metrics = StatViewAssistant(ixnet, stat_name)
        df = pd.DataFrame(dp_metrics.Rows.RawData, columns=dp_metrics.ColumnHeaders)
        df = df[columns] if columns else df
        # cols = ['Tx Frame Rate', 'Rx Frame Rate']
        # df[cols] = df[cols].apply(pd.to_numeric, errors='coerce')
        if return_type == 'print':
            logger.info("\n%s" % tabulate(df, headers="keys", tablefmt="psql"))
        elif return_type == 'df':
            return df

    rows = [
        [deep_getattr(stat, column, None) for column in column_headers]
        for stat in stat_obj
    ]
    tdf = pd.DataFrame(rows, columns=column_headers)
    selected_columns = columns if columns else column_headers
    df = tdf[selected_columns]
    if return_type == 'print':
        logger.info("\n%s" % tabulate(df, headers="keys", tablefmt="psql"))
    elif return_type == 'df':
        return df
    else:
        return stat_obj


def assert_mask(
    df,
    mask,
    columns,
    description,
    context_cols=("flow_name", "port_tx", "port_rx"),
    context_df=None,
    explanation=None,
):
    """
    Generic assertion helper.

    Contract: mask is True where the condition FAILS.
    On pass: prints explanation (if any) and the rows checked.
    On fail: prints explanation + offending rows, then raises.
    """
    if isinstance(mask, pd.Series):
        mask = mask.to_frame()

    base_df = context_df if context_df is not None else df

    # Only include available context columns
    ctx = [c for c in context_cols if c in base_df.columns]
    show_cols = ctx + list(columns)

    # Offending rows (mask True)
    bad_rows = base_df.loc[mask.any(axis=1), show_cols]
    # Rows that were checked (for context on pass)
    checked_rows = base_df[show_cols]

    header = f"[CHECK] {description}"
    if explanation:
        header += f" — {explanation}"
    logger.info(header)

    if bad_rows.empty:
        # PASS: show what we validated
        logger.info(f"[PASS] {description} – no offending rows.")
        if not checked_rows.empty:
            logger.info(
                f"[DATA] {description} – rows checked: \n"
                f"{tabulate(checked_rows, headers='keys', tablefmt='psql')}"
            )
        return

    # FAIL: show offending rows and raise
    logger.error(
        f"[DATA] {description} – offending rows: \n"
        f"{tabulate(bad_rows, headers='keys', tablefmt='psql')}"
    )

    raise AssertionError(
        f"{description} failed: \n"
        f"{tabulate(bad_rows, headers='keys', tablefmt='psql')}"
    )


def run_assertions(df, checks, fail_fast=False):
    """Run all assertions, print summary, fail at end if any failed."""
    failures = []

    for i, entry in enumerate(checks, 1):
        # Support:
        # (mask, cols, desc)
        # (mask, cols, desc, expl)
        # (mask, cols, desc, expl, extra_kwargs)
        if len(entry) == 3:
            mask, cols, desc = entry
            expl = None
            extra = {}
        elif len(entry) == 4:
            mask, cols, desc, expl = entry
            extra = {}
        else:
            mask, cols, desc, expl, extra = entry

        try:
            logger.info(f"✓ Check {i}: {desc}")
            assert_mask(
                df=df,
                mask=mask,
                columns=cols,
                description=desc,
                explanation=expl,
                **extra,
            )
        except AssertionError:
            logger.error(f"✗ Check {i}: {desc}")
            failures.append((i, desc))
            if fail_fast:
                raise

    if failures:
        logger.error(f"\n❌ {len(failures)}/{len(checks)} checks failed: ")
        for i, desc in failures:
            logger.error(f"  {i}. {desc}")
        raise AssertionError(f"{len(failures)} checks failed")
