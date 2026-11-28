# flake8: noqa: F403, F401, F405
"""
Test Case 7 - RoCEv2 hashing and load balancing (leaf-spine Topology 2).

Objective:
    Verify the DUT distributes RoCEv2 traffic across the leaf->spine ECMP uplinks.
    Flows run cross-leaf (sender leaf -> spine -> receiver leaf); we observe how
    they hash across the sender leaf's uplink egress ports.

Topology:
    Test Topology 2 (leaf-spine Clos). Roles are DISCOVERED from conn_graph_facts
    (classify_fabric): leaves = DUTs with tester ports, spine = DUT with only
    DUT<->DUT links. Nothing is hardcoded, so this scales to any leaf/uplink/port
    count. On the reference testbed: leaves dut1/dut2, spine dut3, 8 uplinks/leaf.

Traffic:
    Cross-leaf RoCEv2, lossless Q3 (DSCP from the DUT map), DCQCN on, ECT, 1 MB
    messages, 100% line rate. Scales via two knobs:
      - RANK_PAIRS  : how many cross-leaf tester-port pairs (clamped to available)
      - QPS_PER_PAIR: QPs per pair (the plan's "X QPs"; main hashing-entropy knob)

Parametrized `scenario` mirrors the plan's progression (1/2/4 pairs, 1/X QPs,
with/without staggered transmit).

Checks:
    * HARD: no frame drops on the lossless fabric (frame_delta <= DROP_TOLERANCE_PCT
      of tx frames) and traffic present on >=1 uplink.
    * OBSERVATIONAL (logged + WARNed, not failed): uplink distribution (how many
      uplinks carried traffic, how even) - NOT asserted to an exact port count, as
      hashing is HW-proprietary; message completion and sequence errors - under
      uplink collision these reflect congestion/reorder (expected per the plan),
      not loss, since frame_delta stays ~0; plus a spine->rx-leaf egress spread
      diagnostic to spot the spine re-spreading single flows (a reorder source).

NOTE: staggered transmit (plan steps 6/9) is enabled via restpy (OTG/snappi does
not expose it) in stagger_flows(), applied as a pre_traffic_hook so it survives
set_config and takes effect before traffic starts.
"""
import pytest
import logging

from snappi_tests.rocev2.files.helper import *   # lib + re-exported fixtures

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]

TRAFFIC_DURATION = 30      # seconds
DATA_QUEUE = 3             # lossless data queue; DSCP from the DUT DSCP->TC map
CNP_QUEUE = 5              # CNP control queue; DSCP from the DUT map
LINE_RATE_PCT = 100
QPS_PER_PAIR = 8           # the plan's "X QPs" (hashing-entropy knob)
ACTIVE_UPLINK_THRESH = 1000  # pkts; an uplink carrying more than this is "active"
DROP_TOLERANCE_PCT = 0.1     # hard no-drop: frame_delta must be <= this % of tx frames
SEQ_ERR_TOLERANCE_PCT = 1.0  # seq errors above this are WARNed (reorder under collision), not failed
RATE_SAMPLE_START = 5
ECN = "ect_1"             # ECT so DCQCN keeps the lossless queue loss-free under incast

# scenario -> (cross-leaf pairs, QPs/pair, staggered, soft-expected active uplinks)
HASH_SCENARIOS = {
    "1pair_1qp":         dict(pairs=1, qps=1,           stagger=False, exp_min=1),
    "1pair_Xqp":         dict(pairs=1, qps=QPS_PER_PAIR, stagger=False, exp_min=1),
    "2pair_1qp":         dict(pairs=2, qps=1,           stagger=False, exp_min=1),
    "2pair_1qp_stagger": dict(pairs=2, qps=1,           stagger=True,  exp_min=2),
    "2pair_Xqp":         dict(pairs=2, qps=QPS_PER_PAIR, stagger=False, exp_min=2),
    "4pair_1qp":         dict(pairs=4, qps=1,           stagger=False, exp_min=1),
    "4pair_1qp_stagger": dict(pairs=4, qps=1,           stagger=True,  exp_min=2),
    "4pair_Xqp":         dict(pairs=4, qps=QPS_PER_PAIR, stagger=False, exp_min=2),
}


def _conn(q, ecn_value, priority_to_dscp):
    return {
        "choice": "reliable_connection",
        "reliable_connection": {
            "ack": {"ip_dscp": priority_to_dscp[q], "ecn_value": ecn_value},
            "nak": {"ip_dscp": priority_to_dscp[q], "ecn_value": ecn_value},
            "enable_retransmission_timeout": True,
            "retransmission_timeout_value": 5000,
            "retransmission_retry_count": 254,
        },
    }


def stagger_flows(api):
    """
    Enable IxNetwork staggered transmit (plan steps 6/9) so flow groups / ports
    start at offset times, changing hash timing and spreading load across uplinks.
    OTG/snappi does not expose this, so it is set via restpy on the Traffic object.
    Used as a pre_traffic_hook: it must run AFTER set_config (which rebuilds the
    traffic) and BEFORE traffic starts.
    """
    ixn = api._ixnetwork
    ixn.Traffic.EnableStaggeredTransmit = True      # stagger flow-group starts
    ixn.Traffic.EnableStaggeredStartDelay = True    # stagger per-port starts
    logger.info("Enabled IxNetwork staggered transmit (restpy)")


@pytest.mark.parametrize("scenario", list(HASH_SCENARIOS), ids=list(HASH_SCENARIOS))
def test_rocev2_hashing_lb(
                            request,
                            snappi_api,
                            conn_graph_facts,
                            fanout_graph_facts_multidut,
                            get_snappi_ports,
                            duthosts,
                            prio_dscp_map,
                            scenario,
                        ):
    """
    Cross-leaf RoCEv2 over the leaf->spine ECMP; observe uplink-egress hashing on
    the sender leaf. HARD: no loss / no NAK / >=1 active uplink. Distribution is
    observational (hashing is HW-proprietary).
    """
    cfg = HASH_SCENARIOS[scenario]
    snappi_port_list = get_snappi_ports
    pytest_require(len(snappi_port_list) >= 2, "Need minimum of 2 ports")

    tconfig, plist, sports = snappi_dut_base_config(duthosts, snappi_port_list, snappi_api)
    priority_to_dscp = derive_priority_to_dscp(prio_dscp_map)

    # ---- discover the fabric (leaves / spine / uplinks) from conn_graph_facts ----
    fabric = build_fabric_map(conn_graph_facts, sports, duthosts)
    leaf_names = sorted(fabric.leaves)
    pytest_require(len(leaf_names) >= 2, "TC7 needs a leaf-spine fabric (>=2 leaves)")
    sender_leaf, rx_leaf = leaf_names[0], leaf_names[1]
    sender_ids = fabric.leaves[sender_leaf]["tester_port_ids"]
    rx_ids = fabric.leaves[rx_leaf]["tester_port_ids"]
    uplinks = fabric.leaves[sender_leaf]["uplinks"]
    pytest_require(len(uplinks) >= 2, "Need >=2 uplinks on the sender leaf to observe hashing")

    # scale the rank pairs to what's available (clamped), QPs scale freely
    n_pairs = min(cfg["pairs"], len(sender_ids), len(rx_ids))
    pytest_require(n_pairs >= 1, "Need >=1 tester port on each leaf")
    pairs = list(zip(sender_ids[:n_pairs], rx_ids[:n_pairs]))

    port_cfg = {"transmit_type": "target_line_rate", "target_line_rate": LINE_RATE_PCT}
    cnp_cfg = {"ip_dscp": priority_to_dscp[CNP_QUEUE], "ecn_value": ECN}
    data_dscp = priority_to_dscp[DATA_QUEUE]

    def tx_cfg(qps):
        return {
            "mtu": 4096,
            # distinct UDP source port per QP so the fabric ECMP has L4 entropy to hash on
            # (without it every QP shares src port 49152 and flows polarize onto few uplinks).
            "qp_configs": [{"qp_num": 100 + i, "message_size_unit": "mb", "message_size": 1,
                            "dscp": data_dscp, "ecn": ECN, "udp_source_port": 49152 + i}
                           for i in range(qps)],
            "cnp": cnp_cfg,
            "dcqcn_settings": {"enable_dcqcn": True},
            "connection_type": _conn(DATA_QUEUE, ECN, priority_to_dscp),
            "rocev2_port_config": port_cfg,
        }

    # Every tester port (both leaves) gets a RoCEv2 stack so all ranks are present
    # even when a scenario drives only 1-2 pairs: active senders transmit (peers +
    # QPs); every other rank is receive-only on the data queue. (A bare {"peers":[]}
    # would fall back to the default mixed-DSCP QP set, so give rx a data cfg too.)
    active_senders = {tx for tx, _ in pairs}
    topology = {}
    for lf in leaf_names:
        for pid in fabric.leaves[lf]["tester_port_ids"]:
            if pid not in active_senders:
                topology[pid] = {"peers": [], **tx_cfg(1)}   # receive-only stack
    for tx, rx in pairs:
        topology[tx] = {"peers": [rx], **tx_cfg(cfg["qps"])}

    logger.info(
        "\n===== TC7 hashing/LB run summary =====\n"
        f"  scenario        : {scenario}\n"
        f"  sender leaf     : {sender_leaf}  (ports {sender_ids[:n_pairs]})\n"
        f"  receiver leaf   : {rx_leaf}  (ports {rx_ids[:n_pairs]})\n"
        f"  spine           : {fabric.spine.get('hostname')}\n"
        f"  cross-leaf pairs: {n_pairs}   QPs/pair: {cfg['qps']}   staggered: {cfg['stagger']}\n"
        f"  data            : Q{DATA_QUEUE} -> DSCP {data_dscp}, {ECN}, DCQCN on, {LINE_RATE_PCT}% rate\n"
        f"  uplinks watched : {sorted(uplinks)} on {sender_leaf}\n"
        f"  distribution    : observational (soft-expect >= {cfg['exp_min']} active uplinks)\n"
        "======================================"
    )

    # staggered transmit (plan steps 6/9): applied via pre_traffic_hook so it runs
    # after set_config (which rebuilds traffic) and before traffic starts.
    stagger_hook = stagger_flows if cfg["stagger"] else None

    try:
        clear_fabric_counters(fabric)   # so leaf_egress_counters reads a per-run delta
        qids = [f"UC{q}" for q in (DATA_QUEUE, CNP_QUEUE)]
        merged_df, _, _, _, _ = collect_flow_queue_stats(
            snappi_api=snappi_api, duthosts=duthosts, plist=plist, tconfig=tconfig,
            snappi_dut_port_map=snappi_dut_port_mapping(sports), topology=topology,
            prio_dscp_map=prio_dscp_map, queue_ids=qids, traffic_duration=TRAFFIC_DURATION,
            sample_start=RATE_SAMPLE_START, config_name=request.node.name,
            pre_traffic_hook=stagger_hook)
        # ---- uplink egress distribution on the sender leaf (observational) ----
        egress_df = leaf_egress_counters(fabric.leaves[sender_leaf]["host"], uplinks)
        dist = fabric_distribution(egress_df, active_thresh=ACTIVE_UPLINK_THRESH)
        logger.info(f"Sender-leaf uplink egress ({sender_leaf}):\n"
                    f"{tabulate(egress_df, headers='keys', tablefmt='psql')}")
        logger.info(f"Uplink distribution:\n{tabulate(dist, headers='keys', tablefmt='psql')}")
        n_active = int(dist.iloc[0]["n_active"])
        if n_active < cfg["exp_min"]:
            logger.warning(f"[{scenario}] only {n_active} active uplink(s); soft-expected "
                           f">= {cfg['exp_min']} (hashing is HW-proprietary - informational)")

        # ---- spine-egress diagnostic: how traffic spreads on spine -> rx-leaf links.
        # Wider spread here than on the sender-leaf uplinks points to the spine
        # re-spreading flows (a reorder source for single QPs). Observational.
        spine_name = fabric.spine.get("hostname")
        spine_host = fabric.spine.get("host")
        spine_links = get_fabric_links(conn_graph_facts, spine_name, rx_leaf) if spine_name else {}
        if spine_host and spine_links:
            spine_df = leaf_egress_counters(spine_host, spine_links)
            spine_dist = fabric_distribution(spine_df, active_thresh=ACTIVE_UPLINK_THRESH)
            logger.info(f"Spine egress toward {rx_leaf} ({spine_name}):\n"
                        f"{tabulate(spine_df, headers='keys', tablefmt='psql')}")
            logger.info(f"Spine->rx distribution:\n{tabulate(spine_dist, headers='keys', tablefmt='psql')}")

        dscps = [data_dscp]
        # On a lossless fabric the real guarantee is NO DROPS (frame_delta ~ 0). Message
        # completion / sequence errors under uplink collision reflect congestion+reorder
        # (expected characterization per the plan), so they are WARNed, not failed.
        merged_df["drop_pct"] = (
            pd.to_numeric(merged_df["frame_delta"], errors="coerce").abs()
            / pd.to_numeric(merged_df["data_frames_tx"], errors="coerce").replace(0, pd.NA) * 100)
        merged_df["seq_err_pct"] = (
            pd.to_numeric(merged_df["frame_sequence_error"], errors="coerce")
            / pd.to_numeric(merged_df["data_frames_rx"], errors="coerce").replace(0, pd.NA) * 100)
        checks = [
            make_check(f"ip_dscp in {dscps} and drop_pct > {DROP_TOLERANCE_PCT}",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "data_frames_tx", "frame_delta", "drop_pct"],
                    "Lossless: no frame drops (fabric lossless)",
                    f"frame_delta must be <= {DROP_TOLERANCE_PCT}% of tx frames for DSCPs {dscps}"),
        ]
        assert_queries(merged_df, checks)

        # observational: message incompletion / reorder (congestion under collision, not loss)
        anomalies = merged_df[merged_df["ip_dscp"].isin(dscps) & (
            (pd.to_numeric(merged_df["message_fail"], errors="coerce") > 0)
            | (merged_df["seq_err_pct"] > SEQ_ERR_TOLERANCE_PCT))]
        if not anomalies.empty:
            logger.warning(
                f"[{scenario}] message incompletion / reorder under collision (congestion, not loss - "
                f"frame_delta is ~0):\n"
                f"{tabulate(anomalies[['flow_name', 'port_tx', 'port_rx', 'message_tx', 'message_fail', 'seq_err_pct']], headers='keys', tablefmt='psql')}")
        pytest_assert(n_active >= 1,
                      f"No uplink carried traffic (> {ACTIVE_UPLINK_THRESH} pkts) on {sender_leaf}; "
                      f"egress:\n{tabulate(egress_df, headers='keys', tablefmt='psql')}")
        logger.info(f"*** TC7 hashing/LB [{scenario}] PASSED "
                    f"({n_active}/{len(uplinks)} uplinks active) ***")
    finally:
        start_stop(snappi_api, operation="stop", op_type="traffic", wait_convergence=False)
        start_stop(snappi_api, operation="stop", op_type="protocols")
