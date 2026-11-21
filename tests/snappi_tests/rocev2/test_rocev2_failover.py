# flake8: noqa: F403, F401, F405
"""
Test Case 10 - RoCEv2 failover and recovery (leaf-spine Topology 2).

Objective:
    Validate RoCEv2 traffic continues WITHOUT LOSS when a fabric uplink on the
    sender leaf is taken down mid-traffic (ECMP failover) and when it is restored.

Topology:
    Test Topology 2 (leaf-spine). Roles discovered from conn_graph_facts. Cross-leaf
    traffic (sender leaf -> spine -> receiver leaf) on 3 pairs so flows ride the
    leaf->spine uplink ECMP. Lossless Q3 (DSCP from the DUT map), DCQCN on, ECT,
    4K IB MTU, 1 MB messages.

Phased run (mirrors plan steps 3/4/5):
    baseline  - traffic up, note which uplinks carry it (step 3).
    failover  - admin-DOWN the busiest uplink on the sender leaf; traffic must move
                to the other uplinks with no loss (step 4).
    recovery  - admin-UP the uplink; traffic returns (resilient ECMP) or stays on
                the alternate - both allowed by the plan (step 5).

Checks:
    * HARD: no frame drops across the whole event (frame_delta <= DROP_TOLERANCE_PCT
      of tx) on the lossless fabric; and failover actually happened (the downed
      uplink froze while others picked up the traffic).
    * OBSERVATIONAL (log): per-phase uplink distribution and whether traffic
      returned to the restored link (resilient-ECMP behavior is config-dependent).

"""
import pytest
import logging

from snappi_tests.rocev2.files.helper import *   # lib + re-exported fixtures

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]

BASELINE_SEC = 15          # step 3: traffic steady before failover
SETTLE_SEC = 5             # let a link up/down propagate (SAI/port state) before measuring
FAILOVER_SEC = 15          # step 4: steady window with the uplink down
RECOVERY_SEC = 15          # step 5: steady window after restoring the uplink
DATA_QUEUE = 3             # lossless data queue; DSCP from the DUT map
CNP_QUEUE = 5
LINE_RATE_PCT = 100
IB_MTU = 4096
MSG_SIZE_MB = 1
PAIR_COUNT = 3             # cross-leaf pairs (plan: ports 0-4, 1-5, 2-6)
DROP_TOLERANCE_PCT = 0.1   # hard no-drop across failover (small reconvergence blip tolerated)
ACTIVE_UPLINK_THRESH = 1000  # pkts; uplink carrying more than this is "active"
ECN = "ect_1"


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


def _egress_delta(after_df, before_df):
    """Per-uplink tx_pkts delta between two leaf_egress_counters snapshots."""
    m = after_df.merge(before_df[["uplink_port", "tx_pkts"]], on="uplink_port",
                       suffixes=("", "_before"))
    m["tx_delta"] = (pd.to_numeric(m["tx_pkts"], errors="coerce")
                     - pd.to_numeric(m["tx_pkts_before"], errors="coerce"))
    return m[["leaf", "uplink_port", "peer", "peer_port", "tx_delta"]]


def _phase_table(delta_df, victim, down_victim):
    """Human-readable per-phase view: the packets carried by each uplink DURING a
    phase (the delta, not the cumulative counter) plus a plain-English role, so the
    reader sees at a glance which uplink is the downed victim, which are carrying,
    and which are idle."""
    df = delta_df.rename(columns={"tx_delta": "pkts_this_phase", "leaf": "dut"}).copy()

    def _role(row):
        if row["uplink_port"] == victim:
            return "VICTIM (link down)" if down_victim else "VICTIM (restored)"
        return "carrying" if row["pkts_this_phase"] > ACTIVE_UPLINK_THRESH else "idle"

    df["role"] = df.apply(_role, axis=1)
    return df[["dut", "uplink_port", "peer", "peer_port", "pkts_this_phase", "role"]]


def test_rocev2_failover(
                        request,
                        snappi_api,
                        conn_graph_facts,
                        fanout_graph_facts_multidut,
                        get_snappi_ports,
                        duthosts,
                        prio_dscp_map,
                    ):
    """
    Cross-leaf RoCEv2; drop + restore a sender-leaf uplink mid-traffic. HARD: no
    drops across the event + failover observed. Recovery behavior observational.
    """
    snappi_port_list = get_snappi_ports
    pytest_require(len(snappi_port_list) >= 2, "Need minimum of 2 ports")

    tconfig, plist, sports = snappi_dut_base_config(duthosts, snappi_port_list, snappi_api)
    priority_to_dscp = derive_priority_to_dscp(prio_dscp_map)

    fabric = build_fabric_map(conn_graph_facts, sports, duthosts)
    leaf_names = sorted(fabric.leaves)
    pytest_require(len(leaf_names) >= 2, "TC10 needs a leaf-spine fabric (>=2 leaves)")
    sender_leaf, rx_leaf = leaf_names[0], leaf_names[1]
    sender_host = fabric.leaves[sender_leaf]["host"]
    sender_ids = fabric.leaves[sender_leaf]["tester_port_ids"]
    rx_ids = fabric.leaves[rx_leaf]["tester_port_ids"]
    uplinks = fabric.leaves[sender_leaf]["uplinks"]
    pytest_require(len(uplinks) >= 2, "Need >=2 uplinks on the sender leaf for failover")

    n_pairs = min(PAIR_COUNT, len(sender_ids), len(rx_ids))
    pytest_require(n_pairs >= 1, "Need >=1 tester port on each leaf")
    pairs = list(zip(sender_ids[:n_pairs], rx_ids[:n_pairs]))

    port_cfg = {"transmit_type": "target_line_rate", "target_line_rate": LINE_RATE_PCT}
    cnp_cfg = {"ip_dscp": priority_to_dscp[CNP_QUEUE], "ecn_value": ECN}
    data_dscp = priority_to_dscp[DATA_QUEUE]

    def tx_cfg():
        return {
            "mtu": IB_MTU,
            "qp_configs": [{"qp_num": 100, "message_size_unit": "mb", "message_size": MSG_SIZE_MB,
                            "dscp": data_dscp, "ecn": ECN}],
            "cnp": cnp_cfg,
            "dcqcn_settings": {"enable_dcqcn": True},
            "connection_type": _conn(DATA_QUEUE, ECN, priority_to_dscp),
            "rocev2_port_config": port_cfg,
        }

    active_senders = {tx for tx, _ in pairs}
    topology = {}
    for lf in leaf_names:
        for pid in fabric.leaves[lf]["tester_port_ids"]:
            if pid not in active_senders:
                topology[pid] = {"peers": [], **tx_cfg()}      # receive-only stack
    for tx, rx in pairs:
        topology[tx] = {"peers": [rx], **tx_cfg()}

    logger.info(
        "\n===== TC10 failover/recovery run summary =====\n"
        f"  sender leaf     : {sender_leaf}  (ports {sender_ids[:n_pairs]})\n"
        f"  receiver leaf   : {rx_leaf}  (ports {rx_ids[:n_pairs]})\n"
        f"  spine           : {fabric.spine.get('hostname')}\n"
        f"  cross-leaf pairs: {n_pairs}\n"
        f"  data            : Q{DATA_QUEUE} -> DSCP {data_dscp}, {ECN}, DCQCN on, {LINE_RATE_PCT}% rate\n"
        f"  uplinks (sender): {sorted(uplinks)} on {sender_leaf}\n"
        f"  phases (s)      : baseline {BASELINE_SEC} / failover {FAILOVER_SEC} / recovery {RECOVERY_SEC}\n"
        "=============================================="
    )

    victim = None
    try:
        config = configure_rocev2_topology(tconfig, plist, topology)
        snappi_api.set_config(config)
        start_stop(snappi_api, operation="start", op_type="protocols")
        clear_fabric_counters(fabric)   # leaves + spine, so egress reads per-run deltas
        start_stop(snappi_api, operation="start", op_type="traffic")

        # ---- baseline (step 3): which uplinks carry traffic, and pick the victim ----
        wait(BASELINE_SEC, "baseline traffic before failover")
        egress_before = leaf_egress_counters(sender_host, uplinks)
        base_active = egress_before[pd.to_numeric(egress_before["tx_pkts"], errors="coerce") > ACTIVE_UPLINK_THRESH]
        pytest_assert(not base_active.empty, "No uplink carried traffic at baseline - cannot test failover")
        victim = base_active.sort_values("tx_pkts", ascending=False).iloc[0]["uplink_port"]
        others = [p for p in sorted(uplinks) if p != victim]
        logger.info(f"[baseline] traffic is on uplinks {base_active['uplink_port'].tolist()}; "
                    f"busiest = {victim} -> chosen as the VICTIM to shut down.\n"
                    f"{tabulate(egress_before, headers='keys', tablefmt='psql')}")
        logger.info(f"[expect] shut {victim}: its flow(s) should fail over (ECMP re-hash) to the other "
                    f"uplinks; lossless (PFC/DCQCN) => no drops. Each phase table below shows packets "
                    f"carried DURING that phase (delta), not the cumulative counter.")

        # ---- failover (step 4): drop the victim; measure the STEADY window
        #      (snapshot AFTER the shutdown propagates, so the victim reads ~0 rather
        #      than the residual that flows before the port actually goes down). ----
        set_link_state(sender_host, victim, up=False)
        wait(SETTLE_SEC, "for the uplink shutdown to propagate")
        egress_down_start = leaf_egress_counters(sender_host, uplinks)
        wait(FAILOVER_SEC, "steady traffic with the uplink DOWN (failover)")
        egress_down = leaf_egress_counters(sender_host, uplinks)
        fail_delta = _egress_delta(egress_down, egress_down_start)
        fail_tbl = _phase_table(fail_delta, victim, down_victim=True)
        moved_to = fail_tbl[fail_tbl["role"] == "carrying"]["uplink_port"].tolist()
        logger.info(f"[failover] {victim} is DOWN; traffic failed over to {moved_to}. "
                    f"Packets per uplink during the DOWN window:\n"
                    f"{tabulate(fail_tbl, headers='keys', tablefmt='psql')}")

        # ---- recovery (step 5): restore the victim; measure the STEADY window ----
        set_link_state(sender_host, victim, up=True)
        wait(SETTLE_SEC, "for the uplink startup to propagate")
        egress_up_start = leaf_egress_counters(sender_host, uplinks)
        wait(RECOVERY_SEC, "steady traffic after restoring the uplink (recovery)")
        egress_up = leaf_egress_counters(sender_host, uplinks)
        rec_delta = _egress_delta(egress_up, egress_up_start)
        rec_tbl = _phase_table(rec_delta, victim, down_victim=False)
        logger.info(f"[recovery] {victim} restored. Packets per uplink during the RECOVERY window:\n"
                    f"{tabulate(rec_tbl, headers='keys', tablefmt='psql')}")

        start_stop(snappi_api, operation="stop", op_type="traffic")
        flow_df = get_stats(snappi_api, stat_name="per_qp", return_type="df")
        # IxNetwork per-QP stats (transposed, one column per flow) - same view the other TCs log.
        # Filter to the sending flows so the receive-only ranks don't clutter the table.
        tx_flows = flow_df[pd.to_numeric(flow_df["data_frames_tx"], errors="coerce") > 0]
        logger.info(f"IxNetwork per-QP traffic stats (sending flows):\n"
                    f"{tabulate(tx_flows.set_index('flow_name').T, headers='keys', tablefmt='psql')}")

        # ---- failover evidence (deltas computed inline above) ----
        victim_down = float(fail_delta[fail_delta["uplink_port"] == victim]["tx_delta"].iloc[0])
        others_down = float(fail_delta[fail_delta["uplink_port"] != victim]["tx_delta"].sum())
        victim_rec = float(rec_delta[rec_delta["uplink_port"] == victim]["tx_delta"].iloc[0])
        # Report recovery factually (don't claim resilient ECMP): did the victim carry
        # traffic again, and did the uplinks that absorbed it during the DOWN phase keep
        # carrying it? alternates still busy + victim idle => resilient (flows pinned);
        # victim busy + alternates idle => standard ECMP re-hash back to the restored link.
        alt_ports = fail_delta[(fail_delta["uplink_port"] != victim)
                               & (fail_delta["tx_delta"] > ACTIVE_UPLINK_THRESH)]["uplink_port"].tolist()
        alt_still = rec_delta[(rec_delta["uplink_port"].isin(alt_ports))
                              & (rec_delta["tx_delta"] > ACTIVE_UPLINK_THRESH)]["uplink_port"].tolist()
        if victim_rec > ACTIVE_UPLINK_THRESH and not alt_still:
            behavior = "flows re-hashed back to the restored link (standard ECMP)"
        elif victim_rec <= ACTIVE_UPLINK_THRESH and alt_still:
            behavior = "flows stayed on alternate uplinks (resilient ECMP)"
        else:
            behavior = "mixed"
        logger.info(f"Recovery: victim {victim} carried {victim_rec:.0f} pkts after restore; "
                    f"down-phase alternates still active: {alt_still or 'none'} -> {behavior}")

        # ---- no-loss across the whole event (hard) ----
        flow_df["drop_pct"] = (
            pd.to_numeric(flow_df["frame_delta"], errors="coerce").abs()
            / pd.to_numeric(flow_df["data_frames_tx"], errors="coerce").replace(0, pd.NA) * 100)
        checks = [
            make_check(f"data_frames_tx > 0 and drop_pct > {DROP_TOLERANCE_PCT}",
                    ["flow_name", "port_tx", "port_rx", "data_frames_tx", "frame_delta", "drop_pct"],
                    "No frame drops across failover/recovery",
                    f"frame_delta must be <= {DROP_TOLERANCE_PCT}% of tx frames through the link down/up"),
        ]
        assert_queries(flow_df, checks)

        # ---- failover actually happened (hard) ----
        pytest_assert(victim_down <= ACTIVE_UPLINK_THRESH,
                      f"Victim uplink {victim} still carried {victim_down:.0f} pkts after shutdown "
                      f"(expected ~0):\n{tabulate(fail_delta, headers='keys', tablefmt='psql')}")
        pytest_assert(others_down > ACTIVE_UPLINK_THRESH,
                      f"Traffic did not move to other uplinks after shutdown (others delta {others_down:.0f}):\n"
                      f"{tabulate(fail_delta, headers='keys', tablefmt='psql')}")

        logger.info(f"*** TC10 failover/recovery PASSED (victim {victim}: froze on down, "
                    f"{'returned' if victim_rec > ACTIVE_UPLINK_THRESH else 'stayed off'} on restore) ***")
    finally:
        # make sure the victim link is back up even if the test aborted mid-failover
        if victim is not None:
            try:
                set_link_state(sender_host, victim, up=True)
            except Exception as e:
                logger.warning(f"Could not restore link {victim}: {e}")
        start_stop(snappi_api, operation="stop", op_type="traffic", wait_convergence=False)
        start_stop(snappi_api, operation="stop", op_type="protocols")
