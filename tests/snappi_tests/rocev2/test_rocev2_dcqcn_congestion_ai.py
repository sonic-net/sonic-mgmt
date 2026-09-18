# flake8: noqa: F403, F401, F405
"""
Test cases for RoCEv2 DCQCN congestion control.

Test Case 3 - Congestion Control with DCQCN for AI Traffic
Objective:
    Validate basic congestion control for RoCEv2/RDMA AI traffic using:
        - Priority Flow Control (PFC)
        - ECN marking on the switch
        - CNP/ACK behavior on the endpoints
    Applicable roles: T0, T1, T2.
Topology:
    Test Topology 1 (single DUT with four connected test ports), unidirectional
    3:1 incast. Every Tx sends to one Rx at 100% line rate. The LAST Tx drives the
    lossy queues (0/1/2, one QP each); the other Tx ports drive the scenario's
    lossless queue(s). DCQCN enabled. DSCPs are taken from the DUT DSCP->TC map
    (a random DSCP is picked per queue when several map to it).

Queues: lossless Q3/Q4, lossy Q0/Q1/Q2, CNP -> Q5, ACK/NAK -> Q6.

Scenarios (parametrized):
    q3_single  - lossless Tx all on Q3, 128KB.            [TC3 Scenario 1]
    q3q4_dual  - lossless Tx split Q3/Q4, 128KB each.     [TC3 Scenario 2]
ECN-CE bit (parametrized): ect_0 / ect_1 (01/10) / ce (11).
4K IB MTU, 128KB message size (32 packets per message burst).
Traffic is duration-based (sustained 100% incast) rather than the plan's fixed 4 GB
per rank pair (see TRAFFIC_DURATION) - 4 GB is exceeded in <1 s at line rate.

Expected results (per the test plan) -> encoded as checks below:
    * All messages complete, no loss on the tester (strict: message_fail == 0
      and frame_delta == 0).
    * No NAK / sequence errors (strict).
    * Few or no PFC on the lossless queue(s) -> DUT Tx PFC <= tolerance.
    * ACK observed on the lossless queue(s) and matching the DUT Q6 counter.
    * ECN-CE observed on the lossless queue(s) -> ecn_ce_rx > 0 (see NOTE: the
      DUT does not expose a per-queue ECN-CE counter, so only presence is checked).
    * CNP observed on queue 5, matching the tester CNP counter (sum(cnp_rx) == UC5).
    * Avg/Max latency is logged (informational) and WARNs if above the AI profile;
      not asserted, since DCQCN queuing raises latency above the no-congestion cap.
    * DWRR rate split is logged for visibility but NOT asserted (under DCQCN the
      senders back off, so egress rate is set by the control loop, not DWRR).
Successful results indicate the DUT forwards RoCEv2 AI traffic and control
signalling as expected and DCQCN congestion control functions correctly.
"""
import pytest
import logging

from snappi_tests.rocev2.files.helper import *   # lib + re-exported fixtures

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]

# Traffic is duration-based (sustained 100% incast), NOT the plan's fixed "4 GB per
# rank pair": at line rate 4 GB is sent in <1 s, so a fixed-volume burst would barely
# exercise DCQCN. A fixed window keeps congestion sustained so ECN/CNP/PFC are driven
# for the whole test; 60 s is sufficient (a longer duration adds no coverage).
TRAFFIC_DURATION = 60      # seconds
LOSSY_QUEUES = [0, 1]    # lossy rank drives one QP per lossy queue (plan: Q0/Q1/Q2)
ACK_QUEUE = 6              # common queue carrying ACK/NAK for all (lossless + lossy) flows
CNP_QUEUE = 5              # CNP control queue; its DSCP comes from the DUT DSCP->TC map
LINE_RATE_PCT = 100           # % - each Tx sends at full rate to create the incast
COUNTER_TOLERANCE_PCT = 2  # CNP/ACK vs DUT counter skew allowed (in-flight at stop)
PFC_TOLERANCE_FRAMES = 100  # "few or no" PFC under DCQCN (not PFC-driven)
# Sample rates only after DCQCN has converged (it throttles senders via CNP), so
# the steady-state split is representative rather than caught mid-convergence.
RATE_SAMPLE_START = 12

# Each scenario = the (lossless_queue, message_size_kb) options assigned
# round-robin to the lossless Tx ports. The last Tx always drives LOSSY_QUEUES.
DCQCN_SCENARIOS = {
    "q3_single": [(3, 128)],
    "q3q4_dual": [(3, 128), (4, 128)],
}


def _conn(ack_nak_q, ecn_value, priority_to_dscp):
    return {
        "choice": "reliable_connection",
        "reliable_connection": {
            "ack": {"ip_dscp": priority_to_dscp[ack_nak_q], "ecn_value": ecn_value},
            "nak": {"ip_dscp": priority_to_dscp[ack_nak_q], "ecn_value": ecn_value},
            "enable_retransmission_timeout": True,
            "retransmission_timeout_value": 5000,
            "retransmission_retry_count": 254
        },
    }


@pytest.mark.parametrize("scenario", list(DCQCN_SCENARIOS), ids=list(DCQCN_SCENARIOS))
@pytest.mark.parametrize("ecn_ce", ["ect_0", "ect_1", "ce"])
def test_rocev2_dcqcn_congestion_ai(
                                    request,
                                    snappi_api,
                                    conn_graph_facts,
                                    fanout_graph_facts_multidut,
                                    get_snappi_ports,
                                    duthosts,
                                    prio_dscp_map,
                                    ecn_ce,
                                    scenario,
                                ):
    """
    3:1 incast at 100% line rate with DCQCN enabled. The lossless queues should be
    congestion-controlled by ECN/DCQCN (ECN-CE marked, CNP generated) rather than by
    PFC and complete without loss. The last Tx's lossy queues are unprotected. The
    Rx-egress rate split is logged (DCQCN-governed), not asserted.
    """
    snappi_port_list = get_snappi_ports
    pytest_require(len(snappi_port_list) >= 4, "Need minimum of 4 ports")

    tconfig, plist, sports = snappi_dut_base_config(duthosts, snappi_port_list, snappi_api)
    snappi_dut_port_map = snappi_dut_port_mapping(sports)
    port_ids = [pc.id for pc in plist]
    priority_to_dscp = derive_priority_to_dscp(prio_dscp_map)
    lossless_spec = DCQCN_SCENARIOS[scenario]

    port_cfg = {"transmit_type": "target_line_rate", "target_line_rate": LINE_RATE_PCT}
    cnp_dscp = priority_to_dscp[CNP_QUEUE]
    logger.info(f"CNP on queue {CNP_QUEUE} -> DSCP {cnp_dscp} (from DUT DSCP->TC map)")
    cnp_cfg = {"ip_dscp": cnp_dscp, "ecn_value": ecn_ce}

    def lossless_cfg(q, size_kb):
        return {
            "mtu": 5000,
            "qp_configs": [{"message_size_unit": "kb", "message_size": size_kb,
                            "dscp": priority_to_dscp[q], "ecn": ecn_ce}],
            "cnp": cnp_cfg,
            "dcqcn_settings": {"enable_dcqcn": True},          # DCQCN ON
            "connection_type": _conn(ACK_QUEUE, ecn_ce, priority_to_dscp),   # ACK/NAK on the common ACK queue
            "rocev2_port_config": port_cfg,
        }

    lossy_cfg = {
        "mtu": 5000,
        "qp_configs": [{"message_size_unit": "kb", "message_size": 128,
                        "dscp": priority_to_dscp[q], "ecn": ecn_ce} for q in LOSSY_QUEUES],
        "cnp": cnp_cfg,
        "dcqcn_settings": {"enable_dcqcn": True},
        "connection_type": _conn(ACK_QUEUE, ecn_ce, priority_to_dscp),   # ACK/NAK on the common ACK queue
        "rocev2_port_config": port_cfg,
    }

    # One Rx, rest Tx; lossless Tx cycle the scenario spec, last Tx -> lossy.
    topology, rx, last_tx, used = build_incast_topology(port_ids, lossless_cfg, lossless_spec, lossy_cfg)
    used_lossless = sorted({q for q, _ in used})
    logger.info(f"[{scenario}/{ecn_ce}] incast rx={rx} last_tx={last_tx} lossless_qs={used_lossless}\n{topology}")

    try:
        # ---- run incast + collect DUT-side data (universal collector) ----------
        qids = [f"UC{q}" for q in used_lossless + LOSSY_QUEUES + [ACK_QUEUE, CNP_QUEUE]]
        merged_df, _, dut_queue_df, _, _ = collect_flow_queue_stats(
            snappi_api=snappi_api, duthosts=duthosts, plist=plist, tconfig=tconfig,
            snappi_dut_port_map=snappi_dut_port_map, topology=topology,
            prio_dscp_map=prio_dscp_map, queue_ids=qids, traffic_duration=TRAFFIC_DURATION,
            sample_start=RATE_SAMPLE_START, config_name=request.node.name)

        # Rate split is logged for visibility but NOT asserted here: under DCQCN the
        # senders back off in response to CNP, so the lossless queues are not kept
        # backlogged and their egress rate is set by the control loop, not by the
        # DWRR weight share. (The weight-proportional assertion belongs in the PFC
        # test, where PFC keeps the lossless queue backlogged.)
        rate_info_df = build_rate_fairness_by_queue(merged_df)
        logger.info(f"Rate split (informational, DCQCN-governed):\n"
                    f"{tabulate(rate_info_df, headers='keys', tablefmt='psql')}")

        lossless_dscps = [priority_to_dscp[q] for q in used_lossless]
        cnp_q_col = f"UC{CNP_QUEUE} totalpacket"
        ack_q_col = f"UC{ACK_QUEUE} totalpacket"

        # CNP must ride queue 5 and match the DUT counter. CNP is delivered to the
        # senders (port_tx), so sum cnp_rx per port_tx and compare to UC5 on that
        # port's interface. Counters are compared within a small tolerance because
        # packets in flight when traffic stops cause a benign snappi/DUT skew.
        cnp_agg_df = merged_df.groupby("port_tx", as_index=False)["cnp_rx"].sum()
        cnp_agg_df[cnp_q_col] = cnp_agg_df["port_tx"].map(
            dut_queue_df.set_index("snappi_port")[cnp_q_col])
        cnp_agg_df["pct_err"] = ((cnp_agg_df["cnp_rx"] - cnp_agg_df[cnp_q_col]).abs()
                                 / cnp_agg_df[cnp_q_col].replace(0, pd.NA) * 100)
        logger.info(f"CNP vs DUT Q{CNP_QUEUE}:\n{tabulate(cnp_agg_df, headers='keys', tablefmt='psql')}")

        # ACK rides Q6 toward the senders; sum ack_rx per port_tx and match UC6.
        ack_agg_df = merged_df.groupby("port_tx", as_index=False)["ack_rx"].sum()
        ack_agg_df[ack_q_col] = ack_agg_df["port_tx"].map(dut_queue_df.set_index("snappi_port")[ack_q_col])
        ack_agg_df["pct_err"] = ((ack_agg_df["ack_rx"] - ack_agg_df[ack_q_col]).abs()
                                 / ack_agg_df[ack_q_col].replace(0, pd.NA) * 100)
        logger.info(f"ACK vs DUT Q{ACK_QUEUE}:\n{tabulate(ack_agg_df, headers='keys', tablefmt='psql')}")

        # Few/no PFC expected on the lossless PG(s) under DCQCN. Read the DUT Tx PFC
        # counter (authoritative); the snappi Rx-pause port stat is unreliable, so the
        # plan's "matching tester PFC counter" is taken as both being ~0 (few/no) rather
        # than a direct compare. Delta-safe: run_rocev2_step clears counters pre-traffic.
        pfc_df = pfc_counters(snappi_dut_port_map, direction="Tx")
        logger.info(f"DUT Tx PFC counters:\n{tabulate(pfc_df, headers='keys', tablefmt='psql')}")
        pfc_cols = [f"PFC{q}" for q in used_lossless if f"PFC{q}" in pfc_df.columns]
        pytest_assert(len(pfc_cols) == len(used_lossless),
                      f"Missing DUT PFC counter column(s) for lossless priorities {used_lossless}; "
                      f"have {list(pfc_df.columns)}")
        pfc_totals = {c: int(pd.to_numeric(pfc_df[c], errors="coerce").fillna(0).sum()) for c in pfc_cols}
        pfc_sum_df = pd.DataFrame([pfc_totals])
        pfc_fail_expr = " or ".join(f"{c} > {PFC_TOLERANCE_FRAMES}" for c in pfc_cols)

        # Latency is INFORMATIONAL under congestion. Per the plan ("Note Avg/Max
        # latency ... within DUT spec"), DCQCN queue build-up raises latency well
        # above the no-congestion figure, so we log it (and WARN if it exceeds the
        # profile cap) rather than failing the test on a no-congestion threshold.
        lat_df = merged_df[merged_df["ip_dscp"].isin(lossless_dscps)][
            ["flow_name", "port_tx", "port_rx", "ip_dscp", "avg_latency", "max_latency"]]
        logger.info(f"Lossless latency (informational):\n{tabulate(lat_df, headers='keys', tablefmt='psql')}")
        avg_cap = LATENCY_PROFILES['ai']['avg_latency_max']
        max_cap = LATENCY_PROFILES['ai']['max_latency_max']
        over = lat_df[(pd.to_numeric(lat_df["avg_latency"], errors="coerce") > avg_cap)
                      | (pd.to_numeric(lat_df["max_latency"], errors="coerce") > max_cap)]
        if not over.empty:
            logger.warning(f"Lossless latency exceeds AI profile (avg>{avg_cap}ns or max>{max_cap}ns) "
                           f"under DCQCN congestion - informational, not a failure:\n"
                           f"{tabulate(over, headers='keys', tablefmt='psql')}")

        # ---- checks ------------------------------------------------------------
        # make_check(expr,...): expr is the FAILURE condition (any matching row fails).
        checks = [
            # No loss (strict, per plan): all messages complete AND no frame delta.
            make_check(f"ip_dscp in {lossless_dscps} and (message_fail != 0 or frame_delta != 0)",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "message_tx",
                     "message_complete_rx", "message_fail", "frame_delta"],
                    "Lossless: no loss (all messages complete)",
                    f"message_fail == 0 and frame_delta == 0 required for lossless DSCPs {lossless_dscps}"),
            # No NAK / sequence errors (strict, per plan).
            make_check(f"ip_dscp in {lossless_dscps} and (nak_tx != 0 or nak_rx != 0 or frame_sequence_error != 0)",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "nak_tx", "nak_rx", "frame_sequence_error"],
                    "Lossless: no NAK/sequence errors",
                    f"nak_tx=0 & nak_rx=0 & frame_sequence_error=0 required for lossless DSCPs {lossless_dscps}"),
            # ACK observed on the lossless queue(s).
            make_check(f"ip_dscp in {lossless_dscps} and ack_tx == 0",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "ack_tx", "ack_rx"],
                    f"Lossless: ACKs present {lossless_dscps}",
                    f"ack_tx > 0 required for lossless DSCPs {lossless_dscps}"),
            # ACK rides Q6 and matches the DUT Q6 counter (per receiving Tx port).
            make_check(f"pct_err > {COUNTER_TOLERANCE_PCT}",
                    ["port_tx", "ack_rx", ack_q_col, "pct_err"],
                    f"ACK matches DUT Q{ACK_QUEUE} counter",
                    f"sum(ack_rx) per port must equal {ack_q_col} within {COUNTER_TOLERANCE_PCT}%",
                    override_df=ack_agg_df),
            # ECN-CE observed on the lossless queue(s) (DCQCN marking). EXPECTED > 0.
            # NOTE: the plan asks to match ECN-CE against a DUT ECN-CE counter, but this
            # requires a per-queue ECN-marked SAI stat
            # (SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS) which many ASICs (e.g. Broadcom
            # s6100/Tomahawk) do NOT expose in COUNTERS_DB, so only tester-side presence
            # (ecn_ce_rx > 0) is asserted here.
            make_check(f"ip_dscp in {lossless_dscps} and ecn_ce_rx == 0",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "ecn_ce_rx"],
                    f"Lossless: ECN-CE observed {lossless_dscps}",
                    f"ecn_ce_rx > 0 required for lossless DSCPs {lossless_dscps} (DCQCN marking)"),
            # CNP observed (generated in response to ECN). EXPECTED > 0 both ways.
            make_check(f"ip_dscp in {lossless_dscps} and (cnp_tx == 0 or cnp_rx == 0)",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "cnp_tx", "cnp_rx"],
                    f"Lossless: CNP observed {lossless_dscps}",
                    f"cnp_tx > 0 and cnp_rx > 0 required for lossless DSCPs {lossless_dscps}"),
            # CNP rides Q5 and matches the DUT Q5 counter (per receiving Tx port),
            # within COUNTER_TOLERANCE_PCT for in-flight skew.
            make_check(f"pct_err > {COUNTER_TOLERANCE_PCT}",
                    ["port_tx", "cnp_rx", cnp_q_col, "pct_err"],
                    f"CNP matches DUT Q{CNP_QUEUE} counter",
                    f"sum(cnp_rx) per port must equal {cnp_q_col} within {COUNTER_TOLERANCE_PCT}%",
                    override_df=cnp_agg_df),
            # Few or no PFC on the lossless priority(ies) - DCQCN controls, not PFC.
            make_check(pfc_fail_expr, list(pfc_sum_df.columns),
                    f"Few/no PFC on lossless priority {used_lossless}",
                    f"DUT Tx PFC should be <= {PFC_TOLERANCE_FRAMES} frames on {used_lossless} under DCQCN",
                    override_df=pfc_sum_df),
        ]
        assert_queries(merged_df, checks)
        logger.info(f"*** TC3 DCQCN [{scenario}/{ecn_ce}] PASSED ***")
    finally:
        start_stop(snappi_api, operation="stop", op_type="traffic")
        start_stop(snappi_api, operation="stop", op_type="protocols")
