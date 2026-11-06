# flake8: noqa: F403, F401, F405
"""
Test Case 6 - QP / rank fairness with DCQCN - v2 style.

Objective:
    Validate fair bandwidth distribution between QPs/ranks under DCQCN congestion
    control. Multiple Tx ranks send to a single Rx (N:1 incast) at 100% line rate
    with DCQCN enabled; the per-rank achieved rate must be fair.

Topology:
    Test Topology 1 (single DUT). Unidirectional N:1 incast, every Tx is a
    lossless rank (no lossy last-Tx here - the test is about lossless QP
    fairness). DCQCN enabled, ECT data, CNP -> queue 5.

Scenarios (parametrized):
    single_q3  - every rank on Q3 (shared queue -> QP fairness within a queue).
    dual_q3q4  - ranks split across Q3/Q4 (per-queue, cross-rank fairness).
ECN-CE bit (parametrized): ect_0 / ect_1.

Expected results (per the test plan) -> encoded as checks:
    * Zero unrecovered loss; sequence errors within tolerance (recovered).
    * Few or no PFC (DCQCN, not PFC, controls).
    * ECN-CE and CNP observed on the lossless queue(s); CNP matches DUT Q5.
    * Tx rate of the ranks is FAIR: deviation < 30%.
"""
import pytest
import logging

from snappi_tests.rocev2.files.helper import *   # lib + re-exported fixtures

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]

TRAFFIC_DURATION = 180     # seconds (plan: run traffic for 3 minutes)
CNP_QUEUE = 5              # CNP control queue; its DSCP comes from the DUT DSCP->TC map
LINE_RATE_PCT = 100
COUNTER_TOLERANCE_PCT = 2
PFC_TOLERANCE_FRAMES = 100
SEQ_ERR_TOLERANCE_PCT = 1.0
FAIRNESS_DEVIATION_PCT = 30   # spec: rank rates fair within 30%
RATE_SAMPLE_START = 12        # sample after DCQCN converges

# 1MB messages (AI/QP-fairness workload). One (queue, size_mb) per rank, cycled.
FAIRNESS_SCENARIOS = {
    "single_q3": [(3, 1)],
    "dual_q3q4": [(3, 1), (4, 1)],
}


def _conn(q, ecn_value, priority_to_dscp):
    return {
        "choice": "reliable_connection",
        "reliable_connection": {
            "ack": {"ip_dscp": priority_to_dscp[q], "ecn_value": ecn_value},
            "nak": {"ip_dscp": priority_to_dscp[q], "ecn_value": ecn_value},
            "enable_retransmission_timeout": True,
            "retransmission_timeout_value": 40,
        },
    }


@pytest.mark.parametrize("scenario", list(FAIRNESS_SCENARIOS), ids=list(FAIRNESS_SCENARIOS))
@pytest.mark.parametrize("ecn_ce", ["ect_0", "ect_1"])
def test_rocev2_qp_fairness_dcqcn(
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
    N:1 incast, all lossless ranks, DCQCN on. Validate DCQCN keeps the queues
    loss-free (recovered transients only) and shares bandwidth fairly across the
    ranks (deviation < FAIRNESS_DEVIATION_PCT).
    """
    snappi_port_list = get_snappi_ports
    pytest_require(len(snappi_port_list) >= 4, "Need minimum of 4 ports")

    tconfig, plist, sports = snappi_dut_base_config(duthosts, snappi_port_list, snappi_api)
    snappi_dut_port_map = snappi_dut_port_mapping(sports)
    port_ids = [pc.id for pc in plist]
    priority_to_dscp = derive_priority_to_dscp(prio_dscp_map)
    lossless_spec = FAIRNESS_SCENARIOS[scenario]

    port_cfg = {"transmit_type": "target_line_rate", "target_line_rate": LINE_RATE_PCT}
    cnp_dscp = priority_to_dscp[CNP_QUEUE]
    logger.info(f"CNP on queue {CNP_QUEUE} -> DSCP {cnp_dscp} (from DUT DSCP->TC map)")
    cnp_cfg = {"ip_dscp": cnp_dscp, "ecn_value": ecn_ce}

    def lossless_cfg(q, size_mb):
        return {
            "mtu": 5000,
            "qp_configs": [{"message_size_unit": "mb", "message_size": size_mb,
                            "dscp": priority_to_dscp[q], "ecn": ecn_ce}],
            "cnp": cnp_cfg,
            "dcqcn_settings": {"enable_dcqcn": True},
            "connection_type": _conn(q, ecn_ce, priority_to_dscp),
            "rocev2_port_config": port_cfg,
        }

    # All Tx are lossless ranks (lossy_cfg=None); pick one Rx, rest are senders.
    topology, rx, _, used = build_incast_topology(port_ids, lossless_cfg, lossless_spec, lossy_cfg=None)
    used_lossless = sorted({q for q, _ in used})
    lossless_dscps = [priority_to_dscp[q] for q in used_lossless]
    logger.info(f"[{scenario}/{ecn_ce}] fairness incast rx={rx} lossless_qs={used_lossless}\n{topology}")

    # ---- run summary banner (attributes every stats table below to its config) ----
    n_senders = len(port_ids) - 1
    logger.info(
        "\n===== TC6 QP fairness (DCQCN) run summary =====\n"
        f"  mode            : dcqcn  (DCQCN ON)\n"
        f"  scenario        : {scenario}\n"
        f"  incast          : {n_senders}:1  (rx=Port {rx}, all senders lossless ranks)\n"
        f"  data ECN        : {ecn_ce}\n"
        f"  line rate       : {LINE_RATE_PCT}%   duration: {TRAFFIC_DURATION}s\n"
        f"  lossless queues : {used_lossless} -> DSCPs {lossless_dscps}\n"
        f"  CNP queue       : {CNP_QUEUE} -> DSCP {cnp_dscp}\n"
        f"  fairness spec   : rank rate deviation <= {FAIRNESS_DEVIATION_PCT}%\n"
        "==============================================="
    )

    qids = [f"UC{q}" for q in used_lossless + [CNP_QUEUE]]
    merged_df, flow_df, dut_queue_df, sched_df, port_stats_df = collect_flow_queue_stats(
        snappi_api=snappi_api, duthosts=duthosts, plist=plist, tconfig=tconfig,
        snappi_dut_port_map=snappi_dut_port_map, topology=topology,
        prio_dscp_map=prio_dscp_map, queue_ids=qids, traffic_duration=TRAFFIC_DURATION,
        sample_start=RATE_SAMPLE_START, config_name=request.node.name)

    cnp_q_col = f"UC{CNP_QUEUE} totalpacket"

    merged_df["seq_err_pct"] = (
        pd.to_numeric(merged_df["frame_sequence_error"], errors="coerce")
        / pd.to_numeric(merged_df["data_frames_rx"], errors="coerce").replace(0, pd.NA) * 100)

    # Per-rank fairness (rank == sending port).
    fair_summary, per_rank = build_rank_fairness(merged_df, dsps=lossless_dscps, by="port_tx")
    logger.info(f"Per-rank rate:\n{tabulate(per_rank, headers='keys', tablefmt='psql')}")
    logger.info(f"Rank fairness:\n{tabulate(fair_summary, headers='keys', tablefmt='psql')}")

    # CNP vs DUT Q5 (delivered to senders).
    cnp_agg_df = merged_df.groupby("port_tx", as_index=False)["cnp_rx"].sum()
    cnp_agg_df[cnp_q_col] = cnp_agg_df["port_tx"].map(dut_queue_df.set_index("snappi_port")[cnp_q_col])
    cnp_agg_df["pct_err"] = ((cnp_agg_df["cnp_rx"] - cnp_agg_df[cnp_q_col]).abs()
                             / cnp_agg_df[cnp_q_col].replace(0, pd.NA) * 100)

    # PFC few/no on the lossless priorities - read from the authoritative DUT Tx
    # PFC counter (the snappi Rx-pause port stat is unreliable on IxNetwork).
    pfc_df = pfc_counters(snappi_dut_port_map, direction="Tx")
    logger.info(f"DUT Tx PFC counters:\n{tabulate(pfc_df, headers='keys', tablefmt='psql')}")
    pfc_cols = [f"PFC{q}" for q in used_lossless if f"PFC{q}" in pfc_df.columns]
    pytest_assert(len(pfc_cols) == len(used_lossless),
                  f"Missing DUT PFC counter column(s) for lossless priorities {used_lossless}; "
                  f"have {list(pfc_df.columns)}")
    pfc_totals = {c: int(pd.to_numeric(pfc_df[c], errors="coerce").fillna(0).sum()) for c in pfc_cols}
    pfc_sum_df = pd.DataFrame([pfc_totals])
    pfc_fail_expr = " or ".join(f"{c} > {PFC_TOLERANCE_FRAMES}" for c in pfc_cols)
    # ---- checks ------------------------------------------------------------
    checks = [
        make_check(f"ip_dscp in {lossless_dscps} and message_fail != 0",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "message_fail", "frame_delta"],
                "Lossless: no unrecovered loss",
                f"message_fail == 0 required for lossless DSCPs {lossless_dscps}"),
        make_check(f"ip_dscp in {lossless_dscps} and seq_err_pct > {SEQ_ERR_TOLERANCE_PCT}",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "frame_sequence_error", "data_frames_rx", "seq_err_pct"],
                "Lossless: sequence errors within tolerance",
                f"frame_sequence_error must be <= {SEQ_ERR_TOLERANCE_PCT}% of rx frames {lossless_dscps}"),
        # ACK present and consistent on the tester (ack rides the data queue here, so
        # there is no separate ACK-queue counter to match - verify tester tx == rx).
        make_check(f"ip_dscp in {lossless_dscps} and (ack_tx == 0 or ack_rx != ack_tx)",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "ack_tx", "ack_rx"],
                f"Lossless: ACK present and consistent {lossless_dscps}",
                f"ack_tx > 0 and ack_rx == ack_tx required for lossless DSCPs {lossless_dscps}"),
        make_check(f"ip_dscp in {lossless_dscps} and ecn_ce_rx == 0",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "ecn_ce_rx"],
                f"Lossless: ECN-CE observed {lossless_dscps}",
                f"ecn_ce_rx > 0 required for lossless DSCPs {lossless_dscps} (DCQCN)"),
        make_check(f"ip_dscp in {lossless_dscps} and (cnp_tx == 0 or cnp_rx == 0)",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "cnp_tx", "cnp_rx"],
                f"Lossless: CNP observed {lossless_dscps}",
                f"cnp_tx > 0 and cnp_rx > 0 required for lossless DSCPs {lossless_dscps}"),
        make_check(f"pct_err > {COUNTER_TOLERANCE_PCT}",
                ["port_tx", "cnp_rx", cnp_q_col, "pct_err"],
                f"CNP matches DUT Q{CNP_QUEUE} counter",
                f"sum(cnp_rx) per port must equal {cnp_q_col} within {COUNTER_TOLERANCE_PCT}%",
                override_df=cnp_agg_df),
        make_check(pfc_fail_expr, list(pfc_sum_df.columns),
                f"Few/no PFC on lossless priority {used_lossless} (DCQCN)",
                f"DUT Tx PFC should be <= {PFC_TOLERANCE_FRAMES} on {used_lossless} under DCQCN",
                override_df=pfc_sum_df),
        # The headline check: rank rates fair within FAIRNESS_DEVIATION_PCT.
        make_check(f"deviation_pct > {FAIRNESS_DEVIATION_PCT}",
                ["n_ranks", "min_rate", "max_rate", "mean_rate", "deviation_pct"],
                "QP/rank rate fairness",
                f"rank rate deviation must be <= {FAIRNESS_DEVIATION_PCT}%",
                override_df=fair_summary),
    ]
    assert_queries(merged_df, checks)
    logger.info(f"*** TC6 QP fairness DCQCN [{scenario}/{ecn_ce}] PASSED ***")
