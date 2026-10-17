# flake8: noqa: F403, F401, F405
"""
Test Case 4 - Congestion control for STORAGE RoCEv2 traffic (PFC vs DCQCN).

Objective:
    Validate congestion control for RoCEv2 storage workloads using PFC and
    ECN/CNP, comparing a PFC-controlled phase (DCQCN off) with a DCQCN-controlled
    phase (DCQCN on). Roles T0/T1/T2.

Topology:
    Test Topology 1 (single DUT, 4 TGEN ports), 3:1 incast (Rank0/1/2 -> Rank3),
    100% line rate. Lossless Q3/Q4, lossy Q0/Q1/Q2, CNP -> Q5, ACK/NAK -> Q6.
    DSCPs come from the DUT DSCP->TC map (random pick when several map to a queue).
    Storage profile: 1 MB messages, 4K IB MTU. Data is ECT in BOTH phases.

Parametrized:
    mode     - "pfc"   : DCQCN off -> sender ignores CNP, congestion handled by PFC.
               "dcqcn" : DCQCN on  -> sender rate-reacts to CNP, PFC minimal.
    scenario - "q3_single" (both lossless ranks on Q3) / "q3q4_dual" (Q3 + Q4).

Expected results (per the test plan) -> encoded as checks:
    Both modes: all messages complete, no loss (message_fail==0 & frame_delta==0),
                no NAK/sequence errors; ACK present + matching DUT Q6; ECN-CE
                present; CNP present + matching DUT Q5; latency logged (not asserted).
    pfc mode  : PFC observed on the lossless queue(s) (DUT Tx PFC > 0).
    dcqcn mode: few/no PFC on the lossless queue(s) (DUT Tx PFC <= tolerance).

Traffic is duration-based (sustained 100% incast) rather than the plan's fixed 4 GB
per rank pair - 4 GB is a small fraction of the run window at line rate.

NOTE: ECN-CE is asserted as present only; many ASICs (e.g. Broadcom s6100/Tomahawk)
don't expose a per-queue ECN-marked SAI stat, so there is no DUT counter to match.
"""
import pytest
import logging

from snappi_tests.rocev2.files.helper import *   # lib + re-exported fixtures

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]

TRAFFIC_DURATION = 180      # seconds (duration-based; see module docstring)
LOSSY_QUEUES = [0, 1]
ACK_QUEUE = 6              # ACK/NAK control queue (per plan)
CNP_QUEUE = 5              # CNP control queue; its DSCP comes from the DUT DSCP->TC map
LINE_RATE_PCT = 100        # % - each Tx sends at full rate to create the incast
COUNTER_TOLERANCE_PCT = 2  # CNP/ACK vs DUT counter skew allowed (in-flight at stop)
PFC_TOLERANCE_FRAMES = 100  # "few or no" PFC under DCQCN
RATE_SAMPLE_START = 12

# (lossless_queue, message_size_mb) per rank, cycled across lossless Tx ports.
STORAGE_SCENARIOS = {
    "q3_single": [(3, 1)],
    "q3q4_dual": [(3, 1), (4, 1)],
}


def _conn(ack_nak_q, ecn_value, priority_to_dscp):
    return {
        "choice": "reliable_connection",
        "reliable_connection": {
            "ack": {"ip_dscp": priority_to_dscp[ack_nak_q], "ecn_value": ecn_value},
            "nak": {"ip_dscp": priority_to_dscp[ack_nak_q], "ecn_value": ecn_value},
            "enable_retransmission_timeout": True,
            "retransmission_timeout_value": 5000,
            "retransmission_retry_count": 254,
        },
    }


@pytest.mark.parametrize("scenario", list(STORAGE_SCENARIOS), ids=list(STORAGE_SCENARIOS))
@pytest.mark.parametrize("mode", ["pfc", "dcqcn"])
def test_rocev2_storage_congestion(
                                    request,
                                    snappi_api,
                                    conn_graph_facts,
                                    fanout_graph_facts_multidut,
                                    get_snappi_ports,
                                    duthosts,
                                    prio_dscp_map,
                                    mode,
                                    scenario,
                                ):
    """
    Storage 3:1 incast, ECT data in both phases. pfc mode: DCQCN off -> PFC controls;
    dcqcn mode: DCQCN on -> few PFC. Both: no loss/NAK, ACK/ECN-CE/CNP observed.
    """
    snappi_port_list = get_snappi_ports
    pytest_require(len(snappi_port_list) >= 4, "Need minimum of 4 ports")

    tconfig, plist, sports = snappi_dut_base_config(duthosts, snappi_port_list, snappi_api)
    snappi_dut_port_map = snappi_dut_port_mapping(sports)
    port_ids = [pc.id for pc in plist]
    priority_to_dscp = derive_priority_to_dscp(prio_dscp_map)
    lossless_spec = STORAGE_SCENARIOS[scenario]

    dcqcn_on = (mode == "dcqcn")
    ecn = "ect_1"   # ECT in BOTH phases; mode only toggles DCQCN (sender rate reaction)
    port_cfg = {"transmit_type": "target_line_rate", "target_line_rate": LINE_RATE_PCT}
    cnp_dscp = priority_to_dscp[CNP_QUEUE]
    logger.info(f"CNP on queue {CNP_QUEUE} -> DSCP {cnp_dscp} (from DUT DSCP->TC map)")
    cnp_cfg = {"ip_dscp": cnp_dscp, "ecn_value": ecn}

    def lossless_cfg(q, size_mb):
        return {
            "mtu": 5000,
            "qp_configs": [{"message_size_unit": "mb", "message_size": size_mb,
                            "dscp": priority_to_dscp[q], "ecn": ecn}],
            "cnp": cnp_cfg,
            "dcqcn_settings": {"enable_dcqcn": dcqcn_on},
            "connection_type": _conn(ACK_QUEUE, ecn, priority_to_dscp),   # ACK/NAK on Q6
            "rocev2_port_config": port_cfg,
        }

    lossy_cfg = {
        "mtu": 5000,
        "qp_configs": [{"message_size_unit": "mb", "message_size": 1,
                        "dscp": priority_to_dscp[q], "ecn": ecn} for q in LOSSY_QUEUES],
        "cnp": cnp_cfg,
        "dcqcn_settings": {"enable_dcqcn": dcqcn_on},
        "connection_type": _conn(ACK_QUEUE, ecn, priority_to_dscp),
        "rocev2_port_config": port_cfg,
    }

    topology, rx, last_tx, used = build_incast_topology(port_ids, lossless_cfg, lossless_spec, lossy_cfg)
    used_lossless = sorted({q for q, _ in used})
    lossless_dscps = [priority_to_dscp[q] for q in used_lossless]
    lossy_dscps = [priority_to_dscp[q] for q in LOSSY_QUEUES]
    logger.info(f"[{mode}/{scenario}] storage incast rx={rx} last_tx={last_tx} "
                f"lossless_qs={used_lossless}\n{topology}")

    # ---- run summary banner (attributes every stats table below to its config) ----
    logger.info(
        "\n===== TC4 storage congestion run summary =====\n"
        f"  mode            : {mode}  (DCQCN {'ON' if dcqcn_on else 'OFF'})\n"
        f"  scenario        : {scenario}\n"
        f"  incast          : 3:1  (rx=Port {rx}, senders -> last_tx=Port {last_tx})\n"
        f"  data ECN        : {ecn}  (ECT in both phases)\n"
        f"  line rate       : {LINE_RATE_PCT}%   duration: {TRAFFIC_DURATION}s\n"
        f"  lossless queues : {used_lossless} -> DSCPs {lossless_dscps}\n"
        f"  lossy queues    : {LOSSY_QUEUES} -> DSCPs {lossy_dscps}\n"
        f"  CNP queue       : {CNP_QUEUE} -> DSCP {cnp_dscp}\n"
        f"  ACK/NAK queue   : {ACK_QUEUE} -> DSCP {priority_to_dscp[ACK_QUEUE]}\n"
        f"  PFC expectation : {'few/no PFC (<= %d)' % PFC_TOLERANCE_FRAMES if dcqcn_on else 'PFC present (> 0)'} "
        f"on {used_lossless}\n"
        "=============================================="
    )

    try:
        qids = [f"UC{q}" for q in used_lossless + LOSSY_QUEUES + [ACK_QUEUE, CNP_QUEUE]]
        merged_df, _, dut_queue_df, _, _ = collect_flow_queue_stats(
            snappi_api=snappi_api, duthosts=duthosts, plist=plist, tconfig=tconfig,
            snappi_dut_port_map=snappi_dut_port_map, topology=topology,
            prio_dscp_map=prio_dscp_map, queue_ids=qids, traffic_duration=TRAFFIC_DURATION,
            sample_start=RATE_SAMPLE_START, config_name=request.node.name)

        cnp_q_col = f"UC{CNP_QUEUE} totalpacket"
        ack_q_col = f"UC{ACK_QUEUE} totalpacket"

        # CNP rides Q5 toward the senders; sum cnp_rx per port_tx and match UC5.
        cnp_agg_df = merged_df.groupby("port_tx", as_index=False)["cnp_rx"].sum()
        cnp_agg_df[cnp_q_col] = cnp_agg_df["port_tx"].map(dut_queue_df.set_index("snappi_port")[cnp_q_col])
        cnp_agg_df["pct_err"] = ((cnp_agg_df["cnp_rx"] - cnp_agg_df[cnp_q_col]).abs()
                                 / cnp_agg_df[cnp_q_col].replace(0, pd.NA) * 100)
        logger.info(f"CNP vs DUT Q{CNP_QUEUE}:\n{tabulate(cnp_agg_df, headers='keys', tablefmt='psql')}")

        # ACK rides Q6 toward the senders; sum ack_rx per port_tx and match UC6.
        ack_agg_df = merged_df.groupby("port_tx", as_index=False)["ack_rx"].sum()
        ack_agg_df[ack_q_col] = ack_agg_df["port_tx"].map(dut_queue_df.set_index("snappi_port")[ack_q_col])
        ack_agg_df["pct_err"] = ((ack_agg_df["ack_rx"] - ack_agg_df[ack_q_col]).abs()
                                 / ack_agg_df[ack_q_col].replace(0, pd.NA) * 100)
        logger.info(f"ACK vs DUT Q{ACK_QUEUE}:\n{tabulate(ack_agg_df, headers='keys', tablefmt='psql')}")

        # PFC from the authoritative DUT Tx counter (snappi Rx-pause stat unreliable).
        # Delta-safe: run_rocev2_step clears pfc/queue counters before traffic.
        pfc_df = pfc_counters(snappi_dut_port_map, direction="Tx")
        logger.info(f"DUT Tx PFC counters:\n{tabulate(pfc_df, headers='keys', tablefmt='psql')}")
        pfc_cols = [f"PFC{q}" for q in used_lossless if f"PFC{q}" in pfc_df.columns]
        pytest_assert(len(pfc_cols) == len(used_lossless),
                      f"Missing DUT PFC counter column(s) for lossless priorities {used_lossless}; "
                      f"have {list(pfc_df.columns)}")
        pfc_totals = {c: int(pd.to_numeric(pfc_df[c], errors="coerce").fillna(0).sum()) for c in pfc_cols}
        pfc_sum_df = pd.DataFrame([pfc_totals])

        # Latency informational (log + WARN), not asserted - congestion queuing raises it.
        lat_df = merged_df[merged_df["ip_dscp"].isin(lossless_dscps)][
            ["flow_name", "port_tx", "port_rx", "ip_dscp", "avg_latency", "max_latency"]]
        logger.info(f"Lossless latency (informational):\n{tabulate(lat_df, headers='keys', tablefmt='psql')}")
        avg_cap = LATENCY_PROFILES['storage']['avg_latency_max']
        max_cap = LATENCY_PROFILES['storage']['max_latency_max']
        over = lat_df[(pd.to_numeric(lat_df["avg_latency"], errors="coerce") > avg_cap)
                      | (pd.to_numeric(lat_df["max_latency"], errors="coerce") > max_cap)]
        if not over.empty:
            logger.warning(f"Lossless latency exceeds storage profile (avg>{avg_cap}ns or max>{max_cap}ns):\n"
                           f"{tabulate(over, headers='keys', tablefmt='psql')}")

        # ---- checks: common to both modes ----
        checks = [
            make_check(f"ip_dscp in {lossless_dscps} and (message_fail != 0 or frame_delta != 0)",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "message_tx",
                     "message_complete_rx", "message_fail", "frame_delta"],
                    "Lossless: no loss (all messages complete)",
                    f"message_fail == 0 and frame_delta == 0 required for lossless DSCPs {lossless_dscps}"),
            make_check(f"ip_dscp in {lossless_dscps} and (nak_tx != 0 or nak_rx != 0 or frame_sequence_error != 0)",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "nak_tx", "nak_rx", "frame_sequence_error"],
                    "Lossless: no NAK/sequence errors",
                    f"nak_tx=0 & nak_rx=0 & frame_sequence_error=0 required for lossless DSCPs {lossless_dscps}"),
            make_check(f"ip_dscp in {lossless_dscps} and ack_tx == 0",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "ack_tx", "ack_rx"],
                    f"Lossless: ACKs present {lossless_dscps}",
                    f"ack_tx > 0 required for lossless DSCPs {lossless_dscps}"),
            make_check(f"pct_err > {COUNTER_TOLERANCE_PCT}",
                    ["port_tx", "ack_rx", ack_q_col, "pct_err"],
                    f"ACK matches DUT Q{ACK_QUEUE} counter",
                    f"sum(ack_rx) per port must equal {ack_q_col} within {COUNTER_TOLERANCE_PCT}%",
                    override_df=ack_agg_df),
            # ECN-CE present (presence-only; DUT exposes no per-queue ECN-marked stat - see NOTE).
            make_check(f"ip_dscp in {lossless_dscps} and ecn_ce_rx == 0",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "ecn_ce_rx"],
                    f"Lossless: ECN-CE observed {lossless_dscps}",
                    f"ecn_ce_rx > 0 required for lossless DSCPs {lossless_dscps}"),
            make_check(f"ip_dscp in {lossless_dscps} and (cnp_tx == 0 or cnp_rx == 0)",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "cnp_tx", "cnp_rx"],
                    f"Lossless: CNP observed {lossless_dscps}",
                    f"cnp_tx > 0 and cnp_rx > 0 required for lossless DSCPs {lossless_dscps}"),
            make_check(f"pct_err > {COUNTER_TOLERANCE_PCT}",
                    ["port_tx", "cnp_rx", cnp_q_col, "pct_err"],
                    f"CNP matches DUT Q{CNP_QUEUE} counter",
                    f"sum(cnp_rx) per port must equal {cnp_q_col} within {COUNTER_TOLERANCE_PCT}%",
                    override_df=cnp_agg_df),
        ]

        # ---- mode-specific PFC expectation ----
        if dcqcn_on:
            pfc_fail_expr = " or ".join(f"{c} > {PFC_TOLERANCE_FRAMES}" for c in pfc_cols)
            checks.append(make_check(pfc_fail_expr, list(pfc_sum_df.columns),
                    f"Few/no PFC on lossless priority {used_lossless} (DCQCN)",
                    f"DUT Tx PFC should be <= {PFC_TOLERANCE_FRAMES} on {used_lossless} under DCQCN",
                    override_df=pfc_sum_df))
        else:
            pfc_fail_expr = " or ".join(f"{c} == 0" for c in pfc_cols)
            checks.append(make_check(pfc_fail_expr, list(pfc_sum_df.columns),
                    f"PFC present on lossless priority {used_lossless} (PFC mode)",
                    f"DUT Tx PFC expected (> 0) on {used_lossless} with DCQCN off",
                    override_df=pfc_sum_df))

        assert_queries(merged_df, checks)
        logger.info(f"*** TC4 storage congestion [{mode}/{scenario}] PASSED ***")
    finally:
        start_stop(snappi_api, operation="stop", op_type="traffic")
        start_stop(snappi_api, operation="stop", op_type="protocols")
