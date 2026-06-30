# flake8: noqa: F403, F401, F405
"""
PFC congestion (incast) - all scenarios in one parametrized test.

Unidirectional N:1 incast: every Tx port sends to a single Rx port at 100% line
rate (no compute_tx_rates_single_rx), oversubscribing the Rx egress to trigger
PFC on the lossless queues. The LAST Tx port drives the lossy queues (0/1);
the other Tx ports drive the lossless queue(s) defined by the scenario. ACK/NAK
ride the common ACK queue (Q6) for all flows; CNP -> Q5.

The three original cases are folded into one parametrized test:
    q3_single  - lossless Tx all on Q3 (128KB)            [TC2 Step 4]
    q3q4_same  - lossless Tx split Q3/Q4, both 128KB      [TC2 Step 6]
    q3q4_mixed - lossless Tx split Q3=128KB / Q4=4KB      [TC2 Step 8]

All plumbing lives in files/helper.py; this file carries only the
queue/priority intent, the (incast) topology, and the checks.
"""
import pytest
import logging

from snappi_tests.rocev2.files.helper import *   # lib + re-exported fixtures

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]

TRAFFIC_DURATION = 20      # seconds
LOSSY_QUEUES = [0, 1]
ACK_QUEUE = 6              # common queue carrying ACK/NAK for all (lossless + lossy) flows
CNP_QUEUE = 5              # CNP on DSCP 46 (queue 5) per DUT mapping
LINE_RATE = 100           # % - each Tx sends at full rate to create the incast
RATE_TOLERANCE_PCT = 5

# Each scenario = the (lossless_queue, message_size_kb) options assigned
# round-robin to the lossless Tx ports. The last Tx always drives LOSSY_QUEUES.
PFC_SCENARIOS = {
    "q3_single":  [(3, 128)],
    "q3q4_same":  [(3, 128), (4, 128)],
    "q3q4_mixed": [(3, 128), (4, 4)],
}


def _conn(ack_nak_q, priority_to_dscp):
    return {
        "choice": "reliable_connection",
        "reliable_connection": {
            "ack": {"ip_dscp": priority_to_dscp[ack_nak_q], "ecn_value": "non_ect"},
            "nak": {"ip_dscp": priority_to_dscp[ack_nak_q], "ecn_value": "non_ect"},
            "enable_retransmission_timeout": True,
            "retransmission_timeout_value": 5000,
            "retransmission_retry_count": 254
        },
    }


@pytest.mark.parametrize("scenario", list(PFC_SCENARIOS), ids=list(PFC_SCENARIOS))
def test_rocev2_pfc_congestion_ai(
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
    N:1 incast at 100% line rate. Lossless queues must be protected by PFC
    (no loss, no NAK, ACKs present, no ECN-CE/CNP, PFC pause observed); the
    last Tx's lossy queues are unprotected. DWRR weights govern the Rx-egress
    rate split (validated per queue, since several Tx may share a queue).
    """
    snappi_port_list = get_snappi_ports
    pytest_require(len(snappi_port_list) >= 4, "Need minimum of 4 ports")

    tconfig, plist, sports = snappi_dut_base_config(duthosts, snappi_port_list, snappi_api)
    snappi_dut_port_map = snappi_dut_port_mapping(sports)
    port_ids = [pc.id for pc in plist]
    priority_to_dscp = derive_priority_to_dscp(prio_dscp_map)
    lossless_spec = PFC_SCENARIOS[scenario]

    port_cfg = {"transmit_type": "target_line_rate", "target_line_rate": LINE_RATE}
    cnp_cfg = {"ip_dscp": priority_to_dscp[CNP_QUEUE], "ecn_value": "non_ect"}

    def lossless_cfg(q, size_kb):
        return {
            "mtu": 5000,
            "qp_configs": [{"message_size_unit": "kb", "message_size": size_kb,
                            "dscp": priority_to_dscp[q]}],
            "cnp": cnp_cfg,
            "dcqcn_settings": {"enable_dcqcn": False},
            "connection_type": _conn(ACK_QUEUE, priority_to_dscp),   # ACK/NAK on the common ACK queue
            "rocev2_port_config": port_cfg,
        }

    lossy_cfg = {
        "mtu": 5000,
        "qp_configs": [{"message_size_unit": "kb", "message_size": 128,
                        "dscp": priority_to_dscp[q]} for q in LOSSY_QUEUES],
        "cnp": cnp_cfg,
        "dcqcn_settings": {"enable_dcqcn": False},
        "connection_type": _conn(ACK_QUEUE, priority_to_dscp),   # ACK/NAK on the common ACK queue
        "rocev2_port_config": port_cfg,
    }

    # One Rx, rest Tx; lossless Tx cycle the scenario spec, last Tx -> lossy.
    topology, rx, last_tx, used = build_incast_topology(
        port_ids, lossless_cfg, lossless_spec, lossy_cfg)
    used_lossless = sorted({q for q, _ in used})
    logger.info(f"[{scenario}] incast rx={rx} last_tx={last_tx} lossless_qs={used_lossless}\n{topology}")

    # Pure PFC test: WRED on the lossless queue DROPS non-ECT traffic before PFC
    # engages. Disable WRED on ALL test ports, for ONLY the queues this test uses,
    # so congestion drives PFC pause. Always restored in finally.
    queues_used = used_lossless + LOSSY_QUEUES + [ACK_QUEUE, CNP_QUEUE]
    wred_saved = disable_wred(snappi_dut_port_map, queues_used)
    try:
        # ---- run incast + collect DUT-side data (universal collector) ----------
        qids = [f"UC{q}" for q in queues_used]
        merged_df, flow_df, dut_queue_df, sched_df, port_stats_df = collect_flow_queue_stats(
            snappi_api=snappi_api, duthosts=duthosts, plist=plist, tconfig=tconfig,
            snappi_dut_port_map=snappi_dut_port_map, topology=topology,
            prio_dscp_map=prio_dscp_map, queue_ids=qids, traffic_duration=TRAFFIC_DURATION,
            config_name=request.node.name)

        # DWRR fairness per QUEUE (several Tx may share a lossless queue in incast).
        rate_check_df = build_rate_fairness_by_queue(merged_df)
        logger.info(f"DWRR rate fairness:\n{tabulate(rate_check_df, headers='keys', tablefmt='psql')}")

        lossless_dsps = [priority_to_dscp[q] for q in used_lossless]
        lossy_dsps = [priority_to_dscp[q] for q in LOSSY_QUEUES]

        # PFC pause expected on the lossless priority(ies). Measured from the DUT
        # Tx PFC counter (authoritative); the snappi Rx-pause port stat reads 0
        # even when PFC is demonstrably pacing the senders. One-row total across
        # the DUT interfaces so a single make_check asserts "PFC was generated".
        pfc_df = pfc_counters(snappi_dut_port_map, direction="Tx")
        logger.info(f"DUT Tx PFC counters:\n{tabulate(pfc_df, headers='keys', tablefmt='psql')}")
        pfc_cols = [f"PFC{q}" for q in used_lossless if f"PFC{q}" in pfc_df.columns]
        pfc_totals = {c: int(pd.to_numeric(pfc_df[c], errors="coerce").fillna(0).sum()) for c in pfc_cols}
        pfc_sum_df = pd.DataFrame([pfc_totals]) if pfc_totals else pd.DataFrame([{"PFC_none": 0}])
        pfc_fail_expr = " or ".join(f"{c} == 0" for c in pfc_cols) or "PFC_none == 0"

        # Lossy priorities are unprotected: the DUT must NOT generate PFC pause on
        # them (congestion drops them instead of pausing the sender).
        pfc_lossy_cols = [f"PFC{q}" for q in LOSSY_QUEUES if f"PFC{q}" in pfc_df.columns]
        pfc_lossy_totals = {c: int(pd.to_numeric(pfc_df[c], errors="coerce").fillna(0).sum())
                            for c in pfc_lossy_cols}
        pfc_lossy_df = pd.DataFrame([pfc_lossy_totals]) if pfc_lossy_totals else pd.DataFrame([{"PFC_none": 0}])
        pfc_lossy_fail_expr = " or ".join(f"{c} != 0" for c in pfc_lossy_cols) or "PFC_none != 0"

        # ---- checks --------------------------------------------------------
        # make_check(expr,...): expr is the FAILURE condition (any matching row fails).
        checks = [
            # Lossless queues must be PROTECTED by PFC: no loss ...
            make_check(f"ip_dscp in {lossless_dsps} and (message_fail != 0 or frame_delta != 0)",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "message_fail", "frame_delta"],
                    "Lossless: no loss (PFC protected)",
                    f"message_fail=0 & frame_delta=0 required for lossless DSCPs {lossless_dsps}"),
            # ... no NAK / sequence errors ...
            make_check(f"ip_dscp in {lossless_dsps} and (nak_tx != 0 or nak_rx != 0 or frame_sequence_error != 0)",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "nak_tx", "nak_rx", "frame_sequence_error"],
                    "Lossless: no NAK/sequence errors",
                    f"nak/seq must be 0 for lossless DSCPs {lossless_dsps}"),
            # ... ACKs present ...
            make_check(f"ip_dscp in {lossless_dsps} and ack_tx == 0",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "ack_tx", "ack_rx"],
                    f"Lossless: ACKs present {lossless_dsps}",
                    f"ack_tx > 0 required for lossless DSCPs {lossless_dsps}"),
            # ... no ECN-CE (PFC, not ECN, protects here) ...
            make_check(f"ip_dscp in {lossless_dsps} and ecn_ce_rx != 0",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "ecn_ce_rx"],
                    f"Lossless: no ECN-CE {lossless_dsps}",
                    f"ecn_ce_rx == 0 required for lossless DSCPs {lossless_dsps}"),
            # ... no CNP.
            make_check(f"ip_dscp in {lossless_dsps} and (cnp_tx != 0 or cnp_rx != 0)",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "cnp_tx", "cnp_rx"],
                    f"Lossless: no CNP {lossless_dsps}",
                    f"cnp_tx == 0 and cnp_rx == 0 required for lossless DSCPs {lossless_dsps}"),
            # PFC pause must be generated by the DUT on EVERY lossless priority.
            make_check(pfc_fail_expr, list(pfc_sum_df.columns),
                    f"DUT generated PFC on every lossless priority {used_lossless}",
                    f"DUT Tx PFC expected on EVERY lossless priority {used_lossless} under incast congestion",
                    override_df=pfc_sum_df),
            # Lossy priorities are unprotected: no PFC should be generated for them.
            make_check(pfc_lossy_fail_expr, list(pfc_lossy_df.columns),
                    f"No PFC on lossy priorities {LOSSY_QUEUES}",
                    f"DUT must NOT generate PFC on lossy priorities {LOSSY_QUEUES} (unprotected)",
                    override_df=pfc_lossy_df),
            # Lossy priorities are unprotected: under incast they SHOULD show loss/
            # failure (contrast with the lossless 0-loss guarantee). Fail if a lossy
            # flow saw no loss AND no failure (i.e. it was effectively protected).
            make_check(f"ip_dscp in {lossy_dsps} and message_fail == 0 and frame_delta == 0",
                    ["flow_name", "port_tx", "port_rx", "ip_dscp", "message_fail", "frame_delta", "data_frames_rx"],
                    f"Lossy: unprotected, shows loss {lossy_dsps}",
                    f"lossy DSCPs {lossy_dsps} expected to show loss/failure under incast (unprotected)"),
            # DWRR rate fairness at the Rx egress, per QUEUE (weight-proportional split).
            make_check(f"pct_err > {RATE_TOLERANCE_PCT}",
                    ["port_rx", "tc", "weight", "n_flows", "flows", "offered", "rx_rate", "expected_rate", "pct_err"],
                    "DWRR rate matches weight share (per queue)",
                    f"each queue's rate must be within {RATE_TOLERANCE_PCT}% of its weight-proportional expected rate",
                    override_df=rate_check_df),
        ]
        assert_queries(merged_df, checks)
        logger.info(f"*** PFC congestion incast [{scenario}] PASSED ***")
    finally:
        # restore_wred mutates DUT state and MUST run even if stopping traffic/
        # protocols throws, otherwise the lossless queues stay WRED-disabled for
        # every later test on this shared testbed.
        try:
            start_stop(snappi_api, operation="stop", op_type="protocols")
            start_stop(snappi_api, operation="stop", op_type="traffic")
        finally:
            restore_wred(wred_saved)
