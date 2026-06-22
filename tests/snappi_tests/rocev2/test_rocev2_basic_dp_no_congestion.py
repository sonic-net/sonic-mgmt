# flake8: noqa: F403, F401, F405
import pytest
import logging

from snappi_tests.rocev2.files.helper import *   # lib + re-exported fixtures

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]

TRAFFIC_DURATION = 60      # seconds

# ---- queue / priority intent (tune here) ----
LOSSLESS_QUEUES = [3, 4]        # one is picked at random per run
ACK_NAK_QUEUE = 6               # queue carrying ACK/NAK
LOSSY_QUEUES = [0, 1]           # lossy data queues driven from the last rank pair
CNP_QUEUE = 5                   # CNP control queue - kept out of LOSSY_QUEUES so lossy
#                                 data does not share a queue/DSCP with CNP



def test_rocev2_basic_dp_traffic_no_congestion(
                                    request,
                                    snappi_api,
                                    conn_graph_facts,
                                    fanout_graph_facts_multidut,
                                    get_snappi_ports,
                                    duthosts,
                                    prio_dscp_map,
                                ):
    """
    TC1 - Basic RoCEv2 data-plane traffic, no congestion (bidirectional 1:1 pairs).

    The lossless rank pair runs one QP on a randomly chosen lossless queue
    (LOSSLESS_QUEUES); the last rank pair drives the lossy queues (LOSSY_QUEUES),
    one QP each. ACK/NAK ride ACK_NAK_QUEUE (Q6); CNP on CNP_QUEUE (Q5, DSCP 46),
    kept separate from the ACK queue. 1MB messages, non-ECT, DCQCN off.

    Verifies (nothing is oversubscribed, so congestion control must stay idle):
      all messages complete with no loss, no NAK/sequence errors, latency within
      spec, ACKs present (and matching the DUT ACK-queue counter), no ECN-CE, no
      CNP, NO PFC on the lossless queues (3,4), and lossy data landing on its
      mapped queue. No DWRR rate-fairness check - the egress is never
      oversubscribed, so DWRR weights don't arbitrate (that lives in the PFC test).
    """

    snappi_port_list = get_snappi_ports
    pytest_require(len(snappi_port_list) >= 4, "Need minimum of 4 ports")
    # build_pairwise_topology() pairs first-half with second-half via zip(); an odd
    # count would silently drop the unpaired port, so require an even number.
    pytest_require(len(snappi_port_list) % 2 == 0, "Need an even number of ports for pairwise topology")

    tconfig, plist, sports = snappi_dut_base_config(duthosts, snappi_port_list, snappi_api)
    snappi_dut_port_map = snappi_dut_port_mapping(sports)
    port_ids = [pc.id for pc in plist]

    # ---- queue / priority intent (constants at top of file) ---------------
    lossless_queue = random.choice(LOSSLESS_QUEUES)   # randomized per run
    queue_ack_nak = ACK_NAK_QUEUE
    lossy_queues = LOSSY_QUEUES
    cnp_queue = CNP_QUEUE
    priority_to_dscp = derive_priority_to_dscp(prio_dscp_map)

    # ---- traffic config (tune per test) -----------------------------------
    # Reusable ACK/NAK connection settings so lossless and lossy flows can use
    # the same or different values (ACK/NAK queue, ECN).
    def conn(ack_nak_q, ecn="non_ect"):
        return {
            "choice": "reliable_connection",
            "reliable_connection": {
                "ack": {"ip_dscp": priority_to_dscp[ack_nak_q], "ecn_value": ecn},
                "nak": {"ip_dscp": priority_to_dscp[ack_nak_q], "ecn_value": ecn},
                "enable_retransmission_timeout": True,
                "retransmission_timeout_value": 5000,
                "retransmission_retry_count": 254,
            },
        }

    COMMON_CFG = {
        "mtu": 9100,
        "qp_configs": [{"message_size_unit": "mb", "message_size": 1,
                        "dscp": priority_to_dscp[lossless_queue]}],
        "cnp": {"ip_dscp": priority_to_dscp[cnp_queue], "ecn_value": "non_ect"},
        "dcqcn_settings": {"enable_dcqcn": False},
        "connection_type": conn(queue_ack_nak),
    }
    lossy_qp_configs = [{"message_size_unit": "mb", "message_size": 1, "dscp": priority_to_dscp[q]}
                        for q in lossy_queues]
    # Lossy pair: same plumbing as COMMON_CFG but its own qp_configs and its own
    # ACK/NAK connection_type. Change the conn(...) args below to give the lossy
    # flows a different ACK/NAK queue or ECN (kept identical here so checks 11/12,
    # which match ACKs to the DUT ACK-queue counter, stay valid).
    LOSSY_CFG = {**COMMON_CFG, "qp_configs": lossy_qp_configs,
                 "connection_type": conn(queue_ack_nak)}
    topology = build_pairwise_topology(port_ids, COMMON_CFG, last_pair_cfg=LOSSY_CFG)
    logger.info(f"Test Topology: {topology}")

    # ---- run + collect every analysis frame (all plumbing in the lib) -----
    stats = collect_rocev2_dp_stats(
        snappi_api=snappi_api, duthosts=duthosts, plist=plist, tconfig=tconfig,
        snappi_dut_port_map=snappi_dut_port_map, topology=topology,
        prio_dscp_map=prio_dscp_map, lossless_queue=lossless_queue,
        lossy_queues=lossy_queues, lossy_queue_ack_nak=queue_ack_nak,
        traffic_duration=TRAFFIC_DURATION, config_name=request.node.name)

    dsps = stats.dsps
    lossy_dsps = stats.lossy_dsps
    ack_q_col = stats.ack_q_col

    # No-congestion: the DUT must generate NO PFC on the lossless queues (3,4).
    # Measured from the DUT Tx PFC counter (authoritative); the snappi Rx-pause
    # port stat is unreliable. One-row total across the DUT interfaces.
    lossless_pfc_qs = LOSSLESS_QUEUES
    pfc_df = pfc_counters(snappi_dut_port_map, direction="Tx")
    logger.info(f"DUT Tx PFC counters:\n{tabulate(pfc_df, headers='keys', tablefmt='psql')}")
    pfc_chk_cols = [f"PFC{q}" for q in lossless_pfc_qs if f"PFC{q}" in pfc_df.columns]
    pfc_totals = {c: int(pd.to_numeric(pfc_df[c], errors="coerce").fillna(0).sum()) for c in pfc_chk_cols}
    pfc_sum_df = pd.DataFrame([pfc_totals]) if pfc_totals else pd.DataFrame([{"PFC_none": 0}])
    pfc_fail_expr = " or ".join(f"{c} != 0" for c in pfc_chk_cols) or "PFC_none != 0"

    # ---- checks (the part that defines what this test verifies) -----------
    # make_check(expr, cols, desc, msg): expr is the FAILURE condition - any row
    # matching => the check fails; empty => pass.
    checks = [
        # 1 - all messages complete, no frame loss
        make_check("message_fail != 0 or frame_delta != 0",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "message_tx", "message_complete_rx", "message_fail", "frame_delta"],
                "All messages complete, no loss", "message_fail=0 & frame_delta=0 required"),
        # 2 - no NAK / sequence errors
        make_check("nak_tx != 0 or nak_rx != 0 or frame_sequence_error != 0",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "nak_tx", "nak_rx", "frame_sequence_error"],
                "No NAK/sequence errors", "nak_tx=0 & nak_rx=0 & frame_sequence_error=0 required"),
        # 3 - latency within AI profile
        make_check(f"avg_latency > {LATENCY_PROFILES['ai']['avg_latency_max']}",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "avg_latency", "max_latency"],
                "Latency within spec", f"avg_latency > {LATENCY_PROFILES['ai']['avg_latency_max']} is a failure"),
        # 4/5/6 - lossless DSCP: ACKs present, no ECN-CE, no CNP
        make_check(f"ip_dscp in {dsps} and ack_tx == 0",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "ack_tx", "ack_rx"],
                f"ACK on DSCPs {dsps}", f"ack_tx > 0 required for DSCPs {dsps}"),
        make_check(f"ip_dscp in {dsps} and ecn_ce_rx != 0",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "ecn_ce_rx"],
                f"ECN-CE on DSCPs {dsps}", f"ecn_ce_rx == 0 required for DSCPs {dsps}"),
        make_check(f"ip_dscp in {dsps} and (cnp_tx != 0 or cnp_rx != 0)",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "cnp_tx", "cnp_rx"],
                f"CNP on DSCPs {dsps}", f"cnp_tx == 0 and cnp_rx == 0 required for DSCPs {dsps}"),
        # 7/8/9 - lossy DSCPs (last pair): ACKs present, no ECN-CE, no CNP
        make_check(f"ip_dscp in {lossy_dsps} and ack_tx == 0",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "ack_tx", "ack_rx"],
                f"ACK on lossy DSCPs {lossy_dsps}", f"ack_tx > 0 required for lossy DSCPs {lossy_dsps}"),
        make_check(f"ip_dscp in {lossy_dsps} and ecn_ce_rx != 0",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "ecn_ce_rx"],
                f"ECN-CE on lossy DSCPs {lossy_dsps}", f"ecn_ce_rx == 0 required for lossy DSCPs {lossy_dsps}"),
        make_check(f"ip_dscp in {lossy_dsps} and (cnp_tx != 0 or cnp_rx != 0)",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "cnp_tx", "cnp_rx"],
                f"CNP on lossy DSCPs {lossy_dsps}", f"cnp_tx == 0 and cnp_rx == 0 required for lossy DSCPs {lossy_dsps}"),
        # 10 - NO PFC on the lossless queues 3,4 (no congestion). DUT Tx PFC
        #      counter; fail if any PFC was generated on those priorities.
        make_check(pfc_fail_expr, list(pfc_sum_df.columns),
                "No PFC on lossless queues 3,4 (no congestion)",
                "DUT Tx PFC must be 0 on lossless queues 3,4 under no congestion",
                override_df=pfc_sum_df),
        # 11 - non-lossy ACK count matches DUT ACK queue counter (1 QP per port)
        make_check(f"ip_dscp not in {lossy_dsps} and (ack_tx != `{ack_q_col}` or ack_rx != ack_tx)",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "ack_tx", "ack_rx", ack_q_col],
                "ACK on Snappi and DUT should match.",
                f"ack_tx == {ack_q_col} and ack_rx == ack_tx (non-lossy flows)"),
        # 12 - lossy ACKs (aggregated per port) match DUT ACK queue counter
        make_check(f"ack_tx != `{ack_q_col}`",
                ["port_tx", "ack_tx", ack_q_col],
                "Lossy ACKs match DUT ACK/NAK queue (per port)",
                f"sum(ack_tx) per port must equal {ack_q_col}",
                override_df=stats.ack_agg_df),
        # 13 - lossy data lands on the queue its DSCP maps to
        make_check("expected_pkts != actual_pkts",
                ["snappi_port", "queue", "expected_pkts", "actual_pkts"],
                "Lossy data lands on the mapped queue",
                "DUT UC<q> totalpacket must equal the data of its mapped DSCP per port",
                override_df=stats.data_queue_df),
    ]
    assert_queries(stats.merged_df, checks)
    logger.info("*** TC1 PASSED ***")
