# flake8: noqa: F403, F401, F405
import pytest
import logging

from snappi_tests.rocev2.files.helper import *
from snappi_tests.rocev2.files.helper_common import (
    collect_flow_queue_stats_portable,
    make_scale_qp_configs,
)

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]

TRAFFIC_DURATION = 180
CNP_DSCP = 48
IB_MTU_BYTES = 4096      # 4K IB MTU: payload per packet; STC derives frame size from this
RDMA_MSG_SIZE_KB = 1024  # 1MB RDMA message size (1024KB / 4KB MTU = 256 packets per message)
TX_RATE_PERCENT = 55  # test plan: "55% rate per Tx port"

# Two sub-runs: DCQCN off (PFC-dominant) then DCQCN on (ECN/CNP-dominant).
SCENARIOS = {
    # DCQCN disabled: traffic is ECN-capable (ECT(1)), DUT still marks CE and rx generates CNP,
    # but sender ignores CNP (DCQCN off) so rate stays constant and PFC fires heavily.
    # Runs twice: once with queues=(3,3), once with queues=(3,4).
    "storage_no_dcqcn": {
        "dcqcn": False,
        "ecn_capable": True,
    },
    # DCQCN enabled: ECN-CE and CNP must appear; sender reacts to CNP and reduces rate,
    # so PFC fires less (or not at all) compared to no_dcqcn.
    # Runs twice: once with queues=(3,3), once with queues=(3,4).
    "storage_with_dcqcn": {
        "dcqcn": True,
        "ecn_capable": True,
    },
}


@pytest.mark.parametrize("scenario_name", list(SCENARIOS.keys()))
def test_rocev2_tc4_pfc_ecn_storage_traffic(
                                    request,
                                    snappi_api,
                                    conn_graph_facts,
                                    fanout_graph_facts_multidut,
                                    get_snappi_ports,
                                    duthosts,
                                    prio_dscp_map,
                                    scenario_name,
                                ):
    """
    TC4 - PFC + ECN/CNP Congestion Control for Storage Traffic.

    Storage workloads drive at constant rate with 1 MB messages (vs bursty AI
    traffic in TC2/TC3). Two parametrized sub-runs compare congestion behaviour
    with and without DCQCN:

      storage_no_dcqcn   - constant-rate 2:1 incast, DCQCN off.
                           Traffic is ECN-capable; DUT marks CE and rx generates CNP,
                           but sender ignores CNP. PFC fires heavily.
      storage_with_dcqcn - same traffic, DCQCN on.
                           Sender reacts to CNP and reduces rate; PFC decreases.

    Key difference from TC2/TC3: larger message size (1MB storage workload).
    Key differentiator vs Ixia: vendor-neutral helper (no api._ixnetwork).

    References:
      Test plan: sonic-net/sonic-mgmt#21514
      TC1 reference: sonic-net/sonic-mgmt#23240
    """
    spec = SCENARIOS[scenario_name]
    dcqcn = spec["dcqcn"]
    ecn_capable = spec["ecn_capable"]

    snappi_port_list = get_snappi_ports
    pytest_require(len(snappi_port_list) >= 3, "Need minimum of 3 ports: 2 Tx ranks + 1 common Rx")
    # 2:1 incast per test plan: use exactly 2 Tx ranks + 1 common Rx, even if
    # the testbed has more ports available.
    snappi_port_list = snappi_port_list[:3]

    tconfig, plist, sports = snappi_dut_base_config(duthosts, snappi_port_list, snappi_api)
    try:
        snappi_dut_port_map = snappi_dut_port_mapping(sports)
        port_ids = [pc.id for pc in plist]

        priority_to_dscp = derive_priority_to_dscp(prio_dscp_map)

        # Run twice per scenario: same-priority (3,3) then mixed-priority (3,4).
        for queues in [(3, 3), (3, 4)]:
          run_label = f"{scenario_name} queues={queues}"

          def conn(ack_nak_dscp):
            ecn = "ect_1" if ecn_capable else "non_ect"
            return {
                "choice": "reliable_connection",
                "reliable_connection": {
                    "ack": {"ip_dscp": ack_nak_dscp, "ecn_value": ecn},
                    "nak": {"ip_dscp": ack_nak_dscp, "ecn_value": ecn},
                    "enable_retransmission_timeout": False,
                },
            }

          def lossless_cfg_fn(queue, message_size_kb):
            dscp = priority_to_dscp[queue]
            qp_cfg = {"message_size_unit": "kb", "message_size": message_size_kb, "dscp": dscp, "verb": "write"}
            if ecn_capable:
                qp_cfg["ecn"] = "ect_1"
            return {
                "mtu": IB_MTU_BYTES,
                "eth_mtu": 9100,
                "verb": "write",
                "qp_configs": [qp_cfg],
                "cnp": {"ip_dscp": CNP_DSCP, "ecn_value": "ect_1"},
                "dcqcn_settings": {"enable_dcqcn": dcqcn},
                "connection_type": conn(dscp),
                "rocev2_port_config": {"transmit_type": "target_line_rate", "target_line_rate": TX_RATE_PERCENT},
            }

          lossless_spec = [(q, RDMA_MSG_SIZE_KB) for q in queues]
          # Fix rx as the last port (port_ids[-1]) so Port 0/1 are always Tx, Port 2 is always Rx.
          topology, rx_port_id, _, used_lossless = build_incast_topology(
              port_ids, lossless_cfg_fn, lossless_spec, configure_rx_peers=True,
              rx=port_ids[-1])
          logger.info(f"[{run_label}] TC4 Topology (2:1 incast storage, dcqcn={dcqcn}, rx={rx_port_id})")

          driven_queues = sorted(set(queues))
          dsps = sorted(set(priority_to_dscp[q] for q in queues))
          qids = sorted(set(f"UC{q}" for q in queues) | {"UC6"})  # UC6 for CNP (DSCP 48)

          _merged_df, flow_df, dut_queue_df, _sched_df = collect_flow_queue_stats_portable(
              snappi_api=snappi_api, duthosts=duthosts, plist=plist, tconfig=tconfig,
              snappi_dut_port_map=snappi_dut_port_map, topology=topology,
              prio_dscp_map=prio_dscp_map, queue_ids=qids,
              traffic_duration=TRAFFIC_DURATION, sample_rates=True)

          # STC may not populate all per-QP counters (message_fail, frame_sequence_error, etc.);
          # treat missing (NaN) values as 0 so pandas query() doesn't misfire on NaN != 0.
          flow_df = flow_df.fillna(0)

          # PFC measured from the DUT Tx PFC counter (authoritative); the snappi Rx-pause
          # port stat is unreliable / unsupported on STC. One-row total across the DUT interfaces.
          pfc_df = pfc_counters(snappi_dut_port_map, direction="Tx")
          pfc_cols = [f"PFC{q}" for q in driven_queues if f"PFC{q}" in pfc_df.columns]
          pytest_assert(len(pfc_cols) == len(driven_queues),
                        f"[{run_label}] Missing DUT PFC counter column(s) for queues {driven_queues}; "
                        f"have {list(pfc_df.columns)}")
          pfc_totals = {c: int(pd.to_numeric(pfc_df[c], errors="coerce").fillna(0).sum()) for c in pfc_cols}
          pfc_sum_df = pd.DataFrame([pfc_totals]) if pfc_totals else pd.DataFrame([{"PFC_none": 0}])
          logger.info(f"[{run_label}] DUT Tx PFC counters:\n{tabulate(pfc_df, headers='keys', tablefmt='psql')}")

          # Record bandwidth and latency; avg_latency is checked against LATENCY_PROFILES below.
          bw_lat_cols = [c for c in ["flow_name", "port_tx", "port_rx",
                                      "data_tx_rate", "data_rx_rate",
                                      "min_latency", "avg_latency", "max_latency"]
                         if c in flow_df.columns]
          if bw_lat_cols:
              logger.info(f"[{run_label}] Bandwidth & Latency:\n"
                          f"{tabulate(flow_df[bw_lat_cols], headers='keys', tablefmt='psql', showindex=False)}")

          # Counter comparison with 5% tolerance.
          # CNP:    STC cnp_tx (Port1 sends) vs DUT UC6 totalpacket on TX ports.
          # ACK:    STC ack_tx (Port1 sends) vs STC ack_rx (Port0/2 receives) — no DUT equivalent.
          # ECN-CE: STC ecn_ce_rx (Port1 receives from DUT) — no DUT equivalent, informational.
          # PFC:    DUT Tx PFC Port0 vs Port2 symmetry — no STC per-QP PFC counter.
          rx_mask      = flow_df["port_tx"] == str(rx_port_id) if "port_tx" in flow_df.columns else pd.Series(False, index=flow_df.index)
          tx_mask_flow = ~rx_mask

          stc_cnp_tx = int(flow_df.loc[tx_mask_flow, "cnp_tx"].sum())    if "cnp_tx"    in flow_df.columns else 0
          stc_cnp_rx = int(flow_df.loc[tx_mask_flow, "cnp_rx"].sum())    if "cnp_rx"    in flow_df.columns else 0
          stc_ack_tx = int(flow_df.loc[tx_mask_flow, "ack_tx"].sum())    if "ack_tx"    in flow_df.columns else 0
          stc_ack_rx = int(flow_df.loc[tx_mask_flow, "ack_rx"].sum())    if "ack_rx"    in flow_df.columns else 0
          stc_ecnce  = int(flow_df.loc[tx_mask_flow, "ecn_ce_rx"].sum()) if "ecn_ce_rx" in flow_df.columns else 0

          dut_cnp = 0
          if "UC6 totalpacket" in dut_queue_df.columns:
              dut_cnp = int(dut_queue_df.loc[dut_queue_df["snappi_port"] != str(rx_port_id), "UC6 totalpacket"].sum())

          def _pct_diff(a, b):
              return abs(a - b) / max(a, b) if max(a, b) > 0 else 0.0

          # Per-rank PFC: each TX rank is checked against its own driven queue.
          # queues[i] maps to port_ids[i], so Port 0 → queues[0], Port 1 → queues[1].
          tx_port_ids = [p for p in port_ids if p != rx_port_id]
          rank_pfc_rows = []
          for rank_port, rank_queue in zip(tx_port_ids, queues):
              col = f"PFC{rank_queue}"
              port_rows = pfc_df[pfc_df["snappi_port"] == f"Port {rank_port}"] if "snappi_port" in pfc_df.columns else pfc_df
              val = int(pd.to_numeric(port_rows[col], errors="coerce").fillna(0).sum()) if col in pfc_df.columns else 0
              rank_pfc_rows.append({"snappi_port": f"Port {rank_port}", "queue": rank_queue, "pfc_count": val})
          rank_pfc_df = pd.DataFrame(rank_pfc_rows)

          logger.info(
              f"[{run_label}] Counter comparison (5% tolerance):\n"
              f"  CNP    STC tx={stc_cnp_tx}  rx={stc_cnp_rx}  DUT_UC6={dut_cnp}\n"
              f"  ACK    STC tx={stc_ack_tx}  rx={stc_ack_rx}\n"
              f"  ECN-CE STC rx={stc_ecnce} (informational, no DUT equivalent)\n"
              f"  PFC per rank:\n{tabulate(rank_pfc_df, headers='keys', tablefmt='psql', showindex=False)}"
          )

          TOL = 5.0   # percent
          cnp_stc_df  = pd.DataFrame([{"stc_cnp_tx": stc_cnp_tx, "stc_cnp_rx": stc_cnp_rx,
                                        "pct_diff": round(_pct_diff(stc_cnp_tx, stc_cnp_rx) * 100, 1)}])
          cnp_xsys_df = pd.DataFrame([{"stc_cnp_tx": stc_cnp_tx, "dut_uc6": dut_cnp,
                                        "pct_diff": round(_pct_diff(stc_cnp_tx, dut_cnp) * 100, 1)}])
          ack_stc_df  = pd.DataFrame([{"stc_ack_tx": stc_ack_tx, "stc_ack_rx": stc_ack_rx,
                                        "pct_diff": round(_pct_diff(stc_ack_tx, stc_ack_rx) * 100, 1)}])

          checks = [
              # C_ack: ACK received by TX ports (ack_rx; ack_tx is the responder's counter, not requester's).
              make_check(f"ip_dscp in {dsps} and ack_rx == 0",
                      ["flow_name", "port_tx", "port_rx", "ip_dscp", "ack_tx", "ack_rx"],
                      f"ACK on DSCPs {dsps}", f"ack_rx > 0 required for DSCPs {dsps}"),
              # C1: No packet loss — PFC must pause senders before headroom exhaustion.
              make_check("message_fail != 0 or frame_delta != 0",
                      ["flow_name", "port_tx", "port_rx", "ip_dscp", "message_fail", "frame_delta"],
                      "All messages complete, no loss",
                      "message_fail=0 & frame_delta=0 required — PFC must prevent headroom drops"),
              # C2: No NAK / sequence errors.
              make_check("nak_tx != 0 or nak_rx != 0 or frame_sequence_error != 0",
                      ["flow_name", "port_tx", "port_rx", "ip_dscp", "nak_tx", "nak_rx", "frame_sequence_error"],
                      "No NAK/sequence errors",
                      "nak_tx=0 & nak_rx=0 & frame_sequence_error=0 required"),
          ]
          # C3 (aligned with TC1): latency within AI profile spec.
          checks.append(
              make_check(f"avg_latency > {LATENCY_PROFILES['storage']['avg_latency_max']}",
                      ["flow_name", "port_tx", "port_rx", "ip_dscp", "avg_latency", "max_latency"],
                      "Latency within spec",
                      f"avg_latency > {LATENCY_PROFILES['storage']['avg_latency_max']} is a failure")
          )
          # Counter cross-checks (5% tolerance) via make_check for structured reporting.
          checks += [
              # CNP STC internal: tx (responder sends) vs rx (requester receives).
              make_check(f"(stc_cnp_tx > 0 or stc_cnp_rx > 0) and pct_diff > {TOL}",
                      ["stc_cnp_tx", "stc_cnp_rx", "pct_diff"],
                      "CNP STC tx/rx match (5% tolerance)",
                      "stc_cnp_tx and stc_cnp_rx must be within 5%",
                      override_df=cnp_stc_df),
              # CNP cross-system: STC cnp_tx vs DUT UC6 totalpacket.
              make_check(f"stc_cnp_tx > 0 and pct_diff > {TOL}",
                      ["stc_cnp_tx", "dut_uc6", "pct_diff"],
                      "CNP STC tx matches DUT UC6 (cross-system, 5% tolerance)",
                      "stc_cnp_tx and dut_uc6 must be within 5%",
                      override_df=cnp_xsys_df),
              # ACK STC internal: tx (responder sends) vs rx (requester receives).
              make_check(f"(stc_ack_tx > 0 or stc_ack_rx > 0) and pct_diff > {TOL}",
                      ["stc_ack_tx", "stc_ack_rx", "pct_diff"],
                      "ACK STC tx/rx match (5% tolerance)",
                      "stc_ack_tx and stc_ack_rx must be within 5%",
                      override_df=ack_stc_df),
              # PFC per rank: each TX rank must have PFC > 0 on its own driven queue.
              make_check("pfc_count == 0",
                      ["snappi_port", "queue", "pfc_count"],
                      "PFC fires on each TX rank for its driven queue",
                      "DUT Tx PFC must be > 0 for each TX rank's driven queue",
                      override_df=rank_pfc_df),
          ]

          if not dcqcn:
              pfc_fail_expr = " or ".join(f"{c} == 0" for c in pfc_cols)
              checks += [
                  make_check(pfc_fail_expr, list(pfc_sum_df.columns),
                          f"PFC fires on queues {driven_queues} (no DCQCN, sender does not reduce rate)",
                          "DUT Tx PFC must be > 0 without DCQCN", override_df=pfc_sum_df),
                  make_check(f"ip_dscp in {dsps} and ecn_ce_rx == 0",
                          ["flow_name", "port_tx", "port_rx", "ip_dscp", "ecn_ce_rx"],
                          f"ECN-CE observed (DUT marks CE on congested ECN-capable traffic)",
                          f"ecn_ce_rx > 0 required — DUT must mark CE even when DCQCN disabled"),
                  make_check(f"ip_dscp in {dsps} and cnp_tx == 0 and cnp_rx == 0",
                          ["flow_name", "port_tx", "port_rx", "ip_dscp", "cnp_tx", "cnp_rx"],
                          f"CNP observed (rx generates CNP on ECN-CE)",
                          f"cnp_tx > 0 or cnp_rx > 0 required — rx must send CNP regardless of DCQCN"),
              ]
          else:
              checks += [
                  make_check(f"ip_dscp in {dsps} and ecn_ce_rx == 0",
                          ["flow_name", "port_tx", "port_rx", "ip_dscp", "ecn_ce_rx"],
                          f"ECN-CE observed (DCQCN active on storage traffic)",
                          f"ecn_ce_rx > 0 required — DCQCN must mark CE"),
                  make_check(f"ip_dscp in {dsps} and cnp_tx == 0 and cnp_rx == 0",
                          ["flow_name", "port_tx", "port_rx", "ip_dscp", "cnp_tx", "cnp_rx"],
                          f"CNP observed (DCQCN notification on storage traffic)",
                          f"cnp_tx > 0 or cnp_rx > 0 required — DUT must send CNP"),
              ]

          assert_queries(flow_df, checks)
          logger.info(f"*** TC4 [{run_label}] PASSED ***")
          start_stop(snappi_api, operation="stop", op_type="protocols")
          for duthost in duthosts:
              duthost.command("pfcwd stop")
              duthost.command("sonic-clear pfccounters")
              duthost.command("sonic-clear queuecounters")
    finally:
        pass


# ===========================================================================
# Scale variant - "Increase number of endpoints per port to 4K for testing T4"
# (test plan step equivalent to TC2 step 9).
#
# 2:1 incast constraint: with 2 TX ports and 1 common RX port, the RX must
# accept connections from BOTH TX ports, so RX needs 2 × (TX QPs).
# STC per-port hard limit: 128 blocks × 32 QPs = 4096 QPs.
# Therefore each TX port is limited to 2048 QPs so the RX stays at
# 2 × 2048 = 4096 = the hardware maximum.
# ===========================================================================
STC_PORT_QP_LIMIT = 4096    # 128 blocks × 32 QPs/block; raise if VIAVI unlocks more
NUM_ENDPOINTS_SCALE = 64  # 2:1 incast: RX = 2×TX ≤ STC_PORT_QP_LIMIT


@pytest.mark.disable_memory_utilization
def test_rocev2_tc4_pfc_ecn_storage_traffic_scale(
                                    request,
                                    snappi_api,
                                    conn_graph_facts,
                                    fanout_graph_facts_multidut,
                                    get_snappi_ports,
                                    duthosts,
                                    prio_dscp_map,
                                ):
    """
    TC4 scale step - 2:1 incast storage with NUM_ENDPOINTS_SCALE QPs per TX rank,
    per the test plan's "increase endpoints per port to 4K for testing T4".

    Uses the no_dcqcn scenario (constant rate, PFC-dominant) with queues=(3,3)
    to validate scale behaviour. DCQCN is disabled so the sender does not reduce
    rate; PFC must fire to prevent loss at 2048 QPs/TX rank.

    2:1 incast hard limit: each TX port runs 2048 QPs; the common RX port must
    handle 4096 incoming QPs, which equals the STC per-port maximum
    (128 blocks × 32 QPs = 4096).

    NOT YET VALIDATED at scale - set_config() time at 2048+ QPs has not been
    measured against a real backend. Reduce NUM_ENDPOINTS_SCALE (e.g. 256)
    for a first-pass sanity check, then raise once confirmed working.
    """
    snappi_port_list = get_snappi_ports
    pytest_require(len(snappi_port_list) >= 3, "Need minimum of 3 ports: 2 Tx ranks + 1 common Rx")
    snappi_port_list = snappi_port_list[:3]

    tconfig, plist, sports = snappi_dut_base_config(duthosts, snappi_port_list, snappi_api)
    snappi_dut_port_map = snappi_dut_port_mapping(sports)
    port_ids = [pc.id for pc in plist]

    priority_to_dscp = derive_priority_to_dscp(prio_dscp_map)
    queues = (3, 3)
    driven_queues = sorted(set(queues))

    def conn(ack_nak_dscp):
        return {
            "choice": "reliable_connection",
            "reliable_connection": {
                "ack": {"ip_dscp": ack_nak_dscp, "ecn_value": "ect_1"},
                "nak": {"ip_dscp": ack_nak_dscp, "ecn_value": "ect_1"},
                "enable_retransmission_timeout": True,
                "retransmission_timeout_value": 5000,
                "retransmission_retry_count": 254,
            },
        }

    def lossless_cfg_fn(queue, message_size_kb):
        dscp = priority_to_dscp[queue]
        return {
            "mtu": IB_MTU_BYTES,
            "eth_mtu": 9100,
            "verb": "write",
            "qp_configs": make_scale_qp_configs(
                NUM_ENDPOINTS_SCALE, dscp, message_size_kb=message_size_kb,
                qp_num_base=100 + queue * 10000,
                extra_qp_fields={"ecn": "ect_1", "verb": "write"}),
            "cnp": {"ip_dscp": CNP_DSCP, "ecn_value": "ect_1"},
            "dcqcn_settings": {"enable_dcqcn": False},
            "connection_type": conn(dscp),
            "rocev2_port_config": {"transmit_type": "target_line_rate", "target_line_rate": TX_RATE_PERCENT},
        }

    lossless_spec = [(q, RDMA_MSG_SIZE_KB) for q in queues]
    topology, rx_port_id, _, used_lossless = build_incast_topology(
        port_ids, lossless_cfg_fn, lossless_spec, configure_rx_peers=True,
        rx=port_ids[-1])
    logger.info(
        f"[scale] TC4 Topology (2:1 incast storage, {NUM_ENDPOINTS_SCALE} QPs/TX rank, "
        f"dcqcn=False, rx={rx_port_id})")

    dsps = sorted(set(priority_to_dscp[q] for q in queues))
    qids = sorted(set(f"UC{q}" for q in queues) | {"UC6"})

    _merged_df, flow_df, dut_queue_df, _sched_df = collect_flow_queue_stats_portable(
        snappi_api=snappi_api, duthosts=duthosts, plist=plist, tconfig=tconfig,
        snappi_dut_port_map=snappi_dut_port_map, topology=topology,
        prio_dscp_map=prio_dscp_map, queue_ids=qids,
        traffic_duration=TRAFFIC_DURATION, sample_rates=True,
        settle_time=30)

    flow_df = flow_df.fillna(0)

    pfc_df = pfc_counters(snappi_dut_port_map, direction="Tx")
    pfc_cols = [f"PFC{q}" for q in driven_queues if f"PFC{q}" in pfc_df.columns]
    pfc_totals = {c: int(pd.to_numeric(pfc_df[c], errors="coerce").fillna(0).sum()) for c in pfc_cols}
    pfc_sum_df = pd.DataFrame([pfc_totals]) if pfc_totals else pd.DataFrame([{"PFC_none": 0}])
    logger.info(f"[scale] DUT Tx PFC counters:\n{tabulate(pfc_df, headers='keys', tablefmt='psql')}")

    # NOTE: This scale case has NOT been fully validated.
    # STC currently does not support 8K QPs.
    checks = [
        make_check(" or ".join(f"{c} == 0" for c in pfc_cols) if pfc_cols else "1 == 1",
                list(pfc_sum_df.columns),
                f"PFC fires on queues {driven_queues} at scale ({NUM_ENDPOINTS_SCALE} QPs/TX rank)",
                "DUT Tx PFC must be > 0 at scale", override_df=pfc_sum_df),
        # At scale, aggregate-level checks only (per-QP detail makes failure reports unreadable).
        make_check("message_fail != 0 or frame_delta != 0",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "message_fail", "frame_delta"],
                f"No loss at scale ({NUM_ENDPOINTS_SCALE} QPs/TX rank)",
                "message_fail=0 & frame_delta=0 required for every QP"),
        make_check(f"ip_dscp in {dsps} and cnp_tx == 0 and cnp_rx == 0",
                ["flow_name", "port_tx", "port_rx", "ip_dscp", "cnp_tx", "cnp_rx"],
                f"CNP observed at scale ({NUM_ENDPOINTS_SCALE} QPs/TX rank)",
                "cnp_tx > 0 or cnp_rx > 0 required — rx must generate CNP on ECN-CE marks"),
    ]
    assert_queries(flow_df, checks)
    logger.info(f"*** TC4 [scale, {NUM_ENDPOINTS_SCALE} QPs/TX rank] PASSED ***")
