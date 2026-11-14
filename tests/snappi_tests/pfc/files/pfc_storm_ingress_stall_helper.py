"""
Helpers for PFC storm ingress-stall tests (Ixia-sourced PFC toward DUT).

Uses generate_pause_flows() with pause_flow_config (PPS + optional flow_quanta)
and standard generate_test_flows / generate_background_flows / run_traffic.

DUT setup follows a production-like path: PFC watchdog and packet aging are
started/enabled on the egress and ingress DUTs (see _configure_duts), rather
than being turned off for the run.
"""
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.common_helpers import (
    start_pfcwd,
    enable_packet_aging,
    calc_pfc_pause_flow_rate,
    traffic_flow_mode,
    get_interface_stats,
    get_pfc_count,
    get_pfcwd_stats,
)
from tests.common.snappi_tests.traffic_generation import (
    setup_base_traffic_config,
    generate_test_flows,
    generate_background_flows,
    generate_pause_flows,
    run_traffic,
)
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.snappi_tests.files.helper import get_number_of_streams

logger = logging.getLogger(__name__)

PAUSE_FLOW_PREFIX = "PFC Storm"
TEST_FLOW_NAME = "Test Flow"
BG_FLOW_NAME = "Background Flow"
PAUSE_NAME_SINGLE = "PFC Storm"
DATA_PKT_SIZE = 1024
TEST_FLOW_AGGR_RATE_PERCENT = 90
BG_FLOW_AGGR_RATE_PERCENT = 10
STALL_LOSS_RATIO = 0.75
NO_STALL_LOSS_RATIO = 0.35
# In-flight TGEN throughput (tx_rate_mbps / rx_rate_mbps) vs ideal line rate.
QUANTA_SWEEP_RATE_TOL = 0.15
QUANTA_SWEEP_TX_RX_RATE_REL_TOL = 0.12
# When pause fully stalls RX (expected RX ~0), allow this much leakage.
QUANTA_SWEEP_STALL_RX_FRAC = 0.02
QUANTA_SWEEP_STALL_RX_ABS_MBPS = 50.0
PAUSE_QUANTA_MAX = 0xFFFF
PFC_COUNTER_REL_TOL = 0.15
# Positive quanta cases are expected to propagate backpressure to the ingress.
QUANTA_SWEEP_POSITIVE_QUANTA_INGRESS_TX_PFC_MIN = 1
# Extra pause PPS applied only for quanta-sweep 0xFFFF (max hold) case.
QUANTA_SWEEP_0XFFFF_PPS_BOOST = 200
# Sub-blocking PPS sweep: IXIA throttles offered load by pause_pps / baseline_blocking_pps.
PPS_SWEEP_THROUGHPUT_FRAC_TOL = 0.05


def _expected_test_flow_throughput_mbps(speed_gbps, rate_percent):
    """Ideal offered load in Mbps for a percent-of-line-rate flow."""
    return (rate_percent / 100.0) * float(speed_gbps) * 1000.0


def _tx_rx_mbps_from_in_flight(flow_metrics, prio):
    """Read in-flight TX/RX throughput for a test-flow priority."""
    row = _find_test_flow_metric(flow_metrics, prio)
    pytest_assert(row is not None, "Missing in-flight tgen stats for test prio {}".format(prio))
    return float(row.tx_rate_mbps), float(row.rx_rate_mbps)


def _tx_rx_mbps_with_counter_fallback(in_flight_metrics, flow_stats, prio, flow_dur_sec):
    """Use in-flight rates, or derive L1 rates from final counters when they are stale."""
    tx_mbps, rx_mbps = _tx_rx_mbps_from_in_flight(in_flight_metrics, prio)
    row = _find_test_flow_metric(flow_stats, prio)
    pytest_assert(row is not None, "Missing final tgen stats for test prio {}".format(prio))

    stale_tx = tx_mbps <= 0 and row.frames_tx > 0
    stale_rx = rx_mbps <= 0 and row.frames_rx > 0
    if not (stale_tx or stale_rx):
        return tx_mbps, rx_mbps

    bits_per_l1_frame = (DATA_PKT_SIZE + 20) * 8
    tx_mbps = row.frames_tx * bits_per_l1_frame / float(flow_dur_sec) / 1e6
    rx_mbps = row.frames_rx * bits_per_l1_frame / float(flow_dur_sec) / 1e6
    logger.info(
        "Prio %s: using counter-derived rates because in-flight rates were stale: "
        "tx=%.1f rx=%.1f Mbps", prio, tx_mbps, rx_mbps,
    )
    return tx_mbps, rx_mbps


def _find_test_flow_metric(flow_metrics, prio):
    needle = "{} Prio {}".format(TEST_FLOW_NAME, prio)
    for row in flow_metrics:
        if needle in row.name:
            return row
    return None


def _snapshot_pfc_counts(duthost, peer_port, pause_prio_list):
    """
    Snapshot PFC TX/RX counters per pause priority on a DUT peer port.

    Returns:
        {prio: {"tx": int, "rx": int}}
    """
    raw = get_pfc_count(duthost, peer_port)
    port_stats = raw[duthost.hostname][peer_port]
    counts = {}
    for prio in pause_prio_list:
        p = int(prio)
        counts[p] = {
            "tx": int(port_stats.get("tx_pfc_{}".format(p), 0)),
            "rx": int(port_stats.get("rx_pfc_{}".format(p), 0)),
        }
    return counts


def _snapshot_pfc_tx_by_prio(duthost, peer_port, pause_prio_list):
    """TX PFC counters on ``peer_port`` (DUT -> TGEN direction)."""
    counts = _snapshot_pfc_counts(duthost, peer_port, pause_prio_list)
    return {int(p): counts[int(p)]["tx"] for p in pause_prio_list}


def _snapshot_pfc_rx_by_prio(duthost, peer_port, pause_prio_list):
    """RX PFC counters on ``peer_port`` (TGEN -> DUT direction)."""
    counts = _snapshot_pfc_counts(duthost, peer_port, pause_prio_list)
    return {int(p): counts[int(p)]["rx"] for p in pause_prio_list}


def _pfc_prio_counter_delta(before_by_prio, after_by_prio, prio):
    return after_by_prio[int(prio)] - before_by_prio[int(prio)]


def _pause_frames_sent_by_test(flow_stats, pause_flow_name=PAUSE_NAME_SINGLE):
    pause_row = next((m for m in flow_stats if m.name == pause_flow_name), None)
    pytest_assert(pause_row is not None, "Missing pause flow metrics for {}".format(pause_flow_name))
    return pause_row.frames_tx


def _quanta_sweep_stall_fraction(pause_quanta):
    """Fraction of data-path throughput suppressed by pause quanta (0..1)."""
    if pause_quanta <= 0:
        return 0.0
    if pause_quanta >= PAUSE_QUANTA_MAX:
        return 1.0
    return float(pause_quanta) / float(PAUSE_QUANTA_MAX)


def _quanta_sweep_pause_overlap_sec(
    data_flow_dur_sec, pause_flow_dur_sec, data_flow_delay_sec=0, pause_delay_sec=0,
):
    """
    Seconds of pause active within the data-flow transmit window.

    Both flows use Snappi fixed-duration with independent start delays. Overlap is
    computed relative to the data-flow start (delay excluded from the data duration
    used for mean-rate checks).
    """
    pause_rel_start = float(pause_delay_sec) - float(data_flow_delay_sec)
    pause_rel_end = pause_rel_start + float(pause_flow_dur_sec)
    return max(0.0, min(float(data_flow_dur_sec), pause_rel_end) - max(0.0, pause_rel_start))


def _quanta_sweep_expected_in_flight_tx_rx_mbps(
    offered_mbps,
    pause_quanta,
    data_flow_dur_sec,
    pause_flow_dur_sec,
    data_flow_delay_sec=0,
    pause_delay_sec=0,
):
    """
    Expected in-flight TGEN data-flow TX/RX Mbps for constant-pause-PPS quanta sweep.

    ``run_traffic`` samples in-flight metrics mid-test while pause and data overlap.
    TGEN continues offering at ``offered_mbps``; RX is reduced by ``pause_quanta / 0xFFFF``
    stall fraction for the duration of the pause window.
    """
    stall_frac = _quanta_sweep_stall_fraction(pause_quanta)
    overlap_sec = _quanta_sweep_pause_overlap_sec(
        data_flow_dur_sec, pause_flow_dur_sec, data_flow_delay_sec, pause_delay_sec,
    )
    expected_tx = offered_mbps
    if stall_frac <= 0.0 or overlap_sec <= 0.0:
        expected_rx = offered_mbps
    else:
        expected_rx = offered_mbps * (1.0 - stall_frac)
    return expected_tx, expected_rx


def _assert_throughput_mbps_near(actual_mbps, expected_mbps, label, offered_mbps=None):
    if expected_mbps <= 0:
        ref = offered_mbps if offered_mbps is not None else 1.0
        cap = max(QUANTA_SWEEP_STALL_RX_ABS_MBPS, QUANTA_SWEEP_STALL_RX_FRAC * ref)
        pytest_assert(
            actual_mbps <= cap,
            "{}: expected throughput ~0 (cap {:.1f} Mbps), got {:.1f} Mbps".format(
                label, cap, actual_mbps),
        )
        return
    pytest_assert(
        expected_mbps > 0.1 and actual_mbps > 0.1,
        "{}: expected non-zero throughput, got {:.1f} Mbps (expected~{:.1f})".format(
            label, actual_mbps, expected_mbps),
    )
    dev = abs(actual_mbps - expected_mbps) / max(expected_mbps, 1.0)
    pytest_assert(
        dev < QUANTA_SWEEP_RATE_TOL,
        "{}: throughput {:.1f} Mbps expected ~{:.1f} Mbps".format(
            label, actual_mbps, expected_mbps),
    )


def _assert_pfc_counter_near(actual, expected, label):
    if expected == 0:
        pytest_assert(actual == 0, "{}: expected 0, got {}".format(label, actual))
        return
    rel = abs(actual - expected) / float(expected)
    pytest_assert(
        rel < PFC_COUNTER_REL_TOL,
        "{}: expected ~{}, got {} (rel err {:.3f})".format(label, expected, actual, rel),
    )


def _ingress_tx_pfc_delta_bounds(pause_quanta):
    """
    Inclusive (min, max) ingress TX PFC delta for quanta-sweep cases.

    Zero quanta must not generate upstream PFC. Positive quanta cases must
    generate upstream PFC, but the count has no platform-independent maximum.
    """
    if pause_quanta <= 0:
        return 0, 0
    return QUANTA_SWEEP_POSITIVE_QUANTA_INGRESS_TX_PFC_MIN, None


def _assert_ingress_tx_pfc_delta(pause_quanta, delta, ingress_peer_port, prio):
    lo, hi = _ingress_tx_pfc_delta_bounds(pause_quanta)
    tag = "quanta 0x{:X} {}:{} ingress tx_pfc delta".format(
        pause_quanta, ingress_peer_port, prio)
    if hi is not None:
        pytest_assert(
            lo <= delta <= hi,
            "{}: expected {}..{}, got {}".format(tag, lo, hi, delta),
        )
        return
    pytest_assert(
        delta >= lo,
        "{}: expected >={}, got {}".format(tag, lo, delta),
    )


def _verify_quanta_sweep_pfc_counters(
    pause_quanta,
    pause_prio_list,
    ingress_peer_port,
    egress_peer_port,
    pfc_counts_before,
    pfc_counts_after,
    pause_frames_sent,
):
    """
    Verify PFC counter deltas for the quanta-sweep topology:

        IXIA Tx -> DUT ingress (``ingress_peer_port``) -> DUT egress (``egress_peer_port``) -> IXIA Rx

    Pause frames are injected from IXIA toward the DUT egress port, so RX PFC is checked on
    ``egress_peer_port``. Ingress TX PFC bounds depend on pause quanta; see
    ``_ingress_tx_pfc_delta_bounds``.
    """
    for prio in pause_prio_list:
        egress_rx_delta = _pfc_prio_counter_delta(
            pfc_counts_before["egress_rx"], pfc_counts_after["egress_rx"], prio)
        ingress_tx_delta = _pfc_prio_counter_delta(
            pfc_counts_before["ingress_tx"], pfc_counts_after["ingress_tx"], prio)

        _assert_pfc_counter_near(
            egress_rx_delta,
            pause_frames_sent,
            "quanta 0x{:X} {}:{} egress rx_pfc delta".format(
                pause_quanta, egress_peer_port, prio),
        )
        _assert_ingress_tx_pfc_delta(
            pause_quanta, ingress_tx_delta, ingress_peer_port, prio)


def _pfcwd_asic_value(duthost, port):
    if duthost.is_multi_asic:
        return duthost.get_port_asic_instance(port).get_asic_namespace()
    return None


def _parse_pfcwd_storm_restore_from_stats(stats):
    """
    Normalize ``get_pfcwd_stats`` output to storm detect / restored counts and status.

    ``get_pfcwd_stats`` returns zeros when no storm row exists for the queue.
    """
    if not stats:
        return 0, 0, "operational"

    storm_val = stats.get("STORM_DETECTED/RESTORED", "0/0")
    if isinstance(storm_val, int):
        det, res = 0, 0
    else:
        parts = str(storm_val).split("/")
        det = int(parts[0]) if parts else 0
        res = int(parts[1]) if len(parts) > 1 else 0

    status = stats.get("STATUS", "operational")
    if status in (0, "0"):
        status = "operational"
    return det, res, str(status)


def _pfcwd_stat_row(duthost, port, queue):
    """
    Return PFCWD stats for port/queue via ``get_pfcwd_stats``.

    ``show pfcwd stats`` only lists a queue after a storm episode. When no row exists,
    ``get_pfcwd_stats`` returns zero counters.
    """
    stats = get_pfcwd_stats(
        duthost, port, int(queue), asic_value=_pfcwd_asic_value(duthost, port))
    det, res, status = _parse_pfcwd_storm_restore_from_stats(stats)
    return {
        "port": port,
        "queue": str(int(queue)),
        "status": status,
        "storm_detect_count": str(det),
        "restored_count": str(res),
    }


def _pfcwd_operational_ok(status_str):
    sl = (status_str or "").lower()
    return "operational" in sl or ("storm" not in sl and sl.strip() not in ("", "n/a"))


def _snapshot_pfcwd_storm_restore_counts(duthost, peer_port, pause_prio_list):
    """
    Snapshot PFCWD storm detect / restored counters per pause priority.

    Missing queue rows (no prior storm) are recorded as zero via ``get_pfcwd_stats``.

    Returns:
        {prio: {"storm_detect_count": int, "restored_count": int, "status": str}}
    """
    counts = {}
    for prio in pause_prio_list:
        st = _pfcwd_stat_row(duthost, peer_port, prio)
        counts[int(prio)] = {
            "storm_detect_count": int(st["storm_detect_count"]),
            "restored_count": int(st["restored_count"]),
            "status": st["status"],
        }
    return counts


def _pfcwd_storm_restore_delta(before_counts, after_counts, prio):
    prio_key = int(prio)
    det_delta = after_counts[prio_key]["storm_detect_count"] - before_counts[prio_key]["storm_detect_count"]
    res_delta = after_counts[prio_key]["restored_count"] - before_counts[prio_key]["restored_count"]
    return det_delta, res_delta


def verify_quanta_sweep_constant_pps_case(
    pause_quanta,
    flow_stats,
    in_flight_metrics,
    speed_gbps,
    test_prio_list,
    pause_prio_list,
    ingress_duthost,
    ingress_peer_port,
    egress_peer_port,
    data_flow_dur_sec,
    pause_flow_dur_sec,
    data_flow_delay_sec=0,
    pause_delay_sec=0,
    pfcwd_counts_before=None,
    pfcwd_counts_after=None,
    pfc_counts_before=None,
    pfc_counts_after=None,
):
    """
    Assertions for test_pfc_storm_quanta_sweep_constant_pps.

    Expected data-flow in-flight TX/RX throughput (``_txrate_Gbps`` / ``_rxrate_Gbps`` from
    ``tgen_curr_stats`` via ``run_traffic``) account for pause-quanta hold time
    during the pause/data overlap window. PFC RX is checked on the DUT egress port (pause
    injected from IXIA); PFC TX is checked on the DUT ingress port. PFCWD storm counters use
    before/after snapshots on the DUT egress port (where the pause storm is received).
    """
    pytest_assert(
        in_flight_metrics is not None,
        "quanta 0x{:X}: missing in-flight flow metrics from run_traffic".format(pause_quanta),
    )
    rate_pct = int(TEST_FLOW_AGGR_RATE_PERCENT / len(test_prio_list))
    offered_mbps = _expected_test_flow_throughput_mbps(speed_gbps, rate_pct)
    expected_tx_mbps, expected_rx_mbps = _quanta_sweep_expected_in_flight_tx_rx_mbps(
        offered_mbps,
        pause_quanta,
        data_flow_dur_sec,
        pause_flow_dur_sec,
        data_flow_delay_sec=data_flow_delay_sec,
        pause_delay_sec=pause_delay_sec,
    )
    pause_frames_sent = _pause_frames_sent_by_test(flow_stats)
    is_vs = ingress_duthost.facts.get("asic_type") == "vs"

    for prio in test_prio_list:
        tx_mbps, rx_mbps = _tx_rx_mbps_with_counter_fallback(
            in_flight_metrics, flow_stats, prio, data_flow_dur_sec)
        tag = "quanta 0x{:X} prio {}".format(pause_quanta, prio)
        _assert_throughput_mbps_near(tx_mbps, expected_tx_mbps, "{} tx".format(tag))
        _assert_throughput_mbps_near(
            rx_mbps, expected_rx_mbps, "{} rx".format(tag), offered_mbps=offered_mbps)
        if pause_quanta == 0x0:
            rel = abs(tx_mbps - rx_mbps) / max(tx_mbps, rx_mbps, 1e-6)
            pytest_assert(
                rel < QUANTA_SWEEP_TX_RX_RATE_REL_TOL,
                "0x0 prio {}: in-flight TX and RX throughput should match, tx={:.1f} rx={:.1f} Mbps".format(
                    prio, tx_mbps, rx_mbps),
            )

    if pause_quanta == 0x0:
        for row in flow_stats:
            if row.name.startswith(PAUSE_FLOW_PREFIX):
                continue
            pytest_assert(
                row.frames_tx > 0 and row.frames_rx == row.frames_tx,
                "0x0: expected no loss on flow {}, tx={} rx={}".format(
                    row.name, row.frames_tx, row.frames_rx),
            )

    if not is_vs:
        pytest_assert(
            pfc_counts_before is not None and pfc_counts_after is not None,
            "quanta 0x{:X}: missing PFC before/after snapshots".format(pause_quanta),
        )
        pytest_assert(
            pfcwd_counts_before is not None and pfcwd_counts_after is not None,
            "quanta 0x{:X}: missing PFCWD before/after snapshots".format(pause_quanta),
        )
        _verify_quanta_sweep_pfc_counters(
            pause_quanta,
            pause_prio_list,
            ingress_peer_port,
            egress_peer_port,
            pfc_counts_before,
            pfc_counts_after,
            pause_frames_sent,
        )
        if pause_quanta == 0x0:
            for prio in pause_prio_list:
                det_delta, res_delta = _pfcwd_storm_restore_delta(
                    pfcwd_counts_before, pfcwd_counts_after, prio)
                pytest_assert(
                    det_delta == 0 and res_delta == 0,
                    "0x0: expected no PFCWD storm/restored increment on {}:{} "
                    "(det_delta={} res_delta={})".format(
                        egress_peer_port, prio, det_delta, res_delta),
                )
                pytest_assert(
                    _pfcwd_operational_ok(pfcwd_counts_after[int(prio)]["status"]),
                    "0x0: expected operational PFCWD on {} queue {}, got status={!r}".format(
                        egress_peer_port, prio, pfcwd_counts_after[int(prio)]["status"]),
                )
        elif pause_quanta == 0xFFFF:
            for prio in pause_prio_list:
                det_delta, res_delta = _pfcwd_storm_restore_delta(
                    pfcwd_counts_before, pfcwd_counts_after, prio)
                pytest_assert(
                    det_delta == 1 and res_delta == 1,
                    "0xffff: expected PFCWD storm/restored increment by 1 on {}:{} "
                    "(det_delta={} res_delta={})".format(
                        egress_peer_port, prio, det_delta, res_delta),
                )
        else:
            for prio in pause_prio_list:
                pytest_assert(
                    _pfcwd_operational_ok(pfcwd_counts_after[int(prio)]["status"]),
                    "Mid quanta 0x{:X}: expected operational PFCWD on {} queue {}, got status={!r}".format(
                        pause_quanta, egress_peer_port, prio,
                        pfcwd_counts_after[int(prio)]["status"]),
                )


def _max_pause_pps_for_link(speed_gbps):
    return max(1, int(speed_gbps * 1e9 / (8 * 64)))


def _loss_ratio(frames_tx, frames_rx):
    if frames_tx == 0:
        return 0.0
    return 1.0 - (float(frames_rx) / float(frames_tx))


def _avg_lossless_test_flow_loss_ratio(flow_stats, lossless_prio_list):
    ratios = []
    for prio in lossless_prio_list:
        needle = "{} Prio {}".format(TEST_FLOW_NAME, prio)
        for row in flow_stats:
            if needle in row.name:
                ratios.append(_loss_ratio(row.frames_tx, row.frames_rx))
                break
    pytest_assert(len(ratios) == len(lossless_prio_list),
                  "Could not find test flow stats for all lossless priorities; found {}".format(len(ratios)))
    return sum(ratios) / len(ratios)


def verify_pause_stream_dropped(flow_stats, pause_flow_name):
    pause_row = next((m for m in flow_stats if m.name == pause_flow_name), None)
    pytest_assert(pause_row is not None, "Missing pause flow metrics for {}".format(pause_flow_name))
    pytest_assert(
        pause_row.frames_tx > 0 and pause_row.frames_rx == 0,
        "{}: expected pause TX>0 and RX==0 (drops at sink), got tx={} rx={}".format(
            pause_flow_name, pause_row.frames_tx, pause_row.frames_rx),
    )


def _pause_quanta_is_max_stall(pause_quanta):
    """True when pause flow uses max hold (0xFFFF), including omitted quanta in the helper."""
    return pause_quanta is None or int(pause_quanta) >= PAUSE_QUANTA_MAX


def _verify_dut_egress_tx_drop_sanity(
        egress_duthost, dut_tx_port, ingress_hosts_ports, pause_quanta=None):
    """
    Check DUT egress TX drops against ingress RX.

    Max pause quanta (0xFFFF) may stall the path and increment egress ``tx_drp``.
    All other quanta values must show no egress TX drops.
    """
    if _pause_quanta_is_max_stall(pause_quanta):
        return

    pkt_drop = get_interface_stats(egress_duthost, dut_tx_port)[egress_duthost.hostname][dut_tx_port]["tx_drp"]
    total_rx = 0
    for ih, port in ingress_hosts_ports:
        total_rx += get_interface_stats(ih, port)[ih.hostname][port]["rx_ok"]
    if total_rx == 0:
        logger.warning("Total ingress rx_ok is 0; skip drop percentage check")
        return
    drop_pct = 100.0 * float(pkt_drop) / float(total_rx)
    pytest_assert(round(drop_pct) == 0,
                  "Unexpected egress tx_drp on {}: {} drops vs {} total ingress rx_ok ({:.4f}%)".format(
                      dut_tx_port, pkt_drop, total_rx, drop_pct))


def _pause_flow_dict(flow_name, flow_rate_pps, flow_dur_sec, flow_delay_sec, flow_quanta=None):
    cfg = {
        "flow_name": flow_name,
        "flow_dur_sec": flow_dur_sec,
        "flow_rate_percent": None,
        "flow_rate_pps": flow_rate_pps,
        "flow_rate_bps": None,
        "flow_pkt_size": 64,
        "flow_pkt_count": None,
        "flow_delay_sec": flow_delay_sec,
        "flow_traffic_type": traffic_flow_mode.FIXED_DURATION,
    }
    if flow_quanta is not None:
        cfg["flow_quanta"] = int(flow_quanta)
    return cfg


def _asic_index_for_packet_aging(port):
    """
    Derive numeric ASIC index for enable_packet_aging on DNX (see pfc_congestion_helper).
    Returns None if asic_value is missing or unparsable (caller uses host-wide enable).
    """
    av = port.get("asic_value")
    if av is None:
        return None
    s = str(av)
    if "asic" not in s.lower():
        return None
    try:
        return int(s.split("asic", 1)[1])
    except (IndexError, ValueError):
        return None


def _configure_duts(rx_port, tx_port):
    """
    Enable PFC watchdog and packet aging on path DUTs (aligned with pfc_congestion_helper).
    """
    egress_duthost = rx_port["duthost"]
    ingress_duthost = tx_port["duthost"]

    start_pfcwd(egress_duthost)
    start_pfcwd(ingress_duthost)

    rx_asic = _asic_index_for_packet_aging(rx_port)
    tx_asic = _asic_index_for_packet_aging(tx_port)
    if rx_asic is not None:
        enable_packet_aging(egress_duthost, rx_asic)
    else:
        enable_packet_aging(egress_duthost)
    if tx_asic is not None:
        enable_packet_aging(ingress_duthost, tx_asic)
    else:
        enable_packet_aging(ingress_duthost)


def run_stall_case_with_pause_params(
    api,
    testbed_config,
    port_config_list,
    snappi_ports,
    prio_dscp_map,
    pause_prio_list,
    test_prio_list,
    bg_prio_list,
    pause_pps,
    pause_quanta,
    data_flow_dur_sec,
    pause_flow_dur_sec,
    pause_delay_sec=0,
    data_flow_delay_sec=1,
    snappi_extra_params=None,
):
    """1 TGEN TX -> DUT -> 1 TGEN RX topology with test, background, and PFC pause flows."""
    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    rx_port = snappi_ports[0]
    tx_port = snappi_ports[1]
    egress_duthost = rx_port["duthost"]
    ingress_duthost = tx_port["duthost"]

    _configure_duts(rx_port, tx_port)

    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    snappi_extra_params.multi_dut_params.egress_duthosts = []
    snappi_extra_params.multi_dut_params.ingress_duthosts = []
    snappi_extra_params.multi_dut_params.egress_duthosts.append(rx_port["duthost"])
    snappi_extra_params.multi_dut_params.ingress_duthosts.append(tx_port["duthost"])

    snappi_extra_params.base_flow_config = setup_base_traffic_config(
        testbed_config=testbed_config,
        port_config_list=port_config_list,
        port_id=0,
    )

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(float(speed_str.split("_")[1]))

    test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT / len(test_prio_list))
    bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT / len(bg_prio_list))

    snappi_extra_params.traffic_flow_config.data_flow_config = {
        "flow_name": TEST_FLOW_NAME,
        "flow_dur_sec": data_flow_dur_sec,
        "flow_rate_percent": test_flow_rate_percent,
        "flow_rate_pps": None,
        "flow_rate_bps": None,
        "flow_pkt_size": DATA_PKT_SIZE,
        "flow_pkt_count": None,
        "flow_delay_sec": data_flow_delay_sec,
        "flow_traffic_type": traffic_flow_mode.FIXED_DURATION,
    }
    snappi_extra_params.traffic_flow_config.background_flow_config = {
        "flow_name": BG_FLOW_NAME,
        "flow_dur_sec": data_flow_dur_sec,
        "flow_rate_percent": bg_flow_rate_percent,
        "flow_rate_pps": None,
        "flow_rate_bps": None,
        "flow_pkt_size": DATA_PKT_SIZE,
        "flow_pkt_count": None,
        "flow_delay_sec": data_flow_delay_sec,
        "flow_traffic_type": traffic_flow_mode.FIXED_DURATION,
    }

    snappi_extra_params.traffic_flow_config.pause_flow_config = _pause_flow_dict(
        PAUSE_NAME_SINGLE, pause_pps, pause_flow_dur_sec, pause_delay_sec, pause_quanta,
    )

    no_streams = get_number_of_streams(ingress_duthost, tx_port, rx_port)
    generate_test_flows(
        testbed_config=testbed_config,
        test_flow_prio_list=test_prio_list,
        prio_dscp_map=prio_dscp_map,
        snappi_extra_params=snappi_extra_params,
        number_of_streams=no_streams,
    )
    generate_background_flows(
        testbed_config=testbed_config,
        bg_flow_prio_list=bg_prio_list,
        prio_dscp_map=prio_dscp_map,
        snappi_extra_params=snappi_extra_params,
        number_of_streams=no_streams,
    )

    generate_pause_flows(
        testbed_config=testbed_config,
        pause_prio_list=pause_prio_list,
        global_pause=False,
        snappi_extra_params=snappi_extra_params,
    )

    flows = testbed_config.flows
    all_flow_names = [f.name for f in flows]
    data_flow_names = [n for n in all_flow_names if not n.startswith(PAUSE_FLOW_PREFIX)]

    exp_dur = data_flow_dur_sec + data_flow_delay_sec
    is_vs = ingress_duthost.facts.get("asic_type") == "vs"
    pfcwd_counts_before = {}
    pfcwd_counts_after = {}
    pfc_counts_before = {}
    pfc_counts_after = {}
    if not is_vs:
        pfcwd_counts_before = _snapshot_pfcwd_storm_restore_counts(
            egress_duthost, rx_port["peer_port"], pause_prio_list)
        pfc_counts_before = {
            "ingress_tx": _snapshot_pfc_tx_by_prio(
                ingress_duthost, tx_port["peer_port"], pause_prio_list),
            "egress_rx": _snapshot_pfc_rx_by_prio(
                egress_duthost, rx_port["peer_port"], pause_prio_list),
        }

    flow_stats, _, in_flight_flow_metrics = run_traffic(
        duthost=egress_duthost,
        api=api,
        config=testbed_config,
        data_flow_names=data_flow_names,
        all_flow_names=all_flow_names,
        exp_dur_sec=exp_dur,
        snappi_extra_params=snappi_extra_params,
    )

    if not is_vs:
        pfcwd_counts_after = _snapshot_pfcwd_storm_restore_counts(
            egress_duthost, rx_port["peer_port"], pause_prio_list)
        pfc_counts_after = {
            "ingress_tx": _snapshot_pfc_tx_by_prio(
                ingress_duthost, tx_port["peer_port"], pause_prio_list),
            "egress_rx": _snapshot_pfc_rx_by_prio(
                egress_duthost, rx_port["peer_port"], pause_prio_list),
        }

    _verify_dut_egress_tx_drop_sanity(
        egress_duthost, rx_port["peer_port"], [(ingress_duthost, tx_port["peer_port"])],
        pause_quanta=pause_quanta)

    return (flow_stats, in_flight_flow_metrics, speed_gbps, egress_duthost, rx_port, tx_port,
            pfcwd_counts_before, pfcwd_counts_after, pfc_counts_before, pfc_counts_after)


def _pps_sweep_expected_throughput_fraction(pause_pps, baseline_pps):
    """
    Fraction of configured data rate expected at the TGEN after PFC throttling.

    At sub-blocking PPS with max pause quanta, IXIA reduces transmission by
    ``pause_pps / baseline_pps`` relative to the offered load (e.g. mid PPS at half
    baseline yields ~50% of line-rate test traffic with no drops).
    """
    return max(0.0, 1.0 - float(pause_pps) / float(baseline_pps))


def verify_pps_sweep_sub_blocking_case(
    pps_case,
    pause_pps,
    baseline_pps,
    flow_stats,
    in_flight_metrics,
    data_flow_dur_sec,
    speed_gbps,
    test_prio_list,
    pause_prio_list,
    ingress_duthost,
    ingress_peer_port,
    egress_duthost,
    egress_peer_port,
    pfc_counts_before=None,
    pfc_counts_after=None,
    pfcwd_counts_before=None,
    pfcwd_counts_after=None,
):
    """
    Assertions for low/mid ``test_pfc_storm_pps_sweep_constant_quanta``.

    Sub-blocking PFC PPS with max quanta throttles IXIA TX rather than dropping on the
    DUT path. Expect no loss on data flows, in-flight test-flow TX/RX throughput scaled by
    ``1 - pause_pps / baseline_pps``, egress RX PFC matching IXIA pause TX, ingress TX
    PFC reflecting DUT relay toward IXIA TX, and no PFCWD storm on the egress port.
    """
    pytest_assert(
        in_flight_metrics is not None,
        "{} PPS {}: missing in-flight flow metrics from run_traffic".format(pps_case, pause_pps),
    )
    expected_frac = _pps_sweep_expected_throughput_fraction(pause_pps, baseline_pps)
    rate_pct = int(TEST_FLOW_AGGR_RATE_PERCENT / len(test_prio_list))
    offered_mbps = _expected_test_flow_throughput_mbps(speed_gbps, rate_pct)
    expected_mbps = offered_mbps * expected_frac
    pause_frames_sent = _pause_frames_sent_by_test(flow_stats)
    is_vs = ingress_duthost.facts.get("asic_type") == "vs"

    for row in flow_stats:
        if row.name.startswith(PAUSE_FLOW_PREFIX):
            continue
        pytest_assert(
            row.frames_tx > 0 and row.frames_rx == row.frames_tx,
            "{} PPS {}: expected no loss on flow {}, tx={} rx={}".format(
                pps_case, pause_pps, row.name, row.frames_tx, row.frames_rx),
        )

    for prio in test_prio_list:
        tx_mbps, rx_mbps = _tx_rx_mbps_with_counter_fallback(
            in_flight_metrics, flow_stats, prio, data_flow_dur_sec)
        tag = "{} PPS {} prio {}".format(pps_case, pause_pps, prio)
        lo = expected_mbps * (1.0 - PPS_SWEEP_THROUGHPUT_FRAC_TOL)
        hi = expected_mbps * (1.0 + PPS_SWEEP_THROUGHPUT_FRAC_TOL)
        pytest_assert(
            lo <= tx_mbps <= hi,
            "{} tx: in-flight throughput {:.1f} Mbps expected {:.1f}±{:.0%} Mbps".format(
                tag, tx_mbps, expected_mbps, PPS_SWEEP_THROUGHPUT_FRAC_TOL),
        )
        pytest_assert(
            lo <= rx_mbps <= hi,
            "{} rx: in-flight throughput {:.1f} Mbps expected {:.1f}±{:.0%} Mbps".format(
                tag, rx_mbps, expected_mbps, PPS_SWEEP_THROUGHPUT_FRAC_TOL),
        )
        rel = abs(tx_mbps - rx_mbps) / max(tx_mbps, rx_mbps, 1e-6)
        pytest_assert(
            rel < QUANTA_SWEEP_TX_RX_RATE_REL_TOL,
            "{}: in-flight TX and RX throughput should match, tx={:.1f} rx={:.1f} Mbps".format(
                tag, tx_mbps, rx_mbps),
        )

    if not is_vs:
        pytest_assert(
            pfc_counts_before is not None and pfc_counts_after is not None,
            "{} PPS {}: missing PFC before/after snapshots".format(pps_case, pause_pps),
        )
        pytest_assert(
            pfcwd_counts_before is not None and pfcwd_counts_after is not None,
            "{} PPS {}: missing PFCWD before/after snapshots".format(pps_case, pause_pps),
        )
        for prio in pause_prio_list:
            egress_rx_delta = _pfc_prio_counter_delta(
                pfc_counts_before["egress_rx"], pfc_counts_after["egress_rx"], prio)
            ingress_tx_delta = _pfc_prio_counter_delta(
                pfc_counts_before["ingress_tx"], pfc_counts_after["ingress_tx"], prio)

            _assert_pfc_counter_near(
                egress_rx_delta,
                pause_frames_sent,
                "{} PPS {} {}:{} egress rx_pfc delta".format(
                    pps_case, pause_pps, egress_peer_port, prio),
            )
            logger.info(
                "{} PPS {} {}:{} ingress tx_pfc delta={}, IXIA pause frames sent={}".format(
                    pps_case, pause_pps, ingress_peer_port, prio,
                    ingress_tx_delta, pause_frames_sent),
            )

            det_delta, res_delta = _pfcwd_storm_restore_delta(
                pfcwd_counts_before, pfcwd_counts_after, prio)
            pytest_assert(
                det_delta == 0 and res_delta == 0,
                "{} PPS {}: expected no PFCWD storm/restored increment on {}:{} "
                "(det_delta={} res_delta={})".format(
                    pps_case, pause_pps, egress_peer_port, prio, det_delta, res_delta),
            )
            pytest_assert(
                _pfcwd_operational_ok(pfcwd_counts_after[int(prio)]["status"]),
                "{} PPS {}: expected operational PFCWD on {} queue {}, got status={!r}".format(
                    pps_case, pause_pps, egress_peer_port, prio,
                    pfcwd_counts_after[int(prio)]["status"]),
            )

        pkt_drop = get_interface_stats(
            egress_duthost, egress_peer_port)[egress_duthost.hostname][egress_peer_port]["tx_drp"]
        pytest_assert(
            pkt_drop == 0,
            "{} PPS {}: expected no egress tx_drp on {}, got {}".format(
                pps_case, pause_pps, egress_peer_port, pkt_drop),
        )


def verify_stall_on_lossless(flow_stats, lossless_prio_list):
    avg = _avg_lossless_test_flow_loss_ratio(flow_stats, lossless_prio_list)
    pytest_assert(avg >= STALL_LOSS_RATIO,
                  "Expected ingress stall (avg loss ratio >= {:.2f}), got {:.3f}".format(STALL_LOSS_RATIO, avg))


def verify_no_stall_on_lossless(flow_stats, lossless_prio_list):
    avg = _avg_lossless_test_flow_loss_ratio(flow_stats, lossless_prio_list)
    pytest_assert(avg <= NO_STALL_LOSS_RATIO,
                  "Expected no stall (avg loss ratio <= {:.2f}), got {:.3f}".format(NO_STALL_LOSS_RATIO, avg))


def assert_loss_nondecreasing_with_quanta(quanta_prev, loss_prev, quanta_curr, loss_curr):
    """At the same PPS, larger pause quanta should not materially reduce mean lossless loss."""
    if quanta_curr > quanta_prev:
        pytest_assert(
            loss_curr + 0.18 >= loss_prev,
            "Expected loss ratio not to drop sharply when quanta increases: q {}->{}, loss {:.3f}->{:.3f}".format(
                quanta_prev, quanta_curr, loss_prev, loss_curr),
        )


def baseline_blocking_pps(speed_gbps, oversubscription_ratio=1):
    return calc_pfc_pause_flow_rate(speed_gbps, oversubscription_ratio=oversubscription_ratio)


def quanta_sweep_pause_pps(speed_gbps, pause_quanta):
    """Pause PPS for quanta-sweep; 0xFFFF adds ``QUANTA_SWEEP_0XFFFF_PPS_BOOST`` over baseline."""
    pps = baseline_blocking_pps(speed_gbps)
    if pause_quanta >= PAUSE_QUANTA_MAX:
        pps += QUANTA_SWEEP_0XFFFF_PPS_BOOST
    return pps


__all__ = [
    "run_stall_case_with_pause_params",
    "verify_stall_on_lossless",
    "verify_no_stall_on_lossless",
    "verify_quanta_sweep_constant_pps_case",
    "verify_pps_sweep_sub_blocking_case",
    "assert_loss_nondecreasing_with_quanta",
    "baseline_blocking_pps",
    "quanta_sweep_pause_pps",
    "QUANTA_SWEEP_0XFFFF_PPS_BOOST",
    "_max_pause_pps_for_link",
    "verify_pause_stream_dropped",
    "PAUSE_NAME_SINGLE",
]
