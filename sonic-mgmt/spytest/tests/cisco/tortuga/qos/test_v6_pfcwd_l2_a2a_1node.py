"""
PFCWD All-to-All (A2A) L2 Single-Node Test  -- T8 (L2 variant)

Mirrors snappi: tests/snappi_tests/pfcwd/test_pfcwd_a2a_with_snappi.py.

Topology / pattern:
    3 TGEN ports (P1, P2, P3) on a single DUT, all members of a single
    untagged VLAN (L2 bridged forwarding via SVI/NDP, see
    test_v6_pfcwd_l2_1node.py for the module-fixture topology setup).
    Full directional mesh -- 6 lossless + 6 lossy data flows:
        P1->P2, P1->P3, P2->P1, P2->P3, P3->P1, P3->P2
    PFC XOFF storm is sent FROM TGEN P3 TO the DUT egress port (P3) on the
    lossless TC.

Per-flow rates: 30% lossless + 15% lossy. Each port therefore receives
~2 * (30% + 15%) = 90% of line-rate ingress, matching T9.

Pass criteria (BOTH parametrized variants):
  - The "C" (P3) port flows behave per snappi expectation:
      trigger_pfcwd=True  -> PFCWD storm_detected >= 1 AND restored >= 1
      trigger_pfcwd=False -> storm_detected == 0
  - **Isolation invariant (strict, both variants):**
      The lossless A<->B flows (P1<->P2) must see ZERO loss
      regardless of what happens on the C port. This is the whole point
      of the A2A test: a storm on one port must not affect unrelated
      flows.

Tests in this file:
    test_pfcwd_a2a_trigger_l2     -- long XOFF storm on P3; PFCWD MUST detect
                                  & restore; P1<->P2 lossless MUST be loss-free.
    test_pfcwd_a2a_no_trigger_l2  -- sub-threshold XOFF burst on P3; PFCWD
                                  MUST NOT trigger; P1<->P2 lossless MUST
                                  be loss-free.
"""

import pytest  # noqa: F401  (kept for symmetry / future use)

from spytest import st
try:
    from spytest import tgapi
except ImportError:
    tgapi = None  # tests will use fallback per-stream call below

import qos_test_utils as qos_utils
import pfcwd_utils
import traffic_stream_ixia_api as stream_api

# Reuse module fixture, helpers and shared state from the main PFCWD file
# so this test runs standalone without duplicating topology setup.
from test_v6_pfcwd_l2_1node import (
    data,
    FRAME_SIZE,
    TRAFFIC_SETTLE_SECS,
    RESTORE_MARGIN_SECS,
    get_xoff_rate,
    print_test_summary_counters,
    _parse_iface_counters_row,
    pfcwd_module_setup,  # noqa: F401 -- autouse module fixture
)


# Per-flow line-rate percentages
LOSSLESS_RATE_PCT = 30
LOSSY_RATE_PCT = 15


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_a2a_streams(tg, tgen_ports, handles, tc, dscp,
                       lossy_tc, lossy_dscp):
    """
    Create the full 6-direction mesh of (lossless, lossy) streams.

    Returns: list of dicts, each:
        {
          'sid': stream_id,
          'src_idx': 1|2|3,
          'dst_idx': 1|2|3,
          'kind': 'lossless'|'lossy',
          'label': 'P{src}->P{dst} {kind}',
        }
    """
    ip_tos_lossless = dscp << 2
    ip_tos_lossy = lossy_dscp << 2

    flows_meta = [
        # (kind, tc, dscp, ip_tos, rate_pct, set_pfc_prio)
        ('lossless', tc, dscp, ip_tos_lossless, LOSSLESS_RATE_PCT, True),
        ('lossy', lossy_tc, lossy_dscp, ip_tos_lossy, LOSSY_RATE_PCT, False),
    ]

    streams = []
    pairs = [(1, 2), (1, 3), (2, 1), (2, 3), (3, 1), (3, 2)]
    for src_idx, dst_idx in pairs:
        for kind, f_tc, f_dscp, f_tos, f_rate, set_prio in flows_meta:
            label = f"P{src_idx}->P{dst_idx} {kind}"
            st.log(
                f"Creating {label} stream  rate={f_rate}%  "
                f"TC={f_tc} DSCP={f_dscp}"
            )
            tg_kwargs = dict(
                port_handle=handles[tgen_ports[src_idx]]['port_handle'],
                port_handle2=handles[tgen_ports[dst_idx]]['port_handle'],
                mode='create',
                transmit_mode='continuous',
                rate_percent=f_rate,
                frame_size=FRAME_SIZE,
                circuit_endpoint_type='ipv6',
                ipv6_traffic_class=f_tos,
                emulation_src_handle=handles[tgen_ports[src_idx]]['int_handle'],
                emulation_dst_handle=handles[tgen_ports[dst_idx]]['int_handle'],
            )
            res = tg.tg_traffic_config(**tg_kwargs)
            if res.get('status') != '1':
                st.report_fail(
                    'msg',
                    f"Failed to create {label} stream: {res}",
                )
            sid = res['stream_id']
            if set_prio:
                stream_api.set_pfc_priority_group(tg, res, f_tc)
            streams.append({
                'sid': sid,
                'src_idx': src_idx,
                'dst_idx': dst_idx,
                'kind': kind,
                'label': label,
            })
    return streams


def _get_stream_tx_rx(tg, sid):
    """
    Extract (tx_pkts, rx_pkts) for a specific stream by querying
    per-stream stats. Using ``mode='traffic_item'`` without a
    ``stream_handle`` returns a dict keyed by traffic-item name
    (e.g. 'TI12-HLTAPI_TRAFFICITEM_540'), NOT by stream_id, so the
    previous lookup-by-sid always returned None.

    We use ``tgapi.get_traffic_stats(..., stream_handle=sid)`` which
    returns a flat dict with 'tx'/'rx' subdicts directly. Falls back
    to ``tg.tg_traffic_stats(stream_handle=sid)`` if tgapi is not
    available.
    """
    try:
        if tgapi is not None:
            entry = tgapi.get_traffic_stats(
                tg, mode='traffic_item', stream_handle=sid,
            )
        else:
            entry = tg.tg_traffic_stats(
                mode='traffic_item', stream_handle=sid,
            )
    except Exception as e:
        st.log(f"  per-stream stats query failed for sid={sid}: {e}")
        return None, None

    if not isinstance(entry, dict):
        return None, None

    # Some HLTAPI returns nest the stream stats one level deeper under
    # the stream_id key. Normalise.
    if sid in entry and isinstance(entry[sid], dict):
        entry = entry[sid]

    def _pkts(side):
        d = entry.get(side, {}) or {}
        for k in ('total_pkts', 'total_packets', 'pkts', 'frames',
                  'total_frames'):
            if k in d:
                try:
                    return int(d[k])
                except (TypeError, ValueError):
                    return None
        return None

    return _pkts('tx'), _pkts('rx')


def _verify_a2a_isolation_dut(dut, dut_ports, tc, lossy_tc):
    """
    DUT-counter-based isolation check (replaces unreliable TGEN per-stream
    parser).

    For full A2A isolation we need:
      * Lossless P1<->P2:
          - dut_ports[1] (egress to P1) UC<tc> queue drop_pkts == 0
          - dut_ports[2] (egress to P2) UC<tc> queue drop_pkts == 0
          - Interface TX_DRP on dut_ports[1] and dut_ports[2] == 0
      * Lossy P1->P3 and P2->P3:
          - dut_ports[3] (egress to P3) UC<lossy_tc> queue drop_pkts == 0
            (lossy traffic shares the storm port egress but uses a
             separate queue not paused by PFC, so it must not drop)

    The storm port dut_ports[3] UC<tc> (lossless) is NOT checked here --
    PFCWD storm action is *expected* to drop on its UC<tc> queue, and
    the storm-side checks are already covered by the PFCWD stats delta.

    Counters were cleared by ``qos_utils.clear_all_counters(dut)`` at the
    start of the test, so absolute readings == per-test deltas.

    Returns: (ok: bool, messages: list[str])
    """
    queue_lossless = f"UC{tc}"
    queue_lossy = f"UC{lossy_tc}"
    msgs = []
    overall_ok = True

    # ---- Per-queue drops ----
    queue_checks = [
        ("P1 lossless", dut_ports[1], queue_lossless),
        ("P2 lossless", dut_ports[2], queue_lossless),
        ("P3 lossy",    dut_ports[3], queue_lossy),
    ]
    for label, intf, qname in queue_checks:
        try:
            raw = st.show(
                dut, f"show queue counters {intf}",
                skip_tmpl=True, skip_error_check=True,
            )
            parsed = qos_utils.parse_queue_counters(raw, [intf])
            q = parsed.get(intf, {}).get(qname, {})
            drop = int(q.get('drop_pkts', 0))
            tx = int(q.get('counter_pkts', 0))
            ok = (drop == 0)
            msgs.append(
                f"  {label} egress {intf} {qname}: tx_pkts={tx} "
                f"drop_pkts={drop} -> {'OK' if ok else 'FAIL'}"
            )
            if not ok:
                overall_ok = False
        except Exception as e:
            msgs.append(f"  {label} {intf} queue counters read failed: {e}")
            overall_ok = False

    # ---- Interface-level TX_DRP on the lossless egress ports ----
    # (dut_ports[3] iface TX_DRP is dominated by PFCWD lossless drops, so
    #  not useful as an isolation signal -- queue-level check above is
    #  the right granularity for the lossy stream.)
    try:
        iface_out = st.show(
            dut, "show interfaces counters",
            skip_tmpl=True, skip_error_check=True,
        )
        wanted = {dut_ports[1], dut_ports[2]}
        rows = {}
        for line in iface_out.splitlines():
            r = _parse_iface_counters_row(line)
            if r and r['iface'] in wanted:
                rows[r['iface']] = r
        for label, intf in [("P1", dut_ports[1]), ("P2", dut_ports[2])]:
            r = rows.get(intf)
            if r is None:
                msgs.append(f"  {label} iface {intf}: counters not found")
                overall_ok = False
                continue
            ok = (r['tx_drp'] == 0)
            msgs.append(
                f"  {label} iface {intf}: tx_ok={r['tx_ok']} "
                f"tx_drp={r['tx_drp']} -> {'OK' if ok else 'FAIL'}"
            )
            if not ok:
                overall_ok = False
    except Exception as e:
        msgs.append(f"  interface counters read failed: {e}")
        overall_ok = False

    return overall_ok, msgs


def _verify_a2a_isolation(tg, streams):
    """
    Strict isolation check: for every lossless flow whose endpoints are
    BOTH in {P1, P2} (i.e. does NOT touch P3), require rx_pkts == tx_pkts.

    Returns: (ok: bool, messages: list[str])
    """
    msgs = []
    overall_ok = True
    for s in streams:
        if s['kind'] != 'lossless':
            continue
        if s['src_idx'] == 3 or s['dst_idx'] == 3:
            # Flows that touch P3 are EXPECTED to suffer loss when the
            # storm is active; only A<->B (P1<->P2) is the invariant.
            continue
        tx, rx = _get_stream_tx_rx(tg, s['sid'])
        if tx is None or rx is None:
            msgs.append(f"  {s['label']}: stats missing (tx={tx} rx={rx})")
            overall_ok = False
            continue
        loss = tx - rx
        ok = (loss == 0)
        msgs.append(
            f"  {s['label']}: tx={tx} rx={rx} loss={loss} "
            f"-> {'OK' if ok else 'FAIL'}"
        )
        if not ok:
            overall_ok = False
    return overall_ok, msgs


# ---------------------------------------------------------------------------
# Shared driver
# ---------------------------------------------------------------------------

def _run_a2a(trigger_pfcwd):
    dut = data.dut
    tg = data.tg
    tc = data.tc
    dscp = data.dscp
    lossy_tc = data.lossy_tc
    lossy_dscp = data.lossy_dscp
    port_speed = data.port_speed
    timing = data.pfcwd_timing
    egress_intf = data.dut_ports[3]
    tgen_ports = data.tgen_ports
    handles = data.tgen_handles

    test_name = (
        "test_pfcwd_a2a_trigger_l2" if trigger_pfcwd
        else "test_pfcwd_a2a_no_trigger_l2"
    )

    if trigger_pfcwd:
        storm_duration_sec = max(
            5.0,
            (5 * timing['detect_time_sec'])
            + (3 * timing['poll_interval_sec']) + 1.0,
        )
    else:
        # Sub-threshold burst -- under detect_time so PFCWD must NOT fire.
        storm_duration_sec = max(0.05, timing['detect_time_sec'] * 0.5)

    xoff_rate = get_xoff_rate(port_speed)

    st.banner(f"PFCWD A2A (L2): trigger_pfcwd={trigger_pfcwd}")
    st.log(f"  Platform:        {data.platform}")
    st.log(f"  Lossless TC={tc} DSCP={dscp} @ {LOSSLESS_RATE_PCT}% per flow")
    st.log(f"  Lossy    TC={lossy_tc} DSCP={lossy_dscp} @ {LOSSY_RATE_PCT}% per flow")
    st.log(f"  Port Speed:      {port_speed}G")
    st.log(f"  Ports: P1={tgen_ports[1]} P2={tgen_ports[2]} P3={tgen_ports[3]} "
           f"(egress {egress_intf})")
    st.log(f"  Detect time:     {timing['detect_time_sec']*1000:.0f} ms")
    st.log(f"  Storm duration:  {storm_duration_sec:.3f} s "
           f"({'>' if trigger_pfcwd else '<'} detect_time)")
    st.log(f"  XOFF rate:       {xoff_rate} fps")

    streams = []
    xoff_stream_id = None

    try:
        # P3 is the storm port and an A2A endpoint. Reset it once before
        # creating peer streams so leftover items are cleared, then use
        # reset_port=False on the XOFF stream to keep peer streams alive.
        st.log("Pre-cleaning P3 to remove any stale traffic items")
        tg.tg_traffic_control(
            action='reset',
            port_handle=handles[tgen_ports[3]]['port_handle'],
        )

        st.banner("Building 6x2 A2A traffic mesh (12 streams total)")
        streams = _build_a2a_streams(
            tg, tgen_ports, handles, tc, dscp, lossy_tc, lossy_dscp
        )
        st.log(f"  Created {len(streams)} streams")

        st.banner(f"Creating XOFF stream on P3 ({xoff_rate} fps)")
        if trigger_pfcwd:
            xoff_stream_id = stream_api.create_pfc_xoff_stream(
                tg, tgen_ports[3], data.dut_p3_mac, xoff_rate, tc=tc,
                reset_port=False,
            )
        else:
            pkts = max(1, int(round(xoff_rate * storm_duration_sec)))
            st.log(f"  XOFF single_burst pkts: {pkts} "
                   f"(~{(pkts/float(xoff_rate))*1000:.1f} ms on wire)")
            xoff_stream_id = stream_api.create_pfc_xoff_stream(
                tg, tgen_ports[3], data.dut_p3_mac, xoff_rate, tc=tc,
                frame_count=pkts, reset_port=False,
            )

        tg.tg_traffic_control(action='apply')
        st.wait(2)

        st.banner("Clearing DUT counters for clean baseline")
        qos_utils.clear_all_counters(dut)
        stats_before = pfcwd_utils.get_pfcwd_stats_parsed(
            dut, egress_intf, tc
        )
        st.log(f"PFCWD stats before: {stats_before}")

        # Clear TGEN per-stream stats so the loss check is over our window.
        try:
            tg.tg_traffic_control(action='clear_stats')
        except Exception as e:
            st.log(f"clear_stats warn (continuing): {e}")

        st.banner("Starting all 12 data streams")
        for s in streams:
            tg.tg_traffic_control(action='run', stream_handle=s['sid'])
        st.wait(TRAFFIC_SETTLE_SECS)

        st.banner(f"Starting XOFF storm on P3")
        tg.tg_traffic_control(action='run', stream_handle=xoff_stream_id)

        if trigger_pfcwd:
            st.log(f"Waiting {storm_duration_sec:.2f}s during storm...")
            st.wait(storm_duration_sec)
            st.banner("Stopping XOFF storm to allow restoration")
            try:
                tg.tg_traffic_control(
                    action='stop', stream_handle=xoff_stream_id
                )
            except Exception as e:
                st.log(f"XOFF stop warning (continuing): {e}")
            restore_wait = (
                timing['restore_time_sec']
                + timing['poll_interval_sec']
                + RESTORE_MARGIN_SECS
            )
            st.log(f"Waiting {restore_wait:.2f}s for PFCWD restoration...")
            st.wait(restore_wait)
        else:
            observe = (
                storm_duration_sec
                + timing['detect_time_sec']
                + timing['poll_interval_sec']
                + 0.5
            )
            st.log(f"Waiting {observe:.2f}s (burst + detect+poll observation)")
            st.wait(observe)

        stats_after = pfcwd_utils.get_pfcwd_stats_parsed(
            dut, egress_intf, tc
        )
        st.log(f"PFCWD stats after: {stats_after}")
        delta = pfcwd_utils.get_pfcwd_stats_delta(stats_before, stats_after)
        st.log(f"PFCWD delta: {delta}")

        st.banner("Stopping all traffic")
        tg.tg_traffic_control(action='stop')
        st.wait(2)

        # ---- Validate PFCWD behaviour on the storm port ----
        if trigger_pfcwd:
            det_ok, det_msg = pfcwd_utils.verify_pfcwd_triggered(
                delta, expected=True
            )
            res_ok, res_msg = pfcwd_utils.verify_pfcwd_restored(delta)
            st.log(f"detect : {det_msg}")
            st.log(f"restore: {res_msg}")
            if not det_ok:
                st.banner(f"SUMMARY: TEST FAILED: {test_name}")
                st.report_fail(
                    'msg',
                    f"A2A long storm did NOT trigger PFCWD: {det_msg}",
                )
            if not res_ok:
                st.banner(f"SUMMARY: TEST FAILED: {test_name}")
                st.report_fail(
                    'msg',
                    f"A2A long storm did NOT restore: {res_msg}",
                )
        else:
            if delta.get('storm_detected', 0) != 0:
                st.banner(f"SUMMARY: TEST FAILED: {test_name}")
                st.report_fail(
                    'msg',
                    f"A2A sub-threshold storm UNEXPECTEDLY triggered "
                    f"PFCWD: storm_detected={delta['storm_detected']}",
                )

        # ---- Validate isolation via DUT counters ----
        # (TGEN per-stream stats lookup was unreliable -- it returned
        #  None for every stream in laguna_pfcwd_a2a_Fail_20.log,
        #  causing false failures.)
        st.banner(
            "Verifying A2A isolation via DUT counters "
            f"(P1/P2 egress UC{tc} drops, P3 egress UC{lossy_tc} "
            f"lossy drops, P1/P2 iface TX_DRP all == 0)"
        )
        iso_ok, iso_msgs = _verify_a2a_isolation_dut(
            dut, data.dut_ports, tc, lossy_tc,
        )
        for m in iso_msgs:
            st.log(m)

        # NOTE: TGEN per-stream isolation check temporarily disabled --
        # tg_traffic_stats() lookup-by-stream-id returned (None, None)
        # for every flow on this platform/IxNetwork build. Will revisit
        # once we have a working per-stream stats path.
        # iso_ok, iso_msgs = _verify_a2a_isolation(tg, streams)
        # for m in iso_msgs:
        #     st.log(m)

        if not iso_ok:
            st.banner(f"SUMMARY: TEST FAILED: {test_name}")
            st.report_fail(
                'msg',
                "A2A isolation violated: P1<->P2 lossless flows saw loss "
                "while storm was on P3.",
            )

        st.banner(f"SUMMARY: TEST PASSED: {test_name}")
        st.log(f"  Platform:           {data.platform}")
        st.log(f"  trigger_pfcwd:      {trigger_pfcwd}")
        st.log(f"  storm_duration_sec: {storm_duration_sec:.3f}")
        st.log(f"  storm_detected:     {delta.get('storm_detected', 0)}")
        st.log(f"  storm_restored:     {delta.get('storm_restored', 0)}")
        st.log(f"  tx_drop:            {delta.get('tx_drop', 0)}")
        st.log(f"  Isolation: OK (P1/P2 UC{tc} drops==0, P3 UC{lossy_tc} "
               f"lossy drops==0, P1/P2 TX_DRP==0)")
        st.report_pass("test_case_passed", f"{test_name} passed")

    except Exception as e:
        st.banner(f"SUMMARY: TEST FAILED: {test_name}")
        st.error(f"Test failed with exception: {e}")
        import traceback
        st.log(traceback.format_exc())
        st.report_fail('msg', f"Test failed: {e}")

    finally:
        # Print birdseye counter summary (always, even on failure)
        try:
            print_test_summary_counters(
                dut, data.dut_ports, egress_intf, tc=tc
            )
        except Exception as _e_summary:
            st.log(f"summary counters not captured: {_e_summary}")
        try:
            tg.tg_traffic_control(action='stop')
        except Exception:
            pass
        for s in streams:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=s['sid'])
            except Exception as e:
                st.log(f"remove data stream {s['sid']} warn: {e}")
        if xoff_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
            except Exception as e:
                st.log(f"remove XOFF stream warn: {e}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_pfcwd_a2a_trigger_l2():
    """A2A mesh + long XOFF storm on P3 -- PFCWD MUST detect & restore;
    P1<->P2 lossless MUST be loss-free."""
    _run_a2a(trigger_pfcwd=True)


def test_pfcwd_a2a_no_trigger_l2():
    """A2A mesh + sub-threshold XOFF burst on P3 -- PFCWD MUST NOT trigger;
    P1<->P2 lossless MUST be loss-free."""
    _run_a2a(trigger_pfcwd=False)
