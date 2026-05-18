"""
Standalone PFC XOFF rate calibration test.

This test characterizes the minimum PFC XOFF frame rate that fully blocks
a DUT egress port for a lossless traffic class. It is informational only
(always reports PASS) and is intentionally NOT a PFCWD test -- the watchdog
is disabled during calibration so storm-induced drops/restores do not
confuse the measurement.

Infrastructure (topology fixture, helpers) is shared with
``test_v6_pfcwd_l3_1node`` to avoid duplication. The autouse module
fixture from that file is imported and re-bound locally so this test
file can be run on its own.
"""

import pytest  # noqa: F401  (kept for symmetry / future use)

from spytest import st

# Shared modules (must be on sys.path the same way as in the pfcwd file).
import qos_test_utils as qos_utils
import pfcwd_utils
import traffic_stream_ixia_api as stream_api

# Tell the imported pfcwd_module_setup fixture to skip enabling PFCWD.
# Calibration must run with the watchdog stopped so storm-induced
# drops/restores do not perturb the bisection measurement.
SKIP_PFCWD_CONFIG = True

# Reuse helpers, constants, module-state and autouse fixture from the
# PFCWD test file. The imported ``pfcwd_module_setup`` carries its pytest
# fixture marker (scope='module', autouse=True), so pytest discovers it
# in this module's namespace and runs it automatically for this file too.
from test_v6_pfcwd_l3_1node import (
    data,
    DATA_RATE_PERCENT,
    FRAME_SIZE,
    TRAFFIC_SETTLE_SECS,
    get_xoff_rate,
    set_queue_counterpoll_interval,
    get_queue_tx_packets,
    _check_traffic_blocked,
    pfcwd_module_setup,  # noqa: F401 -- autouse fixture, must be imported
)


def test_pfc_xoff_rate_calibration():
    """
    Bisection search for the minimum PFC XOFF frame rate that fully blocks
    the egress port. Informational only -- always reports pass.

    Algorithm:
      - Set queue counterpoll to 1000ms for accurate measurements
      - theoretical = port_speed / (512 * 0xffff)
      - Gamut (n9164e) uses 2x pause quanta, so start at theoretical/2
      - Bisection over [0, 80000] fps, max 25 iterations
      - Each iteration:
          * Start XOFF stream at `mid` fps (~10s window)
          * Sample queue TX counter at 3s and 6s
          * If counter incremented: traffic flowing -> search higher
          * Else: blocked -> search lower
      - Verify found rate with tests at rate-1, rate, rate+1

    PFCWD is disabled during calibration so storm-induced drops don't
    confuse measurements; re-enabled in finally.
    """
    dut = data.dut
    tg = data.tg
    tc = data.tc
    dscp = data.dscp
    port_speed = data.port_speed
    platform = data.platform
    egress_intf = data.dut_ports[3]
    tgen_ports = data.tgen_ports
    handles = data.tgen_handles

    # Theoretical XOFF rate with pause quanta 0xffff and zero margin.
    theoretical = pfcwd_utils.calculate_xoff_rate(port_speed, margin_pct=0)

    # Gamut platforms use 2x pause quanta -> half the rate fully pauses.
    if platform == 'n9164e':
        effective_theoretical = theoretical // 2
        st.log(f"Gamut platform: effective theoretical = theoretical/2 = "
               f"{effective_theoretical} fps")
    else:
        effective_theoretical = theoretical

    # Search range: 0 to 80000 fps (wide range to find actual blocking point)
    low = 0
    high = 80000

    # Calibration parameters
    # log2(80000) ~= 16.3, so 20 iterations is sufficient for convergence
    max_iterations = 25
    xoff_window_sec = 10.0      # Run XOFF for 10 seconds per iteration
    sample_delay_sec = 3.0      # Wait 3s before first sample
    sample_interval_sec = 3.0   # Wait 3s between samples

    st.banner("PFC XOFF Rate Calibration (informational, no pass/fail)")
    st.log(f"  Platform: {platform}")
    st.log(f"  Port Speed: {port_speed}G, TC: {tc}, DSCP: {dscp}")
    st.log(f"  Theoretical (quanta=0xffff): {theoretical} fps")
    st.log(f"  Effective theoretical:       {effective_theoretical} fps")
    st.log(f"  Search range: [{low}, {high}] fps")
    st.log(f"  Max iterations: {max_iterations}")
    st.log(f"  XOFF window: {xoff_window_sec}s, sample at {sample_delay_sec}s "
           f"and {sample_delay_sec + sample_interval_sec}s")

    ip_tos = dscp << 2
    data_stream_id = None
    xoff_stream_id = None
    blocking_rate = None
    results = []
    orig_counterpoll_interval = None

    try:
        # Step 1: Set queue counterpoll to 1 second for accurate measurements
        st.banner("Setting queue counterpoll interval to 1000ms")
        orig_counterpoll_interval = set_queue_counterpoll_interval(dut, 1000)
        st.log(f"  Original interval was: {orig_counterpoll_interval}ms")

        # PFCWD is already stopped by the module fixture (SKIP_PFCWD_CONFIG=True).

        # Step 3: Clean stale traffic on XOFF port, then create data stream
        st.log("Pre-cleaning XOFF port to remove any stale traffic items")
        tg.tg_traffic_control(
            action='reset', port_handle=handles[tgen_ports[3]]['port_handle']
        )

        st.banner(f"Creating continuous data stream at {DATA_RATE_PERCENT}% "
                  f"from T1D3P1 -> T1D3P3")
        tg_kwargs = dict(
            port_handle=handles[tgen_ports[1]]['port_handle'],
            port_handle2=handles[tgen_ports[3]]['port_handle'],
            mode='create',
            transmit_mode='continuous',
            rate_percent=DATA_RATE_PERCENT,
            frame_size=FRAME_SIZE,
            circuit_endpoint_type='ipv6',
            ipv6_traffic_class=ip_tos,
            emulation_src_handle=handles[tgen_ports[1]]['int_handle'],
            emulation_dst_handle=handles[tgen_ports[3]]['int_handle'],
        )
        data_result = tg.tg_traffic_config(**tg_kwargs)
        if data_result.get('status') != '1':
            st.report_fail('msg', f"Failed to create data stream: {data_result}")
        data_stream_id = data_result['stream_id']
        stream_api.set_pfc_priority_group(tg, data_result, tc)
        tg.tg_traffic_control(action='apply')
        st.wait(2)

        st.banner("Starting data traffic (kept running through entire cal)")
        tg.tg_traffic_control(action='run', stream_handle=data_stream_id)
        st.wait(TRAFFIC_SETTLE_SECS)

        # Step 3.5: Sanity check - verify data traffic is actually flowing
        # Without this check, we could get false "BLOCKED" results if traffic
        # never started (queue counter would be static with delta=0)
        st.banner("Verifying data traffic is flowing (sanity check)")
        sanity_cnt1 = get_queue_tx_packets(dut, egress_intf, tc)
        st.log(f"  Queue TX packets (sample 1): {sanity_cnt1}")
        st.wait(3)
        sanity_cnt2 = get_queue_tx_packets(dut, egress_intf, tc)
        st.log(f"  Queue TX packets (sample 2): {sanity_cnt2}")
        sanity_delta = sanity_cnt2 - sanity_cnt1
        st.log(f"  Delta over 3s: {sanity_delta}")

        if sanity_delta <= 0:
            st.report_fail(
                'msg',
                f"SANITY CHECK FAILED: Data traffic is NOT flowing! "
                f"Queue counter did not increase (cnt1={sanity_cnt1}, "
                f"cnt2={sanity_cnt2}, delta={sanity_delta}). "
                f"Check data stream configuration and DUT forwarding."
            )

        st.log(f"  SANITY CHECK PASSED: Traffic is flowing "
               f"({sanity_delta} pkts in 3s)")

        # Step 4: Bisection search
        # We search for the minimum rate that blocks traffic.
        # low = lowest rate known to NOT block (or lower bound)
        # high = lowest rate known to BLOCK (or upper bound)
        for i in range(1, max_iterations + 1):
            # Compute midpoint, rounding up to avoid getting stuck
            mid = (low + high + 1) // 2

            st.banner(
                f"Iter {i}/{max_iterations}: testing {mid} fps "
                f"(range=[{low}, {high}], delta={high - low})"
            )

            # Create XOFF stream at this rate (single_burst with extra
            # headroom so it lasts longer than xoff_window_sec).
            pkts = int(mid * xoff_window_sec) * 10
            st.log(f"  Creating XOFF stream: {mid} fps, ~{pkts} frames "
                   f"over {xoff_window_sec}s")

            xoff_stream_id = stream_api.create_pfc_xoff_stream(
                tg, tgen_ports[3], data.dut_p3_mac, mid, tc=tc,
                frame_count=pkts, reset_port=False,
            )
            tg.tg_traffic_control(action='apply')
            st.wait(1)

            # IxNetwork 'apply' stops all traffic - restart data stream
            # 2s before XOFF to ensure it is flowing.
            st.log("  Restarting data stream after apply")
            tg.tg_traffic_control(action='run', stream_handle=data_stream_id)
            st.wait(2)

            st.log(f"  Starting XOFF stream @ {mid} fps")
            tg.tg_traffic_control(action='run', stream_handle=xoff_stream_id)

            st.log(f"  Waiting {sample_delay_sec}s before first sample...")
            st.wait(sample_delay_sec)

            blocked, cnt1, cnt2 = _check_traffic_blocked(
                dut, egress_intf, tc, sample_interval_sec
            )

            st.log("  Stopping XOFF stream")
            tg.tg_traffic_control(action='stop', stream_handle=xoff_stream_id)
            st.wait(1)

            try:
                tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
            except Exception as e:
                st.log(f"  Could not remove XOFF stream: {e}")
            xoff_stream_id = None

            results.append((mid, cnt1, cnt2, blocked))
            st.log(f"  Result: {mid} fps -> "
                   f"{'BLOCKED' if blocked else 'FLOWING'} "
                   f"(cnt1={cnt1}, cnt2={cnt2}, delta={cnt2 - cnt1})")

            if blocked:
                high = mid
                blocking_rate = mid
            else:
                low = mid

            if high - low <= 1:
                st.log(f"  Search converged at iter {i} "
                       f"(range delta={high - low})")
                break

            if low == mid and blocked:
                st.log(f"  Converged: low==mid=={mid}, blocked=True")
                blocking_rate = mid
                break

        # Step 5: Verification at rate-1, rate, rate+1
        if blocking_rate is not None:
            st.banner(f"Verifying found rate: {blocking_rate} fps")
            st.log("  Testing at rate-1, rate, rate+1 to confirm boundary")

            verification_results = []
            for test_rate in [blocking_rate - 1, blocking_rate,
                              blocking_rate + 1]:
                if test_rate < 1:
                    st.log(f"  Skipping rate {test_rate} (< 1)")
                    verification_results.append((test_rate, None, None, None))
                    continue

                st.log(f"  Verifying at {test_rate} fps...")
                pkts = int(test_rate * xoff_window_sec) + 10

                xoff_stream_id = stream_api.create_pfc_xoff_stream(
                    tg, tgen_ports[3], data.dut_p3_mac, test_rate, tc=tc,
                    frame_count=pkts, reset_port=False,
                )
                tg.tg_traffic_control(action='apply')
                st.wait(1)

                tg.tg_traffic_control(action='run', stream_handle=data_stream_id)
                st.wait(2)

                tg.tg_traffic_control(action='run', stream_handle=xoff_stream_id)
                st.wait(sample_delay_sec)

                blocked, cnt1, cnt2 = _check_traffic_blocked(
                    dut, egress_intf, tc, sample_interval_sec
                )

                tg.tg_traffic_control(action='stop', stream_handle=xoff_stream_id)
                st.wait(1)

                try:
                    tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
                except Exception:
                    pass
                xoff_stream_id = None

                verification_results.append((test_rate, cnt1, cnt2, blocked))
                st.log(f"    {test_rate} fps: "
                       f"{'BLOCKED' if blocked else 'FLOWING'}")

            st.log("  Verification summary:")
            for rate, c1, c2, blk in verification_results:
                if c1 is not None:
                    expected = "BLOCKED" if rate >= blocking_rate else "FLOWING"
                    actual = "BLOCKED" if blk else "FLOWING"
                    match = "OK" if expected == actual else "MISMATCH"
                    st.log(f"    {rate} fps: {actual} (expected {expected}) "
                           f"{match}")

        # Step 6: Stop data stream
        st.banner("Stopping data stream")
        tg.tg_traffic_control(action='stop', stream_handle=data_stream_id)
        st.wait(2)

        # Summary
        st.banner("Calibration Results")
        st.log("Bisection search history:")
        for mid_r, c1, c2, blk in results:
            st.log(f"  {mid_r:>6} fps -> "
                   f"{'BLOCKED' if blk else 'FLOWING':8} "
                   f"(cnt1={c1}, cnt2={c2}, delta={c2 - c1})")

        if blocking_rate is not None and theoretical > 0:
            ratio_th = blocking_rate / float(theoretical)
            ratio_eff = blocking_rate / float(effective_theoretical)
            st.log("")
            st.log(f"Minimum blocking XOFF rate: {blocking_rate} fps")
            st.log(f"  vs theoretical ({theoretical} fps):     "
                   f"{ratio_th * 100:.1f}%")
            st.log(f"  vs effective theoretical ({effective_theoretical} fps): "
                   f"{ratio_eff * 100:.1f}%")
        else:
            st.log(f"No blocking rate found within search range "
                   f"[{low}, {high}]")

        st.banner("SUMMARY: TEST PASSED: test_pfc_xoff_rate_calibration")
        st.log("Summary:")
        st.log(f"  Platform: {platform}")
        st.log(f"  Port Speed: {port_speed}G")
        st.log(f"  Theoretical: {theoretical} fps "
               f"(effective: {effective_theoretical} fps)")
        st.log(f"  Min blocking rate (measured): {blocking_rate} fps")
        st.report_pass(
            "test_case_passed",
            "test_pfc_xoff_rate_calibration completed (informational)"
        )

    except Exception as e:
        st.banner("SUMMARY: TEST FAILED: test_pfc_xoff_rate_calibration")
        st.error(f"Test failed with exception: {e}")
        import traceback
        st.log(traceback.format_exc())
        st.report_fail('msg', f"Test failed: {e}")

    finally:
        # Stop all traffic
        try:
            tg.tg_traffic_control(action='stop')
        except Exception:
            pass

        # Remove streams
        if xoff_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
            except Exception as e:
                st.log(f"Failed to remove XOFF stream: {e}")
        if data_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=data_stream_id)
            except Exception as e:
                st.log(f"Failed to remove data stream: {e}")

        # Restore queue counterpoll interval
        if orig_counterpoll_interval is not None:
            try:
                st.banner(f"Restoring queue counterpoll to "
                          f"{orig_counterpoll_interval}ms")
                set_queue_counterpoll_interval(dut, orig_counterpoll_interval)
            except Exception as e:
                st.log(f"Failed to restore counterpoll interval: {e}")

        # Restore PFCWD
        try:
            st.banner("Re-enabling PFCWD after calibration")
            pfcwd_utils.enable_pfcwd(dut)
        except Exception as e:
            st.log(f"Failed to re-enable PFCWD: {e}")
