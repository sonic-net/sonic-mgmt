"""
Shared helpers for PFCWD timer test suites (spytest).

This module is imported by:
  * test_v6_pfcwd_timer_detection_l3_1node.py   (detect/poll boundary)
  * test_v6_pfcwd_timer_restoration_l3_1node.py (restore boundary)

Both suites share:
  * The continuous-data + XOFF stream rig set up by `pfcwd_timer_data_stream`.
  * The `_ctx` dict that the per-class `configure_pfcwd` fixtures populate
    with the active detect/restore/poll values.
  * `_apply_pfcwd_timing` for reconfiguring PFCWD on the DUT.
  * `_run_xoff_phase`        -- single-burst detection check.
  * `_run_restoration_phase` -- multi-burst restoration check.

Keeping detection and restoration in separate test files allows the
(already-portable) detection suite to be frozen while the restoration
suite continues to evolve for cross-platform / cross-TGen support.
"""

import re
import time
import pytest

from spytest import st

import pfcwd_utils
import qos_test_utils as qos_utils
import traffic_stream_ixia_api as stream_api

# Constants reused by both L2 and L3 timer test suites. Kept in sync with
# the per-mode test modules (test_v6_pfcwd_l3_1node.py / _l2_1node.py).
FRAME_SIZE = 1024
TRAFFIC_SETTLE_SECS = 5     # Time to let traffic settle before measurements
RESTORE_MARGIN_SECS = 2     # Extra time to wait after restore_time

# Each timer test file exposes its L2 or L3 PFCWD mode module as the
# module-level name ``_mode_mod`` (e.g. ``import test_v6_pfcwd_l3_1node as
# _mode_mod``). The fixtures below look that attribute up on the *requesting*
# test module via ``request.module._mode_mod``, so two timer files collected
# in the same pytest session do not clobber each other's binding.


def _resolve_mode_mod(request):
    """Return the mode module bound by the requesting test file."""
    mode_mod = getattr(request.module, '_mode_mod', None)
    if mode_mod is None:
        raise RuntimeError(
            "pfcwd_timer_common: requesting test module "
            f"{request.module.__name__!r} does not define '_mode_mod'. "
            "Each timer test file must do e.g. "
            "`import test_v6_pfcwd_l3_1node as _mode_mod` at module scope."
        )
    return mode_mod


# XOFF rate margin above the theoretical "full block" rate.
XOFF_MARGIN_PCT = 5  # 105% of full-block rate

# Data stream rate (line %).
DATA_RATE_PERCENT = 50

# Buffer added after a burst before reading on-DUT counters so orchagent /
# pfcwd has time to update its stats (one poll interval is enough on most
# platforms).
SYSLOG_FLUSH_SECS = 1.0


# ---------------------------------------------------------------------------
# Syslog timestamp helpers (kept for diagnostic use, no longer the
# authoritative detection source -- pfcwd counter deltas are).
# ---------------------------------------------------------------------------

# Matches "May 23 14:01:02.123456" or "May  3 14:01:02.123456".
_SYSLOG_TS_RE = re.compile(
    r'\b[A-Za-z]{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}\.\d{6}\b'
)


def _dut_now_ms(dut):
    """Read current DUT wall clock in milliseconds."""
    out = st.config(dut, "date +%s%3N", skip_tmpl=True, skip_error_check=True)
    for line in (out or "").splitlines():
        line = line.strip()
        if line.isdigit():
            return int(line)
    st.warn(f"Could not parse DUT time from output: {out!r}")
    return 0


def _grep_last_timestamp_ms(dut, pattern, since_ms):
    """
    Grep /var/log/syslog for `pattern` and return the ms timestamp of the
    most recent matching line whose syslog timestamp is >= `since_ms`.
    Returns 0 if no such line is found.
    """
    cmd = f"grep -E \"{pattern}\" /var/log/syslog | tail -n 50"
    try:
        out = st.config(dut, cmd, skip_tmpl=True, skip_error_check=True)
    except Exception as e:
        st.warn(f"syslog grep failed for pattern {pattern!r}: {e}")
        return 0
    if not out:
        return 0

    best_ms = 0
    for line in out.splitlines():
        m = _SYSLOG_TS_RE.search(line)
        if not m:
            continue
        ts_str = m.group()
        try:
            ts_ms_out = st.config(
                dut,
                f"date -d '{ts_str}' +%s%3N",
                skip_tmpl=True, skip_error_check=True,
            )
        except Exception as e:
            st.warn(f"date -d failed for {ts_str!r}: {e}")
            continue
        for tok in (ts_ms_out or "").split():
            if tok.isdigit():
                ts_ms = int(tok)
                if ts_ms >= since_ms and ts_ms > best_ms:
                    best_ms = ts_ms
                break
    return best_ms


# ---------------------------------------------------------------------------
# Platform-specific preflight
# ---------------------------------------------------------------------------

# Known laguna bug: after the system has been up for a while the syncd
# queue-counter cache occasionally drops the UC0..UC7 entries on a port.
# Symptom: ``show queue counters <port>`` lists only UC8/UC9 + MC10..MC19
# (no UC0..UC7). With no per-priority unicast queue objects, PFCWD has
# nothing to bind its watchdog to: ``pfcwd show stats`` returns N/A and
# ``storm_detected`` never increments even when PFC pause is clearly
# arriving and the PG watermark is saturating. Recovery requires a DUT
# reboot. Fail fast so the next reboot/retry is obvious.

_LAGUNA_REQUIRED_QUEUES = [f"UC{i}" for i in range(8)]


def _check_laguna_unicast_queues_present(dut, port, platform):
    """If platform is laguna, assert UC0..UC7 are present on ``port``.

    Calls ``pytest.fail`` with a clear remediation hint if any are missing.
    No-op on non-laguna platforms.
    """
    if not platform or 'laguna' not in str(platform).lower():
        return
    out = st.show(dut, f"show queue counters {port}",
                  skip_tmpl=True, skip_error_check=True) or ""
    missing = [q for q in _LAGUNA_REQUIRED_QUEUES
               if not re.search(rf"\b{q}\b", out)]
    if missing:
        st.error(f"[laguna preflight] Port {port}: "
                 f"missing unicast queues {missing} from "
                 f"'show queue counters'. PFCWD cannot bind to these "
                 f"queues so the test would silently produce zero "
                 f"detections. Reboot the DUT to recover.")
        st.log(f"[laguna preflight] Raw 'show queue counters {port}' "
               f"output:\n{out}")
        pytest.fail(
            f"laguna preflight failed: port {port} is missing unicast "
            f"queue counters {missing}. This is a known laguna issue "
            f"that requires a DUT reboot."
        )
    st.log(f"[laguna preflight] Port {port}: UC0..UC7 present, OK.")


# ---------------------------------------------------------------------------
# Phase runners
# ---------------------------------------------------------------------------

def _show_pre_burst_counters(dut, egress_intf):
    """Snapshot ingress/PFC counters just before the burst for debug."""
    st.show(dut, f"show interfaces counters | grep -E 'IFACE|{egress_intf}'",
            skip_tmpl=True, skip_error_check=True)
    st.show(dut, f"show pfc counters | grep -E 'Port|{egress_intf}'",
            skip_tmpl=True, skip_error_check=True)


def _recreate_data_stream(tg, tc, phase_label):
    """
    Remove the previously cached data stream (if any) and create a
    fresh one using the kwargs cached at fixture setup. Update
    ``_ctx['data_stream_id']`` to the new handle and return it.

    IxNetwork ``apply`` regenerates the chassis's per-port traffic
    items, which silently invalidates any previously-returned
    stream-id handle. Re-running with the stale handle is a no-op:
    the test executes but no data packets actually leave the TGEN.
    Calling this helper right after every ``apply`` keeps the cached
    handle in sync with IxNet's regenerated config.

    Caller is responsible for the ``apply`` + ``run`` that follow.

    Returns: the new stream_id, or the old (best-effort) id if the
    create call fails.
    """
    old_id = _ctx.get('data_stream_id')
    data_kwargs = _ctx.get('data_stream_kwargs')
    if data_kwargs is None:
        st.warn(f"{phase_label}: _recreate_data_stream called before "
                f"fixture cached data_stream_kwargs; skipping")
        return old_id
    if old_id is not None:
        try:
            tg.tg_traffic_config(mode='remove', stream_id=old_id)
        except Exception as e:
            st.warn(f"{phase_label}: failed to remove stale data stream "
                    f"{old_id}: {e}")
    try:
        res = tg.tg_traffic_config(**data_kwargs)
    except Exception as e:
        st.error(f"{phase_label}: tg_traffic_config(create data) raised: {e}")
        return old_id
    if res.get('status') != '1':
        st.error(f"{phase_label}: tg_traffic_config(create data) failed: {res}")
        return old_id
    new_id = res['stream_id']
    try:
        stream_api.set_pfc_priority_group(tg, res, tc)
    except Exception as e:
        st.warn(f"{phase_label}: set_pfc_priority_group failed on new "
                f"data stream {new_id}: {e}")
    _ctx['data_stream_id'] = new_id
    st.log(f"{phase_label}: re-resolved data stream: old={old_id} -> "
           f"new={new_id} (kwargs cached at fixture setup)")
    return new_id


def _run_xoff_phase(dut, tg, tgen_ports, handles,
                    ingress_intf, egress_intf, src_mac, tc,
                    xoff_rate_fps, burst_duration_sec, expect_detect,
                    cfg_restore_ms, poll_ms, phase_label,
                    data_stream_id, queue=None):
    """
    Run one XOFF burst and check whether PFCWD detected a storm.

    Important: calling tg_traffic_control(action='apply') on IxNetwork
    regenerates and re-applies all traffic items, which STOPS any running
    streams. After every apply we must explicitly restart the continuous
    data stream so the egress queue has packets backed up; otherwise PFCWD
    will never observe a stuck queue and will not declare a storm even
    when XOFF is being received.

    Args:
        tc: Traffic class -- drives DSCP, PFC priority on the XOFF stream
            and on the data stream's priority group.
        queue: Hardware queue index that PFCWD monitors and that the
            queue-counter snapshots key on. On platforms with a non-identity
            ``TC_TO_QUEUE_MAP`` this differs from ``tc``; passing ``tc``
            silently looks up the wrong queue in ``show pfcwd stats``.
            Defaults to ``tc`` for back-compat.
        burst_duration_sec: Wall-clock duration the burst should cover.
            Frame count is computed as round(burst_duration_sec * xoff_rate_fps).
        expect_detect: True if PFCWD must trigger; False if it must not.
        data_stream_id: Continuous data stream handle. Will be (re)started
            after the apply so the queue is filling when XOFF arrives.

    Returns:
        bool: True if the observed behavior matches `expect_detect`.
    """
    if queue is None:
        queue = tc
    frame_count = int(round(burst_duration_sec * xoff_rate_fps))
    st.banner(f"PFCWD phase '{phase_label}': "
              f"XOFF burst duration={burst_duration_sec*1000:.0f}ms "
              f"rate={xoff_rate_fps}fps frames={frame_count} "
              f"expect_detect={expect_detect}")

    # Stop any in-flight traffic from the previous phase before reconfiguring
    # streams; otherwise the apply step below can race with running traffic.
    tg.tg_traffic_control(action='stop')
    st.wait(1)

    # Clear DUT counters / watermarks / drops so this phase's snapshots
    # show per-test deltas only.
    pfcwd_utils.clear_dut_counters(dut, phase_label)

    # Full snapshot BEFORE this phase (also gets PFCWD cumulative storm
    # counters which sonic-clear does NOT reset). Keyed by queue (not tc)
    # so the underlying ``show pfcwd stats`` / queue-counter lookups hit
    # the right rows on platforms with non-identity TC_TO_QUEUE_MAP.
    snap_before = pfcwd_utils.snapshot_pfcwd_counters(
        dut, ingress_intf, egress_intf, queue, label=f"{phase_label}/before")

    # Create XOFF single_burst stream (reset_port=False to preserve data stream).
    xoff_stream_id = stream_api.create_pfc_xoff_stream(
        tg, tgen_ports[3], src_mac, xoff_rate_fps, tc=tc,
        frame_count=frame_count, reset_port=False,
    )
    # apply regenerates ALL traffic items and stops any running streams.
    # It also silently invalidates prior stream-id handles, so the cached
    # data_stream_id passed in is no longer usable after this point.
    tg.tg_traffic_control(action='apply')
    st.wait(1)

    # Recreate the continuous data stream to get a fresh, valid handle
    # post-apply; reusing the stale id makes the subsequent run a no-op
    # and leaves the egress queue empty so PFCWD has nothing to detect.
    data_stream_id = _recreate_data_stream(tg, tc, phase_label)
    tg.tg_traffic_control(action='apply')
    st.wait(1)

    # Re-start the continuous data stream so the egress queue is backing up
    # before XOFF arrives. Without this, the queue is empty and PFCWD has
    # nothing to declare stuck.
    st.log(f"Phase '{phase_label}': restarting data stream {data_stream_id} "
           f"to fill egress queue before XOFF burst")
    tg.tg_traffic_control(action='run', stream_handle=data_stream_id)
    st.wait(2)
    _show_pre_burst_counters(dut, egress_intf)

    # Start the burst. It self-terminates after `frame_count` frames.
    storm_start_ms = _dut_now_ms(dut)
    tg.tg_traffic_control(action='run', stream_handle=xoff_stream_id)

    # Wait for the burst to complete + a small flush so the on-DUT pfcwd
    # stats counters have time to update.
    st.wait(burst_duration_sec + SYSLOG_FLUSH_SECS)

    # For the positive case, also wait long enough that any "storm restored"
    # event would have settled (one restore_time + poll_interval after
    # the burst ends).
    if expect_detect:
        st.wait((cfg_restore_ms + poll_ms) / 1000.0 + RESTORE_MARGIN_SECS)

    # Show counters for debugging.
    st.log(f"PFC counters after phase '{phase_label}':")
    st.show(dut, f"show pfc counters | grep -E 'Port|{egress_intf}'",
            skip_tmpl=True, skip_error_check=True)
    st.show(dut, "pfcwd show stats", skip_tmpl=True, skip_error_check=True)

    # Full snapshot AFTER this phase.
    snap_after = pfcwd_utils.snapshot_pfcwd_counters(
        dut, ingress_intf, egress_intf, queue, label=f"{phase_label}/after")
    delta = pfcwd_utils.get_pfcwd_stats_delta(
        snap_before['pfcwd'], snap_after['pfcwd'])
    storm_count = delta.get('storm_detected', 0)
    st.log(f"Phase '{phase_label}': pfcwd stats delta  = {delta}")

    detected = storm_count > 0
    st.log(f"Phase '{phase_label}': storm_start={storm_start_ms} "
           f"storm_detected_delta={storm_count} detected={detected}")

    # Clean up the burst stream so the next phase creates a fresh one.
    try:
        tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
    except Exception as e:
        st.warn(f"Failed to remove XOFF stream {xoff_stream_id}: {e}")

    if detected == expect_detect:
        st.log(f"Phase '{phase_label}' PASS (detected={detected})")
        return True
    st.error(f"Phase '{phase_label}' FAIL: expected detected={expect_detect}, "
             f"got detected={detected}")
    return False


def _run_restoration_phase(dut, tg, tgen_ports, handles,
                           ingress_intf, egress_intf,
                           src_mac, tc, xoff_rate_fps, burst_duration_sec,
                           inter_burst_gap_ms, burst_loop_count,
                           expect_restore_during_loop,
                           run_seconds,
                           cfg_restore_ms, poll_ms, phase_label,
                           data_stream_id,
                           tolerate_restore_during_loop=False,
                           queue=None):
    """
    Drive the PFCWD restoration timer with a HARDWARE-timed XOFF
    burst pattern, observe behavior while the pattern is running, then
    stop the pattern and observe the final restoration.

    Pattern (all transitions chassis-scheduled, Python is not in the loop):

        | XOFF burst | quiet | XOFF burst | quiet | ... | XOFF burst |
        <---------------- burst_loop_count bursts ------------------->

    Each burst lasts ``burst_duration_sec`` (chosen >= 2 * detect_time so
    the queue reliably enters/stays in 'stormed' state). Each quiet gap
    is exactly ``inter_burst_gap_ms`` milliseconds, scheduled by the
    IxNetwork chassis with sub-microsecond precision. The pattern runs
    long enough that ``run_seconds`` definitely fits inside it.

    Sequence executed by this function:
      1. Snapshot full counters BEFORE the test (stats_before).
      2. Start the XOFF multi_burst pattern.
      3. Wait ``run_seconds`` seconds for several burst/quiet cycles to fire.
      4. Snapshot counters WHILE the pattern is still running
         (stats_during).
      5. Port-wide stop of all traffic (this also stops the data stream).
      6. Wait (restore_time + poll_interval + RESTORE_MARGIN_SECS) so any
         in-flight restore can fire.
      7. Snapshot counters (stats_after).
      8. Remove the XOFF stream, restart the data stream.

    Assertions:
      Tests 1 & 2 (expect_restore_during_loop=False, i.e. quiet gap
                   <= restore_time):
        * During the loop:  storm_detected delta >= 1, storm_restored
                            delta == 0 (storm is continuous, never
                            recovers between bursts).
        * After stop+wait:  at least one storm was detected
                            (storm_detected delta >= 1) and every
                            detected storm was eventually restored
                            (detected_after == restored_after).
                            We do NOT insist on exactly one pair
                            because L2 (bridged-VLAN) topologies can
                            keep flooding small amounts of background
                            IPv6 traffic on the lossless priority after
                            TGEN stops, triggering extra detect/restore
                            cycles before the AFTER snapshot.

      Test 3 (expect_restore_during_loop=True, quiet gap > restore_time):
        * During the loop:  storm_detected delta >= 2, storm_restored
                            delta >= 1 (multiple detect/restore cycles).
        * After stop+wait:  storm_detected delta == storm_restored delta
                            (everything restored), and the final value
                            is strictly greater than the during-loop
                            value (at least one more detect/restore
                            cycle completed after the during-loop
                            snapshot).

    Args:
        burst_loop_count: how many bursts the chassis should fire. Make
            this high enough that ``run_seconds`` always fits inside
            the on-wire pattern (the caller computes this).
        expect_restore_during_loop: True if the configured gap is
            expected to allow PFCWD to restore between bursts.
        run_seconds: how long to wait between starting the pattern and
            taking the mid-pattern snapshot.

    Returns:
        bool: True if all assertions pass.
    """
    pattern_sec = (burst_loop_count * burst_duration_sec
                   + (burst_loop_count - 1) * inter_burst_gap_ms / 1000.0)
    if queue is None:
        queue = tc
    st.banner(
        f"PFCWD restoration phase '{phase_label}': "
        f"burst={burst_duration_sec*1000:.0f}ms gap={inter_burst_gap_ms}ms "
        f"x {burst_loop_count} bursts (HW-timed; total pattern="
        f"{pattern_sec:.1f}s) run_seconds={run_seconds}s "
        f"expect_restore_during_loop={expect_restore_during_loop}"
    )

    # ------------------------------------------------------------------
    # Step 1: clear DUT counters then snapshot BEFORE so this test's
    # queue drops / watermarks / port counters start from zero.
    # PFCWD stats / queue counters are keyed by HW queue, not by TC.
    # ------------------------------------------------------------------
    pfcwd_utils.clear_dut_counters(dut, phase_label)
    snap_before = pfcwd_utils.snapshot_pfcwd_counters(
        dut, ingress_intf, egress_intf, queue, label=f"{phase_label}/before")
    storm_start_ms = _dut_now_ms(dut)

    # ------------------------------------------------------------------
    # Step 2: build the HW-timed multi_burst XOFF stream and start it.
    # Creating the stream + applying regenerates IxNet traffic items,
    # which stops the data stream AND invalidates its handle. We
    # therefore re-create the data stream after apply (the old handle
    # would silently no-op when 'run' is called, manifesting as a test
    # that runs but pushes zero data packets to the DUT).
    # ------------------------------------------------------------------
    pkts_per_burst = int(round(burst_duration_sec * xoff_rate_fps))
    st.log(f"Phase '{phase_label}': pkts_per_burst={pkts_per_burst} "
           f"({burst_duration_sec*1000:.0f}ms @ {xoff_rate_fps}fps)")
    xoff_stream_id = stream_api.create_pfc_xoff_burst_stream(
        tg, tgen_ports[3], src_mac, xoff_rate_fps,
        pkts_per_burst=pkts_per_burst,
        burst_loop_count=burst_loop_count,
        inter_burst_gap_ms=inter_burst_gap_ms,
        tc=tc, reset_port=False,
    )
    tg.tg_traffic_control(action='apply')
    st.wait(1)
    # apply invalidated the data-stream handle; re-resolve before starting.
    data_stream_id = _recreate_data_stream(tg, tc, phase_label)
    tg.tg_traffic_control(action='apply')
    st.wait(1)
    st.log(f"Phase '{phase_label}': starting (re-resolved) data stream "
           f"{data_stream_id}")
    tg.tg_traffic_control(action='run', stream_handle=data_stream_id)
    st.wait(2)
    _show_pre_burst_counters(dut, egress_intf)

    # Start the chassis-scheduled XOFF pattern.
    tg.tg_traffic_control(action='run', stream_handle=xoff_stream_id)
    #import pdb; pdb.set_trace()

    # ------------------------------------------------------------------
    # Step 3 & 4: poll PFCWD stats every 1s while pattern runs, then
    # take the heavyweight DURING snapshot. The per-second sampler gives
    # a timestamped tuple-table of (t_offset_s, detected, restored,
    # status) so intermittent restores (laguna poll-alignment bug) can
    # be located in time, rather than only seeing aggregate counts at
    # the start/end of the run window.
    # ------------------------------------------------------------------
    st.log(f"Phase '{phase_label}': pattern running, polling PFCWD "
           f"stats every 1s for {run_seconds}s (mid-loop sampler)")
    base_det = snap_before['pfcwd'].get('storm_detected', 0)
    base_res = snap_before['pfcwd'].get('storm_restored', 0)
    samples = []  # list of (t_offset_s, det_delta, res_delta, status)
    loop_start = time.time()
    next_sample = loop_start
    end_time = loop_start + run_seconds
    while True:
        now = time.time()
        if now >= next_sample:
            try:
                stats = pfcwd_utils.get_pfcwd_stats_parsed(
                    dut, egress_intf, queue)
                samples.append((
                    round(now - loop_start, 2),
                    stats.get('storm_detected', 0) - base_det,
                    stats.get('storm_restored', 0) - base_res,
                    stats.get('status', 'N/A'),
                ))
            except Exception as e:
                st.warn(f"Phase '{phase_label}': mid-loop sample "
                        f"failed at t={now-loop_start:.2f}s: {e}")
            next_sample += 1.0
        if now >= end_time:
            break
        time.sleep(max(0.0, min(next_sample, end_time) - time.time()))
    # Emit the timestamped sample table as a single block for easy
    # post-mortem grep.
    table_lines = [
        f"MID-LOOP SAMPLER [{phase_label}] base_det={base_det} "
        f"base_res={base_res} samples={len(samples)}",
        "  t_offset_s | det_delta | res_delta | status",
        "  -----------+-----------+-----------+--------",
    ]
    for (t, d, r, s) in samples:
        table_lines.append(f"  {t:>10.2f} | {d:>9d} | {r:>9d} | {s}")
    st.log("\n".join(table_lines))
    snap_during = pfcwd_utils.snapshot_pfcwd_counters(
        dut, ingress_intf, egress_intf, queue, label=f"{phase_label}/during")
    delta_during = pfcwd_utils.get_pfcwd_stats_delta(
        snap_before['pfcwd'], snap_during['pfcwd'])
    detected_during = delta_during.get('storm_detected', 0)
    restored_during = delta_during.get('storm_restored', 0)
    st.log(f"Phase '{phase_label}': DURING-LOOP delta = "
           f"detected={detected_during} restored={restored_during} "
           f"(raw delta={delta_during})")

    # ------------------------------------------------------------------
    # Step 5: port-wide STOP (kills XOFF pattern AND data stream).
    # ------------------------------------------------------------------
    try:
        tg.tg_traffic_control(action='stop')
    except Exception as e:
        st.warn(f"Phase '{phase_label}': port-wide stop failed: {e}")

    # ------------------------------------------------------------------
    # Step 6: wait long enough for any pending restore to fire.
    # ------------------------------------------------------------------
    settle_sec = (cfg_restore_ms + poll_ms) / 1000.0 + RESTORE_MARGIN_SECS
    st.log(f"Phase '{phase_label}': waiting {settle_sec:.1f}s for final "
           f"restore to fire")
    st.wait(settle_sec)

    # ------------------------------------------------------------------
    # Step 7: snapshot AFTER.
    # ------------------------------------------------------------------
    snap_after = pfcwd_utils.snapshot_pfcwd_counters(
        dut, ingress_intf, egress_intf, queue, label=f"{phase_label}/after")
    delta_after = pfcwd_utils.get_pfcwd_stats_delta(
        snap_before['pfcwd'], snap_after['pfcwd'])
    detected_after = delta_after.get('storm_detected', 0)
    restored_after = delta_after.get('storm_restored', 0)
    st.log(f"Phase '{phase_label}': AFTER-STOP delta = "
           f"detected={detected_after} restored={restored_after} "
           f"(raw delta={delta_after})")

    st.log(f"PFC counters after phase '{phase_label}':")
    st.show(dut, f"show pfc counters | grep -E 'Port|{egress_intf}'",
            skip_tmpl=True, skip_error_check=True)
    st.show(dut, "pfcwd show stats", skip_tmpl=True, skip_error_check=True)

    st.log(f"Phase '{phase_label}': storm_start={storm_start_ms} "
           f"during(detected={detected_during} restored={restored_during}) "
           f"after(detected={detected_after} restored={restored_after}) "
           f"expect_restore_during_loop={expect_restore_during_loop}")

    # ------------------------------------------------------------------
    # Step 8: cleanup -- remove XOFF stream, re-resolve + restart data
    # for next test.
    # The port-wide stop above moves the multi_burst traffic item out of
    # "started" state, so the remove call should succeed cleanly.
    # Removing the XOFF stream triggers another IxNet apply internally,
    # which once again invalidates the data-stream handle -- so we
    # re-resolve before starting it.
    # ------------------------------------------------------------------
    try:
        tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
    except Exception as e:
        st.warn(f"Phase '{phase_label}': failed to remove XOFF stream "
                f"{xoff_stream_id}: {e}")
    try:
        data_stream_id = _recreate_data_stream(tg, tc, phase_label)
        tg.tg_traffic_control(action='apply')
        st.wait(1)
        tg.tg_traffic_control(action='run', stream_handle=data_stream_id)
        st.wait(1)
    except Exception as e:
        st.warn(f"Phase '{phase_label}': failed to re-resolve/restart "
                f"data stream: {e}")

    # ------------------------------------------------------------------
    # Assertions.
    # ------------------------------------------------------------------
    ok = True
    if expect_restore_during_loop:
        # Test 3: multiple full detect/restore cycles during the loop.
        if detected_during < 2:
            st.error(f"Phase '{phase_label}' FAIL [during-loop]: expected "
                     f">=2 storm detects (multiple cycles), got "
                     f"{detected_during}")
            ok = False
        if restored_during < 1:
            st.error(f"Phase '{phase_label}' FAIL [during-loop]: expected "
                     f">=1 storm restore (at least one cycle completed), "
                     f"got {restored_during}")
            ok = False
        # After stop+settle: all detects must be matched by restores.
        if detected_after != restored_after:
            st.error(f"Phase '{phase_label}' FAIL [after-stop]: expected "
                     f"detected==restored once everything quiesces, got "
                     f"detected={detected_after} restored={restored_after}")
            ok = False
        # Total cycles must not regress relative to the during-loop
        # snapshot. We use >= rather than > because the port-stop fires
        # immediately after the DURING snapshot, so a correct run may
        # have no additional cycle complete in that small window
        # (especially for short gaps where the next burst was already
        # scheduled but had not yet armed at stop time). The
        # ``detected_after == restored_after`` check above already
        # asserts every detected storm was matched by a restore.
        if detected_after < detected_during:
            st.error(f"Phase '{phase_label}' FAIL [after-stop]: expected "
                     f"detected_after ({detected_after}) >= "
                     f"detected_during ({detected_during}); cycle counter "
                     f"appears to have regressed")
            ok = False
    else:
        # Tests 1 & 2: continuous storm during the loop.
        if detected_during < 1:
            st.error(f"Phase '{phase_label}' FAIL [during-loop]: expected "
                     f">=1 storm detect (storm must arm at least once), "
                     f"got {detected_during}")
            ok = False
        # ``tolerate_restore_during_loop`` relaxes the strict
        # "restored_during == 0" rule. Use this for gap values that sit
        # within one poll_interval of the configured restore_time:
        # PFCWD on some platforms (e.g. laguna) legitimately restores
        # when the quiet window has lasted (restore_time - 1*poll), and
        # we treat that as acceptable rather than a regression.
        if not tolerate_restore_during_loop and restored_during != 0:
            st.error(f"Phase '{phase_label}' FAIL [during-loop]: expected "
                     f"restored==0 (gap too short to restore), got "
                     f"{restored_during}")
            ok = False
        elif tolerate_restore_during_loop and restored_during != 0:
            st.log(f"Phase '{phase_label}' [during-loop]: "
                   f"restored_during={restored_during} (tolerated; gap "
                   f"sits within 1 poll of restore_time)")
        # After stop+settle: PFCWD must have cleaned up every storm it
        # declared. We don't insist on exactly one detect/restore pair
        # because in L2 (bridged-VLAN) topologies the SVI/VLAN keeps
        # flooding small amounts of background IPv6 traffic (NDP, MLD,
        # RAs, etc.) on the lossless priority after the TGEN stream
        # stops. That residual flood can briefly re-fill the lossless
        # queue and trigger additional detect/restore cycles before the
        # AFTER snapshot is taken. The invariant we DO care about is:
        #   * at least one storm was detected (>=1)
        #   * every detected storm was eventually restored
        #     (detected_after == restored_after)
        if detected_after < 1:
            st.error(f"Phase '{phase_label}' FAIL [after-stop]: expected "
                     f"at least 1 storm detect over the whole test, got "
                     f"{detected_after}")
            ok = False
        if detected_after != restored_after:
            st.error(f"Phase '{phase_label}' FAIL [after-stop]: expected "
                     f"detected==restored (every storm cleaned up), got "
                     f"detected={detected_after} restored={restored_after}")
            ok = False

    if ok:
        st.log(f"Phase '{phase_label}' PASS: "
               f"during(detected={detected_during} restored={restored_during}) "
               f"after(detected={detected_after} restored={restored_after})")
        return True
    return False


# ---------------------------------------------------------------------------
# Module-scoped data stream setup (shared by all suites in the same file)
# ---------------------------------------------------------------------------

# Populated by `pfcwd_timer_data_stream` (module) and by per-class fixtures.
# Keeping it at module scope avoids passing fixture state through helper
# signatures. NOTE: each test file gets its own module-scoped fixture
# instance, but they all mutate this same dict -- safe because pytest
# runs files serially.
_ctx = {}


def _apply_pfcwd_timing(dut, detect_ms, restore_ms, poll_ms):
    """Configure PFCWD on the DUT to the given detect/restore/poll values."""
    st.banner(f"Configuring PFCWD: detect={detect_ms}ms "
              f"restore={restore_ms}ms poll={poll_ms}ms")
    st.config(dut, "sudo pfcwd stop all",
              skip_tmpl=True, skip_error_check=True)
    st.config(
        dut,
        f"sudo pfcwd start --action drop "
        f"--restoration-time {restore_ms} all {detect_ms}",
        skip_tmpl=True, skip_error_check=True,
    )
    st.config(dut, f"sudo config pfcwd interval {poll_ms}",
              skip_tmpl=True, skip_error_check=True)
    # Log the resulting config for the report.
    st.show(dut, "show pfcwd config",
            skip_tmpl=True, skip_error_check=True)


@pytest.fixture(scope='module', autouse=True)
def pfcwd_timer_data_stream(request, pfcwd_module_setup):
    """
    Create the continuous data stream P1 -> P3 once for all phase tests
    in the importing module.

    The bound test module is resolved per-request from
    ``request.module._mode_mod`` so that each timer test file uses its
    own ``data`` SpyTestDict even when several timer files are collected
    in the same pytest session.

    Yields control to the tests, then tears down the data stream and
    restores PFCWD timing to the module-setup defaults.
    """
    data = _resolve_mode_mod(request).data
    dut = data.dut
    tg = data.tg
    tc = data.tc
    # PFCWD stats / queue counters are keyed by HW queue index, not by TC.
    # On platforms with non-identity TC_TO_QUEUE_MAP these differ; using TC
    # for stat lookups silently scrapes the wrong row from `show pfcwd stats`.
    queue = data.lossless_cfg.get('queue', tc) if hasattr(data, 'lossless_cfg') else tc
    dscp = data.dscp
    port_speed = data.port_speed
    timing = data.pfcwd_timing
    platform = getattr(data, 'platform', None)
    ingress_intf = data.dut_ports[1]
    egress_intf = data.dut_ports[3]
    tgen_ports = data.tgen_ports
    handles = data.tgen_handles
    src_mac = data.dut_p3_mac

    # Remember module-setup defaults so we can restore at the end.
    default_detect_ms = int(timing['detect_time_sec'] * 1000)
    default_restore_ms = int(timing['restore_time_sec'] * 1000)
    default_poll_ms = int(timing['poll_interval_sec'] * 1000)

    st.banner("PFCWD Timer: module setup")
    st.log(f"  TC={tc} DSCP={dscp} queue={queue} port_speed={port_speed}G platform={platform}")
    st.log(f"  Module-setup PFCWD timing: "
           f"detect={default_detect_ms}ms restore={default_restore_ms}ms "
           f"poll={default_poll_ms}ms (will be restored at teardown)")

    # Laguna preflight: bail out early if UC0..UC7 queue objects are
    # missing on the egress port. See _check_laguna_unicast_queues_present
    # for details on the underlying SONiC/syncd bug.
    _check_laguna_unicast_queues_present(dut, egress_intf, platform)

    xoff_rate = pfcwd_utils.calculate_xoff_rate(
        port_speed, margin_pct=XOFF_MARGIN_PCT, platform=platform,
    )
    st.log(f"  XOFF rate ({100 + XOFF_MARGIN_PCT}% of full-block): "
           f"{xoff_rate} fps")

    ip_tos = dscp << 2
    data_stream_id = None

    # Pre-clean XOFF port.
    st.log("Pre-cleaning XOFF port to remove stale traffic items")
    tg.tg_traffic_control(
        action='reset',
        port_handle=handles[tgen_ports[3]]['port_handle'],
    )

    # Create continuous data stream P1 -> P3.
    st.banner("Creating continuous data stream P1 -> P3")
    data_kwargs = dict(
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
    data_res = tg.tg_traffic_config(**data_kwargs)
    if data_res.get('status') != '1':
        pytest.fail(f"Failed to create data stream: {data_res}")
    data_stream_id = data_res['stream_id']
    stream_api.set_pfc_priority_group(tg, data_res, tc)
    tg.tg_traffic_control(action='apply')
    st.wait(1)

    qos_utils.clear_all_counters(dut)

    st.banner("Starting continuous data traffic")
    tg.tg_traffic_control(action='run', stream_handle=data_stream_id)
    st.wait(TRAFFIC_SETTLE_SECS)

    _ctx.update(
        dut=dut, tg=tg, tc=tc, queue=queue,
        ingress_intf=ingress_intf, egress_intf=egress_intf,
        tgen_ports=tgen_ports, handles=handles,
        src_mac=src_mac,
        xoff_rate=xoff_rate,
        data_stream_id=data_stream_id,
        # Cache the data-stream config so phase code can recreate the
        # stream after every IxNet apply (apply regenerates port traffic
        # items and silently invalidates any cached stream handles --
        # the symptom is "test runs but zero data packets flow").
        data_stream_kwargs=data_kwargs,
        default_detect_ms=default_detect_ms,
        default_restore_ms=default_restore_ms,
        default_poll_ms=default_poll_ms,
    )

    yield

    # Teardown: stop traffic, remove data stream, restore PFCWD config.
    st.banner("PFCWD Timer: module teardown")
    try:
        tg.tg_traffic_control(action='stop')
    except Exception:
        pass
    if data_stream_id is not None:
        # Phase code may have recreated the data stream one or more
        # times since fixture setup; remove whatever handle is current
        # in _ctx, not the now-stale local variable.
        current_id = _ctx.get('data_stream_id', data_stream_id)
        try:
            tg.tg_traffic_config(mode='remove', stream_id=current_id)
        except Exception:
            pass
    # Restore PFCWD to module-setup defaults so other tests see the
    # documented baseline.
    try:
        _apply_pfcwd_timing(
            dut, default_detect_ms, default_restore_ms, default_poll_ms,
        )
    except Exception as e:
        st.warn(f"Failed to restore PFCWD defaults: {e}")


def _exec_phase(burst_sec, expect_detect, phase_label):
    """Convenience wrapper around _run_xoff_phase using shared _ctx."""
    return _run_xoff_phase(
        _ctx['dut'], _ctx['tg'], _ctx['tgen_ports'], _ctx['handles'],
        _ctx['ingress_intf'], _ctx['egress_intf'], _ctx['src_mac'],
        _ctx['tc'], _ctx['xoff_rate'], burst_sec, expect_detect=expect_detect,
        cfg_restore_ms=_ctx['cfg_restore_ms'], poll_ms=_ctx['poll_ms'],
        phase_label=phase_label,
        data_stream_id=_ctx['data_stream_id'],
        queue=_ctx.get('queue'),
    )


def _exec_restoration_phase(burst_sec, gap_ms, burst_loop_count,
                            expect_restore_during_loop, run_seconds,
                            phase_label,
                            tolerate_restore_during_loop=False):
    """Convenience wrapper around _run_restoration_phase using shared _ctx."""
    return _run_restoration_phase(
        _ctx['dut'], _ctx['tg'], _ctx['tgen_ports'], _ctx['handles'],
        _ctx['ingress_intf'], _ctx['egress_intf'], _ctx['src_mac'],
        _ctx['tc'], _ctx['xoff_rate'], burst_sec,
        inter_burst_gap_ms=gap_ms,
        burst_loop_count=burst_loop_count,
        expect_restore_during_loop=expect_restore_during_loop,
        run_seconds=run_seconds,
        cfg_restore_ms=_ctx['cfg_restore_ms'], poll_ms=_ctx['poll_ms'],
        phase_label=phase_label,
        data_stream_id=_ctx['data_stream_id'],
        tolerate_restore_during_loop=tolerate_restore_during_loop,
        queue=_ctx.get('queue'),
    )


def _exec_continuous_xoff_phase(check_count, check_interval_sec,
                                recovery_wait_sec, phase_label):
    """
    Negation test for premature PFCWD restoration.

    Run a CONTINUOUS XOFF stream (no bursts, no gaps) alongside the
    continuous data stream and verify PFCWD detects the storm and then
    stays armed -- repeatedly sampled. After we stop the XOFF stream,
    verify PFCWD restores exactly once.

    Sequence:
      1. Snapshot BEFORE (baseline).
      2. Start a continuous XOFF stream (apply + restart data stream so
         the queue is filling before XOFF arrives).
      3. Wait detect_time*3 + poll for the initial storm to fire.
      4. Snapshot ``check_count`` times, each separated by
         ``check_interval_sec``. For each interval verify:
            - pfcwd status == 'stormed'
            - storm_restored delta since the previous snapshot == 0
              (the queue must NOT restore while XOFF is being received).
      5. Stop the XOFF stream (keep data running).
      6. Wait ``recovery_wait_sec`` for restoration.
      7. Snapshot AFTER. Verify:
            - pfcwd status == 'operational'
            - storm_restored delta == 1 (the single armed storm
              restored when XOFF stopped).
      8. Stop data, remove the XOFF stream, restart the data stream
         (so the next test has a clean fixture).

    Args:
        check_count: number of mid-storm checks (caller chose 5).
        check_interval_sec: seconds between checks (caller chose 2).
        recovery_wait_sec: seconds to wait after stopping XOFF (caller
            chose 2; should be >= restore_time + poll).
        phase_label: label used in log lines / snapshot keys.

    Returns:
        bool: True if all assertions pass.
    """
    dut = _ctx['dut']
    tg = _ctx['tg']
    tgen_ports = _ctx['tgen_ports']
    ingress_intf = _ctx['ingress_intf']
    egress_intf = _ctx['egress_intf']
    src_mac = _ctx['src_mac']
    tc = _ctx['tc']
    # PFCWD stats / queue counters are keyed by HW queue, not by TC.
    queue = _ctx.get('queue', tc)
    xoff_rate = _ctx['xoff_rate']
    cfg_restore_ms = _ctx['cfg_restore_ms']
    poll_ms = _ctx['poll_ms']
    data_stream_id = _ctx['data_stream_id']
    # detect_time isn't stored in _ctx; the suite class sets the same
    # value as cfg_restore_ms (400/400 or 200/200), so reuse that.
    detect_ms = cfg_restore_ms

    initial_detect_wait_sec = (detect_ms * 3 + poll_ms) / 1000.0
    st.banner(
        f"PFCWD continuous-XOFF phase '{phase_label}': "
        f"check_count={check_count} check_interval={check_interval_sec}s "
        f"initial_detect_wait={initial_detect_wait_sec:.2f}s "
        f"recovery_wait={recovery_wait_sec}s "
        f"detect={detect_ms}ms restore={cfg_restore_ms}ms poll={poll_ms}ms"
    )

    # ------------------------------------------------------------------
    # Step 1: stop any leftover traffic, clear counters, snapshot BEFORE.
    # ------------------------------------------------------------------
    tg.tg_traffic_control(action='stop')
    st.wait(1)
    pfcwd_utils.clear_dut_counters(dut, phase_label)
    snap_before = pfcwd_utils.snapshot_pfcwd_counters(
        dut, ingress_intf, egress_intf, queue, label=f"{phase_label}/before")

    # ------------------------------------------------------------------
    # Step 2: build a CONTINUOUS XOFF stream and start it alongside data.
    # ------------------------------------------------------------------
    xoff_stream_id = stream_api.create_pfc_xoff_stream(
        tg, tgen_ports[3], src_mac, xoff_rate, tc=tc,
        frame_count=None, reset_port=False,
    )
    # apply regenerates ALL traffic items and invalidates any cached
    # data-stream handle, so re-resolve and re-create the data stream
    # before restarting it (otherwise the run is a silent no-op).
    tg.tg_traffic_control(action='apply')
    st.wait(1)
    data_stream_id = _recreate_data_stream(tg, tc, phase_label)
    tg.tg_traffic_control(action='apply')
    st.wait(1)
    st.log(f"Phase '{phase_label}': starting (re-resolved) data stream "
           f"{data_stream_id} to fill egress queue before continuous XOFF")
    tg.tg_traffic_control(action='run', stream_handle=data_stream_id)
    st.wait(1)
    tg.tg_traffic_control(action='run', stream_handle=xoff_stream_id)

    # ------------------------------------------------------------------
    # Step 3: wait for the initial storm detection.
    # ------------------------------------------------------------------
    st.log(f"Phase '{phase_label}': sleeping {initial_detect_wait_sec:.2f}s "
           f"for initial PFCWD detection")
    st.wait(initial_detect_wait_sec)

    snap_initial = pfcwd_utils.snapshot_pfcwd_counters(
        dut, ingress_intf, egress_intf, queue, label=f"{phase_label}/detected")
    initial_delta = pfcwd_utils.get_pfcwd_stats_delta(
        snap_before['pfcwd'], snap_initial['pfcwd'])
    initial_status = snap_initial['pfcwd'].get('status')
    detected = initial_delta.get('storm_detected', 0) >= 1
    st.log(f"Phase '{phase_label}': initial check: status={initial_status} "
           f"detected_delta={initial_delta.get('storm_detected', 0)}")

    failures = []
    if not detected:
        failures.append(
            f"initial detection: expected storm_detected >= 1, "
            f"got {initial_delta.get('storm_detected', 0)}"
        )
    if initial_status != 'stormed':
        failures.append(
            f"initial status: expected 'stormed', got '{initial_status}'"
        )

    # ------------------------------------------------------------------
    # Step 4: repeated mid-storm checks. Each check verifies the queue
    # has not restored since the previous check.
    # ------------------------------------------------------------------
    prev_snap = snap_initial
    for i in range(1, check_count + 1):
        st.log(f"Phase '{phase_label}': mid-check {i}/{check_count} -- "
               f"waiting {check_interval_sec}s")
        st.wait(check_interval_sec)
        snap_i = pfcwd_utils.snapshot_pfcwd_counters(
            dut, ingress_intf, egress_intf, queue,
            label=f"{phase_label}/check{i}")
        delta_i = pfcwd_utils.get_pfcwd_stats_delta(
            prev_snap['pfcwd'], snap_i['pfcwd'])
        status_i = snap_i['pfcwd'].get('status')
        restored_delta_i = delta_i.get('storm_restored', 0)
        detected_delta_i = delta_i.get('storm_detected', 0)
        st.log(f"Phase '{phase_label}': check{i}: status={status_i} "
               f"detected_delta={detected_delta_i} "
               f"restored_delta={restored_delta_i}")
        if status_i != 'stormed':
            failures.append(
                f"check{i}: expected status 'stormed', got '{status_i}'"
            )
        if restored_delta_i != 0:
            failures.append(
                f"check{i}: expected storm_restored delta == 0, "
                f"got {restored_delta_i} (PFCWD restored prematurely "
                f"while XOFF was being received)"
            )
        prev_snap = snap_i

    # ------------------------------------------------------------------
    # Step 5: stop the XOFF stream (keep data running).
    # ------------------------------------------------------------------
    st.log(f"Phase '{phase_label}': stopping continuous XOFF stream")
    try:
        tg.tg_traffic_control(action='stop', stream_handle=xoff_stream_id)
    except Exception as e:
        st.warn(f"Failed to stop XOFF stream {xoff_stream_id}: {e}")

    # ------------------------------------------------------------------
    # Step 6: wait for restoration.
    # ------------------------------------------------------------------
    st.log(f"Phase '{phase_label}': waiting {recovery_wait_sec}s for restore")
    st.wait(recovery_wait_sec)

    # ------------------------------------------------------------------
    # Step 7: snapshot AFTER. Validate exactly one restore vs the
    # detected-baseline snap_initial.
    # ------------------------------------------------------------------
    snap_after = pfcwd_utils.snapshot_pfcwd_counters(
        dut, ingress_intf, egress_intf, queue, label=f"{phase_label}/after")
    after_status = snap_after['pfcwd'].get('status')
    total_delta = pfcwd_utils.get_pfcwd_stats_delta(
        snap_before['pfcwd'], snap_after['pfcwd'])
    detected_total = total_delta.get('storm_detected', 0)
    restored_total = total_delta.get('storm_restored', 0)
    st.log(f"Phase '{phase_label}': recovery: status={after_status} "
           f"detected_total={detected_total} restored_total={restored_total}")

    if after_status != 'operational':
        failures.append(
            f"recovery: expected status 'operational', got '{after_status}'"
        )
    if restored_total != 1:
        failures.append(
            f"recovery: expected storm_restored delta == 1, "
            f"got {restored_total} (multiple restores indicates PFCWD "
            f"flapped during the continuous XOFF window)"
        )
    if detected_total != 1:
        failures.append(
            f"recovery: expected storm_detected delta == 1, "
            f"got {detected_total} (multiple detects indicates PFCWD "
            f"restored and re-detected during the continuous XOFF window)"
        )

    # ------------------------------------------------------------------
    # Step 8: cleanup -- stop everything, remove XOFF stream, re-resolve
    # + restart the data stream so the next test starts from a clean
    # fixture.
    # ------------------------------------------------------------------
    tg.tg_traffic_control(action='stop')
    try:
        tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
    except Exception as e:
        st.warn(f"Failed to remove XOFF stream {xoff_stream_id}: {e}")
    data_stream_id = _recreate_data_stream(tg, tc, phase_label)
    tg.tg_traffic_control(action='apply')
    st.wait(1)
    tg.tg_traffic_control(action='run', stream_handle=data_stream_id)

    if failures:
        for f in failures:
            st.error(f"Phase '{phase_label}' FAIL: {f}")
        return False
    st.log(f"Phase '{phase_label}' PASS: status stayed 'stormed' across "
           f"{check_count} checks; recovered to 'operational' after XOFF stop "
           f"with detected={detected_total} restored={restored_total}")
    return True
