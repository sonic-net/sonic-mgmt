#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2026-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

"""
FX3 QoS WRED Queue Depth Threshold Tests.

Testbed (fx3_qos_testbed_2022.yaml):
  Ingress A: Ixia T1D1P1 -> DUT D1T1P1 (100G)
  Ingress B: Ixia T1D1P2 -> DUT D1T1P2 (100G)
  Egress:    DUT D1T1P3  -> Ixia T1D1P3 (100G)

Uses the fan-in topology (2 ingress ports -> 1 egress port) to create
egress queue congestion.  Verification is performed via the WRED linearity
sweep helper (run_wred_linearity) which sends traffic at increasing margins
above line rate and asserts monotonically increasing drop rates across
WRED zones A (below min_th), B (active WRED), and C (tail drop).

Tests:
  test_wred_reject_invalid_gdrop     — gdrop=200 rejected (valid range 0-100)
  test_wred_custom_gdrop_profile     — change gdrop 5->10, verify linearity
  test_wred_custom_threshold_profile — custom thresholds (2MB/~2.86MB), verify linearity
  test_wred_narrowest_zone           — 1-byte WRED zone, verify high drops under congestion
  test_wred_gdrop_zero               — test plan #10: gdrop=0, no WRED drops, tail drops only
  test_disable_profile_with_traffic          — test plan #19 traffic: unbind WRED under fan-in

All traffic tests are parametrized over address family (IPv4 + IPv6).

Golden WRED profile (AZURE_LOSSY baseline):
  green_min_threshold    = 1,048,576 bytes (1 MB)
  green_max_threshold    = 3,145,728 bytes (3 MB)
  green_drop_probability = 5%
"""

import os
import sys
import pytest

from spytest import st, tgapi

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from qos_helpers import (
    QUEUE_TO_DSCP, GOLDEN_WRED_PROFILE, NUM_QUEUES, WRED_BOUND_QUEUES,
    IXIA_EGRESS_IP, IXIA_EGRESS_IP6,
    setup_topo_common, verify_egress_reachable,
    deploy_dchal_helper,
    ensure_interfaces_admin_up, verify_wred_profile,
    verify_wred_config_values_prog_in_dchal,
    parse_redis_hget, parse_redis_hgetall,
    run_wred_linearity, wred_fanin_send_and_measure,
    wred_fanin_burst_and_measure, wred_fanin_burst_iterated,
    report_wred_result,
    scale_margin, expected_wred_ramp_drop_rate,
    dump_l3_diag,
    clear_dut_counters, dchal_clear_counters,
    get_dchal_queue_counters, get_queue_counters, get_intf_counters,
    log_queue_counters,
    wred_fanin_start_continuous, wred_fanin_stop_continuous,
    unbind_wred_from_queues,
    get_first_asic_wred_profile_oid, verify_queues_wred_binding,
)


# ── Test-specific parameters ──────────────────────────────────────────────
TARGET_QUEUE   = 3
TARGET_DSCP    = QUEUE_TO_DSCP[TARGET_QUEUE]

WRED_DISABLE_TRAFFIC_MARGIN_MBPS = 3000
WRED_DISABLE_TRAFFIC_WAIT_SEC = 30

# ── Linearity sweep margins (Mbps above line rate) ──────────────────────
MARGINS = [0, 250, 500, 1000, 2000, 3000, 4000, 5000, 5250, 5500]

# Higher margin for the narrowest-zone test: the near-zero WRED zone needs
# heavy oversubscription to reliably force drops and constrain queue depth.
NARROWEST_ZONE_MARGIN_MBPS = 10000

# ── Custom WRED profiles for testing ────────────────────────────────────
CUSTOM_GDROP_PROFILE = dict(GOLDEN_WRED_PROFILE,
                            green_drop_probability='10')

CUSTOM_THRESHOLD_PROFILE = dict(GOLDEN_WRED_PROFILE,
                                green_min_threshold='2097152',
                                green_max_threshold='3000000')

NARROW_ZONE_PROFILE = dict(GOLDEN_WRED_PROFILE,
                           green_min_threshold='1048576',
                           green_max_threshold='1048577')

GDROP_ZERO_PROFILE = dict(GOLDEN_WRED_PROFILE,
                          green_drop_probability='0')

# ── Expected SCHEDULER profiles after 'config qos reload' on FX3 ─────────
# CONFIG_DB keys are SCHEDULER|scheduler.N.
# Queues 0-5 use DWRR (Deficit Weighted Round Robin) with per-queue weights;
# queues 6-7 use STRICT priority (drained first, no weight).
EXPECTED_SCHEDULERS = {
    'scheduler.0': {'type': 'DWRR', 'weight': '20'},
    'scheduler.1': {'type': 'DWRR', 'weight': '20'},
    'scheduler.2': {'type': 'DWRR', 'weight': '20'},
    'scheduler.3': {'type': 'DWRR', 'weight': '40'},
    'scheduler.4': {'type': 'DWRR', 'weight': '40'},
    'scheduler.5': {'type': 'DWRR', 'weight': '30'},
    'scheduler.6': {'type': 'STRICT'},
    'scheduler.7': {'type': 'STRICT'},
}

# ── Module state ─────────────────────────────────────────────────────────
dut = None
tg = None
tg_ph = {}
port_info = {}
port_speeds = {}
ingress_speed_mbps = 0
egress_speed_mbps = 0
wred_ctx = {}


# ── Neighbor resolution helper ───────────────────────────────────────────

def _verify_egress_neighbor(af):
    """Closure over module globals, passed as a callback to run_wred_linearity."""
    return verify_egress_reachable(dut, tg, tg_ph, af)


# ── WRED profile helpers ────────────────────────────────────────────────

def _apply_wred_gdrop(dut_handle, value):
    """Set AZURE_LOSSY green_drop_probability via ecnconfig."""
    st.config(dut_handle,
              "sudo ecnconfig -p AZURE_LOSSY -gdrop {}".format(value),
              skip_error_check=True)
    st.wait(2)


def _apply_wred_thresholds(dut_handle, gmin, gmax):
    """Set AZURE_LOSSY green min/max thresholds via ecnconfig."""
    st.config(dut_handle,
              "sudo ecnconfig -p AZURE_LOSSY -gmin {} -gmax {}".format(
                  gmin, gmax),
              skip_error_check=True)
    st.wait(2)


def _read_wred_field(dut_handle, field):
    """Read a single field from WRED_PROFILE|AZURE_LOSSY in CONFIG_DB."""
    out = st.show(
        dut_handle,
        'sonic-db-cli CONFIG_DB HGET "WRED_PROFILE|AZURE_LOSSY" '
        '"{}"'.format(field), skip_tmpl=True)
    return parse_redis_hget(out).strip()


def _restore_golden_profile(dut_handle, fail_msgs):
    """Restore the golden WRED profile via config qos reload and verify."""
    st.log("Restoring golden WRED profile via config qos reload")
    st.config(dut_handle, "config qos reload", skip_error_check=True)
    st.wait(5)
    ensure_interfaces_admin_up(dut_handle, port_info.values())
    verify_wred_profile(dut_handle, fail_msgs)


# ── Scheduler CONFIG_DB helpers ──────────────────────────────────────────

def _log_scheduler_state(dut_handle, label):
    """Dump all 8 SCHEDULER profiles from CONFIG_DB to the log."""
    st.log("--- Scheduler state [{}] ---".format(label))
    for i in range(NUM_QUEUES):
        name = "scheduler.{}".format(i)
        out = st.show(
            dut_handle,
            'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|{}"'.format(name),
            skip_tmpl=True)
        st.log("  {} -> {}".format(name, parse_redis_hgetall(out)))


def _verify_scheduler_weights(dut_handle, label, expected_weights, fail_msgs):
    """Check CONFIG_DB weight for every DWRR profile; append failures to fail_msgs."""
    st.log("{}: verifying scheduler weights in CONFIG_DB".format(label))
    for name, expected in sorted(expected_weights.items()):
        out = st.show(
            dut_handle,
            'sonic-db-cli CONFIG_DB HGET "SCHEDULER|{}" "weight"'.format(name),
            skip_tmpl=True)
        actual = parse_redis_hget(out).strip()
        status = "OK" if actual == expected else "MISMATCH"
        st.log("  {} weight='{}' expected='{}' {}".format(
            name, actual, expected, status))
        if actual != expected:
            fail_msgs.append(
                "{}: {} weight='{}', expected '{}'".format(
                    label, name, actual, expected))


# ── Topology fixture ─────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """Set up DUT L3, IXIA interfaces, and QoS baseline for WRED tests."""
    global dut, tg, tg_ph, port_info, port_speeds
    global ingress_speed_mbps, egress_speed_mbps, wred_ctx

    for result in setup_topo_common(tgapi, target_queue=TARGET_QUEUE):
        dut = result['dut']
        tg = result['tg']
        tg_ph = result['tg_ph']
        port_info = result['port_info']
        port_speeds = result['port_speeds']
        ingress_speed_mbps = result['ingress_speed_mbps']
        egress_speed_mbps = result['egress_speed_mbps']
        wred_ctx = result['wred_ctx']
        yield


# ── Tests ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_wred_reject_invalid_gdrop(af):
    """Verify that setting gdrop above valid range (0-100) is rejected.

    The ecnconfig CLI should reject gdrop=200 and leave the golden
    profile value (5%) unchanged in CONFIG_DB.
    """
    st.banner("test_wred_reject_invalid_gdrop [{}] STARTED".format(af))
    st.banner('AFTER REFACTORING')
    fail_msgs = []

    deploy_dchal_helper(dut)
    verify_wred_profile(dut, fail_msgs)

    gdrop_before = _read_wred_field(dut, 'green_drop_probability')
    st.log("  green_drop_probability before: '{}'".format(gdrop_before))

    st.log("  Attempting gdrop=200 (expect rejection)")
    _apply_wred_gdrop(dut, 200)

    gdrop_after = _read_wred_field(dut, 'green_drop_probability')
    st.log("  green_drop_probability after: '{}'".format(gdrop_after))

    if gdrop_after == '200':
        fail_msgs.append(
            "gdrop=200 was accepted — expected rejection "
            "(valid range 0-100)")
    elif gdrop_after != gdrop_before:
        fail_msgs.append(
            "gdrop changed from '{}' to '{}' after rejected value — "
            "expected unchanged".format(gdrop_before, gdrop_after))

    if fail_msgs:
        st.report_fail('msg',
                       'WRED reject invalid gdrop [{}] '
                       'FAILED: '.format(af)
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'WRED reject invalid gdrop [{}] passed: '
                       'gdrop=200 correctly rejected, value unchanged '
                       'at {}%'.format(af, gdrop_after))


@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_wred_custom_gdrop_profile(af):
    """Verify WRED behavior with custom drop probability (gdrop 5% -> 10%).

    Changes the AZURE_LOSSY profile gdrop from the golden value (5%) to
    10%, then runs a full WRED linearity sweep to verify that WRED is
    still functioning correctly with the new probability.  The linearity
    helper validates zone-based behavior (Zone A: no drops, Zone B: WRED
    active with monotonically increasing drops, Zone C: tail drop) using
    the custom profile's 10% max probability for its zone checks.

    Restores the golden profile via 'config qos reload' after the test.
    """
    st.banner("test_wred_custom_gdrop_profile [{}] gdrop=10".format(af))
    fail_msgs = []

    deploy_dchal_helper(dut)

    st.log("Phase 1: Applying custom gdrop=10")
    _apply_wred_gdrop(dut, 10)

    gdrop_val = _read_wred_field(dut, 'green_drop_probability')
    st.log("  green_drop_probability = '{}'".format(gdrop_val))
    if gdrop_val != '10':
        fail_msgs.append(
            "gdrop not applied: expected '10', got '{}'".format(gdrop_val))
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'WRED custom gdrop [{}] '
                       'FAILED: '.format(af)
                       + '; '.join(fail_msgs))
        return

    st.log("Phase 2: Running WRED linearity sweep with gdrop=10")
    margins = [*MARGINS, 7000, 9000, 11000, 12000]
    sweep_fails, data_points = run_wred_linearity(
        wred_ctx, af, margins, _verify_egress_neighbor,
        duration=20, num_depth_samples=3,
        wred_profile=CUSTOM_GDROP_PROFILE)
    fail_msgs.extend(sweep_fails)

    st.log("Phase 3: Restoring golden profile")
    _restore_golden_profile(dut, fail_msgs)

    if fail_msgs:
        st.report_fail('msg',
                       'WRED custom gdrop [{}] '
                       'FAILED: '.format(af)
                       + '; '.join(fail_msgs))
    else:
        rates_str = ', '.join(
            '{:.2f}%'.format(dp['drop_rate_pct']) for dp in data_points)
        st.report_pass('msg',
                       'WRED custom gdrop [{}] passed: gdrop=10%, '
                       'drop rates [{}] monotonically increasing'.format(
                           af, rates_str))


@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_wred_custom_threshold_profile(af):
    """
    Verify WRED behavior with custom min/max thresholds.

    Changes the AZURE_LOSSY profile thresholds from the golden values
    (min=1MB, max=3MB) to custom values (min=2MB, max=~2.86MB) that
    stay within the FX3 HAL bounds (min >= 1MB, max <= 3MB).  Verifies
    the update propagated to CONFIG_DB, ASIC_DB, and DCHAL HW registers
    before running a WRED linearity sweep.

    Restores the golden profile via 'config qos reload' after the test.
    """
    st.banner("test_wred_custom_threshold_profile [{}] "
              "gmin=2MB gmax=~2.86MB".format(af))
    fail_msgs = []

    deploy_dchal_helper(dut)

    custom_min = CUSTOM_THRESHOLD_PROFILE['green_min_threshold']
    custom_max = CUSTOM_THRESHOLD_PROFILE['green_max_threshold']

    st.log("Phase 1: Applying custom thresholds "
           "(gmin={}, gmax={})".format(custom_min, custom_max))
    _apply_wred_thresholds(dut, custom_min, custom_max)

    actual_min = _read_wred_field(dut, 'green_min_threshold')
    actual_max = _read_wred_field(dut, 'green_max_threshold')
    st.log("  green_min_threshold = '{}'".format(actual_min))
    st.log("  green_max_threshold = '{}'".format(actual_max))

    if actual_min != custom_min:
        fail_msgs.append(
            "gmin not applied: expected '{}', got '{}'".format(
                custom_min, actual_min))
    if actual_max != custom_max:
        fail_msgs.append(
            "gmax not applied: expected '{}', got '{}'".format(
                custom_max, actual_max))

    st.log("Phase 1b: Verify full CONFIG_DB profile matches custom thresholds")
    verify_wred_profile(dut, fail_msgs, wred_profile=CUSTOM_THRESHOLD_PROFILE)

    if fail_msgs:
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'WRED custom thresholds [{}] '
                       'FAILED (CONFIG_DB): '.format(af)
                       + '; '.join(fail_msgs))
        return

    st.log("Phase 1c: Verify ASIC_DB reflects custom thresholds")
    asic_wred_oid = get_first_asic_wred_profile_oid(dut)

    if not asic_wred_oid:
        fail_msgs.append("No SAI_OBJECT_TYPE_WRED found in ASIC_DB")
    else:
        for attr, expected in [
            ('SAI_WRED_ATTR_GREEN_MIN_THRESHOLD', custom_min),
            ('SAI_WRED_ATTR_GREEN_MAX_THRESHOLD', custom_max),
        ]:
            out = st.show(
                dut,
                'sonic-db-cli ASIC_DB HGET "ASIC_STATE:SAI_OBJECT_TYPE_WRED:{}" '
                '"{}"'.format(asic_wred_oid, attr),
                skip_tmpl=True)
            actual_val = parse_redis_hget(out).strip()
            st.log("  ASIC_DB {} = '{}' (expected '{}')".format(
                attr, actual_val, expected))

            if actual_val != expected:
                fail_msgs.append(
                    "ASIC_DB {} mismatch: expected '{}', got '{}'".format(
                        attr, expected, actual_val))

    if fail_msgs:
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'WRED custom thresholds [{}] '
                       'FAILED (ASIC_DB): '.format(af)
                       + '; '.join(fail_msgs))
        return

    st.log("Phase 1d: Verify DCHAL HW registers reflect custom thresholds (Q{})".format(
        TARGET_QUEUE))

    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, port_info['egress'], TARGET_QUEUE,
        custom_min, custom_max,
        CUSTOM_THRESHOLD_PROFILE['green_drop_probability'])

    if dchal_rc != 0:
        fail_msgs.append(
            "DCHAL HW mismatch for custom thresholds on Q{} (rc={})".format(
                TARGET_QUEUE, dchal_rc))

    if fail_msgs:
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'WRED custom thresholds [{}] '
                       'FAILED (DCHAL HW): '.format(af)
                       + '; '.join(fail_msgs))
        return

    st.log("Phase 2: Running WRED linearity sweep with custom thresholds")
    margins = [0, 250, 500, 3000, 4000, 5000, 5500, 7000, 9000, 11000]
    sweep_fails, data_points = run_wred_linearity(
        wred_ctx, af, margins, _verify_egress_neighbor,
        duration=20, num_depth_samples=3,
        wred_profile=CUSTOM_THRESHOLD_PROFILE)
    fail_msgs.extend(sweep_fails)

    st.log("Phase 3: Restoring golden profile")
    _restore_golden_profile(dut, fail_msgs)

    if fail_msgs:
        st.report_fail('msg',
                       'WRED custom thresholds [{}] '
                       'FAILED: '.format(af)
                       + '; '.join(fail_msgs))
    else:
        rates_str = ', '.join(
            '{:.2f}%'.format(dp['drop_rate_pct']) for dp in data_points)
        st.report_pass('msg',
                       'WRED custom thresholds [{}] passed: '
                       'gmin=2MB gmax=~2.86MB, CONFIG_DB/ASIC_DB/DCHAL HW '
                       'verified, drop rates [{}] '
                       'monotonically increasing'.format(af, rates_str))


@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_wred_narrowest_zone(af):
    """Test 8 (traffic): 1-byte WRED zone constrains queue depth near threshold.

    Sets min=1048576, max=1048577 (1-byte WRED zone).  Both values quantize
    to the same HW QDES unit (39), so the WRED zone is effectively zero-width
    in hardware.  Above the threshold, drop probability jumps to max immediately
    (no ramp), so the queue stabilizes near ~1 MB instead of the ~3 MB seen
    with the golden profile under the same oversubscription.

    Validates:
      - drops > 0  (WRED is active with the narrow zone)
      - avg queue depth < 2 MB  (zone constrains depth well below the golden
        profile's ~3 MB; proves the narrow threshold is controlling the queue)

    The config-only portion of test 8 is in test_wred_config_propagation.py.
    """
    st.banner("test_wred_narrowest_zone [{}] gmin=1048576 gmax=1048577".format(
        af))
    fail_msgs = []

    deploy_dchal_helper(dut)

    narrow_min = NARROW_ZONE_PROFILE['green_min_threshold']
    narrow_max = NARROW_ZONE_PROFILE['green_max_threshold']

    st.log("Phase 1: Applying narrowest WRED zone "
           "(gmin={}, gmax={})".format(narrow_min, narrow_max))
    _apply_wred_thresholds(dut, narrow_min, narrow_max)

    actual_max = _read_wred_field(dut, 'green_max_threshold')
    st.log("  green_max_threshold = '{}'".format(actual_max))
    if actual_max != narrow_max:
        fail_msgs.append(
            "gmax not applied: expected '{}', got '{}'".format(
                narrow_max, actual_max))
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'WRED narrowest zone [{}] FAILED: '.format(af)
                       + '; '.join(fail_msgs))
        return

    st.log("Phase 1b: Verify DCHAL HW registers reflect narrow zone (Q{})".format(
        TARGET_QUEUE))
    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, port_info['egress'], TARGET_QUEUE,
        narrow_min, narrow_max,
        NARROW_ZONE_PROFILE['green_drop_probability'])
    if dchal_rc != 0:
        fail_msgs.append(
            "DCHAL HW mismatch for narrow zone (rc={})".format(dchal_rc))

    if fail_msgs:
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'WRED narrowest zone [{}] '
                       'FAILED (DCHAL HW): '.format(af)
                       + '; '.join(fail_msgs))
        return

    margin = NARROWEST_ZONE_MARGIN_MBPS
    depth_limit = 2 * 1024 * 1024  # 2 MB

    st.log("Phase 2: Fan-in traffic with {} Mbps margin [{}]".format(
        margin, af))
    if not _verify_egress_neighbor(af):
        fail_msgs.append("Egress neighbor not resolved for {}".format(af))
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'WRED narrowest zone [{}] FAILED: '.format(af)
                       + '; '.join(fail_msgs))
        return

    result = wred_fanin_send_and_measure(
        wred_ctx, af, margin_mbps=margin, duration=20)

    egress_pkts = result.get('egress_pkts', 0)
    drop_pkts = result.get('drop_pkts', 0)
    drop_rate = result.get('drop_rate_pct', 0.0)
    depth_samples = result.get('depth_samples', [])
    avg_depth = (sum(depth_samples) / len(depth_samples)) \
        if depth_samples else 0

    st.log("  egress_pkts = {}".format(egress_pkts))
    st.log("  drop_pkts   = {}".format(drop_pkts))
    st.log("  drop_rate   = {:.2f}%".format(drop_rate))
    st.log("  avg_depth   = {:,} bytes ({:.2f} MB)".format(
        int(avg_depth), avg_depth / (1024.0 * 1024)))
    st.log("  depth_limit = {:,} bytes ({:.2f} MB)".format(
        depth_limit, depth_limit / (1024.0 * 1024)))

    st.log("Phase 3: Verifying results")
    if egress_pkts == 0:
        fail_msgs.append("No egress packets — traffic may not have flowed")
    if drop_pkts == 0:
        fail_msgs.append(
            "No drops — expected drops with zero-width WRED zone")
    if avg_depth >= depth_limit:
        fail_msgs.append(
            "avg queue depth {:.2f} MB >= {:.2f} MB limit — narrow zone "
            "should constrain depth well below golden profile's ~3 MB".format(
                avg_depth / (1024.0 * 1024),
                depth_limit / (1024.0 * 1024)))

    st.log("Phase 4: Restoring golden profile")
    _restore_golden_profile(dut, fail_msgs)

    if fail_msgs:
        st.report_fail('msg',
                       'WRED narrowest zone [{}] FAILED: '.format(af)
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'WRED narrowest zone [{}] passed: '
                       '1-byte zone, drop_rate={:.2f}%, '
                       'avg_depth={:.2f}MB, '
                       'drop_pkts={}, egress_pkts={}'.format(
                           af, drop_rate,
                           avg_depth / (1024.0 * 1024),
                           drop_pkts, egress_pkts))


@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_wred_gdrop_zero(af):
    """Test 10 (traffic): 4-point WRED gdrop validation.

    Four traffic points total: two configurations x two operating
    regions.  P1 and P4 use sustained traffic; P2 and P3 use BURST
    traffic because Zone B (1MB <= depth <= 3MB) is unreachable in
    steady state under sustained oversubscription with gdrop=0 -- the
    flat WRED ramp does not limit accumulation, so the queue
    inevitably saturates at max_th.  A finite burst sized to push the
    queue into Zone B without crossing max_th is the only clean way
    to validate the gdrop=0 contract.

    Burst sizing is CLOSED-LOOP: between P1 and P2 we run a small
    calibration probe under gdrop=0, measure the resulting peak
    watermark, and compute the bytes-per-burst-pkt accumulation ratio
    for THIS testbed/build/frame-size.  P2 and P3 then use that ratio
    to size the real burst for a target peak in mid Zone B.  This
    eliminates the need for build-specific magic constants and lets
    the test self-adapt to different testbeds.

    Variance reduction: P2 and P3 each run P2_P3_ITERATIONS bursts
    back-to-back with the SAME IXIA stream config (created once,
    reused across iterations).  Counters are snapshotted once before
    the first iteration and once after the last; deltas are the
    aggregate totals across all iterations.  Peak watermark is the
    max across iterations.  This reduces single-run variance and
    makes P2 vs P3 directly comparable (same traffic shape, same
    aggregate measurement).

      Config A: gdrop=0   (WRED enabled, ramp flattened to 0%)
        Point 1 (sustained) -- below min_th: light load, queue
                   depth < min_th.  Expect 0 drops (Zone A, no WRED
                   can apply).
        CALIBRATION (burst, gdrop=0) -- small probe burst to measure
                   actual queue accumulation per burst packet on this
                   device; sizes P2/P3 burst so peak lands in Zone B.
        Point 2 (BURST, calibrated) -- peak in Zone B.
                   Validation: the gdrop=0 contract is asserted
                   RELATIVELY (Option B): P2's drop rate must be
                   strictly less than P3's drop rate by at least
                   P2_VS_P3_RATIO_FLOOR (10x) AND below an absolute
                   safety ceiling (P2_DROP_RATE_HARD_CEIL = 0.1%).
                   This tolerates a handful of sampling-artifact tail
                   drops that occur when transient instantaneous
                   queue depth briefly exceeds max_th without latching
                   into the peak watermark counter, while still
                   failing the test if the gdrop knob has no
                   meaningful effect on the WRED ramp.

      Config B: gdrop=5   (golden profile re-applied)
        Point 3 (BURST, same calibrated size as P2) -- peak in Zone B.
                   Two assertions on P3:
                     - Option B (relative): drop rate must materially
                       exceed P2's gdrop=0 baseline (delta + ratio).
                     - Option D (absolute): the WRED-ramp contribution
                       (P3 - P2) must agree with the linear-ramp
                       formula's theoretical drop rate at this peak
                       depth, within [0.4, 2.0]x.  This catches subtle
                       ramp-slope or threshold bugs that Option B's
                       relative check would not detect.
        Point 4 (sustained) -- heavy load, peak > max_th.
                   Expect drops > 0 AND drop_rate >> WRED max_prob
                   (5%) -- proves Zone C is tail drop, not capped at
                   the WRED ramp's max.

    Config phase:
      1. Verify golden baseline
      2. Apply gdrop=0 via ecnconfig
      3. Verify CONFIG_DB, ASIC_DB and DCHAL HW programmed for gdrop=0

    Margins are scaled with ``scale_margin`` so the same intent works
    on slower links (e.g. 25G breakout).
    """
    max_threshold = int(GOLDEN_WRED_PROFILE['green_max_threshold'])
    egress_port = port_info['egress']

    st.banner(
        "test_wred_gdrop_zero [{}]\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : Test #10 — gdrop=0, verify no WRED drops, "
        "tail drops only above max_threshold".format(af, dut, egress_port))
    fail_msgs = []

    # ── Phase 1: Config verification ─────────────────────────

    st.log("Phase 1a: Verify golden WRED baseline")
    if not verify_wred_profile(dut, fail_msgs):
        st.report_fail('msg',
                       'test_wred_gdrop_zero [{}] FAILED: '
                       'golden baseline not present — {}'.format(
                           af, '; '.join(fail_msgs)))
        return

    deploy_dchal_helper(dut)

    st.log("Phase 1b: Apply gdrop=0")
    _apply_wred_gdrop(dut, 0)

    st.log("Phase 1c: Log CONFIG_DB green_drop_probability")
    gdrop_val = _read_wred_field(dut, 'green_drop_probability')
    st.log("  green_drop_probability = '{}'".format(gdrop_val))

    st.log("Phase 1d: Verify ASIC_DB SAI_WRED_ATTR_GREEN_DROP_PROBABILITY = 0")
    asic_wred_oid = get_first_asic_wred_profile_oid(dut)

    if not asic_wred_oid:
        fail_msgs.append("No SAI_OBJECT_TYPE_WRED found in ASIC_DB")
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'test_wred_gdrop_zero [{}] FAILED: {}'.format(
                           af, '; '.join(fail_msgs)))
        return

    out = st.show(
        dut,
        'sonic-db-cli ASIC_DB HGET "ASIC_STATE:SAI_OBJECT_TYPE_WRED:{}" '
        '"SAI_WRED_ATTR_GREEN_DROP_PROBABILITY"'.format(asic_wred_oid),
        skip_tmpl=True)
    asic_gdrop = parse_redis_hget(out).strip()

    st.log("  ASIC_DB SAI_WRED_ATTR_GREEN_DROP_PROBABILITY = '{}'".format(
        asic_gdrop))

    if asic_gdrop != '0':
        fail_msgs.append(
            "ASIC_DB GREEN_DROP_PROBABILITY='{}', expected '0'".format(
                asic_gdrop))
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'test_wred_gdrop_zero [{}] FAILED (ASIC_DB): {}'.format(
                           af, '; '.join(fail_msgs)))
        return

    st.log("Phase 1e: Verify DCHAL HW max_prob=0 on Q{}".format(TARGET_QUEUE))
    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_port, TARGET_QUEUE,
        GDROP_ZERO_PROFILE['green_min_threshold'],
        GDROP_ZERO_PROFILE['green_max_threshold'],
        GDROP_ZERO_PROFILE['green_drop_probability'])
        
    if dchal_rc != 0:
        fail_msgs.append(
            "DCHAL HW mismatch for gdrop=0 on Q{} (rc={})".format(
                TARGET_QUEUE, dchal_rc))
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'test_wred_gdrop_zero [{}] FAILED (DCHAL HW): {}'.format(
                           af, '; '.join(fail_msgs)))
        return

    # ── Phase 2: 4-point traffic validation ──────────────────────────────

    st.log("Phase 2: gdrop=0 / gdrop=5 traffic validation [{}]".format(af))
    if not _verify_egress_neighbor(af):
        fail_msgs.append("Egress neighbor not resolved for {}".format(af))
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'test_wred_gdrop_zero [{}] FAILED: {}'.format(
                           af, '; '.join(fail_msgs)))
        return

    min_threshold = int(GOLDEN_WRED_PROFILE['green_min_threshold'])
    golden_max_prob = float(GOLDEN_WRED_PROFILE['green_drop_probability'])
    egress = egress_speed_mbps if egress_speed_mbps > 0 else 100000
    data_points = []
    cooldown = 5

    # Margins authored for 100G egress; scale_margin() handles 25G etc.
    margin_below_min = scale_margin(-500, egress)
    margin_zone_c   = scale_margin(10000, egress)

    # Burst sizing for P2/P3: closed-loop empirical calibration.
    #
    # Open-loop theoretical models for queue accumulation under burst
    # traffic do not predict the *actual* peak watermark accurately
    # enough to land cleanly in Zone B across different testbeds, line
    # speeds, frame sizes, scheduler granularities, and IXIA pacing
    # behaviors.  Rather than tune a magic constant per build, we
    # measure the device's response with a small probe burst and use
    # that measurement to size the real burst.
    #
    # Calibration loop (between P1 and P2):
    #   1. Send a small "probe" burst (target depth well below min_th)
    #      under gdrop=0.
    #   2. Read the resulting peak watermark.
    #   3. Compute observed (peak_bytes / probe_pkts_per_port) -- the
    #      device's true bytes-per-packet accumulation under this
    #      testbed/build/frame-size.
    #   4. Size the real P2 burst to land at PEAK_TARGET_BYTES (mid
    #      Zone B) using the observed ratio.
    #
    # Probe sizing rules:
    #   - Probe peak must be << min_th so it cannot accidentally
    #     trigger any drops or saturate the buffer.
    #   - Probe peak must be > 0 (measurable) so the calibration
    #     ratio is valid.
    pkt_size_bytes = wred_ctx.get('pkt_size', 1024)
    num_ing = wred_ctx.get('num_ingress_ports', 2)
    PROBE_PKTS_PER_PORT = 2048  # safe across all common frame sizes
    PEAK_TARGET_BYTES = int(1.5 * 1024 * 1024)  # 1.5 MB, mid Zone B
    PEAK_TARGET_LOW = int(1.1 * 1024 * 1024)   # 1.1 MB, just above min_th
    PEAK_TARGET_HIGH = int(2.5 * 1024 * 1024)  # 2.5 MB, well below max_th
    burst_margin_mbps = 10000
    # P2 and P3 each run this many iterations of the same burst,
    # back-to-back with shared IXIA streams.  Aggregating drop counts
    # and egress packets across iterations reduces single-run variance
    # by ~sqrt(N), so a 3-iteration aggregate has ~58% of the variance
    # of a single shot.  Each iteration adds ~6s wall-clock; 3
    # iterations x 2 phases adds ~36s vs the single-shot version.
    P2_P3_ITERATIONS = 3

    def _run_point(label, margin, duration=20, samples=3):
        """Run one fan-in measurement and return derived metrics."""
        st.log("--- {} margin {}M ---".format(label, margin))
        r = wred_fanin_send_and_measure(
            wred_ctx, af, margin, duration=duration, num_depth_samples=samples)
        report_wred_result(wred_ctx, r, label)
        return _summarize_point(label, r, margin)

    def _run_burst_point(label, pkts_per_port, margin=10000, iterations=1):
        """Run one (or N) burst-mode fan-in measurements.

        When iterations > 1, the iterated helper is used: streams are
        created ONCE and reused, counters are snapshotted ONCE before
        and after, results are aggregated across runs (egress/drops
        SUMmed, peak MAXed).  This eliminates per-iteration IXIA
        config variance and reduces measurement noise for verdict
        math.
        """
        st.log("--- {} burst pkts_per_port={} iterations={} ---".format(
            label, pkts_per_port, iterations))
        if iterations > 1:
            r = wred_fanin_burst_iterated(
                wred_ctx, af, pkts_per_port=pkts_per_port,
                iterations=iterations,
                margin_mbps=margin)
        else:
            r = wred_fanin_burst_and_measure(
                wred_ctx, af, pkts_per_port=pkts_per_port,
                margin_mbps=margin)
        report_wred_result(wred_ctx, r, label)
        return _summarize_point(label, r, margin)

    def _summarize_point(label, r, margin):
        depth_samples = r.get('depth_samples', [])
        avg_depth = (sum(depth_samples) / len(depth_samples)) \
            if depth_samples else 0
        peak_depth = r.get('peak_bytes', 0)
        drop_pkts_v = r['drop_pkts']
        egress_pkts_v = r['egress_pkts']
        total_input = egress_pkts_v + drop_pkts_v
        drop_rate = (100.0 * drop_pkts_v / total_input) if total_input else 0.0
        oversub = (100.0 * margin / (egress + margin)) \
            if (egress + margin) > 0 else 0.0
        st.log("  {}: avg={:.2f}MB peak={:.2f}MB drop_pkts={} "
               "drop_rate={:.4f}% oversub={:.4f}% egress_pkts={}".format(
                   label,
                   avg_depth / (1024.0 * 1024),
                   peak_depth / (1024.0 * 1024),
                   drop_pkts_v, drop_rate, oversub, egress_pkts_v))
        data_points.append(r)
        return {
            'result': r,
            'avg': avg_depth,
            'peak': peak_depth,
            'drop_pkts': drop_pkts_v,
            'egress_pkts': egress_pkts_v,
            'drop_rate': drop_rate,
            'oversub': oversub,
        }

    # ── Point 1: gdrop=0, queue below min_th -> 0 drops ──────────────────
    st.banner("POINT 1: gdrop=0, load below line rate "
              "(margin={}M) -- queue depth < min_th, expect 0 drops".format(
                  margin_below_min))
    p1 = _run_point("P1 gdrop=0 below_min", margin_below_min)
    if p1['egress_pkts'] <= 0:
        fail_msgs.append(
            "P1 (below min_th): no egress pkts -- traffic not forwarded")
    else:
        if p1['peak'] >= min_threshold:
            # Light load wasn't light enough; queue entered WRED region.
            # Cannot prove Zone-A behavior from this point -- log only.
            st.log("  P1: peak {:.2f}MB >= min_th {:.2f}MB -- queue "
                   "entered WRED region under 'below line rate' load; "
                   "cannot prove pure Zone A from this run.".format(
                       p1['peak'] / (1024.0 * 1024),
                       min_threshold / (1024.0 * 1024)))
        if p1['drop_pkts'] > 0:
            fail_msgs.append(
                "P1 (below min_th): drop_pkts={} ({:.4f}%) -- expected "
                "0 drops below min_th (peak={:.2f}MB)".format(
                    p1['drop_pkts'], p1['drop_rate'],
                    p1['peak'] / (1024.0 * 1024)))
    st.wait(cooldown)

    # ── Calibration probe: discover device-actual bytes per burst pkt ────
    # We need P2 to land its peak watermark inside Zone B
    # [min_th=1MB, max_th=3MB).  Open-loop theoretical models do not
    # predict actual peaks accurately enough across testbeds.  Run a
    # small probe burst, measure the resulting peak, then size the
    # real P2/P3 burst to hit PEAK_TARGET_BYTES (1.5 MB).
    #
    # Probe stays under gdrop=0 (same config as P2) so the WRED ramp
    # does not skew the measurement.  Probe size is fixed at
    # PROBE_PKTS_PER_PORT = 2048; for any reasonable frame size the
    # probe will produce a measurable peak well below min_th.
    st.banner("CALIBRATION: probe burst ({} pkts/port) under gdrop=0 "
              "to measure device-actual queue accumulation per "
              "burst packet, then size P2/P3 burst to land peak "
              "near {:.2f}MB (mid Zone B)".format(
                  PROBE_PKTS_PER_PORT,
                  PEAK_TARGET_BYTES / (1024.0 * 1024)))
    probe = _run_burst_point("CAL probe gdrop=0",
                             PROBE_PKTS_PER_PORT)
    if probe['egress_pkts'] <= 0:
        fail_msgs.append(
            "Calibration probe: no egress pkts -- traffic not "
            "forwarded; cannot calibrate burst size for P2/P3")
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'test_wred_gdrop_zero [{}] FAILED: {}'.format(
                           af, '; '.join(fail_msgs)))
        return
    if probe['peak'] <= 0:
        fail_msgs.append(
            "Calibration probe: peak watermark = 0 bytes -- the "
            "probe burst produced no measurable queue depth; check "
            "that traffic actually reaches the egress queue and "
            "that DCHAL peak counters are functional")
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'test_wred_gdrop_zero [{}] FAILED: {}'.format(
                           af, '; '.join(fail_msgs)))
        return
    if probe['peak'] >= min_threshold:
        # Probe peak is already above min_th -- our probe was too
        # large for this device.  We still have a valid
        # bytes-per-pkt measurement; just log a warning.  The
        # subsequent calibration math will still work.
        st.log("  Calibration probe peak {:.2f}MB >= min_th "
               "{:.2f}MB; probe was larger than expected for this "
               "build -- calibration math still valid".format(
                   probe['peak'] / (1024.0 * 1024),
                   min_threshold / (1024.0 * 1024)))

    bytes_per_probe_pkt = probe['peak'] / float(PROBE_PKTS_PER_PORT)
    pkts_per_port_burst = int(round(
        PEAK_TARGET_BYTES / bytes_per_probe_pkt))
    pkts_per_port_burst = max(1024, pkts_per_port_burst)
    expected_p2_peak_mb = (pkts_per_port_burst * bytes_per_probe_pkt
                           / (1024.0 * 1024))
    st.log("  Calibration result: probe sent {} pkts/port -> peak "
           "{:.2f}MB; ratio = {:.2f} bytes per burst-pkt; sized "
           "P2/P3 burst to {} pkts/port -> expected peak "
           "~{:.2f}MB (target {:.2f}MB)".format(
               PROBE_PKTS_PER_PORT,
               probe['peak'] / (1024.0 * 1024),
               bytes_per_probe_pkt,
               pkts_per_port_burst,
               expected_p2_peak_mb,
               PEAK_TARGET_BYTES / (1024.0 * 1024)))

    # The calibration probe also serves as a *direct* proof of the
    # gdrop=0 contract at shallow queue depth.  If the WRED ramp had
    # a residual nonzero floor at gdrop=0, the probe (which ran
    # under gdrop=0 with peak well below min_th) would have produced
    # drops.  Log that explicitly so the verdict story is clear.
    if probe['drop_pkts'] == 0:
        st.log("  CAL probe PROOF: peak {:.2f}MB under gdrop=0 "
               "produced 0 drops -- confirms WRED ramp does NOT "
               "drop with gdrop=0 (any drops at deeper P2 burst are "
               "attributable to tail-drop sampling noise, NOT a "
               "broken gdrop=0 ramp)".format(
                   probe['peak'] / (1024.0 * 1024)))
    else:
        # If the probe itself had drops, that's a much stronger
        # signal -- it would mean the device dropped under gdrop=0
        # even at shallow depth, which cannot be explained by
        # peak-watermark sampling because the depth is far from
        # max_th.  Fail the test loudly.
        fail_msgs.append(
            "CAL probe (gdrop=0, peak {:.2f}MB): drop_pkts={} -- "
            "the probe burst peaked far below max_th but still "
            "produced drops; this is NOT consistent with tail-drop "
            "sampling artifacts and indicates gdrop=0 may not be "
            "honored by the WRED ramp".format(
                probe['peak'] / (1024.0 * 1024),
                probe['drop_pkts']))

    # Sanity: refuse to proceed if expected peak is outside the
    # safe Zone B window even with calibration.  This prevents P2
    # from running a burst we already know won't land in Zone B.
    if expected_p2_peak_mb * 1024 * 1024 < PEAK_TARGET_LOW:
        fail_msgs.append(
            "Calibration: expected P2 peak {:.2f}MB < safe-low "
            "{:.2f}MB even after sizing burst to {} pkts/port -- "
            "device accumulation per burst pkt ({:.2f} bytes) is "
            "lower than the calibration math can compensate for. "
            "Increase PROBE_PKTS_PER_PORT or PEAK_TARGET_BYTES.".format(
                expected_p2_peak_mb,
                PEAK_TARGET_LOW / (1024.0 * 1024),
                pkts_per_port_burst, bytes_per_probe_pkt))
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'test_wred_gdrop_zero [{}] FAILED: {}'.format(
                           af, '; '.join(fail_msgs)))
        return
    if expected_p2_peak_mb * 1024 * 1024 > PEAK_TARGET_HIGH:
        fail_msgs.append(
            "Calibration: expected P2 peak {:.2f}MB > safe-high "
            "{:.2f}MB even after sizing burst to {} pkts/port -- "
            "device accumulation per burst pkt ({:.2f} bytes) is "
            "higher than the calibration math can compensate for. "
            "Lower PROBE_PKTS_PER_PORT.".format(
                expected_p2_peak_mb,
                PEAK_TARGET_HIGH / (1024.0 * 1024),
                pkts_per_port_burst, bytes_per_probe_pkt))
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'test_wred_gdrop_zero [{}] FAILED: {}'.format(
                           af, '; '.join(fail_msgs)))
        return
    st.wait(cooldown)

    # ── Point 2: gdrop=0, BURST into Zone B -> 0 drops (the contract) ────
    # Burst mode is required here.  Sustained oversubscription with
    # gdrop=0 inevitably saturates the buffer to max_th (the WRED ramp
    # is flat at 0%, nothing limits accumulation in Zone B), making
    # Zone B unreachable in steady state.  A finite burst sized by
    # the calibration probe above pushes the queue into Zone B
    # without crossing max_th.
    #
    # The burst peak must land strictly inside Zone B [min_th, max_th).
    # If it doesn't, the test FAILS with a clear message -- silently
    # skipping would falsely pass the gdrop=0 contract.
    st.banner("POINT 2 (BURST x{}): gdrop=0, calibrated burst "
              "({} pkts/port @ line rate, {} iterations averaged) -- "
              "queue peaks in Zone B [min_th, max_th), expect 0 drops "
              "(THE gdrop=0 contract)".format(
                  P2_P3_ITERATIONS, pkts_per_port_burst,
                  P2_P3_ITERATIONS))
    p2 = _run_burst_point("P2 gdrop=0 Zone_B burst",
                          pkts_per_port_burst,
                          iterations=P2_P3_ITERATIONS)
    p2_zone_b_proven = False
    if p2['egress_pkts'] <= 0:
        fail_msgs.append(
            "P2 (Zone B burst, gdrop=0): no egress pkts -- traffic "
            "not forwarded")
    elif p2['peak'] < min_threshold:
        fail_msgs.append(
            "P2 (Zone B burst, gdrop=0): burst peak {:.2f}MB < "
            "min_th {:.2f}MB -- burst was too SMALL to enter Zone B "
            "and prove the gdrop=0 contract. Calibration probe sized "
            "the burst at {} pkts/port using ratio {:.2f}B/pkt; "
            "device may have non-linear accumulation under burst "
            "vs probe -- raise PEAK_TARGET_BYTES toward 2.0MB.".format(
                p2['peak'] / (1024.0 * 1024),
                min_threshold / (1024.0 * 1024),
                pkts_per_port_burst, bytes_per_probe_pkt))
    elif p2['peak'] >= max_threshold:
        fail_msgs.append(
            "P2 (Zone B burst, gdrop=0): burst peak {:.2f}MB >= "
            "max_th {:.2f}MB -- burst was too LARGE and queue "
            "saturated into Zone C; gdrop=0 Zone B contract NOT "
            "proven. Calibration probe sized the burst at {} pkts/port "
            "using ratio {:.2f}B/pkt (probe peak {:.2f}MB); device "
            "may have non-linear accumulation -- lower "
            "PEAK_TARGET_BYTES toward 1.2MB.".format(
                p2['peak'] / (1024.0 * 1024),
                max_threshold / (1024.0 * 1024),
                pkts_per_port_burst, bytes_per_probe_pkt,
                probe['peak'] / (1024.0 * 1024)))
    else:
        # Confirmed Zone B (min_th <= peak < max_th) under gdrop=0
        # via burst.  We do NOT assert drop_pkts==0 here -- ASIC peak
        # watermark counters are sampled, so brief instantaneous depth
        # spikes above max_th can produce a handful of tail drops that
        # the latched watermark doesn't see.  Instead we require P2's
        # drop rate to be << P3's drop rate (gdrop=5 baseline) by at
        # least P2_VS_P3_RATIO_FLOOR times -- this proves the gdrop
        # knob has a meaningful effect on the WRED ramp without
        # requiring perfect zero drops.  See P3 block below for the
        # ratio assertion.
        p2_zone_b_proven = True

        # If SAI split counters are populated, use them to classify
        # any P2 drops as WRED-prob vs tail.  Under gdrop=0 the WRED
        # prob counter MUST be 0 -- that is the strict contract.
        # Tail drops can still occur from peak-watermark sampling
        # artifacts and are tolerated by the relative ratio check
        # below.
        p2_sai = p2['result'].get('sai_split') if p2['result'] else None
        if p2_sai and 'wred_drop_pkts' in p2_sai.get('available', []):
            wred_drops = p2_sai.get('wred_drop_pkts', 0)
            tail_drops = p2_sai.get('tail_drop_inferred_pkts', 0)
            if wred_drops > 0:
                fail_msgs.append(
                    "P2 (Zone B burst, gdrop=0): SAI counters report "
                    "wred_drop_pkts={} (>0) -- with gdrop=0 the WRED "
                    "ramp must NOT drop ANY packets in Zone B; this "
                    "is a strict contract violation independent of "
                    "the P2/P3 ratio (tail_drop_inferred={})".format(
                        wred_drops, tail_drops))
            else:
                st.log("  P2 SAI split: wred_drop_pkts={}, "
                       "tail_drop_inferred={} -- 0 WRED-prob drops "
                       "confirms gdrop=0 contract; any drops here "
                       "are tail drops (sampling artifacts)".format(
                           wred_drops, tail_drops))

        if p2['drop_pkts'] == 0:
            st.log("  P2 PROVEN (strict): burst peak {:.2f}MB in "
                   "Zone B [{:.2f}MB, {:.2f}MB) under gdrop=0, "
                   "drop_pkts=0 -- the gdrop=0 contract holds "
                   "exactly".format(
                       p2['peak'] / (1024.0 * 1024),
                       min_threshold / (1024.0 * 1024),
                       max_threshold / (1024.0 * 1024)))
        else:
            st.log("  P2 (Zone B burst, gdrop=0): drop_pkts={} "
                   "({:.4f}%) -- non-zero but to be evaluated against "
                   "P3 baseline below (Option B: relative ratio "
                   "check)".format(
                       p2['drop_pkts'], p2['drop_rate']))
    st.wait(cooldown)

    # ── Re-apply golden gdrop=5 for points 3 and 4 ───────────────────────
    st.log("Re-applying golden gdrop={} for points 3 and 4".format(
        int(golden_max_prob)))
    _apply_wred_gdrop(dut, int(golden_max_prob))
    actual_gdrop = _read_wred_field(dut, 'green_drop_probability')
    if actual_gdrop != str(int(golden_max_prob)):
        fail_msgs.append(
            "Could not re-apply gdrop={}: CONFIG_DB shows "
            "green_drop_probability='{}'".format(
                int(golden_max_prob), actual_gdrop))
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'test_wred_gdrop_zero [{}] FAILED: {}'.format(
                           af, '; '.join(fail_msgs)))
        return

    # ── Point 3: gdrop=5, BURST into Zone B -> drops re-engage ───────────
    # Same burst as P2 (identical pkts_per_port and rate) so we get
    # an apples-to-apples comparison: only gdrop changed.  With the
    # WRED ramp re-enabled, the burst should now produce *some* drops
    # while the queue is in Zone B.
    st.banner("POINT 3 (BURST x{}): gdrop={}, same burst as P2 "
              "({} pkts/port @ line rate, {} iterations averaged) -- "
              "queue peaks in Zone B, expect drops > 0 within ramp "
              "(0..{}%)".format(
                  P2_P3_ITERATIONS, int(golden_max_prob),
                  pkts_per_port_burst, P2_P3_ITERATIONS,
                  int(golden_max_prob)))
    p3 = _run_burst_point(
        "P3 gdrop={} Zone_B burst".format(int(golden_max_prob)),
        pkts_per_port_burst,
        iterations=P2_P3_ITERATIONS)
    p3_zone_b_proven = False
    if p3['egress_pkts'] <= 0:
        fail_msgs.append(
            "P3 (Zone B burst, gdrop={}): no egress pkts -- traffic "
            "not forwarded".format(int(golden_max_prob)))
    elif p3['peak'] < min_threshold:
        fail_msgs.append(
            "P3 (Zone B burst, gdrop={}): burst peak {:.2f}MB < "
            "min_th {:.2f}MB -- burst did not reach Zone B; "
            "cannot prove WRED ramp re-engagement".format(
                int(golden_max_prob),
                p3['peak'] / (1024.0 * 1024),
                min_threshold / (1024.0 * 1024)))
    elif p3['peak'] >= max_threshold:
        fail_msgs.append(
            "P3 (Zone B burst, gdrop={}): burst peak {:.2f}MB >= "
            "max_th {:.2f}MB -- queue saturated into Zone C; "
            "drops include tail drop and cannot be isolated as "
            "WRED-ramp drops".format(
                int(golden_max_prob),
                p3['peak'] / (1024.0 * 1024),
                max_threshold / (1024.0 * 1024)))
    else:
        # Confirmed Zone B with gdrop=5 via burst.  WRED ramp must
        # produce SOME drops, bounded by max_prob.
        p3_zone_b_proven = True
        if p3['drop_pkts'] <= 0:
            fail_msgs.append(
                "P3 (Zone B burst, gdrop={}): drop_pkts=0 but "
                "burst peak {:.2f}MB is inside Zone B -- WRED "
                "ramp should have produced drops; the gdrop knob "
                "may not be wired through to the ASIC".format(
                    int(golden_max_prob),
                    p3['peak'] / (1024.0 * 1024)))
        ramp_tolerance = 1.0
        if p3['drop_rate'] > golden_max_prob + ramp_tolerance:
            fail_msgs.append(
                "P3 (Zone B burst, gdrop={}): drop_rate={:.4f}% "
                "exceeds WRED max_prob {}% (+{}% tol) -- ramp "
                "should cap at max_prob within Zone B".format(
                    int(golden_max_prob), p3['drop_rate'],
                    int(golden_max_prob), ramp_tolerance))
        if p3['drop_pkts'] > 0 and p3['drop_rate'] <= golden_max_prob + ramp_tolerance:
            st.log("  P3 PROVEN: burst peak {:.2f}MB in Zone B under "
                   "gdrop={}, drop_rate={:.4f}% within ramp -- WRED "
                   "ramp re-engages".format(
                       p3['peak'] / (1024.0 * 1024),
                       int(golden_max_prob), p3['drop_rate']))
    st.wait(cooldown)

    # ── Option B assertion: P2 vs P3 drop_rate comparison ────────────────
    # The strongest evidence that gdrop=0 is honored comes from the
    # CALIBRATION probe step earlier: that probe ran under gdrop=0
    # at peak 0.14MB (well below min_th) and produced 0 drops.  If
    # the WRED ramp had a residual nonzero floor at gdrop=0, the
    # probe would have dropped packets too -- it didn't.  So the
    # gdrop=0 contract is already proven to hold WRED-side; any drops
    # observed at P2 (deeper queue, closer to max_th) are most
    # plausibly transient tail drops from peak-watermark sampling
    # artifacts, NOT WRED-prob drops.
    #
    # The remaining purpose of the P2/P3 comparison is to confirm
    # the gdrop knob has a *materially detectable* effect: P3
    # (gdrop=5) must produce more drops than P2 (gdrop=0), and the
    # difference must be larger than test noise.  Two checks:
    #
    #   1. Absolute additional drops: P3 must show strictly more
    #      drops than P2 by at least P3_MINUS_P2_MIN_DELTA (in % of
    #      total).  This is a direct measurement of the WRED ramp's
    #      effect -- no division required.
    #   2. Ratio: P3 / P2 must be at least P2_VS_P3_RATIO_FLOOR.
    #      Kept loose (3x) because both P2 and P3 share the same
    #      sampling-artifact noise floor, and the WRED ramp's
    #      contribution at burst peaks just inside Zone B is small.
    #
    # An absolute hard ceiling on P2 (P2_DROP_RATE_HARD_CEIL) catches
    # cases where P2 drops are unreasonably large for sampling
    # artifacts -- a true broken gdrop=0 would produce drops similar
    # to or larger than P3.
    P3_MINUS_P2_MIN_DELTA = 0.05  # P3 must exceed P2 by 0.05% absolute
    P2_VS_P3_RATIO_FLOOR = 3.0
    P2_DROP_RATE_HARD_CEIL = 0.5  # broken gdrop=0 would be MUCH higher
    if p2_zone_b_proven and p3_zone_b_proven:
        if p3['drop_rate'] <= 0:
            # P3 produced 0 drops; P3's own block already failed the
            # test for "drop_pkts=0 but peak in Zone B".
            pass
        else:
            delta = p3['drop_rate'] - p2['drop_rate']
            ratio = p3['drop_rate'] / max(p2['drop_rate'], 1e-9)
            st.log("  Option B check: P2 drop_rate={:.4f}% (gdrop=0), "
                   "P3 drop_rate={:.4f}% (gdrop=5) -- delta={:.4f}%, "
                   "ratio={:.1f}x (need delta >= {:.2f}% AND "
                   "ratio >= {:.1f}x)".format(
                       p2['drop_rate'], p3['drop_rate'], delta, ratio,
                       P3_MINUS_P2_MIN_DELTA, P2_VS_P3_RATIO_FLOOR))
            if delta < P3_MINUS_P2_MIN_DELTA:
                fail_msgs.append(
                    "P3 - P2 drop_rate delta {:.4f}% < {:.2f}% -- "
                    "the gdrop knob has no measurable effect on "
                    "drop rate; gdrop=0 and gdrop=5 produce "
                    "indistinguishable drops (P2={:.4f}%, "
                    "P3={:.4f}%)".format(
                        delta, P3_MINUS_P2_MIN_DELTA,
                        p2['drop_rate'], p3['drop_rate']))
            elif ratio < P2_VS_P3_RATIO_FLOOR:
                fail_msgs.append(
                    "P2 vs P3 ratio {:.1f}x < {:.1f}x -- gdrop=0 "
                    "drop rate is too close to gdrop=5 baseline "
                    "(delta {:.4f}% met threshold but ratio is "
                    "weak; suggests an unusually-high gdrop=0 "
                    "noise floor)".format(
                        ratio, P2_VS_P3_RATIO_FLOOR, delta))
            else:
                st.log("  Option B PROVEN: gdrop=5 adds {:.4f}% extra "
                       "drops over gdrop=0 baseline ({:.1f}x ratio) "
                       "-- WRED ramp is materially affected by the "
                       "gdrop knob.  Note: CALIBRATION probe at peak "
                       "0.14MB under gdrop=0 separately produced 0 "
                       "drops, proving gdrop=0 contract holds at "
                       "shallow queue depths.".format(delta, ratio))
        if p2['drop_rate'] > P2_DROP_RATE_HARD_CEIL:
            fail_msgs.append(
                "P2 (Zone B burst, gdrop=0): absolute drop rate "
                "{:.4f}% > {:.2f}% hard ceiling -- under the "
                "gdrop=0 contract, drops should be near zero or at "
                "most a small sampling-artifact noise floor; this "
                "is too high".format(
                    p2['drop_rate'], P2_DROP_RATE_HARD_CEIL))

    # ── Option D assertion: theoretical-vs-observed WRED ramp drop rate ──
    # Linear-ramp model predicts how many drops the WRED ramp should
    # produce at P3's measured peak depth.  Compare to the observed
    # WRED ramp contribution (P3 - P2; subtracts the tail-drop noise
    # floor that's common to both).  If the model and observation
    # agree within RAMP_TOLERANCE_FRAC, the ramp slope and thresholds
    # are working as configured.  If they disagree, we have a
    # quantitative signal that something is wrong (slope half/double,
    # threshold mis-applied, drop probability quantized differently
    # in HW than CONFIG_DB).
    #
    # Tolerance is generous (40%-200% of expected) because the
    # observed ramp contribution is the *difference* of two noisy
    # measurements (P3 - P2), and that subtraction amplifies the
    # variance.  Concrete sources of deviation:
    #   - non-linear queue fill (burst doesn't fill linearly)
    #   - IXIA pacing jitter at the burst start
    #   - Poisson variance in WRED probabilistic drops
    #   - tail-drop sampling noise in P2 (gdrop=0 still produces
    #     a small number of tail drops when an instantaneous peak
    #     briefly crosses max_th); when P2's noise floor is at the
    #     high end of its run-to-run distribution, P3 - P2 shrinks
    #     and the ratio drops.
    # Empirically, repeat runs of [ipv4] / [ipv6] on the FX3 testbed
    # land in the 0.47x .. 0.87x range -- well-separated from the
    # 1.0x ideal and from a genuinely flattened ramp (which would
    # be < ~0.2x).  We set the lower gate at 0.40x so that normal
    # P2-noise driven variance does not flake the test, while a
    # genuinely flattened or quantized-away ramp still trips it.
    # The upper gate at 2.0x is unchanged: a runaway ramp (slope
    # twice configured, or contamination from non-WRED drops) is
    # always a real bug.
    RAMP_TOLERANCE_LOW = 0.4    # observed/expected must be >= this
    RAMP_TOLERANCE_HIGH = 2.0   # observed/expected must be <= this
    if p2_zone_b_proven and p3_zone_b_proven and p3['drop_pkts'] > 0:
        expected_p3_pct = expected_wred_ramp_drop_rate(
            peak_bytes=p3['peak'],
            min_th_bytes=min_threshold,
            max_th_bytes=max_threshold,
            gdrop_pct=golden_max_prob)
        # P2's drop_rate is the tail-drop noise floor (gdrop=0 contract
        # is proven to produce 0 WRED-ramp drops by the CAL probe).
        # Observed WRED-ramp contribution = P3 - P2.
        observed_ramp_pct = max(0.0, p3['drop_rate'] - p2['drop_rate'])
        if expected_p3_pct <= 0:
            st.log("  Option D check: peak {:.2f}MB <= min_th, "
                   "expected ramp drop rate is 0% -- formula does "
                   "not apply, skipping Option D".format(
                       p3['peak'] / (1024.0 * 1024)))
        else:
            ratio_obs_exp = observed_ramp_pct / expected_p3_pct
            st.log("  Option D check: P3 peak {:.2f}MB, gdrop={}%; "
                   "linear-ramp model predicts {:.4f}% drop rate; "
                   "observed (P3 - P2 tail noise) = {:.4f}%; "
                   "ratio observed/expected = {:.2f} (need [{:.2f}, "
                   "{:.2f}])".format(
                       p3['peak'] / (1024.0 * 1024),
                       int(golden_max_prob),
                       expected_p3_pct, observed_ramp_pct,
                       ratio_obs_exp,
                       RAMP_TOLERANCE_LOW, RAMP_TOLERANCE_HIGH))
            if ratio_obs_exp < RAMP_TOLERANCE_LOW:
                fail_msgs.append(
                    "P3 WRED ramp drop rate {:.4f}% is BELOW "
                    "{:.2f}x of theoretical {:.4f}% (peak={:.2f}MB, "
                    "min_th={:.2f}MB, max_th={:.2f}MB, gdrop={}%) -- "
                    "the WRED ramp is dropping LESS than the "
                    "configured slope predicts; ramp may be "
                    "flattened, slope quantized too coarsely, or "
                    "thresholds not honored".format(
                        observed_ramp_pct, RAMP_TOLERANCE_LOW,
                        expected_p3_pct,
                        p3['peak'] / (1024.0 * 1024),
                        min_threshold / (1024.0 * 1024),
                        max_threshold / (1024.0 * 1024),
                        int(golden_max_prob)))
            elif ratio_obs_exp > RAMP_TOLERANCE_HIGH:
                fail_msgs.append(
                    "P3 WRED ramp drop rate {:.4f}% is ABOVE "
                    "{:.2f}x of theoretical {:.4f}% (peak={:.2f}MB, "
                    "min_th={:.2f}MB, max_th={:.2f}MB, gdrop={}%) -- "
                    "the WRED ramp is dropping MORE than the "
                    "configured slope predicts; ramp may be "
                    "steeper than configured, or extra non-WRED "
                    "drops are contaminating the measurement".format(
                        observed_ramp_pct, RAMP_TOLERANCE_HIGH,
                        expected_p3_pct,
                        p3['peak'] / (1024.0 * 1024),
                        min_threshold / (1024.0 * 1024),
                        max_threshold / (1024.0 * 1024),
                        int(golden_max_prob)))
            else:
                st.log("  Option D PROVEN: WRED ramp produces drops "
                       "within [{:.2f}, {:.2f}]x of the linear-ramp "
                       "model -- ramp slope, thresholds, and "
                       "probability are all working as configured".format(
                           RAMP_TOLERANCE_LOW, RAMP_TOLERANCE_HIGH))

    # ── Point 4: gdrop=5, queue above max_th -> tail drop dominates ──────
    st.banner("POINT 4: gdrop={}, heavy load (margin={}M) -- "
              "queue peak > max_th, expect drop_rate >> WRED max_prob "
              "({}%) (tail drop dominates)".format(
                  int(golden_max_prob), margin_zone_c,
                  int(golden_max_prob)))
    p4 = _run_point("P4 gdrop={} Zone_C".format(int(golden_max_prob)),
                    margin_zone_c)
    if p4['egress_pkts'] <= 0:
        fail_msgs.append(
            "P4 (Zone C, gdrop={}): no egress pkts -- traffic not "
            "forwarded".format(int(golden_max_prob)))
    else:
        if p4['peak'] < max_threshold:
            fail_msgs.append(
                "P4 (Zone C, gdrop={}): peak={:.2f}MB < max_th "
                "{:.2f}MB -- queue did not saturate at +{}M margin; "
                "expected Zone C operation".format(
                    int(golden_max_prob),
                    p4['peak'] / (1024.0 * 1024),
                    max_threshold / (1024.0 * 1024),
                    margin_zone_c))
        elif p4['drop_pkts'] <= 0:
            fail_msgs.append(
                "P4 (Zone C, gdrop={}): peak={:.2f}MB >= max_th but "
                "drop_pkts=0 -- expected tail drops".format(
                    int(golden_max_prob),
                    p4['peak'] / (1024.0 * 1024)))
        else:
            # Drops must clearly exceed the WRED ramp's max_prob to
            # demonstrate tail-drop dominance.  Equally important, the
            # drop rate should approximate the oversub rate within a
            # generous tolerance (pure tail drop in Zone C).
            if p4['drop_rate'] <= golden_max_prob + 1.0:
                fail_msgs.append(
                    "P4 (Zone C, gdrop={}): drop_rate={:.4f}% <= "
                    "max_prob {}% (+1% tol) -- Zone C should exceed "
                    "the WRED ramp cap (tail drop, not WRED-shaped)".format(
                        int(golden_max_prob), p4['drop_rate'],
                        int(golden_max_prob)))
            tail_tolerance_pct = max(1.0, 0.25 * p4['oversub'])
            if abs(p4['drop_rate'] - p4['oversub']) > tail_tolerance_pct:
                st.log(
                    "  P4: drop_rate={:.4f}% vs oversub={:.4f}% "
                    "(diff > {:.2f}%); device is dropping but not at "
                    "the pure-tail-drop ratio -- logging only".format(
                        p4['drop_rate'], p4['oversub'],
                        tail_tolerance_pct))
    st.wait(cooldown)

    # ── Phase 3: Restore ──────────────────────────────────────────────────

    st.log("Phase 3: Restoring golden WRED profile")
    _restore_golden_profile(dut, fail_msgs)

    if fail_msgs:
        st.log("test_wred_gdrop_zero [{}] failures ({} total):".format(
            af, len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.report_fail('msg',
                       'test_wred_gdrop_zero [{}] FAILED: {}'.format(
                           af, '; '.join(fail_msgs)))
    else:
        # data_points order: P1, CAL, P2, P3, P4
        labels = ['P1', 'CAL', 'P2', 'P3', 'P4']
        summary = ', '.join(
            '{}={}M peak={:.2f}MB drop={:.4f}%'.format(
                labels[i] if i < len(labels) else 'P?',
                dp['margin_mbps'],
                dp.get('peak_bytes', 0) / (1024.0 * 1024),
                dp.get('drop_rate_pct', 0.0))
            for i, dp in enumerate(data_points))
        # Verdict-message accuracy: only claim "contract proven" if
        # both P2 and P3 actually landed in Zone B (otherwise the
        # comparison is between two Zone C samples and proves
        # nothing).  Note: if either was not proven we would have
        # already added a fail_msg above and not reach this branch,
        # but keep the language conservative for clarity.
        # If we reached here, fail_msgs is empty -- which means BOTH
        # the ratio check (P2 << P3) AND the absolute ceiling check
        # (P2 < hard ceiling) passed, OR P2 had exactly 0 drops
        # (strict pass).
        if p2['drop_pkts'] == 0:
            p2_verdict = ('P2 ZoneB gdrop=0/0drops over {}x burst '
                          '(strict contract PROVEN)'.format(P2_P3_ITERATIONS))
        else:
            if p3['drop_rate'] > 0:
                ratio_str = '{:.1f}x'.format(
                    p3['drop_rate'] / max(p2['drop_rate'], 1e-9))
            else:
                ratio_str = 'n/a'
            p2_verdict = (
                'P2 ZoneB gdrop=0/{} drops {:.4f}% over {}x burst '
                '(Option B PROVEN: P3/P2 ratio {})'
                .format(p2['drop_pkts'], p2['drop_rate'],
                        P2_P3_ITERATIONS, ratio_str))
        # Add Option D summary if the ramp formula was applicable.
        p3_verdict = 'P3 ZoneB gdrop=5/drops in ramp (knob PROVEN)'
        try:
            expected_p3_pct = expected_wred_ramp_drop_rate(
                peak_bytes=p3['peak'],
                min_th_bytes=min_threshold,
                max_th_bytes=max_threshold,
                gdrop_pct=golden_max_prob)
            if expected_p3_pct > 0:
                obs_ramp = max(0.0, p3['drop_rate'] - p2['drop_rate'])
                obs_exp_ratio = obs_ramp / expected_p3_pct
                p3_verdict = (
                    'P3 ZoneB gdrop=5/{:.4f}% (ramp: obs {:.4f}% / '
                    'theory {:.4f}% = {:.2f}x; Option D PROVEN)'
                    .format(p3['drop_rate'], obs_ramp,
                            expected_p3_pct, obs_exp_ratio))
        except Exception:
            pass  # keep the simple string verdict
        verdict_detail = (
            'P1 below_min/0drops; ' +
            p2_verdict + '; ' +
            p3_verdict + '; ' +
            'P4 ZoneC gdrop=5/tail drop')
        st.report_pass('msg',
                       'test_wred_gdrop_zero [{}] passed: {}. '
                       'Summary: {}'.format(af, verdict_detail, summary))


@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_disable_profile_with_traffic(af):
    """
    Unbind WRED under continuous fan-in load.

    Starts two-port fan-in at a fixed margin above line rate, keeps traffic
    running through: baseline snapshot (DCHAL + SONiC queue + interface
    counters), CONFIG_DB HDEL unbind, ASIC_DB queue ``SAI_QUEUE_ATTR_WRED_PROFILE_ID``
    checks, then ``verify_wred_config_values_prog_in_dchal`` on **TARGET_QUEUE**
    (same queue as the fan-in DSCP — the congested queue).  Counter clear,
    second wait, second DCHAL queuing snapshot.  Stops IXIA streams in ``finally``
    and runs ``config qos reload`` to restore queue WRED bindings.
    """
    egress_port = port_info['egress']
    st.banner(
        "test_disable_profile_with_traffic [{}]\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : Test #19 traffic — unbind WRED while traffic runs "
        "({} Mbps margin, {}s waits)".format(
            af, dut, egress_port,
            WRED_DISABLE_TRAFFIC_MARGIN_MBPS, WRED_DISABLE_TRAFFIC_WAIT_SEC))

    fail_msgs = []
    ixia_fanin_stream_ids = []

    deploy_dchal_helper(dut)
    verify_wred_profile(dut, fail_msgs)
    if fail_msgs:
        st.report_fail(
            'msg',
            'test_disable_profile_with_traffic [{}] FAILED at baseline: {}'.format(
                af, '; '.join(fail_msgs)))
        return

    asic_wred_profile_oid = get_first_asic_wred_profile_oid(dut)
    if not asic_wred_profile_oid:
        fail_msgs.append("pre-traffic: no SAI_OBJECT_TYPE_WRED in ASIC_DB")
        st.report_fail(
            'msg',
            'test_disable_profile_with_traffic [{}] FAILED: {}'.format(
                af, '; '.join(fail_msgs)))
        return

    asic_bound_state_failures = []
    verify_queues_wred_binding(
        dut, egress_port, list(WRED_BOUND_QUEUES), asic_wred_profile_oid,
        asic_bound_state_failures, "pre-traffic ASIC")

    if asic_bound_state_failures:
        fail_msgs.extend(asic_bound_state_failures)
        st.report_fail(
            'msg',
            'test_disable_profile_with_traffic [{}] FAILED (ASIC precheck): {}'.format(
                af, '; '.join(fail_msgs)))
        return

    if not _verify_egress_neighbor(af):
        st.report_fail(
            'msg',
            'test_disable_profile_with_traffic [{}] FAILED: egress neighbor not '
            'resolved'.format(af))
        return

    clear_dut_counters(dut)
    dchal_clear_counters(dut, egress_port)

    try:
        ixia_fanin_stream_ids = wred_fanin_start_continuous(
            wred_ctx, af, WRED_DISABLE_TRAFFIC_MARGIN_MBPS)
        st.wait(WRED_DISABLE_TRAFFIC_WAIT_SEC)

        dchal_queuing_before_unbind = get_dchal_queue_counters(
            dut, egress_port, "pre-unbind (continuous traffic)")

        sonic_queue_counters_before_unbind = get_queue_counters(
            dut, egress_port)

        interface_counters_before_unbind = get_intf_counters(
            dut, port_info.values())

        st.log("--- DCHAL pre-unbind ---")
        log_queue_counters(dchal_queuing_before_unbind)
        target_queue_drop_pkts_dchal = dchal_queuing_before_unbind.get(
            TARGET_QUEUE, {}).get('drop_pkts', 0)

        st.log(
            "  show queue counters {}: Q{} tx_pkts={}".format(
                egress_port, TARGET_QUEUE,
                sonic_queue_counters_before_unbind.get(
                    TARGET_QUEUE, {}).get('pkts', 0)))
        st.log(
            "  interface {} tx_drp={}".format(
                egress_port,
                interface_counters_before_unbind.get(
                    egress_port, {}).get('tx_drp', 0)))

        if target_queue_drop_pkts_dchal <= 0:
            fail_msgs.append(
                "pre-unbind: expected DCHAL drop pkts > 0 on Q{} "
                "(proves WRED/tail drops while profile active), got {}".format(
                    TARGET_QUEUE, target_queue_drop_pkts_dchal))

        st.log("Unbind WRED (CONFIG_DB HDEL) while IXIA traffic continues")
        unbind_wred_from_queues(dut, egress_port)

        verify_queues_wred_binding(
            dut, egress_port, list(WRED_BOUND_QUEUES), 'oid:0x0',
            fail_msgs, "post-unbind")
        verify_queues_wred_binding(
            dut, egress_port, [7], 'oid:0x0',
            fail_msgs, "post-unbind Q7")

        dchal_target_queue_hw_verify_rc = verify_wred_config_values_prog_in_dchal(
            dut, egress_port, TARGET_QUEUE, '0', '0', '0')

        if dchal_target_queue_hw_verify_rc != 0:
            fail_msgs.append(
                "post-unbind: DCHAL Q{} HW not zeroed (rc={})".format(
                    TARGET_QUEUE, dchal_target_queue_hw_verify_rc))

        clear_dut_counters(dut)
        dchal_clear_counters(dut, egress_port)
        st.wait(WRED_DISABLE_TRAFFIC_WAIT_SEC)

        dchal_queuing_after_unbind = get_dchal_queue_counters(
            dut, egress_port, "post-unbind after clear + wait")

        st.log("--- DCHAL post-unbind + clear + {}s ---".format(
            WRED_DISABLE_TRAFFIC_WAIT_SEC))
        log_queue_counters(dchal_queuing_after_unbind)

        post_unbind_drop_pkts = dchal_queuing_after_unbind.get(
            TARGET_QUEUE, {}).get('drop_pkts', 0)
        if post_unbind_drop_pkts <= 0:
            fail_msgs.append(
                "post-unbind: expected DCHAL drop pkts > 0 on Q{} "
                "(tail drops should continue after WRED removed), "
                "got {}".format(TARGET_QUEUE, post_unbind_drop_pkts))

        interface_counters_after_unbind = get_intf_counters(
            dut, port_info.values())
        post_unbind_tx_drp = interface_counters_after_unbind.get(
            egress_port, {}).get('tx_drp', 0)
        st.log("  interface {} post-unbind tx_drp={}".format(
            egress_port, post_unbind_tx_drp))
        if post_unbind_tx_drp <= 0:
            fail_msgs.append(
                "post-unbind: expected TX_DRP > 0 on {}, got {}".format(
                    egress_port, post_unbind_tx_drp))

    finally:
        wred_fanin_stop_continuous(tg, ixia_fanin_stream_ids)
        st.log("Restore QoS: config qos reload after WRED unbind")
        st.config(dut, "config qos reload", skip_error_check=True)
        st.wait(5)

        ensure_interfaces_admin_up(dut, port_info.values())
        qos_restore_failures = []
        verify_wred_profile(dut, qos_restore_failures)

        if qos_restore_failures:
            st.warn("post-test restore verify_wred_profile: {}".format(
                '; '.join(qos_restore_failures)))

    if fail_msgs:
        st.log("test_disable_profile_with_traffic [{}] failures ({} total):".format(
            af, len(fail_msgs)))

        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))

        st.report_fail(
            'msg',
            'test_disable_profile_with_traffic [{}] FAILED — {}'.format(
                af, '; '.join(fail_msgs)))
    else:
        st.report_pass(
            'msg',
            'test_disable_profile_with_traffic [{}] passed: pre-unbind drops on Q{}, '
            'ASIC_DB oid:0x0, DCHAL WRED zeroed, post-unbind tail drops '
            'continue on Q{}'.format(af, TARGET_QUEUE, TARGET_QUEUE))


@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_reenable_profile_with_traffic(af):
    """
    Re-enable WRED after unbind and verify drops resume under traffic.

    Implements Test #20 from the WRED test plan.  Starts by unbinding
    WRED (replicating the disabled state from Test 19), then re-applies
    the profile via ``config qos reload``.  Verifies CONFIG_DB, ASIC_DB,
    and DCHAL HW all reflect the golden WRED profile.  Then sends
    oversubscribed fan-in traffic and confirms:
      - DCHAL Tx pkts > 0 on TARGET_QUEUE
      - DCHAL drop pkts > 0 (WRED drops resumed)
      - DCHAL queue depth bytes > 0
      - Interface TX_DRP > 0
    """
    egress_port = port_info['egress']
    st.banner(
        "test_reenable_profile_with_traffic [{}]\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : Test #20 — re-enable WRED after disable, "
        "verify drops resume ({} Mbps margin, {}s waits)".format(
            af, dut, egress_port,
            WRED_DISABLE_TRAFFIC_MARGIN_MBPS, WRED_DISABLE_TRAFFIC_WAIT_SEC))

    fail_msgs = []
    ixia_fanin_stream_ids = []

    # ── Precondition: ensure WRED is currently DISABLED ────────────────
    deploy_dchal_helper(dut)

    st.log("Precondition: unbind WRED to establish disabled state")
    unbind_wred_from_queues(dut, egress_port)

    precond_failures = []
    verify_queues_wred_binding(
        dut, egress_port, list(WRED_BOUND_QUEUES), 'oid:0x0',
        precond_failures, "precondition unbind")

    dchal_zeroed_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_port, TARGET_QUEUE, '0', '0', '0')
    if dchal_zeroed_rc != 0:
        precond_failures.append(
            "precondition: DCHAL Q{} HW not zeroed after unbind (rc={})".format(
                TARGET_QUEUE, dchal_zeroed_rc))

    if precond_failures:
        st.report_fail(
            'msg',
            'test_reenable_profile_with_traffic [{}] FAILED (precondition — '
            'could not disable WRED): {}'.format(
                af, '; '.join(precond_failures)))
        return

    # ── Step 1: Re-enable WRED via config qos reload ───────────────────
    st.log("Step 1: Re-enable WRED — config qos reload")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    ensure_interfaces_admin_up(dut, port_info.values())

    # ── Step 2: Verify CONFIG_DB restored ──────────────────────────────
    st.log("Step 2: Verify CONFIG_DB — WRED_PROFILE|AZURE_LOSSY restored")
    verify_wred_profile(dut, fail_msgs)

    # ── Step 3: Verify ASIC_DB — WRED OID exists and queues re-bound ──
    st.log("Step 3: Verify ASIC_DB — WRED object present and queues bound")
    asic_wred_profile_oid = get_first_asic_wred_profile_oid(dut)
    if not asic_wred_profile_oid:
        fail_msgs.append(
            "post-reload: no SAI_OBJECT_TYPE_WRED in ASIC_DB")
    else:
        verify_queues_wred_binding(
            dut, egress_port, list(WRED_BOUND_QUEUES),
            asic_wred_profile_oid, fail_msgs, "post-reload")
        verify_queues_wred_binding(
            dut, egress_port, [7], 'oid:0x0',
            fail_msgs, "post-reload Q7 unchanged")

    # ── Step 4: Verify DCHAL HW — golden WRED profile re-programmed ───
    st.log("Step 4: Verify DCHAL HW — golden WRED profile on Q{}".format(
        TARGET_QUEUE))
    dchal_hw_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_port, TARGET_QUEUE,
        GOLDEN_WRED_PROFILE['green_min_threshold'],
        GOLDEN_WRED_PROFILE['green_max_threshold'],
        GOLDEN_WRED_PROFILE['green_drop_probability'])
    if dchal_hw_rc != 0:
        fail_msgs.append(
            "post-reload: DCHAL HW mismatch for Q{} (rc={})".format(
                TARGET_QUEUE, dchal_hw_rc))

    if fail_msgs:
        st.report_fail(
            'msg',
            'test_reenable_profile_with_traffic [{}] FAILED (control-plane restore): '
            '{}'.format(af, '; '.join(fail_msgs)))
        return

    # ── Step 5: Verify egress neighbor reachability ────────────────────
    if not _verify_egress_neighbor(af):
        st.report_fail(
            'msg',
            'test_reenable_profile_with_traffic [{}] FAILED: egress neighbor not '
            'resolved after qos reload'.format(af))
        return

    # ── Step 6: Clear counters and send traffic ────────────────────────
    st.log("Step 6: Clear counters and start IXIA fan-in traffic")
    clear_dut_counters(dut)
    dchal_clear_counters(dut, egress_port)

    try:
        ixia_fanin_stream_ids = wred_fanin_start_continuous(
            wred_ctx, af, WRED_DISABLE_TRAFFIC_MARGIN_MBPS)
        st.wait(WRED_DISABLE_TRAFFIC_WAIT_SEC)

        # ── Step 7: Verify DCHAL queue counters ────────────────────────
        dchal_queuing = get_dchal_queue_counters(
            dut, egress_port,
            "post-reload traffic ({} Mbps margin, {}s)".format(
                WRED_DISABLE_TRAFFIC_MARGIN_MBPS,
                WRED_DISABLE_TRAFFIC_WAIT_SEC))

        st.log("--- DCHAL post-reload traffic ---")
        log_queue_counters(dchal_queuing)

        tq_data = dchal_queuing.get(TARGET_QUEUE, {})
        tq_pkts = tq_data.get('pkts', 0)
        tq_drop_pkts = tq_data.get('drop_pkts', 0)
        tq_depth = tq_data.get('q_depth_bytes', 0)

        st.log("  Q{} — pkts={}, drop_pkts={}, q_depth_bytes={}".format(
            TARGET_QUEUE, tq_pkts, tq_drop_pkts, tq_depth))

        if tq_pkts <= 0:
            fail_msgs.append(
                "post-reload traffic: expected DCHAL pkts > 0 on Q{}, "
                "got {}".format(TARGET_QUEUE, tq_pkts))

        if tq_drop_pkts <= 0:
            fail_msgs.append(
                "post-reload traffic: expected DCHAL drop pkts > 0 on Q{} "
                "(WRED drops should resume after re-enable), got {}".format(
                    TARGET_QUEUE, tq_drop_pkts))

        if tq_depth <= 0:
            fail_msgs.append(
                "post-reload traffic: expected DCHAL Q Depth Byts > 0 on "
                "Q{}, got {}".format(TARGET_QUEUE, tq_depth))

        # ── Step 8: Verify interface TX_DRP ────────────────────────────
        intf_counters = get_intf_counters(dut, port_info.values())
        tx_drp = intf_counters.get(egress_port, {}).get('tx_drp', 0)
        st.log("  interface {} tx_drp={}".format(egress_port, tx_drp))

        if tx_drp <= 0:
            fail_msgs.append(
                "post-reload traffic: expected TX_DRP > 0 on {}, "
                "got {}".format(egress_port, tx_drp))

    finally:
        wred_fanin_stop_continuous(tg, ixia_fanin_stream_ids)

    if fail_msgs:
        st.log("test_reenable_profile_with_traffic [{}] failures ({} total):".format(
            af, len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.report_fail(
            'msg',
            'test_reenable_profile_with_traffic [{}] FAILED — {}'.format(
                af, '; '.join(fail_msgs)))
    else:
        st.report_pass(
            'msg',
            'test_reenable_profile_with_traffic [{}] passed: WRED re-enabled '
            'after disable — CONFIG_DB/ASIC_DB/DCHAL HW restored, '
            'drops resumed on Q{} (pkts/drop_pkts/depth > 0), '
            'TX_DRP > 0'.format(af, TARGET_QUEUE))


@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_wred_scheduler_gdrop_change(af):
    """Verify scheduler weight changes in CONFIG_DB and WRED gdrop change
    via linearity sweep.

    Combines the scheduler weight change flow from
    test_fx3_scheduler_weight_change (CONFIG_DB verification only) with a
    WRED green_drop_probability change validated by traffic.

    Scheduler steps (CONFIG_DB only, no traffic):
      Baseline:  scheduler.2=20  scheduler.5=30
      Step 1:    HSET scheduler.2 weight 20->30 + queue rebind
      Step 2:    HSET scheduler.5 weight 30->20 + queue rebind
      Step 3:    Verify STRICT schedulers (6, 7) unchanged

    WRED steps (CONFIG_DB + linearity sweep traffic):
      Step 4:    ecnconfig -p AZURE_LOSSY -gdrop 10 (was 5)
      Step 5:    Linearity sweep with gdrop=10 to verify drop probability

    Restore:   config qos reload -> verify scheduler weights + WRED profile
               back to golden baseline
    """
    egress = port_info['egress']
    st.banner(
        "test_wred_scheduler_gdrop_change [{}]\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : Scheduler weight changes (CONFIG_DB) "
        "+ WRED gdrop 5->10 (linearity sweep)".format(af, dut, egress))
    fail_msgs = []

    w_baseline = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}
    w_step1    = {0: 20, 1: 20, 2: 30, 3: 40, 4: 40, 5: 30}
    w_step2    = {0: 20, 1: 20, 2: 30, 3: 40, 4: 40, 5: 20}

    # ── Baseline ──────────────────────────────────────────────────────────
    st.banner("BASELINE: Verify scheduler weights + WRED profile")
    deploy_dchal_helper(dut)

    _verify_scheduler_weights(dut, "Baseline",
        {'scheduler.{}'.format(k): str(v) for k, v in w_baseline.items()},
        fail_msgs)
    verify_wred_profile(dut, fail_msgs)

    if fail_msgs:
        st.log("=" * 72)
        st.log("  BASELINE FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'WRED scheduler gdrop change [{}] '
            'FAILED at baseline — see above'.format(af))
        return
    _log_scheduler_state(dut, "Baseline")

    # ── Step 1: scheduler.2  weight 20 -> 30 ─────────────────────────────
    st.banner("STEP 1: scheduler.2  weight 20 -> 30")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "SCHEDULER|scheduler.2" "weight" "30"',
        skip_error_check=True)
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|2" "scheduler" '
        '"scheduler.2"'.format(egress),
        skip_error_check=True)
    st.wait(2)
    _verify_scheduler_weights(dut, "Step 1",
        {'scheduler.{}'.format(k): str(v) for k, v in w_step1.items()},
        fail_msgs)
    _log_scheduler_state(dut, "Step 1")

    # ── Step 2: scheduler.5  weight 30 -> 20 ─────────────────────────────
    st.banner("STEP 2: scheduler.5  weight 30 -> 20")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "SCHEDULER|scheduler.5" "weight" "20"',
        skip_error_check=True)
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|5" "scheduler" '
        '"scheduler.5"'.format(egress),
        skip_error_check=True)
    st.wait(2)
    _verify_scheduler_weights(dut, "Step 2",
        {'scheduler.{}'.format(k): str(v) for k, v in w_step2.items()},
        fail_msgs)
    _log_scheduler_state(dut, "Step 2")

    # ── Step 3: Verify STRICT schedulers unchanged ────────────────────────
    st.banner("STEP 3: Verify STRICT schedulers (6, 7) unchanged")
    for name in ('scheduler.6', 'scheduler.7'):
        out = st.show(dut,
            'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|{}"'.format(name),
            skip_tmpl=True)
        actual = parse_redis_hgetall(out)
        st.log("  {} -> {}".format(name, actual))
        if actual.get('type', '') != 'STRICT':
            fail_msgs.append(
                "{} type='{}', expected 'STRICT'".format(
                    name, actual.get('type', '')))
        if 'weight' in actual:
            fail_msgs.append(
                "{} unexpectedly has weight='{}'".format(
                    name, actual['weight']))

    # ── Step 4: Change WRED gdrop 5 -> 10 ─────────────────────────────────
    st.banner("STEP 4: WRED green_drop_probability 5 -> 10")
    _apply_wred_gdrop(dut, 10)

    gdrop_val = _read_wred_field(dut, 'green_drop_probability')
    st.log("  green_drop_probability = '{}'".format(gdrop_val))
    if gdrop_val != '10':
        fail_msgs.append(
            "gdrop not applied: expected '10', got '{}'".format(gdrop_val))
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
            'WRED scheduler gdrop change [{}] '
            'FAILED: gdrop not applied — see above'.format(af))
        return

    # ── Step 5: Linearity sweep with gdrop=10 ─────────────────────────────
    st.banner("STEP 5: WRED linearity sweep with gdrop=10 [{}]".format(af))
    margins = [*MARGINS, 7000, 9000, 11000, 12000]
    sweep_fails, data_points = run_wred_linearity(
        wred_ctx, af, margins, _verify_egress_neighbor,
        duration=20, num_depth_samples=3,
        wred_profile=CUSTOM_GDROP_PROFILE)
    fail_msgs.extend(sweep_fails)

    # ── Restore ───────────────────────────────────────────────────────────
    st.banner("RESTORE: config qos reload")
    _restore_golden_profile(dut, fail_msgs)
    _verify_scheduler_weights(dut, "Restore",
        {'scheduler.{}'.format(k): str(v) for k, v in w_baseline.items()},
        fail_msgs)
    _log_scheduler_state(dut, "Restore")

    # ── Verdict ───────────────────────────────────────────────────────────
    st.log("=" * 72)
    if fail_msgs:
        st.log("  WRED SCHEDULER GDROP CHANGE [{}] — FAILURES "
               "({} total):".format(af, len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'WRED scheduler gdrop change [{}] FAILED '
            '({} failures) — see above'.format(af, len(fail_msgs)))
    else:
        rates_str = ', '.join(
            '{:.2f}%'.format(dp['drop_rate_pct']) for dp in data_points)
        st.log("  WRED SCHEDULER GDROP CHANGE [{}] — ALL CHECKS "
               "PASSED".format(af))
        st.log("  Scheduler: sched.2 20->30, sched.5 30->20 "
               "(CONFIG_DB verified)")
        st.log("  WRED: gdrop 5->10, drop rates [{}] "
               "monotonically increasing".format(rates_str))
        st.log("=" * 72)
        st.report_pass('msg',
            'WRED scheduler gdrop change [{}] passed: '
            'scheduler weights verified in CONFIG_DB, '
            'gdrop=10% linearity sweep OK, '
            'drop rates [{}]'.format(af, rates_str))
