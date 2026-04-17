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
from fx3_qos_helpers import (
    QUEUE_TO_DSCP, GOLDEN_WRED_PROFILE, NUM_QUEUES, WRED_BOUND_QUEUES,
    IXIA_EGRESS_IP, IXIA_EGRESS_IP6,
    setup_topo_common, verify_egress_reachable,
    deploy_dchal_helper,
    ensure_interfaces_admin_up, verify_wred_profile,
    verify_wred_config_values_prog_in_dchal,
    parse_redis_hget, parse_redis_hgetall,
    run_wred_linearity, wred_fanin_send_and_measure, report_wred_result,
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
    """Test 10 (traffic): drop_probability=0 disables WRED probabilistic drops.

    With gdrop=0 the WRED profile is still bound, but the drop probability
    ramp in the WRED zone (between min_threshold and max_threshold) is flat
    at 0%.  The queue fills all the way to max_threshold (~3 MB) before any
    drops occur — and those drops are purely tail drops, not WRED
    probabilistic drops.

    Config phase:
      1. Verify golden baseline
      2. Apply gdrop=0 via ecnconfig
      3. Log CONFIG_DB, verify ASIC_DB and DCHAL HW

    Traffic phase (margin sweep):
      Run fan-in traffic at increasing margins (starts at 500 Mbps above line
      rate, not 0 — avoids flaky shallow-queue drops on breakout paths).  For
      each point:
        - avg_depth < max_threshold  ->  drop_pkts must be 0
        - avg_depth >= max_threshold ->  drop_pkts must be > 0 (tail drops)
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

    # ── Phase 2: Traffic — margin sweep with gdrop=0 ─────────────────────

    st.log("Phase 2: Margin sweep with gdrop=0 [{}]".format(af))
    if not _verify_egress_neighbor(af):
        fail_msgs.append("Egress neighbor not resolved for {}".format(af))
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'test_wred_gdrop_zero [{}] FAILED: {}'.format(
                           af, '; '.join(fail_msgs)))
        return

    # Skip margin 0 — on breakout / single-stream paths, shallow-queue drops can
    # appear before avg_depth reaches max_th; sweep from 500M upward instead.
    gdrop_zero_margins = [500, 1000, 3000, 5000, 7000, 9000, 11000]
    data_points = []
    cooldown = 5

    for margin in gdrop_zero_margins:
        st.log("--- gdrop=0 margin {}M ---".format(margin))
        r = wred_fanin_send_and_measure(
            wred_ctx, af, margin, duration=20, num_depth_samples=3)
        report_wred_result(wred_ctx, r, "gdrop=0 point {}M".format(margin))
        data_points.append(r)

        samples = r.get('depth_samples', [])
        avg_depth = (sum(samples) / len(samples)) if samples else 0
        drop_pkts = r['drop_pkts']
        egress_pkts = r['egress_pkts']

        st.log("  gdrop=0 validation: margin={}M avg_depth={:,.0f}B "
               "({:.2f}MB) drop_pkts={} egress_pkts={}".format(
                   margin, avg_depth, avg_depth / (1024.0 * 1024),
                   drop_pkts, egress_pkts))

        if egress_pkts <= 0:
            fail_msgs.append(
                "Margin={}M: no egress pkts — traffic not forwarded".format(
                    margin))

        if avg_depth < max_threshold and drop_pkts > 0:
            fail_msgs.append(
                "Margin={}M: drop_pkts={} but queue not full "
                "(avg_depth={:,.0f}B < max_th={:,}B) — "
                "WRED should not be dropping with gdrop=0".format(
                    margin, drop_pkts, avg_depth, max_threshold))

        if avg_depth >= max_threshold and drop_pkts <= 0:
            fail_msgs.append(
                "Margin={}M: queue full (avg_depth={:,.0f}B) "
                "but no tail drops".format(margin, avg_depth))

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
        depth_summary = ', '.join(
            '{}M:{:.2f}MB'.format(
                dp['margin_mbps'],
                (sum(dp.get('depth_samples', [0])) /
                 max(len(dp.get('depth_samples', [1])), 1))
                / (1024.0 * 1024))
            for dp in data_points)
        st.report_pass('msg',
                       'test_wred_gdrop_zero [{}] passed: gdrop=0 accepted, '
                       'ASIC_DB=0, DCHAL HW max_prob=0, '
                       'no WRED drops below max_th, '
                       'tail drops above max_th. '
                       'Depths: [{}]'.format(af, depth_summary))


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
