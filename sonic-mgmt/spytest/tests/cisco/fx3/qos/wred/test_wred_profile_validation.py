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

Testbed (fx3_qos_testbed.yaml — dut1 / FX3 2022):
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
  test_wred_custom_threshold_profile — double min/max thresholds, verify linearity

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
    QUEUE_TO_DSCP, GOLDEN_WRED_PROFILE, NUM_QUEUES,
    IXIA_EGRESS_IP, IXIA_EGRESS_IP6,
    setup_topo_common,
    deploy_dchal_helper,
    ensure_interfaces_admin_up, verify_wred_profile,
    parse_redis_hget, parse_redis_hgetall, run_wred_linearity, dump_l3_diag,
)


# ── Test-specific parameters ──────────────────────────────────────────────
TARGET_QUEUE   = 3
TARGET_DSCP    = QUEUE_TO_DSCP[TARGET_QUEUE]

# ── Linearity sweep margins (Mbps above line rate) ──────────────────────
MARGINS = [0, 250, 500, 1000, 2000, 3000, 4000, 5000, 5250, 5500]

# ── Custom WRED profiles for testing ────────────────────────────────────
CUSTOM_GDROP_PROFILE = dict(GOLDEN_WRED_PROFILE,
                            green_drop_probability='10')

CUSTOM_THRESHOLD_PROFILE = dict(GOLDEN_WRED_PROFILE,
                                green_min_threshold='2097152',
                                green_max_threshold='6291456')

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
    """Check that DUT can reach the egress IXIA IP (ARP/NDP resolved)."""
    if af == "ipv6":
        nb_cmd = 'show ndp'
        target = IXIA_EGRESS_IP6
    else:
        nb_cmd = 'show arp'
        target = IXIA_EGRESS_IP
    nb_out = st.show(dut, "{} {}".format(nb_cmd, target), skip_tmpl=True)
    if target in str(nb_out):
        st.log("{} resolved for {} — OK".format(nb_cmd.upper(), target))
        return True
    st.warn("{} NOT resolved for {} — attempting ping".format(
        nb_cmd.upper(), target))
    ping_cmd = 'ping6' if af == 'ipv6' else 'ping'
    st.config(dut, "{} -c 3 -W 2 {}".format(ping_cmd, target),
              skip_error_check=True)
    st.wait(3)
    nb_out = st.show(dut, "{} {}".format(nb_cmd, target), skip_tmpl=True)
    if target in str(nb_out):
        return True
    dump_l3_diag(dut, target)
    return False


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
    """Verify WRED behavior with custom min/max thresholds (doubled).

    Changes the AZURE_LOSSY profile thresholds from the golden values
    (min=1MB, max=3MB) to doubled values (min=2MB, max=6MB), then runs
    a full WRED linearity sweep.  The linearity helper uses the custom
    profile's threshold values for its zone boundary checks, so the
    wider WRED range should still produce monotonically increasing drop
    rates across the sweep.

    Restores the golden profile via 'config qos reload' after the test.
    """
    st.banner("test_wred_custom_threshold_profile [{}] "
              "gmin=2MB gmax=6MB".format(af))
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

    if fail_msgs:
        _restore_golden_profile(dut, fail_msgs)
        st.report_fail('msg',
                       'WRED custom thresholds [{}] '
                       'FAILED: '.format(af)
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
                       'gmin=2MB gmax=6MB, drop rates [{}] '
                       'monotonically increasing'.format(af, rates_str))


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
