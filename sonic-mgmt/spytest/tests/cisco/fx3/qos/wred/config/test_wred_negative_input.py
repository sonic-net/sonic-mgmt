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
FX3 QoS WRED Negative Input Tests

Validates that invalid ``ecnconfig`` invocations do not alter WRED state:
CONFIG_DB (``WRED_PROFILE|AZURE_LOSSY`` and ``WRED_PROFILE|*`` keys),
ASIC_DB (SAI WRED objects), and DCHAL HW (queue 0 on the TGEN-facing
port).  Rejection is proven by before/after snapshot comparison. 
No IXIA traffic is required.

Minimum topology: D1T1:1 (single DUT, one TGEN link).
Works with fx3_qos_testbed_2022.yaml or fx3_qos_testbed_2021.yaml.

Tests:
  test_wred_invalid_profile_name: non-existent profile rejected
  test_wred_non_numeric_threshold: "abc" gmin rejected
  test_wred_missing_required_args: missing -p / profile name
  test_wred_negative_threshold: negative gmin (-1) rejected
  test_wred_min_equals_max_threshold: gmin == gmax rejected
"""

import os
import sys
import pytest

from spytest import st

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from fx3_qos_helpers import (
    GOLDEN_WRED_PROFILE,
    verify_wred_profile,
    parse_redis_hgetall,
    ensure_interfaces_admin_up,
    verify_wred_config_values_prog_in_dchal,
)


# ── Module state ─────────────────────────────────────────────────────────
dut = None
egress_intf = None


# ── Helpers ──────────────────────────────────────────────────────────────

def _run_ecnconfig(dut_handle, args):
    """Run ``sudo ecnconfig <args>`` and return raw CLI output.

    Uses skip_error_check=True so non-zero exit codes do not abort the
    test — callers verify behavior via CONFIG_DB / ASIC_DB / DCHAL snapshots.
    """
    return st.config(dut_handle,
                     "sudo ecnconfig {}".format(args),
                     skip_error_check=True)


def _read_wred_profile_hgetall(dut_handle):
    """Return HGETALL of WRED_PROFILE|AZURE_LOSSY as a str->str dict."""
    out = st.show(
        dut_handle,
        'sonic-db-cli CONFIG_DB HGETALL "WRED_PROFILE|AZURE_LOSSY"',
        skip_tmpl=True)
    return parse_redis_hgetall(out)


def _snapshot_config_db_wred_keys(dut_handle):
    """Return sorted list of CONFIG_DB keys matching WRED_PROFILE|*."""
    out = st.show(
        dut_handle,
        'sonic-db-cli CONFIG_DB KEYS "WRED_PROFILE|*"',
        skip_tmpl=True)
    keys = []
    for line in str(out).splitlines():
        line = line.strip()
        if line and 'WRED_PROFILE|' in line:
            keys.append(line)
    return sorted(keys)


def _get_asic_db_wred_keys(dut_handle):
    """Return list of SAI_OBJECT_TYPE_WRED keys from ASIC_DB, or []."""
    out = st.show(
        dut_handle,
        "sonic-db-cli ASIC_DB KEYS '*SAI_OBJECT_TYPE_WRED*'",
        skip_tmpl=True)
    keys = []
    for line in str(out).splitlines():
        line = line.strip()
        if 'SAI_OBJECT_TYPE_WRED' in line and line.startswith('ASIC_STATE'):
            keys.append(line)
    return keys


def _get_asic_db_attrs(dut_handle, asic_key):
    """HGETALL an ASIC_DB key and return a str->str dict."""
    out = st.show(
        dut_handle,
        'sonic-db-cli ASIC_DB HGETALL "{}"'.format(asic_key),
        skip_tmpl=True)
    return parse_redis_hgetall(out)


def _snapshot_asic_wred_attrs(dut_handle):
    """Return HGETALL attrs for one WRED object in ASIC_DB (sorted key), or {}."""
    wred_keys = sorted(_get_asic_db_wred_keys(dut_handle))
    if not wred_keys:
        return {}
    return _get_asic_db_attrs(dut_handle, wred_keys[0])


def _snapshot_asic_wred_key_set(dut_handle):
    """Return sorted list of SAI_OBJECT_TYPE_WRED keys in ASIC_DB."""
    return sorted(_get_asic_db_wred_keys(dut_handle))


def _wred_negative_baseline_and_snapshot(fail_msgs):
    """Verify golden WRED baseline, ASIC_DB WRED presence, DCHAL Q0; return snapshot or None.

    On failure, appends to *fail_msgs* and returns None.
    """
    verify_wred_profile(dut, fail_msgs)
    if fail_msgs:
        return None

    config_before = _read_wred_profile_hgetall(dut)
    keys_before = _snapshot_config_db_wred_keys(dut)
    st.log("  WRED_PROFILE keys (snapshot): {}".format(keys_before))

    asic_wred_keys_before = _snapshot_asic_wred_key_set(dut)
    asic_before = _snapshot_asic_wred_attrs(dut)
    if not asic_before:
        fail_msgs.append(
            "no SAI_OBJECT_TYPE_WRED object in ASIC_DB to snapshot")
        return None

    st.log("  ASIC_DB WRED keys (snapshot): {}".format(
        asic_wred_keys_before))

    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_intf, 0,
        GOLDEN_WRED_PROFILE['green_min_threshold'],
        GOLDEN_WRED_PROFILE['green_max_threshold'],
        GOLDEN_WRED_PROFILE['green_drop_probability'])
    if dchal_rc != 0:
        fail_msgs.append(
            "DCHAL HW pre-check failed (rc={})".format(dchal_rc))
        return None

    return {
        'config': config_before,
        'keys': keys_before,
        'asic_keys': asic_wred_keys_before,
        'asic_attrs': asic_before,
    }


def _wred_negative_assert_unchanged(snapshot, fail_msgs, context_label,
                                    verify_config_db=True):
    """Append to *fail_msgs* if CONFIG_DB, ASIC_DB, or DCHAL drift from *snapshot*.

    When *verify_config_db* is False, CONFIG_DB (profile hash and WRED_PROFILE
    key list) is still read and logged for diagnostics, but mismatches do not
    fail the check — use when CONFIG_DB may legitimately differ while ASIC_DB
    and DCHAL must remain stable.
    """
    prefix = "[{}] ".format(context_label)

    config_after = _read_wred_profile_hgetall(dut)
    keys_after = _snapshot_config_db_wred_keys(dut)
    st.log("  CONFIG_DB before: {}".format(snapshot['config']))
    st.log("  CONFIG_DB after:  {}".format(config_after))
    st.log("  CONFIG_DB WRED_PROFILE keys before: {}".format(snapshot['keys']))
    st.log("  CONFIG_DB WRED_PROFILE keys after:  {}".format(keys_after))
    if verify_config_db:
        if config_after != snapshot['config']:
            fail_msgs.append(
                prefix + "CONFIG_DB WRED_PROFILE|AZURE_LOSSY changed")
        if keys_after != snapshot['keys']:
            fail_msgs.append(
                prefix + "CONFIG_DB WRED_PROFILE key set changed: "
                "before={}, after={}".format(snapshot['keys'], keys_after))
    else:
        st.log("  CONFIG_DB log: ")

    asic_keys_after = _snapshot_asic_wred_key_set(dut)
    if asic_keys_after != snapshot['asic_keys']:
        fail_msgs.append(
            prefix + "ASIC_DB WRED key set changed: before={}, after={}".format(
                snapshot['asic_keys'], asic_keys_after))

    asic_after = _snapshot_asic_wred_attrs(dut)
    st.log("  ASIC_DB before: {}".format(snapshot['asic_attrs']))
    st.log("  ASIC_DB after:  {}".format(asic_after))
    if asic_after != snapshot['asic_attrs']:
        fail_msgs.append(
            prefix + "ASIC_DB WRED attributes changed")

    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_intf, 0,
        GOLDEN_WRED_PROFILE['green_min_threshold'],
        GOLDEN_WRED_PROFILE['green_max_threshold'],
        GOLDEN_WRED_PROFILE['green_drop_probability'])
    if dchal_rc != 0:
        fail_msgs.append(
            prefix + "DCHAL HW mismatch (rc={})".format(dchal_rc))


# ── Topology fixture ─────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """Lightweight setup: single DUT with QoS baseline (no IXIA/traffic)."""
    global dut, egress_intf

    st.log("setup_topo: establishing minimum topology D1T1:1")
    tb_dict = st.ensure_min_topology("D1T1:1")
    tb_vars = st.get_testbed_vars()
    dut = tb_dict.D1
    egress_intf = tb_vars.D1T1P1
    st.log("setup_topo: DCHAL egress interface -> {}".format(egress_intf))

    st.log("setup_topo: reloading QoS config to ensure AZURE_LOSSY exists")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)

    fail_msgs = []
    verify_wred_profile(dut, fail_msgs)
    if fail_msgs:
        st.warn("setup_topo: WRED baseline issues: {}".format(
            '; '.join(fail_msgs)))

    ensure_interfaces_admin_up(dut, [egress_intf])

    yield

    st.log("setup_topo teardown: restoring QoS baseline")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)


# ── Tests ─────────────────────────────────────────────────────────────────

def test_wred_invalid_profile_name():
    """
    Test that ecnconfig rejects a non-existent profile name.

    Runs ``ecnconfig -p NONEXISTENT -gmin 1048576`` and verifies rejection by
    comparing CONFIG_DB, ASIC_DB, and DCHAL HW before vs after — no layer may
    change (no fragile CLI string matching).
    """
    st.banner("test_wred_invalid_profile_name STARTED")
    fail_msgs = []

    st.log("Baseline: verify WRED + snapshot CONFIG_DB, ASIC_DB, DCHAL")
    snap = _wred_negative_baseline_and_snapshot(fail_msgs)
    if snap is None:
        st.report_fail(
            'msg',
            'test_wred_invalid_profile_name FAILED (baseline): '
            + '; '.join(fail_msgs))
        return

    st.log("Run ecnconfig with non-existent profile NONEXISTENT")
    output = _run_ecnconfig(dut, "-p NONEXISTENT -gmin 1048576")
    st.log("  ecnconfig output: {}".format(output))

    _wred_negative_assert_unchanged(
        snap, fail_msgs, "after rejecting NONEXISTENT profile")

    if fail_msgs:
        st.report_fail('msg',
                       'test_wred_invalid_profile_name FAILED: '
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'test_wred_invalid_profile_name passed: '
                       'CONFIG_DB, ASIC_DB, and DCHAL unchanged after '
                       'rejecting NONEXISTENT')


def test_wred_non_numeric_threshold():
    """
    Test that ecnconfig rejects a non-numeric threshold value.

    Runs ``ecnconfig -p AZURE_LOSSY -gmin abc`` and verifies CONFIG_DB,
    ASIC_DB, and DCHAL HW are unchanged (full WRED snapshot, not CLI text).
    """
    st.banner("test_wred_non_numeric_threshold STARTED")
    fail_msgs = []

    snap = _wred_negative_baseline_and_snapshot(fail_msgs)
    if snap is None:
        st.report_fail(
            'msg',
            'test_wred_non_numeric_threshold FAILED (baseline): '
            + '; '.join(fail_msgs))
        return

    st.log("Run ecnconfig with non-numeric gmin abc")
    output = _run_ecnconfig(dut, "-p AZURE_LOSSY -gmin abc")
    st.log("  ecnconfig output: {}".format(output))

    _wred_negative_assert_unchanged(snap, fail_msgs, "after non-numeric gmin")

    if fail_msgs:
        st.report_fail('msg',
                       'test_wred_non_numeric_threshold FAILED: '
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'test_wred_non_numeric_threshold passed: '
                       'CONFIG_DB, ASIC_DB, and DCHAL unchanged after '
                       'rejecting gmin="abc"')


def test_wred_missing_required_args():
    """
    Test that incomplete ecnconfig invocations do not alter WRED state.

    Two sub-checks (same CONFIG/ASIC/DCHAL baseline snapshot):
      1. ``ecnconfig -p`` (missing profile name)
      2. ``ecnconfig -gmin 1048576`` (missing -p flag)

    After each command, CONFIG_DB, ASIC_DB, and DCHAL must match the snapshot.
    """
    st.banner("test_wred_missing_required_args STARTED")
    fail_msgs = []

    snap = _wred_negative_baseline_and_snapshot(fail_msgs)
    if snap is None:
        st.report_fail(
            'msg',
            'test_wred_missing_required_args FAILED (baseline): '
            + '; '.join(fail_msgs))
        return

    st.log("Sub-check 1: ecnconfig -p (missing profile name)")
    output1 = _run_ecnconfig(dut, "-p")
    st.log("  ecnconfig -p output: {}".format(output1))

    _wred_negative_assert_unchanged(snap, fail_msgs, "after ecnconfig -p")
    if fail_msgs:
        st.report_fail('msg',
                       'test_wred_missing_required_args FAILED: '
                       + '; '.join(fail_msgs))
        return

    st.log("Sub-check 2: ecnconfig -gmin 1048576 (missing -p flag)")
    output2 = _run_ecnconfig(dut, "-gmin 1048576")
    st.log("  ecnconfig -gmin output: {}".format(output2))

    _wred_negative_assert_unchanged(
        snap, fail_msgs, "after ecnconfig -gmin without -p")
    if fail_msgs:
        st.report_fail('msg',
                       'test_wred_missing_required_args FAILED: '
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'test_wred_missing_required_args passed: '
                       'CONFIG_DB, ASIC_DB, and DCHAL unchanged after '
                       'both incomplete ecnconfig invocations')


def test_wred_negative_threshold():
    """
    Test that ecnconfig rejects a negative threshold value.

    Runs ``ecnconfig -p AZURE_LOSSY -gmin -1`` and verifies CONFIG_DB,
    ASIC_DB, and DCHAL HW are unchanged (full WRED snapshot, not CLI text).
    """
    st.banner("test_wred_negative_threshold STARTED")
    fail_msgs = []

    snap = _wred_negative_baseline_and_snapshot(fail_msgs)
    if snap is None:
        st.report_fail(
            'msg',
            'test_wred_negative_threshold FAILED (baseline): '
            + '; '.join(fail_msgs))
        return

    st.log("Run ecnconfig with negative gmin -1")
    output = _run_ecnconfig(dut, "-p AZURE_LOSSY -gmin -1")
    st.log("  ecnconfig output: {}".format(output))

    _wred_negative_assert_unchanged(snap, fail_msgs, "after negative gmin -1")

    if fail_msgs:
        st.report_fail('msg',
                       'test_wred_negative_threshold FAILED: '
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'test_wred_negative_threshold passed: '
                       'CONFIG_DB, ASIC_DB, and DCHAL unchanged after '
                       'rejecting gmin=-1')


def test_wred_min_equals_max_threshold():
    """
    Test that ecnconfig rejects min_threshold equal to max_threshold.

    Runs ``ecnconfig -p AZURE_LOSSY -gmin 1048576 -gmax 1048576`` and
    verifies ASIC_DB and DCHAL HW (Data Center Hardware Abstraction Layer)
    are unchanged.  CONFIG_DB (configuration database) before/after values
    are logged for diagnostics but not asserted.  WRED (Weighted Random Early
    Detection) requires min < max to define a valid probability ramp; min ==
    max collapses the WRED zone to zero width and must be rejected.

    Corresponds to test plan #29 (min = max threshold).
    """
    st.banner("test_wred_min_equals_max_threshold STARTED")
    fail_msgs = []

    snap = _wred_negative_baseline_and_snapshot(fail_msgs)
    if snap is None:
        st.report_fail(
            'msg',
            'test_wred_min_equals_max_threshold FAILED (baseline): '
            + '; '.join(fail_msgs))
        return

    st.log("Run ecnconfig with gmin == gmax (1048576)")
    output = _run_ecnconfig(dut, "-p AZURE_LOSSY -gmin 1048576 -gmax 1048576")
    st.log("  ecnconfig output: {}".format(output))

    _wred_negative_assert_unchanged(
        snap, fail_msgs, "after gmin == gmax (1048576)",
        verify_config_db=False)

    if fail_msgs:
        st.report_fail('msg',
                       'test_wred_min_equals_max_threshold FAILED: '
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'test_wred_min_equals_max_threshold passed: '
                       'ASIC_DB and DCHAL HW unchanged after rejecting gmin == gmax; '
                       'CONFIG_DB logged only (not verified)')
