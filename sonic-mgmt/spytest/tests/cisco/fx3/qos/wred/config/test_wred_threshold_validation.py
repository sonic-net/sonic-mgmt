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
FX3 QoS WRED Threshold Validation Tests (Test Plan #6, #7, #9, #10 config).

No IXIA traffic is required.  These tests verify that SAI correctly
rejects invalid min/max threshold configurations applied via ``ecnconfig``,
checking both ASIC_DB and DCHAL HW registers remain unchanged.

Platform limits (from sai_wred.h):
    WRED_MIN_THRESHOLD = 1,048,576  (1 MB) — minimum allowed green min
    WRED_MAX_THRESHOLD = 3,145,728  (3 MB) — maximum allowed green max

Test 6 — min_threshold > max_threshold (REJECTED)
    SAI enforces min < max on each attribute SET to prevent division-by-zero
    in the HAL.  We test min>max which is rejected regardless of the order
    orchagent applies the two attributes.

Test 7 — min_threshold = 0 (below HAL minimum, REJECTED)
    SAI rejects because the hardware AQM profile requires a minimum
    buffer allocation of 1 MB.

Test 9 — max_threshold above platform limit (REJECTED)
    SAI rejects because the ASIC AQM profile has a fixed buffer limit
    of 3 MB; values above this overflow the hardware register.

Test 10 (config) — drop_probability = 0 (ACCEPTED)
    gdrop=0 is a valid configuration that effectively disables WRED
    probabilistic drops.  SAI accepts it and programs the ASIC AQM
    max_prob register to 0.  Thresholds remain at golden values.
"""

import os
import sys
import pytest

from spytest import st

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from fx3_qos_helpers import (
    GOLDEN_WRED_PROFILE,
    ensure_interfaces_admin_up,
    parse_redis_hgetall,
    verify_wred_config_values_prog_in_dchal,
    verify_wred_profile,
)


GDROP_ZERO_PROFILE = dict(GOLDEN_WRED_PROFILE, green_drop_probability='0')


# ── Module state ─────────────────────────────────────────────────────────
dut = None
egress_intf = None


# ── Topology fixture ─────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """Acquire DUT, reload QoS baseline, yield, and restore on teardown."""
    global dut, egress_intf

    st.log("setup_topo: establishing minimum topology D1T1:1")
    tb_dict = st.ensure_min_topology("D1T1:1")
    tb_vars = st.get_testbed_vars()
    dut = tb_dict.D1
    egress_intf = tb_vars.D1T1P1
    st.log("setup_topo: DCHAL egress interface -> {}".format(egress_intf))

    st.log("setup_topo: reloading QoS config for baseline")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    ensure_interfaces_admin_up(dut, [egress_intf])

    st.log("setup_topo: DONE")
    yield

    st.log("setup_topo: teardown — restoring QoS baseline")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    st.log("setup_topo: teardown complete")


# ── ASIC_DB helpers ──────────────────────────────────────────────────────

def _get_asic_db_wred_attrs(dut_handle):
    """Return the WRED SAI attribute dict from ASIC_DB, or {} if not found."""
    out = st.show(
        dut_handle,
        "sonic-db-cli ASIC_DB KEYS '*SAI_OBJECT_TYPE_WRED*'",
        skip_tmpl=True)
    wred_key = None
    for line in str(out).splitlines():
        line = line.strip()
        if 'SAI_OBJECT_TYPE_WRED' in line and line.startswith('ASIC_STATE'):
            wred_key = line
            break
    if not wred_key:
        return {}
    out = st.show(
        dut_handle,
        'sonic-db-cli ASIC_DB HGETALL "{}"'.format(wred_key),
        skip_tmpl=True)
    return parse_redis_hgetall(out)


# ── CONFIG_DB / ecnconfig helpers ────────────────────────────────────────

def _apply_wred_thresholds(dut_handle, gmin, gmax):
    """Set AZURE_LOSSY green min/max thresholds via ecnconfig."""
    st.config(dut_handle,
              "sudo ecnconfig -p AZURE_LOSSY -gmin {} -gmax {}".format(
                  gmin, gmax),
              skip_error_check=True)
    st.wait(2)


def _apply_wred_gdrop(dut_handle, value):
    """Set AZURE_LOSSY green_drop_probability via ecnconfig."""
    st.config(dut_handle,
              "sudo ecnconfig -p AZURE_LOSSY -gdrop {}".format(value),
              skip_error_check=True)
    st.wait(2)


def _restore_qos_baseline(dut_handle):
    """Restore CONFIG_DB to golden values after an invalid ecnconfig write."""
    st.log("  Restoring CONFIG_DB via config qos reload")
    st.config(dut_handle, "config qos reload", skip_error_check=True)
    st.wait(5)
    ensure_interfaces_admin_up(dut_handle, [egress_intf])


# ── Tests ────────────────────────────────────────────────────────────────

def test_reject_min_gt_max():
    """Test 6: min_threshold > max_threshold is rejected by SAI (ASIC_DB unchanged).

    SAI enforces ``min < max`` on each attribute SET.  Orchagent applies
    min and max as separate SAI calls, so we test min>max which triggers
    rejection regardless of attribute ordering.
    """
    st.banner("test_reject_min_gt_max STARTED")
    fail_msgs = []

    st.log("Snapshot: recording ASIC_DB thresholds before test")
    attrs_before = _get_asic_db_wred_attrs(dut)
    asic_gmin_before = attrs_before.get('SAI_WRED_ATTR_GREEN_MIN_THRESHOLD', '')
    asic_gmax_before = attrs_before.get('SAI_WRED_ATTR_GREEN_MAX_THRESHOLD', '')
    st.log("  ASIC_DB min={}, max={}".format(asic_gmin_before, asic_gmax_before))

    st.log("Attempting min > max (gmin=3145728, gmax=1048576)")
    _apply_wred_thresholds(dut, 3145728, 1048576)

    attrs_after = _get_asic_db_wred_attrs(dut)
    asic_gmin_after = attrs_after.get('SAI_WRED_ATTR_GREEN_MIN_THRESHOLD', '')
    asic_gmax_after = attrs_after.get('SAI_WRED_ATTR_GREEN_MAX_THRESHOLD', '')
    st.log("  ASIC_DB min={}, max={} after min>max".format(
        asic_gmin_after, asic_gmax_after))

    if asic_gmin_after != asic_gmin_before:
        fail_msgs.append("ASIC_DB min changed '{}' -> '{}'".format(
            asic_gmin_before, asic_gmin_after))
    if asic_gmax_after != asic_gmax_before:
        fail_msgs.append("ASIC_DB max changed '{}' -> '{}'".format(
            asic_gmax_before, asic_gmax_after))

    st.log("Verify DCHAL HW registers still match golden profile (Q0)")
    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_intf, 0,
        GOLDEN_WRED_PROFILE['green_min_threshold'],
        GOLDEN_WRED_PROFILE['green_max_threshold'],
        GOLDEN_WRED_PROFILE['green_drop_probability'])
    if dchal_rc != 0:
        fail_msgs.append("DCHAL HW changed after min>max attempt (rc={})".format(
            dchal_rc))

    _restore_qos_baseline(dut)

    if fail_msgs:
        st.report_fail('msg',
                       'test_reject_min_gt_max FAILED: '
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'test_reject_min_gt_max passed: '
                       'min>max rejected at SAI, ASIC_DB and DCHAL unchanged')


def test_reject_min_zero():
    """Test 7: min_threshold = 0 (below HAL minimum 1 MB) is rejected at SAI."""
    st.banner("test_reject_min_zero STARTED")
    fail_msgs = []

    st.log("Snapshot: recording ASIC_DB min threshold before test")
    attrs_before = _get_asic_db_wred_attrs(dut)
    asic_gmin_before = attrs_before.get('SAI_WRED_ATTR_GREEN_MIN_THRESHOLD', '')
    st.log("  ASIC_DB min={}".format(asic_gmin_before))

    st.log("Attempting gmin=0, gmax=3145728 (expect SAI rejection)")
    _apply_wred_thresholds(dut, 0, 3145728)

    attrs_after = _get_asic_db_wred_attrs(dut)
    asic_gmin_after = attrs_after.get('SAI_WRED_ATTR_GREEN_MIN_THRESHOLD', '')
    st.log("  ASIC_DB min={} after gmin=0".format(asic_gmin_after))

    if asic_gmin_after != asic_gmin_before:
        fail_msgs.append("ASIC_DB min changed '{}' -> '{}'".format(
            asic_gmin_before, asic_gmin_after))

    st.log("Verify DCHAL HW registers still match golden profile (Q0)")
    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_intf, 0,
        GOLDEN_WRED_PROFILE['green_min_threshold'],
        GOLDEN_WRED_PROFILE['green_max_threshold'],
        GOLDEN_WRED_PROFILE['green_drop_probability'])
    if dchal_rc != 0:
        fail_msgs.append("DCHAL HW changed after gmin=0 attempt (rc={})".format(
            dchal_rc))

    _restore_qos_baseline(dut)

    if fail_msgs:
        st.report_fail('msg',
                       'test_reject_min_zero FAILED: '
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'test_reject_min_zero passed: '
                       'gmin=0 rejected at SAI, ASIC_DB and DCHAL unchanged')


def test_reject_max_above_limit():
    """Test 9: max_threshold above platform limit (3 MB) is rejected at SAI."""
    st.banner("test_reject_max_above_limit STARTED")
    fail_msgs = []

    st.log("Snapshot: recording ASIC_DB max threshold before test")
    attrs_before = _get_asic_db_wred_attrs(dut)
    asic_gmax_before = attrs_before.get('SAI_WRED_ATTR_GREEN_MAX_THRESHOLD', '')
    st.log("  ASIC_DB max={}".format(asic_gmax_before))

    st.log("Attempting gmin=1048576, gmax=4194304 (4 MB, expect SAI rejection)")
    _apply_wred_thresholds(dut, 1048576, 4194304)

    attrs_after = _get_asic_db_wred_attrs(dut)
    asic_gmax_after = attrs_after.get('SAI_WRED_ATTR_GREEN_MAX_THRESHOLD', '')
    st.log("  ASIC_DB max={} after gmax=4MB".format(asic_gmax_after))

    if asic_gmax_after != asic_gmax_before:
        fail_msgs.append("ASIC_DB max changed '{}' -> '{}'".format(
            asic_gmax_before, asic_gmax_after))

    st.log("Verify DCHAL HW registers still match golden profile (Q0)")
    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_intf, 0,
        GOLDEN_WRED_PROFILE['green_min_threshold'],
        GOLDEN_WRED_PROFILE['green_max_threshold'],
        GOLDEN_WRED_PROFILE['green_drop_probability'])
    if dchal_rc != 0:
        fail_msgs.append("DCHAL HW changed after gmax=4MB attempt (rc={})".format(
            dchal_rc))

    _restore_qos_baseline(dut)

    if fail_msgs:
        st.report_fail('msg',
                       'test_reject_max_above_limit FAILED: '
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'test_reject_max_above_limit passed: '
                       'gmax=4194304 rejected at SAI, ASIC_DB and DCHAL unchanged')


def test_gdrop_zero_config():
    """Test 10 (config): drop_probability=0 is accepted and programs HW to 0.

    Setting ``gdrop=0`` effectively disables WRED probabilistic drops while
    leaving the WRED profile bound.  SAI accepts this value and programs the
    ASIC AQM (Active Queue Management) ``max_prob`` register to 0.  The
    min/max thresholds remain at their golden values (1 MB / 3 MB).

    Verifies the full config path:
      ecnconfig CLI -> CONFIG_DB -> orchagent -> SAI -> ASIC_DB -> DCHAL HW
    """
    st.banner("test_gdrop_zero_config STARTED")
    fail_msgs = []

    # ── Step 1: Verify golden baseline ────────────────────────────────────
    st.log("Step 1: Verify golden WRED baseline before any changes")
    if not verify_wred_profile(dut, fail_msgs):
        st.report_fail('msg',
                       'test_gdrop_zero_config FAILED: '
                       'golden baseline not present — '
                       + '; '.join(fail_msgs))
        return

    # ── Step 2: Apply gdrop=0 ─────────────────────────────────────────────
    st.log("Step 2: Applying gdrop=0 via ecnconfig")
    _apply_wred_gdrop(dut, 0)

    # ── Step 3: Log CONFIG_DB state ───────────────────────────────────────
    st.log("Step 3: Logging CONFIG_DB WRED_PROFILE|AZURE_LOSSY")
    out = st.show(
        dut,
        'sonic-db-cli CONFIG_DB HGETALL "WRED_PROFILE|AZURE_LOSSY"',
        skip_tmpl=True)
    config_db_attrs = parse_redis_hgetall(out)
    for field in sorted(config_db_attrs):
        st.log("  CONFIG_DB {} = '{}'".format(field, config_db_attrs[field]))

    # ── Step 4: Verify ASIC_DB ────────────────────────────────────────────
    st.log("Step 4: Verify ASIC_DB SAI_WRED_ATTR_GREEN_DROP_PROBABILITY = 0")
    asic_attrs = _get_asic_db_wred_attrs(dut)
    asic_gdrop = asic_attrs.get('SAI_WRED_ATTR_GREEN_DROP_PROBABILITY', '')
    st.log("  ASIC_DB SAI_WRED_ATTR_GREEN_DROP_PROBABILITY = '{}'".format(
        asic_gdrop))

    if asic_gdrop != '0':
        fail_msgs.append(
            "ASIC_DB GREEN_DROP_PROBABILITY='{}', expected '0'".format(
                asic_gdrop))
        _restore_qos_baseline(dut)
        st.report_fail('msg',
                       'test_gdrop_zero_config FAILED: '
                       + '; '.join(fail_msgs))
        return

    # ── Step 5: Verify DCHAL HW ───────────────────────────────────────────
    st.log("Step 5: Verify DCHAL HW max_prob register = 0 (Q0)")
    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_intf, 0,
        GDROP_ZERO_PROFILE['green_min_threshold'],
        GDROP_ZERO_PROFILE['green_max_threshold'],
        GDROP_ZERO_PROFILE['green_drop_probability'])
    if dchal_rc != 0:
        fail_msgs.append(
            "DCHAL HW mismatch after gdrop=0 (rc={})".format(dchal_rc))

    # ── Step 6: Restore ───────────────────────────────────────────────────
    st.log("Step 6: Restoring golden WRED profile")
    _restore_qos_baseline(dut)

    if fail_msgs:
        st.report_fail('msg',
                       'test_gdrop_zero_config FAILED: '
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'test_gdrop_zero_config passed: gdrop=0 accepted, '
                       'ASIC_DB GREEN_DROP_PROBABILITY=0, '
                       'DCHAL HW max_prob=0')
