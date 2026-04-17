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
FX3 QoS WRED Configuration Propagation Tests (Test Plan #1, #2, #3, #8 config).

No IXIA traffic is required.  These tests verify the WRED configuration
chain from ``config qos reload`` through CONFIG_DB, orchagent / SAI,
ASIC_DB, and into DCHAL HW registers.

Test 1 — Config reaches CONFIG_DB
    After QoS reload, verify WRED_PROFILE|AZURE_LOSSY fields and per-queue
    wred_profile bindings in CONFIG_DB match the ``config_db.json`` baseline.

Test 2 — Config applied to ASIC_DB
    Verify that a SAI_OBJECT_TYPE_WRED object exists in ASIC_DB with correct
    SAI attribute values, and that queue objects reference the WRED OID.

Test 3 — ecnconfig -p set thresholds
    Use ``ecnconfig`` to change green_max_threshold at runtime, verify the
    change in CONFIG_DB (and optionally ASIC_DB), then restore and verify.

Test 8 (config only) — Narrowest valid WRED zone
    Set min=1048576, max=1048577 (1-byte WRED zone) and verify the config
    is accepted in CONFIG_DB and ASIC_DB.  The traffic portion of test 8
    (verifying near-100% drops) is a separate traffic-based test.
"""

import os
import sys
import pytest

from spytest import st

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from fx3_qos_helpers import (
    GOLDEN_WRED_PROFILE,
    verify_wred_profile,
    verify_queue_bindings,
    ensure_interfaces_admin_up,
    parse_redis_hget,
    parse_redis_hgetall,
    verify_wred_config_values_prog_in_dchal,
)


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


# ── CONFIG_DB helpers ────────────────────────────────────────────────────

def _read_wred_field(dut_handle, field):
    """Read a single field from WRED_PROFILE|AZURE_LOSSY in CONFIG_DB."""
    out = st.show(
        dut_handle,
        'sonic-db-cli CONFIG_DB HGET "WRED_PROFILE|AZURE_LOSSY" '
        '"{}"'.format(field), skip_tmpl=True)
    return parse_redis_hget(out).strip()


def _apply_wred_thresholds(dut_handle, gmin, gmax):
    """Set AZURE_LOSSY green min/max thresholds via ecnconfig."""
    st.config(dut_handle,
              "sudo ecnconfig -p AZURE_LOSSY -gmin {} -gmax {}".format(
                  gmin, gmax),
              skip_error_check=True)
    st.wait(2)


# ── Tests ────────────────────────────────────────────────────────────────

def test_config_reaches_config_db():
    """Test 1: After QoS reload, WRED profile and queue bindings are in CONFIG_DB."""
    st.banner("test_config_reaches_config_db STARTED")
    fail_msgs = []

    st.log("Step 1: Verify WRED_PROFILE|AZURE_LOSSY fields in CONFIG_DB")
    verify_wred_profile(dut, fail_msgs)

    st.log("Step 2: Verify QUEUE wred_profile bindings on {}".format(
        egress_intf))
    verify_queue_bindings(dut, egress_intf, fail_msgs)

    if fail_msgs:
        st.report_fail('msg',
                       'test_config_reaches_config_db FAILED: '
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'test_config_reaches_config_db passed: '
                       'WRED profile and queue bindings match baseline')


def test_config_applied_to_asic_db():
    """Test 2: WRED SAI object exists in ASIC_DB with correct attributes."""
    st.banner("test_config_applied_to_asic_db STARTED")
    fail_msgs = []

    st.log("Step 1: Find SAI_OBJECT_TYPE_WRED keys in ASIC_DB")
    wred_keys = _get_asic_db_wred_keys(dut)
    if not wred_keys:
        st.report_fail('msg',
                       'test_config_applied_to_asic_db FAILED: '
                       'no SAI_OBJECT_TYPE_WRED key found in ASIC_DB')
        return

    st.log("  Found WRED key(s): {}".format(wred_keys))
    wred_key = wred_keys[0]

    st.log("Step 2: Verify SAI WRED attributes")
    attrs = _get_asic_db_attrs(dut, wred_key)
    st.log("  ASIC_DB WRED attrs: {}".format(attrs))

    config_drop_prob = _read_wred_field(dut, 'green_drop_probability')

    expected = {
        'SAI_WRED_ATTR_GREEN_ENABLE':          'true',
        'SAI_WRED_ATTR_GREEN_MIN_THRESHOLD':   '1048576',
        'SAI_WRED_ATTR_GREEN_MAX_THRESHOLD':   '3145728',
        'SAI_WRED_ATTR_GREEN_DROP_PROBABILITY': config_drop_prob,
        'SAI_WRED_ATTR_ECN_MARK_MODE':         'SAI_ECN_MARK_MODE_NONE',
        'SAI_WRED_ATTR_WEIGHT':                '0',
    }

    for attr, exp_val in sorted(expected.items()):
        actual = attrs.get(attr, '(missing)')
        if actual.lower() != exp_val.lower():
            fail_msgs.append("{}: expected='{}', actual='{}'".format(
                attr, exp_val, actual))
        else:
            st.log("  {} = '{}' OK".format(attr, actual))

    st.log("Step 3: Verify at least one queue references the WRED OID")
    # Queue attrs reference the OID as "oid:0x<hex>".
    parts = wred_key.split(':')
    wred_oid = ':'.join(parts[-2:]) if len(parts) >= 2 else wred_key
    queue_out = st.show(
        dut,
        "sonic-db-cli ASIC_DB KEYS '*SAI_OBJECT_TYPE_QUEUE*'",
        skip_tmpl=True)
    queue_keys = [
        line.strip() for line in str(queue_out).splitlines()
        if 'SAI_OBJECT_TYPE_QUEUE' in line
        and line.strip().startswith('ASIC_STATE')
    ]

    bound_count = 0
    for qk in queue_keys:
        q_attrs = _get_asic_db_attrs(dut, qk)
        if q_attrs.get('SAI_QUEUE_ATTR_WRED_PROFILE_ID') == wred_oid:
            bound_count += 1

    if bound_count == 0:
        fail_msgs.append(
            "No queue objects reference WRED OID '{}' "
            "(checked {} queue keys)".format(wred_oid, len(queue_keys)))
    else:
        st.log("  {} queue(s) bound to WRED OID — OK".format(bound_count))

    st.log("Step 4: Verify DCHAL HW registers match golden profile (Q0)")
    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_intf, 0,
        GOLDEN_WRED_PROFILE['green_min_threshold'],
        GOLDEN_WRED_PROFILE['green_max_threshold'],
        GOLDEN_WRED_PROFILE['green_drop_probability'])
    if dchal_rc != 0:
        fail_msgs.append("DCHAL HW mismatch for Q0 (rc={})".format(dchal_rc))

    if fail_msgs:
        st.report_fail('msg',
                       'test_config_applied_to_asic_db FAILED: '
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'test_config_applied_to_asic_db passed: '
                       'WRED OID present, {} attrs verified, '
                       '{} queues bound, DCHAL HW OK'.format(
                           len(expected), bound_count))


def test_ecnconfig_set_thresholds():
    """Test 3: ecnconfig updates thresholds in CONFIG_DB, then restore."""
    st.banner("test_ecnconfig_set_thresholds STARTED")
    fail_msgs = []

    new_gmax = '2097152'
    original_gmin = GOLDEN_WRED_PROFILE['green_min_threshold']
    original_gmax = GOLDEN_WRED_PROFILE['green_max_threshold']

    st.log("Step 1: Record original thresholds from CONFIG_DB")
    gmin_before = _read_wred_field(dut, 'green_min_threshold')
    gmax_before = _read_wred_field(dut, 'green_max_threshold')
    st.log("  green_min_threshold = '{}'".format(gmin_before))
    st.log("  green_max_threshold = '{}'".format(gmax_before))

    st.log("Step 2: Set green_max_threshold to {} via ecnconfig".format(
        new_gmax))
    _apply_wred_thresholds(dut, original_gmin, new_gmax)

    st.log("Step 3: Verify CONFIG_DB updated")
    gmax_after = _read_wred_field(dut, 'green_max_threshold')
    st.log("  green_max_threshold after change = '{}'".format(gmax_after))
    if gmax_after != new_gmax:
        fail_msgs.append(
            "green_max_threshold: expected '{}' after ecnconfig, "
            "got '{}'".format(new_gmax, gmax_after))

    st.log("Step 4: Verify ASIC_DB reflects the change")
    wred_keys = _get_asic_db_wred_keys(dut)
    if wred_keys:
        attrs = _get_asic_db_attrs(dut, wred_keys[0])
        asic_gmax = attrs.get('SAI_WRED_ATTR_GREEN_MAX_THRESHOLD', '(missing)')
        st.log("  ASIC_DB SAI_WRED_ATTR_GREEN_MAX_THRESHOLD = '{}'".format(
            asic_gmax))
        if asic_gmax != new_gmax:
            fail_msgs.append(
                "ASIC_DB GREEN_MAX_THRESHOLD: expected '{}', "
                "got '{}'".format(new_gmax, asic_gmax))
    else:
        fail_msgs.append("No WRED key in ASIC_DB to verify change")

    st.log("Step 5: Verify DCHAL HW registers reflect new threshold (Q0)")
    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_intf, 0,
        original_gmin, new_gmax,
        GOLDEN_WRED_PROFILE['green_drop_probability'])
    if dchal_rc != 0:
        fail_msgs.append(
            "DCHAL HW mismatch after threshold change (rc={})".format(dchal_rc))

    st.log("Step 6: Restore original thresholds")
    _apply_wred_thresholds(dut, original_gmin, original_gmax)

    st.log("Step 7: Verify restore in CONFIG_DB")
    gmax_restored = _read_wred_field(dut, 'green_max_threshold')
    st.log("  green_max_threshold after restore = '{}'".format(gmax_restored))
    if gmax_restored != original_gmax:
        fail_msgs.append(
            "green_max_threshold not restored: expected '{}', "
            "got '{}'".format(original_gmax, gmax_restored))

    st.log("Step 8: Verify DCHAL HW registers restored to golden (Q0)")
    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_intf, 0,
        original_gmin, original_gmax,
        GOLDEN_WRED_PROFILE['green_drop_probability'])
    if dchal_rc != 0:
        fail_msgs.append(
            "DCHAL HW mismatch after restore (rc={})".format(dchal_rc))

    if fail_msgs:
        st.report_fail('msg',
                       'test_ecnconfig_set_thresholds FAILED: '
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'test_ecnconfig_set_thresholds passed: '
                       'CONFIG_DB, ASIC_DB, and DCHAL updated to {}, '
                       'then restored to {}'.format(new_gmax, original_gmax))


def test_narrowest_wred_zone():
    """Test 8 (config only): min=1048576, max=1048577 (1-byte WRED zone) is accepted.

    The traffic portion of test 8 (verifying near-100% drops with this
    extreme range) is handled separately in a traffic-based test.
    """
    st.banner("test_narrowest_wred_zone STARTED")
    fail_msgs = []

    narrow_gmin = '1048576'
    narrow_gmax = '1048577'
    original_gmin = GOLDEN_WRED_PROFILE['green_min_threshold']
    original_gmax = GOLDEN_WRED_PROFILE['green_max_threshold']

    st.log("Step 1: Apply narrowest valid WRED zone (gmin={}, gmax={})".format(
        narrow_gmin, narrow_gmax))
    _apply_wred_thresholds(dut, narrow_gmin, narrow_gmax)

    st.log("Step 2: Verify CONFIG_DB accepted the change")
    cfg_gmax = _read_wred_field(dut, 'green_max_threshold')
    st.log("  green_max_threshold = '{}'".format(cfg_gmax))
    if cfg_gmax != narrow_gmax:
        fail_msgs.append(
            "CONFIG_DB green_max_threshold: expected '{}', "
            "got '{}'".format(narrow_gmax, cfg_gmax))

    st.log("Step 3: Verify ASIC_DB reflects the narrow zone")
    wred_keys = _get_asic_db_wred_keys(dut)
    if wred_keys:
        attrs = _get_asic_db_attrs(dut, wred_keys[0])
        asic_gmax = attrs.get('SAI_WRED_ATTR_GREEN_MAX_THRESHOLD', '(missing)')
        st.log("  ASIC_DB SAI_WRED_ATTR_GREEN_MAX_THRESHOLD = '{}'".format(
            asic_gmax))
        if asic_gmax != narrow_gmax:
            fail_msgs.append(
                "ASIC_DB GREEN_MAX_THRESHOLD: expected '{}', "
                "got '{}'".format(narrow_gmax, asic_gmax))
    else:
        fail_msgs.append("No WRED key in ASIC_DB to verify narrow zone")

    st.log("Step 4: Verify DCHAL HW registers reflect narrow zone (Q0)")
    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_intf, 0,
        narrow_gmin, narrow_gmax,
        GOLDEN_WRED_PROFILE['green_drop_probability'])
    if dchal_rc != 0:
        fail_msgs.append(
            "DCHAL HW mismatch for narrow zone (rc={})".format(dchal_rc))

    st.log("Step 5: Restore original thresholds")
    _apply_wred_thresholds(dut, original_gmin, original_gmax)

    gmax_restored = _read_wred_field(dut, 'green_max_threshold')
    st.log("  green_max_threshold after restore = '{}'".format(gmax_restored))
    if gmax_restored != original_gmax:
        fail_msgs.append(
            "green_max_threshold not restored: expected '{}', "
            "got '{}'".format(original_gmax, gmax_restored))

    if fail_msgs:
        st.report_fail('msg',
                       'test_narrowest_wred_zone FAILED: '
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'test_narrowest_wred_zone passed: '
                       '1-byte WRED zone accepted in CONFIG_DB, ASIC_DB, '
                       'and DCHAL, then restored')
