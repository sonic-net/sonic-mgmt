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
FX3 QoS WRED Enable/Disable Config Tests (Test Plan #19, #20).

Validates the WRED unbind and re-enable config paths through CONFIG_DB,
ASIC_DB (SAI objects), and DCHAL HW (AQM registers on the TGEN-facing
port).  No IXIA traffic is required.

Test 19 — Disable WRED (unbind profile)
    Remove ``wred_profile`` from WRED-bound queues (0-6) via CONFIG_DB
    HDEL.  Verify the profile definition persists but queue bindings,
    ASIC_DB queue-to-WRED association, and DCHAL HW registers all
    reflect the disabled state.

Test 20 — Re-enable WRED after disable
    Starting from the disabled state (test 19), run ``config qos reload``
    to re-apply the WRED profile.  Verify CONFIG_DB, ASIC_DB, and DCHAL
    HW all return to the golden baseline with no stale state.

Minimum topology: D1T1:1 (single DUT, one TGEN link).
Works with fx3_qos_testbed_2022.yaml or fx3_qos_testbed_2021.yaml.
"""

import os
import sys
import pytest

from spytest import st

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from fx3_qos_helpers import (
    GOLDEN_WRED_PROFILE,
    WRED_BOUND_QUEUES,
    verify_wred_profile,
    verify_queue_bindings,
    parse_redis_hgetall,
    parse_redis_hget,
    ensure_interfaces_admin_up,
    verify_wred_config_values_prog_in_dchal,
    unbind_wred_from_queues,
    deploy_dchal_helper,
    dchal_aqm_hw_info,
    report_aqm_hw_info,
    get_first_asic_wred_profile_oid,
    verify_queues_wred_binding,
)


# ── Module state ─────────────────────────────────────────────────────────
dut = None
egress_intf = None


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


def _extract_wred_oid(wred_key):
    """Extract the ``oid:0x...`` portion from an ASIC_STATE WRED key."""
    parts = wred_key.split(':')
    return ':'.join(parts[-2:]) if len(parts) >= 2 else wred_key


# ── Unbind + verify-disabled helper ──────────────────────────────────────

def _unbind_wred_and_verify(fail_msgs):
    """Unbind WRED from queues and verify the disabled state across all layers.

    1. Verify golden WRED baseline (CONFIG_DB, ASIC_DB, DCHAL HW).
    2. HDEL wred_profile from WRED-bound queues (0-6).
    3. Verify disabled state:
       - CONFIG_DB: WRED_PROFILE|AZURE_LOSSY still exists; queue bindings removed;
         scheduler fields unaffected.
       - ASIC_DB: queues 0-6 on egress port show oid:0x0; queue 7 unchanged.
       - DCHAL HW: AQM registers zeroed on Q0.

    Returns True on success, False on failure (details in *fail_msgs*).
    """
    # ── Step 1: Verify golden baseline ────────────────────────────────────
    st.log("Step 1: Verify WRED baseline (CONFIG_DB)")
    verify_wred_profile(dut, fail_msgs)
    if fail_msgs:
        return False

    st.log("Step 1b: Verify ASIC_DB WRED object exists")
    wred_oid = get_first_asic_wred_profile_oid(dut)
    if not wred_oid:
        fail_msgs.append("baseline: no SAI_OBJECT_TYPE_WRED key in ASIC_DB")
        return False
    st.log("  WRED OID: {}".format(wred_oid))

    baseline_fail = []
    bound_before = verify_queues_wred_binding(
        dut, egress_intf, WRED_BOUND_QUEUES, wred_oid,
        baseline_fail, "baseline")
    st.log("  queues bound to WRED OID before unbind: {}".format(bound_before))
    if bound_before == 0:
        fail_msgs.extend(baseline_fail)
        fail_msgs.append("baseline: no queues bound to WRED OID in ASIC_DB")
        return False

    st.log("Step 1c: Verify DCHAL HW baseline (Q0)")
    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_intf, 0,
        GOLDEN_WRED_PROFILE['green_min_threshold'],
        GOLDEN_WRED_PROFILE['green_max_threshold'],
        GOLDEN_WRED_PROFILE['green_drop_probability'])
    if dchal_rc != 0:
        fail_msgs.append(
            "baseline: DCHAL HW mismatch for Q0 (rc={})".format(dchal_rc))
        return False

    # ── Step 2: Unbind WRED from queues ───────────────────────────────────
    st.log("Step 2: Unbind WRED from queues 0-6")
    unbind_wred_from_queues(dut, egress_intf)

    # ── Step 3: Verify disabled state ─────────────────────────────────────

    # 3a — CONFIG_DB: profile definition still exists
    st.log("Step 3a: Verify WRED_PROFILE|AZURE_LOSSY still exists")
    profile_fail = []
    verify_wred_profile(dut, profile_fail)
    if profile_fail:
        fail_msgs.append(
            "post-unbind: WRED_PROFILE|AZURE_LOSSY missing or changed: "
            + '; '.join(profile_fail))

    # 3b — CONFIG_DB: wred_profile removed from queues; scheduler intact
    st.log("Step 3b: Verify wred_profile removed from queue bindings")
    for q in WRED_BOUND_QUEUES:
        wred_out = st.show(
            dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "wred_profile"'.format(
                egress_intf, q),
            skip_tmpl=True)
        val = parse_redis_hget(wred_out).strip()
        if val and val not in ('', 'None', '-'):
            fail_msgs.append(
                "post-unbind: QUEUE|{}|{} wred_profile still set: '{}'".format(
                    egress_intf, q, val))
        else:
            st.log("  Q{} wred_profile removed — OK".format(q))

        sched_out = st.show(
            dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(
                egress_intf, q),
            skip_tmpl=True)
        sched_val = parse_redis_hget(sched_out).strip()
        if not sched_val or sched_val in ('', 'None', '-'):
            fail_msgs.append(
                "post-unbind: QUEUE|{}|{} scheduler unexpectedly cleared".format(
                    egress_intf, q))
        else:
            st.log("  Q{} scheduler = '{}' — intact".format(q, sched_val))

    # 3c — ASIC_DB: queues 0-6 unbound (oid:0x0); queue 7 stays oid:0x0
    st.log("Step 3c: Verify ASIC_DB queues unbound from WRED")
    verify_queues_wred_binding(
        dut, egress_intf, WRED_BOUND_QUEUES, 'oid:0x0',
        fail_msgs, "post-unbind")
    verify_queues_wred_binding(
        dut, egress_intf, [7], 'oid:0x0',
        fail_msgs, "post-unbind Q7 unchanged")

    # 3d — DCHAL HW: WRED registers zeroed on Q0
    st.log("Step 3d: Verify DCHAL HW reflects WRED disabled (Q0)")
    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_intf, 0, '0', '0', '0')
    if dchal_rc != 0:
        fail_msgs.append(
            "post-unbind: DCHAL HW not zeroed for Q0 (rc={})".format(dchal_rc))

    deploy_dchal_helper(dut)
    aqm_data = dchal_aqm_hw_info(dut, egress_intf)
    report_aqm_hw_info(aqm_data)

    return len(fail_msgs) == 0


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

def test_wred_disable_unbind_profile():
    """
    Test 19 (config only): Disable WRED by unbinding the profile from queues.

    Removes the ``wred_profile`` field from WRED-bound queues (0-6) via
    CONFIG_DB HDEL and verifies:
      - CONFIG_DB: WRED_PROFILE|AZURE_LOSSY persists; queue bindings cleared;
        scheduler bindings unaffected.
      - ASIC_DB: queue objects no longer reference the WRED OID.
      - DCHAL HW: AQM registers (min_thr, max_thr, max_prob) zeroed on Q0.
    """
    st.banner("test_wred_disable_unbind_profile STARTED")
    fail_msgs = []

    success = _unbind_wred_and_verify(fail_msgs)

    if not success:
        st.report_fail(
            'msg',
            'test_wred_disable_unbind_profile FAILED: '
            + '; '.join(fail_msgs))
    else:
        st.report_pass(
            'msg',
            'test_wred_disable_unbind_profile passed: '
            'WRED unbound — CONFIG_DB profile persists, queue bindings '
            'cleared, ASIC_DB unbound, DCHAL HW zeroed')


def test_wred_reenable_after_disable():
    """
    Test 20 (config only): Re-enable WRED after disable via config qos reload.

    Unbinds WRED (reuses test 19 logic), then runs ``config qos reload``
    and verifies full restoration:
      - CONFIG_DB: WRED_PROFILE|AZURE_LOSSY golden values; queue bindings
        restored (wred_profile = AZURE_LOSSY on queues 0-6).
      - ASIC_DB: SAI WRED object with correct attributes; queues bound.
      - DCHAL HW: AQM registers match golden profile on Q0.
    """
    st.banner("test_wred_reenable_after_disable STARTED")
    fail_msgs = []

    # ── Restore baseline in case a prior test left WRED unbound ───────────
    st.log("Precondition: config qos reload to restore WRED baseline")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    ensure_interfaces_admin_up(dut, [egress_intf])

    # ── Precondition: unbind WRED ─────────────────────────────────────────
    st.log("Precondition: unbind WRED to establish disabled state")
    unbind_fail = []
    success = _unbind_wred_and_verify(unbind_fail)
    if not success:
        st.report_fail(
            'msg',
            'test_wred_reenable_after_disable FAILED (precondition): '
            'unbind step failed: ' + '; '.join(unbind_fail))
        return

    # ── Re-enable: config qos reload ──────────────────────────────────────
    st.log("Step 1: Re-enable WRED via config qos reload")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    ensure_interfaces_admin_up(dut, [egress_intf])

    # ── Verify CONFIG_DB: profile restored ────────────────────────────────
    st.log("Step 2: Verify CONFIG_DB — WRED_PROFILE|AZURE_LOSSY restored")
    verify_wred_profile(dut, fail_msgs)

    # ── Verify CONFIG_DB: queue bindings restored ─────────────────────────
    st.log("Step 3: Verify CONFIG_DB — queue bindings restored")
    verify_queue_bindings(dut, egress_intf, fail_msgs)

    # ── Verify ASIC_DB: WRED object + queue binding ───────────────────────
    st.log("Step 4: Verify ASIC_DB — WRED object with correct SAI attributes")
    wred_keys = sorted(_get_asic_db_wred_keys(dut))
    if not wred_keys:
        fail_msgs.append(
            "post-reload: no SAI_OBJECT_TYPE_WRED key in ASIC_DB")
    else:
        wred_key = wred_keys[0]
        wred_oid = _extract_wred_oid(wred_key)
        attrs = _get_asic_db_attrs(dut, wred_key)
        st.log("  ASIC_DB WRED attrs: {}".format(attrs))

        config_drop_prob = GOLDEN_WRED_PROFILE['green_drop_probability']
        expected_sai = {
            'SAI_WRED_ATTR_GREEN_ENABLE':          'true',
            'SAI_WRED_ATTR_GREEN_MIN_THRESHOLD':   '1048576',
            'SAI_WRED_ATTR_GREEN_MAX_THRESHOLD':   '3145728',
            'SAI_WRED_ATTR_GREEN_DROP_PROBABILITY': config_drop_prob,
            'SAI_WRED_ATTR_ECN_MARK_MODE':         'SAI_ECN_MARK_MODE_NONE',
            'SAI_WRED_ATTR_WEIGHT':                '0',
        }
        for attr, exp_val in sorted(expected_sai.items()):
            actual = attrs.get(attr, '(missing)')
            if actual.lower() != exp_val.lower():
                fail_msgs.append(
                    "post-reload ASIC_DB {}: expected='{}', actual='{}'".format(
                        attr, exp_val, actual))
            else:
                st.log("  {} = '{}' OK".format(attr, actual))

        st.log("Step 4b: Verify queues re-bound to WRED OID")
        verify_queues_wred_binding(
            dut, egress_intf, WRED_BOUND_QUEUES, wred_oid,
            fail_msgs, "post-reload")
        verify_queues_wred_binding(
            dut, egress_intf, [7], 'oid:0x0',
            fail_msgs, "post-reload Q7 unchanged")

    # ── Verify DCHAL HW: golden profile programmed ────────────────────────
    st.log("Step 5: Verify DCHAL HW — golden WRED profile on Q0")
    dchal_rc = verify_wred_config_values_prog_in_dchal(
        dut, egress_intf, 0,
        GOLDEN_WRED_PROFILE['green_min_threshold'],
        GOLDEN_WRED_PROFILE['green_max_threshold'],
        GOLDEN_WRED_PROFILE['green_drop_probability'])
    if dchal_rc != 0:
        fail_msgs.append(
            "post-reload: DCHAL HW mismatch for Q0 (rc={})".format(dchal_rc))

    deploy_dchal_helper(dut)
    aqm_data = dchal_aqm_hw_info(dut, egress_intf)
    report_aqm_hw_info(aqm_data)

    # ── Report ────────────────────────────────────────────────────────────
    if fail_msgs:
        st.report_fail(
            'msg',
            'test_wred_reenable_after_disable FAILED: '
            + '; '.join(fail_msgs))
    else:
        st.report_pass(
            'msg',
            'test_wred_reenable_after_disable passed: '
            'WRED re-enabled — CONFIG_DB profile + bindings restored, '
            'ASIC_DB WRED object + queue binding OK, DCHAL HW matches golden')
