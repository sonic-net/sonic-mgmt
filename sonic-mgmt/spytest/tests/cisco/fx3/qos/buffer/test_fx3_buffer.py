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
FX3 QoS Buffer Pool & Profile Tests — SONiC end-to-end verification.

FX3 buffer_manager constraints (src/sai_buffer.cpp):
  - One default egress pool seeded at init:
      TYPE=EGRESS, THRESHOLD_MODE=DYNAMIC, SIZE=39,022,464 bytes
      (DEFAULT_POOL_CELLS=93804 * CELL_SIZE_BYTES=416)
  - One default egress profile seeded at init:
      POOL_ID=<default pool>, THRESHOLD_MODE=DYNAMIC,
      SHARED_DYNAMIC_TH=27 (alpha=0x1b)
  - create with matching default attrs returns pre-seeded OID (idempotent)
  - create with non-matching attrs → NOT_SUPPORTED
  - set with matching HW value → SUCCESS; mismatch → NOT_SUPPORTED
  - remove operations → NOT_SUPPORTED
  - All IPG APIs → NOT_SUPPORTED

FX3 HW constants:
  CELL_SIZE_BYTES         = 416
  DEFAULT_POOL_CELLS      = 93804
  EXPECTED_POOL_SIZE      = 93804 * 416 = 39,022,464 bytes
  DEFAULT_DYNAMIC_TH      = 27

SONiC Redis paths:
  CONFIG_DB  BUFFER_POOL|<name>     TYPE / MODE / SIZE
  CONFIG_DB  BUFFER_PROFILE|<name>  POOL / DYNAMIC_TH / STATIC_TH / XOFF / XON
  ASIC_DB    SAI_OBJECT_TYPE_BUFFER_POOL:<oid>
  ASIC_DB    SAI_OBJECT_TYPE_BUFFER_PROFILE:<oid>
  COUNTERS_DB PERIODIC_WATERMARKS|<oid>    (FX3: not COUNTERS:<oid>)

Test plan mapping (scheduler_test_plan.md buffer section):
  (test_fx3_buffer_pool_exists)         — pool exists in CONFIG_DB + ASIC_DB
  (test_fx3_buffer_pool_type_egress)    — TYPE=egress
  (test_fx3_buffer_pool_mode_dynamic)   — MODE=dynamic
  (test_fx3_buffer_pool_size)           — SIZE matches HW constant
  (test_fx3_buffer_profile_exists)      — profile exists in CONFIG_DB + ASIC_DB
  (test_fx3_buffer_profile_dynamic_th)  — DYNAMIC_TH=27 in ASIC_DB
  (test_fx3_buffer_pool_stats)          — watermark/occupancy stats readable and sane
"""

import pytest

from fx3_qos_helpers import (
    parse_redis_hget,
    parse_redis_hgetall,
    ensure_interfaces_admin_up,
    tg_port_speed_gbps,
    get_dut_mac,
)

from spytest import st, tgapi

# ---------------------------------------------------------------------------
# FX3 HW constants
# ---------------------------------------------------------------------------
CELL_SIZE_BYTES    = 416
DEFAULT_POOL_CELLS = 93804
EXPECTED_POOL_SIZE = DEFAULT_POOL_CELLS * CELL_SIZE_BYTES   # 39,022,464
DEFAULT_DYNAMIC_TH = 27

# Default SONiC buffer object names on FX3 (as configured by config qos reload)
# FX3 uses lossy (not lossless) naming; two profiles exist: _dwrr and _sp.
DEFAULT_POOL_NAME    = 'egress_lossy_pool'
DEFAULT_PROFILE_NAME = 'egress_lossy_profile_dwrr'

# ---------------------------------------------------------------------------
# Module-level DUT/port state (populated by setup_topo fixture)
# ---------------------------------------------------------------------------
dut        = None
port_info  = {}

# ---------------------------------------------------------------------------
# Module-level Ixia/traffic state (populated by setup_traffic fixture)
# ---------------------------------------------------------------------------
tg           = None    # tg object from tgapi.get_handle_byname
tg_ph        = {}      # {'ingress_a': ph, 'egress': ph}
port_speeds  = {}      # {'ingress_a': 100, 'egress': 100}  Gbps
STREAM_RATE_PCT = 90   # % of line rate; 2 ingress × 90% = 180% total → congests 10G egress buffer

# L3 addressing for traffic-based buffer tests (ingress_a + ingress_b → egress)
_DUT_IPV4 = {
    'ingress_a': '10.10.10.1/24',
    'ingress_b': '10.10.11.1/24',
    'egress':    '20.20.20.1/24',
}
_IXIA_IPV4 = {
    'ingress_a': '10.10.10.2',
    'ingress_b': '10.10.11.2',
    'egress':    '20.20.20.2',
}
_IXIA_GWV4      = {role: ip.split('/')[0] for role, ip in _DUT_IPV4.items()}
_NETMASK        = '255.255.255.0'
_IXIA_EGRESS_IP = _IXIA_IPV4['egress']
_PKT_SIZE       = 128
_TRAFFIC_DURATION = 10
# DSCP value that maps to each TC/queue under the FX3 default AZURE DSCP map
_QUEUE_TO_DSCP  = {0: 0, 1: 6, 2: 2, 3: 3, 4: 4, 5: 46, 6: 48, 7: 49}


@pytest.fixture(scope='module')
def setup_topo(request):
    """Resolve DUT handle and port map from testbed; verify interfaces up."""
    global dut, port_info

    tbd = st.get_testbed_vars()
    dut = tbd.D1

    port_info = {
        'egress':   tbd.D1T1P3,
        'ingress_a': tbd.D1T1P1,
        'ingress_b': tbd.D1T1P2,
    }

    st.log("Buffer test topology:")
    for role, intf in port_info.items():
        st.log("  {:<12} -> {}".format(role, intf))

    yield

    st.log("Buffer test teardown complete")


# ---------------------------------------------------------------------------
# Helper: read CONFIG_DB BUFFER_POOL|<name>
# ---------------------------------------------------------------------------
def _get_pool_config(dut_h, pool_name):
    out = st.show(dut_h,
        'sonic-db-cli CONFIG_DB HGETALL "BUFFER_POOL|{}"'.format(pool_name),
        skip_tmpl=True)
    return parse_redis_hgetall(out)


# ---------------------------------------------------------------------------
# Helper: read CONFIG_DB BUFFER_PROFILE|<name>
# ---------------------------------------------------------------------------
def _get_profile_config(dut_h, profile_name):
    out = st.show(dut_h,
        'sonic-db-cli CONFIG_DB HGETALL "BUFFER_PROFILE|{}"'.format(profile_name),
        skip_tmpl=True)
    return parse_redis_hgetall(out)


# ---------------------------------------------------------------------------
# Helper: get ASIC_DB OID for a buffer pool by name (via STATE_DB or COUNTERS_DB)
# ---------------------------------------------------------------------------
def _get_pool_oid(dut_h, pool_name):
    """Return the ASIC_DB OID string for a buffer pool, or None if not found."""
    out = st.show(dut_h,
        'sonic-db-cli COUNTERS_DB HGET "COUNTERS_BUFFER_POOL_NAME_MAP" "{}"'.format(
            pool_name),
        skip_tmpl=True)
    return parse_redis_hget(out).strip() or None


# ---------------------------------------------------------------------------
# Helper: get ASIC_DB buffer pool attributes by OID
# ---------------------------------------------------------------------------
def _get_pool_asic_attrs(dut_h, pool_oid):
    out = st.show(dut_h,
        'sonic-db-cli ASIC_DB HGETALL "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:{}"'.format(
            pool_oid),
        skip_tmpl=True)
    return parse_redis_hgetall(out)


# ---------------------------------------------------------------------------
# Helper: get COUNTERS_DB watermark stats for a pool OID
# ---------------------------------------------------------------------------
def _get_pool_stats(dut_h, pool_oid):
    """Read buffer pool watermark stats from COUNTERS_DB.

    Returns dict with key 'SAI_BUFFER_POOL_STAT_WATERMARK_BYTES' from
    PERIODIC_WATERMARKS:<oid> (periodic/read-and-clear, 60s poll).
    """
    out = st.show(dut_h,
        'sonic-db-cli COUNTERS_DB HGETALL "PERIODIC_WATERMARKS:{}"'.format(pool_oid),
        skip_tmpl=True)
    return parse_redis_hgetall(out)


def _get_pool_stats_persistent(dut_h, pool_oid):
    """Read USER_WATERMARKS from COUNTERS_DB (cleared by 'watermarkstat -c')."""
    out = st.show(dut_h,
        'sonic-db-cli COUNTERS_DB HGETALL "USER_WATERMARKS:{}"'.format(pool_oid),
        skip_tmpl=True)
    return parse_redis_hgetall(out)


def _get_pool_stats_true_persistent(dut_h, pool_oid):
    """Read PERSISTENT_WATERMARKS from COUNTERS_DB (never cleared — truly sticky)."""
    out = st.show(dut_h,
        'sonic-db-cli COUNTERS_DB HGETALL "PERSISTENT_WATERMARKS:{}"'.format(pool_oid),
        skip_tmpl=True)
    return parse_redis_hgetall(out)


# ===========================================================================
# Test cases — Buffer Pool
# ===========================================================================

def test_fx3_buffer_pool_exists(setup_topo):
    """Default egress buffer pool exists in CONFIG_DB and has an ASIC_DB OID.

    Maps to SAI test_default_create_pool_succeeds.

    Steps:
      1. Read CONFIG_DB BUFFER_POOL|egress_lossless_pool
      2. Verify key is present (non-empty)
      3. Lookup OID in COUNTERS_DB COUNTERS_BUFFER_POOL_NAME_MAP
      4. Verify OID is non-empty and non-zero
    """
    fail_msgs = []

    st.banner("test_fx3_buffer_pool_exists")

    # Step 1: CONFIG_DB
    pool_cfg = _get_pool_config(dut, DEFAULT_POOL_NAME)
    st.log("  CONFIG_DB BUFFER_POOL|{}: {}".format(DEFAULT_POOL_NAME, pool_cfg))
    if not pool_cfg:
        fail_msgs.append(
            "CONFIG_DB BUFFER_POOL|{} is empty — pool not configured".format(
                DEFAULT_POOL_NAME))

    # Step 2: ASIC_DB OID
    pool_oid = _get_pool_oid(dut, DEFAULT_POOL_NAME)
    st.log("  COUNTERS_DB pool OID: {}".format(pool_oid))
    if not pool_oid or pool_oid in ('0', 'oid:0x0'):
        fail_msgs.append(
            "Buffer pool '{}' has no valid ASIC_DB OID (got '{}')".format(
                DEFAULT_POOL_NAME, pool_oid))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Buffer pool exists check FAILED — see above')
    else:
        st.log("  BUFFER POOL EXISTS — PASSED")
        st.log("  Pool '{}' present in CONFIG_DB and ASIC_DB OID={}".format(
            DEFAULT_POOL_NAME, pool_oid))
        st.log("=" * 72)
        st.report_pass('msg',
            "Buffer pool '{}' exists: CONFIG_DB present, ASIC_DB OID={}".format(
                DEFAULT_POOL_NAME, pool_oid))


def test_fx3_buffer_pool_type_egress(setup_topo):
    """Default buffer pool TYPE must be 'egress'.

    Maps to SAI test_pool_type_is_egress.
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_pool_type_egress")

    pool_cfg = _get_pool_config(dut, DEFAULT_POOL_NAME)
    st.log("  CONFIG_DB BUFFER_POOL|{}: {}".format(DEFAULT_POOL_NAME, pool_cfg))

    pool_type = pool_cfg.get('type', '').lower()
    st.log("  type = '{}'  expected 'egress'".format(pool_type))
    if pool_type != 'egress':
        fail_msgs.append(
            "BUFFER_POOL|{} type='{}', expected 'egress'".format(
                DEFAULT_POOL_NAME, pool_type))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Buffer pool type check FAILED — see above')
    else:
        st.log("  BUFFER POOL TYPE — PASSED (type=egress)")
        st.log("=" * 72)
        st.report_pass('msg', "Buffer pool type=egress: PASSED")


def test_fx3_buffer_pool_mode_dynamic(setup_topo):
    """Default buffer pool THRESHOLD MODE must be 'dynamic'.

    Maps to SAI test_pool_threshold_mode_is_dynamic.
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_pool_mode_dynamic")

    pool_cfg = _get_pool_config(dut, DEFAULT_POOL_NAME)
    mode = pool_cfg.get('mode', '').lower()
    st.log("  mode = '{}'  expected 'dynamic'".format(mode))
    if mode != 'dynamic':
        fail_msgs.append(
            "BUFFER_POOL|{} mode='{}', expected 'dynamic'".format(
                DEFAULT_POOL_NAME, mode))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Buffer pool mode check FAILED — see above')
    else:
        st.log("  BUFFER POOL MODE — PASSED (mode=dynamic)")
        st.log("=" * 72)
        st.report_pass('msg', "Buffer pool mode=dynamic: PASSED")


def test_fx3_buffer_pool_size(setup_topo):
    """Default buffer pool SIZE must match FX3 HW constant (39,022,464 bytes).

    Maps to SAI test_pool_size.
    EXPECTED_POOL_SIZE = DEFAULT_POOL_CELLS(93804) * CELL_SIZE_BYTES(416)
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_pool_size")
    st.log("  Expected pool size: {:,} bytes ({} cells x {} bytes/cell)".format(
        EXPECTED_POOL_SIZE, DEFAULT_POOL_CELLS, CELL_SIZE_BYTES))

    pool_cfg = _get_pool_config(dut, DEFAULT_POOL_NAME)
    size_str = pool_cfg.get('size', '')
    st.log("  CONFIG_DB size = '{}'".format(size_str))

    try:
        actual_size = int(size_str)
    except (ValueError, TypeError):
        fail_msgs.append(
            "BUFFER_POOL|{} size='{}' is not an integer".format(
                DEFAULT_POOL_NAME, size_str))
        actual_size = None

    if actual_size is not None and actual_size != EXPECTED_POOL_SIZE:
        fail_msgs.append(
            "BUFFER_POOL|{} size={}, expected {:,} bytes".format(
                DEFAULT_POOL_NAME, actual_size, EXPECTED_POOL_SIZE))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Buffer pool size check FAILED — see above')
    else:
        st.log("  BUFFER POOL SIZE — PASSED ({:,} bytes)".format(actual_size))
        st.log("=" * 72)
        st.report_pass('msg',
            "Buffer pool size={:,} bytes matches HW constant: PASSED".format(
                actual_size))


# ===========================================================================
# Test cases — Buffer Profile
# ===========================================================================

def test_fx3_buffer_profile_exists(setup_topo):
    """Default egress buffer profile exists in CONFIG_DB and references the default pool.

    Maps to SAI test_default_create_profile_succeeds + test_profile_pool_id_matches_default_pool.
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_profile_exists")

    profile_cfg = _get_profile_config(dut, DEFAULT_PROFILE_NAME)
    st.log("  CONFIG_DB BUFFER_PROFILE|{}: {}".format(DEFAULT_PROFILE_NAME, profile_cfg))

    if not profile_cfg:
        fail_msgs.append(
            "CONFIG_DB BUFFER_PROFILE|{} is empty — profile not configured".format(
                DEFAULT_PROFILE_NAME))
    else:
        pool_ref = profile_cfg.get('pool', '')
        st.log("  pool reference = '{}'".format(pool_ref))
        if DEFAULT_POOL_NAME not in pool_ref:
            fail_msgs.append(
                "BUFFER_PROFILE|{} pool='{}', expected reference to '{}'".format(
                    DEFAULT_PROFILE_NAME, pool_ref, DEFAULT_POOL_NAME))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Buffer profile exists check FAILED — see above')
    else:
        st.log("  BUFFER PROFILE EXISTS — PASSED")
        st.log("  Profile '{}' present; references pool '{}'".format(
            DEFAULT_PROFILE_NAME, DEFAULT_POOL_NAME))
        st.log("=" * 72)
        st.report_pass('msg',
            "Buffer profile '{}' exists and references '{}': PASSED".format(
                DEFAULT_PROFILE_NAME, DEFAULT_POOL_NAME))


def test_fx3_buffer_profile_dynamic_th(setup_topo):
    """Default buffer profile DYNAMIC_TH must be 27 (FX3 alpha=0x1b).

    Maps to SAI test_profile_dynamic_th.
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_profile_dynamic_th")
    st.log("  Expected dynamic_th = {} (FX3 alpha=0x1b)".format(DEFAULT_DYNAMIC_TH))

    profile_cfg = _get_profile_config(dut, DEFAULT_PROFILE_NAME)
    dynamic_th_str = profile_cfg.get('dynamic_th', '')
    st.log("  CONFIG_DB dynamic_th = '{}'".format(dynamic_th_str))

    try:
        actual_th = int(dynamic_th_str)
    except (ValueError, TypeError):
        fail_msgs.append(
            "BUFFER_PROFILE|{} dynamic_th='{}' is not an integer".format(
                DEFAULT_PROFILE_NAME, dynamic_th_str))
        actual_th = None

    if actual_th is not None and actual_th != DEFAULT_DYNAMIC_TH:
        fail_msgs.append(
            "BUFFER_PROFILE|{} dynamic_th={}, expected {}".format(
                DEFAULT_PROFILE_NAME, actual_th, DEFAULT_DYNAMIC_TH))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Buffer profile dynamic_th check FAILED — see above')
    else:
        st.log("  BUFFER PROFILE DYNAMIC_TH — PASSED (dynamic_th={})".format(actual_th))
        st.log("=" * 72)
        st.report_pass('msg',
            "Buffer profile dynamic_th={} matches FX3 HW alpha: PASSED".format(actual_th))


# ===========================================================================
# Test cases — Buffer Pool Stats
# ===========================================================================

def test_fx3_buffer_pool_stats(setup_topo):
    """Buffer pool watermark stat is readable and within bounds.

    Maps to SAI tests:
      test_watermark_bytes_is_nonnegative
      test_watermark_bytes_within_pool_bounds

    Note: SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES, CURR_OCCUPANCY_CELLS, and
    WATERMARK_CELLS are not exported to COUNTERS_DB by SONiC today — they require
    changes to watermarkorch.cpp, bufferorch.cpp, and flexcounterorch.cpp in
    sonic-swss.  Only SAI_BUFFER_POOL_STAT_WATERMARK_BYTES is validated here.

    Steps:
      1. Resolve pool OID from COUNTERS_DB name map
      2. Read PERIODIC_WATERMARKS stats for the pool OID
      3. Verify SAI_BUFFER_POOL_STAT_WATERMARK_BYTES >= 0
      4. Verify SAI_BUFFER_POOL_STAT_WATERMARK_BYTES <= EXPECTED_POOL_SIZE
      5. Verify watermark_bytes is cell-aligned (divisible by CELL_SIZE_BYTES)
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_pool_stats")

    # Step 1: resolve OID
    pool_oid = _get_pool_oid(dut, DEFAULT_POOL_NAME)
    st.log("  Pool '{}' OID: {}".format(DEFAULT_POOL_NAME, pool_oid))
    if not pool_oid or pool_oid in ('0', 'oid:0x0'):
        st.report_fail('msg',
            'Buffer pool stats FAILED — could not resolve pool OID for {}'.format(
                DEFAULT_POOL_NAME))
        return

    # Step 2: read stats
    stats = _get_pool_stats(dut, pool_oid)
    st.log("  COUNTERS_DB stats for {}: {}".format(pool_oid, stats))

    if not stats:
        st.report_fail('msg',
            'Buffer pool stats FAILED — no COUNTERS_DB entries for OID {}'.format(pool_oid))
        return

    watermark_key = 'SAI_BUFFER_POOL_STAT_WATERMARK_BYTES'
    wm_str = stats.get(watermark_key, None)
    if wm_str is None:
        st.report_fail('msg',
            "Buffer pool stats FAILED — stat '{}' not found for pool {}".format(
                watermark_key, pool_oid))
        return
    try:
        watermark_bytes = int(wm_str)
    except (ValueError, TypeError):
        st.report_fail('msg',
            "Buffer pool stats FAILED — stat '{}' = '{}' is not an integer".format(
                watermark_key, wm_str))
        return

    st.log("  watermark_bytes = {:,}".format(watermark_bytes))

    # Step 3
    if watermark_bytes < 0:
        fail_msgs.append("watermark_bytes={} is negative".format(watermark_bytes))
    # Step 4
    if watermark_bytes > EXPECTED_POOL_SIZE:
        fail_msgs.append(
            "watermark_bytes={:,} exceeds pool size {:,}".format(
                watermark_bytes, EXPECTED_POOL_SIZE))
    # Step 5
    if watermark_bytes % CELL_SIZE_BYTES != 0:
        fail_msgs.append(
            "watermark_bytes={} is not cell-aligned (cell={})".format(
                watermark_bytes, CELL_SIZE_BYTES))

    st.log("=" * 72)
    if fail_msgs:
        st.log("  BUFFER POOL STATS — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Buffer pool stats FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  BUFFER POOL STATS — ALL CHECKS PASSED")
        st.log("  watermark_bytes={:,}  pool_size={:,}  cell_aligned=True".format(
            watermark_bytes, EXPECTED_POOL_SIZE))
        st.log("=" * 72)
        st.report_pass('msg',
            'Buffer pool stats PASSED: watermark={:,} bytes, '
            'non-negative, cell-aligned, within pool bounds'.format(watermark_bytes))


def test_fx3_buffer_pool_xoff_size_is_zero(setup_topo):
    """Default buffer pool XOFF_SIZE must be 0 (lossy pool, no PFC headroom).

    Maps to SAI test_pool_xoff_size_is_zero.
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_pool_xoff_size_is_zero")

    pool_cfg = _get_pool_config(dut, DEFAULT_POOL_NAME)
    xoff = pool_cfg.get('xoff', '0').strip()
    st.log("  xoff_size = '{}'  expected '0'".format(xoff))
    try:
        xoff_val = int(xoff) if xoff else 0
    except ValueError:
        xoff_val = None
        fail_msgs.append("BUFFER_POOL|{} xoff='{}' is not an integer".format(
            DEFAULT_POOL_NAME, xoff))
    if xoff_val is not None and xoff_val != 0:
        fail_msgs.append("BUFFER_POOL|{} xoff_size={}, expected 0".format(
            DEFAULT_POOL_NAME, xoff_val))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Buffer pool xoff_size check FAILED — see above')
    else:
        st.log("  BUFFER POOL XOFF_SIZE — PASSED (xoff_size=0)")
        st.log("=" * 72)
        st.report_pass('msg', "Buffer pool xoff_size=0 (lossy pool): PASSED")


def test_fx3_buffer_profile_static_th(setup_topo):
    """Default buffer profile has no static_th — it is a dynamic-mode profile.

    Maps to SAI test_profile_static_th.

    The FX3 default profile uses DYNAMIC threshold mode (dynamic_th=27).
    In dynamic mode SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH is not set
    in ASIC_DB.  CONFIG_DB has no 'static_th' key either.

    Validates:
      1. CONFIG_DB 'static_th' key is absent (dynamic profile has no static_th)
      2. ASIC_DB SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH is absent
         (dynamic profile does not carry a static threshold)
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_profile_static_th")

    # Check CONFIG_DB — static_th key must be absent
    profile_cfg = _get_profile_config(dut, DEFAULT_PROFILE_NAME)
    static_th_str = profile_cfg.get('static_th', None)
    st.log("  CONFIG_DB static_th = {}".format(
        repr(static_th_str) if static_th_str is not None else '<absent>'))

    if static_th_str is not None:
        fail_msgs.append(
            "BUFFER_PROFILE|{} has unexpected 'static_th'='{}' "
            "(dynamic profile should have no static_th)".format(
                DEFAULT_PROFILE_NAME, static_th_str))

    # Check ASIC_DB — SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH must be absent
    pool_oid = _get_pool_oid(dut, DEFAULT_POOL_NAME)
    asic_static_th = None
    if pool_oid:
        # Iterate both profile OIDs (dwrr + sp) — check both
        out = st.show(dut,
            'sonic-db-cli ASIC_DB KEYS "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:*"',
            skip_tmpl=True)
        profile_oids = [ln.split(':')[-1].strip()
                        for ln in (out or '').splitlines()
                        if 'SAI_OBJECT_TYPE_BUFFER_PROFILE' in ln]
        for oid in profile_oids:
            attrs = {}
            attr_out = st.show(dut,
                'sonic-db-cli ASIC_DB HGETALL "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:{}"'.format(oid),
                skip_tmpl=True)
            from fx3_qos_helpers import parse_redis_hgetall as _hgetall
            attrs = _hgetall(attr_out)
            st.log("  ASIC profile {} attrs: {}".format(oid, attrs))
            if 'SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH' in attrs:
                asic_static_th = attrs['SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH']
                fail_msgs.append(
                    "ASIC profile {} has SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH='{}' "
                    "(unexpected for dynamic profile)".format(oid, asic_static_th))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Buffer profile static_th check FAILED — see above')
    else:
        st.log("  BUFFER PROFILE STATIC_TH — PASSED")
        st.log("  Profile is dynamic-mode: no static_th in CONFIG_DB or ASIC_DB")
        st.log("=" * 72)
        st.report_pass('msg',
            "Buffer profile static_th absent as expected "
            "(dynamic profile: no SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH): PASSED")


def test_fx3_buffer_profile_reserved_buffer_size_is_zero(setup_topo):
    """Default buffer profile reserved_buffer_size must be 0.

    Maps to SAI test_profile_reserved_buffer_size_is_zero.
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_profile_reserved_buffer_size_is_zero")

    profile_cfg = _get_profile_config(dut, DEFAULT_PROFILE_NAME)
    resv = profile_cfg.get('reserved_buffer_size', '0').strip()
    st.log("  reserved_buffer_size = '{}'  expected '0'".format(resv))
    try:
        resv_val = int(resv) if resv else 0
    except ValueError:
        resv_val = None
        fail_msgs.append("BUFFER_PROFILE|{} reserved_buffer_size='{}' is not an integer".format(
            DEFAULT_PROFILE_NAME, resv))
    if resv_val is not None and resv_val != 0:
        fail_msgs.append("BUFFER_PROFILE|{} reserved_buffer_size={}, expected 0".format(
            DEFAULT_PROFILE_NAME, resv_val))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Buffer profile reserved_buffer_size check FAILED — see above')
    else:
        st.log("  BUFFER PROFILE RESERVED_BUFFER_SIZE — PASSED (0)")
        st.log("=" * 72)
        st.report_pass('msg', "Buffer profile reserved_buffer_size=0: PASSED")


def test_fx3_buffer_profile_xoff_th_is_zero(setup_topo):
    """Default buffer profile xoff_th must be 0.

    Maps to SAI test_profile_xoff_th_is_zero.
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_profile_xoff_th_is_zero")

    profile_cfg = _get_profile_config(dut, DEFAULT_PROFILE_NAME)
    xoff = profile_cfg.get('xoff_th', '0').strip()
    st.log("  xoff_th = '{}'  expected '0'".format(xoff))
    try:
        val = int(xoff) if xoff else 0
    except ValueError:
        val = None
        fail_msgs.append("BUFFER_PROFILE|{} xoff_th='{}' not an integer".format(
            DEFAULT_PROFILE_NAME, xoff))
    if val is not None and val != 0:
        fail_msgs.append("BUFFER_PROFILE|{} xoff_th={}, expected 0".format(
            DEFAULT_PROFILE_NAME, val))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Buffer profile xoff_th check FAILED — see above')
    else:
        st.log("  BUFFER PROFILE XOFF_TH — PASSED (0)")
        st.log("=" * 72)
        st.report_pass('msg', "Buffer profile xoff_th=0: PASSED")


def test_fx3_buffer_profile_xon_th_is_zero(setup_topo):
    """Default buffer profile xon_th must be 0.

    Maps to SAI test_profile_xon_th_is_zero.
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_profile_xon_th_is_zero")

    profile_cfg = _get_profile_config(dut, DEFAULT_PROFILE_NAME)
    xon = profile_cfg.get('xon_th', '0').strip()
    st.log("  xon_th = '{}'  expected '0'".format(xon))
    try:
        val = int(xon) if xon else 0
    except ValueError:
        val = None
        fail_msgs.append("BUFFER_PROFILE|{} xon_th='{}' not an integer".format(
            DEFAULT_PROFILE_NAME, xon))
    if val is not None and val != 0:
        fail_msgs.append("BUFFER_PROFILE|{} xon_th={}, expected 0".format(
            DEFAULT_PROFILE_NAME, val))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Buffer profile xon_th check FAILED — see above')
    else:
        st.log("  BUFFER PROFILE XON_TH — PASSED (0)")
        st.log("=" * 72)
        st.report_pass('msg', "Buffer profile xon_th=0: PASSED")


def test_fx3_buffer_profile_xon_offset_th_is_zero(setup_topo):
    """Default buffer profile xon_offset_th must be 0.

    Maps to SAI test_profile_xon_offset_th_is_zero.
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_profile_xon_offset_th_is_zero")

    profile_cfg = _get_profile_config(dut, DEFAULT_PROFILE_NAME)
    xon_off = profile_cfg.get('xon_offset_th', '0').strip()
    st.log("  xon_offset_th = '{}'  expected '0'".format(xon_off))
    try:
        val = int(xon_off) if xon_off else 0
    except ValueError:
        val = None
        fail_msgs.append("BUFFER_PROFILE|{} xon_offset_th='{}' not an integer".format(
            DEFAULT_PROFILE_NAME, xon_off))
    if val is not None and val != 0:
        fail_msgs.append("BUFFER_PROFILE|{} xon_offset_th={}, expected 0".format(
            DEFAULT_PROFILE_NAME, val))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Buffer profile xon_offset_th check FAILED — see above')
    else:
        st.log("  BUFFER PROFILE XON_OFFSET_TH — PASSED (0)")
        st.log("=" * 72)
        st.report_pass('msg', "Buffer profile xon_offset_th=0: PASSED")


# ===========================================================================
# Negative tests — operations that must fail / not be supported on FX3
# ===========================================================================

def test_fx3_create_buffer_pool_ingress_not_supported(setup_topo):
    """Creating a buffer pool with type=ingress must be rejected by SONiC/SAI.

    Maps to SAI test_create_buffer_pool_not_supported_ingress.
    Attempts to set CONFIG_DB BUFFER_POOL with type=ingress; verifies the
    config either gets rejected or is not propagated to ASIC_DB.
    """
    fail_msgs = []
    st.banner("test_fx3_create_buffer_pool_ingress_not_supported")

    bad_pool = 'test_ingress_pool_negative'
    st.log("  Attempting to add CONFIG_DB BUFFER_POOL|{} with type=ingress".format(bad_pool))

    # Write a non-supported pool to CONFIG_DB
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "BUFFER_POOL|{}" '
        '"type" "ingress" "mode" "dynamic" "size" "{}"'.format(bad_pool, EXPECTED_POOL_SIZE),
        skip_error_check=True)
    st.wait(2)

    # Verify it is NOT present in ASIC_DB (no OID in name map)
    oid = _get_pool_oid(dut, bad_pool)
    st.log("  ASIC_DB OID for '{}': '{}'".format(bad_pool, oid))
    if oid and oid not in ('', '0', 'oid:0x0'):
        fail_msgs.append(
            "Ingress pool '{}' unexpectedly got ASIC_DB OID='{}' — "
            "ingress pool should be rejected".format(bad_pool, oid))

    # Cleanup: remove the test entry from CONFIG_DB
    st.config(dut,
        'sonic-db-cli CONFIG_DB DEL "BUFFER_POOL|{}"'.format(bad_pool),
        skip_error_check=True)
    st.wait(1)

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Ingress pool not-supported check FAILED — see above')
    else:
        st.log("  CREATE BUFFER POOL INGRESS — PASSED (not propagated to ASIC_DB)")
        st.log("=" * 72)
        st.report_pass('msg',
            "Ingress buffer pool correctly not propagated to ASIC_DB: PASSED")


def test_fx3_buffer_pool_size_mismatch_not_supported(setup_topo):
    """Setting buffer pool size to a non-default value must not change ASIC_DB.

    Maps to SAI test_set_buffer_pool_size_mismatch + test_create_buffer_pool_not_supported_wrong_size.
    Attempts to set CONFIG_DB pool size to EXPECTED_POOL_SIZE//2 and verifies
    ASIC_DB pool size remains at the HW constant.
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_pool_size_mismatch_not_supported")

    wrong_size = EXPECTED_POOL_SIZE // 2
    st.log("  Setting CONFIG_DB pool size to {:,} (wrong, expect ASIC to reject)".format(
        wrong_size))

    # Save original
    pool_cfg_before = _get_pool_config(dut, DEFAULT_POOL_NAME)
    original_size = pool_cfg_before.get('size', str(EXPECTED_POOL_SIZE))

    # Attempt mismatch set
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "BUFFER_POOL|{}" "size" "{}"'.format(
            DEFAULT_POOL_NAME, wrong_size),
        skip_error_check=True)
    st.wait(2)

    # Check ASIC_DB — size must still be the HW constant
    pool_oid = _get_pool_oid(dut, DEFAULT_POOL_NAME)
    if pool_oid:
        asic_attrs = _get_pool_asic_attrs(dut, pool_oid)
        st.log("  ASIC_DB pool attrs after mismatch set: {}".format(asic_attrs))
        asic_size_str = asic_attrs.get('SAI_BUFFER_POOL_ATTR_SIZE', '')
        try:
            asic_size = int(asic_size_str)
        except (ValueError, TypeError):
            asic_size = None
        if asic_size is not None and asic_size != EXPECTED_POOL_SIZE:
            fail_msgs.append(
                "ASIC_DB pool size={} after mismatch set, expected {:,} — "
                "mismatch value should be rejected".format(asic_size, EXPECTED_POOL_SIZE))
    else:
        fail_msgs.append("Could not resolve pool OID to verify ASIC_DB")

    # Restore original size
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "BUFFER_POOL|{}" "size" "{}"'.format(
            DEFAULT_POOL_NAME, original_size),
        skip_error_check=True)
    st.wait(2)

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Buffer pool size mismatch check FAILED — see above')
    else:
        st.log("  BUFFER POOL SIZE MISMATCH — PASSED (ASIC_DB size unchanged)")
        st.log("=" * 72)
        st.report_pass('msg',
            "Buffer pool size mismatch correctly rejected by ASIC: PASSED")


# ===========================================================================
# Buffer Pool Stats — cells consistency and clear tests
# ===========================================================================

def test_fx3_buffer_pool_stats_cells_consistent(setup_topo):
    """watermark_bytes is divisible by CELL_SIZE_BYTES (cell-aligned).

    Maps to SAI test_watermark_cells_consistent_with_bytes.

    Note: SAI_BUFFER_POOL_STAT_WATERMARK_CELLS, CURR_OCCUPANCY_BYTES, and
    CURR_OCCUPANCY_CELLS are not exported to COUNTERS_DB by SONiC today.
    Only WATERMARK_BYTES is available; cell-alignment serves as the equivalent
    consistency check (bytes % CELL_SIZE == 0 ↔ bytes / CELL_SIZE is integral).
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_pool_stats_cells_consistent")

    pool_oid = _get_pool_oid(dut, DEFAULT_POOL_NAME)
    if not pool_oid or pool_oid in ('0', 'oid:0x0'):
        st.report_fail('msg', 'Buffer pool stats cells check FAILED — no pool OID')
        return

    stats = _get_pool_stats(dut, pool_oid)
    if not stats:
        st.report_fail('msg', 'Buffer pool stats cells check FAILED — no COUNTERS_DB entries')
        return

    wm_bytes_str = stats.get('SAI_BUFFER_POOL_STAT_WATERMARK_BYTES', '0')
    try:
        wm_bytes = int(wm_bytes_str)
    except (ValueError, TypeError) as e:
        st.report_fail('msg',
            'Buffer pool stats cells check FAILED — non-integer watermark_bytes: {}'.format(e))
        return

    implied_cells = wm_bytes // CELL_SIZE_BYTES
    st.log("  watermark_bytes={:,}  implied_cells={:,}  CELL_SIZE={}".format(
        wm_bytes, implied_cells, CELL_SIZE_BYTES))

    if wm_bytes % CELL_SIZE_BYTES != 0:
        fail_msgs.append(
            "watermark_bytes({}) % CELL_SIZE({}) = {} != 0 — not cell-aligned".format(
                wm_bytes, CELL_SIZE_BYTES, wm_bytes % CELL_SIZE_BYTES))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Buffer pool stats cells consistency FAILED ({} failures) — see above'.format(
                len(fail_msgs)))
    else:
        st.log("  BUFFER POOL STATS CELLS CONSISTENT — PASSED")
        st.log("  watermark_bytes={:,} is cell-aligned (implied {} cells)".format(
            wm_bytes, implied_cells))
        st.log("=" * 72)
        st.report_pass('msg',
            "Buffer pool stats cells consistent: watermark_bytes={:,} "
            "is cell-aligned (implied {} cells): PASSED".format(wm_bytes, implied_cells))


def test_fx3_buffer_pool_stats_repeated_reads_consistent(setup_topo):
    """Two consecutive COUNTERS_DB reads must both be non-negative, cell-aligned,
    and watermark must be monotonically non-decreasing.

    Maps to SAI test_repeated_reads_are_consistent.
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_pool_stats_repeated_reads_consistent")

    pool_oid = _get_pool_oid(dut, DEFAULT_POOL_NAME)
    if not pool_oid or pool_oid in ('0', 'oid:0x0'):
        st.report_fail('msg', 'Repeated reads check FAILED — no pool OID')
        return

    stats1 = _get_pool_stats(dut, pool_oid)
    st.wait(1)
    stats2 = _get_pool_stats(dut, pool_oid)

    for label, stats in [('read1', stats1), ('read2', stats2)]:
        wm_str = stats.get('SAI_BUFFER_POOL_STAT_WATERMARK_BYTES', '0')
        try:
            wm = int(wm_str)
        except (ValueError, TypeError):
            fail_msgs.append("{} watermark='{}' not an integer".format(label, wm_str))
            continue
        st.log("  {} watermark_bytes = {:,}".format(label, wm))
        if wm < 0:
            fail_msgs.append("{} watermark_bytes={} is negative".format(label, wm))
        if wm % CELL_SIZE_BYTES != 0:
            fail_msgs.append("{} watermark_bytes={} not cell-aligned".format(label, wm))

    if not fail_msgs:
        try:
            wm1 = int(stats1.get('SAI_BUFFER_POOL_STAT_WATERMARK_BYTES', '0'))
            wm2 = int(stats2.get('SAI_BUFFER_POOL_STAT_WATERMARK_BYTES', '0'))
            if wm2 < wm1:
                fail_msgs.append(
                    "Watermark decreased between reads: read1={:,} read2={:,} "
                    "(peak counter must be monotonically non-decreasing)".format(wm1, wm2))
        except (ValueError, TypeError):
            pass

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Repeated reads consistency FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  BUFFER POOL STATS REPEATED READS — PASSED")
        st.log("=" * 72)
        st.report_pass('msg',
            "Buffer pool stats repeated reads: both non-negative, cell-aligned, "
            "watermark non-decreasing: PASSED")


def test_fx3_buffer_pool_stats_clear(setup_topo):
    """sonic-db-cli COUNTERS_DB watermark clear succeeds and resets watermark.

    Maps to SAI tests:
      test_clear_stats_does_not_raise
      test_clear_stats_returned_watermark_is_cell_aligned
      test_clear_stats_returned_occupancy_is_cell_aligned
      test_clear_stats_resets_watermark
      test_clear_stats_idempotent
      test_clear_stats_second_watermark_is_nonnegative

    SONiC mechanism: 'watermarkstat -c' or 'show watermark queue ...' triggers
    a clear of COUNTERS_DB watermark entries. Here we use 'watermarkstat -c'
    to reset watermarks and then re-read COUNTERS_DB to verify.
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_pool_stats_clear")

    pool_oid = _get_pool_oid(dut, DEFAULT_POOL_NAME)
    if not pool_oid or pool_oid in ('0', 'oid:0x0'):
        st.report_fail('msg', 'Buffer pool stats clear check FAILED — no pool OID')
        return

    # Read before clear
    stats_before = _get_pool_stats(dut, pool_oid)
    wm_before_str = stats_before.get('SAI_BUFFER_POOL_STAT_WATERMARK_BYTES', '0')
    try:
        wm_before = int(wm_before_str)
    except (ValueError, TypeError):
        wm_before = 0
    st.log("  Watermark before clear: {:,} bytes".format(wm_before))

    # Step 1: clear watermarks (first clear)
    st.config(dut, "watermarkstat -c", skip_error_check=True)
    st.wait(2)

    # Read after first clear
    stats_after1 = _get_pool_stats(dut, pool_oid)
    wm_after1_str = stats_after1.get('SAI_BUFFER_POOL_STAT_WATERMARK_BYTES', '0')
    try:
        wm_after1 = int(wm_after1_str)
    except (ValueError, TypeError):
        wm_after1 = 0

    st.log("  Watermark after first clear: {:,} bytes".format(wm_after1))

    # Step 1 assertions
    if wm_after1 < 0:
        fail_msgs.append("After first clear: watermark={} is negative".format(wm_after1))
    if wm_after1 % CELL_SIZE_BYTES != 0:
        fail_msgs.append("After first clear: watermark={} not cell-aligned".format(wm_after1))
    if wm_after1 > wm_before:
        fail_msgs.append(
            "After clear: watermark {:,} > pre-clear {:,} — "
            "HW peak counter may not have been reset".format(wm_after1, wm_before))

    # Step 2: second clear (idempotent)
    st.config(dut, "watermarkstat -c", skip_error_check=True)
    st.wait(2)

    stats_after2 = _get_pool_stats(dut, pool_oid)
    wm_after2_str = stats_after2.get('SAI_BUFFER_POOL_STAT_WATERMARK_BYTES', '0')
    try:
        wm_after2 = int(wm_after2_str)
    except (ValueError, TypeError):
        wm_after2 = 0

    st.log("  Watermark after second clear: {:,} bytes".format(wm_after2))

    if wm_after2 < 0:
        fail_msgs.append("After second clear: watermark={} is negative".format(wm_after2))
    if wm_after2 % CELL_SIZE_BYTES != 0:
        fail_msgs.append("After second clear: watermark={} not cell-aligned".format(wm_after2))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Buffer pool stats clear FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  BUFFER POOL STATS CLEAR — ALL CHECKS PASSED")
        st.log("  First clear: watermark={:,} (cell-aligned, >= 0, <= pre-clear)".format(wm_after1))
        st.log("  Second clear (idempotent): watermark={:,} (cell-aligned, >= 0)".format(wm_after2))
        st.log("=" * 72)
        st.report_pass('msg',
            "Buffer pool stats clear PASSED: watermark reset after clear; "
            "cell-aligned; idempotent second clear: PASSED")


# ===========================================================================
# Fixture — Ixia + DUT L3 setup for traffic-based watermark tests
# ===========================================================================

@pytest.fixture(scope='module')
def setup_traffic(request):
    """Set up DUT L3 + Ixia IPv4 interfaces for traffic-based watermark tests.

    Mirrors the working scheduler test setup_topo pattern:
      - start_all_protocols + tg_arp_control to resolve ARP before traffic
      - Both ingress ports send simultaneously to oversubscribe egress
        (2×90% → 180% load on 10G egress fills the buffer pool)

    Depends on the module-level dut/port_info populated by setup_topo.
    """
    global tg, tg_ph, port_speeds

    st.ensure_min_topology("D1T1:3")

    tg_handle, tg_ph_a = tgapi.get_handle_byname('T1D1P1')
    _, tg_ph_b         = tgapi.get_handle_byname('T1D1P2')
    _, tg_ph_e         = tgapi.get_handle_byname('T1D1P3')
    tg   = tg_handle
    tg_ph = {'ingress_a': tg_ph_a, 'ingress_b': tg_ph_b, 'egress': tg_ph_e}

    for role, ph in tg_ph.items():
        port_speeds[role] = tg_port_speed_gbps(tg, ph)
    st.log("setup_traffic: port speeds — {}".format(port_speeds))

    # DUT L3 config
    l3_cmds = []
    for role in sorted(_DUT_IPV4):
        intf = port_info[role]
        l3_cmds.append('config interface ip add {} {}'.format(intf, _DUT_IPV4[role]))
    st.config(dut, '\n'.join(l3_cmds), skip_error_check=True)
    st.wait(10)

    # Ixia IPv4 interfaces
    intf_handles = []
    for role in sorted(_IXIA_IPV4):
        result = tg.tg_interface_config(
            mode='config', port_handle=tg_ph[role],
            intf_ip_addr=_IXIA_IPV4[role], netmask=_NETMASK,
            gateway=_IXIA_GWV4[role],
            arp_send_req=1, enable_ping_response=1, resolve_gateway_mac=1)
        if result and result.get('handle'):
            intf_handles.append(result['handle'])

    # Start protocol stacks (resolves ARP)
    try:
        tg.tg_topology_test_control(action='start_all_protocols')
    except Exception:
        st.warn("start_all_protocols unavailable; relying on arp_send_req")

    st.wait(30)

    # Force ARP from all Ixia interfaces
    for h in intf_handles:
        try:
            tg.tg_arp_control(handle=h, arp_target='all')
        except Exception as e:
            st.warn("tg_arp_control failed for handle {}: {}".format(h, e))
    st.wait(5)

    ensure_interfaces_admin_up(dut, port_info.values())

    yield

    st.log("setup_traffic: teardown — removing L3 IPs")
    cleanup_cmds = []
    for role in sorted(_DUT_IPV4):
        intf = port_info[role]
        cleanup_cmds.append(
            'config interface ip remove {} {}'.format(intf, _DUT_IPV4[role]))
    st.config(dut, '\n'.join(cleanup_cmds), skip_error_check=True)
    st.log("setup_traffic: teardown complete")


# ---------------------------------------------------------------------------
# Flex counter poll interval helpers (FLEX_COUNTER_DB, db5)
# ---------------------------------------------------------------------------
_FLEX_COUNTER_DB_NUM  = 5
_FLEX_GROUP_KEY       = 'FLEX_COUNTER_GROUP_TABLE:BUFFER_POOL_WATERMARK_STAT_COUNTER'
_DEFAULT_POLL_MS      = 60000   # SONiC default (60 s)
_TEST_POLL_MS         = 5000    # shortened during traffic tests (5 s)
_POLL_SETTLE_SECS     = 8       # wait after shortening interval for a poll to fire


def _set_watermark_poll_interval(dut_h, interval_ms):
    """Set BUFFER_POOL_WATERMARK flex counter poll interval (ms) via redis-cli."""
    st.config(dut_h,
        'redis-cli -n {} HSET "{}" POLL_INTERVAL {}'.format(
            _FLEX_COUNTER_DB_NUM, _FLEX_GROUP_KEY, interval_ms),
        skip_error_check=True)
    st.log("  Flex counter poll interval set to {}ms".format(interval_ms))


# ===========================================================================
# Test cases — Buffer pool watermark under traffic
# ===========================================================================

def test_fx3_buffer_pool_watermark_nonzero_under_traffic(setup_topo, setup_traffic):
    """SAI_BUFFER_POOL_STAT_WATERMARK_BYTES is positive after congesting traffic.

    Sends 90%-rate IPv4 traffic on Q1 (DSCP 6) from both ingress ports to
    congest the egress buffer pool (2×90% = 180% on 10G egress), then reads
    SAI_BUFFER_POOL_STAT_WATERMARK_BYTES from:
      - USER_WATERMARKS:<oid>        (cleared by 'watermarkstat -c')
      - PERSISTENT_WATERMARKS:<oid>  (never cleared, truly sticky)

    Note: PERIODIC_WATERMARKS is not validated here as it is cleared
    by the flex counter poll immediately after traffic stops (timing-sensitive).

    Validates for each:
      1. watermark_bytes > 0
      2. watermark_bytes % CELL_SIZE_BYTES == 0
      3. watermark_bytes <= EXPECTED_POOL_SIZE
    """
    fail_msgs = []
    st.banner("test_fx3_buffer_pool_watermark_nonzero_under_traffic")

    # ── Step 1: Resolve pool OID ──────────────────────────────────────────
    pool_oid = _get_pool_oid(dut, DEFAULT_POOL_NAME)
    if not pool_oid or pool_oid in ('0', 'oid:0x0'):
        st.report_fail('msg',
            'Watermark-under-traffic FAILED — no pool OID in COUNTERS_DB')
        return

    try:
        # ── Step 2: Shorten flex poll interval so watermark updates quickly ─
        _set_watermark_poll_interval(dut, _TEST_POLL_MS)
        st.wait(_POLL_SETTLE_SECS)   # let one clean poll fire at the new rate

        # ── Step 3: Baselines ─────────────────────────────────────────────
        wm_user_before = int(
            (_get_pool_stats_persistent(dut, pool_oid) or {}).get(
                'SAI_BUFFER_POOL_STAT_WATERMARK_BYTES', '0') or '0')
        wm_true_before = int(
            (_get_pool_stats_true_persistent(dut, pool_oid) or {}).get(
                'SAI_BUFFER_POOL_STAT_WATERMARK_BYTES', '0') or '0')
        st.log("  Baseline — USER: {:,}  PERSISTENT: {:,} bytes".format(
            wm_user_before, wm_true_before))

        # ── Step 4: Send oversubscribing traffic (ingress_a + ingress_b → egress)
        #   2 × 90% on 10G → 10G egress = 180% load → fills egress buffer
        # ────────────────────────────────────────────────────────────────
        dut_mac_a = get_dut_mac(dut, port_info['ingress_a'])
        dut_mac_b = get_dut_mac(dut, port_info['ingress_b'])
        dscp = _QUEUE_TO_DSCP[1]   # Q1 / TC1
        st.log("  Streams: Q1 DSCP={} | rate={}% each | frame={}B | dur={}s | "
               "2×ingress→egress (180% total)".format(
            dscp, STREAM_RATE_PCT, _PKT_SIZE, _TRAFFIC_DURATION))

        stream_a = tg.tg_traffic_config(
            mode='create', port_handle=tg_ph['ingress_a'],
            l3_protocol='ipv4', l4_protocol='icmp',
            ip_src_addr=_IXIA_IPV4['ingress_a'],
            ip_dst_addr=_IXIA_EGRESS_IP,
            mac_dst=dut_mac_a,
            ip_dscp=dscp, ip_ttl=64,
            frame_size=_PKT_SIZE,
            rate_percent=STREAM_RATE_PCT,
            transmit_mode='continuous',
            high_speed_result_analysis=0,
        )
        stream_b = tg.tg_traffic_config(
            mode='create', port_handle=tg_ph['ingress_b'],
            l3_protocol='ipv4', l4_protocol='icmp',
            ip_src_addr=_IXIA_IPV4['ingress_b'],
            ip_dst_addr=_IXIA_EGRESS_IP,
            mac_dst=dut_mac_b,
            ip_dscp=dscp, ip_ttl=64,
            frame_size=_PKT_SIZE,
            rate_percent=STREAM_RATE_PCT,
            transmit_mode='continuous',
            high_speed_result_analysis=0,
        )
        tg.tg_traffic_control(action='apply')
        tg.tg_traffic_control(action='run')
        st.wait(_TRAFFIC_DURATION)
        tg.tg_traffic_control(action='stop')
        st.wait(2)

        # ── Step 5: Wait for USER/PERSISTENT watermark tables to settle ─
        st.wait(_POLL_SETTLE_SECS)

        # ── Step 6: Read USER_WATERMARKS and PERSISTENT_WATERMARKS ───────
        wm_user = int(
            (_get_pool_stats_persistent(dut, pool_oid) or {}).get(
                'SAI_BUFFER_POOL_STAT_WATERMARK_BYTES', '0') or '0')
        wm_true = int(
            (_get_pool_stats_true_persistent(dut, pool_oid) or {}).get(
                'SAI_BUFFER_POOL_STAT_WATERMARK_BYTES', '0') or '0')
        st.log("  After traffic — USER_WATERMARKS:          {:,} bytes".format(wm_user))
        st.log("  After traffic — PERSISTENT_WATERMARKS:    {:,} bytes".format(wm_true))

    finally:
        # ── Always restore poll interval ──────────────────────────────────
        _set_watermark_poll_interval(dut, _DEFAULT_POLL_MS)
        for sr in [locals().get('stream_a'), locals().get('stream_b')]:
            try:
                sid = sr.get('stream_id') if sr else None
                if sid:
                    tg.tg_traffic_config(mode='remove', stream_id=sid)
            except Exception:
                pass

    # ── Step 7: Assertions ────────────────────────────────────────────────
    st.log("=" * 72)
    st.log("  USER_WATERMARKS:       {:,} bytes".format(wm_user))
    st.log("  PERSISTENT_WATERMARKS: {:,} bytes".format(wm_true))

    for label, wm in [
        ('USER_WATERMARKS',       wm_user),
        ('PERSISTENT_WATERMARKS', wm_true),
    ]:
        if wm <= 0:
            fail_msgs.append(
                "{} watermark_bytes={:,} not positive after traffic".format(label, wm))
        if wm > 0 and wm % CELL_SIZE_BYTES != 0:
            fail_msgs.append(
                "{} watermark_bytes={:,} not cell-aligned (CELL_SIZE_BYTES={})".format(
                    label, wm, CELL_SIZE_BYTES))
        if wm > EXPECTED_POOL_SIZE:
            fail_msgs.append(
                "{} watermark_bytes={:,} > EXPECTED_POOL_SIZE={:,}".format(
                    label, wm, EXPECTED_POOL_SIZE))

    st.log("=" * 72)
    if fail_msgs:
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Watermark-nonzero-under-traffic FAILED ({} failures) — '
            'see above'.format(len(fail_msgs)))
    else:
        st.log("  WATERMARK NONZERO UNDER TRAFFIC — PASSED")
        st.log("  user={:,}  persistent={:,} bytes "
               "(cell-aligned, within bounds)".format(wm_user, wm_true))
        st.log("=" * 72)
        st.report_pass('msg',
            'Watermark-nonzero-under-traffic PASSED: '
            'user={:,} bytes, persistent={:,} bytes, '
            'cell-aligned, within bounds'.format(wm_user, wm_true))




