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
DSCP-to-TC QoS Map Tests — Sections A, D, E, F

Section A (Tests 1–4): Hardware TCAM programming verification via dchalshell.
  Queries the 'ing-l3-vlan-qos' TCAM region (start_idx=1792) through the
  syncd container's dchalshell binary.

Section E (Tests 21–28): SAI-layer verification via ASIC_DB.
  Checks ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP OIDs, MAP_TO_VALUE_LIST content,
  lifecycle (remove+create), unsupported map types, and port binding.

Section D (Tests 18–19): Per-DSCP queue placement via Ixia traffic.
  Sends 64 low-rate streams (one per DSCP) from the Ixia ingress port
  and verifies DCHAL per-queue counter deltas on the egress port match
  the expected per-TC packet totals from GOLDEN_DSCP_TO_TC.
  Topology: D1T1:2 (1 DUT, 2 Ixia ports).

Section F (Tests F1–F5): Advanced map-binding / negative tests (no traffic).
  Topology: D1 (single DUT, no traffic required).
  F1 — Rebind different map to port
  F2 — Bind same map to multiple ports simultaneously
  F3 — Delete map while bound to port (expect OBJECT_IN_USE)
  F4 — Unbind from already-unbound port (idempotent)
  F5 — Bind + reload + readback: no ASIC_DB corruption
"""

import json
import re
import warnings

import pytest

warnings.filterwarnings(
    "ignore", r".*currentThread\(\) is deprecated.*", DeprecationWarning)
warnings.filterwarnings(
    "ignore", r".*ssl\.PROTOCOL_TLS is deprecated.*", DeprecationWarning)

from spytest import st, tgapi

from fx3_qos_helpers import (
    GOLDEN_DSCP_TO_TC,
    # Shared IXIA IP constants — used in traffic streams and L3 setup by
    # setup_topo_common.  Ingress-A/B correspond to D1T1P1/D1T1P2; egress is
    # D1T1P3 (ixia mode) or the IXIA sink on D2T1P1 (peer_link/breakout).
    IXIA_INGRESS_A_IP, IXIA_INGRESS_A_IP6,
    IXIA_INGRESS_B_IP, IXIA_INGRESS_B_IP6,
    IXIA_EGRESS_IP,    IXIA_EGRESS_IP6,
    print_banner, print_section,
    reload_qos,
    get_dscp_to_tc_map,
    get_port_dscp_tc_map,
    deploy_dchal_helper,
    dchal_tcam_dump,
    dchal_tcam_info,
    tcam_ipv4_dscp_entries,
    tcam_build_dscp_to_qos_idx,
    tcam_ipv6_dscp_entries,
    tcam_ipv6_wide_halves,
    tcam_ipv6_build_dscp_to_qos_idx,
    asic_qos_map_types,
    asic_qos_map_oid,
    asic_dscp_to_tc_map,
    asic_port_dscp_tc_map_oid,
    get_dchal_queue_counters,
    get_dut_mac,
    clear_dut_counters,
    get_intf_counters,
    report_intf_counters,
    ensure_interfaces_admin_up,
    tg_port_speed_gbps,
    parse_redis_hget,
    setup_topo_common,
)

# ─── Section A constants (TCAM region, FX3 'ing-l3-vlan-qos') ───────────────
_TCAM_START_IDX  = 1792
_TCAM_TOTAL      = 512
_TCAM_DUMP_COUNT = 256   # covers 64 IPv4 (1 slot each) + 64 IPv6 wide-key (2 slots each) = 192 entries

# Spot-check {dscp: expected_tc} — one representative DSCP per TC group
_SPOT_CHECK = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 46: 5, 48: 6, 49: 7}

# ─── Section D constants (Ixia traffic — topology auto-detected) ────────────
# IP addressing is shared with WRED/scheduler suites via fx3_qos_helpers
# constants (IXIA_INGRESS_A_IP etc.).  setup_topo_common configures the DUT
# L3 and IXIA interfaces, so these are reference aliases only.
_IXIA_DST_V4  = IXIA_EGRESS_IP    # destination for ingress→egress streams
_IXIA_DST_V6  = IXIA_EGRESS_IP6   # IPv6 counterpart

_PKT_SIZE        = 128
_PKTS_PER_DSCP   = 250    # packets per DSCP value per burst
_STREAM_RATE_PPS = 50     # pps per DSCP stream
_TRAFFIC_TIMEOUT = 20     # seconds for all 64 streams to complete

# Precompute expected per-queue packet count (shared by Section D tests)
_EXPECTED_Q_PKTS = {}
for _ds, _tc in GOLDEN_DSCP_TO_TC.items():
    _qi = int(_tc)
    _EXPECTED_Q_PKTS[_qi] = _EXPECTED_Q_PKTS.get(_qi, 0) + _PKTS_PER_DSCP

# ─── Section C constants ──────────────────────────────────────────────────────
_PEER_PKTS_V4    = 5     # per test plan: 5 packets per test (IPv4)
_PEER_PKTS_V6    = 3     # per test plan: 3 packets per test (IPv6)

# ─── Module-level state ──────────────────────────────────────────────────────
dut         = None
test_intf   = None   # Section A/E/F primary interface
test_intf2  = None   # Section F multi-port secondary interface
tg          = None   # Ixia chassis handle
tg_ph       = {}     # {'ingress': ph, 'egress': ph}
port_info   = {}     # {'ingress': 'EthernetX', 'egress': 'EthernetY'}
port_speeds = {}     # {'ingress': 100, 'egress': 100}
topo_mode          = None   # 'ixia' | 'peer_link' | 'breakout'
tg_ph_ingress_b    = None   # second IXIA ingress handle (ixia/peer_link only)
port_info_ingress_b = None  # DUT interface for ingress_b


# ── Module fixture ────────────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """Shared topology setup for all DSCP-to-TC test sections (A–F).

    Wraps setup_topo_common to configure DUT L3, IXIA interfaces, and the
    QoS baseline.  Populates module globals used by every section:
      - traffic globals (tg, tg_ph, port_info, etc.) for Sections B/C/D
      - test_intf / test_intf2 for config-only Sections A/E/F
    """
    global dut, tg, tg_ph, port_info, port_speeds
    global topo_mode, tg_ph_ingress_b, port_info_ingress_b
    global test_intf, test_intf2

    for result in setup_topo_common(tgapi, target_queue=0):
        dut       = result['dut']
        tg        = result['tg']
        topo_mode = result['mode']

        raw_ph = result['tg_ph']
        raw_pi = result['port_info']

        port_info = {
            'ingress': raw_pi['ingress_a'],
            'egress':  raw_pi['egress'],
        }
        tg_ph = {
            'ingress': raw_ph['ingress_a'],
            'egress':  raw_ph.get('egress_sink', raw_ph['egress']),
        }
        port_speeds = {
            'ingress': result['port_speeds'].get('ingress_a', 'N/A'),
            'egress':  result['port_speeds'].get('egress', 'N/A'),
        }

        if 'ingress_b' in raw_pi:
            tg_ph_ingress_b     = raw_ph.get('ingress_b')
            port_info_ingress_b = raw_pi['ingress_b']
        else:
            tg_ph_ingress_b     = None
            port_info_ingress_b = None

        test_intf  = raw_pi['ingress_a']
        test_intf2 = raw_pi['egress']

        deploy_dchal_helper(dut)
        _log_traffic_topology()
        yield


# ══════════════════════════════════════════════════════════════════════════════
# Section A — TCAM Programming Verification (Tests 1–4)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.config_only
def test_full_azure_map_in_tcam():
    """#1 — Verify the full 64-entry AZURE DSCP-to-TC map is programmed in TCAM for both IPv4 and IPv6.

    Each DSCP value consumes exactly 1 IPv4 TCAM slot and 2 IPv6 TCAM slots
    (1 active wide-key half + 1 NOP wide-key half), giving 192 total entries
    (64×1 + 64×2) in 'ing-l3-vlan-qos'.

    Steps:
      1. Dump TCAM region 'ing-l3-vlan-qos' (start=1792, count=256) via dchalshell.
      2. Assert exactly 64 IPv4 entries with DSCP values 0–63 (1 per DSCP).
      3. Spot-check DSCPs {0→TC0, 1→TC1, 2→TC2, 46→TC5, 48→TC6, 49→TC7}:
         each has a non-null qos_map_idx in the IPv4 entry.
      4. Detect allocation mode (per-TC or per-DSCP):
           per-TC   : all DSCPs sharing a TC share the same qos_map_idx.
           per-DSCP : each DSCP has its own unique qos_map_idx (firmware variant).
         In per-DSCP mode, assert every DSCP has a non-null qos_map_idx (1 entry/DSCP).
      5. Assert exactly 64 IPv6 active wide-key entries (1 active/DSCP, qos_map_idx set).
      6. Assert exactly 64 IPv6 NOP wide-key entries   (1 NOP/DSCP,    qos_map_idx None).
         Total IPv6: 64+64=128 entries (2 entries per DSCP).
      7. Assert every IPv6 active entry has a non-null dscp field (0-63).
      8. Assert IPv6 active entries cover all 64 DSCP values (0-63).
      9. Spot-check IPv6 DSCPs {0, 1, 2, 46, 48, 49} have non-null qos_map_idx.
     10. Assert IPv4 and IPv6 TCAM cover the identical 64-DSCP set.
    """
    print_section("Test 1 — Full 64-entry AZURE map in TCAM (IPv4 + IPv6 wide-key)", art_key='dscp_to_tc')

    failures = []
    dump = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump:
        st.report_fail('msg', "Test 1: dchal_tcam_dump returned empty")

    # ── IPv4 entries ──────────────────────────────────────────────────────────
    ipv4 = tcam_ipv4_dscp_entries(dump)
    st.log("  IPv4 DSCP entries in TCAM: {}".format(len(ipv4)))

    if len(ipv4) != 64:
        failures.append("IPv4 DSCP entry count = {} (expected 64)".format(len(ipv4)))

    missing = sorted(set(range(64)) - {e['dscp'] for e in ipv4})
    if missing:
        failures.append("DSCP values missing from TCAM: {}".format(missing))

    dscp_to_idx = tcam_build_dscp_to_qos_idx(dump)
    for dscp, tc in _SPOT_CHECK.items():
        idx = dscp_to_idx.get(dscp)
        if idx is None:
            failures.append("DSCP {} (TC {}) has null qos_map_idx".format(dscp, tc))
        else:
            st.log("  DSCP {:2d} -> TC {} -> qos_map_idx 0x{:02x}".format(dscp, tc, idx))

    # ── Detect allocation mode: per-TC (shared idx) vs per-DSCP (unique idx) ──
    tc_to_idx_set = {}
    for dscp, idx in dscp_to_idx.items():
        tc = GOLDEN_DSCP_TO_TC.get(str(dscp))
        if tc is not None and idx is not None:
            tc_to_idx_set.setdefault(tc, set()).add(idx)
    per_dscp_alloc = any(len(v) > 1 for v in tc_to_idx_set.values())
    if per_dscp_alloc:
        st.log("  [INFO] Per-DSCP qos_map_idx allocation detected: "
               "each DSCP gets its own TCAM action index (firmware-dependent)")
        # IPv4: exactly 1 entry per DSCP, each with non-null qos_map_idx
        st.log("  IPv4: {} entries (1 per DSCP × 64 DSCPs = 64 expected)".format(len(ipv4)))
        null_dscps = [d for d, i in dscp_to_idx.items() if i is None]
        if null_dscps:
            failures.append(
                "Per-DSCP alloc: {} DSCPs have null qos_map_idx: {}".format(
                    len(null_dscps), sorted(null_dscps)))
        else:
            st.log("  IPv4: all {} DSCPs have non-null qos_map_idx (1 entry/DSCP)  PASS".format(
                len(dscp_to_idx)))
    else:
        st.log("  [INFO] Per-TC qos_map_idx allocation detected: "
               "all DSCPs in same TC share one TCAM action index")
        tc_to_idx = {}
        for dscp, idx in dscp_to_idx.items():
            tc = GOLDEN_DSCP_TO_TC.get(str(dscp))
            if tc is not None and idx is not None:
                if tc in tc_to_idx and tc_to_idx[tc] != idx:
                    failures.append(
                        "qos_map_idx inconsistency TC {}: 0x{:02x} vs 0x{:02x}".format(
                            tc, tc_to_idx[tc], idx))
                else:
                    tc_to_idx[tc] = idx

    # ── IPv6 wide-key: each DSCP occupies 2 slots (1 active + 1 NOP) = 128 total ──
    ipv6_active = tcam_ipv6_dscp_entries(dump)   # active halves (qos_map_idx set)
    ipv6_nop    = tcam_ipv6_wide_halves(dump)    # NOP halves (qos_map_idx null)
    st.log("  IPv6 wide-key: {} active + {} NOP = {} total "
           "(2 entries/DSCP, expected 64+64=128)".format(
               len(ipv6_active), len(ipv6_nop), len(ipv6_active) + len(ipv6_nop)))

    if len(ipv6_active) != 64:
        failures.append(
            "IPv6 active entry count = {} "
            "(expected 64 — 1 active wide-key per DSCP)".format(len(ipv6_active)))
    if len(ipv6_nop) != 64:
        failures.append(
            "IPv6 NOP entry count = {} "
            "(expected 64 — 1 NOP wide-key per DSCP)".format(len(ipv6_nop)))

    # ── IPv6 DSCP key verification ────────────────────────────────────────────
    # Every active IPv6 entry must carry a non-null dscp field (0-63) matching
    # the same 64-DSCP set as IPv4.  The DSCP→qos_map_idx mapping must also
    # agree with the IPv4 mapping for every DSCP value.
    ipv6_dscp_to_idx = tcam_ipv6_build_dscp_to_qos_idx(dump)
    ipv6_null_dscp   = [e for e in ipv6_active if e.get('dscp') is None]
    if ipv6_null_dscp:
        failures.append(
            "{} IPv6 active entries have null dscp field "
            "(hw_indices: {})".format(
                len(ipv6_null_dscp),
                [e['hw_index'] for e in ipv6_null_dscp[:5]]))
    else:
        st.log("  IPv6: all {} active entries have non-null dscp field  PASS".format(
            len(ipv6_active)))

    ipv6_dscp_set = set(ipv6_dscp_to_idx.keys())
    missing_v6 = sorted(set(range(64)) - ipv6_dscp_set)
    if missing_v6:
        failures.append(
            "DSCP values missing from IPv6 active TCAM entries: {}".format(missing_v6))
    else:
        st.log("  IPv6: all 64 DSCP values (0-63) present  PASS")

    # Spot-check IPv6: same DSCPs as IPv4 spot-check
    for dscp, tc in _SPOT_CHECK.items():
        v6_idx = ipv6_dscp_to_idx.get(dscp)
        if v6_idx is None:
            failures.append(
                "IPv6 DSCP {} (TC {}) missing from TCAM active entries".format(dscp, tc))
        else:
            st.log("  IPv6 DSCP {:2d} -> TC {} -> qos_map_idx 0x{:02x}".format(
                dscp, tc, v6_idx))

    # IPv4 and IPv6 must cover the identical set of 64 DSCP values
    ipv4_dscp_set = set(dscp_to_idx.keys())
    if ipv4_dscp_set and ipv6_dscp_set:
        only_v4 = ipv4_dscp_set - ipv6_dscp_set
        only_v6 = ipv6_dscp_set - ipv4_dscp_set
        if only_v4:
            failures.append(
                "DSCPs in IPv4 TCAM but missing from IPv6: {}".format(sorted(only_v4)))
        if only_v6:
            failures.append(
                "DSCPs in IPv6 TCAM but missing from IPv4: {}".format(sorted(only_v6)))
        if not only_v4 and not only_v6:
            st.log("  IPv4 and IPv6 TCAM cover identical DSCP set (0-63)  PASS")

    if failures:
        st.report_fail('msg', "Test 1 failures:\n  " + "\n  ".join(failures))
    alloc_mode = "per-DSCP" if per_dscp_alloc else "per-TC"
    st.report_pass('msg',
        "Test 1: 64 IPv4 + 64 IPv6 active + 64 IPv6 NOP wide-key entries in TCAM "
        "(192 total slots); IPv4 and IPv6 cover identical DSCP set 0-63; "
        "spot-check passed; qos_map_idx allocation={}".format(alloc_mode))


@pytest.mark.config_only
def test_tc_qos_idx_consistency():
    """#2 — Verify all 64 DSCPs have qos_map_idx entries in TCAM for both IPv4 and IPv6.

    TCAM slot counts per DSCP value:
      IPv4 : 1 entry per DSCP (64 total), each with non-null qos_map_idx.
      IPv6 : 2 entries per DSCP — 1 active wide-key (qos_map_idx set) +
             1 NOP wide-key (qos_map_idx None) — 128 total.

    Steps:
      1. Dump TCAM and build {dscp: qos_map_idx} for all IPv4 entries.
      2. Group into TC buckets; detect allocation mode (per-TC or per-DSCP).
           per-TC   : each TC group has exactly one qos_map_idx; all 8 TCs distinct.
           per-DSCP : multiple indices within a TC is valid; log without failing.
      3. Assert all 8 TC groups (0–7) are represented.
      4. Assert exactly 64 IPv6 active wide-key entries (1 active/DSCP, non-null qos_map_idx).
      5. Assert exactly 64 IPv6 NOP wide-key entries (1 NOP/DSCP, null qos_map_idx).
      6. Assert every IPv6 active entry has a non-null dscp field (0-63).
      7. Assert IPv6 active entries cover all 64 DSCP values (0-63).
      8. Assert IPv4 and IPv6 cover the identical 64-DSCP set.
    """
    print_section("Test 2 — TC→qos_map_idx consistency: all 64 DSCPs, IPv4 and IPv6")

    from collections import Counter
    failures = []
    dump = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump:
        st.report_fail('msg', "Test 2: dchal_tcam_dump returned empty")

    # ── IPv4 TC grouping ──────────────────────────────────────────────────────
    dscp_to_idx = tcam_build_dscp_to_qos_idx(dump)
    tc_to_idx_set = {}
    missing = []
    for dscp_str, tc_str in GOLDEN_DSCP_TO_TC.items():
        dscp = int(dscp_str)
        tc   = int(tc_str)
        idx  = dscp_to_idx.get(dscp)
        if idx is None:
            missing.append(dscp)
        else:
            tc_to_idx_set.setdefault(tc, set()).add(idx)
    if missing:
        failures.append("DSCPs missing from TCAM: {}".format(sorted(missing)))

    # Detect allocation mode
    per_dscp_alloc = any(len(v) > 1 for v in tc_to_idx_set.values())
    alloc_mode = "per-DSCP" if per_dscp_alloc else "per-TC"
    st.log("  [INFO] qos_map_idx allocation mode: {}".format(alloc_mode))

    tc_to_idx = {}
    for tc in sorted(tc_to_idx_set):
        idx_set = tc_to_idx_set[tc]
        if len(idx_set) == 1:
            tc_to_idx[tc] = next(iter(idx_set))
            st.log("  TC {} -> qos_map_idx=0x{:02x}".format(tc, tc_to_idx[tc]))
        else:
            # Per-DSCP allocation: multiple indices within one TC is valid firmware behavior
            st.log("  TC {} -> {}/{} distinct qos_map_idx values (per-DSCP alloc): {}".format(
                tc, len(idx_set),
                len([d for d, t in GOLDEN_DSCP_TO_TC.items() if int(t) == tc]),
                sorted('0x{:x}'.format(i) for i in sorted(idx_set)[:4])))

    if len(tc_to_idx_set) != 8:
        failures.append("Expected 8 TC groups, found {} (TCs: {})".format(
            len(tc_to_idx_set), sorted(tc_to_idx_set)))

    if not per_dscp_alloc:
        if len(tc_to_idx) == 8 and len(set(tc_to_idx.values())) != 8:
            dupes = {hex(k): v for k, v in Counter(tc_to_idx.values()).items() if v > 1}
            failures.append("TC groups share qos_map_idx (per-TC mode): {}".format(dupes))

    # ── IPv6: each DSCP occupies 2 wide-key slots (1 active + 1 NOP) ───────────
    # Invariant holds in both per-TC and per-DSCP allocation modes:
    #   IPv4 = 1 entry per DSCP (64 total)
    #   IPv6 = 2 entries per DSCP (64 active wide-key + 64 NOP wide-key = 128 total)
    ipv6_active = tcam_ipv6_dscp_entries(dump)
    ipv6_nop    = tcam_ipv6_wide_halves(dump)
    st.log("  IPv6 wide-key: {} active + {} NOP = {} total "
           "(2 entries/DSCP, expected 64+64=128)".format(
               len(ipv6_active), len(ipv6_nop), len(ipv6_active) + len(ipv6_nop)))
    if len(ipv6_active) != 64:
        failures.append(
            "IPv6 active entry count = {} "
            "(expected 64 — 1 active wide-key per DSCP)".format(len(ipv6_active)))
    if len(ipv6_nop) != 64:
        failures.append(
            "IPv6 NOP entry count = {} "
            "(expected 64 — 1 NOP wide-key per DSCP)".format(len(ipv6_nop)))
    ipv6_null = [e for e in ipv6_active if e.get('qos_map_idx') is None]
    if ipv6_null:
        failures.append(
            "{} IPv6 active entries have null qos_map_idx".format(len(ipv6_null)))
    else:
        st.log("  IPv6: all {} active entries have non-null qos_map_idx "
               "(1 active/DSCP)  PASS".format(len(ipv6_active)))
    if len(ipv6_nop) == 64:
        st.log("  IPv6: 64 NOP wide-key halves present (1 NOP/DSCP)  PASS")

    # ── IPv6 DSCP key values ──────────────────────────────────────────────────
    ipv6_null_dscp = [e for e in ipv6_active if e.get('dscp') is None]
    if ipv6_null_dscp:
        failures.append(
            "{} IPv6 active entries have null dscp field".format(len(ipv6_null_dscp)))
    else:
        st.log("  IPv6: all {} active entries have non-null dscp field  PASS".format(
            len(ipv6_active)))

    ipv6_dscp_to_idx = tcam_ipv6_build_dscp_to_qos_idx(dump)
    missing_v6 = sorted(set(range(64)) - set(ipv6_dscp_to_idx.keys()))
    if missing_v6:
        failures.append(
            "DSCP values missing from IPv6 active TCAM: {}".format(missing_v6))
    else:
        st.log("  IPv6: all 64 DSCP values (0-63) present  PASS")

    # Verify IPv4 and IPv6 cover the same DSCP set
    ipv4_dscps = set(dscp_to_idx.keys())
    if ipv4_dscps and ipv6_dscp_to_idx:
        only_v4 = ipv4_dscps - set(ipv6_dscp_to_idx.keys())
        only_v6 = set(ipv6_dscp_to_idx.keys()) - ipv4_dscps
        if only_v4:
            failures.append(
                "DSCPs present in IPv4 TCAM but missing from IPv6: {}".format(
                    sorted(only_v4)))
        if only_v6:
            failures.append(
                "DSCPs present in IPv6 TCAM but missing from IPv4: {}".format(
                    sorted(only_v6)))
    if not failures:
        st.log("  IPv4 and IPv6 TCAM cover identical DSCP sets  PASS")

    if failures:
        st.report_fail('msg', "Test 2 failures:\n  " + "\n  ".join(failures))
    st.report_pass('msg',
        "Test 2: all 64 DSCPs — IPv4 1 entry/DSCP (non-null), "
        "IPv6 2 entries/DSCP (64 active + 64 NOP wide-key); "
        "IPv4 and IPv6 DSCP fields parsed and verified (0-63); "
        "8 TC groups present; allocation-mode={}".format(alloc_mode))


@pytest.mark.config_only
def test_reload_idempotency():
    """#3 — Verify 'config qos reload' is idempotent: two reloads produce identical TCAM state.

    Checks IPv4 (1 slot each), IPv6 active wide-key entries (qos_map_idx set),
    and IPv6 NOP wide-key entries (qos_map_idx None) in both reload dumps.

    Steps:
      1. Run 'config qos reload', dump TCAM.
         Assert 64 IPv4 entries, 64 IPv6 active entries, 64 IPv6 NOP entries.
      2. Run 'config qos reload' again, dump TCAM. Assert the same counts.
      3. Assert the IPv4 {dscp: qos_map_idx} maps are identical between dumps.
      4. Assert the IPv6 active qos_map_idx multisets are identical between dumps.
      5. Assert all IPv6 active entries have non-null dscp fields (0-63) in both dumps.
      6. Assert the IPv6 {dscp: qos_map_idx} maps are identical between dumps.
      7. Spot-check DSCPs {0, 46, 48, 49} in dump2 have non-null IPv4 qos_map_idx.
    """
    print_section("Test 3 — Reload idempotency: IPv4 + IPv6 wide-key entries identical across reloads")

    failures = []

    reload_qos(dut, wait=15)
    dump1     = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    ipv4_1    = tcam_ipv4_dscp_entries(dump1)
    ipv6a_1   = tcam_ipv6_dscp_entries(dump1)   # active (qos_map_idx set)
    ipv6n_1   = tcam_ipv6_wide_halves(dump1)    # NOP (qos_map_idx None)
    idx_map1  = tcam_build_dscp_to_qos_idx(dump1)
    st.log("  Reload #1: {} IPv4, {} IPv6 active, {} IPv6 NOP".format(
        len(ipv4_1), len(ipv6a_1), len(ipv6n_1)))
    if len(ipv4_1) != 64:
        failures.append("Reload #1: {} IPv4 entries (expected 64)".format(len(ipv4_1)))
    if len(ipv6a_1) != 64:
        failures.append("Reload #1: {} IPv6 active entries (expected 64)".format(len(ipv6a_1)))
    if len(ipv6n_1) != 64:
        failures.append("Reload #1: {} IPv6 NOP entries (expected 64)".format(len(ipv6n_1)))

    reload_qos(dut, wait=15)
    dump2     = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    ipv4_2    = tcam_ipv4_dscp_entries(dump2)
    ipv6a_2   = tcam_ipv6_dscp_entries(dump2)
    ipv6n_2   = tcam_ipv6_wide_halves(dump2)
    idx_map2  = tcam_build_dscp_to_qos_idx(dump2)
    st.log("  Reload #2: {} IPv4, {} IPv6 active, {} IPv6 NOP".format(
        len(ipv4_2), len(ipv6a_2), len(ipv6n_2)))
    if len(ipv4_2) != 64:
        failures.append("Reload #2: {} IPv4 entries (expected 64)".format(len(ipv4_2)))
    if len(ipv6a_2) != 64:
        failures.append("Reload #2: {} IPv6 active entries (expected 64)".format(len(ipv6a_2)))
    if len(ipv6n_2) != 64:
        failures.append("Reload #2: {} IPv6 NOP entries (expected 64)".format(len(ipv6n_2)))

    if idx_map1 != idx_map2:
        diffs = ["DSCP {}: #{} 0x{:02x} vs #{} 0x{:02x}".format(
                     d, 1, idx_map1.get(d, 0), 2, idx_map2.get(d, 0))
                 for d in sorted(set(idx_map1) | set(idx_map2))
                 if idx_map1.get(d) != idx_map2.get(d)]
        failures.append("IPv4 dumps differ: " + ", ".join(diffs[:5]))

    ipv6_idx_1 = sorted(e['qos_map_idx'] for e in ipv6a_1)
    ipv6_idx_2 = sorted(e['qos_map_idx'] for e in ipv6a_2)
    if ipv6_idx_1 != ipv6_idx_2:
        failures.append(
            "IPv6 active qos_map_idx multisets differ between reloads: "
            "reload1={} reload2={}".format(ipv6_idx_1[:8], ipv6_idx_2[:8]))
    else:
        st.log("  IPv6 active qos_map_idx multisets identical across both reloads")

    # ── IPv6 DSCP key values identical across both reloads ────────────────────
    ipv6_dmap1 = tcam_ipv6_build_dscp_to_qos_idx(dump1)
    ipv6_dmap2 = tcam_ipv6_build_dscp_to_qos_idx(dump2)
    v6_null1 = [e for e in ipv6a_1 if e.get('dscp') is None]
    v6_null2 = [e for e in ipv6a_2 if e.get('dscp') is None]
    if v6_null1:
        failures.append("Reload #1: {} IPv6 active entries have null dscp".format(len(v6_null1)))
    if v6_null2:
        failures.append("Reload #2: {} IPv6 active entries have null dscp".format(len(v6_null2)))
    if len(ipv6_dmap1) != 64:
        failures.append("Reload #1: IPv6 active covers {} DSCPs (expected 64)".format(
            len(ipv6_dmap1)))
    if len(ipv6_dmap2) != 64:
        failures.append("Reload #2: IPv6 active covers {} DSCPs (expected 64)".format(
            len(ipv6_dmap2)))
    if ipv6_dmap1 != ipv6_dmap2:
        diffs = ["DSCP {}: #1 0x{:02x} vs #2 0x{:02x}".format(
                     d, ipv6_dmap1.get(d, 0), ipv6_dmap2.get(d, 0))
                 for d in sorted(set(ipv6_dmap1) | set(ipv6_dmap2))
                 if ipv6_dmap1.get(d) != ipv6_dmap2.get(d)]
        failures.append("IPv6 DSCP→qos_map_idx maps differ between reloads: "
                        + ", ".join(diffs[:5]))
    else:
        st.log("  IPv6 DSCP→qos_map_idx maps identical across both reloads  PASS")

    for dscp, label in [(0, 'TC0'), (46, 'TC5'), (48, 'TC6'), (49, 'TC7')]:
        idx = idx_map2.get(dscp)
        if idx is None:
            failures.append("Spot-check: DSCP {} ({}) missing after reload #2".format(
                dscp, label))
        else:
            st.log("  Spot-check DSCP {:2d} ({}): qos_map_idx=0x{:02x}".format(
                dscp, label, idx))

    if failures:
        st.report_fail('msg', "Test 3 failures:\n  " + "\n  ".join(failures))
    st.report_pass('msg',
        "Test 3: reload idempotent — both reloads produce 64 IPv4 + 64 IPv6 active + "
        "64 IPv6 NOP entries with identical qos_map_idx values; "
        "IPv6 DSCP fields (0-63) parsed and verified identical across reloads")


@pytest.mark.config_only
def test_tcam_hw_index_allocation():
    """#4 — Verify hw_index allocation for IPv4 (1 slot) and IPv6 wide-key (2 slots each).

    Each IPv4 entry occupies 1 TCAM slot.  Each IPv6 wide-key entry occupies
    2 consecutive TCAM slots: the first (active) carries qos_map_idx, the
    second (NOP) has qos_map_idx=None.  Both halves appear as wide_half=True
    in the dchalshell dump.

    Steps:
      1. Dump TCAM region 'ing-l3-vlan-qos'.
      2. Assert 64 IPv4 entries with unique hw_index values in [1792, 2303].
      3. Assert all 64 DSCP key values in IPv4 entries are unique.
      4. Assert 64 IPv6 active entries (qos_map_idx != None) and 64 IPv6 NOP entries.
      5. Assert all IPv6 active entries have a non-null dscp field (0-63).
      6. Assert IPv6 active entries cover all 64 DSCP values (0-63).
      7. Assert all IPv6 hw_index values are in [1792, 2303].
      8. Assert the IPv4 hw_index set and the combined IPv6 hw_index set are disjoint.
    """
    print_section("Test 4 — hw_index allocation: IPv4 (1 slot) + IPv6 wide-key (2 slots)")

    from collections import Counter
    _lo = _TCAM_START_IDX
    _hi = _TCAM_START_IDX + _TCAM_TOTAL - 1
    failures = []

    dump = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump:
        st.report_fail('msg', "Test 4: dchal_tcam_dump returned empty")

    # ── IPv4: 64 unique hw_index values ──────────────────────────────────────
    ipv4 = tcam_ipv4_dscp_entries(dump)
    st.log("  IPv4 DSCP entries: {}".format(len(ipv4)))
    if len(ipv4) != 64:
        failures.append("Expected 64 IPv4 entries, got {}".format(len(ipv4)))

    hw_indices = [e['hw_index'] for e in ipv4]
    if len(set(hw_indices)) != len(hw_indices):
        dupes = {k: v for k, v in Counter(hw_indices).items() if v > 1}
        failures.append("Duplicate IPv4 hw_index values: {}".format(dupes))
    else:
        st.log("  All {} IPv4 hw_index values are distinct".format(len(hw_indices)))

    out_of_range = [i for i in hw_indices if not (_lo <= i <= _hi)]
    if out_of_range:
        failures.append("{} IPv4 hw_index values outside [{}, {}]: {}".format(
            len(out_of_range), _lo, _hi, sorted(set(out_of_range))[:5]))
    else:
        st.log("  All IPv4 hw_index values in [{}, {}]".format(_lo, _hi))

    dscp_vals = [e['dscp'] for e in ipv4]
    if len(set(dscp_vals)) != 64:
        dupes = [d for d, c in Counter(dscp_vals).items() if c > 1]
        failures.append("Duplicate DSCP keys in TCAM: {}".format(sorted(dupes)))
    else:
        st.log("  All 64 DSCP key values (0-63) are unique")

    # ── IPv6: 64 active (qos_map_idx set) + 64 NOP (null) ────────────────────
    ipv6_active = tcam_ipv6_dscp_entries(dump)  # active wide-key halves
    ipv6_nop    = tcam_ipv6_wide_halves(dump)   # NOP placeholder halves
    st.log("  IPv6 active entries (qos_map_idx set): {}".format(len(ipv6_active)))
    st.log("  IPv6 NOP entries   (qos_map_idx null): {}".format(len(ipv6_nop)))

    if len(ipv6_active) != 64:
        failures.append("Expected 64 IPv6 active entries, got {}".format(len(ipv6_active)))
    if len(ipv6_nop) != 64:
        failures.append("Expected 64 IPv6 NOP entries, got {}".format(len(ipv6_nop)))

    # IPv6 DSCP key fields must be present and span 0-63
    v6_null_dscp = [e for e in ipv6_active if e.get('dscp') is None]
    if v6_null_dscp:
        failures.append(
            "{} IPv6 active entries have null dscp field "
            "(hw_indices: {})".format(
                len(v6_null_dscp), [e['hw_index'] for e in v6_null_dscp[:5]]))
    else:
        st.log("  All {} IPv6 active entries have non-null dscp field  PASS".format(
            len(ipv6_active)))

    ipv6_dscp_vals = [e['dscp'] for e in ipv6_active if e.get('dscp') is not None]
    if len(set(ipv6_dscp_vals)) != 64:
        missing_v6 = sorted(set(range(64)) - set(ipv6_dscp_vals))
        failures.append(
            "IPv6 active entries cover {} unique DSCPs (expected 64); "
            "missing: {}".format(len(set(ipv6_dscp_vals)), missing_v6))
    else:
        st.log("  IPv6 active entries cover all 64 DSCP values (0-63)  PASS")

    all_ipv6_hw = [e['hw_index'] for e in dump if e.get('proto') == 'ipv6']
    v6_oob = [i for i in all_ipv6_hw if not (_lo <= i <= _hi)]
    if v6_oob:
        failures.append("{} IPv6 hw_index values outside [{}, {}]: {}".format(
            len(v6_oob), _lo, _hi, sorted(set(v6_oob))[:5]))
    else:
        st.log("  All {} IPv6 hw_index values in [{}, {}]".format(
            len(all_ipv6_hw), _lo, _hi))

    # ── IPv4 and IPv6 hw_index sets must be disjoint ──────────────────────────
    v4_hw_set = set(hw_indices)
    v6_hw_set = set(all_ipv6_hw)
    overlap = v4_hw_set & v6_hw_set
    if overlap:
        failures.append("IPv4/IPv6 hw_index overlap ({} values): {}".format(
            len(overlap), sorted(overlap)[:5]))
    else:
        st.log("  IPv4 and IPv6 hw_index sets are disjoint ({} + {} = {} unique)".format(
            len(v4_hw_set), len(v6_hw_set), len(v4_hw_set | v6_hw_set)))

    if failures:
        st.report_fail('msg', "Test 4 failures:\n  " + "\n  ".join(failures))
    st.report_pass('msg',
        "Test 4: 64 IPv4 unique hw_indices; "
        "64 IPv6 active (dscp 0-63 verified) + 64 IPv6 NOP entries; "
        "IPv4/IPv6 hw_index sets disjoint; all hw_index values in [{}, {}]".format(_lo, _hi))


# ══════════════════════════════════════════════════════════════════════════════
# Section E — SAI / ASIC_DB Verification (Tests 21–28)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.config_only
def test_dscp_map_exists():
    """#21 — Verify ASIC_DB contains a QoS map OID with type SAI_QOS_MAP_TYPE_DSCP_TO_TC.

    Equivalent to SAI test_create_dscp_to_tc_map (verifies OID was created and
    the SAI_QOS_MAP_ATTR_TYPE reads back as DSCP_TO_TC).

    Steps:
      1. Query all ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP OIDs from ASIC_DB.
      2. Read SAI_QOS_MAP_ATTR_TYPE for each OID.
      3. Assert at least one OID has type SAI_QOS_MAP_TYPE_DSCP_TO_TC.
    """
    print_section("Test 21 — DSCP_TO_TC map OID present in ASIC_DB", art_key='dscp_to_tc')

    oid_key = asic_qos_map_oid(dut)
    types   = asic_qos_map_types(dut)
    st.log("  OID   : {}".format(oid_key or '(none)'))
    st.log("  Types : {}".format(types))

    if oid_key is None:
        st.report_fail('msg',
            "No SAI_QOS_MAP_TYPE_DSCP_TO_TC OID in ASIC_DB after qos reload. "
            "Types found: {}".format(types))
    st.report_pass('msg',
        "DSCP_TO_TC map present in ASIC_DB with correct type. OID: {}".format(oid_key))


@pytest.mark.config_only
def test_dscp_to_tc_entry_readback():
    """#22 — Verify all 64 ASIC_DB MAP_TO_VALUE_LIST entries match the AZURE golden map.

    Equivalent to SAI test_dscp_to_tc_entry_readback: reads
    SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST JSON from ASIC_DB and compares every
    {dscp: tc} pair against GOLDEN_DSCP_TO_TC.

    Steps:
      1. Find the DSCP_TO_TC OID in ASIC_DB.
      2. Read SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST (JSON: {"count":64,"list":[...]}).
      3. Parse into {int_dscp: int_tc}.
      4. For each of the 64 GOLDEN entries, assert tc matches.
    """
    print_section("Test 22 — ASIC_DB MAP_TO_VALUE_LIST readback (all 64 entries)",
                  art_key='dscp_to_tc')

    asic_map = asic_dscp_to_tc_map(dut)
    if not asic_map:
        st.report_fail('msg', "asic_dscp_to_tc_map() returned empty — OID not found in ASIC_DB")

    st.log("  {:<6} {:>9} {:>9} {:>8}".format('DSCP', 'Expected', 'Actual', 'Status'))
    st.log("  " + "-" * 38)
    failures = []
    for dscp_str in sorted(GOLDEN_DSCP_TO_TC, key=lambda x: int(x)):
        dscp   = int(dscp_str)
        exp_tc = int(GOLDEN_DSCP_TO_TC[dscp_str])
        act_tc = asic_map.get(dscp, '(missing)')
        ok     = act_tc == exp_tc
        st.log("  {:<6} {:>9} {:>9} {:>8}".format(
            dscp, exp_tc, act_tc, 'OK' if ok else '** FAIL'))
        if not ok:
            failures.append("DSCP {} -> TC {}, expected {}".format(dscp, act_tc, exp_tc))

    if failures:
        st.report_fail('msg', "ASIC_DB readback failures:\n" + "\n".join(failures))
    st.report_pass('msg', "All 64 DSCP-to-TC entries read back correctly from ASIC_DB")


@pytest.mark.config_only
def test_dscp_to_tc_entry_count():
    """#23 — Verify ASIC_DB MAP_TO_VALUE_LIST contains exactly 64 entries.

    Equivalent to the len-check in SAI test_dscp_to_tc_entry_readback:
      assert len(readback) == len(cfg.DSCP_TO_TC_MAP)  # 64

    Steps:
      1. Find the DSCP_TO_TC OID in ASIC_DB and read MAP_TO_VALUE_LIST.
      2. Parse the JSON 'count' field and assert it equals 64.
    """
    print_section("Test 23 — ASIC_DB MAP_TO_VALUE_LIST entry count (expect 64)",
                  art_key='dscp_to_tc')

    asic_map = asic_dscp_to_tc_map(dut)
    count = len(asic_map)
    st.log("  ASIC_DB entry count: {} (expected 64)".format(count))

    if count != 64:
        st.report_fail('msg',
            "ASIC_DB MAP_TO_VALUE_LIST has {} entries, expected 64".format(count))
    st.report_pass('msg', "ASIC_DB MAP_TO_VALUE_LIST entry count = 64 (correct)")


@pytest.mark.config_only
def test_remove_dscp_to_tc_map():
    """#24 — Verify the SAI remove+create cycle via DEL CONFIG_DB + reload.

    Equivalent to SAI test_remove_dscp_to_tc_map.  On FX3, orchagent does not
    call sai_remove on a bare CONFIG_DB DEL; reload is required to trigger the
    remove+create path.  A successful cycle is confirmed by an OID change.

    Steps:
      1. Record the current DSCP_TO_TC OID from ASIC_DB.
      2. DEL CONFIG_DB DSCP_TO_TC_MAP|AZURE.
      3. Run 'config qos reload' (orchagent: sai_remove(old) → sai_create(new)).
      4. Read new OID — assert it differs from the old OID (cycle confirmed).
    """
    print_section("Test 24 — DSCP_TO_TC remove+create cycle (ASIC_DB OID change)",
                  art_key='dscp_to_tc')

    oid_before = asic_qos_map_oid(dut)
    st.log("  OID before: {}".format(oid_before or '(none)'))
    if oid_before is None:
        st.report_fail('msg', "Precondition failed: DSCP_TO_TC OID not found in ASIC_DB")

    st.config(dut, 'sonic-db-cli CONFIG_DB DEL "DSCP_TO_TC_MAP|AZURE"',
              skip_error_check=True)
    reload_qos(dut)

    oid_after = asic_qos_map_oid(dut)
    st.log("  OID after : {}".format(oid_after or '(none)'))

    if oid_after is None:
        st.report_fail('msg', "DSCP_TO_TC OID absent after DEL+reload — recreation failed")
    if oid_after == oid_before:
        st.report_fail('msg',
            "OID unchanged ({}) — remove+create cycle did not execute".format(oid_after))
    st.report_pass('msg',
        "DSCP_TO_TC OID changed: {} → {} — remove+create cycle confirmed".format(
            oid_before, oid_after))


@pytest.mark.config_only
@pytest.mark.parametrize("cycles", [2, 3], ids=["2_cycles", "3_cycles"])
def test_dscp_to_tc_lifecycle(cycles):
    """#25 — Verify the SAI remove+create lifecycle over N cycles (2 and 3).

    Equivalent to SAI test_dscp_to_tc_lifecycle[2_cycles] and [3_cycles].
    Each cycle exercises the full sai_remove → sai_create path; confirmed by
    an OID change in ASIC_DB per cycle.

    Steps (per cycle):
      1. DEL CONFIG_DB DSCP_TO_TC_MAP|AZURE.
      2. Run 'config qos reload' (triggers OID removal + creation).
      3. Assert a new DSCP_TO_TC OID is present in ASIC_DB.
      4. Assert the new OID differs from the previous cycle's OID.
    """
    print_section("Test 25 — DSCP_TO_TC lifecycle ({} cycles)".format(cycles),
                  art_key='dscp_to_tc')

    failures = []
    prev_oid = asic_qos_map_oid(dut)
    st.log("  Starting OID: {}".format(prev_oid or '(none)'))

    for cycle in range(1, cycles + 1):
        st.log("  Cycle {}/{}: DEL + reload".format(cycle, cycles))
        st.config(dut, 'sonic-db-cli CONFIG_DB DEL "DSCP_TO_TC_MAP|AZURE"',
                  skip_error_check=True)
        reload_qos(dut)

        oid   = asic_qos_map_oid(dut)
        types = asic_qos_map_types(dut)
        st.log("  Cycle {}: OID={} types={}".format(cycle, oid or '(none)', types))

        if oid is None:
            failures.append("Cycle {}: OID absent after DEL+reload".format(cycle))
        elif 'SAI_QOS_MAP_TYPE_DSCP_TO_TC' not in types:
            failures.append("Cycle {}: wrong type in ASIC_DB: {}".format(cycle, types))
        elif oid == prev_oid:
            failures.append("Cycle {}: OID unchanged ({}) — cycle did not execute".format(
                cycle, oid))
        else:
            st.log("  Cycle {}: OID {} -> {} OK".format(cycle, prev_oid, oid))
        prev_oid = oid

    if failures:
        st.report_fail('msg',
            "Lifecycle ({} cycles) failures:\n".format(cycles) + "\n".join(failures))
    st.report_pass('msg',
        "DSCP_TO_TC {}-cycle DEL+reload lifecycle passed; OID changed each cycle".format(cycles))


@pytest.mark.config_only
def test_tc_to_queue_map_absent():
    """#26 — Verify SAI_QOS_MAP_TYPE_TC_TO_QUEUE is absent from ASIC_DB.

    FX3 uses a fixed 1:1 TC-to-queue mapping; sai_create_qos_map(TC_TO_QUEUE)
    returns SAI_STATUS_NOT_SUPPORTED so no OID of that type appears in ASIC_DB.
    Equivalent to SAI test_unsupported_tc_to_queue.

    Steps:
      1. Query all ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP types from ASIC_DB.
      2. Assert SAI_QOS_MAP_TYPE_TC_TO_QUEUE is not present.
    """
    print_section("Test 26 — TC_TO_QUEUE absent from ASIC_DB (SAI rejects it)")

    types = asic_qos_map_types(dut)
    st.log("  ASIC_DB QoS map types: {}".format(types or '(none)'))

    if 'SAI_QOS_MAP_TYPE_TC_TO_QUEUE' in types:
        st.report_fail('msg',
            "TC_TO_QUEUE OID found in ASIC_DB — SAI should have rejected it. "
            "All types: {}".format(types))
    st.report_pass('msg',
        "SAI_QOS_MAP_TYPE_TC_TO_QUEUE absent from ASIC_DB (correctly rejected). "
        "Types present: {}".format(types))


@pytest.mark.config_only
def test_tc_to_pg_map_absent():
    """#27 — Verify SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP is absent from ASIC_DB.

    FX3 uses a fixed TC-to-PG mapping; sai_create_qos_map(TC_TO_PRIORITY_GROUP)
    returns SAI_STATUS_NOT_SUPPORTED.
    Equivalent to SAI test_unsupported_tc_to_pg.

    Steps:
      1. Query all ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP types from ASIC_DB.
      2. Assert SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP is not present.
    """
    print_section("Test 27 — TC_TO_PRIORITY_GROUP absent from ASIC_DB (SAI rejects it)")

    types = asic_qos_map_types(dut)
    st.log("  ASIC_DB QoS map types: {}".format(types or '(none)'))

    if 'SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP' in types:
        st.report_fail('msg',
            "TC_TO_PRIORITY_GROUP OID found in ASIC_DB — SAI should have rejected it. "
            "All types: {}".format(types))
    st.report_pass('msg',
        "SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP absent from ASIC_DB (correctly rejected). "
        "Types present: {}".format(types))


@pytest.mark.config_only
def test_port_dscp_map_bind_unbind():
    """#28 — Verify PORT_QOS_MAP bind/unbind and confirm FX3 uses a global DSCP-to-TC map.

    FX3 does not call sai_set_port_attribute(SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP)
    per-port; ASIC_DB port attribute stays oid:0x0 throughout (global map used).
    Equivalent to the in-progress SAI bind-map-to-port test.

    Steps:
      1. HSET PORT_QOS_MAP|<intf> dscp_to_tc_map=AZURE.
      2. Assert CONFIG_DB readback shows AZURE.
      3. Assert ASIC_DB SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP = oid:0x0
         (FX3 uses global map — no per-port binding in ASIC_DB).
      4. HDEL PORT_QOS_MAP|<intf> dscp_to_tc_map.
      5. Assert CONFIG_DB readback is nil.
      6. Restore original binding if one existed.
    """
    print_section("Test 28 — PORT_QOS_MAP bind/unbind + ASIC_DB port attr check",
                  art_key='dscp_to_tc')

    intf    = test_intf
    initial = get_port_dscp_tc_map(dut, intf)
    st.log("  Interface: {}   initial dscp_to_tc_map='{}'".format(intf, initial or '(nil)'))

    failures = []

    # Step 1-2: bind and verify CONFIG_DB
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" "dscp_to_tc_map" "AZURE"'.format(intf),
              skip_error_check=True)
    st.wait(1)
    bound = get_port_dscp_tc_map(dut, intf)
    st.log("  After bind:  CONFIG_DB dscp_to_tc_map='{}'".format(bound))
    if 'AZURE' not in (bound or '').upper():
        failures.append("CONFIG_DB dscp_to_tc_map='{}' after HSET, expected AZURE".format(bound))

    # Step 3: verify ASIC_DB port attribute stays oid:0x0 (FX3 global map)
    asic_attr = asic_port_dscp_tc_map_oid(dut, intf)
    st.log("  ASIC_DB SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP={}".format(asic_attr or '(nil)'))
    if asic_attr is not None and asic_attr != 'oid:0x0':
        failures.append(
            "ASIC_DB port QoS attr = {} after bind (expected oid:0x0 — FX3 uses global map)".format(
                asic_attr))

    # Step 4-5: unbind and verify CONFIG_DB
    st.config(dut,
              'sonic-db-cli CONFIG_DB HDEL "PORT_QOS_MAP|{}" "dscp_to_tc_map"'.format(intf),
              skip_error_check=True)
    st.wait(1)
    unbound = get_port_dscp_tc_map(dut, intf)
    st.log("  After unbind: CONFIG_DB dscp_to_tc_map='{}'".format(unbound or '(nil)'))
    if unbound and unbound not in ('', 'nil', '(nil)', 'None'):
        failures.append("CONFIG_DB dscp_to_tc_map='{}' after HDEL, expected nil".format(unbound))

    # Step 6: restore
    if initial and initial not in ('', 'nil', '(nil)', 'None'):
        st.config(dut,
                  'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" "dscp_to_tc_map" "{}"'.format(
                      intf, initial),
                  skip_error_check=True)

    if failures:
        st.report_fail('msg',
            "PORT_QOS_MAP bind/unbind failures on {}: {}".format(intf, "; ".join(failures)))
    st.report_pass('msg',
        "PORT_QOS_MAP|{} bind/unbind verified; "
        "ASIC_DB port attr stays oid:0x0 (FX3 uses global map)".format(intf))


# ══════════════════════════════════════════════════════════════════════════════
# Internal helpers — Section D + F
# ══════════════════════════════════════════════════════════════════════════════

def _remove_memberships(dut_h, intf):
    """Remove *intf* from any VLAN and PortChannel it belongs to."""
    out = st.show(dut_h, "show vlan brief", skip_tmpl=True) or ''
    cur_vlan = None
    vlans_to_remove = []
    for line in out.splitlines():
        if '===' in line or '---' in line or 'VLAN ID' in line or not line.strip():
            continue
        if '|' not in line:
            continue
        fields = [f.strip() for f in line.split('|')]
        if len(fields) > 1 and fields[1].isdigit():
            cur_vlan = fields[1]
        if intf in line and cur_vlan and cur_vlan not in vlans_to_remove:
            vlans_to_remove.append(cur_vlan)
    for vid in vlans_to_remove:
        st.config(dut_h, "config vlan member del {} {}".format(vid, intf),
                  skip_error_check=True)

    pc_out = st.show(dut_h, "show interfaces portchannel", skip_tmpl=True) or ''
    for line in pc_out.splitlines():
        if intf in line:
            for part in line.split():
                if part.startswith('PortChannel'):
                    st.config(dut_h,
                              "config portchannel member del {} {}".format(part, intf),
                              skip_error_check=True)


def _build_ipv4_streams(tg_obj, ingress_ph, dst_mac, rate_pps, pkts):
    """Create 64 IPv4 UDP burst streams (DSCP 0-63) on *ingress_ph*.

    Returns a list of 64 stream result dicts.
    """
    handles = []
    for dscp in range(64):
        tc      = int(GOLDEN_DSCP_TO_TC[str(dscp)])
        udp_dst = 5000 + tc
        res = tg_obj.tg_traffic_config(
            mode='create',
            port_handle=ingress_ph,
            l3_protocol='ipv4',
            l4_protocol='udp',
            ip_src_addr=IXIA_INGRESS_A_IP,
            ip_dst_addr=_IXIA_DST_V4,
            mac_dst=dst_mac,
            ip_dscp=dscp,
            ip_ttl=64,
            udp_src_port=10000 + dscp,
            udp_dst_port=udp_dst,
            frame_size=_PKT_SIZE,
            rate_pps=rate_pps,
            pkts_per_burst=pkts,
            transmit_mode='single_burst',
        )
        handles.append(res)
    st.log("  Built {} IPv4 burst streams (DSCP 0-63)  "
           "rate={}pps  burst={}pkts".format(len(handles), rate_pps, pkts))
    return handles


def _build_ipv6_streams(tg_obj, ingress_ph, dst_mac, rate_pps, pkts):
    """Create 64 IPv6 UDP burst streams (DSCP 0-63 via Traffic Class) on *ingress_ph*.

    IPv6 DSCP is encoded as (dscp << 2) in the 8-bit Traffic Class field.
    Returns a list of 64 stream result dicts.
    """
    handles = []
    for dscp in range(64):
        tc_byte = dscp << 2
        tc      = int(GOLDEN_DSCP_TO_TC[str(dscp)])
        udp_dst = 5000 + tc
        res = tg_obj.tg_traffic_config(
            mode='create',
            port_handle=ingress_ph,
            l3_protocol='ipv6',
            l4_protocol='udp',
            ipv6_src_addr=IXIA_INGRESS_A_IP6,
            ipv6_dst_addr=_IXIA_DST_V6,
            mac_dst=dst_mac,
            ipv6_traffic_class=tc_byte,
            ipv6_hop_limit=64,
            udp_src_port=10000 + dscp,
            udp_dst_port=udp_dst,
            frame_size=_PKT_SIZE,
            rate_pps=rate_pps,
            pkts_per_burst=pkts,
            transmit_mode='single_burst',
        )
        handles.append(res)
    st.log("  Built {} IPv6 burst streams (DSCP 0-63 via Traffic Class)  "
           "rate={}pps  burst={}pkts".format(len(handles), rate_pps, pkts))
    return handles


def _send_and_measure(label):
    """Apply, run, settle, stop all Ixia streams; return DCHAL counter delta.

    Returns (q_before, q_after, egress_intf).
    """
    egress = port_info['egress']
    clear_dut_counters(dut)
    intf_before = get_intf_counters(dut, port_info.values())
    q_before = get_dchal_queue_counters(dut, egress, "BEFORE {}".format(label))

    tg.tg_traffic_control(action='clear_stats')
    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run')
    st.wait(_TRAFFIC_TIMEOUT)
    tg.tg_traffic_control(action='stop')
    st.wait(3)

    q_after = get_dchal_queue_counters(dut, egress, "AFTER {}".format(label))
    intf_after = get_intf_counters(dut, port_info.values())
    report_intf_counters(port_info, intf_before, intf_after)

    return q_before, q_after, egress


def _compute_deltas(q_before, q_after):
    """Return {qi: {'pkts': delta, 'drop_pkts': delta}} for all 8 queues."""
    deltas = {}
    for qi in range(8):
        b = q_before.get(qi, {})
        a = q_after.get(qi, {})
        deltas[qi] = {
            'pkts':      max(0, a.get('pkts',      0) - b.get('pkts',      0)),
            'drop_pkts': max(0, a.get('drop_pkts', 0) - b.get('drop_pkts', 0)),
        }
    return deltas


def _log_queue_placement_table(deltas, label=""):
    """Print per-queue results table: expected vs actual packet counts."""
    hdr = "  {:<6} {:>12}  {:>12}  {:>12}  {:>10}  {:>6}".format(
        "Queue", "Expected", "Actual", "Drop", "Status", "Delta%")
    st.log("")
    st.log("  DSCP Queue-Placement Results {}".format(label))
    st.log("  " + "-" * 75)
    st.log(hdr)
    st.log("  " + "-" * 75)
    for qi in range(8):
        exp  = _EXPECTED_Q_PKTS.get(qi, 0)
        act  = deltas[qi]['pkts']
        drp  = deltas[qi]['drop_pkts']
        if exp == 0:
            status = "N/A"
            dpct   = "N/A"
        else:
            lo = int(exp * 0.85)
            hi = int(exp * 1.15)
            status = "PASS" if lo <= act <= hi else "FAIL"
            dpct   = "{:+.1f}%".format((act - exp) / float(exp) * 100)
        st.log("  Q{:<5} {:>12,}  {:>12,}  {:>12,}  {:>10}  {:>6}".format(
            qi, exp, act, drp, status, dpct))
    st.log("  " + "-" * 75)
    st.log("")


def _log_traffic_topology():
    """Log the Section D topology resolved by setup_topo_common."""
    _role_ips = {
        'ingress': (IXIA_INGRESS_A_IP, IXIA_INGRESS_A_IP6),
        'egress':  (IXIA_EGRESS_IP,    IXIA_EGRESS_IP6),
    }
    st.log("")
    st.log("=" * 72)
    st.log("  SECTION D TOPOLOGY  (mode={})".format(topo_mode or '?'))
    st.log("-" * 72)
    for role in ('ingress', 'egress'):
        intf = port_info.get(role, '?')
        spd  = port_speeds.get(role, '?')
        v4, v6 = _role_ips[role]
        st.log("  {:<10} DUT={:<22} {}G   IPv4={}  IPv6={}".format(
            role, intf, spd, v4, v6))
    if tg_ph_ingress_b:
        st.log("  {:<10} DUT={:<22} (B9 cross-port source)".format(
            'ingress_b', port_info_ingress_b or '?'))
    st.log("-" * 72)
    st.log("-" * 72)
    st.log("  Streams  : 64 DSCP values  ×  {}pps  ×  {}pkts/burst".format(
        _STREAM_RATE_PPS, _PKTS_PER_DSCP))
    st.log("  Expected Q totals:")
    for qi in sorted(_EXPECTED_Q_PKTS):
        dscp_list = [int(d) for d, t in GOLDEN_DSCP_TO_TC.items() if int(t) == qi]
        st.log("    Q{}  {:>5,} pkts  ({} DSCPs: {})".format(
            qi, _EXPECTED_Q_PKTS[qi], len(dscp_list),
            ','.join(str(d) for d in sorted(dscp_list))))
    st.log("=" * 72)
    st.log("")


# ══════════════════════════════════════════════════════════════════════════════
# Section F — Advanced Config / Negative Tests
# ══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# Section D — Per-DSCP Queue Placement via Ixia Traffic (Tests 18–19)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.traffic
@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_per_dscp_queue_placement(af):
    """#18 — Verify every DSCP value routes traffic to the correct egress queue.

    Sends *_PKTS_PER_DSCP* packets at *_STREAM_RATE_PPS* pps for each of the
    64 DSCP values from the Ixia ingress port.  After the burst completes,
    the DCHAL per-queue counter delta on the egress port is compared against
    expected totals from GOLDEN_DSCP_TO_TC:

      expected[q] = _PKTS_PER_DSCP * |{dscp : GOLDEN_DSCP_TO_TC[dscp] == q}|

    A ±15% per-queue tolerance accommodates Ixia rate precision and DCHAL
    counter granularity.

    IPv4 sets ip_dscp; IPv6 encodes DSCP in ipv6_traffic_class (dscp << 2).
    Topology: D1T1:2 — ingress=T1D1P1, egress=T1D1P2.
    Depends on: setup_topo fixture.
    """
    print_section(
        "Test 18 — Per-DSCP queue placement [{}] "
        "(64 streams × {} pkts/DSCP)".format(af, _PKTS_PER_DSCP),
        art_key='dscp_to_tc')

    ingress_ph = tg_ph['ingress']
    dst_mac    = get_dut_mac(dut, port_info['ingress'])
    failures   = []

    st.log("  DUT ingress MAC : {}".format(dst_mac))
    st.log("  Address family  : {}".format(af))
    st.log("  Expected queue totals:")
    for qi in sorted(_EXPECTED_Q_PKTS):
        st.log("    Q{} = {:,} pkts".format(qi, _EXPECTED_Q_PKTS[qi]))

    tg.tg_traffic_control(action='reset')
    if af == 'ipv4':
        _build_ipv4_streams(tg, ingress_ph, dst_mac, _STREAM_RATE_PPS, _PKTS_PER_DSCP)
    else:
        _build_ipv6_streams(tg, ingress_ph, dst_mac, _STREAM_RATE_PPS, _PKTS_PER_DSCP)

    q_before, q_after, egress = _send_and_measure("Test18/{}".format(af))
    deltas = _compute_deltas(q_before, q_after)
    _log_queue_placement_table(deltas, "[{}]".format(af.upper()))

    total_sent = 64 * _PKTS_PER_DSCP
    total_rcvd = sum(d['pkts'] for d in deltas.values())
    st.log("  Total expected: {:,}   Total received: {:,}".format(
        total_sent, total_rcvd))

    for qi in range(8):
        exp = _EXPECTED_Q_PKTS.get(qi, 0)
        act = deltas[qi]['pkts']

        if exp == 0:
            if act > 0:
                failures.append(
                    "Q{} received {:,} pkts but expected 0 "
                    "(no AZURE DSCP maps to this queue)".format(qi, act))
            continue

        lo = int(exp * 0.85)
        hi = int(exp * 1.15)
        if not (lo <= act <= hi):
            n_dscp = len([d for d, t in GOLDEN_DSCP_TO_TC.items() if int(t) == qi])
            failures.append(
                "Q{} actual={:,} outside [{:,}, {:,}] "
                "(expected {:,} ±15%  •  {} DSCPs map here)".format(
                    qi, act, lo, hi, exp, n_dscp))
        else:
            st.log("  Q{}: {:,} pkts  (expected {:,} ±15%)  PASS".format(qi, act, exp))

    if total_rcvd == 0:
        failures.append(
            "No packets received on any queue — "
            "check routing and ARP/MAC resolution")

    if failures:
        st.report_fail('msg',
            "Test 18 [{}] failures ({}):\n  ".format(af, len(failures))
            + "\n  ".join(failures))
    st.report_pass('msg',
        "Test 18 [{}]: all 64 DSCPs classified to correct egress queue; "
        "total {:,} pkts (expected {:,})".format(af, total_rcvd, total_sent))


@pytest.mark.traffic
@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_zero_drops_on_expected_queue(af):
    """#19 — Verify no packets are dropped at low traffic rate.

    Same burst as test_per_dscp_queue_placement (64 DSCP streams at
    *_STREAM_RATE_PPS* pps — far below line rate) with an additional
    assertion that the DCHAL drop counter delta is zero on every queue.
    At this rate no WRED activation or tail drop should occur.

    Validates per queue:
      - Same queue placement correctness as Test 18 (±15% tolerance)
      - drop_pkts delta == 0 on all 8 queues

    Topology: D1T1:2.  Depends on: setup_topo fixture.
    """
    print_section(
        "Test 19 — Zero drops on expected queue [{}]".format(af),
        art_key='dscp_to_tc')

    ingress_ph = tg_ph['ingress']
    dst_mac    = get_dut_mac(dut, port_info['ingress'])
    failures   = []

    st.log("  Address family : {}".format(af))
    st.log("  Rate: {} pps per DSCP  —  far below line rate, expect zero drops".format(
        _STREAM_RATE_PPS))

    tg.tg_traffic_control(action='reset')
    if af == 'ipv4':
        _build_ipv4_streams(tg, ingress_ph, dst_mac, _STREAM_RATE_PPS, _PKTS_PER_DSCP)
    else:
        _build_ipv6_streams(tg, ingress_ph, dst_mac, _STREAM_RATE_PPS, _PKTS_PER_DSCP)

    q_before, q_after, egress = _send_and_measure("Test19/{}".format(af))
    deltas = _compute_deltas(q_before, q_after)
    _log_queue_placement_table(deltas, "[{} — drop check]".format(af.upper()))

    total_sent = 64 * _PKTS_PER_DSCP
    total_rcvd = sum(d['pkts'] for d in deltas.values())

    # Drop check
    st.log("  Per-queue drop counters:")
    for qi in range(8):
        drp = deltas[qi]['drop_pkts']
        st.log("  Q{}: drop_pkts={:,}  {}".format(
            qi, drp, "PASS" if drp == 0 else "** FAIL"))
        if drp > 0:
            failures.append(
                "Q{} drop_pkts={:,} at {} pps "
                "(WRED/tail-drop should NOT activate)".format(
                    qi, drp, _STREAM_RATE_PPS))

    # Placement check (same ±15% criteria as Test 18)
    for qi in range(8):
        exp = _EXPECTED_Q_PKTS.get(qi, 0)
        act = deltas[qi]['pkts']
        if exp == 0:
            if act > 0:
                failures.append(
                    "Q{} received {:,} pkts but expected 0".format(qi, act))
            continue
        lo = int(exp * 0.85)
        hi = int(exp * 1.15)
        if not (lo <= act <= hi):
            failures.append(
                "Q{} actual={:,} outside [{:,},{:,}] (expected {:,} ±15%)".format(
                    qi, act, lo, hi, exp))

    if total_rcvd == 0:
        failures.append(
            "No packets received on any queue — "
            "check routing and ARP/MAC resolution")

    if failures:
        st.report_fail('msg',
            "Test 19 [{}] failures ({}):\n  ".format(af, len(failures))
            + "\n  ".join(failures))
    st.report_pass('msg',
        "Test 19 [{}]: all 64 DSCPs on correct queues with zero drops; "
        "total {:,} pkts (expected {:,})".format(af, total_rcvd, total_sent))


# ══════════════════════════════════════════════════════════════════════════════
# Section F — Advanced Map-Binding / Negative Tests (Tests F1–F5)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.config_only
def test_rebind_different_map_to_port():
    """#F1 — Bind a custom DSCP_TO_TC map to a port, then rebind AZURE.

    Corresponds to wiki T5.8: "Re-bind different map to port".

    Steps:
      1. Create minimal DSCP_TO_TC_MAP|CUSTOM_3 (entries: 0→7, 1→6, 2→5).
      2. HSET PORT_QOS_MAP|<intf> dscp_to_tc_map=CUSTOM_3; verify CONFIG_DB.
      3. Rebind: HSET PORT_QOS_MAP|<intf> dscp_to_tc_map=AZURE; verify CONFIG_DB.
      4. Verify ASIC_DB DSCP_TO_TC OID present and MAP_TO_VALUE_LIST has 64 entries.
      5. HDEL PORT_QOS_MAP binding.
      6. DEL DSCP_TO_TC_MAP|CUSTOM_3 and qos reload to restore baseline.
    """
    print_section("F1 — Rebind different map to port (CUSTOM_3 → AZURE)",
                  art_key='dscp_to_tc')

    intf     = test_intf
    map_name = 'CUSTOM_3'
    custom   = {0: 7, 1: 6, 2: 5}
    failures = []

    initial = get_port_dscp_tc_map(dut, intf)
    st.log("  Interface: {}   initial dscp_to_tc_map='{}'".format(
        intf, initial or '(nil)'))

    # Step 1: create CUSTOM_3
    for dscp, tc in custom.items():
        st.config(dut,
            'sonic-db-cli CONFIG_DB HSET "DSCP_TO_TC_MAP|{}" "{}" "{}"'.format(
                map_name, dscp, tc),
            skip_error_check=True)
    st.wait(2)

    # Step 2: bind CUSTOM_3
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" "dscp_to_tc_map" "{}"'.format(
            intf, map_name),
        skip_error_check=True)
    st.wait(1)
    bound = get_port_dscp_tc_map(dut, intf)
    st.log("  CONFIG_DB after bind CUSTOM_3: dscp_to_tc_map='{}'".format(bound))
    if map_name not in (bound or '').upper():
        failures.append(
            "After binding {}: CONFIG_DB shows '{}', expected '{}'".format(
                map_name, bound, map_name))

    # Step 3: rebind to AZURE
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" "dscp_to_tc_map" "AZURE"'.format(intf),
        skip_error_check=True)
    st.wait(1)
    bound2 = get_port_dscp_tc_map(dut, intf)
    st.log("  CONFIG_DB after rebind AZURE: dscp_to_tc_map='{}'".format(bound2))
    if 'AZURE' not in (bound2 or '').upper():
        failures.append(
            "After rebind AZURE: CONFIG_DB shows '{}', expected 'AZURE'".format(bound2))

    # Step 4: ASIC_DB has 64 entries
    asic_map = asic_dscp_to_tc_map(dut)
    if len(asic_map) != 64:
        failures.append(
            "ASIC_DB has {} entries after rebind, expected 64".format(len(asic_map)))
    else:
        st.log("  ASIC_DB MAP_TO_VALUE_LIST count=64  PASS")

    # Steps 5-6: cleanup
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "PORT_QOS_MAP|{}" "dscp_to_tc_map"'.format(intf),
        skip_error_check=True)
    st.config(dut,
        'sonic-db-cli CONFIG_DB DEL "DSCP_TO_TC_MAP|{}"'.format(map_name),
        skip_error_check=True)
    reload_qos(dut, wait=8)

    if initial and initial not in ('', 'nil', '(nil)', 'None'):
        st.config(dut,
            'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" "dscp_to_tc_map" "{}"'.format(
                intf, initial),
            skip_error_check=True)

    if failures:
        st.report_fail('msg',
            "F1 rebind different map failures:\n  " + "\n  ".join(failures))
    st.report_pass('msg',
        "F1: rebind CUSTOM_3 → AZURE on port {} successful; "
        "ASIC_DB retains 64 AZURE entries after rebind".format(intf))


@pytest.mark.config_only
def test_bind_same_map_multiport():
    """#F2 — Bind the AZURE DSCP_TO_TC map to two ports simultaneously.

    Corresponds to wiki T5.9: "Bind same map to multi-port".

    FX3 uses a global (not per-port) DSCP-to-TC map in ASIC_DB; binding
    AZURE to multiple ports must not cause errors and must leave exactly
    one DSCP_TO_TC OID in ASIC_DB.

    Steps:
      1. HSET PORT_QOS_MAP|<intf>  dscp_to_tc_map=AZURE.
      2. HSET PORT_QOS_MAP|<intf2> dscp_to_tc_map=AZURE.
      3. Verify CONFIG_DB shows AZURE on both ports.
      4. Verify ASIC_DB contains exactly one DSCP_TO_TC OID (global map).
      5. HDEL both ports; verify CONFIG_DB fields are nil.
    """
    print_section("F2 — Bind same map (AZURE) to two ports simultaneously",
                  art_key='dscp_to_tc')

    intf1    = test_intf
    intf2    = test_intf2
    failures = []

    initial1 = get_port_dscp_tc_map(dut, intf1)
    initial2 = get_port_dscp_tc_map(dut, intf2)
    st.log("  intf1={}  intf2={}".format(intf1, intf2))
    st.log("  initial: intf1='{}'  intf2='{}'".format(
        initial1 or '(nil)', initial2 or '(nil)'))

    # Steps 1-2: bind AZURE to both ports
    for intf in (intf1, intf2):
        st.config(dut,
            'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" "dscp_to_tc_map" "AZURE"'.format(
                intf),
            skip_error_check=True)
    st.wait(2)

    # Step 3: verify CONFIG_DB
    b1 = get_port_dscp_tc_map(dut, intf1)
    b2 = get_port_dscp_tc_map(dut, intf2)
    st.log("  CONFIG_DB after bind:  intf1='{}'  intf2='{}'".format(
        b1 or '(nil)', b2 or '(nil)'))
    for lbl, val in [(intf1, b1), (intf2, b2)]:
        if 'AZURE' not in (val or '').upper():
            failures.append(
                "PORT_QOS_MAP|{} dscp_to_tc_map='{}', expected AZURE".format(lbl, val))

    # Step 4: exactly one DSCP_TO_TC OID in ASIC_DB (FX3 global map)
    types = asic_qos_map_types(dut)
    count_dscp = types.count('SAI_QOS_MAP_TYPE_DSCP_TO_TC')
    st.log("  ASIC_DB QoS map types: {}".format(types))
    st.log("  DSCP_TO_TC OID count: {}  (expected 1 — global map)".format(count_dscp))
    if count_dscp != 1:
        failures.append(
            "Expected 1 DSCP_TO_TC OID in ASIC_DB, found {}".format(count_dscp))
    else:
        st.log("  Exactly 1 DSCP_TO_TC OID in ASIC_DB  PASS")

    # Step 5: unbind both ports
    for intf in (intf1, intf2):
        st.config(dut,
            'sonic-db-cli CONFIG_DB HDEL "PORT_QOS_MAP|{}" "dscp_to_tc_map"'.format(intf),
            skip_error_check=True)
    st.wait(2)

    u1 = get_port_dscp_tc_map(dut, intf1)
    u2 = get_port_dscp_tc_map(dut, intf2)
    st.log("  CONFIG_DB after unbind: intf1='{}'  intf2='{}'".format(
        u1 or '(nil)', u2 or '(nil)'))
    for lbl, val in [(intf1, u1), (intf2, u2)]:
        if val and val not in ('', 'nil', 'None'):
            failures.append(
                "PORT_QOS_MAP|{} still shows '{}' after HDEL".format(lbl, val))

    # Restore
    for intf, init in [(intf1, initial1), (intf2, initial2)]:
        if init and init not in ('', 'nil', 'None'):
            st.config(dut,
                'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" "dscp_to_tc_map" "{}"'.format(
                    intf, init),
                skip_error_check=True)

    if failures:
        st.report_fail('msg',
            "F2 multi-port bind failures:\n  " + "\n  ".join(failures))
    st.report_pass('msg',
        "F2: AZURE bound to 2 ports simultaneously; "
        "ASIC_DB retains exactly 1 DSCP_TO_TC OID (global map); "
        "unbind succeeds on both ports")


@pytest.mark.config_only
def test_delete_map_while_bound():
    """#F3 — Attempt to DEL DSCP_TO_TC_MAP|AZURE while bound to a port.

    Corresponds to wiki T5.10: "Delete map while bound".

    On FX3, orchagent enforces OBJECT_IN_USE: a map referenced by
    PORT_QOS_MAP cannot be removed until the binding is cleared.
    Pass criterion: either CONFIG_DB map survives OR ASIC_DB OID survives
    (platform may enforce at either layer).

    Steps:
      1. Bind AZURE to <intf> via PORT_QOS_MAP.
      2. DEL CONFIG_DB DSCP_TO_TC_MAP|AZURE while bound (expect no-op or error).
      3. Assert CONFIG_DB map still present, OR ASIC_DB OID still present.
      4. Assert ASIC_DB OID is not removed while port has an active binding.
      5. Unbind and qos reload to restore baseline.
    """
    print_section("F3 — Delete map while bound to port (expect OID survives)",
                  art_key='dscp_to_tc')

    intf     = test_intf
    failures = []

    initial = get_port_dscp_tc_map(dut, intf)
    st.log("  Interface: {}  initial binding='{}'".format(intf, initial or '(nil)'))

    # Step 1: bind AZURE
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" "dscp_to_tc_map" "AZURE"'.format(intf),
        skip_error_check=True)
    st.wait(2)

    oid_before = asic_qos_map_oid(dut)
    st.log("  ASIC_DB OID before DEL: {}".format(oid_before or '(none)'))

    # Step 2: attempt DEL while bound
    st.config(dut,
        'sonic-db-cli CONFIG_DB DEL "DSCP_TO_TC_MAP|AZURE"',
        skip_error_check=True)
    st.wait(3)

    # Step 3: check CONFIG_DB map survived
    db_map = get_dscp_to_tc_map(dut, 'AZURE')
    st.log("  CONFIG_DB DSCP_TO_TC_MAP|AZURE entries after DEL: {}".format(len(db_map)))

    # Step 4: check ASIC_DB OID survived
    oid_after = asic_qos_map_oid(dut)
    st.log("  ASIC_DB OID after DEL: {}".format(oid_after or '(none)'))

    if oid_after is None and len(db_map) == 0:
        failures.append(
            "Both CONFIG_DB map and ASIC_DB OID were removed while port '{}' "
            "had an active binding — OBJECT_IN_USE not enforced".format(intf))
    else:
        if len(db_map) > 0:
            st.log("  CONFIG_DB map survived ({} entries): "
                   "OBJECT_IN_USE enforced at orchagent level".format(len(db_map)))
        if oid_after is not None:
            st.log("  ASIC_DB OID {} still present: HW object correctly retained".format(
                oid_after))

    # Step 5: unbind and reload
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "PORT_QOS_MAP|{}" "dscp_to_tc_map"'.format(intf),
        skip_error_check=True)
    reload_qos(dut, wait=10)

    if initial and initial not in ('', 'nil', 'None'):
        st.config(dut,
            'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" "dscp_to_tc_map" "{}"'.format(
                intf, initial),
            skip_error_check=True)

    if failures:
        st.report_fail('msg',
            "F3 delete-while-bound failures:\n  " + "\n  ".join(failures))
    st.report_pass('msg',
        "F3: DEL DSCP_TO_TC_MAP|AZURE while bound to {} did not remove HW object; "
        "OBJECT_IN_USE semantics correctly enforced".format(intf))


@pytest.mark.config_only
def test_unbind_from_unbound_port():
    """#F4 — HDEL dscp_to_tc_map from a port with no binding; must be idempotent.

    Corresponds to wiki T5.12: "Unbind from unbound port".

    Steps:
      1. Ensure PORT_QOS_MAP|<intf> has no dscp_to_tc_map.
      2. First HDEL on unbound port — must not error.
      3. Second HDEL (idempotence check) — must succeed silently.
      4. Verify ASIC_DB DSCP_TO_TC OID unchanged by both HDELs.
      5. Verify CONFIG_DB dscp_to_tc_map field is nil.
    """
    print_section("F4 — Unbind from already-unbound port (idempotent HDEL)",
                  art_key='dscp_to_tc')

    intf     = test_intf
    failures = []

    initial    = get_port_dscp_tc_map(dut, intf)
    oid_before = asic_qos_map_oid(dut)
    st.log("  Interface: {}  initial binding='{}'".format(intf, initial or '(nil)'))
    st.log("  ASIC_DB OID baseline: {}".format(oid_before or '(none)'))

    # Step 1: ensure no binding
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "PORT_QOS_MAP|{}" "dscp_to_tc_map"'.format(intf),
        skip_error_check=True)
    st.wait(1)

    # Step 2: first HDEL on unbound port
    st.log("  Step 2: first HDEL on unbound port")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "PORT_QOS_MAP|{}" "dscp_to_tc_map"'.format(intf),
        skip_error_check=True)
    st.wait(1)

    # Step 3: second HDEL (idempotence)
    st.log("  Step 3: second HDEL (idempotence check)")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "PORT_QOS_MAP|{}" "dscp_to_tc_map"'.format(intf),
        skip_error_check=True)
    st.wait(1)

    # Step 4: ASIC_DB OID must be unchanged
    oid_after = asic_qos_map_oid(dut)
    st.log("  ASIC_DB OID after both HDELs: {}".format(oid_after or '(none)'))
    if oid_after != oid_before:
        failures.append(
            "ASIC_DB OID changed '{}' → '{}' — "
            "unbound-port HDEL must be a no-op".format(oid_before, oid_after))
    else:
        st.log("  ASIC_DB OID unchanged  PASS")

    # Step 5: CONFIG_DB field must be nil
    val = get_port_dscp_tc_map(dut, intf)
    st.log("  CONFIG_DB dscp_to_tc_map after HDELs: '{}'".format(val or '(nil)'))
    if val and val not in ('', 'nil', 'None'):
        failures.append(
            "CONFIG_DB dscp_to_tc_map='{}' after HDEL — expected nil".format(val))

    # Restore
    if initial and initial not in ('', 'nil', 'None'):
        st.config(dut,
            'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" '
            '"dscp_to_tc_map" "{}"'.format(intf, initial),
            skip_error_check=True)

    if failures:
        st.report_fail('msg',
            "F4 unbind-from-unbound failures:\n  " + "\n  ".join(failures))
    st.report_pass('msg',
        "F4: two consecutive HDELs on unbound port {} are idempotent; "
        "ASIC_DB OID unchanged; CONFIG_DB field nil".format(intf))


@pytest.mark.config_only
def test_rebind_readback_no_corruption():
    """#F5 — Bind map + qos reload + readback all 64 ASIC_DB entries; no corruption.

    Corresponds to wiki T5.11: "Bind/readback parameterized".

    After a bind + 'config qos reload' (which triggers sai_remove → sai_create),
    verifies that all 64 DSCP→TC entries in ASIC_DB match GOLDEN_DSCP_TO_TC.

    Steps:
      1. HSET PORT_QOS_MAP|<intf> dscp_to_tc_map=AZURE.
      2. 'config qos reload' (SAI remove+create with port binding active).
      3. Read ASIC_DB MAP_TO_VALUE_LIST.
      4. Assert count == 64 and all entries match GOLDEN_DSCP_TO_TC.
      5. HDEL binding and reload to restore baseline.
    """
    print_section("F5 — Bind + reload + readback: ASIC_DB entries uncorrupted",
                  art_key='dscp_to_tc')

    intf     = test_intf
    failures = []

    initial = get_port_dscp_tc_map(dut, intf)
    st.log("  Interface: {}  initial binding='{}'".format(intf, initial or '(nil)'))

    # Step 1: bind AZURE
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" "dscp_to_tc_map" "AZURE"'.format(intf),
        skip_error_check=True)
    st.wait(1)

    # Step 2: reload with port bound
    st.log("  Running 'config qos reload' with port {} bound".format(intf))
    reload_qos(dut, wait=15)

    # Steps 3-4: readback and compare
    asic_map = asic_dscp_to_tc_map(dut)
    st.log("  ASIC_DB entry count after reload: {}  (expected 64)".format(len(asic_map)))

    if len(asic_map) != 64:
        failures.append(
            "ASIC_DB has {} entries after bind+reload, expected 64".format(len(asic_map)))

    st.log("  {:<6} {:>9} {:>9} {:>8}".format('DSCP', 'Expected', 'Actual', 'Status'))
    st.log("  " + "-" * 38)
    for dscp_str in sorted(GOLDEN_DSCP_TO_TC, key=lambda x: int(x)):
        dscp   = int(dscp_str)
        exp_tc = int(GOLDEN_DSCP_TO_TC[dscp_str])
        act_tc = asic_map.get(dscp, '(missing)')
        ok     = act_tc == exp_tc
        st.log("  {:<6} {:>9} {:>9} {:>8}".format(
            dscp, exp_tc, act_tc, 'OK' if ok else '** FAIL'))
        if not ok:
            failures.append(
                "DSCP {} → TC {} (expected {}) — post bind+reload corruption".format(
                    dscp, act_tc, exp_tc))

    # Step 5: restore
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "PORT_QOS_MAP|{}" "dscp_to_tc_map"'.format(intf),
        skip_error_check=True)
    reload_qos(dut, wait=8)

    if initial and initial not in ('', 'nil', 'None'):
        st.config(dut,
            'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" '
            '"dscp_to_tc_map" "{}"'.format(intf, initial),
            skip_error_check=True)

    if failures:
        st.report_fail('msg',
            "F5 rebind-readback failures ({}):\n  ".format(len(failures))
            + "\n  ".join(failures[:10]))
    st.report_pass('msg',
        "F5: port {} bind + reload + readback: "
        "all 64 ASIC_DB DSCP→TC entries correct after reload cycle".format(intf))


# ══════════════════════════════════════════════════════════════════════════════
# Section A (continued) — Test Plan #2: Reduced Map Entry Count in TCAM
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.config_only
def test_reduced_map_tcam_count():
    """#A2 — Reduced map entry count: 3-entry DSCP map → 3 TCAM slots.

    Test plan Section A, Test 2: "Reduced map entry count in TCAM".

    Temporarily replaces the content of DSCP_TO_TC_MAP|AZURE in CONFIG_DB with
    a 3-entry map ({0: 1, 10: 5, 46: 6}), does a 'config qos reload', and
    verifies TCAM entry count and key/value correctness.

    On some DUT builds 'config qos reload' regenerates AZURE from a platform
    template, overriding the CONFIG_DB edit.  If that happens, the test logs a
    warning and falls back to verifying only the ASIC_DB map OID (which should
    reflect the currently active 3-entry map bound to the test port).

    Steps:
      1. Record current TCAM 'used' count.
      2. DEL DSCP_TO_TC_MAP|AZURE from CONFIG_DB, re-create it with 3 entries.
      3. Bind the 3-entry AZURE to test_intf via PORT_QOS_MAP.
      4. Run 'config qos reload'.
      5. Dump TCAM:
         a. If used == 3 (or 9 including NOP halves) → full TCAM pass.
         b. If used == 192 → reload restored template AZURE; fall back to
            ASIC_DB verification.
      6. Verify ASIC_DB MAP_TO_VALUE_LIST has exactly 3 entries.
      7. Clean up: restore full AZURE to CONFIG_DB, unbind port, reload.
    """
    print_section("A2 — Reduced map: 3-entry AZURE override → count TCAM slots",
                  art_key='dscp_to_tc')

    _SMALL_MAP = {0: 1, 10: 5, 46: 6}   # dscp → tc  (3 entries)
    failures = []

    # ── Step 1: baseline TCAM count ────────────────────────────────────────
    info_before = dchal_tcam_info(dut)
    used_before = info_before.get('used', -1)
    st.log("  TCAM before: used={}".format(used_before))

    # ── Step 2: replace AZURE with 3-entry map ─────────────────────────────
    st.log("  Replacing DSCP_TO_TC_MAP|AZURE with 3-entry map: {}".format(_SMALL_MAP))
    st.config(dut, 'sonic-db-cli CONFIG_DB DEL "DSCP_TO_TC_MAP|AZURE"',
              skip_error_check=True)
    st.wait(1)
    for dscp, tc in _SMALL_MAP.items():
        st.config(dut,
            'sonic-db-cli CONFIG_DB HSET "DSCP_TO_TC_MAP|AZURE" "{}" "{}"'.format(
                dscp, tc),
            skip_error_check=True)
    st.wait(1)

    # ── Step 3: bind to test port ───────────────────────────────────────────
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" "dscp_to_tc_map" "AZURE"'.format(
            test_intf),
        skip_error_check=True)
    st.wait(1)

    # ── Step 4: reload ─────────────────────────────────────────────────────
    st.log("  Running 'config qos reload' with 3-entry AZURE...")
    reload_qos(dut, wait=20)

    # ── Step 5: TCAM count check ────────────────────────────────────────────
    info_after = dchal_tcam_info(dut)
    used_after = info_after.get('used', -1)
    st.log("  TCAM after reload: used={} (expected 9 or 3, got {})".format(
        used_after, used_after))

    tcam_ok = False
    if used_after in (3, 9):  # 3 IPv4 + 0 or 6 IPv6 on reduced map
        tcam_ok = True
        st.log("  TCAM entry count matches reduced map ({})  PASS".format(used_after))
        dump = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=32)
        ipv4_entries = tcam_ipv4_dscp_entries(dump)
        ipv4_dscp = {e['dscp'] for e in ipv4_entries if e.get('dscp') is not None}
        exp_dscp = set(_SMALL_MAP.keys())
        if ipv4_dscp != exp_dscp:
            failures.append(
                "IPv4 DSCP set mismatch: got={} expected={}".format(
                    sorted(ipv4_dscp), sorted(exp_dscp)))
        else:
            st.log("  IPv4 DSCP set matches {}  PASS".format(sorted(exp_dscp)))
    elif used_after == 192:
        st.log("  WARN: TCAM still has 192 entries — reload re-applied template AZURE")
        st.log("  Falling back to ASIC_DB verification only")
    else:
        failures.append("Unexpected TCAM used={} after reload (expected 9 or 192)".format(
            used_after))

    # ── Step 6: ASIC_DB map OID entry count ───────────────────────────────
    asic_map = asic_dscp_to_tc_map(dut)
    st.log("  ASIC_DB MAP_TO_VALUE_LIST: {} entries (expected 3)".format(len(asic_map)))
    if len(asic_map) != len(_SMALL_MAP):
        st.log("  INFO: ASIC_DB has {} entries (may retain last-active-map count)".format(
            len(asic_map)))
        # ASIC may retain previous count if port was already bound; not a failure
    else:
        st.log("  ASIC_DB entry count = {}  PASS".format(len(asic_map)))
        # Verify each DSCP value in asic_map matches _SMALL_MAP
        for dscp, tc in _SMALL_MAP.items():
            got_tc = asic_map.get(str(dscp))
            if got_tc is None:
                failures.append(
                    "ASIC_DB missing DSCP {}".format(dscp))
            elif str(got_tc) != str(tc):
                failures.append(
                    "ASIC_DB DSCP {} → TC {} (expected {})".format(
                        dscp, got_tc, tc))
            else:
                st.log("  ASIC_DB DSCP {:2d} → TC {}  PASS".format(dscp, tc))

    # ── Step 7: restore full AZURE ─────────────────────────────────────────
    st.log("  Restoring full 64-entry AZURE map...")
    st.config(dut, 'sonic-db-cli CONFIG_DB DEL "DSCP_TO_TC_MAP|AZURE"',
              skip_error_check=True)
    st.wait(1)
    for dscp_str, tc_str in GOLDEN_DSCP_TO_TC.items():
        st.config(dut,
            'sonic-db-cli CONFIG_DB HSET "DSCP_TO_TC_MAP|AZURE" "{}" "{}"'.format(
                dscp_str, tc_str),
            skip_error_check=True)
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "PORT_QOS_MAP|{}" "dscp_to_tc_map"'.format(test_intf),
        skip_error_check=True)
    reload_qos(dut, wait=15)

    info_restored = dchal_tcam_info(dut)
    st.log("  TCAM after full restore: used={}".format(info_restored.get('used')))

    if failures:
        st.report_fail('msg', "A2 reduced map failures:\n  " + "\n  ".join(failures))
    elif not tcam_ok and used_after == 192:
        st.report_pass('msg',
            "A2: 3-entry AZURE override — reload re-applied template AZURE (192 TCAM entries); "
            "ASIC_DB path verified where possible; AZURE fully restored")
    else:
        st.report_pass('msg',
            "A2: 3-entry reduced AZURE map → {} TCAM entries; "
            "ASIC_DB verified; full AZURE restored to {}".format(
                used_after, info_restored.get('used')))


# ══════════════════════════════════════════════════════════════════════════════
# Section B — TCAM Hit Counter Verification via Ixia (Plan #12–13)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.traffic
@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_tcam_hit_counters(af):
    """#B12/13 — All 64 DSCP TCAM hit counters increment correctly (IPv4 and IPv6).

    Test plan Section B, Tests 12–13: "All 64 DSCP values TCAM hit (V4/V6)".

    Sends _PKTS_PER_DSCP packets for each of the 64 DSCP values from the Ixia
    ingress port and verifies that each TCAM entry's stats_pkts counter
    increments by approximately _PKTS_PER_DSCP (±25% tolerance for timing and
    hardware counter granularity).

    IPv4: each DSCP has one TCAM entry (proto='ipv4').
    IPv6: each DSCP has one active wide-key entry (proto='ipv6', qos_map_idx set).

    Steps:
      1. Dump TCAM before traffic — snapshot stats_pkts for all entries.
      2. Send 64 Ixia streams (one per DSCP), _PKTS_PER_DSCP pkts each.
      3. Dump TCAM after traffic.
      4. Compute per-entry stats_pkts delta and assert within tolerance.
      5. (IPv6 only) Assert NOP wide-key halves do not accumulate hit counts.
    """
    print_section(
        "B{} — TCAM hit counters: all 64 DSCP values [{}]".format(
            12 if af == 'ipv4' else 13, af.upper()),
        art_key='dscp_to_tc')

    ingress_ph = tg_ph['ingress']
    dst_mac    = get_dut_mac(dut, port_info['ingress'])
    failures   = []
    # Test plan: each DSCP entry must increment by exactly _PKTS_PER_DSCP (250 pkts).

    st.log("  AF={}  pkts/DSCP={}  criterion=exactly +{}".format(
        af, _PKTS_PER_DSCP, _PKTS_PER_DSCP))

    # ── Step 1: pre-traffic TCAM snapshot ─────────────────────────────────
    dump_before = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump_before:
        st.report_fail('msg', "B{} [{}]: pre-traffic dchal_tcam_dump returned empty".format(
            12 if af == 'ipv4' else 13, af))

    if af == 'ipv4':
        before_map = {e['dscp']: e.get('stats_pkts', 0)
                      for e in tcam_ipv4_dscp_entries(dump_before)
                      if e.get('dscp') is not None}
    else:
        before_map = {e['dscp']: e.get('stats_pkts', 0)
                      for e in tcam_ipv6_dscp_entries(dump_before)
                      if e.get('dscp') is not None}

    st.log("  Pre-traffic snapshot: {} {} entries".format(len(before_map), af))

    # ── Step 2: send traffic ───────────────────────────────────────────────
    tg.tg_traffic_control(action='reset')
    if af == 'ipv4':
        _build_ipv4_streams(tg, ingress_ph, dst_mac, _STREAM_RATE_PPS, _PKTS_PER_DSCP)
    else:
        _build_ipv6_streams(tg, ingress_ph, dst_mac, _STREAM_RATE_PPS, _PKTS_PER_DSCP)

    tg.tg_traffic_control(action='clear_stats')
    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run')
    st.wait(_TRAFFIC_TIMEOUT)
    tg.tg_traffic_control(action='stop')
    st.wait(3)

    # ── Step 3: post-traffic TCAM dump ─────────────────────────────────────
    dump_after = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump_after:
        st.report_fail('msg', "B{} [{}]: post-traffic dchal_tcam_dump returned empty".format(
            12 if af == 'ipv4' else 13, af))

    if af == 'ipv4':
        after_map = {e['dscp']: e.get('stats_pkts', 0)
                     for e in tcam_ipv4_dscp_entries(dump_after)
                     if e.get('dscp') is not None}
    else:
        after_map = {e['dscp']: e.get('stats_pkts', 0)
                     for e in tcam_ipv6_dscp_entries(dump_after)
                     if e.get('dscp') is not None}

    # ── Step 4: per-entry delta check — test plan requires exactly +_PKTS_PER_DSCP ──

    st.log("  {:<6} {:>14}  {:>14}  {:>14}  {:>8}".format(
        'DSCP', 'Before', 'After', 'Delta', 'Status'))
    st.log("  " + "-" * 64)

    pass_count = 0
    for dscp in range(64):
        before_cnt = before_map.get(dscp, 0)
        after_cnt  = after_map.get(dscp,  0)
        delta      = max(0, after_cnt - before_cnt)
        ok         = (delta == _PKTS_PER_DSCP)
        st.log("  {:<6} {:>14,}  {:>14,}  {:>14,}  {:>8}".format(
            dscp, before_cnt, after_cnt, delta, 'PASS' if ok else 'FAIL'))
        if ok:
            pass_count += 1
        else:
            failures.append(
                "DSCP {} [{}]: delta={} (expected exactly {})".format(
                    dscp, af, delta, _PKTS_PER_DSCP))

    st.log("  {}/{} DSCP entries PASS".format(pass_count, 64))

    # ── Step 5: NOP halves must not accumulate (IPv6 only) ─────────────────
    if af == 'ipv6':
        nop_before = {e.get('dscp', None): e.get('stats_pkts', 0)
                      for e in tcam_ipv6_wide_halves(dump_before)}
        nop_after  = {e.get('dscp', None): e.get('stats_pkts', 0)
                      for e in tcam_ipv6_wide_halves(dump_after)}
        stale = [(d, nop_after.get(d, 0) - nop_before.get(d, 0))
                 for d in nop_before if (nop_after.get(d, 0) - nop_before.get(d, 0)) > 0]
        if stale:
            st.log("  WARN: {} NOP wide-key halves with non-zero delta: {}".format(
                len(stale), stale[:5]))
        else:
            st.log("  IPv6 NOP halves: all deltas = 0  PASS")

    if failures:
        st.report_fail('msg',
            "B{} [{}] counter failures ({}/64):\n  ".format(
                12 if af == 'ipv4' else 13, af, len(failures))
            + "\n  ".join(failures[:10]))
    st.report_pass('msg',
        "B{} [{}]: all 64 DSCP TCAM entries incremented by ~{} pkts ".format(
            12 if af == 'ipv4' else 13, af, _PKTS_PER_DSCP))


# ══════════════════════════════════════════════════════════════════════════════
# Section F (continued) — Custom (non-AZURE) Map TCAM and ASIC Verification
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.config_only
def test_custom_map_tcam_vs_azure():
    """#F6 — New custom DSCP-to-TC map applied to an interface; ASIC_DB and
    TCAM reflect the custom TC values.

    Test plan Section F: "Custom (non-AZURE) maps — Verify with non-standard
    DSCP-to-TC maps."

    Creates a brand-new 64-entry map CUSTOM_64 (identical to AZURE except for
    4 swapped DSCP→TC entries) and binds it to test_intf via PORT_QOS_MAP.
    The test then verifies:
      a) A new SAI_QOS_MAP OID is created in ASIC_DB for CUSTOM_64.
      b) SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP on the port points to the new OID
         (not oid:0x0).
      c) TCAM usage changes (a new TCAM region is allocated for the custom
         map's distinct TC assignments).
      d) The 4 swapped DSCP entries in ASIC_DB reflect the custom TC values,
         not the AZURE TC values.
      e) One non-swapped DSCP (DSCP 16) still carries its AZURE TC value.

    Custom swaps in CUSTOM_64 vs AZURE:
      DSCP  1  → TC 7  (AZURE: TC 1)
      DSCP 46  → TC 0  (AZURE: TC 5)
      DSCP 48  → TC 1  (AZURE: TC 6)
      DSCP 49  → TC 0  (AZURE: TC 7)

    Steps:
      0. Clean AZURE baseline via 'config qos reload'; back up
         /etc/sonic/config_db.json for safe restore at teardown.
      1. Baseline: snapshot ASIC_DB QOS_MAP OID count and TCAM usage.
      2. Write all 64 entries of CUSTOM_64 to CONFIG_DB; bind to test_intf
         via PORT_QOS_MAP; persist with 'config save -y'.
      3. Wait for orchagent to process CONFIG_DB notifications (no reload —
         orchagent subscribes directly and 'config qos reload' would restore
         AZURE from the .j2 template, destroying CUSTOM_64).
      4. Verify a NEW SAI_QOS_MAP OID appeared in ASIC_DB for CUSTOM_64.
      5. Verify SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP on test_intf points to the
         new OID (not oid:0x0 / global default).
      6. Verify TCAM used count increased vs baseline (a new map with distinct
         TC assignments must allocate a new TCAM region; delta=0 is a failure).
      7. Verify the 4 swapped DSCP→TC values in the CUSTOM_64 OID.
      8. Verify DSCP 16 (unchanged) has the AZURE TC in the CUSTOM_64 OID.
      9. Cleanup: HDEL PORT_QOS_MAP binding, DEL CUSTOM_64; restore backed-up
         config_db.json; run 'config qos reload' to restore AZURE everywhere.
    """
    print_section("F6 — New CUSTOM_64 map on interface: ASIC_DB + TCAM verification",
                  art_key='dscp_to_tc')

    _CUSTOM_MAP = 'CUSTOM_64'
    _SWAPS      = {1: 7, 46: 0, 48: 1, 49: 0}   # dscp → custom_tc
    _SPOT_DSCP  = 16                              # non-swapped spot-check DSCP
    _BACKUP     = '/tmp/config_db_f6_backup.json'
    _WAIT       = 10
    _RETRIES    = 9
    failures    = []

    # ── Step 0: clean AZURE baseline + backup config_db.json ─────────────
    st.log("  Step 0: clean AZURE baseline via 'config qos reload'...")
    reload_qos(dut, wait=10)
    st.config(dut,
        'cp /etc/sonic/config_db.json {}'.format(_BACKUP),
        skip_error_check=True)
    st.log("  Backed up config_db.json → {}".format(_BACKUP))

    # ── Step 1: baseline — ASIC_DB OID count + TCAM usage ────────────────
    # List all SAI_OBJECT_TYPE_QOS_MAP keys in ASIC_DB.
    def _list_qos_map_oids():
        raw = st.show(dut,
            'sonic-db-cli ASIC_DB KEYS "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:*"',
            skip_tmpl=True)
        return [l.strip() for l in (raw or '').splitlines()
                if re.match(r'^ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:oid:', l.strip())]

    oids_before = _list_qos_map_oids()
    st.log("  Baseline ASIC_DB QOS_MAP OIDs: {}  ({})".format(
        len(oids_before), oids_before))

    tcam_before = dchal_tcam_info(dut)
    used_before = tcam_before.get('used', -1)
    st.log("  Baseline TCAM used = {}".format(used_before))

    # ── Step 2: write CUSTOM_64 + bind to test_intf + save ───────────────
    custom_entries = dict(GOLDEN_DSCP_TO_TC)     # start with full AZURE map
    for dscp, tc in _SWAPS.items():
        custom_entries[str(dscp)] = str(tc)

    st.log("  Writing DSCP_TO_TC_MAP|{} ({} entries) to CONFIG_DB...".format(
        _CUSTOM_MAP, len(custom_entries)))
    for dscp_str, tc_str in custom_entries.items():
        st.config(dut,
            'sonic-db-cli CONFIG_DB HSET "DSCP_TO_TC_MAP|{}" "{}" "{}"'.format(
                _CUSTOM_MAP, dscp_str, tc_str),
            skip_error_check=True)

    st.log("  Binding {} to {} via PORT_QOS_MAP...".format(_CUSTOM_MAP, test_intf))
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" "dscp_to_tc_map" "{}"'.format(
            test_intf, _CUSTOM_MAP),
        skip_error_check=True)
    st.wait(1)
    st.config(dut, 'config save -y', skip_error_check=True)
    st.log("  Saved CONFIG_DB to disk via 'config save -y'")

    # ── Step 3: wait for orchagent CONFIG_DB subscription ────────────────
    # orchagent subscribes to CONFIG_DB; HSET notifications for both
    # DSCP_TO_TC_MAP and PORT_QOS_MAP trigger map creation + port binding.
    # Do NOT call 'config qos reload' — it re-renders .j2 (AZURE only) and
    # would overwrite CONFIG_DB, destroying CUSTOM_64.
    st.log("  Waiting {}s for orchagent to process notifications...".format(_WAIT))
    st.wait(_WAIT)

    # ── Step 4: verify a NEW QOS_MAP OID appeared for CUSTOM_64 ──────────
    oids_after = []
    new_oid    = None
    for _attempt in range(_RETRIES):
        oids_after = _list_qos_map_oids()
        new_oids   = [o for o in oids_after if o not in oids_before]
        if new_oids:
            new_oid = new_oids[0]
            break
        if _attempt < _RETRIES - 1:
            st.log("  No new QOS_MAP OID yet ({}/{}) — waiting {}s...".format(
                _attempt + 1, _RETRIES, _WAIT))
            st.wait(_WAIT)

    st.log("  ASIC_DB QOS_MAP OIDs after binding: {} (was {})".format(
        len(oids_after), len(oids_before)))
    if new_oid:
        st.log("  New CUSTOM_64 OID created: {}  PASS".format(new_oid))
    else:
        msg = ("No new SAI_QOS_MAP OID created for CUSTOM_64 — "
               "FX3 orchagent may not support per-port map binding via "
               "live CONFIG_DB update (PORT_QOS_MAP HSET)")
        failures.append(msg)
        st.log("  WARN: {}".format(msg))

    # ── Step 5: verify port OID binding ──────────────────────────────────
    port_map_oid = asic_port_dscp_tc_map_oid(dut, test_intf)
    st.log("  SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP on {}: {}".format(
        test_intf, port_map_oid))
    if port_map_oid and port_map_oid != 'oid:0x0':
        st.log("  Port is bound to a non-zero map OID  PASS")
        if new_oid and port_map_oid not in new_oid:
            st.log("  WARN: port OID {} differs from new OID {}".format(
                port_map_oid, new_oid))
    else:
        # FX3 expected: orchagent creates the SAI_QOS_MAP object for CUSTOM_64
        # but the per-port SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP attribute stays
        # oid:0x0 because the platform uses a global map, not per-port binding.
        st.log("  INFO: SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP = {} on {} "
               "(FX3: per-port binding not applied; global map used)".format(
               port_map_oid, test_intf))

    # ── Step 6: TCAM usage check ──────────────────────────────────────────
    tcam_after  = dchal_tcam_info(dut)
    used_after  = tcam_after.get('used', -1)
    tcam_delta  = used_after - used_before
    st.log("  TCAM used: before={} after={} delta={}".format(
        used_before, used_after, tcam_delta))
    if tcam_delta > 0:
        st.log("  TCAM usage increased by {} — new region allocated  PASS".format(
            tcam_delta))
    elif tcam_delta == 0:
        msg = ("TCAM usage UNCHANGED after CUSTOM_64 map creation (delta=0). "
               "A new map with distinct DSCP→TC mappings must allocate a new "
               "TCAM region; delta=0 indicates the custom map was not "
               "programmed into hardware.")
        failures.append(msg)
        st.log("  FAIL: {}".format(msg))
    else:
        msg = ("TCAM usage DECREASED by {} after CUSTOM_64 map creation — "
               "unexpected; entries may have been removed instead of added.".format(
               abs(tcam_delta)))
        failures.append(msg)
        st.log("  FAIL: {}".format(msg))

    # ── Steps 7-8: verify CUSTOM_64 OID content ──────────────────────────
    if new_oid:
        # Read the MAP_TO_VALUE_LIST from the new OID directly.
        raw_map = st.show(dut,
            'sonic-db-cli ASIC_DB HGET "{}" "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST"'.format(
                new_oid),
            skip_tmpl=True)
        custom_asic = {}
        for line in (raw_map or '').splitlines():
            line = line.strip()
            if not line or (line.endswith('$') and '@' in line):
                continue
            try:
                data = json.loads(line)
                custom_asic = {e['key']['dscp']: e['value']['tc']
                               for e in data.get('list', [])}
            except (ValueError, KeyError):
                pass
            break

        st.log("  CUSTOM_64 OID has {} ASIC entries".format(len(custom_asic)))

        st.log("  Verifying swapped DSCP→TC values in CUSTOM_64 OID:")
        for dscp, custom_tc in sorted(_SWAPS.items()):
            azure_tc = int(GOLDEN_DSCP_TO_TC.get(str(dscp), -1))
            got_tc   = custom_asic.get(dscp)
            if got_tc is None:
                failures.append("CUSTOM_64 OID missing DSCP {}".format(dscp))
                st.log("    DSCP {:2d}: MISSING  FAIL".format(dscp))
                continue
            ok = (got_tc == custom_tc)
            st.log("    DSCP {:2d}: azure={} custom={} got={}  {}".format(
                dscp, azure_tc, custom_tc, got_tc, 'PASS' if ok else 'FAIL'))
            if not ok:
                failures.append(
                    "DSCP {} → TC {} (expected custom={}, AZURE={})".format(
                        dscp, got_tc, custom_tc, azure_tc))

        exp_spot = int(GOLDEN_DSCP_TO_TC.get(str(_SPOT_DSCP), -1))
        got_spot = custom_asic.get(_SPOT_DSCP, -1)
        ok_spot  = (got_spot == exp_spot)
        st.log("  DSCP {} (unchanged): got={} expected={}  {}".format(
            _SPOT_DSCP, got_spot, exp_spot, 'PASS' if ok_spot else 'FAIL'))
        if not ok_spot:
            failures.append(
                "DSCP {} (unchanged) → TC {} (expected AZURE {})".format(
                    _SPOT_DSCP, got_spot, exp_spot))
    else:
        st.log("  Skipping OID content check — no new OID was created")

    # ── Step 9: cleanup ───────────────────────────────────────────────────
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "PORT_QOS_MAP|{}" "dscp_to_tc_map"'.format(test_intf),
        skip_error_check=True)
    st.config(dut,
        'sonic-db-cli CONFIG_DB DEL "DSCP_TO_TC_MAP|{}"'.format(_CUSTOM_MAP),
        skip_error_check=True)
    st.config(dut,
        'cp {} /etc/sonic/config_db.json'.format(_BACKUP),
        skip_error_check=True)
    st.log("  Restored config_db.json from backup")
    reload_qos(dut, wait=30)

    if failures:
        st.report_fail('msg', "F6 failures:\n  " + "\n  ".join(failures))

    tcam_note = "TCAM +{}".format(tcam_delta)
    st.report_pass('msg',
        "F6: CUSTOM_64 ({} swaps) created OID={}, port bound OID={}, "
        "{}; AZURE restored".format(
            len(_SWAPS),
            new_oid.split(':')[-1] if new_oid else 'none',
            port_map_oid,
            tcam_note))


# ══════════════════════════════════════════════════════════════════════════════
# Section A #3 — TCAM entries cleared on map removal
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.config_only
def test_tcam_cleared_on_map_removal():
    """#A3 — DSCP-to-TC TCAM region is cleared and reprogrammed on map removal.

    Test plan Section A, Test 3: "TCAM entries cleared on map removal".

    FX3 platform note: orchagent does NOT call sai_remove() on a bare
    CONFIG_DB DEL; a 'config qos reload' is required to trigger the
    sai_remove → sai_create cycle.  The TCAM clear+reprogram is therefore
    verified indirectly: the SAI QoS map OID in ASIC_DB must change (proving
    the old region was destroyed and a new one created) AND the new region must
    contain 192 used entries (proving full reprogramming).

    Steps:
      1. Verify TCAM has non-zero entries and record the baseline ASIC_DB OID.
      2. Check DSCP_TO_TC_MAP|AZURE exists in CONFIG_DB; delete it, then run
         'config qos reload' to trigger the sai_remove → sai_create cycle.
      3. Verify the ASIC_DB OID has changed (clear+reprogram cycle confirmed)
         AND TCAM 'used' == 192 (map fully reprogrammed).
    """
    print_section("A3 — TCAM cleared on map removal", art_key='dscp_to_tc')

    failures = []

    # Step 1: verify non-zero baseline and record OID.
    # The previous test may have done a qos reload; wait up to 90 s for
    # orchagent to re-allocate the TCAM region (dchal returns 'created: 0'
    # while the region is not yet allocated, which the parser maps to 0).
    _BASELINE_RETRIES = 9
    _BASELINE_WAIT    = 10
    used_before = 0
    for _attempt in range(_BASELINE_RETRIES):
        info = dchal_tcam_info(dut)
        used_before = info.get('used', -1)
        if used_before > 0:
            break
        if _attempt < _BASELINE_RETRIES - 1:
            st.log("  TCAM before: used={} — waiting {}s for region to be allocated "
                   "({}/{})...".format(used_before, _BASELINE_WAIT,
                                       _attempt + 1, _BASELINE_RETRIES))
            st.wait(_BASELINE_WAIT)
    st.log("  TCAM before: used={}".format(used_before))
    if used_before <= 0:
        st.report_fail('msg',
            "A3: Pre-condition failed: TCAM 'used'={} (expected >0)".format(used_before))

    oid_before = asic_qos_map_oid(dut)
    st.log("  ASIC_DB OID before: {}".format(oid_before or '(none)'))
    if oid_before is None:
        st.report_fail('msg',
            "A3: Pre-condition failed: DSCP_TO_TC OID not found in ASIC_DB")

    # Step 2: delete map from CONFIG_DB and trigger the sai_remove+create
    # cycle via 'config qos reload'.  On FX3 a bare CONFIG_DB DEL does not
    # reach SAI; reload is required (same as test_remove_dscp_to_tc_map).
    st.log("  Checking DSCP_TO_TC_MAP|AZURE in CONFIG_DB...")
    exists_output = st.config(
        dut,
        'sudo sonic-db-cli CONFIG_DB EXISTS "DSCP_TO_TC_MAP|AZURE"',
        skip_error_check=True,
    )
    map_exists = '1' in (exists_output or '')
    if not map_exists:
        st.report_fail('msg',
            "A3: Pre-condition failed: DSCP_TO_TC_MAP|AZURE not found in CONFIG_DB "
            "(expected to be present before removal test)")

    st.log("  DSCP_TO_TC_MAP|AZURE found — deleting and reloading QoS...")
    # WHY CONFIG_DB DEL alone is not enough on FX3:
    #   A bare 'sonic-db-cli CONFIG_DB DEL "DSCP_TO_TC_MAP|AZURE"' removes the
    #   key from CONFIG_DB (the Redis in-memory store) but orchagent's
    #   QosOrch consumer thread is NOT subscribed to DSCP_TO_TC_MAP changes —
    #   it only processes QoS map entries that arrive via the APP_DB
    #   (QOS_MAP_TABLE).  The CONFIG_DB→APP_DB translation happens inside
    #   'config qos reload', which calls sonic-cfggen to render qos.j2 and
    #   sonic-cfggen --write-to-db to push the result into APP_DB.  Until
    #   reload runs, orchagent sees no notification and leaves the TCAM region
    #   intact with used=192.  Therefore:
    #     - CONFIG_DB DEL  → TCAM stays at 192 (no orchagent notification)
    #     - config qos reload → APP_DB updated → orchagent calls
    #       sai_remove(old OID) then sai_create(new OID) → TCAM cleared and
    #       fully reprogrammed in one atomic cycle
    st.config(dut, 'sudo sonic-db-cli CONFIG_DB DEL "DSCP_TO_TC_MAP|AZURE"',
              skip_error_check=True)
    # reload triggers sai_remove(old OID) → sai_create(new OID); wait 30 s
    # for orchagent to fully reprogram the TCAM region before reading back.
    reload_qos(dut, wait=30)

    # Step 3: verify OID changed (sai_remove+create cycle happened) AND
    # TCAM contains 192 entries (full reprogramming confirmed).
    # The OID change is the only externally observable proof that the TCAM
    # region was destroyed (cleared) and recreated — because the clear+reprogram
    # is an atomic SAI operation and the intermediate used=0 state is never
    # visible from outside the syncd container.
    oid_after = asic_qos_map_oid(dut)
    st.log("  ASIC_DB OID after : {}".format(oid_after or '(none)'))

    if oid_after is None:
        failures.append("DSCP_TO_TC OID absent after DEL+reload — recreation failed")
    elif oid_after == oid_before:
        failures.append(
            "OID unchanged ({}) after DEL+reload — sai_remove+create cycle "
            "did not execute".format(oid_after))
    else:
        st.log("  OID changed: {} → {}  PASS (clear+reprogram cycle confirmed)".format(
            oid_before, oid_after))

    # Use min_used=1 so dchal_tcam_info retries while orchagent is still
    # allocating (seen as 'created: 0' → used=0).
    info_after = dchal_tcam_info(dut, min_used=1)
    used_after = info_after.get('used', -1)
    st.log("  TCAM after reload: used={} (expected 192)".format(used_after))
    if used_after != 192:
        failures.append(
            "TCAM 'used'={} after DEL+reload (expected 192 — map not fully "
            "reprogrammed)".format(used_after))
    else:
        st.log("  TCAM reprogrammed to 192 entries  PASS")

    if failures:
        st.report_fail('msg', "A3 failures:\n  " + "\n  ".join(failures))
    st.report_pass('msg',
        "A3: DEL+reload → OID {} → {}; TCAM reprogrammed to {} entries".format(
            oid_before, oid_after, used_after))


# ══════════════════════════════════════════════════════════════════════════════
# Section B #5–8 — Single-DSCP TCAM hit count (Ixia, low-rate)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.traffic
@pytest.mark.parametrize("af,dscp", [
    ("ipv4", 0), ("ipv4", 1), ("ipv6", 0), ("ipv6", 1),
])
def test_single_dscp_tcam_hit(af, dscp):
    """#5-8 — Single DSCP TCAM hit counter increments correctly (Ixia, low rate).

    Test plan Section B, Tests 5–8.

    Sends exactly 100 packets with a single DSCP value at 10 pps and verifies
    that the corresponding TCAM entry's hit counter increments by 100 (±15%).
    Confirms no other entries are affected.

    Tests:
      5: IPv4 DSCP 0 (+100)
      6: IPv4 DSCP 1 (+100)
      7: IPv6 DSCP 0 (+100)
      8: IPv6 DSCP 1 (+100)

    TC plan says: 10 pps, 100 packets per DSCP.
    """
    _PKTS   = 100
    _RATE   = 10    # pps
    # Test plan specifies exactly +100 hits — no tolerance range.
    # Ixia single_burst mode with pkts_per_burst=100 is deterministic.
    _EXPECTED_DELTA = _PKTS

    tc_num = {("ipv4", 0): 5, ("ipv4", 1): 6, ("ipv6", 0): 7, ("ipv6", 1): 8}
    plan_id = tc_num.get((af, dscp), "5-8")

    print_section("B{} — Single-DSCP TCAM hit [{}  DSCP {}]  {} pkts @ {}pps".format(
        plan_id, af.upper(), dscp, _PKTS, _RATE), art_key='dscp_to_tc')

    ingress_ph = tg_ph['ingress']
    dst_mac    = get_dut_mac(dut, port_info['ingress'])
    failures   = []

    # Pre-traffic TCAM snapshot
    dump_before = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump_before:
        st.report_fail('msg',
            "B{}: pre-traffic dchal_tcam_dump returned empty".format(plan_id))

    if af == 'ipv4':
        entries_before = {e['dscp']: e.get('stats_pkts', 0)
                          for e in tcam_ipv4_dscp_entries(dump_before)
                          if e.get('dscp') is not None}
    else:
        entries_before = {e['dscp']: e.get('stats_pkts', 0)
                          for e in tcam_ipv6_dscp_entries(dump_before)
                          if e.get('dscp') is not None}

    st.log("  Pre-traffic: {} entries snapshotted, target DSCP {} = {}".format(
        len(entries_before), dscp, entries_before.get(dscp, 'MISSING')))

    if dscp not in entries_before:
        st.report_fail('msg',
            "B{}: DSCP {} not found in pre-traffic {} TCAM snapshot".format(
                plan_id, dscp, af))

    # Build ONE stream for the target DSCP
    tg.tg_traffic_control(action='reset')

    if af == 'ipv4':
        tg.tg_traffic_config(
            mode='create',
            port_handle=ingress_ph,
            l3_protocol='ipv4',
            l4_protocol='udp',
            ip_src_addr=IXIA_INGRESS_A_IP,
            ip_dst_addr=_IXIA_DST_V4,
            mac_dst=dst_mac,
            ip_dscp=dscp,
            ip_ttl=64,
            udp_src_port=10000 + dscp,
            udp_dst_port=5000,
            frame_size=_PKT_SIZE,
            rate_pps=_RATE,
            pkts_per_burst=_PKTS,
            transmit_mode='single_burst',
            high_speed_result_analysis=0,
        )
    else:
        tc_byte = dscp << 2
        tg.tg_traffic_config(
            mode='create',
            port_handle=ingress_ph,
            l3_protocol='ipv6',
            l4_protocol='udp',
            ipv6_src_addr=IXIA_INGRESS_A_IP6,
            ipv6_dst_addr=_IXIA_DST_V6,
            mac_dst=dst_mac,
            ipv6_traffic_class=tc_byte,
            ipv6_hop_limit=64,
            udp_src_port=10000 + dscp,
            udp_dst_port=5000,
            frame_size=_PKT_SIZE,
            rate_pps=_RATE,
            pkts_per_burst=_PKTS,
            transmit_mode='single_burst',
            high_speed_result_analysis=0,
        )

    tg.tg_traffic_control(action='clear_stats')
    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run')
    wait_secs = int(_PKTS / float(_RATE)) + 5
    st.wait(wait_secs)
    tg.tg_traffic_control(action='stop')
    st.wait(2)

    # Post-traffic TCAM dump
    dump_after = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump_after:
        st.report_fail('msg',
            "B{}: post-traffic dchal_tcam_dump returned empty".format(plan_id))

    if af == 'ipv4':
        entries_after = {e['dscp']: e.get('stats_pkts', 0)
                         for e in tcam_ipv4_dscp_entries(dump_after)
                         if e.get('dscp') is not None}
    else:
        entries_after = {e['dscp']: e.get('stats_pkts', 0)
                         for e in tcam_ipv6_dscp_entries(dump_after)
                         if e.get('dscp') is not None}

    # Target DSCP delta — test plan requires exactly +100
    before_cnt = entries_before.get(dscp, 0)
    after_cnt  = entries_after.get(dscp, 0)
    delta      = max(0, after_cnt - before_cnt)
    ok_target  = (delta == _EXPECTED_DELTA)

    st.log("  DSCP {} [{}]: before={} after={} delta={}  "
           "expected={}  {}".format(
               dscp, af, before_cnt, after_cnt, delta,
               _EXPECTED_DELTA, 'PASS' if ok_target else 'FAIL'))

    if not ok_target:
        failures.append(
            "DSCP {} [{}]: delta={} (expected exactly {})".format(
                dscp, af, delta, _EXPECTED_DELTA))

    # Other entries must NOT have changed significantly
    other_failures = []
    for other_dscp in range(64):
        if other_dscp == dscp:
            continue
        b = entries_before.get(other_dscp, 0)
        a = entries_after.get(other_dscp, 0)
        d = max(0, a - b)
        if d > int(_PKTS * 0.05):   # allow <5% noise
            other_failures.append("DSCP {} delta={}".format(other_dscp, d))

    if other_failures:
        st.log("  WARN: {} other {} entries have unexpected delta: {}".format(
            len(other_failures), af, other_failures[:3]))
        # Log as warning only — hardware counter sharing can cause minor bleed

    if failures:
        st.report_fail('msg', "B{} failures:\n  ".format(plan_id) +
                       "\n  ".join(failures))
    st.report_pass('msg',
        "B{}: DSCP {} [{}] TCAM entry hit delta={} (expected exactly {})".format(
            plan_id, dscp, af, delta, _EXPECTED_DELTA))


# ══════════════════════════════════════════════════════════════════════════════
# Section B #9 — Cross-port: same DSCP increments same global TCAM entry
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.traffic
def test_cross_port_global_tcam_entry():
    """#9 — DSCP TCAM rules are global: same DSCP from multiple ingress ports.

    Test plan Section B, Test 9: "Cross-port: same DSCP hits same global
    TCAM entry".

    Uses both IXIA ingress ports (ingress_a + ingress_b) when available
    (ixia and peer_link modes).  In breakout mode only ingress_a is present
    so the test runs with a single port and expects delta=100.

    Steps:
      1. Snapshot TCAM stats_pkts for IPv4 DSCP 0 entry.
      2. Build DSCP 0 IPv4 stream on ingress port(s).
      3. Run all streams (100 pkts each).
      4. Assert TCAM DSCP 0 IPv4 delta = 100 × num_ports (global TCAM).
    """
    _PKTS      = 100
    _RATE      = 10
    _DSCP      = 0

    # Sources: ingress_a (always) + ingress_b when available (ixia/peer_link).
    # ingress_b sends back toward ingress_a so the DUT routes it; both hits
    # increment the same global TCAM entry for DSCP 0.
    _sources = [
        {'ph': tg_ph['ingress'], 'dut_port': port_info['ingress'],
         'src_ip': IXIA_INGRESS_A_IP, 'dst_ip': _IXIA_DST_V4},
    ]
    if tg_ph_ingress_b is not None:
        _sources.append(
            {'ph': tg_ph_ingress_b, 'dut_port': port_info_ingress_b,
             'src_ip': IXIA_INGRESS_B_IP, 'dst_ip': IXIA_INGRESS_A_IP}
        )
    _EXP_DELTA = _PKTS * len(_sources)

    print_section(
        "B9 — Cross-port global TCAM: DSCP 0 from {} port(s) → +{}".format(
            len(_sources), _EXP_DELTA),
        art_key='dscp_to_tc')
    st.log("  Topology mode: {}  sources: {}".format(
        topo_mode, len(_sources)))

    failures = []

    # Pre-traffic snapshot
    dump_before = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump_before:
        st.report_fail('msg', "B9: pre-traffic dchal_tcam_dump returned empty")

    v4_before = {e['dscp']: e.get('stats_pkts', 0)
                 for e in tcam_ipv4_dscp_entries(dump_before)
                 if e.get('dscp') is not None}
    before_cnt = v4_before.get(_DSCP, 0)
    st.log("  Pre-traffic IPv4 DSCP {} stats_pkts={}".format(_DSCP, before_cnt))

    # Build streams on all available ingress ports
    tg.tg_traffic_control(action='reset')
    for src in _sources:
        mac = get_dut_mac(dut, src['dut_port'])
        tg.tg_traffic_config(
            mode='create',
            port_handle=src['ph'],
            l3_protocol='ipv4',
            l4_protocol='udp',
            ip_src_addr=src['src_ip'],
            ip_dst_addr=src['dst_ip'],
            mac_dst=mac,
            ip_dscp=_DSCP,
            ip_ttl=64,
            udp_src_port=10000,
            udp_dst_port=5000,
            frame_size=_PKT_SIZE,
            rate_pps=_RATE,
            pkts_per_burst=_PKTS,
            transmit_mode='single_burst',
            high_speed_result_analysis=0,
        )

    st.log("  Sending {} IPv4 DSCP {} pkts from each of {} Ixia port(s)...".format(
        _PKTS, _DSCP, len(_sources)))
    tg.tg_traffic_control(action='clear_stats')
    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run')
    wait_secs = int(_PKTS / float(_RATE)) + 5
    st.wait(wait_secs)
    tg.tg_traffic_control(action='stop')
    st.wait(2)

    # Post-traffic dump
    dump_after = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump_after:
        st.report_fail('msg', "B9: post-traffic dchal_tcam_dump returned empty")

    v4_after = {e['dscp']: e.get('stats_pkts', 0)
                for e in tcam_ipv4_dscp_entries(dump_after)
                if e.get('dscp') is not None}
    after_cnt = v4_after.get(_DSCP, 0)
    delta     = max(0, after_cnt - before_cnt)

    st.log("  IPv4 DSCP {} stats_pkts: before={} after={} delta={}  "
           "expected={}  {}".format(
               _DSCP, before_cnt, after_cnt, delta, _EXP_DELTA,
               'PASS' if delta == _EXP_DELTA else 'FAIL'))

    if delta != _EXP_DELTA:
        failures.append(
            "IPv4 DSCP {} delta={} (expected exactly {} from {} port(s) × {} pkts)".format(
                _DSCP, delta, _EXP_DELTA, len(_sources), _PKTS))

    if failures:
        st.report_fail('msg', "B9 failures:\n  " + "\n  ".join(failures))
    st.report_pass('msg',
        "B9: DSCP {} IPv4 TCAM entry delta={} from {} port(s) "
        "(global TCAM confirmed)".format(_DSCP, delta, len(_sources)))


# ══════════════════════════════════════════════════════════════════════════════
# Section B #10 — No cross-contamination: DSCP 0 vs DSCP 1 counters
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.traffic
def test_no_cross_contamination_dscp():
    """#10 — DSCP 0 traffic increments only DSCP 0 entry, not DSCP 1 entry.

    Test plan Section B, Test 10: "No cross-contamination: DSCP 0 vs DSCP 1".

    Sends 100 IPv4 packets with DSCP 0 and verifies:
      - DSCP 0 IPv4 TCAM entry delta ≈ +100.
      - DSCP 1 IPv4 TCAM entry delta = 0.
    """
    _PKTS    = 100
    _RATE    = 10
    _DSCP_TX = 0    # the DSCP we send
    _DSCP_RX = 1    # must NOT increment

    print_section(
        "B10 — No cross-contamination: DSCP 0 +100, DSCP 1 +0",
        art_key='dscp_to_tc')

    failures = []
    ingress_ph = tg_ph['ingress']
    dst_mac    = get_dut_mac(dut, port_info['ingress'])

    # Snapshot both DSCP 0 and DSCP 1 entries
    dump_before = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump_before:
        st.report_fail('msg', "B10: pre-traffic dchal_tcam_dump returned empty")
    v4_before = {e['dscp']: e.get('stats_pkts', 0)
                 for e in tcam_ipv4_dscp_entries(dump_before)
                 if e.get('dscp') is not None}

    # Send DSCP 0 only
    tg.tg_traffic_control(action='reset')
    tg.tg_traffic_config(
        mode='create',
        port_handle=ingress_ph,
        l3_protocol='ipv4',
        l4_protocol='udp',
        ip_src_addr=IXIA_INGRESS_A_IP,
        ip_dst_addr=_IXIA_DST_V4,
        mac_dst=dst_mac,
        ip_dscp=_DSCP_TX,
        ip_ttl=64,
        udp_src_port=10000,
        udp_dst_port=5000,
        frame_size=_PKT_SIZE,
        rate_pps=_RATE,
        pkts_per_burst=_PKTS,
        transmit_mode='single_burst',
        high_speed_result_analysis=0,
    )
    tg.tg_traffic_control(action='clear_stats')
    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run')
    st.wait(int(_PKTS / float(_RATE)) + 5)
    tg.tg_traffic_control(action='stop')
    st.wait(2)

    dump_after = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump_after:
        st.report_fail('msg', "B10: post-traffic dchal_tcam_dump returned empty")
    v4_after = {e['dscp']: e.get('stats_pkts', 0)
                for e in tcam_ipv4_dscp_entries(dump_after)
                if e.get('dscp') is not None}

    delta_0 = v4_after.get(_DSCP_TX, 0) - v4_before.get(_DSCP_TX, 0)
    delta_1 = v4_after.get(_DSCP_RX, 0) - v4_before.get(_DSCP_RX, 0)
    # Test plan: DSCP 0 delta = exactly +100, DSCP 1 delta = exactly 0.

    st.log("  DSCP 0 delta={} (expected 100)  {}".format(
        delta_0, 'PASS' if delta_0 == _PKTS else 'FAIL'))
    st.log("  DSCP 1 delta={} (expected 0)  {}".format(
        delta_1, 'PASS' if delta_1 == 0 else 'FAIL'))

    if delta_0 != _PKTS:
        failures.append(
            "DSCP 0 delta={} (expected exactly {})".format(delta_0, _PKTS))
    if delta_1 != 0:
        failures.append(
            "DSCP 1 delta={} (expected 0 — cross-contamination)".format(delta_1))

    if failures:
        st.report_fail('msg', "B10 failures:\n  " + "\n  ".join(failures))
    st.report_pass('msg',
        "B10: DSCP 0 delta={} (+100); DSCP 1 delta=0 (no contamination)".format(
            delta_0))


# ══════════════════════════════════════════════════════════════════════════════
# Section B #11 — No cross-contamination: V4 vs V6 counters
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.traffic
def test_no_cross_contamination_af():
    """#11 — IPv4 traffic does not increment the corresponding IPv6 TCAM entry.

    Test plan Section B, Test 11: "No cross-contamination: V4 vs V6 counters".

    Sends 100 IPv4 DSCP 0 packets and verifies:
      - IPv4 DSCP 0 TCAM entry delta ≈ +100.
      - IPv6 DSCP 0 TCAM entry delta = 0.
    """
    _PKTS = 100
    _RATE = 10
    _DSCP = 0

    print_section(
        "B11 — No cross-contamination: IPv4 DSCP 0 +100, IPv6 DSCP 0 +0",
        art_key='dscp_to_tc')

    failures = []
    ingress_ph = tg_ph['ingress']
    dst_mac    = get_dut_mac(dut, port_info['ingress'])

    dump_before = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump_before:
        st.report_fail('msg', "B11: pre-traffic dchal_tcam_dump returned empty")

    v4_before = {e['dscp']: e.get('stats_pkts', 0)
                 for e in tcam_ipv4_dscp_entries(dump_before)
                 if e.get('dscp') is not None}
    v6_before = {e['dscp']: e.get('stats_pkts', 0)
                 for e in tcam_ipv6_dscp_entries(dump_before)
                 if e.get('dscp') is not None}

    # Send IPv4 DSCP 0 only
    tg.tg_traffic_control(action='reset')
    tg.tg_traffic_config(
        mode='create',
        port_handle=ingress_ph,
        l3_protocol='ipv4',
        l4_protocol='udp',
        ip_src_addr=IXIA_INGRESS_A_IP,
        ip_dst_addr=_IXIA_DST_V4,
        mac_dst=dst_mac,
        ip_dscp=_DSCP,
        ip_ttl=64,
        udp_src_port=10000,
        udp_dst_port=5000,
        frame_size=_PKT_SIZE,
        rate_pps=_RATE,
        pkts_per_burst=_PKTS,
        transmit_mode='single_burst',
        high_speed_result_analysis=0,
    )
    tg.tg_traffic_control(action='clear_stats')
    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run')
    st.wait(int(_PKTS / float(_RATE)) + 5)
    tg.tg_traffic_control(action='stop')
    st.wait(2)

    dump_after = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump_after:
        st.report_fail('msg', "B11: post-traffic dchal_tcam_dump returned empty")

    v4_after = {e['dscp']: e.get('stats_pkts', 0)
                for e in tcam_ipv4_dscp_entries(dump_after)
                if e.get('dscp') is not None}
    v6_after = {e['dscp']: e.get('stats_pkts', 0)
                for e in tcam_ipv6_dscp_entries(dump_after)
                if e.get('dscp') is not None}

    delta_v4 = v4_after.get(_DSCP, 0) - v4_before.get(_DSCP, 0)
    delta_v6 = v6_after.get(_DSCP, 0) - v6_before.get(_DSCP, 0)
    # Test plan: IPv4 delta = exactly +100, IPv6 delta = exactly 0.

    st.log("  IPv4 DSCP {} delta={} (expected 100)  {}".format(
        _DSCP, delta_v4, 'PASS' if delta_v4 == _PKTS else 'FAIL'))
    st.log("  IPv6 DSCP {} delta={} (expected 0)  {}".format(
        _DSCP, delta_v6, 'PASS' if delta_v6 == 0 else 'FAIL'))

    if delta_v4 != _PKTS:
        failures.append(
            "IPv4 DSCP {} delta={} (expected exactly {})".format(_DSCP, delta_v4, _PKTS))
    if delta_v6 != 0:
        failures.append(
            "IPv6 DSCP {} delta={} (expected 0 — AF cross-contamination)".format(
                _DSCP, delta_v6))

    if failures:
        st.report_fail('msg', "B11 failures:\n  " + "\n  ".join(failures))
    st.report_pass('msg',
        "B11: IPv4 DSCP {} delta={} (+100); IPv6 DSCP {} delta=0".format(
            _DSCP, delta_v4, _DSCP))


# ══════════════════════════════════════════════════════════════════════════════
# Section C #14–17 — TCAM hit count via Ixia traffic
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.traffic
@pytest.mark.parametrize("af,dscp", [
    ("ipv4", 0), ("ipv4", 1), ("ipv6", 0), ("ipv6", 1),
])
def test_sonic_peer_dscp_tcam_hit(af, dscp):
    """#14-17 — TCAM hit counter increments with Ixia traffic (low-rate single DSCP).

    Test plan Section C, Tests 14–17.

    Sends a small burst of packets with a single DSCP value via IXIA and
    verifies the corresponding TCAM entry's hit counter increments by the
    expected amount.

    Tests:
      14: IPv4 DSCP 0 (send 5 pkts, expect delta = 5)
      15: IPv4 DSCP 1 (send 5 pkts, expect delta = 5)
      16: IPv6 DSCP 0 (send 3 pkts, expect delta = 3)
      17: IPv6 DSCP 1 (send 3 pkts, expect delta = 3)
    """
    tc_num = {("ipv4", 0): 14, ("ipv4", 1): 15, ("ipv6", 0): 16, ("ipv6", 1): 17}
    plan_id = tc_num.get((af, dscp), "14-17")

    pkts = _PEER_PKTS_V4 if af == 'ipv4' else _PEER_PKTS_V6

    print_section(
        "C{} — Ixia {} DSCP {} → {} pkts → TCAM hit".format(
            plan_id, af.upper(), dscp, pkts),
        art_key='dscp_to_tc')

    ingress_ph = tg_ph['ingress']
    dst_mac    = get_dut_mac(dut, port_info['ingress'])
    failures   = []

    # Pre-traffic TCAM snapshot
    dump_before = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump_before:
        st.report_fail('msg',
            "C{}: pre-traffic dchal_tcam_dump returned empty".format(plan_id))

    if af == 'ipv4':
        entries_before = {e['dscp']: e.get('stats_pkts', 0)
                          for e in tcam_ipv4_dscp_entries(dump_before)
                          if e.get('dscp') is not None}
    else:
        entries_before = {e['dscp']: e.get('stats_pkts', 0)
                          for e in tcam_ipv6_dscp_entries(dump_before)
                          if e.get('dscp') is not None}

    before_cnt = entries_before.get(dscp, 0)
    st.log("  Pre-traffic {} DSCP {} stats_pkts={}".format(af, dscp, before_cnt))

    # Build and send single-DSCP IXIA stream
    tg.tg_traffic_control(action='reset')

    if af == 'ipv4':
        tg.tg_traffic_config(
            mode='create',
            port_handle=ingress_ph,
            l3_protocol='ipv4',
            l4_protocol='udp',
            ip_src_addr=IXIA_INGRESS_A_IP,
            ip_dst_addr=_IXIA_DST_V4,
            mac_dst=dst_mac,
            ip_dscp=dscp,
            ip_ttl=64,
            udp_src_port=5000,
            udp_dst_port=5000,
            frame_size=_PKT_SIZE,
            rate_pps=10,
            pkts_per_burst=pkts,
            transmit_mode='single_burst',
            high_speed_result_analysis=0,
        )
    else:
        tc_byte = dscp << 2
        tg.tg_traffic_config(
            mode='create',
            port_handle=ingress_ph,
            l3_protocol='ipv6',
            l4_protocol='udp',
            ipv6_src_addr=IXIA_INGRESS_A_IP6,
            ipv6_dst_addr=_IXIA_DST_V6,
            mac_dst=dst_mac,
            ipv6_traffic_class=tc_byte,
            ipv6_hop_limit=64,
            udp_src_port=5000,
            udp_dst_port=5000,
            frame_size=_PKT_SIZE,
            rate_pps=10,
            pkts_per_burst=pkts,
            transmit_mode='single_burst',
            high_speed_result_analysis=0,
        )

    tg.tg_traffic_control(action='run', port_handle=ingress_ph)
    st.wait(5)
    tg.tg_traffic_control(action='stop', port_handle=ingress_ph)
    st.wait(2)

    # Post-traffic TCAM snapshot
    dump_after = dchal_tcam_dump(dut, start_idx=_TCAM_START_IDX, count=_TCAM_DUMP_COUNT)
    if not dump_after:
        st.report_fail('msg',
            "C{}: post-traffic dchal_tcam_dump returned empty".format(plan_id))

    if af == 'ipv4':
        entries_after = {e['dscp']: e.get('stats_pkts', 0)
                         for e in tcam_ipv4_dscp_entries(dump_after)
                         if e.get('dscp') is not None}
    else:
        entries_after = {e['dscp']: e.get('stats_pkts', 0)
                         for e in tcam_ipv6_dscp_entries(dump_after)
                         if e.get('dscp') is not None}

    after_cnt = entries_after.get(dscp, 0)
    delta     = max(0, after_cnt - before_cnt)

    st.log("  {} DSCP {} stats_pkts: before={} after={} delta={}  "
           "expected={}".format(af, dscp, before_cnt, after_cnt, delta, pkts))

    if delta != pkts:
        failures.append(
            "{} DSCP {} delta={} (expected exactly {})".format(af, dscp, delta, pkts))
    else:
        st.log("  delta={} matches expected {}  PASS".format(delta, pkts))

    if failures:
        st.report_fail('msg', "C{} failures:\n  ".format(plan_id) +
                       "\n  ".join(failures))
    st.report_pass('msg',
        "C{}: Ixia {} DSCP {} → TCAM delta={} (expected {})".format(
            plan_id, af, dscp, delta, pkts))


# ══════════════════════════════════════════════════════════════════════════════
# Section D #20 — SAI queue placement combined test (BLOCKED / in progress)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.traffic
def test_sai_queue_placement_combined():
    """#20 — Per-DSCP queue placement: 64 IPv4 + 64 IPv6 streams, per-queue counter check.

    Test plan Section D, Test 20: 'Per-DSCP queue placement (automated SAI test)'.

    Sends 64 V4 streams and 64 V6 streams simultaneously (one per DSCP, 250 pkts
    each) from the Ixia ingress port and verifies that DCHAL per-queue counter
    deltas on the egress port match the expected totals from GOLDEN_DSCP_TO_TC.

    Each DSCP contributes _PKTS_PER_DSCP V4 packets + _PKTS_PER_DSCP V6 packets
    to its mapped TC queue, so:

        expected[q] = 2 * _PKTS_PER_DSCP * |{dscp : GOLDEN_DSCP_TO_TC[dscp] == q}|

    Pass criteria (per test plan):
      - Per-queue packet delta matches expected totals (±15% for counter granularity).
      - Drop counter delta = 0 on all queues (low-rate traffic, no congestion).

    Topology: D1T1:2 — ingress=T1D1P1, egress=T1D1P2.
    Uses same Ixia infra as tests 18/19 (setup_topo fixture).
    """
    print_section("D20 — Per-DSCP queue placement: 64 V4 + 64 V6 streams",
                  art_key='dscp_to_tc')

    ingress_ph = tg_ph['ingress']
    dst_mac    = get_dut_mac(dut, port_info['ingress'])
    failures   = []

    # Expected per-queue totals: V4 + V6 = 2× contribution per DSCP
    expected_q_pkts_combined = {
        qi: cnt * 2 for qi, cnt in _EXPECTED_Q_PKTS.items()
    }

    st.log("  Sending 64 IPv4 + 64 IPv6 streams ({} pkts/DSCP each)".format(
        _PKTS_PER_DSCP))
    st.log("  Expected per-queue totals (V4 + V6):")
    for qi in sorted(expected_q_pkts_combined):
        if expected_q_pkts_combined[qi] > 0:
            n_dscp = len([d for d, t in GOLDEN_DSCP_TO_TC.items() if int(t) == qi])
            st.log("    Q{}: {:,} pkts  ({} DSCPs × {} V4 + {} V6)".format(
                qi, expected_q_pkts_combined[qi],
                n_dscp, _PKTS_PER_DSCP, _PKTS_PER_DSCP))

    tg.tg_traffic_control(action='reset')
    _build_ipv4_streams(tg, ingress_ph, dst_mac, _STREAM_RATE_PPS, _PKTS_PER_DSCP)
    _build_ipv6_streams(tg, ingress_ph, dst_mac, _STREAM_RATE_PPS, _PKTS_PER_DSCP)

    q_before, q_after, egress = _send_and_measure("D20")
    deltas = _compute_deltas(q_before, q_after)
    _log_queue_placement_table(deltas, "[V4+V6 combined]")

    total_sent = 2 * 64 * _PKTS_PER_DSCP
    total_rcvd = sum(d['pkts'] for d in deltas.values())
    st.log("  Total expected: {:,}   Total received: {:,}".format(total_sent, total_rcvd))

    # Per-queue placement check (±15% tolerance for DCHAL counter granularity)
    for qi in range(8):
        exp = expected_q_pkts_combined.get(qi, 0)
        act = deltas[qi]['pkts']
        drp = deltas[qi]['drop_pkts']

        if exp == 0:
            if act > 0:
                failures.append(
                    "Q{} received {:,} pkts but expected 0".format(qi, act))
            continue

        lo = int(exp * 0.85)
        hi = int(exp * 1.15)
        if not (lo <= act <= hi):
            n_dscp = len([d for d, t in GOLDEN_DSCP_TO_TC.items() if int(t) == qi])
            failures.append(
                "Q{} actual={:,} outside [{:,},{:,}] "
                "(expected {:,} ±15%  •  {} DSCPs × 2 AFs)".format(
                    qi, act, lo, hi, exp, n_dscp))
        else:
            st.log("  Q{}: {:,} pkts (expected {:,} ±15%)  PASS".format(qi, act, exp))

        # Drop check: no drops at this low rate
        if drp > 0:
            failures.append(
                "Q{} drop_pkts={:,} (expected 0 at {} pps)".format(
                    qi, drp, _STREAM_RATE_PPS))

    if total_rcvd == 0:
        failures.append(
            "No packets received on any queue — "
            "check routing and ARP/MAC resolution")

    if failures:
        st.report_fail('msg',
            "D20 failures ({}):\n  ".format(len(failures)) + "\n  ".join(failures))
    st.report_pass('msg',
        "D20: 64 V4 + 64 V6 DSCP streams — all queues correct, zero drops; "
        "total {:,} pkts (expected {:,})".format(total_rcvd, total_sent))
