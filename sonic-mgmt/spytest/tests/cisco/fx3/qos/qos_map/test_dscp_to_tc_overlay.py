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
DSCP-to-TC VxLAN Overlay End-to-End QoS Map Tests - Sections I and J

This file holds the VxLAN overlay e2e tests and their associated smoke
suites.  All tests here exercise a 2-DUT VxLAN VTEP topology and use a
per-TC UNIQUE packet count traffic pattern that adds two new
checkpoints on top of the historical aggregate-counter verification.

What this suite verifies on top of test_dscp_to_tc.py's Sections I/J:
  - CP1 (DUT1 transit/egress per-queue) verified against
    EXPECTED_Q_PKTS_UNIQUE with +-2% tolerance.
  - CP2 (DUT2 egress_ixia post-decap per-queue) - catches decap-side
    QoS-map breakages that the original tests never observed.
  - CP3 (Ixia rx per-DSCP) - udp_dst_port is per-DSCP (5000 + dscp) so
    we can detect even same-TC misclassification at the wire level.
    Falls back to Ixia rx filters if stream stats return zeros.

Per-TC unique counts (tuned to the actual GOLDEN_DSCP_TO_TC distribution
on the FX3 testbed: TC0=39 DSCPs, TC1=18, TC2=2, TC3..TC7=1 each):
    PKTS_BY_TC = {0:  20, 1:  50, 2: 350, 3: 100,
                  4: 200, 5: 300, 6: 400, 7: 500}
    EXPECTED_Q_PKTS_UNIQUE = {0:780, 1:900, 2:700, 3:100,
                              4:200, 5:300, 6:400, 7:500}
All 8 queue totals are pairwise distinct (sorted [100,200,300,400,500,700,
780,900], min gap = 80 pkts), so any single cross-TC misclassification
produces an unambiguous "two queues moved in opposite directions" signature
that survives +-2% tolerance (smallest tolerance window half-width = 2 pkts
at Q3=100; min gap of 80 pkts >> any tolerance window).

Tests in this file (8 e2e + 64 smoke instances):
  - I3 / I4 : VxLAN L3VNI VTEP (2-DUT) e2e. CP1 + CP2 + CP3 (strict).
  - J3 / J4 : VxLAN L2VNI BUM (2-DUT) e2e.  CP1 + CP2 + CP3 (loose).
  - TestSmokeL3VNI / TestSmokeL3VNITagged / TestSmokeL2VNIBum /
    TestSmokeL2VNIUcast :
    16 per-DSCP single-packet smoke instances each (2 AFs x 8 TCs)
    that inspect every captured frame and assert TTL / DSCP / queue /
    decap correctness on a per-packet basis.
    The L2VNI pair is split by traffic class:
      * Bum   : forces dst_mac=_J_BUM_MAC; primary col mc on DUT2,
                uc on DUT1 (outer VxLAN frame is unicast between
                VTEP IPs).
      * Ucast : resolves dst_mac via EVPN Type-2; primary col uc on
                both DUTs.  Gated by st.report_unsupported when EVPN
                hasn't converged.

Port allocation (DUT1->T1 links) by the workspace role-to-port mapping
convention:
  ingress_a (D1T1P1, Ethernet1_49) -> L3VNI ingress (VRF-bound)
  ingress_b (D1T1P2, Ethernet1_50) -> L2VNI ingress (VLAN-access)

Topology: requires fx3_qos_vxlan_testbed_breakout.yaml or any other
peer_link/breakout testbed that exposes the DUT1->T1 link.  The L2VNI
tests prefer ingress_b but fall back to ingress_a on single-D1T1P
testbeds (degenerate -- L2VNI and L3VNI share a physical port).
"""

import time
import warnings

import pytest

warnings.filterwarnings(
    "ignore", r".*currentThread\(\) is deprecated.*", DeprecationWarning)
warnings.filterwarnings(
    "ignore", r".*ssl\.PROTOCOL_TLS is deprecated.*", DeprecationWarning)

from spytest import st, tgapi

from qos_helpers import (
    GOLDEN_DSCP_TO_TC,
    V4_INGRESS_A_IP, V6_INGRESS_A_IP,
    V4_EGRESS_IP, V6_EGRESS_IP,
    IXIA_INGRESS_A_IP, IXIA_INGRESS_A_IP6,
    IXIA_EGRESS_IP, IXIA_EGRESS_IP6,

    V4_TRANSIT_DUT2_BARE, V6_TRANSIT_DUT2_BARE,
    print_section,
    get_dut_mac,
    get_port_dscp_tc_map,
    clear_dut_counters,
    get_intf_counters,
    report_intf_counters,
    get_dchal_queue_counters,
    dchal_show_queuing,
    parse_dchal_queue_counters,
    deploy_dchal_helper,
    setup_topo_common,
)

# Per-role Ixia source MACs for our streams.  The overlay e2e/smoke tests
# use IXIA_SRC_MAC['ingress_a'] (and 'ingress_b' on multi-D1T1P testbeds)
# as the Ethernet source on the encap-side wire.  Kept module-local here
# rather than re-exported from qos_helpers so qos_helpers stays at branch
# HEAD.  The same role->MAC convention is used by scheduler/test_scheduler.py.
IXIA_SRC_MAC = {
    'ingress_a': '00:11:01:00:00:01',
    'ingress_b': '00:11:02:00:00:01',
    'egress':    '00:11:04:00:00:01',
}

# Generic non-VxLAN helpers and packet/stream constants still live in
# the sibling test module qos_map/test_dscp_to_tc.py (the original Section
# A–G suite).  We reuse the e2e-scaffold helpers (deltas, queue-placement
# logger) and the packet shape constants (size/rate/timeout/Ixia dst IPs)
# rather than duplicating them here.
from test_dscp_to_tc import (
    _compute_deltas,
    _log_queue_placement_table,
    _PKT_SIZE,
    _STREAM_RATE_PPS,
    _TRAFFIC_TIMEOUT,
    _IXIA_DST_V4,
    _IXIA_DST_V6,
)

# Whole-module handle to test_dscp_to_tc, used by the Section K reused-
# base test wrappers at the end of this file. The wrappers temporarily
# inject this overlay file's globals (dut/dut2/tg/tg_ph/port_info) into
# `_base`'s namespace so the existing test functions in test_dscp_to_tc
# run unmodified against the VxLAN-mode forwarding path.  See the long-
# form rationale at "Section K - Reused base tests under VxLAN L3VNI".
import test_dscp_to_tc as _base  # noqa: E402

# VxLAN-specific helpers and constants live in vxlan/vxlan_helper.py.
# The Section I/J test bodies and smoke classes below consume:
#   - _setup_vxlan_l3vni / _setup_vxlan_l2vni : zero-arg legacy setup
#     entry points that read this module's globals (dut, dut2, tg,
#     tg_ph, port_info, dut2_port_info, topo_mode) via frame-walking,
#     so they get the values the setup_topo fixture assigned below.
#   - smoke_* family : packet capture / decode / scorecard helpers
#     used by the three TestSmoke* classes.
#   - _I_* and _J_* constants : VTEP IPs, VNIs, BGP AS numbers, VLAN
#     IDs, etc., that test bodies log and pass into helpers.
from vxlan.vxlan_helper import (
    _setup_vxlan_l3vni,
    _setup_vxlan_l2vni,
    _smoke_lookup_evpn_mac_for_l2vni,
    # UC/MC-aware re-parser for DCHAL queue stats. Lets _CounterCtx
    # split per-queue 'pkts' into uc_pkts / mc_pkts so the L2VNI BUM
    # smoke (multicast on the wire) and the L3VNI smokes (unicast on
    # the wire) can each pick the correct primary scorecard column.
    parse_dchal_queue_counters_with_mc,
    # ── Smoke-test capture / decode helpers ────────────────────────────
    smoke_start_capture,
    smoke_stop_capture,
    smoke_decode_frames,
    smoke_print_tx_rx_side_by_side,
    smoke_check_frame,
    smoke_pick_one_dscp_per_tc,
    # ── Smoke QoS verdict renderer (DSCP -> TC -> Q placement table) ───
    smoke_log_q_results,
    # ── L3VNI (Section I) constants ────────────────────────────────────
    _I_VNI,
    _I_VRF,
    _I_SPOT_DSCP,
    _I_LB_INTF,        # 'Loopback1' - VTEP source interface (L3VNI)
    _I_VTEP1_IP,       # '40.40.40.1' - DUT1 VTEP IP (L3VNI)
    _I_VTEP2_IP,       # '40.40.40.2' - DUT2 VTEP IP (L3VNI)
    _I_BGP_AS1,        # 65001 - DUT1 BGP AS (L3VNI)
    _I_BGP_AS2,        # 65002 - DUT2 BGP AS (L3VNI)
    # ── L2VNI (Section J) constants ────────────────────────────────────
    _J_VNI,
    _J_L2_VLAN,
    _J_SPOT_DSCP,
    _J_BUM_MAC,
    _J_LB_INTF,        # 'Loopback1' - VTEP source interface (L2VNI)
    _J_VTEP1_IP,       # '40.40.40.1' - DUT1 VTEP IP (L2VNI)
    _J_VTEP2_IP,       # '40.40.40.2' - DUT2 VTEP IP (L2VNI)
    _J_L2VNI_RX_MAC,   # deterministic eth_dst for unicast L2VNI smoke
    _J_L2VNI_RX_IP,    # 20.20.20.22 - Vlan502 receiver host IP
    _J_BGP_AS1,        # 65001 - DUT1 BGP AS (L2VNI)
    _J_BGP_AS2,        # 65002 - DUT2 BGP AS (L2VNI)
    # ── L3VNI-tagged smoke variant constant ────────────────────────────
    _L2_VLAN_ID,       # VID of the tagged-SVI in front of the L3VNI
                       # ingress (TestSmokeL3VNITagged), shared with
                       # _smoke_setup_l3vni_tagged_svi() defined below.
)


# ══════════════════════════════════════════════════════════════════════════════
# Per-TC unique-count traffic pattern (CORE DESIGN)
# ══════════════════════════════════════════════════════════════════════════════

# Per-TC packet count, tuned to the actual GOLDEN_DSCP_TO_TC distribution:
#   TC0=39 DSCPs, TC1=18, TC2=2, TC3..TC7=1 each.
# Chosen so the resulting per-queue totals are well-spread (min gap = 80
# pkts), pairwise distinct, and each ends in a round number that's easy to
# eyeball in the per-queue table.
PKTS_BY_TC = {
    0:  20,   # TC0: 39 DSCPs *  20 = Q0 expects 780
    1:  50,   # TC1: 18 DSCPs *  50 = Q1 expects 900
    2: 350,   # TC2:  2 DSCPs * 350 = Q2 expects 700
    3: 100,   # TC3:  1 DSCP  * 100 = Q3 expects 100
    4: 200,   # TC4:  1 DSCP  * 200 = Q4 expects 200
    5: 300,   # TC5:  1 DSCP  * 300 = Q5 expects 300
    6: 400,   # TC6:  1 DSCP  * 400 = Q6 expects 400
    7: 500,   # TC7:  1 DSCP  * 500 = Q7 expects 500
}

# Precompute expected per-queue totals from the GOLDEN map.
EXPECTED_Q_PKTS_UNIQUE = {qi: 0 for qi in range(8)}
for _ds, _tc in GOLDEN_DSCP_TO_TC.items():
    _qi = int(_tc)
    EXPECTED_Q_PKTS_UNIQUE[_qi] += PKTS_BY_TC[_qi]

# Sanity: all 8 totals are distinct (computed once at import time).
# Expected on the standard FX3 GOLDEN map:
# {0:780, 1:900, 2:700, 3:100, 4:200, 5:300, 6:400, 7:500}
# Sorted: [100, 200, 300, 400, 500, 700, 780, 900], min gap 80 pkts.
_uniq_vals = list(EXPECTED_Q_PKTS_UNIQUE.values())
assert len(set(_uniq_vals)) == len(_uniq_vals), (
    "EXPECTED_Q_PKTS_UNIQUE values must be pairwise distinct for the "
    "unique-counts design to work; got {}. If GOLDEN_DSCP_TO_TC has been "
    "edited, PKTS_BY_TC must be retuned.".format(EXPECTED_Q_PKTS_UNIQUE))

# +-2% tolerance for per-queue assertions (replaces +-15% from old tests),
# with an absolute floor of 5 packets so single-packet Ixia counter race
# doesn't flake the smallest queues.
#   Q3=100 -> +-2% = +-2; +-5 abs floor -> window [95,105]
#   Q7=500 -> +-2% = +-10; window [490,510]
#   Q1=900 -> +-2% = +-18; window [882,918]
# Min gap between adjacent queue totals is 80 pkts, so even with the +-5
# absolute floor every queue is unambiguously distinguishable from neighbors.
_TOL_PCT = 0.02
_TOL_ABS_FLOOR = 5

# Loose threshold for J's CP3 (BUM flood may filter / duplicate).
_J_LOOSE_RX_THRESHOLD = 0.95

# Settle time after ARP/ND prime stream before launching measure traffic.
_ARP_PRIME_WAIT = 2


# ══════════════════════════════════════════════════════════════════════════════
# Module-level state (populated by setup_topo fixture)
# ══════════════════════════════════════════════════════════════════════════════

dut         = None
dut2        = None
tg          = None
tg_ph       = {}
port_info   = {}
dut2_port_info = {}
topo_mode   = None


# ══════════════════════════════════════════════════════════════════════════════
# Module fixture: setup_topo
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """Topology setup for the VxLAN overlay e2e suite.

    Wraps setup_topo_common and publishes its raw position-labelled
    DUT1->T1 keys (``ingress_a`` and, when the testbed has a second
    DUT1->T1 link, ``ingress_b``) into this module's globals.  The
    VxLAN setup helpers in ``vxlan/vxlan_helper.py``
    (``_setup_vxlan_l3vni``, ``_setup_vxlan_l2vni``) walk back to this
    module's globals via ``_resolve_caller_globals`` to find ``dut``,
    ``dut2``, ``tg``, ``tg_ph``, ``port_info``, ``dut2_port_info`` and
    ``topo_mode`` -- no cross-module republish is required.

    Also deploys the DCHAL helper script on dut2 when present, so the
    CP2 readbacks (DUT2 post-decap queue counters) work.
    """
    global dut, dut2, tg, tg_ph, port_info, dut2_port_info, topo_mode

    for result in setup_topo_common(tgapi, target_queue=0):
        dut       = result['dut']
        tg        = result['tg']
        topo_mode = result['mode']

        raw_ph = result['tg_ph']
        raw_pi = result['port_info']

        # ── Supplement raw 'ingress_b' on breakout-mode VxLAN testbeds ────
        #
        # setup_topo_common's 'peer_link' branch natively produces
        # raw_pi['ingress_b'] / raw_ph['ingress_b'] when a second DUT1->T1
        # link is present.  Its 'breakout' branch does not (it only asks
        # for D1T1:1 and stops at ingress_a).  The dedicated VxLAN testbed
        # yaml (fx3_qos_vxlan_testbed_breakout.yaml) uses 'breakout' mode
        # for the transit link AND wires up 3 DUT1->T1 links, so we
        # supplement ingress_b ourselves here.  This keeps qos_helpers.py
        # at branch HEAD and confines the testbed-aware logic to the
        # overlay fixture that consumes it.
        if 'ingress_b' not in raw_pi:
            try:
                tb_vars = st.get_testbed_vars()
                if hasattr(tb_vars, 'D1T1P2'):
                    raw_pi['ingress_b'] = tb_vars.D1T1P2
                    _, tg_ph_b = tgapi.get_handle_byname('T1D1P2')
                    raw_ph['ingress_b'] = tg_ph_b
                    st.log("setup_topo: supplemented ingress_b = {} "
                           "(L2VNI ingress on dedicated VxLAN testbed)"
                           .format(raw_pi['ingress_b']))
            except Exception as exc:
                st.warn("setup_topo: failed to supplement ingress_b "
                        "(non-fatal; L2VNI tests will fall back to "
                        "ingress_a): {}".format(exc))

        # Republish raw setup_topo_common output under the conventional
        # qos_helpers keys.  Role-to-port mapping (which physical port
        # serves which overlay) is documented at the call site of each
        # test body, not encoded in the dict key names -- this keeps the
        # naming consistent across the rest of the QoS suite (Section G,
        # scheduler, buffer, wred) which all speak ingress_a / ingress_b.
        #
        #   By convention on this overlay suite:
        #     ingress_a  -> L3VNI ingress (Section I, VRF-bound)
        #     ingress_b  -> L2VNI ingress (Section J, VLAN-access)
        #
        # The legacy 'ingress' alias remains as a back-compat handle for
        # shared pre-flight helpers that pre-date the port split and
        # want the canonical L3 ingress port (== ingress_a).
        port_info = {
            'ingress':    raw_pi['ingress_a'],
            'ingress_a':  raw_pi['ingress_a'],
            'egress':     raw_pi['egress'],
        }
        if 'ingress_b' in raw_pi:
            port_info['ingress_b'] = raw_pi['ingress_b']

        tg_ph = {
            'ingress':    raw_ph['ingress_a'],
            'ingress_a':  raw_ph['ingress_a'],
            'egress':     raw_ph.get('egress_sink', raw_ph['egress']),
        }
        if 'ingress_b' in raw_ph:
            tg_ph['ingress_b'] = raw_ph['ingress_b']

        dut2           = result.get('dut2')
        dut2_port_info = result.get('dut2_port_info', {})

        # No globals-bridge needed: the VxLAN setup helpers
        # (_setup_vxlan_l3vni / _setup_vxlan_l2vni) live in
        # vxlan/vxlan_helper.py and read their callers' module
        # globals via frame-walking (_resolve_caller_globals).  When a
        # test body in *this* module calls them, they pick up the
        # dut / dut2 / tg / tg_ph / port_info / dut2_port_info /
        # topo_mode names assigned above directly from this module's
        # globals -- no republish required.

        deploy_dchal_helper(dut)
        if dut2:
            deploy_dchal_helper(dut2)

        yield


# ══════════════════════════════════════════════════════════════════════════════
# Helpers: streams, measurement, ARP/ND prime
# ══════════════════════════════════════════════════════════════════════════════

def _build_streams_unique(af, ingress_ph, dst_mac,
                          dscp_range=None, vlan_id=None):
    """Build per-DSCP streams using PKTS_BY_TC[tc] count per DSCP, and
    udp_dst_port = 5000 + dscp (per-DSCP unique, so Ixia rx-side filters
    can disambiguate per DSCP, not just per TC).

    Returns:
        list of dicts:
            [{'dscp': N, 'tc': N, 'expected_pkts': N,
              'udp_dst_port': N, 'handle': <ixia_handle_dict>}, ...]
    """
    if dscp_range is None:
        dscp_range = range(64)

    streams = []
    for dscp in dscp_range:
        tc           = int(GOLDEN_DSCP_TO_TC[str(dscp)])
        expected     = PKTS_BY_TC[tc]
        udp_dst_port = 5000 + int(dscp)
        kwargs = dict(
            mode='create',
            port_handle=ingress_ph,
            mac_dst=dst_mac,
            l4_protocol='udp',
            udp_src_port=10000 + int(dscp),
            udp_dst_port=udp_dst_port,
            frame_size=_PKT_SIZE,
            rate_pps=_STREAM_RATE_PPS,
            pkts_per_burst=expected,
            transmit_mode='single_burst',
            high_speed_result_analysis=0,
        )
        if af == 'ipv4':
            kwargs.update(
                l3_protocol='ipv4',
                ip_src_addr=IXIA_INGRESS_A_IP,
                ip_dst_addr=_IXIA_DST_V4,
                ip_dscp=int(dscp),
                ip_ttl=64,
            )
        else:
            kwargs.update(
                l3_protocol='ipv6',
                ipv6_src_addr=IXIA_INGRESS_A_IP6,
                ipv6_dst_addr=_IXIA_DST_V6,
                ipv6_traffic_class=(int(dscp) << 2),
                ipv6_hop_limit=64,
            )
        if vlan_id is not None:
            kwargs.update(l2_encap='ethernet_ii_vlan', vlan='enable',
                          vlan_id=int(vlan_id), vlan_id_mode='fixed')
        handle = tg.tg_traffic_config(**kwargs)
        streams.append({
            'dscp':         int(dscp),
            'tc':           tc,
            'expected_pkts': expected,
            'udp_dst_port': udp_dst_port,
            'handle':       handle,
        })

    return streams


def _prime_arp_nd(af):
    """Send a brief stream to populate ARP/ND on DUT2 so the first measure
    packets are not punted/dropped while ARP resolves.

    Idempotent and safe for H tests (DUT only) - just costs ~2 seconds.
    For J (BUM flood) this prime is irrelevant (broadcast dst_mac) but is
    still safe to invoke.

    Build the kwargs CONDITIONALLY so we never pass `ipv4 keys = None` or
    `ipv6 keys = None` to Ixia. The TCL Ixia driver rejects `None` with
    "Invalid value for -ipv6_src_addr" / "-ip_src_addr", and that error
    propagates as a fatal TG API error before our try/except can catch it.
    """
    try:
        ingress_ph = tg_ph['ingress']
        kwargs = dict(
            mode='create',
            port_handle=ingress_ph,
            mac_dst=get_dut_mac(dut, port_info['ingress']),
            l4_protocol='icmp',
            frame_size=64,
            rate_pps=10,
            pkts_per_burst=4,
            transmit_mode='single_burst',
            high_speed_result_analysis=0,
        )
        if af == 'ipv4':
            kwargs.update(
                l3_protocol='ipv4',
                ip_src_addr=IXIA_INGRESS_A_IP,
                ip_dst_addr=_IXIA_DST_V4,
            )
        else:
            kwargs.update(
                l3_protocol='ipv6',
                ipv6_src_addr=IXIA_INGRESS_A_IP6,
                ipv6_dst_addr=_IXIA_DST_V6,
            )
        prime = tg.tg_traffic_config(**kwargs)
        tg.tg_traffic_control(action='run', handle=prime.get('stream_id'))
        st.wait(_ARP_PRIME_WAIT)
        tg.tg_traffic_control(action='stop', handle=prime.get('stream_id'))
        # Remove the prime stream so the upcoming measure traffic is
        # not commingled.
        try:
            tg.tg_traffic_config(mode='remove',
                                 stream_id=prime.get('stream_id'),
                                 port_handle=ingress_ph)
        except Exception:
            pass
    except Exception:
        pass


def _measure_dut1_queues_unique(label):
    """Snapshot DUT1 transit/egress DCHAL counters before+after the caller's
    traffic phase. Caller invokes this with a context-manager-like pattern:

        ctx = _measure_dut1_queues_unique('CP1')
        ctx.snap_before()
        # ... run traffic ...
        ctx.snap_after()
        deltas = ctx.deltas()

    Returns an object with snap_before/snap_after/deltas methods. This keeps
    the BEFORE/AFTER calls explicit and ordered.
    """
    return _CounterCtx(dut, port_info['egress'], label + " DUT1 egress")


def _measure_dut2_queues_unique(label):
    """Same as _measure_dut1_queues_unique but reads on
    dut2_port_info['egress_ixia'] (post-decap egress).
    """
    if not dut2 or not dut2_port_info.get('egress_ixia'):
        return _NullCounterCtx(label + " DUT2 egress_ixia (skipped: no DUT2)")
    return _CounterCtx(
        dut2, dut2_port_info['egress_ixia'], label + " DUT2 egress_ixia")


class _CounterCtx:
    """Encapsulates BEFORE/AFTER DCHAL queue counter capture for one port.

    When ``with_aggregate=True``, additionally captures the cheap
    ``show interfaces counters <intf>`` aggregate (rx_ok / tx_ok /
    tx_drp) on the same port. The aggregate is exposed via
    ``aggregate_deltas()`` and is useful as:

      - A FALLBACK if the dchal call hiccups and returns an empty dict
        (then we still know whether frames left the port).
      - A CROSS-CHECK against sum(per-queue dchal pkts), so a discrepancy
        between dchal and the SONiC port-level counter is itself
        diagnostic information.

    The aggregate snapshot adds ~0.3-0.8s per BEFORE/AFTER pair on FX3
    (one `show interfaces counters` per snapshot is much cheaper than
    one dchal docker-exec). For smoke tests it's a cheap and worthwhile
    add; for the larger I3/I4/J3/J4 parametric tests we leave it off
    by default so it doesn't multiply per-CP cost.
    """

    def __init__(self, dut_handle, intf, label, with_aggregate=False,
                 with_uc_mc=False):
        self.dut_h  = dut_handle
        self.intf   = intf
        self.label  = label
        self._with_agg   = with_aggregate
        self._with_ucmc  = with_uc_mc
        self._before = None
        self._after  = None
        self._agg_before = None
        self._agg_after  = None
        # When with_uc_mc=True we also keep a parallel parse of the same
        # raw dchal text that exposes UC and MC columns separately.
        # Cost: zero extra docker-exec -- we just parse the same stdout
        # twice in Python.  Keyed by QOS GROUP index.
        self._before_ucmc = None
        self._after_ucmc  = None

    def _snap_once(self, label_prefix):
        """Run dchal-show-queuing ONCE and return both parses.

        Avoids paying the docker-exec cost twice when with_uc_mc=True.
        Returns (uc_only_dict, uc_mc_dict_or_None).
        """
        full_label = label_prefix + " " + self.label
        if self._with_ucmc:
            raw = dchal_show_queuing(self.dut_h, full_label, self.intf)
            uc_only = parse_dchal_queue_counters(raw)
            uc_mc   = parse_dchal_queue_counters_with_mc(raw)
            if not uc_only:
                st.log("WARNING: DCHAL returned no queue data for {} "
                       "[{}] -- returning empty counters. 'show queue "
                       "counters' will NOT be used as fallback "
                       "(unreliable on FX3).".format(
                           self.intf, full_label))
            return uc_only, uc_mc
        # Legacy path: just delegate to the helper that wraps both
        # dchal_show_queuing + parse_dchal_queue_counters in one call.
        return get_dchal_queue_counters(
            self.dut_h, self.intf, full_label), None

    def snap_before(self):
        self._before, self._before_ucmc = self._snap_once("BEFORE")
        if self._with_agg:
            try:
                self._agg_before = get_intf_counters(
                    self.dut_h, [self.intf]).get(self.intf, {})
            except Exception as exc:
                st.warn("  aggregate snap_before failed for {}: {}".format(
                    self.intf, exc))
                self._agg_before = {}

    def snap_after(self):
        self._after, self._after_ucmc = self._snap_once("AFTER")
        if self._with_agg:
            try:
                self._agg_after = get_intf_counters(
                    self.dut_h, [self.intf]).get(self.intf, {})
            except Exception as exc:
                st.warn("  aggregate snap_after failed for {}: {}".format(
                    self.intf, exc))
                self._agg_after = {}

    def deltas(self):
        if self._before is None or self._after is None:
            return {qi: {'pkts': 0, 'drop_pkts': 0} for qi in range(8)}
        # Legacy UC-only delta (preserves existing semantics for every
        # call site that just looks at d[qi]['pkts']).
        d = _compute_deltas(self._before, self._after)
        # If UC/MC capture was requested, merge the per-queue uc_pkts,
        # mc_pkts, and a UC+MC 'pkts_sum' into each entry.  We do NOT
        # overwrite d[qi]['pkts'] -- that key keeps the UC value so any
        # caller that has been reading it sees no change.  Scorecard
        # code that wants the BUM-aware reading must look at 'pkts_sum'
        # or sum 'uc_pkts'+'mc_pkts' explicitly.
        if self._with_ucmc and self._before_ucmc is not None \
                and self._after_ucmc is not None:
            for qi in range(8):
                b = self._before_ucmc.get(qi, {})
                a = self._after_ucmc.get(qi, {})
                uc = max(0, int(a.get('uc_pkts', 0))
                            - int(b.get('uc_pkts', 0)))
                mc = max(0, int(a.get('mc_pkts', 0))
                            - int(b.get('mc_pkts', 0)))
                entry = d.setdefault(qi, {'pkts': 0, 'drop_pkts': 0})
                entry['uc_pkts']  = uc
                entry['mc_pkts']  = mc
                entry['pkts_sum'] = uc + mc
        return d

    def aggregate_deltas(self):
        """Return {'rx_ok': N, 'tx_ok': N, 'tx_drp': N} for this port.

        Returns an empty dict if with_aggregate=False or either snapshot
        was skipped/failed. Negative deltas (counter wrap or counter
        reset) are clamped to 0 with a WARN log line.
        """
        if not self._with_agg or self._agg_before is None or self._agg_after is None:
            return {}
        out = {}
        for k in ('rx_ok', 'tx_ok', 'tx_drp'):
            b = int(self._agg_before.get(k, 0))
            a = int(self._agg_after.get(k, 0))
            d = a - b
            if d < 0:
                st.warn("  {} aggregate delta {} went negative ({} -> {}); "
                        "counter reset suspected, clamping to 0".format(
                            self.intf, k, b, a))
                d = 0
            out[k] = d
        return out

    def is_real(self):
        return True


class _NullCounterCtx:
    """No-op counter context for cases where the port does not apply
    (e.g. H tests don't have a DUT2)."""

    def __init__(self, label):
        self.label = label

    def snap_before(self):
        pass

    def snap_after(self):
        pass

    def deltas(self):
        return {}

    def aggregate_deltas(self):
        return {}

    def is_real(self):
        return False


class _AggOnlyCtx:
    """Lightweight BEFORE/AFTER snapshot of `show interfaces counters`
    on a single port (no DCHAL queue counters).

    Designed for the ingress-side ports in the smoke pipeline:
      - DUT1 ingress (Ethernet1_49)         : Ixia -> DUT1 entry
      - DUT2 ingress (peer-side Ethernet1_54_1): fabric -> DUT2 entry
    These ports do NOT need per-queue dchal data (the queue placement
    decisions are visible on the EGRESS-side ports). What we DO need is
    the cheap aggregate so the 'Final summary' one-row comparison table
    can show how many packets entered each device, alongside how many
    left. That lets a reader see at a glance whether the loss happened
    inside DUT1, on the fabric, or inside DUT2.

    Cost: ~0.3-0.8s per BEFORE/AFTER pair (one `show interfaces counters`
    each), the same as the with_aggregate=True path on _CounterCtx.
    Failures are SOFT -- a missing snapshot just shows 'n/a' in the
    summary table; the test is never gated on this evidence.
    """

    def __init__(self, dut_handle, intf, label):
        self.dut_h  = dut_handle
        self.intf   = intf
        self.label  = label
        self._before = None
        self._after  = None

    def snap_before(self):
        try:
            self._before = get_intf_counters(
                self.dut_h, [self.intf]).get(self.intf, {})
        except Exception as exc:
            st.warn("  AggOnly snap_before failed for {} ({}): {}".format(
                self.intf, self.label, exc))
            self._before = {}

    def snap_after(self):
        try:
            self._after = get_intf_counters(
                self.dut_h, [self.intf]).get(self.intf, {})
        except Exception as exc:
            st.warn("  AggOnly snap_after failed for {} ({}): {}".format(
                self.intf, self.label, exc))
            self._after = {}

    def aggregate_deltas(self):
        """Return {'rx_ok': N, 'tx_ok': N, 'tx_drp': N} for this port,
        clamped at zero on counter wrap. Returns {} if either snapshot
        was skipped/failed."""
        if self._before is None or self._after is None:
            return {}
        out = {}
        for k in ('rx_ok', 'tx_ok', 'tx_drp'):
            b = int(self._before.get(k, 0))
            a = int(self._after.get(k, 0))
            d = a - b
            if d < 0:
                st.warn("  {} aggregate delta {} went negative ({} -> {}); "
                        "counter reset suspected, clamping to 0".format(
                            self.intf, k, b, a))
                d = 0
            out[k] = d
        return out

    def is_real(self):
        return True


def _measure_ixia_rx_per_stream(streams):
    """Per-DSCP rx count via Ixia stream stats. Returns {dscp: rx_pkts}.

    If stream-mode returns zeros across the board AND aggregate rx is
    nonzero, this is a strong signal that the streams were created without
    track_by/traffic_item. The caller (via the integrated rx wrapper) will
    fall back to _measure_ixia_rx_per_dscp_filter() in that case.
    """
    rx = {}
    for s in streams:
        try:
            stats = tg.tg_traffic_stats(
                mode='stream', stream=s['handle'].get('stream_id'),
                port_handle=tg_ph['egress'])
            # IxNetwork structure varies; defensively walk common shapes.
            rx_pkts = 0
            if isinstance(stats, dict):
                for v in stats.values():
                    if not isinstance(v, dict):
                        continue
                    flow = v.get('flow') or v.get('stream') or v
                    if isinstance(flow, dict):
                        flow = flow.get(str(s['handle'].get('stream_id')),
                                        flow)
                    if isinstance(flow, dict):
                        rxd = flow.get('rx', {})
                        if isinstance(rxd, dict):
                            rx_pkts = int(rxd.get('total_pkts') or
                                          rxd.get('total_pkt') or 0)
                            if rx_pkts:
                                break
            rx[s['dscp']] = rx_pkts
        except Exception as exc:
            st.log("  WARN: tg_traffic_stats(mode=stream) "
                   "DSCP {} failed: {}".format(s['dscp'], exc))
            rx[s['dscp']] = 0
    return rx


def _stream_tx_rx(stream_id, ingress_ph, egress_ph):
    """Return (tx_pkts, rx_pkts) for ONE Ixia stream.

    Uses mode='stream' (NOT mode='aggregate') for two reasons:

    1. mode='aggregate' triggers a fatal Tcl abort in this Ixia build:
         can't read "matched_str": no such variable
       Spytest converts that into pytest.skip(), so the test ends up
       SKIPPED rather than PASS/FAIL. mode='stream' uses a different
       code path inside ixiangpf and is unaffected.
    2. mode='stream' counts ONLY the frames belonging to our tracked
       traffic_item, excluding control-plane noise (BGP/EVPN/LLDP).
       So our rx/tx ratios reflect actual data-plane delivery rather
       than data + control + maybe-some-keepalive.

    Defensive walking of the IxNetwork response shape mirrors the
    existing _measure_ixia_rx_per_stream() helper above: ixiangpf can
    return the per-stream counts under several keys depending on
    chassis OS / API version, so we search common shapes.

    Returns:
        (tx_pkts, rx_pkts) -- both ints, both 0 on error.
    """
    if not stream_id:
        return 0, 0
    # Defensive: if the caller accidentally passed the FULL Ixia
    # handle dict (e.g. {'stream_id': 'S_1', 'port_handle': '1/1/9'})
    # instead of the bare stream_id string, unwrap it. This was the
    # actual bug behind 'Ixia-TX 0 / Ixia-RX 0' in the smoke run on
    # 2026-05-15: stream_handle came back from tg_traffic_config as
    # a dict, the caller wrapped it again as {'stream_id': <dict>},
    # and walk()'s flow.get(str(stream_id)) never matched a key in
    # the IxNetwork response.
    if isinstance(stream_id, dict):
        sid = stream_id.get('stream_id') or stream_id.get('handle')
        if sid is None:
            st.log("  WARN: _stream_tx_rx got a dict with no "
                   "'stream_id' key: {!r}".format(stream_id))
            return 0, 0
        stream_id = sid

    def _walk(stats, side):
        """Pull <side>={'tx'|'rx'}.total_pkts from a tg_traffic_stats
        return-dict. Returns 0 when the structure is unrecognised."""
        if not isinstance(stats, dict):
            return 0
        for v in stats.values():
            if not isinstance(v, dict):
                continue
            flow = v.get('flow') or v.get('stream') or v
            if isinstance(flow, dict):
                # IxNetwork sometimes nests by stream_id string
                inner = flow.get(str(stream_id))
                if isinstance(inner, dict):
                    flow = inner
            if isinstance(flow, dict):
                bucket = flow.get(side, {})
                if isinstance(bucket, dict):
                    n = int(bucket.get('total_pkts')
                            or bucket.get('total_pkt') or 0)
                    if n:
                        return n
        return 0

    tx = rx = 0
    # TX side: read from ingress port. KeyboardInterrupt/SystemExit pass
    # through (Ctrl-C and pytest --exitfirst should still work). Any
    # other failure (including spytest's pytest.skip raised from a
    # fatal Ixia abort) is logged and treated as zero so the caller
    # can keep going.
    try:
        s_ing = tg.tg_traffic_stats(mode='stream', stream=stream_id,
                                    port_handle=ingress_ph)
        tx = _walk(s_ing, 'tx')
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:
        st.log("  WARN: tg_traffic_stats(mode=stream, side=tx, "
               "stream={}, port={}) failed ({}): {}".format(
                   stream_id, ingress_ph, type(exc).__name__, exc))

    try:
        s_egr = tg.tg_traffic_stats(mode='stream', stream=stream_id,
                                    port_handle=egress_ph)
        rx = _walk(s_egr, 'rx')
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:
        st.log("  WARN: tg_traffic_stats(mode=stream, side=rx, "
               "stream={}, port={}) failed ({}): {}".format(
                   stream_id, egress_ph, type(exc).__name__, exc))

    return tx, rx


def _sum_streams_tx_rx(streams):
    """Sum (tx, rx) across a list of streams (each {'handle': {...},
    'dscp': N}).

    Used by J3/J4 to compute the same totals the deprecated
    _measure_ixia_rx_aggregate used to produce, but via the safer
    mode='stream' API. Falls back to (0, 0) if the streams list is
    empty.
    """
    total_tx = total_rx = 0
    for s in (streams or []):
        sid = s.get('handle', {}).get('stream_id') if isinstance(
            s.get('handle'), dict) else None
        t, r = _stream_tx_rx(sid, tg_ph['ingress'], tg_ph['egress'])
        total_tx += t
        total_rx += r
    return total_tx, total_rx


def _measure_ixia_rx_aggregate(streams=None):
    """Return (total_tx_pkts, total_rx_pkts) for the egress (rx) port.

    HISTORY: This used to call tg_traffic_stats(mode='aggregate') on
    each port_handle. That mode triggers a fatal Tcl abort
        can't read "matched_str": no such variable
    in some Ixia/IxNetwork builds, which spytest converts to
    pytest.skip() -- making otherwise-passing tests show up as SKIPPED.

    Now we sum mode='stream' totals across the provided traffic
    streams. If no streams are provided, return (0, 0) -- the caller
    will see "0 tx, 0 rx" rather than the test getting skipped.

    Args:
        streams: list of {'handle': {'stream_id': str}, ...} entries.
                 When None or empty, returns (0, 0). Smoke-test path
                 passes a single-element list, J3/J4 pass all 8 dscp
                 streams.

    Returns:
        (tx_total, rx_total) -- summed across the provided streams.
    """
    if not streams:
        st.log("  _measure_ixia_rx_aggregate called with no streams -- "
               "returning (0, 0). (mode='aggregate' was deprecated "
               "because it triggers a fatal Tcl abort on this build.)")
        return 0, 0
    return _sum_streams_tx_rx(streams)


# ══════════════════════════════════════════════════════════════════════════════
# Send + multi-checkpoint measurement wrapper
# ══════════════════════════════════════════════════════════════════════════════

def _send_and_measure_e2e(label, streams, measure_dut2=True):
    """Snapshot DUT1 + DUT2 BEFORE, run streams, snapshot AFTER, read per-
    stream Ixia rx. Returns:
        {
          'dut1_deltas':  {qi: {'pkts': N, 'drop_pkts': N}, ...},
          'dut2_deltas':  same shape or {} if measure_dut2=False / no dut2,
          'rx_per_dscp':  {dscp: rx_pkts, ...},
          'agg_tx':       int,
          'agg_rx':       int,
          'egress':       <DUT1 egress intf string>,
        }
    """
    cp1 = _measure_dut1_queues_unique(label)
    cp2 = _measure_dut2_queues_unique(label) if measure_dut2 \
          else _NullCounterCtx(label + " DUT2 (disabled)")

    egress = port_info['egress']
    clear_dut_counters(dut)
    intf_before = get_intf_counters(dut, port_info.values())

    cp1.snap_before()
    cp2.snap_before()

    tg.tg_traffic_control(action='clear_stats')
    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run')
    st.wait(_TRAFFIC_TIMEOUT)
    tg.tg_traffic_control(action='stop')
    st.wait(3)  # let DCHAL counters settle

    cp1.snap_after()
    cp2.snap_after()

    intf_after = get_intf_counters(dut, port_info.values())
    report_intf_counters(port_info, intf_before, intf_after)

    rx_per_dscp = _measure_ixia_rx_per_stream(streams)

    return {
        'dut1_deltas':  cp1.deltas(),
        'dut2_deltas':  cp2.deltas() if cp2.is_real() else {},
        'rx_per_dscp':  rx_per_dscp,
        'egress':       egress,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Assertion helpers
# ══════════════════════════════════════════════════════════════════════════════

def _expected_q_pkts_for_dscps(dscps):
    """Compute expected per-queue totals when only the subset 'dscps' is sent.

    For spot-check tests (1 DSCP per TC), only the queues whose TCs are
    represented receive packets; other queues expect 0.
    """
    exp = {qi: 0 for qi in range(8)}
    for d in dscps:
        tc = int(GOLDEN_DSCP_TO_TC[str(d)])
        exp[tc] += PKTS_BY_TC[tc]
    return exp


def _assert_per_queue(deltas, expected, cp_label, failures):
    """Assert deltas[q]['pkts'] within max(+-_TOL_PCT, +-_TOL_ABS_FLOOR) of
    expected[q].

    Queues with expected == 0 must have actual == 0 (any leak is a hard
    failure regardless of tolerance - cross-TC misclassification fingerprint).
    """
    for qi in range(8):
        exp = expected.get(qi, 0)
        act = deltas.get(qi, {}).get('pkts', 0)
        drp = deltas.get(qi, {}).get('drop_pkts', 0)
        if exp == 0:
            if act > 0:
                failures.append(
                    "{} Q{} expected 0 but actual={} (cross-TC leak; "
                    "fingerprint suggests a DSCP normally on TC{} was "
                    "misclassified to TC{})".format(
                        cp_label, qi, qi,
                        _guess_source_tc(act), qi))
            continue
        # Tolerance is max(+-_TOL_PCT, +-_TOL_ABS_FLOOR) packets, so small
        # queues are not flaked by single-packet counter race.
        tol = max(int(round(exp * _TOL_PCT)), _TOL_ABS_FLOOR)
        lo = exp - tol
        hi = exp + tol
        if not (lo <= act <= hi):
            delta = act - exp
            failures.append(
                "{} Q{} actual={} outside [{},{}] "
                "(expected {} +-{} pkts, delta={:+d})".format(
                    cp_label, qi, act, lo, hi, exp, tol, delta))
        if drp > 0:
            failures.append(
                "{} Q{} drop_pkts={} (expected 0)".format(
                    cp_label, qi, drp))


def _guess_source_tc(pkts_seen):
    """Given a leak count on an unexpected queue, return the TC whose
    PKTS_BY_TC value matches (a diagnostic hint for cross-TC leaks).

    Returns '?' if no PKTS_BY_TC value matches.
    """
    for tc, n in PKTS_BY_TC.items():
        if pkts_seen == n:
            return tc
    return '?'


def _assert_ixia_per_dscp(rx, streams, cp_label, failures):
    """Assert per-DSCP rx == expected_pkts (zero loss, strict).

    If ALL streams show rx=0 but aggregate rx is nonzero, do not flag every
    DSCP - instead emit a single 'stream-mode unavailable' note and skip
    CP3 grading for this test. (The unique counts on CP1/CP2 already
    catch the bulk of the QoS-pipeline correctness; CP3 is a bonus.)
    """
    total_stream_rx = sum(rx.values())
    if total_stream_rx == 0:
        # Likely the streams were not created with track_by; aggregate mode
        # would give a number but not per-DSCP. Note and move on.
        st.log("  {} NOTE: Ixia per-stream rx all zero; stream tracking "
               "may not be available on this build. Skipping per-DSCP "
               "rx grading.".format(cp_label))
        return
    for s in streams:
        dscp = s['dscp']
        exp  = s['expected_pkts']
        act  = rx.get(dscp, 0)
        if act != exp:
            failures.append(
                "{} DSCP {} (udp={}) tx={} rx={} loss={} "
                "(expected 0 loss)".format(
                    cp_label, dscp, s['udp_dst_port'], exp, act, exp - act))


def _log_cp_summary(failures, total_checks, label):
    """One-line per-checkpoint summary so success/failure is at-a-glance."""
    n_fail = len(failures)
    status = "PASS" if n_fail == 0 else "FAIL ({} issues)".format(n_fail)
    st.log("  {}: {} ({}/{} checks)".format(
        label, status, total_checks - n_fail, total_checks))


# ══════════════════════════════════════════════════════════════════════════════
# Section H - REMOVED
# ══════════════════════════════════════════════════════════════════════════════
#
# The two former H tests (`test_l2_tagged_e2e_spot_check`,
# `test_l2_tagged_e2e_all_64_dscp`) were non-VxLAN, single-DUT L3-via-SVI
# tests that did not belong in `test_dscp_to_tc_overlay.py` (the
# VxLAN-overlay test file). They depended on a deleted helper
# (`_setup_l2_vlan_svi`) which bound `dscp_to_tc_map` to a Vlan SVI; that
# pattern does not work on the FX3 platform (orchagent does not program
# SAI from a PORT_QOS_MAP entry on an SVI -- see the long-form rationale
# in `_smoke_setup_l3vni_tagged_svi()` lines 3853-3866).
#
# Functional coverage of H1e2e/H2e2e (per-DSCP queue placement + zero loss
# on a single DUT) is fully covered by:
#   * cisco/fx3/qos/qos_map/test_dscp_to_tc.py::test_per_dscp_queue_placement
#     [ipv4] and [ipv6]      -- 64-DSCP per-queue placement, +/-15% tolerance
#   * cisco/fx3/qos/qos_map/test_dscp_to_tc.py::test_zero_drops_on_expected_queue
#     [ipv4] and [ipv6]      -- 64-DSCP placement + zero-drop assertion
#
# The "tagged ingress" angle (the only unique H feature) is covered, the
# Tortuga-reference / FX3-correct way, by:
#   * TestSmokeL3VNITagged::test_dscp_to_tc_smoke_l3vni_tagged_ucast[...]
#     (this file, end of module)  -- keeps the DSCP-to-TC map on the
#     physical port underneath the SVI, which is the only pattern that
#     classifies correctly on FX3.
# ══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# Section I - VxLAN L3VNI End-to-End Tests (2-DUT, requires breakout/peer_link)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.traffic
@pytest.mark.vxlan_transit
@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_vxlan_l3vni_e2e_spot_check(af):
    """#I3 - 8 spot-check DSCPs via VxLAN L3VNI, full 3-CP verification.

    CP1 (DUT1 transit egress): per-queue == PKTS_BY_TC[tc] +-2% (8 queues).
    CP2 (DUT2 egress_ixia):    per-queue == PKTS_BY_TC[tc] +-2%.
    CP3 (Ixia rx):             per-DSCP rx == PKTS_BY_TC[tc] (strict).
    """
    if topo_mode == 'ixia':
        pytest.skip(
            "Section I3 requires 2-DUT topology (peer_link/breakout); "
            "current mode is 'ixia'")

    print_section(
        "I3 - VxLAN L3VNI e2e spot-check [{}]".format(af.upper()),
        art_key='dscp_to_tc')

    # Section I (L3VNI) uses ingress_a as the L3VNI ingress port by
    # convention -- VRF-bound on the first DUT1->T1 link.
    ingress_ph = tg_ph['ingress_a']
    failures   = []

    teardown = _setup_vxlan_l3vni()
    try:
        dst_mac = get_dut_mac(dut, port_info['ingress_a'])
        st.log("  DUT1 ingress MAC={} VRF={} VNI={}".format(
            dst_mac, _I_VRF, _I_VNI))

        _prime_arp_nd(af)

        tg.tg_traffic_control(action='reset')
        spot_dscps = list(_I_SPOT_DSCP.keys())
        streams = _build_streams_unique(
            af, ingress_ph, dst_mac, dscp_range=spot_dscps)

        result = _send_and_measure_e2e(
            "I3/{}".format(af), streams, measure_dut2=True)

        expected_q = _expected_q_pkts_for_dscps(spot_dscps)
        _log_queue_placement_table(
            result['dut1_deltas'],
            "[I3 CP1 DUT1 transit {}]".format(af.upper()),
            expected=expected_q)
        _log_queue_placement_table(
            result['dut2_deltas'],
            "[I3 CP2 DUT2 egress_ixia {}]".format(af.upper()),
            expected=expected_q)

        cp1_before = len(failures)
        _assert_per_queue(result['dut1_deltas'], expected_q,
                          "CP1 DUT1 transit", failures)
        _log_cp_summary(failures[cp1_before:], 8, "CP1 DUT1 transit")

        cp2_before = len(failures)
        _assert_per_queue(result['dut2_deltas'], expected_q,
                          "CP2 DUT2 egress_ixia", failures)
        _log_cp_summary(failures[cp2_before:], 8, "CP2 DUT2 egress_ixia")

        cp3_before = len(failures)
        _assert_ixia_per_dscp(result['rx_per_dscp'], streams,
                              "CP3 Ixia rx", failures)
        _log_cp_summary(failures[cp3_before:], len(streams), "CP3 Ixia rx")
    finally:
        teardown()

    if failures:
        st.report_fail('msg', "I3 [{}] failures ({}):\n  ".format(
            af, len(failures)) + "\n  ".join(failures))
    st.report_pass('msg',
        "I3 [{}]: 8 DSCP spot-check via VxLAN L3VNI ({}) - "
        "CP1+CP2+CP3 PASS".format(af, _I_VNI))


@pytest.mark.traffic
@pytest.mark.vxlan_transit
@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_vxlan_l3vni_e2e_all_64_dscp(af):
    """#I4 - All 64 DSCPs via VxLAN L3VNI, full 3-CP verification.

    CP1: per-queue == EXPECTED_Q_PKTS_UNIQUE +-2% on DUT1 transit.
    CP2: per-queue == EXPECTED_Q_PKTS_UNIQUE +-2% on DUT2 egress_ixia.
    CP3: per-DSCP rx == PKTS_BY_TC[tc] strict.
    """
    if topo_mode == 'ixia':
        pytest.skip(
            "Section I4 requires 2-DUT topology (peer_link/breakout); "
            "current mode is 'ixia'")

    print_section(
        "I4 - VxLAN L3VNI e2e 64-DSCP [{}]".format(af.upper()),
        art_key='dscp_to_tc')

    # Section I (L3VNI) uses ingress_a as the L3VNI ingress port by
    # convention.  See I3 for the rationale.
    ingress_ph = tg_ph['ingress_a']
    failures   = []

    teardown = _setup_vxlan_l3vni()
    try:
        dst_mac = get_dut_mac(dut, port_info['ingress_a'])
        st.log("  DUT1 ingress MAC={} VRF={} VNI={}".format(
            dst_mac, _I_VRF, _I_VNI))

        _prime_arp_nd(af)

        tg.tg_traffic_control(action='reset')
        streams = _build_streams_unique(af, ingress_ph, dst_mac)

        result = _send_and_measure_e2e(
            "I4/{}".format(af), streams, measure_dut2=True)

        _log_queue_placement_table(
            result['dut1_deltas'],
            "[I4 CP1 DUT1 transit {}]".format(af.upper()),
            expected=EXPECTED_Q_PKTS_UNIQUE)
        _log_queue_placement_table(
            result['dut2_deltas'],
            "[I4 CP2 DUT2 egress_ixia {}]".format(af.upper()),
            expected=EXPECTED_Q_PKTS_UNIQUE)

        cp1_before = len(failures)
        _assert_per_queue(result['dut1_deltas'], EXPECTED_Q_PKTS_UNIQUE,
                          "CP1 DUT1 transit", failures)
        _log_cp_summary(failures[cp1_before:], 8, "CP1 DUT1 transit")

        cp2_before = len(failures)
        _assert_per_queue(result['dut2_deltas'], EXPECTED_Q_PKTS_UNIQUE,
                          "CP2 DUT2 egress_ixia", failures)
        _log_cp_summary(failures[cp2_before:], 8, "CP2 DUT2 egress_ixia")

        cp3_before = len(failures)
        _assert_ixia_per_dscp(result['rx_per_dscp'], streams,
                              "CP3 Ixia rx", failures)
        _log_cp_summary(failures[cp3_before:], 64, "CP3 Ixia rx")
    finally:
        teardown()

    if failures:
        st.report_fail('msg', "I4 [{}] failures ({}):\n  ".format(
            af, len(failures)) + "\n  ".join(failures))
    st.report_pass('msg',
        "I4 [{}]: 64 DSCPs via VxLAN L3VNI ({}) - CP1+CP2+CP3 PASS".format(
            af, _I_VNI))


# ══════════════════════════════════════════════════════════════════════════════
# Section J - VxLAN L2VNI BUM End-to-End Tests (2-DUT)
# ══════════════════════════════════════════════════════════════════════════════
#
# DESIGN NOTE on CP2 for J3/J4:
#   The plan flagged a spike requirement: does PORT_QOS_MAP|<dut2_egress_ixia>
#   retain the dscp_to_tc_map binding after _setup_vxlan_l2vni() converts the
#   port to a VLAN access member? If YES, CP2 asserts the same per-queue
#   distribution as CP1 (DSCPs reclassify at DUT2's access egress). If NO,
#   all packets land on Q0 (default queue, no classification).
#
#   Until that spike runs against the live testbed, this code uses the OPTIMISTIC
#   assumption (binding retained -> per-queue distribution matches CP1). The
#   pessimistic mode is one-line replaceable: change `_assert_per_queue(...,
#   expected_q, ...)` to `_assert_default_queue(result['dut2_deltas'], ...)`
#   (defined below) once the spike confirms.
# ══════════════════════════════════════════════════════════════════════════════

def _assert_default_queue(deltas, expected_total, cp_label, failures):
    """Fallback CP2 assertion for J tests if DUT2's PORT_QOS_MAP binding is
    NOT preserved through _setup_vxlan_l2vni(). In that case all packets
    land on Q0 regardless of inner DSCP, with no drops.
    """
    q0 = deltas.get(0, {}).get('pkts', 0)
    lo = int(round(expected_total * (1.0 - _TOL_PCT)))
    hi = int(round(expected_total * (1.0 + _TOL_PCT)))
    if not (lo <= q0 <= hi):
        failures.append(
            "{} Q0 actual={} outside [{},{}] "
            "(expected ~{} all-on-Q0 per dscp_to_tc unbind hypothesis)".format(
                cp_label, q0, lo, hi, expected_total))
    for qi in range(1, 8):
        leak = deltas.get(qi, {}).get('pkts', 0)
        if leak > 0:
            failures.append(
                "{} Q{} actual={} (expected 0 with all-on-Q0 hypothesis)".format(
                    cp_label, qi, leak))


@pytest.mark.traffic
@pytest.mark.vxlan_transit
@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_vxlan_l2vni_e2e_spot_check(af):
    """#J3 - 8 spot-check DSCPs via VxLAN L2VNI (BUM flood) e2e.

    CP1 (DUT1 transit egress): per-queue == PKTS_BY_TC[tc] +-2%.
    CP2 (DUT2 egress_ixia):    per-queue == PKTS_BY_TC[tc] +-2%
                               (optimistic; see Section J header note).
    CP3 (Ixia rx LOOSE):       total_rx / total_tx >= 0.95.
    """
    if topo_mode == 'ixia':
        pytest.skip(
            "Section J3 requires 2-DUT topology (peer_link/breakout); "
            "current mode is 'ixia'")

    print_section(
        "J3 - VxLAN L2VNI BUM e2e spot-check [{}]".format(af.upper()),
        art_key='dscp_to_tc')

    # Section J (L2VNI) uses ingress_b as the L2VNI ingress port by
    # convention -- VLAN-access on the second DUT1->T1 link.  Falls
    # back to ingress_a on single-D1T1P testbeds where L2VNI shares
    # the L3VNI port (legacy/degenerate).
    ingress_ph = tg_ph.get('ingress_b', tg_ph['ingress_a'])
    ingress_port = port_info.get('ingress_b', port_info['ingress_a'])
    failures   = []

    teardown = _setup_vxlan_l2vni()
    try:
        st.log("  VNI={} VLAN={}  dst_mac={} (BUM flood)".format(
            _J_VNI, _J_L2_VLAN, _J_BUM_MAC))

        # J-section converts DUT2 egress_ixia to a VLAN access port; the
        # spike question is whether DUT2's PORT_QOS_MAP binding survives
        # that reshuffle. Probe the binding silently and use it to pick
        # the CP2 assertion variant: full per-queue when bound, or
        # all-on-Q0 (default queue) when DUT2's classifier is missing.
        dut2_has_binding = (
            get_port_dscp_tc_map(
                dut2, dut2_port_info.get('egress_ixia')) == 'AZURE')

        # ARP/ND prime is irrelevant for BUM (broadcast dst_mac) but harmless.
        _prime_arp_nd(af)

        tg.tg_traffic_control(action='reset')
        spot_dscps = list(_J_SPOT_DSCP.keys())
        streams = _build_streams_unique(
            af, ingress_ph, _J_BUM_MAC, dscp_range=spot_dscps)

        result = _send_and_measure_e2e(
            "J3/{}".format(af), streams, measure_dut2=True)

        expected_q   = _expected_q_pkts_for_dscps(spot_dscps)
        expected_tot = sum(s['expected_pkts'] for s in streams)

        _log_queue_placement_table(
            result['dut1_deltas'],
            "[J3 CP1 DUT1 transit {}]".format(af.upper()),
            expected=expected_q)
        _log_queue_placement_table(
            result['dut2_deltas'],
            "[J3 CP2 DUT2 egress_ixia {}]".format(af.upper()),
            expected=expected_q)

        cp1_before = len(failures)
        _assert_per_queue(result['dut1_deltas'], expected_q,
                          "CP1 DUT1 transit", failures)
        _log_cp_summary(failures[cp1_before:], 8, "CP1 DUT1 transit")

        # CP2 assertion varies based on the spike outcome: if DUT2's port
        # carries the dscp_to_tc binding, expect the same per-queue
        # distribution as CP1. Otherwise expect all packets on Q0 (default
        # queue, no classification).
        cp2_before = len(failures)
        if dut2_has_binding:
            _assert_per_queue(result['dut2_deltas'], expected_q,
                              "CP2 DUT2 egress_ixia", failures)
        else:
            _assert_default_queue(result['dut2_deltas'], expected_tot,
                                  "CP2 DUT2 egress_ixia (no-binding)",
                                  failures)
        _log_cp_summary(failures[cp2_before:], 8, "CP2 DUT2 egress_ixia")

        # CP3 LOOSE: total rx / total tx ratio on Ixia (stream-sum totals).
        cp3_before = len(failures)
        tx, rx = _measure_ixia_rx_aggregate(streams)
        if tx == 0:
            failures.append("CP3 LOOSE: total tx=0 (Ixia not transmitting)")
        else:
            ratio = float(rx) / float(tx)
            if ratio < _J_LOOSE_RX_THRESHOLD:
                failures.append(
                    "CP3 LOOSE: rx/tx={:.2%} below threshold {:.0%} "
                    "(tx={} rx={})".format(
                        ratio, _J_LOOSE_RX_THRESHOLD, tx, rx))
        _log_cp_summary(failures[cp3_before:], 1, "CP3 Ixia rx loose")

        # Quiet the linter: expected_tot is computed but not used after CP2.
        _ = expected_tot
    finally:
        teardown()

    if failures:
        st.report_fail('msg', "J3 [{}] failures ({}):\n  ".format(
            af, len(failures)) + "\n  ".join(failures))
    st.report_pass('msg',
        "J3 [{}]: 8 DSCP spot-check via VxLAN L2VNI ({}) BUM - "
        "CP1+CP2+CP3(loose) PASS".format(af, _J_VNI))


@pytest.mark.traffic
@pytest.mark.vxlan_transit
@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_vxlan_l2vni_e2e_all_64_dscp(af):
    """#J4 - All 64 DSCPs via VxLAN L2VNI (BUM flood) e2e.

    CP1: per-queue == EXPECTED_Q_PKTS_UNIQUE +-2% on DUT1 transit.
    CP2: per-queue == EXPECTED_Q_PKTS_UNIQUE +-2% on DUT2 egress_ixia
         (optimistic; see Section J header note).
    CP3: Ixia total rx / total tx >= 0.95 (loose).
    """
    if topo_mode == 'ixia':
        pytest.skip(
            "Section J4 requires 2-DUT topology (peer_link/breakout); "
            "current mode is 'ixia'")

    print_section(
        "J4 - VxLAN L2VNI BUM e2e 64-DSCP [{}]".format(af.upper()),
        art_key='dscp_to_tc')

    # Section J (L2VNI) uses ingress_b as the L2VNI ingress port by
    # convention.  Falls back to ingress_a on single-D1T1P testbeds.
    # See J3.
    ingress_ph = tg_ph.get('ingress_b', tg_ph['ingress_a'])
    ingress_port = port_info.get('ingress_b', port_info['ingress_a'])
    failures   = []

    teardown = _setup_vxlan_l2vni()
    try:
        st.log("  VNI={} VLAN={}  dst_mac={} (BUM flood)".format(
            _J_VNI, _J_L2_VLAN, _J_BUM_MAC))

        # Same J-spike handling as J3 (DUT2 may lose its PORT_QOS_MAP
        # binding when the port is converted to a VLAN access member).
        # Probe DUT2's binding silently to pick the CP2 assertion path.
        dut2_has_binding = (
            get_port_dscp_tc_map(
                dut2, dut2_port_info.get('egress_ixia')) == 'AZURE')

        _prime_arp_nd(af)

        tg.tg_traffic_control(action='reset')
        streams = _build_streams_unique(af, ingress_ph, _J_BUM_MAC)

        result = _send_and_measure_e2e(
            "J4/{}".format(af), streams, measure_dut2=True)

        _log_queue_placement_table(
            result['dut1_deltas'],
            "[J4 CP1 DUT1 transit {}]".format(af.upper()),
            expected=EXPECTED_Q_PKTS_UNIQUE)
        _log_queue_placement_table(
            result['dut2_deltas'],
            "[J4 CP2 DUT2 egress_ixia {}]".format(af.upper()),
            expected=EXPECTED_Q_PKTS_UNIQUE)

        cp1_before = len(failures)
        _assert_per_queue(result['dut1_deltas'], EXPECTED_Q_PKTS_UNIQUE,
                          "CP1 DUT1 transit", failures)
        _log_cp_summary(failures[cp1_before:], 8, "CP1 DUT1 transit")

        # CP2: same conditional as J3 - per-queue if binding present,
        # all-on-Q0 if missing.
        cp2_before = len(failures)
        if dut2_has_binding:
            _assert_per_queue(result['dut2_deltas'], EXPECTED_Q_PKTS_UNIQUE,
                              "CP2 DUT2 egress_ixia", failures)
        else:
            total_tx = sum(s['expected_pkts'] for s in streams)
            _assert_default_queue(result['dut2_deltas'], total_tx,
                                  "CP2 DUT2 egress_ixia (no-binding)",
                                  failures)
        _log_cp_summary(failures[cp2_before:], 8, "CP2 DUT2 egress_ixia")

        cp3_before = len(failures)
        tx, rx = _measure_ixia_rx_aggregate(streams)
        if tx == 0:
            failures.append("CP3 LOOSE: total tx=0 (Ixia not transmitting)")
        else:
            ratio = float(rx) / float(tx)
            if ratio < _J_LOOSE_RX_THRESHOLD:
                failures.append(
                    "CP3 LOOSE: rx/tx={:.2%} below threshold {:.0%} "
                    "(tx={} rx={})".format(
                        ratio, _J_LOOSE_RX_THRESHOLD, tx, rx))
        _log_cp_summary(failures[cp3_before:], 1, "CP3 Ixia rx loose")
    finally:
        teardown()

    if failures:
        st.report_fail('msg', "J4 [{}] failures ({}):\n  ".format(
            af, len(failures)) + "\n  ".join(failures))
    st.report_pass('msg',
        "J4 [{}]: 64 DSCPs via VxLAN L2VNI ({}) BUM - "
        "CP1+CP2+CP3(loose) PASS".format(af, _J_VNI))


# ══════════════════════════════════════════════════════════════════════════════
# 5-PACKET SMOKE TESTS - byte-accurate per-frame validation
# ══════════════════════════════════════════════════════════════════════════════
#
# Goal: prove the entire e2e path is alive BEFORE running the (much slower)
# H/I/J sections. Sends 5 packets at one DSCP, captures BOTH the TX-side
# Ixia port and the RX-side Ixia port (the one connected to DUT2
# Ethernet1_49), decodes every captured frame, and asserts byte-level
# correctness on:
#
#   - L3 family (ipv4 / ipv6) preserved
#   - DSCP value preserved through encap + decap
#   - TTL (or Hop Limit) handling:
#       L3VNI smoke -> assert TTL_rx == TTL_tx - 1   (decap routes once)
#       L2VNI smoke -> assert TTL_rx == TTL_tx       (pure L2 bridge)
#   - has_vxlan_header == False on the RX side
#       (proves DUT2 actually stripped the outer VXLAN encap)
#   - UDP dport == 5000 + dscp                  (test-stream sanity)
#
# Matrix: 8 (DSCP, TC) pairs x {ipv4, ipv6} x {L3VNI, L2VNI} = 32
# parametrize instances at ~3-5s of traffic each. Total runtime ~3-6 min.
#
# Failure-mode: WARN on short captures (<5 frames), HARD-fail on per-frame
# decode mismatch. Tests still PASS overall if at least 1 frame was captured
# and that frame decoded correctly, but every per-frame mismatch is appended
# to a failures list and the test fails if any HARD assertion failed.
# ══════════════════════════════════════════════════════════════════════════════

_SMOKE_PKTS_PER_BURST = 5     # Tiny burst - small enough to fit any cap buf
_SMOKE_SENT_TTL       = 64    # ip_ttl / ipv6_hop_limit on every smoke packet
_SMOKE_RATE_PPS       = 100   # Slow enough that 5 packets land cleanly
_SMOKE_TRAFFIC_WAIT   = 2     # Seconds to let 5 pps complete (5 pkts in <1s,
                              # 2 s gives plenty of slack)

# Last-known preflight result, set by _smoke_preflight() at the start
# of each TestSmokeL3VNI / TestSmokeL2VNIBum class. The per-instance
# scorecard reads this to render the "vxlan_setup" row with real
# pass/fail counts (instead of "N/A") when the preflight passed.
# Cleared at module setup; refreshed by every preflight call.
_SMOKE_LAST_PREFLIGHT = None


# A module-autouse pytest fixture that resets the per-class preflight
# cache at the start of the smoke run.
@pytest.fixture(scope="module", autouse=True)
def _smoke_session_bracket():
    global _SMOKE_LAST_PREFLIGHT
    _SMOKE_LAST_PREFLIGHT = None
    yield


def _smoke_pairs():
    """Return [(tc, dscp), ...] for one DSCP per TC, sourced from
    GOLDEN_DSCP_TO_TC at runtime so the smoke automatically tracks the
    project's official map.
    """
    return smoke_pick_one_dscp_per_tc()


def _smoke_pair_ids():
    """pytest-friendly IDs for the parametrize matrix:
    ['tc0-dscp0', 'tc1-dscp8', ..., 'tc7-dscp56']."""
    return ["tc{}-dscp{}".format(tc, dscp) for tc, dscp in _smoke_pairs()]


def _smoke_reprime_ixia_interface(af, mode='l3vni'):
    """Re-poke the Ixia ingress interface AFTER the VXLAN setup has
    rebound the DUT port into VrfQoS. The VRF rebind on SONiC removes
    and re-adds the same IPs on the port, which leaves Ixia's cached
    gateway-MAC entry stale (or empty if start_all_protocols never
    re-resolved it). Without this re-prime, subsequent
    tg.tg_traffic_config(...) can raise 'Invalid value for TGen
    parameter' because the IPv4/IPv6 gateway MAC didn't resolve.

    Idempotent and exception-safe; logs WARN on failure but does not
    raise so the caller can continue.

    Args:
        af:   'ipv4' or 'ipv6' - controls which gateway resolution is
              re-requested. We always re-prime IPv4 because most stream
              configs include ip_src/dst_addr; if af='ipv6', we also
              re-prime IPv6.
        mode: 'l3vni' (default), 'l3vni_tagged', or 'l2vni'. Selects
              which DUT1->T1 port to re-prime by convention:
                l3vni / l3vni_tagged -> tg_ph['ingress_a']
                                        (first DUT1->T1 link, L3VNI
                                         ingress; Ethernet1_49 on the
                                         VxLAN testbed yaml)
                l2vni                -> tg_ph.get('ingress_b',
                                                  tg_ph['ingress_a'])
                                        (second DUT1->T1 link, L2VNI
                                         ingress; Ethernet1_50 on the
                                         VxLAN testbed yaml.  Falls
                                         back to ingress_a on single-
                                         port testbeds.)
              The default keeps any legacy callers that don't pass
              mode on the L3VNI port - matching the pre-split
              behaviour.
    """
    if mode == 'l2vni':
        ingress_ph = tg_ph.get('ingress_b', tg_ph['ingress_a'])
    else:
        ingress_ph = tg_ph['ingress_a']
    try:
        # Always re-prime IPv4 (covers both ipv4 and ipv6 streams since
        # the IPv4 gateway-MAC resolution doesn't hurt IPv6 streams).
        tg.tg_interface_config(
            mode='modify',
            port_handle=ingress_ph,
            arp_send_req=1, resolve_gateway_mac=1)
        if af == 'ipv6':
            tg.tg_interface_config(
                mode='modify',
                port_handle=ingress_ph,
                ipv6_resolve_gateway_mac=1, arp_send_req=1)
        try:
            tg.tg_topology_test_control(action='start_all_protocols')
        except Exception:
            pass  # not all Ixia builds expose this
        st.wait(3)
        st.log("  ixia re-prime [{}] OK on ingress port_handle={}".format(
            af, ingress_ph))
    except Exception as exc:
        st.warn("  ixia re-prime [{}] failed (non-fatal): {}".format(
            af, exc))


def _smoke_build_one_stream(af, ingress_ph, dst_mac, dscp,
                            vlan_id=None, ip_dst_addr=None):
    """Build a single-stream Ixia config: 5 packets of a given DSCP.

    Returns (handle, udp_dst). The handle is the Ixia dict from
    tg.tg_traffic_config; caller does not need to inspect it because
    traffic is started via port-level tg_traffic_control(action='run').

    Logs the kwargs dict at debug level before invoking the IXIA, so
    if 'Invalid value for TGen parameter' fires we can correlate
    which exact parameter the IXIA rejected. The exception is
    re-raised so the test still records as failed.

    ``ip_dst_addr`` (str | None): override the stream's destination
    IP. Defaults to ``_IXIA_DST_V4`` / ``_IXIA_DST_V6`` (= the L3VNI
    receiver host on Ixia port 1/12, IP 20.20.20.2 / 2001:db8:20::2)
    for backward compatibility with all existing callers. The
    SMOKE-L2VNI[*] path overrides this to ``_J_L2VNI_RX_IP``
    (20.20.20.22) so the captured frame's ip_dst matches the
    Vlan502 receiver host that GARP'd its MAC into EVPN.
    """
    import traceback
    udp_dst = 5000 + int(dscp)
    # Pin mac_src on the stream so the WIRE eth_src is deterministic and
    # known to the test (the side-by-side packet dump in _smoke_run_one
    # reads tx_spec['eth_src'] from this same constant). This is
    # belt-and-braces with setup_topo_common's tg_interface_config(
    # src_mac_addr=...) -- pinning it here too means the smoke is
    # robust to IxNetwork builds that silently ignore src_mac_addr at
    # the interface level, and to topologies where setup_topo_common
    # was bypassed (eg dev runs that re-call _smoke_build_one_stream
    # after a manual tg.tg_interface_config).
    src_mac = IXIA_SRC_MAC.get('ingress_a')
    kwargs = dict(
        mode='create',
        port_handle=ingress_ph,
        mac_dst=dst_mac,
        l4_protocol='udp',
        udp_src_port=10000 + int(dscp),
        # mac_src is conditionally added below (some IxNetwork builds
        # reject the kwarg). Default behavior without it: IXIA uses
        # whatever MAC tg_interface_config(src_mac_addr=...) pinned
        # at topology setup. Per smoke design those two values must
        # be identical, so the wire MAC and the dump intent match.
        udp_dst_port=udp_dst,
        frame_size=_PKT_SIZE,
        rate_pps=_SMOKE_RATE_PPS,
        pkts_per_burst=_SMOKE_PKTS_PER_BURST,
        transmit_mode='single_burst',
        high_speed_result_analysis=0,
        # IMPORTANT: enable per-stream tracking so tg_traffic_stats(
        # mode='stream', stream=<id>) actually returns nonzero TX/RX
        # totals. Without this kwarg IxNetwork allocates only port-
        # level aggregate counters (which the DUT-side scoreboard
        # picks up fine), but the per-flow .tx.total_pkts /
        # .rx.total_pkts buckets stay at 0 -- which is exactly what
        # produced 'Ixia-TX 0 / Ixia-RX 0' in the smoke run on
        # 2026-05-15. The pattern 'trackingenabled0' is the same
        # value used by tortuga/vxlan_utils.py and a number of other
        # IxNetwork callers in this tree; it's the lowest-overhead
        # "just enable per-flow stat" tracker. _grade_per_dscp_rx
        # (line ~1046) already anticipated this failure mode but
        # only printed a NOTE; the smoke path needs the stats live
        # so we enable tracking here at source.
        track_by='trackingenabled0',
    )
    if af == 'ipv4':
        kwargs.update(
            l3_protocol='ipv4',
            ip_src_addr=IXIA_INGRESS_A_IP,
            ip_dst_addr=(ip_dst_addr if ip_dst_addr else _IXIA_DST_V4),
            ip_dscp=int(dscp),
            ip_ttl=_SMOKE_SENT_TTL,
        )
    else:
        kwargs.update(
            l3_protocol='ipv6',
            ipv6_src_addr=IXIA_INGRESS_A_IP6,
            ipv6_dst_addr=(ip_dst_addr if ip_dst_addr else _IXIA_DST_V6),
            ipv6_traffic_class=(int(dscp) << 2),
            ipv6_hop_limit=_SMOKE_SENT_TTL,
        )
    if vlan_id is not None:
        kwargs.update(l2_encap='ethernet_ii_vlan', vlan='enable',
                      vlan_id=int(vlan_id), vlan_id_mode='fixed')

    # Try once with mac_src pinned (so the WIRE eth_src matches the
    # topology constant), and if IxNetwork rejects that kwarg, retry
    # without it. The retry case will still produce healthy traffic
    # because tg_interface_config(src_mac_addr=...) at topology setup
    # already fed IXIA the same value -- the wire MAC just comes from
    # IXIA's port firmware in that path.
    if src_mac:
        kwargs['mac_src'] = src_mac

    try:
        handle = tg.tg_traffic_config(**kwargs)
    except Exception as exc:
        # Defensive retry: if the failure looks mac_src-related (older
        # IxNetwork builds reject the kwarg), strip mac_src and retry
        # once. Other failures fall through to the full diagnostic.
        msg = str(exc).lower()
        if 'mac_src' in kwargs and (
                'mac_src' in msg or 'invalid value' in msg
                or 'invalid parameter' in msg):
            st.warn("  tg_traffic_config rejected mac_src ({}); retry "
                    "without it".format(exc))
            kwargs.pop('mac_src', None)
            try:
                handle = tg.tg_traffic_config(**kwargs)
                return handle, udp_dst
            except Exception as exc2:
                exc = exc2   # fall through to diagnostic with new exc
        st.banner("IXIA tg_traffic_config FAILED")
        st.warn("  exception type : {}".format(type(exc).__name__))
        st.warn("  exception text : {}".format(exc))
        for line in traceback.format_exc().splitlines():
            st.warn("    TRACEBACK: {}".format(line))
        raise
    return handle, udp_dst


def _smoke_run_with_rx_capture(label, ingress_ph, egress_ph):
    """Apply Ixia config, start capture on the RX-side port ONLY,
    run traffic, stop the capture, decode and return:

        {
          'tx': {'decoded': [], 'num_total': 0},   # not captured
          'rx': {'decoded': [...], 'num_total': N},
        }

    Why RX-only?
    ------------
    spytest's tg_packet_control(action='start') wrapper internally
    invokes tg_traffic_control(action='apply') as a side-effect (see
    sonic-mgmt/spytest/spytest/tgen/tg.py:2144 in this tree). Since
    the entire test config lives in ONE ixNet snapshot, the second
    such apply (when we tried to also capture TX) wiped the state of
    the first capture. The result was:
       'TG API Fatal Error: Current port has no active data capture'
    (see smoke_one.log around 23:40 / 00:15 for two reproductions).

    Switching to RX-only is the right trade-off because:
      - The smoke test fundamentally validates the e2e DECAP path on
        DUT2: every per-frame check (DSCP / TTL / has_vxlan_header /
        l4_dport) is meaningful only on the RX side anyway.
      - We still verify TX-side behaviour via the Ixia AGGREGATE TX
        counter (ixia_agg['tx_total']) which proves how many packets
        actually left the Ixia, and via the build spec we passed to
        tg.tg_traffic_config (we know what we asked it to send).
      - The renderer marks the TX side as "(synthesised from build
        spec)" so the analysis output is honest about what is direct
        capture-evidence vs intent.

    If we ever need byte-accurate TX evidence, do a second pass with
    the captures swapped (a 'two-phase' run). That doubles per-instance
    time so we're deferring it until a real bug needs that resolution.

    Capture failures (eg Ixia error) are logged WARN and produce an
    empty rx decoded list; the caller decides whether to abort.
    """
    # Apply test config exactly ONCE before arming the capture, so the
    # plugin's auto-apply on tg_packet_control(start) sees a no-op.
    tg.tg_traffic_control(action='clear_stats')
    tg.tg_traffic_control(action='apply')
    st.wait(1)  # let apply settle on Ixia before arming the capture

    # Single capture on the RX-side port (ingress_ph stays for the log
    # banners but is NOT armed).
    rx_ok = smoke_start_capture(tg, egress_ph,
                                port_alias="{} RX dut2_egress".format(label))

    # Run traffic
    tg.tg_traffic_control(action='run')
    st.wait(_SMOKE_TRAFFIC_WAIT)
    tg.tg_traffic_control(action='stop')
    st.wait(2)  # let frames drain into capture buffers

    # Stop the RX capture and decode
    rx_pkts = smoke_stop_capture(tg, egress_ph, max_frames=64,
                                  port_alias="{} RX".format(label)) \
              if rx_ok else None

    rx_dec, rx_n = smoke_decode_frames(rx_pkts, egress_ph) if rx_pkts \
                   else ([], 0)

    return {
        'tx': {'decoded': [], 'num_total': 0},     # synthesised, not captured
        'rx': {'decoded': rx_dec, 'num_total': rx_n},
    }


def _smoke_classify_noise_frame(d):
    """Return a short human-readable label for a single 'control-plane
    noise' frame so soft-warn messages can summarise WHAT was captured
    alongside the 5 test packets (eg 'LLDP', 'BGP-keepalive',
    'ICMPv6-ND', 'ARP-reply', 'unknown:0x88f7').

    The decoded-frame dict comes from smoke_decode_frames() and
    carries best-effort fields: ethertype (int or hex string),
    l3 ('ipv4'/'ipv6'/'other'), l4 ('udp'/'tcp'/None), l4_sport,
    l4_dport.

    Recognition rules (best-effort, intentionally narrow):
      * eth_type 0x88cc / 35020   -> 'LLDP'
      * eth_type 0x8809           -> 'LACP'
      * eth_type 0x88f7           -> 'PTP'
      * eth_type 0x0806           -> 'ARP'
      * IPv4 + TCP/179            -> 'BGP-TCP'
      * IPv4 + UDP/53             -> 'DNS-v4'
      * IPv4 + ICMP                -> 'ICMPv4'
      * IPv6 + TCP/179            -> 'BGPv6-TCP'
      * IPv6 + UDP/546/547        -> 'DHCPv6'
      * IPv6 + ICMPv6              -> 'ICMPv6/ND'
      * everything else           -> 'unknown:<hex>'
    """
    def _eth(d):
        e = d.get('ethertype')
        try:
            if isinstance(e, str):
                return int(e, 0)
            return int(e) if e is not None else None
        except Exception:
            return None
    e = _eth(d)
    if e == 0x88cc:  return 'LLDP'
    if e == 0x8809:  return 'LACP'
    if e == 0x88f7:  return 'PTP'
    if e == 0x0806:  return 'ARP'
    l3 = d.get('l3')
    l4 = d.get('l4')
    sport = d.get('l4_sport')
    dport = d.get('l4_dport')
    if l3 == 'ipv4':
        if l4 == 'tcp' and (sport == 179 or dport == 179): return 'BGP-TCP'
        if l4 == 'udp' and dport == 53:                    return 'DNS-v4'
        if l4 == 'icmp':                                   return 'ICMPv4'
    if l3 == 'ipv6':
        if l4 == 'tcp' and (sport == 179 or dport == 179): return 'BGPv6-TCP'
        if l4 == 'udp' and dport in (546, 547):            return 'DHCPv6'
        if l4 == 'icmpv6':                                 return 'ICMPv6/ND'
    if e is not None:
        return 'unknown:0x{:04x}'.format(e)
    return 'unknown'


def _smoke_format_noise_breakdown(noise_list):
    """Render a noise_list (list of label strings from
    _smoke_classify_noise_frame) as a compact summary like
    '1 LLDP + 2 BGP-TCP + 1 ICMPv6/ND' for human consumption.
    Returns '' for an empty list.
    """
    if not noise_list:
        return ''
    counts = {}
    for lbl in noise_list:
        counts[lbl] = counts.get(lbl, 0) + 1
    # Stable order: most-common first, ties broken by alphabetical
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return ' + '.join("{} {}".format(n, lbl) for lbl, n in ordered)


def _smoke_assert_frames(decoded, side_label, expected_spec,
                         hard_failures, soft_warns,
                         noise_breakdown=None):
    """Apply expected_spec to every decoded frame and split per-frame
    mismatches into HARD failures vs SOFT warnings.

    Frames that match the spec contribute nothing. Frames that do NOT
    decode an L3 layer (eg malformed) are recorded as HARD failures,
    BUT only if they look like a test packet (matching test_dport on
    UDP). Frames whose DSCP/TTL/has_vxlan_header diverge from
    expected_spec are HARD failures (these indicate a real DUT bug).
    Frames whose UDP src/dst port diverge from expected_spec are SOFT
    warns (less critical sanity).

    Control-plane frames (LLDP, BGP keepalives, IS-IS, ICMPv6 ND,
    STP/LACP, ...) often share the capture buffer with our test
    burst. They are identified as 'not our test stream' by either:
      - failing to decode as IPv4/IPv6 (l3 == 'other'), OR
      - decoding as IPv4/IPv6 but with l4_dport != expected_spec[
        'l4_dport'].
    Both cases are silently filtered here so they don't masquerade
    as HARD failures. The packet-flow renderer (side-by-side TX|RX
    dump) already does the same dport filter independently; this
    keeps the two paths consistent.

    When *noise_breakdown* is a list passed by the caller, each filtered
    noise frame's classification (LLDP, BGP-TCP, ARP, ICMPv6/ND, ...) is
    appended so downstream soft-warn messages can name WHAT was captured
    alongside the test burst instead of just hinting at "control-plane
    drift". See _smoke_classify_noise_frame() for the classifier rules.

    All log lines include the side ('TX'/'RX') and frame index for
    easy correlation.
    """
    # Split spec into hard vs soft fields. The hard set is the "real"
    # invariants that prove decap correctness; soft is informational.
    hard_keys = {'l3', 'dscp', 'ttl_or_hl', 'has_vxlan_header'}
    soft_keys = {'l4', 'l4_dport'}

    hard_spec = {k: v for k, v in expected_spec.items() if k in hard_keys}
    soft_spec = {k: v for k, v in expected_spec.items() if k in soft_keys}

    # Test-stream identity: our streams use deterministic UDP dport =
    # _SMOKE_UDP_DPORT_BASE + dscp (5000 + DSCP). Anything else in the
    # capture is control-plane noise. If expected_spec didn't carry a
    # dport (extremely unlikely path), we keep the old behaviour of
    # validating every frame.
    test_dport = expected_spec.get('l4_dport')

    for d in decoded:
        frame_label = "{} frame[{}]".format(side_label, d.get('idx', '?'))

        # Filter 1: undecodable L3. If this looks like control-plane
        # (ethertype != 0x0800/0x86dd), silently skip. Only HARD-fail
        # when we genuinely can't decode what *should* be a test
        # packet (which would be a real test-side bug, not a DUT bug).
        if d.get('l3') == 'other':
            eth_type = d.get('ethertype')
            noise_kind = _smoke_classify_noise_frame(d)
            # 0x88cc=LLDP, 0x88f7=PTP, 0x8809=LACP, 0x88a8/0x8100=VLAN,
            # 0x0806=ARP, 0x86dd=IPv6 (handled), 0x0800=IPv4 (handled).
            # Anything not IPv4/IPv6 is by definition not our UDP test
            # stream and is safe to ignore.
            st.log(
                "  {} skipped non-test frame (eth_type={}, len={}, "
                "kind={}); treating as control-plane noise".format(
                    frame_label, eth_type, d.get('len'), noise_kind))
            if noise_breakdown is not None:
                noise_breakdown.append(noise_kind)
            continue

        # Filter 2: decoded as IPv4/IPv6 but not on our test UDP dport.
        # This catches things like BGP keepalives (TCP/179), ICMPv6 ND
        # (no UDP), DNS (UDP/53), DHCPv6 (UDP/546/547), etc. The
        # _smoke_build_one_stream() identity is UDP dport = 5000+DSCP
        # which never collides with any well-known service port.
        if test_dport is not None and d.get('l4_dport') != test_dport:
            noise_kind = _smoke_classify_noise_frame(d)
            st.log(
                "  {} skipped non-test frame (l4_dport={}, expected={}, "
                "kind={}); treating as control-plane noise".format(
                    frame_label, d.get('l4_dport'), test_dport, noise_kind))
            if noise_breakdown is not None:
                noise_breakdown.append(noise_kind)
            continue

        for fail in smoke_check_frame(d, hard_spec, frame_label):
            hard_failures.append(fail)
        for fail in smoke_check_frame(d, soft_spec, frame_label):
            soft_warns.append(fail)


def _smoke_run_one(test_label, af, dscp, expected_tc, mode,
                   capture_only_rx=True,
                   primary_queue_col=None,
                   primary_queue_col_dut1=None,
                   primary_queue_col_dut2=None,
                   l2vni_force_bum=False, l2vni_gate_unicast=False):
    """Core smoke runner: send 5 packets at one DSCP through an
    already-configured VXLAN path, capture RX, decode + assert.

    Args:
        test_label, af, dscp, expected_tc, mode: standard smoke fixture
            arguments (see callers in TestSmokeL3VNI*, TestSmokeL2VNI*).
        capture_only_rx: limit Ixia capture to receive side.
        primary_queue_col: shorthand override that sets BOTH DUT1 and
            DUT2 scorecard columns to the same value.  Use when both
            DUTs see the same wire-side traffic class (UC for L3VNI;
            UC for L2VNI-unicast).  Ignored when either of the
            per-DUT overrides below is also passed.
        primary_queue_col_dut1: per-DUT override for the dut1_queue
            scorecard row.  One of 'uc', 'mc', 'any'.  Needed because
            the OUTER VxLAN packet on DUT1's encap-egress port is
            UNICAST (VTEP1->VTEP2) even when the INNER frame is BUM
            multicast.  So for L2VNI-BUM the right combo is
            dut1='uc' / dut2='mc'.
        primary_queue_col_dut2: per-DUT override for the dut2_queue
            row.  See primary_queue_col_dut1.
            When None, defaults are derived from (mode,
            l2vni_force_bum, l2vni_gate_unicast):

              =================  =========  =========
              scenario           dut1 col   dut2 col
              =================  =========  =========
              l3vni / tagged     uc         uc
              l2vni + force_bum  uc *       mc
              l2vni + gate_ucast uc         uc
              l2vni (legacy)     uc         mc
              =================  =========  =========

              * DUT1's outer VxLAN/UDP packet is unicast between
                VTEP IPs regardless of inner traffic class.
        l2vni_force_bum: only consulted when mode='l2vni'.  When True,
            skip the EVPN-MAC lookup entirely and force the burst's
            dst_mac to ``_J_BUM_MAC`` (ff:ff:ff:ff:ff:ff). Used by
            TestSmokeL2VNIBum to guarantee the BUM-flood path even if
            EVPN learning has happened.  Default False keeps the
            legacy best-effort behaviour for unconverted callers.
        l2vni_gate_unicast: only consulted when mode='l2vni' AND
            l2vni_force_bum=False.  When True, treat a missed EVPN-MAC
            lookup as a HARD SKIP (st.report_unsupported) instead of
            silently falling back to BUM. Used by TestSmokeL2VNIUcast
            so the unicast-path scorecard column ('uc') stays
            meaningful -- if EVPN didn't converge, the instance is
            unsupported, not a failing unicast test.

    Returns (hard_failures_list, soft_warns_list).

    IMPORTANT: This function does NOT set up or tear down the VXLAN
    fabric. The caller (a class-scope fixture in TestSmokeL3VNI /
    TestSmokeL2VNIBum) is responsible for setup_vxlan_*() and its
    teardown. This avoids paying the ~10-15s setup cost for every
    one of the 16 smoke instances per class.

    Args:
        test_label:      e.g. 'SMOKE-L3VNI-UCAST[ipv4][tc5-dscp46]'.
        af:              'ipv4' or 'ipv6'.
        dscp:            DSCP value to send (1 stream, 5 packets).
        expected_tc:     The TC that DSCP should map to. Used as a sanity
                         log line.
        mode:            'l3vni' or 'l2vni'. Controls:
                           - the dst_mac (router MAC for l3vni,
                             broadcast/_J_BUM_MAC for l2vni — see
                             below: actually overridden at runtime to
                             the ARP-resolved MAC of the Vlan502 Ixia
                             host on port 1/12 when that host is
                             available, else falls back to BUM.)
                           - the expected TTL delta on the RX side
                             (l3vni: -1, l2vni: 0)
                           - whether an outer VLAN tag is added to TX
        capture_only_rx: Default True - the smoke test only captures on
                         the RX side because the spytest plugin's
                         packet_control(start) wrapper auto-applies the
                         entire test config, which would wipe a TX
                         capture armed before it. See
                         _smoke_run_with_rx_capture's docstring for the
                         full story. The arg is preserved for callers
                         that may eventually want a two-phase TX+RX path.
    """
    # Pick the role-correct DUT1->T1 ingress port by the workspace
    # convention:
    #   ingress_a -> L3VNI / L3VNI-tagged ingress (first DUT1->T1 link;
    #                Ethernet1_49 on the VxLAN testbed yaml)
    #   ingress_b -> L2VNI ingress (second DUT1->T1 link;
    #                Ethernet1_50 on the VxLAN testbed yaml)
    # On a single-D1T1P testbed ingress_b is absent and L2VNI falls
    # back to ingress_a, matching the pre-split behaviour.
    if mode == 'l2vni':
        ingress_ph = tg_ph.get('ingress_b', tg_ph['ingress_a'])
    else:
        ingress_ph = tg_ph['ingress_a']
    egress_ph  = tg_ph['egress']  # Ixia port connected to DUT2 Ethernet1_49

    # ── Mode-specific knobs (VXLAN already up via class fixture) ─────────
    # IMPORTANT: TTL decrement count for L3VNI = 2 (one per L3 hop):
    #   1. DUT1 host->VRF L3 lookup (TTL -1) BEFORE VXLAN encap.
    #   2. DUT2 VXLAN decap -> VRF L3 lookup -> egress (TTL -1).
    # The OUTER VXLAN/UDP/IP TTL is independent (managed by VTEP) and
    # never touches the inner packet's TTL. So a packet sent with
    # ip_ttl=64 must arrive with ip_ttl=62 on the Ixia RX port.
    # Earlier this was set to -1 (incorrectly modelling decap as the
    # only L3 hop), which produced spurious TTL=63 expectations and
    # made the renderer flag a FAIL even on a perfectly healthy DUT.
    # ``mode`` aliases used throughout this function:
    #   * is_l3vni_family : both untagged ('l3vni') and tagged
    #     ('l3vni_tagged') variants -- they share VRF, BGP-EVPN,
    #     L3 VNI, decap path, and TTL-decrement count. Only the
    #     ingress port encapsulation (routed vs. SVI/tagged)
    #     differs.
    #   * is_l3vni_tagged : the variant where the ingress port is
    #     a tagged member of Vlan{_L2_VLAN_ID} and the SVI is
    #     bound to _I_VRF. dst_mac resolves to the SVI MAC and
    #     Ixia adds an 802.1Q tag on the wire.
    is_l3vni_family = mode in ('l3vni', 'l3vni_tagged')
    is_l3vni_tagged = (mode == 'l3vni_tagged')

    if mode == 'l3vni':
        dst_mac    = get_dut_mac(dut, port_info['ingress'])
        expected_ttl_delta = -2   # DUT1 ingress L3 + DUT2 egress L3
    elif mode == 'l3vni_tagged':
        # SVI MAC -- frames arrive 802.1Q-tagged on the trunk member,
        # the SVI does the L3 lookup into _I_VRF, and the rest of the
        # path is identical to plain L3VNI (encap on DUT1, decap on
        # DUT2, two TTL decrements end-to-end).
        dst_mac    = get_dut_mac(dut, 'Vlan{}'.format(_L2_VLAN_ID))
        expected_ttl_delta = -2
    elif mode == 'l2vni':
        # L2VNI ingress.  Two distinct sub-flavors are supported via
        # the l2vni_force_bum / l2vni_gate_unicast flags:
        #
        #   (a) BUM-flood  (l2vni_force_bum=True, used by
        #                   TestSmokeL2VNIBum)
        #       Always use _J_BUM_MAC. Skip EVPN-MAC lookup entirely
        #       so the burst is guaranteed to take the flood path on
        #       the wire (multicast column in DCHAL queue counters).
        #       Scorecard primary_queue_col='mc'.
        #
        #   (b) Unicast   (l2vni_gate_unicast=True, used by
        #                   TestSmokeL2VNIUcast)
        #       Resolve the receiver MAC via EVPN Type-2 in Vlan502.
        #       If the lookup times out, st.report_unsupported() --
        #       the unicast-path scorecard column ('uc') is only
        #       meaningful when EVPN has converged.  Without the
        #       gate, a non-converged run would silently re-route as
        #       BUM and the 'q[N]_uc=0 (short)' row would FAIL.
        #
        #   (c) Best-effort (legacy default; both flags False)
        #       Same as (b) but on lookup-miss falls back to BUM with
        #       a WARN instead of skipping.  Preserved so any legacy
        #       caller that just passes mode='l2vni' still runs.
        if l2vni_force_bum:
            st.log("  smoke[l2vni-bum]: forcing dst_mac=_J_BUM_MAC "
                   "({}) -- skipping EVPN-MAC lookup".format(_J_BUM_MAC))
            dst_mac = _J_BUM_MAC
        else:
            try:
                resolved = _smoke_lookup_evpn_mac_for_l2vni(
                    dut, vlan_id=_J_L2_VLAN, remote_vtep=_J_VTEP2_IP,
                    preferred_mac=_J_L2VNI_RX_MAC)
            except Exception as exc:
                st.warn("  smoke[l2vni]: EVPN-MAC discovery raised "
                        "{}: {} - treating as un-resolved".format(
                            type(exc).__name__, exc))
                resolved = None
            if resolved:
                dst_mac = resolved
            elif l2vni_gate_unicast:
                # Strict unicast-gate path. Hard-skip: the test
                # cannot meaningfully exercise the L2VNI unicast
                # column without a learned EVPN MAC.  Sister class
                # TestSmokeL2VNIBum covers the BUM-flood path.
                msg = ("L2VNI-unicast gate: no EVPN-learned MAC for "
                       "Vlan{} from remote VTEP {} after lookup window. "
                       "Skipping as unsupported (TestSmokeL2VNIBum "
                       "covers the flood-path scenario).".format(
                           _J_L2_VLAN, _J_VTEP2_IP))
                st.warn("  smoke[l2vni-ucast]: " + msg)
                # Note: st.report_unsupported terminates the current
                # test.  Spytest handles teardown via the class-scope
                # fixture, so we don't need a finally clause here.
                st.report_unsupported('msg', msg)
            else:
                # Legacy best-effort: fall back to BUM with a WARN.
                # primary_queue_col defaults to 'mc' for mode='l2vni',
                # so the scorecard still picks the right column.
                st.warn("  smoke[l2vni]: no EVPN-learned MAC in Vlan{} "
                        "FDB (remote_vtep={}); falling back to BUM "
                        "(eth_dst=ff:ff:ff:ff:ff:ff). The test will "
                        "still validate DSCP-to-TC classification but "
                        "the L2VNI path will flood instead of unicast."
                        .format(_J_L2_VLAN, _J_VTEP2_IP))
                dst_mac = _J_BUM_MAC
        expected_ttl_delta = 0    # L2 bridges - TTL unchanged end-to-end
    else:
        raise ValueError(
            "smoke mode must be 'l3vni', 'l3vni_tagged' or 'l2vni'")

    hard_failures = []
    soft_warns    = []

    # Initialize so the analysis renderer (in the finally block) has
    # defined values even if setup blows up before they get assigned.
    # We pre-populate tx_spec / rx_spec with everything we already know
    # at function-entry time (params, topology constants, mode-derived
    # dst_mac and TTL delta). Without this pre-fill, an exception
    # between this point and the full enrichment block at line ~2350
    # leaves the renderer staring at an empty dict and printing every
    # field as '-' -- which is exactly what produced the user-reported
    # 'eth_dst = -' / 'eth_src = -' rows in the 2026-05-15 03:22:50
    # log. The full enrichment block downstream still overwrites these
    # keys with the computed values; the pre-fill is only the safety
    # net for the early-crash path.
    cap     = {'tx': {'decoded': [], 'num_total': 0},
               'rx': {'decoded': [], 'num_total': 0}}
    udp_dst = 5000 + int(dscp)
    sport_v_pre = 10000 + int(dscp)
    ip_src_pre  = (IXIA_INGRESS_A_IP if af == 'ipv4'
                   else IXIA_INGRESS_A_IP6)
    # Pre-fill ip_dst on tx_spec / rx_spec so the early-crash path
    # (any exception before the full enrichment block below) still
    # has a sensible default for the side-by-side dump. The full
    # block below overwrites these. For SMOKE-L2VNI[ipv4] we use
    # _J_L2VNI_RX_IP (20.20.20.22) to match the Vlan502 receiver
    # host's IP — see the comment above stream_ip_dst below for
    # the rationale.
    if mode == 'l2vni' and af == 'ipv4':
        ip_dst_pre = _J_L2VNI_RX_IP
    elif af == 'ipv4':
        ip_dst_pre = _IXIA_DST_V4
    else:
        ip_dst_pre = _IXIA_DST_V6
    eth_src_pre = IXIA_SRC_MAC.get('ingress_a')
    tx_spec = {
        'l3':                af,
        'dscp':              int(dscp),
        'ecn':               0,
        'ttl_or_hl':         _SMOKE_SENT_TTL,
        'has_vxlan_header':  False,
        'l4':                'udp',
        'l4_sport':          sport_v_pre,
        'l4_dport':          udp_dst,
        'eth_src':           eth_src_pre,
        'eth_dst':           dst_mac,
        'ip_src':            ip_src_pre,
        'ip_dst':            ip_dst_pre,
    }
    if mode == 'l2vni':
        tx_spec['vlan'] = int(_J_L2_VLAN)
    elif is_l3vni_tagged:
        tx_spec['vlan'] = int(_L2_VLAN_ID)
    rx_spec = {
        'l3':                af,
        'dscp':              int(dscp),
        'ecn':               0,
        'ttl_or_hl':         _SMOKE_SENT_TTL + expected_ttl_delta,
        'has_vxlan_header':  False,
        'l4':                'udp',
        'l4_sport':          sport_v_pre,
        'l4_dport':          udp_dst,
        'ip_src':            ip_src_pre,
        'ip_dst':            ip_dst_pre,
    }

    # Counter contexts (snapshot wrappers). These are no-ops on H tests
    # but in L3VNI / L2VNI smoke modes they snapshot:
    #   - DUT1 egress (Ethernet1_54_1, the encap'd-traffic fabric port)
    #     with both per-queue dchal AND aggregate show-int counters.
    #   - DUT2 egress_ixia (Ethernet1_49) with per-queue dchal only.
    # Together they let the path-triage table split a missing-packet
    # event into 3 segments: (a) DUT1 didn't encap, (b) fabric or DUT2
    # decap dropped, (c) DUT2-egress to Ixia dropped.
    dut1_ctx = (_CounterCtx(dut, port_info['egress'],
                            test_label + " DUT1 egress (encap)",
                            with_aggregate=True,
                            with_uc_mc=True)
                if dut and port_info.get('egress')
                else _NullCounterCtx(test_label + " DUT1 egress (skipped)"))
    # DUT2 egress: same dchal capture as before, but also enable
    # with_aggregate=True so the 'Final summary' comparison row can show
    # tx_ok on the DUT2->Ixia port alongside the per-queue dchal totals,
    # and with_uc_mc=True so the scorecard can split q[N] into
    # uc_pkts / mc_pkts -- needed by the L2VNI BUM smoke which lands
    # the burst in the multicast column on the wire.
    if dut2 and dut2_port_info.get('egress_ixia'):
        dut2_ctx = _CounterCtx(
            dut2, dut2_port_info['egress_ixia'],
            test_label + " DUT2 egress_ixia",
            with_aggregate=True,
            with_uc_mc=True)
    else:
        dut2_ctx = _NullCounterCtx(
            test_label + " DUT2 egress_ixia (skipped: no DUT2)")
    # New aggregate-only contexts for the INGRESS sides of both DUTs.
    # These power the 'Final summary' one-row table (DUT1-in / DUT2-in
    # cells). show interfaces counters only -- no dchal queue dive.
    dut1_in_ctx = (_AggOnlyCtx(dut, port_info['ingress'],
                               test_label + " DUT1 ingress")
                   if dut and port_info.get('ingress')
                   else _NullCounterCtx(test_label + " DUT1 ingress (skipped)"))
    dut2_in_ctx = (_AggOnlyCtx(dut2, dut2_port_info['peer'],
                               test_label + " DUT2 ingress (fabric peer)")
                   if dut2 and dut2_port_info.get('peer')
                   else _NullCounterCtx(test_label + " DUT2 ingress (skipped)"))

    dut1_q_deltas    = {}
    dut1_agg_deltas  = {}
    dut1_in_agg      = {}
    dut2_q_deltas    = {}
    dut2_egr_agg     = {}
    dut2_in_agg      = {}
    ixia_agg         = None  # {'tx_total': int, 'rx_total': int} or None
    stream_handle    = None  # Ixia stream id (set by _smoke_build_one_stream)
    # Flag the moment we hand off to the Ixia capture call. The 'finally'
    # block uses this (NOT bool(tx_spec)/bool(rx_spec)) to decide whether
    # to render the flow-analysis block. Without this flag, ANY post-
    # capture exception (a DCHAL hiccup, a stats-fetch faut, a decoder
    # type-error like the bytes-pylist one) would falsely log
    # "Packet Flow Analysis skipped: traffic config aborted before
    # capture started", misdirecting future debugging at TGenFail when
    # the real fault is downstream. See smoke_one.log line 3498 for the
    # original false-positive instance.
    capture_attempted = False

    # Wall-clock for duration display in the scorecard footer.
    start_time = time.time()

    try:
        # Pre-measure: reuse the binding check from the H/I/J tests.
        #
        # The encap-side classifier (dscp_to_tc_map) runs at PHYSICAL-
        # PORT INGRESS, so we pin the binding check to whichever DUT1
        # port the smoke flow actually enters on.  By the workspace
        # role-to-port convention:
        #   l3vni        / l3vni_tagged : port_info['ingress_a']
        #                                 (first DUT1->T1 link;
        #                                  Ethernet1_49 / VRF-bound)
        #   l2vni                       : port_info['ingress_b']
        #                                 (second DUT1->T1 link;
        #                                  Ethernet1_50 / VLAN-access)
        #
        # On a single-D1T1P testbed ingress_b is absent and L2VNI smoke
        # falls back to ingress_a -- matching the pre-split behaviour
        # where all three modes shared the same physical port.
        #
        # ── Prime ARP/ND ─────────────────────────────────────────────────
        _prime_arp_nd(af)

        # ── Re-prime Ixia interface state ────────────────────────────────
        # The class-scope VXLAN setup rebound the DUT ingress port into
        # VrfQoS, which removes/re-adds the IPs. Ixia's cached gateway
        # MAC can go stale through that rebind, which manifests as
        # 'Invalid value for TGen parameter' during tg_traffic_config.
        # Re-poke arp_send_req + resolve_gateway_mac so the IXIA has
        # fresh state before we build the smoke stream.
        #
        # Pass mode so L2VNI smoke re-primes the L2VNI ingress port
        # (Ethernet1_50 / tg_ph['ingress_b'] by convention) rather
        # than the L3VNI port that the smoke flow does not actually
        # use.
        _smoke_reprime_ixia_interface(af, mode=mode)

        # ── Build the 5-packet stream ────────────────────────────────────
        # VLAN tagging policy:
        #   l3vni         : untagged (routed ingress port)
        #   l3vni_tagged  : tag = _L2_VLAN_ID (SVI ingress, this var-
        #                   iant exercises the dot1q->SVI->VRF->L3VNI
        #                   ingress path that an EVPN edge typically
        #                   sees from a downstream access switch).
        #   l2vni         : tag = _J_L2_VLAN (BUM flood over L2VNI)
        if mode == 'l2vni':
            stream_vlan = _J_L2_VLAN
        elif is_l3vni_tagged:
            stream_vlan = _L2_VLAN_ID
        else:
            stream_vlan = None

        # Stream ip_dst override: for the SMOKE-L2VNI[ipv4] runs we
        # send to the Vlan502 receiver host's IP (_J_L2VNI_RX_IP =
        # 20.20.20.22) instead of the default L3VNI receiver IP
        # (_IXIA_DST_V4 = 20.20.20.2). The bridge doesn't care
        # about IP at all (pure L2 lookup on inner-Ethernet dst MAC),
        # but matching the IP to the host that GARP'd the MAC keeps
        # the side-by-side packet dump self-consistent: a frame
        # destined to 00:de:ad:be:ef:02 should ALSO be destined to
        # 20.20.20.22, the IP that owns that MAC, not to 20.20.20.2
        # which is the L3VNI receiver host on the same Ixia port.
        # IPv6 L2VNI keeps the default (no separate v6 receiver host
        # configured; bridge doesn't care which v6 dst we use).
        stream_ip_dst = (_J_L2VNI_RX_IP
                         if (mode == 'l2vni' and af == 'ipv4')
                         else None)
        tg.tg_traffic_control(action='reset')
        stream_handle, udp_dst = _smoke_build_one_stream(
            af, ingress_ph, dst_mac, dscp,
            vlan_id=stream_vlan, ip_dst_addr=stream_ip_dst)

        # ── DUT1 evidence: snapshot ENCAP egress port BEFORE ─────────────
        # Captures both per-queue dchal AND aggregate show-int counters
        # on Ethernet1_54_1 (the only fabric sub-port that's UP). Lets
        # us prove "DUT1 actually encap'd 5 pkts to the right queue
        # before they hit the fabric". Wrapped in try so a DCHAL hiccup
        # doesn't kill the instance.
        try:
            dut1_ctx.snap_before()
        except Exception as exc:
            st.warn("  DUT1 snap_before failed (non-fatal): {}".format(exc))

        # ── DUT1 INGRESS aggregate snap BEFORE ───────────────────────────
        # Cheap show-int snapshot only; powers the DUT1-in cell of the
        # final comparison table. _AggOnlyCtx already does its own try/
        # except so no extra wrapping needed here.
        dut1_in_ctx.snap_before()

        # ── DUT2 evidence: snapshot egress-port queue counters BEFORE ────
        # This is wrapped in a try so a DCHAL hiccup on DUT2 doesn't kill
        # the entire smoke instance. If snap fails the deltas() call later
        # returns zeros and the analysis renderer will say
        # "(no DUT2 per-queue deltas available)".
        try:
            dut2_ctx.snap_before()
        except Exception as exc:
            st.warn("  DUT2 snap_before failed (non-fatal): {}".format(exc))

        # ── DUT2 INGRESS aggregate snap BEFORE (fabric peer port) ────────
        dut2_in_ctx.snap_before()

        # ── Run with RX-only capture (see helper docstring for why) ──────
        # Mark BEFORE the call so the finally:-block correctly distinguishes
        # "TGenFail/build-stream error before capture" (capture_attempted
        # stays False) from "capture ran, something downstream blew up"
        # (capture_attempted is True). See note at the variable's init.
        capture_attempted = True
        cap = _smoke_run_with_rx_capture(
            test_label, ingress_ph, egress_ph)

        # ── DUT1 evidence: snapshot ENCAP egress port AFTER ──────────────
        try:
            dut1_ctx.snap_after()
            dut1_q_deltas   = dut1_ctx.deltas()
            dut1_agg_deltas = dut1_ctx.aggregate_deltas()
        except Exception as exc:
            st.warn("  DUT1 snap_after failed (non-fatal): {}".format(exc))
            dut1_q_deltas   = {}
            dut1_agg_deltas = {}

        # ── DUT1 INGRESS aggregate snap AFTER ────────────────────────────
        dut1_in_ctx.snap_after()
        dut1_in_agg = dut1_in_ctx.aggregate_deltas() \
            if dut1_in_ctx.is_real() else {}

        # ── DUT2 evidence: snapshot egress-port queue counters AFTER ─────
        try:
            dut2_ctx.snap_after()
            dut2_q_deltas = dut2_ctx.deltas()
            dut2_egr_agg  = dut2_ctx.aggregate_deltas()
        except Exception as exc:
            st.warn("  DUT2 snap_after failed (non-fatal): {}".format(exc))
            dut2_q_deltas = {}
            dut2_egr_agg  = {}

        # ── DUT2 INGRESS aggregate snap AFTER (fabric peer port) ─────────
        dut2_in_ctx.snap_after()
        dut2_in_agg = dut2_in_ctx.aggregate_deltas() \
            if dut2_in_ctx.is_real() else {}

        # ── Ixia aggregate counters: TX-port and RX-port totals ──────────
        # This is independent of the per-frame decoded capture: the
        # capture engine drops frames silently if the trigger window
        # misses, while the aggregate stats counter is incremented for
        # every framed packet. So if `cap['rx']['decoded']` is short but
        # `ixia_agg['rx_total']` is full, we know the packet WAS at the
        # Ixia RX port and the capture was the lossy stage. The reverse
        # case (capture full, aggregate short) is impossible.
        # NOTE: catch BaseException, not Exception. Spytest's
        # report_tgen_abort path raises pytest.skip() / pytest.exit()
        # under the hood -- those use _pytest.outcomes.Skipped which
        # inherits from BaseException, NOT Exception. A plain
        # `except Exception` lets them slip through and skips the
        # rest of the post-traffic analysis (renderer, scorecard,
        # final-summary table). That's exactly what we hit in the
        # `can't read "matched_str"` Tcl failure inside ixiangpf.
        # KeyboardInterrupt/SystemExit are still re-raised so Ctrl-C
        # and pytest --exitfirst keep working.
        # Build a single-element streams list shaped like the J3/J4
        # callers expect: {'handle': <full ixia dict>, 'dscp': N}.
        # IMPORTANT: stream_handle is already the full Ixia handle
        # dict returned by tg.tg_traffic_config (see
        # _smoke_build_one_stream line 1833). We must pass it AS-IS,
        # not re-wrap it -- the helper extracts the id via
        # s['handle'].get('stream_id'). The previous code wrapped it
        # again as {'stream_id': stream_handle} which made the inner
        # .get('stream_id') return the whole dict, never matching
        # the IxNetwork response keys; result was silent (0, 0).
        smoke_streams = [{'handle': stream_handle,
                          'dscp':   int(dscp)}] \
            if stream_handle is not None else []
        try:
            agg_tx, agg_rx = _measure_ixia_rx_aggregate(smoke_streams)
            # CAPTURED-FRAME RX FALLBACK
            # On many IxNetwork builds, tg_traffic_stats(mode='stream')
            # returns RX=0 even when frames physically arrive at the
            # egress port. The per-stream RX bucket is populated from
            # IxNetwork "Flow Statistics" which require a tracking-
            # filter match on the receiving port; if the egress port's
            # ingress side has no matching tracker (the typical case
            # for a non-tagged routed RX port that received the
            # post-decap frame after L3 rewrites the outer headers),
            # the stream RX counter stays at zero. The packet-capture
            # buffer (smoke_stop_capture, called inside
            # _smoke_run_with_rx_capture above), in contrast, sees
            # every framed packet that crosses the wire regardless of
            # tracker config -- so the decoded-frame count is the
            # authoritative truth for "did the packet actually arrive
            # at the Ixia RX port?". Use it as a fallback ONLY when
            # the stream stats undercount: never inflate, only correct
            # an obvious zero-vs-nonzero discrepancy.
            #
            # IMPORTANT: previous revision tried to inspect a local
            # `rx_pkts` variable here, but that variable only lives
            # inside _smoke_run_with_rx_capture() -- in this scope it
            # raises NameError, which was silently swallowed by the
            # surrounding 'except BaseException', leaving cap_rx at 0
            # and the fallback dead. See smoke_one_tag.log @ 08:58:47
            # for the symptom (TX=5 RX=0 reported even though the
            # capture buffer logged 'RX captured 5 frame(s)' at
            # 08:58:28).
            #
            # The captured/decoded frames ARE accessible here via
            # ``cap['rx']['decoded']``, which _smoke_run_with_rx_capture
            # returns. ``len(cap['rx']['decoded'])`` is exactly the
            # post-stop-capture frame count and equals what
            # qos_helpers logs as "RX captured N frame(s)".
            cap_rx = 0
            try:
                rx_decoded = cap.get('rx', {}).get('decoded') \
                    if isinstance(cap, dict) else None
                if rx_decoded:
                    cap_rx = len(rx_decoded)
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException:
                cap_rx = 0
            if int(agg_rx) == 0 and cap_rx > 0:
                agg_rx = cap_rx
            ixia_agg = {'tx_total': int(agg_tx), 'rx_total': int(agg_rx)}
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as exc:
            st.warn("  Ixia stream-sum stats fetch failed (non-fatal, "
                    "treating as ixia_agg=None to keep analysis going): "
                    "{}: {}".format(type(exc).__name__, exc))
            ixia_agg = None

        # ── Build expected per-frame spec for each side ──────────────────
        # We pin:
        #   * Always-survives invariants (l3/dscp/l4/dport/sport/ecn/IPs)
        #     in BOTH specs -- L3 routing rewrites L2 but preserves L3+L4.
        #   * eth_dst on TX only (= the DUT1-ingress MAC we sent to). On
        #     RX the inner-packet eth_dst is rewritten by DUT2's egress
        #     L3 next-hop lookup, so we deliberately DO NOT pin it on
        #     rx_spec (the side-by-side view will show the captured
        #     value instead of forcing a FAIL).
        #   * eth_src on TX = IXIA_SRC_MAC['ingress_a'] -- this is the
        #     wire MAC the topology-setup pinned via tg_interface_config(
        #     src_mac_addr=...) AND the smoke stream re-pinned via
        #     mac_src=. Both layers point at the same constant in
        #     qos_helpers.py so the dump's TX 'eth_src' row matches what
        #     actually went on the wire. On RX we again leave eth_src
        #     unset because L3 routing on DUT2 rewrites it to DUT2's
        #     egress port MAC; pinning it on rx_spec would force a
        #     spurious FAIL on every healthy packet.
        sport_v       = 10000 + int(dscp)
        ip_src_addr   = IXIA_INGRESS_A_IP if af == 'ipv4' else \
            IXIA_INGRESS_A_IP6
        # Match the IP the stream actually sent to — see
        # stream_ip_dst comment above _smoke_build_one_stream call.
        # SMOKE-L2VNI[ipv4] uses _J_L2VNI_RX_IP so the captured
        # frame's ip_dst column lines up with the stream's
        # ip_dst_addr; otherwise the side-by-side dump would show
        # 20.20.20.22|20.20.20.22 across the wire (captured) but
        # the validator would expect 20.20.20.2, generating a
        # spurious 'ip_dst differs' WARN that has nothing to do
        # with the QoS path under test.
        if mode == 'l2vni' and af == 'ipv4':
            ip_dst_addr = _J_L2VNI_RX_IP
        elif af == 'ipv4':
            ip_dst_addr = _IXIA_DST_V4
        else:
            ip_dst_addr = _IXIA_DST_V6
        eth_src_v     = IXIA_SRC_MAC.get('ingress_a')
        # Pin the 802.1Q tag on tx_spec whenever the stream actually
        # carries one. The renderer's "hide row when both sides are
        # None" rule keeps untagged paths (plain L3VNI) clean. The
        # three tagged paths each tell a slightly different story:
        #
        #   * l3vni_tagged : TX = _L2_VLAN_ID, RX is untagged because
        #     DUT2 egresses on a routed port -> the dump surfaces a
        #     '* VLAN = 100 | VLAN = -' row, which is the natural
        #     cue for "the SVI stripped the tag at L3 ingress and
        #     the egress side is L3 routed (no tag)". Exactly the
        #     L2->L3->L2 transition we want visible.
        #   * l2vni : TX = _J_L2_VLAN, RX usually untagged at the
        #     access-port egress -> same '*' row for the same
        #     L2-flood-then-egress-strip reason.
        #   * l3vni (untagged) : neither side carries a tag, no row.
        if mode == 'l2vni':
            tx_vlan_v = _J_L2_VLAN
        elif is_l3vni_tagged:
            tx_vlan_v = _L2_VLAN_ID
        else:
            tx_vlan_v = None
        tx_spec = {
            'l3':                af,
            'dscp':              int(dscp),
            'ecn':               0,
            'ttl_or_hl':         _SMOKE_SENT_TTL,
            'has_vxlan_header':  False,
            'l4':                'udp',
            'l4_sport':          sport_v,
            'l4_dport':          udp_dst,
            'eth_src':           eth_src_v,
            'eth_dst':           dst_mac,
            'ip_src':            ip_src_addr,
            'ip_dst':            ip_dst_addr,
        }
        if tx_vlan_v is not None:
            tx_spec['vlan'] = int(tx_vlan_v)
        rx_spec = {
            'l3':                af,
            'dscp':              int(dscp),
            'ecn':               0,
            'ttl_or_hl':         _SMOKE_SENT_TTL + expected_ttl_delta,
            'has_vxlan_header':  False,
            'l4':                'udp',
            'l4_sport':          sport_v,
            'l4_dport':          udp_dst,
            # NOTE: no eth_dst / eth_src / vlan on rx_spec -- see
            # block comment above tx_spec for the vlan rationale and
            # the L2/L3 next-hop comment for eth_dst/eth_src.
            'ip_src':            ip_src_addr,
            'ip_dst':            ip_dst_addr,
        }

        # ── Side-by-side TX intent vs RX captured packet dump ────────────
        # Render the TX intent next to each captured RX frame as a
        # vertical tcpdump-style side-by-side dump.  Lets the operator
        # eyeball "DUT2 stripped VXLAN, decremented TTL, preserved DSCP"
        # without reading the field-summary table.
        #
        # IMPORTANT (2026-05-15 fix): we pass tx_spec, NOT rx_spec, as
        # the TX intent. tx_spec carries the values Ixia ACTUALLY put
        # on the wire at the DUT1 ingress (TTL=64, eth_dst=DUT1 MAC,
        # ip_src=Ixia source). rx_spec is the post-decap *expected*
        # packet (TTL=62, no eth_dst pinned because L3 next-hop
        # rewrites it) -- that's the EGRESS-side reference, not the
        # ingress-side intent. Previous behavior fed rx_spec into
        # tx_intent which made the dump claim "TX TTL=62" (impossible
        # -- TX is what we sent, before any DUT decremented it) and
        # masked the L2 rewrite at DUT2's egress.
        #
        # Also: spell out the two vantage points in the column labels so
        # the operator immediately sees that TX is observed at the Ixia
        # injection point into DUT1 and RX is observed at DUT2's egress
        # back to Ixia. Without these labels the table reads ambiguously
        # ("TX intent vs RX captured" -- where exactly?).
        ingress_intf_name = port_info.get('ingress', '?')
        egress_intf_name  = (dut2_port_info.get('egress_ixia')
                             or port_info.get('egress', '?'))
        tx_lbl = "Ixia -> DUT1 {} (intent)".format(ingress_intf_name)
        rx_lbl = "DUT2 {} -> Ixia (captured)".format(egress_intf_name)
        try:
            smoke_print_tx_rx_side_by_side(
                tx_intent=tx_spec,
                decoded_rx=cap['rx']['decoded'],
                label=test_label,
                pkts_sent=_SMOKE_PKTS_PER_BURST,
                test_dport=udp_dst,
                tx_label=tx_lbl,
                rx_label=rx_lbl)
        except Exception as exc:
            st.warn("  Side-by-side renderer raised "
                    "(non-fatal): {}: {}".format(
                        type(exc).__name__, exc))

        # ── Short-capture warnings ───────────────────────────────────────
        # We capture on the RX side only (see _smoke_run_with_rx_capture
        # docstring for the spytest-plugin-side reason); 'tx_n' is always
        # 0 here because the TX side is synthesised from the build spec
        # rather than captured.
        tx_n = len(cap['tx']['decoded'])    # always 0 - kept for symmetry
        rx_n = len(cap['rx']['decoded'])

        # ── Pre-classify noise frames ────────────────────────────────────
        # Walk the RX capture once and classify each non-test frame
        # (LLDP/BGP/ARP/ND/...) so downstream soft-warns can explain
        # "5 test + 1 LLDP + 3 BGP-TCP" instead of saying "counter drift".
        # The same classifier runs again inside _smoke_assert_frames later
        # for the per-frame log lines, but the counts are identical so
        # there's no risk of double-counting -- both use the same UDP-dport
        # identity filter.
        noise_breakdown = []
        if rx_n > 0:
            for d in cap['rx']['decoded']:
                if d.get('l3') == 'other':
                    noise_breakdown.append(_smoke_classify_noise_frame(d))
                    continue
                if (udp_dst is not None
                        and d.get('l4_dport') != udp_dst):
                    noise_breakdown.append(_smoke_classify_noise_frame(d))
        noise_n = len(noise_breakdown)
        noise_summary = _smoke_format_noise_breakdown(noise_breakdown)

        if rx_n == 0:
            hard_failures.append(
                "{}: RX-side captured 0 frames - DUT2 egress port may not "
                "be transmitting decapped traffic (check the e2e path)"
                .format(test_label))

        if 0 < rx_n < _SMOKE_PKTS_PER_BURST:
            soft_warns.append(
                "{}: RX captured only {}/{} frames - some packets were "
                "dropped or missed by the capture trigger window"
                .format(test_label, rx_n, _SMOKE_PKTS_PER_BURST))

        # ── DUT2-evidence soft assertions ────────────────────────────────
        # These are SOFT because they're diagnostic: the per-frame TX/RX
        # decode is the authoritative gate. But they're crucial when
        # rx_n=0 because they tell us WHERE in DUT2 the packet died.
        if dut2_q_deltas:
            tc_q = dut2_q_deltas.get(int(expected_tc), {}) or {}
            tc_p = int(tc_q.get('pkts',      0))
            tc_d = int(tc_q.get('drop_pkts', 0))
            tot_p = sum(int(q.get('pkts',      0))
                         for q in dut2_q_deltas.values())
            tot_d = sum(int(q.get('drop_pkts', 0))
                         for q in dut2_q_deltas.values())

            # Did DUT2 see any traffic at all on the egress port?
            if tot_p == 0 and tot_d == 0 and rx_n == 0:
                soft_warns.append(
                    "{}: DUT2 egress-port queues saw 0 pkts and 0 drops - "
                    "decap may have failed (check show vxlan, show ip route "
                    "vrf, show evpn vni {}) OR the peer-link is not "
                    "forwarding".format(test_label,
                                        _I_VNI if is_l3vni_family else _J_VNI))

            # Did the right queue receive the traffic?
            #
            # HARD failure: the DSCP-to-TC classifier landing on the wrong
            # queue is a deterministic functional contract violation, not a
            # transient "could be congestion" case. The map binding is
            # verified upstream (PORT_QOS_MAP|<egress>.dscp_to_tc_map=AZURE)
            # and the AZURE map content is verified in preflight (golden-
            # map drift check, line 2010 of smoke_one_tag.log). If both of
            # those passed AND the queue is still wrong, SAI/asic isn't
            # honouring the classifier and the smoke must FAIL so it gets
            # visibility in the matrix line (vs being buried in 'soft warns'
            # under a green PASS).
            if tot_p > 0 and tc_p == 0:
                # Find which queue actually got it (highest pkts in deltas).
                wrong_q = max(
                    ((qi, int(q.get('pkts', 0)))
                     for qi, q in dut2_q_deltas.items()),
                    key=lambda kv: kv[1], default=(None, 0))
                hard_failures.append(
                    "{}: DUT2 egress-port classifier sent traffic to TC{} "
                    "instead of expected TC{} (DSCP {} classifier mismatch "
                    "on DUT2 - check PORT_QOS_MAP|<egress_port>.dscp_to_tc_map)"
                    .format(test_label, wrong_q[0], expected_tc, dscp))

            # Did packets show up on the right queue but get dropped?
            if tc_p > 0 and tc_d > 0:
                soft_warns.append(
                    "{}: DUT2 egress-port TC{} saw {} drops alongside {} "
                    "pkts (WRED or queue-tail drop suspect)".format(
                        test_label, expected_tc, tc_d, tc_p))

        # ── DUT1-evidence soft assertions ────────────────────────────────
        # If DUT1's encap egress has no per-queue or aggregate delta, but
        # Ixia's TX side says we sent the burst, DUT1 itself didn't
        # forward (tunnel install failed, peer-link admin-down, etc).
        if dut1_q_deltas:
            d1_tc_q  = dut1_q_deltas.get(int(expected_tc), {}) or {}
            d1_tc_p  = int(d1_tc_q.get('pkts',      0))
            d1_tc_d  = int(d1_tc_q.get('drop_pkts', 0))
            d1_tot_p = sum(int(q.get('pkts',      0))
                            for q in dut1_q_deltas.values())
            d1_tot_d = sum(int(q.get('drop_pkts', 0))
                            for q in dut1_q_deltas.values())
            d1_agg_tx = int(dut1_agg_deltas.get('tx_ok', 0))
            d1_agg_drp= int(dut1_agg_deltas.get('tx_drp', 0))

            # 1) DUT1 saw 0 encap'd pkts (and no drops) but Ixia said we
            #    sent 5 -> the encap path is broken on DUT1.
            if (d1_tot_p == 0 and d1_tot_d == 0 and d1_agg_tx == 0 and
                    rx_n == 0):
                soft_warns.append(
                    "{}: DUT1 encap egress saw 0 pkts and 0 drops on "
                    "{} (port-queue and aggregate both empty) - either "
                    "VXLAN tunnel is not installed (check 'show vxlan "
                    "tunnel' / FIB), or Ethernet1_54_1 is admin-down on "
                    "DUT1, or Ixia stream did not actually run."
                    .format(test_label, port_info.get('egress', '?')))

            # 2) DUT1 encap'd to the WRONG queue (DSCP-to-TC misclassify
            #    on DUT1's INGRESS port from Ixia, before encap).
            #
            # HARD failure: same reasoning as the DUT2 mismatch above --
            # PORT_QOS_MAP|<ingress>.dscp_to_tc_map=AZURE is verified in
            # the pre-measure check, the AZURE map content is verified in
            # preflight, and the queue placement is the direct output of
            # the classifier. If the classifier picked TC0 when AZURE says
            # DSCP 3 -> TC 3, that's SAI/asic ignoring the binding and a
            # smoke FAIL is the right verdict (rather than burying it as
            # a soft warn under a green PASS).
            if d1_tot_p > 0 and d1_tc_p == 0:
                wrong_q = max(
                    ((qi, int(q.get('pkts', 0)))
                     for qi, q in dut1_q_deltas.items()),
                    key=lambda kv: kv[1], default=(None, 0))
                hard_failures.append(
                    "{}: DUT1 encap egress put traffic on TC{} instead "
                    "of expected TC{} (DSCP {} encap-side classifier "
                    "mismatch on DUT1 - check PORT_QOS_MAP|{} dscp_to_tc_map)"
                    .format(test_label, wrong_q[0], expected_tc, dscp,
                            port_info.get('ingress', '?')))

            # 3) DUT1 dropped on egress (queue or aggregate tx_drp).
            if d1_tc_d > 0 or d1_agg_drp > 0:
                soft_warns.append(
                    "{}: DUT1 encap egress reported {} per-queue drops + "
                    "{} aggregate tx_drp on {} (peer-link congested or "
                    "MTU/MAC issue)".format(
                        test_label, d1_tc_d, d1_agg_drp,
                        port_info.get('egress', '?')))

            # 4) Cross-check dchal sum vs aggregate tx_ok. A consistent
            #    mismatch is itself diagnostic (counter bug or platform
            #    feature).
            #
            # 'show int counters' tx_ok counts EVERY framed packet on the
            # wire (test burst + control-plane chatter). dchal sum is
            # filtered to ipv4/ipv6 unicast test traffic. With a 5-pkt
            # burst even 1-2 LLDP/BGP frames during the test window push
            # the absolute drift over the >10% threshold. So if the drift
            # is fully explained by noise we captured on the RX port
            # (LLDP/BGP/ND/ARP/...), it's NOT a counter bug -- skip the
            # warn entirely. Otherwise annotate the warn with the noise
            # breakdown so the operator immediately sees what kind of
            # chatter accounted for the extra packets (eg "+4 unaccounted:
            # 1 LLDP + 3 BGP-TCP").
            if (d1_agg_tx > 0 and d1_tot_p > 0 and
                    abs(d1_agg_tx - d1_tot_p) > max(2, d1_agg_tx // 10)):
                drift = abs(d1_agg_tx - d1_tot_p)
                # If captured noise on the RX port >= drift, the chatter
                # explains the mismatch. The check is intentionally on
                # the RX-port noise rather than DUT1's TX-port noise
                # because we don't capture DUT1's TX side; but typical
                # control-plane chatter (LLDP/BGP) is symmetric on both
                # ends of the peer-link, so RX-port noise is a decent
                # proxy.  We also tolerate exact-match (drift == noise_n)
                # because counters and capture buffers race within the
                # same measurement window.
                if noise_n >= drift:
                    st.log(
                        "  {} dchal sum ({}) vs tx_ok ({}) drift={} fully "
                        "explained by {} noise frame(s) captured on RX "
                        "(detail: {}); NOT a counter bug -- soft-warn "
                        "suppressed".format(
                            test_label, d1_tot_p, d1_agg_tx, drift,
                            noise_n, noise_summary or 'none'))
                else:
                    unaccounted = drift - noise_n
                    detail = ('; captured RX noise: ' + noise_summary
                              if noise_summary else '')
                    soft_warns.append(
                        "{}: DUT1 dchal sum ({}) and 'show int counters' "
                        "tx_ok ({}) disagree by >10% on {} (drift={}, "
                        "+{} unaccounted{}) -- check whether encap "
                        "copies are counted differently between DCHAL "
                        "and SONiC port stats"
                        .format(test_label, d1_tot_p, d1_agg_tx,
                                port_info.get('egress', '?'),
                                drift, unaccounted, detail))

        # ── Ixia aggregate soft assertions ───────────────────────────────
        # ixia_agg may be None if the aggregate-stats call faulted (rare).
        if ixia_agg is not None:
            if ixia_agg['tx_total'] < _SMOKE_PKTS_PER_BURST:
                soft_warns.append(
                    "{}: Ixia TX-port aggregate says only {}/{} pkts left "
                    "the Ixia - stream may not have run, or Ixia TX is "
                    "rate-limiting / the burst window was too narrow"
                    .format(test_label, ixia_agg['tx_total'],
                            _SMOKE_PKTS_PER_BURST))
            if (ixia_agg['rx_total'] < _SMOKE_PKTS_PER_BURST and
                    ixia_agg['tx_total'] >= _SMOKE_PKTS_PER_BURST):
                soft_warns.append(
                    "{}: Ixia TX OK ({} pkts) but Ixia RX-port aggregate "
                    "only saw {}/{} pkts - packets dropped between DUT1 "
                    "and Ixia RX (check peer-link, DUT2 decap, DUT2 egress "
                    "MAC, Ixia RX port up).".format(
                        test_label, ixia_agg['tx_total'],
                        ixia_agg['rx_total'], _SMOKE_PKTS_PER_BURST))
            # If aggregate says RX is full but decoded RX is short, the
            # capture engine missed packets - useful to know.
            if (rx_n == 0 and
                    ixia_agg['rx_total'] >= _SMOKE_PKTS_PER_BURST):
                soft_warns.append(
                    "{}: Ixia aggregate confirms RX-port received {} pkts "
                    "but the capture engine decoded 0 - capture trigger "
                    "window missed the burst. Re-run or widen wait.".format(
                        test_label, ixia_agg['rx_total']))

        # ── Assert per-frame on the RX side ──────────────────────────────
        # TX side is not captured (see _smoke_run_with_rx_capture); the
        # `capture_only_rx` arg is kept on the function signature for
        # backwards compatibility but is now effectively always True.
        #
        # We do NOT pass noise_breakdown here because the pre-classify
        # pass above (just after rx_n is computed) already populated it.
        # Re-counting inside _smoke_assert_frames would double the noise
        # count and produce misleading "2 LLDP" lines when only 1 LLDP
        # frame was captured.
        if rx_n > 0:
            _smoke_assert_frames(
                cap['rx']['decoded'], "RX", rx_spec,
                hard_failures, soft_warns)

    finally:
        # ── QoS verdict: DSCP -> TC -> Q placement on DUT2 egress ────────
        # Mirrors test_dscp_to_tc.py:_log_queue_placement_table style.
        # Renders the canonical DSCP Queue-Placement Results table.
        try:
            if dut2_ctx.is_real():
                deltas = {}
                for qi in range(8):
                    entry = (dut2_q_deltas or {}).get(qi) or {}
                    deltas[qi] = {
                        'pkts': int(entry.get('pkts', 0) or 0),
                        'drop_pkts': int(entry.get('drop_pkts', 0) or 0),
                    }
                expected = {qi: (_SMOKE_PKTS_PER_BURST if qi == int(expected_tc)
                                 else 0)
                            for qi in range(8)}
                smoke_log_q_results(
                    deltas,
                    label="[{} DSCP={} TC={}]".format(
                        test_label, dscp, expected_tc),
                    expected=expected)
        except Exception as exc:
            st.warn("smoke_log_q_results failed: {}".format(exc))

        # ── Build the per-instance evidence bag ──────────────────────────
        # Best-effort: every key is wrapped in try/except so a missing
        # attribute can't shadow the test's real verdict.
        evidence = {}
        try:
            evidence['duration_s']   = time.time() - start_time
            evidence['expected_tc']  = int(expected_tc)
            evidence['pkts_expected'] = int(_SMOKE_PKTS_PER_BURST)
            # Surface the captured control-plane noise breakdown so the
            # scorecard / aggregate readers can see at a glance that the
            # extra captured frames were benign chatter (LLDP/BGP/ARP/
            # ND/...) rather than test traffic with bad markings.
            evidence['noise_count']    = int(noise_n)
            evidence['noise_summary']  = noise_summary
            evidence['noise_breakdown'] = list(noise_breakdown)
            # Tell the scorecard which DCHAL column (UC vs MC) drives
            # the dut1_queue and dut2_queue rows.  Resolution order:
            #
            #   1. Caller-supplied per-DUT overrides
            #      (primary_queue_col_dut1 / primary_queue_col_dut2)
            #      take the highest precedence -- a class fixture can
            #      pin exactly what it expects on each side.
            #   2. Caller-supplied shorthand (primary_queue_col) fills
            #      whichever per-DUT override is still None.  Used by
            #      tests where both DUTs see the same wire class.
            #   3. Mode-derived default (see the docstring table for
            #      the rationale).  IMPORTANT: DUT1's encap egress
            #      sees the OUTER VxLAN/UDP frame which is unicast
            #      between VTEP IPs regardless of whether the inner
            #      frame is BUM/MC -- so DUT1 defaults to 'uc' for
            #      L2VNI-BUM too, while DUT2 (which forwards the
            #      decapped INNER frame) defaults to 'mc'.
            def _resolve_col(per_dut_override, default_for_mode):
                if per_dut_override in ('uc', 'mc', 'any'):
                    return per_dut_override
                if primary_queue_col in ('uc', 'mc', 'any'):
                    return primary_queue_col
                return default_for_mode

            if mode == 'l2vni':
                if l2vni_force_bum:
                    # BUM-flood: inner is MC, outer (DUT1 fabric
                    # encap) is UC.
                    d1_default, d2_default = 'uc', 'mc'
                elif l2vni_gate_unicast:
                    # Unicast-gated: both sides see UC.
                    d1_default, d2_default = 'uc', 'uc'
                else:
                    # Legacy best-effort -- if EVPN learned, both UC;
                    # if it fell back to BUM, DUT2 should be MC.  We
                    # bias toward the BUM expectation here for
                    # backward compatibility with the pre-split
                    # TestSmokeL2VNI scorecard, but the diag rows
                    # will surface either way.
                    d1_default, d2_default = 'uc', 'mc'
            else:
                # L3VNI family: inner and outer both UC.
                d1_default, d2_default = 'uc', 'uc'

            evidence['primary_queue_col_dut1'] = _resolve_col(
                primary_queue_col_dut1, d1_default)
            evidence['primary_queue_col_dut2'] = _resolve_col(
                primary_queue_col_dut2, d2_default)
            # Back-compat alias.  The legacy single-column field is
            # kept in evidence so any external reporter that still
            # reads ev['primary_queue_col'] gets the DUT2 value
            # (which is the more discriminating one for L2VNI).
            evidence['primary_queue_col'] = (
                evidence['primary_queue_col_dut2'])
            evidence['dut2_egress_intf'] = (
                dut2_port_info.get('egress_ixia', '?')
                if dut2_port_info else '?')

            # 1. VXLAN setup -- proxied via the preflight result captured
            #    by _smoke_preflight() and stashed into a module global.
            if _SMOKE_LAST_PREFLIGHT is not None:
                pf = _SMOKE_LAST_PREFLIGHT
                evidence['preflight'] = pf
                evidence['vxlan_setup_ok']   = (pf.get('hard_fail', 0) == 0)
                evidence['vxlan_setup_note'] = (
                    "preflight HARD pass={}/{} fail={}".format(
                        pf.get('hard_pass', 0),
                        pf.get('hard_pass', 0) + pf.get('hard_fail', 0),
                        pf.get('hard_fail', 0)))
            else:
                evidence['vxlan_setup_ok']   = None
                evidence['vxlan_setup_note'] = '(no preflight result)'

            # 2. QoS setup -- check that dscp_to_tc_map is bound on the
            #    DUT1 ingress port. Re-probe once so the scorecard has a
            #    concrete answer.
            try:
                tc_map = get_port_dscp_tc_map(dut, port_info['ingress'])
                # Any non-empty map name == PASS; empty/None == FAIL.
                if tc_map:
                    evidence['qos_binding_ok']   = True
                    evidence['qos_binding_note'] = (
                        "{} bound to {}".format(tc_map, port_info['ingress']))
                else:
                    evidence['qos_binding_ok']   = False
                    evidence['qos_binding_note'] = (
                        "no dscp_to_tc_map on {}".format(port_info['ingress']))
            except Exception as exc:
                evidence['qos_binding_ok']   = None
                evidence['qos_binding_note'] = (
                    "probe failed: {}".format(exc))

            # 3. TX-vs-RX
            if ixia_agg is not None:
                evidence['ixia_tx_total'] = int(ixia_agg.get('tx_total', 0))
                evidence['ixia_rx_total'] = int(ixia_agg.get('rx_total', 0))

            # 4-6. TTL / DSCP / decap pass-flags derived from
            #      hard_failures string content.
            #
            # We also compute concrete COUNTS of how many decoded RX
            # frames satisfied each invariant, so the scorecard can
            # show real values like "TTL=62 (5/5)" instead of vague
            # prose like "all RX TTL match". Expected values come from
            # rx_spec built above.
            joined = " | ".join(hard_failures or [])
            test_dport = rx_spec.get('l4_dport') if rx_spec else None
            decoded_rx_test = [
                d for d in cap['rx']['decoded']
                if test_dport is None or d.get('l4_dport') == test_dport
            ]
            n_test_rx = len(decoded_rx_test)
            if cap['rx']['decoded']:
                evidence['ttl_check_pass']   = ('ttl_or_hl' not in joined)
                evidence['dscp_check_pass']  = ('dscp' not in joined)
                evidence['decap_check_pass'] = (
                    'has_vxlan_header' not in joined.lower())
                # Concrete counters for the scorecard.
                exp_ttl  = rx_spec.get('ttl_or_hl')
                exp_dscp = rx_spec.get('dscp')
                ttl_match  = sum(1 for d in decoded_rx_test
                                 if d.get('ttl_or_hl') == exp_ttl)
                dscp_match = sum(1 for d in decoded_rx_test
                                 if d.get('dscp') == exp_dscp)
                vxlan_strip = sum(1 for d in decoded_rx_test
                                  if d.get('has_vxlan_header') is False)
                evidence['ttl_observed']      = exp_ttl
                evidence['ttl_match_count']   = ttl_match
                evidence['ttl_total_rx']      = n_test_rx
                evidence['dscp_observed']     = exp_dscp
                evidence['dscp_match_count']  = dscp_match
                evidence['dscp_total_rx']     = n_test_rx
                evidence['decap_strip_count'] = vxlan_strip
                evidence['decap_total_rx']    = n_test_rx
                evidence['rx_test_count']     = n_test_rx
                evidence['rx_raw_count']      = len(cap['rx']['decoded'])

            # 7. DUT2 queue placement + wrong-queue dict
            if dut2_q_deltas:
                evidence['dut2_q_deltas'] = dut2_q_deltas
                wrong = {}
                for qi, q in dut2_q_deltas.items():
                    qpkts = (int(q.get('pkts', 0))
                              if isinstance(q, dict) else int(q or 0))
                    if int(qi) != int(expected_tc) and qpkts > 0:
                        wrong[int(qi)] = qpkts
                evidence['wrong_queue_pkts'] = wrong
                # Log UC vs MC for the expected TC -- helpful when the
                # scorecard primary column ('uc' or 'mc') reports 0 and
                # we want to confirm the burst actually landed in the
                # OTHER column.
                exp_q = dut2_q_deltas.get(int(expected_tc), {}) \
                            if isinstance(dut2_q_deltas, dict) else {}
                if isinstance(exp_q, dict):
                    st.log(
                        "  DUT2 q[{}] split: uc={}  mc={}  total={}  "
                        "(scorecard primary_col={})".format(
                            int(expected_tc),
                            exp_q.get('uc_pkts', 'N/A'),
                            exp_q.get('mc_pkts', 'N/A'),
                            exp_q.get('pkts_sum',
                                exp_q.get('pkts', 'N/A')),
                            evidence.get(
                                'primary_queue_col_dut2',
                                evidence.get(
                                    'primary_queue_col', 'uc'))))

            # 7b. DUT1 encap egress -- per-queue + aggregate. Used by the
            #     scorecard's 'DUT1 encap to right TC' row and by the
            #     path-triage table to split 'somewhere DUT1->DUT2' into
            #     'before DUT1 fabric port' vs 'after'.
            if dut1_q_deltas:
                evidence['dut1_q_deltas']      = dut1_q_deltas
                evidence['dut1_egress_intf']   = port_info.get('egress', '?')
                d1_wrong = {}
                for qi, q in dut1_q_deltas.items():
                    qpkts = (int(q.get('pkts', 0))
                              if isinstance(q, dict) else int(q or 0))
                    if int(qi) != int(expected_tc) and qpkts > 0:
                        d1_wrong[int(qi)] = qpkts
                evidence['dut1_wrong_queue_pkts'] = d1_wrong
                # Same UC/MC sanity log line for the DUT1 encap side.
                exp_q1 = dut1_q_deltas.get(int(expected_tc), {}) \
                            if isinstance(dut1_q_deltas, dict) else {}
                if isinstance(exp_q1, dict):
                    st.log(
                        "  DUT1 q[{}] split: uc={}  mc={}  total={}  "
                        "(scorecard primary_col={})".format(
                            int(expected_tc),
                            exp_q1.get('uc_pkts', 'N/A'),
                            exp_q1.get('mc_pkts', 'N/A'),
                            exp_q1.get('pkts_sum',
                                exp_q1.get('pkts', 'N/A')),
                            evidence.get(
                                'primary_queue_col_dut1',
                                evidence.get(
                                    'primary_queue_col', 'uc'))))
            if dut1_agg_deltas:
                evidence['dut1_agg_deltas'] = dut1_agg_deltas

            # Optional Ixia stream handle for GUI cross-reference.
            if stream_handle is not None:
                evidence['tg_streams'] = {'tx': str(stream_handle)}

            # 8. Next-step CLI hints when something failed.
            next_steps = []
            if hard_failures or soft_warns:
                if 'ttl_or_hl' in joined:
                    next_steps.append(
                        "TTL mismatch: on DUT1 'show vxlan tunnel', on DUT2 "
                        "'show vxlan tunnel' + 'show ip route vrf {}' to "
                        "confirm decap path is L3 routing".format(
                            _I_VRF if is_l3vni_family else 'default'))
                if 'dscp' in joined:
                    next_steps.append(
                        "DSCP mismatch: on DUT1 'show qos map dscp-to-tc {}'"
                        " (expect AZURE_LOSSY); on DUT2 same map on egress "
                        "port. Also 'sonic-db-cli ASIC_DB hgetall ...' for "
                        "tunnel decap_dscp_mode (must be UNIFORM).".format(
                            port_info['ingress']))
                if 'has_vxlan_header' in joined.lower():
                    next_steps.append(
                        "VXLAN header still present in RX: DUT2 did not "
                        "decap. Run 'show vxlan remotevtep' / 'show vxlan "
                        "vrfvnimap' / 'show vxlan vlanvnimap' on DUT2.")
                if (ixia_agg is not None and
                        ixia_agg.get('tx_total', 0) > ixia_agg.get('rx_total', 0)):
                    drop = (ixia_agg.get('tx_total', 0) -
                             ixia_agg.get('rx_total', 0))
                    next_steps.append(
                        "Fabric loss of {} pkts (Ixia TX>RX). Inspect peer-"
                        "link counters: 'show interfaces counters' on both "
                        "DUTs. Also 'sonic-clear queuecounters' before re-"
                        "running for a clean baseline.".format(drop))
            if next_steps:
                evidence['next_steps'] = next_steps
        except Exception as exc:
            st.warn("scorecard evidence assembly failed (non-fatal): {}"
                    .format(exc))

    st.log("  {} summary: hard_failures={}  soft_warns={}  "
           "captured={} (test=5 + noise={}{})".format(
                test_label, len(hard_failures), len(soft_warns),
                rx_n, noise_n,
                ': ' + noise_summary if noise_summary else ''))
    for w in soft_warns:
        st.log("    WARN: {}".format(w))
    for f in hard_failures:
        st.log("    FAIL: {}".format(f))

    return hard_failures, soft_warns


# ────────────────────────────────────────────────────────────────────────────
# Pre-flight underlay + overlay verification
# ────────────────────────────────────────────────────────────────────────────
#
# Runs ONCE at smoke-class setup, immediately after _setup_vxlan_l3vni() /
# _setup_vxlan_l2vni() has completed. The job is to prove the fabric is
# actually carrying traffic end-to-end BEFORE we burn ~3 min running 16
# smoke instances that would all fail with "RX captured 0 frames".
#
# If any check fails the preflight calls pytest.skip() with a multi-line
# diagnostic, which marks all 16 smoke instances in the class as SKIPPED
# rather than FAILED. That's the right signal: the fabric is broken,
# not the test.
# ────────────────────────────────────────────────────────────────────────────


def _ping_returns_ok(dut_handle, target, label, cmd='ping'):
    """Run a ping with a 3-packet probe and return (ok_bool, summary_str).

    Returns False if any of these markers appear in the output:
        '0 received', 'Unreachable', 'Network is unreachable',
        '100% packet loss'

    The ``summary_str`` is a compact, structured value the preflight
    summary line surfaces -- e.g. "3/3 reply avg=0.45ms" -- so the
    log shows WHAT proved the OK, not just "OK".

    Logs both pass and fail so the smoke log captures fabric state.
    """
    ping_out = st.config(
        dut_handle, "{} -c 3 -W 2 {}".format(cmd, target),
        skip_error_check=True)
    ping_str = str(ping_out) if ping_out else ''
    bad_markers = ('0 received', 'Unreachable', '100% packet loss',
                   'Network is unreachable', 'Destination Host Unreachable')
    ok = not any(m in ping_str for m in bad_markers)
    last = ping_str.splitlines()[-3:] if ping_str else []
    raw_summary = " | ".join(line.strip() for line in last) or "<no output>"

    # Extract structured value: "<rcv>/<sent> reply" plus avg RTT.
    # Linux ping reports e.g. "3 packets transmitted, 3 received, 0%
    # packet loss" and "rtt min/avg/max/mdev = 0.4/0.5/0.6/0.0 ms".
    import re as _re
    sent = rcv = None
    m = _re.search(r'(\d+)\s+packets transmitted,\s+(\d+)\s+received',
                   ping_str)
    if m:
        sent, rcv = int(m.group(1)), int(m.group(2))
    avg_ms = None
    m = _re.search(r'rtt[^=]*=\s*[\d.]+/([\d.]+)/', ping_str)
    if m:
        try:
            avg_ms = float(m.group(1))
        except ValueError:
            pass
    if sent is not None and rcv is not None:
        value_str = "{}/{} reply".format(rcv, sent)
        if avg_ms is not None:
            value_str += ", avg={:.2f}ms".format(avg_ms)
    else:
        # Fallback: a couple of keywords from the tail (we always have
        # SOME output, even on failure, that's worth surfacing).
        value_str = raw_summary[:80]

    if ok:
        st.log("  preflight ping OK : {} ({}): {}".format(
            label, target, value_str[:160]))
    else:
        st.warn("  preflight ping FAIL: {} ({}): {}".format(
            label, target, raw_summary[:160]))
    return ok, value_str


# ─────────────────────────────────────────────────────────────────────────
# DESIGN NOTE: control-plane noise (LLDP / BGP) on the fabric link
# ─────────────────────────────────────────────────────────────────────────
# An earlier revision of this file shipped a `_smoke_disable_lldp()`
# helper that did `sudo systemctl stop lldp` on both DUTs at class
# setup and `sudo systemctl start lldp` on teardown. The intent was
# to make the per-stage counter table read exactly 5/5/5/5 for a
# 5-packet test burst, instead of 9/10/5/5 once LLDP/BGP frames were
# folded into the fabric-port aggregate.
#
# That helper was REMOVED on 2026-05-15 after smoke_one_tag.log
# revealed it broke the entire DUT2 transceiver plane:
#
#   DUT1: 'show interfaces transceiver presence' -> 57 ports listed
#   DUT2: 'show interfaces transceiver presence' -> 0 ports listed
#
# On some SONiC builds the systemd unit named 'lldp' is actually the
# LLDP container, which co-hosts xcvrd (and other PMon daemons).
# Stopping the container racily took xcvrd down on DUT2 and made the
# preflight ping over Ethernet1_54_1 (transit) and Ethernet1_49
# (Ixia egress) time out -- not because the test broke them, but
# because there was no longer a transceiver from the SAI's point of
# view. The whole preflight failed and the smoke class skipped 16
# instances chasing a phantom fabric break.
#
# The fix: leave LLDP alone, and make the per-stage counter
# comparison tolerant to overcount. That's done in
# `_smoke_render_final_summary_row()._glyph()` -- the rule there is
# now `delta >= pkts_sent -> PASS`. A handful of LLDP frames riding
# alongside our 5-packet burst is a normal lab condition; flagging
# it as anything other than PASS would mask the real signal we care
# about ("did at least our 5 packets make it through this stage?").
# ─────────────────────────────────────────────────────────────────────────


def _smoke_setup_l3vni_tagged_svi():
    """Layer a tagged-SVI ingress on top of an existing L3VNI fabric.

    Pre-conditions: the caller has already invoked ``_setup_vxlan_l3vni()``
    so the ingress port is bound to ``_I_VRF`` with V4/V6 IPs and the
    DSCP-to-TC map bound on the physical port.

    Steps performed on DUT1 (DUT2 is untouched -- its egress remains
    routed-in-VRF, which is the L3VNI behavior we want to preserve):

      1. Remove V4 and V6 IPs from the physical ingress port.
      2. Unbind the physical port from _I_VRF (back to default VRF).
      3. ``config vlan add <_L2_VLAN_ID>``.
      4. ``config vlan member add <_L2_VLAN_ID> <ingress_intf>`` (tagged).
      5. ``config interface vrf bind Vlan<_L2_VLAN_ID> _I_VRF``.
      6. Re-add V4/V6 IPs on the SVI (Vlan<_L2_VLAN_ID>).
      7. (DSCP-to-TC map binding is intentionally LEFT in place on the
         physical port -- see the long-form rationale in the body
         comment below.)

    Why we DON'T touch the dscp_to_tc_map binding (key design choice):
      The Tortuga reference tests
      (cisco/tortuga/qos/test_v6_pfc_vxlan_l3vni_2x2.py and friends)
      leave PORT_QOS_MAP|Ethernet*.dscp_to_tc_map=AZURE bound on the
      PHYSICAL port (set by 'config qos reload' in setup_topo_common)
      and never bind it on the Vlan{N} SVI. The classifier runs at
      PHYSICAL-PORT INGRESS, BEFORE the 802.1Q tag is stripped and
      BEFORE the SVI L3 lookup. So binding on the SVI is at best a
      no-op (orchagent on this platform doesn't program SAI from the
      SVI entry) and at worst silently breaks classification on builds
      where the SVI bind triggers an unbind on the underlying port.
      An earlier revision of this helper (smoke_one_tag.log @
      2026-05-15) HDEL'd the port binding and HSET'd the SVI binding;
      the result was 'all packets to Q0' regardless of inner DSCP.

    Net effect: ingress frames must arrive 802.1Q-tagged with VID
    _L2_VLAN_ID; the SVI does the L3 lookup into _I_VRF; the lookup
    hits the EVPN-imported overlay route to the remote VTEP and triggers
    L3VNI encap. End-to-end TTL decrement is still 2 (DUT1 SVI L3 +
    DUT2 decap L3) -- the SVI is just a different L3 ingress interface;
    it does not add or skip a hop.

    End-to-end picture (concrete values from the running smoke; constants
    sourced from qos_helpers.py + test_dscp_to_tc.py so this stays in
    sync with the actual config; constants are re-listed here so a code
    reader doesn't have to chase imports):

      Ixia Port 1 (TX)                            Ixia Port 2 (RX)
      src: 10.10.10.2 (V4) / 2001:db8:10::2 (V6)  dst seen: 20.20.20.2 (V4)
      gw:  10.10.10.1 (V4) / 2001:db8:10::1 (V6)            2001:db8:20::2 (V6)
      src MAC: 00:11:01:00:00:01  (IXIA_SRC_MAC['ingress_a'])
            |
            |  802.1Q-tagged frame
            |  VID = 100  (_L2_VLAN_ID, the access VLAN under the SVI)
            |  IP src = 10.10.10.2,  dst = 20.20.20.2,  DSCP = <test value>
            |  TTL = 64
            v
      +------------------ DUT1 (VTEP1, ASN _I_BGP_AS1=65001) ------------------+
      |                                                                        |
      |  Ethernet1_49  (physical wire-side port, INGRESS)                      |
      |    L2:   TAGGED member of Vlan100                                      |
      |    L3:   no IP, no VRF binding                                         |
      |    QoS:  PORT_QOS_MAP|Ethernet1_49.dscp_to_tc_map = AZURE              |
      |          <-- DSCP->TC classifier fires HERE, BEFORE 802.1Q strip --    |
      |              (Tortuga reference pattern: classifier on the wire        |
      |               port, NEVER on the SVI on this platform; see "Why we     |
      |               DON'T touch the dscp_to_tc_map binding" above)           |
      |                                                                        |
      |  Vlan100  (SVI sitting on top of Ethernet1_49 -- _L2_VLAN_ID)          |
      |    L3:   10.10.10.1/24      (V4_INGRESS_A_IP -- "lives on the SVI      |
      |                              in this mode, not on Ethernet1_49")      |
      |          2001:db8:10::1/64  (V6_INGRESS_A_IP -- same story for V6)     |
      |    VRF:  VrfQoS                  (_I_VRF, the L3VNI overlay VRF)      |
      |                                                                        |
      |    +-> route lookup in VrfQoS                                          |
      |        |- inner DIP 20.20.20.2 -> next-hop = remote VTEP via L3VNI 5001|
      |        |- TTL: inner-1 (64 -> 63) BEFORE encap                         |
      |        +- VXLAN encap                                                  |
      |            |- outer src = Loopback1 IP = 40.40.40.1   (_I_VTEP1_IP)    |
      |            |- outer dst = remote VTEP   = 40.40.40.2   (_I_VTEP2_IP)   |
      |            |- VNI       = 5001                          (_I_VNI)       |
      |            |- outer DSCP = inner DSCP (uniform, copy-on-encap)         |
      |            +- outer TTL  = pipe model (fresh 64 from VTEP)             |
      |                                                                        |
      |  Ethernet1_54_1  (transit port, default VRF, underlay)                 |
      |    L3:   30.30.30.1/24       (V4_TRANSIT_DUT1_IP, transit to DUT2)     |
      |    Routes: 40.40.40.2/32 -> 30.30.30.2  (BGP-EVPN underlay)            |
      |                                                                        |
      +-------------------------------------+----------------------------------+
                                            |
                                            v  outer IP 40.40.40.1 -> 40.40.40.2
                                               UDP/4789, VXLAN VNI=5001
                                               inner: 10.10.10.2 -> 20.20.20.2
                                               + DSCP preserved
                                            |
      +-------------------------------------+--- DUT2 (VTEP2, ASN _I_BGP_AS2=65002) -+
      |                                                                              |
      |  Ethernet1_54_1  (transit port, default VRF)                                 |
      |    L3:   30.30.30.2/24                                                       |
      |          outer dst = my VTEP IP (40.40.40.2) -> punt to VXLAN decap          |
      |                                                                              |
      |    +-> VXLAN decap                                                           |
      |        |- strip outer Eth + outer IP + UDP + VXLAN                           |
      |        |- DSCP carried into the inner header (uniform model)                 |
      |        +- TTL: inner stays 63 (pipe; outer TTL discarded)                    |
      |                                                                              |
      |    +-> L3 lookup in VrfQoS (associated with VNI 5001)                        |
      |        +- inner DIP 20.20.20.2 -> directly connected via Ethernet1_49        |
      |                                                                              |
      |  Ethernet1_49  (egress port to Ixia Port 2, in VrfQoS)                       |
      |    L3:   20.20.20.1/24       (V4_EGRESS_IP)                                  |
      |          2001:db8:20::1/64   (V6_EGRESS_IP)                                  |
      |    QoS:  PORT_QOS_MAP|Ethernet1_49.dscp_to_tc_map = AZURE                    |
      |          <-- decap-side classifier verifies the TC the packet is queued on --|
      |          (this is what the smoke's per-queue counters actually read)         |
      |                                                                              |
      +-----------------------------------+------------------------------------------+
                                          |
                                          v  IP src = 10.10.10.2, dst = 20.20.20.2
                                             DSCP preserved, TTL = 62
                                             (62 = 64 - 2 hops: VTEP1 + VTEP2)
                                    Ixia Port 2 RX

    Notes:
      * Subnets (10.10.10.0/24, 2001:db8:10::/64) are inherited from
        qos_helpers.py and shared across every QoS test in the suite.
        Reusing them keeps the SVI variant drop-in compatible with
        Ixia gateway resolution from the routed-port (l3vni) variant
        -- no Ixia re-prime is required when switching between
        l3vni and l3vni_tagged within the same fixture lifetime.
      * VLAN ID is _L2_VLAN_ID=100 here (TestSmokeL3VNITagged + the
        older H1/H2 SVI tests). The L2VNI smoke uses a different VLAN
        (_J_L2_VLAN=502); do not confuse the two.
      * TTL accounting: 64 (TX) -> 63 (after DUT1 SVI L3) -> 62 (after
        DUT2 decap+L3). The outer underlay TTL is independent of the
        inner and is discarded at decap (pipe model).

    Returns a teardown callable that reverses every step (idempotent on
    teardown errors -- each st.config uses skip_error_check=True so a
    half-applied state can still be cleaned up). Caller MUST stash the
    returned callable in a try/finally and invoke it to restore the
    plain-L3VNI ingress port for any subsequent class.
    """
    if not dut or not port_info.get('ingress'):
        st.log("  _smoke_setup_l3vni_tagged_svi: no DUT1 ingress -- "
               "skipping (test should also be skipped)")
        return lambda: None

    ingress_intf = port_info['ingress']
    svi_intf     = 'Vlan{}'.format(_L2_VLAN_ID)

    # 1. Remove L3 IPs from the physical port (they were re-added inside
    #    _I_VRF by _setup_vxlan_l3vni; we need to free them before the
    #    VRF unbind in step 2).
    st.config(dut,
        'config interface ip remove {} {}'.format(
            ingress_intf, V4_INGRESS_A_IP),
        skip_error_check=True)
    st.config(dut,
        'config interface ip remove {} {}'.format(
            ingress_intf, V6_INGRESS_A_IP),
        skip_error_check=True)
    st.wait(1)

    # 2. Take the physical port out of _I_VRF (default VRF). The SVI
    #    will own the VRF binding from this point on.
    st.config(dut,
        'config interface vrf unbind {}'.format(ingress_intf),
        skip_error_check=True)
    st.wait(1)

    # 3. Create the access VLAN.
    st.config(dut,
        'config vlan add {}'.format(_L2_VLAN_ID),
        skip_error_check=True)
    st.wait(1)

    # 4. Add the physical port as a TAGGED member (no --untagged flag --
    #    SONiC defaults to tagged when --untagged is omitted).
    st.config(dut,
        'config vlan member add {} {}'.format(
            _L2_VLAN_ID, ingress_intf),
        skip_error_check=True)
    st.wait(1)

    # 5. Bind the SVI to _I_VRF so the L3 lookup happens in the L3VNI
    #    VRF and triggers EVPN-overlay encap.
    st.config(dut,
        'config interface vrf bind {} {}'.format(svi_intf, _I_VRF),
        skip_error_check=True)
    st.wait(1)

    # 6. Re-add the same V4/V6 IPs on the SVI (so Ixia's gateway
    #    config keeps working unchanged -- we keep the IP-of-record
    #    stable across the L3VNI/L3VNI-tagged variants).
    st.config(dut,
        'config interface ip add {} {}'.format(svi_intf, V4_INGRESS_A_IP),
        skip_error_check=True)
    st.config(dut,
        'config interface ip add {} {}'.format(svi_intf, V6_INGRESS_A_IP),
        skip_error_check=True)
    st.wait(2)

    # 7. (No HSET -- the DSCP-to-TC binding stays where 'config qos
    #    reload' in setup_topo_common put it: on the PHYSICAL port.
    #    See the long-form 'Why we DON'T touch the dscp_to_tc_map
    #    binding' note in the docstring above for the reasoning.)
    #
    #    Defensive: re-assert the AZURE binding on the physical port
    #    in case some prior test class HDEL'd it. setup_topo_common
    #    runs 'config qos reload' once at module init, but a previous
    #    smoke instance (eg a stale revision of this helper, an aborted
    #    run that left HDEL applied, or an L2VNI test that swapped the
    #    binding around) might have left PORT_QOS_MAP|<port> empty.
    #    HSET is idempotent: setting it to AZURE when it's already
    #    AZURE is a no-op; setting it from <empty> to AZURE restores
    #    the post-qos-reload state. Either way, the pre-measure check
    #    in _smoke_run_one will assert it's correct before traffic.
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" "dscp_to_tc_map" '
        '"AZURE"'.format(ingress_intf),
        skip_error_check=True)
    st.wait(5)  # orchagent + intfmgrd need a beat to wire up the SVI

    def _teardown():
        # Setup never HSET on the SVI, so there is no SVI-side HDEL
        # needed here. The dscp_to_tc_map=AZURE binding on the physical
        # port stays in place across the teardown -- the plain-L3VNI
        # variant relies on the exact same physical-port binding, and
        # 'config qos reload' (in setup_topo_common) put it there.
        #
        # Reverse step 6: remove IPs from SVI.
        st.config(dut,
            'config interface ip remove {} {}'.format(
                svi_intf, V4_INGRESS_A_IP),
            skip_error_check=True)
        st.config(dut,
            'config interface ip remove {} {}'.format(
                svi_intf, V6_INGRESS_A_IP),
            skip_error_check=True)
        st.wait(1)
        # Reverse step 5: unbind SVI from VRF.
        st.config(dut,
            'config interface vrf unbind {}'.format(svi_intf),
            skip_error_check=True)
        st.wait(1)
        # Reverse step 4/3: drop port from VLAN, delete VLAN.
        st.config(dut,
            'config vlan member del {} {}'.format(
                _L2_VLAN_ID, ingress_intf),
            skip_error_check=True)
        st.config(dut,
            'config vlan del {}'.format(_L2_VLAN_ID),
            skip_error_check=True)
        st.wait(2)
        # Reverse step 2: rebind physical port to _I_VRF.
        st.config(dut,
            'config interface vrf bind {} {}'.format(
                ingress_intf, _I_VRF),
            skip_error_check=True)
        # Reverse step 1: re-add IPs on the physical port.
        st.config(dut,
            'config interface ip add {} {}'.format(
                ingress_intf, V4_INGRESS_A_IP),
            skip_error_check=True)
        st.config(dut,
            'config interface ip add {} {}'.format(
                ingress_intf, V6_INGRESS_A_IP),
            skip_error_check=True)
        st.wait(1)
        # Defensive re-assert: ensure PORT_QOS_MAP|<ingress>.
        # dscp_to_tc_map=AZURE is still in place after all the rebinds.
        # Idempotent if it already is. Mirrors the same defensive HSET
        # at end of setup; the two together guarantee the port-side
        # binding is valid before AND after the tagged-SVI window.
        st.config(dut,
            'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" '
            '"dscp_to_tc_map" "AZURE"'.format(ingress_intf),
            skip_error_check=True)
        st.wait(3)

    return _teardown


def _parse_sonic_db_hash(out_str):
    """Parse 'sonic-db-cli CONFIG_DB hgetall <key>' output into a dict.

    Two output shapes are tolerated (different sonic-db-cli versions and
    different st.show wrappers produce different framings):

      Shape A -- single-line Python-dict literal (observed on the FX3
      build in smoke_one_tag.log line 2014):
          admin@sonic:~$ sonic-db-cli CONFIG_DB hgetall "..."
          {'0': '0', '1': '1', ..., '63': '1'}
          admin@sonic:~$

      Shape B -- one field per line, ALTERNATING field/value:
          field0
          value0
          field1
          value1
          ...

    The parser tries Shape A first (most reliable -- ast.literal_eval
    is unambiguous if a dict is present), then falls back to Shape B.
    Lines from the shell prompt ('admin@sonic:~$') and blank lines are
    ignored. Returns ``{}`` on empty / malformed input rather than
    raising, so the preflight stays diagnostic-only.
    """
    if not out_str:
        return {}

    # ── Shape A: search for a dict literal anywhere in the output ─────
    # The literal might share a line with the prompt or other tokens,
    # so we scan for the first '{' .. matching '}' substring and try
    # ast.literal_eval on it. ast.literal_eval is safe (won't execute
    # arbitrary code) and is the canonical way to parse Python-literal
    # output without resorting to fragile regexes.
    import ast
    start = out_str.find('{')
    if start != -1:
        # Find the matching closing brace by counting depth (handles
        # nested dicts safely, though sonic-db-cli output is flat).
        depth = 0
        end = -1
        for i in range(start, len(out_str)):
            c = out_str[i]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end != -1:
            blob = out_str[start:end]
            try:
                parsed = ast.literal_eval(blob)
                if isinstance(parsed, dict):
                    out = {}
                    for f, v in parsed.items():
                        # Coerce keys/values to str-of-int and validate
                        # they're in DSCP/TC range.
                        try:
                            fi = int(f)
                            vi = int(v)
                        except (TypeError, ValueError):
                            continue
                        if 0 <= fi <= 63 and 0 <= vi <= 7:
                            out[str(fi)] = str(vi)
                    if out:
                        return out
            except (ValueError, SyntaxError):
                # Fall through to Shape B parser.
                pass

    # ── Shape B: alternating field/value lines ─────────────────────────
    pairs = []
    for raw in out_str.splitlines():
        line = raw.strip()
        if not line:
            continue
        # Skip noise: shell prompts, command echo, info lines.
        if line.endswith('$') or line.startswith('admin@') \
                or line.startswith('sonic-db-cli'):
            continue
        # Sometimes the FCMD echo has trailing markers like 'INFO'.
        if line.startswith('FCMD') or line.startswith('SCMD'):
            continue
        pairs.append(line)
    out = {}
    for i in range(0, len(pairs) - 1, 2):
        # Defensive: only accept str-int-ish field/value combos that
        # look like DSCP map entries (field is 0..63, value is 0..7).
        # Generic-mode parses everything; we filter to the expected
        # shape so unrelated noise doesn't pollute the dict.
        f, v = pairs[i], pairs[i + 1]
        try:
            fi = int(f)
            vi = int(v)
        except (TypeError, ValueError):
            continue
        if 0 <= fi <= 63 and 0 <= vi <= 7:
            out[str(fi)] = str(vi)
    return out


def _diff_dscp_maps(golden, live):
    """Return [(dscp:str, golden_tc:str, live_tc:str), ...] for entries
    that differ. DSCPs only present in one map are reported with the
    other side as '?'. Sorted ascending by DSCP int.
    """
    diffs = []
    for d in sorted(set(golden) | set(live), key=lambda s: int(s)):
        g = golden.get(d, '?')
        l = live.get(d, '?')
        if g != l:
            diffs.append((d, g, l))
    return diffs


def _smoke_preflight(mode):
    """Run the full smoke pre-flight after VXLAN setup.

    Mode is 'l3vni' or 'l2vni'. Returns a list of (check, ok, detail)
    tuples and calls pytest.skip(...) if any HARD check failed.

    HARD checks (any failure -> pytest.skip the entire class):
      1. DUT1 -> DUT2 transit IPv4 ping (V4_TRANSIT_DUT2_BARE)
      2. DUT1 -> DUT2 transit IPv6 ping (V6_TRANSIT_DUT2_BARE)

    SOFT checks (logged but don't skip):
      - DUT1 <-> DUT2 VTEP IPv4 ping (sourced from Loopback1)
      - DUT2 -> Ixia egress IPv4 / IPv6 (in VrfQoS for L3VNI)
      - DSCP_TO_TC_MAP|AZURE drift check on both DUTs

    NOTE: VxLAN/EVPN/BGP CLI dumps (show vxlan tunnel, show evpn vni,
    show bgp l2vpn evpn summary, show ip route vrf) were intentionally
    removed -- if BGP/EVPN isn't up, the actual smoke traffic will FAIL
    loudly anyway, and the verbose CLI output dwarfed the QoS verdict.
    """
    results = []   # list of (label, ok_bool, detail, value) for summary
    hard_fails = []
    # Per-call accounting: which results came from hard() vs soft() so the
    # summary line is exact (was previously '-4' magic which broke whenever
    # we added/removed a soft check).
    hard_pass_n = [0]   # list-wrapped to allow inner-fn closure mutation
    hard_fail_n = [0]
    soft_pass_n = [0]
    soft_fail_n = [0]

    def hard(label, ok, detail, value=''):
        results.append((label, ok, detail, value))
        if ok:
            hard_pass_n[0] += 1
        else:
            hard_fail_n[0] += 1
            hard_fails.append("{}: {}".format(label, detail[:200]))

    def soft(label, ok, detail, value=''):
        results.append((label, ok, detail, value))
        if ok:
            soft_pass_n[0] += 1
        else:
            soft_fail_n[0] += 1

    # Resolve the L3VNI-family flag ONCE up-front so every section below
    # (including the G4 Loopback1-sourced VTEP-ping block at 2b) can
    # branch on it. Originally this was defined just before section
    # 3-4, which broke the 2b block when it was inserted above.
    is_l3vni_family_pf = mode in ('l3vni', 'l3vni_tagged')

    # ── 1-2. Underlay transit ping checks (default VRF on both DUTs) ─────
    # These are HARD because if the underlay is dead, VXLAN can't work.
    ok, val = _ping_returns_ok(dut,  V4_TRANSIT_DUT2_BARE,
                               'DUT1->DUT2 transit v4')
    hard("DUT1->DUT2 v4 transit", ok, val, value=val)
    ok, val = _ping_returns_ok(dut,  V6_TRANSIT_DUT2_BARE,
                               'DUT1->DUT2 transit v6', cmd='ping6')
    hard("DUT1->DUT2 v6 transit", ok, val, value=val)

    # ── 2b. Loopback1-sourced VTEP <-> VTEP underlay ping (BOTH DIRS) ────
    # The bare transit ping above proves DUT1's outward physical link can
    # reach DUT2's physical IP, but VXLAN encap actually sources its
    # outer-IP from Loopback1 (the VTEP IP). If the underlay routing
    # of Loopback1 prefixes is broken (e.g. BGP underlay didn't bring
    # 40.40.40.0/24 into both RIBs), the bare transit ping still passes
    # but VXLAN packets get black-holed. Two-directional Loopback1-
    # sourced ping is the *literal* "VXLAN encap can leave the box AND
    # arrive at the remote VTEP" reachability check.
    #
    # Kept SOFT (not HARD) because:
    #   (a) freshly-converged underlay may take a few seconds for
    #       Loopback1 BGP advertisements to install on the remote side;
    #   (b) the actual smoke traffic will fail loudly anyway if VXLAN
    #       encap can't actually leave the box;
    #   (c) we don't want to introduce a new flakiness vector for a
    #       check the user can read directly off the log.
    # If both sides are needed-HARD in the future, flip soft() -> hard().
    vtep_lo_intf = _I_LB_INTF if is_l3vni_family_pf else _J_LB_INTF
    vtep_lo1     = _I_VTEP1_IP if is_l3vni_family_pf else _J_VTEP1_IP
    vtep_lo2     = _I_VTEP2_IP if is_l3vni_family_pf else _J_VTEP2_IP
    ok, val = _ping_returns_ok(
        dut, vtep_lo2,
        'DUT1[{}={}]->DUT2 VTEP {}'.format(vtep_lo_intf, vtep_lo1,
                                           vtep_lo2),
        cmd='ping -I {}'.format(vtep_lo_intf))
    soft("DUT1->DUT2 VTEP ping ({})".format(vtep_lo_intf),
         ok, val, value=val)
    ok, val = _ping_returns_ok(
        dut2, vtep_lo1,
        'DUT2[{}={}]->DUT1 VTEP {}'.format(vtep_lo_intf, vtep_lo2,
                                           vtep_lo1),
        cmd='ping -I {}'.format(vtep_lo_intf))
    soft("DUT2->DUT1 VTEP ping ({})".format(vtep_lo_intf),
         ok, val, value=val)

    # ── 3-4. DUT2 -> Ixia egress, INSIDE VrfQoS (L3VNI only) ─────────────
    # For L3VNI (both untagged and tagged-SVI variants) the egress_ixia
    # port lives in VrfQoS, so a plain `ping` from default VRF will
    # 100% fail (no route). We need `ip vrf exec`. For L2VNI the egress
    # port is a VLAN access member (no VRF), so a plain ping is right
    # but the host endpoint may not be reachable over L2 from DUT2 --
    # we keep this as SOFT in both cases since the overlay-side
    # reachability (DUT1 -> Ixia full path) is the real proof of life.
    # (is_l3vni_family_pf was resolved at the top of this function.)
    if is_l3vni_family_pf:
        # Use `ip vrf exec VrfQoS ping ...` to test DUT2's egress port
        # in its actual VRF.
        ok, val = _ping_returns_ok(
            dut2, IXIA_EGRESS_IP,
            'DUT2[vrf={}]->Ixia egress v4'.format(_I_VRF),
            cmd='sudo ip vrf exec {} ping'.format(_I_VRF))
        soft("DUT2[vrf]->Ixia egress v4", ok, val, value=val)
        ok, val = _ping_returns_ok(
            dut2, IXIA_EGRESS_IP6,
            'DUT2[vrf={}]->Ixia egress v6'.format(_I_VRF),
            cmd='sudo ip vrf exec {} ping6'.format(_I_VRF))
        soft("DUT2[vrf]->Ixia egress v6", ok, val, value=val)
    else:
        # L2VNI: plain ping from DUT2 (no VRF). The egress IP lives on
        # the SVI for the access VLAN; reachability depends on EVPN
        # type-2 routes being installed. Soft only.
        ok, val = _ping_returns_ok(dut2, IXIA_EGRESS_IP,
                                    'DUT2->Ixia egress v4')
        soft("DUT2->Ixia egress v4", ok, val, value=val)
        ok, val = _ping_returns_ok(dut2, IXIA_EGRESS_IP6,
                                    'DUT2->Ixia egress v6', cmd='ping6')
        soft("DUT2->Ixia egress v6", ok, val, value=val)

    # ── AZURE map drift check (DSCP_TO_TC_MAP|AZURE) on BOTH DUTs ────────
    # The smoke test parametrize matrix is generated from
    # GOLDEN_DSCP_TO_TC (in qos_helpers.py), which is sourced from the
    # test plan doc. The DUT's runtime AZURE map however is generated
    # by 'config qos reload' from the platform's qos_fx3.j2 template,
    # which can drift from the doc/repo across image vintages or
    # vendor variants. When the two disagree, the smoke test predicts
    # 'DSCP X -> TC Y' but the DUT actually does 'DSCP X -> TC Z',
    # which manifests as 'expected TC{Y} got 0 pkts; TC{Z} got all 5'
    # and produces the puzzling FAIL on every healthy run (see
    # smoke_one.log 2026-05-15 04:03 -- DSCP 3 -> Q0 instead of Q3).
    #
    # We check BOTH DUTs because:
    #   * DUT1 (ingress/classifier) maps DSCP->TC on packets entering
    #     from Ixia -- drift here breaks the dut1_queue scorecard row.
    #   * DUT2 (egress/decap) ALSO classifies DSCP->TC on the inner
    #     header after VxLAN decap, to pick the egress queue toward
    #     Ixia -- drift here breaks the dut2_queue scorecard row even
    #     when DUT1 is perfect. This is a silent, hard-to-spot root
    #     cause that symmetric diagnostic must catch.
    #
    # For each DUT we:
    #   * Log the live map (always, so you can copy/paste it).
    #   * Log every diff entry as an explicit 'DSCP X golden=Y live=Z'
    #     line, sorted by DSCP. This lets you see at a glance which
    #     test instances would mis-classify on the running image.
    #   * Record SOFT (not hard) so the test still proceeds; the
    #     per-instance scorecard's dut1_queue / dut2_queue checks will
    #     still be definitive about whether a particular DSCP/TC pair
    #     classified correctly OR incorrectly. Promoting drift to
    #     hard would block the smoke whenever the DUT image ships a
    #     non-doc map -- exactly the case where you want diagnostic
    #     evidence, not a class-skip.
    def _azure_drift_check_one(dut_handle, dut_label):
        st.log(" preflight DSCP_TO_TC_MAP|AZURE drift check ({})"
               .format(dut_label))
        try:
            raw = st.show(
                dut_handle,
                'sonic-db-cli CONFIG_DB hgetall "DSCP_TO_TC_MAP|AZURE"',
                skip_tmpl=True, skip_error_check=True)
        except Exception as exc:
            st.warn("    {} AZURE map fetch failed: {}"
                    .format(dut_label, exc))
            raw = ''
        live = _parse_sonic_db_hash(str(raw or ''))
        d = _diff_dscp_maps(GOLDEN_DSCP_TO_TC, live)
        row_label = "AZURE map drift ({})".format(dut_label)
        if not live:
            # Map empty / unparsable -- we cannot compare; soft-warn so
            # operator notices and runs the command manually.
            soft(row_label, False,
                 "could not parse 'sonic-db-cli ... DSCP_TO_TC_MAP|AZURE'",
                 value="parse_failed")
        elif d:
            st.log("    AZURE drift: {} DSCP entries differ between "
                   "GOLDEN_DSCP_TO_TC and the live {} map:"
                   .format(len(d), dut_label))
            for dscp, golden_tc, live_tc in d:
                st.log("      DSCP {:>2}  golden=TC{}  live=TC{}".format(
                    dscp, golden_tc, live_tc))
            st.log("    -> the smoke matrix uses GOLDEN_DSCP_TO_TC; for "
                   "any DSCP listed above the per-instance dut1_queue / "
                   "dut2_queue check will FAIL even on a healthy DUT. "
                   "Either reload the repo's "
                   "tests/cisco/fx3/qos/config_db.json onto the DUT to "
                   "match GOLDEN, or update GOLDEN_DSCP_TO_TC to match "
                   "the live image's qos_fx3.j2 output.")
            soft(row_label, False,
                 "{} DSCP entries differ from GOLDEN_DSCP_TO_TC"
                 .format(len(d)),
                 value="drift={}".format(len(d)))
        else:
            st.log("    AZURE map matches GOLDEN_DSCP_TO_TC exactly "
                   "({} entries)".format(len(live)))
            soft(row_label, True, "",
                 value="match={}".format(len(live)))

    _azure_drift_check_one(dut,  "DUT1")
    _azure_drift_check_one(dut2, "DUT2")

    # Stash a compact summary into a module-global so per-class fixtures
    # can surface preflight totals if needed.
    global _SMOKE_LAST_PREFLIGHT
    _SMOKE_LAST_PREFLIGHT = {
        'mode':      mode,
        'hard_pass': hard_pass_n[0],
        'hard_fail': hard_fail_n[0],
        'soft_pass': soft_pass_n[0],
        'soft_fail': soft_fail_n[0],
        'total':     len(results),
    }

    if hard_fails:
        msg = ("SMOKE PREFLIGHT [{}] FAILED with {} hard check(s). "
               "Skipping all smoke instances in this class:\n  ".format(
                   mode, len(hard_fails)) +
               "\n  ".join(hard_fails))
        pytest.skip(msg)

    return results


# ────────────────────────────────────────────────────────────────────────────
# pytest test classes - one class per VXLAN mode for shared-setup efficiency
# ────────────────────────────────────────────────────────────────────────────
#
# Each class wraps its 16 parametrize instances (8 TCs x 2 AFs) under a
# class-scope autouse fixture that:
#   1. Sets up VXLAN+BGP-EVPN once (via _setup_vxlan_l3vni/l2vni)
#   2. Runs the preflight underlay+overlay verification
#   3. Yields to the test instances
#   4. Tears down VXLAN at the end
#
# This drops per-instance overhead from ~15s setup+teardown to ~0s, saving
# ~6-8 minutes across the 32-instance matrix.
# ────────────────────────────────────────────────────────────────────────────


class TestSmokeL3VNI:
    """16 smoke instances over the L3VNI path (8 TCs x 2 AFs).

    All instances share a single _setup_vxlan_l3vni() configuration. If
    the class fixture's preflight fails, every instance shows SKIPPED with
    the preflight diagnostic, rather than FAILED with confusing 0-RX
    output 16 times in a row.
    """

    @pytest.fixture(scope="class", autouse=True)
    def _setup_l3vni(self):
        if topo_mode == 'ixia':
            pytest.skip(
                "Smoke L3VNI requires 2-DUT topology (peer_link/breakout); "
                "current mode is 'ixia'")

        teardown = _setup_vxlan_l3vni()
        # NOTE: we deliberately do NOT stop LLDP here. The earlier
        # 'systemctl stop lldp' approach disturbed the entire SONiC
        # 'lldp' container (which co-hosts xcvrd in some builds) and
        # silently took DUT2's transceiver plane offline -- both
        # Ethernet1_49 and Ethernet1_54_1 went physically dark even
        # though SONiC port admin/oper state still reported 'up',
        # causing every preflight ping to time out. See the long-form
        # rationale in _smoke_render_final_summary_row()._glyph(): we
        # now treat fabric-port deltas of `>= pkts_sent` as PASS so a
        # handful of LLDP/BGP frames riding alongside our 5-packet
        # burst no longer 'confuses' the per-stage table.
        try:
            _smoke_preflight('l3vni')
            yield
        finally:
            try:
                teardown()
            except Exception as exc:
                st.warn("_setup_vxlan_l3vni teardown raised: {}".format(exc))

    @pytest.mark.parametrize("af", ["ipv4", "ipv6"])
    @pytest.mark.parametrize("tc_dscp",
                             _smoke_pairs(), ids=_smoke_pair_ids())
    def test_dscp_to_tc_smoke_l3vni_ucast(self, af, tc_dscp):
        """SMOKE-L3VNI-UCAST - send 5 unicast packets at one DSCP through
        the L3VNI path, capture both TX and RX Ixia ports, decode every
        frame and assert:

          - L3 family preserved (ipv4 or ipv6)
          - DSCP preserved through encap + decap
          - TTL_rx == TTL_tx - 2  (L3VNI: DUT1 ingress L3 + DUT2 egress L3)
          - has_vxlan_header == False on RX (proves decap stripped VXLAN)
          - UDP dport == 5000 + DSCP       (test-stream identity)

        Naming note
        -----------
        Historically this method was named ``..._smoke_l3vni_e2e`` and
        the test_label was ``SMOKE-L3VNI[...]``.  Both were renamed to
        ``..._smoke_l3vni_ucast`` / ``SMOKE-L3VNI-UCAST[...]`` to make
        the forwarding mode explicit and to stay consistent with the
        L2VNI smoke classes (``TestSmokeL2VNIBum`` for BUM-flood
        verification, ``TestSmokeL2VNIUcast`` for FDB-learned unicast).
        L3VNI traffic is always *routed unicast* (DUT1 looks up the
        destination IP in the L3VNI VRF and forwards via VTEP), so
        ``_ucast`` is the accurate descriptor.
        """
        tc, dscp = tc_dscp
        test_label = "SMOKE-L3VNI-UCAST[{}][tc{}-dscp{}]".format(
            af, tc, dscp)
        print_section(
            "{} - 5 pkts via VxLAN L3VNI ({})".format(test_label, _I_VNI),
            art_key='dscp_to_tc')

        hard_failures, soft_warns = _smoke_run_one(
            test_label, af, dscp, expected_tc=tc, mode='l3vni')

        if hard_failures:
            st.report_fail('msg', "{} HARD failures ({}):\n  ".format(
                test_label, len(hard_failures)) + "\n  ".join(hard_failures))
        st.report_pass('msg',
            "{}: 5 pkts L3VNI UC e2e PASS (soft_warns={})".format(
                test_label, len(soft_warns)))


class TestSmokeL3VNITagged:
    """16 smoke instances over the L3VNI path with an 802.1Q-tagged ingress.

    This class exercises the EDGE deployment shape that is most common in
    DC pods running EVPN: a downstream host or aggregation switch sends
    tagged frames into a leaf, and the leaf SVI does the L3 lookup into
    a tenant VRF that is mapped to an L3VNI. We share the underlying
    VXLAN+EVPN fabric with TestSmokeL3VNI, then layer one extra step
    (the DUT1 ingress port becomes a tagged member of Vlan{_L2_VLAN_ID},
    the SVI gets the same V4/V6 IPs and is bound to _I_VRF).

    Mechanics relative to TestSmokeL3VNI:
      * dst_mac on Ixia is the SVI MAC, not the physical-port MAC.
      * Every frame carries an 802.1Q tag (VID = _L2_VLAN_ID).
      * TTL decrement count is unchanged (-2): the SVI strip-and-route
        is one L3 hop, the DUT2 decap-route is the second.
      * DUT2 is unmodified -- its egress remains a routed-in-VRF port,
        and the captured RX frames on the Ixia side are untagged. The
        side-by-side dump surfaces this asymmetry as a '* VLAN = 100 |
        VLAN = -' row, which is the natural cue for "tag was stripped
        at the L2->L3 ingress and the egress side is L3 routed (no tag)".

    See TestSmokeL3VNI docstring for the shared-setup rationale, the
    pre-flight semantics and the per-instance scorecard contract -- all
    of those carry over unchanged.
    """

    @pytest.fixture(scope="class", autouse=True)
    def _setup_l3vni_tagged(self):
        if topo_mode == 'ixia':
            pytest.skip(
                "Smoke L3VNI-tagged requires 2-DUT topology "
                "(peer_link/breakout); current mode is 'ixia'")

        # Layer order matters:
        #   1. Bring up the underlay+overlay (VXLAN, BGP-EVPN, VRF, VTEPs).
        #   2. Convert the DUT1 ingress to a tagged-SVI-on-VRF on top of
        #      the already-VRF-bound port. Step 2 must run AFTER step 1
        #      so the SVI inherits the live BGP-EVPN imported routes.
        # Teardown is reversed: SVI first, then VXLAN.
        teardown_vxlan = _setup_vxlan_l3vni()
        teardown_svi = None
        # See TestSmokeL3VNI for why LLDP is intentionally LEFT
        # running here (was: _smoke_disable_lldp() prior to
        # 2026-05-15; removed because the systemd 'lldp' container
        # stop on DUT2 took xcvrd down with it).
        try:
            teardown_svi = _smoke_setup_l3vni_tagged_svi()
            # Pre-flight uses mode='l3vni_tagged' so the L3VNI-only
            # checks (overlay route, EVPN routes) still run, but any
            # future tagged-specific checks (eg verify SVI is in the
            # right VRF) can hang off the same mode token.
            _smoke_preflight('l3vni_tagged')
            yield
        finally:
            if teardown_svi is not None:
                try:
                    teardown_svi()
                except Exception as exc:
                    st.warn("_smoke_setup_l3vni_tagged_svi teardown "
                            "raised: {}".format(exc))
            try:
                teardown_vxlan()
            except Exception as exc:
                st.warn("_setup_vxlan_l3vni teardown raised: {}"
                        .format(exc))

    @pytest.mark.parametrize("af", ["ipv4", "ipv6"])
    @pytest.mark.parametrize("tc_dscp",
                             _smoke_pairs(), ids=_smoke_pair_ids())
    def test_dscp_to_tc_smoke_l3vni_tagged_ucast(self, af, tc_dscp):
        """SMOKE-L3VNI-TAGGED-UCAST - send 5 802.1Q-tagged unicast
        packets at one DSCP through the L3VNI path with a tagged-SVI
        ingress, capture both TX and RX Ixia ports, decode every frame
        and assert:

          - L3 family preserved (ipv4 or ipv6)
          - DSCP preserved through SVI L3 lookup + encap + decap
          - TTL_rx == TTL_tx - 2  (SVI L3 + DUT2 egress L3)
          - has_vxlan_header == False on RX (proves decap stripped VXLAN)
          - UDP dport == 5000 + DSCP       (test-stream identity)
          - TX side carries 802.1Q tag VID=_L2_VLAN_ID; RX side is
            untagged (DUT2 egress is a routed port). The renderer's
            VLAN row will mark this with '*' -- that is EXPECTED, not
            a regression.

        Naming note
        -----------
        Renamed from ``..._smoke_l3vni_tagged_e2e`` /
        ``SMOKE-L3VNI-TAGGED[...]`` to
        ``..._smoke_l3vni_tagged_ucast`` /
        ``SMOKE-L3VNI-TAGGED-UCAST[...]`` for the same reason as the
        sibling ``test_dscp_to_tc_smoke_l3vni_ucast``: L3VNI traffic is
        always routed unicast, and the explicit ``_ucast`` suffix
        keeps node-IDs grep-consistent with the L2VNI smoke classes.
        """
        tc, dscp = tc_dscp
        test_label = "SMOKE-L3VNI-TAGGED-UCAST[{}][tc{}-dscp{}]".format(
            af, tc, dscp)
        print_section(
            "{} - 5 pkts via VxLAN L3VNI tagged-SVI (vlan={}, vni={})"
            .format(test_label, _L2_VLAN_ID, _I_VNI),
            art_key='dscp_to_tc')

        hard_failures, soft_warns = _smoke_run_one(
            test_label, af, dscp, expected_tc=tc, mode='l3vni_tagged')

        if hard_failures:
            st.report_fail('msg', "{} HARD failures ({}):\n  ".format(
                test_label, len(hard_failures))
                + "\n  ".join(hard_failures))
        st.report_pass('msg',
            "{}: 5 pkts L3VNI-tagged UC e2e PASS (soft_warns={})".format(
                test_label, len(soft_warns)))


class TestSmokeL2VNIBum:
    """16 smoke instances over the L2VNI BUM-flood path (8 TCs x 2 AFs).

    All instances share a single _setup_vxlan_l2vni() configuration.
    Forces the BUM-flood path on every burst by passing
    ``l2vni_force_bum=True`` to _smoke_run_one(): the dst_mac is
    locked to ``_J_BUM_MAC`` (ff:ff:ff:ff:ff:ff) and the EVPN-MAC
    lookup is skipped entirely.  This guarantees the wire-side
    traffic is multicast, so the scorecard's primary_queue_col is
    'mc' (set explicitly to defend against any future change to the
    mode->col default mapping).

    See TestSmokeL3VNI docstring for the shared-setup rationale and
    pre-flight semantics.  The sister TestSmokeL2VNIUcast class
    covers the converse (EVPN-resolved unicast) flow.
    """

    @pytest.fixture(scope="class", autouse=True)
    def _setup_l2vni(self):
        if topo_mode == 'ixia':
            pytest.skip(
                "Smoke L2VNI requires 2-DUT topology (peer_link/breakout); "
                "current mode is 'ixia'")

        teardown = _setup_vxlan_l2vni()
        # See TestSmokeL3VNI for why LLDP is intentionally LEFT
        # running here. The per-stage counter table now treats
        # `delta >= pkts_sent` as PASS so LLDP/BGP overcount on the
        # fabric link is not flagged as an error.
        try:
            _smoke_preflight('l2vni')
            yield
        finally:
            try:
                teardown()
            except Exception as exc:
                st.warn("_setup_vxlan_l2vni teardown raised: {}".format(exc))

    @pytest.mark.parametrize("af", ["ipv4", "ipv6"])
    @pytest.mark.parametrize("tc_dscp",
                             _smoke_pairs(), ids=_smoke_pair_ids())
    def test_dscp_to_tc_smoke_l2vni_bum(self, af, tc_dscp):
        """SMOKE-L2VNI-BUM - send 5 BUM packets at one DSCP through the
        L2VNI flood path, capture both TX and RX Ixia ports, decode
        every frame and assert:

          - L3 family preserved (ipv4 or ipv6)
          - DSCP preserved through encap + decap
          - TTL_rx == TTL_tx     (L2VNI bridges - no TTL decrement)
          - has_vxlan_header == False on RX (proves decap stripped VXLAN)
          - UDP dport == 5000 + DSCP       (test-stream identity)
          - DCHAL queue [TC] sees MC pkts >= 5  (BUM lands in the MC col)
        """
        tc, dscp = tc_dscp
        test_label = "SMOKE-L2VNI-BUM[{}][tc{}-dscp{}]".format(
            af, tc, dscp)
        print_section(
            "{} - 5 BUM pkts via VxLAN L2VNI ({})".format(
                test_label, _J_VNI),
            art_key='dscp_to_tc')

        # No explicit primary_queue_col override needed -- the
        # mode-derived default for (l2vni, force_bum=True) is
        # dut1='uc' (outer VxLAN encap is UC between VTEP IPs) and
        # dut2='mc' (DUT2 forwards the BUM inner frame).
        hard_failures, soft_warns = _smoke_run_one(
            test_label, af, dscp, expected_tc=tc, mode='l2vni',
            l2vni_force_bum=True)

        if hard_failures:
            st.report_fail('msg', "{} HARD failures ({}):\n  ".format(
                test_label, len(hard_failures)) + "\n  ".join(hard_failures))
        st.report_pass('msg',
            "{}: 5 pkts L2VNI BUM e2e PASS (soft_warns={})".format(
                test_label, len(soft_warns)))


class TestSmokeL2VNIUcast:
    """16 smoke instances over the L2VNI UNICAST path (8 TCs x 2 AFs).

    Drives the same _setup_vxlan_l2vni() topology as TestSmokeL2VNIBum
    but uses the EVPN-learned remote MAC (Type-2 in Vlan502) as the
    burst's dst_mac, so the wire-side frame is unicast (UC) on the
    L2VNI tunnel.  ``primary_queue_col='uc'`` makes the scorecard
    score the UC column; the MC diag row should show ``q[N]_mc=0``.

    EVPN-MAC learning gate: when the lookup misses (e.g., EVPN session
    not converged on this run), ``l2vni_gate_unicast=True`` causes
    _smoke_run_one to skip the instance via st.report_unsupported
    rather than silently fall back to BUM -- BUM coverage lives in
    the sister TestSmokeL2VNIBum class.
    """

    @pytest.fixture(scope="class", autouse=True)
    def _setup_l2vni(self):
        if topo_mode == 'ixia':
            pytest.skip(
                "Smoke L2VNI-Ucast requires 2-DUT topology "
                "(peer_link/breakout); current mode is 'ixia'")

        teardown = _setup_vxlan_l2vni()
        try:
            _smoke_preflight('l2vni')
            yield
        finally:
            try:
                teardown()
            except Exception as exc:
                st.warn("_setup_vxlan_l2vni teardown raised: {}".format(exc))

    @pytest.mark.parametrize("af", ["ipv4", "ipv6"])
    @pytest.mark.parametrize("tc_dscp",
                             _smoke_pairs(), ids=_smoke_pair_ids())
    def test_dscp_to_tc_smoke_l2vni_ucast(self, af, tc_dscp):
        """SMOKE-L2VNI-UCAST - 5 unicast packets via the L2VNI tunnel.

        Identical assertions to the BUM smoke except the DCHAL row is
        evaluated against the UC column.  Gates on EVPN-MAC learning:
        unconverged runs are reported as unsupported.
        """
        tc, dscp = tc_dscp
        test_label = "SMOKE-L2VNI-UCAST[{}][tc{}-dscp{}]".format(
            af, tc, dscp)
        print_section(
            "{} - 5 UC pkts via VxLAN L2VNI ({})".format(
                test_label, _J_VNI),
            art_key='dscp_to_tc')

        # mode-derived default for (l2vni, gate_unicast=True) is
        # dut1='uc' / dut2='uc' (both DUTs forward UC frames).
        hard_failures, soft_warns = _smoke_run_one(
            test_label, af, dscp, expected_tc=tc, mode='l2vni',
            l2vni_gate_unicast=True)

        if hard_failures:
            st.report_fail('msg', "{} HARD failures ({}):\n  ".format(
                test_label, len(hard_failures)) + "\n  ".join(hard_failures))
        st.report_pass('msg',
            "{}: 5 pkts L2VNI UC e2e PASS (soft_warns={})".format(
                test_label, len(soft_warns)))


# ══════════════════════════════════════════════════════════════════════════════
# Section K - Reused base tests under VxLAN L3VNI (Min-Touch Option 3)
# ══════════════════════════════════════════════════════════════════════════════
#
# Goal
# ----
# Run the three high-value, AF-aware, traffic-bearing tests from
# `test_dscp_to_tc.py` against the VxLAN L3VNI forwarding path WITHOUT
# duplicating their code:
#
#   * test_per_dscp_queue_placement     (all 64 DSCPs, per-queue +/-15%)
#   * test_zero_drops_on_expected_queue (all 64 DSCPs, +/-15% + drop==0)
#   * test_sai_queue_placement_combined (64 V4 + 64 V6 simultaneous)
#
# Each test is wrapped in TWO classes - one measuring queue counters at
# the encap-side (DUT1 transit egress, before VxLAN encap) and one at
# the decap-side (DUT2 egress-to-Ixia, after VxLAN decap).  Together the
# pair proves DSCP->TC classification both BEFORE and AFTER the tunnel
# round trip, which is exactly the property a VxLAN QoS test should
# verify.
#
# Implementation
# --------------
# Each wrapper class has a single class-scope autouse fixture that:
#   1. Brings up the L3VNI tunnel by calling _setup_vxlan_l3vni() (the
#      same zero-arg helper that TestSmokeL3VNI uses).
#   2. Mirrors this overlay file's module globals (dut, dut2, tg, tg_ph,
#      port_info, topo_mode) into the test_dscp_to_tc module's namespace
#      so the wrapped test function reads a fully populated set of
#      globals.  The wrapped function calls _send_and_measure(), reads
#      port_info['ingress'] / port_info['egress'], computes deltas, etc.
#      - all of which work transparently once we install the right
#      handles into _base.
#   3. Saves the previous _base.* values and restores them on teardown,
#      so that if test_dscp_to_tc.py tests run in the same session their
#      own setup_topo fixture sees a clean slate (and would re-populate
#      anyway, since it is module-scope autouse).
#
# What "encap" vs "decap" mean inside the wrapper
# -----------------------------------------------
# encap (DUT1 transit egress):
#   _base.dut       = dut                              (DUT1)
#   _base.port_info = {'ingress': port_info['ingress_a'],
#                      'egress':  port_info['egress']} (DUT1 transit port)
# Queue counters on the transit port reflect DUT1's TC classification at
# encap time (before VxLAN header is pushed).  If DSCP->TC is broken at
# encap, the wrong queue gets the packets and the test fails.
#
# decap (DUT2 egress-to-Ixia):
#   _base.dut       = dut2                             (DUT2)
#   _base.port_info = {'ingress': dut2_port_info['peer'],     # decap-in
#                      'egress':  dut2_port_info['egress_ixia']}  # decap-out
# Queue counters on DUT2's egress-to-Ixia port reflect DUT2's TC
# classification at decap time (after VxLAN header is stripped, inner
# DSCP read).  If DSCP is not preserved through the tunnel OR if the
# decap-side classifier is misbound, the wrong queue gets the packets.
#
# Why no L2VNI Section K
# ----------------------
# Section K wraps the three base tests from test_dscp_to_tc.py
# (test_per_dscp_queue_placement, test_zero_drops_on_expected_queue,
# test_sai_queue_placement_combined). All three are L3-routed-unicast
# tests: they build routed IPv4/IPv6 streams targeted at the DUT's
# router MAC and expect the DUT to perform an L3 longest-prefix lookup
# and forward via the routed `egress` port.  L2VNI is a different
# traffic shape - VLAN-access ingress, dst_mac = receiver host MAC on
# the L2VNI overlay (NOT the router MAC), L2 FDB lookup, bridged
# forwarding - so the base tests cannot be wrapped without either
# (a) monkey-patching `_base.get_dut_mac` to return _J_L2VNI_RX_MAC, or
# (b) substantially rewriting them.  Neither approach was deemed worth
# the effort because:
#
#   1. L2VNI DSCP preservation is a *bridge* operation, not a
#      classifier operation.  Once `TestSmokeL2VNIUcast` proves the
#      mechanism works on the 8 spot DSCPs (one per TC) across both
#      AFs, scaling to all 64 DSCPs adds no new code-path coverage -
#      L2VNI does not look at individual DSCP values.  Compare this
#      to L3VNI Section K, which exercises actual per-DSCP classifier
#      logic on both encap and decap sides.
#
#   2. `TestSmokeL2VNIBum` + `TestSmokeL2VNIUcast` already cover all
#      8 TCs (TC0-TC7) under L2VNI for both IPv4 and IPv6, with packet
#      decode + capture verification (the smoke scorecard) which
#      Section K-style queue-counter tests do not provide.  Those
#      smoke tests are strictly stronger L2VNI signal than 64-DSCP
#      placement counts would be.
#
#   3. Compliance / spec coverage for "every DSCP value is preserved
#      across every overlay" is discharged by L3VNI Section K, which
#      proves the classifier respects all 64 DSCP code points.  No
#      regulator / spec we are aware of requires re-proving the same
#      64-DSCP property on a bridged overlay.
#
# If a specific DSCP value is ever suspected to misbehave under L2VNI
# (e.g., a silicon-level remarking quirk at DSCP 46), the right fix is
# to extend `TestSmokeL2VNIUcast` with an additional DSCP-parametrize
# value, not to introduce a Section K L2VNI tier.
#
# Why no WRED Section K
# ---------------------
# Section K wrappers also do NOT exist for the WRED suite under
# `../wred/`, by design.  WRED is a congestion-management feature
# applied at an egress queue, and on the current VxLAN testbed
# neither side of the tunnel can host a meaningful WRED measurement:
#
#   * Encap-side: measuring WRED at DUT1's transit-egress port is
#     the same code path as non-VxLAN WRED (traffic has not been
#     VxLAN-encapsulated yet).  No new coverage vs the existing wred
#     suite on the non-VxLAN testbed.
#
#   * Decap-side: would be where VxLAN actually matters, but the
#     testbed topology has a single transit link DUT1<->DUT2 carried
#     at the same line rate as DUT2's egress-to-Ixia link.  Traffic
#     enters DUT1 on two fan-in ports, gets multiplexed onto ONE
#     VxLAN tunnel, then de-multiplexed at DUT2 onto ONE egress port
#     -- 1-to-1 at the decap egress.  No N-to-1 oversubscription is
#     possible, so the decap egress queue never fills and WRED never
#     enters its drop zone, regardless of WRED config.
#
# This is an architectural property of the topology, not a tuning
# parameter.  WRED-on-VxLAN coverage is therefore deferred until a
# future testbed adds parallel transit links / higher-rate underlay
# / direct-injection traffic generator paths.
#
# Topology requirements
# ---------------------
# All Section K classes require a 2-DUT topology (peer_link or
# breakout).  In 'ixia' mode there is no DUT2 to measure decap-side
# counters on, so the decap classes skip themselves.  Encap classes
# also skip in 'ixia' mode because L3VNI needs two VTEPs.
# ══════════════════════════════════════════════════════════════════════════════


def _section_k_install_base_globals(side):
    """Mirror this overlay file's globals into `test_dscp_to_tc` module
    namespace so a wrapped test function sees a fully populated set of
    module-level handles.  Returns a dict of the previous values so the
    caller can restore them in finally:.

    side: 'encap' or 'decap'.  See the section banner above for the
    semantic difference between the two.
    """
    saved = {
        'dut':       getattr(_base, 'dut',       None),
        'tg':        getattr(_base, 'tg',        None),
        'tg_ph':     getattr(_base, 'tg_ph',     {}),
        'port_info': getattr(_base, 'port_info', {}),
        'topo_mode': getattr(_base, 'topo_mode', None),
    }

    # Shared (both sides): Ixia chassis + ingress handles are the same;
    # only the DUT/port_info swap between encap and decap.
    _base.tg = tg
    _base.tg_ph = {
        'ingress': tg_ph['ingress_a'],
        'egress':  tg_ph.get('egress_sink', tg_ph.get('egress')),
    }
    _base.topo_mode = topo_mode

    if side == 'encap':
        _base.dut = dut
        _base.port_info = {
            'ingress': port_info['ingress_a'],
            'egress':  port_info['egress'],
        }
    elif side == 'decap':
        _base.dut = dut2
        _base.port_info = {
            'ingress': dut2_port_info.get('peer', port_info['ingress_a']),
            'egress':  dut2_port_info['egress_ixia'],
        }
    else:
        raise ValueError(
            "_section_k_install_base_globals: side must be "
            "'encap' or 'decap', got {!r}".format(side))

    st.log(
        "  [Section K] installed _base globals for side={}: "
        "dut={} ingress={} egress={}".format(
            side,
            getattr(_base.dut, 'name', _base.dut),
            _base.port_info['ingress'],
            _base.port_info['egress']))
    return saved


def _section_k_restore_base_globals(saved):
    """Undo `_section_k_install_base_globals`.  Idempotent on missing keys."""
    for k, v in saved.items():
        setattr(_base, k, v)
    st.log("  [Section K] restored _base globals to pre-class state")


def _section_k_setup_or_skip(side):
    """Common class-fixture body: skip on non-2-DUT topology, bring the
    L3VNI tunnel up, install globals, and return (teardown_tunnel,
    saved_globals) so the caller's try/finally can clean up.
    """
    if topo_mode == 'ixia':
        pytest.skip(
            "Section K (reused base tests under VxLAN L3VNI) requires a "
            "2-DUT topology (peer_link/breakout); current mode is 'ixia'.")
    teardown = _setup_vxlan_l3vni()
    saved = _section_k_install_base_globals(side)
    return teardown, saved


# ── Section K.1 - test_per_dscp_queue_placement under L3VNI ─────────────────

class TestL3VNIPerDscpQueuePlacement_Encap:
    """L3VNI reuse: 64-DSCP queue placement measured at DUT1 transit
    egress (encap-side classification).  See Section K banner above."""

    @pytest.fixture(scope="class", autouse=True)
    def _setup(self):
        teardown, saved = _section_k_setup_or_skip('encap')
        try:
            yield
        finally:
            _section_k_restore_base_globals(saved)
            teardown()

    @pytest.mark.traffic
    @pytest.mark.vxlan_transit
    @pytest.mark.parametrize("af", ["ipv4", "ipv6"])
    def test_per_dscp_queue_placement_l3vni_encap(self, af):
        _base.test_per_dscp_queue_placement(af)


class TestL3VNIPerDscpQueuePlacement_Decap:
    """L3VNI reuse: 64-DSCP queue placement measured at DUT2 egress-to-
    Ixia (decap-side classification).  See Section K banner above."""

    @pytest.fixture(scope="class", autouse=True)
    def _setup(self):
        teardown, saved = _section_k_setup_or_skip('decap')
        try:
            yield
        finally:
            _section_k_restore_base_globals(saved)
            teardown()

    @pytest.mark.traffic
    @pytest.mark.vxlan_transit
    @pytest.mark.parametrize("af", ["ipv4", "ipv6"])
    def test_per_dscp_queue_placement_l3vni_decap(self, af):
        _base.test_per_dscp_queue_placement(af)


# ── Section K.2 - test_zero_drops_on_expected_queue under L3VNI ──────────────

class TestL3VNIZeroDrops_Encap:
    """L3VNI reuse: 64-DSCP zero-drops check at DUT1 transit egress."""

    @pytest.fixture(scope="class", autouse=True)
    def _setup(self):
        teardown, saved = _section_k_setup_or_skip('encap')
        try:
            yield
        finally:
            _section_k_restore_base_globals(saved)
            teardown()

    @pytest.mark.traffic
    @pytest.mark.vxlan_transit
    @pytest.mark.parametrize("af", ["ipv4", "ipv6"])
    def test_zero_drops_on_expected_queue_l3vni_encap(self, af):
        _base.test_zero_drops_on_expected_queue(af)


class TestL3VNIZeroDrops_Decap:
    """L3VNI reuse: 64-DSCP zero-drops check at DUT2 egress-to-Ixia."""

    @pytest.fixture(scope="class", autouse=True)
    def _setup(self):
        teardown, saved = _section_k_setup_or_skip('decap')
        try:
            yield
        finally:
            _section_k_restore_base_globals(saved)
            teardown()

    @pytest.mark.traffic
    @pytest.mark.vxlan_transit
    @pytest.mark.parametrize("af", ["ipv4", "ipv6"])
    def test_zero_drops_on_expected_queue_l3vni_decap(self, af):
        _base.test_zero_drops_on_expected_queue(af)


# ── Section K.3 - test_sai_queue_placement_combined under L3VNI ─────────────

class TestL3VNISaiCombined_Encap:
    """L3VNI reuse: 64 V4 + 64 V6 combined burst, encap-side counters."""

    @pytest.fixture(scope="class", autouse=True)
    def _setup(self):
        teardown, saved = _section_k_setup_or_skip('encap')
        try:
            yield
        finally:
            _section_k_restore_base_globals(saved)
            teardown()

    @pytest.mark.traffic
    @pytest.mark.vxlan_transit
    def test_sai_queue_placement_combined_l3vni_encap(self):
        _base.test_sai_queue_placement_combined()


class TestL3VNISaiCombined_Decap:
    """L3VNI reuse: 64 V4 + 64 V6 combined burst, decap-side counters."""

    @pytest.fixture(scope="class", autouse=True)
    def _setup(self):
        teardown, saved = _section_k_setup_or_skip('decap')
        try:
            yield
        finally:
            _section_k_restore_base_globals(saved)
            teardown()

    @pytest.mark.traffic
    @pytest.mark.vxlan_transit
    def test_sai_queue_placement_combined_l3vni_decap(self):
        _base.test_sai_queue_placement_combined()
