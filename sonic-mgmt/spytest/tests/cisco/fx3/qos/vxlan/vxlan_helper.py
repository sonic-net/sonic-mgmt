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

"""VxLAN QoS helper library.

Public functional API:
    setup_vxlan_l3vni(dut, dut2, ingress_intf, dut2_egress, tg, tg_ph,
                      port_info, dut2_port_info, topo_mode, topo=L3VNI)
        -> teardown_callable
    setup_vxlan_l2vni(dut, dut2, ingress_intf, dut2_egress, tg, tg_ph,
                      port_info, dut2_port_info, topo_mode, topo=L2VNI)
        -> teardown_callable
    smoke_lookup_evpn_mac_for_l2vni(dut, vlan_id, remote_vtep, ...)
        -> str (mac) or None

Context-manager wrappers:
    vxlan_l3vni_active(...): with-statement wrapper.
    vxlan_l2vni_active(...): with-statement wrapper.

Pytest fixtures (function-scoped):
    vxlan_l3vni: pre-built fixture that brings the L3VNI tunnel up.
    vxlan_l2vni: pre-built fixture that brings the L2VNI tunnel up.

Back-compat shims for legacy callers (test_dscp_to_tc.py /
test_dscp_to_tc_overlay.py):
    _setup_vxlan_l3vni()   -> no-arg legacy entry point
    _setup_vxlan_l2vni()   -> no-arg legacy entry point
    _smoke_configure_l2vni_ixia_hosts(tg, tg_ph, vlan_id=None)
    _smoke_lookup_evpn_mac_for_l2vni(...)
    _bgp_evpn_config / _bgp_evpn_deconfig /
    _bgp_evpn_l2vni_config / _bgp_evpn_l2vni_deconfig /
    _safe_loopback_del — all expose the original implementation.

Back-compat constants (still importable as _I_*, _J_*):
    _I_VRF, _I_VNI, _I_VTEP_NAME, _I_NVO_NAME, _I_LB_INTF,
    _I_VTEP1_IP, _I_VTEP2_IP, _I_DUT1_TRANSIT_BARE,
    _I_BGP_AS1, _I_BGP_AS2, _I_DUMMY_VLAN, _I_CONV_WAIT, _I_SPOT_DSCP
    _J_VNI, _J_VTEP_NAME, _J_NVO_NAME, _J_LB_INTF,
    _J_VTEP1_IP, _J_VTEP2_IP, _J_DUT1_TRANSIT_BARE,
    _J_L2_VLAN, _J_BGP_AS1, _J_BGP_AS2, _J_CONV_WAIT,
    _J_SPOT_DSCP, _J_BUM_MAC, _J_L2VNI_RX_MAC, _J_L2VNI_RX_IP,
    _J_L2VNI_RX_GW

The legacy zero-argument entry points read the *caller's* module
globals (``dut``, ``dut2``, ``tg``, ``tg_ph``, ``port_info``,
``dut2_port_info``, ``topo_mode``) using ``sys._getframe(1).f_globals``.
This keeps existing test bodies working unchanged while new callers
can use the explicit-parameter public API.
"""

import json
import os
import re
import sys
import time

import pytest
from contextlib import contextmanager

from spytest import st

# Constants from qos_helpers — the underlay/transit/VRF IPs are shared
# with non-VxLAN sections of the test suite.
#
# GOLDEN_DSCP_TO_TC and setup_topo_common are also imported because the
# smoke-test machinery moved here from qos_helpers.py references them.
from qos_helpers import (
    V4_INGRESS_A_IP,
    V6_INGRESS_A_IP,
    V4_EGRESS_IP,
    V6_EGRESS_IP,
    V4_TRANSIT_DUT2_BARE,
    NETMASK,
    GOLDEN_DSCP_TO_TC,
    setup_topo_common,
)

# Topology data classes (the single source of truth for VxLAN VNI / VTEP
# / VRF / VLAN / BGP-AS / MAC / IP constants).
#
# This module gets pulled in via TWO different entry paths and the
# import below has to survive both of them:
#
#   1. ``from vxlan.vxlan_helper import _setup_vxlan_l3vni``
#      Used by qos_map/test_dscp_to_tc_overlay.py.  Loaded as the
#      package member ``vxlan.vxlan_helper`` because qos_map/conftest.py
#      puts qos/ on sys.path and vxlan/ contains __init__.py.
#      ``__package__ == 'vxlan'`` -> relative import works.
#
#   2. ``from vxlan_helper import _setup_vxlan_l3vni``  (no package)
#      Used by qos_map/test_dscp_to_tc.py, which inserts vxlan/ itself
#      onto sys.path and imports the bare module name.  Python loads
#      the module as TOP-LEVEL ``vxlan_helper`` -- ``__package__ == ''``
#      -- so a relative ``from .vxlan_topology import ...`` raises
#      ``ImportError: attempted relative import with no known parent
#      package``.  An absolute ``from vxlan_topology import ...`` works
#      in this case because vxlan/ is already on sys.path.
#
# Try the package-relative import first (case 1 -- our preferred
# entry path), fall back to the bare absolute name for case 2.  We
# can't pick one or the other based on a static check because tests in
# the same test run can use both paths (overlay imports test_dscp_to_tc
# which uses path 2).
try:
    from .vxlan_topology import (
        L3VNI, L2VNI, VxlanL3VniTopo, VxlanL2VniTopo)
except (ImportError, SystemError, ValueError):
    # Loaded as a top-level module via sys.path insertion (legacy
    # path used by test_dscp_to_tc.py at branch HEAD; do not "fix"
    # the caller -- the branch HEAD file is frozen).  The exact
    # exception raised by Python when a relative import has no
    # parent package varies by Python version and Python-impl
    # quirks:
    #   * CPython 3.6+ raises ImportError (the documented behaviour).
    #   * Some older / patched runtimes raise SystemError ("Parent
    #     module '' not loaded, cannot perform relative import").
    #   * A few edge-case loaders raise ValueError ("attempted
    #     relative import beyond top-level package").
    # Catch all three so this helper survives the bare-name path
    # regardless of interpreter.
    from vxlan_topology import (   # noqa: E402
        L3VNI, L2VNI, VxlanL3VniTopo, VxlanL2VniTopo)


# ──────────────────────────────────────────────────────────────────────
# DCHAL per-queue UC/MC parser  (smoke scorecard UC/MC split support)
# ──────────────────────────────────────────────────────────────────────
#
# qos_helpers.parse_dchal_queue_counters() returns one 'pkts' integer per
# QOS GROUP, taken from the FIRST integer in each pipe-delimited cell --
# that's the Unicast column. For L2VNI BUM (broadcast/multicast flood)
# the burst's per-queue contribution lands in the Multicast column
# instead, so the UC-only reading mis-reports the queue-placement check
# as "q[N]=0 (short)" even when the box correctly classified all packets
# into the expected TC.
#
# This re-parser walks the same dchal text and emits BOTH columns:
#
#   {qi: {'uc_pkts': N, 'mc_pkts': N,
#         'uc_bytes': N, 'mc_bytes': N,
#         'drop_uc_pkts': N, 'drop_mc_pkts': N,
#         'pkts': uc+mc, 'bytes': uc+mc,
#         'drop_pkts': drop_uc + drop_mc}}
#
# The legacy 'pkts' / 'bytes' / 'drop_pkts' keys are the UC+MC sums
# (instead of the UC-only value qos_helpers gives us). This means any
# code that reads only 'pkts' (eg the original dut1_queue/dut2_queue
# scorecard row) automatically picks up the BUM contribution too -- no
# additional change needed at those call sites. Code that wants to
# discriminate (the new dut1_queue_diag/dut2_queue_diag rows) reads
# 'uc_pkts' / 'mc_pkts' explicitly.

def parse_dchal_queue_counters_with_mc(dchal_output):
    """Parse DCHAL show-queuing output into per-queue UC+MC counters.

    Companion to qos_helpers.parse_dchal_queue_counters(). Same input
    text; richer output dict that exposes UC and MC separately.

    Args:
        dchal_output : raw stdout from /tmp/dchal_qi.py <intf>.

    Returns:
        ``{qi: {'pkts': uc+mc, 'bytes': uc_bytes+mc_bytes,
                'drop_pkts': drop_uc+drop_mc,
                'uc_pkts': N, 'mc_pkts': N,
                'uc_bytes': N, 'mc_bytes': N,
                'drop_uc_pkts': N, 'drop_mc_pkts': N}}``

        Missing queues are absent from the dict. The caller is expected
        to default missing values to 0.
    """
    def _parse_uc_mc(cell_text):
        """Pull the first two integers out of a pipe-delimited cell.

        DCHAL formats each value row as:
            | <label> | <unicast> | <multicast> |
        where the leading '| <label> ' has already been split off by
        the caller (it does stripped.split('Tx Pkts')[-1] etc.). What
        remains is roughly '|       20|             10|'.
        """
        vals = []
        for p in cell_text.split('|'):
            p = p.strip()
            if not p or p == '-':
                continue
            try:
                vals.append(int(p.replace(',', '')))
            except ValueError:
                continue
            if len(vals) == 2:
                break
        uc = vals[0] if len(vals) >= 1 else 0
        mc = vals[1] if len(vals) >= 2 else 0
        return uc, mc

    counters = {}
    current_qi = None
    for line in dchal_output.splitlines():
        stripped = line.strip()

        if 'QOS GROUP' in stripped:
            m = re.search(r'QOS GROUP\s+(\d+)', stripped)
            if m:
                current_qi = int(m.group(1))
                counters.setdefault(current_qi, {
                    'pkts': 0, 'bytes': 0, 'drop_pkts': 0,
                    'uc_pkts': 0, 'mc_pkts': 0,
                    'uc_bytes': 0, 'mc_bytes': 0,
                    'drop_uc_pkts': 0, 'drop_mc_pkts': 0,
                })
            else:
                current_qi = None
            continue

        if current_qi is None:
            continue

        if 'Tx Pkts' in stripped and 'Drop' not in stripped:
            uc, mc = _parse_uc_mc(stripped.split('Tx Pkts')[-1])
            counters[current_qi]['uc_pkts'] = uc
            counters[current_qi]['mc_pkts'] = mc
            counters[current_qi]['pkts']    = uc + mc
        elif 'Tx Byts' in stripped and 'Drop' not in stripped:
            uc, mc = _parse_uc_mc(stripped.split('Tx Byts')[-1])
            counters[current_qi]['uc_bytes'] = uc
            counters[current_qi]['mc_bytes'] = mc
            counters[current_qi]['bytes']    = uc + mc
        elif 'Drop Pkts' in stripped:
            uc, mc = _parse_uc_mc(stripped.split('Drop Pkts')[-1])
            counters[current_qi]['drop_uc_pkts'] = uc
            counters[current_qi]['drop_mc_pkts'] = mc
            counters[current_qi]['drop_pkts']    = uc + mc

    return counters


# ──────────────────────────────────────────────────────────────────────
# Back-compat module-level constants
# ──────────────────────────────────────────────────────────────────────
# These mirror the names the original test_dscp_to_tc.py used; they
# are re-exported here so that the surgical-trim of that file can do
#   from vxlan.vxlan_helper import _I_VRF, _I_VNI, ...
# without changing any test body.

_I_VRF              = L3VNI.vrf
_I_VNI              = L3VNI.vni
_I_VTEP_NAME        = L3VNI.vtep_name
_I_NVO_NAME         = L3VNI.nvo_name
_I_LB_INTF          = L3VNI.loopback_intf
_I_VTEP1_IP         = L3VNI.dut1_vtep_ip
_I_VTEP2_IP         = L3VNI.dut2_vtep_ip
_I_DUT1_TRANSIT_BARE = L3VNI.dut1_transit_bare
_I_BGP_AS1          = L3VNI.bgp_as_dut1
_I_BGP_AS2          = L3VNI.bgp_as_dut2
_I_DUMMY_VLAN       = L3VNI.dummy_vlan
_I_CONV_WAIT        = L3VNI.conv_wait_s
_I_SPOT_DSCP        = L3VNI.spot_dscp

_J_VNI              = L2VNI.vni
_J_VTEP_NAME        = L2VNI.vtep_name
_J_NVO_NAME         = L2VNI.nvo_name
_J_LB_INTF          = L2VNI.loopback_intf
_J_VTEP1_IP         = L2VNI.dut1_vtep_ip
_J_VTEP2_IP         = L2VNI.dut2_vtep_ip
_J_DUT1_TRANSIT_BARE = L2VNI.dut1_transit_bare
_J_L2_VLAN          = L2VNI.l2_vlan
_J_BGP_AS1          = L2VNI.bgp_as_dut1
_J_BGP_AS2          = L2VNI.bgp_as_dut2
_J_CONV_WAIT        = L2VNI.conv_wait_s
_J_BUM_MAC          = L2VNI.bum_mac
_J_L2VNI_RX_MAC     = L2VNI.rx_mac
_J_L2VNI_RX_IP      = L2VNI.rx_ip
_J_L2VNI_RX_GW      = L2VNI.rx_gw
_J_SPOT_DSCP        = L2VNI.spot_dscp

# ── L3VNI-tagged variant: shared L2 VLAN id ──────────────────────────
# The ``l3vni_tagged`` smoke variant (TestSmokeL3VNITagged) layers an
# 802.1Q tagged-SVI in front of the L3VNI ingress port.  The SVI is
# bound to ``_I_VRF`` and traffic enters DUT1 with VID = _L2_VLAN_ID
# on the wire.  Kept as a module-level constant so callers can use
# either the VID value directly or ``'Vlan{}'.format(_L2_VLAN_ID)`` to
# name the SVI interface.
_L2_VLAN_ID = 100


# ══════════════════════════════════════════════════════════════════════
# BGP EVPN helpers
# ══════════════════════════════════════════════════════════════════════

def _wait_bgp_underlay_up(dut_h, peer_ip, label,
                          timeout_s=120, poll_s=3, grace_s=8):
    """Poll the BGP underlay session until the neighbor is Established.

    Replaces a fixed-duration ``st.wait()`` for BGP convergence with an
    adaptive wait that exits the moment the session comes up. Uses
    ``vtysh -c 'show bgp summary json'`` and reads
    ``ipv4Unicast.peers[<peer_ip>].state`` (or ``peerState``, depending
    on FRR version).

    On success, logs a single INFO line: ``BGP underlay up: <label>
    peer=<peer_ip> in N.Ns``.

    On timeout, logs a WARN and returns False so the caller can decide
    whether to proceed (callers are expected to be soft -- a missing
    underlay will still surface as a queue-counter assertion failure
    later, the actual signal we care about).

    Args:
        dut_h:      DUT handle to query.
        peer_ip:    IPv4 address of the BGP neighbor we expect to reach
                    Established state with.
        label:      Short string used in the success/timeout log
                    line (eg "DUT1->DUT2").
        timeout_s:  Max time to wait (default 120s).
        poll_s:     Sleep between polls (default 3s).
        grace_s:    Initial sleep before the first poll, to let FRR
                    digest the freshly-pushed config (default 8s).
                    Sized so most healthy fabrics converge inside the
                    grace window and the first poll already sees
                    Established -- avoids spamming the log with
                    repeated `show bgp summary json` AUDIT/FCMD pairs
                    on the common-case fast-convergence path.

    Returns:
        True if Established within ``timeout_s``, False otherwise.
    """
    if grace_s:
        st.wait(grace_s)

    deadline = time.time() + max(0, int(timeout_s) - int(grace_s))
    last_state = '<unknown>'
    t0 = time.time()
    while time.time() < deadline:
        out = st.show(
            dut_h,
            "vtysh -c 'show bgp summary json'",
            skip_tmpl=True, skip_error_check=True)
        out_str = str(out) if out else ''
        # st.show() with skip_tmpl=True returns the raw stream, which
        # typically includes the echoed command line AND the trailing
        # shell prompt around the JSON body. Extract the largest balanced
        # {...} substring instead of trusting strip() to land on '{'.
        data = _extract_json_blob(out_str)
        # Walk the AFI buckets a peer entry might live in. SONiC/FRR
        # advertises the underlay session under 'ipv4Unicast' when
        # `address-family ipv4 unicast` is configured. EVPN-only sessions
        # may surface under 'l2VpnEvpn'. Older FRR exposes a flat
        # top-level 'peers' dict.
        info = None
        for bucket in ('ipv4Unicast', 'ipv6Unicast', 'l2VpnEvpn'):
            peers = (data.get(bucket, {}) or {}).get('peers', {}) or {}
            if peer_ip in peers:
                info = peers[peer_ip] or {}
                break
        if info is None:
            info = (data.get('peers') or {}).get(peer_ip) or {}
        # FRR uses 'state' in newer releases, 'peerState' in older.
        state_now = (info.get('state')
                     or info.get('peerState'))
        if state_now:
            last_state = state_now
        if last_state == 'Established':
            elapsed = time.time() - t0
            st.log("  BGP underlay up: {} peer={} in {:.1f}s".format(
                label, peer_ip, elapsed))
            return True
        st.wait(poll_s)

    elapsed = time.time() - t0
    st.warn(
        "  BGP underlay NOT up after {:.1f}s: {} peer={} last_state={}; "
        "proceeding anyway -- subsequent VTEP-ping or queue-counter "
        "checks will surface the real problem if convergence never "
        "completes".format(elapsed, label, peer_ip, last_state))
    return False


def _extract_json_blob(text):
    """Return the largest balanced {...} substring from ``text`` parsed
    as JSON, or {} on any failure.

    ``st.show(... skip_tmpl=True)`` returns a raw stream that wraps the
    JSON body with the echoed command and the shell prompt. A naive
    ``json.loads(text)`` would fail; ``startswith('{')`` after strip()
    misfires for the same reason. Scan for the first '{', then find its
    matching close-brace via a depth counter, and parse only that slice.
    """
    if not text:
        return {}
    start = text.find('{')
    if start < 0:
        return {}
    depth = 0
    end = -1
    for i in range(start, len(text)):
        ch = text[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                end = i
                break
    if end <= start:
        return {}
    try:
        return json.loads(text[start:end + 1]) or {}
    except (ValueError, TypeError):
        return {}


def _bgp_evpn_config(dut_h, local_as, neighbor_ip, neighbor_as,
                     vrf=None, vni=None):
    """Push BGP + EVPN config via vtysh for VxLAN L3VNI (Section I setup).

    Enables both IPv4 and IPv6 unicast address families inside the VRF so
    that both IPv4 and IPv6 overlay traffic is advertised via EVPN Type-5.
    """
    if vrf is None:
        vrf = _I_VRF
    if vni is None:
        vni = _I_VNI
    bgp_cfg = (
        'router bgp {la}\n'
        '  no bgp ebgp-requires-policy\n'
        '  no bgp default ipv4-unicast\n'
        '  neighbor {nbr} remote-as {na}\n'
        '  address-family ipv4 unicast\n'
        '    redistribute connected\n'
        '    neighbor {nbr} activate\n'
        '  exit-address-family\n'
        '  address-family l2vpn evpn\n'
        '    neighbor {nbr} activate\n'
        '    advertise-all-vni\n'
        '    advertise ipv4 unicast\n'
        '    advertise ipv6 unicast\n'
        '  exit-address-family\n'
        'exit\n'
        'vrf {vrf}\n'
        '  vni {vni}\n'
        'exit\n'
        'router bgp {la} vrf {vrf}\n'
        '  address-family ipv4 unicast\n'
        '    redistribute connected\n'
        '  exit-address-family\n'
        '  address-family ipv6 unicast\n'
        '    redistribute connected\n'
        '  exit-address-family\n'
        '  address-family l2vpn evpn\n'
        '    advertise ipv4 unicast\n'
        '    advertise ipv6 unicast\n'
        '  exit-address-family\n'
        'exit\n'
    ).format(la=local_as, nbr=neighbor_ip, na=neighbor_as,
             vrf=vrf, vni=vni)
    st.config(dut_h, bgp_cfg, type='vtysh', skip_error_check=True)


def _bgp_evpn_deconfig(dut_h, local_as, vrf=None):
    """Remove BGP config added by _bgp_evpn_config (Section I teardown).

    Sends BOTH the vrf-scoped router-bgp delete AND the default-vrf
    router-bgp delete, then waits for vrfmgrd to recognise that the VRF
    is no longer referenced.
    """
    if vrf is None:
        vrf = _I_VRF
    # 1. Delete the VRF-scoped BGP instance.
    st.config(
        dut_h,
        'no router bgp {la} vrf {vrf}'.format(la=local_as, vrf=vrf),
        type='vtysh', skip_error_check=True,
    )
    st.wait(1)
    # 2. Delete the default-VRF BGP instance.
    st.config(
        dut_h,
        'no router bgp {la}'.format(la=local_as),
        type='vtysh', skip_error_check=True,
    )
    st.wait(1)
    # 3. Verify FRR/vtysh no longer references the VRF in any
    #    `router bgp ... vrf <vrf>` stanza. Retry several times because
    #    SONiC's frr-to-configdb sync can lag for many seconds.
    max_polls = 5
    poll_wait = 3
    for attempt in range(max_polls):
        try:
            out = st.show(
                dut_h,
                "vtysh -c 'show running-config' "
                "| grep -E 'router bgp [0-9]+ vrf {vrf}'".format(vrf=vrf),
                skip_tmpl=True, skip_error_check=True,
            )
            out_str = str(out) if out else ''
        except Exception:
            out_str = ''
        if 'router bgp' not in out_str:
            return
        st.warn("  _bgp_evpn_deconfig: VRF {} still referenced after "
                "no-router-bgp attempt {}/{} - retrying delete".format(
                    vrf, attempt + 1, max_polls))
        st.config(
            dut_h,
            'no router bgp {la} vrf {vrf}'.format(la=local_as, vrf=vrf),
            type='vtysh', skip_error_check=True,
        )
        st.wait(1)
        st.config(
            dut_h,
            'no router bgp {la}'.format(la=local_as),
            type='vtysh', skip_error_check=True,
        )
        st.wait(poll_wait)
    st.warn("  _bgp_evpn_deconfig: VRF {} still appears in BGP running-"
            "config after {} retries; subsequent 'config vrf del' may "
            "fail".format(vrf, max_polls))


# ══════════════════════════════════════════════════════════════════════
# Shared teardown helpers (used by both L3VNI and L2VNI cleanup)
# ══════════════════════════════════════════════════════════════════════

def _safe_loopback_del(dut_h, lb_intf, label):
    """Delete a Loopback interface ONLY if it currently exists.

    Two-stage probe: CONFIG_DB first, then ``show ip interfaces``. If both
    say absent, skip the delete altogether to avoid noisy
    ``error checking but detected pattern: containing_error`` warnings.
    """
    present = None  # tri-state: True / False / None=unknown
    # Stage 1: ask CONFIG_DB directly.
    try:
        keys = st.show(
            dut_h,
            'redis-cli -n 4 --raw keys "LOOPBACK_INTERFACE|*"',
            skip_tmpl=True, skip_error_check=True,
        )
        keys_str = str(keys) if keys else ''
        if 'LOOPBACK_INTERFACE|{}'.format(lb_intf) in keys_str:
            present = True
        elif keys_str.strip():
            present = False
    except Exception:
        pass

    if present is None:
        try:
            out = st.show(dut_h, "show ip interfaces",
                          skip_tmpl=True, skip_error_check=True)
            out_str = str(out) if out else ''
            if lb_intf in out_str:
                present = True
            else:
                out6 = st.show(dut_h, "show ipv6 interfaces",
                               skip_tmpl=True, skip_error_check=True)
                present = lb_intf in (str(out6) if out6 else '')
        except Exception:
            present = True

    if present is False:
        return

    st.config(dut_h, 'config loopback del {}'.format(lb_intf),
              skip_error_check=True)


# ══════════════════════════════════════════════════════════════════════
# VxLAN L3VNI setup/teardown
# ══════════════════════════════════════════════════════════════════════

def setup_vxlan_l3vni(dut, dut2, ingress_intf, dut2_egress,
                     topo_mode=None, dut2_port_info=None,
                     topo=L3VNI):
    """Configure VxLAN L3VNI + BGP EVPN on both DUTs.

    Public functional API for the L3VNI Section I tunnel bring-up.
    Returns a teardown callable that reverses every step.

    Parameters
    ----------
    dut, dut2 : spytest device handles
        DUT1 (ingress VTEP) and DUT2 (egress VTEP). If ``dut2`` or
        ``dut2_port_info`` is falsy this function ``pytest.skip``s.
    ingress_intf : str
        DUT1 ingress port name (eg ``Ethernet1_49``).
    dut2_egress : str
        DUT2 egress-to-Ixia port name.
    topo_mode : str | None
        Current topology mode (``'ixia'`` / ``'peer_link'`` /
        ``'breakout'``). Only used for the skip message.
    dut2_port_info : dict | None
        Used only for the skip predicate; pass any truthy mapping to
        bypass the check.
    topo : VxlanL3VniTopo
        Topology constants. Defaults to the module-level ``L3VNI``.
    """
    if not dut2 or not dut2_port_info:
        pytest.skip(
            "Section I requires 2-DUT topology (peer_link/breakout); "
            "no DUT2 available in mode='{}'".format(topo_mode))

    # ── DUT1 ──────────────────────────────────────────────────────────
    st.config(dut, 'config loopback add {}'.format(topo.loopback_intf),
              skip_error_check=True)
    st.config(dut,
              'config interface ip add {} {}/32'.format(
                  topo.loopback_intf, topo.dut1_vtep_ip),
              skip_error_check=True)
    st.config(dut,
              'ip route {}/32 {}'.format(
                  topo.dut2_vtep_ip, V4_TRANSIT_DUT2_BARE),
              type='vtysh', skip_error_check=True)
    st.wait(1)

    # VRF + dummy VLAN for L3VNI internal wiring
    st.config(dut, 'config vrf add {}'.format(topo.vrf), skip_error_check=True)
    st.config(dut, 'config vlan add {}'.format(topo.dummy_vlan),
              skip_error_check=True)
    st.config(dut,
              'config interface vrf bind Vlan{} {}'.format(
                  topo.dummy_vlan, topo.vrf),
              skip_error_check=True)

    # VxLAN VTEP + EVPN NVO
    st.config(dut,
              'config vxlan add {} {}'.format(
                  topo.vtep_name, topo.dut1_vtep_ip),
              skip_error_check=True)
    st.config(dut,
              'config vxlan evpn_nvo add {} {}'.format(
                  topo.nvo_name, topo.vtep_name),
              skip_error_check=True)
    st.wait(2)

    # VLAN-VNI map first, then VRF-VNI map (reference test order)
    st.config(dut,
              'config vxlan map add {} {} {}'.format(
                  topo.vtep_name, topo.dummy_vlan, topo.vni),
              skip_error_check=True)
    st.config(dut,
              'config vrf add_vrf_vni_map {} {}'.format(
                  topo.vrf, topo.vni),
              skip_error_check=True)
    st.wait(1)

    # Bind ingress port to VRF; re-add IPs in the VRF
    st.config(dut,
              'config interface vrf bind {} {}'.format(
                  ingress_intf, topo.vrf),
              skip_error_check=True)
    st.config(dut,
              'config interface ip add {} {}'.format(
                  ingress_intf, V4_INGRESS_A_IP),
              skip_error_check=True)
    st.config(dut,
              'config interface ip add {} {}'.format(
                  ingress_intf, V6_INGRESS_A_IP),
              skip_error_check=True)
    st.wait(2)

    _bgp_evpn_config(dut, topo.bgp_as_dut1, V4_TRANSIT_DUT2_BARE,
                     topo.bgp_as_dut2, vrf=topo.vrf, vni=topo.vni)

    # ── DUT2 ──────────────────────────────────────────────────────────
    st.config(dut2, 'config loopback add {}'.format(topo.loopback_intf),
              skip_error_check=True)
    st.config(dut2,
              'config interface ip add {} {}/32'.format(
                  topo.loopback_intf, topo.dut2_vtep_ip),
              skip_error_check=True)
    st.config(dut2,
              'ip route {}/32 {}'.format(
                  topo.dut1_vtep_ip, topo.dut1_transit_bare),
              type='vtysh', skip_error_check=True)
    st.wait(1)

    st.config(dut2, 'config vrf add {}'.format(topo.vrf), skip_error_check=True)
    st.config(dut2, 'config vlan add {}'.format(topo.dummy_vlan),
              skip_error_check=True)
    st.config(dut2,
              'config interface vrf bind Vlan{} {}'.format(
                  topo.dummy_vlan, topo.vrf),
              skip_error_check=True)

    st.config(dut2,
              'config vxlan add {} {}'.format(
                  topo.vtep_name, topo.dut2_vtep_ip),
              skip_error_check=True)
    st.config(dut2,
              'config vxlan evpn_nvo add {} {}'.format(
                  topo.nvo_name, topo.vtep_name),
              skip_error_check=True)
    st.wait(2)

    st.config(dut2,
              'config vxlan map add {} {} {}'.format(
                  topo.vtep_name, topo.dummy_vlan, topo.vni),
              skip_error_check=True)
    st.config(dut2,
              'config vrf add_vrf_vni_map {} {}'.format(
                  topo.vrf, topo.vni),
              skip_error_check=True)
    st.wait(1)

    st.config(dut2,
              'config interface vrf bind {} {}'.format(
                  dut2_egress, topo.vrf),
              skip_error_check=True)
    st.config(dut2,
              'config interface ip add {} {}'.format(
                  dut2_egress, V4_EGRESS_IP),
              skip_error_check=True)
    st.config(dut2,
              'config interface ip add {} {}'.format(
                  dut2_egress, V6_EGRESS_IP),
              skip_error_check=True)
    st.wait(2)

    _bgp_evpn_config(dut2, topo.bgp_as_dut2, topo.dut1_transit_bare,
                     topo.bgp_as_dut1, vrf=topo.vrf, vni=topo.vni)

    # Adaptive BGP convergence wait. Replaces the fixed
    # ``st.wait(topo.conv_wait_s)`` that used to live here -- on a cold
    # box, BGP often took longer than the 60s default and the
    # Loopback1-sourced VTEP-ping in the preflight then false-WARNed.
    # Polls each side's BGP-summary JSON until the neighbor reaches
    # Established, then proceeds. Falls back to ``conv_wait_s`` as the
    # ceiling so we never hang forever.
    _wait_bgp_underlay_up(
        dut, V4_TRANSIT_DUT2_BARE, "DUT1->DUT2",
        timeout_s=topo.conv_wait_s)
    _wait_bgp_underlay_up(
        dut2, topo.dut1_transit_bare, "DUT2->DUT1",
        timeout_s=topo.conv_wait_s, grace_s=0)

    st.log("  I-setup: complete — DUT1 VTEP={} DUT2 VTEP={} VNI={} VRF={}"
           .format(topo.dut1_vtep_ip, topo.dut2_vtep_ip,
                   topo.vni, topo.vrf))

    def _delete_vrf_with_retry(dut_h, local_as, label):
        """Try to delete the VRF; if SONiC says 'VRF is in use by router
        bgp ...', force the BGP deconfig again and retry.

        Settings:
          - 6 attempts total
          - 5 s wait between attempts
        """
        max_attempts = 6
        wait_between = 5
        for attempt in range(max_attempts):
            out = st.config(
                dut_h, 'config vrf del {}'.format(topo.vrf),
                skip_error_check=True)
            out_str = str(out) if out else ''
            if 'in use by' not in out_str and 'is in use' not in out_str:
                return
            _bgp_evpn_deconfig(dut_h, local_as, vrf=topo.vrf)
            st.wait(wait_between)
        st.warn("  I-teardown[{}]: VRF {} could NOT be deleted after {} "
                "attempts; leaving it - subsequent tests may need manual "
                "cleanup or device reboot".format(
                    label, topo.vrf, max_attempts))

    def _teardown():
        # ── DUT1 ──────────────────────────────────────────────────────
        # ORDER MATTERS: remove L3VNI binding (VRF<->VNI map) and the
        # VXLAN objects FIRST, BEFORE the BGP-VRF delete. Otherwise FRR
        # refuses the BGP-VRF delete with "% Please unconfigure l3vni".
        st.config(dut,
                  'config vrf del_vrf_vni_map {}'.format(topo.vrf),
                  skip_error_check=True)
        st.config(dut,
                  'config vxlan map del {} {} {}'.format(
                      topo.vtep_name, topo.dummy_vlan, topo.vni),
                  skip_error_check=True)
        st.config(dut,
                  'config vxlan evpn_nvo del {}'.format(topo.nvo_name),
                  skip_error_check=True)
        st.config(dut,
                  'config vxlan del {}'.format(topo.vtep_name),
                  skip_error_check=True)
        _bgp_evpn_deconfig(dut, topo.bgp_as_dut1, vrf=topo.vrf)
        st.config(dut,
                  'config interface vrf unbind {}'.format(ingress_intf),
                  skip_error_check=True)
        st.wait(1)
        st.config(dut,
                  'config interface ip add {} {}'.format(
                      ingress_intf, V4_INGRESS_A_IP),
                  skip_error_check=True)
        st.config(dut,
                  'config interface ip add {} {}'.format(
                      ingress_intf, V6_INGRESS_A_IP),
                  skip_error_check=True)
        st.config(dut,
                  'config interface vrf unbind Vlan{}'.format(topo.dummy_vlan),
                  skip_error_check=True)
        st.config(dut,
                  'config vlan del {}'.format(topo.dummy_vlan),
                  skip_error_check=True)
        _delete_vrf_with_retry(dut, topo.bgp_as_dut1, 'DUT1')
        st.config(dut,
                  'no ip route {}/32 {}'.format(
                      topo.dut2_vtep_ip, V4_TRANSIT_DUT2_BARE),
                  type='vtysh', skip_error_check=True)
        st.config(dut,
                  'config interface ip remove {} {}/32'.format(
                      topo.loopback_intf, topo.dut1_vtep_ip),
                  skip_error_check=True)
        _safe_loopback_del(dut, topo.loopback_intf, 'DUT1')
        st.wait(2)

        # ── DUT2 ──────────────────────────────────────────────────────
        st.config(dut2,
                  'config vrf del_vrf_vni_map {}'.format(topo.vrf),
                  skip_error_check=True)
        st.config(dut2,
                  'config vxlan map del {} {} {}'.format(
                      topo.vtep_name, topo.dummy_vlan, topo.vni),
                  skip_error_check=True)
        st.config(dut2,
                  'config vxlan evpn_nvo del {}'.format(topo.nvo_name),
                  skip_error_check=True)
        st.config(dut2,
                  'config vxlan del {}'.format(topo.vtep_name),
                  skip_error_check=True)
        _bgp_evpn_deconfig(dut2, topo.bgp_as_dut2, vrf=topo.vrf)
        st.config(dut2,
                  'config interface vrf unbind {}'.format(dut2_egress),
                  skip_error_check=True)
        st.wait(1)
        st.config(dut2,
                  'config interface ip add {} {}'.format(
                      dut2_egress, V4_EGRESS_IP),
                  skip_error_check=True)
        st.config(dut2,
                  'config interface ip add {} {}'.format(
                      dut2_egress, V6_EGRESS_IP),
                  skip_error_check=True)
        st.config(dut2,
                  'config interface vrf unbind Vlan{}'.format(topo.dummy_vlan),
                  skip_error_check=True)
        st.config(dut2,
                  'config vlan del {}'.format(topo.dummy_vlan),
                  skip_error_check=True)
        _delete_vrf_with_retry(dut2, topo.bgp_as_dut2, 'DUT2')
        st.config(dut2,
                  'no ip route {}/32 {}'.format(
                      topo.dut1_vtep_ip, topo.dut1_transit_bare),
                  type='vtysh', skip_error_check=True)
        st.config(dut2,
                  'config interface ip remove {} {}/32'.format(
                      topo.loopback_intf, topo.dut2_vtep_ip),
                  skip_error_check=True)
        _safe_loopback_del(dut2, topo.loopback_intf, 'DUT2')
        st.wait(5)
        st.log("  I-teardown: complete")

    return _teardown


# ══════════════════════════════════════════════════════════════════════
# VxLAN L2VNI setup/teardown
# ══════════════════════════════════════════════════════════════════════

def _bgp_evpn_l2vni_config(dut_h, local_as, neighbor_ip, neighbor_as):
    """Configure BGP EVPN for L2VNI (no VRF BGP; only L2 MAC-IP routes)."""
    bgp_cfg = (
        'router bgp {la}\n'
        '  no bgp ebgp-requires-policy\n'
        '  no bgp default ipv4-unicast\n'
        '  neighbor {nbr} remote-as {na}\n'
        '  address-family l2vpn evpn\n'
        '    neighbor {nbr} activate\n'
        '    advertise-all-vni\n'
        '  exit-address-family\n'
        'exit\n'
    ).format(la=local_as, nbr=neighbor_ip, na=neighbor_as)
    st.config(dut_h, bgp_cfg, type='vtysh', skip_error_check=True)


def _bgp_evpn_l2vni_deconfig(dut_h, local_as):
    """Remove BGP config added by _bgp_evpn_l2vni_config."""
    st.config(dut_h,
              'no router bgp {}'.format(local_as),
              type='vtysh', skip_error_check=True)


def _smoke_configure_l2vni_ixia_hosts(tg, tg_ph, vlan_id=None):
    """Configure ONE Ixia "host" inside Vlan{vlan_id} on the receiver
    port so the L2VNI smoke can send realistic unicast traffic instead
    of BUM-flooding.

    Why this exists
    ---------------
    The L2VNI-UNICAST smoke (TestSmokeL2VNIUcast) bursts frames with
    a *unicast* dst_mac toward a remote Vlan502 host.  For the burst
    to land in DUT2's UC queue (not the MC/flood queue), DUT1 must
    have a valid EVPN Type-2 entry for the destination MAC in
    Vlan502.  That entry only exists if *some* Vlan502 host on the
    Ixia side has emitted a frame DUT2 could learn from and then
    advertise via BGP EVPN.

    Deterministic MAC-learning via a fake gateway
    ---------------------------------------------
    Historically this helper configured the receiver host with
    ``resolve_gateway_mac=0`` and no gateway, on the theory that
    ``arp_send_req=1`` alone would trigger a GARP from Ixia. In
    practice, on this testbed's NGPF-backed Ixia build, that combo
    produces *no* frames on the wire after ``start_protocol``: the
    Ixia protocol engine has nothing to ARP for, and NGPF treats
    ``arp_send_req=1`` as "respond to incoming ARP requests" rather
    than "emit GARP on link-up".  MAC learning then became a race
    against the idle ARP/NDP retransmit cadence of unrelated
    data-plane hosts on the same physical port (deviceGroup:1 /
    deviceGroup:2 on the ``20.20.20.0/24`` and
    ``2001:db8:20::/64`` subnets).  IPv4 vs IPv6 smoke runs would
    pass or fail depending purely on which Ixia retransmit happened
    to land inside the gate's poll window — a flaky test, not a
    real feature bug.

    The fix is to give the receiver host a *fake* gateway in the
    same subnet (``_J_L2VNI_RX_GW``, default ``20.20.20.99``) and
    set ``ipv4_resolve_gateway=1``.  Immediately after
    ``start_protocol``, NGPF emits one or more ARP-for-``20.20.20.99``
    broadcasts sourced from ``receiver_mac``.  DUT2's Vlan502 bridge
    learns ``receiver_mac`` on ``Ethernet1_49`` on a strict schedule,
    EVPN advertises it as a Type-2 route to DUT1, and the smoke
    test's EVPN-MAC gate succeeds on the first poll.  The fake
    gateway is never assigned to any DUT interface, so the ARP
    requests go unanswered — that is intentional and harmless: the
    only thing we need is the *outgoing* broadcast frame, not a
    completed ARP exchange.

    Tier-1 vs Tier-2 arg sets
    -------------------------
    Ixia's HLT-over-NGPF binding silently changed which kwargs it
    accepts on this call between IxNetwork releases:

      Tier-1 (NGPF-style, current): no ``l2_encap`` / ``vlan*``
        kwargs.  VLAN tagging is configured implicitly via the
        device-group's protocol stack (which the wrapper builds for
        us based on the port's role in the topology). All other
        working sibling host calls in the workspace -- see
        qos_helpers.setup_topo_common for ingress_a/ingress_b/
        egress_sink hosts -- use this style.

      Tier-2 (classic-HLT, legacy): explicit ``l2_encap`` +
        ``vlan='1' vlan_id=<n> vlan_id_mode='fixed'`` kwargs.
        Older Ixia builds (and some non-NGPF backends) require
        these.  We attempt this only if Tier-1 raised.

    Tier-1 is tried *first* and is the expected success path on this
    testbed.

    Returns a callable that removes the host.
    """
    if vlan_id is None:
        vlan_id = _J_L2_VLAN
    receiver_ip  = _J_L2VNI_RX_IP
    receiver_mac = _J_L2VNI_RX_MAC
    receiver_gw  = _J_L2VNI_RX_GW
    netmask      = NETMASK

    receiver_ph = tg_ph.get('egress') or tg_ph.get('egress_sink')
    if receiver_ph is None:
        st.warn("  J-smoke: cannot resolve Ixia receiver port handle "
                "(keys present: {}); skipping host config".format(
                    sorted(tg_ph.keys())))
        return lambda: None

    chosen_tier = None
    # NGPF tier: include the fake gateway + ipv4_resolve_gateway=1 so
    # the protocol engine emits a real ARP-for-receiver_gw broadcast
    # immediately after start_protocol. arp_send_req=1 is kept so the
    # host also auto-replies to incoming ARP queries (defensive; not
    # required for the FDB-learning path itself).
    tier_args_ngpf = dict(
        mode='config', port_handle=receiver_ph,
        intf_ip_addr=receiver_ip, netmask=netmask,
        gateway=receiver_gw,
        src_mac_addr=receiver_mac,
        arp_send_req=1, ipv4_resolve_gateway=1,
        enable_ping_response=1,
    )
    tier_args_classic = dict(
        mode='config', port_handle=receiver_ph,
        intf_ip_addr=receiver_ip, netmask=netmask,
        gateway=receiver_gw,
        vlan='1', vlan_id=int(vlan_id), vlan_id_mode='fixed',
        l2_encap='ethernet_ii_vlan',
        src_mac_addr=receiver_mac,
        arp_send_req=1, ipv4_resolve_gateway=1,
        enable_ping_response=1,
    )

    try:
        tg.tg_interface_config(**tier_args_ngpf)
        chosen_tier = 'NGPF'
    except Exception:
        try:
            tg.tg_interface_config(**tier_args_classic)
            chosen_tier = 'classic-HLT'
        except Exception as exc2:
            st.warn("  J-smoke: BOTH NGPF and classic-HLT arg-sets failed "
                    "to configure Ixia receiver host: classic err={}: {}"
                    " - L2VNI-UCAST smokes will skip via the EVPN-MAC "
                    "learning gate (BUM smokes are unaffected)".format(
                        type(exc2).__name__, exc2))
            return lambda: None

    try:
        tg.tg_topology_test_control(action='start_all_protocols')
    except Exception:
        pass

    def _teardown():
        try:
            tg.tg_interface_config(
                mode='destroy', port_handle=receiver_ph)
        except Exception:
            pass

    return _teardown


def smoke_lookup_evpn_mac_for_l2vni(dut_h, vlan_id, remote_vtep,
                                    max_attempts=4, wait_between=5,
                                    preferred_mac=None):
    """Find the EVPN-learned MAC in Vlan{vlan_id} on DUT1 whose remote
    VTEP is ``remote_vtep``.

    Returns the MAC string (lowercased, colons) or None.
    """
    vlan_s = str(int(vlan_id))
    target_vtep = str(remote_vtep)
    preferred = str(preferred_mac).lower() if preferred_mac else None

    _MAC_RE = re.compile(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})')

    def _normalize(text):
        if text is None:
            return ''
        if isinstance(text, (list, tuple)):
            return '\n'.join(str(x) for x in text)
        return str(text)

    def _key_to_mac(key):
        if not key or len(key) < 17:
            return None
        candidate = key[-17:].lower()
        if re.match(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$', candidate):
            return candidate
        return None

    def _try_redis():
        keys_cmd = (
            'redis-cli -n 0 KEYS "VXLAN_FDB_TABLE:Vlan{}:*"'.format(vlan_s))
        try:
            keys_out = _normalize(st.show(
                dut_h, keys_cmd,
                skip_tmpl=True, skip_error_check=True))
        except Exception:
            return None
        if not keys_out.strip():
            return None
        matches = []
        for raw_line in keys_out.splitlines():
            line = raw_line.strip()
            if not line.startswith(
                    'VXLAN_FDB_TABLE:Vlan{}:'.format(vlan_s)):
                continue
            mac_candidate = _key_to_mac(line)
            if not mac_candidate:
                continue
            hget_cmd = 'redis-cli -n 0 HGETALL "{}"'.format(line)
            try:
                vals = _normalize(st.show(
                    dut_h, hget_cmd,
                    skip_tmpl=True, skip_error_check=True))
            except Exception:
                continue
            if not vals or target_vtep not in vals:
                continue
            matches.append((mac_candidate, vals))
        if not matches:
            return None
        if preferred:
            for mac, _vals in matches:
                if mac == preferred:
                    return mac
        return matches[0][0]

    def _try_show_mac():
        try:
            out = _normalize(st.show(
                dut_h, "show mac -v {}".format(vlan_s),
                skip_tmpl=True, skip_error_check=True))
        except Exception:
            return None
        if not out.strip():
            return None
        found = []
        for line in out.splitlines():
            up = line.upper()
            if (target_vtep in line or 'VXLAN' in up
                    or 'TUNNEL' in up or 'DYNAMIC' in up
                    or 'EVPN' in up):
                m = _MAC_RE.search(line)
                if m:
                    found.append(m.group(1).lower())
        if not found:
            return None
        if preferred and preferred in found:
            return preferred
        return found[0]

    def _try_frr():
        vni = _J_VNI if vlan_s == str(_J_L2_VLAN) else None
        if vni is None:
            return None
        cmd = "vtysh -c 'show evpn mac vni {} detail'".format(vni)
        try:
            out = _normalize(st.show(
                dut_h, cmd, skip_tmpl=True, skip_error_check=True))
        except Exception:
            return None
        if not out.strip():
            return None
        macs = []
        last_mac = None
        for line in out.splitlines():
            m = _MAC_RE.search(line)
            if m and ('MAC' in line.upper()
                      or 'NEIGH' in line.upper()):
                last_mac = m.group(1).lower()
            if last_mac and target_vtep in line:
                macs.append(last_mac)
        if not macs:
            return None
        if preferred and preferred in macs:
            return preferred
        return macs[0]

    for attempt in range(1, max_attempts + 1):
        for fn, label in ((_try_redis, 'APP_DB VXLAN_FDB_TABLE'),
                          (_try_show_mac, 'show mac -v'),
                          (_try_frr, 'vtysh show evpn mac')):
            try:
                mac = fn()
            except Exception:
                continue
            if mac:
                return mac
        if attempt < max_attempts:
            st.wait(wait_between)
    return None


# Back-compat alias for the legacy underscore name.
_smoke_lookup_evpn_mac_for_l2vni = smoke_lookup_evpn_mac_for_l2vni


def setup_vxlan_l2vni(dut, dut2, ingress_intf, dut2_egress,
                     tg=None, tg_ph=None, topo_mode=None,
                     dut2_port_info=None, topo=L2VNI):
    """Configure VxLAN L2VNI + BGP EVPN on both DUTs.

    Returns a teardown callable that reverses every step.
    Skips via ``pytest.skip`` if dut2 is unavailable.
    """
    if not dut2 or not dut2_port_info:
        pytest.skip(
            "Section J requires 2-DUT topology (peer_link/breakout); "
            "no DUT2 available in mode='{}'".format(topo_mode))

    # ── DUT1 ──────────────────────────────────────────────────────────
    st.config(dut, 'config loopback add {}'.format(topo.loopback_intf),
              skip_error_check=True)
    st.config(dut,
              'config interface ip add {} {}/32'.format(
                  topo.loopback_intf, topo.dut1_vtep_ip),
              skip_error_check=True)
    st.config(dut,
              'ip route {}/32 {}'.format(
                  topo.dut2_vtep_ip, V4_TRANSIT_DUT2_BARE),
              type='vtysh', skip_error_check=True)
    st.wait(1)

    st.config(dut, 'config vlan add {}'.format(topo.l2_vlan),
              skip_error_check=True)
    st.wait(1)

    # Convert ingress port to L2 access: remove IPs, add as untagged member
    st.config(dut,
              'config interface ip remove {} {}'.format(
                  ingress_intf, V4_INGRESS_A_IP),
              skip_error_check=True)
    st.config(dut,
              'config interface ip remove {} {}'.format(
                  ingress_intf, V6_INGRESS_A_IP),
              skip_error_check=True)
    st.wait(1)
    st.config(dut,
              'config vlan member add {} {} --untagged'.format(
                  topo.l2_vlan, ingress_intf),
              skip_error_check=True)
    st.wait(1)

    st.config(dut,
              'config vxlan add {} {}'.format(
                  topo.vtep_name, topo.dut1_vtep_ip),
              skip_error_check=True)
    st.config(dut,
              'config vxlan evpn_nvo add {} {}'.format(
                  topo.nvo_name, topo.vtep_name),
              skip_error_check=True)
    st.wait(2)

    st.config(dut,
              'config vxlan map add {} {} {}'.format(
                  topo.vtep_name, topo.l2_vlan, topo.vni),
              skip_error_check=True)
    st.wait(1)

    _bgp_evpn_l2vni_config(dut, topo.bgp_as_dut1, V4_TRANSIT_DUT2_BARE,
                           topo.bgp_as_dut2)

    # ── DUT2 ──────────────────────────────────────────────────────────
    st.config(dut2, 'config loopback add {}'.format(topo.loopback_intf),
              skip_error_check=True)
    st.config(dut2,
              'config interface ip add {} {}/32'.format(
                  topo.loopback_intf, topo.dut2_vtep_ip),
              skip_error_check=True)
    st.config(dut2,
              'ip route {}/32 {}'.format(
                  topo.dut1_vtep_ip, topo.dut1_transit_bare),
              type='vtysh', skip_error_check=True)
    st.wait(1)

    st.config(dut2, 'config vlan add {}'.format(topo.l2_vlan),
              skip_error_check=True)
    st.wait(1)

    st.config(dut2,
              'config interface ip remove {} {}'.format(
                  dut2_egress, V4_EGRESS_IP),
              skip_error_check=True)
    st.config(dut2,
              'config interface ip remove {} {}'.format(
                  dut2_egress, V6_EGRESS_IP),
              skip_error_check=True)
    st.wait(1)
    st.config(dut2,
              'config vlan member add {} {} --untagged'.format(
                  topo.l2_vlan, dut2_egress),
              skip_error_check=True)
    st.wait(1)

    st.config(dut2,
              'config vxlan add {} {}'.format(
                  topo.vtep_name, topo.dut2_vtep_ip),
              skip_error_check=True)
    st.config(dut2,
              'config vxlan evpn_nvo add {} {}'.format(
                  topo.nvo_name, topo.vtep_name),
              skip_error_check=True)
    st.wait(2)

    st.config(dut2,
              'config vxlan map add {} {} {}'.format(
                  topo.vtep_name, topo.l2_vlan, topo.vni),
              skip_error_check=True)
    st.wait(1)

    _bgp_evpn_l2vni_config(dut2, topo.bgp_as_dut2,
                           topo.dut1_transit_bare, topo.bgp_as_dut1)

    # Adaptive BGP convergence wait (replaces the fixed
    # ``st.wait(topo.conv_wait_s)`` on cold boxes -- see I-setup for
    # the same rationale).
    _wait_bgp_underlay_up(
        dut, V4_TRANSIT_DUT2_BARE, "DUT1->DUT2",
        timeout_s=topo.conv_wait_s)
    _wait_bgp_underlay_up(
        dut2, topo.dut1_transit_bare, "DUT2->DUT1",
        timeout_s=topo.conv_wait_s, grace_s=0)

    # ── SMOKE-L2VNI Ixia unicast plumbing (optional, only if tg present)
    smoke_ixia_teardown = lambda: None
    if tg is not None and tg_ph is not None:
        smoke_ixia_teardown = _smoke_configure_l2vni_ixia_hosts(
            tg, tg_ph, vlan_id=topo.l2_vlan)
        st.wait(10)

    st.log("  J-setup: complete — DUT1 VTEP={} DUT2 VTEP={} VNI={} VLAN={}"
           .format(topo.dut1_vtep_ip, topo.dut2_vtep_ip,
                   topo.vni, topo.l2_vlan))

    def _teardown():
        try:
            smoke_ixia_teardown()
        except Exception as exc:
            st.warn("  J-teardown: smoke Ixia host teardown raised {}: {}"
                    " (continuing with VxLAN teardown)".format(
                        type(exc).__name__, exc))

        # ── DUT1 ──────────────────────────────────────────────────────
        _bgp_evpn_l2vni_deconfig(dut, topo.bgp_as_dut1)
        st.config(dut,
                  'config vxlan map del {} {} {}'.format(
                      topo.vtep_name, topo.l2_vlan, topo.vni),
                  skip_error_check=True)
        st.config(dut,
                  'config vxlan evpn_nvo del {}'.format(topo.nvo_name),
                  skip_error_check=True)
        st.config(dut,
                  'config vxlan del {}'.format(topo.vtep_name),
                  skip_error_check=True)
        st.config(dut,
                  'config vlan member del {} {}'.format(
                      topo.l2_vlan, ingress_intf),
                  skip_error_check=True)
        st.config(dut,
                  'config vlan del {}'.format(topo.l2_vlan),
                  skip_error_check=True)
        st.wait(1)
        st.config(dut,
                  'config interface ip add {} {}'.format(
                      ingress_intf, V4_INGRESS_A_IP),
                  skip_error_check=True)
        st.config(dut,
                  'config interface ip add {} {}'.format(
                      ingress_intf, V6_INGRESS_A_IP),
                  skip_error_check=True)
        st.config(dut,
                  'no ip route {}/32 {}'.format(
                      topo.dut2_vtep_ip, V4_TRANSIT_DUT2_BARE),
                  type='vtysh', skip_error_check=True)
        st.config(dut,
                  'config interface ip remove {} {}/32'.format(
                      topo.loopback_intf, topo.dut1_vtep_ip),
                  skip_error_check=True)
        _safe_loopback_del(dut, topo.loopback_intf, 'J/DUT1')
        st.wait(2)

        # ── DUT2 ──────────────────────────────────────────────────────
        _bgp_evpn_l2vni_deconfig(dut2, topo.bgp_as_dut2)
        st.config(dut2,
                  'config vxlan map del {} {} {}'.format(
                      topo.vtep_name, topo.l2_vlan, topo.vni),
                  skip_error_check=True)
        st.config(dut2,
                  'config vxlan evpn_nvo del {}'.format(topo.nvo_name),
                  skip_error_check=True)
        st.config(dut2,
                  'config vxlan del {}'.format(topo.vtep_name),
                  skip_error_check=True)
        st.config(dut2,
                  'config vlan member del {} {}'.format(
                      topo.l2_vlan, dut2_egress),
                  skip_error_check=True)
        st.config(dut2,
                  'config vlan del {}'.format(topo.l2_vlan),
                  skip_error_check=True)
        st.wait(1)
        st.config(dut2,
                  'config interface ip add {} {}'.format(
                      dut2_egress, V4_EGRESS_IP),
                  skip_error_check=True)
        st.config(dut2,
                  'config interface ip add {} {}'.format(
                      dut2_egress, V6_EGRESS_IP),
                  skip_error_check=True)
        st.config(dut2,
                  'no ip route {}/32 {}'.format(
                      topo.dut1_vtep_ip, topo.dut1_transit_bare),
                  type='vtysh', skip_error_check=True)
        st.config(dut2,
                  'config interface ip remove {} {}/32'.format(
                      topo.loopback_intf, topo.dut2_vtep_ip),
                  skip_error_check=True)
        _safe_loopback_del(dut2, topo.loopback_intf, 'J/DUT2')
        st.wait(5)
        st.log("  J-teardown: complete")

    return _teardown


# ══════════════════════════════════════════════════════════════════════
# Context-manager wrappers
# ══════════════════════════════════════════════════════════════════════

@contextmanager
def vxlan_l3vni_active(dut, dut2, ingress_intf, dut2_egress,
                       topo_mode=None, dut2_port_info=None, topo=L3VNI):
    """Bring up the L3VNI tunnel, yield, tear it down on exit."""
    teardown = setup_vxlan_l3vni(
        dut, dut2, ingress_intf, dut2_egress,
        topo_mode=topo_mode, dut2_port_info=dut2_port_info, topo=topo)
    try:
        yield
    finally:
        teardown()


@contextmanager
def vxlan_l2vni_active(dut, dut2, ingress_intf, dut2_egress,
                       tg=None, tg_ph=None, topo_mode=None,
                       dut2_port_info=None, topo=L2VNI):
    """Bring up the L2VNI tunnel, yield, tear it down on exit."""
    teardown = setup_vxlan_l2vni(
        dut, dut2, ingress_intf, dut2_egress,
        tg=tg, tg_ph=tg_ph, topo_mode=topo_mode,
        dut2_port_info=dut2_port_info, topo=topo)
    try:
        yield
    finally:
        teardown()


# ══════════════════════════════════════════════════════════════════════
# Legacy zero-arg back-compat shims
# ══════════════════════════════════════════════════════════════════════
#
# The original test_dscp_to_tc.py / test_dscp_to_tc_overlay.py modules
# call the helpers with no arguments and rely on module-level globals
# (``dut``, ``dut2``, ``tg``, ``tg_ph``, ``port_info``,
# ``dut2_port_info``, ``topo_mode``) populated by their ``setup_topo``
# fixture. To keep those test bodies unchanged after the helpers were
# moved here, the back-compat ``_setup_vxlan_l3vni()`` and
# ``_setup_vxlan_l2vni()`` entries introspect the caller's frame and
# read those globals from there.
#
# New callers should use ``setup_vxlan_l3vni(...)`` / ``setup_vxlan_l2vni(...)``
# with explicit arguments instead.

def _resolve_caller_globals(*names):
    """Return a tuple of values pulled from the *direct caller's*
    module globals. Used by the legacy zero-arg shims to discover the
    DUT handles and Ixia state that the calling test module owns.

    Raises RuntimeError listing which globals were missing.
    """
    frame = sys._getframe(2)   # skip this fn + the shim that called it
    g = frame.f_globals
    missing = [n for n in names if n not in g]
    if missing:
        raise RuntimeError(
            "vxlan_helper legacy shim: caller {} is missing required "
            "module-level globals: {}".format(
                g.get('__name__', '<unknown>'), missing))
    return tuple(g[n] for n in names)


def _setup_vxlan_l3vni():
    """Legacy zero-arg entry point for old callers.

    Reads ``dut``, ``dut2``, ``port_info``, ``dut2_port_info``,
    ``topo_mode`` from the *caller's* module globals.

    Ingress port selection
    ----------------------
    Uses ``port_info['ingress_a']`` (the first DUT1->T1 link;
    D1T1P1 / Ethernet1_49 on the fx3 VxLAN breakout testbed) as
    the L3VNI ingress port by convention.  Falls back to
    ``port_info['ingress']`` for the legacy single-DUT 'ixia' mode
    where ``setup_topo_common`` only produces a single 'ingress'
    key.

    See ``_setup_vxlan_l2vni`` for the rationale behind reserving
    a second DUT1->T1 link (``ingress_b``) as the L2VNI ingress
    port on the dedicated VxLAN testbed.
    """
    dut, dut2, port_info, dut2_port_info, topo_mode = _resolve_caller_globals(
        'dut', 'dut2', 'port_info', 'dut2_port_info', 'topo_mode')
    ingress = port_info.get('ingress_a', port_info.get('ingress'))
    if ingress is None:
        raise RuntimeError(
            "_setup_vxlan_l3vni: neither port_info['ingress_a'] nor "
            "port_info['ingress'] is set; cannot determine L3VNI "
            "ingress port.")
    return setup_vxlan_l3vni(
        dut, dut2,
        ingress, dut2_port_info['egress_ixia'],
        topo_mode=topo_mode, dut2_port_info=dut2_port_info)


def _setup_vxlan_l2vni():
    """Legacy zero-arg entry point for old callers.

    Reads ``dut``, ``dut2``, ``tg``, ``tg_ph``, ``port_info``,
    ``dut2_port_info``, ``topo_mode`` from the *caller's* module
    globals so the Ixia receiver-host plumbing is wired up.

    Ingress port selection
    ----------------------
    Uses ``port_info['ingress_b']`` (the second DUT1->T1 link;
    D1T1P2 / Ethernet1_50 on the fx3 VxLAN breakout testbed) as
    the L2VNI ingress port by convention.  Falls back to
    ``port_info['ingress_a']`` (or ``port_info['ingress']``) when
    the testbed only exposes a single DUT1->T1 link; on such a
    testbed L2VNI and L3VNI will reconfigure the same physical
    port between runs.

    Why reserve a second port?  L2VNI places the ingress port in
    VLAN-access mode on Vlan502, which is mutually exclusive with
    the VRF-bound config L3VNI puts on the L3VNI ingress port
    (``ingress_a``).  Splitting the two overlays across separate
    DUT1->T1 ports avoids reconfiguring a single port between
    VRF-bound and VLAN-access modes on every test run, and lets
    the two overlays coexist if a future test wants to drive them
    concurrently.
    """
    dut, dut2, tg, tg_ph, port_info, dut2_port_info, topo_mode = \
        _resolve_caller_globals(
            'dut', 'dut2', 'tg', 'tg_ph',
            'port_info', 'dut2_port_info', 'topo_mode')
    ingress = port_info.get(
        'ingress_b',
        port_info.get('ingress_a', port_info.get('ingress')))
    if ingress is None:
        raise RuntimeError(
            "_setup_vxlan_l2vni: cannot determine L2VNI ingress port "
            "from port_info (no 'ingress_b' / 'ingress_a' / 'ingress' "
            "key set).")
    return setup_vxlan_l2vni(
        dut, dut2,
        ingress, dut2_port_info['egress_ixia'],
        tg=tg, tg_ph=tg_ph,
        topo_mode=topo_mode, dut2_port_info=dut2_port_info)


# ══════════════════════════════════════════════════════════════════════
# Pytest fixtures
# ══════════════════════════════════════════════════════════════════════
#
# These are convenience fixtures for NEW tests that prefer fixture-
# scoped setup over inline teardown callables. Existing tests can keep
# the inline ``teardown = setup_vxlan_l3vni(...); try: ... finally:
# teardown()`` pattern instead.

@pytest.fixture
def vxlan_l3vni(request):
    """Function-scoped fixture: brings up the L3VNI tunnel, yields,
    tears it down.

    The fixture expects the test module to populate ``dut``, ``dut2``,
    ``port_info``, ``dut2_port_info`` and ``topo_mode`` as module globals
    (as the existing qos tests do).
    """
    g = request.module.__dict__
    teardown = setup_vxlan_l3vni(
        g['dut'], g['dut2'],
        g['port_info']['ingress'],
        g['dut2_port_info']['egress_ixia'],
        topo_mode=g.get('topo_mode'),
        dut2_port_info=g['dut2_port_info'])
    try:
        yield
    finally:
        teardown()


@pytest.fixture
def vxlan_l2vni(request):
    """Function-scoped fixture: brings up the L2VNI tunnel, yields,
    tears it down. Wires up the Ixia receiver host when ``tg`` and
    ``tg_ph`` are present on the test module.
    """
    g = request.module.__dict__
    teardown = setup_vxlan_l2vni(
        g['dut'], g['dut2'],
        g['port_info']['ingress'],
        g['dut2_port_info']['egress_ixia'],
        tg=g.get('tg'), tg_ph=g.get('tg_ph'),
        topo_mode=g.get('topo_mode'),
        dut2_port_info=g['dut2_port_info'])
    try:
        yield
    finally:
        teardown()


# ══════════════════════════════════════════════════════════════════════
# Public re-export list
# ══════════════════════════════════════════════════════════════════════

__all__ = [
    # Public functional API
    'setup_vxlan_l3vni',
    'setup_vxlan_l2vni',
    'smoke_lookup_evpn_mac_for_l2vni',
    # Context-manager wrappers
    'vxlan_l3vni_active',
    'vxlan_l2vni_active',
    # Pytest fixtures
    'vxlan_l3vni',
    'vxlan_l2vni',
    # Topology dataclasses
    'L3VNI',
    'L2VNI',
    'VxlanL3VniTopo',
    'VxlanL2VniTopo',
    # Legacy zero-arg back-compat shims
    '_setup_vxlan_l3vni',
    '_setup_vxlan_l2vni',
    '_smoke_configure_l2vni_ixia_hosts',
    '_smoke_lookup_evpn_mac_for_l2vni',
    '_bgp_evpn_config',
    '_bgp_evpn_deconfig',
    '_bgp_evpn_l2vni_config',
    '_bgp_evpn_l2vni_deconfig',
    '_safe_loopback_del',
    # Back-compat constants — Section I
    '_I_VRF', '_I_VNI', '_I_VTEP_NAME', '_I_NVO_NAME', '_I_LB_INTF',
    '_I_VTEP1_IP', '_I_VTEP2_IP', '_I_DUT1_TRANSIT_BARE',
    '_I_BGP_AS1', '_I_BGP_AS2', '_I_DUMMY_VLAN', '_I_CONV_WAIT',
    '_I_SPOT_DSCP',
    # Back-compat constants — Section J
    '_J_VNI', '_J_VTEP_NAME', '_J_NVO_NAME', '_J_LB_INTF',
    '_J_VTEP1_IP', '_J_VTEP2_IP', '_J_DUT1_TRANSIT_BARE',
    '_J_L2_VLAN', '_J_BGP_AS1', '_J_BGP_AS2', '_J_CONV_WAIT',
    '_J_BUM_MAC', '_J_L2VNI_RX_MAC', '_J_L2VNI_RX_IP', '_J_L2VNI_RX_GW',
    '_J_SPOT_DSCP',
]


# ══════════════════════════════════════════════════════════════════════════════
# Smoke-test packet capture / decode helpers — moved from qos_helpers.py
# ──────────────────────────────────────────────────────────────────────────────
# Block moved verbatim from qos_helpers.py (former lines 6939-9633) on the
# VxLAN refactor.  These helpers are exclusively consumed by the
# TestSmokeL3VNI / TestSmokeL3VNITagged / TestSmokeL2VNIBum classes in
# qos_map/test_dscp_to_tc_overlay.py.
#
# Back-compatibility: qos_helpers.py re-exports every smoke_* name defined
# here, so legacy callers that do
#     from qos_helpers import smoke_start_capture, ...
# continue to work unchanged.
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
# Smoke-test packet capture / decode helpers
# ──────────────────────────────────────────────────────────────────────────────
# These helpers support the "5-packet smoke test" pattern: send a tiny burst,
# capture both TX-side and RX-side on the Ixia, decode every frame to
# {eth, vlan, ip, ttl, dscp, l4} fields, and assert per-frame correctness.
#
# Why a separate set of helpers? The full e2e tests rely on aggregate Ixia
# counters + DCHAL queue counters. The smoke test instead inspects each
# byte of each frame so we can prove things like:
#   - DUT2 actually decapsulated (no outer UDP/4789, no VXLAN header)
#   - L3VNI decremented TTL exactly once
#   - L2VNI left TTL unchanged
#   - DSCP field survives the encap/decap round-trip intact
#   - Inner VLAN tag handling is correct (stripped on L3VNI, present on L2VNI
#     when the egress VTEP rebuilds the tag)
#
# The capture path uses spytest wrappers (tg.tg_packet_control /
# tg.tg_packet_stats) which are the project-wide standard for Ixia capture
# (see cisco/tortuga/qos/qos_test_utils.py for the reference implementation).
# ══════════════════════════════════════════════════════════════════════════════


def smoke_start_capture(tg, port_handle, port_alias="port"):
    """Reset + start unfiltered data-plane capture on an Ixia port.

    Wraps tg.tg_packet_control with the action sequence:
        reset -> start (which internally pushes config + enables data plane
        capture in spytest's wrapper).

    Note: spytest's tg_packet_control(action='start') uses Ixia's default
    capture_mode (trigger), which is fine for the 5-packet smoke. For larger
    captures see qos_test_utils.start_packet_capture which uses
    capture_mode='continuous' via ixia_eval to bypass the wrapper.

    Args:
        tg:          TGEN handle from setup_topo_common (tg_handle).
        port_handle: Ixia port_handle to capture on (e.g. tg_ph['ingress']
                     for TX-side or tg_ph['egress'] for RX-side).
        port_alias:  Human label for log lines, e.g. "TX dut1_ingress".

    Returns:
        True on success, False on exception (logged but non-fatal so the
        smoke test can decide whether to proceed without that side's data).
    """
    try:
        tg.tg_packet_control(port_handle=port_handle, action='reset')
        tg.tg_packet_control(port_handle=port_handle, action='start')
        return True
    except Exception as e:
        st.warn("smoke_start_capture failed on {}: {}".format(port_alias, e))
        return False


def smoke_stop_capture(tg, port_handle, max_frames=64, port_alias="port"):
    """Stop capture and fetch the raw frame bytes from Ixia.

    Args:
        tg:          TGEN handle.
        port_handle: Ixia port_handle previously passed to
                     smoke_start_capture.
        max_frames:  Upper bound on number of frames to retrieve. 64 is a
                     safe default that exceeds any 5-packet smoke run while
                     still being fast.
        port_alias:  Human label for log lines.

    Returns:
        Raw pkt_dict from tg.tg_packet_stats keyed by port_handle, or None
        if capture failed / no frames were retrieved.

        Structure (per spytest convention):
            { port_handle: {
                  'aggregate': {'num_frames': '<N>'},
                  'frame': {
                      '0': {'frame_pylist': ['ff','ff', ...], ...},
                      '1': {...},
                  },
              }
            }
    """
    try:
        tg.tg_packet_control(port_handle=port_handle, action='stop')
        st.wait(3)

        pkt_dict = tg.tg_packet_stats(
            port_handle=port_handle,
            format='var',
            output_type='hex',
            var_num_frames=max_frames)

        if not pkt_dict or port_handle not in pkt_dict:
            st.warn("smoke_stop_capture: empty result for {}".format(
                port_alias))
            return None
        return pkt_dict
    except Exception as e:
        st.warn("smoke_stop_capture failed on {}: {}".format(port_alias, e))
        return None


def _normalise_pylist(pylist):
    """Coerce a captured frame_pylist into a uniform list of `str` entries.

    Background: different spytest TGEN drivers expose Ixia capture frames
    in slightly different shapes. Most drivers give us a list of 2-char
    hex strings ('ff', '12', ...). Some Ixia/IxNetwork driver versions
    return them as `bytes` objects (b'ff', b'12', ...) instead. Without
    normalisation, helpers like _bytes_to_mac that do `":".join(...)`
    blow up with:
        TypeError: sequence item 0: expected str instance, bytes found
    (see the cpython-310 traceback from a real run).

    This helper is the single source of truth for that normalisation.
    Decode to ASCII for `bytes` entries (hex chars are always ASCII-safe);
    leave `str` entries as-is. Other unexpected types are stringified
    defensively (`str(x)`) so we surface garbage as an obvious failure
    in the field-summary table rather than crashing the whole test.

    Returns a NEW list; never mutates the caller's data.
    """
    if not pylist:
        return []
    out = []
    for item in pylist:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, (bytes, bytearray)):
            try:
                out.append(item.decode('ascii'))
            except (UnicodeDecodeError, AttributeError):
                # Truly garbled - surface as 00 (a valid hex pair) so
                # the rest of the decoder doesn't trip; the resulting
                # decoded fields will visibly diverge from expected.
                out.append('00')
        else:
            out.append(str(item))
    return out


def _hex_to_int(pylist, off, count):
    """Convert *count* hex-pair entries starting at *off* in pylist to int.

    pylist is the spytest 'frame_pylist' format: a list of 2-char hex strings,
    one per byte ('ff', '12', ...). Returns the big-endian integer value.
    Returns None if the slice runs off the end of pylist.
    """
    if off + count > len(pylist):
        return None
    v = 0
    for i in range(count):
        v = (v << 8) | int(pylist[off + i], 16)
    return v


def _bytes_to_mac(pylist, off):
    """Format 6 hex-pair entries as a MAC address 'aa:bb:cc:dd:ee:ff'."""
    if off + 6 > len(pylist):
        return None
    return ":".join(pylist[off + i].lower() for i in range(6))


def _bytes_to_ipv4(pylist, off):
    """Format 4 hex-pair entries as IPv4 dotted-quad 'a.b.c.d'."""
    if off + 4 > len(pylist):
        return None
    return ".".join(str(int(pylist[off + i], 16)) for i in range(4))


def _bytes_to_ipv6(pylist, off):
    """Format 16 hex-pair entries as IPv6 colon-hex (8 16-bit groups,
    not zero-compressed)."""
    if off + 16 > len(pylist):
        return None
    groups = []
    for g in range(8):
        hi = pylist[off + 2 * g]
        lo = pylist[off + 2 * g + 1]
        groups.append("{}{}".format(hi, lo))
    return ":".join(groups).lower()


# Standard EtherType / L4 protocol constants for the decoder
_ET_VLAN  = 0x8100
_ET_IPV4  = 0x0800
_ET_IPV6  = 0x86DD
_IP_UDP   = 17
_IP_TCP   = 6
_IP_ICMP  = 1
_IP_ICMP6 = 58
_UDP_VXLAN = 4789  # If we see this on the RX-side post-decap port, decap
                   # failed (or we are capturing on a TX/transit port).


def smoke_decode_frame(pylist):
    """Decode a single captured frame_pylist into a dict of L2/L3/L4 fields.

    The returned dict has stable keys so callers can assert any field.
    Unknown protocols return None for the non-applicable fields rather than
    raising — the smoke test relies on the test's own assertion logic to
    flag a frame with eg. l3=='other' as a failure.

    Returns:
        {
          'len': int,                # decoded byte count (= len(pylist),
                                     # the bytes the spytest decoder gave us).
          # 'wire_size' is added by smoke_decode_frames() (not here) from
          # the per-frame Ixia metadata; it is the wire length the chassis
          # reported and may exceed 'len' by the FCS (typically +4) if the
          # driver strips the FCS before exposing frame_pylist.
          'eth_src': 'aa:bb:..', 'eth_dst': 'aa:bb:..',
          'ethertype': int,          # post-VLAN ethertype
          'vlan': int|None,          # VLAN ID (1..4094) if 802.1Q, else None
          'vlan_pcp': int|None,      # 802.1p priority if VLAN tag present
          'l3': 'ipv4'|'ipv6'|'other',
          'ip_src': str|None, 'ip_dst': str|None,
          'ttl_or_hl': int|None,     # IPv4 TTL or IPv6 Hop Limit
          'dscp': int|None,          # 0..63
          'ecn': int|None,           # 0..3
          'ip_proto': int|None,      # IPv4 Protocol or IPv6 Next Header
          'l4': 'udp'|'tcp'|'icmp'|'icmp6'|'other',
          'l4_sport': int|None, 'l4_dport': int|None,
          'has_vxlan_header': bool,  # True if outer UDP dport == 4789
        }
    """
    # Normalise once - some Ixia drivers hand us bytes instead of str
    # (b'ff' vs 'ff'). Doing this at the entry point keeps every
    # downstream helper (_bytes_to_mac/_ipv4/_ipv6, _hex_to_int) free of
    # type-conversion noise. See _normalise_pylist for the rationale.
    pylist = _normalise_pylist(pylist)

    out = {
        'len': len(pylist),
        'eth_src': None, 'eth_dst': None, 'ethertype': None,
        'vlan': None, 'vlan_pcp': None,
        'l3': 'other', 'ip_src': None, 'ip_dst': None,
        'ttl_or_hl': None, 'dscp': None, 'ecn': None,
        'ip_proto': None, 'l4': 'other',
        'l4_sport': None, 'l4_dport': None,
        'has_vxlan_header': False,
    }
    if len(pylist) < 14:
        return out

    out['eth_dst'] = _bytes_to_mac(pylist, 0)
    out['eth_src'] = _bytes_to_mac(pylist, 6)
    et = _hex_to_int(pylist, 12, 2)
    ip_off = 14

    # 802.1Q VLAN tag
    if et == _ET_VLAN:
        if len(pylist) < 18:
            out['ethertype'] = et
            return out
        tci = _hex_to_int(pylist, 14, 2)
        out['vlan_pcp'] = (tci >> 13) & 0x7
        out['vlan']     = tci & 0x0FFF
        et = _hex_to_int(pylist, 16, 2)
        ip_off = 18
    out['ethertype'] = et

    # IPv4
    if et == _ET_IPV4:
        if len(pylist) < ip_off + 20:
            return out
        out['l3'] = 'ipv4'
        tos = int(pylist[ip_off + 1], 16)
        out['dscp'] = tos >> 2
        out['ecn']  = tos & 0x03
        out['ttl_or_hl'] = int(pylist[ip_off + 8], 16)
        out['ip_proto']  = int(pylist[ip_off + 9], 16)
        out['ip_src'] = _bytes_to_ipv4(pylist, ip_off + 12)
        out['ip_dst'] = _bytes_to_ipv4(pylist, ip_off + 16)
        ihl = int(pylist[ip_off], 16) & 0x0F
        l4_off = ip_off + ihl * 4
    elif et == _ET_IPV6:
        if len(pylist) < ip_off + 40:
            return out
        out['l3'] = 'ipv6'
        byte0 = int(pylist[ip_off], 16)
        byte1 = int(pylist[ip_off + 1], 16)
        tc = ((byte0 & 0x0F) << 4) | (byte1 >> 4)
        out['dscp'] = tc >> 2
        out['ecn']  = tc & 0x03
        out['ip_proto']  = int(pylist[ip_off + 6], 16)
        out['ttl_or_hl'] = int(pylist[ip_off + 7], 16)
        out['ip_src'] = _bytes_to_ipv6(pylist, ip_off + 8)
        out['ip_dst'] = _bytes_to_ipv6(pylist, ip_off + 24)
        l4_off = ip_off + 40
    else:
        return out

    # L4 parsing
    proto = out['ip_proto']
    if proto in (_IP_UDP, _IP_TCP):
        if len(pylist) < l4_off + 4:
            return out
        out['l4'] = 'udp' if proto == _IP_UDP else 'tcp'
        out['l4_sport'] = _hex_to_int(pylist, l4_off,     2)
        out['l4_dport'] = _hex_to_int(pylist, l4_off + 2, 2)
        if proto == _IP_UDP and out['l4_dport'] == _UDP_VXLAN:
            out['has_vxlan_header'] = True
    elif proto == _IP_ICMP:
        out['l4'] = 'icmp'
    elif proto == _IP_ICMP6:
        out['l4'] = 'icmp6'
    return out


def smoke_decode_frames(pkt_dict, port_handle, max_frames=64):
    """Decode every captured frame on a port into a list of field dicts.

    Args:
        pkt_dict:    Raw dict from smoke_stop_capture.
        port_handle: Ixia port_handle key in pkt_dict.
        max_frames:  Stop after this many frames (defensive cap).

    Returns:
        (decoded_list, num_total)
            decoded_list: list of smoke_decode_frame() dicts, in capture
                          order, length min(num_total, max_frames).
            num_total:    total frames reported by Ixia (may exceed
                          max_frames).
        Returns ([], 0) if pkt_dict is empty or port_handle is missing.
    """
    if not pkt_dict or port_handle not in pkt_dict:
        return [], 0
    port_data  = pkt_dict[port_handle]
    num_total  = int(port_data.get('aggregate', {}).get('num_frames', 0))
    examine    = min(num_total, max_frames)
    decoded    = []
    for i in range(examine):
        fdata  = port_data.get('frame', {}).get(str(i), {})
        pylist = fdata.get('frame_pylist', [])
        if not pylist:
            continue
        d = smoke_decode_frame(pylist)
        d['idx'] = i
        # Wire-size as reported by the Ixia driver. Different spytest
        # TGEN drivers expose this under different keys ('frame_size',
        # 'frame_length', 'size'); probe in order and fall back to None
        # so the print step can show '?' instead of crashing.
        wire_size = (fdata.get('frame_size')
                     or fdata.get('frame_length')
                     or fdata.get('size'))
        if wire_size is not None:
            try:
                d['wire_size'] = int(wire_size)
            except (TypeError, ValueError):
                d['wire_size'] = None
        else:
            d['wire_size'] = None
        decoded.append(d)
    return decoded, num_total


# Fields used by the side-by-side TX/RX renderers below. Order is the
# read order in the diff/horizontal/vertical views. ``_DUMP_FIELDS`` is
# the canonical list; add new keys here and they show up everywhere.
_DUMP_FIELDS = (
    'l3', 'dscp', 'ttl_or_hl', 'ecn',
    'l4', 'l4_sport', 'l4_dport',
    'has_vxlan_header', 'vxlan_vni',
    'eth_src', 'eth_dst', 'vlan',
    'ip_src', 'ip_dst',
)
# Pretty labels for the field names. Falls back to the raw key if no
# mapping is given.
_DUMP_FIELD_LABELS = {
    'l3':               'L3',
    'dscp':             'DSCP',
    'ttl_or_hl':        'TTL/HL',
    'ecn':              'ECN',
    'l4':               'L4',
    'l4_sport':         'sport',
    'l4_dport':         'dport',
    'has_vxlan_header': 'VXLAN',
    'vxlan_vni':        'VNI',
    'eth_src':          'eth_src',
    'eth_dst':          'eth_dst',
    'vlan':             'VLAN',
    'ip_src':           'ip_src',
    'ip_dst':           'ip_dst',
}


def _dump_label(k):
    return _DUMP_FIELD_LABELS.get(k, k)


def _dump_val(d, k):
    """Coerce a value to its display string. Treats 'missing' as '-'
    so a sparse dict (TX intent often has no eth_src/ip_src/wire_size)
    doesn't print 'None None None'."""
    if d is None:
        return '-'
    v = d.get(k)
    if v is None:
        return '-'
    if isinstance(v, bool):
        return 'Y' if v else 'N'
    return str(v)


def _dump_compact_summary(d):
    """One-line packet summary used for duplicate-frame detection
    in the side-by-side dump (we only re-render later frames whose
    summary differs from frame[0]).

    Picks the most informative subset (l3/dscp/ttl/dport/vxlan) and
    renders as 'l3=ipv4 dscp=0 ttl=62 dport=5000 vxlan=N'."""
    if d is None:
        return '-'
    parts = []
    for k in ('l3', 'dscp', 'ttl_or_hl', 'l4_dport', 'has_vxlan_header'):
        parts.append("{}={}".format(_dump_label(k).lower(), _dump_val(d, k)))
    return ' '.join(parts)


# ─ ANSI color helpers for side-by-side packet dumps ────────────────────
# We highlight the *value* portion of mismatched fields so the eye can
# zero in on the actual divergence. Plaintext markers ('*') stay too so
# log greppers / non-ANSI viewers still surface mismatches. Colors are
# disabled automatically when ``QOS_DUMP_NO_COLOR`` env var is set
# (truthy) -- handy for CI logs that get post-processed by tools that
# choke on escape sequences.
_ANSI_RED   = "\033[31m"
_ANSI_GREEN = "\033[32m"
_ANSI_BOLD  = "\033[1m"
_ANSI_RESET = "\033[0m"
_ANSI_RE    = re.compile(r"\x1b\[[0-9;]*m")


def _color_enabled():
    v = os.environ.get('QOS_DUMP_NO_COLOR', '')
    return not (v and v.lower() not in ('0', 'false', 'no', ''))


def _hi_tx(s):
    """Highlight a TX-side mismatched value (red+bold)."""
    if not _color_enabled():
        return s
    return "{}{}{}{}".format(_ANSI_BOLD, _ANSI_RED, s, _ANSI_RESET)


def _hi_rx(s):
    """Highlight an RX-side mismatched value (green+bold)."""
    if not _color_enabled():
        return s
    return "{}{}{}{}".format(_ANSI_BOLD, _ANSI_GREEN, s, _ANSI_RESET)


def _visible_len(s):
    """Length of *s* with any ANSI escape sequences stripped. Used so
    width-aware pad/truncate math doesn't get fooled by non-printing
    color codes."""
    return len(_ANSI_RE.sub('', s))


def _ljust_visible(s, width):
    """Left-justify *s* to *width* visible columns, padding with spaces.
    If the visible content is already longer than *width*, the original
    string is returned unmodified (callers that need hard truncation
    should use ``_truncate_visible`` first)."""
    pad = width - _visible_len(s)
    if pad <= 0:
        return s
    return s + (' ' * pad)


def _truncate_visible(s, width):
    """Best-effort truncate to *width* visible columns. Strips ANSI
    escapes when truncation actually happens (we'd otherwise risk
    cutting inside an escape sequence and leaking partial codes into
    the rest of the line)."""
    if _visible_len(s) <= width:
        return s
    plain = _ANSI_RE.sub('', s)
    return plain[:width]

def smoke_print_tx_rx_side_by_side(tx_intent, decoded_rx, label,
                                    pkts_sent=None,
                                    test_dport=None,
                                    full_pair_max=8,
                                    tx_label=None,
                                    rx_label=None):
    """Render the TX intent vs RX captured packets in a side-by-side
    tcpdump-style dump.

    For each rendered frame, TX is shown on the left and RX on the
    right with a center '|' divider, so the operator can scan field-
    by-field (TTL 64->62 because DUT2 routed and decremented twice,
    VXLAN Y->N because DUT2 stripped the outer header, DSCP unchanged
    because the map preserved it, etc.). Mismatching fields are
    flagged with a leading '*' marker and ANSI color (TX=red, RX=green)
    so the diverging value pops in the dump.

    Frame selection: frame[0] (the representative packet) is always
    rendered. Any later frame whose compact summary differs from
    frame[0] is also rendered, so a single corrupted frame in an
    otherwise-clean burst still surfaces. Spam is bounded by
    ``full_pair_max`` so a 100-packet stream doesn't blast the log.

    Control-plane noise (LLDP, BPDU, BGP) is filtered out when
    ``test_dport`` is provided, by matching only frames whose UDP
    dport equals ``test_dport``. This stops one LLDP frame from
    producing a misleading 'L3: ipv4 -> other' divergence.

    Args:
        tx_intent:   A dict shaped like the build-spec used by the
                     test (l3, dscp, ttl_or_hl, has_vxlan_header,
                     l4, l4_dport, ...). All TX packets share this
                     intent (the smoke test sends 5 identical
                     bursts), so a single dict is enough.
        decoded_rx:  list of dicts from smoke_decode_frames(rx_pkts).
                     Each dict carries the per-frame decoded fields.
        label:       Free-form test label, used in banners.
        pkts_sent:   Optional; how many TX packets were sent. Shown
                     in the banner so the reader can see at-a-glance
                     'we sent 5, we received N'.
        test_dport:  Optional; the UDP dport of the test stream.
                     When provided, frames whose dport differs are
                     dropped from the side-by-side dump (still
                     listed once in a 'filtered' note).
        full_pair_max: Max number of vertical TX/RX pairs to render.
                     Defaults to 8 so we don't blast the log when
                     someone runs a 100-packet stream.
        tx_label:    Optional human label for the TX side -- replaces
                     the generic 'TX (intent)' header in the banner
                     and side-by-side dump. Use this to
                     name the vantage point of the TX-side data so
                     the operator immediately sees WHERE on the wire
                     it was observed (or built), eg.:
                       'Ixia -> DUT1 Ethernet1_49 (intent)'
                     When omitted, defaults to 'TX (intent)' to keep
                     existing callers backward-compatible.
        rx_label:    Optional human label for the RX side, same idea
                     as tx_label. Eg.:
                       'DUT2 Ethernet1_49 -> Ixia (captured)'
                     Defaults to 'RX (captured)'.
    """
    rx_total = len(decoded_rx)
    # Resolve effective header strings ONCE here so the two
    # downstream log sites (banner / side-by-side dump) all
    # speak the same vocabulary. Strip and fall back to the generic
    # label if an empty string was passed (defensive).
    _tx_lbl = (tx_label or '').strip() or 'TX (intent)'
    _rx_lbl = (rx_label or '').strip() or 'RX (captured)'

    # Filter test-stream frames if a dport is given.
    if test_dport is not None:
        rx_test = [d for d in decoded_rx
                   if d.get('l4_dport') == test_dport]
        rx_noise = [d for d in decoded_rx
                    if d.get('l4_dport') != test_dport]
    else:
        rx_test = list(decoded_rx)
        rx_noise = []

    rx_test_n = len(rx_test)

    st.banner("{}  vs  {} (side-by-side) - {}".format(
        _tx_lbl, _rx_lbl, label))

    if pkts_sent is not None:
        st.log("  Sent: {} pkt(s) ({} shared across all)   "
               "Captured: {} test pkt(s) (+{} control noise)".format(
                   pkts_sent, _tx_lbl, rx_test_n, len(rx_noise)))
    else:
        st.log("  {}: {} test pkt(s) (+{} control noise)".format(
            _rx_lbl, rx_test_n, len(rx_noise)))

    if rx_noise:
        st.log("  (filtered {} non-test frame(s) by dport!={})".format(
            len(rx_noise), test_dport))

    # ─ View: Side-by-side TX | RX dump (tcpdump style) ─────────────
    # Two columns of "<field> = <value>" lines, TX on the left, RX on
    # the right, separated by " | ". Lets the reader scan top-to-bottom
    # and see both sides of each field at the same vertical position.
    # Per-frame: always render frame[0]; render any later frame whose
    # compact summary differs from frame[0] (catches a single corrupted
    # frame in an otherwise-clean burst). Spam is bounded by
    # full_pair_max.
    if rx_test:
        st.log("")
        st.log("  --- TX dump | RX dump "
               "(side-by-side, tcpdump style) -------------")

        col_w = 42  # column width; fits 'eth_dst = aa:bb:cc:dd:ee:ff'

        def _aligned_block_lines(tx, rx):
            """Build TX and RX lines such that the same field appears
            on the same row in both columns. A field present on one
            side but missing on the other gets a '-' row in the
            missing column so the reader can see the asymmetry. A
            leading '*' marker is added to the field row when TX
            pinned a value and RX disagrees -- makes mismatches pop
            in the side-by-side dump. The value portion of mismatched
            fields is also wrapped in ANSI color (TX=red, RX=green)
            so the diverging characters jump out without having to
            cross-reference with the leading marker."""
            tx_lines = [_tx_lbl + ":"]
            rx_lines = [_rx_lbl + ":"]
            for k in _DUMP_FIELDS:
                tv = (tx or {}).get(k)
                rv = rx.get(k)
                if tv is None and rv is None:
                    continue
                lbl = _dump_label(k)
                mismatch = (tv is not None and tv != rv)
                marker = '*' if mismatch else ' '
                tx_val = _dump_val(tx, k)
                rx_val = _dump_val(rx, k)
                if mismatch:
                    tx_val = _hi_tx(tx_val)
                    rx_val = _hi_rx(rx_val)
                tx_lines.append("{} {:<8} = {}".format(marker, lbl, tx_val))
                rx_lines.append("{} {:<8} = {}".format(marker, lbl, rx_val))
            return tx_lines, rx_lines

        def _render_side_by_side(idx, tx, rx):
            st.log("    Frame [{}]:".format(idx))
            tx_lines, rx_lines = _aligned_block_lines(tx, rx)
            n = max(len(tx_lines), len(rx_lines))
            for i in range(n):
                lhs = tx_lines[i] if i < len(tx_lines) else ''
                rhs = rx_lines[i] if i < len(rx_lines) else ''
                # Visible-width-aware truncate + pad keeps the '|'
                # separator vertically aligned even when ANSI escape
                # sequences are present in the line.
                lhs = _ljust_visible(_truncate_visible(lhs, col_w), col_w)
                st.log("      {} | {}".format(lhs, rhs))

        first_summary = _dump_compact_summary(rx_test[0])
        _render_side_by_side(0, tx_intent, rx_test[0])

        printed = 1
        for i, rx in enumerate(rx_test[1:], start=1):
            if printed >= full_pair_max:
                st.log("    ... ({} more frame(s) not dumped)".format(
                           rx_test_n - printed))
                break
            if _dump_compact_summary(rx) != first_summary:
                st.log("    (frame [{}] differs from frame [0]; dumping)"
                       .format(i))
                _render_side_by_side(i, tx_intent, rx)
                printed += 1
        if printed == 1 and rx_test_n > 1:
            st.log("    (frames [1..{}] match frame [0]; not re-dumped)"
                   .format(rx_test_n - 1))

def smoke_check_frame(d, expected, frame_label):
    """Compare a decoded frame against an expected-field spec.

    The expected spec is a dict whose keys are decoder field names. Any
    field set to None in *expected* is skipped (not asserted). Any field
    set to True/False is asserted on truthiness. Numeric/str fields are
    compared with ==.

    Returns a list of human-readable failure strings (empty list on pass).
    Caller decides whether to hard-fail or soft-warn based on these.

    Example expected:
        {
          'l3': 'ipv4',
          'dscp': 46,
          'ttl_or_hl': 63,            # sent 64, expect 63 after L3VNI decap
          'has_vxlan_header': False,  # decap must have stripped VXLAN
          'l4_dport': 5046,
        }
    """
    fails = []
    for key, want in expected.items():
        if want is None:
            continue
        got = d.get(key)
        if got != want:
            fails.append("{} field '{}' got={!r} want={!r}".format(
                frame_label, key, got, want))
    return fails


def smoke_pick_one_dscp_per_tc(dscp_to_tc_map=None):
    """Return a sorted list of 8 (tc, dscp) tuples, one DSCP per TC.

    Uses GOLDEN_DSCP_TO_TC by default. For each TC 0..7 it picks the
    numerically smallest DSCP that maps to that TC, which gives a stable,
    well-known set across runs (eg TC0->0, TC5->40 etc depending on map).

    Returns:
        [(0, dscp_for_tc0), (1, dscp_for_tc1), ..., (7, dscp_for_tc7)]
        Missing TCs (no DSCP maps to that TC in the map) are omitted.
    """
    src_map = dscp_to_tc_map if dscp_to_tc_map is not None \
        else GOLDEN_DSCP_TO_TC
    by_tc = {}
    for dscp_str, tc in src_map.items():
        try:
            dscp = int(dscp_str)
            tc_i = int(tc)
        except (TypeError, ValueError):
            continue
        if tc_i not in by_tc or dscp < by_tc[tc_i]:
            by_tc[tc_i] = dscp
    return [(tc, by_tc[tc]) for tc in sorted(by_tc.keys())]



# ══════════════════════════════════════════════════════════════════════════════
# Smoke QoS verdict renderer (matches test_dscp_to_tc.py:_log_queue_placement_table)
# ══════════════════════════════════════════════════════════════════════════════


def smoke_log_q_results(deltas, label="", expected=None):
    """Print per-queue results table: expected vs actual packet counts.

    Mirrors `_log_queue_placement_table` from `test_dscp_to_tc.py`. This is
    the canonical QoS verdict format used across the suite for proving
    DSCP -> TC -> queue mapping correctness.

    Args:
        deltas:   {qi: {'pkts': int, 'drop_pkts': int}} for queues 0-7.
        label:    short string appended to the heading (e.g. test name).
        expected: {qi: int} expected packet count per queue. Required
                  (single-DSCP smoke bursts always know the target queue).

    Pass criterion (per queue):
        exp == 0      -> PASS if act <= 5%-of-max-noise floor (or 1)
        exp >  0      -> PASS if exp*0.85 <= act <= exp*1.15 (+/- 15%)
    """
    if expected is None:
        expected = {}
    exp_map = expected
    if exp_map:
        noise = max(int(max(exp_map.values()) * 0.05), 1)
    else:
        noise = 0
    hdr = "  {:<6} {:>12}  {:>12}  {:>12}  {:>10}  {:>6}".format(
        "Queue", "Expected", "Actual", "Drop", "Status", "Delta%")
    st.log("")
    st.log("  DSCP Queue-Placement Results {}".format(label))
    st.log("  " + "-" * 75)
    st.log(hdr)
    st.log("  " + "-" * 75)
    for qi in range(8):
        exp = exp_map.get(qi, 0)
        d = deltas.get(qi) or {}
        act = d.get('pkts', 0)
        drp = d.get('drop_pkts', 0)
        if exp == 0:
            status = "PASS" if act <= noise else "FAIL"
            dpct = "-"
        else:
            lo = int(exp * 0.85)
            hi = int(exp * 1.15)
            status = "PASS" if lo <= act <= hi else "FAIL"
            dpct = "{:+.1f}%".format((act - exp) / float(exp) * 100)
        st.log("  Q{:<5} {:>12,}  {:>12,}  {:>12,}  {:>10}  {:>6}".format(
            qi, exp, act, drp, status, dpct))
    st.log("  " + "-" * 75)
    st.log("")
