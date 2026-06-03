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

"""DSCP-to-TC smoke variant that mirrors the leaf0 setup from the
4x4-tortuga-fabric reference run captured in
``results_2026_05_20_11_35_34_mlog_cisco_tortuga_solution_test_fx3_qos.pdf``.

Why a separate file?
====================
The sibling smoke classes in ``test_dscp_to_tc_overlay.py``
(``TestSmokeL3VNI`` / ``TestSmokeL3VNITagged``) configure the minimum
VxLAN+EVPN that's needed to put inner-DSCP onto an underlay wire. They
intentionally skip the "leaf-flavor" knobs that a real EVPN leaf in a
multi-pod fabric would carry -- those knobs add no signal for the bare
encap+decap classifier story.

The PDF run, however, is a **canonical** EVPN deployment shape: leaf0
boots with policy-tightening BGP knobs, ``counterpoll tunnel enable``
for tunnel-stat plumbing, and a tagged-SVI ingress that does the L3
lookup in the L3VNI VRF -- exactly the shape a deployment engineer
would copy into a customer pod. This class reproduces that shape on
the 2-DUT FX3 testbed so the smoke covers the **deployment-realistic**
config path, not just the minimal-fabric one.

Single source of truth: ``cisco/tortuga/solution/validated_configs/
base_l3vni/l3vni_leaf0.cfg`` -- the exact file driven by the PDF run.

What's reproduced (single-VRF "minimal" scope per user request):
  * ``counterpoll tunnel enable`` (both DUTs).
  * BGP policy knobs (both DUTs):
    - ``bgp disable-ebgp-connected-route-check``
    - ``bgp bestpath as-path multipath-relax``
    - (opt-in) ``no ip/ipv6 nht resolve-via-default``
  * Tagged-SVI ingress on a transport VLAN bound to the L3VNI VRF
    (DUT1 only -- delegated to the canonical
    ``_smoke_setup_l3vni_tagged_svi`` from the sibling overlay
    module so the VID and the orchagent settle ordering exactly
    match what ``_smoke_run_one(mode='l3vni_tagged')`` looks for
    at traffic time).

What's intentionally NOT reproduced (would require a fabric refactor
that's out of scope for a 2-DUT testbed):
  * BGP loopback-sourced peering with ``neighbor update-source
    Loopback0`` and interface-mode neighbors. Our base helper peers
    over the underlay transit subnet (V4_TRANSIT_DUT2_BARE), which
    is functionally identical for the encap+decap classifier story
    we're smoking. Switching to loopback peering would require
    re-bringing the underlay routes first, then pivoting the BGP
    session, with no measurable signal added to the test.
  * EVPN-MH (``evpn mh uplink`` etc.) -- needs a peer leaf, which
    the 2-DUT testbed does not have.
  * Multi-VRF tenant separation (``Vrf101``/``Vrf102``/``Vrf103``).
    User explicitly asked for the **minimal** single-VRF scope.
  * ``bgp router-id <vtep_ip>`` and ``static-anycast-gateway-mac``
    -- see the "why dropped" notes above the constants block.

Why this still uses ``mode='l3vni_tagged'`` from the sibling module
===================================================================
The wire shape this class produces is identical to
``TestSmokeL3VNITagged``: 802.1Q-tagged ingress, SVI in a VRF, L3
lookup hits an EVPN-imported overlay route, encap fires. The
per-frame validation logic in ``_smoke_run_one(mode='l3vni_tagged')``
already knows about that shape (TTL_rx == TTL_tx-2, VLAN tag
asymmetric, etc.), so reusing it is the right call -- the only
delta this class introduces is the **setup-side** leaf0-flavor
knobs, not the wire shape.

How this file relates to ``test_dscp_to_tc_overlay.py``
========================================================
This file imports a small set of underscore-private names from
``test_dscp_to_tc_overlay.py`` (``_smoke_run_one``,
``_smoke_preflight``, ``_smoke_pairs``, ``_smoke_pair_ids``,
``_smoke_setup_l3vni_tagged_svi``) plus
the module-level ``setup_topo``-populated globals (``dut``,
``dut2``, ``port_info``, ``topo_mode``). Those names are private
to the *test module* not because they are unstable APIs, but
because they are not part of ``vxlan_helper.py``'s public surface
-- within the ``qos_map/`` package they are the de-facto
smoke-test API and have been heavily exercised by all four
``TestSmoke*`` classes for several months.

This file *does* own its own ``setup_topo`` autouse fixture (a
necessity, not a choice -- pytest only runs autouse-module fixtures
for modules that contribute a test to the session, so we cannot
rely on _overlay's setup_topo firing when only this file's tests
are selected).  To avoid two ``setup_topo_common`` invocations
when both modules are collected together, our fixture borrows
_overlay's already-populated handles when present, and only
invokes ``setup_topo_common`` itself when _overlay's globals are
still uninitialized.  See the fixture's own docstring for the
path-A / path-B contract.

A future rename of any imported _overlay helper will fail fast at
import time, which is the correct fail-loud-not-silent behavior.

Opt-in env-var matrix
=====================

  VXLAN_LEAF0_LAG_INGRESS=0|1   (default: 1 -- ON)
      Wraps the DUT-side L3VNI ingress in a single-member LACP
      PortChannel **with fallback enabled** (PortChannel0001
      backing Vlan100 tagged-SVI on Ethernet1_49). Default ON
      since real-HW validation (smoke_leaf0_lag_one_II.log)
      proved the LACP-fallback ingress path works end-to-end
      on this FX3 build. Set VXLAN_LEAF0_LAG_INGRESS=0 to opt
      out and revert to the single-port baseline (useful for
      A/B comparison against TestSmokeL3VNITagged).
      LACP-fallback chosen over static after both static-via-click
      (silent flag drop on this FX3 build) and static-via-klish
      (UI not supported on this FX3 build) failed. With fallback
      enabled, the LAG admits its lone member to the active
      bundle after the LACP rx Short Timeout (~3s) even when no
      partner LACPDUs arrive. See the constants block near
      ``_LEAF0_LAG_INGRESS`` for the full archeology.

  VXLAN_LEAF0_IXIA_LAG=1
      Wraps the Ixia-side ingress port in a single-member static
      LAG topology object so IxNetwork shows a symmetric LAG-to-LAG
      wire diagram. Cosmetic only -- wire frames are unchanged
      (DUT runs LACP and discards the lack of partner PDUs via
      fallback; Ixia static LAG sends no LACPDUs at all).
      Requires the DUT-side LAG-wrap to be active (which is
      now the default; see VXLAN_LEAF0_LAG_INGRESS above).
      Default off; if the IxNetwork backend rejects ``protocol_type=
      'lag_port_static'`` (this combination is unverified in our
      tree -- the only existing precedent in
      cisco/tortuga/vxlan/vxlan_utils.py:342 uses
      ``'lag_port_lacp'``), the helper falls back to the physical
      handle and emits a clear warn -- the test continues to
      run, only the cosmetic GUI wrap is skipped.

  VXLAN_LEAF0_EGRESS_SVI_LAG=0|1   (default: 1 -- ON)
      Mirrors the DUT1-side leaf0 stack (Vlan100 tagged-SVI in
      VrfQoS, wrapped in PortChannel0001 with LACP fallback)
      onto DUT2's egress-to-Ixia port (Ethernet1_49 on DUT2),
      so the wire shape is symmetric: LAG-to-LAG on both sides
      of the fabric and SVI-in-VrfQoS on both sides of the VxLAN
      tunnel. This matches leaf0.cfg's downlink convention which
      uses the same LAG name on both server-facing and peer-leaf
      interfaces. Default ON: HW validation is performed in
      parallel with the DUT1-LAG smoke baseline; if this becomes
      flaky on a future FX3 build, set VXLAN_LEAF0_EGRESS_SVI_LAG=0
      to opt out and revert to plain routed-port-in-VrfQoS on
      DUT2 for A/B comparison.
      The wrap rebinds dut2_port_info['egress_ixia'] from the
      physical port to 'PortChannel0001' so the smoke's per-queue
      dchal readback (which builds dut2_ctx from
      dut2_port_info['egress_ixia'] in _smoke_run_one) sees the
      LAG-RIF queue counters that SAI accounts decap-side
      egress queueing against on this build. PORT_QOS_MAP|<lag>.
      dscp_to_tc_map = AZURE is additively HSET (the physical-
      port binding from `config qos reload` stays in place);
      on builds where SAI consults the LAG-RIF entry this is
      what makes the decap-side classifier hit, on builds where
      it inherits from the physical member it's a harmless no-op.
      Adds a 4th forensic VxLAN-state-dump snapshot
      ('after-DUT2-egress-SVI-LAG') between the existing
      'after-LAG-wrap' (DUT1) and 'after-BGP-knobs' snapshots so
      the diff between consecutive snapshots isolates whether
      the DUT2 wrap is what caused any oper_status / route-count
      change (which is the discriminator for the DUT2-egress-
      SVI-LAG-specific risk path).

  VXLAN_LEAF0_IXIA_LAG_EGRESS=0|1   (default: 0 -- OFF)
      Cosmetic: wraps the Ixia-side egress port (1/12 by
      convention) in a single-member LAG topology object so
      IxNetwork shows a symmetric LAG-to-LAG wire diagram on
      the egress side too. Mirrors the ingress
      VXLAN_LEAF0_IXIA_LAG knob exactly: both default OFF
      because the underlying _wrap_ixia_ingress_in_lag helper
      has known latent bugs on this Ixia build (wrong
      ``protocol_type`` keyword + TG API Fatal Abort escapes
      the helper's try/except -> session-killing test SKIP).
      See the constants block near _LEAF0_IXIA_LAG_EGRESS for
      the full bug trail.

      Important distinction from the cosmetic wrap: the TAGGED
      v4/v6 host re-prime on Ixia 1/12 is UNCONDITIONAL whenever
      VXLAN_LEAF0_EGRESS_SVI_LAG=1 is in effect (independent of
      this knob), because without it the wire shape mismatches
      between DUT2 (sending tagged ARPs on Vlan100) and Ixia
      1/12 (still configured as an untagged routed host from
      module-init time). The mismatch causes Ixia's vport L2
      filter to drop every ARP-request DUT2 sends, ARP never
      resolves, and every decap'd test packet is silently
      dropped at DUT2's L3 lookup -- the smoke_leaf0_lag_one_IV
      .log "DUT2 q[N]=0 while DUT1 q[N]=5" + preflight ping
      "Destination Host Unreachable from 20.20.20.1" failure
      mode.

      With the cosmetic wrap OFF (default), the Ixia-side wire
      shape is STILL FULLY SYMMETRIC to DUT1's: both Ixia 1/9
      and Ixia 1/12 carry tagged Vlan100 frames as classic-HLT
      routed hosts (20.20.20.2/24 + 2001:db8:20::2/64, gateway
      20.20.20.1 / 2001:db8:20::1). The only asymmetry the GUI
      would show is vport:1 (physical) vs the would-be
      vport:4-inside-LAG view -- a cosmetic-only delta that
      does not affect any test verdict.

      Set VXLAN_LEAF0_IXIA_LAG_EGRESS=1 once
      _wrap_ixia_ingress_in_lag's two latent bugs have been
      fixed (the right protocol_type keyword for this IxNet
      build + outer-most TG-API-Fatal-Abort catch).

  VXLAN_LEAF0_IXIA_TAG_FLIP=0|1   (default: 0 -- OFF)
      Forensic-only re-enable of the broken Step 8b/8c tagged
      re-prime block on Ixia 1/12. Default OFF because the
      block fails in two distinct ways on the current IxNet
      HLTAPI build (NGPF-bookkeeping KeyError on the destroy
      pre-step + NGPF auto-routing rejecting classic-HLT-only
      ``l2_encap``/``vlan`` kwargs on the re-config). See the
      long-form trail at _LEAF0_IXIA_TAG_FLIP in the constants
      block; tl;dr: the DUT1 side does NOT tag-flip Ixia 1/9
      either (it just re-pokes the untagged host's ARP via
      ``mode='modify'``) and the test still works because the
      stream config carries ``mac_dst=<DUT1-LAG-MAC>``
      hardcoded. New default for DUT2 = mirror DUT1: leave
      the untagged host alone; only the always-on Step 8z
      ARP re-poke runs. Flip this knob to 1 on a future
      IxNet build to test whether tag-flip works there.

  VXLAN_LEAF0_DUT2_STATIC_ARP=0|1   (default: 0 -- OFF)
      Forensic-only re-enable of the Step 9 static neighbour
      install on DUT2 (Vlan100 SVI in VrfQoS, IXIA_EGRESS_IP
      -> canonical egress-role MAC). Default OFF because the
      mechanism is structurally wrong: it papers over the
      DUT2->Ixia ARP failure but doesn't teach Ixia 1/12
      anything, so a future Ixia 1/12->DUT2 TX stream would
      still fail to resolve DUT2's SVI MAC; and static
      neighbours don't refresh on SVI rebind. Kept behind a
      knob purely so a future debugging session can answer
      "would the test pass if DUT2 had the right ARP entry?"
      by flipping the knob and re-running.

  SMOKE_DUT2_SAI_QC_FALLBACK=off|auto|force   (default: off)
      Drop-in fallback for DUT2's per-queue scorecard when the
      on-DUT `dchal_qi.py` helper is blind to LAG-RIF queue
      traffic. Takes a parallel SAI snapshot via
      `show queue counters <egress_ixia>` around the burst.

      Modes:
        off    DCHAL is the only source (legacy).
        auto   DCHAL is primary; SAI substitutes only when
               DCHAL deltas are ALL-ZERO across Q0..Q7
               (tot_p==tot_d==0) AND SAI shows real activity.
               '1' / 'true' / 'yes' accepted as aliases.
        force  SAI is always the source on DUT2 egress.
               DCHAL is still logged side-by-side for
               forensics. Recommended when DUT2 egress is
               permanently LAG-wrapped, e.g. every
               TestSmokeL3VNIPortChannelLeaf0 run on this FX3 build.

      WHY THIS EXISTS: on this FX3 build, once Ethernet1_49
      is enslaved to PortChannel0001 (single-member
      leaf0-style LAG-of-one wrap), L3-classified user data
      is queued against the LAG-RIF VOQ. The on-DUT helper
      `dchal_qi.py` calls
      `show_queuing_intf.collect_queuing_data(asic_port=...)`
      which indexes the accounting tables
      (tah_sun_bax_dhs_acct_uc_oqueue_*_count) by
      `physical_asic_port × NUM_QUEUES` and has no LAG-RIF
      VOQ lookup path -- it reads frozen historical values
      from before the LAG enslavement and never picks up
      the new bursts. This is a dchalshell-script-level
      limitation we cannot fix without patching the on-DUT
      package. DUT1 doesn't have this problem because its
      transit-out port (Ethernet1_54_1) is not LAG-wrapped.
      See the long-form trail at `_SMOKE_DUT2_SAI_QC_FALLBACK`
      in ``test_dscp_to_tc_overlay.py`` for the full
      archeology.

      A side-by-side "DUT2 q[N] DCHAL=X  SAI=Y" line is
      logged for every queue that had non-zero activity in
      either source, so the operator can always see the
      comparison (and any mismatch) regardless of which
      source ended up driving the scorecard.

      RECOMMEND 'force' for any class that wraps DUT2 egress
      in a LAG (TestSmokeL3VNIPortChannelLeaf0). Default 'off'
      preserves the byte-for-byte behaviour of pre-existing
      CI runs.

      Example:
          export SMOKE_DUT2_SAI_QC_FALLBACK=force
          pytest ... test_dscp_to_tc_portchannel_smoke_leaf0.py
"""

import os
import warnings

import pytest

# Match the sibling module's deprecation-filter setup so the bare-
# import noise stays consistent across the smoke files.
warnings.filterwarnings(
    "ignore", r".*ssl\.PROTOCOL_TLS is deprecated.*", DeprecationWarning)

from spytest import st, tgapi                      # noqa: E402

from qos_helpers import (                           # noqa: E402
    print_section,
    setup_topo_common,
    deploy_dchal_helper,
    # Constants needed by _setup_egress_svi_dut2 to re-prime the Ixia
    # egress port after the DUT2-side SVI+LAG wrap (see Step 8 there
    # for the full rationale).
    IXIA_EGRESS_IP,
    IXIA_EGRESS_IP6,
    NETMASK,
    PREFIX_LEN_V6,
)

# Borrow the smoke-test machinery (and *only* the helper functions,
# not the module globals) from the sibling overlay module. The
# helpers we use from there -- _smoke_run_one, _smoke_preflight,
# _smoke_pairs, _smoke_pair_ids,
# _smoke_setup_l3vni_tagged_svi -- read their state via Python
# name lookup against *_overlay's* own globals, which are
# populated by _overlay.setup_topo only when at least one test
# from _overlay's module is collected in the same pytest session.
# Since this file's tests live here, _overlay.setup_topo would
# NOT fire when only our tests are selected -- the helpers would
# then see _overlay.dut == None and fail at runtime
# (smoke_leaf0_one.log @ 21:11:55 confirmed that exact failure).
#
# Fix: this module owns its own setup_topo fixture (below) that
# either piggy-backs off _overlay's already-populated globals
# (when both modules are collected together) or runs its own
# setup_topo_common (when only this file is collected). Either
# way, by the time _smoke_run_one / _smoke_preflight execute,
# _overlay.dut and friends are populated, so name-lookup inside
# those helpers resolves correctly.
#
# Plain ``import test_dscp_to_tc_overlay as _overlay`` (NOT
# ``from . import ...``) because qos_map/ is not a Python package
# (no __init__.py) -- pytest adds the test file's containing
# directory to sys.path at collection time, so a bare module-name
# import is the established idiom here. The sibling module itself
# uses the same idiom for ``from test_dscp_to_tc import ...``.
import test_dscp_to_tc_overlay as _overlay          # noqa: E402

# Borrow public-ish constants from vxlan_helper -- same names the
# sibling module imports.
from vxlan.vxlan_helper import (                    # noqa: E402
    _I_VRF,
    _I_VNI,
    _I_BGP_AS1,
    _I_BGP_AS2,
    _setup_vxlan_l3vni,
    _setup_vxlan_l2vni,
    _J_VNI,
    _J_L2_VLAN,
    V4_EGRESS_IP,
    V6_EGRESS_IP,
)


# ══════════════════════════════════════════════════════════════════
# Module-level state (populated by setup_topo fixture below)
# ══════════════════════════════════════════════════════════════════
#
# These names exist in *this* module's globals so that
# ``_setup_vxlan_l3vni()`` -- which frame-walks back to its direct
# caller's module via ``_resolve_caller_globals`` -- finds the live
# DUT/Ixia handles when called from this file's fixture.

dut            = None
dut2           = None
tg             = None
tg_ph          = {}
port_info      = {}
dut2_port_info = {}
topo_mode      = None


# ══════════════════════════════════════════════════════════════════
# Module fixture: setup_topo
# ══════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """Topology setup for this leaf0-style smoke module.

    Mirrors ``_overlay.setup_topo`` so this module is fully
    self-contained: it can be collected and run on its own without
    depending on any other module's autouse fixture firing.  Pytest
    only runs autouse-module fixtures for modules that contribute a
    test to the session, so a plain ``import _overlay`` does NOT
    cause _overlay's setup_topo to fire when only this file's tests
    are selected -- which was the failure mode in
    ``smoke_leaf0_one.log`` @ 21:11:55.

    Two execution paths:

      A. _overlay was *also* collected this session
         (e.g. ``-k test_dscp_to_tc`` selects tests from both files).
         In that case _overlay.setup_topo has already run by the time
         we get here (module-scoped autouse fires before any
         class-scoped autouse), so _overlay.dut is populated and we
         simply borrow its handles into our own globals -- avoiding
         a redundant ``setup_topo_common`` call (saves ~20s, prevents
         a second ``config qos reload`` from running on a live box).

      B. Only this module is collected this session.
         _overlay.dut is still None.  We invoke ``setup_topo_common``
         ourselves with the same ``target_queue=0`` / ingress_b
         supplementation logic as _overlay.setup_topo does, then
         publish the result into both our own globals AND
         _overlay's globals (so the helpers we borrow from
         _overlay -- which read their state from _overlay's
         globals via normal Python name lookup -- see the same
         live values we do).

    Either way, the post-condition is: this module's globals (dut,
    dut2, tg, tg_ph, port_info, dut2_port_info, topo_mode) are all
    populated AND _overlay's globals are populated identically, so
    every helper invoked downstream sees a consistent topology view.
    """
    global dut, dut2, tg, tg_ph, port_info, dut2_port_info, topo_mode

    if _overlay.dut is not None:
        # Path A: _overlay already brought the topology up. Borrow.
        dut            = _overlay.dut
        dut2           = _overlay.dut2
        tg             = _overlay.tg
        tg_ph          = _overlay.tg_ph
        port_info      = _overlay.port_info
        dut2_port_info = _overlay.dut2_port_info
        topo_mode      = _overlay.topo_mode
        st.log("setup_topo (leaf0): borrowing handles from "
               "_overlay (dut={}, mode={})".format(dut, topo_mode))
        yield
        return

    # Path B: bring the topology up ourselves.  Implementation
    # mirrors _overlay.setup_topo line-for-line; the only edit is
    # the final block that ALSO publishes into _overlay's globals.
    for result in setup_topo_common(tgapi, target_queue=0):
        dut       = result['dut']
        tg        = result['tg']
        topo_mode = result['mode']

        raw_ph = result['tg_ph']
        raw_pi = result['port_info']

        # Supplement raw 'ingress_b' on breakout-mode VxLAN testbeds
        # (mirrors _overlay.setup_topo's same supplement block).
        if 'ingress_b' not in raw_pi:
            try:
                tb_vars = st.get_testbed_vars()
                if hasattr(tb_vars, 'D1T1P2'):
                    raw_pi['ingress_b'] = tb_vars.D1T1P2
                    _, tg_ph_b = tgapi.get_handle_byname('T1D1P2')
                    raw_ph['ingress_b'] = tg_ph_b
                    st.log("setup_topo (leaf0): supplemented "
                           "ingress_b = {}"
                           .format(raw_pi['ingress_b']))
            except Exception as exc:
                st.warn("setup_topo (leaf0): failed to supplement "
                        "ingress_b (non-fatal): {}".format(exc))

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

        deploy_dchal_helper(dut)
        if dut2:
            deploy_dchal_helper(dut2)

        # ALSO publish into _overlay's module globals so the helpers
        # we borrow from _overlay (which read their state via name
        # lookup against _overlay's globals -- not via attribute
        # access on the module) see the same handles. Without this
        # step, _smoke_run_one / _smoke_preflight / etc. would still
        # see _overlay.dut == None even though our module's dut is
        # populated.
        _overlay.dut            = dut
        _overlay.dut2           = dut2
        _overlay.tg             = tg
        _overlay.tg_ph          = tg_ph
        _overlay.port_info      = port_info
        _overlay.dut2_port_info = dut2_port_info
        _overlay.topo_mode      = topo_mode

        st.log("setup_topo (leaf0): brought topology up "
               "(mode={}, dut={}, dut2={})"
               .format(topo_mode, dut, dut2))

        yield


# ── leaf0-flavor knobs (sourced from l3vni_leaf0.cfg) ──────────────
#
# leaf0.cfg line  CLI                                    in this file
# --------------  -------------------------------------  --------------------
#  2              counterpoll tunnel enable              _LEAF0_COUNTERPOLL_TUNNEL
# 24              bgp router-id 10.200.200.200           DROPPED (see "why dropped")
# 27              bgp disable-ebgp-connected-...         _LEAF0_BGP_DISABLE_CONN_CHECK
# 28              bgp bestpath as-path multipath-relax   _LEAF0_BGP_MPATH_RELAX
# (PDF mlog)      no ip/ipv6 nht resolve-via-default     _LEAF0_NHT_RESOLVE_OFF (opt-in)
# (PDF mlog)      static-anycast-gateway-mac add ...     DROPPED (see "why dropped")
# (PDF mlog)      tagged-SVI ingress on Vlan<N>          delegated to
#                                                          _overlay._smoke_setup_l3vni_tagged_svi
#
# Why a few knobs are intentionally DROPPED rather than reproduced
# ----------------------------------------------------------------
#   * ``bgp router-id <vtep_ip>``: pushing this on a *converged*
#     BGP session (which our base ``_setup_vxlan_l3vni`` has already
#     established) causes FRR to re-establish the session. Combined
#     with the immediately-following preflight VTEP-ping, that
#     produces spurious WARNs. FRR auto-picks the highest loopback
#     as the router-id by default, which is already Loopback1's
#     VTEP IP -- so the explicit set is also semantically
#     redundant. Dropped: zero observable signal, real flap risk.
#
#   * ``static-anycast-gateway-mac add ...``: the exact SONiC CLI
#     for SAG varies by platform (``config sag mac add`` vs
#     ``config interface ip static-anycast-gateway-mac`` vs
#     ``config interface mac add``). Without a confirmed working
#     CLI for the FX3 build *and* a smoke check that actually
#     consumes the anycast MAC (we have a single ingress + single
#     egress, no host mobility), pushing a guessed CLI is all
#     downside. Dropped: re-add when there is a smoke that
#     actually validates anycast behaviour.
#
# Why the SVI step is delegated, not duplicated
# ---------------------------------------------
# An earlier revision of this file inlined the entire phys-port-IP
# unbind / vlan-create / vlan-member-add / svi-vrf-bind / svi-IP-add
# sequence (~70 lines, a line-for-line copy of
# ``_overlay._smoke_setup_l3vni_tagged_svi``). That duplication had
# two concrete bugs that bit at first run:
#
#   1. The local copy used ``_LEAF0_TENANT_VLAN = 8`` (the literal
#      VID from leaf0.cfg) while ``_smoke_run_one(mode='l3vni_tagged')``
#      tags every Ixia frame with the constant ``_L2_VLAN_ID = 100``
#      and resolves dst_mac from ``Vlan{_L2_VLAN_ID}``. The two
#      mismatched VIDs caused L2 drops on the trunk member and
#      every smoke instance failed with 0 RX.
#
#   2. The local copy also drifted from the canonical helper's
#      orchagent settle ordering and the defensive
#      ``PORT_QOS_MAP|<port>.dscp_to_tc_map=AZURE`` re-assert.
#
# Both bugs go away when we call the canonical helper and let it
# own the wire-shape config; the leaf0 file then only carries the
# truly *additive* knobs (counterpoll + BGP policy) on top.
_LEAF0_BGP_DISABLE_CONN_CHECK = True
_LEAF0_BGP_MPATH_RELAX        = True
# ``no nht resolve-via-default`` is an opt-in. In our 2-DUT testbed
# the BGP underlay neighbor (V4_TRANSIT_DUT2_BARE = 30.30.30.2) is
# *connected*, so the knob is fine in steady state. But during any
# brief window where the next-hop is reachable only via a learned
# route (e.g. underlay re-convergence after a flap), this knob
# blocks recovery. Default off; flip to True to verify the
# leaf0 NHT-tightening behaviour explicitly.
_LEAF0_NHT_RESOLVE_OFF        = False
_LEAF0_COUNTERPOLL_TUNNEL     = True


# ── LACP-fallback LAG ingress (single-member, opt-in) ──────────────
#
# leaf0.cfg models each server-facing access link as its own
# PortChannel (PortChannel0001 on the L3VNI downlink, PortChannel0002
# on the L2VNI downlink). Our 2-DUT testbed has a single physical
# wire (Ethernet1_49) for the L3VNI ingress; to mirror the leaf0
# wire-shape we wrap that single physical port into a single-member
# **LACP-mode LAG with fallback enabled** so the DUT admits the lone
# member to the bundle even when no LACP partner exists on the Ixia
# side.
#
# Why env-gated rather than always-on
# -----------------------------------
# The DSCP-to-TC classifier on FX3 is implemented as an L3QOS ACL
# keyed on bd_label / bd_or_vnid (we proved this during the
# encap-side `bd_or_vnid` investigation, see scripts/qos/sonic_172_
# 26_235_252_ing_l3_vlan_qos_*.sections.txt). Both bd_label and
# bd_or_vnid derive from the *RIF*, and a LAG RIF is a different
# RIF than the underlying physical-port RIF. There is real risk
# that the ACL still installs but no longer hits when the L3 lookup
# happens via a LAG-RIF SVI. Real-HW validation closed that gap:
# smoke_leaf0_lag_one_II.log shows the LACP-fallback LAG ingress
# delivers DUT1 q[4]=5 + DUT2 q[4]=5 end-to-end (the same
# verdict as the single-port baseline), so the LAG path is now
# the default for this class. Setting VXLAN_LEAF0_LAG_INGRESS=0
# reverts to the single-port baseline for A/B comparison
# against TestSmokeL3VNITagged.
#
# Why LACP-with-fallback rather than static
# -----------------------------------------
# The user explicitly requested "DUT as dynamic port channel, Ixia
# as static port channel" (the leaf0.cfg shape: standard LACP on
# the leaf, with the server side typically running LACP too in the
# real fabric, but our Ixia testbed model treats the partner as a
# bare wire that emits no LACPDUs). LACP-with-fallback is the
# combination that satisfies both:
#   * DUT side runs the leaf0-shape LACP control plane.
#   * Ixia side stays free of any required protocol exchange --
#     when the LACP rx Short Timeout (3s) elapses with no PDUs,
#     teamd's fallback fires and the lone member is admitted to
#     the active bundle. Wire frames thereafter are plain ethernet
#     (the LACP machine on DUT keeps emitting periodic LACPDUs
#     into the void; Ixia ignores them harmlessly).
#
# Why NOT static (the trail of pain that led here)
# ------------------------------------------------
# Two earlier attempts at static-mode failed on this FX3 build:
#
#   v1 (smoke_leaf0_lag_one.log first variant):
#     ``create_portchannel(static=True)`` via the click branch
#     of apis/switching/portchannel.py. The click branch gates
#     the ``--static=true`` flag on
#     ``st.is_feature_supported("config_static_portchannel")``,
#     which is False on this FX3 build, so the flag is silently
#     dropped (apis/switching/portchannel.py:106-109). LAG came
#     up in default LACP mode -- and with no LACP partner on
#     the Ixia side, member Ethernet1_49 stayed in
#     LACP_DEFAULTED state and never joined the active bundle ->
#     0 RX (the original run masked this as XPASS via the
#     now-removed _VXLAN_DECAP_QOS_BUG xfail marker; in the
#     current code it would surface as a hard failure).
#
#   v2 (smoke_leaf0_lag_one.log second variant @ 23:50:32):
#     ``create_portchannel(static=True, cli_type='klish')`` --
#     klish branch unconditionally emits ``mode on`` (no
#     feature-flag gate at apis/switching/portchannel.py:140-141),
#     so this should have worked. It didn't: the FX3 build does
#     not advertise klish UI support at all, so spytest aborted
#     with ``Report(Unsupported): UI 'klish' unsupported`` BEFORE
#     create_portchannel sent a single CLI to the box. Worse,
#     this happened AFTER our step-1 ``vlan member del`` already
#     executed -- the testbed was left in a half-state with
#     Ethernet1_49 detached from Vlan100, and no recovery
#     because the wrap helper's _teardown closure was never
#     registered (the helper aborted before reaching ``return
#     _teardown``).
#
# Lesson learned (reflected in the v3 helper below)
# -------------------------------------------------
# The v3 wrap helper has two structural changes vs v1/v2:
#
#   (a) Uses ``fallback=True`` instead of ``static=True``. The
#       click branch's fallback path emits ``--fallback=true``
#       unconditionally with no feature-flag gate
#       (apis/switching/portchannel.py:113-119). Verified post-
#       creation via ``HGET PORTCHANNEL|<lag>.fallback`` so the
#       flag's presence is asserted at runtime.
#
#   (b) Builds the teardown closure incrementally as a list of
#       registered cleanup steps -- each destructive step
#       appends its undo to the list AS SOON AS the destructive
#       call returns. If the helper aborts mid-sequence (raise
#       OR False return from any API), the returned teardown
#       still undoes EXACTLY what was actually done, so the box
#       is restored to a self-consistent state. This is the
#       structural fix for the v2 half-state-leftover bug.
#
# Why a single helper, not a polymorphic vxlan_helper kwarg
# ---------------------------------------------------------
# We could add a `lag=...` kwarg through `_smoke_setup_l3vni_tagged
# _svi` (test_dscp_to_tc_overlay.py) and have it speak port-or-LAG.
# That would touch a helper used by every TestSmoke* class today
# and break the "leaf0 file is purely additive" property. Instead
# we let the canonical helper produce a port-mode SVI as it always
# has, and *layer* the LAG wrap on top inside this file. The wrap
# helper migrates the Vlan{vid} tagged membership from the physical
# port to the LAG, and the SVI's IP-binding survives unchanged
# (the SVI is the L3 RIF either way). Single-purpose, fully-
# reversible, scoped to this file.
_LEAF0_LAG_INGRESS       = os.environ.get('VXLAN_LEAF0_LAG_INGRESS', '1') == '1'
_LEAF0_LAG_NAME_L3VNI    = 'PortChannel0001'   # leaf0.cfg downlink
_LEAF0_LAG_NAME_L2VNI    = 'PortChannel0002'   # leaf0.cfg L2VNI downlink
_LEAF0_LAG_INGRESS_L2VNI = (
    os.environ.get('VXLAN_LEAF0_LAG_INGRESS_L2VNI', '1') == '1')

# ── DUT2 egress LAG for L2VNI (mirror DUT1's LAG-wrap on decap side) ──
#
# Wraps DUT2's egress_ixia port (Ethernet1_49) in a single-member
# LACP+fallback PortChannel, migrating its Vlan502 untagged membership
# to the LAG. This mirrors the DUT1 ingress LAG-wrap on the decap
# side so that both ingress and egress of the L2VNI path are
# PortChannel-based (symmetric leaf0 shape).
_LEAF0_LAG_EGRESS_L2VNI = (
    os.environ.get('VXLAN_LEAF0_LAG_EGRESS_L2VNI', '1') == '1')
_LEAF0_LAG_NAME_L2VNI_EGRESS = 'PortChannel0002'  # same name on DUT2 (different box)


# ── DUT2 egress SVI + LAG (mirror DUT1's leaf0 shape on decap side) ──
#
# Why this exists
# ---------------
# The DUT1 ingress LAG-wrap (above) produces this stack on DUT1:
#
#   Ethernet1_49 (physical, default VRF, no L3)
#     -> member of PortChannel0001 (LACP+fallback, single-member)
#          -> tagged member of Vlan100 (_L2_VLAN_ID)
#               -> Vlan100 SVI in VrfQoS with V4/V6_INGRESS_A_IP
#               -> PORT_QOS_MAP|Ethernet1_49.dscp_to_tc_map = AZURE
#               -> PORT_QOS_MAP|PortChannel0001.dscp_to_tc_map = AZURE
#
# leaf0.cfg models server-facing access links as LAGs on *both* sides
# of the wire (server and peer leaf), so the literal leaf0 mirror is
# to give DUT2's egress-to-Ixia port (Ethernet1_49) the same stack.
# After the wrap DUT2's Ethernet1_49 looks identical to DUT1's --
# same Vlan100, same VrfQoS binding (via the SVI), same LAG
# (PortChannel0001), same LACP+fallback shape.
#
# Why default ON (real-HW validation runs pre-commit)
# ---------------------------------------------------
# Per the user's call-out at request time: "default ON immediately"
# -- the operator will run the HW validation in parallel with the
# DUT1-LAG smoke baseline and accept any first-run failures as part
# of the leaf0 class's existing 'real-HW-validated' contract. If
# this becomes flaky on a future FX3 build, flip the default to OFF
# and revert to symmetric DUT1-only LAG via:
#     export VXLAN_LEAF0_EGRESS_SVI_LAG=0
#
# Risk profile (different from DUT1 ingress LAG-wrap)
# ---------------------------------------------------
# The DUT1 LAG-wrap exercises the ENCAP-side DSCP-to-TC classifier
# (which on FX3 is an L3QOS ACL keyed on bd_label/bd_or_vnid -- both
# RIF-derived; LAG-RIF vs port-RIF lookup change is what the DUT1
# wrap's 'risk note' docstring section calls out). DUT2's egress
# port exercises the DECAP-side classifier on the inner header
# after VxLAN strip -- a different code path. Whether the LAG-RIF
# SAI accounting puts queue counters on the LAG or on the physical
# member is platform-dependent on this build, so we explicitly
# rebind dut2_port_info['egress_ixia'] -> PortChannel0001 below
# (the helper does it; the test inherits the new name via
# _smoke_run_one's frame-walk). If FX3 SAI accounts queueing at
# the physical-port level instead, dut2_q_deltas will read zero
# and the smoke will hard-fail on "DUT2 q[N]=0" -- which is the
# loud signal we want, not a silent pass.
#
# Why we don't re-prime Ixia's RX side
# ------------------------------------
# After the wrap, decapped packets exit DUT2 with a Vlan100 tag --
# the Ixia RX port will see tagged frames where it previously saw
# untagged ones. The per-frame validator in _smoke_run_one does NOT
# hard-assert RX VLAN presence/absence (only DSCP, TTL, VxLAN-strip,
# UDP dport are hard-checked); rx_spec deliberately omits the
# 'vlan' field, leaving the side-by-side dump to render an
# observation-only 'VLAN=100 | VLAN=100' row instead of the prior
# asymmetric '* VLAN=100 | VLAN=-' row. So Ixia-side gateway
# resolution still works unchanged: it only needs the destination
# MAC (which the upstream L3 next-hop rewrite at DUT2's SVI sets
# anyway), and ARP/ND for the egress gateway (20.20.20.1/2001:db8:
# 20::1) succeeds against the SVI just as it did against the
# routed port.
_LEAF0_EGRESS_SVI_LAG     = (
    os.environ.get('VXLAN_LEAF0_EGRESS_SVI_LAG', '1') == '1')
# leaf0.cfg's downlink uses 'PortChannel0001' on both sides of the
# wire; we reuse that name on DUT2 (it's a different box, no
# namespace conflict with DUT1's PortChannel0001).
_LEAF0_LAG_NAME_EGRESS    = 'PortChannel0001'

# ── Wire the qos_helpers.QOS_EGRESS_IXIA_VLAN knob ──────────────────
#
# 2026-05-23 UPDATE (smoke_leaf0_lag_one_IV.log lines 1348-1357):
# the "configure Ixia 1/12 as tagged-Vlan100 host from module-init"
# approach is DEAD. On this IxNet build (11.10.2508.10), the
# `ixiangpf.interface_config` call with `l2_encap='ethernet_ii_vlan',
# vlan='1', vlan_id=100, vlan_id_mode='fixed'` keyword args FAILS
# at module-init time with:
#
#   ERROR TG API Error: Argument: -l2_encap not found in the list
#   of valid arguments
#   COMPLETED: interface_config : FAIL
#
# Both v4 AND v6 host configs fail this way (lines 1349, 1356).
# Net result: Ixia 1/12 has NO L3 host at all -- not tagged, not
# untagged. The deviceGroup is created (line 1346) and a topology
# slot is allocated, but the interface_config that would attach an
# IPv4/IPv6 protocol-stack node to it never succeeds. The previous
# run (results_2026_05_22_18_51_53) saw the SAME args PASS, but
# that was an IxNet session-state quirk we can't depend on.
#
# Why this doesn't matter for the DSCP-to-TC smoke
# ------------------------------------------------
# The actual test traffic flows Ixia 1/9 (TX) -> DUT1 (encap) ->
# DUT2 (decap) -> Ixia 1/12 (RX, capture-only). Ixia 1/12 only
# needs to:
#   1. Have its physical port UP (L1 carrier).
#   2. Run its capture pipeline so the test can read out which
#      hardware queue the received packets landed in.
# It does NOT need an L3 responder, ARP table, or any
# interface_config-installed protocol stack node. The L2 filter
# at the vport level by default accepts whatever the wire delivers
# (the test class's frame_walk reads from the wire, not from a
# protocol-stack receiver).
#
# So the new plan is: leave Ixia 1/12 as its default untagged
# bare-port shape (whatever `tg_interface_config(mode='config',
# ...)` without `l2_encap` produces, which IxNet's NGPF builder
# accepts without complaint). DUT2's egress emits tagged-Vlan100
# frames; Ixia 1/12's vport accepts them at L1; the capture
# pipeline records them. No ARP resolution needed because DUT2's
# kernel has a static neighbour entry for 20.20.20.2 (the
# `_LEAF0_DUT2_STATIC_ARP=1` default, see the constants block
# below). DUT2 -> Ixia ping in the preflight is now INFORMATIONAL
# (expected to fail because there's no Ixia responder); see
# `_smoke_preflight` in test_dscp_to_tc_overlay.py for the
# corresponding hard/soft-check downgrade.
#
# Explicitly clear the env var (regardless of _LEAF0_EGRESS_SVI_LAG)
# so a parent process that pre-exported it doesn't leak through and
# re-trigger the broken tagged-host path. The OLD branch (which set
# the env var when _LEAF0_EGRESS_SVI_LAG=1) is preserved in git
# history; revert this whole block if a future IxNet build fixes
# `l2_encap` handling on the NGPF path.
os.environ.pop('QOS_EGRESS_IXIA_VLAN', None)


# ── Ixia-side single-member static LAG (cosmetic, opt-in) ──────────
#
# Why is this here at all
# -----------------------
# leaf0.cfg models the server-facing access link as a PortChannel on
# *both* sides of the wire (DUT + server). When we wrap the DUT-side
# ingress in PortChannel0001 (above), the IxNetwork view of the wire
# still shows the Ixia port as a bare physical 1/1/9 -- which is
# *functionally* fine (static LAGs run no LACP, so wire frames are
# plain ethernet either way), but **visually** asymmetric vs the
# leaf0 reference shape. This block lets the operator opt into a
# single-member static LAG topology object on the Ixia side too,
# so the IxNetwork GUI shows the same pretty "LAG <-> LAG" pair the
# leaf0 wire diagram does.
#
# Why double-gated (this AND _LEAF0_LAG_INGRESS must both be set)
# ---------------------------------------------------------------
# Wrapping the Ixia port in a LAG without also wrapping the DUT side
# is *worse* than the bare physical config: it changes the
# tg_ph['ingress'] handle that every downstream stream/capture call
# uses, which is a real risk surface, in exchange for zero visible
# value (the wire is still single-port -> single-port). So this
# only fires when the DUT-side wrap is also active.
#
# Why default off
# ---------------
# Two compounding risks:
#   (a) The HLTAPI keyword for static-mode LAG is unverified in our
#       tree -- the only tg_emulation_lag_config precedent is
#       cisco/tortuga/vxlan with protocol_type='lag_port_lacp'.
#       The static-mode keyword *should* be 'lag_port_static' per
#       Ixia HLT-lib convention, but we have not been able to
#       confirm that from inside the sandbox. If the IxNetwork
#       backend rejects the call, the entire stream-build path
#       breaks -- which is why the wrap helper returns
#       (None, None) on any failure and the caller falls back to
#       the physical handle (logged loudly so the operator
#       knows the cosmetic wrap did not take effect).
#   (b) After the wrap succeeds the port_handle changes, so every
#       downstream tg_*_config call has to use the new handle.
#       If even one site is missed, that one stream silently
#       targets the bare physical port and the "LAG" view is a
#       lie. We mitigate by swapping tg_ph['ingress'] (the
#       canonical handle dict the helpers read) at the integration
#       site, but if a future contributor adds a stream that
#       reaches around tg_ph and uses raw_ph or a hardcoded
#       string, the wrap-vs-no-wrap difference will silently bite.
# Net: cosmetic value, real risk -- env-gated, default off, runs
# only when explicitly opted in.
_LEAF0_IXIA_LAG_INGRESS  = (
    os.environ.get('VXLAN_LEAF0_IXIA_LAG', '0') == '1')
_LEAF0_IXIA_LAG_NAME     = 'IxiaLAG-Eth1_49'  # cosmetic IxNet name

# ── Egress-side Ixia-LAG wrap + UNCONDITIONAL tagged re-prime ──────────
#
# DUT2-side analog of the ingress _LEAF0_IXIA_LAG_INGRESS knob, BUT with
# a critical asymmetry to the ingress posture:
#
#   * The egress *cosmetic* LAG-wrap is gated by VXLAN_LEAF0_IXIA_LAG_EGRESS
#     (default ON). This is the optional "make IxNet GUI show LAG-to-LAG
#     on the egress side too" behaviour that mirrors the ingress
#     _LEAF0_IXIA_LAG_INGRESS knob's intent.
#
#   * The TAGGED IP/GATEWAY re-prime on Ixia 1/12 is UNCONDITIONAL whenever
#     _LEAF0_EGRESS_SVI_LAG=1 is in effect (i.e. when DUT2's Ethernet1_49
#     has been migrated to a Vlan{_L2_VLAN_ID} tagged-SVI inside the
#     egress LAG). This is NOT optional: once DUT2 expects tagged frames
#     on Vlan100 and emits tagged ARP-requests on the same VLAN, Ixia
#     1/12 MUST be re-configured to send/receive tagged frames on that
#     same VLAN, otherwise DUT2 can never ARP-resolve the next-hop MAC
#     (20.20.20.2 in V4, 2001:db8:20::2 in V6) and every decap'd test
#     packet is silently dropped at DUT2's L3 lookup. The smoking-gun
#     symptom is the smoke_leaf0_lag_one_IV.log "DUT2 q[5]=0 while DUT1
#     q[5]=5" + preflight ping "Destination Host Unreachable from
#     20.20.20.1" combination.
#
# Default ON because the egress side genuinely *needs* the tagged
# re-prime (the cosmetic LAG is the "while we're already touching Ixia
# 1/12 anyway, might as well finish the symmetry" addition). The
# ingress _LEAF0_IXIA_LAG_INGRESS knob defaulted to OFF because the
# ingress re-prime wasn't needed (the original DUT1 ingress was already
# a tagged-SVI from the very first L3VNI-tagged test, so Ixia 1/9 was
# correctly tagged from module-init).
#
# Default flipped to OFF after smoke_leaf0_lag_one_IV.log demonstrated
# that the underlying _wrap_ixia_ingress_in_lag helper -- which had
# been sitting behind the opt-in VXLAN_LEAF0_IXIA_LAG knob and never
# previously exercised by any run on this Ixia build -- has TWO latent
# bugs that turn into a session-killing TGen abort on first execution:
#
#   1. It passes ``protocol_type='lag_port_static'`` but this IxNet
#      HLTAPI build only accepts ``lag_port_lacp`` or
#      ``lag_port_staticlag`` (note: no underscore between "static"
#      and "lag"). The Ixia error path raises ``HLAPI error,Argument:
#      protocol_type cannot be set a value of lag_port_static``.
#
#   2. The Ixia error is wrapped by spytest's tgapi shim as a
#      ``TG API Fatal Abort`` -- a session-killing exception that
#      bypasses the helper's ``try/except Exception`` (it's a special
#      tgapi-layer exception, not a regular HLTAPI library exception).
#      Result: the whole test class is SKIPPED with
#      ``Report(TGenFail):Traffic generator abort``.
#
# Until those two bugs are fixed in _wrap_ixia_ingress_in_lag itself,
# the cosmetic IxNet topology-LAG wrap stays OPT-IN on both sides
# (ingress: VXLAN_LEAF0_IXIA_LAG=0; egress: VXLAN_LEAF0_IXIA_LAG_EGRESS=0)
# so the dataplane fix (Step 8b's unconditional tagged re-prime, which
# is the part that genuinely matters for ARP/ND to resolve through
# Ixia 1/12 onto the new Vlan100 SVI) keeps working without the
# cosmetic wrap risking a session abort.
#
# The Ixia-side wire shape is FULLY SYMMETRIC to DUT1's even with the
# wrap off: both Ixia 1/9 and Ixia 1/12 carry tagged Vlan100 frames
# as classic-HLT routed hosts. The only asymmetry the GUI shows is
# vport:1 (physical) vs the never-rendered vport:4-inside-LAG view
# we tried to construct -- a cosmetic-only delta that does not affect
# any test verdict.
_LEAF0_IXIA_LAG_EGRESS      = (
    os.environ.get('VXLAN_LEAF0_IXIA_LAG_EGRESS', '0') == '1')
_LEAF0_IXIA_LAG_NAME_EGRESS = 'IxiaLAG-Eth1_49-EG'  # cosmetic IxNet name

# ── DUT2-side Ixia 1/12 tagged re-prime (Step 8b/8c) opt-in ──────────
# Default OFF on 2026-05-23 after smoke_leaf0_lag_one_V.log diagnostic
# chain showed this code path is BROKEN on the current IxNet HLTAPI
# build:
#
#   * The pre-step `tg_interface_config(mode='destroy', port_handle=
#     <ph-with-NGPF-host>)` raises ``KeyError: 'handle'`` because
#     classic-HLT bookkeeping has no 'handle' for a port whose prior
#     host was configured via NGPF (`protocol_handle=...`) -- and the
#     module-init `setup_topo` for both Ixia 1/9 and Ixia 1/12 uses
#     NGPF, not classic-HLT (see lines 481 and 505 of the above log).
#
#   * The follow-up `tg_interface_config(mode='config', port_handle=
#     <ph>, intf_ip_addr=..., l2_encap='ethernet_ii_vlan', vlan='1',
#     vlan_id=100, ...)` then auto-routes through NGPF (because the
#     prior NGPF topology branch is still live on this port), which
#     rejects the classic-HLT-only ``l2_encap``/``vlan``/``vlan_id``
#     kwargs with ``Argument: -l2_encap not found in the list of
#     valid arguments``.
#
#   * Net effect: the tagged-host re-prime never lands; Step 8 spends
#     ~20 s producing two scary-looking errors per AF in the log; no
#     useful state change happens.
#
# Crucially, none of this is needed in the first place: the DUT1 side
# (the working reference) does NOT tag-flip Ixia 1/9's emulated host
# after DUT1 migrates to tagged-Vlan100. The DUT1-side helper
# `_smoke_reprime_ixia_interface` (test_dscp_to_tc_overlay.py:1573)
# just re-pokes the EXISTING UNTAGGED host with
# `mode='modify', arp_send_req=1, resolve_gateway_mac=1` -- a best-
# effort ARP-retry that has nothing to do with VLAN tagging. The
# DUT1 path "works" because the test traffic stream's
# ``mac_dst=<DUT1-LAG-MAC>`` hardcode bypasses the need for Ixia 1/9
# to ever successfully ARP DUT1's tagged SVI.
#
# So the new default for DUT2 is "mirror DUT1": leave the untagged
# host alone (Step 8b/8c off), do a DUT1-style ARP re-poke (Step 8z,
# always on, lower-cost), and let any future Ixia 1/12 TX stream
# handle MAC-destination concerns the same way DUT1's TX stream does
# (via its own ``mac_dst`` hardcode in tg_traffic_config).
#
# Set VXLAN_LEAF0_IXIA_TAG_FLIP=1 to re-enable Step 8b/8c on a future
# IxNet build that has either fixed the NGPF/classic-HLT auto-routing
# bug above or supports a native "tag-flip on existing host" verb.
#
# 2026-05-23 UPDATE: a better fix has landed -- the smoke now wires
# the qos_helpers.QOS_EGRESS_IXIA_VLAN knob (see the os.environ block
# above next to _LEAF0_EGRESS_SVI_LAG) so Ixia 1/12 is configured as
# a TAGGED-Vlan100 classic-HLT host FROM SECOND ZERO (before NGPF
# claims the port). This avoids the entire "auto-routed-through-NGPF"
# trap that broke Step 8b/8c/8d. With QOS_EGRESS_IXIA_VLAN=100 in
# effect, Step 8b/8c/8d is now functionally NEEDLESS (Ixia 1/12 is
# already in the right shape), and Step 8z's ARP re-poke is still
# cheap-and-harmless so it stays. _LEAF0_IXIA_TAG_FLIP is now purely
# forensic: flipping it on with the new mechanism in place would do
# a redundant tag-flip on an already-tagged host, which would fail
# the same way it does today and serves no useful purpose.
_LEAF0_IXIA_TAG_FLIP        = (
    os.environ.get('VXLAN_LEAF0_IXIA_TAG_FLIP', '0') == '1')

# ── DUT2 kernel static-ARP for Ixia 1/12 (Step 9) opt-in ─────────────
# Default OFF on 2026-05-23. Earlier in the same investigation session
# we briefly implemented a Step 9 that installed a static IPv4/IPv6
# neighbour entry on DUT2's Vlan100 SVI in VrfQoS pointing
# `ixia_egress_ip -> <canonical-egress-role-MAC>`, gated on the caller
# passing ``ixia_egress_mac=IXIA_SRC_MAC['egress']``. The intent was
# to bypass the broken DUT2->Ixia 1/12 dynamic ARP path the way DUT1
# bypasses its broken Ixia->DUT1 ARP path (via stream-level mac_dst
# hardcode).
#
# That was wrong for two reasons (caught in this same session before
# merging anywhere except this branch):
#
#   (1) The mirror is mechanically wrong. DUT1's mac_dst hardcode
#       lives on the IXIA SIDE (stream config); the DUT2 analogue
#       must also live on the Ixia side (in a future TX stream from
#       Ixia 1/12), NOT on the DUT side. Putting it on the DUT kernel
#       only fixes today's DUT2->Ixia direction; it would actively
#       BREAK a future Ixia 1/12->DUT2 TX flow because the static
#       neighbour entry wouldn't teach Ixia 1/12 anything, and Ixia
#       still couldn't resolve DUT2's Vlan100 SVI MAC for its own
#       outgoing frames.
#
#   (2) Static neighbours don't refresh on link-flap / SVI rebind, so
#       any future test that toggles the SVI VRF binding (e.g. a
#       follow-up VrfQoS rename or a teardown/redo in a session-scope
#       fixture) would leave a stale neighbour cached for ARP_TIMEOUT
#       seconds (~60s on FX3), masking real reachability bugs.
#
# Kept behind a knob (off by default) for forensic re-runnability:
# if a future debugging session wants to confirm "would the test
# work if DUT2 ARP magically had the right answer?" they can flip
# VXLAN_LEAF0_DUT2_STATIC_ARP=1 once and verify the answer.
# Production runs should always leave this off.
#
# 2026-05-23 UPDATE: Ixia 1/12 cannot be configured as a tagged L3
# host on the current IxNet HLTAPI build (the `l2_encap` arg fails
# silently with "Argument: -l2_encap not found", so the tagged-
# Vlan100 attempt collapses to "no L3 host at all"). Because we
# have no L3 responder on Ixia 1/12, DUT2's dynamic ARP for the
# nominal Ixia gateway IP will always time out, and DUT2->Ixia
# pings will always fail. That has no effect on the actual test
# traffic path (DUT1 hard-codes the destination MAC in the smoke
# stream, see _smoke_build_traffic_stream in
# test_dscp_to_tc_overlay.py, and Ixia 1/12 is used only as a
# packet capture port), but it DOES break the DUT2-kernel ARP
# resolution for the egress next-hop MAC. The static neighbour
# install in Step 9 is therefore the proper egress-side fix in
# this topology, not a workaround. Default is ON.
#
# IMPORTANT: the install is GATED in Step 9 -- if VXLAN tunnel
# setup or BGP-EVPN session is not healthy, the static neighbour
# is NOT installed (we'd just be masking a real upstream bug).
# Per project policy we never touch VXLAN config at runtime in
# this overlay helper; the static neighbour operates purely on
# the kernel L2 plane (`ip neigh add` on Vlan100 in VrfQoS) and
# does not violate that policy.
#
# Set VXLAN_LEAF0_DUT2_STATIC_ARP=0 to opt out and exercise the
# dynamic ARP path (forensic / debug only -- expected to fail
# until Ixia 1/12 can be wired as a tagged L3 host).
_LEAF0_DUT2_STATIC_ARP      = (
    os.environ.get('VXLAN_LEAF0_DUT2_STATIC_ARP', '1') == '1')


# ──────────────────────────────────────────────────────────────────
# VXLAN_LEAF0_PDB_BEFORE_BURST=0|1   (default: 0 -- OFF)
# ------------------------------------------------------------------
# Interactive forensic knob. When set to 1, drop into pdb in the
# leaf0 test JUST BEFORE _smoke_run_one fires the 5-packet burst
# (after all BEFORE snapshots have been taken). Used to manually
# poke DUT2 from a second shell while the BEFORE state is frozen --
# e.g. run `dchal_qi.py Ethernet1_49`, `show queue counters
# Ethernet1_49 / PortChannel0001`, `sonic-db-cli COUNTERS_DB
# HGETALL COUNTERS:<oid>`, etc. -- then `c` to continue and watch
# how the same counters move after the burst.
#
# Only fires for the leaf0 class. Default OFF so CI runs don't hang
# at the breakpoint.
#
# Example:
#   export VXLAN_LEAF0_PDB_BEFORE_BURST=1
#   pytest -s ...test_dscp_to_tc_portchannel_smoke_leaf0.py::TestSmokeL3VNIPortChannelLeaf0 \
#          -k "tc5-dscp46-ipv4"
#
# Inside pdb, useful commands:
#   p test_label, af, dscp, expected_tc
#   p dut, dut2
#   p port_info, dut2_port_info
#   !import os; print(os.popen(
#       'ssh admin@<dut2-mgmt> "sudo docker exec syncd python3 '
#       '/tmp/dchal_qi.py Ethernet1_49"').read())
#   c            # continue -> fires burst -> snap_after -> verdict
#
# IMPORTANT: -s flag is required to keep stdin attached to pytest;
# otherwise the breakpoint will fire but you can't type into it.
_LEAF0_PDB_BEFORE_BURST     = (
    os.environ.get('VXLAN_LEAF0_PDB_BEFORE_BURST', '0') == '1')


# ══════════════════════════════════════════════════════════════════
# LAG-wrap helper (single-member LACP w/ fallback, opt-in)
# ══════════════════════════════════════════════════════════════════

def _wrap_l3vni_ingress_in_lag(dut_h, physical_port, lag_name, vlan_id):
    """Wrap an existing tagged-SVI ingress port in a single-member
    LACP PortChannel **with LACP fallback enabled**.

    Why LACP-with-fallback rather than static (and the trail of pain)
    -----------------------------------------------------------------
    Earlier revisions of this helper tried two simpler shapes; both
    failed on the FX3 build under test. Documenting the trail here so
    nobody flips back without understanding why.

      v1: static LAG via the click branch
          ``create_portchannel(static=True)`` -- click branch's
          ``--static=true`` flag is gated on
          ``st.is_feature_supported("config_static_portchannel")``,
          which is False on this FX3 build, so the flag is silently
          dropped (apis/switching/portchannel.py:106-109). The LAG
          comes up in default LACP mode. With no LACP partner on the
          Ixia side, member port ``Ethernet1_49`` stays in
          LACP_DEFAULTED state and never joins the active bundle ->
          0 RX (the original run masked this as XPASS via the
          now-removed _VXLAN_DECAP_QOS_BUG xfail marker; in the
          current code it would surface as a hard failure).
          See smoke_leaf0_lag_one.log (first variant) for the
          full forensic trail.

      v2: static LAG via the klish branch
          ``create_portchannel(static=True, cli_type='klish')`` --
          klish branch *does* unconditionally emit ``mode on``
          (apis/switching/portchannel.py:140-141), so it would have
          worked... except the FX3 build does not advertise klish
          UI support at all. spytest aborts the entire module setup
          with ``Report(Unsupported): UI 'klish' unsupported`` BEFORE
          create_portchannel sends a single CLI to the box. Worse,
          this happens AFTER our step-1 ``vlan member del`` already
          executed, so the testbed is left in a half-state with the
          physical port no longer in Vlan100 and no recovery.
          See smoke_leaf0_lag_one.log (second variant) lines
          2024-2030 for the failure trace.

      v3 (this version): default LACP + fallback enabled
          ``create_portchannel(fallback=True)`` -- the click branch's
          fallback path (apis/switching/portchannel.py:113-119)
          emits ``--fallback=true`` unconditionally, with no feature-
          flag gate. With fallback enabled, the SONiC LACP daemon
          (teamd) will admit the only member port to the active
          bundle after the LACP receive timeout (~3s short-timeout)
          if no partner LACPDUs arrive. The Ixia side stays as a
          plain physical port (or, if VXLAN_LEAF0_IXIA_LAG=1, a
          static LAG topology object that emits no LACPDUs) and
          the wire converges anyway via fallback.

    Why this DEVIATES from leaf0.cfg's exact CLI shape
    --------------------------------------------------
    The leaf0 reference (cisco/tortuga/solution/validated_configs/
    base_l3vni/l3vni_leaf0.cfg, also visible in any 4x4-tortuga
    fabric run log e.g. results_2026_05_20_18_39_31) uses BARE
    default-LACP -- no flags at all:

        sudo config portchannel add PortChannel1
        sudo config portchannel member add PortChannel1 Ethernet1_2

    That works in the Tortuga fabric because the same setup ALSO
    drives full IxNetwork NGPF LACP plumbing on the Ixia side
    (cisco/tortuga/vxlan/vxlan_utils.py:330-403's
    config_lag_interface() does
    ``tg_emulation_lag_config(protocol_type='lag_port_lacp')``
    plus tg_topology_config / tg_interface_config /
    tg_test_control(start_protocol)). With a real LACP partner
    on the wire, the DUT's LAG converges normally and fallback
    is never needed.

    Our 2-DUT FX3 testbed has NO Ixia-side LACP plumbing today
    (qos_helpers.py:setup_topo_common just calls
    ``tg_interface_config(mode='config', intf_ip_addr=..,
    gateway=.., arp_send_req=1)``). Without an LACP partner,
    a bare-LACP DUT LAG would sit in LACP_DEFAULTED indefinitely
    -> 0 RX -> the silent-drop trap (already burned us twice
    with the static-mode attempts -- see v1/v2 above).

    Adding full Ixia NGPF LACP plumbing would be a separate
    larger workstream: the 5-call NGPF chain, plus NGPF protocol
    stacks claim ownership of src_mac_addr / intf_ip_addr fields
    that _smoke_run_one's per-DSCP streams set explicitly, plus
    LACP convergence timing has to interleave correctly with
    _smoke_preflight. None of that adds signal for the
    "DSCP-to-TC classification across a LAG-RIF SVI" question
    this test class actually validates.

    So we use ``fallback=True``: it's a *conservative-equivalent*
    deviation. With a real LACP partner the fallback bit never
    fires and wire behavior is identical to leaf0's bare-LACP;
    without one (our testbed reality), fallback admits the lone
    member and the test still measures the thing it's supposed to
    measure. Verified post-creation via
    ``HGET PORTCHANNEL|<lag>.fallback``, and the LAG-up status
    is double-checked via ``ip link show`` after the convergence
    wait so any silent-drop regression surfaces loudly.

    cisco/tortuga/vxlan/test_lacp_fallback_over_evpn_mh.py:123
    is the in-tree precedent for this exact pattern
    (``portchannel_obj.create_portchannel(... fallback=True)``).

    Pre-conditions (the caller must have run
    ``_overlay._smoke_setup_l3vni_tagged_svi()`` first):
      * Vlan{vlan_id} exists.
      * ``physical_port`` is a tagged member of Vlan{vlan_id}.
      * ``Vlan{vlan_id}`` SVI is bound to _I_VRF and has the
        L3VNI ingress IPs (V4_INGRESS_A_IP / V6_INGRESS_A_IP).
      * ``PORT_QOS_MAP|<physical_port>.dscp_to_tc_map = AZURE`` is
        bound from ``config qos reload`` plus the canonical
        helper's defensive HSET.

    Post-conditions after this helper returns:
      * ``lag_name`` is created with ``--fallback=true`` (LACP-mode,
        will admit the lone member to the bundle even without a
        partner after the LACP rx timeout).
      * ``physical_port`` is the LAG's only member.
      * Vlan{vlan_id} tagged membership has migrated from
        ``physical_port`` to ``lag_name``.
      * Vlan{vlan_id} SVI is unchanged (same IP, same VRF) -- it's
        still the L3 RIF, just now sitting on a LAG instead of
        the underlying physical port.
      * ``PORT_QOS_MAP|<lag_name>.dscp_to_tc_map = AZURE`` is
        additionally HSET (idempotent; some FX3 builds need the
        LAG-level binding, some inherit from members; we set
        both so the test does not depend on which behavior the
        target build implements).
      * The helper has waited 10s after the final config push to
        give teamd's LACP rx timer time to fire its fallback.

    Returns a teardown callable that fully reverses every step that
    actually executed -- crucially, even if the helper aborts mid-
    sequence (any st.config raise, create_portchannel returning
    False, etc.), the returned teardown will still undo every
    destructive step that DID complete. This is what protects the
    testbed from being left in the half-state that bit us in
    smoke_leaf0_lag_one.log v2 line 2025-2030.

    Order matters
    -------------
    SONiC rejects attaching/detaching VLAN membership against a LAG
    that has no members, and rejects adding a member to a LAG that
    is already in a VLAN on some builds. We therefore use the
    sequence: ``vlan member del port`` -> create LAG (empty) ->
    ``portchannel member add port`` -> ``vlan member add LAG``.
    Teardown is the strict reverse: ``vlan member del LAG`` ->
    ``portchannel member del port`` -> ``portchannel del LAG`` ->
    ``vlan member add port``. The trailing re-attach to the
    physical port is what lets the canonical SVI teardown find
    Vlan{vlan_id} membership where it expects it.

    Risk note (read this before adding more wrap variants)
    -------------------------------------------------------
    The DSCP-to-TC classifier on FX3 is implemented as an L3QOS
    ACL keyed on bd_label / bd_or_vnid; both are RIF-derived. A
    LAG RIF is not the same RIF as the underlying physical port,
    so the ACL programming may shift. Whether it still HITS at
    traffic time is what phase 1e validates with a TCAM dump.
    Do not add a second wrap variant (L2VNI / Ethernet1_50) until
    phase 1e has confirmed the L3VNI variant programs and hits.
    """
    from apis.switching.portchannel import (
        create_portchannel, add_portchannel_member,
        delete_portchannel_member, delete_portchannel,
    )

    st.log("  leaf0 LAG-wrap: migrating L3VNI ingress {} -> {} "
           "(LACP w/ fallback, single-member, Vlan{} tagged-"
           "membership follows)".format(physical_port, lag_name,
                                        vlan_id))

    # Build the teardown closure as a list of registered cleanup
    # steps that grows as we make destructive changes. Each step
    # appends its undo callable here as soon as the destructive
    # call succeeds, so the returned teardown undoes EXACTLY what
    # was actually done -- no more, no less. If the helper aborts
    # mid-sequence (raise OR False return from create_portchannel
    # OR add_portchannel_member), the partial teardown still runs
    # cleanly and the box is restored to a self-consistent state.
    cleanup_steps = []

    def _teardown():
        st.log("  leaf0 LAG-wrap teardown: unwrapping (steps to "
               "undo: {})".format(len(cleanup_steps)))
        # Walk the registered undos in *reverse* order -- LIFO is
        # the safe ordering for nested config (undo the most-
        # recent change first).
        for step_label, step_fn in reversed(cleanup_steps):
            try:
                step_fn()
            except Exception as exc:
                st.warn("leaf0 LAG-wrap teardown: step '{}' raised: "
                        "{} (continuing with remaining undos)"
                        .format(step_label, exc))
        st.log("  leaf0 LAG-wrap teardown: done")

    # 1. Detach the physical port from Vlan{vid}. The SVI keeps its
    #    IP -- it is the L3 RIF, not the L2 port we are migrating.
    st.config(dut_h,
        'config vlan member del {} {}'.format(vlan_id, physical_port),
        skip_error_check=True)
    st.wait(1)
    # Register the undo for step 1 IMMEDIATELY -- if anything below
    # fails, we MUST be able to put the physical port back in
    # Vlan{vid} so the canonical SVI teardown's
    # `config vlan member del <vid> <physical_port>` lines up with
    # the actual config. This is the line that smoke_leaf0_lag_one.
    # log v2 was missing -- when create_portchannel aborted on
    # klish-unsupported, this undo never registered, and Vlan100
    # stayed detached from Ethernet1_49 with no recovery.
    cleanup_steps.append(('vlan member add {} {}'.format(vlan_id, physical_port),
        lambda: st.config(dut_h,
            'config vlan member add {} {}'.format(vlan_id, physical_port),
            skip_error_check=True)))

    # 2. Create the LAG with LACP fallback. We pass fallback=True
    #    and DO NOT pass static=True (mutex with fallback per
    #    apis/switching/portchannel.py:56-58). cli_type is left at
    #    its default -- the click branch's fallback path emits
    #    ``--fallback=true`` unconditionally with no feature-flag
    #    gate (apis/switching/portchannel.py:113-119), so the
    #    silent-flag-drop trap from v1 does not apply here.
    #
    # If create_portchannel returns False, the LAG was not created;
    # we still register the undo (delete_portchannel) defensively
    # because some failure modes (transient API timeout, partial
    # config push) leave a half-created LAG behind that needs to
    # be deleted. The delete is idempotent on a non-existent LAG
    # (skip_error=True).
    pc_ok = create_portchannel(dut_h, [lag_name], fallback=True)
    cleanup_steps.append(('delete_portchannel({})'.format(lag_name),
        lambda: delete_portchannel(dut_h, [lag_name], skip_error=True)))
    if not pc_ok:
        st.error("leaf0 LAG-wrap: create_portchannel({}, fallback=True) "
                 "returned False -- aborting wrap and executing teardown"
                 .format(lag_name))
        _teardown()
        raise RuntimeError("LAG-wrap setup failed: create_portchannel "
                           "returned False for {}".format(lag_name))
    st.wait(2)

    # 2b. Verify the LAG came up with fallback enabled (CONFIG_DB
    #     ``fallback`` field == 'true'). Without fallback, a default
    #     LACP LAG with no partner on the wire would silently drop
    #     every frame -- exactly the trap we are trying to avoid.
    fb_check = st.show(dut_h,
        'sonic-db-cli CONFIG_DB HGET "PORTCHANNEL|{}" "fallback"'
        .format(lag_name),
        skip_tmpl=True) or ''
    if 'true' not in fb_check.lower():
        st.error("leaf0 LAG-wrap: CONFIG_DB|PORTCHANNEL|{}.fallback "
                 "is NOT 'true' (got: {!r}). The LAG is in default "
                 "LACP mode without fallback; with no Ixia-side LACP "
                 "partner, member port will stay in LACP_DEFAULTED "
                 "state and traffic will be silently dropped. "
                 "Executing teardown."
                 .format(lag_name, fb_check.strip()))
        _teardown()
        raise RuntimeError("LAG-wrap setup failed: fallback not enabled "
                           "on {}".format(lag_name))
    st.log("  leaf0 LAG-wrap: confirmed CONFIG_DB|PORTCHANNEL|"
           "{}.fallback = true (LAG will admit lone member after "
           "LACP rx timeout)".format(lag_name))

    # 3. Bind the physical port as the (only) LAG member. Once
    #    fallback fires (~3s after carrier-up with no partner),
    #    teamd admits Ethernet1_49 to the active bundle.
    if not add_portchannel_member(dut_h, lag_name, [physical_port]):
        st.error("leaf0 LAG-wrap: add_portchannel_member({}, [{}]) "
                 "returned False -- aborting wrap and executing teardown"
                 .format(lag_name, physical_port))
        _teardown()
        raise RuntimeError("LAG-wrap setup failed: add_portchannel_member "
                           "returned False for {} member {}"
                           .format(lag_name, physical_port))
    cleanup_steps.append(('delete_portchannel_member({}, [{}])'.format(
            lag_name, physical_port),
        lambda: delete_portchannel_member(
            dut_h, lag_name, [physical_port])))
    st.wait(1)

    # 4. Re-attach Vlan{vid} tagged membership to the LAG. From
    #    here the SVI sits on the LAG; the physical port carries
    #    tagged frames as a LAG member, which is what we want.
    st.config(dut_h,
        'config vlan member add {} {}'.format(vlan_id, lag_name),
        skip_error_check=True)
    cleanup_steps.append(('vlan member del {} {}'.format(vlan_id, lag_name),
        lambda: st.config(dut_h,
            'config vlan member del {} {}'.format(vlan_id, lag_name),
            skip_error_check=True)))

    # 5. Defensively HSET the LAG-level dscp_to_tc_map binding. This
    #    is additive: the physical-port binding from `config qos
    #    reload` stays in place, so on builds where the LAG-level
    #    HSET is a no-op the data plane still sees the right map
    #    via the member port. Idempotent on teardown.
    st.config(dut_h,
        'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" '
        '"dscp_to_tc_map" "AZURE"'.format(lag_name),
        skip_error_check=True)
    cleanup_steps.append(('HDEL PORT_QOS_MAP|{}'.format(lag_name),
        lambda: st.config(dut_h,
            'sonic-db-cli CONFIG_DB HDEL "PORT_QOS_MAP|{}" '
            '"dscp_to_tc_map"'.format(lag_name),
            skip_error_check=True)))

    # 6. Wait for LACP fallback convergence. SONiC's teamd uses the
    #    LACP rx machine's Short Timeout (3s) for fallback decisions
    #    -- after 3s of no partner PDUs on the only member port,
    #    fallback admits the member to the bundle. We sleep 10s for
    #    a comfortable margin (covers Short Timeout + orchagent
    #    settle + ARP/ND prime). Without this wait, downstream
    #    tg_traffic_run() would fire frames before the bundle is
    #    active and we'd see 0 RX with no obvious cause.
    st.wait(10)

    # 7. Post-check: confirm the LAG kernel netdev is actually UP.
    #    This is a READ-ONLY check (no destructive side-effects, so
    #    no cleanup_step registration needed). It exists because
    #    silent-drop traps in this code path have a long history
    #    (see "trail of pain" docstring above). We want to know
    #    LOUDLY at setup time -- not implicitly via 0-RX in
    #    _smoke_run_one -- whether fallback actually fired.
    #
    # `ip link show` output for a healthy, fallback-converged LAG:
    #   <BROADCAST,MULTICAST,UP,LOWER_UP> ... state UP ...
    #
    # The two distinct flags both must be present:
    #   * UP            : admin status (set by step 2's
    #                     create_portchannel + the implicit
    #                     `no shutdown` SONiC does on add)
    #   * LOWER_UP      : carrier sense (set by teamd once the
    #                     bundle has at least one COLLECTING/
    #                     DISTRIBUTING member -- this is the bit
    #                     fallback flips when it admits the
    #                     lone member after Short Timeout)
    # Missing LOWER_UP after the 10s wait => fallback did NOT
    # fire and downstream traffic will silently drop.
    link_check = st.show(dut_h,
        'ip link show {} 2>&1 | head -2'.format(lag_name),
        skip_tmpl=True) or ''
    if 'LOWER_UP' in link_check and 'state UP' in link_check:
        st.log("  leaf0 LAG-wrap: LAG is UP+LOWER_UP after fallback "
               "wait -- bundle is active, ready to forward")
    else:
        # Loud warn (not error) -- the test continues so the
        # operator gets the full diagnostic context. If traffic
        # also fails downstream, this warn is the root-cause
        # signal that points at LACP/fallback rather than at the
        # DSCP-to-TC classifier under test. We pull teamdctl
        # state for further forensics; the helper carries on
        # rather than aborting because this is a diagnostic
        # post-check, not a guarantee.
        st.warn("leaf0 LAG-wrap: LAG {} is NOT fully up after the "
                "10s LACP-fallback wait. ip link snippet: {!r}. "
                "Most likely fallback did not fire (teamd config "
                "drift, member port carrier issue, or LACP rx "
                "timer not actually firing). Downstream traffic "
                "will probably show 0 RX. Test continues so the "
                "diagnostic context survives in the run log."
                .format(lag_name, link_check.strip()))
        # Best-effort teamdctl probe for forensic context. The
        # bond name format on SONiC is the lag_name verbatim
        # (no PortChannel/teamd prefix translation). Tolerated
        # to fail (skip_tmpl=True; not all FX3 builds package
        # teamdctl in admin's PATH).
        try:
            tc_state = st.show(dut_h,
                'sudo teamdctl {} state 2>&1 | head -40'.format(lag_name),
                skip_tmpl=True) or ''
            if tc_state.strip():
                st.warn("leaf0 LAG-wrap: teamdctl {} state -- {}"
                        .format(lag_name, tc_state.strip()))
        except Exception:
            pass

    # 8. Cross-check: confirm the SONiC application-layer view of
    #    the bundle agrees with the kernel view from step 7.
    #    `ip link show` covers the kernel netdev / team driver layer;
    #    `show interfaces portchannel` covers the SONiC orchagent +
    #    teammgrd + portchannel-application layer. Both must agree
    #    for traffic to actually traverse the LAG: the kernel can
    #    say UP+LOWER_UP while orchagent has not yet bound the LAG
    #    into the bridge / VLAN / RIF stack (transient race during
    #    config changes). Catching this disagreement at setup time
    #    is much cheaper than triaging "0 RX" downstream.
    #
    # Expected output for a healthy, fallback-converged single-
    # member LAG (one row, columns abbreviated):
    #   0001  PortChannel0001  LACP(A)(Up)  Ethernet1_49(S)
    # Decoded:
    #   * `LACP(A)(Up)` -- protocol=LACP, role=Active, BUNDLE state=Up
    #   * `Ethernet1_49(S)` -- member, status=Selected
    # Bad signals to flag:
    #   * `LACP(A)(Dw)` -- bundle Down (no member selected, fallback
    #                     did not fire OR no member at all)
    #   * member shown as `(D)`/`(R)`/missing -- member not in the
    #     active distribution set, frames will not be forwarded
    #
    # We dump the FULL `show interfaces portchannel` output (no
    # `| grep`) so the run log preserves three pieces of context
    # that grep would strip:
    #   * the column header row (Team Dev, Protocol, Ports), which
    #     makes the dumped row self-explanatory at read time,
    #   * the "Flags:" legend (A/I/Up/Dw/N/A/S/D/*) -- handy when
    #     decoding less-common states like `(D)` or `*`,
    #   * any other PortChannelN that exists on the DUT. In the
    #     leaf0 context there should be exactly one (PortChannel0001),
    #     and an unexpected second row is itself a useful signal
    #     (e.g. stale config from a prior failed teardown).
    # The narrower per-row parse below still keys off the LAG name
    # substring, so dumping more context does NOT loosen the check.
    # Read-only (no cleanup_step needed). Best-effort: if the CLI
    # is missing/broken on a future SONiC refactor we want to
    # continue with a soft warn rather than aborting setup.
    try:
        pc_show = st.show(dut_h,
            'show interfaces portchannel',
            skip_tmpl=True, skip_error_check=True) or ''
        pc_show_stripped = pc_show.strip()
        # Log the entire output verbatim so future log readers see
        # the header + legend + every PortChannel row, not just our
        # one-line verdict. Indented to align with surrounding
        # leaf0 LAG-wrap step messages.
        if pc_show_stripped:
            st.log("  leaf0 LAG-wrap: 'show interfaces portchannel' "
                   "(full output, {} expected as the only row):"
                   .format(lag_name))
            for raw_line in pc_show_stripped.splitlines():
                st.log("    {}".format(raw_line.rstrip()))
        # Pull out just our LAG's row for the verdict check below.
        # We match by whole-word lag_name so a substring like
        # 'PortChannel0001' inside another row's text (unlikely but
        # cheap to defend against) does not confuse us.
        lag_rows = [
            ln for ln in pc_show.splitlines()
            if ' {} '.format(lag_name) in ' {} '.format(ln)
        ]
        lag_row = lag_rows[0].strip() if lag_rows else ''
        if 'LACP(A)(Up)' in lag_row and '{}(S)'.format(physical_port) in lag_row:
            st.log("  leaf0 LAG-wrap: SONiC portchannel view confirms "
                   "bundle Up + member Selected -- {}"
                   .format(lag_row))
        elif 'LACP(A)(Dw)' in lag_row or '(Dw)' in lag_row:
            # Bundle reports Down at the SONiC layer even though
            # the kernel said UP+LOWER_UP -- this is the disagreement
            # case the cross-check exists to catch.
            st.warn("leaf0 LAG-wrap: SONiC portchannel view says LAG "
                    "{} bundle is DOWN (kernel said UP+LOWER_UP). "
                    "This disagreement usually means orchagent has "
                    "not yet propagated the bundle state into "
                    "APPL_DB:LAG_TABLE -- typically a 1-3s race. If "
                    "the run is still failing after this point, "
                    "extend the post-create st.wait(). LAG row: "
                    "{!r}".format(lag_name, lag_row))
        elif not lag_row:
            # Our specific LAG was not found in the table (header/
            # legend may still be present). This is much worse than
            # a Down state -- it suggests orchagent/teammgrd never
            # bound the LAG into APPL_DB.
            st.warn("leaf0 LAG-wrap: 'show interfaces portchannel' "
                    "did not list LAG {} -- the bundle is not "
                    "visible to the SONiC application layer despite "
                    "the kernel reporting UP+LOWER_UP. Likely "
                    "orchagent / teammgrd binding failure."
                    .format(lag_name))
        else:
            # Found our LAG row but neither (Up)+(S) nor (Dw): some
            # unexpected state we want to surface verbatim.
            st.warn("leaf0 LAG-wrap: SONiC portchannel view for {} "
                    "returned an unexpected row: {!r} (was looking "
                    "for 'LACP(A)(Up)' + '{}(S)' or 'LACP(A)(Dw)')"
                    .format(lag_name, lag_row, physical_port))
    except Exception as exc:
        st.warn("leaf0 LAG-wrap: 'show interfaces portchannel' "
                "raised: {} (continuing -- this is a diagnostic "
                "cross-check, not a fixture guarantee)".format(exc))

    # 9. L3-path verification dump.
    #
    # Steps 7+8 confirmed the LAG itself is up at the kernel and
    # SONiC-application layers respectively, but neither answers
    # the question "is the LAG actually wired into the L3 path
    # the test expects to exercise?". In leaf0-style our L3 RIF
    # is the Vlan{vlan_id} SVI in VRF _I_VRF, so the LAG is
    # correctly L3-bound IFF three things hold simultaneously:
    #
    #   (a) `show vlan brief` lists {lag_name} as a TAGGED member
    #       of Vlan{vlan_id}. This is the L2->L3 binding -- without
    #       it, frames coming in on the LAG never reach the SVI's
    #       IP stack.
    #   (b) `show ip interfaces` still shows Vlan{vlan_id} with
    #       its original IP and in the right VRF. This is the
    #       sanity check that VLAN-membership churn during the
    #       wrap (vlan member del Eth -> add LAG) didn't
    #       inadvertently bounce the SVI's IP/VRF binding.
    #   (c) `ip addr show {lag_name}` shows NO IPv4/IPv6 -- the
    #       LAG itself is L2-only by design (it's a Vlan member,
    #       not a routed interface). A non-empty inet/inet6 line
    #       here would mean something accidentally L3'd the LAG,
    #       which would conflict with the SVI for ARP/ND/RIF
    #       ownership.
    #
    # All three are READ-ONLY (no cleanup_step needed). All three
    # are best-effort: any of them raising is logged as a soft
    # warn and we carry on -- the goal is forensic context, not
    # a setup-time hard gate. We dump verbatim (no grep/awk)
    # so the run log preserves headers, VRF columns, and any
    # other rows that might be diagnostic later.
    try:
        vlan_brief = st.show(dut_h, 'show vlan brief',
                             skip_tmpl=True, skip_error_check=True) or ''
        if vlan_brief.strip():
            st.log("  leaf0 LAG-wrap: 'show vlan brief' (full output, "
                   "expect Vlan{} row to list {} as tagged member):"
                   .format(vlan_id, lag_name))
            for raw_line in vlan_brief.strip().splitlines():
                st.log("    {}".format(raw_line.rstrip()))
    except Exception as exc:
        st.warn("leaf0 LAG-wrap: 'show vlan brief' raised: {} "
                "(continuing -- diagnostic dump only)".format(exc))

    try:
        # `show ip interfaces` is the canonical CLI on this FX3
        # build (see vxlan_helper.py:2419 for the same form). It
        # prints IPv4 only -- if we wanted IPv6 SVIs we'd also
        # call `show ipv6 interfaces`. For the leaf0 smoke the
        # underlay/overlay v4 RIF is the diagnostic that matters.
        ip_int = st.show(dut_h, 'show ip interfaces',
                         skip_tmpl=True, skip_error_check=True) or ''
        if ip_int.strip():
            st.log("  leaf0 LAG-wrap: 'show ip interfaces' (full "
                   "output, expect Vlan{} in VRF {}):"
                   .format(vlan_id, _I_VRF))
            for raw_line in ip_int.strip().splitlines():
                st.log("    {}".format(raw_line.rstrip()))
    except Exception as exc:
        st.warn("leaf0 LAG-wrap: 'show ip interfaces' raised: {} "
                "(continuing -- diagnostic dump only)".format(exc))

    try:
        # `ip addr show <lag>` is the kernel netdev view -- a
        # successful return with NO inet/inet6 line is the healthy
        # case for our L2-trunk LAG. We dump verbatim and leave
        # interpretation to the operator; we do NOT auto-flag a
        # non-empty inet line because there are valid future
        # variants (e.g. an IPv6 link-local on the LAG itself for
        # router solicitation) where it's expected.
        lag_addr = st.show(dut_h,
                           'ip addr show {}'.format(lag_name),
                           skip_tmpl=True, skip_error_check=True) or ''
        if lag_addr.strip():
            st.log("  leaf0 LAG-wrap: 'ip addr show {}' (full "
                   "kernel-netdev view, expect NO inet/inet6 line "
                   "-- LAG is L2-only by design):".format(lag_name))
            for raw_line in lag_addr.strip().splitlines():
                st.log("    {}".format(raw_line.rstrip()))
    except Exception as exc:
        st.warn("leaf0 LAG-wrap: 'ip addr show {}' raised: {} "
                "(continuing -- diagnostic dump only)"
                .format(lag_name, exc))

    st.log("  leaf0 LAG-wrap: done -- {} now backs Vlan{} "
           "tagged-SVI ingress (member: {}, LACP fallback active)"
           .format(lag_name, vlan_id, physical_port))

    return _teardown


# ══════════════════════════════════════════════════════════════════
# Ixia-side LAG-wrap helper (single-member static, opt-in, cosmetic)
# ══════════════════════════════════════════════════════════════════

def _wrap_ixia_ingress_in_lag(tg_obj, physical_ph, lag_name):
    """Optionally wrap the Ixia ingress port_handle in a single-member
    static LAG topology object so the IxNetwork view matches a
    "LAG <-> LAG" wire shape (cosmetic; wire frames are unchanged).

    Parameters
    ----------
    tg_obj : spytest.tgen.tg.TGIxia
        The traffic-generator handle (typically the module-level ``tg``).
    physical_ph : str
        The bare physical port_handle (e.g. ``'1/1/9'``) that the
        canonical setup_topo gave us for the L3VNI ingress.
    lag_name : str
        Cosmetic LAG name displayed in IxNetwork (e.g. ``'IxiaLAG-Eth1_49'``).

    Returns
    -------
    (lag_port_handle, teardown) tuple
      * On success: ``lag_port_handle`` is the new port_handle that
        downstream tg_*_config calls should use (mirrors the Tortuga
        pattern at vxlan_utils.py:402, ``"1/1/" + lag_handle.split(":")[-1]``).
        ``teardown`` is a zero-arg callable that deletes the LAG.
      * On any failure: returns ``(None, None)`` and logs a clear
        warning. The caller MUST treat this as "Ixia LAG wrap not
        applied; keep using the physical handle" and continue;
        because the DUT-side LAG runs LACP-with-fallback (it admits
        its lone member to the active bundle after the LACP rx
        Short Timeout regardless of partner activity), the dataplane
        works fine with an asymmetric (DUT-LAG <-> Ixia-bare)
        topology -- only the GUI representation differs.

    Why so much defensive plumbing
    ------------------------------
    1. The HLTAPI keyword for static-mode aggregation is unverified
       in our tree -- the only existing tg_emulation_lag_config
       precedent uses ``protocol_type='lag_port_lacp'``. By Ixia
       HLT-lib convention the static keyword is ``'lag_port_static'``,
       which is what we pass below. If the backend rejects it, we
       want a graceful fallback, not a fixture crash.
    2. The IxNetwork API can reject the call with status='0' (returned
       in a dict, not raised), or it can raise an actual exception
       (network blip, tcl proc not loaded, etc.). We catch both.
    3. Even if the create succeeds, ``tg_topology_config`` and the
       protocol-stack apply chain can fail downstream; we treat any
       step's failure as "abort the wrap, fall back to physical".
       Partial success would leave a dangling LAG in IxNetwork that
       interferes with the next test run, so we explicitly call
       ``mode='delete'`` on the LAG before returning the (None, None)
       fallback.

    What the wrap actually does on success
    --------------------------------------
    It mirrors the Tortuga LAG-creation sequence (vxlan_utils.py:330-403)
    in single-member, static-LAG, no-NGPF-protocol-stack form:
      step (a)  Convert physical_ph -> vport_handle.
      step (b)  ``tg_emulation_lag_config(mode='create',
                  protocol_type='lag_port_static', ...)``.
      step (c)  Derive the new port_handle from the LAG handle
                (Tortuga's ``"1/1/<id>"`` convention) and return it.

    Step (c) is the key piece: from the spytest abstraction layer's
    perspective, the LAG behaves *exactly* like a port handle. All
    downstream ``tg_traffic_config`` / ``tg_packet_stats`` calls just
    pass the new handle and IxNetwork transparently forwards through
    the LAG's single member port (1/1/9 in our case).
    """
    # Step (a): convert the physical port_handle to a vport. Errors
    # here mean the physical port itself is unhealthy, which is
    # already a bigger problem than this wrap can paper over -- but
    # we still want to fail soft (log + return None) rather than
    # crash the fixture.
    try:
        vport_status = tg_obj.tg_convert_porthandle_to_vport(
            port_handle=physical_ph)
    except Exception as exc:
        st.warn("leaf0 Ixia-LAG wrap: tg_convert_porthandle_to_vport"
                "({}) raised: {} -- falling back to physical handle"
                .format(physical_ph, exc))
        return (None, None)

    if not isinstance(vport_status, dict) or 'handle' not in vport_status:
        st.warn("leaf0 Ixia-LAG wrap: tg_convert_porthandle_to_vport"
                "({}) returned unexpected payload {!r} -- falling back"
                .format(physical_ph, vport_status))
        return (None, None)

    vport_handle = vport_status['handle'].split('-')[-1]
    # IxNetwork wants the vport list as a Tcl-style braced set.
    lag_vport_list = '{' + vport_handle + '}'

    # Step (b): create the static LAG. The Tortuga precedent uses
    # ``protocol_type='lag_port_lacp'``; per Ixia HLT-lib convention
    # the static-mode keyword is ``'lag_port_static'``. Wrapped in a
    # broad try/except because IxNetwork's HLTAPI is known to either
    # raise *or* return status='0' depending on the failure class.
    st.log("  leaf0 Ixia-LAG wrap: attempting create LAG '{}' on "
           "vport {} (physical_ph={}, mode=static)"
           .format(lag_name, vport_handle, physical_ph))
    try:
        lag_result = tg_obj.tg_emulation_lag_config(
            mode='create',
            port_handle=lag_vport_list,
            active='1',
            lag_name=lag_name,
            protocol_type='lag_port_static',
        )
    except Exception as exc:
        st.warn("leaf0 Ixia-LAG wrap: tg_emulation_lag_config(create, "
                "static, {}) raised: {} -- falling back to physical "
                "handle. The DUT-side LACP+fallback LAG still works "
                "without this (fallback admits the lone member after "
                "LACP rx Short Timeout regardless of partner state); "
                "only the IxNetwork GUI will show the wire as "
                "1/1/9 -> PortChannel0001 (asymmetric) instead of the "
                "fully-symmetric LAG-to-LAG view."
                .format(lag_name, exc))
        return (None, None)

    if (not isinstance(lag_result, dict)
            or lag_result.get('status', '0') != '1'
            or 'lag_handle' not in lag_result):
        st.warn("leaf0 Ixia-LAG wrap: tg_emulation_lag_config(create, "
                "static, {}) returned non-success payload {!r} -- "
                "falling back to physical handle. Most likely cause: "
                "the IxNetwork HLTAPI on this backend does not accept "
                "protocol_type='lag_port_static' (only 'lag_port_lacp' "
                "is exercised elsewhere in this tree). The DUT-side "
                "LACP+fallback LAG still works without this wrap."
                .format(lag_name, lag_result))
        # Best-effort cleanup in case the call partially succeeded
        # before reporting failure (an empty LAG in IxNetwork would
        # interfere with the next test run).
        try:
            tg_obj.tg_emulation_lag_config(
                mode='delete', lag_name=lag_name)
        except Exception:
            pass
        return (None, None)

    lag_handle = lag_result['lag_handle']
    # Step (c): derive the spytest-style port_handle. Tortuga
    # convention (vxlan_utils.py:402): the LAG handle is "::ixn::lag:N"
    # and the corresponding port_handle that downstream tg_*_config
    # calls accept is "1/1/N". The "1/1/" prefix matches IxNetwork's
    # internal numbering scheme (chassis 1, card 1) which is the
    # only chassis/card layout this testbed uses.
    try:
        lag_port_handle = '1/1/' + lag_handle.split(':')[-1]
    except Exception as exc:
        st.warn("leaf0 Ixia-LAG wrap: could not derive port_handle "
                "from lag_handle {!r} ({}) -- falling back to "
                "physical handle".format(lag_handle, exc))
        try:
            tg_obj.tg_emulation_lag_config(
                mode='delete', lag_name=lag_name)
        except Exception:
            pass
        return (None, None)

    st.log("  leaf0 Ixia-LAG wrap: success -- LAG '{}' created "
           "(lag_handle={}, new port_handle={}). All downstream "
           "tg_*_config calls will target the LAG instead of the "
           "bare physical port."
           .format(lag_name, lag_handle, lag_port_handle))

    def _teardown():
        st.log("  leaf0 Ixia-LAG teardown: deleting LAG '{}'"
               .format(lag_name))
        try:
            del_result = tg_obj.tg_emulation_lag_config(
                mode='delete', lag_name=lag_name)
            if (isinstance(del_result, dict)
                    and del_result.get('status', '0') != '1'):
                st.warn("leaf0 Ixia-LAG teardown: lag-delete returned "
                        "non-success {!r} (continuing; LAG may need "
                        "manual cleanup in IxNetwork)"
                        .format(del_result))
        except Exception as exc:
            st.warn("leaf0 Ixia-LAG teardown: lag-delete raised: {} "
                    "(LAG may need manual cleanup in IxNetwork)"
                    .format(exc))

    return (lag_port_handle, _teardown)


# ══════════════════════════════════════════════════════════════════
# DUT2 egress SVI helper (leaf0-only, mirrors DUT1 SVI on decap side)
# ══════════════════════════════════════════════════════════════════

def _setup_egress_svi_dut2(dut2_h, egress_intf, vlan_id, vrf,
                           v4_ip, v6_ip,
                           tg=None, tg_obj=None,
                           tg_ph_dict_ref=None,
                           ixia_egress_ip=None, ixia_egress_ip6=None,
                           ixia_egress_gw_v4=None,
                           ixia_egress_gw_v6=None,
                           ixia_wrap_in_lag=False,
                           ixia_lag_name=None,
                           ixia_egress_mac=None):
    """Migrate DUT2's egress-to-Ixia port from routed-port-in-VRF to
    tagged-SVI-in-VRF, mirroring the DUT1-side stack that
    ``_smoke_setup_l3vni_tagged_svi`` produces.

    Optional Step 8 (Ixia re-prime + cosmetic LAG-wrap)
    ---------------------------------------------------
    When the caller passes the Ixia-side kwargs (``tg``, ``tg_obj``,
    ``tg_ph_dict_ref``, ``ixia_egress_ip``), this helper additionally:

      * Optionally wraps the Ixia egress port in a single-member static
        IxNet LAG (gated on ``ixia_wrap_in_lag``; cosmetic-only for
        symmetric GUI view). On success the new LAG port_handle is used
        as the target for the re-prime; the caller's
        ``tg_ph_dict_ref['egress']`` and ``_overlay.tg_ph['egress']``
        are also swapped to the LAG handle so downstream
        ``_smoke_run_one`` reads counters/captures on the LAG port.

      * UNCONDITIONALLY re-primes the (LAG-or-physical) Ixia port with
        a tagged Vlan{vlan_id} v4 + v6 emulated host whose
        ``intf_ip_addr`` / ``ipv6_intf_addr`` match the IP-of-record
        Ixia originally owned (20.20.20.2 / 2001:db8:20::2). Without
        this re-prime, DUT2's tagged ARP-requests on Vlan{vlan_id} are
        dropped at Ixia's vport L2 filter, ARP never resolves, and
        every decap'd test packet is dropped at DUT2's L3 lookup --
        the smoke_leaf0_lag_one_IV.log "DUT2 q[N]=0 while DUT1 q[N]=5"
        + preflight "Destination Host Unreachable from 20.20.20.1"
        failure mode.

    The teardown reverses Step 8 in strict LIFO order (destroy Ixia
    tagged host config, optionally delete the LAG, restore
    ``tg_ph['egress']``) BEFORE the DUT2-side unwind, then continues
    with the DUT2-side reversal as before.

    Optional Step 9 (deterministic DUT2->Ixia ARP shortcut)
    ------------------------------------------------------
    When the caller passes ``ixia_egress_mac=<known-MAC>``, this helper
    additionally:

      * Pins ``src_mac_addr=<known-MAC>`` on the Step 8 Ixia tagged
        emulated host config so Ixia 1/12 announces a deterministic
        source MAC on the wire (instead of whatever Ixia port-default
        MAC the protocol engine would otherwise use).

      * Installs a static IPv4 ARP entry on DUT2's Vlan{vlan_id} SVI
        in ``vrf`` mapping ``ixia_egress_ip`` -> ``ixia_egress_mac``,
        via `sudo ip vrf exec <vrf> ip neigh add <ip> lladdr <mac>
        dev <svi> nud permanent`. (Best-effort IPv6 too if
        ``ixia_egress_ip6`` was supplied.)

    This is the DUT2-side mirror of the DUT1-side ``mac_dst=<DUT1-LAG-
    MAC>`` hard-code in the test traffic streams (test_dscp_to_tc_
    overlay.py:_traffic_run_one). Both sides bypass the broken
    Ixia<->DUT ARP path -- DUT1's encap traffic doesn't need Ixia 1/9
    to know DUT1's MAC (test hard-codes it as mac_dst), and now DUT2's
    decap egress doesn't need to ARP Ixia 1/12 (this helper hard-codes
    it as a static neighbor entry). Symmetric workaround for the same
    class of problem (Ixia HLTAPI re-prime can't reliably tag-flip an
    NGPF-configured port on this build).

    Step 9 is gated only on ``ixia_egress_mac`` being non-None. If the
    caller omits it, Step 9 is silently skipped and the helper reverts
    to relying on dynamic ARP (the smoke_leaf0_lag_one_IV/V symptom).

    Important caveat: Step 9 does NOT help if the SAI VXLAN tunnel
    object for the remote VTEP is missing on DUT2 -- the decap'd
    packets won't even reach the L3 lookup stage that would consult
    the static ARP entry. The 2c preflight gate in
    test_dscp_to_tc_overlay.py catches that case independently. Step 9
    is the closing piece *given* a healthy SAI tunnel.

    This is the DUT2 analogue of the canonical DUT1 helper. The
    sequence is identical (remove IPs from physical, unbind VRF,
    create Vlan, tag-member, bind SVI to VRF, re-add IPs on SVI,
    defensive PORT_QOS_MAP HSET on the physical port). The only
    differences are:
      * dut2_h, egress_intf, v4_ip, v6_ip parameters instead of
        the DUT1 helper's module-global reads.
      * Configures DUT2 (decap-egress side) instead of DUT1
        (encap-ingress side).
      * The L3 lookup that follows traffic ingress here is the
        decap-side route to the directly-connected Ixia host,
        not the encap-side route into the L3VNI overlay.

    Why we keep PORT_QOS_MAP on the physical port (not on the SVI)
    --------------------------------------------------------------
    Same reason as the DUT1 helper: the FX3 DSCP-to-TC classifier
    is implemented as an L3QOS ACL keyed on bd_label/bd_or_vnid
    (both RIF-derived). On this platform the binding is honoured
    when programmed on the PHYSICAL-PORT entry of PORT_QOS_MAP;
    earlier experiments (DUT1 side, smoke_one_tag.log 2026-05-15)
    showed that moving the binding to the SVI silently broke
    classification ('all packets to Q0'). The egress-side DSCP-to-
    TC classification is the WHOLE POINT of the dut2_q_deltas
    readback in _smoke_run_one, so we MUST get this right.

    Pre-conditions: caller has already invoked _setup_vxlan_l3vni()
    so DUT2's egress port is bound to ``vrf`` with v4_ip / v6_ip,
    and the DSCP-to-TC map is bound on the physical port (from
    setup_topo_common's `config qos reload`).

    Post-conditions:
      * Vlan{vlan_id} exists on dut2.
      * egress_intf is a TAGGED member of Vlan{vlan_id}.
      * Vlan{vlan_id} SVI is bound to ``vrf`` and carries v4_ip /
        v6_ip (the same IPs that used to live on the physical port,
        so Ixia gateway resolution keeps working unchanged).
      * PORT_QOS_MAP|egress_intf.dscp_to_tc_map = AZURE (re-asserted
        defensively; idempotent if it was already AZURE).

    Returns a teardown callable that reverses every step in strict
    LIFO order. Each st.config uses skip_error_check=True so a
    half-applied state can still be cleaned up.

    Order matters
    -------------
    The order below ('remove physical IPs -> unbind VRF -> add Vlan
    -> add member -> bind SVI VRF -> add SVI IPs') is the same
    order the DUT1 helper uses and the same order the live FX3 build
    has been observed to accept. SONiC rejects vrf-binding a port
    while it still has IPs in another VRF, and rejects adding a port
    to a Vlan while the SVI for that Vlan is in a VRF with no
    members yet -- so we hold the VRF-bind for the SVI until *after*
    the tagged-member-add lands.
    """
    if not dut2_h or not egress_intf:
        st.log("  _setup_egress_svi_dut2: no DUT2 egress -- skipping "
               "(caller decides whether to skip the test)")
        return lambda: None

    svi_intf = 'Vlan{}'.format(vlan_id)

    st.log("  _setup_egress_svi_dut2: migrating egress {} from routed-"
           "port-in-{} to tagged-SVI-{}-in-{}"
           .format(egress_intf, vrf, svi_intf, vrf))

    # 1. Remove L3 IPs from the physical port (they were added inside
    #    `vrf` by _setup_vxlan_l3vni; we need to free them before the
    #    VRF unbind in step 2).
    st.config(dut2_h,
        'config interface ip remove {} {}'.format(egress_intf, v4_ip),
        skip_error_check=True)
    st.config(dut2_h,
        'config interface ip remove {} {}'.format(egress_intf, v6_ip),
        skip_error_check=True)
    st.wait(1)

    # 2. Take the physical port out of `vrf` (back to default VRF).
    #    The SVI will own the VRF binding from this point on.
    st.config(dut2_h,
        'config interface vrf unbind {}'.format(egress_intf),
        skip_error_check=True)
    st.wait(1)

    # 3. Create the access VLAN on DUT2 (idempotent).
    #
    # Same FX3 startup-config consideration as the DUT1 ingress
    # helper: ``Vlan100`` is present from boot on this testbed
    # (see fx3_qos_vxlan_testbed_breakout.yaml's target device
    # baseline + ``show vlan brief`` at module-init time). Pre-
    # check with a read-only ``show vlan brief | grep`` so the
    # run log stays clean; keep ``skip_error_check=True`` on the
    # actual add as a safety net for fixture-race / stale-output
    # cases.
    _vlan_check = st.show(dut2_h,
        'show vlan brief | grep -E "\\| *{} "'.format(vlan_id),
        skip_tmpl=True, skip_error_check=True) or ''
    if 'Vlan{}'.format(vlan_id) in _vlan_check \
            or '| {} '.format(vlan_id) in _vlan_check:
        st.log("  _setup_egress_svi_dut2: Vlan{} already present "
               "(likely from device startup config); skipping "
               "'config vlan add' to avoid noisy WARN"
               .format(vlan_id))
    else:
        st.config(dut2_h,
            'config vlan add {}'.format(vlan_id),
            skip_error_check=True)
    st.wait(1)

    # 4. Add the physical port as a TAGGED member (no --untagged flag).
    st.config(dut2_h,
        'config vlan member add {} {}'.format(vlan_id, egress_intf),
        skip_error_check=True)
    st.wait(1)

    # 5. Bind the SVI to `vrf`. After this the SVI is the L3 RIF for
    #    the decap'd traffic going out to Ixia.
    st.config(dut2_h,
        'config interface vrf bind {} {}'.format(svi_intf, vrf),
        skip_error_check=True)
    st.wait(1)

    # 6. Re-add the same V4/V6 IPs on the SVI so Ixia's gateway
    #    config (intf_ip_addr=IXIA_EGRESS_IP, gateway=20.20.20.1)
    #    keeps working unchanged -- we keep the IP-of-record stable
    #    across the routed-port-in-VRF / SVI-in-VRF variants.
    st.config(dut2_h,
        'config interface ip add {} {}'.format(svi_intf, v4_ip),
        skip_error_check=True)
    st.config(dut2_h,
        'config interface ip add {} {}'.format(svi_intf, v6_ip),
        skip_error_check=True)
    st.wait(2)

    # 7. Defensive re-assert: ensure PORT_QOS_MAP|<egress>.dscp_to_tc_map
    #    is still AZURE. setup_topo_common runs `config qos reload`
    #    once at module init, but the rebind churn above can leave the
    #    binding in an inconsistent state on some builds. HSET is
    #    idempotent. Whether to additionally HSET the LAG-level
    #    binding is deferred to the LAG-wrap helper (step 5 there).
    st.config(dut2_h,
        'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" '
        '"dscp_to_tc_map" "AZURE"'.format(egress_intf),
        skip_error_check=True)
    st.wait(5)  # orchagent + intfmgrd need a beat to wire up the SVI

    st.log("  _setup_egress_svi_dut2: done -- {} is now a tagged "
           "member of {}; SVI {} carries {} / {} in {}"
           .format(egress_intf, svi_intf, svi_intf, v4_ip, v6_ip, vrf))

    # ── Step 8 (optional): Re-prime Ixia egress for the new tagged SVI ──
    #
    # DUT2 just migrated egress_intf from a routed port (untagged) to a
    # Vlan{vlan_id} SVI inside the egress LAG. From this point on DUT2
    # will:
    #   * ACCEPT only tagged frames on Vlan{vlan_id}
    #   * EMIT tagged ARP/ND requests on Vlan{vlan_id} when resolving
    #     next-hops
    #
    # Ixia 1/12 was configured at module-init time as an untagged routed
    # host (intf_ip_addr=20.20.20.2, gateway=20.20.20.1). Without this
    # re-prime, every ARP-request DUT2 sends would be dropped at Ixia's
    # vport L2 filter, every ND-solicit would be dropped the same way,
    # and every decap'd test packet would be dropped at DUT2's egress
    # L3 lookup ("Destination Host Unreachable from 20.20.20.1"). The
    # 5/5 DUT1 ingress -> 0/0 DUT2 egress symptom in
    # smoke_leaf0_lag_one_IV.log is precisely this failure mode.
    #
    # Optional sub-step: also wrap Ixia 1/12 in a single-member static
    # IxNet LAG so the GUI view matches the DUT side (cosmetic only --
    # the dataplane works either way once the tagged re-prime is done).
    #
    # All this state is captured by closure into the _teardown function
    # below so reversal happens in strict LIFO order BEFORE the DUT2-
    # side unwind starts.
    # State referenced by both Step 8 (below) and _teardown (defined
    # after Step 8) is initialised here so the teardown closure can
    # safely close over it even when Step 8 raises mid-execution
    # (e.g. a TG-API-Fatal-Abort from tg_interface_config). The
    # actual crash-resilience comes from the CALLER (see the
    # try/except around ``teardown_egress_svi = _setup_egress_svi_
    # dut2(...)`` in _setup_leaf0_style_overlay): on Step 8 failure
    # the caller catches, synthesises a DUT2-side-only teardown
    # closure that runs the same reversal as our own _teardown but
    # without the Ixia-side LIFO step (since Step 8 left no
    # successfully-registered Ixia state), and registers that
    # synthetic teardown so the class fixture can still unwind the
    # DUT2 PortChannel0001 + Vlan100 + SVI on its way out.
    ixia_teardown_fns = []   # LIFO stack of cleanup callables
    target_ph = tg_ph_dict_ref.get('egress') \
        if isinstance(tg_ph_dict_ref, dict) else None
    saved_egress_ph = target_ph
    ixia_reprime_active = False
    ixia_tier_used = None
    if (tg is not None and tg_ph_dict_ref is not None
            and ixia_egress_ip is not None
            and 'egress' in tg_ph_dict_ref):

        # 8a. Optionally wrap Ixia 1/12 in a single-member IxNet LAG.
        # Mirrors the ingress _wrap_ixia_ingress_in_lag pattern; the
        # helper returns (new_ph, teardown) or (None, None). On
        # success we use the LAG handle as the re-prime target; on
        # failure we fall back to the bare physical handle (dataplane
        # works either way -- the LAG is cosmetic for the IxNet GUI).
        if not ixia_wrap_in_lag:
            st.log("  _setup_egress_svi_dut2: Step 8a SKIPPED -- "
                   "VXLAN_LEAF0_IXIA_LAG_EGRESS not set; Ixia egress "
                   "stays on physical port_handle={}. Wire shape is "
                   "still fully symmetric to DUT1 (DUT1 Ixia 1/9 also "
                   "stays on its physical handle by default). Tagged "
                   "re-prime in Step 8b/c still applies."
                   .format(target_ph))
        if ixia_wrap_in_lag and tg_obj is not None and ixia_lag_name:
            st.log("  _setup_egress_svi_dut2: Step 8a -- wrapping Ixia "
                   "egress port_handle={} in single-member static IxNet "
                   "LAG '{}' for symmetric GUI view"
                   .format(target_ph, ixia_lag_name))
            lag_ph, td_lag = _wrap_ixia_ingress_in_lag(
                tg_obj=tg_obj, physical_ph=target_ph,
                lag_name=ixia_lag_name)
            if lag_ph is not None:
                # Swap the tg_ph dict so downstream _smoke_run_one's
                # `egress_ph = tg_ph['egress']` reads the LAG handle.
                # Write to BOTH the caller-supplied dict AND _overlay's
                # globals (mirrors the ingress LAG-wrap publish pattern
                # at the integration site so frame-walking helpers find
                # the LAG handle by name lookup).
                tg_ph_dict_ref['egress'] = lag_ph
                try:
                    _overlay.tg_ph['egress'] = lag_ph
                except Exception as exc:
                    st.warn("  _setup_egress_svi_dut2: could not "
                            "publish egress LAG handle into _overlay."
                            "tg_ph: {} (downstream helpers reading "
                            "from _overlay's namespace may keep using "
                            "the physical handle)".format(exc))
                target_ph = lag_ph
                ixia_teardown_fns.append(('ixia-lag-wrap', td_lag))
                st.log("  _setup_egress_svi_dut2: Step 8a OK -- "
                       "tg_ph['egress'] swapped from {} to {}; re-prime "
                       "will target the LAG handle"
                       .format(saved_egress_ph, lag_ph))
            else:
                st.log("  _setup_egress_svi_dut2: Step 8a SKIPPED -- "
                       "Ixia egress LAG-wrap helper returned None "
                       "(see preceding warn for root cause); re-prime "
                       "will target the bare physical handle {} "
                       "instead. Dataplane works either way; only the "
                       "IxNet GUI view differs.".format(target_ph))

        # 8b. Tagged v4 re-prime. Adapted from
        # vxlan_helper.py:1004 (L2VNI receiver classic-HLT tier) which
        # is the only existing tagged-Ixia-host precedent in the tree.
        #
        # IMPORTANT pre-step: destroy any prior NGPF/classic emulated
        # host on this port_handle BEFORE the tagged re-config.
        # Without the destroy, IxNet treats our tagged ``mode='config'``
        # as "create a new sibling deviceGroup under the same topology"
        # (we observed ``/topology:2/deviceGroup:3`` being injected
        # automatically in smoke_leaf0_lag_one_V.log), which makes the
        # backend validate the call under NGPF semantics where
        # ``vlan`` is a Bool kwarg unrelated to L2 tagging --
        # producing the TG-API-Fatal-Abort "Argument vlan cannot be
        # set a value of 'enable'" we hit on the first run. The
        # destroy collapses the prior NGPF deviceGroup(s) on this
        # port so the next ``mode='config'`` is interpreted as the
        # classic-HLT tagged host config we actually want.
        #
        # ── GATE on VXLAN_LEAF0_IXIA_TAG_FLIP (default OFF) ──────────
        # See _LEAF0_IXIA_TAG_FLIP in the constants block for the full
        # trail. tl;dr: this code path has two independent failure
        # modes on the current IxNet HLTAPI build (NGPF KeyError on
        # destroy + NGPF auto-routing rejecting classic-HLT kwargs)
        # and ISN'T NEEDED IN THE FIRST PLACE because the DUT1 side
        # doesn't tag-flip Ixia 1/9 either. Step 8z below is the
        # always-on DUT1-mirror replacement.
        if not _LEAF0_IXIA_TAG_FLIP:
            st.log("  _setup_egress_svi_dut2: Step 8b/8c/8d SKIPPED -- "
                   "VXLAN_LEAF0_IXIA_TAG_FLIP not set (default OFF). "
                   "Tagged-host re-prime is disabled because it fails "
                   "on the current IxNet HLTAPI build. DUT1's mirror "
                   "code in test_dscp_to_tc_overlay.py:_smoke_reprime"
                   "_ixia_interface ALSO doesn't tag-flip Ixia 1/9 -- "
                   "it just re-pokes the untagged host's ARP. Step 8z "
                   "below does the same for Ixia 1/12.")
            ixia_tier_used = 'tag-flip-skipped'
            ixia_reprime_active = False
        else:
            st.log("  _setup_egress_svi_dut2: Step 8b -- destroying prior "
                   "(untagged) Ixia host config on port_handle={} before "
                   "tagged re-prime".format(target_ph))
            try:
                tg.tg_interface_config(
                    mode='destroy', port_handle=target_ph)
            except Exception as exc_d:
                # Non-fatal: a destroy on a port with no host config
                # typically raises a benign warning. We log and continue;
                # if the destroy was genuinely needed but failed, the
                # next mode='config' will surface the real error.
                st.log("  _setup_egress_svi_dut2: Step 8b -- destroy on "
                       "port_handle={} raised {}: {} (continuing -- if "
                       "the next config call fails, the destroy is the "
                       "likely culprit)".format(
                           target_ph, type(exc_d).__name__, exc_d))

            st.log("  _setup_egress_svi_dut2: Step 8b -- re-prime Ixia "
                   "egress port_handle={} as TAGGED Vlan{} emulated host "
                   "(v4={}, gw={})"
                   .format(target_ph, vlan_id,
                           ixia_egress_ip, ixia_egress_gw_v4))
            common_v4 = dict(
                mode='config', port_handle=target_ph,
                intf_ip_addr=ixia_egress_ip,
                netmask=NETMASK,
                gateway=ixia_egress_gw_v4,
                arp_send_req=1,
                ipv4_resolve_gateway=1,
                enable_ping_response=1,
                resolve_gateway_mac=1,
            )
            # If the caller supplied a deterministic source MAC for Ixia
            # 1/12 (the egress-LAG-IP-owner), pin it on the emulated host
            # so the WIRE eth_src is the same constant we will later
            # install as a static ARP entry on DUT2 in Step 9 below.
            # Without this pin, Ixia uses the port-default MAC which may
            # differ across IxNet sessions / chassis resets, making the
            # Step 9 static ARP entry stale (and Step 9 the very next time
            # the smoke runs would install a static neighbour for a MAC
            # that no longer matches the new Ixia port-default MAC).
            if ixia_egress_mac:
                common_v4['src_mac_addr'] = ixia_egress_mac
            # NOTE: IxNet HLTAPI on this build wants ``vlan`` as a Bool-
            # coercible string ('1'/'0'), NOT 'enable'/'disable'. Passing
            # 'enable' raises a TG-API-Fatal-Abort -- see the proven
            # precedent at vxlan_helper.py:1004 (the L2VNI receiver
            # classic-HLT tier) which uses the same vlan='1' shape and is
            # the only known-working tagged-Ixia-host config on this
            # build.
            common_v4_tagged = dict(common_v4,
                l2_encap='ethernet_ii_vlan',
                vlan='1',
                vlan_id=int(vlan_id),
                vlan_id_mode='fixed')

            try:
                tg.tg_interface_config(**common_v4_tagged)
                ixia_tier_used = 'classic-HLT-tagged'
                ixia_reprime_active = True
            except Exception as exc_t:
                # Classic-HLT tagged rejected (rare; usually means an older
                # IxNet HLTAPI build that doesn't recognise some kwarg).
                # Try the untagged form as a degraded fallback -- this will
                # NOT respond to DUT2's tagged ARP, but it does at least
                # log the situation loudly so the operator sees it.
                st.warn("  _setup_egress_svi_dut2: classic-HLT tagged v4 "
                        "re-prime FAILED on port_handle={}: {}: {}. "
                        "Trying untagged form as DEGRADED fallback (the "
                        "preflight ping will fail loud if the DUT side is "
                        "tagged -- see the preflight ping FAIL line for "
                        "the operator-actionable error)."
                        .format(target_ph, type(exc_t).__name__, exc_t))
                try:
                    tg.tg_interface_config(**common_v4)
                    ixia_tier_used = 'classic-HLT-UNTAGGED-degraded'
                    ixia_reprime_active = True
                except Exception as exc_u:
                    st.warn("  _setup_egress_svi_dut2: BOTH tagged and "
                            "untagged v4 re-prime FAILED on port_handle={}"
                            ": {}: {}. DUT2 ARP for {} will not resolve; "
                            "decap'd traffic will be dropped at L3 lookup."
                            .format(target_ph, type(exc_u).__name__, exc_u,
                                    ixia_egress_ip))
                    ixia_tier_used = None

            # 8c. v6 in the same tagged shape (best-effort; v4 is the
            # critical path for the DSCP-to-TC smoke).
            if ixia_egress_ip6 is not None and ixia_tier_used is not None:
                common_v6_tagged = dict(
                    mode='config', port_handle=target_ph,
                    ipv6_intf_addr=ixia_egress_ip6,
                    ipv6_prefix_length=PREFIX_LEN_V6,
                    ipv6_gateway=ixia_egress_gw_v6,
                    ipv6_resolve_gateway_mac=1,
                    arp_send_req=1)
                # Same MAC-pinning rationale as the v4 dict above; the v6
                # ND-solicitation will use this src_mac too. Pinning both
                # AFs keeps the Ixia 1/12 host symmetric and the Step 9
                # static neighbour entries on DUT2 valid for both AFs.
                if ixia_egress_mac:
                    common_v6_tagged['src_mac_addr'] = ixia_egress_mac
                if 'tagged' in (ixia_tier_used or '') \
                        and 'UNTAGGED' not in (ixia_tier_used or ''):
                    # Same Bool-coercible-string requirement as v4 above.
                    common_v6_tagged.update(
                        l2_encap='ethernet_ii_vlan',
                        vlan='1',
                        vlan_id=int(vlan_id),
                        vlan_id_mode='fixed')
                try:
                    tg.tg_interface_config(**common_v6_tagged)
                    st.log("  _setup_egress_svi_dut2: Step 8c -- v6 tagged "
                           "re-prime OK (ip6={}, gw6={})"
                           .format(ixia_egress_ip6, ixia_egress_gw_v6))
                except Exception as exc:
                    st.warn("  _setup_egress_svi_dut2: v6 tagged re-prime "
                            "raised {}: {} (non-fatal; v4 path still "
                            "primed so the IPv4 smoke instances will "
                            "still pass)".format(type(exc).__name__, exc))

            # 8d. Kick the protocol engine so the new tagged ARP/ND fires
            # immediately rather than at the next traffic-config call.
            # Best-effort: some IxNet backends don't expose this entry
            # point or return non-success when there's nothing new to
            # start; either is fine because the very next tg_traffic_config
            # call will kick the protocol engine implicitly.
            if ixia_reprime_active:
                try:
                    tg.tg_topology_test_control(action='start_all_protocols')
                except Exception:
                    pass

                # Register the host-config destroy as the FIRST item to
                # undo (last LIFO step pushed = first undone). This is
                # explicitly LIFO-ordered before the LAG-delete teardown
                # registered in step 8a, so on teardown we destroy the
                # tagged host BEFORE deleting the LAG underneath it.
                _td_target_ph = target_ph
                def _td_destroy_host():
                    try:
                        tg.tg_interface_config(
                            mode='destroy', port_handle=_td_target_ph)
                    except Exception as exc:
                        st.warn("  _setup_egress_svi_dut2 teardown: Ixia "
                                "host destroy on port_handle={} raised {}: "
                                "{} (continuing; may need manual cleanup "
                                "in IxNetwork)".format(
                                    _td_target_ph, type(exc).__name__, exc))
                ixia_teardown_fns.append(('ixia-host-destroy', _td_destroy_host))

                st.log("  _setup_egress_svi_dut2: Step 8 complete -- Ixia "
                       "egress re-primed (tier={}, ph={}, tagged vlan={}, "
                       "v4={}, v6={}, lag_wrap={})"
                       .format(ixia_tier_used, target_ph, vlan_id,
                               ixia_egress_ip,
                               ixia_egress_ip6 if ixia_egress_ip6 else 'skipped',
                               target_ph != saved_egress_ph))

        # ── Step 8z: ALWAYS-ON DUT1-mirror ARP re-poke on Ixia 1/12 ──
        # This is the always-on counterpart to the gated Step 8b/8c/8d.
        # It mirrors the DUT1-side helper `_smoke_reprime_ixia_interface`
        # (test_dscp_to_tc_overlay.py) exactly: a single ``mode='modify'``
        # call to re-poke the EXISTING (untagged-at-module-init) NGPF host
        # on this port_handle, plus a ``start_all_protocols`` to make the
        # protocol engine actually retry ARP/ND immediately rather than
        # at the next traffic-config call. Two important properties:
        #
        #   (1) ``mode='modify'`` is the operative verb -- it does NOT
        #       create a new sibling deviceGroup the way the broken
        #       Step 8b ``mode='config'`` does. It just refreshes the
        #       arp_send_req / resolve_gateway_mac flags on the existing
        #       deviceGroup (the one created at module-init line 505 of
        #       the smoke_leaf0_lag_one_V.log -- /topology:2/deviceGroup:1
        #       for Ixia 1/12, mirroring /topology:1/deviceGroup:1 for
        #       Ixia 1/9).
        #
        #   (2) Best-effort: any exception is logged at warn-level and
        #       continues. This step CANNOT make the dataplane work
        #       better than the DUT1 side does (because the underlying
        #       tag-mismatch problem is identical), but it CANNOT
        #       regress anything either -- the worst case is that ARP
        #       still fails and the test relies entirely on the
        #       stream-level ``mac_dst`` hardcode (which is exactly
        #       what DUT1 also does today).
        st.log("  _setup_egress_svi_dut2: Step 8z -- DUT1-mirror ARP "
               "re-poke on Ixia 1/12 port_handle={} (mode=modify, "
               "arp_send_req=1, resolve_gateway_mac=1)".format(target_ph))
        try:
            tg.tg_interface_config(
                mode='modify',
                port_handle=target_ph,
                arp_send_req=1,
                resolve_gateway_mac=1)
            try:
                tg.tg_topology_test_control(action='start_all_protocols')
            except Exception:
                pass
            st.wait(3)
            st.log("  _setup_egress_svi_dut2: Step 8z -- ARP re-poke "
                   "submitted; protocol engine restarted (best-effort)")
        except Exception as exc:
            # Non-fatal: this is the always-on equivalent of DUT1's
            # _smoke_reprime_ixia_interface, and DUT1 tolerates failures
            # here too. The test traffic stream's mac_dst hardcode is
            # the real workaround; this re-poke is just a best-effort
            # attempt at dynamic ARP resolution for any future tests
            # that might want it (e.g. a future preflight ping from
            # Ixia 1/12 toward DUT2's Vlan100 SVI, or a future TX
            # stream that wants Ixia 1/12 to dynamically learn DUT2's
            # MAC instead of hard-coding it).
            st.warn("  _setup_egress_svi_dut2: Step 8z -- ARP re-poke "
                    "on port_handle={} raised {}: {} (non-fatal; "
                    "matches DUT1-side tolerance behavior; test "
                    "traffic uses hardcoded mac_dst anyway)"
                    .format(target_ph, type(exc).__name__, exc))
    else:
        st.log("  _setup_egress_svi_dut2: Step 8 SKIPPED -- caller did "
               "not supply Ixia re-prime kwargs (tg={}, tg_ph_dict_ref={}, "
               "ixia_egress_ip={}). DUT2-side SVI migration is complete "
               "but the Ixia 1/12 vport L2 filter is unchanged; if DUT2 "
               "starts sending tagged ARPs on Vlan{}, they will be "
               "dropped at Ixia and decap'd traffic will be silently "
               "dropped at DUT2's L3 lookup."
               .format(bool(tg), bool(tg_ph_dict_ref),
                       ixia_egress_ip, vlan_id))

    # ── Step 9 (optional): Hard-code DUT2-side ARP for Ixia 1/12 ─────
    #
    # If the caller supplied ``ixia_egress_mac``, install a static
    # IPv4 neighbour entry on DUT2's Vlan{vlan_id} SVI inside ``vrf``
    # pointing ``ixia_egress_ip`` -> ``ixia_egress_mac``. This is the
    # DUT2-side mirror of the DUT1-side ``mac_dst=<DUT1-LAG-MAC>``
    # hard-code in the test traffic streams: both sides pre-populate
    # the L2-resolution answer that the broken Ixia<->DUT ARP path
    # cannot deliver dynamically.
    #
    # Why this is needed (smoke_leaf0_lag_one_V.log diagnostic chain):
    #   DUT2 just migrated its egress port to a tagged Vlan100 SVI in
    #   VrfQoS. When decap'd packets arrive, DUT2 looks up the next-
    #   hop IP (20.20.20.2 = ixia_egress_ip) in VrfQoS, hits the
    #   connected 20.20.20.0/24 route over Vlan100, and emits a
    #   tagged ARP-request on Vlan100. Ixia 1/12 on this build has
    #   trouble accepting tagged ARPs after the NGPF->classic-HLT
    #   re-prime (Step 8 errors `Argument: -l2_encap not found ...`
    #   and `KeyError: handle` -- see this turn's earlier diagnosis).
    #   ARP never resolves -> `Destination Host Unreachable from
    #   20.20.20.1` -> packet dropped at DUT2's L3 forwarding stage
    #   -> DUT2 egress queue counters stay at 0 -> test FAILs.
    #
    # The static neighbour entry pre-populates the answer DUT2 needs,
    # so the decap'd packet's L3 lookup finds a complete next-hop
    # without ever needing to ARP. The ``nud permanent`` flag tells
    # the kernel to never time it out and never re-validate via ARP.
    #
    # Constraints:
    #   * Use ``ip vrf exec <vrf> ip neigh add`` (NOT plain ``ip
    #     neigh add``). The Vlan{vlan_id} SVI lives inside ``vrf``,
    #     so the neighbour table is per-VRF, not global.
    #   * Use ``dev Vlan{vlan_id}`` (the SVI), NOT ``dev
    #     <egress_intf>``. The SVI is what owns the L3 RIF in this
    #     stack; ``egress_intf`` is just an L2 member of Vlan100.
    #   * If the entry already exists (`ip neigh replace` is the
    #     idempotent form), use replace to avoid `RTNETLINK answers:
    #     File exists` noise on re-run. Same idempotent pattern as
    #     the `ip neigh replace` precedent in qos_helpers.py.
    #
    # IPv6 ND: best-effort symmetric add for ``ixia_egress_ip6``.
    # The IPv4 entry is the critical path for the DSCP-to-TC smoke
    # (every IPv4 test instance), so we register the v4-teardown
    # first (LIFO -> undone last) even if the v6 add raises below.
    static_neigh_v4 = None    # tracks what we successfully installed
    static_neigh_v6 = None
    # ── GATE on VXLAN_LEAF0_DUT2_STATIC_ARP (default OFF) ────────────
    # See _LEAF0_DUT2_STATIC_ARP in the constants block for the full
    # rationale. tl;dr: this DUT-kernel-side workaround papers over
    # the DUT2->Ixia ARP failure but breaks a future Ixia 1/12->DUT2
    # TX flow because it doesn't teach Ixia 1/12 anything. The
    # correct symmetric fix is the always-on Step 8z above (DUT1-
    # mirror ARP re-poke on the Ixia side). Kept behind a knob for
    # forensic "would the test pass if DUT2 had the right ARP?" runs.
    if ixia_egress_mac and ixia_egress_ip and not _LEAF0_DUT2_STATIC_ARP:
        st.log("  _setup_egress_svi_dut2: Step 9 SKIPPED -- "
               "VXLAN_LEAF0_DUT2_STATIC_ARP not set (default OFF). "
               "DUT2-side static neighbour install is disabled. ARP "
               "resolution between DUT2's Vlan{} SVI and Ixia 1/12 "
               "will rely on dynamic ARP (which may fail on this "
               "IxNet build due to the tag-mismatch trail described "
               "at _LEAF0_IXIA_TAG_FLIP). The test traffic stream's "
               "mac_dst hardcode (see test_dscp_to_tc_overlay.py:"
               "_smoke_build_traffic_stream) handles the DUT1-side "
               "ARP gap the same way and is the production-correct "
               "mechanism for DUT2 too.".format(vlan_id))
    elif ixia_egress_mac and ixia_egress_ip:
        # ── Step 9 healthy-upstream gate ────────────────────────────
        # Per user direction (2026-05-23): install the static neighbour
        # on DUT2's egress SVI ONLY AFTER we've confirmed that
        #   (a) the VXLAN data plane is up, AND
        #   (b) the BGP-EVPN session to the peer VTEP is Established.
        # If either is broken, installing the static neigh would just
        # mask the real upstream regression -- traffic would still drop
        # at decap (no VXLAN) or never reach DUT2 at all (no EVPN
        # type-5 route exchange), but the operator would chase a red
        # herring on the egress side.
        #
        # The two probes are cheap (~1s each), tolerant of CLI output
        # format drift (we substring-match for unambiguous tokens),
        # and never raise -- on any exception we treat that probe as
        # "did not pass" and skip the install with a clear st.warn.
        def _vxlan_tunnel_present(dut_h):
            try:
                raw = st.show(dut_h, 'show vxlan tunnel',
                              skip_tmpl=True,
                              skip_error_check=True) or ''
            except Exception as exc:
                return False, "show vxlan tunnel raised {}: {}".format(
                    type(exc).__name__, exc)
            # We do NOT inspect the "destination ip" column -- the
            # May-17 known-good run confirmed that column stays blank
            # for EVPN-learned remote VTEPs in this SONiC build. We
            # just want a non-empty row for VTEP_QOS (proves the
            # local VTEP object is created and orchagent has wired
            # at least the source side).
            ok = 'VTEP_QOS' in str(raw)
            return ok, ("VTEP_QOS row {} 'show vxlan tunnel'"
                        .format('present in' if ok else 'NOT present in'))

        def _bgp_evpn_established(dut_h):
            # CRITICAL: route through `vtysh -c '...'`, NOT through
            # SONiC's outer `show bgp ...` click wrapper. The SONiC
            # wrapper does not know about FRR's `l2vpn` keyword and
            # returns:
            #     Error: No such command "l2vpn".
            # (See smoke_leaf0_lag_one_IV.log line 2228 for the trail.)
            # vtysh always understands the full FRR CLI surface and
            # is the canonical way to query BGP-EVPN state from spytest.
            #
            # We use the `summary json` form so the output is
            # machine-parsable (FRR's text-summary layout drifted
            # across versions and is fragile to substring-match).
            # The JSON layout has top-level AFI buckets ('ipv4Unicast',
            # 'l2VpnEvpn', etc.) each with a 'peers' dict keyed by
            # neighbour IP. A peer is Established iff its 'state' (or
            # legacy 'peerState') is the literal string 'Established'.
            #
            # We accept Established in EITHER the l2VpnEvpn bucket OR
            # the ipv4Unicast bucket. Both prove the FRR side is alive
            # and exchanging routes -- if l2VpnEvpn alone is Established
            # we have EVPN type-5 prefix exchange; if only ipv4Unicast
            # is Established we still have the underlay (good enough
            # for the static-ARP gate, which only needs to know that
            # decap'd packets will have a forwarding path).
            try:
                raw = st.show(dut_h,
                              "vtysh -c 'show bgp l2vpn evpn summary json'",
                              skip_tmpl=True,
                              skip_error_check=True) or ''
            except Exception as exc:
                return False, ("vtysh show bgp l2vpn evpn summary json "
                               "raised {}: {}").format(
                                   type(exc).__name__, exc)
            text = str(raw)
            # Cheap, parser-free check first: the literal
            # "Established" token appears in FRR's JSON only as a peer
            # state value. False positives are essentially impossible
            # (the word doesn't appear in headers or labels).
            if '"Established"' in text or "'Established'" in text:
                return True, "Established peer seen in l2VpnEvpn summary"
            # Fallback: maybe the json form failed (very old FRR) --
            # try the plain text form via vtysh.
            try:
                raw2 = st.show(dut_h,
                               "vtysh -c 'show bgp l2vpn evpn summary'",
                               skip_tmpl=True,
                               skip_error_check=True) or ''
                text2 = str(raw2)
                if 'Established' in text2:
                    return True, "Established peer seen in plain summary"
            except Exception:
                pass
            # Last resort: drop down to plain `show bgp summary json`
            # (underlay-only). If even the ipv4 underlay isn't up, the
            # static-ARP install is definitely a bad idea.
            try:
                raw3 = st.show(dut_h,
                               "vtysh -c 'show bgp summary json'",
                               skip_tmpl=True,
                               skip_error_check=True) or ''
                if '"Established"' in str(raw3) or "'Established'" in str(raw3):
                    return True, ("Established peer seen in underlay "
                                  "ipv4Unicast summary (no EVPN bucket "
                                  "but underlay is alive)")
            except Exception:
                pass
            tail = '\n'.join(text.splitlines()[-4:])[:200] if text else '<no output>'
            return False, ("no Established peer found in any BGP summary "
                           "view (tail: {!r})").format(tail)

        vx_ok, vx_why = _vxlan_tunnel_present(dut2_h)
        bg_ok, bg_why = _bgp_evpn_established(dut2_h)
        if not (vx_ok and bg_ok):
            st.warn("  _setup_egress_svi_dut2: Step 9 GATED -- DUT2 "
                    "upstream not healthy, skipping static-neigh "
                    "install. vxlan_ok={} ({}); bgp_evpn_ok={} ({}). "
                    "Installing the static neighbour now would mask "
                    "the real failure: traffic would never reach the "
                    "DUT2 egress port anyway. Fix the upstream first."
                    .format(vx_ok, vx_why, bg_ok, bg_why))
            # Leave static_neigh_v4/v6 as None; downstream traffic
            # will FAIL at the per-instance gate with a clear
            # 'DUT2 q[N]=0' verdict, which correctly fingers the
            # upstream as the culprit (not a missing ARP).
        else:
            st.log("  _setup_egress_svi_dut2: Step 9 gate PASSED -- "
                   "vxlan: {}; bgp-evpn: {}".format(vx_why, bg_why))
            st.log("  _setup_egress_svi_dut2: Step 9 -- installing "
                   "static IPv4 neighbour entry on {} in {}: {} -> {} "
                   "(mirrors the DUT1-side mac_dst hardcode; bypasses "
                   "the broken DUT2<->Ixia 1/12 tagged ARP path)"
                   .format(svi_intf, vrf, ixia_egress_ip,
                           ixia_egress_mac))
            try:
                st.config(dut2_h,
                    'sudo ip vrf exec {} ip neigh replace {} lladdr {} '
                    'dev {} nud permanent'.format(
                        vrf, ixia_egress_ip, ixia_egress_mac, svi_intf),
                    skip_error_check=True)
                static_neigh_v4 = (ixia_egress_ip, svi_intf)
            except Exception as exc:
                st.warn("  _setup_egress_svi_dut2: Step 9 v4 static "
                        "neigh install raised {}: {} -- decap'd v4 "
                        "traffic will fall back to dynamic ARP "
                        "(likely to fail on this build).".format(
                            type(exc).__name__, exc))

            if ixia_egress_ip6:
                st.log("  _setup_egress_svi_dut2: Step 9 -- installing "
                       "static IPv6 neighbour entry on {} in {}: {} -> {}"
                       .format(svi_intf, vrf, ixia_egress_ip6,
                               ixia_egress_mac))
                try:
                    st.config(dut2_h,
                        'sudo ip vrf exec {} ip -6 neigh replace {} '
                        'lladdr {} dev {} nud permanent'.format(
                            vrf, ixia_egress_ip6, ixia_egress_mac,
                            svi_intf),
                        skip_error_check=True)
                    static_neigh_v6 = (ixia_egress_ip6, svi_intf)
                except Exception as exc:
                    st.warn("  _setup_egress_svi_dut2: Step 9 v6 "
                            "static neigh install raised {}: {} -- "
                            "decap'd v6 traffic will fall back to "
                            "dynamic ND.".format(type(exc).__name__,
                                                 exc))
    else:
        st.log("  _setup_egress_svi_dut2: Step 9 SKIPPED -- caller did "
               "not supply ixia_egress_mac. DUT2 will rely on dynamic "
               "ARP/ND to resolve Ixia 1/12; if the Step 8 tagged "
               "re-prime didn't take effect (e.g. NGPF blocked the "
               "classic-HLT route), the dynamic resolution will time "
               "out and decap'd traffic will be dropped.")

    def _teardown():
        st.log("  _setup_egress_svi_dut2 teardown: restoring routed-"
               "port-in-{} on {}".format(vrf, egress_intf))

        # ── Reverse Step 9 first (static neighbour entries) ────────
        # Delete the static ARP/ND entries we installed in setup.
        # This MUST run BEFORE the SVI VRF-unbind (step 5 reverse
        # below) because once the SVI is removed from VrfQoS the
        # ``ip vrf exec VrfQoS ip neigh del`` would fail with `Cannot
        # find device "VlanXXX"`. Also runs BEFORE the Step-8 Ixia
        # reversal because the static entries belong to DUT2's
        # kernel, not Ixia, and have no ordering dependency on the
        # Ixia tagged host destroy.
        if static_neigh_v4 is not None:
            _ip, _dev = static_neigh_v4
            try:
                st.config(dut2_h,
                    'sudo ip vrf exec {} ip neigh del {} dev {}'.format(
                        vrf, _ip, _dev),
                    skip_error_check=True)
                st.log("  _setup_egress_svi_dut2 teardown: Step 9 "
                       "v4 static neigh removed ({} on {} in {})"
                       .format(_ip, _dev, vrf))
            except Exception as exc:
                st.warn("  _setup_egress_svi_dut2 teardown: Step 9 "
                        "v4 static neigh remove raised {}: {} "
                        "(continuing; may leak a kernel neigh entry "
                        "that will age out naturally)".format(
                            type(exc).__name__, exc))
        if static_neigh_v6 is not None:
            _ip6, _dev = static_neigh_v6
            try:
                st.config(dut2_h,
                    'sudo ip vrf exec {} ip -6 neigh del {} dev {}'.format(
                        vrf, _ip6, _dev),
                    skip_error_check=True)
                st.log("  _setup_egress_svi_dut2 teardown: Step 9 "
                       "v6 static neigh removed ({} on {} in {})"
                       .format(_ip6, _dev, vrf))
            except Exception as exc:
                st.warn("  _setup_egress_svi_dut2 teardown: Step 9 "
                        "v6 static neigh remove raised {}: {}"
                        .format(type(exc).__name__, exc))

        # ── Reverse Step 8 (Ixia-side; LIFO) ───────────────────────
        # Order is critical:
        #   (a) Destroy the tagged emulated host on the (LAG-or-phys)
        #       port_handle. This stops Ixia from sending tagged
        #       protocol frames on Vlan{vlan_id} that would race the
        #       DUT2-side untagged restore below.
        #   (b) Delete the IxNet LAG (if step 8a wrapped one). The
        #       LAG must be gone before tg_ph['egress'] is restored,
        #       otherwise the next test class's tg_interface_config
        #       on the physical handle would race against the still-
        #       present LAG.
        #   (c) Restore tg_ph['egress'] back to the bare physical
        #       handle so the next test class (or the next preflight
        #       run) sees the original topology.
        # ixia_teardown_fns was populated in setup as:
        #   [('ixia-lag-wrap', td_lag), ('ixia-host-destroy', td_host)]
        # so reversed() gives us host-destroy first, then LAG-delete --
        # exactly the order we want.
        for step_label, step_fn in reversed(ixia_teardown_fns):
            try:
                st.log("  _setup_egress_svi_dut2 teardown: Step 8 "
                       "reverse -- {}".format(step_label))
                step_fn()
            except Exception as exc:
                st.warn("  _setup_egress_svi_dut2 teardown: Step 8 "
                        "reverse '{}' raised {}: {} (continuing; may "
                        "need manual cleanup in IxNetwork)".format(
                            step_label, type(exc).__name__, exc))

        # Restore tg_ph['egress'] to the saved physical handle. Do this
        # AFTER the LAG-delete teardown so any handle-resolution race
        # in the IxNet HLTAPI sees the LAG gone before we hand the
        # caller back the physical handle.
        if (ixia_reprime_active and tg_ph_dict_ref is not None
                and saved_egress_ph is not None
                and tg_ph_dict_ref.get('egress') != saved_egress_ph):
            prior = tg_ph_dict_ref.get('egress')
            tg_ph_dict_ref['egress'] = saved_egress_ph
            try:
                _overlay.tg_ph['egress'] = saved_egress_ph
            except Exception:
                pass
            st.log("  _setup_egress_svi_dut2 teardown: tg_ph['egress'] "
                   "restored from {} -> {}".format(prior, saved_egress_ph))

        # Setup never HSET on the SVI, so no SVI-side HDEL is needed.
        # The dscp_to_tc_map=AZURE binding on the physical port stays
        # in place across the teardown (the plain-L3VNI variant
        # relies on the exact same physical-port binding, and
        # `config qos reload` put it there).
        #
        # Reverse step 6: remove IPs from SVI.
        st.config(dut2_h,
            'config interface ip remove {} {}'.format(svi_intf, v4_ip),
            skip_error_check=True)
        st.config(dut2_h,
            'config interface ip remove {} {}'.format(svi_intf, v6_ip),
            skip_error_check=True)
        st.wait(1)
        # Reverse step 5: unbind SVI from VRF.
        st.config(dut2_h,
            'config interface vrf unbind {}'.format(svi_intf),
            skip_error_check=True)
        st.wait(1)
        # Reverse steps 4/3: drop physical port from VLAN, delete VLAN.
        # NOTE: if the LAG-wrap helper (below) ran successfully, the
        # vlan tagged-membership has already been migrated from
        # egress_intf to the LAG and back again by the LAG teardown,
        # so by the time we get here egress_intf IS the active
        # tagged-member of vlan_id. The LAG teardown's last step is
        # exactly that re-attach -- which is why this teardown MUST
        # run AFTER the LAG teardown.
        st.config(dut2_h,
            'config vlan member del {} {}'.format(vlan_id, egress_intf),
            skip_error_check=True)
        st.config(dut2_h,
            'config vlan del {}'.format(vlan_id),
            skip_error_check=True)
        st.wait(2)
        # Reverse step 2: re-bind physical port to `vrf`.
        st.config(dut2_h,
            'config interface vrf bind {} {}'.format(egress_intf, vrf),
            skip_error_check=True)
        # Reverse step 1: re-add IPs on the physical port.
        st.config(dut2_h,
            'config interface ip add {} {}'.format(egress_intf, v4_ip),
            skip_error_check=True)
        st.config(dut2_h,
            'config interface ip add {} {}'.format(egress_intf, v6_ip),
            skip_error_check=True)
        st.wait(1)
        # Defensive re-assert PORT_QOS_MAP after all the rebinds.
        st.config(dut2_h,
            'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" '
            '"dscp_to_tc_map" "AZURE"'.format(egress_intf),
            skip_error_check=True)
        st.wait(3)

    return _teardown


# ══════════════════════════════════════════════════════════════════
# DUT2 egress LAG-wrap helper (single-member LACP w/ fallback)
# ══════════════════════════════════════════════════════════════════

def _wrap_l3vni_egress_in_lag(dut2_h, physical_port, lag_name, vlan_id):
    """Wrap DUT2's tagged-SVI egress port in a single-member LACP
    PortChannel with LACP fallback enabled. DUT2 analogue of
    ``_wrap_l3vni_ingress_in_lag``.

    Pre-conditions (caller MUST have run ``_setup_egress_svi_dut2``
    first):
      * Vlan{vlan_id} exists on dut2_h.
      * ``physical_port`` is a TAGGED member of Vlan{vlan_id}.
      * Vlan{vlan_id} SVI is bound to the L3VNI VRF and has the
        decap-side IPs (V4_EGRESS_IP / V6_EGRESS_IP).
      * ``PORT_QOS_MAP|<physical_port>.dscp_to_tc_map = AZURE`` is
        bound (from `config qos reload` + the SVI helper's
        defensive HSET).

    Post-conditions:
      * ``lag_name`` is created with ``--fallback=true`` (LACP-mode;
        admits the lone member to the bundle after the LACP rx
        Short Timeout even without a partner).
      * ``physical_port`` is the LAG's only member.
      * Vlan{vlan_id} tagged-membership has migrated from
        ``physical_port`` to ``lag_name``.
      * Vlan{vlan_id} SVI is unchanged (still bound to the L3VNI
        VRF; the IPs/MAC stay put -- it's still the L3 RIF, just
        sitting on a LAG instead of the underlying physical port).
      * ``PORT_QOS_MAP|<lag_name>.dscp_to_tc_map = AZURE`` is
        additionally HSET (additive; physical-port binding stays).
      * The helper has waited 10s after the final config push to
        give teamd's LACP rx timer time to fire its fallback.

    Why this is structurally identical to the DUT1 ingress helper
    -------------------------------------------------------------
    The DUT1 helper migrates a Vlan tagged-membership from a
    physical port to a LAG, leaving the SVI on top as the L3 RIF.
    DUT2's egress side, after _setup_egress_svi_dut2, has the same
    shape (physical -> Vlan -> SVI in VRF). So the LAG-migration
    sequence is bit-for-bit the same: vlan-member-del physical,
    create-LAG-with-fallback, add-member, vlan-member-add LAG,
    HSET PORT_QOS_MAP|LAG. The trail-of-pain context (why fallback,
    not static; why we don't use klish) all applies identically --
    see the DUT1 helper's docstring for the full archeology.

    Why we use the same lag_name 'PortChannel0001' on both DUTs
    ----------------------------------------------------------
    Each SONiC box has its own PortChannel namespace; PortChannel0001
    on DUT1 and PortChannel0001 on DUT2 are independent objects.
    Reusing the name matches leaf0.cfg's downlink convention where
    both the server-facing leaf interface AND the upstream peer-leaf
    interface use the same LAG name. Makes the symmetric LAG-to-LAG
    diagram easier to reason about.

    Risk note (DUT2 egress-side specific)
    -------------------------------------
    The DUT1 LAG-wrap docstring's risk note about LAG-RIF vs port-
    RIF (bd_label/bd_or_vnid) classifier programming applies on the
    encap side. On the DECAP side (which this helper exercises), the
    DSCP-to-TC classification runs on the inner DSCP after VxLAN
    strip, with the PORT_QOS_MAP|<egress>.dscp_to_tc_map binding
    consulted at egress-queue-select time. Whether SAI evaluates
    that map against the LAG-RIF or the underlying physical-port
    RIF is platform-dependent on this FX3 build. We defensively HSET
    the binding on BOTH the LAG and the physical port (step 5 below)
    so the data plane sees AZURE on whichever entry SAI consults.
    The smoke's dut2_q_deltas readback (which now targets the LAG --
    see the caller's dut2_port_info rebind) is what loudly catches
    any regression.

    Order matters
    -------------
    Strict: ``vlan member del physical`` -> ``create LAG`` ->
    ``portchannel member add physical`` -> ``vlan member add LAG``.
    Teardown is the strict reverse: ``vlan member del LAG`` ->
    ``portchannel member del physical`` -> ``portchannel del LAG`` ->
    ``vlan member add physical``. The trailing re-attach to the
    physical port is what lets _setup_egress_svi_dut2's teardown
    find Vlan{vid} membership where it expects it.

    Returns a teardown callable that fully reverses every step that
    actually executed -- even if the helper aborts mid-sequence (any
    st.config raise, create_portchannel returning False, etc.) the
    returned teardown undoes EXACTLY the destructive steps that DID
    complete. Mirrors the DUT1 helper's LIFO cleanup_steps pattern.
    """
    from apis.switching.portchannel import (
        create_portchannel, add_portchannel_member,
        delete_portchannel_member, delete_portchannel,
    )

    st.log("  leaf0 DUT2 egress LAG-wrap: migrating {} -> {} (LACP "
           "w/ fallback, single-member, Vlan{} tagged-membership "
           "follows)".format(physical_port, lag_name, vlan_id))

    cleanup_steps = []

    def _teardown():
        st.log("  leaf0 DUT2 egress LAG-wrap teardown: unwrapping "
               "(steps to undo: {})".format(len(cleanup_steps)))
        for step_label, step_fn in reversed(cleanup_steps):
            try:
                step_fn()
            except Exception as exc:
                st.warn("leaf0 DUT2 egress LAG-wrap teardown: step "
                        "'{}' raised: {} (continuing with remaining "
                        "undos)".format(step_label, exc))
        st.log("  leaf0 DUT2 egress LAG-wrap teardown: done")

    # 1. Detach the physical port from Vlan{vid}. The SVI keeps its
    #    IP/VRF -- it is the L3 RIF, not the L2 port we are migrating.
    st.config(dut2_h,
        'config vlan member del {} {}'.format(vlan_id, physical_port),
        skip_error_check=True)
    st.wait(1)
    cleanup_steps.append(('vlan member add {} {}'.format(vlan_id, physical_port),
        lambda: st.config(dut2_h,
            'config vlan member add {} {}'.format(vlan_id, physical_port),
            skip_error_check=True)))

    # 2. Create the LAG with LACP fallback. Same rationale as the
    #    DUT1 helper: fallback=True avoids the trail-of-pain that
    #    bit static-mode twice (click-branch silent flag drop,
    #    klish-mode unsupported on FX3).
    pc_ok = create_portchannel(dut2_h, [lag_name], fallback=True)
    cleanup_steps.append(('delete_portchannel({})'.format(lag_name),
        lambda: delete_portchannel(dut2_h, [lag_name], skip_error=True)))
    if not pc_ok:
        st.error("leaf0 DUT2 egress LAG-wrap: create_portchannel({}, "
                 "fallback=True) returned False -- aborting wrap and "
                 "executing teardown".format(lag_name))
        _teardown()
        raise RuntimeError("DUT2 egress LAG-wrap setup failed: "
                           "create_portchannel returned False for {}"
                           .format(lag_name))
    st.wait(2)

    # 2b. Verify CONFIG_DB.PORTCHANNEL|<lag>.fallback == 'true'.
    fb_check = st.show(dut2_h,
        'sonic-db-cli CONFIG_DB HGET "PORTCHANNEL|{}" "fallback"'
        .format(lag_name),
        skip_tmpl=True) or ''
    if 'true' not in fb_check.lower():
        st.error("leaf0 DUT2 egress LAG-wrap: CONFIG_DB|PORTCHANNEL|"
                 "{}.fallback is NOT 'true' (got: {!r}). With no Ixia-"
                 "side LACP partner the lone member will stay in "
                 "LACP_DEFAULTED and traffic will be silently dropped. "
                 "Executing teardown."
                 .format(lag_name, fb_check.strip()))
        _teardown()
        raise RuntimeError("DUT2 egress LAG-wrap setup failed: fallback "
                           "not enabled on {}".format(lag_name))
    st.log("  leaf0 DUT2 egress LAG-wrap: confirmed CONFIG_DB|"
           "PORTCHANNEL|{}.fallback = true".format(lag_name))

    # 3. Bind the physical port as the (only) LAG member. Once
    #    fallback fires (~3s after carrier-up with no partner),
    #    teamd admits physical_port to the active bundle.
    if not add_portchannel_member(dut2_h, lag_name, [physical_port]):
        st.error("leaf0 DUT2 egress LAG-wrap: add_portchannel_member"
                 "({}, [{}]) returned False -- aborting wrap and "
                 "executing teardown".format(lag_name, physical_port))
        _teardown()
        raise RuntimeError("DUT2 egress LAG-wrap setup failed: "
                           "add_portchannel_member returned False for {} "
                           "member {}".format(lag_name, physical_port))
    cleanup_steps.append(('delete_portchannel_member({}, [{}])'.format(
            lag_name, physical_port),
        lambda: delete_portchannel_member(
            dut2_h, lag_name, [physical_port])))
    st.wait(1)

    # 4. Re-attach Vlan{vid} tagged membership to the LAG. From here
    #    the SVI sits on the LAG; the physical port carries tagged
    #    frames as a LAG member.
    st.config(dut2_h,
        'config vlan member add {} {}'.format(vlan_id, lag_name),
        skip_error_check=True)
    cleanup_steps.append(('vlan member del {} {}'.format(vlan_id, lag_name),
        lambda: st.config(dut2_h,
            'config vlan member del {} {}'.format(vlan_id, lag_name),
            skip_error_check=True)))

    # 5. Defensively HSET PORT_QOS_MAP|<lag>.dscp_to_tc_map = AZURE.
    #    The physical-port binding from `config qos reload` stays in
    #    place (additive). On builds where SAI consults the LAG-RIF
    #    entry, this is what makes the decap-side classifier hit;
    #    on builds where it inherits from the physical member, this
    #    is a harmless no-op.
    st.config(dut2_h,
        'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" '
        '"dscp_to_tc_map" "AZURE"'.format(lag_name),
        skip_error_check=True)
    cleanup_steps.append(('HDEL PORT_QOS_MAP|{}'.format(lag_name),
        lambda: st.config(dut2_h,
            'sonic-db-cli CONFIG_DB HDEL "PORT_QOS_MAP|{}" '
            '"dscp_to_tc_map"'.format(lag_name),
            skip_error_check=True)))

    # 6. Wait for LACP fallback convergence. Same timing as DUT1.
    st.wait(10)

    # 7. Post-check: confirm the LAG kernel netdev is UP+LOWER_UP.
    #    Read-only diagnostic (no cleanup_step registration needed).
    link_check = st.show(dut2_h,
        'ip link show {} 2>&1 | head -2'.format(lag_name),
        skip_tmpl=True) or ''
    if 'LOWER_UP' in link_check and 'state UP' in link_check:
        st.log("  leaf0 DUT2 egress LAG-wrap: LAG is UP+LOWER_UP "
               "after fallback wait -- bundle is active")
    else:
        st.warn("leaf0 DUT2 egress LAG-wrap: LAG {} is NOT fully up "
                "after the 10s LACP-fallback wait. ip link snippet: "
                "{!r}. Most likely fallback did not fire; downstream "
                "traffic will probably show 0 RX. Test continues so "
                "the diagnostic context survives in the run log."
                .format(lag_name, link_check.strip()))
        try:
            tc_state = st.show(dut2_h,
                'sudo teamdctl {} state 2>&1 | head -40'.format(lag_name),
                skip_tmpl=True) or ''
            if tc_state.strip():
                st.warn("leaf0 DUT2 egress LAG-wrap: teamdctl {} "
                        "state -- {}".format(lag_name, tc_state.strip()))
        except Exception:
            pass

    # 8. Cross-check: SONiC application-layer view via `show
    #    interfaces portchannel`. Same Up/Selected/Dw check as the
    #    DUT1 helper. Read-only (no cleanup_step registration).
    try:
        pc_show = st.show(dut2_h,
            'show interfaces portchannel',
            skip_tmpl=True, skip_error_check=True) or ''
        pc_show_stripped = pc_show.strip()
        if pc_show_stripped:
            st.log("  leaf0 DUT2 egress LAG-wrap: 'show interfaces "
                   "portchannel' (full output, {} expected as the "
                   "only row):".format(lag_name))
            for raw_line in pc_show_stripped.splitlines():
                st.log("    {}".format(raw_line.rstrip()))
        lag_rows = [
            ln for ln in pc_show.splitlines()
            if ' {} '.format(lag_name) in ' {} '.format(ln)
        ]
        lag_row = lag_rows[0].strip() if lag_rows else ''
        if 'LACP(A)(Up)' in lag_row and '{}(S)'.format(physical_port) in lag_row:
            st.log("  leaf0 DUT2 egress LAG-wrap: SONiC portchannel "
                   "view confirms bundle Up + member Selected -- {}"
                   .format(lag_row))
        elif 'LACP(A)(Dw)' in lag_row or '(Dw)' in lag_row:
            st.warn("leaf0 DUT2 egress LAG-wrap: SONiC portchannel "
                    "view says LAG {} bundle is DOWN (kernel said "
                    "UP+LOWER_UP). Likely orchagent has not yet "
                    "propagated bundle state into APPL_DB:LAG_TABLE "
                    "-- typically a 1-3s race. LAG row: {!r}"
                    .format(lag_name, lag_row))
        elif not lag_row:
            st.warn("leaf0 DUT2 egress LAG-wrap: 'show interfaces "
                    "portchannel' did not list LAG {} -- bundle is "
                    "not visible to SONiC application layer despite "
                    "kernel reporting UP+LOWER_UP. Likely orchagent "
                    "/ teammgrd binding failure.".format(lag_name))
        else:
            st.warn("leaf0 DUT2 egress LAG-wrap: SONiC portchannel "
                    "view for {} returned an unexpected row: {!r} "
                    "(was looking for 'LACP(A)(Up)' + '{}(S)' or "
                    "'LACP(A)(Dw)')"
                    .format(lag_name, lag_row, physical_port))
    except Exception as exc:
        st.warn("leaf0 DUT2 egress LAG-wrap: 'show interfaces "
                "portchannel' raised: {} (continuing -- this is a "
                "diagnostic cross-check, not a fixture guarantee)"
                .format(exc))

    # 9. L3-path verification dump (mirrors the DUT1 step 9).
    #    All three dumps are READ-ONLY and best-effort.
    try:
        vlan_brief = st.show(dut2_h, 'show vlan brief',
                             skip_tmpl=True, skip_error_check=True) or ''
        if vlan_brief.strip():
            st.log("  leaf0 DUT2 egress LAG-wrap: 'show vlan brief' "
                   "(full output, expect Vlan{} row to list {} as "
                   "tagged member):".format(vlan_id, lag_name))
            for raw_line in vlan_brief.strip().splitlines():
                st.log("    {}".format(raw_line.rstrip()))
    except Exception as exc:
        st.warn("leaf0 DUT2 egress LAG-wrap: 'show vlan brief' "
                "raised: {} (continuing -- diagnostic dump only)"
                .format(exc))

    try:
        ip_int = st.show(dut2_h, 'show ip interfaces',
                         skip_tmpl=True, skip_error_check=True) or ''
        if ip_int.strip():
            st.log("  leaf0 DUT2 egress LAG-wrap: 'show ip interfaces' "
                   "(full output, expect Vlan{} in VRF {}):"
                   .format(vlan_id, _I_VRF))
            for raw_line in ip_int.strip().splitlines():
                st.log("    {}".format(raw_line.rstrip()))
    except Exception as exc:
        st.warn("leaf0 DUT2 egress LAG-wrap: 'show ip interfaces' "
                "raised: {} (continuing -- diagnostic dump only)"
                .format(exc))

    try:
        lag_addr = st.show(dut2_h,
                           'ip addr show {}'.format(lag_name),
                           skip_tmpl=True, skip_error_check=True) or ''
        if lag_addr.strip():
            st.log("  leaf0 DUT2 egress LAG-wrap: 'ip addr show {}' "
                   "(full kernel-netdev view, expect NO inet/inet6 "
                   "line -- LAG is L2-only by design):".format(lag_name))
            for raw_line in lag_addr.strip().splitlines():
                st.log("    {}".format(raw_line.rstrip()))
    except Exception as exc:
        st.warn("leaf0 DUT2 egress LAG-wrap: 'ip addr show {}' "
                "raised: {} (continuing -- diagnostic dump only)"
                .format(lag_name, exc))

    st.log("  leaf0 DUT2 egress LAG-wrap: done -- {} now backs "
           "Vlan{} tagged-SVI egress on DUT2 (member: {}, LACP "
           "fallback active)".format(lag_name, vlan_id, physical_port))

    return _teardown


# ══════════════════════════════════════════════════════════════════
# VxLAN state-dump helper (leaf0-only diagnostic, always-on)
# ══════════════════════════════════════════════════════════════════

def _dump_vxlan_state(label):
    """Dump VxLAN tunnel + map state on both DUTs for forensic
    context.

    Why this lives only in test_dscp_to_tc_portchannel_smoke_leaf0.py
    -----------------------------------------------------
    The sibling overlay module (test_dscp_to_tc_overlay.py) used
    to dump these CLIs in _smoke_preflight, but they were
    explicitly removed in an earlier round
    (test_dscp_to_tc_overlay.py:3897-3900) on the grounds that
    "if BGP/EVPN isn't up, the actual smoke traffic will FAIL
    loudly anyway, and the verbose CLI output dwarfed the QoS
    verdict." That decision still holds for the bulk of the
    smoke classes -- per-test dumps cost log noise per parametrize
    instance.

    This helper is different: it fires ONCE per leaf0 fixture run
    (not per parametrize instance) and only when the leaf0-style
    test class is collected. The volume cost is small and the
    diagnostic value is high specifically for the LAG-ingress
    investigation: when LAG-RIF based VXLAN encap silently fails,
    `show vxlan tunnel` is the single CLI that distinguishes
    "tunnel not installed" from "tunnel installed, traffic just
    not flowing" -- exactly the discrimination we need.

    What gets dumped
    ----------------
    `show vxlan tunnel` on both DUT1 (encap origin) and DUT2
    (encap destination). The output table format is consistent
    enough across SONiC versions that a raw dump is easier to
    eyeball than a parsed-and-reformatted version. We use
    skip_tmpl=True so spytest doesn't try to fit the table into
    a parser template and silently mis-parse rows.

    Failure handling
    ----------------
    Wrapped in try/except. If the CLI fails for any reason
    (transient ssh blip, command-not-found on a future SONiC
    refactor, etc.), the dump emits a soft st.warn and the
    fixture continues. This is a diagnostic, not a guarantee --
    we never want a forensics-only helper to abort a test setup.

    Parameters
    ----------
    label : str
        Short context tag (e.g. 'after-LAG-wrap', 'after-BGP-knobs')
        that prefixes the section header. Helps the operator
        correlate the dump with the surrounding setup phase when
        reading the log.
    """
    print_section("leaf0-style: VxLAN tunnel state ({})".format(label),
                  art_key=None)
    for dut_label, dut_handle in (('DUT1', dut), ('DUT2', dut2)):
        if dut_handle is None:
            st.log("  [{}] skipped (no handle)".format(dut_label))
            continue
        try:
            out = st.show(dut_handle, 'show vxlan tunnel',
                          skip_tmpl=True,
                          skip_error_check=True) or ''
            # Log the raw table rather than reformatting -- the
            # SONiC CLI already produces a clean fixed-width
            # format that survives copy/paste into a bug report.
            # Strip trailing whitespace per line for log hygiene.
            st.log("  [{}] show vxlan tunnel:".format(dut_label))
            for line in out.splitlines():
                st.log("    {}".format(line.rstrip()))
        except Exception as exc:
            st.warn("leaf0-style: 'show vxlan tunnel' on {} raised: "
                    "{} (continuing -- this is a diagnostic, not "
                    "a fixture guarantee)".format(dut_label, exc))


# ══════════════════════════════════════════════════════════════════
# Setup helper
# ══════════════════════════════════════════════════════════════════

def _setup_leaf0_style_overlay():
    """Layer leaf0-flavor knobs on top of the base L3VNI fabric.

    Pre-conditions: caller has already invoked ``_setup_vxlan_l3vni()``
    so the underlying VxLAN VTEP, EVPN session, VRF binding and
    DSCP-to-TC map are all in place. We *augment* that state, we do
    not replace it.

    Steps performed:

      1. Tagged-SVI ingress on DUT1 -- delegated to
         ``_overlay._smoke_setup_l3vni_tagged_svi()`` so the VID and
         the orchagent settle ordering exactly match what
         ``_smoke_run_one(mode='l3vni_tagged')`` will look for at
         traffic time. See the module-level "why delegated, not
         duplicated" note for the bug-finding trail that drove this
         choice.

      2. ``counterpoll tunnel enable`` on both DUTs (matches
         leaf0.cfg line 2). Idempotent: a second 'enable' is a
         no-op on this platform.

      3. BGP policy knobs in the default-VRF router-bgp instance on
         both DUTs:
           - ``bgp disable-ebgp-connected-route-check``
           - ``bgp bestpath as-path multipath-relax``
           - (opt-in) ``no ip/ipv6 nht resolve-via-default``
         These are layered on top of the session our base helper
         already brought up; the session itself is preserved (we
         do NOT pivot to loopback-sourced peering, and we do NOT
         set ``bgp router-id`` -- see the "why dropped" notes
         above the constants block for the rationale).

    Returns a teardown callable that reverses every step. The
    caller MUST stash it in a try/finally and invoke it.
    """
    # Read the populated module-level globals. ``setup_topo`` (the
    # autouse=module fixture above) is what populates them, and it
    # has run by the time we get here.  We read from this module's
    # globals (NOT _overlay's) because the autouse fixture writes to
    # both, and this module is the canonical owner for our test class.
    dut_h  = dut
    dut2_h = dut2
    if not dut_h:
        st.log("  leaf0-style: no DUT1 -- skipping helper "
               "(test should also be skipped)")
        return lambda: None

    # ── Step 1: tagged-SVI ingress (delegated) ────────────────────
    # The canonical helper handles the entire phys-port-IP unbind /
    # VLAN create / VLAN member add / SVI VRF bind / SVI IP add /
    # PORT_QOS_MAP defensive re-assert dance, using the same VID
    # (_L2_VLAN_ID) that ``_smoke_run_one(mode='l3vni_tagged')``
    # will tag Ixia frames with at traffic time. Returns its own
    # teardown callable that we chain into ours.
    teardown_svi = _overlay._smoke_setup_l3vni_tagged_svi()

    # ── Step 1.4: baseline VxLAN tunnel snapshot (forensic) ───────
    # Capture the tunnel state at the same configuration point where
    # the canonical sibling class (TestSmokeL3VNITagged) would be
    # ready to send traffic -- i.e. SVI-on-VRF + EVPN-imported tunnel
    # but BEFORE any leaf0-flavor knobs (LAG-wrap, counterpoll,
    # BGP-knobs) have been layered on. Pairs with the post-knobs
    # dump in Step 4 -- the diff between the two tells us whether
    # any of our leaf0 knobs (especially the LAG-wrap in Step 1.5)
    # disturbed the EVPN-imported tunnel.
    #
    # Why dump *before* Step 1.5 specifically: if the LAG-wrap re-
    # creates a RIF on PortChannel0001 and that RIF re-allocates a
    # new bd_or_vnid label, the encap-side TCAM lookup we already
    # know is fragile (commit 6d8e04d4 archeology) could regress.
    # Comparing the before/after dumps is the fastest way to
    # disambiguate "tunnel never came up" from "tunnel up before
    # LAG, broke after LAG".
    _dump_vxlan_state(label='before-LAG-wrap')

    # ── Step 1.5: wrap the L3VNI ingress in a LACP+fallback LAG ──
    # ON by default (real-HW-validated; see
    # smoke_leaf0_lag_one_II.log). Set VXLAN_LEAF0_LAG_INGRESS=0
    # to opt out and run on the bare physical port for A/B
    # comparison against TestSmokeL3VNITagged. The wrap helper
    # itself carries the full rationale for why we use
    # LACP-with-fallback rather than static (two earlier
    # attempts at static-mode failed on this FX3 build -- see
    # the helper's docstring "trail of pain" section).
    #
    # Wrap the helper call in try/except so a
    # create_portchannel/add_portchannel_member failure does NOT
    # escape this function with teardown_svi unregistered. The LAG
    # helper calls its own _teardown() to undo its partial LAG steps,
    # then raises RuntimeError. We catch that, invoke teardown_svi to
    # undo the SVI setup from Step 1, then re-raise so the fixture
    # sees the failure. Without this wrapper, a LAG setup failure
    # leaves Vlan100/VRF changes from _smoke_setup_l3vni_tagged_svi()
    # dirty with no cleanup path (the base VXLAN teardown does not
    # remove that SVI).
    teardown_lag = None
    if _LEAF0_LAG_INGRESS:
        try:
            teardown_lag = _wrap_l3vni_ingress_in_lag(
                dut_h         = dut_h,
                physical_port = port_info['ingress'],
                lag_name      = _LEAF0_LAG_NAME_L3VNI,
                vlan_id       = _overlay._L2_VLAN_ID,
            )
        except BaseException as exc_lag:
            st.warn("  leaf0-style: _wrap_l3vni_ingress_in_lag raised "
                    "{}: {}. LAG helper already executed its own "
                    "_teardown() to undo partial LAG steps; now "
                    "invoking teardown_svi to undo Step 1 SVI setup, "
                    "then re-raising so the fixture sees the failure."
                    .format(type(exc_lag).__name__, exc_lag))
            try:
                teardown_svi()
            except Exception as exc_svi:
                st.warn("  leaf0-style: teardown_svi raised during "
                        "post-LAG-failure cleanup: {} (continuing)"
                        .format(exc_svi))
            raise
    else:
        st.log("  leaf0-style: VXLAN_LEAF0_LAG_INGRESS=0 -- "
               "opted out of the default LAG ingress; L3VNI "
               "ingress stays on physical port {} (unset the "
               "env var or set VXLAN_LEAF0_LAG_INGRESS=1 to "
               "wrap into a LACP+fallback single-member {})"
               .format(port_info['ingress'], _LEAF0_LAG_NAME_L3VNI))

    # ── Step 1.5b: post-LAG-wrap VxLAN tunnel snapshot (forensic) ──
    # Only fires if Step 1.5 actually ran (i.e. _LEAF0_LAG_INGRESS=1).
    # Skipping this dump when LAG-wrap is off avoids redundant log
    # noise -- with no LAG migration, the tunnel state is
    # bit-identical to the Step 1.4 baseline and a third dump
    # adds nothing.
    #
    # When LAG-wrap IS on, this snapshot is the most diagnostic
    # of the three: any state delta between "before-LAG-wrap"
    # (Step 1.4) and "after-LAG-wrap" (this) is *causally*
    # attributable to the LAG migration, with no confounding
    # variables. If oper_status flips here, the LAG-wrap broke
    # the tunnel; if it stays the same, the LAG-wrap is innocent
    # and any later regression must come from Steps 2 or 3.
    if teardown_lag is not None:
        _dump_vxlan_state(label='after-LAG-wrap')

    # ── Step 1.6: (opt-in) wrap the Ixia ingress in a static LAG ──
    # Cosmetic-only: makes the IxNetwork GUI show LAG-to-LAG instead
    # of a port-to-LAG asymmetric wire. Wire frames are unchanged
    # (DUT side runs LACP+fallback, harmlessly emitting LACPDUs into
    # the void; Ixia static LAG sends no LACPDUs at all -- frames
    # going out of the Ixia side are plain ethernet, indistinguishable
    # from the bare-physical-port case). Double-gated by design
    # (see _LEAF0_IXIA_LAG_INGRESS rationale): only fires when the
    # DUT-side wrap is also active, otherwise the Ixia GUI would
    # show the wire as "LAG <-> bare port", which is *more*
    # asymmetric than the current "bare <-> bare" baseline.
    #
    # Failure handling: if the wrap helper returns (None, None)
    # (HLTAPI rejected static-mode, IxNetwork backend returned
    # status='0', etc.), tg_ph['ingress'] / tg_ph['ingress_a']
    # stay pointed at the physical handle and the rest of the run
    # proceeds normally -- the DUT-side LACP+fallback LAG works
    # fine without a matching Ixia-side LAG (only the GUI view
    # differs).
    teardown_ixia_lag = None
    saved_ingress_ph  = None
    saved_ingress_a   = None
    if _LEAF0_LAG_INGRESS and _LEAF0_IXIA_LAG_INGRESS:
        new_ph, td_ixia = _wrap_ixia_ingress_in_lag(
            tg_obj      = tg,
            physical_ph = tg_ph['ingress'],
            lag_name    = _LEAF0_IXIA_LAG_NAME,
        )
        if new_ph is not None:
            # Stash originals so teardown can restore them; then swap
            # both 'ingress' and 'ingress_a' (helpers reference both
            # keys depending on which mode they're in).  Write to
            # *both* this module's globals AND _overlay's globals,
            # mirroring the publish pattern in setup_topo above --
            # _smoke_run_one / _build_streams_unique read tg_ph from
            # _overlay's namespace via Python name lookup.
            saved_ingress_ph = tg_ph['ingress']
            saved_ingress_a  = tg_ph.get('ingress_a')
            tg_ph['ingress']   = new_ph
            tg_ph['ingress_a'] = new_ph
            _overlay.tg_ph['ingress']   = new_ph
            _overlay.tg_ph['ingress_a'] = new_ph
            teardown_ixia_lag  = td_ixia
            st.log("  leaf0-style: Ixia LAG-wrap applied -- tg_ph["
                   "'ingress'] swapped from {} to {} for the duration "
                   "of this test class".format(saved_ingress_ph, new_ph))
        else:
            st.log("  leaf0-style: Ixia LAG-wrap not applied "
                   "(helper returned None; see preceding warn for "
                   "root cause). Continuing with physical handle {} -- "
                   "DUT-side static LAG works fine without an Ixia-"
                   "side LAG (the wire view in IxNetwork will show "
                   "'1/1/9 -> PortChannel0001' asymmetric, but "
                   "frames are identical to the symmetric case)."
                   .format(tg_ph['ingress']))
    elif _LEAF0_LAG_INGRESS and not _LEAF0_IXIA_LAG_INGRESS:
        st.log("  leaf0-style: VXLAN_LEAF0_IXIA_LAG not set -- Ixia "
               "ingress stays on physical port {}; IxNetwork GUI "
               "will show 'physical -> LAG' asymmetric wire (set "
               "VXLAN_LEAF0_IXIA_LAG=1 alongside "
               "VXLAN_LEAF0_LAG_INGRESS=1 for the symmetric view)."
               .format(tg_ph['ingress']))

    # ── Step 1.7: DUT2 egress tagged-SVI + LAG wrap ──────────────────
    # Mirror DUT1's leaf0 stack onto DUT2's egress-to-Ixia port so the
    # wire shape is symmetric (LAG-to-LAG on both sides of the fabric,
    # SVI-in-VrfQoS on both sides of the VxLAN tunnel). Two sub-steps:
    #
    #   1.7   _setup_egress_svi_dut2 -- migrate from routed-port-in-
    #         VRF to tagged-SVI-in-VRF on DUT2 (same shape as DUT1
    #         ingress after Step 1's delegated SVI helper).
    #   1.7b  _wrap_l3vni_egress_in_lag -- migrate the SVI's L2 layer
    #         from the physical port to a single-member LACP+fallback
    #         LAG (same shape as DUT1 ingress after Step 1.5).
    #
    # On success: dut2_port_info['egress_ixia'] is rebound to the LAG
    # name (both this module's dict AND _overlay.dut2_port_info), so
    # _smoke_run_one's frame-walk picks up the LAG for the
    # dut2_q_deltas readback. Saved-originals are stashed for the
    # teardown to restore.
    #
    # Default ON (per user request at design time; HW validation done
    # in parallel with the DUT1-LAG smoke baseline). Set
    # VXLAN_LEAF0_EGRESS_SVI_LAG=0 to skip this step entirely and
    # keep DUT2's egress as a plain routed-port-in-VRF for A/B
    # comparison against the DUT1-only LAG baseline.
    teardown_egress_svi  = None
    teardown_egress_lag  = None
    saved_egress_ixia    = None
    if _LEAF0_EGRESS_SVI_LAG and dut2_h and dut2_port_info.get('egress_ixia'):
        dut2_egress_phys = dut2_port_info['egress_ixia']
        st.log("  leaf0-style: applying DUT2 egress tagged-SVI + LAG "
               "wrap (mirrors DUT1's stack on the decap side); "
               "egress port = {}, target LAG = {}, VLAN = {}"
               .format(dut2_egress_phys, _LEAF0_LAG_NAME_EGRESS,
                       _overlay._L2_VLAN_ID))
        # 1.7  Tagged-SVI migration.
        #
        # CRITICAL: wrap the helper call in try/except BaseException so
        # a TG-API-Fatal-Abort inside the helper's Step 8 (Ixia tagged
        # re-prime / cosmetic LAG-wrap) does NOT escape this fixture
        # with ``teardown_egress_svi`` unassigned. If the abort escaped:
        #   * The class-fixture teardown stack would never get a
        #     reference to the DUT2-side partial state.
        #   * The next test's module-init teardown would trip over the
        #     stranded PortChannel0001 + Vlan100 + SVI on DUT2 with
        #     "Error: Ethernet1_49 is configured as a member of
        #     portchannel" (see smoke_leaf0_lag_one_VI.log).
        # We catch BaseException (not just Exception) because spytest's
        # tgapi shim wraps IxNet HLTAPI validation errors as a session-
        # level "TG API Fatal Abort" that is not a regular Exception
        # subclass and bypasses ``except Exception``.
        try:
            teardown_egress_svi = _setup_egress_svi_dut2(
                dut2_h      = dut2_h,
                egress_intf = dut2_egress_phys,
                vlan_id     = _overlay._L2_VLAN_ID,
                vrf         = _I_VRF,
                v4_ip       = V4_EGRESS_IP,
                v6_ip       = V6_EGRESS_IP,
                # ── Ixia-side re-prime (Step 8 in the helper) ──────────
                # Unconditional whenever _LEAF0_EGRESS_SVI_LAG=1 (the
                # surrounding if-guard already enforces that). The
                # cosmetic IxNet LAG-wrap is gated by the new
                # _LEAF0_IXIA_LAG_EGRESS env-var (default OFF; see the
                # constants block for the bug trail). The tagged-IP
                # re-prime is NEVER optional once DUT2's Ethernet1_49
                # has been migrated to a tagged-SVI inside a LAG --
                # without it the wire shape mismatches between DUT2
                # (tagged Vlan100) and Ixia 1/12 (untagged), and every
                # ARP-request DUT2 sends gets dropped at Ixia's vport
                # L2 filter (smoke_leaf0_lag_one_IV.log failure mode).
                tg                 = tg,
                tg_obj             = tg,
                tg_ph_dict_ref     = tg_ph,
                ixia_egress_ip     = IXIA_EGRESS_IP,
                ixia_egress_ip6    = IXIA_EGRESS_IP6,
                ixia_egress_gw_v4  = '20.20.20.1',
                ixia_egress_gw_v6  = '2001:db8:20::1',
                ixia_wrap_in_lag   = _LEAF0_IXIA_LAG_EGRESS,
                ixia_lag_name      = _LEAF0_IXIA_LAG_NAME_EGRESS,
                # ── Step 9: deterministic DUT2-side ARP shortcut ──────
                # Pass the canonical egress-role MAC from the overlay
                # module's IXIA_SRC_MAC dict (the same one DUT1's test
                # traffic uses for mac_src='00:11:01:00:00:01' on the
                # encap side). This pins both Ixia 1/12's emulated host
                # src_mac AND DUT2's static neighbour entry to the same
                # constant -- both sides know the answer without ever
                # needing to ARP. Mirror of the DUT1-side mac_dst hard-
                # code in the test traffic streams.
                ixia_egress_mac    = _overlay.IXIA_SRC_MAC['egress'],
            )
        except BaseException as exc_step8:
            st.warn("  leaf0-style: _setup_egress_svi_dut2 raised {}: "
                    "{}. Step 8 (Ixia re-prime) likely tripped a TG-API-"
                    "Fatal-Abort. Synthesising a DUT2-side-only teardown "
                    "closure so the class fixture can still unwind the "
                    "PortChannel0001 + Vlan100 + SVI on DUT2 -- the "
                    "downstream preflight ping check will surface the "
                    "Ixia-side failure with an actionable error."
                    .format(type(exc_step8).__name__, exc_step8))
            # Synthesise a DUT2-side-only teardown that mirrors the
            # body of _setup_egress_svi_dut2's _teardown closure for
            # the DUT2-side LIFO unwind (Steps 6 -> 1). We omit the
            # Ixia-side reversal because Step 8 raised before any Ixia
            # state was successfully registered into ixia_teardown_fns.
            # Capture all loop-vars by default args so the closure
            # doesn't pick up a stale reference if this fixture is re-
            # entered (defensive; class fixtures are normally one-shot
            # but better-safe-than-sorry).
            _td_dut2_h      = dut2_h
            _td_phys        = dut2_egress_phys
            _td_vlan_id     = _overlay._L2_VLAN_ID
            _td_vrf         = _I_VRF
            _td_v4_ip       = V4_EGRESS_IP
            _td_v6_ip       = V6_EGRESS_IP
            _td_svi_intf    = 'Vlan{}'.format(_td_vlan_id)
            def teardown_egress_svi():
                st.log("  synthesised post-Step8-abort teardown: "
                       "restoring routed-port-in-{} on {}"
                       .format(_td_vrf, _td_phys))
                st.config(_td_dut2_h,
                    'config interface ip remove {} {}'.format(
                        _td_svi_intf, _td_v4_ip), skip_error_check=True)
                st.config(_td_dut2_h,
                    'config interface ip remove {} {}'.format(
                        _td_svi_intf, _td_v6_ip), skip_error_check=True)
                st.wait(1)
                st.config(_td_dut2_h,
                    'config interface vrf unbind {}'.format(_td_svi_intf),
                    skip_error_check=True)
                st.wait(1)
                st.config(_td_dut2_h,
                    'config vlan member del {} {}'.format(
                        _td_vlan_id, _td_phys), skip_error_check=True)
                st.config(_td_dut2_h,
                    'config vlan del {}'.format(_td_vlan_id),
                    skip_error_check=True)
                st.wait(2)
                st.config(_td_dut2_h,
                    'config interface vrf bind {} {}'.format(
                        _td_phys, _td_vrf), skip_error_check=True)
                st.config(_td_dut2_h,
                    'config interface ip add {} {}'.format(
                        _td_phys, _td_v4_ip), skip_error_check=True)
                st.config(_td_dut2_h,
                    'config interface ip add {} {}'.format(
                        _td_phys, _td_v6_ip), skip_error_check=True)
                st.wait(1)
                st.config(_td_dut2_h,
                    'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" '
                    '"dscp_to_tc_map" "AZURE"'.format(_td_phys),
                    skip_error_check=True)
                st.wait(3)
        # 1.7b LAG-wrap on top of the SVI.
        #
        # Wrap the helper call in try/except so a
        # create_portchannel/add_portchannel_member failure does NOT
        # escape this function with all earlier teardown callbacks
        # unregistered. The LAG helper calls its own _teardown() to
        # undo its partial LAG steps, then raises RuntimeError. We
        # catch that and invoke ALL earlier teardown callbacks in
        # reverse order (DUT2 egress SVI, Ixia ingress LAG, DUT1 LAG,
        # DUT1 SVI) before re-raising, ensuring no testbed state is
        # left dirty.
        try:
            teardown_egress_lag = _wrap_l3vni_egress_in_lag(
                dut2_h        = dut2_h,
                physical_port = dut2_egress_phys,
                lag_name      = _LEAF0_LAG_NAME_EGRESS,
                vlan_id       = _overlay._L2_VLAN_ID,
            )
        except BaseException as exc_lag:
            st.warn("  leaf0-style: _wrap_l3vni_egress_in_lag raised "
                    "{}: {}. LAG helper already executed its own "
                    "_teardown() to undo partial LAG steps; now "
                    "invoking all earlier teardown callbacks (DUT2 SVI, "
                    "Ixia LAG, DUT1 LAG, DUT1 SVI) in reverse order "
                    "before re-raising."
                    .format(type(exc_lag).__name__, exc_lag))
            # Reverse order: DUT2 egress SVI -> Ixia LAG -> DUT1 LAG -> DUT1 SVI
            if teardown_egress_svi is not None:
                try:
                    teardown_egress_svi()
                except Exception as exc:
                    st.warn("  teardown_egress_svi raised: {} (continuing)"
                            .format(exc))
            if teardown_ixia_lag is not None:
                try:
                    teardown_ixia_lag()
                except Exception as exc:
                    st.warn("  teardown_ixia_lag raised: {} (continuing)"
                            .format(exc))
                # Restore tg_ph handles
                if saved_ingress_ph is not None:
                    tg_ph['ingress'] = saved_ingress_ph
                    _overlay.tg_ph['ingress'] = saved_ingress_ph
                if saved_ingress_a is not None:
                    tg_ph['ingress_a'] = saved_ingress_a
                    _overlay.tg_ph['ingress_a'] = saved_ingress_a
            if teardown_lag is not None:
                try:
                    teardown_lag()
                except Exception as exc:
                    st.warn("  teardown_lag raised: {} (continuing)"
                            .format(exc))
            try:
                teardown_svi()
            except Exception as exc:
                st.warn("  teardown_svi raised: {} (continuing)"
                        .format(exc))
            raise
        # DCHAL-port-handle decision: KEEP `dut2_port_info['egress_ixia']`
        # pointing at the PHYSICAL member port (e.g. Ethernet1_49),
        # NOT the LAG name (e.g. PortChannel0001). The smoke's per-
        # queue dchal readback in _smoke_run_one builds dut2_ctx from
        # dut2_port_info['egress_ixia'] (see overlay line 2280-2285)
        # and then calls `docker exec syncd python3 /tmp/dchal_qi.py
        # <name>`. On FX3 the deployed dchal_qi.py resolves <name> via
        # platform.json -- which only contains physical port names.
        # When <name> is a LAG, dchal_qi prints:
        #
        #   DCHAL_SKIP: cannot resolve PortChannel0001 (tried [...])
        #     Interface 'PortChannel0001' not found in platform.json
        #
        # and returns no queue counters at all. That made every DUT2
        # egress queue read 0/0/0/0/0/0/0/0 in
        # smoke_leaf0_lag_one_IV.log (line 3263) even when the ASIC
        # was clearly forwarding the burst out the physical member
        # (Ethernet1_49 TX_OK = 3,015 at line 3320; DCHAL on the
        # physical port showed 15 pkts at QOS GROUP 5 -- matching
        # the test's 3 x 5-pkt bursts).
        #
        # On Broadcom DNX (FX3 family), per-queue egress accounting
        # lives on the physical sysport regardless of LAG membership
        # -- LAG is a transmit-distribution layer, not an accounting
        # boundary. So polling the physical member is BOTH the
        # technically correct place AND the only place dchal_qi.py
        # can actually query. A future enhancement to teach
        # _CounterCtx to resolve LAG -> member member-list is
        # tracked separately (option B in the design discussion); for
        # today's single-member LAG topology the physical port is
        # equivalent and reliable.
        #
        # We keep `saved_egress_ixia` as None so the teardown branch
        # (line 3672) is a no-op -- no swap was made, no restore is
        # needed.
        saved_egress_ixia = None
        st.log("  leaf0-style: DUT2 egress SVI+LAG wrap complete -- "
               "dut2_port_info['egress_ixia'] KEPT at {} (physical "
               "member). dchal_qi.py on FX3 only resolves physical "
               "ports from platform.json; LAG names like {} would "
               "produce DCHAL_SKIP and false q[N]=0 readings."
               .format(dut2_port_info['egress_ixia'],
                       _LEAF0_LAG_NAME_EGRESS))

        # 1.7c Post-wrap VxLAN state snapshot (forensic).
        # Pairs with the 'after-LAG-wrap' (DUT1 side) and the final
        # 'after-BGP-knobs' (Step 4) dumps. A diff between this
        # snapshot and 'after-LAG-wrap' isolates whether the DUT2
        # egress migration disturbed the EVPN-imported overlay -- if
        # oper_status flips here, the DUT2 wrap broke the tunnel; if
        # it stays the same, the wrap is innocent and any later
        # regression must come from Step 2 (counterpoll) or Step 3
        # (BGP knobs).
        _dump_vxlan_state(label='after-DUT2-egress-SVI-LAG')
    elif not _LEAF0_EGRESS_SVI_LAG:
        st.log("  leaf0-style: VXLAN_LEAF0_EGRESS_SVI_LAG=0 -- DUT2 "
               "egress stays as routed-port-in-{} on physical port "
               "(unset the env var or set VXLAN_LEAF0_EGRESS_SVI_LAG"
               "=1 to mirror DUT1's tagged-SVI + LACP-fallback LAG "
               "stack on the decap side too)".format(_I_VRF))

    # ── Step 2: counterpoll tunnel enable (both DUTs) ─────────────
    if _LEAF0_COUNTERPOLL_TUNNEL:
        st.config(dut_h, 'counterpoll tunnel enable',
                  skip_error_check=True)
        if dut2_h:
            st.config(dut2_h, 'counterpoll tunnel enable',
                      skip_error_check=True)

    # ── Step 3: BGP policy knobs (both DUTs) ──────────────────────
    # All knobs go into the *default-VRF* router-bgp instance plus
    # (opt-in) the global NHT block. We push them in a single
    # vtysh transaction per DUT so FRR sees them as one config
    # event -- avoids transient mid-config best-path flaps.
    def _push_bgp_knobs(dut_handle, local_as, label):
        lines = ['router bgp {}'.format(local_as)]
        if _LEAF0_BGP_DISABLE_CONN_CHECK:
            lines.append('  bgp disable-ebgp-connected-route-check')
        if _LEAF0_BGP_MPATH_RELAX:
            lines.append('  bgp bestpath as-path multipath-relax')
        lines.append('exit')
        if _LEAF0_NHT_RESOLVE_OFF:
            lines.append('no ip nht resolve-via-default')
            lines.append('no ipv6 nht resolve-via-default')
        # Skip the push if no actual policy lines were added
        # (only the bare 'router bgp / exit' frame is present).
        if (not _LEAF0_BGP_DISABLE_CONN_CHECK
                and not _LEAF0_BGP_MPATH_RELAX
                and not _LEAF0_NHT_RESOLVE_OFF):
            return
        cfg = '\n'.join(lines) + '\n'
        knob_count = sum([_LEAF0_BGP_DISABLE_CONN_CHECK,
                          _LEAF0_BGP_MPATH_RELAX,
                          _LEAF0_NHT_RESOLVE_OFF])
        st.log("  leaf0-style: pushing BGP policy knobs on {} "
               "(local_as={}, knobs={})"
               .format(label, local_as, knob_count))
        st.config(dut_handle, cfg, type='vtysh',
                  skip_error_check=True)

    _push_bgp_knobs(dut_h, _I_BGP_AS1, 'DUT1')
    if dut2_h:
        _push_bgp_knobs(dut2_h, _I_BGP_AS2, 'DUT2')

    st.wait(2)  # let FRR settle the new policy bits

    # ── Step 4: post-knobs VxLAN state dump (forensic) ───────────
    # Final snapshot in the 4-point sequence (1.4 -> 1.5b -> 1.7c -> 4):
    #   1.4  'before-LAG-wrap'           : tunnel after SVI-on-VRF
    #                                      setup, no leaf0 knobs yet
    #   1.5b 'after-LAG-wrap'            : tunnel after DUT1-side LAG
    #                                      migration only, no DUT2 wrap
    #                                      yet, no BGP-knobs yet (fires
    #                                      only when _LEAF0_LAG_INGRESS=1)
    #   1.7c 'after-DUT2-egress-SVI-LAG' : tunnel after DUT2-side SVI+
    #                                      LAG migration on top of DUT1
    #                                      wrap, still no BGP-knobs
    #                                      (fires only when
    #                                      _LEAF0_EGRESS_SVI_LAG=1)
    #   4    'after-BGP-knobs'           : tunnel after all leaf0 policy
    #                                      (DUT1+DUT2 LAGs, counterpoll,
    #                                      BGP knobs) has been applied
    #                                      and FRR settled
    #
    # The diff between consecutive snapshots isolates *which* knob
    # caused any oper_status / route-count change. This four-point
    # sweep is the forensic spine of the leaf0 class: any future
    # regression in LAG-RIF VXLAN encap or DSCP-to-TC over LAG can
    # be triaged from these CLIs alone, without re-running the test.
    # Specifically the 1.5b -> 1.7c delta is causally attributable
    # to the DUT2 wrap (DUT2 RIF re-allocation, decap-side classifier
    # re-program) with no confounding variables, which is the
    # discriminator for the DUT2-egress-SVI-LAG-specific risk path.
    _dump_vxlan_state(label='after-BGP-knobs')

    # ── Step 4b: REMOVED ────────────────────────────────────────────────
    # A previous revision did a runtime del+re-add of VTEP / EVPN-NVO /
    # VLAN-VNI map / VRF-VNI map on DUT2 here, intended to "kick" the
    # orchagent SAI-tunnel state machine after the DUT2 egress
    # SVI+LAG churn in Step 1.7. The diagnosis driving that was the
    # 2c HARD gate in _smoke_preflight (test_dscp_to_tc_overlay.py)
    # which asserted that `show vxlan tunnel`'s `destination ip`
    # column must be non-blank for the peer VTEP.
    #
    # That diagnosis was WRONG. The May-17 known-good run
    # (smoke_one_l3vni.log) shows the same blank `destination ip`
    # column for the EVPN-learned remote VTEP, yet had a clean Q2
    # PASS on DUT2 egress -- VXLAN was forwarding correctly. The
    # column is populated only for STATICALLY configured remote
    # VTEPs in this SONiC build; for EVPN-learned VTEPs it stays
    # blank by design, and that's not a signal of failure. The 2c
    # gate has been removed and replaced with an informational
    # `show vxlan tunnel` dump in _smoke_preflight.
    #
    # Per project policy, we do NOT reprogram VXLAN at runtime.
    # VXLAN is configured ONCE by _setup_vxlan_l3vni() and the
    # entire teardown is the responsibility of that function's
    # registered teardown closure. The static ARP install in Step 9
    # below remains -- it operates purely on the kernel L2 plane
    # (`ip neigh add` on Vlan100 in VrfQoS) and does not touch any
    # VXLAN config, so it does not violate the no-VXLAN-reprogramming
    # policy.

    # ────────────────────────────────────────────────────────────
    # Teardown (reverse order: BGP knobs -> counterpoll -> SVI)
    # ────────────────────────────────────────────────────────────
    def _teardown():
        # Reverse step 3: best-effort restore of BGP / NHT knobs.
        # We use 'no ...' for each line we pushed; if a knob was
        # already at default before our push, the 'no' is a no-op,
        # which FRR tolerates silently.
        def _revert_bgp_knobs(dut_handle, local_as, label):
            lines = ['router bgp {}'.format(local_as)]
            if _LEAF0_BGP_DISABLE_CONN_CHECK:
                lines.append('  no bgp disable-ebgp-connected-route-check')
            if _LEAF0_BGP_MPATH_RELAX:
                lines.append('  no bgp bestpath as-path multipath-relax')
            lines.append('exit')
            if _LEAF0_NHT_RESOLVE_OFF:
                lines.append('ip nht resolve-via-default')
                lines.append('ipv6 nht resolve-via-default')
            if (not _LEAF0_BGP_DISABLE_CONN_CHECK
                    and not _LEAF0_BGP_MPATH_RELAX
                    and not _LEAF0_NHT_RESOLVE_OFF):
                return
            cfg = '\n'.join(lines) + '\n'
            st.log("  leaf0-style teardown: reverting BGP knobs on {}"
                   .format(label))
            st.config(dut_handle, cfg, type='vtysh',
                      skip_error_check=True)

        _revert_bgp_knobs(dut_h, _I_BGP_AS1, 'DUT1')
        if dut2_h:
            _revert_bgp_knobs(dut2_h, _I_BGP_AS2, 'DUT2')

        # Reverse step 2: counterpoll tunnel disable on both DUTs.
        # Default state on this platform is 'disabled'; we reset.
        if _LEAF0_COUNTERPOLL_TUNNEL:
            st.config(dut_h, 'counterpoll tunnel disable',
                      skip_error_check=True)
            if dut2_h:
                st.config(dut2_h, 'counterpoll tunnel disable',
                          skip_error_check=True)

        # Reverse step 1.7: DUT2 egress SVI+LAG teardown (if step 1.7
        # ran). Strict ordering:
        #   (a) restore dut2_port_info['egress_ixia'] FIRST -- a
        #       lingering swapped-to-LAG name in dut2_port_info would
        #       point at a deleted LAG after step (c), and any later
        #       access from a parametrized teardown that pytest re-runs
        #       due to a finalizer-ordering quirk would crash. Restoring
        #       before the LAG-delete is always safe (the physical port
        #       is always valid).
        #   (b) DUT2 LAG-wrap teardown (LIFO of cleanup_steps) BEFORE
        #       the SVI teardown, same reason as DUT1: the SVI teardown
        #       expects to find Vlan{vid} tagged-membership on the
        #       physical port (so its `config vlan member del <vid>
        #       <physical_port>` lines up), and the LAG-wrap teardown's
        #       last step is exactly that re-attach.
        #   (c) DUT2 SVI teardown (remove SVI IPs, unbind SVI VRF,
        #       drop physical port from Vlan, delete Vlan, re-bind
        #       physical port to VrfQoS, re-add EGRESS IPs, defensive
        #       PORT_QOS_MAP HSET).
        # This sub-block runs AFTER the counterpoll-disable (above)
        # and BEFORE the DUT1-side Ixia-LAG / LAG / SVI teardowns
        # (below) because the two LAG stacks are on different DUTs
        # and have no cross-dependency -- cleaning DUT2 first keeps
        # the box in a recognisable state for the DUT1 teardown logs.
        if saved_egress_ixia is not None:
            dut2_port_info['egress_ixia']          = saved_egress_ixia
            _overlay.dut2_port_info['egress_ixia'] = saved_egress_ixia
            st.log("  leaf0-style teardown: dut2_port_info["
                   "'egress_ixia'] restored to {}"
                   .format(saved_egress_ixia))
        if teardown_egress_lag is not None:
            try:
                teardown_egress_lag()
            except Exception as exc:
                st.warn("leaf0-style teardown: DUT2 egress LAG-wrap "
                        "helper raised: {}".format(exc))
        if teardown_egress_svi is not None:
            try:
                teardown_egress_svi()
            except Exception as exc:
                st.warn("leaf0-style teardown: DUT2 egress SVI "
                        "helper raised: {}".format(exc))

        # Reverse step 1.6: Ixia LAG-wrap teardown (if step 1.6 ran).
        # MUST run BEFORE the DUT LAG teardown so the Ixia side
        # tears down its topology object while the DUT-side LAG is
        # still operational -- IxNetwork can occasionally emit a
        # last LAG-state-change frame on lag-delete, and we don't
        # want that frame hitting a half-torn-down DUT LAG. Also
        # MUST restore tg_ph[] back to the physical handle here so
        # any later access (e.g. from a parametrized teardown that
        # gets re-run by pytest because of a fixture finalizer
        # ordering quirk) sees a self-consistent state.
        if teardown_ixia_lag is not None:
            try:
                teardown_ixia_lag()
            except Exception as exc:
                st.warn("leaf0-style teardown: Ixia LAG-wrap "
                        "helper raised: {}".format(exc))
            # Restore tg_ph regardless of whether lag-delete
            # succeeded -- a lingering swapped handle in tg_ph[]
            # would point at a deleted LAG object, which is
            # strictly worse than restoring it back to the
            # physical handle (which is always valid).
            if saved_ingress_ph is not None:
                tg_ph['ingress'] = saved_ingress_ph
                _overlay.tg_ph['ingress'] = saved_ingress_ph
            if saved_ingress_a is not None:
                tg_ph['ingress_a'] = saved_ingress_a
                _overlay.tg_ph['ingress_a'] = saved_ingress_a
            st.log("  leaf0-style teardown: tg_ph['ingress'] "
                   "restored to {}".format(saved_ingress_ph))

        # Reverse step 1.5: DUT LAG-wrap teardown (if step 1.5 ran).
        # MUST run *before* the SVI teardown -- the SVI teardown
        # expects to find Vlan{vid} tagged-membership on the
        # physical port (so its `config vlan member del <vid>
        # <physical_port>` lines up with the actual config), and
        # the LAG-wrap teardown's last step is exactly that
        # re-attach.
        if teardown_lag is not None:
            try:
                teardown_lag()
            except Exception as exc:
                st.warn("leaf0-style teardown: DUT LAG-wrap "
                        "helper raised: {}".format(exc))

        # Reverse step 1: SVI teardown (delegated). The canonical
        # helper's teardown re-binds the physical port to the
        # L3VNI VRF, restores the V4/V6 IPs, and re-asserts the
        # PORT_QOS_MAP|<port>.dscp_to_tc_map=AZURE binding.
        if teardown_svi is not None:
            try:
                teardown_svi()
            except Exception as exc:
                st.warn("leaf0-style teardown: tagged-SVI helper "
                        "raised: {}".format(exc))

    return _teardown


# ══════════════════════════════════════════════════════════════════
# Test class
# ══════════════════════════════════════════════════════════════════

class TestSmokeL3VNIPortChannelLeaf0:
    """16 smoke instances over an L3VNI path configured leaf0-style.

    Wire shape is identical to ``TestSmokeL3VNITagged`` (tagged-SVI
    ingress in an L3VNI VRF), so we reuse ``mode='l3vni_tagged'`` in
    ``_smoke_run_one``. The delta over that class is purely on the
    *setup* side -- this class additionally programs the leaf0-flavor
    knobs documented in the module docstring above.

    Per-instance assertions (inherited unchanged from
    ``_smoke_run_one(mode='l3vni_tagged')``):
      * L3 family preserved (ipv4 or ipv6)
      * DSCP preserved through encap+decap
      * TTL_rx == TTL_tx - 2 (SVI L3 + DUT2 egress L3)
      * has_vxlan_header == False on RX (decap stripped VXLAN)
      * UDP dport == 5000 + DSCP (test-stream identity)
      * 802.1Q tag on TX side, untagged on RX (asymmetric '*' marker)

    """

    @pytest.fixture(scope="class", autouse=True)
    def _setup_l3vni_leaf0(self):
        if topo_mode == 'ixia':
            pytest.skip(
                "Smoke L3VNI-leaf0-style requires 2-DUT topology "
                "(peer_link/breakout); current mode is 'ixia'")

        # Layer order (mirrors TestSmokeL3VNITagged):
        #   1. Bring up the underlay+overlay (VXLAN, BGP-EVPN, VRF,
        #      VTEPs) via the legacy zero-arg shim. The shim
        #      frame-walks back to *this* module's globals (populated
        #      by setup_topo above) -- this is why this module owns
        #      its own dut/dut2/port_info/... assignments rather than
        #      reaching into _overlay at fixture-run-time.
        #   2. Layer leaf0-flavor knobs on top.
        # Teardown is reversed.
        teardown_vxlan = _setup_vxlan_l3vni()
        teardown_leaf0 = None
        try:
            teardown_leaf0 = _setup_leaf0_style_overlay()
            # Pre-flight uses the same 'l3vni_tagged' mode as the
            # sibling tagged class -- the SVI-on-VRF + EVPN-route
            # checks are exactly what we want to verify before
            # firing traffic. Future leaf0-specific preflight rules
            # (eg "tunnel counterpoll shows non-zero polling state")
            # can hang off a new mode token without touching this
            # fixture.
            _overlay._smoke_preflight('l3vni_tagged')
            yield
        finally:
            if teardown_leaf0 is not None:
                try:
                    teardown_leaf0()
                except Exception as exc:
                    st.warn("_setup_leaf0_style_overlay teardown "
                            "raised: {}".format(exc))
            try:
                teardown_vxlan()
            except Exception as exc:
                st.warn("_setup_vxlan_l3vni teardown raised: {}"
                        .format(exc))

    @pytest.mark.parametrize("af", ["ipv4", "ipv6"])
    @pytest.mark.parametrize("tc_dscp",
                             _overlay._smoke_pairs(),
                             ids=_overlay._smoke_pair_ids())
    def test_dscp_to_tc_smoke_l3vni_leaf0_ucast(self, af, tc_dscp):
        """SMOKE-L3VNI-LEAF0-UCAST -- 5 unicast tagged packets at one
        DSCP through a leaf0-style L3VNI tagged-SVI ingress.

        See the class docstring for the full assertion list. Test
        node-IDs match the pattern of the sibling smoke classes:
        ``test_dscp_to_tc_smoke_l3vni_leaf0_ucast[<af>][tc<N>-dscp<M>]``.
        """
        tc, dscp = tc_dscp
        test_label = ("SMOKE-L3VNI-LEAF0-UCAST[{}][tc{}-dscp{}]"
                      .format(af, tc, dscp))
        print_section(
            "{} - {} pkts via VxLAN L3VNI leaf0-style "
            "(vni={}, vrf={})".format(
                test_label, _overlay._SMOKE_PKTS_PER_BURST,
                _I_VNI, _I_VRF),
            art_key='dscp_to_tc')

        hard_failures, soft_warns = _overlay._smoke_run_one(
            test_label, af, dscp,
            expected_tc=tc, mode='l3vni_tagged')

        if hard_failures:
            st.report_fail('msg',
                "{} HARD failures ({}):\n  ".format(
                    test_label, len(hard_failures))
                + "\n  ".join(hard_failures))
        st.report_pass('msg',
            "{}: {} pkts L3VNI-leaf0 UC e2e PASS (soft_warns={})"
            .format(test_label, _overlay._SMOKE_PKTS_PER_BURST,
                    len(soft_warns)))


# ══════════════════════════════════════════════════════════════════
# L2VNI LAG-wrap helper (single-member LACP w/ fallback, untagged)
# ══════════════════════════════════════════════════════════════════

def _wrap_l2vni_ingress_in_lag(dut_h, physical_port, lag_name, vlan_id):
    """Wrap an existing L2VNI untagged-access ingress port in a
    single-member LACP PortChannel with LACP fallback enabled.

    Mirrors _wrap_l3vni_ingress_in_lag for the L2VNI path. The key
    difference is that the physical_port is an UNTAGGED (access)
    VLAN member (config vlan member add <vlan> <port> --untagged),
    not a tagged-trunk member backing an SVI. The LAG wrap migrates
    that untagged membership from the physical port to the LAG,
    preserving the L2 forwarding path for BUM/unicast L2VNI frames.

    Pre-conditions (caller has run _setup_vxlan_l2vni() first):
      * Vlan{vlan_id} exists (L2VNI access VLAN).
      * physical_port is an UNTAGGED member of Vlan{vlan_id}.
      * PORT_QOS_MAP|<physical_port>.dscp_to_tc_map = AZURE is bound.

    Post-conditions after this helper returns:
      * lag_name is created with --fallback=true.
      * physical_port is the LAG's only member.
      * Vlan{vlan_id} UNTAGGED membership migrated from
        physical_port to lag_name.
      * PORT_QOS_MAP|<lag_name>.dscp_to_tc_map = AZURE is HSET.
      * 10s convergence wait completed for LACP fallback.

    Returns a teardown callable that reverses every step executed.
    """
    from apis.switching.portchannel import (
        create_portchannel, add_portchannel_member,
        delete_portchannel_member, delete_portchannel,
    )

    st.log("  leaf0 L2VNI LAG-wrap: migrating L2VNI ingress {} -> {} "
           "(LACP w/ fallback, single-member, Vlan{} untagged-"
           "membership follows)".format(physical_port, lag_name,
                                        vlan_id))

    cleanup_steps = []

    def _teardown():
        st.log("  leaf0 L2VNI LAG-wrap teardown: unwrapping "
               "(steps: {})".format(len(cleanup_steps)))
        for step_label, step_fn in reversed(cleanup_steps):
            try:
                step_fn()
            except Exception as exc:
                st.warn("leaf0 L2VNI LAG-wrap teardown: step '{}' "
                        "raised: {} (continuing)"
                        .format(step_label, exc))
        st.log("  leaf0 L2VNI LAG-wrap teardown: done")

    # 0. Pre-step: remove any stale INTERFACE|<physical_port> entry
    #    from CONFIG_DB. _setup_vxlan_l2vni() may leave this behind
    #    from the L3->L2 port conversion, and its presence blocks
    #    the subsequent vlan member add on some SONiC builds.
    st.config(dut_h,
        'sonic-db-cli CONFIG_DB DEL "INTERFACE|{}"'.format(physical_port),
        skip_error_check=True)
    st.wait(1)

    # 1. Detach physical port from Vlan{vid} (untagged).
    st.config(dut_h,
        'config vlan member del {} {}'.format(vlan_id, physical_port),
        skip_error_check=True)
    st.wait(1)
    cleanup_steps.append((
        'vlan member add {} {} --untagged'.format(vlan_id, physical_port),
        lambda: st.config(dut_h,
            'config vlan member add {} {} --untagged'.format(
                vlan_id, physical_port),
            skip_error_check=True)))

    # 2. Create the LAG with LACP fallback.
    pc_ok = create_portchannel(dut_h, [lag_name], fallback=True)
    cleanup_steps.append((
        'delete_portchannel({})'.format(lag_name),
        lambda: delete_portchannel(dut_h, [lag_name], skip_error=True)))
    if not pc_ok:
        st.error("leaf0 L2VNI LAG-wrap: create_portchannel({}, "
                 "fallback=True) returned False -- aborting wrap and "
                 "executing teardown".format(lag_name))
        _teardown()
        raise RuntimeError("L2VNI LAG-wrap setup failed: "
                           "create_portchannel returned False for {}"
                           .format(lag_name))
    st.wait(2)

    # 2b. Verify fallback is enabled in CONFIG_DB.
    fb_check = st.show(dut_h,
        'sonic-db-cli CONFIG_DB HGET "PORTCHANNEL|{}" "fallback"'
        .format(lag_name), skip_tmpl=True) or ''
    if 'true' not in fb_check.lower():
        st.error("leaf0 L2VNI LAG-wrap: CONFIG_DB|PORTCHANNEL|{}."
                 "fallback is NOT 'true' (got: {!r}). Without fallback "
                 "the lone member stays in LACP_DEFAULTED and traffic "
                 "is silently dropped. Executing teardown."
                 .format(lag_name, fb_check.strip()))
        _teardown()
        raise RuntimeError("L2VNI LAG-wrap setup failed: fallback not "
                           "enabled on {}".format(lag_name))
    st.log("  leaf0 L2VNI LAG-wrap: confirmed fallback=true on {}"
           .format(lag_name))

    # 3. Bind physical port as the only LAG member.
    if not add_portchannel_member(dut_h, lag_name, [physical_port]):
        st.error("leaf0 L2VNI LAG-wrap: add_portchannel_member({}, "
                 "[{}]) returned False -- aborting wrap and executing "
                 "teardown".format(lag_name, physical_port))
        _teardown()
        raise RuntimeError("L2VNI LAG-wrap setup failed: "
                           "add_portchannel_member returned False for {} "
                           "member {}".format(lag_name, physical_port))
    cleanup_steps.append((
        'delete_portchannel_member({}, [{}])'.format(
            lag_name, physical_port),
        lambda: delete_portchannel_member(
            dut_h, lag_name, [physical_port])))
    st.wait(1)

    # 4. Re-attach Vlan{vid} UNTAGGED membership to the LAG.
    st.config(dut_h,
        'config vlan member add {} {} --untagged'.format(
            vlan_id, lag_name),
        skip_error_check=True)
    cleanup_steps.append((
        'vlan member del {} {}'.format(vlan_id, lag_name),
        lambda: st.config(dut_h,
            'config vlan member del {} {}'.format(vlan_id, lag_name),
            skip_error_check=True)))

    # 5. Defensively HSET the LAG-level dscp_to_tc_map binding.
    st.config(dut_h,
        'sonic-db-cli CONFIG_DB HSET "PORT_QOS_MAP|{}" '
        '"dscp_to_tc_map" "AZURE"'.format(lag_name),
        skip_error_check=True)
    cleanup_steps.append((
        'HDEL PORT_QOS_MAP|{}'.format(lag_name),
        lambda: st.config(dut_h,
            'sonic-db-cli CONFIG_DB HDEL "PORT_QOS_MAP|{}" '
            '"dscp_to_tc_map"'.format(lag_name),
            skip_error_check=True)))

    # 6. Wait for LACP fallback convergence (~3s Short Timeout + margin).
    st.wait(10)

    # 7. Post-check: confirm kernel netdev is UP+LOWER_UP.
    link_check = st.show(dut_h,
        'ip link show {} 2>&1 | head -2'.format(lag_name),
        skip_tmpl=True) or ''
    if 'LOWER_UP' in link_check and 'state UP' in link_check:
        st.log("  leaf0 L2VNI LAG-wrap: {} UP+LOWER_UP after fallback "
               "wait -- bundle active, ready to forward"
               .format(lag_name))
    else:
        st.warn("leaf0 L2VNI LAG-wrap: {} not fully up after 10s "
                "LACP-fallback wait. ip link: {!r}. Downstream "
                "traffic will likely show 0 RX."
                .format(lag_name, link_check.strip()))

    st.log("  leaf0 L2VNI LAG-wrap: done -- {} now backs Vlan{} "
           "untagged-access ingress (member: {}, LACP fallback active)"
           .format(lag_name, vlan_id, physical_port))

    return _teardown


# ══════════════════════════════════════════════════════════════════
# L2VNI leaf0-style setup helper
# ══════════════════════════════════════════════════════════════════

def _setup_leaf0_style_l2vni():
    """Layer leaf0-flavor knobs on top of the base L2VNI fabric.

    Pre-conditions: caller has already invoked _setup_vxlan_l2vni()
    so the L2VNI VTEP, EVPN session, VLAN binding and DSCP-to-TC
    map are all in place. We augment that state without replacing it.

    Steps:
      1. Wrap the L2VNI ingress (port_info['ingress_b']) in a
         LACP+fallback PortChannel0002 -- mirrors the L3VNI
         LAG-wrap but uses --untagged VLAN membership (L2 access
         port) rather than tagged-SVI membership.
      2. counterpoll tunnel enable on both DUTs.
      3. BGP policy knobs on both DUTs (same as L3VNI leaf0).

    Returns a teardown callable that reverses every step.
    """
    dut_h  = dut
    dut2_h = dut2
    if not dut_h:
        st.log("  leaf0 L2VNI-style: no DUT1 -- skipping")
        return lambda: None

    ingress_b = port_info.get('ingress_b')
    teardown_lag = None
    if not ingress_b:
        st.warn("leaf0 L2VNI-style: port_info['ingress_b'] not "
                "available -- L2VNI LAG-wrap requires a dedicated "
                "L2VNI ingress port (Ethernet1_50 on breakout "
                "testbed). Skipping LAG-wrap.")
    else:
        if _LEAF0_LAG_INGRESS_L2VNI:
            teardown_lag = _wrap_l2vni_ingress_in_lag(
                dut_h         = dut_h,
                physical_port = ingress_b,
                lag_name      = _LEAF0_LAG_NAME_L2VNI,
                vlan_id       = _J_L2_VLAN,
            )
        else:
            st.log("  leaf0 L2VNI-style: VXLAN_LEAF0_LAG_INGRESS_L2VNI=0 "
                   "-- L2VNI ingress stays on physical port {} "
                   "(set VXLAN_LEAF0_LAG_INGRESS_L2VNI=1 to wrap into "
                   "LACP+fallback {})"
                   .format(ingress_b, _LEAF0_LAG_NAME_L2VNI))

    # Step 1b: Wrap DUT2 egress (egress_ixia) in a PortChannel.
    #   Mirrors the DUT1 ingress LAG-wrap on the decap side so that
    #   both sides of the L2VNI path are PortChannel-based (symmetric
    #   leaf0 shape). Uses the same _wrap_l2vni_ingress_in_lag helper
    #   since the operation is identical (untagged Vlan502 member
    #   migration to a single-member LACP+fallback LAG).
    #
    #   Wrap the helper call in try/except so a create_portchannel/
    #   add_portchannel_member failure does NOT escape this function
    #   with teardown_lag from Step 1 unregistered. If DUT2 egress wrap
    #   raises, invoke teardown_lag to undo the DUT1 ingress LAG wrap
    #   before re-raising.
    teardown_egress_lag = None
    if _LEAF0_LAG_EGRESS_L2VNI and dut2_h and dut2_port_info.get('egress_ixia'):
        dut2_egress_phys = dut2_port_info['egress_ixia']
        st.log("  leaf0 L2VNI-style: wrapping DUT2 egress {} -> {} "
               "(LACP+fallback, Vlan{} untagged, mirrors DUT1 ingress)"
               .format(dut2_egress_phys, _LEAF0_LAG_NAME_L2VNI_EGRESS,
                       _J_L2_VLAN))
        try:
            teardown_egress_lag = _wrap_l2vni_ingress_in_lag(
                dut_h         = dut2_h,
                physical_port = dut2_egress_phys,
                lag_name      = _LEAF0_LAG_NAME_L2VNI_EGRESS,
                vlan_id       = _J_L2_VLAN,
            )
        except BaseException as exc_egress:
            st.warn("  leaf0 L2VNI-style: _wrap_l2vni_ingress_in_lag "
                    "(DUT2 egress) raised {}: {}. LAG helper already "
                    "executed its own _teardown() to undo partial LAG "
                    "steps; now invoking teardown_lag to undo Step 1 "
                    "DUT1 ingress LAG wrap before re-raising."
                    .format(type(exc_egress).__name__, exc_egress))
            if teardown_lag is not None:
                try:
                    teardown_lag()
                except Exception as exc:
                    st.warn("  teardown_lag raised: {} (continuing)"
                            .format(exc))
            raise
        # Keep dut2_port_info['egress_ixia'] on the PHYSICAL member port
        # (do NOT rebind to LAG name).  dchal_qi.py and `show queue
        # counters` on FX3 only resolve physical ports from
        # platform.json; LAG names like PortChannel0002 would produce
        # "Port doesn't exist!" and false q[N]=0 readings.  Same
        # pattern as L3VNI _setup_egress_svi_dut2() which keeps
        # egress_ixia at Ethernet1_49.
        st.log("  leaf0 L2VNI-style: DUT2 egress LAG wrap complete -- "
               "dut2_port_info['egress_ixia'] KEPT at {} (physical "
               "member). Queue counters will read the member port."
               .format(dut2_egress_phys))
    elif not _LEAF0_LAG_EGRESS_L2VNI:
        st.log("  leaf0 L2VNI-style: VXLAN_LEAF0_LAG_EGRESS_L2VNI=0 "
               "-- DUT2 egress stays on physical port (set "
               "VXLAN_LEAF0_LAG_EGRESS_L2VNI=1 to wrap)")

    # Step 2: counterpoll tunnel enable on both DUTs.
    if _LEAF0_COUNTERPOLL_TUNNEL:
        st.config(dut_h, 'counterpoll tunnel enable',
                  skip_error_check=True)
        if dut2_h:
            st.config(dut2_h, 'counterpoll tunnel enable',
                      skip_error_check=True)

    # Step 3: BGP policy knobs on both DUTs.
    def _push_bgp_knobs(dut_handle, local_as, label):
        lines = ['router bgp {}'.format(local_as)]
        if _LEAF0_BGP_DISABLE_CONN_CHECK:
            lines.append('  bgp disable-ebgp-connected-route-check')
        if _LEAF0_BGP_MPATH_RELAX:
            lines.append('  bgp bestpath as-path multipath-relax')
        lines.append('exit')
        if (not _LEAF0_BGP_DISABLE_CONN_CHECK
                and not _LEAF0_BGP_MPATH_RELAX):
            return
        cfg = '\n'.join(lines) + '\n'
        st.log("  leaf0 L2VNI-style: pushing BGP knobs on {} "
               "(local_as={})".format(label, local_as))
        st.config(dut_handle, cfg, type='vtysh',
                  skip_error_check=True)

    _push_bgp_knobs(dut_h, _I_BGP_AS1, 'DUT1')
    if dut2_h:
        _push_bgp_knobs(dut2_h, _I_BGP_AS2, 'DUT2')
    st.wait(2)

    def _teardown():
        # Reverse step 3: revert BGP knobs.
        def _revert_bgp_knobs(dut_handle, local_as, label):
            lines = ['router bgp {}'.format(local_as)]
            if _LEAF0_BGP_DISABLE_CONN_CHECK:
                lines.append('  no bgp disable-ebgp-connected-route-check')
            if _LEAF0_BGP_MPATH_RELAX:
                lines.append('  no bgp bestpath as-path multipath-relax')
            lines.append('exit')
            if (not _LEAF0_BGP_DISABLE_CONN_CHECK
                    and not _LEAF0_BGP_MPATH_RELAX):
                return
            cfg = '\n'.join(lines) + '\n'
            st.log("  leaf0 L2VNI-style teardown: reverting BGP knobs "
                   "on {}".format(label))
            st.config(dut_handle, cfg, type='vtysh',
                      skip_error_check=True)

        _revert_bgp_knobs(dut_h, _I_BGP_AS1, 'DUT1')
        if dut2_h:
            _revert_bgp_knobs(dut2_h, _I_BGP_AS2, 'DUT2')

        # Reverse step 2: counterpoll tunnel disable.
        if _LEAF0_COUNTERPOLL_TUNNEL:
            st.config(dut_h, 'counterpoll tunnel disable',
                      skip_error_check=True)
            if dut2_h:
                st.config(dut2_h, 'counterpoll tunnel disable',
                          skip_error_check=True)

        # Reverse step 1b: DUT2 egress LAG-wrap teardown.
        if teardown_egress_lag is not None:
            try:
                teardown_egress_lag()
            except Exception as exc:
                st.warn("leaf0 L2VNI-style teardown: DUT2 egress "
                        "LAG-wrap helper raised: {}".format(exc))

        # Reverse step 1: LAG-wrap teardown.
        if teardown_lag is not None:
            try:
                teardown_lag()
            except Exception as exc:
                st.warn("leaf0 L2VNI-style teardown: LAG-wrap "
                        "helper raised: {}".format(exc))

    return _teardown


# ══════════════════════════════════════════════════════════════════
# L2VNI leaf0-style test classes
# ══════════════════════════════════════════════════════════════════

class TestSmokeL2VNIPortChannelLeaf0Bum:
    """16 smoke instances over an L2VNI BUM-flood path configured
    leaf0-style (LAG-ingress + leaf0 BGP knobs).

    Mirrors TestSmokeL2VNIBum from test_dscp_to_tc_overlay.py but
    layers the same leaf0-flavor knobs as TestSmokeL3VNIPortChannelLeaf0:
      * L2VNI ingress (Ethernet1_50 / ingress_b) wrapped in
        PortChannel0002 (LACP+fallback, single-member).
      * counterpoll tunnel enable on both DUTs.
      * BGP policy knobs (disable-ebgp-connected-route-check,
        bestpath multipath-relax) on both DUTs.

    The L2VNI ingress is placed in VLAN-access (untagged) mode by
    _setup_vxlan_l2vni(); the LAG-wrap migrates that untagged
    membership from Ethernet1_50 to PortChannel0002.

    Wire shape (BUM path):
      * DUT1 receives untagged frames on PortChannel0002, L2VNI-
        encapsulates them and forwards to DUT2 over the VTEP tunnel.
      * DUT2 floods the inner frame on Vlan{_J_L2_VLAN} -- BUM path
        (dst_mac=ff:ff:ff:ff:ff:ff, primary_queue_col='mc').
      * Ixia RX port (DUT2 egress) captures the decapped frame.
    """

    @pytest.fixture(scope="class", autouse=True)
    def _setup_l2vni_leaf0(self):
        if topo_mode == 'ixia':
            pytest.skip(
                "Smoke L2VNI-leaf0-BUM requires 2-DUT topology "
                "(peer_link/breakout); current mode is 'ixia'")
        if not port_info.get('ingress_b'):
            pytest.skip(
                "Smoke L2VNI-leaf0-BUM requires a dedicated L2VNI "
                "ingress port (ingress_b / Ethernet1_50); not present "
                "in this testbed")

        # Reset IxNetwork topology state from any prior class.
        if tg is not None:
            try:
                tg.clean_all()
            except Exception as exc:
                st.warn("_setup_l2vni_leaf0: pre-class clean_all raised "
                        "(non-fatal): {}".format(exc))

        teardown_vxlan = _setup_vxlan_l2vni()
        teardown_leaf0 = None
        try:
            teardown_leaf0 = _setup_leaf0_style_l2vni()
            _overlay._smoke_preflight('l2vni')
            yield
        finally:
            if teardown_leaf0 is not None:
                try:
                    teardown_leaf0()
                except Exception as exc:
                    st.warn("_setup_leaf0_style_l2vni teardown "
                            "raised: {}".format(exc))
            try:
                teardown_vxlan()
            except Exception as exc:
                st.warn("_setup_vxlan_l2vni teardown raised: {}"
                        .format(exc))

    @pytest.mark.parametrize("af", ["ipv4", "ipv6"])
    @pytest.mark.parametrize("tc_dscp",
                             _overlay._smoke_pairs(),
                             ids=_overlay._smoke_pair_ids())
    def test_dscp_to_tc_smoke_l2vni_leaf0_bum(self, af, tc_dscp):
        """SMOKE-L2VNI-LEAF0-BUM -- 5 BUM packets at one DSCP through
        a leaf0-style L2VNI LAG-ingress (PortChannel0002) path.

        Per-instance assertions (inherited from _smoke_run_one):
          * L3 family preserved (ipv4 or ipv6)
          * DSCP preserved through encap+decap
          * TTL_rx == TTL_tx (L2VNI bridges -- no TTL decrement)
          * has_vxlan_header == False on RX (decap stripped VXLAN)
          * UDP dport == 5000 + DSCP (test-stream identity)
          * DCHAL queue [TC] sees MC pkts >= burst (BUM floods as MC)
        """
        tc, dscp = tc_dscp
        test_label = ("SMOKE-L2VNI-LEAF0-BUM[{}][tc{}-dscp{}]"
                      .format(af, tc, dscp))
        print_section(
            "{} - {} BUM pkts via VxLAN L2VNI leaf0-style "
            "(vni={})".format(
                test_label, _overlay._SMOKE_PKTS_PER_BURST,
                _J_VNI),
            art_key='dscp_to_tc')

        hard_failures, soft_warns = _overlay._smoke_run_one(
            test_label, af, dscp,
            expected_tc=tc, mode='l2vni',
            l2vni_force_bum=True)

        if hard_failures:
            st.report_fail('msg',
                "{} HARD failures ({}):\n  ".format(
                    test_label, len(hard_failures))
                + "\n  ".join(hard_failures))
        st.report_pass('msg',
            "{}: {} pkts L2VNI-leaf0 BUM e2e PASS (soft_warns={})"
            .format(test_label, _overlay._SMOKE_PKTS_PER_BURST,
                    len(soft_warns)))


class TestSmokeL2VNIPortChannelLeaf0Ucast:
    """16 smoke instances over an L2VNI unicast path configured
    leaf0-style (LAG-ingress + leaf0 BGP knobs).

    Mirrors TestSmokeL2VNIUcast from test_dscp_to_tc_overlay.py with
    the same leaf0-flavor additive knobs as the BUM variant above.
    Uses EVPN-learned remote MAC (Type-2) for unicast forwarding.
    Gates on EVPN-MAC convergence via l2vni_gate_unicast=True so
    unconverged runs are reported as unsupported rather than failing.
    """

    @pytest.fixture(scope="class", autouse=True)
    def _setup_l2vni_leaf0_ucast(self):
        if topo_mode == 'ixia':
            pytest.skip(
                "Smoke L2VNI-leaf0-Ucast requires 2-DUT topology "
                "(peer_link/breakout); current mode is 'ixia'")
        if not port_info.get('ingress_b'):
            pytest.skip(
                "Smoke L2VNI-leaf0-Ucast requires a dedicated L2VNI "
                "ingress port (ingress_b / Ethernet1_50); not present "
                "in this testbed")

        # Reset IxNetwork topology state from any prior class.
        if tg is not None:
            try:
                tg.clean_all()
            except Exception as exc:
                st.warn("_setup_l2vni_leaf0_ucast: pre-class clean_all "
                        "raised (non-fatal): {}".format(exc))

        teardown_vxlan = _setup_vxlan_l2vni()
        teardown_leaf0 = None
        try:
            teardown_leaf0 = _setup_leaf0_style_l2vni()
            _overlay._smoke_preflight('l2vni')
            yield
        finally:
            if teardown_leaf0 is not None:
                try:
                    teardown_leaf0()
                except Exception as exc:
                    st.warn("_setup_leaf0_style_l2vni teardown "
                            "raised: {}".format(exc))
            try:
                teardown_vxlan()
            except Exception as exc:
                st.warn("_setup_vxlan_l2vni teardown raised: {}"
                        .format(exc))

    @pytest.mark.parametrize("af", ["ipv4", "ipv6"])
    @pytest.mark.parametrize("tc_dscp",
                             _overlay._smoke_pairs(),
                             ids=_overlay._smoke_pair_ids())
    def test_dscp_to_tc_smoke_l2vni_leaf0_ucast(self, af, tc_dscp):
        """SMOKE-L2VNI-LEAF0-UCAST -- 5 unicast packets via a
        leaf0-style L2VNI LAG-ingress (PortChannel0002) path.
        EVPN-MAC gated: unconverged runs are reported as unsupported.
        """
        tc, dscp = tc_dscp
        test_label = ("SMOKE-L2VNI-LEAF0-UCAST[{}][tc{}-dscp{}]"
                      .format(af, tc, dscp))
        print_section(
            "{} - {} UC pkts via VxLAN L2VNI leaf0-style "
            "(vni={})".format(
                test_label, _overlay._SMOKE_PKTS_PER_BURST,
                _J_VNI),
            art_key='dscp_to_tc')

        hard_failures, soft_warns = _overlay._smoke_run_one(
            test_label, af, dscp,
            expected_tc=tc, mode='l2vni',
            l2vni_gate_unicast=True)

        # ── Enforce DUT2 egress queue validation ──────────────────
        # Do NOT let the test pass on majority-verdict alone if DUT2
        # egress queue counters are missing or zero.  The whole point
        # of the DUT2 egress PortChannel wrap is to validate that
        # decapped traffic hits the correct queue on the egress LAG
        # member port.  Mirror L3VNI which always has dut2_cli as a
        # PASS witness.
        dut2_egress_port = (_overlay.dut2_port_info or {}).get(
            'egress_ixia')
        if dut2_egress_port and _LEAF0_LAG_EGRESS_L2VNI:
            # Safely access _smoke_cli_q_snaps (may not exist in overlay module)
            cli_q_snaps = getattr(_overlay, '_smoke_cli_q_snaps', {})
            cli_stash = cli_q_snaps.get(test_label) or {}
            after_snap = (cli_stash.get('after') or {}).get(
                (_overlay.dut2, dut2_egress_port))
            before_snap = (cli_stash.get('before') or {}).get(
                (_overlay.dut2, dut2_egress_port))
            # Compute delta for the expected TC queue.
            dut2_tc_pkts = 0
            if after_snap and before_snap:
                aq = (after_snap.get(tc) or {})
                bq = (before_snap.get(tc) or {})
                dut2_tc_pkts = max(0,
                    int(aq.get('pkts', 0)) - int(bq.get('pkts', 0)))
            elif after_snap:
                dut2_tc_pkts = int(
                    (after_snap.get(tc) or {}).get('pkts', 0))

            st.log("  {} DUT2 egress Q{} validation: {} pkts on {}"
                   .format(test_label, tc, dut2_tc_pkts,
                           dut2_egress_port))

            if dut2_tc_pkts == 0:
                hard_failures.append(
                    "{}: DUT2 egress queue counters on {} show 0 "
                    "pkts on Q{} -- traffic did NOT egress the "
                    "PortChannel member port as expected (queue "
                    "counter read may have failed or decap path is "
                    "broken)".format(test_label, dut2_egress_port, tc))
        # ──────────────────────────────────────────────────────────

        if hard_failures:
            st.report_fail('msg',
                "{} HARD failures ({}):\n  ".format(
                    test_label, len(hard_failures))
                + "\n  ".join(hard_failures))
        st.report_pass('msg',
            "{}: {} pkts L2VNI-leaf0 UC e2e PASS (soft_warns={})"
            .format(test_label, _overlay._SMOKE_PKTS_PER_BURST,
                    len(soft_warns)))
