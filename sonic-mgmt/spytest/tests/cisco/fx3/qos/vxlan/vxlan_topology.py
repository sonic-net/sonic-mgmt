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

"""VxLAN QoS topology constants.

Single source of truth for VTEP IPs, VNIs, VLAN/VRF identifiers, BGP AS
numbers and timing knobs used by the VxLAN QoS test suite. Tests and
helpers should import the module-level instances ``L3VNI`` and ``L2VNI``
rather than hard-coding values, so that a future testbed re-IP can be
done in one place.

The default values match the historical ``_I_*`` (L3VNI) and ``_J_*``
(L2VNI) constants that used to live inside
``qos_map/test_dscp_to_tc.py``. The back-compat aliases for those
underscore names are re-exported from ``vxlan_helper.py``.

Port allocation (orthogonal to the semantic constants below)
------------------------------------------------------------
Physical port assignment for the two overlays is *not* defined in this
file — it lives in ``qos_helpers.setup_topo_common`` (which produces
``port_info['ingress_a']`` and ``port_info['ingress_b']`` from the
testbed YAML at
``sonic-mgmt/spytest/testbeds/fx3/fx3_qos_vxlan_testbed_breakout.yaml``)
and is consumed in test bodies under a workspace-wide *role-to-port
mapping convention*:

  ingress_a  ->  L3VNI ingress (Section I, VRF-bound)
                 D1T1P1 / Ethernet1_49 on the fx3 VxLAN breakout testbed
  ingress_b  ->  L2VNI ingress (Section J, VLAN-access)
                 D1T1P2 / Ethernet1_50 on the fx3 VxLAN breakout testbed
  egress     ->  shared DUT2 egress, decap-side classifier
                 D2T1P1 / Ethernet1_49 on DUT2

The names ``ingress_a`` / ``ingress_b`` are *position labels* (first
and second DUT1->T1 link).  The mapping to overlay role lives in the
test bodies in ``qos_map/test_dscp_to_tc_overlay.py`` and in
``vxlan_helper._setup_vxlan_l3vni`` / ``_setup_vxlan_l2vni``.  This
keeps the dict-key naming consistent with the rest of the QoS suite
(Section G, scheduler, buffer, wred) which all speak the same
``ingress_a`` / ``ingress_b`` vocabulary.

The legacy ``port_info['ingress']`` key remains as a back-compat alias
that always points at the same physical port as ``ingress_a``, so
non-VxLAN tests and shared helpers that predate the split continue to
work unchanged.

Reserving a second port for L2VNI lets the VLAN-access config L2VNI
needs coexist with the VRF-bound config L3VNI needs, without flipping
a single port between modes on every test run.

NOTE: this module deliberately uses plain ``class`` definitions instead
of ``@dataclasses.dataclass`` so that the test suite stays compatible
with the older Python 3.5/3.6 interpreters historically used in some
SONiC spytest tool-chains. The values themselves are the same single-
source-of-truth they would be in a dataclass.
"""


class VxlanL3VniTopo(object):
    """L3VNI VTEP overlay parameters (Section I).

    Instances of this class are intentionally treated as immutable —
    callers may copy fields off of them but must not mutate them.
    """

    def __init__(self,
                 vrf='VrfQoS',
                 vni=5001,
                 vtep_name='VTEP_QOS',
                 nvo_name='NVO_QOS',
                 loopback_intf='Loopback1',
                 dut1_vtep_ip='40.40.40.1',
                 dut2_vtep_ip='40.40.40.2',
                 dut1_transit_bare='30.30.30.1',
                 bgp_as_dut1=65001,
                 bgp_as_dut2=65002,
                 dummy_vlan=501,
                 conv_wait_s=60,
                 spot_dscp=None):
        self.vrf = vrf
        self.vni = vni
        self.vtep_name = vtep_name
        self.nvo_name = nvo_name
        self.loopback_intf = loopback_intf
        self.dut1_vtep_ip = dut1_vtep_ip
        self.dut2_vtep_ip = dut2_vtep_ip
        self.dut1_transit_bare = dut1_transit_bare
        self.bgp_as_dut1 = bgp_as_dut1
        self.bgp_as_dut2 = bgp_as_dut2
        self.dummy_vlan = dummy_vlan
        self.conv_wait_s = conv_wait_s
        if spot_dscp is None:
            spot_dscp = {0: 0, 1: 1, 2: 2, 3: 3,
                         4: 4, 46: 5, 48: 6, 49: 7}
        self.spot_dscp = spot_dscp


class VxlanL2VniTopo(object):
    """L2VNI BUM-flood overlay parameters (Section J)."""

    def __init__(self,
                 vni=5002,
                 vtep_name='VTEP_QOS',
                 nvo_name='NVO_QOS',
                 loopback_intf='Loopback1',
                 dut1_vtep_ip='40.40.40.1',
                 dut2_vtep_ip='40.40.40.2',
                 dut1_transit_bare='30.30.30.1',
                 l2_vlan=502,
                 bgp_as_dut1=65001,
                 bgp_as_dut2=65002,
                 conv_wait_s=30,
                 bum_mac='ff:ff:ff:ff:ff:ff',
                 rx_mac='00:de:ad:be:ef:02',
                 rx_ip='20.20.20.22',
                 # Fake L2 gateway used ONLY to force the Ixia receiver
                 # host (NGPF) to emit a deterministic ARP-broadcast
                 # immediately after start_protocol. The broadcast
                 # populates DUT2's Vlan502 FDB on a strict schedule
                 # instead of relying on the idle ARP/NDP retransmit
                 # cadence of the unrelated data-plane hosts. The fake
                 # gateway is intentionally never assigned to any
                 # interface; only the broadcast ARP-request matters.
                 rx_gw='20.20.20.99',
                 spot_dscp=None):
        self.vni = vni
        self.vtep_name = vtep_name
        self.nvo_name = nvo_name
        self.loopback_intf = loopback_intf
        self.dut1_vtep_ip = dut1_vtep_ip
        self.dut2_vtep_ip = dut2_vtep_ip
        self.dut1_transit_bare = dut1_transit_bare
        self.l2_vlan = l2_vlan
        self.bgp_as_dut1 = bgp_as_dut1
        self.bgp_as_dut2 = bgp_as_dut2
        self.conv_wait_s = conv_wait_s
        self.bum_mac = bum_mac
        self.rx_mac = rx_mac
        self.rx_ip = rx_ip
        self.rx_gw = rx_gw
        if spot_dscp is None:
            spot_dscp = {0: 0, 1: 1, 2: 2, 3: 3,
                         4: 4, 46: 5, 48: 6, 49: 7}
        self.spot_dscp = spot_dscp


# Default instances. Most callers just `from vxlan_topology import
# L3VNI, L2VNI` and read fields off these.
L3VNI = VxlanL3VniTopo()
L2VNI = VxlanL2VniTopo()
