# Copyright 2021-present Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, wither express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

'''
Thrift SAI SRv6 tests for alibaba use case
'''

import random

from ptf.mask import Mask
from sai_thrift.sai_headers import *

from sai_base_test import *

from sai_thrift.ttypes import sai_thrift_neighbor_entry_t as _sai_thrift_neighbor_entry_t_origin
from sai_thrift.ttypes import sai_thrift_route_entry_t as _sai_thrift_route_entry_t_origin
from sai_thrift.ttypes import sai_thrift_my_sid_entry_t as _sai_thrift_my_sid_entry_t_origin
import sai_base_test as _sai_base_test


def _get_switch_id():
    """Retrieve the current SAI switch ID from the active test helper.

    Returns:
        The switch_id attribute of the current SAI helper, or None if no
        helper is registered.
    """
    helper = getattr(_sai_base_test, '_current_sai_helper', None)
    return helper.switch_id if helper is not None else None


def sai_thrift_neighbor_entry_t(switch_id=None, **kwargs):
    """Wrapper for sai_thrift_neighbor_entry_t that auto-fills switch_id.

    If switch_id is not provided, it is obtained from the current test helper
    so that callers do not need to pass it explicitly.
    """
    if switch_id is None:
        switch_id = _get_switch_id()
    return _sai_thrift_neighbor_entry_t_origin(switch_id=switch_id, **kwargs)


def sai_thrift_route_entry_t(switch_id=None, **kwargs):
    """Wrapper for sai_thrift_route_entry_t that auto-fills switch_id.

    If switch_id is not provided, it is obtained from the current test helper
    so that callers do not need to pass it explicitly.
    """
    if switch_id is None:
        switch_id = _get_switch_id()
    return _sai_thrift_route_entry_t_origin(switch_id=switch_id, **kwargs)


def sai_thrift_my_sid_entry_t(switch_id=None, **kwargs):
    """Wrapper for sai_thrift_my_sid_entry_t that auto-fills switch_id.

    If switch_id is not provided, it is obtained from the current test helper
    so that callers do not need to pass it explicitly.
    """
    if switch_id is None:
        switch_id = _get_switch_id()
    return _sai_thrift_my_sid_entry_t_origin(switch_id=switch_id, **kwargs)

@group("draft")
class SRv6SimplifiedTestHelper(SaiHelperSimplified):
    """
    Base test helper class for SRv6 PTF tests.

    Sets up three routed ports (port0/port1/port2) with corresponding router
    interfaces in the default VRF.  Sub-classes inherit this topology and
    create their own SRv6-specific objects on top of it.

    Port/RIF mapping:
    +----------+-----------+
    | port0    | port0_rif |
    +----------+-----------+
    | port1    | port1_rif |
    +----------+-----------+
    | port2    | port2_rif |
    +----------+-----------+
    """
    def setUp(self):
        super(SRv6SimplifiedTestHelper, self).setUp()

        dmac1 = '00:11:22:33:44:55'

        # Create L3 router interfaces on port0, port1, and port2
        self.create_routing_interfaces(ports=[0, 1, 2])

    def tearDown(self):
        # Remove all L3 router interfaces created in setUp
        self.destroy_routing_interfaces()

        super(SRv6SimplifiedTestHelper, self).tearDown()

@group("draft")
class Srv6DecapMySidTest(SRv6SimplifiedTestHelper):
    '''
    Test suite for SRv6 local My SID endpoint behaviors.

    Covers the following endpoint types:
      - End   : basic SRv6 endpoint (no decap), supports PSP and USD flavors
      - End.DT46: decap + dual-stack (IPv4/IPv6) routing table lookup
      - End.DT4 : decap + IPv4 routing table lookup
      - End.DT6 : decap + IPv6 routing table lookup
      - End.X  : adjacency cross-connect endpoint, supports PSP/USP/ECMP
    '''
    def setUp(self):
        super(Srv6DecapMySidTest, self).setUp()

        # --- SID address definitions ---
        # node0 locator prefix SID (End behavior)
        self.node0_prefix_sid = 'baba:1001:0:10::'
        # node0 End.DT46 SIDs: sid1 -> default VRF, sid2 -> non-default VRF
        self.node0_dt46_sid1 = 'baba:1001:0:10:df46:100::'
        self.node0_dt46_sid2 = 'baba:1001:0:10:df46:200::'
        # node0 End.DT4 SID (IPv4 decap) and End.DT6 SID (IPv6 decap)
        self.node0_dt4_sid = 'baba:1001:0:10:df4::'
        self.node0_dt6_sid = 'baba:1001:0:10:df6::'
        # node0 End.X (adjacency / cross-connect) SID
        self.node0_adj_sid = 'baba:1001:0:10:ad::'
        # node1 prefix SID used as next segment in the SID list
        self.node1_prefix_sid = 'baba:1001:0:20::'
        self.sid_list = [self.node1_prefix_sid]

        # --- Underlay / SRv6 transport addresses ---
        self.srv6_mac = '00:aa:bb:cc:dd:ee'   # MAC of underlay next-hop
        self.unbor_ip = '100.100.100.100'       # underlay neighbor IP
        self.srv6_src_ip = '2001:1001:0:10::1' # SRv6 outer source IPv6
        self.srv6_dst_ip = '2064:100::1d'       # SRv6 outer destination IPv6

        self.vpnsid = 'fd00:201:201:fff1:1::'   # VPN SID for encap tests

        # --- Overlay (client) addresses ---
        self.client_ip_src = '10.10.10.10'
        self.client_ip_dest = '20.20.20.20'
        self.nbor_ip = '30.30.30.30'            # overlay next-hop IP (port0)
        self.xconn_nbor_ip = '40.40.40.40'     # cross-connect next-hop IP (port3)
        self.client_ipv6_src = '1100:1001::10'
        self.client_ipv6_dest = '1100:1001::20'
        self.client_smac = "00:11:11:11:11:11"
        self.client_dmac = '00:22:22:22:22:22'

        # Create an extra router interface on port3 for cross-connect tests
        self.port3_rif = sai_thrift_create_router_interface(
            self.client,
            type=SAI_ROUTER_INTERFACE_TYPE_PORT,
            virtual_router_id=self.default_vrf,
            port_id=self.port3)

        # --- Overlay neighbor / route setup (port0_rif) ---
        # client route
        self.ip_nbor = sai_thrift_neighbor_entry_t(
            rif_id=self.port0_rif,
            ip_address=sai_ipaddress(self.nbor_ip))
        sai_thrift_create_neighbor_entry(
            self.client, self.ip_nbor, dst_mac_address=self.client_dmac)

        # Next-hop pointing to overlay neighbor via port0_rif
        self.ip_nhop = sai_thrift_create_next_hop(
            self.client,
            ip=sai_ipaddress(self.nbor_ip),
            router_interface_id=self.port0_rif,
            type=SAI_NEXT_HOP_TYPE_IP)

        # IPv4 host route for client destination
        self.ip_route = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.client_ip_dest + '/32'))
        sai_thrift_create_route_entry(
            self.client, self.ip_route, next_hop_id=self.ip_nhop)

        # IPv6 host route for client IPv6 destination
        self.ipv6_route = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.client_ipv6_dest + '/128'))
        sai_thrift_create_route_entry(
            self.client, self.ipv6_route, next_hop_id=self.ip_nhop)

        # --- Underlay neighbor / route setup (port2_rif) ---
        self.und_nbor = sai_thrift_neighbor_entry_t(
            rif_id=self.port2_rif, ip_address=sai_ipaddress(self.unbor_ip))
        sai_thrift_create_neighbor_entry(
            self.client, self.und_nbor, dst_mac_address=self.srv6_mac)

        # Next-hop for the SRv6 underlay transport via port2_rif
        self.und_nhop = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_IP,
            ip=sai_ipaddress(self.unbor_ip),
            router_interface_id=self.port2_rif)

        # Underlay route for node0 locator prefix (used by End SID forwarding)
        self.tunnel_route1 = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.node0_prefix_sid + '/64'))
        sai_thrift_create_route_entry(
            self.client, self.tunnel_route1, next_hop_id=self.und_nhop)

        # Underlay route for node1 prefix SID (next segment destination)
        self.tunnel_route2 = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.node1_prefix_sid + '/64'))
        sai_thrift_create_route_entry(
            self.client, self.tunnel_route2, next_hop_id=self.und_nhop)

        # Create a non-default VRF for DT4/DT6/DT46 tests, plus its route
        self.t_vrf_id = sai_thrift_create_virtual_router(self.client)
        self.t_route = sai_thrift_route_entry_t(
            vr_id=self.t_vrf_id,
            destination=sai_ipprefix(self.node1_prefix_sid + '/80'))
        sai_thrift_create_route_entry(
            self.client, self.t_route, next_hop_id=self.und_nhop)

        # --- Cross-connect neighbor / next-hop on port3_rif (End.X tests) ---
        self.xconn_nbor = sai_thrift_neighbor_entry_t(
            rif_id=self.port3_rif,
            ip_address=sai_ipaddress(self.xconn_nbor_ip))
        sai_thrift_create_neighbor_entry(
            self.client, self.xconn_nbor, dst_mac_address=self.srv6_mac)

        # port 13 cross-connect nhop
        self.xconn_nhop = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_IP,
            ip=sai_ipaddress(self.xconn_nbor_ip),
            router_interface_id=self.port3_rif)

        # --- Packet counter for the End SID ---
        self.end_sid_counter = sai_thrift_create_counter(self.client)
        self.end_sid_stats = 0

        # --- My SID entries (local SRv6 endpoint programming) ---
        # PSP_AND_USD flavor: support both Penultimate Segment Pop and
        # Ultimate Segment Decapsulation behaviors
        end_bf = SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_FLAVOR_PSP_AND_USD
        # End SID: basic endpoint, advances the segment pointer and forwards
        self.end_sid = sai_thrift_my_sid_entry_t(
            locator_block_len=40,
            locator_node_len=24,
            function_len=16,
            args_len=8,
            sid=self.node0_prefix_sid, vr_id=self.default_vrf)
        sai_thrift_create_my_sid_entry(
            self.client,
            self.end_sid,
            endpoint_behavior=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_E,
            endpoint_behavior_flavor=end_bf,
            counter_id=self.end_sid_counter)

        # End.DT46 SIDs: decap outer IPv6 and perform dual-stack route lookup
        # default VRF
        self.end_dt46_sid1 = sai_thrift_my_sid_entry_t(
            locator_block_len=40,
            locator_node_len=24,
            function_len=16,
            args_len=8,
            sid=self.node0_dt46_sid1, vr_id=self.default_vrf)
        sai_thrift_create_my_sid_entry(
            self.client,
            self.end_dt46_sid1,
            vrf=self.default_vrf,
            endpoint_behavior=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_DT46,
            endpoint_behavior_flavor=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_FLAVOR_PSP_AND_USD)
        # non-default VRF
        self.end_dt46_sid2 = sai_thrift_my_sid_entry_t(
            locator_block_len=40,
            locator_node_len=24,
            function_len=16,
            args_len=8,
            sid=self.node0_dt46_sid2, vr_id=self.default_vrf)
        sai_thrift_create_my_sid_entry(
            self.client,
            self.end_dt46_sid2,
            vrf=self.t_vrf_id,
            endpoint_behavior=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_DT46,
            endpoint_behavior_flavor=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_FLAVOR_PSP_AND_USD)

        # End.DT4 SID with non-default VRF
        self.end_dt4_sid = sai_thrift_my_sid_entry_t(
            locator_block_len=40,
            locator_node_len=24,
            function_len=16,
            args_len=8,
            sid=self.node0_dt4_sid, vr_id=self.default_vrf)
        sai_thrift_create_my_sid_entry(
            self.client,
            self.end_dt4_sid,
            vrf=self.t_vrf_id,
            endpoint_behavior=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_DT4,
            endpoint_behavior_flavor=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_FLAVOR_PSP_AND_USD)

        # End.DT6 SID with non-default VRF
        self.end_dt6_sid = sai_thrift_my_sid_entry_t(
            locator_block_len=40,
            locator_node_len=24,
            function_len=16,
            args_len=8,
            sid=self.node0_dt6_sid, vr_id=self.default_vrf)
        sai_thrift_create_my_sid_entry(
            self.client,
            self.end_dt6_sid,
            vrf=self.t_vrf_id,
            endpoint_behavior=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_DT6,
            endpoint_behavior_flavor=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_FLAVOR_PSP_AND_USD)

        # End.X SID: adjacency cross-connect, uses PSP_AND_USP flavor
        # Traffic is forwarded via xconn_nhop (port3_rif)
        self.end_x_sid = sai_thrift_my_sid_entry_t(
            locator_block_len=40,
            locator_node_len=24,
            function_len=16,
            args_len=8,
            sid=self.node0_adj_sid, vr_id=self.default_vrf)
        sai_thrift_create_my_sid_entry(
            self.client,
            self.end_x_sid,
            vrf=self.default_vrf,
            endpoint_behavior=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_X,
            endpoint_behavior_flavor=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_FLAVOR_PSP_AND_USP,
            next_hop_id=self.xconn_nhop)

        # --- Test packet templates ---
        # inner_v4_pkt / inner_v6_pkt: incoming SRv6-encapsulated payloads
        # v4_exp_pkt / v6_exp_pkt: expected packets after SRv6 decap + routing
        # test packets
        self.inner_v4_pkt = simple_tcp_packet(eth_dst=ROUTER_MAC,
                                              eth_src='00:22:22:22:22:21',
                                              ip_dst=self.client_ip_dest,
                                              ip_src=self.client_ip_src,
                                              ip_id=105,
                                              ip_ttl=64)
        self.v4_exp_pkt = simple_tcp_packet(eth_src=ROUTER_MAC,
                                            eth_dst=self.client_dmac,
                                            ip_dst=self.client_ip_dest,
                                            ip_src=self.client_ip_src,
                                            ip_id=105,
                                            ip_ttl=64)
        self.inner_v6_pkt = simple_tcpv6_packet(eth_dst=ROUTER_MAC,
                                                eth_src='00:22:22:22:22:21',
                                                ipv6_dst=self.client_ipv6_dest,
                                                ipv6_src=self.client_ipv6_src,
                                                ipv6_hlim=64)
        self.v6_exp_pkt = simple_tcpv6_packet(eth_src=ROUTER_MAC,
                                              eth_dst=self.client_dmac,
                                              ipv6_dst=self.client_ipv6_dest,
                                              ipv6_src=self.client_ipv6_src,
                                              ipv6_hlim=64)

    def runTest(self):
        self.mySidEndTest()
        self.mySidEndDT46Test()
        self.mySidEndDT4Test()
        self.mySidEndDT6Test()
        self.mySidXConnectTest()

    def tearDown(self):
        # Remove My SID entries in reverse creation order
        sai_thrift_remove_my_sid_entry(self.client, self.end_x_sid)
        sai_thrift_remove_my_sid_entry(self.client, self.end_dt6_sid)
        sai_thrift_remove_my_sid_entry(self.client, self.end_dt4_sid)
        sai_thrift_remove_my_sid_entry(self.client, self.end_dt46_sid2)
        sai_thrift_remove_my_sid_entry(self.client, self.end_dt46_sid1)
        sai_thrift_remove_my_sid_entry(self.client, self.end_sid)
        sai_thrift_remove_counter(self.client, self.end_sid_counter)
        # Remove cross-connect neighbor and next-hop
        sai_thrift_remove_neighbor_entry(self.client, self.xconn_nbor)
        sai_thrift_remove_next_hop(self.client, self.xconn_nhop)
        # Remove non-default VRF and its route
        sai_thrift_remove_route_entry(self.client, self.t_route)
        sai_thrift_remove_virtual_router(self.client, self.t_vrf_id)
        # Remove underlay routes and next-hops
        sai_thrift_remove_route_entry(self.client, self.tunnel_route2)
        sai_thrift_remove_route_entry(self.client, self.tunnel_route1)
        sai_thrift_remove_neighbor_entry(self.client, self.und_nbor)
        sai_thrift_remove_next_hop(self.client, self.und_nhop)
        # Remove overlay routes, neighbors and next-hops
        sai_thrift_remove_route_entry(self.client, self.ipv6_route)
        sai_thrift_remove_route_entry(self.client, self.ip_route)
        sai_thrift_remove_neighbor_entry(self.client, self.ip_nbor)
        sai_thrift_remove_next_hop(self.client, self.ip_nhop)
        # Remove the extra RIF created for port3
        sai_thrift_remove_router_interface(self.client, self.port3_rif)

        super(Srv6DecapMySidTest, self).tearDown()

    def mySidEndTest(self):
        '''
        Verify SRv6 End endpoint behavior.

        Two sub-cases are tested:
          1. PSP (Penultimate Segment Pop): seg_left == 1 on arrival, SRH is
             popped and the next segment (node1_prefix_sid) becomes the new
             IPv6 destination; packet is forwarded via the underlay (port2).
          2. USD (Ultimate Segment Decap): seg_left == 0 (reduced mode),
             outer IPv6 header is removed and the inner IPv4 payload is
             routed to the client via the overlay (port0).
        '''
        print("\nmySidEndTest()")

        # SRv6 packet with SRH: one segment remaining (seg_left=1), PSP case
        sr6_one_seg_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node0_prefix_sid,
            ipv6_hlim=64,
            srh_seg_left=1,
            srh_first_seg=0,
            srh_nh=0x4,
            srh_seg_list=self.sid_list,
            inner_frame=self.inner_v4_pkt[IP])
        # Expected packet after PSP: SRH popped, dst updated to node1_prefix_sid
        exp_pkt2 = simple_ipv6ip_packet(
            eth_src=ROUTER_MAC,
            eth_dst=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node1_prefix_sid,
            ipv6_hlim=63,
            inner_frame=self.inner_v4_pkt[IP])

        # Packet in reduced mode (no SRH): USD case, seg_left effectively 0
        sr6_zero_seg_pkt = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node0_prefix_sid,
            ipv6_hlim=63,
            inner_frame=self.inner_v4_pkt[IP])

        # Expected packet after USD: outer IPv6 decapped, inner IPv4 routed out
        exp_pkt3 = simple_tcp_packet(
            eth_src=ROUTER_MAC,
            eth_dst=self.client_dmac,
            ip_dst=self.client_ip_dest,
            ip_src=self.client_ip_src,
            ip_id=105,
            ip_ttl=64)

        print("END with PSP: Send packet with seg_left == 1")
        send_packet(self, self.dev_port1, sr6_one_seg_pkt)
        verify_packet(self, exp_pkt2, self.dev_port2)
        self.end_sid_stats += 1

        print("END with USD: Send packet with seg_left == 0")
        send_packet(self, self.dev_port1, sr6_zero_seg_pkt)
        verify_packet(self, exp_pkt3, self.dev_port0)
        self.end_sid_stats += 1

    def mySidEndDT46Test(self):
        '''
        Verify SRv6 End.DT46 endpoint behavior.

        End.DT46 decapsulates the outer SRv6 header and performs a dual-stack
        (IPv4 or IPv6) route lookup in the specified VRF.

        Sub-cases:
          - IPv4 inner payload with default VRF (DT46_sid1)
          - IPv6 inner payload with non-default VRF (DT46_sid2)
          - Reduced-mode packet (seg_left=0, no SRH, default VRF)
          - Packet with seg_left=1 and non-DT SID: should be dropped (End.DT46
            only processes the final segment)
        '''
        print("\nmySidEndDT46Test()")

        # default VRF
        sr6_pkt = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node0_dt46_sid1,
            ipv6_hlim=64,
            inner_frame=self.inner_v4_pkt[IP])

        # Reduced-mode IPv4 packet (no SRH, seg_left effectively 0)
        # Packet in reduced mode
        sr6_zero_seg_pkt = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node0_dt46_sid1,
            ipv6_hlim=63,
            inner_frame=self.inner_v4_pkt[IP])

        # SRv6 packet with SRH: seg_left=1, should be dropped by End.DT46
        sr6_one_seg_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node0_dt46_sid1,
            ipv6_hlim=64,
            srh_seg_left=1,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=[self.node1_prefix_sid],
            inner_frame=self.inner_v4_pkt[IP])

        # non-default VRF
        sr6_v6_pkt = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node0_dt46_sid2,
            ipv6_hlim=64,
            inner_frame=self.inner_v6_pkt[IPv6])

        try:
            # Route entry with non-default VRF for DT.46
            dt46_v6_route_entry = sai_thrift_route_entry_t(
                vr_id=self.t_vrf_id,
                destination=sai_ipprefix(self.client_ipv6_dest + '/128'))
            sai_thrift_create_route_entry(
                self.client, dt46_v6_route_entry, next_hop_id=self.ip_nhop)

            print("DT46: Sending SRv6 packet on port %d to port %d, "
                  "forward from %s to %s"
                  % (self.dev_port1, self.dev_port0, self.srv6_src_ip,
                     self.node0_prefix_sid))
            send_packet(self, self.dev_port1, sr6_pkt)
            verify_packets(self, self.v4_exp_pkt, [self.dev_port0])

            print("DT46: Sending SRv6 packet on port %d to port %d, "
                  "forward from %s to %s"
                  % (self.dev_port1, self.dev_port0, self.srv6_src_ip,
                     self.node1_prefix_sid))
            send_packet(self, self.dev_port1, sr6_v6_pkt)
            verify_packets(self, self.v6_exp_pkt, [self.dev_port0])

            print("DT46: Sending SRv6 packet with SL=0, forward to %s"
                  % (self.dev_port0))
            send_packet(self, self.dev_port1, sr6_zero_seg_pkt)
            verify_packets(self, self.v4_exp_pkt, [self.dev_port0])

            print("DT46: Sending SRv6 packet with SL=1, drop packet")
            send_packet(self, self.dev_port1, sr6_one_seg_pkt)
            verify_no_other_packets(self)

        finally:
            sai_thrift_remove_route_entry(self.client, dt46_v6_route_entry)

    def mySidEndDT6Test(self):
        '''
        Verify SRv6 End.DT6 endpoint behavior.

        End.DT6 decapsulates the outer SRv6 header and performs an IPv6 route
        lookup in the specified VRF.

        Sub-cases:
          - IPv6 inner payload with non-default VRF (DT6 SID)
          - Reduced-mode packet (seg_left=0, no SRH)
          - Packet with seg_left=1: should be dropped
        '''
        print("\nmySidEndDT6Test()")

        # non-default VRF
        sr6_v6_pkt = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node0_dt6_sid,
            ipv6_hlim=64,
            inner_frame=self.inner_v6_pkt[IPv6])

        # Reduced-mode IPv6 packet (no SRH)
        # SRv6 packet in reduced mode
        sr6_zero_seg_pkt = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node0_dt6_sid,
            ipv6_hlim=63,
            inner_frame=self.inner_v6_pkt[IPv6])

        # SRv6 packet with SRH: seg_left=1, should be dropped by End.DT6
        sr6_one_seg_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node0_dt6_sid,
            ipv6_hlim=64,
            srh_seg_left=1,
            srh_first_seg=1,
            srh_nh=0x29,
            srh_seg_list=[self.node1_prefix_sid],
            inner_frame=self.inner_v6_pkt[IPv6])

        try:
            # Temporary route entry in the non-default VRF for DT6 test
            # Route entry with non-default VRF for DT.6
            dt6_v6_route_entry = sai_thrift_route_entry_t(
                vr_id=self.t_vrf_id,
                destination=sai_ipprefix(self.client_ipv6_dest + '/128'))
            sai_thrift_create_route_entry(
                self.client, dt6_v6_route_entry, next_hop_id=self.ip_nhop)

            print("DT6: Sending SRv6 packet on port %d to port %d, "
                  "forward from %s to %s"
                  % (self.dev_port1, self.dev_port0, self.srv6_src_ip,
                     self.node1_prefix_sid))
            send_packet(self, self.dev_port1, sr6_v6_pkt)
            verify_packets(self, self.v6_exp_pkt, [self.dev_port0])

            print("DT6: Sending SRv6 packet with SL=0, forward to %s"
                  % (self.dev_port0))
            send_packet(self, self.dev_port1, sr6_zero_seg_pkt)
            verify_packets(self, self.v6_exp_pkt, [self.dev_port0])

            print("DT6: Sending SRv6 packet with SL=1, drop packet")
            send_packet(self, self.dev_port1, sr6_one_seg_pkt)
            verify_no_other_packets(self)

        finally:
            sai_thrift_remove_route_entry(self.client, dt6_v6_route_entry)

    def mySidEndDT4Test(self):
        '''
        Verify SRv6 End.DT4 endpoint behavior.

        End.DT4 decapsulates the outer SRv6 header and performs an IPv4 route
        lookup in the specified VRF.

        Sub-cases:
          - IPv4 inner payload with non-default VRF
          - Reduced-mode packet (seg_left=0, no SRH)
          - Packet with seg_left=1: should be dropped
        '''
        print("\nmySidEndDT4Test()")

        # SRv6 packet carrying IPv4 payload, no SRH (USD case)
        sr6_pkt = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node0_dt4_sid,
            ipv6_hlim=64,
            inner_frame=self.inner_v4_pkt[IP])

        # Packet in reduced mode
        sr6_zero_seg_pkt = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node0_dt4_sid,
            ipv6_hlim=63,
            inner_frame=self.inner_v4_pkt[IP])

        sr6_one_seg_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node0_dt4_sid,
            ipv6_hlim=64,
            srh_seg_left=1,
            srh_first_seg=0,
            srh_nh=0x4,
            srh_seg_list=[self.node1_prefix_sid],
            inner_frame=self.inner_v4_pkt[IP])

        try:
            # Route entry with non-default VRF for DT.4
            dt4_v4_route_entry = sai_thrift_route_entry_t(
                vr_id=self.t_vrf_id,
                destination=sai_ipprefix(self.client_ip_dest + '/32'))
            sai_thrift_create_route_entry(
                self.client, dt4_v4_route_entry, next_hop_id=self.ip_nhop)

            print("DT4: Sending SRv6 packet on port %d to port %d, "
                  "forward from %s to %s"
                  % (self.dev_port1, self.dev_port0, self.srv6_src_ip,
                     self.node0_prefix_sid))
            send_packet(self, self.dev_port1, sr6_pkt)
            verify_packets(self, self.v4_exp_pkt, [self.dev_port0])

            print("DT4: Sending SRv6 packet with SL=0, forward to %s"
                  % (self.dev_port0))
            send_packet(self, self.dev_port1, sr6_zero_seg_pkt)
            verify_packets(self, self.v4_exp_pkt, [self.dev_port0])

            print("DT4: Sending SRv6 packet with SL=1, drop packet")
            send_packet(self, self.dev_port1, sr6_one_seg_pkt)
            verify_no_other_packets(self)

        finally:
            sai_thrift_remove_route_entry(self.client, dt4_v4_route_entry)

    def mySidXConnectTest(self):
        '''
        Verify SRv6 End.X endpoint behavior.

        End.X is the adjacency (cross-connect) endpoint: it advances the
        segment pointer (PSP) or decapsulates (USD) and then forwards the
        packet to the specified next-hop without consulting the routing table.

        Sub-cases:
          1. PSP: seg_left=1, SRH popped, forward to cross-connect port3.
          2. USD: reduced-mode (no SRH), inner IPv4 forwarded to port3.
          3. ECMP: xconn next-hop changed to an ECMP group with two members
             (und_nhop on port2 and xconn_nhop on port3); verify load sharing.
          4. Drop: packet_action set to DROP, verify packets are discarded.
        '''
        print("\nmySidXConnectTest()")

        sr6_one_seg_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node0_adj_sid,
            ipv6_hlim=64,
            srh_seg_left=1,
            srh_first_seg=0,
            srh_nh=0x4,
            srh_seg_list=self.sid_list,
            inner_frame=self.inner_v4_pkt[IP])
        exp_pkt2 = simple_ipv6ip_packet(
            eth_src=ROUTER_MAC,
            eth_dst=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node1_prefix_sid,
            ipv6_hlim=63,
            inner_frame=self.inner_v4_pkt[IP])

        # Packet in reduced mode
        sr6_zero_seg_pkt = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.node0_adj_sid,
            ipv6_hlim=64,
            inner_frame=self.inner_v4_pkt[IP])

        exp_pkt3 = simple_tcp_packet(
            eth_src=ROUTER_MAC,
            eth_dst=self.srv6_mac,
            ip_dst=self.client_ip_dest,
            ip_src=self.client_ip_src,
            ip_id=105,
            ip_ttl=64)

        try:
            print("END.X with PSP: Send packet with seg_left == 1, "
                  "Cross-connect to port 3")
            send_packet(self, self.dev_port1, sr6_one_seg_pkt)
            verify_packets(self, exp_pkt2, [self.dev_port3])

            print("END.X with USD: Send packet with seg_left == 0, "
                  "Cross-connect to port 3")
            send_packet(self, self.dev_port1, sr6_zero_seg_pkt)
            verify_packets(self, exp_pkt3, [self.dev_port3])

            # Build an ECMP group with two next-hops for load-balancing test
            xconnect_ecmp = sai_thrift_create_next_hop_group(
                self.client, type=SAI_NEXT_HOP_GROUP_TYPE_ECMP)
            xconnect_ecmp1 = sai_thrift_create_next_hop_group_member(
                self.client,
                next_hop_group_id=xconnect_ecmp,
                next_hop_id=self.und_nhop)
            xconnect_ecmp2 = sai_thrift_create_next_hop_group_member(
                self.client,
                next_hop_group_id=xconnect_ecmp,
                next_hop_id=self.xconn_nhop)

            print("Set XConnect NHOP to ECMP")
            sai_thrift_set_my_sid_entry_attribute(
                self.client,
                self.end_x_sid,
                next_hop_id=xconnect_ecmp)

            count = [0, 0]
            max_iter = 60
            sip_address = self.srv6_src_ip
            inner_pkt = self.inner_v4_pkt
            # Vary TCP ports to exercise ECMP hash variation
            for i in range(0, max_iter):
                tcp_sport = 1000 + i
                tcp_dport = 1000 + i
                inner_pkt['TCP'].sport = tcp_sport
                inner_pkt['TCP'].dport = tcp_dport
                inner_frame = inner_pkt
                exp_pkt3['TCP'].sport = tcp_sport
                exp_pkt3['TCP'].dport = tcp_dport

                # Packet in reduced mode
                sr6_zero_seg_pkt = simple_ipv6ip_packet(
                    eth_dst=ROUTER_MAC,
                    eth_src=self.srv6_mac,
                    ipv6_src=sip_address,
                    ipv6_dst=self.node0_adj_sid,
                    ipv6_hlim=64,
                    inner_frame=inner_frame[IP])

                send_packet(self, self.dev_port1, sr6_zero_seg_pkt)
                recv_index = verify_any_packet_any_port(
                    self,
                    [exp_pkt3],
                    [self.dev_port2, self.dev_port3])
                count[recv_index] += 1
            print("ECMP count: ", count)

            # Each member should receive at least 30% of traffic
            for i in range(0, 2):
                self.assertGreater(count[i], 0.3*max_iter)

            print("Set XConnect NHOP back to port and packet action to drop")
            sai_thrift_set_my_sid_entry_attribute(self.client,
                                                  self.end_x_sid,
                                                  next_hop_id=self.xconn_nhop)
            sai_thrift_set_my_sid_entry_attribute(
                self.client,
                self.end_x_sid,
                packet_action=SAI_PACKET_ACTION_DROP)

            print("END.X: Send packet with seg_left == 1, Drop the packet")
            send_packet(self, self.dev_port1, sr6_one_seg_pkt)
            verify_no_other_packets(self)

            print("END.X: Send packet with seg_left == 0, Drop the packet")
            send_packet(self, self.dev_port1, sr6_zero_seg_pkt)
            verify_no_other_packets(self)

        finally:
            sai_thrift_set_my_sid_entry_attribute(
                self.client,
                self.end_x_sid,
                packet_action=SAI_PACKET_ACTION_FORWARD)
            sai_thrift_remove_next_hop_group_member(
                self.client, xconnect_ecmp2)
            sai_thrift_remove_next_hop_group_member(
                self.client, xconnect_ecmp1)
            sai_thrift_remove_next_hop_group(self.client, xconnect_ecmp)


@group("draft")
class Srv6DecapMySidUsidTest(SRv6SimplifiedTestHelper):
    '''
    Test suite for SRv6 compressed uSID (micro SID) endpoint behaviors.

    uSIDs use a 32-bit locator block + 16-bit node-id format, allowing
    multiple SIDs to be encoded in a single 128-bit IPv6 address.  This
    class tests the following endpoint types:

      - End.uN (micro Node SID): shifts the active uSID left by 16 bits
        to advance to the next uSID in the same container.  When the
        current uSID is the last one, pops the SRH segment (PSP) or
        removes the outer header (USD/reduced mode).
      - End.uA (micro Adjacency SID): same uSID shift logic as End.uN,
        but additionally cross-connects to a specified next-hop.
    '''
    def setUp(self):
        super(Srv6DecapMySidUsidTest, self).setUp()

        # --- Client / overlay addresses ---
        self.client_ip_src = '11.0.0.10'
        self.client_ip_dest = '11.0.0.11'
        # --- SRv6 transport addresses ---
        self.srv6_src_ip = '2001:1001:0:10::1'
        self.srv6_dst_ip = '2064:100::1d'
        self.client_dmac = '00:22:33:44:55:66'
        self.und_nbor_mac = '00:aa:bb:cc:dd:ee'      # underlay neighbor MAC
        self.und_xconn_nbor_mac = '00:aa:bb:cc:dd:ee' # cross-connect MAC

        # --- uSID address definitions ---
        # in_un_local_usid: local End.uN SID (block+node, rest = 0)
        self.in_un_local_usid = '2001:db8:100::'
        # in_un_usid: incoming uSID container with extra uSIDs appended
        self.in_un_usid = '2001:db8:100:200:300:400:500:600'
        # out_un_usid: expected IPv6 dst after advancing one uSID (shift left)
        self.out_un_usid = '2001:db8:200:300:400:500:600::'
        # in_ua_local_usid / in_ua_usid: End.uA (adjacency) equivalents
        self.in_ua_local_usid = '2001:db8:700:d800::'
        self.in_ua_usid = '2001:db8:700:d800:800:900:a00:b00'
        self.out_ua_usid = '2001:db8:800:900:a00:b00::'
        # next_usid1/2: subsequent uSID container values in the SID list
        self.next_usid1 = '2001:db8:1100:1200:1300:1400:1500:1600'
        self.next_usid2 = '2001:db8:2100:2200:2300:2400:2500:2600'
        un_usid_mask = '/48'  # 32-bit block len + 16-bit id len

        self.xconn_nbor_ip = '40.40.40.40'

        # Segment list for SRH: [next_usid2, next_usid1] (next_usid2 is active)
        self.usid_segment_list = [self.next_usid2, self.next_usid1]

        # Create extra RIF on port3 for cross-connect (End.uA) tests
        self.port3_rif = sai_thrift_create_router_interface(
            self.client,
            type=SAI_ROUTER_INTERFACE_TYPE_PORT,
            virtual_router_id=self.default_vrf,
            port_id=self.port3)

        # Loopback RIF used as the SRv6 tunnel underlay interface
        self.urif_lb = sai_thrift_create_router_interface(
            self.client,
            type=SAI_ROUTER_INTERFACE_TYPE_LOOPBACK,
            virtual_router_id=self.default_vrf)

        # Tunnel map: prefix_agg_id -> VPN SID (used by encap next-hops)
        self.tunnel_map = sai_thrift_create_tunnel_map(
            self.client,
            type=SAI_TUNNEL_MAP_TYPE_PREFIX_AGG_ID_TO_SRV6_VPN_SID)

        # SRv6 P2P tunnel object with source/destination IPv6 addresses
        self.sr_tunnel = sai_thrift_create_tunnel(
            self.client,
            type=SAI_TUNNEL_TYPE_SRV6,
            encap_src_ip=sai_ipaddress(self.srv6_src_ip),
            underlay_interface=self.urif_lb,
            encap_mappers=sai_thrift_object_list_t(
                count=1, idlist=[self.tunnel_map]),
            peer_mode=SAI_TUNNEL_PEER_MODE_P2P,
            encap_dst_ip=sai_ipaddress(self.srv6_dst_ip))

        # Cross-connect neighbor on port3_rif (End.uA forwarding target)
        self.xconn_nbor = sai_thrift_neighbor_entry_t(
            rif_id=self.port3_rif,
            ip_address=sai_ipaddress(self.xconn_nbor_ip))
        sai_thrift_create_neighbor_entry(
            self.client, self.xconn_nbor, dst_mac_address=self.und_nbor_mac)

        # Underlay neighbor and next-hop on port2_rif
        self.und_nbor = sai_thrift_neighbor_entry_t(
            rif_id=self.port2_rif, ip_address=sai_ipaddress('20.20.20.20'))
        sai_thrift_create_neighbor_entry(
            self.client, self.und_nbor, dst_mac_address=self.und_nbor_mac)

        self.und_nhop = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_IP,
            ip=sai_ipaddress('20.20.20.20'),
            router_interface_id=self.port2_rif)

        # Underlay route for the local uN SID block (in_un_local_usid/48)
        self.und_route_entry1 = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.in_un_local_usid + un_usid_mask))
        sai_thrift_create_route_entry(
            self.client, self.und_route_entry1, next_hop_id=self.und_nhop)

        # Underlay route for the output uN uSID block (out_un_usid/48)
        self.und_route_entry2 = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.out_un_usid + un_usid_mask))
        sai_thrift_create_route_entry(
            self.client, self.und_route_entry2, next_hop_id=self.und_nhop)

        # Underlay route for the first SRH next-segment (next_usid1/48)
        self.und_route_entry3 = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.next_usid1 + un_usid_mask))
        sai_thrift_create_route_entry(
            self.client, self.und_route_entry3, next_hop_id=self.und_nhop)

        # Underlay route for the second SRH next-segment (next_usid2/48)
        self.und_route_entry4 = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.next_usid2 + un_usid_mask))
        sai_thrift_create_route_entry(
            self.client, self.und_route_entry4, next_hop_id=self.und_nhop)

        # Route for decapsulated client destination (USD decap path)
        self.client_route_entry = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.client_ip_dest + '/32'))
        sai_thrift_create_route_entry(
            self.client, self.client_route_entry, next_hop_id=self.und_nhop)
        
        # Underlay route for the SRv6 tunnel destination IP
        self.und_route_srv6_dstip = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.srv6_dst_ip + '/64'))
        sai_thrift_create_route_entry(
            self.client, self.und_route_srv6_dstip, next_hop_id=self.und_nhop)

        # Additional cross-connect neighbor on port0_rif for End.uA forwarding
        self.und_xnbor = sai_thrift_neighbor_entry_t(
            rif_id=self.port0_rif, ip_address=sai_ipaddress('30.30.30.30'))
        sai_thrift_create_neighbor_entry(
            self.client, self.und_xnbor,
            dst_mac_address=self.und_xconn_nbor_mac)

        self.und_xnhop = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_IP,
            ip=sai_ipaddress('30.30.30.30'),
            router_interface_id=self.port0_rif)

        # --- My SID entries for uSID behaviors ---
        # end_sid_counter: byte/packet counter attached to the End.uN SID
        self.end_sid_counter = sai_thrift_create_counter(self.client)
        # End.uN SID: locator_block=32, locator_node=16, function=0, args=64
        # (Standard uSID format: /48 block + rest as uSID arguments)
        self.end_un_sid = sai_thrift_my_sid_entry_t(
            locator_block_len=32,
            locator_node_len=16,
            function_len=0,
            args_len=64,
            sid=self.in_un_local_usid, vr_id=self.default_vrf)
        sai_thrift_create_my_sid_entry(
            self.client,
            self.end_un_sid,
            endpoint_behavior_flavor=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_FLAVOR_PSP_AND_USP,
            endpoint_behavior=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_E,
            counter_id=self.end_sid_counter)

        # End.uA SID: locator_block=32, locator_node=16, function=16, args=64
        # next_hop_id points to und_xnhop (port0_rif cross-connect)
        self.end_ua_sid = sai_thrift_my_sid_entry_t(
            locator_block_len=32,
            locator_node_len=16,
            function_len=16,
            args_len=64,
            sid=self.in_ua_local_usid, vr_id=self.default_vrf)
        sai_thrift_create_my_sid_entry(
            self.client,
            self.end_ua_sid,
            next_hop_id=self.und_xnhop,
            endpoint_behavior_flavor=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_FLAVOR_PSP_AND_USP,
            endpoint_behavior=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_X)

        # Inner IPv4 packet template used in all uSID test cases
        self.inner_v4_pkt = simple_tcp_packet(ip_dst=self.client_ip_dest,
                                              ip_src=self.client_ip_src,
                                              ip_id=105,
                                              ip_ttl=63)

    def runTest(self):
        self.mySidEndUNTest()
        self.mySidEndUNPSPTest()
        self.mySidEndUNUSDTest()
        self.mySidEndUNUSDNoSRHTest()
        self.mySidEndUATest()
        self.mySidEndUAPSPTest()
        self.mySidEndUAUSDTest()
        self.mySidEndUAUSDNoSRHTest()

    def tearDown(self):
        # Remove My SID entries first
        sai_thrift_remove_my_sid_entry(self.client, self.end_ua_sid)
        sai_thrift_remove_my_sid_entry(self.client, self.end_un_sid)
        # Remove cross-connect neighbor and next-hop on port0_rif
        sai_thrift_remove_neighbor_entry(self.client, self.und_xnbor)
        sai_thrift_remove_next_hop(self.client, self.und_xnhop)
        # Remove all underlay routes
        sai_thrift_remove_route_entry(self.client, self.und_route_srv6_dstip)
        sai_thrift_remove_route_entry(self.client, self.und_route_entry4)
        sai_thrift_remove_route_entry(self.client, self.und_route_entry3)
        sai_thrift_remove_route_entry(self.client, self.und_route_entry2)
        sai_thrift_remove_route_entry(self.client, self.und_route_entry1)
        sai_thrift_remove_route_entry(self.client, self.client_route_entry)
        # Remove underlay neighbor and next-hop on port2_rif
        sai_thrift_remove_neighbor_entry(self.client, self.und_nbor)
        sai_thrift_remove_next_hop(self.client, self.und_nhop)
        # Remove tunnel map and SRv6 tunnel object
        sai_thrift_remove_tunnel_map(self.client, self.tunnel_map)
        sai_thrift_remove_tunnel(self.client, self.sr_tunnel)
        # Remove loopback RIF and port3 RIF
        sai_thrift_remove_router_interface(self.client, self.urif_lb)
        sai_thrift_remove_router_interface(self.client, self.port3_rif)

        super(Srv6DecapMySidUsidTest, self).tearDown()

    def mySidEndUNTest(self):
        '''
        Verify SRv6 End.uN uSID behavior (normal forwarding).

        When the active uSID within the current IPv6 destination is NOT the
        last one, End.uN shifts the remaining uSIDs left by 16 bits (removing
        the current 16-bit uSID) and sets the new IPv6 destination.  The SRH
        segment pointer (seg_left) is unchanged.

        Sub-cases:
          1. in_un_usid dst, seg_left=2: shift current uSID, output = out_un_usid
          2. in_un_local_usid dst, seg_left=2 (last uSID in container):
             move to next SRH entry (next_usid1), decrement seg_left to 1.
        '''
        print("\nmySidEndUNTest()")

        sr_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_un_usid,
            ipv6_hlim=64,
            srh_seg_left=2,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])
        exp_pkt = simple_ipv6_sr_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.out_un_usid,
            ipv6_hlim=63,
            srh_seg_left=2,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])

        print("Verifying End.uN function with SL>1 and >1 uSIDs left")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, exp_pkt, self.dev_port2)

        sr_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_un_local_usid,
            ipv6_hlim=64,
            srh_seg_left=2,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])
        exp_pkt = simple_ipv6_sr_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.next_usid1,
            ipv6_hlim=63,
            srh_seg_left=1,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])

        print("Verifying End.uN function with SL>1 and last uSID in use")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, exp_pkt, self.dev_port2)

    def mySidEndUNPSPTest(self):
        '''
        Verify SRv6 End.uN uSID behavior with PSP (Penultimate Segment Pop).

        PSP applies when seg_left == 1 (this is the penultimate segment):
          - If more uSIDs remain in the container: shift uSIDs, keep SRH.
          - If this is the last uSID in the container: SRH is popped and the
            packet becomes an encap-reduced packet (IPv6-in-IPv6 without SRH).
        '''
        print("\nmySidEndUNPSPTest()")

        sr_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_un_usid,
            ipv6_hlim=63,
            srh_seg_left=1,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])
        exp_pkt = simple_ipv6_sr_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.out_un_usid,
            ipv6_hlim=62,
            srh_seg_left=1,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])

        print("Verifying End.uN function with SL=1 and >1 uSIDs left")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, exp_pkt, self.dev_port2)

        sr_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_un_local_usid,
            ipv6_hlim=63,
            srh_seg_left=1,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])
        ipip_pkt = simple_ipv6ip_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.next_usid2,
            ipv6_hlim=62,
            inner_frame=self.inner_v4_pkt[IP])

        print("Verifying End.uN function with SL=1 and last uSID in use")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, ipip_pkt, self.dev_port2)

    def mySidEndUNUSDTest(self):
        '''
        Verify SRv6 End.uN uSID behavior with USD (Ultimate Segment Decap).

        USD applies when seg_left == 0 (this is the last segment):
          - If more uSIDs remain in the container: shift uSIDs, keep SRH.
          - If this is the last uSID (local uSID, reduced-mode packet):
            the entire outer IPv6 header is removed and the inner payload
            is delivered via normal IP routing.
        '''
        print("\nmySidEndUNUSDTest()")

        sr_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_un_usid,
            ipv6_hlim=63,
            srh_seg_left=0,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])
        exp_pkt = simple_ipv6_sr_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.out_un_usid,
            ipv6_hlim=62,
            srh_seg_left=0,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])

        print("Verifying End.uN function with SL=0 and >1 uSIDs left")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, exp_pkt, self.dev_port2)

        # Packet in reduced mode
        sr_pkt = simple_ipv6ip_packet(
                eth_dst=ROUTER_MAC,
                eth_src=self.und_nbor_mac,
                ipv6_src=self.srv6_src_ip,
                ipv6_dst=self.in_un_local_usid,
                ipv6_hlim=64,
                inner_frame=self.inner_v4_pkt[IP])
        exp_pkt = simple_tcp_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ip_src=self.client_ip_src,
            ip_dst=self.client_ip_dest,
            ip_id=105,
            ip_ttl=63)

        print("Verifying End.uN function with SL=1 and last uSID in use")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, exp_pkt, self.dev_port2)

    def mySidEndUNUSDNoSRHTest(self):
        '''
        Verify SRv6 End.uN uSID behavior with USD flavor and no SRH header.

        Reduced-mode packets (IPv6-in-IPv6 without SRH) are treated as having
        seg_left=0, so USD rules apply.  This tests the same shift/decap logic
        as mySidEndUNUSDTest but with encap-reduced input packets.
        '''
        print("\nmySidEndUNUSDNoSRHTest()")

        sr_pkt = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_un_usid,
            ipv6_hlim=62,
            inner_frame=self.inner_v4_pkt[IP])
        exp_pkt = simple_ipv6ip_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.out_un_usid,
            ipv6_hlim=61,
            inner_frame=self.inner_v4_pkt[IP])

        print("Verifying End.uN function with SL=0 and >1 uSIDs left")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, exp_pkt, self.dev_port2)

        sr_pkt = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_un_local_usid,
            ipv6_hlim=62,
            inner_frame=self.inner_v4_pkt[IP])
        exp_pkt = simple_tcp_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ip_src=self.client_ip_src,
            ip_dst=self.client_ip_dest,
            ip_id=105,
            ip_ttl=63)

        print("Verifying End.uN function with SL=1 and last uSID in use")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, exp_pkt, self.dev_port2)

    def mySidEndUATest(self):
        '''
        Verify SRv6 End.uA uSID behavior (normal forwarding with cross-connect).

        End.uA behaves like End.uN (shift active uSID) but after the shift it
        forwards the packet to the configured adjacency next-hop (und_xnhop on
        port0_rif) instead of performing a routing table lookup.
        '''
        print("\nmySidEndUATest()")

        sr_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_ua_usid,
            ipv6_hlim=64,
            srh_seg_left=2,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])
        exp_pkt = simple_ipv6_sr_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.out_ua_usid,
            ipv6_hlim=63,
            srh_seg_left=2,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])

        print("Verifying End.uA function with SL>1 and >1 uSIDs left")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, exp_pkt, self.dev_port0)

        sr_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_ua_local_usid,
            ipv6_hlim=64,
            srh_seg_left=2,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])
        exp_pkt = simple_ipv6_sr_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.next_usid1,
            ipv6_hlim=63,
            srh_seg_left=1,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])

        print("Verifying End.uA function with SL>1 and last uSID in use")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, exp_pkt, self.dev_port0)

    def mySidEndUAPSPTest(self):
        '''
        Verify SRv6 End.uA uSID behavior with PSP (Penultimate Segment Pop).

        Same semantics as mySidEndUNPSPTest but with cross-connect forwarding
        after the uSID shift: traffic is sent to und_xnhop on port0_rif.
        '''
        print("\nmySidEndUAPSPTest()")

        sr_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_ua_usid,
            ipv6_hlim=63,
            srh_seg_left=1,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])
        exp_pkt = simple_ipv6_sr_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.out_ua_usid,
            ipv6_hlim=62,
            srh_seg_left=1,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])

        print("Verifying End.uA function with SL=1 and >1 uSIDs left")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, exp_pkt, self.dev_port0)

        sr_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_ua_local_usid,
            ipv6_hlim=63,
            srh_seg_left=1,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])
        ipip_pkt = simple_ipv6ip_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.next_usid2,
            ipv6_hlim=62,
            inner_frame=self.inner_v4_pkt[IP])

        print("Verifying End.uA function with SL=1 and last uSID in use")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, ipip_pkt, self.dev_port0)

    def mySidEndUAUSDTest(self):
        '''
        Verify SRv6 End.uA uSID behavior with USD (Ultimate Segment Decap).

        Same semantics as mySidEndUNUSDTest but with cross-connect forwarding.
        When the last uSID is consumed, the outer header is decapped and the
        inner payload is forwarded to the adjacency next-hop.
        '''
        print("\nmySidEndUAUSDTest()")

        sr_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_ua_usid,
            ipv6_hlim=63,
            srh_seg_left=0,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])
        exp_pkt = simple_ipv6_sr_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.out_ua_usid,
            ipv6_hlim=62,
            srh_seg_left=0,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])

        print("Verifying End.uA function with SL=0 and >1 uSIDs left")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, exp_pkt, self.dev_port0)

        sr_pkt = simple_ipv6_sr_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_ua_local_usid,
            ipv6_hlim=63,
            srh_seg_left=0,
            srh_first_seg=1,
            srh_nh=0x4,
            srh_seg_list=self.usid_segment_list,
            inner_frame=self.inner_v4_pkt[IP])
        exp_pkt = simple_tcp_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ip_src=self.client_ip_src,
            ip_dst=self.client_ip_dest,
            ip_id=105,
            ip_ttl=63)

        print("Verifying End.uA function with SL=1 and last uSID in use")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, exp_pkt, self.dev_port0)

    def mySidEndUAUSDNoSRHTest(self):
        '''
        Verify SRv6 End.uA uSID behavior with USD flavor and no SRH header.

        Same as mySidEndUNUSDNoSRHTest but with cross-connect forwarding:
        reduced-mode (no SRH) packets are processed with USD logic and the
        inner payload is sent to the adjacency next-hop after decap.
        '''
        print("\nmySidEndUAUSDNoSRHTest()")

        sr_pkt = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_ua_usid,
            ipv6_hlim=62,
            inner_frame=self.inner_v4_pkt[IP])
        exp_pkt = simple_ipv6ip_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.out_ua_usid,
            ipv6_hlim=61,
            inner_frame=self.inner_v4_pkt[IP])

        print("Verifying End.uA function with SL=0 and >1 uSIDs left")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, exp_pkt, self.dev_port0)

        sr_pkt = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.und_nbor_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.in_ua_local_usid,
            ipv6_hlim=62,
            inner_frame=self.inner_v4_pkt[IP])
        exp_pkt = simple_tcp_packet(
            eth_dst=self.und_nbor_mac,
            eth_src=ROUTER_MAC,
            ip_src=self.client_ip_src,
            ip_dst=self.client_ip_dest,
            ip_id=105,
            ip_ttl=63)

        print("Verifying End.uA function with SL=1 and last uSID in use")
        send_packet(self, self.dev_port1, sr_pkt)
        verify_packet(self, exp_pkt, self.dev_port0)

@group("draft")
class Srv6EncapTest(SRv6SimplifiedTestHelper):
    '''
    Test suite for SRv6 source encapsulation.

    Tests cover the following encap scenarios:
      - VPN-only  : no TE SID list, encap outer dst = VPN SID
      - TE + VPN  : TE SID list + appended VPN SID
      - TE-only   : two TE SIDs, no VPN SID
      - ECMP      : SRv6 next-hop group with multiple SID lists
      - DT46+Encap: SRv6 decap (DT46) followed by re-encap with VPN SID
      - B6 Encaps : B6 endpoint with SRv6 re-encapsulation
      - SID marking: per-flow VPN SID selection via DSCP -> FC -> VPN SID map

    Topology:
    +----------+-----------+
    | port3    | port3_rif | -> user traffic injection port (ovrf VRF)
    +----------+-----------+
    '''
    def setUp(self):
        super(Srv6EncapTest, self).setUp()

        # --- Overlay / client addresses ---
        self.client_ip_src = '11.0.0.10'
        self.client_ip_dest = '11.0.0.11'
        self.client_ipv6_src = '1100:1001::10'
        self.client_ipv6_dest = '1100:1001::11'

        # --- SRv6 transport addresses ---
        self.srv6_src_ip = '2001:1001:0:10::1'
        self.srv6_dst_ip = '2064:100::1d'

        # --- TE SID list entries (segment routing path) ---
        self.seg1 = 'baba:1001:0:10::'  # first TE segment (port0 route)
        self.seg2 = 'baba:1001:0:20::'  # second TE segment (port2 route)
        self.seg3 = 'baba:1001:0:30::'  # third TE segment (port2 route)

        # VPN SID: used for VPN-only and TE+VPN encap modes
        self.vpnsid = 'fd00:201:201:fff1:1::'

        #self.client_dmac = '00:22:33:44:55:66'
        self.srv6_mac = '00:aa:bb:cc:dd:ee'  # MAC used for all underlay nhops

        # Create overlay VRF and port3 RIF for user traffic injection
        self.ovrf = sai_thrift_create_virtual_router(self.client)
        self.port3_rif = sai_thrift_create_router_interface(
            self.client,
            type=SAI_ROUTER_INTERFACE_TYPE_PORT,
            virtual_router_id=self.ovrf,
            port_id=self.port3)

        #create IP neighbor on port0_rif
        self.nbr_entry = sai_thrift_neighbor_entry_t(
            rif_id=self.port0_rif,
            ip_address=sai_ipaddress(self.client_ip_dest))
        sai_thrift_create_neighbor_entry(
            self.client, self.nbr_entry, dst_mac_address=self.srv6_mac)

        # IPv4 next-hop via port0_rif (used for seg1 underlay route)
        self.ip_nhop = sai_thrift_create_next_hop(
            self.client,
            ip=sai_ipaddress(self.client_ip_dest),
            router_interface_id=self.port0_rif,
            type=SAI_NEXT_HOP_TYPE_IP)
        
        #create IPv6 neighbor on port1_rif
        # Create neighbor
        self.nbr6_entry = sai_thrift_neighbor_entry_t(
                    rif_id=self.port1_rif,
                    ip_address=sai_ipaddress("192:168:22::22"))
        sai_thrift_create_neighbor_entry(
                    self.client,
                    self.nbr6_entry,
                    dst_mac_address=self.srv6_mac)

        # Create next hop
        self.ip6_nhop = sai_thrift_create_next_hop(
                    self.client,
                    type=SAI_NEXT_HOP_TYPE_IP,
                    router_interface_id=self.port1_rif,
                    ip=sai_ipaddress("192:168:22::22"))

        # Default VRF host route for decap forwarding (End.DT46 inner dest)
        self.route_entry = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.client_ip_dest + '/32'))
        sai_thrift_create_route_entry(
            self.client, self.route_entry, next_hop_id=self.ip_nhop)

        # Loopback RIF: used as SRv6 tunnel underlay interface
        self.urif_lb = sai_thrift_create_router_interface(
            self.client,
            type=SAI_ROUTER_INTERFACE_TYPE_LOOPBACK,
            virtual_router_id=self.default_vrf)

        # Tunnel map: maps prefix_agg_id (from route entry) to VPN SID
        self.tunnel_map = sai_thrift_create_tunnel_map(
            self.client,
            type=SAI_TUNNEL_MAP_TYPE_PREFIX_AGG_ID_TO_SRV6_VPN_SID)

        # SRv6 P2P tunnel object (source = srv6_src_ip, dest = srv6_dst_ip)
        self.sr_tunnel = sai_thrift_create_tunnel(
            self.client,
            type=SAI_TUNNEL_TYPE_SRV6,
            encap_src_ip=sai_ipaddress(self.srv6_src_ip),
            underlay_interface=self.urif_lb,
            encap_mappers=sai_thrift_object_list_t(
                count=1, idlist=[self.tunnel_map]),
            peer_mode=SAI_TUNNEL_PEER_MODE_P2P,
            encap_dst_ip=sai_ipaddress(self.srv6_dst_ip))

        # Tunnel map entry: prefix_agg_id=5 -> vpnsid (used by VPN route entries)
        self.tunnel_map_entry = sai_thrift_create_tunnel_map_entry(
            self.client,
            tunnel_map_type=SAI_TUNNEL_MAP_TYPE_PREFIX_AGG_ID_TO_SRV6_VPN_SID,
            tunnel_map=self.tunnel_map,
            prefix_agg_id_key=5,
            srv6_vpn_sid_value=self.vpnsid)

        # SRv6 SID list objects used for TE path selection:
        #   sidlist1: single segment [seg1] (TE to seg1 only)
        sai_segment_list_1 = sai_thrift_segment_list_t(
            count=1, ip6list=[self.seg1])
        self.sidlist1 = sai_thrift_create_srv6_sidlist(
            self.client,
            type=SAI_SRV6_SIDLIST_TYPE_ENCAPS_RED,
            segment_list=sai_segment_list_1)

        #   sidlist2: single segment [seg2] (TE to seg2 only)
        sai_segment_list_2 = sai_thrift_segment_list_t(
            count=1, ip6list=[self.seg2])
        self.sidlist2 = sai_thrift_create_srv6_sidlist(
            self.client,
            type=SAI_SRV6_SIDLIST_TYPE_ENCAPS_RED,
            segment_list=sai_segment_list_2)

        #   sidlist3: two segments [seg2, seg1] (TE-only, two-hop path)
        sai_segment_list_3 = sai_thrift_segment_list_t(
            count=2, ip6list=[self.seg2, self.seg1])
        self.sidlist3 = sai_thrift_create_srv6_sidlist(
            self.client,
            type=SAI_SRV6_SIDLIST_TYPE_ENCAPS_RED,
            segment_list=sai_segment_list_3)

        #create IP neighbor on port2_rif
        self.und_nbor = sai_thrift_neighbor_entry_t(
            rif_id=self.port2_rif, ip_address=sai_ipaddress('33.33.33.33'))
        sai_thrift_create_neighbor_entry(
            self.client, self.und_nbor, dst_mac_address=self.srv6_mac)

        # Underlay next-hop for seg2 and seg3 routes via port2_rif
        self.und_nhop = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_IP,
            ip=sai_ipaddress('33.33.33.33'),
            router_interface_id=self.port2_rif)

        # Underlay route for seg1 prefix: via ip_nhop (port0_rif)
        self.und_route_entry1 = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.seg1 + '/64'))
        sai_thrift_create_route_entry(
            self.client, self.und_route_entry1, next_hop_id=self.ip_nhop)

        # Underlay route for seg2 prefix: via und_nhop (port2_rif)
        self.und_route_entry2 = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.seg2 + '/64'))
        sai_thrift_create_route_entry(
            self.client, self.und_route_entry2, next_hop_id=self.und_nhop)

        # Underlay route for seg3 prefix: via und_nhop (port2_rif)
        self.und_route_entry3 = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.seg3 + '/64'))
        sai_thrift_create_route_entry(
            self.client, self.und_route_entry3, next_hop_id=self.und_nhop)
    
        # Underlay route for the VPN SID prefix
        self.und_route_vpnsid = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.vpnsid + '/64'))
        sai_thrift_create_route_entry(
            self.client, self.und_route_vpnsid, next_hop_id=self.und_nhop)

        # Underlay route for the SRv6 tunnel dst IP (srv6_dst_ip)
        # In VPN mode, traffic uses tunnel dst IP nexthop, NOT vpnsid nexthop
        self.und_route_srv6_dstip = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix(self.srv6_dst_ip + '/64'))
        #tunnel dst ip to a different next_hop_id, In VPN case, traffice goes to tunnel dstip nexthop instead of vpnsid nexthop
        sai_thrift_create_route_entry(
            self.client, self.und_route_srv6_dstip, next_hop_id=self.ip6_nhop)

        # SRv6 next-hops referencing each SID list + tunnel:
        #   sr_nhop_sid1: TE via sidlist1 ([seg1])
        self.sr_nhop_sid1 = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_SRV6_SIDLIST,
            srv6_sidlist_id=self.sidlist1,
            tunnel_id=self.sr_tunnel)

        #   sr_nhop_sid2: TE via sidlist2 ([seg2])
        self.sr_nhop_sid2 = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_SRV6_SIDLIST,
            srv6_sidlist_id=self.sidlist2,
            tunnel_id=self.sr_tunnel)

        #   sr_nhop_sid3: TE via sidlist3 ([seg2, seg1])
        self.sr_nhop_sid3 = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_SRV6_SIDLIST,
            srv6_sidlist_id=self.sidlist3,
            tunnel_id=self.sr_tunnel)

        #srv6 nexthop with empty sidist, VPN only case
        self.sr_nhop_sid4 = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_SRV6_SIDLIST,
            srv6_sidlist_id=0,
            tunnel_id=self.sr_tunnel)

        # ECMP group with sr_nhop_sid1 and sr_nhop_sid2 for load-balancing tests
        self.ecmp_sid_nhop = sai_thrift_create_next_hop_group(
            self.client, type=SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP)
        self.ecmp_nhop1 = sai_thrift_create_next_hop_group_member(
            self.client,
            next_hop_group_id=self.ecmp_sid_nhop,
            next_hop_id=self.sr_nhop_sid1)
        self.ecmp_nhop2 = sai_thrift_create_next_hop_group_member(
            self.client,
            next_hop_group_id=self.ecmp_sid_nhop,
            next_hop_id=self.sr_nhop_sid2)

        # Overlay IPv4 route in ovrf -> VPN-only SRv6 next-hop (prefix_agg_id=5)
        self.over_route_entry = sai_thrift_route_entry_t(
            vr_id=self.ovrf,
            destination=sai_ipprefix(self.client_ip_dest + '/24'))
        sai_thrift_create_route_entry(
            self.client, self.over_route_entry, next_hop_id=self.sr_nhop_sid4, prefix_agg_id=5)

        # Overlay IPv6 route in ovrf -> VPN-only SRv6 next-hop (prefix_agg_id=5)
        self.over_v6_route_entry = sai_thrift_route_entry_t(
            vr_id=self.ovrf,
            destination=sai_ipprefix(self.client_ipv6_dest + '/120'))
        sai_thrift_create_route_entry(self.client,
                                      self.over_v6_route_entry,
                                      next_hop_id=self.sr_nhop_sid4, prefix_agg_id=5)

        # --- Test packet templates ---
        # pkt: ingress IPv4 TCP packet sent on port3 (ovrf)
        # v6_pkt: ingress IPv6 TCP packet sent on port3 (ovrf)
        # inner_v4_pkt: expected inner IPv4 payload after encap (TTL decremented)
        # test packets
        self.pkt = simple_tcp_packet(eth_dst=ROUTER_MAC,
                                     eth_src='00:22:22:22:22:21',
                                     ip_dst=self.client_ip_dest,
                                     ip_src=self.client_ip_src,
                                     ip_id=105,
                                     ip_ttl=64)

        self.v6_pkt = simple_tcpv6_packet(eth_dst=ROUTER_MAC,
                                          eth_src='00:22:22:22:22:21',
                                          ipv6_dst=self.client_ipv6_dest,
                                          ipv6_src=self.client_ipv6_src,
                                          ipv6_hlim=64)
        self.exp_v6_pkt = simple_tcpv6_packet(ipv6_dst=self.client_ipv6_dest,
                                              ipv6_src=self.client_ipv6_src,
                                              ipv6_hlim=63)

        self.inner_v4_pkt = simple_tcp_packet(ip_dst=self.client_ip_dest,
                                              ip_src=self.client_ip_src,
                                              ip_id=105,
                                              ip_ttl=63)

    def runTest(self):
        self.encapVPNonlyTest()
        self.encapTEandVPNTest()
        self.encapTEonlyTest()
        self.encapEcmpTest()
        self.decapEncapVPNonlyTest()
        self.encapB6Test()
        self.encapSidmarkingTest()

    def tearDown(self):
        # Remove routes first (they reference next hops)
        sai_thrift_remove_route_entry(self.client, self.over_v6_route_entry)
        sai_thrift_remove_route_entry(self.client, self.over_route_entry)
        sai_thrift_remove_route_entry(self.client, self.und_route_srv6_dstip)
        sai_thrift_remove_route_entry(self.client, self.und_route_vpnsid)
        sai_thrift_remove_route_entry(self.client, self.und_route_entry3)
        sai_thrift_remove_route_entry(self.client, self.und_route_entry2)
        sai_thrift_remove_route_entry(self.client, self.und_route_entry1)
        sai_thrift_remove_route_entry(self.client, self.route_entry)
        # Remove ECMP group members and group
        sai_thrift_remove_next_hop_group_member(self.client, self.ecmp_nhop2)
        sai_thrift_remove_next_hop_group_member(self.client, self.ecmp_nhop1)
        sai_thrift_remove_next_hop_group(self.client, self.ecmp_sid_nhop)
        # Remove SR next hops (reference sidlists and tunnel)
        sai_thrift_remove_next_hop(self.client, self.sr_nhop_sid4)
        sai_thrift_remove_next_hop(self.client, self.sr_nhop_sid3)
        sai_thrift_remove_next_hop(self.client, self.sr_nhop_sid2)
        sai_thrift_remove_next_hop(self.client, self.sr_nhop_sid1)
        # Remove IP next hops
        sai_thrift_remove_next_hop(self.client, self.ip6_nhop)
        sai_thrift_remove_next_hop(self.client, self.ip_nhop)
        sai_thrift_remove_next_hop(self.client, self.und_nhop)
        # Remove neighbor entries
        sai_thrift_remove_neighbor_entry(self.client, self.nbr6_entry)
        sai_thrift_remove_neighbor_entry(self.client, self.nbr_entry)
        sai_thrift_remove_neighbor_entry(self.client, self.und_nbor)
        # Remove sidlists (now that nhops are gone)
        sai_thrift_remove_srv6_sidlist(self.client, self.sidlist3)
        sai_thrift_remove_srv6_sidlist(self.client, self.sidlist2)
        sai_thrift_remove_srv6_sidlist(self.client, self.sidlist1)
        # Remove tunnel map entry and tunnel
        sai_thrift_remove_tunnel_map_entry(self.client, self.tunnel_map_entry)
        sai_thrift_remove_tunnel(self.client, self.sr_tunnel)
        sai_thrift_remove_tunnel_map(self.client, self.tunnel_map)
        # Remove router interfaces
        sai_thrift_remove_router_interface(self.client, self.urif_lb)
        sai_thrift_remove_router_interface(self.client, self.port3_rif)
        # Remove VRF last
        sai_thrift_remove_virtual_router(self.client, self.ovrf)

        super(Srv6EncapTest, self).tearDown()

    def encapVPNonlyTest(self):
        '''
        Verify SRv6 source encapsulation with VPN SID only (no TE SID list).

        The overlay route uses sr_nhop_sid4 (empty SID list) with prefix_agg_id=5.
        The tunnel map translates prefix_agg_id=5 to the VPN SID (vpnsid).
        The encapsulated outer IPv6 destination is the vpnsid; the underlay
        route lookup uses the tunnel dst IP (srv6_dst_ip), NOT the vpnsid.

        Also verifies that updating the underlay route for srv6_dst_ip changes
        the egress port, and that reverting restores original behavior.
        '''
        print("encapVPNonlyTest()")

        sr6_v4_pkt = simple_ipv6ip_packet(
            eth_src=ROUTER_MAC,
            eth_dst=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.vpnsid,
            ipv6_hlim=63,
            inner_frame=self.inner_v4_pkt[IP])
        sr6_v6_pkt = simple_ipv6ip_packet(
            eth_src=ROUTER_MAC,
            eth_dst=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.vpnsid,
            ipv6_hlim=63,
            inner_frame=self.exp_v6_pkt[IPv6])

        m_sr6_v4_pkt = Mask(sr6_v4_pkt)
        m_sr6_v4_pkt.set_do_not_care_scapy(IPv6, 'fl')
        m_sr6_v6_pkt = Mask(sr6_v6_pkt)
        m_sr6_v6_pkt.set_do_not_care_scapy(IPv6, 'fl')

        #self.und_route_vpnsid -> self.und_nhop -> port2_rif
        #self.srv6_dst_ip -> self.ip6_nhop -> port1_rif
        #we will verify that traffic goes to port1_rif, not port2_rif, which means the underlay route lookup is based on ENCAP_DST_IP
        print("Sending IPv4 packet - encap with VPN SID")
        self.dataplane.flush()
        send_packet(self, self.dev_port3, self.pkt)
        verify_packets(self, m_sr6_v4_pkt, [self.dev_port1])

        print("Sending IPv6 packet - encap with VPN SID")
        self.dataplane.flush()
        send_packet(self, self.dev_port3, self.v6_pkt)
        verify_packets(self, m_sr6_v6_pkt, [self.dev_port1])

        # Change the underlay route for tunnel dst IP to ip_nhop (port0_rif)
        # and verify that encapped traffic now egresses via port0
        sai_thrift_set_route_entry_attribute(
            self.client, self.und_route_srv6_dstip, next_hop_id=self.ip_nhop)

        m_sr6_v4_pkt = Mask(sr6_v4_pkt)
        m_sr6_v4_pkt.set_do_not_care_scapy(IPv6, 'fl')
        m_sr6_v6_pkt = Mask(sr6_v6_pkt)
        m_sr6_v6_pkt.set_do_not_care_scapy(IPv6, 'fl')
        print("Sending IPv4 packet after nexthop update - encap with VPN SID")
        self.dataplane.flush()
        send_packet(self, self.dev_port3, self.pkt)
        verify_packets(self, m_sr6_v4_pkt, [self.dev_port0])

        print("Sending IPv6 packet after nexthop update - encap with VPN SID")
        self.dataplane.flush()
        send_packet(self, self.dev_port3, self.v6_pkt)
        verify_packets(self, m_sr6_v6_pkt, [self.dev_port0])

        #recover to original state
        sai_thrift_set_route_entry_attribute(
            self.client, self.und_route_srv6_dstip, next_hop_id=self.ip6_nhop)

    def encapTEandVPNTest(self):
        '''
        Verify SRv6 source encapsulation with TE SID list + VPN SID.

        The overlay route is switched to sr_nhop_sid1 (sidlist1 = [seg1]).
        The tunnel map appends the VPN SID so the final SRH contains:
          [vpnsid] as the last segment, with seg1 as the outer IPv6 dst.

        Also verifies dynamic nexthop update: changing the underlay route for
        seg1 (und_route_entry1) redirects encapped traffic to a new port.
        '''
        print("encapTEandVPNTest()")

        #egress traffic pattern after encapsulation
        sr6_v4_pkt = simple_ipv6_sr_packet(
            eth_src=ROUTER_MAC,
            eth_dst=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.seg1,
            ipv6_hlim=63,
            inner_frame=self.inner_v4_pkt[IP],
            srh_seg_left=1,
            srh_first_seg=0,
            srh_nh=0x4,
            srh_seg_list=[self.vpnsid])

        #egress traffic pattern after encapsulation
        sr6_v6_pkt = simple_ipv6_sr_packet(
            eth_src=ROUTER_MAC,
            eth_dst=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.seg1,
            ipv6_hlim=63,
            inner_frame=self.exp_v6_pkt[IPv6],
            srh_seg_left=1,
            srh_first_seg=0,
            srh_nh=0x29,
            srh_seg_list=[self.vpnsid])

        try:
            sai_thrift_set_route_entry_attribute(self.client,
                                                 self.over_route_entry,
                                                 next_hop_id=self.sr_nhop_sid1, prefix_agg_id=5)
            sai_thrift_set_route_entry_attribute(self.client,
                                                 self.over_v6_route_entry,
                                                 next_hop_id=self.sr_nhop_sid1, prefix_agg_id=5)

            m_sr6_v4_pkt = Mask(sr6_v4_pkt)
            m_sr6_v4_pkt.set_do_not_care_scapy(IPv6, 'fl')
            m_sr6_v4_pkt.set_do_not_care_scapy(IPv6ExtHdrRouting, 'reserved')
            m_sr6_v6_pkt = Mask(sr6_v6_pkt)
            m_sr6_v6_pkt.set_do_not_care_scapy(IPv6, 'fl')
            m_sr6_v6_pkt.set_do_not_care_scapy(IPv6ExtHdrRouting, 'reserved')

            print("Sending IPv4 packet - encap with TE + VPN SIDs")
            self.dataplane.flush()
            send_packet(self, self.dev_port3, self.pkt)
            verify_packets(self, m_sr6_v4_pkt, [self.dev_port0])

            print("Sending IPv6 packet - encap with TE + VPN SIDs")
            self.dataplane.flush()
            send_packet(self, self.dev_port3, self.v6_pkt)
            verify_packets(self, m_sr6_v6_pkt, [self.dev_port0])

            #update sid nexthop, and verify that traffic changes according to new nexthop
            sai_thrift_set_route_entry_attribute(
                self.client, self.und_route_entry1, next_hop_id=self.ip6_nhop)
            m_sr6_v4_pkt = Mask(sr6_v4_pkt)
            m_sr6_v4_pkt.set_do_not_care_scapy(IPv6, 'fl')
            m_sr6_v4_pkt.set_do_not_care_scapy(IPv6ExtHdrRouting, 'reserved')
            m_sr6_v6_pkt = Mask(sr6_v6_pkt)
            m_sr6_v6_pkt.set_do_not_care_scapy(IPv6, 'fl')
            m_sr6_v6_pkt.set_do_not_care_scapy(IPv6ExtHdrRouting, 'reserved')

            print("Sending IPv4 packet after nexthop update - encap with TE + VPN SIDs")
            self.dataplane.flush()
            send_packet(self, self.dev_port3, self.pkt)
            verify_packets(self, m_sr6_v4_pkt, [self.dev_port1])

            print("Sending IPv6 packet after nexthop update - encap with TE + VPN SIDs")
            self.dataplane.flush()
            send_packet(self, self.dev_port3, self.v6_pkt)
            verify_packets(self, m_sr6_v6_pkt, [self.dev_port1])

            #recover to original state
            sai_thrift_set_route_entry_attribute(
                self.client, self.und_route_entry1, next_hop_id=self.ip_nhop)

        finally:
            sai_thrift_set_route_entry_attribute(self.client,
                                                 self.over_route_entry,
                                                 next_hop_id=self.sr_nhop_sid4, prefix_agg_id=5)
            sai_thrift_set_route_entry_attribute(self.client,
                                                 self.over_v6_route_entry,
                                                 next_hop_id=self.sr_nhop_sid4, prefix_agg_id=5)

    def encapTEonlyTest(self):
        '''
        Verify SRv6 source encapsulation with two TE SIDs (no VPN SID).

        The overlay route is switched to sr_nhop_sid3 (sidlist3 = [seg2, seg1]).
        No VPN SID is appended.  The outer IPv6 dst is seg2 (first hop) with
        seg1 in the SRH.  Traffic is forwarded via und_nhop (port2_rif).
        '''
        print("encapTEonlyTest()")

        seglist3 = [self.seg2, self.seg1]
        sr6_v4_pkt = simple_ipv6_sr_packet(
            eth_src=ROUTER_MAC,
            eth_dst=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=seglist3[0],
            ipv6_hlim=63,
            inner_frame=self.inner_v4_pkt[IP],
            srh_seg_left=1,
            srh_first_seg=0,
            srh_nh=0x4,
            srh_seg_list=[seglist3[1]])
        sr6_v6_pkt = simple_ipv6_sr_packet(
            eth_src=ROUTER_MAC,
            eth_dst=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=seglist3[0],
            ipv6_hlim=63,
            inner_frame=self.exp_v6_pkt[IPv6],
            srh_seg_left=1,
            srh_first_seg=0,
            srh_nh=0x29,
            srh_seg_list=[seglist3[1]])

        try:
            sai_thrift_set_route_entry_attribute(self.client,
                                                 self.over_route_entry,
                                                 next_hop_id=self.sr_nhop_sid3)
            sai_thrift_set_route_entry_attribute(self.client,
                                                 self.over_v6_route_entry,
                                                 next_hop_id=self.sr_nhop_sid3)

            m_sr6_v4_pkt = Mask(sr6_v4_pkt)
            m_sr6_v4_pkt.set_do_not_care_scapy(IPv6, 'fl')
            m_sr6_v4_pkt.set_do_not_care_scapy(IPv6ExtHdrRouting, 'reserved')
            m_sr6_v6_pkt = Mask(sr6_v6_pkt)
            m_sr6_v6_pkt.set_do_not_care_scapy(IPv6, 'fl')
            m_sr6_v6_pkt.set_do_not_care_scapy(IPv6ExtHdrRouting, 'reserved')

            print("Sending IPv4 packet - encap with two TE SIDs")
            self.dataplane.flush()
            send_packet(self, self.dev_port3, self.pkt)
            verify_packets(self, m_sr6_v4_pkt, [self.dev_port2])

            print("Sending IPv6 packet - encap with two TE SIDs")
            self.dataplane.flush()
            send_packet(self, self.dev_port3, self.v6_pkt)
            verify_packets(self, m_sr6_v6_pkt, [self.dev_port2])

        finally:
            #work around for P200 SAI error: Invalid NH - Null Sidlist with no prefix agg id
            sai_thrift_set_route_entry_attribute(self.client,
                                                 self.over_route_entry,
                                                 next_hop_id=self.sr_nhop_sid1, prefix_agg_id=5)
            sai_thrift_set_route_entry_attribute(self.client,
                                                 self.over_v6_route_entry,
                                                 next_hop_id=self.sr_nhop_sid1, prefix_agg_id=5)

            #recover to original state
            sai_thrift_set_route_entry_attribute(self.client,
                                                 self.over_route_entry,
                                                 next_hop_id=self.sr_nhop_sid4, prefix_agg_id=5)
            sai_thrift_set_route_entry_attribute(self.client,
                                                 self.over_v6_route_entry,
                                                 next_hop_id=self.sr_nhop_sid4, prefix_agg_id=5)

    def encapEcmpTest(self):
        '''
        Verify SRv6 source encapsulation with ECMP SID next-hop group.

        The overlay route is set to ecmp_sid_nhop (containing sr_nhop_sid1 and
        sr_nhop_sid2).  Different TCP source ports are used to exercise ECMP
        hashing; both encap paths (seg1/port0 and seg2/port2) should receive
        traffic.
        '''
        print("\nencapEcmpTest()")

        send_pkt = simple_tcp_packet(eth_dst=ROUTER_MAC,
                                     eth_src='00:22:22:22:22:21',
                                     ip_dst=self.client_ip_dest,
                                     ip_src=self.client_ip_src,
                                     ip_id=105,
                                     ip_ttl=64)
        inner_v4_pkt = simple_tcp_packet(ip_dst=self.client_ip_dest,
                                         ip_src=self.client_ip_src,
                                         ip_id=105,
                                         ip_ttl=63)

        try:
            sai_thrift_set_route_entry_attribute(
                self.client,
                self.over_route_entry,
                next_hop_id=self.ecmp_sid_nhop, prefix_agg_id=5)

            max_iter = 30
            count = [0, 0]
            for i in range(0, max_iter):
                tcp_sport = 2000 + i

                send_pkt['TCP'].sport = tcp_sport
                inner_v4_pkt['TCP'].sport = tcp_sport

                sid1_sr6_pkt = simple_ipv6_sr_packet(
                    eth_src=ROUTER_MAC,
                    eth_dst=self.srv6_mac,
                    ipv6_src=self.srv6_src_ip,
                    ipv6_dst=self.seg1,
                    ipv6_hlim=63,
                    inner_frame=inner_v4_pkt[IP],
                    srh_seg_left=1,
                    srh_first_seg=0,
                    srh_nh=0x4,
                    srh_seg_list=[self.vpnsid])
                
                sid2_sr6_pkt = simple_ipv6_sr_packet(
                    eth_src=ROUTER_MAC,
                    eth_dst=self.srv6_mac,
                    ipv6_src=self.srv6_src_ip,
                    ipv6_dst=self.seg2,
                    ipv6_hlim=63,
                    inner_frame=inner_v4_pkt[IP],
                    srh_seg_left=1,
                    srh_first_seg=0,
                    srh_nh=0x4,
                    srh_seg_list=[self.vpnsid])
                
                m_sid1_sr6_pkt = Mask(sid1_sr6_pkt)
                m_sid1_sr6_pkt.set_do_not_care_scapy(IPv6, 'fl')
                m_sid1_sr6_pkt.set_do_not_care_scapy(IPv6ExtHdrRouting, 'reserved')

                m_sid2_sr6_pkt = Mask(sid2_sr6_pkt)
                m_sid2_sr6_pkt.set_do_not_care_scapy(IPv6, 'fl')
                m_sid2_sr6_pkt.set_do_not_care_scapy(IPv6ExtHdrRouting, 'reserved')

                self.dataplane.flush()
                send_packet(self, self.dev_port3, send_pkt)
                rcv_index = verify_any_packet_any_port(
                    self,
                    [m_sid1_sr6_pkt, m_sid2_sr6_pkt],
                    [self.dev_port0, self.dev_port2])
                count[rcv_index] += 1
            print("Encap ECMP count: ", count)

            for i in range(0, 2):
                self.assertNotEqual(count[i], 0)

        finally:
            sai_thrift_set_route_entry_attribute(self.client,
                                                 self.over_route_entry,
                                                 next_hop_id=self.sr_nhop_sid4, prefix_agg_id=5)

    def decapEncapVPNonlyTest(self):
        '''
        Verify DT46 decap followed by SRv6 VPN-only re-encapsulation.

        A temporary End.DT46 My SID entry is created pointing to the overlay
        VRF (ovrf).  Incoming SRv6-encapsulated IPv4/IPv6 packets received on
        port2 are:
          1. Decapsulated by End.DT46 (SRv6 outer header removed).
          2. Routed in ovrf, which matches over_route_entry/over_v6_route_entry.
          3. Re-encapsulated with the VPN SID (sr_nhop_sid4).
          4. Forwarded via the tunnel dst IP route to port1.
        '''
        print("decapEncapVPNonlyTest()")

        self.end_dt46_sid = sai_thrift_my_sid_entry_t(
            locator_block_len=32,
            locator_node_len=16,
            function_len=32,
            args_len=48,
            sid="fd00:202:203a:fff0:10::", vr_id=self.default_vrf)
        sai_thrift_create_my_sid_entry(
            self.client,
            self.end_dt46_sid,
            vrf=self.ovrf,
            endpoint_behavior=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_DT46,
            endpoint_behavior_flavor=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_FLAVOR_PSP_AND_USD)

        sr6_pkt_4 = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst="fd00:202:203a:fff0:10::",
            ipv6_hlim=64,
            inner_frame=self.pkt[IP])

        sr6_pkt_6 = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst="fd00:202:203a:fff0:10::",
            ipv6_hlim=64,
            inner_frame=self.v6_pkt[IPv6])

        sr6_v4_pkt = simple_ipv6ip_packet(
            eth_src=ROUTER_MAC,
            eth_dst=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.vpnsid,
            ipv6_hlim=63,
            inner_frame=self.inner_v4_pkt[IP])
        sr6_v6_pkt = simple_ipv6ip_packet(
            eth_src=ROUTER_MAC,
            eth_dst=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=self.vpnsid,
            ipv6_hlim=63,
            inner_frame=self.exp_v6_pkt[IPv6])

        m_sr6_v4_pkt = Mask(sr6_v4_pkt)
        m_sr6_v4_pkt.set_do_not_care_scapy(IPv6, 'fl')
        m_sr6_v6_pkt = Mask(sr6_v6_pkt)
        m_sr6_v6_pkt.set_do_not_care_scapy(IPv6, 'fl')

        print("Sending DT46+IPv4 packet - decap DT46 and encap with VPN SID")
        self.dataplane.flush()
        send_packet(self, self.dev_port2, sr6_pkt_4)
        verify_packets(self, m_sr6_v4_pkt, [self.dev_port1])

        print("Sending DT46+IPv6 packet - decap DT46 and encap with VPN SID")
        self.dataplane.flush()
        send_packet(self, self.dev_port2, sr6_pkt_6)
        verify_packets(self, m_sr6_v6_pkt, [self.dev_port1])

        sai_thrift_remove_my_sid_entry(self.client, self.end_dt46_sid)

    def encapB6Test(self):
        '''
        Verify B6 (Binding SID with SRv6 encapsulation) endpoint behavior.

        A temporary End.B6_ENCAPS_RED My SID entry is created.  When an
        incoming SRv6 packet matches this SID, the device performs a new
        SRv6 encapsulation using sr_nhop_sid3 (sidlist3 = [seg2, seg1]).
        The B6 SID acts as a re-entry point that steers traffic onto a new
        TE path.
        '''
        print("encapB6Test()")

        self.end_b6_encap_sid = sai_thrift_my_sid_entry_t(
            locator_block_len=32,
            locator_node_len=16,
            function_len=16,
            args_len=64,
            sid="fd00:201:173:71::", vr_id=self.default_vrf)
        sai_thrift_create_my_sid_entry(
            self.client,
            self.end_b6_encap_sid,
            vrf=self.default_vrf,
            endpoint_behavior=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_B6_ENCAPS_RED,
            endpoint_behavior_flavor=SAI_MY_SID_ENTRY_ENDPOINT_BEHAVIOR_FLAVOR_PSP_AND_USD,
            next_hop_id=self.sr_nhop_sid3)

        sr6_pkt_4 = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst="fd00:201:173:71::",
            ipv6_hlim=64,
            inner_frame=self.pkt[IP])

        sr6_pkt_6 = simple_ipv6ip_packet(
            eth_dst=ROUTER_MAC,
            eth_src=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst="fd00:201:173:71::",
            ipv6_hlim=64,
            inner_frame=self.v6_pkt[IPv6])

        seglist3 = [self.seg2, self.seg1]
        sr6_v4_pkt = simple_ipv6_sr_packet(
            eth_src=ROUTER_MAC,
            eth_dst=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=seglist3[0],
            ipv6_hlim=63,
            inner_frame=self.inner_v4_pkt[IP],
            srh_seg_left=1,
            srh_first_seg=0,
            srh_nh=0x4,
            srh_seg_list=[seglist3[1]])
        sr6_v6_pkt = simple_ipv6_sr_packet(
            eth_src=ROUTER_MAC,
            eth_dst=self.srv6_mac,
            ipv6_src=self.srv6_src_ip,
            ipv6_dst=seglist3[0],
            ipv6_hlim=63,
            inner_frame=self.exp_v6_pkt[IPv6],
            srh_seg_left=1,
            srh_first_seg=0,
            srh_nh=0x29,
            srh_seg_list=[seglist3[1]])

        m_sr6_v4_pkt = Mask(sr6_v4_pkt)
        m_sr6_v4_pkt.set_do_not_care_scapy(IPv6, 'fl')
        m_sr6_v4_pkt.set_do_not_care_scapy(IPv6ExtHdrRouting, 'reserved')
        m_sr6_v6_pkt = Mask(sr6_v6_pkt)
        m_sr6_v6_pkt.set_do_not_care_scapy(IPv6, 'fl')
        m_sr6_v6_pkt.set_do_not_care_scapy(IPv6ExtHdrRouting, 'reserved')

        print("Sending B6SID+IPv4 packet - encap with TE SIDs")
        self.dataplane.flush()
        send_packet(self, self.dev_port1, sr6_pkt_4)
        verify_packets(self, m_sr6_v4_pkt, [self.dev_port2])

        print("Sending B6SID+IPv6 packet - encap with TE SIDs")
        self.dataplane.flush()
        send_packet(self, self.dev_port1, sr6_pkt_6)
        verify_packets(self, m_sr6_v6_pkt, [self.dev_port2])

        sai_thrift_remove_my_sid_entry(self.client, self.end_b6_encap_sid)

    def encapSidmarkingTest(self):
        '''
        Verify SRv6 SID marking encapsulation (per-flow VPN SID selection).

        SID marking selects the VPN SID based on the incoming packet DSCP:
          1. A DSCP-to-FC QoS map is bound to port3.
          2. An outer tunnel map (prefix_agg_id=6 -> inner_tunnel_map) is
             attached to a new SRv6 tunnel.
          3. The inner tunnel map maps FC values to VPN SIDs:
               FC 0 -> fd00:201:201:fff1:20::  (DSCP 0)
               FC 1 -> fd00:201:201:fff1:21::  (DSCP 6)
               FC 2 -> fd00:201:201:fff1:22::  (DSCP 8)
          4. The overlay route uses the new SRv6 nhop with prefix_agg_id=6.

        For each DSCP value the test sends IPv4 and IPv6 packets and verifies
        that the outer IPv6 dst matches the expected VPN SID.
        '''
        print("encapSidmarkingTest()")

        # Create QOS map for DSCP to Forwarding Class
        qos_map_list = []
        # DSCP 0 -> FC 0
        qos_map_list.append(sai_thrift_qos_map_t(
            key=sai_thrift_qos_map_params_t(dscp=0),
            value=sai_thrift_qos_map_params_t(fc=0)))
        # DSCP 6 -> FC 1
        qos_map_list.append(sai_thrift_qos_map_t(
            key=sai_thrift_qos_map_params_t(dscp=6),
            value=sai_thrift_qos_map_params_t(fc=1)))
        # DSCP 8 -> FC 2
        qos_map_list.append(sai_thrift_qos_map_t(
            key=sai_thrift_qos_map_params_t(dscp=8),
            value=sai_thrift_qos_map_params_t(fc=2)))

        qos_map_value_list = sai_thrift_qos_map_list_t(
            count=len(qos_map_list),
            maplist=qos_map_list)

        dscp_to_fc_map = sai_thrift_create_qos_map(
            self.client,
            type=SAI_QOS_MAP_TYPE_DSCP_TO_FORWARDING_CLASS,
            map_to_value_list=qos_map_value_list)

        # Bind QOS map to port3 - Ethernet4
        sai_thrift_set_port_attribute(
            self.client,
            self.port3,
            qos_dscp_to_forwarding_class_map=dscp_to_fc_map)

        # Create outer tunnel map for sid marking:
        # maps prefix_agg_id -> inner tunnel map (which maps FC -> VPN SID)
        # create outer tunnel map for sid marking
        outer_tunnel_map = sai_thrift_create_tunnel_map(
            self.client,
            type=SAI_TUNNEL_MAP_TYPE_PREFIX_AGG_ID_TO_TUNNEL_MAP_ID)

        # New SRv6 tunnel for SID-marking (uses outer_tunnel_map)
        sr_tunnel_sidmrking = sai_thrift_create_tunnel(
            self.client,
            type=SAI_TUNNEL_TYPE_SRV6,
            encap_src_ip=sai_ipaddress(self.srv6_src_ip),
            underlay_interface=self.urif_lb,
            encap_mappers=sai_thrift_object_list_t(
                count=1, idlist=[outer_tunnel_map]),
            peer_mode=SAI_TUNNEL_PEER_MODE_P2P,
            encap_dst_ip=sai_ipaddress(self.srv6_dst_ip))
        
        # SRv6 VPN-only next-hop using the sid-marking tunnel
        sr_nhop_sidmarking = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_SRV6_SIDLIST,
            srv6_sidlist_id=0,
            tunnel_id=sr_tunnel_sidmrking)

        # Create inner tunnel map for sid marking:
        # maps FC (forwarding class) -> VPN SID
        # create inner tunnel map for sid marking
        inner_tunnel_map = sai_thrift_create_tunnel_map(
            self.client,
            type=SAI_TUNNEL_MAP_TYPE_FORWARDING_CLASS_TO_SRV6_VPN_SID)
        # Outer map entry: prefix_agg_id=6 -> inner_tunnel_map
        outer_tunnel_map_entry = sai_thrift_create_tunnel_map_entry(
            self.client,
            tunnel_map_type=SAI_TUNNEL_MAP_TYPE_PREFIX_AGG_ID_TO_TUNNEL_MAP_ID,
            tunnel_map=outer_tunnel_map,
            prefix_agg_id_key=6,
            tunnel_map_id_value=inner_tunnel_map)

        # Inner map entry: FC 0 (DSCP 0) -> VPN SID 20::
        inner_tunnel_map_entry0 = sai_thrift_create_tunnel_map_entry(
            self.client,
            tunnel_map_type=SAI_TUNNEL_MAP_TYPE_FORWARDING_CLASS_TO_SRV6_VPN_SID,
            tunnel_map=inner_tunnel_map,
            forwarding_class_key=0,
            srv6_vpn_sid_value="fd00:201:201:fff1:20::")
        
        # Inner map entry: FC 1 (DSCP 6) -> VPN SID 21::
        inner_tunnel_map_entry1 = sai_thrift_create_tunnel_map_entry(
            self.client,
            tunnel_map_type=SAI_TUNNEL_MAP_TYPE_FORWARDING_CLASS_TO_SRV6_VPN_SID,
            tunnel_map=inner_tunnel_map,
            forwarding_class_key=1,
            srv6_vpn_sid_value="fd00:201:201:fff1:21::")

        # Inner map entry: FC 2 (DSCP 8) -> VPN SID 22::
        inner_tunnel_map_entry2 = sai_thrift_create_tunnel_map_entry(
            self.client,
            tunnel_map_type=SAI_TUNNEL_MAP_TYPE_FORWARDING_CLASS_TO_SRV6_VPN_SID,
            tunnel_map=inner_tunnel_map,
            forwarding_class_key=2,
            srv6_vpn_sid_value="fd00:201:201:fff1:22::")

        # Temporary overlay routes that use the sid-marking nhop (prefix_agg_id=6)
        tmp_over_route_entry = sai_thrift_route_entry_t(
            vr_id=self.ovrf,
            destination=sai_ipprefix(self.client_ip_dest + '/32'))
        sai_thrift_create_route_entry(
            self.client, tmp_over_route_entry, next_hop_id=sr_nhop_sidmarking, prefix_agg_id=6)

        tmp_over_v6_route_entry = sai_thrift_route_entry_t(
            vr_id=self.ovrf,
            destination=sai_ipprefix(self.client_ipv6_dest + '/128'))
        sai_thrift_create_route_entry(self.client,
                                      tmp_over_v6_route_entry,
                                      next_hop_id=sr_nhop_sidmarking, prefix_agg_id=6)

        try:
            # --- Test case 1: DSCP 0 -> FC 0 -> VPN SID fd00:201:201:fff1:20:: ---
            #test with dscp=0
            sr6_v4_pkt = simple_ipv6ip_packet(
                eth_src=ROUTER_MAC,
                eth_dst=self.srv6_mac,
                ipv6_src=self.srv6_src_ip,
                ipv6_dst="fd00:201:201:fff1:20::",
                ipv6_hlim=63,
                inner_frame=self.inner_v4_pkt[IP])
            sr6_v6_pkt = simple_ipv6ip_packet(
                eth_src=ROUTER_MAC,
                eth_dst=self.srv6_mac,
                ipv6_src=self.srv6_src_ip,
                ipv6_dst="fd00:201:201:fff1:20::",
                ipv6_hlim=63,
                inner_frame=self.exp_v6_pkt[IPv6])

            m_sr6_v4_pkt = Mask(sr6_v4_pkt)
            m_sr6_v4_pkt.set_do_not_care_scapy(IPv6, 'fl')
            m_sr6_v6_pkt = Mask(sr6_v6_pkt)
            m_sr6_v6_pkt.set_do_not_care_scapy(IPv6, 'fl')

            print("Sending IPv4 packet with dscp=0 - encap with VPN SID fd00:201:201:fff1:20::")

            send_packet(self, self.dev_port3, self.pkt)
            verify_packets(self, m_sr6_v4_pkt, [self.dev_port1])

            print("Sending IPv6 packet with dscp=0 - encap with VPN SID fd00:201:201:fff1:20::")
            send_packet(self, self.dev_port3, self.v6_pkt)
            verify_packets(self, m_sr6_v6_pkt, [self.dev_port1])

            #test with dscp=6
            # --- Test case 2: DSCP 6 -> FC 1 -> VPN SID fd00:201:201:fff1:21:: ---
            # Update packet TOS/TC fields to DSCP 6 (traffic class bits 7:2)
            self.pkt[IP].tos = (6<<2) & 0xff
            self.v6_pkt[IPv6].tc = (6<<2) & 0xff
            self.inner_v4_pkt[IP].tos = (6<<2) & 0xff
            self.exp_v6_pkt[IPv6].tc = (6<<2) & 0xff

            sr6_v4_pkt = simple_ipv6ip_packet(
                eth_src=ROUTER_MAC,
                eth_dst=self.srv6_mac,
                ipv6_src=self.srv6_src_ip,
                ipv6_dst="fd00:201:201:fff1:21::",
                ipv6_tc = ((6<<2) & 0xff),
                ipv6_hlim=63,
                inner_frame=self.inner_v4_pkt[IP])
            sr6_v6_pkt = simple_ipv6ip_packet(
                eth_src=ROUTER_MAC,
                eth_dst=self.srv6_mac,
                ipv6_src=self.srv6_src_ip,
                ipv6_dst="fd00:201:201:fff1:21::",
                ipv6_tc = ((6<<2) & 0xff),
                ipv6_hlim=63,
                inner_frame=self.exp_v6_pkt[IPv6])

            m_sr6_v4_pkt = Mask(sr6_v4_pkt)
            m_sr6_v4_pkt.set_do_not_care_scapy(IPv6, 'fl')
            m_sr6_v6_pkt = Mask(sr6_v6_pkt)
            m_sr6_v6_pkt.set_do_not_care_scapy(IPv6, 'fl')

            print("Sending IPv4 packet with dscp=6 - encap with VPN SID fd00:201:201:fff1:21::")
            send_packet(self, self.dev_port3, self.pkt)
            verify_packets(self, m_sr6_v4_pkt, [self.dev_port1])

            print("Sending IPv6 packet with dscp=6 - encap with VPN SID fd00:201:201:fff1:21::")
            send_packet(self, self.dev_port3, self.v6_pkt)
            verify_packets(self, m_sr6_v6_pkt, [self.dev_port1])

            #test with dscp=8
            # --- Test case 3: DSCP 8 -> FC 2 -> VPN SID fd00:201:201:fff1:22:: ---
            # Update packet TOS/TC fields to DSCP 8
            self.pkt[IP].tos = (8<<2) & 0xff
            self.v6_pkt[IPv6].tc = (8<<2) & 0xff
            self.inner_v4_pkt[IP].tos = (8<<2) & 0xff
            self.exp_v6_pkt[IPv6].tc = (8<<2) & 0xff

            sr6_v4_pkt = simple_ipv6ip_packet(
                eth_src=ROUTER_MAC,
                eth_dst=self.srv6_mac,
                ipv6_src=self.srv6_src_ip,
                ipv6_dst="fd00:201:201:fff1:22::",
                ipv6_tc = ((8<<2) & 0xff),
                ipv6_hlim=63,
                inner_frame=self.inner_v4_pkt[IP])
            sr6_v6_pkt = simple_ipv6ip_packet(
                eth_src=ROUTER_MAC,
                eth_dst=self.srv6_mac,
                ipv6_src=self.srv6_src_ip,
                ipv6_dst="fd00:201:201:fff1:22::",
                ipv6_tc = ((8<<2) & 0xff),
                ipv6_hlim=63,
                inner_frame=self.exp_v6_pkt[IPv6])

            m_sr6_v4_pkt = Mask(sr6_v4_pkt)
            m_sr6_v4_pkt.set_do_not_care_scapy(IPv6, 'fl')
            m_sr6_v6_pkt = Mask(sr6_v6_pkt)
            m_sr6_v6_pkt.set_do_not_care_scapy(IPv6, 'fl')

            print("Sending IPv4 packet with dscp=8 - encap with VPN SID fd00:201:201:fff1:22::")

            send_packet(self, self.dev_port3, self.pkt)
            verify_packets(self, m_sr6_v4_pkt, [self.dev_port1])

            print("Sending IPv6 packet with dscp=8 - encap with VPN SID fd00:201:201:fff1:22::")
            send_packet(self, self.dev_port3, self.v6_pkt)
            verify_packets(self, m_sr6_v6_pkt, [self.dev_port1])

            pass

        finally:
            sai_thrift_remove_route_entry(self.client, tmp_over_v6_route_entry)
            sai_thrift_remove_route_entry(self.client, tmp_over_route_entry)
            sai_thrift_remove_tunnel_map_entry(self.client, inner_tunnel_map_entry2)
            sai_thrift_remove_tunnel_map_entry(self.client, inner_tunnel_map_entry1)
            sai_thrift_remove_tunnel_map_entry(self.client, inner_tunnel_map_entry0)
            sai_thrift_remove_tunnel_map_entry(self.client, outer_tunnel_map_entry)
            sai_thrift_remove_tunnel_map(self.client, inner_tunnel_map)
            sai_thrift_remove_next_hop(self.client, sr_nhop_sidmarking)
            sai_thrift_remove_tunnel(self.client, sr_tunnel_sidmrking)
            sai_thrift_remove_tunnel_map(self.client, outer_tunnel_map)
            # Cleanup: unbind QOS map from port
            sai_thrift_set_port_attribute(
                self.client,
                self.port3,
                qos_dscp_to_forwarding_class_map=0)
            sai_thrift_remove_qos_map(self.client, dscp_to_fc_map)