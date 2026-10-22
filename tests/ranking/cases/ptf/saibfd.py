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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

'''
Thrift SAI BFD tests for alibaba use case
'''

import time

from scapy.all import Ether
from sai_thrift.sai_headers import *

from sai_base_test import *

from sai_thrift.ttypes import sai_thrift_neighbor_entry_t as _sai_thrift_neighbor_entry_t_origin
from sai_thrift.ttypes import sai_thrift_route_entry_t as _sai_thrift_route_entry_t_origin
import sai_base_test as _sai_base_test


def _get_switch_id():
    helper = getattr(_sai_base_test, '_current_sai_helper', None)
    return helper.switch_id if helper is not None else None


def sai_thrift_neighbor_entry_t(switch_id=None, **kwargs):
    if switch_id is None:
        switch_id = _get_switch_id()
    return _sai_thrift_neighbor_entry_t_origin(switch_id=switch_id, **kwargs)


def sai_thrift_route_entry_t(switch_id=None, **kwargs):
    if switch_id is None:
        switch_id = _get_switch_id()
    return _sai_thrift_route_entry_t_origin(switch_id=switch_id, **kwargs)


@group("draft")
class BfdTestHelper(SaiHelperSimplified):
    """
    BFD test base helper class.
    Topology:
    +----------+-----------+------------------+
    | port0    | port0_rif | default_vrf(vrf1)|
    +----------+-----------+------------------+
    | port1    | port1_rif | default_vrf(vrf1)|
    +----------+-----------+------------------+
    | port2    | port2_rif | default_vrf(vrf1)|
    +----------+-----------+------------------+
    | port3    | port3_rif | vrf0 (gid=0)     | <- for SRv6 BFD
    +----------+-----------+------------------+
    """

    def setUp(self):
        super(BfdTestHelper, self).setUp()
        self.create_routing_interfaces(ports=[0, 1, 2])

        # Get vrf0 (device default VRF, gid=0) via SAI switch attribute.
        attr = sai_thrift_get_switch_attribute(
            self.client, default_virtual_router_id=True)
        self.vrf0 = attr['default_virtual_router_id']
        self.assertNotEqual(self.vrf0, 0, 'Failed to get default_virtual_router_id')

        # port3 RIF is bound to vrf0 (gid=0) for SRv6 BFD use
        self.port3_rif = sai_thrift_create_router_interface(
            self.client,
            type=SAI_ROUTER_INTERFACE_TYPE_PORT,
            virtual_router_id=self.vrf0,
            port_id=self.port3)
        print('####  BfdTestHelper: default_vrf=0x%x  vrf0=0x%x  port3_rif=0x%x'
              % (self.default_vrf, self.vrf0, self.port3_rif))

    def tearDown(self):
        sai_thrift_remove_router_interface(self.client, self.port3_rif)
        self.destroy_routing_interfaces()
        super(BfdTestHelper, self).tearDown()

    def _parse_ipv6_addr(self, raw, offset):
        """Parse 16-byte IPv6 address from raw packet bytes."""
        return ':'.join('%02x%02x' % (
            (raw[offset+i] if isinstance(raw[offset+i], int) else ord(raw[offset+i])),
            (raw[offset+i+1] if isinstance(raw[offset+i+1], int) else ord(raw[offset+i+1]))
        ) for i in range(0, 16, 2))

    def _parse_u8(self, raw, offset):
        return raw[offset] if isinstance(raw[offset], int) else ord(raw[offset])

    def _parse_u16(self, raw, offset):
        return (self._parse_u8(raw, offset) << 8) | self._parse_u8(raw, offset + 1)

    def _parse_u32(self, raw, offset):
        return (self._parse_u8(raw, offset) << 24) | (self._parse_u8(raw, offset+1) << 16) | \
               (self._parse_u8(raw, offset+2) << 8) | self._parse_u8(raw, offset+3)

    def _validate_srv6_bfd_packet(self, raw, expected_outer_src, expected_outer_dst,
                                   expected_inner_src, expected_inner_dst,
                                   expected_udp_dport, expected_bfd_my_disc,
                                   expected_bfd_your_disc=None):
        """
        Validate SRv6 BFD packet fields.
        Packet layout: Eth(14) | Outer IPv6(40) [Inner IPv6(40) | UDP(8) | BFD(24)]
        When single SID, SRH is optimized out (next_header=41/IPv6 directly).
        """
        # Ethernet
        ethertype = self._parse_u16(raw, 12)
        self.assertEqual(ethertype, 0x86DD, 'Expected IPv6 ethertype')

        # Outer IPv6
        outer_nh = self._parse_u8(raw, 20)
        outer_hlim = self._parse_u8(raw, 21)
        outer_src = self._parse_ipv6_addr(raw, 22)
        outer_dst = self._parse_ipv6_addr(raw, 38)
        self.assertEqual(outer_src, expected_outer_src,
            'Outer IPv6 src mismatch: expected %s got %s' % (expected_outer_src, outer_src))
        self.assertEqual(outer_dst, expected_outer_dst,
            'Outer IPv6 dst mismatch: expected %s got %s' % (expected_outer_dst, outer_dst))
        self.assertIn(outer_nh, [41, 43],
            'Outer IPv6 next_header should be 41(IPv6) or 43(SRH), got %d' % outer_nh)
        self.assertEqual(outer_hlim, 255, 'Outer hop limit should be 255')
        print('  Outer IPv6: src=%s dst=%s nh=%d hlim=%d' % (outer_src, outer_dst, outer_nh, outer_hlim))

        # Inner IPv6 (offset 54 if no SRH)
        inner_offset = 54
        inner_nh = self._parse_u8(raw, inner_offset + 6)
        inner_hlim = self._parse_u8(raw, inner_offset + 7)
        inner_src = self._parse_ipv6_addr(raw, inner_offset + 8)
        inner_dst = self._parse_ipv6_addr(raw, inner_offset + 24)
        self.assertEqual(inner_src, expected_inner_src,
            'Inner IPv6 src mismatch: expected %s got %s' % (expected_inner_src, inner_src))
        self.assertEqual(inner_dst, expected_inner_dst,
            'Inner IPv6 dst mismatch: expected %s got %s' % (expected_inner_dst, inner_dst))
        self.assertEqual(inner_nh, 17, 'Inner IPv6 next_header should be UDP(17), got %d' % inner_nh)
        print('  Inner IPv6: src=%s dst=%s nh=%d hlim=%d' % (inner_src, inner_dst, inner_nh, inner_hlim))

        # UDP
        udp_offset = inner_offset + 40
        udp_sport = self._parse_u16(raw, udp_offset)
        udp_dport = self._parse_u16(raw, udp_offset + 2)
        self.assertEqual(udp_dport, expected_udp_dport,
            'UDP dport mismatch: expected %d got %d' % (expected_udp_dport, udp_dport))
        print('  UDP: sport=%d dport=%d' % (udp_sport, udp_dport))

        # BFD
        bfd_offset = udp_offset + 8
        bfd_ver = self._parse_u8(raw, bfd_offset) >> 5
        bfd_diag = self._parse_u8(raw, bfd_offset) & 0x1F
        bfd_state = self._parse_u8(raw, bfd_offset + 1) >> 6
        bfd_my_disc = self._parse_u32(raw, bfd_offset + 4)
        bfd_your_disc = self._parse_u32(raw, bfd_offset + 8)
        self.assertEqual(bfd_ver, 1, 'BFD version should be 1, got %d' % bfd_ver)
        self.assertEqual(bfd_my_disc, expected_bfd_my_disc,
            'BFD my_discriminator mismatch: expected 0x%x got 0x%x' % (expected_bfd_my_disc, bfd_my_disc))
        if expected_bfd_your_disc is not None:
            self.assertEqual(bfd_your_disc, expected_bfd_your_disc,
                'BFD your_discriminator mismatch: expected 0x%x got 0x%x' % (expected_bfd_your_disc, bfd_your_disc))
        print('  BFD: ver=%d diag=%d state=%d my_disc=0x%08x your_disc=0x%08x'
              % (bfd_ver, bfd_diag, bfd_state, bfd_my_disc, bfd_your_disc))


@group("draft")
class BfdEchoSrv6Test(BfdTestHelper):
    """
    BFD Echo for SRv6 test.
    """

    def setUp(self):
        super(BfdEchoSrv6Test, self).setUp()

        self.my_ip    = '2000::58'
        self.peer_ip  = '2000::59'
        self.nbor_mac = '00:aa:bb:cc:dd:ee'
        self.vpn_sid  = 'fd00:303:2022:fff1:eee::'

        self.echo_local_disc     = 720954906
        self.echo_remote_disc    = 720954906
        self.echo_udp_src_port   = 3784
        self.echo_min_tx         = 300000
        self.echo_min_rx         = 300000
        self.echo_multiplier     = 3
        self.echo_desired_min_tx = 300000
        self.echo_desired_min_rx = 300000
        self.echo_local_multiplier = 3

        print('####  BfdSessionTest: vrf0=0x%x  port3_rif=0x%x'
              % (self.vrf0, self.port3_rif))

        # Loopback RIF under vrf0
        self.urif_lb = sai_thrift_create_router_interface(
            self.client,
            type=SAI_ROUTER_INTERFACE_TYPE_LOOPBACK,
            virtual_router_id=self.vrf0)

        # Underlay neighbor / next-hop toward remote router
        self.echo_nbor = sai_thrift_neighbor_entry_t(
            rif_id=self.port3_rif,
            ip_address=sai_ipaddress(self.peer_ip))
        sai_thrift_create_neighbor_entry(
            self.client, self.echo_nbor,
            dst_mac_address=self.nbor_mac)

        self.echo_nhop = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_IP,
            ip=sai_ipaddress(self.peer_ip),
            router_interface_id=self.port3_rif)

        # Outer route for SID under vrf0
        self.srv6_sid_route = sai_thrift_route_entry_t(
            vr_id=self.vrf0,
            destination=sai_ipprefix('fd00:303:2022:fff1:eee::/128'))
        sai_thrift_create_route_entry(
            self.client, self.srv6_sid_route, next_hop_id=self.echo_nhop)

        # Route for my_ip under vrf0
        self.my_ip_route = sai_thrift_route_entry_t(
            vr_id=self.vrf0,
            destination=sai_ipprefix('2000::58/128'))
        sai_thrift_create_route_entry(
            self.client, self.my_ip_route, next_hop_id=self.echo_nhop)

        # SRv6 SID list
        sai_segment_list = sai_thrift_segment_list_t(
            count=1, ip6list=[self.vpn_sid])
        self.srv6_sidlist = sai_thrift_create_srv6_sidlist(
            self.client,
            type=SAI_SRV6_SIDLIST_TYPE_ENCAPS_RED,
            segment_list=sai_segment_list)
        self.assertNotEqual(self.srv6_sidlist, SAI_NULL_OBJECT_ID,
                            'Failed to create SRv6 sidlist')

        # BFD Echo SRv6 session
        self.echo_session = sai_thrift_create_bfd_session(
            self.client,
            type=SAI_BFD_SESSION_TYPE_ASYNC_ACTIVE,
            local_discriminator=self.echo_local_disc,
            remote_discriminator=self.echo_remote_disc,
            udp_src_port=self.echo_udp_src_port,
            tc=0,
            iphdr_version=6,
            ttl=255 - 0x100,
            tos=0,
            src_ip_address=sai_ipaddress(self.my_ip),
            dst_ip_address=sai_ipaddress(self.my_ip),
            min_tx=self.echo_min_tx,
            min_rx=self.echo_min_rx,
            multiplier=self.echo_multiplier,
            desired_min_tx=self.echo_desired_min_tx,
            desired_min_rx=self.echo_desired_min_rx,
            local_multiplier=self.echo_local_multiplier,
            bfd_encapsulation_type=SAI_BFD_ENCAPSULATION_TYPE_SRV6,
            tunnel_src_ip_address=sai_ipaddress(self.my_ip),
            srv6_sidlist_id=self.srv6_sidlist,
            echo_enable=True,
            virtual_router=self.vrf0,
            offload_type=SAI_BFD_SESSION_OFFLOAD_TYPE_SUSTENANCE,
            hw_lookup_valid=True)
        print('####     srv6_sidlist oid=0x%x' % self.srv6_sidlist)
        print('####     echo_session oid=0x%x' % self.echo_session)

    def runTest(self):
        try:
            self.bfdEchoSrv6CreateTest()
            print('Finished bfdEchoSrv6CreateTest')

            self.bfdEchoSrv6GetAttrTest()
            print('Finished bfdEchoSrv6GetAttrTest')

            self.bfdEchoSrv6SessionStateTest()
            print('Finished bfdEchoSrv6SessionStateTest')

            print('==================================================')
            print('All BFD tests PASSED!')
            print('==================================================')
        finally:
            pass

    def tearDown(self):
        pass

    def bfdEchoSrv6CreateTest(self):
        print('\nbfdEchoSrv6CreateTest()')
        self.assertNotEqual(self.echo_session, SAI_NULL_OBJECT_ID)
        print('####     BFD Echo SRv6 session created: oid=0x%lx' % self.echo_session)

    def bfdEchoSrv6GetAttrTest(self):
        print('\nbfdEchoSrv6GetAttrTest()')
        attrs = sai_thrift_get_bfd_session_attribute(
            self.client,
            self.echo_session,
            type=True,
            hw_lookup_valid=True,
            virtual_router=True,
            bfd_encapsulation_type=True,
            srv6_sidlist_id=True,
            tunnel_src_ip_address=True,
            echo_enable=True,
            offload_type=True)
        self.assertTrue(attrs is not None)
        for k, v in attrs.items():
            print('####       %s = %s' % (k, v))
        self.assertTrue(attrs.get('hw_lookup_valid') is True)
        self.assertEqual(attrs.get('bfd_encapsulation_type'),
                         SAI_BFD_ENCAPSULATION_TYPE_SRV6,
                         'BFD encapsulation type should be SRV6')
        self.assertTrue(attrs.get('echo_enable'),
                        'Echo enable should be True')
        self.assertNotEqual(attrs.get('srv6_sidlist_id'), SAI_NULL_OBJECT_ID,
                            'SRv6 SID list ID should not be null')

    def bfdEchoSrv6SessionStateTest(self):
        print('\nbfdEchoSrv6SessionStateTest()')
        print('  Waiting for DUT sBFD Echo SRv6 packet on port3 ...')
        captured = None
        deadline = time.time() + 10.0
        while time.time() < deadline:
            result = self.dataplane.poll(device_number=0, port_number=3, timeout=1.0)
            raw = result[2]
            if raw is None:
                continue
            ethertype = self._parse_u16(raw, 12)
            if ethertype != 0x86DD:
                continue
            ipv6_dst = self._parse_ipv6_addr(raw, 38)
            if not ipv6_dst.startswith('fd00:'):
                continue
            captured = raw
            break

        self.assertIsNotNone(captured,
            'No packet received on port3 within 10s - DUT did not send sBFD Echo')

        print('  Captured packet: %d bytes' % len(captured))
        hex_str = ' '.join('%02x' % self._parse_u8(captured, i) for i in range(len(captured)))
        print('  RAW HEX: %s' % hex_str)

        # Validate all key fields
        # BFD Echo: SDK puts local_disc in your_disc, my_disc=0
        self._validate_srv6_bfd_packet(
            captured,
            expected_outer_src='2000:0000:0000:0000:0000:0000:0000:0058',
            expected_outer_dst='fd00:0303:2022:fff1:0eee:0000:0000:0000',
            expected_inner_src='2000:0000:0000:0000:0000:0000:0000:0058',
            expected_inner_dst='2000:0000:0000:0000:0000:0000:0000:0058',
            expected_udp_dport=3785,  # BFD Echo port
            expected_bfd_my_disc=0,  # Echo: my_disc=0 per SDK
            expected_bfd_your_disc=self.echo_local_disc)  # Echo: your_disc=local_disc

        print('  sBFD Echo SRv6 packet validated - PASS')


@group("draft")
class BfdSingleHopTest(BfdTestHelper):
    """
    Plain IPv4 single-hop BFD session (no SRv6 encap).
    """

    def setUp(self):
        super(BfdSingleHopTest, self).setUp()

        self.my_ip    = '10.2.2.1'
        self.peer_ip  = '10.2.2.2'
        self.nbor_mac = '00:aa:bb:cc:dd:ee'

        self.local_disc   = 111111
        self.remote_disc  = 222222
        self.udp_src_port = 49155
        self.min_tx       = 300000
        self.min_rx       = 300000
        self.multiplier   = 3
        self.desired_min_tx   = 300000
        self.desired_min_rx   = 300000
        self.local_multiplier = 3

        print('####  BfdSingleHopTest setUp: default_vrf=0x%x  port2_rif=0x%x'
              % (self.default_vrf, self.port2_rif))

        # Neighbor toward peer
        self.nbor = sai_thrift_neighbor_entry_t(
            rif_id=self.port2_rif,
            ip_address=sai_ipaddress(self.peer_ip))
        sai_thrift_create_neighbor_entry(
            self.client, self.nbor,
            dst_mac_address=self.nbor_mac)

        # Next-hop toward peer
        self.nhop = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_IP,
            ip=sai_ipaddress(self.peer_ip),
            router_interface_id=self.port2_rif)

        # Route: 10.2.2.2/32 -> nhop
        self.peer_route = sai_thrift_route_entry_t(
            vr_id=self.default_vrf,
            destination=sai_ipprefix('10.2.2.2/32'))
        sai_thrift_create_route_entry(
            self.client, self.peer_route, next_hop_id=self.nhop)

        # Plain IPv4 single-hop BFD session
        self.session = sai_thrift_create_bfd_session(
            self.client,
            type=SAI_BFD_SESSION_TYPE_ASYNC_ACTIVE,
            local_discriminator=self.local_disc,
            remote_discriminator=self.remote_disc,
            udp_src_port=self.udp_src_port,
            tc=0,
            iphdr_version=4,
            ttl=255 - 0x100,
            tos=0,
            src_ip_address=sai_ipaddress(self.my_ip),
            dst_ip_address=sai_ipaddress(self.peer_ip),
            min_tx=self.min_tx,
            min_rx=self.min_rx,
            multiplier=self.multiplier,
            desired_min_tx=self.desired_min_tx,
            desired_min_rx=self.desired_min_rx,
            local_multiplier=self.local_multiplier,
            bfd_encapsulation_type=SAI_BFD_ENCAPSULATION_TYPE_NONE,
            virtual_router=self.default_vrf,
            offload_type=SAI_BFD_SESSION_OFFLOAD_TYPE_SUSTENANCE,
            hw_lookup_valid=True)
        print('####     single-hop BFD session oid=%s' % self.session)
        self.assertNotEqual(self.session, SAI_NULL_OBJECT_ID,
                            'Failed to create single-hop BFD session')

    def runTest(self):
        try:
            self.bfdSingleHopTxTest()
            print('==================================================')
            print('BfdSingleHopTest PASSED!')
            print('==================================================')
        finally:
            pass

    def tearDown(self):
        pass

    def bfdSingleHopTxTest(self):
        print('\nbfdSingleHopTxTest()')
        print('  Waiting for DUT BFD packet on port2 (up to 10s) ...')
        captured = None
        deadline = time.time() + 10.0
        while time.time() < deadline:
            result = self.dataplane.poll(device_number=0, port_number=2, timeout=1.0)
            raw = result[2]
            if raw is None:
                continue
            ethertype = (raw[12] if isinstance(raw[12], int) else ord(raw[12])) << 8 | \
                        (raw[13] if isinstance(raw[13], int) else ord(raw[13]))
            if ethertype != 0x0800:
                continue
            ipv4_dst_bytes = raw[30:34]
            ipv4_dst = '.'.join('%d' % (b if isinstance(b, int) else ord(b))
                                for b in ipv4_dst_bytes)
            if ipv4_dst != '10.2.2.2':
                continue
            captured = raw
            break

        self.assertIsNotNone(captured,
            'No BFD packet received on port2 within 10s - DUT did not send BFD')

        print('  Captured packet: %d bytes' % len(captured))

        def _b(raw, i):
            return raw[i] if isinstance(raw[i], int) else ord(raw[i])

        def _u16(raw, i):
            return (_b(raw, i) << 8) | _b(raw, i + 1)

        def _u32(raw, i):
            return (_b(raw, i) << 24) | (_b(raw, i+1) << 16) | (_b(raw, i+2) << 8) | _b(raw, i+3)

        # Verify IPv4 src/dst
        ipv4_src = '.'.join('%d' % _b(captured, i) for i in range(26, 30))
        ipv4_dst = '.'.join('%d' % _b(captured, i) for i in range(30, 34))
        self.assertEqual(ipv4_src, self.my_ip)
        self.assertEqual(ipv4_dst, self.peer_ip)

        # Verify UDP dport
        udp_dport = _u16(captured, 36)
        self.assertEqual(udp_dport, 3784)

        # Verify BFD discriminators
        bfd_my_disc   = _u32(captured, 46)
        bfd_your_disc = _u32(captured, 50)
        self.assertEqual(bfd_my_disc, self.local_disc)
        self.assertEqual(bfd_your_disc, self.remote_disc)

        print('  Single-hop BFD packet verification PASS')


@group("draft")
class SbfdInitiatorSrv6Test(BfdTestHelper):
    """
    SBFD Initiator for SRv6 test.
    DUT sends: IPv6(SID) / IPv6(src->dst) / UDP(sbfd) / BFD
    """

    def setUp(self):
        super(SbfdInitiatorSrv6Test, self).setUp()

        peer_ip = '2000::59'
        sid = 'fd00:303:2022:fff1:eee::'

        # Neighbor + nexthop on port3_rif toward peer
        nbor = sai_thrift_neighbor_entry_t(
            rif_id=self.port3_rif,
            ip_address=sai_ipaddress(peer_ip))
        sai_thrift_create_neighbor_entry(
            self.client, nbor, dst_mac_address='00:aa:bb:cc:dd:ee')
        self.nhop = sai_thrift_create_next_hop(
            self.client,
            type=SAI_NEXT_HOP_TYPE_IP,
            ip=sai_ipaddress(peer_ip),
            router_interface_id=self.port3_rif)

        # Route for SID -> nexthop
        self.sid_route = sai_thrift_route_entry_t(
            vr_id=self.vrf0,
            destination=sai_ipprefix(sid + '/128'))
        sai_thrift_create_route_entry(
            self.client, self.sid_route, next_hop_id=self.nhop)

        # SRv6 SID list
        self.sidlist = sai_thrift_create_srv6_sidlist(
            self.client,
            type=SAI_SRV6_SIDLIST_TYPE_ENCAPS,
            segment_list=sai_thrift_segment_list_t(count=1, ip6list=[sid]))

        # SBFD Initiator session
        self.bfd = sai_thrift_create_bfd_session(
            self.client,
            type=SAI_BFD_SESSION_TYPE_INITIATOR,
            local_discriminator=12345,
            remote_discriminator=10087,
            udp_src_port=7784,
            iphdr_version=6,
            ttl=255 - 0x100,
            src_ip_address=sai_ipaddress('2000::58'),
            dst_ip_address=sai_ipaddress(peer_ip),
            min_tx=300000, min_rx=300000, multiplier=3,
            desired_min_tx=300000, desired_min_rx=300000, local_multiplier=3,
            bfd_encapsulation_type=SAI_BFD_ENCAPSULATION_TYPE_SRV6,
            srv6_sidlist_id=self.sidlist,
            tunnel_src_ip_address=sai_ipaddress('2000::58'),
            virtual_router=self.vrf0,
            offload_type=SAI_BFD_SESSION_OFFLOAD_TYPE_SUSTENANCE,
            hw_lookup_valid=True)
        self.assertNotEqual(self.bfd, SAI_NULL_OBJECT_ID, 'Failed to create SBFD Initiator session')

    def runTest(self):
        print('\nSbfdInitiatorSrv6Test: Waiting for packet on port3 ...')
        captured = None
        deadline = time.time() + 10.0
        while time.time() < deadline:
            result = self.dataplane.poll(device_number=0, port_number=3, timeout=1.0)
            raw = result[2]
            if raw is None:
                continue
            ethertype = self._parse_u16(raw, 12)
            if ethertype != 0x86DD:
                continue
            ipv6_dst = self._parse_ipv6_addr(raw, 38)
            if ipv6_dst.startswith('fd00:0303:2022:fff1:0eee'):
                captured = raw
                break

        self.assertIsNotNone(captured,
            'No SBFD packet received on port3 within 10s')

        print('  Captured packet: %d bytes' % len(captured))

        # Validate all key fields
        self._validate_srv6_bfd_packet(
            captured,
            expected_outer_src='2000:0000:0000:0000:0000:0000:0000:0058',
            expected_outer_dst='fd00:0303:2022:fff1:0eee:0000:0000:0000',
            expected_inner_src='2000:0000:0000:0000:0000:0000:0000:0058',
            expected_inner_dst='2000:0000:0000:0000:0000:0000:0000:0059',
            expected_udp_dport=7784,  # SBFD port
            expected_bfd_my_disc=12345,
            expected_bfd_your_disc=10087)

        print('  SBFD Initiator SRv6 packet validated - PASS')

    def tearDown(self):
        pass


@group("draft")
class SbfdReflectorSrv6Test(BfdTestHelper):
    """
    SBFD Reflector test - verify session attributes via GET.
    """

    def setUp(self):
        super(SbfdReflectorSrv6Test, self).setUp()

        self.bfd = sai_thrift_create_bfd_session(
            self.client,
            type=SAI_BFD_SESSION_TYPE_REFLECTOR,
            local_discriminator=10087,
            remote_discriminator=0,
            udp_src_port=0,
            iphdr_version=6,
            ttl=255 - 0x100,
            src_ip_address=sai_ipaddress('2000::59'),
            dst_ip_address=sai_ipaddress('::'),
            min_tx=300000, min_rx=300000, multiplier=3,
            desired_min_tx=300000, desired_min_rx=300000, local_multiplier=3,
            bfd_encapsulation_type=SAI_BFD_ENCAPSULATION_TYPE_NONE,
            virtual_router=self.vrf0,
            offload_type=SAI_BFD_SESSION_OFFLOAD_TYPE_SUSTENANCE,
            hw_lookup_valid=True)
        self.assertNotEqual(self.bfd, SAI_NULL_OBJECT_ID, 'Failed to create SBFD Reflector session')

    def runTest(self):
        print('\nSbfdReflectorSrv6Test: Verifying attributes ...')
        attr = sai_thrift_get_bfd_session_attribute(
            self.client, self.bfd,
            type=True, hw_lookup_valid=True,
            local_discriminator=True, remote_discriminator=True,
            bfd_encapsulation_type=True, virtual_router=True)
        self.assertEqual(attr['type'], SAI_BFD_SESSION_TYPE_REFLECTOR)
        self.assertEqual(attr['local_discriminator'], 10087)
        self.assertEqual(attr['remote_discriminator'], 0)
        self.assertEqual(attr['bfd_encapsulation_type'], SAI_BFD_ENCAPSULATION_TYPE_NONE)
        self.assertTrue(attr['hw_lookup_valid'])
        print('  SBFD Reflector attributes verified - PASS')

    def tearDown(self):
        pass
