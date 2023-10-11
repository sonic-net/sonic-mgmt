import pytest

import ipaddress
import re
import time
import logging

from collections import defaultdict
from scapy.all import Packet, BitField, ByteField, FieldLenField, PacketListField, IPv6ExtHdrHopByHop, NBytesField
import ptf.mask as mask
import ptf.packet as packet
import ptf.testutils as testutils

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0", "t1")
]


class MCD(Packet):
    name = "Midpoint Compress Data (MCD)"
    fields_desc = [
        BitField("oif", 0, 12),
        BitField("oil", 0, 4),
        BitField("tts", 0, 8),
    ]


class HopByHopHdrPathTracing(Packet):
    """
    IPv6 Hop-By-Hop Path Tracing Option, draft-filsfils-spring-path-tracing-05, section #9.1
    
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |  Option Type  |  Opt Data Len |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    ~                          MCD  Stack                           ~
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Reference:
        https://www.ietf.org/archive/id/draft-filsfils-spring-path-tracing-05.html
    """
    name = "Hop-by-Hop Header Path Tracing"
    fields_desc = [ByteField("otype", 0x32),
                   FieldLenField("optlen", None, length_of="mcdstack", fmt="B"),
                   PacketListField("mcdstack", [], MCD)]

    def alignment_delta(self, curpos):  # alignment requirement : 4n+2
        x = 4
        y = 2
        delta = x * ((curpos - y + x - 1) // x) + y - curpos
        return delta

    def extract_padding(self, p):
        return b"", p


class DestinationOptionHdrPathTracing(Packet):
    name = "Destination Option Header Path Tracing"
    fields_desc = [ByteField("otype", 0x13),
                   ByteField("optlen", 4),
                   NBytesField("t64", 0, 8),
                   NBytesField("sessionId", 0, 2),
                   BitField("ifId", 0, 12),
                   BitField("ifLd", 0, 4)]

    def alignment_delta(self, curpos):  # alignment requirement : 4n+2
        x = 4
        y = 2
        delta = x * ((curpos - y + x - 1) // x) + y - curpos
        return delta

    def extract_padding(self, p):
        return b"", p


class TestPathTracingMidpoint:
    """
    Base class for Path Tracing Midpoint testing.
    """

    @staticmethod
    def parse_interfaces(output_lines, pc_ports_map):
        """
        Parse the inerfaces from 'show ip route' into an array
        """
        route_targets = []
        ifaces = []
        output_lines = output_lines[3:]

        for item in output_lines:
            match = re.search(r"(Ethernet\d+|PortChannel\d+)", item)
            if match:
                route_targets.append(match.group(0))

        for route_target in route_targets:
            if route_target.startswith("Ethernet"):
                ifaces.append(route_target)
            elif route_target.startswith("PortChannel") and route_target in pc_ports_map:
                ifaces.extend(pc_ports_map[route_target])

        return route_targets, ifaces

    @pytest.fixture(scope="class")
    def common_param(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

        # generate peer_ip and port channel pair, be like:[("10.0.0.57", "PortChannel0001")]
        peer_ip_pc_pair = [(pc["peer_addr"], pc["attachto"]) for pc in mg_facts["minigraph_portchannel_interfaces"]
                           if ipaddress.ip_address(pc['peer_addr']).version == 6]
        pc_ports_map = {pair[1]: mg_facts["minigraph_portchannels"][pair[1]]["members"] for pair in
                        peer_ip_pc_pair}

        # generate peer_ip and interfaces pair,
        # be like:[("10.0.0.57", ["Ethernet48"])]
        router_port_peer_ip_ifaces_pair = \
            [(intf["peer_addr"], [intf["attachto"]],  mg_facts["minigraph_neighbors"][intf["attachto"]]['namespace'])
             for intf in mg_facts["minigraph_interfaces"] if ipaddress.ip_address(intf['peer_addr']).version == 6]
        # generate peer_ip and interfaces(port channel members) pair,
        # be like:[("10.0.0.57", ["Ethernet48", "Ethernet52"])]
        port_channel_peer_ip_ifaces_pair = \
            [(pair[0], mg_facts["minigraph_portchannels"][pair[1]]["members"],
              mg_facts["minigraph_neighbors"][mg_facts["minigraph_portchannels"][pair[1]]["members"][0]]['namespace'])
             for pair in peer_ip_pc_pair]

        namespace_with_min_two_ip_interface = None
        peer_ip_ifaces_pair_list = [router_port_peer_ip_ifaces_pair, port_channel_peer_ip_ifaces_pair]
        namespace_neigh_cnt_map = defaultdict(list)
        for idx, peer_ip_ifaces in enumerate(peer_ip_ifaces_pair_list):
            for peer_idx, peer_info in enumerate(peer_ip_ifaces):
                namespace_neigh_cnt_map[peer_info[2]].append((idx, peer_idx))
                if len(namespace_neigh_cnt_map[peer_info[2]]) == 2:
                    namespace_with_min_two_ip_interface = peer_info[2]
                    break
            if namespace_with_min_two_ip_interface is not None:
                break

        selected_peer_ip_ifaces_pairs = []
        rif_rx_ifaces = None
        if namespace_with_min_two_ip_interface is not None:
            for v in namespace_neigh_cnt_map[namespace_with_min_two_ip_interface]:
                selected_peer_ip_ifaces_pairs.append(peer_ip_ifaces_pair_list[v[0]][v[1]])
                if not rif_rx_ifaces:
                    if v[0]:
                        rif_rx_ifaces = \
                            list(pc_ports_map.keys())[list(pc_ports_map.values())
                                                      .index(selected_peer_ip_ifaces_pairs[0][1])]
                    else:
                        rif_rx_ifaces = selected_peer_ip_ifaces_pairs[0][1][0]
        else:
            pytest.skip("Skip test as not enough neighbors/ports.")

        # use first port of first peer_ip_ifaces pair as input port
        # all ports in second peer_ip_ifaces pair will be output/forward port
        ptf_port_idx = mg_facts["minigraph_ptf_indices"][selected_peer_ip_ifaces_pairs[0][1][0]]
        ptf_port_idx_namespace = namespace_with_min_two_ip_interface
        asic_id = duthost.get_asic_id_from_namespace(ptf_port_idx_namespace)
        ingress_router_mac = duthost.asic_instance(asic_id).get_router_mac()

        # Some platforms do not support rif counter
        try:
            rif_counter_out = TestIPPacket.parse_rif_counters(
                duthost.command("show interfaces counters rif")["stdout_lines"])
            rif_iface = list(rif_counter_out.keys())[0]
            rif_support = False if rif_counter_out[rif_iface]['rx_err'] == 'N/A' else True
        except Exception as e:
            logger.info("Show rif counters failed with exception: {}".format(repr(e)))
            rif_support = False

        for prefix in ["2001:db8:2::1/128"]:
            duthost.shell(duthost.get_vtysh_cmd_for_namespace(
                "vtysh -c \"configure terminal\" -c \"ip route {} {} tag 1\""
                .format(prefix, selected_peer_ip_ifaces_pairs[1][0]), ptf_port_idx_namespace))
        yield selected_peer_ip_ifaces_pairs, rif_rx_ifaces, rif_support, \
            ptf_port_idx, pc_ports_map, mg_facts["minigraph_ptf_indices"], ingress_router_mac

        for prefix in ["2001:db8:2::1/128"]:
            duthost.shell(duthost.get_vtysh_cmd_for_namespace(
                "vtysh -c \"configure terminal\" -c \"no ip route {} {} tag 1\""
                .format(prefix, selected_peer_ip_ifaces_pairs[1][0]), ptf_port_idx_namespace))

    def teardown_path_tracing(self, duthost):
        """
        teardown Path Tracing after test by disabling Path Tracing on all interfaces
        :param duthost: DUT host object
        :return:
        """
        logger.info("Disable Path Tracing")
        self.config_path_tracing(duthost, ifname="Ethernet8", enable=False)

    def simple_ipv6_packet(
        pktlen=100,
        eth_dst="00:01:02:03:04:05",
        eth_src="00:06:07:08:09:0a",
        ipv6_src="2001:db8:85a3::8a2e:370:7334",
        ipv6_dst="2001:db8:85a3::8a2e:370:7335",
        ipv6_tc=0,
        ipv6_ecn=None,
        ipv6_dscp=None,
        ipv6_hlim=64,
        ipv6_fl=0,
    ):
        """
        Return a simple IPv6 packet

        Supports a few parameters:
        @param len Length of packet in bytes w/o CRC
        @param eth_dst Destination MAC
        @param eth_src Source MAC
        @param ipv6_src IPv6 source
        @param ipv6_dst IPv6 destination
        @param ipv6_tc IPv6 traffic class
        @param ipv6_ecn IPv6 traffic class ECN
        @param ipv6_dscp IPv6 traffic class DSCP
        @param ipv6_ttl IPv6 hop limit
        @param ipv6_fl IPv6 flow label

        Generates a simple IPv6 packet. Users shouldn't assume anything about this
        packet other than that it is a valid ethernet/IPv6 frame.
        """

        ipv6_tc = testutils.ip_make_tos(ipv6_tc, ipv6_ecn, ipv6_dscp)

        pkt = packet.Ether(dst=eth_dst, src=eth_src)
        pkt /= packet.IPv6(
            src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim
        )

        return pkt

    def ipv6_packet_no_hbh_pt(self, common_param, ptfadapter):
        """ create IPv6 packet for testing """

        (peer_ip_ifaces_pair, rif_rx_ifaces, rif_support, ptf_port_idx,
         pc_ports_map, ptf_indices, ingress_router_mac) = common_param

        return TestPathTracingMidpoint.simple_ipv6_packet(
            eth_dst=ingress_router_mac,
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
            ipv6_dst='2001:db8:2::1',
            ipv6_src='2001:db8:1::1',
            ipv6_hlim=64,
        )

    def ipv6_packet_with_hbh_pt(self, common_param, ptfadapter):
        """ create IPv6 packet followed by a Hop-by-Hop Path Tracing Option with an empty MCD stack for testing """

        (peer_ip_ifaces_pair, rif_rx_ifaces, rif_support, ptf_port_idx,
         pc_ports_map, ptf_indices, ingress_router_mac) = common_param

        ipv6_pkt = TestPathTracingMidpoint.simple_ipv6_packet(
            eth_dst=ingress_router_mac,
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
            ipv6_dst='2001:db8:2::1',
            ipv6_src='2001:db8:1::1',
            ipv6_hlim=64,
        )

        hbh_pt = HopByHopHdrPathTracing(
            mcdstack=[

            ]
        )

        doh_pt = DestinationOptionHdrPathTracing(
            t64=0x1234,
            sessionId=0x1,
            ifId=100,
            ifLd=7
        )

        return ipv6_pkt / IPv6ExtHdrHopByHop(options=[hbh_pt, doh_pt])

    def expected_mask_forward_ipv6_packet(self, pkt):
        """ Return mask for ipv6 packet base forwarding """

        exp_pkt = pkt.copy()
        exp_pkt = mask.Mask(exp_pkt, ignore_extra_bytes=True)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IPv6, 'hlim')

        return exp_pkt

    def expected_mask_path_tracing_push_mcd_packet(self, pkt, outgoing_interface_id, outgoing_interface_load=None, truncated_timestamp=None):
        """ return mask for Path Tracing MCD push operation packet """

        if (outgoing_interface_load is None):
            outgoing_interface_load = 0
        if (truncated_timestamp is None):
            truncated_timestamp = 0

        exp_pkt = pkt.copy()
        exp_pkt['HopByHopHdrPathTracing'].mcdstack.append(
            MCD(
                oif=outgoing_interface_id,
                oil=outgoing_interface_load,
                tts=truncated_timestamp
            )
        )
        exp_pkt = mask.Mask(exp_pkt, ignore_extra_bytes=True)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IPv6, 'hlim')
        if (truncated_timestamp is None):
            exp_pkt.set_do_not_care_scapy(MCD, 'tts')
        if (outgoing_interface_load is None):
            exp_pkt.set_do_not_care_scapy(MCD, 'oil')

        return exp_pkt

    def config_path_tracing(self, duthost, ifname, enable=True, interface_id=None, ts_template=None):
        """ Enable/disable Path tracing on interface """

        # Case 1: Disable Path Tracing on interface
        if not enable:
            logger.info('Disabling Path Tracing on interface %s'.format(ifname))
            result = duthost.shell('config interface path-tracing del {}'.format(ifname))
            if result['rc'] != 0:
                pytest.fail('Failed to disable Path Tracing on interface {} : {}'.format(ifname, result['stderr']))
            return

        # Case 2: Enable Path Tracing with default timestamp template
        if ts_template is None:
            logger.info('Enabling Path Tracing on interface %s (interface ID {})'.format(ifname, interface_id))
            result = duthost.shell('config interface path-tracing add {} --interface-id {}'.format(ifname, interface_id))
            if result['rc'] != 0:
                pytest.fail('Failed to enable Path Tracing on interface {} : {}'.format(ifname, result['stderr']))
            return

        # Case 3: Enable Path Tracing with default timestamp template
        logger.info('Enabling Path Tracing on interface %s (interface ID {}, timestamp template "{}")'.format(ifname, interface_id, ts_template))
        result = duthost.shell('config interface path-tracing add {} --interface-id {} --ts-template {}'.format(ifname, interface_id, ts_template))
        if result['rc'] != 0:
            pytest.fail('Failed to enable Path Tracing on interface {} : {}'.format(ifname, result['stderr']))


    def test_base_forwarding(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfadapter, common_param):
        """
        Test scenario in which:
            - Path Tracing is disabled on the port
            - The DUT receives a simple IPv6 packet

        Expected result:
            - The packet is forwarded without any modification
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        (peer_ip_ifaces_pair, rif_rx_ifaces, rif_support, ptf_port_idx,
         pc_ports_map, ptf_indices, ingress_router_mac) = common_param

        pkt = self.ipv6_packet_no_hbh_pt(common_param, ptfadapter)
        exp_pkt = self.expected_mask_forward_ipv6_packet(pkt)

        time.sleep(2)

        out_rif_ifaces, out_ifaces = TestPathTracingMidpoint.parse_interfaces(
            duthost.command("show ip route 2001:db8:2::1")["stdout_lines"], pc_ports_map)
        logger.info("out_rif_ifaces: {}, out_ifaces: {}".format(out_rif_ifaces, out_ifaces))
        out_ptf_indices = [ptf_indices[iface] for iface in out_ifaces]

        self.config_path_tracing(duthost, ifname=out_ifaces[0], enable=False)

        time.sleep(5)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_port_idx, pkt)
        time.sleep(5)
        try:
            res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=list(out_ptf_indices))
            logger.info(res)
        except Exception as e:
            self.teardown_path_tracing(duthost)
            pytest.fail('Simple packet forwarding test failed \n' + str(e))

        self.teardown_path_tracing(duthost)


    def test_path_tracing(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfadapter, common_param):
        """
        Test scenario in which:
            - Path Tracing is enabled on the port
            - The DUT receives an IPv6 packet followed by a HbH-PT

        Expected result:
            - The DUT pushes a new MCD before forwarding the packet on the outgoing interface
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        (peer_ip_ifaces_pair, rif_rx_ifaces, rif_support, ptf_port_idx,
         pc_ports_map, ptf_indices, ingress_router_mac) = common_param

        pkt = self.ipv6_packet_with_hbh_pt(common_param, ptfadapter)
        exp_pkt = self.expected_mask_path_tracing_push_mcd_packet(pkt, 128, None, None)

        time.sleep(2)

        out_rif_ifaces, out_ifaces = TestPathTracingMidpoint.parse_interfaces(
            duthost.command("show ip route 2001:db8:2::1")["stdout_lines"], pc_ports_map)
        logger.info("out_rif_ifaces: {}, out_ifaces: {}".format(out_rif_ifaces, out_ifaces))
        out_ptf_indices = [ptf_indices[iface] for iface in out_ifaces]

        self.config_path_tracing(duthost, ifname=out_ifaces[0], enable=True, interface_id=128)

        time.sleep(5)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_port_idx, pkt)
        time.sleep(5)
        try:
            res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=list(out_ptf_indices))
            logger.info(res)
        except Exception as e:
            self.teardown_path_tracing(duthost)
            pytest.fail('"Path Tracing" test failed \n' + str(e))

        self.teardown_path_tracing(duthost)
