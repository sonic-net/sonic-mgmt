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
    pytest.mark.topology("t1")
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

    @pytest.fixture(scope="class", autouse=True)
    def is_path_tracing_supported(self, duthosts, rand_one_dut_hostname):
        """
        Check if switch supports path tracing, if not then skip test cases
        """
        duthost = duthosts[rand_one_dut_hostname]
        path_tracing_capable = duthost.shell(
            'redis-cli -n 6 hget "SWITCH_CAPABILITY|switch" PATH_TRACING_CAPABLE')['stdout']
        if "true" not in path_tracing_capable:
            pytest.skip("Switch does not support Path Tracing")

    @pytest.fixture(scope="class")
    def setup_info(self, duthosts, rand_one_dut_hostname, tbinfo):

        """
        Collect T0, T2 neighbor interface names, addresses and corresponding PTF indexes
        """
        duthost = duthosts[rand_one_dut_hostname]

        tor_ports = []
        spine_ports = []

        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

        for dut_port, neigh in mg_facts["minigraph_neighbors"].items():
            if "T0" in neigh["name"]:
                tor_ports.append(dut_port)
            elif "T2" in neigh["name"]:
                spine_ports.append(dut_port)

        neigh_if_map = {
            v['name']: iface
            for iface, v in mg_facts["minigraph_neighbors"].items()
        }
        setup_information = {
            "router_mac": duthost.facts["router_mac"],
            "tor_ports": tor_ports,
            "spine_ports": spine_ports,
            "port_index_map": {
                k: v
                for k, v in mg_facts["minigraph_ptf_indices"].items()
                if k in mg_facts["minigraph_ports"]
            },
            "ipv6": {
                neigh_if_map[v["name"]]: v["addr"]
                for v in mg_facts["minigraph_bgp"]
                if ipaddr.IPAddress(v["addr"]).version == 6
            },
            "ipv4": {
                neigh_if_map[v["name"]]: v["addr"]
                for v in mg_facts["minigraph_bgp"]
                if ipaddr.IPAddress(v["addr"]).version == 4
            },
        }

        yield setup_information

    def teardown_path_tracing(self, duthost):
        """
        teardown Path Tracing after test by disabling Path Tracing on all interfaces
        :param duthost: DUT host object
        :return:
        """
        logger.info("Disable Path Tracing")

        nexthop_iface = setup_info['spine_ports'][0]
        nexthop_addr = setup_info['ipv6'][nexthop_iface]
        nexthop_ptf_port_idx = setup_info['port_index_map'][nexthop_iface]

        self.config_path_tracing(duthost, ifname=nexthop_iface, enable=False)

    def ipv6_packet_no_hbh_pt(self, setup_info, ptfadapter):
        """ create IPv6 packet for testing """

        rx_iface = setup_info['tor_ports'][0]
        ptf_tx_addr = setup_info['ipv6'][rx_iface]
        ptf_tx_port_idx = setup_info['port_index_map'][rx_iface]

        nexthop_iface = setup_info['spine_ports'][0]
        nexthop_addr = setup_info['ipv6'][nexthop_iface]
        nexthop_ptf_port_idx = setup_info['port_index_map'][nexthop_iface]

        return testutils.simple_udpv6_packet(
            eth_dst=ingress_router_mac,
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
            ipv6_dst=nexthop_addr,
            ipv6_src=ptf_tx_addr,
            ipv6_hlim=64,
        )

    def ipv6_packet_with_hbh_pt(self, setup_info, ptfadapter):
        """ create IPv6 packet followed by a Hop-by-Hop Path Tracing Option with an empty MCD stack for testing """

        rx_iface = setup_info['tor_ports'][0]
        ptf_tx_addr = setup_info['ipv6'][rx_iface]
        ptf_tx_port_idx = setup_info['port_index_map'][rx_iface]

        nexthop_iface = setup_info['spine_ports'][0]
        nexthop_addr = setup_info['ipv6'][nexthop_iface]
        nexthop_ptf_port_idx = setup_info['port_index_map'][nexthop_iface]

        udp_pkt = testutils.simple_udpv6_packet(
            eth_dst=ingress_router_mac,
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
            ipv6_dst=nexthop_addr,
            ipv6_src=ptf_tx_addr,
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

        # Insert the Hop-by-Hop header between the IPv6 and UDP headers
        return udp_pkt[IPv6] / IPv6ExtHdrHopByHop(options=[hbh_pt, doh_pt]) / udp_pkt[IPv6].payload

    def expected_mask_forward_ipv6_packet(self, pkt):
        """ Return mask for ipv6 packet base forwarding """

        exp_pkt = pkt.copy()
        exp_pkt = mask.Mask(exp_pkt, ignore_extra_bytes=True)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IPv6, 'hlim')

        return exp_pkt

    def expected_mask_path_tracing_push_mcd_packet(self, pkt, outgoing_interface_id,
                                                   outgoing_interface_load=None, truncated_timestamp=None):
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
            logger.info('Disabling Path Tracing on interface {}'.format(ifname))
            result = duthost.shell('config interface path-tracing del {}'.format(ifname))
            if result['rc'] != 0:
                pytest.fail('Failed to disable Path Tracing on interface {} : {}'.format(ifname, result['stderr']))
            return

        # Case 2: Enable Path Tracing with default timestamp template
        if ts_template is None:
            logger.info('Enabling Path Tracing on interface {} (interface ID {})'.format(ifname, interface_id))
            result = duthost.shell('config interface path-tracing add {} --interface-id {}'
                                   .format(ifname, interface_id))
            if result['rc'] != 0:
                pytest.fail('Failed to enable Path Tracing on interface {} : {}'.format(ifname, result['stderr']))
            return

        # Case 3: Enable Path Tracing with non-default timestamp template
        logger.info('Enabling Path Tracing on interface {} (interface ID {}, timestamp template "{}")'
                    .format(ifname, interface_id, ts_template))
        result = duthost.shell('config interface path-tracing add {} --interface-id {} --ts-template {}'
                               .format(ifname, interface_id, ts_template))
        if result['rc'] != 0:
            pytest.fail('Failed to enable Path Tracing on interface {} : {}'.format(ifname, result['stderr']))

    def test_base_forwarding(self, duthosts, rand_one_dut_hostname, ptfadapter, setup_info):
        """
        Test scenario in which:
            - Path Tracing is disabled on the port
            - The DUT receives a simple IPv6 packet

        Expected result:
            - The packet is forwarded without any modification
        """
        duthost = duthosts[rand_one_dut_hostname]

        # Ingress interface through which the packet enters the DUT
        rx_iface = setup_info['tor_ports'][0]
        ptf_tx_port_idx = setup_info['port_index_map'][rx_iface]

        # Egress interface through which the packet leaves the DUT
        nexthop_iface = setup_info['spine_ports'][0]
        nexthop_ptf_port_idx = setup_info['port_index_map'][nexthop_iface]

        # Packet received from the DUT: IPv6 packet without any Hop-by-Hop header
        pkt = self.ipv6_packet_no_hbh_pt(setup_info, ptfadapter)
        # Packet expected to be sent by the DUT: same IPv6 packet without any Hop-by-Hop header
        exp_pkt = self.expected_mask_forward_ipv6_packet(pkt)

        time.sleep(2)

        # Ensure Path Tracing is disabled on the egress interface
        self.config_path_tracing(duthost, ifname=nexthop_iface, enable=False)

        time.sleep(5)

        # Instruct the PTF to send the packet to the DUT through the ingress interface
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_tx_port_idx, pkt)
        time.sleep(5)
        try:
            # Verify that the DUT sends the expected packet through the egress interface
            res = testutils.verify_packet(ptfadapter, exp_pkt, nexthop_ptf_port_idx, timeout=5)
            logger.info(res)
        except Exception as e:
            self.teardown_path_tracing(duthost)
            pytest.fail('Simple packet forwarding test failed \n' + str(e))

        # Disable Path Tracing
        self.teardown_path_tracing(duthost)

    def test_path_tracing(self, duthosts, rand_one_dut_hostname, ptfadapter, setup_info):
        """
        Test scenario in which:
            - Path Tracing is enabled on the port
            - The DUT receives an IPv6 packet followed by a HbH-PT

        Expected result:
            - The DUT pushes a new MCD before forwarding the packet on the outgoing interface
        """
        duthost = duthosts[rand_one_dut_hostname]

        # Ingress interface through which the packet enters the DUT
        rx_iface = setup_info['tor_ports'][0]
        ptf_tx_port_idx = setup_info['port_index_map'][rx_iface]

        # Egress interface through which the packet leaves the DUT
        nexthop_iface = setup_info['spine_ports'][0]
        nexthop_ptf_port_idx = setup_info['port_index_map'][nexthop_iface]

        # Packet received from the DUT: IPv6 packet without any Hop-by-Hop header
        pkt = self.ipv6_packet_no_hbh_pt(setup_info, ptfadapter)
        # Packet expected to be sent by the DUT: same IPv6 packet with Path Tracing information included
        exp_pkt = self.expected_mask_path_tracing_push_mcd_packet(pkt, 128)

        time.sleep(2)

        # Enable Path Tracing on the egress interface with Interface ID 128
        self.config_path_tracing(duthost, ifname=nexthop_iface, enable=True, interface_id=128)

        time.sleep(5)

        # Instruct the PTF to send the packet to the DUT through the ingress interface
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_tx_port_idx, pkt)
        time.sleep(5)
        try:
            # Verify that the DUT sends the expected packet through the egress interface
            res = testutils.verify_packet(ptfadapter, exp_pkt, nexthop_ptf_port_idx, timeout=5)
            logger.info(res)
        except Exception as e:
            self.teardown_path_tracing(duthost)
            pytest.fail('Simple packet forwarding test failed \n' + str(e))

        # Disable Path Tracing
        self.teardown_path_tracing(duthost)

    def test_path_tracing_ecmp(self, duthosts, rand_one_dut_hostname, ptfadapter, setup_info):
        """
        Test scenario in which:
            - Path Tracing is enabled on the first port
            - Path Tracing is enabled on the second port
            - The DUT receives an IPv6 packet followed by a HbH-PT

        Expected result:
            - The DUT pushes a new MCD before forwarding the packet through the first port
              and the Interface ID corresponds to the first port
        """
        duthost = duthosts[rand_one_dut_hostname]

        # Ingress interface through which the packet enters the DUT
        rx_iface = setup_info['tor_ports'][0]
        ptf_tx_port_idx = setup_info['port_index_map'][rx_iface]

        # First egress interface through which the packet leaves the DUT
        nexthop_iface_1 = setup_info['spine_ports'][0]
        nexthop_ptf_port_idx_1 = setup_info['port_index_map'][nexthop_iface_1]

        # Second egress interface
        nexthop_iface_2 = setup_info['spine_ports'][1]
        nexthop_ptf_port_idx_2 = setup_info['port_index_map'][nexthop_iface_2]

        # Packet received from the DUT: IPv6 packet without any Hop-by-Hop header
        pkt = self.ipv6_packet_no_hbh_pt(setup_info, ptfadapter)
        # Packet expected to be sent by the DUT: same IPv6 packet with Path Tracing information included
        exp_pkt = self.expected_mask_path_tracing_push_mcd_packet(pkt, 128)

        time.sleep(2)

        # Enable Path Tracing on the first egress interface with Interface ID 128
        self.config_path_tracing(duthost, ifname=nexthop_iface_1, enable=True, interface_id=128)
        # Enable Path Tracing on the second egress interface with Interface ID 128
        self.config_path_tracing(duthost, ifname=nexthop_iface_2, enable=True, interface_id=129)

        time.sleep(5)

        # Instruct the PTF to send the packet to the DUT through the ingress interface
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_tx_port_idx, pkt)
        time.sleep(5)
        try:
            # Verify that the DUT sends the expected packet through the first egress interface
            res = testutils.verify_packet(ptfadapter, exp_pkt, nexthop_ptf_port_idx_1, timeout=5)
            logger.info(res)
        except Exception as e:
            self.teardown_path_tracing(duthost)
            pytest.fail('Simple packet forwarding test failed \n' + str(e))

        # Disable Path Tracing
        self.teardown_path_tracing(duthost)
