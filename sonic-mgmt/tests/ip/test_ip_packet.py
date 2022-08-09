import random
import re
import time

import ipaddress
import ptf.testutils as testutils
import pytest
from ptf import mask, packet

from tests.common.helpers.assertions import pytest_assert
from tests.common.portstat_utilities import parse_portstat


class TestIPPacket(object):
    PKT_NUM = 1000
    PKT_NUM_MIN = PKT_NUM * 0.9
    PKT_NUM_MAX = PKT_NUM * 1.3
    # a number <= PKT_NUM * 0.1 can be considered as 0
    PKT_NUM_ZERO = PKT_NUM * 0.1

    @staticmethod
    def sum_portstat_ifaces_counts(portstat_out, ifaces, column):
        if len(ifaces) == 0:
            return 0
        if len(ifaces) == 1:
            return int(portstat_out[ifaces[0]][column].replace(",", ""))
        return sum(map(lambda iface: int(portstat_out[iface][column].replace(",", "")), ifaces))

    @staticmethod
    def parse_interfaces(output_lines, pc_ports_map):
        """
        Parse the inerfaces from 'show ip route' into an array
        """
        route_targets = []
        ifaces = []
        output_lines = output_lines[3:]

        for item in output_lines:
            match = re.search("(Ethernet\d+|PortChannel\d+)", item)
            if match:
                route_targets.append(match.group(0))

        for route_target in route_targets:
            if route_target.startswith("Ethernet"):
                ifaces.append(route_target)
            elif route_target.startswith("PortChannel") and route_target in pc_ports_map:
                ifaces.extend(pc_ports_map[route_target])

        return ifaces

    @pytest.fixture(scope="class")
    def common_param(self, duthost, tbinfo):
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        pc_ports_map = {}

        if len(mg_facts["minigraph_interfaces"]) >= 2:
            # generate peer_ip and interfaces pair,
            # be like:[("10.0.0.57", ["Ethernet48"])]
            peer_ip_ifaces_pair = [(intf["peer_addr"], [intf["attachto"]]) for intf in mg_facts["minigraph_interfaces"]
                                   if
                                   ipaddress.ip_address(intf['peer_addr']).version == 4]
        else:
            # generate peer_ip and port channel pair, be like:[("10.0.0.57", "PortChannel0001")]
            peer_ip_pc_pair = [(pc["peer_addr"], pc["attachto"]) for pc in mg_facts["minigraph_portchannel_interfaces"]
                               if
                               ipaddress.ip_address(pc['peer_addr']).version == 4]
            pc_ports_map = {pair[1]: mg_facts["minigraph_portchannels"][pair[1]]["members"] for pair in
                            peer_ip_pc_pair}
            # generate peer_ip and interfaces(port channel members) pair,
            # be like:[("10.0.0.57", ["Ethernet48", "Ethernet52"])]
            peer_ip_ifaces_pair = [(pair[0], mg_facts["minigraph_portchannels"][pair[1]]["members"]) for pair in
                                   peer_ip_pc_pair]

        selected_peer_ip_ifaces_pairs = random.sample(peer_ip_ifaces_pair, k=2)
        # use first port of first peer_ip_ifaces pair as input port
        # all ports in second peer_ip_ifaces pair will be output/forward port
        ptf_port_idx = mg_facts["minigraph_ptf_indices"][selected_peer_ip_ifaces_pairs[0][1][0]]

        yield selected_peer_ip_ifaces_pairs, ptf_port_idx, pc_ports_map, mg_facts["minigraph_ptf_indices"]

    def test_forward_ip_packet_with_0x0000_chksum(self, duthost, ptfadapter, common_param):
        # GIVEN a ip packet with checksum 0x0000(compute from scratch)
        # WHEN send the packet to DUT
        # THEN DUT should forward it as normal ip packet

        (peer_ip_ifaces_pair, ptf_port_idx, pc_ports_map, ptf_indices) = common_param
        pkt = testutils.simple_ip_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
            pktlen=1246,
            ip_src="10.250.136.195",
            ip_dst="10.156.94.34",
            ip_proto=47,
            ip_tos=0x84,
            ip_id=0,
            ip_ihl=5,
            ip_ttl=121,
        )
        pkt.payload.flags = 2
        exp_pkt = pkt.copy()
        exp_pkt.payload.ttl = 120
        exp_pkt.payload.chksum = 0x0100
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')

        out_ifaces = TestIPPacket.parse_interfaces(duthost.command("show ip route 10.156.94.34")["stdout_lines"],
                                                   pc_ports_map)
        out_ptf_indices = map(lambda iface: ptf_indices[iface], out_ifaces)

        duthost.command("portstat -c")
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_port_idx, pkt, self.PKT_NUM)
        time.sleep(5)
        match_cnt = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=out_ptf_indices)

        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])

        rx_ok = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_drp"].replace(",", ""))
        tx_ok = TestIPPacket.sum_portstat_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = TestIPPacket.sum_portstat_ifaces_counts(portstat_out, out_ifaces, "tx_drp")

        pytest_assert(match_cnt == self.PKT_NUM, "Packet lost")
        pytest_assert(self.PKT_NUM_MIN <= rx_ok <= self.PKT_NUM_MAX, "rx_ok unexpected")
        pytest_assert(self.PKT_NUM_MIN <= tx_ok <= self.PKT_NUM_MAX, "tx_ok unexpected")
        pytest_assert(rx_drp <= self.PKT_NUM_ZERO, "rx_drp unexpected")
        pytest_assert(tx_drp <= self.PKT_NUM_ZERO, "tx_drp unexpected")

    @pytest.mark.xfail
    def test_forward_ip_packet_with_0xffff_chksum_tolerant(self, duthost, ptfadapter, common_param):
        # GIVEN a ip packet with checksum 0x0000(compute from scratch)
        # WHEN manually set checksum as 0xffff and send the packet to DUT
        # THEN DUT should tolerant packet with 0xffff, forward it as normal packet

        (peer_ip_ifaces_pair, ptf_port_idx, pc_ports_map, ptf_indices) = common_param
        pkt = testutils.simple_ip_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
            pktlen=1246,
            ip_src="10.250.136.195",
            ip_dst="10.156.94.34",
            ip_proto=47,
            ip_tos=0x84,
            ip_id=0,
            ip_ihl=5,
            ip_ttl=121,
        )
        pkt.payload.flags = 2
        pkt.payload.chksum = 0xffff
        exp_pkt = pkt.copy()
        exp_pkt.payload.ttl = 120
        exp_pkt.payload.chksum = 0x0100
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')

        out_ifaces = TestIPPacket.parse_interfaces(duthost.command("show ip route 10.156.94.34")["stdout_lines"],
                                                   pc_ports_map)
        out_ptf_indices = map(lambda iface: ptf_indices[iface], out_ifaces)

        duthost.command("portstat -c")
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_port_idx, pkt, self.PKT_NUM)
        time.sleep(5)
        match_cnt = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=out_ptf_indices)

        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])

        rx_ok = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_drp"].replace(",", ""))
        tx_ok = TestIPPacket.sum_portstat_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = TestIPPacket.sum_portstat_ifaces_counts(portstat_out, out_ifaces, "tx_drp")

        pytest_assert(match_cnt == self.PKT_NUM, "Packet lost")
        pytest_assert(self.PKT_NUM_MIN <= rx_ok <= self.PKT_NUM_MAX, "rx_ok unexpected")
        pytest_assert(self.PKT_NUM_MIN <= tx_ok <= self.PKT_NUM_MAX, "tx_ok unexpected")
        pytest_assert(rx_drp <= self.PKT_NUM_ZERO, "rx_drp unexpected")
        pytest_assert(tx_drp <= self.PKT_NUM_ZERO, "tx_drp unexpected")

    @pytest.mark.xfail
    def test_forward_ip_packet_with_0xffff_chksum_drop(self, duthost, ptfadapter, common_param):
        # GIVEN a ip packet with checksum 0x0000(compute from scratch)
        # WHEN manually set checksum as 0xffff and send the packet to DUT
        # THEN DUT should drop packet with 0xffff and add drop count

        (peer_ip_ifaces_pair, ptf_port_idx, pc_ports_map, ptf_indices) = common_param
        pkt = testutils.simple_ip_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
            pktlen=1246,
            ip_src="10.250.136.195",
            ip_dst="10.156.94.34",
            ip_proto=47,
            ip_tos=0x84,
            ip_id=0,
            ip_ihl=5,
            ip_ttl=121,
        )
        pkt.payload.flags = 2
        pkt.payload.chksum = 0xffff
        exp_pkt = pkt.copy()
        exp_pkt.payload.ttl = 120
        exp_pkt.payload.chksum = 0x0100
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')

        out_ifaces = TestIPPacket.parse_interfaces(duthost.command("show ip route 10.156.94.34")["stdout_lines"],
                                                   pc_ports_map)
        out_ptf_indices = map(lambda iface: ptf_indices[iface], out_ifaces)

        duthost.command("portstat -c")
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_port_idx, pkt, self.PKT_NUM)
        time.sleep(5)
        match_cnt = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=out_ptf_indices)

        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])

        rx_ok = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_drp"].replace(",", ""))
        tx_ok = TestIPPacket.sum_portstat_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = TestIPPacket.sum_portstat_ifaces_counts(portstat_out, out_ifaces, "tx_drp")

        pytest_assert(match_cnt == 0, "Packet not dropped")
        pytest_assert(self.PKT_NUM_MIN <= rx_ok <= self.PKT_NUM_MAX, "rx_ok unexpected")
        pytest_assert(self.PKT_NUM_MIN <= rx_drp <= self.PKT_NUM_MAX, "rx_drp unexpected")
        pytest_assert(tx_drp <= self.PKT_NUM_ZERO, "tx_drp unexpected")
        pytest_assert(tx_ok <= self.PKT_NUM_ZERO, "tx_ok unexpected")

    def test_forward_ip_packet_recomputed_0xffff_chksum(self, duthost, ptfadapter, common_param):
        # GIVEN a ip packet, after forwarded(ttl-1) by DUT,
        #   it's checksum will be 0xffff after wrongly incrementally recomputed
        #   ref to https://datatracker.ietf.org/doc/html/rfc1624
        #   HC' = HC(0xff00) + m(0x7a2f) + ~m'(~0x792f)= 0xffff
        # WHEN send the packet to DUT
        # THEN DUT recompute new checksum correctly and forward packet as expected.

        (peer_ip_ifaces_pair, ptf_port_idx, pc_ports_map, ptf_indices) = common_param
        pkt = testutils.simple_ip_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
            pktlen=1246,
            ip_src="10.250.40.40",
            ip_dst="10.156.190.188",
            ip_proto=47,
            ip_tos=0x84,
            ip_id=0,
            ip_ihl=5,
            ip_ttl=122,
        )
        pkt.payload.flags = 2
        exp_pkt = pkt.copy()
        exp_pkt.payload.ttl = 121
        exp_pkt.payload.chksum = 0x0001
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')

        out_ifaces = TestIPPacket.parse_interfaces(duthost.command("show ip route 10.156.190.188")["stdout_lines"],
                                                   pc_ports_map)
        out_ptf_indices = map(lambda iface: ptf_indices[iface], out_ifaces)

        duthost.command("portstat -c")
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_port_idx, pkt, self.PKT_NUM)
        time.sleep(5)
        match_cnt = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=out_ptf_indices)

        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])

        rx_ok = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_drp"].replace(",", ""))
        tx_ok = TestIPPacket.sum_portstat_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = TestIPPacket.sum_portstat_ifaces_counts(portstat_out, out_ifaces, "tx_drp")

        pytest_assert(match_cnt == self.PKT_NUM, "Packet lost")
        pytest_assert(self.PKT_NUM_MIN <= rx_ok <= self.PKT_NUM_MAX, "rx_ok unexpected")
        pytest_assert(self.PKT_NUM_MIN <= tx_ok <= self.PKT_NUM_MAX, "tx_ok unexpected")
        pytest_assert(rx_drp <= self.PKT_NUM_ZERO, "rx_drp unexpected")
        pytest_assert(tx_drp <= self.PKT_NUM_ZERO, "tx_drp unexpected")

    def test_forward_ip_packet_recomputed_0x0000_chksum(self, duthost, ptfadapter, common_param):
        # GIVEN a ip packet, after forwarded(ttl-1) by DUT, it's checksum will be 0x0000 after recompute from scratch
        # WHEN send the packet to DUT
        # THEN DUT recompute new checksum as 0x0000 and forward packet as expected.

        (peer_ip_ifaces_pair, ptf_port_idx, pc_ports_map, ptf_indices) = common_param
        pkt = testutils.simple_ip_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
            pktlen=1246,
            ip_src="10.250.136.195",
            ip_dst="10.156.94.34",
            ip_proto=47,
            ip_tos=0x84,
            ip_id=0,
            ip_ihl=5,
            ip_ttl=122,
        )
        pkt.payload.flags = 2
        exp_pkt = pkt.copy()
        exp_pkt.payload.ttl = 121
        exp_pkt.payload.chksum = 0x0000
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')

        out_ifaces = TestIPPacket.parse_interfaces(duthost.command("show ip route 10.156.94.34")["stdout_lines"],
                                                   pc_ports_map)
        out_ptf_indices = map(lambda iface: ptf_indices[iface], out_ifaces)

        duthost.command("portstat -c")
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_port_idx, pkt, self.PKT_NUM)
        time.sleep(5)
        match_cnt = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=out_ptf_indices)

        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])

        rx_ok = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_drp"].replace(",", ""))
        tx_ok = TestIPPacket.sum_portstat_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = TestIPPacket.sum_portstat_ifaces_counts(portstat_out, out_ifaces, "tx_drp")

        pytest_assert(match_cnt == self.PKT_NUM, "Packet lost")
        pytest_assert(self.PKT_NUM_MIN <= rx_ok <= self.PKT_NUM_MAX, "rx_ok unexpected")
        pytest_assert(self.PKT_NUM_MIN <= tx_ok <= self.PKT_NUM_MAX, "tx_ok unexpected")
        pytest_assert(rx_drp <= self.PKT_NUM_ZERO, "rx_drp unexpected")
        pytest_assert(tx_drp <= self.PKT_NUM_ZERO, "tx_drp unexpected")

    def test_forward_normal_ip_packet(self, duthost, ptfadapter, common_param):
        # GIVEN a random normal ip packet
        # WHEN send the packet to DUT
        # THEN DUT should forward it as normal ip packet, nothing change but ttl-1
        (peer_ip_ifaces_pair, ptf_port_idx, pc_ports_map, ptf_indices) = common_param
        pkt = testutils.simple_ip_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
            ip_src=peer_ip_ifaces_pair[0][0],
            ip_dst=peer_ip_ifaces_pair[1][0])

        exp_pkt = pkt.copy()
        exp_pkt.payload.ttl = pkt.payload.ttl - 1
        exp_pkt = mask.Mask(exp_pkt)

        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')

        out_ifaces = TestIPPacket.parse_interfaces(
            duthost.command("show ip route %s" % peer_ip_ifaces_pair[1][0])["stdout_lines"],
            pc_ports_map)
        out_ptf_indices = map(lambda iface: ptf_indices[iface], out_ifaces)

        duthost.command("portstat -c")
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_port_idx, pkt, self.PKT_NUM)
        time.sleep(5)
        match_cnt = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=out_ptf_indices)

        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])

        rx_ok = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_drp"].replace(",", ""))
        tx_ok = TestIPPacket.sum_portstat_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = TestIPPacket.sum_portstat_ifaces_counts(portstat_out, out_ifaces, "tx_drp")

        pytest_assert(match_cnt == self.PKT_NUM, "Packet lost")
        pytest_assert(self.PKT_NUM_MIN <= rx_ok <= self.PKT_NUM_MAX, "rx_ok unexpected")
        pytest_assert(self.PKT_NUM_MIN <= tx_ok <= self.PKT_NUM_MAX, "tx_ok unexpected")
        pytest_assert(rx_drp <= self.PKT_NUM_ZERO, "rx_drp unexpected")
        pytest_assert(tx_drp <= self.PKT_NUM_ZERO, "tx_drp unexpected")

    def test_drop_ip_packet_with_wrong_0xffff_chksum(self, duthost, ptfadapter, common_param):
        # GIVEN a random normal ip packet, and manually modify checksum to 0xffff
        # WHEN send the packet to DUT
        # THEN DUT should drop it and add drop count
        (peer_ip_ifaces_pair, ptf_port_idx, pc_ports_map, ptf_indices) = common_param
        pkt = testutils.simple_ip_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
            ip_src=peer_ip_ifaces_pair[0][0],
            ip_dst=peer_ip_ifaces_pair[1][0])

        pkt.payload.chksum = 0xffff

        out_ifaces = TestIPPacket.parse_interfaces(
            duthost.command("show ip route %s" % peer_ip_ifaces_pair[1][0])["stdout_lines"],
            pc_ports_map)

        duthost.command("portstat -c")
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_port_idx, pkt, self.PKT_NUM)
        time.sleep(5)

        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])

        rx_ok = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_drp"].replace(",", ""))
        tx_ok = TestIPPacket.sum_portstat_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = TestIPPacket.sum_portstat_ifaces_counts(portstat_out, out_ifaces, "tx_drp")

        pytest_assert(self.PKT_NUM_MIN <= rx_ok <= self.PKT_NUM_MAX, "rx_ok unexpected")
        pytest_assert(self.PKT_NUM_MIN <= rx_drp <= self.PKT_NUM_MAX, "rx_drp unexpected")
        pytest_assert(tx_ok <= self.PKT_NUM_ZERO, "tx_ok unexpected")
        pytest_assert(tx_drp <= self.PKT_NUM_ZERO, "tx_drp unexpected")
