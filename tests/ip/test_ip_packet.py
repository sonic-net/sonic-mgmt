import re
import time
import logging

import ipaddress
import ptf.testutils as testutils
import pytest
from ptf import mask, packet

from collections import defaultdict
from tests.common.helpers.assertions import pytest_assert
from tests.common.portstat_utilities import parse_column_positions
from tests.common.portstat_utilities import parse_portstat
# from tests.common.fixtures.ptfhost_utils import skip_traffic_test           # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test           # noqa: F401
from tests.drop_packets.drop_packets import is_mellanox_fanout


pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)


class TestIPPacket(object):
    PKT_NUM = 1000
    PKT_NUM_MIN = PKT_NUM * 0.9
    # in dualtor PKT_NUM_MAX should be larger
    PKT_NUM_MAX = PKT_NUM * 1.5
    # a number <= PKT_NUM * 0.1 can be considered as 0
    PKT_NUM_ZERO = PKT_NUM * 0.1

    @staticmethod
    def sum_ifaces_counts(counter_out, ifaces, column):
        if len(ifaces) == 0:
            return 0
        if len(ifaces) == 1:
            return int(counter_out[ifaces[0]][column].replace(",", ""))
        return sum([int(counter_out[iface][column].replace(",", "")) for iface in ifaces])

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

    @staticmethod
    def parse_rif_counters(output_lines):
        '''Parse the output of "show interfaces counters rif" command
        Args:
            output_lines (list): The output lines of "show interfaces counters rif" command
        Returns:
            list: A dictionary, key is interface name, value is a dictionary of fields/values
        '''

        header_line = ''
        separation_line = ''
        separation_line_number = 0
        for idx, line in enumerate(output_lines):
            if line.find('----') >= 0:
                header_line = output_lines[idx-1]
                separation_line = output_lines[idx]
                separation_line_number = idx
                break

        try:
            positions = parse_column_positions(separation_line)
        except Exception:
            logger.error('Possibly bad command output')
            return {}

        headers = []
        for pos in positions:
            header = header_line[pos[0]:pos[1]].strip().lower()
            headers.append(header)

        if not headers:
            return {}

        results = {}
        for line in output_lines[separation_line_number+1:]:
            portstats = []
            for pos in positions:
                portstat = line[pos[0]:pos[1]].strip()
                portstats.append(portstat)

            intf = portstats[0]
            results[intf] = {}
            for idx in range(1, len(portstats)):    # Skip the first column interface name
                results[intf][headers[idx]] = portstats[idx]

        return results

    @pytest.fixture(scope="class")
    def common_param(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

        # generate peer_ip and port channel pair, be like:[("10.0.0.57", "PortChannel0001")]
        peer_ip_pc_pair = [(pc["peer_addr"], pc["attachto"]) for pc in mg_facts["minigraph_portchannel_interfaces"]
                           if ipaddress.ip_address(pc['peer_addr']).version == 4]
        pc_ports_map = {pair[1]: mg_facts["minigraph_portchannels"][pair[1]]["members"] for pair in
                        peer_ip_pc_pair}

        # generate peer_ip and interfaces pair,
        # be like:[("10.0.0.57", ["Ethernet48"])]
        router_port_peer_ip_ifaces_pair = \
            [(intf["peer_addr"], [intf["attachto"]],  mg_facts["minigraph_neighbors"][intf["attachto"]]['namespace'])
             for intf in mg_facts["minigraph_interfaces"] if ipaddress.ip_address(intf['peer_addr']).version == 4]
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

        for prefix in ["10.156.94.34/32", "10.156.190.188/32"]:
            duthost.shell(duthost.get_vtysh_cmd_for_namespace(
                "vtysh -c \"configure terminal\" -c \"ip route {} {} tag 1\""
                .format(prefix, selected_peer_ip_ifaces_pairs[1][0]), ptf_port_idx_namespace))
        yield selected_peer_ip_ifaces_pairs, rif_rx_ifaces, rif_support, \
            ptf_port_idx, pc_ports_map, mg_facts["minigraph_ptf_indices"], ingress_router_mac

        for prefix in ["10.156.94.34/32", "10.156.190.188/32"]:
            duthost.shell(duthost.get_vtysh_cmd_for_namespace(
                "vtysh -c \"configure terminal\" -c \"no ip route {} {} tag 1\""
                .format(prefix, selected_peer_ip_ifaces_pairs[1][0]), ptf_port_idx_namespace))

    def test_forward_ip_packet_with_0x0000_chksum(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                                  ptfadapter, common_param, skip_traffic_test):     # noqa F811
        # GIVEN a ip packet with checksum 0x0000(compute from scratch)
        # WHEN send the packet to DUT
        # THEN DUT should forward it as normal ip packet

        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        (peer_ip_ifaces_pair, rif_rx_ifaces, rif_support, ptf_port_idx,
         pc_ports_map, ptf_indices, ingress_router_mac) = common_param
        pkt = testutils.simple_ip_packet(
            eth_dst=ingress_router_mac,
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

        out_rif_ifaces, out_ifaces = TestIPPacket.parse_interfaces(
            duthost.command("show ip route 10.156.94.34")["stdout_lines"], pc_ports_map)
        logger.info("out_rif_ifaces: {}, out_ifaces: {}".format(out_rif_ifaces, out_ifaces))
        out_ptf_indices = [ptf_indices[iface] for iface in out_ifaces]

        duthost.command("portstat -c")
        if rif_support:
            duthost.command("sonic-clear rifcounters")
        ptfadapter.dataplane.flush()

        testutils.send(ptfadapter, ptf_port_idx, pkt, self.PKT_NUM)
        time.sleep(5)
        match_cnt = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=list(out_ptf_indices))

        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])
        if rif_support:
            rif_counter_out = TestIPPacket.parse_rif_counters(
                duthost.command("show interfaces counters rif")["stdout_lines"])

        # In different platforms, IP packets with specific checksum will be dropped in different layer
        # We use both layer 2 counter and layer 3 counter to check where packet are dropped
        rx_ok = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_drp"].replace(",", ""))
        rx_err = int(rif_counter_out[rif_rx_ifaces]["rx_err"].replace(",", "")) if rif_support else 0
        tx_ok = TestIPPacket.sum_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = TestIPPacket.sum_ifaces_counts(portstat_out, out_ifaces, "tx_drp")
        tx_err = TestIPPacket.sum_ifaces_counts(rif_counter_out, out_rif_ifaces, "tx_err") if rif_support else 0

        if skip_traffic_test is True:
            return
        pytest_assert(rx_ok >= self.PKT_NUM_MIN,
                      "Received {} packets in rx, not in expected range".format(rx_ok))
        pytest_assert(tx_ok >= self.PKT_NUM_MIN,
                      "Forwarded {} packets in tx, not in expected range".format(tx_ok))
        pytest_assert(max(rx_drp, rx_err) <= self.PKT_NUM_ZERO,
                      "Dropped {} packets in rx, not in expected range".format(rx_err))
        pytest_assert(max(tx_drp, tx_err) <= self.PKT_NUM_ZERO,
                      "Dropped {} packets in tx, not in expected range".format(tx_err))
        pytest_assert(match_cnt >= self.PKT_NUM_MIN,
                      "DUT forwarded {} packets, but {} packets matched expected format, not in expected range"
                      .format(tx_ok, match_cnt))

    def test_forward_ip_packet_with_0xffff_chksum_tolerant(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                                           ptfadapter, common_param, skip_traffic_test):    # noqa F811
        # GIVEN a ip packet with checksum 0x0000(compute from scratch)
        # WHEN manually set checksum as 0xffff and send the packet to DUT
        # THEN DUT should tolerant packet with 0xffff, forward it as normal packet

        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        (peer_ip_ifaces_pair, rif_rx_ifaces, rif_support, ptf_port_idx,
         pc_ports_map, ptf_indices, ingress_router_mac) = common_param
        pkt = testutils.simple_ip_packet(
            eth_dst=ingress_router_mac,
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

        out_rif_ifaces, out_ifaces = TestIPPacket.parse_interfaces(
            duthost.command("show ip route 10.156.94.34")["stdout_lines"], pc_ports_map)
        out_ptf_indices = [ptf_indices[iface] for iface in out_ifaces]

        duthost.command("portstat -c")
        if rif_support:
            duthost.command("sonic-clear rifcounters")
        ptfadapter.dataplane.flush()

        testutils.send(ptfadapter, ptf_port_idx, pkt, self.PKT_NUM)
        time.sleep(5)
        match_cnt = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=list(out_ptf_indices))

        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])
        if rif_support:
            rif_counter_out = TestIPPacket.parse_rif_counters(
                duthost.command("show interfaces counters rif")["stdout_lines"])

        # In different platforms, IP packets with specific checksum will be dropped in different layer
        # We use both layer 2 counter and layer 3 counter to check where packet are dropped
        rx_ok = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_drp"].replace(",", ""))
        rx_err = int(rif_counter_out[rif_rx_ifaces]["rx_err"].replace(",", "")) if rif_support else 0
        tx_ok = TestIPPacket.sum_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = TestIPPacket.sum_ifaces_counts(portstat_out, out_ifaces, "tx_drp")
        tx_err = TestIPPacket.sum_ifaces_counts(rif_counter_out, out_rif_ifaces, "tx_err") if rif_support else 0

        if skip_traffic_test is True:
            return
        pytest_assert(rx_ok >= self.PKT_NUM_MIN,
                      "Received {} packets in rx, not in expected range".format(rx_ok))
        pytest_assert(tx_ok >= self.PKT_NUM_MIN,
                      "Forwarded {} packets in tx, not in expected range".format(tx_ok))
        pytest_assert(max(rx_drp, rx_err) <= self.PKT_NUM_ZERO,
                      "Dropped {} packets in rx, not in expected range".format(rx_err))
        pytest_assert(max(tx_drp, tx_err) <= self.PKT_NUM_ZERO,
                      "Dropped {} packets in tx, not in expected range".format(tx_err))
        pytest_assert(match_cnt >= self.PKT_NUM_MIN,
                      "DUT forwarded {} packets, but {} packets matched expected format, not in expected range"
                      .format(tx_ok, match_cnt))

    def test_forward_ip_packet_with_0xffff_chksum_drop(self, duthosts, localhost,
                                                       enum_rand_one_per_hwsku_frontend_hostname, ptfadapter,
                                                       common_param, tbinfo, skip_traffic_test):    # noqa F811

        # GIVEN a ip packet with checksum 0x0000(compute from scratch)
        # WHEN manually set checksum as 0xffff and send the packet to DUT
        # THEN DUT should drop packet with 0xffff and add drop count

        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        if is_mellanox_fanout(duthost, localhost):
            pytest.skip("Not supported at Mellanox fanout")
        (peer_ip_ifaces_pair, rif_rx_ifaces, rif_support, ptf_port_idx,
         pc_ports_map, ptf_indices, ingress_router_mac) = common_param
        pkt = testutils.simple_ip_packet(
            eth_dst=ingress_router_mac,
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

        out_rif_ifaces, out_ifaces = TestIPPacket.parse_interfaces(
            duthost.command("show ip route 10.156.94.34")["stdout_lines"], pc_ports_map)
        out_ptf_indices = [ptf_indices[iface] for iface in out_ifaces]

        duthost.command("portstat -c")
        if rif_support:
            duthost.command("sonic-clear rifcounters")
        ptfadapter.dataplane.flush()

        testutils.send(ptfadapter, ptf_port_idx, pkt, self.PKT_NUM)
        time.sleep(5)
        match_cnt = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=list(out_ptf_indices))

        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])
        if rif_support:
            rif_counter_out = TestIPPacket.parse_rif_counters(
                duthost.command("show interfaces counters rif")["stdout_lines"])

        # In different platforms, IP packets with specific checksum will be dropped in different layer
        # We use both layer 2 counter and layer 3 counter to check where packet are dropped
        rx_ok = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_drp"].replace(",", ""))
        rx_err = int(rif_counter_out[rif_rx_ifaces]["rx_err"].replace(",", "")) if rif_support else 0
        tx_ok = TestIPPacket.sum_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = TestIPPacket.sum_ifaces_counts(portstat_out, out_ifaces, "tx_drp")
        tx_err = TestIPPacket.sum_ifaces_counts(rif_counter_out, out_rif_ifaces, "tx_err") if rif_support else 0

        # For t2 max topology, increase the tolerance value from 0.1 to 0.2
        # Set the tolerance value to 0.2 if the topology is T2 max, PKT_NUM_ZERO would be set to 200
        vms_num = len(tbinfo['topo']['properties']['topology']['VMs'])
        if tbinfo['topo']['type'] == "t2" and vms_num > 8:
            logger.info("Setting PKT_NUM_ZERO for t2 max topology with 0.2 tolerance")
            self.PKT_NUM_ZERO = self.PKT_NUM * 0.2

        if skip_traffic_test is True:
            return
        pytest_assert(rx_ok >= self.PKT_NUM_MIN,
                      "Received {} packets in rx, not in expected range".format(rx_ok))
        pytest_assert(max(rx_drp, rx_err) >= self.PKT_NUM_MIN,
                      "Dropped {} packets in rx, not in expected range".format(rx_err))
        pytest_assert(tx_ok <= self.PKT_NUM_ZERO,
                      "Forwarded {} packets in tx, not in expected range".format(tx_ok))
        pytest_assert(max(tx_drp, tx_err) <= self.PKT_NUM_ZERO,
                      "Dropped {} packets in tx, not in expected range".format(tx_err))
        pytest_assert(match_cnt == 0,
                      "DUT shouldn't forward packets, but forwarded {} packets, not in expected range"
                      .format(match_cnt))

    def test_forward_ip_packet_recomputed_0xffff_chksum(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                                        ptfadapter, common_param, skip_traffic_test):   # noqa F811
        # GIVEN a ip packet, after forwarded(ttl-1) by DUT,
        #   it's checksum will be 0xffff after wrongly incrementally recomputed
        #   ref to https://datatracker.ietf.org/doc/html/rfc1624
        #   HC' = HC(0xff00) + m(0x7a2f) + ~m'(~0x792f)= 0xffff
        # WHEN send the packet to DUT
        # THEN DUT recompute new checksum correctly and forward packet as expected.

        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        (peer_ip_ifaces_pair, rif_rx_ifaces, rif_support, ptf_port_idx,
         pc_ports_map, ptf_indices, ingress_router_mac) = common_param
        pkt = testutils.simple_ip_packet(
            eth_dst=ingress_router_mac,
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

        out_rif_ifaces, out_ifaces = TestIPPacket.parse_interfaces(
            duthost.command("show ip route 10.156.190.188")["stdout_lines"], pc_ports_map)
        out_ptf_indices = [ptf_indices[iface] for iface in out_ifaces]

        duthost.command("portstat -c")
        if rif_support:
            duthost.command("sonic-clear rifcounters")
        ptfadapter.dataplane.flush()

        testutils.send(ptfadapter, ptf_port_idx, pkt, self.PKT_NUM)
        time.sleep(5)
        match_cnt = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=list(out_ptf_indices))

        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])
        if rif_support:
            rif_counter_out = TestIPPacket.parse_rif_counters(
                duthost.command("show interfaces counters rif")["stdout_lines"])

        # In different platforms, IP packets with specific checksum will be dropped in different layer
        # We use both layer 2 counter and layer 3 counter to check where packet are dropped
        rx_ok = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_drp"].replace(",", ""))
        rx_err = int(rif_counter_out[rif_rx_ifaces]["rx_err"].replace(",", "")) if rif_support else 0
        tx_ok = TestIPPacket.sum_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = TestIPPacket.sum_ifaces_counts(portstat_out, out_ifaces, "tx_drp")
        tx_err = TestIPPacket.sum_ifaces_counts(rif_counter_out, out_rif_ifaces, "tx_err") if rif_support else 0

        if skip_traffic_test is True:
            return
        pytest_assert(rx_ok >= self.PKT_NUM_MIN,
                      "Received {} packets in rx, not in expected range".format(rx_ok))
        pytest_assert(tx_ok >= self.PKT_NUM_MIN,
                      "Forwarded {} packets in tx, not in expected range".format(tx_ok))
        pytest_assert(max(rx_drp, rx_err) <= self.PKT_NUM_ZERO,
                      "Dropped {} packets in rx, not in expected range".format(rx_err))
        pytest_assert(max(tx_drp, tx_err) <= self.PKT_NUM_ZERO,
                      "Dropped {} packets in tx, not in expected range".format(tx_err))
        pytest_assert(match_cnt >= self.PKT_NUM_MIN,
                      "DUT forwarded {} packets, but {} packets matched expected format, not in expected range"
                      .format(tx_ok, match_cnt))

    def test_forward_ip_packet_recomputed_0x0000_chksum(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                                        ptfadapter, common_param, skip_traffic_test):   # noqa F811
        # GIVEN a ip packet, after forwarded(ttl-1) by DUT, it's checksum will be 0x0000 after recompute from scratch
        # WHEN send the packet to DUT
        # THEN DUT recompute new checksum as 0x0000 and forward packet as expected.

        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        (peer_ip_ifaces_pair, rif_rx_ifaces, rif_support, ptf_port_idx,
         pc_ports_map, ptf_indices, ingress_router_mac) = common_param
        pkt = testutils.simple_ip_packet(
            eth_dst=ingress_router_mac,
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

        out_rif_ifaces, out_ifaces = TestIPPacket.parse_interfaces(
            duthost.command("show ip route 10.156.94.34")["stdout_lines"], pc_ports_map)
        out_ptf_indices = [ptf_indices[iface] for iface in out_ifaces]

        duthost.command("portstat -c")
        if rif_support:
            duthost.command("sonic-clear rifcounters")
        ptfadapter.dataplane.flush()

        testutils.send(ptfadapter, ptf_port_idx, pkt, self.PKT_NUM)
        time.sleep(5)
        match_cnt = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=list(out_ptf_indices))

        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])
        if rif_support:
            rif_counter_out = TestIPPacket.parse_rif_counters(
                duthost.command("show interfaces counters rif")["stdout_lines"])

        # In different platforms, IP packets with specific checksum will be dropped in different layer
        # We use both layer 2 counter and layer 3 counter to check where packet are dropped
        rx_ok = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_drp"].replace(",", ""))
        rx_err = int(rif_counter_out[rif_rx_ifaces]["rx_err"].replace(",", "")) if rif_support else 0
        tx_ok = TestIPPacket.sum_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = TestIPPacket.sum_ifaces_counts(portstat_out, out_ifaces, "tx_drp")
        tx_err = TestIPPacket.sum_ifaces_counts(rif_counter_out, out_rif_ifaces, "tx_err") if rif_support else 0

        if skip_traffic_test is True:
            return
        pytest_assert(rx_ok >= self.PKT_NUM_MIN,
                      "Received {} packets in rx, not in expected range".format(rx_ok))
        pytest_assert(tx_ok >= self.PKT_NUM_MIN,
                      "Forwarded {} packets in tx, not in expected range".format(tx_ok))
        pytest_assert(max(rx_drp, rx_err) <= self.PKT_NUM_ZERO,
                      "Dropped {} packets in rx, not in expected range".format(rx_err))
        pytest_assert(max(tx_drp, tx_err) <= self.PKT_NUM_ZERO,
                      "Dropped {} packets in tx, not in expected range".format(tx_err))
        pytest_assert(match_cnt >= self.PKT_NUM_MIN,
                      "DUT forwarded {} packets, but {} packets matched expected format, not in expected range"
                      .format(tx_ok, match_cnt))

    def test_forward_normal_ip_packet(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                      ptfadapter, common_param, skip_traffic_test):     # noqa F811
        # GIVEN a random normal ip packet
        # WHEN send the packet to DUT
        # THEN DUT should forward it as normal ip packet, nothing change but ttl-1
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        (peer_ip_ifaces_pair, rif_rx_ifaces, rif_support, ptf_port_idx,
         pc_ports_map, ptf_indices, ingress_router_mac) = common_param
        pkt = testutils.simple_ip_packet(
            eth_dst=ingress_router_mac,
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
            ip_src=peer_ip_ifaces_pair[0][0],
            ip_dst=peer_ip_ifaces_pair[1][0])

        exp_pkt = pkt.copy()
        exp_pkt.payload.ttl = pkt.payload.ttl - 1
        exp_pkt = mask.Mask(exp_pkt)

        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')

        out_rif_ifaces, out_ifaces = TestIPPacket.parse_interfaces(
            duthost.command("show ip route %s" % peer_ip_ifaces_pair[1][0])["stdout_lines"],
            pc_ports_map)
        out_ptf_indices = [ptf_indices[iface] for iface in out_ifaces]

        duthost.command("portstat -c")
        if rif_support:
            duthost.command("sonic-clear rifcounters")
        ptfadapter.dataplane.flush()

        testutils.send(ptfadapter, ptf_port_idx, pkt, self.PKT_NUM)
        time.sleep(5)
        match_cnt = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=list(out_ptf_indices))

        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])
        if rif_support:
            rif_counter_out = TestIPPacket.parse_rif_counters(
                duthost.command("show interfaces counters rif")["stdout_lines"])

        # In different platforms, IP packets with specific checksum will be dropped in different layer
        # We use both layer 2 counter and layer 3 counter to check where packet are dropped
        rx_ok = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_drp"].replace(",", ""))
        rx_err = int(rif_counter_out[rif_rx_ifaces]["rx_err"].replace(",", "")) if rif_support else 0
        tx_ok = TestIPPacket.sum_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = TestIPPacket.sum_ifaces_counts(portstat_out, out_ifaces, "tx_drp")
        tx_err = TestIPPacket.sum_ifaces_counts(rif_counter_out, out_rif_ifaces, "tx_err") if rif_support else 0

        if skip_traffic_test is True:
            return
        pytest_assert(rx_ok >= self.PKT_NUM_MIN,
                      "Received {} packets in rx, not in expected range".format(rx_ok))
        pytest_assert(tx_ok >= self.PKT_NUM_MIN,
                      "Forwarded {} packets in tx, not in expected range".format(tx_ok))
        pytest_assert(max(rx_drp, rx_err) <= self.PKT_NUM_ZERO,
                      "Dropped {} packets in rx, not in expected range".format(rx_err))
        pytest_assert(max(tx_drp, tx_err) <= self.PKT_NUM_ZERO,
                      "Dropped {} packets in tx, not in expected range".format(tx_err))
        pytest_assert(match_cnt >= self.PKT_NUM_MIN,
                      "DUT forwarded {} packets, but {} packets matched expected format, not in expected range"
                      .format(tx_ok, match_cnt))

    def test_drop_ip_packet_with_wrong_0xffff_chksum(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                                     ptfadapter, common_param, skip_traffic_test):  # noqa F811
        # GIVEN a random normal ip packet, and manually modify checksum to 0xffff
        # WHEN send the packet to DUT
        # THEN DUT should drop it and add drop count
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        (peer_ip_ifaces_pair, rif_rx_ifaces, rif_support, ptf_port_idx,
         pc_ports_map, ptf_indices, ingress_router_mac) = common_param
        pkt = testutils.simple_ip_packet(
            eth_dst=ingress_router_mac,
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
            ip_src=peer_ip_ifaces_pair[0][0],
            ip_dst=peer_ip_ifaces_pair[1][0])

        pkt.payload.chksum = 0xffff

        out_rif_ifaces, out_ifaces = TestIPPacket.parse_interfaces(
            duthost.command("show ip route %s" % peer_ip_ifaces_pair[1][0])["stdout_lines"], pc_ports_map)

        duthost.command("portstat -c")
        if rif_support:
            duthost.command("sonic-clear rifcounters")
        ptfadapter.dataplane.flush()

        testutils.send(ptfadapter, ptf_port_idx, pkt, self.PKT_NUM)
        time.sleep(5)

        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])
        if rif_support:
            rif_counter_out = TestIPPacket.parse_rif_counters(
                duthost.command("show interfaces counters rif")["stdout_lines"])

        # In different platforms, IP packets with specific checksum will be dropped in different layer
        # We use both layer 2 counter and layer 3 counter to check where packet are dropped
        rx_ok = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[peer_ip_ifaces_pair[0][1][0]]["rx_drp"].replace(",", ""))
        rx_err = int(rif_counter_out[rif_rx_ifaces]["rx_err"].replace(",", "")) if rif_support else 0
        tx_ok = TestIPPacket.sum_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = TestIPPacket.sum_ifaces_counts(portstat_out, out_ifaces, "tx_drp")
        tx_err = TestIPPacket.sum_ifaces_counts(rif_counter_out, out_rif_ifaces, "tx_err") if rif_support else 0

        asic_type = duthost.facts['asic_type']
        if skip_traffic_test is True:
            return
        pytest_assert(rx_ok >= self.PKT_NUM_MIN,
                      "Received {} packets in rx, not in expected range".format(rx_ok))
        pytest_assert(max(rx_drp, rx_err) >= self.PKT_NUM_MIN if asic_type not in ["marvell"] else True,
                      "Dropped {} packets in rx, not in expected range".format(rx_err))
        pytest_assert(tx_ok <= self.PKT_NUM_ZERO,
                      "Forwarded {} packets in tx, not in expected range".format(tx_ok))
        pytest_assert(max(tx_drp, tx_err) <= self.PKT_NUM_ZERO,
                      "Dropped {} packets in tx, not in expected range".format(tx_err))
