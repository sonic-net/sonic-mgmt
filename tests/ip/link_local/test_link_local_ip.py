import re
import random
import logging
import json
import ipaddress
import pytest
import tempfile
import time
from ptf import mask, packet
import ptf.packet as scapy
import ptf.testutils as testutils
from scapy.all import sniff
from tests.common import utilities
from tests.common.helpers.assertions import pytest_assert
from tests.common.portstat_utilities import parse_portstat
from tests.common.utilities import parse_rif_counters
from tests.ip.ip_util import sum_ifaces_counts

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)
IPV4_ROUTE = "10.156.94.34"
IPV6_ROUTE = "20c0:a958::1"
IPV4_LINK_LOCAL_ADDRESS = "169.254.1.5"
IPV6_LINK_LOCAL_ADDRESS = "fe80::7efe:90ff:fe12:2024"
VLAN_ID = 10
PKT_NUM = 500
PKT_NUM_ZERO = 0
PACKET_SAVE_PATH = "/tmp/link_local.pcap"
TCPDUMP_WAIT_TIME = 50


def cleanup(cleanup_list):
    """
    Execute all the functions in the cleanup list
    """
    for func, args, kwargs in cleanup_list:
        func(*args, **kwargs)


@pytest.fixture()
def cleanup_list():
    """
    Fixture to execute cleanup after test run
    """
    cleanup_list = []

    yield cleanup_list

    cleanup(cleanup_list)


class TestLinkLocalIPacket:

    @staticmethod
    def check_if_test_is_supported(duthost):
        platform = duthost.facts['platform']
        hwsku = duthost.facts['hwsku']
        sai_settings = {}
        sai_profile = "/usr/share/sonic/device/{}/{}/sai.profile".format(platform, hwsku)
        for line in duthost.command("cat %s" % sai_profile)["stdout_lines"]:
            key, value = line.split("=")
            sai_settings[key] = value
        if int(sai_settings.get("SAI_NOT_DROP_SIP_DIP_LINK_LOCAL", 0)) != 1:
            pytest.skip("Test is not supported, SAI_NOT_DROP_SIP_DIP_LINK_LOCAL is not equal 1 or not specified")

    @pytest.fixture(scope="class", autouse=True)
    def common_params(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo, ptfadapter, ptfhost):
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        self.check_if_test_is_supported(duthost)
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

        # generate peer_ip and port channel pair, i.e :[("10.0.0.57", "PortChannel0001")]
        peer_ip_pc_pair = [(pc["peer_addr"], pc["attachto"]) for pc in mg_facts["minigraph_portchannel_interfaces"]
                           if ipaddress.ip_address(pc['peer_addr']).version == 4]
        # generate port channel members dict, i.e: {'PortChannel101': ['Ethernet64'], ...}
        pc_ports_map = {pair[1]: mg_facts["minigraph_portchannels"][pair[1]]["members"]
                        for pair in peer_ip_pc_pair}
        pc_ports = []
        for pc, pc_port_members in pc_ports_map.items():
            pc_ports += pc_port_members
        downlinks = set(mg_facts['minigraph_ports'].keys()).difference(pc_ports)
        if not downlinks:
            pytest.skip(f'Test case not supported at {tbinfo["topo"]["name"]} topology')

        # Get 2 Port Channels to send traffic
        rx_pc, tx_pc = random.sample(list(pc_ports_map.keys()), 2)
        dut_pc_rx_iface = pc_ports_map[rx_pc][0]
        ptf_pc_port_idx = mg_facts["minigraph_ptf_indices"][dut_pc_rx_iface]
        ptf_pc_port_mac = ptfadapter.dataplane.get_mac(0, ptf_pc_port_idx).decode("utf-8")
        ptf_port_idx_namespace = mg_facts["minigraph_portchannels"][rx_pc]['namespace']
        asic_id = duthost.get_asic_id_from_namespace(ptf_port_idx_namespace)
        ingress_router_mac = duthost.asic_instance(asic_id).get_router_mac()
        ptf_indices = mg_facts["minigraph_ptf_indices"]
        rif_support = self.is_rif_supported(duthost)
        out_rif_ifaces = [tx_pc]
        out_ifaces = pc_ports_map[tx_pc]
        out_ptf_indices = [ptf_indices[iface] for iface in out_ifaces]

        # Add tag to routes to ensure traffic is forwarded to tx_pc
        ipv4_prefix = "{}/32".format(IPV4_ROUTE)
        ipv6_prefix = "{}/64".format(IPV6_ROUTE)
        pc_ipv4_addr = self.get_pc_peer_addr(mg_facts, tx_pc, prefixlen=31)
        pc_ipv6_addr = self.get_pc_peer_addr(mg_facts, tx_pc, prefixlen=126)
        tag_route_cmd = "vtysh -c \"configure terminal\" -c \"ip route {} {} tag 1\"".format(ipv4_prefix, pc_ipv4_addr)
        vtysh_cmd_for_namespace = duthost.get_vtysh_cmd_for_namespace(tag_route_cmd, ptf_port_idx_namespace)
        duthost.shell(vtysh_cmd_for_namespace)
        tag_route_cmd = "vtysh -c \"configure terminal\" -c \"ip route {} {} tag 1\"".format(ipv6_prefix, pc_ipv6_addr)
        vtysh_cmd_for_namespace = duthost.get_vtysh_cmd_for_namespace(tag_route_cmd, ptf_port_idx_namespace)
        duthost.shell(vtysh_cmd_for_namespace)
        duthost.command("rm -rf {}".format(PACKET_SAVE_PATH))

        # Get 2 downlinks
        rx_iface, tx_iface = random.sample(downlinks, 2)
        ptf_rx_idx = mg_facts["minigraph_ptf_indices"][rx_iface]
        ptf_tx_idx = mg_facts["minigraph_ptf_indices"][tx_iface]
        link_local_src = self.get_port_default_ipv6_link_local_address(ptfhost, 'eth{}'.format(ptf_rx_idx))
        link_local_dst = self.get_port_default_ipv6_link_local_address(ptfhost, 'eth{}'.format(ptf_tx_idx))
        ptf_rx_mac = ptfadapter.dataplane.get_mac(0, ptf_rx_idx).decode("utf-8")
        ptf_tx_mac = ptfadapter.dataplane.get_mac(0, ptf_tx_idx).decode("utf-8")
        downlink_uplink_rx_info = [(ptf_pc_port_mac, ptf_pc_port_idx, dut_pc_rx_iface, rx_pc, out_rif_ifaces,
                                    out_ifaces, out_ptf_indices),
                                   (ptf_rx_mac, ptf_rx_idx, rx_iface, None, out_rif_ifaces, out_ifaces, out_ptf_indices)
                                   ]
        yield duthost, mg_facts, pc_ports_map, ptf_indices, ingress_router_mac, rx_iface, tx_iface, ptf_rx_mac, \
            ptf_rx_idx, ptf_tx_mac, ptf_tx_idx, link_local_src, link_local_dst, downlink_uplink_rx_info, rif_support
        # Remove tag from routes
        tag_route_cmd = "vtysh -c \"configure terminal\" -c \"no ip route {} {} tag 1\"". \
            format(ipv4_prefix, pc_ipv4_addr)
        vtysh_cmd_for_namespace = duthost.get_vtysh_cmd_for_namespace(tag_route_cmd, ptf_port_idx_namespace)
        duthost.shell(vtysh_cmd_for_namespace)
        tag_route_cmd = "vtysh -c \"configure terminal\" -c \"no ip route {} {} tag 1\"". \
            format(ipv6_prefix, pc_ipv6_addr)
        vtysh_cmd_for_namespace = duthost.get_vtysh_cmd_for_namespace(tag_route_cmd, ptf_port_idx_namespace)
        duthost.shell(vtysh_cmd_for_namespace)

    @pytest.fixture(scope='class', autouse=True)
    def config_counter_poll_interval(self, duthost):
        """
        Set counter poll interval to 100ms to ensure that the counters are updated in time
        """
        origin_queue_interval = duthost.get_counter_poll_status()['PORT_STAT']['interval']
        duthost.set_counter_poll_interval('PORT_STAT', 100)

        yield

        duthost.set_counter_poll_interval('PORT_STAT', origin_queue_interval)

    @staticmethod
    def remove_ips_form_downlink_ifaces(duthost, mg_facts, rx_iface, tx_iface):
        for addr_dict in mg_facts['minigraph_interfaces']:
            for iface in [rx_iface, tx_iface]:
                if addr_dict['attachto'] == iface:
                    duthost.command("sudo config interface ip remove {} {}/{}".format(iface,
                                                                                      addr_dict['addr'],
                                                                                      addr_dict['mask']))

    @staticmethod
    def get_pc_peer_addr(mg_facts, pc, prefixlen=31):
        for addr_dict in mg_facts['minigraph_portchannel_interfaces']:
            if addr_dict['attachto'] == pc and int(addr_dict['prefixlen']) == prefixlen:
                return addr_dict['peer_addr']

    @staticmethod
    def is_rif_supported(duthost):
        # Some platforms do not support rif counter
        rif_support = False
        try:
            rif_counter_out = parse_rif_counters(
                duthost.command("show interfaces counters rif")["stdout_lines"])
            rif_iface = list(rif_counter_out.keys())[0]
            rif_support = False if rif_counter_out[rif_iface]['rx_err'] == 'N/A' else True
        except Exception as e:
            logger.info("Show rif counters failed with exception: {}".format(repr(e)))
        return rif_support

    @staticmethod
    def get_rx_ifaces(namespace_with_min_two_ip_interface, namespace_neigh_cnt_map,
                      peer_ip_ifaces_pair_list, peer_ip_ifaces_pair, pc_ports_map):
        """
        :return: will return port channel interface in case rif is supported,
        and pc interface member name.
        i.e, PortChannel101, Ethernet64
        """
        rif_rx_ifaces, dut_rx_iface = None, None
        if namespace_with_min_two_ip_interface is not None:
            for v in namespace_neigh_cnt_map[namespace_with_min_two_ip_interface]:
                peer_ip_ifaces_pair.append(peer_ip_ifaces_pair_list[v[0]][v[1]])
                dut_rx_iface = peer_ip_ifaces_pair[0][1][0]
                if not rif_rx_ifaces:
                    if v[0]:
                        rif_rx_ifaces = \
                            list(pc_ports_map.keys())[list(pc_ports_map.values()).index(peer_ip_ifaces_pair[0][1])]
                    else:
                        rif_rx_ifaces = dut_rx_iface
        else:
            pytest.skip("Skip test as not enough neighbors/ports.")
        return rif_rx_ifaces, dut_rx_iface

    def test_link_local_src_ipv4_packet(self, ptfadapter, common_params):
        (duthost, mg_facts, pc_ports_map, ptf_indices, ingress_router_mac, rx_iface, tx_iface,
         ptf_rx_mac, ptf_rx_idx, _, ptf_tx_idx, link_local_src,
         link_local_dst, downlink_uplink_rx_info, rif_support) = common_params

        for ptf_mac, ptf_idx, dut_rx_iface, rif_rx_iface, out_rif_ifaces, out_ifaces, out_ptf_indices \
                in downlink_uplink_rx_info:

            logger.info("Sending IPV4 Packet from dut interface {}, rif interface {}".format(dut_rx_iface,
                                                                                             rif_rx_iface))
            pkt = testutils.simple_ip_packet(eth_dst=ingress_router_mac,
                                             eth_src=ptf_mac,
                                             ip_src=IPV4_LINK_LOCAL_ADDRESS,
                                             ip_dst=IPV4_ROUTE)

            exp_pkt = self.get_exp_packet(pkt)

            self.clear_counters(duthost, rif_support)
            ptfadapter.dataplane.flush()

            testutils.send(ptfadapter, ptf_idx, pkt, PKT_NUM)
            time.sleep(1)
            self.validate_counters(duthost, ptfadapter, exp_pkt, dut_rx_iface, rif_rx_iface,
                                   out_ptf_indices, out_ifaces, out_rif_ifaces, rif_support)

    def test_link_local_src_ipv6_packet(self, ptfadapter, common_params):
        (duthost, mg_facts, pc_ports_map, ptf_indices, ingress_router_mac, rx_iface, tx_iface,
         ptf_rx_mac, ptf_rx_idx, _, ptf_tx_idx, link_local_src,
         link_local_dst, downlink_uplink_rx_info, rif_support) = common_params

        for ptf_mac, ptf_idx, dut_rx_iface, rif_rx_iface, out_rif_ifaces, out_ifaces, out_ptf_indices\
                in downlink_uplink_rx_info:
            logger.info("Sending IPV6 Packet from dut interface {}, rif interface {}".format(dut_rx_iface,
                                                                                             rif_rx_iface))
            pkt = testutils.simple_ipv6ip_packet(eth_dst=ingress_router_mac,
                                                 eth_src=ptf_mac,
                                                 ipv6_src=IPV6_LINK_LOCAL_ADDRESS,
                                                 ipv6_dst=IPV6_ROUTE)

            exp_pkt = self.get_exp_packet(pkt, is_ipv6_pkt=True)

            self.clear_counters(duthost, rif_support)
            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, ptf_idx, pkt, PKT_NUM)
            time.sleep(1)
            self.validate_counters(duthost, ptfadapter, exp_pkt, dut_rx_iface, rif_rx_iface,
                                   out_ptf_indices, out_ifaces, out_rif_ifaces, rif_support)

    def test_link_local_dst_ipv6_packet_dut_cpu(self, ptfadapter, common_params):
        (duthost, mg_facts, pc_ports_map, ptf_indices, ingress_router_mac, rx_iface, tx_iface,
         ptf_rx_mac, ptf_rx_idx, _, ptf_tx_idx, link_local_src,
         link_local_dst, downlink_uplink_rx_info, rif_support) = common_params

        dut_link_local_dst = self.get_port_default_ipv6_link_local_address(duthost, rx_iface)

        logger.info("Sending IPV6 Packet to dut interface {},".format(rx_iface))
        pkt = testutils.simple_ipv6ip_packet(eth_dst=ingress_router_mac,
                                             eth_src=ptf_rx_mac,
                                             ipv6_src=link_local_src,
                                             ipv6_dst=dut_link_local_dst)
        start_pcap = "tcpdump -i {} -w {} -vv ip6 'src host {} and dst host {}'".format(rx_iface,
                                                                                        PACKET_SAVE_PATH,
                                                                                        link_local_src,
                                                                                        dut_link_local_dst)
        start_pcap = "nohup %s" % start_pcap
        stop_pcap = 'pkill tcpdump'
        duthost.shell(start_pcap, module_async=True)
        self.clear_counters(duthost, rif_support)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_rx_idx, pkt, PKT_NUM)
        time.sleep(1)
        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])
        rx_ok = int(portstat_out[rx_iface]["rx_ok"].replace(",", ""))
        pytest_assert(rx_ok >= PKT_NUM,
                      "Received {} packets in rx counters, expected >= {}".format(rx_ok, PKT_NUM))
        # Sleep to ensure all packets will be captured
        time.sleep(TCPDUMP_WAIT_TIME)
        duthost.shell(stop_pcap, module_ignore_errors=True)

        tmp_pcap = tempfile.NamedTemporaryFile()
        duthost.fetch(src=PACKET_SAVE_PATH, dest=tmp_pcap.name, flat=True)
        received_packets = sniff(offline=tmp_pcap.name)

        logging.debug("Packets received by port %s:", rx_iface)
        for i, pkt in enumerate(received_packets):
            logging.debug("%d: %s" % (i, utilities.dump_scapy_packet_show_output(pkt)))
        pytest_assert(len(received_packets) >= PKT_NUM,
                      "Received tcpdump {} packets, expected >= {}".format(len(received_packets), PKT_NUM))

    def test_link_local_dst_ipv4_packet(self, ptfhost, ptfadapter, cleanup_list, common_params):
        (duthost, mg_facts, pc_ports_map, ptf_indices, ingress_router_mac, rx_iface, tx_iface,
         ptf_rx_mac, ptf_rx_idx, ptf_tx_mac, ptf_tx_idx, link_local_src,
         link_local_dst, downlink_uplink_rx_info, rif_support) = common_params

        self.remove_ips_form_downlink_ifaces(duthost, mg_facts, rx_iface, tx_iface)
        self.add_vlan_configuration(duthost, rx_iface, tx_iface, cleanup_list)

        link_local_src, link_local_dst = self.add_link_local_address_to_ptf(ptfhost, ptf_rx_idx,
                                                                            ptf_tx_idx, cleanup_list)

        logger.info("Sending IPV4 Packet from {} to {}".format(rx_iface, tx_iface))
        pkt = testutils.simple_ip_packet(eth_dst=ptf_tx_mac,
                                         eth_src=ptf_rx_mac,
                                         ip_src=link_local_src,
                                         ip_dst=link_local_dst)
        exp_pkt = self.get_exp_packet(pkt)

        out_rif_ifaces, out_ifaces, out_ptf_indices = None, [tx_iface], [ptf_tx_idx]

        self.clear_counters(duthost, rif_support)
        ptfadapter.dataplane.flush()

        testutils.send(ptfadapter, ptf_rx_idx, pkt, PKT_NUM)
        time.sleep(1)
        self.validate_counters(duthost, ptfadapter, exp_pkt, rx_iface, None,
                               out_ptf_indices, out_ifaces, out_rif_ifaces, rif_support)

    def test_link_local_dst_ipv6_packet(self, ptfadapter, cleanup_list, common_params):
        (duthost, mg_facts, pc_ports_map, ptf_indices, ingress_router_mac, rx_iface, tx_iface,
         ptf_rx_mac, ptf_rx_idx, ptf_tx_mac, ptf_tx_idx, link_local_src,
         link_local_dst, downlink_uplink_rx_info, rif_support) = common_params

        self.remove_ips_form_downlink_ifaces(duthost, mg_facts, rx_iface, tx_iface)
        self.add_vlan_configuration(duthost, rx_iface, tx_iface, cleanup_list)

        logger.info("Sending IPV6 Packet from {} to {}".format(rx_iface, tx_iface))
        pkt = testutils.simple_ipv6ip_packet(eth_dst=ptf_tx_mac,
                                             eth_src=ptf_rx_mac,
                                             ipv6_src=link_local_src,
                                             ipv6_dst=link_local_dst)

        exp_pkt = self.get_exp_packet(pkt, is_ipv6_pkt=True)

        out_rif_ifaces, out_ifaces, out_ptf_indices = None, [tx_iface], [ptf_tx_idx]
        self.clear_counters(duthost, rif_support)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, ptf_rx_idx, pkt, PKT_NUM)
        time.sleep(1)
        self.validate_counters(duthost, ptfadapter, exp_pkt, rx_iface, None,
                               out_ptf_indices, out_ifaces, out_rif_ifaces, rif_support)

    @staticmethod
    def add_vlan_configuration(duthost, rx_iface, tx_iface, cleanup_list):
        duthost.command("config vlan add {}".format(VLAN_ID))
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

        vlan_member = config_facts.get('VLAN_MEMBER')
        if vlan_member:
            for vlan_interface, vlan_members in vlan_member.items():
                vlan_id = re.search(r"Vlan(\d+)", vlan_interface).group(1)
                if vlan_members.get(rx_iface):
                    for iface in [rx_iface, tx_iface]:
                        tagging_mode = "-u" if vlan_members[iface]["tagging_mode"] == "untagged" else ""
                        duthost.command("config vlan member del {} {}".format(vlan_id, iface))
                        duthost.command("config vlan member add {} {} -u".format(VLAN_ID, iface))
                        cleanup_list.append((duthost.command,
                                             ("config vlan member del {} {}".format(VLAN_ID, iface), ), {}))
                        cleanup_list.append((duthost.command,
                                             ("config vlan member add {} {} {}".format(vlan_id,
                                                                                       iface, tagging_mode), ), {}))
        else:
            for iface in [rx_iface, tx_iface]:
                duthost.command("config vlan member add {} {} -u".format(VLAN_ID, iface))
                cleanup_list.append((duthost.command,
                                     ("config vlan member del {} {}".format(VLAN_ID, iface), ), {}))

        cleanup_list.append((duthost.command, ("config vlan del {}".format(VLAN_ID), ), {}))

    @staticmethod
    def add_link_local_address_to_ptf(ptfhost, ptf_rx_idx, ptf_tx_idx, cleanup_list):
        link_local_src, link_local_dst = "169.254.2.1", "169.254.2.2"

        ptfhost.command('ip addr add {}/24 dev eth{}'.format(link_local_src, ptf_rx_idx))
        ptfhost.command('ip addr add {}/24 dev eth{}'.format(link_local_dst, ptf_tx_idx))

        cleanup_list.append((ptfhost.command,
                             ('ip addr del {}/24 dev eth{}'.format(link_local_src, ptf_rx_idx), ), {}))
        cleanup_list.append((ptfhost.command,
                             ('ip addr del {}/24 dev eth{}'.format(link_local_dst, ptf_tx_idx), ), {}))
        return link_local_src, link_local_dst

    @staticmethod
    def clear_counters(duthost, rif_support):
        duthost.command("sonic-clear counters")
        if rif_support:
            duthost.command("sonic-clear rifcounters")

    @staticmethod
    def get_exp_packet(pkt, is_ipv6_pkt=False):
        """
        ttl is not checked because not all test route the packets, is some tests packets are switched.
        :param pkt: pkt sent
        :param is_ipv6_pkt: True if packet is IPV6, False if IPV4
        :return: The expected packet that should be received by PTF
        """
        logger.debug("Packet: {}".format(pkt))
        exp_pkt = pkt.copy()
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        if is_ipv6_pkt:
            exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
        else:
            exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
            exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
        return exp_pkt

    @staticmethod
    def validate_counters(duthost, ptfadapter, exp_pkt, dut_rx_iface, rif_rx_ifaces, out_ptf_indices,
                          out_ifaces, out_rif_ifaces, rif_support):
        portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])
        if rif_support:
            rif_counter_out = parse_rif_counters(duthost.command("show interfaces counters rif")["stdout_lines"])

        # Rx counters Validations
        rx_ok = int(portstat_out[dut_rx_iface]["rx_ok"].replace(",", ""))
        rx_drp = int(portstat_out[dut_rx_iface]["rx_drp"].replace(",", ""))
        rx_err = int(rif_counter_out[rif_rx_ifaces]["rx_err"].replace(",", "")) \
            if rif_support and rif_rx_ifaces else 0
        pytest_assert(rx_ok >= PKT_NUM,
                      "Received {} packets in rx, expected >= {}".format(rx_ok, PKT_NUM))
        pytest_assert(max(rx_drp, rx_err) <= PKT_NUM_ZERO,
                      "Dropped {} packets in rx, expected range <= {}".format(rx_err, PKT_NUM_ZERO))

        # Match packets by PTF Validation
        match_cnt = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=list(out_ptf_indices))
        pytest_assert(match_cnt >= PKT_NUM,
                      "packets matched by PTF {}, expected >= {}"
                      .format(match_cnt, PKT_NUM))

        # Tx counters Validation
        tx_ok = sum_ifaces_counts(portstat_out, out_ifaces, "tx_ok")
        tx_drp = sum_ifaces_counts(portstat_out, out_ifaces, "tx_drp")
        tx_err = sum_ifaces_counts(rif_counter_out, out_rif_ifaces, "tx_err") \
            if rif_support and out_rif_ifaces else 0
        pytest_assert(tx_ok >= PKT_NUM,
                      "Forwarded {} packets in tx, expected >= {}".format(tx_ok, PKT_NUM))
        pytest_assert(max(tx_drp, tx_err) <= PKT_NUM_ZERO,
                      "Dropped {} packets in tx, expected range <= {}".format(tx_err, PKT_NUM_ZERO))

    @staticmethod
    def get_port_default_ipv6_link_local_address(host, iface):
        ipv6_link_local_address = None
        cmd = "ip -6 -json -brief address show dev {}".format(iface)
        ipv6_link_local_address_data = str(host.command(cmd)["stdout_lines"][0])
        ipv6_link_local_address_json = json.loads(ipv6_link_local_address_data)
        for ip_address_dict in ipv6_link_local_address_json:
            if ip_address_dict.get("ifname") == iface:
                for addr_info in ip_address_dict["addr_info"]:
                    if int(addr_info.get("prefixlen")) == 64:
                        ipv6_link_local_address = addr_info.get("local")
        return ipv6_link_local_address
