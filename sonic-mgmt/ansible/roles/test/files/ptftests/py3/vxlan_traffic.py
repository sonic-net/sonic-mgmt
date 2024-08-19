# VxLAN Traffic Script, to be run in PTF container. Usage:
# ptf --test-dir ptftests vxlan_traffic.VXLAN --platform-dir ptftests
#    --qlen=1000 --platform remote -t
#    't2_ports=[16, 17, 0, 1, 4, 5, 21, 20];dut_mac=u"64:3a:ea:c1:73:f8";\
#    expect_encap_success=True;packet_count=10;downed_endpoints=["100.0.1.10"]\
#    vxlan_port=4789;topo_file="/tmp/vxlan_topo_file.json";config_file=\
#    "/tmp/vxlan-config-TC1-v6_in_v4.json";t0_ports=[u"Ethernet42"];\
#    random_src_ip=False;random_dport=True;random_dport=False' --relax
#    --debug info --log-file /tmp/vxlan-tests.TC1.v6_in_v4.log

'''
     The test checks vxlan encapsulation:
     'test_encap' : Sends regular packets to T0-facing interface and expects to
                    see the encapsulated packets on the T2-facing interfaces.

    The test has the following parameters:
    config_file          : is a filename of a file which contains all
                           necessary information to run the test. The file is
                           populated by ansible. This parameter is mandatory.
    t2_ports             : The list of PTF port indices facing T2 Neighbors,
                           AKA ports to expect the encapsulated packets to
                           come in.
    dut_mac              : The MAC address of the dut, given by "show
                           platform summary".
    expect_encap_success : Is the encapsulation expected to succeed ?
                           True/False.
    packet_count         : Number of packets per endpoint to try. Default 10
    downned_endpoints    : The list of IP addresses which are down, due to BFD
                           being disabled.
    vxlan_port           : The global VxLAN port setup in the DUT.
                           Default: 4789
    topo_file            : The file that contains the topology information,
                           like minigraph data, connections, and so on.
    t0_ports             : The DUT intf into which we will inject payload
                           packets.
    random_src_ip        : Should we use random src IP addresses for the
                           payload packets?  Default:False
    random_dport         : Should we use random dest port for the payload
                           packets? Default:True
    random_sport         : Should we use random src port for the payload
                           packets? Default:False
'''

import os.path
import json
import base64
import six
from datetime import datetime
import logging
import random
from ipaddress import ip_address, IPv4Address, IPv6Address
import ptf
import ptf.packet as scapy
from ptf.base_tests import BaseTest
from ptf.testutils import (
    simple_tcp_packet,
    simple_tcpv6_packet,
    simple_vxlan_packet,
    simple_vxlanv6_packet,
    verify_no_packet_any,
    send_packet,
    test_params_get,
    dp_poll)
from ptf.mask import Mask

VARS = {}
VARS['tcp_sport'] = 1234
VARS['tcp_dport'] = 5000
VARS['udp_sport'] = 1234

Logger = logging.getLogger(__name__)

# Some constants used in this code
MIN_PACKET_COUNT = 10
MINIMUM_PACKETS_FOR_ECMP_VALIDATION = 300
TEST_ECN = True

Address_Count = 0


def get_ip_address(af, hostid=1, netid=100):
    '''
        Get a new IP address to use based on the arguments.
        hostid : The last octet in the Address.
        netid  : The first octet in the Address.
    '''
    global Address_Count
    third_octet = int(Address_Count % 255)
    second_octet = int((Address_Count / 255) % 255)
    first_octet = int(netid + (Address_Count / 65025))
    Address_Count = Address_Count + 1
    if af == 'v4':
        return six.text_type("{}.{}.{}.{}".format(
            first_octet, second_octet, third_octet, hostid))
    if af == 'v6':
        # :0: gets removed in the IPv6 addresses.
        # Adding a to octets, to avoid it.
        return six.text_type("fddd:a{}:a{}::a{}:{}".format(
            first_octet, second_octet, third_octet, hostid))


def get_incremental_value(key):
    '''
        Global function to keep track of the tcp/udp port numbers used in
        payload.
    '''
    global VARS
    # We would like to use the ports from 1234 to 65535
    VARS[key] = max(1234, (VARS[key] + 1) % 65535)
    return VARS[key]


def read_ptf_macs():
    '''
        Get the list of mac addresses of all interfaces in the PTF.
    '''
    addrs = {}
    for intf in os.listdir('/sys/class/net'):
        if os.path.isdir('/sys/class/net/%s' % intf):
            with open('/sys/class/net/%s/address' % intf) as fp:
                addrs[intf] = fp.read().strip()

    return addrs


class VXLAN(BaseTest):
    '''
        Testcase for VxLAN. Currently implements encap testcase.
        decap is TBD.
    '''

    def __init__(self):
        BaseTest.__init__(self)

    def setUp(self):
        '''
            Setup the internal structures for running the test.
            1. Parse the command line arguments.
            2. Load the configs from the input files.
            3. Ready the mapping of destination->nexthops.
        '''
        self.dataplane = ptf.dataplane_instance
        self.test_params = test_params_get()
        self.random_src_ip = self.test_params['random_src_ip']
        self.random_dport = self.test_params['random_dport']
        self.random_sport = self.test_params['random_sport']
        self.tolerance = self.test_params['tolerance']
        self.dut_mac = self.test_params['dut_mac']
        self.vxlan_port = self.test_params['vxlan_port']
        self.expect_encap_success = self.test_params['expect_encap_success']
        self.packet_count = self.test_params['packet_count']
        self.downed_endpoints = self.test_params['downed_endpoints']
        self.t2_ports = self.test_params['t2_ports']
        # The ECMP check fails occasionally if there is not enough packets.
        # We should keep the packet count atleast MIN_PACKET_COUNT.
        if self.packet_count < MIN_PACKET_COUNT:
            Logger.warning(
                "Packet_count is below minimum, resetting to %s",
                MIN_PACKET_COUNT)
            self.packet_count = MIN_PACKET_COUNT

        self.random_mac = "00:aa:bb:cc:dd:ee"
        self.ptf_mac_addrs = read_ptf_macs()
        with open(self.test_params['config_file']) as fp:
            self.config_data = json.load(fp)
        with open(self.test_params['topo_file']) as fp:
            self.topo_data = json.load(fp)

        self.fill_loopback_ip()
        self.nbr_info = self.config_data['neighbors']
        self.packets = []
        self.dataplane.flush()
        self.vxlan_enabled = True
        return

    def tearDown(self):
        '''
            Close the packet capture file.
        '''
        if self.vxlan_enabled:
            json.dump(self.packets, open("/tmp/vnet_pkts.json", 'w'))
        return

    def fill_loopback_ip(self):
        '''
            Get the DUT's Loopback ipv4 ipv6 addresses from minigraph.
        '''
        loop_config_data = \
            self.topo_data['minigraph_facts']['minigraph_lo_interfaces']
        for entry in loop_config_data:
            if isinstance(ip_address(entry['addr']), IPv4Address):
                self.loopback_ipv4 = entry['addr']
            if isinstance(ip_address(entry['addr']), IPv6Address):
                self.loopback_ipv6 = entry['addr']

    def runTest(self):
        '''
            Main code of this script.
            Run the encap test for every destination, and its nexthops.
        '''
        mg_facts = self.topo_data['minigraph_facts']
        for t0_intf in self.test_params['t0_ports']:
            # find the list of neigh addresses for the t0_ports.
            # For each neigh address(Addr1):
            # For each destination address(Addr2) in the same Vnet as t0_intf,
            # send traffic from Add1 to it. If there
            # are multiple nexthops for the Addr2, then send that
            # many different streams(different tcp ports).
            neighbors = [self.config_data['neighbors'][t0_intf]]
            ptf_port = mg_facts['minigraph_ptf_indices'][t0_intf]
            vnet = self.config_data['vnet_intf_map'][t0_intf]
            vni = self.config_data['vnet_vni_map'][vnet]
            for addr in neighbors:
                for destination, nexthops in \
                        list(self.config_data['dest_to_nh_map'][vnet].items()):
                    self.test_encap(
                        ptf_port,
                        vni,
                        addr,
                        destination,
                        nexthops,
                        test_ecn=TEST_ECN,
                        random_dport=self.random_dport,
                        random_sport=self.random_sport,
                        random_src_ip=self.random_src_ip)

    def verify_all_addresses_used_equally(self,
                                          nhs,
                                          returned_ip_addresses,
                                          packet_count,
                                          downed_endpoints=[]):
        '''
           Verify the ECMP functionality using 2 checks.
           Check 1 verifies every nexthop address has been used.
           Check 2 verifies the distribution of number of packets among the
           nexthops.
           Params:
               nhs                   : the nexthops that are configured.
               returned_ip_addresses : The dict containing the nh addresses
                                       and corresponding packet counts.
        '''

        if downed_endpoints:
            for down_endpoint in downed_endpoints:
                if down_endpoint in nhs:
                    nhs.remove(down_endpoint)
                if down_endpoint in returned_ip_addresses:
                    raise RuntimeError(
                        "We received traffic with a downed endpoint({}), "
                        "unexpected.".format(down_endpoint))

        # Check #1 : All addresses have been used, except the downed ones.
        if set(nhs) - set(returned_ip_addresses.keys()) == set([]):
            Logger.info("    Each valid endpoint address has been used")
            Logger.info("Packets sent:%s distribution:", packet_count)
            for nh_address in list(returned_ip_addresses.keys()):
                Logger.info("      %s : %s",
                            nh_address,
                            returned_ip_addresses[nh_address])
            # Check #2 : The packets are almost equally distributed.
            # Every next-hop should have received within {tolerance}% of the
            # packets that we sent per nexthop(which is packet_count). This
            # check is valid only if there are large enough number of
            # packets(300). Any lower number will need higher
            # tolerance(more than 2%).
            if packet_count > MINIMUM_PACKETS_FOR_ECMP_VALIDATION:
                for nh_address in list(returned_ip_addresses.keys()):
                    if (1.0-self.tolerance) * packet_count <= \
                        returned_ip_addresses[nh_address] <= \
                            (1.0+self.tolerance) * packet_count:
                        pass
                    else:
                        raise RuntimeError(
                            "ECMP nexthop address: {} received too less or too"
                            " many of the packets expected. Expected:{}, "
                            "received on that address:{}".format(
                                nh_address,
                                packet_count,
                                returned_ip_addresses[nh_address]))
        else:
            raise RuntimeError(
                "Not all addresses were used. Here are the unused ones:{},"
                "expected:{}, got:{}".format(
                    set(nhs) - set(returned_ip_addresses.keys()),
                    nhs,
                    returned_ip_addresses))

    def test_encap(
            self,
            ptf_port,
            vni,
            ptf_addr,
            destination,
            nhs,
            test_ecn=False,
            random_dport=True,
            random_sport=False,
            random_src_ip=False):
        '''
           Test the encapsulation of packets works correctly.
           1. Send a TCP packet to the DUT port.
           2. Verify that the DUT returns an encapsulated packet correctly.
           3. Optionally: Perform if the ECMP is working(all nexthops are used
           equally).
        '''
        try:
            pkt_len = 100

            options = {'ip_ecn': 0}
            options_v6 = {'ipv6_ecn': 0}
            if test_ecn:
                ecn = random.randint(0, 3)
                options = {'ip_ecn': ecn}
                options_v6 = {'ipv6_ecn': ecn}

            # ECMP support, assume it is a string of comma seperated list of
            # addresses.
            check_ecmp = False
            working_nhs = list(set(nhs) - set(self.downed_endpoints))
            expect_success = self.expect_encap_success
            test_nhs = working_nhs
            packet_count = self.packet_count
            if not working_nhs:
                # Since there is no NH that is up for this destination,
                # we can't expect success here.
                expect_success = False
                test_nhs = nhs
                # Also reduce the packet count, since this script has to wait
                # 1 second per packet(1000 packets is 20 minutes).
                packet_count = 4
            returned_ip_addresses = {}
            for host_address in test_nhs:
                check_ecmp = True
                # This will ensure that every nh is used atleast once.
                Logger.info(
                    "Sending %s packets from port %s to %s",
                    packet_count,
                    str(ptf_port),
                    destination)
                for _ in range(packet_count):
                    if random_sport:
                        tcp_sport = get_incremental_value('tcp_sport')
                    else:
                        tcp_sport = VARS['tcp_sport']
                    if random_dport:
                        tcp_dport = get_incremental_value('tcp_dport')
                    else:
                        tcp_dport = VARS['tcp_dport']
                    if isinstance(ip_address(destination), IPv4Address) and \
                            isinstance(ip_address(ptf_addr), IPv4Address):
                        if random_src_ip:
                            ptf_addr = get_ip_address(
                                "v4", hostid=3, netid=170)
                        pkt_opts = {
                            "pktlen": pkt_len,
                            "eth_dst": self.dut_mac,
                            "eth_src": self.ptf_mac_addrs['eth%d' % ptf_port],
                            "ip_dst": destination,
                            "ip_src": ptf_addr,
                            "ip_id": 105,
                            "ip_ttl": 64,
                            "tcp_sport": tcp_sport,
                            "tcp_dport": tcp_dport}
                        pkt_opts.update(options)
                        pkt = simple_tcp_packet(**pkt_opts)
                        pkt_opts['ip_ttl'] = 63
                        pkt_opts['eth_src'] = self.dut_mac
                        exp_pkt = simple_tcp_packet(**pkt_opts)
                    elif isinstance(ip_address(destination), IPv6Address) and \
                            isinstance(ip_address(ptf_addr), IPv6Address):
                        if random_src_ip:
                            ptf_addr = get_ip_address(
                                "v6", hostid=4, netid=170)
                        pkt_opts = {
                            "pktlen": pkt_len,
                            "eth_dst": self.dut_mac,
                            "eth_src": self.ptf_mac_addrs['eth%d' % ptf_port],
                            "ipv6_dst": destination,
                            "ipv6_src": ptf_addr,
                            "ipv6_hlim": 64,
                            "tcp_sport": tcp_sport,
                            "tcp_dport": VARS['tcp_dport']}
                        pkt_opts.update(options_v6)
                        pkt = simple_tcpv6_packet(**pkt_opts)
                        pkt_opts['ipv6_hlim'] = 63
                        pkt_opts['eth_src'] = self.dut_mac
                        exp_pkt = simple_tcpv6_packet(**pkt_opts)
                    else:
                        raise RuntimeError(
                            "Invalid mapping of destination and PTF address.")
                    udp_sport = 1234    # it will be ignored in the test later.
                    udp_dport = self.vxlan_port
                    if isinstance(ip_address(host_address), IPv4Address):
                        encap_pkt = simple_vxlan_packet(
                            eth_src=self.dut_mac,
                            eth_dst=self.random_mac,
                            ip_id=0,
                            ip_ihl=5,
                            ip_src=self.loopback_ipv4,
                            ip_dst=host_address,
                            ip_ttl=128,
                            udp_sport=udp_sport,
                            udp_dport=udp_dport,
                            with_udp_chksum=False,
                            vxlan_vni=vni,
                            inner_frame=exp_pkt,
                            **options)
                        encap_pkt[scapy.IP].flags = 0x2
                    elif isinstance(ip_address(host_address), IPv6Address):
                        encap_pkt = simple_vxlanv6_packet(
                            eth_src=self.dut_mac,
                            eth_dst=self.random_mac,
                            ipv6_src=self.loopback_ipv6,
                            ipv6_dst=host_address,
                            udp_sport=udp_sport,
                            udp_dport=udp_dport,
                            with_udp_chksum=False,
                            vxlan_vni=vni,
                            inner_frame=exp_pkt,
                            **options_v6)
                    send_packet(self, ptf_port, pkt)

                # After we sent all packets, wait for the responses.
                if expect_success:
                    wait_timeout = 2
                    loop_timeout = max(packet_count * 5, 1000)   # milliseconds
                    start_time = datetime.now()
                    vxlan_count = 0
                    Logger.info("Loop time:out %s milliseconds", loop_timeout)
                    while (datetime.now() - start_time).total_seconds() *\
                            1000 < loop_timeout and vxlan_count < packet_count:
                        result = dp_poll(
                            self, timeout=wait_timeout
                        )
                        if isinstance(result, self.dataplane.PollSuccess):
                            if not isinstance(
                                result, self.dataplane.PollSuccess) or \
                                    result.port not in self.t2_ports or \
                                    "VXLAN" not in scapy.Ether(result.packet):
                                continue
                            else:
                                vxlan_count += 1
                                scapy_pkt = scapy.Ether(result.packet)
                                # Store every destination that was received.
                                if isinstance(
                                        ip_address(host_address), IPv6Address):
                                    dest_ip = scapy_pkt['IPv6'].dst
                                else:
                                    dest_ip = scapy_pkt['IP'].dst
                                try:
                                    returned_ip_addresses[dest_ip] = \
                                        returned_ip_addresses[dest_ip] + 1
                                except KeyError:
                                    returned_ip_addresses[dest_ip] = 1
                        else:
                            Logger.info("No packet came in %s seconds",
                                        wait_timeout)
                            break
                    if not vxlan_count or not returned_ip_addresses:
                        raise RuntimeError(
                            "Didnot get any reply for this destination:{}"
                            " Its active endpoints:{}".format(
                                destination, test_nhs))
                    Logger.info(
                        "Vxlan packets received:%s, loop time:%s "
                        "seconds", vxlan_count,
                        (datetime.now() - start_time).total_seconds())
                    Logger.info("received = {}".format(returned_ip_addresses))

                else:
                    check_ecmp = False
                    Logger.info("Verifying no packet")

                    masked_exp_pkt = Mask(encap_pkt)
                    masked_exp_pkt.set_ignore_extra_bytes()
                    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
                    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
                    if isinstance(ip_address(host_address), IPv4Address):
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IP,
                                                             "chksum")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "dst")
                    else:
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6,
                                                             "hlim")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6,
                                                             "dst")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.UDP,
                                                             "sport")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.UDP,
                                                             "chksum")

                    try:
                        verify_no_packet_any(
                            self,
                            masked_exp_pkt,
                            self.t2_ports)
                    except BaseException:
                        raise RuntimeError(
                            "Verify_no_packet failed. Args:ports:{} sent:{}\n,"
                            "expected:{}\n, encap_pkt:{}\n".format(
                                self.t2_ports,
                                repr(pkt),
                                repr(exp_pkt),
                                repr(encap_pkt)))

            # Verify ECMP:
            if check_ecmp:
                self.verify_all_addresses_used_equally(
                    nhs,
                    returned_ip_addresses,
                    packet_count,
                    self.downed_endpoints)

            pkt.load = '0' * 60 + str(len(self.packets))
            b = base64.b64encode(bytes(str(pkt), 'utf-8'))  # bytes
            base64_str = b.decode('utf-8')  # convert bytes to string
            self.packets.append((ptf_port, base64_str))

        finally:
            Logger.info("")


class VxLAN_in_VxLAN(VXLAN):
    def test_encap(
            self,
            ptf_port,
            vni,
            ptf_addr,
            destination,
            nhs,
            test_ecn=False,
            random_dport=True,
            random_sport=False,
            random_src_ip=False):
        '''
           Test the encapsulation of packets works correctly when the payload
           itself is a vxlan packet.
           1. Send a TCP packet to the DUT port.
           2. Verify that the DUT returns an encapsulated packet correctly.
           3. Optionally: Perform if the ECMP is working(all nexthops are used
           equally).
        '''
        pkt_len = 100
        pkt_opts = {
            "pktlen": pkt_len,
            "eth_dst": "aa:bb:cc:dd:ee:ff",
            "eth_src": "ff:ee:dd:cc:bb:aa",
            "ip_dst": "1.1.1.1",
            "ip_src": "2.2.2.2",
            "ip_id": 105,
            "ip_ttl": 64,
            "tcp_sport": 3000,
            "tcp_dport": 5000}
        innermost_frame = simple_tcp_packet(**pkt_opts)

        try:
            pkt_len = 100
            udp_dport = self.vxlan_port

            options = {'ip_ecn': 0}
            options_v6 = {'ipv6_ecn': 0}
            if test_ecn:
                ecn = random.randint(0, 3)
                options = {'ip_ecn': ecn}
                options_v6 = {'ipv6_ecn': ecn}

            # ECMP support, assume it is a string of comma seperated list of
            # addresses.
            check_ecmp = False
            working_nhs = list(set(nhs) - set(self.downed_endpoints))
            expect_success = self.expect_encap_success
            test_nhs = working_nhs
            packet_count = self.packet_count
            if not working_nhs:
                # Since there is no NH that is up for this destination,
                # we can't expect success here.
                expect_success = False
                test_nhs = nhs
                # Also reduce the packet count, since this script has to wait
                # 1 second per packet(1000 packets is 20 minutes).
                packet_count = 4
            returned_ip_addresses = {}
            for host_address in test_nhs:
                check_ecmp = True
                # This will ensure that every nh is used atleast once.
                Logger.info(
                    "Sending %s packets from port %s to %s",
                    packet_count,
                    str(ptf_port),
                    destination)
                for _ in range(packet_count):
                    udp_sport = get_incremental_value('udp_sport')
                    if isinstance(ip_address(destination), IPv4Address) and \
                            isinstance(ip_address(ptf_addr), IPv4Address):
                        if random_src_ip:
                            ptf_addr = get_ip_address(
                                "v4", hostid=3, netid=170)
                        pkt_opts = {
                            'eth_src': self.random_mac,
                            'eth_dst': self.dut_mac,
                            'ip_id': 0,
                            'ip_ihl': 5,
                            'ip_src': ptf_addr,
                            'ip_dst': destination,
                            'ip_ttl': 63,
                            'udp_sport': udp_sport,
                            'udp_dport': udp_dport,
                            'with_udp_chksum': False,
                            'vxlan_vni': vni,
                            'inner_frame': innermost_frame}
                        pkt_opts.update(**options)
                        pkt = simple_vxlan_packet(**pkt_opts)

                        pkt_opts['ip_ttl'] = 62
                        pkt_opts['eth_dst'] = self.random_mac
                        pkt_opts['eth_src'] = self.dut_mac
                        exp_pkt = simple_vxlan_packet(**pkt_opts)
                    elif isinstance(ip_address(destination), IPv6Address) and \
                            isinstance(ip_address(ptf_addr), IPv6Address):
                        if random_src_ip:
                            ptf_addr = get_ip_address(
                                "v6", hostid=4, netid=170)
                        pkt_opts = {
                            "pktlen": pkt_len,
                            "eth_dst": self.dut_mac,
                            "eth_src": self.ptf_mac_addrs['eth%d' % ptf_port],
                            "ipv6_dst": destination,
                            "ipv6_src": ptf_addr,
                            "ipv6_hlim": 64,
                            "udp_sport": udp_sport,
                            "udp_dport": udp_dport,
                            'inner_frame': innermost_frame}
                        pkt_opts.update(**options_v6)

                        pkt = simple_vxlanv6_packet(**pkt_opts)
                        pkt_opts.update(options_v6)

                        pkt_opts['eth_dst'] = self.random_mac
                        pkt_opts['eth_src'] = self.dut_mac
                        pkt_opts['ipv6_hlim'] = 63
                        exp_pkt = simple_vxlanv6_packet(**pkt_opts)
                    else:
                        raise RuntimeError(
                            "Invalid mapping of destination and PTF address.")
                    udp_sport = 1234    # it will be ignored in the test later.
                    udp_dport = self.vxlan_port
                    if isinstance(ip_address(host_address), IPv4Address):
                        encap_pkt = simple_vxlan_packet(
                            eth_src=self.dut_mac,
                            eth_dst=self.random_mac,
                            ip_id=0,
                            ip_ihl=5,
                            ip_src=self.loopback_ipv4,
                            ip_dst=host_address,
                            ip_ttl=63,
                            udp_sport=udp_sport,
                            udp_dport=udp_dport,
                            with_udp_chksum=False,
                            vxlan_vni=vni,
                            inner_frame=exp_pkt,
                            **options)
                        encap_pkt[scapy.IP].flags = 0x2
                    elif isinstance(ip_address(host_address), IPv6Address):
                        encap_pkt = simple_vxlanv6_packet(
                            eth_src=self.dut_mac,
                            eth_dst=self.random_mac,
                            ipv6_src=self.loopback_ipv6,
                            ipv6_dst=host_address,
                            udp_sport=udp_sport,
                            udp_dport=udp_dport,
                            with_udp_chksum=False,
                            vxlan_vni=vni,
                            inner_frame=exp_pkt,
                            **options_v6)
                    send_packet(self, ptf_port, pkt)

                # After we sent all packets, wait for the responses.
                if expect_success:
                    wait_timeout = 2
                    loop_timeout = max(packet_count * 5, 1000)   # milliseconds
                    start_time = datetime.now()
                    vxlan_count = 0
                    Logger.info("Loop time:out %s milliseconds", loop_timeout)
                    while (datetime.now() - start_time).total_seconds() *\
                            1000 < loop_timeout and vxlan_count < packet_count:
                        result = dp_poll(
                            self, timeout=wait_timeout
                        )
                        if isinstance(result, self.dataplane.PollSuccess):
                            if not isinstance(
                                result, self.dataplane.PollSuccess) or \
                                    result.port not in self.t2_ports or \
                                    "VXLAN" not in scapy.Ether(result.packet):
                                continue
                            else:
                                vxlan_count += 1
                                scapy_pkt = scapy.Ether(result.packet)
                                # Store every destination that was received.
                                if isinstance(
                                        ip_address(host_address), IPv6Address):
                                    dest_ip = scapy_pkt['IPv6'].dst
                                else:
                                    dest_ip = scapy_pkt['IP'].dst
                                try:
                                    returned_ip_addresses[dest_ip] = \
                                        returned_ip_addresses[dest_ip] + 1
                                except KeyError:
                                    returned_ip_addresses[dest_ip] = 1
                        else:
                            Logger.info("No packet came in %s seconds",
                                        wait_timeout)
                            break
                    if not vxlan_count or not returned_ip_addresses:
                        raise RuntimeError(
                            "Didnot get any reply for this destination:{}"
                            " Its active endpoints:{}".format(
                                destination, test_nhs))
                    Logger.info(
                        "Vxlan packets received:%s, loop time:%s "
                        "seconds", vxlan_count,
                        (datetime.now() - start_time).total_seconds())
                    Logger.info("received = {}".format(returned_ip_addresses))

                else:
                    check_ecmp = False
                    Logger.info("Verifying no packet")

                    masked_exp_pkt = Mask(encap_pkt)
                    masked_exp_pkt.set_ignore_extra_bytes()
                    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
                    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
                    if isinstance(ip_address(host_address), IPv4Address):
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IP,
                                                             "chksum")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "dst")
                    else:
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6,
                                                             "hlim")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6,
                                                             "chksum")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6,
                                                             "dst")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.UDP,
                                                             "sport")
                        masked_exp_pkt.set_do_not_care_scapy(scapy.UDP,
                                                             "chksum")

                    try:
                        verify_no_packet_any(
                            self,
                            masked_exp_pkt,
                            self.t2_ports)
                    except BaseException:
                        raise RuntimeError(
                            "Verify_no_packet failed. Args:ports:{} sent:{}\n,"
                            "expected:{}\n, encap_pkt:{}\n".format(
                                self.t2_ports,
                                repr(pkt),
                                repr(exp_pkt),
                                repr(encap_pkt)))

            # Verify ECMP:
            if check_ecmp:
                self.verify_all_addresses_used_equally(
                    nhs,
                    returned_ip_addresses,
                    packet_count,
                    self.downed_endpoints)

            pkt.load = '0' * 60 + str(len(self.packets))
            b = base64.b64encode(bytes(str(pkt), 'utf-8'))  # bytes
            base64_str = b.decode('utf-8')  # convert bytes to string
            self.packets.append((ptf_port, base64_str))

        finally:
            Logger.info("")
