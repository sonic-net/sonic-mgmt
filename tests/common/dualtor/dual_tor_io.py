import datetime
import threading
import time
import socket
import random
import struct
import ipaddress
import logging
import json
import scapy.all as scapyall
import ptf.testutils as testutils
from operator import itemgetter
from itertools import groupby

from tests.common.dualtor.dual_tor_common import CableType
from tests.common.utilities import InterruptableThread
from natsort import natsorted
from collections import defaultdict

TCP_DST_PORT = 5000
SOCKET_RECV_BUFFER_SIZE = 10 * 1024 * 1024
PTFRUNNER_QLEN = 1000
VLAN_INDEX = 0
VLAN_HOSTS = 100
VLAN_BASE_MAC_PATTERN = "72060001{:04}"
LAG_BASE_MAC_PATTERN = '5c010203{:04}'

logger = logging.getLogger(__name__)


class DualTorIO:
    """Class to conduct IO over ports in `active-standby` mode."""

    def __init__(self, activehost, standbyhost, ptfhost, ptfadapter, tbinfo,
                io_ready, tor_vlan_port=None, send_interval=0.01, cable_type=CableType.active_standby):
        self.tor_pc_intf = None
        self.tor_vlan_intf = tor_vlan_port
        self.duthost = activehost
        self.ptfadapter = ptfadapter
        self.ptfhost = ptfhost
        self.tbinfo = tbinfo
        self.io_ready_event = io_ready
        self.dut_mac = self.duthost.facts["router_mac"]
        self.active_mac = self.dut_mac
        self.standby_mac = standbyhost.facts["router_mac"]

        self.cable_type = cable_type

        self.dataplane = self.ptfadapter.dataplane
        self.dataplane.flush()
        self.test_results = dict()
        self.stop_early = False
        self.ptf_sniffer = "/root/dual_tor_sniffer.py"

        # Calculate valid range for T1 src/dst addresses
        mg_facts = self.duthost.get_extended_minigraph_facts(self.tbinfo)
        prefix_len = mg_facts['minigraph_vlan_interfaces'][VLAN_INDEX]['prefixlen'] - 3
        test_network = ipaddress.ip_address(
            mg_facts['minigraph_vlan_interfaces'][VLAN_INDEX]['addr']) +\
            (1 << (32 - prefix_len))
        self.default_ip_range = str(ipaddress.ip_interface(unicode(
            str(test_network) + '/{0}'.format(prefix_len))).network)
        self.src_addr, mask = self.default_ip_range.split('/')
        self.n_hosts = 2**(32 - int(mask))

        self.tor_to_ptf_intf_map = mg_facts['minigraph_ptf_indices']

        portchannel_info = mg_facts['minigraph_portchannels']
        self.tor_pc_intfs = list()
        for pc in portchannel_info.values():
            for member in pc['members']:
                self.tor_pc_intfs.append(member)

        self.vlan_interfaces = mg_facts["minigraph_vlans"].values()[VLAN_INDEX]["members"]

        config_facts = self.duthost.get_running_config_facts()
        vlan_table = config_facts['VLAN']
        vlan_name = list(vlan_table.keys())[0]
        self.vlan_mac = vlan_table[vlan_name]['mac']
        self.mux_cable_table = config_facts['MUX_CABLE']

        self.test_interfaces = self._select_test_interfaces()

        self.ptf_intf_to_server_ip_map = self._generate_vlan_servers()
        self.__configure_arp_responder()

        logger.info("VLAN interfaces: {}".format(str(self.vlan_interfaces)))
        logger.info("PORTCHANNEL interfaces: {}".format(str(self.tor_pc_intfs)))
        logger.info("Selected testing interfaces: %s", self.test_interfaces)

        self.time_to_listen = 300.0
        self.sniff_time_incr = 0
        # Inter-packet send-interval (minimum interval 3.5ms)
        if send_interval < 0.0035:
            if send_interval is not None:
                logger.warn("Minimum packet send-interval is .0035s. \
                    Ignoring user-provided interval {}".format(send_interval))
            self.send_interval = 0.0035
        else:
            self.send_interval = send_interval
        # How many packets to be sent by sender thread
        logger.info("Using send interval {}".format(self.send_interval))
        self.packets_to_send = min(int(self.time_to_listen /
            (self.send_interval * 2)), 45000)
        self.packets_sent_per_server = dict()

        if self.tor_vlan_intf:
            self.packets_per_server = self.packets_to_send
        else:
            self.packets_per_server = self.packets_to_send // len(self.test_interfaces)

        self.all_packets = []

    def _generate_vlan_servers(self):
        """
        Create mapping of server IPs to PTF interfaces
        """
        server_ip_list = []

        for _, config in natsorted(self.mux_cable_table.items()):
            server_ip_list.append(str(config['server_ipv4'].split("/")[0]))
        logger.info("ALL server address:\n {}".format(server_ip_list))

        ptf_to_server_map = dict()
        for intf in natsorted(self.test_interfaces):
            ptf_intf = self.tor_to_ptf_intf_map[intf]
            server_ip = str(self.mux_cable_table[intf]['server_ipv4'].split("/")[0])
            ptf_to_server_map[ptf_intf] = [server_ip]

        logger.debug('VLAN intf to server IP map: {}'.format(json.dumps(ptf_to_server_map, indent=4, sort_keys=True)))
        return ptf_to_server_map

    def _select_test_interfaces(self):
        """Select DUT interfaces that is in `active-standby` cable type."""
        test_interfaces = []
        for port, port_config in natsorted(self.mux_cable_table.items()):
            if port_config.get("cable_type", CableType.active_standby) == self.cable_type:
                test_interfaces.append(port)
        return test_interfaces

    def __configure_arp_responder(self):
        """
        @summary: Generate ARP responder configuration using vlan_host_map.
        Copy this configuration to PTF and restart arp_responder
        """
        arp_responder_conf = {}
        for intf, ip in self.ptf_intf_to_server_ip_map.items():
            arp_responder_conf['eth{}'.format(intf)] = ip
        with open("/tmp/from_t1.json", "w") as fp:
            json.dump(arp_responder_conf, fp, indent=4, sort_keys=True)
        self.ptfhost.copy(src="/tmp/from_t1.json", dest="/tmp/from_t1.json")
        self.ptfhost.shell("supervisorctl reread && supervisorctl update")
        self.ptfhost.shell("supervisorctl restart arp_responder")
        logger.info("arp_responder restarted")

    def start_io_test(self, traffic_generator=None):
        """
        @summary: The entry point to start the TOR dataplane I/O test.
        Args:
            traffic_generator (function): A callback function to decide the
                traffic direction (T1 to server / server to T1)
                Allowed values: self.generate_from_t1_to_server or
                self.generate_from_server_to_t1
        """
        # Check in a conditional for better readability
        self.traffic_generator = traffic_generator
        if self.traffic_generator == self.generate_from_t1_to_server:
            self.generate_from_t1_to_server()
        elif self.traffic_generator == self.generate_from_server_to_t1:
            self.generate_from_server_to_t1()
        else:
            logger.error("Traffic generator not provided or invalid")
            return
        # start and later join the sender and sniffer threads
        self.send_and_sniff(sender=self.traffic_sender_thread,
            sniffer=self.traffic_sniffer_thread)

    def generate_from_t1_to_server(self):
        """
        @summary: Generate (not send) the packets to be sent from T1 to server
        """
        logger.info("Generating T1 to server packets")
        eth_dst = self.dut_mac
        ip_ttl = 255

        if self.tor_pc_intf and self.tor_pc_intf in self.tor_pc_intfs:
            # If a source portchannel intf is specified,
            # get the corresponding PTF info
            ptf_t1_src_intf = self.tor_to_ptf_intf_map[self.tor_pc_intf]
            eth_src = self.ptfadapter.dataplane.get_mac(0, ptf_t1_src_intf)
            random_source = False
        else:
            # If no source portchannel specified, randomly choose one
            # during packet generation
            logger.info('Using random T1 source intf')
            ptf_t1_src_intf = None
            eth_src = None
            random_source = True

        if self.tor_vlan_intf:
            # If destination VLAN intf is specified,
            # use only the connected server
            ptf_port = self.tor_to_ptf_intf_map[self.tor_vlan_intf]
            server_ip_list = [
                self.ptf_intf_to_server_ip_map[ptf_port]
            ]
        else:
            # Otherwise send packets to all servers
            server_ip_list = self.ptf_intf_to_server_ip_map.values()

        logger.info("-"*20 + "T1 to server packet" + "-"*20)
        logger.info("PTF source intf: {}"
                    .format('random' if random_source else ptf_t1_src_intf)
                   )
        logger.info("Ethernet address: dst: {} src: {}"
                    .format(eth_dst, 'random' if random_source else eth_src)
                   )
        logger.info("IP address: dst: {} src: random"
                    .format('all' if len(server_ip_list) > 1
                                  else server_ip_list[0]
                           )
                   )
        logger.info("TCP port: dst: {}".format(TCP_DST_PORT))
        logger.info("DUT mac: {}".format(self.dut_mac))
        logger.info("VLAN mac: {}".format(self.vlan_mac))
        logger.info("-"*50)

        self.packets_list = []

        # Create packet #1 for each server and append to the list,
        # then packet #2 for each server, etc.
        # This way, when sending packets we continuously send for all servers
        # instead of sending all packets for server #1, then all packets for
        # server #2, etc.
        tcp_tx_packet_orig = testutils.simple_tcp_packet(
            eth_dst=eth_dst,
            eth_src=eth_src,
            ip_ttl=ip_ttl,
            tcp_dport=TCP_DST_PORT
        )
        tcp_tx_packet_orig = scapyall.Ether(str(tcp_tx_packet_orig))
        payload_suffix = "X" * 60
        for i in range(self.packets_per_server):
            for server_ip in server_ip_list:
                packet = tcp_tx_packet_orig.copy()
                if random_source:
                    tor_pc_src_intf = random.choice(
                        self.tor_pc_intfs
                    )
                    ptf_t1_src_intf = self.tor_to_ptf_intf_map[tor_pc_src_intf]
                    eth_src = self.ptfadapter.dataplane.get_mac(
                        0, ptf_t1_src_intf
                    )
                packet[scapyall.Ether].src = eth_src
                packet[scapyall.IP].src = self.random_host_ip()
                packet[scapyall.IP].dst = server_ip
                payload = str(i) + payload_suffix
                packet.load = payload
                packet[scapyall.TCP].chksum = None
                packet[scapyall.IP].chksum = None
                self.packets_list.append((ptf_t1_src_intf, str(packet)))

        self.sent_pkt_dst_mac = self.dut_mac
        self.received_pkt_src_mac = [self.vlan_mac]

    def generate_from_server_to_t1(self):
        """
        @summary: Generate (not send) the packets to be sent from server to T1
        """
        logger.info("Generating server to T1 packets")
        if self.tor_vlan_intf:
            vlan_src_intfs = [self.tor_vlan_intf]
            # If destination VLAN intf is specified,
            # use only the connected server
        else:
            # Otherwise send packets to all servers
            vlan_src_intfs = self.test_interfaces

        ptf_intf_to_mac_map = {}

        for ptf_intf in self.ptf_intf_to_server_ip_map.keys():
            ptf_intf_to_mac_map[ptf_intf] = self.ptfadapter.dataplane.get_mac(0, ptf_intf)

        logger.info("-"*20 + "Server to T1 packet" + "-"*20)
        if self.tor_vlan_intf is None:
            src_mac = 'random'
            src_ip = 'random'
        else:
            ptf_port = self.tor_to_ptf_intf_map[self.tor_vlan_intf]
            src_mac = ptf_intf_to_mac_map[ptf_port]
            src_ip = self.ptf_intf_to_server_ip_map[ptf_port]
        logger.info(
            "Ethernet address: dst: {} src: {}".format(
                self.vlan_mac, src_mac
            )
        )
        logger.info(
            "IP address: dst: {} src: {}".format(
                'random', src_ip
            )
        )
        logger.info("TCP port: dst: {} src: 1234".format(TCP_DST_PORT))
        logger.info("Active ToR MAC: {}, Standby ToR MAC: {}".format(self.active_mac,
            self.standby_mac))
        logger.info("VLAN MAC: {}".format(self.vlan_mac))
        logger.info("-"*50)

        self.packets_list = []

        # Create packet #1 for each server and append to the list,
        # then packet #2 for each server, etc.
        # This way, when sending packets we continuously send for all servers
        # instead of sending all packets for server #1, then all packets for
        # server #2, etc.
        tcp_tx_packet_orig = testutils.simple_tcp_packet(
            eth_dst=self.vlan_mac,
            tcp_dport=TCP_DST_PORT
        )
        tcp_tx_packet_orig = scapyall.Ether(str(tcp_tx_packet_orig))
        payload_suffix = "X" * 60

        # use the same dst ip to ensure that packets from one server are always forwarded
        # to the same active ToR by the server NiC
        dst_ips = {vlan_intf: self.random_host_ip() for vlan_intf in vlan_src_intfs}
        for i in range(self.packets_per_server):
            for vlan_intf in vlan_src_intfs:
                ptf_src_intf = self.tor_to_ptf_intf_map[vlan_intf]
                server_ip = self.ptf_intf_to_server_ip_map[ptf_src_intf]
                eth_src = ptf_intf_to_mac_map[ptf_src_intf]
                payload = str(i) + payload_suffix
                packet = tcp_tx_packet_orig.copy()
                packet[scapyall.Ether].src = eth_src
                packet[scapyall.IP].src = server_ip
                packet[scapyall.IP].dst = dst_ips[vlan_intf] if self.cable_type == CableType.active_active else self.random_host_ip()
                packet.load = payload
                packet[scapyall.TCP].chksum = None
                packet[scapyall.IP].chksum = None
                self.packets_list.append((ptf_src_intf, str(packet)))
        self.sent_pkt_dst_mac = self.vlan_mac
        self.received_pkt_src_mac = [self.active_mac, self.standby_mac]

    def random_host_ip(self):
        """
        @summary: Helper method to find a random host IP for generating a random src/dst IP address
        Returns:
            host_ip (str): Random IP address
        """
        host_number = random.randint(2, self.n_hosts - 2)
        if host_number > (self.n_hosts - 2):
            raise Exception("host number {} is greater than number of hosts {}\
                in the network {}".format(
                    host_number, self.n_hosts - 2, self.default_ip_range))
        src_addr_n = struct.unpack(">I", socket.inet_aton(self.src_addr))[0]
        net_addr_n = src_addr_n & (2**32 - self.n_hosts)
        host_addr_n = net_addr_n + host_number
        host_ip = socket.inet_ntoa(struct.pack(">I", host_addr_n))

        return host_ip


    def send_and_sniff(self, sender, sniffer):
        """
        @summary: This method starts and joins two background threads in parallel: sender and sniffer
        """
        self.sender_thr = InterruptableThread(target=sender)
        self.sniff_thr = InterruptableThread(target=sniffer)
        self.sniffer_started = threading.Event()
        self.sniff_thr.set_error_handler(lambda *args, **kargs: self.sniffer_started.set())
        self.sender_thr.set_error_handler(lambda *args, **kargs: self.io_ready_event.set())
        self.sniff_thr.start()
        self.sender_thr.start()
        self.sender_thr.join()
        self.sniff_thr.join()


    def traffic_sender_thread(self):
        """
        @summary: Generalized Sender thread (to be used for traffic in both directions)
        Waits for a signal from the `traffic_sniffer_thread` before actually starting.
        This is to make sure that that packets are not sent before they are ready to be captured.
        """
        logger.info("Sender waiting to send {} packets".format(len(self.packets_list)))

        self.sniffer_started.wait(timeout=10)
        sender_start = datetime.datetime.now()
        logger.info("Sender started at {}".format(str(sender_start)))

        # Signal data_plane_utils that sender and sniffer threads have begun
        self.io_ready_event.set()

        sent_packets_count = 0
        for entry in self.packets_list:
            _, packet = entry
            server_addr = self.get_server_address(scapyall.Ether(str(packet)))
            time.sleep(self.send_interval)
            # the stop_early flag can be set to True by data_plane_utils to stop prematurely
            if self.stop_early:
                break
            testutils.send_packet(self.ptfadapter, *entry)
            self.packets_sent_per_server[server_addr] =\
                self.packets_sent_per_server.get(server_addr, 0) + 1
            sent_packets_count = sent_packets_count + 1

        time.sleep(10)
        self.stop_sniffer_early()
        logger.info("Stop the sender thread gracefully after sending {} packets"\
            .format(sent_packets_count))

        logger.info("Sender finished running after {}".format(
            str(datetime.datetime.now() - sender_start)))


    def stop_sniffer_early(self):
        # Try to stop sniffer earlier by sending SIGINT signal to the sniffer process
        # Python installs a small number of signal handlers by default.
        # SIGINT is translated into a KeyboardInterrupt exception.
        logger.info("Stop the sniffer thread gracefully: sending SIGINT to ptf process")
        self.ptfhost.command("pkill -SIGINT -f {}".format(self.ptf_sniffer),\
            module_ignore_errors=True)


    def get_server_address(self, packet):
        if self.traffic_generator == self.generate_from_t1_to_server:
            server_addr = packet[scapyall.IP].dst
        elif self.traffic_generator == self.generate_from_server_to_t1:
            server_addr = packet[scapyall.IP].src
        return server_addr


    def traffic_sniffer_thread(self):
        """
        @summary: Generalized sniffer thread (to be used for traffic in both directions)
        Starts `scapy_sniff` thread, and waits for its setup before
        signalling the sender thread to start
        """
        wait = self.time_to_listen + self.sniff_time_incr
        sniffer_start = datetime.datetime.now()
        logger.info("Sniffer started at {}".format(str(sniffer_start)))
        sniff_filter = "tcp and tcp dst port {} and tcp src port 1234 and not icmp".\
            format(TCP_DST_PORT)

        # We run a PTF script on PTF to sniff traffic. The PTF script calls
        # scapy.sniff which by default capture the backplane interface for
        # announcing routes from PTF to VMs. On VMs, the PTF backplane is the
        # next hop for the annoucned routes. So, packets sent by DUT to VMs
        # are forwarded to the PTF backplane interface as well. Then on PTF,
        # the packets sent by DUT to VMs can be captured on both the PTF interfaces
        # tapped to VMs and on the backplane interface. This will result in
        # packet duplication and fail the test. Below change is to add capture
        # filter to filter out all the packets destined to the PTF backplane interface.
        output = self.ptfhost.shell('cat /sys/class/net/backplane/address',\
            module_ignore_errors=True)
        if not output['failed']:
            ptf_bp_mac = output['stdout']
            sniff_filter = '({}) and (not ether dst {})'.format(sniff_filter, ptf_bp_mac)

        scapy_sniffer = InterruptableThread(
            target=self.scapy_sniff,
            kwargs={
                'sniff_timeout': wait,
                'sniff_filter': sniff_filter
            }
        )
        scapy_sniffer.start()
        time.sleep(10)               # Let the scapy sniff initialize completely.
        self.sniffer_started.set()  # Unblock waiter for the send_in_background.
        scapy_sniffer.join()
        logger.info("Sniffer finished running after {}".\
            format(str(datetime.datetime.now() - sniffer_start)))
        self.sniffer_started.clear()


    def scapy_sniff(self, sniff_timeout=180, sniff_filter=''):
        """
        @summary: PTF runner -  runs a sniffer in PTF container.
        Running sniffer in sonic-mgmt container has missing SOCKET problem
        and permission issues (scapy and tcpdump require root user)
        The remote function listens on all intfs. Once found, all packets
        are dumped to local pcap file, and all packets are saved to
        self.all_packets as scapy type.

        Args:
            sniff_timeout (int): Duration in seconds to sniff the traffic
            sniff_filter (str): Filter that Scapy will use to collect only relevant packets
        """
        capture_pcap = '/tmp/capture.pcap'
        capture_log = '/tmp/capture.log'
        self.ptfhost.copy(src='scripts/dual_tor_sniffer.py', dest=self.ptf_sniffer)
        self.ptfhost.command(
            'python {} -f "{}" -p {} -l {} -t {}'.format(
                self.ptf_sniffer, sniff_filter, capture_pcap, capture_log, sniff_timeout
            )
        )
        logger.info('Fetching pcap file from ptf')
        self.ptfhost.fetch(src=capture_pcap, dest='/tmp/', flat=True, fail_on_missing=False)
        self.all_packets = scapyall.rdpcap(capture_pcap)
        logger.info("Number of all packets captured: {}".format(len(self.all_packets)))


    def get_test_results(self):
        return self.test_results

    def examine_flow(self):
        """
        @summary: This method examines packets collected by sniffer thread
            The method compares TCP payloads of the packets one by one (assuming all
            payloads are consecutive integers), and the losses if found - are treated
            as disruptions in Dataplane forwarding. All disruptions are saved to
            self.lost_packets dictionary, in format:
            disrupt_start_id = (missing_packets_count, disrupt_time,
            disrupt_start_timestamp, disrupt_stop_timestamp)
        """
        examine_start = datetime.datetime.now()
        logger.info("Packet flow examine started {}".format(str(examine_start)))

        if not self.all_packets:
            logger.error("self.all_packets not defined.")
            return None

        # Filter out packets:
        filtered_packets = [ pkt for pkt in self.all_packets if
            scapyall.TCP in pkt and
            not scapyall.ICMP in pkt and
            pkt[scapyall.TCP].sport == 1234 and
            pkt[scapyall.TCP].dport == TCP_DST_PORT and
            self.check_tcp_payload(pkt) and
            (
                pkt[scapyall.Ether].dst == self.sent_pkt_dst_mac or
                pkt[scapyall.Ether].src in self.received_pkt_src_mac
            )
        ]
        logger.info("Number of filtered packets captured: {}".format(len(filtered_packets)))
        if not filtered_packets or len(filtered_packets) == 0:
            logger.error("Sniffer failed to capture any traffic")
            return

        server_to_packet_map = defaultdict(list)

        # Split packets into separate lists based on server IP
        for packet in filtered_packets:
            server_addr = self.get_server_address(packet)
            server_to_packet_map[server_addr].append(packet)

        # For each server's packet list, sort by payload then timestamp
        # (in case of duplicates)
        for server in server_to_packet_map.keys():
            server_to_packet_map[server].sort(
                key=lambda packet: (int(str(packet[scapyall.TCP].payload)
                                        .replace('X','')),
                                    packet.time)
            )

        logger.info("Measuring traffic disruptions...")
        for server_ip, packet_list in server_to_packet_map.items():
            filename = '/tmp/capture_filtered_{}.pcap'.format(server_ip)
            scapyall.wrpcap(filename, packet_list)
            logger.info("Filtered pcap dumped to {}".format(filename))

        self.test_results = {}

        for server_ip in natsorted(server_to_packet_map.keys()):
            result = self.examine_each_packet(server_ip, server_to_packet_map[server_ip])
            logger.info("Server {} results:\n{}"
                        .format(server_ip, json.dumps(result, indent=4)))
            self.test_results[server_ip] = result


    def examine_each_packet(self, server_ip, packets):
        num_sent_packets = 0
        received_packet_list = list()
        duplicate_packet_list = list()
        disruption_ranges = list()
        disruption_before_traffic = False
        disruption_after_traffic = False
        duplicate_ranges = []

        for packet in packets:
            if packet[scapyall.Ether].dst == self.sent_pkt_dst_mac:
                # This is a sent packet
                num_sent_packets += 1
                continue
            if packet[scapyall.Ether].src in self.received_pkt_src_mac:
                # This is a received packet.
                # scapy 2.4.5 will use Decimal to calulcate time, but json.dumps
                # can't recognize Decimal, transform to float here
                curr_time = float(packet.time)
                curr_payload = int(str(packet[scapyall.TCP].payload).replace('X',''))

                # Look back at the previous received packet to check for gaps/duplicates
                # Only if we've already received some packets
                if len(received_packet_list) > 0:
                    prev_payload, prev_time = received_packet_list[-1]

                    if prev_payload == curr_payload:
                        # Duplicate packet detected, increment the counter
                        duplicate_packet_list.append((curr_payload, curr_time))
                    if prev_payload + 1 < curr_payload:
                        # Non-sequential packets indicate a disruption
                        disruption_dict = {
                            'start_time': prev_time,
                            'end_time': curr_time,
                            'start_id': prev_payload,
                            'end_id': curr_payload
                        }
                        disruption_ranges.append(disruption_dict)

                # Save packets as (payload_id, timestamp) tuples
                # for easier timing calculations later
                received_packet_list.append((curr_payload, curr_time))

        if len(received_packet_list) == 0:
            logger.error("Sniffer failed to filter any traffic from DUT")
        else:
            # Find ranges of consecutive packets that have been duplicated
            # All packets within the same consecutive range will have the same
            # difference between the packet index and the sequence number
            for _, grouper in groupby(enumerate(duplicate_packet_list), lambda (i,x): i - x[0]):
                group = map(itemgetter(1), grouper)
                duplicate_start, duplicate_end = group[0], group[-1]
                duplicate_dict = {
                    'start_time': duplicate_start[1],
                    'end_time': duplicate_end[1],
                    'start_id': duplicate_start[0],
                    'end_id': duplicate_end[0]
                }
                duplicate_ranges.append(duplicate_dict)

            # If the first packet we received is not #0, some disruption started
            # before traffic started. Store the id of the first received packet
            if received_packet_list[0][0] != 0:
                disruption_before_traffic = received_packet_list[0][0]
            # If the last packet we received does not match the number of packets
            # sent, some disruption continued after the traffic finished.
            # Store the id of the last received packet
            if received_packet_list[-1][0] != self.packets_sent_per_server.get(server_ip) - 1:
                disruption_after_traffic = received_packet_list[-1][0]

        result = {
            'sent_packets': num_sent_packets,
            'received_packets': len(received_packet_list),
            'disruption_before_traffic': disruption_before_traffic,
            'disruption_after_traffic': disruption_after_traffic,
            'duplications': duplicate_ranges,
            'disruptions': disruption_ranges
        }

        if num_sent_packets < self.packets_sent_per_server.get(server_ip):
            server_addr = self.get_server_address(packet)
            logger.error('Not all sent packets were captured. '
                         'Something went wrong!')
            logger.error('Dumping server {} results and continuing:\n{}'
                         .format(server_addr, json.dumps(result, indent=4)))

        return result

    def check_tcp_payload(self, packet):
        """
        @summary: Helper method

        Returns: Bool: True if a packet is not corrupted and has a valid TCP
            sequential TCP Payload
        """
        try:
            int(str(packet[scapyall.TCP].payload).replace('X','')) in range(
                self.packets_to_send)
            return True
        except Exception as err:
            return False

