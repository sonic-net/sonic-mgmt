import datetime
import threading
import time
import socket
import random
import struct
import ipaddress
import logging
import json
from collections import defaultdict

import scapy.all as scapyall
import ptf.testutils as testutils
from tests.ptf_runner import ptf_runner

TCP_DST_PORT = 5000
SOCKET_RECV_BUFFER_SIZE = 10 * 1024 * 1024
PTFRUNNER_QLEN = 1000
VLAN_INDEX = 0
VLAN_HOSTS = 100
VLAN_BASE_MAC_PATTERN = "72060001{:04}"
LAG_BASE_MAC_PATTERN = '5c010203{:04}'

logger = logging.getLogger(__name__)


class DualTorIO:
    def __init__(self, activehost, standbyhost, ptfhost, ptfadapter, tbinfo,
                io_ready, tor_vlan_port=None):
        self.tor_port = None
        self.tor_vlan_port = tor_vlan_port
        self.duthost = activehost
        self.ptfadapter = ptfadapter
        self.ptfhost = ptfhost
        self.tbinfo = tbinfo
        self.io_ready_event = io_ready
        self.dut_mac = self.duthost.facts["router_mac"]
        self.active_mac = self.dut_mac
        if standbyhost:
            self.standby_mac = standbyhost.facts["router_mac"]

        self.mux_cable_table = self.duthost.get_running_config_facts()['MUX_CABLE']
        if tor_vlan_port:
            if tor_vlan_port in self.mux_cable_table:
                self.downstream_dst_ip = self.mux_cable_table[tor_vlan_port]['server_ipv4'].split("/")[0]
            else:
                logger.error("Port {} not found in MUX cable table".format(tor_vlan_port))
        else:
            self.downstream_dst_ip = None

        self.time_to_listen = 180.0
        self.sniff_time_incr = 60
        self.send_interval = 0.0035 # Inter-packet interval
        # How many packets to be sent by sender thread
        self.packets_to_send = min(int(self.time_to_listen /
            (self.send_interval + 0.0015)), 45000)

        self.dataplane = self.ptfadapter.dataplane
        self.dataplane.flush()
        self.total_disrupt_time = None
        self.disrupts_count = None
        self.total_disrupt_packets = None
        self.max_lost_id = None
        self.max_disrupt_time = None
        self.received_counter = int()
        self.lost_packets = dict()
        self.duplicated_packets_count = int()
        self.total_lost_packets = None
        # This list will contain all unique Payload ID, to filter out received floods.
        self.unique_id = set()

        mg_facts = self.duthost.get_extended_minigraph_facts(self.tbinfo)
        prefix_len = mg_facts['minigraph_vlan_interfaces'][VLAN_INDEX]['prefixlen'] - 3
        test_network = ipaddress.ip_address(
            mg_facts['minigraph_vlan_interfaces'][VLAN_INDEX]['addr']) +\
            (1 << (32 - prefix_len))
        self.default_ip_range = str(ipaddress.ip_interface(unicode(
            str(test_network) + '/{0}'.format(prefix_len))).network)
        self.src_addr, mask = self.default_ip_range.split('/')
        self.n_hosts = 2**(32 - int(mask))
        self.port_indices = mg_facts['minigraph_ptf_indices']
        portchannel_info = mg_facts['minigraph_portchannels']
        self.port_channel_ports = dict()
        for pc in portchannel_info.values():
            for member in pc['members']:
                self.port_channel_ports.update({member: self.port_indices[member]})

        self.server_ip_list = list()
        self.vlan_interfaces = mg_facts["minigraph_vlan_interfaces"][VLAN_INDEX]
        self.vlan_network = self.vlan_interfaces["subnet"]
        self.vlan_ports = dict()
        for ifname in mg_facts["minigraph_vlans"].values()[VLAN_INDEX]["members"]:
            self.vlan_ports.update({ifname: self.port_indices[ifname]})
        self.vlan_host_map = self._generate_vlan_servers()
        self.__configure_arp_responder()

        vlan_table = self.duthost.get_running_config_facts()['VLAN']
        vlan_name = list(vlan_table.keys())[0]
        self.vlan_mac = vlan_table[vlan_name]['mac']

        logger.info("VLAN ports: {}".format(str(self.vlan_ports.keys())))
        logger.info("PORTCHANNEL ports: {}".format(str(self.port_channel_ports.keys())))


    def _generate_vlan_servers(self):
        """
        @summary: Generates physical port maps which is a set of IP address and
                their associated MAC addresses
                - MACs are generated sequentially as offsets from VLAN_BASE_MAC_PATTERN
                - IP addresses are randomly selected from the given VLAN network
                - "Hosts" (IP/MAC pairs) are distributed evenly amongst the ports in the VLAN
        """
        for _, config in self.mux_cable_table.items():
            self.server_ip_list.append(str(config['server_ipv4'].split("/")[0]))
        logger.info("ALL server address:\n {}".format(self.server_ip_list))

        vlan_host_map = defaultdict(dict)
        addr_list = list(self.server_ip_list)
        for _, i in enumerate(range(2, len(self.server_ip_list) + 2)):
            port = self.vlan_ports.values()[i % len(self.vlan_ports.values())]
            addr = random.choice(addr_list)
            # Ensure that we won't get a duplicate ip address
            addr_list.remove(addr)
            vlan_host_map[port] = [str(addr)]

        return vlan_host_map


    def __configure_arp_responder(self):
        """
        @summary: Generate ARP responder configuration using vlan_host_map.
        Copy this configuration to PTF and restart arp_responder
        """
        arp_responder_conf = {}
        for port in self.vlan_host_map:
            arp_responder_conf['eth{}'.format(port)] = self.vlan_host_map[port]
        with open("/tmp/from_t1.json", "w") as fp:
            json.dump(arp_responder_conf, fp)
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
        if traffic_generator == self.generate_from_t1_to_server:
            self.generate_from_t1_to_server()
        elif traffic_generator == self.generate_from_server_to_t1:
            self.generate_from_server_to_t1()
        else:
            logger.error("Traffic generator not provided or invalid")
            return
        # start and later join the sender and sniffer threads
        self.send_and_sniff(sender=self.traffic_sender_thread,
            sniffer=self.traffic_sniffer_thread)

        # Sender and sniffer have finished the job. Start examining the collected flow
        self.examine_flow()
        if self.lost_packets:
            self.no_routing_stop, self.no_routing_start =\
                datetime.datetime.fromtimestamp(self.no_routing_stop),\
                datetime.datetime.fromtimestamp(self.no_routing_start)
            logger.error("The longest disruption lasted %.3f seconds."\
                "%d packet(s) lost." % (self.max_disrupt_time, self.max_lost_id))
            logger.error("Total disruptions count is %d. All disruptions lasted "\
                "%.3f seconds. Total %d packet(s) lost" % \
                (self.disrupts_count, self.total_disrupt_time, self.total_disrupt_packets))


    def generate_from_t1_to_server(self):
        """
        @summary: Generate (not send) the packets to be sent from T1 to server
        """
        eth_dst = self.dut_mac
        eth_src = self.ptfadapter.dataplane.get_mac(0, 0)
        ip_ttl = 255
        tcp_dport = TCP_DST_PORT

        if self.tor_port:
            from_tor_src_port = self.tor_port
        else:
            from_tor_src_port = random.choice(self.port_channel_ports.keys())

        from_tor_src_port_index = None
        for port_name, ptf_port_index in self.port_channel_ports.items():
            if port_name == from_tor_src_port:
                from_tor_src_port_index = ptf_port_index
                break

        if from_tor_src_port_index is None:
            logger.error("Port index {} not found in the list of port channel ports {}"\
                .format(from_tor_src_port, self.port_channel_ports.values()))

        logger.info("-"*20 + "T1 to server packet" + "-"*20)
        logger.info("Source port: {}".format(from_tor_src_port))
        logger.info("Ethernet address: dst: {} src: {}".format(eth_dst, eth_src))
        if self.downstream_dst_ip:
            server_ip_list = [self.downstream_dst_ip]
            logger.info("IP address: dst: {} src: random".format(self.downstream_dst_ip))
        else:
             server_ip_list = self.server_ip_list
             logger.info("IP address: dst: random src: random")
        logger.info("TCP port: dst: {}".format(tcp_dport))
        logger.info("DUT mac: {}".format(self.dut_mac))
        logger.info("VLAN mac: {}".format(self.vlan_mac))
        logger.info("-"*50)

        self.packets_list = []
        for i in range(self.packets_to_send):
            tcp_tx_packet = testutils.simple_tcp_packet(
                eth_dst=eth_dst,
                eth_src=eth_src,
                ip_dst=random.choice(server_ip_list),
                ip_src=self.random_host_ip(),
                ip_ttl=ip_ttl,
                tcp_dport=tcp_dport)
            payload =  str(i) + 'X' * 60
            packet = scapyall.Ether(str(tcp_tx_packet))
            packet.load = payload
            self.packets_list.append((from_tor_src_port_index, str(packet)))

        self.sent_pkt_dst_mac = self.dut_mac
        self.received_pkt_src_mac = [self.vlan_mac]


    def generate_from_server_to_t1(self):
        """
        @summary: Generate (not send) the packets to be sent from server to T1
        """
        eth_src = self.ptfadapter.dataplane.get_mac(0, 0)
        if self.tor_vlan_port:
            from_server_src_port = self.tor_vlan_port
        else:
            from_server_src_port = random.choice(self.vlan_ports.values())
        self.from_server_src_addr  = random.choice(
            self.vlan_host_map[from_server_src_port])
        self.from_server_dst_addr = self.random_host_ip()
        tcp_dport = TCP_DST_PORT
        tcp_tx_packet = testutils.simple_tcp_packet(
                      eth_dst=self.vlan_mac,
                      eth_src=eth_src,
                      ip_src=self.from_server_src_addr,
                      ip_dst=self.from_server_dst_addr,
                      tcp_dport=tcp_dport
                 )
        logger.info("-"*20 + "Server to T1 packet" + "-"*20)
        logger.info("Source port: {}".format(from_server_src_port))
        logger.info("Ethernet address: dst: {} src: {}".format(self.vlan_mac, eth_src))
        logger.info("IP address: dst: {} src: {}".format(self.from_server_dst_addr,
            self.from_server_src_addr))
        logger.info("TCP port: dst: {} src: 1234".format(tcp_dport))
        logger.info("Active ToR MAC: {}, Standby ToR MAC: {}".format(self.active_mac,
            self.standby_mac))
        logger.info("VLAN MAC: {}".format(self.vlan_mac))
        logger.info("-"*50)

        self.packets_list = []
        for i in range(self.packets_to_send):
            payload =  str(i) + 'X' * 60
            packet = scapyall.Ether(str(tcp_tx_packet))
            packet.load = payload
            self.packets_list.append((from_server_src_port, str(packet)))

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
        self.sender_thr = threading.Thread(target=sender)
        self.sniff_thr = threading.Thread(target=sniffer)
        self.sniffer_started = threading.Event()
        self.sniff_thr.start()
        self.sender_thr.start()
        self.sniff_thr.join()
        self.sender_thr.join()


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

        for entry in self.packets_list:
            time.sleep(self.send_interval)
            testutils.send_packet(self.ptfadapter, *entry)

        logger.info("Sender has been running for {}".format(
            str(datetime.datetime.now() - sender_start)))


    def traffic_sniffer_thread(self):
        """
        @summary: Generalized sniffer thread (to be used for traffic in both directions)
        Starts `scapy_sniff` thread, and waits for its setup before signalling the sender thread to start
        """
        wait = self.time_to_listen + self.sniff_time_incr
        sniffer_start = datetime.datetime.now()
        logger.info("Sniffer started at {}".format(str(sniffer_start)))
        sniff_filter = "tcp and tcp dst port {} and tcp src port 1234 and not icmp".format(TCP_DST_PORT)

        scapy_sniffer = threading.Thread(target=self.scapy_sniff, kwargs={'sniff_timeout': wait,
            'sniff_filter': sniff_filter})
        scapy_sniffer.start()
        time.sleep(2)               # Let the scapy sniff initialize completely.
        self.sniffer_started.set()  # Unblock waiter for the send_in_background.
        scapy_sniffer.join()
        logger.info("Sniffer has been running for {}".format(str(datetime.datetime.now() - sniffer_start)))
        self.sniffer_started.clear()


    def scapy_sniff(self, sniff_timeout=180, sniff_filter=''):
        """
        @summary: PTF runner -  runs a sniffer in PTF container.
        Running sniffer in sonic-mgmt container has missing SOCKET problem
        and permission issues (scapy and tcpdump require root user)
        The remote function listens on all ports. Once found, all packets
        are dumped to local pcap file, and all packets are saved to
        self.all_packets as scapy type.

        Args:
            sniff_timeout (int): Duration in seconds to sniff the traffic
            sniff_filter (str): Filter that Scapy will use to collect only relevant packets
        """
        capture_pcap = '/tmp/capture.pcap'
        sniffer_log = '/tmp/dualtor-sniffer.log'
        result = ptf_runner(
            self.ptfhost,
            "ptftests",
            "dualtor_sniffer.Sniff",
            qlen=PTFRUNNER_QLEN,
            platform_dir="ptftests",
            platform="remote",
            params={
                "sniff_timeout" : sniff_timeout,
                "sniff_filter" : sniff_filter,
                "capture_pcap": capture_pcap,
                "sniffer_log": sniffer_log,
                "port_filter_expression": 'not (arp and ether src {})\
                    and not tcp'.format(self.dut_mac)
            },
            log_file=sniffer_log,
            module_ignore_errors=False
        )
        logger.debug("Ptf_runner result: {}".format(result))     

        logger.info('Fetching log files from ptf and dut hosts')
        logs_list =  [
            {'src': sniffer_log, 'dest': '/tmp/', 'flat': True, 'fail_on_missing': False},
            {'src': capture_pcap, 'dest': '/tmp/', 'flat': True, 'fail_on_missing': False}
        ]

        for log_item in logs_list:
            self.ptfhost.fetch(**log_item)
        
        self.all_packets = scapyall.rdpcap(capture_pcap)
        logger.info("Number of all packets captured: {}".format(len(self.all_packets)))


    def get_total_disruptions(self):
        return self.disrupts_count


    def get_longest_disruption(self):
        return self.max_disrupt_time


    def get_total_disrupted_packets(self):
        return self.total_disrupt_packets


    def get_total_sent_packets(self):
        return len(self.packets_list)


    def get_total_received_packets(self):
        return self.received_counter


    def get_total_lost_packets(self):
        return self.total_lost_packets


    def get_total_disrupt_time(self):
        return self.total_disrupt_time


    def get_duplicated_packets_count(self):
        return self.duplicated_packets_count


    def no_flood(self, packet):
        """
        @summary: This method filters packets which are unique (i.e. no floods).
        """
        if (not int(str(packet[scapyall.TCP].payload).replace('X',''))in self.unique_id)\
            and (packet[scapyall.Ether].src in self.received_pkt_src_mac):
            # This is a unique (no flooded) received packet.
            self.unique_id.add(int(str(packet[scapyall.TCP].payload).replace('X','')))
            return True
        elif packet[scapyall.Ether].dst == self.sent_pkt_dst_mac:
            # This is a sent packet.
            return True
        else:
            return False


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
        # Filter out packets and remove floods:
        filtered_packets = [ pkt for pkt in self.all_packets if
            scapyall.TCP in pkt and
            not scapyall.ICMP in pkt and
            pkt[scapyall.TCP].sport == 1234 and
            pkt[scapyall.TCP].dport == TCP_DST_PORT and
            self.check_tcp_payload(pkt) and
            self.no_flood(pkt)
            ]
        logger.info("Number of filtered packets captured: {}".format(len(filtered_packets)))

        # Re-arrange packets, if delayed, by Payload ID and Timestamp:
        packets = sorted(filtered_packets, key = lambda packet: (
            int(str(packet[scapyall.TCP].payload).replace('X','')), packet.time ))
        self.max_disrupt, self.total_disruption = 0, 0

        if not packets or len(packets) == 0:
            logger.error("Sniffer failed to capture any traffic")
            return
        else:
            logger.info("Measuring traffic disruptions..")
            filename = '/tmp/capture_filtered.pcap'
            scapyall.wrpcap(filename, packets)
            logger.info("Filtered pcap dumped to {}".format(filename))

        self.examine_each_packet(packets)

        self.disrupts_count = len(self.lost_packets) # Total disrupt counter.
        if self.lost_packets:
            # Find the longest loss with the longest time:
            _, (self.max_lost_id, self.max_disrupt_time, self.no_routing_start,
                self.no_routing_stop) = \
                max(self.lost_packets.items(), key = lambda item:item[1][0:2])
            self.total_disrupt_packets = sum([item[0] for item in self.lost_packets.values()])
            self.total_disrupt_time = sum([item[1] for item in self.lost_packets.values()])
        elif self.total_lost_packets == 0:
            self.max_lost_id = 0
            self.max_disrupt_time = 0
            self.total_disrupt_packets = 0
            self.total_disrupt_time = 0
            logger.info("Gaps in forwarding not found.")

        logger.info("Packet flow examine finished after {}".format(
            str(datetime.datetime.now() - examine_start)))
        logger.info("Total number of filtered incoming packets captured {}".format(
            self.received_counter))
        logger.info("Number of duplicated packets received: {}".format(
            self.duplicated_packets_count))
        logger.info("Number of packets lost: {}".format(self.total_lost_packets))


    def examine_each_packet(self, packets):
        lost_packets = dict()
        sent_packets = dict()
        duplicated_packets_count = 0
        prev_payload, prev_time = None, None
        sent_payload = 0
        disruption_start, disruption_stop = None, None
        received_counter = 0    # Counts packets from dut.
        for packet in packets:
            if packet[scapyall.Ether].dst == self.sent_pkt_dst_mac:
                # This is a sent packet - keep track of it as payload_id:timestamp.
                sent_payload = int(str(packet[scapyall.TCP].payload).replace('X',''))
                sent_packets[sent_payload] = packet.time
                continue
            if packet[scapyall.Ether].src in self.received_pkt_src_mac:
                # This is a received packet.
                received_time = packet.time
                received_payload = int(str(packet[scapyall.TCP].payload).replace('X',''))
                if received_payload == prev_payload:
                    # make account for packet duplication, and keep looking for a
                    # new and unique received packet
                    duplicated_packets_count = duplicated_packets_count + 1
                    continue
                received_counter += 1
            if not (received_payload and received_time):
                # This is the first valid received packet.
                prev_payload = received_payload
                prev_time = received_time
                continue
            if received_payload - prev_payload > 1:
                # Packets in a row are missing, a disruption.
                lost_id = (received_payload - 1) - prev_payload # How many packets lost in a row.
                # How long disrupt lasted.
                disrupt = (sent_packets[received_payload] - sent_packets[prev_payload + 1])
                # Add disruption to the lost_packets dict:
                lost_packets[prev_payload] = (lost_id, disrupt, received_time - disrupt, received_time)
                logger.info("Disruption between packet ID %d and %d. For %.4f " % (
                    prev_payload, received_payload, disrupt))
                if not disruption_start:
                    disruption_start = datetime.datetime.fromtimestamp(prev_time)
                disruption_stop = datetime.datetime.fromtimestamp(received_time)
            prev_payload = received_payload
            prev_time = received_time

        self.total_lost_packets = len(sent_packets) - received_counter
        self.received_counter = received_counter
        self.lost_packets = lost_packets
        self.duplicated_packets_count = duplicated_packets_count

        if self.received_counter == 0:
            logger.error("Sniffer failed to filter any traffic from DUT")
        if self.lost_packets:
            logger.info("Disruptions happen between {} and {}.".format(
                str(disruption_start), str(disruption_stop)))


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
