import time
import logging
import subprocess
import signal
import os
import ptf.testutils as testutils
import ptf.packet as scapy
from dhcp_relay_test import DHCPTest

logger = logging.getLogger(__name__)


class DHCPContinuousStressTest(DHCPTest):
    """
    Keep sending packets, but don't verify form ptf side.
    """
    def __init__(self):
        DHCPTest.__init__(self)

    def setUp(self):
        DHCPTest.setUp(self)
        self.send_interval = 1 / self.test_params["pps"]
        self.duration = self.test_params["duration"]
        self.client_ports = self.other_client_port
        self.client_ports.append(self.client_port_index)

    def send_packet_with_interval(self, pkt, index):
        testutils.send_packet(self, index, pkt)
        time.sleep(self.send_interval)

    def runTest(self):
        dhcp_discover = self.create_dhcp_discover_packet(self.dest_mac_address, self.client_udp_src_port)
        dhcp_offer = self.create_dhcp_offer_packet()
        dhcp_request = self.create_dhcp_request_packet(self.dest_mac_address, self.client_udp_src_port)
        dhcp_ack = self.create_dhcp_ack_packet()

        start_time = time.time()
        while time.time() - start_time <= self.duration:
            for client_port in self.client_ports:
                self.send_packet_with_interval(dhcp_discover, client_port)
            for server_port in self.server_port_indices:
                self.send_packet_with_interval(dhcp_offer, server_port)
            for client_port in self.client_ports:
                self.send_packet_with_interval(dhcp_request, client_port)
            for server_port in self.server_port_indices:
                self.send_packet_with_interval(dhcp_ack, server_port)


class DHCPStressTest(DHCPTest):
    def setUp(self):
        DHCPTest.setUp(self)
        self.packets_send_duration = self.test_params["packets_send_duration"]
        self.client_packets_per_sec = self.test_params["client_packets_per_sec"]

    # Simulate client coming on VLAN and broadcasting a DHCPDISCOVER message
    def client_send_packet_stress(self):
        server_ports = "|".join(["eth{}".format(idx) for idx in self.receive_port_indices])
        tcpdump_cmd = (
            "tcpdump -i any -n -q -l 'inbound and udp and (port 67 or port 68) and (udp[249:2] = 0x01{})' "
            "| grep -w -E '{}' > /tmp/dhcp_stress_test_{}.log"
        ).format(self.packet_type_hex, server_ports, self.packet_type)
        tcpdump_proc = subprocess.Popen(tcpdump_cmd, shell=True)
        if self.packet_type == "discover" or self.packet_type == "request":
            dhcp_packet = self.create_packet(self.dest_mac_address, self.client_udp_src_port)
        else:
            dhcp_packet = self.create_packet()
        end_time = time.time() + self.packets_send_duration
        xid = 0
        while time.time() < end_time:
            # Set a unique transaction ID for each DHCPOFFER packet for making sure no packet miss
            dhcp_packet[scapy.BOOTP].xid = xid
            xid += 1
            testutils.send_packet(self, self.send_port_indices[0], dhcp_packet)
            time.sleep(1/self.client_packets_per_sec)

        time.sleep(15)

        pids = subprocess.check_output("pgrep tcpdump", shell=True).split()
        for pid in pids:
            os.kill(int(pid), signal.SIGINT)
        tcpdump_proc.wait()

        wc_cmd = f"wc -l /tmp/dhcp_stress_test_{self.packet_type}.log"
        wc_output = subprocess.check_output(wc_cmd, shell=True)
        line_cnt = wc_output.decode().split()[0]
        os.remove("/tmp/dhcp_stress_test_{}.log".format(self.packet_type))
        subprocess.check_output("echo {} > /tmp/dhcp_stress_test_{}".format(line_cnt, self.packet_type), shell=True)

    def runTest(self):
        self.client_send_packet_stress()


class DHCPStressDiscoverTest(DHCPStressTest):
    def setUp(self):
        DHCPStressTest.setUp(self)
        self.receive_port_indices = self.server_port_indices
        self.send_port_indices = [self.client_port_index]
        self.create_packet = self.create_dhcp_discover_packet
        self.packet_type = "discover"
        self.packet_type_hex = "01"


class DHCPStressOfferTest(DHCPStressTest):
    def setUp(self):
        DHCPStressTest.setUp(self)
        self.receive_port_indices = [self.client_port_index]
        self.send_port_indices = self.server_port_indices
        self.create_packet = self.create_dhcp_offer_packet
        self.packet_type = "offer"
        self.packet_type_hex = "02"


class DHCPStressRequestTest(DHCPStressTest):
    def setUp(self):
        DHCPStressTest.setUp(self)
        self.receive_port_indices = self.server_port_indices
        self.send_port_indices = [self.client_port_index]
        self.create_packet = self.create_dhcp_request_packet
        self.packet_type = "request"
        self.packet_type_hex = "03"


class DHCPStressAckTest(DHCPStressTest):
    def setUp(self):
        DHCPStressTest.setUp(self)
        self.receive_port_indices = [self.client_port_index]
        self.send_port_indices = self.server_port_indices
        self.create_packet = self.create_dhcp_ack_packet
        self.packet_type = "ack"
        self.packet_type_hex = "05"
