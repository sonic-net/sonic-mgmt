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
        capture_filter = "inbound and udp and (port 67 or port 68) and (udp[249:2] = 0x01{})".format(
            self.packet_type_hex
        )
        capture_log_files = [
            "/tmp/dhcp_stress_test_{}_eth{}.log".format(self.packet_type, port_index)
            for port_index in self.receive_port_indices
        ]
        capture_outputs = []
        tcpdump_procs = []
        try:
            for port_index, log_file in zip(self.receive_port_indices, capture_log_files):
                capture_output = open(log_file, "w")
                capture_outputs.append(capture_output)
                tcpdump_procs.append(subprocess.Popen([
                    "tcpdump", "--buffer-size=102400", "--immediate-mode", "-U",
                    "-i", "eth{}".format(port_index), "-n", "-q", "-l", capture_filter
                ], stdout=capture_output, stderr=subprocess.DEVNULL))

            if self.packet_type == "discover" or self.packet_type == "request":
                dhcp_packet = self.create_packet(self.dest_mac_address, self.client_udp_src_port)
            else:
                dhcp_packet = self.create_packet()
            end_time = time.time() + self.packets_send_duration
            xid = 0
            while time.time() < end_time:
                dhcp_packet[scapy.BOOTP].xid = xid
                xid += 1
                testutils.send_packet(self, self.send_port_indices[0], dhcp_packet)
                time.sleep(1/self.client_packets_per_sec)

            # Wait until tcpdump stops receiving packets (idle for 5s, max 120s)
            last_size = 0
            idle_count = 0
            deadline = time.time() + 120
            while idle_count < 5 and time.time() < deadline:
                time.sleep(1)
                current_size = sum(os.path.getsize(log_file) for log_file in capture_log_files)
                if current_size == last_size:
                    idle_count += 1
                else:
                    idle_count = 0
                last_size = current_size
        finally:
            for tcpdump_proc in tcpdump_procs:
                if tcpdump_proc.poll() is None:
                    tcpdump_proc.send_signal(signal.SIGINT)
            for tcpdump_proc in tcpdump_procs:
                tcpdump_proc.wait()
            for capture_output in capture_outputs:
                capture_output.close()

        line_count = 0
        for log_file in capture_log_files:
            with open(log_file) as capture_log:
                line_count += sum(1 for _ in capture_log)
            os.remove(log_file)

        with open("/tmp/dhcp_stress_test_{}".format(self.packet_type), "w") as result_file:
            result_file.write(str(line_count))

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
