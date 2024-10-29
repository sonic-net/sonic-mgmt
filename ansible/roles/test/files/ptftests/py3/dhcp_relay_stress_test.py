import time
import logging
import ptf.testutils as testutils
import ptf.packet as scapy
from ptf.mask import Mask
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


class DHCPStressDiscoverTest(DHCPTest):
    def __init__(self):
        DHCPTest.__init__(self)

    def setUp(self):
        DHCPTest.setUp(self)
        self.packets_send_duration = self.test_params["packets_send_duration"]
        self.client_packets_per_sec = self.test_params["client_packets_per_sec"]

    # Simulate client coming on VLAN and broadcasting a DHCPDISCOVER message
    def client_send_discover_stress(self, dst_mac, src_port):
        # Form and send DHCPDISCOVER packet
        dhcp_discover = self.create_dhcp_discover_packet(dst_mac, src_port)
        end_time = time.time() + self.packets_send_duration
        while time.time() < end_time:
            testutils.send_packet(self, self.client_port_index, dhcp_discover)
            time.sleep(1/self.client_packets_per_sec)

    def count_relayed_discover(self):
        # Create a packet resembling a relayed DCHPDISCOVER packet
        dhcp_discover_relayed = self.create_dhcp_discover_relayed_packet()

        # Mask off fields we don't care about matching
        masked_discover = Mask(dhcp_discover_relayed)
        masked_discover.set_do_not_care_scapy(scapy.Ether, "dst")

        masked_discover.set_do_not_care_scapy(scapy.IP, "version")
        masked_discover.set_do_not_care_scapy(scapy.IP, "ihl")
        masked_discover.set_do_not_care_scapy(scapy.IP, "tos")
        masked_discover.set_do_not_care_scapy(scapy.IP, "len")
        masked_discover.set_do_not_care_scapy(scapy.IP, "id")
        masked_discover.set_do_not_care_scapy(scapy.IP, "flags")
        masked_discover.set_do_not_care_scapy(scapy.IP, "frag")
        masked_discover.set_do_not_care_scapy(scapy.IP, "ttl")
        masked_discover.set_do_not_care_scapy(scapy.IP, "proto")
        masked_discover.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_discover.set_do_not_care_scapy(scapy.IP, "src")
        masked_discover.set_do_not_care_scapy(scapy.IP, "dst")
        masked_discover.set_do_not_care_scapy(scapy.IP, "options")

        masked_discover.set_do_not_care_scapy(scapy.UDP, "chksum")
        masked_discover.set_do_not_care_scapy(scapy.UDP, "len")

        masked_discover.set_do_not_care_scapy(scapy.BOOTP, "sname")
        masked_discover.set_do_not_care_scapy(scapy.BOOTP, "file")

        discover_count = testutils.count_matched_packets_all_ports(
            self, masked_discover, self.server_port_indices)
        return discover_count

    def runTest(self):
        self.client_send_discover_stress(self.dest_mac_address, self.client_udp_src_port)
        discover_cnt = self.count_relayed_discover()

        # At the end of the test, overwrite the file with discover count.
        try:
            with open('/tmp/dhcp_stress_test_discover.json', 'w') as result_file:
                result_file.write(str(discover_cnt))
        except Exception as e:
            logger.error("Failed to write to the discover file: %s", repr(e))


class DHCPStressOfferTest(DHCPTest):
    def __init__(self):
        DHCPTest.__init__(self)

    def setUp(self):
        DHCPTest.setUp(self)
        self.packets_send_duration = self.test_params["packets_send_duration"]
        self.client_packets_per_sec = self.test_params["client_packets_per_sec"]

    # Simulate client coming on VLAN and broadcasting a DHCPOFFER message
    def client_send_offer_stress(self):
        dhcp_offer = self.create_dhcp_offer_packet()
        end_time = time.time() + self.packets_send_duration
        while time.time() < end_time:
            testutils.send_packet(self, self.server_port_indices[0], dhcp_offer)
            time.sleep(1/self.client_packets_per_sec)

    def count_relayed_offer(self):
        # Create a packet resembling a relayed DCHPOFFER packet
        dhcp_offer_relayed = self.create_dhcp_offer_relayed_packet()

        # Mask off fields we don't care about matching
        masked_offer = Mask(dhcp_offer_relayed)

        masked_offer.set_do_not_care_scapy(scapy.IP, "version")
        masked_offer.set_do_not_care_scapy(scapy.IP, "ihl")
        masked_offer.set_do_not_care_scapy(scapy.IP, "tos")
        masked_offer.set_do_not_care_scapy(scapy.IP, "len")
        masked_offer.set_do_not_care_scapy(scapy.IP, "id")
        masked_offer.set_do_not_care_scapy(scapy.IP, "flags")
        masked_offer.set_do_not_care_scapy(scapy.IP, "frag")
        masked_offer.set_do_not_care_scapy(scapy.IP, "ttl")
        masked_offer.set_do_not_care_scapy(scapy.IP, "proto")
        masked_offer.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_offer.set_do_not_care_scapy(scapy.IP, "options")
        masked_offer.set_do_not_care_scapy(scapy.IP, "src")
        masked_offer.set_do_not_care_scapy(scapy.IP, "dst")

        masked_offer.set_do_not_care_scapy(scapy.UDP, "len")
        masked_offer.set_do_not_care_scapy(scapy.UDP, "chksum")

        masked_offer.set_do_not_care_scapy(scapy.BOOTP, "sname")
        masked_offer.set_do_not_care_scapy(scapy.BOOTP, "file")

        offer_count = testutils.count_matched_packets(self, masked_offer, self.client_port_index)
        return offer_count

    def runTest(self):
        self.client_send_offer_stress()
        offer_cnt = self.count_relayed_offer()

        # At the end of the test, overwrite the file with offer count.
        try:
            with open('/tmp/dhcp_stress_test_offer.json', 'w') as result_file:
                result_file.write(str(offer_cnt))
        except Exception as e:
            logger.error("Failed to write to the offer file: %s", repr(e))


class DHCPStressRequestTest(DHCPTest):
    def __init__(self):
        DHCPTest.__init__(self)

    def setUp(self):
        DHCPTest.setUp(self)
        self.packets_send_duration = self.test_params["packets_send_duration"]
        self.client_packets_per_sec = self.test_params["client_packets_per_sec"]

    # Simulate client coming on VLAN and broadcasting a DHCPREQUEST message
    def client_send_request_stress(self, dst_mac, src_port):
        # Form and send DHCPREQUEST packet
        dhcp_request = self.create_dhcp_request_packet(dst_mac, src_port)
        end_time = time.time() + self.packets_send_duration
        while time.time() < end_time:
            testutils.send_packet(self, self.client_port_index, dhcp_request)
            time.sleep(1/self.client_packets_per_sec)

    def count_relayed_request(self):
        # Create a packet resembling a relayed DCHPREQUEST packet
        dhcp_request_relayed = self.create_dhcp_request_relayed_packet()

        # Mask off fields we don't care about matching
        masked_request = Mask(dhcp_request_relayed)
        masked_request.set_do_not_care_scapy(scapy.Ether, "dst")

        masked_request.set_do_not_care_scapy(scapy.IP, "version")
        masked_request.set_do_not_care_scapy(scapy.IP, "ihl")
        masked_request.set_do_not_care_scapy(scapy.IP, "tos")
        masked_request.set_do_not_care_scapy(scapy.IP, "len")
        masked_request.set_do_not_care_scapy(scapy.IP, "id")
        masked_request.set_do_not_care_scapy(scapy.IP, "flags")
        masked_request.set_do_not_care_scapy(scapy.IP, "frag")
        masked_request.set_do_not_care_scapy(scapy.IP, "ttl")
        masked_request.set_do_not_care_scapy(scapy.IP, "proto")
        masked_request.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_request.set_do_not_care_scapy(scapy.IP, "src")
        masked_request.set_do_not_care_scapy(scapy.IP, "dst")
        masked_request.set_do_not_care_scapy(scapy.IP, "options")

        masked_request.set_do_not_care_scapy(scapy.UDP, "chksum")
        masked_request.set_do_not_care_scapy(scapy.UDP, "len")

        masked_request.set_do_not_care_scapy(scapy.BOOTP, "sname")
        masked_request.set_do_not_care_scapy(scapy.BOOTP, "file")

        request_count = testutils.count_matched_packets_all_ports(
            self, masked_request, self.server_port_indices)
        return request_count

    def runTest(self):
        self.client_send_request_stress(self.dest_mac_address, self.client_udp_src_port)
        request_cnt = self.count_relayed_request()

        # At the end of the test, overwrite the file with request count.
        try:
            with open('/tmp/dhcp_stress_test_request.json', 'w') as result_file:
                result_file.write(str(request_cnt))
        except Exception as e:
            logger.error("Failed to write to the request file: %s", repr(e))


class DHCPStressAckTest(DHCPTest):
    def __init__(self):
        DHCPTest.__init__(self)

    def setUp(self):
        DHCPTest.setUp(self)
        self.packets_send_duration = self.test_params["packets_send_duration"]
        self.client_packets_per_sec = self.test_params["client_packets_per_sec"]

    # Simulate client coming on VLAN and broadcasting a DHCPACK message
    def client_send_ack_stress(self):
        dhcp_ack = self.create_dhcp_ack_packet()
        end_time = time.time() + self.packets_send_duration
        while time.time() < end_time:
            testutils.send_packet(self, self.server_port_indices[0], dhcp_ack)
            time.sleep(1/self.client_packets_per_sec)

    def count_relayed_ack(self):
        # Create a packet resembling a relayed DCHPACK packet
        dhcp_ack_relayed = self.create_dhcp_ack_relayed_packet()

        # Mask off fields we don't care about matching
        masked_ack = Mask(dhcp_ack_relayed)

        masked_ack.set_do_not_care_scapy(scapy.IP, "version")
        masked_ack.set_do_not_care_scapy(scapy.IP, "ihl")
        masked_ack.set_do_not_care_scapy(scapy.IP, "tos")
        masked_ack.set_do_not_care_scapy(scapy.IP, "len")
        masked_ack.set_do_not_care_scapy(scapy.IP, "id")
        masked_ack.set_do_not_care_scapy(scapy.IP, "flags")
        masked_ack.set_do_not_care_scapy(scapy.IP, "frag")
        masked_ack.set_do_not_care_scapy(scapy.IP, "ttl")
        masked_ack.set_do_not_care_scapy(scapy.IP, "proto")
        masked_ack.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_ack.set_do_not_care_scapy(scapy.IP, "options")
        masked_ack.set_do_not_care_scapy(scapy.IP, "src")
        masked_ack.set_do_not_care_scapy(scapy.IP, "dst")

        masked_ack.set_do_not_care_scapy(scapy.UDP, "len")
        masked_ack.set_do_not_care_scapy(scapy.UDP, "chksum")

        masked_ack.set_do_not_care_scapy(scapy.BOOTP, "sname")
        masked_ack.set_do_not_care_scapy(scapy.BOOTP, "file")

        ack_count = testutils.count_matched_packets(self, masked_ack, self.client_port_index)
        return ack_count

    def runTest(self):
        self.client_send_ack_stress()
        ack_cnt = self.count_relayed_ack()

        # At the end of the test, overwrite the file with ack count.
        try:
            with open('/tmp/dhcp_stress_test_ack.json', 'w') as result_file:
                result_file.write(str(ack_cnt))
        except Exception as e:
            logger.error("Failed to write to the ack file: %s", repr(e))
