import ast
import struct
import ipaddress

# Packet Test Framework imports
import ptf
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf import config
from ptf.base_tests import BaseTest
from ptf.mask import Mask


# Helper function to increment an IP address
# ip_addr should be passed as a dot-decimal string
# Return value is also a dot-decimal string
def incrementIpAddress(ip_addr, by=1):
    new_addr = ipaddress.ip_address(unicode(ip_addr))
    new_addr = new_addr + by
    return str(new_addr)



class DataplaneBaseTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        if config["log_dir"] is not None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] is not None:
            self.dataplane.stop_pcap()

"""
 This test simulates a new host booting up of the Vlan network of a ToR and
 requesting an IP address via DHCP. Setup is as follows:
  - DHCP client is simulated by crafting and sending packets on a port
    connected to Vlan of ToR.
  - PTF listens/sends on injected interfaces which link ToR to leaves. With this,
    we can listen for traffic sent from DHCP relay out to would-be DHCP servers

 This test performs the following functionality:
   1.) Simulated client broadcasts a DHCPDISCOVER message
   2.) Verify DHCP relay running on ToR receives the DHCPDISCOVER message
       and relays it to all of its known DHCP servers
   3.) Simulate DHCPOFFER message broadcast from a DHCP server to the ToR
   4.) Verify DHCP relay receives the DHCPOFFER message and forwards it to our
       simulated client.
   5.) Simulated client broadcasts a DHCPREQUEST message
   6.) Verify DHCP relay running on ToR receives the DHCPREQUEST message
       and relays it to all of its known DHCP servers
   7.) Simulate DHCPACK message sent from a DHCP server to the ToR
   8.) Verify DHCP relay receives the DHCPACK message and forwards it to our
       simulated client.


 To run: place the following in a shell script (this will test against str-s6000-acs-12 (ec:f4:bb:fe:88:0a)):
   ptf --test-dir test dhcp_relay_test.DHCPTest --platform remote -t "verbose=True; client_port_index=\"4\"; leaf_port_indices=\"[28, 29, 30, 31]\"; server_ip=\"2.2.2.2\"; relay_iface_name=\"Vlan1000\"; relay_iface_ip=\"192.168.0.1\"; relay_iface_mac=\"ec:f4:bb:fe:88:0a\"; relay_iface_netmask=\"255.255.255.224\"" --disable-ipv6 --disable-vxlan --disable-geneve --disable-erspan --disable-mpls --disable-nvgre

 The above command is configured to test with the following configuration:
  - Vlan IP of DuT is 192.168.0.1, MAC address is ec:f4:bb:fe:88:0a (this is configured to test against str-s6000-acs-12)
  - Simulated client will live on PTF interface eth4 (interface number 4)
  - Assumes leaf switches are connected to injected PTF interfaces 28, 29, 30, 31
  - Test will simulate replies from server with IP '2.2.2.2'
  - Simulated server will offer simulated client IP '192.168.0.2' with a subnet of '255.255.255.0' (this should be in the Vlan of DuT)


 DHCP Relay currently installed with SONiC is isc-dhcp-relay

 TODO???:
	1) DHCP Renew Test
	2) DHCP NACK Test
	3) DHCP Option 82 - remote ID test when available
	4) Test with multiple DHCP Servers

"""

class DHCPTest(DataplaneBaseTest):

    BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
    BROADCAST_IP = '255.255.255.255'
    DEFAULT_ROUTE_IP = '0.0.0.0'
    DHCP_CLIENT_PORT = 68
    DHCP_SERVER_PORT = 67
    DHCP_LEASE_TIME_OFFSET = 292
    DHCP_LEASE_TIME_LEN = 6
    LEASE_TIME = 86400

    def __init__(self):
        DataplaneBaseTest.__init__(self)


    def setUp(self):
        DataplaneBaseTest.setUp(self)

        self.test_params = testutils.test_params_get()

        # These are the interfaces we are injected into that link to out leaf switches
        self.server_port_indices = ast.literal_eval(self.test_params['leaf_port_indices'])
        self.num_dhcp_servers = int(self.test_params['num_dhcp_servers'])
        self.server_ip = self.test_params['server_ip']

        self.relay_iface_name = self.test_params['relay_iface_name']
        self.relay_iface_ip = self.test_params['relay_iface_ip']
        self.relay_iface_mac = self.test_params['relay_iface_mac']

        self.client_port_index = int(self.test_params['client_port_index'])
        self.client_iface_mac = self.dataplane.get_mac(0, self.client_port_index)

        # relay_agent_info is a byte string created by the relay agent to specify which
        # interface it received the message on. It is stored as suboption 1 of option 82.
        # It consists of the following:
        #  Byte 0: Suboption number, always set to 1
        #  Byte 1: Length of suboption data in bytes (i.e., length of interface name)
        #  Bytes 2+: Suboption data (interface name)
        self.relay_agent_info = struct.pack('BB', 1, len(self.relay_iface_name))
        self.relay_agent_info += self.relay_iface_name

        # We'll assign our client the IP address 1 greater than our relay interface (i.e., gateway) IP
        self.client_ip = incrementIpAddress(self.relay_iface_ip, 1) 
        self.client_subnet = self.test_params['relay_iface_netmask']


    def tearDown(self):
        DataplaneBaseTest.tearDown(self)


    """
     Packet generation functions/wrappers
    
    """

    def create_dhcp_discover_packet(self):
        return testutils.dhcp_discover_packet(eth_client=self.client_iface_mac)

    def create_dhcp_discover_relayed_packet(self):
        my_chaddr = ''.join([chr(int(octet, 16)) for octet in self.client_iface_mac.split(':')])

        # Relay modifies the DHCPDISCOVER message in the following ways:
        #  1.) Increments the hops count in the DHCP header
        #  2.) Updates the gateway IP address in hte BOOTP header (if it is 0.0.0.0)
        #  3.) Replaces the source IP with the IP of the interface which the relay
        #      received the broadcast DHCPDISCOVER message on
        #  4.) Replaces the destination IP with the IP address of the DHCP server
        #      each message is being forwarded to
        # Here, the actual destination MAC should be the MAC of the leaf the relay
        # forwards through and the destination IP should be the IP of the DHCP server
        # the relay is forwarding to. We don't need to confirm these, so we'll
        # just mask them off later
        #
        # TODO: Relay also replaces source IP with IP of interface on which it received the 
        #       broadcast DHCPDISCOVER from client. This appears to be loopback.
        #       We could pull from minigraph and check here.
        pkt = scapy.Ether(dst=self.BROADCAST_MAC, src=self.relay_iface_mac, type=0x0800)
        pkt /= scapy.IP(src=self.DEFAULT_ROUTE_IP, dst=self.BROADCAST_IP, len=328, ttl=64)
        pkt /= scapy.UDP(sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT, len=308)
        pkt /= scapy.BOOTP(op=1,
                    htype=1,
                    hlen=6,
                    hops=1,
                    xid=0,
                    secs=0,
                    flags=0x8000,
                    ciaddr=self.DEFAULT_ROUTE_IP,
                    yiaddr=self.DEFAULT_ROUTE_IP,
                    siaddr=self.DEFAULT_ROUTE_IP,
                    giaddr=self.relay_iface_ip,
                    chaddr=my_chaddr)
        pkt /= scapy.DHCP(options=[('message-type', 'discover'),
                    ('relay_agent_Information', self.relay_agent_info),
                    ('end')])

        # The isc-dhcp-relay adds 44 bytes of padding to our discover packet
        pkt /= scapy.PADDING('\x00' * 44)
        return pkt

    def create_dhcp_offer_packet(self):
        return testutils.dhcp_offer_packet(eth_client=self.client_iface_mac,
                    eth_server=self.relay_iface_mac,
                    ip_server=self.relay_iface_ip,
                    ip_offered=self.client_ip,
                    ip_gateway=self.relay_iface_ip,
                    netmask_client=self.client_subnet,
                    dhcp_lease=self.LEASE_TIME,
                    padding_bytes=0)

    def create_dhcp_request_packet(self):
        return testutils.dhcp_request_packet(eth_client=self.client_iface_mac,
                    ip_server=self.server_ip,
                    ip_requested=self.client_ip)

    def create_dhcp_request_relayed_packet(self):
        my_chaddr = ''.join([chr(int(octet, 16)) for octet in self.client_iface_mac.split(':')])

        # Here, the actual destination MAC should be the MAC of the leaf the relay
        # forwards through and the destination IP should be the IP of the DHCP server
        # the relay is forwarding to. We don't need to confirm these, so we'll
        # just mask them off later
        #
        # TODO: Relay also replaces source IP with IP of interface on which it received the 
        #       broadcast DHCPDISCOVER from client. This appears to be loopback.
        #       We could pull from minigraph and check here.
        pkt = scapy.Ether(dst=self.BROADCAST_MAC, src=self.relay_iface_mac, type=0x0800)
        pkt /= scapy.IP(src=self.DEFAULT_ROUTE_IP, dst=self.BROADCAST_IP, len=328, ttl=64)
        pkt /= scapy.UDP(sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT, len=308)
        pkt /= scapy.BOOTP(op=1,
                    htype=1,
                    hlen=6,
                    hops=1,
                    xid=0,
                    secs=0,
                    flags=0x8000,
                    ciaddr=self.DEFAULT_ROUTE_IP,
                    yiaddr=self.DEFAULT_ROUTE_IP,
                    siaddr=self.DEFAULT_ROUTE_IP,
                    giaddr=self.relay_iface_ip,
                    chaddr=my_chaddr)
        pkt /= scapy.DHCP(options=[('message-type', 'request'),
                    ('requested_addr', self.client_ip),
                    ('server_id', self.server_ip),
                    ('relay_agent_Information', self.relay_agent_info),
                    ('end')])

        # The isc-dhcp-relay adds 32 bytes of padding to our request
        pkt /= scapy.PADDING('\x00' * 32)
        return pkt

    def create_dhcp_ack_packet(self):
        return testutils.dhcp_ack_packet(eth_client=self.client_iface_mac,
                    eth_server=self.relay_iface_mac,
                    ip_server=self.relay_iface_ip,
                    ip_offered=self.client_ip,
                    netmask_client=self.client_subnet,
                    ip_gateway=self.relay_iface_ip,
                    dhcp_lease=self.LEASE_TIME,
                    padding_bytes=0)


    """
     Send/receive functions

    """

    # Simulate client coming on vlan and broadcasting a DHCPDISCOVER message
    def client_send_discover(self):
        # Form and send DHCPDISCOVER packet
        dhcp_discover = self.create_dhcp_discover_packet()
        testutils.send_packet(self, self.client_port_index, dhcp_discover)

    # Verify that the DHCP relay actually received and relayed the DHCPDISCOVER message to all of
    # its known DHCP servers. We also verify that the relay inserted Option 82 information in the
    # packet.
    def verify_relayed_discover(self):
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

        masked_discover.set_do_not_care_scapy(scapy.BOOTP, "sname")
        masked_discover.set_do_not_care_scapy(scapy.BOOTP, "file")

        masked_discover.set_do_not_care_scapy(scapy.PADDING, "load")

        # Count the number of these packets received on the ports connected to our leaves
        discover_count = testutils.count_matched_packets_all_ports(self, masked_discover, self.server_port_indices)
        self.assertTrue(discover_count == self.num_dhcp_servers,
                "Failed: Discover count of %d != %d (num_dhcp_servers)" % (discover_count, self.num_dhcp_servers))

    # Simulate a DHCP server sending a DHCPOFFER message to client.
    # We do this by injecting a DHCPOFFER message on the link connected to one
    # of our leaf switches.
    def server_send_offer(self):
        dhcp_offer = self.create_dhcp_offer_packet()
        testutils.send_packet(self, self.client_port_index, dhcp_offer)

    # Verify that the DHCPOFFER would be received by our simulated client
    def verify_offer_received(self):
        dhcp_offer = self.create_dhcp_offer_packet()

        masked_offer = Mask(dhcp_offer)
        masked_offer.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_offer.set_do_not_care_scapy(scapy.UDP, "chksum")
        masked_offer.set_do_not_care_scapy(scapy.IP, "chksum")

        # Mask out lease time since it changes depending on when the server recieves the request
        # Lease time in ack can be slightly different than in offer, since lease time varies slightly
        # We also want to ignore the checksums since they will vary a bit depending on the timestamp
        # Offset is byte 292, 6 byte field, set_do_not_care() expects values in bits
        masked_offer.set_do_not_care((self.DHCP_LEASE_TIME_OFFSET * 8), (self.DHCP_LEASE_TIME_LEN * 8))

        # NOTE: verify_packet() will fail for us via an assert, so no nedd to check a return value here
        testutils.verify_packet(self, masked_offer, self.client_port_index)

    # Simulate our client sending a DHCPREQUEST message
    def client_send_request(self):
        dhcp_request = self.create_dhcp_request_packet()
        testutils.send_packet(self, self.client_port_index, dhcp_request)

    # Verify that the DHCP relay actually received and relayed the DHCPREQUEST message to all of
    # its known DHCP servers. We also verify that the relay inserted Option 82 information in the
    # packet.
    def verify_relayed_request(self):
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

        masked_request.set_do_not_care_scapy(scapy.BOOTP, "sname")
        masked_request.set_do_not_care_scapy(scapy.BOOTP, "file")

        masked_request.set_do_not_care_scapy(scapy.PADDING, "load")

        # Count the number of these packets received on the ports connected to our leaves
        request_count = testutils.count_matched_packets_all_ports(self, masked_request, self.server_port_indices)
        self.assertTrue(request_count == self.num_dhcp_servers,
                "Failed: Request count of %d != %d (num_dhcp_servers)" % (request_count, self.num_dhcp_servers))

    # Simulate a DHCP server sending a DHCPOFFER message to client from one of our leaves
    def server_send_ack(self):
        dhcp_ack = self.create_dhcp_ack_packet()
        testutils.send_packet(self, self.client_port_index, dhcp_ack)

    # Verify that the DHCPACK would be received by our simulated client
    def verify_ack_received(self):
        dhcp_ack = self.create_dhcp_ack_packet()

        # Mask out lease time, ip checksum, udp checksum (explanation above)
        masked_ack = Mask(dhcp_ack)
        masked_ack.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_ack.set_do_not_care_scapy(scapy.UDP, "chksum")
        masked_ack.set_do_not_care_scapy(scapy.IP, "chksum")

        # Also mask out lease time (see comment in verify_offer_received() above)
        masked_ack.set_do_not_care((self.DHCP_LEASE_TIME_OFFSET * 8), (self.DHCP_LEASE_TIME_LEN * 8))

        # NOTE: verify_packet() will fail for us via an assert, so no nedd to check a return value here
        testutils.verify_packet(self, masked_ack, self.client_port_index)

    def runTest(self):
        self.client_send_discover()
        self.verify_relayed_discover()
        self.server_send_offer()
        self.verify_offer_received()
        self.client_send_request()
        self.verify_relayed_request()
        self.server_send_ack()
        self.verify_ack_received()

