import ast
import struct
import ipaddress
import binascii

# Packet Test Framework imports
import ptf
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf import config
from ptf.base_tests import BaseTest
from ptf.mask import Mask
import scapy.all as scapy2
from threading import Thread


# Helper function to increment an IP address
# ip_addr should be passed as a dot-decimal string
# Return value is also a dot-decimal string
def incrementIpAddress(ip_addr, by=1):
    new_addr = ipaddress.ip_address(str(ip_addr))
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
 This test simulates a new host booting up on the VLAN network of a ToR and
 requesting an IP address via DHCP. Setup is as follows:
  - DHCP client is simulated by listening/sending on an interface connected to VLAN of ToR.
  - DHCP server is simulated by listening/sending on injected PTF interfaces which link
    ToR to leaves. This way we can listen for traffic sent from DHCP relay out to would-be DHCP servers

 This test performs the following functionality:
   1.) Simulated client broadcasts a DHCPDISCOVER message
   2.) Verify DHCP relay running on ToR receives the DHCPDISCOVER message
       and relays it to all of its known DHCP servers, appending the proper Option 82 information
   3.) Simulate DHCPOFFER message broadcast from a DHCP server to the ToR
   4.) Verify DHCP relay receives the DHCPOFFER message and forwards it to our
       simulated client.
   5.) Simulated client broadcasts a DHCPREQUEST message
   6.) Verify DHCP relay running on ToR receives the DHCPREQUEST message
       and relays it to all of its known DHCP servers, appending the proper Option 82 information
   7.) Simulate DHCPACK message sent from a DHCP server to the ToR
   8.) Verify DHCP relay receives the DHCPACK message and forwards it to our
       simulated client.

 To run: place the following in a shell script (this will test against str-s6000-acs-12 (ec:f4:bb:fe:88:0a)):
   ptf --test-dir ptftests dhcp_relay_test.DHCPTest --platform remote -t "hostname=\"str-s6000-acs-12\"; client_port_index=\"1\"; client_iface_alias=\"fortyGigE0/4\"; leaf_port_indices=\"[29, 31, 28, 30]\"; num_dhcp_servers=\"48\"; server_ip=\"192.0.0.1\"; relay_iface_ip=\"192.168.0.1\"; relay_iface_mac=\"ec:f4:bb:fe:88:0a\"; relay_iface_netmask=\"255.255.255.224\"" --disable-vxlan --disable-geneve --disable-erspan --disable-mpls --disable-nvgre

 The above command is configured to test with the following configuration:
  - VLAN IP of DuT is 192.168.0.1, MAC address is ec:f4:bb:fe:88:0a (this is configured to test against str-s6000-acs-12)
  - Simulated client will live on PTF interface eth4 (interface number 4)
  - Assumes leaf switches are connected to injected PTF interfaces 28, 29, 30, 31
  - Test will simulate replies from server with IP '192.0.0.1'
  - Simulated server will offer simulated client IP '192.168.0.2' with a subnet of '255.255.255.0' (this should be in the VLAN of DuT)


 DHCP Relay currently installed with SONiC is isc-dhcp-relay

 TODO???:
        1) DHCP Renew Test
        2) DHCP NACK Test
        3) Test with multiple DHCP Servers

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
    DHCP_PKT_BOOTP_MIN_LEN = 300

    def __init__(self):
        DataplaneBaseTest.__init__(self)


    def setUp(self):
        DataplaneBaseTest.setUp(self)

        self.test_params = testutils.test_params_get()

        self.hostname = self.test_params['hostname']
        self.verified_option82 = False
        
        if 'other_client_port' in self.test_params:
            self.other_client_port = ast.literal_eval(self.test_params['other_client_port'])

        # These are the interfaces we are injected into that link to out leaf switches
        self.server_port_indices = ast.literal_eval(self.test_params['leaf_port_indices'])
        self.num_dhcp_servers = int(self.test_params['num_dhcp_servers'])

        self.assertTrue(self.num_dhcp_servers > 0,
                "Error: This test requires at least one DHCP server to be specified!")

        # We will simulate a responding DHCP server on the first interface in the provided set
        self.server_ip = self.test_params['server_ip']
        self.server_iface_mac = self.dataplane.get_mac(0, self.server_port_indices[0])

        self.relay_iface_ip = self.test_params['relay_iface_ip']
        self.relay_iface_mac = self.test_params['relay_iface_mac']

        self.client_iface_alias = self.test_params['client_iface_alias']
        self.client_port_index = int(self.test_params['client_port_index'])
        self.client_mac = self.dataplane.get_mac(0, self.client_port_index)

        self.switch_loopback_ip = self.test_params['switch_loopback_ip']

        self.uplink_mac = self.test_params['uplink_mac']

        # 'dual' for dual tor testing
        # 'single' for regular single tor testing
        self.dual_tor = (self.test_params['testing_mode'] == 'dual')

        self.testbed_mode = self.test_params['testbed_mode']

        # option82 is a byte string created by the relay agent. It contains the circuit_id and remote_id fields.
        # circuit_id is stored as suboption 1 of option 82.
        # It consists of the following:
        #  Byte 0: Suboption number, always set to 1
        #  Byte 1: Length of suboption data in bytes
        #  Bytes 2+: Suboption data
        # Our circuit_id string is of the form "hostname:portname"
        circuit_id_string = self.hostname + ":" + self.client_iface_alias
        self.option82 = struct.pack('BB', 1, len(circuit_id_string))
        self.option82 += circuit_id_string.encode('utf-8')

        # remote_id is stored as suboption 2 of option 82.
        # It consists of the following:
        #  Byte 0: Suboption number, always set to 2
        #  Byte 1: Length of suboption data in bytes
        #  Bytes 2+: Suboption data
        # Our remote_id string simply consists of the MAC address of the port that received the request
        remote_id_string = self.relay_iface_mac
        self.option82 += struct.pack('BB', 2, len(remote_id_string))
        self.option82 += remote_id_string.encode('utf-8')

        # In 'dual' testing mode, vlan ip is stored as suboption 5 of option 82.
        # It consists of the following:
        #  Byte 0: Suboption number, always set to 5
        #  Byte 1: Length of suboption data in bytes, always set to 4 (ipv4 addr has 4 bytes)
        #  Bytes 2+: vlan ip addr
        if self.dual_tor:
            link_selection = bytes(list(map(int, self.relay_iface_ip.split('.'))))
            self.option82 += struct.pack('BB', 5, 4)
            self.option82 += link_selection

        # We'll assign our client the IP address 1 greater than our relay interface (i.e., gateway) IP
        self.client_ip = incrementIpAddress(self.relay_iface_ip, 1) 
        self.client_subnet = self.test_params['relay_iface_netmask']

        self.dest_mac_address = self.test_params['dest_mac_address']
        self.client_udp_src_port = self.test_params['client_udp_src_port']


    def tearDown(self):
        DataplaneBaseTest.tearDown(self)


    """
     Packet generation functions/wrappers
    
    """

    def create_dhcp_discover_packet(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        discover_packet = testutils.dhcp_discover_packet(eth_client=self.client_mac, set_broadcast_bit=True)

        discover_packet[scapy.Ether].dst = dst_mac
        discover_packet[scapy.IP].sport = src_port

        if dst_mac != self.BROADCAST_MAC:
            discover_packet[scapy.IP].dst = self.switch_loopback_ip
            discover_packet[scapy.IP].src = self.client_ip

        return discover_packet

    def create_dhcp_discover_relayed_packet(self):
        my_chaddr = binascii.unhexlify(self.client_mac.replace(':', ''))
        my_chaddr += b'\x00\x00\x00\x00\x00\x00'

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
        # TODO: In IP layer, DHCP relay also replaces source IP with IP of interface on
        #       which it received the broadcast DHCPDISCOVER from client. This appears to
        #       be loopback. We could pull from minigraph and check here.
        ether = scapy.Ether(dst=self.BROADCAST_MAC, src=self.uplink_mac, type=0x0800)
        ip = scapy.IP(src=self.DEFAULT_ROUTE_IP, dst=self.BROADCAST_IP, len=328, ttl=64)
        udp = scapy.UDP(sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT, len=308)
        bootp = scapy.BOOTP(op=1,
                    htype=1,
                    hlen=6,
                    hops=1,
                    xid=0,
                    secs=0,
                    flags=0x8000,
                    ciaddr=self.DEFAULT_ROUTE_IP,
                    yiaddr=self.DEFAULT_ROUTE_IP,
                    siaddr=self.DEFAULT_ROUTE_IP,
                    giaddr=self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip,
                    chaddr=my_chaddr)
        bootp /= scapy.DHCP(options=[('message-type', 'discover'),
                    (82, self.option82),
                    ('end')])

        # If our bootp layer is too small, pad it
        pad_bytes = self.DHCP_PKT_BOOTP_MIN_LEN - len(bootp)
        if pad_bytes > 0:
            bootp /= scapy.PADDING('\x00' * pad_bytes)

        pkt = ether / ip / udp / bootp
        return pkt

    def create_dhcp_offer_packet(self):
        return testutils.dhcp_offer_packet(eth_server=self.server_iface_mac,
                    eth_dst=self.uplink_mac,
                    eth_client=self.client_mac,
                    ip_server=self.server_ip,
                    ip_dst=self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip,
                    ip_offered=self.client_ip,
                    port_dst=self.DHCP_SERVER_PORT,
                    ip_gateway=self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip,
                    netmask_client=self.client_subnet,
                    dhcp_lease=self.LEASE_TIME,
                    padding_bytes=0,
                    set_broadcast_bit=True)

    def create_dhcp_offer_relayed_packet(self):
        my_chaddr = binascii.unhexlify(self.client_mac.replace(':', ''))
        my_chaddr += b'\x00\x00\x00\x00\x00\x00'

        # Relay modifies the DHCPOFFER message in the following ways:
        #  1.) Replaces the source MAC with the MAC of the interface it received it on
        #  2.) Replaces the destination MAC with boradcast (ff:ff:ff:ff:ff:ff)
        #  3.) Replaces the source IP with the IP of the interface which the relay
        #      received it on
        #  4.) Replaces the destination IP with broadcast (255.255.255.255)
        #  5.) Replaces the destination port with the DHCP client port (68)
        ether = scapy.Ether(dst=self.BROADCAST_MAC, src=self.relay_iface_mac, type=0x0800)
        ip = scapy.IP(src=self.relay_iface_ip, dst=self.BROADCAST_IP, len=290, ttl=64)
        udp = scapy.UDP(sport=self.DHCP_SERVER_PORT, dport=self.DHCP_CLIENT_PORT, len=262)
        bootp = scapy.BOOTP(op=2,
                    htype=1,
                    hlen=6,
                    hops=0,
                    xid=0,
                    secs=0,
                    flags=0x8000,
                    ciaddr=self.DEFAULT_ROUTE_IP,
                    yiaddr=self.client_ip,
                    siaddr=self.server_ip,
                    giaddr=self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip,
                    chaddr=my_chaddr)
        bootp /= scapy.DHCP(options=[('message-type', 'offer'),
                    ('server_id', self.server_ip),
                    ('lease_time', self.LEASE_TIME),
                    ('subnet_mask', self.client_subnet),
                    ('end')])

        # TODO: Need to add this to the packet creation functions in PTF code first!
        # If our bootp layer is too small, pad it
        #pad_bytes = self.DHCP_PKT_BOOTP_MIN_LEN - len(bootp)
        #if pad_bytes > 0:
        #    bootp /= scapy.PADDING('\x00' * pad_bytes)

        pkt = ether / ip / udp / bootp
        return pkt

    def create_dhcp_request_packet(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        request_packet = testutils.dhcp_request_packet(
            eth_client=self.client_mac,
            ip_server=self.server_ip,
            ip_requested=self.client_ip,
            set_broadcast_bit=True
        )

        request_packet[scapy.Ether].dst = dst_mac
        request_packet[scapy.IP].sport = src_port

        if dst_mac != self.BROADCAST_MAC:
            request_packet[scapy.IP].dst = self.switch_loopback_ip
            request_packet[scapy.IP].src = self.client_ip

        return request_packet

    def create_dhcp_request_relayed_packet(self):
        my_chaddr = binascii.unhexlify(self.client_mac.replace(':', ''))
        my_chaddr += b'\x00\x00\x00\x00\x00\x00'

        # Here, the actual destination MAC should be the MAC of the leaf the relay
        # forwards through and the destination IP should be the IP of the DHCP server
        # the relay is forwarding to. We don't need to confirm these, so we'll
        # just mask them off later
        #
        # TODO: In IP layer, DHCP relay also replaces source IP with IP of interface on
        #       which it received the broadcast DHCPREQUEST from client. This appears to
        #       be loopback. We could pull from minigraph and check here.
        ether = scapy.Ether(dst=self.BROADCAST_MAC, src=self.uplink_mac, type=0x0800)
        ip = scapy.IP(src=self.DEFAULT_ROUTE_IP, dst=self.BROADCAST_IP, len=336, ttl=64)
        udp = scapy.UDP(sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT, len=316)
        bootp = scapy.BOOTP(op=1,
                    htype=1,
                    hlen=6,
                    hops=1,
                    xid=0,
                    secs=0,
                    flags=0x8000,
                    ciaddr=self.DEFAULT_ROUTE_IP,
                    yiaddr=self.DEFAULT_ROUTE_IP,
                    siaddr=self.DEFAULT_ROUTE_IP,
                    giaddr=self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip,
                    chaddr=my_chaddr)
        bootp /= scapy.DHCP(options=[('message-type', 'request'),
                    ('requested_addr', self.client_ip),
                    ('server_id', self.server_ip),
                    (82, self.option82),
                    ('end')])

        # If our bootp layer is too small, pad it
        pad_bytes = self.DHCP_PKT_BOOTP_MIN_LEN - len(bootp)
        if pad_bytes > 0:
            bootp /= scapy.PADDING('\x00' * pad_bytes)

        pkt = ether / ip / udp / bootp
        return pkt

    def create_dhcp_ack_packet(self):
        return testutils.dhcp_ack_packet(eth_server=self.server_iface_mac,
                    eth_dst=self.uplink_mac,
                    eth_client=self.client_mac,
                    ip_server=self.server_ip,
                    ip_dst=self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip,
                    ip_offered=self.client_ip,
                    port_dst=self.DHCP_SERVER_PORT,
                    ip_gateway=self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip,
                    netmask_client=self.client_subnet,
                    dhcp_lease=self.LEASE_TIME,
                    padding_bytes=0,
                    set_broadcast_bit=True)

    def create_dhcp_ack_relayed_packet(self):
        my_chaddr = binascii.unhexlify(self.client_mac.replace(':', ''))
        my_chaddr += b'\x00\x00\x00\x00\x00\x00'

        # Relay modifies the DHCPACK message in the following ways:
        #  1.) Replaces the source MAC with the MAC of the interface it received it on
        #  2.) Replaces the destination MAC with boradcast (ff:ff:ff:ff:ff:ff)
        #  3.) Replaces the source IP with the IP of the interface which the relay
        #      received it on
        #  4.) Replaces the destination IP with broadcast (255.255.255.255)
        #  5.) Replaces the destination port with the DHCP client port (68)
        ether = scapy.Ether(dst=self.BROADCAST_MAC, src=self.relay_iface_mac, type=0x0800)
        ip = scapy.IP(src=self.relay_iface_ip, dst=self.BROADCAST_IP, len=290, ttl=64)
        udp = scapy.UDP(sport=self.DHCP_SERVER_PORT, dport=self.DHCP_CLIENT_PORT, len=262)
        bootp = scapy.BOOTP(op=2,
                    htype=1,
                    hlen=6,
                    hops=0,
                    xid=0,
                    secs=0,
                    flags=0x8000,
                    ciaddr=self.DEFAULT_ROUTE_IP,
                    yiaddr=self.client_ip,
                    siaddr=self.server_ip,
                    giaddr=self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip,
                    chaddr=my_chaddr)
        bootp /= scapy.DHCP(options=[('message-type', 'ack'),
                    ('server_id', self.server_ip),
                    ('lease_time', self.LEASE_TIME),
                    ('subnet_mask', self.client_subnet),
                    ('end')])

        # TODO: Need to add this to the packet creation functions in PTF code first!
        # If our bootp layer is too small, pad it
        #pad_bytes = self.DHCP_PKT_BOOTP_MIN_LEN - len(bootp)
        #if pad_bytes > 0:
        #    bootp /= scapy.PADDING('\x00' * pad_bytes)

        pkt = ether / ip / udp / bootp
        return pkt



    """
     Send/receive functions

    """

    # Simulate client coming on VLAN and broadcasting a DHCPDISCOVER message
    def client_send_discover(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        # Form and send DHCPDISCOVER packet
        dhcp_discover = self.create_dhcp_discover_packet(dst_mac, src_port)
        testutils.send_packet(self, self.client_port_index, dhcp_discover)

    #Verify the relayed packet has option82 info or not. Sniffing for the relayed packet on leaves and 
    #once the packet is recieved checking for the destination and looking into options and verifying 
    #the option82 info

    def pkt_callback(self, pkt):
        if pkt.haslayer(scapy2.IP) and pkt.haslayer(scapy2.DHCP):
            if pkt.getlayer(scapy2.IP).dst in [self.server_ip] and pkt.getlayer(scapy2.DHCP) is not None:
                self.verified_option82 = False
                pkt_options = ''
                for option in pkt.getlayer(scapy2.DHCP).options:
                    if option[0] == 'relay_agent_information':
                        pkt_options = option[1]
                        break
                if self.option82 in pkt_options:
                    self.verified_option82 = True

    def Sniffer(self,iface):
        scapy2.sniff(iface=iface, filter="udp and (port 67 or 68)",prn=self.pkt_callback, store=0, timeout=5)


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
        masked_discover.set_do_not_care_scapy(scapy.UDP, "len")

        masked_discover.set_do_not_care_scapy(scapy.BOOTP, "sname")
        masked_discover.set_do_not_care_scapy(scapy.BOOTP, "file")

        # Count the number of these packets received on the ports connected to our leaves
        num_expected_packets = self.num_dhcp_servers
        discover_count = testutils.count_matched_packets_all_ports(self, masked_discover, self.server_port_indices)
        self.assertTrue(discover_count == num_expected_packets,
                "Failed: Discover count of %d != %d" % (discover_count, num_expected_packets))

    # Simulate a DHCP server sending a DHCPOFFER message to client.
    # We do this by injecting a DHCPOFFER message on the link connected to one
    # of our leaf switches.
    def server_send_offer(self):
        dhcp_offer = self.create_dhcp_offer_packet()
        testutils.send_packet(self, self.server_port_indices[0], dhcp_offer)

    # Verify that the DHCPOFFER would be received by our simulated client
    def verify_offer_received(self):
        dhcp_offer = self.create_dhcp_offer_relayed_packet()

        masked_offer = Mask(dhcp_offer)

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

        masked_offer.set_do_not_care_scapy(scapy.UDP, "len")
        masked_offer.set_do_not_care_scapy(scapy.UDP, "chksum")

        masked_offer.set_do_not_care_scapy(scapy.BOOTP, "sname")
        masked_offer.set_do_not_care_scapy(scapy.BOOTP, "file")

        # NOTE: verify_packet() will fail for us via an assert, so no need to check a return value here
        testutils.verify_packet(self, masked_offer, self.client_port_index)

    # Simulate our client sending a DHCPREQUEST message
    def client_send_request(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        dhcp_request = self.create_dhcp_request_packet(dst_mac, src_port)
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
        masked_request.set_do_not_care_scapy(scapy.UDP, "len")

        masked_request.set_do_not_care_scapy(scapy.BOOTP, "sname")
        masked_request.set_do_not_care_scapy(scapy.BOOTP, "file")

        # Count the number of these packets received on the ports connected to our leaves
        num_expected_packets = self.num_dhcp_servers
        request_count = testutils.count_matched_packets_all_ports(self, masked_request, self.server_port_indices)
        self.assertTrue(request_count == num_expected_packets,
                "Failed: Request count of %d != %d" % (request_count, num_expected_packets))

    # Simulate a DHCP server sending a DHCPOFFER message to client from one of our leaves
    def server_send_ack(self):
        dhcp_ack = self.create_dhcp_ack_packet()
        testutils.send_packet(self, self.server_port_indices[0], dhcp_ack)

    # Verify that the DHCPACK would be received by our simulated client
    def verify_ack_received(self):
        dhcp_ack = self.create_dhcp_ack_relayed_packet()

        masked_ack = Mask(dhcp_ack)

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

        masked_ack.set_do_not_care_scapy(scapy.UDP, "len")
        masked_ack.set_do_not_care_scapy(scapy.UDP, "chksum")

        masked_ack.set_do_not_care_scapy(scapy.BOOTP, "sname")
        masked_ack.set_do_not_care_scapy(scapy.BOOTP, "file")

        # NOTE: verify_packet() will fail for us via an assert, so no need to check a return value here
        testutils.verify_packet(self, masked_ack, self.client_port_index)

    def verify_dhcp_relay_pkt_on_other_client_port_with_no_padding(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        # Form and send DHCP Relay packet
        dhcp_request = self.create_dhcp_request_packet(dst_mac, src_port)
        testutils.send_packet(self, self.client_port_index, dhcp_request)

        # Mask off fields we don't care about matching
        masked_request = Mask(dhcp_request)
        masked_request.set_do_not_care_scapy(scapy.Ether, "src")

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
        masked_request.set_do_not_care_scapy(scapy.DHCP, "options")
        masked_request.set_do_not_care_scapy(scapy.BOOTP, "sname")
        masked_request.set_do_not_care_scapy(scapy.BOOTP, "file")

        masked_request.set_do_not_care_scapy(scapy.BOOTP, "yiaddr")
        masked_request.set_do_not_care_scapy(scapy.BOOTP, "ciaddr")
        masked_request.set_do_not_care_scapy(scapy.BOOTP, "siaddr")
        masked_request.set_do_not_care_scapy(scapy.BOOTP, "giaddr")
        masked_request.set_do_not_care_scapy(scapy.BOOTP, "chaddr")

        try :
            testutils.verify_packets_any(self, masked_request, self.other_client_port)
        except Exception:
            self.assertTrue(False,"DHCP Relay packet not matched  or Padded extra on client side")

    def verify_dhcp_relay_pkt_on_server_port_with_no_padding(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        # Form and send DHCP Relay packet
        dhcp_request = self.create_dhcp_request_packet(dst_mac, src_port)
        testutils.send_packet(self, self.client_port_index, dhcp_request)

        # Mask off fields we don't care about matching
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

        try :
            testutils.verify_packets_any(self, masked_request, self.server_port_indices)
        except Exception:
            self.assertTrue(False,"DHCP Relay packet not matched or Padded extra on server side")

    def runTest(self):
        # Start sniffer process for each server port to capture DHCP packet
        # and then verify option 82
        for interface_index in self.server_port_indices:
            t1 = Thread(target=self.Sniffer, args=("eth"+str(interface_index),))
            t1.start()

        self.client_send_discover(self.dest_mac_address, self.client_udp_src_port)
        self.verify_relayed_discover()
        self.server_send_offer()
        self.verify_offer_received()
        self.client_send_request(self.dest_mac_address, self.client_udp_src_port)
        self.verify_relayed_request()
        self.server_send_ack()
        self.verify_ack_received()
        self.assertTrue(self.verified_option82,"Failed: Verifying option 82")

        ## Below verification will be done only when client port is set in ptf_runner
        if 'other_client_port' in self.test_params:
            self.verify_dhcp_relay_pkt_on_other_client_port_with_no_padding(self.dest_mac_address, self.client_udp_src_port)
            self.verify_dhcp_relay_pkt_on_server_port_with_no_padding(self.dest_mac_address, self.client_udp_src_port)
