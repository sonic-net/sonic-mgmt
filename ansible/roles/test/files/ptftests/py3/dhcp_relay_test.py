import ast
import struct
import ipaddress
import binascii
import os
import logging

# Packet Test Framework imports
import ptf
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf import config
from ptf.base_tests import BaseTest
from ptf.mask import Mask
import scapy.all as scapy2
from threading import Thread

logger = logging.getLogger(__name__)


# Helper function to increment an IP address
# ip_addr should be passed as a dot-decimal string
# Return value is also a dot-decimal string
def incrementIpAddress(ip_addr, by=1):
    new_addr = ipaddress.ip_address(str(ip_addr))
    new_addr = new_addr + by
    return str(new_addr)


def log_dhcp_packet_info(packet):
    if isinstance(packet, Mask):
        packet = packet.packet
    logger.info("Ether: src_mac={}, dst_mac={}".format(packet[scapy.Ether].src, packet[scapy.Ether].dst))
    logger.info("IP: src_ip={}, dst_ip={}".format(packet[scapy.IP].src, packet[scapy.IP].dst))
    logger.info("UDP: sport={}, dport={}".format(packet[scapy.UDP].sport, packet[scapy.UDP].dport))
    chaddr = packet[scapy.BOOTP].chaddr
    logger.info("BOOTP: op={}, hops={}, ciaddr={}, yiaddr={}, siaddr={}, giaddr={}, chaddr={}"
                .format(packet[scapy.BOOTP].op, packet[scapy.BOOTP].hops, packet[scapy.BOOTP].ciaddr,
                        packet[scapy.BOOTP].yiaddr, packet[scapy.BOOTP].siaddr, packet[scapy.BOOTP].giaddr,
                        binascii.hexlify(chaddr[:6]).decode('utf-8')))


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
   (ptf --test-dir ptftests dhcp_relay_test.DHCPTest --platform remote -t "hostname=\"str-s6000-acs-12\";
    client_port_index=\"1\"; client_iface_alias=\"fortyGigE0/4\"; leaf_port_indices=\"[29, 31, 28, 30]\";
    num_dhcp_servers=\"48\"; server_ip=\"192.0.0.1\"; relay_iface_ip=\"192.168.0.1\";
    relay_iface_mac=\"ec:f4:bb:fe:88:0a\"; relay_iface_netmask=\"255.255.255.224\""
    --disable-vxlan --disable-geneve --disable-erspan --disable-mpls --disable-nvgre)

 The above command is configured to test with the following configuration:
  - VLAN IP of DuT is 192.168.0.1, MAC address is ec:f4:bb:fe:88:0a
    (this is configured to test against str-s6000-acs-12)
  - Simulated client will live on PTF interface eth4 (interface number 4)
  - Assumes leaf switches are connected to injected PTF interfaces 28, 29, 30, 31
  - Test will simulate replies from server with IP '192.0.0.1'
  - Simulated server will offer simulated client IP '192.168.0.2' with a subnet of '255.255.255.0'
    (this should be in the VLAN of DuT)


 DHCP Relay currently installed with SONiC is isc-dhcp-relay

 TODO???:
        1) DHCP Renew Test
        2) DHCP NACK Test
        3) Test with multiple DHCP Servers

"""


class DHCPTest(DataplaneBaseTest):

    # DHCP packet macro's
    BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
    BROADCAST_IP = '255.255.255.255'
    DEFAULT_ROUTE_IP = '0.0.0.0'
    DHCP_CLIENT_PORT = 68
    DHCP_SERVER_PORT = 67
    DHCP_LEASE_TIME_OFFSET = 292
    DHCP_LEASE_TIME_LEN = 6
    LEASE_TIME = 86400
    DHCP_PKT_BOOTP_MIN_LEN = 300
    DHCP_ETHER_TYPE_IP = 0x0800
    DHCP_BOOTP_OP_REPLY = 2
    DHCP_BOOTP_HTYPE_ETHERNET = 1
    DHCP_BOOTP_HLEN_ETHERNET = 6
    DHCP_BOOTP_FLAGS_BROADCAST_REPLY = 0x8000
    # DHCP option sub types
    CIRCUIT_ID_SUBOPTION = 1
    REMOTE_ID_SUBOPTION = 2
    LINK_SELECTION_SUBOPTION = 5
    SERVER_ID_OVERRIDE_SUBOPTION = 11
    VRF_NAME_SUBOPTION = 151
    MAX_HOP_COUNT = 16

    def __init__(self):
        DataplaneBaseTest.__init__(self)

    def setUp(self):
        DataplaneBaseTest.setUp(self)

        self.test_params = testutils.test_params_get()

        self.hostname = self.test_params['hostname']
        self.verified_option82 = False

        if 'other_client_port' in self.test_params:
            self.other_client_port = ast.literal_eval(
                self.test_params['other_client_port'])

        # These are the interfaces we are injected into that link to out leaf switches
        self.server_port_indices = ast.literal_eval(
            self.test_params['leaf_port_indices'])
        self.num_dhcp_servers = int(self.test_params['num_dhcp_servers'])

        self.assertTrue(self.num_dhcp_servers > 0,
                        "Error: This test requires at least one DHCP server to be specified!")

        # We will simulate a responding DHCP server on the first interface in the provided set
        self.server_ip = self.test_params['server_ip']
        self.server_iface_mac = self.dataplane.get_mac(
            0, self.server_port_indices[0])

        self.relay_iface_ip = self.test_params['relay_iface_ip']
        self.relay_iface_mac = self.test_params.get('relay_iface_mac', '')

        self.client_iface_alias = self.test_params.get('client_iface_alias', '')
        self.client_port_index = int(self.test_params['client_port_index'])
        self.client_mac = self.dataplane.get_mac(0, self.client_port_index)

        self.switch_loopback_ip = self.test_params['switch_loopback_ip']
        self.relay_agent = self.test_params['relay_agent']
        self.link_selection = self.test_params.get('link_selection', None)
        self.source_interface = self.test_params.get('source_interface', None)
        self.server_id_override = self.test_params.get('server_id_override', None)
        self.server_vrf = self.test_params.get('server_vrf', None)
        self.vrf_selection = self.test_params.get('vrf_selection', None)
        self.portchannels_ip_list = self.test_params.get('portchannels_ip_list', None)
        self.agent_relay_mode = self.test_params.get('agent_relay_mode', None)
        self.max_hop_count = self.test_params.get('max_hop_count', None)
        self.client_vrf = self.test_params.get('client_vrf', None)
        self.dhcpv4_disable_flag = self.test_params.get('dhcpv4_disable_flag', None)
        if self.relay_agent == "sonic-relay-agent":
            if (self.link_selection and self.source_interface) or self.server_vrf:
                self.link_selection_ip = self.test_params['link_selection_ip']

        self.uplink_mac = self.test_params['uplink_mac']

        # 'dual' for dual tor testing
        # 'single' for regular single tor testing
        self.dual_tor = (self.test_params['testing_mode'] == 'dual')
        self.vlan_iface_name = self.test_params.get('downlink_vlan_iface_name', None)

        # option82 is a byte string created by the relay agent. It contains the circuit_id and remote_id fields.
        # circuit_id is stored as suboption 1 of option 82.
        # It consists of the following:
        #  Byte 0: Suboption number, always set to 1
        #  Byte 1: Length of suboption data in bytes
        #  Bytes 2+: Suboption data
        # Our circuit_id string is of the form "hostname:portname"
        circuit_id_string = self.hostname + ":" + self.client_iface_alias
        if self.relay_agent == "sonic-relay-agent":
            circuit_id_string = circuit_id_string + ":" + self.vlan_iface_name
        self.option82 = struct.pack('BB', self.CIRCUIT_ID_SUBOPTION, len(circuit_id_string))
        self.option82 += circuit_id_string.encode('utf-8')

        # remote_id is stored as suboption 2 of option 82.
        # It consists of the following:
        #  Byte 0: Suboption number, always set to 2
        #  Byte 1: Length of suboption data in bytes
        #  Bytes 2+: Suboption data
        # Our remote_id string simply consists of the MAC address of the port that received the request
        remote_id_string = self.relay_iface_mac
        self.option82 += struct.pack('BB', self.REMOTE_ID_SUBOPTION, len(remote_id_string))
        self.option82 += remote_id_string.encode('utf-8')

        if self.relay_agent == "sonic-relay-agent":
            # Structure:
            #  Byte 0: Suboption number, always set to 5
            #  Byte 1: Length of suboption data (4 bytes for IPv4)
            #  Bytes 2–5: The link selection IP address (in byte format)
            if (self.link_selection and self.source_interface) or self.server_vrf:
                link_selection_ip = bytes(list(map(int, self.link_selection_ip.split('.'))))
                self.option82 += struct.pack('BB', self.LINK_SELECTION_SUBOPTION, 4)
                self.option82 += link_selection_ip

            # The structure is as follows:
            #  Byte 0: Suboption number, always set to 11
            #  Byte 1: Length of suboption data (4 bytes for an IPv4 address)
            #  Bytes 2–5: The IPv4 address of the relay interface (in byte format)
            if self.server_id_override or self.server_vrf:
                server_id_override = bytes(list(map(int, self.relay_iface_ip.split('.'))))
                self.option82 += struct.pack('BB', self.SERVER_ID_OVERRIDE_SUBOPTION, 4)
                self.option82 += server_id_override

            # Sub-option 151 (VRF Name) is included if any VRF type is specified.
            # It conveys the client VRF name to the DHCP server.
            # Structure:
            #  Byte 0: Suboption number, always set to 151
            #  Byte 1: Length of VRF name + 1 (to pad with a null byte)
            #  Bytes 2+: Null byte followed by the UTF-8 encoded VRF name
            if self.server_vrf:
                vrf_data = self.client_vrf
                vrf_bytes = '\x00' + vrf_data
                self.option82 += struct.pack('BB', self.VRF_NAME_SUBOPTION, len(vrf_bytes))
                self.option82 += vrf_bytes.encode('utf-8')

        # In 'dual' testing mode, vlan ip is stored as suboption 5 of option 82.
        # It consists of the following:
        #  Byte 0: Suboption number, always set to 5
        #  Byte 1: Length of suboption data in bytes, always set to 4 (ipv4 addr has 4 bytes)
        #  Bytes 2+: vlan ip addr
        if self.dual_tor:
            link_selection = bytes(
                list(map(int, self.relay_iface_ip.split('.'))))
            self.option82 += struct.pack('BB', self.LINK_SELECTION_SUBOPTION, 4)
            self.option82 += link_selection

        # We'll assign our client the IP address 1 greater than our relay interface (i.e., gateway) IP
        self.client_ip = incrementIpAddress(self.relay_iface_ip, 1)
        self.client_subnet = self.test_params['relay_iface_netmask']

        self.dest_mac_address = self.test_params['dest_mac_address']
        self.client_udp_src_port = self.test_params['client_udp_src_port']
        self.enable_source_port_ip_in_relay = self.test_params.get('enable_source_port_ip_in_relay', False)

    def tearDown(self):
        DataplaneBaseTest.tearDown(self)

    """
     Packet generation functions/wrappers

    """

    def create_dhcp_discover_packet(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        discover_packet = testutils.dhcp_discover_packet(eth_client=self.client_mac, set_broadcast_bit=True)

        if not self.agent_relay_mode:
            discover_packet[scapy.Ether].dst = dst_mac
            discover_packet[scapy.IP].sport = src_port

            if dst_mac != self.BROADCAST_MAC:
                discover_packet[scapy.IP].dst = self.switch_loopback_ip
                discover_packet[scapy.IP].src = self.client_ip
        else:
            # Sub-option 1: Circuit ID (VLAN 100)
            # Circuit ID sub-option type 1, length 7, data 'Vlan100'
            circuit_id = b'\x01' + bytes([7]) + b'Vlan100'

            # Sub-option 2: Remote ID (MAC address)
            # Remote ID sub-option type 2, length 6, MAC address
            remote_id = b'\x02' + bytes([6]) + bytes.fromhex("112233445566")
            # Combine the new sub-options for relay
            relay_option82 = circuit_id + remote_id

            discover_packet[scapy.Ether].dst = self.uplink_mac
            discover_packet[scapy.IP].src = self.client_ip
            discover_packet[scapy.IP].dst = self.switch_loopback_ip
            discover_packet[scapy.BOOTP].hops = self.max_hop_count if self.max_hop_count == self.MAX_HOP_COUNT else 1
            discover_packet[scapy.BOOTP].giaddr = self.switch_loopback_ip
            discover_packet[scapy.DHCP].options.insert(
                discover_packet[scapy.DHCP].options.index("end"),
                (82, relay_option82)
            )

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
        ether = scapy.Ether(dst=self.BROADCAST_MAC,
                            src=self.uplink_mac, type=0x0800)

        if self.server_vrf is None and self.vrf_selection is None:
            source_ip = self.switch_loopback_ip
            if self.enable_source_port_ip_in_relay:
                source_ip = self.relay_iface_ip
        else:
            source_ip = self.portchannels_ip_list[0]

        if ((self.link_selection and self.source_interface) or
           self.server_vrf or self.dual_tor or self.agent_relay_mode):
            giaddr = self.switch_loopback_ip
        elif self.server_id_override or not self.dual_tor:
            giaddr = self.relay_iface_ip

        ip = scapy.IP(src=source_ip,
                      dst=self.BROADCAST_IP, len=328, ttl=64)
        udp = scapy.UDP(sport=self.DHCP_SERVER_PORT,
                        dport=self.DHCP_SERVER_PORT, len=308)

        # Relay-side behavior based on agent_mode
        if self.agent_relay_mode == "discard":
            dhcp_options = [('message-type', 'discover'), (82, self.option82), ('end')]

        elif self.agent_relay_mode == "replace":
            dhcp_options = [('message-type', 'discover'), (82, self.option82), ('end')]

        elif self.agent_relay_mode == "append":
            # Sub-option 1: Circuit ID (VLAN 100)
            # Circuit ID sub-option type 1, length 7, data 'Vlan100'
            circuit_id = b'\x01' + bytes([7]) + b'Vlan100'

            # Sub-option 2: Remote ID (MAC address)
            # Remote ID sub-option type 2, length 6, MAC address
            remote_id = b'\x02' + bytes([6]) + bytes.fromhex("112233445566")

            # Create two separate Option 82 entries (client and relay)
            relay_option82 = circuit_id + remote_id  # Combine the new sub-options for relay

            # Construct DHCP options with both client and relay Option 82
            dhcp_options = [
                ('message-type', 'discover'),
                (82, relay_option82),   # New Option 82 from the relay
                (82, self.option82),  # Original Option 82 from the client
                ('end')
            ]

        else:
            dhcp_options = [('message-type', 'discover'),
                            (82, self.option82),
                            ('end')]

        if self.max_hop_count == self.MAX_HOP_COUNT:
            hops = 17
        elif self.agent_relay_mode:
            hops = 2
        else:
            hops = 1

        bootp = scapy.BOOTP(op=1,
                            htype=1,
                            hlen=6,
                            hops=hops,
                            xid=0,
                            secs=0,
                            flags=0x8000,
                            ciaddr=self.DEFAULT_ROUTE_IP,
                            yiaddr=self.DEFAULT_ROUTE_IP,
                            siaddr=self.DEFAULT_ROUTE_IP,
                            giaddr=giaddr,
                            chaddr=my_chaddr)

        bootp /= scapy.DHCP(options=dhcp_options)

        return self.merge_layers_to_packet(ether, ip, udp, bootp)

    def create_dhcp_unknown_relayed_packet_from_client(self):
        my_chaddr = binascii.unhexlify(self.client_mac.replace(':', ''))
        my_chaddr += b'\x00\x00\x00\x00\x00\x00'

        ether = scapy.Ether(dst=self.BROADCAST_MAC,
                            src=self.uplink_mac, type=0x0800)

        if self.server_vrf is None and self.vrf_selection is None:
            source_ip = self.switch_loopback_ip
            if self.enable_source_port_ip_in_relay:
                source_ip = self.relay_iface_ip
        else:
            source_ip = self.portchannels_ip_list[0]

        if ((self.link_selection and self.source_interface) or
           self.server_vrf or self.dual_tor or self.agent_relay_mode):
            giaddr = self.switch_loopback_ip
        elif self.server_id_override or not self.dual_tor:
            giaddr = self.relay_iface_ip

        ip = scapy.IP(src=source_ip,
                      dst=self.BROADCAST_IP, len=328, ttl=64)
        udp = scapy.UDP(sport=self.DHCP_SERVER_PORT,
                        dport=self.DHCP_SERVER_PORT, len=308)
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
                            giaddr=giaddr,
                            chaddr=my_chaddr)
        bootp /= scapy.DHCP(options=[('message-type', 11),
                                     (82, self.option82),
                                     ('end')])

        return self.merge_layers_to_packet(ether, ip, udp, bootp)

    def create_dhcp_decline_relayed_packet(self):
        my_chaddr = binascii.unhexlify(self.client_mac.replace(':', ''))
        my_chaddr += b'\x00\x00\x00\x00\x00\x00'

        ether = scapy.Ether(dst=self.BROADCAST_MAC,
                            src=self.uplink_mac, type=0x0800)

        if self.server_vrf is None and self.vrf_selection is None:
            source_ip = self.switch_loopback_ip
            if self.enable_source_port_ip_in_relay:
                source_ip = self.relay_iface_ip
        else:
            source_ip = self.portchannels_ip_list[0]

        if ((self.link_selection and self.source_interface) or
           self.server_vrf or self.dual_tor or self.agent_relay_mode):
            giaddr = self.switch_loopback_ip
        elif self.server_id_override or not self.dual_tor:
            giaddr = self.relay_iface_ip

        ip = scapy.IP(src=source_ip,
                      dst=self.BROADCAST_IP, len=328, ttl=64)
        udp = scapy.UDP(sport=self.DHCP_SERVER_PORT,
                        dport=self.DHCP_SERVER_PORT)
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
                            giaddr=giaddr,
                            chaddr=my_chaddr)
        bootp /= scapy.DHCP(options=[('message-type', "decline"),
                                     (82, self.option82),
                                     ('end')])

        return self.merge_layers_to_packet(ether, ip, udp, bootp)

    def dhcp_offer_packet(self,
                          eth_server="00:01:02:03:04:05",
                          eth_dst="06:07:08:09:10:11",
                          eth_client="12:13:14:15:16:17",
                          ip_server="0.1.2.3",
                          ip_dst="255.255.255.255",
                          ip_offered="8.9.10.11",
                          port_dst=DHCP_CLIENT_PORT,
                          netmask_client="255.255.255.0",
                          ip_gateway=DEFAULT_ROUTE_IP,
                          dhcp_lease=LEASE_TIME,
                          padding_bytes=0,
                          set_broadcast_bit=False,
                          ):
        """
        Return a DHCPOFFER packet
        Supports a few parameters:
        @param eth_server MAC address of DHCP server
        @param eth_dst MAC address of destination (DHCP Client, Relay agent) or broadcast (ff:ff:ff:ff:ff:ff)
        @param eth_client MAC address of DHCP client
        @param ip_server IP address of DHCP server
        @param ip_dst IP address of destination (DHCP Client, Relay agent) or broadcast (255.255.255.255)
        @param ip_offered IP address that server is assigning to client
        @param ip_gateway Gateway IP Address, address of relay agent if encountered
        @param port_dst Destination port of packet (default: DHCP_PORT_CLIENT)
        @param netmask_client Subnet mask of client
        @param dhcp_lease Time in seconds of DHCP lease
        @param padding_bytes Number of '\x00' bytes to append to end of packet
        Destination IP can be unicast or broadcast (255.255.255.255)
        Source port is always 67 (DHCP server port)
        Destination port by default is 68 (DHCP client port),
        but can be also be 67 (DHCP server port) if being sent to a DHCP relay agent
        """
        my_chaddr = binascii.unhexlify(eth_client.replace(':', ''))
        my_chaddr += b'\x00\x00\x00\x00\x00\x00'

        siaddr = ip_server
        pkt = scapy.Ether(dst=eth_dst, src=eth_server,
                          type=self.DHCP_ETHER_TYPE_IP)
        pkt /= scapy.IP(src=ip_server, dst=ip_dst, ttl=128, id=0)
        pkt /= scapy.UDP(sport=self.DHCP_SERVER_PORT, dport=port_dst)
        pkt /= scapy.BOOTP(
            op=self.DHCP_BOOTP_OP_REPLY,
            htype=self.DHCP_BOOTP_HTYPE_ETHERNET,
            hlen=self.DHCP_BOOTP_HLEN_ETHERNET,
            hops=0,
            xid=0,
            secs=0,
            flags=self.DHCP_BOOTP_FLAGS_BROADCAST_REPLY if set_broadcast_bit else 0,
            ciaddr=self.DEFAULT_ROUTE_IP,
            yiaddr=ip_offered,
            siaddr=siaddr,
            giaddr=ip_gateway,
            chaddr=my_chaddr,
        )
        # The length of option82 is 41 bytes, and dhcp relay will strip option82,
        # when the length of next option is bigger than 42 bytes,
        # it could introduce the overwritten issue.
        pkt /= scapy.DHCP(
            options=[
                ("message-type", "offer"),
                ("server_id", siaddr),
                ("lease_time", int(dhcp_lease)),
                ("subnet_mask", netmask_client),
                (82, self.option82),
                ("vendor_class_id",
                 "http://0.0.0.0/this_is_a_very_very_long_path/test.bin".encode('utf-8')),
                ("end"),
            ]
        )
        if padding_bytes:
            pkt /= scapy.PADDING("\x00" * padding_bytes)
        return pkt

    def create_dhcp_offer_packet(self):
        if (self.link_selection and self.source_interface) or self.dual_tor:
            ip_dst = self.switch_loopback_ip
            ip_gateway = self.switch_loopback_ip
        elif self.server_id_override or not self.dual_tor:
            ip_dst = self.relay_iface_ip
            ip_gateway = self.relay_iface_ip

        return self.dhcp_offer_packet(
            eth_server=self.server_iface_mac,
            eth_dst=self.uplink_mac,
            eth_client=self.client_mac,
            ip_server=self.server_ip[0],
            ip_dst=ip_dst,
            ip_offered=self.client_ip,
            port_dst=self.DHCP_SERVER_PORT,
            ip_gateway=ip_gateway,
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
        ether = scapy.Ether(dst=self.BROADCAST_MAC,
                            src=self.relay_iface_mac, type=self.DHCP_ETHER_TYPE_IP)
        ip = scapy.IP(src=self.relay_iface_ip, dst=self.BROADCAST_IP, ttl=64)
        udp = scapy.UDP(sport=self.DHCP_SERVER_PORT,
                        dport=self.DHCP_CLIENT_PORT)

        giaddr = self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip
        siaddr = self.server_ip[0]
        if self.relay_agent == "sonic-relay-agent":
            if self.server_id_override:
                giaddr = self.relay_iface_ip
            elif (self.link_selection and self.source_interface):
                giaddr = self.switch_loopback_ip

        bootp = scapy.BOOTP(op=2,
                            htype=1,
                            hlen=6,
                            hops=0,
                            xid=0,
                            secs=0,
                            flags=0x8000,
                            ciaddr=self.DEFAULT_ROUTE_IP,
                            yiaddr=self.client_ip,
                            siaddr=siaddr,
                            giaddr=giaddr,
                            chaddr=my_chaddr)
        bootp /= scapy.DHCP(options=[('message-type', 'offer'),
                                     ('server_id', siaddr),
                                     ('lease_time', self.LEASE_TIME),
                                     ('subnet_mask', self.client_subnet),
                                     ("vendor_class_id",
                                      "http://0.0.0.0/this_is_a_very_very_long_path/test.bin".encode('utf-8')),
                                     ('end')])

        return self.merge_layers_to_packet(ether, ip, udp, bootp)

    def create_dhcp_request_packet(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        request_packet = testutils.dhcp_request_packet(
            eth_client=self.client_mac,
            ip_server=self.server_ip[0],
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
        ether = scapy.Ether(dst=self.BROADCAST_MAC,
                            src=self.uplink_mac, type=0x0800)

        if self.server_vrf is None and self.vrf_selection is None:
            source_ip = self.switch_loopback_ip
            if self.enable_source_port_ip_in_relay:
                source_ip = self.relay_iface_ip
        else:
            source_ip = self.portchannels_ip_list[0]

        ip = scapy.IP(src=source_ip,
                      dst=self.BROADCAST_IP, len=336, ttl=64)
        udp = scapy.UDP(sport=self.DHCP_SERVER_PORT,
                        dport=self.DHCP_SERVER_PORT, len=316)
        # Choose giaddr and siaddr based on test mode
        if ((self.link_selection and self.source_interface) or self.server_vrf or self.dual_tor):
            giaddr = self.switch_loopback_ip
        elif self.server_id_override or not self.dual_tor:
            giaddr = self.relay_iface_ip

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
                            giaddr=giaddr,
                            chaddr=my_chaddr)
        bootp /= scapy.DHCP(options=[('message-type', 'request'),
                                     ('requested_addr', self.client_ip),
                                     ('server_id', self.server_ip[0]),
                                     (82, self.option82),
                                     ('end')])

        return self.merge_layers_to_packet(ether, ip, udp, bootp)

    def create_dhcp_inform_relayed_packet(self):
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
        ether = scapy.Ether(dst=self.BROADCAST_MAC,
                            src=self.uplink_mac, type=0x0800)

        if self.server_vrf is None and self.vrf_selection is None:
            source_ip = self.switch_loopback_ip
            if self.enable_source_port_ip_in_relay:
                source_ip = self.relay_iface_ip
        else:
            source_ip = self.portchannels_ip_list[0]

        if ((self.link_selection and self.source_interface) or
           self.server_vrf or self.dual_tor or self.agent_relay_mode):
            giaddr = self.switch_loopback_ip
        elif self.server_id_override or not self.dual_tor:
            giaddr = self.relay_iface_ip

        ip = scapy.IP(src=source_ip,
                      dst=self.BROADCAST_IP, len=336, ttl=64)
        udp = scapy.UDP(sport=self.DHCP_SERVER_PORT,
                        dport=self.DHCP_SERVER_PORT, len=316)
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
                            giaddr=giaddr,
                            chaddr=my_chaddr)
        bootp /= scapy.DHCP(options=[('message-type', 'inform'),
                                     (82, self.option82),
                                     ('end')])

        return self.merge_layers_to_packet(ether, ip, udp, bootp)

    def create_dhcp_release_relayed_packet(self):
        my_chaddr = binascii.unhexlify(self.client_mac.replace(':', ''))
        my_chaddr += b'\x00\x00\x00\x00\x00\x00'

        ether = scapy.Ether(dst=self.BROADCAST_MAC,
                            src=self.uplink_mac, type=self.DHCP_ETHER_TYPE_IP)

        if self.server_vrf is None and self.vrf_selection is None:
            source_ip = self.switch_loopback_ip
            if self.enable_source_port_ip_in_relay:
                source_ip = self.relay_iface_ip
        else:
            source_ip = self.portchannels_ip_list[0]

        if ((self.link_selection and self.source_interface) or
           self.server_vrf or self.dual_tor or self.agent_relay_mode):
            giaddr = self.switch_loopback_ip
        elif self.server_id_override or not self.dual_tor:
            giaddr = self.relay_iface_ip

        ip = scapy.IP(src=source_ip,
                      dst=self.server_ip[0], len=328, ttl=64)
        udp = scapy.UDP(sport=self.DHCP_SERVER_PORT,
                        dport=self.DHCP_SERVER_PORT, len=308)
        bootp = scapy.BOOTP(op=1,
                            htype=1,
                            hlen=6,
                            hops=1,
                            xid=0,
                            secs=0,
                            flags=0x0000,
                            ciaddr=self.client_ip,
                            yiaddr=self.DEFAULT_ROUTE_IP,
                            siaddr=self.DEFAULT_ROUTE_IP,
                            giaddr=giaddr,
                            chaddr=my_chaddr)
        bootp /= scapy.DHCP(options=[('message-type', 'release'),
                                     ('server_id', self.server_ip[0]),
                                     (82, self.option82),
                                     ('end')])

        return self.merge_layers_to_packet(ether, ip, udp, bootp)

    def create_dhcp_ack_packet(self):
        if self.server_id_override:
            ip_dst = self.relay_iface_ip
            ip_gateway = self.relay_iface_ip
        elif (self.link_selection and self.source_interface):
            ip_dst = self.switch_loopback_ip
            ip_gateway = self.switch_loopback_ip
        else:
            ip_dst = self.relay_iface_ip if not self.dual_tor else self.switch_loopback_ip
            ip_gateway = ip_dst

        dhcp_ack_packet = testutils.dhcp_ack_packet(
                          eth_server=self.server_iface_mac,
                          eth_dst=self.uplink_mac,
                          eth_client=self.client_mac,
                          ip_server=self.server_ip[0],
                          ip_dst=ip_dst,
                          ip_offered=self.client_ip,
                          port_dst=self.DHCP_SERVER_PORT,
                          ip_gateway=ip_gateway,
                          netmask_client=self.client_subnet,
                          dhcp_lease=self.LEASE_TIME,
                          padding_bytes=0,
                          set_broadcast_bit=True)
        if (self.link_selection and self.source_interface):
            dhcp_ack_packet[scapy.DHCP].options.insert(
                dhcp_ack_packet[scapy.DHCP].options.index("end"),
                (82, self.option82)
            )

        return dhcp_ack_packet

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
        ether = scapy.Ether(dst=self.BROADCAST_MAC,
                            src=self.relay_iface_mac, type=0x0800)
        ip = scapy.IP(src=self.relay_iface_ip,
                      dst=self.BROADCAST_IP, len=290, ttl=64)
        udp = scapy.UDP(sport=self.DHCP_SERVER_PORT,
                        dport=self.DHCP_CLIENT_PORT, len=262)
        # Choose giaddr based on test mode
        if (self.link_selection and self.source_interface) or self.dual_tor:
            giaddr = self.switch_loopback_ip
        elif self.server_id_override or not self.dual_tor:
            giaddr = self.relay_iface_ip

        bootp = scapy.BOOTP(op=2,
                            htype=1,
                            hlen=6,
                            hops=0,
                            xid=0,
                            secs=0,
                            flags=0x8000,
                            ciaddr=self.DEFAULT_ROUTE_IP,
                            yiaddr=self.client_ip,
                            siaddr=self.server_ip[0],
                            giaddr=giaddr,
                            chaddr=my_chaddr)
        bootp /= scapy.DHCP(options=[('message-type', 'ack'),
                                     ('server_id', self.server_ip[0]),
                                     ('lease_time', self.LEASE_TIME),
                                     ('subnet_mask', self.client_subnet),
                                     ('end')])
        # TODO: Need to add this to the packet creation functions in PTF code first!
        # If our bootp layer is too small, pad it
        # pad_bytes = self.DHCP_PKT_BOOTP_MIN_LEN - len(bootp)
        # if pad_bytes > 0:
        #    bootp /= scapy.PADDING('\x00' * pad_bytes)

        if self.relay_agent == "sonic-relay-agent" and (self.link_selection and self.source_interface):
            pad_bytes = self.DHCP_PKT_BOOTP_MIN_LEN - len(bootp)
            if pad_bytes > 0:
                bootp /= scapy.PADDING('\x00' * pad_bytes)

        pkt = ether / ip / udp / bootp
        return pkt

    """
     Send/receive functions

    """

    # Simulate client coming on VLAN and broadcasting a DHCPDISCOVER message
    def client_send_discover(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        # Form and send DHCPDISCOVER packet
        dhcp_discover = self.create_dhcp_discover_packet(dst_mac, src_port)
        logger.info("Client send discover packet via interface: {}".format(self.client_port_index))
        log_dhcp_packet_info(dhcp_discover)
        sent = testutils.send_packet(self, self.client_port_index, dhcp_discover)
        logger.info("Client sent {} bytes".format(sent))

    # Verify the relayed packet has option82 info or not. Sniffing for the relayed packet on leaves and
    # once the packet is recieved checking for the destination and looking into options and verifying
    # the option82 info

    def pkt_callback(self, pkt):
        if pkt.haslayer(scapy2.IP) and pkt.haslayer(scapy2.DHCP):
            if pkt.getlayer(scapy2.IP).dst in self.server_ip and pkt.getlayer(scapy2.DHCP) is not None:
                self.verified_option82 = False
                pkt_options = ''
                for option in pkt.getlayer(scapy2.DHCP).options:
                    if option[0] == 'relay_agent_information':
                        pkt_options = option[1]
                        break
                if self.option82 in pkt_options:
                    self.verified_option82 = True

    def Sniffer(self, iface):
        scapy2.sniff(iface=iface, filter="udp and (port 67 or 68)",
                     prn=self.pkt_callback, store=0, timeout=5)

    # Verify that the DHCP relay actually received and relayed the DHCPDISCOVER message to all of
    # its known DHCP servers. We also verify that the relay inserted Option 82 information in the
    # packet.

    def verify_relayed_discover(self):
        # Create a packet resembling a relayed DCHPDISCOVER packet
        dhcp_discover_relayed = self.create_dhcp_discover_relayed_packet()

        # Mask off fields we don't care about matching
        masked_discover = Mask(dhcp_discover_relayed)
        masked_discover.set_do_not_care_scapy(scapy.Ether, "dst")

        self.set_common_ignored_mask_fields(masked_discover)
        # Count the number of these packets received on the ports connected to our leaves
        self.check_relayed_pkts_on_server_side(masked_discover, dhcp_discover_relayed, "discover")

    # Simulate a DHCP server sending a DHCPOFFER message to client.
    # We do this by injecting a DHCPOFFER message on the link connected to one
    # of our leaf switches.
    def server_send_offer(self):
        dhcp_offer = self.create_dhcp_offer_packet()
        logger.info("Server send offer packet via interface: {}".format(self.server_port_indices[0]))
        log_dhcp_packet_info(dhcp_offer)
        testutils.send_packet(self, self.server_port_indices[0], dhcp_offer)

    # Verify that the DHCPOFFER would be received by our simulated client
    def verify_offer_received(self):
        dhcp_offer = self.create_dhcp_offer_relayed_packet()

        masked_offer = Mask(dhcp_offer)

        self.set_common_ignored_mask_fields(masked_offer)

        self.check_pkt_on_client_side(masked_offer, dhcp_offer, "Offer")

    # Simulate our client sending a DHCPREQUEST message
    def client_send_request(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        dhcp_request = self.create_dhcp_request_packet(dst_mac, src_port)
        logger.info("Client send request packet")
        log_dhcp_packet_info(dhcp_request)
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

        self.set_common_ignored_mask_fields(masked_request)
        # Count the number of these packets received on the ports connected to our leaves
        self.check_relayed_pkts_on_server_side(masked_request, dhcp_request_relayed, "Request")

    # Simulate a DHCP server sending a DHCPOFFER message to client from one of our leaves
    def server_send_ack(self):
        dhcp_ack = self.create_dhcp_ack_packet()
        logger.info("Server send ack packet")
        log_dhcp_packet_info(dhcp_ack)
        testutils.send_packet(self, self.server_port_indices[0], dhcp_ack)

    # Verify that the DHCPACK would be received by our simulated client
    def verify_ack_received(self):
        dhcp_ack = self.create_dhcp_ack_relayed_packet()
        masked_ack = Mask(dhcp_ack)
        self.set_common_ignored_mask_fields(masked_ack)
        self.check_pkt_on_client_side(masked_ack, dhcp_ack, "Ack")

    def verify_dhcp_relay_pkt_on_other_client_port_with_no_padding(self, dst_mac=BROADCAST_MAC,
                                                                   src_port=DHCP_CLIENT_PORT):
        # Form and send DHCP Relay packet
        dhcp_request = self.create_dhcp_request_packet(dst_mac, src_port)
        testutils.send_packet(self, self.client_port_index, dhcp_request)

        # Mask off fields we don't care about matching
        masked_request = Mask(dhcp_request)
        masked_request.set_do_not_care_scapy(scapy.Ether, "src")

        self.set_common_ignored_mask_fields(masked_request)

        try:
            testutils.verify_packets_any(
                self, masked_request, self.other_client_port)
        except Exception:
            self.assertTrue(
                False, "DHCP Relay packet not matched  or Padded extra on client side")

    def verify_dhcp_relay_pkt_on_server_port_with_no_padding(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        # Form and send DHCP Relay packet
        dhcp_request = self.create_dhcp_request_packet(dst_mac, src_port)
        logger.info("Client send request packet")
        log_dhcp_packet_info(dhcp_request)
        testutils.send_packet(self, self.client_port_index, dhcp_request)

        # Mask off fields we don't care about matching
        # Create a packet resembling a relayed DCHPREQUEST packet
        dhcp_request_relayed = self.create_dhcp_request_relayed_packet()

        # Mask off fields we don't care about matching
        masked_request = Mask(dhcp_request_relayed)
        masked_request.set_do_not_care_scapy(scapy.Ether, "dst")

        self.set_common_ignored_mask_fields(masked_request)

        try:
            logger.info("Expect receiving request packets from port [{}]".format(self.server_port_indices))
            log_dhcp_packet_info(dhcp_request_relayed)
            testutils.verify_packets_any(
                self, masked_request, self.server_port_indices)
        except Exception:
            self.assertTrue(
                False, "DHCP Relay packet not matched or Padded extra on server side")

    def create_bootp_packet(self, src_mac, src_ip, sport, giaddr, hops, dst_mac=BROADCAST_MAC):
        # Bootp vendor specific options that not related to DHCP
        vendor_options = bytes.fromhex("63865363350101111111111111111111111111111111111111111111111111111111111111" +
                                       "111111111111111000000000000000000000000000000000000000")
        my_chaddr = binascii.unhexlify(self.client_mac.replace(':', ''))
        my_chaddr += b'\x00\x00\x00\x00\x00\x00'
        bootp_packet = scapy.Ether(dst=dst_mac, src=src_mac, type=0x0800) / \
            scapy.IP(src=src_ip, dst=self.BROADCAST_IP, flags="DF", ttl=255) / \
            scapy.UDP(sport=sport, dport=self.DHCP_SERVER_PORT) / \
            scapy.BOOTP(op=1, htype=1, hlen=6, hops=hops, xid=0, secs=0, flags=0x8000,
                        ciaddr=self.DEFAULT_ROUTE_IP, yiaddr=self.DEFAULT_ROUTE_IP,
                        siaddr=self.DEFAULT_ROUTE_IP, giaddr=giaddr, chaddr=my_chaddr) / \
            vendor_options
        return bootp_packet

    def client_send_bootp(self):
        bootp_packet = self.create_bootp_packet(src_mac=self.client_mac, src_ip=self.DEFAULT_ROUTE_IP,
                                                giaddr=self.DEFAULT_ROUTE_IP, hops=1, sport=self.DHCP_CLIENT_PORT)
        logger.info("Client send bootp packet")
        log_dhcp_packet_info(bootp_packet)
        testutils.send_packet(self, self.client_port_index, bootp_packet)

    def verify_relayed_bootp(self):
        if self.server_vrf is None and self.vrf_selection is None:
            source_ip = self.relay_iface_ip if self.enable_source_port_ip_in_relay else self.switch_loopback_ip
        else:
            source_ip = self.portchannels_ip_list[0]

        if ((self.link_selection and self.source_interface) or self.server_vrf or self.dual_tor):
            giaddr = self.switch_loopback_ip
        elif self.server_id_override or not self.dual_tor:
            giaddr = self.relay_iface_ip

        bootp_packet = self.create_bootp_packet(src_mac=self.uplink_mac, src_ip=source_ip, giaddr=giaddr,
                                                sport=self.DHCP_SERVER_PORT, hops=2)

        masked_bootp = Mask(bootp_packet)
        masked_bootp.set_do_not_care_scapy(scapy.Ether, "dst")

        self.set_common_ignored_mask_fields(masked_bootp)

        # Count the number of these packets received on the ports connected to upstream
        self.check_relayed_pkts_on_server_side(masked_bootp, bootp_packet, "Bootp")

    def client_send_unknown(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        dhcp_unknown = self.create_dhcp_discover_packet(dst_mac, src_port)
        logger.info("Client send unknown packet")
        dhcp_unknown[scapy.DHCP] = scapy.DHCP(options=[('message-type', 11), ('end')])
        log_dhcp_packet_info(dhcp_unknown)
        testutils.send_packet(self, self.client_port_index, dhcp_unknown)

    def verify_relayed_unknown_on_server_side(self):
        # Create a packet resembling a relayed unknown packet
        dhcp_unknown_relayed = self.create_dhcp_unknown_relayed_packet_from_client()

        # Mask off fields we don't care about matching
        masked_unknown = Mask(dhcp_unknown_relayed)
        self.set_common_ignored_mask_fields(masked_unknown)
        masked_unknown.set_do_not_care_scapy(scapy.Ether, "dst")

        # Count the number of these packets received on the ports connected to our leaves
        self.check_relayed_pkts_on_server_side(masked_unknown, dhcp_unknown_relayed, "Unknown")

    def server_send_unknown(self):
        dhcp_unknown = self.create_dhcp_offer_packet()
        logger.info("Server send unknown packet")
        dhcp_unknown[scapy.DHCP] = scapy.DHCP(options=[('message-type', 11), ('end')])
        if self.relay_agent == "sonic-relay-agent" and (self.link_selection and self.source_interface):
            dhcp_unknown[scapy.DHCP].options.insert(
                    dhcp_unknown[scapy.DHCP].options.index("end"),
                    (82, self.option82)
            )
        log_dhcp_packet_info(dhcp_unknown)
        testutils.send_packet(self, self.server_port_indices[0], dhcp_unknown)

    def verify_relayed_unknown_on_client_side(self):
        dhcp_offer = self.create_dhcp_offer_relayed_packet()
        dhcp_offer[scapy.DHCP] = scapy.DHCP(options=[('message-type', 11), ('end')])
        if self.relay_agent == "sonic-relay-agent" and (self.link_selection and self.source_interface):
            bootp_len = len(dhcp_offer[scapy.BOOTP])
            pad_bytes = self.DHCP_PKT_BOOTP_MIN_LEN - bootp_len
            if pad_bytes > 0:
                dhcp_offer = dhcp_offer / scapy.PADDING(b"\x00" * pad_bytes)
        masked_offer = Mask(dhcp_offer)
        self.set_common_ignored_mask_fields(masked_offer)

        self.check_pkt_on_client_side(masked_offer, dhcp_offer, "Unknown")

    def client_send_decline(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        dhcp_decline = self.create_dhcp_request_packet(dst_mac, src_port)
        dhcp_decline[scapy.DHCP] = scapy.DHCP(options=[('message-type', 'decline'), ('end')])
        log_dhcp_packet_info(dhcp_decline)
        testutils.send_packet(self, self.client_port_index, dhcp_decline)

    def verify_relayed_decline(self):
        # Create a packet resembling a relayed DHCPDECLINE packet
        dhcp_decline_relayed = self.create_dhcp_decline_relayed_packet()

        # Mask off fields we don't care about matching
        masked_decline = Mask(dhcp_decline_relayed)
        masked_decline.set_do_not_care_scapy(scapy.Ether, "dst")

        self.set_common_ignored_mask_fields(masked_decline)

        # Count the number of these packets received on the ports connected to our leaves
        self.check_relayed_pkts_on_server_side(masked_decline, dhcp_decline_relayed, "Decline")

    def server_send_nak(self):
        # Build the DHCP NAK packet
        packet = self.create_dhcp_ack_packet()
        packet[scapy.DHCP] = scapy.DHCP(options=[('message-type', 'nak'), ('server_id', self.server_ip[0]), ('end')])
        if self.relay_agent == "sonic-relay-agent" and (self.link_selection and self.source_interface):
            packet[scapy.DHCP].options.insert(
                    packet[scapy.DHCP].options.index("end"),
                    (82, self.option82)
            )
        log_dhcp_packet_info(packet)
        testutils.send_packet(self, self.server_port_indices[0], packet)

    def verify_relayed_nak(self):
        dhcp_nak = self.create_dhcp_ack_relayed_packet()
        dhcp_nak[scapy.DHCP] = scapy.DHCP(options=[('message-type', 'nak'), ('server_id', self.server_ip[0]), ('end')])
        if self.relay_agent == "sonic-relay-agent" and (self.link_selection and self.source_interface):
            bootp_len = len(dhcp_nak[scapy.BOOTP])
            pad_bytes = self.DHCP_PKT_BOOTP_MIN_LEN - bootp_len
            if pad_bytes > 0:
                dhcp_nak = dhcp_nak / scapy.PADDING(b"\x00" * pad_bytes)
        masked_ack = Mask(dhcp_nak)
        self.set_common_ignored_mask_fields(masked_ack)
        self.check_pkt_on_client_side(masked_ack, dhcp_nak, "Nak")

    def client_send_release(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        dhcp_release = testutils.dhcp_release_packet(self.client_mac, self.client_ip, self.server_ip[0])
        dhcp_release[scapy.Ether].dst = dst_mac
        dhcp_release[scapy.IP].sport = src_port

        if dst_mac != self.BROADCAST_MAC:
            dhcp_release[scapy.IP].dst = self.switch_loopback_ip
            dhcp_release[scapy.IP].src = self.client_ip
        logger.info("Client send release packet")
        log_dhcp_packet_info(dhcp_release)
        testutils.send_packet(self, self.client_port_index, dhcp_release)

    def verify_relayed_release(self):
        dhcp_release = self.create_dhcp_release_relayed_packet()

        masked_release = Mask(dhcp_release)
        masked_release.set_do_not_care_scapy(scapy.Ether, "dst")
        self.set_common_ignored_mask_fields(masked_release)

        self.check_relayed_pkts_on_server_side(masked_release, dhcp_release, "Release")

    def client_send_inform(self, dst_mac=BROADCAST_MAC, src_port=DHCP_CLIENT_PORT):
        dhcp_inform = self.create_dhcp_discover_packet(dst_mac, src_port)
        logger.info("Client send unknown packet")
        dhcp_inform[scapy.DHCP] = scapy.DHCP(options=[('message-type', "inform"), ('end')])
        log_dhcp_packet_info(dhcp_inform)
        testutils.send_packet(self, self.client_port_index, dhcp_inform)

    def verify_relayed_inform(self):
        dhcp_request_relayed = self.create_dhcp_inform_relayed_packet()

        # Mask off fields we don't care about matching
        masked_request = Mask(dhcp_request_relayed)
        masked_request.set_do_not_care_scapy(scapy.Ether, "dst")
        self.set_common_ignored_mask_fields(masked_request)

        # Count the number of these packets received on the ports connected to our leaves
        self.check_relayed_pkts_on_server_side(masked_request, dhcp_request_relayed, "Inform")

    def check_relayed_pkts_on_server_side(self, mask, pkt, packet_type):
        logger.info("Expect receiving {} packets from port [{}]".format(packet_type, self.server_port_indices))
        log_dhcp_packet_info(pkt)
        num_expected_packets = self.num_dhcp_servers
        if self.agent_relay_mode == "discard" or self.dhcpv4_disable_flag or self.max_hop_count == self.MAX_HOP_COUNT:
            # Expected result: No packet sent
            num_expected_packets = 0
        captured_count = testutils.count_matched_packets_all_ports(
            self, mask, self.server_port_indices)
        self.assertTrue(captured_count == num_expected_packets,
                        "Failed: %s packet counts are not equal %d != %d"
                        % (packet_type, captured_count, num_expected_packets))

    def check_pkt_on_client_side(self, mask, pkt, packet_type):
        logger.info("Expect receiving relayed {} packet from port {}".format(packet_type, self.client_port_index))
        log_dhcp_packet_info(pkt)
        testutils.verify_packet(self, mask, self.client_port_index)

    def set_common_ignored_mask_fields(self, mask):
        mask.set_do_not_care_scapy(scapy.IP, "version")
        mask.set_do_not_care_scapy(scapy.IP, "ihl")
        mask.set_do_not_care_scapy(scapy.IP, "tos")
        mask.set_do_not_care_scapy(scapy.IP, "len")
        mask.set_do_not_care_scapy(scapy.IP, "id")
        mask.set_do_not_care_scapy(scapy.IP, "flags")
        mask.set_do_not_care_scapy(scapy.IP, "frag")
        mask.set_do_not_care_scapy(scapy.IP, "ttl")
        mask.set_do_not_care_scapy(scapy.IP, "proto")
        mask.set_do_not_care_scapy(scapy.IP, "chksum")
        mask.set_do_not_care_scapy(scapy.IP, "dst")
        mask.set_do_not_care_scapy(scapy.IP, "options")

        mask.set_do_not_care_scapy(scapy.UDP, "chksum")
        mask.set_do_not_care_scapy(scapy.UDP, "len")

        mask.set_do_not_care_scapy(scapy.BOOTP, "sname")
        mask.set_do_not_care_scapy(scapy.BOOTP, "file")

    def merge_layers_to_packet(self, ether, ip, udp, bootp):
        pad_bytes = self.DHCP_PKT_BOOTP_MIN_LEN - len(bootp)
        # If our bootp layer is too small, pad it
        if pad_bytes > 0:
            bootp /= scapy.PADDING('\x00' * pad_bytes)

        pkt = ether / ip / udp / bootp
        return pkt

    def runTest(self):
        if self.agent_relay_mode or self.dhcpv4_disable_flag:
            self.client_send_discover(
                self.dest_mac_address, self.client_udp_src_port)
            self.verify_relayed_discover()
        else:
            # Start sniffer process for each server port to capture DHCP packet
            # and then verify option 82
            for interface_index in self.server_port_indices:
                t1 = Thread(target=self.Sniffer, args=(
                    "eth"+str(interface_index),))
                t1.start()

            self.client_send_discover(
                self.dest_mac_address, self.client_udp_src_port)
            self.verify_relayed_discover()
            self.server_send_offer()
            self.verify_offer_received()
            self.client_send_request(
                self.dest_mac_address, self.client_udp_src_port)
            self.verify_relayed_request()
            self.server_send_ack()
            self.verify_ack_received()
            self.client_send_bootp()
            self.verify_relayed_bootp()
            self.client_send_unknown(self.dest_mac_address, self.client_udp_src_port)
            self.verify_relayed_unknown_on_server_side()
            self.server_send_unknown()
            self.verify_relayed_unknown_on_client_side()
            self.client_send_decline(self.dest_mac_address, self.client_udp_src_port)
            self.verify_relayed_decline()
            self.server_send_nak()
            self.verify_relayed_nak()
            self.client_send_release(self.dest_mac_address, self.client_udp_src_port)
            self.verify_relayed_release()
            self.client_send_inform(self.dest_mac_address, self.client_udp_src_port)
            self.verify_relayed_inform()
            self.assertTrue(self.verified_option82, "Failed: Verifying option 82")

            # Below verification will be done only when client port is set in ptf_runner
            if not self.dual_tor and 'other_client_port' in self.test_params:
                self.verify_dhcp_relay_pkt_on_server_port_with_no_padding(
                    self.dest_mac_address, self.client_udp_src_port)


class DHCPPacketsServerToClientTest(DHCPTest):
    """
    Only Test DHCP packets from server to client, including offer, ack, nak and unknown.
    """
    def runTest(self):
        # Start sniffer process for each server port to capture DHCP packet
        for interface_index in self.server_port_indices:
            t1 = Thread(target=self.Sniffer, args=(
                "eth"+str(interface_index),))
            t1.start()

        self.server_send_offer()
        self.verify_offer_received()
        self.server_send_ack()
        self.verify_ack_received()
        self.server_send_unknown()
        self.verify_relayed_unknown_on_client_side()
        self.server_send_nak()
        self.verify_relayed_nak()


class DHCPInvalidChecksumTest(DHCPTest):
    """
    Test DHCP packets with invalid checksum.
    """

    def create_dhcp_discover_packet(self, dst_mac=DHCPTest.BROADCAST_MAC, src_port=DHCPTest.DHCP_CLIENT_PORT):
        pkt = super().create_dhcp_discover_packet(dst_mac, src_port)

        pkt[scapy.UDP].chksum = 0x1234
        return pkt

    def create_dhcp_offer_packet(self):
        pkt = super().create_dhcp_offer_packet()
        pkt[scapy.IP].chksum = 0x1234
        return pkt

    def create_dhcp_request_packet(self, dst_mac=DHCPTest.BROADCAST_MAC, src_port=DHCPTest.DHCP_CLIENT_PORT):
        pkt = super().create_dhcp_request_packet(dst_mac, src_port)

        pkt[scapy.IP].chksum = 0x4321
        return pkt

    def create_dhcp_ack_packet(self):
        pkt = super().create_dhcp_ack_packet()

        pkt[scapy.UDP].chksum = 0x4321
        return pkt

    def create_bootp_packet(self, src_mac, src_ip, sport, giaddr, hops, dst_mac=DHCPTest.BROADCAST_MAC):
        pkt = super().create_bootp_packet(src_mac=src_mac, src_ip=src_ip,
                                          giaddr=giaddr, hops=hops, sport=sport, dst_mac=dst_mac)
        pkt[scapy.IP].chksum = 0x1234
        return pkt

    def runTest(self):
        # Start sniffer process for each server port to capture DHCP packet
        # and then verify option 82
        for interface_index in self.server_port_indices:
            t1 = Thread(target=self.Sniffer, args=(
                "eth"+str(interface_index),))
            t1.start()

        self.client_send_discover(
            self.dest_mac_address, self.client_udp_src_port)
        self.server_send_offer()
        self.client_send_request(
            self.dest_mac_address, self.client_udp_src_port)
        self.server_send_ack()
        self.client_send_bootp()
        self.client_send_unknown(self.dest_mac_address, self.client_udp_src_port)
        self.server_send_unknown()
