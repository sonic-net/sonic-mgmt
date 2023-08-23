import os
import ast
import subprocess
import scapy
# Packet Test Framework imports
import ptf
import ptf.packet as packet
import ptf.testutils as testutils
from ptf import config
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from scapy.fields import MACField, ShortEnumField, FieldLenField, ShortField
from scapy.data import ETHER_ANY
from scapy.layers.dhcp6 import _DHCP6OptGuessPayload

IPv6 = scapy.layers.inet6.IPv6
DHCP6_Solicit = scapy.layers.dhcp6.DHCP6_Solicit
DHCP6_RelayForward = scapy.layers.dhcp6.DHCP6_RelayForward
DHCP6_Request = scapy.layers.dhcp6.DHCP6_Request
DHCP6_Advertise = scapy.layers.dhcp6.DHCP6_Advertise
DHCP6_Reply = scapy.layers.dhcp6.DHCP6_Reply
DHCP6_RelayReply = scapy.layers.dhcp6.DHCP6_RelayReply
DHCP6OptRelayMsg = scapy.layers.dhcp6.DHCP6OptRelayMsg
DHCP6OptUnknown = scapy.layers.dhcp6.DHCP6OptUnknown

DHCP6OptClientId = scapy.layers.dhcp6.DHCP6OptClientId
DHCP6OptOptReq = scapy.layers.dhcp6.DHCP6OptOptReq
DHCP6OptElapsedTime = scapy.layers.dhcp6.DHCP6OptElapsedTime
DHCP6OptIA_NA = scapy.layers.dhcp6.DHCP6OptIA_NA
DUID_LLT = scapy.layers.dhcp6.DUID_LLT
DHCP6OptIfaceId = scapy.layers.dhcp6.DHCP6OptIfaceId
DHCP6OptServerId = scapy.layers.dhcp6.DHCP6OptServerId


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
 requesting an IPv6 address via DHCPv6. Setup is as follows:
  - DHCP client is simulated by listening/sending on an interface connected to VLAN of ToR.
  - DHCP server is simulated by listening/sending on injected PTF interfaces which link
    ToR to leaves. This way we can listen for traffic sent from DHCP relay out to would-be DHCPv6 servers

 This test performs the following functionality:
   1.) Simulated client broadcasts a DHCPv6 SOLICIT message.
   2.) Verify DHCP relay running on ToR receives the DHCPv6 SOLICIT message and send a DHCPv6 RELAY-FORWARD
       message encapsulating the client DHCPv6 SOLICIT message and relays it to all of its known DHCP servers.
   3.) Simulate DHCPv6 RELAY-REPLY message send from a DHCP server to the ToR encapsulating DHCPv6 ADVERTISE message.
   4.) Verify DHCP relay receives the DHCPv6 RELAY-REPLY message decapsulate it and forwards DHCPv6 ADVERTISE
       message to our simulated client.
   5.) Simulated client broadcasts a DHCPv6 REQUEST message.
   6.) Verify DHCP relay running on ToR receives the DHCPv6 REQUEST message and send a DHCPv6 RELAY-FORWARD
       message encapsulating the client DHCPv6 REQUEST message and relays it to all of its known DHCP servers.
   7.) Simulate DHCPv6 RELAY-REPLY message send from a DHCP server to the ToR encapsulating DHCPv6 REPLY message.
   8.) Verify DHCP relay receives the DHCPv6 RELAY-REPLY message decapsulate it and forwards DHCPv6 REPLY
       message to our simulated client.

"""

dhcp6opts = {79: "OPTION_CLIENT_LINKLAYER_ADDR",  # RFC6939
             }


class _LLAddrField(MACField):
    pass

# "Client link-layer address type.  The link-layer type MUST be a valid hardware  # noqa: E501
# type assigned by the IANA, as described in [RFC0826]


class DHCP6OptClientLinkLayerAddr(_DHCP6OptGuessPayload):  # RFC6939
    name = "DHCP6 Option - Client Link Layer address"
    fields_desc = [ShortEnumField("optcode", 79, dhcp6opts),
                   FieldLenField("optlen", None, length_of="clladdr",
                                 adjust=lambda pkt, x: x + 2),
                   ShortField("lltype", 1),  # ethernet
                   _LLAddrField("clladdr", ETHER_ANY)]


class DHCPTest(DataplaneBaseTest):
    BROADCAST_MAC = '33:33:00:01:00:02'
    BROADCAST_IP = 'ff02::1:2'
    DHCP_CLIENT_PORT = 546
    DHCP_SERVER_PORT = 547

    def __init__(self):
        self.test_params = testutils.test_params_get()
        self.client_port_index = int(self.test_params['client_port_index'])
        self.client_link_local = self.generate_client_interace_ipv6_link_local_address(
            self.client_port_index)

        DataplaneBaseTest.__init__(self)

    def setUp(self):
        DataplaneBaseTest.setUp(self)
        self.hostname = self.test_params['hostname']

        # These are the interfaces we are injected into that link to out leaf switches
        self.server_port_indices = ast.literal_eval(
            self.test_params['leaf_port_indices'])
        self.num_dhcp_servers = int(self.test_params['num_dhcp_servers'])
        self.assertTrue(self.num_dhcp_servers > 0,
                        "Error: This test requires at least one DHCP server to be specified!")

        # We will simulate a responding DHCP server on the first interface in the provided set
        self.server_ip = self.test_params['server_ip']

        self.relay_iface_ip = self.test_params['relay_iface_ip']
        self.relay_iface_mac = self.test_params['relay_iface_mac']
        self.relay_link_local = self.test_params['relay_link_local']
        self.relay_linkaddr = '::'

        self.vlan_ip = self.test_params['vlan_ip']

        self.client_mac = self.dataplane.get_mac(0, self.client_port_index)
        self.uplink_mac = self.test_params['uplink_mac']

    def generate_client_interace_ipv6_link_local_address(self, client_port_index):
        # Shutdown and startup the client interface to generate a proper IPv6 link-local address
        command = "ifconfig eth{} down".format(client_port_index)
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        proc.communicate()

        command = "ifconfig eth{} up".format(client_port_index)
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        proc.communicate()

        command = "ip addr show eth{} | grep inet6 | grep 'scope link' | awk '{{print $2}}' | cut -d '/' -f1".\
                  format(client_port_index)
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        return stdout.strip()

    def tearDown(self):
        DataplaneBaseTest.tearDown(self)

    """
     Packet generation functions/wrappers
    """

    def create_dhcp_solicit_packet(self):
        solicit_packet = packet.Ether(
            src=self.client_mac, dst=self.BROADCAST_MAC)
        solicit_packet /= IPv6(src=self.client_link_local,
                               dst=self.BROADCAST_IP)
        solicit_packet /= packet.UDP(sport=self.DHCP_CLIENT_PORT,
                                     dport=self.DHCP_SERVER_PORT)
        solicit_packet /= DHCP6_Solicit(trid=12345)
        solicit_packet /= DHCP6OptClientId(
            duid=DUID_LLT(lladdr=self.client_mac))
        solicit_packet /= DHCP6OptIA_NA()
        solicit_packet /= DHCP6OptOptReq(reqopts=[23, 24, 29])
        solicit_packet /= DHCP6OptElapsedTime(elapsedtime=0)

        return solicit_packet

    # order: relay forward option list sequence
    # 0 - increase order, 1 - decrease order
    def create_dhcp_solicit_relay_forward_packet(self, order):
        solicit_relay_forward_packet = packet.Ether(src=self.uplink_mac)
        solicit_relay_forward_packet /= IPv6()
        solicit_relay_forward_packet /= packet.UDP(
            sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT)
        solicit_relay_forward_packet /= DHCP6_RelayForward(msgtype=12, linkaddr=self.vlan_ip,
                                                           peeraddr=self.client_link_local)
        if order == 1:
            solicit_relay_forward_packet /= DHCP6OptClientLinkLayerAddr()

        solicit_relay_forward_packet /= DHCP6OptRelayMsg(message=[DHCP6_Solicit(trid=12345) /
                                                         DHCP6OptClientId(duid=DUID_LLT(lladdr=self.client_mac)) /
                                                         DHCP6OptIA_NA()/DHCP6OptOptReq(reqopts=[23, 24, 29]) /
                                                         DHCP6OptElapsedTime(elapsedtime=0)])
        if order == 0:
            solicit_relay_forward_packet /= DHCP6OptClientLinkLayerAddr()

        return solicit_relay_forward_packet

    def create_dhcp_advertise_packet(self):
        advertise_packet = packet.Ether(
            src=self.relay_iface_mac, dst=self.client_mac)
        advertise_packet /= IPv6(src=self.relay_link_local,
                                 dst=self.client_link_local)
        advertise_packet /= packet.UDP(sport=self.DHCP_SERVER_PORT,
                                       dport=self.DHCP_CLIENT_PORT)
        advertise_packet /= DHCP6_Advertise(trid=12345)

        return advertise_packet

    def create_dhcp_advertise_relay_reply_packet(self):
        advertise_relay_reply_packet = packet.Ether(dst=self.uplink_mac)
        advertise_relay_reply_packet /= IPv6(
            src=self.server_ip, dst=self.relay_iface_ip)
        advertise_relay_reply_packet /= packet.UDP(
            sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT)
        advertise_relay_reply_packet /= DHCP6_RelayReply(msgtype=13, linkaddr=self.vlan_ip,
                                                         peeraddr=self.client_link_local)
        advertise_relay_reply_packet /= DHCP6OptRelayMsg(
            message=[DHCP6_Advertise(trid=12345)])
        return advertise_relay_reply_packet

    def create_dhcp_request_packet(self):
        request_packet = packet.Ether(
            src=self.client_mac, dst=self.BROADCAST_MAC)
        request_packet /= IPv6(src=self.client_link_local,
                               dst=self.BROADCAST_IP)
        request_packet /= packet.UDP(sport=self.DHCP_CLIENT_PORT,
                                     dport=self.DHCP_SERVER_PORT)
        request_packet /= DHCP6_Request(trid=12345)

        return request_packet

    # order: relay forward option list sequence
    # 0 - increase order, 1 - decrease order
    def create_dhcp_request_relay_forward_packet(self, order):
        request_relay_forward_packet = packet.Ether(src=self.uplink_mac)
        request_relay_forward_packet /= IPv6()
        request_relay_forward_packet /= packet.UDP(
            sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT)
        request_relay_forward_packet /= DHCP6_RelayForward(msgtype=12, linkaddr=self.vlan_ip,
                                                           peeraddr=self.client_link_local)
        if order == 1:
            request_relay_forward_packet /= DHCP6OptClientLinkLayerAddr()

        request_relay_forward_packet /= DHCP6OptRelayMsg(
            message=[DHCP6_Request(trid=12345)])
        if order == 0:
            request_relay_forward_packet /= DHCP6OptClientLinkLayerAddr()

        return request_relay_forward_packet

    def create_dhcp_reply_packet(self):
        reply_packet = packet.Ether(
            src=self.relay_iface_mac, dst=self.client_mac)
        reply_packet /= IPv6(src=self.relay_link_local,
                             dst=self.client_link_local)
        reply_packet /= packet.UDP(sport=self.DHCP_SERVER_PORT,
                                   dport=self.DHCP_CLIENT_PORT)
        reply_packet /= DHCP6_Reply(trid=12345)

        return reply_packet

    def create_dhcp_reply_relay_reply_packet(self):
        reply_relay_reply_packet = packet.Ether(dst=self.uplink_mac)
        reply_relay_reply_packet /= IPv6(src=self.server_ip,
                                         dst=self.relay_iface_ip)
        reply_relay_reply_packet /= packet.UDP(
            sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT)
        reply_relay_reply_packet /= DHCP6_RelayReply(msgtype=13, linkaddr=self.vlan_ip,
                                                     peeraddr=self.client_link_local)
        reply_relay_reply_packet /= DHCP6OptRelayMsg(
            message=[DHCP6_Reply(trid=12345)])
        reply_relay_reply_packet /= DHCP6OptIfaceId(ifaceid=self.vlan_ip)

        return reply_relay_reply_packet

    def create_dhcp_relay_forward_packet(self):
        relay_forward_packet = packet.Ether(
            src=self.client_mac, dst=self.BROADCAST_MAC)
        relay_forward_packet /= IPv6(src=self.client_link_local,
                                     dst=self.BROADCAST_IP)
        relay_forward_packet /= packet.UDP(
            sport=self.DHCP_CLIENT_PORT, dport=self.DHCP_SERVER_PORT)
        relay_forward_packet /= DHCP6_RelayForward(
            msgtype=12, linkaddr=self.vlan_ip, peeraddr=self.client_link_local)
        relay_forward_packet /= DHCP6OptRelayMsg(
            message=[DHCP6_Solicit(trid=12345)])
        relay_forward_packet /= DHCP6OptElapsedTime(elapsedtime=0)

        return relay_forward_packet

    def create_dhcp_relayed_relay_packet(self):
        relayed_relay_packet = packet.Ether(src=self.uplink_mac)
        relayed_relay_packet /= IPv6()
        relayed_relay_packet /= packet.UDP(
            sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT)
        packet_inside = DHCP6_RelayForward(
            msgtype=12, linkaddr=self.vlan_ip, peeraddr=self.client_link_local)
        packet_inside /= DHCP6OptRelayMsg(message=[DHCP6_Solicit(trid=12345)])
        packet_inside /= DHCP6OptElapsedTime(elapsedtime=0)
        relayed_relay_packet /= DHCP6_RelayForward(msgtype=12, hopcount=1, linkaddr=self.relay_linkaddr,
                                                   peeraddr=self.client_link_local)
        relayed_relay_packet /= DHCP6OptRelayMsg(message=[packet_inside])

        return relayed_relay_packet

    def create_dhcp_relay_relay_reply_packet(self):
        relay_relay_reply_packet = packet.Ether(dst=self.uplink_mac)
        relay_relay_reply_packet /= IPv6(src=self.server_ip,
                                         dst=self.relay_iface_ip)
        relay_relay_reply_packet /= packet.UDP(
            sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT)
        relay_relay_reply_packet /= DHCP6_RelayReply(msgtype=13, hopcount=1, linkaddr=self.vlan_ip,
                                                     peeraddr=self.client_link_local)
        packet_inside = DHCP6_RelayReply(
            msgtype=13, linkaddr=self.vlan_ip, peeraddr=self.client_link_local)
        packet_inside /= DHCP6OptRelayMsg(message=[DHCP6_Reply(trid=12345)])
        relay_relay_reply_packet /= DHCP6OptServerId(duid=DUID_LLT(lladdr="00:11:22:33:44:55"))
        relay_relay_reply_packet /= DHCP6OptRelayMsg(message=[packet_inside])

        return relay_relay_reply_packet

    def create_dhcp_relay_reply_packet(self):
        relay_reply_packet = packet.Ether(
            src=self.relay_iface_mac, dst=self.client_mac)
        relay_reply_packet /= IPv6(src=self.relay_link_local,
                                   dst=self.client_link_local)
        relay_reply_packet /= packet.UDP(sport=self.DHCP_SERVER_PORT,
                                         dport=self.DHCP_CLIENT_PORT)
        relay_reply_packet /= DHCP6_RelayReply(
            msgtype=13, linkaddr=self.vlan_ip, peeraddr=self.client_link_local)
        relay_reply_packet /= DHCP6OptRelayMsg(
            message=[DHCP6_Reply(trid=12345)])

        return relay_reply_packet

    """
     Send/receive functions

    """

    # Simulate client connecting on VLAN and broadcasting a DHCPv6 SOLICIT message
    def client_send_solicit(self):
        # Form and send DHCPv6 SOLICIT packet
        solicit_packet = self.create_dhcp_solicit_packet()
        testutils.send_packet(self, self.client_port_index, solicit_packet)

    # Verify that the DHCP relay actually received and relayed the DHCPv6 SOLICIT message to all of
    # its known DHCP servers.
    def verify_relayed_solicit_relay_forward(self, try_count=0):
        # Create a packet resembling a DHCPv6 RELAY-FORWARD encapsulating SOLICIT packet
        solicit_relay_forward_packet = self.create_dhcp_solicit_relay_forward_packet(
            order=try_count)

        # Mask off fields we don't care about matching
        masked_packet = Mask(solicit_relay_forward_packet)
        masked_packet.set_do_not_care_scapy(packet.Ether, "dst")
        masked_packet.set_do_not_care_scapy(IPv6, "src")
        masked_packet.set_do_not_care_scapy(IPv6, "dst")
        masked_packet.set_do_not_care_scapy(IPv6, "fl")
        masked_packet.set_do_not_care_scapy(IPv6, "tc")
        masked_packet.set_do_not_care_scapy(IPv6, "plen")
        masked_packet.set_do_not_care_scapy(IPv6, "nh")
        masked_packet.set_do_not_care_scapy(packet.UDP, "chksum")
        masked_packet.set_do_not_care_scapy(packet.UDP, "len")
        masked_packet.set_do_not_care_scapy(
            scapy.layers.dhcp6.DHCP6_RelayForward, "linkaddr")
        masked_packet.set_do_not_care_scapy(
            DHCP6OptClientLinkLayerAddr, "clladdr")

        # Count the number of these packets received on the ports connected to our leaves
        solicit_count = testutils.count_matched_packets_all_ports(self, masked_packet,
                                                                  self.server_port_indices, timeout=4.0)

        if try_count == 0:
            if solicit_count >= 1:
                return True
            return False

        self.assertTrue(solicit_count >= 1,
                        "Failed: Solicit count of %d" % solicit_count)
        return True

    # Simulate a DHCP server sending a DHCPv6 RELAY-REPLY encapsulating ADVERTISE packet message to client.
    # We do this by injecting a RELAY-REPLY encapsulating ADVERTISE message on the link connected to one
    # of our leaf switches.
    def server_send_advertise_relay_reply(self):
        # Form and send DHCPv6 RELAY-REPLY encapsulating ADVERTISE packet
        advertise_relay_reply_packet = self.create_dhcp_advertise_relay_reply_packet()
        advertise_relay_reply_packet.src = self.dataplane.get_mac(
            0, self.server_port_indices[0])
        testutils.send_packet(
            self, self.server_port_indices[0], advertise_relay_reply_packet)

    # Verify that the DHCPv6 ADVERTISE would be received by our simulated client
    def verify_relayed_advertise(self):
        # Create a packet resembling a DHCPv6 ADVERTISE packet
        advertise_packet = self.create_dhcp_advertise_packet()

        # Mask off fields we don't care about matching
        masked_packet = Mask(advertise_packet)
        masked_packet.set_do_not_care_scapy(IPv6, "fl")
        # dual tor uses relay_iface_ip as ip src
        masked_packet.set_do_not_care_scapy(IPv6, "src")
        masked_packet.set_do_not_care_scapy(packet.UDP, "chksum")
        masked_packet.set_do_not_care_scapy(packet.UDP, "len")

        # NOTE: verify_packet() will fail for us via an assert, so no need to check a return value here
        testutils.verify_packet(self, masked_packet, self.client_port_index)

    # Simulate our client sending a DHCPv6 REQUEST message
    def client_send_request(self):
        # Form and send DHCPv6 REQUEST packet
        request_packet = self.create_dhcp_request_packet()
        testutils.send_packet(self, self.client_port_index, request_packet)

    # Verify that the DHCP relay actually received and relayed the DHCPv6 REQUEST message to all of
    # its known DHCP servers.
    def verify_relayed_request_relay_forward(self, try_count=0):
        # Create a packet resembling a DHCPv6 RELAY-FORWARD encapsulating REQUEST packet
        request_relay_forward_packet = self.create_dhcp_request_relay_forward_packet(
            try_count)

        # Mask off fields we don't care about matching
        masked_packet = Mask(request_relay_forward_packet)
        masked_packet.set_do_not_care_scapy(packet.Ether, "dst")
        masked_packet.set_do_not_care_scapy(IPv6, "src")
        masked_packet.set_do_not_care_scapy(IPv6, "dst")
        masked_packet.set_do_not_care_scapy(IPv6, "fl")
        masked_packet.set_do_not_care_scapy(IPv6, "tc")
        masked_packet.set_do_not_care_scapy(IPv6, "plen")
        masked_packet.set_do_not_care_scapy(IPv6, "nh")
        masked_packet.set_do_not_care_scapy(packet.UDP, "chksum")
        masked_packet.set_do_not_care_scapy(packet.UDP, "len")
        masked_packet.set_do_not_care_scapy(
            scapy.layers.dhcp6.DHCP6_RelayForward, "linkaddr")
        masked_packet.set_do_not_care_scapy(
            DHCP6OptClientLinkLayerAddr, "clladdr")

        # Count the number of these packets received on the ports connected to our leaves
        request_count = testutils.count_matched_packets_all_ports(self, masked_packet,
                                                                  self.server_port_indices, timeout=4.0)

        if try_count == 0:
            if request_count >= 1:
                return True
            return False

        self.assertTrue(request_count >= 1,
                        "Failed: Request count of %d" % request_count)
        return True

    # Simulate a DHCP server sending a DHCPv6 RELAY-REPLY encapsulating REPLY packet message to client.
    def server_send_reply_relay_reply(self):
        # Form and send DHCPv6 RELAY-REPLY encapsulating REPLY packet
        reply_relay_reply_packet = self.create_dhcp_reply_relay_reply_packet()
        reply_relay_reply_packet.src = self.dataplane.get_mac(
            0, self.server_port_indices[0])
        testutils.send_packet(
            self, self.server_port_indices[0], reply_relay_reply_packet)

    # Verify that the DHCPv6 REPLY would be received by our simulated client
    def verify_relayed_reply(self):
        # Create a packet resembling a DHCPv6 REPLY packet
        reply_packet = self.create_dhcp_reply_packet()

        # Mask off fields we don't care about matching
        masked_packet = Mask(reply_packet)
        masked_packet.set_do_not_care_scapy(IPv6, "fl")
        # dual tor uses relay_iface_ip as ip src
        masked_packet.set_do_not_care_scapy(IPv6, "src")
        masked_packet.set_do_not_care_scapy(packet.UDP, "chksum")
        masked_packet.set_do_not_care_scapy(packet.UDP, "len")

        # NOTE: verify_packet() will fail for us via an assert, so no need to check a return value here
        testutils.verify_packet(self, masked_packet, self.client_port_index)

    # Simulate a DHCP server sending a DHCPv6 RELAY-FORWARD encapsulating SOLICIT packet message to client.
    def client_send_relayed_relay_forward(self):
        # Form and send DHCPv6 RELAY-FORWARD encapsulating REPLY packet
        relay_forward_packet = self.create_dhcp_relay_forward_packet()
        testutils.send_packet(
            self, self.client_port_index, relay_forward_packet)

    # Verify that the DHCPv6 RELAYED RELAY would be received by our simulated server
    def verify_relayed_relay_forward(self):
        # Create a packet resembling a DHCPv6 RELAYED RELAY FORWARD packet
        relayed_relay_forward_count = self.create_dhcp_relayed_relay_packet()

        # Mask off fields we don't care about matching
        masked_packet = Mask(relayed_relay_forward_count)
        masked_packet.set_do_not_care_scapy(packet.Ether, "dst")
        masked_packet.set_do_not_care_scapy(IPv6, "src")
        masked_packet.set_do_not_care_scapy(IPv6, "dst")
        masked_packet.set_do_not_care_scapy(IPv6, "fl")
        masked_packet.set_do_not_care_scapy(IPv6, "tc")
        masked_packet.set_do_not_care_scapy(IPv6, "plen")
        masked_packet.set_do_not_care_scapy(IPv6, "nh")
        masked_packet.set_do_not_care_scapy(packet.UDP, "chksum")
        masked_packet.set_do_not_care_scapy(packet.UDP, "len")

        relayed_relay_forward_count = testutils.count_matched_packets_all_ports(self, masked_packet,
                                                                                self.server_port_indices, timeout=4.0)
        self.assertTrue(relayed_relay_forward_count >= 1, "Failed: Relayed Relay Forward count of %d"
                        % relayed_relay_forward_count)

    # Simulate a DHCP server sending a DHCPv6 RELAY-REPLY encapsulating RELAY-REPLY packet message to next relay agent
    def server_send_relay_relay_reply(self):
        # Form and send DHCPv6 RELAY-REPLY encapsulating REPLY packet
        relay_relay_reply_packet = self.create_dhcp_relay_relay_reply_packet()
        relay_relay_reply_packet.src = self.dataplane.get_mac(
            0, self.server_port_indices[0])
        testutils.send_packet(
            self, self.server_port_indices[0], relay_relay_reply_packet)

    # Verify that the DHCPv6 RELAY REPLY would be uncapsulated and forwarded to the next relay agent
    def verify_relay_relay_reply(self):
        # Create a packet resembling a DHCPv6 RELAY REPLY packet
        relay_reply_packet = self.create_dhcp_relay_reply_packet()

        # Mask off fields we don't care about matching
        masked_packet = Mask(relay_reply_packet)
        masked_packet.set_do_not_care_scapy(IPv6, "fl")
        # dual tor uses relay_iface_ip as ip src
        masked_packet.set_do_not_care_scapy(IPv6, "src")
        masked_packet.set_do_not_care_scapy(packet.UDP, "chksum")
        masked_packet.set_do_not_care_scapy(packet.UDP, "len")

        # NOTE: verify_packet() will fail for us via an assert, so no need to check a return value here
        testutils.verify_packet(self, masked_packet, self.client_port_index)

    def runTest(self):
        for x in range(2):
            self.client_send_solicit()
            if self.verify_relayed_solicit_relay_forward(x):
                break

        self.server_send_advertise_relay_reply()
        self.verify_relayed_advertise()
        for x in range(2):
            self.client_send_request()
            if self.verify_relayed_request_relay_forward(x):
                break

        self.server_send_reply_relay_reply()
        self.verify_relayed_reply()
        self.client_send_relayed_relay_forward()
        self.verify_relayed_relay_forward()
        self.server_send_relay_relay_reply()
        self.verify_relay_relay_reply()
