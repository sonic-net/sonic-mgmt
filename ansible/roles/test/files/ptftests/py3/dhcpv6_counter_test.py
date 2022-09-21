import ast
import subprocess
import scapy
# Packet Test Framework imports
import ptf
import ptf.testutils as testutils
from ptf import config
from ptf.base_tests import BaseTest

IPv6 = scapy.layers.inet6.IPv6
DHCP6_Solicit = scapy.layers.dhcp6.DHCP6_Solicit
DHCP6_Request = scapy.layers.dhcp6.DHCP6_Request
DHCP6_Confirm = scapy.layers.dhcp6.DHCP6_Confirm
DHCP6_Renew = scapy.layers.dhcp6.DHCP6_Renew
DHCP6_Rebind = scapy.layers.dhcp6.DHCP6_Rebind
DHCP6_Release = scapy.layers.dhcp6.DHCP6_Release
DHCP6_Decline = scapy.layers.dhcp6.DHCP6_Decline
DHCP6_Reconf= scapy.layers.dhcp6.DHCP6_Reconf
DHCP6_InfoRequest = scapy.layers.dhcp6.DHCP6_InfoRequest
DHCP6_Advertise = scapy.layers.dhcp6.DHCP6_Advertise
DHCP6_Reply = scapy.layers.dhcp6.DHCP6_Reply
DHCP6_RelayReply = scapy.layers.dhcp6.DHCP6_RelayReply
DHCP6OptRelayMsg = scapy.layers.dhcp6.DHCP6OptRelayMsg
DHCP6OptAuth = scapy.layers.dhcp6.DHCP6OptAuth

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

This test tests for DHCPv6 Counter. Packets are sent from both the client and server side, and packets are verified to be received by the counter.

"""

class DHCPCounterTest(DataplaneBaseTest):
    
    BROADCAST_MAC = '33:33:00:01:00:02'
    BROADCAST_IP = 'ff02::1:2'
    DHCP_CLIENT_PORT = 546
    DHCP_SERVER_PORT = 547

    def __init__(self):
        self.test_params = testutils.test_params_get()
        self.client_port_index = int(self.test_params['client_port_index'])
        self.client_link_local =  self.generate_client_interace_ipv6_link_local_address(self.client_port_index)
        
        DataplaneBaseTest.__init__(self)

    def setUp(self):
        DataplaneBaseTest.setUp(self)

        # These are the interfaces we are injected into that link to out leaf switches
        self.server_port_indices = ast.literal_eval(self.test_params['leaf_port_indices'])
        self.num_dhcp_servers = int(self.test_params['num_dhcp_servers'])
        self.assertTrue(self.num_dhcp_servers > 0,
                "Error: This test requires at least one DHCP server to be specified!")

        self.server_ip = self.test_params['server_ip']
        self.relay_iface_ip = self.test_params['relay_iface_ip']
        self.relay_iface_mac = self.test_params['relay_iface_mac']
        self.vlan_ip = self.test_params['vlan_ip']
        self.client_mac = self.dataplane.get_mac(0, self.client_port_index)

    def generate_client_interace_ipv6_link_local_address(self, client_port_index):
        # Shutdown and startup the client interface to generate a proper IPv6 link-local address
        command = "ifconfig eth{} down".format(client_port_index)
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        proc.communicate()

        command = "ifconfig eth{} up".format(client_port_index)
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        proc.communicate()

        command = "ip addr show eth{} | grep inet6 | grep 'scope link' | awk '{{print $2}}' | cut -d '/' -f1".format(client_port_index)
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        return stdout.strip()

    def tearDown(self):
        DataplaneBaseTest.tearDown(self)


    """
     Packet generation functions/wrappers

    """

    def create_packet(self, message):
        packet = Ether(src=self.client_mac, dst=self.BROADCAST_MAC)
        packet /= IPv6(src=self.client_link_local, dst=self.BROADCAST_IP)
        packet /= UDP(sport=self.DHCP_CLIENT_PORT, dport=self.DHCP_SERVER_PORT)
        packet /= message(trid=12345)

        return packet

    def create_malformed_client_packet(self, message):
        packet = Ether(src=self.client_mac, dst=self.BROADCAST_MAC)
        packet /= IPv6(src=self.client_link_local, dst=self.BROADCAST_IP)
        packet /= UDP(sport=self.DHCP_CLIENT_PORT, dport=self.DHCP_SERVER_PORT)
        packet /= message(trid=12345)/DHCP6OptAuth(optcode=100) # changes optcode to be out of client scope to test malformed counters

        return packet

    def create_server_packet(self, message):
        packet = Ether(dst=self.relay_iface_mac)
        packet /= IPv6(src=self.server_ip, dst=self.relay_iface_ip)
        packet /= UDP(sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT)
        packet /= DHCP6_RelayReply(msgtype=13, linkaddr=self.vlan_ip, peeraddr=self.client_link_local)
        packet /= DHCP6OptRelayMsg(message=[message(trid=12345)])

        return packet

    def create_unknown_server_packet(self):
        packet = Ether(dst=self.relay_iface_mac)
        packet /= IPv6(src=self.server_ip, dst=self.relay_iface_ip)
        packet /= UDP(sport=self.DHCP_SERVER_PORT, dport=self.DHCP_SERVER_PORT)
        packet /= DHCP6_RelayReply(msgtype=13, linkaddr=self.vlan_ip, peeraddr=self.client_link_local)

        return packet

    """
     Send functions

    """

    def client_send(self):
        client_messages = [DHCP6_Solicit, DHCP6_Request, DHCP6_Confirm, DHCP6_Renew, DHCP6_Rebind, DHCP6_Release, DHCP6_Decline, DHCP6_Reconf, DHCP6_InfoRequest]
        for message in client_messages:
            packet = self.create_packet(message)
            testutils.send_packet(self, self.client_port_index, packet)

        malformed_packet = self.create_malformed_client_packet(DHCP6_Solicit)
        testutils.send_packet(self, self.client_port_index, malformed_packet)

    def server_send(self):
        server_messages = [DHCP6_Advertise, DHCP6_Reply, DHCP6_Reconf]
        for message in server_messages:
            packet = self.create_server_packet(message)
            packet.src = self.dataplane.get_mac(0, self.server_port_indices[0])
            testutils.send_packet(self, self.server_port_indices[0], packet)

        unknown_packet = self.create_unknown_server_packet()
        unknown_packet.src = self.dataplane.get_mac(0, self.server_port_indices[0])
        testutils.send_packet(self, self.server_port_indices[0], unknown_packet)

    def runTest(self):
        self.client_send()
        self.server_send()
