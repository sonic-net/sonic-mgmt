import ipaddress
import json
import logging
import ptf

# Packet Test Framework imports
import ptf
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf import config
from ptf.base_tests import BaseTest

logger = logging.getLogger(__name__)

class PopulateFdb(BaseTest):
    """
        Populate DUT FDB entries
    """
    TCP_DST_PORT = 5000
    TCP_SRC_PORT = 6000

    def __init__(self):
        """
            class constructor

            Args:
                None

            Returns:
                None
        """
        BaseTest.__init__(self)

    def setUp(self):
        """
            Sets up Populate FDB instance data

            Args:
                None

            Returns:
                None
        """
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        self.testParams = testutils.test_params_get()
        self.packetCount = self.testParams["packet_count"]
        self.startMac = self.testParams["start_mac"]

        self.configFile = self.testParams["config_data"]
        with open(self.configFile) as fp:
            self.configData = json.load(fp)

        self.dutMac = self.configData["dut_mac"]
        self.macToIpRatio = [int(i) for i in self.testParams["mac_to_ip_ratio"].split(':')]
        self.assertTrue(
            len(self.macToIpRatio) == 2 and self.macToIpRatio[0] > 0 and self.macToIpRatio[1] > 0,
            "Invalid MAC to IP ratio: {0}".format(self.testParams["mac_to_ip_ratio"])
        )

        if config["log_dir"] is not None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        """
            Tears down FDB instance data

            Args:
                None

            Returns:
                None
        """
        if config["log_dir"] is not None:
            self.dataplane.stop_pcap()

    def __convertMacToInt(self, mac):
        """
            Converts MAC address to integer

            Args:
                mac (str): MAC Address

            Returns:
                mac (int): integer representation of MAC address
        """
        return int(mac.translate(None, ":.- "), 16)

    def __convertMacToStr(self, mac):
        """
            Converts MAC address to string

            Args:
                mac (int): MAC Address

            Returns:
                mac (str): string representation of MAC address
        """
        mac = "{:012x}".format(mac)
        return ":".join(mac[i : i + 2] for i in range(0, len(mac), 2))

    def __prepareVmIp(self):
        """
            Prepares VM IP addresses

            Args:
                None

            Returns:
                vmIp (dict): Map containing vlan to VM IP address
        """
        vmIp = {}
        for vlan, config in self.configData["vlan_interfaces"].items():
            prefixLen = self.configData["vlan_interfaces"][vlan]["prefixlen"]
            ipCount = 2**(32 - prefixLen) - 3
            numDistinctIp = self.packetCount * self.macToIpRatio[1] / self.macToIpRatio[0]
            self.assertTrue(
                ipCount >= numDistinctIp,
                "Vlan network '{0}' does not support the requested number of IPs '{1}'".format(
                    ipCount,
                    numDistinctIp
                )
            )
            vmIp[vlan] = ipaddress.ip_address(unicode(config["addr"])) + 1

        return vmIp

    def __populateDutFdb(self):
        """
            Populates DUT FDB entries

            It accepts MAC to IP ratio and packet count. It generates packets withratio of distinct MAC addresses
            to distinct IP addresses as provided. The IP addresses starts from VLAN address pool.

            Args:
                None

            Returns:
                None
        """
        if not self.configData["vlan_ports"]:
            # No vlan port to test
            return

        packet = testutils.simple_tcp_packet(
            eth_dst=self.dutMac,
            tcp_sport=self.TCP_SRC_PORT,
            tcp_dport=self.TCP_DST_PORT
        )
        vmIp = self.__prepareVmIp()
        macInt = self.__convertMacToInt(self.startMac)
        numMac = numIp = 0
        for i in range(self.packetCount):
            port = i % len(self.configData["vlan_ports"])
            vlan = self.configData["vlan_ports"][port]["vlan"]

            if i % self.macToIpRatio[1] == 0:
                mac = self.__convertMacToStr(macInt + i)
                numMac += 1
            if i % self.macToIpRatio[0] == 0:
                vmIp[vlan] = ipaddress.ip_address(unicode(vmIp[vlan])) + 1
                numIp += 1

            packet[scapy.Ether].src = mac
            packet[scapy.IP].src = str(vmIp[vlan])
            packet[scapy.IP].dst = self.configData["vlan_interfaces"][vlan]["addr"]
            testutils.send(self, self.configData["vlan_ports"][port]["index"], packet)

        logger.info(
            "Generated {0} packets with distinct {1} MAC addresses and {2} IP addresses".format(
                self.packetCount,
                numMac,
                numIp
            )
        )

    def runTest(self):
        self.__populateDutFdb()
