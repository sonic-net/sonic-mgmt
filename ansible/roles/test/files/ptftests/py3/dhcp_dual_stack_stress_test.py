import logging
import time

import ptf
import ptf.packet as packet
import ptf.testutils as testutils
import scapy
from ptf.base_tests import BaseTest

IPv6 = scapy.layers.inet6.IPv6
DHCP6_Solicit = scapy.layers.dhcp6.DHCP6_Solicit
DHCP6OptClientId = scapy.layers.dhcp6.DHCP6OptClientId
DUID_LL = scapy.layers.dhcp6.DUID_LL
in6_mactoifaceid = scapy.utils6.in6_mactoifaceid

logger = logging.getLogger(__name__)


class DHCPDualStackStressTest(BaseTest):
    """
    Send DHCPv4 DISCOVER and DHCPv6 SOLICIT packets back to back from every
    client port for the configured duration, so DHCPmon on the DUT processes
    both address families at the same time.
    """

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        self.test_params = testutils.test_params_get()
        self.duration = float(self.test_params["duration"])

        self.packets = []
        for port in self.test_params["client_port_indices"]:
            mac = self.dataplane.get_mac(0, port)
            mac = mac.decode() if isinstance(mac, bytes) else mac
            self.packets.append((port, self._discover(mac)))
            self.packets.append((port, self._solicit(mac)))

    @staticmethod
    def _discover(mac):
        return (packet.Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
                / packet.IP(src="0.0.0.0", dst="255.255.255.255")
                / packet.UDP(sport=68, dport=67)
                / packet.BOOTP(op=1, chaddr=bytes.fromhex(mac.replace(":", "")))
                / packet.DHCP(options=[("message-type", "discover"), "end"]))

    @staticmethod
    def _solicit(mac):
        return (packet.Ether(src=mac, dst="33:33:00:01:00:02")
                / IPv6(src="fe80::" + in6_mactoifaceid(mac), dst="ff02::1:2")
                / packet.UDP(sport=546, dport=547)
                / DHCP6_Solicit(trid=1)
                / DHCP6OptClientId(duid=DUID_LL(lladdr=mac)))

    def runTest(self):
        rounds = 0
        deadline = time.monotonic() + self.duration
        while time.monotonic() < deadline:
            for port, pkt in self.packets:
                testutils.send_packet(self, port, pkt)
            rounds += 1
        logger.info("Sent %d DHCPv4 DISCOVER and DHCPv6 SOLICIT rounds", rounds)
        self.assertGreater(rounds, 0)
