"""
Everflow Neighbor Discovery Test

Tests that the DUT can mirror ARP packets for IPv4 neighbors and ICMPv6
Neighbor Discovery packets for IPv6 neighbors.
"""

import time

import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane
import ptf.testutils as testutils
from ptf.base_tests import BaseTest
from ptf.mask import Mask


class EverflowNeighborTest(BaseTest):
    IP_PROTO_GRE = 47
    IP_ID = 0

    GRE_PROTO_ERSPAN = 0x88be
    GRE_PROTO_MLNX = 0x8949

    MIRROR_SESSION_SRC_IP = "1.1.1.1"
    MIRROR_SESSION_DST_IP = "2.2.2.2"
    MIRROR_SESSION_TTL = 1
    MIRROR_SESSION_DSCP = 8

    OUTER_HEADER_LENGTH = 38

    def setUp(self):
        """
        Fetches all the parameters we need to run the tests.
        """

        self.dataplane = ptf.dataplane_instance

        self.test_params = testutils.test_params_get()
        self.hwsku = self.test_params['hwsku']
        self.asic_type = self.test_params['asic_type']
        self.router_mac = self.test_params['router_mac']
        self.src_port = int(self.test_params['src_port'])
        self.dst_mirror_ports = [
            int(p)
            for p
            in self.test_params['dst_mirror_ports'].split(",")
            if p
        ]
        self.dst_ports = [
            int(p)
            for p
            in self.test_params['dst_ports'].split(",")
        ]

        self.base_pkt = testutils.simple_arp_packet(
            eth_dst=self.router_mac,
            eth_src=self.dataplane.get_mac(0, 0)
        )

        self.basev6_pkt = testutils.simple_icmpv6_packet(
            eth_dst=self.router_mac,
            eth_src=self.dataplane.get_mac(0, 0),
            icmp_type=135
        )

        testutils.add_filter(self.gre_filter)

    def gre_filter(self, pkt_str):
        """
        Filters GRE packets.

        Keyword arguments:
        pkt_str -- the packet being filtered in string format
        """

        try:
            pkt = scapy.Ether(pkt_str)

            if scapy.IP not in pkt:
                return False

            return pkt[scapy.IP].proto == self.IP_PROTO_GRE
        except:
            return False

    def trim_extra_asic_headers(self, pkt, payload_size):
        """
        Removes extra, ASIC-specific information from received packets, leaving
        only the outermost headers (Ether / IP / GRE) and the payload.

        This includes ERSPAN because it is still a relatively new standard, so
        a lot of ASICs do not support it even if it is specified in the GRE
        protocol field.

        The same is true for extra info that different vendors include in their
        GRE headers.

        See https://tools.ietf.org/html/draft-foschiano-erspan-03#section-4.1
        for more info about ERSPAN.

        EXAMPLE:
         <----- Outer Headers -----> <- Payload ->
        | Ether | IP | GRE | ERSPAN | Ether | ARP |

            is converted to

        | Ether | IP | GRE | Ether | ARP |

        Keyword arguments:
        pkt -- the packet being trimmed
        payload_size -- the size of the payload
        """

        if len(pkt) < self.OUTER_HEADER_LENGTH + payload_size:
            return None

        outer_frame = pkt[:self.OUTER_HEADER_LENGTH]
        inner_frame = pkt[-payload_size:]
        return outer_frame + inner_frame

    def check_mirrored_packet(self, ipv6=False):
        """
        Send an ARP or ND request and verify that it is mirrored.

        NOTE: This test only verifies that the payload is correct and that the
        outermost packet headers are correct (Ether / IP / GRE). Any extra info
        or headers that an ASIC chooses to include is ignored.

        Keyword arguments:
        ipv6 -- the IP version for this test run
        """

        pkt = self.basev6_pkt if ipv6 else self.base_pkt
        payload = pkt.copy()

        if self.mirror_stage == "egress":
            payload['Ethernet'].src = self.router_mac
            payload['IP'].ttl -= 1

        exp_pkt = testutils.simple_gre_packet(
            eth_src=self.router_mac,
            ip_src=self.MIRROR_SESSION_SRC_IP,
            ip_dst=self.MIRROR_SESSION_DST_IP,
            ip_dscp=self.MIRROR_SESSION_DSCP,
            ip_id=self.IP_ID,
            ip_ttl=self.MIRROR_SESSION_TTL,
            inner_frame=payload
        )

        if self.asic_type in ["mellanox"]:
            exp_pkt['GRE'].proto = self.GRE_PROTO_MLNX
        else:
            exp_pkt['GRE'].proto = self.GRE_PROTO_ERSPAN

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ihl")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "flags")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")

        # NOTE: The fanout modifies the tos field, so it will always be 0 even
        # if we specify a particular value in the mirror session.
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "tos")

        # NOTE: Later versions of PTF allow you to ignore extra bytes, which
        # would allow us to specify an expected packet to be received by
        # masking off everything but the outer headers (Ether / IP / GRE).
        #
        # For now we just trim away any extra headers and check that the packet
        # matches after it is received.

        self.dataplane.flush()

        testutils.send_packet(self, self.src_port, pkt)
        _, _, rcv_pkt, _ = testutils.dp_poll(self, timeout=0.1)

        rcv_pkt = self.trim_extra_asic_headers(rcv_pkt, len(payload))

        if rcv_pkt and masked_exp_pkt.pkt_match(rcv_pkt):
            print("{} mirroring succesful".format("ND" if ipv6 else "ARP"))
        else:
            assert False

    def runTest(self):
        """
        Tests that the DUT can mirror ARP packets for IPv4 neighbors and
        ICMPv6 Neighbor Discovery packets for IPv6 neighbors.
        """

        print("\nStarting Everflow Neighbor Discovery test")

        self.check_mirrored_packet()
        self.check_mirrored_packet(ipv6=True)
