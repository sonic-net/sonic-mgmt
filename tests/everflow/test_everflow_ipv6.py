"""Test cases to support the Everflow IPv6 Mirroring feature in SONiC."""
import pytest
import ptf.testutils as testutils

from everflow_test_utilities import BaseEverflowTest

# Module-level fixtures
from everflow_test_utilities import setup_info  # noqa: F401, E501 lgtm[py/unused-import] pylint: disable=import-error

pytestmark = [
    pytest.mark.topology("t1")
]

EVERFLOW_V6_RULES = "ipv6_test_rules.yaml"


class EverflowIPv6Tests(BaseEverflowTest):
    """
    Base class for testing IPv6 match types for the Everflow feature.

    Todo:
        - Converge w/ existing Everflow tests
        - Add Egress IPv6 test
        - Check for the forwarded packet in the test cases
        - Figure out some way to automate the acl.json file
    """

    DEFAULT_SRC_IP = "ffbe:0225:7c6b:a982:d48b:230e:f271:0000"
    DEFAULT_DST_IP = "ffbe:0225:7c6b:a982:d48b:230e:f271:0001"

    def test_src_ipv6_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on Source IPv6 addresses."""
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0002"
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_dst_ipv6_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on Destination IPv6 addresses."""
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0003"
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_next_header_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on the Next Header field."""
        test_packet = self._base_tcpv6_packet(ptfadapter, setup_info, next_header=0x7E)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_l4_src_port_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on the L4 Source Port."""
        test_packet = self._base_tcpv6_packet(ptfadapter, setup_info, sport=9000)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_l4_dst_port_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on the L4 Destination Port."""
        test_packet = self._base_tcpv6_packet(ptfadapter, setup_info, dport=9001)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_l4_src_port_range_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on a range of L4 Source Ports."""
        test_packet = self._base_tcpv6_packet(ptfadapter, setup_info, sport=10200)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_l4_dst_port_range_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on a range of L4 Destination Ports."""
        test_packet = self._base_tcpv6_packet(ptfadapter, setup_info, dport=10700)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_tcp_flags_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on TCP Flags."""
        test_packet = self._base_tcpv6_packet(ptfadapter, setup_info, flags=0x1B)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_dscp_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on DSCP."""
        test_packet = self._base_tcpv6_packet(ptfadapter, setup_info, dscp=37)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_l4_range_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match from a source port to a range of destination ports and vice-versa."""
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0004",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0005",
            sport=11200,
            dport=11700
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0005",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0004",
            sport=11700,
            dport=11200
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_tcp_response_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match a SYN -> SYN-ACK pattern."""
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0006",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0007",
            flags=0x2
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0007",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0006",
            flags=0x12
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_tcp_application_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match a TCP handshake between a client and server."""
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0008",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0009",
            sport=12000,
            dport=443,
            flags=0x2
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0009",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0008",
            sport=443,
            dport=12000,
            flags=0x12
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_udp_application_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match UDP traffic between a client and server application."""
        test_packet = self._base_udpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000a",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000b",
            dscp=8,
            sport=12001,
            dport=514
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)
        test_packet = self._base_udpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000b",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000a",
            dscp=8,
            sport=514,
            dport=12001
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_any_protocol(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that the protocol number is ignored if it is not specified in the ACL rule."""
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000c",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000d"
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

        test_packet = self._base_udpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000c",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000d"
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

        test_packet = self._base_udpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000c",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000d",
            next_header=0xAB
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_any_transport_protocol(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that src port and dst port rules match regardless of whether TCP or UDP traffic is sent."""
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:001c",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:001d",
            sport=12002,
            dport=12003
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

        test_packet = self._base_udpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:001c",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:001d",
            sport=12002,
            dport=12003
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_invalid_tcp_rule(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that the ASIC does not reject rules with TCP flags if the protocol is not TCP."""
        pass

        # NOTE: This type of rule won't really function since you need a TCP packet to have TCP flags.
        # However, we have still included such a rule in the acl.json file to validate that the SAI
        # will not crash if such a rule is installed. If this does happen, we expect the whole test
        # suite + loganaylzer + the sanity check to fail.

    def test_source_subnet(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match packets with a Source IPv6 Subnet."""
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:b000:0000:0000:0000:0010",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0010",
            sport=12006,
            dport=12007
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_dest_subnet(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match packets with a Destination IPv6 Subnet."""
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0010",
            dst_ip="ffbe:0225:7c6b:b000:0000:0000:0000:0010",
            sport=12008,
            dport=12009
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_both_subnets(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match packets with both source and destination subnets."""
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:c000:0000:0000:0000:0010",
            dst_ip="ffbe:0225:7c6b:d000:0000:0000:0000:0010",
            sport=12010,
            dport=12011
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def test_fuzzy_subnets(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match packets with non-standard subnet sizes."""
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:e000:0000:0000:0000:0010",
            dst_ip="ffbe:0225:7c6b:f000:0000:0000:0000:0010",
            sport=12012,
            dport=12013
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet)

    def _base_tcpv6_packet(self,
                           ptfadapter,
                           setup,
                           src_ip=DEFAULT_SRC_IP,
                           dst_ip=DEFAULT_DST_IP,
                           next_header=None,
                           dscp=None,
                           sport=2020,
                           dport=8080,
                           flags=0x10):
        pkt = testutils.simple_tcpv6_packet(
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            eth_dst=setup["router_mac"],
            ipv6_src=src_ip,
            ipv6_dst=dst_ip,
            ipv6_dscp=dscp,
            ipv6_hlim=64,
            tcp_sport=sport,
            tcp_dport=dport,
            tcp_flags=flags,
        )

        if next_header:
            pkt["IPv6"].nh = next_header

        return pkt

    def _base_udpv6_packet(self,
                           ptfadapter,
                           setup,
                           src_ip=DEFAULT_SRC_IP,
                           dst_ip=DEFAULT_DST_IP,
                           next_header=None,
                           dscp=None,
                           sport=2020,
                           dport=8080):
        pkt = testutils.simple_udpv6_packet(
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            eth_dst=setup["router_mac"],
            ipv6_src=src_ip,
            ipv6_dst=dst_ip,
            ipv6_dscp=dscp,
            ipv6_hlim=64,
            udp_sport=sport,
            udp_dport=dport,
        )

        if next_header:
            pkt["IPv6"].nh = next_header

        return pkt


class TestIngressEverflowIPv6(EverflowIPv6Tests):
    """Parameters for Ingress Everflow IPv6 testing. (Ingress ACLs/Ingress Mirror)"""
    def acl_stage(self):
        return "ingress"

    def mirror_type(self):
        return "ingress"

    @pytest.fixture(scope='class',  autouse=True)
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session, config_method):
        table_name = self._get_table_name(duthost)
        temporary_table = False

        if not table_name:
            table_name = "EVERFLOWV6"
            temporary_table = True
            self.apply_acl_table_config(duthost, table_name, "MIRRORV6", config_method)

        self.apply_acl_rule_config(duthost, table_name, setup_mirror_session["session_name"], config_method, rules=EVERFLOW_V6_RULES)

        yield

        self.remove_acl_rule_config(duthost, table_name, config_method)

        if temporary_table:
            self.remove_acl_table_config(duthost, table_name, config_method)

    # TODO: This can probably be refactored into a common utility method later.
    def _get_table_name(self, duthost):
        show_output = duthost.command("show acl table")

        table_name = None
        for line in show_output["stdout_lines"]:
            if "MIRRORV6" in line:
                # NOTE: Once we branch out the sonic-mgmt repo we can skip the version check.
                if "201811" in duthost.os_version or "ingress" in line:
                    table_name = line.split()[0]
                    break

        return table_name
