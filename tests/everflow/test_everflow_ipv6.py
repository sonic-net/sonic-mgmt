"""Test cases to support the Everflow IPv6 Mirroring feature in SONiC."""
import binascii
import logging
import random
import pytest
import ptf.testutils as testutils

from ptf.mask import Mask
import ptf.packet as packet

from tests.common.helpers.assertions import pytest_assert
from everflow_test_utilities import BaseEverflowTest

# Module-level fixtures
from everflow_test_utilities import setup_info  # noqa: F401, E501 lgtm[py/unused-import] pylint: disable=import-error

pytestmark = [
    pytest.mark.topology("t1")
]


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

    OUTER_HEADER_SIZE = 38

    def test_src_ipv6_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on Source IPv6 addresses."""
        test_packet = self._base_tcp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0002"
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_dst_ipv6_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on Destination IPv6 addresses."""
        test_packet = self._base_tcp_packet(
            ptfadapter,
            setup_info,
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0003"
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_next_header_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on the Next Header field."""
        test_packet = self._base_tcp_packet(ptfadapter, setup_info, next_header=0x7E)

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_l4_src_port_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on the L4 Source Port."""
        test_packet = self._base_tcp_packet(ptfadapter, setup_info, sport=9000)

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_l4_dst_port_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on the L4 Destination Port."""
        test_packet = self._base_tcp_packet(ptfadapter, setup_info, dport=9001)

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_l4_src_port_range_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on a range of L4 Source Ports."""
        test_packet = self._base_tcp_packet(ptfadapter, setup_info, sport=10200)

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_l4_dst_port_range_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on a range of L4 Destination Ports."""
        test_packet = self._base_tcp_packet(ptfadapter, setup_info, dport=10700)

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_tcp_flags_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on TCP Flags."""
        test_packet = self._base_tcp_packet(ptfadapter, setup_info, flags=0x1B)

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_dscp_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match on DSCP."""
        test_packet = self._base_tcp_packet(ptfadapter, setup_info, dscp=37)

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_l4_range_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match from a source port to a range of destination ports and vice-versa."""
        test_packet = self._base_tcp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0004",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0005",
            sport=11200,
            dport=11700
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

        test_packet = self._base_tcp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0005",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0004",
            sport=11700,
            dport=11200
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_tcp_response_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match a SYN -> SYN-ACK pattern."""
        test_packet = self._base_tcp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0006",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0007",
            flags=0x2
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

        test_packet = self._base_tcp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0007",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0006",
            flags=0x12
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_tcp_application_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match a TCP handshake between a client and server."""
        test_packet = self._base_tcp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0008",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0009",
            sport=12000,
            dport=443,
            flags=0x2
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

        test_packet = self._base_tcp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0009",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0008",
            sport=443,
            dport=12000,
            flags=0x12
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_udp_application_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match UDP traffic between a client and server application."""
        test_packet = self._base_udp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000a",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000b",
            dscp=8,
            sport=12001,
            dport=514
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

        test_packet = self._base_udp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000b",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000a",
            dscp=8,
            sport=514,
            dport=12001
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_any_protocol(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that the protocol number is ignored if it is not specified in the ACL rule."""
        test_packet = self._base_tcp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000c",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000d",
            sport=12002,
            dport=12003
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

        test_packet = self._base_udp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000c",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000d",
            sport=12002,
            dport=12003
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

        test_packet = self._base_udp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000c",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000d",
            sport=12002,
            dport=12003,
            next_header=0xAB
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_invalid_tcp_rule(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that the ASIC does not reject rules with TCP flags if the protocol is not TCP."""
        test_packet = self._base_tcp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000e",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:000f",
            dscp=16,
            sport=12004,
            dport=12005,
            flags=0x12,
            next_header=0x7F
        )

        # NOTE: We're keeping this test + its associated ACL rule here for now since tbh
        # it mostly just exists to see if the ASIC will panic if it sees proto=UDP +
        # TCP flags in the same ACL rule. Will take another look at the payload comparison
        # logic later.
        pytest.xfail("Invalid comparison logic")

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_source_subnet(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match packets with a Source IPv6 Subnet."""
        test_packet = self._base_tcp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:b000:0000:0000:0000:0010",
            dst_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0010",
            sport=12006,
            dport=12007
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_dest_subnet(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match packets with a Destination IPv6 Subnet."""
        test_packet = self._base_tcp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:a982:d48b:230e:f271:0010",
            dst_ip="ffbe:0225:7c6b:b000:0000:0000:0000:0010",
            sport=12008,
            dport=12009
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_both_subnets(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match packets with both source and destination subnets."""
        test_packet = self._base_tcp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:c000:0000:0000:0000:0010",
            dst_ip="ffbe:0225:7c6b:d000:0000:0000:0000:0010",
            sport=12010,
            dport=12011
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def test_fuzzy_subnets(self, setup_info, setup_mirror_session, ptfadapter, duthost):
        """Verify that we can match packets with non-standard subnet sizes."""
        test_packet = self._base_tcp_packet(
            ptfadapter,
            setup_info,
            src_ip="ffbe:0225:7c6b:e000:0000:0000:0000:0010",
            dst_ip="ffbe:0225:7c6b:f000:0000:0000:0000:0010",
            sport=12012,
            dport=12013
        )

        self._send_and_check_mirror_packets(setup_info,
                                            setup_mirror_session,
                                            ptfadapter,
                                            duthost,
                                            test_packet)

    def _send_and_check_mirror_packets(self, setup, mirror_session, ptfadapter, duthost, mirror_packet):
        expected_mirror_packet = self._get_expected_mirror_packet(mirror_session, setup, duthost, mirror_packet)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self._get_src_port(setup), mirror_packet)
        _, received_packet = testutils.verify_packet_any_port(
            ptfadapter,
            expected_mirror_packet,
            ports=[self._get_monitor_port(setup, mirror_session, duthost)]
        )

        logging.info("received: %s", packet.Ether(received_packet).summary())

        inner_packet = self._extract_mirror_payload(received_packet, len(mirror_packet))
        logging.info("inner_packet: %s", inner_packet.summary())
        logging.info("expected_packet: %s", mirror_packet.summary())
        pytest_assert(Mask(inner_packet).pkt_match(mirror_packet), "Mirror payload does not match received packet")

    def _get_src_port(self, setup):
        return setup["port_index_map"][random.choice(setup["port_index_map"].keys())]

    # TODO: This could probably be refactored into a common utility method later.
    def _get_monitor_port(self, setup, mirror_session, duthost):
        mirror_output = duthost.command("show mirror_session")
        logging.info("mirror session configuration: %s", mirror_output["stdout"])

        pytest_assert(mirror_session["session_name"] in mirror_output["stdout"],
                      "Test mirror session {} not found".format(mirror_session["session_name"]))

        pytest_assert(len(mirror_output["stdout_lines"]) == 3,
                      "Unexpected number of mirror sesssions:\n{}".format(mirror_output["stdout"]))

        monitor_intf = mirror_output["stdout_lines"][2].split()[-1:][0]

        pytest_assert(monitor_intf in setup["port_index_map"],
                      "Invalid monitor port:\n{}".format(mirror_output["stdout"]))
        logging.info("selected monitor interface %s (port=%s)", monitor_intf, setup["port_index_map"][monitor_intf])

        return setup["port_index_map"][monitor_intf]

    def _get_expected_mirror_packet(self, mirror_session, setup, duthost, mirror_packet):
        payload = mirror_packet.copy()

        # Add vendor specific padding to the packet
        if duthost.facts["asic_type"] in ["mellanox"]:
            payload = binascii.unhexlify("0" * 44) + str(payload)

        if duthost.facts["asic_type"] in ["barefoot"]:
            payload = binascii.unhexlify("0" * 24) + str(payload)

        expected_packet = testutils.simple_gre_packet(
            eth_src=setup["router_mac"],
            ip_src=mirror_session["session_src_ip"],
            ip_dst=mirror_session["session_dst_ip"],
            ip_dscp=int(mirror_session["session_dscp"]),
            ip_id=0,
            ip_ttl=int(mirror_session["session_ttl"]),
            inner_frame=payload
        )

        expected_packet["GRE"].proto = mirror_session["session_gre"]

        expected_packet = Mask(expected_packet)
        expected_packet.set_do_not_care_scapy(packet.Ether, "dst")
        expected_packet.set_do_not_care_scapy(packet.IP, "ihl")
        expected_packet.set_do_not_care_scapy(packet.IP, "len")
        expected_packet.set_do_not_care_scapy(packet.IP, "flags")
        expected_packet.set_do_not_care_scapy(packet.IP, "chksum")

        # The fanout switch may modify this value en route to the PTF so we should ignore it, even
        # though the session does have a DSCP specified.
        expected_packet.set_do_not_care_scapy(packet.IP, "tos")

        # Mask off the payload (we check it later)
        expected_packet.set_do_not_care(self.OUTER_HEADER_SIZE * 8, len(payload) * 8)

        return expected_packet

    def _extract_mirror_payload(self, encapsulated_packet, payload_size):
        pytest_assert(len(encapsulated_packet) >= self.OUTER_HEADER_SIZE,
                      "Incomplete packet, expected at least {} header bytes".format(self.OUTER_HEADER_SIZE))

        inner_frame = encapsulated_packet[-payload_size:]
        return packet.Ether(inner_frame)

    def _base_tcp_packet(self,
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

    def _base_udp_packet(self,
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
    def setup_acl_table(self, duthost, setup_info, setup_mirror_session):
        duthost.command("rm -rf everflow_v6_tests")
        duthost.command("mkdir -p everflow_v6_tests")

        table_name = self._get_table_name(duthost)
        temporary_table = False

        if not table_name:
            table_name = "EVERFLOWV6"
            temporary_table = True
            duthost.command("config acl add table {} MIRRORV6".format(table_name))

        duthost.host.options["variable_manager"].extra_vars.update({"acl_table_name": table_name})
        duthost.template(src="everflow/templates/acl_rule_v6.json.j2", dest="everflow_v6_tests/acl_rule_v6.json")
        duthost.command("acl-loader update full everflow_v6_tests/acl_rule_v6.json --session_name={}".format(setup_mirror_session["session_name"]))

        yield

        duthost.copy(src="everflow/templates/acl_rule_persistent-del.json", dest="everflow_v6_tests/acl_rule_persistent-del.json")
        duthost.command("acl-loader update full everflow_v6_tests/acl_rule_persistent-del.json")
        duthost.command("rm -rf everflow_v6_tests")

        if temporary_table:
            duthost.command("config acl remove table {}".format(table_name))

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
