"""
Test cases for IPv6 Egress Everflow functionality.

This module tests egress ACL with egress mirroring for IPv6 traffic,
covering various SAI ACL table attributes and scenarios.
"""

import logging
import pytest
import ptf.testutils as testutils
import ptf.packet as packet

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode
from tests.common.fixtures.ptfhost_utils import ptf_portmap_file
from tests.everflow.everflow_test_utilities import BaseEverflowTest
from tests.everflow.everflow_test_utilities import DOWN_STREAM, UP_STREAM

pytestmark = [
    pytest.mark.topology("t1", "t2")
]

EVERFLOW_IPV6_EGRESS_RULES = "ipv6_egress_test_rules.yaml"
# Removed unused 'acl_rules_file' variable (was causing Flake8 F841 error)


@pytest.fixture(scope="module")
def setup_ipv6_egress_routes(setup_info, tbinfo):
    """
    Set up IPv6 routes required for egress Everflow testing.
    """
    duthost = setup_info[DOWN_STREAM]["everflow_dut"]
    namespace = setup_info[DOWN_STREAM]["everflow_namespace"]

    # IPv6 test routes
    test_routes = [
        ("2001:db8:1::/64", "fc00:1::2"),
        ("2001:db8:2::/64", "fc00:1::2")
    ]

    # Add routes
    for route, nexthop in test_routes:
        duthost.shell(f"ip -6 route add {route} via {nexthop}", module_ignore_errors=True)

    yield

    # Teardown: Remove routes
    for route, nexthop in test_routes:
        duthost.shell(f"ip -6 route del {route} via {nexthop}", module_ignore_errors=True)


@pytest.fixture(scope="class")
def conftest_docker_cp_acl_rules(ptfhost, duthost):
    """
    Copy the ACL rule definition file to the PTF container.
    """
    ptfhost.copy(src="everflow/files/everflow_ipv6_egress_acl_rules.yaml",
                 dest="/root/ipv6_egress_test_rules.yaml")


@pytest.mark.usefixtures(
    "setup_vlan_interfaces",
    "conftest_docker_cp_acl_rules",
    "setup_acl_table"
)
class TestEverflowV6EgressAclEgressMirror(BaseEverflowTest):
    """
    Test suite for IPv6 Egress ACL with Egress Mirroring.
    """

    @pytest.fixture(scope="class", autouse=True)
    def setup_acl_table(self, duthost, setup_info):
        """
        Apply the egress ACL table definition.
        """
        namespace = setup_info[DOWN_STREAM]["everflow_namespace"]
        mirror_session_name = setup_info[DOWN_STREAM]["mirror_session_name"]
        
        logging.info("Applying ACL rule config for session {}".format(mirror_session_name))
        self.apply_acl_rule_config(
            duthost,
            EVERFLOW_IPV6_EGRESS_RULES,
            mirror_session_name,
            namespace=namespace
        )

    def _base_tcpv6_packet(self, ptfadapter, setup, direction, vlan_id=None,
                           src_ip=None, dst_ip=None,
                           ip_protocol=None,
                           l4_src_port=None, l4_dst_port=None,
                           tcp_flags=None,
                           dl_dst=None,
                           ip_dscp=None,
                           ip_ecn=None,
                           ip_ttl=None,
                           ip_id=None,
                           **kwargs):
        """
        Generate a base TCPv6 packet for testing.
        """
        if direction == DOWN_STREAM:
            src_mac = setup[direction]["src_mac"]
            if dl_dst is None:
                dl_dst = setup[direction]["ingress_router_mac"]
            
            # Use specific IPs if provided, else use defaults
            pkt_src_ip = src_ip or "2001:db8:1::1"
            pkt_dst_ip = dst_ip or "2001:db8:2::1"
            
            base_pkt = testutils.simple_tcpv6_packet(
                eth_src=src_mac,
                eth_dst=dl_dst,
                ipv6_src=pkt_src_ip,
                ipv6_dst=pkt_dst_ip,
                ipv6_hlim=64,
                **kwargs
            )
            
            if vlan_id:
                # FIX: Pass 'eth_dst=dl_dst' to ensure the correct MAC is used for VLAN packets.
                base_pkt = testutils.simple_tcpv6_packet(
                    eth_src=src_mac,
                    eth_dst=dl_dst,  # This was the bug, it was missing.
                    ipv6_src=pkt_src_ip,
                    ipv6_dst=pkt_dst_ip,
                    ipv6_hlim=64,
                    dl_vlan_enable=True,
                    vlan_vid=vlan_id,
                    **kwargs
                )
        else:  # UP_STREAM
            src_mac = setup[direction]["src_mac"]
            if dl_dst is None:
                dl_dst = setup[direction]["src_mac"]
            
            # Use specific IPs if provided, else use defaults
            pkt_src_ip = src_ip or "2001:db8:2::1"
            pkt_dst_ip = dst_ip or "2001:db8:1::1"

            base_pkt = testutils.simple_tcpv6_packet(
                eth_src=setup[direction]["ingress_router_mac"],
                eth_dst=dl_dst,
                ipv6_src=pkt_src_ip,
                ipv6_dst=pkt_dst_ip,
                ipv6_hlim=63,
                **kwargs
            )
            
            if vlan_id:
                base_pkt = testutils.simple_tcpv6_packet(
                    eth_src=setup[direction]["ingress_router_mac"],
                    eth_dst=dl_dst,
                    ipv6_src=pkt_src_ip,
                    ipv6_dst=pkt_dst_ip,
                    ipv6_hlim=63,
                    dl_vlan_enable=True,
                    vlan_vid=vlan_id,
                    **kwargs
                )

        # Update fields if they are specified
        if ip_protocol:
            base_pkt['IPv6'].nh = ip_protocol
        if l4_src_port:
            base_pkt['TCP'].sport = l4_src_port
        if l4_dst_port:
            base_pkt['TCP'].dport = l4_dst_port
        if tcp_flags:
            base_pkt['TCP'].flags = tcp_flags
        if ip_dscp:
            base_pkt['IPv6'].tc = ip_dscp << 2
        if ip_ecn:
            base_pkt['IPv6'].tc = (base_pkt['IPv6'].tc & ~0x3) | (ip_ecn & 0x3)
        if ip_ttl:
            base_pkt['IPv6'].hlim = ip_ttl
        if ip_id:
            # IPv6 doesn't have an IP ID field like IPv4.
            # If flow label is intended, it should be passed as ipv6_fl
            pass

        return base_pkt

    # FIX: Removed redundant _get_tx_port_id_list method.
    # The base class method is inherited automatically.
    # This fixes a Flake8 F811 (redefinition) error.

    def test_src_ipv6_match(self, setup_info, setup_mirror_session, ptfadapter, duthost,
                            setup_ipv6_egress_routes):
        """
        Verify ACL match on source IPv6 address.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])

        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            src_ip="2001:db8:1::1"  # This should match rule 100
        )

        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=True
        )

    def test_dst_ipv6_match(self, setup_info, setup_mirror_session, ptfadapter, duthost,
                            setup_ipv6_egress_routes):
        """
        Verify ACL match on destination IPv6 address.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])

        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            dst_ip="2001:db8:2::1"  # This should match rule 99
        )

        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=True
        )

    def test_l4_src_port_match(self, setup_info, setup_mirror_session, ptfadapter, duthost,
                             setup_ipv6_egress_routes):
        """
        Verify ACL match on L4 source port.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])

        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            l4_src_port=1001  # This should match rule 98
        )

        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=True
        )

    def test_l4_dst_port_match(self, setup_info, setup_mirror_session, ptfadapter, duthost,
                             setup_ipv6_egress_routes):
        """
        Verify ACL match on L4 destination port.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])

        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            l4_dst_port=1002  # This should match rule 97
        )

        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=True
        )

    def test_ip_protocol_match(self, setup_info, setup_mirror_session, ptfadapter, duthost,
                              setup_ipv6_egress_routes):
        """
        Verify ACL match on IP protocol number.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])

        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            ip_protocol=6  # This is TCP, should match rule 96
        )

        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=True
        )

    def test_tcp_flags_match(self, setup_info, setup_mirror_session, ptfadapter, duthost,
                             setup_ipv6_egress_routes):
        """
        Verify ACL match on TCP flags.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])

        # SYN flag (0x02)
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            tcp_flags=0x02  # This should match rule 95
        )

        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=True
        )

    def test_dscp_match(self, setup_info, setup_mirror_session, ptfadapter, duthost,
                        setup_ipv6_egress_routes):
        """
        Verify ACL match on DSCP value.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])

        # DSCP 8 (0x08)
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            ip_dscp=8  # This should match rule 94
        )

        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=True
        )

    def test_ecn_match(self, setup_info, setup_mirror_session, ptfadapter, duthost,
                       setup_ipv6_egress_routes):
        """
        Verify ACL match on ECN value.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])

        # ECN 1
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            ip_ecn=1  # This should match rule 93
        )

        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=True
        )

    def test_ttl_match(self, setup_info, setup_mirror_session, ptfadapter, duthost,
                       setup_ipv6_egress_routes):
        """
        Verify ACL match on TTL (Hop Limit) value.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])

        # TTL 64
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            ip_ttl=64  # This should match rule 92
        )

        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=True
        )

    def test_no_match(self, setup_info, setup_mirror_session, ptfadapter, duthost,
                      setup_ipv6_egress_routes):
        """
        Verify that non-matching traffic is not mirrored.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])

        # A packet designed to not match any rule
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            src_ip="2001:db8:aaaa::1",  # No match
            dst_ip="2001:db8:bbbb::1",  # No match
            l4_src_port=2001,           # No match
            l4_dst_port=2002,           # No match
            ip_dscp=3,                  # No match
            tcp_flags=0x10              # No match (ACK)
        )

        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=False  # Expect NO mirror packet
        )

    def test_vlan_tagged_match(self, setup_info, setup_mirror_session, ptfadapter, duthost,
                              setup_ipv6_egress_routes):
        """
        Verify that VLAN-tagged traffic is mirrored correctly.
        """
        vlan_id = setup_info[DOWN_STREAM]["src_vlan_id"]
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])

        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            vlan_id=vlan_id,
            src_ip="2001:db8:1::1"  # This should match rule 100
        )

        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=True
        )

    def test_mirror_packet_strips_vlan_tag(self, setup_info, setup_mirror_session, ptfadapter, duthost,
                                         setup_ipv6_egress_routes):
        """
        Verify that the mirrored packet (ERSPAN) does not contain the inner VLAN tag.
        """
        vlan_id = setup_info[DOWN_STREAM]["src_vlan_id"]
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])

        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            vlan_id=vlan_id,
            src_ip="2001:db8:1::1"  # Match rule 100
        )

        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=True,
            expect_vlan_tag=False  # Expect the mirrored packet to be untagged
        )

    # FIX: Removed redundant 'test_acl_ip_type_match' test.
    # Its functionality is fully covered by the parameterized test
    # 'test_ipv6_traffic_with_both_erspan_versions' below.
    
    @pytest.mark.parametrize("erspan_ip_ver", [4, 6],
                           ids=["ipv6_traffic_ipv4_erspan", "ipv6_traffic_ipv6_erspan"])
    def test_ipv6_traffic_with_both_erspan_versions(self, setup_info, setup_mirror_session,
                                                    ptfadapter, duthost,
                                                    setup_ipv6_egress_routes, erspan_ip_ver):
        """
        Test IPv6 egress mirroring with both IPv4 and IPv6 ERSPAN encapsulation.

        Verify that IPv6 traffic can be mirrored using both:
        - IPv4 ERSPAN envelope (traditional)
        - IPv6 ERSPAN envelope (modern)
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])
        
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            src_ip="2001:db8:1::1"  # Match rule 100
        )
        
        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=True,
            erspan_ip_ver=erspan_ip_ver
        )
