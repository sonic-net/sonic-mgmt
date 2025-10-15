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
acl_rules_file = 'everflow/files/everflow_ipv6_egress_acl_rules.yaml'


@pytest.fixture(scope="module")
def setup_ipv6_egress_routes(setup_info, tbinfo):
    """
    Setup IPv6 routes required for egress Everflow testing.
    """
    duthost = setup_info[DOWN_STREAM]["everflow_dut"]
    namespace = setup_info[DOWN_STREAM]["everflow_namespace"]
    
    # IPv6 test routes
    test_routes = [
        ("2001:db8:1::/64", "fc00:1::2"),
        ("2001:db8:2::/64", "fc00:2::2"),
    ]
    
    for prefix, nexthop in test_routes:
        duthost.shell(duthost.get_vtysh_cmd_for_namespace(
            f"vtysh -c \"configure terminal\" -c \"ipv6 route {prefix} {nexthop}\"",
            namespace
        ))
    
    yield
    
    # Cleanup routes
    for prefix, nexthop in test_routes:
        duthost.shell(duthost.get_vtysh_cmd_for_namespace(
            f"vtysh -c \"configure terminal\" -c \"no ipv6 route {prefix} {nexthop}\"",
            namespace
        ))


class EverflowIPv6EgressTests(BaseEverflowTest):
    """
    Base class for IPv6 Egress Everflow tests.
    
    Covers egress ACL with egress mirroring for IPv6 traffic.
    """
    
    DEFAULT_SRC_IP = "2001:db8:1::10"
    DEFAULT_DST_IP = "2001:db8:2::20"
    
    def mirror_type(self):
        return "egress"
    
    def acl_stage(self):
        return "egress"
    
    def _base_tcpv6_packet(
        self,
        ptfadapter,
        setup,
        direction=DOWN_STREAM,
        src_ip=None,
        dst_ip=None,
        tcp_sport=0x1234,
        tcp_dport=0x50,
        tcp_flags=0x10,
        dscp=8,
        vlan_id=None,
        dl_dst=None
    ):
        """
        Generate a base TCPv6 packet for testing.
        """
        if src_ip is None:
            src_ip = self.DEFAULT_SRC_IP
        if dst_ip is None:
            dst_ip = self.DEFAULT_DST_IP
        
        if dl_dst is None:
            dl_dst = setup[direction]["ingress_router_mac"]
        
        pkt = testutils.simple_tcpv6_packet(
            eth_dst=dl_dst,
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ipv6_src=src_ip,
            ipv6_dst=dst_ip,
            ipv6_dscp=dscp,
            tcp_sport=tcp_sport,
            tcp_dport=tcp_dport,
            tcp_flags=tcp_flags
        )
        
        if vlan_id:
            pkt = testutils.simple_tcpv6_packet(
                eth_dst=dl_dst,
                eth_src=ptfadapter.dataplane.get_mac(0, 0),
                ipv6_src=src_ip,
                ipv6_dst=dst_ip,
                ipv6_dscp=dscp,
                tcp_sport=tcp_sport,
                tcp_dport=tcp_dport,
                tcp_flags=tcp_flags,
                dl_vlan_enable=True,
                vlan_vid=vlan_id
            )
        
        return pkt
    
    def _base_udpv6_packet(
        self,
        ptfadapter,
        setup,
        direction=DOWN_STREAM,
        src_ip=None,
        dst_ip=None,
        udp_sport=0x1234,
        udp_dport=0x50,
        dscp=8
    ):
        """
        Generate a base UDPv6 packet for testing.
        """
        if src_ip is None:
            src_ip = self.DEFAULT_SRC_IP
        if dst_ip is None:
            dst_ip = self.DEFAULT_DST_IP
        
        return testutils.simple_udpv6_packet(
            eth_dst=setup[direction]["ingress_router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ipv6_src=src_ip,
            ipv6_dst=dst_ip,
            ipv6_dscp=dscp,
            udp_sport=udp_sport,
            udp_dport=udp_dport
        )
    
    def _base_icmpv6_packet(
        self,
        ptfadapter,
        setup,
        direction=DOWN_STREAM,
        src_ip=None,
        dst_ip=None,
        icmp_type=128,
        icmp_code=0,
        dscp=8
    ):
        """
        Generate a base ICMPv6 packet for testing.
        """
        if src_ip is None:
            src_ip = self.DEFAULT_SRC_IP
        if dst_ip is None:
            dst_ip = self.DEFAULT_DST_IP
        
        return testutils.simple_icmpv6_packet(
            eth_dst=setup[direction]["ingress_router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ipv6_src=src_ip,
            ipv6_dst=dst_ip,
            icmp_type=icmp_type,
            icmp_code=icmp_code
        )
    
    def _get_tx_port_id_list(self, tx_ports):
        """
        Extract list of transmit port IDs from port configuration.
        """
        return BaseEverflowTest._get_tx_port_id_list(tx_ports)


class TestEverflowV6EgressAclEgressMirror(EverflowIPv6EgressTests):
    """
    Test class for IPv6 Egress ACL with Egress Mirror.
    
    Tests SAI_ACL_TABLE_ATTR_FIELD_* attributes for IPv6:
    - OUTER_VLAN_ID
    - ACL_IP_TYPE
    - SRC_IPV6
    - DST_IPV6
    - ICMPV6_CODE
    - ICMPV6_TYPE
    - IPV6_NEXT_HEADER
    - L4_SRC_PORT
    - L4_DST_PORT
    - TCP_FLAGS
    - DSCP
    - L4_SRC_PORT_RANGE
    - L4_DST_PORT_RANGE
    """
    
    @pytest.fixture(scope="class", autouse=True)
    def setup_acl_table(self, setup_info, setup_mirror_session, config_method):
        """
        Setup IPv6 egress ACL table for testing.
        """
        table_name = "EVERFLOW_V6_EGRESS"
        
        duthost_set = BaseEverflowTest.get_duthost_set(setup_info)
        
        if not setup_info[self.acl_stage()][self.mirror_type()]:
            pytest.skip(f"{self.acl_stage()} ACL w/ {self.mirror_type()} Mirroring not supported")
        
        for duthost in duthost_set:
            inst_list = duthost.get_sonic_host_and_frontend_asic_instance()
            for inst in inst_list:
                self.apply_acl_table_config(
                    duthost,
                    table_name,
                    "MIRRORV6",
                    config_method,
                    bind_namespace=getattr(inst, 'namespace', None)
                )
            
            self.apply_acl_rule_config(
                duthost,
                table_name,
                setup_mirror_session["session_name"],
                config_method,
                rules=EVERFLOW_IPV6_EGRESS_RULES
            )
        
        yield
        
        for duthost in duthost_set:
            BaseEverflowTest.remove_acl_rule_config(duthost, table_name, config_method)
            inst_list = duthost.get_sonic_host_and_frontend_asic_instance()
            for inst in inst_list:
                self.remove_acl_table_config(
                    duthost,
                    table_name,
                    config_method,
                    bind_namespace=getattr(inst, 'namespace', None)
                )
    
    def test_src_ipv6_match(self, setup_info, setup_mirror_session, ptfadapter, 
                           duthost, setup_ipv6_egress_routes, erspan_ip_ver):
        """
        Test SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6 matching.
        
        Verify that packets with specific source IPv6 addresses are mirrored.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])
        
        # Test with matching source IP
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            src_ip="2001:db8:1::100"
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
    
    def test_dst_ipv6_match(self, setup_info, setup_mirror_session, ptfadapter,
                           duthost, setup_ipv6_egress_routes, erspan_ip_ver):
        """
        Test SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6 matching.
        
        Verify that packets with specific destination IPv6 addresses are mirrored.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])
        
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            dst_ip="2001:db8:2::200"
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
    
    def test_l4_src_port_match(self, setup_info, setup_mirror_session, ptfadapter,
                              duthost, setup_ipv6_egress_routes, erspan_ip_ver):
        """
        Test SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT matching.
        
        Verify that packets with specific TCP source ports are mirrored.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])
        
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            tcp_sport=8000
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
    
    def test_l4_dst_port_match(self, setup_info, setup_mirror_session, ptfadapter,
                              duthost, setup_ipv6_egress_routes, erspan_ip_ver):
        """
        Test SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT matching.
        
        Verify that packets with specific TCP destination ports are mirrored.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])
        
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            tcp_dport=443
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
    
    def test_l4_port_range_match(self, setup_info, setup_mirror_session, ptfadapter,
                                duthost, setup_ipv6_egress_routes, erspan_ip_ver):
        """
        Test SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE and L4_DST_PORT_RANGE.
        
        Verify that packets with port numbers in specified ranges are mirrored.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])
        
        # Test source port range (e.g., 8000-9000)
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            tcp_sport=8500,
            tcp_dport=80
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
        
        # Test destination port range (e.g., 1024-2048)
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            tcp_sport=12345,
            tcp_dport=1500
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
    
    def test_tcp_flags_match(self, setup_info, setup_mirror_session, ptfadapter,
                            duthost, setup_ipv6_egress_routes, erspan_ip_ver):
        """
        Test SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS matching.
        
        Verify that packets with specific TCP flags are mirrored.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])
        
        # Test SYN flag
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            tcp_flags=0x02
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
        
        # Test FIN flag
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            tcp_flags=0x01
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
    
    def test_dscp_match(self, setup_info, setup_mirror_session, ptfadapter,
                       duthost, setup_ipv6_egress_routes, erspan_ip_ver):
        """
        Test SAI_ACL_TABLE_ATTR_FIELD_DSCP matching.
        
        Verify that packets with specific DSCP values are mirrored.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])
        
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            dscp=48  # EF (Expedited Forwarding)
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
    
    def test_icmpv6_type_code_match(self, setup_info, setup_mirror_session, ptfadapter,
                                   duthost, setup_ipv6_egress_routes, erspan_ip_ver):
        """
        Test SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_TYPE and ICMPV6_CODE matching.
        
        Verify that ICMPv6 packets with specific type and code are mirrored.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])
        
        # Echo Request (Type 128, Code 0)
        pkt = self._base_icmpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            icmp_type=128,
            icmp_code=0
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
        
        # Destination Unreachable (Type 1, Code 3)
        pkt = self._base_icmpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            icmp_type=1,
            icmp_code=3
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
    
    def test_ipv6_next_header_match(self, setup_info, setup_mirror_session, ptfadapter,
                                   duthost, setup_ipv6_egress_routes, erspan_ip_ver):
        """
        Test SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER matching.
        
        Verify that packets with specific next header values are mirrored.
        Next Header 6 = TCP, 17 = UDP, 58 = ICMPv6
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])
        
        # TCP (Next Header = 6)
        tcp_pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM
        )
        
        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            tcp_pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=True,
            erspan_ip_ver=erspan_ip_ver
        )
        
        # UDP (Next Header = 17)
        udp_pkt = self._base_udpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM
        )
        
        self.send_and_check_mirror_packets(
            setup_info,
            setup_mirror_session,
            ptfadapter,
            duthost,
            udp_pkt,
            DOWN_STREAM,
            src_port=rx_port,
            dest_ports=tx_ports,
            expect_recv=True,
            erspan_ip_ver=erspan_ip_ver
        )
    
    def test_acl_ip_type_match(self, setup_info, setup_mirror_session, ptfadapter,
                              duthost, setup_ipv6_egress_routes, erspan_ip_ver):
        """
        Test SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE matching.
        
        Verify that IPv6 packets are correctly identified and mirrored.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])
        
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM
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
    
    def test_outer_vlan_id_match(self, setup_info, setup_mirror_session, ptfadapter,
                                duthost, setup_ipv6_egress_routes, erspan_ip_ver):
        """
        Test SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_ID matching.
        
        Verify that VLAN-tagged IPv6 packets with specific VLAN IDs are mirrored.
        """
        rx_port = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        tx_ports = self._get_tx_port_id_list(setup_info[DOWN_STREAM]["dest_port_ptf_id"])
        
        pkt = self._base_tcpv6_packet(
            ptfadapter,
            setup_info,
            direction=DOWN_STREAM,
            vlan_id=100
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
            direction=DOWN_STREAM
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