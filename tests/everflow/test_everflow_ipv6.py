"""Test cases to support the Everflow IPv6 Mirroring feature in SONiC."""
import pytest
import ptf.testutils as testutils
import time
import logging

import everflow_test_utilities as everflow_utils
from everflow_test_utilities import BaseEverflowTest, DOWN_STREAM, UP_STREAM, get_intf_namespace

# Module-level fixtures
from everflow_test_utilities import setup_info  # noqa: F401, E501 lgtm[py/unused-import] pylint: disable=import-error

pytestmark = [
    pytest.mark.topology("t0", "t1", "t2")
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

    DEFAULT_SRC_IP = "2002:0225:7c6b:a982:d48b:230e:f271:0000"
    DEFAULT_DST_IP = "2002:0225:7c6b:a982:d48b:230e:f271:0001"
    tx_port_ids = []

    @pytest.fixture(scope='class', autouse=True)
    def setup_mirror_session_dest_ip_route(self, duthosts, rand_one_dut_hostname, tbinfo, setup_info, setup_mirror_session):
        """
        Setup the route for mirror session destination ip and update monitor port list.
        Remove the route as part of cleanup.
        """
        if setup_info['topo'] == 't0':
            # On T0 testbed, the collector IP is routed to T1
            tx_port = setup_info[UP_STREAM]["dest_port"][0]
            rx_port = setup_info[DOWN_STREAM]["dest_port"][0]
            routed_host = duthosts[rand_one_dut_hostname]
            routed_ns = get_intf_namespace(setup_info, DOWN_STREAM, rx_port)
            namespace = get_intf_namespace(setup_info, UP_STREAM, tx_port)
            dest_port_ptf_id_list = [setup_info[UP_STREAM]["dest_port_ptf_id"][0]]
            duthost = duthosts[rand_one_dut_hostname]
        elif setup_info['topo'] == 't2':
            tx_port = setup_info[DOWN_STREAM]["dest_port"][0]
            rx_port = setup_info[UP_STREAM]["dest_port"][1]
            routed_host = setup_info[UP_STREAM]["remote_dut"]
            routed_ns = get_intf_namespace(setup_info, UP_STREAM, rx_port)
            namespace = get_intf_namespace(setup_info, DOWN_STREAM, tx_port)
            dest_port_ptf_id_list = [setup_info[DOWN_STREAM]["dest_port_ptf_id"][0]]
            duthost = setup_info[DOWN_STREAM]['remote_dut']
        else:
            tx_port = setup_info[DOWN_STREAM]["dest_port"][0]
            rx_port = setup_info[UP_STREAM]["dest_port"][0]
            routed_host = duthosts[rand_one_dut_hostname]
            routed_ns = get_intf_namespace(setup_info, UP_STREAM, rx_port)
            namespace = get_intf_namespace(setup_info, DOWN_STREAM, tx_port)
            dest_port_ptf_id_list = [setup_info[DOWN_STREAM]["dest_port_ptf_id"][0]]
            duthost = duthosts[rand_one_dut_hostname]

        duthost.shell(duthost.get_vtysh_cmd_for_namespace("vtysh -c \"config\" -c \"router bgp\" -c \"address-family ipv4\" -c \"redistribute static\"", namespace))
        peer_ip = everflow_utils.get_neighbor_info(duthost, tx_port, tbinfo)
        everflow_utils.add_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip, namespace)
        EverflowIPv6Tests.tx_port_ids = self._get_tx_port_id_list(dest_port_ptf_id_list)

        if self.acl_stage() == "egress":
            dst_addr = "2002:0225:7c6b:a982::/64"
            nexthop_ip = everflow_utils.get_neighbor_info(routed_host, rx_port, tbinfo, ipver=6)
            logging.info("Add egress route on host: %s, %s, %s", routed_host.hostname, dst_addr, nexthop_ip)
            routed_host.shell(duthost.get_vtysh_cmd_for_namespace("vtysh -c \"config\" -c \"router bgp\" -c \"address-family ipv6\" -c \"redistribute static\"", routed_ns))
            routed_host.shell(duthost.get_vtysh_cmd_for_namespace("vtysh -c \"configure terminal\" -c \"ipv6 route {} {}\"".format(dst_addr, nexthop_ip), routed_ns))
        time.sleep(5)

        yield

        everflow_utils.remove_route(duthost, setup_mirror_session["session_prefixes"][0], peer_ip, namespace)
        duthost.shell(duthost.get_vtysh_cmd_for_namespace("vtysh -c \"config\" -c \"router bgp\" -c \"address-family ipv4\" -c \"no redistribute static\"", namespace))

        if self.acl_stage() == "egress":
            routed_host.shell(duthost.get_vtysh_cmd_for_namespace("vtysh -c \"config\" -c \"router bgp\" -c \"address-family ipv6\" -c \"no redistribute static\"", routed_ns))
            routed_host.shell(duthost.get_vtysh_cmd_for_namespace("vtysh -c \"configure terminal\" -c \"no ipv6 route {} {}\"".format(dst_addr, nexthop_ip), routed_ns))

    def get_test_topo_vars(self, duthosts, rand_one_dut_hostname, setup_info):
        """
        Return the correct duthost and MAC addresses based on topology type.
        
        Args:
            duthosts: The duthosts fixture.
            rand_one_dut_hostname: random duthost fixture.
            setup_info: The setup_info fixture.
        
        Returns:
            duthost: the duthost everflow will be used on.
            router_mac: the mac address of the everflow DUT, for PTF packet ethernet destination.
            src_port: the PTF port to send the packet on T2.  On T0/T1 this is handled by the library function, so
                it is None there.
            mirror_packet_src_mac:  On T2, this is the MAC of the remote linecard since it is forwarding the packet
                towards mirror destination.  On T0/T1 pizzabox MAC is the same as router_mac.
        """
        if setup_info['topo'] == 't2':
            duthost = setup_info[DOWN_STREAM]['everflow_dut']
            router_mac = setup_info[DOWN_STREAM]['router_mac']
            src_port = setup_info[DOWN_STREAM]['src_port_ptf_id']
            if setup_info[DOWN_STREAM]['everflow_dut'] != setup_info[DOWN_STREAM]['remote_dut']:
                # Intercard dut mac will change
                mirror_packet_src_mac = setup_info[DOWN_STREAM]['remote_dut'].facts["router_mac"]
            else:
                mirror_packet_src_mac = router_mac
        else:
            duthost = duthosts[rand_one_dut_hostname]
            router_mac = setup_info['router_mac']
            mirror_packet_src_mac = router_mac
            src_port = None

        return (duthost, router_mac, src_port, mirror_packet_src_mac)

    def test_src_ipv6_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match on Source IPv6 addresses."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0002"
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_dst_ipv6_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match on Destination IPv6 addresses."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            router_mac,
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0003"
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_next_header_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match on the Next Header field."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)

        test_packet = self._base_tcpv6_packet(ptfadapter, router_mac, next_header=0x7E)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_l4_src_port_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match on the L4 Source Port."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(ptfadapter, router_mac, sport=9000)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_l4_dst_port_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match on the L4 Destination Port."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(ptfadapter, router_mac, dport=9001)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_l4_src_port_range_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match on a range of L4 Source Ports."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(ptfadapter, router_mac, sport=10200)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_l4_dst_port_range_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match on a range of L4 Destination Ports."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(ptfadapter, router_mac, dport=10700)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_tcp_flags_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match on TCP Flags."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(ptfadapter, router_mac, flags=0x1B)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_dscp_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match on DSCP."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(ptfadapter, router_mac, dscp=37)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_l4_range_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match from a source port to a range of destination ports and vice-versa."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0004",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0005",
            sport=11200,
            dport=11700
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0005",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0004",
            sport=11700,
            dport=11200
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_tcp_response_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match a SYN -> SYN-ACK pattern."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0006",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0007",
            flags=0x2
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0007",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0006",
            flags=0x12
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_tcp_application_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match a TCP handshake between a client and server."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0008",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0009",
            sport=12000,
            dport=443,
            flags=0x2
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0009",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0008",
            sport=443,
            dport=12000,
            flags=0x12
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_udp_application_mirroring(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match UDP traffic between a client and server application."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_udpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:000a",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:000b",
            dscp=8,
            sport=12001,
            dport=514
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

        test_packet = self._base_udpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:000b",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:000a",
            dscp=8,
            sport=514,
            dport=12001
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_any_protocol(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that the protocol number is ignored if it is not specified in the ACL rule."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:000c",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:000d"
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

        test_packet = self._base_udpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:000c",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:000d"
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

        test_packet = self._base_udpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:000c",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:000d",
            next_header=0xAB
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_any_transport_protocol(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that src port and dst port rules match regardless of whether TCP or UDP traffic is sent."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:001c",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:001d",
            sport=12002,
            dport=12003
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

        test_packet = self._base_udpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:001c",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:001d",
            sport=12002,
            dport=12003
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_invalid_tcp_rule(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that the ASIC does not reject rules with TCP flags if the protocol is not TCP."""
        pass

        # NOTE: This type of rule won't really function since you need a TCP packet to have TCP flags.
        # However, we have still included such a rule in the acl.json file to validate that the SAI
        # will not crash if such a rule is installed. If this does happen, we expect the whole test
        # suite + loganaylzer + the sanity check to fail.

    def test_source_subnet(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match packets with a Source IPv6 Subnet."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:b000:0000:0000:0000:0010",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0010",
            sport=12006,
            dport=12007
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_dest_subnet(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match packets with a Destination IPv6 Subnet."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0010",
            dst_ip="2002:0225:7c6b:b000:0000:0000:0000:0010",
            sport=12008,
            dport=12009
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_both_subnets(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match packets with both source and destination subnets."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:c000:0000:0000:0000:0010",
            dst_ip="2002:0225:7c6b:d000:0000:0000:0000:0010",
            sport=12010,
            dport=12011
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def test_fuzzy_subnets(self, setup_info, setup_mirror_session, ptfadapter, duthosts, rand_one_dut_hostname):
        """Verify that we can match packets with non-standard subnet sizes."""
        (duthost, router_mac, src_port, mirror_packet_src_mac) = self.get_test_topo_vars(duthosts, rand_one_dut_hostname, setup_info)
        test_packet = self._base_tcpv6_packet(
            ptfadapter,
            router_mac,
            src_ip="2002:0225:7c6b:e000:0000:0000:0000:0010",
            dst_ip="2002:0225:7c6b:f000:0000:0000:0000:0010",
            sport=12012,
            dport=12013
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           duthost,
                                           test_packet,
                                           src_port=src_port,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids,
                                           gre_pkt_src_mac=mirror_packet_src_mac,
                                           egress_mirror_src_mac=router_mac)

    def _base_tcpv6_packet(self,
                           ptfadapter,
                           router_mac,
                           src_ip=DEFAULT_SRC_IP,
                           dst_ip=DEFAULT_DST_IP,
                           next_header=None,
                           dscp=None,
                           sport=2020,
                           dport=8080,
                           flags=0x10):
        pkt = testutils.simple_tcpv6_packet(
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            eth_dst=router_mac,
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
                           router_mac,
                           src_ip=DEFAULT_SRC_IP,
                           dst_ip=DEFAULT_DST_IP,
                           next_header=None,
                           dscp=None,
                           sport=2020,
                           dport=8080):
        pkt = testutils.simple_udpv6_packet(
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            eth_dst=router_mac,
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

    @pytest.fixture(scope='class', autouse=True)
    def setup_acl_table(self, duthosts, rand_one_dut_hostname, setup_info, setup_mirror_session, config_method):
        if setup_info['topo'] == 't2':
            duthost_list = [setup_info[DOWN_STREAM]['everflow_dut']]
            if setup_info[UP_STREAM]['everflow_dut'] != setup_info[DOWN_STREAM]['everflow_dut']:
                duthost_list.append(setup_info[UP_STREAM]['everflow_dut'])
        else:
            duthost_list = [duthosts[rand_one_dut_hostname]]
        if not setup_info[self.acl_stage()][self.mirror_type()]:
            pytest.skip("{} ACL w/ {} Mirroring not supported, skipping"
                        .format(self.acl_stage(), self.mirror_type()))

        for duthost in duthost_list:

            if self.acl_stage() == "ingress":
                table_name = self._get_table_name(duthost)
                temporary_table = False

                if not table_name:
                    table_name = "EVERFLOWV6"
                    temporary_table = True
                    self.apply_acl_table_config(duthost, table_name, "MIRRORV6", config_method)
            else:
                logging.info("ADD EGRESS TABLE - %s", duthost.hostname)
                table_name = "EVERFLOWV6_EGRESS"
                temporary_table = True
                inst_list = duthost.get_sonic_host_and_frontend_asic_instance()
                for inst in inst_list:
                    self.apply_acl_table_config(duthost, table_name, "MIRRORV6", config_method, bind_namespace=getattr(inst, 'namespace', None))

            self.apply_acl_rule_config(duthost, table_name, setup_mirror_session["session_name"], config_method, rules=EVERFLOW_V6_RULES)

        yield

        for duthost in duthost_list:
            self.remove_acl_rule_config(duthost, table_name, config_method)

            if temporary_table:
                inst_list = duthost.get_sonic_host_and_frontend_asic_instance()
                for inst in inst_list:
                    self.remove_acl_table_config(duthost, table_name, config_method, bind_namespace=getattr(inst, 'namespace', None))

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


class TestIngressEverflowIPv6(EverflowIPv6Tests):
    """Parameters for Ingress Everflow IPv6 testing. (Ingress ACLs/Ingress Mirror)"""
    def acl_stage(self):
        return "ingress"

    def mirror_type(self):
        return "ingress"


class TestEgressEverflowIPv6(EverflowIPv6Tests):
    """Parameters for Ingress Everflow IPv6 testing. (Ingress ACLs/Ingress Mirror)"""
    def acl_stage(self):
        return "egress"

    def mirror_type(self):
        return "egress"
