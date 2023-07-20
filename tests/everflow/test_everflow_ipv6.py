"""Test cases to support the Everflow IPv6 Mirroring feature in SONiC."""
import time
import pytest
import ptf.testutils as testutils
from . import everflow_test_utilities as everflow_utils
from .everflow_test_utilities import BaseEverflowTest, DOWN_STREAM, UP_STREAM

# Module-level fixtures
from .everflow_test_utilities import setup_info      # noqa: F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor      # noqa F401
pytestmark = [
    pytest.mark.topology("t0", "t1", "t2", "m0")
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
    rx_port_ptf_id = None
    tx_port_ids = []

    @pytest.fixture(scope='class',  autouse=True)
    def setup_mirror_session_dest_ip_route(self, tbinfo, setup_info, setup_mirror_session):     # noqa F811
        """
        Setup the route for mirror session destination ip and update monitor port list.
        Remove the route as part of cleanup.
        """
        if setup_info['topo'] in ['t0', 'm0_vlan']:
            # On T0 testbed, the collector IP is routed to T1
            namespace = setup_info[UP_STREAM]['remote_namespace']
            tx_port = setup_info[UP_STREAM]["dest_port"][0]
            dest_port_ptf_id_list = [setup_info[UP_STREAM]["dest_port_ptf_id"][0]]
            remote_dut = setup_info[UP_STREAM]['remote_dut']
            rx_port_id = setup_info[UP_STREAM]["src_port_ptf_id"]
        else:
            namespace = setup_info[DOWN_STREAM]['remote_namespace']
            tx_port = setup_info[DOWN_STREAM]["dest_port"][0]
            dest_port_ptf_id_list = [setup_info[DOWN_STREAM]["dest_port_ptf_id"][0]]
            remote_dut = setup_info[DOWN_STREAM]['remote_dut']
            rx_port_id = setup_info[DOWN_STREAM]["src_port_ptf_id"]
        remote_dut.shell(remote_dut.get_vtysh_cmd_for_namespace(
            "vtysh -c \"config\" -c \"router bgp\" -c \"address-family ipv4\" -c \"redistribute static\"", namespace))
        peer_ip = everflow_utils.get_neighbor_info(remote_dut, tx_port, tbinfo)
        everflow_utils.add_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip, namespace)
        EverflowIPv6Tests.tx_port_ids = BaseEverflowTest._get_tx_port_id_list(dest_port_ptf_id_list)
        EverflowIPv6Tests.rx_port_ptf_id = rx_port_id
        time.sleep(5)

        yield

        everflow_utils.remove_route(remote_dut, setup_mirror_session["session_prefixes"][0], peer_ip, namespace)
        remote_dut.shell(remote_dut.get_vtysh_cmd_for_namespace(
            "vtysh -c \"config\" -c \"router bgp\" -c \"address-family ipv4\" -c \"no redistribute static\"",
            namespace))

    @pytest.fixture(scope='class')
    def everflow_dut(self, setup_info):             # noqa F811
        if setup_info['topo'] in ['t0', 'm0_vlan']:
            dut = setup_info[UP_STREAM]['everflow_dut']
        else:
            dut = setup_info[DOWN_STREAM]['everflow_dut']

        yield dut

    @pytest.fixture(scope='class')
    def everflow_direction(self, setup_info):       # noqa F811
        if setup_info['topo'] in ['t0', 'm0_vlan']:
            direction = UP_STREAM
        else:
            direction = DOWN_STREAM

        yield direction

    def test_src_ipv6_mirroring(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,       # noqa F811
                                everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):   # noqa F811
        """Verify that we can match on Source IPv6 addresses."""
        test_packet = self._base_tcpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0002"
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_dst_ipv6_mirroring(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,       # noqa F811
                                everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):   # noqa F811
        """Verify that we can match on Destination IPv6 addresses."""
        test_packet = self._base_tcpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0003"
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_next_header_mirroring(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,        # noqa F811
                                   everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):    # noqa F811
        """Verify that we can match on the Next Header field."""
        test_packet = self._base_tcpv6_packet(everflow_direction, ptfadapter, setup_info, next_header=0x7E)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_l4_src_port_mirroring(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,        # noqa F811
                                   everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):    # noqa F811
        """Verify that we can match on the L4 Source Port."""
        test_packet = self._base_tcpv6_packet(everflow_direction, ptfadapter, setup_info, sport=9000)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_l4_dst_port_mirroring(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,        # noqa F811
                                   everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):    # noqa F811
        """Verify that we can match on the L4 Destination Port."""
        test_packet = self._base_tcpv6_packet(everflow_direction, ptfadapter, setup_info, dport=9001)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_l4_src_port_range_mirroring(self, setup_info, setup_mirror_session,                # noqa F811
                                         ptfadapter, everflow_dut, everflow_direction,
                                         toggle_all_simulator_ports_to_rand_selected_tor):      # noqa F811
        """Verify that we can match on a range of L4 Source Ports."""
        test_packet = self._base_tcpv6_packet(everflow_direction, ptfadapter, setup_info, sport=10200)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_l4_dst_port_range_mirroring(self, setup_info, setup_mirror_session,                # noqa F811
                                         ptfadapter, everflow_dut, everflow_direction,
                                         toggle_all_simulator_ports_to_rand_selected_tor):      # noqa F811
        """Verify that we can match on a range of L4 Destination Ports."""
        test_packet = self._base_tcpv6_packet(everflow_direction, ptfadapter, setup_info, dport=10700)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_tcp_flags_mirroring(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,          # noqa F811
                                 everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):      # noqa F811
        """Verify that we can match on TCP Flags."""
        test_packet = self._base_tcpv6_packet(everflow_direction, ptfadapter, setup_info, flags=0x1B)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_dscp_mirroring(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,               # noqa F811
                            everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):           # noqa F811
        """Verify that we can match on DSCP."""
        test_packet = self._base_tcpv6_packet(everflow_direction, ptfadapter, setup_info, dscp=37)

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_l4_range_mirroring(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,           # noqa F811
                                everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):       # noqa F811
        """Verify that we can match from a source port to a range of destination ports and vice-versa."""
        test_packet = self._base_tcpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0004",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0005",
            sport=11200,
            dport=11700
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

        test_packet = self._base_tcpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0005",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0004",
            sport=11700,
            dport=11200
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_tcp_response_mirroring(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,       # noqa F811
                                    everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):   # noqa F811
        """Verify that we can match a SYN -> SYN-ACK pattern."""
        test_packet = self._base_tcpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0006",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0007",
            flags=0x2
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

        test_packet = self._base_tcpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0007",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0006",
            flags=0x12
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_tcp_application_mirroring(self, setup_info, setup_mirror_session,              # noqa F811
                                       ptfadapter, everflow_dut, everflow_direction,
                                       toggle_all_simulator_ports_to_rand_selected_tor):    # noqa F811
        """Verify that we can match a TCP handshake between a client and server."""
        test_packet = self._base_tcpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0008",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0009",
            sport=12000,
            dport=443,
            flags=0x2
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

        test_packet = self._base_tcpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0009",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0008",
            sport=443,
            dport=12000,
            flags=0x12
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_udp_application_mirroring(self, setup_info, setup_mirror_session,              # noqa F811
                                       ptfadapter, everflow_dut, everflow_direction,
                                       toggle_all_simulator_ports_to_rand_selected_tor):    # noqa F811
        """Verify that we can match UDP traffic between a client and server application."""
        test_packet = self._base_udpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:000a",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:000b",
            dscp=8,
            sport=12001,
            dport=514
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)
        test_packet = self._base_udpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:000b",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:000a",
            dscp=8,
            sport=514,
            dport=12001
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_any_protocol(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,         # noqa F811
                          everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):     # noqa F811
        """Verify that the protocol number is ignored if it is not specified in the ACL rule."""
        test_packet = self._base_tcpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:000c",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:000d"
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

        test_packet = self._base_udpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:000c",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:000d"
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

        test_packet = self._base_udpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:000c",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:000d",
            next_header=0xAB
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_any_transport_protocol(self, setup_info, setup_mirror_session,                 # noqa F811
                                    ptfadapter, everflow_dut, everflow_direction,
                                    toggle_all_simulator_ports_to_rand_selected_tor):       # noqa F811
        """Verify that src port and dst port rules match regardless of whether TCP or UDP traffic is sent."""
        test_packet = self._base_tcpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:001c",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:001d",
            sport=12002,
            dport=12003
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

        test_packet = self._base_udpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:001c",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:001d",
            sport=12002,
            dport=12003
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_invalid_tcp_rule(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,         # noqa F811
                              everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):     # noqa F811
        """Verify that the ASIC does not reject rules with TCP flags if the protocol is not TCP."""
        pass

        # NOTE: This type of rule won't really function since you need a TCP packet to have TCP flags.
        # However, we have still included such a rule in the acl.json file to validate that the SAI
        # will not crash if such a rule is installed. If this does happen, we expect the whole test
        # suite + loganaylzer + the sanity check to fail.

    def test_source_subnet(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,            # noqa F811
                           everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):        # noqa F811
        """Verify that we can match packets with a Source IPv6 Subnet."""
        test_packet = self._base_tcpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:b000:0000:0000:0000:0010",
            dst_ip="2002:0225:7c6b:a982:d48b:230e:f271:0010",
            sport=12006,
            dport=12007
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_dest_subnet(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,          # noqa F811
                         everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):      # noqa F811
        """Verify that we can match packets with a Destination IPv6 Subnet."""
        test_packet = self._base_tcpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:a982:d48b:230e:f271:0010",
            dst_ip="2002:0225:7c6b:b000:0000:0000:0000:0010",
            sport=12008,
            dport=12009
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_both_subnets(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,         # noqa F811
                          everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):     # noqa F811
        """Verify that we can match packets with both source and destination subnets."""
        test_packet = self._base_tcpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:c000:0000:0000:0000:0010",
            dst_ip="2002:0225:7c6b:d000:0000:0000:0000:0010",
            sport=12010,
            dport=12011
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def test_fuzzy_subnets(self, setup_info, setup_mirror_session, ptfadapter, everflow_dut,        # noqa F811
                           everflow_direction, toggle_all_simulator_ports_to_rand_selected_tor):    # noqa F811
        """Verify that we can match packets with non-standard subnet sizes."""
        test_packet = self._base_tcpv6_packet(
            everflow_direction,
            ptfadapter,
            setup_info,
            src_ip="2002:0225:7c6b:e000:0000:0000:0000:0010",
            dst_ip="2002:0225:7c6b:f000:0000:0000:0000:0010",
            sport=12012,
            dport=12013
        )

        self.send_and_check_mirror_packets(setup_info,
                                           setup_mirror_session,
                                           ptfadapter,
                                           everflow_dut,
                                           test_packet, everflow_direction, src_port=EverflowIPv6Tests.rx_port_ptf_id,
                                           dest_ports=EverflowIPv6Tests.tx_port_ids)

    def _base_tcpv6_packet(self,
                           direction,
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
            eth_dst=setup[direction]["ingress_router_mac"],
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
                           direction,
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
            eth_dst=setup[direction]["ingress_router_mac"],
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
    def setup_acl_table(self, setup_info, setup_mirror_session, config_method):         # noqa F811

        if setup_info['topo'] in ['t0', 'm0_vlan']:
            everflow_dut = setup_info[UP_STREAM]['everflow_dut']
            remote_dut = setup_info[UP_STREAM]['remote_dut']
        else:
            everflow_dut = setup_info[DOWN_STREAM]['everflow_dut']
            remote_dut = setup_info[DOWN_STREAM]['remote_dut']

        table_name = self._get_table_name(everflow_dut)
        temporary_table = False

        duthost_set = set()
        duthost_set.add(everflow_dut)
        duthost_set.add(remote_dut)

        if not table_name:
            table_name = "EVERFLOWV6"
            temporary_table = True

        for duthost in duthost_set:
            if temporary_table:
                self.apply_acl_table_config(duthost, table_name, "MIRRORV6", config_method)

            self.apply_acl_rule_config(duthost, table_name, setup_mirror_session["session_name"],
                                       config_method, rules=EVERFLOW_V6_RULES)

        yield

        for duthost in duthost_set:
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
