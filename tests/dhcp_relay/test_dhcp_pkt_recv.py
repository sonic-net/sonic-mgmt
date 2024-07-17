import logging
import ptf.packet as scapy
import pytest
import random

from ptf import testutils
from scapy.layers.dhcp6 import DHCP6_Solicit
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import capture_and_check_packet_on_dut

pytestmark = [
    pytest.mark.topology("t0", "m0", 'mx')
]

ACL_TABLE_NAME_DHCPV6_PKT_RECV_TEST = "DHCPV6_PKT_RECV_TEST"
ACL_STAGE_INGRESS = "ingress"
ACL_TABLE_TYPE_L3V6 = "L3V6"

ACL_RULE_FILE_PATH_MULTICAST_ACCEPT = "dhcp_relay/acl/dhcpv6_pkt_recv_multicast_accept.json"
ACL_RULE_DST_FILE = "/tmp/test_dchp_pkt_acl_rule.json"

DHCP_RELAY_FEATRUE_NAME = "dhcp_relay"
DHCPV6_MAC_MULTICAST = "33:33:00:01:00:02"
DHCPV6_IP_MULTICAST = "ff02::1:2"
DHCPV6_UDP_CLIENT_PORT = 546
DHCPV6_UDP_SERVER_PORT = 547


@pytest.fixture(scope="module", autouse=True)
def check_dhcp_relay_feature_state(duthost):
    features_state, _ = duthost.get_feature_status()
    if "enabled" not in features_state.get(DHCP_RELAY_FEATRUE_NAME, ""):
        pytest.skip('dhcp relay feature is not enabled, skip the test')


class Dhcpv6PktRecvBase:

    @pytest.fixture(scope="class")
    def setup_teardown(self, duthost, tbinfo):
        disabled_host_interfaces = tbinfo['topo']['properties']['topology'].get('disabled_host_interfaces', [])
        ptf_indices = [interface for interface in tbinfo['topo']['properties']['topology'].get('host_interfaces', [])
                       if interface not in disabled_host_interfaces]
        dut_intf_ptf_index = duthost.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']
        yield ptf_indices, dut_intf_ptf_index

    def test_dhcpv6_multicast_recv(self, duthost, ptfadapter, setup_teardown):
        """
        Test the DUT can receive DHCPv6 multicast packet
        """
        ptf_indices, dut_intf_ptf_index = setup_teardown
        ptf_index = random.choice(ptf_indices)
        intf, ptf_port_id = [(intf, id) for intf, id in dut_intf_ptf_index.items() if id == ptf_index][0]
        logging.info("Start to verify dhcpv6 multicast with infterface=%s and ptf_port_id=%s" % (intf, ptf_port_id))

        def func(pkts):
            pytest_assert(len([pkt for pkt in pkts if pkt[DHCP6_Solicit].trid == test_trid]) > 0,
                          "Didn't get packet with expected transaction id")
        src_mac = ptfadapter.dataplane.get_mac(0, ptf_port_id).decode('utf-8')
        test_trid = 234
        pkts_filter = "ether src %s and udp dst port %s" % (src_mac, DHCPV6_UDP_SERVER_PORT)
        with capture_and_check_packet_on_dut(
            duthost=duthost,
            interface=intf,
            pkts_filter=pkts_filter,
            pkts_validator=func
        ):
            link_local_ipv6_addr = duthost.get_intf_link_local_ipv6_addr(intf)
            req_pkt = scapy.Ether(dst=DHCPV6_MAC_MULTICAST, src=src_mac) \
                / scapy.IPv6(src=link_local_ipv6_addr, dst=DHCPV6_IP_MULTICAST)\
                / scapy.UDP(sport=DHCPV6_UDP_CLIENT_PORT, dport=DHCPV6_UDP_SERVER_PORT)\
                / DHCP6_Solicit(trid=test_trid)
            ptfadapter.dataplane.flush()
            testutils.send_packet(ptfadapter, pkt=req_pkt, port_id=ptf_port_id)


class TestDhcpv6WithEmptyAclTable(Dhcpv6PktRecvBase):
    """
    Test the DUT with empty ACL table
    """
    @pytest.fixture(scope="class", autouse=True)
    def setup_teardown_acl(self, duthost, setup_teardown):
        ptf_indices, dut_intf_ptf_index = setup_teardown
        ptf_intfs = [intf for intf, index in dut_intf_ptf_index.items() if index in ptf_indices]
        acl_table_name = ACL_TABLE_NAME_DHCPV6_PKT_RECV_TEST
        duthost.add_acl_table(
            table_name=acl_table_name,
            table_type=ACL_TABLE_TYPE_L3V6,
            acl_stage=ACL_STAGE_INGRESS,
            bind_ports=ptf_intfs
        )

        yield

        duthost.remove_acl_table(acl_table_name)


class TestDhcpv6WithMulticastAccpectAcl(Dhcpv6PktRecvBase):
    """
    Test the DUT with multicast accept ACL rule and default drop all rule.
    The drop all rule is added by default for L3V6 table type by acl-loader
    """
    @pytest.fixture(scope="class", autouse=True)
    def setup_teardown_acl(self, duthost, setup_teardown):
        ptf_indices, dut_intf_ptf_index = setup_teardown
        ptf_intfs = [intf for intf, index in dut_intf_ptf_index.items() if index in ptf_indices]
        acl_table_name = ACL_TABLE_NAME_DHCPV6_PKT_RECV_TEST
        duthost.add_acl_table(
            table_name=acl_table_name,
            table_type=ACL_TABLE_TYPE_L3V6,
            acl_stage=ACL_STAGE_INGRESS,
            bind_ports=ptf_intfs
        )
        duthost.copy(src=ACL_RULE_FILE_PATH_MULTICAST_ACCEPT, dest=ACL_RULE_DST_FILE)
        duthost.shell("acl-loader update full --table_name {} {}".format(acl_table_name, ACL_RULE_DST_FILE))

        yield

        duthost.remove_acl_table(acl_table_name)
