import pytest
import time
import random
import logging
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import Ether

from srv6_utils import runSendReceive
from common.helpers.voq_helpers import get_neighbor_info
from ptf.testutils import simple_ipv6_sr_packet

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.asic("mellanox", "broadcom"),
    pytest.mark.topology("t0", "t1")
]


def get_ptf_src_port_and_dut_port_and_neighbor(dut, tbinfo):
    """Get the PTF port mapping for the duthost or an asic of the duthost"""
    dut_mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    ports_map = dut_mg_facts["minigraph_ptf_indices"]
    if len(ports_map) == 0:
        pytest.skip("No PTF ports found for {}".format(dut))

    lldp_table = dut.command("show lldp table")['stdout'].split("\n")[3:]
    neighbor_table = [line.split() for line in lldp_table]
    for entry in neighbor_table:
        intf = entry[0]
        if intf in ports_map:
            return intf, ports_map[intf], entry[1]  # local intf, ptf_src_port, neighbor hostname

    dut_port, ptf_src_port = random.choice(ports_map)
    return dut_port, ptf_src_port, None


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_uN_forwarding(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index,
                            ptfadapter, tbinfo, nbrhosts, with_srh):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_frontend_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
        dut_asic = duthost.asic_instance[asic_index]
        dut_mac = dut_asic.get_router_mac()
        dut_port, ptf_src_port, neighbor = get_ptf_src_port_and_dut_port_and_neighbor(dut_asic, tbinfo)
    else:
        cli_options = ''
        dut_mac = duthost._get_router_mac()
        dut_port, ptf_src_port, neighbor = get_ptf_src_port_and_dut_port_and_neighbor(duthost, tbinfo)

    logger.info("Doing test on DUT port {} | PTF port {}".format(dut_port, ptf_src_port))

    # get neighbor IP
    lines = duthost.command("show ipv6 bgp sum")['stdout'].split("\n")
    for line in lines:
        if neighbor in line:
            neighbor_ip = line.split()[0]
    assert neighbor_ip

    # use DUT portchannel if applicable
    pc_info = duthost.command("show int portchannel")['stdout']
    if dut_port in pc_info:
        lines = pc_info.split("\n")
        for line in lines:
            if dut_port in line:
                dut_port = line.split()[1]

    sonic_db_cli = "sonic-db-cli" + cli_options

    # add a locator configuration entry
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1::")
    # add a uN sid configuration entry
    duthost.command(sonic_db_cli +
                    " CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48 action uN decap_dscp_mode pipe")
    # add the static route for IPv6 forwarding towards PTF's uSID
    duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb:2::/48 nexthop {} ifname {}"
                    .format(neighbor_ip, dut_port))
    time.sleep(5)

    for i in range(0, 10):
        if with_srh:
            injected_pkt = simple_ipv6_sr_packet(
                eth_dst=dut_mac,
                eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode(),
                ipv6_src=ptfadapter.ptf_ipv6,
                ipv6_dst="fcbb:bbbb:1:2::",
                srh_seg_left=1,
                srh_nh=41,
                inner_frame=IPv6()/ICMPv6EchoRequest(seq=i)
            )
        else:
            injected_pkt = Ether(dst=dut_mac, src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode()) \
                / IPv6(src=ptfadapter.ptf_ipv6, dst="fcbb:bbbb:1:2::") \
                / IPv6() / ICMPv6EchoRequest(seq=i)

        expected_pkt = injected_pkt.copy()
        expected_pkt['Ether'].dst = get_neighbor_info(neighbor_ip, nbrhosts)['mac']
        expected_pkt['Ether'].src = dut_mac
        expected_pkt['IPv6'].dst = "fcbb:bbbb:2::"
        expected_pkt['IPv6'].hlim -= 1
        logger.debug("Expected packet #{}: {}".format(i, expected_pkt.summary()))
        runSendReceive(injected_pkt, ptf_src_port, expected_pkt, [ptf_src_port], True, ptfadapter)

    # delete the SRv6 configuration
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL STATIC_ROUTE\\|default\\|fcbb:bbbb:2::/48")


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_uN_decap_pipe_mode(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index,
                                 ptfadapter, tbinfo, nbrhosts, with_srh):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_frontend_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
        dut_asic = duthost.asic_instance[asic_index]
        dut_mac = dut_asic.get_router_mac()
        dut_port, ptf_src_port, neighbor = get_ptf_src_port_and_dut_port_and_neighbor(dut_asic, tbinfo)
    else:
        cli_options = ''
        dut_mac = duthost._get_router_mac()
        dut_port, ptf_src_port, neighbor = get_ptf_src_port_and_dut_port_and_neighbor(duthost, tbinfo)

    logger.info("Doing test on DUT port {} | PTF port {}".format(dut_port, ptf_src_port))

    # get neighbor IP
    lines = duthost.command("show ipv6 bgp sum")['stdout'].split("\n")
    for line in lines:
        if neighbor in line:
            neighbor_ip = line.split()[0]
    assert neighbor_ip

    # use DUT portchannel if applicable
    pc_info = duthost.command("show int portchannel")['stdout']
    if dut_port in pc_info:
        lines = pc_info.split("\n")
        for line in lines:
            if dut_port in line:
                dut_port = line.split()[1]

    sonic_db_cli = "sonic-db-cli" + cli_options

    # add a locator configuration entry
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1::")
    # add a uN sid configuration entry
    duthost.command(sonic_db_cli +
                    " CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48 action uN decap_dscp_mode pipe")

    time.sleep(5)

    for i in range(0, 10):
        if with_srh:
            injected_pkt = simple_ipv6_sr_packet(
                eth_dst=dut_mac,
                eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode(),
                ipv6_src=ptfadapter.ptf_ipv6,
                ipv6_dst="fcbb:bbbb:1::",
                srh_seg_left=1,
                srh_nh=41,
                inner_frame=IPv6(dst=neighbor_ip, src=ptfadapter.ptf_ipv6)/ICMPv6EchoRequest(seq=i)
            )
        else:
            injected_pkt = Ether(dst=dut_mac, src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode()) \
                / IPv6(src=ptfadapter.ptf_ipv6, dst="fcbb:bbbb:1::") \
                / IPv6(dst=neighbor_ip, src=ptfadapter.ptf_ipv6) / ICMPv6EchoRequest(seq=i)

        expected_pkt = Ether(dst=get_neighbor_info(neighbor_ip, nbrhosts)['mac'], src=dut_mac) / \
            IPv6(dst=neighbor_ip, src=ptfadapter.ptf_ipv6)/ICMPv6EchoRequest(seq=i)
        logger.debug("Expected packet #{}: {}".format(i, expected_pkt.summary()))
        runSendReceive(injected_pkt, ptf_src_port, expected_pkt, [ptf_src_port], True, ptfadapter)

    # delete the SRv6 configuration
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48")
