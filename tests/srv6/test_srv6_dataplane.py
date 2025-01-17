import pytest
import time
import random
import logging
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest

from srv6_utils import runSendReceive
from ptf.testutils import simple_ipv6_sr_packet

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0")
]

def get_ptf_src_port_and_dut_port(dut, tbinfo):
    """Get the PTF port mapping for the duthost or an asic of the duthost"""
    dut_mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    ports_map = list(dut_mg_facts["minigraph_ptf_indices"].items())
    if not ports_map:
        pytest.skip("No PTF ports found for {}".format(dut))

    dut_port, ptf_src_port = random.choice(ports_map)
    return dut_port, ptf_src_port

def test_srv6_uN_forwarding(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, ptfadapter, tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_frontend_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
        dut_asic= duthost.asic_instance[asic_index]
        dut_mac = dut_asic.get_router_mac()
        dut_port, ptf_src_port = get_ptf_src_port_and_dut_port(dut_asic, tbinfo)
    else:
        cli_options = ''
        dut_mac = duthost._get_router_mac()
        dut_port, ptf_src_port = get_ptf_src_port_and_dut_port(duthost, tbinfo)

    logger.info("Doing test on DUT port {} | PTF port {}".format(dut_port, ptf_src_port))

    sonic_db_cli = "sonic-db-cli" + cli_options

    # add a locator configuration entry
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1::")
    # add a uN sid configuration entry
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1:1:: action uN")
    # add the static route for IPv6 forwarding towards PTF's uSID
    duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE|default|fcbb:bbbb:2:1::/64 nexthop {} ifname {}"
                    .format(ptfadapter.ptf_ipv6, dut_port))
    time.sleep(5)

    for i in range(0, 10):
        injected_pkt = simple_ipv6_sr_packet(
            eth_dst=dut_mac,
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port),
            ipv6_src=ptfadapter.ptf_ipv6,
            ipv6_dst="fcbb:bbbb:1:1:2:1::",
            srh_seg_left=1,
            srh_nh=41,
            inner_frame=IPv6()/ICMPv6EchoRequest(seq=i)
        )
        expected_pkt = injected_pkt.copy()
        expected_pkt['IPv6'].dst = "fcbb:bbbb:2:1::"
        expected_pkt['IPv6'].hlim -= 1
        runSendReceive(injected_pkt, ptf_src_port, expected_pkt, [ptf_src_port], True, ptfadapter)

    # delete the SRv6 configuration
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1:1::")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL STATIC_ROUTE|default|fcbb:bbbb:2:1::/64")

# def test_srv6_uDT46_decapsulation(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, ptfadapter, tbinfo):
#     duthost = duthosts[enum_frontend_dut_hostname]
#     asic_index = enum_frontend_asic_index

#     if duthost.is_multi_asic:
#         cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
#         dut_asic= duthost.asic_instance[asic_index]
#         dut_mac = dut_asic.get_router_mac()
#         dut_port, ptf_src_port = get_ptf_src_port_and_dut_port(dut_asic, tbinfo)
#     else:
#         cli_options = ''
#         dut_mac = duthost._get_router_mac()
#         dut_port, ptf_src_port = get_ptf_src_port_and_dut_port(duthost, tbinfo)

#     logger.info("Doing test on DUT port {} | PTF port {}".format(dut_port, ptf_src_port))

#     sonic_db_cli = "sonic-db-cli" + cli_options

#     # add a locator configuration entry
#     duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1::")
#     # add a uN sid configuration entry
#     duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1:1:: action uDT46 decap_dscp_mode pipe")
#     time.sleep(5)

#     injected_pkt = simple_ipv6_sr_packet(
#         eth_dst=dut_mac,
#         eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port),
#         ipv6_src=ptfadapter.ptf_ipv6,
#         ipv6_dst="fcbb:bbbb:1:1::",
#         ipv6_tc=4,
#         srh_seg_left=1,
#         srh_nh=41,
#         inner_frame=IPv6(src=ptfadapter.ptf_ipv6, dst=ptfadapter.ptf_ipv6)/ICMPv6EchoRequest()
#     )
#     expected_pkt = IPv6(src=ptfadapter.ptf_ipv6, dst=ptfadapter.ptf_ipv6, tc=4)/ICMPv6EchoRequest()
#     expected_pkt['IPv6'].hlim -= 1
#     for i in range(0, 10):
#         runSendReceive(injected_pkt, ptf_src_port, expected_pkt, [ptf_src_port], True, ptfadapter)

#     # delete the SRv6 configuration
#     duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
#     duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1:1::")