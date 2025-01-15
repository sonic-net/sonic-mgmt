import pytest
import time
import random
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest

from srv6_utils import runSendReceive
from ptf.testutils import simple_ipv6_sr_packet

pytestmark = [
    pytest.mark.topology("t0")
]

def get_ptf_src_port(dut, tbinfo):
    src_asic_mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    ptf_src_ports = list(src_asic_mg_facts["minigraph_ptf_indices"].values())
    if not ptf_src_ports:
        pytest.skip("No PTF ports found for asic{}".format(dut.asic_index))

    return random.choice(ptf_src_ports)

def test_srv6_uN_forwarding(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, ptfadapter, tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_frontend_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
        dut_asic= duthost.asic_instance[asic_index]
        dut_mac = dut_asic.get_router_mac()
        ptf_src_port = get_ptf_src_port(dut_asic, tbinfo)
    else:
        cli_options = ''
        dut_mac = duthost._get_router_mac()
        ptf_src_port = get_ptf_src_port(duthost, tbinfo)

    sonic_db_cli = "sonic-db-cli" + cli_options

    # add a locator configuration entry
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1::")
    # add a uN sid configuration entry
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1:1:: action uN")
    # add the static route for IPv6 forwarding towards PTF's uSID
    duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE|default|fcbb:bbbb:2:1::/64 nexthop {} ifname {}"
                    .format(ptfadapter.ptf_ip, ))
    time.sleep(5)

    injected_pkt = simple_ipv6_sr_packet(
        eth_dst=dut_mac,
        eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port),
        ipv6_src=ptfadapter.ptf_ip,
        ipv6_dst="fcbb:bbbb:1:1:2:1::",
        srh_seg_left=1,
        srh_nh=41,
        inner_frame=IPv6()/ICMPv6EchoRequest()
    )
    expected_pkt = injected_pkt.copy()
    expected_pkt['IPv6'].dst = "fcbb:bbbb:2:1::"
    expected_pkt['IPv6'].ttl -= 1
    for i in range(0, 10):
        runSendReceive(injected_pkt, ptf_src_port, expected_pkt, [ptf_src_port], True, ptfadapter)

    # delete the SRv6 configuration
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1:1::")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL STATIC_ROUTE|default|fcbb:bbbb:2:1::/64")

def test_srv6_uDT46_decapsulation():
    pass