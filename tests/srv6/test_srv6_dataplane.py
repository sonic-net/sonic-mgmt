import pytest
import time
import random
import logging
import string
from scapy.all import Raw
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, UDP
from scapy.layers.l2 import Ether

from srv6_utils import runSendReceive, verify_appl_db_sid_entry_exist
from common.reboot import reboot
from common.portstat_utilities import parse_portstat
from common.utilities import wait_until
from ptf.testutils import simple_ipv6_sr_packet, send_packet, verify_no_packet_any
from ptf.mask import Mask

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.asic("mellanox", "broadcom"),
    pytest.mark.topology("t0", "t1")
]


def get_neighbor_mac(dut, neighbor_ip):
    """Get the MAC address of the neighbor via the ip neighbor table"""
    return dut.command("ip neigh show {}".format(neighbor_ip))['stdout'].split()[4]


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


def run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, ptfhost, with_srh):
    for i in range(0, 10):
        # generate a random payload
        payload = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
        if with_srh:
            injected_pkt = simple_ipv6_sr_packet(
                eth_dst=dut_mac,
                eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode(),
                ipv6_src=ptfhost.mgmt_ipv6,
                ipv6_dst="fcbb:bbbb:1:2::",
                srh_seg_left=1,
                srh_nh=41,
                inner_frame=IPv6() / UDP(dport=4791) / Raw(load=payload)
            )
        else:
            injected_pkt = Ether(dst=dut_mac, src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode()) \
                / IPv6(src=ptfhost.mgmt_ipv6, dst="fcbb:bbbb:1:2::") \
                / IPv6() / UDP(dport=4791) / Raw(load=payload)

        expected_pkt = injected_pkt.copy()
        expected_pkt['Ether'].dst = get_neighbor_mac(duthost, neighbor_ip)
        expected_pkt['Ether'].src = dut_mac
        expected_pkt['IPv6'].dst = "fcbb:bbbb:2::"
        expected_pkt['IPv6'].hlim -= 1
        logger.debug("Expected packet #{}: {}".format(i, expected_pkt.summary()))
        runSendReceive(injected_pkt, ptf_src_port, expected_pkt, [ptf_src_port], True, ptfadapter)


@pytest.fixture()
def setup_uN(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_frontend_asic_index

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_port_ids = []
    for interface in list(mg_facts["minigraph_ptf_indices"].keys()):
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        ptf_port_ids.append(port_id)

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

    neighbor_ip = None
    # get neighbor IP
    lines = duthost.command("show ipv6 bgp sum")['stdout'].split("\n")
    for line in lines:
        if neighbor in line:
            neighbor_ip = line.split()[0]
    assert neighbor_ip, "Unable to find neighbor {} IP".format(neighbor)

    # use DUT portchannel if applicable
    pc_info = duthost.command("show int portchannel")['stdout']
    if dut_port in pc_info:
        lines = pc_info.split("\n")
        for line in lines:
            if dut_port in line:
                dut_port = line.split()[1]

    sonic_db_cli = "sonic-db-cli" + cli_options

    # add a locator configuration entry
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1:: func_len 0")
    # add a uN sid configuration entry
    duthost.command(sonic_db_cli +
                    " CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48 action uN decap_dscp_mode pipe")
    random.seed(time.time())
    # add the static route for IPv6 forwarding towards PTF's uSID and the blackhole route in a random order
    if random.randint(0, 1) == 0:
        duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb:2::/48 nexthop {} ifname {}"
                        .format(neighbor_ip, dut_port))
        duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb::/32 blackhole true")
    else:
        duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb::/32 blackhole true")
        duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb:2::/48 nexthop {} ifname {}"
                        .format(neighbor_ip, dut_port))
    duthost.command("config save -y")
    time.sleep(5)

    setup_info = {
        "asic_index": asic_index,
        "duthost": duthost,
        "dut_mac": dut_mac,
        "dut_port": dut_port,
        "ptf_src_port": ptf_src_port,
        "neighbor_ip": neighbor_ip,
        "cli_options": cli_options,
        "ptf_port_ids": ptf_port_ids
    }

    yield setup_info

    # delete the SRv6 configuration
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL STATIC_ROUTE\\|default\\|fcbb:bbbb:2::/48")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL STATIC_ROUTE\\|default\\|fcbb:bbbb::/32")
    duthost.command("config save -y")


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_uN_forwarding(setup_uN, ptfadapter, ptfhost, with_srh):
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    ptf_src_port = setup_uN['ptf_src_port']
    neighbor_ip = setup_uN['neighbor_ip']

    run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, ptfhost, with_srh)


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_uN_decap_pipe_mode(setup_uN, ptfadapter, ptfhost, with_srh):
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    ptf_src_port = setup_uN['ptf_src_port']
    neighbor_ip = setup_uN['neighbor_ip']

    for i in range(0, 10):
        if with_srh:
            injected_pkt = simple_ipv6_sr_packet(
                eth_dst=dut_mac,
                eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode(),
                ipv6_src=ptfhost.mgmt_ipv6,
                ipv6_dst="fcbb:bbbb:1::",
                srh_seg_left=1,
                srh_nh=41,
                inner_frame=IPv6(dst=neighbor_ip, src=ptfhost.mgmt_ipv6, tc=0x1, hlim=64)/ICMPv6EchoRequest(seq=i)
            )
        else:
            injected_pkt = Ether(dst=dut_mac, src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode()) \
                / IPv6(src=ptfhost.mgmt_ipv6, dst="fcbb:bbbb:1::") \
                / IPv6(dst=neighbor_ip, src=ptfhost.mgmt_ipv6) / ICMPv6EchoRequest(seq=i)

        expected_pkt = Ether(dst=get_neighbor_mac(duthost, neighbor_ip), src=dut_mac) / \
            IPv6(dst=neighbor_ip, src=ptfhost.mgmt_ipv6, tc=0x1, hlim=63)/ICMPv6EchoRequest(seq=i)
        logger.debug("Expected packet #{}: {}".format(i, expected_pkt.summary()))
        runSendReceive(injected_pkt, ptf_src_port, expected_pkt, [ptf_src_port], True, ptfadapter)


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_dataplane_after_config_reload(setup_uN, ptfadapter, ptfhost, with_srh):
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    ptf_src_port = setup_uN['ptf_src_port']
    neighbor_ip = setup_uN['neighbor_ip']

    # verify the forwarding works
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, with_srh)

    # reload the config
    duthost.command("config reload -y -f")
    time.sleep(180)

    sonic_db_cli = "sonic-db-cli" + setup_uN['cli_options']
    # wait for the config to be reprogrammed
    assert wait_until(180, 2, 0, verify_appl_db_sid_entry_exist, duthost, sonic_db_cli,
                      "SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1::", True), "SID is missing in APPL_DB"

    # verify the forwarding works after config reload
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, ptfhost, with_srh)


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_dataplane_after_bgp_restart(setup_uN, ptfadapter, ptfhost, with_srh):
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    ptf_src_port = setup_uN['ptf_src_port']
    neighbor_ip = setup_uN['neighbor_ip']

    # verify the forwarding works
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, with_srh)

    # restart BGP service, which will restart the BGP container
    if duthost.is_multi_asic:
        duthost.command("systemctl restart bgp@{}".format(setup_uN['asic_index']))
    else:
        duthost.command("systemctl restart bgp")
    time.sleep(180)

    sonic_db_cli = "sonic-db-cli" + setup_uN['cli_options']
    # wait for the config to be reprogrammed
    assert wait_until(180, 2, 0, verify_appl_db_sid_entry_exist, duthost, sonic_db_cli,
                      "SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1::", True), "SID is missing in APPL_DB"

    # verify the forwarding works after BGP restart
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, ptfhost, with_srh)


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_dataplane_after_reboot(setup_uN, ptfadapter, ptfhost, localhost, with_srh):
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    ptf_src_port = setup_uN['ptf_src_port']
    neighbor_ip = setup_uN['neighbor_ip']

    # verify the forwarding works
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, with_srh)

    # reboot DUT
    reboot(duthost, localhost, safe_reboot=True, check_intf_up_ports=True, wait_for_bgp=True)

    sonic_db_cli = "sonic-db-cli" + setup_uN['cli_options']
    # wait for the config to be reprogrammed
    assert wait_until(180, 2, 0, verify_appl_db_sid_entry_exist, duthost, sonic_db_cli,
                      "SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1::", True), "SID is missing in APPL_DB"

    # verify the forwarding works after reboot
    run_srv6_traffic_test(duthost, dut_mac, ptf_src_port, neighbor_ip, ptfadapter, ptfhost, with_srh)


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_no_sid_blackhole(setup_uN, ptfadapter, ptfhost, with_srh):
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    dut_port = setup_uN['dut_port']
    ptf_src_port = setup_uN['ptf_src_port']
    neighbor_ip = setup_uN['neighbor_ip']
    ptf_port_ids = setup_uN['ptf_port_ids']

    # get the RX_DROP counter before traffic test
    before_count = parse_portstat(duthost.command(f'portstat -i {dut_port}')['stdout_lines'])[dut_port]['RX_DRP']

    # inject a number of packets with random payload
    pkt_count = 100
    for i in range(pkt_count):
        payload = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
        if with_srh:
            injected_pkt = simple_ipv6_sr_packet(
                eth_dst=dut_mac,
                eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode(),
                ipv6_src=ptfhost.mgmt_ipv6,
                ipv6_dst="fcbb:bbbb:3:2::",
                srh_seg_left=1,
                srh_nh=41,
                inner_frame=IPv6(dst=neighbor_ip, src=ptfhost.mgmt_ipv6) / UDP(dport=4791) / Raw(load=payload)
            )
        else:
            injected_pkt = Ether(dst=dut_mac, src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode()) \
                / IPv6(src=ptfhost.mgmt_ipv6, dst="fcbb:bbbb:3:2::") \
                / IPv6(dst=neighbor_ip, src=ptfhost.mgmt_ipv6) / UDP(dport=4791) / Raw(load=payload)

        expected_pkt = injected_pkt.copy()
        expected_pkt['IPv6'].dst = "fcbb:bbbb:3:2::"
        expected_pkt['IPv6'].hlim -= 1
        logger.debug("Expected packet #{}: {}".format(i, expected_pkt.summary()))

        expected_pkt = Mask(expected_pkt)
        expected_pkt.set_do_not_care_packet(Ether, "dst")
        expected_pkt.set_do_not_care_packet(Ether, "src")
        send_packet(ptfadapter, ptf_src_port, injected_pkt, 1)
        verify_no_packet_any(ptfadapter, expected_pkt, ptf_port_ids, 0, 1)

    # verify that the RX_DROP counter is incremented
    after_count = parse_portstat(duthost.command(f'portstat -i {dut_port}')['stdout_lines'])[dut_port]['RX_DRP']
    assert after_count >= (before_count + pkt_count), "RX_DROP counter is not incremented as expected"
