import random
import string
import ipaddress
import time
import logging
import pytest
from scapy.all import Raw
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.l2 import Ether

from ptf.testutils import simple_ipv6_sr_packet, send, verify_no_packet_any
from srv6_utils import runSendReceive, get_neighbor_mac
from tests.common.helpers.assertions import pytest_require


logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.asic("mellanox", "broadcom", "vs"),
    pytest.mark.topology("t0")
]


def run_srv6_downstrean_traffic_test(duthost, dut_mac, ptf_src_port, ptf_dst_port,
                                     neighbor_ip, ptfadapter, ptfhost, with_srh):
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
        runSendReceive(injected_pkt, ptf_src_port, expected_pkt, [ptf_dst_port], True, ptfadapter)


@pytest.fixture
def proxy_arp_enabled(rand_selected_dut):
    """
    Tries to enable proxy ARP for each VLAN on the ToR

    Also checks CONFIG_DB to see if the attempt was successful

    During teardown, restores the original proxy ARP setting
    """
    duthost = rand_selected_dut
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    pytest_require(duthost.has_config_subcommand('config vlan proxy_arp'),
                   "Proxy ARP command does not exist on device")

    proxy_arp_check_cmd = 'sonic-db-cli CONFIG_DB HGET "VLAN_INTERFACE|Vlan{}" proxy_arp'
    proxy_arp_config_cmd = 'config vlan proxy_arp {} {}'
    vlans = config_facts['VLAN']
    vlan_ids = [vlans[vlan]['vlanid'] for vlan in list(vlans.keys())]
    old_proxy_arp_vals = {}

    # Enable proxy ARP/NDP for every VLAN on the DUT
    for vid in vlan_ids:
        old_proxy_arp_res = duthost.shell(proxy_arp_check_cmd.format(vid))
        old_proxy_arp_vals[vid] = old_proxy_arp_res['stdout']

        duthost.shell(proxy_arp_config_cmd.format(vid, 'enabled'))
        logger.info("Enabled proxy ARP for Vlan{}".format(vid))

    yield

    proxy_arp_del_cmd = 'sonic-db-cli CONFIG_DB HDEL "VLAN_INTERFACE|Vlan{}" proxy_arp'
    for vid, proxy_arp_val in list(old_proxy_arp_vals.items()):
        if 'enabled' not in proxy_arp_val:
            # Disable proxy_arp explicitly
            duthost.shell(proxy_arp_config_cmd.format(vid, 'disabled'))
            time.sleep(2)
            # Delete the DB entry instead of using the config command to satisfy check_dut_health_status
            duthost.shell(proxy_arp_del_cmd.format(vid))


@pytest.fixture()
def setup_downstream_uN(rand_selected_dut, ptfhost, tbinfo):
    duthost = rand_selected_dut
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_ports_map = mg_facts["minigraph_ptf_indices"]
    vlan = list(mg_facts["minigraph_vlans"].keys())[0]
    logger.info("Doing test on VLAN: {}".format(vlan))
    logger.info(mg_facts["minigraph_vlan_interfaces"])
    for vlan_intf in mg_facts["minigraph_vlan_interfaces"]:
        if vlan_intf["attachto"] == vlan and ":" in str(vlan_intf['subnet']):
            vlan_ipv6_subnet = ipaddress.IPv6Network(vlan_intf["subnet"])
            vlan_gw_ip = vlan_intf["addr"]
            break
    assert vlan_ipv6_subnet is not None, "No IPv6 subnet found for VLAN {}".format(vlan)
    for ip in vlan_ipv6_subnet.hosts():
        if str(ip) != str(vlan_gw_ip):
            server_neighbor_ip = str(ip)
            break
    logger.debug("PTF port map: {}".format(ptf_ports_map))

    topo = tbinfo["topo"]["type"]
    if topo != "t0":
        pytest.skip("Only support T0 topo")
    if len(ptf_ports_map) == 0:
        pytest.skip("No PTF ports found for {}".format(duthost.hostname))

    # get upstream ptf ports and downstream ptf ports (for one VLAN)
    downstream_port_ids = []
    upstream_port_ids = []
    for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
        if interface in mg_facts["minigraph_vlans"][vlan]["members"]:
            port_id = ptf_ports_map[interface]
            if topo == "t0" and "Servers" in neighbor["name"]:
                downstream_port_ids.append(port_id)
            elif topo == "t0" and "T1" in neighbor["name"]:
                upstream_port_ids.append(port_id)

    # use the first healthy upstream port as the PTF src port
    lldp_table = duthost.command("show lldp table")['stdout'].split("\n")[3:]
    neighbor_table = [line.split() for line in lldp_table]
    for entry in neighbor_table:
        intf = entry[0]
        if intf in ptf_ports_map:
            dut_port = intf
            ptf_src_port = ptf_ports_map[intf]

    # randomly select a downstream port to be used as the PTF dst port
    random.seed(time.time())
    ptf_dst_port = random.choice(downstream_port_ids)
    for intf in ptf_ports_map:
        if ptf_ports_map[intf] == ptf_dst_port:
            dut_downstream_port = intf
            break
    assert dut_downstream_port, "No downstream port on DUT found for {}".format(ptf_dst_port)

    logger.info("Doing test on DUT port {} | PTF src port {} | PTF dst port {}".format(
        dut_port, ptf_src_port, ptf_dst_port))

    # add the VLAN IP address to PTF host
    ptfhost.command(f"ip addr add {server_neighbor_ip}/{vlan_ipv6_subnet.prefixlen} dev eth{ptf_dst_port}")

    sonic_db_cli = "sonic-db-cli"
    # add a locator configuration entry
    duthost.command(sonic_db_cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1:: func_len 0")
    # add a uN sid configuration entry
    duthost.command(sonic_db_cli +
                    " CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48 action uN decap_dscp_mode pipe")

    # add the static route for IPv6 forwarding towards PTF's destination port
    duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb:2::/48 nexthop {} ifname {}"
                    .format(server_neighbor_ip, vlan))
    duthost.command(sonic_db_cli + " CONFIG_DB HSET STATIC_ROUTE\\|default\\|fcbb:bbbb::/32 blackhole true")
    duthost.command("config save -y")
    time.sleep(5)

    setup_info = {
        "duthost": duthost,
        "dut_mac": duthost._get_router_mac(),
        "dut_port": dut_port,
        "dut_downstream_port": dut_downstream_port,
        "ptf_src_port": ptf_src_port,
        "ptf_dst_port": ptf_dst_port,
        "downstream_port_ids": downstream_port_ids,
        "neighbor_ip": server_neighbor_ip,
        "vlan": vlan,
    }

    yield setup_info

    # delete the VLAN IP address from PTF host and clean neighbor entry on duthost
    ptfhost.command(f"ip addr del {server_neighbor_ip}/{vlan_ipv6_subnet.prefixlen} dev eth{ptf_dst_port}")
    duthost.command(f"ip neigh del {server_neighbor_ip} dev {vlan}")

    # delete the SRv6 configuration
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL STATIC_ROUTE\\|default\\|fcbb:bbbb:2::/48")
    duthost.command(sonic_db_cli + " CONFIG_DB DEL STATIC_ROUTE\\|default\\|fcbb:bbbb::/32")
    duthost.command("config save -y")


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_uN_forwarding_towards_vlan(setup_downstream_uN, ptfadapter, ptfhost, with_srh):
    duthost = setup_downstream_uN['duthost']
    dut_mac = setup_downstream_uN['dut_mac']
    ptf_src_port = setup_downstream_uN['ptf_src_port']
    ptf_dst_port = setup_downstream_uN['ptf_dst_port']
    neighbor_ip = setup_downstream_uN['neighbor_ip']

    run_srv6_downstrean_traffic_test(duthost, dut_mac, ptf_src_port, ptf_dst_port,
                                     neighbor_ip, ptfadapter, ptfhost, with_srh)


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_uN_no_vlan_flooding(setup_downstream_uN, proxy_arp_enabled, ptfadapter, ptfhost, with_srh):
    duthost = setup_downstream_uN['duthost']
    dut_mac = setup_downstream_uN['dut_mac']
    ptf_src_port = setup_downstream_uN['ptf_src_port']
    dut_downstream_port = setup_downstream_uN['dut_downstream_port']
    ptf_downstream_ports = setup_downstream_uN['downstream_port_ids']
    neighbor_ip = setup_downstream_uN['neighbor_ip']

    # shutdown DUT downstream port
    duthost.shell("config interface shutdown {}".format(dut_downstream_port))
    duthost.shell("sonic-clear fdb all")
    time.sleep(5)

    # run traffic test and verify no flooding in vlan
    ptfadapter.dataplane.flush()
    # generate a random payload
    payload = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
    if with_srh:
        injected_pkt = simple_ipv6_sr_packet(
            eth_dst=dut_mac,
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode(),
            ipv6_src=ptfhost.mgmt_ipv6,
            ipv6_dst="fcbb:bbbb:1:2::",
            srh_seg_left=0,
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
    send(ptfadapter, ptf_src_port, injected_pkt, count=100)
    verify_no_packet_any(ptfadapter, expected_pkt, ptf_downstream_ports, timeout=5)

    # bring DUT downstream port back up
    duthost.shell("config interface startup {}".format(dut_downstream_port))
