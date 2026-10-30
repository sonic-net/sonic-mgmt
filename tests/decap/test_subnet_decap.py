import pytest
import logging
import json
import time
import random
import ipaddress
import ast
from collections import defaultdict

import ptf.packet as packet
import ptf.testutils as testutils
from ptf.mask import Mask
from tests.common.dualtor.dual_tor_utils import rand_selected_interface     # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py       # noqa: F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m  # noqa: F401
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until, compose_dict_from_cli
from tests.common.helpers.sonic_db import redis_get_keys
from tests.common.helpers.bgp import BGPNeighbor, NEIGHBOR_SAVE_DEST_TMPL, \
    BGP_SAVE_DEST_TMPL, _write_variable_from_j2_to_configdb, wait_tcp_connection

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1', 'dualtor')
]

DECAP_IPINIP_SUBNET_CONFIG_TEMPLATE = "decap/template/decap_ipinip_subnet_config.j2"
DECAP_IPINIP_SUBNET_CONFIG_JSON = "decap_ipinip_subnet_config.json"
DECAP_IPINIP_SUBNET_DEL_TEMPLATE = "decap/template/decap_ipinip_subnet_delete.j2"
DECAP_IPINIP_SUBNET_DEL_JSON = "decap_ipinip_subnet_delete.json"

SUBNET_DECAP_SRC_IP_V4 = "20.20.20.0/24"
SUBNET_DECAP_SRC_IP_V6 = "fc01::/120"
OUTER_DST_IP_V4 = "192.168.0.200"
OUTER_DST_IP_V6 = "fc02:1000::200"
VIP_ROUTE_V4 = "192.168.1.0/24"
VIP_OUTER_DST_IP_V4 = "192.168.1.1"
VIP_ROUTE_V6 = "fc02:2000::/120"
VIP_OUTER_DST_IP_V6 = "fc02:2000::1"
SUBNET_DECAP_TUNNEL_NAME_V4 = "IPINIP_SUBNET"
SUBNET_DECAP_TUNNEL_NAME_V6 = "IPINIP_SUBNET_V6"


@pytest.fixture(scope='module')
def prepare_subnet_decap_config(rand_selected_dut):
    logger.info("Prepare subnet decap config")
    rand_selected_dut.shell('sonic-db-cli CONFIG_DB hset "SUBNET_DECAP|subnet_type" \
                            "status" "enable" "src_ip" "{}" "src_ip_v6" "{}"'
                            .format(SUBNET_DECAP_SRC_IP_V4, SUBNET_DECAP_SRC_IP_V6))
    rand_selected_dut.shell('sudo config save -y')
    config_reload(rand_selected_dut)
    #  Wait for all processes come up
    time.sleep(120)

    yield
    rand_selected_dut.shell('sonic-db-cli CONFIG_DB del "SUBNET_DECAP|subnet_type"')
    rand_selected_dut.shell('sudo config save -y')
    config_reload(rand_selected_dut, config_source='minigraph')


@pytest.fixture(scope='module')
def prepare_vlan_subnet_test_port(rand_selected_dut, tbinfo):
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    topo = tbinfo["topo"]["type"]

    if not mg_facts['minigraph_portchannels']:
        pytest.skip('No portchannels found in minigraph')

    dut_port = list(mg_facts['minigraph_portchannels'].keys())[0]
    dut_eth_port = mg_facts["minigraph_portchannels"][dut_port]["members"][0]
    ptf_src_port = mg_facts["minigraph_ptf_indices"][dut_eth_port]

    downstream_port_ids = []
    upstream_port_ids = []
    for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        if topo == "t0" and "Servers" in neighbor["name"]:
            downstream_port_ids.append(port_id)
        elif (topo == "t0" and "T1" in neighbor["name"]) or (topo == "t1" and "T2" in neighbor["name"]):
            upstream_port_ids.append(port_id)

    logger.info("ptf_src_port: {}, downstream_port_ids: {}, upstream_port_ids: {}"
                .format(ptf_src_port, downstream_port_ids, upstream_port_ids))
    return ptf_src_port, downstream_port_ids, upstream_port_ids


@pytest.fixture(scope='module')
def prepare_negative_ip_port_map(prepare_vlan_subnet_test_port):
    _, downstream_port_ids, _ = prepare_vlan_subnet_test_port
    ptf_target_port = random.choice(downstream_port_ids)
    ip_to_port = {
        OUTER_DST_IP_V4: ptf_target_port,
        OUTER_DST_IP_V6: ptf_target_port
    }
    return ptf_target_port, ip_to_port


@pytest.fixture
def setup_arp_responder(rand_selected_dut, ptfhost, prepare_negative_ip_port_map):
    ptfhost.command('supervisorctl stop arp_responder', module_ignore_errors=True)

    _, ip_to_port = prepare_negative_ip_port_map
    arp_responder_cfg = defaultdict(list)
    ip_list = []

    for ip, port in list(ip_to_port.items()):
        iface = "eth{}".format(port)
        arp_responder_cfg[iface].append(ip)
        ip_list.append(ip)

    CFG_FILE = '/tmp/arp_responder.json'
    with open(CFG_FILE, 'w') as file:
        json.dump(arp_responder_cfg, file)

    ptfhost.copy(src=CFG_FILE, dest=CFG_FILE)
    extra_vars = {
            'arp_responder_args': '--conf {}'.format(CFG_FILE)
        }

    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    ptfhost.template(src='templates/arp_responder.conf.j2', dest='/etc/supervisor/conf.d/arp_responder.conf')

    ptfhost.command('supervisorctl reread')
    ptfhost.command('supervisorctl update')

    logger.info("Start arp_responder")
    ptfhost.command('supervisorctl start arp_responder')
    time.sleep(10)

    yield

    ptfhost.command('supervisorctl stop arp_responder', module_ignore_errors=True)
    ptfhost.file(path='/tmp/arp_responder.json', state="absent")
    rand_selected_dut.command('sonic-clear arp')


def build_encapsulated_vlan_subnet_packet(ptfadapter, rand_selected_dut, ip_version, stage):
    eth_dst = rand_selected_dut.asic_instance().get_router_mac()
    eth_src = ptfadapter.dataplane.get_mac(*list(ptfadapter.dataplane.ports.keys())[0])
    logger.info("eth_src: {}, eth_dst: {}".format(eth_src, eth_dst))

    if ip_version == "IPv4":
        outer_dst_ipv4 = OUTER_DST_IP_V4
        if stage == "positive":
            outer_src_ipv4 = "20.20.20.10"
        elif stage == "negative":
            outer_src_ipv4 = "30.30.30.10"

        inner_packet = testutils.simple_ip_packet(
            ip_src="1.1.1.1",
            ip_dst="2.2.2.2"
        )[packet.IP]
        outer_packet = testutils.simple_ipv4ip_packet(
            eth_dst=eth_dst,
            eth_src=eth_src,
            ip_src=outer_src_ipv4,
            ip_dst=outer_dst_ipv4,
            inner_frame=inner_packet
        )

    elif ip_version == "IPv6":
        outer_dst_ipv6 = OUTER_DST_IP_V6
        if stage == "positive":
            outer_src_ipv6 = "fc01::10"
        elif stage == "negative":
            outer_src_ipv6 = "fc01::10:10"

        inner_packet = testutils.simple_tcpv6_packet(
            ipv6_src="1::1",
            ipv6_dst="2::2"
        )[packet.IPv6]
        outer_packet = testutils.simple_ipv6ip_packet(
            eth_dst=eth_dst,
            eth_src=eth_src,
            ipv6_src=outer_src_ipv6,
            ipv6_dst=outer_dst_ipv6,
            inner_frame=inner_packet
        )

    return outer_packet


def build_expected_vlan_subnet_packet(encapsulated_packet, ip_version, stage, decrease_ttl=False):
    if stage == "positive":
        if ip_version == "IPv4":
            pkt = encapsulated_packet[packet.IP].payload[packet.IP].copy()
        elif ip_version == "IPv6":
            pkt = encapsulated_packet[packet.IPv6].payload[packet.IPv6].copy()
        # Use dummy mac address that will be ignored in mask
        pkt = packet.Ether(src="aa:bb:cc:dd:ee:ff", dst="aa:bb:cc:dd:ee:ff") / pkt
    elif stage == "negative":
        pkt = encapsulated_packet.copy()

    if ip_version == "IPv4":
        pkt.ttl = pkt.ttl - 1 if decrease_ttl else pkt.ttl
    elif ip_version == "IPv6":
        pkt.hlim = pkt.hlim - 1 if decrease_ttl else pkt.hlim

    exp_pkt = Mask(pkt)
    exp_pkt.set_do_not_care_packet(packet.Ether, "dst")
    exp_pkt.set_do_not_care_packet(packet.Ether, "src")
    if ip_version == "IPv4":
        exp_pkt.set_do_not_care_packet(packet.IP, "chksum")
    return exp_pkt


def verify_packet_with_expected(ptfadapter, stage, pkt, exp_pkt, send_port,
                                recv_ports=[], recv_port=None, timeout=10):    # noqa: F811
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, send_port, pkt, 10)
    if stage == "positive":
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, recv_ports, timeout=timeout)
    elif stage == "negative":
        testutils.verify_packet(ptfadapter, exp_pkt, recv_port, timeout=timeout)


def get_vip_route(ip_version):
    if ip_version == "IPv4":
        return VIP_ROUTE_V4
    return VIP_ROUTE_V6


def get_subnet_decap_tunnel_name(ip_version):
    if ip_version == "IPv4":
        return SUBNET_DECAP_TUNNEL_NAME_V4
    return SUBNET_DECAP_TUNNEL_NAME_V6


def is_vip_decap_term_programmed(duthost, ip_version, vip_prefix):
    tunnel_name = get_subnet_decap_tunnel_name(ip_version)
    cmd = 'sonic-db-cli STATE_DB hgetall "TUNNEL_DECAP_TERM_TABLE|{}|{}"'.format(
        tunnel_name, vip_prefix
    )
    output = duthost.command(cmd, module_ignore_errors=True)["stdout"].strip()
    try:
        decap_term = ast.literal_eval(output or "{}")
    except (SyntaxError, ValueError):
        logger.warning("Failed to parse VIP decap term output: %s", output)
        return False
    return decap_term.get("term_type") == "MP2MP" and decap_term.get("subnet_type") == "vip"


@pytest.mark.parametrize("ip_version", ["IPv4", "IPv6"])
@pytest.mark.parametrize("stage", ["positive", "negative"])
def test_vlan_subnet_decap(request, rand_selected_dut, tbinfo, ptfhost, ptfadapter, ip_version, stage,
                           prepare_subnet_decap_config, prepare_vlan_subnet_test_port,
                           prepare_negative_ip_port_map, setup_arp_responder,      # noqa: F811
                           toggle_all_simulator_ports_to_rand_selected_tor_m,      # noqa: F811
                           setup_standby_ports_on_rand_unselected_tor):            # noqa: F811
    ptf_src_port, _, upstream_port_ids = prepare_vlan_subnet_test_port

    encapsulated_packet = build_encapsulated_vlan_subnet_packet(ptfadapter, rand_selected_dut, ip_version, stage)
    exp_pkt = build_expected_vlan_subnet_packet(encapsulated_packet, ip_version, stage, decrease_ttl=True)

    if stage == "negative":
        ptf_target_port, _ = prepare_negative_ip_port_map
        request.getfixturevalue('setup_arp_responder')
    else:
        ptf_target_port = None

    verify_packet_with_expected(ptfadapter, stage, encapsulated_packet, exp_pkt,
                                ptf_src_port, recv_ports=upstream_port_ids, recv_port=ptf_target_port)


@pytest.fixture
def setup_IPv4_SLB_connection(rand_selected_dut, ptfhost, prepare_vlan_subnet_test_port, tbinfo):
    duthost = rand_selected_dut
    # gather DUT's VLAN info
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vlan = list(mg_facts["minigraph_vlans"].keys())[0]
    for vlan_intf in mg_facts["minigraph_vlan_interfaces"]:
        if vlan_intf["attachto"] == vlan and "." in str(vlan_intf['subnet']):
            vlan_ip_subnet = ipaddress.IPv4Network(vlan_intf["subnet"])
            vlan_gw_ip = vlan_intf["addr"]
            break

    # pick a VLAN IP as the SLB's IP
    for addr in vlan_ip_subnet.hosts():
        if str(addr) != str(vlan_gw_ip):
            peer_addr = str(addr)
            break
    assert peer_addr, "Failed to generate ip address for test"

    _, downstream_port_ids, _ = prepare_vlan_subnet_test_port

    # Get loopback0 address
    cfg_facts = duthost.config_facts(source='persistent', asic_index='all')[0]['ansible_facts']
    if 'Loopback0' in cfg_facts['LOOPBACK_INTERFACE']:
        lbs0 = list(cfg_facts['LOOPBACK_INTERFACE']['Loopback0'].keys())
        for lb0 in lbs0:
            lb0intf = ipaddress.ip_interface(lb0)
            if lb0intf.ip.version == 4:
                if "/" in lb0:
                    local_addr = lb0.split("/")[0]
                    break
                else:
                    local_addr = lb0

    # Assign peer addr to an interface on ptf
    logger.info("Generated peer address {}".format(peer_addr))
    peer_port = random.choice(downstream_port_ids)
    router_mac = duthost.asic_instance().get_router_mac()
    ptf_interface = "eth" + str(peer_port)
    logger.info("Configured route to from PTF to DUT on PTF interface {}".format(ptf_interface))
    ptfhost.shell("ip addr add {}/{} dev {}".format(peer_addr, vlan_ip_subnet.prefixlen, ptf_interface))
    ptfhost.shell("ip neigh add %s lladdr %s dev %s" % (local_addr, router_mac, ptf_interface))
    ptfhost.shell("ip route add %s/%s dev %s" % (local_addr, str(32), ptf_interface))

    # setup BGP connection between SLB on PTF host and DUT
    dut_asn = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']['minigraph_bgp_asn']
    slb_bgp = BGPNeighbor(duthost, ptfhost, "slb", peer_addr, 65534,
                          local_addr, dut_asn, port=5168)

    # start exaBGP instance
    slb_bgp.start_session()

    # announce the VIP route
    vip_route = {
        "prefix": VIP_ROUTE_V4,
        "nexthop": peer_addr,
        "aspath": "{}".format(slb_bgp.asn)
    }
    slb_bgp.announce_route(vip_route)

    # Get the upstream neighbor connected to PortChannel101
    ip_intf = duthost.command("show ip int")['stdout'].split('\n')
    for line in ip_intf:
        content = line.split()
        if len(content) > 0 and content[0] == "PortChannel101":
            neighbor_ip = content[4]
    duthost.command(f"sonic-db-cli CONFIG_DB hset 'STATIC_ROUTE|default|2.2.0.0/16' \
                    nexthop '{neighbor_ip}' ifname 'PortChannel101'")

    yield neighbor_ip

    duthost.command("sonic-db-cli CONFIG_DB del 'STATIC_ROUTE|default|2.2.0.0/16'")

    # withdraw the VIP route
    slb_bgp.withdraw_route(vip_route)

    # tear down BGP connection
    slb_bgp.stop_session()

    # clean ip config upon teardown
    ptfhost.shell("ip route del %s/%s dev %s" % (local_addr, str(32), ptf_interface))
    ptfhost.shell("ip neigh del %s lladdr %s dev %s" % (local_addr, router_mac, ptf_interface))
    ptfhost.shell("ip addr del %s/%s dev %s" % (peer_addr, str(vlan_ip_subnet.prefixlen), ptf_interface))


@pytest.fixture
def setup_IPv6_SLB_connection(rand_selected_dut, ptfhost, prepare_vlan_subnet_test_port, tbinfo):
    duthost = rand_selected_dut

    # gather DUT's VLAN info
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vlan = list(mg_facts["minigraph_vlans"].keys())[0]
    for vlan_intf in mg_facts["minigraph_vlan_interfaces"]:
        if vlan_intf["attachto"] == vlan and ":" in str(vlan_intf['subnet']):
            vlan_ipv6_subnet = ipaddress.IPv6Network(vlan_intf["subnet"])
            vlan_gw_ip = vlan_intf["addr"]
            break

    # pick a VLAN IP as the SLB's IP
    for addr in vlan_ipv6_subnet.hosts():
        if str(addr) != str(vlan_gw_ip):
            peer_addr = str(addr)
            break
    assert peer_addr, "Failed to generate ip address for test"

    _, downstream_port_ids, _ = prepare_vlan_subnet_test_port

    # Get loopback0 address
    cfg_facts = duthost.config_facts(source='persistent', asic_index='all')[0]['ansible_facts']
    if 'Loopback0' in cfg_facts['LOOPBACK_INTERFACE']:
        lbs0 = list(cfg_facts['LOOPBACK_INTERFACE']['Loopback0'].keys())
        for lb0 in lbs0:
            lb0intf = ipaddress.ip_interface(lb0)
            if lb0intf.ip.version == 6:
                if "/" in lb0:
                    local_addr = lb0.split("/")[0]
                    break
                else:
                    local_addr = lb0

    # Assign peer addr to an interface on ptf
    logger.info("Generated peer address {}".format(peer_addr))
    random.seed(time.time())
    peer_port = random.choice(downstream_port_ids)
    router_mac = duthost.asic_instance().get_router_mac()
    ptf_interface = "eth" + str(peer_port)
    logger.info("Configured route to from PTF to DUT on PTF interface {}".format(ptf_interface))
    ptfhost.shell("ip -6 addr add {}/{} dev {}".format(peer_addr, str(vlan_ipv6_subnet.prefixlen), ptf_interface))
    ptfhost.shell("ip neigh add %s lladdr %s dev %s" % (local_addr, router_mac, ptf_interface))
    ptfhost.shell("ip -6 route add %s/%s dev %s" % (local_addr, str(128), ptf_interface))

    # setup BGP connection between SLB on PTF host and DUT
    dut_asn = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']['minigraph_bgp_asn']
    slb_bgp = BGPNeighbor(duthost, ptfhost, "slb", peer_addr, 65534,
                          local_addr, dut_asn, port=5168)
    _write_variable_from_j2_to_configdb(
        slb_bgp.duthost,
        "bgp/templates/neighbor_metadata_template.j2",
        namespace=slb_bgp.namespace,
        save_dest_path=NEIGHBOR_SAVE_DEST_TMPL % slb_bgp.name,
        neighbor_name=slb_bgp.name,
        neighbor_lo_addr=slb_bgp.ip,
        neighbor_mgmt_addr=slb_bgp.ip,
        neighbor_hwsku=None,
        neighbor_type=slb_bgp.type
    )

    _write_variable_from_j2_to_configdb(
        slb_bgp.duthost,
        "bgp/templates/bgp_template.j2",
        namespace=slb_bgp.namespace,
        save_dest_path=BGP_SAVE_DEST_TMPL % slb_bgp.name,
        db_table_name="BGP_NEIGHBOR",
        peer_addr=slb_bgp.ip,
        asn=slb_bgp.asn,
        local_addr=slb_bgp.peer_ip,
        peer_name=slb_bgp.name
    )

    # start the exaBGP instance
    slb_bgp.ptfhost.exabgp(
        name=slb_bgp.name,
        state="started",
        local_ip=slb_bgp.ip,
        router_id="11.0.0.1",
        peer_ip=slb_bgp.peer_ip,
        local_asn=slb_bgp.asn,
        peer_asn=slb_bgp.peer_asn,
        port=slb_bgp.port
    )

    if not wait_tcp_connection(ptfhost, slb_bgp.ptfip, slb_bgp.port, timeout_s=60):
        raise RuntimeError("Failed to start BGP neighbor %s" % slb_bgp.name)

    # allow ebgp-multihop on DUT
    allow_ebgp_multihop_cmd = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'neighbor %s ebgp-multihop'"
    )
    allow_ebgp_multihop_cmd %= (slb_bgp.peer_asn, slb_bgp.ip)
    duthost.shell(allow_ebgp_multihop_cmd)

    # announce the VIP route
    vip_route = {
        "prefix": VIP_ROUTE_V6,
        "nexthop": peer_addr,
        "aspath": "{}".format(slb_bgp.asn)
    }
    slb_bgp.announce_route(vip_route)

    # Get the upstream neighbor connected to PortChannel101
    ipv6_intf = duthost.command("show ipv6 int")['stdout'].split('\n')
    for line in ipv6_intf:
        content = line.split()
        if len(content) > 0 and content[0] == "PortChannel101":
            neighbor_ip = content[4]
    duthost.command(f"sonic-db-cli CONFIG_DB hset 'STATIC_ROUTE|default|2::/16' \
                    nexthop '{neighbor_ip}' ifname 'PortChannel101'")

    yield neighbor_ip

    duthost.command("sonic-db-cli CONFIG_DB del 'STATIC_ROUTE|default|2::/16'")

    # withdraw the VIP route
    slb_bgp.withdraw_route(vip_route)

    # tear down BGP connection
    slb_bgp.stop_session()

    # clean ip config upon teardown
    ptfhost.shell("ip -6 route del %s/%s dev %s" % (local_addr, str(128), ptf_interface))
    ptfhost.shell("ip -6 neigh del %s lladdr %s dev %s" % (local_addr, router_mac, ptf_interface))
    ptfhost.shell("ip -6 addr del %s/%s dev %s" % (peer_addr, str(vlan_ipv6_subnet.prefixlen), ptf_interface))


@pytest.mark.parametrize("ip_version", ["IPv4", "IPv6"])
def test_vip_packet_decap(rand_selected_dut, ptfhost, ptfadapter, ip_version,
                          prepare_vlan_subnet_test_port, prepare_subnet_decap_config, request):
    duthost = rand_selected_dut
    ptf_src_port, downstream_port_ids, upstream_port_ids = prepare_vlan_subnet_test_port
    logger.info("Doing test with ptf_src_port: {}, downstream_port_ids: {}, upstream_port_ids: {}"
                .format(ptf_src_port, downstream_port_ids, upstream_port_ids))

    # setup BGP connection between SLB on PTF host and DUT
    if ip_version == "IPv4":
        neighbor_ip = request.getfixturevalue("setup_IPv4_SLB_connection")
    else:
        neighbor_ip = request.getfixturevalue("setup_IPv6_SLB_connection")

    # Verify that the specific VIP decap term is programmed. A broad VLAN
    # subnet term can decap overlapping traffic and hide VIP term failures.
    vip_route = get_vip_route(ip_version)
    subnet_decap_tunnel_name = get_subnet_decap_tunnel_name(ip_version)
    assert wait_until(30, 2, 0, is_vip_decap_term_programmed, duthost, ip_version, vip_route), \
        "VIP decap term TUNNEL_DECAP_TERM_TABLE|{}|{} is not programmed in STATE_DB".format(
            subnet_decap_tunnel_name, vip_route
        )

    # construct encapsulated packet and expected packet
    if ip_version == "IPv4":
        inner_packet = testutils.simple_ip_packet(
            eth_src=duthost.asic_instance().get_router_mac(),
            eth_dst=duthost.command("ip neigh show {}".format(neighbor_ip))['stdout'].split()[4],
            ip_src="1.1.1.1",
            ip_dst="2.2.2.2"
        )
        encapsulated_packet = testutils.simple_ipv4ip_packet(
            eth_dst=duthost.asic_instance().get_router_mac(),
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode(),
            ip_src="20.20.20.10",
            ip_dst=VIP_OUTER_DST_IP_V4,
            inner_frame=inner_packet[packet.IP]
        )
        expected_packet = inner_packet.copy()
        expected_packet[packet.IP].ttl -= 1

        exp_pkt = Mask(expected_packet)
        exp_pkt.set_do_not_care_packet(packet.Ether, "dst")
        exp_pkt.set_do_not_care_packet(packet.Ether, "src")
        exp_pkt.set_do_not_care_packet(packet.IP, "chksum")
    else:
        inner_packet = packet.Ether(dst=duthost.command("ip neigh show {}".format(neighbor_ip))['stdout'].split()[4],
                                    src=duthost.asic_instance().get_router_mac()) / packet.IPv6(
            src="1::1",
            dst="2::2",
        )
        encapsulated_packet = testutils.simple_ipv6ip_packet(
            eth_dst=duthost.asic_instance().get_router_mac(),
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode(),
            ipv6_src="fc01::10",
            ipv6_dst=VIP_OUTER_DST_IP_V6,
            inner_frame=inner_packet[packet.IPv6]
        )
        expected_packet = inner_packet.copy()
        expected_packet[packet.IPv6].hlim -= 1

        exp_pkt = expected_packet

    logger.info("Expected packet: {}".format(expected_packet.show(dump=True)))

    # run the traffic test
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_src_port, encapsulated_packet, count=10)
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, upstream_port_ids, timeout=30)


# Minimum expected MP2MP term scale to validate per address family on known platforms.
# This is the target scale for this test, not the hardware maximum (which varies by ASIC).
SUBNET_DECAP_SCALE_TARGET_BY_ASIC = {
    "mellanox": 64,
    "cisco-8000": 64,
    "broadcom": 64,
    "innovium": 64,
    "vs": 16,
}
SUBNET_DECAP_SCALE_TARGET_DEFAULT = 64

SCALE_V4_TERM_BASE = "10.100.0.0/24"
SCALE_V6_TERM_BASE = "fc0a:0::/64"

SCALE_V4_OUTER_SRC = "20.20.20.10"
SCALE_V6_OUTER_SRC = "fc01::10"

SCALE_V4_INNER_SRC = "1.1.1.1"
SCALE_V4_INNER_DST = "2.2.2.2"
SCALE_V6_INNER_SRC = "1::1"
SCALE_V6_INNER_DST = "2::2"

SCALE_V4_TUNNEL_NAME = "IPINIP_SUBNET"
SCALE_V6_TUNNEL_NAME = "IPINIP_SUBNET_V6"

SCALE_ECN_MODE = "copy_from_outer"
ASIC_TERM_ENTRY = "ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY"
ASIC_TUNNEL_TERM_DST_ADDR_FIELD = "SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_ADDR"
SCALE_TRAFFIC_TIMEOUT_SEC = 5


def _generate_term_prefixes(base_prefix, count):
    net = ipaddress.ip_network(base_prefix)
    base_addr = int(net.network_address)
    step = 1 << (net.max_prefixlen - net.prefixlen)
    return [str(ipaddress.ip_network((base_addr + i * step, net.prefixlen))) for i in range(count)]


def _outer_dst_from_prefix(prefix):
    net = ipaddress.ip_network(prefix)
    return str(net.network_address + 1)


def _get_subnet_decap_scale_target_per_af(duthost):
    asic_type = (duthost.facts.get('asic_type') or '').lower()
    return SUBNET_DECAP_SCALE_TARGET_BY_ASIC.get(asic_type, SUBNET_DECAP_SCALE_TARGET_DEFAULT)


def _count_appl_subnet_term_entries(duthost, tunnel_name):
    keys = redis_get_keys(
        duthost, 'APPL_DB', 'TUNNEL_DECAP_TERM_TABLE:{}:*'.format(tunnel_name)) or []
    return len(keys)


def _get_subnet_decap_scale_term_counts(duthost, tbinfo):
    topo = tbinfo["topo"]["type"]
    asic_type = (duthost.facts.get('asic_type') or '').lower()
    target_per_af = _get_subnet_decap_scale_target_per_af(duthost)
    baseline_v4 = _count_appl_subnet_term_entries(duthost, SCALE_V4_TUNNEL_NAME)
    baseline_v6 = _count_appl_subnet_term_entries(duthost, SCALE_V6_TUNNEL_NAME)

    assert baseline_v4 <= target_per_af and baseline_v6 <= target_per_af, (
        "APPL baseline exceeds scale target: v4 baseline {} / v6 baseline {} (target per AF {})".format(
            baseline_v4, baseline_v6, target_per_af)
    )

    v4_term_count = target_per_af - baseline_v4
    v6_term_count = target_per_af - baseline_v6
    logger.info(
        "Subnet decap scale term counts: asic='{}', topo='{}', target_per_af={}, "
        "baseline_v4={}, baseline_v6={}, v4_term_count={}, v6_term_count={}".format(
            asic_type, topo, target_per_af, baseline_v4, baseline_v6, v4_term_count, v6_term_count)
    )
    return {
        'v4_term_count': v4_term_count,
        'v6_term_count': v6_term_count,
        'expected_total_v4_appl': target_per_af,
        'expected_total_v6_appl': target_per_af,
    }


def _get_scale_term_prefixes(duthost, tbinfo):
    term_counts = _get_subnet_decap_scale_term_counts(duthost, tbinfo)
    return {
        'v4': _generate_term_prefixes(SCALE_V4_TERM_BASE, term_counts['v4_term_count']),
        'v6': _generate_term_prefixes(SCALE_V6_TERM_BASE, term_counts['v6_term_count']),
    }


def _classify_tunnel_term_af(attrs):
    dst_addr = attrs.get(ASIC_TUNNEL_TERM_DST_ADDR_FIELD, '')
    if dst_addr:
        try:
            return ipaddress.ip_address(dst_addr.split('/')[0]).version
        except ValueError:
            logger.debug("Failed to parse tunnel term dst addr '%s'", dst_addr)
    return 6 if "::" in " ".join(attrs.values()) else 4


def _build_scale_decap_config(term_prefixes, ttl_mode, dscp_mode, op):
    config = []
    tunnel_prefix_pairs = [
        (SCALE_V4_TUNNEL_NAME, term_prefixes['v4']),
        (SCALE_V6_TUNNEL_NAME, term_prefixes['v6']),
    ]

    if op == 'SET':
        for tunnel_name, prefixes in tunnel_prefix_pairs:
            config.append({
                "TUNNEL_DECAP_TABLE:{}".format(tunnel_name): {
                    "tunnel_type": "IPINIP",
                    "dscp_mode": dscp_mode,
                    "ecn_mode": SCALE_ECN_MODE,
                    "ttl_mode": ttl_mode,
                },
                "OP": op,
            })
            for prefix in prefixes:
                config.append({
                    "TUNNEL_DECAP_TERM_TABLE:{}:{}".format(tunnel_name, prefix): {
                        "term_type": "MP2MP",
                        "subnet_type": "vlan",
                    },
                    "OP": op,
                })
    else:
        # Only remove scale term entries. IPINIP_SUBNET tunnels are owned by the
        # baseline subnet decap setup and must remain for later tests/cleanup.
        for tunnel_name, prefixes in tunnel_prefix_pairs:
            for prefix in prefixes:
                config.append({
                    "TUNNEL_DECAP_TERM_TABLE:{}:{}".format(tunnel_name, prefix): {},
                    "OP": op,
                })

    return config


def _apply_scale_decap_config(duthost, config, op):
    """Apply scale decap config via the single swss instance (single-ASIC only)."""
    dest = '/tmp/decap_scale_{}.json'.format(op)
    duthost.copy(content=json.dumps(config, indent=2), dest=dest)
    swss = 'swss'
    cmds = [
        'docker cp {} {}:/decap_scale_{}.json'.format(dest, swss, op),
        'docker exec {} swssconfig /decap_scale_{}.json'.format(swss, op),
        'docker exec {} rm /decap_scale_{}.json'.format(swss, op),
    ]
    duthost.shell_cmds(cmds=cmds)
    duthost.shell('rm -f {}'.format(dest))


def _count_asic_term_entries_by_af(duthost):
    """Count tunnel term entries in the default ASIC_DB (single-ASIC only)."""
    cmd = "sonic-db-cli ASIC_DB keys '{}:*'".format(ASIC_TERM_ENTRY)
    keys = [line for line in duthost.shell(cmd, module_ignore_errors=True)['stdout_lines'] if line.strip()]
    v4 = v6 = 0
    for key in keys:
        raw = duthost.shell("sonic-db-cli ASIC_DB hgetall '{}'".format(key),
                            module_ignore_errors=True)['stdout']
        if not raw or "NULL" in raw:
            attrs = {}
        else:
            attrs = compose_dict_from_cli(raw)
        if _classify_tunnel_term_af(attrs) == 6:
            v6 += 1
        else:
            v4 += 1
    return len(keys), v4, v6


@pytest.fixture(scope='module')
def scale_term_prefixes(rand_selected_dut, prepare_subnet_decap_config, tbinfo):
    return _get_scale_term_prefixes(rand_selected_dut, tbinfo)


@pytest.fixture(scope='module')
def setup_scale_tunnels(request, rand_selected_dut, scale_term_prefixes, tbinfo,
                        supported_ttl_dscp_params, prepare_subnet_decap_config):
    duthost = rand_selected_dut
    ttl_mode = supported_ttl_dscp_params['ttl']
    dscp_mode = supported_ttl_dscp_params['dscp']
    term_counts = _get_subnet_decap_scale_term_counts(duthost, tbinfo)
    v4_terms_to_add = term_counts['v4_term_count']
    v6_terms_to_add = term_counts['v6_term_count']
    expected_total_v4_appl = term_counts['expected_total_v4_appl']
    expected_total_v6_appl = term_counts['expected_total_v6_appl']
    _, asic_baseline_v4, asic_baseline_v6 = _count_asic_term_entries_by_af(duthost)

    config = _build_scale_decap_config(scale_term_prefixes, ttl_mode, dscp_mode, 'SET')
    logger.info("Applying {} MP2MP subnet decap terms ({} IPv4 + {} IPv6)"
                .format(v4_terms_to_add + v6_terms_to_add, v4_terms_to_add, v6_terms_to_add))
    _apply_scale_decap_config(duthost, config, 'SET')

    def _remove_scale_config():
        logger.info("Removing scale subnet decap terms (preserving baseline tunnel objects)")
        del_config = _build_scale_decap_config(scale_term_prefixes, ttl_mode, dscp_mode, 'DEL')
        _apply_scale_decap_config(duthost, del_config, 'DEL')

    request.addfinalizer(_remove_scale_config)

    def _is_scale_programming_complete():
        _, asic_v4, asic_v6 = _count_asic_term_entries_by_af(duthost)
        v4_appl = _count_appl_subnet_term_entries(duthost, SCALE_V4_TUNNEL_NAME)
        v6_appl = _count_appl_subnet_term_entries(duthost, SCALE_V6_TUNNEL_NAME)
        return (v4_appl >= expected_total_v4_appl and v6_appl >= expected_total_v6_appl and
                (asic_v4 - asic_baseline_v4) >= v4_terms_to_add and
                (asic_v6 - asic_baseline_v6) >= v6_terms_to_add)

    wait_until(120, 5, 0, _is_scale_programming_complete)

    _, asic_v4, asic_v6 = _count_asic_term_entries_by_af(duthost)
    v4_appl = _count_appl_subnet_term_entries(duthost, SCALE_V4_TUNNEL_NAME)
    v6_appl = _count_appl_subnet_term_entries(duthost, SCALE_V6_TUNNEL_NAME)
    assert (
        v4_appl == expected_total_v4_appl and v6_appl == expected_total_v6_appl and
        (asic_v4 - asic_baseline_v4) == v4_terms_to_add and
        (asic_v6 - asic_baseline_v6) == v6_terms_to_add
    ), (
        "Scale subnet decap programming incomplete: APPL v4={} (expected {}), APPL v6={} (expected {}), "
        "ASIC v4 +{} (expected +{}), ASIC v6 +{} (expected +{})".format(
            v4_appl, expected_total_v4_appl,
            v6_appl, expected_total_v6_appl,
            asic_v4 - asic_baseline_v4, v4_terms_to_add,
            asic_v6 - asic_baseline_v6, v6_terms_to_add)
    )
    logger.info("Scale programming result: APPL v4={}, v6={}, ASIC v4 +{}, v6 +{}".format(
        v4_appl, v6_appl,
        asic_v4 - asic_baseline_v4, asic_v6 - asic_baseline_v6))


def _build_scale_encapsulated_packet(ptfadapter, duthost, ip_version, outer_dst):
    eth_dst = duthost.asic_instance().get_router_mac()
    eth_src = ptfadapter.dataplane.get_mac(*list(ptfadapter.dataplane.ports.keys())[0])
    if isinstance(eth_src, bytes):
        eth_src = eth_src.decode()

    if ip_version == "IPv4":
        inner = testutils.simple_ip_packet(ip_src=SCALE_V4_INNER_SRC, ip_dst=SCALE_V4_INNER_DST)[packet.IP]
        return testutils.simple_ipv4ip_packet(
            eth_dst=eth_dst, eth_src=eth_src,
            ip_src=SCALE_V4_OUTER_SRC, ip_dst=outer_dst,
            inner_frame=inner)
    else:
        inner = testutils.simple_tcpv6_packet(ipv6_src=SCALE_V6_INNER_SRC, ipv6_dst=SCALE_V6_INNER_DST)[packet.IPv6]
        return testutils.simple_ipv6ip_packet(
            eth_dst=eth_dst, eth_src=eth_src,
            ipv6_src=SCALE_V6_OUTER_SRC, ipv6_dst=outer_dst,
            inner_frame=inner)


@pytest.mark.stress_test
@pytest.mark.parametrize("ip_version", ["IPv4", "IPv6"])
def test_subnet_decap_tunnel_scale(rand_selected_dut, ptfadapter, ip_version, scale_term_prefixes,
                                   setup_scale_tunnels, prepare_vlan_subnet_test_port):
    duthost = rand_selected_dut
    ptf_src_port, _, upstream_port_ids = prepare_vlan_subnet_test_port

    state_keys = duthost.shell(
        'sonic-db-cli STATE_DB keys "*TUNNEL_DECAP_TABLE*IPINIP_SUBNET*"',
        module_ignore_errors=True)['stdout_lines']
    logger.info("STATE_DB subnet decap entries: {}".format(len(state_keys)))

    term_prefixes = scale_term_prefixes['v4'] if ip_version == "IPv4" else scale_term_prefixes['v6']
    for prefix in term_prefixes:
        outer_dst = _outer_dst_from_prefix(prefix)
        encapsulated_packet = _build_scale_encapsulated_packet(
            ptfadapter, duthost, ip_version, outer_dst)
        exp_pkt = build_expected_vlan_subnet_packet(
            encapsulated_packet, ip_version, "positive", decrease_ttl=True)

        verify_packet_with_expected(
            ptfadapter, "positive", encapsulated_packet, exp_pkt,
            ptf_src_port, recv_ports=upstream_port_ids, timeout=SCALE_TRAFFIC_TIMEOUT_SEC)
