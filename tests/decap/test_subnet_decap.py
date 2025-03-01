import pytest
import logging
import json
import time
import random
import ipaddress
from collections import defaultdict

import ptf.packet as packet
import ptf.testutils as testutils
from ptf.mask import Mask
from tests.common.dualtor.dual_tor_utils import rand_selected_interface     # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py       # noqa F401
from tests.common.config_reload import config_reload
from tests.common.helpers.bgp import BGPNeighbor
from tests.common.helpers.generators import generate_ip_through_default_route, generate_ip_through_default_v6_route

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
    dut_port = list(mg_facts['minigraph_portchannels'].keys())[0]
    if not dut_port:
        pytest.skip('No portchannels found')
    dut_eth_port = mg_facts["minigraph_portchannels"][dut_port]["members"][0]
    ptf_src_port = mg_facts["minigraph_ptf_indices"][dut_eth_port]

    downstream_port_ids = []
    upstream_port_ids = []
    for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        if topo == "t0" and "Servers" in neighbor["name"]:
            downstream_port_ids.append(port_id)
        elif topo == "t0" and "T1" in neighbor["name"]:
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
    eth_dst = rand_selected_dut.facts["router_mac"]
    eth_src = ptfadapter.dataplane.get_mac(0, 0)
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
                                recv_ports=[], recv_port=None, timeout=10):    # noqa F811
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, send_port, pkt)
    if stage == "positive":
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, recv_ports, timeout=timeout)
    elif stage == "negative":
        testutils.verify_packet(ptfadapter, exp_pkt, recv_port, timeout=timeout)


@pytest.mark.parametrize("ip_version", ["IPv4", "IPv6"])
@pytest.mark.parametrize("stage", ["positive", "negative"])
def test_vlan_subnet_decap(request, rand_selected_dut, tbinfo, ptfhost, ptfadapter, ip_version, stage,
                           prepare_subnet_decap_config, prepare_vlan_subnet_test_port,
                           prepare_negative_ip_port_map, setup_arp_responder):     # noqa F811
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
def setup_v4_interface_pair(rand_selected_dut, ptfhost, prepare_vlan_subnet_test_port):
    duthost = rand_selected_dut
    peer_addr = generate_ip_through_default_route(duthost)
    assert peer_addr, "Failed to generate ip address for test"
    _, downstream_port_ids, _ = prepare_vlan_subnet_test_port

    # Get loopback4096 address
    cfg_facts = duthost.config_facts(source='persistent', asic_index='all')[0]['ansible_facts']
    if 'Loopback4096' in cfg_facts['LOOPBACK_INTERFACE']:
        lbs4096 = list(cfg_facts['LOOPBACK_INTERFACE']['Loopback4096'].keys())
        for lb4096 in lbs4096:
            lb4096intf = ipaddress.ip_interface(lb4096)
            if lb4096intf.ip.version == 4:
                if "/" in lb4096:
                    local_addr = lb4096.split("/")[0]
                    break
                else:
                    local_addr = lb4096

    # Assign peer addr to an interface on ptf
    logger.info("Generated peer address {}".format(peer_addr))
    peer_port = random.choice(downstream_port_ids)
    logger.info("Configured route to from PTF to LC on PTF port {}".format(peer_port))
    router_mac = duthost._get_router_mac()
    ptf_interface = "eth" + str(peer_port)
    ptfhost.shell("ip addr add {} dev {}".format(peer_addr + "/32", ptf_interface))
    ptfhost.shell("ip neigh add %s lladdr %s dev %s" % (local_addr, router_mac, ptf_interface))
    ptfhost.shell("ip route add %s dev %s" % (local_addr + "/32", ptf_interface))

    yield local_addr, peer_addr

    # clean ip config upon teardown
    ptfhost.shell("ip route del %s dev %s" % (local_addr + "/32", ptf_interface))
    ptfhost.shell("ip neigh del %s lladdr %s dev %s" % (local_addr, router_mac, ptf_interface))
    ptfhost.shell("ip addr del %s dev %s" % (peer_addr + "/32", ptf_interface))


@pytest.fixture
def setup_v6_interface_pair(rand_selected_dut, ptfhost, prepare_vlan_subnet_test_port):
    duthost = rand_selected_dut
    peer_addr = generate_ip_through_default_v6_route(duthost)
    assert peer_addr, "Failed to generate ip address for test"
    _, downstream_port_ids, _ = prepare_vlan_subnet_test_port

    # Get loopback4096 address
    cfg_facts = duthost.config_facts(source='persistent', asic_index='all')[0]['ansible_facts']
    if 'Loopback4096' in cfg_facts['LOOPBACK_INTERFACE']:
        lbs4096 = list(cfg_facts['LOOPBACK_INTERFACE']['Loopback4096'].keys())
        for lb4096 in lbs4096:
            lb4096intf = ipaddress.ip_interface(lb4096)
            if lb4096intf.ip.version == 6:
                if "/" in lb4096:
                    local_addr = lb4096.split("/")[0]
                    break
                else:
                    local_addr = lb4096

    # Assign peer addr to an interface on ptf
    logger.info("Generated peer address {}".format(peer_addr))
    peer_port = random.choice(downstream_port_ids)
    logger.info("Configured route to from PTF to LC on PTF port {}".format(peer_port))
    router_mac = duthost._get_router_mac()
    ptf_interface = "eth" + str(peer_port)
    ptfhost.shell("ip -6 addr add {} dev {}".format(peer_addr + "/128", ptf_interface))
    ptfhost.shell("ip neigh add %s lladdr %s dev %s" % (local_addr, router_mac, ptf_interface))
    ptfhost.shell("ip -6 route add %s dev %s" % (local_addr + "/128", ptf_interface))

    yield local_addr, peer_addr

    # clean ip config upon teardown
    ptfhost.shell("ip -6 route del %s dev %s" % (local_addr + "/128", ptf_interface))
    ptfhost.shell("ip -6 neigh del %s lladdr %s dev %s" % (local_addr, router_mac, ptf_interface))
    ptfhost.shell("ip -6 addr del %s dev %s" % (peer_addr + "/128", ptf_interface))


def setup_SLB_connection(duthost, ptfhost, ip_version, dut_ip, neighbor_ip):
    dut_asn = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']['minigraph_bgp_asn']
    slb_bgp = BGPNeighbor(duthost, ptfhost, "slb", neighbor_ip, 65534,
                          dut_ip, dut_asn, port=179)
    slb_bgp.start_session()
    return slb_bgp


@pytest.mark.parametrize("ip_version,setup_interface_pair",
                         [("IPv4", setup_v4_interface_pair), ("IPv6", setup_v6_interface_pair)])
def test_vip_packet_decap(rand_selected_dut, ptfhost, ptfadapter, ip_version, prepare_subnet_decap_config,
                          prepare_vlan_subnet_test_port, setup_interface_pair):
    duthost = rand_selected_dut
    ptf_src_port, downstream_port_ids, _ = prepare_vlan_subnet_test_port

    # setup BGP connection between SLB on PTF host and DUT
    local_addr, peer_addr = setup_interface_pair
    slb_bgp = setup_SLB_connection(duthost, ptfhost, ip_version, local_addr, peer_addr)

    # announce the VIP route on SLB
    vip_route = {
        "prefix": "192.168.1.0/24" if ip_version == "IPv4" else "fc02:2000::/120",
        "nexthop": peer_addr,
        "aspath": "{}".format(slb_bgp.asn)
    }
    slb_bgp.announce_route(vip_route)

    # TODO: verify that STATE_DB gets programmed

    # construct encapsulated packet and expected packet
    inner_packet = testutils.simple_ip_packet(
        ip_src="1.1.1.1",
        ip_dst="2.2.2.2"
    )
    if ip_version == "IPv4":
        encapsulated_packet = testutils.simple_ipv4ip_packet(
            eth_dst=duthost._get_router_mac(),
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode(),
            ip_src="20.20.20.10",
            ip_dst="192.168.1.1",
            inner_frame=inner_packet[packet.IP]
        )
    else:
        encapsulated_packet = testutils.simple_ipv6ip_packet(
            eth_dst=duthost._get_router_mac(),
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port).decode(),
            ip_src="fc01::10",
            ip_dst="fc02:2000::1",
            inner_frame=inner_packet[packet.IP]
        )
    expected_packet = Mask(inner_packet)
    expected_packet.set_do_not_care_packet(packet.Ether, "dst")
    expected_packet.set_do_not_care_packet(packet.Ether, "src")
    expected_packet.set_do_not_care_packet(packet.IP, "chksum")

    # run the traffic test
    verify_packet_with_expected(ptfadapter, "positive", encapsulated_packet, expected_packet,
                                ptf_src_port, recv_ports=downstream_port_ids)

    # withdraw the VIP route
    slb_bgp.withdraw_route(vip_route)

    # tear down BGP connection
    slb_bgp.teardown_session()
