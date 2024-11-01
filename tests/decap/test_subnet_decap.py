import pytest
import logging
import json
import time
import random
from collections import defaultdict

import ptf.packet as packet
import ptf.testutils as testutils
from ptf.mask import Mask
from tests.common.config_reload import config_reload
from tests.common.dualtor.dual_tor_utils import rand_selected_interface     # noqa F401
from tests.common.fixtures.ptfhost_utils import skip_traffic_test           # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py       # noqa F401
from tests.common.vxlan_ecmp_utils import Ecmp_Utils

ecmp_utils = Ecmp_Utils()
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1', 'dualtor')
]

SUBNET_DECAP_SRC_IP_V4 = "20.20.20.0/24"
SUBNET_DECAP_SRC_IP_V6 = "fc01::/120"
VLAN_SUBNET_OUTER_DST_IP_V4 = "192.168.0.200"
VLAN_SUBNET_OUTER_DST_IP_V6 = "fc02:1000::200"
VNET_ROUTE_IP_V4 = "40.40.40.0"
VNET_ROUTE_IP_V6 = "fc04::"


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
def prepare_vnet_vxlan_config(rand_selected_dut, tbinfo):
    logger.info("Prepare vnet vxlan config")
    minigraph_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)

    # Should I keep the temporary files copied to DUT?
    ecmp_utils.Constants['KEEP_TEMP_FILES'] = True

    # Is debugging going on, or is it a production run? If it is a
    # production run, use time-stamped file names for temp files.
    ecmp_utils.Constants['DEBUG'] = True

    # The host id in the ip addresses for DUT. It can be anything,
    # but helps to keep as a single number that is easy to identify
    # as DUT.
    ecmp_utils.Constants['DUT_HOSTID'] = 10

    data = {}
    for af in ['v4', 'v6']:
        if af == 'v4':
            vni_base = 1000
        elif af == 'v6':
            vni_base = 2000

        encap_type_data = {}
        encap_type_data['selected_interfaces'] = ecmp_utils.select_required_interfaces(
                rand_selected_dut,
                number_of_required_interfaces=1,
                minigraph_data=minigraph_facts,
                af=af)
        # To store the names of the tunnels, for every outer layer version.
        tunnel_names = {}
        # To track the vnets for every outer_layer_version.
        vnet_af_map = {}
        outer_layer_version = af

        tunnel_names[outer_layer_version] = ecmp_utils.create_vxlan_tunnel(
            rand_selected_dut,
            minigraph_data=minigraph_facts,
            af=outer_layer_version)

        payload_version = af
        encap_type = "{}_in_{}".format(payload_version, outer_layer_version)

        vnet_af_map[outer_layer_version] = ecmp_utils.create_vnets(
            rand_selected_dut,
            tunnel_name=tunnel_names[outer_layer_version],
            vnet_count=1,     # default scope can take only one vnet.
            vnet_name_prefix="Vnet_" + encap_type,
            scope="default",
            vni_base=vni_base)
        encap_type_data['vnet_vni_map'] = vnet_af_map[outer_layer_version]

        encap_type_data['vnet_intf_map'] = ecmp_utils.setup_vnet_intf(
            selected_interfaces=encap_type_data['selected_interfaces'],
            vnet_list=list(encap_type_data['vnet_vni_map'].keys()),
            minigraph_data=minigraph_facts)
        encap_type_data['intf_to_ip_map'] = ecmp_utils.assign_intf_ip_address(
            selected_interfaces=encap_type_data['selected_interfaces'],
            af=payload_version)
        encap_type_data['t2_ports'] = ecmp_utils.get_t2_ports(
            rand_selected_dut,
            minigraph_facts)
        encap_type_data['neighbor_config'] = ecmp_utils.configure_vnet_neighbors(
            rand_selected_dut,
            encap_type_data['intf_to_ip_map'],
            minigraph_data=minigraph_facts,
            af=payload_version)
        encap_type_data['dest_to_nh_map'] = ecmp_utils.create_vnet_routes(
            rand_selected_dut, list(encap_type_data['vnet_vni_map'].keys()),
            nhs_per_destination=1,
            number_of_available_nexthops=10,
            number_of_ecmp_nhs=10,
            dest_af=payload_version,
            dest_net_prefix=10,
            nexthop_prefix=10,
            nh_af=outer_layer_version)

        data[af] = encap_type_data

    yield data

    for af in data:
        encap_type_data = data[af]
        outer_layer_version = af
        payload_version = af

        ecmp_utils.set_routes_in_dut(
            rand_selected_dut,
            encap_type_data['dest_to_nh_map'],
            payload_version,
            "DEL")

        for intf in encap_type_data['selected_interfaces']:
            redis_string = "INTERFACE"
            if "PortChannel" in intf:
                redis_string = "PORTCHANNEL_INTERFACE"
            rand_selected_dut.shell("redis-cli -n 4 hdel \"{}|{}\""
                                    "vnet_name".format(redis_string, intf))
            rand_selected_dut.shell(
                "for i in `redis-cli -n 4 --scan --pattern \"NEIGH|{}|*\" `; "
                "do redis-cli -n 4 del $i ; done".format(intf))

        # This script's setup code re-uses same vnets for v4inv4 and v6inv4.
        # There will be same vnet in multiple encap types.
        # So remove vnets *after* removing the routes first.
        for vnet in list(data[encap_type]['vnet_vni_map'].keys()):
            rand_selected_dut.shell("redis-cli -n 4 del \"VNET|{}\"".format(vnet))

        time.sleep(5)
        for tunnel in list(tunnel_names.values()):
            rand_selected_dut.shell(
                "redis-cli -n 4 del \"VXLAN_TUNNEL|{}\"".format(tunnel))

        time.sleep(1)


@pytest.fixture(scope='module')
def prepare_test_ports(rand_selected_dut, tbinfo):
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    topo = tbinfo["topo"]["type"]

    downstream_ptf_port_ids = []
    upstream_ptf_port_ids = []
    for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        if (topo == "t1" and "T2" in neighbor["name"]) or (topo == "t0" and "T1" in neighbor["name"]):
            upstream_ptf_port_ids.append(port_id)
        elif (topo == "t0" and "Servers" in neighbor["name"]) or (topo == "t1" and "T0" in neighbor["name"]):
            downstream_ptf_port_ids.append(port_id)

    logger.info("downstream_ptf_port_ids: {}, upstream_ptf_port_ids: {}"
                .format(downstream_ptf_port_ids, upstream_ptf_port_ids))
    return downstream_ptf_port_ids, upstream_ptf_port_ids


@pytest.fixture(scope='module')
def prepare_negative_ip_port_map(prepare_test_ports):
    downstream_port_ids, _ = prepare_test_ports
    ptf_target_port = random.choice(downstream_port_ids)
    ip_to_port = {
        VLAN_SUBNET_OUTER_DST_IP_V4: ptf_target_port,
        VLAN_SUBNET_OUTER_DST_IP_V6: ptf_target_port
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
        outer_dst_ipv4 = VLAN_SUBNET_OUTER_DST_IP_V4
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
        outer_dst_ipv6 = VLAN_SUBNET_OUTER_DST_IP_V6
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


def build_expected_packet(encapsulated_packet, ip_version, stage="positive", decrease_ttl=False):
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


def build_encapsulated_vnet_route_packet(ptfadapter, rand_selected_dut, ip_version):
    eth_dst = rand_selected_dut.facts["router_mac"]
    eth_src = ptfadapter.dataplane.get_mac(0, 0)
    logger.info("eth_src: {}, eth_dst: {}".format(eth_src, eth_dst))

    if ip_version == "IPv4":
        inner_packet = testutils.simple_ip_packet(
            ip_src="1.1.1.1",
            ip_dst="2.2.2.2"
        )[packet.IP]
        outer_src_ipv4 = "20.20.20.10"
        outer_dst_ipv4 = "40.40.40.10"
        outer_packet = testutils.simple_vxlan_packet(
            eth_dst=eth_dst,
            eth_src=eth_src,
            ip_src=outer_src_ipv4,
            ip_dst=outer_dst_ipv4,
            vxlan_vni=1000,
            inner_frame=inner_packet
        )

    elif ip_version == "IPv6":
        inner_packet = testutils.simple_tcpv6_packet(
            ipv6_src="1::1",
            ipv6_dst="2::2"
        )[packet.IPv6]
        outer_src_ipv6 = "fc01::10"
        outer_dst_ipv6 = "fc04::10"
        outer_packet = testutils.simple_vxlanv6_packet(
            eth_dst=eth_dst,
            eth_src=eth_src,
            ipv6_src=outer_src_ipv6,
            ipv6_dst=outer_dst_ipv6,
            vxlan_vni=2000,
            inner_frame=inner_packet
        )

    return outer_packet


def verify_packet_with_expected(ptfadapter, pkt, exp_pkt, send_port,
                                recv_ports=[], recv_port=None, timeout=10, skip_traffic_test=False):    # noqa F811
    if skip_traffic_test is True:
        logger.info("Skip traffic test")
        return
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, send_port, pkt)
    if len(recv_ports) > 0:
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, recv_ports, timeout=10)
    elif recv_port is not None:
        testutils.verify_packet(ptfadapter, exp_pkt, recv_port, timeout=10)


@pytest.mark.parametrize("ip_version", ["IPv4", "IPv6"])
@pytest.mark.parametrize("stage", ["positive", "negative"])
def test_vlan_subnet_decap(request, rand_selected_dut, tbinfo, ptfhost, ptfadapter, ip_version, stage,
                           prepare_subnet_decap_config, prepare_test_ports,
                           prepare_negative_ip_port_map, setup_arp_responder, skip_traffic_test):     # noqa F811
    _, upstream_ptf_port_ids = prepare_test_ports
    ptf_src_port = random.choice(upstream_ptf_port_ids)

    encapsulated_packet = build_encapsulated_vlan_subnet_packet(ptfadapter, rand_selected_dut, ip_version, stage)
    exp_pkt = build_expected_packet(encapsulated_packet, ip_version, stage=stage, decrease_ttl=True)

    if stage == "negative":
        recv_ports = []
        ptf_target_port, _ = prepare_negative_ip_port_map
        request.getfixturevalue('setup_arp_responder')
    else:
        recv_ports = upstream_ptf_port_ids
        ptf_target_port = None

    verify_packet_with_expected(ptfadapter, encapsulated_packet, exp_pkt,
                                ptf_src_port, recv_ports=recv_ports, recv_port=ptf_target_port,
                                skip_traffic_test=skip_traffic_test)


@pytest.mark.parametrize("ip_version", ["IPv4", "IPv6"])
def test_vnet_route_decap(request, rand_selected_dut, tbinfo, ptfhost, ptfadapter, ip_version,
                          prepare_subnet_decap_config, prepare_vnet_vxlan_config,
                          prepare_test_ports, skip_traffic_test):     # noqa F811

    _, upstream_ptf_port_ids = prepare_test_ports
    ptf_src_port = random.choice(upstream_ptf_port_ids)
    encapsulated_packet = build_encapsulated_vnet_route_packet(ptfadapter, rand_selected_dut, ip_version)
    exp_pkt = build_expected_packet(encapsulated_packet, ip_version, decrease_ttl=True)
    recv_ports = upstream_ptf_port_ids
    verify_packet_with_expected(ptfadapter, encapsulated_packet, exp_pkt, ptf_src_port,
                                recv_ports=recv_ports, skip_traffic_test=skip_traffic_test)
