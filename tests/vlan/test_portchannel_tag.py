
import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask
from collections import defaultdict

import json
import itertools
import logging

from tests.common.errors import RunAnsibleModuleFail
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py       # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # lgtm[py/unused-import]

from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # lgtm[py/unused-import]

from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('topo_t0-56-po2vlan')
]


@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']


@pytest.fixture(scope="module")
def vlan_ports_list(rand_selected_dut, tbinfo, cfg_facts):
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    vlan_ports_list = []
    config_ports = {k: v for k,v in cfg_facts['PORT'].items() if v.get('admin_status', 'down') == 'up'}
    config_portchannels = cfg_facts.get('PORTCHANNEL', {})
    config_port_indices = {k: v for k, v in mg_facts['minigraph_ptf_indices'].items() if k in config_ports}
    ptf_ports_available_in_topo = {port_index: 'eth{}'.format(port_index) for port_index in config_port_indices.values()}
    config_port_channel_members = [port_channel[1]['members'] for port_channel in config_portchannels.items()]
    config_port_channel_member_ports = list(itertools.chain.from_iterable(config_port_channel_members))
    config_ports_vlan = defaultdict(list)
    for k, v in cfg_facts['VLAN'].items():
        for port in v['members']:
            vlanid = v['vlanid']
            for addr in cfg_facts['VLAN_INTERFACE']['Vlan'+vlanid]:
                if addr.find(':') == -1:
                    ip = addr
                    break
            else:
                continue
            config_ports_vlan[port].append((int(vlanid), ip))
    # when running on t0 we can use the portchannel members
    if config_portchannels:
        for po in config_portchannels.keys():
            if po not in config_ports_vlan:
                continue
            port = config_portchannels[po]['members'][0]
            vlan_ports_list.append({
                'dev' : po,
                'port_index' : [config_port_indices[member] for member in config_portchannels[po]['members']],
                'pvid' : config_ports_vlan[po][0][0] if len(config_ports_vlan[po]) == 1 else 0,
                'permit_vlanid' : { item[0] : {
                    'peer_ip' : '{}.{}'.format('.'.join(item[1].split('.')[:3]), 2 + config_port_indices.keys().index(port)),
                    'remote_ip' : '{}.1.1.{}'.format(item[0]&255, 2 + config_port_indices.keys().index(port))
                    } for item in config_ports_vlan[po] }
            })

    ports = [port for port in config_ports
        if config_port_indices[port] in ptf_ports_available_in_topo
        and config_ports[port].get('admin_status', 'down') == 'up'
        and port not in config_port_channel_member_ports]

    for port in ports:
        if port not in config_ports_vlan:
            continue
        vlan_ports_list.append({
            'dev' : port,
            'port_index' : [config_port_indices[port]],
            'pvid' : config_ports_vlan[port][0][0] if len(config_ports_vlan[port]) == 1 else 0,
            'permit_vlanid' : { item[0] : {
                    'peer_ip' : '{}.{}'.format('.'.join(item[1].split('.')[:3]), 2 + config_port_indices.keys().index(port)),
                    'remote_ip' : '{}.1.1.{}'.format(item[0]&255, 2 + config_port_indices.keys().index(port))
                } for item in config_ports_vlan[port] }
        })
    return vlan_ports_list


@pytest.fixture(scope="module", autouse=True)
def setup_vlan(duthosts, rand_one_dut_hostname, ptfhost, vlan_ports_list, cfg_facts):
    duthost = duthosts[rand_one_dut_hostname]
    # --------------------- Setup -----------------------
    try:
        setUpArpResponder(vlan_ports_list, ptfhost)
    # --------------------- Testing -----------------------
        yield
    # --------------------- Teardown -----------------------
    finally:
        tearDown(duthost, ptfhost)


def tearDown(duthost, ptfhost):
    logger.info("Stop arp_responder")
    ptfhost.command('supervisorctl stop arp_responder')

    config_reload(duthost)


def setUpArpResponder(vlan_ports_list, ptfhost):
    logger.info("Copy arp_responder to ptfhost")
    d = defaultdict(list)
    for vlan_port in vlan_ports_list:
        for permit_vlanid in vlan_port["permit_vlanid"].keys():
            if int(permit_vlanid) == vlan_port["pvid"]:
                iface = "eth{}".format(vlan_port["port_index"][0])
            else:
                iface = "eth{}".format(vlan_port["port_index"][0])
            d[iface].append(vlan_port["permit_vlanid"][permit_vlanid]["peer_ip"])

    with open('/tmp/from_t1.json', 'w') as file:
        json.dump(d, file)
    ptfhost.copy(src='/tmp/from_t1.json', dest='/tmp/from_t1.json')

    extra_vars = {
            'arp_responder_args': ''
    }

    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    ptfhost.template(src='templates/arp_responder.conf.j2', dest='/tmp')
    ptfhost.command("cp /tmp/arp_responder.conf.j2 /etc/supervisor/conf.d/arp_responder.conf")

    ptfhost.command('supervisorctl reread')
    ptfhost.command('supervisorctl update')

    logger.info("Start arp_responder")
    ptfhost.command('supervisorctl start arp_responder')


def build_icmp_packet(vlan_id, src_mac="00:22:00:00:00:02", dst_mac="ff:ff:ff:ff:ff:ff",
                        src_ip="192.168.0.1", dst_ip="192.168.0.2", ttl=64):

    pkt = testutils.simple_icmp_packet(pktlen=100 if vlan_id == 0 else 104,
                                eth_dst=dst_mac,
                                eth_src=src_mac,
                                dl_vlan_enable=False if vlan_id == 0 else True,
                                vlan_vid=vlan_id,
                                vlan_pcp=0,
                                ip_src=src_ip,
                                ip_dst=dst_ip,
                                ip_ttl=ttl)
    return pkt


def verify_packets_with_portchannel(test, pkt, ports=[], portchannel_ports=[], device_number=0, timeout=1):
    for port in ports:
        result = testutils.dp_poll(test, device_number=device_number, port_number=port,
                                   timeout=timeout, exp_pkt=pkt)
        if isinstance(result, test.dataplane.PollFailure):
            test.fail("Expected packet was not received on device %d, port %r.\n%s"
                    % (device_number, port, result.format()))

    for port_group in portchannel_ports:
        for port in port_group:
            result = testutils.dp_poll(test, device_number=device_number, port_number=port,
                                       timeout=timeout, exp_pkt=pkt)
            if isinstance(result, test.dataplane.PollSuccess):
                break
        else:
            test.fail("Expected packet was not received on device %d, ports %s.\n"
                    % (device_number, str(port_group)))


def verify_icmp_packets(ptfadapter, vlan_ports_list, vlan_port, vlan_id):
    untagged_pkt = build_icmp_packet(0)
    tagged_pkt = build_icmp_packet(vlan_id)
    untagged_dst_ports = []
    tagged_dst_ports = []
    untagged_dst_pc_ports = []
    tagged_dst_pc_ports = []
    # vlan priority attached to packets is determined by the port, so we ignore it here
    masked_tagged_pkt = Mask(tagged_pkt)
    masked_tagged_pkt.set_do_not_care_scapy(scapy.Dot1Q, "prio")

    logger.info("Verify untagged packets from ports " + str(vlan_port["port_index"][0]))
    for port in vlan_ports_list:
        if vlan_port["port_index"] == port["port_index"]:
            # Skip src port
            continue
        if port["pvid"] == vlan_id:
            if len(port["port_index"]) > 1:
                untagged_dst_pc_ports.append(port["port_index"])
            else:
                untagged_dst_ports += port["port_index"]
        elif vlan_id in map(int, port["permit_vlanid"].keys()):
            if len(port["port_index"]) > 1:
                tagged_dst_pc_ports.append(port["port_index"])
            else:
                tagged_dst_ports += port["port_index"]

    verify_packets_with_portchannel(test=ptfadapter,
                                    pkt=untagged_pkt,
                                    ports=untagged_dst_ports,
                                    portchannel_ports=untagged_dst_pc_ports)
    verify_packets_with_portchannel(test=ptfadapter,
                                    pkt=masked_tagged_pkt,
                                    ports=tagged_dst_ports,
                                    portchannel_ports=tagged_dst_pc_ports)


@pytest.mark.bsl
def test_vlan_tc1_send_untagged_broadcast(ptfadapter, vlan_ports_list, toggle_all_simulator_ports_to_rand_selected_tor):
    """
    Test case #1
    Verify untagged broadcast packet send from tagged port
    """
    for vlan_port in vlan_ports_list:
        if vlan_port['pvid'] != 0:
            continue
        pkt = build_icmp_packet(0)
        exp_pkt = build_icmp_packet(0)
        dst_ports = []
        for port in vlan_ports_list:
            dst_ports += port["port_index"] if port != vlan_port else []
        for po in vlan_port["port_index"]:
            logger.info("Send untagged packet from {}-{}...".format(vlan_port["dev"], po))
            logger.info(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
            testutils.send(ptfadapter, po, pkt)
            testutils.verify_no_packet_any(ptfadapter, exp_pkt, dst_ports)


@pytest.mark.bsl
def test_vlan_tc2_send_untagged_broadcast(ptfadapter, vlan_ports_list, toggle_all_simulator_ports_to_rand_selected_tor):
    """
    Test case #2
    Verify untagged broadcast packet send from untagged port
    """
    for vlan_port in vlan_ports_list:
        if vlan_port['pvid'] == 0:
            continue
        pkt = build_icmp_packet(vlan_port['pvid'])
        for po in vlan_port["port_index"]:
            logger.info("Send untagged packet from {}-{}...".format(vlan_port["dev"], po))
            logger.info(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
            testutils.send(ptfadapter, po, pkt)
            verify_icmp_packets(ptfadapter, vlan_ports_list, vlan_port, vlan_port["pvid"])


@pytest.mark.bsl
def test_vlan_tc3_send_tagged_broadcast(ptfadapter, vlan_ports_list, toggle_all_simulator_ports_to_rand_selected_tor):
    """
    Test case #3
    Verify tagged broadcast packet send from tagged port
    """
    for vlan_port in vlan_ports_list:
        if vlan_port['pvid'] != 0:
            continue
        for vid in vlan_port['permit_vlanid']:
            pkt = build_icmp_packet(vid)
            for po in vlan_port["port_index"]:
                logger.info("Send tagged packet {} from {}-{}...".format(vid, vlan_port["dev"], po))
                logger.info(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
                testutils.send(ptfadapter, po, pkt)
                verify_icmp_packets(ptfadapter, vlan_ports_list, vlan_port, vid)


@pytest.mark.bsl
def test_vlan_tc4_send_tagged_broadcast(ptfadapter, vlan_ports_list, toggle_all_simulator_ports_to_rand_selected_tor):
    """
    Test case #4
    Verify tagged broadcast packet send from untagged port
    """
    for vlan_port in vlan_ports_list:
        if vlan_port['pvid'] == 0:
            continue
        pkt = build_icmp_packet(vlan_port['pvid'])
        for po in vlan_port["port_index"]:
            logger.info("Send tagged packet {} from {}-{}...".format(vlan_port['pvid'], vlan_port["dev"], po))
            logger.info(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
            testutils.send(ptfadapter, po, pkt)
            verify_icmp_packets(ptfadapter, vlan_ports_list, vlan_port, vlan_port['pvid'])


@pytest.mark.bsl
def test_vlan_tc5_unicast(ptfadapter, vlan_ports_list, toggle_all_simulator_ports_to_rand_selected_tor):
    """
    Test case #5
    Send unicast packets from tagged port to untagged port
    Verify that bidirectional communication work
    """
    tagged_ports_list = []
    untagged_ports_list = []
    for vlan_port in vlan_ports_list:
        if vlan_port['pvid'] != 0:
            untagged_ports_list.append(vlan_port)
        else:
            tagged_ports_list.append(vlan_port)

    for tagged_port in tagged_ports_list:
        for untagged_port in untagged_ports_list:
            if untagged_port['pvid'] not in tagged_port['permit_vlanid']:
                continue
            tagged_test_vlan = untagged_port['pvid']
            src_port = tagged_port['port_index']
            dst_port = untagged_port['port_index']
            src_mac = ptfadapter.dataplane.get_mac(0, src_port[0])
            dst_mac = ptfadapter.dataplane.get_mac(0, dst_port[0])
            tagged_to_untagged_pkt = build_icmp_packet(vlan_id=tagged_test_vlan, src_mac=src_mac, dst_mac=dst_mac)
            tagged_to_untagged_exp_pkt = build_icmp_packet(vlan_id=0, src_mac=src_mac, dst_mac=dst_mac)
            untagged_to_tagged_pkt = build_icmp_packet(vlan_id=0, src_mac=dst_mac, dst_mac=src_mac)
            untagged_to_tagged_exp_pkt = build_icmp_packet(vlan_id=tagged_test_vlan, src_mac=dst_mac, dst_mac=src_mac)

            logger.info("Tagged packet {} to be sent from port {} to port {}".format(tagged_test_vlan, src_port[0], dst_port))
            testutils.send(ptfadapter, src_port[0], tagged_to_untagged_pkt)
            try:
                testutils.verify_packets_any(ptfadapter, tagged_to_untagged_exp_pkt, ports=dst_port)
            except Exception as detail:
                if "Did not receive expected packet on any of ports" in str(detail):
                    logger.error("Expected packet was not received")
                raise

            logger.info("Untagged packet to be sent from port {} to port {}".format(dst_port[0], src_port))
            testutils.send(ptfadapter, dst_port[0], untagged_to_tagged_pkt)
            try:
                testutils.verify_packets_any(ptfadapter, untagged_to_tagged_exp_pkt, ports=src_port)
            except Exception as detail:
                if "Did not receive expected packet on any of ports" in str(detail):
                    logger.error("Expected packet was not received")
                raise
