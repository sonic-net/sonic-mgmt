
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

vlan_id_list = [ 100, 200 ]

pytestmark = [
    pytest.mark.topology('t0')
]

# Use original ports intead of sub interfaces for ptfadapter if it's t0-backend
PTF_PORT_MAPPING_MODE = "use_orig_interface"


@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']


@pytest.fixture(scope="module")
def vlan_intfs_list():
    return [ { 'vlan_id': vlan, 'ip': '192.168.{}.1/24'.format(vlan) } for vlan in vlan_id_list  ]


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
    pvid_cycle = itertools.cycle(vlan_id_list)
    # when running on t0 we can use the portchannel members
    if config_portchannels:
        for po in config_portchannels.keys()[:2]:
            port = config_portchannels[po]['members'][0]
            vlan_ports_list.append({
                'dev' : po,
                'port_index' : [config_port_indices[member] for member in config_portchannels[po]['members']],
                'pvid' : pvid_cycle.next(),
                'permit_vlanid' : { vid : {
                    'peer_ip' : '192.168.{}.{}'.format(vid, 2 + config_port_indices.keys().index(port)),
                    'remote_ip' : '{}.1.1.{}'.format(vid, 2 + config_port_indices.keys().index(port))
                    } for vid in vlan_id_list }
            })

    ports = [port for port in config_ports
        if config_port_indices[port] in ptf_ports_available_in_topo
        and config_ports[port].get('admin_status', 'down') == 'up'
        and port not in config_port_channel_member_ports]

    for port in ports[:4]:
        vlan_ports_list.append({
            'dev' : port,
            'port_index' : [config_port_indices[port]],
            'pvid' : pvid_cycle.next(),
            'permit_vlanid' : { vid : {
                'peer_ip' : '192.168.{}.{}'.format(vid, 2 + config_port_indices.keys().index(port)),
                'remote_ip' : '{}.1.1.{}'.format(vid, 2 + config_port_indices.keys().index(port))
                } for vid in vlan_id_list }
        })

    return vlan_ports_list


def create_vlan_interfaces(vlan_ports_list, ptfhost):
    logger.info("Create PTF VLAN intfs")
    for vlan_port in vlan_ports_list:
        for permit_vlanid in vlan_port["permit_vlanid"].keys():
            if int(permit_vlanid) != vlan_port["pvid"]:

                ptfhost.command("ip link add link eth{idx} name eth{idx}.{pvid} type vlan id {pvid}".format(
                   idx=vlan_port["port_index"][0],
                   pvid=permit_vlanid
                ))

                ptfhost.command("ip link set eth{idx}.{pvid} up".format(
                   idx=vlan_port["port_index"][0],
                   pvid=permit_vlanid
                ))

def shutdown_portchannels(duthost, portchannel_interfaces):
    cmds = []
    logger.info("Shutdown lags, flush IP addresses")
    for portchannel, ips in portchannel_interfaces.items():
        cmds.append('config interface shutdown {}'.format(portchannel))
        for ip in ips:
            cmds.append('config interface ip remove {} {}'.format(portchannel, ip))

    duthost.shell_cmds(cmds=cmds)

def create_test_vlans(duthost, cfg_facts, vlan_ports_list, vlan_intfs_list):
    cmds = []
    logger.info("Add vlans, assign IPs")
    for vlan in vlan_intfs_list:
        cmds.append('config vlan add {}'.format(vlan['vlan_id']))
        cmds.append("config interface ip add Vlan{} {}".format(vlan['vlan_id'], vlan['ip'].upper()))

    # Delete untagged vlans from interfaces to avoid error message
    # when adding untagged vlan to interface that already have one
    if '201911' not in duthost.os_version:
        logger.info("Delete untagged vlans from interfaces")
        for vlan_port in vlan_ports_list:
            vlan_members = cfg_facts.get('VLAN_MEMBER', {})
            vlan_name, vid = vlan_members.keys()[0], vlan_members.keys()[0].replace("Vlan", '')
            try:
                if vlan_members[vlan_name][vlan_port['dev']]['tagging_mode'] == 'untagged':
                    cmds.append("config vlan member del {} {}".format(vid, vlan_port['dev']))
            except KeyError:
                continue

    logger.info("Add members to Vlans")
    for vlan_port in vlan_ports_list:
        for permit_vlanid in vlan_port['permit_vlanid'].keys():
            cmds.append('config vlan member add {tagged} {id} {port}'.format(
                tagged=('--untagged' if vlan_port['pvid'] == permit_vlanid else ''),
                id=permit_vlanid,
                port=vlan_port['dev']
            ))

    duthost.shell_cmds(cmds=cmds)

def startup_portchannels(duthost, portchannel_interfaces):
    cmds  =[]
    logger.info("Bringup lags")
    for portchannel in portchannel_interfaces:
        cmds.append('config interface startup {}'.format(portchannel))

    duthost.shell_cmds(cmds=cmds)

def add_test_routes(duthost, vlan_ports_list):
    cmds = []
    logger.info("Configure route for remote IP")
    for item in vlan_ports_list:
        for i in vlan_ports_list[0]['permit_vlanid']:
            cmds.append('ip route add {} via {}'.format(
                item['permit_vlanid'][i]['remote_ip'],
                item['permit_vlanid'][i]['peer_ip']
                ))

    duthost.shell_cmds(cmds=cmds)


@pytest.fixture(scope="module", autouse=True)
def setup_vlan(duthosts, rand_one_dut_hostname, ptfhost, vlan_ports_list, vlan_intfs_list, cfg_facts):
    duthost = duthosts[rand_one_dut_hostname]
    # --------------------- Setup -----------------------
    try:
        portchannel_interfaces = cfg_facts.get('PORTCHANNEL_INTERFACE', {})

        shutdown_portchannels(duthost, portchannel_interfaces)

        create_vlan_interfaces(vlan_ports_list, ptfhost)

        setUpArpResponder(vlan_ports_list, ptfhost)

        create_test_vlans(duthost, cfg_facts, vlan_ports_list, vlan_intfs_list)

        startup_portchannels(duthost, portchannel_interfaces)
        add_test_routes(duthost, vlan_ports_list)
    # --------------------- Testing -----------------------
        yield
    # --------------------- Teardown -----------------------
    finally:
        tearDown(vlan_ports_list, duthost, ptfhost)


def tearDown(vlan_ports_list, duthost, ptfhost):

    logger.info("VLAN test ending ...")
    logger.info("Stop arp_responder")
    ptfhost.command('supervisorctl stop arp_responder')

    logger.info("Delete VLAN intf")
    for vlan_port in vlan_ports_list:
        for permit_vlanid in vlan_port["permit_vlanid"].keys():
            if int(permit_vlanid) != vlan_port["pvid"]:
                try:
                    ptfhost.command("ip link delete eth{idx}.{pvid}".format(
                    idx=vlan_port["port_index"][0],
                    pvid=permit_vlanid
                    ))
                except RunAnsibleModuleFail as e:
                    logger.error(e)

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
                # iface = "eth{}.{}".format(vlan_port["port_index"][0], permit_vlanid)
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


def build_qinq_packet(outer_vlan_id, vlan_id,
                      src_mac="00:22:00:00:00:02", dst_mac="ff:ff:ff:ff:ff:ff",
                      src_ip="192.168.0.1", dst_ip="192.168.0.2", ttl=64):
    pkt = testutils.simple_qinq_tcp_packet(eth_dst=dst_mac,
                             eth_src=src_mac,
                             dl_vlan_outer=outer_vlan_id,
                             vlan_vid=vlan_id,
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
def test_vlan_tc1_send_untagged(ptfadapter, vlan_ports_list, toggle_all_simulator_ports_to_rand_selected_tor):
    """
    Test case #1
    Verify packets egress without tag from ports whose PVID same with ingress port
    Verify packets egress with tag from ports who include VLAN ID but PVID different from ingress port.
    """

    logger.info("Test case #1 starting ...")

    for vlan_port in vlan_ports_list:
        pkt = build_icmp_packet(0)
        logger.info("Send untagged packet from {} ...".format(vlan_port["port_index"][0]))
        logger.info(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
        testutils.send(ptfadapter, vlan_port["port_index"][0], pkt)
        verify_icmp_packets(ptfadapter, vlan_ports_list, vlan_port, vlan_port["pvid"])


@pytest.mark.bsl
def test_vlan_tc2_send_tagged(ptfadapter, vlan_ports_list, toggle_all_simulator_ports_to_rand_selected_tor):
    """
    Test case #2
    Send tagged packets from each port.
    Verify packets egress without tag from ports whose PVID same with ingress port
    Verify packets egress with tag from ports who include VLAN ID but PVID different from ingress port.
    """

    logger.info("Test case #2 starting ...")

    for vlan_port in vlan_ports_list:
        for permit_vlanid in map(int, vlan_port["permit_vlanid"].keys()):
            pkt = build_icmp_packet(permit_vlanid)
            logger.info("Send tagged({}) packet from {} ...".format(permit_vlanid, vlan_port["port_index"][0]))
            logger.info(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
            testutils.send(ptfadapter, vlan_port["port_index"][0], pkt)
            verify_icmp_packets(ptfadapter, vlan_ports_list, vlan_port, permit_vlanid)


@pytest.mark.bsl
def test_vlan_tc3_send_invalid_vid(ptfadapter, vlan_ports_list, toggle_all_simulator_ports_to_rand_selected_tor):
    """
    Test case #3
    Send packets with invalid VLAN ID
    Verify no port can receive these packets
    """

    logger.info("Test case #3 starting ...")

    invalid_tagged_pkt = build_icmp_packet(4095)
    masked_invalid_tagged_pkt = Mask(invalid_tagged_pkt)
    masked_invalid_tagged_pkt.set_do_not_care_scapy(scapy.Dot1Q, "vlan")
    for vlan_port in vlan_ports_list:
        dst_ports = []
        src_port = vlan_port["port_index"][0]
        dst_ports += [port["port_index"] for port in vlan_ports_list
                                if port != vlan_port ]
        logger.info("Send invalid tagged packet " + " from " + str(src_port) + "...")
        logger.info(invalid_tagged_pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
        testutils.send(ptfadapter, src_port, invalid_tagged_pkt)
        logger.info("Check on " + str(dst_ports) + "...")
        testutils.verify_no_packet_any(ptfadapter, masked_invalid_tagged_pkt, dst_ports)


@pytest.mark.bsl
def test_vlan_tc4_tagged_non_broadcast(ptfadapter, vlan_ports_list, toggle_all_simulator_ports_to_rand_selected_tor):
    """
    Test case #4
    Send packets w/ src and dst specified over tagged ports in vlan
    Verify that bidirectional communication between two tagged ports work
    """
    vlan_ids = vlan_ports_list[0]['permit_vlanid'].keys()
    tagged_test_vlan = vlan_ids[0]

    ports_for_test = []

    for vlan_port in vlan_ports_list:
        if vlan_port['pvid'] != tagged_test_vlan:
            ports_for_test.append(vlan_port['port_index'])

    #take two tagged ports for test
    src_port = ports_for_test[0]
    dst_port = ports_for_test[-1]

    src_mac = ptfadapter.dataplane.get_mac(0, src_port[0])
    dst_mac = ptfadapter.dataplane.get_mac(0, dst_port[0])

    transmit_tagged_pkt = build_icmp_packet(vlan_id=tagged_test_vlan, src_mac=src_mac, dst_mac=dst_mac)
    return_transmit_tagged_pkt = build_icmp_packet(vlan_id=tagged_test_vlan, src_mac=dst_mac, dst_mac=src_mac)

    logger.info("Tagged packet to be sent from port {} to port {}".format(src_port[0], dst_port))

    testutils.send(ptfadapter, src_port[0], transmit_tagged_pkt)

    try:
        testutils.verify_packets_any(ptfadapter, transmit_tagged_pkt, ports=dst_port)
    except Exception as detail:
        if "Did not receive expected packet on any of ports" in str(detail):
            logger.error("Expected packet was not received")
        raise

    logger.info("One Way Tagged Packet Transmission Works")
    logger.info("Tagged packet successfully sent from port {} to port {}".format(src_port[0], dst_port))

    logger.info("Tagged packet to be sent from port {} to port {}".format(dst_port[0], src_port))

    testutils.send(ptfadapter, dst_port[0], return_transmit_tagged_pkt)

    try:
        testutils.verify_packets_any(ptfadapter, return_transmit_tagged_pkt, ports=src_port)
    except Exception as detail:
        if "Did not receive expected packet on any of ports" in str(detail):
            logger.error("Expected packet was not received")
        raise

    logger.info("Two Way Tagged Packet Transmission Works")
    logger.info("Tagged packet successfully sent from port {} to port {}".format(dst_port[0], src_port))


@pytest.mark.bsl
def test_vlan_tc5_untagged_non_broadcast(ptfadapter, vlan_ports_list, toggle_all_simulator_ports_to_rand_selected_tor):
    """
    Test case #5
    Send packets w/ src and dst specified over untagged ports in vlan
    Verify that bidirectional communication between two untagged ports work
    """
    vlan_ids = vlan_ports_list[0]['permit_vlanid'].keys()
    tagged_test_vlan = vlan_ids[0]

    ports_for_test = []

    for vlan_port in vlan_ports_list:
        if vlan_port['pvid'] != tagged_test_vlan:
            ports_for_test.append(vlan_port['port_index'])

    #take two tagged ports for test
    src_port = ports_for_test[0]
    dst_port = ports_for_test[-1]

    src_mac = ptfadapter.dataplane.get_mac(0, src_port[0])
    dst_mac = ptfadapter.dataplane.get_mac(0, dst_port[0])

    transmit_untagged_pkt = build_icmp_packet(vlan_id=0, src_mac=src_mac, dst_mac=dst_mac)
    return_transmit_untagged_pkt = build_icmp_packet(vlan_id=0, src_mac=dst_mac, dst_mac=src_mac)

    logger.info("Untagged packet to be sent from port {} to port {}".format(src_port[0], dst_port))

    testutils.send(ptfadapter, src_port[0], transmit_untagged_pkt)

    try:
        testutils.verify_packets_any(ptfadapter, transmit_untagged_pkt, ports=dst_port)
    except Exception as detail:
        if "Did not receive expected packet on any of ports" in str(detail):
            logger.error("Expected packet was not received")
        raise

    logger.info("One Way Untagged Packet Transmission Works")
    logger.info("Untagged packet successfully sent from port {} to port {}".format(src_port[0], dst_port))

    logger.info("Untagged packet to be sent from port {} to port {}".format(dst_port[0], src_port))

    testutils.send(ptfadapter, dst_port[0], return_transmit_untagged_pkt)

    try:
        testutils.verify_packets_any(ptfadapter, return_transmit_untagged_pkt, ports=src_port)
    except Exception as detail:
        if "Did not receive expected packet on any of ports" in str(detail):
            logger.error("Expected packet was not received")
        raise

    logger.info("Two Way Untagged Packet Transmission Works")
    logger.info("Untagged packet successfully sent from port {} to port {}".format(dst_port[0], src_port))


def test_vlan_tc6_tagged_qinq_switch_on_outer_tag(ptfadapter, vlan_ports_list, duthost, toggle_all_simulator_ports_to_rand_selected_tor):
    """
    Test case #6
    Send qinq packets w/ src and dst specified over tagged ports in vlan
    Verify that the qinq packet is switched based on outer vlan tag + src/dst mac
    """

    # Add more supported platforms to the list as they are tested
    qinq_switching_supported_platforms = ['mellanox', 'barefoot']
    if duthost.facts["asic_type"] not in qinq_switching_supported_platforms:
        pytest.skip("Unsupported platform")

    vlan_ids = vlan_ports_list[0]['permit_vlanid'].keys()
    tagged_test_vlan = vlan_ids[0]

    ports_for_test = []
    for vlan_port in vlan_ports_list:
        if vlan_port['pvid'] != tagged_test_vlan:
            ports_for_test.append(vlan_port['port_index'][0])

    #take two tagged ports for test
    src_port = ports_for_test[0]
    dst_port = ports_for_test[-1]

    src_mac = ptfadapter.dataplane.get_mac(0, src_port)
    dst_mac = ptfadapter.dataplane.get_mac(0, dst_port)

    transmit_qinq_pkt = build_qinq_packet(outer_vlan_id=tagged_test_vlan, vlan_id=250, src_mac=src_mac, dst_mac=dst_mac)
    logger.info ("QinQ packet to be sent from port {} to port {}".format(src_port, dst_port))
    testutils.send(ptfadapter, src_port, transmit_qinq_pkt)

    testutils.verify_packet(ptfadapter, transmit_qinq_pkt, dst_port)
    logger.info ("QinQ packet switching worked successfully...")