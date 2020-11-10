
import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask
from collections import defaultdict

import time
import json
import itertools
import logging
import pprint

from tests.common.errors import RunAnsibleModuleFail
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py       # lgtm[py/unused-import]

logger = logging.getLogger(__name__)

vlan_id_list = [ 100, 200 ]

pytestmark = [
    pytest.mark.topology('t0')
]

@pytest.fixture(scope="module")
def cfg_facts(duthost):
    return duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

@pytest.fixture(scope="module")
def vlan_intfs_list():
    return [ { 'vlan_id': vlan, 'ip': '192.168.{}.1/24'.format(vlan) } for vlan in vlan_id_list  ]

@pytest.fixture(scope="module")
def vlan_ports_list(cfg_facts, ptfhost):
    vlan_ports_list = []
    config_ports = cfg_facts['PORT']
    config_portchannels = cfg_facts.get('PORTCHANNEL', {})
    config_port_indices = cfg_facts['port_index_map']
    ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")

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


def create_vlan_interfaces(vlan_ports_list, vlan_intfs_list, duthost, ptfhost):
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


@pytest.fixture(scope="module", autouse=True)
def setup_vlan(ptfadapter, duthost, ptfhost, vlan_ports_list, vlan_intfs_list, cfg_facts):

    # --------------------- Setup -----------------------
    try:
        # Generate vlan info
        portchannel_interfaces = cfg_facts.get('PORTCHANNEL_INTERFACE', {})

        logger.info("Shutdown lags, flush IP addresses")
        for portchannel, ips in portchannel_interfaces.items():
            duthost.command('config interface shutdown {}'.format(portchannel))
            for ip in ips:
                duthost.command('config interface ip remove {} {}'.format(portchannel, ip))

        # Wait some time for route, neighbor, next hop groups to be removed,
        # otherwise PortChannel RIFs are still referenced and won't be removed
        time.sleep(90)

        logger.info("Add vlans, assign IPs")
        for vlan in vlan_intfs_list:
            duthost.command('config vlan add {}'.format(vlan['vlan_id']))
            duthost.command("config interface ip add Vlan{} {}".format(vlan['vlan_id'], vlan['ip'].upper()))

        logger.info("Add members to Vlans")
        for vlan_port in vlan_ports_list:
            for permit_vlanid in vlan_port['permit_vlanid'].keys():
                duthost.command('config vlan member add {tagged} {id} {port}'.format(
                    tagged=('--untagged' if vlan_port['pvid'] == permit_vlanid else ''),
                    id=permit_vlanid,
                    port=vlan_port['dev']
                ))

        # Make sure config applied
        time.sleep(30)

        logger.info("Bringup lags")
        for portchannel in portchannel_interfaces:
            duthost.command('config interface startup {}'.format(portchannel))

        # Make sure config applied
        time.sleep(30)

        logger.info("Create VLAN intf")
        create_vlan_interfaces(vlan_ports_list, vlan_intfs_list, duthost, ptfhost)

        logger.info("Configure route for remote IP")
        for item in vlan_ports_list:
            for i in vlan_ports_list[0]['permit_vlanid']:
                duthost.command('ip route add {} via {}'.format(
                    item['permit_vlanid'][i]['remote_ip'],
                    item['permit_vlanid'][i]['peer_ip']
                    ))

        logger.info("Copy arp_responder to ptfhost")

        setUpArpResponder(vlan_ports_list, ptfhost)

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

        time.sleep(10)

    # --------------------- Testing -----------------------
        yield
    # --------------------- Teardown -----------------------
    finally:
        tearDown(vlan_ports_list, duthost, ptfhost, vlan_intfs_list, portchannel_interfaces)


def tearDown(vlan_ports_list, duthost, ptfhost, vlan_intfs_list, portchannel_interfaces):

    logger.info("VLAN test ending ...")
    logger.info("Stop arp_responder")
    ptfhost.command('supervisorctl stop arp_responder')

    logger.info("Delete VLAN intf")
    try:
        for item in vlan_ports_list:
            for i in vlan_ports_list[0]['permit_vlanid']:
                duthost.command('ip route flush {}'.format(
                    item['permit_vlanid'][i]['remote_ip']))

        for vlan_port in vlan_ports_list:
            for permit_vlanid in vlan_port["permit_vlanid"].keys():
                if int(permit_vlanid) != vlan_port["pvid"]:
                    ptfhost.command("ip link delete eth{idx}.{pvid}".format(
                    idx=vlan_port["port_index"][0],
                    pvid=permit_vlanid
                    ))
    except RunAnsibleModuleFail as e:
        logger.error(e)

    duthost.shell("config reload -y &>/dev/null", executable="/bin/bash")

    # make sure Portchannels go up for post-test link sanity
    time.sleep(90)


def setUpArpResponder(vlan_ports_list, ptfhost):
    d = defaultdict(list)
    for vlan_port in vlan_ports_list:
        for permit_vlanid in vlan_port["permit_vlanid"].keys():
            if int(permit_vlanid) == vlan_port["pvid"]:
                iface = "eth{}".format(vlan_port["port_index"][0])
            else:
                iface = "eth{}.{}".format(vlan_port["port_index"][0], permit_vlanid)
            d[iface].append(vlan_port["permit_vlanid"][permit_vlanid]["peer_ip"])

    with open('/tmp/from_t1.json', 'w') as file:
        json.dump(d, file)
    ptfhost.copy(src='/tmp/from_t1.json', dest='/tmp/from_t1.json')

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
def test_vlan_tc1_send_untagged(ptfadapter, vlan_ports_list):
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
def test_vlan_tc2_send_tagged(ptfadapter, vlan_ports_list):
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
def test_vlan_tc3_send_invalid_vid(ptfadapter, vlan_ports_list):
    """
    Test case #3
    Send packets with invalid VLAN ID
    Verify no port can receive these pacekts
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
