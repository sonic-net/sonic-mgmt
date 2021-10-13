
import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask

import itertools
import logging
import ipaddress
import pprint

from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # lgtm[py/unused-import]

from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # lgtm[py/unused-import]

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't0-56-po2vlan')
]

DUMMY_MAC_PREFIX = "02:11:22:33"
DUMMY_IP_PREFIX = "192.168"
DUMMY_ARP_COUNT = 10

@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']


@pytest.fixture(scope="module")
def vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, cfg_facts):
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    vlan_ports_list = []
    config_ports = {k: v for k,v in cfg_facts['PORT'].items() if v.get('admin_status', 'down') == 'up'}
    config_portchannels = cfg_facts.get('PORTCHANNEL', {})
    config_port_indices = {k: v for k, v in mg_facts['minigraph_ptf_indices'].items() if k in config_ports}
    ptf_ports_available_in_topo = {port_index: 'eth{}'.format(port_index) for port_index in config_port_indices.values()}
    config_port_channel_members = [port_channel['members'] for port_channel in config_portchannels.values()]
    config_port_channel_member_ports = list(itertools.chain.from_iterable(config_port_channel_members))
    config_ports_vlan = defaultdict(list)
    vlan_members = cfg_facts.get('VLAN_MEMBER', {})
    # key is dev name, value is list for configured VLAN member.
    for k, v in cfg_facts['VLAN'].items():
        vlanid = v['vlanid']
        for addr in cfg_facts['VLAN_INTERFACE']['Vlan'+vlanid]:
            # address could be IPV6 and IPV4, only need IPV4 here
            if addr.find(':') == -1:
                ip = addr
                break
        else:
            continue
        for port in v['members']:
            if k in vlan_members and port in vlan_members[k]:
                if 'tagging_mode' not in vlan_members[k][port]:
                    continue
                mode = vlan_members[k][port]['tagging_mode']
                config_ports_vlan[port].append({'vlanid':int(vlanid), 'ip':ip, 'tagging_mode':mode})

    if config_portchannels:
        portchannel_cnt = 0
        for po in config_portchannels:
            vlan_port = {
                'dev' : po,
                'port_index' : [config_port_indices[member] for member in config_portchannels[po]['members']],
                'permit_vlanid' : []
            }
            if po in config_ports_vlan:
                vlan_port['pvid'] = 0
                for vlan in config_ports_vlan[po]:
                    if 'vlanid' not in vlan or 'ip' not in vlan or 'tagging_mode' not in vlan:
                        continue
                    if vlan['tagging_mode'] == 'untagged':
                        vlan_port['pvid'] = vlan['vlanid']
                    vlan_port['permit_vlanid'].append(vlan['vlanid'])
            if 'pvid' in vlan_port:
                vlan_ports_list.append(vlan_port)

    ports = [port for port in config_ports
        if config_port_indices[port] in ptf_ports_available_in_topo
        and config_ports[port].get('admin_status', 'down') == 'up'
        and port not in config_port_channel_member_ports]

    for i, port in enumerate(ports):
        vlan_port = {
            'dev' : port,
            'port_index' : [config_port_indices[port]],
            'permit_vlanid' : []
        }
        if port in config_ports_vlan:
            vlan_port['pvid'] = 0
            for vlan in config_ports_vlan[port]:
                if 'vlanid' not in vlan or 'ip' not in vlan or 'tagging_mode' not in vlan:
                    continue
                if vlan['tagging_mode'] == 'untagged':
                    vlan_port['pvid'] = vlan['vlanid']
                vlan_port['permit_vlanid'].append(vlan['vlanid'])
        if 'pvid' in vlan_port:
            vlan_ports_list.append(vlan_port)

    return vlan_ports_list


def enable_arp(duthost, cfg_facts, enable):
    vlan_members = cfg_facts.get('VLAN_MEMBER', {})
    on_cmd = "echo 1 > /proc/sys/net/ipv4/conf/%s/arp_accept"
    off_cmd = "echo 0 > /proc/sys/net/ipv4/conf/%s/arp_accept"
    for vlan in vlan_members.keys():
        if enable:
            logger.info("Enable ARP for %s" % vlan)
            duthost.shell(on_cmd % vlan)
        else:
            logger.info("Disable ARP for %s" % vlan)
            duthost.shell(off_cmd % vlan)


def arp_cleanup(duthost):
    """ cleanup ARP entry """
    duthost.command('sonic-clear arp')


@pytest.fixture(scope="module", autouse=True)
def setup_arp(duthosts, rand_one_dut_hostname, cfg_facts):
    duthost = duthosts[rand_one_dut_hostname]
    # --------------------- Setup -----------------------
    try:
        enable_arp(duthost, cfg_facts, True)
    # --------------------- Testing -----------------------
        yield
    # --------------------- Teardown -----------------------
    finally:
        enable_arp(duthost, cfg_facts, False)
        arp_cleanup(duthost)


def build_arp_packet(vlan_id, neighbor_mac, neighbor_ip):

    pkt = testutils.simple_arp_packet(pktlen=60 if vlan_id == 0 else 64,
            eth_dst='ff:ff:ff:ff:ff:ff',
            eth_src=neighbor_mac,
            vlan_vid=vlan_id,
            arp_op=2,
            hw_snd=neighbor_mac,
            ip_snd=neighbor_ip,
            ip_tgt=neighbor_ip)
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


def verify_arp_packets(ptfadapter, vlan_ports_list, vlan_port, vlan_id, untagged_pkt, masked_tagged_pkt):
    untagged_dst_ports = []
    tagged_dst_ports = []
    untagged_dst_pc_ports = []
    tagged_dst_pc_ports = []
    logger.info("Verify packets from ports " + str(vlan_port["port_index"][0]))
    for port in vlan_ports_list:
        if vlan_port["port_index"] == port["port_index"]:
            # Skip src port
            continue
        if port["pvid"] == vlan_id:
            if len(port["port_index"]) > 1:
                untagged_dst_pc_ports.append(port["port_index"])
            else:
                untagged_dst_ports += port["port_index"]
        elif vlan_id in map(int, port["permit_vlanid"]):
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
def test_tagged_arp_pkt(ptfadapter, vlan_ports_list, duthosts, rand_one_dut_hostname, toggle_all_simulator_ports_to_rand_selected_tor):
    """
    Send tagged GARP packets from each port.
    Verify packets egress without tag from ports whose PVID same with ingress port.
    Verify packets egress with tag from ports who include VLAN ID but PVID different from ingress port.
    verify show arp command on DUT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    for vlan_port in vlan_ports_list:
        port_index = vlan_port["port_index"][0]
        # Send GARP packets to switch to populate the arp table with dummy MACs for each port
        # Totally 10 dummy MACs for each port, send 1 packet for each dummy MAC
        dummy_macs = ['{}:{:02x}:{:02x}'.format(DUMMY_MAC_PREFIX, port_index, i+1)
                      for i in range(DUMMY_ARP_COUNT)]
        dummy_ips = ['{}.{:d}.{:d}'.format(DUMMY_IP_PREFIX, port_index, i+1)
                      for i in range(DUMMY_ARP_COUNT)]
        for permit_vlanid in map(int, vlan_port["permit_vlanid"]):
            logger.info('Test ARP: interface %s, VLAN %u' % (vlan_port["dev"], permit_vlanid))
            # Perform ARP clean up
            arp_cleanup(duthost)
            for i in range(DUMMY_ARP_COUNT):
                pkt = build_arp_packet(permit_vlanid, dummy_macs[i], dummy_ips[i])
                exp_untagged_pkt = build_arp_packet(0, dummy_macs[i], dummy_ips[i])
                # vlan priority attached to packets is determined by the port, so we ignore it here
                exp_tagged_pkt = Mask(pkt)
                exp_tagged_pkt.set_do_not_care_scapy(scapy.Dot1Q, "prio")
                logger.info("Send tagged({}) packet from {} ...".format(permit_vlanid, port_index))
                testutils.send(ptfadapter, port_index, pkt)
                verify_arp_packets(ptfadapter, vlan_ports_list, vlan_port, permit_vlanid, exp_untagged_pkt, exp_tagged_pkt)

            res = duthost.command('show arp')
            assert res['rc'] == 0
            logger.info('"show arp" output on DUT:\n{}'.format(pprint.pformat(res['stdout_lines'])))

            for l in res['stdout_lines']:
                # Address MacAddress Iface Vlan
                items = l.split()
                if len(items) != 4:
                    continue
                # Vlan must be number
                if not items[3].isdigit():
                    continue
                ip = items[0]
                mac = items[1]
                ifname = items[2]
                vlan_id = int(items[3])
                assert ip in dummy_ips
                assert mac in dummy_macs
                assert ifname == vlan_port["dev"]
                assert vlan_id == permit_vlanid
