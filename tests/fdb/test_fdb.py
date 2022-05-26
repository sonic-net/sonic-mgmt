
import pytest
import ptf.testutils as testutils
import ptf.packet as scapy
from ptf.mask import Mask

import time
import itertools
import logging
import pprint
import re
import random

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # lgtm[py/unused-import]
from tests.common.fixtures.duthost_utils import disable_fdb_aging
from tests.common.dualtor.mux_simulator_control import mux_server_url, toggle_all_simulator_ports_to_rand_selected_tor_m
from utils import fdb_cleanup, send_eth, send_arp_request, send_arp_reply, send_recv_eth

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.usefixtures('disable_fdb_aging')
]

DEFAULT_FDB_ETHERNET_TYPE = 0x1234
DUMMY_MAC_PREFIX = "02:11:22:33"
DUMMY_MAC_COUNT = 10
DUMMY_MAC_COUNT_SLIM = 2
FDB_POPULATE_SLEEP_TIMEOUT = 2
FDB_CLEAN_UP_SLEEP_TIMEOUT = 2
FDB_WAIT_EXPECTED_PACKET_TIMEOUT = 20
PKT_TYPES = ["ethernet", "arp_request", "arp_reply", "cleanup"]

logger = logging.getLogger(__name__)

@pytest.fixture(scope="module")
def get_dummay_mac_count(tbinfo):
    # t0-116 will take 90m with DUMMY_MAC_COUNT, so use DUMMY_MAC_COUNT_SLIM for t0-116 to reduce running time
    REQUIRED_TOPO = ["t0-116"]
    if tbinfo["topo"]["name"] in REQUIRED_TOPO:
        # To reduce the case running time
        logger.info("Use dummy mac count {} on topo {}\n".format(DUMMY_MAC_COUNT_SLIM, tbinfo["topo"]["name"]))
        return DUMMY_MAC_COUNT_SLIM
    else:
        logger.info("Use dummy mac count {} on topo {}\n".format(DUMMY_MAC_COUNT, tbinfo["topo"]["name"]))
        return DUMMY_MAC_COUNT

def simple_eth_packet(
    pktlen=60,
    eth_dst="00:01:02:03:04:05",
    eth_src="00:06:07:08:09:0a",
    vlan_vid=0,
    vlan_pcp=0
):
    pkt = scapy.Ether(dst=eth_dst, src=eth_src)
    if vlan_vid or vlan_pcp:
        pktlen += 4
        pkt /= scapy.Dot1Q(vlan=vlan_vid, prio=vlan_pcp)
        pkt[scapy.Dot1Q : 1].type = DEFAULT_FDB_ETHERNET_TYPE
    else:
        pkt.type = DEFAULT_FDB_ETHERNET_TYPE
    pkt = pkt / ("0" * (pktlen - len(pkt)))

    return pkt

def send_eth(ptfadapter, source_port, source_mac, dest_mac, vlan_id):
    """
    send ethernet packet
    :param ptfadapter: PTF adapter object
    :param source_port: source port
    :param source_mac: source MAC
    :param dest_mac: destination MAC
    :param vlan_id: VLAN id
    :return:
    """
    pkt = simple_eth_packet(
        eth_dst=dest_mac,
        eth_src=source_mac,
        vlan_vid=vlan_id
    )
    logger.debug('send packet source port id {} smac: {} dmac: {} vlan: {}'.format(source_port, source_mac, dest_mac, vlan_id))
    testutils.send(ptfadapter, source_port, pkt)


def send_arp_request(ptfadapter, source_port, source_mac, dest_mac, vlan_id):
    """
    send arp request packet
    :param ptfadapter: PTF adapter object
    :param source_port: source port
    :param source_mac: source MAC
    :param dest_mac: destination MAC
    :param vlan_id: VLAN id
    :return:
    """
    pkt = testutils.simple_arp_packet(pktlen=60,
                eth_dst=dest_mac,
                eth_src=source_mac,
                vlan_vid=vlan_id,
                vlan_pcp=0,
                arp_op=1,
                ip_snd='10.10.1.3',
                ip_tgt='10.10.1.2',
                hw_snd=source_mac,
                hw_tgt='ff:ff:ff:ff:ff:ff',
                )
    logger.debug('send ARP request packet source port id {} smac: {} dmac: {} vlan: {}'.format(source_port, source_mac, dest_mac, vlan_id))
    testutils.send(ptfadapter, source_port, pkt)

def send_arp_reply(ptfadapter, source_port, source_mac, dest_mac, vlan_id):
    """
    send arp reply packet
    :param ptfadapter: PTF adapter object
    :param source_port: source port
    :param source_mac: source MAC
    :param dest_mac: destination MAC
    :param vlan_id: VLAN id
    :return:
    """
    pkt = testutils.simple_arp_packet(eth_dst=dest_mac,
                eth_src=source_mac,
                vlan_vid=vlan_id,
                vlan_pcp=0,
                arp_op=2,
                ip_snd='10.10.1.2',
                ip_tgt='10.10.1.3',
                hw_tgt=dest_mac,
                hw_snd=source_mac,
                )
    logger.debug('send ARP reply packet source port id {} smac: {} dmac: {} vlan: {}'.format(source_port, source_mac, dest_mac, vlan_id))
    testutils.send(ptfadapter, source_port, pkt)


def send_recv_eth(duthost, ptfadapter, source_ports, source_mac, dest_ports, dest_mac, src_vlan, dst_vlan):
    """
    send ethernet packet and verify it on dest_port
    :param ptfadapter: PTF adapter object
    :param source_port: source port
    :param source_mac: source MAC
    :param dest_port: destination port to receive packet on
    :param dest_mac: destination MAC
    :param vlan_id: VLAN id
    :return:
    """
    pkt = simple_eth_packet(
        eth_dst=dest_mac,
        eth_src=source_mac,
        vlan_vid=src_vlan
    )
    exp_pkt = simple_eth_packet(
        eth_dst=dest_mac,
        eth_src=source_mac,
        vlan_vid=dst_vlan
    )
    if dst_vlan:
        # expect to receive tagged packet:
        # sonic device might modify the 802.1p field,
        # need to use Mask to ignore the priority field.
        exp_pkt = Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(scapy.Dot1Q, "prio")
    logger.debug('send packet src port {} smac: {} dmac: {} vlan: {} verifying on dst port {}'.format(
        source_ports, source_mac, dest_mac, src_vlan, dest_ports))

    # fdb test will send lots of pkts between paired ports, it's hard to guarantee there is no congestion
    # on server side during this period. So tolerant to retry 3 times before complain the assert.

    retry_count = 3
    pkt_count = 1
    for _ in range(retry_count):
        try:
            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, source_ports[0], pkt, count=pkt_count)
            if len(dest_ports) == 1:
                testutils.verify_packet(ptfadapter, exp_pkt, dest_ports[0], timeout=FDB_WAIT_EXPECTED_PACKET_TIMEOUT)
            else:
                testutils.verify_packet_any_port(ptfadapter, exp_pkt, dest_ports, timeout=FDB_WAIT_EXPECTED_PACKET_TIMEOUT)
            break
        except:
            # Send 10 pkts in retry to make this test case to be more tolerent of congestion on server/ptf
            pkt_count = 10
            pass
    else:
        result = duthost.command("show mac", module_ignore_errors=True)
        logger.info("Dest MAC is {}, show mac results {}".format(dest_mac, result['stdout']))
        pytest_assert(False, "Expected packet was not received on ports {}"
                             "Dest MAC in fdb is {}".format(dest_ports, dest_mac.lower() in result['stdout'].lower()))

def setup_fdb(ptfadapter, vlan_table, router_mac, pkt_type, dummy_mac_count):
    """
    :param ptfadapter: PTF adapter object
    :param vlan_table: VLAN table map: VLAN subnet -> list of VLAN members
    :return: FDB table map : VLAN member -> MAC addresses set
    """

    fdb = {}

    assert pkt_type in PKT_TYPES

    for vlan in vlan_table:
        for member in vlan_table[vlan]:
            if 'port_index' not in member or 'tagging_mode' not in member:
                continue
            # member['port_index'] is a list,
            # front panel port only has one member, and portchannel might have 0, 1 and multiple member ports,
            # portchannel might have no member ports or all member ports are down, so skip empty list
            if not member['port_index']:
                continue
            port_index = member['port_index'][0]
            vlan_id = vlan if member['tagging_mode'] == 'tagged' else 0
            mac = ptfadapter.dataplane.get_mac(0, port_index)
            # send a packet to switch to populate layer 2 table with MAC of PTF interface
            send_eth(ptfadapter, port_index, mac, router_mac, vlan_id)

            # put in learned MAC
            fdb[port_index] = { mac }

            # Send packets to switch to populate the layer 2 table with dummy MACs for each port
            # Totally 10 dummy MACs for each port, send 1 packet for each dummy MAC
            dummy_macs = ['{}:{:02x}:{:02x}'.format(DUMMY_MAC_PREFIX, port_index, i)
                          for i in range(dummy_mac_count)]

            for dummy_mac in dummy_macs:
                if pkt_type == "ethernet":
                    send_eth(ptfadapter, port_index, dummy_mac, router_mac, vlan_id)
                elif pkt_type == "arp_request":
                    send_arp_request(ptfadapter, port_index, dummy_mac, router_mac, vlan_id)
                elif pkt_type == "arp_reply":
                    send_arp_reply(ptfadapter, port_index, dummy_mac, router_mac, vlan_id)
                else:
                    pytest.fail("Unknown option '{}'".format(pkt_type))

            # put in set learned dummy MACs
            fdb[port_index].update(dummy_macs)

    time.sleep(FDB_POPULATE_SLEEP_TIMEOUT)
    # Flush dataplane
    ptfadapter.dataplane.flush()

    return fdb


def validate_mac(mac):
    if mac.find(':') != -1:
        pattern = re.compile(r"^([0-9a-fA-F]{2,2}:){5,5}[0-9a-fA-F]{2,2}$")
        if pattern.match(mac):
            return True
    return False


@pytest.fixture
def record_mux_status(request, rand_selected_dut, tbinfo):
    """
    A function level fixture to record mux cable status if test failed.
    """
    yield
    if request.node.rep_call.failed and 'dualtor' in tbinfo['topo']['name']:
        mux_status = rand_selected_dut.shell("show muxcable status", module_ignore_errors=True)['stdout']
        logger.warning("fdb test failed. Mux status are \n {}".format(mux_status))


@pytest.mark.bsl
@pytest.mark.parametrize("pkt_type", PKT_TYPES)
def test_fdb(ansible_adhoc, ptfadapter, duthosts, rand_one_dut_hostname, ptfhost, pkt_type,
             toggle_all_simulator_ports_to_rand_selected_tor_m, record_mux_status, get_dummay_mac_count):

    # Perform FDB clean up before each test and at the end of the final test
    fdb_cleanup(duthosts, rand_one_dut_hostname)
    if pkt_type == "cleanup":
        return

    """
    1. verify fdb forwarding.
    2. verify show mac command on DUT for learned mac.
    """
    duthost = duthosts[rand_one_dut_hostname]
    conf_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

    # reinitialize data plane due to above changes on PTF interfaces
    ptfadapter.reinit()

    router_mac = duthost.facts['router_mac']

    port_index_to_name = { v: k for k, v in conf_facts['port_index_map'].items() }

    configured_dummay_mac_count = get_dummay_mac_count
    # Only take interfaces that are in ptf topology
    ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")
    available_ports_idx = []
    for idx, name in ptf_ports_available_in_topo.items():
        if idx in port_index_to_name and conf_facts['PORT'][port_index_to_name[idx]].get('admin_status', 'down') == 'up':
            available_ports_idx.append(idx)

    vlan_table = {}
    interface_table = defaultdict(set)
    config_portchannels = conf_facts.get('PORTCHANNEL', {})

    for name, vlan in conf_facts['VLAN'].items():
        vlan_id = int(vlan['vlanid'])
        vlan_table[vlan_id] = []

        for ifname in conf_facts['VLAN_MEMBER'][name].keys():
            if 'tagging_mode' not in conf_facts['VLAN_MEMBER'][name][ifname]:
                continue
            tagging_mode = conf_facts['VLAN_MEMBER'][name][ifname]['tagging_mode']
            port_index = []
            if ifname in config_portchannels:
                for member in config_portchannels[ifname]['members']:
                    if conf_facts['port_index_map'][member] in available_ports_idx:
                        port_index.append(conf_facts['port_index_map'][member])
                if port_index:
                    interface_table[ifname].add(vlan_id)
            elif conf_facts['port_index_map'][ifname] in available_ports_idx:
                    port_index.append(conf_facts['port_index_map'][ifname])
                    interface_table[ifname].add(vlan_id)
            if port_index:
                vlan_table[vlan_id].append({'port_index':port_index, 'tagging_mode':tagging_mode})

    vlan_member_count = sum([ len(members) for members in vlan_table.values() ])

    fdb = setup_fdb(ptfadapter, vlan_table, router_mac, pkt_type, configured_dummay_mac_count)
    for vlan in vlan_table:
        for src, dst in itertools.combinations(vlan_table[vlan], 2):
            if 'port_index' not in src or 'tagging_mode' not in src:
                continue
            if 'port_index' not in dst or 'tagging_mode' not in dst:
                continue
            src_vlan = vlan if src['tagging_mode'] == 'tagged' else 0
            dst_vlan = vlan if dst['tagging_mode'] == 'tagged' else 0
            src_ports = src['port_index']
            dst_ports = dst['port_index']
            for src_mac, dst_mac in itertools.product(fdb[src_ports[0]], fdb[dst_ports[0]]):
                send_recv_eth(duthost, ptfadapter, src_ports, src_mac, dst_ports, dst_mac, src_vlan, dst_vlan)

    # Should we have fdb_facts ansible module for this test?
    fdb_fact = duthost.fdb_facts()['ansible_facts']
    logger.info('fdb facts on DUT:\n{}'.format(pprint.pformat(fdb_fact)))

    dummy_mac_count = 0
    total_mac_count = 0
    for k, vl in fdb_fact.items():
        assert validate_mac(k) == True
        for v in vl:
            assert v['port'] in interface_table
            assert v['vlan'] in interface_table[v['port']]
            assert v['type'] in ['Dynamic', 'Static']
            if DUMMY_MAC_PREFIX in k.lower():
                dummy_mac_count += 1
            if "dynamic" in v['type'].lower():
                total_mac_count += 1

    assert vlan_member_count > 0

    # Verify that the number of dummy MAC entries is expected
    assert dummy_mac_count == configured_dummay_mac_count * vlan_member_count


@pytest.mark.parametrize("pkt_type", PKT_TYPES)
def test_self_mac_not_learnt(ptfadapter, rand_selected_dut, pkt_type, toggle_all_simulator_ports_to_rand_selected_tor_m, tbinfo):
    """
    Verify self mac will not be learnt.
    """
    # Clear existing FDB entry from DUT
    rand_selected_dut.command('sonic-clear fdb all')
    # Sleep some time to ensure clear is done
    time.sleep(5)
    if pkt_type == "cleanup":
        return

    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    port_index = random.choice(list(mg_facts['minigraph_ptf_indices'].values()))
    self_mac = rand_selected_dut.facts['router_mac']
    dummy_mac = "00:22:33:44:33:22"
    if pkt_type == "ethernet":
        send_eth(ptfadapter, port_index, self_mac, dummy_mac, 0)
    elif pkt_type == "arp_request":
        send_arp_request(ptfadapter, port_index, self_mac, dummy_mac, 0)
    elif pkt_type == "arp_reply":
        send_arp_reply(ptfadapter, port_index, self_mac, dummy_mac, 0)
    # Sleep some time to ensure FDB is populate
    time.sleep(5)
    # Verify that self mac is not learnt
    fdb_facts = rand_selected_dut.fdb_facts()['ansible_facts']
    pytest_assert(self_mac not in fdb_facts,
                    "Self-mac {} is not supposed to be learnt".format(self_mac))
