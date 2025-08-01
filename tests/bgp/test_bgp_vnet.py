import sys
import time
from copy import deepcopy
import json
import logging
import traceback
import yaml

from natsort import natsorted
import pytest

from tests.common.reboot import reboot
from tests.common.storage_backend.backend_utils import skip_test_module_over_backend_topologies     # noqa F401
import ptf.testutils as testutils
from ptf.mask import Mask
from scapy.all import IP, Ether

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer
]

logger = logging.getLogger(__name__)

# global variables
g_vars = {}

TEMPLATE_CONFIGS = {
    "vnet_dynamic_peer_add": {
        "BGP_PEER_RANGE": {
            "Vnet2|BGPSLBPassive": {
                "ip_range": ["10.0.0.60/31", "10.0.0.62/31"],
                "peer_asn": "64600",
                "src_address": "10.0.0.60",
                "name": "BGPSLBPassive"
            }
        }
    },
    "vnet_dynamic_peer_del": {
        "BGP_PEER_RANGE": {
            "Vnet2|BGPSLBPassive": {
                "ip_range": ["10.0.0.60/31"],
                "peer_asn": "64600",
                "src_address": "10.0.0.60",
                "name": "BGPSLBPassive"
            }
        }
    }
}


# helper functions
def get_vlan_members(vlan_name, cfg_facts):
    tmp_member_list = []

    for m in list(cfg_facts['VLAN_MEMBER'].keys()):
        v, port = m.split('|')
        if vlan_name == v:
            tmp_member_list.append(port)

    return natsorted(tmp_member_list)


def get_cfg_facts(duthost):
    # return config db contents(running-config)
    tmp_facts = json.loads(duthost.shell(
        "sonic-cfggen -d --print-data")['stdout'])

    port_name_list_sorted = natsorted(list(tmp_facts['PORT'].keys()))
    port_index_map = {}
    for idx, val in enumerate(port_name_list_sorted):
        port_index_map[val] = idx

    tmp_facts['config_port_indices'] = port_index_map

    return tmp_facts


def setup_vnet_cfg(duthost, localhost, cfg_facts):
    '''
    setup vrf configuration on dut before test suite
    '''

    cfg_t0 = deepcopy(cfg_facts)

    cfg_t0.pop('config_port_indices', None)

    # get members from Vlan1000, and move half of them to Vlan2000 in vrf basic cfg
    ports = get_vlan_members('Vlan1000', cfg_facts)

    vlan_ports = {'Vlan1000': ports[:len(ports)//2],
                  'Vlan2000': ports[len(ports)//2:]}

    extra_vars = {'cfg_t0': cfg_t0,
                  'vlan_ports': vlan_ports}

    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)

    duthost.template(src="bgp/templates/vnet_config_db.j2",
                     dest="/tmp/config_db_vnet.json")
    duthost.shell("cp /tmp/config_db_vnet.json /etc/sonic/config_db.json")

    reboot(duthost, localhost)


# fixtures
@pytest.fixture(scope="module")
def dut_facts(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.facts


@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return get_cfg_facts(duthost)


def restore_config_db(localhost, duthost):
    # In case something went wrong in previous reboot, wait until the DUT is accessible to ensure that
    # the `mv /etc/sonic/config_db.json.bak /etc/sonic/config_db.json` is executed on DUT.
    # If the DUT is still inaccessible after timeout, we may have already lose the DUT. Something sad happened.
    localhost.wait_for(host=g_vars["dut_ip"],
                       port=22,
                       state='started',
                       search_regex='OpenSSH_[\\w\\.]+ Debian',
                       timeout=180)   # Similiar approach to increase the chance that the next line get executed.
    duthost.shell("mv /etc/sonic/config_db.json.bak /etc/sonic/config_db.json")
    reboot(duthost, localhost)


@pytest.fixture(scope="module", autouse=True)
def setup_vnet(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, localhost,
              skip_test_module_over_backend_topologies):        # noqa F811
    duthost = duthosts[rand_one_dut_hostname]

    # backup config_db.json
    duthost.shell("cp /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")

    # Setup global variables
    global g_vars

    try:
        # Setup dut
        g_vars["dut_ip"] = duthost.host.options["inventory_manager"].get_host(
            duthost.hostname).vars["ansible_host"]
        # Don't care about 'pmon' and 'lldp' here
        duthost.critical_services = [
            "swss", "syncd", "database", "teamd", "bgp"]
        cfg_t0 = get_cfg_facts(duthost)  # generate cfg_facts for t0 topo

        setup_vnet_cfg(duthost, localhost, cfg_t0)

        duthost.shell("sonic-clear arp")
        duthost.shell("sonic-clear nd")
        duthost.shell("sonic-clear fdb all")

        with open("../ansible/vars/topo_{}.yml".format(tbinfo['topo']['name']), 'r') as fh:
            g_vars['topo_properties'] = yaml.safe_load(fh)

        g_vars['props'] = g_vars['topo_properties']['configuration_properties']['common']

    except Exception as e:
        # Ensure that config_db is restored.
        # If exception is raised in setup, the teardown code won't be executed. That's why we need to capture
        # exception and do cleanup here in setup part (code before 'yield').
        logger.error("Exception raised in setup: {}".format(repr(e)))
        logger.error(json.dumps(
            traceback.format_exception(*sys.exc_info()), indent=2))

        restore_config_db(localhost, duthost)

        # Setup failed. There is no point to continue running the cases.
        # If this line is hit, script execution will stop here
        pytest.fail("Vnet testing setup failed")

    # --------------------- Testing -----------------------
    yield

    # --------------------- Teardown -----------------------
    restore_config_db(localhost, duthost)


@pytest.fixture(scope="module")
def mg_facts(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    return mg_facts


def validate_state_db_entry(duthost, peer, vnet, dynamic_peer):
    '''
    Validate the entry for a given peer in the state db.
    '''
    if dynamic_peer:
        peer_config_db_key = "BGP_PEER_RANGE" + "|" + vnet + "|" + peer
    else:
        peer_config_db_key = "BGP_NEIGHBOR" + "|" + vnet + "|" + peer
    peer_state_db_key = "BGP_PEER_CONFIGURED_TABLE" + "|" + vnet + "|" + peer
    expected_state = duthost.shell(
        'redis-cli -n 4 --json HGETALL "{}"'.format(str(peer_config_db_key)))['stdout']
    expected_state = json.loads(expected_state)
    if isinstance(expected_state, dict):
        expected_state = {k.rstrip('@'): v for k, v in expected_state.items()}
    peer_state = duthost.shell(
        'redis-cli -n 6 --json HGETALL "{}"'.format(str(peer_state_db_key)))['stdout']
    peer_state = json.loads(peer_state)
    assert peer_state == expected_state, \
        "Peer {} vnet {} state in state db is not {}. Found {}".format(peer, vnet, expected_state, peer_state)


def get_bgp_peer_uptime(duthost, static_peers, dynamic_peer=None):
    '''
    Get the uptime of the static and dynamic peers.
    '''
    static_peers_uptime = {}
    bgp_summary_string = duthost.shell("vtysh -c 'show bgp vrf Vnet2 summary json'")['stdout']
    bgp_summary = json.loads(bgp_summary_string)
    for static_peer in static_peers:
        static_peers_uptime[static_peer] = bgp_summary['ipv4Unicast']['peers'][static_peer]['peerUptimeMsec']
    if dynamic_peer is not None:
        dynamic_peer_uptime = bgp_summary['ipv4Unicast']['peers'][dynamic_peer]['peerUptimeMsec']
        return static_peers_uptime, dynamic_peer_uptime
    else:
        return static_peers_uptime


def validate_dynamic_peer_established(bgp_summary, template):
    '''
    Validate that the dynamic peer is in the established state.
    '''
    if template == 'vnet_dynamic_peer_add':
        assert (
            '10.0.0.61' in bgp_summary['ipv4Unicast']['peers']
            and bgp_summary['ipv4Unicast']['peers']['10.0.0.61']['state'] == 'Established'
        ), "BGP peer 10.0.0.61 not in Established state or missing from summary"
        assert (
            '10.0.0.63' in bgp_summary['ipv4Unicast']['peers']
            and bgp_summary['ipv4Unicast']['peers']['10.0.0.63']['state'] == 'Established'
        ), "BGP peer 10.0.0.63 not in Established state or missing from summary"
    elif template == 'vnet_dynamic_peer_del':
        assert (
            '10.0.0.61' in bgp_summary['ipv4Unicast']['peers']
            and bgp_summary['ipv4Unicast']['peers']['10.0.0.61']['state'] == 'Established'
        ), "BGP peer 10.0.0.61 not in Established state or missing from summary"
        assert (
            '10.0.0.63' not in bgp_summary['ipv4Unicast']['peers']
            ), "BGP peer 10.0.63 should not be in show bgp summary output"


def modify_dynamic_peer_cfg(duthost, template):
    '''
    modify dynamic peer configuration on DUT
    '''
    if template not in TEMPLATE_CONFIGS:
        raise ValueError(f"Unknown template name: {template}")

    config_dict = TEMPLATE_CONFIGS[template]
    config_json_str = json.dumps(config_dict, indent=4)

    temp_location = f"/tmp/{template}.json"

    # Copy rendered config to DUT and apply it
    duthost.copy(content=config_json_str, dest=temp_location)
    duthost.shell(f"sonic-cfggen -j {temp_location} --write-to-db")
    time.sleep(10)
    validate_state_db_entry(duthost, "BGPSLBPassive", "Vnet2", True)


def dynamic_range_add_delete(duthost, template):
    '''
    Validate the behavior when a different dynamic range is added/deleted.
    '''
    static_peers = ['fc00::7a', 'fc00::7e']
    dynamic_peer = '10.0.0.61'
    static_peer_uptime_before, dynamic_peer_uptime_before = get_bgp_peer_uptime(
        duthost, static_peers, dynamic_peer)
    time.sleep(10)
    modify_dynamic_peer_cfg(duthost, template)
    if template == 'vnet_dynamic_peer_add':
        time.sleep(120)

    static_peer_uptime_after, dynamic_peer_uptime_after = get_bgp_peer_uptime(
        duthost, static_peers, dynamic_peer)

    for static_peer in static_peers:
        assert static_peer_uptime_after[static_peer] >= static_peer_uptime_before[static_peer] + 2*10*1000, \
            f"Static peer {static_peer} should not flap when a different dynamic range is added/deleted!"
    assert dynamic_peer_uptime_after >= dynamic_peer_uptime_before + 2*10*1000, \
        "Peer from other range should not flap when a different dynamic range is added/deleted!"

    bgp_summary_string = duthost.shell("vtysh -c 'show bgp vrf Vnet2 summary json'")['stdout']
    bgp_summary = json.loads(bgp_summary_string)
    validate_dynamic_peer_established(bgp_summary, template)


def get_core_dumps(duthost):
    '''
    Check if there is a core dump file in the /var/core directory.
    '''
    cmd = "ls /var/core 2>/dev/null"  # List only core dump files (core*)
    result = duthost.shell(cmd)['stdout'].strip()

    # If result is empty, no core dumps exist, otherwise core dumps are present
    return result.split('\n') if result else []


def get_ptf_port_index(interface_name):
    """
    Convert Ethernet interface name to PTF port index (Ethernet112 → 28).
    """
    return int(interface_name.replace("Ethernet", "")) // 4


def get_expected_unexpected_ptf_ports(cfg_facts, vnet_expected, vnet_unexpected):
    portchannel_interfaces = cfg_facts.get("PORTCHANNEL_INTERFACE", {})
    portchannel_members = cfg_facts.get("PORTCHANNEL_MEMBER", {})

    # Identify portchannels per vnet
    expected_portchannels = set()
    unexpected_portchannels = set()

    for key, value in portchannel_interfaces.items():
        if "|" in key:
            continue  # Skip sub-entries with IPs
        vnet_name = value.get("vnet_name")
        if vnet_name == vnet_expected:
            expected_portchannels.add(key)
        elif vnet_name == vnet_unexpected:
            unexpected_portchannels.add(key)

    # Map portchannels to their member interfaces
    def collect_ptf_ports(portchannels):
        ptf_ports = []
        for key in portchannel_members:
            pc, iface = key.split("|")
            if pc in portchannels:
                ptf_ports.append(get_ptf_port_index(iface))
        return ptf_ports

    expected_ptf_ports = collect_ptf_ports(expected_portchannels)
    unexpected_ptf_ports = collect_ptf_ports(unexpected_portchannels)

    return expected_ptf_ports, unexpected_ptf_ports


def test_dynamic_peer_vnet(duthosts, rand_one_dut_hostname, cfg_facts):
    '''
    Tests for static and dynamic peers inside a vnet.
    '''
    try:
        duthost = duthosts[rand_one_dut_hostname]
        props = g_vars['props']
        route_count = props['podset_number'] * \
            props['tor_number'] * props['tor_subnet_number']

        # Validate static and dynamic peers are established and have correct route counts inside VNET.
        for vnet in cfg_facts['VNET']:
            bgp_summary_string = duthost.shell(
                "vtysh -c 'show bgp vrf {} summary json'".format(vnet))['stdout']
            bgp_summary = json.loads(bgp_summary_string)
            for info in bgp_summary:
                for peer, attr in list(bgp_summary[info]['peers'].items()):
                    prefix_count = attr['pfxRcd']
                    # skip ipv6 peers under 'ipv4Unicast' and compare only ipv4 peers under 'ipv4Unicast',
                    # and ipv4 peers under 'ipv6Unicast'
                    if ((info == "ipv4Unicast" and attr['idType'] == 'ipv6') or
                            (info == "ipv6Unicast" and attr['idType'] == 'ipv4')):
                        continue
                    else:
                        assert int(prefix_count) == route_count, "%s should received %s route prefixes!" % (
                            peer, route_count)
                        if 'dynamicPeer' in attr:
                            validate_state_db_entry(duthost, peer, vnet, True)
                        else:
                            validate_state_db_entry(duthost, peer, vnet, False)

        # Verify changing ip_range for dynamic peers
        bgp_summary_string = duthost.shell("vtysh -c 'show bgp vrf Vnet2 summary json'")['stdout']
        bgp_summary = json.loads(bgp_summary_string)
        validate_dynamic_peer_established(bgp_summary, 'vnet_dynamic_peer_add')
        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_del')
        bgp_summary_string = duthost.shell("vtysh -c 'show bgp vrf Vnet2 summary json'")['stdout']
        bgp_summary = json.loads(bgp_summary_string)
        validate_dynamic_peer_established(bgp_summary, 'vnet_dynamic_peer_del')

        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')
    except Exception as e:
        logger.error("Exception raised in test_setup_vnet: {}".format(repr(e)))
        pytest.fail("Vnet testing setup failed")
        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')


def test_bgp_vnet_route_forwarding(ptfadapter, duthosts, rand_one_dut_hostname, cfg_facts):
    '''
    Verify that the traffic to the peer in Vnet1 is forwarded correctly.
    Send a UDP packet to with the destination as one of the routes learned via bgp in Vnet1
    and verify that it is received on the correct port in Vnet1.
    Also verify that the packet is not received on the other ports which belong to Vnet2.
    '''
    try:
        duthost = duthosts[rand_one_dut_hostname]
        router_mac = duthost.facts["router_mac"]
        # Destination IP is one of the routes learned via bgp in Vnet1
        dst_ip = "193.11.248.129"

        send_port = 28
        src_mac = ptfadapter.dataplane.get_mac(0, send_port)

        inner_pkt = testutils.simple_udp_packet(
            eth_dst=router_mac,
            eth_src=src_mac,
            ip_dst=dst_ip,
            ip_src="20.20.20.1",
            udp_sport=1234,
            udp_dport=4321,
        )

        expected_pkt = Mask(inner_pkt)
        expected_pkt.set_do_not_care_scapy(Ether, "dst")
        expected_pkt.set_do_not_care_scapy(Ether, "src")
        expected_pkt.set_do_not_care_scapy(IP, "ttl")
        expected_pkt.set_do_not_care_scapy(IP, "chksum")

        expected_ports, unexpected_ports = get_expected_unexpected_ptf_ports(cfg_facts, "Vnet1", "Vnet2")

        logger.info(f"Sending UDP packet on port {send_port}")
        testutils.send(ptfadapter, send_port, inner_pkt)

        logger.info(f"Expecting UDP packet on one of {expected_ports}")
        testutils.verify_packet_any_port(ptfadapter, expected_pkt, expected_ports)

        logger.info(f"Verifying packet is not received on ports {unexpected_ports}")
        testutils.verify_no_packet_any(ptfadapter, expected_pkt, unexpected_ports)
    except Exception as e:
        logger.error("Exception raised in test_bgp_vnet_route_forwarding: {}".format(repr(e)))
        pytest.fail("Packet test for per vnet BGP failed")
        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')


def test_add_delete_ip_range(duthosts, rand_one_dut_hostname):
    '''
    Verify adding and deleting of a new dynamic ip range.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    try:
        # Prepare initial config
        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_del')

        # Verify adding a new dynamic range
        dynamic_range_add_delete(duthost, 'vnet_dynamic_peer_add')

        # Verify deleting a dynamic range
        dynamic_range_add_delete(duthost, 'vnet_dynamic_peer_del')

        # Restore the config
        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')
    except Exception as e:
        logger.error("Exception raised in test_add_delete_ip_range: {}".format(repr(e)))
        pytest.fail("Adding/deleting IP range for dynamic peers failed")
        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')


def test_dynamic_peer_group_delete(duthosts, rand_one_dut_hostname):
    '''
    Validate the behavior when a dynamic peer group is deleted.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    try:
        static_peers = ['fc00::7a', 'fc00::7e']
        static_peer_uptime_before = get_bgp_peer_uptime(duthost, static_peers)
        redis_cmd = 'redis-cli -n 4 DEL "BGP_PEER_RANGE|Vnet2|BGPSLBPassive"'
        duthost.shell(redis_cmd)
        time.sleep(10)

        static_peer_uptime_after = get_bgp_peer_uptime(duthost, static_peers)
        for static_peer in static_peers:
            assert static_peer_uptime_after[static_peer] >= static_peer_uptime_before[static_peer] + 10000, \
                f"Static peer {static_peer} should not flap when a dynamic peer group is deleted!"

        bgp_summary_string = duthost.shell("vtysh -c 'show bgp vrf Vnet2 summary json'")['stdout']
        bgp_summary = json.loads(bgp_summary_string)
        total_peers = bgp_summary['ipv4Unicast']['dynamicPeers']
        assert int(total_peers) == 0, "There should be no dynamic peer. Found {}".format(total_peers)

        validate_state_db_entry(duthost, "BGPSLBPassive", "Vnet2", True)
        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')
    except Exception as e:
        logger.error("Exception raised in test_dynamic_peer_group_delete: {}".format(repr(e)))
        pytest.fail("Dynamic peer group deletion test failed")
        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')


def test_dynamic_peer_modify_stress(duthosts, rand_one_dut_hostname):
    '''
    Stress test for modifying dynamic peer configuration.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    try:
        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')
        time.sleep(120)
        static_peers = ['fc00::7a', 'fc00::7e']
        dynamic_peer = '10.0.0.61'
        static_peer_uptime_before, dynamic_peer_uptime_before = get_bgp_peer_uptime(
            duthost, static_peers, dynamic_peer)
        core_dumps_before = get_core_dumps(duthost)

        for i in range(20):
            modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_del')
            modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')

        static_peer_uptime_after, dynamic_peer_uptime_after = get_bgp_peer_uptime(
            duthost, static_peers, dynamic_peer)

        for static_peer in static_peers:
            assert static_peer_uptime_after[static_peer] >= static_peer_uptime_before[static_peer] + 20*20*1000, \
                f"Static peer {static_peer} should not flap when a dynamic peer is modified!"
        assert dynamic_peer_uptime_after >= dynamic_peer_uptime_before, \
            f"Dynamic peer {dynamic_peer} should not flap when a dynamic peer is modified!"
        core_dumps_after = get_core_dumps(duthost)
        assert core_dumps_before == core_dumps_after, \
            "Core dumps should not be generated when modifying dynamic peer configuration."
        # restore the config
        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')
    except Exception as e:
        logger.error("Exception raised in test_dynamic_peer_modify_stress: {}".format(repr(e)))
        pytest.fail("Stress test for dynamic peer group modification failed")
        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')


def test_dynamic_peer_delete_stress(duthosts, rand_one_dut_hostname):
    '''
    Stress test for deleting dynamic peer configuration.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    try:
        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')
        time.sleep(120)
        static_peers = ['fc00::7a', 'fc00::7e']
        static_peer_uptime_before = get_bgp_peer_uptime(duthost, static_peers)
        core_dumps_before = get_core_dumps(duthost)

        for i in range(20):
            redis_cmd = 'redis-cli -n 4 DEL "BGP_PEER_RANGE|Vnet2|BGPSLBPassive"'
            duthost.shell(redis_cmd)
            time.sleep(10)
            modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')
            bgp_summary_string = duthost.shell("vtysh -c 'show bgp vrf Vnet2 summary json'")['stdout']
            bgp_summary = json.loads(bgp_summary_string)
            validate_dynamic_peer_established(bgp_summary, 'vnet_dynamic_peer_add')

        static_peer_uptime_after = get_bgp_peer_uptime(duthost, static_peers)
        for static_peer in static_peers:
            assert static_peer_uptime_after[static_peer] >= static_peer_uptime_before[static_peer] + 20*20*1000, \
                f"Static peer {static_peer} should not flap when a dynamic peer is deleted!"
        core_dumps_after = get_core_dumps(duthost)
        assert core_dumps_before == core_dumps_after, \
            "Core dumps should not be generated when deleting dynamic peer configuration."
        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')
    except Exception as e:
        logger.error("Exception raised in test_dynamic_peer_delete_stress: {}".format(repr(e)))
        pytest.fail("Stress test for dynamic peer group deletion failed")
        modify_dynamic_peer_cfg(duthost, 'vnet_dynamic_peer_add')
