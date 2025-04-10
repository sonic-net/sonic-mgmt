import sys
import time
import threading
import yaml
import json
import random
import logging
import tempfile
import traceback

from collections import OrderedDict
from natsort import natsorted
from netaddr import IPNetwork
from six.moves import queue
from copy import deepcopy
import pytest
from ptf import mask
import ptf.packet as scapy
import ptf.testutils as testutils
import scapy.utils as scapy_utils
from ptf.packet import Ether, IP, UDP, VXLAN, simple_vxlan_packet

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses    # noqa F401
from tests.common.storage_backend.backend_utils import skip_test_module_over_backend_topologies     # noqa F401
from tests.ptf_runner import ptf_runner
from tests.common.utilities import wait_until
from tests.common.reboot import reboot
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t0')
]

logger = logging.getLogger(__name__)

# global variables
g_vars = {}
PTF_TEST_PORT_MAP = '/root/ptf_test_port_map.json'

# helper functions
def get_vlan_members(vlan_name, cfg_facts):
    tmp_member_list = []

    for m in list(cfg_facts['VLAN_MEMBER'].keys()):
        v, port = m.split('|')
        if vlan_name == v:
            tmp_member_list.append(port)

    return natsorted(tmp_member_list)

def get_intf_ips(interface_name, cfg_facts):
    prefix_to_intf_table_map = {
        'Vlan': 'VLAN_INTERFACE',
        'PortChannel': 'PORTCHANNEL_INTERFACE',
        'Ethernet': 'INTERFACE',
        'Loopback': 'LOOPBACK_INTERFACE'
    }

    intf_table_name = None

    ip_facts = {
        'ipv4': [],
        'ipv6': []
    }

    for pfx, t_name in list(prefix_to_intf_table_map.items()):
        if pfx in interface_name:
            intf_table_name = t_name
            break

    if intf_table_name is None:
        return ip_facts

    for intf in cfg_facts[intf_table_name]:
        if '|' in intf:
            if_name, ip = intf.split('|')
            if if_name == interface_name:
                ip = IPNetwork(ip)
                if ip.version == 4:
                    ip_facts['ipv4'].append(ip)
                else:
                    ip_facts['ipv6'].append(ip)

    return ip_facts

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

def get_vrf_intfs(cfg_facts):
    intf_tables = ['INTERFACE', 'PORTCHANNEL_INTERFACE',
                   'VLAN_INTERFACE', 'LOOPBACK_INTERFACE']
    vrf_intfs = {}

    for table in intf_tables:
        for intf, attrs in list(cfg_facts.get(table, {}).items()):
            if '|' not in intf:
                vrf = attrs['vnet_name']
                if vrf not in vrf_intfs:
                    vrf_intfs[vrf] = {}
                vrf_intfs[vrf][intf] = get_intf_ips(intf, cfg_facts)

    return vrf_intfs

def get_vrf_ports(cfg_facts):
    '''
    :return: vrf_member_port_indices, vrf_intf_member_port_indices
    '''

    vlan_member = list(cfg_facts['VLAN_MEMBER'].keys())
    pc_member = list(cfg_facts['PORTCHANNEL_MEMBER'].keys())
    member = vlan_member + pc_member

    vrf_intf_member_port_indices = {}
    vrf_member_port_indices = {}

    vrf_intfs = get_vrf_intfs(cfg_facts)

    for vrf, intfs in list(vrf_intfs.items()):
        vrf_intf_member_port_indices[vrf] = {}
        vrf_member_port_indices[vrf] = []

        for intf in intfs:
            vrf_intf_member_port_indices[vrf][intf] = natsorted(
                [cfg_facts['config_port_indices'][m.split('|')[1]] for m in [
                    m for m in member if intf in m]]
            )
            vrf_member_port_indices[vrf].extend(
                vrf_intf_member_port_indices[vrf][intf])

        vrf_member_port_indices[vrf] = natsorted(vrf_member_port_indices[vrf])

    return vrf_intf_member_port_indices, vrf_member_port_indices

def setup_vrf_cfg(duthost, localhost, cfg_facts):
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

def get_dut_enabled_ptf_ports(tbinfo, hostname):
    dut_index = str(tbinfo['duts_map'][hostname])
    ptf_ports = set(tbinfo['topo']['ptf_map'][dut_index].values())
    disabled_ports = set()
    if dut_index in tbinfo['topo']['ptf_map_disabled']:
        disabled_ports = set(
            tbinfo['topo']['ptf_map_disabled'][dut_index].values())
    return ptf_ports - disabled_ports

def get_dut_vlan_ptf_ports(mg_facts):
    ports = set()
    for vlan in mg_facts['minigraph_vlans']:
        for member in mg_facts['minigraph_vlans'][vlan]['members']:
            ports.add(mg_facts['minigraph_port_indices'][member])
    return ports

# fixtures
@pytest.fixture(scope="module")
def dut_facts(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.facts

@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return get_cfg_facts(duthost)

def restore_config_db(localhost, duthost, ptfhost):
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
    duthost.shell("mv /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")

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

        setup_vrf_cfg(duthost, localhost, cfg_t0)

        cfg_facts = get_cfg_facts(duthost)

        duthost.shell("sonic-clear arp")
        duthost.shell("sonic-clear nd")
        duthost.shell("sonic-clear fdb all")

        with open("../ansible/vars/topo_{}.yml".format(tbinfo['topo']['name']), 'r') as fh:
            g_vars['topo_properties'] = yaml.safe_load(fh)

        g_vars['props'] = g_vars['topo_properties']['configuration_properties']['common']

        g_vars['vrf_intfs'] = get_vrf_intfs(cfg_facts)

        g_vars['vrf_intf_member_port_indices'], g_vars['vrf_member_port_indices'] = get_vrf_ports(
            cfg_facts)

    except Exception as e:
        # Ensure that config_db is restored.
        # If exception is raised in setup, the teardown code won't be executed. That's why we need to capture
        # exception and do cleanup here in setup part (code before 'yield').
        logger.error("Exception raised in setup: {}".format(repr(e)))
        logger.error(json.dumps(
            traceback.format_exception(*sys.exc_info()), indent=2))

        restore_config_db(localhost, duthost, ptfhost)

        # Setup failed. There is no point to continue running the cases.
        # If this line is hit, script execution will stop here
        pytest.fail("Vnet testing setup failed")

    # --------------------- Testing -----------------------
    yield

    # --------------------- Teardown -----------------------
    restore_config_db(localhost, duthost, ptfhost)

@pytest.fixture(scope="module")
def mg_facts(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    return mg_facts

@pytest.fixture(scope='module')
def vlan_mac(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    config_facts = duthost.config_facts(
        host=duthost.hostname, source='running')['ansible_facts']
    dut_vlan_mac = None
    for vlan in list(config_facts.get('VLAN', {}).values()):
        if 'mac' in vlan:
            logger.debug('Found VLAN mac')
            dut_vlan_mac = vlan['mac']
            break
    if not dut_vlan_mac:
        logger.debug('No VLAN mac, use default router_mac')
        dut_vlan_mac = duthost.facts['router_mac']
    return dut_vlan_mac

@pytest.fixture(scope="module", autouse=True)
def ptf_test_port_map(tbinfo, duthosts, mg_facts, ptfhost, rand_one_dut_hostname, vlan_mac):
    duthost = duthosts[rand_one_dut_hostname]
    ptf_test_port_map = {}
    enabled_ptf_ports = get_dut_enabled_ptf_ports(tbinfo, duthost.hostname)
    vlan_ptf_ports = get_dut_vlan_ptf_ports(mg_facts)
    for port in enabled_ptf_ports:
        if port in vlan_ptf_ports:
            target_mac = vlan_mac
        else:
            target_mac = duthost.facts['router_mac']
        ptf_test_port_map[str(port)] = {
            'target_dut': 0,
            'target_dest_mac': target_mac,
            'target_src_mac': duthost.facts['router_mac']
        }
    ptfhost.copy(content=json.dumps(ptf_test_port_map), dest=PTF_TEST_PORT_MAP)

def verify_bgp_vnet_traffic(duthost, cfg_facts, ptfadapter):
    '''
    Verify BGP VNET traffic between DUT and PTF.
    '''
    inner_src_ip = "192.168.0.2"
    inner_dst_ip = "192.168.0.1"
    vni_id = 799999
    original_inner_src_mac = "00:66:77:88:99:aa"
    outer_src_mac = "00:11:22:33:44:66"
    outer_src_ip = "10.0.0.57"
    outer_dst_ip = "10.0.0.56"
    # Create VXLAN-encapsulated packet sent by server
    innerpkt = testutils.simple_udp_packet(
            eth_dst=duthost.facts['router_mac'],
            eth_src=original_inner_src_mac,
            ip_src=inner_src_ip,
            ip_dst=inner_dst_ip,
            ip_id=0,
            ip_ihl=5,
            udp_sport=1234,
            udp_dport=4321,
            ip_ttl=121)
    pkt = testutils.simple_vxlan_packet(
        eth_dst=duthost.facts['router_mac'],
        eth_src=outer_src_mac,
        ip_src=outer_src_ip,
        ip_dst=outer_dst_ip,
        udp_sport=1234,
        udp_dport=4789,
        vxlan_vni=vni_id,
        inner_frame=innerpkt
    )
    # Send packet from server into the DUT
    testutils.send(ptfadapter, 0, pkt)
    time.sleep(2)
    masked_exp_pkt =  mask.Mask(pkt)
    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
    # Verify the packet received
    testutils.verify_packet(ptfadapter, masked_exp_pkt, 0)

def modify_dynamic_peer_cfg(duthost, cfg_facts, template):
    '''
    modify dynamic peer configuration on DUT
    '''
    cfg_t0 = deepcopy(cfg_facts)
    cfg_t0.pop('config_port_indices', None)
    extra_vars = {'cfg_t0': cfg_t0}
    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)
    if template is "delete":
        duthost.template(src="bgp/templates/vnet_dynamic_peer_del.j2", dest="/tmp/vnet_dynamic_peer_del.json")
        duthost.shell("cp /tmp/vnet_dynamic_peer_del.json /etc/sonic/vnet_dynamic_peer_del.json")
        duthost.shell("cp /tmp/vnet_dynamic_peer_del.json /home/admin/vnet_dynamic_peer_del.json")
        duthost.shell("sonic-cfggen -j /etc/sonic/vnet_dynamic_peer_del.json --write-to-db")
    elif template is "add":
        duthost.template(src="bgp/templates/vnet_dynamic_peer_add.j2", dest="/tmp/vnet_dynamic_peer_add.json")
        duthost.shell("cp /tmp/vnet_dynamic_peer_add.json /etc/sonic/vnet_dynamic_peer_add.json")
        duthost.shell("cp /tmp/vnet_dynamic_peer_add.json /home/admin/vnet_dynamic_peer_add.json")
        duthost.shell("sonic-cfggen -j /etc/sonic/vnet_dynamic_peer_add.json --write-to-db")
    elif template is "modify":
        duthost.template(src="bgp/templates/vnet_config_db.j2", dest="/tmp/config_db_vnet.json")
        duthost.shell("cp /tmp/config_db_vnet.json /etc/sonic/config_db.json")
        duthost.shell("cp /tmp/config_db_vnet.json /etc/sonic/vnet_config_db.json")
        duthost.shell("sonic-cfggen -j /etc/sonic/config_db.json --write-to-db")
    else:
        logger.error("Invalid template type: {}".format(template))

def test_setup_vnet(duthosts, rand_one_dut_hostname, cfg_facts, ptfadapter):
    try:
        print("test_setup_vnet")
        duthost = duthosts[rand_one_dut_hostname]
        props = g_vars['props']
        route_count = props['podset_number'] * \
            props['tor_number'] * props['tor_subnet_number']
        for vnet in cfg_facts['VNET']:
            bgp_summary_string = duthost.shell(
                "vtysh -c 'show bgp vrf {} summary json'".format(vnet))['stdout']
            bgp_summary = json.loads(bgp_summary_string)
            for info in bgp_summary:
                for peer, attr in list(bgp_summary[info]['peers'].items()):
                    prefix_count = attr['pfxRcd']
                    # skip ipv6 peers under 'ipv4Unicast' and compare only ipv4 peers under 'ipv4Unicast',
                    # and ipv6 peers under 'ipv6Unicast'
                    if (info == "ipv4Unicast" and attr['idType'] == 'ipv6') or (info == "ipv6Unicast" and attr['idType'] == 'ipv4'):
                        continue
                    else:
                        assert int(prefix_count) == route_count, "%s should received %s route prefixs!" % (
                            peer, route_count)

        #Verify changing ip_range for dynamic peers
        modify_dynamic_peer_cfg(duthost, cfg_facts, 'delete')
        time.sleep(10)
        bgp_summary_string = duthost.shell("vtysh -c 'show bgp vrf Vnet2 summary json'")['stdout']
        bgp_summary = json.loads(bgp_summary_string)
        total_peers = bgp_summary['ipv4Unicast']['dynamicPeers']
        assert int(total_peers) == 1, "There should be only 1 dynamic peer!"

        modify_dynamic_peer_cfg(duthost, cfg_facts, 'add')
        time.sleep(10)
        bgp_summary_string = duthost.shell("vtysh -c 'show bgp vrf Vnet2 summary json'")['stdout']
        bgp_summary = json.loads(bgp_summary_string)
        total_peers = bgp_summary['ipv4Unicast']['dynamicPeers']
        assert int(total_peers) == 2, "There should be 2 dynamic peer!"

        verify_bgp_vnet_traffic(duthost, cfg_facts, ptfadapter)
    except Exception as e:
        logger.error("Exception raised in test_setup_vnet: {}".format(repr(e)))
        pytest.fail("Vnet testing setup failed")
