import contextlib
import logging
import pytest
import random
import time
import json
import ptf
from scapy.all import Ether, IP, TCP
import scapy.all as scapyall
from datetime import datetime
from tests.ptf_runner import ptf_runner

from collections import defaultdict
from natsort import natsorted
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.helpers.dut_ports import encode_dut_port_name
from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR
from tests.common.utilities import dump_scapy_packet_show_output, get_intf_by_sub_intf
import ipaddress

from ptf import mask
from ptf import testutils
from scapy.all import Ether, IP
from tests.common.helpers.generators import generate_ip_through_default_route
from tests.common import constants


__all__ = ['tor_mux_intf', 'tor_mux_intfs', 'ptf_server_intf', 't1_upper_tor_intfs', 't1_lower_tor_intfs', 'upper_tor_host', 'lower_tor_host', 'force_active_tor']

logger = logging.getLogger(__name__)


def get_tor_mux_intfs(duthost):
    return sorted(duthost.get_vlan_intfs(), key=lambda intf: int(intf.replace('Ethernet', '')))


@pytest.fixture(scope='session')
def tor_mux_intfs(duthosts):
    '''
    Returns the server-facing interfaces on the ToR to be used for testing
    '''
    # The same ports on both ToRs should be connected to the same PTF port
    return get_tor_mux_intfs(duthosts[0])


@pytest.fixture(scope='session')
def tor_mux_intf(tor_mux_intfs):
    '''
    Returns the first server-facing interface on the ToR to be used for testing
    '''
    # The same ports on both ToRs should be connected to the same PTF port
    return tor_mux_intfs[0]


@pytest.fixture(scope='session')
def ptf_server_intf(duthosts, tor_mux_intf, tbinfo):
    '''
    Returns the ToR-facing interface on the PTF to be used for testing

    This should be connected to the interface returned by `tor_mux_intf`
    '''
    mg_facts = duthosts[0].get_extended_minigraph_facts(tbinfo)
    ptf_port_index = mg_facts['minigraph_ptf_indices'][tor_mux_intf]
    ptf_intf = 'eth{}'.format(ptf_port_index)

    logger.info("Using PTF server interface {} for test".format(ptf_intf))
    return ptf_intf


@pytest.fixture(scope='session')
def t1_upper_tor_intfs(upper_tor_host, tbinfo):
    '''
    Gets the PTF ports connected to the upper ToR for the first T1
    '''
    return get_t1_ptf_ports(upper_tor_host, tbinfo)


@pytest.fixture(scope='session')
def t1_lower_tor_intfs(lower_tor_host, tbinfo):
    '''
    Gets the PTF ports connected to the lower ToR for the first T1
    '''
    return get_t1_ptf_ports(lower_tor_host, tbinfo)


@pytest.fixture(scope='session')
def upper_tor_host(duthosts):
    '''
    Gets the host object for the upper ToR

    Uses the convention that the first ToR listed in the testbed file is the upper ToR
    '''
    dut = duthosts[0]
    logger.info("Using {} as upper ToR".format(dut.hostname))
    return dut


@pytest.fixture(scope='session')
def lower_tor_host(duthosts):
    '''
    Gets the host object for the lower ToR

    Uses the convention that the second ToR listed in the testbed file is the lower ToR
    '''
    dut = duthosts[-1]
    logger.info("Using {} as lower ToR".format(dut.hostname))
    return dut


def map_hostname_to_tor_side(tbinfo, hostname):
    if 'dualtor' not in tbinfo['topo']['name']:
        return None

    if hostname not in tbinfo['duts_map']:
        return None
    if tbinfo['duts_map'][hostname] == 0:
        return UPPER_TOR
    elif tbinfo['duts_map'][hostname] == 1:
        return LOWER_TOR
    else:
        return None


def get_t1_ptf_ports_for_backend_topo(mg_facts):
    """
    In backend topology, there isn't any port channel between T0 and T1,
    we use sub interface instead.
    Args:
        mg_facts (dict): mg_facts
    Returns:
        list: ptf t1 ports, e.g. ['eth10', 'eth11']
    """
    ptf_portmap = mg_facts['minigraph_ptf_indices']

    ports = set()
    for vlan_sub_interface in mg_facts['minigraph_vlan_sub_interfaces']:
        sub_intf_name = vlan_sub_interface['attachto']
        vlan_id = vlan_sub_interface['vlan']
        intf_name = get_intf_by_sub_intf(sub_intf_name, vlan_id)

        ptf_port_index = ptf_portmap[intf_name]
        ports.add("eth{}".format(ptf_port_index))

    return list(ports)


def get_t1_ptf_pc_ports(dut, tbinfo):
    """Gets the PTF portchannel ports connected to the T1 switchs."""
    config_facts = dut.get_running_config_facts()
    mg_facts = dut.get_extended_minigraph_facts(tbinfo)

    pc_ports = {}
    for pc in config_facts['PORTCHANNEL'].keys():
        pc_ports[pc] = []
        for intf in config_facts["PORTCHANNEL"][pc]["members"]:
            ptf_port_index = mg_facts["minigraph_ptf_indices"][intf]
            intf_name = "eth{}".format(ptf_port_index)
            pc_ports[pc].append(intf_name)

    return pc_ports


def get_t1_ptf_ports(dut, tbinfo):
    '''
    Gets the PTF ports connected to a given DUT for the first T1
    '''
    mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    is_backend_topology = mg_facts.get(constants.IS_BACKEND_TOPOLOGY_KEY, False)

    if is_backend_topology:
        return get_t1_ptf_ports_for_backend_topo(mg_facts)

    pc_ports = get_t1_ptf_pc_ports(dut, tbinfo)
    # Always choose the first portchannel
    portchannel = sorted(pc_ports.keys())[0]
    ptf_portchannel_intfs = pc_ports[portchannel]

    logger.info("Using portchannel ports {} on PTF for DUT {}".format(ptf_portchannel_intfs, dut.hostname))
    return ptf_portchannel_intfs


def get_t1_active_ptf_ports(dut, tbinfo):
    """
    @summary: Get ptf port indices for active PortChannels on DUT
    @param dut: The DUT we are testing against
    @param tbinfo: The fixture tbinfo
    @return: A dict { "PortChannel0001": [0, 1], ...}
    """
    config_facts = dut.get_running_config_facts()
    mg_facts = dut.get_extended_minigraph_facts(tbinfo)

    up_portchannels = dut.get_up_ip_ports()
    ptf_portchannel_intfs = {}
    for k, v in config_facts['PORTCHANNEL'].items():
        if k in up_portchannels:
            ptf_portchannel_intfs[k] = []
            for member in v['members']:
                ptf_portchannel_intfs[k].append(mg_facts['minigraph_ptf_indices'][member])

    return ptf_portchannel_intfs

def get_t1_bgp_up_ptf_ports(dut, tbinfo):
    """
    @summary: Get ptf port indices for PortChannels on which BGP session is up
    @param dut: The DUT we are testing against
    @param tbinfo: The fixture tbinfo
    @return: A dict { "PortChannel0001": [0, 1], ...}
    """
    config_facts = dut.get_running_config_facts()
    mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    bgp_facts = dut.bgp_facts()['ansible_facts']
    ip_interfaces = dut.shell('show ip interface')['stdout_lines'][2:]
    portchannels = []
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['state'] == 'established':
            for line in ip_interfaces:
                if k in line:
                    portchannels.append(line.split()[0])
                    break

    ptf_portchannel_intfs = {}
    for k, v in config_facts['PORTCHANNEL'].items():
        if k in portchannels:
            ptf_portchannel_intfs[k]  = []
            for member in v['members']:
                ptf_portchannel_intfs[k].append(mg_facts['minigraph_ptf_indices'][member])

    return ptf_portchannel_intfs


def update_mux_configs_and_config_reload(dut, state):
    """
    @summary: Update config_db.json, and then load with 'config reload'
            Please note that this is a general method, and caller must
            backup config_db.json and do a restore at the end.
    @param dut: The DUT we are testing against
    @param state: A str, auto|active|standby
    """
    STATE_LIST = ['auto', 'active', 'standby']
    pt_assert(state in STATE_LIST, "state should be one of {}".format(STATE_LIST))

    mux_cable_config = dut.shell("sonic-cfggen -d  --var-json 'MUX_CABLE'")['stdout']
    pt_assert(len(mux_cable_config.strip()) != 0, "No mux_cable configuration is found in config_db")

    # Update mux_cable state and dump to a temp file
    mux_cable_config_json = json.loads(mux_cable_config)
    for _, config in mux_cable_config_json.items():
        config['state'] = state
    mux_cable_config_json = {"MUX_CABLE": mux_cable_config_json}
    TMP_FILE = "/tmp/mux_config.json"
    with open(TMP_FILE, "w") as f:
        json.dump(mux_cable_config_json, f)

    dut.copy(src=TMP_FILE, dest=TMP_FILE)

    # Load updated mux_cable config with sonic-cfggen
    cmds = [
        "sonic-cfggen -j {} -w".format(TMP_FILE),
        "config save -y"
    ]
    dut.shell_cmds(cmds=cmds)
    config_reload(dut)
    dut.file(path=TMP_FILE, state='absent')


@pytest.fixture
def force_active_tor():
    """
    @summary: Manually set dut host to the active tor for intf
    @param dut: The duthost for which to toggle mux
    @param intf: One or a list of names of interface or 'all' for all interfaces
    """
    forced_intfs = []
    def force_active_tor_fn(dut, intf):
        logger.info('Setting {} as active for intfs {}'.format(dut, intf))
        if type(intf) == str:
            cmds = ["config muxcable mode active {}; true".format(intf)]
            forced_intfs.append((dut, intf))
        else:
            cmds = []
            for i in intf:
                forced_intfs.append((dut, i))
                cmds.append("config muxcable mode active {}; true".format(i))
        dut.shell_cmds(cmds=cmds, continue_on_fail=True)

    yield force_active_tor_fn

    for x in forced_intfs:
        x[0].shell("config muxcable mode auto {}; true".format(x[1]))



def _get_tor_fanouthosts(tor_host, fanouthosts):
    """Helper function to get the fanout host objects that the current tor_host connected to.

    Args:
        tor_host (object): Host object for the ToR DUT.
        fanouthosts (dict): Key is fanout hostname, value is fanout host object.

    Returns:
        dict: Key is fanout hostname, value is fanout host object.
    """
    hosts = {}
    for fanout_hostname, fanout_host in fanouthosts.items():
        if tor_host.hostname in fanout_host.dut_hostnames:
            hosts[fanout_hostname] = fanout_host
    if not hosts:
        pt_assert('Failed to get fanout for tor_host "{}"'.format(tor_host.hostname))
    return hosts


@pytest.fixture(scope='module')
def upper_tor_fanouthosts(upper_tor_host, fanouthosts):
    """Fixture to get the fanout hosts that the upper_tor_host connected to.

    Args:
        upper_tor_host (object): Host object for upper_tor.
        fanouthosts (dict): Key is fanout hostname, value is fanout host object.

    Returns:
        dict: Key is fanout hostname, value is fanout host object.
    """
    return _get_tor_fanouthosts(upper_tor_host, fanouthosts)


@pytest.fixture(scope='module')
def lower_tor_fanouthosts(lower_tor_host, fanouthosts):
    """Fixture to get the fanout hosts that the lower_tor_host connected to.

    Args:
        lower_tor_host (object): Host object for lower_tor.
        fanouthosts (dict): Key is fanout hostname, value is fanout host object.

    Returns:
        dict: Key is fanout hostname, value is fanout host object.
    """
    return _get_tor_fanouthosts(lower_tor_host, fanouthosts)


def _shutdown_fanout_tor_intfs(tor_host, tor_fanouthosts, tbinfo, dut_intfs=None):
    """Helper function for shutting down fanout interfaces that are connected to specified DUT interfaces.

    Args:
        tor_host (object): Host object for the ToR DUT.
        tor_fanouthosts (dict): Key is fanout hostname, value is fanout host object.
        tbinfo (dict): Testbed info from the tbinfo fixture.
        dut_intfs (list, optional): List of DUT interface names, for example: ['Ethernet0', 'Ethernet4']. All the
            fanout interfaces that are connected to the specified DUT interfaces will be shutdown. If dut_intfs is not
            specified, the function will shutdown all the fanout interfaces that are connected to the tor_host DUT and in a VLAN.
            Defaults to None.

    Returns:
        dict (fanouthost: list): Each key is a fanout host, and the corresponding value is the interfaces that were shut down
                                 on that host device.
    """
    if not dut_intfs:
        # If no interface is specified, shutdown all VLAN ports
        vlan_intfs = []
        vlan_member_table = tor_host.get_running_config_facts()['VLAN_MEMBER']
        for vlan_members in vlan_member_table.values():
            vlan_intfs.extend(list(vlan_members.keys()))

        dut_intfs = vlan_intfs

    dut_intfs = natsorted(dut_intfs)

    full_dut_fanout_port_map = {}
    for fanout_host in tor_fanouthosts.values():
        for encoded_dut_intf, fanout_intf in fanout_host.host_to_fanout_port_map.items():
            full_dut_fanout_port_map[encoded_dut_intf] = {
                'fanout_host': fanout_host,
                'fanout_intf': fanout_intf
            }

    logger.debug('full_dut_fanout_port_map: {}'.format(full_dut_fanout_port_map))

    fanout_shut_intfs = defaultdict(list)

    for dut_intf in dut_intfs:
        encoded_dut_intf = encode_dut_port_name(tor_host.hostname, dut_intf)
        if encoded_dut_intf in full_dut_fanout_port_map:
            fanout_host = full_dut_fanout_port_map[encoded_dut_intf]['fanout_host']
            fanout_intf = full_dut_fanout_port_map[encoded_dut_intf]['fanout_intf']
            fanout_shut_intfs[fanout_host].append(fanout_intf)
        else:
            logger.error('No dut intf "{}" in full_dut_fanout_port_map'.format(encoded_dut_intf))

    for fanout_host, intf_list in fanout_shut_intfs.items():
        fanout_host.shutdown(intf_list)

    return fanout_shut_intfs


@pytest.fixture
def shutdown_fanout_upper_tor_intfs(upper_tor_host, upper_tor_fanouthosts, tbinfo):
    """
    Fixture for shutting down fanout interfaces connected to specified upper_tor interfaces.

    Args:
        upper_tor_host (object): Host object for upper_tor.
        upper_tor_fanouthosts (dict): Key is fanout hostname, value is fanout host object.
        tbinfo (dict): Testbed info from the tbinfo fixture.

    Yields:
        function: A function for shutting down fanout interfaces connected to specified upper_tor interfaces
    """
    shut_fanouts = []

    def shutdown(dut_intfs=None):
        logger.info('Shutdown fanout ports connected to upper_tor')
        shut_fanouts.append(_shutdown_fanout_tor_intfs(upper_tor_host, upper_tor_fanouthosts, tbinfo, dut_intfs))

    yield shutdown

    logger.info('Recover fanout ports connected to upper_tor')

    for instance in shut_fanouts:
        for fanout_host, intf_list in instance.items():
            fanout_host.no_shutdown(intf_list)


@pytest.fixture
def shutdown_fanout_lower_tor_intfs(lower_tor_host, lower_tor_fanouthosts, tbinfo):
    """
    Fixture for shutting down fanout interfaces connected to specified lower_tor interfaces.

    Args:
        lower_tor_host (object): Host object for lower_tor.
        lower_tor_fanouthosts (dict): Key is fanout hostname, value is fanout host object.
        tbinfo (dict): Testbed info from the tbinfo fixture.

    Yields:
        function: A function for shutting down fanout interfaces connected to specified lower_tor interfaces
    """
    shut_fanouts = []

    def shutdown(dut_intfs=None):
        logger.info('Shutdown fanout ports connected to lower_tor')
        shut_fanouts.append(_shutdown_fanout_tor_intfs(lower_tor_host, lower_tor_fanouthosts, tbinfo, dut_intfs))

    yield shutdown

    logger.info('Recover fanout ports connected to lower_tor')

    for instance in shut_fanouts:
        for fanout_host, intf_list in instance.items():
            fanout_host.no_shutdown(intf_list)


@pytest.fixture
def shutdown_fanout_tor_intfs(upper_tor_host, upper_tor_fanouthosts, lower_tor_host, lower_tor_fanouthosts, tbinfo):
    """Fixture for shutting down fanout interfaces connected to specified lower_tor interfaces.

    Args:
        upper_tor_host (object): Host object for upper_tor.
        upper_tor_fanouthosts (dict): Key is fanout hostname, value is fanout host object.
        lower_tor_host (object): Host object for lower_tor.
        lower_tor_fanouthosts (dict): Key is fanout hostname, value is fanout host object.
        tbinfo (dict): Testbed info from the tbinfo fixture.

    Yields:
        function: A function for shutting down fanout interfaces connected to specified lower_tor interfaces
    """
    down_intfs = []

    def shutdown(dut_intfs=None, upper=False, lower=False):
        if not upper and not lower:
            logger.info('lower=False and upper=False, no fanout interface will be shutdown.')
            return

        if upper:
            logger.info('Shutdown fanout ports connected to upper_tor')
            down_intfs.extend(_shutdown_fanout_tor_intfs(upper_tor_host, upper_tor_fanouthosts, tbinfo, dut_intfs))

        if lower:
            logger.info('Shutdown fanout ports connected to lower_tor')
            down_intfs.extend(_shutdown_fanout_tor_intfs(lower_tor_host, lower_tor_fanouthosts, tbinfo, dut_intfs))

    yield shutdown

    logger.info('Recover fanout ports connected to tor')
    for fanout_host, fanout_intf in down_intfs:
        fanout_host.no_shutdown(fanout_intf)


def _shutdown_t1_tor_intfs(tor_host, nbrhosts, tbinfo, vm_names=None):
    """Function for shutting down specified T1 VMs' interfaces that are connected to the tor_host.

    Args:
        tor_host (object): Host object for the ToR DUT.
        nbrhosts (dict): Dict returned by the nbrhosts fixture.
        tbinfo (dict): Testbed info from the tbinfo fixture.
        vm_names (list, optional): List of VM names, for example: ['ARISTA01T1', 'ARISTA02T1']. All the interfaces
            connected to tor_host on the specified VMs will be shutdown. If vm_names is None, shutdown will be performed
            on all the T1 VMs of tor_host.
            Defaults to None.

    Returns:
        list of tuple: Return a list of tuple. Each tuple has two items. The first item is the host object for VM.
            The second item is the VM interface that has been shutdown. The returned list makes it easy to recover
            the interfaces.
    """
    down_intfs = []

    tor_index = tbinfo['duts_map'][tor_host.hostname]

    if not vm_names:
        target_vms = nbrhosts
    else:
        target_vms = {}
        for vm_name in vm_names:
            if vm_name in nbrhosts:
                target_vms[vm_name] = nbrhosts[vm_name]
            else:
                logger.error('Unknown vm_name: "{}"'.format(vm_name))

    for vm_name in natsorted(target_vms.keys()):
        eos_host = target_vms[vm_name]['host']
        vm_intfs = tbinfo['topo']['properties']['configuration'][vm_name]['interfaces']
        for vm_intf in natsorted(vm_intfs.keys()):
            intf_detail = vm_intfs[vm_intf]
            if 'dut_index' in intf_detail:
                if intf_detail['dut_index'] == tor_index:
                    eos_host.shutdown(vm_intf)
                    down_intfs.append((eos_host, vm_intf))

    return down_intfs


@pytest.fixture
def shutdown_t1_upper_tor_intfs(upper_tor_host, nbrhosts, tbinfo):
    """Function for shutting down specified T1 VMs' interfaces that are connected to the upper_tor_host.

    Args:
        upper_tor_host (object): Host object for upper_tor.
        nbrhosts (dict): Dict returned by the nbrhosts fixture.
        tbinfo (dict): Testbed info from the tbinfo fixture.

    Yields:
        function: A function for shutting down specified T1 VMs interfaces connected to upper_tor_host.
    """
    down_intfs = []

    def shutdown(vm_names=None):
        logger.info('Shutdown T1 VM ports connected to upper_tor')
        down_intfs.extend(_shutdown_t1_tor_intfs(upper_tor_host, nbrhosts, tbinfo, vm_names))

    yield shutdown

    logger.info('Recover T1 VM ports connected to upper_tor')
    for eos_host, vm_intf in down_intfs:
        eos_host.no_shutdown(vm_intf)


@pytest.fixture
def shutdown_t1_lower_tor_intfs(lower_tor_host, nbrhosts, tbinfo):
    """Function for shutting down specified T1 VMs' interfaces that are connected to the lower_tor_host.

    Args:
        lower_tor_host (object): Host object for lower_tor.
        nbrhosts (dict): Dict returned by the nbrhosts fixture.
        tbinfo (dict): Testbed info from the tbinfo fixture.

    Yields:
        function: A function for shutting down specified T1 VMs interfaces connected to lower_tor_host.
    """
    down_intfs = []

    def shutdown(vm_names=None):
        logger.info('Shutdown T1 VM ports connected to lower_tor')
        down_intfs.extend(_shutdown_t1_tor_intfs(lower_tor_host, nbrhosts, tbinfo, vm_names))

    yield shutdown

    logger.info('Recover T1 VM ports connected to lower_tor')
    for eos_host, vm_intf in down_intfs:
        eos_host.no_shutdown(vm_intf)


@pytest.fixture
def shutdown_t1_tor_intfs(upper_tor_host, lower_tor_host, nbrhosts, tbinfo):
    """Function for shutting down specified T1 VMs' interfaces that are connected to the upper_tor_host.

    Args:
        upper_tor_host (object): Host object for upper_tor.
        lower_tor_host (object): Host object for lower_tor.
        nbrhosts (dict): Dict returned by the nbrhosts fixture.
        tbinfo (dict): Testbed info from the tbinfo fixture.

    Yields:
        function: A function for shutting down specified T1 VMs interfaces connected to upper_tor_host.
    """
    down_intfs = []

    def shutdown(vm_names=None, upper=False, lower=False):
        if not upper and not lower:
            logger.info('lower=False and upper=False, no T1 VM interface will be shutdown.')

        if upper:
            logger.info('Shutdown T1 VM ports connected to upper_tor')
            down_intfs.extend(_shutdown_t1_tor_intfs(upper_tor_host, nbrhosts, tbinfo, vm_names))

        if lower:
            logger.info('Shutdown T1 VM ports connected to lower_tor')
            down_intfs.extend(_shutdown_t1_tor_intfs(lower_tor_host, nbrhosts, tbinfo, vm_names))

    yield shutdown

    logger.info('Recover T1 VM ports connected to tor')
    for eos_host, vm_intf in down_intfs:
        eos_host.no_shutdown(vm_intf)


def mux_cable_server_ip(dut):
    """Function for retrieving all ip of servers connected to mux_cable

    Args:
        dut: The host object

    Returns:
        A dict: {"Ethernet12" : {"server_ipv4":"192.168.0.4/32", "server_ipv6":"fc02:1000::4/128"}, ....}
    """
    mux_cable_config = dut.shell("sonic-cfggen -d  --var-json 'MUX_CABLE'")['stdout']
    return json.loads(mux_cable_config)


def check_tunnel_balance(ptfhost, standby_tor_mac, vlan_mac, active_tor_ip, standby_tor_ip, selected_port, target_server_ip, target_server_port, ptf_portchannel_indices):
    """
    Function for testing traffic distribution among all avtive T1.
    A test script will be running on ptf to generate traffic to standby interface, and the traffic will be forwarded to
    active ToR. The running script will capture all traffic and verify if these packets are distributed evenly.
    Args:
        ptfhost: The ptf host connected to current testbed
        standby_tor_mac: MAC address of the standby ToR
        vlan_mac: MAC address of Vlan (For verifying packet)
        active_tor_ip: IP Address of Loopback0 of active ToR (For verifying packet)
        standby_tor_ip: IP Address of Loopback0 of standby ToR (For verifying packet)
        target_server_ip: The IP address of server for testing. The mux cable connected to this server must be standby
        target_server_port: PTF port indice on which server is connected
        ptf_portchannel_indices: A dict, the mapping from portchannel to ptf port indices
    Returns:
        None.
    """
    HASH_KEYS = ["src-port", "dst-port", "src-ip"]
    params = {
        "server_ip": target_server_ip,
        "server_port": target_server_port,
        "standby_tor_mac": standby_tor_mac,
        "vlan_mac": vlan_mac,
        "active_tor_ip": active_tor_ip,
        "standby_tor_ip": standby_tor_ip,
        "ptf_portchannel_indices": ptf_portchannel_indices,
        "hash_key_list": HASH_KEYS
    }
    logging.info("run ptf test for verifying IPinIP tunnel balance")
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/ip_in_ip_tunnel_test.{}.log".format(timestamp)
    logging.info("PTF log file: %s" % log_file)
    ptf_runner(ptfhost,
               "ptftests",
               "ip_in_ip_tunnel_test.IpinIPTunnelTest",
               platform_dir="ptftests",
               params=params,
               log_file=log_file,
               qlen=2000,
               socket_recv_size=16384)


def generate_hashed_packet_to_server(ptfadapter, duthost, hash_key, target_server_ip):
    """
    Generate a packet to server based on hash.
    The value of field in packet is filled with random value according to hash_key
    """
    src_mac = ptfadapter.dataplane.get_mac(0, 0)
    ip_dst = target_server_ip
    SRC_IP_RANGE = [unicode('1.0.0.0'), unicode('200.255.255.255')]
    ip_src = random_ip(SRC_IP_RANGE[0], SRC_IP_RANGE[1]) if 'src-ip' in hash_key else SRC_IP_RANGE[0]
    sport = random.randint(1, 65535) if 'src-port' in hash_key else 1234
    dport = random.randint(1, 65535) if 'dst-port' in hash_key else 80
    dst_mac = duthost.facts["router_mac"]
    send_pkt = testutils.simple_tcp_packet(pktlen=128,
                        eth_dst=dst_mac,
                        eth_src=src_mac,
                        dl_vlan_enable=False,
                        vlan_vid=0,
                        vlan_pcp=0,
                        ip_src=ip_src,
                        ip_dst=ip_dst,
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ip_ttl=64)
    exp_pkt = mask.Mask(send_pkt)
    exp_pkt.set_do_not_care_scapy(scapyall.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(scapyall.Ether, "src")
    exp_pkt.set_do_not_care_scapy(scapyall.IP, "ttl")
    exp_pkt.set_do_not_care_scapy(scapyall.IP, "chksum")

    inner_packet = send_pkt[IP]
    inner_packet.ttl = inner_packet.ttl - 1
    exp_tunnel_pkt = testutils.simple_ipv4ip_packet(
        eth_dst=dst_mac,
        eth_src=src_mac,
        ip_src="10.1.0.32",
        ip_dst="10.1.0.33",
        inner_frame=inner_packet
    )
    send_pkt.ttl = 64
    exp_tunnel_pkt[TCP] = inner_packet[TCP]
    exp_tunnel_pkt = mask.Mask(exp_tunnel_pkt)
    exp_tunnel_pkt.set_do_not_care_scapy(scapyall.Ether, "dst")
    exp_tunnel_pkt.set_do_not_care_scapy(scapyall.Ether, "src")
    exp_tunnel_pkt.set_do_not_care_scapy(scapyall.IP, "id") # since src and dst changed, ID would change too
    exp_tunnel_pkt.set_do_not_care_scapy(scapyall.IP, "ttl") # ttl in outer packet is set to 255
    exp_tunnel_pkt.set_do_not_care_scapy(scapyall.IP, "chksum") # checksum would differ as the IP header is not the same

    return send_pkt, exp_pkt, exp_tunnel_pkt


def random_ip(begin, end):
    """
    Generate a random IP from given ip range
    """
    length = int(ipaddress.ip_address(end)) - int(ipaddress.ip_address(begin))
    return str(ipaddress.ip_address(begin) + random.randint(0, length))


def count_matched_packets_all_ports(ptfadapter, exp_packet, exp_tunnel_pkt, ports=[], device_number=0, timeout=None, count=1):
    """
    Receive all packets on all specified ports and count how many expected packets were received.
    """
    if timeout is None:
        timeout = ptf.ptfutils.default_timeout
    if timeout <= 0:
        raise Exception("%s() requires positive timeout value." % sys._getframe().f_code.co_name)

    start_time = time.time()
    port_packet_count = dict()
    packet_count = 0
    while True:
        if (time.time() - start_time) > timeout:
            break

        result = testutils.dp_poll(ptfadapter, device_number=device_number, timeout=timeout)
        if isinstance(result, ptfadapter.dataplane.PollSuccess):
            if ((result.port in ports) and
                (ptf.dataplane.match_exp_pkt(exp_packet, result.packet) or
                ptf.dataplane.match_exp_pkt(exp_tunnel_pkt, result.packet))):
                port_packet_count[result.port] = port_packet_count.get(result.port, 0) + 1
                packet_count += 1
                if packet_count == count:
                    return port_packet_count
        else:
            break

    return port_packet_count


def check_nexthops_balance(rand_selected_dut,
    ptfadapter,
    dst_server_ipv4,
    tbinfo,
    downlink_ints,
    nexthops_count):
    HASH_KEYS = ["src-port", "dst-port", "src-ip"]
    # expect this packet to be sent to downlinks (active mux) and uplink (stanby mux)
    expected_downlink_ports =  [get_ptf_server_intf_index(rand_selected_dut, tbinfo, iface) for iface in downlink_ints]
    expected_uplink_ports = list()
    expected_uplink_portchannels = list()
    portchannel_ports = get_t1_ptf_pc_ports(rand_selected_dut, tbinfo)
    for pc, intfs in portchannel_ports.items():
        expected_uplink_portchannels.append(pc)
        for member in intfs:
            expected_uplink_ports.append(int(member.strip("eth")))
    logging.info("Expecting packets in downlink ports {}".format(expected_downlink_ports))
    logging.info("Expecting packets in uplink ports {}".format(expected_uplink_ports))

    ptf_t1_intf = random.choice(get_t1_ptf_ports(rand_selected_dut, tbinfo))
    port_packet_count = dict()
    for _ in range(10000):
        send_packet, exp_pkt, exp_tunnel_pkt = generate_hashed_packet_to_server(ptfadapter, rand_selected_dut, HASH_KEYS, dst_server_ipv4)
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), send_packet, count=1)
        # expect ECMP hashing to work and distribute downlink traffic evenly to every nexthop
        all_allowed_ports = expected_downlink_ports + expected_uplink_ports
        ptf_port_count = count_matched_packets_all_ports(ptfadapter,
                                            exp_packet=exp_pkt,
                                            exp_tunnel_pkt=exp_tunnel_pkt,
                                            ports=all_allowed_ports,
                                            timeout=0.1,
                                            count=1)

        for ptf_idx, pkt_count in ptf_port_count.items():
            port_packet_count[ptf_idx] = port_packet_count.get(ptf_idx, 0) + pkt_count

    logging.info("Received packets in ports: {}".format(str(port_packet_count)))
    expect_packet_num = 10000 // nexthops_count
    for downlink_int in expected_downlink_ports:
        # ECMP validation:
        pkt_num_lo = expect_packet_num * (1.0 - 0.25)
        pkt_num_hi = expect_packet_num * (1.0 + 0.25)
        count = port_packet_count.get(downlink_int, 0)
        logging.info("Packets received on downlink port {}: {}".format(downlink_int, count))
        if count < pkt_num_lo or count > pkt_num_hi:
            balance = False
            pt_assert(balance, "Packets not evenly distributed on downlink port {}".format(downlink_int))

    if len(downlink_ints) < nexthops_count:
        # Some nexthop is now connected to standby mux, and the packets will be sent towards portchanel ints
        # Hierarchical ECMP validation (in case of standby MUXs):
        # Step 1: Calculate total uplink share.
        total_uplink_share = expect_packet_num * (nexthops_count - len(expected_downlink_ports))
        # Step 2: Divide uplink share among all portchannels
        expect_packet_num = total_uplink_share // len(expected_uplink_portchannels)
        pkt_num_lo = expect_packet_num * (1.0 - 0.25)
        pkt_num_hi = expect_packet_num * (1.0 + 0.25)
        # Step 3: Check if uplink distribution (hierarchical ECMP) is balanced
        for pc, intfs in portchannel_ports.items():
            count = 0
            # Collect the packets count within a single portchannel
            for member in intfs:
                uplink_int = int(member.strip("eth"))
                count = count + port_packet_count.get(uplink_int, 0)
            logging.info("Packets received on portchannel {}: {}".format(pc, count))

            if count < pkt_num_lo or count > pkt_num_hi:
                balance = False
                pt_assert(balance, "Hierarchical ECMP failed: packets not evenly distributed on portchannel {}".format(
                    pc))


def verify_upstream_traffic(host, ptfadapter, tbinfo, itfs, server_ip, pkt_num = 100, drop = False):
    """
    @summary: Helper function for verifying upstream packets
    @param host: The dut host
    @param ptfadapter: The ptfadapter fixture
    @param tbinfo: The tbinfo fixture
    @param ifts: The interface name on DUT
    @param server_ip: The IP address of server
    @param pkt_num: The number of packets to generete and tx
    @param drop: Packets are expected to be dropped if drop is True, and vice versa
    @return: No return value. An exception will be raised if verify fails.
    """
    random_ip = generate_ip_through_default_route(host).split('/')[0]
    vlan_table = host.get_running_config_facts()['VLAN']
    vlan_name = list(vlan_table.keys())[0]
    vlan_mac = host.get_dut_iface_mac(vlan_name)
    router_mac = host.facts['router_mac']
    mg_facts = host.get_extended_minigraph_facts(tbinfo)
    tx_port = mg_facts['minigraph_ptf_indices'][itfs]
    eth_src = ptfadapter.dataplane.get_mac(0, tx_port)
    # Generate packets from server to a random IP address, which goes default routes
    pkt = testutils.simple_ip_packet(eth_src=eth_src,
                                    eth_dst=vlan_mac,
                                    ip_src=server_ip,
                                    ip_dst=random_ip)
    # Generate packet forwarded to portchannels
    pkt_copy = pkt.copy()
    pkt_copy[Ether].src = router_mac

    exp_pkt = mask.Mask(pkt_copy)
    exp_pkt.set_do_not_care_scapy(Ether, "dst")

    exp_pkt.set_do_not_care_scapy(IP, "dst")
    exp_pkt.set_do_not_care_scapy(IP, "ihl")
    exp_pkt.set_do_not_care_scapy(IP, "tos")
    exp_pkt.set_do_not_care_scapy(IP, "len")
    exp_pkt.set_do_not_care_scapy(IP, "id")
    exp_pkt.set_do_not_care_scapy(IP, "flags")
    exp_pkt.set_do_not_care_scapy(IP, "frag")
    exp_pkt.set_do_not_care_scapy(IP, "ttl")
    exp_pkt.set_do_not_care_scapy(IP, "proto")
    exp_pkt.set_do_not_care_scapy(IP, "chksum")

    exp_pkt.set_ignore_extra_bytes()

    port_channels = get_t1_ptf_pc_ports(host, tbinfo)
    rx_ports = []
    for v in port_channels.values():
        rx_ports += v
    rx_ports = [int(x.strip('eth')) for x in rx_ports]

    logger.info("Verifying upstream traffic. packet number = {} interface = {} server_ip = {} expect_drop = {}".format(pkt_num, itfs, server_ip, drop))
    for i in range(0, pkt_num):
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, tx_port, pkt, count=1)
        if drop:
            testutils.verify_no_packet_any(ptfadapter, exp_pkt, rx_ports)
        else:
            testutils.verify_packet_any_port(ptfadapter, exp_pkt, rx_ports)


def get_crm_nexthop_counter(host):
    """
    Get used crm nexthop counter
    """
    crm_facts = host.get_crm_facts()
    return crm_facts['resources']['ipv4_nexthop']['used']


def dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo):
    """
    @summary: A helper function for collecting info of dualtor testbed.
    @param ptfhost: The ptf host fixture
    @param rand_selected_dut: The randomly selected dut host, will be set as standby ToR
    @param rand_unselected_dut: The other dut in dualtor testbed, will be set as active ToR
    @param tbinfo: The tbinfo fixture
    @return: A dict, can be used as the argument of check_tunnel_balance
    """
    active_tor = rand_unselected_dut
    standby_tor = rand_selected_dut
    standby_tor_mg_facts = standby_tor.get_extended_minigraph_facts(tbinfo)

    def _get_iface_ip(mg_facts, ifacename):
        for loopback in mg_facts['minigraph_lo_interfaces']:
            if loopback['name'] == ifacename and ipaddress.ip_address(loopback['addr']).version == 4:
                return loopback['addr']

    res = {}
    res['ptfhost'] = ptfhost
    res['standby_tor_mac'] = standby_tor.facts['router_mac']
    vlan_name = standby_tor_mg_facts['minigraph_vlans'].keys()[0]
    res['vlan_mac'] = standby_tor.get_dut_iface_mac(vlan_name)
    res['standby_tor_ip'] = _get_iface_ip(standby_tor_mg_facts, 'Loopback0')

    if 't0' in tbinfo["topo"]["name"]:
        # For mocked dualtor
        res['active_tor_ip'] = str(ipaddress.ip_address(res['standby_tor_ip']) + 1)
        # For mocked dualtor, routes to peer switch is static 
        res['ptf_portchannel_indices'] = get_t1_active_ptf_ports(standby_tor, tbinfo)
    else:
        active_tor_mg_facts = active_tor.get_extended_minigraph_facts(tbinfo)
        res['active_tor_ip'] = _get_iface_ip(active_tor_mg_facts, 'Loopback0')
        res['ptf_portchannel_indices'] = get_t1_bgp_up_ptf_ports(standby_tor, tbinfo)

    servers = mux_cable_server_ip(standby_tor)
    random_server_iface = random.choice(servers.keys())

    res['selected_port'] = random_server_iface
    res['target_server_ip'] = servers[random_server_iface]['server_ipv4'].split('/')[0]
    res['target_server_port'] = standby_tor_mg_facts['minigraph_ptf_indices'][random_server_iface]

    logger.debug("dualtor info is generated {}".format(res))
    return res


def show_arp(duthost, neighbor_addr):
    """Show arp table entry for neighbor."""
    command = "/usr/sbin/arp -n %s" % neighbor_addr
    output = duthost.shell(command)["stdout_lines"]
    if "no entry" in output[0]:
        return {}
    headers = ("address", "hwtype", "hwaddress", "flags", "iface")
    return dict(zip(headers, output[1].split()))


@contextlib.contextmanager
def flush_neighbor(duthost, neighbor, restore=True):
    """Flush neighbor entry for server in duthost."""
    neighbor_info = show_arp(duthost, neighbor)
    logging.info("neighbor entry for %s: %s", neighbor, neighbor_info)
    assert neighbor_info, "No neighbor info for neighbor %s" % neighbor
    logging.info("remove neighbor entry for %s", neighbor)
    duthost.shell("ip -4 neighbor del %s dev %s" % (neighbor, neighbor_info["iface"]))
    try:
        yield
    finally:
        if restore:
            logging.info("restore neighbor entry for %s", neighbor)
            duthost.shell("ip -4 neighbor replace {address} lladdr {hwaddress} dev {iface}".format(**neighbor_info))


@pytest.fixture(scope="function")
def rand_selected_interface(rand_selected_dut):
    """Select a random interface to test."""
    tor = rand_selected_dut
    server_ips = mux_cable_server_ip(tor)
    iface = str(random.choice(server_ips.keys()))
    logging.info("select DUT interface %s to test.", iface)
    return iface, server_ips[iface]


def show_muxcable_status(duthost):
    """
    Show muxcable status and parse into a dict
    """
    command = "show muxcable status"
    output = duthost.shell(command)["stdout_lines"]
    
    ret = {}
    for i in range(2, len(output)):
        port, status, health = output[i].split()
        ret[port] = {'status': status, 'health': health}

    return ret


def build_packet_to_server(duthost, ptfadapter, target_server_ip):
    """Build packet and expected mask packet destinated to server."""
    pkt_dscp = random.choice(range(0, 33))
    pkt_ttl = random.choice(range(3, 65))
    pkt = testutils.simple_ip_packet(
        eth_dst=duthost.facts["router_mac"],
        eth_src=ptfadapter.dataplane.get_mac(0, 0),
        ip_src="1.1.1.1",
        ip_dst=target_server_ip,
        ip_dscp=pkt_dscp,
        ip_ttl=pkt_ttl
    )
    logging.info(
        "the packet destinated to server %s:\n%s",
        target_server_ip,
        dump_scapy_packet_show_output(pkt)
    )
    exp_pkt = mask.Mask(pkt)
    exp_pkt.set_do_not_care_scapy(scapyall.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(scapyall.Ether, "src")
    exp_pkt.set_do_not_care_scapy(scapyall.IP, "tos")
    exp_pkt.set_do_not_care_scapy(scapyall.IP, "ttl")
    exp_pkt.set_do_not_care_scapy(scapyall.IP, "chksum")
    return pkt, exp_pkt


@contextlib.contextmanager
def crm_neighbor_checker(duthost):
    crm_facts_before = duthost.get_crm_facts()
    ipv4_neighbor_before = crm_facts_before["resources"]["ipv4_neighbor"]["used"]
    logging.info("ipv4 neighbor before test: %s", ipv4_neighbor_before)
    yield
    time.sleep(crm_facts_before["polling_interval"])
    crm_facts_after = duthost.get_crm_facts()
    ipv4_neighbor_after = crm_facts_after["resources"]["ipv4_neighbor"]["used"]
    logging.info("ipv4 neighbor after test: %s", ipv4_neighbor_after)
    if ipv4_neighbor_after != ipv4_neighbor_before:
        raise ValueError("ipv4 neighbor differs, before %s, after %s", ipv4_neighbor_before, ipv4_neighbor_after)


def get_ptf_server_intf_index(tor, tbinfo, iface):
    """Get the index of ptf ToR-facing interface on ptf."""
    mg_facts = tor.get_extended_minigraph_facts(tbinfo)
    return mg_facts["minigraph_ptf_indices"][iface]


def get_interface_server_map(torhost, count):
    server_ips = mux_cable_server_ip(torhost)
    interfaces = [str(_) for _ in server_ips.keys()]
    interfaces = interfaces[:count]
    iface_server_map = {_: server_ips[_] for _ in interfaces}
    logging.info("select DUT interface %s to test.", iface_server_map)
    return iface_server_map


def add_nexthop_routes(standby_tor, route_dst, nexthops=None):
    """
    Add static routes to reach route_dst via nexthop.
    The function is similar with fixture apply_dual_tor_peer_switch_route, but we can't use the fixture directly
    """
    logging.info("Applying route on {} to dst {}".format(standby_tor.hostname, route_dst))
    bgp_neighbors = standby_tor.bgp_facts()['ansible_facts']['bgp_neighbors'].keys()

    ipv4_neighbors = []

    for neighbor in bgp_neighbors:
        if ipaddress.ip_address(neighbor).version == 4:
            ipv4_neighbors.append(neighbor)

    nexthop_str = ''
    if nexthops is None:
        for neighbor in ipv4_neighbors:
            nexthop_str += 'nexthop via {} '.format(neighbor)
    else:
        for nexthop in nexthops:
            nexthop_str += 'nexthop via {} '.format(nexthop)

    # Use `ip route replace` in case a rule already exists for this IP
    # If there are no pre-existing routes, equivalent to `ip route add`
    route_cmd = 'ip route replace {}/32 {}'.format(route_dst, nexthop_str)
    standby_tor.shell(route_cmd)
    logging.info("Route added to {}: {}".format(standby_tor.hostname, route_cmd))


def remove_static_routes(standby_tor, active_tor_loopback_ip):
    """
    Remove static routes for active tor
    """
    logger.info("Removing dual ToR peer switch static route")
    standby_tor.shell('ip route del {}/32'.format(active_tor_loopback_ip), module_ignore_errors=True)
