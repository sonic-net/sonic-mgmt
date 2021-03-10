import contextlib
import logging
import pytest
import random
import json
from datetime import datetime
from tests.ptf_runner import ptf_runner

from natsort import natsorted
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.helpers.dut_ports import encode_dut_port_name
from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR

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


def update_mux_configs_and_config_reload(dut, state):
    """
    @summary: Update config_db.json, and then load with 'config reload'
            Please note that this is a general method, and caller must
            backup config_db.json and do a restore at the end.
    @param dut: The DUT we are testing against
    @param state: A str, auto|active|standby
    """
    STATE_LIST = ['auto', 'active', 'standby']
    pytest_assert(state in STATE_LIST, "state should be one of {}".format(STATE_LIST))

    mux_cable_config = dut.shell("sonic-cfggen -d  --var-json 'MUX_CABLE'")['stdout']
    pytest_assert(len(mux_cable_config.strip()) != 0, "No mux_cable configuration is found in config_db")

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
            specified, the function will shutdown all the fanout interfaces that are connected to the tor_host DUT.
            Defaults to None.

    Returns:
        list of tuple: Return a list of tuple. Each tuple has two items. The first item is the host object for fanout.
            The second item is the fanout interface that has been shutdown. The returned list makes it easy to recover
            the interfaces.
    """
    down_intfs = []

    if not dut_intfs:
        # If no interface is specified, shutdown all ports
        mg_facts = tor_host.get_extended_minigraph_facts(tbinfo)
        dut_intfs = mg_facts['minigraph_ports'].keys()

    dut_intfs = natsorted(dut_intfs)

    full_dut_fanout_port_map = {}
    for fanout_host in tor_fanouthosts.values():
        for encoded_dut_intf, fanout_intf in fanout_host.host_to_fanout_port_map.items():
            full_dut_fanout_port_map[encoded_dut_intf] = {
                'fanout_host': fanout_host,
                'fanout_intf': fanout_intf
            }

    logger.debug('full_dut_fanout_port_map: {}'.format(full_dut_fanout_port_map))

    for dut_intf in dut_intfs:
        encoded_dut_intf = encode_dut_port_name(tor_host.hostname, dut_intf)
        if encoded_dut_intf in full_dut_fanout_port_map:
            fanout_host = full_dut_fanout_port_map[encoded_dut_intf]['fanout_host']
            fanout_intf = full_dut_fanout_port_map[encoded_dut_intf]['fanout_intf']
            fanout_host.shutdown(fanout_intf)
            down_intfs.append((fanout_host, fanout_intf))
        else:
            logger.error('No dut intf "{}" in full_dut_fanout_port_map'.format(encoded_dut_intf))

    return down_intfs


@pytest.fixture
def shutdown_fanout_upper_tor_intfs(upper_tor_host, upper_tor_fanouthosts, tbinfo):
    """Fixture for shutting down fanout interfaces connected to specified upper_tor interfaces.

    Args:
        upper_tor_host (object): Host object for upper_tor.
        upper_tor_fanouthosts (dict): Key is fanout hostname, value is fanout host object.
        tbinfo (dict): Testbed info from the tbinfo fixture.

    Yields:
        function: A function for shutting down fanout interfaces connected to specified upper_tor interfaces
    """
    down_intfs = []

    def shutdown(dut_intfs=None):
        logger.info('Shutdown fanout ports connected to upper_tor')
        down_intfs.extend(_shutdown_fanout_tor_intfs(upper_tor_host, upper_tor_fanouthosts, tbinfo, dut_intfs))

    yield shutdown

    logger.info('Recover fanout ports connected to upper_tor')
    for fanout_host, fanout_intf in down_intfs:
        fanout_host.no_shutdown(fanout_intf)


@pytest.fixture
def shutdown_fanout_lower_tor_intfs(lower_tor_host, lower_tor_fanouthosts, tbinfo):
    """Fixture for shutting down fanout interfaces connected to specified lower_tor interfaces.

    Args:
        lower_tor_host (object): Host object for lower_tor.
        lower_tor_fanouthosts (dict): Key is fanout hostname, value is fanout host object.
        tbinfo (dict): Testbed info from the tbinfo fixture.

    Yields:
        function: A function for shutting down fanout interfaces connected to specified lower_tor interfaces
    """
    down_intfs = []

    def shutdown(dut_intfs=None):
        logger.info('Shutdown fanout ports connected to lower_tor')
        down_intfs.extend(_shutdown_fanout_tor_intfs(lower_tor_host, lower_tor_fanouthosts, tbinfo, dut_intfs))

    yield shutdown

    logger.info('Recover fanout ports connected to lower_tor')
    for fanout_host, fanout_intf in down_intfs:
        fanout_host.no_shutdown(fanout_intf)


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


def check_tunnel_balance(ptfhost, active_tor_mac, standby_tor_mac, vlan_mac, active_tor_ip, standby_tor_ip, targer_server_ip, target_server_port, ptf_portchannel_indices):
    """
    Function for testing traffic distribution among all avtive T1.
    A test script will be running on ptf to generate traffic to standby interface, and the traffic will be forwarded to
    active ToR. The running script will capture all traffic and verify if these packets are distributed evenly.
    Args:
        ptfhost: The ptf host connected to current testbed
        active_tor_mac: MAC address of active ToR
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
        "server_ip": targer_server_ip,
        "server_port": target_server_port,
        "active_tor_mac": active_tor_mac,
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


def get_crm_nexthop_counter(host):
    """
    Get used crm nexthop counter
    """
    crm_facts = host.get_crm_facts()
    return crm_facts['resources']['ipv4_nexthop']['used']


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
