import contextlib
import ipaddress
import logging
import itertools
import pytest
import random
import time
import json
import os
import ptf
import re
import string
import sys
import six
import tabulate

from collections import defaultdict
from datetime import datetime
from natsort import natsorted
from ptf import mask
from ptf import testutils
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6

from tests.common import constants
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.helpers.dut_ports import encode_dut_port_name
from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR
from tests.common.dualtor.nic_simulator_control import restart_nic_simulator                            # noqa F401
from tests.common.dualtor.nic_simulator_control import nic_simulator_flap_counter                       # noqa F401
from tests.common.dualtor.mux_simulator_control import simulator_flap_counter                           # noqa F401
from tests.common.dualtor.dual_tor_common import ActiveActivePortID
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.dual_tor_common import cable_type                                             # noqa F401
from tests.common.dualtor.dual_tor_common import active_standby_ports                                   # noqa F401
from tests.common.dualtor.dual_tor_common import active_active_ports                                    # noqa F401
from tests.common.dualtor.dual_tor_common import mux_config                                             # noqa F401
from tests.common.helpers.generators import generate_ip_through_default_route
from tests.common.utilities import dump_scapy_packet_show_output, get_intf_by_sub_intf, is_ipv4_address, wait_until
from tests.ptf_runner import ptf_runner


__all__ = ['tor_mux_intf', 'tor_mux_intfs', 'ptf_server_intf', 't1_upper_tor_intfs', 't1_lower_tor_intfs',
           'upper_tor_host', 'lower_tor_host', 'force_active_tor', 'force_standby_tor',
           'config_active_active_dualtor_active_standby', 'validate_active_active_dualtor_setup',
           'setup_standby_ports_on_rand_selected_tor',
           'setup_standby_ports_on_rand_unselected_tor',
           'setup_standby_ports_on_non_enum_rand_one_per_hwsku_frontend_host_m',
           'setup_standby_ports_on_rand_unselected_tor_unconditionally',
           'setup_standby_ports_on_non_enum_rand_one_per_hwsku_frontend_host_m_unconditionally',
           ]

logger = logging.getLogger(__name__)

ARP_RESPONDER_PY = "arp_responder.py"
SCRIPTS_SRC_DIR = "scripts/"
OPT_DIR = "/opt"

EOS_RETRY_MAX = 3
RETRY_TIMEOUT_SECONDS = 5


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
    for pc in list(config_facts['PORTCHANNEL'].keys()):
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
    for k, v in list(config_facts['PORTCHANNEL'].items()):
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
    for k, v in list(bgp_facts['bgp_neighbors'].items()):
        if v['state'] == 'established':
            for line in ip_interfaces:
                if k in line:
                    portchannels.append(line.split()[0])
                    break

    ptf_portchannel_intfs = {}
    for k, v in list(config_facts['PORTCHANNEL'].items()):
        if k in portchannels:
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
    pt_assert(state in STATE_LIST, "state should be one of {}".format(STATE_LIST))

    mux_cable_config = dut.shell("sonic-cfggen -d  --var-json 'MUX_CABLE'")['stdout']
    pt_assert(len(mux_cable_config.strip()) != 0, "No mux_cable configuration is found in config_db")

    # Update mux_cable state and dump to a temp file
    mux_cable_config_json = json.loads(mux_cable_config)
    for _, config in list(mux_cable_config_json.items()):
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


@pytest.fixture
def force_standby_tor():
    """
    @summary: Manually set dut host to the standby tor for intf
    @param dut: The duthost for which to toggle mux
    @param intf: One or a list of names of interface or 'all' for all interfaces
    """
    forced_intfs = []

    def force_standby_tor_fn(dut, intf):
        logger.info('Setting {} as standby for intfs {}'.format(dut, intf))
        if type(intf) == str:
            cmds = ["config muxcable mode standby {}; true".format(intf)]
            forced_intfs.append((dut, intf))
        else:
            cmds = []
            for i in intf:
                forced_intfs.append((dut, i))
                cmds.append("config muxcable mode standby {}; true".format(i))
        dut.shell_cmds(cmds=cmds, continue_on_fail=True)

    yield force_standby_tor_fn

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
    for fanout_hostname, fanout_host in list(fanouthosts.items()):
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


fanout_intfs_to_recover = defaultdict(list)


def _shutdown_fanout_tor_intfs(tor_host, tor_fanouthosts, tbinfo, dut_intfs=None):
    """Helper function for shutting down fanout interfaces that are connected to specified DUT interfaces.

    Args:
        tor_host (object): Host object for the ToR DUT.
        tor_fanouthosts (dict): Key is fanout hostname, value is fanout host object.
        tbinfo (dict): Testbed info from the tbinfo fixture.
        dut_intfs (list, optional): List of DUT interface names,
            for example: ['Ethernet0', 'Ethernet4']. All the
            fanout interfaces that are connected to the specified DUT interfaces will be shutdown.
            If dut_intfs is not specified, the function will shutdown all the fanout interfaces
            that are connected to the tor_host DUT and in a VLAN.
            Defaults to None.

    Returns:
        dict (fanouthost: list): Each key is a fanout host, and the corresponding value
            is the interfaces that were shut down on that host device.
    """
    if not dut_intfs:
        # If no interface is specified, shutdown all VLAN ports
        vlan_intfs = []
        vlan_member_table = tor_host.get_running_config_facts()['VLAN_MEMBER']
        for vlan_members in list(vlan_member_table.values()):
            vlan_intfs.extend(list(vlan_members.keys()))

        dut_intfs = vlan_intfs

    dut_intfs = natsorted(dut_intfs)

    full_dut_fanout_port_map = {}
    for fanout_host in list(tor_fanouthosts.values()):
        for encoded_dut_intf, fanout_intf in list(fanout_host.host_to_fanout_port_map.items()):
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

    for fanout_host, intf_list in list(fanout_shut_intfs.items()):
        fanout_host.shutdown(intf_list)
        fanout_intfs_to_recover[fanout_host].extend(intf_list)

    oper_up_dut_intf = _oper_up_dut_intfs(tor_host, dut_intfs)
    retry_cnt = 0

    while oper_up_dut_intf and retry_cnt < EOS_RETRY_MAX:

        retry_fanout_shut_intfs = defaultdict(list)
        for dut_intf in oper_up_dut_intf:
            encoded_dut_intf = encode_dut_port_name(tor_host.hostname, dut_intf)
            if encoded_dut_intf in full_dut_fanout_port_map:
                fanout_host = full_dut_fanout_port_map[encoded_dut_intf]['fanout_host']
                fanout_intf = full_dut_fanout_port_map[encoded_dut_intf]['fanout_intf']
                retry_fanout_shut_intfs[fanout_host].append(fanout_intf)

        for fanout_host, intf_list in list(retry_fanout_shut_intfs.items()):
            fanout_host.shutdown(intf_list)
            fanout_intfs_to_recover[fanout_host].extend(intf_list)

        retry_cnt += 1
        time.sleep(RETRY_TIMEOUT_SECONDS)

        oper_up_dut_intf = _oper_up_dut_intfs(tor_host, dut_intfs)

    return fanout_shut_intfs


def _oper_up_dut_intfs(tor_host, dut_intfs):
    """Helper function for checking if fanout interfaces that are connected to specified DUT
    are shutdown.
    """

    logger.debug("dut_intfs: {}".format(dut_intfs))

    intfs_status = tor_host.show_and_parse("show interface status")
    logger.debug("show interface status: {}".format(intfs_status))

    up_dut_intfs = [intf['interface'] for intf in intfs_status
                    if intf['interface'] in dut_intfs and intf['oper'] == 'up']
    logger.debug("up_dut_intfs: {}".format(up_dut_intfs))

    return up_dut_intfs


@pytest.fixture
def shutdown_fanout_upper_tor_intfs(upper_tor_host, upper_tor_fanouthosts, tbinfo,
                                    cable_type, active_active_ports, active_standby_ports):     # noqa F811
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
    fanout_intfs_to_recover.clear()

    mux_ports = active_active_ports if cable_type == CableType.active_active else active_standby_ports

    def shutdown(dut_intfs=None):
        logger.info('Shutdown fanout ports connected to upper_tor')
        if dut_intfs is None:
            dut_intfs = mux_ports
        shut_fanouts.append(_shutdown_fanout_tor_intfs(upper_tor_host, upper_tor_fanouthosts, tbinfo, dut_intfs))

    yield shutdown

    logger.info('Recover fanout ports connected to upper_tor')

    for fanout_host, intf_list in list(fanout_intfs_to_recover.items()):
        fanout_host.no_shutdown(intf_list)
    fanout_intfs_to_recover.clear()


@pytest.fixture
def shutdown_fanout_lower_tor_intfs(lower_tor_host, lower_tor_fanouthosts, tbinfo,
                                    cable_type, active_active_ports, active_standby_ports):     # noqa F811
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
    fanout_intfs_to_recover.clear()

    mux_ports = active_active_ports if cable_type == CableType.active_active else active_standby_ports

    def shutdown(dut_intfs=None):
        logger.info('Shutdown fanout ports connected to lower_tor')
        if dut_intfs is None:
            dut_intfs = mux_ports
        shut_fanouts.append(_shutdown_fanout_tor_intfs(lower_tor_host, lower_tor_fanouthosts, tbinfo, dut_intfs))

    yield shutdown

    logger.info('Recover fanout ports connected to lower_tor')

    for fanout_host, intf_list in list(fanout_intfs_to_recover.items()):
        fanout_host.no_shutdown(intf_list)
    fanout_intfs_to_recover.clear()


@pytest.fixture
def shutdown_fanout_tor_intfs(upper_tor_host, upper_tor_fanouthosts, lower_tor_host, lower_tor_fanouthosts,
                              tbinfo, cable_type, active_active_ports, active_standby_ports):       # noqa F811
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
    fanout_intfs_to_recover.clear()

    mux_ports = active_active_ports if cable_type == CableType.active_active else active_standby_ports

    def shutdown(dut_intfs=None, upper=False, lower=False):
        if not upper and not lower:
            logger.info('lower=False and upper=False, no fanout interface will be shutdown.')
            return

        if dut_intfs is None:
            dut_intfs = mux_ports

        if upper:
            logger.info('Shutdown fanout ports connected to upper_tor')
            down_intfs.extend(_shutdown_fanout_tor_intfs(upper_tor_host, upper_tor_fanouthosts, tbinfo, dut_intfs))

        if lower:
            logger.info('Shutdown fanout ports connected to lower_tor')
            down_intfs.extend(_shutdown_fanout_tor_intfs(lower_tor_host, lower_tor_fanouthosts, tbinfo, dut_intfs))

    yield shutdown

    logger.info('Recover fanout ports connected to tor')
    for fanout_host, intf_list in list(fanout_intfs_to_recover.items()):
        fanout_host.no_shutdown(intf_list)
    fanout_intfs_to_recover.clear()


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

    for vm_name in natsorted(list(target_vms.keys())):
        eos_host = target_vms[vm_name]['host']
        vm_intfs = tbinfo['topo']['properties']['configuration'][vm_name]['interfaces']
        for vm_intf in natsorted(list(vm_intfs.keys())):
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


def _shutdown_tor_downlink_intfs(tor_host, dut_intfs=None):
    """Helper function for shutting down DUT downlink interfaces connected to fanout.

    Args:
        tor_host (object): Host object for the ToR DUT.
        dut_intfs (list, optional): List of DUT interface names, for example: ['Ethernet0', 'Ethernet4']. All
            downlink interfaces on DUT will be shutdown. If dut_intfs is not
            specified, the function will shutdown all DUT downlink interfaces.
            Defaults to None.

    Returns:
        dut_intfs (list): interfaces that were shut down on that host device.
    """
    if not dut_intfs:
        # If no interface is specified, shutdown all VLAN ports
        vlan_intfs = []
        vlan_member_table = tor_host.get_running_config_facts()['VLAN_MEMBER']
        for vlan_members in list(vlan_member_table.values()):
            vlan_intfs.extend(list(vlan_members.keys()))

        dut_intfs = vlan_intfs

    dut_intfs = natsorted(dut_intfs)

    logger.debug('dut_intfs: {}'.format(dut_intfs))

    tor_host.shutdown_multiple(dut_intfs)

    return dut_intfs


@pytest.fixture
def shutdown_upper_tor_downlink_intfs(upper_tor_host):
    """
    Fixture for shutting down upper tor downlink interfaces connected to fanout.

    Args:
        upper_tor_host (object): Host object for upper_tor.

    Yields:
        function: A function for shutting down upper tor downlink interfaces connected to fanout
    """
    shut_intfs = []

    def shutdown(dut_intfs=None):
        logger.info('Shutdown downlink interfaces in upper_tor')
        shut_intfs.extend(_shutdown_tor_downlink_intfs(upper_tor_host, dut_intfs))

    yield shutdown

    logger.info('Recover upper_tor downlink interfaces connected to fanout')

    upper_tor_host.no_shutdown_multiple(shut_intfs)


@pytest.fixture
def shutdown_lower_tor_downlink_intfs(lower_tor_host):
    """
    Fixture for shutting down lower tor downlink interfaces connected to fanout.

    Args:
        lower_tor_host (object): Host object for lower_tor.

    Yields:
        function: A function for shutting down lower tor downlink interfaces connected to fanout
    """
    shut_intfs = []

    def shutdown(dut_intfs=None):
        logger.info('Shutdown downlink interfaces in lower_tor')
        shut_intfs.extend(_shutdown_tor_downlink_intfs(lower_tor_host, dut_intfs))

    yield shutdown

    logger.info('Recover lower_tor downlink interfaces connected to fanout')

    lower_tor_host.no_shutdown_multiple(shut_intfs)


def mux_cable_server_ip(dut):
    """Function for retrieving all ip of servers connected to mux_cable

    Args:
        dut: The host object

    Returns:
        A dict: {"Ethernet12" : {"server_ipv4":"192.168.0.4/32", "server_ipv6":"fc02:1000::4/128"}, ....}
    """
    mux_cable_config = dut.shell("sonic-cfggen -d  --var-json 'MUX_CABLE'")['stdout']
    return json.loads(mux_cable_config)


def check_tunnel_balance(ptfhost, standby_tor_mac, vlan_mac, active_tor_ip,
                         standby_tor_ip, selected_port, target_server_ip,
                         target_server_ipv6, target_server_port, ptf_portchannel_indices,
                         completeness_level, check_ipv6=False, skip_traffic_test=False):
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
        check_ipv6: if True, check ipv6 traffic, if False, check ipv4 traffic
    Returns:
        None.
    """
    if skip_traffic_test is True:
        logging.info("Skip checking tunnel balance due to traffic test was skipped")
        return
    HASH_KEYS = ["src-port", "dst-port", "src-ip"]
    params = {
        "server_ip": target_server_ip,
        "server_port": target_server_port,
        "standby_tor_mac": standby_tor_mac,
        "vlan_mac": vlan_mac,
        "active_tor_ip": active_tor_ip,
        "standby_tor_ip": standby_tor_ip,
        "ptf_portchannel_indices": ptf_portchannel_indices,
        "hash_key_list": HASH_KEYS,
        "completeness_level": completeness_level
    }
    if check_ipv6:
        params["server_ip"] = target_server_ipv6

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
               socket_recv_size=16384,
               is_python3=True)


def generate_hashed_packet_to_server(ptfadapter, duthost, hash_key, target_server_ip, count=1):
    """
    Generate a packet to server based on hash.
    The value of field in packet is filled with random value according to hash_key
    """

    def _generate_hashed_ipv4_packet(src_mac, dst_mac, dst_ip, hash_key):
        SRC_IP_RANGE = ['1.0.0.0', '126.255.255.255']
        src_ip = random_ip(SRC_IP_RANGE[0], SRC_IP_RANGE[1]) if 'src-ip' in hash_key else SRC_IP_RANGE[0]
        sport = random.randint(1, 65535) if 'src-port' in hash_key else 1234
        dport = random.randint(1, 65535) if 'dst-port' in hash_key else 80
        send_pkt = testutils.simple_tcp_packet(
            pktlen=128,
            eth_dst=dst_mac,
            eth_src=src_mac,
            dl_vlan_enable=False,
            vlan_vid=0,
            vlan_pcp=0,
            ip_src=src_ip,
            ip_dst=dst_ip,
            tcp_sport=sport,
            tcp_dport=dport,
            ip_ttl=64
        )
        exp_pkt = mask.Mask(send_pkt)
        exp_pkt.set_do_not_care_scapy(Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(Ether, "src")
        exp_pkt.set_do_not_care_scapy(IP, "ttl")
        exp_pkt.set_do_not_care_scapy(IP, "chksum")

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
        exp_tunnel_pkt.set_do_not_care_scapy(Ether, "dst")
        exp_tunnel_pkt.set_do_not_care_scapy(Ether, "src")
        exp_tunnel_pkt.set_do_not_care_scapy(IP, "id")       # since src and dst changed, ID would change too
        exp_tunnel_pkt.set_do_not_care_scapy(IP, "ttl")      # ttl in outer packet is set to 255
        exp_tunnel_pkt.set_do_not_care_scapy(IP, "chksum")   # checksum would differ as the IP header is not the same
        exp_tunnel_pkt.set_do_not_care_scapy(IP, "flags")    # "Don't fragment" flag may be set in the outer header

        return send_pkt, exp_pkt, exp_tunnel_pkt

    def _generate_hashed_ipv6_packet(src_mac, dst_mac, dst_ip, hash_key):
        SRC_IP_RANGE = ['20D0:A800:0:00::', '20D0:FFFF:0:00::FFFF']
        src_ip = random_ip(SRC_IP_RANGE[0], SRC_IP_RANGE[1]) if 'src-ip' in hash_key else SRC_IP_RANGE[0]
        sport = random.randint(1, 65535) if 'src-port' in hash_key else 1234
        dport = random.randint(1, 65535) if 'dst-port' in hash_key else 80
        send_pkt = testutils.simple_tcpv6_packet(
            pktlen=128,
            eth_dst=dst_mac,
            eth_src=src_mac,
            dl_vlan_enable=False,
            ipv6_src=src_ip,
            ipv6_dst=dst_ip,
            ipv6_hlim=64,
            tcp_sport=sport,
            tcp_dport=dport
        )
        exp_pkt = mask.Mask(send_pkt)
        exp_pkt.set_do_not_care_scapy(Ether, "dst")
        exp_pkt.set_do_not_care_scapy(Ether, "src")
        exp_pkt.set_do_not_care_scapy(IPv6, "hlim")

        inner_packet = send_pkt[IPv6]
        inner_packet[IPv6].hlim -= 1
        exp_tunnel_pkt = testutils.simple_ipv4ip_packet(
            eth_dst=dst_mac,
            eth_src=src_mac,
            ip_src="10.1.0.32",
            ip_dst="10.1.0.33",
            inner_frame=inner_packet
        )
        send_pkt.hlim = 64
        exp_tunnel_pkt[TCP] = inner_packet[TCP]
        exp_tunnel_pkt = mask.Mask(exp_tunnel_pkt)
        exp_tunnel_pkt.set_do_not_care_scapy(Ether, "dst")
        exp_tunnel_pkt.set_do_not_care_scapy(Ether, "src")
        exp_tunnel_pkt.set_do_not_care_scapy(IP, "id")
        exp_tunnel_pkt.set_do_not_care_scapy(IP, "ttl")
        exp_tunnel_pkt.set_do_not_care_scapy(IP, "chksum")
        exp_tunnel_pkt.set_do_not_care_scapy(IP, "flags")

        return send_pkt, exp_pkt, exp_tunnel_pkt

    src_mac = ptfadapter.dataplane.get_mac(0, 0)
    dst_mac = duthost.facts["router_mac"]

    # initialize the packets cache
    if not hasattr(generate_hashed_packet_to_server, "packets_cache"):
        generate_hashed_packet_to_server.packets_cache = defaultdict(list)

    call_signature = (target_server_ip, tuple(hash_key))
    if len(generate_hashed_packet_to_server.packets_cache[call_signature]) < count:
        pkt_num = count - len(generate_hashed_packet_to_server.packets_cache[call_signature])
        for _ in range(pkt_num):
            if ipaddress.ip_address(six.text_type(target_server_ip)).version == 4:
                pkt_t = _generate_hashed_ipv4_packet(src_mac, dst_mac, target_server_ip, hash_key)
            else:
                pkt_t = _generate_hashed_ipv6_packet(src_mac, dst_mac, target_server_ip, hash_key)
            generate_hashed_packet_to_server.packets_cache[call_signature].append(pkt_t)

    return generate_hashed_packet_to_server.packets_cache[call_signature][:count]


def random_ip(begin, end):
    """
    Generate a random IP from given ip range
    """
    length = int(ipaddress.ip_address(end)) - int(ipaddress.ip_address(begin))
    return str(ipaddress.ip_address(begin) + random.randint(0, length))


def count_matched_packets_all_ports(ptfadapter, exp_packet, exp_tunnel_pkt,
                                    ports=[], device_number=0, timeout=None, count=1):
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


# behavior has changed with such that ecmp groups that span across multiple
# mux interfaces are not balanced. Instead we expect packets to be sent to
# a single mux interface.
def check_nexthops_balance(rand_selected_dut, ptfadapter, dst_server_addr,
                           tbinfo, downlink_ints, nexthops_count):
    HASH_KEYS = ["src-port", "dst-port", "src-ip"]
    # expect this packet to be sent to downlinks (active mux) and uplink (stanby mux)
    expected_downlink_ports = [get_ptf_server_intf_index(rand_selected_dut, tbinfo, iface) for iface in downlink_ints]
    expected_uplink_ports = list()
    expected_uplink_portchannels = list()
    portchannel_ports = get_t1_ptf_pc_ports(rand_selected_dut, tbinfo)
    for pc, intfs in list(portchannel_ports.items()):
        expected_uplink_portchannels.append(pc)
        for member in intfs:
            expected_uplink_ports.append(int(member.strip("eth")))
    logging.info("Expecting packets in downlink ports {}".format(expected_downlink_ports))
    logging.info("Expecting packets in uplink ports {}".format(expected_uplink_ports))

    ptf_t1_intf = random.choice(get_t1_ptf_ports(rand_selected_dut, tbinfo))
    port_packet_count = dict()
    packets_to_send = generate_hashed_packet_to_server(ptfadapter, rand_selected_dut, HASH_KEYS, dst_server_addr, 10000)
    for send_packet, exp_pkt, exp_tunnel_pkt in packets_to_send:
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), send_packet, count=1)
        # expect ECMP hashing to work and distribute downlink traffic evenly to every nexthop
        all_allowed_ports = expected_downlink_ports + expected_uplink_ports
        ptf_port_count = count_matched_packets_all_ports(ptfadapter,
                                                         exp_packet=exp_pkt,
                                                         exp_tunnel_pkt=exp_tunnel_pkt,
                                                         ports=all_allowed_ports,
                                                         timeout=0.1,
                                                         count=1)

        for ptf_idx, pkt_count in list(ptf_port_count.items()):
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
        for pc, intfs in list(portchannel_ports.items()):
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


def check_nexthops_single_uplink(portchannel_ports, port_packet_count, expect_packet_num, skip_traffic_test=False):
    for pc, intfs in portchannel_ports.items():
        count = 0
        # Collect the packets count within a single portchannel
        for member in intfs:
            uplink_int = int(member.strip("eth"))
            count = count + port_packet_count.get(uplink_int, 0)
        logging.info("Packets received on portchannel {}: {}".format(pc, count))

        if skip_traffic_test is True:
            logging.info("Skip checking single uplink balance due to traffic test was skipped")
            continue
        if count > 0 and count != expect_packet_num:
            pytest.fail("Packets not sent up single standby port {}".format(pc))


# verify nexthops are only sent to single active or standby mux
def check_nexthops_single_downlink(rand_selected_dut, ptfadapter, dst_server_addr,
                                   tbinfo, downlink_ints, skip_traffic_test=False):
    HASH_KEYS = ["src-port", "dst-port", "src-ip"]
    expect_packet_num = 1000
    expect_packet_num_high = expect_packet_num * (0.90)
    expect_packet_num_low = expect_packet_num * (1.1)

    # expect this packet to be sent to downlinks (active mux) and uplink (stanby mux)
    expected_downlink_ports = [get_ptf_server_intf_index(rand_selected_dut, tbinfo, iface) for iface in downlink_ints]
    portchannel_ports = get_t1_ptf_pc_ports(rand_selected_dut, tbinfo)
    logging.info("Expecting packets in downlink ports {}".format(expected_downlink_ports))

    ptf_t1_intf = random.choice(get_t1_ptf_ports(rand_selected_dut, tbinfo))
    port_packet_count = dict()
    packets_to_send = generate_hashed_packet_to_server(ptfadapter, rand_selected_dut, HASH_KEYS, dst_server_addr,
                                                       expect_packet_num)
    if skip_traffic_test is True:
        logging.info("Skip checking single downlink balance due to traffic test was skipped")
        return
    for send_packet, exp_pkt, exp_tunnel_pkt in packets_to_send:
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), send_packet, count=1)
        # expect multi-mux nexthops to focus packets to one downlink
        all_allowed_ports = expected_downlink_ports
        ptf_port_count = count_matched_packets_all_ports(ptfadapter, exp_packet=exp_pkt, exp_tunnel_pkt=exp_tunnel_pkt,
                                                         ports=all_allowed_ports, timeout=1, count=1)

        for ptf_idx, pkt_count in ptf_port_count.items():
            port_packet_count[ptf_idx] = port_packet_count.get(ptf_idx, 0) + pkt_count

    logging.info("Received packets in ports: {}".format(str(port_packet_count)))
    for downlink_int in expected_downlink_ports:
        # packets should be either 0 or expect_packet_num:
        count = port_packet_count.get(downlink_int, 0)
        logging.info("Packets received on downlink port {}: {}".format(downlink_int, count))
        if count > 0 and count <= expect_packet_num_high and count >= expect_packet_num_low:
            pytest.fail("Packets not sent down single active port {}".format(downlink_int))

    if len(downlink_ints) == 0:
        # All nexthops are now connected to standby mux, and the packets will be sent towards a single portchanel int
        # Check if uplink distribution is towards a single portchannel
        check_nexthops_single_uplink(portchannel_ports, port_packet_count, expect_packet_num, skip_traffic_test)


def verify_upstream_traffic(host, ptfadapter, tbinfo, itfs, server_ip,
                            pkt_num=100, drop=False, skip_traffic_test=False):
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
    for v in list(port_channels.values()):
        rx_ports += v
    rx_ports = [int(x.strip('eth')) for x in rx_ports]

    logger.info("Verifying upstream traffic. packet number = {} interface = {} \
                server_ip = {} expect_drop = {}".format(pkt_num, itfs, server_ip, drop))
    if skip_traffic_test is True:
        logger.info("Skip verifying upstream traffic due to traffic test was skipped")
        return
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


def dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo, get_function_completeness_level=None):
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
    vlan_name = list(standby_tor_mg_facts['minigraph_vlans'].keys())[0]
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
    random_server_iface = random.choice(list(servers.keys()))

    res['selected_port'] = random_server_iface
    res['target_server_ip'] = servers[random_server_iface]['server_ipv4'].split('/')[0]
    res['target_server_ipv6'] = servers[random_server_iface]['server_ipv6'].split('/')[0]
    res['target_server_port'] = standby_tor_mg_facts['minigraph_ptf_indices'][random_server_iface]

    normalize_level = get_function_completeness_level if get_function_completeness_level else 'thorough'
    res['completeness_level'] = normalize_level

    logger.debug("dualtor info is generated {}".format(res))
    return res


def get_neighbor(duthost, neighbor_addr):
    """Get the neighbor details from ip neighbor show output."""
    command = "ip neighbor show %s" % neighbor_addr
    output = [_.strip() for _ in duthost.shell(command)["stdout_lines"]]
    if not output:
        return {}
    output = output[0]
    return dict(_.split() for _ in itertools.chain(*re.findall(r'(dev\s+[\w\.]+)|(lladdr\s+[\w\.:]+)', output)) if _)


@contextlib.contextmanager
def flush_neighbor(duthost, neighbor, restore=True):
    """Flush neighbor entry for server in duthost."""
    neighbor_details = get_neighbor(duthost, neighbor)
    assert neighbor_details, "No dev found for neighbor %s" % neighbor
    logging.info("neighbor details for %s: %s", neighbor, neighbor_details)
    logging.info("remove neighbor entry for %s", neighbor)
    duthost.shell("ip neighbor del %s dev %s" % (neighbor, neighbor_details['dev']))
    try:
        yield neighbor_details
    finally:
        if restore:
            logging.info("restore neighbor entry for %s", neighbor)
            duthost.shell("ip neighbor replace %s lladdr %s dev %s" %
                          (neighbor, neighbor_details['lladdr'], neighbor_details['dev']))


def delete_neighbor(duthost, neighbor):
    """Delete neighbor entry for server in duthost, ignore it if doesn't exist."""
    neighbor_details = get_neighbor(duthost, neighbor)
    if neighbor_details:
        logging.info("neighbor details for %s: %s", neighbor, neighbor_details)
        logging.info("remove neighbor entry for %s", neighbor)
        duthost.shell("ip neighbor del %s dev %s" % (neighbor, neighbor_details['dev']))
    else:
        logging.info("Neighbor entry %s doesn't exist", neighbor)
        return True

    neighbor_details = get_neighbor(duthost, neighbor)
    if neighbor_details:
        return False
    return True


@pytest.fixture(scope="function")
def rand_selected_interface(rand_selected_dut):
    """Select a random interface to test."""
    tor = rand_selected_dut
    server_ips = mux_cable_server_ip(tor)
    iface = str(random.choice(list(server_ips.keys())))
    logging.info("select DUT interface %s to test.", iface)
    return iface, server_ips[iface]


def show_muxcable_status(duthost):
    """
    Show muxcable status and parse into a dict
    """
    command = "show muxcable status --json"
    output = json.loads(duthost.shell(command)["stdout"])

    ret = {}
    for port, muxcable in list(output['MUX_CABLE'].items()):
        ret[port] = {'status': muxcable['STATUS'], 'health': muxcable['HEALTH']}

    return ret


def check_muxcable_status(duthost, port, expected_status):
    """
    Check the muxcable status of a specific interface is as expected.
    """
    command = "show muxcable status --json"
    output = json.loads(duthost.shell(command)["stdout"])
    return output['MUX_CABLE'][port]['STATUS'] == expected_status


def build_ipv4_packet_to_server(duthost, ptfadapter, target_server_ip):
    """Build ipv4 packet and expected mask packet destinated to server."""
    pkt_dscp = random.choice(list(range(0, 33)))
    pkt_ttl = random.choice(list(range(3, 65)))
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
    exp_pkt.set_do_not_care_scapy(Ether, "dst")
    exp_pkt.set_do_not_care_scapy(Ether, "src")
    exp_pkt.set_do_not_care_scapy(IP, "tos")
    exp_pkt.set_do_not_care_scapy(IP, "ttl")
    exp_pkt.set_do_not_care_scapy(IP, "chksum")
    return pkt, exp_pkt


def build_ipv6_packet_to_server(duthost, ptfadapter, target_server_ip):
    """Build ipv6 packet and expected mask packet destinated to server."""
    pkt_dscp = random.choice(list(range(0, 33)))
    pkt_hl = random.choice(list(range(3, 65)))
    pktlen = 100
    pkt_tc = testutils.ip_make_tos(0, 0, pkt_dscp)
    pkt = Ether(src=ptfadapter.dataplane.get_mac(0, 0), dst=duthost.facts["router_mac"])
    pkt /= IPv6(src="fc02:1200::1", dst=target_server_ip, fl=0, tc=pkt_tc, hlim=pkt_hl)
    pkt /= "".join(random.choice(string.ascii_lowercase) for _ in range(pktlen - len(pkt)))
    logging.info(
        "the packet destinated to server %s:\n%s",
        target_server_ip,
        dump_scapy_packet_show_output(pkt)
    )
    exp_pkt = mask.Mask(pkt)
    exp_pkt.set_do_not_care_scapy(Ether, "dst")
    exp_pkt.set_do_not_care_scapy(Ether, "src")
    exp_pkt.set_do_not_care_scapy(IPv6, "hlim")
    return pkt, exp_pkt


def build_packet_to_server(duthost, ptfadapter, target_server_ip):
    """Build packet and expected mask packet destinated to server."""
    if is_ipv4_address(target_server_ip):
        return build_ipv4_packet_to_server(duthost, ptfadapter, target_server_ip)
    else:
        return build_ipv6_packet_to_server(duthost, ptfadapter, target_server_ip)


@contextlib.contextmanager
def crm_neighbor_checker(duthost, ip_version="ipv4", expect_change=False):
    resource_name = "{}_neighbor".format(ip_version)
    crm_facts_before = duthost.get_crm_facts()
    neighbor_before = crm_facts_before["resources"][resource_name]["used"]
    logging.info("{} neighbor before test: {}".format(ip_version, neighbor_before))
    yield
    time.sleep(crm_facts_before["polling_interval"])
    crm_facts_after = duthost.get_crm_facts()
    neighbor_after = crm_facts_after["resources"][resource_name]["used"]
    logging.info("{} neighbor after test: {}".format(ip_version, neighbor_after))
    if neighbor_after != neighbor_before and not expect_change:
        raise ValueError("{} neighbor differs, before {}, after {}".format(ip_version, neighbor_before, neighbor_after))


def get_ptf_server_intf_index(tor, tbinfo, iface):
    """Get the index of ptf ToR-facing interface on ptf."""
    mg_facts = tor.get_extended_minigraph_facts(tbinfo)
    return mg_facts["minigraph_ptf_indices"][iface]


def get_interface_server_map(torhost, count):
    server_ips = mux_cable_server_ip(torhost)
    interfaces = [str(_) for _ in list(server_ips.keys())]
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
    bgp_neighbors = list(standby_tor.bgp_facts()['ansible_facts']['bgp_neighbors'].keys())

    route_dst = ipaddress.ip_address(six.text_type(route_dst))
    ip_neighbors = []
    for neighbor in bgp_neighbors:
        if ipaddress.ip_address(neighbor).version == route_dst.version:
            ip_neighbors.append(neighbor)

    nexthop_str = ''
    if nexthops is None:
        for neighbor in ip_neighbors:
            nexthop_str += 'nexthop via {} '.format(neighbor)
    else:
        for nexthop in nexthops:
            nexthop_str += 'nexthop via {} '.format(nexthop)

    # Use `ip route replace` in case a rule already exists for this IP
    # If there are no pre-existing routes, equivalent to `ip route add`
    subnet_mask_len = 32 if route_dst.version == 4 else 128
    route_cmd = 'ip route replace {}/{} {}'.format(str(route_dst), subnet_mask_len, nexthop_str)
    standby_tor.shell(route_cmd)
    logging.info("Route added to {}: {}".format(standby_tor.hostname, route_cmd))


def remove_static_routes(duthost, route_dst):
    """
    Remove static routes for duthost
    """
    route_dst = ipaddress.ip_address(six.text_type(route_dst))
    subnet_mask_len = 32 if route_dst.version == 4 else 128

    logger.info("Removing dual ToR peer switch static route:  {}/{}".format(str(route_dst), subnet_mask_len))
    duthost.shell('ip route del {}/{}'.format(str(route_dst), subnet_mask_len), module_ignore_errors=True)


def recover_linkmgrd_probe_interval(duthosts, tbinfo):
    '''
    Recover the linkmgrd probe interval to default value
    '''
    default_probe_interval_ms = 100
    update_linkmgrd_probe_interval(duthosts, tbinfo, default_probe_interval_ms)
    duthosts.shell('sonic-db-cli CONFIG_DB DEL "MUX_LINKMGR|LINK_PROBER"')


def update_linkmgrd_probe_interval(duthosts, tbinfo, probe_interval_ms):
    '''
    Update the linkmgrd probe interval
    '''
    if 'dualtor' not in tbinfo['topo']['name']:
        return

    logger.info("Update linkmgrd probe interval on {} to {}ms".format(duthosts, probe_interval_ms))
    duthosts.shell('sonic-db-cli CONFIG_DB HSET "MUX_LINKMGR|LINK_PROBER" "interval_v4" "{}"'
                   .format(probe_interval_ms))


@pytest.fixture(scope='module')
def dualtor_ports(request, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    # Fetch dual ToR ports
    logger.info("Starting fetching dual ToR info")

    fetch_dual_tor_ports_script = "\
        local remap_enabled = redis.call('HGET', 'SYSTEM_DEFAULTS|tunnel_qos_remap', 'status')\
        if remap_enabled ~= 'enabled' then\
            return {}\
        end\
        local type = redis.call('HGET', 'DEVICE_METADATA|localhost', 'type')\
        local expected_neighbor_type\
        local expected_neighbor_suffix\
        if type == 'LeafRouter' then\
            expected_neighbor_type = 'ToRRouter'\
            expected_neighbor_suffix = 'T0'\
        else\
            if type == 'ToRRouter' then\
                local subtype = redis.call('HGET', 'DEVICE_METADATA|localhost', 'subtype')\
                if subtype == 'DualToR' then\
                    expected_neighbor_type = 'LeafRouter'\
                    expected_neighbor_suffix = 'T1'\
                end\
            end\
        end\
        if expected_neighbor_type == nil then\
            return {}\
        end\
        local result = {}\
        local all_ports_with_neighbor = redis.call('KEYS', 'DEVICE_NEIGHBOR|*')\
        for i = 1, #all_ports_with_neighbor, 1 do\
            local neighbor = redis.call('HGET', all_ports_with_neighbor[i], 'name')\
            if neighbor ~= nil and string.sub(neighbor, -2, -1) == expected_neighbor_suffix then\
                local peer_type = redis.call('HGET', 'DEVICE_NEIGHBOR_METADATA|' .. neighbor, 'type')\
                if peer_type == expected_neighbor_type then\
                    table.insert(result, string.sub(all_ports_with_neighbor[i], 17, -1))\
                end\
            end\
        end\
        return result\
    "

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    dualtor_ports_str = duthost.run_redis_cmd(argv=["sonic-db-cli", "CONFIG_DB", "eval",
                                                    fetch_dual_tor_ports_script, "0"])
    if dualtor_ports_str:
        dualtor_ports_set = set(dualtor_ports_str)
    else:
        dualtor_ports_set = set({})

    logger.info("Finish fetching dual ToR info {}".format(dualtor_ports_set))

    return dualtor_ports_set


def is_tunnel_qos_remap_enabled(duthost):
    """
    Check whether tunnel_qos_remap is enabled or not
    """
    try:
        tunnel_qos_remap_status = duthost.shell('sonic-cfggen -d -v \'SYSTEM_DEFAULTS.tunnel_qos_remap.status\'',
                                                module_ignore_errors=True)["stdout_lines"][0]
    except (IndexError, NameError):
        return False
    return "enabled" == tunnel_qos_remap_status


@pytest.fixture(scope="session")
def config_dualtor_arp_responder(tbinfo, duthost, mux_config, ptfhost):     # noqa F811
    """
    Apply standard ARP responder for dualtor testbeds

    In this case, ARP responder will reply to ARP requests and NA messages for the
    server IPs configured in the ToR's config DB MUX_CABLE table
    """
    ptfhost.copy(src=os.path.join(SCRIPTS_SRC_DIR, ARP_RESPONDER_PY), dest=OPT_DIR)
    arp_responder_conf = {}
    tor_to_ptf_intf_map = duthost.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']

    for tor_intf, config_vals in list(mux_config.items()):
        ptf_intf = "eth{}".format(tor_to_ptf_intf_map[tor_intf])
        arp_responder_conf[ptf_intf] = [
            str(ipaddress.ip_interface(config_vals["SERVER"]["IPv4"]).ip),
            str(ipaddress.ip_interface(config_vals["SERVER"]["IPv6"]).ip)]

    ptfhost.copy(content=json.dumps(arp_responder_conf, indent=4, sort_keys=True), dest="/tmp/from_t1.json")
    ptfhost.host.options["variable_manager"].extra_vars.update({"arp_responder_args": ""})
    ptfhost.template(src="templates/arp_responder.conf.j2", dest="/etc/supervisor/conf.d/arp_responder.conf")

    supervisor_cmd = "supervisorctl reread && supervisorctl update && supervisorctl restart arp_responder"
    ptfhost.shell(supervisor_cmd)

    yield

    ptfhost.shell("supervisorctl stop arp_responder", module_ignore_errors=True)


@pytest.fixture
def validate_active_active_dualtor_setup(
    duthosts, active_active_ports, ptfhost, tbinfo, restart_nic_simulator):  # noqa F811
    """Validate that both ToRs are active for active-active mux ports."""

    def check_active_active_port_status(duthost, ports, status):
        logging.debug("Check mux status for ports {} is {}".format(ports, status))
        show_mux_status_ret = show_muxcable_status(duthost)
        logging.debug("show_mux_status_ret: {}".format(json.dumps(show_mux_status_ret, indent=4)))
        for port in ports:
            if port not in show_mux_status_ret:
                return False
            elif show_mux_status_ret[port]['status'] != status:
                return False
        return True

    if not ('dualtor' in tbinfo['topo']['name'] and active_active_ports):
        return

    if not all(check_active_active_port_status(duthost, active_active_ports, "active") for duthost in duthosts):
        restart_nic_simulator()
        ptfhost.shell("supervisorctl restart icmp_responder")

    # verify icmp_responder is running
    icmp_responder_status = ptfhost.shell("supervisorctl status icmp_responder", module_ignore_errors=True)["stdout"]
    pt_assert("RUNNING" in icmp_responder_status, "icmp_responder not running in ptf")

    # verify both ToRs are active
    for duthost in duthosts:
        pt_assert(
            wait_until(30, 5, 0, check_active_active_port_status, duthost, active_active_ports, "active"),
            "Not all active-active mux ports are active on device %s" % duthost.hostname
        )

    return


@pytest.fixture
def config_active_active_dualtor_active_standby(duthosts, active_active_ports, tbinfo):                         # noqa F811
    """Config the active-active dualtor that one ToR as active and the other as standby."""
    if not ('dualtor' in tbinfo['topo']['name'] and active_active_ports):
        yield
        return

    def check_active_active_port_status(duthost, ports, status):
        logging.debug("Check mux status for ports {} is {}".format(ports, status))
        show_mux_status_ret = show_muxcable_status(duthost)
        logging.debug("show_mux_status_ret: {}".format(json.dumps(show_mux_status_ret, indent=4)))
        for port in ports:
            if port not in show_mux_status_ret:
                return False
            elif show_mux_status_ret[port]['status'] != status:
                return False
        return True

    def _config_the_active_active_dualtor(active_tor, standby_tor, ports, unconditionally=False):
        active_side_commands = []
        standby_side_commands = []
        logging.info("Configuring {} as active".format(active_tor.hostname))
        logging.info("Configuring {} as standby".format(standby_tor.hostname))
        for port in ports:
            if port not in active_active_ports:
                raise ValueError("Port {} is not in the active-active ports".format(port))
            active_side_commands.append("config mux mode active {}".format(port))
            standby_side_commands.append("config mux mode standby {}".format(port))

        if not check_active_active_port_status(active_tor, ports, 'active') or unconditionally:
            active_tor.shell_cmds(cmds=active_side_commands)
        standby_tor.shell_cmds(cmds=standby_side_commands)

        pt_assert(wait_until(30, 5, 0, check_active_active_port_status, active_tor, ports, 'active'),
                  "Could not config ports {} to active on {}".format(ports, active_tor.hostname))
        pt_assert(wait_until(30, 5, 0, check_active_active_port_status, standby_tor, ports, 'standby'),
                  "Could not config ports {} to standby on {}".format(ports, standby_tor.hostname))

        ports_to_restore.extend(ports)

    ports_to_restore = []

    yield _config_the_active_active_dualtor

    if ports_to_restore:
        restore_cmds = []
        for port in ports_to_restore:
            restore_cmds.append("config mux mode auto {}".format(port))

        for duthost in duthosts:
            duthost.shell_cmds(cmds=restore_cmds)


@pytest.fixture
def toggle_all_aa_ports_to_lower_tor(config_active_active_dualtor_active_standby,
                                     lower_tor_host, upper_tor_host, active_active_ports):  # noqa F811
    if active_active_ports:
        config_active_active_dualtor_active_standby(lower_tor_host, upper_tor_host, active_active_ports)
    return


@pytest.fixture
def toggle_all_aa_ports_to_rand_selected_tor(config_active_active_dualtor_active_standby,
                                             rand_selected_dut, rand_unselected_dut, active_active_ports):  # noqa F811
    if active_active_ports:
        config_active_active_dualtor_active_standby(rand_selected_dut, rand_unselected_dut, active_active_ports)
    return


@pytest.fixture
def toggle_all_aa_ports_to_rand_unselected_tor(config_active_active_dualtor_active_standby,
                                               rand_selected_dut, rand_unselected_dut, active_active_ports):  # noqa F811
    if active_active_ports:
        config_active_active_dualtor_active_standby(rand_unselected_dut, rand_selected_dut, active_active_ports)
    return


@pytest.fixture(autouse=True)
def check_simulator_flap_counter(
    nic_simulator_flap_counter, simulator_flap_counter, active_active_ports, active_standby_ports, cable_type   # noqa F811
):
    """Check the flap count for mux ports."""

    def set_expected_counter_diff(diff):
        """Set expected counter difference."""
        if isinstance(diff, list) or isinstance(diff, tuple):
            expected_diff.extend(diff)
        else:
            expected_diff.append(diff)

    def check_nic_simulator_flaps_helper(mux_ports):
        logging.info("Check active-active mux port flap counters: %s", mux_ports)
        result = nic_simulator_flap_counter(mux_ports)
        mux_port_flaps = {}
        for mux_port, flaps in zip(mux_ports, result):
            mux_port_flaps[mux_port] = {
                UPPER_TOR: flaps[ActiveActivePortID.UPPER_TOR],
                LOWER_TOR: flaps[ActiveActivePortID.LOWER_TOR]
            }
        return mux_port_flaps

    def check_mux_simulator_flaps_helper(mux_ports):
        logging.info("Check active-standby mux port flap counters: %s", mux_ports)
        mux_port_flaps = {}
        for mux_port in mux_ports:
            flaps = simulator_flap_counter(mux_port)
            mux_port_flaps[mux_port] = {
                UPPER_TOR: flaps,
                LOWER_TOR: flaps
            }
        return mux_port_flaps

    def check_flaps_diff_active_active(expected_diff, counter_diffs):
        unexpected_flap_mux_ports = []
        for mux_port, counter_diff in counter_diffs.items():
            if (counter_diff[UPPER_TOR] != expected_diff[ActiveActivePortID.UPPER_TOR] or
                    counter_diff[LOWER_TOR] != expected_diff[ActiveActivePortID.LOWER_TOR]):
                unexpected_flap_mux_ports.append(mux_port)
        return unexpected_flap_mux_ports

    def check_flaps_diff_active_standby(expected_diff, counter_diffs):
        unexpected_flap_mux_ports = []
        for mux_port, counter_diff in counter_diffs.items():
            if counter_diff[UPPER_TOR] != expected_diff[-1] or counter_diff[LOWER_TOR] != expected_diff[-1]:
                unexpected_flap_mux_ports.append(mux_port)
        return unexpected_flap_mux_ports

    def log_flap_counter(flap_counters):
        for mux_port, flaps in flap_counters.items():
            logging.debug("Mux port %s flap counter: %s", mux_port, flaps)

    expected_diff = []
    if cable_type == CableType.active_active:
        mux_ports = [str(_) for _ in active_active_ports]
        check_flap_func = check_nic_simulator_flaps_helper
        check_flap_diff_func = check_flaps_diff_active_active
    elif cable_type == CableType.active_standby:
        mux_ports = [str(_) for _ in active_standby_ports]
        check_flap_func = check_mux_simulator_flaps_helper
        check_flap_diff_func = check_flaps_diff_active_standby
    else:
        raise ValueError

    counters_before = check_flap_func(mux_ports)
    log_flap_counter(counters_before)
    yield set_expected_counter_diff
    counters_after = check_flap_func(mux_ports)
    log_flap_counter(counters_after)

    counter_diffs = {}
    for mux_port in mux_ports:
        counter_diffs[mux_port] = {
            UPPER_TOR: counters_after[mux_port][UPPER_TOR] - counters_before[mux_port][UPPER_TOR],
            LOWER_TOR: counters_after[mux_port][LOWER_TOR] - counters_before[mux_port][LOWER_TOR]
        }
    logging.info(
        "\n%s\n",
        tabulate.tabulate(
            [[mux_port, flaps[UPPER_TOR], flaps[LOWER_TOR]] for mux_port, flaps in counter_diffs.items()],
            headers=["port", "upper ToR flaps", "lower ToR flaps"]
        )
    )
    if expected_diff:
        unexpected_flap_mux_ports = check_flap_diff_func(expected_diff, counter_diffs)
        error_str = json.dumps(unexpected_flap_mux_ports, indent=4)
        if unexpected_flap_mux_ports:
            logging.error(error_str)
            raise ValueError(error_str)


@pytest.fixture
def setup_standby_ports_on_rand_selected_tor(active_active_ports, rand_selected_dut, rand_unselected_dut,                  # noqa F811
                                             config_active_active_dualtor_active_standby,                                  # noqa F811
                                             validate_active_active_dualtor_setup):                                        # noqa F811
    if active_active_ports:
        config_active_active_dualtor_active_standby(rand_unselected_dut, rand_selected_dut, active_active_ports)
    return


@pytest.fixture
def setup_standby_ports_on_rand_unselected_tor(active_active_ports, rand_selected_dut, rand_unselected_dut,                  # noqa F811
                                               config_active_active_dualtor_active_standby,
                                               validate_active_active_dualtor_setup):
    if active_active_ports:
        config_active_active_dualtor_active_standby(rand_selected_dut, rand_unselected_dut, active_active_ports)
    return


@pytest.fixture
def setup_standby_ports_on_non_enum_rand_one_per_hwsku_frontend_host_m(
    active_active_ports,                                                   # noqa F811
    enum_rand_one_per_hwsku_frontend_hostname,
    config_active_active_dualtor_active_standby,
    validate_active_active_dualtor_setup,
    upper_tor_host,
    lower_tor_host,
    duthosts
):
    if active_active_ports:
        active_tor = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        standby_tor = upper_tor_host if active_tor == lower_tor_host else lower_tor_host
        config_active_active_dualtor_active_standby(active_tor, standby_tor, active_active_ports)
    return


@pytest.fixture
def setup_standby_ports_on_rand_unselected_tor_unconditionally(
    active_active_ports,                                                   # noqa F811
    rand_selected_dut,
    rand_unselected_dut,
    config_active_active_dualtor_active_standby
):
    if active_active_ports:
        config_active_active_dualtor_active_standby(rand_selected_dut, rand_unselected_dut, active_active_ports, True)
    return


@pytest.fixture
def setup_standby_ports_on_non_enum_rand_one_per_hwsku_frontend_host_m_unconditionally(
    active_active_ports,                                                   # noqa F811
    enum_rand_one_per_hwsku_frontend_hostname,
    config_active_active_dualtor_active_standby,
    upper_tor_host,
    lower_tor_host,
    duthosts
):
    if active_active_ports:
        active_tor = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        standby_tor = upper_tor_host if active_tor == lower_tor_host else lower_tor_host
        config_active_active_dualtor_active_standby(active_tor, standby_tor, active_active_ports, True)
    return


@pytest.fixture(scope='session', autouse=True)
def disable_timed_oscillation_active_standby(duthosts, tbinfo):
    """
    Disable timed oscillation for active-standby mux ports
    """
    if 'dualtor' not in tbinfo['topo']['name']:
        return

    for duthost in duthosts:
        duthost.shell('sonic-db-cli CONFIG_DB HSET "MUX_LINKMGR|TIMED_OSCILLATION" "oscillation_enabled" "false"')
