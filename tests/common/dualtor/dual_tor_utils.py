import logging
import pytest

from natsort import natsorted

from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.helpers.dut_ports import encode_dut_port_name

logger = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def tor_mux_intf(duthosts):
    '''
    Returns the server-facing interface on the ToR to be used for testing
    '''
    # The same ports on both ToRs should be connected to the same PTF port
    dut = duthosts[0]
    return sorted(dut.get_vlan_intfs(), key=lambda intf: int(intf.replace('Ethernet', '')))[0]


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
    dut = duthosts[1]
    logger.info("Using {} as lower ToR".format(dut.hostname))
    return dut


def get_t1_ptf_ports(dut, tbinfo):
    '''
    Gets the PTF ports connected to a given DUT for the first T1
    '''
    config_facts = dut.get_running_config_facts()
    mg_facts = dut.get_extended_minigraph_facts(tbinfo)

    # Always choose the first portchannel
    portchannel = sorted(config_facts['PORTCHANNEL'].keys())[0]
    dut_portchannel_members = config_facts['PORTCHANNEL'][portchannel]['members']

    ptf_portchannel_intfs = []

    for intf in dut_portchannel_members:
        member = mg_facts['minigraph_ptf_indices'][intf]
        intf_name = 'eth{}'.format(member)
        ptf_portchannel_intfs.append(intf_name)

    logger.info("Using portchannel ports {} on PTF for DUT {}".format(ptf_portchannel_intfs, dut.hostname))
    return ptf_portchannel_intfs


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
