import logging
import pytest

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

    Uses the convention that the first ToR alphabetically by hostname is the upper ToR
    '''
    dut = sorted(duthosts, key=lambda dut: dut.hostname)[0]
    logger.info("Using {} as upper ToR".format(dut.hostname))
    return dut


@pytest.fixture(scope='session')
def lower_tor_host(duthosts):
    '''
    Gets the host object for the lower ToR

    Uses the convention that the first ToR alphabetically by hostname is the upper ToR
    '''
    dut = sorted(duthosts, key=lambda dut: dut.hostname)[-1]
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
