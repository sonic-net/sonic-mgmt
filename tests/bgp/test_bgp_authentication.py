'''This script is to test the EBGP Authentication feature of SONiC.
'''
import logging

import pytest
import time

from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]

bgp_config_sleeptime = 60
bgp_pass = "sonic.123"
mismatch_pass = "badpassword"


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, enum_frontend_dut_hostname, enum_rand_one_frontend_asic_index, request):
    # verify neighbors are type sonic
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Neighbor type must be sonic")
    duthost = duthosts[enum_frontend_dut_hostname]
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    lldp_table = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()
    tor1 = lldp_table[1]
    dut_int = lldp_table[0]
    neigh_int = lldp_table[2]
    if duthost.is_multi_asic:
        asic_index = duthost.get_port_asic_instance(dut_int).asic_index
    else:
        asic_index = None

    if nbrhosts[tor1]["host"].is_multi_asic:
        neigh_asic_index = nbrhosts[tor1]["host"].get_port_asic_instance(neigh_int).asic_index
    else:
        neigh_asic_index = None

    namespace = duthost.get_namespace_from_asic_id(asic_index)

    skip_hosts = duthost.get_asic_namespace_list()
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            if v['description'] == tor1:
                if v['ip_version'] == 4:
                    neigh_ip_v4 = k
                    peer_group_v4 = v['peer group']
                elif v['ip_version'] == 6:
                    neigh_ip_v6 = k
                    peer_group_v6 = v['peer group']
                neigh_asn = v['remote AS']

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][tor1]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][tor1]['bgp']['peers'][dut_asn][1]

    logger.info("default namespace {}".format(DEFAULT_NAMESPACE))

    tor1_namespace = DEFAULT_NAMESPACE
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for dut_port, neigh in mg_facts['minigraph_neighbors'].items():
        if tor1 == neigh['name']:
            tor1_namespace = neigh['namespace']
            break

    # verify sessions are established
    logger.debug(duthost.shell('show ip bgp summary'))
    logger.debug(duthost.shell('show ipv6 bgp summary'))

    assert bgp_facts['bgp_neighbors'][neigh_ip_v4]['state'] == 'established'
    assert bgp_facts['bgp_neighbors'][neigh_ip_v6]['state'] == 'established'

    setup_info = {
        'duthost': duthost,
        'neighhost': nbrhosts[tor1]["host"],
        'tor1': tor1,
        'dut_asn': dut_asn,
        'neigh_asn': neigh_asn,
        'dut_ip_v4': dut_ip_v4,
        'dut_ip_v6': dut_ip_v6,
        'neigh_ip_v4': neigh_ip_v4,
        'neigh_ip_v6': neigh_ip_v6,
        'peer_group_v4': peer_group_v4,
        'peer_group_v6': peer_group_v6,
        'tor1_namespace': tor1_namespace,
        'dut_namespace': namespace,
        'asic_index': asic_index,
        'neigh_asic_index': neigh_asic_index
    }

    logger.debug("DUT BGP Config: {}".format(duthost.shell("show run bgp", module_ignore_errors=True)))
    logger.debug("Neighbor BGP Config: {}".format(nbrhosts[tor1]["host"].shell("show run bgp",
                                                                               module_ignore_errors=True)))
    logger.debug('Setup_info: {}'.format(setup_info))

    yield setup_info

    # restore config to original state
    config_reload(duthost, safe_reload=True)
    time.sleep(10)
    config_reload(nbrhosts[tor1]["host"], is_dut=False)


def test_bgp_peer_group_password(setup):
    ns = '-n ' + str(setup['asic_index']) if setup['asic_index'] is not None else ''
    cmd = 'vtysh ' + ns + ' -c "config" -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}" \
        -c "end"'.format(setup['dut_asn'], setup['peer_group_v4'], bgp_pass,
                         setup['peer_group_v6'], bgp_pass)
    command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False

    logger.debug(setup['duthost'].shell('show run bgp'))

    time.sleep(bgp_config_sleeptime)

    logger.debug(setup['duthost'].shell('show ip bgp summary'))
    logger.debug(setup['duthost'].shell('show ipv6 bgp summary'))
    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] != 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] != 'established'

    # set password on neighbor
    ns = '-n ' + str(setup['neigh_asic_index']) if setup['neigh_asic_index'] is not None else ''
    cmd = 'vtysh ' + ns + ' -c "config"  -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}"' \
        .format(setup['neigh_asn'], setup['dut_ip_v4'], bgp_pass, setup['dut_ip_v6'],
                bgp_pass)
    logger.debug(setup['neighhost'].shell(cmd, module_ignore_errors=True))
    logger.debug(setup['neighhost'].shell("show run bgp"))

    time.sleep(bgp_config_sleeptime)

    logger.debug(setup['duthost'].shell('show ip bgp summary'))
    logger.debug(setup['duthost'].shell('show ipv6 bgp summary'))
    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] == 'established'

    # mismatch peer group passwords
    ns = '-n ' + str(setup['asic_index']) if setup['asic_index'] is not None else ''
    cmd = 'vtysh ' + ns + ' -c "config" -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}" \
          -c "end"'.format(setup['dut_asn'], setup['peer_group_v4'], mismatch_pass,
                           setup['peer_group_v6'], mismatch_pass)

    command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False

    logger.debug(setup['duthost'].shell('show run bgp'))

    time.sleep(bgp_config_sleeptime)

    logger.debug(setup['duthost'].shell('show ip bgp summary'))
    logger.debug(setup['duthost'].shell('show ipv6 bgp summary'))
    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] != 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] != 'established'

    # turn off peer group passwords on DUT
    ns = '-n ' + str(setup['asic_index']) if setup['asic_index'] is not None else ''
    cmd = 'vtysh ' + ns + ' -c "config" -c "router bgp {}" -c "no neighbor {} password {}" \
          -c "no neighbor {} password {}" -c "end"'.format(setup['dut_asn'], setup['peer_group_v4'],
                                                           mismatch_pass, setup['peer_group_v6'], mismatch_pass)

    command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False

    logger.debug(setup['duthost'].shell('show run bgp'))

    # remove passwords from neighbor
    ns = '-n ' + str(setup['neigh_asic_index']) if setup['neigh_asic_index'] is not None else ''
    cmd = 'vtysh ' + ns + ' -c "config" -c "router bgp {}" -c "no neighbor {} password {}" \
                            -c "no neighbor {} password {}"'.format(setup['neigh_asn'], setup['dut_ip_v4'],
                                                                    bgp_pass, setup['dut_ip_v6'], bgp_pass)
    logger.debug(setup['neighhost'].shell(cmd, module_ignore_errors=True))
    logger.debug(setup['neighhost'].shell("show run bgp"))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] == 'established'


def test_bgp_neighbor_password(setup):
    ns = '-n ' + str(setup['asic_index']) if setup['asic_index'] is not None else ''
    cmd = 'vtysh ' + ns + ' -c "config" -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}" \
        -c "end"'.format(setup['dut_asn'], setup['neigh_ip_v4'], bgp_pass, setup['neigh_ip_v6'], bgp_pass)

    command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False

    logger.debug(setup['duthost'].shell('show run bgp'))

    time.sleep(bgp_config_sleeptime)

    # verify BGP sessions are not established
    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']

    logger.debug(setup['duthost'].shell('show ip bgp summary'))
    logger.debug(setup['duthost'].shell('show ipv6 bgp summary'))

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] != 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] != 'established'

    # configure password on neighbor
    ns = '-n ' + str(setup['neigh_asic_index']) if setup['neigh_asic_index'] is not None else ''
    cmd = 'vtysh ' + ns + ' -c "config" -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}"' \
          .format(setup['neigh_asn'], setup['dut_ip_v4'], bgp_pass, setup['dut_ip_v6'],
                  bgp_pass)
    logger.debug(setup['neighhost'].shell(cmd, module_ignore_errors=True))
    logger.debug(setup['neighhost'].shell("show run bgp"))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] == 'established'

    # mismatch passwords
    ns = '-n ' + str(setup['asic_index']) if setup['asic_index'] is not None else ''
    cmd = 'vtysh ' + ns + ' -c "config" -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}" \
        -c "end"'.format(setup['dut_asn'], setup['neigh_ip_v4'], mismatch_pass, setup['neigh_ip_v6'], mismatch_pass)

    command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False

    time.sleep(bgp_config_sleeptime)

    # verify sessions are not established
    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']

    logger.debug(setup['duthost'].shell('show ip bgp summary'))
    logger.debug(setup['duthost'].shell('show ipv6 bgp summary'))

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] != 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] != 'established'

    # remove password configs
    ns = '-n ' + str(setup['asic_index']) if setup['asic_index'] is not None else ''
    cmd = 'vtysh ' + ns + ' -c "config" -c "router bgp {}" -c "no neighbor {} password {}" -c \
        "no neighbor {} password {}" -c "end"'.format(setup['dut_asn'],
                                                      setup['neigh_ip_v4'], mismatch_pass, setup['neigh_ip_v6'],
                                                      mismatch_pass)

    command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False

    ns = '-n ' + str(setup['neigh_asic_index']) if setup['neigh_asic_index'] is not None else ''
    cmd = 'vtysh ' + ns + ' -c "config" -c "router bgp {}" -c "no neighbor {} password {}" -c "no neighbor {} ' \
                          'password {}"'.format(setup['neigh_asn'], setup['dut_ip_v4'],
                                                bgp_pass, setup['dut_ip_v6'], bgp_pass)
    logger.debug(setup['neighhost'].shell(cmd, module_ignore_errors=True))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] == 'established'
