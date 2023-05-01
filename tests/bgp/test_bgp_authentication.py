'''This script is to test the EBGP Authentication feature of SONiC.
'''
import logging

import pytest
import time

from natsort import natsorted
from tests.common.helpers.constants import DEFAULT_NAMESPACE

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1')
]

bgp_config_sleeptime = 60
bgp_pass = "sonic.123"
mismatch_pass = "badpassword"


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, rand_one_dut_hostname, enum_asic_index):
    duthost = duthosts[rand_one_dut_hostname]
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    tor_neighbors = natsorted([neighbor for neighbor in nbrhosts.keys() if neighbor.endswith('T0')])
    tor1 = tor_neighbors[0]

    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
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

    tor1_namespace = DEFAULT_NAMESPACE
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for dut_port, neigh in mg_facts['minigraph_neighbors'].items():
        if tor1 == neigh['name']:
            tor1_namespace = neigh['namespace']
            break

    # verify sessions are established
    logger.info(duthost.shell('show ip bgp summary'))
    logger.info(duthost.shell('show ipv6 bgp summary'))

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
        'tor1_namespace': tor1_namespace
    }

    logger.info("DUT BGP Config: {}".format(duthost.shell("show run bgp", module_ignore_errors=True)))
    logger.info("Neighbor BGP Config: {}".format(
        nbrhosts[tor1]["host"].eos_command(commands=["show run | section bgp"])))
    logger.info('Setup_info: {}'.format(setup_info))

    yield setup_info

    # remove all password combinations
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "no neighbor {} password {}" -c "no neighbor {} password {}" '\
        '-c "no neighbor {} password {}" -c "no neighbor {} password {}" -c "no neighbor {} password {}" '\
        '-c "no neighbor {} password {}" -c "no neighbor {} password {}" -c "no neighbor {} password {}" '\
        '-c "end"'.format(tor1_namespace, dut_asn, peer_group_v4, bgp_pass, peer_group_v6, bgp_pass, peer_group_v4,
                          mismatch_pass, peer_group_v6, mismatch_pass, neigh_ip_v4, bgp_pass, neigh_ip_v6, bgp_pass,
                          neigh_ip_v4, mismatch_pass, neigh_ip_v6, mismatch_pass)
    duthost.shell(cmd, module_ignore_errors=True)

    cmd = ["no neighbor {} password 0 {}".format(dut_ip_v4, bgp_pass), "no neighbor {} password 0 {}"
           .format(dut_ip_v6, bgp_pass)]
    nbrhosts[tor1]["host"].eos_config(lines=cmd, parents="router bgp {}".format(neigh_asn))


def test_bgp_peer_group_password(setup, enum_asic_index):
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}" -c "end"'\
        .format(setup['tor1_namespace'], setup['dut_asn'], setup['peer_group_v4'], bgp_pass, setup['peer_group_v6'], bgp_pass)
    command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False

    logger.info(setup['duthost'].shell('show run bgp'))

    time.sleep(bgp_config_sleeptime)

    logger.info(setup['duthost'].shell('show ip bgp summary'))
    logger.info(setup['duthost'].shell('show ipv6 bgp summary'))
    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_asic_index)['ansible_facts']

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] != 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] != 'established'

    # set password on neighbor
    cmd = ["neighbor {} password 0 {}".format(setup['dut_ip_v4'], bgp_pass), "neighbor {} password 0 {}"
           .format(setup['dut_ip_v6'], bgp_pass)]
    logger.info(setup['neighhost'].eos_config(lines=cmd, parents="router bgp {}".format(setup['neigh_asn'])))
    logger.info(setup['neighhost'].eos_command(commands=["show run | section bgp"]))

    time.sleep(bgp_config_sleeptime)

    logger.info(setup['duthost'].shell('show ip bgp summary'))
    logger.info(setup['duthost'].shell('show ipv6 bgp summary'))
    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_asic_index)['ansible_facts']

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] == 'established'

    # mismatch peer group passwords
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}" -c "end"'\
        .format(setup['tor1_namespace'], setup['dut_asn'], setup['peer_group_v4'], mismatch_pass, setup['peer_group_v6'], mismatch_pass)

    command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False

    logger.info(setup['duthost'].shell('show run bgp'))

    time.sleep(bgp_config_sleeptime)

    logger.info(setup['duthost'].shell('show ip bgp summary'))
    logger.info(setup['duthost'].shell('show ipv6 bgp summary'))
    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_asic_index)['ansible_facts']

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] != 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] != 'established'

    # turn off peer group passwords on DUT
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "no neighbor {} password {}" -c "no neighbor {} password {}" '\
        '-c "end"'.format(setup['tor1_namespace'], setup['dut_asn'], setup['peer_group_v4'], mismatch_pass, setup['peer_group_v6'],
                          mismatch_pass)

    command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False

    logger.info(setup['duthost'].shell('show run bgp'))

    # remove passwords from neighbor
    cmd = ["no neighbor {} password 0 {}".format(setup['dut_ip_v4'], bgp_pass), "no neighbor {} password 0 {}"
           .format(setup['dut_ip_v6'], bgp_pass)]
    logger.info(setup['neighhost'].eos_config(lines=cmd, parents="router bgp {}".format(setup['neigh_asn'])))
    logger.info(setup['neighhost'].eos_command(commands=["show run | section bgp"]))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_asic_index)['ansible_facts']

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] == 'established'


def test_bgp_neighbor_password(setup, enum_asic_index):
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}" -c "end"'\
        .format(setup['tor1_namespace'], setup['dut_asn'], setup['neigh_ip_v4'], bgp_pass, setup['neigh_ip_v6'], bgp_pass)

    command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False

    logger.info(setup['duthost'].shell('show run bgp'))

    time.sleep(bgp_config_sleeptime)

    # verify sessions are not established
    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_asic_index)['ansible_facts']

    logger.info(setup['duthost'].shell('show ip bgp summary'))
    logger.info(setup['duthost'].shell('show ipv6 bgp summary'))

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] != 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] != 'established'

    # configure password on neighbor
    cmd = ["neighbor {} password 0 {}".format(setup['dut_ip_v4'], bgp_pass), "neighbor {} password 0 {}"
           .format(setup['dut_ip_v6'], bgp_pass)]
    logger.info(setup['neighhost'].eos_config(lines=cmd, parents="router bgp {}".format(setup['neigh_asn'])))
    logger.info(setup['neighhost'].eos_command(commands=["show run | section bgp"]))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_asic_index)['ansible_facts']

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] == 'established'

    # mismatch passwords
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}" -c "end"'\
        .format(setup['tor1_namespace'], setup['dut_asn'], setup['neigh_ip_v4'], mismatch_pass, setup['neigh_ip_v6'], mismatch_pass)

    command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False

    time.sleep(bgp_config_sleeptime)

    # verify sessions are not established
    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_asic_index)['ansible_facts']

    logger.info(setup['duthost'].shell('show ip bgp summary'))
    logger.info(setup['duthost'].shell('show ipv6 bgp summary'))

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] != 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] != 'established'

    # remove password configs
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "no neighbor {} password {}" -c "no neighbor {} password {}" '\
        '-c "end"'.format(setup['tor1_namespace'], setup['dut_asn'], setup['neigh_ip_v4'], mismatch_pass, setup['neigh_ip_v6'], mismatch_pass)

    command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False

    cmd = ["no neighbor {} password 0 {}".format(setup['dut_ip_v4'], bgp_pass), "no neighbor {} password 0 {}"
           .format(setup['dut_ip_v6'], bgp_pass)]
    logger.info(setup['neighhost'].eos_config(lines=cmd, parents="router bgp {}".format(setup['neigh_asn'])))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_asic_index)['ansible_facts']

    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established'
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] == 'established'
