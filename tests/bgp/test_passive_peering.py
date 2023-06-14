'''

This script is to test BGP passive peering on SONiC.

'''

import logging
import pytest
import time
from natsort import natsorted

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]

bgp_config_sleeptime = 60
peer_password = "sonic.123"
wrong_password = "wrong-password"


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, rand_one_dut_hostname, enum_rand_one_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]
    namespace = duthost.get_namespace_from_asic_id(enum_rand_one_frontend_asic_index)
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    tor_neighbors = dict()
    tor1 = natsorted(nbrhosts.keys())[0]

    skip_hosts = duthost.get_asic_namespace_list()

    bgp_facts = duthost.bgp_facts(instance_id=enum_rand_one_frontend_asic_index)['ansible_facts']
    neigh_asn = dict()
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'] not in skip_hosts:
            if v['ip_version'] == 4:
                neigh_ip_v4 = k
                peer_group_v4 = v['peer group']
                assert v['state'] == 'established'
            elif v['ip_version'] == 6:
                neigh_ip_v6 = k
                peer_group_v6 = v['peer group']
                assert v['state'] == 'established'
            neigh_asn[v['description']] = v['remote AS']
            tor_neighbors[v['description']] = nbrhosts[v['description']]["host"]

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][tor1]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][tor1]['bgp']['peers'][dut_asn][1]

    # verify sessions are established
    logger.info(duthost.shell('show ip bgp summary'))
    logger.info(duthost.shell('show ipv6 bgp summary'))

    setup_info = {
        'duthost': duthost,
        'neighhost': tor_neighbors[tor1],
        'tor1': tor1,
        'dut_asn': dut_asn,
        'neigh_asn': neigh_asn[tor1],
        'asn_dict':  neigh_asn,
        'neighbors': tor_neighbors,
        'namespace': namespace,
        'dut_ip_v4': dut_ip_v4,
        'dut_ip_v6': dut_ip_v6,
        'neigh_ip_v4': neigh_ip_v4,
        'neigh_ip_v6': neigh_ip_v6,
        'peer_group_v4': peer_group_v4,
        'peer_group_v6': peer_group_v6
    }

    logger.info("DUT BGP Config: {}".format(duthost.shell("vtysh -n {} -c \"show run bgp\"".format(namespace),
                                                          module_ignore_errors=True)))
    logger.info("Neighbor BGP Config: {}".format(
        tor_neighbors[tor1].eos_command(commands=["show run | section bgp"])))
    logger.info('Setup_info: {}'.format(setup_info))

    yield setup_info

    # remove all password combinations and passive peering
    cmd = 'vtysh -c "config" -c "router bgp {}" -c "no neighbor {} password {}" -c "no neighbor {} password {}" '\
        '-c "no neighbor {} password {}" -c "no neighbor {} password {}" -c "no neighbor {} passive" '\
        '-c "no neighbor {} passive" -c "end"'.format(dut_asn, neigh_ip_v4, peer_password, neigh_ip_v6, peer_password,
                                                      neigh_ip_v4, wrong_password, neigh_ip_v6, wrong_password,
                                                      peer_group_v4, peer_group_v6)
    duthost.shell(cmd, module_ignore_errors=True)

    cmd = ["no neighbor {} password 0 {}".format(dut_ip_v4, peer_password), "no neighbor {} password 0 {}"
           .format(dut_ip_v6, peer_password)]
    tor_neighbors[tor1].eos_config(lines=cmd, parents="router bgp {}".format(neigh_asn[tor1]))


def test_bgp_passive_peering_ipv4(setup, enum_rand_one_frontend_asic_index):
    # configure passive EBGP peering session on DUT and ensure adjacency stays established (IPv4)
    cmd = 'vtysh -c "config" -c "router bgp {}" -c "neighbor {} passive"'.format(setup['dut_asn'],
                                                                                 setup['peer_group_v4'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)
    time.sleep(1)

    logger.info("DUT BGP Config: {}".format(setup['duthost'].shell("vtysh -n {} -c \"show run bgp\""
                                                                   .format(setup['namespace']),
                                                                   module_ignore_errors=True)))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_rand_one_frontend_asic_index)['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established'

    # configure password on DUT and ensure the adjacency is not established (IPv4)
    cmd = 'vtysh -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(setup['dut_asn'],
                                                                                     setup['peer_group_v4'],
                                                                                     peer_password)
    setup['duthost'].shell(cmd, module_ignore_errors=True)
    time.sleep(1)

    logger.info("DUT BGP Config: {}".format(setup['duthost'].shell("vtysh -n {} -c \"show run bgp\""
                                                                   .format(setup['namespace']),
                                                                   module_ignore_errors=True)))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_rand_one_frontend_asic_index)['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] != 'established'

    # configure password on Neighbor and ensure the adjacency is established (IPv4)
    cmd = ["neighbor {} password 0 {}".format(setup['dut_ip_v4'], peer_password)]
    logger.info(setup['neighhost'].eos_config(lines=cmd, parents="router bgp {}".format(setup['neigh_asn'])))
    logger.info(setup['neighhost'].eos_command(commands=["show run | section bgp"]))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_rand_one_frontend_asic_index)['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established'

    # configure mismatch password on DUT and ensure the adjacency is not established (IPv4)
    cmd = 'vtysh -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(setup['dut_asn'],
                                                                                     setup['peer_group_v4'],
                                                                                     wrong_password)
    setup['duthost'].shell(cmd, module_ignore_errors=True)
    time.sleep(1)

    logger.info("DUT BGP Config: {}".format(setup['duthost'].shell("vtysh -n {} -c \"show run bgp\""
                                                                   .format(setup['namespace']),
                                                                   module_ignore_errors=True)))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_rand_one_frontend_asic_index)['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] != 'established'


def test_bgp_passive_peering_ipv6(setup, enum_rand_one_frontend_asic_index):
    # configure passive EBGP peering session on DUT and ensure adjacency stays established (IPv6)
    cmd = 'vtysh -c "config" -c "router bgp {}" -c "neighbor {} passive"'.format(setup['dut_asn'],
                                                                                 setup['peer_group_v6'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)
    time.sleep(1)

    logger.info("DUT BGP Config: {}".format(setup['duthost'].shell("vtysh -n {} -c \"show run bgp\""
                                                                   .format(setup['namespace']),
                                                                   module_ignore_errors=True)))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_rand_one_frontend_asic_index)['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] == 'established'

    # configure password on DUT and ensure the adjacency is not established (IPv6)
    cmd = 'vtysh -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(setup['dut_asn'],
                                                                                     setup['peer_group_v6'],
                                                                                     peer_password)
    setup['duthost'].shell(cmd, module_ignore_errors=True)
    time.sleep(1)

    logger.info("DUT BGP Config: {}".format(setup['duthost'].shell("vtysh -n {} -c \"show run bgp\""
                                                                   .format(setup['namespace']),
                                                                   module_ignore_errors=True)))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_rand_one_frontend_asic_index)['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] != 'established'

    # configure password on Neighbor and ensure the adjacency is established (IPv6)
    cmd = ["neighbor {} password 0 {}".format(setup['dut_ip_v6'], peer_password)]
    logger.info(setup['neighhost'].eos_config(lines=cmd, parents="router bgp {}".format(setup['neigh_asn'])))
    logger.info(setup['neighhost'].eos_command(commands=["show run | section bgp"]))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_rand_one_frontend_asic_index)['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] == 'established'

    # configure mismatch password on DUT and ensure the adjacency is not established (IPv6)
    cmd = 'vtysh -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(setup['dut_asn'],
                                                                                     setup['peer_group_v6'],
                                                                                     wrong_password)
    setup['duthost'].shell(cmd, module_ignore_errors=True)
    time.sleep(1)

    logger.info("DUT BGP Config: {}".format(setup['duthost'].shell("vtysh -n {} -c \"show run bgp\""
                                                                   .format(setup['namespace']),
                                                                   module_ignore_errors=True)))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=enum_rand_one_frontend_asic_index)['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] != 'established'
