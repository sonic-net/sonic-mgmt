'''

This script is to Verify applied communities manipulate traffic as 
expected between 4-byte and 2-byte AS neighbors.

'''
import logging

import pytest
import time
import re

from natsort import natsorted

logger = logging.getLogger(__name__)
dut_4byte_asn = 400003
neighbor_4byte_asn = 400001


pytestmark = [
    pytest.mark.topology('t0')
]

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

    # verify sessions are established and gather neighbor information
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
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
        nbrhosts[tor1]["host"].eos_command(commands=["show run | section bgp"])))
    logger.info('Setup_info: {}'.format(setup_info))

    yield setup_info

def test_(setup):
    # if setup['duthost'].get_facts()['asic_type'] == 'vs':
    #     logger.info("vs asic type")
    # logger.info(setup['duthost'].get_facts()['asics_present'])
    bgp_run = setup['duthost'].shell('show run bgp')['stdout']
    bgp_index = bgp_run.index("router bgp {}".format(setup['dut_asn']))
    sub_bgp = re.sub("router bgp {}".format(setup['dut_asn']), "router bgp {}".format(dut_4byte_asn), bgp_run)[bgp_index:]
    logger.info(sub_bgp)
