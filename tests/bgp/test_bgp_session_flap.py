'''This script is to test BGP session flapping on SONiC and monitor
the CPU.
'''
import logging

import pytest
# import time
from tests.common.utilities import InterruptableThread
# import threading
from tests.common.utilities import join_all

from natsort import natsorted

logger = logging.getLogger(__name__)
# flap_threads = []
# flap_handle = dict()
max_wait = 0

# on current virtual testbed the sanity check is not working
pytestmark = [pytest.mark.sanity_check(skip_sanity=True)]


def get_cpu_stats(dut):
    cmd = 'vtysh -c "show processes cpu | head -n 20" '\
        '-c "show processes memory | head -n 20" '\
        '-c "show processes summary | grep -v \'0.0  0.0\'" '\
        '-c "show processes cpu | grep bgp" '\
        '-c "show processes memory | grep bgp" '\
        '-c "show ip bgp summary | grep memory" '\
        '-c "show ipv6 bgp summary | grep memory"'
    logger.info(dut.shell(cmd, module_ignore_errors=True))


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
            assert v['state'] == 'established'

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][tor1]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][tor1]['bgp']['peers'][dut_asn][1]

    # verify sessions are established
    logger.info(duthost.shell('show ip bgp summary'))
    logger.info(duthost.shell('show ipv6 bgp summary'))

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
        'peer_group_v6': peer_group_v6
    }

    logger.info("DUT BGP Config: {}".format(duthost.shell("show run bgp", module_ignore_errors=True)))
    logger.info("Neighbor BGP Config: {}".format(
        nbrhosts[tor1]["host"].eos_command(commands=["show run | section bgp"])))
    logger.info('Setup_info: {}'.format(setup_info))

    # get baseline BGP CPU and Memory Utilization
    get_cpu_stats(duthost)

    return setup_info


def flap_neighbor_session():
    logger.info("in thread")


def test_bgp_session_flaps(setup):
    flap_threads = []
    # flap_handle = dict()

    thread = InterruptableThread(
        target=flap_neighbor_session,
        args=())
    thread.daemon = True
    thread.start()
    flap_threads.append(thread)

    get_cpu_stats(setup['duthost'])

    logger.info("Wait for all the threads to start and stop ...")
    join_all(flap_threads, max_wait)
    flap_threads = []
    # flap_handle = dict()
