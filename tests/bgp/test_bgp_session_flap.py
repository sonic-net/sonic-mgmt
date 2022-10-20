'''This script is to test BGP session flapping on SONiC and monitor
the CPU.
'''
import logging

import pytest
import time
from tests.common.utilities import InterruptableThread
# from tests.common.utilities import join_all
import textfsm
import traceback

from natsort import natsorted

logger = logging.getLogger(__name__)
max_wait = 0
wait_time = 2
stop_threads = False
proc_textfsm = "./bgp/templates/show_proc_cpu.template"
bgp_sum_textfsm = "./bgp/templates/bgp_summary.template"

# on current virtual testbed the sanity check is not working
pytestmark = [pytest.mark.sanity_check(skip_sanity=True)]


def get_cpu_stats(dut):
    # cmd = 'vtysh -c "show processes cpu" '\
    #     '-c "show processes memory" '\
    #     '-c "show processes summary" '\
    #     '-c "show ip bgp summary" '\
    #     '-c "show ipv6 bgp summary"'
    # logger.info(dut.shell(cmd, module_ignore_errors=True))
    proc_cpu = dut.shell("show processes cpu | head -n 20", module_ignore_errors=True)['stdout']
    proc_mem = dut.shell("show processes memory | head -n 20", module_ignore_errors=True)['stdout']
    proc_sum = dut.shell("show processes summary | grep -v '0.0 0.0'", module_ignore_errors=True)['stdout']
    bgp_cpu = dut.shell("show processes cpu | grep bgp", module_ignore_errors=True)['stdout']
    bgp_v4_sum = dut.shell("show ip bgp summary | grep memory", module_ignore_errors=True)['stdout']
    bgp_v6_sum = dut.shell("show ipv6 bgp summary | grep memory", module_ignore_errors=True)['stdout']
    logger.info("CPU: {} Memory: {} Summary: {} BGP Memory: {} BGP IPv4: {} IPv6: {}"
                .format(proc_cpu, proc_mem, proc_sum, bgp_cpu, bgp_v4_sum, bgp_v6_sum))
    with open(proc_textfsm) as template:
        fsm = textfsm.TextFSM(template)
        result = fsm.ParseText(proc_cpu)
    logger.info(fsm.header)
    logger.info(result)


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


def flap_neighbor_session(neigh, asn):
    while(True):
        # cmd = ["shutdown"]
        # neigh.eos_config(lines=cmd, parents="router bgp {}".format(asn))
        # neigh.eos_command(commands=["enable", "config", "router bgp {}".format(asn), "shutdown"],
        #     answer="", prompt="\[confirm\]")
        # neigh.eos_config(lines=["no shutdown"], parents="router bgp {}".format(asn))
        neigh.kill_bgpd()
        neigh.start_bgpd()
        if stop_threads:
            break


def test_bgp_single_session_flaps(setup):
    flap_threads = []

    thread = InterruptableThread(
        target=flap_neighbor_session,
        args=(setup['neighhost'], setup['neigh_asn']))
    thread.daemon = True
    thread.start()
    flap_threads.append(thread)

    for i in range(10):
        get_cpu_stats(setup['duthost'])
        time.sleep(wait_time)

    logger.info("Wait for all the threads to stop ...")
    global stop_threads
    stop_threads = True
    for thread in flap_threads:
        thread_exception = thread.join(timeout=0.1,
                                       suppress_exception=True)
        if thread_exception:
            logger.debug("Exception in thread %r:", thread)
            logger.debug(
                "".join(traceback.format_exception(*thread_exception))
            )
    # join_all(flap_threads, max_wait)
    flap_threads = []
