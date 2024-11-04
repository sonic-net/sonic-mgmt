'''

This script is to test BGP session flapping on SONiC and monitor
the CPU.

'''

import logging

import pytest
import time
from tests.common.utilities import InterruptableThread
import textfsm
import traceback

from natsort import natsorted

logger = logging.getLogger(__name__)
max_wait = 0
wait_time = 2
stop_threads = False
proc_textfsm = "./bgp/templates/show_proc_cpu.template"
bgp_sum_textfsm = "./bgp/templates/bgp_summary.template"
flap_threads = []
skip_hosts = []

cpuSpike = 10
memSpike = 1.3

pytestmark = [
    pytest.mark.topology('t1', 't2')
]


def get_cpu_stats(dut):
    proc_cpu = dut.shell("show processes cpu | head -n 20", module_ignore_errors=True)['stdout']
    proc_mem = dut.shell("show processes memory | head -n 20", module_ignore_errors=True)['stdout']
    proc_sum = dut.shell("show processes summary | grep -v '0.0 0.0'", module_ignore_errors=True)['stdout']
    bgp_cpu = dut.shell("show processes cpu | grep bgp", module_ignore_errors=True)['stdout']
    bgp_v4_sum = dut.shell("show ip bgp summary | grep memory", module_ignore_errors=True)['stdout']
    bgp_v6_sum = dut.shell("show ipv6 bgp summary | grep memory", module_ignore_errors=True)['stdout']
    logger.info("CPU:\n{}\nMemory:\n{}\nSummary:\n{}\nBGP Memory:\n{}\nBGP IPv4:\n{}\nIPv6:\n{}\n"
                .format(proc_cpu, proc_mem, proc_sum, bgp_cpu, bgp_v4_sum, bgp_v6_sum))
    with open(proc_textfsm) as template:
        fsm = textfsm.TextFSM(template)
        parsed_cpu = fsm.ParseText(proc_cpu)[0]

    with open(bgp_sum_textfsm) as template:
        fsm = textfsm.TextFSM(template)
        parsed_ipv4 = fsm.ParseText(bgp_v4_sum)[0]
        parsed_ipv6 = fsm.ParseText(bgp_v6_sum)[0]
    data = [float(parsed_cpu[0]), float(parsed_cpu[1]), float(parsed_cpu[2]),
            float(parsed_ipv4[0]), float(parsed_ipv4[1]), float(parsed_ipv4[2]),
            float(parsed_ipv6[0]), float(parsed_ipv6[1]), float(parsed_ipv6[2])]
    return data


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, enum_frontend_dut_hostname, enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_frontend_asic_index
    namespace = duthost.get_namespace_from_asic_id(asic_index)

    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    neigh_keys = []
    tor_neighbors = dict()
    neigh_asn = dict()
    for k, v in bgp_facts['bgp_neighbors'].items():
        if 'asic' not in v['description'].lower():
            neigh_keys.append(v['description'])
            neigh_asn[v['description']] = v['remote AS']
            tor_neighbors[v['description']] = nbrhosts[v['description']]["host"]
            assert v['state'] == 'established'

    if not neigh_keys:
        pytest.skip("No BGP neighbors found on ASIC {} of DUT {}".format(asic_index, duthost.hostname))

    tor1 = natsorted(neigh_keys)[0]

    # verify sessions are established
    logger.info(duthost.shell('show ip bgp summary'))
    logger.info(duthost.shell('show ipv6 bgp summary'))

    setup_info = {
        'duthost': duthost,
        'neighhost': tor_neighbors[tor1],
        'neigh_asn': neigh_asn[tor1],
        'asn_dict':  neigh_asn,
        'neighbors': tor_neighbors,
        'namespace': namespace
    }

    logger.info("DUT BGP Config: {}".format(duthost.shell("vtysh -n {} -c \"show run bgp\"".format(namespace),
                                                          module_ignore_errors=True)))
    logger.info("Neighbor BGP Config: {}".format(
        nbrhosts[tor1]["host"].eos_command(commands=["show run | section bgp"])))
    logger.info('Setup_info: {}'.format(setup_info))

    #  get baseline BGP CPU and Memory Utilization
    get_cpu_stats(duthost)

    yield setup_info

    global stop_threads
    global flap_threads
    stop_threads = True
    time.sleep(wait_time)

    # ensure no threads are left running
    for thread in flap_threads:
        thread_exception = thread.join(timeout=0.1,
                                       suppress_exception=True)
        if thread_exception:
            logger.debug("Exception in thread %r:", thread)
            logger.debug(
                "".join(traceback.format_exception(*thread_exception))
            )
    flap_threads = []

    for neigh in tor_neighbors:
        tor_neighbors[neigh].start_bgpd()
    time.sleep(30)

    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            assert v['state'] == 'established'


def flap_neighbor_session(neigh):
    while (True):
        neigh.kill_bgpd()
        neigh.start_bgpd()
        if stop_threads:
            logger.info("stop_threads now true, breaking loop")
            break


def test_bgp_single_session_flaps(setup):
    global flap_threads
    global stop_threads
    stop_threads = False

    # get baseline stat information
    stats = []
    stats.append(get_cpu_stats(setup['duthost']))

    # start threads to flap neighbor sessions
    thread = InterruptableThread(
        target=flap_neighbor_session,
        args=(setup['neighhost']))
    thread.daemon = True
    thread.start()
    flap_threads.append(thread)

    for i in range(10):
        stats.append(get_cpu_stats(setup['duthost']))
        index = len(stats) - 1
        assert stats[index][0] < (stats[0][0] + cpuSpike)
        assert stats[index][1] < (stats[0][1] + cpuSpike)
        assert stats[index][2] < (stats[0][2] + cpuSpike)
        assert stats[index][3] < (stats[0][3] * memSpike)
        assert stats[index][4] < (stats[0][4] * memSpike)
        assert stats[index][5] < (stats[0][5] * memSpike)
        assert stats[index][6] < (stats[0][6] * memSpike)
        assert stats[index][7] < (stats[0][7] * memSpike)
        assert stats[index][8] < (stats[0][8] * memSpike)

        time.sleep(wait_time)

    stop_threads = True
    time.sleep(wait_time)

    for thread in flap_threads:
        thread_exception = thread.join(timeout=0.1,
                                       suppress_exception=True)
        if thread_exception:
            logger.debug("Exception in thread %r:", thread)
            logger.debug(
                "".join(traceback.format_exception(*thread_exception))
            )
    flap_threads = []


def test_bgp_multiple_session_flaps(setup):
    global flap_threads
    global stop_threads
    stop_threads = False

    # get baseline stat information
    stats = []
    stats.append(get_cpu_stats(setup['duthost']))

    # start threads to flap neighbor sessions
    for neigh in setup['neighbors']:
        thread = InterruptableThread(
            target=flap_neighbor_session,
            args=(neigh))
        thread.daemon = True
        thread.start()
        flap_threads.append(thread)

    for i in range(10):
        stats.append(get_cpu_stats(setup['duthost']))
        index = len(stats) - 1
        assert stats[index][0] < (stats[0][0] + cpuSpike)
        assert stats[index][1] < (stats[0][1] + cpuSpike)
        assert stats[index][2] < (stats[0][2] + cpuSpike)
        assert stats[index][3] < (stats[0][3] * memSpike)
        assert stats[index][4] < (stats[0][4] * memSpike)
        assert stats[index][5] < (stats[0][5] * memSpike)
        assert stats[index][6] < (stats[0][6] * memSpike)
        assert stats[index][7] < (stats[0][7] * memSpike)
        assert stats[index][8] < (stats[0][8] * memSpike)

        time.sleep(wait_time)

    stop_threads = True
    time.sleep(wait_time)

    for thread in flap_threads:
        thread_exception = thread.join(timeout=0.1,
                                       suppress_exception=True)
        if thread_exception:
            logger.debug("Exception in thread %r:", thread)
            logger.debug(
                "".join(traceback.format_exception(*thread_exception))
            )
    flap_threads = []
