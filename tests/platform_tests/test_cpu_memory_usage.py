import logging
import pytest

from collections import namedtuple, Counter


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical'),
]


@pytest.fixture(scope='module')
def setup_thresholds(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    cpu_threshold = 50
    memory_threshold = 60
    high_cpu_consume_procs = {}
    if duthost.facts['platform'] in ('x86_64-arista_7050_qx32', 'x86_64-kvm_x86_64-r0'):
        memory_threshold = 80
    if duthost.facts['platform'] in ('x86_64-arista_7260cx3_64'):
        high_cpu_consume_procs['syncd'] = 80
    # The CPU usage of `sx_sdk` on mellanox is expected to be higher, and the actual CPU usage
    # is correlated with the number of ports. So we ignore the check of CPU for sx_sdk
    if duthost.facts["asic_type"] == 'mellanox':
        high_cpu_consume_procs['sx_sdk'] = 90
    return memory_threshold, cpu_threshold, high_cpu_consume_procs

def test_cpu_memory_usage(duthosts, enum_rand_one_per_hwsku_hostname, setup_thresholds):
    """Check DUT memory usage and process cpu usage are within threshold."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    MonitResult = namedtuple('MonitResult', ['processes', 'memory'])
    monit_results = duthost.monit_process(iterations=24)['monit_results']

    memory_threshold, normal_cpu_threshold, high_cpu_consume_procs = setup_thresholds
    persist_threshold = 8
    outstanding_mem_polls = {}
    outstanding_procs = {}
    outstanding_procs_counter = Counter()
    for i, monit_result in enumerate(MonitResult(*_) for _ in monit_results):
        logging.debug("------ Iteration %d ------", i)
        if monit_result.memory['used_percent'] > memory_threshold:
            logging.debug("system memory usage exceeds %d%%: %s",
                          memory_threshold, monit_result.memory)
            outstanding_mem_polls[i] = monit_result.memory
        for proc in monit_result.processes:
            cpu_threshold = normal_cpu_threshold
            if high_cpu_consume_procs.has_key(proc['name']):
                cpu_threshold = high_cpu_consume_procs[proc['name']]                
            if proc['cpu_percent'] >= cpu_threshold:
                logging.debug("process %s(%d) cpu usage exceeds %d%%.",
                              proc['name'], proc['pid'], cpu_threshold)
                outstanding_procs[proc['pid']] = proc['name']
                outstanding_procs_counter[proc['pid']] += 1

    persist_outstanding_procs = []
    for pid, freq in outstanding_procs_counter.most_common():
        if freq <= persist_threshold:
            break
        persist_outstanding_procs.append(pid)

    if outstanding_mem_polls or persist_outstanding_procs:
        failure_message = ""

        if outstanding_mem_polls:
            failure_message += "System memory usage exceeds {}%".format(memory_threshold)
            if persist_outstanding_procs:
                failure_message += "; "

        if persist_outstanding_procs:
            failure_message += "Processes that persistently exceed CPU usage ({}%): {}".format(
                cpu_threshold, [outstanding_procs[p] for p in persist_outstanding_procs])

        pytest.fail(failure_message)
