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
    if duthost.facts['platform'] in ('x86_64-arista_7050_qx32', 'x86_64-kvm_x86_64-r0'):
        memory_threshold = 80
    return memory_threshold, cpu_threshold


def test_cpu_memory_usage(duthosts, enum_rand_one_per_hwsku_hostname, setup_thresholds):
    """Check DUT memory usage and process cpu usage are within threshold."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    MonitResult = namedtuple('MonitResult', ['processes', 'memory'])
    monit_results = duthost.monit_process(iterations=12)['monit_results']

    memory_threshold, cpu_threshold = setup_thresholds
    persist_threshold = 4
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
            if proc['cpu_percent'] >= cpu_threshold:
                logging.debug("process %s(%d) cpu usage exceeds %d%%.",
                              proc['name'], proc['pid'], cpu_threshold)
                outstanding_procs[proc['pid']] = proc['name']
                outstanding_procs_counter[proc['pid']] += 1

    persist_outstanding_procs = []
    for pid, freq in outstanding_procs_counter.most_common():
        if freq < persist_threshold:
            break
        persist_outstanding_procs.append(pid)

    if outstanding_mem_polls or persist_outstanding_procs:
        if outstanding_mem_polls:
            logging.error("system memory usage exceeds %d%%", memory_threshold)
        if persist_outstanding_procs:
            logging.error(
                "processes that persistently exceeds cpu usage %d%%: %s",
                cpu_threshold,
                [outstanding_procs[p] for p in persist_outstanding_procs]
            )
        pytest.fail("system cpu and memory usage check fails")
