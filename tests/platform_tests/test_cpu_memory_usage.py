import logging
import pytest

from collections import namedtuple, Counter
from tests.platform_tests.counterpoll.cpu_memory_helper import restore_counter_poll, counterpoll_type
from tests.platform_tests.counterpoll.counterpoll_helper import ConterpollHelper
from tests.platform_tests.counterpoll.counterpoll_constants import CounterpollConstants
from tests.common.errors import RunAnsibleModuleFail


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
        check_memory(i, memory_threshold, monit_result, outstanding_mem_polls)
        for proc in monit_result.processes:
            check_cpu_usage(cpu_threshold, outstanding_procs, outstanding_procs_counter, proc)

    analyse_monitoring_results(cpu_threshold, memory_threshold, outstanding_mem_polls, outstanding_procs,
                               outstanding_procs_counter, persist_threshold)


def analyse_monitoring_results(cpu_threshold, memory_threshold, outstanding_mem_polls, outstanding_procs,
                               outstanding_procs_counter, persist_threshold):
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


def test_cpu_memory_usage_counterpoll(duthosts, enum_rand_one_per_hwsku_hostname, setup_thresholds,
                                           restore_counter_poll,
                                           counterpoll_type):
    """Check DUT memory usage and process cpu usage are within threshold.
    If mlnx add additional check, when setting port-buffer-drop to 10000 or 30000 and compare cpu usage
    Before the test check counterpoll status and interval
    Disable all counterpoll types except tested
    Check current CPU usage for 30 sec
        IF mlnx and tested counerpoll is port-buffer-drop. Configure interval to 10000
    Check current CPU usage for 30 sec
    Restore counterpoll interval and status to state before the test
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    MonitResult = namedtuple('MonitResult', ['processes', 'memory'])
    disable_all_counterpoll_type_except_tested(duthost, counterpoll_type)
    monit_results = duthost.monit_process(iterations=30, delay_interval=1)['monit_results']

    memory_threshold, cpu_threshold = setup_thresholds
    persist_threshold = 4
    outstanding_mem_polls = {}
    outstanding_procs = {}
    outstanding_procs_counter = Counter()

    program_to_check = get_manufacturer_program_to_check(duthost)
    cpu_usage_program_to_check = []

    prepare_ram_cpu_usage_results(MonitResult, cpu_threshold, memory_threshold, monit_results, outstanding_mem_polls,
                                  outstanding_procs, outstanding_procs_counter, program_to_check,
                                  cpu_usage_program_to_check)

    set_mellanox_counterpoll_port_bufer_drop(duthost, counterpoll_type)

    monit_results.extend(duthost.monit_process(iterations=30, delay_interval=1)['monit_results'])
    prepare_ram_cpu_usage_results(MonitResult, cpu_threshold, memory_threshold, monit_results, outstanding_mem_polls,
                                  outstanding_procs, outstanding_procs_counter, program_to_check,
                                  cpu_usage_program_to_check)
    log_cpu_usage_by_vendor(cpu_usage_program_to_check, counterpoll_type)

    analyse_monitoring_results(cpu_threshold, memory_threshold, outstanding_mem_polls, outstanding_procs,
                               outstanding_procs_counter, persist_threshold)


def log_cpu_usage_by_vendor(cpu_usage_program_to_check, counterpoll_type):
    if cpu_usage_program_to_check:
        logging.info('CPU usage for counterpoll type {} : {}'.format(
                counterpoll_type, cpu_usage_program_to_check[:len(cpu_usage_program_to_check)//2]))
        if counterpoll_type == CounterpollConstants.PORT_BUFFER_DROP:
            logging.info('CPU usage after setting counterpoll {} to minimum allowed value next 30 seconds: {}'.format(
                counterpoll_type, cpu_usage_program_to_check[len(cpu_usage_program_to_check)//2:]))
        else:
            logging.info('CPU usage for counterpoll type {} next 30 seconds: {}'.format(
                counterpoll_type, cpu_usage_program_to_check[:len(cpu_usage_program_to_check) // 2]))


def get_manufacturer_program_to_check(duthost):
    if is_mlnx(duthost):
        return CounterpollConstants.SX_SDK
    else:
        None


def is_mlnx(duthost):
    if CounterpollConstants.MLNX_PLATFORM_STR in duthost.facts["platform"]:
        return True


def prepare_ram_cpu_usage_results(MonitResult, cpu_threshold, memory_threshold, monit_results, outstanding_mem_polls,
                                  outstanding_procs, outstanding_procs_counter, program_to_check,
                                  program_to_check_cpu_usage):
    for i, monit_result in enumerate(MonitResult(*_) for _ in monit_results):
        logging.debug("------ Iteration %d ------", i)
        check_memory(i, memory_threshold, monit_result, outstanding_mem_polls)
        for proc in monit_result.processes:
            update_cpu_usage_desired_program(proc, program_to_check, program_to_check_cpu_usage)
            check_cpu_usage(cpu_threshold, outstanding_procs, outstanding_procs_counter, proc)


def check_cpu_usage(cpu_threshold, outstanding_procs, outstanding_procs_counter, proc):
    if proc['cpu_percent'] >= cpu_threshold:
        logging.debug("process %s(%d) cpu usage exceeds %d%%.",
                      proc['name'], proc['pid'], cpu_threshold)
        outstanding_procs[proc['pid']] = proc['name']
        outstanding_procs_counter[proc['pid']] += 1


def update_cpu_usage_desired_program(proc, program_to_check, program_to_check_cpu_usage):
    if program_to_check:
        if proc['name'] == program_to_check:
            program_to_check_cpu_usage.append(proc['cpu_percent'])


def check_memory(i, memory_threshold, monit_result, outstanding_mem_polls):
    if monit_result.memory['used_percent'] > memory_threshold:
        logging.debug("system memory usage exceeds %d%%: %s",
                      memory_threshold, monit_result.memory)
        outstanding_mem_polls[i] = monit_result.memory


def set_mellanox_counterpoll_port_bufer_drop(duthost, counterpoll_type):
    if not is_mlnx(duthost) or counterpoll_type != CounterpollConstants.PORT_BUFFER_DROP:
        return
    try:
        duthost.command(CounterpollConstants.COUNTERPOLL_INTERVAL_STR.format(
            CounterpollConstants.PORT_BUFFER_DROP,
            CounterpollConstants.PORT_BUFFER_DROP_NEW_INTERVAL))
    except RunAnsibleModuleFail:
        logging.warning('Version does not support new counterpoll interval for port-buffer-drop={}\n'
                        'Setting old ounterpoll interval for port-buffer-drop={}'.format(
            CounterpollConstants.PORT_BUFFER_DROP_NEW_INTERVAL,
            CounterpollConstants.PORT_BUFFER_DROP_OLD_INTERVAL))
        duthost.command(CounterpollConstants.COUNTERPOLL_INTERVAL_STR.format(
            CounterpollConstants.PORT_BUFFER_DROP,
            CounterpollConstants.PORT_BUFFER_DROP_OLD_INTERVAL))


def disable_all_counterpoll_type_except_tested(duthost, counterpoll_type):
    available_types = ConterpollHelper.get_available_counterpoll_types(duthost)
    available_types.remove(counterpoll_type)
    ConterpollHelper.disable_counterpoll(duthost, available_types)
