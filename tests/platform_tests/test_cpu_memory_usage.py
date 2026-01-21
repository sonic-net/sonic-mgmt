import logging
import pytest

from collections import namedtuple, Counter
from tests.platform_tests.counterpoll.cpu_memory_helper import restore_counter_poll     # noqa: F401
from tests.platform_tests.counterpoll.cpu_memory_helper import counterpoll_type         # noqa: F401
from tests.common.constants import CounterpollConstants
from tests.common.helpers.counterpoll_helper import ConterpollHelper
from tests.common.mellanox_data import is_mellanox_device
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology('any')
]


def is_asan_image(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    asan_val_from_sonic_ver_cmd = "sonic-cfggen -y /etc/sonic/sonic_version.yml -v asan"
    asan_val = duthost.command(asan_val_from_sonic_ver_cmd)['stdout']
    is_asan = False
    if asan_val == "yes":
        logging.info("The current sonic image is a ASAN image")
        is_asan = True
    return is_asan


@pytest.fixture(scope='module')
def setup_thresholds(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    is_chassis = duthost.get_facts().get("modular_chassis")
    cpu_threshold = 70 if is_chassis else 50
    memory_threshold = 60
    high_cpu_consume_procs = {}
    is_asan = is_asan_image(duthosts, enum_rand_one_per_hwsku_hostname)
    if ('arista_7800' in duthost.facts['platform'].lower()) or duthost.facts['platform'] in ('x86_64-mlnx_msn4600c-r0'):
        memory_threshold = 75
    if duthost.facts['platform'] in ('x86_64-arista_7050_qx32', 'x86_64-kvm_x86_64-r0', 'x86_64-arista_7050_qx32s',
                                     'x86_64-cel_e1031-r0', 'x86_64-arista_7800r3a_36dm2_lc') or is_asan:
        memory_threshold = 90
    if duthost.facts['platform'] in ('x86_64-mlnx_msn3800-r0',
                                     'x86_64-mlnx_msn2700-r0', 'x86_64-mlnx_msn2700a1-r0', 'x86_64-mlnx_msn3420-r0',
                                     'x86_64-arista_7060_cx32s'):
        memory_threshold = 70
    if duthost.facts['platform'] in ('x86_64-8800_rp_o-r0', 'x86_64-8800_rp-r0'):
        memory_threshold = 65
    if duthost.facts['platform'] in ('arm64-elba-asic-flash128-r0'):
        memory_threshold = 90
        cpu_threshold = 90
    if duthost.facts['platform'] in ('x86_64-arista_7260cx3_64'):
        high_cpu_consume_procs['syncd'] = 80
    # The CPU usage of `sx_sdk` on mellanox is expected to be higher, and the actual CPU usage
    # is correlated with the number of ports. So we ignore the check of CPU for sx_sdk
    if duthost.facts["asic_type"] == 'mellanox':
        high_cpu_consume_procs['sx_sdk'] = 90
    num_cpu = int(duthost.command('nproc --all')['stdout_lines'][0])
    cpu_threshold = cpu_threshold * num_cpu
    return memory_threshold, cpu_threshold, high_cpu_consume_procs


def test_cpu_memory_usage(duthosts, enum_rand_one_per_hwsku_hostname, setup_thresholds):
    """Check DUT memory usage and process cpu usage are within threshold."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    # Wait until all critical services is fully started
    pytest_assert(wait_until(360, 20, 0, duthost.critical_services_fully_started),
                  "All critical services must be fully started!{}".format(duthost.critical_services))
    MonitResult = namedtuple('MonitResult', ['processes', 'memory'])
    monit_results = duthost.monit_process(iterations=24)['monit_results']

    memory_threshold, normal_cpu_threshold, high_cpu_consume_procs = setup_thresholds
    persist_threshold = 8
    outstanding_mem_polls = {}
    outstanding_procs = {}
    outstanding_procs_counter = Counter()
    for i, monit_result in enumerate(MonitResult(*_) for _ in monit_results):
        logging.debug("------ Iteration %d ------", i)
        check_memory(i, memory_threshold, monit_result, outstanding_mem_polls)
        for proc in monit_result.processes:
            cpu_threshold = normal_cpu_threshold
            if proc['name'] == 'nasa':
                logging.info("skip nasa proc")
                continue
            if proc['name'] in high_cpu_consume_procs:
                cpu_threshold = high_cpu_consume_procs[proc['name']]
            check_cpu_usage(cpu_threshold, outstanding_procs,
                            outstanding_procs_counter, proc)
    analyse_monitoring_results(cpu_threshold, memory_threshold, outstanding_mem_polls, outstanding_procs,
                               outstanding_procs_counter, persist_threshold)


def analyse_monitoring_results(cpu_threshold, memory_threshold, outstanding_mem_polls, outstanding_procs,
                               outstanding_procs_counter, persist_threshold):
    persist_outstanding_procs = []
    reason = []
    for pid, freq in outstanding_procs_counter.most_common():
        if freq <= persist_threshold:
            continue
        persist_outstanding_procs.append({"pid": pid, "freq": freq})
    if outstanding_mem_polls or persist_outstanding_procs:
        if outstanding_mem_polls:
            logging.error("system memory usage exceeds %d%%", memory_threshold)
            all_mem_usage = [f"{per['used_percent']}%" for per in outstanding_mem_polls.values()]
            reason.append(f"system memory usage is [{', '.join(all_mem_usage)}], threshold is {memory_threshold}%")
        if persist_outstanding_procs:
            logging.error(
                "processes that persistently exceeds cpu usage %d%%: %s",
                cpu_threshold,
                [outstanding_procs[p['pid']] for p in persist_outstanding_procs]
            )
            all_freqs = [f"{proc['freq']}%" for proc in persist_outstanding_procs]
            reason.append(f"system cpu usage is [{', '.join(all_freqs)}], cpu threshold is {cpu_threshold}%")
        pytest.fail("system cpu and memory usage check fails due to " + "; ".join(reason))


@pytest.fixture(scope='module')
def counterpoll_cpu_threshold(duthosts, request):
    counterpoll_cpu_usage_threshold = {
        "port-buffer-drop": request.config.getoption("--port_buffer_drop_cpu_usage_threshold")}
    return counterpoll_cpu_usage_threshold


@pytest.fixture
def disable_pfcwd(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Disable PFCWD before testing, and start_default after testing
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    pfcwd_status = duthost.shell(
        "sonic-db-cli CONFIG_DB hget \'DEVICE_METADATA|localhost\' \'default_pfcwd_status\'")['stdout']
    if pfcwd_status != 'enable':
        yield
        return
    duthost.shell('pfcwd stop')
    yield
    duthost.shell('pfcwd start_default')


def test_cpu_memory_usage_counterpoll(duthosts, enum_rand_one_per_hwsku_hostname,
                                      setup_thresholds, restore_counter_poll, counterpoll_type,     # noqa: F811
                                      counterpoll_cpu_threshold, disable_pfcwd):
    """Check DUT memory usage and process cpu usage are within threshold.
    Disable all counterpoll types except tested one
    Collect memory and CPUs usage for 60 secs
    Compare the memory usage with the memory threshold
    Compare the average cpu usage with the cpu threshold for the specified progress
    Restore counterpolls status
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    program_to_check = get_manufacturer_program_to_check(duthost)
    if program_to_check is None:
        pytest.skip("Skip no program is offered to check")

    memory_threshold, _, _ = setup_thresholds
    counterpoll_cpu_usage_threshold = counterpoll_cpu_threshold[counterpoll_type]

    MonitResult = namedtuple('MonitResult', ['processes', 'memory'])
    disable_all_counterpoll_type_except_tested(duthost, counterpoll_type)
    monit_results = duthost.monit_process(
        iterations=60, delay_interval=1)['monit_results']
    poll_interval = CounterpollConstants.COUNTERPOLL_INTERVAL[counterpoll_type] // 1000

    outstanding_mem_polls = {}
    outstanding_procs = {}
    outstanding_procs_counter = Counter()

    cpu_usage_program_to_check = []

    prepare_ram_cpu_usage_results(MonitResult, counterpoll_cpu_usage_threshold, memory_threshold,
                                  monit_results, outstanding_mem_polls, outstanding_procs,
                                  outstanding_procs_counter, program_to_check, cpu_usage_program_to_check)

    log_cpu_usage_by_vendor(cpu_usage_program_to_check, counterpoll_type)

    cpu_usage_average = caculate_cpu_usge_average_value(extract_valid_cpu_usage_data(
        cpu_usage_program_to_check, poll_interval), cpu_usage_program_to_check)
    logging.info("Average cpu_usage is {}".format(cpu_usage_average))
    assert cpu_usage_average < counterpoll_cpu_usage_threshold, \
        "cpu_usage_average of {} exceeds the cpu threshold:{}"\
        .format(program_to_check, counterpoll_cpu_usage_threshold)
    assert not outstanding_mem_polls, " Memory {} exceeds the memory threshold {} ".format(
        outstanding_mem_polls, memory_threshold)


def log_cpu_usage_by_vendor(cpu_usage_program_to_check, counterpoll_type):      # noqa: F811
    if cpu_usage_program_to_check:
        logging.info('CPU usage for counterpoll type {} : {}'.format(
            counterpoll_type, cpu_usage_program_to_check))


def get_manufacturer_program_to_check(duthost):
    if is_mellanox_device(duthost):
        return CounterpollConstants.SX_SDK


def prepare_ram_cpu_usage_results(MonitResult, cpu_threshold, memory_threshold, monit_results, outstanding_mem_polls,
                                  outstanding_procs, outstanding_procs_counter, program_to_check,
                                  program_to_check_cpu_usage):
    for i, monit_result in enumerate(MonitResult(*_) for _ in monit_results):
        logging.debug("------ Iteration %d ------", i)
        check_memory(i, memory_threshold, monit_result, outstanding_mem_polls)
        for proc in monit_result.processes:
            update_cpu_usage_desired_program(
                proc, program_to_check, program_to_check_cpu_usage)


def extract_valid_cpu_usage_data(program_to_check_cpu_usage, poll_interval):
    """
    This method it to extract the valid cpu usage data according to the poll_interval
    1. Find the index for the max one for every poll interval,
    2. Discard the data if the index is on the edge(0 o the length of program_to_check_cpu_usage -1)
    3. If the index is closed in the neighbour interval, only keep the former one
    4. Return all indexes
    For example:
    poll_interval = 10
    7, 1, 0, 1, 0, 1, 5, 1, 1,2, 0, 1, 0, 1, 0, 6, 1, 1, 1,2
    return [15]
    0, 1, 0, 1, 0, 1, 0, 1, 0, 8, 7, 1, 0, 1, 0, 6, 1, 1, 1,2
    return [9]
    """
    valid_cpu_usage_center_index_list = []
    poll_number = len(program_to_check_cpu_usage) // poll_interval

    def find_max_cpu_usage(cpu_usage_list, poll_times):
        max_cpu_usage = cpu_usage_list[0]
        max_cpu_usage_index = 0
        for i, cpu_usage in enumerate(cpu_usage_list):
            if cpu_usage > max_cpu_usage:
                max_cpu_usage = cpu_usage
                max_cpu_usage_index = i
        return [max_cpu_usage, max_cpu_usage_index + poll_times * poll_interval]

    for i in range(0, poll_number):
        max_cpu_usage, max_cpu_usage_index = find_max_cpu_usage(
            program_to_check_cpu_usage[poll_interval * i:poll_interval * (i + 1)], i)
        if max_cpu_usage_index == 0 or max_cpu_usage_index == len(program_to_check_cpu_usage) - 1:
            logging.info("The data is on the edge:{}, discard it ".format(
                max_cpu_usage_index))
        else:
            if valid_cpu_usage_center_index_list and valid_cpu_usage_center_index_list[-1] + 1 == max_cpu_usage_index:
                continue
            valid_cpu_usage_center_index_list.append(max_cpu_usage_index)

    return valid_cpu_usage_center_index_list


def caculate_cpu_usge_average_value(valid_cpu_usage_center_index_list, program_to_check_cpu_usage):
    len_valid_cpu_usage = len(valid_cpu_usage_center_index_list)
    cpu_usage_average = 0.0
    for i in valid_cpu_usage_center_index_list:
        cpu_usage_average += sum(program_to_check_cpu_usage[i - 1: i + 2])
        logging.info("cpu usage center index:{}: cpu usage:{}".format(
            i, program_to_check_cpu_usage[i - 1:i + 2]))
    return cpu_usage_average / len_valid_cpu_usage / 3.0 if len_valid_cpu_usage != 0 else 0


def check_cpu_usage(cpu_threshold, outstanding_procs, outstanding_procs_counter, proc):
    if proc['cpu_percent'] >= cpu_threshold:
        logging.debug("process %s(%d) cpu usage %d%% exceeds %d%%.",
                      proc['name'], proc['pid'], proc['cpu_percent'], cpu_threshold)
        outstanding_procs[proc['pid']] = proc.get('cmdline', proc['name'])
        outstanding_procs_counter[proc['pid']] += 1


def update_cpu_usage_desired_program(proc, program_to_check, program_to_check_cpu_usage):
    if program_to_check:
        if proc['name'] == program_to_check:
            program_to_check_cpu_usage.append(proc['cpu_percent'])


def check_memory(i, memory_threshold, monit_result, outstanding_mem_polls):
    used_memory_percent = monit_result.memory['used_percent']
    logging.debug(
        "System memory usage: %d%% (%s %d%%) - Result: %s",
        used_memory_percent,
        "exceed" if used_memory_percent > memory_threshold else "below",
        memory_threshold,
        monit_result.memory
    )
    if used_memory_percent > memory_threshold:
        outstanding_mem_polls[i] = monit_result.memory


def disable_all_counterpoll_type_except_tested(duthost, counterpoll_type):      # noqa: F811
    available_types = ConterpollHelper.get_available_counterpoll_types(duthost)
    available_types.remove(counterpoll_type)
    ConterpollHelper.disable_counterpoll(duthost, available_types)
