import ast
import logging
import re
import pytest

from typing import Any, Dict, List, Tuple, TypedDict

from collections import namedtuple, Counter
from tests.platform_tests.counterpoll.cpu_memory_helper import counterpoll_type         # noqa: F401
from tests.common.constants import CounterpollConstants
from tests.common.helpers.counterpoll_helper import ConterpollHelper
from tests.common.mellanox_data import is_mellanox_device
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology('any')
]

CLI_TO_COUNTER_POLL_STAT_TYPE = {
    cli_type: stat_type for stat_type, cli_type in CounterpollConstants.COUNTERPOLL_MAPPING.items()
}
MIN_MONITOR_SECONDS = 60
MIN_POLL_CYCLES = 3
# Keep the TIME_STAMP-change second and this many seconds before it (poll CPU is before the stamp update).
POLL_CPU_LOOKBACK_SEC = 2
SDK_API_SNIFFER_SCRIPT = "platform_tests/mellanox/files/sdk_api_sniffer.py"
SDK_API_SNIFFER_CONTAINER_PATH = "/sdk_api_sniffer.py"
SDK_API_SNIFFER_MODE_RE = re.compile(r"^(?:PREV_)?MODE_NAME=(?P<mode>\w+)$", re.MULTILINE)


class CpuMemoryPollSample(TypedDict):
    """One-second sample of process CPU, COUNTERS:TIME_STAMP, and system memory."""
    cpu: float
    stamp: str
    used_percent: float


def is_asan_image(duthost):
    asan_val_from_sonic_ver_cmd = "sonic-cfggen -y /etc/sonic/sonic_version.yml -v asan"
    asan_val = duthost.command(asan_val_from_sonic_ver_cmd)['stdout']
    is_asan = False
    if asan_val == "yes":
        logging.info("The current sonic image is a ASAN image")
        is_asan = True
    return is_asan


@pytest.fixture(scope='module')
def setup_thresholds(rand_selected_dut):
    duthost = rand_selected_dut
    is_chassis = duthost.get_facts().get("modular_chassis")
    cpu_threshold = 70 if is_chassis else 50
    memory_threshold = 60
    high_cpu_consume_procs = {}
    is_asan = is_asan_image(duthost)
    if ('arista_7800' in duthost.facts['platform'].lower()) or duthost.facts['platform'] in ('x86_64-mlnx_msn4600c-r0'):
        memory_threshold = 75
    if duthost.facts['platform'] in ('x86_64-arista_7050_qx32', 'x86_64-kvm_x86_64-r0', 'x86_64-arista_7050_qx32s',
                                     'x86_64-cel_e1031-r0', 'x86_64-arista_7800r3a_36dm2_lc') or is_asan:
        memory_threshold = 90
    if duthost.facts['platform'] in ('x86_64-mlnx_msn3800-r0', 'arm64-nvda_bf-bf3comdpu',
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


def test_cpu_memory_usage(rand_selected_dut, setup_thresholds):
    """Check DUT memory usage and process cpu usage are within threshold."""
    duthost = rand_selected_dut
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
def disable_pfcwd(rand_selected_dut):
    """
    Disable PFCWD before testing, and start_default after testing
    """
    duthost = rand_selected_dut
    pfcwd_status = duthost.shell(
        "sonic-db-cli CONFIG_DB hget \'DEVICE_METADATA|localhost\' \'default_pfcwd_status\'")['stdout']
    if pfcwd_status != 'enable':
        yield
        return
    duthost.shell('pfcwd stop')
    yield
    duthost.shell('pfcwd start_default')


def _run_sdk_api_sniffer_script(duthost, args):
    """Copy sdk_api_sniffer.py into syncd and run it; return stdout."""
    duthost.copy(src=SDK_API_SNIFFER_SCRIPT, dest="/tmp/sdk_api_sniffer.py")
    duthost.command("docker cp /tmp/sdk_api_sniffer.py syncd:{}".format(
        SDK_API_SNIFFER_CONTAINER_PATH))
    result = duthost.command(
        "docker exec syncd python3 {} {}".format(SDK_API_SNIFFER_CONTAINER_PATH, args))
    duthost.command("docker exec syncd rm -f {}".format(SDK_API_SNIFFER_CONTAINER_PATH))
    duthost.command("rm -f /tmp/sdk_api_sniffer.py", module_ignore_errors=True)
    return result["stdout"]


def _parse_sdk_api_sniffer_mode_name(stdout):
    match = SDK_API_SNIFFER_MODE_RE.search(stdout)
    return match.group("mode") if match else None


@pytest.fixture
def disable_sdk_api_sniffer(rand_selected_dut):
    """Disable SDK API sniffer during counterpoll CPU sampling, then restore it.

    Cyclic sniffer pcap rotation starts sxSnifferGzip inside sx_sdk and can spike
    process CPU unrelated to flex-counter work. Same syncd + python_sdk_api pattern
    as configure_packet_aging / packets_aging.py.
    """
    duthost = rand_selected_dut
    if not is_mellanox_device(duthost):
        yield
        return

    previous_mode = None
    try:
        stdout = _run_sdk_api_sniffer_script(duthost, "disable")
        previous_mode = _parse_sdk_api_sniffer_mode_name(stdout)
        logging.info("SDK API sniffer disable output: %s", stdout.strip())
    except Exception as err:
        logging.warning(
            "Failed to disable SDK API sniffer; continuing without it: %s", err)

    yield

    if previous_mode in ("cyclic", "linear"):
        try:
            stdout = _run_sdk_api_sniffer_script(
                duthost, "enable --mode {}".format(previous_mode))
            logging.info("SDK API sniffer restore output: %s", stdout.strip())
        except Exception as err:
            logging.warning("Failed to restore SDK API sniffer: %s", err)


def test_cpu_memory_usage_counterpoll(rand_selected_dut,
                                      setup_thresholds, restore_counter_poll, counterpoll_type,     # noqa: F811
                                      counterpoll_cpu_threshold, disable_pfcwd,
                                      disable_sdk_api_sniffer):
    """Check DUT memory usage and process cpu usage are within threshold.
    Disable SDK API sniffer so pcap gzip rotation does not inflate sx_sdk CPU
    Disable all counterpoll types except tested one
    Collect memory and CPUs usage for multiple poll cycles
    Compare the memory usage with the memory threshold
    Compare the average cpu usage with the cpu threshold for the specified progress
    Restore counterpolls status and SDK API sniffer
    """
    duthost = rand_selected_dut
    program_to_check = get_manufacturer_program_to_check(duthost)
    if program_to_check is None:
        pytest.skip("Skip no program is offered to check")

    memory_threshold, _, _ = setup_thresholds
    counterpoll_cpu_usage_threshold = counterpoll_cpu_threshold[counterpoll_type]

    MonitResult = namedtuple('MonitResult', ['processes', 'memory'])
    disable_all_counterpoll_type_except_tested(duthost, counterpoll_type)
    poll_interval_sec = get_effective_poll_interval_seconds(duthost, counterpoll_type)
    monitor_seconds = max(MIN_MONITOR_SECONDS, MIN_POLL_CYCLES * poll_interval_sec)
    stamp_field = get_flex_counter_time_stamp_field(duthost, counterpoll_type)
    samples = collect_cpu_memory_and_poll_stamps(
        duthost, program_to_check, stamp_field, monitor_seconds)

    outstanding_mem_polls = {}

    cpu_usage_program_to_check = [sample['cpu'] for sample in samples]
    for i, sample in enumerate(samples):
        logging.debug("------ Iteration %d ------", i)
        monit_result = MonitResult([], {'used_percent': sample['used_percent']})
        check_memory(i, memory_threshold, monit_result, outstanding_mem_polls)

    log_cpu_usage_by_vendor(cpu_usage_program_to_check, counterpoll_type)

    cpu_in_stamp_windows, poll_count = get_cpu_samples_in_poll_stamp_windows(
        cpu_usage_program_to_check, [sample['stamp'] for sample in samples])
    pytest_assert(
        poll_count >= MIN_POLL_CYCLES,
        "Expected at least {} {} polls (TIME_STAMP updates); observed {}".format(
            MIN_POLL_CYCLES, counterpoll_type, poll_count))
    cpu_usage_average = sum(cpu_in_stamp_windows) / len(cpu_in_stamp_windows)
    logging.info(
        "Average cpu_usage is {} (poll interval {}s, monitor {}s)".format(
            cpu_usage_average, poll_interval_sec, monitor_seconds))
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


def get_effective_poll_interval_seconds(duthost, counterpoll_type):
    """Return the DUT's configured counterpoll interval in seconds.

    Reads `counterpoll show` via `get_counter_poll_status()` instead of assuming
    the hardcoded 10s default. Interval is at least 1s.
    """
    stat_type = CLI_TO_COUNTER_POLL_STAT_TYPE[counterpoll_type]
    poll_interval_ms = duthost.get_counter_poll_status()[stat_type]['interval']
    poll_interval_sec = max(1, poll_interval_ms // 1000)
    logging.info(
        "Using effective counterpoll interval for %s: %sms (%ss)",
        counterpoll_type, poll_interval_ms, poll_interval_sec)
    return poll_interval_sec


def get_flex_counter_time_stamp_field(duthost, counterpoll_type: str) -> str:
    """Return the COUNTERS:TIME_STAMP hash field for this counterpoll group.

    The hash is updated when a flex-counter poll for that group finishes. Field
    names start with ``{STAT_TYPE}_STAT`` (e.g. PORT_BUFFER_DROP_STAT_...).
    Fails the test if no matching field exists.
    """
    prefix = CLI_TO_COUNTER_POLL_STAT_TYPE[counterpoll_type] + "_STAT"
    output = duthost.shell("sonic-db-cli COUNTERS_DB HGETALL COUNTERS:TIME_STAMP")["stdout"]
    # sonic-db-cli prints HGETALL as a Python dict, e.g.
    # {'PORT_BUFFER_DROP_STAT_Port_Counter_time_stamp': '75157997853692',
    #  'QUEUE_STAT_COUNTER_Queue_Counter_time_stamp': '75172715360322', ...}
    try:
        stamp_fields = ast.literal_eval(output.strip())
    except (SyntaxError, ValueError):
        pytest.fail("Could not parse COUNTERS:TIME_STAMP as a dict: {}".format(output))
    for field_name in stamp_fields:
        if field_name.startswith(prefix):
            logging.info("Using COUNTERS:TIME_STAMP field %s", field_name)
            return field_name
    pytest.fail(
        "No COUNTERS:TIME_STAMP field starting with {} in {}".format(prefix, list(stamp_fields)))


def get_program_cpu_percent(processes: List[Dict[str, Any]], program_to_check: str) -> float:
    """Return `cpu_percent` for `program_to_check` from a monit process list, or 0.0."""
    for proc in processes:
        if proc['name'] == program_to_check:
            return proc['cpu_percent']
    return 0.0


def collect_cpu_memory_and_poll_stamps(
        duthost, program_to_check: str, stamp_field: str,
        iterations: int) -> List[CpuMemoryPollSample]:
    """Collect one CpuMemoryPollSample per second for `iterations` seconds.

    Each sample records process CPU, system memory used_percent, and the
    COUNTERS:TIME_STAMP value so later analysis can tell which seconds overlap
    a flex-counter poll (stamp is written at the end of the poll).
    """
    stamp_cmd = "sonic-db-cli COUNTERS_DB HGET COUNTERS:TIME_STAMP {}".format(stamp_field)
    samples = []
    for i in range(iterations):
        processes, memory = duthost.monit_process(
            iterations=1, delay_interval=1)['monit_results'][0]
        stamp = duthost.shell(stamp_cmd)['stdout'].strip()
        samples.append({
            'cpu': get_program_cpu_percent(processes, program_to_check),
            'stamp': stamp,
            'used_percent': memory['used_percent'],
        })
        logging.debug(
            "Sample %d: cpu=%s stamp=%s mem=%s",
            i, samples[-1]['cpu'], stamp, samples[-1]['used_percent'])
    return samples


def get_cpu_samples_in_poll_stamp_windows(
        cpu_usage: List[float], stamps: List[str],
        lookback: int = POLL_CPU_LOOKBACK_SEC) -> Tuple[List[float], int]:
    """Return flattened CPU samples in COUNTERS:TIME_STAMP-change windows, and poll count.

    A stamp change at index i means a poll just finished. That second plus
    `lookback` seconds before it are kept (poll CPU is before the stamp write).
    Overlapping windows contribute each sample once.
    """
    kept_indices = []
    seen = set()
    poll_count = 0
    for i in range(1, len(stamps)):
        if stamps[i] and stamps[i] != stamps[i - 1]:
            poll_count += 1
            window_start = max(0, i - lookback)
            window_end = i + 1
            window_indices = list(range(window_start, window_end))
            logging.info(
                "Poll stamp window [%s:%s]: %s",
                window_start, window_end,
                [cpu_usage[j] for j in window_indices])
            for sample_index in window_indices:
                if sample_index not in seen:
                    seen.add(sample_index)
                    kept_indices.append(sample_index)
    return [cpu_usage[i] for i in kept_indices], poll_count


def check_cpu_usage(cpu_threshold, outstanding_procs, outstanding_procs_counter, proc):
    if proc['cpu_percent'] >= cpu_threshold:
        logging.debug("process %s(%d) cpu usage %d%% exceeds %d%%.",
                      proc['name'], proc['pid'], proc['cpu_percent'], cpu_threshold)
        outstanding_procs[proc['pid']] = proc.get('cmdline', proc['name'])
        outstanding_procs_counter[proc['pid']] += 1


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
