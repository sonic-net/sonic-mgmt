"""
This test file uses python and validates various test cases that Monit is able
to correctly handle the recovery actions when a container exceeds the memory
threshold.
"""
import dateutil.parser
import logging
import re
import time
import pytest

from pkg_resources import parse_version
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.dut_utils import check_container_state
from tests.common.helpers.dut_utils import is_container_running
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

CONTAINER_STOP_THRESHOLD_SECS = 200
CONTAINER_RESTART_THRESHOLD_SECS = 180
CONTAINER_CHECK_INTERVAL_SECS = 1
MONIT_RESTART_THRESHOLD_SECS = 320
MONIT_CHECK_INTERVAL_SECS = 5
WAITING_SYSLOG_MSG_SECS = 30
MONIT_MEMORY_CHECK_TIMEOUT = 700


def remove_container(duthost, container_name):
    """Removes the specified container on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: A string represents name of the container.

    Returns:
        None.
    """
    if not is_container_running(duthost, container_name):
        pytest.fail("'{}' container is not running on DuT '{}'!".format(container_name, duthost.hostname))

    logger.info("Stopping '{}' container ...".format(container_name))
    duthost.shell("systemctl stop {}.service".format(container_name))
    logger.info("'{}' container is stopped.".format(container_name))

    logger.info("Removing '{}' container ...".format(container_name))
    duthost.shell("docker rm {}".format(container_name))
    logger.info("'{}' container is removed.".format(container_name))


def restart_container(duthost, container_name):
    """Restarts the specified container on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: A string represents name of the container.

    Returns:
        None.
    """
    logger.info("Resetting '{}' status ...".format(container_name))
    logger.info("systemctl reset-failed {}.service".format(container_name))
    logger.info("Restarting '{}' container ...".format(container_name))
    duthost.shell("systemctl restart {}.service".format(container_name))

    logger.info("Waiting for '{}' container to be restarted ...".format(container_name))
    restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                           CONTAINER_CHECK_INTERVAL_SECS,
                           0,
                           check_container_state, duthost, container_name, True)
    pytest_assert(restarted, "Failed to restart '{}' container!".format(container_name))
    logger.info("'{}' container is restarted.".format(container_name))


def backup_monit_config_files(duthost):
    """Backs up Monit configuration files on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        None.
    """
    logger.info("Backing up Monit configuration files on DuT '{}' ...".format(duthost.hostname))
    duthost.shell("cp -rf /etc/monit /tmp/")
    logger.info("Monit configuration files on DuT '{}' is backed up.".format(duthost.hostname))


def customize_monit_config_files(duthost, container, daemon_cycle_interval, start_delay, fail_cycles):
    """Customizes the Monit configuration file on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.
        daemon_cycle_interval: Interval between two cycles of monit check
        start_delay: Delay used by monit before running checks

    Returns:
        None.
    """
    logger.info("Modifying Monit config to change interval and start delay ...")
    duthost.shell(r"sed -Ei 's/(set daemon) [0-9]+/\1 {}/' /etc/monit/monitrc".format(daemon_cycle_interval))
    duthost.shell(r"sed -Ei 's/(with start delay) [0-9]+/\1 {}/' /etc/monit/monitrc".format(start_delay))
    logger.info("Modifying Monit config to change interval and start delay done.")
    if fail_cycles is not None:
        config_path = '/etc/monit/conf.d/monit_{}'.format(container.name)
        logger.info("Modifying monit container specific config %s", config_path)
        duthost.shell(r"sed -Ei 's/for [0-9]+ times/for {} times/' {}".format(fail_cycles, config_path))
        logger.info("Modifying monit container specific config done.")


def restore_monit_config_files(duthost):
    """Restores the initial Monit configuration file on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        None.
    """
    logger.info("Restoring original Monit configuration files on DuT '{}' ...".format(duthost.hostname))
    duthost.shell("rm -rf /etc/monit")
    duthost.shell("mv /tmp/monit /etc/monit")
    logger.info("Original Monit configuration files on DuT '{}' are restored.".format(duthost.hostname))


def check_monit_running(duthost):
    """Checks whether Monit is running or not.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        Returns True if Monit is running; Otherwist, returns False.
    """
    monit_services_status = duthost.get_monit_services_status()
    if not monit_services_status:
        return False

    return True


def parse_monit_output(lines):
    data = {}
    service = None
    for line in lines:
        if line.startswith("Program '"):
            prog = line[len("Program '"):].rstrip("'")
            service = {}
            data[prog] = service
            continue
        if service is None:
            continue
        if line.startswith('  '):
            key, value = line.lstrip().split('  ', 1)
            service[key.replace(' ', '_')] = value.lstrip()
    return data


def get_monit_service_status(duthost, service):
    """Returns the current status of a given monit service.

    Args:
        duthost: The AnsibleHost object of DuT.
        service: Name of the monit service

    Returns:
        Status string for the monit service
    """
    result = duthost.shell("sudo monit status -B", module_ignore_errors=True, verbose=False)
    if result["rc"] != 0:
        return {}

    services = parse_monit_output(result["stdout_lines"])
    return services[service]


def restart_monit_service(duthost):
    """Restarts Monit service and polls Monit running status.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        None.
    """
    logger.info("Restarting Monit service ...")
    duthost.shell("systemctl restart monit")
    logger.info("Monit service is restarted.")

    logger.info("Checks whether Monit is running or not after restarted ...")
    is_monit_running = wait_until(MONIT_RESTART_THRESHOLD_SECS,
                                  MONIT_CHECK_INTERVAL_SECS,
                                  0,
                                  check_monit_running,
                                  duthost)
    pytest_assert(is_monit_running, "Monit is not running after restarted!")
    logger.info("Monit is running!")


@pytest.fixture
def test_setup_and_cleanup(memory_checker_dut_and_container, request):
    """Backups Monit configuration files, customizes Monit configuration files and
    restarts Monit service before testing. Restores original Monit configuration files
    and restart Monit service after testing.

    Args:
        duthost: Hostname of DuT.

    Returns:
        None.
    """
    duthost, container = memory_checker_dut_and_container

    if not container.is_running():
        container.restart()
    container.post_check()

    backup_monit_config_files(duthost)
    customize_monit_config_files(duthost, container, *request.param)
    restart_monit_service(duthost)

    yield

    restore_monit_config_files(duthost)
    restart_monit_service(duthost)

    if not container.is_running():
        container.restart()
    container.post_check()


@pytest.fixture
def remove_and_restart_container(memory_checker_dut_and_container):
    """Removes and restarts 'telemetry' container from DuT.

    Args:
        memory_checker_dut_and_container: Fixture providing the duthost and container to test

    Returns:
        None.
    """
    duthost, container = memory_checker_dut_and_container
    container.remove()

    yield

    if not container.is_running():
        container.restart()
    container.post_check()


def get_test_container(duthost):
    test_container = "telemetry"
    cmd = "docker images | grep -w sonic-gnmi"
    if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
        test_container = "gnmi"
    return test_container


@pytest.fixture
def memory_checker_dut_and_container(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Perform some checks and return applicable duthost and container name

    Args:
        duthosts: The fixture returns list of DuTs.
        enum_rand_one_per_hwsku_frontend_hostname: The fixture randomly pick up
          a frontend DuT from testbed.

    Returns:
        (duthost, container)
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    container_name = get_test_container(duthost)
    container = MemoryCheckerContainer(container_name, duthost)

    pytest_require("Celestica-E1031" not in duthost.facts["hwsku"]
                   and (("20191130" in duthost.os_version and
                         parse_version(duthost.os_version) > parse_version("20191130.72"))
                   or parse_version(duthost.kernel_version) > parse_version("4.9.0")),
                   "Test is not supported for platform Celestica E1031, 20191130.72 and older image versions!")

    return duthost, container


def start_consume_memory(duthost, container):
    """Consumes memory more than the threshold value of specified container.

    Args:
        duthost: The AnsibleHost object of DuT.
        container: Container object to test

    Returns:
        None.
    """
    mem_size = container.mem_size_to_allocate()
    cmd = """python3 -c 'import ctypes, time; arr = (ctypes.c_uint8 * {})(); time.sleep(1000)'""".format(mem_size)
    logger.info("Executing python command to consume %s in %s container", mem_size, container.name)
    docker_cmd = 'docker exec {} {} &'.format(container.name, cmd)
    duthost.shell(docker_cmd, module_ignore_errors=True)


def stop_consume_memory(duthost, container):
    """Stop the excessive memory allocation if running

    Args:
        duthost: The AnsibleHost object of DuT.
        container: Container object to test

    Returns:
        None.
    """
    logger.info("Stopping python command that consumes memory in %s container", container.name)
    docker_cmd = 'docker exec {} pkill -f time.sleep'.format(container.name)
    duthost.shell(docker_cmd, module_ignore_errors=True)


def check_critical_processes(duthost, container_name):
    """Checks whether the critical processes are running after container was restarted.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.

    Returns:
        None.
    """
    status_result = duthost.critical_process_status(container_name)
    if status_result["status"] is False or len(status_result["exited_critical_process"]) > 0:
        return False

    return True


def postcheck_critical_processes(duthost, container_name):
    """Checks whether the critical processes are running after container was restarted.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.

    Returns:
        None.
    """
    logger.info("Checking the running status of critical processes in '{}' container ..."
                .format(container_name))
    is_succeeded = wait_until(CONTAINER_RESTART_THRESHOLD_SECS, CONTAINER_CHECK_INTERVAL_SECS, 0,
                              check_critical_processes, duthost, container_name)
    if not is_succeeded:
        pytest.fail("Not all critical processes in '{}' container are running!"
                    .format(container_name))
    logger.info("All critical processes in '{}' container are running.".format(container_name))


def get_container_mem_usage(duthost, container_name):
    """Gets the memory usage of a container.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: A string represents the name of container.

    Returns:
        mem_usage: A string represents memory usage.
    """
    get_mem_usage_cmd = r"docker stats --no-stream --format \{{\{{.MemUsage\}}\}} {}".format(container_name)
    cmd_result = duthost.shell(get_mem_usage_cmd)

    exit_code = cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to get memory usage of '{}'!".format(container_name))

    mem_info = cmd_result["stdout_lines"]
    mem_usage = mem_info[0].split()[0]

    return mem_usage


def mem_size_str_to_int(size_str):
    size, unit = re.match(r'([0-9\.]+)(.*)', size_str).groups()
    factor = {
        'B': 1,
        'KB': 1000,
        'KiB': 1024,
        'MB': 1000 ** 2,
        'MiB': 1024 ** 2,
        'GB': 1000 ** 3,
        'GiB': 1024 ** 3,
    }[unit]
    return int(float(size) * factor)


class MemoryCheckerContainer(object):

    EXTRA_MEMORY_TO_ALLOCATE = 20 * 1024 * 1024
    # NOTE: these limits could be computed by reading the monit_$container config
    MEMORY_LIMITS = {
        'telemetry': 400 * 1024 * 1024,
        'gnmi': 400 * 1024 * 1024,
    }

    def __init__(self, name, duthost):
        self.name = name
        self.duthost = duthost
        self._last_start_date = None

    @property
    def memory_limit(self):
        return self.MEMORY_LIMITS[self.name]

    def current_memory_used(self):
        value = get_container_mem_usage(self.duthost, self.name)
        return mem_size_str_to_int(value)

    def mem_size_to_allocate(self):
        return self.memory_limit - self.current_memory_used() + self.EXTRA_MEMORY_TO_ALLOCATE

    @property
    def memory_service_name(self):
        return 'container_memory_{}'.format(self.name)

    def is_running(self):
        return is_container_running(self.duthost, self.name)

    def get_monit_mem_status(self):
        return get_monit_service_status(self.duthost, self.memory_service_name)

    def is_monit_mem_ok(self):
        status = self.get_monit_mem_status()
        return status['status'] == 'Status ok'

    def is_monit_mem_failed(self):
        status = self.get_monit_mem_status()
        logger.info("Monit status for %s: %s", self.name, status['status'])
        return status['status'] == 'Status failed'

    def is_monit_mem_last_ok(self):
        status = self.get_monit_mem_status()
        return status['status'] == 'Status ok' and status['last_exit_value'] == '0'

    def is_monit_mem_last_failed(self):
        status = self.get_monit_mem_status()
        return status['status'] == 'Status ok' and status['last_exit_value'] != '0'

    def remove(self):
        remove_container(self.duthost, self.name)

    def restart(self):
        restart_container(self.duthost, self.name)

    def post_check(self):
        postcheck_critical_processes(self.duthost, self.name)

    def start_consume_memory(self):
        start_consume_memory(self.duthost, self)

    def stop_consume_memory(self):
        stop_consume_memory(self.duthost, self)

    def get_restart_expected_logre(self):
        cap_name = self.name.capitalize()
        if self.name == "gnmi":
            cap_name = "GNMI"
        return [
            r".*restart_service.*Restarting service '{}'.*".format(self.name),
            r".*Stopping {} container.*".format(cap_name),
            r".*Stopped {} container.*".format(cap_name),
            r".*Starting {} container.*".format(cap_name),
            r".*Started {} container.*".format(cap_name),
        ]

    def get_last_start_date(self):
        rc = self.duthost.shell(r"docker inspect --format \{{\{{.State.StartedAt\}}\}} {}".format(self.name))
        date_str = rc['stdout_lines'][0].strip()
        return dateutil.parser.isoparse(date_str)

    def has_container_restarted(self):
        start_date = self.get_last_start_date()
        return start_date > self._last_start_date

    def wait_restarted(self, start_date=None):
        self._last_start_date = start_date or self.get_last_start_date()
        restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS, 1, 0,
                               self.has_container_restarted)
        pytest_assert(restarted, "Failed to restart '{}' container!".format(self.name))
        self._last_start_date = None

    def wait_monit_mem_ok(self, timeout=MONIT_MEMORY_CHECK_TIMEOUT):
        logger.info("Waiting for monit status ok for %s", self.name)
        res = wait_until(timeout, 1, 0, self.is_monit_mem_ok)
        pytest_assert(res, "Failed to wait for one monit cycle to be ok for {}".format(self.name))

    def wait_monit_mem_failed(self, timeout=MONIT_MEMORY_CHECK_TIMEOUT):
        logger.info("Waiting for monit status failed for %s", self.name)
        res = wait_until(timeout, 1, 0, self.is_monit_mem_failed)
        pytest_assert(res, "Failed to wait for one monit cycle to fail for {}".format(self.name))

    def wait_monit_mem_last_ok(self, timeout=MONIT_MEMORY_CHECK_TIMEOUT):
        logger.info("Waiting for last monit status ok for %s", self.name)
        res = wait_until(timeout, 1, 0, self.is_monit_mem_last_ok)
        pytest_assert(res, "Failed to wait for one monit cycle to be ok for {}".format(self.name))

    def wait_monit_mem_last_failed(self, timeout=MONIT_MEMORY_CHECK_TIMEOUT):
        logger.info("Waiting for last monit status failed for %s", self.name)
        res = wait_until(timeout, 1, 0, self.is_monit_mem_last_failed)
        pytest_assert(res, "Failed to wait for one monit cycle to fail for {}".format(self.name))

    def wait_ready(self):
        if not self.is_running():
            pytest.fail("'{}' is not running!".format(self.name))
        self.post_check()
        self.wait_monit_mem_ok()


def consumes_memory_and_checks_container_restart(duthost, container):
    """Allocates memory in the container and checks whether the container can be
    stopped and restarted. Loganalyzer is leveraged to check whether the log messages
    related to container stopped were generated.

    Args:
        duthost: The AnsibleHost object of DuT.
        container: Container object to test

    Returns:
        None.
    """
    marker_prefix = "container_restart_due_to_memory"
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=marker_prefix)
    loganalyzer.expect_regex = container.get_restart_expected_logre()
    with loganalyzer:
        timeout_monit_fail = 180  # fails happens after 10 cycles of 1 second
        container.start_consume_memory()
        container.wait_monit_mem_failed(timeout_monit_fail)
        logger.info("Container %s should now be restarting", container.name)
        container.wait_monit_mem_ok(CONTAINER_RESTART_THRESHOLD_SECS)
        # Wait until the service has started, then the loganalyzer will capture all the expected messages
        wait_until(CONTAINER_RESTART_THRESHOLD_SECS, CONTAINER_CHECK_INTERVAL_SECS, 0,
                   duthost.is_host_service_running, container.name)

    logger.info("Container %s restarted.", container.name)


def consumes_memory_and_checks_monit(duthost, container):
    """Invokes a command consuming memory in the background and checks whether the container can
    be stopped and restarted.
    After container was restarted, the command will be invoked again to consume memory and checks
    whether Monit was able to restart this container.
    Loganalyzer is leveraged to check whether the log messages related to container stopped
    and started were generated.

    Args:
        duthost: The AnsibleHost object of DuT.
        container: Container object being tested

    Returns:
        None.
    """

    marker_prefix = "test_memory_checker"
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=marker_prefix)
    loganalyzer.expect_regex = container.get_restart_expected_logre()
    marker = loganalyzer.init()

    start_date = container.get_last_start_date()

    container.start_consume_memory()
    container.wait_monit_mem_last_failed(200)

    logger.info("Waiting for container to restart")
    container.wait_restarted(start_date)

    # Monit container memory check should still be failed at this point
    container.wait_monit_mem_failed(10)

    # Start consuming memory early and then check the logs so we hit the memory
    # limit before monit first cycle
    container.start_consume_memory()

    logger.info("Checking the alerting messages related to container restart ...")
    loganalyzer.analyze(marker)
    logger.info("Found all the expected alerting messages from syslog!")

    marker = loganalyzer.update_marker_prefix("test_monit_counter")

    logger.info("Waiting for container %s to restart after monit initial delay", container.name)
    container.wait_restarted()
    container.wait_ready()

    logger.info("Analyzing syslog messages to verify whether '%s' is restarted ...", container.name)
    loganalyzer.analyze(marker)

    logger.info("Monit was able to restart '%s'", container.name)


@pytest.mark.parametrize("test_setup_and_cleanup", [(1, 0, None)], indirect=True, ids=[''])
def test_memory_checker(memory_checker_dut_and_container, test_setup_and_cleanup):
    """Checks whether the container can be restarted or not if the memory
    usage of it is beyond its threshold for specfic times within a sliding window.
    A command is used to generate memory allocations beyond the limits.

    Args:
        memory_checker_dut_and_container: Fixture providing a duthost and container to test
        test_setup_and_cleanup: Fixture setting up the test environment

    Returns:
        None.
    """
    duthost, container = memory_checker_dut_and_container
    container.wait_ready()
    consumes_memory_and_checks_container_restart(duthost, container)


@pytest.mark.parametrize("test_setup_and_cleanup", [(5, 0, None)], indirect=True, ids=[''])
def test_memory_checker_recover(memory_checker_dut_and_container, test_setup_and_cleanup):
    """Checks whether the container can be restarted or not if the memory
    usage of it is beyond its threshold for specfic times within a sliding window.
    A command is used to generate memory allocations beyond the limits.

    Args:
        memory_checker_dut_and_container: Fixture providing a duthost and container to test
        test_setup_and_cleanup: Fixture setting up the test environment

    Returns:
        None.
    """
    duthost, container = memory_checker_dut_and_container

    container.wait_ready()

    marker_prefix = "container_memory_checker_recover"
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=marker_prefix)
    loganalyzer.expect_regex = container.get_restart_expected_logre()
    marker = loganalyzer.init()

    timeout_status_change = 30  # monit has a 5s cycle interval per test parameters

    container.start_consume_memory()
    container.wait_monit_mem_last_failed(timeout_status_change)

    container.stop_consume_memory()
    container.wait_monit_mem_last_ok(timeout_status_change)

    analysis = loganalyzer.analyze(marker, fail=False)
    pytest_assert(not analysis['total']['expected_match'],
                  "Container {} restarted during the test which was not expected".format(container.name))


@pytest.mark.parametrize("test_setup_and_cleanup", [(60, 0, 2)], indirect=True, ids=[''])
def test_monit_reset_counter_failure(memory_checker_dut_and_container, test_setup_and_cleanup):
    """Checks that Monit was unable to reset its counter. Specifically Monit will restart
    the container if memory usage of it is larger than the threshold for specific times within
    a sliding window. However, Monit was unable to restart the container anymore if memory usage is
    still larger than the threshold continuoulsy since Monit failed to reset its internal counter.
    A command is used to generate memory allocations beyond the limits.

    Args:
        memory_checker_dut_and_container: Fixture providing a duthost and container to test
        test_setup_and_cleanup: Fixture setting up the test environment

    Returns:
        None.
    """
    duthost, container = memory_checker_dut_and_container
    container.wait_ready()
    consumes_memory_and_checks_monit(duthost, container)


def check_log_message(duthost, container, wait_time):
    """Leverages LogAanlyzer to check whether `memory_checker` can log the specific message
    into syslog or not.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: A string represents the name of container.

    Returns:
        None.
    """
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="memory_checker_skip_removed_container")
    loganalyzer.expect_regex = [
        r".*\[memory_checker\] Exits without checking memory usage.*'{}'.*".format(container.name),
    ]
    with loganalyzer:
        logger.info("Sleep '{}' seconds to wait for the message from syslog ...".format(wait_time))
        time.sleep(wait_time)


@pytest.mark.parametrize("test_setup_and_cleanup", [(1, 0, None)], indirect=True, ids=[''])
def test_memory_checker_without_container_created(memory_checker_dut_and_container,
                                                  test_setup_and_cleanup,
                                                  remove_and_restart_container):
    """Checks whether 'memory_checker' script can log an message into syslog if
    one container is not created during device is booted/reooted. This test case will
    remove a container explicitly to simulate the scenario in which the container was not created
    successfully.

    Args:
        memory_checker_dut_and_container: Fixture providing a duthost and container to test
        test_setup_and_cleanup: Fixture setting up the test environment
        remove_and_restart_container: Fixture removing the container before the test
                                      and restarting it after

    Returns:
        None.
    """
    duthost, container = memory_checker_dut_and_container
    wait_time_monit_complaints = 20
    check_log_message(duthost, container, wait_time_monit_complaints)
