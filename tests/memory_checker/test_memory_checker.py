"""
The 'stress' utility is leveraged to increase the memory usage of a container continuously, then
1) Test whether that container can be restarted by the script ran by Monit.
2) Test whether that container can be restarted by the script ran by Monit; If that container
   was restarted, then test the script ran by Monit was unable to restart the container anymore
   due to Monit failed to reset its internal counter.
3) Test whether that container can be restarted by the script ran by Monit; If that container
   was restarted, then test the script ran by Monit was able to restart the container with the
   help of new Monit syntax although Monit failed to reset its internal counter.
"""
import logging
from multiprocessing.pool import ThreadPool

import pytest

from pkg_resources import parse_version
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.dut_utils import check_container_state
from tests.common.helpers.dut_utils import decode_dut_and_container_name
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
WAITING_SYSLOG_MSG_SECS = 130


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
    duthost.shell("cp -f /etc/monit/monitrc /tmp/")
    duthost.shell("mv -f /etc/monit/conf.d/monit_* /tmp/")
    duthost.shell("cp -f /tmp/monit_telemetry /etc/monit/conf.d/")
    logger.info("Monit configuration files on DuT '{}' is backed up.".format(duthost.hostname))


def customize_monit_config_files(duthost, temp_config_line):
    """Customizes the Monit configuration file on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.
        temp_config_line: A stirng to replace the initial Monit configuration.

    Returns:
        None.
    """
    logger.info("Modifying Monit config to eliminate start delay and decrease interval ...")
    duthost.shell("sed -i '$s/^./#/' /etc/monit/conf.d/monit_telemetry")
    duthost.shell("echo '{}' | tee -a /etc/monit/conf.d/monit_telemetry".format(temp_config_line))
    duthost.shell("sed -i '/with start delay 300/s/^./#/' /etc/monit/monitrc")
    logger.info("Modifying Monit config to eliminate start delay and decrease interval are done.")


def restore_monit_config_files(duthost):
    """Restores the initial Monit configuration file on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        None.
    """
    logger.info("Restoring original Monit configuration files on DuT '{}' ...".format(duthost.hostname))
    duthost.shell("mv -f /tmp/monitrc /etc/monit/")
    duthost.shell("mv -f /tmp/monit_* /etc/monit/conf.d/")
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


def install_stress_utility(duthost, creds, container_name):
    """Installs 'stress' utility in the container on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: A string represents name of the container.

    Returns:
        None.
    """
    logger.info("Installing 'stress' utility in '{}' container ...".format(container_name))

    # Get proxy settings from creds
    http_proxy = creds.get('proxy_env', {}).get('http_proxy', '')
    https_proxy = creds.get('proxy_env', {}).get('https_proxy', '')

    # Shutdown bgp for having ability to install stress tool
    logger.info("Shutting down all BGP sessions ...")
    duthost.shell("config bgp shutdown all")
    logger.info("All BGP sessions are shut down!...")
    install_cmd_result = duthost.shell("docker exec {} bash -c 'export http_proxy={} \
                                        && export https_proxy={} \
                                        && apt-get install stress -y'".format(container_name, http_proxy, https_proxy))

    exit_code = install_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to install 'stress' utility!")
    logger.info("'stress' utility was installed.")


def remove_stress_utility(duthost, container_name):
    """Removes the 'stress' utility from container and brings up BGP sessions
    on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: A string represents the name of container.

    Returns:
        None.
    """
    logger.info("Removing 'stress' utility from '{}' container ...".format(container_name))
    remove_cmd_result = duthost.shell("docker exec {} apt-get purge stress -y".format(container_name))
    exit_code = remove_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to remove 'stress' utility!")
    logger.info("'stress' utility was removed.")

    logger.info("Bringing up all BGP sessions ...")
    duthost.shell("config bgp startup all")
    logger.info("BGP sessions are started up.")


@pytest.fixture
def test_setup_and_cleanup(duthosts, creds, enum_dut_feature_container,
                           enum_rand_one_per_hwsku_frontend_hostname, request):
    """Backups Monit configuration files, customizes Monit configuration files and
    restarts Monit service before testing. Restores original Monit configuration files
    and restart Monit service after testing.

    Args:
        duthost: Hostname of DuT.

    Returns:
        None.
    """
    dut_name, container_name = decode_dut_and_container_name(enum_dut_feature_container)
    pytest_require(dut_name == enum_rand_one_per_hwsku_frontend_hostname,
                   "Skips testing memory_checker of container '{}' on the DuT '{}' since another DuT '{}' was chosen."
                   .format(container_name, dut_name, enum_rand_one_per_hwsku_frontend_hostname))

    pytest_require(container_name == "telemetry",
                   "Skips testing memory_checker of container '{}' since memory monitoring is only enabled for 'telemetry'."
                   .format(container_name))

    duthost = duthosts[dut_name]

    install_stress_utility(duthost, creds, container_name)

    backup_monit_config_files(duthost)
    customize_monit_config_files(duthost, request.param)
    restart_monit_service(duthost)

    yield

    restore_monit_config_files(duthost)
    restart_monit_service(duthost)

    restart_container(duthost, container_name)
    remove_stress_utility(duthost, container_name)
    postcheck_critical_processes(duthost, container_name)


@pytest.fixture
def remove_and_restart_container(duthosts, creds, enum_dut_feature_container,
                                 enum_rand_one_per_hwsku_frontend_hostname):
    """Removes and restarts 'telemetry' container from DuT.

    Args:
        duthosts: The fixture returns list of DuTs.
        enum_rand_one_per_hwsku_frontend_hostname: The fixture randomly pick up
        a frontend DuT from testbed.


    Returns:
        None.
    """
    dut_name, container_name = decode_dut_and_container_name(enum_dut_feature_container)
    pytest_require(dut_name == enum_rand_one_per_hwsku_frontend_hostname,
                   "Skips testing memory_checker of container '{}' on the DuT '{}' since another DuT '{}' was chosen."
                   .format(container_name, dut_name, enum_rand_one_per_hwsku_frontend_hostname))

    pytest_require(container_name == "telemetry",
                   "Skips testing memory_checker of container '{}' since memory monitoring is only enabled for 'telemetry'."
                   .format(container_name))

    duthost = duthosts[dut_name]
    remove_container(duthost, container_name)

    yield

    restart_container(duthost, container_name)
    postcheck_critical_processes(duthost, container_name)


def consume_memory(duthost, container_name, vm_workers):
    """Consumes memory more than the threshold value of specified container.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.
        vm_workers: Number of workers which does the spinning on malloc()/free()
          to consume memory.

    Returns:
        None.
    """
    logger.info("Executing command 'stress -m {}' in '{}' container ...".format(vm_workers, container_name))
    duthost.shell("docker exec {} stress -m {}".format(container_name, vm_workers), module_ignore_errors=True)


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


def consumes_memory_and_checks_container_restart(duthost, container_name, vm_workers):
    """Invokes the 'stress' utility to consume memory more than the threshold asynchronously
    and checks whether the container can be stopped and restarted. Loganalyzer is leveraged
    to check whether the log messages related to container stopped were generated.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: A string represents the name of container.
        vm_workers: Number of workers which does the spinning on malloc()/free()
          to consume memory.

    Returns:
        None.
    """
    expected_alerting_messages = []
    expected_alerting_messages.append(".*restart_service.*Restarting service 'telemetry'.*")
    expected_alerting_messages.append(".*Stopping Telemetry container.*")
    expected_alerting_messages.append(".*Stopped Telemetry container.*")
    expected_alerting_messages.append(".*Starting Telemetry container.*")
    expected_alerting_messages.append(".*Started Telemetry container.*")

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="container_restart_due_to_memory")
    loganalyzer.expect_regex = []
    loganalyzer.expect_regex.extend(expected_alerting_messages)
    marker = loganalyzer.init()

    thread_pool = ThreadPool()
    thread_pool.apply_async(consume_memory, (duthost, container_name, vm_workers))

    logger.info("Sleep '{}' seconds to wait for the alerting messages from syslog ...".format(WAITING_SYSLOG_MSG_SECS))
    time.sleep(WAITING_SYSLOG_MSG_SECS)

    logger.info("Checking the alerting messages related to container stopped ...")
    loganalyzer.analyze(marker)
    logger.info("Found all the expected alerting messages from syslog!")

    logger.info("Waiting for '{}' container to be restarted ...".format(container_name))
    restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                           CONTAINER_CHECK_INTERVAL_SECS,
                           0,
                           check_container_state, duthost, container_name, True)
    pytest_assert(restarted, "Failed to restart '{}' container!".format(container_name))
    logger.info("'{}' container is restarted.".format(container_name))


def get_container_mem_usage(duthost, container_name):
    """Gets the memory usage of a container.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: A string represents the name of container.

    Returns:
        mem_usage: A string represents memory usage.
    """
    get_mem_usage_cmd = "docker stats --no-stream --format \{{\{{.MemUsage\}}\}} {}".format(container_name)
    cmd_result = duthost.shell(get_mem_usage_cmd)

    exit_code = cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to get memory usage of '{}'!".format(container_name))

    mem_info = cmd_result["stdout_lines"]
    mem_usage = mem_info[0].split()[0]

    return mem_usage


def consumes_memory_and_checks_monit(duthost, container_name, vm_workers, new_syntax_enabled):
    """Invokes the 'stress' utility to consume memory more than the threshold asynchronously
    and checks whether the container can be stopped and restarted. After container was restarted,
    'stress' utility will be invoked again to consume memory and checks whether Monit was able to
    restart this container with or without help of new syntax.
    Loganalyzer is leveraged to check whether the log messages related to container stopped
    and started were generated.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.
        vm_workers: Number of workers which does the spinning on malloc()/free()
          to consume memory.
        new_syntax_enabled: Checks to make sure container will be restarted if it is set to be
          `True`.

    Returns:
        None.
    """
    expected_alerting_messages = []
    expected_alerting_messages.append(".*restart_service.*Restarting service 'telemetry'.*")
    expected_alerting_messages.append(".*Stopping Telemetry container.*")
    expected_alerting_messages.append(".*Stopped Telemetry container.*")
    expected_alerting_messages.append(".*Starting Telemetry container.*")
    expected_alerting_messages.append(".*Started Telemetry container.*")

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="test_memory_checker")
    loganalyzer.expect_regex = []
    loganalyzer.expect_regex.extend(expected_alerting_messages)
    marker = loganalyzer.init()

    thread_pool = ThreadPool()
    thread_pool.apply_async(consume_memory, (duthost, container_name, vm_workers))

    logger.info("Sleep '{}' seconds to wait for the alerting messages from syslog ...".format(WAITING_SYSLOG_MSG_SECS))
    time.sleep(WAITING_SYSLOG_MSG_SECS)

    logger.info("Checking the alerting messages related to container restart ...")
    loganalyzer.analyze(marker)
    logger.info("Found all the expected alerting messages from syslog!")

    logger.info("Waiting for '{}' container to be restarted ...".format(container_name))
    restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                           CONTAINER_CHECK_INTERVAL_SECS,
                           0,
                           check_container_state, duthost, container_name, True)
    pytest_assert(restarted, "Failed to restart '{}' container!".format(container_name))
    logger.info("'{}' container is restarted.".format(container_name))

    logger.info("Running 'stress' utility again in '{}' ...".format(container_name))
    thread_pool.apply_async(consume_memory, (duthost, container_name, vm_workers))

    check_counter = 0
    marker = loganalyzer.update_marker_prefix("test_monit_counter")
    logger.info("Checking memory usage of '{}' every 30 seconds for 6 times ...".format(container_name))
    while check_counter < 6:
        check_counter += 1
        mem_usage = get_container_mem_usage(duthost, container_name)
        logger.info("Memory usage of '{}' is '{}'".format(container_name, mem_usage))
        time.sleep(30)

    logger.info("Analyzing syslog messages to verify whether '{}' is restarted ...".format(container_name))
    analyzing_result = loganalyzer.analyze(marker, fail=False)
    if not new_syntax_enabled:
        pytest_assert(analyzing_result["total"]["expected_match"] == 0,
                      "Monit can reset counter and restart '{}'!".format(container_name))
        logger.info("Monit was unable to reset its counter and '{}' can not be restarted!".format(container_name))
    else:
        pytest_assert(analyzing_result["total"]["expected_match"] == len(expected_alerting_messages),
                      "Monit still can not restart '{}' with the help of new syntax!".format(container_name))
        logger.info("Monit was able to restart '{}' with the help of new syntax!".format(container_name))


@pytest.mark.parametrize("test_setup_and_cleanup",
                         ['    if status == 3 for 1 times within 2 cycles then exec "/usr/bin/restart_service telemetry"'],
                         indirect=["test_setup_and_cleanup"])
def test_memory_checker(duthosts, enum_dut_feature_container, test_setup_and_cleanup,
                        enum_rand_one_per_hwsku_frontend_hostname):
    """Checks whether the container can be restarted or not if the memory
    usage of it is beyond its threshold for specfic times within a sliding window.
    The `stress` utility is leveraged as the memory stressing tool.

    Args:
        duthosts: The fixture returns list of DuTs.
        enum_rand_one_per_hwsku_frontend_hostname: The fixture randomly pick up
          a frontend DuT from testbed.

    Returns:
        None.
    """
    dut_name, container_name = decode_dut_and_container_name(enum_dut_feature_container)
    pytest_require(dut_name == enum_rand_one_per_hwsku_frontend_hostname,
                   "Skips testing memory_checker of container '{}' on the DuT '{}' since another DuT '{}' was chosen."
                   .format(container_name, dut_name, enum_rand_one_per_hwsku_frontend_hostname))

    pytest_require(container_name == "telemetry",
                   "Skips testing memory_checker of container '{}' since memory monitoring is only enabled for 'telemetry'."
                   .format(container_name))

    duthost = duthosts[dut_name]

    # TODO: Currently we only test 'telemetry' container which has the memory threshold 400MB
    # and number of vm_workers is hard coded. We will extend this testing on all containers after
    # the feature 'memory_checker' is fully implemented.
    container_name = "telemetry"
    vm_workers = 6

    pytest_require("Celestica-E1031" not in duthost.facts["hwsku"]
                   and (("20191130" in duthost.os_version and parse_version(duthost.os_version) > parse_version("20191130.72"))
                   or parse_version(duthost.kernel_version) > parse_version("4.9.0")),
                   "Test is not supported for platform Celestica E1031, 20191130.72 and older image versions!")

    if not is_container_running(duthost, container_name):
        pytest.fail("'{}' is nor running!".format(container_name))

    consumes_memory_and_checks_container_restart(duthost, container_name, vm_workers)


@pytest.mark.parametrize("test_setup_and_cleanup",
                         ['    if status == 3 for 1 times within 2 cycles then exec "/usr/bin/restart_service telemetry"'],
                         indirect=["test_setup_and_cleanup"])
def test_monit_reset_counter_failure(duthosts, enum_dut_feature_container, test_setup_and_cleanup,
                                     enum_rand_one_per_hwsku_frontend_hostname):
    """Checks that Monit was unable to reset its counter. Specifically Monit will restart
    the contanier if memory usage of it is larger than the threshold for specific times within
    a sliding window. However, Monit was unable to restart the container anymore if memory usage is
    still larger than the threshold continuoulsy since Monit failed to reset its internal counter.
    The `stress` utility is leveraged as the memory stressing tool.

    Args:
        duthosts: The fixture returns list of DuTs.
        test_setup_and_cleanup: Fixture to setup prerequisites before and after testing.
        enum_rand_one_per_hwsku_frontend_hostname: The fixture randomly pick up
          a frontend DuT from testbed.

    Returns:
        None.
    """
    dut_name, container_name = decode_dut_and_container_name(enum_dut_feature_container)
    pytest_require(dut_name == enum_rand_one_per_hwsku_frontend_hostname,
                   "Skips testing memory_checker of container '{}' on the DuT '{}' since another DuT '{}' was chosen."
                   .format(container_name, dut_name, enum_rand_one_per_hwsku_frontend_hostname))

    pytest_require(container_name == "telemetry",
                   "Skips testing memory_checker of container '{}' since memory monitoring is only enabled for 'telemetry'."
                   .format(container_name))

    duthost = duthosts[dut_name]

    # TODO: Currently we only test 'telemetry' container which has the memory threshold 400MB
    # and number of vm_workers is hard coded. We will extend this testing on all containers after
    # the feature 'memory_checker' is fully implemented.
    container_name = "telemetry"
    vm_workers = 6

    pytest_require("Celestica-E1031" not in duthost.facts["hwsku"]
                   and ("20201231" in duthost.os_version or parse_version(duthost.kernel_version) > parse_version("4.9.0")),
                   "Test is not supported for platform Celestica E1031, 20191130 and older image versions!")

    logger.info("Checks whether '{}' is running ...".format(container_name))
    is_running = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                            CONTAINER_CHECK_INTERVAL_SECS,
                            0,
                            check_container_state, duthost, container_name, True)
    pytest_assert(is_running, "'{}' is not running on DuT!".format(container_name))
    logger.info("'{}' is running on DuT!".format(container_name))

    consumes_memory_and_checks_monit(duthost, container_name, vm_workers, False)


@pytest.mark.parametrize("test_setup_and_cleanup",
                         ['    if status == 3 for 1 times within 2 cycles then exec "/usr/bin/restart_service telemetry" repeat every 2 cycles'],
                         indirect=["test_setup_and_cleanup"])
def test_monit_new_syntax(duthosts, enum_dut_feature_container, test_setup_and_cleanup,
                          enum_rand_one_per_hwsku_frontend_hostname):
    """Checks that new syntax of Monit can mitigate the issue which shows Monit was unable
    to restart container due to failing reset its internal counter. With the help of this syntax,
    the culprit container can be restarted by Monit if memory usage of it is larger than the threshold
    for specific times continuously.

    Args:
        duthosts: The fixture returns list of DuTs.
        test_setup_and_cleanup: Fixture to setup prerequisites before and after testing.
        enum_rand_one_per_hwsku_frontend_hostname: The fixture randomly pick up
          a frontend DuT from testbed.

    Returns:
        None.
    """
    dut_name, container_name = decode_dut_and_container_name(enum_dut_feature_container)
    pytest_require(dut_name == enum_rand_one_per_hwsku_frontend_hostname,
                   "Skips testing memory_checker of container '{}' on the DuT '{}' since another DuT '{}' was chosen."
                   .format(container_name, dut_name, enum_rand_one_per_hwsku_frontend_hostname))

    pytest_require(container_name == "telemetry",
                   "Skips testing memory_checker of container '{}' since memory monitoring is only enabled for 'telemetry'."
                   .format(container_name))

    duthost = duthosts[dut_name]

    # TODO: Currently we only test 'telemetry' container which has the memory threshold 400MB
    # and number of vm_workers is hard coded. We will extend this testing on all containers after
    # the feature 'memory_checker' is fully implemented.
    container_name = "telemetry"
    vm_workers = 6

    pytest_require("Celestica-E1031" not in duthost.facts["hwsku"]
                   and (("20191130" in duthost.os_version and parse_version(duthost.os_version) > parse_version("20191130.72"))
                   or parse_version(duthost.kernel_version) > parse_version("4.9.0")),
                   "Test is not supported for platform Celestica E1031, 20191130.72 and older image versions!")

    logger.info("Checks whether '{}' is running ...".format(container_name))
    is_running = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                            CONTAINER_CHECK_INTERVAL_SECS,
                            0,
                            check_container_state, duthost, container_name, True)
    pytest_assert(is_running, "'{}' is not running on DuT!".format(container_name))
    logger.info("'{}' is running on DuT!".format(container_name))

    consumes_memory_and_checks_monit(duthost, container_name, vm_workers, True)


def check_log_message(duthost, container_name):
    """Leverages LogAanlyzer to check whether `memory_checker` can log the specific message
    into syslog or not.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: A string represents the name of container.

    Returns:
        None.
    """
    expected_alerting_messages = []
    expected_alerting_messages.append(".*\[memory_checker\] Exits without checking memory usage.*'telemetry'.*")

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="memory_checker_skip_removed_container")
    loganalyzer.expect_regex = []
    loganalyzer.expect_regex.extend(expected_alerting_messages)
    marker = loganalyzer.init()

    logger.info("Sleep '{}' seconds to wait for the message from syslog ...".format(WAITING_SYSLOG_MSG_SECS))
    time.sleep(WAITING_SYSLOG_MSG_SECS)

    logger.info("Checking the syslog message written by 'memory_checker' ...")
    loganalyzer.analyze(marker)
    logger.info("Found the expected message from syslog!")


def test_memory_checker_without_container_created(duthosts, enum_dut_feature_container, remove_and_restart_container,
                                                  enum_rand_one_per_hwsku_frontend_hostname):
    """Checks whether 'memory_checker' script can log an message into syslog if
    one container is not created during device is booted/reooted. This test case will
    remove a container explicitly to simulate the scenario in which the container was not created
    successfully.

    Args:
        duthosts: The fixture returns list of DuTs.
        enum_rand_one_per_hwsku_frontend_hostname: The fixture randomly pick up
          a frontend DuT from testbed.

    Returns:
        None.
    """
    dut_name, container_name = decode_dut_and_container_name(enum_dut_feature_container)
    pytest_require(dut_name == enum_rand_one_per_hwsku_frontend_hostname,
                   "Skips testing memory_checker of container '{}' on the DuT '{}' since another DuT '{}' was chosen."
                   .format(container_name, dut_name, enum_rand_one_per_hwsku_frontend_hostname))

    pytest_require(container_name == "telemetry",
                   "Skips testing memory_checker of container '{}' since memory monitoring is only enabled for 'telemetry'."
                   .format(container_name))

    duthost = duthosts[dut_name]

    # TODO: Currently we only test 'telemetry' container which has the memory threshold 400MB
    # and number of vm_workers is hard coded. We will extend this testing on all containers after
    # the feature 'memory_checker' is fully implemented.
    container_name = "telemetry"

    pytest_require("Celestica-E1031" not in duthost.facts["hwsku"]
                   and (("20191130" in duthost.os_version and parse_version(duthost.os_version) > parse_version("20191130.72"))
                   or parse_version(duthost.kernel_version) > parse_version("4.9.0")),
                   "Test is not supported for platform Celestica E1031, 20191130.72 and older image versions!")

    check_log_message(duthost, container_name)
