"""
Test the feature of memory checker.
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
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

CONTAINER_STOP_THRESHOLD_SECS = 200
CONTAINER_RESTART_THRESHOLD_SECS = 180
CONTAINER_CHECK_INTERVAL_SECS = 1


@pytest.fixture(autouse=True)
def modify_monit_config_and_restart(duthosts, enum_dut_feature_container, enum_rand_one_per_hwsku_frontend_hostname):

    """Backup Monit configuration files, then customize and restart it before testing.
    Restore original Monit configuration files and restart Monit service after testing.

    Args:
        duthost: Hostname of DuT.

    Returns:
        None.
    """
    dut_name, container_name = decode_dut_and_container_name(enum_dut_feature_container)
    pytest_require(dut_name == enum_rand_one_per_hwsku_frontend_hostname and container_name == "telemetry",
                   "Skips testing memory_checker of container '{}' on the DuT '{}' since another DuT '{}' was chosen."
                   .format(container_name, dut_name, enum_rand_one_per_hwsku_frontend_hostname))
    duthost = duthosts[dut_name]

    logger.info("Back up Monit configuration files on DuT '{}' ...".format(duthost.hostname))
    duthost.shell("sudo cp -f /etc/monit/monitrc /tmp/")
    duthost.shell("sudo cp -f /etc/monit/conf.d/monit_telemetry /tmp/")

    temp_config_line = '    if status == 3 for 5 times within 10 cycles then exec "/usr/bin/restart_service telemetry"'
    logger.info("Modifying Monit config to eliminate start delay and decrease interval ...")
    duthost.shell("sudo sed -i '$s/^./#/' /etc/monit/conf.d/monit_telemetry")
    duthost.shell("echo '{}' | sudo tee -a /etc/monit/conf.d/monit_telemetry".format(temp_config_line))
    duthost.shell("sudo sed -i 's/set daemon 60/set daemon 10/' /etc/monit/monitrc")
    duthost.shell("sudo sed -i '/with start delay 300/s/^./#/' /etc/monit/monitrc")

    logger.info("Restart Monit service ...")
    duthost.shell("sudo systemctl restart monit")

    yield

    logger.info("Restore original Monit configuration files on DuT '{}' ...".format(duthost.hostname))
    duthost.shell("sudo mv -f /tmp/monitrc /etc/monit/")
    duthost.shell("sudo mv -f /tmp/monit_telemetry /etc/monit/conf.d/")

    logger.info("Restart Monit service ...")
    duthost.shell("sudo systemctl restart monit")

    logger.info("Restore bgp neighbours ...")
    duthost.shell("config bgp startup all")


def install_stress_utility(duthost, creds, container_name):
    """Installs the 'stress' utility in container.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.

    Returns:
        None.
    """
    logger.info("Installing 'stress' utility in '{}' container ...".format(container_name))

    # Get proxy settings from creds
    http_proxy = creds.get('proxy_env', {}).get('http_proxy', '')
    https_proxy = creds.get('proxy_env', {}).get('https_proxy', '')

    # Shutdown bgp for having ability to install stress tool
    duthost.shell("config bgp shutdown all")
    install_cmd_result = duthost.shell("docker exec {} bash -c 'export http_proxy={} \
                                        && export https_proxy={} \
                                        && apt-get install stress -y'".format(container_name, http_proxy, https_proxy))

    exit_code = install_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to install 'stress' utility!")
    logger.info("'stress' utility was installed.")


def remove_stress_utility(duthost, container_name):
    """Removes the 'stress' utility from container.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.

    Returns:
        None.
    """
    logger.info("Removing 'stress' utility from '{}' container ...".format(container_name))
    remove_cmd_result = duthost.shell("docker exec {} apt-get remove stress -y".format(container_name))
    exit_code = remove_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to remove 'stress' utility!")
    logger.info("'stress' utility was removed.")


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


def consume_memory_and_restart_container(duthost, container_name, vm_workers, loganalyzer, marker):
    """Invokes the 'stress' utility to consume memory more than the threshold asynchronously
    and checks whether the container can be stopped and restarted. Loganalyzer was leveraged
    to check whether the log messages related to container stopped were generated.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.
        vm_workers: Number of workers which does the spinning on malloc()/free()
          to consume memory.

    Returns:
        None.

    """
    thread_pool = ThreadPool()
    thread_pool.apply_async(consume_memory, (duthost, container_name, vm_workers))

    logger.info("Sleep 100 seconds to wait for the alerting messages from syslog...")
    time.sleep(100)

    logger.info("Checking the alerting messages related to container stopped ...")
    loganalyzer.analyze(marker)
    logger.info("Found all the expected alerting messages from syslog!")

    logger.info("Waiting for '{}' container to be restarted ...".format(container_name))
    restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                           CONTAINER_CHECK_INTERVAL_SECS,
                           check_container_state, duthost, container_name, True)
    pytest_assert(restarted, "Failed to restart '{}' container!".format(container_name))
    logger.info("'{}' container is restarted.".format(container_name))


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
    is_succeeded = wait_until(CONTAINER_RESTART_THRESHOLD_SECS, CONTAINER_CHECK_INTERVAL_SECS,
                              check_critical_processes, duthost, container_name)
    if not is_succeeded:
        pytest.fail("Not all critical processes in '{}' container are running!"
                    .format(container_name))
    logger.info("All critical processes in '{}' container are running.".format(container_name))


def test_memory_checker(duthosts, enum_dut_feature_container, creds, enum_rand_one_per_hwsku_frontend_hostname):
    """Checks whether the telemetry container can be restarted or not if the memory
    usage of it is beyond the threshold. The `stress` utility is leveraged as
    the memory stressing tool.

    Args:
        duthosts: The fixture returns list of DuTs.
        enum_rand_one_per_hwsku_frontend_hostname: The fixture randomly pick up
          a frontend DuT from testbed.

    Returns:
        None.
    """
    dut_name, container_name = decode_dut_and_container_name(enum_dut_feature_container)
    pytest_require(dut_name == enum_rand_one_per_hwsku_frontend_hostname and container_name == "telemetry",
                   "Skips testing memory_checker of container '{}' on the DuT '{}' since another DuT '{}' was chosen."
                   .format(container_name, dut_name, enum_rand_one_per_hwsku_frontend_hostname))
    duthost = duthosts[dut_name]

    # TODO: Currently we only test 'telemetry' container which has the memory threshold 400MB
    # and number of vm_workers is hard coded. We will extend this testing on all containers after
    # the feature 'memory_checker' is fully implemented.
    container_name = "telemetry"
    vm_workers = 4

    pytest_require("Celestica-E1031" not in duthost.facts["hwsku"]
                   and (("20191130" in duthost.os_version and parse_version(duthost.os_version) > parse_version("20191130.72"))
                   or parse_version(duthost.kernel_version) > parse_version("4.9.0")),
                   "Test is not supported for platform Celestica E1031, 20191130.72 and older image versions!")

    expected_alerting_messages = []
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="container_restart_due_to_memory")
    loganalyzer.expect_regex = []
    expected_alerting_messages.append(".*restart_service.*Restarting service 'telemetry'.*")
    expected_alerting_messages.append(".*Stopping Telemetry container.*")
    expected_alerting_messages.append(".*Stopped Telemetry container.*")

    loganalyzer.expect_regex.extend(expected_alerting_messages)
    marker = loganalyzer.init()

    install_stress_utility(duthost, creds, container_name)
    consume_memory_and_restart_container(duthost, container_name, vm_workers, loganalyzer, marker)

    remove_stress_utility(duthost, container_name)
    postcheck_critical_processes(duthost, container_name)
