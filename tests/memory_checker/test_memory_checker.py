"""
Test the feature of memory checker.
"""
import logging
from multiprocessing.pool import ThreadPool

import pytest

from pkg_resources import parse_version
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import check_container_state
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

CONTAINER_STOP_THRESHOLD_SECS = 200
CONTAINER_RESTART_THRESHOLD_SECS = 180
CONTAINER_CHECK_INTERVAL_SECS = 1


@pytest.fixture(autouse=True, scope="module")
def modify_monit_config_and_restart(duthost):
    """Backup Monit configuration file, then customize and restart it before testing. Restore original
    Monit configuration file and restart it after testing.

    Args:
        duthost: Hostname of DuT.

    Returns:
        None.
    """
    logger.info("Back up Monit configuration file ...")
    duthost.shell("sudo cp -f /etc/monit/monitrc /tmp/")

    logger.info("Modifying Monit config to eliminate start delay and decrease interval ...")
    duthost.shell("sudo sed -i 's/set daemon 60/set daemon 10/' /etc/monit/monitrc")
    duthost.shell("sudo sed -i '/with start delay 300/s/^./#/' /etc/monit/monitrc")

    logger.info("Restart Monit service ...")
    duthost.shell("sudo systemctl restart monit")

    yield

    logger.info("Restore original Monit configuration ...")
    duthost.shell("sudo mv -f /tmp/monitrc /etc/monit/")

    logger.info("Restart Monit service ...")
    duthost.shell("sudo systemctl restart monit")


def install_stress_utility(duthost, container_name):
    """Installs the 'stress' utility in container before testing.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.

    Retuerns:
        None.
    """
    logger.info("Installing 'stress' utility in '{}' container ...".format(container_name))

    install_cmd_result = duthost.shell("docker exec {} bash -c 'export http_proxy=http://100.127.20.21:8080 \
                                        && export https_proxy=http://100.127.20.21:8080 \
                                        && apt-get install stress -y'".format(container_name))

    exit_code = install_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to install 'stress' utility!")
    logger.info("'stress' utility was installed.")


def remove_stress_utility(duthost, container_name):
    """Removes the 'stress' utility from container after testing.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.

    Retuerns:
        None.
    """
    logger.info("Removing 'stress' utility on device ...")
    remove_cmd_result = duthost.shell("docker exec {} apt-get remove stress -y".format(container_name))
    exit_code = remove_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to remove 'stress' utility!")
    logger.info("'stress' utility was removed.")


def eatup_memory(duthost, container_name):
    """Eats up more than 400MB memory in specified container.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.

    Retuerns:
        None.
    """
    logger.info("Executing command 'stress -m 4' in '{}' container ...".format(container_name))
    duthost.shell("docker exec {} stress -m 4".format(container_name), module_ignore_errors=True)


def eatup_memory_and_restart_container(duthost, container_name):
    """Invokes the 'stress' utility to eat up more than 400MB memory asynchronously and checkes
    whether the container can be restarted or not.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.

    Retuerns:
        None.

    """
    thread_pool = ThreadPool()

    thread_pool.apply_async(eatup_memory, (duthost, container_name))

    logger.info("Waiting '{}' container to be stopped ...".format(container_name))
    stopped = wait_until(CONTAINER_STOP_THRESHOLD_SECS,
                         CONTAINER_CHECK_INTERVAL_SECS,
                         check_container_state, duthost, container_name, False)
    pytest_assert(stopped, "Failed to stop '{}' container!".format(container_name))
    logger.info("'{}' container is stopped.".format(container_name))

    logger.info("Waiting '{}' container to be restarted ...".format(container_name))
    stopped = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                         CONTAINER_CHECK_INTERVAL_SECS,
                         check_container_state, duthost, container_name, True)
    pytest_assert(stopped, "Failed to restart '{}' container!".format(container_name))
    logger.info("'{}' container is restarted.".format(container_name))


def check_critical_processes(duthost, container_name):
    """Checks whether the critical processes are running after container was restarted.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.

    Retuerns:
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

    Retuerns:
        None.
    """
    logger.info("Checking running status of critical processes in '{}' container ..."
                .format(container_name))
    is_succeeded = wait_until(CONTAINER_RESTART_THRESHOLD_SECS, CONTAINER_CHECK_INTERVAL_SECS,
                              check_critical_processes, duthost, container_name)
    if not is_succeeded:
        pytest.fail("Not all critical processes in '{}' container are running!"
                    .format(container_name))
    logger.info("All critical processes in '{}' container are running.".format(container_name))


def test_memory_checker(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Checks whether the telemetry container can be restarted or not if the memory
    usage of it is beyond 400MB.

    Args:
        duthosts: The fixture returns list of DuTs.
        enum_rand_one_per_hwsku_frontend_hostname: The fixture randomly pick up
        a frontend DuT from testbed.

    Returns:
        None.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    # TODO: Currently we only test 'telemetry' container and need extend this
    # testing on all containers after the feature 'memory_checker' is fully implemented.
    container_name = "telemetry"

    pytest_require(("20191130" in duthost.os_version and parse_version(duthost.os_version) > parse_version("20191130.72"))
                   or parse_version(duthost.kernel_version) > parse_version("4.9.0"),
                   "Test is not supported for 20191130.70 and older image versions!")

    install_stress_utility(duthost, container_name)
    eatup_memory_and_restart_container(duthost, container_name)
    remove_stress_utility(duthost, container_name)
    postcheck_critical_processes(duthost, container_name)
