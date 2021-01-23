"""
Test the feature of container_checker
"""
import logging

import pytest

from pkg_resources import parse_version
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

CONTAINER_CHECK_INTERVAL_SECS = 1
CONTAINER_STOP_THRESHOLD_SECS = 30
CONTAINER_RESTART_THRESHOLD_SECS = 180


@pytest.fixture(autouse=True, scope='module')
def config_reload_after_tests(duthost):
    yield
    config_reload(duthost)


@pytest.fixture(autouse=True, scope="module")
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT was 201911 or old version.

    Args:
        duthost: Host DUT.

    Return:
        None.
    """
    if parse_version(duthost.kernel_version) <= parse_version("4.9.0"):
        pytest.skip("Test was not supported for 201911 and older image version!")


def get_disabled_container_list(duthost):
    """Gets the container/service names which are disabled.

    Args:
        duthost: Host DUT.

    Return:
        A list includes the names of disabled containers/services
    """
    disabled_containers = []

    container_status, succeeded = duthost.get_feature_status()
    pytest_assert(succeeded, "Failed to get status ('enabled'|'disabled') of containers. Exiting...")

    for container_name, status in container_status.items():
        if status == "disabled":
            disabled_containers.append(container_name)

    return disabled_containers


def is_container_running(duthost, container_name):
    """Decides whether the container is running or not

    Args:
        duthost: Host DUT.
        container_name: Name of a container.
    Return:
        Boolean value. True represents the container is running
    """
    result = duthost.shell("docker inspect -f \{{\{{.State.Running\}}\}} {}".format(container_name))
    return result["stdout_lines"][0].strip() == "true"


def check_container_state(duthost, container_name, should_be_running):
    """Determines whether a container is in the expected state (running/not running)

    Args:
        duthost: Host DUT.
        container_name: Name of container.
        should be running: Boolean value.

    Return:
        This function will return True if the container was in the expected state.
        Otherwise, it will return False.
    """
    is_running = is_container_running(duthost, container_name)
    return is_running == should_be_running


def is_hiting_start_limit(duthost, container_name):
    """Checks whether the container can not be restarted is due to start-limit-hit.

    Args:
        duthost: Host DUT.
        container_name: name of a container.

    Return:
        If start limitation was hit, then this function will return True. Otherwise
        it returns False.
    """
    service_status = duthost.shell("sudo systemctl status {}.service | grep 'Active'".format(container_name))
    for line in service_status["stdout_lines"]:
        if "start-limit-hit" in line:
            return True

    return False


def clear_failed_flag_and_restart(duthost, container_name):
    """Clears the failed flag of a container and restart it.

    Args:
        duthost: Host DUT.
        container_name: name of a container.

    Return:
        None
    """
    logger.info("{} hits start limit and clear reset-failed flag".format(container_name))
    duthost.shell("sudo systemctl reset-failed {}.service".format(container_name))
    duthost.shell("sudo systemctl start {}.service".format(container_name))
    restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                           CONTAINER_CHECK_INTERVAL_SECS,
                           check_container_state, duthost, container_name, True)
    pytest_assert(restarted, "Failed to restart container '{}' after reset-failed was cleared".format(container_name))


def check_all_critical_processes_status(duthost):
    """Post-checks the status of critical processes.

    Args:
        duthost: Host DUT.

    Return:
        This function will return True if all critical processes are running.
        Otherwise it will return False.
    """

    processes_status = duthost.all_critical_process_status()
    for container_name, processes in processes_status.items():
        if processes["status"] is False or len(processes["exited_critical_process"]) > 0:
            return False

    return True


def post_test_check(duthost, up_bgp_neighbors):
    """Post-checks the status of critical processes and state of BGP sessions.

    Args:
        duthost: Host DUT.
        skip_containers: A list contains the container names which should be skipped.

    Return:
        This function will return True if all critical processes are running and
        all BGP sessions are established. Otherwise it will return False.
    """

    return check_all_critical_processes_status(duthost) and duthost.check_bgp_session_state(up_bgp_neighbors, "established")


def postcheck_critical_processes_status(duthost, up_bgp_neighbors):
    """Calls the functions to post-check the status of critical processes and
       state of BGP sessions.

    Args:
        duthost: Host DUT.
        skip_containers: A list contains the container names which should be skipped.

    Return:
        If all critical processes are running and all BGP sessions are established, it
        returns True. Otherwise it will call the function to do post-check every 30 seconds
        for 3 minutes. It will return False after timeout
    """
    return wait_until(CONTAINER_RESTART_THRESHOLD_SECS, CONTAINER_CHECK_INTERVAL_SECS,
                      post_test_check, duthost, up_bgp_neighbors)


def stop_containers(duthost, container_autorestart_states, skip_containers):
    """Stops the running containers and returns their names .

    Args:
        duthost: Host DUT.
        container_autorestart_states: A dictionary which key is container name and
        value is the state of autorestart feature.
        skip_containers: A list contains the container names which should be skipped.

    Return:
        A list which contains the container names which are stopped to run.
    """
    stopped_containers_list = []

    for container_name in container_autorestart_states.keys():
        if container_name not in skip_containers:
            logger.info("Stopping the container '{}'...".format(container_name))
            duthost.shell("sudo systemctl stop {}.service".format(container_name))
            logger.info("Waiting until container '{}' is stopped...".format(container_name))
            stopped = wait_until(CONTAINER_STOP_THRESHOLD_SECS,
                                 CONTAINER_CHECK_INTERVAL_SECS,
                                 check_container_state, duthost, container_name, False)
            pytest_assert(stopped, "Failed to stop container '{}'".format(container_name))
            logger.info("Container '{}' was stopped".format(container_name))
            stopped_containers_list.append(container_name)

    return stopped_containers_list


def check_alerting_message(duthost, stopped_containers_list):
    """Checks whether the names of stopped containers appear in Monit alerting message.

    Args:
        duthost: Host DUT.
        stopped_containers_list: A list of stopped container names.

    Return:
        None.
    """
    alerting_message = duthost.shell("sudo cat /var/log/syslog | grep -m 1 '.*monit.*container_checker'",
                                     module_ignore_errors=True)

    pytest_assert(len(alerting_message["stdout_lines"]) > 0,
                  "Failed to get Monit alerting message from container_checker!")

    for container_name in stopped_containers_list:
        if container_name not in alerting_message["stdout_lines"][0]:
            pytest.fail("Container '{}' was not running and not found in Monit alerting message!"
                        .format(container_name))


def restart_containers(duthost, stopped_containers_list):
    """Restarts the container after testing.

    This function will restart the stopped containers and then check whether the
    containers are actually restarted.

    Args:
        duthost: Host DUT.
        stopped_containers_list: A list of stopped container names.

    Return:
        None.
    """
    for container_name in stopped_containers_list:
        logger.info("Restarting the container '{}'...".format(container_name))
        duthost.shell("sudo systemctl restart {}.service".format(container_name), module_ignore_errors=True)

    for container_name in stopped_containers_list:
        logger.info("Checking the running status of container '{}'...".format(container_name))
        restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                               CONTAINER_CHECK_INTERVAL_SECS,
                               check_container_state, duthost, container_name, True)
        if not restarted:
            if is_hiting_start_limit(duthost, container_name):
                clear_failed_flag_and_restart(duthost, container_name)
            else:
                pytest.fail("Failed to restart container '{}'".format(container_name))
        logger.info("Container '{}' was restarted".format(container_name))


def test_container_checker(duthosts, rand_one_dut_hostname, tbinfo):
    """Tests the feature of container checker.

    This function will check whether the container names will appear in the Monit
    alerting message if they are stopped explicitly or they hit start limitation.

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: hostname of DUT.
        tbinfo: Testbed information.

    Returns:
        None.
    """
    duthost = duthosts[rand_one_dut_hostname]
    container_autorestart_states = duthost.get_container_autorestart_states()
    disabled_containers = get_disabled_container_list(duthost)

    bgp_neighbors = duthost.get_bgp_neighbors()
    up_bgp_neighbors = [ k.lower() for k, v in bgp_neighbors.items() if v["state"] == "established" ]

    skip_containers = disabled_containers[:]
    # Skip 'radv' container on devices whose role is not T0.
    if tbinfo["topo"]["type"] != "t0":
        skip_containers.append("radv")

    stopped_containers_list = stop_containers(duthost, container_autorestart_states, skip_containers)
    # Wait for 6 minutes such that Monit has a chance to write alerting message into syslog.
    time.sleep(360)

    check_alerting_message(duthost, stopped_containers_list)
    restart_containers(duthost, stopped_containers_list)

    if not postcheck_critical_processes_status(duthost, up_bgp_neighbors):
        pytest.fail("Post-check failed after testing")
