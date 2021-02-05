"""
Test the feature of container_checker
"""
import logging

import pytest

from pkg_resources import parse_version
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import check_container_state
from tests.common.helpers.dut_utils import clear_failed_flag_and_restart
from tests.common.helpers.dut_utils import is_hitting_start_limit
from tests.common.helpers.dut_utils import is_container_running
from tests.common.utilities import wait_until

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


@pytest.fixture(autouse=True, scope="module")
def update_monit_service(duthost):
    """Update Monit configuration and restart it.

    This function will first reduce the monitoring interval of container checker
    from 5 minutes to 2 minutes, then restart Monit service without delaying. After
    testing, these two changes will be rolled back.

    Args:
        duthost: name of Host DUT.

    Return:
        None.
    """
    temp_config_line = "    if status != 0 for 2 times within 2 cycles then alert repeat every 1 cycles"
    logger.info("Reduing the monitoring interval of container_checker.")
    duthost.shell("sudo sed -i '$s/^./#/' /etc/monit/conf.d/sonic-host")
    duthost.shell("echo '{}' | sudo tee -a /etc/monit/conf.d/sonic-host".format(temp_config_line))
    duthost.shell("sudo sed -i '/with start delay 300/s/^./#/' /etc/monit/monitrc")
    logger.info("Restarting the Monit without delaying.")
    duthost.shell("sudo systemctl restart monit")
    yield
    logger.info("Rolling back the Monit configuration of container checker.")
    duthost.shell("sudo sed -i '$d' /etc/monit/conf.d/sonic-host")
    duthost.shell("sudo sed -i '$s/^#/ /' /etc/monit/conf.d/sonic-host")
    duthost.shell("sudo sed -i '/with start delay 300/s/^#/ /' /etc/monit/monitrc")
    logger.info("Restarting the Monit with delaying.")
    duthost.shell("sudo systemctl restart monit")


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
    logger.info("Post-checking status of critical processes and BGP sessions...")
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
    stopped_container_list = []

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
            stopped_container_list.append(container_name)

    return stopped_container_list


def check_alerting_message(duthost, stopped_container_list):
    """Checks whether the names of stopped containers appear in Monit alerting message.

    Args:
        duthost: Host DUT.
        stopped_container_list: A list of stopped container names.

    Return:
        None.
    """
    logger.info("Checking the alerting message...")
    alerting_messages = duthost.shell("sudo cat /var/log/syslog | grep '.*monit.*container_checker'",
                                      module_ignore_errors=True)

    pytest_assert(len(alerting_messages["stdout_lines"]) > 0,
                  "Failed to get Monit alerting messages from container_checker!")

    expected_alerting_message = ""
    for message in alerting_messages["stdout_lines"]:
        if "Expected containers not running" in message:
            expected_alerting_message = message
            break
    pytest_assert(expected_alerting_message,
                  "Failed to get expected Monit alerting message from container_checker!")

    for container_name in stopped_container_list:
        if container_name not in expected_alerting_message:
            pytest.fail("Container '{}' was not running, but its name was not found in Monit alerting message!"
                        .format(container_name))

    logger.info("Checking the alerting message was done!")


def check_containers_status(duthost, stopped_container_list):
    """Checks whether the stopped containers were started.

    This function will check whether the pervious stopped containers were actually
    restarted. If the container was not restarted by the command 'config reload', then we
    start it and check its status.

    Args:
        duthost: Hostname of DUT.
        stopped_container_list: names of stopped containers.

    Returns:
        None.
    """
    for container_name in stopped_container_list:
        logger.info("Checking the running status of container '{}'".format(container_name))
        if is_container_running(duthost, container_name):
            logger.info("Container '{}' is running.".format(container_name))
        else:
            logger.info("Container '{}' is not running and restart it...".format(container_name))
            duthost.shell("sudo systemctl restart {}".format(container_name))
            logger.info("Waiting until container '{}' is restarted...".format(container_name))
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

    stopped_container_list = stop_containers(duthost, container_autorestart_states, skip_containers)
    pytest_assert(len(stopped_container_list) > 0, "None of containers was stopped!")

    # Wait for 2 minutes such that Monit has a chance to write alerting message into syslog.
    logger.info("Sleep 2 minutes to wait for the alerting message...")
    time.sleep(130)

    check_alerting_message(duthost, stopped_container_list)

    logger.info("Executing the config reload...")
    config_reload(duthost)
    logger.info("Executing the config reload was done!")

    check_containers_status(duthost, stopped_container_list)

    if not postcheck_critical_processes_status(duthost, up_bgp_neighbors):
        pytest.fail("Post-check failed after testing the container checker!")
    logger.info("Post-checking status of critical processes and BGP sessions was done!")
