"""
Test the feature of container_checker
"""
import logging

import pytest

from pkg_resources import parse_version
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.dut_utils import check_container_state
from tests.common.helpers.dut_utils import clear_failed_flag_and_restart
from tests.common.helpers.dut_utils import is_hitting_start_limit
from tests.common.helpers.dut_utils import is_container_running
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import get_disabled_container_list

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
    bgp_neighbors = duthost.get_bgp_neighbors()
    up_bgp_neighbors = [ k.lower() for k, v in bgp_neighbors.items() if v["state"] == "established" ]
    yield
    config_reload(duthost)
    postcheck_critical_processes_status(duthost, up_bgp_neighbors)


@pytest.fixture(autouse=True, scope="module")
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT was 201911 or old version.

    Args:
        duthost: Host DUT.

    Return:
        None.
    """
    pytest_require(parse_version(duthost.kernel_version) > parse_version("4.9.0"),
                   "Test was not supported for 201911 and older image version!")


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
    logger.info("Back up Monit configuration files.")
    duthost.shell("sudo cp -f /etc/monit/monitrc /tmp/")
    duthost.shell("sudo cp -f /etc/monit/conf.d/sonic-host /tmp/")

    temp_config_line = "    if status != 0 for 2 times within 2 cycles then alert repeat every 1 cycles"
    logger.info("Reduce the monitoring interval of container_checker.")
    duthost.shell("sudo sed -i '$s/^./#/' /etc/monit/conf.d/sonic-host")
    duthost.shell("echo '{}' | sudo tee -a /etc/monit/conf.d/sonic-host".format(temp_config_line))
    duthost.shell("sudo sed -i '/with start delay 300/s/^./#/' /etc/monit/monitrc")
    logger.info("Restart the Monit service without delaying to monitor.")
    duthost.shell("sudo systemctl restart monit")
    yield
    logger.info("Roll back the Monit configuration of container checker.")
    duthost.shell("sudo mv -f /tmp/monitrc /etc/monit/")
    duthost.shell("sudo mv -f /tmp/sonic-host /etc/monit/conf.d/")
    logger.info("Restart the Monit service and delay monitoring for 5 minutes.")
    duthost.shell("sudo systemctl restart monit")


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
    """Stops the running containers and returns their names as a list.

    Args:
        duthost: Host DUT.
        container_autorestart_states: A dictionary which key is container name and
        value is the state of autorestart feature.
        skip_containers: A list contains the container names which should be skipped.

    Return:
        A list contains the container names which are stopped.
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


def get_expected_alerting_messages(stopped_container_list):
    """Generates the expected alerting messages from the stopped containers.

    Args:
        stopped_container_list: A list contains container names.

    Return:
        A list contains the expected alerting messages.
    """
    logger.info("Generating the expected alerting messages...")
    expected_alerting_messages = []

    for container_name in stopped_container_list:
        expected_alerting_messages.append(".*Expected containers not running.*{}.*".format(container_name))

    logger.info("Generating the expected alerting messages was done!")
    return expected_alerting_messages


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
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="container_checker")
    loganalyzer.expect_regex = []

    container_autorestart_states = duthost.get_container_autorestart_states()
    disabled_containers = get_disabled_container_list(duthost)

    skip_containers = disabled_containers[:]
    skip_containers.append("gbsyncd")
    # Skip 'radv' container on devices whose role is not T0.
    if tbinfo["topo"]["type"] != "t0":
        skip_containers.append("radv")

    stopped_container_list = stop_containers(duthost, container_autorestart_states, skip_containers)
    pytest_assert(len(stopped_container_list) > 0, "None of containers was stopped!")

    expected_alerting_messages = get_expected_alerting_messages(stopped_container_list)
    loganalyzer.expect_regex.extend(expected_alerting_messages)
    marker = loganalyzer.init()

    # Wait for 2 minutes such that Monit has a chance to write alerting message into syslog.
    logger.info("Sleep 2 minutes to wait for the alerting message...")
    time.sleep(130)

    logger.info("Checking the alerting messages from syslog...")
    loganalyzer.analyze(marker)
    logger.info("Found all the expected alerting messages from syslog!")
