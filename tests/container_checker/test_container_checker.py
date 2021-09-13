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
from tests.common.helpers.dut_utils import decode_dut_and_container_name
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


@pytest.fixture(autouse=True, scope="module")
def config_reload_after_tests(rand_selected_dut):
    """Restores the DuT.

    Args:
      rand_selected_dut: The fixture returns a randomly selected DuT.

    Returns:
      None.
    """
    duthost = rand_selected_dut

    bgp_neighbors = duthost.get_bgp_neighbors()
    up_bgp_neighbors = [ k.lower() for k, v in bgp_neighbors.items() if v["state"] == "established" ]

    yield

    config_reload(duthost)
    postcheck_critical_processes_status(duthost, up_bgp_neighbors)


@pytest.fixture(autouse=True, scope="module")
def check_image_version(rand_selected_dut):
    """Skips this test if the SONiC image installed on DUT was 201911 or old version.

    Args:
      rand_selected_dut: The fixture returns a randomly selected DuT.

    Returns:
      None.
    """
    duthost = rand_selected_dut

    pytest_require(parse_version(duthost.kernel_version) > parse_version("4.9.0"),
                   "Test was not supported for 201911 and older image version!")


@pytest.fixture(autouse=True, scope="module")
def update_monit_service(rand_selected_dut):
    """Update Monit configuration and restart it.

    This function will first reduce the monitoring interval of container checker
    from 5 minutes to 1 minute, then restart Monit service with delaying 10 seconds.
    After testing, these two changes will be rolled back.

    Args:
      rand_selected_dut: The fixture returns a randomly selected DuT.

    Returns:
      None.
    """
    duthost = rand_selected_dut

    logger.info("Back up Monit configuration files on DuT '{}' ...".format(duthost.hostname))
    duthost.shell("sudo cp -f /etc/monit/monitrc /tmp/")
    duthost.shell("sudo cp -f /etc/monit/conf.d/sonic-host /tmp/")

    temp_config_line = "    if status != 0 for 1 times within 1 cycles then alert repeat every 1 cycles"
    logger.info("Reduce the monitoring interval of container_checker.")
    duthost.shell("sudo sed -i '$s/^./#/' /etc/monit/conf.d/sonic-host")
    duthost.shell("echo '{}' | sudo tee -a /etc/monit/conf.d/sonic-host".format(temp_config_line))
    duthost.shell("sudo sed -i 's/with start delay 300/with start delay 10/' /etc/monit/monitrc")
    duthost.shell("sudo sed -i 's/set daemon 60/set daemon 10/' /etc/monit/monitrc")
    logger.info("Restart the Monit service without delaying to monitor.")
    duthost.shell("sudo systemctl restart monit")

    yield

    logger.info("Roll back the Monit configuration of container checker on DuT '{}' ..."
                .format(duthost.hostname))
    duthost.shell("sudo mv -f /tmp/monitrc /etc/monit/")
    duthost.shell("sudo mv -f /tmp/sonic-host /etc/monit/conf.d/")
    logger.info("Restart the Monit service and delay monitoring for 5 minutes.")
    duthost.shell("sudo systemctl restart monit")


def check_all_critical_processes_status(duthost):
    """Post-checks the status of critical processes.

    Args:
      duthost: Host DUT.

    Returns:
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

    Returns:
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

    Returns:
      If all critical processes are running and all BGP sessions are established, it
      returns True. Otherwise it will call the function to do post-check every 30 seconds
      for 3 minutes. It will return False after timeout
    """
    logger.info("Post-checking status of critical processes and BGP sessions...")
    return wait_until(CONTAINER_RESTART_THRESHOLD_SECS, CONTAINER_CHECK_INTERVAL_SECS,
                      post_test_check, duthost, up_bgp_neighbors)


def stop_container(duthost, container_name):
    """Stops the running container.

    Args:
      duthost: Host DUT.
      container_name: A string represents the container which will be stopped.

    Returns:
      None
    """

    logger.info("Stopping the container '{}' on DuT '{}' ...".format(container_name, duthost.hostname))
    duthost.shell("sudo systemctl stop {}.service".format(container_name))
    logger.info("Waiting until container '{}' is stopped...".format(container_name))
    stopped = wait_until(CONTAINER_STOP_THRESHOLD_SECS,
                         CONTAINER_CHECK_INTERVAL_SECS,
                         check_container_state, duthost, container_name, False)
    pytest_assert(stopped, "Failed to stop container '{}'".format(container_name))
    logger.info("Container '{}' on DuT '{}' was stopped".format(container_name, duthost.hostname))


def get_expected_alerting_message(container_name):
    """Generates the expected alerting message from the stopped container.

    Args:
      container_name: A string represents the container name.

    Return:
      A list contains the expected alerting message.
    """
    logger.info("Generating the expected alerting message for container '{}' ...".format(container_name))
    expected_alerting_messages = []

    expected_alerting_messages.append(".*Expected containers not running.*{}.*".format(container_name))

    logger.info("Generating the expected alerting message was done!")
    return expected_alerting_messages


def test_container_checker(duthosts, enum_dut_feature_container, rand_selected_dut, tbinfo):
    """Tests the feature of container checker.

    This function will check whether the container names will appear in the Monit
    alerting message if they are stopped explicitly or they hit start limitation.

    Args:
        duthosts: list of DUTs.
        enum_dut_feature_container: A list contains strings ("<dut_name>|<container_name>").
        rand_selected_dut: The fixture returns a randomly selected DuT.
        tbinfo: Testbed information.

    Returns:
        None.
    """
    dut_name, container_name = decode_dut_and_container_name(enum_dut_feature_container)
    pytest_require(dut_name == rand_selected_dut.hostname and container_name != "unknown",
                   "Skips testing container_checker of container '{}' on the DuT '{}' since another DuT '{}' was chosen."
                   .format(container_name, dut_name, rand_selected_dut.hostname))
    duthost = duthosts[dut_name]

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="container_checker_{}".format(container_name))

    disabled_containers = get_disabled_container_list(duthost)

    skip_containers = disabled_containers[:]
    skip_containers.append("gbsyncd")
    skip_containers.append("database")
    # Skip 'radv' container on devices whose role is not T0.
    if tbinfo["topo"]["type"] != "t0":
        skip_containers.append("radv")

    pytest_require(container_name not in skip_containers,
                   "Container '{}' is skipped for testing.".format(container_name))
    stop_container(duthost, container_name)

    loganalyzer.expect_regex = get_expected_alerting_message(container_name)
    with loganalyzer:
        # Wait for 1 minutes such that Monit has a chance to write alerting message into syslog.
        logger.info("Sleep 1 minutes to wait for the alerting message...")
        time.sleep(70)
