import logging
import re
import random
import pytest
from datetime import timedelta

from tests.common.platform.daemon_utils import check_pmon_daemon_enable_status
from tests.common.utilities import wait_until

from tests.system_health.test_system_health import get_system_health_config

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("any"), pytest.mark.disable_loganalyzer]

daemon_name = "thermalctld"

daemon_running_str = "RUNNING"
daemon_stopped_str = "STOPPED"
daemon_exited_str = "EXITED"

FAN_DIR_ERROR_MSG_REX = ".*direction .* is not aligned with .* direction.*"
STATUS_LED_COLOR_MSG_REX = r"System status LED (.*)"
NOT_OK_REX = r"\bNot OK\b"

TIMEOUT = 60 * 2
BOOT_TIME_IN_SECONDS = 300


def is_booting_time_expired(duthost):
    uptime = duthost.get_uptime()
    logging.info("uptime={}".format(uptime))
    booting_time = timedelta(seconds=float(BOOT_TIME_IN_SECONDS))

    return uptime > booting_time


def check_thermalctld_pid(duthost, daemon_pid):
    result_pid = duthost.shell("docker exec pmon bash -c 'ps -aux| grep thermalctld | head -n -2' | awk '{print $2}' ")[
        "stdout_lines"
    ]
    return len(result_pid) == 1 and int(result_pid[0]) == daemon_pid


def check_expected_daemon_status(duthost, expected_daemon_status):
    daemon_status, _ = duthost.get_pmon_daemon_status(daemon_name)
    logging.info("daemon_status = {}, expected_daemon_status = {}".format(daemon_status, expected_daemon_status))
    # check whether the daemon_status got from 'get_pmon_daemon_status()' matches the expected status
    if daemon_status != expected_daemon_status:
        return False
    else:
        # if the expected status matches, check extra conditions under different expected daemon status
        if daemon_status == daemon_running_str:
            result_pid = duthost.shell(
                "docker exec pmon bash -c 'ps -aux| grep thermalctld | head -n -2' | awk '{print $2}' "
            )["stdout_lines"]
            return len(result_pid) >= 2

    return True


@pytest.fixture(scope="function")
def setup(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    daemon_en_status = check_pmon_daemon_enable_status(duthost, daemon_name)
    if daemon_en_status is False:
        pytest.skip("{} is not enabled in {}".format(daemon_name, duthost.facts["platform"]))
    data = collect_data(duthost)

    if len(data["keys"]) == 0:
        pytest.skip("(ECMSG-feature) Fan direction not support on this dut")

    select_key = random.sample(data["keys"], 1)
    select_direction = data["data"][select_key[0]]

    # check all fan direction is the same
    for direction in data["data"].items():
        assert direction[1] == select_direction, "Not all fans spin the same way before testing."

    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    logger.info("{} daemon is {} with pid {}".format(daemon_name, daemon_status, daemon_pid))
    stop_thermalctld_child_processes(duthost, daemon_pid)

    led_dict = get_system_health_config(duthost, "led_color", None)

    sys_led_color = get_led_color_by_system_health_summary(duthost)

    return data, led_dict, sys_led_color


@pytest.fixture(scope="function", autouse=True)
def teardown_function(duthosts, rand_one_dut_hostname, setup):
    _, _, sys_led_color = setup
    logging.info("sys_led_color = {}".format(sys_led_color))
    duthost = duthosts[rand_one_dut_hostname]
    wait_until(300, 5, 0, is_booting_time_expired, duthost)

    yield

    duthost.stop_pmon_daemon(daemon_name)
    assert wait_until(
        50, 10, 0, check_expected_daemon_status, duthost, daemon_stopped_str
    ), "The daemon thermalctld is not successfully stopped"

    duthost.start_pmon_daemon(daemon_name)
    logger.info("To make sure thermalctld two process are running.")
    assert wait_until(
        50, 10, 0, check_expected_daemon_status, duthost, daemon_running_str
    ), "The daemon thermalctld is not successfully restarted"

    if sys_led_color is not None:
        assert wait_until(
            TIMEOUT, 10, 0, verify_sys_led_status, duthost, sys_led_color
        ), "The color {} of the System Status LED is not successfully restored.".format(sys_led_color)


def stop_thermalctld_child_processes(duthost, daemon_pid):
    """
    Stop thermalctld child processes.

    Args:
        duthost(obj): dut object
        daemon_pid(int): thermalctld main process pid.
    """
    logging.info("Stopping thermalctld child processes for PID: {}".format(daemon_pid))

    child_list = duthost.shell("docker exec pmon bash -c 'pgrep -P {}'".format(daemon_pid))["stdout_lines"]

    cmd = "docker exec pmon bash -c 'kill -9 {}'"
    for pid_str in child_list:
        pid = int(pid_str)
        logging.info(cmd.format(pid))
        try:
            duthost.shell(cmd.format(pid))
        except Exception as e:
            logging.error("Failed to stop process with PID {}: {}".format(pid, str(e)))

    assert wait_until(
        30, 3, 0, check_thermalctld_pid, duthost, daemon_pid
    ), "Can't stop thermalctld child processes within expceted time."


def collect_data(duthost):
    """
    Collect fan direction data through STATE_DB.

    Return
        dev_keys : list of device name as keys in state db.
        dev_data : dict of fan direction (intake/exhaust)
    """
    keys = duthost.shell('sonic-db-cli STATE_DB KEYS "FAN_INFO|*"')["stdout_lines"]

    dev_keys = []
    dev_data = {}
    for k in keys:
        data = duthost.shell('sonic-db-cli STATE_DB HGET "{}" "direction"'.format(k))["stdout_lines"]
        if "N/A" not in data:
            # skip fan direction is 'N/A'.
            dev_data[k] = data
            dev_keys.append(k)

    return {"keys": dev_keys, "data": dev_data}


def get_system_health_summary_output(duthost):
    """
    Retrieves the system health summary output.

    Args:
        duthost: The host on which the command is executed.

    Returns:
        msg_list(list): A list of strings representing the system health summary messages.
    """

    msg_list = duthost.shell("show system-health summary")["stdout_lines"]
    return msg_list


def parse_system_health_summary(duthost, msg_regex):
    """
    Parse the system health summary output

    Args:
        duthost: The host on which the command is executed.
        msg_regex: The regular expression to match against the error messages.

    Return:
        True if a matching string is found in the  messages, otherwise False.
    """
    message = get_system_health_summary_output(duthost)
    logging.info("message = {}".format(message))

    for string in message:
        if re.search(msg_regex, string):
            return True

    return False


def get_led_color_by_system_health_summary(duthost):
    """
    Retrieves the LED color from the system health summary output.

    Args:
        duthost: The host on which the command is executed.

    Returns:
        color(string): The LED color message if found, otherwise None.
    """
    logging.info("Enter API {}".format(get_led_color_by_system_health_summary.__name__))
    color = None
    msg_list = get_system_health_summary_output(duthost)

    for msg in msg_list:
        match = re.search(STATUS_LED_COLOR_MSG_REX, msg)
        if match:
            color = match.group(1)
            logging.info("color = {}".format(color))
            return color

    return color


def verify_sys_led_status(duthost, expected_value):
    """
    Verify the system LED status.

    Parameters:
        led_status (str): The current LED status obtained from the system.
        expected_value (str): The expected LED status for verification.

    Returns:
        bool: True if the expected LED status is found in the current LED status; False otherwise.
    """

    led_status = get_led_color_by_system_health_summary(duthost)
    logging.info("led_status{}, expected{}".format(led_status, expected_value))
    return expected_value in led_status


def test_fan_direction_alarm(duthosts, rand_one_dut_hostname, setup):
    """
    Test Scenario:
        S1.Select one running fan.
        S2.Set the fan direction to another one to State DB.
        S3.Check the system-health output as expected or not.
        S4.Restore the fan direction.
        S5.Check the error message disappear or not.
    """

    duthost = duthosts[rand_one_dut_hostname]
    data, led_dict, sys_led_color = setup
    logging.info("data{}, led_dict{}, color{}".format(data, led_dict, sys_led_color))

    # S1.Select one running fan.
    select_key = random.sample(data["keys"], 1)
    select_direction = data["data"][select_key[0]]
    logging.info("select_direction{}".format(select_direction))

    # S2.Set the fan direction to another one to State DB.
    change_direction = "intake" if "exhaust" in select_direction else "exhaust"
    duthost.shell('sonic-db-cli STATE_DB HSET "{}" "direction" "{}"'.format(select_key[0], change_direction))

    # S3.Check the system-health output as expected or not.
    # Contain the string match pattern FAN_DIR_ERROR_MSG_REX
    # Contain the string match led_color["fault"] defined in system_health_monitoring_config.json
    assert parse_system_health_summary(
        duthost, FAN_DIR_ERROR_MSG_REX
    ), "Missing error message about fans spin in different way"

    if led_dict.get("fault", None) is not None:
        assert wait_until(
            TIMEOUT, 10, 0, verify_sys_led_status, duthost, led_dict["fault"]
        ), "The color {} of the System Status LED is not shown.".format(led_dict["fault"])

    # S4.Restore the fan direction.
    duthost.shell('sonic-db-cli STATE_DB HSET "{}" "direction" "{}"'.format(select_key[0], select_direction[0]))

    # S5.Check the system-health output error message disappear or not.
    assert not parse_system_health_summary(duthost, FAN_DIR_ERROR_MSG_REX), "Shouldn't have error message."
