import logging
import re
import pytest

from tests.common.platform.daemon_utils import check_pmon_daemon_enable_status
from tests.common.utilities import wait_until

from tests.system_health.test_system_health import get_system_health_config

from tests.system_health.test_system_health_fan_direction import get_led_color_by_system_health_summary
from tests.system_health.test_system_health_fan_direction import verify_sys_led_status, is_booting_time_expired

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


STATUS_LED_COLOR_MSG_REX = r'System status LED (.*)'
NOT_OK_REX = r'\bNot OK\b'
TIMEOUT = 60*2


@pytest.fixture(scope="function")
def setup(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    led_dict = get_system_health_config(duthost, "led_color", None)
    sys_led_color = get_led_color_by_system_health_summary(duthost)

    return led_dict, sys_led_color


@pytest.fixture(scope="function", autouse=True)
def teardown_function(duthosts, rand_one_dut_hostname, setup):
    led_dict, sys_led_color = setup
    logging.info("sys_led_color = {}".format(sys_led_color))
    duthost = duthosts[rand_one_dut_hostname]
    wait_until(300, 5, 0, is_booting_time_expired, duthost)

    yield

    logger.info("Restart pmon container")
    stdout = duthost.shell("docker start pmon")['stdout_lines']

    if sys_led_color is None:
        return

    assert wait_until(TIMEOUT, 10, 0, verify_sys_led_status,
        duthost, sys_led_color), \
        "The color {} of the System Status LED is not successfully restored.".format(sys_led_color)


def test_system_health_led(duthosts, enum_rand_one_per_hwsku_hostname, setup):
    """
    Test Scenario:
        S1. pmon container
        S2. Check System Status Led Status from show system-health summary output
    """

    #S1. Stop pmon container
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    led_dict, sys_led_color = setup
    stdout = duthost.shell("docker stop pmon")['stdout_lines']

    #S2. Check System Status Led Status from show system-health summary output
    if led_dict.get("fault", None) is not None:
        assert wait_until(TIMEOUT, 10, 0, verify_sys_led_status,
            duthost, led_dict["fault"]), \
            "The color {} of the System Status LED is not shown.".format(led_dict["fault"])
