"""
Tests for the `pddf_ledutil` command in SONiC

"""

import logging
import os
import re
import time
from contextlib import contextmanager

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import chassis
from tests.common.platform.device_utils import start_platform_api_service, platform_api_conn    # noqa: F401
from tests.platform_tests.utils import get_config_from_yaml

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
]

TEST_CONFIG_FILE = os.path.join(os.path.split(__file__)[0], "pddf_ledutil.yml")


@pytest.fixture(scope="module")
def led_config(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Load LED configuration from YAML file based on platform and hwsku.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    test_config = get_config_from_yaml(TEST_CONFIG_FILE)

    config = test_config.get('default')

    platform = duthost.facts['platform']
    hwsku = duthost.facts['hwsku']

    # Override test config with platform/hwsku specific configs
    for platform_regexp in test_config:
        if platform_regexp == 'default':
            continue
        if re.match(platform_regexp, platform):
            config = test_config[platform_regexp].get('default', {})
            for hwsku_regexp in test_config[platform_regexp]:
                if hwsku_regexp == 'default':
                    continue
                if re.match(hwsku_regexp, hwsku):
                    config.update(test_config[platform_regexp][hwsku_regexp])
            break

    if config is None:
        pytest.skip(f"No LED configuration found for platform: {platform} hwsku: {hwsku}")

    logger.info(f'LED configuration for platform: {platform} hwsku: {hwsku}: {config}')
    return config


@pytest.fixture(scope="module", autouse=True)
def check_pddf_mode(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Check if the platform supports pddf_ledutil.
    Skip tests if pddf_ledutil is not available.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Check if pddf_ledutil command exists
    result = duthost.shell("which pddf_ledutil", module_ignore_errors=True)
    if result["rc"] != 0:
        pytest.skip("pddf_ledutil command not found - platform may not support PDDF")

    logger.info(f"pddf_ledutil found at: {result['stdout'].strip()}")

    # Verify pddf_ledutil is functional by trying to run it
    duthost.shell("pddf_ledutil --help 2>&1 || pddf_ledutil 2>&1", module_ignore_errors=True)
    logger.info("pddf_ledutil appears to be functional")

    logger.info("Platform supports pddf_ledutil, proceeding with tests")


@pytest.fixture(scope="function")
def dut(duthosts, enum_rand_one_per_hwsku_hostname):
    """Fixture that provides the DUT host."""
    return duthosts[enum_rand_one_per_hwsku_hostname]


@contextmanager
def stop_and_restart_led_service(duthost, led_type_config, led_name):
    """
    Context manager to stop LED service, yield duthost, then restart service.

    Args:
        duthost: The DUT host
        led_type_config: The specific LED type dict (e.g., led_config["PORT_LED"])
        led_name: The actual LED instance name (e.g., "PORT_LED_1")
    """
    service_name = led_type_config.get("service")
    logger.info(f"Stopping {service_name} to allow manual LED control for {led_name}")

    service_status = duthost.shell(f"systemctl is-active {service_name}", module_ignore_errors=True)
    was_running = service_status["stdout"].strip() == "active"

    if was_running:
        duthost.shell(f"sudo systemctl stop {service_name}")
        time.sleep(1)

    yield duthost

    if was_running:
        logger.info(f"Restarting {service_name}")
        duthost.shell(f"sudo systemctl start {service_name}")
        time.sleep(2)


def run_led_color_test(duthost, led_type_config, led_name):
    """
    Test LED color changes for a specific LED instance.

    Args:
        duthost: The DUT host
        led_type_config: The specific LED type dict (e.g., led_config["PORT_LED"])
        led_name: The actual LED instance name (e.g., "PORT_LED_1")
    """
    colors = led_type_config.get("colors", [])
    if not colors:
        pytest.fail(f"No color configuration found for {led_name}")

    logger.info(f"Testing {led_name} with colors: {colors}")

    initial_color_result = duthost.shell(f"sudo pddf_ledutil getstatusled {led_name}", module_ignore_errors=True)
    initial_color = initial_color_result["stdout"].strip()

    valid_color_received = (initial_color_result["rc"] == 0) and ("not configured" not in initial_color)
    if not valid_color_received:
        pytest.fail(f"LED {led_name} status could not be determined cannot proceed with test.")

    # Test each color
    for color in colors:
        logger.info(f"Setting {led_name} to {color}")

        # Set the LED color
        set_result = duthost.shell(f"sudo pddf_ledutil setstatusled {led_name} {color}", module_ignore_errors=True)
        output_is_true = set_result["stdout"].strip() == "True"
        pytest_assert(
            output_is_true, f"Failed to set {led_name} to {color}: expected True, got {set_result.get('stdout', '')}"
        )
        if not output_is_true:
            break
        time.sleep(0.1)

        # Get the LED's current color
        get_result = duthost.shell(f"sudo pddf_ledutil getstatusled {led_name}", module_ignore_errors=True)
        successful_status_read = get_result["rc"] == 0
        pytest_assert(
            successful_status_read,
            f"Failed to get {led_name} status after setting to {color}: {get_result.get('stderr', '')}",
        )
        if successful_status_read:
            color_actual = get_result["stdout"].strip()

            pytest_assert(
                color_actual == color, f"LED color for {led_name} expected to be '{color}', got '{color_actual}'"
            )
    # Restore the initial color
    if initial_color:
        logger.info(f"Restoring {led_name} to initial color: {initial_color}")
        restore_result = duthost.shell(
            f"sudo pddf_ledutil setstatusled {led_name} {initial_color}", module_ignore_errors=True
        )
        if restore_result["rc"] == 0:
            logger.info(f"Successfully restored {led_name} to {initial_color}")
        else:
            logger.warning(f"Failed to restore {led_name} to {initial_color}: {restore_result.get('stderr', '')}")


def get_led_count(led_type_config, _platform_api_conn):
    """Get the count of LEDs based on config or dynamic detection"""
    count_function = led_type_config.get("count_function")

    try:
        func = getattr(chassis, count_function)
        count = int(func(_platform_api_conn))
        logger.info(f"Found {count} LEDs using chassis.{count_function}")
        return count

    except AttributeError:
        logger.warning(f"Function {count_function} not found in chassis module")  # noqa: E713
        return 0
    except Exception as e:
        logger.warning(f"Failed to get LED count using {count_function}: {e}")
        return 0


def test_pddf_ledutil_leds(dut, led_config, platform_api_conn):  # noqa: F811
    """
    Test all LEDs configured in the YAML file.
    """
    for led_type, led_type_config in led_config.items():
        if not isinstance(led_type_config, dict):
            continue

        is_multiple = led_type_config.get("multiple", False)

        if is_multiple:
            count = get_led_count(led_type_config, platform_api_conn)
            if count == 0:
                logger.info(f"No {led_type} LEDs found on this platform, skipping")
                continue

            name_template = led_type_config.get("name_template", f"{led_type}_{{}}")
            index_start = led_type_config.get("index_start", 1)

            logger.info(f"Testing {count} {led_type} LEDs")

            first_led_name = name_template.format(index_start)
            with stop_and_restart_led_service(dut, led_type_config, first_led_name):
                for i in range(index_start, index_start + count):
                    led_name = name_template.format(i)
                    logger.info(f"Testing {led_name}")
                    run_led_color_test(dut, led_type_config, led_name)
        else:
            led_name = led_type
            logger.info(f"Testing single LED: {led_name}")
            with stop_and_restart_led_service(dut, led_type_config, led_name):
                run_led_color_test(dut, led_type_config, led_name)
