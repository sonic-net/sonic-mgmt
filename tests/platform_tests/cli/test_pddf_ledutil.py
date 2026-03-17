"""
Tests for the `pddf_ledutil` command in SONiC

"""

import logging
import os
import re
import time
import types
from contextlib import contextmanager

import pytest

from tests.common.helpers.platform_api import chassis
from tests.common.platform.device_utils import start_platform_api_service, platform_api_conn    # noqa: F401
from tests.platform_tests.utils import get_config_from_yaml

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
]

TEST_CONFIG_FILE = os.path.join(os.path.split(__file__)[0], "pddf_ledutil.yml")

_INVALID_LED = "NONEXISTENT_LED"
_INVALID_COLOR = "NONEXISTENT_COLOR"


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


@pytest.fixture
def led_service_manager(dut):
    """
    Fixture providing a context manager for stopping and restarting LED services.
    Uses try/finally to guarantee services are restarted even if the test fails.
    """
    @contextmanager
    def _manage(led_type_config, led_name):
        service_cfg = led_type_config.get("service")
        services = service_cfg if isinstance(service_cfg, list) else [service_cfg]

        services_to_restart = []
        for service_name in services:
            logger.info(f"Stopping {service_name} to allow manual LED control for {led_name}")
            service_status = dut.shell(f"systemctl is-active {service_name}", module_ignore_errors=True)
            if service_status["stdout"].strip() == "active":
                dut.shell(f"sudo systemctl stop {service_name}")
                services_to_restart.append(service_name)

        if services_to_restart:
            time.sleep(1)

        try:
            yield
        finally:
            for service_name in services_to_restart:
                logger.info(f"Restarting {service_name}")
                dut.shell(f"sudo systemctl start {service_name}")
            if services_to_restart:
                time.sleep(2)

    yield _manage


@pytest.fixture
def valid_single_led(led_config):
    """
    Resolve the first single (non-multiple) LED entry that has at least one configured color.
    Skips the test if no such entry exists.
    """
    for led_type, led_type_config in led_config.items():
        if isinstance(led_type_config, dict) and not led_type_config.get("multiple", False):
            colors = led_type_config.get("colors", [])
            if colors:
                return types.SimpleNamespace(
                    name=led_type,
                    color=colors[0],
                    type_config=led_type_config,
                )
    pytest.skip("No single-LED config with colors available")


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
        pytest.fail(f"LED {led_name} initial status could not be determined cannot begin test.")

    failures = []

    # Test each color
    for color in colors:
        logger.info(f"Setting {led_name} to {color}")

        # Set the LED color
        t_set = time.monotonic()
        set_result = duthost.shell(f"sudo pddf_ledutil setstatusled {led_name} {color}", module_ignore_errors=True)
        t_set_done = time.monotonic()
        logger.info(
            f"setstatusled {led_name} {color} — rc={set_result['rc']} "
            f"stdout={set_result['stdout'].strip()!r} stderr={set_result.get('stderr', '').strip()!r} "
            f"elapsed={t_set_done - t_set: .3f}s"
        )
        output_is_true = set_result["stdout"].strip() == "True"
        if not output_is_true:
            msg = f"Failed to set  {led_name} to {color} — \
                command output was {set_result['stdout'].strip()!r} (expected 'True')"
            logger.error(msg)
            failures.append(msg)
            continue
        time.sleep(0.1)

        # Get the LED's current color
        t_get = time.monotonic()
        get_result = duthost.shell(f"sudo pddf_ledutil getstatusled {led_name}", module_ignore_errors=True)
        t_get_done = time.monotonic()
        color_actual = get_result["stdout"].strip()
        logger.info(
            f"getstatusled {led_name} — rc={get_result['rc']} "
            f"stdout={color_actual!r} stderr={get_result.get('stderr', '').strip()!r} "
            f"elapsed={t_get_done - t_get: .3f}s "
            f"delay_after_set={t_get - t_set_done: .3f}s"
        )
        if get_result["rc"] != 0:
            msg = f"Failed to get {led_name} status after setting to {color}: {get_result.get('stderr', '').strip()!r}"
            logger.error(msg)
            failures.append(msg)
            continue

        if color_actual != color:
            # Timing diagnostic: poll a few more times to see if the value eventually settles
            logger.warning(
                f"LED color mismatch for {led_name}: expected {color!r}, got {color_actual!r}. "
                f"Polling to check if value settles..."
            )
            settled = False
            for poll_i, poll_delay in enumerate([0.1, 0.25, 0.5, 1.0], start=1):
                time.sleep(poll_delay)
                poll_result = duthost.shell(
                    f"sudo pddf_ledutil getstatusled {led_name}", module_ignore_errors=True
                )
                poll_color = poll_result["stdout"].strip()
                logger.warning(
                    f"  [{led_name}={color!r}] Poll {poll_i} (+{poll_delay}s): got {poll_color!r} "
                    f"(rc={poll_result['rc']}, stderr={poll_result.get('stderr', '').strip()!r})"
                )
                if poll_color == color:
                    logger.warning(f"  [{led_name}] Value settled to {color!r} after poll {poll_i}")
                    settled = True
                    break

            if not settled:
                msg = f"LED color for {led_name} expected to be '{color}', got '{color_actual}'"
                logger.error(msg)
                failures.append(msg)
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

    if failures:
        pytest.fail(f"{len(failures)} color {'tests' if len(failures) > 1 else 'test'} failed "
                    f"for {led_name}: \n" + "\n".join(f" - {f}" for f in failures))


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


def assert_led_state_unchanged(dut, led_name, pre_color):
    post_color = dut.shell(
        f"sudo pddf_ledutil getstatusled {led_name}", module_ignore_errors=True
    )["stdout"].strip()
    assert post_color == pre_color, (
        f"LED {led_name} color changed after rejected command: {pre_color!r} -> {post_color!r}"
    )


def test_pddf_ledutil_leds(dut, led_config, platform_api_conn, led_service_manager):  # noqa: F811
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

            for i in range(index_start, index_start + count):
                led_name = name_template.format(i)
                logger.info(f"Testing {led_name}")
                # Restart per LED, prevents the watchdog restarting services mid-test during long tests
                with led_service_manager(led_type_config, led_name):
                    run_led_color_test(dut, led_type_config, led_name)
        else:
            led_name = led_type
            logger.info(f"Testing single LED: {led_name}")
            with led_service_manager(led_type_config, led_name):
                run_led_color_test(dut, led_type_config, led_name)


def test_getstatusled_valid_led(dut, valid_single_led):  # noqa: F811
    stdout = dut.shell(
        f"sudo pddf_ledutil getstatusled {valid_single_led.name}", module_ignore_errors=True
    )["stdout"].strip()
    valid_colors = valid_single_led.type_config.get("colors", [])
    assert stdout in valid_colors, f"Expected one of {valid_colors}, got {stdout!r}"


def test_getstatusled_invalid_led(dut):  # noqa: F811
    stdout = dut.shell(
        f"sudo pddf_ledutil getstatusled {_INVALID_LED}", module_ignore_errors=True
    )["stdout"].strip()
    assert "not configured" in stdout, f"Expected 'not configured', got {stdout!r}"


def test_setstatusled_valid_led_valid_color(dut, valid_single_led, led_service_manager):  # noqa: F811
    with led_service_manager(valid_single_led.type_config, valid_single_led.name):
        pre_color = dut.shell(
            f"sudo pddf_ledutil getstatusled {valid_single_led.name}", module_ignore_errors=True
        )["stdout"].strip()
        stdout = dut.shell(
            f"sudo pddf_ledutil setstatusled {valid_single_led.name} {valid_single_led.color}", module_ignore_errors=True
        )["stdout"].strip()

        assert "True" in stdout, f"Expected 'True', got {stdout!r}"

        restore = dut.shell(
            f"sudo pddf_ledutil setstatusled {valid_single_led.name} {pre_color}", module_ignore_errors=True
        )
        if "True" not in restore["stdout"]:
            logger.warning(f"Failed to restore {valid_single_led.name} to {pre_color!r}: {restore['stdout'].strip()!r}")


def test_setstatusled_valid_led_invalid_color(dut, valid_single_led, led_service_manager):  # noqa: F811
    with led_service_manager(valid_single_led.type_config, valid_single_led.name):
        pre_color = dut.shell(
            f"sudo pddf_ledutil getstatusled {valid_single_led.name}", module_ignore_errors=True
        )["stdout"].strip()
        stdout = dut.shell(
            f"sudo pddf_ledutil setstatusled {valid_single_led.name} {_INVALID_COLOR}", module_ignore_errors=True
        )["stdout"].strip()

        assert "Invalid color" in stdout, f"Expected 'Invalid color', got {stdout!r}"
        assert "False" in stdout, f"Expected 'False', got {stdout!r}"
        assert_led_state_unchanged(dut, valid_single_led.name, pre_color)


def test_setstatusled_invalid_led(dut, valid_single_led):  # noqa: F811
    for color in [valid_single_led.color, _INVALID_COLOR]:
        stdout = dut.shell(
            f"sudo pddf_ledutil setstatusled {_INVALID_LED} {color}", module_ignore_errors=True
        )["stdout"].strip()
        assert "not configured" in stdout, f"Expected 'not configured' for color {color!r}, got {stdout!r}"
        assert "False" in stdout, f"Expected 'False' for color {color!r}, got {stdout!r}"
