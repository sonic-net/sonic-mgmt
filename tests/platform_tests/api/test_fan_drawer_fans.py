import logging
import random
import time

import pytest

from tests.common.helpers.platform_api import chassis, fan_drawer, fan_drawer_fan
from tests.common.helpers.thermal_control_test_helper import start_thermal_control_daemon, stop_thermal_control_daemon
from tests.common.platform.device_utils import platform_api_conn    # noqa F401
from .platform_api_test_base import PlatformApiTestBase

###################################################
# TODO: Remove this after we transition to Python 3
import sys
if sys.version_info.major >= 3:
    STRING_TYPE = str
else:
    STRING_TYPE = basestring    # noqa: F821
# END Remove this after we transition to Python 3
###################################################

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]

FAN_DIRECTION_INTAKE = "intake"
FAN_DIRECTION_EXHAUST = "exhaust"
FAN_DIRECTION_NOT_APPLICABLE = "N/A"

STATUS_LED_COLOR_GREEN = "green"
STATUS_LED_COLOR_AMBER = "amber"
STATUS_LED_COLOR_RED = "red"
STATUS_LED_COLOR_OFF = "off"


class TestFanDrawerFans(PlatformApiTestBase):

    num_fan_drawers = None
    chassis_facts = None

    # This fixture would probably be better scoped at the class level, but
    # it relies on the platform_api_conn fixture, which is scoped at the function
    # level, so we must do the same here to prevent a scope mismatch.

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn): # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        if self.num_fan_drawers is None:
            try:
                self.num_fan_drawers = chassis.get_num_fan_drawers(platform_api_conn)
            except Exception:
                if "201811" in duthost.os_version or "201911" in duthost.os_version:
                    pytest.skip("Image version {} does not support API: num_fan_drawers, test will be skipped"
                                .format(duthost.os_version))
                else:
                    pytest.fail("num_fans is not an integer")
            else:
                if self.num_fan_drawers == 0:
                    pytest.skip("No fan drawers found on device")
        stop_thermal_control_daemon(duthost)
        yield
        start_thermal_control_daemon(duthost)
    #
    # Helper functions
    #

    def compare_value_with_platform_facts(self, duthost, key, value, fan_drawer_idx, fan_idx):
        expected_value = None
        if duthost.facts.get("chassis"):
            expected_fan_drawers = duthost.facts.get("chassis").get("fan_drawers")
            if expected_fan_drawers:
                expected_fans = expected_fan_drawers[fan_drawer_idx].get("fans")
                if expected_fans:
                    expected_value = expected_fans[fan_idx].get(key)

        if self.expect(expected_value is not None,
                       "Unable to get expected value for '{}' from platform.json file for fan {} within fan_drawer {}"
                       .format(key, fan_idx, fan_drawer_idx)):
            self.expect(value == expected_value,
                        "'{}' value is incorrect. Got '{}', expected '{}' for fan {} within fan_drawer {}"
                        .format(key, value, expected_value, fan_idx, fan_drawer_idx))

    def get_fan_facts(self, duthost, fan_drawer_idx, fan_idx, def_value, *keys):
        if duthost.facts.get("chassis"):
            fan_drawers = duthost.facts.get("chassis").get("fan_drawers")
            if fan_drawers:
                fans = fan_drawers[fan_drawer_idx].get("fans")
                if fans:
                    value = fans[fan_idx]
                    for key in keys:
                        value = value.get(key)
                        if value is None:
                            return def_value

                    return value

        return def_value

    #
    # Functions to test methods inherited from DeviceBase class
    #
    def test_get_name(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                name = fan_drawer_fan.get_name(platform_api_conn, j, i)

                if self.expect(name is not None, "Unable to retrieve fan drawer {} fan {} name".format(j, i)):
                    self.expect(isinstance(name, STRING_TYPE),
                                "fan drawer {} fan {} name appears incorrect".format(j, i))
                    self.compare_value_with_platform_facts(duthost, 'name', name, j, i)

        self.assert_expectations()

    def test_get_presence(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa F811

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                name = fan_drawer_fan.get_name(platform_api_conn, j, i)     # noqa F841

                presence = fan_drawer_fan.get_presence(platform_api_conn, j, i)

                if self.expect(presence is not None, "Unable to retrieve fan drawer {} fan {} presence".format(j, i)):
                    if self.expect(isinstance(presence, bool),
                                   "Fan drawer {} fan {} presence appears incorrect".format(j, i)):
                        self.expect(presence is True, "Fan {} is not present".format(i))

        self.assert_expectations()

    def test_get_model(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn): # noqa F811

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                model = fan_drawer_fan.get_model(platform_api_conn, j, i)

                if self.expect(model is not None, "Unable to retrieve fan drawer {} fan {} model".format(j, i)):
                    self.expect(isinstance(model, STRING_TYPE),
                                "Fan drawer {} fan {} model appears incorrect".format(j, i))

        self.assert_expectations()

    def test_get_serial(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):    # noqa F811

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                serial = fan_drawer_fan.get_serial(platform_api_conn, j, i)

                if self.expect(serial is not None,
                               "Unable to retrieve fan drawer {} fan {} serial number".format(j, i)):
                    self.expect(isinstance(serial, STRING_TYPE),
                                "Fan drawer {} fan {}serial number appears incorrect".format(j, i))

        self.assert_expectations()

    def test_get_status(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):    # noqa F811

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                status = fan_drawer_fan.get_status(platform_api_conn, j, i)

                if self.expect(status is not None, "Unable to retrieve drawer {} fan {} status".format(j, i)):
                    self.expect(isinstance(status, bool), "Fan drawer {} fan {} status appears incorrect".format(j, i))

        self.assert_expectations()

    def test_get_position_in_parent(self, platform_api_conn):   # noqa F811
        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)
            for i in range(num_fans):
                position = fan_drawer_fan.get_position_in_parent(platform_api_conn, j, i)
                if self.expect(position is not None,
                               "Failed to perform get_position_in_parent for drawer {} fan {}".format(j, i)):
                    self.expect(isinstance(position, int),
                                "Position value must be an integer value for drawer {} fan {}".format(j, i))
        self.assert_expectations()

    def test_is_replaceable(self, platform_api_conn):       # noqa F811
        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)
            for i in range(num_fans):
                replaceable = fan_drawer_fan.is_replaceable(platform_api_conn, j, i)
                if self.expect(replaceable is not None,
                               "Failed to perform is_replaceable for drawer {} fan {}".format(j, i)):
                    self.expect(isinstance(replaceable, bool),
                                "Replaceable value must be a bool value for drawer {} fan {}".format(j, i))

        self.assert_expectations()

    #
    # Functions to test methods defined in FanBase class
    #

    def test_get_speed(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):     # noqa F811

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                # Ensure the fan speed is sane
                speed = fan_drawer_fan.get_speed(platform_api_conn, j, i)
                if self.expect(speed is not None, "Unable to retrieve Fan drawer {} fan {} speed".format(j, i)):
                    if self.expect(isinstance(speed, int),
                                   "Fan drawer {} fan {} speed appears incorrect".format(j, i)):
                        self.expect(speed > 0 and speed <= 100,
                                    "Fan drawer {} fan {} speed {} reading is not within range".format(j, i, speed))

        self.assert_expectations()

    def test_get_direction(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn): # noqa F811
        # Ensure the fan speed is sane
        FAN_DIRECTION_LIST = [
            "intake",
            "exhaust",
            "N/A",
        ]

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                direction = fan_drawer_fan.get_direction(platform_api_conn, j, i)
                if self.expect(direction is not None,
                               "Unable to retrieve Fan drawer {} fan {} direction".format(j, i)):
                    self.expect(direction in FAN_DIRECTION_LIST,
                                "Fan drawer {} fan {} direction is not one of predefined directions".format(j, i))

        self.assert_expectations()

    def test_get_fans_target_speed(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                                   platform_api_conn, suspend_and_resume_hw_tc_on_mellanox_device):        # noqa F811

        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        fan_drawers_skipped = 0

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)
            fans_skipped = 0

            for i in range(num_fans):
                speed_target_val = 25
                speed_controllable = self.get_fan_facts(duthost, j, i, True, "speed", "controllable")
                if not speed_controllable:
                    logger.info("test_get_fans_target_speed: Skipping fandrawer {} fan {} (speed not controllable)"
                                .format(j, i))
                    fans_skipped += 1
                    continue

                speed_minimum = self.get_fan_facts(duthost, j, i, 25, "speed", "minimum")
                speed_maximum = self.get_fan_facts(duthost, j, i, 100, "speed", "maximum")
                if speed_minimum > speed_target_val or speed_maximum < speed_target_val:
                    speed_target_val = random.randint(speed_minimum, speed_maximum)

                speed_set = fan_drawer_fan.set_speed(platform_api_conn, j, i, speed_target_val)     # noqa F841
                target_speed = fan_drawer_fan.get_target_speed(platform_api_conn, j, i)
                if self.expect(target_speed is not None,
                               "Unable to retrieve Fan drawer {} fan {} target speed".format(j, i)):
                    if self.expect(isinstance(target_speed, int),
                                   "Fan drawer {} fan {} target speed appears incorrect".format(j, i)):
                        self.expect(target_speed == speed_target_val,
                                    "Fan drawer {} fan {} target speed setting is not correct, "
                                    "speed_target_val {} target_speed = {}"
                                    .format(j, i, speed_target_val, target_speed))

            if fans_skipped == num_fans:
                fan_drawers_skipped += 1

        if fan_drawers_skipped == self.num_fan_drawers:
            pytest.skip("skipped as all fandrawer fans' speed is not controllable")

        self.assert_expectations()

    def test_set_fans_speed(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn): # noqa F811

        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        fan_drawers_skipped = 0

        for j in range(self.num_fan_drawers):
            target_speed = random.randint(1, 100)
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)
            fans_skipped = 0

            for i in range(num_fans):
                speed_controllable = self.get_fan_facts(duthost, j, i, True, "speed", "controllable")
                if not speed_controllable:
                    logger.info("test_set_fans_speed: Skipping fandrawer {} fan {} (speed not controllable)"
                                .format(j, i))
                    fans_skipped += 1
                    continue

                speed_minimum = self.get_fan_facts(duthost, j, i, 1, "speed", "minimum")
                speed_maximum = self.get_fan_facts(duthost, j, i, 100, "speed", "maximum")
                if speed_minimum > target_speed or speed_maximum < target_speed:
                    target_speed = random.randint(speed_minimum, speed_maximum)

                speed = fan_drawer_fan.get_speed(platform_api_conn, j, i)
                speed_delta = abs(speed-target_speed)

                speed_set = fan_drawer_fan.set_speed(platform_api_conn, j, i, target_speed)     # noqa F841
                time_wait = 10 if speed_delta > 40 else 5
                time.sleep(self.get_fan_facts(duthost, j, i, time_wait, "speed", "delay"))

                act_speed = fan_drawer_fan.get_speed(platform_api_conn, j, i)
                under_speed = fan_drawer_fan.is_under_speed(platform_api_conn, j, i)
                over_speed = fan_drawer_fan.is_over_speed(platform_api_conn, j, i)
                self.expect(not under_speed and not over_speed,
                            "Fan drawer {} fan {} speed change from {} to {} is not within tolerance, actual speed {}"
                            .format(j, i, speed, target_speed, act_speed))

            if fans_skipped == num_fans:
                fan_drawers_skipped += 1

        if fan_drawers_skipped == self.num_fan_drawers:
            pytest.skip("skipped as all fandrawer fans' speed is not controllable")

        self.assert_expectations()

    def test_set_fans_led(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        FAULT_LED_COLOR_LIST = [
            STATUS_LED_COLOR_AMBER,
            STATUS_LED_COLOR_RED
        ]

        NORMAL_LED_COLOR_LIST = [
            STATUS_LED_COLOR_GREEN
        ]

        OFF_LED_COLOR_LIST = [
            STATUS_LED_COLOR_OFF
        ]

        LED_COLOR_TYPES = []
        LED_COLOR_TYPES.append(FAULT_LED_COLOR_LIST)
        LED_COLOR_TYPES.append(NORMAL_LED_COLOR_LIST)

        # Mellanox is not supporting set leds to 'off'
        if duthost.facts.get("asic_type") != "mellanox":
            LED_COLOR_TYPES.append(OFF_LED_COLOR_LIST)

        LED_COLOR_TYPES_DICT = {
            0: "fault",
            1: "normal",
            2: "off"
        }

        fan_drawers_skipped = 0
        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)
            fans_skipped = 0

            for i in range(num_fans):
                led_available = self.get_fan_facts(duthost, j, i, True, "status_led", "available")
                if not led_available:
                    logger.info("test_set_fans_led: Skipping fandrawer {} fan {} (LED not available)".format(j, i))
                    fans_skipped += 1
                    continue

                led_controllable = self.get_fan_facts(duthost, j, i, True, "status_led", "controllable")
                led_supported_colors = self.get_fan_facts(duthost, j, i, None, "status_led", "colors")

                if led_controllable:
                    led_type_skipped = 0
                    for index, led_type in enumerate(LED_COLOR_TYPES):
                        if led_supported_colors:
                            led_type = set(led_type) & set(led_supported_colors)
                            if not led_type:
                                logger.warning("test_status_led: Skipping fandrawer {} fan {} set status_led to {} "
                                               "(No supported colors)".format(j, i, LED_COLOR_TYPES_DICT[index]))
                                led_type_skipped += 1
                                continue

                        led_type_result = False
                        for color in led_type:
                            result = fan_drawer_fan.set_status_led(platform_api_conn, j, i, color)
                            if self.expect(result is not None, "Failed to perform set_status_led"):
                                led_type_result = result or led_type_result
                            if ((result is None) or (not result)):
                                continue
                            color_actual = fan_drawer_fan.get_status_led(platform_api_conn, j, i)
                            if self.expect(color_actual is not None, "Failed to retrieve status_led"):
                                if self.expect(isinstance(color_actual, STRING_TYPE),
                                               "Status LED color appears incorrect"):
                                    self.expect(color == color_actual,
                                                "Status LED color incorrect (expected: {}, actual: {} for fan {})"
                                                .format(color, color_actual, i))
                        self.expect(result is True, "Failed to set status_led for fan drawer {} fan {} to {}"
                                    .format(j, i, LED_COLOR_TYPES_DICT[index]))

                    if led_type_skipped == len(LED_COLOR_TYPES):
                        logger.info("test_status_led: Skipping fandrawer {} fan {} (no supported colors for all types)"
                                    .format(j, i))
                        fans_skipped += 1

                else:
                    logger.info("test_status_led: Skipping fandrawer {} fan {} (LED is not controllable)".format(j, i))
                    fans_skipped += 1

            if fans_skipped == num_fans:
                fan_drawers_skipped += 1

        if fan_drawers_skipped == self.num_fan_drawers:
            pytest.skip("skipped as all fandrawer fans' LED is not available/controllable/no supported colors")

        self.assert_expectations()
