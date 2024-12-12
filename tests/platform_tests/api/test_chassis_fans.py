import logging
import random
import time
import pytest

from tests.common.helpers.platform_api import chassis, fan
from .platform_api_test_base import PlatformApiTestBase
from tests.common.platform.device_utils import platform_api_conn    # noqa F401
from tests.common.helpers.thermal_control_test_helper import start_thermal_control_daemon, stop_thermal_control_daemon

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


class TestChassisFans(PlatformApiTestBase):

    num_fans = None
    chassis_facts = None

    # This fixture would probably be better scoped at the class level, but
    # it relies on the platform_api_conn fixture, which is scoped at the function
    # level, so we must do the same here to prevent a scope mismatch.

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, platform_api_conn, duthost):    # noqa F811
        if self.num_fans is None:
            try:
                self.num_fans = int(chassis.get_num_fans(platform_api_conn))
            except Exception:
                pytest.fail("num_fans is not an integer")
            else:
                if self.num_fans == 0:
                    pytest.skip("No fans found on device")
        stop_thermal_control_daemon(duthost)
        yield
        start_thermal_control_daemon(duthost)

    #
    # Helper functions
    #

    def compare_value_with_platform_facts(self, duthost, key, value, fan_idx):
        expected_value = None
        if duthost.facts.get("chassis"):
            expected_fans = duthost.facts.get("chassis").get("fans")
            if expected_fans:
                expected_value = expected_fans[fan_idx].get(key)

        if self.expect(expected_value is not None,
                       "Unable to get expected value for '{}' from platform.json file for fan {}".format(key, fan_idx)):
            self.expect(value == expected_value,
                        "'{}' value is incorrect. Got '{}', expected '{}' for fan {}"
                        .format(key, value, expected_value, fan_idx))

    def get_fan_facts(self, duthost, fan_idx, def_value, *keys):
        if duthost.facts.get("chassis"):
            fans = duthost.facts.get("chassis").get("fans")
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
        for i in range(self.num_fans):
            name = fan.get_name(platform_api_conn, i)

            if self.expect(name is not None, "Unable to retrieve Fan {} name".format(i)):
                self.expect(isinstance(name, STRING_TYPE), "Fan {} name appears incorrect".format(i))
                self.compare_value_with_platform_facts(duthost, 'name', name, i)

        self.assert_expectations()

    def test_get_presence(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa F811
        for i in range(self.num_fans):
            presence = fan.get_presence(platform_api_conn, i)

            if self.expect(presence is not None, "Unable to retrieve fan {} presence".format(i)):
                if self.expect(isinstance(presence, bool), "Fan {} presence appears incorrect".format(i)):
                    self.expect(presence is True, "Fan {} is not present".format(i))

        self.assert_expectations()

    def test_get_model(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):     # noqa F811
        for i in range(self.num_fans):
            model = fan.get_model(platform_api_conn, i)

            if self.expect(model is not None, "Unable to retrieve fan {} model".format(i)):
                self.expect(isinstance(model, STRING_TYPE), "Fan {} model appears incorrect".format(i))

        self.assert_expectations()

    def test_get_serial(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):    # noqa F811
        for i in range(self.num_fans):
            serial = fan.get_serial(platform_api_conn, i)

            if self.expect(serial is not None, "Unable to retrieve fan {} serial number".format(i)):
                self.expect(isinstance(serial, STRING_TYPE), "Fan {} serial number appears incorrect".format(i))

        self.assert_expectations()

    def test_get_status(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):    # noqa F811
        for i in range(self.num_fans):
            status = fan.get_status(platform_api_conn, i)

            if self.expect(status is not None, "Unable to retrieve fan {} status".format(i)):
                self.expect(isinstance(status, bool), "Fan {} status appears incorrect".format(i))

        self.assert_expectations()

    def test_get_position_in_parent(self, platform_api_conn):   # noqa F811
        for i in range(self.num_fans):
            position = fan.get_position_in_parent(platform_api_conn, i)
            if self.expect(position is not None, "Failed to perform get_position_in_parent for fan {}".format(i)):
                self.expect(isinstance(position, int), "Position value must be an integer value for fan {}".format(i))
        self.assert_expectations()

    def test_is_replaceable(self, platform_api_conn):       # noqa F811
        for i in range(self.num_fans):
            replaceable = fan.is_replaceable(platform_api_conn, i)
            if self.expect(replaceable is not None, "Failed to perform is_replaceable for fan {}".format(i)):
                self.expect(isinstance(replaceable, bool),
                            "Replaceable value must be a bool value for fan {}".format(i))
        self.assert_expectations()

    #
    # Functions to test methods defined in FanBase class
    #

    def test_get_speed(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn): # noqa F811
        # Ensure the fan speed is sane
        for i in range(self.num_fans):
            speed = fan.get_speed(platform_api_conn, i)
            if self.expect(speed is not None, "Unable to retrieve Fan {} speed".format(i)):
                if self.expect(isinstance(speed, int), "Fan {} speed appears incorrect".format(i)):
                    self.expect(speed > 0 and speed <= 100,
                                "Fan {} speed {} reading is not within range".format(i, speed))

        self.assert_expectations()

    def test_get_direction(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn): # noqa F811
        # Ensure the fan speed is sane
        FAN_DIRECTION_LIST = [
            "intake",
            "exhaust",
            "N/A",
        ]
        for i in range(self.num_fans):
            direction = fan.get_direction(platform_api_conn, i)
            if self.expect(direction is not None, "Unable to retrieve Fan {} direction".format(i)):
                self.expect(direction in FAN_DIRECTION_LIST,
                            "Fan {} direction is not one of predefined directions".format(i))

        self.assert_expectations()

    def test_get_fans_target_speed(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                   localhost, platform_api_conn):   # noqa F811

        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        fans_skipped = 0

        for i in range(self.num_fans):
            speed_target_val = 25
            speed_controllable = self.get_fan_facts(duthost, i, True, "speed", "controllable")
            if not speed_controllable:
                logger.info("test_get_fans_target_speed: Skipping chassis fan {} (speed not controllable)"
                            .format(i))
                fans_skipped += 1
                continue

            speed_minimum = self.get_fan_facts(duthost, i, 25, "speed", "minimum")
            speed_maximum = self.get_fan_facts(duthost, i, 100, "speed", "maximum")
            if speed_minimum > speed_target_val or speed_maximum < speed_target_val:
                speed_target_val = random.randint(speed_minimum, speed_maximum)

            speed_set = fan.set_speed(platform_api_conn, i, speed_target_val)       # noqa F841
            target_speed = fan.get_target_speed(platform_api_conn, i)
            if self.expect(target_speed is not None, "Unable to retrieve Fan {} target speed".format(i)):
                if self.expect(isinstance(target_speed, int), "Fan {} target speed appears incorrect".format(i)):
                    self.expect(target_speed == speed_target_val,
                                "Fan {} target speed setting is not correct, speed_target_val {} target_speed = {}"
                                .format(i, speed_target_val, target_speed))

        if fans_skipped == self.num_fans:
            pytest.skip("skipped as all chassis fans' speed is not controllable")

        self.assert_expectations()

    def test_set_fans_speed(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn): # noqa F811

        fans_skipped = 0
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        if duthost.facts["asic_type"] in ["cisco-8000"]:
            target_speed = random.randint(40, 60)
        else:
            target_speed = random.randint(1, 100)

        for i in range(self.num_fans):
            speed_controllable = self.get_fan_facts(duthost, i, True, "speed", "controllable")
            if not speed_controllable:
                logger.info("test_set_fans_speed: Skipping chassis fan {} (speed not controllable)".format(i))
                fans_skipped += 1
                continue

            speed_minimum = self.get_fan_facts(duthost, i, 1, "speed", "minimum")
            speed_maximum = self.get_fan_facts(duthost, i, 100, "speed", "maximum")
            if speed_minimum > target_speed or speed_maximum < target_speed:
                target_speed = random.randint(speed_minimum, speed_maximum)

            speed = fan.get_speed(platform_api_conn, i)
            speed_delta = abs(speed-target_speed)

            speed_set = fan.set_speed(platform_api_conn, i, target_speed)       # noqa F841
            time_wait = 10 if speed_delta > 40 else 5
            time.sleep(self.get_fan_facts(duthost, i, time_wait, "speed", "delay"))

            act_speed = fan.get_speed(platform_api_conn, i)
            under_speed = fan.is_under_speed(platform_api_conn, i)
            over_speed = fan.is_over_speed(platform_api_conn, i)
            self.expect(not under_speed and not over_speed,
                        "Fan {} speed change from {} to {} is not within tolerance, actual speed {}"
                        .format(i, speed, target_speed, act_speed))

        if fans_skipped == self.num_fans:
            pytest.skip("skipped as all chassis fans' speed is not controllable")

        self.assert_expectations()

    def test_set_fans_led(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa F811
        LED_COLOR_LIST = [
            "off",
            "red",
            "amber",
            "green",
        ]
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        fans_skipped = 0

        for i in range(self.num_fans):
            led_available = self.get_fan_facts(duthost, i, True, "status_led", "available")
            if not led_available:
                logger.info("test_set_fans_led: Skipping chassis fan {} (LED not available)".format(i))
                fans_skipped += 1
                continue

            led_controllable = self.get_fan_facts(duthost, i, True, "status_led", "controllable")
            if not led_controllable:
                logger.info("test_set_fans_led: Skipping chassis fan {} (LED not controllable)".format(i))
                fans_skipped += 1
                continue

            LED_COLOR_LIST = self.get_fan_facts(duthost, i, LED_COLOR_LIST, "status_led", "colors")
            for color in LED_COLOR_LIST:

                result = fan.set_status_led(platform_api_conn, i, color)
                if self.expect(result is not None, "Failed to perform set_status_led"):
                    self.expect(result is True, "Failed to set status_led for fan {} to {}".format(i, color))

                color_actual = fan.get_status_led(platform_api_conn, i)

                if self.expect(color_actual is not None, "Failed to retrieve status_led"):
                    if self.expect(isinstance(color_actual, STRING_TYPE), "Status LED color appears incorrect"):
                        self.expect(color == color_actual,
                                    "Status LED color incorrect (expected: {}, actual: {} for fan {})"
                                    .format(color, color_actual, i))

        if fans_skipped == self.num_fans:
            pytest.skip("skipped as all chassis fans' LED is not available/controllable")

        self.assert_expectations()
