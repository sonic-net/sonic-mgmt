import logging
import random
import time
import os
import pytest

from tests.common.helpers.platform_api import chassis, psu, psu_fan

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
    pytest.mark.topology('any')
]

FAN_DIRECTION_INTAKE = "intake"
FAN_DIRECTION_EXHAUST = "exhaust"
FAN_DIRECTION_NOT_APPLICABLE = "N/A"

STATUS_LED_COLOR_GREEN = "green"
STATUS_LED_COLOR_AMBER = "amber"
STATUS_LED_COLOR_RED = "red"
STATUS_LED_COLOR_OFF = "off"


class TestPsuFans(PlatformApiTestBase):

    num_psus = None
    chassis_facts = None

    # This fixture would probably be better scoped at the class level, but
    # it relies on the platform_api_conn fixture, which is scoped at the function
    # level, so we must do the same here to prevent a scope mismatch.

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, platform_api_conn):
        if self.num_psus is None:
            try:
                self.num_psus = chassis.get_num_psus(platform_api_conn)
            except Exception:
                pytest.fail("num_fans is not an integer")
            else:
                if self.num_psus == 0:
                    pytest.skip("No psus found on device")

    #
    # Helper functions
    #

    def compare_value_with_platform_facts(self, duthost, key, value, psu_idx, fan_idx):
        expected_value = None

        if duthost.facts.get("chassis"):
            expected_psus = duthost.facts.get("chassis").get("psus")
            if expected_psus:
                expected_fans = expected_psus[psu_idx].get("fans")
                if expected_fans:
                    expected_value = expected_fans[fan_idx].get(key)

        if self.expect(expected_value is not None,
                       "Unable to get expected value for '{}' from platform.json file for fan {} within psu {}"
                       .format(key, fan_idx, psu_idx)):
            self.expect(value == expected_value,
                        "'{}' value is incorrect. Got '{}', expected '{}' for fan {} within psu {}"
                        .format(key, value, expected_value, fan_idx, psu_idx))

    def get_fan_facts(self, duthost, psu_idx, fan_idx, def_value, *keys):
        if duthost.facts.get("chassis"):
            psus = duthost.facts.get("chassis").get("psus")
            if psus:
                fans = psus[psu_idx].get("fans")
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
    def test_get_name(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        for j in range(self.num_psus):
            num_fans = psu.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                name = psu_fan.get_name(platform_api_conn, j, i)

                if self.expect(name is not None, "Unable to retrieve psu {} fan {} name".format(j, i)):
                    self.expect(isinstance(name, STRING_TYPE), "psu {} fan {} name appears incorrect".format(j, i))
                    self.expect(duthost._facts.get("platform") is not None, "Unable to retrieve platform name")
                    #
                    # Check whether platform.json file exists for this specific platform. If yes compare names.
                    # If not, skip comparison.
                    #
                    platform_file_path = os.path.join("/usr/share/sonic/device",
                                                      duthost._facts.get("platform"), "platform.json")
                    platform_file_check = {}
                    try:
                        #
                        # Check if the JSON file exists in the specific path. Return 0 if it DOES exist.
                        # The command function throws exception if rc is non-zero, so handle it.
                        #
                        platform_file_check = duthost.command("[ -f {} ]".format(platform_file_path))
                    except Exception:
                        # The JSON file does not exist, so set rc to 1.
                        platform_file_check['rc'] = 1
                    if platform_file_check.get('rc') == 0:
                        logging.info("{} has a platform.json file. Running comparison with platform facts."
                                     .format(duthost._facts.get("platform")))
                        self.compare_value_with_platform_facts(duthost, 'name', name, j, i)
                    else:
                        logging.info("{} does not have a platform.json file. Skipping comparison with platform facts."
                                     .format(duthost._facts.get("platform")))

        self.assert_expectations()

    def test_get_presence(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):

        for j in range(self.num_psus):
            num_fans = psu.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                name = psu_fan.get_name(platform_api_conn, j, i)    # noqa F841

                presence = psu_fan.get_presence(platform_api_conn, j, i)

                if self.expect(presence is not None, "Unable to retrieve psu {} fan {} presence".format(j, i)):
                    if self.expect(isinstance(presence, bool),
                                   "Psu {} fan {} presence appears incorrect".format(j, i)):
                        self.expect(presence is True, "Psu {} fan {} is not present".format(j, i))

        self.assert_expectations()

    def test_get_model(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):

        for j in range(self.num_psus):
            num_fans = psu.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                model = psu_fan.get_model(platform_api_conn, j, i)

                if self.expect(model is not None, "Unable to retrieve psu {} fan {} model".format(j, i)):
                    self.expect(isinstance(model, STRING_TYPE), "psu {} fan {} model appears incorrect".format(j, i))

        self.assert_expectations()

    def test_get_serial(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):

        for j in range(self.num_psus):
            num_fans = psu.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                serial = psu_fan.get_serial(platform_api_conn, j, i)

                if self.expect(serial is not None, "Unable to retrieve psu {} fan {} serial number".format(j, i)):
                    self.expect(isinstance(serial, STRING_TYPE),
                                "psu {} fan {}serial number appears incorrect".format(j, i))

        self.assert_expectations()

    def test_get_status(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):

        for j in range(self.num_psus):
            num_fans = psu.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                status = psu_fan.get_status(platform_api_conn, j, i)

                if self.expect(status is not None, "Unable to retrieve psu {} fan {} status".format(j, i)):
                    self.expect(isinstance(status, bool), "psu {} fan {} status appears incorrect".format(j, i))

        self.assert_expectations()

    def test_get_position_in_parent(self, platform_api_conn):
        for j in range(self.num_psus):
            num_fans = psu.get_num_fans(platform_api_conn, j)
            for i in range(num_fans):
                position = psu_fan.get_position_in_parent(platform_api_conn, j, i)
                if self.expect(position is not None,
                               "Failed to perform get_position_in_parent for PSU {} fan {}".format(j, i)):
                    self.expect(isinstance(position, int),
                                "Position value must be an integer value for PSU {} fan {}".format(j, i))
        self.assert_expectations()

    def test_is_replaceable(self, platform_api_conn):
        for j in range(self.num_psus):
            num_fans = psu.get_num_fans(platform_api_conn, j)
            for i in range(num_fans):
                replaceable = psu_fan.is_replaceable(platform_api_conn, j, i)
                if self.expect(replaceable is not None,
                               "Failed to perform is_replaceable for PSU {} fan {}".format(j, i)):
                    self.expect(isinstance(replaceable, bool),
                                "Replaceable value must be a bool value for PSU {} fan {}".format(j, i))

        self.assert_expectations()

    #
    # Functions to test methods defined in FanBase class
    #

    def test_get_speed(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        for j in range(self.num_psus):
            num_fans = psu.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                # Ensure the fan speed is sane
                speed_controllable = self.get_fan_facts(duthost, j, i, True, "speed", "controllable")
                if not speed_controllable:
                    logger.info("test_get_speed: Skipping PSU {} fan {} (speed not controllable)".format(j, i))
                    continue
                speed = psu_fan.get_speed(platform_api_conn, j, i)
                if self.expect(speed is not None, "Unable to retrieve psu {} fan {} speed".format(j, i)):
                    if self.expect(isinstance(speed, int), "psu {} fan {} speed appears incorrect".format(j, i)):
                        self.expect(speed > 0 and speed <= 100,
                                    "psu {} fan {} speed {} reading is not within range".format(j, i, speed))

        self.assert_expectations()

    def test_get_direction(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        # Ensure the fan speed is sane
        FAN_DIRECTION_LIST = [
            "intake",
            "exhaust",
            "N/A",
        ]

        for j in range(self.num_psus):
            num_fans = psu.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                direction = psu_fan.get_direction(platform_api_conn, j, i)
                if self.expect(direction is not None, "Unable to retrieve psu {} fan {} direction".format(j, i)):
                    self.expect(direction in FAN_DIRECTION_LIST,
                                "psu {} fan {} direction is not one of predefined directions".format(j, i))

        self.assert_expectations()

    def test_get_fans_target_speed(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):

        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        psus_skipped = 0

        for j in range(self.num_psus):
            num_fans = psu.get_num_fans(platform_api_conn, j)
            fans_skipped = 0

            for i in range(num_fans):
                speed_target_val = 25
                speed_controllable = self.get_fan_facts(duthost, j, i, True, "speed", "controllable")
                if not speed_controllable:
                    logger.info("test_get_fans_target_speed: Skipping PSU {} fan {} (speed not controllable)"
                                .format(j, i))
                    fans_skipped += 1
                    continue

                speed_minimum = self.get_fan_facts(duthost, j, i, 25, "speed", "minimum")
                speed_maximum = self.get_fan_facts(duthost, j, i, 100, "speed", "maximum")
                if speed_minimum > speed_target_val or speed_maximum < speed_target_val:
                    speed_target_val = random.randint(speed_minimum, speed_maximum)

                speed_set = psu_fan.set_speed(platform_api_conn, j, i, speed_target_val)    # noqa F841
                target_speed = psu_fan.get_target_speed(platform_api_conn, j, i)
                if self.expect(target_speed is not None, "Unable to retrieve psu {} fan {} target speed".format(j, i)):
                    if self.expect(isinstance(target_speed, int),
                                   "psu {} fan {} target speed appears incorrect".format(j, i)):
                        self.expect(
                            target_speed == speed_target_val,
                            "psu {} fan {} target speed setting is not correct, speed_target_val {} target_speed = {}"
                            .format(j, i, speed_target_val, target_speed))

            if num_fans != 0 and fans_skipped == num_fans:
                psus_skipped += 1

        if psus_skipped == self.num_psus:
            pytest.skip("skipped as all PSU fans' speed is not controllable")

        self.assert_expectations()

    def test_get_fans_speed_tolerance(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        for j in range(self.num_psus):
            num_fans = psu.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                speed_controllable = self.get_fan_facts(duthost, j, i, True, "speed", "controllable")
                if not speed_controllable:
                    logger.info("test_get_fans_speed_tolerance: Skipping PSU {} fan {} (speed not controllable)"
                                .format(j, i))
                    continue
                speed_tolerance = psu_fan.get_speed_tolerance(platform_api_conn, j, i)
                if self.expect(speed_tolerance is not None,
                               "Unable to retrieve psu {} fan {} speed tolerance".format(j, i)):
                    if self.expect(isinstance(speed_tolerance, int), "psu {} fan {} speed tolerance appears incorrect"
                                   .format(j, i)):
                        self.expect(speed_tolerance > 0 and speed_tolerance <= 100,
                                    "psu {} fan {} speed tolerance {} reading does not make sense"
                                    .format(j, i, speed_tolerance))

        self.assert_expectations()

    def test_set_fans_speed(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):

        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        psus_skipped = 0

        for j in range(self.num_psus):
            target_speed = random.randint(1, 100)
            num_fans = psu.get_num_fans(platform_api_conn, j)
            fans_skipped = 0

            for i in range(num_fans):
                speed_controllable = self.get_fan_facts(duthost, j, i, True, "speed", "controllable")
                if not speed_controllable:
                    logger.info("test_set_fans_speed: Skipping PSU {} fan {} (speed not controllable)".format(j, i))
                    fans_skipped += 1
                    continue

                speed_minimum = self.get_fan_facts(duthost, j, i, 1, "speed", "minimum")
                speed_maximum = self.get_fan_facts(duthost, j, i, 100, "speed", "maximum")
                if speed_minimum > target_speed or speed_maximum < target_speed:
                    target_speed = random.randint(speed_minimum, speed_maximum)

                speed = psu_fan.get_speed(platform_api_conn, j, i)
                speed_tol = psu_fan.get_speed_tolerance(platform_api_conn, j, i)

                speed_set = psu_fan.set_speed(platform_api_conn, j, i, target_speed)    # noqa F841
                time.sleep(5)

                act_speed = psu_fan.get_speed(platform_api_conn, j, i)
                self.expect(abs(act_speed - target_speed) <= speed_tol,
                            "psu {} fan {} speed change from {} to {} is not within tolerance, actual speed {}"
                            .format(j, i, speed, target_speed, act_speed))

            if num_fans != 0 and fans_skipped == num_fans:
                psus_skipped += 1

        if psus_skipped == self.num_psus:
            pytest.skip("skipped as all PSU fans' speed is not controllable")

        self.assert_expectations()

    def test_set_fans_led(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        LED_COLOR_LIST = [
            "off",
            "red",
            "amber",
            "green",
        ]
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        psus_skipped = 0

        for j in range(self.num_psus):
            num_fans = psu.get_num_fans(platform_api_conn, j)
            fans_skipped = 0

            for i in range(num_fans):
                led_available = self.get_fan_facts(duthost, j, i, True, "status_led", "available")
                if not led_available:
                    logger.info("test_set_fans_led: Skipping PSU {} fan {} (LED not available)".format(j, i))
                    fans_skipped += 1
                    continue

                led_controllable = self.get_fan_facts(duthost, j, i, True, "status_led", "controllable")
                if not led_controllable:
                    logger.info("test_set_fans_led: Skipping PSU {} fan {} (LED not controllable)".format(j, i))
                    fans_skipped += 1
                    continue

                LED_COLOR_LIST = self.get_fan_facts(duthost, j, i, LED_COLOR_LIST, "status_led", "colors")
                for color in LED_COLOR_LIST:

                    result = psu_fan.set_status_led(platform_api_conn, j, i, color)
                    if self.expect(result is not None, "Failed to perform set_status_led"):
                        self.expect(result is True, "Failed to set status_led for psu {} fan {} to {}"
                                    .format(j, i, color))

                    color_actual = psu_fan.get_status_led(platform_api_conn, j, i)

                    if self.expect(color_actual is not None, "Failed to retrieve status_led"):
                        if self.expect(isinstance(color_actual, STRING_TYPE), "Status LED color appears incorrect"):
                            self.expect(color == color_actual,
                                        "Status LED color incorrect (expected: {}, actual: {} for fan {})"
                                        .format(color, color_actual, i))

            if num_fans != 0 and fans_skipped == num_fans:
                psus_skipped += 1

        if psus_skipped == self.num_psus:
            pytest.skip("skipped as all PSU fans' LED is not available/controllable")

        self.assert_expectations()
