import logging
import random
import re
import time

import pytest
import yaml

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import chassis, fan_drawer, fan_drawer_fan

from platform_api_test_base import PlatformApiTestBase

###################################################
# TODO: Remove this after we transition to Python 3
import sys
if sys.version_info.major == 3:
    STRING_TYPE = str
else:
    STRING_TYPE = basestring
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

@pytest.fixture(scope="class")
def gather_facts(request, duthost):
    # Get platform facts from platform.json file
    request.cls.chassis_facts = duthost.facts.get("chassis")


@pytest.mark.usefixtures("gather_facts")
class TestFanDrawerFans(PlatformApiTestBase):

    num_fan_drawers = None
    chassis_facts = None

    # This fixture would probably be better scoped at the class level, but
    # it relies on the platform_api_conn fixture, which is scoped at the function
    # level, so we must do the same here to prevent a scope mismatch.

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, platform_api_conn):
        if self.num_fan_drawers is None:
            try:
                self.num_fan_drawers = chassis.get_num_fan_drawers(platform_api_conn)
            except:
                pytest.fail("num_fans is not an integer")

    #
    # Helper functions
    #

    def compare_value_with_platform_facts(self, key, value, fan_drawer_idx, fan_idx):
        expected_value = None

        if self.chassis_facts:
            expected_fan_drawers = self.chassis_facts.get("fan_drawer")
            if expected_fan_drawers:
                expected_fans = expected_fan_drawers[fan_drawer_idx].get("fans")
                if expected_fans:
                    expected_value = expected_fans[fan_idx].get(key)

        if self.expect(expected_value is not None,
                       "Unable to get expected value for '{}' from platform.json file for fan {} within fan_drawer {}".format(key, fan_idx, fan_drawer_idx)):
            self.expect(value == expected_value,
                          "'{}' value is incorrect. Got '{}', expected '{}' for fan {} within fan_drawer {}".format(key, value, expected_value, fan_idx, fan_drawer_idx))


    #
    # Functions to test methods inherited from DeviceBase class
    #
    def test_get_name(self, duthost, localhost, platform_api_conn):

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                name = fan_drawer_fan.get_name(platform_api_conn, j ,i)

                if self.expect(name is not None, "Unable to retrieve fan drawer {} fan {} name".format(j, i)):
                    self.expect(isinstance(name, STRING_TYPE), "fan drawer {} fan {} name appears incorrect".format(j, i))
                    self.compare_value_with_platform_facts('name', name, j, i)

        self.assert_expectations()

    def test_get_presence(self, duthost, localhost, platform_api_conn):

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                name = fan_drawer_fan.get_name(platform_api_conn, j ,i)

                presence = fan_drawer_fan.get_presence(platform_api_conn, j, i)

                if self.expect(presence is not None, "Unable to retrieve fan drawer {} fan {} presence".format(j, i)):
                    if self.expect(isinstance(presence, bool), "Fan drawer {} fan {} presence appears incorrect".format(j, i)):
                        self.expect(presence is True, "Fan {} is not present".format(j, i))

        self.assert_expectations()

    def test_get_model(self, duthost, localhost, platform_api_conn):

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                model = fan_drawer_fan.get_model(platform_api_conn, j ,i)

                if self.expect(model is not None, "Unable to retrieve fan drawer {} fan {} model".format(j, i)):
                    self.expect(isinstance(model, STRING_TYPE), "Fan drawer {} fan {} model appears incorrect".format(j, i))

        self.assert_expectations()

    def test_get_serial(self, duthost, localhost, platform_api_conn):

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                serial = fan_drawer_fan.get_serial(platform_api_conn, j ,i)

                if self.expect(serial is not None, "Unable to retrieve fan drawer {} fan {} serial number".format(j, i)):
                    self.expect(isinstance(serial, STRING_TYPE), "Fan drawer {} fan {}serial number appears incorrect".format(j, i))

        self.assert_expectations()

    def test_get_status(self, duthost, localhost, platform_api_conn):

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                status = fan_drawer_fan.get_status(platform_api_conn, j, i)

                if self.expect(status is not None, "Unable to retrieve drawer {} fan {} status".format(j, i)):
                    self.expect(isinstance(status, bool), "Fan drawer {} fan {} status appears incorrect".format(j, i))

        self.assert_expectations()

    #
    # Functions to test methods defined in FanBase class
    #

    def test_get_speed(self, duthost, localhost, platform_api_conn):

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
            # Ensure the fan speed is sane
                speed = fan_drawer_fan.get_speed(platform_api_conn, j, i)
                if self.expect(speed is not None, "Unable to retrieve Fan drawer {} fan {} speed".format(j, i)):
                    if self.expect(isinstance(speed, int), "Fan drawer {} fan {} speed appears incorrect".format(j, i)):
                        self.expect(speed > 0 and speed <= 100,
                                    "Fan drawer {} fan {} speed {} reading is not within range".format(j , i, speed))

        self.assert_expectations()

    def test_get_direction(self, duthost, localhost, platform_api_conn):
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
                if self.expect(direction is not None, "Unable to retrieve Fan drawer {} fan {} direction".format(j, i)):
                    self.expect(direction in FAN_DIRECTION_LIST, "Fan drawer {} fan {} direction is not one of predefined directions".format(j, i))

        self.assert_expectations()

    def test_get_fans_target_speed(self, duthost, localhost, platform_api_conn):

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):

                speed_target_val = 25
                speed_set = fan_drawer_fan.set_speed(platform_api_conn, j, i, speed_target_val)
                target_speed = fan_drawer_fan.get_target_speed(platform_api_conn, j, i)
                if self.expect(target_speed is not None, "Unable to retrieve Fan drawer {} fan {} target speed".format(j, i)):
                    if self.expect(isinstance(target_speed, int), "Fan drawer {} fan {} target speed appears incorrect".format(j,i)):
                        self.expect(target_speed == speed_target_val, "Fan drawer {} fan {} target speed setting is not correct, speed_target_val {} target_speed = {}".format(
                            j, i, speed_target_val, target_speed))

        self.assert_expectations()

    def test_get_fans_speed_tolerance(self, duthost, localhost, platform_api_conn):

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):
                speed_tolerance = fan_drawer_fan.get_speed_tolerance(platform_api_conn, j, i)
                if self.expect(speed_tolerance is not None, "Unable to retrieve fan drawer {} fan {} speed tolerance".format(j, i)):
                    if self.expect(isinstance(speed_tolerance, int), "Fan drawer {} fan {} speed tolerance appears incorrect".format(j, i)):
                        self.expect(speed_tolerance > 0 and speed_tolerance <= 100, "Fan drawer {} fan {} speed tolerance {} reading does not make sense".format(j, i, speed_tolerance))

        self.assert_expectations()

    def test_set_fans_speed(self, duthost, localhost, platform_api_conn):

        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            target_speed = random.randint(1, 100)

            for i in range(num_fans):
                speed = fan_drawer_fan.get_speed(platform_api_conn, j, i)
                speed_tol = fan_drawer_fan.get_speed_tolerance(platform_api_conn, j, i)

                speed_set = fan_drawer_fan.set_speed(platform_api_conn, j, i, target_speed)
                time.sleep(5)

                act_speed = fan_drawer_fan.get_speed(platform_api_conn, j, i)
                self.expect(abs(act_speed - target_speed) <= speed_tol,
                            "Fan drawer {} fan {} speed change from {} to {} is not within tolerance, actual speed {}".format(j, i, speed, target_speed, act_speed))

        self.assert_expectations()

    def test_set_fans_led(self, duthost, localhost, platform_api_conn):
        LED_COLOR_LIST = [
            "off",
            "red",
            "amber",
            "green",
        ]


        for j in range(self.num_fan_drawers):
            num_fans = fan_drawer.get_num_fans(platform_api_conn, j)

            for i in range(num_fans):

                for color in LED_COLOR_LIST:

                    result = fan_drawer_fan.set_status_led(platform_api_conn, j, i, color)
                    if self.expect(result is not None, "Failed to perform set_status_led"):
                        self.expect(result is True, "Failed to set status_led for fan drawer {} fan {} to {}".format(j , i, color))

                    color_actual = fan_drawer_fan.get_status_led(platform_api_conn, j, i)

                    if self.expect(color_actual is not None, "Failed to retrieve status_led"):
                        if self.expect(isinstance(color_actual, STRING_TYPE), "Status LED color appears incorrect"):
                            self.expect(color == color_actual, "Status LED color incorrect (expected: {}, actual: {} for fan {})".format(
                                color, color_actual, i))

        self.assert_expectations()
