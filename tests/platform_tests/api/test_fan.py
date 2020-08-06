import logging
import random
import re
import time

import pytest
import yaml

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import chassis, fan

from platform_api_test_base import PlatformApiTestBase

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


class TestFanApi(PlatformApiTestBase):

    num_fans = None

    # This fixture would probably be better scoped at the class level, but
    # it relies on the platform_api_conn fixture, which is scoped at the function
    # level, so we must do the same here to prevent a scope mismatch.

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, platform_api_conn):
        if self.num_fans is None:
            try:
                self.num_fans = int(chassis.get_num_fans(platform_api_conn))
            except:
                pytest.fail("num_fans is not an integer")

    #
    # Functions to test methods inherited from DeviceBase class
    #
    def test_get_name(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fans):
            name = fan.get_name(platform_api_conn, i)

            if self.expect(name is not None, "Unable to retrieve Fan {} name".format(i)):
                self.expect(isinstance(name, str), "Fan {} name appears incorrect".format(i))

        self.assert_expectations()

    def test_get_presence(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fans):
            presence = fan.get_presence(platform_api_conn, i)

            if self.expect(presence is not None, "Unable to retrieve fan {} presence".format(i)):
                if self.expect(isinstance(presence, bool), "Fan {} presence appears incorrect".format(i)):
                    self.expect(presence is True, "Fan {} is not present".format(i))

        self.assert_expectations()

    def test_get_model(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fans):
            model = fan.get_model(platform_api_conn, i)

            if self.expect(model is not None, "Unable to retrieve fan {} model".format(i)):
                self.expect(isinstance(model, str), "Fan {} model appears incorrect".format(i))

        self.assert_expectations()

    def test_get_serial(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fans):
            serial = fan.get_serial(platform_api_conn, i)

            if self.expect(serial is not None, "Unable to retrieve fan {} serial number".format(i)):
                self.expect(isinstance(serial, str), "Fan {} serial number appears incorrect".format(i))

        self.assert_expectations()

    def test_get_status(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fans):
            status = fan.get_status(platform_api_conn, i)

            if self.expect(status is not None, "Unable to retrieve fan {} status".format(i)):
                self.expect(isinstance(status, bool), "Fan {} status appears incorrect".format(i))

        self.assert_expectations()

    #
    # Functions to test methods defined in FanBase class
    #

    def test_get_speed(self, duthost, localhost, platform_api_conn):
        # Ensure the fan speed is sane
        for i in range(self.num_fans):
            speed = fan.get_speed(platform_api_conn, i)
            if self.expect(speed is not None, "Unable to retrieve Fan {} speed".format(i)):
                if self.expect(isinstance(speed, int), "Fan {} speed appears incorrect".format(i)):
                    self.expect(speed > 0 and speed <= 100,
                                "Fan {} speed {} reading is not within range".format(i, speed))
        self.assert_expectations()

    def test_get_direction(self, duthost, localhost, platform_api_conn):
        # Ensure the fan speed is sane
        FAN_DIRECTION_LIST = [
            "intake",
            "exhaust",
            "N/A",
        ]
        for i in range(self.num_fans):
            direction = fan.get_direction(platform_api_conn, i)
            if self.expect(direction is not None, "Unable to retrieve Fan {} direction".format(i)):
                self.expect(direction in FAN_DIRECTION_LIST, "Fan {} direction is not one of predefined directions".format(i))

        self.assert_expectations()

    def test_get_fans_target_speed(self, duthost, localhost, platform_api_conn):

        for i in range(self.num_fans):
            speed_target_val = 25
            speed_set = fan.set_speed(platform_api_conn, i, speed_target_val)
            target_speed = fan.get_target_speed(platform_api_conn, i)
            if self.expect(target_speed is not None, "Unable to retrieve Fan {} target speed".format(i)):
                if self.expect(isinstance(target_speed, int), "Fan {} target speed appears incorrect".format(i)):
                    self.expect(target_speed == speed_target_val, "Fan {} target speed setting is not correct, speed_target_val {} target_speed = {}".format(
                        i, speed_target_val, target_speed))

        self.assert_expectations()

    def test_get_fans_speed_tolerance(self, duthost, localhost, platform_api_conn):

        for i in range(self.num_fans):
            speed_tol = fan.get_speed_tolerance(platform_api_conn, i)
            if self.expect(speed_tol is not None, "Unable to retrieve Fan {} speed tolerance".format(i)):
                if self.expect(isinstance(speed_tol, int), "Fan {} speed tolerance appears incorrect".format(i)):
                    self.expect(speed_tol > 0 and speed_tol <= 100, "Fan {} speed tolerance {} reading does not make sense".format(i, speed_tol))

        self.assert_expectations()

    def test_set_fans_speed(self, duthost, localhost, platform_api_conn):

        target_speed = random.randint(1, 100)

        for i in range(self.num_fans):
            speed = fan.get_speed(platform_api_conn, i)
            speed_tol = fan.get_speed_tolerance(platform_api_conn, i)

            led_status = fan.get_status_led(platform_api_conn, i)
            speed_set = fan.set_speed(platform_api_conn, i, target_speed)
            time.sleep(5)

            act_speed = fan.get_speed(platform_api_conn, i)
            self.expect(abs(act_speed - target_speed) <= speed_tol,
                        "Fan {} speed change from {} to {} is not within tolerance, actual speed {}".format(i, speed, target_speed, act_speed))

        self.assert_expectations()

    def test_set_fans_led(self, duthost, localhost, platform_api_conn):
        LED_COLOR_LIST = [
            "off",
            "red",
            "amber",
            "green",
        ]

        for i in range(self.num_fans):
            for color in LED_COLOR_LIST:

                result = fan.set_status_led(platform_api_conn, i, color)
                if self.expect(result is not None, "Failed to perform set_status_led"):
                    self.expect(result is True, "Failed to set status_led for fan {} to {}".format(i, color))

                color_actual = fan.get_status_led(platform_api_conn, i)

                if self.expect(color_actual is not None, "Failed to retrieve status_led"):
                    if self.expect(isinstance(color_actual, str), "Status LED color appears incorrect"):
                        self.expect(color == color_actual, "Status LED color incorrect (expected: {}, actual: {} for fan {})".format(
                            color, color_actual, i))

        self.assert_expectations()
