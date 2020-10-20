import logging
import random
import re
import time

import pytest
import yaml

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import chassis, fan_drawer

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

STATUS_LED_COLOR_GREEN = "green"
STATUS_LED_COLOR_AMBER = "amber"
STATUS_LED_COLOR_RED = "red"
STATUS_LED_COLOR_OFF = "off"


class TestFanDrawerApi(PlatformApiTestBase):

    num_fan_drawers = None
    fan_drawer_truth = None

    # This fixture would probably be better scoped at the class level, but
    # it relies on the platform_api_conn fixture, which is scoped at the function
    # level, so we must do the same here to prevent a scope mismatch.

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, duthost, platform_api_conn):
        if self.num_fan_drawers is None:
            try:
                self.num_fan_drawers = int(chassis.get_num_fan_drawers(platform_api_conn))
            except:
                pytest.fail("num_fan_drawers is not an integer")

        chassis_truth = duthost.facts.get('chassis', None)
        if chassis_truth:
            self.fan_drawer_truth = chassis_truth.get('fan_drawers', None)
            if not self.fan_drawer_truth:
                logger.warning("Unable to get fan_drawer_truth from platform.json, test results will not be comprehensive")
        else:
            logger.warning("Unable to get chassis_truth from platform.json, test results will not be comprehensive")

    #
    # Functions to test methods inherited from DeviceBase class
    #
    def test_get_name(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):
            name = fan_drawer.get_name(platform_api_conn, i)

            if self.expect(name is not None, "Unable to retrieve Fan_drawer {} name".format(i)):
                self.expect(isinstance(name, STRING_TYPE), "Fan_drawer {} name appears incorrect".format(i))
                if self.fan_drawer_truth:
                    self.expect(name == self.fan_drawer_truth[i]['name'], "Fan_drawer {} name does not match, expected name {}".format(i, self.fan_drawer_truth[i]['name']))

        self.assert_expectations()

    def test_get_presence(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):
            presence = fan_drawer.get_presence(platform_api_conn, i)

            if self.expect(presence is not None, "Unable to retrieve fan_drawer {} presence".format(i)):
                if self.expect(isinstance(presence, bool), "Fan_drawer {} presence appears incorrect".format(i)):
                    self.expect(presence is True, "Fan_drawer {} is not present".format(i))

        self.assert_expectations()

    def test_get_model(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):
            model = fan_drawer.get_model(platform_api_conn, i)

            if self.expect(model is not None, "Unable to retrieve fan_drawer {} model".format(i)):
                self.expect(isinstance(model, STRING_TYPE), "Fan_drawer {} model appears incorrect".format(i))

        self.assert_expectations()

    def test_get_serial(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):
            serial = fan_drawer.get_serial(platform_api_conn, i)

            if self.expect(serial is not None, "Unable to retrieve fan_drawer {} serial number".format(i)):
                self.expect(isinstance(serial, STRING_TYPE), "Fan_drawer {} serial number appears incorrect".format(i))

        self.assert_expectations()

    def test_get_status(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):
            status = fan_drawer.get_status(platform_api_conn, i)

            if self.expect(status is not None, "Unable to retrieve fan_drawer {} status".format(i)):
                self.expect(isinstance(status, bool), "Fan_drawer {} status appears incorrect".format(i))

        self.assert_expectations()

    #
    # Functions to test methods defined in Fan_drawerBase class
    #
    def test_get_num_fans(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):

            num_fans = fan_drawer.get_num_fans(platform_api_conn, i)
            if self.expect(num_fans is not None, "Unable to retrieve fan_drawer {} number of fans".format(i)):
                self.expect(isinstance(num_fans, int), "fan drawer {} number of fans appear to be incorrect".format(i))
                if self.fan_drawer_truth:
                    self.expect(name == self.fan_drawer_truth[i]['num_fans'], "Fan_drawer {} num_fans does not match, expected num_fans {}".format(i, self.fan_drawer_truth[i]['num_fans']))
        self.assert_expectations()

    def test_get_all_fans(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):

            fans_list = fan_drawer.get_all_fans(platform_api_conn, i)
            if self.expect(fans_list is not None, "Unable to retrieve fan_drawer {} all fans".format(i)):
                self.expect(isinstance(fans_list, list), "fan drawer {} list of fans appear to be incorrect".format(i))
        self.assert_expectations()

    def test_set_fan_drawers_led(self, duthost, localhost, platform_api_conn):
        LED_COLOR_LIST = [
            "off",
            "red",
            "amber",
            "green",
        ]

        for i in range(self.num_fan_drawers):
            for color in LED_COLOR_LIST:

                result = fan_drawer.set_status_led(platform_api_conn, i, color)
                if self.expect(result is not None, "Failed to perform set_status_led"):
                    self.expect(result is True, "Failed to set status_led for fan_drawer {} to {}".format(i, color))

                color_actual = fan_drawer.get_status_led(platform_api_conn, i)

                if self.expect(color_actual is not None, "Failed to retrieve status_led"):
                    if self.expect(isinstance(color_actual, STRING_TYPE), "Status LED color appears incorrect"):
                        self.expect(color == color_actual, "Status LED color incorrect (expected: {}, actual: {} for fan_drawer {})".format(
                            color, color_actual, i))

        self.assert_expectations()

    def test_get_position_in_parent(self, platform_api_conn):
        for i in range(self.num_fan_drawers):
            position = fan_drawer.get_position_in_parent(platform_api_conn, i)
            self.expect(position is not None, "Failed to perform get_position_in_parent for fan drawer {}".format(i))
            self.expect(isinstance(position, int), "Position value must be an integer value for fan drawer {}".format(i))
        self.assert_expectations()

    def test_is_replaceable(self, platform_api_conn):
        for i in range(self.num_fan_drawers):
            replaceable = fan_drawer.is_replaceable(platform_api_conn, i)
            self.expect(replaceable is not None, "Failed to perform is_replaceable for fan drawer {}".format(i))
            self.expect(isinstance(replaceable, bool), "Replaceable value must be a bool value for fan drawer [}".format(i))
        self.assert_expectations()
