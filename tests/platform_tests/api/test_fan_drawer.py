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


@pytest.fixture(scope="class")
def gather_facts(request, duthost):
    # Get platform facts from platform.json file
    request.cls.chassis_facts = duthost.facts.get("chassis")
    request.cls.asic_type = duthost.facts.get("asic_type")


@pytest.mark.usefixtures("gather_facts")
class TestFanDrawerApi(PlatformApiTestBase):

    num_fan_drawers = None
    chassis_facts = None

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

    #
    # Helper functions
    #

    def compare_value_with_platform_facts(self, key, value, fan_drawer_idx):
        expected_value = None

        if self.chassis_facts:
            expected_fan_drawers = self.chassis_facts.get("fan_drawers")
            if expected_fan_drawers:
                expected_value = expected_fan_drawers[fan_drawer_idx].get(key)
                if key == "num_fans" and not expected_value:
                    expected_value = len(expected_fan_drawers[fan_drawer_idx].get("fans"))

        if self.expect(expected_value is not None,
                       "Unable to get expected value for '{}' from platform.json file for fan drawer {}".format(key, fan_drawer_idx)):
            self.expect(value == expected_value,
                        "'{}' value is incorrect. Got '{}', expected '{}' for fan drawer {}".format(key, value, expected_value, fan_drawer_idx))

    #
    # Functions to test methods inherited from DeviceBase class
    #
    def test_get_name(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):
            name = fan_drawer.get_name(platform_api_conn, i)

            if self.expect(name is not None, "Unable to retrieve Fan_drawer {} name".format(i)):
                self.expect(isinstance(name, STRING_TYPE), "Fan_drawer {} name appears incorrect".format(i))
                self.compare_value_with_platform_facts('name', name, i)

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

    def test_get_position_in_parent(self, platform_api_conn):
        for i in range(self.num_fan_drawers):
            position = fan_drawer.get_position_in_parent(platform_api_conn, i)
            if self.expect(position is not None, "Failed to perform get_position_in_parent for fan drawer {}".format(i)):
                self.expect(isinstance(position, int), "Position value must be an integer value for fan drawer {}".format(i))
        self.assert_expectations()

    def test_is_replaceable(self, platform_api_conn):
        for i in range(self.num_fan_drawers):
            replaceable = fan_drawer.is_replaceable(platform_api_conn, i)
            if self.expect(replaceable is not None, "Failed to perform is_replaceable for fan drawer {}".format(i)):
                self.expect(isinstance(replaceable, bool), "Replaceable value must be a bool value for fan drawer {}".format(i))
        self.assert_expectations()

    #
    # Functions to test methods defined in Fan_drawerBase class
    #
    def test_get_num_fans(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):

            num_fans = fan_drawer.get_num_fans(platform_api_conn, i)
            if self.expect(num_fans is not None, "Unable to retrieve fan_drawer {} number of fans".format(i)):
                self.expect(isinstance(num_fans, int), "fan drawer {} number of fans appear to be incorrect".format(i))
                self.compare_value_with_platform_facts('num_fans', num_fans, i)
        self.assert_expectations()

    def test_get_all_fans(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):

            fans_list = fan_drawer.get_all_fans(platform_api_conn, i)
            if self.expect(fans_list is not None, "Unable to retrieve fan_drawer {} all fans".format(i)):
                self.expect(isinstance(fans_list, list), "fan drawer {} list of fans appear to be incorrect".format(i))
        self.assert_expectations()

    def test_set_fan_drawers_led(self, duthost, localhost, platform_api_conn):

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
        if self.asic_type != "mellanox":
            LED_COLOR_TYPES.append(OFF_LED_COLOR_LIST)

        LED_COLOR_TYPES_DICT = {
            0: "fault",
            1: "normal",
            2: "off"
        }

        for i in range(self.num_fan_drawers):
            for index, led_type in enumerate(LED_COLOR_TYPES):
                led_type_result = False
                for color in led_type:
                    result = fan_drawer.set_status_led(platform_api_conn, i, color)
                    if self.expect(result is not None, "Failed to perform set_status_led"):
                        led_type_result = result or led_type_result
                    if ((result is None) or (not result)):
                        continue
                    color_actual = fan_drawer.get_status_led(platform_api_conn, i)
                    if self.expect(color_actual is not None, "Failed to retrieve status_led"):
                        if self.expect(isinstance(color_actual, STRING_TYPE), "Status LED color appears incorrect"):
                            self.expect(color == color_actual, "Status LED color incorrect (expected: {}, actual: {} for fan_drawer {})".format(
                                color, color_actual, i))
                self.expect(led_type_result is True, "Failed to set status_led for fan_drawer {} to {}".format(i, LED_COLOR_TYPES_DICT[index]))
        self.assert_expectations()
