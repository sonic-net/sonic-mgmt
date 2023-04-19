import logging

import pytest

from tests.common.helpers.platform_api import chassis, fan_drawer

from platform_api_test_base import PlatformApiTestBase

###################################################
# TODO: Remove this after we transition to Python 3
import sys
if sys.version_info.major >= 3:
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
    chassis_facts = None

    # This fixture would probably be better scoped at the class level, but
    # it relies on the platform_api_conn fixture, which is scoped at the function
    # level, so we must do the same here to prevent a scope mismatch.
    @pytest.fixture(scope="function", autouse=True)
    def setup(self, duthost, platform_api_conn):
        if self.num_fan_drawers is None:
            try:
                self.num_fan_drawers = int(chassis.get_num_fan_drawers(platform_api_conn))
            except Exception:
                pytest.fail("num_fan_drawers is not an integer")
            else:
                if self.num_fan_drawers == 0:
                    pytest.skip("No fan drawers found on device")

    #
    # Helper functions
    #

    def compare_value_with_platform_facts(self, duthost, key, value, fan_drawer_idx):
        expected_value = None

        if duthost.facts.get("chassis"):
            expected_fan_drawers = duthost.facts.get("chassis").get("fan_drawers")
            if expected_fan_drawers:
                expected_value = expected_fan_drawers[fan_drawer_idx].get(key)
                if key == "num_fans" and not expected_value:
                    expected_value = len(expected_fan_drawers[fan_drawer_idx].get("fans"))

        if self.expect(expected_value is not None,
                       "Unable to get expected value for '{}' from platform.json file for fan drawer {}"
                       .format(key, fan_drawer_idx)):
            self.expect(value == expected_value,
                        "'{}' value is incorrect. Got '{}', expected '{}' for fan drawer {}"
                        .format(key, value, expected_value, fan_drawer_idx))

    def get_fan_drawer_facts(self, duthost, fan_drawer_idx, def_value, *keys):
        if duthost.facts.get("chassis"):
            fan_drawers = duthost.facts.get("chassis").get("fan_drawers")
            if fan_drawers:
                value = fan_drawers[fan_drawer_idx]
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
        for i in range(self.num_fan_drawers):
            name = fan_drawer.get_name(platform_api_conn, i)

            if self.expect(name is not None, "Unable to retrieve Fan_drawer {} name".format(i)):
                self.expect(isinstance(name, STRING_TYPE), "Fan_drawer {} name appears incorrect".format(i))
                self.compare_value_with_platform_facts(duthost, 'name', name, i)

        self.assert_expectations()

    def test_get_presence(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):
            presence = fan_drawer.get_presence(platform_api_conn, i)

            if self.expect(presence is not None, "Unable to retrieve fan_drawer {} presence".format(i)):
                if self.expect(isinstance(presence, bool), "Fan_drawer {} presence appears incorrect".format(i)):
                    self.expect(presence is True, "Fan_drawer {} is not present".format(i))

        self.assert_expectations()

    def test_get_model(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):
            model = fan_drawer.get_model(platform_api_conn, i)

            if self.expect(model is not None, "Unable to retrieve fan_drawer {} model".format(i)):
                self.expect(isinstance(model, STRING_TYPE), "Fan_drawer {} model appears incorrect".format(i))

        self.assert_expectations()

    def test_get_serial(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):
            serial = fan_drawer.get_serial(platform_api_conn, i)

            if self.expect(serial is not None, "Unable to retrieve fan_drawer {} serial number".format(i)):
                self.expect(isinstance(serial, STRING_TYPE), "Fan_drawer {} serial number appears incorrect".format(i))

        self.assert_expectations()

    def test_get_status(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):
            status = fan_drawer.get_status(platform_api_conn, i)

            if self.expect(status is not None, "Unable to retrieve fan_drawer {} status".format(i)):
                self.expect(isinstance(status, bool), "Fan_drawer {} status appears incorrect".format(i))

        self.assert_expectations()

    def test_get_position_in_parent(self, platform_api_conn):
        for i in range(self.num_fan_drawers):
            position = fan_drawer.get_position_in_parent(platform_api_conn, i)
            if self.expect(position is not None,
                           "Failed to perform get_position_in_parent for fan drawer {}".format(i)):
                self.expect(isinstance(position, int),
                            "Position value must be an integer value for fan drawer {}".format(i))
        self.assert_expectations()

    def test_is_replaceable(self, platform_api_conn):
        for i in range(self.num_fan_drawers):
            replaceable = fan_drawer.is_replaceable(platform_api_conn, i)
            if self.expect(replaceable is not None, "Failed to perform is_replaceable for fan drawer {}".format(i)):
                self.expect(isinstance(replaceable, bool),
                            "Replaceable value must be a bool value for fan drawer {}".format(i))
        self.assert_expectations()

    #
    # Functions to test methods defined in Fan_drawerBase class
    #
    def test_get_num_fans(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        for i in range(self.num_fan_drawers):

            num_fans = fan_drawer.get_num_fans(platform_api_conn, i)
            if self.expect(num_fans is not None, "Unable to retrieve fan_drawer {} number of fans".format(i)):
                self.expect(isinstance(num_fans, int),
                            "fan drawer {} number of fans appear to be incorrect".format(i))
                self.compare_value_with_platform_facts(duthost, 'num_fans', num_fans, i)
        self.assert_expectations()

    def test_get_all_fans(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        for i in range(self.num_fan_drawers):

            fans_list = fan_drawer.get_all_fans(platform_api_conn, i)
            if self.expect(fans_list is not None, "Unable to retrieve fan_drawer {} all fans".format(i)):
                self.expect(isinstance(fans_list, list),
                            "fan drawer {} list of fans appear to be incorrect".format(i))
        self.assert_expectations()

    def test_set_fan_drawers_led(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
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
        for i in range(self.num_fan_drawers):
            led_controllable = self.get_fan_drawer_facts(duthost, i, True, "status_led", "controllable")
            led_supported_colors = self.get_fan_drawer_facts(duthost, i, None, "status_led", "colors")

            if led_controllable:
                led_type_skipped = 0
                for index, led_type in enumerate(LED_COLOR_TYPES):
                    if led_supported_colors:
                        led_type = set(led_type) & set(led_supported_colors)
                        if not led_type:
                            logger.warning(
                                "test_status_led: Skipping fandrawer {} set status_led to {} (No supported colors)"
                                .format(i, LED_COLOR_TYPES_DICT[index]))
                            led_type_skipped += 1
                            continue

                    led_type_result = False
                    for color in led_type:
                        result = fan_drawer.set_status_led(platform_api_conn, i, color)
                        if self.expect(result is not None, "Failed to perform set_status_led"):
                            led_type_result = result or led_type_result
                        if ((result is None) or (not result)):
                            continue
                        color_actual = fan_drawer.get_status_led(platform_api_conn, i)
                        if self.expect(color_actual is not None, "Failed to retrieve status_led"):
                            if self.expect(isinstance(color_actual, STRING_TYPE),
                                           "Status LED color appears incorrect"):
                                self.expect(color == color_actual,
                                            "Status LED color incorrect (expected: {}, actual: {} for fan_drawer {})"
                                            .format(color, color_actual, i))
                    self.expect(led_type_result is True, "Failed to set status_led for fan_drawer {} to {}"
                                .format(i, LED_COLOR_TYPES_DICT[index]))

                if led_type_skipped == len(LED_COLOR_TYPES):
                    logger.info("test_status_led: Skipping fandrawer {} (no supported colors for all types)".format(i))
                    fan_drawers_skipped += 1

            else:
                logger.info("test_status_led: Skipping fandrawer {} (LED is not controllable)".format(i))
                fan_drawers_skipped += 1

        if fan_drawers_skipped == self.num_fan_drawers:
            pytest.skip("skipped as all fandrawers' LED is not controllable/no supported colors")

        self.assert_expectations()

    def test_get_maximum_consumed_power(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                        localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        max_power_skipped = 0

        for i in range(self.num_fan_drawers):
            max_power_supported = self.get_fan_drawer_facts(duthost, i, True, "max_consumed_power")
            if not max_power_supported:
                logger.info("test_get_maximum_consumed_power: Skipping drawer {} (max power not supported)".format(i))
                max_power_skipped += 1
                continue

            fan_drawer_max_con_power = fan_drawer.get_maximum_consumed_power(platform_api_conn, i)
            if self.expect(fan_drawer_max_con_power is not None, "Unable to retrieve module {} slot id".format(i)):
                self.expect(isinstance(fan_drawer_max_con_power, float),
                            "Module {} max consumed power format appears incorrect ".format(i))

        if max_power_skipped == self.num_fan_drawers:
            pytest.skip("skipped as all chassis fan drawers' max consumed power is not supported")

        self.assert_expectations()
