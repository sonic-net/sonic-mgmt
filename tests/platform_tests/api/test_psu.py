import logging
import re
import pytest
import yaml

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import chassis, psu
from tests.common.utilities import skip_release
from tests.platform_tests.cli.util import get_skip_mod_list
from platform_api_test_base import PlatformApiTestBase
from tests.common.utilities import skip_release_for_platform


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
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer  # disable automatic loganalyzer
]

STATUS_LED_COLOR_GREEN = "green"
STATUS_LED_COLOR_AMBER = "amber"
STATUS_LED_COLOR_RED = "red"
STATUS_LED_COLOR_OFF = "off"


class TestPsuApi(PlatformApiTestBase):
    ''' Platform API test cases for the PSU class'''

    num_psus = None
    chassis_facts = None

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, platform_api_conn, duthosts, enum_rand_one_per_hwsku_hostname):
        if self.num_psus is None:
            try:
                self.num_psus = int(chassis.get_num_psus(platform_api_conn))
            except:
                pytest.fail("num_psus is not an integer")
            else:
                if self.num_psus == 0:
                    pytest.skip("No psus found on device")

        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        self.psu_skip_list = get_skip_mod_list(duthost, ['psus'])

    def compare_value_with_platform_facts(self, duthost, key, value, psu_idx):
        expected_value = None
        if duthost.facts.get("chassis"):
            expected_psus = duthost.facts.get("chassis").get("psus")
            if expected_psus:
                expected_value = expected_psus[psu_idx].get(key)

        if self.expect(expected_value is not None,
                      "Unable to get expected value for '{}' from platform.json file for PSU {}".format(key, psu_idx)):
            self.expect(value == expected_value,
                      "'{}' value is incorrect. Got '{}', expected '{}' for PSU {}".format(key, value, expected_value, psu_idx))

    def get_psu_facts(self, duthost, psu_idx, def_value, *keys):
        if duthost.facts.get("chassis"):
            psus = duthost.facts.get("chassis").get("psus")
            if psus:
                value = psus[psu_idx]
                for key in keys:
                    value = value.get(key)
                    if value is None:
                        return def_value

                return value

        return def_value

    def skip_absent_psu(self, psu_num, platform_api_conn):
        name = psu.get_name(platform_api_conn, psu_num)
        if name in self.psu_skip_list:
            logger.info("Skipping PSU {} since it is part of psu_skip_list".format(name))
            return True
        return False

    #
    # Functions to test methods inherited from DeviceBase class
    #

    def test_get_name(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        for i in range(self.num_psus):
            if self.skip_absent_psu(i,platform_api_conn):
                continue
            name = psu.get_name(platform_api_conn, i)
            if self.expect(name is not None, "Unable to retrieve PSU {} name".format(i)):
                self.expect(isinstance(name, STRING_TYPE), "PSU {} name appears incorrect".format(i))
                self.compare_value_with_platform_facts(duthost, 'name', name, i)
        self.assert_expectations()

    def test_get_presence(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        for i in range(self.num_psus):
            presence = psu.get_presence(platform_api_conn, i)
            name = psu.get_name(platform_api_conn, i)
            if self.expect(presence is not None, "Unable to retrieve PSU {} presence".format(i)):
                if self.expect(isinstance(presence, bool), "PSU {} presence appears incorrect".format(i)):
                    if name in self.psu_skip_list:
                        self.expect(presence is False,
                                    "PSU {} in skip_modules inventory got presence True expected False".format(i))
                    else:
                        self.expect(presence is True, "PSU {} is not present".format(i))
        self.assert_expectations()

    def test_get_model(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        for i in range(self.num_psus):
            if self.skip_absent_psu(i,platform_api_conn):
                continue
            model = psu.get_model(platform_api_conn, i)
            if self.expect(model is not None, "Unable to retrieve PSU {} model".format(i)):
                self.expect(isinstance(model, STRING_TYPE), "PSU {} model appears incorrect".format(i))
        self.assert_expectations()

    def test_get_serial(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        for i in range(self.num_psus):
            if self.skip_absent_psu(i,platform_api_conn):
                continue
            serial = psu.get_serial(platform_api_conn, i)
            if self.expect(serial is not None, "Unable to retrieve PSU {} serial number".format(i)):
                self.expect(isinstance(serial, STRING_TYPE), "PSU {} serial number appears incorrect".format(i))
        self.assert_expectations()

    def test_get_revision(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release(duthost, ["201811", "201911", "202012"])
        for i in range(self.num_psus):
            if self.skip_absent_psu(i,platform_api_conn):
                continue
            revision = psu.get_revision(platform_api_conn, i)
            if self.expect(revision is not None, "Unable to retrieve PSU {} serial number".format(i)):
                self.expect(isinstance(revision, STRING_TYPE), "PSU {} serial number appears incorrect".format(i))
        self.assert_expectations()

    def test_get_status(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        for i in range(self.num_psus):
            if self.skip_absent_psu(i,platform_api_conn):
                continue
            status = psu.get_status(platform_api_conn, i)
            if self.expect(status is not None, "Unable to retrieve PSU {} status".format(i)):
                self.expect(isinstance(status, bool), "PSU {} status appears incorrect".format(i))
        self.assert_expectations()

    def test_get_position_in_parent(self, platform_api_conn):
        for psu_id in range(self.num_psus):
            if self.skip_absent_psu(psu_id,platform_api_conn):
                continue
            position = psu.get_position_in_parent(platform_api_conn, psu_id)
            if self.expect(position is not None, "Failed to perform get_position_in_parent for psu id {}".format(psu_id)):
                self.expect(isinstance(position, int), "Position value must be an integer value for psu id {}".format(psu_id))
        self.assert_expectations()

    def test_is_replaceable(self, platform_api_conn):
        for psu_id in range(self.num_psus):
            if self.skip_absent_psu(psu_id,platform_api_conn):
                continue
            replaceable = psu.is_replaceable(platform_api_conn, psu_id)
            if self.expect(replaceable is not None, "Failed to perform is_replaceable for psu id {}".format(psu_id)):
                self.expect(isinstance(replaceable, bool), "Replaceable value must be a bool value for psu id {}".format(psu_id))
        self.assert_expectations()

    #
    # Functions to test methods defined in PsuBase class
    #

    def test_fans(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        ''' PSU fan test '''
        for psu_id in range(self.num_psus):
            try:
                num_fans = int(psu.get_num_fans(platform_api_conn, psu_id))
            except:
                pytest.fail("num_fans is not an integer!")

            fan_list = psu.get_all_fans(platform_api_conn, psu_id)
            if self.expect(fan_list is not None, "Failed to retrieve fans of PSU {}".format(psu_id)):
                self.expect(isinstance(fan_list, list) and len(fan_list) == num_fans, "Fans of PSU {} appear to be incorrect".format(psu_id))

            for i in range(num_fans):
                fan = psu.get_fan(platform_api_conn, psu_id, i)
                if self.expect(fan is not None, "Failed to retrieve fan {} of PSU {}".format(i, psu_id)):
                    self.expect(fan and fan == fan_list[i], "Fan {} of PSU {} is incorrect".format(i, psu_id))
        self.assert_expectations()

    def test_power(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        ''' PSU power test '''
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012", "201911", "201811"], ["arista"])

        for psu_id in range(self.num_psus):
            name = psu.get_name(platform_api_conn, psu_id)
            if name in self.psu_skip_list:
                logger.info("skipping check for {}".format(name))
            else:
                voltage = None
                voltage_supported = self.get_psu_facts(duthost, psu_id, True, "voltage")
                if voltage_supported:
                    voltage = psu.get_voltage(platform_api_conn, psu_id)
                    if self.expect(voltage is not None, "Failed to retrieve voltage of PSU {}".format(psu_id)):
                        self.expect(isinstance(voltage, float), "PSU {} voltage appears incorrect".format(psu_id))
                current = None
                current_supported = self.get_psu_facts(duthost, psu_id, True, "current")
                if current_supported:
                    current = psu.get_current(platform_api_conn, psu_id)
                    if self.expect(current is not None, "Failed to retrieve current of PSU {}".format(psu_id)):
                        self.expect(isinstance(current, float), "PSU {} current appears incorrect".format(psu_id))
                power = None
                power_supported = self.get_psu_facts(duthost, psu_id, True, "power")
                if power_supported:
                    power = psu.get_power(platform_api_conn, psu_id)
                    if self.expect(power is not None, "Failed to retrieve power of PSU {}".format(psu_id)):
                        self.expect(isinstance(power, float), "PSU {} power appears incorrect".format(psu_id))
                max_supp_power = None
                max_power_supported = self.get_psu_facts(duthost, psu_id, True, "max_power")
                if max_power_supported:
                    max_supp_power = psu.get_maximum_supplied_power(platform_api_conn, psu_id)
                    if self.expect(max_supp_power is not None,
                                   "Failed to retrieve maximum supplied power power of PSU {}".format(psu_id)):
                        self.expect(isinstance(max_supp_power, float), "PSU {} maximum supplied power appears incorrect".format(psu_id))

                if current is not None and voltage is not None and power is not None:
                    self.expect(abs(power - (voltage*current)) < power*0.1, "PSU {} reading does not make sense \
                        (power:{}, voltage:{}, current:{})".format(psu_id, power, voltage, current))

                powergood_status = psu.get_powergood_status(platform_api_conn, psu_id)
                if self.expect(powergood_status is not None, "Failed to retrieve operational status of PSU {}".format(psu_id)):
                    self.expect(powergood_status is True, "PSU {} is not operational".format(psu_id))

                high_threshold = None
                voltage_high_threshold_supported = self.get_psu_facts(duthost, psu_id, True, "voltage_high_threshold")
                if voltage_high_threshold_supported:
                    high_threshold = psu.get_voltage_high_threshold(platform_api_conn, psu_id)
                    if self.expect(high_threshold is not None, "Failed to retrieve the high voltage threshold of PSU {}".format(psu_id)):
                        self.expect(isinstance(high_threshold, float), "PSU {} voltage high threshold appears incorrect".format(psu_id))
                low_threshold = None
                voltage_low_threshold_supported = self.get_psu_facts(duthost, psu_id, True, "voltage_low_threshold")
                if voltage_low_threshold_supported:
                    low_threshold = psu.get_voltage_low_threshold(platform_api_conn, psu_id)
                    if self.expect(low_threshold is not None, "Failed to retrieve the low voltage threshold of PSU {}".format(psu_id)):
                        self.expect(isinstance(low_threshold, float), "PSU {} voltage low threshold appears incorrect".format(psu_id))
                if high_threshold is not None and low_threshold is not None:
                    self.expect(voltage < high_threshold and voltage > low_threshold,
                                "Voltage {} of PSU {} is not in between {} and {}".format(voltage, psu_id,
                                                                                          low_threshold,
                                                                                          high_threshold))
        self.assert_expectations()

    def test_temperature(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        ''' PSU temperature test '''
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012", "201911", "201811"], ["arista"])
        psus_skipped = 0

        for psu_id in range(self.num_psus):
            name = psu.get_name(platform_api_conn, psu_id)
            if name in self.psu_skip_list:
               logger.info("skipping check for {}".format(name))
            else:
                temperature_supported = self.get_psu_facts(duthost, psu_id, True, "temperature")
                if not temperature_supported:
                    logger.info("test_set_fans_speed: Skipping chassis fan {} (speed not controllable)".format(psu_id))
                    psus_skipped += 1
                    continue

                temperature = psu.get_temperature(platform_api_conn, psu_id)
                if self.expect(temperature is not None, "Failed to retrieve temperature of PSU {}".format(psu_id)):
                    self.expect(isinstance(temperature, float), "PSU {} temperature appears incorrect".format(psu_id))

                temp_threshold = psu.get_temperature_high_threshold(platform_api_conn, psu_id)
                if self.expect(temp_threshold is not None,
                               "Failed to retrieve temperature threshold of PSU {}".format(psu_id)):
                    if self.expect(isinstance(temp_threshold, float),
                                   "PSU {} temperature high threshold appears incorrect".format(psu_id)):
                        self.expect(temperature < temp_threshold,
                                    "Temperature {} of PSU {} is over the threshold {}".format(temperature, psu_id,
                                                                                               temp_threshold))

        if psus_skipped == self.num_psus:
            pytest.skip("skipped as all chassis psus' temperature sensor is not supported")

        self.assert_expectations()

    def test_led(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        ''' PSU status led test '''
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

        psus_skipped = 0
        for psu_id in range(self.num_psus):
            if self.skip_absent_psu(psu_id,platform_api_conn):
                continue
            name = psu.get_name(platform_api_conn, psu_id)
            led_support = duthost.facts.get("chassis").get("psus")[psu_id].get("led")
            if led_support == "N/A":
                logger.info("led not supported for this psu {}".format(name))
            elif name in self.psu_skip_list:
                logger.info("skipping check for {}".format(name))
                psus_skipped += 1
            else:
                led_controllable = self.get_psu_facts(duthost, psu_id, True, "status_led", "controllable")
                led_supported_colors = self.get_psu_facts(duthost, psu_id, None, "status_led", "colors")

                if led_controllable:
                    led_type_skipped = 0
                    for index, led_type in enumerate(LED_COLOR_TYPES):
                        if led_supported_colors:
                            led_type = set(led_type) & set(led_supported_colors)
                            if not led_type:
                                logger.warning("test_status_led: Skipping PSU {} set status_led to {} (No supported colors)".format(psu_id, LED_COLOR_TYPES_DICT[index]))
                                led_type_skipped += 1
                                continue

                        led_type_result = False
                        for color in led_type:
                            result = psu.set_status_led(platform_api_conn, psu_id, color)
                            if self.expect(result is not None, "Failed to perform set_status_led of PSU {}".format(psu_id)):
                                led_type_result = result or led_type_result
                            if ((result is None) or (not result)):
                                continue
                            color_actual = psu.get_status_led(platform_api_conn, psu_id)
                            if self.expect(color_actual is not None,
                                           "Failed to retrieve status_led of PSU {}".format(psu_id)):
                                if self.expect(isinstance(color_actual, STRING_TYPE),
                                               "PSU {} status LED color appears incorrect".format(psu_id)):
                                    self.expect(color == color_actual,
                                                "Status LED color incorrect (expected: {}, actual: {}) from PSU {}".format(
                                                    color, color_actual, psu_id))
                        self.expect(led_type_result is True,
                                    "Failed to set status_led of PSU {} to {}".format(psu_id, LED_COLOR_TYPES_DICT[index]))

                    if led_type_skipped == len(LED_COLOR_TYPES):
                        logger.info("test_status_led: Skipping PSU {} (no supported colors for all types)".format(psu_id))
                        psus_skipped += 1

                else:
                    logger.info("test_status_led: Skipping PSU {} (LED is not controllable)".format(psu_id))
                    psus_skipped += 1

        if psus_skipped == self.num_psus:
            pytest.skip("skipped as all PSUs' LED is not controllable/no supported colors/in skip list")

        self.assert_expectations()

    def test_thermals(self, platform_api_conn):
        for psu_id in range(self.num_psus):
            if self.skip_absent_psu(psu_id,platform_api_conn):
                continue
            try:
                num_thermals = int(psu.get_num_thermals(platform_api_conn, psu_id))
            except Exception:
                pytest.fail("PSU {}: num_thermals is not an integer".format(psu_id))

            thermal_list = psu.get_all_thermals(platform_api_conn, psu_id)
            pytest_assert(thermal_list is not None, "Failed to retrieve thermals for psu {}".format(psu_id))
            pytest_assert(isinstance(thermal_list, list) and len(thermal_list) == num_thermals, "Thermals appear to be incorrect for psu {}".format(psu_id))

            for i in range(num_thermals):
                thermal = psu.get_thermal(platform_api_conn, psu_id, i)
                self.expect(thermal and thermal == thermal_list[i], "Thermal {} is incorrect for psu {}".format(i, psu_id))

        self.assert_expectations()

    def test_master_led(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
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
        LED_COLOR_TYPES.append(OFF_LED_COLOR_LIST)

        LED_COLOR_TYPES_DICT = {
            0: "fault",
            1: "normal",
            2: "off"
        }
        supported_colors = []
        if self.num_psus == 0:
            pytest.skip("No psus found on device skipping for device {}".format(duthost))

        supported_colors = duthost.facts.get("chassis").get("master_psu_led_color")
        if supported_colors:
            for index, colors in enumerate(LED_COLOR_TYPES):
                for color in colors:
                    if color not in supported_colors:
                        LED_COLOR_TYPES[index].remove(color)

        for psu_id in range(self.num_psus):
            name = psu.get_name(platform_api_conn, psu_id)
            if name in self.psu_skip_list:
                continue
            for index, led_type in enumerate(LED_COLOR_TYPES):
                led_type_result = False
                for color in led_type:
                    result = psu.set_status_master_led(platform_api_conn, psu_id, color)
                    if self.expect(result is not None, "Failed to perform set master LED"):
                        led_type_result = result or led_type_result
                    if ((result is None) or (not result)):
                        continue
                    color_actual = psu.get_status_master_led(platform_api_conn, psu_id)
                    if self.expect(color_actual is not None,
                                   "Failed to retrieve status_led master led"):
                        if self.expect(isinstance(color_actual, STRING_TYPE),
                                       "Status of master LED color appears incorrect"):
                            self.expect(color == color_actual,
                                        "Status LED color incorrect (expected: {}, actual: {}) for master led".format(
                                            color, color_actual))
                    self.expect(led_type_result is True,
                                "Failed to set status_led of master LED to {}".format(LED_COLOR_TYPES_DICT[index]))

            self.assert_expectations()
