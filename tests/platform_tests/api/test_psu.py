import logging
import pytest

from tests.common.helpers.platform_api import psu
from tests.common.mellanox_data import is_mellanox_device
from tests.common.utilities import skip_release_for_platform, wait_until
from tests.common.platform.device_utils import platform_api_conn, start_platform_api_service    # noqa: F401
from .power_api_test_base import TestPowerApi, STRING_TYPE


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]

STATUS_LED_COLOR_GREEN = "green"
STATUS_LED_COLOR_AMBER = "amber"
STATUS_LED_COLOR_RED = "red"
STATUS_LED_COLOR_OFF = "off"


class TestPsuApi(TestPowerApi):
    ''' Platform API test cases for the PSU class'''

    power_unit_api = psu
    power_unit_label = "PSU"
    facts_key = "psus"

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

    def get_psu_parameter(self, psu_info, psu_parameter, get_data, message):
        data = None
        is_supported = self.get_psu_facts(psu_info["duthost"], psu_info["psu_id"], True, psu_parameter)
        if is_supported:
            data = get_data(psu_info["api"], psu_info["psu_id"])
            if not is_mellanox_device(self.duthost):
                if self.expect(
                        data is not None, f"Failed to retrieve {message} of PSU {psu_info['psu_id']}"):
                    self.expect(
                        isinstance(data, float), f"PSU {psu_info['psu_id']} {message} appears incorrect")

        return data

    #
    # Functions to test methods inherited from DeviceBase class
    #

    def test_get_position_in_parent(self, platform_api_conn):     # noqa: F811
        for device_id in range(self.num_power_units):
            if self._skip_absent_power_unit(device_id, platform_api_conn):
                continue
            position = self.power_unit_api.get_position_in_parent(platform_api_conn, device_id)
            if self.expect(position is not None,
                           f"Failed to perform get_position_in_parent for {self.power_unit_label} {device_id}"):
                self.expect(isinstance(position, int),
                            f"Position value must be an integer value for {self.power_unit_label} {device_id}")
        self.assert_expectations()

    def test_is_replaceable(self, platform_api_conn):     # noqa: F811
        for device_id in range(self.num_power_units):
            if self._skip_absent_power_unit(device_id, platform_api_conn):
                continue
            replaceable = self.power_unit_api.is_replaceable(platform_api_conn, device_id)
            if self.expect(replaceable is not None,
                           f"Failed to perform is_replaceable for {self.power_unit_label} {device_id}"):
                self.expect(isinstance(replaceable, bool),
                            f"Replaceable value must be a bool value for {self.power_unit_label} {device_id}")
        self.assert_expectations()

    #
    # Functions to test methods defined in PsuBase class
    #

    def test_fans(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):    # noqa: F811
        ''' PSU fan test '''
        for psu_id in range(self.num_power_units):
            try:
                num_fans = int(psu.get_num_fans(platform_api_conn, psu_id))
            except Exception:
                pytest.fail("num_fans is not an integer!")

            fan_list = psu.get_all_fans(platform_api_conn, psu_id)
            if self.expect(fan_list is not None, f"Failed to retrieve fans of PSU {psu_id}"):
                self.expect(isinstance(fan_list, list) and len(fan_list) == num_fans,
                            f"Fans of PSU {psu_id} appear to be incorrect")

            for i in range(num_fans):
                fan = psu.get_fan(platform_api_conn, psu_id, i)
                if self.expect(fan is not None, f"Failed to retrieve fan {i} of PSU {psu_id}"):
                    self.expect(fan and fan == fan_list[i], f"Fan {i} of PSU {psu_id} is incorrect")
        self.assert_expectations()

    def test_power(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):   # noqa: F811
        ''' PSU power test '''
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012", "201911", "201811"], ["arista"])
        voltage = current = power = None
        self.duthost = duthost
        psu_info = {
            "duthost": duthost,
            "api": platform_api_conn,
            "psu_id": None
        }

        def check_psu_power(failure_count):
            nonlocal voltage
            nonlocal current
            nonlocal power
            voltage = self.get_psu_parameter(psu_info, "voltage", psu.get_voltage, "voltage")
            current = self.get_psu_parameter(psu_info, "current", psu.get_current, "current")
            power = self.get_psu_parameter(psu_info, "power", psu.get_power, "power")

            failure_occured = self.get_len_failed_expectations() > failure_count
            if is_mellanox_device(self.duthost):
                logger.info("Skipping power value validation for Mellanox device")
                return True
            if current and voltage and power:
                is_within_tolerance = abs(power - (voltage*current)) < power*0.1
                if not failure_occured and not is_within_tolerance:
                    return False

                self.expect(is_within_tolerance,
                            f"PSU {psu_id} reading does not make sense "
                            f"(power:{power}, voltage:{voltage}, current:{current})")

            return True

        for psu_id in range(self.num_power_units):
            failure_count = self.get_len_failed_expectations()
            psu_info['psu_id'] = psu_id
            name = psu.get_name(platform_api_conn, psu_id)
            if name in self.power_unit_skip_list:
                logger.info(f"skipping check for {name}")
            else:
                check_result = wait_until(30, 10, 0, check_psu_power, failure_count)
                self.expect(check_result,
                            f"PSU {psu_id} reading does not make sense "
                            f"(power:{power}, voltage:{voltage}, current:{current})")

                self.get_psu_parameter(psu_info, "max_power", psu.get_maximum_supplied_power,
                                       "maximum supplied power")

                powergood_status = psu.get_powergood_status(platform_api_conn, psu_id)
                if self.expect(powergood_status is not None,
                               f"Failed to retrieve operational status of PSU {psu_id}"):
                    self.expect(powergood_status is True, f"PSU {psu_id} is not operational")

                high_threshold = self.get_psu_parameter(psu_info, "voltage_high_threshold",
                                                        psu.get_voltage_high_threshold, "high voltage threshold")
                low_threshold = self.get_psu_parameter(psu_info, "voltage_low_threshold",
                                                       psu.get_voltage_low_threshold, "low voltage threshold")

                if not is_mellanox_device(self.duthost):
                    if high_threshold and low_threshold:
                        self.expect(voltage < high_threshold and voltage > low_threshold,
                                    f"Voltage {voltage} of PSU {psu_id} is not in between "
                                    f"{low_threshold} and {high_threshold}")

        self.assert_expectations()

    def test_temperature(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):   # noqa: F811
        ''' PSU temperature test '''
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012", "201911", "201811"], ["arista"])
        psus_skipped = 0

        for psu_id in range(self.num_power_units):
            name = psu.get_name(platform_api_conn, psu_id)
            if name in self.power_unit_skip_list:
                logger.info(f"skipping check for {name}")
            else:
                temperature_supported = self.get_psu_facts(duthost, psu_id, True, "temperature")
                if not temperature_supported:
                    logger.info(f"test_set_fans_speed: Skipping chassis fan {psu_id} (speed not controllable)")
                    psus_skipped += 1
                    continue

                temperature = psu.get_temperature(platform_api_conn, psu_id)
                if self.expect(temperature is not None, f"Failed to retrieve temperature of PSU {psu_id}"):
                    self.expect(isinstance(temperature, float), f"PSU {psu_id} temperature appears incorrect")

                temp_threshold = psu.get_temperature_high_threshold(platform_api_conn, psu_id)
                if self.expect(temp_threshold is not None,
                               f"Failed to retrieve temperature threshold of PSU {psu_id}"):
                    if self.expect(isinstance(temp_threshold, float),
                                   f"PSU {psu_id} temperature high threshold appears incorrect"):
                        self.expect(temperature < temp_threshold,
                                    f"Temperature {temperature} of PSU {psu_id} is over the "
                                    f"threshold {temp_threshold}")

        if psus_skipped == self.num_power_units:
            pytest.skip("skipped as all chassis psus' temperature sensor is not supported")

        self.assert_expectations()

    @pytest.mark.disable_loganalyzer
    def test_led(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):     # noqa: F811
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
        for psu_id in range(self.num_power_units):
            if self._skip_absent_power_unit(psu_id, platform_api_conn):
                continue
            name = psu.get_name(platform_api_conn, psu_id)
            led_support = duthost.facts.get("chassis").get("psus")[psu_id].get("led")
            if led_support == "N/A":
                logger.info(f"led not supported for this psu {name}")
            elif name in self.power_unit_skip_list:
                logger.info(f"skipping check for {name}")
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
                                logger.warning(
                                    f"test_status_led: Skipping PSU {psu_id} set status_led to "
                                    f"{LED_COLOR_TYPES_DICT[index]} (No supported colors)"
                                )
                                led_type_skipped += 1
                                continue

                        led_type_result = False
                        for color in led_type:
                            result = psu.set_status_led(platform_api_conn, psu_id, color)
                            if self.expect(result is not None,
                                           f"Failed to perform set_status_led of PSU {psu_id}"):
                                led_type_result = result or led_type_result
                            if ((result is None) or (not result)):
                                continue
                            color_actual = psu.get_status_led(platform_api_conn, psu_id)
                            if self.expect(color_actual is not None,
                                           f"Failed to retrieve status_led of PSU {psu_id}"):
                                if self.expect(isinstance(color_actual, STRING_TYPE),
                                               f"PSU {psu_id} status LED color appears incorrect"):
                                    self.expect(color == color_actual,
                                                f"Status LED color incorrect (expected: {color}, "
                                                f"actual: {color_actual}) from PSU {psu_id}")
                        self.expect(led_type_result is True,
                                    f"Failed to set status_led of PSU {psu_id} to "
                                    f"{LED_COLOR_TYPES_DICT[index]}")

                    if led_type_skipped == len(LED_COLOR_TYPES):
                        logger.info(f"test_status_led: Skipping PSU {psu_id} "
                                    "(no supported colors for all types)")
                        psus_skipped += 1

                else:
                    logger.info(f"test_status_led: Skipping PSU {psu_id} (LED is not controllable)")
                    psus_skipped += 1

        if psus_skipped == self.num_power_units:
            pytest.skip("skipped as all PSUs' LED is not controllable/no supported colors/in skip list")

        self.assert_expectations()

    @pytest.mark.disable_loganalyzer
    def test_master_led(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa: F811
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
        if self.num_power_units == 0:
            pytest.skip(f"No psus found on device skipping for device {duthost}")

        supported_colors = duthost.facts.get("chassis").get("master_psu_led_color")
        if supported_colors:
            for index, colors in enumerate(LED_COLOR_TYPES):
                for color in colors:
                    if color not in supported_colors:
                        LED_COLOR_TYPES[index].remove(color)

        for psu_id in range(self.num_power_units):
            name = psu.get_name(platform_api_conn, psu_id)
            if name in self.power_unit_skip_list:
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
                                        f"Status LED color incorrect (expected: {color}, "
                                        f"actual: {color_actual}) for master led")
                    self.expect(led_type_result is True,
                                f"Failed to set status_led of master LED to {LED_COLOR_TYPES_DICT[index]}")

            self.assert_expectations()
