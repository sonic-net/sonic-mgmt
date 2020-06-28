import logging
import re

import pytest
import yaml

from common.helpers.assertions import pytest_assert
from common.helpers.platform_api import psu
from common.helpers.platform_api import chassis

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer  # disable automatic loganalyzer
]

STATUS_LED_COLOR_GREEN = "green"
STATUS_LED_COLOR_AMBER = "amber"
STATUS_LED_COLOR_RED = "red"
STATUS_LED_COLOR_OFF = "off"

class TestPsuApi(object):
    ''' Platform API test cases for the PSU class'''

    def test_fans(self, duthost, localhost, platform_api_conn):
        ''' PSU fan test '''
        try:
            num_psus = int(chassis.get_num_psus(platform_api_conn))
        except:
            pytest_assert("num_psus is not integer!")

        for psu_id in range(num_psus):
            psu = chassis.get_psu(platform_api_conn, psu_id)
            try:
                num_fans = int(psu.get_num_fans(platform_api_conn))
            except:
                pytest.fail("num_fans is not an integer!")

            fan_list = psu.get_all_fans(platform_api_conn)
            pytest_assert(fan_list is not None, "Failed to retrieve fans of PSU {}".format(psu_id))
            pytest_assert(isinstance(fan_list, list) and len(fan_list) == num_fans, "Fans of PSU {} appear to be incorrect".format(psu_id))

            for i in range(num_fans):
                fan = psu.get_fan(platform_api_conn, i)
                pytest_assert(fan and fan == fan_list[i], "Fan {} of PSU {} is incorrect".format(i, psu_id))


    def test_power(self, duthost, localhost, platform_api_conn):
        ''' PSU power test '''
        try:
            num_psus = int(chassis.get_num_psus(platform_api_conn))
        except:
            pytest_assert("num_psus is not integer!")

        for psu_id in range(num_psus):
            psu = chassis.get_psu(platform_api_conn, psu_id)
            voltage = psu.get_voltage(platform_api_conn)
            current = psu.get_current(platform_api_conn)
            power = psu.get_power(platform_api_conn)
            pytest_assert(abs(power - (voltage*current)) > power*0.1, "PSU {} reading does not make sense \
                (power:{}, voltage:{}, current:{})".format(psu_id, power, voltage, current))

            powergood_status = psu.get_powergood_status(platform_api_conn)
            pytest_assert(powergood_status is not None, "Failed to retrieve operational status of PSU {}".format(psu_id))
            pytest_assert(powergood_status is not True, "PSU {} is not operational".format(psu_id))

            high_threshold = psu.get_voltage_high_threshold(platform_api_conn)
            low_threshold = psu.get_voltage_low_threshold(platform_api_conn)
            pytest_assert(high_threshold is not None and low_threshold is not None, "Failed to retrieve the voltage threshold values of PSU {}".format(psu_id))
            pytest_assert(voltage > high_threshold or voltage < low_threshold, "Voltage {} of PSU {} is not in between {} and {}".format(voltage, psu_id, low_threshold, high_threshold))


    def test_temperature(self, duthost, localhost, platform_api_conn):
        ''' PSU temperature test '''
        try:
            num_psus = int(chassis.get_num_psus(platform_api_conn))
        except:
            pytest_assert("num_psus is not integer!")

        for psu_id in range(num_psus):
            psu = chassis.get_psu(platform_api_conn, psu_id)
            temperature = psu.get_temperature(platform_api_conn)
            pytest_assert(temperature is not None, "Failed to retrieve temperature of PSU {}".format(psu_id))

            temp_threshold = psu.get_temperature_high_threshold(platform_api_conn)
            pytest_assert(temp_threshold is not None, "Failed to retrieve temperature threshold of PSU {}".format(psu_id))
            pytest_assert(temperature > temp_threshold, "Temperature {} of PSU {} is over the threshold {}".format(temperature, psu_id, temp_threshold))


    def test_led(self, duthost, localhost, platform_api_conn):
        ''' PSU status led test '''
        LED_COLOR_LIST = [
            STATUS_LED_COLOR_GREEN,
            STATUS_LED_COLOR_AMBER,
            STATUS_LED_COLOR_RED,
            STATUS_LED_COLOR_OFF
        ]
        try:
            num_psus = int(chassis.get_num_psus(platform_api_conn))
        except:
            pytest_assert("num_psus is not integer!")

        for psu_id in range(num_psus):
            psu = chassis.get_psu(platform_api_conn, psu_id)

            for color in LED_COLOR_LIST:
                result = psu.set_status_led(platform_api_conn, color)
                pytest_assert(result is not None, "Failed to perform set_status_led of PSU {}".format(psu_id))
                pytest_assert(result is not True, "Failed to set status_led of PSU {}".format(psu_id))

                color_status = psu.get_status_led(platform_api_conn)
                pytest_assert(color == color_status, "Retrived the status_led {} not {} from PSU {}".format(color_status, color, psu_id))

