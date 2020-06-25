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

class TestPSUAPI(object):
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
            pytest_assert(fan_list is not None, "Failed to retrieve fans")
            pytest_assert(isinstance(fan_list, list) and len(fan_list) == num_fans, "Fans appear to be incorrect")

            for i in range(num_fans):
                fan = psu.get_fan(platform_api_conn, i)
                pytest_assert(fan and fan == fan_list[i], "Fan {} is incorrect".format(i))


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
            pytest_assert(abs(power - (voltage*current)) > power*0.1, "Power is too off compared to the voltage and current reading")

            powergood_status = psu.get_powergood_status(platform_api_conn)
            pytest_assert(powergood_status is not True, "PSU Powergood status test returns failed")

            try:
                high_threshold = psu.get_voltage_high_threshold(platform_api_conn)
                low_threshold = psu.get_voltage_low_threshold(platform_api_conn)
            except NotImplementedError:
                logger.warning('get_voltage_high/low_threshold is not implemented yet') 
            else:
                if high_threshold is not None and low_threshold is not None:
                    pytest_assert(voltage > high_threshold or voltage < low_threshold, "Voltage is not in valid range")


    def test_temperature(self, duthost, localhost, platform_api_conn):
        ''' PSU temperature test '''
        try:
            num_psus = int(chassis.get_num_psus(platform_api_conn))
        except:
            pytest_assert("num_psus is not integer!")

        for psu_id in range(num_psus):
            psu = chassis.get_psu(platform_api_conn, psu_id)
            try:
                temperature = psu.get_temperature(platform_api_conn)
            except NotImplementedError:
                logger.warning('get_temperature is not implemented yet') 
            else:
                try:
                    temp_threshold = psu.get_temperature_high_threshold(platform_api_conn)
                except NotImplementedError:
                    logger.warning('get_temperature_high_threshold is not implemented yet') 
                else:
                    pytest_assert(temperature > temp_threshold, "temperature is not in valid range")


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
                try:
                    result = psu.set_status_led(platform_api_conn, color)
                except NotImplementedError:
                    logger.warning('set_status_led is not implemented yet') 
                else:
                    if result is True:
                        color_status = psu.get_status_led(platform_api_conn)
                        pytest_assert(color == color_status, "get_status_led doesn't return {}".format(color))
                    else:
                        pytest_assert("set_status_led for {} return False")

