import logging
import re

import pytest
import yaml

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import chassis, psu

from platform_api_test_base import PlatformApiTestBase


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

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, platform_api_conn):
        if self.num_psus is None:
            try:
                self.num_psus = int(chassis.get_num_psus(platform_api_conn))
            except:
                pytest.fail("num_psus is not an integer")

    #
    # Functions to test methods inherited from DeviceBase class
    #

    def test_get_name(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_psus):
            name = psu.get_name(platform_api_conn, i)
            if self.expect(name is not None, "Unable to retrieve PSU {} name".format(i)):
                self.expect(isinstance(name, str), "PSU {} name appears incorrect".format(i))
        self.assert_expectations()

    def test_get_presence(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_psus):
            presence = psu.get_presence(platform_api_conn, i)
            if self.expect(presence is not None, "Unable to retrieve PSU {} presence".format(i)):
                if self.expect(isinstance(presence, bool), "PSU {} presence appears incorrect".format(i)):
                    self.expect(presence is True, "PSU {} is not present".format(i))
        self.assert_expectations()

    def test_get_model(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_psus):
            model = psu.get_model(platform_api_conn, i)
            if self.expect(model is not None, "Unable to retrieve PSU {} model".format(i)):
                self.expect(isinstance(model, str), "PSU {} model appears incorrect".format(i))
        self.assert_expectations()

    def test_get_serial(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_psus):
            serial = psu.get_serial(platform_api_conn, i)
            if self.expect(serial is not None, "Unable to retrieve PSU {} serial number".format(i)):
                self.expect(isinstance(serial, str), "PSU {} serial number appears incorrect".format(i))
        self.assert_expectations()

    def test_get_status(self, duthost, localhost, platform_api_conn):
        for i in range(self.num_psus):
            status = psu.get_status(platform_api_conn, i)
            if self.expect(status is not None, "Unable to retrieve PSU {} status".format(i)):
                self.expect(isinstance(status, bool), "PSU {} status appears incorrect".format(i))
        self.assert_expectations()

    #
    # Functions to test methods defined in PsuBase class
    #

    def test_fans(self, duthost, localhost, platform_api_conn):
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


    def test_power(self, duthost, localhost, platform_api_conn):
        ''' PSU power test '''
        for psu_id in range(self.num_psus):
            voltage = psu.get_voltage(platform_api_conn, psu_id)
            if self.expect(voltage is not None, "Failed to retrieve voltage of PSU {}".format(psu_id)):
                self.expect(isinstance(voltage, float), "PSU {} voltage appears incorrect".format(psu_id))
            current = psu.get_current(platform_api_conn, psu_id)
            if self.expect(current is not None, "Failed to retrieve current of PSU {}".format(psu_id)):
                self.expect(isinstance(current, float), "PSU {} current appears incorrect".format(psu_id))
            power = psu.get_power(platform_api_conn, psu_id)
            if self.expect(current is not None, "Failed to retrieve current of PSU {}".format(psu_id)):
                self.expect(isinstance(power, float), "PSU {} power appears incorrect".format(psu_id))
            if current is not None and voltage is not None and power is not None:
                self.expect(abs(power - (voltage*current)) < power*0.1, "PSU {} reading does not make sense \
                    (power:{}, voltage:{}, current:{})".format(psu_id, power, voltage, current))

            powergood_status = psu.get_powergood_status(platform_api_conn, psu_id)
            if self.expect(powergood_status is not None, "Failed to retrieve operational status of PSU {}".format(psu_id)):
                self.expect(powergood_status is True, "PSU {} is not operational".format(psu_id))

            high_threshold = psu.get_voltage_high_threshold(platform_api_conn, psu_id)
            if self.expect(high_threshold is not None, "Failed to retrieve the high voltage threshold of PSU {}".format(psu_id)):
                self.expect(isinstance(high_threshold, float), "PSU {} voltage high threshold appears incorrect".format(psu_id))
            low_threshold = psu.get_voltage_low_threshold(platform_api_conn, psu_id)
            if self.expect(low_threshold is not None, "Failed to retrieve the low voltage threshold of PSU {}".format(psu_id)):
                self.expect(isinstance(low_threshold, float), "PSU {} voltage low threshold appears incorrect".format(psu_id))
            if high_threshold is not None and low_threshold is not None:
                self.expect(voltage < high_threshold and voltage > low_threshold, "Voltage {} of PSU {} is not in between {} and {}".format(voltage, psu_id, low_threshold, high_threshold))
        self.assert_expectations()


    def test_temperature(self, duthost, localhost, platform_api_conn):
        ''' PSU temperature test '''
        for psu_id in range(self.num_psus):
            temperature = psu.get_temperature(platform_api_conn, psu_id)
            if self.expect(temperature is not None, "Failed to retrieve temperature of PSU {}".format(psu_id)):
                self.expect(isinstance(temperature, float), "PSU {} temperature appears incorrect".format(psu_id))

            temp_threshold = psu.get_temperature_high_threshold(platform_api_conn, psu_id)
            if self.expect(temp_threshold is not None, "Failed to retrieve temperature threshold of PSU {}".format(psu_id)):
                if self.expect(isinstance(temp_threshold, float), "PSU {} temperature high threshold appears incorrect".format(psu_id)):
                    self.expect(temperature < temp_threshold, "Temperature {} of PSU {} is over the threshold {}".format(temperature, psu_id, temp_threshold))
        self.assert_expectations()


    def test_led(self, duthost, localhost, platform_api_conn):
        ''' PSU status led test '''
        LED_COLOR_LIST = [
            STATUS_LED_COLOR_GREEN,
            STATUS_LED_COLOR_AMBER,
            STATUS_LED_COLOR_RED,
            STATUS_LED_COLOR_OFF
        ]

        for psu_id in range(self.num_psus):
            for color in LED_COLOR_LIST:
                result = psu.set_status_led(platform_api_conn, psu_id, color)
                if self.expect(result is not None, "Failed to perform set_status_led of PSU {}".format(psu_id)):
                    self.expect(result is True, "Failed to set status_led of PSU {} to {}".format(psu_id, color))

                color_actual = psu.get_status_led(platform_api_conn, psu_id)
                if self.expect(color_actual is not None, "Failed to retrieve status_led of PSU {}".format(psu_id)):
                    if self.expect(isinstance(color_actual, str), "PSU {} status LED color appears incorrect".format(psu_id)):
                        self.expect(color == color_actual, "Status LED color incorrect (expected: {}, actual: {}) from PSU {}".format(color, color_actual, psu_id))
        self.assert_expectations()

