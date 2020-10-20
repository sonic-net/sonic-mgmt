import logging
import re

import pytest
import yaml

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import chassis

from platform_api_test_base import PlatformApiTestBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

###################################################
# TODO: Remove this after we transition to Python 3
import sys
if sys.version_info.major == 3:
    STRING_TYPE = str
else:
    STRING_TYPE = basestring
# END Remove this after we transition to Python 3
###################################################


REGEX_MAC_ADDRESS = r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$'
REGEX_SERIAL_NUMBER = r'^[A-Za-z0-9]+$'

# Valid OCP ONIE TlvInfo EEPROM type codes as defined here:
# https://opencomputeproject.github.io/onie/design-spec/hw_requirements.html
ONIE_TLVINFO_TYPE_CODE_PRODUCT_NAME = '0x21'    # Product Name
ONIE_TLVINFO_TYPE_CODE_PART_NUMBER = '0x22'     # Part Number
ONIE_TLVINFO_TYPE_CODE_SERIAL_NUMBER = '0x23'   # Serial Number
ONIE_TLVINFO_TYPE_CODE_BASE_MAC_ADDR = '0x24'   # Base MAC Address
ONIE_TLVINFO_TYPE_CODE_MFR_DATE = '0x25'        # Manufacture Date
ONIE_TLVINFO_TYPE_CODE_DEVICE_VERSION = '0x26'  # Device Version
ONIE_TLVINFO_TYPE_CODE_LABEL_REVISION = '0x27'  # Label Revision
ONIE_TLVINFO_TYPE_CODE_PLATFORM_NAME = '0x28'   # Platform Name
ONIE_TLVINFO_TYPE_CODE_ONIE_VERSION = '0x29'    # ONIE Version
ONIE_TLVINFO_TYPE_CODE_NUM_MACS = '0x2A'        # Number of MAC Addresses
ONIE_TLVINFO_TYPE_CODE_MANUFACTURER = '0x2B'    # Manufacturer
ONIE_TLVINFO_TYPE_CODE_COUNTRY_CODE = '0x2C'    # Country Code
ONIE_TLVINFO_TYPE_CODE_VENDOR = '0x2D'          # Vendor
ONIE_TLVINFO_TYPE_CODE_DIAG_VERSION = '0x2E'    # Diag Version
ONIE_TLVINFO_TYPE_CODE_SERVICE_TAG = '0x2F'     # Service Tag
ONIE_TLVINFO_TYPE_CODE_VENDOR_EXT = '0xFD'      # Vendor Extension
ONIE_TLVINFO_TYPE_CODE_CRC32 = '0xFE'           # CRC-32


@pytest.fixture(scope="class")
def gather_facts(request, duthost):
    # Get platform facts from platform.json file
    request.cls.chassis_facts = duthost.facts.get("chassis")

    # Get host vars from inventory file
    request.cls.duthost_vars = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars


@pytest.mark.usefixtures("gather_facts")
class TestChassisApi(PlatformApiTestBase):
    """Platform API test cases for the Chassis class"""

    chassis_facts = None
    duthost_vars = None

    #
    # Helper functions
    #

    def compare_value_with_platform_facts(self, key, value):
        expected_value = None

        if self.chassis_facts:
            expected_value = self.chassis_facts.get(key)

        pytest_assert(expected_value is not None,
                      "Unable to get expected value for '{}' from platform.json file".format(key))

        pytest_assert(value == expected_value,
                      "'{}' value is incorrect. Got '{}', expected '{}'".format(key, value, expected_value))

    def compare_value_with_device_facts(self, key, value, case_sensitive=True):
        expected_value = None

        if self.duthost_vars:
            expected_value = self.duthost_vars.get(key)

        pytest_assert(expected_value is not None,
                      "Unable to get expected value for '{}' from inventory file".format(key))

        if case_sensitive:
            pytest_assert(value == expected_value,
                          "'{}' value is incorrect. Got '{}', expected '{}'".format(key, value, expected_value))
        else:
            value_lower = value.lower()
            expected_value_lower = expected_value.lower()
            pytest_assert(value_lower == expected_value_lower,
                          "'{}' value is incorrect. Got '{}', expected '{}'".format(key, value, expected_value))

    #
    # Functions to test methods inherited from DeviceBase class
    #

    def test_get_name(self, duthost, localhost, platform_api_conn):
        name = chassis.get_name(platform_api_conn)
        pytest_assert(name is not None, "Unable to retrieve chassis name")
        pytest_assert(isinstance(name, STRING_TYPE), "Chassis name appears incorrect")
        self.compare_value_with_platform_facts('name', name)

    def test_get_presence(self, duthost, localhost, platform_api_conn):
        presence = chassis.get_presence(platform_api_conn)
        pytest_assert(presence is not None, "Unable to retrieve chassis presence")
        pytest_assert(isinstance(presence, bool), "Chassis presence appears incorrect")
        # Chassis should always be present
        pytest_assert(presence is True, "Chassis is not present")

    def test_get_model(self, duthost, localhost, platform_api_conn):
        model = chassis.get_model(platform_api_conn)
        pytest_assert(model is not None, "Unable to retrieve chassis model")
        pytest_assert(isinstance(model, STRING_TYPE), "Chassis model appears incorrect")
        self.compare_value_with_device_facts('model', model)

    def test_get_serial(self, duthost, localhost, platform_api_conn):
        serial = chassis.get_serial(platform_api_conn)
        pytest_assert(serial is not None, "Unable to retrieve chassis serial number")
        pytest_assert(isinstance(serial, STRING_TYPE), "Chassis serial number appears incorrect")
        self.compare_value_with_device_facts('serial', serial)

    def test_get_status(self, duthost, localhost, platform_api_conn):
        status = chassis.get_status(platform_api_conn)
        pytest_assert(status is not None, "Unable to retrieve chassis status")
        pytest_assert(isinstance(status, bool), "Chassis status appears incorrect")

    #
    # Functions to test methods defined in ChassisBase class
    #

    def test_get_base_mac(self, duthost, localhost, platform_api_conn):
        # Ensure the base MAC address is sane
        base_mac = chassis.get_base_mac(platform_api_conn)
        pytest_assert(base_mac is not None, "Failed to retrieve base MAC address")
        pytest_assert(re.match(REGEX_MAC_ADDRESS, base_mac), "Base MAC address appears to be incorrect")
        self.compare_value_with_device_facts('base_mac', base_mac, False)

    def test_get_system_eeprom_info(self, duthost, localhost, platform_api_conn):
        ''' Test that we can retrieve sane system EEPROM info from the DUT via the platform API
        '''
        # OCP ONIE TlvInfo EEPROM type codes defined here: https://opencomputeproject.github.io/onie/design-spec/hw_requirements.html
        VALID_ONIE_TLVINFO_TYPE_CODES_LIST = [
            ONIE_TLVINFO_TYPE_CODE_PRODUCT_NAME,
            ONIE_TLVINFO_TYPE_CODE_PART_NUMBER,
            ONIE_TLVINFO_TYPE_CODE_SERIAL_NUMBER,
            ONIE_TLVINFO_TYPE_CODE_BASE_MAC_ADDR,
            ONIE_TLVINFO_TYPE_CODE_MFR_DATE,
            ONIE_TLVINFO_TYPE_CODE_DEVICE_VERSION,
            ONIE_TLVINFO_TYPE_CODE_LABEL_REVISION,
            ONIE_TLVINFO_TYPE_CODE_PLATFORM_NAME,
            ONIE_TLVINFO_TYPE_CODE_ONIE_VERSION,
            ONIE_TLVINFO_TYPE_CODE_NUM_MACS,
            ONIE_TLVINFO_TYPE_CODE_MANUFACTURER,
            ONIE_TLVINFO_TYPE_CODE_COUNTRY_CODE,
            ONIE_TLVINFO_TYPE_CODE_VENDOR,
            ONIE_TLVINFO_TYPE_CODE_DIAG_VERSION,
            ONIE_TLVINFO_TYPE_CODE_SERVICE_TAG,
            ONIE_TLVINFO_TYPE_CODE_VENDOR_EXT,
            ONIE_TLVINFO_TYPE_CODE_CRC32
        ]

        MINIMUM_REQUIRED_TYPE_CODES_LIST = [
            ONIE_TLVINFO_TYPE_CODE_SERIAL_NUMBER,
            ONIE_TLVINFO_TYPE_CODE_BASE_MAC_ADDR,
            ONIE_TLVINFO_TYPE_CODE_CRC32
        ]

        syseeprom_info_dict = chassis.get_system_eeprom_info(platform_api_conn)
        pytest_assert(syseeprom_info_dict is not None, "Failed to retrieve system EEPROM data")
        pytest_assert(isinstance(syseeprom_info_dict, dict), "System EEPROM data is not in the expected format")

        syseeprom_type_codes_list = syseeprom_info_dict.keys()

        # Ensure that all keys in the resulting dictionary are valid ONIE TlvInfo type codes
        pytest_assert(set(syseeprom_type_codes_list) <= set(VALID_ONIE_TLVINFO_TYPE_CODES_LIST), "Invalid TlvInfo type code found")

        # Ensure that we were able to obtain the minimum required type codes
        pytest_assert(set(MINIMUM_REQUIRED_TYPE_CODES_LIST) <= set(syseeprom_type_codes_list), "Minimum required TlvInfo type codes not provided")

        # Ensure the base MAC address is sane
        base_mac = syseeprom_info_dict[ONIE_TLVINFO_TYPE_CODE_BASE_MAC_ADDR]
        pytest_assert(base_mac is not None, "Failed to retrieve base MAC address")
        pytest_assert(re.match(REGEX_MAC_ADDRESS, base_mac), "Base MAC address appears to be incorrect")

        # Ensure the serial number is sane
        serial = syseeprom_info_dict[ONIE_TLVINFO_TYPE_CODE_SERIAL_NUMBER]
        pytest_assert(serial is not None, "Failed to retrieve serial number")
        pytest_assert(re.match(REGEX_SERIAL_NUMBER, serial), "Serial number appears to be incorrect")

        self.compare_value_with_device_facts('syseeprom_info', syseeprom_info_dict)

    def test_get_reboot_cause(self, duthost, localhost, platform_api_conn):
        # TODO: Compare return values to potential combinations
        reboot_cause = chassis.get_reboot_cause(platform_api_conn)

        # Actual return value is a tuple, but since we're using the HTTP server
        # to make the call and it uses JSON, the tuple is changed to a list
        pytest_assert(reboot_cause is not None, "Failed to retrieve reboot cause")
        pytest_assert(isinstance(reboot_cause, list) and len(reboot_cause) == 2, "Reboot cause appears to be incorrect")

    def test_components(self, duthost, localhost, platform_api_conn):
        try:
            num_components = int(chassis.get_num_components(platform_api_conn))
        except:
            pytest.fail("num_components is not an integer")

        if self.chassis_facts:
            expected_num_components = len(self.chassis_facts.get('components'))
            pytest_assert(num_components == expected_num_components,
                          "Number of components ({}) does not match expected number ({})"
                          .format(num_components, expected_num_components))

        component_list = chassis.get_all_components(platform_api_conn)
        pytest_assert(component_list is not None, "Failed to retrieve components")
        pytest_assert(isinstance(component_list, list) and len(component_list) == num_components, "Components appear to be incorrect")

        for i in range(num_components):
            component = chassis.get_component(platform_api_conn, i)
            self.expect(component and component == component_list[i], "Component {} is incorrect".format(i))
        self.assert_expectations()

    def test_modules(self, duthost, localhost, platform_api_conn):
        try:
            num_modules = int(chassis.get_num_modules(platform_api_conn))
        except:
            pytest.fail("num_modules is not an integer")

        module_list = chassis.get_all_modules(platform_api_conn)
        pytest_assert(module_list is not None, "Failed to retrieve modules")
        pytest_assert(isinstance(module_list, list) and len(module_list) == num_modules, "Modules appear to be incorrect")

        for i in range(num_modules):
            module = chassis.get_module(platform_api_conn, i)
            self.expect(module and module == module_list[i], "Module {} is incorrect".format(i))
        self.assert_expectations()

    def test_fans(self, duthost, localhost, platform_api_conn):
        try:
            num_fans = int(chassis.get_num_fans(platform_api_conn))
        except:
            pytest.fail("num_fans is not an integer")

        if self.chassis_facts:
            expected_num_fans = len(self.chassis_facts.get('fans'))
            pytest_assert(num_fans == expected_num_fans,
                          "Number of fans ({}) does not match expected number ({})"
                          .format(num_fans, expected_num_fans))

        fan_list = chassis.get_all_fans(platform_api_conn)
        pytest_assert(fan_list is not None, "Failed to retrieve fans")
        pytest_assert(isinstance(fan_list, list) and len(fan_list) == num_fans, "Fans appear to be incorrect")

        for i in range(num_fans):
            fan = chassis.get_fan(platform_api_conn, i)
            self.expect(fan and fan == fan_list[i], "Fan {} is incorrect".format(i))
        self.assert_expectations()

    def test_fan_drawers(self, duthost, localhost, platform_api_conn):
        try:
            num_fan_drawers = int(chassis.get_num_fan_drawers(platform_api_conn))
        except:
            pytest.fail("num_fan_drawers is not an integer")

        if self.chassis_facts:
            expected_num_fan_drawers = len(self.chassis_facts.get('fan_drawers'))
            pytest_assert(num_fan_drawers == expected_num_fan_drawers,
                          "Number of fan drawers ({}) does not match expected number ({})"
                          .format(num_fan_drawers, expected_num_fan_drawers))

        fan_drawer_list = chassis.get_all_fan_drawers(platform_api_conn)
        pytest_assert(fan_drawer_list is not None, "Failed to retrieve fan drawers")
        pytest_assert(isinstance(fan_drawer_list, list) and len(fan_drawer_list) == num_fan_drawers, "Fan drawerss appear to be incorrect")

        for i in range(num_fan_drawers):
            fan_drawer = chassis.get_fan_drawer(platform_api_conn, i)
            self.expect(fan_drawer and fan_drawer == fan_drawer_list[i], "Fan drawer {} is incorrect".format(i))
        self.assert_expectations()

    def test_psus(self, duthost, localhost, platform_api_conn):
        try:
            num_psus = int(chassis.get_num_psus(platform_api_conn))
        except:
            pytest.fail("num_psus is not an integer")

        if self.chassis_facts:
            expected_num_psus = len(self.chassis_facts.get('psus'))
            pytest_assert(num_psus == expected_num_psus,
                          "Number of psus ({}) does not match expected number ({})"
                          .format(num_psus, expected_num_psus))

        psu_list = chassis.get_all_psus(platform_api_conn)
        pytest_assert(psu_list is not None, "Failed to retrieve PSUs")
        pytest_assert(isinstance(psu_list, list) and len(psu_list) == num_psus, "PSUs appear to be incorrect")

        for i in range(num_psus):
            psu = chassis.get_psu(platform_api_conn, i)
            self.expect(psu and psu == psu_list[i], "PSU {} is incorrect".format(i))
        self.assert_expectations()

    def test_thermals(self, duthost, localhost, platform_api_conn):
        try:
            num_thermals = int(chassis.get_num_thermals(platform_api_conn))
        except:
            pytest.fail("num_thermals is not an integer")

        if self.chassis_facts:
            expected_num_thermals = len(self.chassis_facts.get('thermals'))
            pytest_assert(num_thermals == expected_num_thermals,
                          "Number of thermals ({}) does not match expected number ({})"
                          .format(num_thermals, expected_num_thermals))

        thermal_list = chassis.get_all_thermals(platform_api_conn)
        pytest_assert(thermal_list is not None, "Failed to retrieve thermals")
        pytest_assert(isinstance(thermal_list, list) and len(thermal_list) == num_thermals, "Thermals appear to be incorrect")

        for i in range(num_thermals):
            thermal = chassis.get_thermal(platform_api_conn, i)
            self.expect(thermal and thermal == thermal_list[i], "Thermal {} is incorrect".format(i))
        self.assert_expectations()

    def test_sfps(self, duthost, localhost, platform_api_conn):
        try:
            num_sfps = int(chassis.get_num_sfps(platform_api_conn))
        except:
            pytest.fail("num_sfps is not an integer")

        if self.chassis_facts:
            expected_num_sfps = len(self.chassis_facts.get('sfps'))
            pytest_assert(num_sfps == expected_num_sfps,
                          "Number of sfps ({}) does not match expected number ({})"
                          .format(num_sfps, expected_num_sfps))

        sfp_list = chassis.get_all_sfps(platform_api_conn)
        pytest_assert(sfp_list is not None, "Failed to retrieve SFPs")
        pytest_assert(isinstance(sfp_list, list) and len(sfp_list) == num_sfps, "SFPs appear to be incorrect")

        for i in range(num_sfps):
            sfp = chassis.get_sfp(platform_api_conn, i)
            self.expect(sfp and sfp == sfp_list[i], "SFP {} is incorrect".format(i))
        self.assert_expectations()

    def test_status_led(self, duthost, localhost, platform_api_conn):
        # TODO: Get a platform-specific list of available colors for the status LED
        LED_COLOR_LIST = [
            "off",
            "red",
            "amber",
            "green",
        ]

        for color in LED_COLOR_LIST:
            result = chassis.set_status_led(platform_api_conn, color)
            if self.expect(result is not None, "Failed to perform set_status_led"):
                self.expect(result is True, "Failed to set status_led to {}".format(color))

            color_actual = chassis.get_status_led(platform_api_conn)
            if self.expect(color_actual is not None, "Failed to retrieve status_led"):
                if self.expect(isinstance(color_actual, STRING_TYPE), "Status LED color appears incorrect"):
                    self.expect(color == color_actual, "Status LED color incorrect (expected: {}, actual: {})".format(color, color_actual))
        self.assert_expectations()

    def test_get_thermal_manager(self, duthost, localhost, platform_api_conn):
        thermal_mgr = chassis.get_thermal_manager(platform_api_conn)
        pytest_assert(thermal_mgr is not None, "Failed to retrieve thermal manager")

    def test_get_watchdog(self, duthost, localhost, platform_api_conn):
        watchdog = chassis.get_watchdog(platform_api_conn)
        pytest_assert(watchdog is not None, "Failed to retrieve watchdog")

    def test_get_eeprom(self, duthost, localhost, platform_api_conn):
        eeprom = chassis.get_eeprom(platform_api_conn)
        pytest_assert(eeprom is not None, "Failed to retrieve system EEPROM")

    def test_get_position_in_parent(self, platform_api_conn):
        position = chassis.get_position_in_parent(platform_api_conn)
        self.expect(position is not None, "Failed to perform get_position_in_parent")
        self.expect(isinstance(position, int), "Position value must be an integer value")
        self.assert_expectations()

    def test_is_replaceable(self, platform_api_conn):
        replaceable = chassis.is_replaceable(platform_api_conn)
        self.expect(replaceable is not None, "Failed to perform is_replaceable")
        self.expect(isinstance(replaceable, bool), "Replaceable value must be a bool value")
        self.assert_expectations()
