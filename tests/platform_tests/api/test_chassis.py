import logging
import re

import pytest
import yaml

from natsort import natsorted

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import chassis, module
from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.utilities import get_inventory_files
from tests.common.utilities import get_host_visible_vars
from tests.common.utilities import skip_release
from tests.common.platform.interface_utils import get_physical_port_indices

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
REGEX_SERIAL_NUMBER = r'^[A-Za-z0-9\-]+$'

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

# get_physical_port_indices() is wrapped around pytest fixture with module
# scope because this function can be quite time consuming based upon the
# number of ports on the DUT
@pytest.fixture(scope="module")
def physical_port_indices(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    port_map = get_physical_port_indices(duthost)
    result = []
    visited_intfs = set()
    for intf in natsorted(port_map.keys()):
        if intf in visited_intfs:
            continue
        visited_intfs.add(intf)
        result.append(port_map[intf])
    return result

@pytest.fixture(scope="class")
def gather_facts(request, duthosts):
    request.cls.inv_files = get_inventory_files(request)

@pytest.mark.usefixtures("gather_facts", "physical_port_indices")
class TestChassisApi(PlatformApiTestBase):
    """Platform API test cases for the Chassis class"""
    inv_files = None

    #
    # Helper functions
    #
    def compare_value_with_platform_facts(self, duthost, key, value):
        expected_value = None

        if duthost.facts.get("chassis"):
            expected_value = duthost.facts.get("chassis").get(key)

        pytest_assert(expected_value is not None,
                      "Unable to get expected value for '{}' from platform.json file".format(key))

        pytest_assert(value == expected_value,
                      "'{}' value is incorrect. Got '{}', expected '{}'".format(key, value, expected_value))

    def compare_value_with_device_facts(self, duthost, key, value, case_sensitive=True):
        expected_value = None

        if self.inv_files:
            host_vars = get_host_visible_vars(self.inv_files, duthost.hostname)
            expected_value = host_vars.get(key)

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

    def test_get_name(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        name = chassis.get_name(platform_api_conn)
        pytest_assert(name is not None, "Unable to retrieve chassis name")
        pytest_assert(isinstance(name, STRING_TYPE), "Chassis name appears incorrect")
        self.compare_value_with_platform_facts(duthost, 'name', name)

    def test_get_presence(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        presence = chassis.get_presence(platform_api_conn)
        pytest_assert(presence is not None, "Unable to retrieve chassis presence")
        pytest_assert(isinstance(presence, bool), "Chassis presence appears incorrect")
        # Chassis should always be present
        pytest_assert(presence is True, "Chassis is not present")

    def test_get_model(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        model = chassis.get_model(platform_api_conn)
        pytest_assert(model is not None, "Unable to retrieve chassis model")
        pytest_assert(isinstance(model, STRING_TYPE), "Chassis model appears incorrect")
        self.compare_value_with_device_facts(duthost, 'model', model)

    def test_get_serial(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        serial = chassis.get_serial(platform_api_conn)
        pytest_assert(serial is not None, "Unable to retrieve chassis serial number")
        pytest_assert(isinstance(serial, STRING_TYPE), "Chassis serial number appears incorrect")
        self.compare_value_with_device_facts(duthost, 'serial', serial)

    def test_get_revision(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release(duthost, ["201811", "201911", "202012"])
        revision = chassis.get_revision(platform_api_conn)
        pytest_assert(revision is not None, "Unable to retrieve chassis revision")
        pytest_assert(isinstance(revision, STRING_TYPE), "Revision appears incorrect")

    def test_get_status(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        status = chassis.get_status(platform_api_conn)
        pytest_assert(status is not None, "Unable to retrieve chassis status")
        pytest_assert(isinstance(status, bool), "Chassis status appears incorrect")

    def test_get_position_in_parent(self, platform_api_conn):
        position = chassis.get_position_in_parent(platform_api_conn)
        if self.expect(position is not None, "Failed to perform get_position_in_parent"):
            self.expect(isinstance(position, int), "Position value must be an integer value")
        self.assert_expectations()

    def test_is_replaceable(self, platform_api_conn):
        replaceable = chassis.is_replaceable(platform_api_conn)
        if self.expect(replaceable is not None, "Failed to perform is_replaceable"):
            self.expect(isinstance(replaceable, bool), "Replaceable value must be a bool value")
        self.assert_expectations()

    #
    # Functions to test methods defined in ChassisBase class
    #

    def test_get_base_mac(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        # Ensure the base MAC address is sane
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        base_mac = chassis.get_base_mac(platform_api_conn)
        pytest_assert(base_mac is not None, "Failed to retrieve base MAC address")
        pytest_assert(re.match(REGEX_MAC_ADDRESS, base_mac), "Base MAC address appears to be incorrect")
        self.compare_value_with_device_facts(duthost, 'base_mac', base_mac, False)

    def test_get_system_eeprom_info(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
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

        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        syseeprom_info_dict = chassis.get_system_eeprom_info(platform_api_conn)
        # Convert all keys of syseeprom_info_dict into lower case
        syseeprom_info_dict = {k.lower() : v for k, v in syseeprom_info_dict.items()}
        pytest_assert(syseeprom_info_dict is not None, "Failed to retrieve system EEPROM data")
        pytest_assert(isinstance(syseeprom_info_dict, dict), "System EEPROM data is not in the expected format")
        
        # case sensitive,so make all characters lowercase
        syseeprom_type_codes_list = [key.lower() for key in syseeprom_info_dict.keys()]
        VALID_ONIE_TLVINFO_TYPE_CODES_LIST = [key.lower() for key in VALID_ONIE_TLVINFO_TYPE_CODES_LIST]
        MINIMUM_REQUIRED_TYPE_CODES_LIST = [key.lower() for key in MINIMUM_REQUIRED_TYPE_CODES_LIST]
        
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
        host_vars = get_host_visible_vars(self.inv_files, duthost.hostname)
        expected_syseeprom_info_dict = host_vars.get('syseeprom_info')
        # Ignore case of keys in syseeprom_info
        expected_syseeprom_info_dict = {k.lower(): v for k, v in expected_syseeprom_info_dict.items()}

        for field in expected_syseeprom_info_dict:
            pytest_assert(field in syseeprom_info_dict, "Expected field '{}' not present in syseeprom on '{}'".format(field, duthost.hostname))
            pytest_assert(syseeprom_info_dict[field] == expected_syseeprom_info_dict[field],
                          "System EEPROM info is incorrect - for '{}', rcvd '{}', expected '{}' on '{}'".
                          format(field, syseeprom_info_dict[field], expected_syseeprom_info_dict[field], duthost.hostname))


    def test_get_reboot_cause(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        # TODO: Compare return values to potential combinations
        reboot_cause = chassis.get_reboot_cause(platform_api_conn)

        # Actual return value is a tuple, but since we're using the HTTP server
        # to make the call and it uses JSON, the tuple is changed to a list
        pytest_assert(reboot_cause is not None, "Failed to retrieve reboot cause")
        pytest_assert(isinstance(reboot_cause, list) and len(reboot_cause) == 2, "Reboot cause appears to be incorrect")

    def test_components(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        try:
            num_components = int(chassis.get_num_components(platform_api_conn))
        except:
            pytest.fail("num_components is not an integer")
        else:
            if num_components == 0:
                pytest.skip("No components found on device")

        if duthost.facts.get("chassis"):
            components = duthost.facts.get("chassis").get('components')
            expected_num_components = 0 if components is None else len(components)
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

    def test_modules(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        try:
            num_modules = int(chassis.get_num_modules(platform_api_conn))
        except:
            pytest.fail("num_modules is not an integer")
        else:
            if num_modules == 0:
                pytest.skip("No modules found on device")

        module_list = chassis.get_all_modules(platform_api_conn)
        pytest_assert(module_list is not None, "Failed to retrieve modules")
        pytest_assert(isinstance(module_list, list) and len(module_list) == num_modules, "Modules appear to be incorrect")

        for i in range(num_modules):
            module_idx = chassis.get_module(platform_api_conn, i)
            module_name = module.get_name(platform_api_conn, i)
            module_index = chassis.get_module_index(platform_api_conn, module_name)
            self.expect(module_idx and module_idx == module_list[i], "Module {} is incorrect".format(i))
            self.expect(module_index == i, "Module index {} is not correct".format(module_index))
        self.assert_expectations()

    def test_fans(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        try:
            num_fans = int(chassis.get_num_fans(platform_api_conn))
        except:
            pytest.fail("num_fans is not an integer")
        else:
            if num_fans == 0:
                pytest.skip("No fans found on device")

        if duthost.facts.get("chassis"):
            expected_num_fans = len(duthost.facts.get("chassis").get('fans'))
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

    def test_fan_drawers(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        try:
            num_fan_drawers = int(chassis.get_num_fan_drawers(platform_api_conn))
        except:
            pytest.fail("num_fan_drawers is not an integer")
        else:
            if num_fan_drawers == 0:
                pytest.skip("No fan drawers found on device")

        if duthost.facts.get("chassis"):
            expected_num_fan_drawers = len(duthost.facts.get("chassis").get('fan_drawers'))
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

    def test_psus(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        try:
            num_psus = int(chassis.get_num_psus(platform_api_conn))
        except:
            pytest.fail("num_psus is not an integer")
        else:
            if num_psus == 0:
                pytest.skip("No psus found on device")

        if duthost.facts.get("chassis"):
            expected_num_psus = len(duthost.facts.get("chassis").get('psus'))
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

    def test_thermals(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        try:
            num_thermals = int(chassis.get_num_thermals(platform_api_conn))
        except:
            pytest.fail("num_thermals is not an integer")
        else:
            if num_thermals == 0:
                pytest.skip("No thermals found on device")

        if duthost.facts.get("chassis"):
            expected_num_thermals = len(duthost.facts.get("chassis").get('thermals'))
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

    def test_sfps(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn, physical_port_indices):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        if duthost.is_supervisor_node():
            pytest.skip("skipping for supervisor node")
        try:
            num_sfps = int(chassis.get_num_sfps(platform_api_conn))
        except:
            pytest.fail("num_sfps is not an integer")
        else:
            if num_sfps == 0:
                pytest.skip("No sfps found on device")

        list_sfps = physical_port_indices

        logging.info("Physical port indices = {}".format(list_sfps))

        if duthost.facts.get("chassis"):
            expected_num_sfps = len(duthost.facts.get("chassis").get('sfps'))
            if duthost.facts.get("platform") == 'x86_64-nvidia_sn2201-r0':
                # On SN2201, there are 48 RJ45 ports which are also counted in SFP object lists
                # So we need to adjust test case accordingly
                expected_num_sfps += 48
            pytest_assert(num_sfps == expected_num_sfps,
                          "Number of sfps ({}) does not match expected number ({})"
                          .format(num_sfps, expected_num_sfps))

        sfp_list = chassis.get_all_sfps(platform_api_conn)
        pytest_assert(sfp_list is not None, "Failed to retrieve SFPs")
        pytest_assert(isinstance(sfp_list, list) and len(sfp_list) == num_sfps, "SFPs appear to be incorrect")

        for i in range(len(list_sfps)):
            index = list_sfps[i]
            sfp = chassis.get_sfp(platform_api_conn, index)
            self.expect(sfp and sfp in sfp_list, "SFP object for PORT{} NOT found".format(index))
        self.assert_expectations()

    def test_status_led(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        # TODO: Get a platform-specific list of available colors for the status LED

        FAULT_LED_COLOR_LIST = [
            "amber",
            "red"
        ]

        NORMAL_LED_COLOR_LIST = [
            "green"
        ]

        OFF_LED_COLOR_LIST = [
            "off"
        ]

        LED_COLOR_TYPES = []
        LED_COLOR_TYPES.append(FAULT_LED_COLOR_LIST)
        LED_COLOR_TYPES.append(NORMAL_LED_COLOR_LIST)

        # Mellanox is not supporting set leds to 'off'
        if duthost.facts.get('asic_type') != "mellanox":
            LED_COLOR_TYPES.append(OFF_LED_COLOR_LIST)

        LED_COLOR_TYPES_DICT = {
            0: "fault",
            1: "normal",
            2: "off"
        }

        led_controllable = True
        led_supported_colors = []
        if duthost.facts.get("chassis"):
            status_led = duthost.facts.get("chassis").get("status_led")
            if status_led:
                led_controllable = status_led.get("controllable", True)
                led_supported_colors = status_led.get("colors")

        if led_controllable:
            led_type_skipped = 0
            for index, led_type in enumerate(LED_COLOR_TYPES):
                if led_supported_colors:
                    led_type = set(led_type) & set(led_supported_colors)
                    if not led_type:
                        logger.warning("test_status_led: Skipping set status_led to {} (No supported colors)".format(LED_COLOR_TYPES_DICT[index]))
                        led_type_skipped += 1
                        continue

                led_type_result = False
                for color in led_type:
                    result = chassis.set_status_led(platform_api_conn, color)
                    if self.expect(result is not None, "Failed to perform set_status_led"):
                        led_type_result = result or led_type_result
                    if ((result is None) or (not result)):
                        continue
                    color_actual = chassis.get_status_led(platform_api_conn)
                    if self.expect(color_actual is not None, "Failed to retrieve status_led"):
                        if self.expect(isinstance(color_actual, STRING_TYPE), "Status LED color appears incorrect"):
                            self.expect(color == color_actual, "Status LED color incorrect (expected: {}, actual: {})".format(color, color_actual))
                self.expect(led_type_result is True, "Failed to set status_led to {}".format(LED_COLOR_TYPES_DICT[index]))

            if led_type_skipped == len(LED_COLOR_TYPES):
                pytest.skip("skipped as no supported colors for all types")

        else:
            pytest.skip("skipped as chassis's status led is not controllable")

        self.assert_expectations()

    def test_get_thermal_manager(self, localhost, platform_api_conn, thermal_manager_enabled):
        thermal_mgr = chassis.get_thermal_manager(platform_api_conn)
        pytest_assert(thermal_mgr is not None, "Failed to retrieve thermal manager")

    def test_get_watchdog(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        watchdog = chassis.get_watchdog(platform_api_conn)
        pytest_assert(watchdog is not None, "Failed to retrieve watchdog")

    def test_get_eeprom(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        eeprom = chassis.get_eeprom(platform_api_conn)
        pytest_assert(eeprom is not None, "Failed to retrieve system EEPROM")

    def test_get_supervisor_slot(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        if chassis.is_modular_chassis(platform_api_conn):
            sup_slot = chassis.get_supervisor_slot(platform_api_conn)
            pytest_assert(isinstance(sup_slot, int) or isinstance(sup_slot, STRING_TYPE), "supervisor slot is not type integer")
        else:
            pytest.skip("skipped as this test is applicable to modular chassis only")

    def test_get_my_slot(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        if chassis.is_modular_chassis(platform_api_conn):
            my_slot = chassis.get_my_slot(platform_api_conn)
            pytest_assert(isinstance(my_slot, int) or isinstance(my_slot, STRING_TYPE), "supervisor slot is not type integer")
        else:
            pytest.skip("skipped as this test is applicable to modular chassis only")
