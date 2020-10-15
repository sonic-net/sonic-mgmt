import logging
import re

import pytest
import yaml

from tests.common.helpers.platform_api import chassis, module

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

REGEX_MAC_ADDRESS = r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$'
REGEX_SERIAL_NUMBER = r'^[A-Za-z0-9]+$'

# TODO: EEPROM info is duplicated with chassis.py. Break out into a shared module
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


class TestModuleApi(PlatformApiTestBase):
    """Platform API test cases for the Module class"""

    num_modules = None

    # This fixture would probably be better scoped at the class level, but
    # it relies on the platform_api_conn fixture, which is scoped at the function
    # level, so we must do the same here to prevent a scope mismatch.
    @pytest.fixture(scope="function", autouse=True)
    def setup(self, platform_api_conn):
        if self.num_modules is None:
            try:
                self.num_modules = int(chassis.get_num_modules(platform_api_conn))
            except:
                pytest.fail("num_modules is not an integer")

    #
    # Functions to test methods inherited from DeviceBase class
    #

    def test_get_name(self, duthost, localhost, platform_api_conn):
        if self.num_modules == 0:
            pytest.skip("No modules found on device")

        for i in range(self.num_modules):
            name = module.get_name(platform_api_conn, i)
            if self.expect(name is not None, "Unable to retrieve module {} name".format(i)):
                self.expect(isinstance(name, STRING_TYPE), "Module {} name appears incorrect".format(i))
        self.assert_expectations()

    def test_get_presence(self, duthost, localhost, platform_api_conn):
        if self.num_modules == 0:
            pytest.skip("No modules found on device")

        for i in range(self.num_modules):
            presence = module.get_presence(platform_api_conn, i)
            if self.expect(presence is not None, "Unable to retrieve module {} presence".format(i)):
                if self.expect(isinstance(presence, bool), "Module {} presence appears incorrect".format(i)):
                    self.expect(presence is True, "Module {} is not present".format(i))
        self.assert_expectations()

    def test_get_model(self, duthost, localhost, platform_api_conn):
        if self.num_modules == 0:
            pytest.skip("No modules found on device")

        for i in range(self.num_modules):
            model = module.get_model(platform_api_conn, i)
            if self.expect(model is not None, "Unable to retrieve module {} model".format(i)):
                self.expect(isinstance(model, STRING_TYPE), "Module {} model appears incorrect".format(i))
        self.assert_expectations()

    def test_get_serial(self, duthost, localhost, platform_api_conn):
        if self.num_modules == 0:
            pytest.skip("No modules found on device")

        for i in range(self.num_modules):
            serial = module.get_serial(platform_api_conn, i)
            if self.expect(serial is not None, "Module {}: Failed to retrieve serial number".format(i)):
                self.expect(isinstance(serial, STRING_TYPE), "Module {} serial number appears incorrect".format(i))
        self.assert_expectations()

    def test_get_status(self, duthost, localhost, platform_api_conn):
        if self.num_modules == 0:
            pytest.skip("No modules found on device")

        for i in range(self.num_modules):
            status = module.get_status(platform_api_conn, i)
            if self.expect(status is not None, "Unable to retrieve module {} status".format(i)):
                self.expect(isinstance(status, bool), "Module {} status appears incorrect".format(i))
        self.assert_expectations()

    #
    # Functions to test methods defined in ModuleBase class
    #

    def test_get_base_mac(self, duthost, localhost, platform_api_conn):
        if self.num_modules == 0:
            pytest.skip("No modules found on device")

        # Ensure the base MAC address of each module is sane
        # TODO: Add expected base MAC address for each module to inventory file and compare against it
        for i in range(self.num_modules):
            base_mac = module.get_base_mac(platform_api_conn, i)
            if not self.expect(base_mac is not None, "Module {}: Failed to retrieve base MAC address".format(i)):
                continue
            self.expect(re.match(REGEX_MAC_ADDRESS, base_mac), "Module {}: Base MAC address appears to be incorrect".format(i))
        self.assert_expectations()

    def test_get_system_eeprom_info(self, duthost, localhost, platform_api_conn):
        """
        Test that we can retrieve sane system EEPROM info from each module of the DUT via the platform API
        """
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

        if self.num_modules == 0:
            pytest.skip("No modules found on device")

        # TODO: Add expected system EEPROM info for each module to inventory file and compare against it
        for i in range(self.num_modules):
            syseeprom_info_dict = module.get_system_eeprom_info(platform_api_conn, i)
            if not self.expect(syseeprom_info_dict is not None, "Module {}: Failed to retrieve system EEPROM data".format(i)):
                continue

            if not self.expect(isinstance(syseeprom_info_dict, dict), "Module {}: System EEPROM data is not in the expected format".format(i)):
                continue

            syseeprom_type_codes_list = syseeprom_info_dict.keys()

            # Ensure that all keys in the resulting dictionary are valid ONIE TlvInfo type codes
            self.expect(set(syseeprom_type_codes_list) <= set(VALID_ONIE_TLVINFO_TYPE_CODES_LIST), "Module {}: Invalid TlvInfo type code found".format(i))

            # Ensure that we were able to obtain the minimum required type codes
            self.expect(set(MINIMUM_REQUIRED_TYPE_CODES_LIST) <= set(syseeprom_type_codes_list), "Module {}: Minimum required TlvInfo type codes not provided".format(i))

            # Ensure the base MAC address is sane
            base_mac = syseeprom_info_dict[ONIE_TLVINFO_TYPE_CODE_BASE_MAC_ADDR]
            self.expect(base_mac is not None, "Module {}: Failed to retrieve base MAC address".format(i))
            self.expect(re.match(REGEX_MAC_ADDRESS, base_mac), "Module {}: Base MAC address appears to be incorrect".format(i))

            # Ensure the serial number is sane
            serial = syseeprom_info_dict[ONIE_TLVINFO_TYPE_CODE_SERIAL_NUMBER]
            self.expect(serial is not None, "Module {}: Failed to retrieve serial number".format(i))
            self.expect(re.match(REGEX_SERIAL_NUMBER, serial), "Module {}: Serial number appears to be incorrect".format(i))
        self.assert_expectations()

    def test_components(self, duthost, localhost, platform_api_conn):
        if self.num_modules == 0:
            pytest.skip("No modules found on device")

        # TODO: Ensure the number of components and that the returned list is correct for this platform
        for mod_idx in range(self.num_modules):
            try:
                num_components = int(module.get_num_components(platform_api_conn, mod_idx))
            except:
                pytest.fail("Module {}: num_components is not an integer".format(mod_idx))

            component_list = module.get_all_components(platform_api_conn, mod_idx)
            if not self.expect(component_list is not None, "Module {}: Failed to retrieve components".format(mod_idx)):
                continue

            self.expect(isinstance(component_list, list) and len(component_list) == num_components, "Module {}: Components appear to be incorrect".format(mod_idx))

            for comp_idx in range(num_components):
                component = module.get_component(platform_api_conn, mod_idx, comp_idx)
                self.expect(component and component == component_list[mod_idx], "Module {}: Component {} is incorrect".format(mod_idx, comp_idx))
        self.assert_expectations()

    def test_fans(self, duthost, localhost, platform_api_conn):
        if self.num_modules == 0:
            pytest.skip("No modules found on device")

        # TODO: Ensure the number of fans and that the returned list is correct for this platform
        for mod_idx in range(self.num_modules):
            try:
                num_fans = int(module.get_num_fans(platform_api_conn, mod_idx))
            except:
                pytest.fail("Module {}: num_fans is not an integer".format(mod_idx))

            fan_list = module.get_all_fans(platform_api_conn, mod_idx)
            if not self.expect(fan_list is not None, "Module {}: Failed to retrieve fans".format(mod_idx)):
                continue

            self.expect(isinstance(fan_list, list) and len(fan_list) == num_fans, "Module {}: Fans appear to be incorrect".format(mod_idx))

            for fan_idx in range(num_fans):
                fan = module.get_fan(platform_api_conn, mod_idx, fan_idx)
                self.expect(fan and fan == fan_list[mod_idx], "Module {}: Fan {} is incorrect".format(mod_idx, fan_idx))
        self.assert_expectations()

    def test_psus(self, duthost, localhost, platform_api_conn):
        if self.num_modules == 0:
            pytest.skip("No modules found on device")

        # TODO: Ensure the number of PSUs and that the returned list is correct for this platform
        for mod_idx in range(self.num_modules):
            try:
                num_psus = int(module.get_num_psus(platform_api_conn, mod_idx))
            except:
                pytest.fail("Module {}: num_psus is not an integer".format(mod_idx))

            psu_list = module.get_all_psus(platform_api_conn, mod_idx)
            if not self.expect(psu_list is not None, "Module {}: Failed to retrieve PSUs".format(mod_idx)):
                continue

            self.expect(isinstance(psu_list, list) and len(psu_list) == num_psus, "Module {}: PSUs appear to be incorrect".format(mod_idx))

            for psu_idx in range(num_psus):
                psu = module.get_psu(platform_api_conn, mod_idx, psu_idx)
                self.expect(psu and psu == psu_list[mod_idx], "Module {}: PSU {} is incorrect".format(mod_idx, psu_idx))
        self.assert_expectations()

    def test_thermals(self, duthost, localhost, platform_api_conn):
        if self.num_modules == 0:
            pytest.skip("No modules found on device")

        # TODO: Ensure the number of thermals and that the returned list is correct for this platform
        for mod_idx in range(self.num_modules):
            try:
                num_thermals = int(module.get_num_thermals(platform_api_conn, mod_idx))
            except:
                pytest.fail("Module {}: num_thermals is not an integer".format(mod_idx))

            thermal_list = module.get_all_thermals(platform_api_conn, mod_idx)
            if not self.expect(thermal_list is not None, "Module {}: Failed to retrieve thermals".format(mod_idx)):
                continue

            self.expect(isinstance(thermal_list, list) and len(thermal_list) == num_thermals, "Module {}: Thermals appear to be incorrect".format(mod_idx))

            for therm_idx in range(num_thermals):
                thermal = module.get_thermal(platform_api_conn, mod_idx, therm_idx)
                self.expect(thermal and thermal == thermal_list[mod_idx], "Thermal {} is incorrect".format(mod_idx, therm_idx))
        self.assert_expectations()

    def test_sfps(self, duthost, localhost, platform_api_conn):
        if self.num_modules == 0:
            pytest.skip("No modules found on device")

        # TODO: Ensure the number of SFPs and that the returned list is correct for this platform
        for mod_idx in range(self.num_modules):
            try:
                num_sfps = int(module.get_num_sfps(platform_api_conn, mod_idx))
            except:
                pytest.fail("Module {}: num_sfps is not an integer".format(mod_idx))

            sfp_list = module.get_all_sfps(platform_api_conn, mod_idx)
            if not self.expect(sfp_list is not None, "Module {}: Failed to retrieve SFPs".format(mod_idx)):
               continue

            self.expect(isinstance(sfp_list, list) and len(sfp_list) == num_sfps, "Module {}: SFPs appear to be incorrect".format(mod_idx))

            for sfp_idx in range(num_sfps):
                sfp = module.get_sfp(platform_api_conn, mod_idx, sfp_idx)
                self.expect(sfp and sfp == sfp_list[mod_idx], "Module {}: SFP {} is incorrect".format(mod_idx, sfp_idx))
        self.assert_expectations()
