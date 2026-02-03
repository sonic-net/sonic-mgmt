from tests.common.helpers.assertions import pytest_assert as assertion
from tests.common.platform.transceiver_utils import parse_sfp_eeprom_infos
from tests.common.mellanox_data import (
    get_supported_available_optical_interfaces,
    is_nvidia_platform_with_sw_control_enabled,
)


class TestMACFaultGeneral:

    def return_available_interfaces(self, dut, parsed_presence):
        interfaces = list(dut.show_and_parse("show interfaces status"))
        supported_available_interfaces = [
            intf["interface"] for intf in interfaces
            if parsed_presence.get(intf["interface"]) == "Present"
        ]

        assertion(supported_available_interfaces,
                  "No interfaces with SFP detected. Cannot proceed with tests.")
        return supported_available_interfaces, []

    def is_platform_setting_supported(self, dut):
        return True


class TestMACFaultMellanox(TestMACFaultGeneral):

    def return_available_interfaces(self, dut, parsed_presence):
        supported_available_interfaces = []
        failed_api_ports = []
        eeprom_infos = dut.shell("sudo sfputil show eeprom -d")['stdout']
        eeprom_infos = parse_sfp_eeprom_infos(eeprom_infos)
        supported_available_interfaces, failed_api_ports = (
            get_supported_available_optical_interfaces(
                eeprom_infos, parsed_presence, return_failed_api_ports=True
            )
        )
        assertion(supported_available_interfaces,
                  "No interfaces with SFP detected. Cannot proceed with tests.")
        return supported_available_interfaces, failed_api_ports

    def is_platform_setting_supported(self, dut):
        return is_nvidia_platform_with_sw_control_enabled(dut)
