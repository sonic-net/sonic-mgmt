import pytest
from tests.common.helpers.assertions import pytest_assert as assertion
from tests.common.platform.transceiver_utils import parse_sfp_eeprom_infos
from tests.common.mellanox_data import (
    get_supported_available_optic_ifaces,
    is_sw_control_feature_enabled,
)
DEFAULT_COLLECTED_PORTS_NUM = 5


def pytest_addoption(parser):
    """
    Add command line options for pytest
    """
    parser.addoption(
        "--collected-ports-num",
        action="store",
        default=DEFAULT_COLLECTED_PORTS_NUM,
        type=int,
        help="Number of ports to collect for testing (default: {})".format(DEFAULT_COLLECTED_PORTS_NUM)
    )


@pytest.fixture(scope="session")
def collected_ports_num(request):
    """
    Fixture to get the number of ports to collect from command line argument
    """
    return request.config.getoption("--collected-ports-num")


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

    def is_setting_support_feature(self, dut):
        pass


class TestMACFaultMellanox(TestMACFaultGeneral):

    def return_available_interfaces(self, dut, parsed_presence):
        supported_available_interfaces = []
        failed_api_ports = []
        eeprom_infos = dut.shell("sudo sfputil show eeprom -d")['stdout']
        eeprom_infos = parse_sfp_eeprom_infos(eeprom_infos)
        supported_available_interfaces, failed_api_ports = (
            get_supported_available_optic_ifaces(
                eeprom_infos, parsed_presence
            )
        )
        assertion(supported_available_interfaces,
                  "No interfaces with SFP detected. Cannot proceed with tests.")
        return supported_available_interfaces, failed_api_ports

    def is_setting_support_feature(self, dut):
        return is_sw_control_feature_enabled(dut)
