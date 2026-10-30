import json
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert as assertion
from tests.common.platform.device_utils import get_primary_fanout, get_primary_fanout_peer
from tests.common.platform.interface_utils import get_physical_port_indices
from tests.common.platform.transceiver_utils import parse_sfp_eeprom_infos
from tests.common.mellanox_data import (
    get_supported_available_optic_ifaces,
    is_sw_control_feature_enabled,
)

DEFAULT_COLLECTED_PORTS_NUM = 5
cmd_sfp_presence = "sudo sfpshow presence"


def get_sfp_presence(host):
    """Return the 'Port Presence' table of 'sfpshow presence' on a SONiC host as a {port: presence} map"""
    return {entry["port"]: entry["presence"] for entry in host.show_and_parse(cmd_sfp_presence)}


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

    @staticmethod
    def filter_rx_disable_supported_interfaces(dut, interfaces):
        """Exclude interfaces whose module does not support RX disable"""
        port_index_map = get_physical_port_indices(dut, interfaces)
        indexes = sorted({idx for idx in port_index_map.values() if idx is not None})
        cmd = """
cat << EOF > get_rx_disable_supported_indexes.py
from sonic_platform.chassis import Chassis
c = Chassis()
supported = []
for i in {indexes}:
    try:
        api = c.get_sfp(i).get_xcvr_api()
        if api and api.get_rx_disable_support() is True:
            supported.append(i)
    except Exception:
        pass
print(supported)
EOF
""".format(indexes=indexes)
        dut.shell(cmd)
        out = dut.shell("python3 get_rx_disable_supported_indexes.py")["stdout"].strip()
        supported_indexes = set(json.loads(out))
        supported = [intf for intf in interfaces if port_index_map.get(intf) in supported_indexes]
        logging.info("Excluded interfaces without RX disable support: {}".format(
            [intf for intf in interfaces if intf not in supported]))
        return supported

    @classmethod
    def filter_fanout_resettable_interfaces(cls, dut, interfaces, fanouthosts):
        """Keep interfaces whose peer is a present fanout module that can be reset with sfputil"""
        # Peers are looked up on the primary fanout only, so one presence table covers every interface
        primary_fanout = get_primary_fanout(dut, fanouthosts)
        # sfputil only exists on SONiC fanouts, FanoutHost also wraps onyx/eos/aos/ixia
        if not primary_fanout or primary_fanout.os != 'sonic':
            logging.info("{} has no SONiC fanout peer, no interface has a resettable peer".format(dut.hostname))
            return []
        peer_presence = get_sfp_presence(primary_fanout.host)

        selected_ifaces = []
        for intf in interfaces:
            _, fanout_port = get_primary_fanout_peer(dut, intf, fanouthosts)
            if fanout_port and peer_presence.get(fanout_port) == "Present":
                selected_ifaces.append(intf)

        logging.info("Excluded interfaces without a resettable peer: {}".format(
            [intf for intf in interfaces if intf not in selected_ifaces]))
        return selected_ifaces


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
