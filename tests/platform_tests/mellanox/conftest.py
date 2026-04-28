import pytest
import json

from tests.platform_tests.mellanox.software_control_helper import sc_supported, sc_ms_sku, get_ports_supporting_sc, \
    check_sc_sai_attribute_value

HWSKU_JSON_PATH = "/usr/share/sonic/device/{}/{}/hwsku.json"
CPO_PORT_TYPE = "CPO"


def pytest_addoption(parser):
    '''
        Adds option to Mellanox specific pytest

        Args:
            parser: pytest parser object

        Returns:
            None
    '''
    mellanox_group = parser.getgroup("Mellanox test suite options")

    mellanox_group.addoption(
        "--mock_any_testbed",
        action="store_true",
        help="Mock on testbeds which do not support PSU power thresholds",
    )


@pytest.fixture(scope="module")
def is_sw_control_feature_enabled(duthost):
    return sc_supported(duthost) and sc_ms_sku(duthost) and check_sc_sai_attribute_value(duthost)


@pytest.fixture(scope="module")
def get_sw_control_ports(duthost, is_sw_control_feature_enabled, conn_graph_facts):
    if is_sw_control_feature_enabled:
        sw_ports = get_ports_supporting_sc(duthost)
        return sw_ports


@pytest.fixture(scope="module")
def is_cpo_supported(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    platform = duthost.facts["platform"]
    hwsku = duthost.facts['hwsku']
    f_path = HWSKU_JSON_PATH.format(platform, hwsku)
    if not duthost.stat(path=f_path)["stat"]["exists"]:
        return False

    output = duthost.command(f"cat {f_path}")["stdout"]
    hwsku_info = json.loads(output)
    if hwsku_info.get('interfaces'):
        for intf in hwsku_info['interfaces']:
            if hwsku_info['interfaces'][intf].get('port_type') == CPO_PORT_TYPE:
                return True
    return False
