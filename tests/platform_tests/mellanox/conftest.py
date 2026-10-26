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
def is_sw_control_feature_enabled(rand_selected_dut):
    return (sc_supported(rand_selected_dut) and sc_ms_sku(rand_selected_dut)
            and check_sc_sai_attribute_value(rand_selected_dut))


@pytest.fixture(scope="module")
def get_sw_control_ports(rand_selected_dut, is_sw_control_feature_enabled, conn_graph_facts):
    if not is_sw_control_feature_enabled:
        return []
    return get_ports_supporting_sc(rand_selected_dut)


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


def get_cpo_ports(duthost):
    """Return the set of port names in CONFIG_DB whose cage is CPO per hwsku.json.

    hwsku.json only lists the parent port of each breakout group, so breakout
    child ports (e.g. SN6810_LD Ethernet513 of non-CPO Ethernet512, or Ethernet9
    of CPO Ethernet8) are missing from it. Every CONFIG_DB port is therefore
    mapped to the hwsku.json port sharing its `index` (physical cage) and
    inherits that port's `port_type`. Returns an empty set if hwsku.json
    doesn't exist (no information to filter on).
    """
    platform = duthost.facts["platform"]
    hwsku = duthost.facts['hwsku']
    f_path = HWSKU_JSON_PATH.format(platform, hwsku)
    if not duthost.stat(path=f_path)["stat"]["exists"]:
        return set()
    output = duthost.command(f"cat {f_path}")["stdout"]
    hwsku_interfaces = json.loads(output).get('interfaces') or {}
    port_config = json.loads(duthost.command("sudo sonic-cfggen -d --var-json PORT")["stdout"])
    cpo_indexes = {port_config[intf].get('index') for intf, intf_info in hwsku_interfaces.items()
                   if intf in port_config and intf_info.get('port_type') == CPO_PORT_TYPE}
    return {intf for intf, intf_info in port_config.items() if intf_info.get('index') in cpo_indexes}
