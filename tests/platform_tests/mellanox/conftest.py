import pytest

from tests.platform_tests.mellanox.software_control_helper import sc_supported, sc_ms_sku, get_ports_supporting_sc, \
    check_sc_sai_attribute_value


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
