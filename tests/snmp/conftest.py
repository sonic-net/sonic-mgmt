import pytest
from tests.common.platform.interface_utils import get_port_map
from tests.common.utilities import wait_until

@pytest.fixture(scope="module", autouse=True)
def setup_check_snmp_ready(duthosts):
    for duthost in duthosts:
        assert wait_until(300, 20, duthost.is_service_fully_started, "snmp"), "SNMP service is not running"

def pytest_addoption(parser):
    """
    Adds options to pytest that are used by the snmp tests.
    """
    parser.addoption(
                    "--percentage",
                    action="store",
                    default=False,
                    help="Set percentage difference for snmp test",
                    type=int)

@pytest.fixture(scope='function')
def skip_if_no_ports(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Fixture that skips test execution in case dut doesn't have data ports
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    for asic_index in duthost.get_frontend_asic_ids():
        interface_list = get_port_map(duthost, asic_index)
        if not interface_list:
            pytest.skip("This test is not supported as there are no data ports in dut")

