import pytest
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
