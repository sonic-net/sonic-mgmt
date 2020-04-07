import pytest
from common.utilities import wait_until

@pytest.fixture(scope="module", autouse=True)
def setup_check_snmp_ready(testbed_devices):
    dut = testbed_devices['dut']
    assert wait_until(300, 20, dut.is_service_fully_started, "snmp"), "SNMP service is not running"
