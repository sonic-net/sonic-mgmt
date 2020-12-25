import pytest
from tests.common.utilities import wait_until

@pytest.fixture(scope="module", autouse=True)
def setup_check_snmp_ready(pre_selected_dut):
    assert wait_until(300, 20, pre_selected_dut.is_service_fully_started, "snmp"), "SNMP service is not running"
