"""
Verify that the hw-management service is running properly

This script covers test case 'Ensure that the hw-management service is running properly' in the SONiC platform test
plan: https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import pytest
from check_hw_mgmt_service import check_hw_management_service

pytestmark = [
    pytest.mark.asic('mellanox'),
    pytest.mark.topology('any')
]

def test_hw_management_service_status(duthosts, rand_one_dut_hostname):
    """This test case is to verify that the hw-management service is running properly
    """
    duthost = duthosts[rand_one_dut_hostname]
    check_hw_management_service(duthost)
