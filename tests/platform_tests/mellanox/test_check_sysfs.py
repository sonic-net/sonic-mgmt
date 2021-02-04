"""
Check SYSFS

This script covers the test case 'Check SYSFS' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import pytest
from check_sysfs import check_sysfs

pytestmark = [
    pytest.mark.asic('mellanox'),
    pytest.mark.topology('any')
]

def test_check_hw_mgmt_sysfs(duthosts, rand_one_dut_hostname):
    """This test case is to check the symbolic links under /var/run/hw-management
    """
    duthost = duthosts[rand_one_dut_hostname]
    check_sysfs(duthost)


def test_hw_mgmt_sysfs_mapped_to_pmon(duthosts, rand_one_dut_hostname):
    """This test case is to verify that the /var/run/hw-management folder is mapped to pmon container
    """
    duthost = duthosts[rand_one_dut_hostname]
    logging.info("Verify that the /var/run/hw-management folder is mapped to the pmon container")
    files_under_dut = set(duthost.command("find /var/run/hw-management")["stdout_lines"])
    files_under_pmon = set(duthost.command("docker exec pmon find /var/run/hw-management")["stdout_lines"])
    assert files_under_dut == files_under_pmon, "Folder /var/run/hw-management is not mapped to pmon"
