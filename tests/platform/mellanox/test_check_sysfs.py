"""
Check SYSFS

This script covers the test case 'Check SYSFS' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import os

try:
    from platform_fixtures import conn_graph_facts
except ImportError:
    import sys
    current_file_dir = os.path.dirname(os.path.realpath(__file__))
    parent_folder = os.path.normpath(os.path.join(current_file_dir, "../"))
    if parent_folder not in sys.path:
        sys.path.append(parent_folder)
    from platform_fixtures import conn_graph_facts
from check_sysfs import check_sysfs


def test_check_hw_mgmt_sysfs(testbed_devices, conn_graph_facts):
    """This test case is to check the symbolic links under /var/run/hw-management
    """
    ans_host = testbed_devices["dut"]
    check_sysfs(ans_host, conn_graph_facts["device_conn"])
