"""
Datapath power zone fault insertion tests
"""
import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import wait_for_startup, reboot, REBOOT_TYPE_COLD
from tests.common.platform.processes_utils import wait_critical_processes
from tests.cisco.common.utils import skip_if_sim


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

class TestDatapathPZ:

    skip_tests = False # Flag to skip test cases if needed

    def test_pcie_devices(self, duthost, skip_if_sim):
    
        result = duthost.command("show platform pcie -c")
        if not "PASSED" in str(result):
            TestDatapathPZ.skip_tests = True
            assert False, "Not all expected devices are present on PCIe"
    
    def test_datapath_powerzone_fault(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, skip_if_sim):
        """
        @summary: Trigger datapath power zone fault
        """

        if TestDatapathPZ.skip_tests:
            pytest.skip("Skipped due to test_pcie_devices failure")
    
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    
        is_sup = duthost.get_facts().get("modular_chassis") and duthost.is_supervisor_node()
        if is_sup:
            pytest.skip("Currently not support on RP")
    
        result = duthost.command("/opt/cisco/bin/npu_shutdown.py")
        assert "All rails powered off" in str(result), "Error in bringing datapath down"
    
        # Check PCIe failure
        result = duthost.command("show platform pcie -c")
        assert "FAILED" in str(result), "Expected NPUs to be missing on PCIe after datapath down."
    
    
        # TBD: Check Voltage fault
    
        reboot(duthost, localhost, reboot_type=REBOOT_TYPE_COLD)
    
        wait_critical_processes(duthost)

        result = duthost.command("show platform pcie -c")
        assert "PASSED" in str(result), "All expected devices are not present on PCIe on reboot"
    

