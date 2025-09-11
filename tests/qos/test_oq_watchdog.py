"""SAI thrift-based tests for the OQ watchdog feature in SONiC.

This set of test cases verifies OQ watchdog behavior. These are dataplane
tests that depend on the SAI thrift library in order to pause ports and read
drop counters.

Parameters:
    --ptf_portmap <filename> (str): file name of port index to DUT interface alias map. Default is None.
        In case a filename is not provided, a file containing a port indices to aliases map will be generated.

    --qos_swap_syncd (bool): Used to install the RPC syncd image before running the tests. Default is True.

    --qos_dst_ports (list) Indices of available DUT test ports to serve as destination ports. Note: This is not port
        index on DUT, rather an index into filtered (excludes lag member ports) DUT ports. Plan is to randomize port
        selection. Default is [0, 1, 3].

    --qos_src_ports (list) Indices of available DUT test ports to serve as source port. Similar note as in
        qos_dst_ports applies. Default is [2].
"""

import logging
import pytest

from tests.common.fixtures.duthost_utils import dut_qos_maps, \
    separated_dscp_to_tc_map_on_uplink                                                      # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                     # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory                     # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                        # noqa F401
from .qos_sai_base import QosSaiBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

PKTS_NUM = 100


@pytest.fixture(scope="function")
def ignore_log_oq_watchdog(duthosts, loganalyzer):
    if not loganalyzer:
        yield
        return
    ignore_list = [r".*HARDWARE_WATCHDOG.*", r".*soft_reset*"]
    for dut in duthosts:
        for line in ignore_list:
            loganalyzer[dut.hostname].ignore_regex.append(line)
    yield
    return


class TestOqWatchdog(QosSaiBase):
    """TestVoqWatchdog derives from QosSaiBase and contains collection of OQ watchdog test cases.
    """
    @pytest.fixture(scope="class", autouse=True)
    def check_skip_oq_watchdog_test(self, get_src_dst_asic_and_duts):
        if not self.oq_watchdog_enabled(get_src_dst_asic_and_duts):
            pytest.skip("OQ watchdog test is skipped since OQ watchdog is not enabled.")

    def testOqWatchdog(
            self, ptfhost, dutTestParams, dutConfig, dutQosConfig,
            get_src_dst_asic_and_duts, ignore_log_oq_watchdog,
            disable_voq_watchdog_function_scope
    ):
        """
            Test OQ watchdog functionality.
            Test steps:
                1. block voq7, sys_port scheduler set Q7 credit_pir to 0
                2. fill leakout of Q7 by ping, make sure no packet dequeue/enqueue in OQ7 afterwards
                3. block oq0, sys_port scheduler set Q0 transmit_pir to 0
                4. send traffic on Q0, oq watchdog should be triggered in about 5 seconds
                5. Unblock voq7 and oq0 to restore the system state
                6. Run TrafficSanityTest to verify the system state is restored
            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
            Returns:
                None
            Raises:
                RunAnsibleModuleFail if ptf test fails
        """

        dst_dut = get_src_dst_asic_and_duts['dst_dut']
        dst_asic_index = get_src_dst_asic_and_duts['dst_asic_index']
        dst_port = dutConfig['dutInterfaces'][dutConfig["testPorts"]["dst_port_id"]]
        interfaces = self.get_port_channel_members(dst_dut, dst_port)

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dscp": 8,
            "queue_id": 0,
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "dst_interfaces": interfaces,
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "packet_size": 1350,
            "pkts_num": PKTS_NUM,
            "oq_watchdog_enabled": True,
        })

        # Run TrafficSanityTest to verify the system in good state before starting the test
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.TrafficSanityTest",
            testParams=testParams)

        try:
            # Block voq7
            original_pir_voq7 = self.block_queue(dst_dut, dst_port, 7, "voq", dst_asic_index)
            # Fill leakout of Q7 by ping
            dst_port_ip = dutConfig["testPorts"]["dst_port_ip"]
            cmd_opt = "sudo ip netns exec asic{}".format(dst_asic_index)
            if not dst_dut.sonichost.is_multi_asic:
                cmd_opt = ""
            dst_dut.shell("{} ping -I {} -c 50 {} -i 0 -w 0 || true".format(cmd_opt, dst_port, dst_port_ip))

            # Block oq0
            original_pir_oq0 = self.block_queue(dst_dut, dst_port, 0, "oq", dst_asic_index)

            self.runPtfTest(
                ptfhost, testCase="sai_qos_tests.OqWatchdogTest",
                testParams=testParams)

        finally:
            # Unblock voq7 and oq0 to restore the system state
            self.unblock_queue(dst_dut, dst_port, 7, "voq", original_pir_voq7, dst_asic_index)
            self.unblock_queue(dst_dut, dst_port, 0, "oq", original_pir_oq0, dst_asic_index)

            self.runPtfTest(
                ptfhost, testCase="sai_qos_tests.TrafficSanityTest",
                testParams=testParams)
