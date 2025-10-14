"""SAI thrift-based tests for the VOQ watchdog feature in SONiC.

This set of test cases verifies VOQ watchdog behavior. These are dataplane
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
from .qos_helpers import voq_watchdog_enabled, modify_voq_watchdog
from .qos_sai_base import QosSaiBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

PKTS_NUM = 100


@pytest.fixture(scope="function", autouse=True)
def ignore_log_voq_watchdog(duthosts, loganalyzer):
    if not loganalyzer:
        yield
        return
    ignore_list = [r".*HARDWARE_WATCHDOG.*", r".*soft_reset*", r".*VOQ Appears to be stuck*"]
    for dut in duthosts:
        for line in ignore_list:
            loganalyzer[dut.hostname].ignore_regex.append(line)
    yield
    return


class TestVoqWatchdog(QosSaiBase):
    """TestVoqWatchdog derives from QosSaiBase and contains collection of VOQ watchdog test cases.
    """
    @pytest.fixture(scope="class", autouse=True)
    def check_skip_voq_watchdog_test(self, get_src_dst_asic_and_duts):
        if not voq_watchdog_enabled(get_src_dst_asic_and_duts):
            pytest.skip("Voq watchdog test is skipped since voq watchdog is not enabled.")

    @pytest.mark.parametrize("enable_voq_watchdog", [True, False])
    def testVoqWatchdog(
            self, ptfhost, dutTestParams, dutConfig, dutQosConfig,
            duthosts, get_src_dst_asic_and_duts, enable_voq_watchdog
    ):
        """
            Test VOQ watchdog
            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                enable_voq_watchdog (bool): Whether to enable or disable VOQ watchdog during the test
            Returns:
                None
            Raises:
                RunAnsibleModuleFail if ptf test fails
        """

        try:
            if not enable_voq_watchdog:
                modify_voq_watchdog(duthosts, get_src_dst_asic_and_duts, enable=False)

            testParams = dict()
            testParams.update(dutTestParams["basicParams"])
            testParams.update({
                "dscp": 8,
                "queue_idx": 0,
                "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
                "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
                "src_port_id": dutConfig["testPorts"]["src_port_id"],
                "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
                "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
                "packet_size": 1350,
                "pkts_num": PKTS_NUM,
                "voq_watchdog_enabled": enable_voq_watchdog,
                "dutInterfaces": dutConfig["dutInterfaces"],
                "testPorts": dutConfig["testPorts"],
            })

            self.runPtfTest(
                ptfhost, testCase="sai_qos_tests.VoqWatchdogTest",
                testParams=testParams)

            self.runPtfTest(
                ptfhost, testCase="sai_qos_tests.TrafficSanityTest",
                testParams=testParams)

        finally:
            if not enable_voq_watchdog:
                modify_voq_watchdog(duthosts, get_src_dst_asic_and_duts, enable=True)
