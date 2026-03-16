"""SAI thrift-based test for the VOQ Credit-WD-Del counter on single-ASIC SONiC devices.

This test case verifies that the VOQ Credit-WD-Del counter increments as expected on
a single-ASIC broadcom-dnx VOQ device. It uses the SAI thrift library to disable TX
on a destination port, sends traffic via PTF to back up the VOQ, and waits for the
credit watchdog to fire and increment the Credit-WD-Del/pkts counter.

For multi-ASIC broadcom-dnx VOQ devices, see tests/voq/test_voq_counter.py which
uses bcmcmd to disable SFI ports.

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
    separated_dscp_to_tc_map_on_uplink                                                      # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                     # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory                     # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                        # noqa: F401
from .qos_sai_base import QosSaiBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

PKTS_NUM = 100


class TestVoqCreditWDCounter(QosSaiBase):
    """TestVoqCreditWDCounter verifies the VOQ Credit-WD-Del counter on single-ASIC broadcom-dnx devices.

    The test disables TX on a destination port via SAI thrift, sends traffic via PTF to
    back up the VOQ, and waits for the credit watchdog to fire and increment Credit-WD-Del/pkts.
    """

    @pytest.fixture(scope="class", autouse=True)
    def check_skip_voq_credit_wd_counter(self, get_src_dst_asic_and_duts):
        src_dut = get_src_dst_asic_and_duts['src_dut']
        if src_dut.facts.get('platform_asic') != 'broadcom-dnx':
            pytest.skip("VOQ Credit-WD-Del counter test is only supported on broadcom-dnx ASIC")
        if src_dut.is_multi_asic:
            pytest.skip(
                "VOQ Credit-WD-Del counter test in qos package targets single-ASIC devices; "
                "for multi-ASIC devices see tests/voq/test_voq_counter.py"
            )

    def testVoqCreditWDCounter(
            self, ptfhost, dutTestParams, dutConfig, dutQosConfig,
            duthosts, get_src_dst_asic_and_duts
    ):
        """
        Test that the VOQ Credit-WD-Del counter increments on a single-ASIC broadcom-dnx device.

        The test disables TX on a destination port via SAI thrift (without disabling the
        credit watchdog), sends traffic to back up the VOQ, and waits for the credit
        watchdog to fire and increment Credit-WD-Del/pkts.

        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)
            dutTestParams (Fixture, dict): DUT host test params
            dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs,
                test port IPs, and test ports
            dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
            duthosts: DUT hosts
            get_src_dst_asic_and_duts: Source/destination ASIC and DUT info

        Returns:
            None

        Raises:
            RunAnsibleModuleFail if ptf test fails
        """
        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dscp": 8,
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "packet_size": 1350,
            "pkts_num": PKTS_NUM,
        })

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.VoqCreditWDCounterTest",
            testParams=testParams)
