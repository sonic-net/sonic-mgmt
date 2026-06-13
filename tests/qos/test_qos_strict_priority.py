"""Test case for default strict priority scheduling validation.

Covers test gap issue #22405:
https://github.com/sonic-net/sonic-mgmt/issues/22405

In default strict priority scheduling, traffic classes (TCs) are served in
descending order of priority (TC7 > TC6 > ... > TC0). Existing tests only
validate PIR/CIR in strict priority schedulers but do not verify the actual
priority ordering across TCs.

This test validates that under congestion, higher priority TCs are served
before lower priority TCs.
"""

import logging
import pytest

from tests.common.fixtures.conn_graph_facts import fanout_graph_facts, conn_graph_facts     # noqa: F401
from tests.common.fixtures.duthost_utils import dut_qos_maps                                # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                      # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory                      # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                         # noqa: F401
from tests.common.fixtures.ptfhost_utils import ptf_portmap_file                             # noqa: F401
from tests.common.dualtor.dual_tor_utils import dualtor_ports, is_tunnel_qos_remap_enabled   # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from .qos_sai_base import QosSaiBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]


class TestQosSaiStrictPriority(QosSaiBase):
    """Test class for validating default strict priority scheduling behavior.

    Under default strict priority, the scheduler should serve traffic classes
    in descending priority order. This means TC7 has the highest priority and
    TC0 has the lowest. When all TCs compete for bandwidth on the same egress
    port, the higher priority TC should be fully served before any lower
    priority TC receives bandwidth.

    This test complements the existing DWRR/WRR tests by specifically
    validating priority ordering rather than rate limiting (PIR/CIR).
    """

    def testQosSaiStrictPriorityScheduling(
        self, ptfhost, duthosts, get_src_dst_asic_and_duts, dutTestParams,
        dutConfig, dutQosConfig, skip_src_dst_different_asic,
        change_lag_lacp_timer
    ):
        """
        Test QoS SAI Default Strict Priority Scheduling.

        Validates that under congestion, traffic classes are served in
        descending priority order (TC7 > TC6 > ... > TC0).

        Test Steps:
            1. Send equal amounts of traffic for multiple TCs simultaneously
               to the same egress port, creating congestion.
            2. Read egress queue counters to determine how many packets each
               TC forwarded.
            3. Verify that higher priority TCs forwarded at least as many
               packets as lower priority TCs.
            4. Verify that the highest priority TC achieves near line-rate
               throughput.

        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)
            dutTestParams (Fixture, dict): DUT host test params
            dutConfig (Fixture, dict): Map of DUT config containing dut
                interfaces, test port IDs, test port IPs, and test ports
            dutQosConfig (Fixture, dict): Map containing DUT host QoS
                configuration

        Returns:
            None

        Raises:
            RunAnsibleModuleFail if ptf test fails
        """
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        qosConfig = dutQosConfig["param"]

        if "strict_priority" in qosConfig.get(portSpeedCableLength, {}):
            qosConfigSp = qosConfig[portSpeedCableLength]["strict_priority"]
        elif "strict_priority" in qosConfig:
            qosConfigSp = qosConfig["strict_priority"]
        else:
            pytest.skip(
                "strict_priority test parameters not defined in QoS config"
            )

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts)

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update(qosConfigSp)
        testParams.update({
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "pkts_num_leak_out":
                qosConfig[portSpeedCableLength]["pkts_num_leak_out"],
            "hwsku": dutTestParams["hwsku"],
            "topo": dutTestParams["topo"],
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = \
                dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "pkts_num_egr_mem" in list(
            qosConfig[portSpeedCableLength].keys()
        ):
            testParams["pkts_num_egr_mem"] = \
                qosConfig[portSpeedCableLength]["pkts_num_egr_mem"]

        # Dry run first to normalize queue scheduling state,
        # following the same pattern as testQosSaiDwrr.
        testParams["dry_run"] = True
        self.runPtfTest(
            ptfhost,
            testCase="sai_qos_tests.StrictPriorityTest",
            testParams=testParams,
        )

        testParams["dry_run"] = False
        self.runPtfTest(
            ptfhost,
            testCase="sai_qos_tests.StrictPriorityTest",
            testParams=testParams,
        )
