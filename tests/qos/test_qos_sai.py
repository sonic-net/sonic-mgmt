"""SAI thrift-based tests for the QoS feature in SONiC.

This set of test cases verifies QoS, buffer behavior, and buffer drop counter behavior. These are dataplane
tests that depend on the SAI thrift library in order to pause ports/queues and read buffer drop counters as well
as generic drop counters.

Parameters:
    --ptf_portmap <filename> (str): file name of port index to DUT interface alias map. Default is None.
        In case a filename is not provided, a file containing a port indices to aliases map will be generated.

    --disable_test (bool): Disables experimental QoS SAI test cases. Default is True.

    --qos_swap_syncd (bool): Used to install the RPC syncd image before running the tests. Default is True.

    --qos_dst_ports (list) Indices of available DUT test ports to serve as destination ports. Note: This is not port
        index on DUT, rather an index into filtered (excludes lag member ports) DUT ports. Plan is to randomize port
        selection. Default is [0, 1, 3].

    --qos_src_ports (list) Indices of available DUT test ports to serve as source port. Similar note as in
        qos_dst_ports applies. Default is [2].
"""

import logging
import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import ptf_portmap_file          # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from qos_sai_base import QosSaiBase, QosSaiBaseMasic

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

PTF_PORT_MAPPING_MODE = 'use_orig_interface'

class TestQosSai(QosSaiBase):
    """TestQosSai derives from QosSaiBase and contains collection of QoS SAI test cases.

    Note:
        This test implicitly verifies that buffer drop counters (i.e. SAI_PORT_IN/OUT_DROPPED_PKTS)
        are working as expected by verifying the drop counters everywhere that normal drop counters
        are verified.
    """

    SUPPORTED_HEADROOM_SKUS = [
        'Arista-7060CX-32S-C32',
        'Celestica-DX010-C32',
        'Arista-7260CX3-D108C8',
        'Force10-S6100',
        'Arista-7260CX3-Q64',
        'Arista-7050CX3-32S-C32'
    ]

    BREAKOUT_SKUS = ['Arista-7050-QX-32S']

    def testParameter(
        self, duthost, dutConfig, dutQosConfig, ingressLosslessProfile,
        ingressLossyProfile, egressLosslessProfile
    ):
        logger.info("asictype {}".format(duthost.facts["asic_type"]))
        logger.info("config {}".format(dutConfig))
        logger.info("qosConfig {}".format(dutQosConfig))

    @pytest.mark.parametrize("xoffProfile", ["xoff_1", "xoff_2"])
    def testQosSaiPfcXoffLimit(
        self, xoffProfile, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        ingressLosslessProfile, egressLosslessProfile
    ):
        """
            Test QoS SAI XOFF limits

            Args:
                xoffProfile (pytest parameter): XOFF profile
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLosslessProfile (Fxiture): Map of egress lossless buffer profile attributes
                egressLosslessProfile (Fxiture): Map of egress lossless buffer profile attributes

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if dutTestParams['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in dutTestParams['topo']:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]["breakout"]
        else:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]
        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dscp": qosConfig[xoffProfile]["dscp"],
            "ecn": qosConfig[xoffProfile]["ecn"],
            "pg": qosConfig[xoffProfile]["pg"],
            "buffer_max_size": ingressLosslessProfile["size"],
            "queue_max_size": egressLosslessProfile["static_th"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "pkts_num_leak_out": qosConfig["pkts_num_leak_out"],
            "pkts_num_trig_pfc": qosConfig[xoffProfile]["pkts_num_trig_pfc"],
            "pkts_num_trig_ingr_drp": qosConfig[xoffProfile]["pkts_num_trig_ingr_drp"],
            "hwsku":dutTestParams['hwsku']
        })
        if "pkts_num_margin" in qosConfig[xoffProfile].keys():
            testParams["pkts_num_margin"] = qosConfig[xoffProfile]["pkts_num_margin"]
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.PFCtest", testParams=testParams
        )

    @pytest.mark.parametrize("xonProfile", ["xon_1", "xon_2"])
    def testQosSaiPfcXonLimit(
        self, xonProfile, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        ingressLosslessProfile
    ):
        """
            Test QoS SAI XON limits

            Args:
                xonProfile (pytest parameter): XON profile
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLosslessProfile (Fxiture): Map of egress lossless buffer profile attributes

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if xonProfile in dutQosConfig["param"][portSpeedCableLength].keys():
            qosConfig = dutQosConfig["param"][portSpeedCableLength]
        else:
            if dutTestParams['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in dutTestParams['topo']:
                qosConfig = dutQosConfig["param"][portSpeedCableLength]["breakout"]
            else:
                qosConfig = dutQosConfig["param"]


        dst_port_count = set([
            dutConfig["testPorts"]["dst_port_id"],
            dutConfig["testPorts"]["dst_port_2_id"],
            dutConfig["testPorts"]["dst_port_3_id"],
        ])

        if len(dst_port_count) != 3:
            pytest.skip("PFC Xon Limit test: Need at least 3 destination ports")

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dscp": qosConfig[xonProfile]["dscp"],
            "ecn": qosConfig[xonProfile]["ecn"],
            "pg": qosConfig[xonProfile]["pg"],
            "buffer_max_size": ingressLosslessProfile["size"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "dst_port_2_id": dutConfig["testPorts"]["dst_port_2_id"],
            "dst_port_2_ip": dutConfig["testPorts"]["dst_port_2_ip"],
            "dst_port_3_id": dutConfig["testPorts"]["dst_port_3_id"],
            "dst_port_3_ip": dutConfig["testPorts"]["dst_port_3_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "pkts_num_trig_pfc": qosConfig[xonProfile]["pkts_num_trig_pfc"],
            "pkts_num_dismiss_pfc": qosConfig[xonProfile]["pkts_num_dismiss_pfc"],
            "pkts_num_leak_out": dutQosConfig["param"][portSpeedCableLength]["pkts_num_leak_out"],
            "hwsku":dutTestParams['hwsku']
        })
        if "pkts_num_hysteresis" in qosConfig[xonProfile].keys():
            testParams["pkts_num_hysteresis"] = qosConfig[xonProfile]["pkts_num_hysteresis"]
        if "pkts_num_margin" in qosConfig[xonProfile].keys():
            testParams["pkts_num_margin"] = qosConfig[xonProfile]["pkts_num_margin"]
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.PFCXonTest", testParams=testParams
        )

    def testQosSaiHeadroomPoolSize(
        self, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        ingressLosslessProfile
    ):
        """
            Test QoS SAI Headroom pool size

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLosslessProfile (Fxiture): Map of egress lossless buffer profile attributes

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        if dutTestParams["hwsku"] not in self.SUPPORTED_HEADROOM_SKUS and dutTestParams["basicParams"]["sonic_asic_type"] != "mellanox":
            pytest.skip("Headroom pool size not supported")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        qosConfig = dutQosConfig["param"][portSpeedCableLength]
        testPortIps = dutConfig["testPortIps"]

        if not 'hdrm_pool_size' in qosConfig.keys():
            pytest.skip("Headroom pool size is not enabled on this DUT")

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "testbed_type": dutTestParams["topo"],
            "dscps": qosConfig["hdrm_pool_size"]["dscps"],
            "ecn": qosConfig["hdrm_pool_size"]["ecn"],
            "pgs": qosConfig["hdrm_pool_size"]["pgs"],
            "src_port_ids": qosConfig["hdrm_pool_size"]["src_port_ids"],
            "src_port_ips": [testPortIps[port]['peer_addr'] for port in qosConfig["hdrm_pool_size"]["src_port_ids"]],
            "dst_port_id": qosConfig["hdrm_pool_size"]["dst_port_id"],
            "dst_port_ip": testPortIps[qosConfig["hdrm_pool_size"]["dst_port_id"]]['peer_addr'],
            "pgs_num": qosConfig["hdrm_pool_size"]["pgs_num"],
            "pkts_num_trig_pfc": qosConfig["hdrm_pool_size"]["pkts_num_trig_pfc"],
            "pkts_num_leak_out": qosConfig["pkts_num_leak_out"],
            "pkts_num_hdrm_full": qosConfig["hdrm_pool_size"]["pkts_num_hdrm_full"],
            "pkts_num_hdrm_partial": qosConfig["hdrm_pool_size"]["pkts_num_hdrm_partial"],
            "hwsku":dutTestParams['hwsku']
        })

        pkts_num_trig_pfc_shp = qosConfig["hdrm_pool_size"].get("pkts_num_trig_pfc_shp")
        if pkts_num_trig_pfc_shp:
            testParams["pkts_num_trig_pfc_shp"] = pkts_num_trig_pfc_shp

        packet_size = qosConfig["hdrm_pool_size"].get("packet_size")
        if packet_size:
            testParams["packet_size"] = packet_size
            testParams["cell_size"] = qosConfig["hdrm_pool_size"]["cell_size"]

        margin = qosConfig["hdrm_pool_size"].get("margin")
        if margin:
            testParams["margin"] = margin

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.HdrmPoolSizeTest",
            testParams=testParams
        )

    def testQosSaiHeadroomPoolWatermark(
        self, duthosts, rand_one_dut_hostname,  ptfhost, dutTestParams,
        dutConfig, dutQosConfig, ingressLosslessProfile, sharedHeadroomPoolSize,
        resetWatermark
    ):
        """
            Test QoS SAI Headroom pool watermark

            Args:
                duthosts (AnsibleHost): Dut hosts
                rand_one_dut_hostname (AnsibleHost): select one of the duts in multi dut testbed
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLosslessProfile (Fxiture): Map of egress lossless buffer profile attributes
                resetWatermark (Fixture): reset watermarks

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        duthost = duthosts[rand_one_dut_hostname]
        cmd_output = duthost.shell("show headroom-pool watermark", module_ignore_errors=True)
        if dutTestParams["hwsku"] not in self.SUPPORTED_HEADROOM_SKUS or cmd_output['rc'] != 0:
            pytest.skip("Headroom pool watermark is not supported")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        qosConfig = dutQosConfig["param"][portSpeedCableLength]
        testPortIps = dutConfig["testPortIps"]
        if not 'hdrm_pool_size' in qosConfig.keys():
            pytest.skip("Headroom pool size is not enabled on this DUT")

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "testbed_type": dutTestParams["topo"],
            "dscps": qosConfig["hdrm_pool_size"]["dscps"],
            "ecn": qosConfig["hdrm_pool_size"]["ecn"],
            "pgs": qosConfig["hdrm_pool_size"]["pgs"],
            "src_port_ids": qosConfig["hdrm_pool_size"]["src_port_ids"],
            "src_port_ips": [testPortIps[port]['peer_addr'] for port in qosConfig["hdrm_pool_size"]["src_port_ids"]],
            "dst_port_id": qosConfig["hdrm_pool_size"]["dst_port_id"],
            "dst_port_ip": testPortIps[qosConfig["hdrm_pool_size"]["dst_port_id"]]['peer_addr'],
            "pgs_num": qosConfig["hdrm_pool_size"]["pgs_num"],
            "pkts_num_leak_out": qosConfig["pkts_num_leak_out"],
            "pkts_num_trig_pfc": qosConfig["hdrm_pool_size"]["pkts_num_trig_pfc"],
            "pkts_num_hdrm_full": qosConfig["hdrm_pool_size"]["pkts_num_hdrm_full"],
            "pkts_num_hdrm_partial": qosConfig["hdrm_pool_size"]["pkts_num_hdrm_partial"],
            "hdrm_pool_wm_multiplier": dutQosConfig["param"]["hdrm_pool_wm_multiplier"],
            "cell_size": dutQosConfig["param"]["cell_size"],
            "buf_pool_roid": ingressLosslessProfile["bufferPoolRoid"],
            "max_headroom": sharedHeadroomPoolSize,
            "hwsku":dutTestParams['hwsku']
        })
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.HdrmPoolSizeTest",
            testParams=testParams
        )

    @pytest.mark.parametrize("bufPool", ["wm_buf_pool_lossless", "wm_buf_pool_lossy"])
    def testQosSaiBufferPoolWatermark(
        self, request, bufPool, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        ingressLosslessProfile, egressLossyProfile, resetWatermark,
    ):
        """
            Test QoS SAI Queue buffer pool watermark for lossless/lossy traffic

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLosslessProfile (Fixture): Map of ingress lossless buffer profile attributes
                egressLossyProfile (Fixture): Map of egress lossy buffer profile attributes
                resetWatermark (Fixture): reset watermarks

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        disableTest = request.config.getoption("--disable_test")
        if disableTest:
            pytest.skip("Buffer Pool watermark test is disabled")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if "wm_buf_pool_lossless" in bufPool:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]
            triggerDrop = qosConfig[bufPool]["pkts_num_trig_pfc"]
            fillMin = qosConfig[bufPool]["pkts_num_fill_ingr_min"]
            buf_pool_roid = ingressLosslessProfile["bufferPoolRoid"]
        elif "wm_buf_pool_lossy" in bufPool:
            qosConfig = dutQosConfig["param"]
            triggerDrop = qosConfig[bufPool]["pkts_num_trig_egr_drp"]
            fillMin = qosConfig[bufPool]["pkts_num_fill_egr_min"]
            buf_pool_roid = egressLossyProfile["bufferPoolRoid"]
        else:
            pytest.fail("Unknown pool type")

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dscp": qosConfig[bufPool]["dscp"],
            "ecn": qosConfig[bufPool]["ecn"],
            "pg": qosConfig[bufPool]["pg"],
            "queue": qosConfig[bufPool]["queue"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "pkts_num_leak_out": dutQosConfig["param"][portSpeedCableLength]["pkts_num_leak_out"],
            "pkts_num_fill_min": fillMin,
            "pkts_num_fill_shared": triggerDrop - 1,
            "cell_size": qosConfig[bufPool]["cell_size"],
            "buf_pool_roid": buf_pool_roid
        })
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.BufferPoolWatermarkTest",
            testParams=testParams
        )

    def testQosSaiLossyQueue(
        self, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        ingressLossyProfile
    ):
        """
            Test QoS SAI Lossy queue, shared buffer dynamic allocation

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLosslessProfile (Fxiture): Map of egress lossless buffer profile attributes

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if "lossy_queue_1" in dutQosConfig["param"][portSpeedCableLength].keys():
            qosConfig = dutQosConfig["param"][portSpeedCableLength]
        else:
            qosConfig = dutQosConfig["param"]


        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dscp": qosConfig["lossy_queue_1"]["dscp"],
            "ecn": qosConfig["lossy_queue_1"]["ecn"],
            "pg": qosConfig["lossy_queue_1"]["pg"],
            "buffer_max_size": ingressLossyProfile["static_th"],
            "headroom_size": ingressLossyProfile["size"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "dst_port_2_id": dutConfig["testPorts"]["dst_port_2_id"],
            "dst_port_2_ip": dutConfig["testPorts"]["dst_port_2_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "pkts_num_leak_out": dutQosConfig["param"][portSpeedCableLength]["pkts_num_leak_out"],
            "pkts_num_trig_egr_drp": qosConfig["lossy_queue_1"]["pkts_num_trig_egr_drp"],
            "hwsku":dutTestParams['hwsku']
        })
        if "packet_size" in qosConfig["lossy_queue_1"].keys():
            testParams["packet_size"] = qosConfig["lossy_queue_1"]["packet_size"]
            testParams["cell_size"] = qosConfig["lossy_queue_1"]["cell_size"]
        if "pkts_num_margin" in qosConfig["lossy_queue_1"].keys():
            testParams["pkts_num_margin"] = qosConfig["lossy_queue_1"]["pkts_num_margin"]
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.LossyQueueTest",
            testParams=testParams
        )

    def testQosSaiDscpQueueMapping(
        self, ptfhost, dutTestParams, dutConfig
    ):
        """
            Test QoS SAI DSCP to queue mapping

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        if "backend" in dutTestParams["topo"]:
            pytest.skip("Dscp-queue mapping is not supported on {}".format(dutTestParams["topo"]))

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "hwsku":dutTestParams['hwsku']
        })
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.DscpMappingPB",
            testParams=testParams
        )

    def testQosSaiDot1pQueueMapping(
        self, ptfhost, dutTestParams, dutConfig
    ):
        """
            Test QoS SAI Dot1p to queue mapping

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        if "backend" not in dutTestParams["topo"]:
            pytest.skip("Dot1p-queue mapping is not supported on {}".format(dutTestParams["topo"]))

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "vlan_id": dutConfig["testPorts"]["src_port_vlan"]
        })
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.Dot1pToQueueMapping",
            testParams=testParams
        )

    def testQosSaiDot1pPgMapping(
        self, ptfhost, dutTestParams, dutConfig
    ):
        """
            Test QoS SAI Dot1p to PG mapping
            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        if "backend" not in dutTestParams["topo"]:
            pytest.skip("Dot1p-PG mapping is not supported on {}".format(dutTestParams["topo"]))

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "vlan_id": dutConfig["testPorts"]["src_port_vlan"]
        })
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.Dot1pToPgMapping",
            testParams=testParams
        )

    def testQosSaiDwrr(
        self, ptfhost, dutTestParams, dutConfig, dutQosConfig,
    ):
        """
            Test QoS SAI DWRR

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
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        qosConfig = dutQosConfig["param"]

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "q0_num_of_pkts": qosConfig["wrr"]["q0_num_of_pkts"],
            "q1_num_of_pkts": qosConfig["wrr"]["q1_num_of_pkts"],
            "q2_num_of_pkts": qosConfig["wrr"]["q2_num_of_pkts"],
            "q3_num_of_pkts": qosConfig["wrr"]["q3_num_of_pkts"],
            "q4_num_of_pkts": qosConfig["wrr"]["q4_num_of_pkts"],
            "q5_num_of_pkts": qosConfig["wrr"]["q5_num_of_pkts"],
            "q6_num_of_pkts": qosConfig["wrr"]["q6_num_of_pkts"],
            "limit": qosConfig["wrr"]["limit"],
            "pkts_num_leak_out": qosConfig[portSpeedCableLength]["pkts_num_leak_out"],
            "hwsku":dutTestParams['hwsku'],
            "topo": dutTestParams["topo"]
        })

        if "lossy_queue_1" in dutQosConfig["param"][portSpeedCableLength].keys():
            testParams["ecn"] = qosConfig[portSpeedCableLength]["lossy_queue_1"]["ecn"]
        else:
            testParams["ecn"] = qosConfig["lossy_queue_1"]["ecn"]

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.WRRtest", testParams=testParams
        )

    @pytest.mark.parametrize("pgProfile", ["wm_pg_shared_lossless", "wm_pg_shared_lossy"])
    def testQosSaiPgSharedWatermark(
        self, pgProfile, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        resetWatermark
    ):
        """
            Test QoS SAI PG shared watermark test for lossless/lossy traffic

            Args:
                pgProfile (pytest parameter): priority group profile
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                resetWatermark (Fxiture): reset queue watermarks

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if pgProfile in dutQosConfig["param"][portSpeedCableLength].keys():
            qosConfig = dutQosConfig["param"][portSpeedCableLength]
        else:
            if dutTestParams['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in dutTestParams['topo'] and pgProfile in dutQosConfig["param"][portSpeedCableLength]["breakout"].keys():
                qosConfig = dutQosConfig["param"][portSpeedCableLength]["breakout"]
            else:
                qosConfig = dutQosConfig["param"]

        if "wm_pg_shared_lossless" in pgProfile:
            pktsNumFillShared = qosConfig[pgProfile]["pkts_num_trig_pfc"]
        elif "wm_pg_shared_lossy" in pgProfile:
            pktsNumFillShared = int(qosConfig[pgProfile]["pkts_num_trig_egr_drp"]) - 1

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dscp": qosConfig[pgProfile]["dscp"],
            "ecn": qosConfig[pgProfile]["ecn"],
            "pg": qosConfig[pgProfile]["pg"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "pkts_num_leak_out": dutQosConfig["param"][portSpeedCableLength]["pkts_num_leak_out"],
            "pkts_num_fill_min": qosConfig[pgProfile]["pkts_num_fill_min"],
            "pkts_num_fill_shared": pktsNumFillShared,
            "cell_size": qosConfig[pgProfile]["cell_size"],
            "hwsku":dutTestParams['hwsku']
        })

        if "packet_size" in qosConfig[pgProfile].keys():
            testParams["packet_size"] = qosConfig[pgProfile]["packet_size"]

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.PGSharedWatermarkTest",
            testParams=testParams
        )

    def testQosSaiPgHeadroomWatermark(
        self, ptfhost, dutTestParams, dutConfig, dutQosConfig, resetWatermark,
    ):
        """
            Test QoS SAI PG headroom watermark test

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                resetWatermark (Fxiture): reset queue watermarks

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if dutTestParams['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in dutTestParams['topo']:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]["breakout"]
        else:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dscp": qosConfig["wm_pg_headroom"]["dscp"],
            "ecn": qosConfig["wm_pg_headroom"]["ecn"],
            "pg": qosConfig["wm_pg_headroom"]["pg"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "pkts_num_leak_out": qosConfig["pkts_num_leak_out"],
            "pkts_num_trig_pfc": qosConfig["wm_pg_headroom"]["pkts_num_trig_pfc"],
            "pkts_num_trig_ingr_drp": qosConfig["wm_pg_headroom"]["pkts_num_trig_ingr_drp"],
            "cell_size": qosConfig["wm_pg_headroom"]["cell_size"],
            "hwsku":dutTestParams['hwsku']
        })
        if "pkts_num_margin" in qosConfig["wm_pg_headroom"].keys():
            testParams["pkts_num_margin"] = qosConfig["wm_pg_headroom"]["pkts_num_margin"]
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.PGHeadroomWatermarkTest",
            testParams=testParams
        )

    @pytest.mark.parametrize("queueProfile", ["wm_q_shared_lossless", "wm_q_shared_lossy"])
    def testQosSaiQSharedWatermark(
        self, queueProfile, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        resetWatermark
    ):
        """
            Test QoS SAI Queue shared watermark test for lossless/lossy traffic

            Args:
                queueProfile (pytest parameter): queue profile
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                resetWatermark (Fixture): reset queue watermarks

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]

        if queueProfile == "wm_q_shared_lossless":
            if dutTestParams['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in dutTestParams['topo']:
                qosConfig = dutQosConfig["param"][portSpeedCableLength]["breakout"]
            else:
                qosConfig = dutQosConfig["param"][portSpeedCableLength]
            triggerDrop = qosConfig[queueProfile]["pkts_num_trig_ingr_drp"]
        else:
            if queueProfile in dutQosConfig["param"][portSpeedCableLength].keys():
                qosConfig = dutQosConfig["param"][portSpeedCableLength]
            else:
                qosConfig = dutQosConfig["param"]
            triggerDrop = qosConfig[queueProfile]["pkts_num_trig_egr_drp"]

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dscp": qosConfig[queueProfile]["dscp"],
            "ecn": qosConfig[queueProfile]["ecn"],
            "queue": qosConfig[queueProfile]["queue"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "pkts_num_leak_out": dutQosConfig["param"][portSpeedCableLength]["pkts_num_leak_out"],
            "pkts_num_fill_min": qosConfig[queueProfile]["pkts_num_fill_min"],
            "pkts_num_trig_drp": triggerDrop,
            "cell_size": qosConfig[queueProfile]["cell_size"],
            "hwsku":dutTestParams['hwsku']
        })
        if "packet_size" in qosConfig[queueProfile].keys():
            testParams["packet_size"] = qosConfig[queueProfile]["packet_size"]
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.QSharedWatermarkTest",
            testParams=testParams
        )

    def testQosSaiDscpToPgMapping(
        self, request, ptfhost, dutTestParams, dutConfig,
    ):
        """
            Test QoS SAI DSCP to PG mapping ptf test

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        disableTest = request.config.getoption("--disable_test")
        if disableTest:
            pytest.skip("DSCP to PG mapping test disabled")

        if "backend" in dutTestParams["topo"]:
            pytest.skip("Dscp-PG mapping is not supported on {}".format(dutTestParams["topo"]))

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
        })
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.DscpToPgMapping",
            testParams=testParams
        )

    def testQosSaiDwrrWeightChange(
        self, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        updateSchedProfile
    ):
        """
            Test QoS SAI DWRR runtime weight change

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                updateSchedProfile (Fxiture): Updates lossless/lossy scheduler profiles

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        if dutTestParams["basicParams"]["sonic_asic_type"] == "mellanox":
            pytest.skip("Skip DWRR weight change test on Mellanox platform")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        qosConfig = dutQosConfig["param"]

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "ecn": qosConfig["wrr_chg"]["ecn"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "q0_num_of_pkts": qosConfig["wrr_chg"]["q0_num_of_pkts"],
            "q1_num_of_pkts": qosConfig["wrr_chg"]["q1_num_of_pkts"],
            "q2_num_of_pkts": qosConfig["wrr_chg"]["q2_num_of_pkts"],
            "q3_num_of_pkts": qosConfig["wrr_chg"]["q3_num_of_pkts"],
            "q4_num_of_pkts": qosConfig["wrr_chg"]["q4_num_of_pkts"],
            "q5_num_of_pkts": qosConfig["wrr_chg"]["q5_num_of_pkts"],
            "q6_num_of_pkts": qosConfig["wrr_chg"]["q6_num_of_pkts"],
            "limit": qosConfig["wrr_chg"]["limit"],
            "pkts_num_leak_out": qosConfig[portSpeedCableLength]["pkts_num_leak_out"],
            "hwsku":dutTestParams['hwsku'],
            "topo": dutTestParams["topo"]
        })
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.WRRtest", testParams=testParams
        )


class TestQosSaiMasic(QosSaiBaseMasic):

    def test_qos_masic_dscp_queue_mapping(
        self, duthosts, rand_one_dut_hostname, enum_backend_asic_index,
        ptfhost, dutTestParams, get_test_ports
    ):
        duthost = duthosts[rand_one_dut_hostname]
        src_asic = get_test_ports["src_asic"]

        if not duthost.sonichost.is_multi_asic:
            pytest.skip("Test applies to only multi ASIC platform")

        if enum_backend_asic_index is None:
            pytest.skip("Backend ASIC is None")

        try:
            # Bring down port (channel) towards ASICs other than the ASIC
            # under test, so that traffic always goes via ASIC under test
            self.backend_ip_if_admin_state(
                duthost, enum_backend_asic_index, src_asic, "shutdown"
            )

            test_params = dict()
            test_params.update(dutTestParams["basicParams"])
            test_params.update(get_test_ports)
            logger.debug(test_params)

            # ensure the test destination IP has a path to backend ASIC
            pytest_assert(
                wait_until(
                    30, 1, self.check_v4route_backend_nhop, duthost,
                    test_params["src_asic"], test_params["dst_port_ip"]
                ),
                "Route {} doesn't have backend ASIC nexthop on ASIC {}".format(
                    test_params["dst_port_ip"], test_params["src_asic"]
                )
            )

            duthost.asic_instance(
                enum_backend_asic_index
            ).create_ssh_tunnel_sai_rpc()

            # find traffic src/dst ports on the ASIC under test
            test_params.update(
                self.find_asic_traffic_ports(duthost, ptfhost, test_params)
            )

            self.runPtfTest(
                ptfhost, testCase="sai_qos_tests.DscpMappingPB",
                testParams=test_params
            )

        finally:
            # bring up the backed IFs
            self.backend_ip_if_admin_state(
                duthost, enum_backend_asic_index, src_asic, "startup"
            )

            duthost.asic_instance(
                enum_backend_asic_index
            ).remove_ssh_tunnel_sai_rpc()
