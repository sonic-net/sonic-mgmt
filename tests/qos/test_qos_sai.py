"""
    QoS SAI feature in SONiC.

    Parameters:
        --ptf_portmap <filename> (str): file name of port index to DUT interface alias map. Default is None.
            In case of a filename is not provided, a file containing port indeces to aliases map will be generated.

        --disable_test (bool): Disables experimental QoS SAI test cases. Deafult is True

        --qos_swap_syncd (bool): Used to install the RPC syncd image before running the tests. Default is True.

        --qos_dst_ports (list) Indeces of available DUT test ports to serve as destination ports. Note, This is not port
            index on DUT, rather an index into filtered (excludes lag member ports) DUT ports. Plan is to randomize port
            selection. Default is [0, 1, 3]

        --qos_src_ports (list) Indeces of available DUT test ports to serve as source port. Similar note as in
            qos_dst_ports applies. Default is [2]
"""

import logging
import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from qos_sai_base import QosSaiBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

class TestQosSai(QosSaiBase):
    """
        TestQosSai derives from QosSaiBase and contains collection of QoS SAI test cases.
    """
    SUPPORTED_PGSHARED_WATERMARK_SKUS = ['Arista-7260CX3-Q64', 'Arista-7260CX3-D108C8']
    SUPPORTED_HEADROOM_SKUS = [
        'Arista-7060CX-32S-C32',
        'Celestica-DX010-C32',
        'Arista-7260CX3-D108C8',
        'Force10-S6100',
        'Arista-7260CX3-Q64'
    ]

    def testParameter(self, duthost, dutQosConfig, ingressLosslessProfile, ingressLossyProfile, egressLosslessProfile):
        logger.info("asictype {}".format(duthost.facts["asic_type"]))
        logger.info("qosConfig {}".format(dutQosConfig))

    @pytest.mark.parametrize("xoffProfile", ["xoff_1", "xoff_2"])
    def testQosSaiPfcXoffLimit(self, xoffProfile, ptfhost, dutTestParams, dutConfig, dutQosConfig,
                               ingressLosslessProfile, egressLosslessProfile):
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
        qosConfig = dutQosConfig["param"][portSpeedCableLength]
        testParams = {
            "dscp": qosConfig[xoffProfile]["dscp"],
            "ecn": qosConfig[xoffProfile]["ecn"],
            "pg": qosConfig[xoffProfile]["pg"],
            "buffer_max_size": ingressLosslessProfile["size"],
            "queue_max_size": egressLosslessProfile["static_th"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "pkts_num_leak_out": qosConfig["pkts_num_leak_out"],
            "pkts_num_trig_pfc": qosConfig[xoffProfile]["pkts_num_trig_pfc"],
            "pkts_num_trig_ingr_drp": qosConfig[xoffProfile]["pkts_num_trig_ingr_drp"],
        }
        if "pkts_num_margin" in qosConfig[xoffProfile].keys():
            testParams["pkts_num_margin"] = qosConfig[xoffProfile]["pkts_num_margin"]
        testParams.update(dutTestParams["basicParams"])
        self.runPtfTest(ptfhost, testCase="sai_qos_tests.PFCtest", testParams=testParams)

    @pytest.mark.parametrize("xonProfile", ["xon_1", "xon_2"])
    def testQosSaiPfcXonLimit(self, xonProfile, ptfhost, dutTestParams, dutConfig, dutQosConfig,
                              ingressLosslessProfile):
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
        qosConfig = dutQosConfig["param"]
        testParams = {
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
            "pkts_num_leak_out": qosConfig[portSpeedCableLength]["pkts_num_leak_out"],
            "pkts_num_trig_pfc": qosConfig[xonProfile]["pkts_num_trig_pfc"],
            "pkts_num_dismiss_pfc": qosConfig[xonProfile]["pkts_num_dismiss_pfc"]
        }
        if "pkts_num_hysteresis" in qosConfig[xonProfile].keys():
            testParams["pkts_num_hysteresis"] = qosConfig[xonProfile]["pkts_num_hysteresis"]
        if "pkts_num_margin" in qosConfig[xonProfile].keys():
            testParams["pkts_num_margin"] = qosConfig[xonProfile]["pkts_num_margin"]
        testParams.update(dutTestParams["basicParams"])
        self.runPtfTest(ptfhost, testCase="sai_qos_tests.PFCXonTest", testParams=testParams)

    def testQosSaiHeadroomPoolSize(self, ptfhost, dutTestParams, dutConfig, dutQosConfig, ingressLosslessProfile):
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
        if dutTestParams["hwsku"] not in self.SUPPORTED_HEADROOM_SKUS:
            pytest.skip("Headroom pool size not supported")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        qosConfig = dutQosConfig["param"][portSpeedCableLength]
        testPortIps = dutConfig["testPortIps"]

        testParams = {
            "testbed_type": dutTestParams["topo"],
            "dscps": qosConfig["hdrm_pool_size"]["dscps"],
            "ecn": qosConfig["hdrm_pool_size"]["ecn"],
            "pgs": qosConfig["hdrm_pool_size"]["pgs"],
            "src_port_ids": qosConfig["hdrm_pool_size"]["src_port_ids"],
            "src_port_ips": [testPortIps[port] for port in qosConfig["hdrm_pool_size"]["src_port_ids"]],
            "dst_port_id": qosConfig["hdrm_pool_size"]["dst_port_id"],
            "dst_port_ip": testPortIps[qosConfig["hdrm_pool_size"]["dst_port_id"]],
            "pgs_num": qosConfig["hdrm_pool_size"]["pgs_num"],
            "pkts_num_leak_out": qosConfig["pkts_num_leak_out"],
            "pkts_num_trig_pfc": qosConfig["hdrm_pool_size"]["pkts_num_trig_pfc"],
            "pkts_num_hdrm_full": qosConfig["hdrm_pool_size"]["pkts_num_hdrm_full"],
            "pkts_num_hdrm_partial": qosConfig["hdrm_pool_size"]["pkts_num_hdrm_partial"],
        }
        testParams.update(dutTestParams["basicParams"])
        self.runPtfTest(ptfhost, testCase="sai_qos_tests.HdrmPoolSizeTest", testParams=testParams)

    def testQosSaiLossyQueue(self, ptfhost, dutTestParams, dutConfig, dutQosConfig, ingressLossyProfile):
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
        qosConfig = dutQosConfig["param"]

        testParams = {
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
            "pkts_num_leak_out": qosConfig[portSpeedCableLength]["pkts_num_leak_out"],
            "pkts_num_trig_egr_drp": qosConfig["lossy_queue_1"]["pkts_num_trig_egr_drp"],
        }
        if "packet_size" in qosConfig["lossy_queue_1"].keys():
            testParams["packet_size"] = qosConfig["lossy_queue_1"]["packet_size"]
            testParams["cell_size"] = qosConfig["lossy_queue_1"]["cell_size"]
        if "pkts_num_margin" in qosConfig["lossy_queue_1"].keys():
            testParams["pkts_num_margin"] = qosConfig["lossy_queue_1"]["pkts_num_margin"]
        testParams.update(dutTestParams["basicParams"])
        self.runPtfTest(ptfhost, testCase="sai_qos_tests.LossyQueueTest", testParams=testParams)

    def testQosSaiDscpQueueMapping(self, ptfhost, dutTestParams, dutConfig):
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
        testParams = {
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
        }
        testParams.update(dutTestParams["basicParams"])
        self.runPtfTest(ptfhost, testCase="sai_qos_tests.DscpMappingPB", testParams=testParams)

    def testQosSaiDwrr(self, ptfhost, dutTestParams, dutConfig, dutQosConfig):
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

        testParams = {
            "ecn": qosConfig["lossy_queue_1"]["ecn"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "q0_num_of_pkts": qosConfig["wrr"]["q0_num_of_pkts"],
            "q1_num_of_pkts": qosConfig["wrr"]["q1_num_of_pkts"],
            "q2_num_of_pkts": qosConfig["wrr"]["q2_num_of_pkts"],
            "q3_num_of_pkts": qosConfig["wrr"]["q3_num_of_pkts"],
            "q4_num_of_pkts": qosConfig["wrr"]["q4_num_of_pkts"],
            "q5_num_of_pkts": qosConfig["wrr"]["q5_num_of_pkts"],
            "q6_num_of_pkts": qosConfig["wrr"]["q6_num_of_pkts"],
            "limit": qosConfig["wrr"]["limit"],
            "pkts_num_leak_out": qosConfig[portSpeedCableLength]["pkts_num_leak_out"],
        }
        testParams.update(dutTestParams["basicParams"])
        self.runPtfTest(ptfhost, testCase="sai_qos_tests.WRRtest", testParams=testParams)

    @pytest.mark.parametrize("pgProfile", ["wm_pg_shared_lossless", "wm_pg_shared_lossy"])
    def testQosSaiPgSharedWatermark(self, pgProfile, ptfhost, dutTestParams, dutConfig, dutQosConfig,
                                    resetWatermark):
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
        if dutTestParams["hwsku"] in self.SUPPORTED_PGSHARED_WATERMARK_SKUS:
            pytest.skip("PG shared watermark test not supported")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        qosConfig = dutQosConfig["param"]

        if "wm_pg_shared_lossless" in pgProfile:
            pktsNumFillShared = qosConfig[pgProfile]["pkts_num_trig_pfc"]
        elif "wm_pg_shared_lossy" in pgProfile:
            pktsNumFillShared = int(qosConfig[pgProfile]["pkts_num_trig_egr_drp"]) - 1

        testParams = {
            "dscp": qosConfig[pgProfile]["dscp"],
            "ecn": qosConfig[pgProfile]["ecn"],
            "pg": qosConfig[pgProfile]["pg"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "pkts_num_leak_out": qosConfig[portSpeedCableLength]["pkts_num_leak_out"],
            "pkts_num_fill_min": qosConfig[pgProfile]["pkts_num_fill_min"],
            "pkts_num_fill_shared": pktsNumFillShared,
            "cell_size": qosConfig[pgProfile]["cell_size"],
        }
        if "packet_size" in qosConfig[pgProfile].keys():
            testParams["packet_size"] = qosConfig[pgProfile]["packet_size"]
        testParams.update(dutTestParams["basicParams"])
        self.runPtfTest(ptfhost, testCase="sai_qos_tests.PGSharedWatermarkTest", testParams=testParams)

    def testQosSaiPgHeadroomWatermark(self, ptfhost, dutTestParams, dutConfig, dutQosConfig, resetWatermark):
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
        qosConfig = dutQosConfig["param"][portSpeedCableLength]

        testParams = {
            "dscp": qosConfig["wm_pg_headroom"]["dscp"],
            "ecn": qosConfig["wm_pg_headroom"]["ecn"],
            "pg": qosConfig["wm_pg_headroom"]["pg"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "pkts_num_leak_out": qosConfig["pkts_num_leak_out"],
            "pkts_num_trig_pfc": qosConfig["wm_pg_headroom"]["pkts_num_trig_pfc"],
            "pkts_num_trig_ingr_drp": qosConfig["wm_pg_headroom"]["pkts_num_trig_ingr_drp"],
            "cell_size": qosConfig["wm_pg_headroom"]["cell_size"],
        }
        if "pkts_num_margin" in qosConfig["wm_pg_headroom"].keys():
            testParams["pkts_num_margin"] = qosConfig["wm_pg_headroom"]["pkts_num_margin"]
        testParams.update(dutTestParams["basicParams"])
        self.runPtfTest(ptfhost, testCase="sai_qos_tests.PGHeadroomWatermarkTest", testParams=testParams)

    @pytest.mark.parametrize("queueProfile", ["wm_q_shared_lossless", "wm_q_shared_lossy"])
    def testQosSaiQSharedWatermark(self, queueProfile, ptfhost, dutTestParams, dutConfig, dutQosConfig, resetWatermark):
        """
            Test QoS SAI Queue shared watermark test for lossless/lossy traffic

            Args:
                queueProfile (pytest parameter): queue profile
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
        qosConfig = dutQosConfig["param"][portSpeedCableLength] if "wm_q_shared_lossless" in queueProfile \
                    else dutQosConfig["param"]
        triggerDrop = qosConfig[queueProfile]["pkts_num_trig_ingr_drp"] if "wm_q_shared_lossless" in queueProfile \
                      else qosConfig[queueProfile]["pkts_num_trig_egr_drp"]

        testParams = {
            "dscp": qosConfig[queueProfile]["dscp"],
            "ecn": qosConfig[queueProfile]["ecn"],
            "queue": qosConfig[queueProfile]["queue"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "pkts_num_leak_out": dutQosConfig["param"][portSpeedCableLength]["pkts_num_leak_out"],
            "pkts_num_fill_min": qosConfig[queueProfile]["pkts_num_fill_min"],
            "pkts_num_trig_drp": triggerDrop,
            "cell_size": qosConfig[queueProfile]["cell_size"],
        }
        if "packet_size" in qosConfig[queueProfile].keys():
            testParams["packet_size"] = qosConfig[queueProfile]["packet_size"]
        testParams.update(dutTestParams["basicParams"])
        self.runPtfTest(ptfhost, testCase="sai_qos_tests.QSharedWatermarkTest", testParams=testParams)

    def testQosSaiDscpToPgMapping(self, request, ptfhost, dutTestParams, dutConfig):
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

        testParams = {
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
        }
        testParams.update(dutTestParams["basicParams"])
        self.runPtfTest(ptfhost, testCase="sai_qos_tests.DscpToPgMapping", testParams=testParams)

    def testQosSaiDwrrWeightChange(self, ptfhost, dutTestParams, dutConfig, dutQosConfig, updateSchedProfile):
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
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        qosConfig = dutQosConfig["param"]

        testParams = {
            "ecn": qosConfig["wrr_chg"]["ecn"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "q0_num_of_pkts": qosConfig["wrr_chg"]["q0_num_of_pkts"],
            "q1_num_of_pkts": qosConfig["wrr_chg"]["q1_num_of_pkts"],
            "q2_num_of_pkts": qosConfig["wrr_chg"]["q2_num_of_pkts"],
            "q3_num_of_pkts": qosConfig["wrr_chg"]["q3_num_of_pkts"],
            "q4_num_of_pkts": qosConfig["wrr_chg"]["q4_num_of_pkts"],
            "q5_num_of_pkts": qosConfig["wrr_chg"]["q5_num_of_pkts"],
            "q6_num_of_pkts": qosConfig["wrr_chg"]["q6_num_of_pkts"],
            "limit": qosConfig["wrr_chg"]["limit"],
            "pkts_num_leak_out": qosConfig[portSpeedCableLength]["pkts_num_leak_out"],
        }
        testParams.update(dutTestParams["basicParams"])
        self.runPtfTest(ptfhost, testCase="sai_qos_tests.WRRtest", testParams=testParams)
