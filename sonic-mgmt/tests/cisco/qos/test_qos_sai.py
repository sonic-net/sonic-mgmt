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
import re

from tests.common.fixtures.conn_graph_facts import fanout_graph_facts, conn_graph_facts, get_graph_facts    # noqa F401
from tests.common.fixtures.duthost_utils import dut_qos_maps, \
    separated_dscp_to_tc_map_on_uplink, load_dscp_to_pg_map                                 # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                     # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory                     # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                        # noqa F401
from tests.cisco.common.utils import copy_cisco_directory
from tests.common.fixtures.ptfhost_utils import ptf_portmap_file                            # noqa F401
from tests.common.dualtor.dual_tor_utils import dualtor_ports, is_tunnel_qos_remap_enabled  # noqa F401
from tests.common.helpers.assertions import pytest_assert
from .qos_sai_base import QosSaiBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

PTF_PORT_MAPPING_MODE = 'use_orig_interface'


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exception(get_src_dst_asic_and_duts, loganalyzer):
    """ignore the syslog ERR syncd0#syncd: [03:00.0] brcm_sai_set_switch_
       attribute:1920 updating switch mac addr failed with error -2"""
    ignore_regex = [
        ".*ERR syncd[0-9]*#syncd.*brcm_sai_set_switch_attribute.*updating switch mac addr failed with error.*"
    ]

    if loganalyzer:
        for a_dut in get_src_dst_asic_and_duts['all_duts']:
            hwsku = a_dut.facts["hwsku"]
            if "7050" in hwsku and "QX" in hwsku.upper():
                logger.info("ignore memory threshold check for 7050qx")
                # ERR memory_threshold_check: Free memory 381608 is less then free memory threshold 400382.4
                ignore_regex.append(".*ERR memory_threshold_check: Free memory .* is less then free memory threshold.*")
            loganalyzer[a_dut.hostname].ignore_regex.extend(ignore_regex)


@pytest.fixture(autouse=False)
def check_skip_shared_res_test(
        sharedResSizeKey, dutQosConfig,
        get_src_dst_asic_and_duts, dutConfig):
    qosConfig = dutQosConfig["param"]
    src_dut_index = get_src_dst_asic_and_duts['src_dut_index']
    src_asic_index = get_src_dst_asic_and_duts['src_asic_index']
    dst_dut_index = get_src_dst_asic_and_duts['dst_dut_index']
    dst_asic_index = get_src_dst_asic_and_duts['dst_asic_index']
    src_testPortIps = dutConfig["testPortIps"][src_dut_index][src_asic_index]
    dst_testPortIps = dutConfig["testPortIps"][dst_dut_index][dst_asic_index]

    if sharedResSizeKey not in qosConfig.keys():
        pytest.skip(
            "Shared reservation size parametrization '%s' "
            "is not enabled" % sharedResSizeKey)

    if "skip" in qosConfig[sharedResSizeKey]:
        # Skip if buffer pools and profiles are not be present,
        # marked by qos param generator
        pytest.skip(qosConfig[sharedResSizeKey]["skip"])

    src_port_idx_to_id = list(src_testPortIps.keys())
    dst_port_idx_to_id = list(dst_testPortIps.keys())
    # Translate requested port indices to available port IDs
    try:
        src_port_ids = [src_port_idx_to_id[idx] for idx in qosConfig[sharedResSizeKey]["src_port_i"]]
        dst_port_ids = [dst_port_idx_to_id[idx] for idx in qosConfig[sharedResSizeKey]["dst_port_i"]]
        return (True, src_port_ids, dst_port_ids)
    except IndexError:
        # Not enough ports.
        pytest.skip(
            "This test cannot be run since there are not enough ports."
            " Pls see qos.yaml for the port idx's that are needed.")


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
        'Arista-7050CX3-32S-C32',
        'Arista-7050CX3-32S-D48C8'
    ]

    BREAKOUT_SKUS = ['Arista-7050-QX-32S']

    def replaceNonExistentPortId(self, availablePortIds, portIds):
        '''
        if port id of availablePortIds/dst_port_ids is not existing in availablePortIds
        replace it with correct one, make sure all port id is valid
        e.g.
            Given below parameter:
                availablePortIds: [0, 2, 4, 6, 8, 10, 16, 18, 20, 22, 24, 26,
                                   28, 30, 32, 34, 36, 38, 44, 46, 48, 50, 52, 54]
                portIds: [1, 2, 3, 4, 5, 6, 7, 8, 9]
            get result:
                portIds: [0, 2, 16, 4, 18, 6, 20, 8, 22]
        '''
        if len(portIds) > len(availablePortIds):
            logger.info('no enough ports for test')
            return False

        # cache available as free port pool
        freePorts = [pid for pid in availablePortIds]

        # record invaild port
        # and remove valid port from free port pool
        invalid = []
        for idx, pid in enumerate(portIds):
            if pid not in freePorts:
                invalid.append(idx)
            else:
                freePorts.remove(pid)

        # replace invalid port from free port pool
        for idx in invalid:
            portIds[idx] = freePorts.pop(0)

        return True

    def updateTestPortIdIp(self, dutConfig, get_src_dst_asic_and_duts, qosParams=None):
        src_dut_index = get_src_dst_asic_and_duts['src_dut_index']
        dst_dut_index = get_src_dst_asic_and_duts['dst_dut_index']
        src_asic_index = get_src_dst_asic_and_duts['src_asic_index']
        dst_asic_index = get_src_dst_asic_and_duts['dst_asic_index']
        src_testPortIds = dutConfig["testPortIds"][src_dut_index][src_asic_index]
        dst_testPortIds = dutConfig["testPortIds"][dst_dut_index][dst_asic_index]
        testPortIds = src_testPortIds + list(set(dst_testPortIds) - set(src_testPortIds))

        portIdNames = []
        portIds = []

        for idName in dutConfig["testPorts"]:
            if re.match(r'(?:src|dst)_port\S+id', idName):
                portIdNames.append(idName)
                ipName = idName.replace('id', 'ip')
                pytest_assert(
                    ipName in dutConfig["testPorts"], 'Not find {} for {} in dutConfig'.format(ipName, idName))
                portIds.append(dutConfig["testPorts"][idName])
        pytest_assert(self.replaceNonExistentPortId(testPortIds, set(portIds)), "No enough test ports")
        for idx, idName in enumerate(portIdNames):
            dutConfig["testPorts"][idName] = portIds[idx]
            ipName = idName.replace('id', 'ip')
            if 'src' in ipName:
                testPortIps = dutConfig["testPortIps"][src_dut_index][src_asic_index]
            else:
                testPortIps = dutConfig["testPortIps"][dst_dut_index][dst_asic_index]
            dutConfig["testPorts"][ipName] = testPortIps[portIds[idx]]['peer_addr']

        if qosParams is not None:
            portIdNames = []
            portNumbers = []
            portIds = []
            for idName in qosParams.keys():
                if re.match(r'(?:src|dst)_port\S+ids?', idName):
                    portIdNames.append(idName)
                    ids = qosParams[idName]
                    if isinstance(ids, list):
                        portIds += ids
                        # if it's port list, record number of pots
                        portNumbers.append(len(ids))
                    else:
                        portIds.append(ids)
                        # record None to indicate it's just one port
                        portNumbers.append(None)
            pytest_assert(self.replaceNonExistentPortId(testPortIds, portIds), "No enough test ports")
            startPos = 0
            for idx, idName in enumerate(portIdNames):
                if portNumbers[idx] is not None:    # port list
                    qosParams[idName] = [
                        portId for portId in portIds[startPos:startPos + portNumbers[idx]]]
                    startPos += portNumbers[idx]
                else:   # not list, just one port
                    qosParams[idName] = portIds[startPos]
                    startPos += 1

    def testQosSaiTrafficSanity(
            self, ptfhost, dutTestParams, dutConfig, dutQosConfig, get_src_dst_asic_and_duts
    ):
        """
            Test QoS SAI traffic sanity
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
        if dutTestParams["basicParams"]["sonic_asic_type"] != "cisco-8000":
            pytest.skip("Traffic sanity size test is not supported")

        if dutTestParams["basicParams"]["is_sim"]:
            pytest.skip("Test not supported in SIM environment")

        dst_dut_idx = get_src_dst_asic_and_duts['dst_dut_index']
        dst_asic_idx = get_src_dst_asic_and_duts['dst_asic_index']
        testPortIps = dutConfig["testPortIps"][dst_dut_idx][dst_asic_idx]

        # Fetch all port IDs and IPs
        all_port_id_to_ip = {port_id: testPortIps[port_id]['peer_addr'] for port_id in testPortIps.keys()}
        all_port_id_to_name = {port_id: dutConfig["dutInterfaces"][port_id] for port_id in testPortIps.keys()}
        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "testbed_type": dutTestParams["topo"],
            "all_port_id_to_ip": all_port_id_to_ip,
            "all_port_id_to_name": all_port_id_to_name,
            "hwsku": dutTestParams['hwsku']
        })

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.TrafficSanity",
            testParams=testParams
        )
