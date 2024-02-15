import json
import math
import pytest
import re
import six
from tests.common.fixtures.duthost_utils import dut_qos_maps, \
    separated_dscp_to_tc_map_on_uplink
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory
from tests.common.helpers.assertions import pytest_assert
from tests.cisco.common.utils import CheckEnvironment
from tests.cisco.common.utils import copy_cisco_directory
from tests.cisco.common.utils import enable_serviceability_cli
from tests.ptf_runner import ptf_runner
from tests.cisco.qos.qos_sai_base import QosSaiBase

pytestmark = [
    pytest.mark.topology('t2')
]

def get_sqg0(duthost, asic_index):
    cmd = "sudo show platform npu rx cgm_global -n asic{} -d".format(asic_index)
    json_str = duthost.command(cmd)['stdout'].strip()
    try:
        data = json.loads(json_str)
    except Exception as e:
        pytest.fail("JSon load error: {}".format(e))
    if "sqg_cntr" in data:
        sqg0 = data["sqg_cntr"][0]
    else:
        pytest.fail("No sqg_cntr in show platform npu rx cgm_global -n asic{} -d".format(asic_index))
    return sqg0


def is_longlink(dutQosConfig):
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        match = re.search("_([0-9]*)m", portSpeedCableLength)
        if match and int(match.group(1)) > 2000:
            return True
        return False


def get_static_th_bp(duthost):
    port = "Ethernet0"
    db = 4
    bp_profile = "pg_lossless_200000_1m_profile"
    asic = duthost.get_port_asic_instance(port)
    static_th = six.text_type(asic.run_redis_cmd(
        argv=[
            "redis-cli", "-n", db, "HGET", "BUFFER_PROFILE|{}".format(bp_profile), "static_th"
            ]
        )[0])
    return static_th


class TestMemory(QosSaiBase):
    def runPtfTest(self, ptfhost, testCase='', testParams={}, relax=False):
        """
            Runs QoS SAI test case on PTF host

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                testCase (str): SAI tests test case name
                testParams (dict): Map of test params required by testCase
                relax (bool): Relax ptf verify packet requirements (default: False)

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        custom_options = " --disable-ipv6 --disable-vxlan --disable-geneve" \
                         " --disable-erspan --disable-mpls --disable-nvgre"
        ptf_runner(
            ptfhost,
            "cisco/qos",
            testCase,
            platform_dir="ptftests",
            params=testParams,
            log_file="/tmp/{0}.log".format(testCase),
            qlen=10000,
            is_python3=True,
            relax=relax,
            timeout=1200,
            socket_recv_size=16384,
            custom_options=custom_options
        )
    
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
                    ipName in dutConfig["testPorts"], 'Not found {} for {} in dutConfig'.format(ipName, idName))
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
                        # if it's port list, record number of ports
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


    @pytest.mark.parametrize(
        "MemoryProfile",
        ["memory_1", "memory_2", "memory_3", "memory_4"])
    def testMemory(
        self, MemoryProfile, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        get_src_dst_asic_and_duts, skip_src_dst_different_platform, duthosts
    ):
        """
            Test QoS SAI SMS memory usage for various voq mode configurations
            Args:
                MemoryProfile (pytest parameter): SMS Memory Profile
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut
                    interfaces, test port IDs, test port IPs, configuration.
                dutQosConfig (Fixture, dict): Map containing DUT host QoS
                    configuration
                get_src_dst_asic_and_duts(Fixture, dict): Map containing the
                    src/dst asics, and duts.
            Returns:
                None
            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        if get_src_dst_asic_and_duts['single_asic_test']:
            pytest.skip("SMS memory test is only for multi asic.")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        qosConfig = dutQosConfig["param"][portSpeedCableLength]
        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts, qosConfig[MemoryProfile])

        src_dut_index = get_src_dst_asic_and_duts['src_dut_index']
        src_asic_index = get_src_dst_asic_and_duts['src_asic_index']
        dst_asic_index = get_src_dst_asic_and_duts['dst_asic_index']
        
        dst_port_ip = dutConfig["testPorts"]["dst_port_ip"]
        dst_ip = "100.0.0.1"
        
        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        all_src_ports = dutConfig["testPortIps"][src_dut_index][src_asic_index]
        all_src_port_ids = list(all_src_ports.keys())
        src_duthost = get_src_dst_asic_and_duts['src_dut']
        dst_duthost = get_src_dst_asic_and_duts['dst_dut']

        if CheckEnvironment.is_sim(src_duthost):
            pytest.skip("Test not supported in SIM environment")

        pkts_num_trig_pfc = qosConfig[MemoryProfile]["pkts_num_trig_pfc"]
        packet_size = qosConfig[MemoryProfile]["packet_size"]
        cell_size = qosConfig[MemoryProfile]["cell_size"]
        num_of_flows = qosConfig[MemoryProfile]['num_of_flows']
        testParams.update(qosConfig[MemoryProfile])
        testParams.update({
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dst_ip,
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_1_id": all_src_port_ids[0],
            "src_port_1_ip": all_src_ports[all_src_port_ids[0]]['peer_addr'],
            "src_port_2_id": all_src_port_ids[1],
            "src_port_2_ip":  all_src_ports[all_src_port_ids[1]]['peer_addr'],
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = \
                dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "pkts_num_margin" in qosConfig[MemoryProfile].keys():
            testParams["pkts_num_margin"] = \
                qosConfig[MemoryProfile]["pkts_num_margin"]

        if "packet_size" in qosConfig[MemoryProfile].keys():
            testParams["packet_size"] = \
                qosConfig[MemoryProfile]["packet_size"]

        rp_duthost = duthosts.supervisor_nodes[0]
        for duthost in set([src_duthost, dst_duthost, rp_duthost]):
            enable_serviceability_cli(duthost)

        cmd = "sudo ip netns exec asic{} config route add prefix {}/32 nexthop {}".format(dst_asic_index, dst_ip, dst_port_ip)
        res = dst_duthost.command(cmd)
        pytest_assert(res['rc'] == 0, "Config static route failed")

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.Memorytest",
            testParams=testParams
        )

        # Caculate xoff threshold based on pkts_num_trig_pfc
        cell_per_pkt = math.ceil(packet_size/cell_size)
        xoff_thres_cell = cell_per_pkt * pkts_num_trig_pfc
        xoff_thres_cell_bp = xoff_thres_cell
        if is_longlink(dutQosConfig):
            static_th = get_static_th_bp(dst_duthost)
            xoff_thres_cell_bp = math.ceil(static_th/cell_size)

        # Check SQG0 of ingress asic
        # ingress asic: xoff_threshold * 2 voqs (src ports)
        sqg0 = get_sqg0(src_duthost, src_asic_index)
        expected_num_of_cells = xoff_thres_cell * 2
        assert abs(sqg0 - expected_num_of_cells) < expected_num_of_cells * 0.1, "asic{} sqg0 {} divert from expected buffers {}".format(
                src_asic_index, sqg0, expected_num_of_cells)

        # Check SQG0 of FC asics
        # FC asic: xoff_threshold * min(num_of_flows * 2, number of FC asics)
        cmd = "show platform inventory"
        output = rp_duthost.command(cmd)['stdout'].strip()
        num_of_fc = output.count('Cisco 8808 Fabric Card')
        num_of_fc_asic = 2 * num_of_fc
        sqg0_total = 0
        for line in output.split('\n'):
            if line.find('Cisco 8808 Fabric Card') == -1:
                continue
            matchObj = re.search(r"FC([0-9]+)", line)
            if matchObj:
                fc_index = int(matchObj.group(1))
                asic_indexes = [fc_index * 2, fc_index * 2 + 1]
                for asic_index in asic_indexes:
                    sqg0 = get_sqg0(rp_duthost, asic_index)
                    sqg0_total += sqg0
        expected_num_of_cells = xoff_thres_cell * min(num_of_flows * 2, num_of_fc_asic)
        assert abs(sqg0_total - expected_num_of_cells) < expected_num_of_cells * 0.1, "FC sqg0_total {} divert from expected buffers {}".format(
            sqg0_total, expected_num_of_cells)

        # Check SQG0 of egress asic
        # egress asic: xoff_threshold * min(num_of_flows * 2, number of FC asics)
        sqg0 = get_sqg0(dst_duthost, dst_asic_index)
        expected_num_of_cells = xoff_thres_cell_bp * min(num_of_flows * 2, num_of_fc_asic)
        assert abs(sqg0 - expected_num_of_cells) < expected_num_of_cells * 0.1, "asic{} sqg0 {} divert from expected buffers {}".format(
                dst_asic_index, sqg0, expected_num_of_cells)

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.ReleaseAllPorts",
            testParams=dutTestParams["basicParams"]
        )

        cmd = "sudo ip netns exec asic{} config route del prefix {}/32 nexthop {}".format(dst_asic_index, dst_ip, dst_port_ip)
        res = dst_duthost.command(cmd)
        pytest_assert(res['rc'] == 0, "Delete static route failed")
