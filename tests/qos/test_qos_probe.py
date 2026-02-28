"""SAI thrift-based buffer threshold probing tests for SONiC.

This module contains probe-based tests for buffer threshold detection, including:
- testQosPfcXoffProbe: PFC XOFF threshold probing
- testQosIngressDropProbe: Ingress drop threshold probing
- testQosHeadroomPoolProbe: Headroom pool threshold probing

These tests use advanced probing algorithms to automatically detect buffer thresholds.

Parameters:
    --enable_qos_ptf_pdb (bool): Enable pdb debugger in PTF tests. Default is False.
"""

import logging
import pytest
from collections import defaultdict

from tests.common.fixtures.conn_graph_facts import fanout_graph_facts, conn_graph_facts, get_graph_facts    # noqa: F401
from tests.common.fixtures.duthost_utils import dut_qos_maps, \
    separated_dscp_to_tc_map_on_uplink, load_dscp_to_pg_map                                 # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                     # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory                     # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                        # noqa: F401
from tests.common.fixtures.ptfhost_utils import ptf_portmap_file                            # noqa: F401
from tests.common.fixtures.ptfhost_utils import iptables_drop_ipv6_tx                       # noqa: F401
from tests.common.dualtor.dual_tor_utils import dualtor_ports, is_tunnel_qos_remap_enabled  # noqa: F401
from .qos_sai_base import QosSaiBase
from tests.common.helpers.ptf_tests_helper import downstream_links, upstream_links, select_random_link,\
    get_stream_ptf_ports, apply_dscp_cfg_setup, apply_dscp_cfg_teardown, fetch_test_logs_ptf   # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


class TestQosProbe(QosSaiBase):
    """TestQosProbe contains probe-based buffer threshold detection tests.

    These tests use advanced algorithms to automatically detect buffer thresholds:
    - Binary search for PFC XOFF threshold
    - Ingress drop threshold detection
    - Headroom pool size probing
    """

    @pytest.fixture(scope="class", autouse=True)
    def setup(self, disable_voq_watchdog_class_scope):
        return

    @pytest.mark.parametrize("xoffProfile", ["xoff_1", "xoff_2", "xoff_3", "xoff_4"])
    def testQosPfcXoffProbe(
        self, xoffProfile, duthost, get_src_dst_asic_and_duts,
        ptfhost, dutTestParams, dutConfig, dutQosConfig,
        ingressLosslessProfile, egressLosslessProfile, change_lag_lacp_timer, tbinfo, request
    ):
        # NOTE: this test will be skipped for t2 cisco 8800 if it's not xoff_1 or xoff_2
        """
            Test QoS XOFF limits using PFC XOFF probing algorithm

            Args:
                xoffProfile (pytest parameter): XOFF profile
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLosslessProfile (Fxiture): Map of ingress lossless buffer profile attributes
                egressLosslessProfile (Fxiture): Map of egress lossless buffer profile attributes
                set_static_route (Fixture): Setup the static route if the src
                                            and dst ASICs are different.

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        normal_profile = ["xoff_1", "xoff_2"]
        if not dutConfig["dualTor"] and xoffProfile not in normal_profile:
            pytest.skip(
                "Additional DSCPs are not supported on non-dual ToR ports")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if dutTestParams['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in dutTestParams['topo']:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]["breakout"]
        else:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts)

        probing_port_ids = [dutConfig["testPorts"]["src_port_id"], dutConfig["testPorts"]["dst_port_id"]]
        logger.info(f"Simplified probing strategy: using "
                    f"src_port_id={dutConfig['testPorts']['src_port_id']}, "
                    f"dst_port_id={dutConfig['testPorts']['dst_port_id']}")

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({"test_port_ids": dutConfig["testPortIds"]})
        testParams.update({"test_port_ips": dutConfig["testPortIps"]})
        testParams.update({"probing_port_ids": probing_port_ids})
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
            "hwsku": dutTestParams['hwsku'],
            "src_dst_asic_diff": (dutConfig['dutAsic'] != dutConfig['dstDutAsic'])
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "pkts_num_egr_mem" in list(qosConfig.keys()):
            testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem"]

        if dutTestParams["basicParams"].get("platform_asic", None) == "cisco-8000" \
                and not get_src_dst_asic_and_duts["src_long_link"] and get_src_dst_asic_and_duts["dst_long_link"]:
            if "pkts_num_egr_mem_short_long" in list(qosConfig.keys()):
                testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem_short_long"]
            else:
                pytest.skip(
                    "pkts_num_egr_mem_short_long is missing in yaml file ")

        if "pkts_num_margin" in list(qosConfig[xoffProfile].keys()):
            testParams["pkts_num_margin"] = qosConfig[xoffProfile]["pkts_num_margin"]

        if "packet_size" in list(qosConfig[xoffProfile].keys()):
            testParams["packet_size"] = qosConfig[xoffProfile]["packet_size"]

        if 'cell_size' in list(qosConfig[xoffProfile].keys()):
            testParams["cell_size"] = qosConfig[xoffProfile]["cell_size"]

        bufferConfig = dutQosConfig["bufferConfig"]
        testParams["ingress_lossless_pool_size"] = bufferConfig["BUFFER_POOL"]["ingress_lossless_pool"]["size"]
        testParams["egress_lossy_pool_size"] = bufferConfig["BUFFER_POOL"]["egress_lossy_pool"]["size"]

        # Get cell_size with fallback to sub-layers if not found at top level
        def find_cell_size(config_dict):
            """Recursively find cell_size in config dictionary"""
            if isinstance(config_dict, dict):
                if 'cell_size' in config_dict:
                    return config_dict['cell_size']
                for value in config_dict.values():
                    result = find_cell_size(value)
                    if result is not None:
                        return result
            return None

        cell_size = dutQosConfig["param"].get("cell_size", None)
        if cell_size is None:
            cell_size = find_cell_size(dutQosConfig["param"])
        testParams["cell_size"] = cell_size

        # Get pdb parameter from command line
        enable_qos_ptf_pdb = request.config.getoption("--enable_qos_ptf_pdb", default=False)

        self.runPtfTest(
            ptfhost, testCase="pfc_xoff_probing.PfcXoffProbing", testParams=testParams,
            pdb=enable_qos_ptf_pdb, test_subdir='probe'
        )

    @pytest.mark.parametrize("xoffProfile", ["xoff_1", "xoff_2", "xoff_3", "xoff_4"])
    def testQosIngressDropProbe(
        self, xoffProfile, duthost, get_src_dst_asic_and_duts,
        ptfhost, dutTestParams, dutConfig, dutQosConfig,
        ingressLosslessProfile, egressLosslessProfile, change_lag_lacp_timer, tbinfo, request
    ):
        """
            Test QoS Ingress Drop limits using IngressDropProbe

            Args:
                xoffProfile (pytest parameter): XOFF profile (used for config lookup)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLosslessProfile (Fxiture): Map of ingress lossless buffer profile attributes
                egressLosslessProfile (Fxiture): Map of egress lossless buffer profile attributes

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        normal_profile = ["xoff_1", "xoff_2"]
        if not dutConfig["dualTor"] and xoffProfile not in normal_profile:
            pytest.skip(
                "Additional DSCPs are not supported on non-dual ToR ports")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if dutTestParams['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in dutTestParams['topo']:
            qosConfig = dutQosConfig["param"][portSpeedCableLength][" breakout"]
        else:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts)

        probing_port_ids = [dutConfig["testPorts"]["src_port_id"], dutConfig["testPorts"]["dst_port_id"]]
        logger.info(f"Simplified probing strategy: using "
                    f"src_port_id={dutConfig['testPorts']['src_port_id']}, "
                    f"dst_port_id={dutConfig['testPorts']['dst_port_id']}")

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({"test_port_ids": dutConfig["testPortIds"]})
        testParams.update({"test_port_ips": dutConfig["testPortIps"]})
        testParams.update({"probing_port_ids": probing_port_ids})
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
            "hwsku": dutTestParams['hwsku'],
            "src_dst_asic_diff": (dutConfig['dutAsic'] != dutConfig['dstDutAsic'])
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "pkts_num_egr_mem" in list(qosConfig.keys()):
            testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem"]

        if dutTestParams["basicParams"].get("platform_asic", None) == "cisco-8000" \
                and not get_src_dst_asic_and_duts["src_long_link"] and get_src_dst_asic_and_duts["dst_long_link"]:
            if "pkts_num_egr_mem_short_long" in list(qosConfig.keys()):
                testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem_short_long"]
            else:
                pytest.skip(
                    "pkts_num_egr_mem_short_long is missing in yaml file ")

        if "pkts_num_margin" in list(qosConfig[xoffProfile].keys()):
            testParams["pkts_num_margin"] = qosConfig[xoffProfile]["pkts_num_margin"]

        if "packet_size" in list(qosConfig[xoffProfile].keys()):
            testParams["packet_size"] = qosConfig[xoffProfile]["packet_size"]

        if 'cell_size' in list(qosConfig[xoffProfile].keys()):
            testParams["cell_size"] = qosConfig[xoffProfile]["cell_size"]

        bufferConfig = dutQosConfig["bufferConfig"]
        testParams["ingress_lossless_pool_size"] = bufferConfig["BUFFER_POOL"]["ingress_lossless_pool"]["size"]
        testParams["egress_lossy_pool_size"] = bufferConfig["BUFFER_POOL"]["egress_lossy_pool"]["size"]

        # Get cell_size with fallback to sub-layers if not found at top level
        def find_cell_size(config_dict):
            """Recursively find cell_size in config dictionary"""
            if isinstance(config_dict, dict):
                if 'cell_size' in config_dict:
                    return config_dict['cell_size']
                for value in config_dict.values():
                    result = find_cell_size(value)
                    if result is not None:
                        return result
            return None

        cell_size = dutQosConfig["param"].get("cell_size", None)
        if cell_size is None:
            cell_size = find_cell_size(dutQosConfig["param"])
        testParams["cell_size"] = cell_size

        # Get pdb parameter from command line
        enable_qos_ptf_pdb = request.config.getoption("--enable_qos_ptf_pdb", default=False)

        self.runPtfTest(
            ptfhost, testCase="ingress_drop_probing.IngressDropProbing", testParams=testParams,
            pdb=enable_qos_ptf_pdb, test_subdir='probe'
        )

    def testQosHeadroomPoolProbe(
            self, duthosts, get_src_dst_asic_and_duts, ptfhost, dutTestParams,
            dutConfig, dutQosConfig, ingressLosslessProfile, iptables_drop_ipv6_tx,  # noqa: F811
            change_lag_lacp_timer, tbinfo, request):
        # NOTE: cisco-8800 will skip this test since there are no headroom pool
        """
            Test QoS Headroom pool size using advanced probing

            This test uses a multi-source probing strategy to detect headroom pool limits.

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLosslessProfile (Fxiture): Map of ingress lossless buffer profile attributes

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        qosConfig = dutQosConfig["param"][portSpeedCableLength]
        testPortIps = dutConfig["testPortIps"]

        if 'hdrm_pool_size' not in list(qosConfig.keys()):
            pytest.skip("Headroom pool size is not enabled on this DUT")

        # if no enough ports, src_port_ids is empty list, skip the test
        if not qosConfig['hdrm_pool_size'].get('src_port_ids', None):
            pytest.skip("No enough test ports on this DUT")

        # run 4 pgs and 4 dscps test for dualtor and T1 dualtor scenario
        if not dutConfig['dualTor'] and not dutConfig['dualTorScenario']:
            qosConfig['hdrm_pool_size']['pgs'] = qosConfig['hdrm_pool_size']['pgs'][:2]
            qosConfig['hdrm_pool_size']['dscps'] = qosConfig['hdrm_pool_size']['dscps'][:2]

        src_dut_index = get_src_dst_asic_and_duts['src_dut_index']
        dst_dut_index = get_src_dst_asic_and_duts['dst_dut_index']
        src_asic_index = get_src_dst_asic_and_duts['src_asic_index']
        dst_asic_index = get_src_dst_asic_and_duts['dst_asic_index']

        if ('platform_asic' in dutTestParams["basicParams"] and
                dutTestParams["basicParams"]["platform_asic"] == "broadcom-dnx"):
            # for 100G port speed the number of ports required to fill headroom is huge,
            # hence skipping the test with speed 100G or cable length of 2k
            if portSpeedCableLength not in ['400000_120000m']:
                pytest.skip("Insufficient number of ports to fill the headroom")
            # Need to adjust hdrm_pool_size src_port_ids, dst_port_id and pgs_num based on how many source and dst ports
            # present
            src_ports = dutConfig['testPortIds'][src_dut_index][src_asic_index]
            if len(duthosts) == 1:
                if len(src_ports) < 3:
                    pytest.skip("Insufficient number of src ports for testQosHeadroomPoolProbe")
                qosConfig["hdrm_pool_size"]["src_port_ids"] = src_ports[1:3]
                qosConfig["hdrm_pool_size"]["pgs_num"] = 2 * len(qosConfig["hdrm_pool_size"]["src_port_ids"])
            else:
                if len(src_ports) < 5:
                    pytest.skip("Insufficient number of src ports for testQosHeadroomPoolProbe")
                qosConfig["hdrm_pool_size"]["src_port_ids"] = src_ports[1:5]
                qosConfig["hdrm_pool_size"]["pgs_num"] = 2 * len(qosConfig["hdrm_pool_size"]["src_port_ids"])

            if get_src_dst_asic_and_duts['src_asic'] == get_src_dst_asic_and_duts['dst_asic']:
                # Src and dst are the same asics, leave one for dst port and the rest for src ports
                qosConfig["hdrm_pool_size"]["dst_port_id"] = src_ports[0]

            else:
                qosConfig["hdrm_pool_size"]["dst_port_id"] = dutConfig['testPortIds'][dst_dut_index][dst_asic_index][0]

            src_port_vlans = [testPortIps[src_dut_index][src_asic_index][port]['vlan_id']
                              if 'vlan_id' in testPortIps[src_dut_index][src_asic_index][port]
                              else None for port in qosConfig["hdrm_pool_size"]["src_port_ids"]]
        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts, qosConfig["hdrm_pool_size"])

        # begin - collect all available test ports for probing
        duthost = get_src_dst_asic_and_duts['src_dut']
        src_dut = get_src_dst_asic_and_duts['src_dut']
        src_mgFacts = src_dut.get_extended_minigraph_facts(tbinfo)
        sonicport_to_testport = src_mgFacts.get("minigraph_port_indices", {})

        sonicport_to_pc = {}
        for pc_name, pc_info in src_mgFacts['minigraph_portchannels'].items():
            for member in pc_info['members']:
                sonicport_to_pc[member] = pc_name

        bcmport_to_sonicport = {}
        cmd = " | ".join(("bcmcmd 'knetctrl netif show'",
                          "grep Interface",
                          "awk '{print $4 \"=\" $7}'",
                          "awk -F= '{print $4 \" \" $2}'"))
        result = duthost.shell(cmd)['stdout'].strip('"\'"')
        for line in result.split("\n"):
            if line:
                parts = line.split()
                if len(parts) == 2:
                    bcmport_to_sonicport[parts[0]] = parts[1]

        xpe_to_bcmports = defaultdict(list)
        cmd = " | ".join(("bcmcmd 'show pmap'",
                          "grep -vE 'drivshell|show pmap|===|pipe'",
                          "awk '{ print $2 \" \" $1}'"))
        result = duthost.shell(cmd)['stdout'].strip('"\'"')
        for line in result.split("\n"):
            if line:
                parts = line.split()
                if len(parts) == 2:
                    xpe_to_bcmports[parts[0]].append(parts[1])
        if dutTestParams["basicParams"]["sonic_asic_type"] == "broadcom" and dutConfig["dutAsic"] in ("td2", "td3"):
            all_ports = []
            for xpe in list(xpe_to_bcmports.keys()):
                all_ports.extend(xpe_to_bcmports[xpe])
                if xpe != '0':
                    del xpe_to_bcmports[xpe]
            xpe_to_bcmports['0'] = all_ports

        cmd = " | ".join(("show int des",
                          r"grep -E 'Ethernet[0-9]+\s+up\s+up'",
                          " awk ' { print $1 } '"))
        sonicports_in_upstate = [intf for intf in duthost.shell(cmd)['stdout'].strip('"\'"').split("\n") if intf]

        xpe_to_sonicports = defaultdict(list)
        for xpe, bcmports in xpe_to_bcmports.items():
            for bcmport in bcmports:
                if bcmport in bcmport_to_sonicport:
                    xpe_to_sonicports[xpe].append(bcmport_to_sonicport[bcmport])

        xpe_to_sonicports_in_upstate = defaultdict(list)
        for xpe, bcmports in xpe_to_bcmports.items():
            for bcmport in bcmports:
                if bcmport in bcmport_to_sonicport:
                    if bcmport_to_sonicport[bcmport] in sonicports_in_upstate:
                        xpe_to_sonicports_in_upstate[xpe].append(bcmport_to_sonicport[bcmport])

        src_dut_index = get_src_dst_asic_and_duts['src_dut_index']
        src_asic_index = get_src_dst_asic_and_duts['src_asic_index']
        src_testPortIds = dutConfig["testPortIds"][src_dut_index][src_asic_index]

        xpe_to_sonicports_in_testPortIds = defaultdict(list)
        for xpe, ports in xpe_to_sonicports_in_upstate.items():
            for port in ports:
                if sonicport_to_testport[port] in src_testPortIds:
                    xpe_to_sonicports_in_testPortIds[xpe].append(port)

        xpe_to_unique_sonicports = defaultdict(list)
        for xpe, ports in xpe_to_sonicports_in_testPortIds.items():
            # sort by sonic port number
            sorted_ports = sorted(ports, key=lambda port: int(port.replace("Ethernet", "")))
            included_pcs = set()
            for port in sorted_ports:
                pc = sonicport_to_pc.get(port, None)
                if pc is None or pc not in included_pcs:
                    xpe_to_unique_sonicports[xpe].append(port)
                    if pc:
                        included_pcs.add(pc)

        xpe_to_testports = defaultdict(list)
        for xpe, sonicports in xpe_to_unique_sonicports.items():
            for sonicport in sonicports:
                if sonicport in sonicport_to_testport:
                    xpe_to_testports[xpe].append(sonicport_to_testport[sonicport])

        max_ports_xpe = max(xpe_to_testports.keys(),
                            key=lambda xpe: len(xpe_to_testports[xpe]))
        probing_port_ids = xpe_to_testports[max_ports_xpe]

        logger.info(
            f"sonicport_to_testport {sonicport_to_testport},\n"
            f"sonicport_to_pc {sonicport_to_pc},\n"
            f"bcmport_to_sonicport {bcmport_to_sonicport},\n"
            f"xpe_to_bcmports {xpe_to_bcmports},\n"
            f"sonicports_in_upstate {sonicports_in_upstate},\n"
            f"xpe_to_sonicports {xpe_to_sonicports},\n"
            f"xpe_to_sonicports_in_upstate {xpe_to_sonicports_in_upstate},\n"
            f"xpe_to_unique_sonicports {xpe_to_unique_sonicports},\n"
            f"xpe_to_testports {xpe_to_testports},\n"
            f"probing_port_ids {probing_port_ids},\n"
            f"test_port_ids {dutConfig['testPortIds']},\n"
            f"testPortIps {dutConfig['testPortIps']}"
        )
        # end

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])

        testParams.update({"test_port_ips": dutConfig["testPortIps"]})
        testParams.update({"probing_port_ids": probing_port_ids})

        testParams.update({
            "testbed_type": dutTestParams["topo"],
            "dscps": qosConfig["hdrm_pool_size"]["dscps"],
            "ecn": qosConfig["hdrm_pool_size"]["ecn"],
            "pgs": qosConfig["hdrm_pool_size"]["pgs"],
            "src_port_ids": qosConfig["hdrm_pool_size"]["src_port_ids"],
            "src_port_ips": [testPortIps[src_dut_index][src_asic_index][port]['peer_addr']
                             for port in qosConfig["hdrm_pool_size"]["src_port_ids"]],
            "dst_port_id": qosConfig["hdrm_pool_size"]["dst_port_id"],
            "dst_port_ip":
                testPortIps[dst_dut_index][dst_asic_index][qosConfig["hdrm_pool_size"]["dst_port_id"]]['peer_addr'],
            "pgs_num": qosConfig["hdrm_pool_size"]["pgs_num"],
            "pkts_num_trig_pfc": qosConfig["hdrm_pool_size"]["pkts_num_trig_pfc"],
            "pkts_num_leak_out": qosConfig["pkts_num_leak_out"],
            "pkts_num_hdrm_full": qosConfig["hdrm_pool_size"]["pkts_num_hdrm_full"],
            "pkts_num_hdrm_partial": qosConfig["hdrm_pool_size"]["pkts_num_hdrm_partial"],
            "hwsku": dutTestParams['hwsku'],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"]
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        pkts_num_trig_pfc_shp = qosConfig["hdrm_pool_size"].get(
            "pkts_num_trig_pfc_shp")
        if pkts_num_trig_pfc_shp:
            testParams["pkts_num_trig_pfc_shp"] = pkts_num_trig_pfc_shp

        packet_size = qosConfig["hdrm_pool_size"].get("packet_size")
        if packet_size:
            testParams["packet_size"] = packet_size
            testParams["cell_size"] = qosConfig["hdrm_pool_size"]["cell_size"]

        margin = qosConfig["hdrm_pool_size"].get("margin")
        if margin:
            testParams["margin"] = margin

        if "pkts_num_egr_mem" in list(qosConfig.keys()):
            testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem"]

        if "pkts_num_trig_pfc_multi" in qosConfig["hdrm_pool_size"]:
            testParams.update({"pkts_num_trig_pfc_multi": qosConfig["hdrm_pool_size"]["pkts_num_trig_pfc_multi"]})

        bufferConfig = dutQosConfig["bufferConfig"]
        testParams["ingress_lossless_pool_size"] = bufferConfig["BUFFER_POOL"]["ingress_lossless_pool"]["size"]
        testParams["egress_lossy_pool_size"] = bufferConfig["BUFFER_POOL"]["egress_lossy_pool"]["size"]

        # Get cell_size with fallback to sub-layers if not found at top level
        def find_cell_size(config_dict):
            """Recursively find cell_size in config dictionary"""
            if isinstance(config_dict, dict):
                if 'cell_size' in config_dict:
                    return config_dict['cell_size']
                for value in config_dict.values():
                    result = find_cell_size(value)
                    if result is not None:
                        return result
            return None

        cell_size = dutQosConfig["param"].get("cell_size", None)
        if cell_size is None:
            cell_size = find_cell_size(dutQosConfig["param"])
        testParams["cell_size"] = cell_size

        # Get pdb parameter from command line
        enable_qos_ptf_pdb = request.config.getoption("--enable_qos_ptf_pdb", default=False)

        if ('platform_asic' in dutTestParams["basicParams"] and
                dutTestParams["basicParams"]["platform_asic"] == "broadcom-dnx"):
            testParams['src_port_vlan'] = src_port_vlans

        self.runPtfTest(
            ptfhost, testCase="headroom_pool_probing.HeadroomPoolProbing",
            testParams=testParams, pdb=enable_qos_ptf_pdb, test_subdir='probe')
