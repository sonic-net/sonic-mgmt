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
import time
import json
import re
from tabulate import tabulate

from tests.common.fixtures.conn_graph_facts import fanout_graph_facts, conn_graph_facts, get_graph_facts    # noqa F401
from tests.common.fixtures.duthost_utils import dut_qos_maps, \
    separated_dscp_to_tc_map_on_uplink, load_dscp_to_pg_map                                 # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                     # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory                     # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                        # noqa F401
from tests.common.fixtures.ptfhost_utils import ptf_portmap_file                            # noqa F401
from tests.common.dualtor.dual_tor_utils import dualtor_ports, is_tunnel_qos_remap_enabled  # noqa F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.pfc_storm import PFCStorm
from tests.pfcwd.files.pfcwd_helper import set_pfc_timers, start_wd_on_ports
from tests.common.platform.device_utils import list_dut_fanout_connections
from tests.common.utilities import wait_until
from .qos_sai_base import QosSaiBase
from tests.common.helpers.ptf_tests_helper import downstream_links, upstream_links, select_random_link,\
    get_stream_ptf_ports, apply_dscp_cfg_setup, apply_dscp_cfg_teardown, fetch_test_logs_ptf   # noqa F401
from tests.common.utilities import get_ipv4_loopback_ip
from tests.common.helpers.base_helper import read_logs

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

PTF_PORT_MAPPING_MODE = 'use_orig_interface'

# Constants for DSCP to PG mapping test
DUMMY_OUTER_SRC_IP = '8.8.8.8'
DUMMY_INNER_SRC_IP = '9.9.9.9'
DUMMY_INNER_DST_IP = '10.10.10.10'


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exception(get_src_dst_asic_and_duts, loganalyzer):
    """ignore the syslog ERR syncd0#syncd: [03:00.0] brcm_sai_set_switch_
       attribute:1920 updating switch mac addr failed with error -2"""
    ignore_regex = [
        ".*ERR syncd[0-9]*#syncd.*brcm_sai_set_switch_attribute.*updating switch mac addr failed with error.*",
        # The following error log is related to the bug of https://github.com/sonic-net/sonic-buildimage/issues/13265
        ".*ERR lldp#lldpmgrd.*Command failed.*lldpcli.*configure.*ports.*unable to connect to socket.*",
        ".*ERR lldp#lldpmgrd.*Command failed.*lldpcli.*configure.*ports.*lldp.*unknown command from argument"
        ".*configure.*command was failed.*times, disabling retry.*"
        # Error related to syncd socket-timeout intermittenly
        ".*ERR syncd[0-9]*#dsserve: _ds2tty broken pipe.*"
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

    @pytest.fixture(scope='function')
    def change_port_speed(
            self, request, ptfhost, duthosts, dutTestParams, fanouthosts, dutConfig, tbinfo,
            get_src_dst_asic_and_duts, releaseAllPorts, handleFdbAging, lower_tor_host):
        """When port_target_speed is not None, change dut dst port speed and the corresponding port speed,
           and then recover them.
        """
        target_speed = request.config.getoption("--port_target_speed")
        is_change_sport_speed = False

        if target_speed:
            logger.info("target speed is {}".format(target_speed))
            duthost = get_src_dst_asic_and_duts['src_dut']
            dut_dst_port = dutConfig['dutInterfaces'][dutConfig["testPorts"]["dst_port_id"]]
            dut_int_status = duthost.get_interfaces_status()
            original_speed = dut_int_status[dut_dst_port]["speed"].replace("G", "000")

            if int(target_speed) < int(original_speed):
                fanout_port_list = []

                def _get_dut_change_speed_port_list():
                    src_mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
                    portchannels = src_mgFacts["minigraph_portchannels"]
                    dut_port_list = [dut_dst_port]
                    for po, po_info in portchannels.items():
                        if dut_dst_port in po_info['members']:
                            dut_port_list = po_info['members']
                            break
                    logger.info("dut port list :{}".format(dut_port_list))
                    return dut_port_list

                def _get_fanout_and_fanout_change_speed_port_list(dut_port_list):
                    for dut_port, fanout, fanout_port in list_dut_fanout_connections(duthost, fanouthosts):
                        if dut_port in dut_port_list:
                            fanout_port_list.append(fanout_port)
                            fanout_host = fanout
                    logger.info("fanout port list :{}".format(fanout_port_list))
                    return fanout_host

                def _update_target_speed(fanout_host, target_speed, dut_port_list):
                    logger.info("Get one speed that is smaller or equal than target speed")
                    all_dut_speeds = duthost.get_supported_speeds(dut_port_list[0])
                    all_fanout_speeds = fanout_host.get_supported_speeds(fanout_port_list[0])
                    common_speeds = list(set(all_dut_speeds).intersection(set(all_fanout_speeds)))
                    if target_speed not in common_speeds:
                        min_speed = common_speeds[0]
                        for speed in common_speeds:
                            if int(min_speed) > int(speed):
                                min_speed = speed
                            target_speed = min_speed
                    logger.info("Updated target_speed is {}".format(target_speed))
                    return target_speed

                def _set_speed_and_populate_arp(fanout_host, speed, dut_port_list):
                    for dut_port in dut_port_list:
                        logger.info('DUT: Set {} speed to {}'.format(dut_port, speed))
                        duthost.shell("sudo config interface speed {} {}".format(dut_port, speed))
                    for fanout_port in fanout_port_list:
                        logger.info('Fanout: Set {} speed to {}'.format(fanout_host, speed))
                        fanout_host.set_speed(fanout_port, speed)
                    wait_until(60, 1, 0, duthost.links_status_up, dut_port_list)

                    logger.info("populate arp, because change speed will cause port flap")
                    self.populate_arp_entries(
                        get_src_dst_asic_and_duts, ptfhost, dutTestParams, dutConfig,
                        releaseAllPorts, handleFdbAging, tbinfo, lower_tor_host)

                dut_port_list = _get_dut_change_speed_port_list()
                fanout_host = _get_fanout_and_fanout_change_speed_port_list(dut_port_list)
                target_speed = _update_target_speed(fanout_host, target_speed, dut_port_list)

                if int(target_speed) < int(original_speed):
                    logger.info("Change speed to {}".format(target_speed))
                    is_change_sport_speed = True
                    _set_speed_and_populate_arp(fanout_host, target_speed, dut_port_list)

        yield

        if is_change_sport_speed:
            logger.info("Restore speed to {}".format(original_speed))
            _set_speed_and_populate_arp(fanout_host, original_speed, dut_port_list)

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
        logger.debug('updateTestPortIdIp dutConfig["testPorts"]: {}'.format(dutConfig["testPorts"]))

    def testParameter(
        self, duthosts, get_src_dst_asic_and_duts, dutConfig, dutQosConfig, ingressLosslessProfile,
        ingressLossyProfile, egressLosslessProfile, dualtor_ports_for_duts
    ):
        logger.info("asictype {}".format(get_src_dst_asic_and_duts['src_dut'].facts["asic_type"]))
        logger.info("config {}".format(dutConfig))
        logger.info("qosConfig {}".format(dutQosConfig))
        logger.info("dualtor_ports {}".format(dualtor_ports_for_duts))

    @pytest.mark.parametrize("xoffProfile", ["xoff_1", "xoff_2", "xoff_3", "xoff_4"])
    def testQosSaiPfcXoffLimit(
        self, xoffProfile, duthosts, get_src_dst_asic_and_duts,
        ptfhost, dutTestParams, dutConfig, dutQosConfig,
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

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({"test_port_ids": dutConfig["testPortIds"]})
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

        if "pkts_num_margin" in list(qosConfig[xoffProfile].keys()):
            testParams["pkts_num_margin"] = qosConfig[xoffProfile]["pkts_num_margin"]

        if "packet_size" in list(qosConfig[xoffProfile].keys()):
            testParams["packet_size"] = qosConfig[xoffProfile]["packet_size"]

        if 'cell_size' in list(qosConfig[xoffProfile].keys()):
            testParams["cell_size"] = qosConfig[xoffProfile]["cell_size"]

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.PFCtest", testParams=testParams
        )

    @pytest.mark.parametrize("xonProfile", ["xon_1", "xon_2", "xon_3", "xon_4"])
    def testPfcStormWithSharedHeadroomOccupancy(
        self, xonProfile, ptfhost, fanouthosts, conn_graph_facts,  fanout_graph_facts,              # noqa F811
        dutTestParams, dutConfig, dutQosConfig, sharedHeadroomPoolSize, ingressLosslessProfile, localhost
    ):
        """
            Verify if the PFC Frames are not sent from the DUT after a PFC Storm from peer link.
            Ingress PG occupancy must cross into shared headroom region when the PFC Storm is seen
            Only for MLNX Platforms

            Args:
                xonProfile (pytest parameter): XON profile
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                fanout_graph_facts(fixture) : fanout graph info
                fanouthosts(AnsibleHost): fanout instance
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLosslessProfile (Fxiture): Map of egress lossless buffer profile attributes

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        normal_profile = ["xon_1", "xon_2"]
        if not dutConfig["dualTor"] and xonProfile not in normal_profile:
            pytest.skip(
                "Additional DSCPs are not supported on non-dual ToR ports")

        if dutTestParams["basicParams"]["sonic_asic_type"] != "mellanox":
            pytest.skip("This Test Case is only meant for Mellanox ASIC")

        if not sharedHeadroomPoolSize or sharedHeadroomPoolSize == "0":
            pytest.skip("Shared Headroom has to be enabled for this test")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if xonProfile in list(dutQosConfig["param"][portSpeedCableLength].keys()):
            qosConfig = dutQosConfig["param"][portSpeedCableLength]
        else:
            if dutTestParams['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in dutTestParams['topo']:
                qosConfig = dutQosConfig["param"][portSpeedCableLength]["breakout"]
            else:
                qosConfig = dutQosConfig["param"]

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dscp": qosConfig[xonProfile]["dscp"],
            "ecn": qosConfig[xonProfile]["ecn"],
            "pg": qosConfig[xonProfile]["pg"],
            "buffer_max_size": ingressLosslessProfile["size"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "pkts_num_trig_pfc": qosConfig[xonProfile]["pkts_num_trig_pfc"],
            "pkts_num_private_headrooom": dutQosConfig["param"]["pkts_num_private_headrooom"]
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "packet_size" in list(qosConfig[xonProfile].keys()):
            testParams["packet_size"] = qosConfig[xonProfile]["packet_size"]
        if 'cell_size' in list(qosConfig[xonProfile].keys()):
            testParams["cell_size"] = qosConfig[xonProfile]["cell_size"]

        # Params required for generating a PFC Storm
        duthost = dutConfig["srcDutInstance"]
        pfcwd_timers = set_pfc_timers()
        pfcwd_test_port_id = dutConfig["testPorts"]["src_port_id"]
        pfcwd_test_port = dutConfig["dutInterfaces"][pfcwd_test_port_id]
        fanout_neighbors = conn_graph_facts["device_conn"][duthost.hostname]
        peerdevice = fanout_neighbors[pfcwd_test_port]["peerdevice"]
        peerport = fanout_neighbors[pfcwd_test_port]["peerport"]
        peerdevice_hwsku = get_graph_facts(duthost, localhost, peerdevice)["device_info"][peerdevice]["HwSku"]
        peer_info = {
            'peerdevice': peerdevice,
            'hwsku': peerdevice_hwsku,
            'pfc_fanout_interface': peerport
        }
        queue_index = qosConfig[xonProfile]["pg"]
        frames_number = 100000000

        logging.info("PFC Storm Gen Params \n DUT iface: {} Fanout iface : {}\
                      queue_index: {} peer_info: {}".format(pfcwd_test_port,
                                                            peerport,
                                                            queue_index,
                                                            peer_info))

        # initialize PFC Storm Handler
        storm_hndle = PFCStorm(duthost, fanout_graph_facts, fanouthosts,
                               pfc_queue_idx=queue_index,
                               pfc_frames_number=frames_number,
                               peer_info=peer_info)
        storm_hndle.deploy_pfc_gen()

        # check if pfcwd status is enabled before running the test
        prev_state = duthost.shell(
            'sonic-db-cli CONFIG_DB HGETALL "PFC_WD|{}"'.format(pfcwd_test_port))['stdout']
        prev_poll_interval = duthost.shell(
            'sonic-db-cli CONFIG_DB HGET "PFC_WD|GLOBAL" POLL_INTERVAL')['stdout']

        try:
            prev_state = json.loads(prev_state)
        except Exception as e:
            logging.debug(
                "Exception: {}, PFC_WD State: {}".format(str(e), prev_state))
            prev_state = {}

        try:
            prev_poll_interval = int(prev_poll_interval)
            if int(pfcwd_timers['pfc_wd_poll_time']) > prev_poll_interval:
                pfcwd_timers['pfc_wd_poll_time'] = str(prev_poll_interval)
        except Exception as e:
            logging.debug("Exception: {}, Poll Interval: {}".format(
                str(e), prev_poll_interval))
            prev_poll_interval = 0

        # set poll interval for pfcwd
        duthost.command("pfcwd interval {}".format(
            pfcwd_timers['pfc_wd_poll_time']))

        logger.info("--- Start Pfcwd on port {}".format(pfcwd_test_port))
        start_wd_on_ports(duthost,
                          pfcwd_test_port,
                          pfcwd_timers['pfc_wd_restore_time'],
                          pfcwd_timers['pfc_wd_detect_time'])

        try:
            logger.info("---  Fill the ingress buffers ---")
            self.runPtfTest(
                ptfhost, testCase="sai_qos_tests.PtfFillBuffer", testParams=testParams
            )

            # Trigger PfcWd
            storm_hndle.start_storm()
            logger.info("PfcWd Status: {}".format(
                duthost.command("pfcwd show stats")["stdout_lines"]))
            time.sleep(10)
            storm_hndle.stop_storm()
            logger.info("PfcWd Status: {}".format(
                duthost.command("pfcwd show stats")["stdout_lines"]))

            logger.info(
                "---  Enable dst iface and verify if the PFC frames are not sent from src port ---")
            self.runPtfTest(
                ptfhost, testCase="sai_qos_tests.PtfReleaseBuffer", testParams=testParams
            )
        except Exception as e:
            raise e
        finally:
            if prev_state:
                logger.info(
                    "--- Restore original config {} for PfcWd on {} ---".format(prev_state, pfcwd_test_port))
                start_wd_on_ports(duthost,
                                  pfcwd_test_port,
                                  prev_state.get("restoration_time", "200"),
                                  prev_state.get("detection_time", "200"),
                                  prev_state.get("action", "drop"))
            else:
                logger.info("--- Stop PfcWd on {} ---".format(pfcwd_test_port))
                duthost.command("pfcwd stop {}".format(pfcwd_test_port))

            if prev_poll_interval:
                logger.info(
                    "--- Restore original poll interval {} ---".format(prev_poll_interval))
                duthost.command("pfcwd interval {}".format(prev_poll_interval))
            else:
                logger.info("--- Set Default Polling Interval ---".format())
                duthost.command("pfcwd interval {}".format("200"))

            self.runPtfTest(
                ptfhost, testCase="sai_qos_tests.PtfEnableDstPorts", testParams=testParams
            )

    @pytest.mark.parametrize("xonProfile", ["xon_1", "xon_2", "xon_3", "xon_4"])
    def testQosSaiPfcXonLimit(
        self, get_src_dst_asic_and_duts, xonProfile, ptfhost, dutTestParams, dutConfig, dutQosConfig,
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
        normal_profile = ["xon_1", "xon_2"]
        if not dutConfig["dualTor"] and xonProfile not in normal_profile:
            pytest.skip(
                "Additional DSCPs are not supported on non-dual ToR ports")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if xonProfile in list(dutQosConfig["param"][portSpeedCableLength].keys()):
            qosConfig = dutQosConfig["param"][portSpeedCableLength]
        else:
            if dutTestParams['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in dutTestParams['topo']:
                qosConfig = dutQosConfig["param"][portSpeedCableLength]["breakout"]
            else:
                qosConfig = dutQosConfig["param"]

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts)

        dst_port_count = set([
            dutConfig["testPorts"]["dst_port_id"],
            dutConfig["testPorts"]["dst_port_2_id"],
            dutConfig["testPorts"]["dst_port_3_id"],
        ])

        if len(dst_port_count) != 3:
            pytest.skip(
                "PFC Xon Limit test: Need at least 3 destination ports")

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({"test_port_ids": dutConfig["testPortIds"]})
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
            "hwsku": dutTestParams['hwsku'],
            "pkts_num_egr_mem": qosConfig[xonProfile].get('pkts_num_egr_mem', None),
            "src_dst_asic_diff": (dutConfig['dutAsic'] != dutConfig['dstDutAsic'])
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "pkts_num_egr_mem" in list(qosConfig.keys()):
            testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem"]

        if "pkts_num_hysteresis" in list(qosConfig[xonProfile].keys()):
            testParams["pkts_num_hysteresis"] = qosConfig[xonProfile]["pkts_num_hysteresis"]

        if "pkts_num_margin" in list(qosConfig[xonProfile].keys()):
            testParams["pkts_num_margin"] = qosConfig[xonProfile]["pkts_num_margin"]

        if "packet_size" in list(qosConfig[xonProfile].keys()):
            testParams["packet_size"] = qosConfig[xonProfile]["packet_size"]

        if 'cell_size' in list(qosConfig[xonProfile].keys()):
            testParams["cell_size"] = qosConfig[xonProfile]["cell_size"]

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.PFCXonTest", testParams=testParams
        )

    @pytest.mark.parametrize(
        "LosslessVoqProfile",
        ["lossless_voq_1", "lossless_voq_2",
         "lossless_voq_3", "lossless_voq_4"])
    def testQosSaiLosslessVoq(
            self, LosslessVoqProfile, ptfhost, dutTestParams, dutConfig,
            dutQosConfig, get_src_dst_asic_and_duts, skip_longlink
    ):
        """
            Test QoS SAI XOFF limits for various voq mode configurations
            Args:
                LosslessVoqProfile (pytest parameter): LosslessVoq Profile
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
        if not get_src_dst_asic_and_duts['single_asic_test']:
            pytest.skip(
                "This test needs to be revisited later, for the case "
                "where src and dst ASICs are different.")
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if dutTestParams['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in dutTestParams['topo']:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]["breakout"]
        else:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]
        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts, qosConfig[LosslessVoqProfile])

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        # Swapping the src_port_*_id with all available src ports, src_port* are
        # not available in this structure anymore.
        testParams.update({
            "dscp": qosConfig[LosslessVoqProfile]["dscp"],
            "ecn": qosConfig[LosslessVoqProfile]["ecn"],
            "pg": qosConfig[LosslessVoqProfile]["pg"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_1_id": dutConfig["testPorts"]["dst_port_2_id"],
            "src_port_1_ip": dutConfig["testPorts"]["dst_port_2_ip"],
            "src_port_2_id": dutConfig["testPorts"]["dst_port_3_id"],
            "src_port_2_ip": dutConfig["testPorts"]["dst_port_3_ip"],
            "num_of_flows": qosConfig[LosslessVoqProfile]["num_of_flows"],
            "pkts_num_leak_out": qosConfig["pkts_num_leak_out"],
            "pkts_num_trig_pfc": qosConfig[LosslessVoqProfile]
            ["pkts_num_trig_pfc"]
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = \
                dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "pkts_num_margin" in qosConfig[LosslessVoqProfile].keys():
            testParams["pkts_num_margin"] = \
                qosConfig[LosslessVoqProfile]["pkts_num_margin"]

        if "packet_size" in qosConfig[LosslessVoqProfile].keys():
            testParams["packet_size"] = \
                qosConfig[LosslessVoqProfile]["packet_size"]

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.LosslessVoq", testParams=testParams
        )

    def testQosSaiHeadroomPoolSize(
        self, get_src_dst_asic_and_duts, ptfhost, dutTestParams, dutConfig, dutQosConfig,
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
            # Need to adjust hdrm_pool_size src_port_ids, dst_port_id and pgs_num based on how many source and dst ports
            # present
            src_ports = dutConfig['testPortIds'][src_dut_index][src_asic_index]
            if get_src_dst_asic_and_duts['src_asic'] == get_src_dst_asic_and_duts['dst_asic']:
                # Src and dst are the same asics, leave one for dst port and the rest for src ports
                qosConfig["hdrm_pool_size"]["src_port_ids"] = src_ports[:-1]
                qosConfig["hdrm_pool_size"]["dst_port_id"] = src_ports[-1]
                qosConfig["hdrm_pool_size"]["pgs_num"] = 2 * len(qosConfig["hdrm_pool_size"]["src_port_ids"])
            else:
                qosConfig["hdrm_pool_size"]["src_port_ids"] = src_ports
                qosConfig["hdrm_pool_size"]["dst_port_id"] = dutConfig['testPortIds'][dst_dut_index][dst_asic_index][-1]
                qosConfig["hdrm_pool_size"]["pgs_num"] = 2 * len(qosConfig["hdrm_pool_size"]["src_port_ids"])

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts, qosConfig["hdrm_pool_size"])

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
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
            "hwsku": dutTestParams['hwsku']
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

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.HdrmPoolSizeTest",
            testParams=testParams
        )

    @pytest.mark.parametrize("sharedResSizeKey", ["shared_res_size_1", "shared_res_size_2"])
    def testQosSaiSharedReservationSize(
        self, sharedResSizeKey, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        get_src_dst_asic_and_duts, check_skip_shared_res_test
    ):
        """
            Test QoS SAI shared reservation size
            Args:
                sharedResSizeKey: qos.yml entry lookup key
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
        if ('modular_chassis' in get_src_dst_asic_and_duts['src_dut'].facts and
                get_src_dst_asic_and_duts['src_dut'].facts["modular_chassis"] == "True"):
            if dutConfig['dstDutAsic'] != "pac":
                pytest.skip("This test is skipped since not enough ports on cisco-8000 "
                            "T2 Q200.")
            if "shared_res_size_2" in sharedResSizeKey:
                pytest.skip("This test is skipped since on cisco-8000 Q100, "
                            "SQG thresholds have no impact on XOFF thresholds.")

        qosConfig = dutQosConfig["param"]
        src_dut_index = get_src_dst_asic_and_duts['src_dut_index']
        src_asic_index = get_src_dst_asic_and_duts['src_asic_index']
        dst_dut_index = get_src_dst_asic_and_duts['dst_dut_index']
        dst_asic_index = get_src_dst_asic_and_duts['dst_asic_index']
        src_testPortIps = dutConfig["testPortIps"][src_dut_index][src_asic_index]
        dst_testPortIps = dutConfig["testPortIps"][dst_dut_index][dst_asic_index]
        (_, src_port_ids, dst_port_ids) = check_skip_shared_res_test

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "testbed_type": dutTestParams["topo"],
            "dscps": qosConfig[sharedResSizeKey]["dscps"],
            "ecn": qosConfig[sharedResSizeKey]["ecn"],
            "pgs": qosConfig[sharedResSizeKey]["pgs"],
            "queues": qosConfig[sharedResSizeKey]["queues"],
            "src_port_ids": src_port_ids,
            "src_port_ips": [src_testPortIps[port]['peer_addr'] for port in src_port_ids],
            "dst_port_ids": dst_port_ids,
            "dst_port_ips": [dst_testPortIps[port]['peer_addr'] for port in dst_port_ids],
            "pkt_counts":  qosConfig[sharedResSizeKey]["pkt_counts"],
            "shared_limit_bytes": qosConfig[sharedResSizeKey]["shared_limit_bytes"],
            "hwsku": dutTestParams['hwsku']
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "packet_size" in qosConfig[sharedResSizeKey]:
            testParams["packet_size"] = qosConfig[sharedResSizeKey]["packet_size"]

        if "cell_size" in qosConfig[sharedResSizeKey]:
            testParams["cell_size"] = qosConfig[sharedResSizeKey]["cell_size"]

        if "pkts_num_margin" in qosConfig[sharedResSizeKey]:
            testParams["pkts_num_margin"] = qosConfig[sharedResSizeKey]["pkts_num_margin"]

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.SharedResSizeTest",
            testParams=testParams
        )

    def testQosSaiHeadroomPoolWatermark(
        self, duthosts, get_src_dst_asic_and_duts,  ptfhost, dutTestParams,
        dutConfig, dutQosConfig, ingressLosslessProfile, sharedHeadroomPoolSize,
        resetWatermark
    ):
        """
            Test QoS SAI Headroom pool watermark

            Args:
                duthosts (AnsibleHost): Dut hosts
                enum_rand_one_per_hwsku_frontend_hostname (AnsibleHost): select one of the frontend node
                    in multi dut testbed
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
        duthost = get_src_dst_asic_and_duts['src_dut']
        cmd_output = duthost.shell("show headroom-pool watermark", module_ignore_errors=True)
        if cmd_output['rc'] != 0:
            pytest.skip("Headroom pool watermark is not supported")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        qosConfig = dutQosConfig["param"][portSpeedCableLength]
        testPortIps = dutConfig["testPortIps"]
        if 'hdrm_pool_size' not in list(qosConfig.keys()):
            pytest.skip("Headroom pool size is not enabled on this DUT")

        # if no enough ports, src_port_ids is empty list, skip the test
        if not qosConfig['hdrm_pool_size'].get('src_port_ids', None):
            pytest.skip("No enough test ports on this DUT")

        src_dut_index = get_src_dst_asic_and_duts['src_dut_index']
        dst_dut_index = get_src_dst_asic_and_duts['dst_dut_index']
        src_asic_index = get_src_dst_asic_and_duts['src_asic_index']
        dst_asic_index = get_src_dst_asic_and_duts['dst_asic_index']

        if ('platform_asic' in dutTestParams["basicParams"] and
                dutTestParams["basicParams"]["platform_asic"] == "broadcom-dnx"):
            # Need to adjust hdrm_pool_size src_port_ids, dst_port_id and pgs_num based on how many source and dst ports
            # present
            src_ports = dutConfig['testPortIds'][src_dut_index][src_asic_index]
            if get_src_dst_asic_and_duts['src_asic'] == get_src_dst_asic_and_duts['dst_asic']:
                # Src and dst are the same asics, leave one for dst port and the rest for src ports
                qosConfig["hdrm_pool_size"]["src_port_ids"] = src_ports[:-1]
                qosConfig["hdrm_pool_size"]["dst_port_id"] = src_ports[-1]
                qosConfig["hdrm_pool_size"]["pgs_num"] = 2 * len(qosConfig["hdrm_pool_size"]["src_port_ids"])
            else:
                qosConfig["hdrm_pool_size"]["src_port_ids"] = src_ports
                qosConfig["hdrm_pool_size"]["dst_port_id"] = dutConfig['testPortIds'][dst_dut_index][dst_asic_index][-1]
                qosConfig["hdrm_pool_size"]["pgs_num"] = 2 * len(qosConfig["hdrm_pool_size"]["src_port_ids"])

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts, qosConfig["hdrm_pool_size"])

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
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
            "pkts_num_leak_out": qosConfig["pkts_num_leak_out"],
            "pkts_num_trig_pfc": qosConfig["hdrm_pool_size"]["pkts_num_trig_pfc"],
            "pkts_num_hdrm_full": qosConfig["hdrm_pool_size"]["pkts_num_hdrm_full"],
            "pkts_num_hdrm_partial": qosConfig["hdrm_pool_size"]["pkts_num_hdrm_partial"],
            "hdrm_pool_wm_multiplier": dutQosConfig["param"]["hdrm_pool_wm_multiplier"],
            "cell_size": dutQosConfig["param"]["cell_size"],
            "buf_pool_roid": ingressLosslessProfile["bufferPoolRoid"],
            "max_headroom": sharedHeadroomPoolSize,
            "hwsku": dutTestParams['hwsku']
        })

        margin = qosConfig["hdrm_pool_size"].get("margin")
        if margin:
            testParams["margin"] = margin

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "pkts_num_egr_mem" in list(qosConfig.keys()):
            testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem"]

        if "pkts_num_trig_pfc_multi" in qosConfig["hdrm_pool_size"]:
            testParams.update({"pkts_num_trig_pfc_multi": qosConfig["hdrm_pool_size"]["pkts_num_trig_pfc_multi"]})

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.HdrmPoolSizeTest",
            testParams=testParams
        )

    @pytest.mark.parametrize("bufPool", ["wm_buf_pool_lossless", "wm_buf_pool_lossy"])
    def testQosSaiBufferPoolWatermark(
        self, request, get_src_dst_asic_and_duts, bufPool, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        ingressLosslessProfile, egressLossyProfile, resetWatermark, _skip_watermark_multi_DUT
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
        if dutTestParams["basicParams"]["sonic_asic_type"] == 'cisco-8000' or \
                ('platform_asic' in dutTestParams["basicParams"] and
                 dutTestParams["basicParams"]["platform_asic"] == "broadcom-dnx"):
            disableTest = False
        if disableTest:
            pytest.skip("Buffer Pool watermark test is disabled")

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        if "wm_buf_pool_lossless" in bufPool:
            qosConfig = dutQosConfig["param"][portSpeedCableLength]
            triggerDrop = qosConfig[bufPool]["pkts_num_trig_pfc"]
            fillMin = qosConfig[bufPool]["pkts_num_fill_ingr_min"]
            buf_pool_roid = ingressLosslessProfile["bufferPoolRoid"]
        elif "wm_buf_pool_lossy" in bufPool:
            baseQosConfig = dutQosConfig["param"]
            qosConfig = baseQosConfig.get(portSpeedCableLength, baseQosConfig)
            try:
                triggerDrop = qosConfig[bufPool]["pkts_num_trig_egr_drp"]
            except KeyError:
                qosConfig = baseQosConfig
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
            "pkts_num_margin": qosConfig[bufPool].get("pkts_num_margin", 0),
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

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "packet_size" in list(qosConfig[bufPool].keys()):
            testParams["packet_size"] = qosConfig[bufPool]["packet_size"]

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.BufferPoolWatermarkTest",
            testParams=testParams
        )

    def testQosSaiLossyQueue(
        self, ptfhost, get_src_dst_asic_and_duts, dutTestParams, dutConfig, dutQosConfig,
        ingressLossyProfile, skip_src_dst_different_asic
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
        if "lossy_queue_1" in list(dutQosConfig["param"][portSpeedCableLength].keys()):
            qosConfig = dutQosConfig["param"][portSpeedCableLength]
        else:
            qosConfig = dutQosConfig["param"]

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts)

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({"test_port_ids": dutConfig["testPortIds"]})
        testParams.update({
            "dscp": qosConfig["lossy_queue_1"]["dscp"],
            "ecn": qosConfig["lossy_queue_1"]["ecn"],
            "pg": qosConfig["lossy_queue_1"]["pg"],
            "buffer_max_size": ingressLossyProfile["static_th"],
            "headroom_size": ingressLossyProfile["size"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_sys_ports": dutConfig["testPorts"]["dst_sys_ports"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "dst_port_2_id": dutConfig["testPorts"]["dst_port_2_id"],
            "dst_port_2_ip": dutConfig["testPorts"]["dst_port_2_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "pkts_num_leak_out": dutQosConfig["param"][portSpeedCableLength]["pkts_num_leak_out"],
            "pkts_num_trig_egr_drp": qosConfig["lossy_queue_1"]["pkts_num_trig_egr_drp"],
            "hwsku": dutTestParams['hwsku']
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "pkts_num_egr_mem" in list(qosConfig.keys()):
            testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem"]

        if "packet_size" in list(qosConfig["lossy_queue_1"].keys()):
            testParams["packet_size"] = qosConfig["lossy_queue_1"]["packet_size"]
            testParams["cell_size"] = qosConfig["lossy_queue_1"]["cell_size"]

        if "pkts_num_margin" in list(qosConfig["lossy_queue_1"].keys()):
            testParams["pkts_num_margin"] = qosConfig["lossy_queue_1"]["pkts_num_margin"]

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.LossyQueueTest",
            testParams=testParams
        )

    @pytest.mark.parametrize("LossyVoq", ["lossy_queue_voq_1", "lossy_queue_voq_2"])
    def testQosSaiLossyQueueVoq(
        self, LossyVoq, ptfhost, dutTestParams, dutConfig, dutQosConfig,
            ingressLossyProfile, duthost, localhost, get_src_dst_asic_and_duts,
            skip_src_dst_different_asic, dut_qos_maps    # noqa:  F811
    ):
        """
            Test QoS SAI Lossy queue with non_default voq and default voq
            Args:
                LossyVoq : qos.yml entry lookup key
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                ingressLossyProfile (Fxiture): Map of ingress lossy buffer profile attributes
                duthost : DUT host params
                localhost : local host params
            Returns:
                None
            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        if not get_src_dst_asic_and_duts['single_asic_test']:
            pytest.skip("Lossy Queue Voq test is only supported on cisco-8000 single-asic")
        if "lossy_queue_voq_1" in LossyVoq:
            if ('modular_chassis' in get_src_dst_asic_and_duts['src_dut'].facts and
                    get_src_dst_asic_and_duts['src_dut'].facts["modular_chassis"] == "True"):
                if get_src_dst_asic_and_duts['src_dut'].facts['platform'] != 'x86_64-88_lc0_36fh-r0':
                    pytest.skip("LossyQueueVoq: This test is skipped since cisco-8000 T2 "
                                "doesn't support split-voq.")
        elif "lossy_queue_voq_2" in LossyVoq:
            if get_src_dst_asic_and_duts['src_dut'].facts['platform'] == 'x86_64-88_lc0_36fh-r0':
                pytest.skip("LossyQueueVoq: lossy_queue_voq_2 test is not applicable "
                            "for x86_64-88_lc0_36fh-r0, with split-voq.")
            if not ('modular_chassis' in get_src_dst_asic_and_duts['src_dut'].facts and
                    get_src_dst_asic_and_duts['src_dut'].facts["modular_chassis"] == "True"):
                pytest.skip("LossyQueueVoq: lossy_queue_voq_2 test is not applicable "
                            "for split-voq.")
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        qosConfig = dutQosConfig["param"][portSpeedCableLength]
        flow_config = qosConfig[LossyVoq]["flow_config"]
        assert flow_config in ["separate", "shared"], "Invalid flow config '{}'".format(
            flow_config)

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts, qosConfig[LossyVoq])

        dst_port_id = dutConfig["testPorts"]["dst_port_id"]
        dst_port_ip = dutConfig["testPorts"]["dst_port_ip"]
        src_port_id = dutConfig["testPorts"]["src_port_id"]
        src_port_ip = dutConfig["testPorts"]["src_port_ip"]

        if separated_dscp_to_tc_map_on_uplink(dut_qos_maps):
            # We need to choose only the downlink port ids, which are associated
            # with AZURE dscp_to_tc mapping. The uplink ports have a
            # different mapping.
            if src_port_id not in dutConfig["testPorts"]["downlink_port_ids"]:
                for port_index, port_id in enumerate(dutConfig["testPorts"]["downlink_port_ids"]):
                    if port_id != dst_port_id:
                        src_port_id = port_id
                        src_port_ip = dutConfig["testPorts"]["downlink_port_ips"][port_index]
                        break
            if dst_port_id not in dutConfig["testPorts"]["downlink_port_ids"]:
                for port_index, port_id in enumerate(dutConfig["testPorts"]["downlink_port_ids"]):
                    if port_id != src_port_id:
                        dst_port_id = port_id
                        dst_port_ip = dutConfig["testPorts"]["downlink_port_ips"][port_index]
                        break

        try:
            testParams = dict()
            testParams.update(dutTestParams["basicParams"])
            testParams.update({
                "dscp": qosConfig[LossyVoq]["dscp"],
                "ecn": qosConfig[LossyVoq]["ecn"],
                "pg": qosConfig[LossyVoq]["pg"],
                "src_port_id": src_port_id,
                "src_port_ip": src_port_ip,
                "dst_port_id": dst_port_id,
                "dst_port_ip": dst_port_ip,
                "pkts_num_leak_out": dutQosConfig["param"][portSpeedCableLength]["pkts_num_leak_out"],
                "flow_config": flow_config,
                "pkts_num_trig_egr_drp": qosConfig[LossyVoq]["pkts_num_trig_egr_drp"]
            })

            if "platform_asic" in dutTestParams["basicParams"]:
                testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
            else:
                testParams["platform_asic"] = None

            if "packet_size" in qosConfig[LossyVoq].keys():
                testParams["packet_size"] = qosConfig[LossyVoq]["packet_size"]
                testParams["cell_size"] = qosConfig[LossyVoq]["cell_size"]

            if "pkts_num_margin" in list(qosConfig[LossyVoq].keys()):
                testParams["pkts_num_margin"] = qosConfig[LossyVoq]["pkts_num_margin"]

            self.runPtfTest(
                ptfhost, testCase="sai_qos_tests.LossyQueueVoqTest",
                testParams=testParams
            )

        except Exception:
            raise

    def testQosSaiDscpQueueMapping(
        self, ptfhost, get_src_dst_asic_and_duts, dutTestParams, dutConfig, dut_qos_maps # noqa F811
    ):
        """
            Test QoS SAI DSCP to queue mapping

            Args:
                duthost (AnsibleHost): The DUT host
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dut_qos_maps(Fixture): A fixture, return qos maps on DUT host
            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        # Skip the regular dscp to pg mapping test. Will run another test case instead.
        duthost = get_src_dst_asic_and_duts['src_dut']    # noqa F841
        if separated_dscp_to_tc_map_on_uplink(dut_qos_maps):
            pytest.skip(
                "Skip this test since separated DSCP_TO_TC_MAP is applied")

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts)

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "hwsku": dutTestParams['hwsku'],
            "dual_tor": dutConfig['dualTor'],
            "dual_tor_scenario": dutConfig['dualTorScenario']
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.DscpMappingPB",
            testParams=testParams
        )

    @pytest.mark.parametrize("direction", ["downstream", "upstream"])
    def testQosSaiSeparatedDscpQueueMapping(self, duthost, ptfhost, dutTestParams,
                                            dutConfig, direction, dut_qos_maps):        # noqa F811
        """
            Test QoS SAI DSCP to queue mapping.
            We will have separated DSCP_TO_TC_MAP for uplink/downlink ports on T1 if PCBB enabled.
            This test case will generate both upstream and downstream traffic to verify the behavior

            Args:
                duthost (AnsibleHost): The DUT host
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                direction (str): upstream/downstream
                dut_qos_maps(Fixture): A fixture, return qos maps on DUT host
            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        # Only run this test on T1 testbed when separated DSCP_TO_TC_MAP is defined
        if not separated_dscp_to_tc_map_on_uplink(dut_qos_maps):
            pytest.skip(
                "Skip this test since separated DSCP_TO_TC_MAP is not applied")
        if "dualtor" in dutTestParams['topo']:
            pytest.skip("Skip this test case on dualtor testbed")

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "hwsku": dutTestParams['hwsku'],
            "dual_tor_scenario": True
        })
        if direction == "downstream":
            testParams.update({
                "dst_port_id": dutConfig["testPorts"]["downlink_port_ids"][0],
                "dst_port_ip": dutConfig["testPorts"]["downlink_port_ips"][0],
                "src_port_id": dutConfig["testPorts"]["uplink_port_ids"][0],
                "src_port_ip": dutConfig["testPorts"]["uplink_port_ips"][0]
            })
            testParams.update({"leaf_downstream": True})
        else:
            testParams.update({
                "dst_port_id": dutConfig["testPorts"]["uplink_port_ids"][0],
                "dst_port_ip": dutConfig["testPorts"]["uplink_port_ips"][0],
                "src_port_id": dutConfig["testPorts"]["downlink_port_ids"][0],
                "src_port_ip": dutConfig["testPorts"]["downlink_port_ips"][0]
            })
            testParams.update({"leaf_downstream": False})

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

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
        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "vlan_id": dutConfig["testPorts"]["src_port_vlan"]
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

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

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "vlan_id": dutConfig["testPorts"]["src_port_vlan"]
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.Dot1pToPgMapping",
            testParams=testParams
        )

    def testQosSaiDwrr(
        self, ptfhost, duthosts, get_src_dst_asic_and_duts, dutTestParams, dutConfig, dutQosConfig, change_port_speed,
        skip_src_dst_different_asic
    ):
        """
            Test QoS SAI DWRR

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                duthost (AnsibleHost): The DUT for testing
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
        if "wrr" in qosConfig[portSpeedCableLength]:
            qosConfigWrr = qosConfig[portSpeedCableLength]["wrr"]
        else:
            qosConfigWrr = qosConfig["wrr"]
        duthost = get_src_dst_asic_and_duts['src_dut']
        qos_remap_enable = is_tunnel_qos_remap_enabled(duthost)

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts)

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update(qosConfigWrr)
        testParams.update({
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "pkts_num_leak_out": qosConfig[portSpeedCableLength]["pkts_num_leak_out"],
            "hwsku": dutTestParams['hwsku'],
            "topo": dutTestParams["topo"],
            "qos_remap_enable": qos_remap_enable
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "lossy_queue_1" in list(dutQosConfig["param"][portSpeedCableLength].keys()):
            testParams["ecn"] = qosConfig[portSpeedCableLength]["lossy_queue_1"]["ecn"]
        else:
            testParams["ecn"] = qosConfig["lossy_queue_1"]["ecn"]

        # To overcome this case:
        # When the previous test case just sends a large of packets only by one queue such as queue1,
        # then Dwrr test might fail, because queue1 has got much chance to send packets before,
        # so it will get less chance to send packets than expected.
        # Therefore the first run is a dry run, and will not check Dwrr function.
        # After the dry run, all tested queues can be scheduled so that all queues are at the same start.
        testParams["dry_run"] = True
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.WRRtest", testParams=testParams
        )

        testParams["dry_run"] = False
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.WRRtest", testParams=testParams
        )

    @pytest.mark.parametrize("pgProfile", ["wm_pg_shared_lossless", "wm_pg_shared_lossy"])
    def testQosSaiPgSharedWatermark(
        self, pgProfile, ptfhost, get_src_dst_asic_and_duts, dutTestParams, dutConfig, dutQosConfig,
        resetWatermark, _skip_watermark_multi_DUT, skip_src_dst_different_asic
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
        if pgProfile in list(dutQosConfig["param"][portSpeedCableLength].keys()):
            qosConfig = dutQosConfig["param"][portSpeedCableLength]
        else:
            if dutTestParams['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in dutTestParams['topo'] \
                    and pgProfile in list(dutQosConfig["param"][portSpeedCableLength]["breakout"].keys()):
                qosConfig = dutQosConfig["param"][portSpeedCableLength]["breakout"]
            else:
                qosConfig = dutQosConfig["param"]

        if "wm_pg_shared_lossless" in pgProfile:
            pktsNumFillShared = qosConfig[pgProfile]["pkts_num_trig_pfc"]
        elif "wm_pg_shared_lossy" in pgProfile:
            if dutConfig.get('dstDutAsic', 'UnknownDstDutAsic') == "pac":
                pytest.skip(
                    "PGSharedWatermark: Lossy test is not applicable in "
                    "cisco-8000 Q100 platform.")
            pktsNumFillShared = int(
                qosConfig[pgProfile]["pkts_num_trig_egr_drp"]) - 1

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts)

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
            "hwsku": dutTestParams['hwsku']
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "pkts_num_egr_mem" in list(qosConfig.keys()):
            testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem"]

        if "packet_size" in list(qosConfig[pgProfile].keys()):
            testParams["packet_size"] = qosConfig[pgProfile]["packet_size"]

        if "pkts_num_margin" in list(qosConfig[pgProfile].keys()):
            testParams["pkts_num_margin"] = qosConfig[pgProfile]["pkts_num_margin"]

        # For J2C+ we need the internal header size in calculating the shared watermarks
        if "internal_hdr_size" in list(qosConfig.keys()):
            testParams["internal_hdr_size"] = qosConfig["internal_hdr_size"]

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.PGSharedWatermarkTest",
            testParams=testParams
        )

    def testQosSaiPgHeadroomWatermark(
        self, ptfhost, get_src_dst_asic_and_duts, dutTestParams, dutConfig, dutQosConfig, resetWatermark,
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

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts)

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
            "hwsku": dutTestParams['hwsku']
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "pkts_num_egr_mem" in list(qosConfig.keys()):
            testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem"]

        if "pkts_num_margin" in list(qosConfig["wm_pg_headroom"].keys()):
            testParams["pkts_num_margin"] = qosConfig["wm_pg_headroom"]["pkts_num_margin"]

        if "packet_size" in list(qosConfig["wm_pg_headroom"].keys()):
            testParams["packet_size"] = qosConfig["wm_pg_headroom"]["packet_size"]

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.PGHeadroomWatermarkTest",
            testParams=testParams
        )

    def testQosSaiPGDrop(
        self, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        _check_ingress_speed_gte_400g
    ):
        """
            Test QoS SAI PG drop counter
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
        if "pg_drop" in list(dutQosConfig["param"][portSpeedCableLength].keys()):
            qosConfig = dutQosConfig["param"][portSpeedCableLength]
        else:
            qosConfig = dutQosConfig["param"]

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update(qosConfig['pg_drop'])
        testParams.update({
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "hwsku": dutTestParams['hwsku']
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.PGDropTest", testParams=testParams
        )

    @pytest.mark.parametrize("queueProfile", ["wm_q_shared_lossless", "wm_q_shared_lossy"])
    def testQosSaiQSharedWatermark(
        self, get_src_dst_asic_and_duts, queueProfile, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        resetWatermark, _skip_watermark_multi_DUT, skip_pacific_dst_asic
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
            if not get_src_dst_asic_and_duts['single_asic_test'] and \
                dutTestParams["basicParams"].get("platform_asic", None) \
                    == "cisco-8000":
                pytest.skip(
                    "Lossy test is not applicable in multiple ASIC case"
                    " in cisco-8000 platform.")
            if queueProfile in list(dutQosConfig["param"][portSpeedCableLength].keys()):
                qosConfig = dutQosConfig["param"][portSpeedCableLength]
            else:
                qosConfig = dutQosConfig["param"]
            triggerDrop = qosConfig[queueProfile]["pkts_num_trig_egr_drp"]

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts)

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
            "hwsku": dutTestParams['hwsku']
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "pkts_num_egr_mem" in list(qosConfig.keys()):
            testParams["pkts_num_egr_mem"] = qosConfig["pkts_num_egr_mem"]

        if "packet_size" in list(qosConfig[queueProfile].keys()):
            testParams["packet_size"] = qosConfig[queueProfile]["packet_size"]

        if "pkts_num_margin" in list(qosConfig[queueProfile].keys()):
            testParams["pkts_num_margin"] = qosConfig[queueProfile]["pkts_num_margin"]

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.QSharedWatermarkTest",
            testParams=testParams
        )

    def testQosSaiDscpToPgMapping(
        self, get_src_dst_asic_and_duts, duthost, request, ptfhost, dutTestParams, dutConfig, dut_qos_maps  # noqa F811
    ):
        """
            Test QoS SAI DSCP to PG mapping ptf test

            Args:
                duthost (AnsibleHost): The DUT host
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                dut_qos_maps(Fixture): A fixture, return qos maps on DUT host
            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        disableTest = request.config.getoption("--disable_test")
        if dutTestParams["basicParams"]["sonic_asic_type"] == 'cisco-8000' or \
                ('platform_asic' in dutTestParams["basicParams"] and
                 dutTestParams["basicParams"]["platform_asic"] in ["broadcom-dnx", "mellanox"]):
            disableTest = False
        if disableTest:
            pytest.skip("DSCP to PG mapping test disabled")
        # Skip the regular dscp to pg mapping test. Will run another test case instead.
        if separated_dscp_to_tc_map_on_uplink(dut_qos_maps):
            pytest.skip(
                "Skip this test since separated DSCP_TO_TC_MAP is applied")

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"]
        })

        if dutTestParams["basicParams"]["sonic_asic_type"] == 'cisco-8000':
            src_port_name = dutConfig["dutInterfaces"][testParams["src_port_id"]]
            testParams['dscp_to_pg_map'] = load_dscp_to_pg_map(duthost, src_port_name, dut_qos_maps)

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.DscpToPgMapping",
            testParams=testParams
        )

    @pytest.mark.parametrize("decap_mode", ["uniform", "pipe"])
    def testIPIPQosSaiDscpToPgMapping(
        self, duthost, ptfhost, dutTestParams, downstream_links, upstream_links, dut_qos_maps, decap_mode  # noqa F811
    ):
        """
            Test QoS SAI DSCP to PG mapping ptf test
            Args:
                duthost (AnsibleHost): The DUT host
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                downstream_links (Fixture): Dict containing DUT host downstream links
                upstream_links (Fixture): Dict containing DUT host upstream links
                dut_qos_maps(Fixture): A fixture, return qos maps on DUT host
                decap_mode (str): decap mode for DSCP
            Returns:
                None
            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        if separated_dscp_to_tc_map_on_uplink(dut_qos_maps):
            pytest.skip("Skip this test since separated DSCP_TO_TC_MAP is applied")

        # Setup DSCP decap config on DUT
        apply_dscp_cfg_setup(duthost, decap_mode)

        loopback_ip = get_ipv4_loopback_ip(duthost)
        downlink = select_random_link(downstream_links)
        uplink_ptf_ports = get_stream_ptf_ports(upstream_links)
        router_mac = duthost.facts["router_mac"]

        pytest_assert(downlink is not None, "No downlink found")
        pytest_assert(uplink_ptf_ports is not None, "No uplink found")
        pytest_assert(loopback_ip is not None, "No loopback IP found")
        pytest_assert(router_mac is not None, "No router MAC found")

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "router_mac": router_mac,
            "src_port_id": downlink.get("ptf_port_id"),
            "upstream_ptf_ports": uplink_ptf_ports,
            "inner_dst_port_ip": DUMMY_INNER_DST_IP,
            "inner_src_port_ip": DUMMY_INNER_SRC_IP,
            "outer_dst_port_ip": loopback_ip,
            "outer_src_port_ip": DUMMY_OUTER_SRC_IP,
            "decap_mode": decap_mode
        })

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.DscpToPgMappingIPIP",
            testParams=testParams,
            relax=True
        )

        output_table_path = fetch_test_logs_ptf(ptfhost, ptf_location="./dscp_to_pg_mapping_ipip.txt",
                                                dest_dir="/logs/dscp_to_pg_mapping_ipip.txt")
        fail_logs_path = fetch_test_logs_ptf(ptfhost, ptf_location="./dscp_to_pg_mapping_ipip_failures.txt",
                                             dest_dir="/logs/dscp_to_pg_mapping_ipip_failures.txt")
        local_logs = read_logs(output_table_path)
        local_fail_logs = read_logs(fail_logs_path)
        headers = local_logs[0]
        data = local_logs[1:]
        logger.info(tabulate(data, headers=headers))

        # Teardown DSCP decap config on DUT
        apply_dscp_cfg_teardown(duthost)

        if local_fail_logs:
            pytest.fail("Test Failed: {}".format(local_fail_logs))

    @pytest.mark.parametrize("direction", ["downstream", "upstream"])
    def testQosSaiSeparatedDscpToPgMapping(self, duthost, request, ptfhost,
                                           dutTestParams, dutConfig, direction, dut_qos_maps):      # noqa F811
        """
            Test QoS SAI DSCP to PG mapping ptf test.
            Since we are using different DSCP_TO_TC_MAP on uplink/downlink port, the test case also need to
            run separately

            Args:
                duthost (AnsibleHost)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                direction (str): downstream or upstream
                dut_qos_maps(Fixture): A fixture, return qos maps on DUT host
            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        if not separated_dscp_to_tc_map_on_uplink(dut_qos_maps):
            pytest.skip(
                "Skip this test since separated DSCP_TO_TC_MAP is not applied")
        if "dualtor" in dutTestParams['topo']:
            pytest.skip("Skip this test case on dualtor testbed")

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        if direction == "downstream":
            testParams.update({
                "dst_port_id": dutConfig["testPorts"]["downlink_port_ids"][0],
                "dst_port_ip": dutConfig["testPorts"]["downlink_port_ips"][0],
                "src_port_id": dutConfig["testPorts"]["uplink_port_ids"][0],
                "src_port_ip": dutConfig["testPorts"]["uplink_port_ips"][0]
            })
            src_port_name = dutConfig["testPorts"]["uplink_port_names"][0]
        else:
            testParams.update({
                "dst_port_id": dutConfig["testPorts"]["uplink_port_ids"][0],
                "dst_port_ip": dutConfig["testPorts"]["uplink_port_ips"][0],
                "src_port_id": dutConfig["testPorts"]["downlink_port_ids"][0],
                "src_port_ip": dutConfig["testPorts"]["downlink_port_ips"][0]
            })
            src_port_name = dutConfig["testPorts"]["downlink_port_names"][0]

        testParams['dscp_to_pg_map'] = load_dscp_to_pg_map(
            duthost, src_port_name, dut_qos_maps)

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.DscpToPgMapping",
            testParams=testParams
        )

    def testQosSaiDwrrWeightChange(
        self, get_src_dst_asic_and_duts, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        updateSchedProfile, skip_src_dst_different_asic
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

        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        qosConfig = dutQosConfig["param"]
        if "wrr_chg" in qosConfig[portSpeedCableLength]:
            qosConfigWrrChg = qosConfig[portSpeedCableLength]["wrr_chg"]
        else:
            qosConfigWrrChg = qosConfig["wrr_chg"]

        duthost = get_src_dst_asic_and_duts['src_dut']
        qos_remap_enable = is_tunnel_qos_remap_enabled(duthost)
        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update(qosConfigWrrChg)
        testParams.update({
            "ecn": qosConfigWrrChg["ecn"],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "pkts_num_leak_out": qosConfig[portSpeedCableLength]["pkts_num_leak_out"],
            "hwsku": dutTestParams['hwsku'],
            "topo": dutTestParams["topo"],
            "qos_remap_enable": qos_remap_enable
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.WRRtest", testParams=testParams
        )

    @pytest.mark.parametrize("queueProfile", ["wm_q_wm_all_ports"])
    def testQosSaiQWatermarkAllPorts(
        self, queueProfile, ptfhost, dutTestParams, dutConfig, dutQosConfig,
        get_src_dst_asic_and_duts, resetWatermark, _skip_watermark_multi_DUT,
        skip_pacific_dst_asic, dut_qos_maps    # noqa F811
    ):
        """
            Test QoS SAI Queue watermark test for lossless/lossy traffic on all ports

            Args:
                queueProfile (pytest parameter): queue profile
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut
                    interfaces, test port IDs, test port IPs, and test ports
                dutQosConfig (Fixture, dict): Map containing DUT host QoS
                    configuration
                resetWatermark (Fixture): reset queue watermarks
                dut_qos_maps (Fixture):  A fixture, return qos maps on DUT host

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

        allTestPorts = []
        allTestPortIps = []
        testPortIps = dutConfig["testPortIps"]
        all_dst_info = dutConfig['testPortIps'][get_src_dst_asic_and_duts['dst_dut_index']]
        allTestPorts.extend(list(all_dst_info[get_src_dst_asic_and_duts['dst_asic_index']].keys()))
        allTestPortIps.extend([
            x['peer_addr'] for x in
            all_dst_info[get_src_dst_asic_and_duts['dst_asic_index']].values()])

        src_port_id = dutConfig["testPorts"]["src_port_id"]
        src_port_ip = dutConfig["testPorts"]["src_port_ip"]
        if separated_dscp_to_tc_map_on_uplink(dut_qos_maps):
            # Remove the upstream ports from the test port list.
            allTestPorts = list(set(allTestPorts) - set(dutConfig['testPorts']['uplink_port_ids']))
            allTestPortIps = [
                testPortIps[get_src_dst_asic_and_duts['dst_dut_index']]
                [get_src_dst_asic_and_duts['dst_asic_index']][port]['peer_addr']
                for port in allTestPorts]
            src_port_id = allTestPorts[0]
            src_port_ip = allTestPortIps[0]
        try:
            tc_to_q_map = dut_qos_maps['tc_to_queue_map']['AZURE']
            tc_to_dscp_map = {v: k for k, v in dut_qos_maps['dscp_to_tc_map']['AZURE'].items()}
        except KeyError:
            pytest.skip(
                "Need both TC_TO_PRIORITY_GROUP_MAP and DSCP_TO_TC_MAP"
                "and key AZURE to run this test.")
        dscp_to_q_map = {tc_to_dscp_map[tc]: tc_to_q_map[tc] for tc in tc_to_dscp_map}
        if get_src_dst_asic_and_duts['single_asic_test']:
            if dutConfig["testPorts"]["src_port_id"] in allTestPorts:
                allTestPorts.remove(dutConfig["testPorts"]["src_port_id"])
            if dutConfig["testPorts"]["src_port_ip"] in allTestPortIps:
                allTestPortIps.remove(dutConfig["testPorts"]["src_port_ip"])

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "ecn": qosConfig[queueProfile]["ecn"],
            "dst_port_ids": allTestPorts,
            "dst_port_ips": allTestPortIps,
            "src_port_id": src_port_id,
            "src_port_ip": src_port_ip,
            "src_port_vlan": dutConfig["testPorts"]["src_port_vlan"],
            "pkts_num_leak_out": dutQosConfig["param"][portSpeedCableLength]["pkts_num_leak_out"],
            "pkt_count": qosConfig[queueProfile]["pkt_count"],
            "cell_size": qosConfig[queueProfile]["cell_size"],
            "hwsku": dutTestParams['hwsku'],
            "dscp_to_q_map": dscp_to_q_map
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "packet_size" in qosConfig[queueProfile].keys():
            testParams["packet_size"] = qosConfig[queueProfile]["packet_size"]

        if "pkts_num_margin" in qosConfig[queueProfile].keys():
            testParams["pkts_num_margin"] = qosConfig[queueProfile]["pkts_num_margin"]

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.QWatermarkAllPortTest",
            testParams=testParams
        )

    def testQosSaiLossyQueueVoqMultiSrc(
        self, ptfhost, dutTestParams, dutConfig, dutQosConfig,
            get_src_dst_asic_and_duts, skip_longlink
    ):
        """
            Test QoS SAI Lossy queue with multiple source ports, applicable for fair-voq and split-voq
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
        if not get_src_dst_asic_and_duts['single_asic_test']:
            pytest.skip("LossyQueueVoqMultiSrc: This test is skipped on multi-asic,"
                        "since same ingress backplane port will be used on egress asic.")
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        LossyVoq = "lossy_queue_voq_3"
        if LossyVoq in dutQosConfig["param"][portSpeedCableLength].keys():
            qosConfig = dutQosConfig["param"][portSpeedCableLength]
        else:
            qosConfig = dutQosConfig["param"]

        self.updateTestPortIdIp(dutConfig, get_src_dst_asic_and_duts, qosConfig[LossyVoq])

        src_dut_index = get_src_dst_asic_and_duts['src_dut_index']
        src_asic_index = get_src_dst_asic_and_duts['src_asic_index']

        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        all_src_ports = dutConfig["testPortIps"][src_dut_index][src_asic_index]
        all_src_port_ids = set(all_src_ports.keys())
        if get_src_dst_asic_and_duts['single_asic_test']:
            all_src_port_ids = set(all_src_ports.keys()) - \
                    set([dutConfig["testPorts"]["src_port_id"],
                        dutConfig["testPorts"]["dst_port_id"],
                        dutConfig["testPorts"]["dst_port_2_id"],
                        dutConfig["testPorts"]["dst_port_3_id"]])
        all_src_port_ids = list(all_src_port_ids)
        testParams.update({
            "dscp": qosConfig[LossyVoq]["dscp"],
            "ecn": qosConfig[LossyVoq]["ecn"],
            "pg": qosConfig[LossyVoq]["pg"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
            "src_port_2_id": all_src_port_ids[0],
            "src_port_2_ip":  all_src_ports[all_src_port_ids[0]]['peer_addr'],
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "pkts_num_leak_out": dutQosConfig["param"][portSpeedCableLength]["pkts_num_leak_out"],
            "pkts_num_trig_egr_drp": qosConfig[LossyVoq]["pkts_num_trig_egr_drp"]
        })

        if "platform_asic" in dutTestParams["basicParams"]:
            testParams["platform_asic"] = dutTestParams["basicParams"]["platform_asic"]
        else:
            testParams["platform_asic"] = None

        if "packet_size" in qosConfig[LossyVoq].keys():
            testParams["packet_size"] = qosConfig[LossyVoq]["packet_size"]
            testParams["cell_size"] = qosConfig[LossyVoq]["cell_size"]

        if "pkts_num_margin" in qosConfig[LossyVoq].keys():
            testParams["pkts_num_margin"] = qosConfig[LossyVoq]["pkts_num_margin"]

        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.LossyQueueVoqMultiSrcTest",
            testParams=testParams
        )

    def testQosSaiFullMeshTrafficSanity(
            self, ptfhost, dutTestParams, dutConfig, dutQosConfig,
            get_src_dst_asic_and_duts, dut_qos_maps, # noqa F811
            set_static_route_ptf64
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
        # Execution with a specific set of dst port
        def run_test_for_dst_port(start, end):
            test_params = dict()
            test_params.update(dutTestParams["basicParams"])
            test_params.update({
                "testbed_type": dutTestParams["topo"],
                "all_src_port_id_to_ip": all_src_port_id_to_ip,
                "all_src_port_id_to_name": all_src_port_id_to_name,
                "all_dst_port_id_to_ip": {port_id: all_dst_port_id_to_ip[port_id] for port_id in range(start, end)},
                "all_dst_port_id_to_name": {port_id: all_dst_port_id_to_name[port_id] for port_id in range(start, end)},
                "dscp_to_q_map": dscp_to_q_map,
                # Add a log_suffix to have separate log and pcap file name
                "log_suffix": "_".join([str(port_id) for port_id in range(start, end)]),
                "hwsku": dutTestParams['hwsku']
            })

            self.runPtfTest(ptfhost, testCase="sai_qos_tests.FullMeshTrafficSanity", testParams=test_params)

        src_dut_index = get_src_dst_asic_and_duts['src_dut_index']
        dst_dut_index = get_src_dst_asic_and_duts['dst_dut_index']
        src_asic_index = get_src_dst_asic_and_duts['src_asic_index']
        dst_asic_index = get_src_dst_asic_and_duts['dst_asic_index']

        src_testPortIps = dutConfig["testPortIps"][src_dut_index][src_asic_index]
        dst_testPortIps = dutConfig["testPortIps"][dst_dut_index][dst_asic_index]

        # Fetch all port IDs and IPs
        all_src_port_id_to_ip = {port_id: src_testPortIps[port_id]['peer_addr'] for port_id in src_testPortIps.keys()}

        all_src_port_id_to_name = {
                                    port_id: dutConfig["dutInterfaces"][port_id]
                                    for port_id in all_src_port_id_to_ip.keys()
                                  }

        all_dst_port_id_to_ip = {
                                    port_id: set_static_route_ptf64[port_id]['generated_ip']
                                    for port_id in dst_testPortIps.keys()
                                }

        all_dst_port_id_to_name = {
                                    port_id: dutConfig["dutInterfaces"][port_id]
                                    for port_id in all_dst_port_id_to_ip.keys()
                                  }

        try:
            tc_to_q_map = dut_qos_maps['tc_to_queue_map']['AZURE']
            tc_to_dscp_map = {v: k for k, v in dut_qos_maps['dscp_to_tc_map']['AZURE'].items()}
        except KeyError:
            pytest.skip(
                "Need both TC_TO_PRIORITY_GROUP_MAP and DSCP_TO_TC_MAP"
                "and key AZURE to run this test.")

        dscp_to_q_map = {tc_to_dscp_map[tc]: tc_to_q_map[tc] for tc in tc_to_dscp_map if tc != 7}

        # Define the number of splits
        # for the dst port list
        num_splits = 4

        # Get all keys and sort them
        all_keys = sorted(all_dst_port_id_to_ip.keys())

        # Calculate the split points
        split_points = [all_keys[i * len(all_keys) // num_splits] for i in range(1, num_splits)]

        # Execute with one set of dst port at a time,  avoids ptf run getting timed out
        for start, end in zip([0] + split_points, split_points + [len(all_keys)]):
            run_test_for_dst_port(start, end)
