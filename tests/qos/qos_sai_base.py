import ipaddress
import json
import logging
import pytest
import re
import yaml

import random
import os
import sys
import copy

from tests.common.fixtures.ptfhost_utils import ptf_portmap_file  # noqa F401
import copy
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice
from tests.common.cisco_data import is_cisco_device
from tests.common.dualtor.dual_tor_utils import upper_tor_host,lower_tor_host,dualtor_ports
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports, get_mux_status, check_mux_status, validate_check_result
from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR
from tests.common.utilities import check_qos_db_fv_reference_with_table
from tests.common.fixtures.duthost_utils import dut_qos_maps, separated_dscp_to_tc_map_on_uplink
from tests.common.utilities import wait_until
from tests.ptf_runner import ptf_runner
from tests.common.system_utils import docker
from tests.common.errors import RunAnsibleModuleFail

logger = logging.getLogger(__name__)

class QosBase:
    """
    Common APIs
    """
    SUPPORTED_T0_TOPOS = ["t0", "t0-64", "t0-116", "t0-35", "dualtor-56", "dualtor-120", "dualtor", "t0-80", "t0-backend"]
    SUPPORTED_T1_TOPOS = ["t1-lag", "t1-64-lag", "t1-56-lag", "t1-backend"]
    SUPPORTED_PTF_TOPOS = ['ptf32', 'ptf64']
    SUPPORTED_ASIC_LIST = ["gb", "td2", "th", "th2", "spc1", "spc2", "spc3", "td3", "th3", "j2c+", "jr2"]

    TARGET_QUEUE_WRED = 3
    TARGET_LOSSY_QUEUE_SCHED = 0
    TARGET_LOSSLESS_QUEUE_SCHED = 3

    buffer_model_initialized = False
    buffer_model = None

    def isBufferInApplDb(self, dut_asic):
        if not self.buffer_model_initialized:
            self.buffer_model = dut_asic.run_redis_cmd(
                argv = [
                    "redis-cli", "-n", "4", "hget",
                    "DEVICE_METADATA|localhost", "buffer_model"
                ]
            )

            self.buffer_model_initialized = True
            logger.info(
                "Buffer model is {}, buffer tables will be fetched from {}".
                format(
                    self.buffer_model or "not defined",
                    "APPL_DB" if self.buffer_model else "CONFIG_DB"
                )
            )
        return self.buffer_model

    @pytest.fixture(scope='class', autouse=True)
    def dutTestParams(self, duthosts, dut_test_params_qos, tbinfo, get_src_dst_asic_and_duts):
        """
            Prepares DUT host test params
            Returns:
                dutTestParams (dict): DUT host test params
        """
        # update router mac
        if dut_test_params_qos["topo"] in self.SUPPORTED_T0_TOPOS:
            dut_test_params_qos["basicParams"]["router_mac"] = ''

        elif "dualtor" in tbinfo["topo"]["name"]:
            # For dualtor qos test scenario, DMAC of test traffic is default vlan interface's MAC address.
            # To reduce duplicated code, put "is_dualtor" and "def_vlan_mac" into dutTestParams['basicParams'].
            dut_test_params_qos["basicParams"]["is_dualtor"] = True
            vlan_cfgs = tbinfo['topo']['properties']['topology']['DUT']['vlan_configs']
            if vlan_cfgs and 'default_vlan_config' in vlan_cfgs:
                default_vlan_name = vlan_cfgs['default_vlan_config']
                if default_vlan_name:
                    for vlan in vlan_cfgs[default_vlan_name].values():
                        if 'mac' in vlan and vlan['mac']:
                            dut_test_params_qos["basicParams"]["def_vlan_mac"] = vlan['mac']
                            break
            pytest_assert(dut_test_params_qos["basicParams"]["def_vlan_mac"] is not None, "Dual-TOR miss default VLAN MAC address")
        else:
            try:
                duthost = get_src_dst_asic_and_duts['src_dut']
                asic = duthost.asic_instance().asic_index
                dut_test_params_qos['basicParams']["router_mac"] = duthost.shell(
                    'sonic-db-cli -n asic{} CONFIG_DB hget "DEVICE_METADATA|localhost" mac'.format(asic))['stdout']
            except RunAnsibleModuleFail:
                dut_test_params_qos['basicParams']["router_mac"] = duthost.shell(
                    'sonic-db-cli CONFIG_DB hget "DEVICE_METADATA|localhost" mac')['stdout']

        yield dut_test_params_qos

    def runPtfTest(self, ptfhost, testCase='', testParams={}):
        """
            Runs QoS SAI test case on PTF host

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                testCase (str): SAI tests test case name
                testParams (dict): Map of test params required by testCase

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        params = [
                  "/root/env-python3/bin/ptf",
                  "--test-dir",
                  "saitests/py3",
                  testCase,
                  "--platform-dir",
                  "ptftests",
                  "--platform",
                  "remote",
                  "-t",
                  ";".join(["{}={}".format(k, repr(v)) for k, v in testParams.items()]),
                  "--qlen",
                  "10000",
                  "--disable-ipv6",
                  "--disable-vxlan",
                  "--disable-geneve",
                  "--disable-erspan",
                  "--disable-mpls",
                  "--disable-nvgre",
                  "--log-file",
                  "/tmp/{0}.log".format(testCase),
                  "--test-case-timeout",
                  "1200"
              ]
        result = ptfhost.shell(
                      argv=params,
                      chdir="/root",
                      )
        pytest_assert(result["rc"] == 0, "Failed when running test '{0}'".format(testCase))

class QosSaiBase(QosBase):
    """
        QosSaiBase contains collection of pytest fixtures that ready the
        testbed for QoS SAI test cases.
    """

    def __computeBufferThreshold(self, dut_asic, bufferProfile):
        """
            Computes buffer threshold for dynamic threshold profiles

            Args:
                dut_asic (SonicAsic): Device ASIC Under Test (DUT)
                bufferProfile (dict, inout): Map of puffer profile attributes

            Returns:
                Updates bufferProfile with computed buffer threshold
        """
        if self.isBufferInApplDb(dut_asic):
            db = "0"
            keystr = "BUFFER_POOL_TABLE:"
        else:
            db = "4"
            keystr = "BUFFER_POOL|"
        if check_qos_db_fv_reference_with_table(dut_asic) == True:
            pool = bufferProfile["pool"].encode("utf-8").translate(None, "[]")
        else:
            pool = keystr + bufferProfile["pool"].encode("utf-8")
        bufferSize = int(
            dut_asic.run_redis_cmd(
                argv = ["redis-cli", "-n", db, "HGET", pool, "size"]
            )[0]
        )
        bufferScale = 2**float(bufferProfile["dynamic_th"])
        bufferScale /= (bufferScale + 1)
        bufferProfile.update(
            {"static_th": int(bufferProfile["size"]) + int(bufferScale * bufferSize)}
        )

    def __updateVoidRoidParams(self, dut_asic, bufferProfile):
        """
            Updates buffer profile with VOID/ROID params

            Args:
                dut_asic (SonicAsic): Device Under Test (DUT)
                bufferProfile (dict, inout): Map of puffer profile attributes

            Returns:
                Updates bufferProfile with VOID/ROID obtained from Redis db
        """
        if check_qos_db_fv_reference_with_table(dut_asic) == True:
            if self.isBufferInApplDb(dut_asic):
                bufferPoolName = bufferProfile["pool"].encode("utf-8").translate(
                    None, "[]").replace("BUFFER_POOL_TABLE:",''
                )
            else:
                bufferPoolName = bufferProfile["pool"].encode("utf-8").translate(
                    None, "[]").replace("BUFFER_POOL|",''
                )
        else:
            bufferPoolName = bufferProfile["pool"].encode("utf-8")

        bufferPoolVoid = dut_asic.run_redis_cmd(
            argv = [
                "redis-cli", "-n", "2", "HGET",
                "COUNTERS_BUFFER_POOL_NAME_MAP", bufferPoolName
            ]
        )[0].encode("utf-8")
        bufferProfile.update({"bufferPoolVoid": bufferPoolVoid})

        bufferPoolRoid = dut_asic.run_redis_cmd(
            argv = ["redis-cli", "-n", "1", "HGET", "VIDTORID", bufferPoolVoid]
        )[0].encode("utf-8").replace("oid:",'')
        bufferProfile.update({"bufferPoolRoid": bufferPoolRoid})

    def __getBufferProfile(self, request, dut_asic, os_version, table, port, priorityGroup):
        """
            Get buffer profile attribute from Redis db

            Args:
                request (Fixture): pytest request object
                dut_asic(SonicAsic): Device Under Test (DUT)
                table (str): Redis table name
                port (str): DUT port alias
                priorityGroup (str): QoS priority group

            Returns:
                bufferProfile (dict): Map of buffer profile attributes
        """

        if table == "BUFFER_QUEUE_TABLE" and dut_asic.sonichost.facts['switch_type'] == 'voq':
            # For VoQ chassis, the buffer queues config is based on system port
            if dut_asic.sonichost.is_multi_asic:
                port = "{}:{}:{}".format(dut_asic.sonichost.hostname, dut_asic.namespace, port)
            else:
                port = "{}:Asic0:{}".format(dut_asic.sonichost.hostname, port)

        if self.isBufferInApplDb(dut_asic):
            db = "0"
            keystr = "{0}:{1}:{2}".format(table, port, priorityGroup)
            bufkeystr = "BUFFER_PROFILE_TABLE:"
        else:
            db = "4"
            keystr = "{0}|{1}|{2}".format(table, port, priorityGroup)
            bufkeystr = "BUFFER_PROFILE|"

        if check_qos_db_fv_reference_with_table(dut_asic) == True:
            bufferProfileName = dut_asic.run_redis_cmd(
                argv = ["redis-cli", "-n", db, "HGET", keystr, "profile"]
            )[0].encode("utf-8").translate(None, "[]")
        else:
            bufferProfileName = bufkeystr + dut_asic.run_redis_cmd(
                argv = ["redis-cli", "-n", db, "HGET", keystr, "profile"])[0].encode("utf-8")

        result = dut_asic.run_redis_cmd(
            argv = ["redis-cli", "-n", db, "HGETALL", bufferProfileName]
        )
        it = iter(result)
        bufferProfile = dict(zip(it, it))
        bufferProfile.update({"profileName": bufferProfileName})

        # Update profile static threshold value if  profile threshold is dynamic
        if "dynamic_th" in bufferProfile.keys():
            self.__computeBufferThreshold(dut_asic, bufferProfile)

        if "pg_lossless" in bufferProfileName:
            pytest_assert(
                "xon" in bufferProfile.keys() and "xoff" in bufferProfile.keys(),
                "Could not find xon and/or xoff values for profile '{0}'".format(
                    bufferProfileName
                )
            )

        if "201811" not in os_version:
            self.__updateVoidRoidParams(dut_asic, bufferProfile)

        return bufferProfile

    def __getSharedHeadroomPoolSize(self, request, dut_asic):
        """
            Get shared headroom pool size from Redis db

            Args:
                request (Fixture): pytest request object
                dut_asic (SonicAsic): Device Under Test (DUT)

            Returns:
                size (str) size of shared headroom pool
                None if shared headroom pool isn't enabled
        """
        if self.isBufferInApplDb(dut_asic):
            db = "0"
            keystr = "BUFFER_POOL_TABLE:ingress_lossless_pool"
        else:
            db = "4"
            keystr = "BUFFER_POOL|ingress_lossless_pool"
        result = dut_asic.run_redis_cmd(
            argv = ["redis-cli", "-n", db, "HGETALL", keystr]
        )
        it = iter(result)
        ingressLosslessPool = dict(zip(it, it))
        return ingressLosslessPool.get("xoff")

    def __getEcnWredParam(self, dut_asic, table, port):
        """
            Get ECN/WRED parameters from Redis db

            Args:
                dut_asic (SonicAsic): Device Under Test (DUT)
                table (str): Redis table name
                port (str): DUT port alias

            Returns:
                wredProfile (dict): Map of ECN/WRED attributes
        """
        if check_qos_db_fv_reference_with_table(dut_asic) == True:
            wredProfileName = dut_asic.run_redis_cmd(
                argv = [
                    "redis-cli", "-n", "4", "HGET",
                    "{0}|{1}|{2}".format(table, port, self.TARGET_QUEUE_WRED),
                    "wred_profile"
                ]
            )[0].encode("utf-8").translate(None, "[]")
        else:
            wredProfileName = "WRED_PROFILE|" + dut_asic.run_redis_cmd(
                argv = [
                    "redis-cli", "-n", "4", "HGET",
                    "{0}|{1}|{2}".format(table, port, self.TARGET_QUEUE_WRED),
                    "wred_profile"
                ]
            )[0].encode("utf-8")

        result = dut_asic.run_redis_cmd(
            argv = ["redis-cli", "-n", "4", "HGETALL", wredProfileName]
        )
        it = iter(result)
        wredProfile = dict(zip(it, it))

        return wredProfile

    def __getWatermarkStatus(self, dut_asic):
        """
            Get watermark status from Redis db

            Args:
                dut_asic (SonicAsic): Device Under Test (DUT)

            Returns:
                watermarkStatus (str): Watermark status
        """
        watermarkStatus = dut_asic.run_redis_cmd(
            argv = [
                "redis-cli", "-n", "4", "HGET",
                "FLEX_COUNTER_TABLE|QUEUE_WATERMARK", "FLEX_COUNTER_STATUS"
            ]
        )[0].encode("utf-8")

        return watermarkStatus

    def __getSchedulerParam(self, dut_asic, port, queue):
        """
            Get scheduler parameters from Redis db

            Args:
                dut_asic (SonicAsic): Device Under Test (DUT)
                port (str): DUT port alias
                queue (str): QoS queue

            Returns:
                SchedulerParam (dict): Map of scheduler parameters
        """
        if check_qos_db_fv_reference_with_table(dut_asic) == True:
            schedProfile = dut_asic.run_redis_cmd(
                argv = [
                    "redis-cli", "-n", "4", "HGET",
                    "QUEUE|{0}|{1}".format(port, queue), "scheduler"
                ]
            )[0].encode("utf-8").translate(None, "[]")
        else:
            schedProfile = "SCHEDULER|" + dut_asic.run_redis_cmd(
                argv = [
                    "redis-cli", "-n", "4", "HGET",
                    "QUEUE|{0}|{1}".format(port, queue), "scheduler"
                ]
            )[0].encode("utf-8")

        schedWeight = dut_asic.run_redis_cmd(
            argv = ["redis-cli", "-n", "4", "HGET", schedProfile, "weight"]
        )[0].encode("utf-8")

        return {"schedProfile": schedProfile, "schedWeight": schedWeight}

    def __assignTestPortIps(self, mgFacts):
        """
            Assign IPs to test ports of DUT host

            Args:
                mgFacts (dict): Map of DUT minigraph facts

            Returns:
                dutPortIps (dict): Map of port index to IPs
        """
        dutPortIps = {}
        if len(mgFacts["minigraph_vlans"]) > 0:
            #TODO: handle the case when there are multiple vlans
            testVlan = next(iter(mgFacts["minigraph_vlans"]))
            testVlanMembers = mgFacts["minigraph_vlans"][testVlan]["members"]

            testVlanIp = None
            for vlan in mgFacts["minigraph_vlan_interfaces"]:
                if mgFacts["minigraph_vlans"][testVlan]["name"] in vlan["attachto"]:
                    testVlanIp = ipaddress.ip_address(unicode(vlan["addr"]))
                    break
            pytest_assert(testVlanIp, "Failed to obtain vlan IP")

            vlan_id = None
            if 'type' in mgFacts["minigraph_vlans"][testVlan]:
                vlan_type = mgFacts["minigraph_vlans"][testVlan]['type']
                if vlan_type is not None and "Tagged" in vlan_type:
                    vlan_id =  mgFacts["minigraph_vlans"][testVlan]['vlanid']

            for i in range(len(testVlanMembers)):
                portIndex = mgFacts["minigraph_ptf_indices"][testVlanMembers[i]]
                portIpMap = {'peer_addr': str(testVlanIp + portIndex + 1)}
                if vlan_id is not None:
                    portIpMap['vlan_id'] = vlan_id
                dutPortIps.update({portIndex: portIpMap})

        return dutPortIps

    @pytest.fixture(scope='class')
    def swapSyncd_on_selected_duts(self, request, duthosts, get_src_dst_asic_and_duts, creds, tbinfo, lower_tor_host):
        """
            Swap syncd on DUT host

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        swapSyncd = request.config.getoption("--qos_swap_syncd")
        public_docker_reg = request.config.getoption("--public_docker_registry")
        try:
            if swapSyncd:
                if public_docker_reg:
                    new_creds = copy.deepcopy(creds)
                    new_creds['docker_registry_host'] = new_creds['public_docker_registry_host']
                    new_creds['docker_registry_username'] = ''
                    new_creds['docker_registry_password'] = ''
                else:
                    new_creds = creds
                for duthost in get_src_dst_asic_and_duts["all_duts"]:
                    docker.swap_syncd(duthost, new_creds)
            yield
        finally:
            if swapSyncd:
                for duthost in get_src_dst_asic_and_duts["all_duts"]:
                    docker.restore_default_syncd(duthost, new_creds)

    @pytest.fixture(scope='class', name="select_src_dst_dut_and_asic",
                    params=("single_asic", "single_dut_multi_asic", "multi_dut"))
    def select_src_dst_dut_and_asic(self, duthosts, request, tbinfo, lower_tor_host):
        test_port_selection_criteria = request.param
        logger.info("test_port_selection_criteria is {}".format(test_port_selection_criteria))
        src_dut_index = 0
        dst_dut_index = 0
        src_asic_index = 0
        dst_asic_index = 0
        topo = tbinfo["topo"]["name"]
        if 'dualtor' in tbinfo['topo']['name']:
            # index of lower_tor_host
            for a_dut_index in range(len(duthosts)):
                if duthosts[a_dut_index] == lower_tor_host:
                    lower_tor_dut_index = a_dut_index
                    break

        duthost = duthosts.frontend_nodes[0]
        if test_port_selection_criteria == 'single_asic':
            # We should randomly pick a dut from duthosts.frontend_nodes and a random asic in that selected DUT
            # for now hard code the first DUT and the first asic
            if 'dualtor' in tbinfo['topo']['name']:
                src_dut_index = lower_tor_dut_index
            else:
                src_dut_index = 0
            dst_dut_index = src_dut_index
            src_asic_index = 0
            dst_asic_index = 0

        elif test_port_selection_criteria == "single_dut_multi_asic":
            if topo in self.SUPPORTED_T0_TOPOS or isMellanoxDevice(duthost):
                pytest.skip("single_dut_multi_asic is not supported on T0 topologies")
            found_multi_asic_dut = False
            for a_dut_index in range(len(duthosts.frontend_nodes)):
                a_dut = duthosts.frontend_nodes[a_dut_index]
                if a_dut.sonichost.is_multi_asic:
                    src_dut_index = a_dut_index
                    dst_dut_index = a_dut_index
                    src_asic_index = 0
                    dst_asic_index = 1
                    found_multi_asic_dut = True
                    logger.info ("Using dut {} for single_dut_multi_asic testing".format(a_dut.hostname))
                    break
            if not found_multi_asic_dut:
                pytest.skip("Did not find any frontend node that is multi-asic - so can't run single_dut_multi_asic tests")
        else:
            # Dealing with multi-dut
            if topo in self.SUPPORTED_T0_TOPOS or isMellanoxDevice(duthost):
                pytest.skip("multi-dut is not supported on T0 topologies")
            elif topo in self.SUPPORTED_T1_TOPOS:
                pytest.skip("multi-dut is not supported on T1 topologies")

            if (len(duthosts.frontend_nodes)) < 2:
                pytest.skip("Don't have 2 frontend nodes - so can't run multi_dut tests")

            src_dut_index = 0
            dst_dut_index = 1
            src_asic_index = 0
            dst_asic_index = 0

        yield {
            "src_dut_index": src_dut_index,
            "dst_dut_index": dst_dut_index,
            "src_asic_index": src_asic_index,
            "dst_asic_index": dst_asic_index
        }

    @pytest.fixture(scope='class')
    def get_src_dst_asic_and_duts(self, duthosts, tbinfo, select_src_dst_dut_and_asic, lower_tor_host):
        if 'dualtor' in tbinfo['topo']['name']:
            src_dut = lower_tor_host
            dst_dut = lower_tor_host
        else:
            src_dut = duthosts.frontend_nodes[select_src_dst_dut_and_asic["src_dut_index"]]
            dst_dut = duthosts.frontend_nodes[select_src_dst_dut_and_asic["dst_dut_index"]]

        src_asic = src_dut.asics[select_src_dst_dut_and_asic["src_asic_index"]]
        dst_asic = dst_dut.asics[select_src_dst_dut_and_asic["dst_asic_index"]]

        all_asics = [src_asic]
        if src_asic != dst_asic:
            all_asics.append(dst_asic)

        all_duts = [src_dut]
        if src_dut != dst_dut:
            all_duts.append(dst_dut)

        rtn_dict = {
            "src_asic": src_asic,
            "dst_asic": dst_asic,
            "src_dut": src_dut,
            "dst_dut": dst_dut,
            "all_asics": all_asics,
            "all_duts": all_duts
        }
        rtn_dict.update(select_src_dst_dut_and_asic)
        yield rtn_dict

    def __buildTestPorts(self, request, testPortIds, testPortIps, src_port_ids, dst_port_ids, get_src_dst_asic_and_duts):
        """
            Build map of test ports index and IPs

            Args:
                request (Fixture): pytest request object
                testPortIds (list): List of QoS SAI test port IDs
                testPortIps (list): List of QoS SAI test port IPs

            Returns:
                testPorts (dict): Map of test ports index and IPs
        """
        dstPorts = request.config.getoption("--qos_dst_ports")
        srcPorts = request.config.getoption("--qos_src_ports")

        src_dut_port_ids = testPortIds[get_src_dst_asic_and_duts['src_dut_index']]
        src_test_port_ids = src_dut_port_ids[get_src_dst_asic_and_duts['src_asic_index']]
        dst_dut_port_ids = testPortIds[get_src_dst_asic_and_duts['dst_dut_index']]
        dst_test_port_ids = dst_dut_port_ids[get_src_dst_asic_and_duts['dst_asic_index']]

        src_dut_port_ips = testPortIps[get_src_dst_asic_and_duts['src_dut_index']]
        src_test_port_ips = src_dut_port_ips[get_src_dst_asic_and_duts['src_asic_index']]
        dst_dut_port_ips = testPortIps[get_src_dst_asic_and_duts['dst_dut_index']]
        dst_test_port_ips = dst_dut_port_ips[get_src_dst_asic_and_duts['dst_asic_index']]


        if dstPorts is None:
            if dst_port_ids:
                pytest_assert(
                    len(set(dst_test_port_ids).intersection(set(dst_port_ids))) == len(set(dst_port_ids)),
                        "Dest port id passed in qos.yml not valid"
                    )
                dstPorts = dst_port_ids
            elif len(dst_test_port_ids) >= 4:
                dstPorts = [0, 2, 3]
            elif len(dst_test_port_ids) == 3:
                dstPorts = [0, 2, 2]
            else:
                dstPorts = [0, 0, 0]

        if srcPorts is None:
            if src_port_ids:
                pytest_assert(
                    len(set(src_test_port_ids).intersection(set(src_port_ids))) == len(set(src_port_ids)),
                        "Source port id passed in qos.yml not valid"
                )
                # To verify ingress lossless speed/cable-length randomize the source port.
                srcPorts = [random.choice(src_port_ids)]
            else:
                srcPorts = [1]

        pytest_assert(len(dst_test_port_ids) >= 1 and len(src_test_port_ids) >= 1, "Provide at least 2 test ports")
        logging.debug(
            "Test Port IDs:{} IPs:{}".format(testPortIds, testPortIps)
        )
        logging.debug("Test Port dst:{}, src:{}".format(dstPorts, srcPorts))

        pytest_assert(
            len(set(dstPorts).intersection(set(srcPorts))) == 0,
            "Duplicate destination and source ports '{0}'".format(
                set(dstPorts).intersection(set(srcPorts))
            )
        )

        # TODO: Randomize port selection
        dstPort = dstPorts[0] if dst_port_ids else dst_test_port_ids[dstPorts[0]]
        dstVlan = dst_test_port_ips[dstPort]['vlan_id'] if 'vlan_id' in dst_test_port_ips[dstPort] else None
        dstPort2 = dstPorts[1] if dst_port_ids else dst_test_port_ids[dstPorts[1]]
        dstVlan2 = dst_test_port_ips[dstPort2]['vlan_id'] if 'vlan_id' in dst_test_port_ips[dstPort2] else None
        dstPort3 = dstPorts[2] if dst_port_ids else dst_test_port_ids[dstPorts[2]]
        dstVlan3 = dst_test_port_ips[dstPort3]['vlan_id'] if 'vlan_id' in dst_test_port_ips[dstPort3] else None
        srcPort = srcPorts[0] if src_port_ids else src_test_port_ids[srcPorts[0]]
        srcVlan = src_test_port_ips[srcPort]['vlan_id'] if 'vlan_id' in src_test_port_ips[srcPort] else None
        return {
            "dst_port_id": dstPort,
            "dst_port_ip": dst_test_port_ips[dstPort]['peer_addr'],
            "dst_port_vlan": dstVlan,
            "dst_port_2_id": dstPort2,
            "dst_port_2_ip": dst_test_port_ips[dstPort2]['peer_addr'],
            "dst_port_2_vlan": dstVlan2,
            'dst_port_3_id': dstPort3,
            "dst_port_3_ip": dst_test_port_ips[dstPort3]['peer_addr'],
            "dst_port_3_vlan": dstVlan3,
            "src_port_id": srcPort,
            "src_port_ip": src_test_port_ips[srcPorts[0] if src_port_ids else src_test_port_ids[srcPorts[0]]]["peer_addr"],
            "src_port_vlan": srcVlan
        }

    @pytest.fixture(scope='class', autouse=True)
    def dutConfig(
        self, request, duthosts, get_src_dst_asic_and_duts,
            lower_tor_host, tbinfo, dualtor_ports_for_duts, dut_qos_maps): # noqa F811
        """
            Build DUT host config pertaining to QoS SAI tests

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                dutConfig (dict): Map of DUT config containing dut interfaces,
                test port IDs, test port IPs, and test ports
        """

        """
        Below are dictionaries with key being dut_index and value a dictionary with key asic_index 
        Example for 2 DUTs with 2 asics each
            { 0: { 0: <asic0_value>, 1: <asic1_value>}, 1: { 0: <asic0_value>, 1: <asic1_value> }}
        """
        dutPortIps = {}
        testPortIps = {}
        testPortIds = {}
        dualTorPortIndexes = {}
        uplinkPortIds = []
        uplinkPortIps = []
        uplinkPortNames = []
        downlinkPortIds = []
        downlinkPortIps = []
        downlinkPortNames = []

        src_dut_index = get_src_dst_asic_and_duts['src_dut_index']
        src_asic_index = get_src_dst_asic_and_duts['src_asic_index']
        src_dut = get_src_dst_asic_and_duts['src_dut']
        src_mgFacts = src_dut.get_extended_minigraph_facts(tbinfo)
        topo = tbinfo["topo"]["name"]


        # LAG ports in T1 TOPO need to be removed in Mellanox devices
        if topo in self.SUPPORTED_T0_TOPOS or isMellanoxDevice(src_dut):
            # Only single asic is supported for this scenario, so use src_dut and src_asic - which will be the same
            # as dst_dut and dst_asic
            pytest_assert(
                not src_dut.sonichost.is_multi_asic, "Fixture not supported on T0 multi ASIC"
            )
            dutLagInterfaces = []
            testPortIds[src_dut_index] = {}
            for _, lag in src_mgFacts["minigraph_portchannels"].items():
                for intf in lag["members"]:
                    dutLagInterfaces.append(src_mgFacts["minigraph_ptf_indices"][intf])

            testPortIds[src_dut_index][src_asic_index] = set(src_mgFacts["minigraph_ptf_indices"][port]
                                for port in src_mgFacts["minigraph_ports"].keys())
            testPortIds[src_dut_index][src_asic_index] -= set(dutLagInterfaces)
            if isMellanoxDevice(src_dut):
                # The last port is used for up link from DUT switch
                testPortIds[src_dut_index][src_asic_index] -= {len(src_mgFacts["minigraph_ptf_indices"]) - 1}
            testPortIds[src_dut_index][src_asic_index] = sorted(testPortIds[src_dut_index][src_asic_index])
            pytest_require(len(testPortIds[src_dut_index][src_asic_index]) != 0, "Skip test since no ports are available for testing")

            # get current DUT port IPs
            dutPortIps[src_dut_index] = {}
            dutPortIps[src_dut_index][src_asic_index] = {}
            dualTorPortIndexes[src_dut_index] = {}
            dualTorPortIndexes[src_dut_index][src_asic_index] = {}
            if 'backend' in topo:
                intf_map = src_mgFacts["minigraph_vlan_sub_interfaces"]
            else:
                intf_map = src_mgFacts["minigraph_interfaces"]

            use_separated_upkink_dscp_tc_map = separated_dscp_to_tc_map_on_uplink(src_dut, dut_qos_maps)
            for portConfig in intf_map:
                intf = portConfig["attachto"].split(".")[0]
                if ipaddress.ip_interface(portConfig['peer_addr']).ip.version == 4:
                    portIndex = src_mgFacts["minigraph_ptf_indices"][intf]
                    if portIndex in testPortIds[src_dut_index][src_asic_index]:
                        portIpMap = {'peer_addr': portConfig["peer_addr"]}
                        if 'vlan' in portConfig:
                            portIpMap['vlan_id'] = portConfig['vlan']
                        dutPortIps[src_dut_index][src_asic_index].update({portIndex: portIpMap})
                        if intf in dualtor_ports_for_duts:
                            dualTorPortIndexes[src_dut_index][src_asic_index].append(portIndex)
                    # If the leaf router is using separated DSCP_TO_TC_MAP on uplink/downlink ports.
                    # we also need to test them separately
                    # for mellanox device, we run it on t1 topo mocked by ptf32 topo
                    if use_separated_upkink_dscp_tc_map and isMellanoxDevice(src_dut):
                        neighName = src_mgFacts["minigraph_neighbors"].get(intf, {}).get("name", "").lower()
                        if 't0' in neighName:
                            downlinkPortIds.append(portIndex)
                            downlinkPortIps.append(portConfig["peer_addr"])
                            downlinkPortNames.append(intf)
                        elif 't2' in neighName:
                            uplinkPortIds.append(portIndex)
                            uplinkPortIps.append(portConfig["peer_addr"])
                            uplinkPortNames.append(intf)

            testPortIps[src_dut_index] = {}
            testPortIps[src_dut_index][src_asic_index] = self.__assignTestPortIps(src_mgFacts)

            # restore currently assigned IPs
            if len(dutPortIps[src_dut_index][src_asic_index]) != 0:
                testPortIps.update(dutPortIps)

        elif topo in self.SUPPORTED_T1_TOPOS:

            # T1 is supported only for 'single_asic' or 'single_dut_multi_asic'.
            # So use src_dut as the dut
            use_separated_upkink_dscp_tc_map = separated_dscp_to_tc_map_on_uplink(src_dut, dut_qos_maps)
            dutPortIps[src_dut_index] = {}
            testPortIds[src_dut_index] = {}
            for dut_asic in get_src_dst_asic_and_duts['all_asics']:
                dutPortIps[src_dut_index][dut_asic.asic_index] = {}
                for iface,addr in dut_asic.get_active_ip_interfaces(tbinfo).items():
                    vlan_id = None
                    if iface.startswith("Ethernet"):
                        portName = iface
                        if "." in iface:
                            portName, vlan_id = iface.split(".")
                        portIndex = src_mgFacts["minigraph_ptf_indices"][portName]
                        portIpMap = {'peer_addr': addr["peer_ipv4"]}
                        if vlan_id is not None:
                            portIpMap['vlan_id'] = vlan_id
                        dutPortIps[src_dut_index][dut_asic.asic_index].update({portIndex: portIpMap})
                    elif iface.startswith("PortChannel"):
                        portName = next(
                            iter(src_mgFacts["minigraph_portchannels"][iface]["members"])
                        )
                        portIndex = src_mgFacts["minigraph_ptf_indices"][portName]
                        portIpMap = {'peer_addr': addr["peer_ipv4"]}
                        dutPortIps[src_dut_index][dut_asic.asic_index].update({portIndex: portIpMap})
                    # If the leaf router is using separated DSCP_TO_TC_MAP on uplink/downlink ports.
                    # we also need to test them separately
                    if use_separated_upkink_dscp_tc_map:
                        neighName = src_mgFacts["minigraph_neighbors"].get(portName, {}).get("name", "").lower()
                        if 't0' in neighName:
                            downlinkPortIds.append(portIndex)
                            downlinkPortIps.append(addr["peer_ipv4"])
                            downlinkPortNames.append(portName)
                        elif 't2' in neighName:
                            uplinkPortIds.append(portIndex)
                            uplinkPortIps.append(addr["peer_ipv4"])
                            uplinkPortNames.append(portName)

                testPortIds[src_dut_index][dut_asic.asic_index] = sorted(dutPortIps[src_dut_index][dut_asic.asic_index].keys())

            # Need to fix this
            testPortIps[src_dut_index] = {}
            testPortIps[src_dut_index][src_asic_index] = self.__assignTestPortIps(src_mgFacts)

            # restore currently assigned IPs
            if len(dutPortIps[src_dut_index][src_asic_index]) != 0:
                testPortIps.update(dutPortIps)

        elif tbinfo["topo"]["type"] == "t2":
            src_asic = get_src_dst_asic_and_duts['src_asic']
            dst_dut_index = get_src_dst_asic_and_duts['dst_dut_index']
            dst_asic = get_src_dst_asic_and_duts['dst_asic']

            # Lets get data for the src dut and src asic
            dutPortIps[src_dut_index] = {}
            testPortIds[src_dut_index] = {}
            dutPortIps[src_dut_index][src_asic_index] = {}
            active_ips = src_asic.get_active_ip_interfaces(tbinfo)
            for iface,addr in active_ips.items():
                if iface.startswith("Ethernet") and ("Ethernet-Rec" not in iface):
                    portIndex = src_mgFacts["minigraph_ptf_indices"][iface]
                    portIpMap = {'peer_addr': addr["peer_ipv4"], 'port': iface}
                    dutPortIps[src_dut_index][src_asic_index].update({portIndex: portIpMap})
                elif iface.startswith("PortChannel"):
                    portName = next(
                        iter(src_mgFacts["minigraph_portchannels"][iface]["members"])
                    )
                    portIndex = src_mgFacts["minigraph_ptf_indices"][portName]
                    portIpMap = {'peer_addr': addr["peer_ipv4"], 'port': portName}
                    dutPortIps[src_dut_index][src_asic_index].update({portIndex: portIpMap})

            testPortIds[src_dut_index][src_asic_index] = sorted(dutPortIps[src_dut_index][src_asic_index].keys())

            if dst_asic != src_asic:
                # Dealing with different asic
                dst_dut = get_src_dst_asic_and_duts['dst_dut']
                dst_asic_index = get_src_dst_asic_and_duts['dst_asic_index']
                if dst_dut_index != src_dut_index:
                    dst_mgFacts = dst_dut.get_extended_minigraph_facts(tbinfo)
                    dutPortIps[dst_dut_index] = {}
                    testPortIds[dst_dut_index] = {}
                else:
                    dst_mgFacts = src_mgFacts
                dutPortIps[dst_dut_index][dst_asic_index] = {}
                active_ips = dst_asic.get_active_ip_interfaces(tbinfo)
                for iface, addr in active_ips.items():
                    if iface.startswith("Ethernet") and ("Ethernet-Rec" not in iface):
                        portIndex = dst_mgFacts["minigraph_ptf_indices"][iface]
                        portIpMap = {'peer_addr': addr["peer_ipv4"], 'port': iface}
                        dutPortIps[dst_dut_index][dst_asic_index].update({portIndex: portIpMap})
                    elif iface.startswith("PortChannel"):
                        portName = next(
                            iter(dst_mgFacts["minigraph_portchannels"][iface]["members"])
                        )
                        portIndex = dst_mgFacts["minigraph_ptf_indices"][portName]
                        portIpMap = {'peer_addr': addr["peer_ipv4"], 'port': portName}
                        dutPortIps[dst_dut_index][dst_asic_index].update({portIndex: portIpMap})

                testPortIds[dst_dut_index][dst_asic_index] = sorted(dutPortIps[dst_dut_index][dst_asic_index].keys())

            # restore currently assigned IPs
            testPortIps.update(dutPortIps)

        qosConfigs = {}
        with open(r"qos/files/qos.yml") as file:
            qosConfigs = yaml.load(file, Loader=yaml.FullLoader)
        # Assuming the same chipset for all DUTs so can use src_dut to get asic type
        vendor = src_dut.facts["asic_type"]
        hostvars = src_dut.host.options['variable_manager']._hostvars[src_dut.hostname]
        dutAsic = None
        for asic in self.SUPPORTED_ASIC_LIST:
            vendorAsic = "{0}_{1}_hwskus".format(vendor, asic)
            if vendorAsic in hostvars.keys() and src_mgFacts["minigraph_hwsku"] in hostvars[vendorAsic]:
                dutAsic = asic
                break

        pytest_assert(dutAsic, "Cannot identify DUT ASIC type")

        dutTopo = "topo-"

        if dutTopo + topo in qosConfigs['qos_params'].get(dutAsic, {}):
            dutTopo = dutTopo + topo
        else:
            # Default topo is any
            dutTopo = dutTopo + "any"

        # Support of passing source and dest ptf port id from qos.yml
        # This is needed when on some asic port are distributed across
        # multiple buffer pipes.
        src_port_ids = None
        dst_port_ids = None
        try:
            if "src_port_ids" in qosConfigs['qos_params'][dutAsic][dutTopo]:
                src_port_ids = qosConfigs['qos_params'][dutAsic][dutTopo]["src_port_ids"]

            if "dst_port_ids" in qosConfigs['qos_params'][dutAsic][dutTopo]:
                dst_port_ids = qosConfigs['qos_params'][dutAsic][dutTopo]["dst_port_ids"]
        except KeyError:
            pass

        dualTor = request.config.getoption("--qos_dual_tor")
        if dualTor:
            testPortIds = dualTorPortIndexes

        testPorts = self.__buildTestPorts(request, testPortIds, testPortIps, src_port_ids, dst_port_ids, get_src_dst_asic_and_duts)
        # Update the uplink/downlink ports to testPorts
        testPorts.update({
            "uplink_port_ids": uplinkPortIds,
            "uplink_port_ips": uplinkPortIps,
            "uplink_port_names": uplinkPortNames,
            "downlink_port_ids": downlinkPortIds,
            "downlink_port_ips": downlinkPortIps,
            "downlink_port_names": downlinkPortNames
        })
        dutinterfaces = {}

        if tbinfo["topo"]["type"] == "t2":
            #dutportIps={0: {0: {0: {'peer_addr': u'10.0.0.1', 'port': u'Ethernet8'}, 2: {'peer_addr': u'10.0.0.5', 'port': u'Ethernet17'}}}}
            # { 0: 'Ethernet8', 2: 'Ethernet17' }
            for dut_index,dut_val in dutPortIps.items():
                for asic_index,asic_val in dut_val.items():
                    for ptf_port, ptf_val in asic_val.items():
                        dutinterfaces[ptf_port] = ptf_val['port']
        else:
            dutinterfaces = {
                index: port for port, index in src_mgFacts["minigraph_ptf_indices"].items()
            }

        yield {
            "dutInterfaces": dutinterfaces,
            "testPortIds": testPortIds,
            "testPortIps": testPortIps,
            "testPorts": testPorts,
            "qosConfigs": qosConfigs,
            "dutAsic": dutAsic,
            "dutTopo": dutTopo,
            "srcDutInstance" : src_dut,
            "dstDutInstance": get_src_dst_asic_and_duts['dst_dut'],
            "dualTor": request.config.getoption("--qos_dual_tor"),
            "dualTorScenario": len(dualtor_ports_for_duts) != 0
        }

    @pytest.fixture(scope='class')
    def ssh_tunnel_to_syncd_rpc(self, duthosts, get_src_dst_asic_and_duts, swapSyncd_on_selected_duts, tbinfo, lower_tor_host):
        all_asics = get_src_dst_asic_and_duts['all_asics']

        for a_asic in all_asics:
            a_asic.create_ssh_tunnel_sai_rpc()

        yield

        for a_asic in all_asics:
            a_asic.remove_ssh_tunnel_sai_rpc()

    @pytest.fixture(scope='class')
    def updateIptables(self, duthosts, get_src_dst_asic_and_duts, swapSyncd_on_selected_duts, tbinfo, lower_tor_host):
        """
            Update iptables on DUT host with drop rule for BGP SYNC packets

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                swapSyncd (Fixture): swapSyncd fixture is required to run prior to updating iptables

            Returns:
                None
        """
        all_asics = get_src_dst_asic_and_duts['all_asics']

        ipVersions = [{"ip_version": "ipv4"}, {"ip_version": "ipv6"}]

        logger.info("Add ip[6]tables rule to drop BGP SYN Packet from peer so that we do not ACK back")
        for ipVersion in ipVersions:
            for a_asic in all_asics:
                a_asic.bgp_drop_rule(state="present", **ipVersion)

        yield

        logger.info("Remove ip[6]tables rule to drop BGP SYN Packet from Peer")
        for ipVersion in ipVersions:
            for a_asic in all_asics:
                a_asic.bgp_drop_rule(state="absent", **ipVersion)

    @pytest.fixture(scope='class')
    def stopServices(
        self, duthosts, get_src_dst_asic_and_duts,
        swapSyncd_on_selected_duts, enable_container_autorestart, disable_container_autorestart, get_mux_status,
        tbinfo, upper_tor_host, lower_tor_host, toggle_all_simulator_ports): # noqa F811
        """
            Stop services (lldp-syncs, lldpd, bgpd) on DUT host prior to test start

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                swapSyncd (Fxiture): swapSyncd fixture is required to run prior to stopping services

            Returns:
                None
        """
        src_asic = get_src_dst_asic_and_duts['src_asic']
        src_dut = get_src_dst_asic_and_duts['src_dut']
        dst_asic = get_src_dst_asic_and_duts['dst_asic']
        dst_dut = get_src_dst_asic_and_duts['dst_dut']

        if 'dualtor' in tbinfo['topo']['name']:
            duthost_upper = upper_tor_host

        def updateDockerService(host, docker="", action="", service=""):
            """
                Helper function to update docker services

                Args:
                    host (AnsibleHost): Ansible host that is running docker
                    docker (str): docker container name
                    action (str): action to apply to service running within docker
                    service (str): service name running within docker

                Returns:
                    None
            """
            host.command(
                "docker exec {docker} supervisorctl {action} {service}".format(
                    docker=docker,
                    action=action,
                    service=service
                ),
                module_ignore_errors=True
            )
            logger.info("{}ed {}".format(action, service))

        """ Stop mux container for dual ToR """
        if 'dualtor' in tbinfo['topo']['name']:
            file = "/usr/local/bin/write_standby.py"
            backup_file = "/usr/local/bin/write_standby.py.bkup"
            toggle_all_simulator_ports(LOWER_TOR)
            check_result = wait_until(120, 10, 10, check_mux_status, duthosts, LOWER_TOR)
            validate_check_result(check_result, duthosts, get_mux_status)

            try:
                lower_tor_host.shell("ls %s" % file)
                lower_tor_host.shell("sudo cp {} {}".format(file,backup_file))
                lower_tor_host.shell("sudo rm {}".format(file))
                lower_tor_host.shell("sudo touch {}".format(file))
            except:
                pytest.skip('file {} not found'.format(file))

            duthost_upper.shell('sudo config feature state mux disabled')
            lower_tor_host.shell('sudo config feature state mux disabled')

        src_services = [
            {"docker": src_asic.get_docker_name("lldp"), "service": "lldp-syncd"},
            {"docker": src_asic.get_docker_name("lldp"), "service": "lldpd"},
            {"docker": src_asic.get_docker_name("bgp"), "service": "bgpd"},
            {"docker": src_asic.get_docker_name("bgp"), "service": "bgpmon"},
            {"docker": src_asic.get_docker_name("radv"), "service": "radvd"},
            {"docker": src_asic.get_docker_name("swss"), "service": "radvd"}
        ]
        dst_services = []
        if src_asic != dst_asic:
            dst_services = [
                {"docker": dst_asic.get_docker_name("lldp"), "service": "lldp-syncd"},
                {"docker": dst_asic.get_docker_name("lldp"), "service": "lldpd"},
                {"docker": dst_asic.get_docker_name("bgp"), "service": "bgpd"},
                {"docker": dst_asic.get_docker_name("bgp"), "service": "bgpmon"},
                {"docker": dst_asic.get_docker_name("radv"), "service": "radvd"},
                {"docker": dst_asic.get_docker_name("swss"), "service": "radvd"},
            ]

        feature_list = ['lldp', 'bgp', 'syncd', 'swss']
        if 'dualtor' in tbinfo['topo']['name']:
            disable_container_autorestart(duthost_upper, testcase="test_qos_sai", feature_list=feature_list)


        disable_container_autorestart(src_dut, testcase="test_qos_sai", feature_list=feature_list)
        for service in src_services:
            updateDockerService(src_dut, action="stop", **service)
        if src_asic != dst_asic:
            disable_container_autorestart(dst_dut, testcase="test_qos_sai", feature_list=feature_list)
            for service in dst_services:
                updateDockerService(dst_dut, action="stop", **service)
        yield

        for service in src_services:
            updateDockerService(src_dut, action="start", **service)
        if src_asic != dst_asic:
            for service in dst_services:
                updateDockerService(dst_dut, action="start", **service)

        """ Start mux conatiner for dual ToR """
        if 'dualtor' in tbinfo['topo']['name']:
           try:

               lower_tor_host.shell("ls %s" % backup_file)
               lower_tor_host.shell("sudo cp {} {}".format(backup_file,file))
               lower_tor_host.shell("sudo chmod +x {}".format(file))
               lower_tor_host.shell("sudo rm {}".format(backup_file))
           except:
               pytest.skip('file {} not found'.format(backup_file))

           lower_tor_host.shell('sudo config feature state mux enabled')
           lower_tor_host.shell('sudo config feature state mux enabled')
           logger.info("Start mux container for dual ToR testbed")

        enable_container_autorestart(src_dut, testcase="test_qos_sai", feature_list=feature_list)
        if src_asic != dst_asic:
            enable_container_autorestart(dst_dut, testcase="test_qos_sai", feature_list=feature_list)
        if 'dualtor' in tbinfo['topo']['name']:
            enable_container_autorestart(duthost_upper, testcase="test_qos_sai", feature_list=feature_list)


    @pytest.fixture(autouse=True)
    def updateLoganalyzerExceptions(self, get_src_dst_asic_and_duts, loganalyzer):
        """
            Update loganalyzer ignore regex list

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                loganalyzer (Fixture): log analyzer fixture

            Returns:
                None
        """
        if loganalyzer:
            ignoreRegex = [
                ".*ERR monit.*'lldpd_monitor' process is not running.*",
                ".*ERR monit.* 'lldp\|lldpd_monitor' status failed.*-- 'lldpd:' is not running.*",

                ".*ERR monit.*'lldp_syncd' process is not running.*",
                ".*ERR monit.*'lldp\|lldp_syncd' status failed.*-- 'python.* -m lldp_syncd' is not running.*",

                ".*ERR monit.*'bgpd' process is not running.*",
                ".*ERR monit.*'bgp\|bgpd' status failed.*-- '/usr/lib/frr/bgpd' is not running.*",

                ".*ERR monit.*'bgpcfgd' process is not running.*",
                ".*ERR monit.*'bgp\|bgpcfgd' status failed.*-- '/usr/bin/python.* /usr/local/bin/bgpcfgd' is not running.*",

                ".*ERR syncd#syncd:.*brcm_sai_set_switch_attribute:.*updating switch mac addr failed.*",

                ".*ERR monit.*'bgp\|bgpmon' status failed.*'/usr/bin/python.* /usr/local/bin/bgpmon' is not running.*",
                ".*ERR monit.*bgp\|fpmsyncd.*status failed.*NoSuchProcess process no longer exists.*",
                ".*WARNING syncd#SDK:.*check_attribs_metadata: Not implemented attribute.*",
                ".*WARNING syncd#SDK:.*sai_set_attribute: Failed attribs check, key:Switch ID.*",
                ".*WARNING syncd#SDK:.*check_rate: Set max rate to 0.*"
            ]
            for a_dut in get_src_dst_asic_and_duts['all_duts']:
                loganalyzer[a_dut.hostname].ignore_regex.extend(ignoreRegex)

        yield

    @pytest.fixture(scope='class', autouse=True)
    def disablePacketAging(
        self, duthosts, get_src_dst_asic_and_duts, stopServices
    ):
        """
            disable packet aging on DUT host

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                stopServices (Fxiture): stopServices fixture is required to run prior to disabling packet aging

            Returns:
                None
        """
        for duthost in get_src_dst_asic_and_duts['all_duts']:
            if isMellanoxDevice(duthost):
                logger.info("Disable Mellanox packet aging")
                duthost.copy(src="qos/files/mellanox/packets_aging.py", dest="/tmp")
                duthost.command("docker cp /tmp/packets_aging.py syncd:/")
                duthost.command("docker exec syncd python /packets_aging.py disable")

            yield

            if isMellanoxDevice(duthost):
                logger.info("Enable Mellanox packet aging")
                duthost.command("docker exec syncd python /packets_aging.py enable")
                duthost.command("docker exec syncd rm -rf /packets_aging.py")

    def dutArpProxyConfig(self, duthost):
        # so far, only record ARP proxy config to logging for debug purpose
        for a_asic in duthost.asics:
            vlanInterface = {}
            try:
                sonic_cfgen_cmd = 'sonic-cfggen {} -d --var-json "VLAN_INTERFACE"'.format(a_asic.cli_ns_option)
                vlanInterface = json.loads(duthost.shell(sonic_cfgen_cmd)['stdout'])
            except:
                logger.info('Failed to read vlan interface config')
            if not vlanInterface:
                return
            for key, value in vlanInterface.items():
                if 'proxy_arp' in value:
                    logger.info('ARP proxy is {} on {}'.format(value['proxy_arp'], key))

    def dutBufferConfig(self, duthost, dut_asic):
        bufferConfig = {}
        try:
            ns_spec = ""
            ns = dut_asic.get_asic_namespace()
            if ns is not None:
                # multi-asic support
                ns_spec = " -n " + ns
            bufferConfig['BUFFER_POOL'] = json.loads(duthost.shell(
                'sonic-cfggen -d --var-json "BUFFER_POOL"' + ns_spec)['stdout'])
            bufferConfig['BUFFER_PROFILE'] = json.loads(duthost.shell(
                'sonic-cfggen -d --var-json "BUFFER_PROFILE"' + ns_spec)['stdout'])
            bufferConfig['BUFFER_QUEUE'] = json.loads(duthost.shell(
                'sonic-cfggen -d --var-json "BUFFER_QUEUE"' + ns_spec)['stdout'])
            bufferConfig['BUFFER_PG'] = json.loads(duthost.shell(
                'sonic-cfggen -d --var-json "BUFFER_PG"' + ns_spec)['stdout'])
        except Exception as err:
            logger.info(err)
        return bufferConfig

    @pytest.fixture(scope='class', autouse=True)
    def dutQosConfig(
        self, duthosts, get_src_dst_asic_and_duts,
        dutConfig, ingressLosslessProfile, ingressLossyProfile,
        egressLosslessProfile, egressLossyProfile, sharedHeadroomPoolSize,
        tbinfo, lower_tor_host
    ):
        """
            Prepares DUT host QoS configuration

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ingressLosslessProfile (Fxiture): ingressLosslessProfile fixture is required to run prior to collecting
                    QoS configuration

            Returns:
                QoSConfig (dict): Map containing DUT host QoS configuration
        """
        duthost = get_src_dst_asic_and_duts['src_dut']
        dut_asic = get_src_dst_asic_and_duts['src_asic']

        mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
        pytest_assert("minigraph_hwsku" in mgFacts, "Could not find DUT SKU")

        profileName = ingressLosslessProfile["profileName"]
        logger.info("Lossless Buffer profile selected is {}".format(profileName))

        if self.isBufferInApplDb(dut_asic):
            profile_pattern = "^BUFFER_PROFILE_TABLE\:pg_lossless_(.*)_profile$"
        else:
            profile_pattern = "^BUFFER_PROFILE\|pg_lossless_(.*)_profile"
        m = re.search(profile_pattern, profileName)
        pytest_assert(m.group(1), "Cannot find port speed/cable length")

        portSpeedCableLength = m.group(1)

        qosConfigs = dutConfig["qosConfigs"]
        dutAsic = dutConfig["dutAsic"]
        dutTopo = dutConfig["dutTopo"]

        self.dutArpProxyConfig(duthost)

        if isMellanoxDevice(duthost):
            current_file_dir = os.path.dirname(os.path.realpath(__file__))
            sub_folder_dir = os.path.join(current_file_dir, "files/mellanox/")
            if sub_folder_dir not in sys.path:
                sys.path.append(sub_folder_dir)
            import qos_param_generator
            qpm = qos_param_generator.QosParamMellanox(qosConfigs['qos_params']['mellanox'][dutTopo], dutAsic,
                                                       portSpeedCableLength,
                                                       dutConfig,
                                                       ingressLosslessProfile,
                                                       ingressLossyProfile,
                                                       egressLosslessProfile,
                                                       egressLossyProfile,
                                                       sharedHeadroomPoolSize,
                                                       dutConfig["dualTor"],
                                                       get_src_dst_asic_and_duts['src_dut_index'],
                                                       get_src_dst_asic_and_duts['src_asic_index'],
                                                       get_src_dst_asic_and_duts['dst_dut_index'],
                                                       get_src_dst_asic_and_duts['dst_asic_index']
                                                       )
            qosParams = qpm.run()

        elif 'broadcom' in duthost.facts['asic_type'].lower():
            if 'platform_asic' in duthost.facts and duthost.facts['platform_asic'] == 'broadcom-dnx':
                logger.info ("THDI_BUFFER_CELL_LIMIT_SP is not valid for broadcom DNX - ignore dynamic buffer config")
                qosParams = qosConfigs['qos_params'][dutAsic][dutTopo]
            else:
                bufferConfig = self.dutBufferConfig(duthost, dut_asic)
                pytest_assert(len(bufferConfig) == 4,
                              "buffer config is incompleted")
                pytest_assert('BUFFER_POOL' in bufferConfig,
                              'BUFFER_POOL is not exist in bufferConfig')
                pytest_assert('BUFFER_PROFILE' in bufferConfig,
                              'BUFFER_PROFILE is not exist in bufferConfig')
                pytest_assert('BUFFER_QUEUE' in bufferConfig,
                              'BUFFER_QUEUE is not exist in bufferConfig')
                pytest_assert('BUFFER_PG' in bufferConfig,
                              'BUFFER_PG is not exist in bufferConfig')

                current_file_dir = os.path.dirname(os.path.realpath(__file__))
                sub_folder_dir = os.path.join(current_file_dir, "files/brcm/")
                if sub_folder_dir not in sys.path:
                    sys.path.append(sub_folder_dir)
                import qos_param_generator
                qpm = qos_param_generator.QosParamBroadcom(qosConfigs['qos_params'][dutAsic][dutTopo],
                                                           dutAsic,
                                                           portSpeedCableLength,
                                                           dutConfig,
                                                           ingressLosslessProfile,
                                                           ingressLossyProfile,
                                                           egressLosslessProfile,
                                                           egressLossyProfile,
                                                           sharedHeadroomPoolSize,
                                                           dutConfig["dualTor"],
                                                           dutTopo,
                                                           bufferConfig,
                                                           duthost,
                                                           tbinfo["topo"]["name"])
                qosParams = qpm.run()
        elif is_cisco_device(duthost):
            bufferConfig = self.dutBufferConfig(duthost, dut_asic)
            pytest_assert('BUFFER_POOL' in bufferConfig,
                          'BUFFER_POOL does not exist in bufferConfig')
            pytest_assert('BUFFER_PROFILE' in bufferConfig,
                          'BUFFER_PROFILE does not exist in bufferConfig')
            pytest_assert('BUFFER_QUEUE' in bufferConfig,
                          'BUFFER_QUEUE does not exist in bufferConfig')
            pytest_assert('BUFFER_PG' in bufferConfig,
                          'BUFFER_PG does not exist in bufferConfig')
            current_file_dir = os.path.dirname(os.path.realpath(__file__))
            sub_folder_dir = os.path.join(current_file_dir, "files/cisco/")
            if sub_folder_dir not in sys.path:
                sys.path.append(sub_folder_dir)
            import qos_param_generator
            qpm = qos_param_generator.QosParamCisco(qosConfigs['qos_params'][dutAsic][dutTopo],
                                                    duthost,
                                                    bufferConfig)
            qosParams = qpm.run()
        else:
            qosParams = qosConfigs['qos_params'][dutAsic][dutTopo]
        yield {
            "param": qosParams,
            "portSpeedCableLength": portSpeedCableLength,
        }

    @pytest.fixture(scope='class')
    def releaseAllPorts(
        self, duthosts, ptfhost, dutTestParams, updateIptables, ssh_tunnel_to_syncd_rpc
    ):
        """
            Release all paused ports prior to running QoS SAI test cases

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                updateIptables (Fixture, dict): updateIptables to run prior to releasing paused ports

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.ReleaseAllPorts",
            testParams=dutTestParams["basicParams"]
        )

    def __loadSwssConfig(self, duthost):
        """
            Load SWSS configuration on DUT

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Raises:
                asserts if the load SWSS config failed

            Returns:
                None
        """
        duthost.docker_cmds_on_all_asics("swssconfig /etc/swss/config.d/switch.json", "swss")

    def __deleteTmpSwitchConfig(self, duthost):
        """
            Delete temporary switch.json cofiguration files

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        result = duthost.find(path=["/tmp"], patterns=["switch.json*"])
        for file in result["files"]:
            duthost.file(path=file["path"], state="absent")

    @pytest.fixture(scope='class', autouse=True)
    def handleFdbAging(self, tbinfo, duthosts, lower_tor_host, get_src_dst_asic_and_duts):
        """
            Disable FDB aging and reenable at the end of tests

            Set fdb_aging_time to 0, update the swss configuration, and restore SWSS configuration afer
            test completes

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        fdbAgingTime = 0

        for duthost in get_src_dst_asic_and_duts['all_duts']:
            self.__deleteTmpSwitchConfig(duthost)
            duthost.docker_copy_from_asic("swss", "/etc/swss/config.d/switch.json", "/tmp")
            duthost.replace(
                dest='/tmp/switch.json',
                regexp='"fdb_aging_time": ".*"',
                replace='"fdb_aging_time": "{0}"'.format(fdbAgingTime),
                backup=True
            )
            duthost.docker_copy_to_all_asics("swss", "/tmp/switch.json", "/etc/swss/config.d/switch.json")
            self.__loadSwssConfig(duthost)

        yield
        for duthost in get_src_dst_asic_and_duts['all_duts']:
            result = duthost.find(path=["/tmp"], patterns=["switch.json.*"])
            if result["matched"] > 0:
                src = result["files"][0]["path"]
                duthost.docker_copy_to_all_asics("swss", src, "/etc/swss/config.d/switch.json")
                self.__loadSwssConfig(duthost)
            self.__deleteTmpSwitchConfig(duthost)

    @pytest.fixture(scope='class', autouse=True)
    def populateArpEntries(
        self, duthosts, get_src_dst_asic_and_duts,
        ptfhost, dutTestParams, dutConfig, releaseAllPorts, handleFdbAging, tbinfo, lower_tor_host
    ):
        """
            Update ARP entries of QoS SAI test ports

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                releaseAllPorts (Fixture, dict): releaseAllPorts to run prior to updating ARP entries

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """

        dut_asic = get_src_dst_asic_and_duts['src_asic']
        duthost = get_src_dst_asic_and_duts['src_dut']

        dut_asic.command('sonic-clear fdb all')
        dut_asic.command('sonic-clear arp')

        saiQosTest = None
        if dutTestParams["topo"] in self.SUPPORTED_T0_TOPOS:
            saiQosTest = "sai_qos_tests.ARPpopulate"
        elif dutTestParams["topo"] in self.SUPPORTED_PTF_TOPOS:
            saiQosTest = "sai_qos_tests.ARPpopulatePTF"
        else:
            for dut_asic in get_src_dst_asic_and_duts['all_asics']:
                result = dut_asic.command("arp -n")
                pytest_assert(result["rc"] == 0, "failed to run arp command on {0}".format(dut_asic.sonichost.hostname))
                if result["stdout"].find("incomplete") == -1:
                    saiQosTest = "sai_qos_tests.ARPpopulate"

        if saiQosTest:
            testParams = dutTestParams["basicParams"]
            testParams.update(dutConfig["testPorts"])
            self.runPtfTest(
                ptfhost, testCase=saiQosTest, testParams=testParams
            )

    @pytest.fixture(scope='class', autouse=True)
    def dut_disable_ipv6(self, duthosts, get_src_dst_asic_and_duts, tbinfo, lower_tor_host):
        for duthost in get_src_dst_asic_and_duts['all_duts']:
            duthost.shell("sysctl -w net.ipv6.conf.all.disable_ipv6=1")

        yield

        for duthost in get_src_dst_asic_and_duts['all_duts']:
            duthost.shell("sysctl -w net.ipv6.conf.all.disable_ipv6=0")

    @pytest.fixture(scope='class', autouse=True)
    def sharedHeadroomPoolSize(
        self, request, duthosts, get_src_dst_asic_and_duts, tbinfo, lower_tor_host
    ):
        """
            Retreives shared headroom pool size

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                size: shared headroom pool size
                      none if it is not defined
        """
        yield self.__getSharedHeadroomPoolSize(
            request,
            get_src_dst_asic_and_duts['src_asic']
        )

    @pytest.fixture(scope='class', autouse=True)
    def ingressLosslessProfile(
        self, request, get_src_dst_asic_and_duts, dutConfig, tbinfo, lower_tor_host, dualtor_ports_for_duts
    ):
        """
            Retreives ingress lossless profile

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports

            Returns:
                ingressLosslessProfile (dict): Map of ingress lossless buffer profile attributes
        """

        dut_asic = get_src_dst_asic_and_duts['src_asic']
        duthost = get_src_dst_asic_and_duts['src_dut']
        srcport = dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]]

        if srcport in dualtor_ports_for_duts:
            pgs = "2-4"
        else:
            pgs = "3-4"

        yield self.__getBufferProfile(
            request,
            dut_asic,
            duthost.os_version,
            "BUFFER_PG_TABLE" if self.isBufferInApplDb(dut_asic) else "BUFFER_PG",
            srcport,
            pgs
        )

    @pytest.fixture(scope='class', autouse=True)
    def ingressLossyProfile(
        self, request, duthosts, get_src_dst_asic_and_duts, dutConfig, tbinfo, lower_tor_host
    ):
        """
            Retreives ingress lossy profile

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports

            Returns:
                ingressLossyProfile (dict): Map of ingress lossy buffer profile attributes
        """
        duthost = get_src_dst_asic_and_duts['src_dut']
        dut_asic = get_src_dst_asic_and_duts['src_asic']
        yield self.__getBufferProfile(
            request,
            dut_asic,
            duthost.os_version,
            "BUFFER_PG_TABLE" if self.isBufferInApplDb(dut_asic) else "BUFFER_PG",
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            "0"
        )

    @pytest.fixture(scope='class', autouse=True)
    def egressLosslessProfile(
        self, request, duthosts, get_src_dst_asic_and_duts, dutConfig, tbinfo, lower_tor_host, dualtor_ports_for_duts
    ):
        """
            Retreives egress lossless profile

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports

            Returns:
                egressLosslessProfile (dict): Map of egress lossless buffer profile attributes
        """
        duthost = get_src_dst_asic_and_duts['src_dut']
        dut_asic = get_src_dst_asic_and_duts['src_asic']

        srcport = dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]]

        if srcport in dualtor_ports_for_duts:
            queues = "2-4"
        else:
            queues = "3-4"

        yield self.__getBufferProfile(
            request,
            dut_asic,
            duthost.os_version,
            "BUFFER_QUEUE_TABLE" if self.isBufferInApplDb(dut_asic) else "BUFFER_QUEUE",
            srcport,
            queues
        )

    @pytest.fixture(scope='class', autouse=True)
    def egressLossyProfile(
        self, request, duthosts, get_src_dst_asic_and_duts, dutConfig, tbinfo, lower_tor_host, dualtor_ports_for_duts
    ):
        """
            Retreives egress lossy profile

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces,
                test port IDs, test port IPs, and test ports

            Returns:
                egressLossyProfile (dict): Map of egress lossy buffer profile attributes
        """
        duthost = get_src_dst_asic_and_duts['src_dut']
        dut_asic = get_src_dst_asic_and_duts['src_asic']

        srcport = dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]]

        if srcport in dualtor_ports_for_duts:
            queues = "0-1"
        else:
            queues = "0-2"

        yield self.__getBufferProfile(
            request,
            dut_asic,
            duthost.os_version,
            "BUFFER_QUEUE_TABLE" if self.isBufferInApplDb(dut_asic) else "BUFFER_QUEUE",
            srcport,
            queues
        )

    @pytest.fixture(scope='class')
    def losslessSchedProfile(
            self, duthosts, get_src_dst_asic_and_duts, dutConfig, tbinfo, lower_tor_host
    ):
        """
            Retreives lossless scheduler profile

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces,
                test port IDs, test port IPs, and test ports

            Returns:
                losslessSchedProfile (dict): Map of scheduler parameters
        """
        dut_asic = get_src_dst_asic_and_duts['src_asic']

        yield self.__getSchedulerParam(
            dut_asic,
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            self.TARGET_LOSSLESS_QUEUE_SCHED
        )

    @pytest.fixture(scope='class')
    def lossySchedProfile(
        self, duthosts, get_src_dst_asic_and_duts, dutConfig, tbinfo, lower_tor_host
   ):
        """
            Retreives lossy scheduler profile

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces,
                test port IDs, test port IPs, and test ports

            Returns:
                lossySchedProfile (dict): Map of scheduler parameters
        """
        dut_asic = get_src_dst_asic_and_duts['src_asic']
        yield self.__getSchedulerParam(
            dut_asic,
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            self.TARGET_LOSSY_QUEUE_SCHED
        )

    @pytest.fixture
    def updateSchedProfile(
        self, duthosts, get_src_dst_asic_and_duts,
        dutQosConfig, losslessSchedProfile, lossySchedProfile, tbinfo, lower_tor_host
    ):
        """
            Updates lossless/lossy scheduler profiles

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                losslessSchedProfile (Fixture, dict): Map of lossless scheduler parameters
                lossySchedProfile (Fixture, dict): Map of lossy scheduler parameters

            Returns:
                None
        """
        def updateRedisSchedParam(schedParam):
            """
                Helper function to updates lossless/lossy scheduler profiles

                Args:
                    schedParam (dict): Scheduler params to be set

                Returns:
                    None
            """
            for a_asic in get_src_dst_asic_and_duts['all_asics']:
                a_asic.run_redis_cmd(
                    argv = [
                        "redis-cli",
                        "-n",
                        "4",
                        "HSET",
                        schedParam["profile"],
                        "weight",
                        schedParam["qosConfig"]
                    ]
                )

        wrrSchedParams = [
            {
                "profile": lossySchedProfile["schedProfile"],
                "qosConfig": dutQosConfig["param"]["wrr_chg"]["lossy_weight"]
            },
            {
                "profile": losslessSchedProfile["schedProfile"],
                "qosConfig": dutQosConfig["param"]["wrr_chg"]["lossless_weight"]
            },
        ]

        for schedParam in wrrSchedParams:
            updateRedisSchedParam(schedParam)

        yield

        schedProfileParams = [
            {
                "profile": lossySchedProfile["schedProfile"],
                "qosConfig": lossySchedProfile["schedWeight"]
            },
            {
                "profile": losslessSchedProfile["schedProfile"],
                "qosConfig": losslessSchedProfile["schedWeight"]
            },
        ]

        for schedParam in schedProfileParams:
            updateRedisSchedParam(schedParam)

    @pytest.fixture
    def resetWatermark(
        self, duthosts, get_src_dst_asic_and_duts, tbinfo, lower_tor_host
    ):
        """
            Reset queue watermark

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """

        for dut_asic in get_src_dst_asic_and_duts['all_asics']:
            dut_asic.command("counterpoll watermark enable")
            dut_asic.command("counterpoll queue enable")
            dut_asic.command("sleep 70")
            dut_asic.command("counterpoll watermark disable")
            dut_asic.command("counterpoll queue disable")

    @pytest.fixture(scope='class')
    def dualtor_ports_for_duts(request, get_src_dst_asic_and_duts):
        # Fetch dual ToR ports
        logger.info("Starting fetching dual ToR info")

        fetch_dual_tor_ports_script = "\
            local remap_enabled = redis.call('HGET', 'SYSTEM_DEFAULTS|tunnel_qos_remap', 'status')\
            if remap_enabled ~= 'enabled' then\
                return {}\
            end\
            local type = redis.call('HGET', 'DEVICE_METADATA|localhost', 'type')\
            local expected_neighbor_type\
            local expected_neighbor_suffix\
            if type == 'LeafRouter' then\
                expected_neighbor_type = 'ToRRouter'\
                expected_neighbor_suffix = 'T0'\
            else\
                if type == 'ToRRouter' then\
                    local subtype = redis.call('HGET', 'DEVICE_METADATA|localhost', 'subtype')\
                    if subtype == 'DualToR' then\
                        expected_neighbor_type = 'LeafRouter'\
                        expected_neighbor_suffix = 'T1'\
                    end\
                end\
            end\
            if expected_neighbor_type == nil then\
                return {}\
            end\
            local result = {}\
            local all_ports_with_neighbor = redis.call('KEYS', 'DEVICE_NEIGHBOR|*')\
            for i = 1, #all_ports_with_neighbor, 1 do\
                local neighbor = redis.call('HGET', all_ports_with_neighbor[i], 'name')\
                if neighbor ~= nil and string.sub(neighbor, -2, -1) == expected_neighbor_suffix then\
                    local peer_type = redis.call('HGET', 'DEVICE_NEIGHBOR_METADATA|' .. neighbor, 'type')\
                    if peer_type == expected_neighbor_type then\
                        table.insert(result, string.sub(all_ports_with_neighbor[i], 17, -1))\
                    end\
                end\
            end\
            return result\
        "

        duthost = get_src_dst_asic_and_duts['src_dut']

        dualtor_ports_str = get_src_dst_asic_and_duts['src_asic'].run_redis_cmd(
            argv=["sonic-db-cli", "CONFIG_DB", "eval", fetch_dual_tor_ports_script, "0"])
        if dualtor_ports_str:
            dualtor_ports_set = set(dualtor_ports_str)
        else:
            dualtor_ports_set = set({})

        logger.info("Finish fetching dual ToR info {}".format(dualtor_ports_set))

        return dualtor_ports_set

    @pytest.fixture(scope='function', autouse=False)
    def set_static_route(
            self, get_src_dst_asic_and_duts, dutTestParams, dutConfig):
        # Get portchannels.
        # find the one that is backplane based.
        # set a static route through that portchannel.
        # remove when done.
        if dutTestParams["basicParams"]["sonic_asic_type"] != "cisco-8000":
            yield
            return
        src_asic = get_src_dst_asic_and_duts['src_asic']
        dst_asic = get_src_dst_asic_and_duts['dst_asic']
        dst_keys = []
        for k in dutConfig["testPorts"].keys():
            if re.search("dst_port.*ip", k):
                dst_keys.append(k)

        for k in dst_keys:
            dst_asic.shell("ip netns exec asic{} ping -c 3 {}".format(
                dst_asic.asic_index,
                dutConfig["testPorts"][k]))

        if src_asic == dst_asic:
            yield
            return
        dst_ip = dutConfig["testPorts"]["dst_port_ip"]
        portchannels = dst_asic.command(
            "show interface portchannel -n asic{} -d all".format(
                dst_asic.asic_index))['stdout']
        regx = re.compile("(PortChannel[0-9]+)")
        bp_portchannels= []
        for l in portchannels.split("\n"):
            if "-BP" in l:
                match = regx.search(l)
                if match:
                    bp_portchannels.append(match.group(1))
        if not bp_portchannels:
            raise RuntimeError(
                "Couldn't find the backplane porchannels from {}".format(
                    bp_portchannels))

        ip_address_mapping = self.get_interface_ip(dst_asic)
        dst_keys = []
        for k in dutConfig["testPorts"].keys():
            if re.search("dst_port.*ip", k):
                dst_keys.append(k)

        for dst_index in range(len(dst_keys)):
            src_asic.shell("ip netns exec asic{} ping -c 1 {}".format(
                src_asic.asic_index,
                ip_address_mapping[bp_portchannels[dst_index]]))
            src_asic.shell("ip netns exec asic{} route add {} gw {}".format(
                src_asic.asic_index,
                dutConfig["testPorts"][dst_keys[dst_index]],
                ip_address_mapping[bp_portchannels[dst_index]]))
        yield
        for dst_index in range(len(dst_keys)):
            src_asic.shell("ip netns exec asic{} route del {} gw {}".format(
                src_asic.asic_index,
                dutConfig["testPorts"][dst_keys[dst_index]],
                ip_address_mapping[bp_portchannels[dst_index]]))

    def get_interface_ip(self, dut_asic):
        """
            Parse the output of "show ip int -n asic0 -d all" into a dict:
            interface => ip address.
        """
        mapping = {}
        ip_address_out = dut_asic.command("show ip interface -n asic{}".format(
            dut_asic.asic_index))['stdout']
        re_pattern = re.compile("^([^ ]*) [ ]*([0-9\.]*)\/")
        for line in ip_address_out.split("\n"):
            match = re_pattern.search(line)
            if match:
                mapping[match.group(1)] = match.group(2)

        return mapping
