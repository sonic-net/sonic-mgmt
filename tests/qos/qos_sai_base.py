import ipaddress
import json
import logging
import pytest
import re
import yaml
import random
import os
import sys
import six

from tests.common.fixtures.ptfhost_utils import ptf_portmap_file  # noqa F401
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice
from tests.common.cisco_data import is_cisco_device
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host, dualtor_ports  # noqa F401
from tests.common.dualtor.mux_simulator_control \
    import toggle_all_simulator_ports, get_mux_status, check_mux_status, validate_check_result  # noqa F401
from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR  # noqa F401
from tests.common.utilities import check_qos_db_fv_reference_with_table
from tests.common.fixtures.duthost_utils import dut_qos_maps, separated_dscp_to_tc_map_on_uplink  # noqa F401
from tests.common.utilities import wait_until
from tests.ptf_runner import ptf_runner
from tests.common.errors import RunAnsibleModuleFail

logger = logging.getLogger(__name__)


class QosBase:
    """
    Common APIs
    """
    SUPPORTED_T0_TOPOS = ["t0", "t0-56-po2vlan", "t0-64", "t0-116", "t0-35", "dualtor-56", "dualtor-120", "dualtor",
                          "t0-80", "t0-backend"]
    SUPPORTED_T1_TOPOS = ["t1-lag", "t1-64-lag", "t1-56-lag", "t1-backend"]
    SUPPORTED_PTF_TOPOS = ['ptf32', 'ptf64']
    SUPPORTED_ASIC_LIST = ["gb", "td2", "th", "th2",
                           "spc1", "spc2", "spc3", "td3", "th3", "j2c+", "jr2"]

    TARGET_QUEUE_WRED = 3
    TARGET_LOSSY_QUEUE_SCHED = 0
    TARGET_LOSSLESS_QUEUE_SCHED = 3

    buffer_model_initialized = False
    buffer_model = None

    def isBufferInApplDb(self, dut_asic):
        if not self.buffer_model_initialized:
            self.buffer_model = dut_asic.run_redis_cmd(
                argv=[
                    "redis-cli", "-n", "4", "hget",
                    "DEVICE_METADATA|localhost", "buffer_model"
                ]
            )

            self.buffer_model_initialized = True
            logger.info(
                "Buffer model is {}, buffer tables will be fetched from {}".format(
                    self.buffer_model or "not defined",
                    "APPL_DB" if self.buffer_model else "CONFIG_DB"
                )
            )
        return self.buffer_model

    @pytest.fixture(scope='class', autouse=True)
    def dutTestParams(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index,
                      dut_test_params, tbinfo):
        """
            Prepares DUT host test params
            Returns:
                dutTestParams (dict): DUT host test params
        """
        # update router mac
        dut_test_params["basicParams"]["asic_id"] = enum_frontend_asic_index
        if dut_test_params["topo"] in self.SUPPORTED_T0_TOPOS:
            dut_test_params["basicParams"]["router_mac"] = ''

        elif "dualtor" in tbinfo["topo"]["name"]:
            # For dualtor qos test scenario, DMAC of test traffic is default vlan interface's MAC address.
            # To reduce duplicated code, put "is_dualtor" and "def_vlan_mac" into dutTestParams['basicParams'].
            dut_test_params["basicParams"]["is_dualtor"] = True
            vlan_cfgs = tbinfo['topo']['properties']['topology']['DUT']['vlan_configs']
            if vlan_cfgs and 'default_vlan_config' in vlan_cfgs:
                default_vlan_name = vlan_cfgs['default_vlan_config']
                if default_vlan_name:
                    for vlan in list(vlan_cfgs[default_vlan_name].values()):
                        if 'mac' in vlan and vlan['mac']:
                            dut_test_params["basicParams"]["def_vlan_mac"] = vlan['mac']
                            break
            pytest_assert(dut_test_params["basicParams"]["def_vlan_mac"]
                          is not None, "Dual-TOR miss default VLAN MAC address")
        else:
            try:
                duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
                asic = duthost.asic_instance().asic_index
                dut_test_params['basicParams']["router_mac"] = duthost.shell(
                    'sonic-db-cli -n asic{} CONFIG_DB hget "DEVICE_METADATA|localhost" mac'.format(asic))['stdout']
            except RunAnsibleModuleFail:
                dut_test_params['basicParams']["router_mac"] = duthost.shell(
                    'sonic-db-cli CONFIG_DB hget "DEVICE_METADATA|localhost" mac')['stdout']

        yield dut_test_params

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
        custom_options = " --disable-ipv6 --disable-vxlan --disable-geneve" \
                         " --disable-erspan --disable-mpls --disable-nvgre"
        ptf_runner(
            ptfhost,
            "saitests",
            testCase,
            platform_dir="ptftests",
            params=testParams,
            log_file="/tmp/{0}.log".format(testCase),
            qlen=10000,
            is_python3=True,
            relax=False,
            timeout=1200,
            custom_options=custom_options
        )


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
        if check_qos_db_fv_reference_with_table(dut_asic):
            if six.PY2:
                pool = bufferProfile["pool"].encode("utf-8").translate(None, "[]")
            else:
                pool = bufferProfile["pool"].translate({ord(i): None for i in '[]'})
        else:
            pool = keystr + bufferProfile["pool"]
        bufferSize = int(
            dut_asic.run_redis_cmd(
                argv=["redis-cli", "-n", db, "HGET", pool, "size"]
            )[0]
        )
        bufferScale = 2 ** float(bufferProfile["dynamic_th"])
        bufferScale /= (bufferScale + 1)
        bufferProfile.update(
            {"static_th": int(
                bufferProfile["size"]) + int(bufferScale * bufferSize)}
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
        if check_qos_db_fv_reference_with_table(dut_asic):
            if self.isBufferInApplDb(dut_asic):
                if six.PY2:
                    bufferPoolName = bufferProfile["pool"].encode("utf-8").translate(
                        None, "[]").replace("BUFFER_POOL_TABLE:", '')
                else:
                    bufferPoolName = bufferProfile["pool"].translate(
                        {ord(i): None for i in '[]'}).replace("BUFFER_POOL_TABLE:", '')
            else:
                if six.PY2:
                    bufferPoolName = bufferProfile["pool"].encode("utf-8").translate(
                        None, "[]").replace("BUFFER_POOL|", '')
                else:
                    bufferPoolName = bufferProfile["pool"].translate(
                        {ord(i): None for i in '[]'}).replace("BUFFER_POOL|", '')
        else:
            bufferPoolName = six.text_type(bufferProfile["pool"])

        bufferPoolVoid = six.text_type(dut_asic.run_redis_cmd(
            argv=[
                "redis-cli", "-n", "2", "HGET",
                "COUNTERS_BUFFER_POOL_NAME_MAP", bufferPoolName
            ]
        )[0])
        bufferProfile.update({"bufferPoolVoid": bufferPoolVoid})

        bufferPoolRoid = six.text_type(dut_asic.run_redis_cmd(
            argv=["redis-cli", "-n", "1", "HGET", "VIDTORID", bufferPoolVoid]
        )[0]).replace("oid:", '')
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
                port = "{}:{}:{}".format(
                    dut_asic.sonichost.hostname, dut_asic.namespace, port)
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

        if check_qos_db_fv_reference_with_table(dut_asic):
            out = dut_asic.run_redis_cmd(argv=["redis-cli", "-n", db, "HGET", keystr, "profile"])[0]
            if six.PY2:
                bufferProfileName = out.encode("utf-8").translate(None, "[]")
            else:
                bufferProfileName = out.translate({ord(i): None for i in '[]'})
        else:
            bufferProfileName = bufkeystr + dut_asic.run_redis_cmd(
                argv=["redis-cli", "-n", db, "HGET", keystr, "profile"])[0]

        result = dut_asic.run_redis_cmd(
            argv=["redis-cli", "-n", db, "HGETALL", bufferProfileName]
        )
        it = iter(result)
        bufferProfile = dict(list(zip(it, it)))
        bufferProfile.update({"profileName": bufferProfileName})

        # Update profile static threshold value if  profile threshold is dynamic
        if "dynamic_th" in list(bufferProfile.keys()):
            self.__computeBufferThreshold(dut_asic, bufferProfile)

        if "pg_lossless" in bufferProfileName:
            pytest_assert(
                "xon" in list(bufferProfile.keys()) and "xoff" in list(
                    bufferProfile.keys()),
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
            argv=["redis-cli", "-n", db, "HGETALL", keystr]
        )
        it = iter(result)
        ingressLosslessPool = dict(list(zip(it, it)))
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
        if check_qos_db_fv_reference_with_table(dut_asic):
            out = dut_asic.run_redis_cmd(
                    argv=[
                        "redis-cli", "-n", "4", "HGET",
                        "{0}|{1}|{2}".format(table, port, self.TARGET_QUEUE_WRED),
                        "wred_profile"
                    ]
                )[0]
            if six.PY2:
                wredProfileName = out.encode("utf-8").translate(None, "[]")
            else:
                wredProfileName = out.translate({ord(i): None for i in '[]'})
        else:
            wredProfileName = "WRED_PROFILE|" + six.text_type(dut_asic.run_redis_cmd(
                argv=[
                    "redis-cli", "-n", "4", "HGET",
                    "{0}|{1}|{2}".format(table, port, self.TARGET_QUEUE_WRED),
                    "wred_profile"
                ]
            )[0])

        result = dut_asic.run_redis_cmd(
            argv=["redis-cli", "-n", "4", "HGETALL", wredProfileName]
        )
        it = iter(result)
        wredProfile = dict(list(zip(it, it)))

        return wredProfile

    def __getWatermarkStatus(self, dut_asic):
        """
            Get watermark status from Redis db

            Args:
                dut_asic (SonicAsic): Device Under Test (DUT)

            Returns:
                watermarkStatus (str): Watermark status
        """
        watermarkStatus = six.text_type(dut_asic.run_redis_cmd(
            argv=[
                "redis-cli", "-n", "4", "HGET",
                "FLEX_COUNTER_TABLE|QUEUE_WATERMARK", "FLEX_COUNTER_STATUS"
            ]
        )[0])

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
        if check_qos_db_fv_reference_with_table(dut_asic):
            out = dut_asic.run_redis_cmd(
                    argv=[
                        "redis-cli", "-n", "4", "HGET",
                        "QUEUE|{0}|{1}".format(port, queue), "scheduler"
                    ]
                )[0]
            if six.PY2:
                schedProfile = out.encode("utf-8").translate(None, "[]")
            else:
                schedProfile = out.translate({ord(i): None for i in '[]'})
        else:
            schedProfile = "SCHEDULER|" + six.text_type(dut_asic.run_redis_cmd(
                argv=[
                    "redis-cli", "-n", "4", "HGET",
                    "QUEUE|{0}|{1}".format(port, queue), "scheduler"
                ]
            )[0])

        schedWeight = six.text_type(dut_asic.run_redis_cmd(
            argv=["redis-cli", "-n", "4", "HGET", schedProfile, "weight"]
        )[0])

        return {"schedProfile": schedProfile, "schedWeight": schedWeight}

    def __assignTestPortIps(self, mgFacts, topo):
        """
            Assign IPs to test ports of DUT host

            Args:
                mgFacts (dict): Map of DUT minigraph facts

            Returns:
                dutPortIps (dict): Map of port index to IPs
        """
        dutPortIps = {}
        if len(mgFacts["minigraph_vlans"]) > 0:
            # TODO: handle the case when there are multiple vlans
            vlans = iter(mgFacts["minigraph_vlans"])
            testVlan = next(vlans)
            testVlanMembers = mgFacts["minigraph_vlans"][testVlan]["members"]
            # To support t0-56-po2vlan topo, choose the Vlan with physical ports and remove the lag in Vlan members
            if topo == 't0-56-po2vlan':
                if len(testVlanMembers) == 1:
                    testVlan = next(vlans)
                    testVlanMembers = mgFacts["minigraph_vlans"][testVlan]["members"]
                for member in testVlanMembers:
                    if 'PortChannel' in member:
                        testVlanMembers.remove(member)
                        break

            testVlanIp = None
            for vlan in mgFacts["minigraph_vlan_interfaces"]:
                if mgFacts["minigraph_vlans"][testVlan]["name"] in vlan["attachto"]:
                    testVlanIp = ipaddress.ip_address(str(vlan["addr"]))  # noqa F821
                    break
            pytest_assert(testVlanIp, "Failed to obtain vlan IP")

            vlan_id = None
            if 'type' in mgFacts["minigraph_vlans"][testVlan]:
                vlan_type = mgFacts["minigraph_vlans"][testVlan]['type']
                if vlan_type is not None and "Tagged" in vlan_type:
                    vlan_id = mgFacts["minigraph_vlans"][testVlan]['vlanid']

            for i in range(len(testVlanMembers)):
                portIndex = mgFacts["minigraph_ptf_indices"][testVlanMembers[i]]
                portIpMap = {'peer_addr': str(testVlanIp + portIndex + 1)}
                if vlan_id is not None:
                    portIpMap['vlan_id'] = vlan_id
                dutPortIps.update({portIndex: portIpMap})

        return dutPortIps

    def __buildTestPorts(self, request, testPortIds, testPortIps, src_port_ids, dst_port_ids):
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

        if dstPorts is None:
            if dst_port_ids:
                pytest_assert(
                    len(set(testPortIds).intersection(
                        set(dst_port_ids))) == len(set(dst_port_ids)),
                    "Dest port id passed in qos.yml not valid"
                )
                dstPorts = dst_port_ids
            elif len(testPortIds) >= 4:
                dstPorts = [0, 2, 3]
            elif len(testPortIds) == 3:
                dstPorts = [0, 2, 2]
            else:
                dstPorts = [0, 0, 0]

        if srcPorts is None:
            if src_port_ids:
                pytest_assert(
                    len(set(testPortIds).intersection(
                        set(src_port_ids))) == len(set(src_port_ids)),
                    "Source port id passed in qos.yml not valid"
                )
                # To verify ingress lossless speed/cable-length randomize the source port.
                srcPorts = [random.choice(src_port_ids)]
            else:
                srcPorts = [1]

        pytest_assert(len(testPortIds) >= 2, "Provide at least 2 test ports")
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
        dstPort = dstPorts[0] if dst_port_ids else testPortIds[dstPorts[0]]
        dstVlan = testPortIps[dstPort]['vlan_id'] if 'vlan_id' in testPortIps[dstPort] else None
        dstPort2 = dstPorts[1] if dst_port_ids else testPortIds[dstPorts[1]]
        dstVlan2 = testPortIps[dstPort2]['vlan_id'] if 'vlan_id' in testPortIps[dstPort2] else None
        dstPort3 = dstPorts[2] if dst_port_ids else testPortIds[dstPorts[2]]
        dstVlan3 = testPortIps[dstPort3]['vlan_id'] if 'vlan_id' in testPortIps[dstPort3] else None
        srcPort = srcPorts[0] if src_port_ids else testPortIds[srcPorts[0]]
        srcVlan = testPortIps[srcPort]['vlan_id'] if 'vlan_id' in testPortIps[srcPort] else None
        return {
            "dst_port_id": dstPort,
            "dst_port_ip": testPortIps[dstPort]['peer_addr'],
            "dst_port_vlan": dstVlan,
            "dst_port_2_id": dstPort2,
            "dst_port_2_ip": testPortIps[dstPort2]['peer_addr'],
            "dst_port_2_vlan": dstVlan2,
            'dst_port_3_id': dstPort3,
            "dst_port_3_ip": testPortIps[dstPort3]['peer_addr'],
            "dst_port_3_vlan": dstVlan3,
            "src_port_id": srcPorts[0] if src_port_ids else testPortIds[srcPorts[0]],
            "src_port_ip": testPortIps[srcPorts[0] if src_port_ids else testPortIds[srcPorts[0]]]["peer_addr"],
            "src_port_vlan": srcVlan
        }

    @pytest.fixture(scope='class', autouse=True)
    def dutConfig(
            self, request, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
            enum_frontend_asic_index, lower_tor_host, tbinfo, dualtor_ports, dut_qos_maps):  # noqa F811
        """
            Build DUT host config pertaining to QoS SAI tests

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                dutConfig (dict): Map of DUT config containing dut interfaces,
                test port IDs, test port IPs, and test ports
        """
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
            dut_asic = duthost.asic_instance(enum_frontend_asic_index)

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        dutLagInterfaces = []
        dutPortIps = {}
        testPortIps = {}
        uplinkPortIds = []
        uplinkPortIps = []
        uplinkPortNames = []
        downlinkPortIds = []
        downlinkPortIps = []
        downlinkPortNames = []

        mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
        topo = tbinfo["topo"]["name"]

        dualTorPortIndexes = []

        testPortIds = []
        # LAG ports in T1 TOPO need to be removed in Mellanox devices
        if topo in self.SUPPORTED_T0_TOPOS or isMellanoxDevice(duthost):
            pytest_assert(
                not duthost.sonichost.is_multi_asic, "Fixture not supported on T0 multi ASIC"
            )
            for _, lag in list(mgFacts["minigraph_portchannels"].items()):
                for intf in lag["members"]:
                    dutLagInterfaces.append(
                        mgFacts["minigraph_ptf_indices"][intf])

            testPortIds = set(mgFacts["minigraph_ptf_indices"][port]
                              for port in list(mgFacts["minigraph_ports"].keys()))
            testPortIds -= set(dutLagInterfaces)
            if isMellanoxDevice(duthost):
                # The last port is used for up link from DUT switch
                testPortIds -= {len(mgFacts["minigraph_ptf_indices"]) - 1}
            testPortIds = sorted(testPortIds)
            pytest_require(len(testPortIds) != 0,
                           "Skip test since no ports are available for testing")

            # get current DUT port IPs
            dutPortIps = {}
            if 'backend' in topo:
                intf_map = mgFacts["minigraph_vlan_sub_interfaces"]
            else:
                intf_map = mgFacts["minigraph_interfaces"]

            use_separated_upkink_dscp_tc_map = separated_dscp_to_tc_map_on_uplink(
                duthost, dut_qos_maps)
            for portConfig in intf_map:
                intf = portConfig["attachto"].split(".")[0]
                if ipaddress.ip_interface(portConfig['peer_addr']).ip.version == 4:
                    portIndex = mgFacts["minigraph_ptf_indices"][intf]
                    if portIndex in testPortIds:
                        portIpMap = {'peer_addr': portConfig["peer_addr"]}
                        if 'vlan' in portConfig:
                            portIpMap['vlan_id'] = portConfig['vlan']
                        dutPortIps.update({portIndex: portIpMap})
                        if intf in dualtor_ports:
                            dualTorPortIndexes.append(portIndex)
                    # If the leaf router is using separated DSCP_TO_TC_MAP on uplink/downlink ports.
                    # we also need to test them separately
                    # for mellanox device, we run it on t1 topo mocked by ptf32 topo
                    if use_separated_upkink_dscp_tc_map and isMellanoxDevice(duthost):
                        neighName = mgFacts["minigraph_neighbors"].get(
                            intf, {}).get("name", "").lower()
                        if 't0' in neighName:
                            downlinkPortIds.append(portIndex)
                            downlinkPortIps.append(portConfig["peer_addr"])
                            downlinkPortNames.append(intf)
                        elif 't2' in neighName:
                            uplinkPortIds.append(portIndex)
                            uplinkPortIps.append(portConfig["peer_addr"])
                            uplinkPortNames.append(intf)

            testPortIps = self.__assignTestPortIps(mgFacts, topo)

        elif topo in self.SUPPORTED_T1_TOPOS:
            use_separated_upkink_dscp_tc_map = separated_dscp_to_tc_map_on_uplink(
                duthost, dut_qos_maps)
            for iface, addr in list(dut_asic.get_active_ip_interfaces(tbinfo).items()):
                vlan_id = None
                if iface.startswith("Ethernet"):
                    portName = iface
                    if "." in iface:
                        portName, vlan_id = iface.split(".")
                    portIndex = mgFacts["minigraph_ptf_indices"][portName]
                    portIpMap = {'peer_addr': addr["peer_ipv4"]}
                    if vlan_id is not None:
                        portIpMap['vlan_id'] = vlan_id
                    dutPortIps.update({portIndex: portIpMap})
                elif iface.startswith("PortChannel"):
                    portName = next(
                        iter(mgFacts["minigraph_portchannels"]
                             [iface]["members"])
                    )
                    portIndex = mgFacts["minigraph_ptf_indices"][portName]
                    portIpMap = {'peer_addr': addr["peer_ipv4"]}
                    dutPortIps.update({portIndex: portIpMap})
                # If the leaf router is using separated DSCP_TO_TC_MAP on uplink/downlink ports.
                # we also need to test them separately
                if use_separated_upkink_dscp_tc_map:
                    neighName = mgFacts["minigraph_neighbors"].get(
                        portName, {}).get("name", "").lower()
                    if 't0' in neighName:
                        downlinkPortIds.append(portIndex)
                        downlinkPortIps.append(addr["peer_ipv4"])
                        downlinkPortNames.append(portName)
                    elif 't2' in neighName:
                        uplinkPortIds.append(portIndex)
                        uplinkPortIps.append(addr["peer_ipv4"])
                        uplinkPortNames.append(portName)

            testPortIds = sorted(dutPortIps.keys())

        elif tbinfo["topo"]["type"] == "t2":
            for iface, addr in list(dut_asic.get_active_ip_interfaces(tbinfo).items()):
                vlan_id = None
                if iface.startswith("Ethernet") and ("Ethernet-Rec" not in iface):
                    if "." in iface:
                        iface, vlan_id = iface.split(".")
                    portIndex = mgFacts["minigraph_ptf_indices"][iface]
                    portIpMap = {'peer_addr': addr["peer_ipv4"], 'port': iface}
                    if vlan_id is not None:
                        portIpMap['vlan_id'] = vlan_id
                    dutPortIps.update({portIndex: portIpMap})
                elif iface.startswith("PortChannel"):
                    portName = next(
                        iter(mgFacts["minigraph_portchannels"]
                             [iface]["members"])
                    )
                    portIndex = mgFacts["minigraph_ptf_indices"][portName]
                    portIpMap = {
                        'peer_addr': addr["peer_ipv4"], 'port': portName}
                    dutPortIps.update({portIndex: portIpMap})

            testPortIds = sorted(dutPortIps.keys())

        # restore currently assigned IPs
        testPortIps.update(dutPortIps)

        qosConfigs = {}
        with open(r"qos/files/qos.yml") as file:
            qosConfigs = yaml.load(file, Loader=yaml.FullLoader)

        vendor = duthost.facts["asic_type"]
        hostvars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]
        dutAsic = None
        for asic in self.SUPPORTED_ASIC_LIST:
            vendorAsic = "{0}_{1}_hwskus".format(vendor, asic)
            if vendorAsic in list(hostvars.keys()) and mgFacts["minigraph_hwsku"] in hostvars[vendorAsic]:
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

        testPorts = self.__buildTestPorts(
            request, testPortIds, testPortIps, src_port_ids, dst_port_ids)
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
            for ptf_port, ptf_val in list(dutPortIps.items()):
                dutinterfaces[ptf_port] = ptf_val['port']
        else:
            for port, index in list(mgFacts["minigraph_ptf_indices"].items()):
                if 'Ethernet-Rec' not in port and 'Ethernet-IB' not in port:
                    dutinterfaces[index] = port

        yield {
            "dutInterfaces": dutinterfaces,
            "testPortIds": testPortIds,
            "testPortIps": testPortIps,
            "testPorts": testPorts,
            "qosConfigs": qosConfigs,
            "dutAsic": dutAsic,
            "dutTopo": dutTopo,
            "dutInstance": duthost,
            "dualTor": request.config.getoption("--qos_dual_tor"),
            "dualTorScenario": len(dualtor_ports) != 0
        }

    @pytest.fixture(scope='class')
    def ssh_tunnel_to_syncd_rpc(
            self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index,
            swapSyncd, tbinfo, lower_tor_host  # noqa: F811
    ):
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        dut_asic.create_ssh_tunnel_sai_rpc()

        yield

        dut_asic.remove_ssh_tunnel_sai_rpc()

    @pytest.fixture(scope='class')
    def updateIptables(
            self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, swapSyncd, tbinfo,
            lower_tor_host  # noqa: F811
    ):
        """
            Update iptables on DUT host with drop rule for BGP SYNC packets

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                swapSyncd (Fixture): swapSyncd fixture is required to run prior to updating iptables

            Returns:
                None
        """
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        dut_asic = duthost.asic_instance(enum_frontend_asic_index)

        ipVersions = [{"ip_version": "ipv4"}, {"ip_version": "ipv6"}]

        logger.info(
            "Add ip[6]tables rule to drop BGP SYN Packet from peer so that we do not ACK back")
        for ipVersion in ipVersions:
            dut_asic.bgp_drop_rule(state="present", **ipVersion)

        yield

        logger.info("Remove ip[6]tables rule to drop BGP SYN Packet from Peer")
        for ipVersion in ipVersions:
            dut_asic.bgp_drop_rule(state="absent", **ipVersion)

    @pytest.fixture(scope='class')
    def stopServices(
            self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
            enum_frontend_asic_index, swapSyncd, enable_container_autorestart,
            disable_container_autorestart, get_mux_status, tbinfo, upper_tor_host,      # noqa F811
            lower_tor_host, toggle_all_simulator_ports):                                # noqa F811
        """
            Stop services (lldp-syncs, lldpd, bgpd) on DUT host prior to test start

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                swapSyncd (Fxiture): swapSyncd fixture is required to run prior to stopping services

            Returns:
                None
        """
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
            duthost_upper = upper_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)

        def updateDockerService(host, docker="", action="", service=""):  # noqa: F811
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
            check_result = wait_until(
                120, 10, 10, check_mux_status, duthosts, LOWER_TOR)
            validate_check_result(check_result, duthosts, get_mux_status)

            try:
                duthost.shell("ls %s" % file)
                duthost.shell("sudo cp {} {}".format(file, backup_file))
                duthost.shell("sudo rm {}".format(file))
                duthost.shell("sudo touch {}".format(file))
            except Exception:
                pytest.skip('file {} not found'.format(file))

            duthost_upper.shell('sudo config feature state mux disabled')
            duthost.shell('sudo config feature state mux disabled')

        services = [
            {"docker": dut_asic.get_docker_name(
                "lldp"), "service": "lldp-syncd"},
            {"docker": dut_asic.get_docker_name("lldp"), "service": "lldpd"},
            {"docker": dut_asic.get_docker_name("bgp"), "service": "bgpd"},
            {"docker": dut_asic.get_docker_name("bgp"), "service": "bgpmon"},
            {"docker": dut_asic.get_docker_name("radv"), "service": "radvd"},
            {"docker": dut_asic.get_docker_name(
                "swss"), "service": "arp_update"}
        ]

        feature_list = ['lldp', 'bgp', 'syncd', 'swss']
        if 'dualtor' in tbinfo['topo']['name']:
            disable_container_autorestart(
                duthost_upper, testcase="test_qos_sai", feature_list=feature_list)

        disable_container_autorestart(
            duthost, testcase="test_qos_sai", feature_list=feature_list)
        for service in services:
            updateDockerService(duthost, action="stop", **service)

        yield

        for service in services:
            updateDockerService(duthost, action="start", **service)

        """ Start mux conatiner for dual ToR """
        if 'dualtor' in tbinfo['topo']['name']:
            try:
                duthost.shell("ls %s" % backup_file)
                duthost.shell("sudo cp {} {}".format(backup_file, file))
                duthost.shell("sudo chmod +x {}".format(file))
                duthost.shell("sudo rm {}".format(backup_file))
            except Exception:
                pytest.skip('file {} not found'.format(backup_file))

            duthost.shell('sudo config feature state mux enabled')
            duthost_upper.shell('sudo config feature state mux enabled')
            logger.info("Start mux container for dual ToR testbed")

        enable_container_autorestart(
            duthost, testcase="test_qos_sai", feature_list=feature_list)
        if 'dualtor' in tbinfo['topo']['name']:
            enable_container_autorestart(
                duthost_upper, testcase="test_qos_sai", feature_list=feature_list)

    @pytest.fixture(autouse=True)
    def updateLoganalyzerExceptions(self, enum_rand_one_per_hwsku_frontend_hostname, loganalyzer):
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
                ".*ERR monit.* 'lldp\\|lldpd_monitor' status failed.*-- 'lldpd:' is not running.*",

                ".*ERR monit.*'lldp_syncd' process is not running.*",
                ".*ERR monit.*'lldp\\|lldp_syncd' status failed.*-- 'python.* -m lldp_syncd' is not running.*",

                ".*ERR monit.*'bgpd' process is not running.*",
                ".*ERR monit.*'bgp\\|bgpd' status failed.*-- '/usr/lib/frr/bgpd' is not running.*",

                ".*ERR monit.*'bgpcfgd' process is not running.*",
                ".*ERR monit.*'bgp\\|bgpcfgd' status failed.*-- "
                "'/usr/bin/python.* /usr/local/bin/bgpcfgd' is not running.*",

                ".*ERR syncd#syncd:.*brcm_sai_set_switch_attribute:.*updating switch mac addr failed.*",

                ".*ERR monit.*'bgp\\|bgpmon' status failed.*'/usr/bin/python.* /usr/local/bin/bgpmon' is not running.*",
                ".*ERR monit.*bgp\\|fpmsyncd.*status failed.*NoSuchProcess process no longer exists.*",
                ".*WARNING syncd#SDK:.*check_attribs_metadata: Not implemented attribute.*",
                ".*WARNING syncd#SDK:.*sai_set_attribute: Failed attribs check, key:Switch ID.*",
                ".*WARNING syncd#SDK:.*check_rate: Set max rate to 0.*"
            ]
            loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend(
                ignoreRegex)

        yield

    @pytest.fixture(scope='class', autouse=True)
    def disablePacketAging(
            self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, stopServices
    ):
        """
            disable packet aging on DUT host

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                stopServices (Fxiture): stopServices fixture is required to run prior to disabling packet aging

            Returns:
                None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        if isMellanoxDevice(duthost):
            logger.info("Disable Mellanox packet aging")
            duthost.copy(
                src="qos/files/mellanox/packets_aging.py", dest="/tmp")
            duthost.command("docker cp /tmp/packets_aging.py syncd:/")
            duthost.command(
                "docker exec syncd python /packets_aging.py disable")

        yield

        if isMellanoxDevice(duthost):
            logger.info("Enable Mellanox packet aging")
            duthost.command(
                "docker exec syncd python /packets_aging.py enable")
            duthost.command("docker exec syncd rm -rf /packets_aging.py")

    def dutArpProxyConfig(self, duthost):
        # so far, only record ARP proxy config to logging for debug purpose
        vlanInterface = {}
        try:
            vlanInterface = json.loads(duthost.shell(
                'sonic-cfggen -d --var-json "VLAN_INTERFACE"')['stdout'])
        except Exception:
            logger.info('Failed to read vlan interface config')
        if not vlanInterface:
            return
        for key, value in list(vlanInterface.items()):
            if 'proxy_arp' in value:
                logger.info('ARP proxy is {} on {}'.format(
                    value['proxy_arp'], key))

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
            self, duthosts, enum_frontend_asic_index, enum_rand_one_per_hwsku_frontend_hostname,
            dutConfig, ingressLosslessProfile, ingressLossyProfile,
            egressLosslessProfile, egressLossyProfile, sharedHeadroomPoolSize,
            tbinfo, lower_tor_host  # noqa: F811
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
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
        pytest_assert("minigraph_hwsku" in mgFacts, "Could not find DUT SKU")

        profileName = ingressLosslessProfile["profileName"]
        logger.info(
            "Lossless Buffer profile selected is {}".format(profileName))

        if self.isBufferInApplDb(dut_asic):
            profile_pattern = "^BUFFER_PROFILE_TABLE\\:pg_lossless_(.*)_profile$"
        else:
            profile_pattern = "^BUFFER_PROFILE\\|pg_lossless_(.*)_profile"
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
                                                       dutConfig["dualTor"]
                                                       )
            qosParams = qpm.run()

        elif 'broadcom' in duthost.facts['asic_type'].lower():
            if 'platform_asic' in duthost.facts and duthost.facts['platform_asic'] == 'broadcom-dnx':
                logger.info(
                    "THDI_BUFFER_CELL_LIMIT_SP is not valid for broadcom DNX - ignore dynamic buffer config")
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
            self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, dutTestParams,
            updateIptables, ssh_tunnel_to_syncd_rpc
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
        duthost.docker_cmds_on_all_asics(
            "swssconfig /etc/swss/config.d/switch.json", "swss")

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
    def handleFdbAging(self, tbinfo, duthosts, lower_tor_host, enum_rand_one_per_hwsku_frontend_hostname):  # noqa: F811
        """
            Disable FDB aging and reenable at the end of tests

            Set fdb_aging_time to 0, update the swss configuration, and restore SWSS configuration afer
            test completes

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        fdbAgingTime = 0

        self.__deleteTmpSwitchConfig(duthost)
        duthost.docker_copy_from_asic(
            "swss", "/etc/swss/config.d/switch.json", "/tmp")
        duthost.replace(
            dest='/tmp/switch.json',
            regexp='"fdb_aging_time": ".*"',
            replace='"fdb_aging_time": "{0}"'.format(fdbAgingTime),
            backup=True
        )
        duthost.docker_copy_to_all_asics(
            "swss", "/tmp/switch.json", "/etc/swss/config.d/switch.json")
        self.__loadSwssConfig(duthost)

        yield

        result = duthost.find(path=["/tmp"], patterns=["switch.json.*"])
        if result["matched"] > 0:
            src = result["files"][0]["path"]
            duthost.docker_copy_to_all_asics(
                "swss", src, "/etc/swss/config.d/switch.json")
            self.__loadSwssConfig(duthost)
        self.__deleteTmpSwitchConfig(duthost)

    @pytest.fixture(scope='class', autouse=True)
    def populateArpEntries(
            self, duthosts, enum_frontend_asic_index, enum_rand_one_per_hwsku_frontend_hostname,
            ptfhost, dutTestParams, dutConfig, releaseAllPorts, handleFdbAging, tbinfo, lower_tor_host  # noqa: F811
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
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)

        if 't2' not in tbinfo['topo']['name']:
            dut_asic.command('sonic-clear fdb all')
            dut_asic.command('sonic-clear arp')


        saiQosTest = None
        if dutTestParams["topo"] in self.SUPPORTED_T0_TOPOS:
            saiQosTest = "sai_qos_tests.ARPpopulate"
        elif dutTestParams["topo"] in self.SUPPORTED_PTF_TOPOS:
            saiQosTest = "sai_qos_tests.ARPpopulatePTF"
        else:
            result = dut_asic.command("arp -n")
            pytest_assert(
                result["rc"] == 0, "failed to run arp command on {0}".format(duthost.hostname))
            if result["stdout"].find("incomplete") == -1:
                saiQosTest = "sai_qos_tests.ARPpopulate"

        if saiQosTest:
            testParams = dutTestParams["basicParams"]
            testParams.update(dutConfig["testPorts"])
            self.runPtfTest(
                ptfhost, testCase=saiQosTest, testParams=testParams
            )

    @pytest.fixture(scope='class', autouse=True)
    def dut_disable_ipv6(
            self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo, lower_tor_host):  # noqa: F811
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        duthost.shell("sysctl -w net.ipv6.conf.all.disable_ipv6=1")

        yield
        duthost.shell("sysctl -w net.ipv6.conf.all.disable_ipv6=0")

    @pytest.fixture(scope='class', autouse=True)
    def sharedHeadroomPoolSize(
            self, request, duthosts, enum_frontend_asic_index,
            enum_rand_one_per_hwsku_frontend_hostname, tbinfo, lower_tor_host  # noqa: F811
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
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        yield self.__getSharedHeadroomPoolSize(
            request,
            duthost.asic_instance(enum_frontend_asic_index)
        )

    @pytest.fixture(scope='class', autouse=True)
    def ingressLosslessProfile(
            self, request, duthosts, enum_frontend_asic_index,
            enum_rand_one_per_hwsku_frontend_hostname, dutConfig, tbinfo, lower_tor_host, dualtor_ports  # noqa: F811
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
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        srcport = dutConfig["dutInterfaces"][dutConfig["testPorts"]
                                             ["src_port_id"]]

        if srcport in dualtor_ports:
            pgs = "2-4"
        else:
            pgs = "3-4"

        yield self.__getBufferProfile(
            request,
            dut_asic,
            duthost.os_version,
            "BUFFER_PG_TABLE" if self.isBufferInApplDb(
                dut_asic) else "BUFFER_PG",
            srcport,
            pgs
        )

    @pytest.fixture(scope='class', autouse=True)
    def ingressLossyProfile(
            self, request, duthosts, enum_frontend_asic_index,
            enum_rand_one_per_hwsku_frontend_hostname, dutConfig, tbinfo, lower_tor_host  # noqa: F811
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
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        yield self.__getBufferProfile(
            request,
            dut_asic,
            duthost.os_version,
            "BUFFER_PG_TABLE" if self.isBufferInApplDb(
                dut_asic) else "BUFFER_PG",
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            "0"
        )

    @pytest.fixture(scope='class', autouse=True)
    def egressLosslessProfile(
            self, request, duthosts, enum_frontend_asic_index,
            enum_rand_one_per_hwsku_frontend_hostname, dutConfig, tbinfo, lower_tor_host, dualtor_ports  # noqa: F811
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
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        srcport = dutConfig["dutInterfaces"][dutConfig["testPorts"]
                                             ["src_port_id"]]

        if srcport in dualtor_ports:
            queues = "2-4"
        else:
            queues = "3-4"

        yield self.__getBufferProfile(
            request,
            dut_asic,
            duthost.os_version,
            "BUFFER_QUEUE_TABLE" if self.isBufferInApplDb(
                dut_asic) else "BUFFER_QUEUE",
            srcport,
            queues
        )

    @pytest.fixture(scope='class', autouse=True)
    def egressLossyProfile(
            self, request, duthosts, enum_frontend_asic_index,
            enum_rand_one_per_hwsku_frontend_hostname, dutConfig, tbinfo, lower_tor_host, dualtor_ports  # noqa: F811
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
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        srcport = dutConfig["dutInterfaces"][dutConfig["testPorts"]
                                             ["src_port_id"]]

        if srcport in dualtor_ports:
            queues = "0-1"
        else:
            queues = "0-2"

        yield self.__getBufferProfile(
            request,
            dut_asic,
            duthost.os_version,
            "BUFFER_QUEUE_TABLE" if self.isBufferInApplDb(
                dut_asic) else "BUFFER_QUEUE",
            srcport,
            queues
        )

    @pytest.fixture(scope='class')
    def losslessSchedProfile(
            self, duthosts, enum_frontend_asic_index, enum_rand_one_per_hwsku_frontend_hostname,
            dutConfig, tbinfo, lower_tor_host  # noqa: F811
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
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        yield self.__getSchedulerParam(
            duthost.asic_instance(enum_frontend_asic_index),
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            self.TARGET_LOSSLESS_QUEUE_SCHED
        )

    @pytest.fixture(scope='class')
    def lossySchedProfile(
            self, duthosts, enum_frontend_asic_index, enum_rand_one_per_hwsku_frontend_hostname,
            dutConfig, tbinfo, lower_tor_host  # noqa: F811
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
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        yield self.__getSchedulerParam(
            duthost.asic_instance(enum_frontend_asic_index),
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            self.TARGET_LOSSY_QUEUE_SCHED
        )

    @pytest.fixture
    def updateSchedProfile(
            self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index,
            dutQosConfig, losslessSchedProfile, lossySchedProfile, tbinfo, lower_tor_host  # noqa: F811
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
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        def updateRedisSchedParam(schedParam):
            """
                Helper function to updates lossless/lossy scheduler profiles

                Args:
                    schedParam (dict): Scheduler params to be set

                Returns:
                    None
            """
            duthost.asic_instance(enum_frontend_asic_index).run_redis_cmd(
                argv=[
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
    def resetWatermark(self, duthosts, enum_frontend_asic_index,
                       enum_rand_one_per_hwsku_frontend_hostname, tbinfo, lower_tor_host):  # noqa: F811
        """
            Reset queue watermark

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        dut_asic.command("counterpoll watermark enable")
        dut_asic.command("counterpoll queue enable")
        dut_asic.command("sleep 70")
        dut_asic.command("counterpoll watermark disable")
        dut_asic.command("counterpoll queue disable")
