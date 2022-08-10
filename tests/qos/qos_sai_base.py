import ipaddress
import logging
import pytest
import re
import yaml

from tests.common.fixtures.ptfhost_utils import ptf_portmap_file    # lgtm[py/unused-import]
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice
from tests.common.dualtor.dual_tor_utils import upper_tor_host,lower_tor_host,dualtor_ports
from tests.common.dualtor.mux_simulator_control import mux_server_url, toggle_all_simulator_ports
from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR
from tests.common.utilities import check_qos_db_fv_reference_with_table

logger = logging.getLogger(__name__)

class QosBase:
    """
    Common APIs
    """
    SUPPORTED_T0_TOPOS = ["t0", "t0-64", "t0-116", "t0-35", "dualtor-56", "dualtor", "t0-80", "t0-backend"]
    SUPPORTED_T1_TOPOS = ["t1-lag", "t1-64-lag", "t1-backend"]
    SUPPORTED_PTF_TOPOS = ['ptf32', 'ptf64']
    SUPPORTED_ASIC_LIST = ["gb", "td2", "th", "th2", "spc1", "spc2", "spc3", "td3", "th3"]

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
    def dutTestParams(self, dut_test_params):
        """
            Prepares DUT host test params
            Returns:
                dutTestParams (dict): DUT host test params
        """
        # update router mac
        if dut_test_params["topo"] in self.SUPPORTED_T0_TOPOS:
            dut_test_params["basicParams"]["router_mac"] = ''

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
        pytest_assert(ptfhost.shell(
                      argv = [
                          "ptf",
                          "--test-dir",
                          "saitests",
                          testCase,
                          "--platform-dir",
                          "ptftests",
                          "--platform",
                          "remote",
                          "-t",
                          ";".join(["{}={}".format(k, repr(v)) for k, v in testParams.items()]),
                          "--disable-ipv6",
                          "--disable-vxlan",
                          "--disable-geneve",
                          "--disable-erspan",
                          "--disable-mpls",
                          "--disable-nvgre",
                          "--log-file",
                          "/tmp/{0}.log".format(testCase),
                          "--test-case-timeout",
                          "600"
                      ],
                      chdir = "/root",
                      )["rc"] == 0, "Failed when running test '{0}'".format(testCase))


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
                    len(set(testPortIds).intersection(set(dst_port_ids))) == len(set(dst_port_ids)),
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
                    len(set(testPortIds).intersection(set(src_port_ids))) == len(set(src_port_ids)),
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


        #TODO: Randomize port selection
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
        self, request, duthosts, rand_one_dut_hostname, tbinfo,
        enum_frontend_asic_index, lower_tor_host, dualtor_ports
    ):
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
            duthost = duthosts[rand_one_dut_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        dutLagInterfaces = []
        dutPortIps = {}
        testPortIps = {}

        mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
        topo = tbinfo["topo"]["name"]

        dualTorPortIndexes = []

        testPortIds = []
        # LAG ports in T1 TOPO need to be removed in Mellanox devices
        if topo in self.SUPPORTED_T0_TOPOS or topo in self.SUPPORTED_T1_TOPOS or isMellanoxDevice(duthost):
            pytest_assert(
                not duthost.sonichost.is_multi_asic, "Fixture not supported on T0 multi ASIC"
            )
            for _, lag in mgFacts["minigraph_portchannels"].items():
                for intf in lag["members"]:
                    dutLagInterfaces.append(mgFacts["minigraph_ptf_indices"][intf])

            testPortIds = set(mgFacts["minigraph_ptf_indices"][port]
                                for port in mgFacts["minigraph_ports"].keys())
            testPortIds -= set(dutLagInterfaces)
            if isMellanoxDevice(duthost):
                # The last port is used for up link from DUT switch
                testPortIds -= {len(mgFacts["minigraph_ptf_indices"]) - 1}
            testPortIds = sorted(testPortIds)
            pytest_require(len(testPortIds) != 0, "Skip test since no ports are available for testing")

            # get current DUT port IPs
            dutPortIps = {}
            if 'backend' in topo:
                intf_map = mgFacts["minigraph_vlan_sub_interfaces"]
            else:
                intf_map = mgFacts["minigraph_interfaces"]

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

            testPortIps = self.__assignTestPortIps(mgFacts)

        elif topo in self.SUPPORTED_T1_TOPOS:
            for iface,addr in dut_asic.get_active_ip_interfaces(tbinfo).items():
                vlan_id = None
                if iface.startswith("Ethernet"):
                    if "." in iface:
                        iface, vlan_id = iface.split(".")
                    portIndex = mgFacts["minigraph_ptf_indices"][iface]
                    portIpMap = {'peer_addr': addr["peer_ipv4"]}
                    if vlan_id is not None:
                        portIpMap['vlan_id'] = vlan_id
                    dutPortIps.update({portIndex: portIpMap})
                elif iface.startswith("PortChannel"):
                    portName = next(
                        iter(mgFacts["minigraph_portchannels"][iface]["members"])
                    )
                    portIndex = mgFacts["minigraph_ptf_indices"][portName]
                    portIpMap = {'peer_addr': addr["peer_ipv4"]}
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
            if vendorAsic in hostvars.keys() and mgFacts["minigraph_hwsku"] in hostvars[vendorAsic]:
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
            if "src_port_ids" in  qosConfigs['qos_params'][dutAsic][dutTopo]:
                src_port_ids = qosConfigs['qos_params'][dutAsic][dutTopo]["src_port_ids"]

            if "dst_port_ids" in  qosConfigs['qos_params'][dutAsic][dutTopo]:
                dst_port_ids = qosConfigs['qos_params'][dutAsic][dutTopo]["dst_port_ids"]
        except KeyError:
            pass

        dualTor = request.config.getoption("--qos_dual_tor")
        if dualTor:
            testPortIds = dualTorPortIndexes

        testPorts = self.__buildTestPorts(request, testPortIds, testPortIps, src_port_ids, dst_port_ids)
        yield {
            "dutInterfaces" : {
                index: port for port, index in mgFacts["minigraph_ptf_indices"].items()
            },
            "testPortIds": testPortIds,
            "testPortIps": testPortIps,
            "testPorts": testPorts,
            "qosConfigs": qosConfigs,
            "dutAsic" : dutAsic,
            "dutTopo" : dutTopo,
            "dutInstance" : duthost,
            "dualTor" : request.config.getoption("--qos_dual_tor"),
            "dualTorScenario" : len(dualtor_ports) != 0
        }

    @pytest.fixture(scope='class')
    def ssh_tunnel_to_syncd_rpc(
        self, duthosts, rand_one_dut_hostname, enum_frontend_asic_index,
        swapSyncd, tbinfo, lower_tor_host
    ):
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[rand_one_dut_hostname]
        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        dut_asic.create_ssh_tunnel_sai_rpc()

        yield

        dut_asic.remove_ssh_tunnel_sai_rpc()

    @pytest.fixture(scope='class')
    def updateIptables(
        self, duthosts, rand_one_dut_hostname, enum_frontend_asic_index, swapSyncd, tbinfo, lower_tor_host
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
            duthost = duthosts[rand_one_dut_hostname]
        dut_asic = duthost.asic_instance(enum_frontend_asic_index)

        ipVersions  = [{"ip_version": "ipv4"}, {"ip_version": "ipv6"}]

        logger.info("Add ip[6]tables rule to drop BGP SYN Packet from peer so that we do not ACK back")
        for ipVersion in ipVersions:
            dut_asic.bgp_drop_rule(state="present", **ipVersion)

        yield

        logger.info("Remove ip[6]tables rule to drop BGP SYN Packet from Peer")
        for ipVersion in ipVersions:
            dut_asic.bgp_drop_rule(state="absent", **ipVersion)

    @pytest.fixture(scope='class')
    def stopServices(
        self, duthosts, rand_one_dut_hostname, enum_frontend_asic_index,
        swapSyncd, enable_container_autorestart, disable_container_autorestart,
        tbinfo, upper_tor_host, lower_tor_host, toggle_all_simulator_ports
    ):
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
            duthost = duthosts[rand_one_dut_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
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
                )
            )
            logger.info("{}ed {}".format(action, service))

        services = [
            {"docker": dut_asic.get_docker_name("lldp"), "service": "lldp-syncd"},
            {"docker": dut_asic.get_docker_name("lldp"), "service": "lldpd"},
            {"docker": dut_asic.get_docker_name("bgp"),  "service": "bgpd"},
            {"docker": dut_asic.get_docker_name("bgp"),  "service": "bgpmon"},
        ]

        feature_list = ['lldp', 'bgp', 'syncd', 'swss']
        if 'dualtor' in tbinfo['topo']['name']:
            disable_container_autorestart(duthost_upper, testcase="test_qos_sai", feature_list=feature_list)

        disable_container_autorestart(duthost, testcase="test_qos_sai", feature_list=feature_list)
        for service in services:
            updateDockerService(duthost, action="stop", **service)

        """ Stop mux container for dual ToR """
        if 'dualtor' in tbinfo['topo']['name']:
            file = "/usr/local/bin/write_standby.py"
            backup_file = "/usr/local/bin/write_standby.py.bkup"
            toggle_all_simulator_ports(LOWER_TOR)

            try:
                duthost.shell("ls %s" % file)
                duthost.shell("sudo cp {} {}".format(file,backup_file))
                duthost.shell("sudo rm {}".format(file))
                duthost.shell("sudo touch {}".format(file))
            except:
                pytest.skip('file {} not found'.format(file))

            duthost_upper.shell('sudo config feature state mux disabled')
            duthost.shell('sudo config feature state mux disabled')

        yield

        for service in services:
            updateDockerService(duthost, action="start", **service)

        """ Start mux conatiner for dual ToR """
        if 'dualtor' in tbinfo['topo']['name']:
           try:
               duthost.shell("ls %s" % backup_file)
               duthost.shell("sudo cp {} {}".format(backup_file,file))
               duthost.shell("sudo chmod +x {}".format(file))
               duthost.shell("sudo rm {}".format(backup_file))
           except:
               pytest.skip('file {} not found'.format(backup_file))

           duthost.shell('sudo config feature state mux enabled')
           duthost_upper.shell('sudo config feature state mux enabled')
           logger.info("Start mux container for dual ToR testbed")

        enable_container_autorestart(duthost, testcase="test_qos_sai", feature_list=feature_list)
        if 'dualtor' in tbinfo['topo']['name']:
            enable_container_autorestart(duthost_upper, testcase="test_qos_sai", feature_list=feature_list)


    @pytest.fixture(autouse=True)
    def updateLoganalyzerExceptions(self, rand_one_dut_hostname, loganalyzer):
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
            loganalyzer[rand_one_dut_hostname].ignore_regex.extend(ignoreRegex)

        yield

    @pytest.fixture(scope='class', autouse=True)
    def disablePacketAging(
        self, duthosts, rand_one_dut_hostname, stopServices
    ):
        """
            disable packet aging on DUT host

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                stopServices (Fxiture): stopServices fixture is required to run prior to disabling packet aging

            Returns:
                None
        """
        duthost = duthosts[rand_one_dut_hostname]

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

    @pytest.fixture(scope='class', autouse=True)
    def dutQosConfig(
        self, duthosts, enum_frontend_asic_index, rand_one_dut_hostname,
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
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[rand_one_dut_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
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
        else:
            qosParams = qosConfigs['qos_params'][dutAsic][dutTopo]
        yield {
            "param": qosParams,
            "portSpeedCableLength": portSpeedCableLength,
        }

    @pytest.fixture(scope='class')
    def releaseAllPorts(
        self, duthosts, rand_one_dut_hostname, ptfhost, dutTestParams,
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
    def handleFdbAging(self, duthosts, rand_one_dut_hostname):
        """
            Disable FDB aging and reenable at the end of tests

            Set fdb_aging_time to 0, update the swss configuration, and restore SWSS configuration afer
            test completes

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        duthost = duthosts[rand_one_dut_hostname]
        fdbAgingTime = 0

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

        result = duthost.find(path=["/tmp"], patterns=["switch.json.*"])
        if result["matched"] > 0:
            src = result["files"][0]["path"]
            duthost.docker_copy_to_all_asics("swss", src, "/etc/swss/config.d/switch.json")
            self.__loadSwssConfig(duthost)
        self.__deleteTmpSwitchConfig(duthost)

    @pytest.fixture(scope='class', autouse=True)
    def populateArpEntries(
        self, duthosts, enum_frontend_asic_index, rand_one_dut_hostname,
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
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[rand_one_dut_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        saiQosTest = None
        if dutTestParams["topo"] in self.SUPPORTED_T0_TOPOS:
            saiQosTest = "sai_qos_tests.ARPpopulate"
        elif dutTestParams["topo"] in self.SUPPORTED_PTF_TOPOS:
            saiQosTest = "sai_qos_tests.ARPpopulatePTF"
        else:
            result = dut_asic.command("arp -n")
            pytest_assert(result["rc"] == 0, "failed to run arp command on {0}".format(duthost.hostname))
            if result["stdout"].find("incomplete") == -1:
                saiQosTest = "sai_qos_tests.ARPpopulate"

        if saiQosTest:
            testParams = dutTestParams["basicParams"]
            testParams.update(dutConfig["testPorts"])
            self.runPtfTest(
                ptfhost, testCase=saiQosTest, testParams=testParams
            )

    @pytest.fixture(scope='class', autouse=True)
    def dut_disable_ipv6(self, duthosts, rand_one_dut_hostname, tbinfo, lower_tor_host):
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[rand_one_dut_hostname]

        duthost.shell("sysctl -w net.ipv6.conf.all.disable_ipv6=1")

        yield
        duthost.shell("sysctl -w net.ipv6.conf.all.disable_ipv6=0")

    @pytest.fixture(scope='class', autouse=True)
    def sharedHeadroomPoolSize(
        self, request, duthosts, enum_frontend_asic_index,
        rand_one_dut_hostname, tbinfo, lower_tor_host
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
            duthost = duthosts[rand_one_dut_hostname]

        yield self.__getSharedHeadroomPoolSize(
            request,
            duthost.asic_instance(enum_frontend_asic_index)
        )

    @pytest.fixture(scope='class', autouse=True)
    def ingressLosslessProfile(
        self, request, duthosts, enum_frontend_asic_index,
        rand_one_dut_hostname, dutConfig, tbinfo, lower_tor_host, dualtor_ports
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
            duthost = duthosts[rand_one_dut_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        srcport = dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]]

        if srcport in dualtor_ports:
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
        self, request, duthosts, enum_frontend_asic_index,
        rand_one_dut_hostname, dutConfig, tbinfo, lower_tor_host
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
            duthost = duthosts[rand_one_dut_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
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
        self, request, duthosts, enum_frontend_asic_index,
        rand_one_dut_hostname, dutConfig, tbinfo, lower_tor_host, dualtor_ports
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
            duthost = duthosts[rand_one_dut_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        srcport = dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]]

        if srcport in dualtor_ports:
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
        self, request, duthosts, enum_frontend_asic_index,
        rand_one_dut_hostname, dutConfig, tbinfo, lower_tor_host, dualtor_ports
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
            duthost = duthosts[rand_one_dut_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        srcport = dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]]

        if srcport in dualtor_ports:
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
            self, duthosts, enum_frontend_asic_index, rand_one_dut_hostname,
            dutConfig, tbinfo, lower_tor_host
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
            duthost = duthosts[rand_one_dut_hostname]

        yield self.__getSchedulerParam(
            duthost.asic_instance(enum_frontend_asic_index),
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            self.TARGET_LOSSLESS_QUEUE_SCHED
        )

    @pytest.fixture(scope='class')
    def lossySchedProfile(
        self, duthosts, enum_frontend_asic_index, rand_one_dut_hostname,
        dutConfig, tbinfo, lower_tor_host
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
            duthost = duthosts[rand_one_dut_hostname]

        yield self.__getSchedulerParam(
            duthost.asic_instance(enum_frontend_asic_index),
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            self.TARGET_LOSSY_QUEUE_SCHED
        )

    @pytest.fixture
    def updateSchedProfile(
        self, duthosts, enum_frontend_asic_index, rand_one_dut_hostname,
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
        if 'dualtor' in tbinfo['topo']['name']:
            duthost = lower_tor_host
        else:
            duthost = duthosts[rand_one_dut_hostname]

        def updateRedisSchedParam(schedParam):
            """
                Helper function to updates lossless/lossy scheduler profiles

                Args:
                    schedParam (dict): Scheduler params to be set

                Returns:
                    None
            """
            duthost.asic_instance(enum_frontend_asic_index).run_redis_cmd(
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
        self, duthosts, enum_frontend_asic_index, rand_one_dut_hostname, tbinfo, lower_tor_host
    ):
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
            duthost = duthosts[rand_one_dut_hostname]

        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        dut_asic.command("counterpoll watermark enable")
        dut_asic.command("counterpoll queue enable")
        dut_asic.command("sleep 70")
        dut_asic.command("counterpoll watermark disable")
        dut_asic.command("counterpoll queue disable")
