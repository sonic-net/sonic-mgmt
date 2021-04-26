import ipaddress
import logging
import pytest
import re
import yaml

from tests.common.fixtures.ptfhost_utils import ptf_portmap_file    # lgtm[py/unused-import]
from tests.common.helpers.assertions import pytest_assert
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice
from tests.common.system_utils import docker

logger = logging.getLogger(__name__)

class QosSaiBase:
    """
        QosSaiBase contains collection of pytest fixtures that ready the tesbed for QoS SAI test cases.
    """
    SUPPORTED_T0_TOPOS = ["t0", "t0-64", "t0-116"]
    SUPPORTED_T1_TOPOS = {"t1-lag", "t1-64-lag"}
    SUPPORTED_PTF_TOPOS = ['ptf32', 'ptf64']
    SUPPORTED_ASIC_LIST = ["td2", "th", "th2", "spc1", "spc2", "spc3"]
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

    def __computeBufferThreshold(self, dut_asic, bufferProfile):
        """
            Computes buffer threshold for dynamic threshold profiles

            Args:
                dut_asic (SonicAsic): Device ASIC Under Test (DUT)
                bufferProfile (dict, inout): Map of puffer profile attributes

            Returns:
                Updates bufferProfile with computed buffer threshold
        """
        db = "0" if self.isBufferInApplDb(dut_asic) else "4"
        pool = bufferProfile["pool"].encode("utf-8").translate(None, "[]")
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
        if self.isBufferInApplDb(dut_asic):
            bufferPoolName = bufferProfile["pool"].encode("utf-8").translate(
                None, "[]").replace("BUFFER_POOL_TABLE:",''
            )
        else:
            bufferPoolName = bufferProfile["pool"].encode("utf-8").translate(
                None, "[]").replace("BUFFER_POOL|",''
            )

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

    def __getBufferProfile(self, request, dut_asic, table, port, priorityGroup):
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
        else:
            db = "4"
            keystr = "{0}|{1}|{2}".format(table, port, priorityGroup)
        bufferProfileName = dut_asic.run_redis_cmd(
            argv = ["redis-cli", "-n", db, "HGET", keystr, "profile"]
        )[0].encode("utf-8").translate(None, "[]")

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
        wredProfileName = dut_asic.run_redis_cmd(
            argv = [
                "redis-cli", "-n", "4", "HGET",
                "{0}|{1}|{2}".format(table, port, self.TARGET_QUEUE_WRED),
                "wred_profile"
            ]
        )[0].encode("utf-8").translate(None, "[]")

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
        schedProfile = dut_asic.run_redis_cmd(
            argv = [
                "redis-cli", "-n", "4", "HGET",
                "QUEUE|{0}|{1}".format(port, queue), "scheduler"
            ]
        )[0].encode("utf-8").translate(None, "[]")

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

            for i in range(len(testVlanMembers)):
                portIndex = mgFacts["minigraph_ptf_indices"][testVlanMembers[i]]
                dutPortIps.update({portIndex: str(testVlanIp + portIndex + 1)})

        return dutPortIps

    def __buildTestPorts(self, request, testPortIds, testPortIps):
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
            if len(testPortIds) >= 4:
                dstPorts = [0, 2, 3]
            elif len(testPortIds) == 3:
                dstPorts = [0, 2, 2]
            else:
                dstPorts = [0, 0, 0]

        if srcPorts is None:
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
        return {
            "dst_port_id": testPortIds[dstPorts[0]],
            "dst_port_ip": testPortIps[testPortIds[dstPorts[0]]],
            "dst_port_2_id": testPortIds[dstPorts[1]],
            "dst_port_2_ip": testPortIps[testPortIds[dstPorts[1]]],
            'dst_port_3_id': testPortIds[dstPorts[2]],
            "dst_port_3_ip": testPortIps[testPortIds[dstPorts[2]]],
            "src_port_id": testPortIds[srcPorts[0]],
            "src_port_ip": testPortIps[testPortIds[srcPorts[0]]],
        }

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


    @pytest.fixture(scope='class')
    def swapSyncd(self, request, duthosts, rand_one_dut_hostname, creds):
        """
            Swap syncd on DUT host

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        duthost = duthosts[rand_one_dut_hostname]
        swapSyncd = request.config.getoption("--qos_swap_syncd")
        try:
            if swapSyncd:
                docker.swap_syncd(duthost, creds)

            yield
        finally:
            if swapSyncd:
                docker.restore_default_syncd(duthost, creds)

    @pytest.fixture(scope='class', autouse=True)
    def dutConfig(
        self, request, duthosts, rand_one_dut_hostname, tbinfo,
        enum_frontend_asic_index
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
        duthost = duthosts[rand_one_dut_hostname]
        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        dutLagInterfaces = []
        dutPortIps = {}
        testPortIps = {}

        mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
        topo = tbinfo["topo"]["name"]

        testPortIds = []
        # LAG ports in T1 TOPO need to be removed in Mellanox devices
        if topo in self.SUPPORTED_T0_TOPOS or isMellanoxDevice(duthost):
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

            # get current DUT port IPs
            dutPortIps = {}
            for portConfig in mgFacts["minigraph_interfaces"]:
                if ipaddress.ip_interface(portConfig['peer_addr']).ip.version == 4:
                    portIndex = mgFacts["minigraph_ptf_indices"][portConfig["attachto"]]
                    if portIndex in testPortIds:
                        dutPortIps.update({portIndex: portConfig["peer_addr"]})

            testPortIps = self.__assignTestPortIps(mgFacts)

        elif topo in self.SUPPORTED_T1_TOPOS:
            for iface,addr in dut_asic.get_active_ip_interfaces().items():
                if iface.startswith("Ethernet"):
                    portIndex = mgFacts["minigraph_ptf_indices"][iface]
                    dutPortIps.update({portIndex: addr["peer_ipv4"]})
                elif iface.startswith("PortChannel"):
                    portName = next(
                        iter(mgFacts["minigraph_portchannels"][iface]["members"])
                    )
                    portIndex = mgFacts["minigraph_ptf_indices"][portName]
                    dutPortIps.update({portIndex: addr["peer_ipv4"]})

            testPortIds = sorted(dutPortIps.keys())
        else:
            raise Exception("Unsupported testbed type - {}".format(topo))

        # restore currently assigned IPs
        testPortIps.update(dutPortIps)

        testPorts = self.__buildTestPorts(request, testPortIds, testPortIps)
        yield {
            "dutInterfaces" : {
                index: port for port, index in mgFacts["minigraph_ptf_indices"].items()
            },
            "testPortIds": testPortIds,
            "testPortIps": testPortIps,
            "testPorts": testPorts,
        }

    @pytest.fixture(scope='class')
    def ssh_tunnel_to_syncd_rpc(
        self, duthosts, rand_one_dut_hostname, enum_frontend_asic_index,
        swapSyncd
    ):
        duthost = duthosts[rand_one_dut_hostname]
        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        dut_asic.create_ssh_tunnel_sai_rpc()

        yield

        dut_asic.remove_ssh_tunnel_sai_rpc()

    @pytest.fixture(scope='class')
    def updateIptables(
        self, duthosts, rand_one_dut_hostname, enum_frontend_asic_index, swapSyncd
    ):
        """
            Update iptables on DUT host with drop rule for BGP SYNC packets

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                swapSyncd (Fixture): swapSyncd fixture is required to run prior to updating iptables

            Returns:
                None
        """
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
        swapSyncd, enable_container_autorestart, disable_container_autorestart
    ):
        """
            Stop services (lldp-syncs, lldpd, bgpd) on DUT host prior to test start

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                swapSyncd (Fxiture): swapSyncd fixture is required to run prior to stopping services

            Returns:
                None
        """
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
        disable_container_autorestart(duthost, testcase="test_qos_sai", feature_list=feature_list)
        for service in services:
            updateDockerService(duthost, action="stop", **service)

        yield

        enable_container_autorestart(duthost, testcase="test_qos_sai", feature_list=feature_list)
        for service in services:
            updateDockerService(duthost, action="start", **service)

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
        tbinfo
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
        duthost = duthosts[rand_one_dut_hostname]
        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
        pytest_assert("minigraph_hwsku" in mgFacts, "Could not find DUT SKU")

        profileName = ingressLosslessProfile["profileName"]
        if self.isBufferInApplDb(dut_asic):
            profile_pattern = "^BUFFER_PROFILE_TABLE\:pg_lossless_(.*)_profile$"
        else:
            profile_pattern = "^BUFFER_PROFILE\|pg_lossless_(.*)_profile"
        m = re.search(profile_pattern, profileName)
        pytest_assert(m.group(1), "Cannot find port speed/cable length")

        portSpeedCableLength = m.group(1)

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

        if isMellanoxDevice(duthost):
            current_file_dir = os.path.dirname(os.path.realpath(__file__))
            sub_folder_dir = os.path.join(current_file_dir, "files/mellanox/")
            if sub_folder_dir not in sys.path:
                sys.path.append(sub_folder_dir)
            import qos_param_generator
            qpm = qos_param_generator.QosParamMellanox(qosConfigs['qos_params']['mellanox'], dutAsic,
                                                       portSpeedCableLength,
                                                       dutConfig,
                                                       ingressLosslessProfile,
                                                       ingressLossyProfile,
                                                       egressLosslessProfile,
                                                       egressLossyProfile,
                                                       sharedHeadroomPoolSize
            )
            qosParams = qpm.run()
        else:
            qosParams = qosConfigs['qos_params'][dutAsic]

        yield {
            "param": qosParams,
            "portSpeedCableLength": portSpeedCableLength,
        }

    @pytest.fixture(scope='class', autouse=True)
    def dutTestParams(self, duthosts, rand_one_dut_hostname, tbinfo, ptf_portmap_file):
        """
            Prepares DUT host test params

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                tbinfo (Fixture, dict): Map containing testbed information
                ptfPortMapFile (Fxiture, str): filename residing on PTF host and contains port maps information

            Returns:
                dutTestParams (dict): DUT host test params
        """
        duthost = duthosts[rand_one_dut_hostname]
        mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
        topo = tbinfo["topo"]["name"]

        yield {
            "topo": topo,
            "hwsku": mgFacts["minigraph_hwsku"],
            "basicParams": {
                "router_mac": '' if topo in self.SUPPORTED_T0_TOPOS else duthost.facts["router_mac"],
                "server": duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host'],
                "port_map_file": ptf_portmap_file,
                "sonic_asic_type": duthost.facts['asic_type'],
            }
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

    @pytest.fixture(scope='class', autouse=True)
    def populateArpEntries(
        self, duthosts, enum_frontend_asic_index, rand_one_dut_hostname,
        ptfhost, dutTestParams, dutConfig, releaseAllPorts,
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
    def sharedHeadroomPoolSize(
        self, request, duthosts, enum_frontend_asic_index,
        rand_one_dut_hostname
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
        duthost = duthosts[rand_one_dut_hostname]
        yield self.__getSharedHeadroomPoolSize(
            request,
            duthost.asic_instance(enum_frontend_asic_index)
        )

    @pytest.fixture(scope='class', autouse=True)
    def ingressLosslessProfile(
        self, request, duthosts, enum_frontend_asic_index,
        rand_one_dut_hostname, dutConfig
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
        duthost = duthosts[rand_one_dut_hostname]
        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        yield self.__getBufferProfile(
            request,
            dut_asic,
            "BUFFER_PG_TABLE" if self.isBufferInApplDb(dut_asic) else "BUFFER_PG",
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            "3-4"
        )

    @pytest.fixture(scope='class', autouse=True)
    def ingressLossyProfile(
        self, request, duthosts, enum_frontend_asic_index,
        rand_one_dut_hostname, dutConfig
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
        duthost = duthosts[rand_one_dut_hostname]
        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        yield self.__getBufferProfile(
            request,
            dut_asic,
            "BUFFER_PG_TABLE" if self.isBufferInApplDb(dut_asic) else "BUFFER_PG",
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            "0"
        )

    @pytest.fixture(scope='class', autouse=True)
    def egressLosslessProfile(
        self, request, duthosts, enum_frontend_asic_index,
        rand_one_dut_hostname, dutConfig
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
        duthost = duthosts[rand_one_dut_hostname]
        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        yield self.__getBufferProfile(
            request,
            dut_asic,
            "BUFFER_QUEUE_TABLE" if self.isBufferInApplDb(dut_asic) else "BUFFER_QUEUE",
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            "3-4"
        )

    @pytest.fixture(scope='class', autouse=True)
    def egressLossyProfile(
        self, request, duthosts, enum_frontend_asic_index,
        rand_one_dut_hostname, dutConfig
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
        duthost = duthosts[rand_one_dut_hostname]
        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        yield self.__getBufferProfile(
            request,
            dut_asic,
            "BUFFER_QUEUE_TABLE" if self.isBufferInApplDb(dut_asic) else "BUFFER_QUEUE",
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            "0-2"
        )

    @pytest.fixture(scope='class')
    def losslessSchedProfile(
            self, duthosts, enum_frontend_asic_index, rand_one_dut_hostname,
            dutConfig
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
        duthost = duthosts[rand_one_dut_hostname]
        yield self.__getSchedulerParam(
            duthost.asic_instance(enum_frontend_asic_index),
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            self.TARGET_LOSSLESS_QUEUE_SCHED
        )

    @pytest.fixture(scope='class')
    def lossySchedProfile(
        self, duthosts, enum_frontend_asic_index, rand_one_dut_hostname,
        dutConfig
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
        duthost = duthosts[rand_one_dut_hostname]
        yield self.__getSchedulerParam(
            duthost.asic_instance(enum_frontend_asic_index),
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            self.TARGET_LOSSY_QUEUE_SCHED
        )

    @pytest.fixture
    def updateSchedProfile(
        self, duthosts, enum_frontend_asic_index, rand_one_dut_hostname,
        dutQosConfig, losslessSchedProfile, lossySchedProfile
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
        self, duthosts, enum_frontend_asic_index, rand_one_dut_hostname
    ):
        """
            Reset queue watermark

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        duthost = duthosts[rand_one_dut_hostname]
        dut_asic = duthost.asic_instance(enum_frontend_asic_index)
        dut_asic.command("counterpoll watermark enable")
        dut_asic.command("sleep 20")
        dut_asic.command("counterpoll watermark disable")
