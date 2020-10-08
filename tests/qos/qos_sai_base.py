import ipaddress
import logging
import pytest
import re
import yaml

from natsort import natsorted
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice
from tests.common.system_utils import docker

logger = logging.getLogger(__name__)

class QosSaiBase:
    """
        QosSaiBase contains collection of pytest fixtures that ready the tesbed for QoS SAI test cases.
    """
    SUPPORTED_T0_TOPOS = ["t0", "t0-64", "t0-116"]
    SUPPORTED_PTF_TOPOS = ['ptf32', 'ptf64']
    SUPPORTED_ASIC_LIST = ["td2", "th", "th2", "spc1", "spc2", "spc3"]
    TARGET_QUEUE_WRED = 3
    TARGET_LOSSY_QUEUE_SCHED = 0
    TARGET_LOSSLESS_QUEUE_SCHED = 3
    DEFAULT_PORT_INDEX_TO_ALIAS_MAP_FILE = "/tmp/default_interface_to_front_map.ini"

    def __runRedisCommandOrAssert(self, duthost, argv=[]):
        """
            Runs Redis command on DUT host.

            The method asserts if the command fails.

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                argv (list): List of commands to run on duthost

            Returns:
                stdout (list): List of stdout lines spewed by the invoked command
        """
        result = duthost.shell(argv=argv)
        assert result["rc"] == 0, \
            "Failed to run Redis command '{0}' with error '{1}'".format(" ".join(argv), result["stderr"])

        return result["stdout_lines"]

    def __computeBufferThreshold(self, duthost, bufferProfile):
        """
            Computes buffer threshold for dynamic threshold profiles

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                bufferProfile (dict, inout): Map of puffer profile attributes

            Returns:
                Updates bufferProfile with computed buffer threshold
        """
        pool = bufferProfile["pool"].encode("utf-8").translate(None, "[]")
        bufferSize = int(self.__runRedisCommandOrAssert(
            duthost,
            argv = ["redis-cli", "-n", "4", "HGET", pool, "size"]
        )[0])
        bufferScale = 2**float(bufferProfile["dynamic_th"])
        bufferScale /= (bufferScale + 1)
        bufferProfile.update({"static_th": int(bufferProfile["size"]) + int(bufferScale * bufferSize)})

    def __updateVoidRoidParams(self, duthost, bufferProfile):
        """
            Updates buffer profile with VOID/ROID params

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                bufferProfile (dict, inout): Map of puffer profile attributes

            Returns:
                Updates bufferProfile with VOID/ROID obtained from Redis db
        """
        bufferPoolName = bufferProfile["pool"].encode("utf-8").translate(None, "[]").replace("BUFFER_POOL|",'')

        bufferPoolVoid = self.__runRedisCommandOrAssert(
            duthost,
            argv = ["redis-cli", "-n", "2", "HGET", "COUNTERS_BUFFER_POOL_NAME_MAP", bufferPoolName]
        )[0].encode("utf-8")
        bufferProfile.update({"bufferPoolVoid": bufferPoolVoid})

        bufferPoolRoid = self.__runRedisCommandOrAssert(
            duthost,
            argv = ["redis-cli", "-n", "1", "HGET", "VIDTORID", bufferPoolVoid]
        )[0].encode("utf-8").replace("oid:",'')
        bufferProfile.update({"bufferPoolRoid": bufferPoolRoid})

    def __getBufferProfile(self, request, duthost, table, port, priorityGroup):
        """
            Get buffer profile attribute from Redis db

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                table (str): Redis table name
                port (str): DUT port alias
                priorityGroup (str): QoS priority group

            Returns:
                bufferProfile (dict): Map of buffer profile attributes
        """
        bufferProfileName = self.__runRedisCommandOrAssert(
            duthost,
            argv = ["redis-cli", "-n", "4", "HGET", "{0}|{1}|{2}".format(table, port, priorityGroup), "profile"]
        )[0].encode("utf-8").translate(None, "[]")

        result = self.__runRedisCommandOrAssert(
            duthost,
            argv = ["redis-cli", "-n", "4", "HGETALL", bufferProfileName]
        )
        it = iter(result)
        bufferProfile = dict(zip(it, it))
        bufferProfile.update({"profileName": bufferProfileName})

        # Update profile static threshold value if  profile threshold is dynamic
        if "dynamic_th" in bufferProfile.keys():
            self.__computeBufferThreshold(duthost, bufferProfile)

        if "pg_lossless" in bufferProfileName:
            assert "xon" in bufferProfile.keys() and "xoff" in bufferProfile.keys(), \
                "Could not find xon and/or xoff values for profile '{0}'".format(bufferProfileName)

        disableTest = request.config.getoption("--disable_test")
        if not disableTest:
            self.__updateVoidRoidParams(duthost, bufferProfile)

        return bufferProfile

    def __getEcnWredParam(self, duthost, table, port):
        """
            Get ECN/WRED parameters from Redis db

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                table (str): Redis table name
                port (str): DUT port alias

            Returns:
                wredProfile (dict): Map of ECN/WRED attributes
        """
        wredProfileName = self.__runRedisCommandOrAssert(
            duthost,
            argv = ["redis-cli", "-n", "4", "HGET", "{0}|{1}|{2}".format(table, port, self.TARGET_QUEUE_WRED), "wred_profile"]
        )[0].encode("utf-8").translate(None, "[]")

        result = self.__runRedisCommandOrAssert(
            duthost,
            argv = ["redis-cli", "-n", "4", "HGETALL", wredProfileName]
        )
        it = iter(result)
        wredProfile = dict(zip(it, it))

        return wredProfile

    def __getWatermarkStatus(self, duthost):
        """
            Get watermark status from Redis db

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                watermarkStatus (str): Watermark status
        """
        watermarkStatus = self.__runRedisCommandOrAssert(
            duthost,
            argv = ["redis-cli", "-n", "4", "HGET", "FLEX_COUNTER_TABLE|QUEUE_WATERMARK", "FLEX_COUNTER_STATUS"]
        )[0].encode("utf-8")

        return watermarkStatus

    def __getSchedulerParam(self, duthost, port, queue):
        """
            Get scheduler parameters from Redis db

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                port (str): DUT port alias
                queue (str): QoS queue

            Returns:
                SchedulerParam (dict): Map of scheduler parameters
        """
        schedProfile = self.__runRedisCommandOrAssert(
            duthost,
            argv = ["redis-cli", "-n", "4", "HGET", "QUEUE|{0}|{1}".format(port, queue), "scheduler"]
        )[0].encode("utf-8").translate(None, "[]")

        schedWeight = self.__runRedisCommandOrAssert(
            duthost,
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
            assert testVlanIp, "Failed to obtain vlan IP"

            for i in range(len(testVlanMembers)):
                portIndex = mgFacts["minigraph_port_indices"][testVlanMembers[i]]
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

        assert len(set(dstPorts).intersection(set(srcPorts))) == 0, \
            "Duplicate destination and source ports '{0}'".format(set(dstPorts).intersection(set(srcPorts)))

        assert len(dstPorts) == 3 and len(srcPorts) == 1, \
            "Invalid number of ports provided, qos_dst_ports:{0}, qos_src_ports:{1}".format(len(dstPorts), len(srcPorts))

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
        assert ptfhost.shell(
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
        )["rc"] == 0, "Failed when running test '{0}'".format(testCase)

    @pytest.fixture(scope='class')
    def swapSyncd(self, request, duthost, creds):
        """
            Swap syncd on DUT host

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        swapSyncd = request.config.getoption("--qos_swap_syncd")
        if swapSyncd:
            docker.swap_syncd(duthost, creds)

        yield

        if swapSyncd:
            docker.restore_default_syncd(duthost, creds)

    @pytest.fixture(scope='class', autouse=True)
    def dutConfig(self, request, duthost):
        """
            Build DUT host config pertaining to QoS SAI tests

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                dutConfig (dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs, and
                    test ports
        """
        dutLagInterfaces = []
        mgFacts = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]

        for _, lag in mgFacts["minigraph_portchannels"].items():
            for intf in lag["members"]:
                dutLagInterfaces.append(mgFacts["minigraph_port_indices"][intf])

        testPortIds = set(mgFacts["minigraph_port_indices"][port] for port in mgFacts["minigraph_ports"].keys())
        testPortIds -= set(dutLagInterfaces)
        if isMellanoxDevice(duthost):
            # The last port is used for up link from DUT switch
            testPortIds -= {len(mgFacts["minigraph_port_indices"]) - 1}
        testPortIds = sorted(testPortIds)

        # get current DUT port IPs
        dutPortIps = {}
        for portConfig in mgFacts["minigraph_interfaces"]:
            if ipaddress.ip_interface(portConfig['peer_addr']).ip.version == 4:
                portIndex = mgFacts["minigraph_port_indices"][portConfig["attachto"]]
                if portIndex in testPortIds:
                    dutPortIps.update({portIndex: portConfig["peer_addr"]})

        testPortIps = self.__assignTestPortIps(mgFacts)
        # restore currently assigned IPs
        testPortIps.update(dutPortIps)

        testPorts = self.__buildTestPorts(request, testPortIds, testPortIps)
        yield {
            "dutInterfaces" : {index: port for port, index in mgFacts["minigraph_port_indices"].items()},
            "testPortIds": testPortIds,
            "testPortIps": testPortIps,
            "testPorts": testPorts,
        }

    @pytest.fixture(scope='class')
    def updateIptables(self, duthost, swapSyncd):
        """
            Update iptables on DUT host with drop rule for BGP SYNC packets

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                swapSyncd (Fixture): swapSyncd fixture is required to run prior to updating iptables

            Returns:
                None
        """
        def updateIptablesDropRule(duthost, ipVersion,  state='present'):
            duthost.iptables(
                ip_version=ipVersion,
                action="insert",
                rule_num="1",
                chain="INPUT",
                jump="DROP",
                protocol="tcp",
                destination_port="bgp",
                state=state
            )


        ipVersions  = [{"ipVersion": "ipv4"}, {"ipVersion": "ipv6"}]

        logger.info("Add ip[6]tables rule to drop BGP SYN Packet from peer so that we do not ACK back")
        for ipVersion in ipVersions:
            updateIptablesDropRule(duthost, state="present", **ipVersion)

        yield

        logger.info("Remove ip[6]tables rule to drop BGP SYN Packet from Peer")
        for ipVersion in ipVersions:
            updateIptablesDropRule(duthost, state="absent", **ipVersion)

    @pytest.fixture(scope='class')
    def stopServices(self, duthost, swapSyncd):
        """
            Stop services (lldp-syncs, lldpd, bgpd) on DUT host prior to test start

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                swapSyncd (Fxiture): swapSyncd fixture is required to run prior to stopping services

            Returns:
                None
        """
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

        services = [
            {"docker": "lldp", "service": "lldp-syncd"},
            {"docker": "lldp", "service": "lldpd"},
            {"docker": "bgp",  "service": "bgpd"},
        ]

        logger.info("Stop lldp, lldp-syncd, and bgpd services")
        for service in services:
            updateDockerService(duthost, action="stop", **service)

        yield

        logger.info("Start lldp, lldp-syncd, and bgpd services")
        for service in services:
            updateDockerService(duthost, action="start", **service)

    @pytest.fixture(autouse=True)
    def updateLoganalyzerExceptions(self, duthost, loganalyzer):
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
                ".*ERR monit.*'lldpd_monitor' process is not running",
                ".*ERR monit.*'lldp_syncd' process is not running",
                ".*ERR monit.*'bgpd' process is not running",
                ".*ERR monit.*'bgpcfgd' process is not running",
                ".*ERR syncd#syncd:.*brcm_sai_set_switch_attribute:.*updating switch mac addr failed.*"
            ]
            loganalyzer.ignore_regex.extend(ignoreRegex)

        yield

    @pytest.fixture(scope='class', autouse=True)
    def disablePacketAging(self, duthost, stopServices):
        """
            disable packet aging on DUT host

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                stopServices (Fxiture): stopServices fixture is required to run prior to disabling packet aging

            Returns:
                None
        """
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
    def dutQosConfig(self, duthost, ingressLosslessProfile, ingressLossyProfile, egressLosslessProfile, egressLossyProfile):
        """
            Prepares DUT host QoS configuration

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ingressLosslessProfile (Fxiture): ingressLosslessProfile fixture is required to run prior to collecting
                    QoS configuration

            Returns:
                QoSConfig (dict): Map containing DUT host QoS configuration
        """
        mgFacts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
        assert "minigraph_hwsku" in mgFacts, "Could not find DUT SKU"

        profileName = ingressLosslessProfile["profileName"]
        m = re.search("^BUFFER_PROFILE\|pg_lossless_(.*)_profile$", profileName)
        assert m.group(1), "Cannot find port speed/cable length"

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

        assert dutAsic, "Cannot identify DUT ASIC type"

        if isMellanoxDevice(duthost):
            current_file_dir = os.path.dirname(os.path.realpath(__file__))
            sub_folder_dir = os.path.join(current_file_dir, "files/mellanox/")
            if sub_folder_dir not in sys.path:
                sys.path.append(sub_folder_dir)
            import qos_param_generator
            qpm = qos_param_generator.QosParamMellanox(qosConfigs['qos_params']['mellanox'], dutAsic,
                                                      portSpeedCableLength,
                                                      ingressLosslessProfile,
                                                      ingressLossyProfile,
                                                      egressLosslessProfile,
                                                      egressLossyProfile)
            qosParams = qpm.run()
        else:
            qosParams = qosConfigs['qos_params'][dutAsic]

        yield {
            "param": qosParams,
            "portSpeedCableLength": portSpeedCableLength,
        }

    @pytest.fixture(scope='class')
    def ptfPortMapFile(self, duthost, ptfhost):
        """
            Prepare and copys port map file to PTF host

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                filename (str): returns the filename copied to PTF host
        """
        intfInfo = duthost.show_interface(command = "status")['ansible_facts']['int_status']
        portList = natsorted([port for port in intfInfo if port.startswith('Ethernet') and intfInfo[port]['speed'] != '10G'])
        portMapFile = self.DEFAULT_PORT_INDEX_TO_ALIAS_MAP_FILE
        with open(portMapFile, 'w') as file:
            file.write("# ptf host interface @ switch front port name\n")
            file.writelines(
                map(
                     lambda (index, port): "{0}@{1}\n".format(index, port),
                     enumerate(portList)
                    )
                )

        ptfhost.copy(src=portMapFile, dest="/root/")

        yield "/root/{}".format(portMapFile.split('/')[-1])

    @pytest.fixture(scope='class', autouse=True)
    def dutTestParams(self, duthost, tbinfo, ptfPortMapFile):
        """
            Prepares DUT host test params

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                tbinfo (Fixture, dict): Map containing testbed information
                ptfPortMapFile (Fxiture, str): filename residing on PTF host and contains port maps information

            Returns:
                dutTestParams (dict): DUT host test params
        """
        dutFacts = duthost.setup()['ansible_facts']
        mgFacts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
        topo = tbinfo["topo"]["name"]

        yield {
            "topo": topo,
            "hwsku": mgFacts["minigraph_hwsku"],
            "basicParams": {
                "router_mac": '' if topo in self.SUPPORTED_T0_TOPOS else dutFacts['ansible_Ethernet0']['macaddress'],
                "server": duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host'],
                "port_map_file": ptfPortMapFile,
                "sonic_asic_type": duthost.facts['asic_type'],
            }
        }

    @pytest.fixture(scope='class')
    def releaseAllPorts(self, ptfhost, dutTestParams, updateIptables):
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
        self.runPtfTest(ptfhost, testCase="sai_qos_tests.ReleaseAllPorts", testParams=dutTestParams["basicParams"])

    @pytest.fixture(scope='class', autouse=True)
    def populateArpEntries(self, duthost, ptfhost, dutTestParams, dutConfig, releaseAllPorts):
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
        saiQosTest = None
        if dutTestParams["topo"] in self.SUPPORTED_T0_TOPOS:
            saiQosTest = "sai_qos_tests.ARPpopulate"
        elif dutTestParams["topo"] in self.SUPPORTED_PTF_TOPOS:
            saiQosTest = "sai_qos_tests.ARPpopulatePTF"
        else:
            result = duthost.command(argv = ["arp", "-n"])
            assert result["rc"] == 0, "failed to run arp command on {0}".format(duthost.hostname)
            if result["stdout"].find("incomplete") == -1:
                saiQosTest = "sai_qos_tests.ARPpopulate"

        if saiQosTest:
            testParams = dutTestParams["basicParams"]
            testParams.update(dutConfig["testPorts"])
            self.runPtfTest(ptfhost, testCase=saiQosTest, testParams=testParams)

    @pytest.fixture(scope='class', autouse=True)
    def ingressLosslessProfile(self, request, duthost, dutConfig):
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
        yield self.__getBufferProfile(
            request,
            duthost,
            "BUFFER_PG",
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            "3-4"
        )

    @pytest.fixture(scope='class', autouse=True)
    def ingressLossyProfile(self, request, duthost, dutConfig):
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
        yield self.__getBufferProfile(
            request,
            duthost,
            "BUFFER_PG",
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            "0"
        )

    @pytest.fixture(scope='class', autouse=True)
    def egressLosslessProfile(self, request, duthost, dutConfig):
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
        yield self.__getBufferProfile(
            request,
            duthost,
            "BUFFER_QUEUE",
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            "3-4"
        )

    @pytest.fixture(scope='class', autouse=True)
    def egressLossyProfile(self, request, duthost, dutConfig):
        """
            Retreives egress lossy profile

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports

            Returns:
                egressLossyProfile (dict): Map of egress lossy buffer profile attributes
        """
        yield self.__getBufferProfile(
            request,
            duthost,
            "BUFFER_QUEUE",
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            "0-2"
        )

    @pytest.fixture(scope='class')
    def losslessSchedProfile(self, duthost, dutConfig):
        """
            Retreives lossless scheduler profile

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports

            Returns:
                losslessSchedProfile (dict): Map of scheduler parameters
        """
        yield self.__getSchedulerParam(
            duthost,
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            self.TARGET_LOSSLESS_QUEUE_SCHED
        )

    @pytest.fixture(scope='class')
    def lossySchedProfile(self, duthost, dutConfig):
        """
            Retreives lossy scheduler profile

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports

            Returns:
                lossySchedProfile (dict): Map of scheduler parameters
        """
        yield self.__getSchedulerParam(
            duthost,
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            self.TARGET_LOSSY_QUEUE_SCHED
        )

    @pytest.fixture
    def updateSchedProfile(self, duthost, dutQosConfig, losslessSchedProfile, lossySchedProfile):
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
            self.__runRedisCommandOrAssert(
                duthost,
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
            {"profile": lossySchedProfile["schedProfile"], "qosConfig": dutQosConfig["param"]["wrr_chg"]["lossy_weight"]},
            {"profile": losslessSchedProfile["schedProfile"], "qosConfig": dutQosConfig["param"]["wrr_chg"]["lossless_weight"]},
        ]

        for schedParam in wrrSchedParams:
            updateRedisSchedParam(schedParam)

        yield

        schedProfileParams = [
            {"profile": lossySchedProfile["schedProfile"], "qosConfig": lossySchedProfile["schedWeight"]},
            {"profile": losslessSchedProfile["schedProfile"], "qosConfig": losslessSchedProfile["schedWeight"]},
        ]

        for schedParam in schedProfileParams:
            updateRedisSchedParam(schedParam)

    @pytest.fixture
    def resetWatermark(self, duthost):
        """
            Reset queue watermark

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        duthost.shell("counterpoll watermark enable")
        duthost.shell("sleep 20")
        duthost.shell("counterpoll watermark disable")
