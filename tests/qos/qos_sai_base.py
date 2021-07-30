import ipaddress
import json
import logging
import pytest
import re
import yaml

from tests.common.fixtures.ptfhost_utils import ptf_portmap_file    # lgtm[py/unused-import]
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

class QosBase:
    """
    Common APIs
    """
    SUPPORTED_T0_TOPOS = ["t0", "t0-64", "t0-116", "t0-35", "dualtor-56", "dualtor"]
    SUPPORTED_T1_TOPOS = {"t1-lag", "t1-64-lag"}
    SUPPORTED_PTF_TOPOS = ['ptf32', 'ptf64']
    SUPPORTED_ASIC_LIST = ["td2", "th", "th2", "spc1", "spc2", "spc3", "td3"]

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
                "sonic_version": duthost.os_version
            }
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
        return {
            "dst_port_id": dstPorts[0] if dst_port_ids else testPortIds[dstPorts[0]],
            "dst_port_ip": testPortIps[dstPorts[0] if dst_port_ids else testPortIds[dstPorts[0]]],
            "dst_port_2_id": dstPorts[1] if dst_port_ids else testPortIds[dstPorts[1]],
            "dst_port_2_ip": testPortIps[dstPorts[1] if dst_port_ids else testPortIds[dstPorts[1]]],
            'dst_port_3_id': dstPorts[2] if dst_port_ids else testPortIds[dstPorts[2]],
            "dst_port_3_ip": testPortIps[dstPorts[2] if dst_port_ids else testPortIds[dstPorts[2]]],
            "src_port_id": srcPorts[0] if src_port_ids else testPortIds[srcPorts[0]],
            "src_port_ip": testPortIps[srcPorts[0] if src_port_ids else testPortIds[srcPorts[0]]],
        }

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
            pytest_require(len(testPortIds) != 0, "Skip test since no ports are available for testing")

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
            pytest.skip("Unsupported testbed type - {}".format(topo))

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
            "dutTopo" : dutTopo
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
                                                       sharedHeadroomPoolSize
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
            duthost.os_version,
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
            duthost.os_version,
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
            duthost.os_version,
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
            duthost.os_version,
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


class QosSaiBaseMasic(QosBase):

    def build_port_ips(self, asic_index, ifaces, mg_facts):
        """
        Returns list of port index and IP address for a given ASIC
        """

        dut_port_ips = dict()

        for iface, addr in ifaces.items():
            if iface.startswith("Ethernet"):
                portIndex = mg_facts["minigraph_ptf_indices"][iface]
            elif iface.startswith("PortChannel"):
                portName = mg_facts["minigraph_portchannels"][iface]["members"][0]
                portIndex = mg_facts["minigraph_ptf_indices"][portName]

            dut_port_ips.update({
                portIndex: {
                    "ipv4": addr["peer_ipv4"],
                    "bgp_neighbor": addr["bgp_neighbor"]
                }
            })

        return {asic_index: dut_port_ips}

    def get_backend_ip_ifs(self, duthost, frontend_asic):
        """
        On a frontend ASIC return a dict of interfaces with
        backend ASIC names
        """
        pytest_assert(
            frontend_asic in duthost.get_frontend_asic_ids(),
            "{} is not frontend ASIC ID".format(frontend_asic)
        )

        ip_ifs = duthost.asic_instance(
            frontend_asic
        ).show_ip_interface()["ansible_facts"]["ip_interfaces"]

        # Find backend interface names
        return {intf: ip["bgp_neighbor"].lower() for intf, ip in ip_ifs.items()
                if ip["bgp_neighbor"].lower().startswith("asic")}

    def check_v4route_backend_nhop(self, duthost, frontend_asic, route):
        """
        On frontend ASIC Check if v4 address has at least one backend
        ASIC nexthop

        Returns:
          False if not nexthops with backend ASICs
        """
        cmd = 'vtysh -n {} -c "show ip route {} json"'.format(
            frontend_asic, route
        )
        result = duthost.command(cmd)
        pytest_assert(result["rc"] == 0, cmd)
        route_info = json.loads(result["stdout"])
        nhop = route_info[route_info.keys().pop()][0]

        nhop_ifs = {x["interfaceName"] for x in nhop["nexthops"]}
        backend_ifs = set(self.get_backend_ip_ifs(
            duthost, frontend_asic).keys()
        )

        return len(nhop_ifs.intersection(backend_ifs))

    def backend_ip_if_admin_state(
        self, duthost, test_asic, frontend_asic, admin_state
    ):
        """
        On a frontend ASIC bring down ports (channels) towards backend ASICs
        other than the ASIC under test, so that traffic always goes via
        backend ASIC under test
        """

        def is_intf_status(asic, intf, oper_state):
            intf_status = duthost.asic_instance(asic).show_interface(
                command="status", include_internal_intfs=True
            )["ansible_facts"]["int_status"]
            if intf_status[intf]["oper_state"] == oper_state:
                return True
            return False

        oper_state = "up" if admin_state == "startup" else "down"
        ip_ifs = self.get_backend_ip_ifs(duthost, frontend_asic)

        for intf, asic in ip_ifs.items():
            if  asic != "asic{}".format(test_asic):
                if admin_state == "startup":
                    duthost.asic_instance(frontend_asic).startup_interface(intf)
                else:
                    duthost.asic_instance(frontend_asic).shutdown_interface(intf)

                # wait for port status to change
                pytest_assert(
                    wait_until(
                        10, 1, is_intf_status, frontend_asic, intf,
                        oper_state
                    ),
                    "Failed to update port status {} {}".format(
                        intf, admin_state
                    )
                )


    def find_asic_traffic_ports(self, duthost, ptfhost, test_params):
        """
        For a given pair of source IP and destination IP, identify
        the path taken by the L3 packet. Path implies the backend ASIC
        and its tx and rx ports. The path is identified by sending
        a burst of packets and finding the difference in interface
        counters before and after the burst.

        Assert is thrown if multiple ports or multiple backend ASICs
        have similar interface counters.
        """
        def find_traffic_ports(asic_id, c1, c2, diff):

            rx_port = None
            tx_port = None

            a1 = c1[asic_id]["ansible_facts"]["int_counter"]
            a2 = c2[asic_id]["ansible_facts"]["int_counter"]

            for port in a2.keys():
                rx_diff = int(a2[port]["RX_OK"]) - int(a1[port]["RX_OK"])

                if rx_diff >= diff:
                    pytest_assert(
                        rx_port is None,
                        "Multiple rx ports with {} rx packets".format(diff)
                    )
                    rx_port = port

                tx_diff = int(a2[port]["TX_OK"]) - int(a1[port]["TX_OK"])
                if tx_diff >= diff:
                    pytest_assert(
                        tx_port is None,
                        "Multiple tx ports with {} tx packets".format(diff)
                    )
                    tx_port = port

            # return rx, tx ports that have a packet count difference of > diff
            return rx_port, tx_port

        test_params["count"] = 100
        duthost.command("sonic-clear counters")
        cnt_before = duthost.show_interface(
            command="counter", asic_index="all", include_internal_intfs=True
        )
        # send a burst of packets from a given src IP to dst IP
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.PacketTransmit",
            testParams=test_params
        )
        time.sleep(8)
        cnt_after = duthost.show_interface(
            command="counter", asic_index="all", include_internal_intfs=True
        )

        asic_idx = None
        rx_port = None
        tx_port = None

        # identify the backend ASIC and the rx, tx ports on that ASIC
        # that forwarded the traffic
        for asic in duthost.get_backend_asic_ids():
            rx, tx = find_traffic_ports(
                asic, cnt_before, cnt_after, test_params["count"]
            )
            if rx and tx:
                pytest_assert(
                    rx_port is None and tx_port is None,
                    "Multiple backend ASICs with rx/tx ports"
                )
                rx_port, tx_port, asic_idx  = rx, tx, asic

        pytest_assert(asic_idx is not None, "ASIC, rx and tx ports not found")
        return ({
            "test_src_port_name": rx_port,
            "test_dst_port_name": tx_port,
            "asic_under_test": asic_idx,
            }
        )

    @pytest.fixture(scope='class')
    def build_ip_interface(
        self, duthosts, rand_one_dut_hostname, swapSyncd, tbinfo
    ):
        """
        builds a list of active IP interfaces and port index
        for each ASIC

        Returns:
        {
            asic_index: {
                portIndex: {
                    "ipv4": peer ipv4,
                    "bgp_neighbor": BGP neighbor
                }
                .
                .
            }
           .
           .
        }
        """
        duthost = duthosts[rand_one_dut_hostname]

        topo = tbinfo["topo"]["name"]
        if topo not in self.SUPPORTED_T1_TOPOS:
            pytest.skip("unsupported topology {}".format(topo))

        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        ip_ifaces = duthost.get_active_ip_interfaces(asic_index="all")

        port_ips = dict()
        for idx in range(len(ip_ifaces)):
            port_ips.update(self.build_port_ips(idx, ip_ifaces[idx], mg_facts))

        yield port_ips

    @pytest.fixture(scope='class')
    def build_test_ports(self, build_ip_interface):
        """
        This fixture builds a list of active L3 interface ports on each
        ASIC so that source and destination interfaces can be selected
        from different ASICs. Returns a dict of 'src' and 'dst' interfaces
        along with the ASIC ID

        Only frontend ASCIs connected to T0 devices are reachable end
        to end on multi ASIC platform.
        """
        # find asics with T0 neighbors
        ports = dict()
        for k, v in build_ip_interface.items():
            try:
                port_index = next(iter(v))
                port_info = v[port_index]
                if port_info["bgp_neighbor"].lower().endswith("t0"):
                    ports.update({k: v})
            except StopIteration:
                continue

        pytest_assert(
            len(ports) >= 0, "Ports from at least two ASICs required"
        )

        test_ports = dict()
        keys = ports.keys()
        src_asic = keys.pop(0)
        test_ports.update({"src": {src_asic: ports[src_asic]}})
        test_ports.update({"dst": dict()})
        for dst_asic in keys:
            test_ports["dst"].update({dst_asic: ports[dst_asic]})

        yield test_ports

    @pytest.fixture(scope='class')
    def get_test_ports(self, build_test_ports):
        """
        Fixture to select test ports from a given list of active L3
        interfaces from multiple frontend ASICs. The source and
        destination port will be on different ASICs.

        Fixture also returns the source and desitnation ASCIS IDs
        """

        # source port
        src_asic = build_test_ports["src"].keys().pop(0)
        src_port_ids = build_test_ports["src"][src_asic].keys()
        src_port_id = src_port_ids.pop(0)
        src_port_ip = build_test_ports["src"][src_asic][src_port_id]["ipv4"]

        # destination port
        dst_asic = build_test_ports["dst"].keys().pop(0)
        dst_port_ids = build_test_ports["dst"][dst_asic].keys()
        dst_port_id = dst_port_ids.pop(0)
        dst_port_ip = build_test_ports["dst"][dst_asic][dst_port_id]["ipv4"]

        return {
            "dst_port_id": dst_port_id,
            "dst_port_ip": dst_port_ip,
            "dst_asic": dst_asic,
            "src_port_id": src_port_id,
            "src_port_ip": src_port_ip,
            "src_asic": src_asic,
        }
