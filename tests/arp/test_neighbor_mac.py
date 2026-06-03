import contextlib
import logging
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('m1', 't1', 'ptf', 'c0')
]


class TestNeighborMac:
    """
        Test handling of neighbor MAC in SONiC switch with PTF docker
    """
    PTF_HOST_IF = "eth0"
    DUT_ETH_IF = "Ethernet0"
    PTF_HOST_IP = "20.0.0.2"
    PTF_HOST_NETMASK = "255.255.255.0"
    DUT_INTF_IP = "20.0.0.1"
    DUT_INTF_NETMASK = "24"
    TEST_MAC = ["00:c0:ca:c0:1a:05", "00:c0:ca:c0:1a:06"]
    PING_CAPTURE_FILTER = "arp or icmp"
    DELAYED_MANUAL_PING_WAIT = 30

    @pytest.fixture(scope="module", autouse=True)
    def interfaceConfig(self, duthosts, rand_one_dut_hostname):
        """
            Configures and Restores DUT configuration after test completes

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        duthost = duthosts[rand_one_dut_hostname]
        if duthost.facts['platform'].startswith('arm64-c8220tg_48a_o'):
            self.DUT_ETH_IF = "Ethernet1"

        intfStatus = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
        if self.DUT_ETH_IF not in intfStatus:
            pytest.skip('{} not found'.format(self.DUT_ETH_IF))

        status = intfStatus[self.DUT_ETH_IF]
        if "up" not in status["oper_state"]:
            pytest.skip('{} is down'.format(self.DUT_ETH_IF))

        portchannel = status["vlan"] if "PortChannel" in status["vlan"] else None

        @contextlib.contextmanager
        def removeFromPortChannel(duthost, portchannel, intf):
            try:
                if portchannel:
                    duthost.command("sudo config portchannel member del {} {}".format(portchannel, intf))
                    pytest_assert(wait_until(
                        10, 1, 0,
                        lambda: 'routed' in duthost.show_interface(command="status")
                        ["ansible_facts"]["int_status"][intf]["vlan"]),
                        '{} is not in routed status'.format(intf)
                    )
                yield
            finally:
                if portchannel:
                    duthost.command("sudo config portchannel member add {} {}".format(portchannel, intf))

        with removeFromPortChannel(duthost, portchannel, self.DUT_ETH_IF):
            logger.info("Configure the DUT interface, start interface, add IP address")
            self.__startInterface(duthost)
            self.__configureInterfaceIp(duthost, action="add")

            yield

            logger.info("Restore the DUT interface config, remove IP address")
            self.__configureInterfaceIp(duthost, action="remove")
            self.__shutdownInterface(duthost)

    @pytest.fixture(params=[0, 1])
    def macIndex(self, request):
        """
            Parameterized fixture for macIndex

            Args:
                request: pytest request object

            Returns:
                macIndex (int): index of the mac address used from TEST_MAC
        """
        yield request.param

    def __configureNeighborIp(self, ptfhost, macIndex):
        """
            Configure interface and set IP address/mac address on the PTF host

            Args:
                ptfhost (PTF host): PTF instance used
                macIndex (int): test MAC index to be used

            Returns:
                None
        """
        ptfhost.shell("ifconfig {} {} netmask 255.255.255.0".format(self.PTF_HOST_IF, self.PTF_HOST_IP))
        neighborMac = self.TEST_MAC[macIndex]
        logger.info("neighbor {0} lladdr {1} for {2}".format(self.PTF_HOST_IP, neighborMac, self.PTF_HOST_IF))
        ptfhost.shell("ifconfig {} down".format(self.PTF_HOST_IF))
        ptfhost.shell("ifconfig {} hw ether {}".format(self.PTF_HOST_IF, neighborMac))
        ptfhost.shell("ifconfig {} up".format(self.PTF_HOST_IF))

    def __startInterface(self, duthost):
        """
            Startup the interface on the DUT

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        logger.info("Configure the interface '{0}' as UP".format(self.DUT_ETH_IF))
        duthost.shell(argv=[
            "config",
            "interface",
            "startup",
            self.DUT_ETH_IF
        ])

    def __shutdownInterface(self, duthost):
        """
            Shutdown the interface on the DUT

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        logger.info("Configure the interface '{0}' as DOWN".format(self.DUT_ETH_IF))
        duthost.shell(argv=[
            "config",
            "interface",
            "shutdown",
            self.DUT_ETH_IF
        ])

    def __configureInterfaceIp(self, duthost, action=None):
        """
            Configure interface IP address on the DUT

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                action (str): action to perform, add/remove interface IP

            Returns:
                None
        """

        logger.info("{0} an ip entry {1} for {2}".format(action, self.DUT_INTF_IP, self.DUT_ETH_IF))
        interfaceIp = "{}/{}".format(self.DUT_INTF_IP, self.DUT_INTF_NETMASK)
        duthost.shell(argv=[
            "config",
            "interface",
            "ip",
            action,
            self.DUT_ETH_IF,
            interfaceIp
        ])

    def __runDebugCommand(self, host, command, description):
        result = host.shell(command, module_ignore_errors=True)
        logger.info(
            "%s rc=%s\nstdout:\n%s\nstderr:\n%s",
            description,
            result.get("rc"),
            result.get("stdout", ""),
            result.get("stderr", "")
        )
        return result

    def __startPtfCapture(self, ptfhost, macIndex):
        captureFile = "/tmp/test_neighbor_mac_{}.tcpdump".format(macIndex)
        pidFile = "/tmp/test_neighbor_mac_{}.pid".format(macIndex)
        ptfhost.shell(
            "rm -f {capture_file} {pid_file}; "
            "nohup tcpdump -i {intf} -nnevv -l '{capture_filter}' "
            "> {capture_file} 2>&1 & echo $! > {pid_file}".format(
                capture_file=captureFile,
                pid_file=pidFile,
                intf=self.PTF_HOST_IF,
                capture_filter=self.PING_CAPTURE_FILTER
            ),
            module_ignore_errors=True
        )
        time.sleep(1)
        return captureFile, pidFile

    def __stopPtfCapture(self, ptfhost, captureFile, pidFile):
        ptfhost.shell(
            "if [ -s {pid_file} ]; then kill $(cat {pid_file}) 2>/dev/null || true; fi; "
            "sleep 1".format(pid_file=pidFile),
            module_ignore_errors=True
        )
        capture = ptfhost.shell("cat {}".format(captureFile), module_ignore_errors=True)
        logger.info("PTF packet capture during neighbor MAC ping:\n%s", capture.get("stdout", ""))
        ptfhost.shell("rm -f {} {}".format(captureFile, pidFile), module_ignore_errors=True)
        return capture

    def __runDelayedManualPingCheck(self, duthost, ptfhost, macIndex):
        logger.error(
            "Running delayed manual ping check after initial failure: wait %s seconds",
            self.DELAYED_MANUAL_PING_WAIT
        )
        time.sleep(self.DELAYED_MANUAL_PING_WAIT)

        self.__runDebugCommand(
            ptfhost,
            "ip neigh flush {} dev {} || true".format(self.DUT_INTF_IP, self.PTF_HOST_IF),
            "PTF flush neighbor entry before delayed manual ping"
        )

        captureFile, pidFile = self.__startPtfCapture(ptfhost, "{}_delayed".format(macIndex))
        try:
            pingResult = ptfhost.shell(
                "ping {} -c 3 -I {}".format(self.DUT_INTF_IP, self.PTF_HOST_IP),
                module_ignore_errors=True
            )
        finally:
            self.__stopPtfCapture(ptfhost, captureFile, pidFile)

        logger.error(
            "Delayed manual ping result after %s seconds rc=%s\nstdout:\n%s\nstderr:\n%s",
            self.DELAYED_MANUAL_PING_WAIT,
            pingResult.get("rc"),
            pingResult.get("stdout", ""),
            pingResult.get("stderr", "")
        )
        self.__dumpNeighborState(duthost, ptfhost, "Delayed manual ping diagnostic result")
        return pingResult

    def __dumpNeighborState(self, duthost, ptfhost, reason):
        logger.error("Dumping neighbor MAC debug state: %s", reason)
        self.__runDebugCommand(
            ptfhost,
            "ip -d link show {}".format(self.PTF_HOST_IF),
            "PTF interface link state"
        )
        self.__runDebugCommand(
            ptfhost,
            "ip addr show {}".format(self.PTF_HOST_IF),
            "PTF interface IP state"
        )
        self.__runDebugCommand(
            ptfhost,
            "ip neigh show {} dev {}".format(self.DUT_INTF_IP, self.PTF_HOST_IF),
            "PTF neighbor entry for DUT"
        )
        self.__runDebugCommand(
            duthost,
            "ip addr show {}".format(self.DUT_ETH_IF),
            "DUT test interface IP state"
        )
        self.__runDebugCommand(duthost, "show ip interfaces", "DUT IP interfaces")
        self.__runDebugCommand(duthost, "show arp", "DUT ARP table")
        self.__runDebugCommand(
            duthost,
            "ip neigh show {}".format(self.PTF_HOST_IP),
            "DUT Linux neighbor entry for PTF"
        )
        self.__runDebugCommand(
            duthost,
            "redis-cli -n 1 KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY*'",
            "DUT ASIC_DB neighbor keys"
        )
        self.__runDebugCommand(
            duthost,
            "docker exec syncd vppctl show interface",
            "VPP interface state"
        )
        self.__runDebugCommand(
            duthost,
            "docker exec syncd vppctl show interface address",
            "VPP interface address state"
        )
        self.__runDebugCommand(
            duthost,
            "docker exec syncd vppctl show ip neighbors",
            "VPP IP neighbor state"
        )
        self.__runDebugCommand(
            duthost,
            "docker exec syncd vppctl show lcp",
            "VPP LCP state"
        )

    @pytest.fixture(autouse=True)
    def configureNeighborIpAndPing(self, duthosts, rand_one_dut_hostname, ptfhost, macIndex):
        """
            Configure Neighbor/Interface IP

            Prepares the DUT for testing by adding IP to the test interface, add and update
            the neighbor MAC 2 times.

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (PTFHost): PTF instance used
                macIndex (Fixture<int>): Index in the TEST_MAC list

            Returns:
                None
        """
        duthost = duthosts[rand_one_dut_hostname]
        self.__configureNeighborIp(ptfhost, macIndex)
        captureFile, pidFile = self.__startPtfCapture(ptfhost, macIndex)
        try:
            pingResult = ptfhost.shell(
                "ping {} -c 3 -I {}".format(self.DUT_INTF_IP, self.PTF_HOST_IP),
                module_ignore_errors=True
            )
        finally:
            self.__stopPtfCapture(ptfhost, captureFile, pidFile)

        logger.info(
            "PTF ping result rc=%s\nstdout:\n%s\nstderr:\n%s",
            pingResult.get("rc"),
            pingResult.get("stdout", ""),
            pingResult.get("stderr", "")
        )
        if pingResult.get("rc") != 0:
            self.__dumpNeighborState(duthost, ptfhost, "PTF ping to DUT failed")
            self.__runDelayedManualPingCheck(duthost, ptfhost, macIndex)
        pytest_assert(
            pingResult.get("rc") == 0,
            "Failed to ping DUT interface {} from PTF IP {}, stdout: {}, stderr: {}".format(
                self.DUT_INTF_IP,
                self.PTF_HOST_IP,
                pingResult.get("stdout", ""),
                pingResult.get("stderr", "")
            )
        )

        time.sleep(2)

        yield

    @pytest.fixture
    def redisNeighborMac(self, duthosts, rand_one_dut_hostname, ptfhost, macIndex, configureNeighborIpAndPing):
        """
            Retrieve DUT Redis MAC entry of neighbor IP

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (PTFHost): PTF instance used
                macIndex (Fixture<int>): Index in the TEST_MAC list
                configureNeighborIpAndPing (Fixture<str>): test fixture that assign/update IP/neighbor MAC and ping DUT

            Returns:
                redisNeighborMac (str): Redis MAC entry of neighbor IP
        """
        duthost = duthosts[rand_one_dut_hostname]
        result = duthost.shell(argv=["redis-cli", "-n", "1", "KEYS", "ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY*"])
        neighborKey = None
        for key in result["stdout_lines"]:
            if self.PTF_HOST_IP in key:
                neighborKey = key
                break

        pytest_assert(neighborKey, "Neighbor key NOT found in Redis DB, Redis db Output '{0}'".format(result["stdout"]))
        result = duthost.shell(argv=["redis-cli", "-n", "1", "HGETALL", neighborKey])

        yield result["stdout_lines"][1]

    def testNeighborMac(self, duthosts, rand_one_dut_hostname, ptfhost, macIndex, redisNeighborMac):
        """
            Neighbor MAC test

            Args:
                macIndex (Fixture<int>): Index in the TEST_MAC list
                redisNeighborMac (Fixture<str>): Redis MAC entry of neighbor IP

            Returns:
                None
        """
        duthost = duthosts[rand_one_dut_hostname]
        testMac = self.TEST_MAC[macIndex]
        if redisNeighborMac.lower() != testMac:
            self.__dumpNeighborState(duthost, ptfhost, "Redis neighbor MAC mismatch")
        pytest_assert(
            redisNeighborMac.lower() == testMac,
            "Failed to find test MAC address '{0}' in Redis Neighbor table '{1}'".format(testMac, redisNeighborMac)
        )
