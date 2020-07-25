import logging
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]
class TestNeighborMacNoPtf:
    """
        Test handling of neighbor MAC in SONiC switch
    """
    TEST_MAC = {
        4: ["08:bc:27:af:cc:45", "08:bc:27:af:cc:47"],
        6: ["08:bc:27:af:cc:65", "08:bc:27:af:cc:67"],
    }

    TEST_INTF = {
        4: {"intfIp": "29.0.0.1/24", "NeighborIp": "29.0.0.2"},
        6: {"intfIp": "fe00::1/64", "NeighborIp": "fe00::2"},
    }

    @pytest.fixture(scope="module", autouse=True)
    def restoreDutConfig(self, duthost):
        """
            Restores DUT configuration after test completes

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        yield

        logger.info("Reload Config DB")
        config_reload(duthost, config_source='config_db', wait=120)

    @pytest.fixture(params=[4, 6])
    def ipVersion(self, request):
        """
            Parameterized fixture for IP versions. This Fixture will run the test twice for both
            IPv4 and IPv6

            Args:
                request: pytest request object

            Retruns:
                ipVersion (int): IP version to be used for testing
        """
        yield request.param

    @pytest.fixture(scope="module")
    def routedInterface(self, duthost):
        """
            Find routed interface to test neighbor MAC functionality with

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Retruns:
                routedInterface (str): Routed interface used for testing
        """
        testRoutedInterface = None

        intfStatus = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
        for intf, status in intfStatus.items():
            if "routed" in status["vlan"] and "up" in status["oper_state"]:
                testRoutedInterface = intf
        pytest_assert(testRoutedInterface, "Failed to find a routed interface in '%s'" % intfStatus)

        yield testRoutedInterface

    @pytest.fixture
    def verifyOrchagentPresence(self, duthost):
        """
            Verify orchagent is running before and after the test is finished

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        def verifyOrchagentRunningOrAssert(duthost):
            """
                Verifyes that orchagent is running, asserts otherwise

                Args:
                    duthost (AnsibleHost): Device Under Test (DUT)
            """
            result = duthost.shell(argv=["pgrep", "orchagent"])
            pytest_assert(int(result["stdout"]) > 0, "Orchagent is not running")

        verifyOrchagentRunningOrAssert(duthost)

        yield

        verifyOrchagentRunningOrAssert(duthost)

    def __updateNeighborIp(self, duthost, intf, ipVersion, macIndex, action=None):
        """
            Update IP neighbor

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                intf (str): Interface name
                ipVersion (Fixture<int>): IP version
                macIndex (int): test MAC index to be used
                action (str): action to perform

            Returns:
                None
        """
        neighborIp = self.TEST_INTF[ipVersion]["NeighborIp"]
        neighborMac = self.TEST_MAC[ipVersion][macIndex]
        logger.info("{0} neighbor {1} lladdr {2} for {3}".format(action, neighborIp, neighborMac, intf))
        argv = ["ip"] if "add" in action else ["ip", "-{0}".format(ipVersion)]
        argv.extend([
            "neigh",
            action,
            neighborIp,
            "lladdr",
            neighborMac,
            "dev",
            intf
        ])
        duthost.shell(argv=argv)

    def __updateInterfaceIp(self, duthost, intf, ipVersion, action=None):
        """
            Update interface IP

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                intf (str): Interface name
                ipVersion (Fixture<int>): IP version
                action (str): action to perform

            Returns:
                None
        """
        logger.info("{0} an ip entry '{1}' for {2}".format(action, self.TEST_INTF[ipVersion]["intfIp"], intf))
        duthost.shell(argv=[
            "config",
            "interface",
            "ip",
            action,
            intf,
            self.TEST_INTF[ipVersion]["intfIp"]
        ])

    @pytest.fixture(autouse=True)
    def updateNeighborIp(self, duthost, routedInterface, ipVersion, verifyOrchagentPresence):
        """
            Update Neighbor/Interface IP

            Prepares the DUT for testing by adding IP to the test interface, add and update
            the neighbor MAC 2 times.

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                routedInterface (Fixture<str>): test Interface name
                ipVersion (Fixture<int>): IP version
                verifyOrchagentPresence (Fixture): Make sure orchagent is running before and
                    after update takes place

            Returns:
                None
        """
        self.__updateInterfaceIp(duthost, routedInterface, ipVersion, action="add")
        self.__updateNeighborIp(duthost, routedInterface, ipVersion, 0, action="add")
        self.__updateNeighborIp(duthost, routedInterface, ipVersion, 0, action="change")
        self.__updateNeighborIp(duthost, routedInterface, ipVersion, 1, action="change")

        time.sleep(2)

        yield

        self.__updateNeighborIp(duthost, routedInterface, ipVersion, 1, action="del")
        self.__updateInterfaceIp(duthost, routedInterface, ipVersion, action="remove")

    @pytest.fixture
    def arpTableMac(self, duthost, ipVersion, updateNeighborIp):
        """
            Retreive DUT ARP table MAC entry of neighbor IP

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ipVersion (Fixture<int>): IP version
                updateNeighborIp (Fixture<str>): test fixture that assign/update IP/neighbor MAC

            Returns:
                arpTableMac (str): ARP MAC entry of neighbor IP
        """
        dutArpTable = duthost.switch_arptable()["ansible_facts"]["arptable"]
        yield dutArpTable["v{0}".format(ipVersion)][self.TEST_INTF[ipVersion]["NeighborIp"]]["macaddress"]

    @pytest.fixture
    def redisNeighborMac(self, duthost, ipVersion, updateNeighborIp):
        """
            Retreive DUT Redis MAC entry of neighbor IP

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ipVersion (Fixture<int>): IP version
                updateNeighborIp (Fixture<str>): test fixture that assign/update IP/neighbor MAC

            Returns:
                redisNeighborMac (str): Redis MAC entry of neighbor IP
        """
        result = duthost.shell(argv=["redis-cli", "-n", "1", "KEYS", "ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY*"])
        neighborKey = None
        for key in result["stdout_lines"]:
            if self.TEST_INTF[ipVersion]["NeighborIp"] in key:
                neighborKey = key
                break
        pytest_assert(neighborKey, "Neighbor key NOT found in Redis DB, Redis db Output '{0}'".format(result["stdout"]))

        result = duthost.shell(argv=["redis-cli", "-n", "1", "HGETALL", neighborKey])

        yield result["stdout_lines"][1]

    def testNeighborMacNoPtf(self, ipVersion, arpTableMac, redisNeighborMac):
        """
            Neighbor MAC test

            Args:
                ipVersion (Fixture<int>): IP version
                arpTableMac (Fixture<str>): ARP MAC entry of neighbor IP
                redisNeighborMac (Fixture<str>): Redis MAC entry of neighbor IP

            Returns:
                None
        """
        testMac = self.TEST_MAC[ipVersion][1]
        pytest_assert(
            arpTableMac.lower() == testMac,
            "Failed to find test MAC address '{0}' in ARP table '{1}'".format(testMac, arpTableMac)
        )

        pytest_assert(
            redisNeighborMac.lower() == testMac,
            "Failed to find test MAC address '{0}' in Redis Neighbor table '{1}'".format(testMac, redisNeighborMac)
        )
