import logging
import pytest
import time

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

REDIS_NEIGH_ENTRY_MAC_ATTR ="SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS"
ROUTE_TABLE_NAME = 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY'
DEFAULT_ROUTE_NUM = 2

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

    def count_routes(self, asichost, prefix):
        # Counts routes in ASIC_DB with a given prefix
        num = asichost.shell(
                '{} ASIC_DB eval "return #redis.call(\'keys\', \'{}:{{\\"dest\\":\\"{}*\')" 0'.format(asichost.sonic_db_cli, ROUTE_TABLE_NAME, prefix),
                module_ignore_errors=True, verbose=True)['stdout']
        return int(num)

    def _get_bgp_routes_asic(self, asichost):
        # Get the routes installed by BGP in ASIC_DB by filtering out all local routes installed on asic
        localv6 = self.count_routes(asichost, "fc") + self.count_routes(asichost, "fe")
        localv4 = self.count_routes(asichost, "10.") + self.count_routes(asichost, "192.168.0.")
        # these routes are present only on multi asic device, on single asic platform they will be zero
        internal = self.count_routes(asichost, "8.") + self.count_routes(asichost, "2603")
        allroutes = self.count_routes(asichost, "")
        logger.info("asic[{}] localv4 routes {} localv6 routes {} internalv4 {} allroutes {}".format(asichost.asic_index, localv4, localv6, internal, allroutes))
        bgp_routes_asic = allroutes - localv6 - localv4 - internal - DEFAULT_ROUTE_NUM

        return bgp_routes_asic

    def _check_no_bgp_routes(self, duthost):
        bgp_routes = 0
        # Checks that there are no routes installed by BGP in ASIC_DB by filtering out all local routes installed on testbed
        for asic in duthost.asics:
            bgp_routes += self._get_bgp_routes_asic(asic)
        
        return bgp_routes == 0
            
    @pytest.fixture(scope="module", autouse=True)
    def setupDutConfig(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
            Disabled BGP to reduce load on switch and restores DUT configuration after test completes

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        if not duthost.get_facts().get("modular_chassis"):
            duthost.command("sudo config bgp shutdown all")
            if not wait_until(120, 2.0, self._check_no_bgp_routes, duthost):
                pytest.fail('BGP Shutdown Timeout: BGP route removal exceeded 120 seconds.')

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
    def routedInterfaces(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
            Find routed interface to test neighbor MAC functionality with

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Retruns:
                routedInterface (str): Routed interface used for testing
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        testRoutedInterface = {}

        def find_routed_interface():
            for asichost in duthost.asics:
                intfStatus = asichost.show_interface(command="status")["ansible_facts"]["int_status"]
                for intf, status in intfStatus.items():
                    if "routed" in status["vlan"] and "up" in status["oper_state"]:
                        testRoutedInterface[asichost.asic_index] = intf
            return testRoutedInterface

        if not wait_until(120, 2, find_routed_interface):
            pytest.fail('Failed to find routed interface in 120 s')

        yield testRoutedInterface

    @pytest.fixture
    def verifyOrchagentPresence(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
            Verify orchagent is running before and after the test is finished

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        def verifyOrchagentRunningOrAssert(duthost):
            """
                Verifyes that orchagent is running, asserts otherwise

                Args:
                    duthost (AnsibleHost): Device Under Test (DUT)
            """
            result = duthost.shell(argv=["pgrep", "orchagent"])
            orchagent_pids = result['stdout'].splitlines()
            pytest_assert(len(orchagent_pids) == duthost.num_asics(), "Orchagent is not running")
            for pid in orchagent_pids:
                pytest_assert(int(pid) > 0, "Orchagent is not running")

        verifyOrchagentRunningOrAssert(duthost)

        yield

        verifyOrchagentRunningOrAssert(duthost)

    def __updateNeighborIp(self, asichost, intf, ipVersion, macIndex, action=None):
        """
            Update IP neighbor

            Args:
                asichost (SonicHost): Asic Under Test (DUT)
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
        cmd = asichost.ip_cmd if "add" in action else "{0} -{1}".format(asichost.ip_cmd, ipVersion)
        cmd += " neigh {0} {1} lladdr {2} dev {3}".format(action, neighborIp, neighborMac, intf)
        logger.info(cmd)
        asichost.shell(cmd)

    def __updateInterfaceIp(self, asichost, intf, ipVersion, action=None):
        """
            Update interface IP

            Args:
                asichost (SonicHost): Asic Under Test (DUT)
                intf (str): Interface name
                ipVersion (Fixture<int>): IP version
                action (str): action to perform

            Returns:
                None
        """
        logger.info("{0} an ip entry '{1}' for {2}".format(action, self.TEST_INTF[ipVersion]["intfIp"], intf))
        asichost.config_ip_intf(intf, self.TEST_INTF[ipVersion]["intfIp"], action)


    @pytest.fixture(autouse=True)
    def updateNeighborIp(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, routedInterfaces, ipVersion, verifyOrchagentPresence):
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
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asichost = duthost.asic_instance(enum_frontend_asic_index)
        routedInterface = routedInterfaces[asichost.asic_index]
        self.__updateInterfaceIp(asichost, routedInterface, ipVersion, action="add")
        self.__updateNeighborIp(asichost, routedInterface, ipVersion, 0, action="add")
        self.__updateNeighborIp(asichost, routedInterface, ipVersion, 0, action="change")
        self.__updateNeighborIp(asichost, routedInterface, ipVersion, 1, action="change")

        time.sleep(2)

        yield

        self.__updateNeighborIp(asichost, routedInterface, ipVersion, 1, action="del")
        self.__updateInterfaceIp(asichost, routedInterface, ipVersion, action="remove")

    @pytest.fixture
    def arpTableMac(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, ipVersion, updateNeighborIp):
        """
            Retreive DUT ARP table MAC entry of neighbor IP

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ipVersion (Fixture<int>): IP version
                updateNeighborIp (Fixture<str>): test fixture that assign/update IP/neighbor MAC

            Returns:
                arpTableMac (str): ARP MAC entry of neighbor IP
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asichost = duthost.asic_instance(enum_frontend_asic_index)
        dutArpTable = asichost.switch_arptable()["ansible_facts"]["arptable"]
        yield dutArpTable["v{0}".format(ipVersion)][self.TEST_INTF[ipVersion]["NeighborIp"]]["macaddress"]

    @pytest.fixture
    def redisNeighborMac(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,enum_frontend_asic_index,  ipVersion, updateNeighborIp):
        """
            Retreive DUT Redis MAC entry of neighbor IP

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ipVersion (Fixture<int>): IP version
                updateNeighborIp (Fixture<str>): test fixture that assign/update IP/neighbor MAC

            Returns:
                redisNeighborMac (str): Redis MAC entry of neighbor IP
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asichost = duthost.asic_instance(enum_frontend_asic_index)
        redis_cmd = "{} ASIC_DB KEYS \"ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY*\"".format(asichost.sonic_db_cli)
        result = duthost.shell(redis_cmd)
        neighborKey = None
        for key in result["stdout_lines"]:
            if self.TEST_INTF[ipVersion]["NeighborIp"] in key:
                neighborKey = key
                break
        pytest_assert(neighborKey, "Neighbor key NOT found in Redis DB, Redis db Output '{0}'".format(result["stdout"]))
        neighborKey = " '{}' {} ".format(
            neighborKey,
            REDIS_NEIGH_ENTRY_MAC_ATTR)
        result = duthost.shell("{} ASIC_DB HGET {}".format(asichost.sonic_db_cli, neighborKey))

        yield (result['stdout_lines'][0])

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
