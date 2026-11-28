import logging
import os
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa: F401  # lgtm [py/unused-import]
from tests.ptf_runner import ptf_runner
from .utils import get_frontend_asics, get_vlan_asics, ns_option

pytestmark = [
    pytest.mark.topology('t0', 'm0', 'mx')
]

logger = logging.getLogger(__name__)

DISABLE_REFRESH = "disable_refresh"
REFRESH_DEST_MAC = "refresh_with_dest_mac"


class TestFdbMacExpire:
    """
        TestFdbMacExpire Verifies FDb aging timer is respected

        The test updates fdb_aging_time value, restarts swssconfig in order to pickup the new value,
        populated the FDB table with dummy MAC entry, and then waits for fdb_aging_time and makes sure
        FDB entry with dummy MAC is cleared.
    """
    DUMMY_MAC_PREFIX = "00:11:22:33:44"
    FDB_INFO_FILE = "/root/fdb_info.txt"
    POLLING_INTERVAL_SEC = 15

    def __getFdbTableCount(self, duthost, mac):
        """
            Gets number of FDB table entries containing mac entry.

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                mac (str): MAC value to search for in the FDB table

            Returns:
                (int) representing the number of the FDB entries containing th eMAC address
        """
        return sum(int(duthost.shell("show mac {0}| grep {1} | wc -l".format(ns_option(asic), mac))["stdout"])
                   for asic in get_frontend_asics(duthost))

    def __tmpSwitchConfig(self, asic):
        """
            Returns the 'docker cp' destination and the path of the temporary switch.json copy of the ASIC.
            Multi-ASIC DUTs keep one copy per ASIC namespace.
        """
        if asic.namespace:
            path = "/tmp/switch.json.{}".format(asic.namespace)
            return path, path
        return "/tmp", "/tmp/switch.json"

    def __loadSwssConfig(self, duthost, asic):
        """
            Load SWSS configuration on DUT

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                asic (SonicAsic): ASIC whose swss container loads the configuration

            Raises:
                asserts if the load SWSS config failed

            Returns:
                None
        """
        duthost.shell(argv=[
            "docker",
            "exec",
            asic.get_docker_name("swss"),
            "bash",
            "-c",
            "swssconfig /etc/swss/config.d/switch.json"
        ])

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

    def __runPtfTest(self, ptfhost, testCase='', testParams={}):
        """
            Runs FDB MAC Expire test case on PTF host

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                testCase (str): FDB tests test case name
                testParams (dict): Map of test params required by testCase

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        logger.info("Running PTF test case '{0}' on '{1}'".format(testCase, ptfhost.hostname))
        ptf_runner(
            ptfhost,
            "ptftests",
            testCase,
            platform_dir="ptftests",
            params=testParams,
            log_file="/tmp/{0}".format(testCase),
            is_python3=True
        )

    @pytest.fixture(scope="class", autouse=True)
    def copyFdbInfo(self, duthosts, rand_one_dut_hostname, ptfhost, tbinfo):
        """
            Compies FDB info file to PTF host

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        """
        duthost = duthosts[rand_one_dut_hostname]
        mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
        ptfhost.host.options['variable_manager'].extra_vars.update({
            "minigraph_vlan_interfaces": mgFacts["minigraph_vlan_interfaces"],
            "minigraph_port_indices": mgFacts["minigraph_ptf_indices"],
            "minigraph_portchannels": mgFacts["minigraph_portchannels"],
            "minigraph_vlans": mgFacts["minigraph_vlans"],
        })

        logger.info("Copying fdb_info.txt config file to {0}".format(ptfhost.hostname))
        ptfhost.template(src="fdb/files/fdb.j2", dest=self.FDB_INFO_FILE)

    @pytest.fixture(scope="class", autouse=True)
    def clearSonicFdbEntries(self, duthosts, rand_one_dut_hostname):
        """
            Clears SONiC FDB entries before and after test

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        duthost = duthosts[rand_one_dut_hostname]
        duthost.shell(argv=["sonic-clear", "fdb", "all"])

        yield

        duthost.shell(argv=["sonic-clear", "fdb", "all"])

    @pytest.fixture(scope="class", autouse=True)
    def validateDummyMacAbsent(self, duthosts, rand_one_dut_hostname):
        """
            Validates that test/dummy MAC entry is absent before the test runs

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        duthost = duthosts[rand_one_dut_hostname]
        pytest_assert(self.__getFdbTableCount(duthost, self.DUMMY_MAC_PREFIX) == 0, "Test dummy MAC is already present")

    @pytest.fixture(scope="class", autouse=True)
    def prepareDut(self, request, duthosts, rand_one_dut_hostname):
        """
            Prepare DUT for FDB test

            It update the fdb_aging_time value, update the swss configuration, and restore SWSS configuration afer
            test completes

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        duthost = duthosts[rand_one_dut_hostname]
        fdbAgingTime = request.config.getoption('--fdb_aging_time')
        # Every ASIC with a VLAN has its own swss container and FDB on multi-ASIC DUTs
        asics = get_vlan_asics(duthost)

        self.__deleteTmpSwitchConfig(duthost)
        for asic in asics:
            swss = asic.get_docker_name("swss")
            cpDest, tmpSwitchJson = self.__tmpSwitchConfig(asic)
            duthost.shell(argv=["docker", "cp", "{}:/etc/swss/config.d/switch.json".format(swss), cpDest])
            duthost.replace(
                dest=tmpSwitchJson,
                regexp='"fdb_aging_time": ".*"',
                replace='"fdb_aging_time": "{0}"'.format(fdbAgingTime),
                backup=True
            )
            duthost.shell(argv=["docker", "cp", tmpSwitchJson, "{}:/etc/swss/config.d/switch.json".format(swss)])
            self.__loadSwssConfig(duthost, asic)

        yield

        for asic in asics:
            swss = asic.get_docker_name("swss")
            _, tmpSwitchJson = self.__tmpSwitchConfig(asic)
            result = duthost.find(path=["/tmp"], patterns=["{}.*".format(os.path.basename(tmpSwitchJson))])
            if result["matched"] > 0:
                duthost.shell(argv=["docker", "cp", result["files"][0]["path"],
                                    "{}:/etc/swss/config.d/switch.json".format(swss)])
                self.__loadSwssConfig(duthost, asic)
        self.__deleteTmpSwitchConfig(duthost)

    @pytest.mark.parametrize("refresh_type", [DISABLE_REFRESH, REFRESH_DEST_MAC])
    def testFdbMacExpire(self, request, tbinfo, rand_selected_dut, ptfhost, refresh_type):
        """
            TestFdbMacExpire Verifies FDb aging timer is respected

            The test updates fdb_aging_time value, restarts swssconfig in order to pickup the new value,
            populated the FDB table with dummy MAC entry, and then waits for fdb_aging_time and makes sure
            FDB entry with dummy MAC is cleared.

            Args:
                request (Fixture): pytest request object
                tbinfo (Fixture, dict): Map containing testbed information
                rand_selected_dut (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)

            Returns:
                None
        """
        fdbAgingTime = request.config.getoption('--fdb_aging_time')

        testParams = {
            "testbed_type": tbinfo["topo"]["name"],
            "router_mac": rand_selected_dut.facts["router_mac"],
            "fdb_info": self.FDB_INFO_FILE,
            "dummy_mac_prefix": self.DUMMY_MAC_PREFIX,
            "refresh_type":  refresh_type,
            "aging_time": fdbAgingTime,
            "kvm_support": True
        }
        self.__runPtfTest(ptfhost, "fdb_mac_expire_test.FdbMacExpireTest", testParams)

        logger.info("wait for FDB aging time of '{0}' secs".format(fdbAgingTime))
        time.sleep(fdbAgingTime)

        count = 0
        dummyMacCount = self.__getFdbTableCount(rand_selected_dut, self.DUMMY_MAC_PREFIX)
        while count * self.POLLING_INTERVAL_SEC < fdbAgingTime and dummyMacCount != 0:
            time.sleep(self.POLLING_INTERVAL_SEC)
            dummyMacCount = self.__getFdbTableCount(rand_selected_dut, self.DUMMY_MAC_PREFIX)
            count += 1
            logger.info(
                "MAC table entries count: {0}, after {1} sec".format(
                    dummyMacCount,
                    fdbAgingTime + count * self.POLLING_INTERVAL_SEC
                )
            )

        pytest_assert(
            dummyMacCount == 0,
            "Failed! MAC did not expire after expected FDB aging time expired"
        )
