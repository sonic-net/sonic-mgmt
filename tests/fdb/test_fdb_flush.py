import logging
import pytest
import time
import json

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory
from tests.ptf_runner import ptf_runner
from utils import fdb_cleanup

pytestmark = [
    pytest.mark.topology('t0', 'm0', 'mx')
]

logger = logging.getLogger(__name__)

FLUSH_TYPES = ["dynamic", "static", "interface", "mix"]

FDB_SET_JSON_FILE = 'fdb_set_test.json'
FDB_DEL_JSON_FILE = 'fdb_del_test.json'
FDB_FILES_DIR = '/tmp/'
DUT_WORKING_DIR = '/etc/sonic/'

class TestFdbFlush:
    """
        TestFdbFlush Verifies FDb operation is smooth, No new core files are generated after FDb operation.
        FDb operation:
            - Swssconfig add static fdb
            - Swssconfig remove static fdb
            - Sonic-clear fdb all
            - Send packets to create dynamic fdb
            - interface shutdown
            - interface startup

        The test do FDb operation, and make sure no new core files are generated after the test.
    """

    DUMMY_MAC_PREFIX = "00:11:22:33:55"
    FDB_INFO_FILE = "/tmp/fdb_info.txt"

    def __getFdbTableCount(self, duthost, mac):
        """
            Gets number of FDB table entries containing mac entry.

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                mac (str): MAC value to search for in the FDB table

            Returns:
                (int) representing the number of the FDB entries containing th eMAC address
        """
        return int(duthost.shell("show mac | grep {0} | wc -l".format(mac))["stdout"])

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
        duthost.shell(argv=[
            "docker",
            "exec",
            "swss",
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

        self.__deleteTmpSwitchConfig(duthost)
        duthost.shell(argv=["docker", "cp", "swss:/etc/swss/config.d/switch.json", "/tmp"])
        duthost.replace(
            dest='/tmp/switch.json',
            regexp='"fdb_aging_time": ".*"',
            replace='"fdb_aging_time": "{0}"'.format(fdbAgingTime),
            backup=True
        )
        duthost.shell(argv=["docker", "cp", "/tmp/switch.json", "swss:/etc/swss/config.d/switch.json"])
        self.__loadSwssConfig(duthost)

        yield

        result = duthost.find(path=["/tmp"], patterns=["switch.json.*"])
        if result["matched"] > 0:
            duthost.shell(argv=["docker", "cp", result["files"][0]["path"], "swss:/etc/swss/config.d/switch.json"])
            self.__loadSwssConfig(duthost)
        self.__deleteTmpSwitchConfig(duthost)

    def prepare_test(self, duthosts, rand_one_dut_hostname):
        logging.info("Start prepare_test")

        # Perform FDB clean up before each test
        fdb_cleanup(duthosts, rand_one_dut_hostname)
   
        duthost = duthosts[rand_one_dut_hostname]

        # save existing core files list
        self.checkDutCorefiles(duthost, True)
        logging.info("pre_exist_cores {} ".format(self.pre_exist_cores))

        # determine target test port
        self.target_port = None
        ifs_status = duthost.get_interfaces_status()
        logging.info("ifs_status {} ".format(ifs_status))
        for interface_key, interface_info in ifs_status.items():
            if ('N\/A' != interface_info['alias']) and ('N\/A' != interface_info['type']) and ('up' == interface_info['oper']):
                logging.debug('get interface %s' % (interface_info['interface']))
                self.target_port = interface_info['interface']
                break
        pytest_assert(self.target_port != None, "Test FDB Flush: cannot get target port to test")

        # create fdb operation json file
        self.create_fdb_oper_files(duthost)
        logging.info("FDB set json file {} ".format(self.fdb_set_json_file))
        logging.info("FDB del json file {} ".format(self.fdb_del_json_file))


    def checkDutCorefiles(self, duthost, is_before_test):
        if True == is_before_test:
            if "20191130" in duthost.os_version:
                existing_core_dumps = duthost.shell('ls /var/core/ | grep -v python || true')['stdout'].split()
            else:
                existing_core_dumps = duthost.shell('ls /var/core/')['stdout'].split()
    
            logging.info("duthost {} pre_existing_core_dumps {} ".format(duthost, existing_core_dumps))
            self.pre_exist_cores = existing_core_dumps
        else:
            if "20191130" in duthost.os_version:
                existing_core_dumps = duthost.shell('ls /var/core/ | grep -v python || true')['stdout'].split()
            else:
                existing_core_dumps = duthost.shell('ls /var/core/')['stdout'].split()

            logging.info("duthost {} curr_exist_cores {} ".format(duthost, existing_core_dumps))
            self.curr_exist_cores = existing_core_dumps


    def create_fdb_oper_files(self, duthost):
        fdb_table_item_key = 'FDB_TABLE:Vlan1000:00-11-22-33-55-66'
        interface = self.target_port

        fdb_static_set = [
            {
                fdb_table_item_key: {
                        "port": interface,
                        "type": "static"
                },
                "OP": "SET"
            }
        ]
        if len(fdb_static_set) >= 0:
            with open(os.path.join(FDB_FILES_DIR, FDB_SET_JSON_FILE), 'w') as outfile:
                json.dump(fdb_static_set, outfile)
                logger.info("fdb_static_set {} ".format(fdb_static_set))

        fdb_static_del = [
            {
                fdb_table_item_key: {
                        "port": interface,
                        "type": "static"
                },
                "OP": "DEL"
            }
        ]
        if len(fdb_static_del) >= 0:
            with open(os.path.join(FDB_FILES_DIR, FDB_DEL_JSON_FILE), 'w') as outfile:
                json.dump(fdb_static_del, outfile)
                logger.info("fdb_static_del {} ".format(fdb_static_del))

        logger.info('Copying fdb json files to dut: {}'.format(duthost.hostname))
        duthost.shell("sudo rm {}".format(os.path.join(DUT_WORKING_DIR, FDB_SET_JSON_FILE)), module_ignore_errors=True)
        duthost.shell("sudo rm {}".format(os.path.join(DUT_WORKING_DIR, FDB_DEL_JSON_FILE)), module_ignore_errors=True)

        duthost.copy(
            src=os.path.join(FDB_FILES_DIR, FDB_SET_JSON_FILE),
            dest=DUT_WORKING_DIR
        )
        duthost.copy(
            src=os.path.join(FDB_FILES_DIR, FDB_DEL_JSON_FILE),
            dest=DUT_WORKING_DIR
        )
        self.fdb_set_json_file = os.path.join(DUT_WORKING_DIR, FDB_SET_JSON_FILE)
        self.fdb_del_json_file = os.path.join(DUT_WORKING_DIR, FDB_DEL_JSON_FILE)


    def dynamic_fdb_oper(self, duthost, tbinfo, ptfhost, create_or_clear):
        if 'create' == create_or_clear:
            # create dynamic fdb by sending packets via ptf
            testParams = {
                "testbed_type": tbinfo["topo"]["name"],
                "router_mac": duthost.facts["router_mac"],
                "fdb_info": self.FDB_INFO_FILE,
                "dummy_mac_prefix": self.DUMMY_MAC_PREFIX,
            }
            self.__runPtfTest(ptfhost, "fdb_flush_test.FdbFlushTest", testParams)
        elif 'clear' == create_or_clear:
            duthost.command('sonic-clear fdb all')

        res = duthost.command('show mac')
        logging.info("show mac {} after {}".format(res['stdout_lines'], create_or_clear))


    def static_fdb_oper(self, duthost, fdb_oper_file):
        logging.info("fdb_oper_file {} ".format(fdb_oper_file))

        res = duthost.command('ls -al /etc/sonic')
        logging.info("show fdb files {} ".format(res['stdout_lines']))

        duthost.shell("docker exec -i swss swssconfig {}".format(fdb_oper_file), module_ignore_errors=True)


    @pytest.mark.parametrize("flush_type", FLUSH_TYPES)
    def testFdbFlush(self, ptfadapter, duthosts, rand_one_dut_hostname, ptfhost, tbinfo, request, flush_type):
        
        logging.info("test type {} ".format(flush_type))
        self.prepare_test(duthosts, rand_one_dut_hostname)

        if "dynamic" == flush_type or "mix" == flush_type:
            self.dynamic_fdb_oper(duthosts[rand_one_dut_hostname], tbinfo, ptfhost, 'create')
        
        if "static" == flush_type or "mix" == flush_type:
            self.static_fdb_oper(duthosts[rand_one_dut_hostname], self.fdb_set_json_file)
       
        if "interface" == flush_type or "mix" == flush_type:
            duthosts[rand_one_dut_hostname].shell("sudo config interface shutdown {}".format(self.target_port))

        # clear dynmaic/static fdb and startup interface anyway
        self.dynamic_fdb_oper(duthosts[rand_one_dut_hostname], tbinfo, ptfhost, 'clear')
        self.static_fdb_oper(duthosts[rand_one_dut_hostname], self.fdb_del_json_file)
        duthosts[rand_one_dut_hostname].shell("sudo config interface startup {}".format(self.target_port))

        # check the core files after test
        self.checkDutCorefiles(duthosts[rand_one_dut_hostname], False)

        if list(set(self.curr_exist_cores) - set(self.pre_exist_cores)):
            logging.info("pre_exist_cores {} ".format(self.pre_exist_cores))
            logging.info("curr_exist_cores {} ".format(self.curr_exist_cores))
            pytest_assert(False, "New core file created")

        duthosts[rand_one_dut_hostname].shell("sudo rm {}".format(os.path.join(DUT_WORKING_DIR, FDB_SET_JSON_FILE)), module_ignore_errors=True)
        duthosts[rand_one_dut_hostname].shell("sudo rm {}".format(os.path.join(DUT_WORKING_DIR, FDB_DEL_JSON_FILE)), module_ignore_errors=True)

        logging.info("Test end {} ".format(flush_type))
