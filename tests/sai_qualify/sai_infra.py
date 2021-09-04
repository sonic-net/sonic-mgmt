"""
    SAI testing test bed setup.

    Notes:
        This test is used to setup the SAI testing environment, and start the SAI test cases
        from the PTF.
        For running this tests, please specify the sai test case folder via the parameters --sai_test_folder.

"""

import pytest, socket, sys, itertools, logging
from struct import pack, unpack
from ptf.mask import Mask
import ptf.packet as scapy
import tests.common.system_utils.docker as docker
import tests.common.fixtures.ptfhost_utils as ptfhost_utils
from conftest import *
from community_cases import *

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("ptf")
]

TEST_INTERFACE_PARAMS = "--interface '0@eth0' --interface '1@eth1' --interface '2@eth2' \
    --interface '3@eth3' --interface '4@eth4' --interface '5@eth5' --interface '6@eth6' \
    --interface '7@eth7'"
CONFIG = {}


@pytest.mark.parametrize("test_case", COMMUN_TEST_CASE)
def test_sai_from_ptf(sai_testbed, duthost, ptfhost, test_case):
    """
        trigger the test here
    """
    logger.info("Checking test environment before running test.")
    dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    start_saiserver_with_retry(duthost)
    try:
        logger.info("Running test: {0}".format(test_case))
        ptfhost.shell("cd {0} && ptf --test-dir {1} {2} {3} --relax --xunit --xunit-dir {4} -t \"server='{5}';port_map_file='{6}'\""
        .format(
            CONFIG['SAI_TEST_ROOT_DIR'], 
            SAI_TEST_CASE_DIR_ON_PTF, 
            test_case, 
            TEST_INTERFACE_PARAMS,
            SAI_TEST_REPORT_TMP_DIR_ON_PTF, 
            dut_ip, 
            PORT_MAP_FILE_PATH))
        logger.info("Test case [{}] passed.".format(test_case))
    except BaseException:               
        stop_and_rm_saiserver(duthost)
        pytest.fail("Test case [{}] failed.".format(test_case))
    finally:
        _store_test_result(ptfhost)


@pytest.fixture(scope="module")
def sai_testbed(
    duthost,
    request,
    ptfhost,
    start_saiserver,
    prepare_ptf_server):
    """
        Pytest fixture to handle setup and cleanup for the SAI tests.
    """
    _parse_config(request)
    try:        
        _setup_dut(ptfhost)
        yield  
    finally:  
        _teardown_dut(duthost, ptfhost)


def _setup_dut(ptfhost):
    """
        Sets up the SAI tests.
    """
    logger.info("Set up SAI tests.")
    _prepare_test_cases(ptfhost)


def _teardown_dut(duthost, ptfhost):
    """
        Tears down the SAI test.
    """
    logger.info("Teardown SAI tests.")
    _collect_test_result(duthost, ptfhost)
    _cleanup_dut(duthost)
    _cleanup_ptf(ptfhost)


def _cleanup_ptf(ptfhost):
    """
    Cleanup PTF server, including delete test cases and root test folder.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    _delete_sai_test_cases(ptfhost)
    _delete_sai_test_folder(ptfhost)


def _delete_sai_test_cases(ptfhost):
    """
    Delete SAI test cases on PTF.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Delete SAI tests cases")
    ptfhost.file(path="{0}/{1}".format(CONFIG['SAI_TEST_ROOT_DIR'], SAI_TEST_CASE_DIR_ON_PTF), state="absent")


def _delete_sai_test_folder(ptfhost):
    """
    Delete SAI test root folder on PTF.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Delete SAI tests root folder: {0}.".format(CONFIG['SAI_TEST_ROOT_DIR']))
    ptfhost.file(path=CONFIG['SAI_TEST_ROOT_DIR'], state="absent")


def _prepare_test_cases(ptfhost):
    """
    Prepare SAI test env including create root test folder and copy cases.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Preparing SAI test environment.")
    _create_sai_test_folders(ptfhost)
    _copy_sai_test_cases(ptfhost)


def _create_sai_test_folders(ptfhost):
    """
    Create SAI test root folder on PTF server.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Creating SAI tests root folder: {0}.".format(CONFIG['SAI_TEST_ROOT_DIR']))
    ptfhost.shell("mkdir -p {0}".format(CONFIG['SAI_TEST_ROOT_DIR']))
    logger.info("Creating SAI tests root folder: {0}/{1}.".format(
        CONFIG['SAI_TEST_ROOT_DIR'], 
        SAI_TEST_REPORT_DIR_ON_PTF))
    ptfhost.shell("mkdir -p {0}/{1}".format(CONFIG['SAI_TEST_ROOT_DIR'], SAI_TEST_REPORT_DIR_ON_PTF))


def _copy_sai_test_cases(ptfhost):
    """
    Copy SAI test cases to PTF server.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Copying SAI test cases to PTF server.")
    ptfhost.shell("cd {0} && mkdir -p {1} && mkdir -p {2}".format(
        CONFIG['SAI_TEST_ROOT_DIR'], 
        SAI_TEST_CASE_DIR_ON_PTF, SAI_TEST_REPORT_DIR_ON_PTF))
    ptfhost.copy(src=CONFIG['LOCAL_SAI_TEST_DIR'], dest=CONFIG['SAI_TEST_ROOT_DIR'] + "/" + SAI_TEST_CASE_DIR_ON_PTF)


def _collect_test_result(duthost, ptfhost):
    """
    Collect SAI test resport from DUT and PTF server.

    Args:
        duthost (SonicHost): The DUT.
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Collecting test result and related information.")
    # TODO : collect DUT test report
    _collect_sonic_os_and_platform_info(duthost)
    _collect_sai_test_report_xml(ptfhost)
    

def _cleanup_dut(duthost):
    """
    Clean up DUT.

    Args:
        duthost (SonicHost): The DUT.
    """

    logger.info("Cleanup DUT.")
    duthost.file(path="{0}/version.txt".format(CONFIG['DUT_WORKING_DIR']), state="absent")


def _collect_sonic_os_and_platform_info(duthost):
    """
    Collect SONiC OS and Testbed info.

    Args:
        duthost (SonicHost): The DUT.
    """
    logger.info("Getting SONiC OS version and Testbed platform info.")
    duthost.shell("cd {0} && show version > version.txt".format(CONFIG['DUT_WORKING_DIR']))
    duthost.fetch(src="{0}/version.txt".format(CONFIG['DUT_WORKING_DIR']), dest=CONFIG['SAI_TEST_RESULT_DIR'] + "/", flat=True)


def _store_test_result(ptfhost):
    """
        Backup the test result
    
    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Copying file from folder: {0}/{1} to folder: {0}/{2}".format(
        CONFIG['SAI_TEST_ROOT_DIR'], 
        SAI_TEST_REPORT_TMP_DIR_ON_PTF, 
        SAI_TEST_REPORT_DIR_ON_PTF))
    ptfhost.shell("cp {0}/{1}/*.* {0}/{2}/".format(
        CONFIG['SAI_TEST_ROOT_DIR'], 
        SAI_TEST_REPORT_TMP_DIR_ON_PTF, 
        SAI_TEST_REPORT_DIR_ON_PTF))
    

def _collect_sai_test_report_xml(ptfhost):
    """
    Collect SAI test report.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Collecting xunit SAI tests log from ptf")
    ptfhost.shell("cd {0}/{1} && tar -czvf result.tar.gz *".format(
        CONFIG['SAI_TEST_ROOT_DIR'], 
        SAI_TEST_REPORT_DIR_ON_PTF))
    ptfhost.fetch(src="{0}/{1}/result.tar.gz".format
    (CONFIG['SAI_TEST_ROOT_DIR'],
    SAI_TEST_REPORT_DIR_ON_PTF), 
    dest=CONFIG['SAI_TEST_RESULT_DIR'] + "/", flat=True)


def _parse_config(request):

    CONFIG['LOCAL_SAI_TEST_DIR'] = request.config.option.sai_test_dir
    CONFIG['SAI_TEST_RESULT_DIR'] = request.config.option.sai_test_report_dir

    if not CONFIG['LOCAL_SAI_TEST_DIR'] or not CONFIG['SAI_TEST_RESULT_DIR']:
        raise AttributeError("Needs to specify parameter: sai_test_dir or sai_test_reprot_dir")
    
    CONFIG['DUT_WORKING_DIR'] = DUT_WORKING_DIR
    CONFIG['SAI_TEST_ROOT_DIR'] = PTF_TEST_ROOT_DIR

    logger.info("Parsed config : {0}".format(CONFIG))
