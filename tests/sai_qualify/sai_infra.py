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



@pytest.mark.parametrize("test_case", COMMUN_TEST_CASE)
def test_sai_from_ptf(sai_testbed, duthost, ptfhost, test_case, request):
    """
        trigger the test here
    """
    logger.info("Checking test environment before running test.")
    dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    start_sai_test_conatiner_with_retry(duthost, get_sai_test_container_name(request))
    try:
        logger.info("Running test: {0}".format(test_case))
        ptfhost.shell("ptf --test-dir {0} {1} {2} --relax --xunit --xunit-dir {3} \
            -t \"server='{4}';port_map_file='{5}'\""
        .format(
            SAI_TEST_CASE_DIR_ON_PTF, 
            test_case, 
            TEST_INTERFACE_PARAMS,
            SAI_TEST_REPORT_TMP_DIR_ON_PTF, 
            dut_ip, 
            PORT_MAP_FILE_PATH))
        logger.info("Test case [{}] passed.".format(test_case))
    except BaseException as e:               
        stop_and_rm_sai_test_container(duthost, get_sai_test_container_name(request))
        logger.info("Test case [{}] failed as {}".format(test_case, e))
        pytest.fail("Test case [{}] failed".format(test_case), e)
    finally:
        _store_test_result(ptfhost)


@pytest.fixture(scope="module")
def sai_testbed(
    duthost,
    request,
    ptfhost,
    start_sai_test_container,
    prepare_ptf_server):
    """
        Pytest fixture to handle setup and cleanup for the SAI tests.
    """
    try:        
        _setup_dut(ptfhost, request)
        yield  
    finally:  
        _teardown_dut(duthost, ptfhost, request)


def _setup_dut(ptfhost, request):
    """
        Sets up the SAI tests.
    """
    logger.info("Set up SAI tests.")

    _prepare_test_cases(ptfhost, request)


def _teardown_dut(duthost, ptfhost, request):
    """
        Tears down the SAI test.
    """
    logger.info("Teardown SAI tests.")
    _collect_test_result(duthost, ptfhost, request)
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
    ptfhost.file(path="{0}".format(SAI_TEST_CASE_DIR_ON_PTF), state="absent")


def _delete_sai_test_folder(ptfhost):
    """
    Delete SAI test root folder on PTF.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Delete SAI tests root folder: {0}.".format(PTF_TEST_ROOT_DIR))
    ptfhost.file(path=PTF_TEST_ROOT_DIR, state="absent")


def _prepare_test_cases(ptfhost, request):
    """
    Prepare SAI test env including create root test folder and copy cases.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Preparing SAI test environment.")
    _create_sai_test_folders(ptfhost)
    _copy_sai_test_cases(ptfhost, request)


def _create_sai_test_folders(ptfhost):
    """
    Create SAI test root folder on PTF server.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Creating SAI tests root folder: {0}.".format(PTF_TEST_ROOT_DIR))
    ptfhost.shell("mkdir -p {0}".format(PTF_TEST_ROOT_DIR))
    logger.info("Creating SAI tests report folder: {0}.".format(SAI_TEST_REPORT_DIR_ON_PTF))
    ptfhost.shell("mkdir -p {0}".format(SAI_TEST_REPORT_DIR_ON_PTF))


def _copy_sai_test_cases(ptfhost, request):
    """
    Copy SAI test cases to PTF server.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Copying SAI test cases to PTF server.")
    ptfhost.copy(src=request.config.option.sai_test_dir, dest=PTF_TEST_ROOT_DIR + "/")


def _collect_test_result(duthost, ptfhost, request):
    """
    Collect SAI test resport from DUT and PTF server.

    Args:
        duthost (SonicHost): The DUT.
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Collecting test result and related information.")
    # TODO : collect DUT test report
    _collect_sonic_os_and_platform_info(duthost, request)
    _collect_sai_test_report_xml(ptfhost, request)


def _collect_sonic_os_and_platform_info(duthost, request):
    """
    Collect SONiC OS and Testbed info.

    Args:
        duthost (SonicHost): The DUT.
    """
    logger.info("Getting SONiC OS version and Testbed platform info.")

    out = duthost.shell("cd {0} && show version".format(DUT_WORKING_DIR))
    _parse_info(out['stdout'], request.config.option.sai_test_report_dir)


def _parse_info(content, report_path):
    OS_VERSION=""
    PLT_VERSION=""

    with open(report_path + "/version.txt", 'w+') as f:
        f.writelines(content)

    with open(report_path + "/version.txt", 'r') as f:
        cc = f.readlines()

        for line in cc:
            if "SONiC Software Version" in line:
                OS_VERSION = line.split(":")[1].strip()
            if "Platform" in line:
                PLT_VERSION = line.split(":")[1].strip()

    # TODO: Getting info should not depend on AZP, later this logging command will be removed
    logger.info('Get SONiC version: {0}, Platform: {1}'.format(OS_VERSION, PLT_VERSION))
    logger.info('##vso[task.setvariable variable=OS_VERSION]{}'.format(OS_VERSION))
    logger.info('##vso[task.setvariable variable=PLT_VERSION]{}'.format(PLT_VERSION))


def _store_test_result(ptfhost):
    """
        Backup the test result
    
    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Copying file from folder: {0} to folder: {1}".format(
		SAI_TEST_REPORT_TMP_DIR_ON_PTF, 
		SAI_TEST_REPORT_DIR_ON_PTF))
    ptfhost.shell("cp {0}/*.* {1}/".format(
		SAI_TEST_REPORT_TMP_DIR_ON_PTF, 
		SAI_TEST_REPORT_DIR_ON_PTF))


def _collect_sai_test_report_xml(ptfhost, request):
    """
    Collect SAI test report.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Collecting xunit SAI tests log from ptf")
    ptfhost.shell("cd {0} && tar -czvf result.tar.gz *".format(SAI_TEST_REPORT_DIR_ON_PTF))
    ptfhost.fetch(
        src="{0}/result.tar.gz".format(SAI_TEST_REPORT_DIR_ON_PTF), 
        dest=request.config.option.sai_test_report_dir + "/", 
        flat=True)

