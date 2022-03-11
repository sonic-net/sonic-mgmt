"""
    SAI testing test bed setup.

    Notes:
        This test is used to setup the SAI testing environment, and start the SAI test cases
        from the PTF.
        For running this tests, please specify the sai test case folder via the parameters --sai_test_folder.

"""

import pytest, socket, sys, itertools, logging
import ptf.packet as scapy
import tests.common.system_utils.docker as docker
import tests.common.fixtures.ptfhost_utils as ptfhost_utils
import time

from conftest import *
from community_cases import *

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("ptf")
]


SAI_TEST_ENV_RESET_TIMES = 3
LIVENESS_CHECK_RETRY_TIMES = 12
LIVENESS_CHECK_INTERVAL_IN_SEC = 5
CONFIG_RELOAD_INTERVAL_IN_SEC = 30
TEST_INTERVAL_IN_SEC = 1


@pytest.mark.parametrize("community_test_case", COMMUN_TEST_CASE)
def test_commun_sai_from_ptf(
    sai_testbed, sai_test_env_check, creds, duthost, ptfhost, community_test_case, request, create_sai_test_interface_param):
    """
        trigger the test here
    """
    logger.info("sai_test_keep_test_env {}".format(request.config.option.sai_test_keep_test_env))
    dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    try:
        sai_test_interface_para = create_sai_test_interface_param
        run_case_from_ptf(duthost, dut_ip, ptfhost, community_test_case, sai_test_interface_para, request)
    except BaseException as e:
        logger.info("Test case [{}] failed, trying to restart sai test container, failed as {}.".format(community_test_case, e))               
        stop_and_rm_sai_test_container(duthost, get_sai_test_container_name(request))        
        pytest.fail("Test case [{}] failed".format(community_test_case), e)
    finally:
        __store_test_result(ptfhost)


@pytest.mark.parametrize("ptf_sai_test_case", PTF_SAI_TEST_CASE)
def test_ptf_sai_from_ptf(
    sai_testbed, sai_test_env_check, creds, duthost, ptfhost, ptf_sai_test_case, request, create_sai_test_interface_param):
    """
        trigger the test here
    """
    logger.info("sai_test_keep_test_env {}".format(request.config.option.sai_test_keep_test_env))
    dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    try:
        sai_test_interface_para = create_sai_test_interface_param
        run_case_from_ptf(duthost, dut_ip, ptfhost, ptf_sai_test_case, sai_test_interface_para, request)
        if request.config.option.always_stop_sai_test_container:
            stop_and_rm_sai_test_container(duthost, get_sai_test_container_name(request))
    except BaseException as e:
        logger.info("Test case [{}] failed, trying to restart sai test container, failed as {}.".format(ptf_sai_test_case, e))               
        stop_and_rm_sai_test_container(duthost, get_sai_test_container_name(request))        
        pytest.fail("Test case [{}] failed".format(ptf_sai_test_case), e)
    finally:
        __store_test_result(ptfhost)


@pytest.fixture
def sai_test_env_check(creds, duthost, ptfhost, request, create_sai_test_interface_param):
    """
        Check the sai test environment.
        In this function, it will make a liveness check test to check if the sai test container is ready for test.
        This check has three stage:
        1. If the liveness check test failed, then it will make a environment reset.
        2. If the envvironment reset failed with attempts, then the test environment will be marked as failed.
        3. If environment marked as failed, this check will be failed in following round of check. 
    """
    global IS_TEST_ENV_FAILED
    if IS_TEST_ENV_FAILED:
        logger.info("Test env check is failed in previous check. Fails this check directly.")
        raise Exception("SAI Test env error.")

    for retry in range(SAI_TEST_ENV_RESET_TIMES):
        try:
            sai_test_interface_para = create_sai_test_interface_param
            if request.config.option.enable_ptf_sai_test:
                saiv2_test_container_liveness_check(duthost, request)
            else:
                sai_test_container_liveness_check(duthost, ptfhost, PROBE_TEST_CASE, request, sai_test_interface_para)
            break
        except BaseException as e:  
            logger.info("Run test env check failed, reset the env, retry: [{}/{}], failed as {}.".format(retry + 1, SAI_TEST_ENV_RESET_TIMES, e))
            if retry + 1 < SAI_TEST_ENV_RESET_TIMES:
                reset_sai_test_dut(duthost, creds, request)
                logger.info("Liveness check waiting {} sec for another retry.".format(LIVENESS_CHECK_INTERVAL_IN_SEC))
                time.sleep(LIVENESS_CHECK_INTERVAL_IN_SEC)
            else:
                logger.info("Run test env check failed. Run test env is not ready. Error: {}".format(e))
                IS_TEST_ENV_FAILED = True
                raise e


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
        __setup_dut(ptfhost, request)
        yield  
    finally:  
        __store_test_result(ptfhost)
        if not request.config.option.sai_test_keep_test_env:
            __teardown_dut(duthost, ptfhost, request)


def run_case_from_ptf(duthost, dut_ip, ptfhost, test_case, test_interface_params, request):
    """
    Run the sai test cases from ptf.
    Args:
        duthost (SonicHost): The target device.
        dut_ip: dut ip address.
        ptfhost (AnsibleHost): The PTF server.
        test_case: Test case name used to make test.
        test_interface_params: Testbed switch interface
    """
    logger.info("Running test: {0}".format(test_case))
    logger.info("Sleep {} sec between tests.".format(TEST_INTERVAL_IN_SEC))
    time.sleep(TEST_INTERVAL_IN_SEC)
    cmds = []
    test_para = "-t \"server='{}';port_map_file='{}'\" --test-dir {}".format(dut_ip, PORT_MAP_FILE_PATH, SAI_TEST_CONMUN_CASE_DIR_ON_PTF)
    if request.config.option.enable_ptf_sai_test:
        cmds.append("echo \"export PLATFORM={}\" >> ~/.bashrc".format(get_sai_running_vendor_id(duthost)))
        test_para = "\"--test-params=thrift_server='{}'\" --test-dir {}".format(dut_ip, SAI_TEST_PTF_SAI_CASE_DIR_ON_PTF)
    
    cmds.append(("ptf {} {} --relax --xunit --xunit-dir {} {}")
    .format( 
        test_case, 
        test_interface_params,
        SAI_TEST_REPORT_TMP_DIR_ON_PTF, 
        test_para))
    ptfhost.shell_cmds(cmds=cmds)
    logger.info("Test case [{}] passed.".format(test_case))


def reset_sai_test_dut(duthost, creds, request):
    """
        Resets the sai test environment.
        This function will remove all the sai test container, reload config, re_deploy sai test container and start them.
    Args:
        duthost (SonicHost): The target device.
        creds (dict): Credentials used to access the docker registry.
        request: Pytest request. 
    """
    logger.info("Start to reset dut environment to default.")
    stop_and_rm_sai_test_container(duthost, get_sai_test_container_name(request))
    revert_sai_test_container(duthost, creds, get_sai_test_container_name(request), request)    
    reload_dut_config(duthost)
    logger.info("Resetting Dut env, waiting {} sec for env gets ready ...".format(CONFIG_RELOAD_INTERVAL_IN_SEC))
    time.sleep(CONFIG_RELOAD_INTERVAL_IN_SEC)
    stop_dockers(duthost)
    prepare_sai_test_container(duthost, creds, get_sai_test_container_name(request), request)
    start_sai_test_conatiner_with_retry(duthost, get_sai_test_container_name(request))


def sai_test_container_liveness_check(duthost, ptfhost, test_case, request, sai_test_interface_para):
    """
        Run a liveness check.
        This function will run a simple test to check if the sai test container is ready.
    Args:
        duthost (SonicHost): The target device.        
        ptfhost (AnsibleHost): The PTF server.
        test_case: Test case name used to make the liveness check.
        request: Pytest request. 
        test_interface_params: Testbed switch interface
    """
    logger.info("Checking test environment before running test.")
    dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    start_sai_test_conatiner_with_retry(duthost, get_sai_test_container_name(request))
    for retry in range(LIVENESS_CHECK_RETRY_TIMES):
        try:
            run_case_from_ptf(duthost, dut_ip, ptfhost, test_case, sai_test_interface_para, request)
            break
        except BaseException as e:  
            logger.info("Run liveness check [{}], retry: [{}/{}] failed as {}".format(test_case, retry + 1, LIVENESS_CHECK_RETRY_TIMES,  e))
            if retry + 1 < LIVENESS_CHECK_RETRY_TIMES:
                logger.info("Liveness check waiting {} sec for another retry.".format(LIVENESS_CHECK_INTERVAL_IN_SEC))
                time.sleep(LIVENESS_CHECK_INTERVAL_IN_SEC)
            else:
                logger.info("Liveness check failed. TestBed is not ready. Error: {}".format(e))
                raise e


def saiv2_test_container_liveness_check(duthost, request):
    """
        Run a liveness check.
        This function will run a simple test to check if the sai test container is ready.
    Args:
        duthost (SonicHost): The target device.        
        test_case: Test case name used to make the liveness check.
        request: Pytest request. 
    """
    logger.info("Checking test environment before running test.")
    try:
        start_sai_test_conatiner_with_retry(duthost, get_sai_test_container_name(request))
    except BaseException as e:  
        logger.info("Liveness check failed. TestBed is not ready. Error: {}".format(e))
        raise e


def __setup_dut(ptfhost, request):
    """
        Sets up the SAI tests.
    Args:
        ptfhost (AnsibleHost): The PTF server.
        request: Pytest request. 
    """
    logger.info("Set up SAI tests.")

    __prepare_test_cases(ptfhost, request)


def __teardown_dut(duthost, ptfhost, request):
    """
        Tears down the SAI test.
    """
    logger.info("Teardown SAI tests.")
    __collect_test_result(duthost, ptfhost, request)
    __cleanup_ptf(ptfhost, request)


def __cleanup_ptf(ptfhost, request):
    """
    Cleanup PTF server, including delete test cases and root test folder.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    __delete_sai_test_cases(ptfhost, request)
    __delete_sai_test_folder(ptfhost)


def __delete_sai_test_cases(ptfhost, request):
    """
    Delete SAI test cases on PTF.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Delete SAI tests cases")
    if request.config.option.enable_ptf_sai_test:
        ptfhost.file(path="{0}".format(SAI_TEST_PTF_SAI_CASE_DIR_ON_PTF), state="absent")
    else:
        ptfhost.file(path="{0}".format(SAI_TEST_CONMUN_CASE_DIR_ON_PTF), state="absent")


def __delete_sai_test_folder(ptfhost):
    """
    Delete SAI test root folder on PTF.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Delete SAI tests root folder: {0}.".format(PTF_TEST_ROOT_DIR))
    ptfhost.file(path=PTF_TEST_ROOT_DIR, state="absent")


def __prepare_test_cases(ptfhost, request):
    """
    Prepare SAI test env including create root test folder and copy cases.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Preparing SAI test environment.")
    __create_sai_test_folders(ptfhost)
    __copy_sai_test_cases(ptfhost, request)


def __create_sai_test_folders(ptfhost):
    """
    Create SAI test root folder on PTF server.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Creating SAI tests root folder: {0}.".format(PTF_TEST_ROOT_DIR))
    ptfhost.shell("mkdir -p {0}".format(PTF_TEST_ROOT_DIR))
    logger.info("Creating SAI tests report folder: {0}.".format(SAI_TEST_REPORT_DIR_ON_PTF))
    ptfhost.shell("mkdir -p {0}".format(SAI_TEST_REPORT_DIR_ON_PTF))


def __copy_sai_test_cases(ptfhost, request):
    """
    Copy SAI test cases to PTF server.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Copying SAI test cases to PTF server.")
    ptfhost.copy(src=request.config.option.sai_test_dir, dest=PTF_TEST_ROOT_DIR + "/")


def __collect_test_result(duthost, ptfhost, request):
    """
    Collect SAI test resport from DUT and PTF server.

    Args:
        duthost (SonicHost): The DUT.
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Collecting test result and related information.")
    # TODO : collect DUT test report
    __collect_sonic_os_and_platform_info(duthost, request)
    __collect_sai_test_report_xml(ptfhost, request)


def __collect_sonic_os_and_platform_info(duthost, request):
    """
    Collect SONiC OS and Testbed info.

    Args:
        duthost (SonicHost): The DUT.
    """
    logger.info("Getting SONiC OS version and Testbed platform info.")

    out = duthost.shell("cd {0} && show version".format(DUT_WORKING_DIR))
    __parse_info(out['stdout'], request.config.option.sai_test_report_dir)


def __parse_info(content, report_path):
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


def __store_test_result(ptfhost):
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


def __collect_sai_test_report_xml(ptfhost, request):
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

