"""
    SAI testing test bed setup.

    Notes:
        This test is used to setup the SAI testing environment,
         and start the SAI test cases
        from the PTF.
        For running this tests,
        please specify the sai test case
        folder via the parameters --sai_test_folder.

"""

import pytest
import logging
import time
from apscheduler.schedulers.background import BackgroundScheduler

from conftest import DUT_WORKING_DIR
from conftest import USR_BIN_DIR
from conftest import PORT_MAP_FILE_PATH
from conftest import PTF_TEST_ROOT_DIR
from conftest import SAI_TEST_REPORT_DIR_ON_PTF
from conftest import prepare_sai_test_container
from conftest import reload_dut_config
from conftest import revert_sai_test_container
from conftest import stop_and_rm_sai_test_container
from conftest import stop_dockers
from conftest import SAI_TEST_CONMUN_CASE_DIR_ON_PTF
from conftest import SAI_TEST_PTF_SAI_CASE_DIR_ON_PTF
from conftest import SAI_TEST_REPORT_TMP_DIR_ON_PTF
from conftest import SAI_TEST_T0_CASE_DIR_ON_PTF
from conftest import SAI_TEST_RESOURCE_ON_PTF_DIR
from conftest import SAI_TEST_INVOCATION_LOG_DIR
from conftest import WARM_TEST_ARGS
from conftest import PTF_TEST_CASE_TIMEOUT_IN_SEC
from conftest import start_sai_test_conatiner_with_retry
from conftest import get_sai_running_vendor_id
from conftest import get_sai_test_container_name
from conftest import saiserver_warmboot_config
from conftest import *  # noqa: F403 F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("ptf")
]


SAI_TEST_ENV_RESET_TIMES = 3
LIVENESS_CHECK_RETRY_TIMES = 12
LIVENESS_CHECK_INTERVAL_IN_SEC = 5
CONFIG_RELOAD_INTERVAL_IN_SEC = 30
TEST_INTERVAL_IN_SEC = 1


@pytest.fixture
def sai_test_env_check(creds, duthost, ptfhost, request):
    """
    Check the sai test environment.
    In this function, it will make a liveness check test to check
    if the sai test container is ready for test.
    This check has three stage:
    1. If the liveness check test failed, then it will
    make a environment reset.
    2. If the envvironment reset failed with attempts,
    then the test environment will be marked as failed.
    3. If environment marked as failed, this check will
    be failed in following round of check.

    Args:
        creds (dict): Credentials used to access the docker registry.
        duthost (SonicHost): The target device.
        dut_ip: dut ip address.
        ptfhost (AnsibleHost): The PTF server.
        test_case: Test case name used to make test.
        test_interface_params: Testbed switch interface
        request: Pytest request.
    """
    global IS_TEST_ENV_FAILED
    if IS_TEST_ENV_FAILED:
        logger.info("Test env check is failed in previous check. \
            Fails this check directly.")
        raise Exception("SAI Test env error.")
    check_test_env_with_retry(creds, duthost, ptfhost, request)


@pytest.fixture(scope="module")
def start_warm_reboot_watcher(duthost, request, ptfhost):
    """
    In this function
    1. First, a file will be created in the ptf container to interact with the ptf test
    2. Start a watcher daemon
    Args:
        duthost (SonicHost): The target device.
        request: Pytest request.
        ptfhost (AnsibleHost): The PTF server.
    """
    # install apscheduler before running
    logger.info("create and clean up the shared file with ptf")
    ptfhost.shell("touch {}".format("/tmp/warm_reboot"))
    ptfhost.shell("echo  > {}".format("/tmp/warm_reboot"))

    logger.info("start warm reboot watcher")
    close_apschedule_log()
    scheduler = BackgroundScheduler(
        {'apscheduler.job_defaults.max_instances': 1})

    scheduler.add_job(warm_reboot_change_handler, "cron", [
                      duthost, request, ptfhost], second="*/1")
    scheduler.start()


def close_apschedule_log():
    logging.getLogger("apscheduler.executors.default").propagate = False
    logging.getLogger("apscheduler.executors.default").setLevel(logging.ERROR)


def warm_reboot_change_handler(duthost, request, ptfhost):
    '''
    1. Loop to monitor whether the switch setup of the ptf test is completed
    2. If setup ends ('rebooting' is obtained from the file)
        i. Stop the saiserver container
        ii. Update the script to start saiserver so that the next startup is a warm reboot,
            using the previous configuration
        iii. Restart saiserver
        iv. Write 'post_reboot_done' in the shared file to notify ptf that warm reboot is done
    '''
    result = ptfhost.shell("cat {}".format("/tmp/warm_reboot"))
    if result["stdout_lines"] and result["stdout_lines"][0] == 'rebooting':
        duthost.shell(USR_BIN_DIR + "/saiserver.sh" + " stop")
        saiserver_warmboot_config(duthost, "start")
        result = ptfhost.shell(
            "echo rebooting_done > {}".format("/tmp/warm_reboot"))

        start_sai_test_conatiner_with_retry(
            duthost, get_sai_test_container_name(request))
        logger.info("saiserver start warm reboot")
        result = ptfhost.shell(
            "echo post_reboot_done > {}".format("/tmp/warm_reboot"))


@pytest.fixture(scope="module")
def sai_testbed(duthost,
                request,
                ptfhost,
                start_sai_test_container,
                prepare_ptf_server):
    """
    Pytest fixture to handle setup and cleanup for the SAI tests.

    Args:
        duthost (SonicHost): The target device.
        request: Pytest request.
        ptfhost (AnsibleHost): The PTF server.
        start_sai_test_container: fixture to start the sai test container.
        prepare_ptf_server: fixture to prepare the ptf server.
    """
    try:
        if not request.config.option.sai_test_skip_setup_env:
            dut_ip = duthost.host.options['inventory_manager'].get_host(
                duthost.hostname).vars['ansible_host']
            ptfhost.shell(
                "echo \"export PLATFORM={}\" >> ~/.bashrc".format(
                    get_sai_running_vendor_id(duthost)))
            ptfhost.shell(
                "echo \"export DUTIP={}\" >> ~/.bashrc".format(dut_ip))
            prepare_test_cases(ptfhost, request)
        yield
    finally:
        # ptfhost.shell(
        #    "sed -i \'/export PLATFORM={}/d\' \
        # ~/.bashrc".format(get_sai_running_vendor_id(duthost)))
        store_test_result(ptfhost)
        if not request.config.option.sai_test_keep_test_env:
            teardown_dut(duthost, ptfhost, request)


def check_test_env_with_retry(creds, duthost, ptfhost, request):
    """
    Args:
        creds (dict): Credentials used to access the docker registry.
        duthost (SonicHost): The target device.
        ptfhost (AnsibleHost): The PTF server.
        request: Pytest request.
    """
    global IS_TEST_ENV_FAILED
    for retry in range(SAI_TEST_ENV_RESET_TIMES):
        try:
            start_sai_test_conatiner_with_retry(
                duthost, get_sai_test_container_name(request))
            break
        except BaseException as e:
            logger.info(
                "Run test env check failed, reset the env, \
                    retry: [{}/{}], failed as {}.".format(
                    retry + 1, SAI_TEST_ENV_RESET_TIMES, e))
            if retry + 1 < SAI_TEST_ENV_RESET_TIMES:
                reset_sai_test_dut(duthost, creds, request)
                logger.info("Liveness check waiting {} \
                    sec for another retry.".format(
                    LIVENESS_CHECK_INTERVAL_IN_SEC))
                time.sleep(LIVENESS_CHECK_INTERVAL_IN_SEC)
            else:
                logger.info("Run test env check failed. \
                    Run test env is not ready. Error: {}".format(e))
                IS_TEST_ENV_FAILED = True
                raise e


def run_case_from_ptf(duthost,
                      dut_ip,
                      ptfhost,
                      test_case,
                      test_interface_params,
                      request,
                      warm_boot_stage=None):
    """
    Run the sai test cases from ptf.

    Args:
        duthost (SonicHost): The target device.
        dut_ip: dut ip address.
        ptfhost (AnsibleHost): The PTF server.
        test_case: Test case name used to make test.
        test_interface_params: Testbed switch interface
        request: Pytest request.
        warm_boot_stage: support warm reboot in three stage,
         WARM_TEST_STAGES, WARM_TEST_STARTING, WARM_TEST_POST
    """
    logger.info("Running test: {0}".format(test_case))
    logger.info("Sleep {} sec between tests.".format(TEST_INTERVAL_IN_SEC))
    time.sleep(TEST_INTERVAL_IN_SEC)
    test_param = ''

    if request.config.option.enable_sai_test \
       or request.config.option.enable_ptf_sai_test \
       or request.config.option.enable_ptf_warmboot_test \
       or request.config.option.enable_t0_warmboot_test:
        test_param = compose_sai_ptfv2_running_param(dut_ip, request)
    else:  # for old community test
        test_param = compose_community_running_param(dut_ip, request)
    logger.info("Test case param: [{}].".format(test_param))
    ptfhost.shell(("ptf {} {} --relax --xunit --test-case-timeout={} \
        --xunit-dir {} {}").format(test_case,
                                   test_interface_params,
                                   PTF_TEST_CASE_TIMEOUT_IN_SEC,
                                   SAI_TEST_REPORT_TMP_DIR_ON_PTF,
                                   test_param))
    logger.info("Test case [{}] passed.".format(test_case))


def compose_sai_ptfv2_running_param(dut_ip, request):
    """
    Run the sai test cases from ptf.

    Args:
        dut_ip: dut ip address.
        request: Pytest request.
    """
    test_param = ''
    test_set = ''
    warm_param = ''
    if request.config.option.enable_sai_test \
       or request.config.option.enable_t0_warmboot_test:
        test_set = SAI_TEST_T0_CASE_DIR_ON_PTF
    elif request.config.option.enable_ptf_sai_test \
        or request.config.option.enable_ptf_warmboot_test:   # noqa: E125
        test_set = SAI_TEST_PTF_SAI_CASE_DIR_ON_PTF
    else:
        raise Exception("Unknown Test set.")

    if request.config.option.enable_t0_warmboot_test \
       or request.config.option.enable_ptf_warmboot_test:
        warm_param = WARM_TEST_ARGS

    port_config_file = SAI_TEST_RESOURCE_ON_PTF_DIR + '/port_config.ini'
    config_db_file = SAI_TEST_RESOURCE_ON_PTF_DIR + '/config_db.json'
    if request.config.option.sai_port_config_file:
        port_config_file = request.config.option.sai_port_config_file
    if request.config.option.sai_config_db_file:
        config_db_file = request.config.option.sai_config_db_file

    test_param = "--test-dir {}".format(test_set)
    if request.config.option.sai_port_config_file:
        test_param += " \"--test-params=thrift_server='{}';\
            port_config_ini='{}';config_db_json='{}';{}\"".format(
            dut_ip,
            port_config_file,
            config_db_file,
            warm_param)
    else:
        test_param += " \"--test-params=thrift_server='{}';\
            config_db_json='{}';{}\"".format(
            dut_ip,
            config_db_file,
            warm_param)
    return test_param


def compose_community_running_param(dut_ip, request):
    """
    Run the community sai test cases from ptf.

    Args:
        dut_ip: dut ip address.
        request: Pytest request.
    """
    test_param = "--test-dir {} -t \"server='{}';port_map_file='{}'\"".format(
        SAI_TEST_CONMUN_CASE_DIR_ON_PTF,
        dut_ip,
        PORT_MAP_FILE_PATH)
    return test_param


def reset_sai_test_dut(duthost, creds, request):
    """
    Resets the sai test environment.
    This function will remove all the sai test container, reload config,
    re_deploy sai test container and start them.

    Args:
        duthost (SonicHost): The target device.
        creds (dict): Credentials used to access the docker registry.
        request: Pytest request.
    """
    logger.info("Start to reset dut environment to default.")
    stop_and_rm_sai_test_container(
        duthost, get_sai_test_container_name(request))
    revert_sai_test_container(
        duthost, creds,
        get_sai_test_container_name(request), request)
    reload_dut_config(duthost)
    logger.info("Resetting Dut env, \
        waiting {} sec for env gets \
            ready ...".format(CONFIG_RELOAD_INTERVAL_IN_SEC))
    time.sleep(CONFIG_RELOAD_INTERVAL_IN_SEC)
    stop_dockers(duthost)
    prepare_sai_test_container(
        duthost, creds, get_sai_test_container_name(request), request)
    start_sai_test_conatiner_with_retry(
        duthost, get_sai_test_container_name(request))


def sai_test_container_liveness_check(duthost,
                                      ptfhost,
                                      test_case,
                                      request,
                                      sai_test_interface_para):
    """
    Run a liveness check.
    This function will run a simple test to check
    if the sai test container is ready.

    Args:
        duthost (SonicHost): The target device.
        ptfhost (AnsibleHost): The PTF server.
        test_case: Test case name used to make the liveness check.
        request: Pytest request.
        sai_test_interface_para: Testbed switch interface
    """
    logger.info("Checking test environment before running test.")
    dut_ip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    start_sai_test_conatiner_with_retry(
        duthost, get_sai_test_container_name(request))
    for retry in range(LIVENESS_CHECK_RETRY_TIMES):
        try:
            run_case_from_ptf(
                duthost, dut_ip,
                ptfhost, test_case,
                sai_test_interface_para, request)
            break
        except BaseException as e:
            logger.info("Run liveness check [{}], \
                retry: [{}/{}] failed as {}".format(
                test_case, retry + 1, LIVENESS_CHECK_RETRY_TIMES,  e))
            if retry + 1 < LIVENESS_CHECK_RETRY_TIMES:
                logger.info(
                    "Liveness check waiting {} sec for another retry.".format(
                        LIVENESS_CHECK_INTERVAL_IN_SEC))
                time.sleep(LIVENESS_CHECK_INTERVAL_IN_SEC)
            else:
                logger.info(
                    "Liveness check failed. \
                        TestBed is not ready. Error: {}".format(e))
                raise e


def teardown_dut(duthost, ptfhost, request):
    """
    Tears down the SAI test.

    Args:
        duthost (SonicHost): The target device.
        ptfhost (AnsibleHost): The PTF server.
        request: Pytest request.
    """
    logger.info("Teardown SAI tests.")
    collect_test_result(duthost, ptfhost, request)
    cleanup_ptf(ptfhost, request)


def cleanup_ptf(ptfhost, request):
    """
    Cleanup PTF server, including delete test cases and root test folder.

    Args:
        ptfhost (AnsibleHost): The PTF server.
        request: Pytest request.
    """
    delete_sai_test_cases(ptfhost, request)
    delete_sai_test_folder(ptfhost)


def delete_sai_test_cases(ptfhost, request):
    """
    Delete SAI test cases on PTF.

    Args:
        ptfhost (AnsibleHost): The PTF server.
        request: Pytest request.
    """
    logger.info("Delete SAI tests cases")
    if request.config.option.enable_ptf_sai_test \
       or request.config.option.enable_ptf_warmboot_test:
        ptfhost.file(path="{0}".format(
            SAI_TEST_PTF_SAI_CASE_DIR_ON_PTF), state="absent")
    if request.config.option.enable_sai_test \
       or request.config.option.enable_t0_warmboot_test:
        ptfhost.file(path="{0}".format(
            SAI_TEST_T0_CASE_DIR_ON_PTF), state="absent")
    else:
        ptfhost.file(path="{0}".format(
            SAI_TEST_CONMUN_CASE_DIR_ON_PTF), state="absent")


def delete_sai_test_folder(ptfhost):
    """
    Delete SAI test root folder on PTF.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Delete SAI tests root folder: {0}.".format(PTF_TEST_ROOT_DIR))
    ptfhost.file(path=PTF_TEST_ROOT_DIR, state="absent")


def prepare_test_cases(ptfhost, request):
    """
    Prepare SAI test env including create root test folder and copy cases.

    Args:
        ptfhost (AnsibleHost): The PTF server.
        request: Pytest request.
    """
    logger.info("Preparing SAI test environment.")
    create_sai_test_folders(ptfhost)
    copy_sai_test_cases(ptfhost, request)


def create_sai_test_folders(ptfhost):
    """
    Create SAI test root folder on PTF server.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info(
        "Creating SAI tests root folder: {0}.".format(
            PTF_TEST_ROOT_DIR))
    ptfhost.shell(
        "mkdir -p {0}".format(PTF_TEST_ROOT_DIR))
    logger.info(
        "Creating SAI tests report folder: {0}.".format(
            SAI_TEST_REPORT_DIR_ON_PTF))
    ptfhost.shell("mkdir -p {0}".format(SAI_TEST_REPORT_DIR_ON_PTF))


def copy_sai_test_cases(ptfhost, request):
    """
    Copy SAI test cases to PTF server.

    Args:
        ptfhost (AnsibleHost): The PTF server.
        request: Pytest request.
    """
    if request.config.option.sai_test_dir:
        logger.info("Copying SAI test cases to PTF server.")
        ptfhost.copy(
            src=request.config.option.sai_test_dir,
            dest=PTF_TEST_ROOT_DIR + "/")
    else:
        logger.info("Skip Copying SAI test cases to PTF server.")


def collect_test_result(duthost, ptfhost, request):
    """
    Collect SAI test resport from DUT and PTF server.

    Args:
        duthost (SonicHost): The DUT.
        ptfhost (AnsibleHost): The PTF server.
        request: Pytest request.
    """
    logger.info("Collecting test result and related information.")
    # TODO : collect DUT test report
    collect_sonic_os_and_platform_info(duthost, request)
    collect_sai_test_report_xml(ptfhost, request)
    collect_sai_test_invocation_report(ptfhost, request)


def collect_sonic_os_and_platform_info(duthost, request):
    """
    Collect SONiC OS and Testbed info.

    Args:
        duthost (SonicHost): The DUT.
        request: Pytest request.
    """
    logger.info("Getting SONiC OS version and Testbed platform info.")

    out = duthost.shell("cd {0} && show version".format(DUT_WORKING_DIR))
    parse_info(out['stdout'], request.config.option.sai_test_report_dir)


def parse_info(content, report_path):
    """
    Parse the Version and platform info.
    Then output to the pipeline console as pipeline variable.

    Args:
        content: Ado pipeline stand output.
        report_path: sai test report dir.
    """
    OS_VERSION = ""
    PLT_VERSION = ""

    with open(report_path + "/version.txt", 'w+') as f:
        f.writelines(content)

    with open(report_path + "/version.txt", 'r') as f:
        cc = f.readlines()

        for line in cc:
            if "SONiC Software Version" in line:
                OS_VERSION = line.split(":")[1].strip()
            if "Platform" in line:
                PLT_VERSION = line.split(":")[1].strip()

    # TODO: Getting info should not depend on AZP,
    # later this logging command will be removed
    logger.info(
        'Get SONiC version: {0}, Platform: {1}'.format(
            OS_VERSION, PLT_VERSION))
    logger.info(
        '##vso[task.setvariable variable=OS_VERSION]{}'.format(
            OS_VERSION))
    logger.info(
        '##vso[task.setvariable variable=PLT_VERSION]{}'.format(
            PLT_VERSION))


def store_test_result(ptfhost):
    """
    Backup the test result

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info(
        "Copying file from folder: {0} to folder: {1}".format(
            SAI_TEST_REPORT_TMP_DIR_ON_PTF,
            SAI_TEST_REPORT_DIR_ON_PTF))
    try:
        logger.info("Copy test reports")
        ptfhost.shell("mkdir -p {}".format(
            SAI_TEST_REPORT_TMP_DIR_ON_PTF))
        ptfhost.shell("mkdir -p {}".format(
            SAI_TEST_REPORT_DIR_ON_PTF))
        ptfhost.shell("cp {0}/*.* {1}/".format(
            SAI_TEST_REPORT_TMP_DIR_ON_PTF,
            SAI_TEST_REPORT_DIR_ON_PTF))

    except BaseException as e:  # lgtm [py/catch-base-exception]
        logger.info(
            "Error when restoring test result: {}.".format(e))


def collect_sai_test_report_xml(ptfhost, request):
    """
    Collect SAI test report.

    Args:
        ptfhost (AnsibleHost): The PTF server.
        request: Pytest request.
    """
    logger.info("Collecting xunit SAI tests log from ptf")
    try:
        ptfhost.shell(
            "cd {0} && tar -czvf result.tar.gz *".format(
                SAI_TEST_REPORT_DIR_ON_PTF))
        ptfhost.fetch(
            src="{0}/result.tar.gz".format(SAI_TEST_REPORT_DIR_ON_PTF),
            dest=request.config.option.sai_test_report_dir + "/",
            flat=True)
    except BaseException as e:  # lgtm [py/catch-base-exception]
        logger.info("Error when Collecting xunit SAI tests log from ptf.\
             Failes as {0}".format(e))


def collect_sai_test_invocation_report(ptfhost, request):
    """
    Collect SAI test invocation report.

    Args:
        ptfhost (AnsibleHost): The PTF server.
        request: Pytest request.
    """
    logger.info("Collecting invocation log from ptf")
    try:

        logger.info("Copy test invocation logs")
        ptfhost.shell("mkdir -p {}".format(
            SAI_TEST_INVOCATION_LOG_DIR))
        if request.config.option.enable_sai_test \
                or request.config.option.enable_t0_warmboot_test:
            logger.info("Copy test T0 invocation logs")
            ptfhost.shell("mkdir -p {}/{}".format(
                SAI_TEST_INVOCATION_LOG_DIR, "T0"))
            ptfhost.shell("cp {}/logs/*.* {}/{}/".format(
                SAI_TEST_T0_CASE_DIR_ON_PTF,
                SAI_TEST_INVOCATION_LOG_DIR,
                "T0"))
        elif request.config.option.enable_ptf_sai_test \
                or request.config.option.enable_ptf_warmboot_test:
            logger.info("Copy test PTF invocation logs")
            ptfhost.shell("mkdir -p {}/{}".format(
                SAI_TEST_INVOCATION_LOG_DIR, "PTF"))
            ptfhost.shell("cp {}/logs/*.* {}/{}/".format(
                SAI_TEST_PTF_SAI_CASE_DIR_ON_PTF,
                SAI_TEST_INVOCATION_LOG_DIR,
                "PTF"))

        ptfhost.shell(
            "cd {0} && tar -czvf invocation.tar.gz *".format(
                SAI_TEST_INVOCATION_LOG_DIR))
        ptfhost.fetch(
            src="{0}/invocation.tar.gz".format(SAI_TEST_INVOCATION_LOG_DIR),
            dest=request.config.option.sai_test_report_dir + "/",
            flat=True)
    except BaseException as e:  # lgtm [py/catch-base-exception]
        logger.info("Error when Collecting xunit SAI tests log from ptf.\
             Failes as {0}".format(e))
