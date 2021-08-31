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

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("ptf")
]


def test_sai_from_ptf(sai_testbed, duthost, ptfhost):
    """
        trigger the test here
    """
    _run_tests(duthost, ptfhost)


@pytest.fixture(scope="module")
def sai_testbed(
    duthost,
    creds,
    request,
    ptfhost,
    start_saiserver,
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

    _prepare_test_env(ptfhost, request)


def _teardown_dut(duthost, ptfhost, request):
    """
        Tears down the SAI test.
    """
    logger.info("Teardown SAI tests.")
    _collect_test_result(duthost, ptfhost, request)
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
    ptfhost.file(path="{0}/{1}".format(PTF_TEST_ROOT_DIR, SAI_TEST_CASE_DIR_ON_PTF), state="absent")


def _delete_sai_test_folder(ptfhost):
    """
    Delete SAI test root folder on PTF.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Delete SAI tests root folder: {0}.".format(PTF_TEST_ROOT_DIR))
    ptfhost.file(path=PTF_TEST_ROOT_DIR, state="absent")


def _prepare_test_env(ptfhost, request):
    """
    Prepare SAI test env including create root test folder and copy cases.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Preparing SAI test environment.")
    _create_sai_test_folder(ptfhost)
    _copy_sai_test_cases(ptfhost, request.config.option.sai_test_dir)


def _create_sai_test_folder(ptfhost):
    """
    Create SAI test root folder on PTF server.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Creating SAI tests root folder: {0}.".format(PTF_TEST_ROOT_DIR))
    ptfhost.shell("mkdir -p {0}".format(PTF_TEST_ROOT_DIR))


def _copy_sai_test_cases(ptfhost, SAI_TEST_DIR):
    """
    Copy SAI test cases to PTF server.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Copying SAI test cases to PTF server.")
    ptfhost.shell("cd {0} && mkdir -p {1} && mkdir -p {2}".format(PTF_TEST_ROOT_DIR, SAI_TEST_CASE_DIR_ON_PTF, SAI_TEST_REPORT_DIR_ON_PTF))
    ptfhost.copy(src=SAI_TEST_DIR, dest=PTF_TEST_ROOT_DIR + "/" + SAI_TEST_CASE_DIR_ON_PTF)


def _collect_test_result(duthost, ptfhost, request):
    """
    Collect SAI test resport from DUT and PTF server.

    Args:
        duthost (SonicHost): The DUT.
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Collecting test result and related information.")
    _collect_sonic_os_and_platform_info(duthost, request.config.option.sai_test_report_dir)
    _collect_sai_test_report_xml(ptfhost, request.config.option.sai_test_report_dir)


def _run_tests(dut, ptfhost):
    """
    Run SAI tests.

    Args:
        duthost (SonicHost): The DUT.
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Start SAI tests")

    test_case = "L2AccessToAccessVlanTest"
    dut_ip = dut.host.options['inventory_manager'].get_host(dut.hostname).vars['ansible_host']
    ptfhost.shell("cd {0} && ptf --test-dir {1} sail2.{2} --interface '0@eth0' --interface '1@eth1' --xunit --xunit-dir {3} -t \"server='{4}';port_map_file='{5}'\"".format(PTF_TEST_ROOT_DIR, SAI_TEST_CASE_DIR_ON_PTF, test_case, SAI_TEST_REPORT_DIR_ON_PTF, dut_ip, PORT_MAP_FILE_PATH))


def _cleanup_dut(duthost):
    """
    Clean up DUT.

    Args:
        duthost (SonicHost): The DUT.
    """

    logger.info("Cleanup DUT.")
    duthost.file(path="{0}/version.txt".format(DUT_WORKING_DIR), state="absent")


def _collect_sonic_os_and_platform_info(duthost, SAI_TEST_REPORT_DIR):
    """
    Collect SONiC OS and Testbed info.

    Args:
        duthost (SonicHost): The DUT.
    """
    logger.info("Getting SONiC OS version and Testbed platform info.")
    duthost.shell("cd {0} && show version > version.txt".format(DUT_WORKING_DIR))
    duthost.fetch(src="{0}/version.txt".format(DUT_WORKING_DIR), dest=SAI_TEST_REPORT_DIR + "/", flat=True)


def _collect_sai_test_report_xml(ptfhost, SAI_TEST_REPORT_DIR):
    """
    Collect SAI test report.

    Args:
        ptfhost (AnsibleHost): The PTF server.
    """
    logger.info("Collecting xunit SAI tests log from ptf")
    ptfhost.shell("cd {0}/{1} && tar -czvf result.tar.gz *".format(PTF_TEST_ROOT_DIR, SAI_TEST_REPORT_DIR_ON_PTF))
    ptfhost.fetch(src="{0}/{1}/result.tar.gz".format(PTF_TEST_ROOT_DIR,SAI_TEST_REPORT_DIR_ON_PTF), dest=SAI_TEST_REPORT_DIR + "/", flat=True)

