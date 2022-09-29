from conftest import *
from sai_infra import *
from cases_warmreboot import *


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("ptf")
]


def test_sai(
    sai_testbed, sai_test_env_check, creds, duthost, localhost, ptfhost, request, create_sai_test_interface_param
):
    for stage in WARM_TEST_STAGES:
        if stage == WARM_TEST_PRE_REBOOT:
            test_sai_pre_reboot(creds, duthost, ptfhost,
                                request, create_sai_test_interface_param)

        elif stage == WARM_TEST_REBOOTING:
            test_sai_rebooting(duthost, ptfhost,
                               request, create_sai_test_interface_param)

        elif stage == WARM_TEST_POST_REBOOT:
            test_sai_post_reboot(creds, duthost, ptfhost,
                                 request, create_sai_test_interface_param)


def test_sai_pre_reboot(creds, duthost, ptfhost, request, create_sai_test_interface_param):
    """
    Trigger warm reboot test here.

    Args:
        creds (dict): Credentials used to access the docker registry.
        duthost (SonicHost): The target device.
        ptfhost (AnsibleHost): The PTF server.
        request: Pytest request.
        create_sai_test_interface_param: Testbed switch interface
    """
    test_failed = False
    check_test_env_with_retry(creds, duthost, ptfhost,
                              request, create_sai_test_interface_param)
    logger.info("sai_test_keep_test_env {}".format(
        request.config.option.sai_test_keep_test_env))
    dut_ip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    common_configures = [
        'false' if index == 0 else 'true'for index, _ in enumerate(PRE_REBOOT_TEST_CASE)]
    for ptf_sai_test_case, common_configure in zip(PRE_REBOOT_TEST_CASE, common_configures):
        try:
            sai_test_interface_para = create_sai_test_interface_param
            run_case_from_ptf(duthost, dut_ip, ptfhost, ptf_sai_test_case,
                              sai_test_interface_para, request, WARM_TEST_PRE_REBOOT, COMMON_CONFIG_FORMAT.format(common_configure))
        except BaseException as e:
            test_failed = True
            logger.info("Test case [{}] failed, failed as {}.".format(
                ptf_sai_test_case, e))
            stop_and_rm_sai_test_container(
                duthost, get_sai_test_container_name(request))
            pytest.fail("Test case [{}] failed".format(ptf_sai_test_case), e)
        finally:
            store_test_result(ptfhost)
        if not test_failed:
            if request.config.option.always_stop_sai_test_container:
                stop_and_rm_sai_test_container(
                    duthost, get_sai_test_container_name(request))


def test_sai_rebooting(duthost, ptfhost, request, create_sai_test_interface_param):
    """
    Trigger warm reboot test here.

    Args:
        duthost (SonicHost): The target device.
        ptfhost (AnsibleHost): The PTF server.
        sai_test_case: Test case name used to make test.
        request: Pytest request.
        create_sai_test_interface_param: Testbed switch interface
    """
    test_failed = False
    saiserver_warmboot_config(duthost, "start")
    stop_and_rm_sai_test_container(
        duthost, get_sai_test_container_name(request))
    dut_ip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    common_configures = ['true'for _ in REBOOTING_TEST_CASE]
    for ptf_sai_test_case, common_configure in zip(REBOOTING_TEST_CASE, common_configures):
        try:
            sai_test_interface_para = create_sai_test_interface_param
            run_case_from_ptf(duthost, dut_ip, ptfhost, ptf_sai_test_case,
                              sai_test_interface_para, request, WARM_TEST_REBOOTING, COMMON_CONFIG_FORMAT.format(common_configure))
        except BaseException as e:
            test_failed = True
            logger.info("Test case [{}] failed, failed as {}.".format(
                ptf_sai_test_case, e))
            stop_and_rm_sai_test_container(
                duthost, get_sai_test_container_name(request))
            pytest.fail("Test case [{}] failed".format(ptf_sai_test_case), e)
        finally:
            store_test_result(ptfhost)
        if not test_failed:
            if request.config.option.always_stop_sai_test_container:
                stop_and_rm_sai_test_container(
                    duthost, get_sai_test_container_name(request))


def test_sai_post_reboot(creds, duthost, ptfhost, request, create_sai_test_interface_param):
    """
    Trigger warm reboot test here.

    Args:
        creds (dict): Credentials used to access the docker registry.
        duthost (SonicHost): The target device.
        ptfhost (AnsibleHost): The PTF server.
        request: Pytest request.
        create_sai_test_interface_param: Testbed switch interface
    """
    test_failed = False
    check_test_env_with_retry(creds, duthost, ptfhost,
                              request, create_sai_test_interface_param)
    logger.info("sai_test_keep_test_env {}".format(
        request.config.option.sai_test_keep_test_env))
    dut_ip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    common_configures = ['true'for _ in POST_REBOOT_TEST_CASE]
    for ptf_sai_test_case, common_configure in zip(POST_REBOOT_TEST_CASE, common_configures):
        try:
            sai_test_interface_para = create_sai_test_interface_param
            run_case_from_ptf(duthost, dut_ip, ptfhost, ptf_sai_test_case,
                              sai_test_interface_para, request, WARM_TEST_POST_REBOOT, COMMON_CONFIG_FORMAT.format(common_configure))
        except BaseException as e:
            test_failed = True
            logger.info("Test case [{}] failed, failed as {}.".format(
                ptf_sai_test_case, e))
            stop_and_rm_sai_test_container(
                duthost, get_sai_test_container_name(request))
            pytest.fail("Test case [{}] failed".format(ptf_sai_test_case), e)
        finally:
            store_test_result(ptfhost)
        if not test_failed:
            if request.config.option.always_stop_sai_test_container:
                stop_and_rm_sai_test_container(
                    duthost, get_sai_test_container_name(request))
