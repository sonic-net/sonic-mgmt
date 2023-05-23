import pytest
import logging

from .cases_t0_warmreboot import WARM_REBOOT_T0_TEST_CASE
from .conftest import get_sai_test_container_name
from .conftest import saiserver_warmboot_config
from .conftest import stop_and_rm_sai_test_container
from .sai_infra import run_case_from_ptf
from .sai_infra import store_test_result
from .sai_infra import *  # noqa: F403 F401
from .conftest import *  # noqa: F403 F401


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("ptf"),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]


@pytest.mark.parametrize("sai_test_case", WARM_REBOOT_T0_TEST_CASE)
def test_sai(
            sai_testbed,
            sai_test_env_check,
            creds,
            duthost,
            localhost,
            ptfhost,
            sai_test_case,
            request,
            create_sai_test_interface_param,
            start_warm_reboot_watcher):
    """
    Trigger warm reboot test here.

    Args:
        sai_testbed: Fixture which can help prepare the sai testbed.
        sai_test_env_check: Fixture, use to check the test env.
        creds (dict): Credentials used to access the docker registry.
        duthost (SonicHost): The target device.
        ptfhost (AnsibleHost): The PTF server.
        sai_test_case: Test case name used to make test.
        request: Pytest request.
        create_sai_test_interface_param: Testbed switch interface
    """
    logger.info("sai_test_keep_test_env {}".format(request.config.option.sai_test_keep_test_env))
    dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    try:
        sai_test_interface_para = create_sai_test_interface_param
        run_case_from_ptf(duthost, dut_ip, ptfhost, sai_test_case, sai_test_interface_para, request)
    except BaseException as e:
        logger.info("Test case [{}] failed, failed as {}.".format(sai_test_case, e))
        pytest.fail("Test case [{}] failed".format(sai_test_case), e)
    finally:
        stop_and_rm_sai_test_container(
            duthost, get_sai_test_container_name(request))
        store_test_result(ptfhost)
        saiserver_warmboot_config(duthost, "restore")
        saiserver_warmboot_config(duthost, "init")
