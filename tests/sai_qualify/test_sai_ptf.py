import pytest
import logging

from cases_sai_ptf import TEST_CASE
from conftest import get_sai_test_container_name
from conftest import stop_and_rm_sai_test_container
from sai_infra import run_case_from_ptf, store_test_result
from sai_infra import *  # noqa: F403 F401
from conftest import *  # noqa: F403 F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("ptf"),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]


@pytest.mark.parametrize("ptf_sai_test_case", TEST_CASE)
def test_sai(sai_testbed,
             sai_test_env_check,
             creds,
             duthost,
             ptfhost,
             ptf_sai_test_case,
             request,
             create_sai_test_interface_param):
    """
    Trigger sai ptf test here.

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
    test_fail = False
    dut_ip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    try:
        sai_test_interface_para = create_sai_test_interface_param
        run_case_from_ptf(
            duthost, dut_ip, ptfhost,
            ptf_sai_test_case, sai_test_interface_para, request)
    except BaseException as e:
        logger.info("Test case [{}] failed, \
            trying to restart sai test container, \
                failed as {}.".format(ptf_sai_test_case, e))
        test_fail = True
        pytest.fail("Test case [{}] failed".format(ptf_sai_test_case), e)
    finally:
        if test_fail or request.config.option.always_stop_sai_test_container:
            stop_and_rm_sai_test_container(
                duthost, get_sai_test_container_name(request))
        store_test_result(ptfhost)
