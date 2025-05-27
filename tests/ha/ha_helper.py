import pytest
import logging

from tests.smartswitch.common.device_utils_dpu import pre_test_check, post_test_dpus_check
from tests.common.utilities import wait_until


def dpu_syncd_process_kill(
    duthosts,
    dpuhosts,
    enum_rand_one_per_hwsku_hostname,
    platform_api_conn,
    num_dpu_modules
):

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Executing pre test check")
    ip_address_list, dpu_on_list, dpu_off_list = pre_test_check(
        duthost,
        platform_api_conn,
        num_dpu_modules
    )

    # Target only DPU0
    dpu_on = "DPU0"
    dpu_id = 0

    if dpu_on not in dpu_on_list:
        pytest.skip("DPU0 is not in the list of active DPUs. Skipping test.")

    logging.info("Triggering syncd crash on %s" % dpu_on)
    dpuhosts[dpu_id].shell("pkill syncd", executable="/bin/bash")

    logging.info("Executing post test dpu check")
    post_test_dpus_check(duthost, dpuhosts, [dpu_on], ip_address_list, num_dpu_modules, "Non-Hardware")


def dpu_bgpd_process_kill(
    duthosts,
    dpuhosts,
    enum_rand_one_per_hwsku_hostname,
    platform_api_conn,
    num_dpu_modules
):

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Executing pre test check")
    ip_address_list, dpu_on_list, dpu_off_list = pre_test_check(
        duthost,
        platform_api_conn,
        num_dpu_modules
    )

    # Target only DPU0
    dpu_on = "DPU0"
    dpu_id = 0

    if dpu_on not in dpu_on_list:
        pytest.skip("DPU0 is not in the list of active DPUs. Skipping test.")

    logging.info("Triggering syncd crash on %s" % dpu_on)
    dpuhosts[dpu_id].shell("pkill bgpd", executable="/bin/bash")

    logging.info("Executing post test dpu check")
    post_test_dpus_check(duthost, dpuhosts, [dpu_on], ip_address_list, num_dpu_modules, "Non-Hardware")


def check_pmon_service(duthost):
    pmon_service_state = duthost.get_service_props("pmon")
    return pmon_service_state["ActiveState"] == "active"


def restart_pmon(duthost):
    duthost.shell("pkill pmon")
    if not wait_until(1, 60, 0, check_pmon_service, duthost):
        pytest.fail('pmon service is not up after 60 seconds. Test failed')


def check_bgp_service(duthost):
    bgp_service_state = duthost.get_service_props("bgp")
    return bgp_service_state["ActiveState"] == "active"


def restart_bgp(duthost):
    duthost.shell("pkill bgp")
    if not wait_until(1, 60, 0, check_bgp_service, duthost):
        pytest.fail('bgp service is not up after 60 seconds. Test failed')


def check_hamgrd_service(duthost):
    hamgr_service_state = duthost.get_service_props("hamgr")
    return hamgr_service_state["ActiveState"] == "active"


def restart_hamgrd(duthost):
    duthost.shell("pkill hamgrd")
    if not wait_until(1, 60, 0, check_hamgrd_service, duthost):
        pytest.fail('hamgrd service is not up after 60 seconds. Test failed')
