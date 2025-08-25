"""
Tests for the `reboot and reload ...` commands in DPU
"""

import logging
import pytest
import re
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import reboot, REBOOT_TYPE_COLD
from tests.common.helpers.platform_api import module
from tests.smartswitch.common.device_utils_dpu import check_dpu_link_and_status,\
    pre_test_check, post_test_switch_check, post_test_dpus_check,\
    num_dpu_modules  # noqa: F401
from tests.common.platform.device_utils import platform_api_conn, start_platform_api_service  # noqa: F401,F403
from tests.smartswitch.common.reboot import perform_reboot
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor

pytestmark = [
    pytest.mark.topology('smartswitch')
]

kernel_panic_cmd = "sudo nohup bash -c 'sleep 5 && echo c > /proc/sysrq-trigger' &"
memory_exhaustion_cmd = "sudo nohup bash -c 'sleep 5 && tail /dev/zero' &"


def test_dpu_status_post_switch_reboot(duthosts,
                                       enum_rand_one_per_hwsku_hostname,
                                       localhost,
                                       platform_api_conn, num_dpu_modules):  # noqa F811, E501
    """
    @summary: To Check Ping between NPU and DPU
              after reboot of NPU
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Executing pre test check")
    ip_address_list, dpu_on_list, dpu_off_list = pre_test_check(
                                                 duthost,
                                                 platform_api_conn,
                                                 num_dpu_modules)

    logging.info("Starting switch reboot...")
    reboot(duthost, localhost, reboot_type=REBOOT_TYPE_COLD,
           wait_for_ssh=False)

    logging.info("Executing post test check")
    post_test_switch_check(duthost, localhost,
                           dpu_on_list, dpu_off_list,
                           ip_address_list)


def test_dpu_status_post_switch_config_reload(duthosts,
                                              enum_rand_one_per_hwsku_hostname,
                                              localhost,
                                              platform_api_conn, num_dpu_modules):   # noqa F811, E501
    """
    @summary: To Check Ping between NPU and DPU
              after configuration reload on NPU
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Executing pre test check")
    ip_address_list, dpu_on_list, dpu_off_list = pre_test_check(
                                                 duthost,
                                                 platform_api_conn,
                                                 num_dpu_modules)

    logging.info("Reload configuration")
    duthost.shell("sudo config reload -y &>/dev/null", executable="/bin/bash")

    logging.info("Wait until all critical services are fully started")
    wait_critical_processes(duthost)

    logging.info("Checking DPU link status and connectivity")
    check_dpu_link_and_status(duthost, dpu_on_list,
                              dpu_off_list, ip_address_list)


@pytest.mark.disable_loganalyzer
def test_dpu_status_post_switch_mem_exhaustion(duthosts,
                                               enum_rand_one_per_hwsku_hostname,  # noqa: E501
                                               localhost,
                                               platform_api_conn, num_dpu_modules):  # noqa: F811, E501
    """
    @summary: Test memory exhaustion on NPU by running a heavy process,
              causing reboot of the NPU.
              Verify DPU connectivity and operational status before and
              after the reboot.
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Executing pre test check")
    ip_address_list, dpu_on_list, dpu_off_list = pre_test_check(
                                                 duthost,
                                                 platform_api_conn,
                                                 num_dpu_modules)

    logging.info("Starting memory exhaustion test on NPU by running \
                  a large process...")
    duthost.shell(memory_exhaustion_cmd, executable="/bin/bash")

    logging.info("Executing post test check")
    post_test_switch_check(duthost, localhost,
                           dpu_on_list, dpu_off_list,
                           ip_address_list)


@pytest.mark.disable_loganalyzer
def test_dpu_status_post_switch_kernel_panic(duthosts,
                                             enum_rand_one_per_hwsku_hostname,
                                             localhost,
                                             platform_api_conn, num_dpu_modules):  # noqa: F811, E501
    """
    @summary: Test NPU recovery from a kernel panic,
              Kernel panic causing reboot of the NPU.
              Verify DPU connectivity and operational status before
              and after the reboot.
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Executing pre test check")
    ip_address_list, dpu_on_list, dpu_off_list = pre_test_check(
                                                 duthost,
                                                 platform_api_conn,
                                                 num_dpu_modules)

    logging.info("Triggering kernel panic on NPU...")
    duthost.shell(kernel_panic_cmd, executable="/bin/bash")

    logging.info("Executing post test check")
    post_test_switch_check(duthost, localhost,
                           dpu_on_list, dpu_off_list,
                           ip_address_list)


@pytest.mark.disable_loganalyzer
def test_dpu_status_post_dpu_kernel_panic(duthosts, dpuhosts,
                                          enum_rand_one_per_hwsku_hostname,
                                          platform_api_conn, num_dpu_modules):  # noqa: F811, E501
    """
    @summary: Test to verify DPU recovery on `kernel panic on DPU`
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Executing pre test check")
    ip_address_list, dpu_on_list, dpu_off_list = pre_test_check(
                                                 duthost,
                                                 platform_api_conn,
                                                 num_dpu_modules)

    for index in range(len(dpu_on_list)):
        logging.info("Triggering Kernel Panic on %s" % (dpu_on_list[index]))
        dpu_on = dpu_on_list[index]
        dpu_id = int(re.search(r'\d+', dpu_on).group())
        dpuhosts[dpu_id].shell(kernel_panic_cmd, executable="/bin/bash")

    logging.info("Executing post test dpu check")
    post_test_dpus_check(duthost, dpuhosts, dpu_on_list, ip_address_list, num_dpu_modules, "Non-Hardware")


@pytest.mark.disable_loganalyzer
def test_dpu_check_post_dpu_mem_exhaustion(duthosts, dpuhosts,
                                           enum_rand_one_per_hwsku_hostname,
                                           platform_api_conn, num_dpu_modules):  # noqa: F811, E501
    """
    @summary: Test to verify DPU recovery on `Memory Exhaustion on DPU`
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Executing pre test check")
    ip_address_list, dpu_on_list, dpu_off_list = pre_test_check(
                                                 duthost,
                                                 platform_api_conn,
                                                 num_dpu_modules)

    for index in range(len(dpu_on_list)):
        logging.info(
                "Triggering Memory Exhaustion on %s" % (dpu_on_list[index])
                )
        dpu_on = dpu_on_list[index]
        dpu_id = int(re.search(r'\d+', dpu_on).group())
        dpuhosts[dpu_id].shell(memory_exhaustion_cmd, executable="/bin/bash")

    logging.info("Executing post test dpu check")
    post_test_dpus_check(duthost, dpuhosts, dpu_on_list, ip_address_list,
                         num_dpu_modules, "Non-Hardware")


def test_cold_reboot_dpus(duthosts, dpuhosts, enum_rand_one_per_hwsku_hostname,
                          platform_api_conn, num_dpu_modules):  # noqa: F811, E501
    """
    Test to cold reboot all DPUs in the DUT.
    Steps:
    1. Perform pre-test checks to gather DPU state.
    2. Initiate cold reboot on all DPUs concurrently.
    3. Perform post-test checks to verify the state after reboot.

    Args:
        duthosts: DUT hosts object
        dpuhosts: DPU hosts object
        enum_rand_one_per_hwsku_hostname: Randomized DUT hostname
        platform_api_conn: Platform API connection object
        num_dpu_modules: Number of DPU modules to reboot
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Executing pre test check")
    ip_address_list, dpu_on_list, dpu_off_list = pre_test_check(duthost, platform_api_conn, num_dpu_modules)
    dpu_names = [module.get_name(platform_api_conn, index) for index in range(num_dpu_modules)]

    with SafeThreadPoolExecutor(max_workers=num_dpu_modules) as executor:
        logging.info("Rebooting all DPUs in parallel")
        for dpu_name in dpu_names:
            executor.submit(perform_reboot, duthost, REBOOT_TYPE_COLD, dpu_name)

    logging.info("Executing post test dpu check")
    post_test_dpus_check(duthost, dpuhosts, dpu_on_list, ip_address_list, num_dpu_modules, "Non-Hardware")


def test_cold_reboot_switch(duthosts, dpuhosts, enum_rand_one_per_hwsku_hostname,
                            platform_api_conn, num_dpu_modules):  # noqa: F811, E501
    """
    Test to cold reboot the switch in the DUT.
    Steps:
    1. Perform pre-test checks to gather DPU state.
    2. Initiate a cold reboot on the switch.
    3. Perform post-test checks to verify the state of DPUs after the reboot.

    Args:
        duthosts: DUT hosts object
        dpuhosts: DPU hosts object
        enum_rand_one_per_hwsku_hostname: Randomized DUT hostname
        platform_api_conn: Platform API connection object
        num_dpu_modules: Number of DPU modules to verify
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Executing pre test check")
    ip_address_list, dpu_on_list, dpu_off_list = pre_test_check(duthost, platform_api_conn, num_dpu_modules)

    logging.info("Starting switch reboot...")
    perform_reboot(duthost, REBOOT_TYPE_COLD, None)

    logging.info("Executing post switch reboot dpu check")
    post_test_dpus_check(duthost, dpuhosts, dpu_on_list, ip_address_list, num_dpu_modules, "reboot")
