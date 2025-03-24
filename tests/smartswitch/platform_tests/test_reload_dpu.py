"""
Tests for the `reboot and reload ...` commands in DPU
"""

import logging
import pytest
import re
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import reboot, REBOOT_TYPE_COLD
from tests.smartswitch.common.device_utils_dpu import get_dpu_link_status,\
    check_dpu_ping_status, check_dpu_link_and_status, check_dpu_module_status,\
    pre_test_check, post_test_switch_check, post_test_dpu_check,\
    check_dpu_reboot_cause, num_dpu_modules  # noqa: F401
from tests.common.platform.device_utils import platform_api_conn  # noqa: F401,F403

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
        dpu_number = int(re.search(r'\d+', dpu_on).group())
        dpuhosts[dpu_number].shell(kernel_panic_cmd, executable="/bin/bash")

    logging.info("Executing post test dpu check")
    post_test_dpu_check(duthost, dpuhosts,
                        dpu_on_list, dpu_off_list,
                        ip_address_list)


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
        dpu_number = int(re.search(r'\d+', dpu_on).group())
        dpuhosts[dpu_number].shell(memory_exhaustion_cmd,
                                   executable="/bin/bash")

    logging.info("Executing post test dpu check")
    post_test_dpu_check(duthost, dpuhosts,
                        dpu_on_list, dpu_off_list,
                        ip_address_list)
