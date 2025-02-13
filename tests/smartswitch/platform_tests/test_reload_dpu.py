"""
Tests for the `reboot and reload ...` commands in DPU
"""

import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.interface_utils \
     import check_interface_status_of_up_ports
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import reboot, wait_for_startup, REBOOT_TYPE_COLD
from tests.smartswitch.common.device_utils_dpu import get_dpu_link_status,\
    check_dpu_ping_status, check_dpu_link_and_status, check_dpu_module_status,\
    execute_dpu_commands, check_dpu_reboot_cause, num_dpu_modules  # noqa: F401
from tests.common.platform.device_utils import platform_api_conn  # noqa: F401,F403

pytestmark = [
    pytest.mark.topology('smartswitch')
]


def test_dpu_ping_after_reboot(duthosts, enum_rand_one_per_hwsku_hostname,
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


def test_show_ping_int_after_reload(duthosts, enum_rand_one_per_hwsku_hostname,
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


def test_memory_exhaustion_on_switch(duthosts,
                                     enum_rand_one_per_hwsku_hostname,
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
    duthost.shell("nohup bash -c 'sleep 5 && tail /dev/zero' &",
                  executable="/bin/bash")

    logging.info("Executing post test check")
    post_test_switch_check(duthost, localhost,
                           dpu_on_list, dpu_off_list,
                           ip_address_list)


def test_kernel_panic_on_switch(duthosts,
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
    duthost.shell("nohup bash -c 'sleep 5 && echo c > /proc/sysrq-trigger' &",
                  executable="/bin/bash")

    logging.info("Executing post test check")
    post_test_switch_check(duthost, localhost,
                           dpu_on_list, dpu_off_list,
                           ip_address_list):


def test_kernel_panic_on_dpu(duthosts, enum_rand_one_per_hwsku_hostname,
                             platform_api_conn, num_dpu_modules):  # noqa: F811, E501
    """
    @summary: Test to verify DPU recovery on `kernel panic on DPU`
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    kernel_panic_cmd = "echo c | sudo tee /proc/sysrq-trigger"

    logging.info("Executing pre test check")
    ip_address_list, dpu_on_list, dpu_off_list = pre_test_check(
                                                 duthost,
                                                 platform_api_conn,
                                                 num_dpu_modules)

    for index in range(len(dpu_on_list)):
        logging.info("Triggering Kernel Panic on %s" % (dpu_on_list[index]))
        execute_dpu_commands(duthost,
                             ip_address_list[index],
                             kernel_panic_cmd,
                             output=False)

    logging.info("Executing post test dpu check")
    post_test_dpu_check(duthost,
                        dpu_on_list, dpu_off_list,
                        ip_address_list)


def test_memory_exhaustion_on_dpu(duthosts, enum_rand_one_per_hwsku_hostname,
                                  platform_api_conn, num_dpu_modules):  # noqa: F811, E501
    """
    @summary: Test to verify DPU recovery on `Memory Exhaustion on DPU`
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    swap_off_cmd = "sudo swapoff -a"
    memory_exhaustion_cmd = "tail /dev/zero"

    logging.info("Executing pre test check")
    ip_address_list, dpu_on_list, dpu_off_list = pre_test_check(
                                                 duthost,
                                                 platform_api_conn,
                                                 num_dpu_modules)

    for index in range(len(dpu_on_list)):
        logging.info("Enabling Swap off in %s" % (dpu_on_list[index]))
        execute_dpu_commands(duthost,
                             ip_address_list[index],
                             swap_off_cmd)

        logging.info(
                "Triggering Memory Exhaustion on %s" % (dpu_on_list[index])
                )
        execute_dpu_commands(duthost,
                             ip_address_list[index],
                             memory_exhaustion_cmd,
                             output=False)

    logging.info("Executing post test dpu check")
    post_test_dpu_check(duthost,
                        dpu_on_list, dpu_off_list,
                        ip_address_list)
