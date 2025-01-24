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
from tests.common.helpers.platform_api import module
from tests.smartswitch.common.device_utils_dpu import (  # noqa: F401
     get_dpu_link_status,
     check_dpu_ping_status,
     check_dpu_link_and_status,
     check_dpu_module_status,
     execute_dpu_commands,
     check_dpu_reboot_cause,
     num_dpu_modules
     )
from tests.common.platform.device_utils import platform_api_conn  # noqa: F401,F403

pytestmark = [
    pytest.mark.topology('smartswitch')
]


def test_dpu_ping_after_reboot(duthosts, enum_rand_one_per_hwsku_hostname,
                               localhost,
                               platform_api_conn, num_dpu_modules):  # noqa F811, E501
    """
    @summary: Verify output of `config chassis modules startup <DPU_Number>`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Getting DPU On/Off list and IP address list")
    ip_address_list, dpu_on_list, dpu_off_list = get_dpu_link_status(
                                                 duthost, num_dpu_modules,
                                                 platform_api_conn)

    logging.info("Checking DPU connectivity before reboot..")
    pytest_assert(wait_until(30, 10, 0, check_dpu_ping_status,
                  duthost, ip_address_list),
                  "Error: Not all DPUs are pingable before reboot")

    logging.info("Starting switch reboot...")
    reboot(duthost, localhost, reboot_type=REBOOT_TYPE_COLD,
           wait_for_ssh=False)

    logging.info("Waiting for ssh connection to switch")
    wait_for_startup(duthost, localhost, 10, 300)

    logging.info("Checking for Interface status")
    pytest_assert(wait_until(300, 5, 0, check_interface_status_of_up_ports,
                  duthost),
                  "Not all ports that are admin up on are operationally up")
    logging.info("Interfaces are up")

    logging.info("Wait until all critical services are fully started")
    wait_critical_processes(duthost)

    logging.info("Checking DPU link status and connectivity")
    check_dpu_link_and_status(duthost, dpu_on_list,
                              dpu_off_list, ip_address_list)


def test_show_ping_int_after_reload(duthosts, enum_rand_one_per_hwsku_hostname,
                                    localhost,
                                    platform_api_conn, num_dpu_modules):   # noqa F811, E501
    """
    @summary: To Check Ping between NPU and DPU
              after configuration reload on NPU
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Getting DPU On/Off list and IP address list")
    ip_address_list, dpu_on_list, dpu_off_list = get_dpu_link_status(
                                                 duthost, num_dpu_modules,
                                                 platform_api_conn)

    logging.info("Checking DPU connectivity before config reload..")
    pytest_assert(wait_until(30, 10, 0, check_dpu_ping_status,
                  duthost, ip_address_list),
                  "Error: Not all DPUs are pingable before config reload")

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
              followed by a reboot of the NPU.
              Verify DPU connectivity and operational status before and
              after the reboot.
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Getting DPU On/Off list and IP address list")
    ip_address_list, dpu_on_list, dpu_off_list = get_dpu_link_status(
                                                 duthost, num_dpu_modules,
                                                 platform_api_conn)

    logging.info("Checking DPU connectivity before memory exhaustion \
                  on switch..")
    pytest_assert(wait_until(30, 10, 0, check_dpu_ping_status,
                  duthost, ip_address_list),
                  "Error: Not all DPUs are pingable before memory exhaustion \
                          on switch")

    logging.info("Starting memory exhaustion test on NPU by running \
                  a large process...")
    duthost.shell("nohup bash -c 'sleep 5 && tail /dev/zero' &",
                  executable="/bin/bash")

    logging.info("Waiting for ssh connection to switch")
    wait_for_startup(duthost, localhost, 100, 400)

    logging.info("Checking for Interface status")
    pytest_assert(wait_until(300, 5, 0, check_interface_status_of_up_ports,
                  duthost),
                  "Not all ports that are admin up on are operationally up")
    logging.info("Interfaces are up")

    logging.info("Checking DPU link status and connectivity")
    check_dpu_link_and_status(duthost, dpu_on_list,
                              dpu_off_list, ip_address_list)


def test_kernel_panic_on_switch(duthosts,
                                enum_rand_one_per_hwsku_hostname,
                                localhost,
                                platform_api_conn, num_dpu_modules):  # noqa: F811, E501
    """
    @summary: Test NPU recovery from a kernel panic,
              followed by a reboot of the NPU.
              Verify DPU connectivity and operational status before
              and after the reboot.
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Getting DPU On/Off list and IP address list")
    ip_address_list, dpu_on_list, dpu_off_list = get_dpu_link_status(
                                                 duthost, num_dpu_modules,
                                                 platform_api_conn)

    logging.info("Checking DPU connectivity before kernel panic on switch..")
    pytest_assert(wait_until(30, 10, 0, check_dpu_ping_status,
                  duthost, ip_address_list),
                  "Error: Not all DPUs are pingable before kernel panic \
                          on switch")

    logging.info("Triggering kernel panic on NPU...")
    duthost.shell("nohup bash -c 'sleep 5 && echo c > /proc/sysrq-trigger' &",
                  executable="/bin/bash")

    logging.info("Waiting for ssh connection to switch")
    wait_for_startup(duthost, localhost, 100, 400)

    logging.info("Checking for Interface status")
    pytest_assert(wait_until(300, 5, 0, check_interface_status_of_up_ports,
                  duthost),
                  "Not all ports that are admin up on are operationally up")
    logging.info("Interfaces are up")

    logging.info("Checking DPU link status and connectivity")
    check_dpu_link_and_status(duthost, dpu_on_list,
                              dpu_off_list, ip_address_list)


def test_kernel_panic_on_dpu(duthosts, enum_rand_one_per_hwsku_hostname,
                             localhost,
                             platform_api_conn, num_dpu_modules):  # noqa: F811, E501
    """
    @summary: To Verify `kernel panic on dpu`
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ip_address_list = []
    kernel_panic_cmd = "echo c | sudo tee /proc/sysrq-trigger"

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        rc = check_dpu_module_status(duthost, "on", dpu_name)
        ip_address = module.get_midplane_ip(platform_api_conn, index)

        if rc:
            ip_address_list.append(ip_address)
        else:
            continue

        logging.info("Triggering Kernel Panic on %s" % (dpu_name))
        execute_dpu_commands(duthost,
                             ip_address,
                             kernel_panic_cmd,
                             output=False)

        logging.info("Checking %s is down after kernel panic" % (dpu_name))
        pytest_assert(wait_until(360, 120, 0,
                      check_dpu_module_status,
                      duthost, "off", dpu_name),
                      "DPU is not down after kernel panic")

        logging.info("Shutting down %s" % (dpu_name))
        duthosts.shell("config chassis modules shutdown %s" % (dpu_name))
        pytest_assert(wait_until(360, 120, 0,
                      check_dpu_module_status,
                      duthost, "off", dpu_name),
                      "DPU is not operationally down after shutdown")

        logging.info("Powering up %s" % (dpu_name))
        duthosts.shell("config chassis modules startup %s" % (dpu_name))
        pytest_assert(wait_until(360, 120, 0,
                      check_dpu_module_status,
                      duthost, "on", dpu_name),
                      "DPU is not operationally up after startup")

        logging.info("Checking reboot cause of %s" % (dpu_name))
        pytest_assert(wait_until(30, 10, 0,
                      check_dpu_reboot_cause,
                      duthost, dpu_name, "Non-Hardware"),
                      "Reboot cause is not correct")

    logging.info("Checking all Powered on DPUs connectivity")
    ping_status = check_dpu_ping_status(duthost, ip_address_list)
    pytest_assert(ping_status == 1, "Ping to DPU has failed")


def test_memory_exhaustion_on_dpu(duthosts, enum_rand_one_per_hwsku_hostname,
                                  localhost,
                                  platform_api_conn, num_dpu_modules):  # noqa: F811, E501
    """
    @summary: To Verify `kernel panic on dpu`
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ip_address_list = []
    swap_off_cmd = "sudo swapoff -a"
    memory_exhaustion_cmd = "tail /dev/zero"

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        rc = check_dpu_module_status(duthost, "on", dpu_name)
        ip_address = module.get_midplane_ip(platform_api_conn, index)

        if rc:
            ip_address_list.append(ip_address)
        else:
            continue

        logging.info("Enabling Swap off in %s" % (dpu_name))
        execute_dpu_commands(duthost,
                             ip_address,
                             swap_off_cmd)

        logging.info("Triggering Memory Exhaustion on %s" % (dpu_name))
        execute_dpu_commands(duthost,
                             ip_address,
                             memory_exhaustion_cmd,
                             output=False)

        logging.info("Checking %s is down after mem exhaustion" % (dpu_name))
        pytest_assert(wait_until(360, 120, 0,
                      check_dpu_module_status,
                      duthost, "off", dpu_name),
                      "DPU is not down after memory exhaustion")

        logging.info("Shutting down %s" % (dpu_name))
        duthosts.shell("config chassis modules shutdown %s" % (dpu_name))
        pytest_assert(wait_until(360, 120, 0,
                      check_dpu_module_status,
                      duthost, "off", dpu_name),
                      "DPU is not operationally down after shutdown")

        logging.info("Powering up %s" % (dpu_name))
        duthosts.shell("config chassis modules startup %s" % (dpu_name))
        pytest_assert(wait_until(360, 120, 0,
                      check_dpu_module_status,
                      duthost, "on", dpu_name),
                      "DPU is not operationally up after startup")

        logging.info("Checking reboot cause of %s" % (dpu_name))
        pytest_assert(wait_until(30, 10, 0,
                      check_dpu_reboot_cause,
                      duthost, dpu_name, "Non-Hardware"),
                      "Reboot cause is not correct")

    logging.info("Checking all powered on DPUs connectivity")
    ping_status = check_dpu_ping_status(duthost, ip_address_list)
    pytest_assert(ping_status == 1, "Ping to DPU has failed")
