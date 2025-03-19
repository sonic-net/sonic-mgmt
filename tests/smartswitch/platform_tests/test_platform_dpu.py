"""
Tests for the `platform cli ...` commands in DPU
"""

import logging
import pytest
from datetime import datetime
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import module
from tests.smartswitch.common.device_utils_dpu import check_dpu_ping_status,\
    check_dpu_module_status, check_dpu_reboot_cause, check_pmon_status,\
    parse_dpu_memory_usage, parse_system_health_summary,\
    pre_test_check, post_test_dpu_check,\
    check_dpu_health_status, num_dpu_modules  # noqa: F401
from tests.common.platform.device_utils import platform_api_conn  # noqa: F401,F403

pytestmark = [
    pytest.mark.topology('smartswitch')
]

# Timeouts, Delays and Time Intervals in secs
DPU_MAX_TIMEOUT = 360
DPU_TIME_INT = 30
SYS_TIME_INT = 180

# DPU Memory Threshold
DPU_MEMORY_THRESHOLD = 90


def test_midplane_ip(duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn):  # noqa F811
    """
    @summary: Verify `Midplane ip address between NPU and DPU`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ip_address_list = []

    output_dpu_status = duthost.show_and_parse('show chassis module status')

    for index in range(len(output_dpu_status)):
        parse_output = output_dpu_status[index]
        if 'DPU' in parse_output['name']:
            if parse_output['oper-status'].lower() != 'offline':
                index = (parse_output['name'])[-1]
                ip_address_list.append(
                      module.get_midplane_ip(platform_api_conn, index))

    ping_status = check_dpu_ping_status(duthost, ip_address_list)
    pytest_assert(ping_status == 1, "Ping to one or more DPUs has failed")


def test_reboot_cause(duthosts, enum_rand_one_per_hwsku_hostname,
                      platform_api_conn, num_dpu_modules):    # noqa F811
    """
    @summary: Verify `Reboot Cause`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        duthost.shell("sudo config chassis \
                       module shutdown %s" % (dpu_name))["stdout_lines"]

    for index in range(num_dpu_modules):
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, DPU_TIME_INT, 0,
                                 check_dpu_module_status,
                                 duthost, "off",
                                 dpu_name), "DPU is not operationally down")
        dpu_name = module.get_name(platform_api_conn, index)
        duthost.shell("sudo config chassis modules startup %s" % (dpu_name))

    for index in range(num_dpu_modules):
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, DPU_TIME_INT, 0,
                      check_dpu_module_status,
                      duthost, "on", dpu_name),
                      "DPU is not operationally up")
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, DPU_TIME_INT, 0,
                                 check_dpu_reboot_cause,
                                 duthost,
                                 dpu_name,
                                 "Non-Hardware"), "Reboot cause is incorrect")


def test_pcie_link(duthosts, dpuhosts,
                   enum_rand_one_per_hwsku_hostname,
                   platform_api_conn, num_dpu_modules):   # noqa F811
    """
    @summary: Verify `PCIe link`
    """
    CMD_PCIE_INFO = "show platform pcieinfo -c"

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Executing pre test check")
    ip_address_list, dpu_on_list, dpu_off_list = pre_test_check(
                                                 duthost,
                                                 platform_api_conn,
                                                 num_dpu_modules)

    logging.info("Verifying output of \
                 '{}' on '{}'...".format(CMD_PCIE_INFO, duthost.hostname))
    output_pcie_info = duthost.command(CMD_PCIE_INFO)["stdout_lines"]
    pytest_assert(output_pcie_info[-1] ==
                  'PCIe Device Checking All Test ----------->>> PASSED',
                  "PCIe Link test failed'{}'".format(duthost.hostname))

    for index in range(len(dpu_on_list)):
        duthost.shell("sudo config chassis modules \
                       shutdown %s" % (dpu_on_list[index]))

    for index in range(len(dpu_on_list)):
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, DPU_TIME_INT, 0,
                      check_dpu_module_status,
                      duthost, "off", dpu_on_list[index]),
                      "DPU is not operationally down")

    output_pcie_info = duthost.command(CMD_PCIE_INFO)["stdout_lines"]
    pytest_assert(output_pcie_info[-1] ==
                  'PCIe Device Checking All Test ----------->>> PASSED',
                  "PCIe Link test failed'{}'".format(duthost.hostname))

    for index in range(len(dpu_on_list)):
        duthost.shell("sudo config chassis modules \
                       startup %s" % (dpu_on_list[index]))

    post_test_dpu_check(duthost, dpuhosts,
                        dpu_on_list, dpu_off_list,
                        ip_address_list)

    logging.info("Verifying output of '{}' on '{}'..."
                 .format(CMD_PCIE_INFO, duthost.hostname))
    output_pcie_info = duthost.command(CMD_PCIE_INFO)["stdout_lines"]
    pytest_assert(output_pcie_info[-1] ==
                  'PCIe Device Checking All Test ----------->>> PASSED',
                  "PCIe Link test failed'{}'".format(duthost.hostname))


def test_restart_pmon(duthosts, enum_rand_one_per_hwsku_hostname,
                      platform_api_conn, num_dpu_modules):  # noqa: F811
    """
    @summary: Verify `DPU status and pcie Link after restart pmon`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ip_address_list = []

    logging.info("Checking pmon status")
    pmon_status = check_pmon_status(duthost)
    pytest_assert(pmon_status == 1, "PMON status is Not UP")

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        rc = check_dpu_module_status(duthost, "on", dpu_name)
        if rc:
            ip_address_list.append(
                          module.get_midplane_ip(platform_api_conn, index))

    ping_status = check_dpu_ping_status(duthost, ip_address_list)
    pytest_assert(ping_status == 1, "Ping to one or more DPUs has failed")

    logging.info("Restarting pmon....")
    duthost.shell("systemctl restart pmon")

    ping_status = check_dpu_ping_status(duthost, ip_address_list)
    pytest_assert(ping_status == 1, "Ping to one or more DPUs has failed")

    logging.info("Checking pmon status")
    pmon_status = check_pmon_status(duthost)
    pytest_assert(pmon_status == 1, "PMON status is Not UP")


def test_system_health_state(duthosts, enum_rand_one_per_hwsku_hostname,
                             platform_api_conn, num_dpu_modules):  # noqa: F811
    """
    @summary: To Verify `show system-health dpu` cli
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Executing pre test check")
    ip_address_list, dpu_on_list, dpu_off_list = pre_test_check(
                                                 duthost,
                                                 platform_api_conn,
                                                 num_dpu_modules)

    for index in range(len(dpu_on_list)):
        logging.info("Shutting down {}".format(dpu_on_list[index]))
        duthost.shell("sudo config chassis modules \
                       shutdown %s" % (dpu_on_list[index]))

    for index in range(len(dpu_on_list)):
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, DPU_TIME_INT, 0,
                      check_dpu_module_status,
                      duthost, "off", dpu_on_list[index]),
                      "DPU is not operationally down")

        check_dpu_health_status(duthost, dpu_on_list[index],
                                'Offline', 'down')

    for index in range(len(dpu_on_list)):
        logging.info("Powering up {}".format(dpu_on_list[index]))
        duthost.shell("sudo config chassis modules \
                       startup %s" % (dpu_on_list[index]))

    for index in range(len(dpu_on_list)):
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, SYS_TIME_INT, 0,
                      check_dpu_module_status,
                      duthost, "on", dpu_on_list[index]),
                      "DPU is not operationally up")

        check_dpu_health_status(duthost, dpu_on_list[index],
                                'Online', 'up')


def test_dpu_console(duthosts, enum_rand_one_per_hwsku_hostname,
                     platform_api_conn, num_dpu_modules):  # noqa: F811
    """
    @summary: To Verify `DPU console access`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        rc = check_dpu_module_status(duthost, "off", dpu_name)
        if rc:
            continue

        command = ('sudo python -c "import pexpect; '
                   'child = pexpect.spawn(\'python /usr/local/bin/dpu-tty.py -n dpu%s\'); '  # noqa: E501
                   'child.expect(r\' \'); '
                   'child.sendline(\'\\r\\r\'); '
                   'child.expect(r\' \'); '
                   'child.sendline(\'exit\\rexit\\r\'); '
                   'child.expect(r\'sonic login: \'); '
                   'print(child.after.decode()); child.close()"'
                   % (index))

        logging.info("Checking console access of {}".format(dpu_name))
        output_dpu_console = duthost.shell(command)
        pytest_assert(output_dpu_console['stdout'] == 'sonic login: ',
                      "{} console is not accessible"
                      .format(dpu_name))


def test_npu_dpu_date(duthosts, dpuhosts,
                      enum_rand_one_per_hwsku_hostname,
                      platform_api_conn, num_dpu_modules):  # noqa: F811
    """
    @summary: Verify `Date sync in NPU and DPU`
              It also verifies in turn the RTC clock sync
              that has been part of bootup
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    date_format = "%a %b %d %I:%M:%S %p %Z %Y"

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        rc = check_dpu_module_status(duthost, "off", dpu_name)
        if rc:
            continue

        logging.info("Checking date and time on {}".format(dpu_name))
        dpu_date = dpuhosts[index].command("date")['stdout']

        logging.info("Checking date and time on switch")
        switch_date = duthost.command("date")['stdout_lines']

        date1 = datetime.strptime(switch_date[0], date_format)
        date2 = datetime.strptime(dpu_date, date_format)

        time_difference = abs((date1 - date2).total_seconds())

        pytest_assert(time_difference <= 7,
                      "NPU {} and DPU {} are not in sync for NPU and {}'"
                      .format(switch_date, dpu_date, dpu_name))


def test_dpu_memory(duthosts, dpuhosts,
                    enum_rand_one_per_hwsku_hostname,
                    platform_api_conn, num_dpu_modules):  # noqa: F811
    """
    @summary: Verify `show system-memory in DPU`
              against the threshold value set in
              platform.json
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    for index in range(num_dpu_modules):

        dpu_name = module.get_name(platform_api_conn, index)
        rc = check_dpu_module_status(duthost, "off", dpu_name)
        if rc:
            continue

        logging.info("Checking show system-memory on {}"
                     .format(dpu_name))
        dpu_memory = dpuhosts[index].command(
                             "sudo show system-memory")['stdout']

        dpu_memory_usage = parse_dpu_memory_usage(dpu_memory)

        result = (dpu_memory_usage <= DPU_MEMORY_THRESHOLD)

        pytest_assert(result,
                      "{} memory usage is not within \
                      the threshold value"
                      .format(dpu_name))


def test_system_health_summary(duthosts, dpuhosts,
                               enum_rand_one_per_hwsku_hostname,
                               platform_api_conn, num_dpu_modules):  # noqa: F811
    """
    @summary: To Verify `show system-health summary` cli
              It verifies all hw, sw and service status are OK
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Checking show system-health summary on Switch")
    output_health_summary = duthost.command("show system-health summary")
    result = parse_system_health_summary(output_health_summary['stdout'])

    pytest_assert(result, "Switch health status is not ok")

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        rc = check_dpu_module_status(duthost, "off", dpu_name)
        if rc:
            continue

        logging.info("Checking show system-health summary on {}"
                     .format(dpu_name))
        output_health_summary = dpuhosts[index].command(
                                "sudo show system-health summary")['stdout']

        result = parse_system_health_summary(output_health_summary)

        logging.info(output_health_summary)
        pytest_assert(result,
                      "{} health status is not ok"
                      .format(dpu_name))
