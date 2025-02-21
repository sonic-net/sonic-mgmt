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
    execute_dpu_commands, parse_dpu_memory_usage, parse_system_health_summary,\
    check_dpu_health_status, num_dpu_modules  # noqa: F401
from tests.common.platform.device_utils import platform_api_conn  # noqa: F401,F403

pytestmark = [
    pytest.mark.topology('smartswitch')
]

# Timeouts, Delays and Time Intervals in secs
DPU_MAX_TIMEOUT = 360
DPU_TIME_INT = 120
SYS_TIME_INT = 180


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
            if parse_output['oper-status'] != 'Offline':
                index = (parse_output['name'])[-1]
                ip_address_list.append(
                      module.get_midplane_ip(platform_api_conn, index))

    ping_status = check_dpu_ping_status(duthost, ip_address_list)
    pytest_assert(ping_status == 1, "Ping to one or more DPUs has failed")


def test_shutdown_power_up_dpu(duthosts, enum_rand_one_per_hwsku_hostname,
                               platform_api_conn, num_dpu_modules):   # noqa F811
    """
    @summary: Verify `shut down and power up DPU`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        duthost.shell("config chassis modules shutdown %s" % (dpu_name))
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, DPU_TIME_INT, 0,
                      check_dpu_module_status,
                      duthost, "off", dpu_name),
                      "DPU is not operationally down")

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        duthost.shell("config chassis modules startup %s" % (dpu_name))
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, DPU_TIME_INT, 0,
                      check_dpu_module_status,
                      duthost, "on", dpu_name),
                      "DPU is not operationally up")


def test_reboot_cause(duthosts, enum_rand_one_per_hwsku_hostname,
                      platform_api_conn, num_dpu_modules):    # noqa F811
    """
    @summary: Verify `Reboot Cause`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        duthost.shell("config chassis \
                       module shutdown %s" % (dpu_name))["stdout_lines"]
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, DPU_TIME_INT, 0,
                                 check_dpu_module_status,
                                 duthost, "off",
                                 dpu_name), "DPU is not operationally down")

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        duthost.shell("config chassis modules startup %s" % (dpu_name))
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, DPU_TIME_INT, 0,
                      check_dpu_module_status,
                      duthost, "on", dpu_name),
                      "DPU is not operationally up")
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, DPU_TIME_INT, 0,
                                 check_dpu_reboot_cause,
                                 duthost,
                                 dpu_name,
                                 "Non-Hardware"), "Reboot cause is incorrect")


def test_pcie_link(duthosts, enum_rand_one_per_hwsku_hostname,
                   platform_api_conn, num_dpu_modules):   # noqa F811
    """
    @summary: Verify `PCIe link`
    """
    CMD_PCIE_INFO = "show platform pcieinfo -c"

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Verifying output of \
                 '{}' on '{}'...".format(CMD_PCIE_INFO, duthost.hostname))
    output_pcie_info = duthost.command(CMD_PCIE_INFO)["stdout_lines"]
    pytest_assert(output_pcie_info[-1] ==
                  'PCIe Device Checking All Test ----------->>> PASSED',
                  "PCIe Link test failed'{}'".format(duthost.hostname))

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        duthost.shell("config chassis modules shutdown %s" % (dpu_name))
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, DPU_TIME_INT, 0,
                      check_dpu_module_status,
                      duthost, "off", dpu_name),
                      "DPU is not operationally down")

    output_pcie_info = duthost.command(CMD_PCIE_INFO)["stdout_lines"]
    pytest_assert(output_pcie_info[-1] ==
                  'PCIe Device Checking All Test ----------->>> PASSED',
                  "PCIe Link test failed'{}'".format(duthost.hostname))

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        duthost.shell("config chassis modules startup %s" % (dpu_name))
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, DPU_TIME_INT, 0,
                      check_dpu_module_status,
                      duthost, "on", dpu_name), "DPU is not operationally up")

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

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        rc = check_dpu_module_status(duthost, "off", dpu_name)
        if rc:
            continue

        logging.info("Shutting down {}".format(dpu_name))
        duthost.shell("config chassis modules shutdown %s" % (dpu_name))
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, DPU_TIME_INT, 0,
                      check_dpu_module_status,
                      duthost, "off", dpu_name),
                      "DPU is not operationally down")

        check_dpu_health_status(duthost, dpu_name, 'Offline', 'down')

        logging.info("Powering up {}".format(dpu_name))
        duthost.shell("config chassis modules startup %s" % (dpu_name))
        pytest_assert(wait_until(DPU_MAX_TIMEOUT, SYS_TIME_INT, 0,
                      check_dpu_module_status,
                      duthost, "on", dpu_name),
                      "DPU is not operationally up")

        check_dpu_health_status(duthost, dpu_name, 'Online', 'up')


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

        command = ('python -c "import pexpect; '
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
                      "dpu console is not accessible")


def test_npu_dpu_date(duthosts, enum_rand_one_per_hwsku_hostname,
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
        ip_address = module.get_midplane_ip(platform_api_conn, index)

        logging.info("Checking date and time on {}".format(dpu_name))
        dpu_date = execute_dpu_commands(duthost, ip_address, "date")

        logging.info("Checking date and time on switch")
        switch_date = duthost.command("date")['stdout']

        date1 = datetime.strptime(switch_date, date_format)
        date2 = datetime.strptime(dpu_date, date_format)

        time_difference = abs((date1 - date2).total_seconds())

        pytest_assert(time_difference <= 2,
                      "NPU {} and DPU {} are not in sync for NPU and {}'"
                      .format(switch_date, dpu_date, dpu_name))


def test_dpu_memory(duthosts, enum_rand_one_per_hwsku_hostname,
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
        ip_address = module.get_midplane_ip(platform_api_conn,  # noqa: F811
                                            index)

        logging.info("Checking show system-memory on DPU")
        dpu_memory = execute_dpu_commands(duthost, ip_address,
                                          "show system-memory")
        dpu_memory_usage = parse_dpu_memory_usage(dpu_memory)

        result = (dpu_memory_usage <= duthosts.facts['dpu_memory_threshold'])  # noqa: F405, E501

        pytest_assert(result, "DPU memory usage is not within \
                      the threshold value")


def test_system_health_summary(duthosts, enum_rand_one_per_hwsku_hostname,
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
        ip_address = module.get_midplane_ip(platform_api_conn, index)

        logging.info("Checking show system-health summary on DPU")
        output_health_summary = execute_dpu_commands(duthost, ip_address,
                                                     "sudo show system-health summary")  # noqa: E501
        result = parse_system_health_summary(output_health_summary)

        logging.info(output_health_summary)
        pytest_assert(result, "DPU health status is not ok")
