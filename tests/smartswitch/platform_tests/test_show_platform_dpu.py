"""
Tests for the `platform cli ...` commands in DPU
"""

import logging
import pytest
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.smartswitch.common.platform.device_utils_dpu import *  # noqa: F403,F401,E501
from tests.common.helpers.platform_api import chassis, module  # noqa: F401
from tests.platform_tests.api.conftest import *  # noqa: F401,F403
from tests.common.devices.sonic import *  # noqa: 403

pytestmark = [
    pytest.mark.topology('t1')
]


def test_midplane_ip(duthosts, enum_rand_one_per_hwsku_hostname,
                     platform_api_conn, check_dpu_ping_status):
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
    pytest_assert(ping_status == 1, "Ping to DPU has been tested")


def test_shutdown_power_up_dpu(duthosts, enum_rand_one_per_hwsku_hostname,
                               platform_api_conn, num_dpu_modules,
                               check_dpu_module_status):
    """
    @summary: Verify `shut down and power up DPU`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    num_modules = num_dpu_modules(platform_api_conn)

    for index in range(num_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        duthosts.shell("config chassis modules shutdown %s" % (dpu_name))
        pytest_assert(wait_until(180, 60, 0,
                      check_dpu_module_status,
                      duthost, "off", dpu_name),
                      "DPU is not operationally down")

    for index in range(num_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        duthosts.shell("config chassis modules startup %s" % (dpu_name))
        pytest_assert(wait_until(180, 60, 0,
                      check_dpu_module_status,
                      duthost, "on", dpu_name),
                      "DPU is not operationally up")


def test_reboot_cause(duthosts, enum_rand_one_per_hwsku_hostname,
                      platform_api_conn, num_dpu_modules,
                      check_dpu_module_status, check_dpu_reboot_cause):
    """
    @summary: Verify `Reboot Cause`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    num_modules = num_dpu_modules(platform_api_conn)

    for index in range(num_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        duthost.shell("config chassis \
                       module shutdown %s" % (dpu_name))["stdout_lines"]
        pytest_assert(wait_until(180, 60, 0,
                                 check_dpu_module_status,
                                 duthost, "off",
                                 dpu_name), "DPU is not operationally down")

    for index in range(num_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        duthosts.shell("config chassis modules startup %s" % (dpu_name))
        pytest_assert(wait_until(180, 60, 0,
                                 check_dpu_reboot_cause,
                                 duthost,
                                 dpu_name), "DPU is not operationally up")


def test_pcie_link(duthosts, enum_rand_one_per_hwsku_hostname,
                   platform_api_conn, num_dpu_modules,
                   check_dpu_module_status):
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
                  "PCIe Link is good'{}'".format(duthost.hostname))

    num_modules = num_dpu_modules(platform_api_conn)

    for index in range(num_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        duthosts.shell("config chassis modules shutdown %s" % (dpu_name))
        pytest_assert(wait_until(180, 60, 0,
                      check_dpu_module_status,
                      duthost, "off", dpu_name),
                      "DPU is not operationally down")

    output_pcie_info = duthost.command(CMD_PCIE_INFO)["stdout_lines"]
    pytest_assert(output_pcie_info[-1] ==
                  'PCIe Device Checking All Test ----------->>> PASSED',
                  "PCIe Link is good'{}'".format(duthost.hostname))

    for index in range(num_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        duthosts.shell("config chassis modules startup %s" % (dpu_name))
        pytest_assert(wait_until(180, 60, 0,
                      check_dpu_module_status,
                      duthost, "on", dpu_name), "DPU is not operationally up")

    logging.info("Verifying output of '{}' on '{}'..."
                 .format(CMD_PCIE_INFO, duthost.hostname))
    output_pcie_info = duthost.command(CMD_PCIE_INFO)["stdout_lines"]
    pytest_assert("PASSED" == output_pcie_info[-1], "PCIe Link is good'{}'"
                  .format(duthost.hostname))
