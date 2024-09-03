"""
Tests for the `platform cli ...` commands in DPU 
"""

import http.client
import logging
import pytest
import time
import redis
from tests.common.utilities import wait_until
from . import util
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.device_utils_dpu import *
from tests.common.helpers.platform_api import chassis, module
from tests.platform_tests.api.conftest import platform_api_conn
from tests.common.devices.sonic import *

pytestmark = [
    pytest.mark.topology('t1')
]

def test_midplane_ip(duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn):
    """
    @summary: Verify `Midplane ip address between NPU and DPU`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    num_modules = int(chassis.get_num_modules(platform_api_conn))
    ping_count = 0
    dpu_count = 0
    ip_address_list = []

    output_dpu_status = duthost.show_and_parse('show chassis module status')

    for index in range(len(output_dpu_status)):
        parse_output = output_dpu_status[index]
        if 'DPU' in parse_output['name']:
            if parse_output['oper-status'] != 'Offline':
                index = (parse_output['name'])[-1]
                # Api will always return the ip address as it is statically configured now
                # Check will be added for ip address once dynamic implementation is in place
                ip_address_list.append(module.get_midplane_ip(platform_api_conn, index))

    check_dpu_ping_status(duthost, ip_address_list)

def test_link_flap(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify `Link flap between NPU and DPU`
    - Bringing all DPU interfaces down.
    - Deleting the state table from redis db
    - Checking show system-health dpu to see no output is there.
      (Since the db entries are deleted and link down, state table would be empty which gets reflected in the cli)
    - Brining up the interfaces.
    - State table gets updated automatically after a minute
    - Checking the show system-health dpu cli to get all the details
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    count_up = 0
    count_down = 0
    dpu_db_before = 0
    dpu_db_after = 0

    # Checking the state of dpu health before the flap
    dpu_db_before = count_dpu_modules_in_system_health_cli(duthost)

    output_interface_cmd = duthost.show_and_parse('show ip interface')
    for index in range(len(output_interface_cmd)):
        parse_output = output_interface_cmd[index]
        interface = parse_output['interface']

        if interface != "eth0" and 'eth' in interface:
            duthost.shell("ifconfig %s down"%(interface))["stdout_lines"]
            time.sleep(1)

    # Deleting the DB table entry after bringing down the interface
    duthost.shell(
            "for key in `redis-cli -p 6380 -h 127.0.0.1 -n 13 --scan --pattern \"DPU_STATE|DPU*\" `; "
            "do redis-cli -p 6380 -h 127.0.0.1 -n 13 del $key ; done")

    # Checking the state of dpu health again after bringing down interface and deleting db entry
    dpu_db = wait_until(60, 60, 0, count_dpu_modules_in_system_health_cli, duthost)

    pytest_assert(dpu_db == 0, "Link is not down'{}'".format(duthost.hostname))

    output_interface_cmd = duthost.show_and_parse('show ip interface')
    for index in range(len(output_interface_cmd)):
        parse_output = output_interface_cmd[index]
        interface = parse_output['interface']
        status = parse_output['admin/oper']

        if interface != "eth0" and 'eth' in interface:
            if status == "down/down":
                count_down += 1
            output_intf_up = duthost.shell("ifconfig %s up"%(interface))["stdout_lines"]
            time.sleep(1)

    output_interface_cmd = duthost.show_and_parse('show ip interface')
    for index in range(len(output_interface_cmd)):
        parse_output = output_interface_cmd[index]
        interface = parse_output['interface']
        status = parse_output['admin/oper']

        if interface != "eth0" and 'eth' in interface:
            if status == "up/up":
                count_up += 1

    # Checking the state of dpu health again after bringing up interface and waiting for db entry to get populated
    dpu_db_after = wait_until(60, 60, 0, count_dpu_modules_in_system_health_cli, duthost)

    pytest_assert(dpu_db_before == count_up == count_down == dpu_db_after, "Link Flap is Tested'{}'".format(duthost.hostname))

def test_shutdown_power_up_dpu(duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn):
    """
    @summary: Verify `shut down and power up DPU`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    num_modules = int(chassis.get_num_modules(platform_api_conn))

    for index in range(num_modules):
        dpu = module.get_name(platform_api_conn, index)
        duthosts.shell("config chassis modules shutdown %s"%dpu)
        time.sleep(2)

    pytest_assert(wait_until(120, 60, 0, check_dpu_module_status, duthost, num_modules, "off"),
                          "Not all DPUs operationally down")

    for index in range(num_modules):
        dpu = module.get_name(platform_api_conn, index)
        duthosts.shell("config chassis modules startup %s"%dpu)
        time.sleep(2)

    pytest_assert(wait_until(120, 60, 0, check_dpu_module_status, duthost, num_modules, "on"),
                          "Not all DPUs operationally up")

def test_reboot_cause(duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn):
    """
    @summary: Verify `Reboot Cause`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    num_modules = int(chassis.get_num_modules(platform_api_conn))

    for index in range(num_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        output_shutdown_dpu = duthost.shell("config chassis module shutdown %s"%(dpu_name))["stdout_lines"]
        time.sleep(2)
        output_startup_dpu = duthost.shell("config chassis module startup %s"%(dpus_name))["stdout_lines"]

    pytest_assert(wait_until(120, 60, 0, check_dpu_reboot_cause, duthost, num_modules),
                          "Not all DPUs operationally up")

def test_pcie_link(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify `PCIe link`
    """
    CMD_PCIE_INFO = "show platform pcieinfo -c"

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logging.info("Verifying output of '{}' on '{}'...".format(CMD_PCIE_INFO, duthost.hostname))
    output_pcie_info = duthost.command(CMD_PCIE_INFO)["stdout_lines"]
    pytest_assert(output_pcie_info[-1] == 'PCIe Device Checking All Test ----------->>> PASSED', "PCIe Link is good'{}'".format(duthost.hostname))

    num_modules = int(chassis.get_num_modules(platform_api_conn))

    for index in range(num_modules):
        dpu = module.get_name(platform_api_conn, index)
        duthosts.shell("config chassis modules shutdown %s"%dpu)
        time.sleep(2)

    pytest_assert(wait_until(120, 60, 0, check_dpu_module_status, duthost, num_modules, "off"),
                          "Not all DPUs operationally down")

    for index in range(num_modules):
        dpu = module.get_name(platform_api_conn, index)
        duthosts.shell("config chassis modules startup %s"%dpu)
        time.sleep(2)

    pytest_assert(wait_until(120, 60, 0, check_dpu_module_status, duthost, num_modules, "on"),
                          "Not all DPUs operationally up")

    logging.info("Verifying output of '{}' on '{}'...".format(CMD_PCIE_INFO, duthost.hostname))
    output_pcie_info = duthost.command(CMD_PCIE_INFO)["stdout_lines"]
    pytest_assert("PASSED" == output_pcie_info[-1], "PCIe Link is good'{}'".format(duthost.hostname))
