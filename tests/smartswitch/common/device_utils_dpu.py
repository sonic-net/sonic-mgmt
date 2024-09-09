"""
Helper script for DPU  operations
"""

import time
import pytest
from tests.common.utilities import wait_until
from tests.common.helpers.platform_api import chassis, module
from tests.platform_tests.api.conftest import * #noqa
from tests.common.devices.sonic import * #noqa
from tests.common.helpers.assertions import pytest_assert

@pytest.fixture(scope='function', autouse=True)
def dpu_poweron(duthosts, enum_rand_one_per_hwsku_hostname, request, platform_api_conn):
    """
    Executes power on all DPUs
    Returns:
        Returns True or False based on all DPUs powered on or not
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    num_modules = int(chassis.get_num_modules(platform_api_conn))
    ip_address_list = []

    for index in range(num_modules):
        dpu = module.get_name(platform_api_conn, index)
        ip_address_list.append(module.get_midplane_ip(platform_api_conn, index))
        duthosts.shell("config chassis modules startup %s"%dpu)
        time.sleep(2)

    pytest_assert(wait_until(120, 30, 0, check_dpu_ping_status, duthost, ip_address_list),
                          "Not all DPUs operationally up")

def check_dpu_ping_status(duthost, ip_address_list):
    """
    Executes ping to all DPUs
    Args:
        duthost : Host handle
        ip_address_list (list): List of all DPU ip addresses
    Returns:
        Returns True or False based on Ping is successfull or not to all DPUs
    """

    ping_count = 0
    for ip_address in ip_address_list:
        output_ping = duthost.command("ping -c 3 %s"%ip_address)["stdout_lines"]
        for i in range(len(output_ping)):
            if "0% packet loss" in output_ping[i]:
                ping_count += 1

    return ping_count == len(ip_address_list)


def check_dpu_module_status(duthost, num_modules, power_status):
    """
    Check status of all DPU modules against given option on/off
    Args:
        duthost : Host handle
        num_modules: Number of dpu modules
        power_status: on/off status of dpu
    Returns:
        Returns True or False based on status of all DPU modules
    """
    dpu_off_count = 0
    dpu_on_count = 0
    dpu_status_count = 0

    output_dpu_status = duthost.show_and_parse('show chassis module status')

    for index in range(len(output_dpu_status)):
        parse_output = output_dpu_status[index]
        if parse_output['oper-status'] == 'Offline':
            logging.info("'{}' is offline ...".format(parse_output['name']))
            dpu_off_count += 1
        else:
            logging.info("'{}' is online ...".format(parse_output['name']))
            dpu_on_count += 1

    if power_status == "on":
        dpu_status_count = dpu_on_count
    elif power_status == "off":
        dpu_status_count = dpu_off_count

    return dpu_status_count == num_modules


def check_dpu_reboot_cause(duthost, num_modules):
    """
    Check reboot cause of all DPU modules
    Args:
        duthost : Host handle
        num_modules: Number of dpu modules
    Returns:
        Returns True or False based on reboot cause of all DPU modules
    """
    len_show_cmd = 0
    output_reboot_cause = duthost.show_and_parse('show reboot-cause all')

    for index in range(len(output_reboot_cause)):
        parse_output = output_reboot_cause[index]
        # Checking for Unknown as of now and implementation for other reasons are not in place now
        # TODO: Needs to be extend the function for other reasons
        if 'DPU' in parse_output['device']
            logging.info("'{}' - reboot cause is {}...".format(parse_output['device'], parse_output['cause']))
            if parse_output['cause'] == 'Unknown':
                len_show_cmd += 1

    return num_modules == len_show_cmd

def count_dpu_modules_in_system_health_cli(duthost):
    """
    Checks and returns number of dpu modules listed  in show system-health DPU
    Args:
        duthost : Host handle
    Returns:
        Returns number of DPU modules that displays system-health status
    """

    num_dpu_health_status = 0
    output_dpu_health_cmd = duthost.show_and_parse("show system-health DPU")

    for index in range(len(output_dpu_health_cmd)):
        parse_output = output_dpu_health_cmd[index]
        if 'DPU' in parse_output['name']:
            num_dpu_health_status += 1

    return num_dpu_health_status
