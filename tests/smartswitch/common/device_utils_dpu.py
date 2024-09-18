"""
Helper script for DPU  operations
"""
import logging
import pytest
from tests.common.devices.sonic import *  # noqa: F403, F401
from tests.platform_tests.api.conftest import *  # noqa: F403
from pkg_resources import parse_version


@pytest.fixture(scope='function')
def skip_test_smartswitch(duthosts, enum_rand_one_per_hwsku_hostname,
                          platform_api_conn):
    """
    Checks whethere given testbed is smartswitch or not
    If not smartswitch, then skip tests
    else, checks for darkmode of dpus
    If dpus are in dark mode, then skip tests
    else, proceeds to run test cases scripts
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if not duthost.facts["DPUS"] and parse_version(duthost.os_version) <= parse_version("202405"):
        pytest.skip("It is not a smartswitch")

    darkmode = is_dark_mode(duthost, platform_api_conn)

    if darkmode:
        dpu_power_on(duthost, platform_api_conn)


def is_dark_mode(duthost, platform_api_conn):

    num_modules = int(chassis.get_num_modules(platform_api_conn))
    count_admin_down = 0

    for index in range(num_modules):
        output_config_db = duthost.command(
                           redis-cli -p 6379 -h 127.0.0.1 \
                           -n 4 hgetall "CHASSIS_MODULE|DPU%s", % (index))
        if 'down' in output_config_db['stdout']:
             count_admin_down += 1

    if count_admin_down == num_modules:
            return True

    return False


def dpu_poweron(duthost, platform_api_conn):
    """
    Executes power on all DPUs
    Returns:
        Returns True or False based on all DPUs powered on or not
    """

    num_modules = int(chassis.get_num_modules(platform_api_conn))
    ip_address_list = []

    for index in range(num_modules):
        dpu = module.get_name(platform_api_conn, index)
        ip_address_list.append(
                module.get_midplane_ip(platform_api_conn, index))
        duthosts.shell("config chassis modules startup %s" % (dpu))
        time.sleep(2)

    pytest_assert(wait_until(180, 60, 0, check_dpu_ping_status,  # noqa: F405
                  duthost, ip_address_list), "Not all DPUs operationally up")


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
        output_ping = duthost.command("ping -c 3 %s" % (ip_address))
        if "0% packet loss" in output_ping["stdout"]:
            ping_count += 1

    return ping_count == len(ip_address_list)


def check_dpu_module_status(duthost, power_status, dpu_name):
    """
    Check status of given DPU module against given option on/off
    Args:
        duthost : Host handle
        power_status: on/off status of dpu
        dpu_name: name of the dpu module
    Returns:
        Returns True or False based on status of given DPU module
    """

    output_dpu_status = duthost.command(
            'show chassis module status | grep %s' % (dpu_name))

    if "Offline" in output_dpu_status["stdout"]:
        if power_status == "off":
            logging.info("'{}' is offline ...".format(dpu_name))
            return True
        else:
            logging.info("'{}' is online ...".format(dpu_name))
            return False
    else:
        if power_status == "on":
            logging.info("'{}' is online ...".format(dpu_name))
            return True
        else:
            logging.info("'{}' is offline ...".format(dpu_name))
            return False


def check_dpu_reboot_cause(duthost, dpu_name):
    """
    Check reboot cause of all DPU modules
    Args:
        duthost : Host handle
        dpu_name: name of the dpu module
    Returns:
        Returns True or False based on reboot cause of all DPU modules
    """

    output_reboot_cause = duthost.command(
            'show reboot-cause all | grep %s' % (dpu_name))

    if 'Unknown' in output_reboot_cause["stdout"]:
        # Checking for Unknown as of now and
        # implementation for other reasons are not in place now
        # TODO: Needs to be extend the function for other reasons
        logging.info("'{}' - reboot cause is Unkown...".format(dpu_name))
        return True

    return False


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
