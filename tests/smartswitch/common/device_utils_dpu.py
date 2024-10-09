"""
Helper script for DPU  operations
"""
import logging
import pytest
from tests.common.devices.sonic import *  # noqa: F401,F403
from tests.platform_tests.api.conftest import *  # noqa: F401,F403
from tests.common.helpers.platform_api import chassis, module
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from pkg_resources import parse_version


@pytest.fixture(scope='function')
def num_dpu_modules(platform_api_conn):
    """
    Returns the number of DPU modules
    """

    num_modules = int(chassis.get_num_modules(platform_api_conn))
    logging.info("Num of modules: '{}'".format(num_modules))

    return num_modules


@pytest.fixture(scope='function')
def check_smartswitch_and_dark_mode(duthosts,
                                    enum_rand_one_per_hwsku_hostname,
                                    platform_api_conn):
    """
    Checks whether given testbed is running
    202405 image or below versions
    If True, then skip the script
    else checks if dpus are in darkmode
    If dpus are in dark mode, then power up the DPUs
    else, proceeds to run all test cases
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if not duthost.facts["DPUS"] and \
            parse_version(duthost.os_version) <= parse_version("202405"):
        pytest.skip("Test is not supported for this testbed and os version")

    darkmode = is_dark_mode_enabled(duthost, platform_api_conn)

    if darkmode:
        dpu_power_on(duthost, platform_api_conn)


def is_dark_mode_enabled(duthost, platform_api_conn):
    """
    Checks the liveliness of DPU
    Returns:
        True if all DPUs admin status are down
        else False
    """

    num_modules = num_dpu_modules(platform_api_conn)
    count_admin_down = 0

    for index in range(num_modules):
        dpu = module.get_name(platform_api_conn, index)
        output_config_db = duthost.command(
                           'redis-cli -p 6379 -h 127.0.0.1 \
                            -n 4 hgetall "CHASSIS_MODULE|{}"'.format(dpu))
        if output_config_db['stdout'] is None:
            logging.warn("redis cli output for chassis module state is empty")
            return False

        if 'down' in output_config_db['stdout']:
            count_admin_down += 1

    if count_admin_down == num_modules:
        logging.info("Smartswitch is in dark mode")
        return True

    logging.info("Smartswitch is in non-dark mode")
    return False


def dpu_power_on(duthost, platform_api_conn, check_dpu_ping_status):
    """
    Executes power on all DPUs
    Returns:
        Returns True or False based on all DPUs powered on or not
    """

    num_modules = num_dpu_modules(platform_api_conn)
    ip_address_list = []

    for index in range(num_modules):
        dpu = module.get_name(platform_api_conn, index)
        ip_address_list.append(
                module.get_midplane_ip(platform_api_conn, index))
        duthost.shell("config chassis modules startup %s" % (dpu))

    pytest_assert(wait_until(180, 60, 0, check_dpu_ping_status,
                  duthost, ip_address_list), "Not all DPUs are operationally up")


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
        logging.info("Ping output: '{}'".format(output_ping))
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
