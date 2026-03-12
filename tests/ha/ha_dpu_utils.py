import logging
from tests.common.platform.device_utils import platform_api_conn  # noqa: F401,F403
from tests.common.helpers.platform_api import module
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

PING_MAX_TIMEOUT = 180
PING_MAX_TIME_INT = 60


def dpu_power_on_index(duthost, platform_api_conn, dpu_index):    # noqa F811
    """
    Executes power on for a specific DPU
    """

    dpu = module.get_name(platform_api_conn, dpu_index)
    ip_address = module.get_midplane_ip(platform_api_conn, dpu_index)
    duthost.shell("sudo config chassis modules startup %s" % (dpu))

    pytest_assert(wait_until(PING_MAX_TIMEOUT, PING_MAX_TIME_INT, 0,
                  check_dpu_ping_status,
                  duthost, ip_address),
                  "DPU is not operationally UP")


def dpu_power_off_index(duthost, platform_api_conn, dpu_index):    # noqa F811
    """
    Executes power off a specific DPU
    """

    dpu = module.get_name(platform_api_conn, dpu_index)
    ip_address = module.get_midplane_ip(platform_api_conn, dpu_index)
    duthost.shell("sudo config chassis modules shutdown %s" % (dpu))

    pytest_assert(wait_until(PING_MAX_TIMEOUT, PING_MAX_TIME_INT, 0,
                  check_dpu_not_pingable,
                  duthost, ip_address),
                  "DPU is still UP")


def check_dpu_ping_status(duthost, ip_address):
    """
    Executes ping to the IP address of the DPU
    Args:
        duthost : Host handle
        ip_address: DPU ip addresses
    Returns:
        Returns True or False based on Ping is successfull or not
    """

    output_ping = duthost.command("ping -c 3 %s" % (ip_address))
    logging.info("Ping output: '{}'".format(output_ping))
    if "0% packet loss" in output_ping["stdout"]:
        return True
    else:
        logging.error("Ping failed for '{}'".format(ip_address))
        return False


def check_dpu_not_pingable(duthost, ip_address):
    """
    Executes ping to a DPU
    Args:
        duthost : Host handle
        ip_address : DPU ip addresses
    Returns:
        Returns True or False if Ping failed or not
    """
    output_ping = duthost.command("ping -c 3 %s" % (ip_address), module_ignore_errors=True)
    logging.info("Ping output: '{}'".format(output_ping))
    if "100% packet loss" in output_ping["stdout"]:
        logging.info("Ping is not working for '{}'".format(ip_address))
        return True
    else:
        logging.error("Ping still work for '{}'".format(ip_address))
        return False
