import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

PING_MAX_TIMEOUT = 180
PING_MAX_TIME_INT = 60
midplane_prefix = "169.254.200."

logger = logging.getLogger(__name__)



def dpu_power_on_for_index(duthost, dpu_index):    # noqa F811
    """
    Executes power on for a specific DPU
    """
    try:
        duthost.shell(f"sudo config chassis module startup DPU{dpu_index}")
    except Exception as e:
        logger.error(f"Error powering on dpu{dpu_index}: {e}")

    ip_address = f"{midplane_prefix}{dpu_index + 1}"
    pytest_assert(wait_until(PING_MAX_TIMEOUT, PING_MAX_TIME_INT, 0,
                  check_dpu_ping_status,
                  duthost, ip_address),
                  "DPU is not operationally UP")


def dpu_power_off_for_index(duthost, dpu_index):    # noqa F811
    """
    Executes power off a specific DPU
    """
    try:
        duthost.shell(f"sudo config chassis module shutdown DPU{dpu_index}")
    except Exception as e:
        logger.error(f"Error powering off dpu{dpu_index}: {e}")

    ip_address = f"{midplane_prefix}{dpu_index + 1}"
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
    try:
        output_ping = duthost.command("ping -c 3 %s" % (ip_address))
        logging.info("Ping output: '{}'".format(output_ping))
        if "0% packet loss" in output_ping["stdout"]:
            return True
        else:
            logging.warn("Ping failed for '{}'".format(ip_address))
            return False
    except Exception as e:
        logging.info(f"Ping output exception {e}")
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
    try:
        output_ping = duthost.command("ping -c 3 %s" % (ip_address), module_ignore_errors=True)
        logging.info("Ping output: '{}'".format(output_ping))
        if "100% packet loss" in output_ping["stdout"]:
            logging.info("Ping is not working for '{}'".format(ip_address))
            return True
        else:
            logging.error("Ping still work for '{}'".format(ip_address))
            return False
    except Exception as e:
        logging.info(f"Ping output exception {e}")
        return True
