import re
import time
import logging
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_ports import encode_dut_port_name

"""
Helper script for fanout switch operations
"""

logger = logging.getLogger(__name__)


def fanout_switch_port_lookup(fanout_switches, dut_name, dut_port):
    """
        look up the fanout switch instance and the fanout switch port
        connecting to the dut_port

        Args:
            fanout_switches (list FanoutHost): list of fanout switch
                                               instances.
            dut_name (str): the host name of the DUT
            dut_port (str): port name on the DUT

        Returns:
            None, None if fanout switch instance and port is not found
            FanoutHost, Portname(str) if found
    """
    dut_host_port = encode_dut_port_name(dut_name, dut_port)
    for _, fanout in list(fanout_switches.items()):
        if dut_host_port in fanout.host_to_fanout_port_map:
            return fanout, fanout.host_to_fanout_port_map[dut_host_port]

    return None, None


def get_dut_psu_line_pattern(dut):
    if "201811" in dut.os_version or "201911" in dut.os_version:
        psu_line_pattern = re.compile(r"PSU\s+(\d)+\s+(OK|NOT OK|NOT PRESENT)")
    elif dut.facts['platform'] == "x86_64-dellemc_z9332f_d1508-r0":
        psu_line_pattern = re.compile(r"PSU\s+(\d+).*?(OK|NOT OK|NOT PRESENT|WARNING)\s+(N/A)")
    else:
        """
        Changed the pattern to match space (s+) and non-space (S+) only.
        w+ cannot match following examples properly:

        example 1:
            PSU 1  PWR-500AC-R  L8180S01HTAVP  N/A            N/A            N/A          OK        green
            PSU 2  PWR-500AC-R  L8180S01HFAVP  N/A            N/A            N/A          OK        green
        example 2:
            PSU 1  N/A      N/A               12.05           3.38        40.62  OK        green
            PSU 2  N/A      N/A               12.01           4.12        49.50  OK        green

        """
        psu_line_pattern = re.compile(r"PSU\s+(\d+).*?(OK|NOT OK|NOT PRESENT|WARNING)\s+(green|amber|red|off|N/A)")
    return psu_line_pattern


def list_dut_fanout_connections(dut, fanouthosts):
    """
    Lists connected dut-fanout ports

    Args:
        dut: DUT host object
        fanouthosts: List of fanout switch instances.

    Returns:
        A list of tuple with DUT's port, fanout port
        and fanout
    """
    candidates = []

    status = dut.show_interface(command='status')['ansible_facts']['int_status']

    for dut_port in list(status.keys()):
        fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, dut.hostname, dut_port)

        if fanout and fanout_port and status[dut_port]['admin_state'] != 'down':
            candidates.append((dut_port, fanout, fanout_port))

    return candidates


def watch_system_status(dut):
    """
    Watch DUT's system status

    Args:
        dut: DUT host object
    """
    # Watch memory status
    memory_output = dut.shell("show system-memory")["stdout"]
    logger.info("Memory Status: %s", memory_output)

    # Watch orchagent CPU utilization
    orch_cpu = dut.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"]
    logger.info("Orchagent CPU Util: %s", orch_cpu)

    # Watch Redis Memory
    redis_memory = dut.shell("redis-cli info memory | grep used_memory_human")["stdout"]
    logger.info("Redis Memory: %s", redis_memory)


def __get_dut_if_status(dut, ifname=None):
    """
    Get interface status on the DUT.

    Args:
        dut: DUT host object
        ifname: Interface of DUT
        exp_state: State of DUT's port ('up' or 'down')
        verbose: Logging port state.

    Returns:
        Interface state
    """
    if not ifname:
        status = dut.show_interface(command='status')['ansible_facts']['int_status']
    else:
        status = dut.show_interface(command='status', interfaces=[ifname])['ansible_facts']['int_status']
    return status


def __check_if_status(dut, dut_port, exp_state, verbose=False):
    """
    Check interface status on the DUT.

    Args:
        dut: DUT host object
        dut_port: Port of DUT
        exp_state: State of DUT's port ('up' or 'down')
        verbose: Logging port state.

    Returns:
        Bool value which confirm port state
    """
    status = __get_dut_if_status(dut, dut_port)[dut_port]
    if verbose:
        logger.debug("Interface status : %s", status)
    return status['oper_state'] == exp_state


def toggle_one_link(dut, dut_port, fanout, fanout_port, watch=False, check_status=True):
    """
    Toggle one link on the fanout.

    Args:
        dut: DUT host object
        dut_port: Port of DUT
        fanout: Fanout host object
        fanout_port: Port of fanout
        watch: Logging system state
    """

    sleep_time = 90
    logger.info("Testing link flap on %s", dut_port)
    if check_status:
        pytest_assert(__check_if_status(dut, dut_port, 'up', verbose=True),
                      "Fail: dut port {}: link operational down".format(dut_port))

    logger.info("Shutting down fanout switch %s port %s connecting to %s", fanout.hostname, fanout_port, dut_port)

    need_recovery = True
    try:
        fanout.shutdown(fanout_port)
        if check_status:
            pytest_assert(wait_until(sleep_time, 1, 0, __check_if_status, dut, dut_port, 'down', True),
                          "dut port {} didn't go down as expected".format(dut_port))

        if watch:
            time.sleep(1)
            watch_system_status(dut)

        logger.info("Bring up fanout switch %s port %s connecting to %s", fanout.hostname, fanout_port, dut_port)
        fanout.no_shutdown(fanout_port)
        need_recovery = False

        if check_status:
            pytest_assert(wait_until(sleep_time, 1, 0, __check_if_status, dut, dut_port, 'up', True),
                          "dut port {} didn't go up as expected".format(dut_port))
    finally:
        if need_recovery:
            fanout.no_shutdown(fanout_port)
            if check_status:
                wait_until(sleep_time, 1, 0, __check_if_status, dut, dut_port, 'up', True)
