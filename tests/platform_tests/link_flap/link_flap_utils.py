"""
Test utils used by the link flap tests.
"""
import time
import logging

from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert


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
        logging.debug("Interface status : %s", status)
    return status['oper_state'] == exp_state


def build_test_candidates(dut, fanouthosts, completeness_level=None):
    """
    Find test candidates for link flap test.

    Args:
        dut: DUT host object
        fanouthosts: List of fanout switch instances.
        completeness_level: Completeness level.

    Returns:
        A list of tuple with DUT's port, fanout port
        and fanout
    """
    status = __get_dut_if_status(dut)
    candidates = []

    for dut_port in status.keys():
        fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, dut_port)

        if not fanout or not fanout_port:
            logging.info("Skipping port %s that is not found in connection graph", dut_port)
        elif status[dut_port]['admin_state'] == 'down':
            logging.info("Skipping port %s that is admin down", dut_port)
        else:
            candidates.append((dut_port, fanout, fanout_port))
            if completeness_level == 'debug':
                # Run the test for one port only - to just test if the test works fine
                return candidates

    return candidates


def toggle_one_link(dut, dut_port, fanout, fanout_port, watch=False):
    """
    Toggle one link on the fanout.

    Args:
        dut: DUT host object
        dut_port: Port of DUT
        fanout: Fanout host object
        fanout_port: Port of fanout
        watch: Logging system state
    """
    logging.info("Testing link flap on %s", dut_port)

    pytest_assert(__check_if_status(dut, dut_port, 'up', verbose=True), "Fail: dut port {}: link operational down".format(dut_port))

    logging.info("Shutting down fanout switch %s port %s connecting to %s", fanout.hostname, fanout_port, dut_port)
    fanout.shutdown(fanout_port)
    wait_until(30, 1, __check_if_status, dut, dut_port, 'down')
    pytest_assert(__check_if_status(dut, dut_port, 'down', verbose=True), "dut port {} didn't go down as expected".format(dut_port))

    if watch:
        time.sleep(1)
        watch_system_status(dut)

    logging.info("Bring up fanout switch %s port %s connecting to %s", fanout.hostname, fanout_port, dut_port)
    fanout.no_shutdown(fanout_port)
    wait_until(30, 1, __check_if_status, dut, dut_port, 'up')
    pytest_assert(__check_if_status(dut, dut_port, 'up', verbose=True), "dut port {} didn't go down as expected".format(dut_port))


def watch_system_status(dut):
    """
    Watch DUT's system status

    Args:
        dut: DUT host object
    """
    # Watch memory status
    memory_output = dut.shell("show system-memory")["stdout"]
    logging.info("Memory Status: %s", memory_output)

    # Watch orchagent CPU utilization
    orch_cpu = dut.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"]
    logging.info("Orchagent CPU Util: %s", orch_cpu)

    # Watch Redis Memory
    redis_memory = dut.shell("redis-cli info memory | grep used_memory_human")["stdout"]
    logging.info("Redis Memory: %s", redis_memory)
