"""
Helper script for checking status of critical processes

This script contains re-usable functions for checking status of critical services.
"""
import logging
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, get_plt_reboot_ctrl


def reset_timeout(duthost):
    """
    return: if timeout is specified in inventory file for this dut, return new timeout
            if not specified, return 300 sec as default timeout
    e.g.
        processes_utils.py:
          timeout: 400
          wait: 60
    """
    reset_timeout = 300
    plt_reboot_ctrl = get_plt_reboot_ctrl(duthost, 'processes_utils.py', 'cold')
    if plt_reboot_ctrl:
        reset_timeout = plt_reboot_ctrl.get('timeout', 300)
    return reset_timeout


def get_critical_processes_status(dut):
    processes_status = dut.all_critical_process_status()
    for k, v in list(processes_status.items()):
        if v['status'] is False or len(v['exited_critical_process']) > 0:
            return False, processes_status

    return True, processes_status


def _all_critical_processes_healthy(dut):
    logging.info("Check critical processes status")
    status, _ = get_critical_processes_status(dut)
    return status


def check_critical_processes(dut, watch_secs=0):
    """
    @summary: check all critical processes. They should be all running.
              keep on checking every 5 seconds until watch_secs drops below 0.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param watch_secs: all processes should remain healthy for watch_secs seconds.
    """
    logging.info("Check all critical processes are healthy for {} seconds".format(watch_secs))
    while watch_secs >= 0:
        status, details = get_critical_processes_status(dut)
        pytest_assert(status, "Not all critical processes are healthy: {}".format(details))
        if watch_secs > 0:
            time.sleep(min(5, watch_secs))
        watch_secs = watch_secs - 5


def wait_critical_processes(dut):
    """
    @summary: wait until all critical processes are healthy.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    """
    timeout = reset_timeout(dut)
    # No matter what we set in inventory file, we always set sup timeout to 900
    # because most SUPs have 10+ dockers that need to come up
    if dut.is_supervisor_node():
        timeout = 900
    logging.info("Wait until all critical processes are healthy in {} sec"
                 .format(timeout))
    pytest_assert(wait_until(timeout, 20, 0, _all_critical_processes_healthy, dut),
                  "Not all critical processes are healthy")
