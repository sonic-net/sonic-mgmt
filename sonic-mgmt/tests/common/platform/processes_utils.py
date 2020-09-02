"""
Helper script for checking status of critical processes

This script contains re-usable functions for checking status of critical services.
"""
import logging
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


def get_critical_processes_status(dut):
    processes_status = dut.all_critical_process_status()
    for k, v in processes_status.items():
        if v['status'] == False or len(v['exited_critical_process']) > 0:
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
    logging.info("Wait until all critical processes are healthy")
    pytest_assert(wait_until(300, 20, _all_critical_processes_healthy, dut),
                  "Not all critical processes are healthy")

