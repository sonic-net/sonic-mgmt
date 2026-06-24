"""
Helper script for checking status of critical processes

This script contains re-usable functions for checking status of critical services.
"""
import logging
import time
import re

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, get_plt_reboot_ctrl

logger = logging.getLogger(__name__)

# Conversion factors (minutes) for every unit that `docker ps` may emit.
_DOCKER_UPTIME_UNIT_TO_MINUTES = {
    "second":  1 / 60,
    "seconds": 1 / 60,
    "minute":  1,
    "minutes": 1,
    "hour":    60,
    "hours":   60,
    "day":     60 * 24,
    "days":    60 * 24,
    "week":    60 * 24 * 7,
    "weeks":   60 * 24 * 7,
    "month":   60 * 24 * 30,
    "months":  60 * 24 * 30,
    "year":    60 * 24 * 365,
    "years":   60 * 24 * 365,
}


def check_pmon_uptime_minutes(duthost, minimal_runtime=6, pmon_status=None):
    """
    @summary: Check whether the pmon container has been running for at least minimal_runtime minutes.
    @param duthost: AnsibleHost object for the DUT. May be None when pmon_status is supplied directly.
    @param minimal_runtime: Required minimum uptime in minutes (default 6).
    @param pmon_status: Optional pre-fetched STATUS string from `docker ps` (e.g. "Up 2 months").
                        When supplied, duthost is not queried. Intended for unit-testing only.
    @return: True if pmon uptime >= minimal_runtime minutes, False otherwise.
    """
    if pmon_status is None:
        result = duthost.command("docker ps | grep pmon", _uses_shell=True)
        status_str = result["stdout"] if result["stdout"] else ""
    else:
        status_str = pmon_status

    if not status_str:
        return False

    # Standard form: "Up N <unit>" (e.g. "Up 3 days", "Up 2 months", "Up 6 minutes")
    match = re.search(r'Up (\d+) (\w+)', status_str)
    if match:
        count = int(match.group(1))
        unit = match.group(2).lower()
        factor = _DOCKER_UPTIME_UNIT_TO_MINUTES.get(unit)
        if factor is not None:
            return count * factor >= minimal_runtime

    # Older docker versions emit "Up About an hour" (no digit) for ~60 minutes.
    if re.search(r'Up About an hour', status_str):
        return minimal_runtime <= 60

    return False


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
    for container_name, processes in list(processes_status.items()):
        if processes['status'] is False or len(processes['exited_critical_process']) > 0:
            logger.info("The status of checking process in container '{}' is: {}"
                        .format(container_name, processes["status"]))
            logger.info("The processes not running in container '{}' are: '{}'"
                        .format(container_name, processes["exited_critical_process"]))
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


def wait_critical_processes(dut, timeout=None):
    """
    @summary: wait until all critical processes are healthy.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param timeout: customized timeout value in seconds. If specified, it overwrites the value from inventory file.
    """
    if timeout is None:
        timeout = reset_timeout(dut)
        # No matter what we set in inventory file, we always set sup timeout to 900
        # because most SUPs have 10+ dockers that need to come up
        if dut.is_supervisor_node():
            timeout = 900
    logging.info("Wait until all critical processes are healthy in {} sec"
                 .format(timeout))
    pytest_assert(wait_until(timeout, 20, 0, _all_critical_processes_healthy, dut),
                  "Not all critical processes are healthy")
