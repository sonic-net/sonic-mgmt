"""
Helper script for checking status of critical services

This script contains re-usable functions for checking status of critical services.
"""
import time
import logging

from common.utilities import wait_until


def _all_critical_services_fully_started(dut):
    logging.info("Check critical service status")
    if not dut.critical_services_fully_started():
        logging.info("dut.critical_services_fully_started is False")
        return False

    for service in dut.CRITICAL_SERVICES:
        status = dut.get_service_props(service)
        if status["ActiveState"] != "active":
            logging.info("ActiveState of %s is %s, expected: active" % (service, status["ActiveState"]))
            return False
        if status["SubState"] != "running":
            logging.info("SubState of %s is %s, expected: running" % (service, status["SubState"]))
            return False

    return True

def check_critical_services(dut):
    """
    @summary: Use systemctl to check whether all the critical services have expected status. ActiveState of all
        services must be "active". SubState of all services must be "running".
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    """
    logging.info("Wait until all critical services are fully started")
    assert wait_until(300, 20, _all_critical_services_fully_started, dut), "Not all critical services are fully started"

