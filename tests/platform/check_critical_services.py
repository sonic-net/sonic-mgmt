"""
Helper script for checking status of critical services

This script contains re-usable functions for checking status of critical services.
"""
import time
import logging

from common.utilities import wait_until


def check_critical_services(dut):
    """
    @summary: Use systemctl to check whether all the critical services have expected status. ActiveState of all
        services must be "active". SubState of all services must be "running".
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    """
    logging.info("Wait until all critical services are fully started")
    assert wait_until(300, 20, dut.critical_services_fully_started), "Not all critical services are fully started"

    logging.info("Check critical service status")
    for service in dut.CRITICAL_SERVICES:
        status = dut.get_service_props(service)
        assert status["ActiveState"] == "active", \
            "ActiveState of %s is %s, expected: active" % (service, status["ActiveState"])
        assert status["SubState"] == "running", \
            "SubState of %s is %s, expected: active" % (service, status["SubState"])
