"""
Helper script for checking status of critical services

This script contains re-usable functions for checking status of critical services.
"""
import time
import logging

from utilities import wait_until

critical_services = ["swss", "syncd", "database", "teamd", "bgp", "pmon", "lldp"]


def get_service_status(dut, service):
    """
    @summary: Get the ActiveState and SubState of a service. This function uses the systemctl tool to get the
        ActiveState and SubState of specified service.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param service: Service name.
    @return: Returns a dictionary containing ActiveState and SubState of the specified service, for example:
        {
            "ActivateState": "active",
            "SubState": "running"
        }
    """
    output = dut.command("systemctl -p ActiveState -p SubState show %s" % service)
    result = {}
    for line in output["stdout_lines"]:
        fields = line.split("=")
        if len(fields) >= 2:
            result[fields[0]] = fields[1]
    return result


def service_fully_started(dut, service):
    """
    @summary: Check whether the specified service is fully started on DUT. According to the SONiC design, the last
        instruction in service starting script is to run "docker wait <service_name>". This function take advantage
        of this design to check whether a service has been fully started. The trick is to check whether
        "docker wait <service_name>" exists in current running processes.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param service: Service name.
    @return: Return True if the specified service is fully started. Otherwise return False.
    """
    try:
        output = dut.command('pgrep -f "docker wait %s"' % service)
        if output["stdout_lines"]:
            return True
        else:
            return False
    except:
        return False


def critical_services_fully_started(dut):
    """
    @summary: Check whether all the critical service have been fully started.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @return: Return True if all the critical services have been fully started. Otherwise return False.
    """
    result = {}
    for service in critical_services:
        result[service] = service_fully_started(dut, service)
    logging.debug("Status of critical services: %s" % str(result))
    return all(result.values())


def check_critical_services(dut):
    """
    @summary: Use systemctl to check whether all the critical services have expected status. ActiveState of all
        services must be "active". SubState of all services must be "running".
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    """
    logging.info("Wait until all critical services are fully started")
    assert wait_until(300, 20, critical_services_fully_started, dut), "Not all critical services are fully started"

    logging.info("Check critical service status")
    for service in critical_services:
        status = get_service_status(dut, service)
        assert status["ActiveState"] == "active", \
            "ActiveState of %s is %s, expected: active" % (service, status["ActiveState"])
        assert status["SubState"] == "running", \
            "SubState of %s is %s, expected: active" % (service, status["SubState"])
