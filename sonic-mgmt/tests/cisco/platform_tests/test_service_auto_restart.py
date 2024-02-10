"""
Test auto restart of platform services
"""
import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology('any')
]

def stop_and_restart_status(duthost, service, signal, sleep_time):

    current_status = duthost.command("systemctl is-active {}".format(service), module_ignore_errors=True)
    logging.info(current_status)
    assert "active" == current_status["stdout"].strip(), "{} is currently not running".format(service)

    pid = duthost.command("systemctl show -p MainPID --value {}".format(service))
    logging.info(pid)

    duthost.command("kill -s {} {}".format(signal, pid["stdout"].strip()))
    time.sleep(sleep_time)

    service_status = duthost.command("systemctl is-active {}".format(service), module_ignore_errors=True)
    assert "active" == service_status["stdout"].strip(), "service was not restarted"

    new_pid = duthost.command("systemctl show -p MainPID --value {}".format(service))
    assert new_pid != pid, "restarted service pid should be different than previous running pid"

def check_service_restart_limit_reached(duthost, service):

    pid = duthost.command("systemctl show -p MainPID --value {}".format(service))
    logging.info(pid)
 
    duthost.command("kill -s {} {}".format("SIGKILL", pid["stdout"].strip()))
    time.sleep(20)

    service_status = duthost.command("systemctl status {}".format(service), module_ignore_errors=True)
    assert "Start request repeated too quickly" in service_status["stdout"], "service is active even after restart limit was reached"

    logging.info("{} hits start limit and clear reset-failed flag".format(service))
    duthost.command("systemctl reset-failed {}".format(service))
    duthost.command("systemctl start {}".format(service))


def test_service_reboot_listener(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: test auto restart of platform headless listener service
    """

    service = "platform-reboot-listener.service"
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if not duthost.is_multi_asic or duthost.is_supervisor_node():
        pytest.skip(" {} is not applicable on this DUT".format(service))

    # test multiple auto restart of a service
    for i in range(2):
        stop_and_restart_status(duthost, service, "SIGKILL", 5) 
        time.sleep(5)

def test_service_headless_listener(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: test auto restart of platform reboot listener service
    """

    service = "platform-headless-listener.service"
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if not duthost.is_multi_asic or duthost.is_supervisor_node():
        pytest.skip(" {} is not applicable on this DUT".format(service))

    for i in range(2):
        stop_and_restart_status(duthost, service, "SIGKILL", 5)
        time.sleep(5)

def test_service_cardevent_manager(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: test auto restart of platform cardevent manager service
    """

    service = "platform-cardevent-manager.service"
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if not duthost.is_multi_asic:
        pytest.skip(" {} is not applicable on this DUT".format(service))
        
    for i in range(2):
        stop_and_restart_status(duthost, service, "SIGKILL", 5)
        time.sleep(5)

@pytest.mark.disable_loganalyzer
def test_service_ethswitch(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: test auto restart of platform ethswitch monitor service
    """

    service = "platform-ethswitch.service"
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if not duthost.is_multi_asic:
        pytest.skip(" {} is not applicable on this DUT".format(service))

    for i in range(3):
        stop_and_restart_status(duthost, service, "SIGKILL", 15)
        time.sleep(5)

    check_service_restart_limit_reached(duthost, service)

@pytest.mark.disable_loganalyzer
def test_service_platform_monitor(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: test auto restart of platform monitor service
    """

    service = "platform-monitor.service"
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    for i in range(3):
        stop_and_restart_status(duthost, service, "SIGKILL", 15)
        time.sleep(5)

    check_service_restart_limit_reached(duthost, service)
