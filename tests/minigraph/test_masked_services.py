import logging
import time

from tests.common.helpers.assertions import pytest_assert

def is_service_up(duthost, service):
    output = duthost.shell("sudo systemctl show -p LoadState --value {}.service".format(service))
    if output['stdout'] != "loaded":
        return False
    return True

def change_service_state(duthost, service, enable):
    if not enable:
        duthost.shell("sudo systemctl stop {}.service".format(service))
        duthost.shell("sudo systemctl disable {}.service".format(service))
        duthost.shell("sudo systemctl mask {}.service".format(service))
    else:
        duthost.shell("sudo systemctl unmask {}.service".format(service))
        duthost.shell("sudo systemctl enable {}.service".format(service))
        duthost.shell("sudo systemctl start {}.service".format(service))

def test_masked_services(duthosts, rand_one_dut_hostname):
    """
    @summary: This test case will mask a running service, then test load_minigraph and check its success
    """

    duthost = duthosts[rand_one_dut_hostname]

    logging.info("Bringing down a running service")

    test_service = ""
    services = [
        "telemetry",
        "restapi",
        "bgp",
        "lldp",
        "pmon",
        "swss",
        "nat"
    ]
   
    for service in services:
        service_status = duthost.critical_process_status(service)
        if service_status:
            test_service = service
            break

    if not test_service:
        logging.error("No valid service to run test on.")
        return

    logging.info("Bringing down {}".format(test_service))
    change_service_state(duthost, test_service, False)

    logging.info("Wait until service is masked and inactive")

    time.sleep(3)

    logging.info("Check service status")

    assert is_service_up(duthost, test_service) == False
    logging.info("Starting load_minigraph")

    duthost.shell("sudo config load_minigraph -y")
    load_minigraph_error_code = duthost.shell("sudo echo $?")
    result = load_minigraph_error_code['stdout'] == "0"

    if not result:
        logging.info("Bring back service if not up")
        change_service_state(duthost, test_service, True)
        logging.info("Wait until service is unmasked and active")
        time.sleep(3)
        duthost.shell("sudo config reload")
        time.sleep(3)
        assert result == True
