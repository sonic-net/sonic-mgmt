import logging
import time
from tests.common.helpers.assertions import pytest_assert

def is_service_loaded(duthost, service):
    output = duthost.shell("systemctl show -p LoadState --value {}.service".format(service))
    if output['rc'] != "0":
        pytest.fail("Error showing load state of telemetry service")
        return False
    return output['stdout'] == "loaded"

def change_service_state(duthost, service, enable):
    outputs = []
    if enable:
        outputs = [
            duthost.shell("systemctl unmask {}.service".format(service)),
            duthost.shell("systemctl enable {}.service".format(service)),
            duthost.shell("systemctl start {}.service".format(service))
        ]
    else:
        outputs = [
            duthost.shell("systemctl stop {}.service".format(service)),
            duthost.shell("systemctl disable {}.service".format(service)),
            duthost.shell("systemctl mask {}.service".format(service))
        ]
    for output in outputs:
        if output['rc'] != 0:
            pytest.fail("Error starting or stopping service")
            return

def test_masked_services(duthosts, rand_one_dut_hostname):
    """
    @summary: This test case will mask telemetry service, then test load_minigraph and check its success
    """
    duthost = duthosts[rand_one_dut_hostname]
    test_service = "telemetry"

    logging.info("Bringing down telemetry service")
    service_status = duthost.critical_process_status("telemetry")
    if not service_status:
        pytest.fail("Make sure telemetry is up and running before calling this test")

    change_service_state(duthost, test_service, False)
    logging.info("Wait until service is masked and inactive")

    time.sleep(3) #give adequate time for service to become masked and inactive

    logging.info("Check service status")
    assert is_service_loaded(duthost, test_service) == False

    logging.info("Starting load_minigraph")
    load_minigraph_ret = duthost.shell("config load_minigraph -y")
    load_minigraph_error_code = load_minigraph_ret['rc']
    result = load_minigraph_error_code == "0"

    if not result:  
        logging.info("Bring back service if not up")
        change_service_state(duthost, test_service, True)
        logging.info("Wait until service is unmasked and active")
        time.sleep(3)
        duthost.shell("sudo config reload")
        pytest.fail("Test failed as load_minigraph was not successful")

