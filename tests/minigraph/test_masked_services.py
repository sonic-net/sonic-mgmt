import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common import config_reload

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)


def is_service_loaded(duthost, service):
    output = duthost.shell("systemctl show -p LoadState --value {}.service".format(service))
    if output["failed"]:
        return False
    return output["stdout"] == "loaded"


def change_service_state(duthost, service, enable):
    if enable:
        duthost.command("systemctl unmask {}.service".format(service)),
        duthost.command("systemctl enable {}.service".format(service),
                        module_ignore_errors=True),
        duthost.command("systemctl start {}.service".format(service))
    else:
        duthost.command("systemctl stop {}.service".format(service)),
        duthost.command("systemctl disable {}.service".format(service)),
        duthost.command("systemctl mask {}.service".format(service))


@pytest.mark.disable_loganalyzer
def test_masked_services(duthosts, rand_one_dut_hostname):
    """
    @summary: This test case will mask telemetry/gnmi service, then test load_minigraph and check its success
    """
    duthost = duthosts[rand_one_dut_hostname]
    cmd = "docker images | grep -w sonic-telemetry"
    if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
        cmd = "docker ps | grep -w telemetry"
        if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
            test_service = "telemetry"
        else:
            pytest.fail("Telemetry is not running")
    else:
        cmd = "docker images | grep -w sonic-gnmi"
        if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
            cmd = "docker ps | grep -w gnmi"
            if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
                test_service = "gnmi"
            else:
                pytest.fail("GNMI is not running")
        else:
            pytest.fail("Can't find telemetry and gnmi image")
    logging.info("Bringing down {} service".format(test_service))
    service_status = duthost.critical_process_status(test_service)

    if not service_status:
        pytest.fail("Make sure {} is up and running before calling this test".format(test_service))

    change_service_state(duthost, test_service, False)
    logging.info("Wait until service is masked and inactive")
    pytest_assert(not wait_until(30, 10, 0, duthost.is_service_fully_started, test_service),
                  "{} still running".format(test_service))

    logging.info("Check service status")
    assert not is_service_loaded(duthost, test_service)

    logging.info("Starting load_minigraph")
    try:
        config_reload(duthost, config_source='minigraph')
    except Exception as e:
        pytest.fail("Test failed as load_minigraph was not successful and got exception {}".format(e))
    finally:
        logging.info("Bring back service if not up")
        change_service_state(duthost, test_service, True)
        logging.info("Wait until service is unmasked and active")
        pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, test_service),
                      "{} not started".format(test_service))
        config_reload(duthost, config_source='config_db', safe_reload=True, check_intf_up_ports=True)
