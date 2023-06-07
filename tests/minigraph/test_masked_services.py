import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

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
        if output["failed"]:
            pytest.fail("Error starting or stopping service")
            return


@pytest.mark.disable_loganalyzer
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
    pytest_assert(not wait_until(30, 10, 0, duthost.is_service_fully_started, "telemetry"), "TELEMETRY still running")

    logging.info("Check service status")
    assert not is_service_loaded(duthost, test_service)

    logging.info("Starting load_minigraph")
    load_minigraph_ret = duthost.shell("config load_minigraph -y")
    load_minigraph_error_code = load_minigraph_ret['failed']

    logging.info("Bring back service if not up")
    change_service_state(duthost, test_service, True)
    logging.info("Wait until service is unmasked and active")
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, "telemetry"), "TELEMETRY not started")

    if load_minigraph_error_code:
        pytest.fail("Test failed as load_minigraph was not successful")
