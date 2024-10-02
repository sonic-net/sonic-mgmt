import logging
import pytest
import os
import sys

from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.utilities import wait_until
from tests.telemetry.telemetry_utils import get_list_stdout
from tests.common.helpers.telemetry_helper import _context_for_setup_streaming_telemetry

EVENTS_TESTS_PATH = "./telemetry/events"
sys.path.append(EVENTS_TESTS_PATH)

BASE_DIR = "logs/telemetry"
DATA_DIR = os.path.join(BASE_DIR, "files")

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse=True)
def verify_telemetry_dockerimage(duthosts, enum_rand_one_per_hwsku_hostname):
    """If telemetry docker is available in image then return true
    """
    docker_out_list = []
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    docker_out = duthost.shell('docker images', module_ignore_errors=False)['stdout_lines']
    docker_out_list = get_list_stdout(docker_out)
    matching = [s for s in docker_out_list if b"docker-sonic-gnmi" in s or b"docker-sonic-telemetry" in s]
    if not (len(matching) > 0):
        pytest.skip("docker-sonic-gnmi and docker-sonic-telemetry are not part of the image")


@pytest.fixture(scope="module")
def setup_streaming_telemetry(request, duthosts, enum_rand_one_per_hwsku_hostname, localhost, ptfhost, gnxi_path):
    with _context_for_setup_streaming_telemetry(request, duthosts, enum_rand_one_per_hwsku_hostname,
                                                localhost, ptfhost, gnxi_path) as result:
        yield result


def do_init(duthost):
    for i in [BASE_DIR, DATA_DIR]:
        try:
            os.mkdir(i)
        except OSError as e:
            logger.info("Dir/file already exists: {}, skipping mkdir".format(e))

        duthost.copy(src="telemetry/validate_yang_events.py", dest="~/")


@pytest.fixture(scope="module")
def test_eventd_healthy(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, ptfadapter,
                        setup_streaming_telemetry, gnxi_path):
    """
    @summary: Test eventd heartbeat before testing all testcases
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    features_dict, succeeded = duthost.get_feature_status()
    if succeeded and ('eventd' not in features_dict or features_dict['eventd'] == 'disabled'):
        pytest.skip("eventd is disabled on the system")

    do_init(duthost)

    module = __import__("eventd_events")

    duthost.shell("systemctl restart eventd")

    py_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, "eventd"), "eventd not started.")

    module.test_event(duthost, gnxi_path, ptfhost, ptfadapter, DATA_DIR, None)

    logger.info("Completed test file: {}".format("eventd_events test completed."))
