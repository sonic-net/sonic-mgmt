import logging
import pytest
import os
import sys

from tests.common.utilities import wait_until
from tests.common.utilities import InterruptableThread
from telemetry_utils import listen_for_events
from telemetry_utils import skip_201911_and_older
from events.event_utils import create_ip_file
from events.event_utils import event_publish_tool, verify_received_output

pytestmark = [
    pytest.mark.topology('any')
]

EVENTS_TESTS_PATH = "./telemetry/events"
sys.path.append(EVENTS_TESTS_PATH)


logger = logging.getLogger(__name__)

BASE_DIR = "logs/telemetry"
DATA_DIR = os.path.join(BASE_DIR, "files")


def validate_yang(duthost, op_file="", yang_file=""):
    assert op_file != "" and yang_file != "", "op_file path or yang_file name not provided"
    cmd = "python ~/validate_yang_events.py -f {} -y {}".format(op_file, yang_file)
    logger.info("Performing yang validation on {} for {}".format(op_file, yang_file))
    ret = duthost.shell(cmd)
    assert ret["rc"] == 0, "Yang validation failed for {}".format(yang_file)


def do_init(duthost):
    for i in [BASE_DIR, DATA_DIR]:
        try:
            os.mkdir(i)
        except OSError as e:
            logger.info("Dir/file already exists: {}, skipping mkdir".format(e))

    duthost.copy(src="telemetry/validate_yang_events.py", dest="~/")

    duthost.shell("docker cp eventd:/usr/bin/events_publish_tool.py ~/")
    duthost.shell("chmod +x ~/events_publish_tool.py")


@pytest.mark.disable_loganalyzer
def test_events(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, setup_streaming_telemetry, localhost, gnxi_path):
    """Run series of events inside duthost and validate that output is correct
    and conforms to YANG schema"""
    
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logger.info("Start events testing")

    skip_201911_and_older(duthost)
    do_init(duthost)

    # Test eventd heartbeat event first

    file = "./telemetry/events/eventd_events.py"
    module = __import__(file[:len(file)-3])
    module.test_event(duthost, gnxi_path, ptfhost, DATA_DIR, valdidate_yang)

    # Test rest of events

    for file in os.listdir(EVENTS_TESTS_PATH):
        if file.endswith("bgp_events.py") and not file.endswith("eventd_events.py"):
            module = __import__(file[:len(file)-3])
            module.test_event(duthost, gnxi_path, ptfhost, DATA_DIR, validate_yang)
            logger.info("Completed test file: {}".format(os.path.join(EVENTS_TESTS_PATH, file)))


@pytest.mark.disable_loganalyzer
def test_events_cache(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, gnxi_path):
    """Create expected o/p file of events with N events. Call event-publisher tool to publish M events (M<N). Publish
    remainder of events. Verify o/p file that N events were received"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logger.info("Start events cache testing")

    skip_201911_and_older(duthost)

    M = 20
    N = 30

    received_op_file = os.path.join(DATA_DIR, "received_op_file")

    create_ip_file(duthost, DATA_DIR, "first_part_ip_file", 1, M)
    create_ip_file(duthost, DATA_DIR, "second_part_ip_file", M + 1, N)

    # Publish first M events
    event_publish_tool(duthost, "first_part_ip_file")

    event_thread = InterruptableThread(target=listen_for_events, args=(duthost, gnxi_path, ptfhost, "test-event-source:test", received_op_file, 30))
    event_thread.start()

    # Publish second batch of events
    event_publish_tool(duthost, "second_part_ip_file")

    event_thread.join(30)

    # Verify received output
    verify_received_output(duthost, received_op_file)
