import logging
import pytest
import os
import sys

from tests.common.utilities import InterruptableThread
from telemetry_utils import listen_for_events
from telemetry_utils import skip_201911_and_older
from events.event_utils import create_ip_file
from events.event_utils import event_publish_tool, verify_received_output
from events.event_utils import reset_event_counters, read_event_counters
from events.event_utils import verify_counter_increase, restart_eventd

pytestmark = [
    pytest.mark.topology('any')
]

EVENTS_TESTS_PATH = "./telemetry/events"
sys.path.append(EVENTS_TESTS_PATH)


logger = logging.getLogger(__name__)

BASE_DIR = "logs/telemetry"
DATA_DIR = os.path.join(BASE_DIR, "files")
MISSED_TO_CACHE = 0
PUBLISHED = 1


def validate_yang(duthost, op_file="", yang_file=""):
    assert op_file != "" and yang_file != "", "op_file path or yang_file name not provided"
    cmd = "python ~/validate_yang_events.py -f {} -y {}".format(op_file, yang_file)
    logger.info("Performing yang validation on {} for {}".format(op_file, yang_file))
    ret = duthost.shell(cmd)
    assert ret["rc"] == 0, "Yang validation failed for {}".format(yang_file)


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
@pytest.mark.disable_loganalyzer
def test_events(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, ptfadapter, setup_streaming_telemetry, gnxi_path,
                test_eventd_healthy):
    """ Run series of events inside duthost and validate that output is correct
    and conforms to YANG schema"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logger.info("Start events testing")

    skip_201911_and_older(duthost)

    # Load rest of events
    for file in os.listdir(EVENTS_TESTS_PATH):
        if file.endswith("_events.py") and not file.endswith("eventd_events.py"):
            module = __import__(file[:len(file)-3])
            module.test_event(duthost, gnxi_path, ptfhost, ptfadapter, DATA_DIR, validate_yang)
            logger.info("Completed test file: {}".format(os.path.join(EVENTS_TESTS_PATH, file)))


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
@pytest.mark.disable_loganalyzer
def test_events_cache(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, setup_streaming_telemetry, gnxi_path):
    """Create expected o/p file of events with N events. Call event-publisher tool to publish M events (M<N). Publish
    remainder of events. Verify o/p file that N events were received"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logger.info("Start events cache testing")

    skip_201911_and_older(duthost)
    reset_event_counters(duthost)
    restart_eventd(duthost)
    current_published_counter = read_event_counters(duthost)[1]

    M = 20
    N = 30

    received_op_file = os.path.join(DATA_DIR, "received_op_file")

    create_ip_file(duthost, DATA_DIR, "first_part_ip_file", 1, M)
    create_ip_file(duthost, DATA_DIR, "second_part_ip_file", M + 1, N)

    # Publish first M events
    event_publish_tool(duthost, "first_part_ip_file")

    event_thread = InterruptableThread(target=listen_for_events, args=(duthost, gnxi_path, ptfhost,
                                       "test-event-source:test", received_op_file, 30, N, N-1))
    event_thread.start()

    # Publish second batch of events
    event_publish_tool(duthost, "second_part_ip_file")

    event_thread.join(30)

    # Verify received output
    verify_received_output(received_op_file, N)

    verify_counter_increase(duthost, current_published_counter, N, PUBLISHED)


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
@pytest.mark.disable_loganalyzer
def test_events_cache_overflow(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, setup_streaming_telemetry,
                               gnxi_path):
    """ Published events till cache overflow, stats should read events missed_to_cache"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logger.info("Start events cache overflow testing")

    skip_201911_and_older(duthost)
    reset_event_counters(duthost)
    restart_eventd(duthost)

    current_missed_to_cache_counter = read_event_counters(duthost)[0]

    """Max cache default configuration size is defined as 100 MB (100 * 1024 * 1024) bytes
    and each event is around 150 bytes,such that max cache would hold ~700,000 events.
    event_publish_tool if no input file provided will post X test bgp events twice,
    for shutdown and startup, hence why we pick 351,000 such that 702,000 events get published
    in order to get cache overflow"""

    event_publish_tool(duthost, "", 351000)

    verify_counter_increase(duthost, current_missed_to_cache_counter, 2000, MISSED_TO_CACHE)
