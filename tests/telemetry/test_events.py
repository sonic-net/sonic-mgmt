import logging
import pytest
import os
import sys

from telemetry_utils import skip_201911_and_older
from events.event_utils import event_publish_tool
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
            try:
                module.test_event(duthost, gnxi_path, ptfhost, ptfadapter, DATA_DIR, validate_yang)
            except pytest.skip.Exception as e:
                logger.info("Skipping test file: {} due to {}".format(file, e))
                continue
            logger.info("Completed test file: {}".format(os.path.join(EVENTS_TESTS_PATH, file)))


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
