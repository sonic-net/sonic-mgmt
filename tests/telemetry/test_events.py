import logging
import pytest
import json
import os
import sys

from telemetry_utils import skip_201911_and_older

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
    cmd = "python /tmp/validate_yang_events.py -f {} -y {}".format(op_file, yang_file)
    logger.info("Performing yang validation on {} for {}".format(op_file, yang_file))
    ret = duthost.shell(cmd)
    assert ret["rc"] == 0, "Yang validation failed for {}".format(yang_file)


def do_init(duthost): 
    for i in [BASE_DIR, DATA_DIR]:
        try:
            os.mkdir(i)
        except OSError as e:
            logger.info("Dir/file already exists: {}, skipping mkdir".format(e))

    ret = duthost.copy(src="telemetry/validate_yang_events.py", dest="/tmp")


def test_events(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, setup_streaming_telemetry, localhost, gnxi_path):
    """ Run series of events inside duthost and validate that output is correct
    and conforms to YANG schema
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logger.info("Start events testing")

    skip_201911_and_older(duthost)
    do_init(duthost)

    # Load all events test code and run
    for file in os.listdir(EVENTS_TESTS_PATH):
        if file.endswith("_events.py"):
            module = __import__(file[:len(file)-3])
            module.test_event(duthost, gnxi_path, ptfhost, DATA_DIR, validate_yang)
            logger.info("Completed test file: {}".format(os.path.join(EVENTS_TESTS_PATH, file)))
