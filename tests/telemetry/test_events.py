import logging
import pytest
import json
import os
import sys

from telemetry_utils import skip_201911_and_older
from telemetry_utils import skip_arm_platform

pytestmark = [
    pytest.mark.topology('any')
]

EVENTS_TESTS_PATH = "./telemetry/events"
sys.path.append(EVENTS_TESTS_PATH)


logger = logging.getLogger(__name__)

BASE_DIR = "logs/telemetry"
DATA_DIR = os.path.join(BASE_DIR, "files")

CMD_PREFIX_FMT = ("{} -client_types=gnmi -a {}:50051 -t EVENTS "
                  "-logtostderr -insecure -v 7 -streaming_type ON_CHANGE "
                  "-qt s -q all")
CMD_PREFIX = ""

GNMI_CLI_BIN = None


def validate_yang(duthost, op_file="", yang_file=""):
    assert op_file != "" and yang_file != "", "op_file path or yang_file name not provided"
    cmd = "python /tmp/validate_yang_events.py -f {} -y {}".format(op_file, yang_file)
    logger.info("Performing yang validation on {} for {}".format(op_file, yang_file))
    ret = duthost.shell(cmd)
    assert ret["rc"] == 0, "Yang validation failed for {}".format(yang_file)


def run_cmd(localhost, params={}, op_file="", filter_event="", event_cnt=0, timeout=0):
    cmd = CMD_PREFIX
    for i in params:
        cmd += "[{}]".format(i)

    if (op_file != ""):
        cmd += " -output_file={}".format(op_file)

    if (filter_event != ""):
        cmd += " -expected_event={}".format(filter_event)

    if (event_cnt > 0):
        cmd += " -expected_count={}".format(event_cnt)

    if (timeout > 0):
        cmd += " -streaming_timeout={}".format(timeout)

    ret = localhost.shell(cmd)
    assert ret["rc"] == 0, "Failed to run cmd {}".format(cmd)


def do_init(duthost):
    global CMD_PREFIX, GNMI_CLI_BIN

    for i in [BASE_DIR, DATA_DIR]:
        try:
            os.mkdir(i)
        except OSError as e:
            logger.info("Dir/file already exists: {}, skipping mkdir".format(e))

    duthost.shell("docker cp telemetry:/usr/sbin/gnmi_cli /tmp")
    ret = duthost.fetch(src="/tmp/gnmi_cli", dest=DATA_DIR)
    GNMI_CLI_BIN = ret.get("dest", None)
    assert GNMI_CLI_BIN is not None, "Failing to get gnmi_cli"

    os.system("chmod +x {}".format(GNMI_CLI_BIN))
    logger.info("GNMI_CLI_BIN={}".format(GNMI_CLI_BIN))
    CMD_PREFIX = CMD_PREFIX_FMT.format(GNMI_CLI_BIN, duthost.mgmt_ip)

    ret = duthost.copy(src="telemetry/validate_yang_events.py", dest="/tmp")


def drain_cache(duthost, localhost):
    run_cmd(localhost, ["heartbeat=2"], timeout=180)


def check_heartbeat(duthost, localhost):
    op_file = os.path.join(DATA_DIR, "check_heartbeat.json")
    logger.info("Validating sonic-events-eventd:heartbeat is working")
    run_cmd(localhost, ["heartbeat=2"], op_file=op_file,
            filter_event="sonic-events-eventd:heartbeat", event_cnt=1,
            timeout=60)
    data = {}
    with open(op_file, "r") as f:
        data = json.load(f)
    logger.info("events received: ({})".format(json.dumps(data, indent=4)))
    assert len(data) > 0, "Failed to check heartbeat"


def test_events(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, setup_streaming_telemetry, localhost, gnxi_path):
    """ Run series of events inside duthost and validate that output is correct
    and conforms to YANG schema
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logger.info("Start events testing")

    skip_201911_and_older(duthost)
    skip_arm_platform(duthost)
    do_init(duthost)

    drain_cache(duthost, localhost)
    check_heartbeat(duthost, localhost)

    # Load all events test code and run
    for file in os.listdir(EVENTS_TESTS_PATH):
        if file.endswith(".py"):
            module = __import__(file[:len(file)-3])
            module.test_event(duthost, localhost, run_cmd, DATA_DIR, validate_yang)
            logger.info("Completed test file: {}".format(os.path.join(EVENTS_TESTS_PATH, file)))
