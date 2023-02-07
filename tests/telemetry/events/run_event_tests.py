#! /usr/bin/env python3

import json
import logging
import os

from telemetry_utils import listenForEvent

logger = logging.getLogger(__name__)


def run_test(duthost, localhost, run_cmd, data_dir, validate_yang, trigger, json_file, tag, event, timeout=20):
    op_file = os.path.join(data_dir, json_file)

    trigger(duthost)
    listenForEvent(tag, event, timeout, localhost, run_cmd, op_file)

    data = {}
    with open(op_file, "r") as f:
        data = json.load(f)
    logger.info("events received: ({})".format(json.dumps(data, indent=4)))
    assert len(data) > 0, "Did not receive event {}".format(event)
    dest = "/tmp/{}".format(json_file)
    duthost.copy(src=op_file, dest=dest)
    validate_yang(duthost, dest, event)
