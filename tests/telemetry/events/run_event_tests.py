#! /usr/bin/env python3

import json
import logging
import os

from telemetry_utils import listen_for_event, drain_cache
from telemetry_utils import prepare_yang_validation
logger = logging.getLogger(__name__)


def run_test(duthost, run_cmd, data_dir, validate_yang, trigger, json_file, tag,
             event, timeout=60):
    drain_cache(duthost, 60, run_cmd) # timeout may be called before event is seen
    trigger(duthost) # add events to cache
    # listen from cache
    listen_for_event(tag, event, timeout, duthost, run_cmd, json_file)
    op_file = os.path.join(data_dir, json_file)
    data = {}
    with open(op_file, "r") as f:
        data = json.load(f)
    logger.info("events received: ({})".format(json.dumps(data, indent=4)))
    assert len(data) > 0, "Did not receive event {}".format(event)
    dest = prepare_yang_validation(duthost, json_file)
    validate_yang(duthost, dest, tag)
