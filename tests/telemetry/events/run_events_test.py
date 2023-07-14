#! /usr/bin/env python3

import json
import logging
import os


from telemetry_utils import listen_for_events
logger = logging.getLogger(__name__)


def run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, trigger, json_file,
             filter_event_regex, tag):
    op_file = os.path.join(data_dir, json_file)
    heartbeat = trigger is None
    if not heartbeat:  # no trigger for heartbeat
        trigger(duthost)  # add events to cache
    listen_for_events(duthost, gnxi_path, ptfhost, filter_event_regex, op_file)  # listen from cache
    data = {}
    with open(op_file, "r") as f:
        data = json.load(f)
    assert len(data) > 0, "Did not parse regex from output: {}".format(filter_event_regex)
    logger.info("events received: ({})".format(json.dumps(data, indent=4)))
    if heartbeat:  # no yang validation for heartbeat
        return
    dest = "/tmp/" + json_file
    duthost.copy(src=op_file, dest=dest)
    validate_yang(duthost, dest, tag)
