#! /usr/bin/env python3

import json
import logging
import os
import re

from tests.common.utilities import wait_until
from telemetry_utils import listen_for_events
logger = logging.getLogger(__name__)


def run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, trigger, json_file,
             filter_event_regex, tag, heartbeat=False, timeout=30, ptfadapter=None):
    op_file = os.path.join(data_dir, json_file)
    if trigger is not None:  # no trigger for heartbeat
        if ptfadapter is None:
            trigger(duthost)  # add events to cache
        else:
            trigger(duthost, ptfadapter)
    listen_for_events(duthost, gnxi_path, ptfhost, filter_event_regex, op_file,
                      timeout)  # listen from cache
    data = {}
    with open(op_file, "r") as f:
        data = json.load(f)
    assert len(data) > 0, "Did not parse regex from output: {}".format(filter_event_regex)
    logger.info("events received: ({})".format(json.dumps(data, indent=4)))
    if heartbeat:  # no yang validation for heartbeat
        return
    dest = "~/" + json_file
    duthost.copy(src=op_file, dest=dest)
    validate_yang(duthost, dest, tag)
    wait_until(5, 1, 0, is_gnmi_cli_finished, duthost)


def is_gnmi_cli_finished(duthost):
    last_logs = duthost.shell("tail -n 2 /var/log/syslog",
                              module_ignore_errors=True)["stdout"]
    matches = re.findall('Set heartbeat_ctrl pause=1', last_logs)
    return len(matches) > 0
