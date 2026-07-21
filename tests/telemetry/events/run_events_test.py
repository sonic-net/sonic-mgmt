#! /usr/bin/env python3

import json
import logging
import os
import re
import threading
import time

from tests.common.utilities import wait_until
from telemetry_utils import listen_for_events
logger = logging.getLogger(__name__)


def run_test(duthost, tbinfo, gnxi_path, ptfhost, data_dir, validate_yang, trigger, json_file,
             filter_event_regex, tag, heartbeat=False, timeout=30, ptfadapter=None,
             start_listen_first=False, pre_trigger_wait=3):
    op_file = os.path.join(data_dir, json_file)
    if start_listen_first and trigger is not None:
        # Start the gNMI subscriber first so it is already listening when the trigger fires.
        # Monit emits mem-threshold events only on state transitions (healthy→alarm), so the
        # event is published exactly once ~1s after the trigger.  If gNMI subscribes after
        # that point it will miss the event entirely.
        # timeout=30 keeps gnmi-cli alive long enough for the event to arrive.
        # update_count=1 (default) ensures gnmi-cli exits cleanly after the single event.
        # Heartbeat responses do not count toward update_count, so update_count=1 is correct.
        errors = []

        def _listen():
            try:
                listen_for_events(duthost, gnxi_path, ptfhost, filter_event_regex, op_file,
                                  timeout)
            except Exception as e:
                errors.append(e)

        thread = threading.Thread(target=_listen)
        thread.start()
        time.sleep(pre_trigger_wait)  # let gNMI subscription establish before triggering
        try:
            if ptfadapter is None:
                trigger(duthost, tbinfo)
            else:
                trigger(duthost, tbinfo, ptfadapter)
        finally:
            thread.join()  # always join, even if trigger raises, to avoid thread leak
        if errors:
            raise errors[0]
    else:
        if trigger is not None:  # no trigger for heartbeat
            if ptfadapter is None:
                trigger(duthost, tbinfo)  # add events to cache
            else:
                trigger(duthost, tbinfo, ptfadapter)
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
