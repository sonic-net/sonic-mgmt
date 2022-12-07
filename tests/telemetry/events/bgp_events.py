#! /usr/bin/env python3

import json
import logging
import os

logger = logging.getLogger(__name__)


def test_event(duthost, localhost, run_cmd, data_dir, validate_yang):
    ret = duthost.shell("config bgp shutdown all")
    assert ret["rc"] == 0, "Failing to shutdown"

    ret = duthost.shell("config bgp startup all")
    assert ret["rc"] == 0, "Failing to startup"

    op_file = os.path.join(data_dir, "bgp_state.json")
    run_cmd(localhost, ["heartbeat=5"], op_file=op_file,
            filter_event="sonic-events-bgp:bgp-state",
            event_cnt=1, timeout=10)

    data = ""
    with open(op_file, "r") as f:
        data = f.read()
    logger.info("op_file contains: ({})".format(data))
    event_json = json.loads(data)
    logger.info("events received: ({})".format(json.dumps(d, indent=4)))
    assert len(d) > 0, "Failed to receive bgp-state event"
    duthost.copy(src=op_file, dest="/tmp/bgp_state.json")
    validate_yang(duthost, "/tmp/bgp_state.json", "sonic-events-bgp")
