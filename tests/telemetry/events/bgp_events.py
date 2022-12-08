#! /usr/bin/env python3

import json
import logging
import os
from threading import Thread

logger = logging.getLogger(__name__)


def test_event(duthost, localhost, run_cmd, data_dir, validate_yang):
    op_file = os.path.join(data_dir, "bgp_state.json")

    gnmiThread = Thread(target=listenForBGPState, args=(localhost, run_cmd, op_file,))
    shutdownThread = Thread(target=shutdownBGPNeighbors, args=(duthost,))

    gnmiThread.start()
    shutdownThread.start()

    gnmiThread.join()
    shutdownThread.join()

    data = {}
    with open(op_file, "r") as f:
        data = json.load(f)
    logger.info("events received: ({})".format(json.dumps(data, indent=4)))
    assert len(data) > 0, "Failed to receive bgp-state event"
    duthost.copy(src=op_file, dest="/tmp/bgp_state.json")
    validate_yang(duthost, "/tmp/bgp_state.json", "sonic-events-bgp")


def listenForBGPState(localhost, run_cmd, op_file):
    logger.info("Starting to listen for bgp-state events")
    run_cmd(localhost, ["heartbeat=5", "usecache=false"], op_file=op_file,
            filter_event="sonic-events-bgp:bgp-state",
            event_cnt=1, timeout=20)


def shutdownBGPNeighbors(duthost):
    logger.info("Starting to shutdown bgp")
    ret = duthost.shell("config bgp shutdown all")
    assert ret["rc"] == 0, "Failing to shutdown"

    ret = duthost.shell("config bgp startup all")
    assert ret["rc"] == 0, "Failing to startup"
