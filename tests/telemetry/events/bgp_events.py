#! /usr/bin/env python3

import json
import logging
import os

logger = logging.getLogger(__name__)


def test_event(duthost, localhost, run_cmd, data_dir, validate_yang):
    op_file = os.path.join(data_dir, "bgp_state.json")

    shutdownBGPNeighbors(duthost)
    listenForBGPStateEvents(localhost, run_cmd, op_file)

    data = {}
    with open(op_file, "r") as f:
        data = json.load(f)
    logger.info("events received: ({})".format(json.dumps(data, indent=4)))
    assert len(data) > 0, "Failed to check heartbeat"
    duthost.copy(src=op_file, dest="/tmp/bgp_state.json")
    validate_yang(duthost, "/tmp/bgp_state.json", "sonic-events-bgp")


def listenForBGPStateEvents(localhost, run_cmd, op_file):
    logger.info("Starting to listen for bgp event")
    run_cmd(localhost, ["heartbeat=5"], op_file=op_file,
            filter_event="sonic-events-bgp:bgp-state",
            event_cnt=1, timeout=20)


def shutdownBGPNeighbors(duthost):
    assert duthost.is_service_running("bgpcfgd", "bgp") is True and duthost.is_bgp_state_idle() is False
    logger.info("Start all bgp sessions")
    ret = duthost.shell("config bgp startup all")
    assert ret["rc"] == 0, "Failing to startup"

    ret = duthost.shell("config bgp shutdown all")
    assert ret["rc"] == 0, "Failing to shutdown"

    ret = duthost.shell("config bgp startup all")
    assert ret["rc"] == 0, "Failing to startup"
