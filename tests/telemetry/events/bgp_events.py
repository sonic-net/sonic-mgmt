#! /usr/bin/env python3

import json
import logging
import os

from run_events_test import run_test

logger = logging.getLogger(__name__)
tag = "sonic-events-bgp"


def test_event(duthost, localhost, run_cmd, data_dir, validate_yang):
    test_bgp_state_event(duthost, localhost, run_cmd, data_dir, validate_yang)


def test_bgp_state_event(duthost, localhost, run_cmd, data_dir, validate_yang):
    run_test(duthost, localhost, run_cmd, data_dir, validate_yang, shutdownBGPNeighbors, "bgp_state".json, tag, "bgp-state", 20)


def shutdownBGPNeighbors(duthost):
    assert duthost.is_service_running("bgpcfgd", "bgp") is True and duthost.is_bgp_state_idle() is False
    logger.info("Start all bgp sessions")
    ret = duthost.shell("config bgp startup all")
    assert ret["rc"] == 0, "Failing to startup"

    ret = duthost.shell("config bgp shutdown all")
    assert ret["rc"] == 0, "Failing to shutdown"

    ret = duthost.shell("config bgp startup all")
    assert ret["rc"] == 0, "Failing to startup"
