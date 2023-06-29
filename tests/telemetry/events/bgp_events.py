#! /usr/bin/env python3

import logging
import os

from run_event_tests import run_test

logger = logging.getLogger(__name__)
tag = "sonic-events-bgp"


def test_event(duthost, ptfhost, data_dir, validate_yang):
    test_bgp_state_event(duthost, ptfhost, data_dir, validate_yang)


def test_bgp_state_event(duthost, ptfhost, data_dir, validate_yang):
    logger.info("Beginning to test bgp-state event")
    run_test(duthost, ptfhost, data_dir, validate_yang, shutdown_bgp_neighbors,
            "bgp_state.json", "sonic-events-bgp:bgp-state", tag)


def shutdown_bgp_neighbors(duthost):
    assert duthost.is_service_running("bgpcfgd", "bgp") is True and duthost.is_bgp_state_idle() is False
    logger.info("Start all bgp sessions")
    ret = duthost.shell("config bgp startup all")
    assert ret["rc"] == 0, "Failing to startup"

    ret = duthost.shell("config bgp shutdown all")
    assert ret["rc"] == 0, "Failing to shutdown"

    ret = duthost.shell("config bgp startup all")
    assert ret["rc"] == 0, "Failing to startup"
