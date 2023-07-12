#! /usr/bin/env python3

import logging

from run_events_test import run_test

logger = logging.getLogger(__name__)
tag = "sonic-events-swss"


def test_event(duthost, gnxi_path, ptfhost, data_dir, validate_yang):
    logger.info("Beginning to test swss if-state")
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, shutdown_interface,
             "if_state.json", "sonic-events-swss:if-state", tag)


def shutdown_interface(duthost):
    logger.info("Shutting down an interface")
    ret = duthost.shell("config interface startup Ethernet0")
    assert ret["rc"] == 0, "Failing to startup interface Ethernet0"

    ret = duthost.shell("config interface shutdown Ethernet0")
    assert ret["rc"] == 0, "Failing to shutdown interface Ethernet0"

    ret = duthost.shell("config interface startup Ethernet0")
    assert ret["rc"] == 0, "Failing to startup interface Ethernet0"
