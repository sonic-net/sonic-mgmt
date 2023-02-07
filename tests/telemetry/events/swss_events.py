#! /usr/bin/env python3

import json
import logging
import os
import time

from run_events_test import run_test

logger = logging.getLogger(__name__)
tag = "sonic-events-swss"


def test_event(duthost, localhost, run_cmd, data_dir, validate_yang):
    test_if_state_event(duthost, localhost, run_cmd, data_dir, validate_yang)


def test_if_state_event(duthost, localhost, run_cmd, data_dir, validate_yang):
    run_test(duthost, localhost, run_cmd, data_dir, validate_yang, shutdownInterface, "if_state.json", tag, "if-state", 20)


def shutdownInterface(duthost):
    logger.info("Shutting down interface")
    cfg_facts = duthost.get_running_config_facts()
    vlan = cfg_facts['PORT'].keys()[0]
    ret = duthost.shell("config interface startup {}".format(vlan))
    assert ret["rc"] == 0, "Failing to startup interface"

    ret = duthost.shell("config interface shutdown {}".format(vlan))
    assert ret["rc"] == 0, "Failing to shutdown interface"

    ret = duthost.shell("config interface startup {}".format(vlan))
    assert ret["rc"] == 0, "Failing to startup interface"
