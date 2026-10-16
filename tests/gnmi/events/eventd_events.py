#! /usr/bin/env python3

import logging

from run_events_test import run_test

logger = logging.getLogger(__name__)
tag = "sonic-events-eventd"


def test_event(duthost, tbinfo, pygnmi_client, ptfhost, ptfadapter, data_dir, validate_yang):
    logger.info("Beginning to test eventd heartbeat")
    run_test(duthost, tbinfo, pygnmi_client, ptfhost, data_dir, validate_yang, None,
             "heartbeat.json", "sonic-events-eventd:heartbeat", tag, True)
