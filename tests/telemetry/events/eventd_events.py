#! /usr/bin/env python3

import logging
import os

from run_events_test import run_test

logger = logging.getLogger(__name__)
tag = "sonic-events-eventd"


def test_event(duthost, gnxi_path, ptfhost, data_dir, validate_yang):
    logger.info("Beginning to test eventd heartbeat")
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, None,
            "heartbeat.json", "sonic-events-eventd:heartbeat", tag)
