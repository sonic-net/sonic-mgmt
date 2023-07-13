#! /usr/bin/env python3

import logging
import time

from run_events_test import run_test

logger = logging.getLogger(__name__)
tag = "sonic-events-swss"


def test_event(duthost, gnxi_path, ptfhost, data_dir, validate_yang):
    logger.info("Beginning to test swss events")
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, shutdown_interface,
             "if_state.json", "sonic-events-swss:if-state", tag)
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, generate_pfc_storm,
             "pfc_storm.json", "sonic-events-swss:pfc-storm", tag)


def shutdown_interface(duthost):
    logger.info("Shutting down an interface")
    ret = duthost.shell("config interface startup Ethernet0")
    assert ret["rc"] == 0, "Failing to startup interface Ethernet0"

    ret = duthost.shell("config interface shutdown Ethernet0")
    assert ret["rc"] == 0, "Failing to shutdown interface Ethernet0"

    ret = duthost.shell("config interface startup Ethernet0")
    assert ret["rc"] == 0, "Failing to startup interface Ethernet0"


def generate_pfc_storm(duthost):
    logger.info("Generating pfc storm on Ethernet4:4")
    queue_oid = duthost.get_queue_oid("Ethernet4", 4)
    duthost.shell("redis-cli -n 2 hset \"COUNTERS:{}\" \"DEBUG_STORM\" \"enabled\"".format(queue_oid))
    duthost.shell("pfcwd start --action alert Ethernet4 100 --restoration-time 100")
    time.sleep(3)  # give time for pfcwd to detect pfc storm
    duthost.shell("pfcwd stop")
    duthost.shell("redis-cli -n 2 hdel \"COUNTERS:{}\" \"DEBUG_STORM\"".format(queue_oid))
