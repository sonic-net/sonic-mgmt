#! /usr/bin/env python3

import logging
import time

from run_events_test import run_test

logger = logging.getLogger(__name__)
tag = "sonic-events-swss"

IF_STATE_TEST_PORT = "Ethernet0"
PFC_STORM_TEST_PORT = "Ethernet4"
PFC_STORM_TEST_QUEUE = "4"
PFC_STORM_DETECTION_TIME = 100
PFC_STORM_RESTORATION_TIME = 100
CRM_DEFAULT_POLLING_INTERVAL = 300
CRM_DEFAULT_ACL_GROUP_HIGH = 85
CRM_TEST_POLLING_INTERVAL = 1
CRM_TEST_ACL_GROUP_HIGH = 0
WAIT_TIME = 3


def test_event(duthost, gnxi_path, ptfhost, data_dir, validate_yang):
    logger.info("Beginning to test swss events")
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, shutdown_interface,
             "if_state.json", "sonic-events-swss:if-state", tag)
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, generate_pfc_storm,
             "pfc_storm.json", "sonic-events-swss:pfc-storm", tag)
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, trigger_crm_threshold_exceeded,
             "chk_crm_threshold.json", "sonic-events-swss:chk_crm_threshold", tag)


def shutdown_interface(duthost):
    logger.info("Shutting down an interface")
    ret = duthost.shell("config interface startup {}".format(IF_STATE_TEST_PORT))
    assert ret["rc"] == 0, "Failing to startup interface {}".format(IF_STATE_TEST_PORT)

    ret = duthost.shell("config interface shutdown {}".format(IF_STATE_TEST_PORT))
    assert ret["rc"] == 0, "Failing to shutdown interface {}".format(IF_STATE_TEST_PORT)

    ret = duthost.shell("config interface startup {}".format(IF_STATE_TEST_PORT))
    assert ret["rc"] == 0, "Failing to startup interface {}".format(IF_STATE_TEST_PORT)


def generate_pfc_storm(duthost):
    logger.info("Generating pfc storm")
    queue_oid = duthost.get_queue_oid(PFC_STORM_TEST_PORT, PFC_STORM_TEST_QUEUE)
    duthost.shell("sonic-db-cli COUNTERS_DB HSET \"COUNTERS:{}\" \"DEBUG_STORM\" \"enabled\"".
                  format(queue_oid))
    duthost.shell("pfcwd start --action drop {} {} --restoration-time {}".
                  format(PFC_STORM_TEST_PORT, PFC_STORM_DETECTION_TIME, PFC_STORM_RESTORATION_TIME))
    time.sleep(WAIT_TIME)  # give time for pfcwd to detect pfc storm
    duthost.shell("pfcwd stop")
    duthost.shell("sonic-db-cli COUNTERS_DB HDEL \"COUNTERS:{}\" \"DEBUG_STORM\"".
                  format(queue_oid))


def trigger_crm_threshold_exceeded(duthost):
    logger.info("Triggering crm threshold exceeded")
    duthost.shell("crm config polling interval {}".format(CRM_TEST_POLLING_INTERVAL))
    duthost.shell("crm config thresholds acl group high {}".format(CRM_TEST_ACL_GROUP_HIGH))
    time.sleep(WAIT_TIME)  # give time for crm threshold exceed to be detected
    duthost.shell("crm config polling interval {}".format(CRM_DEFAULT_POLLING_INTERVAL))
    duthost.shell("crm config thresholds acl group high {}".format(CRM_DEFAULT_ACL_GROUP_HIGH))
