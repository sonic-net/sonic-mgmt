#! /usr/bin/env python3

import logging
import time
import random
import re

from run_events_test import run_test
from tests.common.utilities import wait_until

random.seed(10)
logger = logging.getLogger(__name__)
tag = "sonic-events-swss"

PFC_STORM_TEST_QUEUE = "4"
PFC_STORM_DETECTION_TIME = 100
PFC_STORM_RESTORATION_TIME = 100
CRM_DEFAULT_POLLING_INTERVAL = 300
CRM_DEFAULT_ACL_GROUP_HIGH = 85
CRM_TEST_IPV4_ROUTE_FREE_LOW = 52530
CRM_TEST_IPV4_ROUTE_FREE_HIGH = 52531
CRM_TEST_IPV4_ROUTE_USED_LOW = 6475
CRM_TEST_IPV4_ROUTE_USED_HIGH = 6476
CRM_DEFAULT_IPV4_ROUTE_LOW = 70
CRM_DEFAULT_IPV4_ROUTE_HIGH = 85
CRM_TEST_POLLING_INTERVAL = 1
CRM_TEST_ACL_GROUP_HIGH = 0
WAIT_TIME = 3


def test_event(duthost, gnxi_path, ptfhost, ptfadapter, data_dir, validate_yang):
    if duthost.topo_type.lower() in ["m0", "mx"]:
        logger.info("Skipping swss events test on MGFX topologies")
        return
    logger.info("Beginning to test swss events")
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, shutdown_interface,
             "if_state.json", "sonic-events-swss:if-state", tag)
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, generate_pfc_storm,
             "pfc_storm.json", "sonic-events-swss:pfc-storm", tag)
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, trigger_crm_threshold_exceeded,
             "chk_crm_threshold.json", "sonic-events-swss:chk_crm_threshold", tag)


def shutdown_interface(duthost):
    logger.info("Shutting down interface")
    interfaces = duthost.get_interfaces_status()
    pattern = re.compile(r'^Ethernet[0-9]{1,2}$')
    interface_list = []
    for interface, status in interfaces.items():
        if pattern.match(interface) and status["oper"] == "up" and status["admin"] == "up":
            interface_list.append(interface)
    if_state_test_port = random.choice(interface_list)
    assert if_state_test_port is not None, "Unable to find valid interface for test"

    ret = duthost.shell("config interface shutdown {}".format(if_state_test_port))
    assert ret["rc"] == 0, "Failing to shutdown interface {}".format(if_state_test_port)

    # Wait until port goes down
    wait_until(15, 1, 0, verify_port_admin_oper_status, duthost, if_state_test_port, "down")

    ret = duthost.shell("config interface startup {}".format(if_state_test_port))
    assert ret["rc"] == 0, "Failing to startup interface {}".format(if_state_test_port)

    # Wait until port comes back up
    wait_until(15, 1, 0, verify_port_admin_oper_status, duthost, if_state_test_port, "up")


def generate_pfc_storm(duthost):
    logger.info("Generating pfc storm")
    interfaces = duthost.get_interfaces_status()
    pattern = re.compile(r'^Ethernet[0-9]{1,2}$')
    interface_list = []
    for interface, status in interfaces.items():
        if pattern.match(interface) and status["oper"] == "up" and status["admin"] == "up":
            interface_list.append(interface)
    PFC_STORM_TEST_PORT = random.choice(interface_list)
    assert PFC_STORM_TEST_PORT is not None, "Unable to find valid interface for test"

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

    duthost.shell("crm config thresholds ipv4 route type free")
    duthost.shell("crm config thresholds ipv4 route low {}".format(CRM_TEST_IPV4_ROUTE_FREE_LOW))
    duthost.shell("crm config thresholds ipv4 route high {}".format(CRM_TEST_IPV4_ROUTE_FREE_HIGH))
    duthost.shell("crm config thresholds ipv4 route type used")
    duthost.shell("crm config thresholds ipv4 route low {}".format(CRM_TEST_IPV4_ROUTE_USED_LOW))
    duthost.shell("crm config thresholds ipv4 route high {}".format(CRM_TEST_IPV4_ROUTE_USED_HIGH))

    time.sleep(WAIT_TIME)  # give time for crm threshold exceed to be detected

    duthost.shell("crm config polling interval {}".format(CRM_DEFAULT_POLLING_INTERVAL))

    duthost.shell("crm config thresholds acl group high {}".format(CRM_DEFAULT_ACL_GROUP_HIGH))

    duthost.shell("crm config thresholds ipv4 route low {}".format(CRM_DEFAULT_IPV4_ROUTE_LOW))
    duthost.shell("crm config thresholds ipv4 route high {}".format(CRM_DEFAULT_IPV4_ROUTE_HIGH))
    duthost.shell("crm config thresholds ipv4 route type free")
    duthost.shell("crm config thresholds ipv4 route low {}".format(CRM_DEFAULT_IPV4_ROUTE_LOW))
    duthost.shell("crm config thresholds ipv4 route high {}".format(CRM_DEFAULT_IPV4_ROUTE_HIGH))


def verify_port_admin_oper_status(duthost, interface, state):
    interface_facts = duthost.get_interfaces_status()[interface]
    admin_status = interface_facts["admin"]
    oper_status = interface_facts["oper"]
    return admin_status == state and oper_status == state
