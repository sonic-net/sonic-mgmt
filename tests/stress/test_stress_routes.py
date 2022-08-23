#!/usr/bin/env python

import math
import os
import yaml
import re
import requests
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from utils import get_crm_resources, check_queue_status, sleep_to_wait, LOOP_TIMES_LEVEL_MAP

ALLOW_ROUTES_CHANGE_NUMS = 5
CRM_POLLING_INTERVAL = 1
MAX_WAIT_TIME = 120

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]

def announce_withdraw_routes(duthost, localhost, ptf_ip, topo_name):
    logger.info("announce ipv4 and ipv6 routes")
    localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="announce", path="../ansible/")

    wait_until(MAX_WAIT_TIME, CRM_POLLING_INTERVAL, 0, lambda: check_queue_status(duthost, "outq") == True)

    logger.info("ipv4 route used {}".format(get_crm_resources(duthost, "ipv4_route", "used")))
    logger.info("ipv6 route used {}".format(get_crm_resources(duthost, "ipv6_route", "used")))
    sleep_to_wait(CRM_POLLING_INTERVAL * 5)

    logger.info("withdraw ipv4 and ipv6 routes")
    localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="withdraw", path="../ansible/")

    wait_until(MAX_WAIT_TIME, CRM_POLLING_INTERVAL, 0, lambda: check_queue_status(duthost, "inq") == True)
    sleep_to_wait(CRM_POLLING_INTERVAL * 5)
    logger.info("ipv4 route used {}".format(get_crm_resources(duthost, "ipv4_route", "used")))
    logger.info("ipv6 route used {}".format(get_crm_resources(duthost, "ipv6_route", "used")))


def test_announce_withdraw_route(duthost, localhost, tbinfo, get_function_conpleteness_level,
                                 withdraw_and_announce_existing_routes):
    ptf_ip = tbinfo["ptf_ip"]
    topo_name = tbinfo["topo"]["name"]

    normalized_level = get_function_conpleteness_level
    if normalized_level is None:
        normalized_level = "basic"

    ipv4_route_used_before, ipv6_route_used_before = withdraw_and_announce_existing_routes

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    while loop_times > 0:
        announce_withdraw_routes(duthost, localhost, ptf_ip, topo_name)
        loop_times -= 1

    sleep_to_wait(CRM_POLLING_INTERVAL * 100)

    ipv4_route_used_after = get_crm_resources(duthost, "ipv4_route", "used")
    ipv6_route_used_after = get_crm_resources(duthost, "ipv6_route", "used")

    pytest_assert(abs(ipv4_route_used_after - ipv4_route_used_before) < ALLOW_ROUTES_CHANGE_NUMS,
              "ipv4 route used after is not equal to it used before")
    pytest_assert(abs(ipv6_route_used_after - ipv6_route_used_before) < ALLOW_ROUTES_CHANGE_NUMS,
              "ipv6 route used after is not equal to it used before")
