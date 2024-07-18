#!/usr/bin/env python

import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from utils import get_crm_resource_status, check_queue_status, sleep_to_wait, LOOP_TIMES_LEVEL_MAP

ALLOW_ROUTES_CHANGE_NUMS = 5
CRM_POLLING_INTERVAL = 1
MAX_WAIT_TIME = 120

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1', 'm0', 'mx', 't2')
]


def announce_withdraw_routes(duthost, namespace, localhost, ptf_ip, topo_name):
    logger.info("announce ipv4 and ipv6 routes")
    localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="announce", path="../ansible/",
                              log_path="logs")

    wait_until(MAX_WAIT_TIME, CRM_POLLING_INTERVAL, 0, lambda: check_queue_status(duthost, "outq") is True)

    logger.info("ipv4 route used {}".format(get_crm_resource_status(duthost, "ipv4_route", "used", namespace)))
    logger.info("ipv6 route used {}".format(get_crm_resource_status(duthost, "ipv6_route", "used", namespace)))
    sleep_to_wait(CRM_POLLING_INTERVAL * 5)

    logger.info("withdraw ipv4 and ipv6 routes")
    localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="withdraw", path="../ansible/",
                              log_path="logs")

    wait_until(MAX_WAIT_TIME, CRM_POLLING_INTERVAL, 0, lambda: check_queue_status(duthost, "inq") is True)
    sleep_to_wait(CRM_POLLING_INTERVAL * 5)
    logger.info("ipv4 route used {}".format(get_crm_resource_status(duthost, "ipv4_route", "used", namespace)))
    logger.info("ipv6 route used {}".format(get_crm_resource_status(duthost, "ipv6_route", "used", namespace)))


def test_announce_withdraw_route(duthosts, localhost, tbinfo, get_function_conpleteness_level,
                                 withdraw_and_announce_existing_routes, loganalyzer,
                                 enum_rand_one_per_hwsku_frontend_hostname, enum_rand_one_frontend_asic_index):
    ptf_ip = tbinfo["ptf_ip"]
    topo_name = tbinfo["topo"]["name"]
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    namespace = asichost.namespace

    if loganalyzer:
        ignoreRegex = [
            ".*ERR route_check.py:.*",
            ".*ERR.* 'routeCheck' status failed.*",
            ".*Process \'orchagent\' is stuck in namespace \'host\'.*",
            ".*ERR rsyslogd: .*"
        ]

        hwsku = duthost.facts['hwsku']
        if hwsku in ['Arista-7050-QX-32S', 'Arista-7050QX32S-Q32', 'Arista-7050-QX32', 'Arista-7050QX-32S-S4Q31']:
            ignoreRegex.append(".*ERR memory_threshold_check:.*")
            ignoreRegex.append(".*ERR monit.*memory_check.*")
            ignoreRegex.append(".*ERR monit.*mem usage of.*matches resource limit.*")

        # Ignore errors in ignoreRegex for *all* DUTs
        for dut in duthosts:
            loganalyzer[dut.hostname].ignore_regex.extend(ignoreRegex)

    normalized_level = get_function_conpleteness_level
    if normalized_level is None:
        normalized_level = "basic"

    ipv4_route_used_before, ipv6_route_used_before = withdraw_and_announce_existing_routes

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    while loop_times > 0:
        announce_withdraw_routes(duthost, namespace, localhost, ptf_ip, topo_name)
        loop_times -= 1

    sleep_to_wait(CRM_POLLING_INTERVAL * 120)

    ipv4_route_used_after = get_crm_resource_status(duthost, "ipv4_route", "used", namespace)
    ipv6_route_used_after = get_crm_resource_status(duthost, "ipv6_route", "used", namespace)

    pytest_assert(abs(ipv4_route_used_after - ipv4_route_used_before) < ALLOW_ROUTES_CHANGE_NUMS,
                  "ipv4 route used after is not equal to it used before")
    pytest_assert(abs(ipv6_route_used_after - ipv6_route_used_before) < ALLOW_ROUTES_CHANGE_NUMS,
                  "ipv6 route used after is not equal to it used before")
