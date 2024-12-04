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


def test_announce_withdraw_route(duthosts, localhost, tbinfo, get_function_completeness_level,
                                 withdraw_and_announce_existing_routes, loganalyzer,
                                 enum_rand_one_per_hwsku_frontend_hostname, enum_rand_one_frontend_asic_index,
                                 rotate_syslog):
    ptf_ip = tbinfo["ptf_ip"]
    topo_name = tbinfo["topo"]["name"]
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    namespace = asichost.namespace

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
    for dut in duthosts.frontend_nodes:
        if dut.loganalyzer:
            loganalyzer[dut.hostname].ignore_regex.extend(ignoreRegex)

    normalized_level = get_function_completeness_level
    if normalized_level is None:
        normalized_level = "debug"

    ipv4_route_used_before, ipv6_route_used_before = withdraw_and_announce_existing_routes

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    frr_demons_to_check = ['bgpd', 'zebra']
    start_time_frr_daemon_memory = get_frr_daemon_memory_usage(duthost, frr_demons_to_check)
    logging.info(f"memory usage at start: {start_time_frr_daemon_memory}")

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

    end_time_frr_daemon_memory = get_frr_daemon_memory_usage(duthost, frr_demons_to_check)
    logging.info(f"memory usage at end: {end_time_frr_daemon_memory}")
    check_memory_usage_is_expected(duthost, frr_demons_to_check, start_time_frr_daemon_memory,
                                   end_time_frr_daemon_memory)


def check_memory_usage_is_expected(duthost, frr_demons_to_check, start_time_frr_daemon_memory,
                                   end_time_frr_daemon_memory):

    unsupported_branches = ['202012', '202205', '202211', '202305', '202311', "20405"]
    if duthost.os_version in unsupported_branches or duthost.sonic_release in unsupported_branches:
        logger.info("Only check the memory usage after the 202405")
        return ""
    incr_frr_daemon_memory_threshold_dict = {
        "bgpd": 100,
        "zebra": 200
    }  # unit is MiB
    for daemon in frr_demons_to_check:
        logging.info(f"{daemon} memory usage at end: \n%s", end_time_frr_daemon_memory[daemon])

        # Calculate diff in FRR daemon memory
        incr_frr_daemon_memory = \
            float(end_time_frr_daemon_memory[daemon]) - float(start_time_frr_daemon_memory[daemon])
        logging.info(f"{daemon} absolute difference: %d", incr_frr_daemon_memory)
        pytest_assert(incr_frr_daemon_memory < incr_frr_daemon_memory_threshold_dict[daemon],
                      f"The increase memory should not exceed than {incr_frr_daemon_memory_threshold_dict[daemon]} MiB")


def get_frr_daemon_memory_usage(duthost, daemon_list):
    frr_daemon_memory_dict = {}
    for daemon in daemon_list:
        frr_daemon_memory_output = duthost.shell(f'vtysh -c "show memory {daemon}"')["stdout"]
        logging.info(f"{daemon} memory status: \n%s", frr_daemon_memory_output)
        output = duthost.shell(f'vtysh -c "show memory {daemon}" | grep "Free ordinary blocks"')["stdout"]
        frr_daemon_memory = output.split()[-2]
        unit = output.split()[-1]
        if unit == "KiB":
            frr_daemon_memory = frr_daemon_memory / 1000
        elif unit == "GiB":
            frr_daemon_memory = frr_daemon_memory * 1000
        frr_daemon_memory_dict[daemon] = frr_daemon_memory
    return frr_daemon_memory_dict
