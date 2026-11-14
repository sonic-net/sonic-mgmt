#!/usr/bin/env python

import logging
import time

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from utils import (
    get_crm_route_counts,
    check_queue_status,
    get_topo_scale_factor,
    LOOP_TIMES_LEVEL_MAP,
)

ALLOW_ROUTES_CHANGE_NUMS = 5
CRM_POLLING_INTERVAL = 1
MAX_WAIT_TIME = 120

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1', 'm0', 'mx', 'm1', 'uma', 'lma', 't2', 'lrh', 'urh', 'lt2', 'ft2')
]


def announce_withdraw_routes(duthost, namespace, localhost, ptf_ip, topo_name, route_counts,
                             max_wait=MAX_WAIT_TIME):
    logger.info("announce ipv4 and ipv6 routes")
    localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="announce", path="../ansible/")

    wait_for_route_counts(duthost, namespace, route_counts["announced"], "outq", "announced",
                          max_wait)

    logger.info("route used after announce: {}".format(get_crm_route_counts(duthost, namespace)))

    logger.info("withdraw ipv4 and ipv6 routes")
    localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="withdraw", path="../ansible/")

    wait_for_route_counts(duthost, namespace, route_counts["withdrawn"], "inq", "withdrawn",
                          max_wait)
    logger.info("route used after withdraw: {}".format(get_crm_route_counts(duthost, namespace)))


def test_announce_withdraw_route(duthosts, localhost, tbinfo, get_function_completeness_level,
                                 withdraw_and_announce_existing_routes, loganalyzer,
                                 enum_rand_one_per_hwsku_frontend_hostname, enum_rand_one_frontend_asic_index,
                                 rotate_syslog):
    ptf_ip = tbinfo["ptf_ip"]
    topo_name = tbinfo["topo"]["name"]
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    asic_type = duthost.facts["asic_type"]
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

    ipv4_route_used_before, ipv6_route_used_before = withdraw_and_announce_existing_routes["withdrawn"]

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    # Scale BGP-queue-drain timeout and post-loop convergence sleep by topology
    # peer count. The defaults are tuned for ~5-peer topos; for high-fanout
    # topos like t2_single_node_max_64p, 120s is not enough for the SAI/HW
    # pipeline to settle after the inq queue drains, leading to spurious diffs.
    scale = get_topo_scale_factor(tbinfo)
    max_wait = MAX_WAIT_TIME * scale
    post_loop_sleep = CRM_POLLING_INTERVAL * 120 * scale
    logging.info(f"topo scale={scale} (peers={len(tbinfo['topo']['properties']['topology'].get('VMs', {}))}), "
                 f"max_wait={max_wait}s, post_loop_sleep={post_loop_sleep}s")

    frr_demons_to_check = ['bgpd', 'zebra']
    start_time_frr_daemon_memory = get_frr_daemon_memory_usage(duthost, frr_demons_to_check, namespace)
    logging.info(f"memory usage at start: {start_time_frr_daemon_memory}")

    while loop_times > 0:
        announce_withdraw_routes(
            duthost, namespace, localhost, ptf_ip, topo_name, withdraw_and_announce_existing_routes,
            max_wait=max_wait)
        loop_times -= 1

    time.sleep(post_loop_sleep)

    # Do not check route used for vs tests because vs testbed do not have real asic
    if asic_type != "vs":
        counts = get_crm_route_counts(duthost, namespace)
        pytest_assert(counts is not None, "CRM did not report route counts at the end of the test")
        ipv4_route_used_after, ipv6_route_used_after = counts
        pytest_assert(abs(ipv4_route_used_after - ipv4_route_used_before) < ALLOW_ROUTES_CHANGE_NUMS,
                      f"ipv4 route used after is not equal to it used before "
                      f"(before={ipv4_route_used_before}, after={ipv4_route_used_after})")
        pytest_assert(abs(ipv6_route_used_after - ipv6_route_used_before) < ALLOW_ROUTES_CHANGE_NUMS,
                      f"ipv6 route used after is not equal to it used before "
                      f"(before={ipv6_route_used_before}, after={ipv6_route_used_after})")
    end_time_frr_daemon_memory = get_frr_daemon_memory_usage(duthost, frr_demons_to_check, namespace)
    logging.info(f"memory usage at end: {end_time_frr_daemon_memory}")
    check_memory_usage_is_expected(duthost, frr_demons_to_check, start_time_frr_daemon_memory,
                                   end_time_frr_daemon_memory, scale=scale)


def check_memory_usage_is_expected(duthost, frr_demons_to_check, start_time_frr_daemon_memory,
                                   end_time_frr_daemon_memory, scale=1):

    unsupported_branches = ['202012', '202205', '202211', '202305', '202311', "20405"]
    if duthost.os_version in unsupported_branches or duthost.sonic_release in unsupported_branches:
        logger.info("Only check the memory usage after the 202405")
        return ""
    # Thresholds (MiB) for the increase in FRR daemon "Free ordinary blocks".
    # This metric is allocator-held working set, which scales with route/peer
    # count, so we multiply by the same topology scale factor used for the
    # convergence sleeps. Without this, maxtopo (~60 peers) trips the mintopo
    # baseline by a small margin even on a clean run.
    incr_frr_daemon_memory_threshold_dict = {
        "bgpd": 100 * scale,
        "zebra": 200 * scale,
    }  # unit is MiB
    for daemon in frr_demons_to_check:
        logging.info(f"{daemon} memory usage at end: \n%s", end_time_frr_daemon_memory[daemon])

        # Calculate diff in FRR daemon memory
        incr_frr_daemon_memory = \
            float(end_time_frr_daemon_memory[daemon]) - float(start_time_frr_daemon_memory[daemon])
        logging.info(f"{daemon} absolute difference: %d", incr_frr_daemon_memory)
        pytest_assert(incr_frr_daemon_memory < incr_frr_daemon_memory_threshold_dict[daemon],
                      f"The increase memory should not exceed than {incr_frr_daemon_memory_threshold_dict[daemon]} MiB")


def get_frr_daemon_memory_usage(duthost, daemon_list, namespace):
    frr_daemon_memory_dict = {}
    for daemon in daemon_list:
        frr_daemon_memory_output = duthost.shell(duthost.get_vtysh_cmd_for_namespace(
           f'vtysh -c "show memory {daemon}"', namespace))["stdout"]
        logging.info(f"{daemon} memory status: \n%s", frr_daemon_memory_output)
        output = duthost.shell(duthost.get_vtysh_cmd_for_namespace(
           f'vtysh -c "show memory {daemon}" | grep "Free ordinary blocks"', namespace))["stdout"]
        frr_daemon_memory = int(output.split()[-2])
        unit = output.split()[-1]
        if unit == "KiB":
            frr_daemon_memory = int(frr_daemon_memory) / 1000
        elif unit == "GiB":
            frr_daemon_memory = int(frr_daemon_memory) * 1000
        frr_daemon_memory_dict[daemon] = frr_daemon_memory
    return frr_daemon_memory_dict


def wait_for_route_counts(duthost, namespace, expected, queue, action, max_wait=MAX_WAIT_TIME):
    full_wait_time = max_wait
    current = None
    previous_match = False

    def route_counts_match():
        nonlocal current, previous_match
        prior_match = previous_match
        previous_match = False
        current = get_crm_route_counts(duthost, namespace)
        matched = current is not None and check_queue_status(duthost, queue) and all(
            abs(value - target) < ALLOW_ROUTES_CHANGE_NUMS
            for value, target in zip(current, expected)
        )
        converged = matched and prior_match
        previous_match = matched
        return converged

    pytest_assert(
        wait_until(full_wait_time, CRM_POLLING_INTERVAL, CRM_POLLING_INTERVAL, route_counts_match),
        "Routes failed to reach the {} CRM counts in {} seconds: expected={}, current={}".format(
            action, full_wait_time, expected, current),
    )
