#!/usr/bin/env python

import json
import logging
import sys
from collections import deque
from collections.abc import Mapping

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from utils import get_crm_resource_status, sleep_to_wait, LOOP_TIMES_LEVEL_MAP

ALLOW_ROUTES_CHANGE_NUMS = 5
CRM_POLLING_INTERVAL = 1
MAX_WAIT_TIME = 120

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1', 'm0', 'mx', 'm1', 'uma', 'lma', 't2', 'lrh', 'urh', 'lt2', 'ft2')
]


def announce_withdraw_routes(duthost, namespace, localhost, ptf_ip, topo_name, route_states):
    """Use the fixture's immutable targets for every stress cycle."""
    before = get_route_state(duthost, namespace)
    before = wait_for_route_convergence(
        duthost, namespace, "snapshot", before, (False, False), expected=route_states["withdrawn"])
    announced = change_routes_and_wait(
        duthost, namespace, localhost, ptf_ip, topo_name, "announce", before=before, expected=route_states["announced"])
    change_routes_and_wait(duthost, namespace, localhost, ptf_ip, topo_name, "withdraw",
                           before=announced, expected=route_states["withdrawn"])


def test_announce_withdraw_route(duthosts, localhost, tbinfo, get_function_completeness_level,
                                 withdraw_and_restore_routes, loganalyzer,
                                 enum_rand_one_per_hwsku_frontend_hostname, enum_rand_one_frontend_asic_index,
                                 rotate_syslog):
    """Stress route churn without overlapping unconverged operations."""
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

    ipv4_route_used_before, ipv6_route_used_before = withdraw_and_restore_routes["withdrawn"]["crm"]

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    frr_demons_to_check = ['bgpd', 'zebra']
    start_time_frr_daemon_memory = get_frr_daemon_memory_usage(duthost, frr_demons_to_check, namespace)
    logging.info(f"memory usage at start: {start_time_frr_daemon_memory}")

    while loop_times > 0:
        announce_withdraw_routes(duthost, namespace, localhost, ptf_ip, topo_name, withdraw_and_restore_routes)
        loop_times -= 1

    sleep_to_wait(CRM_POLLING_INTERVAL * 120)

    ipv4_route_used_after = get_crm_resource_status(duthost, "ipv4_route", "used", namespace)
    ipv6_route_used_after = get_crm_resource_status(duthost, "ipv6_route", "used", namespace)

    # Do not check route used for vs tests because vs testbed do not have real asic
    if asic_type != "vs":
        pytest_assert(abs(ipv4_route_used_after - ipv4_route_used_before) < ALLOW_ROUTES_CHANGE_NUMS,
                      "ipv4 route used before={}, after={}".format(ipv4_route_used_before, ipv4_route_used_after))
        pytest_assert(abs(ipv6_route_used_after - ipv6_route_used_before) < ALLOW_ROUTES_CHANGE_NUMS,
                      "ipv6 route used before={}, after={}".format(ipv6_route_used_before, ipv6_route_used_after))
    end_time_frr_daemon_memory = get_frr_daemon_memory_usage(duthost, frr_demons_to_check, namespace)
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


def get_route_state(duthost, namespace):
    """Read both BGP families, peer queues and CRM in the selected ASIC."""
    command = duthost.get_vtysh_cmd_for_namespace('vtysh -c "show bgp summary json"', namespace)
    result = duthost.shell(command)
    stdout = result.get("stdout") if isinstance(result, Mapping) else None
    pytest_assert(isinstance(result, Mapping) and isinstance(stdout, str)
                  and not result.get("failed", False),
                  "Invalid BGP command result in namespace {}: result_type={}.{}, stdout_type={}.{}, "
                  "result={}".format(namespace, type(result).__module__, type(result).__qualname__,
                                     type(stdout).__module__, type(stdout).__qualname__, result))
    summary = None
    try:
        summary = json.loads(stdout)
    except ValueError as error:
        pytest.fail("Invalid BGP JSON in namespace {}: {}; stdout_type={}.{}, stdout={}".format(
            namespace, error, type(stdout).__module__, type(stdout).__qualname__, stdout))
    pytest_assert(isinstance(summary, dict), "Invalid BGP route summary: {}".format(summary))
    received = []
    peer_counts = []
    peer_names = []
    queues = {"inq": [], "outq": []}
    ready = True
    for family in ("ipv4Unicast", "ipv6Unicast"):
        if family not in summary:
            logger.debug("BGP address family %s is not configured", family)
            received.append(0)
            peer_counts.append({})
            peer_names.append({})
            for counts in queues.values():
                counts.append(0)
            continue
        family_summary = summary[family]
        pytest_assert(isinstance(family_summary, dict) and isinstance(family_summary.get("peers"), dict),
                      "Invalid BGP route summary: {}".format(family_summary))
        peers = family_summary["peers"]
        pytest_assert(all(isinstance(peer, dict) and isinstance(peer.get("state"), str)
                          and all(type(peer.get(field)) is int and peer[field] >= 0
                                  for field in ("pfxRcd", "inq", "outq")) for peer in peers.values()),
                      "Invalid BGP peer counts, queues or state: {}".format(family_summary))
        counts = {address: peer["pfxRcd"] for address, peer in peers.items()}
        peer_counts.append(counts)
        peer_names.append({address: peer.get("desc") for address, peer in peers.items()})
        received.append(sum(counts.values()))
        ready &= all(peer["state"] == "Established" for peer in peers.values())
        for queue, values in queues.items():
            values.append(sum(peer[queue] for peer in peers.values()))
    resources = duthost.get_crm_resources(namespace)
    pytest_assert(isinstance(resources, Mapping) and isinstance(resources.get("main_resources"), Mapping),
                  "Invalid route CRM counters: resource_type={}.{}, resources={}".format(
                      type(resources).__module__, type(resources).__qualname__, resources))
    resources = resources["main_resources"]
    pytest_assert(all(isinstance(resources.get(family), Mapping) and "used" in resources[family]
                      for family in ("ipv4_route", "ipv6_route")),
                  "Invalid route CRM counters: {}".format(resources))
    crm = tuple(resources[family]["used"] for family in ("ipv4_route", "ipv6_route"))
    pytest_assert(all(type(count) is int and count >= 0 for count in crm),
                  "Invalid route CRM counters: {}".format(crm))
    return {
        "bgp": tuple(received), "crm": crm, "peers": tuple(peer_counts),
        "peer_names": tuple(peer_names),
        "queues": {queue: tuple(counts) for queue, counts in queues.items()}, "ready": ready,
    }


def wait_for_route_convergence(duthost, namespace, action, before, route_families, expected=None):
    """Require progress, known targets and two consecutive healthy, queue-empty samples."""
    pytest_assert(action in ("announce", "withdraw", "snapshot"), "Invalid route action: {}".format(action))
    pytest_assert(isinstance(route_families, tuple) and len(route_families) == 2
                  and all(type(family) is bool for family in route_families),
                  "Invalid submitted route families: {}".format(route_families))
    if expected is not None:
        pytest_assert(isinstance(expected, dict)
                      and all(isinstance(expected.get(counter), tuple) and len(expected[counter]) == 2
                              and all(target is None or type(target) is int and target >= 0
                                      for target in expected[counter]) for counter in ("bgp", "crm")),
                      "Invalid route target: {}".format(expected))
        if "peers" in expected:
            pytest_assert(isinstance(expected["peers"], tuple) and len(expected["peers"]) == 2
                          and all(peers is None or isinstance(peers, dict)
                                  and all(type(count) is int and count >= 0 for count in peers.values())
                                  for peers in expected["peers"]),
                          "Invalid BGP peer target: {}".format(expected))
    direction = 1 if action == "announce" else -1
    check_crm = duthost.facts["asic_type"] != "vs"
    previous = None
    current = None
    samples = deque(maxlen=10)

    def routes_converged():
        nonlocal previous, current
        last = previous
        previous = None
        sample = {"state": None, "queue_empty": False}
        samples.append(sample)
        current = get_route_state(duthost, namespace)
        queue_empty = all(count == 0 for counts in current["queues"].values() for count in counts)
        sample.update(state=current, queue_empty=queue_empty)
        same_peers = all(set(now) == set(original) for now, original in zip(current["peers"], before["peers"]))
        progressed = True
        at_target = True
        for index, has_routes in enumerate(route_families):
            has_routes = has_routes and bool(before["peers"][index]) and action != "snapshot"
            bgp_target = expected["bgp"][index] if expected is not None else None
            crm_target = expected["crm"][index] if expected is not None else None
            if action != "snapshot" and not has_routes:
                bgp_target = before["bgp"][index] if bgp_target is None else bgp_target
                crm_target = before["crm"][index] if crm_target is None else crm_target
                at_target &= current["peers"][index] == before["peers"][index]
                if check_crm:
                    at_target &= abs(current["crm"][index] - before["crm"][index]) < ALLOW_ROUTES_CHANGE_NUMS
            needs_bgp_change = has_routes and (
                bgp_target != before["bgp"][index] if bgp_target is not None
                else action == "announce" or before["bgp"][index] > 0
            )
            if needs_bgp_change:
                progressed &= (current["bgp"][index] - before["bgp"][index]) * direction > 0
            needs_crm_change = has_routes and (
                crm_target != before["crm"][index]
                and (needs_bgp_change or abs(crm_target - before["crm"][index]) >= ALLOW_ROUTES_CHANGE_NUMS)
                if crm_target is not None else needs_bgp_change
            )
            if check_crm and needs_crm_change:
                progressed &= (current["crm"][index] - before["crm"][index]) * direction > 0
            if bgp_target is not None:
                at_target &= current["bgp"][index] == bgp_target
            if check_crm and crm_target is not None:
                at_target &= abs(current["crm"][index] - crm_target) < ALLOW_ROUTES_CHANGE_NUMS
        if expected is not None and "peers" in expected:
            at_target &= all(target is None or now == target for now, target
                             in zip(current["peers"], expected["peers"]))
        stable = last is not None and current["peers"] == last["peers"] and (
            not check_crm or current["crm"] == last["crm"]
        )
        eligible = queue_empty and current["ready"] and same_peers and progressed and at_target
        logger.debug("Route sample: action=%s namespace=%s families=%s before=%s expected=%s state=%s "
                     "queue_empty=%s same_peers=%s progressed=%s at_target=%s stable=%s",
                     action, namespace, route_families, before, expected, current,
                     queue_empty, same_peers, progressed, at_target, stable)
        previous = current if eligible else None
        return eligible and stable

    full_wait_time = MAX_WAIT_TIME + CRM_POLLING_INTERVAL * 100
    converged = wait_until(full_wait_time, CRM_POLLING_INTERVAL, CRM_POLLING_INTERVAL, routes_converged)
    pytest_assert(converged,
                  "Routes failed to converge after {} in {} seconds: namespace={}, before={}, "
                  "families={}, expected={}, samples={}".format(
                      action, full_wait_time, namespace, before, route_families, expected, list(samples)))
    logger.info("Routes converged after %s: namespace=%s, expected=%s, state=%s", action, namespace, expected, current)
    return current


def change_routes_and_wait(duthost, namespace, localhost, ptf_ip, topo_name, action, before=None, expected=None):
    """The announce_routes receipt describes submitted routes, not DUT convergence."""
    pytest_assert(action in ("announce", "withdraw"), "Invalid route action: {}".format(action))
    if before is None:
        before = get_route_state(duthost, namespace)
    logger.info("%s ipv4 and ipv6 routes", action)
    result = localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action=action, path="../ansible/")
    topo_routes = result.get("topo_routes") if isinstance(result, Mapping) else None
    pytest_assert(isinstance(result, Mapping) and isinstance(topo_routes, Mapping)
                  and not result.get("failed", False),
                  "Route action {} did not return topo_routes: result_type={}.{}, topo_routes_type={}.{}, "
                  "result={}".format(action, type(result).__module__, type(result).__qualname__,
                                     type(topo_routes).__module__, type(topo_routes).__qualname__, result))
    pytest_assert(all(isinstance(routes, Mapping) and all(isinstance(routes.get(family, []), (list, tuple))
                      for family in ("ipv4", "ipv6")) for routes in result["topo_routes"].values()),
                  "Route action {} returned invalid topo_routes: {}".format(action, result))
    pytest_assert(all(isinstance(route, (list, tuple)) and len(route) == 3
                      and isinstance(route[0], str) and route[0]
                      and isinstance(route[1], str) and route[1]
                      and (route[2] is None or isinstance(route[2], str))
                      for routes in result["topo_routes"].values() for family in ("ipv4", "ipv6")
                      for route in routes.get(family, [])),
                  "Route action {} returned invalid route tuples: {}".format(action, result))
    route_families = []
    for index, family in enumerate(("ipv4", "ipv6")):
        submitted = any(routes.get(family, []) for routes in result["topo_routes"].values())
        names = before["peer_names"][index]
        if not submitted or not before["peers"][index]:
            route_families.append(False)
        elif all(isinstance(name, str) and name in result["topo_routes"] for name in names.values()):
            route_families.append(any(result["topo_routes"][name].get(family, []) for name in names.values()))
        else:
            # Internal peers or older summaries may not identify topology VMs; do not waive progress.
            logger.warning("Cannot scope %s route receipt to every BGP peer in namespace %s: names=%s; "
                           "requiring topology-wide family progress", family, namespace, names)
            route_families.append(submitted)
    return wait_for_route_convergence(duthost, namespace, action, before, tuple(route_families), expected)


@pytest.fixture(scope="module")
def withdraw_and_restore_routes(duthosts, localhost, tbinfo, enum_rand_one_per_hwsku_frontend_hostname,
                                enum_rand_one_frontend_asic_index, cleanup_neighbors_dualtor, set_polling_interval):
    """Capture a converged withdrawn baseline and restore routes even if setup fails."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    namespace = duthost.asic_instance(enum_rand_one_frontend_asic_index).namespace
    ptf_ip = tbinfo["ptf_ip"]
    topo_name = tbinfo["topo"]["name"]
    initial = get_route_state(duthost, namespace)
    initial = wait_for_route_convergence(duthost, namespace, "snapshot", initial, (False, False))
    # A family with no received routes has no known announced target yet.
    restore_expected = {
        "bgp": tuple(count if count > 0 else None for count in initial["bgp"]),
        "crm": tuple(initial["crm"][index] if count > 0 else None
                     for index, count in enumerate(initial["bgp"])),
        "peers": tuple(peers if count > 0 or not peers else None
                       for count, peers in zip(initial["bgp"], initial["peers"])),
    }
    withdrawn = initial
    try:
        withdrawn = change_routes_and_wait(
            duthost, namespace, localhost, ptf_ip, topo_name, "withdraw", before=initial)
        yield {"withdrawn": withdrawn, "announced": restore_expected}
    finally:
        error_type, error, traceback = sys.exc_info()
        try:
            # Do not let a failed pre-cleanup observation prevent route re-announcement.
            change_routes_and_wait(duthost, namespace, localhost, ptf_ip, topo_name,
                                   "announce", before=withdrawn, expected=restore_expected)
        except (Exception, pytest.fail.Exception) as restore_error:
            logger.exception("Route restoration failed in namespace %s; original failure=%r", namespace, error)
            if error_type is not None and error_type is not GeneratorExit:
                raise error.with_traceback(traceback) from restore_error
            raise
