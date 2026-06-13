import logging
import re
import time
from collections import deque

from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import wait_until

TOPO_FILENAME_TEMPLATE = 'topo_{}.yml'
SHOW_BGP_SUMMARY_CMD = "show ip bgp summary"
SHOW_BGP_SUMMARY_CMD_V6 = "show ipv6 bgp summary"
LOOP_TIMES_LEVEL_MAP = {
    'debug': 1,
    'basic': 10,
    'confident': 50,
    'thorough': 100,
    'diagnose': 200
}


def get_crm_resource_status(duthost, resource, status, namespace=DEFAULT_NAMESPACE):
    return duthost.get_crm_resources(namespace).get("main_resources").get(resource).get(status)


def check_queue_status(duthost, queue):
    """True when InQ/OutQ are idle for both IPv4 and IPv6 BGP peers.

    T2 (e.g. lt2) may finish IPv4 updates while IPv6 peers still drain;
    waiting on IPv4-only caused announce/withdraw to continue before routes left ASIC/CRM.
    """
    if not bgp_peer_queue_rows_idle(duthost, SHOW_BGP_SUMMARY_CMD, queue, ipv4_peers_only=True):
        return False
    if not bgp_peer_queue_rows_idle(duthost, SHOW_BGP_SUMMARY_CMD_V6, queue, ipv4_peers_only=False):
        return False
    return True


def crm_route_counts_near_baseline(duthost, namespace, ipv4_before, ipv6_before, tolerance):
    """True when CRM ipv4/ipv6 route used counts are within tolerance of baseline."""
    v4 = get_crm_resource_status(duthost, "ipv4_route", "used", namespace)
    v6 = get_crm_resource_status(duthost, "ipv6_route", "used", namespace)
    if v4 is None or v6 is None:
        return False
    return abs(v4 - ipv4_before) < tolerance and abs(v6 - ipv6_before) < tolerance


def wait_crm_route_counts_stabilized(
    duthost,
    namespace,
    max_wait=300,
    poll_interval=10,
    stability_delta=10,
    consecutive_stable_required=3,
    min_elapsed_before_stable_sec=0,
    flat_window_samples=0,
    flat_window_delta=25,
):
    """Wait until CRM ipv4/ipv6 route 'used' look settled.

    BGP InQ/OutQ can be idle while ASIC/CRM counts are still moving after large route withdraws; the stress
    test baseline must be taken after CRM settles.

    A single pair of samples within `stability_delta` is not enough on lt2: ipv6 (and sometimes ipv4)
    CRM can decrease slowly (<= delta every poll) for minutes, so we require consecutive stable polls,
    optionally a minimum wall time, and optionally a rolling window where max-min across recent stable
    samples must be small
    """
    state = {"pv4": None, "pv6": None, "streak": 0}
    start_ts = time.time()
    history = deque(maxlen=flat_window_samples) if flat_window_samples else None

    def stable():
        v4 = get_crm_resource_status(duthost, "ipv4_route", "used", namespace)
        v6 = get_crm_resource_status(duthost, "ipv6_route", "used", namespace)
        if v4 is None or v6 is None:
            return False
        if state["pv4"] is None:
            state["pv4"], state["pv6"] = v4, v6
            state["streak"] = 0
            if history is not None:
                history.clear()
            return False
        ok = (
            abs(v4 - state["pv4"]) <= stability_delta
            and abs(v6 - state["pv6"]) <= stability_delta
        )
        state["pv4"], state["pv6"] = v4, v6
        if ok:
            state["streak"] += 1
            if history is not None:
                history.append((v4, v6))
        else:
            state["streak"] = 0
            if history is not None:
                history.clear()
        elapsed = time.time() - start_ts
        if history is not None:
            if len(history) < flat_window_samples:
                return False
            v4s = [p[0] for p in history]
            v6s = [p[1] for p in history]
            if (
                max(v4s) - min(v4s) > flat_window_delta
                or max(v6s) - min(v6s) > flat_window_delta
            ):
                return False
        return (
            state["streak"] >= consecutive_stable_required
            and elapsed >= min_elapsed_before_stable_sec
        )

    settled = wait_until(max_wait, poll_interval, 0, stable)
    if not settled:
        logging.warning(
            "CRM ipv4/ipv6 route used did not stabilize within {}s (delta<={} between polls, "
            "need {} consecutive stable polls, min_elapsed={}s, flat_window={}/{}); "
            "using last sample v4={} v6={}".format(
                max_wait, stability_delta, consecutive_stable_required, min_elapsed_before_stable_sec,
                flat_window_samples, flat_window_delta, state["pv4"], state["pv6"])
        )
    return state["pv4"], state["pv6"]


def neighbor_cell(neighbor):
    if "neighbhor" in neighbor:
        return neighbor["neighbhor"]
    return neighbor.get("neighbor")


def bgp_peer_queue_rows_idle(duthost, show_cmd, queue, ipv4_peers_only):
    """Return True when all relevant BGP peers have queue counter == 0."""
    try:
        ipv4_regex = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$")
        bgp_neighbors = duthost.show_and_parse(show_cmd)
    except Exception:
        # Broad catch: show_and_parse / CLI can fail transiently
        logging.debug(
            "check_queue_status: failed to parse {}".format(show_cmd),
            exc_info=True
        )
        return True

    if not bgp_neighbors:
        return True

    for neighbor in bgp_neighbors:
        neigh = neighbor_cell(neighbor)
        if neigh is None:
            continue
        if neigh.startswith("Neighbhor") or neigh.startswith("Neighbor") or neigh.startswith("---"):
            continue
        if ipv4_peers_only:
            if not ipv4_regex.match(neigh):
                continue
        else:
            # IPv6 unicast summary: peer addresses contain ':' (skip v4-mapped if any)
            if ":" not in neigh or ipv4_regex.match(neigh):
                continue
        try:
            if int(neighbor[queue]) != 0:
                return False
        except (KeyError, ValueError, TypeError):
            # Parser row missing queue column or non-integer
            continue
    return True


def sleep_to_wait(seconds):
    if seconds > 300:
        seconds = 300
    time.sleep(seconds)
