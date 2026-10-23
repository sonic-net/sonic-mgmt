import re
import time

from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import wait_until

TOPO_FILENAME_TEMPLATE = 'topo_{}.yml'
# Seconds the CRM route counts must hold still before they count as settled; scaled by topology at the call site.
CRM_SETTLE_TIME = 30
SHOW_BGP_SUMMARY_CMD = "show ip bgp summary"
LOOP_TIMES_LEVEL_MAP = {
    'debug': 1,
    'basic': 10,
    'confident': 50,
    'thorough': 100,
    'diagnose': 200
}


def get_crm_route_counts(duthost, namespace=DEFAULT_NAMESPACE):
    """Return (ipv4, ipv6) CRM route used counts, or None while orchagent has not published CRM stats."""
    resources = duthost.get_crm_resources(namespace)
    # A multi-asic DUT returns one table per ASIC, keyed by namespace.
    if namespace in resources:
        resources = resources[namespace]
    resources = resources.get("main_resources") or {}
    if "ipv4_route" not in resources or "ipv6_route" not in resources:
        return None
    return resources["ipv4_route"]["used"], resources["ipv6_route"]["used"]


def wait_crm_route_counts_settled(duthost, namespace, timeout, settle_time, poll_interval=5, below=None):
    """Return (ipv4, ipv6) CRM route used counts once both stay unchanged for settle_time seconds.

    Counts that hold still are not proof the withdraw is done: on a topology with many peers a route entry
    stays until its last path is withdrawn, so the counts can sit flat near the full table for minutes.
    below rejects any reading where a family has gone up, or where none has come down, so that plateau
    cannot be mistaken for a settled baseline however long it lasts. Returns None if the counts do not
    settle within timeout.
    """
    state = {"counts": None, "since": None}

    def settled():
        # A failed CRM read raises out of here, and wait_until counts that as False without touching state,
        # so the settle window runs on through it.
        counts = get_crm_route_counts(duthost, namespace)
        now = time.time()
        if counts is None:
            state["counts"] = None
            return False
        # The withdraw has reached CRM once something has dropped and nothing has gone up. Demanding a
        # drop in both families would fail setup on a topology that only has one family to withdraw.
        # A family still on its way down keeps changing, so the settle window below covers the rest.
        if below is not None and (any(count > ref for count, ref in zip(counts, below))
                                  or not any(count < ref for count, ref in zip(counts, below))):
            state["counts"] = None
            return False
        if counts != state["counts"]:
            state["counts"], state["since"] = counts, now
            return False
        return now - state["since"] >= settle_time

    if wait_until(timeout, poll_interval, 0, settled):
        return state["counts"]
    return None


def check_queue_status(duthost, queue):
    bgp_neighbors = duthost.show_and_parse(SHOW_BGP_SUMMARY_CMD)
    bgp_neighbor_addr_regex = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}")
    for neighbor in bgp_neighbors:
        if "neighbhor" in neighbor:
            neigh = neighbor["neighbhor"]
        else:
            neigh = neighbor["neighbor"]
        if bgp_neighbor_addr_regex.match(neigh) and int(neighbor[queue]) != 0:
            return False
    return True


def sleep_to_wait(seconds):
    if seconds > 300:
        seconds = 300
    time.sleep(seconds)


def get_topo_scale_factor(tbinfo):
    # Baseline timings are tuned for ~5-peer topos (e.g. t2_single_node_min);
    # large fanout topos like t2_single_node_max_64p (64 peers) need
    # proportionally longer for BGP withdraw -> zebra -> SAI -> HW to converge.
    try:
        vms = tbinfo["topo"]["properties"]["topology"].get("VMs", {})
    except (KeyError, TypeError):
        return 1
    peer_count = len(vms)
    return max(1, peer_count // 10)
