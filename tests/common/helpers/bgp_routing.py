"""
Reusable helpers for BGP route injection via ExaBGP and neighbor route verification.

These utilities are designed to be used across multiple BGP test modules that need to:
  - Announce/withdraw routes via ExaBGP HTTP API on PTF host
  - Verify route presence/absence on neighbor hosts (EosHost, SonicHost)
"""

import ipaddress
import logging
import time

import requests

from tests.common.devices.eos import EosHost
from tests.common.devices.sonic import SonicHost
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# Default wait time after ExaBGP route injection for BGP convergence
DEFAULT_BGP_ANNOUNCE_WAIT = 3


# ---- ExaBGP helpers ----

def exabgp_send(ptfhost, port, msg):
    """Post a single command to an ExaBGP HTTP API endpoint.

    Args:
        ptfhost: PTF host object (must have .mgmt_ip attribute)
        port: ExaBGP HTTP API port number
        msg: ExaBGP command string (e.g. "announce route 10.0.0.0/24 next-hop 10.0.0.1")
    """
    url = "http://{}:{}".format(ptfhost.mgmt_ip, port)
    r = requests.post(url, data={"commands": msg}, proxies={"http": None, "https": None})
    assert r.status_code == 200, "ExaBGP API call failed: status={}, url={}, msg={}".format(
        r.status_code, url, msg
    )


def inject_routes(setup, ptfhost, prefixes, action, announce_wait=DEFAULT_BGP_ANNOUNCE_WAIT):
    """Announce or withdraw a list of prefixes via ExaBGP on a downstream neighbor.

    Args:
        setup: dict with keys 'nhipv4', 'nhipv6', 'm0_exabgp_port', 'm0_exabgp_port_v6'
        ptfhost: PTF host object
        prefixes: list of prefix strings (e.g. ["10.100.1.0/24", "10.100.2.0/24"])
        action: 'announce' or 'withdraw'
        announce_wait: seconds to wait after injection for BGP convergence
    """
    assert action in ("announce", "withdraw"), "Invalid action: {}".format(action)
    for prefix in prefixes:
        ver = ipaddress.ip_network(prefix, strict=False).version
        if ver == 4:
            nexthop = setup["nhipv4"]
            port = setup["m0_exabgp_port"]
        else:
            nexthop = setup["nhipv6"]
            port = setup["m0_exabgp_port_v6"]
        msg = "{} route {} next-hop {}".format(action, prefix, nexthop)
        exabgp_send(ptfhost, port, msg)
        logger.info("ExaBGP: %s (port=%d)", msg, port)
    time.sleep(announce_wait)


# ---- Neighbor route verification helpers ----

def route_present_on_host(host, prefix):
    """Return True if the prefix is in the BGP table of the given neighbor host.

    Supports EosHost and SonicHost. Exception-safe: returns False on any error
    so that wait_until polling can continue retrying instead of aborting on
    transient SSH / API failures.

    Args:
        host: neighbor host object (EosHost or SonicHost)
        prefix: route prefix string (e.g. "10.100.0.0/16")

    Returns:
        bool: True if the prefix is present in the BGP table
    """
    try:
        if isinstance(host, EosHost):
            route_data = host.get_route(prefix)
            entries = route_data.get("vrfs", {}).get("default", {}).get("bgpRouteEntries", {})
            return prefix in entries
        elif isinstance(host, SonicHost):
            route_data = host.get_route(prefix)
            return bool(route_data and "paths" in route_data)
        else:
            logger.warning("Unknown neighbor host type: %s", type(host))
            return False
    except Exception as e:
        logger.debug("Failed to check route %s on %s: %s", prefix, host, e)
        return False


def check_route_on_neighbors(nbrhosts, neighbor_list, prefix, expected_present):
    """Polling target: returns True when ALL neighbors match expected_present.

    Args:
        nbrhosts: dict of neighbor host info (nbrhosts[name]["host"])
        neighbor_list: list of neighbor names to check
        prefix: route prefix to check
        expected_present: True if route should be present, False if absent

    Returns:
        bool: True when all neighbors match the expected state
    """
    for nbr in neighbor_list:
        present = route_present_on_host(nbrhosts[nbr]["host"], prefix)
        if present != expected_present:
            state = "present" if expected_present else "absent"
            logger.info("%s not yet %s on %s", prefix, state, nbr)
            return False
    return True


def verify_route_on_neighbors(nbrhosts, neighbor_list, prefix, expected_present, timeout=60):
    """Assert that a route is present (or absent) on ALL specified neighbors,
    polling until convergence or timeout.

    Args:
        nbrhosts: dict of neighbor host info
        neighbor_list: list of neighbor names to check
        prefix: route prefix to verify
        expected_present: True if route should be present, False if absent
        timeout: max seconds to wait for convergence
    """
    ok = wait_until(timeout, 2, 0, check_route_on_neighbors,
                    nbrhosts, neighbor_list, prefix, expected_present)
    state_str = "present" if expected_present else "absent"
    pytest_assert(
        ok,
        "Route {} expected to be {} on {} after {}s".format(prefix, state_str, neighbor_list, timeout)
    )
