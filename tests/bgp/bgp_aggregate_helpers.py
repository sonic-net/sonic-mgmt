"""Shared helpers for BGP aggregate-address tests.

Provides:
  - Constants (aggregate prefixes, DB table names, ExaBGP ports)
  - AggregateCfg namedtuple
  - DB dump / FRR running-config helpers
  - GCU JSON patch helpers (add/remove aggregate)
  - ExaBGP route announce/withdraw helpers
  - M2 (upstream) route verification helpers
  - Common Validators (CONFIG_DB / STATE_DB / FRR consistency, cleanup)
"""

import ast
import logging
import time
from collections import namedtuple

import requests

from tests.common.devices.eos import EosHost
from tests.common.gcu_utils import (
    apply_gcu_patch,
    apply_patch,
    generate_tmpfile,
    delete_tmpfile,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# ---- Constants ----
BGP_AGGREGATE_ADDRESS = "BGP_AGGREGATE_ADDRESS"
PLACEHOLDER_PREFIX = "192.0.2.0/32"

# Convergence wait times
ROUTE_PROPAGATION_WAIT = 10
BGP_SETTLE_WAIT = 5

# ---- AggregateCfg ----
AggregateCfg = namedtuple("AggregateCfg", ["prefix", "bbr_required", "summary_only", "as_set"])


# ---- DB & running-config helpers ----
def dump_db(duthost, dbname, tablename):
    """Return current DB content as dict."""
    keys_out = duthost.shell(
        f"sonic-db-cli {dbname} keys '{tablename}*'", module_ignore_errors=True
    )["stdout"]
    logger.info(f"dump {dbname} db, table {tablename}, keys output: {keys_out}")
    keys = keys_out.strip().splitlines() if keys_out.strip() else []
    res = {}
    for k in keys:
        fields = duthost.shell(
            f"sonic-db-cli {dbname} hgetall '{k}'", module_ignore_errors=True
        )["stdout"]
        logger.info(f"all fields:{fields} for key: {k}")
        prefix = k.removeprefix(f"{tablename}|")
        res[prefix] = ast.literal_eval(fields)
    logger.info(f"dump {dbname} table {tablename} result: {res}")
    return res


def running_bgp_has_aggregate(duthost, prefix):
    """Grep FRR running BGP config for aggregate-address lines."""
    return duthost.shell(
        f"show runningconfiguration bgp | grep -i 'aggregate-address {prefix}'",
        module_ignore_errors=True,
    )["stdout"]


# ---- GCU JSON patch helpers ----
def gcu_add_placeholder_aggregate(duthost, prefix):
    patch = [
        {
            "op": "add",
            "path": f"/BGP_AGGREGATE_ADDRESS/{prefix.replace('/', '~1')}",
            "value": {"summary-only": "false", "as-set": "false"},
        }
    ]
    logger.info(f"Adding placeholder BGP aggregate {prefix.replace('/', '~1')}")
    return apply_gcu_patch(duthost, patch)


def gcu_add_aggregate(duthost, aggregate_cfg):
    logger.info("Add BGP_AGGREGATE_ADDRESS by GCU cmd")
    patch = [
        {
            "op": "add",
            "path": f"/BGP_AGGREGATE_ADDRESS/{aggregate_cfg.prefix.replace('/', '~1')}",
            "value": {
                "bbr-required": "true" if aggregate_cfg.bbr_required else "false",
                "summary-only": "true" if aggregate_cfg.summary_only else "false",
                "as-set": "true" if aggregate_cfg.as_set else "false",
            },
        }
    ]
    apply_gcu_patch(duthost, patch)


def gcu_remove_aggregate(duthost, prefix):
    patch = [{"op": "remove", "path": f"/BGP_AGGREGATE_ADDRESS/{prefix.replace('/', '~1')}"}]
    apply_gcu_patch(duthost, patch)


def safe_remove_aggregate(duthost, prefix):
    """Best-effort removal for cleanup — never raises."""
    try:
        patch = [
            {
                "op": "remove",
                "path": f"/BGP_AGGREGATE_ADDRESS/{prefix.replace('/', '~1')}",
            }
        ]
        tmpfile = generate_tmpfile(duthost)
        try:
            apply_patch(duthost, json_data=patch, dest_file=tmpfile)
        finally:
            delete_tmpfile(duthost, tmpfile)
    except Exception:
        logger.debug(
            "Cleanup: aggregate %s already absent or will be recovered by rollback",
            prefix,
        )


def gcu_add_multiple_aggregates(duthost, cfgs):
    """Add several aggregate entries in a single GCU patch."""
    patch = [
        {
            "op": "add",
            "path": f"/BGP_AGGREGATE_ADDRESS/{c.prefix.replace('/', '~1')}",
            "value": {
                "bbr-required": "true" if c.bbr_required else "false",
                "summary-only": "true" if c.summary_only else "false",
                "as-set": "true" if c.as_set else "false",
            },
        }
        for c in cfgs
    ]
    apply_gcu_patch(duthost, patch)


def gcu_remove_multiple_aggregates(duthost, prefixes):
    """Remove several aggregate entries in a single GCU patch."""
    patch = [
        {
            "op": "remove",
            "path": f"/BGP_AGGREGATE_ADDRESS/{p.replace('/', '~1')}",
        }
        for p in prefixes
    ]
    apply_gcu_patch(duthost, patch)


def gcu_update_aggregate_field(duthost, prefix, field, value):
    """Update a single field of an existing aggregate via GCU."""
    patch = [
        {
            "op": "replace",
            "path": f"/BGP_AGGREGATE_ADDRESS/{prefix.replace('/', '~1')}/{field}",
            "value": value,
        }
    ]
    apply_gcu_patch(duthost, patch)


# ---- ExaBGP route announcement helpers ----
def exabgp_announce_route(ptfip, port, prefix, nexthop):
    """Announce a route via ExaBGP HTTP API."""
    msg = 'announce route {} next-hop {}'.format(prefix, nexthop)
    url = 'http://{}:{}'.format(ptfip, port)
    data = {'commands': msg}
    logger.info("ExaBGP announce: url={}, data={}".format(url, data))
    r = requests.post(url, data=data, proxies={"http": None, "https": None})
    assert r.status_code == 200


def exabgp_withdraw_route(ptfip, port, prefix, nexthop):
    """Withdraw a route via ExaBGP HTTP API."""
    msg = 'withdraw route {} next-hop {}'.format(prefix, nexthop)
    url = 'http://{}:{}'.format(ptfip, port)
    data = {'commands': msg}
    logger.info("ExaBGP withdraw: url={}, data={}".format(url, data))
    r = requests.post(url, data=data, proxies={"http": None, "https": None})
    assert r.status_code == 200


def announce_contributing_routes(setup, prefixes, ip_version="ipv4"):
    """Announce a list of contributing route prefixes from the downstream M0 neighbor."""
    if ip_version == "ipv4":
        port = setup['downstream_exabgp_port']
        nexthop = setup['nhipv4']
    else:
        port = setup['downstream_exabgp_port_v6']
        nexthop = setup['nhipv6']
    for prefix in prefixes:
        exabgp_announce_route(setup['ptfip'], port, prefix, nexthop)
    time.sleep(ROUTE_PROPAGATION_WAIT)


def withdraw_contributing_routes(setup, prefixes, ip_version="ipv4"):
    """Withdraw a list of contributing route prefixes from the downstream M0 neighbor."""
    if ip_version == "ipv4":
        port = setup['downstream_exabgp_port']
        nexthop = setup['nhipv4']
    else:
        port = setup['downstream_exabgp_port_v6']
        nexthop = setup['nhipv6']
    for prefix in prefixes:
        exabgp_withdraw_route(setup['ptfip'], port, prefix, nexthop)
    time.sleep(BGP_SETTLE_WAIT)


# ---- M2 (upstream) route verification helpers ----
def _check_route_on_neighbor(nbrhosts, neighbor, prefix):
    """Check whether a prefix exists and is active in the BGP table of a neighbor VM.

    Returns True if the route is present with at least one BGP path, False otherwise.
    On EOS, a withdrawn route may briefly remain in bgpRouteEntries with empty
    bgpRoutePaths; checking for non-empty paths avoids false positives.
    """
    host = nbrhosts[neighbor]['host']
    route_info = host.get_route(prefix)
    if isinstance(host, EosHost):
        entries = route_info.get('vrfs', {}).get('default', {}).get('bgpRouteEntries', {})
        if prefix not in entries:
            return False
        # Verify the entry has at least one BGP path (not a stale/withdrawn entry)
        paths = entries[prefix].get('bgpRoutePaths', [])
        return len(paths) > 0
    else:
        # SonicHost — route_info is the JSON from vtysh show bgp
        return bool(route_info) and 'paths' in route_info


def verify_route_on_m2(nbrhosts, upstream_neighbors, prefix, expected_present=True):
    """Verify a route is present or absent on upstream M2 neighbors.

    Checks at least one upstream neighbor (the first one) for the route.
    Uses wait_until for convergence tolerance.
    """
    neighbor = upstream_neighbors[0]

    def _check():
        return _check_route_on_neighbor(nbrhosts, neighbor, prefix) == expected_present

    action = "present" if expected_present else "absent"
    pytest_assert(
        wait_until(120, 5, 0, _check),
        f"Route {prefix} expected to be {action} on upstream neighbor {neighbor} but was not"
    )


def verify_contributing_routes_on_m2(nbrhosts, upstream_neighbors, prefixes, expected_present=True):
    """Verify contributing routes are present or absent on upstream M2 neighbors."""
    neighbor = upstream_neighbors[0]
    for prefix in prefixes:
        def _check(p=prefix):
            return _check_route_on_neighbor(nbrhosts, neighbor, p) == expected_present
        action = "present" if expected_present else "absent"
        pytest_assert(
            wait_until(120, 5, 0, _check),
            f"Contributing route {prefix} expected to be {action} on upstream neighbor {neighbor} but was not"
        )


# ---- Common Validators ----
def verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg):
    """Validate CONFIG_DB, STATE_DB, and FRR running-config are consistent for an aggregate."""
    # CONFIG_DB validation
    config_db = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(cfg.prefix in config_db, f"Aggregate row {cfg.prefix} not found in CONFIG_DB")
    pytest_assert(
        config_db[cfg.prefix].get("bbr-required") == ("true" if cfg.bbr_required else "false"),
        "bbr-required flag mismatch",
    )
    pytest_assert(
        config_db[cfg.prefix].get("summary-only") == ("true" if cfg.summary_only else "false"),
        "summary-only flag mismatch",
    )
    pytest_assert(
        config_db[cfg.prefix].get("as-set") == ("true" if cfg.as_set else "false"),
        "as-set flag mismatch",
    )

    # STATE_DB validation
    expected_state = "inactive" if (cfg.bbr_required and not bbr_enabled) else "active"

    def _state_db_ready():
        sdb = dump_db(duthost, "STATE_DB", BGP_AGGREGATE_ADDRESS)
        if cfg.prefix not in sdb:
            return False
        return sdb[cfg.prefix].get("state") == expected_state

    pytest_assert(
        wait_until(30, 5, 0, _state_db_ready),
        f"STATE_DB entry for {cfg.prefix} not found with state={expected_state} after waiting 30s",
    )

    # Running-config validation
    if cfg.bbr_required and not bbr_enabled:
        running_config = running_bgp_has_aggregate(duthost, cfg.prefix)
        pytest_assert(
            cfg.prefix not in running_config,
            f"aggregate-address {cfg.prefix} should not present in FRR running-config when bbr is disabled",
        )
    else:
        running_config = running_bgp_has_aggregate(duthost, cfg.prefix)
        pytest_assert(
            cfg.prefix in running_config,
            f"aggregate-address {cfg.prefix} not present in FRR running-config",
        )
        if cfg.summary_only:
            pytest_assert("summary-only" in running_config, "summary-only expected in running-config")
        else:
            pytest_assert("summary-only" not in running_config,
                          "summary-only should NOT be present for this scenario")
        if cfg.as_set:
            pytest_assert("as-set" in running_config, "as_set expected in running-config")
        else:
            pytest_assert("as-set" not in running_config, "as_set should NOT be present for this scenario")


def verify_bgp_aggregate_cleanup(duthost, prefix):
    """Validate aggregate is fully removed from CONFIG_DB, STATE_DB, and FRR running-config."""
    # CONFIG_DB validation
    config_db = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(prefix not in config_db, f"Aggregate row {prefix} should be cleaned up from CONFIG_DB")

    # STATE_DB validation
    def _state_db_prefix_gone():
        sdb = dump_db(duthost, "STATE_DB", BGP_AGGREGATE_ADDRESS)
        return prefix not in sdb

    pytest_assert(
        wait_until(30, 5, 0, _state_db_prefix_gone),
        f"STATE_DB entry for {prefix} should be removed after aggregate cleanup",
    )

    # Running-config validation
    running_config = running_bgp_has_aggregate(duthost, prefix)
    pytest_assert(
        prefix.split("/")[0] not in running_config,
        f"aggregate-address {prefix} should not present in FRR running-config",
    )
