"""
Tests for the BGP aggregate-address with bbr awareness feature in SONiC,
aligned with: https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/BGP-Aggregate-Address.md

Test Case 1: Scenarios covered via parametrize ipversion, bbr-required, summary-only and as-set.

Test Case 2: Test BBR Features State Change
  During device up, the BBR state may change, and this feature should take action accordingly.

Validations:
  - CONFIG_DB: BGP_AGGREGATE_ADDRESS row content (bbr-required/summary-only/as-set flags)
  - STATE_DB: BGP_AGGREGATE_ADDRESS row content (state flag align with bbr status)
  - FRR running config: aggregate-address line contains expected flags
"""

import ast
import ipaddress
import logging
import time
from collections import namedtuple

import pytest
import requests
from natsort import natsorted

# Functions
from bgp_bbr_helpers import config_bbr_by_gcu, get_bbr_default_state, is_bbr_enabled

from tests.common.devices.eos import EosHost
from tests.common.devices.sonic import SonicHost
from tests.common.gcu_utils import apply_gcu_patch
from tests.common.gcu_utils import create_checkpoint, rollback_or_reload, delete_checkpoint
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP, DOWNSTREAM_NEIGHBOR_MAP
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# ---- Topology & device-type markers (register in pytest.ini to avoid warnings) ----
pytestmark = [pytest.mark.topology("t1", "m1"), pytest.mark.device_type("vs"), pytest.mark.disable_loganalyzer]

# ---- Constants & helper structures ----
CONSTANTS_FILE = "/etc/sonic/constants.yml"

# Aggregate prefixes (Groups 1 & 2 — single /24 aggregate used for DB/FRR validation)
AGGR_V4 = "172.16.51.0/24"
AGGR_V6 = "2000:172:16:50::/64"
BGP_AGGREGATE_ADDRESS = "BGP_AGGREGATE_ADDRESS"
PLACEHOLDER_PREFIX = "192.0.2.0/32"  # RFC5737 TEST-NET-1

# ExaBGP base ports (downstream PTF ports)
EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000

# ---- Group 3: Route Presence and Withdrawal Behavior ----
# IPv4 /16 aggregate with three /24 contributing routes exercises the full lifecycle.
AGGR_GRP3_V4 = "10.100.0.0/16"
CONTRIBUTING_V4 = ["10.100.1.0/24", "10.100.2.0/24", "10.100.3.0/24"]

BGP_ANNOUNCE_TIME = 3  # seconds to wait after ExaBGP route injection for BGP convergence

AggregateCfg = namedtuple("AggregateCfg", ["prefix", "bbr_required", "summary_only", "as_set"])


@pytest.fixture(scope="module", autouse=True)
def setup_teardown(duthost):
    # This testcase will use GCU to modify several entries in running-config.
    # Restore the config via config_reload may cost too much time.
    # So we leverage GCU for the config update. Setup checkpoint before the test
    # and rollback to it after the test.
    create_checkpoint(duthost)

    # add placeholder aggregate to avoid GCU to remove empty table
    default_aggregates = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    if not default_aggregates:
        gcu_add_placeholder_aggregate(duthost, PLACEHOLDER_PREFIX)

    yield

    try:
        rollback_or_reload(duthost, fail_on_rollback_error=False)
    finally:
        delete_checkpoint(duthost)


# ---- DB & running-config helpers ----
def dump_db(duthost, dbname, tablename):
    """Return current DB content as dict."""
    keys_out = duthost.shell(f"sonic-db-cli {dbname} keys '{tablename}*'", module_ignore_errors=True)["stdout"]
    logger.info(f"dump {dbname} db, table {tablename}, keys output: {keys_out}")
    keys = keys_out.strip().splitlines() if keys_out.strip() else []
    res = {}
    for k in keys:
        fields = duthost.shell(f"sonic-db-cli {dbname} hgetall '{k}'", module_ignore_errors=True)["stdout"]
        logger.info(f"all fields:{fields} for key: {k}")
        prefix = k.removeprefix(f"{tablename}|")

        res[prefix] = ast.literal_eval(fields)
        logger.info("dump config db result: {}".format(res))
    return res


def running_bgp_has_aggregate(duthost, prefix):
    """Grep FRR running BGP config for aggregate-address lines."""
    return duthost.shell(
        f"show runningconfiguration bgp | grep -i 'aggregate-address {prefix}'", module_ignore_errors=True
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


def gcu_add_aggregate(duthost, aggregate_cfg: AggregateCfg):
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


# ---- Common Validator for Every Case ----
def verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg: AggregateCfg):
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
    pytest_assert(config_db[cfg.prefix].get("as-set") == ("true" if cfg.as_set else "false"), "as-set flag mismatch")

    # STATE_DB validation
    state_db = dump_db(duthost, "STATE_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(cfg.prefix in state_db, f"Aggregate row {cfg.prefix} not found in STATE_DB")

    # Running-config validation
    running_config = running_bgp_has_aggregate(duthost, cfg.prefix)

    if cfg.bbr_required and not bbr_enabled:
        pytest_assert(state_db[cfg.prefix].get("state") == "inactive", "state flag mismatch")
        pytest_assert(
            cfg.prefix not in running_config,
            f"aggregate-address {cfg.prefix} should not present in FRR running-config when bbr is disabled",
        )
    else:
        pytest_assert(state_db[cfg.prefix].get("state") == "active", "state flag mismatch")
        pytest_assert(cfg.prefix in running_config, f"aggregate-address {cfg.prefix} not present in FRR running-config")
        if cfg.summary_only:
            pytest_assert("summary-only" in running_config, "summary-only expected in running-config")
        else:
            pytest_assert("summary-only" not in running_config, "summary-only should NOT be present for this scenario")
        if cfg.as_set:
            pytest_assert("as-set" in running_config, "as_set expected in running-config")
        else:
            pytest_assert("as-set" not in running_config, "as_set should NOT be present for this scenario")


def verify_bgp_aggregate_cleanup(duthost, prefix):
    # CONFIG_DB validation
    config_db = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(prefix not in config_db, f"Aggregate row {prefix} should be clean up from CONFIG_DB")

    # STATE_DB validation
    state_db = dump_db(duthost, "STATE_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(prefix not in state_db, f"Aggregate row {prefix} should be clean up from  STATE_DB")

    # Running-config validation
    running_config = running_bgp_has_aggregate(duthost, prefix)
    pytest_assert(
        prefix.split("/")[0] not in running_config,
        f"aggregate-address {prefix} should not present in FRR running-config",
    )


# Test with parameters Combination
@pytest.mark.parametrize(
    "ip_version,bbr_required,summary_only,as_set",
    [
        ("ipv4", True, True, False),  # v4 + bbr-required + summary_only
        ("ipv6", True, True, False),  # v6 + bbr-required + summary_only
        ("ipv4", False, True, True),  # v4 + summary_only + as_set
        ("ipv6", False, False, False),  # v6
    ],
)
def test_bgp_aggregate_address(duthosts, rand_one_dut_hostname, ip_version, bbr_required, summary_only, as_set):
    """
    Unified BGP aggregate-address test with parametrize
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Select specific data
    if ip_version == "ipv4":
        cfg = AggregateCfg(prefix=AGGR_V4, bbr_required=bbr_required, summary_only=summary_only, as_set=as_set)
    else:
        cfg = AggregateCfg(prefix=AGGR_V6, bbr_required=bbr_required, summary_only=summary_only, as_set=as_set)

    # get default bbr state
    bbr_enabled = is_bbr_enabled(duthost)

    # Apply aggregate via GCU
    gcu_add_aggregate(duthost, cfg)

    # Verify config db, state db and running config
    verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg)

    # Cleanup
    gcu_remove_aggregate(duthost, cfg.prefix)

    # Verify config db, state db and running config are cleanup
    verify_bgp_aggregate_cleanup(duthost, cfg.prefix)


# Test BBR Features State Change
@pytest.mark.parametrize(
    "ip_version,bbr_required,summary_only,as_set",
    [
        ("ipv4", True, True, True),  # v4 + bbr-required + summary_only + as_set
        ("ipv6", True, True, False),  # v6 + bbr-required + summary_only
        ("ipv4", False, True, True),  # v4 + summary_only + as_set
        ("ipv6", False, False, True),  # v6 +  as_set
    ],
)
def test_bgp_aggregate_address_when_bbr_changed(
    duthosts, rand_one_dut_hostname, ip_version, bbr_required, summary_only, as_set
):
    """
    During device up, the BBR state may change, and the bgp aggregate address feature should take action accordingly.
    """
    duthost = duthosts[rand_one_dut_hostname]

    bbr_supported, bbr_default_state = get_bbr_default_state(duthost)
    if not bbr_supported:
        pytest.skip("BGP BBR is not supported")

    # Change BBR current state
    if bbr_default_state == "enabled":
        config_bbr_by_gcu(duthost, "disabled")
        bbr_enabled = False
    else:
        config_bbr_by_gcu(duthost, "enabled")
        bbr_enabled = True

    # Select specific data
    if ip_version == "ipv4":
        cfg = AggregateCfg(prefix=AGGR_V4, bbr_required=bbr_required, summary_only=summary_only, as_set=as_set)
    else:
        cfg = AggregateCfg(prefix=AGGR_V6, bbr_required=bbr_required, summary_only=summary_only, as_set=as_set)

    # Apply aggregate via GCU
    gcu_add_aggregate(duthost, cfg)

    # Verify config db, statedb and running config
    verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg)

    # Cleanup
    gcu_remove_aggregate(duthost, cfg.prefix)

    # Verify config db, statedb and running config are cleanup
    verify_bgp_aggregate_cleanup(duthost, cfg.prefix)

    # withdraw BBR state change
    if bbr_enabled:
        config_bbr_by_gcu(duthost, "disabled")
    else:
        config_bbr_by_gcu(duthost, "enabled")


# ===========================================================================
# Test Group 3: Route Presence and Withdrawal Behavior
# ===========================================================================
# Objective: Validate that the aggregate route on M2 (upstream) depends on the
# presence of contributing routes injected from M0 (downstream via ExaBGP), and
# that route withdrawal converges correctly.
#
# Validation model (black-box / neighbor-visible):
#   - M0 (downstream): ExaBGP announces/withdraws contributing more-specific routes
#   - M2 (upstream):   nbrhosts.get_route() checks aggregate/contributing presence
#
# Topology mapping (topology-agnostic via UPSTREAM/DOWNSTREAM_NEIGHBOR_MAP):
#   t1:  downstream=T0,  upstream=T2
#   m1:  downstream=M0,  upstream=MA  (test plan calls this "M2/MgmtSpineRouter";
#                                      nbrhosts key suffix is "MA" per UPSTREAM_NEIGHBOR_MAP)


@pytest.fixture(scope="module")
def route_propagation_setup(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo):
    """
    Discover downstream (M0/T0) and upstream (MA/T2) neighbors and ExaBGP ports
    for Test Group 3 route propagation tests.
    """
    topo_type = tbinfo["topo"]["type"]
    downstream_suffix = DOWNSTREAM_NEIGHBOR_MAP[topo_type].upper()
    upstream_suffix = UPSTREAM_NEIGHBOR_MAP[topo_type].upper()

    # Downstream neighbor used to inject contributing routes via ExaBGP
    downstream_neighbors = natsorted(
        [n for n in nbrhosts if n.upper().endswith(downstream_suffix)]
    )
    pytest_assert(downstream_neighbors, f"No downstream ({downstream_suffix}) neighbors found in nbrhosts")
    m0 = downstream_neighbors[0]

    # Upstream neighbors used to verify aggregate route reception
    upstream_neighbors = natsorted(
        [n for n in nbrhosts if n.upper().endswith(upstream_suffix)]
    )
    pytest_assert(upstream_neighbors, f"No upstream ({upstream_suffix}) neighbors found in nbrhosts")

    # ExaBGP HTTP API port for the chosen downstream neighbor
    m0_offset = tbinfo["topo"]["properties"]["topology"]["VMs"][m0]["vm_offset"]
    m0_exabgp_port = EXABGP_BASE_PORT + m0_offset
    m0_exabgp_port_v6 = EXABGP_BASE_PORT_V6 + m0_offset

    common_cfg = tbinfo["topo"]["properties"]["configuration_properties"]["common"]
    nhipv4 = common_cfg.get("nhipv4")
    nhipv6 = common_cfg.get("nhipv6")

    yield {
        "m0": m0,
        "m2_neighbors": upstream_neighbors,
        "m0_exabgp_port": m0_exabgp_port,
        "m0_exabgp_port_v6": m0_exabgp_port_v6,
        "nhipv4": nhipv4,
        "nhipv6": nhipv6,
    }


# ---- ExaBGP helpers ----

def _exabgp_send(ptfhost, port, msg):
    """Post a single command to an ExaBGP HTTP API endpoint."""
    url = f"http://{ptfhost.mgmt_ip}:{port}"
    r = requests.post(url, data={"commands": msg}, proxies={"http": None, "https": None})
    assert r.status_code == 200, f"ExaBGP API call failed: status={r.status_code}, url={url}, msg={msg}"


def _inject_routes(setup, ptfhost, prefixes, action):
    """
    Announce or withdraw a list of prefixes via ExaBGP on the downstream neighbor.

    Args:
        action: 'announce' or 'withdraw'
    """
    assert action in ("announce", "withdraw"), f"Invalid action: {action}"
    for prefix in prefixes:
        ver = ipaddress.ip_network(prefix, strict=False).version
        if ver == 4:
            nexthop = setup["nhipv4"]
            port = setup["m0_exabgp_port"]
        else:
            nexthop = setup["nhipv6"]
            port = setup["m0_exabgp_port_v6"]
        msg = f"{action} route {prefix} next-hop {nexthop}"
        _exabgp_send(ptfhost, port, msg)
        logger.info(f"ExaBGP: {msg} (port={port})")
    time.sleep(BGP_ANNOUNCE_TIME)


# ---- Neighbor route verification helpers ----

def _route_present_on_host(host, prefix):
    """Return True if the prefix is in the BGP table of the given neighbor host.

    Exception-safe: returns False on any error so that wait_until polling can
    continue retrying instead of aborting on transient SSH / API failures.
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
            logger.warning(f"Unknown neighbor host type: {type(host)}")
            return False
    except Exception as e:
        logger.debug(f"Failed to check route {prefix} on {host}: {e}")
        return False


def _check_route_on_all_m2(nbrhosts, m2_list, prefix, expected_present):
    """Polling target: returns True when ALL M2 neighbors match expected_present."""
    for m2 in m2_list:
        present = _route_present_on_host(nbrhosts[m2]["host"], prefix)
        if present != expected_present:
            state = "present" if expected_present else "absent"
            logger.info(f"{prefix} not yet {state} on {m2}")
            return False
    return True


def verify_route_on_m2(nbrhosts, m2_list, prefix, expected_present, timeout=60):
    """
    Assert that a route is present (or absent) on ALL upstream M2 neighbors,
    polling until convergence or timeout.
    """
    ok = wait_until(timeout, 2, 0, _check_route_on_all_m2, nbrhosts, m2_list, prefix, expected_present)
    state_str = "present" if expected_present else "absent"
    pytest_assert(ok, f"Route {prefix} expected to be {state_str} on M2 {m2_list} after {timeout}s")


# ===========================================================================
# Test Case 3.1 — Aggregate route with no contributing routes
# ===========================================================================

def test_aggregate_no_contributing_routes(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, route_propagation_setup
):
    """
    TC 3.1: Aggregate address is NOT advertised to M2 when no contributing
    more-specific routes exist in the DUT BGP table.  Once a contributing
    route is injected the aggregate MUST appear on M2.

    Steps:
      1. Add aggregate (bbr-required=false, summary-only=false) without
         any contributing routes.
      2. Verify aggregate is absent on M2.
      3. Inject one contributing route from M0.
      4. Verify aggregate appears on M2.
      5. Cleanup: withdraw contributing route, remove aggregate.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = route_propagation_setup
    agg_prefix = AGGR_GRP3_V4
    contributing = CONTRIBUTING_V4[:1]  # single /24 is enough to trigger aggregation

    cfg = AggregateCfg(prefix=agg_prefix, bbr_required=False, summary_only=False, as_set=False)

    try:
        # Step 1: configure aggregate, no contributing routes yet
        gcu_add_aggregate(duthost, cfg)

        # Step 2: aggregate must NOT be on M2
        verify_route_on_m2(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=False, timeout=15)

        # Step 3: inject a contributing route
        _inject_routes(setup, ptfhost, contributing, "announce")

        # Step 4: aggregate must now appear on M2
        verify_route_on_m2(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)
    finally:
        _inject_routes(setup, ptfhost, contributing, "withdraw")
        try:
            gcu_remove_aggregate(duthost, agg_prefix)
        except Exception:
            logger.warning(f"Cleanup: failed to remove aggregate {agg_prefix}, will be recovered by rollback")


# ===========================================================================
# Test Case 3.2 — All contributing routes withdrawn
# ===========================================================================

def test_aggregate_all_contributing_withdrawn(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, route_propagation_setup
):
    """
    TC 3.2: Aggregate disappears on M2 once ALL contributing routes are
    withdrawn, and re-appears when even a single contributing route is
    re-announced.

    Steps:
      1. Announce 3 contributing routes from M0, add aggregate.
      2. Verify aggregate received on M2.
      3. Withdraw all 3 contributing routes.
      4. Verify aggregate withdrawn from M2.
      5. Re-announce one contributing route.
      6. Verify aggregate re-appears on M2.
      7. Cleanup.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = route_propagation_setup
    agg_prefix = AGGR_GRP3_V4
    contributing = CONTRIBUTING_V4  # all three /24 routes

    cfg = AggregateCfg(prefix=agg_prefix, bbr_required=False, summary_only=False, as_set=False)

    try:
        # Steps 1-2
        _inject_routes(setup, ptfhost, contributing, "announce")
        gcu_add_aggregate(duthost, cfg)
        verify_route_on_m2(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)

        # Steps 3-4: withdraw ALL contributors
        _inject_routes(setup, ptfhost, contributing, "withdraw")
        verify_route_on_m2(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=False)

        # Steps 5-6: re-announce a single contributor
        _inject_routes(setup, ptfhost, contributing[:1], "announce")
        verify_route_on_m2(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)
    finally:
        _inject_routes(setup, ptfhost, contributing, "withdraw")
        try:
            gcu_remove_aggregate(duthost, agg_prefix)
        except Exception:
            logger.warning(f"Cleanup: failed to remove aggregate {agg_prefix}, will be recovered by rollback")


# ===========================================================================
# Test Case 3.3 — Partial contributing route withdrawal
# ===========================================================================

def test_aggregate_partial_contributing_withdrawal(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, route_propagation_setup
):
    """
    TC 3.3: Aggregate STAYS present on M2 when only a subset of contributing
    routes is withdrawn (at least one contributing route remains active).

    Steps:
      1. Announce contributing routes from two simulated sources (set-A and set-B).
      2. Add aggregate, verify received on M2.
      3. Withdraw set-A only.
      4. Verify aggregate is still present on M2 (set-B still active).
      5. Cleanup: withdraw set-B, remove aggregate.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = route_propagation_setup
    agg_prefix = AGGR_GRP3_V4
    # Two logical "sets" representing different M0 sources
    set_a = CONTRIBUTING_V4[:2]    # 10.100.1.0/24, 10.100.2.0/24
    set_b = CONTRIBUTING_V4[2:]    # 10.100.3.0/24

    cfg = AggregateCfg(prefix=agg_prefix, bbr_required=False, summary_only=False, as_set=False)

    try:
        # Steps 1-2
        _inject_routes(setup, ptfhost, set_a + set_b, "announce")
        gcu_add_aggregate(duthost, cfg)
        verify_route_on_m2(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)

        # Step 3: partial withdrawal
        _inject_routes(setup, ptfhost, set_a, "withdraw")

        # Step 4: aggregate must remain — set_b is still active
        verify_route_on_m2(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)
    finally:
        _inject_routes(setup, ptfhost, set_a + set_b, "withdraw")
        try:
            gcu_remove_aggregate(duthost, agg_prefix)
        except Exception:
            logger.warning(f"Cleanup: failed to remove aggregate {agg_prefix}, will be recovered by rollback")


# ===========================================================================
# Test Case 3.4 — New contributing route added dynamically
# ===========================================================================

def test_aggregate_new_contributing_route_added(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, route_propagation_setup
):
    """
    TC 3.4: Dynamically adding a new contributing route does not disturb the
    aggregate.  With summary-only=false, the new contributing route is also
    visible on M2 alongside the aggregate.

    Steps:
      1. Start with one contributing route, add aggregate.
      2. Verify aggregate received on M2.
      3. Announce a second contributing route.
      4. Verify aggregate still present on M2.
      5. Verify the new contributing route is also visible on M2 (not suppressed).
      6. Cleanup.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = route_propagation_setup
    agg_prefix = AGGR_GRP3_V4
    initial_contributing = CONTRIBUTING_V4[:1]   # 10.100.1.0/24
    new_contributing = CONTRIBUTING_V4[1:2]      # 10.100.2.0/24

    cfg = AggregateCfg(prefix=agg_prefix, bbr_required=False, summary_only=False, as_set=False)

    try:
        # Steps 1-2
        _inject_routes(setup, ptfhost, initial_contributing, "announce")
        gcu_add_aggregate(duthost, cfg)
        verify_route_on_m2(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)

        # Step 3
        _inject_routes(setup, ptfhost, new_contributing, "announce")

        # Step 4: aggregate still present
        verify_route_on_m2(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)

        # Step 5: new contributing route visible (summary-only=false → not suppressed)
        verify_route_on_m2(nbrhosts, setup["m2_neighbors"], new_contributing[0], expected_present=True)
    finally:
        _inject_routes(setup, ptfhost, initial_contributing + new_contributing, "withdraw")
        try:
            gcu_remove_aggregate(duthost, agg_prefix)
        except Exception:
            logger.warning(f"Cleanup: failed to remove aggregate {agg_prefix}, will be recovered by rollback")
