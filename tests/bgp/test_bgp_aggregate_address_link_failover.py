"""
Tests for BGP aggregate-address link failover behavior.

Test Group 6: Link Flapping and Convergence
  Validates that the aggregate route on upstream (M2) neighbors correctly
  reflects the availability of contributing routes when DUT interfaces to
  downstream (M0) neighbors are shut down or flapped.

Aligned with: https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/BGP-Aggregate-Address.md
"""

import logging
from collections import defaultdict

import pytest
from natsort import natsorted

# Shared helpers from the aggregate-address helper module
from bgp_aggregate_helpers import (
    BGP_AGGREGATE_ADDRESS,
    PLACEHOLDER_PREFIX,
    AggregateCfg,
    dump_db,
    gcu_add_aggregate,
    gcu_add_placeholder_aggregate,
    gcu_remove_aggregate,
)

from tests.common.gcu_utils import create_checkpoint, rollback_or_reload, delete_checkpoint
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.bgp_routing import inject_routes, verify_route_on_neighbors
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP, DOWNSTREAM_NEIGHBOR_MAP
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("m1"),
    pytest.mark.disable_loganalyzer,
]

# Aggregate prefix for Group 6 tests
AGGR_GRP6_V4 = "10.100.0.0/16"

# Contributing /24 routes (spread across M0 neighbors)
CONTRIBUTING_V4 = ["10.100.1.0/24", "10.100.2.0/24", "10.100.3.0/24"]

# ExaBGP base ports
EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000

# Timeouts and polling intervals
BGP_SESSION_WAIT_TIMEOUT = 300
BGP_SESSION_POLL_INTERVAL = 10
INTF_STATE_WAIT_TIMEOUT = 90


@pytest.fixture(scope="module", autouse=True)
def setup_teardown(duthost):
    """Checkpoint before tests, rollback after.

    Link-failover tests shut down and restore DUT interfaces, which can leave
    stale BGP aggregate state if a test fails mid-way.  The checkpoint/rollback
    ensures CONFIG_DB is restored to a clean state regardless of test outcome.
    """
    create_checkpoint(duthost)
    default_aggregates = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    if not default_aggregates:
        gcu_add_placeholder_aggregate(duthost, PLACEHOLDER_PREFIX)
    yield
    try:
        rollback_or_reload(duthost, fail_on_rollback_error=False)
    finally:
        delete_checkpoint(duthost)


# ===========================================================================
# Module-scoped fixture: link_failover_setup
# ===========================================================================

@pytest.fixture(scope="module")
def link_failover_setup(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo):
    """
    Discover downstream (M0) and upstream (M2) neighbors, resolve DUT-side
    interfaces connected to downstream neighbors, and prepare ExaBGP port
    mappings for per-M0 route injection.

    Yields a dict with:
      - m0_neighbors: sorted list of downstream neighbor names
      - m2_neighbors: sorted list of upstream neighbor names
      - m0_interfaces: {m0_name: [dut_intf, ...]}
      - m0_exabgp_ports: {m0_name: port}
      - m0_exabgp_ports_v6: {m0_name: port_v6}
      - nhipv4, nhipv6: next-hop addresses for ExaBGP
    """
    duthost = duthosts[rand_one_dut_hostname]
    topo_type = tbinfo["topo"]["type"]
    downstream_suffix = DOWNSTREAM_NEIGHBOR_MAP[topo_type].upper()
    upstream_suffix = UPSTREAM_NEIGHBOR_MAP[topo_type].upper()

    # Partition nbrhosts into downstream (M0) and upstream (M2)
    downstream_neighbors = natsorted(
        [n for n in nbrhosts if n.upper().endswith(downstream_suffix)]
    )
    pytest_assert(downstream_neighbors, f"No downstream ({downstream_suffix}) neighbors found")

    upstream_neighbors = natsorted(
        [n for n in nbrhosts if n.upper().endswith(upstream_suffix)]
    )
    pytest_assert(upstream_neighbors, f"No upstream ({upstream_suffix}) neighbors found")

    # Build DUT interface mapping per downstream neighbor from DEVICE_NEIGHBOR
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    device_neighbor = cfg_facts.get("DEVICE_NEIGHBOR", {})
    m0_interfaces = defaultdict(list)
    for dut_intf, nbr_info in device_neighbor.items():
        nbr_name = nbr_info.get("name", "")
        if nbr_name in downstream_neighbors:
            m0_interfaces[nbr_name].append(dut_intf)
    for name in m0_interfaces:
        m0_interfaces[name] = natsorted(m0_interfaces[name])

    # Compute ExaBGP ports per downstream neighbor
    vm_topo = tbinfo["topo"]["properties"]["topology"]["VMs"]
    m0_exabgp_ports = {}
    m0_exabgp_ports_v6 = {}
    for m0 in downstream_neighbors:
        offset = vm_topo[m0]["vm_offset"]
        m0_exabgp_ports[m0] = EXABGP_BASE_PORT + offset
        m0_exabgp_ports_v6[m0] = EXABGP_BASE_PORT_V6 + offset

    common_cfg = tbinfo["topo"]["properties"]["configuration_properties"]["common"]
    nhipv4 = common_cfg.get("nhipv4")
    nhipv6 = common_cfg.get("nhipv6")

    # Track which interfaces were shut down for safety-net cleanup
    shutdown_intfs = set()

    setup_data = {
        "m0_neighbors": downstream_neighbors,
        "m2_neighbors": upstream_neighbors,
        "m0_interfaces": dict(m0_interfaces),
        "m0_exabgp_ports": m0_exabgp_ports,
        "m0_exabgp_ports_v6": m0_exabgp_ports_v6,
        "nhipv4": nhipv4,
        "nhipv6": nhipv6,
        "_shutdown_intfs": shutdown_intfs,
    }

    yield setup_data

    # Teardown: restore all interfaces that might still be shut down
    for intf in list(shutdown_intfs):
        try:
            duthost.no_shutdown(intf)
            logger.info("Teardown: restored interface %s", intf)
        except Exception as e:
            logger.warning("Teardown: failed to restore %s: %s", intf, e)

    if shutdown_intfs:
        # Wait for all BGP sessions to recover after interface restore
        def _all_bgp_up():
            for ip in list(bgp_neighbors.keys()):
                try:
                    nbinfo = duthost.get_bgp_neighbor_info(ip)
                    if not nbinfo or nbinfo.get("bgpState", "").lower() != "established":
                        return False
                except Exception:
                    return False
            return True

        bgp_neighbors = cfg_facts.get("BGP_NEIGHBOR", {})
        if bgp_neighbors:
            wait_until(BGP_SESSION_WAIT_TIMEOUT, BGP_SESSION_POLL_INTERVAL, 0, _all_bgp_up)


# ===========================================================================
# Helper Functions
# ===========================================================================

def shutdown_m0_interfaces(duthost, setup, m0_name):
    """Shut down all DUT-side interfaces connected to a specific downstream neighbor.

    Waits until all interfaces report oper-status down.
    """
    intfs = setup["m0_interfaces"][m0_name]
    for intf in intfs:
        duthost.shutdown(intf)
        setup["_shutdown_intfs"].add(intf)
    logger.info("Shut down interfaces to %s: %s", m0_name, intfs)

    def _check_intfs_down():
        for intf in intfs:
            output = duthost.shell(
                "show interfaces status {} | tail -1".format(intf),
                module_ignore_errors=True
            )["stdout"].strip()
            if output and "down" not in output.lower():
                return False
        return True

    wait_until(INTF_STATE_WAIT_TIMEOUT, 5, 2, _check_intfs_down)


def startup_m0_interfaces(duthost, setup, m0_name):
    """Bring up all DUT-side interfaces connected to a specific downstream neighbor.

    Waits until all interfaces report oper-status up.
    """
    intfs = setup["m0_interfaces"][m0_name]
    for intf in intfs:
        duthost.no_shutdown(intf)
        setup["_shutdown_intfs"].discard(intf)
    logger.info("Brought up interfaces to %s: %s", m0_name, intfs)

    def _check_intfs_up():
        for intf in intfs:
            output = duthost.shell(
                "show interfaces status {} | tail -1".format(intf),
                module_ignore_errors=True
            )["stdout"].strip()
            if output and "up" not in output.lower():
                return False
        return True

    wait_until(INTF_STATE_WAIT_TIMEOUT, 5, 2, _check_intfs_up)


def wait_for_bgp_to_neighbor(duthost, m0_name, setup, timeout=BGP_SESSION_WAIT_TIMEOUT):
    """Poll until the BGP session(s) to a specific downstream neighbor reach Established.

    Resolves neighbor IPs from BGP_NEIGHBOR config filtered by the M0 name.
    Uses direct ``get_bgp_neighbor_info`` polling rather than
    ``check_bgp_session_state`` to avoid the neigh_desc mismatch issue.
    """
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    bgp_neighbors = cfg_facts.get("BGP_NEIGHBOR", {})
    m0_ips = [ip for ip, info in bgp_neighbors.items() if info.get("name") == m0_name]
    pytest_assert(m0_ips, f"No BGP neighbor IPs found for {m0_name}")
    logger.info("Waiting for BGP sessions to %s (IPs: %s)", m0_name, m0_ips)

    def _all_sessions_established():
        for ip in m0_ips:
            try:
                nbinfo = duthost.get_bgp_neighbor_info(ip)
                state = nbinfo.get("bgpState", "").lower() if nbinfo else ""
                if state != "established":
                    logger.debug("BGP to %s (%s): state=%s", m0_name, ip, state)
                    return False
            except Exception as e:
                logger.debug("BGP check failed for %s: %s", ip, e)
                return False
        return True

    ok = wait_until(timeout, BGP_SESSION_POLL_INTERVAL, 0, _all_sessions_established)
    pytest_assert(ok, f"BGP sessions to {m0_name} ({m0_ips}) not established after {timeout}s")


def inject_routes_via_m0(setup, ptfhost, m0_name, prefixes, action):
    """Inject/withdraw routes via ExaBGP through a specific M0 neighbor.

    Constructs a per-M0 setup dict with the correct ExaBGP ports so that the
    shared ``inject_routes`` helper targets the right downstream neighbor.
    """
    local_setup = {
        "nhipv4": setup["nhipv4"],
        "nhipv6": setup["nhipv6"],
        "m0_exabgp_port": setup["m0_exabgp_ports"][m0_name],
        "m0_exabgp_port_v6": setup["m0_exabgp_ports_v6"][m0_name],
    }
    inject_routes(local_setup, ptfhost, prefixes, action)


# ===========================================================================
# Test Case 6.1 — Shutdown interface to one M0 — partial contributing route loss
# ===========================================================================

def test_aggregate_partial_link_loss(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, link_failover_setup
):
    """
    TC 6.1: Aggregate route STAYS present on M2 when one of multiple M0
    neighbors loses connectivity, as long as another M0 still provides
    contributing routes.

    Steps:
      1. Inject contributing routes from two M0 neighbors (M0-1 and M0-2).
      2. Add aggregate (summary-only=false), verify aggregate on M2.
      3. Shutdown DUT interfaces to M0-1.
      4. Verify aggregate still present on M2 (M0-2 contributing routes remain).
      5. Verify M0-1 contributing routes withdrawn from M2.
      6. Verify M0-2 contributing routes still present on M2.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = link_failover_setup

    if len(setup["m0_neighbors"]) < 2:
        pytest.skip("TC 6.1 requires at least 2 downstream M0 neighbors")

    m0_1 = setup["m0_neighbors"][0]
    m0_2 = setup["m0_neighbors"][1]
    agg_prefix = AGGR_GRP6_V4
    m0_1_routes = CONTRIBUTING_V4[:2]   # 10.100.1.0/24, 10.100.2.0/24
    m0_2_routes = CONTRIBUTING_V4[2:]   # 10.100.3.0/24

    cfg = AggregateCfg(prefix=agg_prefix, bbr_required=False, summary_only=False, as_set=False)

    try:
        # Step 1: inject from both M0s
        inject_routes_via_m0(setup, ptfhost, m0_1, m0_1_routes, "announce")
        inject_routes_via_m0(setup, ptfhost, m0_2, m0_2_routes, "announce")

        # Step 2: add aggregate, verify on M2
        gcu_add_aggregate(duthost, cfg)
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)

        # Step 3: shutdown M0-1
        shutdown_m0_interfaces(duthost, setup, m0_1)

        # Step 4: aggregate still present (M0-2 routes remain)
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)

        # Step 5: M0-1 routes withdrawn
        for route in m0_1_routes:
            verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], route, expected_present=False)

        # Step 6: M0-2 routes still present
        for route in m0_2_routes:
            verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], route, expected_present=True)
    finally:
        inject_routes_via_m0(setup, ptfhost, m0_1, m0_1_routes, "withdraw")
        inject_routes_via_m0(setup, ptfhost, m0_2, m0_2_routes, "withdraw")
        startup_m0_interfaces(duthost, setup, m0_1)
        wait_for_bgp_to_neighbor(duthost, m0_1, setup)
        try:
            gcu_remove_aggregate(duthost, agg_prefix)
        except Exception:
            logger.warning("Cleanup: failed to remove aggregate %s", agg_prefix)


# ===========================================================================
# Test Case 6.2 — Shutdown and restore interface — full recovery
# ===========================================================================

def test_aggregate_link_shutdown_and_restore(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, link_failover_setup
):
    """
    TC 6.2: After shutting down and restoring a M0 link, the aggregate route
    and all contributing routes fully recover on M2.

    Steps:
      1. Inject contributing routes from two M0 neighbors.
      2. Add aggregate (summary-only=false), verify on M2.
      3. Shutdown M0-1 interfaces — verify partial state.
      4. Bring M0-1 interfaces back up, wait for BGP session.
      5. Verify full recovery: all contributing routes and aggregate on M2.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = link_failover_setup

    if len(setup["m0_neighbors"]) < 2:
        pytest.skip("TC 6.2 requires at least 2 downstream M0 neighbors")

    m0_1 = setup["m0_neighbors"][0]
    m0_2 = setup["m0_neighbors"][1]
    agg_prefix = AGGR_GRP6_V4
    m0_1_routes = CONTRIBUTING_V4[:2]
    m0_2_routes = CONTRIBUTING_V4[2:]

    cfg = AggregateCfg(prefix=agg_prefix, bbr_required=False, summary_only=False, as_set=False)

    try:
        # Steps 1-2: inject routes, add aggregate, verify
        inject_routes_via_m0(setup, ptfhost, m0_1, m0_1_routes, "announce")
        inject_routes_via_m0(setup, ptfhost, m0_2, m0_2_routes, "announce")
        gcu_add_aggregate(duthost, cfg)
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)

        # Step 3: shutdown M0-1, verify partial state
        shutdown_m0_interfaces(duthost, setup, m0_1)
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)
        for route in m0_1_routes:
            verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], route, expected_present=False)
        for route in m0_2_routes:
            verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], route, expected_present=True)

        # Step 4: restore M0-1, wait for BGP
        startup_m0_interfaces(duthost, setup, m0_1)
        wait_for_bgp_to_neighbor(duthost, m0_1, setup)

        # Step 5: full recovery — all routes present
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)
        for route in m0_1_routes:
            verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], route, expected_present=True)
        for route in m0_2_routes:
            verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], route, expected_present=True)
    finally:
        inject_routes_via_m0(setup, ptfhost, m0_1, m0_1_routes, "withdraw")
        inject_routes_via_m0(setup, ptfhost, m0_2, m0_2_routes, "withdraw")
        startup_m0_interfaces(duthost, setup, m0_1)
        wait_for_bgp_to_neighbor(duthost, m0_1, setup)
        try:
            gcu_remove_aggregate(duthost, agg_prefix)
        except Exception:
            logger.warning("Cleanup: failed to remove aggregate %s", agg_prefix)


# ===========================================================================
# Test Case 6.3 — All contributing routes lost via link shutdown
# ===========================================================================

def test_aggregate_all_links_lost(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, link_failover_setup
):
    """
    TC 6.3: Aggregate route DISAPPEARS from M2 when all contributing routes
    are lost via link shutdown, and RE-APPEARS after the link is restored.

    Steps:
      1. Inject contributing routes from one M0 neighbor only.
      2. Add aggregate, verify received on M2.
      3. Shutdown M0 interfaces — aggregate disappears from M2.
      4. Bring M0 interfaces back up, wait for BGP — aggregate re-appears.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = link_failover_setup
    m0_1 = setup["m0_neighbors"][0]
    agg_prefix = AGGR_GRP6_V4
    contributing = CONTRIBUTING_V4

    cfg = AggregateCfg(prefix=agg_prefix, bbr_required=False, summary_only=False, as_set=False)

    try:
        # Steps 1-2
        inject_routes_via_m0(setup, ptfhost, m0_1, contributing, "announce")
        gcu_add_aggregate(duthost, cfg)
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)

        # Step 3: all links lost — aggregate disappears
        shutdown_m0_interfaces(duthost, setup, m0_1)
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=False)

        # Step 4: restore — aggregate re-appears
        startup_m0_interfaces(duthost, setup, m0_1)
        wait_for_bgp_to_neighbor(duthost, m0_1, setup)
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)
    finally:
        inject_routes_via_m0(setup, ptfhost, m0_1, contributing, "withdraw")
        startup_m0_interfaces(duthost, setup, m0_1)
        wait_for_bgp_to_neighbor(duthost, m0_1, setup)
        try:
            gcu_remove_aggregate(duthost, agg_prefix)
        except Exception:
            logger.warning("Cleanup: failed to remove aggregate %s", agg_prefix)


# ===========================================================================
# Test Case 6.4 — Link flap with summary-only — no transient contributing route leak
# ===========================================================================

def test_aggregate_link_flap_summary_only_no_leak(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, link_failover_setup
):
    """
    TC 6.4: With summary-only=true, a link flap does not cause contributing
    routes to transiently leak to M2 during reconvergence.

    Steps:
      1. Inject contributing routes from M0.
      2. Add aggregate with summary-only=true.
      3. Verify: aggregate present on M2, contributing routes NOT present.
      4. Flap: shutdown M0 interfaces, wait briefly, bring them back up.
      5. Wait for BGP session to M0 to re-establish.
      6. After recovery: aggregate present, contributing routes still suppressed.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = link_failover_setup
    m0_1 = setup["m0_neighbors"][0]
    agg_prefix = AGGR_GRP6_V4
    contributing = CONTRIBUTING_V4

    cfg = AggregateCfg(prefix=agg_prefix, bbr_required=False, summary_only=True, as_set=False)

    try:
        # Steps 1-2
        inject_routes_via_m0(setup, ptfhost, m0_1, contributing, "announce")
        gcu_add_aggregate(duthost, cfg)

        # Step 3: aggregate present, contributing routes suppressed
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)
        for route in contributing:
            verify_route_on_neighbors(
                nbrhosts, setup["m2_neighbors"], route, expected_present=False, timeout=15
            )

        # Step 4: flap — shutdown then startup
        shutdown_m0_interfaces(duthost, setup, m0_1)
        startup_m0_interfaces(duthost, setup, m0_1)

        # Step 5: wait for BGP re-establishment
        wait_for_bgp_to_neighbor(duthost, m0_1, setup)

        # Step 6: after recovery — aggregate present, contributing still suppressed
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)
        for route in contributing:
            verify_route_on_neighbors(
                nbrhosts, setup["m2_neighbors"], route, expected_present=False, timeout=15
            )
    finally:
        inject_routes_via_m0(setup, ptfhost, m0_1, contributing, "withdraw")
        startup_m0_interfaces(duthost, setup, m0_1)
        wait_for_bgp_to_neighbor(duthost, m0_1, setup)
        try:
            gcu_remove_aggregate(duthost, agg_prefix)
        except Exception:
            logger.warning("Cleanup: failed to remove aggregate %s", agg_prefix)
