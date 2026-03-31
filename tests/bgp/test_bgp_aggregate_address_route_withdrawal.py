"""
Tests for BGP aggregate-address route withdrawal behavior.

Test Group 3: Route Presence and Withdrawal Behavior
  Validates that the aggregate route on upstream neighbors depends on the
  presence of contributing routes injected from downstream neighbors via ExaBGP,
  and that route withdrawal converges correctly.

Aligned with: https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/BGP-Aggregate-Address.md
"""

import logging

import pytest
from natsort import natsorted

# Shared helpers from the aggregate-address helpers module
from bgp_aggregate_helpers import (  # noqa: F401
    AggregateCfg,
    gcu_add_aggregate,
    safe_remove_aggregate,
    setup_teardown,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.bgp_routing import inject_routes, verify_route_on_neighbors
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP, DOWNSTREAM_NEIGHBOR_MAP

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("m1"), pytest.mark.device_type("vs"), pytest.mark.disable_loganalyzer]

# ExaBGP base ports (downstream PTF ports)
EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000

# IPv4 /16 aggregate with three /24 contributing routes exercises the full lifecycle.
AGGR_GRP3_V4 = "10.100.0.0/16"
CONTRIBUTING_V4 = ["10.100.1.0/24", "10.100.2.0/24", "10.100.3.0/24"]


@pytest.fixture(scope="module")
def route_propagation_setup(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo):
    """
    Discover downstream (M0/T0) and upstream (MA/T2) neighbors and ExaBGP ports
    for route propagation tests.
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
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=False, timeout=15)

        # Step 3: inject a contributing route
        inject_routes(setup, ptfhost, contributing, "announce")

        # Step 4: aggregate must now appear on M2
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)
    finally:
        inject_routes(setup, ptfhost, contributing, "withdraw")
        safe_remove_aggregate(duthost, agg_prefix)


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
        inject_routes(setup, ptfhost, contributing, "announce")
        gcu_add_aggregate(duthost, cfg)
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)

        # Steps 3-4: withdraw ALL contributors
        inject_routes(setup, ptfhost, contributing, "withdraw")
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=False)

        # Steps 5-6: re-announce a single contributor
        inject_routes(setup, ptfhost, contributing[:1], "announce")
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)
    finally:
        inject_routes(setup, ptfhost, contributing, "withdraw")
        safe_remove_aggregate(duthost, agg_prefix)


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
        inject_routes(setup, ptfhost, set_a + set_b, "announce")
        gcu_add_aggregate(duthost, cfg)
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)

        # Step 3: partial withdrawal
        inject_routes(setup, ptfhost, set_a, "withdraw")

        # Step 4: aggregate must remain — set_b is still active
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)
    finally:
        inject_routes(setup, ptfhost, set_a + set_b, "withdraw")
        safe_remove_aggregate(duthost, agg_prefix)


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
        inject_routes(setup, ptfhost, initial_contributing, "announce")
        gcu_add_aggregate(duthost, cfg)
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)

        # Step 3
        inject_routes(setup, ptfhost, new_contributing, "announce")

        # Step 4: aggregate still present
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], agg_prefix, expected_present=True)

        # Step 5: new contributing route visible (summary-only=false → not suppressed)
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], new_contributing[0], expected_present=True)
    finally:
        inject_routes(setup, ptfhost, initial_contributing + new_contributing, "withdraw")
        safe_remove_aggregate(duthost, agg_prefix)
