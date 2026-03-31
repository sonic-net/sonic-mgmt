"""
Tests for BGP aggregate-address CRUD (add / remove / update) operations.

Test Group 4: Aggregate Address Lifecycle Operations
  Validates that add, remove, and update operations via GCU produce the
  expected route-advertisement changes observable on upstream (M2) neighbors.

Aligned with: https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/BGP-Aggregate-Address.md
"""

import logging

import pytest
from natsort import natsorted

from bgp_aggregate_helpers import (  # noqa: F401
    AggregateCfg,
    gcu_add_aggregate,
    gcu_remove_aggregate,
    gcu_add_multiple_aggregates,
    gcu_remove_multiple_aggregates,
    gcu_update_aggregate_field,
    safe_remove_aggregate,
    setup_teardown,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.bgp_routing import inject_routes, verify_route_on_neighbors
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP, DOWNSTREAM_NEIGHBOR_MAP

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("m1"), pytest.mark.device_type("vs"), pytest.mark.disable_loganalyzer]

EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000

# --- Test data ---
AGGR_V4 = "10.100.0.0/16"
AGGR_V6 = "2001:db8:100::/48"
CONTRIBUTING_V4 = ["10.100.1.0/24", "10.100.2.0/24", "10.100.3.0/24"]
CONTRIBUTING_V6 = ["2001:db8:100:1::/64", "2001:db8:100:2::/64", "2001:db8:100:3::/64"]

# Additional aggregates for multi-aggregate / overlapping tests
EXTRA_AGGR_V4_1 = "10.200.0.0/16"
EXTRA_AGGR_V4_2 = "10.150.0.0/16"
EXTRA_AGGR_V6_1 = "2001:db8:200::/48"
EXTRA_AGGR_V6_2 = "2001:db8:150::/48"
CONTRIBUTING_EXTRA_V4_1 = ["10.200.1.0/24"]
CONTRIBUTING_EXTRA_V4_2 = ["10.150.1.0/24"]
CONTRIBUTING_EXTRA_V6_1 = ["2001:db8:200:1::/64"]
CONTRIBUTING_EXTRA_V6_2 = ["2001:db8:150:1::/64"]


@pytest.fixture(scope="module")
def crud_setup(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo):
    """Discover downstream/upstream neighbors and ExaBGP ports."""
    topo_type = tbinfo["topo"]["type"]
    downstream_suffix = DOWNSTREAM_NEIGHBOR_MAP[topo_type].upper()
    upstream_suffix = UPSTREAM_NEIGHBOR_MAP[topo_type].upper()

    downstream_neighbors = natsorted(
        [n for n in nbrhosts if n.upper().endswith(downstream_suffix)]
    )
    pytest_assert(downstream_neighbors, f"No downstream ({downstream_suffix}) neighbors found")
    m0 = downstream_neighbors[0]

    upstream_neighbors = natsorted(
        [n for n in nbrhosts if n.upper().endswith(upstream_suffix)]
    )
    pytest_assert(upstream_neighbors, f"No upstream ({upstream_suffix}) neighbors found")

    m0_offset = tbinfo["topo"]["properties"]["topology"]["VMs"][m0]["vm_offset"]

    common_cfg = tbinfo["topo"]["properties"]["configuration_properties"]["common"]

    yield {
        "m0": m0,
        "m2_neighbors": upstream_neighbors,
        "m0_exabgp_port": EXABGP_BASE_PORT + m0_offset,
        "m0_exabgp_port_v6": EXABGP_BASE_PORT_V6 + m0_offset,
        "nhipv4": common_cfg.get("nhipv4"),
        "nhipv6": common_cfg.get("nhipv6"),
    }


# ===========================================================================
# TC 4.1 — Add and remove single aggregate
# ===========================================================================
def test_add_and_remove_single_aggregate(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, crud_setup
):
    """
    TC 4.1: Add a single aggregate via GCU → verify it is received on M2.
    Remove it → verify it is withdrawn on M2.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = crud_setup
    cfg = AggregateCfg(prefix=AGGR_V4, bbr_required=False, summary_only=False, as_set=False)

    try:
        inject_routes(setup, ptfhost, CONTRIBUTING_V4[:2], "announce")
        gcu_add_aggregate(duthost, cfg)

        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], AGGR_V4, expected_present=True)

        gcu_remove_aggregate(duthost, AGGR_V4)

        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], AGGR_V4, expected_present=False)
    finally:
        inject_routes(setup, ptfhost, CONTRIBUTING_V4[:2], "withdraw")
        safe_remove_aggregate(duthost, AGGR_V4)


# ===========================================================================
# TC 4.2 — Remove aggregate restores contributing route visibility
# ===========================================================================
def test_remove_aggregate_restores_contributing(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, crud_setup
):
    """
    TC 4.2: With summary-only=true, contributing routes are suppressed on M2.
    After removing the aggregate, contributing routes must reappear on M2.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = crud_setup
    contributing = CONTRIBUTING_V4[:2]
    cfg = AggregateCfg(prefix=AGGR_V4, bbr_required=False, summary_only=True, as_set=False)

    try:
        inject_routes(setup, ptfhost, contributing, "announce")
        gcu_add_aggregate(duthost, cfg)

        # Aggregate present, contributing suppressed
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], AGGR_V4, expected_present=True)
        for route in contributing:
            verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], route, expected_present=False, timeout=15)

        # Remove aggregate
        gcu_remove_aggregate(duthost, AGGR_V4)

        # Contributing routes must reappear
        for route in contributing:
            verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], route, expected_present=True)
    finally:
        inject_routes(setup, ptfhost, contributing, "withdraw")
        safe_remove_aggregate(duthost, AGGR_V4)


# ===========================================================================
# TC 4.3 — Update aggregate parameters: toggle summary-only
# ===========================================================================
def test_update_toggle_summary_only(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, crud_setup
):
    """
    TC 4.3: Start with summary-only=false (contributing visible), update to
    summary-only=true (contributing suppressed), then back to false (visible
    again).
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = crud_setup
    contributing = CONTRIBUTING_V4[:2]
    cfg = AggregateCfg(prefix=AGGR_V4, bbr_required=False, summary_only=False, as_set=False)

    try:
        inject_routes(setup, ptfhost, contributing, "announce")
        gcu_add_aggregate(duthost, cfg)

        # Step 1-2: both aggregate and contributing visible
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], AGGR_V4, expected_present=True)
        for route in contributing:
            verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], route, expected_present=True)

        # Step 3: update to summary-only=true
        gcu_update_aggregate_field(duthost, AGGR_V4, "summary-only", "true")

        # Step 4: contributing now suppressed
        for route in contributing:
            verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], route, expected_present=False, timeout=15)

        # Step 5: update back to summary-only=false
        gcu_update_aggregate_field(duthost, AGGR_V4, "summary-only", "false")

        # Step 6: contributing visible again
        for route in contributing:
            verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], route, expected_present=True)
    finally:
        inject_routes(setup, ptfhost, contributing, "withdraw")
        safe_remove_aggregate(duthost, AGGR_V4)


# ===========================================================================
# TC 4.4 — Add multiple aggregates in single GCU patch
# ===========================================================================
def test_add_multiple_aggregates_single_patch(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, crud_setup
):
    """
    TC 4.4: Apply a single GCU patch that adds 5 aggregate addresses (mix of
    IPv4 & IPv6).  Verify all are received on M2.  Remove all in one patch,
    verify all withdrawn.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = crud_setup

    cfgs = [
        AggregateCfg(prefix=AGGR_V4, bbr_required=False, summary_only=False, as_set=False),
        AggregateCfg(prefix=EXTRA_AGGR_V4_1, bbr_required=False, summary_only=False, as_set=False),
        AggregateCfg(prefix=EXTRA_AGGR_V4_2, bbr_required=False, summary_only=False, as_set=False),
        AggregateCfg(prefix=AGGR_V6, bbr_required=False, summary_only=False, as_set=False),
        AggregateCfg(prefix=EXTRA_AGGR_V6_1, bbr_required=False, summary_only=False, as_set=False),
    ]
    all_prefixes = [c.prefix for c in cfgs]
    all_contributing = (
        CONTRIBUTING_V4[:1]
        + CONTRIBUTING_EXTRA_V4_1
        + CONTRIBUTING_EXTRA_V4_2
        + CONTRIBUTING_V6[:1]
        + CONTRIBUTING_EXTRA_V6_1
    )

    try:
        inject_routes(setup, ptfhost, all_contributing, "announce")
        gcu_add_multiple_aggregates(duthost, cfgs)

        for prefix in all_prefixes:
            verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], prefix, expected_present=True)

        gcu_remove_multiple_aggregates(duthost, all_prefixes)

        for prefix in all_prefixes:
            verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], prefix, expected_present=False, timeout=15)
    finally:
        inject_routes(setup, ptfhost, all_contributing, "withdraw")
        for prefix in all_prefixes:
            safe_remove_aggregate(duthost, prefix)


# ===========================================================================
# TC 4.5 — Sequential add/remove of independent aggregates
# ===========================================================================
def test_overlapping_aggregates_sequential(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, crud_setup
):
    """
    TC 4.5: Add two independent aggregates sequentially, each with its own
    contributing routes.  Both should be received on M2.  Removing the first
    must leave the second intact.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = crud_setup
    contributing_a = CONTRIBUTING_V4[:2]
    contributing_b = CONTRIBUTING_EXTRA_V4_1

    cfg_a = AggregateCfg(prefix=AGGR_V4, bbr_required=False, summary_only=False, as_set=False)
    cfg_b = AggregateCfg(prefix=EXTRA_AGGR_V4_1, bbr_required=False, summary_only=False, as_set=False)

    try:
        inject_routes(setup, ptfhost, contributing_a + contributing_b, "announce")

        # Step 1: add first aggregate
        gcu_add_aggregate(duthost, cfg_a)
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], AGGR_V4, expected_present=True)

        # Step 2: add second aggregate
        gcu_add_aggregate(duthost, cfg_b)
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], EXTRA_AGGR_V4_1, expected_present=True)

        # Step 3: both present
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], AGGR_V4, expected_present=True)

        # Step 4: remove first aggregate
        gcu_remove_aggregate(duthost, AGGR_V4)
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], AGGR_V4, expected_present=False, timeout=15)

        # Step 5: second still present
        verify_route_on_neighbors(nbrhosts, setup["m2_neighbors"], EXTRA_AGGR_V4_1, expected_present=True)
    finally:
        inject_routes(setup, ptfhost, contributing_a + contributing_b, "withdraw")
        for prefix in (AGGR_V4, EXTRA_AGGR_V4_1):
            safe_remove_aggregate(duthost, prefix)
