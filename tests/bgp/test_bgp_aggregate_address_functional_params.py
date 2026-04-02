"""
Test Group 1: BGP Aggregate Address — Parameter Combination Matrix

Validates aggregate address with all parameter combinations by verifying
route advertisement to M2 (upstream) neighbors. The feature is treated as
a black box and verified through its observable routing behavior.

Contributing routes are injected from M0 (downstream) via ExaBGP.

Test cases:
  1.1  Basic aggregate (summary-only=false, bbr-required=false)
  1.2  Summary-only aggregate
  1.3  BBR-required with BBR enabled
  1.4  BBR-required with BBR disabled (aggregate inactive)
  1.5  BBR-required + summary-only with BBR disabled
  1.6  BBR-required + summary-only with BBR enabled
  1.7  IPv6 basic aggregate
  1.8  IPv6 summary-only aggregate
"""

import logging

import pytest

from bgp_bbr_helpers import config_bbr_by_gcu, get_bbr_default_state, is_bbr_enabled

from bgp_aggregate_helpers import (  # noqa: F401
    AGGR_V4_1,
    AGGR_V6,
    CONTRIBUTING_V4,
    CONTRIBUTING_V6,
    AggregateCfg,
    announce_contributing_routes,
    gcu_add_aggregate,
    gcu_remove_aggregate,
    setup_teardown,  # noqa: F401
    verify_bgp_aggregate_cleanup,
    verify_bgp_aggregate_consistence,
    verify_contributing_routes_on_m2,
    verify_route_on_m2,
    withdraw_contributing_routes,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("m1"),
]


class TestGroup1ParameterCombination:
    """Test Group 1: Parameter Combination Matrix.

    Contributing routes are injected from M0 via ExaBGP, aggregate addresses
    are configured on DUT via GCU, and route presence is verified on M2
    upstream neighbors together with DUT internal state.
    """

    def test_1_1_basic_aggregate_summary_only_false(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 1.1: Basic aggregate — summary-only=false, bbr-required=false.

        Config: bbr-required=false, summary-only=false, as-set=false
        Verify: aggregate route received on M2, contributing routes also received (not suppressed).
        After removal: aggregate disappears, contributing routes still received.
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']
        cfg = AggregateCfg(prefix=AGGR_V4_1, bbr_required=False, summary_only=False, as_set=False)

        announce_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
        try:
            gcu_add_aggregate(duthost, cfg)

            # DUT-side validation
            bbr_enabled = is_bbr_enabled(duthost)
            verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg)

            # M2 route validation
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=True)
            verify_contributing_routes_on_m2(nbrhosts, upstream, CONTRIBUTING_V4[:2], expected_present=True)

            # Remove aggregate
            gcu_remove_aggregate(duthost, cfg.prefix)

            verify_bgp_aggregate_cleanup(duthost, cfg.prefix)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=False)
            verify_contributing_routes_on_m2(nbrhosts, upstream, CONTRIBUTING_V4[:2], expected_present=True)
        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")

    def test_1_2_summary_only_aggregate(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 1.2: Summary-only aggregate.

        Config: bbr-required=false, summary-only=true, as-set=false
        Verify: aggregate route received on M2, contributing routes suppressed (NOT received).
        After removal: contributing routes become visible again.
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']
        cfg = AggregateCfg(prefix=AGGR_V4_1, bbr_required=False, summary_only=True, as_set=False)

        announce_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
        try:
            gcu_add_aggregate(duthost, cfg)

            bbr_enabled = is_bbr_enabled(duthost)
            verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg)

            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=True)
            verify_contributing_routes_on_m2(nbrhosts, upstream, CONTRIBUTING_V4[:2], expected_present=False)

            gcu_remove_aggregate(duthost, cfg.prefix)

            verify_bgp_aggregate_cleanup(duthost, cfg.prefix)
            verify_contributing_routes_on_m2(nbrhosts, upstream, CONTRIBUTING_V4[:2], expected_present=True)
        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")

    def test_1_3_bbr_required_with_bbr_enabled(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 1.3: BBR-required with BBR enabled.

        Config: bbr-required=true, summary-only=false, as-set=false, BBR enabled
        Verify: aggregate route received on M2 (BBR satisfied -> aggregate active).
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']

        bbr_supported, _ = get_bbr_default_state(duthost)
        if not bbr_supported:
            pytest.skip("BGP BBR is not supported")

        _, bbr_original_state = get_bbr_default_state(duthost)
        config_bbr_by_gcu(duthost, "enabled")
        cfg = AggregateCfg(prefix=AGGR_V4_1, bbr_required=True, summary_only=False, as_set=False)

        announce_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
        try:
            gcu_add_aggregate(duthost, cfg)

            verify_bgp_aggregate_consistence(duthost, True, cfg)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=True)

            gcu_remove_aggregate(duthost, cfg.prefix)
            verify_bgp_aggregate_cleanup(duthost, cfg.prefix)
        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
            config_bbr_by_gcu(duthost, bbr_original_state)

    def test_1_4_bbr_required_with_bbr_disabled(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 1.4: BBR-required with BBR disabled.

        Config: bbr-required=true, summary-only=false, as-set=false, BBR disabled
        Verify: aggregate route NOT received on M2 (BBR not satisfied -> aggregate inactive).
        Contributing routes still received.
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']

        bbr_supported, bbr_original_state = get_bbr_default_state(duthost)
        if not bbr_supported:
            pytest.skip("BGP BBR is not supported")

        config_bbr_by_gcu(duthost, "disabled")
        cfg = AggregateCfg(prefix=AGGR_V4_1, bbr_required=True, summary_only=False, as_set=False)

        announce_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
        try:
            gcu_add_aggregate(duthost, cfg)

            verify_bgp_aggregate_consistence(duthost, False, cfg)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=False)
            verify_contributing_routes_on_m2(nbrhosts, upstream, CONTRIBUTING_V4[:2], expected_present=True)

            gcu_remove_aggregate(duthost, cfg.prefix)
            verify_bgp_aggregate_cleanup(duthost, cfg.prefix)
        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
            config_bbr_by_gcu(duthost, bbr_original_state)

    def test_1_5_bbr_required_summary_only_bbr_disabled(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 1.5: BBR-required + summary-only with BBR disabled.

        Config: bbr-required=true, summary-only=true, as-set=false, BBR disabled
        Verify: aggregate route NOT received on M2.
        Contributing routes ARE received (not suppressed since aggregate is inactive).
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']

        bbr_supported, bbr_original_state = get_bbr_default_state(duthost)
        if not bbr_supported:
            pytest.skip("BGP BBR is not supported")

        config_bbr_by_gcu(duthost, "disabled")
        cfg = AggregateCfg(prefix=AGGR_V4_1, bbr_required=True, summary_only=True, as_set=False)

        announce_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
        try:
            gcu_add_aggregate(duthost, cfg)

            verify_bgp_aggregate_consistence(duthost, False, cfg)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=False)
            verify_contributing_routes_on_m2(nbrhosts, upstream, CONTRIBUTING_V4[:2], expected_present=True)

            gcu_remove_aggregate(duthost, cfg.prefix)
            verify_bgp_aggregate_cleanup(duthost, cfg.prefix)
        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
            config_bbr_by_gcu(duthost, bbr_original_state)

    def test_1_6_bbr_required_summary_only_bbr_enabled(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 1.6: BBR-required + summary-only with BBR enabled.

        Config: bbr-required=true, summary-only=true, as-set=false, BBR enabled
        Verify: aggregate route received on M2, contributing routes suppressed (not received).
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']

        bbr_supported, _ = get_bbr_default_state(duthost)
        if not bbr_supported:
            pytest.skip("BGP BBR is not supported")

        _, bbr_original_state = get_bbr_default_state(duthost)
        config_bbr_by_gcu(duthost, "enabled")
        cfg = AggregateCfg(prefix=AGGR_V4_1, bbr_required=True, summary_only=True, as_set=False)

        announce_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
        try:
            gcu_add_aggregate(duthost, cfg)

            verify_bgp_aggregate_consistence(duthost, True, cfg)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=True)
            verify_contributing_routes_on_m2(nbrhosts, upstream, CONTRIBUTING_V4[:2], expected_present=False)

            gcu_remove_aggregate(duthost, cfg.prefix)
            verify_bgp_aggregate_cleanup(duthost, cfg.prefix)
        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
            config_bbr_by_gcu(duthost, bbr_original_state)

    def test_1_7_ipv6_basic_aggregate(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 1.7: IPv6 — basic aggregate.

        Config: IPv6, bbr-required=false, summary-only=false, as-set=false
        Verify: IPv6 aggregate route received on M2, contributing routes also received.
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']
        cfg = AggregateCfg(prefix=AGGR_V6, bbr_required=False, summary_only=False, as_set=False)

        announce_contributing_routes(setup, CONTRIBUTING_V6, "ipv6")
        try:
            gcu_add_aggregate(duthost, cfg)

            bbr_enabled = is_bbr_enabled(duthost)
            verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg)

            verify_route_on_m2(nbrhosts, upstream, AGGR_V6, expected_present=True)
            verify_contributing_routes_on_m2(nbrhosts, upstream, CONTRIBUTING_V6[:2], expected_present=True)

            gcu_remove_aggregate(duthost, cfg.prefix)
            verify_bgp_aggregate_cleanup(duthost, cfg.prefix)
        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V6, "ipv6")

    def test_1_8_ipv6_summary_only_aggregate(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 1.8: IPv6 — summary-only aggregate.

        Config: IPv6, bbr-required=false, summary-only=true, as-set=false
        Verify: IPv6 aggregate received on M2, contributing routes suppressed.
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']
        cfg = AggregateCfg(prefix=AGGR_V6, bbr_required=False, summary_only=True, as_set=False)

        announce_contributing_routes(setup, CONTRIBUTING_V6, "ipv6")
        try:
            gcu_add_aggregate(duthost, cfg)

            bbr_enabled = is_bbr_enabled(duthost)
            verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg)

            verify_route_on_m2(nbrhosts, upstream, AGGR_V6, expected_present=True)
            verify_contributing_routes_on_m2(nbrhosts, upstream, CONTRIBUTING_V6[:2], expected_present=False)

            gcu_remove_aggregate(duthost, cfg.prefix)
            verify_bgp_aggregate_cleanup(duthost, cfg.prefix)
        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V6, "ipv6")
