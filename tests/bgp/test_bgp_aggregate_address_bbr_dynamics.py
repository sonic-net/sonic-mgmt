"""
Test Group 2: BGP Aggregate Address — BBR Feature State Interaction

Validates dynamic BBR state changes correctly activate/deactivate aggregate
addresses, observable via route presence on M2 (upstream) neighbors.
The feature is treated as a black box and verified through its observable
routing behavior.

Test cases:
  2.1  BBR enable activates BBR-required aggregate
  2.2  BBR disable deactivates BBR-required aggregate
  2.3  BBR toggle does NOT affect non-BBR-required aggregate
  2.4  Mixed BBR-required and non-BBR-required aggregates
  2.5  Rapid BBR state toggling
"""

import time

import pytest

from bgp_bbr_helpers import config_bbr_by_gcu, get_bbr_default_state

from bgp_aggregate_helpers import (  # noqa: F401
    AGGR_V4_1,
    BGP_SETTLE_WAIT,
    CONTRIBUTING_V4,
    CONTRIBUTING_V4_SECOND,
    EXTRA_AGGR_V4_1,
    ROUTE_PROPAGATION_WAIT,
    AggregateCfg,
    announce_contributing_routes,
    gcu_add_aggregate,
    gcu_remove_aggregate,
    setup_teardown,  # noqa: F401
    verify_bgp_aggregate_cleanup,
    verify_bgp_aggregate_consistence,
    verify_route_on_m2,
    withdraw_contributing_routes,
)

pytestmark = [
    pytest.mark.topology("m1"),
]


class TestGroup2BBRStateInteraction:
    """Test Group 2: BBR Feature State Interaction.

    Tests dynamic BBR enable/disable after aggregate addresses are already
    configured, verifying route appearance/disappearance on M2 neighbors
    and DUT internal state consistency.
    """

    def _skip_if_no_bbr(self, duthost):
        bbr_supported, _ = get_bbr_default_state(duthost)
        if not bbr_supported:
            pytest.skip("BGP BBR is not supported")

    def test_2_1_bbr_enable_activates_bbr_required_aggregate(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 2.1: BBR enable activates BBR-required aggregate.

        Steps:
        1. Disable BBR on DUT
        2. Announce contributing routes from M0
        3. Add aggregate with bbr-required=true
        4. Verify DUT state inactive, aggregate NOT received on M2
        5. Enable BBR on DUT via GCU
        6. Verify DUT state active, aggregate now received on M2
        """
        duthost = duthosts[rand_one_dut_hostname]
        self._skip_if_no_bbr(duthost)
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']
        cfg = AggregateCfg(prefix=AGGR_V4_1, bbr_required=True, summary_only=False, as_set=False)

        config_bbr_by_gcu(duthost, "disabled")
        announce_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
        try:
            gcu_add_aggregate(duthost, cfg)

            # BBR disabled: aggregate inactive
            verify_bgp_aggregate_consistence(duthost, False, cfg)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=False)

            # Enable BBR
            config_bbr_by_gcu(duthost, "enabled")
            time.sleep(BGP_SETTLE_WAIT)

            # BBR enabled: aggregate active
            verify_bgp_aggregate_consistence(duthost, True, cfg)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=True)

            gcu_remove_aggregate(duthost, cfg.prefix)
            verify_bgp_aggregate_cleanup(duthost, cfg.prefix)
        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
            config_bbr_by_gcu(duthost, "enabled")

    def test_2_2_bbr_disable_deactivates_bbr_required_aggregate(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 2.2: BBR disable deactivates BBR-required aggregate.

        Steps:
        1. Enable BBR, add aggregate with bbr-required=true
        2. Verify aggregate active and received on M2
        3. Disable BBR via GCU
        4. Verify aggregate inactive and withdrawn on M2
        """
        duthost = duthosts[rand_one_dut_hostname]
        self._skip_if_no_bbr(duthost)
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']
        cfg = AggregateCfg(prefix=AGGR_V4_1, bbr_required=True, summary_only=False, as_set=False)

        config_bbr_by_gcu(duthost, "enabled")
        announce_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
        try:
            gcu_add_aggregate(duthost, cfg)

            verify_bgp_aggregate_consistence(duthost, True, cfg)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=True)

            # Disable BBR
            config_bbr_by_gcu(duthost, "disabled")
            time.sleep(BGP_SETTLE_WAIT)

            verify_bgp_aggregate_consistence(duthost, False, cfg)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=False)

            gcu_remove_aggregate(duthost, cfg.prefix)
            verify_bgp_aggregate_cleanup(duthost, cfg.prefix)
        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
            config_bbr_by_gcu(duthost, "enabled")

    def test_2_3_bbr_toggle_does_not_affect_non_bbr_required(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 2.3: BBR toggle does NOT affect non-BBR-required aggregate.

        Steps:
        1. Add aggregate with bbr-required=false, verify received on M2
        2. Toggle BBR: enabled -> disabled -> enabled
        3. Verify aggregate route remains received and DUT state stays active throughout
        """
        duthost = duthosts[rand_one_dut_hostname]
        self._skip_if_no_bbr(duthost)
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']
        cfg = AggregateCfg(prefix=AGGR_V4_1, bbr_required=False, summary_only=False, as_set=False)

        announce_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
        try:
            gcu_add_aggregate(duthost, cfg)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=True)

            # Toggle: enabled -> disabled -> enabled
            config_bbr_by_gcu(duthost, "enabled")
            time.sleep(BGP_SETTLE_WAIT)
            verify_bgp_aggregate_consistence(duthost, True, cfg)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=True)

            config_bbr_by_gcu(duthost, "disabled")
            time.sleep(BGP_SETTLE_WAIT)
            verify_bgp_aggregate_consistence(duthost, False, cfg)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=True)

            config_bbr_by_gcu(duthost, "enabled")
            time.sleep(BGP_SETTLE_WAIT)
            verify_bgp_aggregate_consistence(duthost, True, cfg)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=True)

            gcu_remove_aggregate(duthost, cfg.prefix)
            verify_bgp_aggregate_cleanup(duthost, cfg.prefix)
        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")

    def test_2_4_mixed_bbr_required_and_non_bbr_required(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 2.4: Mixed BBR-required and non-BBR-required aggregates.

        Steps:
        1. Add aggregate A (bbr-required=true) and B (bbr-required=false)
        2. With BBR enabled: both received on M2
        3. Disable BBR: A withdrawn, B still received
        4. Enable BBR: both received again
        """
        duthost = duthosts[rand_one_dut_hostname]
        self._skip_if_no_bbr(duthost)
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']
        cfg_a = AggregateCfg(prefix=AGGR_V4_1, bbr_required=True, summary_only=False, as_set=False)
        cfg_b = AggregateCfg(prefix=EXTRA_AGGR_V4_1, bbr_required=False, summary_only=False, as_set=False)

        config_bbr_by_gcu(duthost, "enabled")
        announce_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
        announce_contributing_routes(setup, CONTRIBUTING_V4_SECOND, "ipv4")
        try:
            gcu_add_aggregate(duthost, cfg_a)
            gcu_add_aggregate(duthost, cfg_b)

            # Both received with BBR enabled
            verify_bgp_aggregate_consistence(duthost, True, cfg_a)
            verify_bgp_aggregate_consistence(duthost, True, cfg_b)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=True)
            verify_route_on_m2(nbrhosts, upstream, EXTRA_AGGR_V4_1, expected_present=True)

            # Disable BBR: A withdrawn, B still received
            config_bbr_by_gcu(duthost, "disabled")
            time.sleep(BGP_SETTLE_WAIT)
            verify_bgp_aggregate_consistence(duthost, False, cfg_a)
            verify_bgp_aggregate_consistence(duthost, False, cfg_b)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=False)
            verify_route_on_m2(nbrhosts, upstream, EXTRA_AGGR_V4_1, expected_present=True)

            # Enable BBR: both received again
            config_bbr_by_gcu(duthost, "enabled")
            time.sleep(BGP_SETTLE_WAIT)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=True)
            verify_route_on_m2(nbrhosts, upstream, EXTRA_AGGR_V4_1, expected_present=True)

            gcu_remove_aggregate(duthost, cfg_a.prefix)
            gcu_remove_aggregate(duthost, cfg_b.prefix)
            verify_bgp_aggregate_cleanup(duthost, cfg_a.prefix)
            verify_bgp_aggregate_cleanup(duthost, cfg_b.prefix)
        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
            withdraw_contributing_routes(setup, CONTRIBUTING_V4_SECOND, "ipv4")

    def test_2_5_rapid_bbr_state_toggling(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 2.5: Rapid BBR state toggling.

        Steps:
        1. Add bbr-required aggregate, announce contributing routes from M0
        2. Rapidly toggle BBR (enable -> disable -> enable) with minimal delay
        3. After settling, verify final route state and DUT consistency
        """
        duthost = duthosts[rand_one_dut_hostname]
        self._skip_if_no_bbr(duthost)
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']
        cfg = AggregateCfg(prefix=AGGR_V4_1, bbr_required=True, summary_only=False, as_set=False)

        config_bbr_by_gcu(duthost, "enabled")
        announce_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
        try:
            gcu_add_aggregate(duthost, cfg)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=True)

            # Rapid toggles
            config_bbr_by_gcu(duthost, "disabled")
            config_bbr_by_gcu(duthost, "enabled")
            config_bbr_by_gcu(duthost, "disabled")
            config_bbr_by_gcu(duthost, "enabled")

            # After settling, aggregates should be received (final state: enabled)
            time.sleep(ROUTE_PROPAGATION_WAIT)
            verify_bgp_aggregate_consistence(duthost, True, cfg)
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4_1, expected_present=True)

            gcu_remove_aggregate(duthost, cfg.prefix)
            verify_bgp_aggregate_cleanup(duthost, cfg.prefix)
        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
