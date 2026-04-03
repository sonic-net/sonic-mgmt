"""
Tests for BGP aggregate-address dual-stack concurrent operation.

Test Group 9: Dual-Stack Concurrent Operation
  Validates that IPv4 and IPv6 aggregate addresses work simultaneously,
  including correct behavior when BBR state changes affect one or both
  address families.

Aligned with: https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/BGP-Aggregate-Address.md
"""

import logging

import pytest
from natsort import natsorted

# Shared helpers from the aggregate-address helper module
from bgp_aggregate_helpers import (
    AggregateCfg,
    BGP_AGGREGATE_ADDRESS,
    PLACEHOLDER_PREFIX,
    dump_db,
    gcu_add_placeholder_aggregate,
    running_bgp_has_aggregate,
    safe_remove_aggregate,
    verify_bgp_aggregate_cleanup,
)

from bgp_bbr_helpers import config_bbr_by_gcu, get_bbr_default_state

from tests.common.gcu_utils import apply_gcu_patch, create_checkpoint, rollback_or_reload, delete_checkpoint
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.bgp_routing import inject_routes
from tests.common.helpers.constants import DOWNSTREAM_NEIGHBOR_MAP
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("m1"),
    pytest.mark.disable_loganalyzer,
]

# ---------------------------------------------------------------------------
# Constants — Test Group 9
# ---------------------------------------------------------------------------

# Aggregate prefixes and contributing routes per the test plan.
AGGR_GRP9_V4 = "10.100.0.0/16"
AGGR_GRP9_V6 = "2001:db8:100::/48"

# Contributing routes (more-specifics of the aggregate)
CONTRIBUTING_V4 = ["10.100.1.0/24", "10.100.2.0/24", "10.100.3.0/24"]
CONTRIBUTING_V6 = ["2001:db8:100:1::/64", "2001:db8:100:2::/64", "2001:db8:100:3::/64"]

# ExaBGP base ports (downstream PTF ports)
EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000

# Timeout for route convergence checks (seconds).
ROUTE_CHECK_TIMEOUT = 120


# ===========================================================================
# DUT-based aggregate route verification via BGP table
# ===========================================================================

def _aggregate_in_bgp_table(duthost, prefix):
    """Return True if the aggregate prefix is in the DUT's BGP table."""
    is_v4 = "." in prefix
    cmd = 'vtysh -c "show ip bgp {}"'.format(prefix) if is_v4 \
        else 'vtysh -c "show bgp ipv6 {}"'.format(prefix)
    result = duthost.shell(cmd, module_ignore_errors=True)
    stdout = result.get("stdout", "")
    return "BGP routing table entry" in stdout and "Network not in table" not in stdout


def verify_aggregate_present(duthost, prefix, timeout=ROUTE_CHECK_TIMEOUT):
    """Poll the DUT's BGP table until the aggregate route appears."""
    ok = wait_until(timeout, 3, 0, _aggregate_in_bgp_table, duthost, prefix)
    pytest_assert(ok, "Aggregate route {} not present in DUT BGP table after {}s".format(prefix, timeout))


def verify_aggregate_absent(duthost, prefix, timeout=ROUTE_CHECK_TIMEOUT):
    """Poll the DUT's BGP table until the aggregate route disappears."""
    ok = wait_until(timeout, 3, 0, lambda d, p: not _aggregate_in_bgp_table(d, p), duthost, prefix)
    pytest_assert(ok, "Aggregate route {} still present in DUT BGP table after {}s".format(prefix, timeout))


def verify_aggregate_active(duthost, cfg, timeout=60):
    """Verify an aggregate is active: present in CONFIG_DB and in FRR running-config.

    Polls FRR running-config with timeout to handle bgpcfgd processing delay.
    """
    config_db = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(cfg.prefix in config_db, "Aggregate {} not in CONFIG_DB".format(cfg.prefix))

    def _in_frr(dut, prefix):
        return prefix in running_bgp_has_aggregate(dut, prefix)

    ok = wait_until(timeout, 3, 0, _in_frr, duthost, cfg.prefix)
    pytest_assert(ok, "aggregate-address {} not in FRR running-config after {}s".format(cfg.prefix, timeout))


def verify_aggregate_inactive(duthost, cfg, timeout=60):
    """Verify an aggregate is inactive: present in CONFIG_DB but NOT in FRR running-config.

    Polls FRR running-config with timeout to handle bgpcfgd processing delay.
    """
    config_db = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(cfg.prefix in config_db, "Aggregate {} not in CONFIG_DB".format(cfg.prefix))

    def _not_in_frr(dut, prefix):
        return prefix not in running_bgp_has_aggregate(dut, prefix)

    ok = wait_until(timeout, 3, 0, _not_in_frr, duthost, cfg.prefix)
    pytest_assert(ok,
                  "aggregate-address {} should not be in FRR running-config when inactive (waited {}s)".format(
                      cfg.prefix, timeout))


# ===========================================================================
# Module-scoped setup/teardown with feature gate
# ===========================================================================

@pytest.fixture(scope="module", autouse=True)
def setup_teardown(duthosts, rand_one_dut_hostname):
    """Checkpoint config, verify BGP_AGGREGATE_ADDRESS support, and rollback after tests."""
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)

    # bgpcfgd's AggregateAddressMgr always reads BGP_BBR status when
    # processing aggregate-address entries, even for bbr_required=false.
    # Ensure BGP_BBR exists so bgpcfgd does not crash with KeyError.
    bbr_exists = int(duthost.shell(
        'redis-cli -n 4 HEXISTS "BGP_BBR|all" "status"',
        module_ignore_errors=True,
    )["stdout"])
    if not bbr_exists:
        config_bbr_by_gcu(duthost, "disabled")

    # Verify the DUT supports BGP_AGGREGATE_ADDRESS by attempting to add a probe entry.
    try:
        default_aggregates = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
        if not default_aggregates:
            gcu_add_placeholder_aggregate(duthost, PLACEHOLDER_PREFIX)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        logger.warning("BGP_AGGREGATE_ADDRESS not supported on this DUT: %s", e)
        delete_checkpoint(duthost)
        pytest.skip("BGP_AGGREGATE_ADDRESS not supported in CONFIG_DB schema on this DUT")

    yield

    try:
        rollback_or_reload(duthost, fail_on_rollback_error=False)
    finally:
        delete_checkpoint(duthost)


# ===========================================================================
# Route injection fixture — discover M0 neighbors and ExaBGP ports
# ===========================================================================

@pytest.fixture(scope="module")
def route_injection_setup(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo):
    """
    Discover downstream (M0) neighbor and ExaBGP ports for route injection.
    """
    topo_type = tbinfo["topo"]["type"]
    downstream_suffix = DOWNSTREAM_NEIGHBOR_MAP[topo_type].upper()

    downstream_neighbors = natsorted(
        [n for n in nbrhosts if n.upper().endswith(downstream_suffix)]
    )
    pytest_assert(downstream_neighbors, "No downstream ({}) neighbors found in nbrhosts".format(downstream_suffix))
    m0 = downstream_neighbors[0]

    m0_offset = tbinfo["topo"]["properties"]["topology"]["VMs"][m0]["vm_offset"]
    m0_exabgp_port = EXABGP_BASE_PORT + m0_offset
    m0_exabgp_port_v6 = EXABGP_BASE_PORT_V6 + m0_offset

    common_cfg = tbinfo["topo"]["properties"]["configuration_properties"]["common"]
    nhipv4 = common_cfg.get("nhipv4")
    nhipv6 = common_cfg.get("nhipv6")

    yield {
        "m0": m0,
        "m0_exabgp_port": m0_exabgp_port,
        "m0_exabgp_port_v6": m0_exabgp_port_v6,
        "nhipv4": nhipv4,
        "nhipv6": nhipv6,
    }


# ===========================================================================
# GCU helpers — dual-stack single-patch operations
# ===========================================================================

def gcu_add_dual_aggregate(duthost, cfg_v4, cfg_v6):
    """Add IPv4 and IPv6 aggregate-address entries in a single GCU JSON patch."""
    logger.info("Add dual-stack BGP_AGGREGATE_ADDRESS by GCU cmd (single patch)")
    patch = [
        {
            "op": "add",
            "path": "/BGP_AGGREGATE_ADDRESS/{}".format(cfg_v4.prefix.replace("/", "~1")),
            "value": {
                "bbr-required": "true" if cfg_v4.bbr_required else "false",
                "summary-only": "true" if cfg_v4.summary_only else "false",
                "as-set": "true" if cfg_v4.as_set else "false",
            },
        },
        {
            "op": "add",
            "path": "/BGP_AGGREGATE_ADDRESS/{}".format(cfg_v6.prefix.replace("/", "~1")),
            "value": {
                "bbr-required": "true" if cfg_v6.bbr_required else "false",
                "summary-only": "true" if cfg_v6.summary_only else "false",
                "as-set": "true" if cfg_v6.as_set else "false",
            },
        },
    ]
    apply_gcu_patch(duthost, patch)


def gcu_remove_dual_aggregate(duthost, prefix_v4, prefix_v6):
    """Remove IPv4 and IPv6 aggregate-address entries in a single GCU JSON patch."""
    logger.info("Remove dual-stack BGP_AGGREGATE_ADDRESS by GCU cmd (single patch)")
    patch = [
        {"op": "remove", "path": "/BGP_AGGREGATE_ADDRESS/{}".format(prefix_v4.replace("/", "~1"))},
        {"op": "remove", "path": "/BGP_AGGREGATE_ADDRESS/{}".format(prefix_v6.replace("/", "~1"))},
    ]
    apply_gcu_patch(duthost, patch)


# ===========================================================================
# Test Case 9.1 — Simultaneous IPv4 and IPv6 aggregates
# ===========================================================================

def test_dual_stack_simultaneous_aggregates(
    duthosts, rand_one_dut_hostname, ptfhost, route_injection_setup
):
    """
    TC 9.1: IPv4 and IPv6 aggregate addresses configured and active at the
    same time via a single GCU patch.

    Steps:
      1. Add IPv4 aggregate and IPv6 aggregate in a single GCU patch.
      2. Announce contributing routes for both families from M0 via ExaBGP.
      3. Verify IPv4 aggregate route generated in DUT BGP table.
      4. Verify IPv6 aggregate route generated in DUT BGP table.
      5. Remove both aggregates via GCU.
      6. Verify aggregate addresses cleaned up from CONFIG_DB, STATE_DB, and FRR.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = route_injection_setup
    agg_v4 = AGGR_GRP9_V4
    agg_v6 = AGGR_GRP9_V6

    cfg_v4 = AggregateCfg(prefix=agg_v4, bbr_required=False, summary_only=False, as_set=False)
    cfg_v6 = AggregateCfg(prefix=agg_v6, bbr_required=False, summary_only=False, as_set=False)

    try:
        # Step 1: add both aggregates in a single GCU patch
        gcu_add_dual_aggregate(duthost, cfg_v4, cfg_v6)

        # Wait for bgpcfgd to push aggregate-address config to FRR
        verify_aggregate_active(duthost, cfg_v4)
        verify_aggregate_active(duthost, cfg_v6)

        # Step 2: announce contributing routes for both families from M0 via ExaBGP
        inject_routes(setup, ptfhost, CONTRIBUTING_V4, "announce")
        inject_routes(setup, ptfhost, CONTRIBUTING_V6, "announce")

        # Steps 3-4: verify both aggregate routes generated in DUT BGP table
        verify_aggregate_present(duthost, agg_v4)
        verify_aggregate_present(duthost, agg_v6)

        # Step 5: withdraw contributing routes then remove aggregate config
        inject_routes(setup, ptfhost, CONTRIBUTING_V4 + CONTRIBUTING_V6, "withdraw")
        gcu_remove_dual_aggregate(duthost, agg_v4, agg_v6)

        # Step 6: verify aggregate addresses cleaned up
        verify_bgp_aggregate_cleanup(duthost, agg_v4)
        verify_bgp_aggregate_cleanup(duthost, agg_v6)
    finally:
        inject_routes(setup, ptfhost, CONTRIBUTING_V4 + CONTRIBUTING_V6, "withdraw")
        for prefix in (agg_v4, agg_v6):
            safe_remove_aggregate(duthost, prefix)


# ===========================================================================
# Test Case 9.2 — BBR toggle with dual-stack
# ===========================================================================

def test_dual_stack_bbr_toggle(
    duthosts, rand_one_dut_hostname, ptfhost, route_injection_setup
):
    """
    TC 9.2: Both IPv4 and IPv6 BBR-required aggregates respond correctly to
    BBR state changes — withdrawn when BBR is disabled, re-appear when
    BBR is re-enabled.

    Steps:
      1. Ensure BBR is enabled.
      2. Add IPv4 and IPv6 aggregates with bbr-required=true in a single GCU patch.
      3. Inject contributing routes for both families from M0 via ExaBGP.
      4. Verify both aggregate routes present in DUT BGP table.
      5. Disable BBR.
      6. Verify both aggregate routes absent from DUT BGP table.
      7. Re-enable BBR.
      8. Verify both aggregate routes present again in DUT BGP table.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = route_injection_setup
    agg_v4 = AGGR_GRP9_V4
    agg_v6 = AGGR_GRP9_V6

    bbr_supported, bbr_default_state = get_bbr_default_state(duthost)
    if not bbr_supported:
        pytest.skip("BGP BBR is not supported")

    cfg_v4 = AggregateCfg(prefix=agg_v4, bbr_required=True, summary_only=False, as_set=False)
    cfg_v6 = AggregateCfg(prefix=agg_v6, bbr_required=True, summary_only=False, as_set=False)

    try:
        # Step 1: ensure BBR is enabled
        config_bbr_by_gcu(duthost, "enabled")

        # Step 2: add both aggregates with bbr-required=true in a single GCU patch
        gcu_add_dual_aggregate(duthost, cfg_v4, cfg_v6)

        # Wait for bgpcfgd to push aggregate-address config to FRR
        verify_aggregate_active(duthost, cfg_v4)
        verify_aggregate_active(duthost, cfg_v6)

        # Step 3: inject contributing routes for both families from M0 via ExaBGP
        inject_routes(setup, ptfhost, CONTRIBUTING_V4, "announce")
        inject_routes(setup, ptfhost, CONTRIBUTING_V6, "announce")

        # Step 4: verify both aggregate routes present
        verify_aggregate_present(duthost, agg_v4)
        verify_aggregate_present(duthost, agg_v6)

        # Step 5: disable BBR
        config_bbr_by_gcu(duthost, "disabled")

        # Step 6: verify both aggregates became inactive (CONFIG_DB present, FRR absent)
        verify_aggregate_inactive(duthost, cfg_v4)
        verify_aggregate_inactive(duthost, cfg_v6)

        # Step 7: re-enable BBR
        config_bbr_by_gcu(duthost, "enabled")

        # Step 8: verify both aggregates became active again
        verify_aggregate_active(duthost, cfg_v4)
        verify_aggregate_active(duthost, cfg_v6)
        verify_aggregate_present(duthost, agg_v4)
        verify_aggregate_present(duthost, agg_v6)
    finally:
        inject_routes(setup, ptfhost, CONTRIBUTING_V4 + CONTRIBUTING_V6, "withdraw")
        for prefix in (agg_v4, agg_v6):
            safe_remove_aggregate(duthost, prefix)
        try:
            config_bbr_by_gcu(duthost, bbr_default_state)
        except Exception:
            logger.warning("Cleanup: failed to restore BBR state, will be recovered by rollback")


# ===========================================================================
# Test Case 9.3 — Mixed BBR-required across address families
# ===========================================================================

def test_dual_stack_mixed_bbr_required(
    duthosts, rand_one_dut_hostname, ptfhost, route_injection_setup
):
    """
    TC 9.3: IPv4 aggregate with bbr-required=true and IPv6 aggregate with
    bbr-required=false.  When BBR is disabled, only the IPv4 aggregate is
    withdrawn; the IPv6 aggregate remains active.

    Steps:
      1. Ensure BBR is enabled.
      2. Add IPv4 aggregate (bbr-required=true), IPv6 aggregate (bbr-required=false)
         in a single GCU patch.
      3. Inject contributing routes for both families from M0 via ExaBGP.
      4. Verify both aggregate routes present in DUT BGP table.
      5. Disable BBR.
      6. Verify IPv4 aggregate absent (bbr-required=true, BBR off).
      7. Verify IPv6 aggregate still present (bbr-required=false).
      8. Enable BBR.
      9. Verify both aggregate routes present.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = route_injection_setup
    agg_v4 = AGGR_GRP9_V4
    agg_v6 = AGGR_GRP9_V6

    bbr_supported, bbr_default_state = get_bbr_default_state(duthost)
    if not bbr_supported:
        pytest.skip("BGP BBR is not supported")

    cfg_v4 = AggregateCfg(prefix=agg_v4, bbr_required=True, summary_only=False, as_set=False)
    cfg_v6 = AggregateCfg(prefix=agg_v6, bbr_required=False, summary_only=False, as_set=False)

    try:
        # Step 1: ensure BBR is enabled
        config_bbr_by_gcu(duthost, "enabled")

        # Step 2: add both aggregates in a single GCU patch
        gcu_add_dual_aggregate(duthost, cfg_v4, cfg_v6)

        # Wait for bgpcfgd to push aggregate-address config to FRR
        verify_aggregate_active(duthost, cfg_v4)
        verify_aggregate_active(duthost, cfg_v6)

        # Step 3: inject contributing routes for both families from M0 via ExaBGP
        inject_routes(setup, ptfhost, CONTRIBUTING_V4, "announce")
        inject_routes(setup, ptfhost, CONTRIBUTING_V6, "announce")

        # Step 4: verify both aggregate routes present
        verify_aggregate_present(duthost, agg_v4)
        verify_aggregate_present(duthost, agg_v6)

        # Step 5: disable BBR
        config_bbr_by_gcu(duthost, "disabled")

        # Step 6: verify IPv4 aggregate inactive (bbr-required=true, BBR off)
        verify_aggregate_inactive(duthost, cfg_v4)

        # Step 7: verify IPv6 aggregate still active (bbr-required=false, unaffected)
        verify_aggregate_active(duthost, cfg_v6)
        verify_aggregate_present(duthost, agg_v6)

        # Step 8: enable BBR
        config_bbr_by_gcu(duthost, "enabled")

        # Step 9: verify both aggregates active again
        verify_aggregate_active(duthost, cfg_v4)
        verify_aggregate_active(duthost, cfg_v6)
        verify_aggregate_present(duthost, agg_v4)
        verify_aggregate_present(duthost, agg_v6)
    finally:
        inject_routes(setup, ptfhost, CONTRIBUTING_V4 + CONTRIBUTING_V6, "withdraw")
        for prefix in (agg_v4, agg_v6):
            safe_remove_aggregate(duthost, prefix)
        try:
            config_bbr_by_gcu(duthost, bbr_default_state)
        except Exception:
            logger.warning("Cleanup: failed to restore BBR state, will be recovered by rollback")
