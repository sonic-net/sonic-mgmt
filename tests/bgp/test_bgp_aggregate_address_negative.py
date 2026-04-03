"""
Tests for BGP aggregate-address negative and boundary conditions.

Test Group 8: Negative and Boundary Tests
  Validates error handling for invalid inputs, duplicate/update semantics,
  removal of non-existent aggregates, aggregates with no matching
  contributing routes, and overlapping aggregate prefixes.

Aligned with:
  https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/
  BGP-Aggregate-Address.md
"""

import logging
import time

import pytest
from natsort import natsorted

from bgp_aggregate_helpers import (
    AggregateCfg,
    BGP_AGGREGATE_ADDRESS,
    PLACEHOLDER_PREFIX,
    dump_db,
    gcu_add_aggregate,
    gcu_add_placeholder_aggregate,
    gcu_remove_aggregate,
    safe_remove_aggregate,
)

from tests.common.gcu_utils import (
    apply_patch,
    generate_tmpfile,
    delete_tmpfile,
    create_checkpoint,
    rollback_or_reload,
    delete_checkpoint,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.bgp_routing import (
    inject_routes,
    verify_route_on_neighbors,
)
from tests.common.helpers.constants import (
    UPSTREAM_NEIGHBOR_MAP,
    DOWNSTREAM_NEIGHBOR_MAP,
)

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("m1")]

# ExaBGP base ports
EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000

# --- Test data ---
AGGR_V4 = "10.100.0.0/16"
CONTRIBUTING_V4 = [
    "10.100.1.0/24",
    "10.100.2.0/24",
    "10.100.3.0/24",
]
# Routes that fall *outside* the aggregate range
NON_CONTRIBUTING_V4 = ["10.200.1.0/24"]

# Nested aggregate for the overlapping test — contained within AGGR_V4
AGGR_EXTRA_V4 = "10.100.1.0/24"
CONTRIBUTING_EXTRA_V4 = ["10.100.1.0/25", "10.100.1.128/25"]


@pytest.fixture(scope="module", autouse=True)
def setup_teardown(duthosts, rand_one_dut_hostname):
    """Create checkpoint before tests, rollback after."""
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)

    # Add placeholder aggregate to avoid GCU removing empty table
    default_aggregates = dump_db(
        duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS
    )
    if not default_aggregates:
        gcu_add_placeholder_aggregate(duthost, PLACEHOLDER_PREFIX)

    yield

    try:
        rollback_or_reload(duthost, fail_on_rollback_error=False)
    finally:
        delete_checkpoint(duthost)


@pytest.fixture(scope="module")
def negative_setup(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo):
    """Discover downstream / upstream neighbors and ExaBGP ports."""
    topo_type = tbinfo["topo"]["type"]
    downstream_suffix = DOWNSTREAM_NEIGHBOR_MAP[topo_type].upper()
    upstream_suffix = UPSTREAM_NEIGHBOR_MAP[topo_type].upper()

    downstream_neighbors = natsorted(
        [n for n in nbrhosts if n.upper().endswith(downstream_suffix)]
    )
    pytest_assert(
        downstream_neighbors,
        "No downstream ({}) neighbors found".format(downstream_suffix),
    )
    m0 = downstream_neighbors[0]

    upstream_neighbors = natsorted(
        [n for n in nbrhosts if n.upper().endswith(upstream_suffix)]
    )
    pytest_assert(
        upstream_neighbors,
        "No upstream ({}) neighbors found".format(upstream_suffix),
    )

    m0_offset = (
        tbinfo["topo"]["properties"]["topology"]["VMs"][m0]["vm_offset"]
    )
    common_cfg = (
        tbinfo["topo"]["properties"]["configuration_properties"]["common"]
    )

    yield {
        "m0": m0,
        "m2_neighbors": upstream_neighbors,
        "m0_exabgp_port": EXABGP_BASE_PORT + m0_offset,
        "m0_exabgp_port_v6": EXABGP_BASE_PORT_V6 + m0_offset,
        "nhipv4": common_cfg.get("nhipv4"),
        "nhipv6": common_cfg.get("nhipv6"),
    }


# ===================================================================
# TC 8.1a — Add aggregate with invalid prefix (rejected by GCU/YANG)
# ===================================================================
@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize("invalid_prefix", [
    pytest.param("999.999.999.999/33", id="garbage-ip-and-mask"),
    pytest.param("10.100.0.256/32", id="octet-out-of-range"),
    pytest.param("10.100.0.1/33", id="mask-exceeds-32"),
    pytest.param("10.100.0.0", id="missing-prefix-length"),
    pytest.param("abc.def.0.0/16", id="non-numeric-octets"),
    pytest.param("10.100.0/24", id="too-few-octets"),
    pytest.param("10.100.0.0/-1", id="negative-mask"),
])
def test_invalid_prefix_rejected_by_gcu(
    duthosts, rand_one_dut_hostname, nbrhosts, negative_setup,
    invalid_prefix,
):
    """
    TC 8.1a: GCU must reject a patch that adds an aggregate with an
    invalid prefix.  CONFIG_DB must remain unchanged and no aggregate
    route must appear on M2.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = negative_setup

    # Snapshot CONFIG_DB before the attempt
    db_before = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)

    # Build the patch manually and apply with low-level helper so we
    # can tolerate the expected failure.
    patch = [
        {
            "op": "add",
            "path": "/BGP_AGGREGATE_ADDRESS/{}".format(
                invalid_prefix.replace("/", "~1")
            ),
            "value": {
                "bbr-required": "false",
                "summary-only": "false",
                "as-set": "false",
            },
        }
    ]
    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(
            duthost, json_data=patch, dest_file=tmpfile
        )
        # GCU should return a non-zero rc for invalid data
        pytest_assert(
            output["rc"] != 0,
            "GCU should reject invalid prefix {}".format(invalid_prefix),
        )
    finally:
        delete_tmpfile(duthost, tmpfile)

    # CONFIG_DB must be unchanged
    db_after = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(
        db_before == db_after,
        "CONFIG_DB must not change after invalid GCU patch",
    )

    # No unexpected aggregate on M2
    verify_route_on_neighbors(
        nbrhosts,
        setup["m2_neighbors"],
        invalid_prefix,
        expected_present=False,
        timeout=10,
    )


# ===================================================================
# TC 8.1b — Host-bits-set prefix passes GCU but rejected by bgpcfgd
# ===================================================================
@pytest.mark.parametrize("invalid_prefix,corrected_prefix", [
    pytest.param("10.100.0.1/24", "10.100.0.0/24", id="host-bits-set-24"),
    pytest.param("10.100.1.0/23", "10.100.0.0/23", id="host-bits-set-23"),
])
def test_invalid_prefix_rejected_by_bgpcfgd(
    duthosts, rand_one_dut_hostname, nbrhosts, negative_setup,
    invalid_prefix, corrected_prefix, loganalyzer,
):
    """
    TC 8.1b: YANG does not enforce canonical prefix form, so GCU
    accepts host-bits-set prefixes into CONFIG_DB.  However bgpcfgd
    validates via ipaddress.ip_network(strict=True) and rejects them
    before pushing to FRR.  The syslog must contain the bgpcfgd
    rejection message.  Neither the invalid prefix nor the
    FRR-auto-corrected prefix (e.g. 10.100.0.1/24 -> 10.100.0.0/24)
    must appear on M2.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = negative_setup

    # Tell LogAnalyzer to expect the bgpcfgd rejection message.
    # LogAnalyzer.init() already marked the log start position during
    # fixture setup; analyze() runs at teardown and checks between
    # start and current.  So expect_regex must be set before the
    # action that produces the log.
    if loganalyzer:
        loganalyzer[duthost.hostname].expect_regex.extend([
            r".*AggregateAddressMgr::invalid aggregate prefix.*",
        ])

    cfg = AggregateCfg(
        prefix=invalid_prefix, bbr_required=False,
        summary_only=False, as_set=False,
    )
    try:
        gcu_add_aggregate(duthost, cfg)

        # Neither the original nor the FRR-auto-corrected prefix
        # should appear.  If bgpcfgd validation is bypassed, FRR
        # silently rewrites host-bits-set prefixes to their network
        # address (e.g. 10.100.0.1/24 -> 10.100.0.0/24).
        verify_route_on_neighbors(
            nbrhosts,
            setup["m2_neighbors"],
            invalid_prefix,
            expected_present=False,
            timeout=15,
        )
        verify_route_on_neighbors(
            nbrhosts,
            setup["m2_neighbors"],
            corrected_prefix,
            expected_present=False,
            timeout=10,
        )
    finally:
        safe_remove_aggregate(duthost, invalid_prefix)


# ===================================================================
# TC 8.2 — Duplicate aggregate add with different parameters (update)
# ===================================================================
def test_duplicate_add_updates_params(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, negative_setup
):
    """
    TC 8.2: Adding the same aggregate prefix a second time with
    different parameters acts as an update.  Start with
    summary-only=false, re-add with summary-only=true, and verify
    contributing routes become suppressed on M2.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = negative_setup
    contributing = CONTRIBUTING_V4[:2]

    cfg_v1 = AggregateCfg(
        prefix=AGGR_V4, bbr_required=False,
        summary_only=False, as_set=False,
    )
    cfg_v2 = AggregateCfg(
        prefix=AGGR_V4, bbr_required=False,
        summary_only=True, as_set=False,
    )

    try:
        inject_routes(setup, ptfhost, contributing, "announce")

        # Wait for contributing routes to propagate before adding
        # the aggregate — the aggregate won't be generated until at
        # least one contributing route exists in the DUT's BGP table.
        for route in contributing:
            verify_route_on_neighbors(
                nbrhosts, setup["m2_neighbors"],
                route, expected_present=True,
            )

        # First add — summary-only=false
        gcu_add_aggregate(duthost, cfg_v1)
        verify_route_on_neighbors(
            nbrhosts, setup["m2_neighbors"],
            AGGR_V4, expected_present=True,
        )

        # Re-add with summary-only=true (update)
        gcu_add_aggregate(duthost, cfg_v2)

        # Contributing routes must now be suppressed
        for route in contributing:
            verify_route_on_neighbors(
                nbrhosts, setup["m2_neighbors"],
                route, expected_present=False, timeout=15,
            )
        # Aggregate still present
        verify_route_on_neighbors(
            nbrhosts, setup["m2_neighbors"],
            AGGR_V4, expected_present=True,
        )
    finally:
        inject_routes(setup, ptfhost, contributing, "withdraw")
        safe_remove_aggregate(duthost, AGGR_V4)


# ===================================================================
# TC 8.3 — Remove non-existent aggregate
# ===================================================================
def test_remove_nonexistent_aggregate(
    duthosts, rand_one_dut_hostname, nbrhosts, negative_setup
):
    """
    TC 8.3: Attempting to remove an aggregate that was never configured
    must not crash the system.  CONFIG_DB and M2 routing table must
    remain stable.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = negative_setup
    bogus_prefix = "192.168.99.0/24"

    db_before = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)

    # Use low-level apply_patch so we can tolerate the expected error
    patch = [
        {
            "op": "remove",
            "path": "/BGP_AGGREGATE_ADDRESS/{}".format(
                bogus_prefix.replace("/", "~1")
            ),
        }
    ]
    tmpfile = generate_tmpfile(duthost)
    try:
        apply_patch(duthost, json_data=patch, dest_file=tmpfile)
    finally:
        delete_tmpfile(duthost, tmpfile)

    # Brief pause, then verify system stability
    time.sleep(5)

    db_after = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(
        db_before == db_after,
        "CONFIG_DB must not change after removing non-existent "
        "aggregate",
    )

    # DUT BGP sessions should still be up — spot-check that a known
    # neighbor can be queried for route absence
    verify_route_on_neighbors(
        nbrhosts,
        setup["m2_neighbors"],
        bogus_prefix,
        expected_present=False,
        timeout=10,
    )


# ===================================================================
# TC 8.4 — Aggregate with no matching contributing routes
# ===================================================================
def test_aggregate_no_matching_contributing(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, negative_setup
):
    """
    TC 8.4: An aggregate whose prefix range does not cover any of the
    announced routes must NOT appear on M2.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = negative_setup

    cfg = AggregateCfg(
        prefix=AGGR_V4, bbr_required=False,
        summary_only=False, as_set=False,
    )

    try:
        # Announce routes *outside* the aggregate range
        inject_routes(setup, ptfhost, NON_CONTRIBUTING_V4, "announce")

        gcu_add_aggregate(duthost, cfg)

        # Aggregate must NOT appear — no valid contributing routes
        verify_route_on_neighbors(
            nbrhosts, setup["m2_neighbors"],
            AGGR_V4, expected_present=False, timeout=15,
        )
    finally:
        inject_routes(setup, ptfhost, NON_CONTRIBUTING_V4, "withdraw")
        safe_remove_aggregate(duthost, AGGR_V4)


# ===================================================================
# TC 8.5 — Overlapping aggregates (independent prefixes)
# ===================================================================
def test_overlapping_aggregates(
    duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, negative_setup
):
    """
    TC 8.5: Two overlapping aggregates where one is nested inside the
    other (10.100.0.0/16 and 10.100.1.0/24).  Both must be received
    on M2.  Removing the more-specific must not affect the broader
    aggregate.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup = negative_setup
    # Use /16 contributing routes that fall outside the nested /24
    contributing_a = CONTRIBUTING_V4[1:3]
    contributing_b = CONTRIBUTING_EXTRA_V4

    cfg_a = AggregateCfg(
        prefix=AGGR_V4, bbr_required=False,
        summary_only=False, as_set=False,
    )
    cfg_b = AggregateCfg(
        prefix=AGGR_EXTRA_V4, bbr_required=False,
        summary_only=False, as_set=False,
    )

    try:
        inject_routes(
            setup, ptfhost,
            contributing_a + contributing_b, "announce",
        )

        # Wait for contributing routes to propagate before adding
        # the aggregates.
        for route in contributing_a + contributing_b:
            verify_route_on_neighbors(
                nbrhosts, setup["m2_neighbors"],
                route, expected_present=True,
            )

        gcu_add_aggregate(duthost, cfg_a)
        gcu_add_aggregate(duthost, cfg_b)

        # Both aggregates present
        verify_route_on_neighbors(
            nbrhosts, setup["m2_neighbors"],
            AGGR_V4, expected_present=True,
        )
        verify_route_on_neighbors(
            nbrhosts, setup["m2_neighbors"],
            AGGR_EXTRA_V4, expected_present=True,
        )

        # Remove more-specific; broader must stay
        gcu_remove_aggregate(duthost, AGGR_EXTRA_V4)
        verify_route_on_neighbors(
            nbrhosts, setup["m2_neighbors"],
            AGGR_EXTRA_V4, expected_present=False, timeout=15,
        )
        verify_route_on_neighbors(
            nbrhosts, setup["m2_neighbors"],
            AGGR_V4, expected_present=True,
        )
    finally:
        inject_routes(
            setup, ptfhost,
            contributing_a + contributing_b, "withdraw",
        )
        safe_remove_aggregate(duthost, AGGR_V4)
        safe_remove_aggregate(duthost, AGGR_EXTRA_V4)
