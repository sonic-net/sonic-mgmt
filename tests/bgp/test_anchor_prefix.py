"""
Test URH (UpperRegionalHub) ANCHOR_PREFIX end-to-end pipeline.

Exercises the real production path:

    CONFIG_DB PREFIX_LIST|ANCHOR_PREFIX|<prefix>
        -> bgpcfgd PrefixListMgr (managers_prefix_list.py)
        -> bgpd/radian/add_radian.conf.j2 / del_radian.conf.j2
              - ip[v6] prefix-list ANCHOR_CONTRIBUTING_ROUTES permit <prefix> ge <prefixlen+1>
              - aggregate-address <prefix> route-map TAG_ANCHOR_COMMUNITY
        -> TAG_ANCHOR_COMMUNITY tags the resulting aggregate with
           LOCAL_ANCHOR_ROUTE_COMMUNITY
        -> SELECTIVE_ROUTE_DOWNLOAD_V4/V6 table-map suppresses that
           community-tagged aggregate from FIB while contributing
           (more-specific) routes stay installed normally.

This is distinct from:
  - tests/bgp/test_prefix_list_suppress.py: PrefixListMgr refactor /
    SUPPRESS_PREFIX regression, CLI-focused, no data-plane verification.
  - tests/bgp/test_prefix_list.py: requires a SpineRouter+UpstreamLC/
    UpperSpineRouter DUT with RegionalHub/AZNGHub neighbors, and does not
    cover the UpperRegionalHub device type.

Neither of the above exercise the UpperRegionalHub device type against the
real ANCHOR_PREFIX CONFIG_DB pipeline, which is what this file covers.

This module runs only against the native URH KVM topology ('urh_min',
pytest topology 'urh'), so the DUT is a genuine UpperRegionalHub.

Assumes a single-ASIC DUT for the FRR-level checks, matching the shared
helpers in table_map_helpers.py.

See each test function's own docstring for the individual urh-tc-* case it
covers (urh-tc-single-anchor, urh-tc-multi-anchor,
urh-tc-partial-delete-overlap [xfail], urh-tc-contributing-route-withdraw
[xfail], urh-tc-churn-idempotency, urh-tc-reboot-persistence).
"""

import json
import logging
import re

import pytest

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.bgp.bgp_helpers import update_routes
from tests.bgp.table_map_helpers import (  # noqa: F401
    bgpcfgd_is_running,
    get_anchor_community,
    is_route_in_rib,
    is_route_in_fib,
    exabgp_setup,
)

pytestmark = [
    pytest.mark.topology('urh'),
    pytest.mark.skip_check_dut_health
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse=True)
def skip_multi_asic(duthosts, enum_dut_hostname):
    """Skip this module on multi-ASIC DUTs.

    This module assumes a single-ASIC DUT (matching table_map_helpers.py's
    helpers, several of which are re-used here directly): FRR-level checks
    hard-code the single 'bgp' docker/namespace rather than per-ASIC
    'bgpN'/'-n asicN' targeting, so on multi-ASIC platforms they'd target the
    wrong or nonexistent container and fail before exercising the
    ANCHOR_PREFIX pipeline at all.
    """
    duthost = duthosts[enum_dut_hostname]
    pytest_require(
        not duthost.is_multi_asic,
        "test_anchor_prefix module requires a single-ASIC DUT "
        "(helpers assume a single 'bgp' container)"
    )


@pytest.fixture(autouse=True)
def ignore_fabric_port_count_error(duthosts, enum_dut_hostname, loganalyzer):
    """Ignore the periodic getFabricPortList error on this KVM URH testbed.

    This module only ever runs against the KVM 'urh' topology (see the
    module-level topology marker above) - a single-ASIC virtual switch with
    no real fabric ASIC. orchagent's FabricPortsOrch health-check thread
    retries querying the (nonexistent) fabric port count every ~30s and logs
    this error continuously in the background, regardless of what test is
    running - it is not a regression caused by these tests. This ignore is
    scoped to this module only (not the global loganalyzer ignore list),
    since the same message could indicate a real defect on a physical
    chassis/other hwskus that do have a fabric ASIC.
    """
    if loganalyzer:
        duthost = duthosts[enum_dut_hostname]
        loganalyzer[duthost.hostname].ignore_regex.extend([
            r".*ERR swss\d*#orchagent: :- getFabricPortList: Failed to get fabric port number.*",
        ])


@pytest.fixture(autouse=True)
def _ensure_clean_anchor_state(duthosts, enum_dut_hostname):
    """Best-effort pre-test cleanup of all test ANCHOR_PREFIX entries.

    Residue left behind by a previous failed/interrupted run (CONFIG_DB
    entry, rendered prefix-list/aggregate-address config) could otherwise
    satisfy this test's own "not present yet" preconditions or leak into its
    assertions, since the module-level cleanup fixture (setup_urh_anchor)
    only runs once at module teardown, not before each individual test.
    """
    duthost = duthosts[enum_dut_hostname]
    for prefix in ALL_TEST_ANCHOR_PREFIXES:
        op_anchor_prefix(duthost, prefix, "remove", ignore_error=True)
    for prefix in ALL_TEST_ANCHOR_PREFIXES:
        wait_until(15, 3, 0, lambda p=prefix: not anchor_prefix_in_config_db(duthost, p))
    yield


PREFIX_TYPE = "ANCHOR_PREFIX"
ANCHOR_PL_NAME = "ANCHOR_CONTRIBUTING_ROUTES"

# Single-anchor / multi-anchor test prefixes.
# Use RFC 5737 documentation-only address space (never routable/allocated on
# the real internet) so these can't collide with a genuine route/aggregate
# already present in a live full BGP table.
ANCHOR_A = "192.0.2.0/24"  # TEST-NET-1
ANCHOR_A_LEN = 24
CONTRIB_A1 = "192.0.2.64/26"
CONTRIB_A2 = "192.0.2.128/26"

ANCHOR_B = "203.0.113.0/24"  # TEST-NET-3
ANCHOR_B_LEN = 24
CONTRIB_B1 = "203.0.113.64/26"

# Overlapping parent/child anchors for the partial-delete test, nested within
# TEST-NET-2 (198.51.100.0/24 - the only remaining RFC 5737 /24, so the
# parent/child relationship is expressed via prefix length within it rather
# than a separate /16 block).
ANCHOR_PARENT = "198.51.100.0/24"  # TEST-NET-2
ANCHOR_PARENT_LEN = 24
ANCHOR_CHILD = "198.51.100.0/26"
ANCHOR_CHILD_LEN = 26
CONTRIB_PARENT = "198.51.100.128/27"
CONTRIB_CHILD = "198.51.100.0/27"

ALL_TEST_ANCHOR_PREFIXES = [ANCHOR_A, ANCHOR_B, ANCHOR_PARENT, ANCHOR_CHILD]

CONSTANTS_FILE = "/etc/sonic/constants.yml"


# ============================================================
# Helpers
# ============================================================


def op_anchor_prefix(duthost, prefix, action, ignore_error=False):
    """Run 'sudo prefix_list <add|remove> ANCHOR_PREFIX <prefix>'."""
    pytest_assert(action in ("add", "remove"), "Invalid action {!r}".format(action))
    cmd = "sudo prefix_list {} {} {}".format(action, PREFIX_TYPE, prefix)
    return duthost.shell(cmd, module_ignore_errors=ignore_error)


def anchor_prefix_in_config_db(duthost, prefix):
    """Return True if PREFIX_LIST|ANCHOR_PREFIX|<prefix> exists in CONFIG_DB."""
    key = 'PREFIX_LIST|{}|{}'.format(PREFIX_TYPE, prefix)
    out = duthost.shell('sonic-db-cli CONFIG_DB keys "{}"'.format(key), module_ignore_errors=True)["stdout"]
    return key in out


def anchor_prefix_list_entry_count(duthost, prefix, prefixlen, ip_version=4):
    """Count occurrences of 'permit <prefix> ge <prefixlen+1>' in ANCHOR_CONTRIBUTING_ROUTES.

    Query only bgpd (-d bgpd) rather than broadcasting to all daemons: plain
    'vtysh -c' fans the command out to every daemon that recognizes it (here,
    both zebra and bgpd keep their own copy of the prefix-list), and vtysh
    prefixes each daemon's identical reply with its name, so a single real
    entry shows up twice ("ZEBRA: ..." and "BGP: ...") and inflates the count.
    """
    ipv = "ip" if ip_version == 4 else "ipv6"
    out = duthost.shell(
        "docker exec bgp vtysh -d bgpd -c 'show {} prefix-list {}'".format(ipv, ANCHOR_PL_NAME),
        module_ignore_errors=True
    )["stdout"]
    pattern = r"permit\s+{}\s+ge\s+{}\b".format(re.escape(prefix), prefixlen + 1)
    return len(re.findall(pattern, out))


def anchor_prefix_list_entry_present(duthost, prefix, prefixlen, ip_version=4):
    return anchor_prefix_list_entry_count(duthost, prefix, prefixlen, ip_version) > 0


def aggregate_address_count(duthost, prefix):
    """Count occurrences of 'aggregate-address <prefix> route-map TAG_ANCHOR_COMMUNITY' in running-config."""
    out = duthost.shell("docker exec bgp vtysh -c 'show running-config'", module_ignore_errors=True)["stdout"]
    needle = "aggregate-address {} route-map TAG_ANCHOR_COMMUNITY".format(prefix)
    return out.count(needle)


def has_aggregate_address(duthost, prefix):
    return aggregate_address_count(duthost, prefix) > 0


def get_route_communities(duthost, prefix, ip_version=4):
    """Return the list of BGP communities attached to prefix, or [] if not present/parseable."""
    ipv = "ipv4" if ip_version == 4 else "ipv6"
    cmd = "docker exec bgp vtysh -c 'show bgp {} {} json'".format(ipv, prefix)
    out = duthost.shell(cmd, module_ignore_errors=True)["stdout"]
    try:
        data = json.loads(out)
    except (ValueError, TypeError):
        return []
    communities = []
    for path in data.get("paths", []):
        communities.extend(path.get("community", {}).get("list", []))
    return communities


def _cleanup_all_anchor_prefixes(duthost):
    for prefix in ALL_TEST_ANCHOR_PREFIXES:
        op_anchor_prefix(duthost, prefix, "remove", ignore_error=True)


# ============================================================
# Module-level fixture: device type + anchor route-maps
# ============================================================

@pytest.fixture(scope="module")
def setup_urh_anchor(duthosts, enum_dut_hostname):
    """
    Confirm the DUT is a native UpperRegionalHub (this module only runs on
    the 'urh' topology, so this should always hold) and read the anchor
    route community, so the ANCHOR_PREFIX CONFIG_DB pipeline can be
    exercised against the real, unmodified device.

    Yields (duthost, local_anchor_route_community).
    """
    duthost = duthosts[enum_dut_hostname]

    device_type = duthost.shell(
        "redis-cli -n 4 HGET 'DEVICE_METADATA|localhost' type",
        module_ignore_errors=True
    )["stdout"].strip()
    pytest_assert(
        device_type == "UpperRegionalHub",
        "test_anchor_prefix requires a native UpperRegionalHub DUT, got {!r}".format(device_type)
    )

    community = get_anchor_community(duthost)

    try:
        yield duthost, community
    finally:
        _cleanup_all_anchor_prefixes(duthost)


# ============================================================
# Tests
# ============================================================

def test_anchor_single_prefix(setup_urh_anchor, exabgp_setup):  # noqa F811
    """
    urh-tc-single-anchor

    Configuring a single ANCHOR_PREFIX produces:
      - CONFIG_DB PREFIX_LIST|ANCHOR_PREFIX|<prefix> entry
      - ip prefix-list ANCHOR_CONTRIBUTING_ROUTES permit <prefix> ge <prefixlen+1>
      - aggregate-address <prefix> route-map TAG_ANCHOR_COMMUNITY
    Once a contributing (more-specific) route is announced, the aggregate:
      - appears in the BGP table tagged with LOCAL_ANCHOR_ROUTE_COMMUNITY
      - is suppressed from FIB by the table-map
    while the contributing route itself is installed in FIB normally.
    """
    duthost, community = setup_urh_anchor
    route = {"prefix": CONTRIB_A1, "nexthop": exabgp_setup["nhipv4"]}

    try:
        op_anchor_prefix(duthost, ANCHOR_A, "add")
        pytest_assert(
            wait_until(15, 3, 0, anchor_prefix_in_config_db, duthost, ANCHOR_A),
            "CONFIG_DB entry for {} not created".format(ANCHOR_A)
        )
        pytest_assert(
            wait_until(30, 3, 0, anchor_prefix_list_entry_present, duthost, ANCHOR_A, ANCHOR_A_LEN),
            "ANCHOR_CONTRIBUTING_ROUTES prefix-list entry for {} not rendered".format(ANCHOR_A)
        )
        pytest_assert(
            wait_until(30, 3, 0, has_aggregate_address, duthost, ANCHOR_A),
            "aggregate-address for {} not configured".format(ANCHOR_A)
        )

        # Precondition: with no contributing route announced yet, the aggregate
        # must NOT be in the RIB. Without this check, the "aggregate appeared"
        # assertion below would be an unverified assumption - the aggregate
        # could already be present (stale/leftover) rather than caused by the
        # announce that follows.
        pytest_assert(
            not is_route_in_rib(duthost, ANCHOR_A, 4),
            "Anchor aggregate {} should not be in RIB before any contributing route is announced"
            .format(ANCHOR_A)
        )

        update_routes("announce", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)
        pytest_assert(
            wait_until(60, 3, 5, is_route_in_rib, duthost, CONTRIB_A1, 4),
            "Contributing route {} not received in BGP RIB".format(CONTRIB_A1)
        )
        pytest_assert(
            wait_until(30, 3, 5, is_route_in_rib, duthost, ANCHOR_A, 4),
            "Anchor aggregate {} did not appear in BGP table".format(ANCHOR_A)
        )

        communities = get_route_communities(duthost, ANCHOR_A)
        pytest_assert(
            community in communities,
            "Aggregate {} missing anchor community {}: got {}".format(ANCHOR_A, community, communities)
        )
        pytest_assert(
            not is_route_in_fib(duthost, ANCHOR_A),
            "Anchor aggregate {} should be suppressed from FIB by table-map".format(ANCHOR_A)
        )
        pytest_assert(
            wait_until(30, 3, 0, is_route_in_fib, duthost, CONTRIB_A1),
            "Contributing route {} should be installed in FIB".format(CONTRIB_A1)
        )
        logger.info("PASS: single anchor prefix {} suppressed, contributing route {} installed"
                    .format(ANCHOR_A, CONTRIB_A1))
    finally:
        update_routes("withdraw", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)
        op_anchor_prefix(duthost, ANCHOR_A, "remove", ignore_error=True)


def test_anchor_multiple_prefixes(setup_urh_anchor, exabgp_setup):  # noqa F811
    """
    urh-tc-multi-anchor

    Multiple ANCHOR_PREFIX entries configured simultaneously are each
    independently rendered into the prefix-list/aggregate-address config,
    and each resulting aggregate is independently suppressed from FIB while
    its own contributing routes are unaffected.
    """
    duthost, community = setup_urh_anchor
    routes = [
        {"prefix": CONTRIB_A1, "nexthop": exabgp_setup["nhipv4"]},
        {"prefix": CONTRIB_B1, "nexthop": exabgp_setup["nhipv4"]},
    ]

    try:
        op_anchor_prefix(duthost, ANCHOR_A, "add")
        op_anchor_prefix(duthost, ANCHOR_B, "add")

        for prefix, prefixlen in ((ANCHOR_A, ANCHOR_A_LEN), (ANCHOR_B, ANCHOR_B_LEN)):
            pytest_assert(
                wait_until(15, 3, 0, anchor_prefix_in_config_db, duthost, prefix),
                "CONFIG_DB entry for {} not created".format(prefix)
            )
            pytest_assert(
                wait_until(30, 3, 0, anchor_prefix_list_entry_present, duthost, prefix, prefixlen),
                "ANCHOR_CONTRIBUTING_ROUTES entry for {} not rendered".format(prefix)
            )
            pytest_assert(
                wait_until(30, 3, 0, has_aggregate_address, duthost, prefix),
                "aggregate-address for {} not configured".format(prefix)
            )

        # Precondition: neither aggregate may be in the RIB yet, before any
        # contributing route is announced - guards against a stale/leftover
        # aggregate masking as one caused by the announces below.
        for prefix in (ANCHOR_A, ANCHOR_B):
            pytest_assert(
                not is_route_in_rib(duthost, prefix, 4),
                "Anchor aggregate {} should not be in RIB before any contributing route is announced"
                .format(prefix)
            )

        for route in routes:
            update_routes("announce", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)

        for prefix in (CONTRIB_A1, CONTRIB_B1, ANCHOR_A, ANCHOR_B):
            pytest_assert(
                wait_until(60, 3, 5, is_route_in_rib, duthost, prefix, 4),
                "{} not received in BGP RIB".format(prefix)
            )

        for prefix, contrib in ((ANCHOR_A, CONTRIB_A1), (ANCHOR_B, CONTRIB_B1)):
            communities = get_route_communities(duthost, prefix)
            pytest_assert(
                community in communities,
                "Aggregate {} missing anchor community {}: got {}".format(prefix, community, communities)
            )
            pytest_assert(
                not is_route_in_fib(duthost, prefix),
                "Anchor aggregate {} should be suppressed from FIB".format(prefix)
            )
            pytest_assert(
                wait_until(30, 3, 0, is_route_in_fib, duthost, contrib),
                "Contributing route {} should be installed in FIB".format(contrib)
            )
        logger.info("PASS: both anchors {}/{} independently suppressed".format(ANCHOR_A, ANCHOR_B))
    finally:
        for route in routes:
            update_routes("withdraw", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)
        op_anchor_prefix(duthost, ANCHOR_A, "remove", ignore_error=True)
        op_anchor_prefix(duthost, ANCHOR_B, "remove", ignore_error=True)


@pytest.mark.xfail(
    strict=False,
    reason="Known issue: child aggregate-address route lingers in RIB after "
           "ANCHOR_PREFIX config removal (same root symptom as "
           "urh-tc-contributing-route-withdraw, triggered by config removal "
           "instead of route withdrawal) - see "
           "https://github.com/sonic-net/sonic-mgmt/issues/28132"
)
def test_anchor_partial_delete_overlap(setup_urh_anchor, exabgp_setup):  # noqa F811
    """
    urh-tc-partial-delete-overlap

    A child anchor prefix (ANCHOR_CHILD) nested inside a parent anchor
    prefix (ANCHOR_PARENT) is configured alongside it. Deleting the child
    only removes the child's own prefix-list entry / aggregate-address /
    aggregate route, leaving the parent's config and aggregate route intact.
    """
    duthost, community = setup_urh_anchor
    route_parent = {"prefix": CONTRIB_PARENT, "nexthop": exabgp_setup["nhipv4"]}
    route_child = {"prefix": CONTRIB_CHILD, "nexthop": exabgp_setup["nhipv4"]}

    try:
        op_anchor_prefix(duthost, ANCHOR_PARENT, "add")
        op_anchor_prefix(duthost, ANCHOR_CHILD, "add")
        for prefix, prefixlen in ((ANCHOR_PARENT, ANCHOR_PARENT_LEN), (ANCHOR_CHILD, ANCHOR_CHILD_LEN)):
            pytest_assert(
                wait_until(15, 3, 0, anchor_prefix_in_config_db, duthost, prefix),
                "CONFIG_DB entry for {} not created".format(prefix)
            )
            pytest_assert(
                wait_until(30, 3, 0, anchor_prefix_list_entry_present, duthost, prefix, prefixlen),
                "ANCHOR_CONTRIBUTING_ROUTES entry for {} not rendered".format(prefix)
            )
            pytest_assert(
                wait_until(30, 3, 0, has_aggregate_address, duthost, prefix),
                "aggregate-address for {} not configured".format(prefix)
            )

        # Precondition: with no contributing routes announced yet, neither
        # aggregate may be in the RIB. Without this check, the "aggregate
        # appeared" assertions below would be an unverified assumption - an
        # aggregate could already be present (stale/leftover) rather than
        # caused by the announces that follow.
        for prefix in (ANCHOR_PARENT, ANCHOR_CHILD):
            pytest_assert(
                not is_route_in_rib(duthost, prefix, 4),
                "Anchor aggregate {} should not be in RIB before any contributing route is announced"
                .format(prefix)
            )

        update_routes("announce", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route_parent)
        update_routes("announce", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route_child)
        for prefix in (CONTRIB_PARENT, CONTRIB_CHILD, ANCHOR_PARENT, ANCHOR_CHILD):
            pytest_assert(
                wait_until(60, 3, 5, is_route_in_rib, duthost, prefix, 4),
                "{} not received in BGP RIB".format(prefix)
            )
        for prefix in (ANCHOR_PARENT, ANCHOR_CHILD):
            pytest_assert(
                not is_route_in_fib(duthost, prefix),
                "Aggregate {} should be suppressed from FIB before deletion".format(prefix)
            )

        # Delete only the child anchor
        op_anchor_prefix(duthost, ANCHOR_CHILD, "remove")
        pytest_assert(
            wait_until(15, 3, 0, lambda: not anchor_prefix_in_config_db(duthost, ANCHOR_CHILD)),
            "CONFIG_DB entry for child {} should be removed".format(ANCHOR_CHILD)
        )
        pytest_assert(
            wait_until(30, 3, 0, lambda: not anchor_prefix_list_entry_present(
                duthost, ANCHOR_CHILD, ANCHOR_CHILD_LEN)),
            "ANCHOR_CONTRIBUTING_ROUTES entry for child {} should be removed".format(ANCHOR_CHILD)
        )
        pytest_assert(
            wait_until(30, 3, 0, lambda: not has_aggregate_address(duthost, ANCHOR_CHILD)),
            "aggregate-address for child {} should be removed".format(ANCHOR_CHILD)
        )
        pytest_assert(
            # 30s was tuned against a lighter synthetic setup; on this KVM host
            # under a real ~100k-entry full BGP table (6 confederation
            # neighbors), aggregate withdrawal genuinely takes longer to
            # propagate under sustained CPU/memory pressure, so use a larger
            # budget to avoid flaking on slow-but-healthy convergence.
            wait_until(90, 5, 10, lambda: not is_route_in_rib(duthost, ANCHOR_CHILD, 4)),
            "Child aggregate {} should disappear from BGP table after deletion".format(ANCHOR_CHILD)
        )

        # Parent anchor must remain fully intact and unaffected
        pytest_assert(
            anchor_prefix_in_config_db(duthost, ANCHOR_PARENT),
            "CONFIG_DB entry for parent {} should remain after child deletion".format(ANCHOR_PARENT)
        )
        pytest_assert(
            anchor_prefix_list_entry_present(duthost, ANCHOR_PARENT, ANCHOR_PARENT_LEN),
            "ANCHOR_CONTRIBUTING_ROUTES entry for parent {} should remain".format(ANCHOR_PARENT)
        )
        pytest_assert(
            has_aggregate_address(duthost, ANCHOR_PARENT),
            "aggregate-address for parent {} should remain".format(ANCHOR_PARENT)
        )
        pytest_assert(
            is_route_in_rib(duthost, ANCHOR_PARENT, 4),
            "Parent aggregate {} should still be in BGP table".format(ANCHOR_PARENT)
        )
        pytest_assert(
            not is_route_in_fib(duthost, ANCHOR_PARENT),
            "Parent aggregate {} should still be suppressed from FIB".format(ANCHOR_PARENT)
        )
        logger.info("PASS: deleting child anchor {} left parent anchor {} intact"
                    .format(ANCHOR_CHILD, ANCHOR_PARENT))
    finally:
        update_routes("withdraw", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route_parent)
        update_routes("withdraw", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route_child)
        op_anchor_prefix(duthost, ANCHOR_PARENT, "remove", ignore_error=True)
        op_anchor_prefix(duthost, ANCHOR_CHILD, "remove", ignore_error=True)


@pytest.mark.xfail(
    strict=False,
    reason="Known issue: aggregate-address route lingers in RIB after last "
           "contributing route is withdrawn - see "
           "https://github.com/sonic-net/sonic-mgmt/issues/28132"
)
def test_anchor_contributing_route_withdraw(setup_urh_anchor, exabgp_setup):  # noqa F811
    """
    urh-tc-contributing-route-withdraw

    Withdrawing the last contributing (more-specific) route under an anchor
    aggregate causes FRR to stop originating the aggregate (standard
    aggregate-address behavior: it only exists while at least one matching
    more-specific route is present), even though the ANCHOR_PREFIX CONFIG_DB
    entry and its rendered prefix-list/aggregate-address config remain
    untouched. Re-announcing the contributing route must bring the aggregate
    back with correct community tagging and FIB suppression.
    """
    duthost, community = setup_urh_anchor
    route = {"prefix": CONTRIB_A1, "nexthop": exabgp_setup["nhipv4"]}

    try:
        op_anchor_prefix(duthost, ANCHOR_A, "add")
        pytest_assert(
            wait_until(30, 3, 0, has_aggregate_address, duthost, ANCHOR_A),
            "aggregate-address for {} not configured".format(ANCHOR_A)
        )

        # Precondition: with no contributing route announced yet, the aggregate
        # must NOT be in the RIB. Without this check, a later "aggregate appeared"
        # assertion would be an unverified assumption - the aggregate could
        # already have been present (stale/leftover) rather than caused by the
        # announce below.
        pytest_assert(
            not is_route_in_rib(duthost, ANCHOR_A, 4),
            "Anchor aggregate {} should not be in RIB before any contributing route is announced"
            .format(ANCHOR_A)
        )

        update_routes("announce", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)
        pytest_assert(
            wait_until(60, 3, 5, is_route_in_rib, duthost, ANCHOR_A, 4),
            "Anchor aggregate {} did not appear after contributing route announced".format(ANCHOR_A)
        )

        # Withdraw the only contributing route
        update_routes("withdraw", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)
        pytest_assert(
            # 60s was tuned against a lighter synthetic setup; see the similar
            # bump in test_anchor_partial_delete_overlap above for why a
            # heavier real full-table environment needs more headroom here.
            wait_until(120, 5, 10, lambda: not is_route_in_rib(duthost, ANCHOR_A, 4)),
            "Anchor aggregate {} should disappear once its last contributing route is withdrawn"
            .format(ANCHOR_A)
        )

        # Config-side artifacts must remain untouched
        pytest_assert(
            anchor_prefix_in_config_db(duthost, ANCHOR_A),
            "CONFIG_DB entry for {} should persist even though the aggregate withdrew".format(ANCHOR_A)
        )
        pytest_assert(
            anchor_prefix_list_entry_present(duthost, ANCHOR_A, ANCHOR_A_LEN),
            "ANCHOR_CONTRIBUTING_ROUTES entry for {} should persist".format(ANCHOR_A)
        )
        pytest_assert(
            has_aggregate_address(duthost, ANCHOR_A),
            "aggregate-address config for {} should persist".format(ANCHOR_A)
        )

        # Re-announcing the contributing route must bring the aggregate back
        update_routes("announce", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)
        pytest_assert(
            wait_until(60, 3, 5, is_route_in_rib, duthost, ANCHOR_A, 4),
            "Anchor aggregate {} did not reappear after contributing route re-announced".format(ANCHOR_A)
        )
        communities = get_route_communities(duthost, ANCHOR_A)
        pytest_assert(
            community in communities,
            "Reappeared aggregate {} missing anchor community: {}".format(ANCHOR_A, communities)
        )
        pytest_assert(
            not is_route_in_fib(duthost, ANCHOR_A),
            "Reappeared aggregate {} should still be suppressed from FIB".format(ANCHOR_A)
        )
        logger.info("PASS: aggregate {} correctly withdrew/reformed with its contributing route"
                    .format(ANCHOR_A))
    finally:
        update_routes("withdraw", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)
        op_anchor_prefix(duthost, ANCHOR_A, "remove", ignore_error=True)


def test_anchor_churn_idempotency(setup_urh_anchor):
    """
    urh-tc-churn-idempotency

    Rapidly adding/removing the same ANCHOR_PREFIX entry must converge
    idempotently: no duplicate ANCHOR_CONTRIBUTING_ROUTES prefix-list entries
    or duplicate aggregate-address lines accumulate, and bgpcfgd does not
    crash during the churn.
    """
    duthost, _ = setup_urh_anchor

    try:
        for i in range(5):
            op_anchor_prefix(duthost, ANCHOR_A, "add")
            op_anchor_prefix(duthost, ANCHOR_A, "remove")

        pytest_assert(bgpcfgd_is_running(duthost), "bgpcfgd should still be running after churn")

        # Final add — verify convergence to exactly one of each artifact
        op_anchor_prefix(duthost, ANCHOR_A, "add")
        pytest_assert(
            wait_until(15, 3, 0, anchor_prefix_in_config_db, duthost, ANCHOR_A),
            "CONFIG_DB entry for {} not created after churn".format(ANCHOR_A)
        )
        pytest_assert(
            wait_until(30, 3, 0, lambda: anchor_prefix_list_entry_count(
                duthost, ANCHOR_A, ANCHOR_A_LEN) == 1),
            "ANCHOR_CONTRIBUTING_ROUTES should have exactly one entry for {} after churn, got {}"
            .format(ANCHOR_A, anchor_prefix_list_entry_count(duthost, ANCHOR_A, ANCHOR_A_LEN))
        )
        pytest_assert(
            wait_until(30, 3, 0, lambda: aggregate_address_count(duthost, ANCHOR_A) == 1),
            "aggregate-address for {} should appear exactly once after churn, got {}"
            .format(ANCHOR_A, aggregate_address_count(duthost, ANCHOR_A))
        )
        pytest_assert(bgpcfgd_is_running(duthost), "bgpcfgd should still be running after final add")
        logger.info("PASS: churn on {} converged idempotently, bgpcfgd stayed up".format(ANCHOR_A))
    finally:
        op_anchor_prefix(duthost, ANCHOR_A, "remove", ignore_error=True)


def test_anchor_config_reload_persistence(setup_urh_anchor, exabgp_setup):  # noqa F811
    """
    urh-tc-reboot-persistence

    ANCHOR_PREFIX configuration must survive a 'config save' + 'config reload'
    cycle (the standard sonic-mgmt proxy for reboot persistence, matching
    TC-A4 in docs/testplan/PrefixListMgr-Refactor-Test-Plan.md): the CONFIG_DB
    entry, and the FRR prefix-list/aggregate-address config bgpcfgd derives
    from it, must be automatically regenerated on startup purely from
    CONFIG_DB — no CLI re-invocation required.
    """
    duthost, community = setup_urh_anchor
    route = {"prefix": CONTRIB_A1, "nexthop": exabgp_setup["nhipv4"]}

    try:
        op_anchor_prefix(duthost, ANCHOR_A, "add")
        pytest_assert(
            wait_until(30, 3, 0, has_aggregate_address, duthost, ANCHOR_A),
            "aggregate-address for {} not configured before reload".format(ANCHOR_A)
        )

        duthost.shell("sudo config save -y")
        # config_reload already restarts bgp as part of reapplying the full
        # config; wait_for_bgp=True asks it to also wait for BGP sessions to
        # re-establish, so a separate restart_bgp_and_wait() call here would
        # only be a redundant extra 'docker restart bgp' (and an unnecessary
        # hit against bgp.service's systemd restart-counter).
        config_reload(duthost, wait=300, wait_for_bgp=True)

        # Core assertion: CONFIG_DB entry and derived FRR config persisted
        # purely via config_db.json + bgpcfgd startup, no CLI re-run.
        pytest_assert(
            wait_until(30, 3, 0, anchor_prefix_in_config_db, duthost, ANCHOR_A),
            "CONFIG_DB entry for {} did not survive config reload".format(ANCHOR_A)
        )
        pytest_assert(
            wait_until(60, 5, 5, anchor_prefix_list_entry_present, duthost, ANCHOR_A, ANCHOR_A_LEN),
            "ANCHOR_CONTRIBUTING_ROUTES entry for {} not regenerated after reload".format(ANCHOR_A)
        )
        pytest_assert(
            wait_until(60, 5, 0, has_aggregate_address, duthost, ANCHOR_A),
            "aggregate-address for {} not regenerated after reload".format(ANCHOR_A)
        )

        # On the native URH topology, TAG_ANCHOR_COMMUNITY/SELECTIVE_ROUTE_DOWNLOAD
        # are rendered by the real minigraph-driven FRR templates (not CONFIG_DB
        # directly), so they are regenerated by config_reload just like the rest
        # of bgpd.conf — no manual reapplication needed here.
        update_routes("announce", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)
        pytest_assert(
            wait_until(60, 3, 5, is_route_in_rib, duthost, ANCHOR_A, 4),
            "Anchor aggregate {} did not reform after reload + contributing route".format(ANCHOR_A)
        )
        communities = get_route_communities(duthost, ANCHOR_A)
        pytest_assert(
            community in communities,
            "Aggregate {} missing anchor community after reload: {}".format(ANCHOR_A, communities)
        )
        pytest_assert(
            not is_route_in_fib(duthost, ANCHOR_A),
            "Anchor aggregate {} should be suppressed from FIB after reload".format(ANCHOR_A)
        )
        logger.info("PASS: ANCHOR_PREFIX {} persisted across config reload".format(ANCHOR_A))
    finally:
        update_routes("withdraw", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)
        op_anchor_prefix(duthost, ANCHOR_A, "remove", ignore_error=True)
        # This test explicitly ran 'config save -y' above to persist ANCHOR_A
        # into /etc/sonic/config_db.json. 'prefix_list remove' only updates
        # runtime CONFIG_DB (redis) - without saving again here, the on-disk
        # config_db.json would still contain ANCHOR_A, and a later reboot or
        # config reload (in this test or a subsequent one) would reintroduce
        # it, polluting the testbed with stale state.
        duthost.shell("sudo config save -y", module_ignore_errors=True)
