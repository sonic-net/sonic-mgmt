"""
Test SUPPRESS_PREFIX prefix-list feature on T0 (ToRRouter) devices.

Validates the end-to-end CONFIG_DB -> bgpcfgd -> FRR prefix-list pipeline
for SUPPRESS_PREFIX. When a PREFIX_LIST|SUPPRESS_PREFIX|<prefix> entry is
added to CONFIG_DB (via the `prefix_list` CLI), bgpcfgd renders an FRR
`ip prefix-list <name> permit <prefix>` command. The static T0 route-map
TO_TIER1_V4/V6 permit 100 matches that prefix-list and tags the route
with community 65525:110.

Phase 3 of the SONiC SUPPRESS_PREFIX feature. Test categories:
  A. DUT-local plumbing       - CONFIG_DB -> bgpcfgd -> FRR
  B. CLI surface              - `prefix_list add/remove/status`
  C. Upstream BGP propagation - T0 -> T1 EOS neighbor UPDATE
"""

import logging
import time

import pytest
import yaml

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('t0', 't0-64'),
]

logger = logging.getLogger(__name__)

PREFIX_TYPE = "SUPPRESS_PREFIX"
CONSTANTS_FILE = "/etc/sonic/constants.yml"
SUPPRESS_COMMUNITY = "65525:110"

# RFC 5737 / RFC 3849 documentation ranges - will not collide with real testbed routes.
TEST_PREFIXES_V4 = ["198.51.100.0/24", "198.51.101.0/24", "198.51.102.0/24"]
TEST_PREFIXES_V6 = ["2001:db8:abcd::/48", "2001:db8:abce::/48", "2001:db8:abcf::/48"]

DEFAULT_PREFIX_LIST_NAMES = {
    "ip": "SUPPRESS_ON_T1_IPV4_PREFIX",
    "ipv6": "SUPPRESS_ON_T1_IPV6_PREFIX",
}


# ---------------------------------------------------------------------------
# Helpers - name resolution and FRR state
# ---------------------------------------------------------------------------

def get_suppress_prefix_names(duthost):
    """Resolve FRR prefix-list names from the DUT's constants.yml, with defaults."""
    names = dict(DEFAULT_PREFIX_LIST_NAMES)
    try:
        output = duthost.shell("cat {}".format(CONSTANTS_FILE))["stdout"]
        constants = yaml.safe_load(output)
        pl_cfg = (constants.get("constants", {})
                           .get("bgp", {})
                           .get("prefix_list", {})
                           .get("SUPPRESS_PREFIX", {}))
        if pl_cfg.get("ipv4_name"):
            names["ip"] = pl_cfg["ipv4_name"]
        if pl_cfg.get("ipv6_name"):
            names["ipv6"] = pl_cfg["ipv6_name"]
    except Exception as e:
        logger.warning("Failed to read constants.yml, using defaults: %s", e)
    return names


def get_ipv(prefix):
    return "ipv6" if ":" in prefix else "ip"


def op_suppress_prefix(duthost, prefix, action, ignore_error=False):
    pytest_assert(action in ("add", "remove"), "Invalid action: must be 'add' or 'remove'")
    cmd = "sudo prefix_list {} {} {}".format(action, PREFIX_TYPE, prefix)
    return duthost.shell(cmd, module_ignore_errors=ignore_error)


def _show_prefix_list(duthost, ipv, list_name):
    # Single-daemon query: bare `vtysh` aggregates bgpd+zebra and double-counts.
    cmd = "vtysh -d bgpd -c 'show {} prefix-list {}'".format(ipv, list_name)
    return duthost.shell(cmd, module_ignore_errors=True)["stdout"]


def _has_prefix_in_frr(duthost, prefix, prefix_list_names):
    """Return True iff `prefix` is permitted in its FRR prefix-list."""
    ipv = get_ipv(prefix)
    output = _show_prefix_list(duthost, ipv, prefix_list_names[ipv])
    return any(prefix in line and "permit" in line for line in output.splitlines())


def wait_for_prefix_in_frr(duthost, prefix, prefix_list_names, present=True, timeout=15):
    """Poll FRR until prefix presence matches `present`; assert on timeout."""
    ok = wait_until(timeout, 2, 0,
                    lambda: _has_prefix_in_frr(duthost, prefix, prefix_list_names) == present)
    direction = "appear in" if present else "disappear from"
    pytest_assert(ok,
                  "Prefix {} did not {} FRR within {}s".format(prefix, direction, timeout))


def count_suppress_prefixes_in_frr(duthost, ipv, prefix_list_names):
    """Count permit entries excluding the static placeholder (anchor)."""
    output = _show_prefix_list(duthost, ipv, prefix_list_names[ipv])
    return sum(1 for line in output.splitlines()
               if "permit" in line and "127.0.0.1/32" not in line and "::1/128" not in line)


def verify_anchor_present(duthost, ipv, prefix_list_names):
    """Confirm the static placeholder anchor is live in FRR runtime state.

    The anchor (`permit 127.0.0.1/32` for v4, `permit ::1/128` for v6) is
    rendered by bgpcfgd's BGPPolicyMgr from `msft.general/{v4,v6}.tor/policy.conf.j2`
    over vtysh at container start - it is NOT in `/etc/frr/bgpd.conf`. So we
    query runtime state via `vtysh -d bgpd`, not the on-disk config.

    Pinned to `seq 1` (below FRR's empty-list auto-start of 5): on the batched
    `config reload` render, add_suppress_prefix.conf.j2 (no explicit seq) lands
    the user line BEFORE the anchor line. seq 5 (original) collided and the
    anchor overwrote the user; seq 4294967294 (max) overflowed auto-seq
    (`last+5`). This check is seq-agnostic so it tolerates any layout.
    """
    placeholder = "permit 127.0.0.1/32" if ipv == "ip" else "permit ::1/128"
    output = _show_prefix_list(duthost, ipv, prefix_list_names[ipv])
    return any(placeholder in line and "seq " in line for line in output.splitlines())


def verify_prefix_in_db(duthost, prefix):
    """Check whether `prefix_list status` shows the SUPPRESS_PREFIX entry."""
    output = duthost.shell("prefix_list status", module_ignore_errors=True)["stdout"]
    return "('{}', '{}')".format(PREFIX_TYPE, prefix) in output


# ---------------------------------------------------------------------------
# Helpers - neighbor (T1 EOS) BGP state
# ---------------------------------------------------------------------------

def get_route_state_on_neighbor(nbrhost, prefix):
    """Return (active, communities) for a prefix in the T1 EOS BGP table.

    Scans all bgpRoutePaths - a multi-homed prefix can have multiple paths and
    the desired community may not be on the first one. Returns (False, []) when
    the prefix is missing from the neighbor's BGP table.
    """
    try:
        route_data = nbrhost["host"].get_route(prefix)
    except Exception as e:
        logger.warning("get_route(%s) on neighbor failed: %s", prefix, e)
        return False, []
    entry = (route_data.get("vrfs", {})
                       .get("default", {})
                       .get("bgpRouteEntries", {})
                       .get(prefix, {}))
    paths = entry.get("bgpRoutePaths", [])
    active = any(p.get("routeType", {}).get("active", False) for p in paths)
    communities = [c for p in paths for c in p.get("routeDetail", {}).get("communityList", [])]
    return active, communities


def verify_community_on_neighbor(nbrhost, prefix, community=SUPPRESS_COMMUNITY, present=True):
    """wait_until predicate: True iff route is Active and community presence matches."""
    active, communities = get_route_state_on_neighbor(nbrhost, prefix)
    if not active:
        return False
    return (community in communities) if present else (community not in communities)


def get_advertised_prefix(duthost, tbinfo, ipv="ip"):
    """Pick a Vlan-interface prefix the T0 advertises to T1; fall back to Loopback0.

    Avoid hardcoding - minigraph regeneration can shift the address across testbeds.
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    is_v4 = (ipv == "ip")
    for vlan_intf in mg_facts.get("minigraph_vlan_interfaces", []):
        addr = vlan_intf.get("addr", "")
        if (":" in addr) != is_v4 and addr:
            return "{}/{}".format(vlan_intf["subnet"].split("/")[0], vlan_intf["prefixlen"]) \
                if "subnet" in vlan_intf else "{}/{}".format(addr, vlan_intf["prefixlen"])
    for lo in mg_facts.get("minigraph_lo_interfaces", []):
        addr = lo.get("addr", "")
        if lo.get("name") == "Loopback0" and ((":" in addr) != is_v4) and addr:
            prefixlen = 128 if ":" in addr else 32
            return "{}/{}".format(addr, prefixlen)
    pytest.skip("No suitable {} prefix found in minigraph for Category C tests".format(ipv))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def prefix_list_names(duthosts, rand_one_dut_hostname):
    return get_suppress_prefix_names(duthosts[rand_one_dut_hostname])


@pytest.fixture(scope="function")
def setup_suppress_prefix(duthosts, rand_one_dut_hostname):
    """Yield the DUT; clean up all test prefixes after each test."""
    duthost = duthosts[rand_one_dut_hostname]
    yield duthost
    for prefix in TEST_PREFIXES_V4 + TEST_PREFIXES_V6:
        op_suppress_prefix(duthost, prefix, "remove", ignore_error=True)


@pytest.fixture(scope="module")
def t1_neighbor(nbrhosts):
    """Pick one T1 EOS neighbor for Category C tests."""
    t1_names = [name for name in nbrhosts.keys() if name.upper().endswith("T1")]
    if not t1_names:
        pytest.skip("No T1 neighbors found in nbrhosts")
    name = sorted(t1_names)[0]
    return name, nbrhosts[name]


# ===========================================================================
# Category A - DUT-local plumbing
# ===========================================================================

@pytest.mark.parametrize("prefix", [TEST_PREFIXES_V4[0], TEST_PREFIXES_V6[0]],
                         ids=["ipv4", "ipv6"])
def test_add_suppress_prefix(setup_suppress_prefix, prefix_list_names, prefix):
    """Add prefix -> appears in FRR prefix-list."""
    duthost = setup_suppress_prefix
    op_suppress_prefix(duthost, prefix, "add")
    wait_for_prefix_in_frr(duthost, prefix, prefix_list_names, present=True)


@pytest.mark.parametrize("prefix", [TEST_PREFIXES_V4[0], TEST_PREFIXES_V6[0]],
                         ids=["ipv4", "ipv6"])
def test_remove_suppress_prefix(setup_suppress_prefix, prefix_list_names, prefix):
    """Remove prefix -> gone from FRR."""
    duthost = setup_suppress_prefix
    op_suppress_prefix(duthost, prefix, "add")
    wait_for_prefix_in_frr(duthost, prefix, prefix_list_names, present=True)
    op_suppress_prefix(duthost, prefix, "remove")
    wait_for_prefix_in_frr(duthost, prefix, prefix_list_names, present=False)


def test_multiple_suppress_prefixes(setup_suppress_prefix, prefix_list_names):
    """Add N prefixes -> all appear, count matches."""
    duthost = setup_suppress_prefix
    initial = count_suppress_prefixes_in_frr(duthost, "ip", prefix_list_names)
    for prefix in TEST_PREFIXES_V4:
        op_suppress_prefix(duthost, prefix, "add")
    for prefix in TEST_PREFIXES_V4:
        wait_for_prefix_in_frr(duthost, prefix, prefix_list_names, present=True)
    final = count_suppress_prefixes_in_frr(duthost, "ip", prefix_list_names)
    pytest_assert(final - initial == len(TEST_PREFIXES_V4),
                  "Expected count delta {}, got {} (initial={}, final={})"
                  .format(len(TEST_PREFIXES_V4), final - initial, initial, final))


def test_suppress_prefix_any_device(setup_suppress_prefix, prefix_list_names):
    """SUPPRESS_PREFIX has no device-type restriction - CLI accepts it on ToRRouter."""
    duthost = setup_suppress_prefix
    prefix = TEST_PREFIXES_V4[0]
    result = op_suppress_prefix(duthost, prefix, "add")
    pytest_assert(result["rc"] == 0,
                  "prefix_list add should succeed on ToRRouter, got rc={}, stderr={}"
                  .format(result["rc"], result.get("stderr", "")))
    wait_for_prefix_in_frr(duthost, prefix, prefix_list_names, present=True)


def test_suppress_prefix_persistence(duthosts, rand_one_dut_hostname, prefix_list_names):
    """config save + config reload -> prefix-list survives.

    Requires the runtime anchor to be live in FRR (so frr-reload.py preserves
    the prefix-list section instead of wiping it during diff-and-apply). See
    `verify_anchor_present()` for the seq-collision / batched-render rationale.
    Pre-flight skips when the anchor is missing (image without policy templates).
    """
    duthost = duthosts[rand_one_dut_hostname]
    if not verify_anchor_present(duthost, "ip", prefix_list_names):
        pytest.skip("{} anchor missing from FRR runtime -- bgpcfgd did not render "
                    "msft.general/v4.tor/policy.conf.j2 (image lacks the SUPPRESS "
                    "policy templates)".format(prefix_list_names["ip"]))
    if not verify_anchor_present(duthost, "ipv6", prefix_list_names):
        pytest.skip("{} anchor missing from FRR runtime -- bgpcfgd did not render "
                    "msft.general/v6.tor/policy.conf.j2 (image lacks the SUPPRESS "
                    "policy templates)".format(prefix_list_names["ipv6"]))

    prefix_v4 = TEST_PREFIXES_V4[0]
    prefix_v6 = TEST_PREFIXES_V6[0]
    try:
        op_suppress_prefix(duthost, prefix_v4, "add")
        op_suppress_prefix(duthost, prefix_v6, "add")
        wait_for_prefix_in_frr(duthost, prefix_v4, prefix_list_names, present=True)
        wait_for_prefix_in_frr(duthost, prefix_v6, prefix_list_names, present=True)

        duthost.shell("config save -y")
        config_reload(duthost, wait_for_bgp=True)

        wait_for_prefix_in_frr(duthost, prefix_v4, prefix_list_names, present=True)
        wait_for_prefix_in_frr(duthost, prefix_v6, prefix_list_names, present=True)
    finally:
        op_suppress_prefix(duthost, prefix_v4, "remove", ignore_error=True)
        op_suppress_prefix(duthost, prefix_v6, "remove", ignore_error=True)
        duthost.shell("config save -y", module_ignore_errors=True)


def test_add_duplicate_prefix_idempotent(setup_suppress_prefix, prefix_list_names):
    """Add same prefix twice -> single FRR entry, no error."""
    duthost = setup_suppress_prefix
    prefix = TEST_PREFIXES_V4[0]
    op_suppress_prefix(duthost, prefix, "add")
    wait_for_prefix_in_frr(duthost, prefix, prefix_list_names, present=True)
    result = op_suppress_prefix(duthost, prefix, "add", ignore_error=True)
    logger.info("Second add returned rc=%s", result["rc"])
    wait_for_prefix_in_frr(duthost, prefix, prefix_list_names, present=True)
    output = _show_prefix_list(duthost, "ip", prefix_list_names["ip"])
    matches = [line for line in output.splitlines() if prefix in line and "permit" in line]
    pytest_assert(len(matches) == 1,
                  "Expected exactly 1 FRR entry for {}, found {}: {}".format(prefix, len(matches), matches))


def test_remove_nonexistent_prefix_harmless(setup_suppress_prefix, prefix_list_names):
    """Remove never-added prefix -> no error, FRR unchanged."""
    duthost = setup_suppress_prefix
    prefix = "203.0.113.0/24"  # TEST-NET-3, never added
    initial = count_suppress_prefixes_in_frr(duthost, "ip", prefix_list_names)
    op_suppress_prefix(duthost, prefix, "remove", ignore_error=True)
    final = count_suppress_prefixes_in_frr(duthost, "ip", prefix_list_names)
    pytest_assert(initial == final,
                  "FRR prefix-list count changed after removing nonexistent prefix: {} -> {}"
                  .format(initial, final))


# ===========================================================================
# Category B - CLI surface
# ===========================================================================

def test_cli_add_remove_status(setup_suppress_prefix, prefix_list_names):
    """Exercise `prefix_list add/remove/status` end-to-end."""
    duthost = setup_suppress_prefix
    prefix = TEST_PREFIXES_V4[0]

    result = op_suppress_prefix(duthost, prefix, "add")
    pytest_assert(result["rc"] == 0,
                  "prefix_list add failed: rc={}, stderr={}".format(result["rc"], result.get("stderr", "")))
    pytest_assert(wait_until(10, 1, 0, lambda: verify_prefix_in_db(duthost, prefix)),
                  "prefix_list status did not show SUPPRESS_PREFIX entry for {} within 10s".format(prefix))
    wait_for_prefix_in_frr(duthost, prefix, prefix_list_names, present=True)

    result = op_suppress_prefix(duthost, prefix, "remove")
    pytest_assert(result["rc"] == 0,
                  "prefix_list remove failed: rc={}, stderr={}".format(result["rc"], result.get("stderr", "")))
    pytest_assert(wait_until(10, 1, 0, lambda: not verify_prefix_in_db(duthost, prefix)),
                  "prefix_list status still showed {} after removal".format(prefix))
    wait_for_prefix_in_frr(duthost, prefix, prefix_list_names, present=False)


def test_cli_invalid_input_handling(setup_suppress_prefix, prefix_list_names):
    """Bad inputs do not propagate to FRR; clean up any CONFIG_DB leaks.

    Current CLI behavior (verified 2026-05-11): `prefix_list` is a thin CONFIG_DB
    shim with sloppy exit codes:
      - Bad CIDR / missing network arg: CLI exits 0 and writes to CONFIG_DB.
        FRR / YANG catches the bad value downstream.
      - Unknown prefix type: CLI exits 0 but prints "Prefix type not supported"
        to stderr and writes nothing to CONFIG_DB.
    We assert the end-state (nothing bad in FRR) and clean any DB leaks so
    teardown's config_db_check passes.
    """
    duthost = setup_suppress_prefix
    initial_v4 = count_suppress_prefixes_in_frr(duthost, "ip", prefix_list_names)
    initial_v6 = count_suppress_prefixes_in_frr(duthost, "ipv6", prefix_list_names)

    # (a) Bad CIDR - /33 invalid for IPv4. CLI does not validate; FRR rejects.
    # Sleep (not wait_until): testing a negative (absence) - no positive signal to poll.
    bad_prefix = "10.0.0.0/33"
    try:
        duthost.shell("sudo prefix_list add SUPPRESS_PREFIX {}".format(bad_prefix),
                      module_ignore_errors=True)
        time.sleep(2)
        v4_out = _show_prefix_list(duthost, "ip", prefix_list_names["ip"])
        pytest_assert(bad_prefix not in v4_out,
                      "Bad CIDR {} unexpectedly propagated to FRR:\n{}".format(bad_prefix, v4_out))
    finally:
        # CLI 'remove' would route through YANG (same rejection); delete CONFIG_DB
        # entry directly so teardown's config_db_check does not fail on the leak.
        duthost.shell(
            "sudo sonic-db-cli CONFIG_DB DEL 'PREFIX_LIST|SUPPRESS_PREFIX|{}'".format(bad_prefix),
            module_ignore_errors=True,
        )

    # (b) Unknown prefix type - CLI rejects with stderr (no DB write).
    bad_type = duthost.shell("sudo prefix_list add FAKE_TYPE 10.0.0.0/24", module_ignore_errors=True)
    bad_type_output = bad_type.get("stderr", "") + bad_type.get("stdout", "")
    pytest_assert("Prefix type not supported" in bad_type_output,
                  "Unknown prefix type should produce 'Prefix type not supported' error; got: {}"
                  .format(bad_type_output))

    # (c) Missing network arg - CLI accepts (no validation), writes empty-network leak.
    try:
        duthost.shell("sudo prefix_list add SUPPRESS_PREFIX", module_ignore_errors=True)
        time.sleep(2)
        pytest_assert(
            count_suppress_prefixes_in_frr(duthost, "ip", prefix_list_names) == initial_v4,
            "Empty network arg unexpectedly added IPv4 FRR entry",
        )
    finally:
        duthost.shell(
            "sudo sonic-db-cli CONFIG_DB DEL 'PREFIX_LIST|SUPPRESS_PREFIX|'",
            module_ignore_errors=True,
        )

    # No FRR state change from (a)-(c)
    pytest_assert(count_suppress_prefixes_in_frr(duthost, "ip", prefix_list_names) == initial_v4,
                  "Invalid CLI inputs must not change IPv4 FRR state")
    pytest_assert(count_suppress_prefixes_in_frr(duthost, "ipv6", prefix_list_names) == initial_v6,
                  "Invalid CLI inputs must not change IPv6 FRR state")

    # (d) IPv6 prefix routes to v6 list only
    prefix = TEST_PREFIXES_V6[0]
    ok = op_suppress_prefix(duthost, prefix, "add")
    pytest_assert(ok["rc"] == 0,
                  "Valid IPv6 add should succeed; got rc={}, stderr={}"
                  .format(ok["rc"], ok.get("stderr", "")))
    wait_for_prefix_in_frr(duthost, prefix, prefix_list_names, present=True)
    v4_out = _show_prefix_list(duthost, "ip", prefix_list_names["ip"])
    pytest_assert(prefix not in v4_out,
                  "IPv6 prefix leaked into IPv4 list:\n{}".format(v4_out))


# ===========================================================================
# Category C - Upstream BGP propagation (T0 -> T1 EOS neighbor)
# ===========================================================================

def test_suppress_prefix_community_tagging(duthosts, rand_one_dut_hostname, prefix_list_names,
                                           t1_neighbor, tbinfo):
    """Steady state: T0 advertises a matching prefix -> T1 EOS observes community 65525:110.

    Validates the design doc's primary BGP propagation claim. Uses a Vlan-interface
    prefix from the minigraph (already advertised by the T0 to its T1 neighbors).
    """
    duthost = duthosts[rand_one_dut_hostname]
    nbr_name, nbr = t1_neighbor
    target = get_advertised_prefix(duthost, tbinfo, "ip")
    logger.info("Category C target prefix on neighbor %s: %s", nbr_name, target)

    pytest_assert(wait_until(60, 5, 0,
                             lambda: verify_community_on_neighbor(nbr, target, present=False)),
                  "Pre-condition: route {} should be Active on {} without community {} "
                  "before SUPPRESS is configured".format(target, nbr_name, SUPPRESS_COMMUNITY))

    try:
        op_suppress_prefix(duthost, target, "add")
        wait_for_prefix_in_frr(duthost, target, prefix_list_names, present=True)
        pytest_assert(wait_until(60, 5, 0,
                                 lambda: verify_community_on_neighbor(nbr, target, present=True)),
                      "T1 neighbor {} did not receive {} with community {} within 60s"
                      .format(nbr_name, target, SUPPRESS_COMMUNITY))
    finally:
        op_suppress_prefix(duthost, target, "remove", ignore_error=True)


def test_suppress_prefix_no_withdraw_on_add(duthosts, rand_one_dut_hostname, prefix_list_names,
                                            t1_neighbor, tbinfo):
    """Adding a prefix mid-session produces an UPDATE, not a Withdraw.

    Design Figure 2: when SUPPRESS is added, T0 sends an UPDATE (community
    changes); T1 must NOT see a Withdraw+re-Advertise. 1s polling is
    intentional - a wider interval can miss a transient inactive window.
    """
    duthost = duthosts[rand_one_dut_hostname]
    nbr_name, nbr = t1_neighbor
    target = get_advertised_prefix(duthost, tbinfo, "ip")

    pre_active, pre_communities = get_route_state_on_neighbor(nbr, target)
    pytest_assert(pre_active and SUPPRESS_COMMUNITY not in pre_communities,
                  "Pre-condition: {} must be Active on {} without {} (active={}, communities={})"
                  .format(target, nbr_name, SUPPRESS_COMMUNITY, pre_active, pre_communities))

    try:
        op_suppress_prefix(duthost, target, "add")

        deadline = time.time() + 60
        observed_inactive = []
        community_observed = False
        while time.time() < deadline:
            active, communities = get_route_state_on_neighbor(nbr, target)
            if not active:
                observed_inactive.append(communities)
            if active and SUPPRESS_COMMUNITY in communities:
                community_observed = True
                break
            time.sleep(1)

        pytest_assert(not observed_inactive,
                      "Route {} transitioned to inactive/withdrawn during SUPPRESS add - "
                      "violates design Figure 2 (UPDATE, not Withdraw). Samples: {}"
                      .format(target, observed_inactive))
        pytest_assert(community_observed,
                      "Did not observe community {} on {} within 60s after SUPPRESS add"
                      .format(SUPPRESS_COMMUNITY, target))

        post_active, post_communities = get_route_state_on_neighbor(nbr, target)
        pytest_assert(post_active and SUPPRESS_COMMUNITY in post_communities,
                      "Post-condition: {} must be Active with {} (active={}, communities={})"
                      .format(target, SUPPRESS_COMMUNITY, post_active, post_communities))
    finally:
        op_suppress_prefix(duthost, target, "remove", ignore_error=True)


def test_suppress_prefix_community_removed_on_delete(duthosts, rand_one_dut_hostname,
                                                     prefix_list_names, t1_neighbor, tbinfo):
    """Removing a prefix drops community 65525:110 while route stays Active.

    Validates rollback symmetry: an UPDATE removes the community; T1 then
    re-advertises the previously-suppressed route upstream. 1s polling
    intentional (same rationale as test_suppress_prefix_no_withdraw_on_add).
    """
    duthost = duthosts[rand_one_dut_hostname]
    nbr_name, nbr = t1_neighbor
    target = get_advertised_prefix(duthost, tbinfo, "ip")

    op_suppress_prefix(duthost, target, "add")
    wait_for_prefix_in_frr(duthost, target, prefix_list_names, present=True)
    pytest_assert(wait_until(60, 5, 0,
                             lambda: verify_community_on_neighbor(nbr, target, present=True)),
                  "Setup: {} did not converge with community {} on {} within 60s"
                  .format(target, SUPPRESS_COMMUNITY, nbr_name))

    try:
        op_suppress_prefix(duthost, target, "remove")

        deadline = time.time() + 60
        observed_inactive = []
        community_gone = False
        while time.time() < deadline:
            active, communities = get_route_state_on_neighbor(nbr, target)
            if not active:
                observed_inactive.append(communities)
            if active and SUPPRESS_COMMUNITY not in communities:
                community_gone = True
                break
            time.sleep(1)

        pytest_assert(not observed_inactive,
                      "Route {} transitioned to inactive/withdrawn during SUPPRESS remove - "
                      "violates rollback symmetry. Samples: {}".format(target, observed_inactive))
        pytest_assert(community_gone,
                      "Community {} was not removed from {} on {} within 60s"
                      .format(SUPPRESS_COMMUNITY, target, nbr_name))
    finally:
        op_suppress_prefix(duthost, target, "remove", ignore_error=True)
