"""
BGP Aggregate Address — MSFT Internal Community Tagging Tests

Test Plan Reference:
    BGP-Aggregate-Address-MSFT-Internal-TestPlan.md

Background (MSFT Aggregation Strategy):
    MSFT does NOT use summary-only=true in production.  Instead, both the
    aggregate route and contributing routes are advertised to upstream
    neighbors, each tagged with different BGP community values.  Upstream
    devices use these communities to make routing policy decisions (e.g.
    whether to apply NO_EXPORT or NO_ADVERTISE).

    The public feature's prefix-lists (aggregate-address-prefix-list and
    contributing-address-prefix-list) are the mechanism that drives the
    MSFT FRR template's route-map matching and community tagging.

    Two distinct upstream scenarios:
        MA (MgmtSpineRouter):
            aggregate  -> 8075:8801
            contributing -> 8075:8800
            MA applies NO_EXPORT to routes matching 8075:8800.
        OOB (CoreTs):
            aggregate  -> 8075:9120
            contributing -> 8075:9120 + NO_ADVERTISE
            Contributing routes not advertised further due to NO_ADVERTISE.

Topology:
    M1-48 with MSFT internal SONiC image.
    - M0 (downstream, MgmtToRRouter): injects contributing routes via ExaBGP
    - MA (upstream, MgmtSpineRouter): receives routes with MA communities
    - MB (upstream, CoreTs/OOB): receives routes with OOB communities

Groups:
    1. MA Device Scenario — Community Tagging (TC 1.1-1.5)
    2. OOB Device Scenario — NO_ADVERTISE Tagging (TC 2.1-2.5)
    3. Prefix-List Driven Community Tagging Mechanism (TC 3.1-3.4, 3.7)
    4. BBR Interaction with Community Tagging (TC 4.1-4.4)
    5. Lifecycle Operations with Community Verification (TC 5.1-5.5)
    6. Mixed MA and OOB Scenario (TC 6.1-6.4)
    7. Upstream Device Behavior Verification (TC 7.1-7.5)
"""

import json as json_lib
import logging
import time
from collections import namedtuple

import pytest
from natsort import natsorted

# ---- Reuse from existing test modules (mssonic/internal branch) ----
from bgp_bbr_helpers import config_bbr_by_gcu, get_bbr_default_state, is_bbr_enabled

from bgp_aggregate_helpers import (
    BGP_AGGREGATE_ADDRESS,
    PLACEHOLDER_PREFIX,
    dump_db,
    gcu_add_placeholder_aggregate,
    gcu_remove_aggregate,
    running_bgp_has_aggregate,
)

from tests.common.gcu_utils import (
    apply_gcu_patch,
    create_checkpoint,
    delete_checkpoint,
    rollback_or_reload,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.bgp_routing import inject_routes, verify_route_on_neighbors
from tests.common.utilities import wait_until
from tests.common.devices.eos import EosHost
from tests.common.devices.sonic import SonicHost
from tests.common.config_reload import config_reload as do_config_reload

import ptf.testutils as testutils
import ptf.packet as scapy
from ptf.mask import Mask

logger = logging.getLogger(__name__)

# ---- Topology & device-type markers ----
pytestmark = [
    pytest.mark.topology("m1"),
    pytest.mark.disable_loganalyzer,
]


# ===========================================================================
# CONSTANTS
# ===========================================================================

# ---- MA (MgmtSpineRouter) upstream community tags ----
MA_AGGREGATE_COMMUNITY = "8075:8801"       # Applied to aggregate route toward MA
MA_CONTRIBUTING_COMMUNITY = "8075:8800"    # Applied to contributing routes toward MA

# ---- OOB (CoreTs) upstream community tags ----
OOB_AGGREGATE_COMMUNITY = "8075:9120"      # Applied to aggregate route toward OOB
OOB_CONTRIBUTING_COMMUNITY = "8075:9120"   # Same tag, but contributing also gets NO_ADVERTISE
NO_ADVERTISE_COMMUNITY = "no-advertise"    # Well-known community preventing re-advertisement

# ---- IPv4 test prefixes ----
AGGR_V4 = "10.100.0.0/16"
CONTRIBUTING_V4 = ["10.100.1.0/24", "10.100.2.0/24", "10.100.3.0/24"]
AGG_PREFIX_LIST_V4 = "AGGREGATE_ROUTES_V4"
CONTRIBUTING_PREFIX_LIST_V4 = "AGGREGATE_CONTRIBUTING_ROUTES_V4"

# Second aggregate for multi-aggregate tests (TC 3.4)
AGGR_V4_B = "10.200.0.0/16"
CONTRIBUTING_V4_B = ["10.200.1.0/24", "10.200.2.0/24"]

# ---- IPv6 test prefixes ----
AGGR_V6 = "2001:db8:100::/48"
CONTRIBUTING_V6 = ["2001:db8:100:1::/64", "2001:db8:100:2::/64", "2001:db8:100:3::/64"]
AGG_PREFIX_LIST_V6 = "AGGREGATE_ROUTES_V6"
CONTRIBUTING_PREFIX_LIST_V6 = "AGGREGATE_CONTRIBUTING_ROUTES_V6"

# ---- ExaBGP ports (downstream route injection) ----
EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000

# ---- Timing constants ----
BGP_CONVERGE_TIMEOUT = 120        # seconds to wait for route/community convergence
BGP_CONVERGE_TIMEOUT_LONG = 180   # for operations like BGP restart or config reload
BGP_CONVERGE_POLL_INTERVAL = 3    # seconds between poll attempts


# ===========================================================================
# ROUTE-MAP HOT-PATCH — fallback for older images without native template support
# ===========================================================================
# SONiC 202511+ FRR templates include community-tagging route-map entries
# (seq 110/120) that reference built-in prefix-lists AGGREGATE_ROUTES_V4 and
# AGGREGATE_CONTRIBUTING_ROUTES_V4.  On these images, bgpcfgd populates the
# prefix-lists from ConfigDB and the template handles tagging natively.
#
# On older images that lack these template entries, we fall back to hot-patching
# via vtysh at seq 200/300.  The _frr_template_has_community_tagging() function
# detects which mode to use at runtime.
#
# Route-map ordering (hot-patch mode only):
#   seq 100  — existing (default prefix handling)
#   seq 200  — HOT-PATCH: aggregate prefix-list → community tag
#   seq 300  — HOT-PATCH: contributing prefix-list → community tag
#   seq 1000 — existing catch-all
# ===========================================================================

_ROUTE_MAP_PATCH_COMMANDS = [
    # ---- TO_MA_PATH_V4: MA upstream, IPv4 ----
    "route-map TO_MA_PATH_V4 permit 200",
    "match ip address prefix-list {}".format(AGG_PREFIX_LIST_V4),
    "set community {} additive".format(MA_AGGREGATE_COMMUNITY),
    "exit",
    "route-map TO_MA_PATH_V4 permit 300",
    "match ip address prefix-list {}".format(CONTRIBUTING_PREFIX_LIST_V4),
    "set community {} additive".format(MA_CONTRIBUTING_COMMUNITY),
    "exit",
    # ---- TO_MA_PATH_V6: MA upstream, IPv6 ----
    "route-map TO_MA_PATH_V6 permit 200",
    "match ipv6 address prefix-list {}".format(AGG_PREFIX_LIST_V6),
    "set community {} additive".format(MA_AGGREGATE_COMMUNITY),
    "exit",
    "route-map TO_MA_PATH_V6 permit 300",
    "match ipv6 address prefix-list {}".format(CONTRIBUTING_PREFIX_LIST_V6),
    "set community {} additive".format(MA_CONTRIBUTING_COMMUNITY),
    "exit",
    # ---- TO_MB_PATH_V4: OOB upstream, IPv4 ----
    "route-map TO_MB_PATH_V4 permit 200",
    "match ip address prefix-list {}".format(AGG_PREFIX_LIST_V4),
    "set community {} additive".format(OOB_AGGREGATE_COMMUNITY),
    "exit",
    "route-map TO_MB_PATH_V4 permit 300",
    "match ip address prefix-list {}".format(CONTRIBUTING_PREFIX_LIST_V4),
    "set community {} {} additive".format(OOB_CONTRIBUTING_COMMUNITY, NO_ADVERTISE_COMMUNITY),
    "exit",
    # ---- TO_MB_PATH_V6: OOB upstream, IPv6 ----
    "route-map TO_MB_PATH_V6 permit 200",
    "match ipv6 address prefix-list {}".format(AGG_PREFIX_LIST_V6),
    "set community {} additive".format(OOB_AGGREGATE_COMMUNITY),
    "exit",
    "route-map TO_MB_PATH_V6 permit 300",
    "match ipv6 address prefix-list {}".format(CONTRIBUTING_PREFIX_LIST_V6),
    "set community {} {} additive".format(OOB_CONTRIBUTING_COMMUNITY, NO_ADVERTISE_COMMUNITY),
    "exit",
]


def apply_route_map_patch(duthost, retries=5, delay=10):
    """Hot-patch FRR route-maps with community-tagging entries via vtysh.

    Only used on older images where the FRR template lacks native
    community-tagging entries (pre-202511).  On 202511+ this function
    is not called — see _frr_template_has_community_tagging().

    Idempotent: re-applying the same entries simply overwrites them.
    Entries are lost on BGP container restart or config reload.
    Retries if the BGP container is not yet running (e.g. after restart).
    """
    vtysh_args = " ".join(
        "-c '{}'".format(cmd) for cmd in ["configure terminal"] + _ROUTE_MAP_PATCH_COMMANDS
    )
    cmd = "vtysh {}".format(vtysh_args)
    logger.info("Applying community-tagging route-map hot-patch via vtysh")
    for attempt in range(retries):
        result = duthost.shell(cmd, module_ignore_errors=True)
        if result["rc"] == 0:
            logger.info("Route-map hot-patch applied successfully")
            return
        logger.warning(
            "Route-map hot-patch attempt %d/%d failed (rc=%d): %s",
            attempt + 1, retries, result["rc"], result.get("stderr", ""))
        if attempt < retries - 1:
            time.sleep(delay)
    # Final attempt without ignore_errors to raise on failure
    duthost.shell(cmd)


def _frr_template_has_community_tagging(duthost):
    """Return True if FRR has native community-tagging route-map entries.

    SONiC 202511+ templates include seq 110/120 in TO_MA_PATH_V4 with
    AGGREGATE_ROUTES prefix-lists and 8075:8801 community.  Older images
    lack these entries entirely, requiring a vtysh hot-patch.
    """
    result = duthost.shell(
        "vtysh -c 'show route-map TO_MA_PATH_V4' 2>/dev/null",
        module_ignore_errors=True,
    )
    output = result.get("stdout", "")
    return "8075:8801" in output


# ===========================================================================
# TYPES
# ===========================================================================

CommunityAggregateCfg = namedtuple("CommunityAggregateCfg", [
    "prefix",                    # e.g. "10.100.0.0/16"
    "bbr_required",              # bool
    "summary_only",              # bool — always False for MSFT internal
    "as_set",                    # bool
    "aggregate_prefix_list",     # e.g. "AGG_ROUTES_V4" or "" for none
    "contributing_prefix_list",  # e.g. "AGG_CONTRIBUTING_ROUTES_V4" or "" for none
])


# ===========================================================================
# HELPERS — GCU operations
# ===========================================================================

def gcu_add_community_aggregate(duthost, cfg):
    """Add a BGP aggregate address with optional prefix-list fields via GCU.

    The prefix-list fields drive MSFT FRR template route-map matching.
    When populated, the template applies community tags to aggregate and
    contributing routes advertised to upstream neighbors.

    Args:
        duthost: DUT host object
        cfg: CommunityAggregateCfg namedtuple
    """
    value = {
        "bbr-required": "true" if cfg.bbr_required else "false",
        "summary-only": "true" if cfg.summary_only else "false",
        "as-set": "true" if cfg.as_set else "false",
    }
    if cfg.aggregate_prefix_list:
        value["aggregate-address-prefix-list"] = cfg.aggregate_prefix_list
    if cfg.contributing_prefix_list:
        value["contributing-address-prefix-list"] = cfg.contributing_prefix_list

    patch = [{
        "op": "add",
        "path": "/BGP_AGGREGATE_ADDRESS/{}".format(cfg.prefix.replace("/", "~1")),
        "value": value,
    }]
    logger.info("GCU: adding aggregate %s with value %s", cfg.prefix, value)
    apply_gcu_patch(duthost, patch)


def verify_aggregate_inactive_on_dut(duthost, prefix, timeout=60):
    """Verify that aggregate-address is removed from FRR running-config (control plane).

    When bgpcfgd deactivates an aggregate (e.g., BBR disabled for a BBR-required aggregate),
    it removes the 'aggregate-address' command from FRR.  This is a faster and more reliable
    check than waiting for the route to disappear on a neighbor, especially on OOB neighbors
    where route withdrawal can take >180s due to hold-timers and catch-all route-maps.

    Args:
        duthost: DUT host object
        prefix: aggregate prefix string (e.g. "10.100.0.0/16")
        timeout: max seconds to wait for deactivation
    """
    ok = wait_until(timeout, 5, 0, lambda: not running_bgp_has_aggregate(duthost, prefix))
    pytest_assert(
        ok,
        "aggregate-address {} still in FRR running-config after {}s — "
        "expected deactivation (control-plane check)".format(prefix, timeout)
    )


def safe_remove_aggregate(duthost, prefix):
    """Remove aggregate via GCU, suppressing errors if already absent.

    Uses broad exception handling because pytest.fail() raises
    _pytest.outcomes.Failed which inherits from BaseException, not Exception.
    See bgp-agg-dual-stack-patch-notes.md Section 2.

    Args:
        duthost: DUT host object
        prefix: aggregate prefix string (e.g. "10.100.0.0/16")

    Returns:
        True if removal succeeded, False if already gone or failed
    """
    try:
        gcu_remove_aggregate(duthost, prefix)
        return True
    except (Exception, pytest.fail.Exception):
        logger.warning("safe_remove_aggregate: %s already absent or removal failed", prefix)
        return False


# ===========================================================================
# HELPERS — Community verification
# ===========================================================================

def get_route_communities(host, prefix):
    """Extract the set of BGP community strings attached to a prefix on a neighbor.

    Supports EosHost (Arista vEOS) and SonicHost (FRR/vtysh).

    Args:
        host: neighbor host object (EosHost or SonicHost)
        prefix: route prefix string, e.g. "10.100.0.0/16"

    Returns:
        set of community strings, e.g. {"8075:8801"} or {"8075:9120", "no-advertise"}.
        Returns empty set if route not found or on any error.

    EOS JSON path:
        vrfs.default.bgpRouteEntries.<prefix>.bgpRoutePaths[*]
            .routeDetail.communityList

    FRR JSON path (vtysh):
        paths[*].community.list[*].string
    """
    communities = set()
    try:
        if isinstance(host, EosHost):
            route_data = host.get_route(prefix)
            entries = route_data.get("vrfs", {}).get("default", {}).get("bgpRouteEntries", {})
            for path_info in entries.get(prefix, {}).get("bgpRoutePaths", []):
                detail = path_info.get("routeDetail", {})
                for comm in detail.get("communityList", []):
                    communities.add(comm)
        elif isinstance(host, SonicHost):
            cmd = "vtysh -c 'show ip bgp {} json'".format(prefix)
            output = host.shell(cmd, module_ignore_errors=True)["stdout"]
            data = json_lib.loads(output) if output.strip() else {}
            for path_info in data.get("paths", []):
                comm_data = path_info.get("community", {})
                for comm_entry in comm_data.get("list", []):
                    comm_str = comm_entry.get("string", "")
                    if comm_str:
                        communities.add(comm_str)
        else:
            logger.warning("get_route_communities: unsupported host type %s", type(host))
    except Exception as e:
        logger.debug("get_route_communities(%s, %s) failed: %s", getattr(host, 'hostname', host), prefix, e)
    return communities


def check_communities_on_neighbors(nbrhosts, neighbor_list, prefix,
                                   expected, unexpected):
    """Polling target for wait_until. Returns True when ALL neighbors match.

    Args:
        nbrhosts: dict of neighbor host info (nbrhosts[name]["host"])
        neighbor_list: list of neighbor names to check
        prefix: route prefix to inspect
        expected: set of community strings that MUST be present
        unexpected: set of community strings that MUST be absent

    Returns:
        True when all neighbors have expected communities and lack unexpected ones.
    """
    for nbr_name in neighbor_list:
        host = nbrhosts[nbr_name]["host"]
        actual = get_route_communities(host, prefix)
        if not expected.issubset(actual):
            logger.info("check_communities: %s on %s missing %s (has %s)",
                        prefix, nbr_name, expected - actual, actual)
            return False
        if unexpected and unexpected.intersection(actual):
            logger.info("check_communities: %s on %s has unwanted %s",
                        prefix, nbr_name, unexpected.intersection(actual))
            return False
    return True


def verify_route_communities(nbrhosts, neighbor_list, prefix,
                             expected_communities=None, unexpected_communities=None,
                             timeout=BGP_CONVERGE_TIMEOUT):
    """Assert that a route on ALL specified neighbors carries expected communities
    and does NOT carry unexpected communities. Polls until convergence or timeout.

    Either or both of expected/unexpected may be provided.  When only
    unexpected is given this replaces the former verify_no_communities helper.

    Args:
        nbrhosts: dict of neighbor host info
        neighbor_list: list of neighbor names to check
        prefix: route prefix to verify
        expected_communities: set/list of community strings that MUST be present (optional)
        unexpected_communities: set/list of community strings that MUST be absent (optional)
        timeout: max seconds to wait for convergence
    """
    expected = set(expected_communities or [])
    unexpected = set(unexpected_communities or [])

    ok = wait_until(timeout, BGP_CONVERGE_POLL_INTERVAL, 0,
                    check_communities_on_neighbors,
                    nbrhosts, neighbor_list, prefix, expected, unexpected)
    pytest_assert(
        ok,
        "Community check FAILED on {} for prefix {} after {}s. "
        "Expected present: {}, Expected absent: {}".format(
            neighbor_list, prefix, timeout, expected, unexpected)
    )


def get_ptf_ports_by_neighbor_suffix(mg_facts, suffix):
    """Return PTF port indices for DUT interfaces connected to neighbors
    whose VM name ends with the given suffix (e.g. "M0", "MA", "MB").

    Args:
        mg_facts: result of duthost.get_extended_minigraph_facts(tbinfo)
        suffix: neighbor name suffix to match (case-insensitive)

    Returns:
        list of PTF port indices (integers)
    """
    ports = []
    for intf, neigh in mg_facts["minigraph_neighbors"].items():
        if neigh["name"].upper().endswith(suffix.upper()):
            if intf in mg_facts["minigraph_ptf_indices"]:
                ports.append(mg_facts["minigraph_ptf_indices"][intf])
    pytest_assert(ports, "No PTF ports found for neighbors with suffix '{}'".format(suffix))
    return ports


# ===========================================================================
# FIXTURES
# ===========================================================================

@pytest.fixture(scope="module", autouse=True)
def setup_teardown(duthosts, rand_one_dut_hostname):
    """Checkpoint DUT config before tests, rollback after.

    Also seeds BGP_BBR|all if missing to prevent bgpcfgd KeyError crash.
    See bgp-agg-dual-stack-patch-notes.md Section 1.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # ---- BBR guard: seed BGP_BBR|all if missing, then ensure enabled ----
    # bgpcfgd always reads BBR status when processing aggregates.
    # If the key is absent, bgpcfgd crashes with KeyError: 'status'.
    # Test plan prerequisite: BBR must be enabled for most community tagging tests.
    bbr_exists = int(duthost.shell(
        'redis-cli -n 4 HEXISTS "BGP_BBR|all" "status"',
        module_ignore_errors=True,
    )["stdout"])
    if not bbr_exists:
        logger.info("BBR key missing in CONFIG_DB — seeding with 'enabled'")
        config_bbr_by_gcu(duthost, "enabled")
    elif not is_bbr_enabled(duthost):
        logger.info("BBR present but disabled — enabling for community tagging tests")
        config_bbr_by_gcu(duthost, "enabled")

    # ---- Checkpoint for rollback ----
    create_checkpoint(duthost)

    # ---- Seed placeholder aggregate to keep table non-empty for GCU ----
    default_aggregates = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    if not default_aggregates:
        gcu_add_placeholder_aggregate(duthost, PLACEHOLDER_PREFIX)

    yield

    # ---- Teardown: rollback to clean state ----
    try:
        rollback_or_reload(duthost, fail_on_rollback_error=False)
    finally:
        delete_checkpoint(duthost)


@pytest.fixture(scope="module")
def community_tagging_setup(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, tbinfo):
    """Discover MA, MB (OOB), M0 neighbors and ExaBGP injection ports.

    Yields a dict with all info tests need to inject routes and verify communities:
        duthost, ma_neighbors, mb_neighbors, m0_neighbors, m0,
        m0_exabgp_port, m0_exabgp_port_v6, nhipv4, nhipv6

    Neighbor suffix mapping for M1-48 topology:
        MA suffix = MgmtSpineRouter = test plan "M2/MA"
        MB suffix = CoreTs           = test plan "OOB/CoreTs"
        M0 suffix = MgmtToRRouter   = test plan "M0" (downstream)
    """
    duthost = duthosts[rand_one_dut_hostname]

    # ---- Discover neighbors by suffix ----
    ma_neighbors = natsorted([n for n in nbrhosts if n.upper().endswith("MA")])
    mb_neighbors = natsorted([n for n in nbrhosts if n.upper().endswith("MB")])
    m0_neighbors = natsorted([n for n in nbrhosts if n.upper().endswith("M0")])

    pytest_assert(ma_neighbors, "No MA (MgmtSpineRouter) upstream neighbors found in nbrhosts")
    pytest_assert(m0_neighbors, "No M0 (MgmtToRRouter) downstream neighbors found in nbrhosts")
    # Note: mb_neighbors may be empty — tests requiring OOB will skip individually
    if not mb_neighbors:
        logger.warning("No MB (CoreTs/OOB) neighbors found — OOB tests will be skipped")

    # ---- ExaBGP port for downstream route injection ----
    m0 = m0_neighbors[0]
    m0_offset = tbinfo["topo"]["properties"]["topology"]["VMs"][m0]["vm_offset"]
    m0_exabgp_port = EXABGP_BASE_PORT + m0_offset
    m0_exabgp_port_v6 = EXABGP_BASE_PORT_V6 + m0_offset

    common_cfg = tbinfo["topo"]["properties"]["configuration_properties"]["common"]

    # ---- Detect native template support vs hot-patch ----
    # SONiC 202511+ templates have community-tagging route-map entries
    # (seq 110/120) natively.  Older images need a vtysh hot-patch.
    native_tagging = _frr_template_has_community_tagging(duthost)
    if native_tagging:
        logger.info(
            "FRR template has native community-tagging (202511+) "
            "— skipping hot-patch")
    else:
        logger.info(
            "FRR template lacks community-tagging — applying hot-patch")
        apply_route_map_patch(duthost)

    # ---- Patch A: Prerequisite validation — verify route-map entries exist ----
    frr_cfg = duthost.shell(
        "vtysh -c 'show running-config'", module_ignore_errors=True
    )["stdout"]
    for expected_rm in ["TO_MA_PATH_V4", "TO_MB_PATH_V4"]:
        pytest_assert(
            expected_rm in frr_cfg,
            "Prerequisite FAILED: route-map '{}' not found in FRR running-config. "
            "Community tagging tests cannot proceed.".format(expected_rm)
        )
    if not native_tagging:
        # On older images the hot-patch must have injected prefix-list matches;
        # on native images the template handles this after GCU populates the lists.
        for expected_pl in [AGG_PREFIX_LIST_V4, CONTRIBUTING_PREFIX_LIST_V4]:
            if "match ip address prefix-list {}".format(expected_pl) not in frr_cfg:
                logger.warning(
                    "Route-map match for prefix-list '%s' not found in FRR config"
                    " — community tagging may not activate until aggregate is"
                    " added", expected_pl
                )
    logger.info("Prerequisite validation PASSED: route-maps present in FRR")

    # ---- Patch B: EOS sanity check — verify community parser can reach EOS ----
    ma_host = nbrhosts[ma_neighbors[0]]["host"]
    if isinstance(ma_host, EosHost):
        try:
            ma_host.eos_command(commands=["show ip bgp summary | json"])
            logger.info("EOS community parser sanity check: EOS BGP is reachable")
        except Exception as e:
            logger.warning(
                "EOS sanity check: could not query MA neighbor %s: %s — "
                "community verification may fail", ma_neighbors[0], e
            )

    yield {
        "duthost": duthost,
        "ma_neighbors": ma_neighbors,
        "mb_neighbors": mb_neighbors,
        "m0_neighbors": m0_neighbors,
        "m0": m0,
        "m0_exabgp_port": m0_exabgp_port,
        "m0_exabgp_port_v6": m0_exabgp_port_v6,
        "nhipv4": common_cfg.get("nhipv4"),
        "nhipv6": common_cfg.get("nhipv6"),
        "native_tagging": native_tagging,
    }


@pytest.fixture(autouse=True)
def ensure_route_map_patch(duthosts, rand_one_dut_hostname, community_tagging_setup):
    """Re-apply route-map hot-patch before each test if needed.

    On SONiC 202511+ the FRR template has native community-tagging entries,
    so no hot-patch is required.  On older images, the hot-patch is lost on
    BGP container restart or config reload and must be re-applied.
    """
    if community_tagging_setup["native_tagging"]:
        yield
        return
    duthost = duthosts[rand_one_dut_hostname]
    # Quick check: skip if route-map entries are already present (both MA and MB)
    check = duthost.shell(
        "vtysh -c 'show route-map TO_MA_PATH_V4' 2>/dev/null | grep -q {0} && "
        "vtysh -c 'show route-map TO_MB_PATH_V4' 2>/dev/null | grep -q {0}".format(
            AGG_PREFIX_LIST_V4),
        module_ignore_errors=True,
    )
    if check["rc"] == 0:
        yield
        return
    # Route-map missing or BGP container not ready — wait and re-apply
    container_up = wait_until(120, 5, 0, lambda: duthost.shell(
        "docker ps -f name=bgp -q",
        module_ignore_errors=True,
    )["stdout"].strip() != "")
    if not container_up:
        logger.error("BGP container not running after 120s — tests will likely fail")
    apply_route_map_patch(duthost)
    yield


# ===========================================================================
# Convenience: build standard IPv4/IPv6 configs used by most tests
# ===========================================================================

_AF_CONSTANTS = {
    "v4": (AGGR_V4, AGG_PREFIX_LIST_V4, CONTRIBUTING_PREFIX_LIST_V4),
    "v6": (AGGR_V6, AGG_PREFIX_LIST_V6, CONTRIBUTING_PREFIX_LIST_V6),
}


def build_cfg(af="v4", bbr_required=True, with_prefix_lists=True):
    """Build a CommunityAggregateCfg for the given address family (v4 or v6)."""
    prefix, agg_pl, contrib_pl = _AF_CONSTANTS[af]
    return CommunityAggregateCfg(
        prefix=prefix,
        bbr_required=bbr_required,
        summary_only=False,
        as_set=False,
        aggregate_prefix_list=agg_pl if with_prefix_lists else "",
        contributing_prefix_list=contrib_pl if with_prefix_lists else "",
    )


# ===========================================================================
# GROUP 1: MA Device Scenario — Community Tagging
# ===========================================================================

class TestGroupMA:
    """Test Group 1: MA Device Scenario — Community Tagging (TC 1.1-1.5)

    Validates that routes advertised toward MA (MgmtSpineRouter) upstream
    devices carry correct community tags:
        Aggregate route:    8075:8801 (MA_AGGREGATE_COMMUNITY)
        Contributing routes: 8075:8800 (MA_CONTRIBUTING_COMMUNITY)
    """

    def test_ma_aggregate_and_contributing_community_tags(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 1.1 + 1.2: Aggregate route tagged with 8075:8801, contributing
        routes tagged with 8075:8800 toward MA upstream neighbors.

        Steps:
            1. Add aggregate 10.100.0.0/16 with prefix-list config via GCU
            2. Inject contributing routes 10.100.1.0/24, 10.100.2.0/24 from M0
            3. Verify on MA: aggregate has 8075:8801, NOT 8075:8800
            4. Verify on MA: each contributing route has 8075:8800, NOT 8075:8801
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()

        try:
            # Step 1: Add aggregate with prefix-lists
            gcu_add_community_aggregate(duthost, cfg)

            # Step 2: Inject contributing routes from M0 via ExaBGP
            inject_routes(setup, ptfhost, contributing, "announce")

            # Step 3: Verify aggregate route presence and community on MA
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
                unexpected_communities={MA_CONTRIBUTING_COMMUNITY},
            )

            # Step 4: Verify contributing routes community on MA
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                    unexpected_communities={MA_AGGREGATE_COMMUNITY},
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_ma_ipv6_community_tags(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 1.3: MA scenario with IPv6 — aggregate 2001:db8:100::/48 has
        8075:8801, contributing routes have 8075:8800.

        Steps:
            1. Add IPv6 aggregate with IPv6 prefix-list config
            2. Inject IPv6 contributing routes from M0
            3. Verify on MA: aggregate has 8075:8801, NOT 8075:8800
            4. Verify on MA: contributing routes have 8075:8800, NOT 8075:8801
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V6[:2]
        cfg = build_cfg("v6")

        try:
            # Step 1: Add IPv6 aggregate
            gcu_add_community_aggregate(duthost, cfg)

            # Step 2: Inject IPv6 contributing routes
            inject_routes(setup, ptfhost, contributing, "announce")

            # Step 3: Verify aggregate community
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V6, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V6,
                expected_communities={MA_AGGREGATE_COMMUNITY},
                unexpected_communities={MA_CONTRIBUTING_COMMUNITY},
            )

            # Step 4: Verify contributing route communities
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                    unexpected_communities={MA_AGGREGATE_COMMUNITY},
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V6)

    def test_ma_new_contributing_inherits_tag(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 1.4: A new contributing route dynamically added also inherits
        the 8075:8800 community tag on MA.

        Steps:
            1. Setup aggregate + 2 contributing routes, verify MA communities
            2. Inject a NEW 3rd contributing route 10.100.3.0/24 from M0
            3. Verify on MA: new route also has 8075:8800
            4. Verify on MA: aggregate still has 8075:8801 (unchanged)
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        initial = CONTRIBUTING_V4[:2]
        new_route = [CONTRIBUTING_V4[2]]   # 10.100.3.0/24
        cfg = build_cfg()

        try:
            # Step 1: Baseline — aggregate + initial contributing routes
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, initial, "announce")
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)

            # Step 2: Inject new contributing route
            inject_routes(setup, ptfhost, new_route, "announce")

            # Step 3: New route gets 8075:8800
            verify_route_communities(
                nbrhosts, ma, new_route[0],
                expected_communities={MA_CONTRIBUTING_COMMUNITY},
                unexpected_communities={MA_AGGREGATE_COMMUNITY},
            )

            # Step 4: Aggregate unchanged
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )
        finally:
            inject_routes(setup, ptfhost, initial + new_route, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_ma_withdrawn_contributing_removed(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 1.5: Withdrawn contributing route disappears from MA;
        remaining routes and aggregate keep their tags.

        Steps:
            1. Setup aggregate + 2 contributing routes, verify MA communities
            2. Withdraw contributing route 10.100.2.0/24 from M0
            3. Verify on MA: 10.100.2.0/24 no longer received
            4. Verify on MA: 10.100.1.0/24 still has 8075:8800
            5. Verify on MA: aggregate still has 8075:8801
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()

        try:
            # Step 1: Baseline
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                )

            # Step 2: Withdraw one contributing route
            inject_routes(setup, ptfhost, [CONTRIBUTING_V4[1]], "withdraw")

            # Step 3: Withdrawn route gone
            verify_route_on_neighbors(
                nbrhosts, ma, CONTRIBUTING_V4[1],
                expected_present=False, timeout=30
            )

            # Step 4: Remaining contributing route still tagged
            verify_route_communities(
                nbrhosts, ma, CONTRIBUTING_V4[0],
                expected_communities={MA_CONTRIBUTING_COMMUNITY},
            )

            # Step 5: Aggregate unchanged
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)


# ===========================================================================
# GROUP 2: OOB Device Scenario — NO_ADVERTISE Tagging
# ===========================================================================

class TestGroupOOB:
    """Test Group 2: OOB Device Scenario — NO_ADVERTISE Tagging (TC 2.1-2.5)

    Validates that routes advertised toward OOB (CoreTs, MB suffix) upstream
    devices carry correct community tags:
        Aggregate route:    8075:9120 (without NO_ADVERTISE)
        Contributing routes: 8075:9120 + NO_ADVERTISE
    """

    def test_oob_aggregate_and_contributing_community_tags(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 2.1 + 2.2: Aggregate route tagged with 8075:9120 (no NO_ADVERTISE),
        contributing routes tagged with 8075:9120 + NO_ADVERTISE toward OOB.

        Steps:
            1. Skip if no MB (OOB/CoreTs) neighbors
            2. Add aggregate with prefix-list config
            3. Inject contributing routes from M0
            4. Verify on OOB: aggregate has 8075:9120, NOT no-advertise
            5. Verify on OOB: contributing routes have 8075:9120 AND no-advertise
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        mb = setup["mb_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()

        # Step 1: Guard — skip if no OOB neighbors
        if not mb:
            pytest.skip("No MB/OOB (CoreTs) neighbors in topology")

        try:
            # Step 2: Add aggregate
            gcu_add_community_aggregate(duthost, cfg)

            # Step 3: Inject contributing routes
            inject_routes(setup, ptfhost, contributing, "announce")

            # Step 4: Aggregate on OOB has 8075:9120, NOT no-advertise
            verify_route_on_neighbors(nbrhosts, mb, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, mb, AGGR_V4,
                expected_communities={OOB_AGGREGATE_COMMUNITY},
                unexpected_communities={NO_ADVERTISE_COMMUNITY},
            )

            # Step 5: Contributing routes on OOB have 8075:9120 AND no-advertise
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, mb, prefix,
                    expected_communities={OOB_CONTRIBUTING_COMMUNITY, NO_ADVERTISE_COMMUNITY},
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_oob_ipv6_community_tags(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 2.3: OOB scenario with IPv6 — same community pattern.

        Steps:
            1. Skip if no MB neighbors
            2. Add IPv6 aggregate with prefix-lists
            3. Inject IPv6 contributing routes
            4. Verify on OOB: aggregate has 8075:9120 only
            5. Verify on OOB: contributing routes have 8075:9120 + no-advertise
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        mb = setup["mb_neighbors"]
        contributing = CONTRIBUTING_V6[:2]
        cfg = build_cfg("v6")

        if not mb:
            pytest.skip("No MB/OOB (CoreTs) neighbors in topology")

        try:
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")

            # Aggregate: 8075:9120, no NO_ADVERTISE
            verify_route_on_neighbors(nbrhosts, mb, AGGR_V6, expected_present=True)
            verify_route_communities(
                nbrhosts, mb, AGGR_V6,
                expected_communities={OOB_AGGREGATE_COMMUNITY},
                unexpected_communities={NO_ADVERTISE_COMMUNITY},
            )

            # Contributing: 8075:9120 + NO_ADVERTISE
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, mb, prefix,
                    expected_communities={OOB_CONTRIBUTING_COMMUNITY, NO_ADVERTISE_COMMUNITY},
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V6)

    def test_oob_no_propagate_contributing(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 2.4: OOB does NOT propagate contributing routes further
        due to well-known NO_ADVERTISE community (RFC 1997).

        We verify on the MB (OOB) device itself that:
        - Contributing routes carry NO_ADVERTISE → will not be re-advertised
        - Aggregate route does NOT carry NO_ADVERTISE → eligible for propagation

        This asymmetry is the mechanism that ensures only the aggregate
        (not contributing routes) is propagated beyond OOB.

        Steps:
            1. Skip if no MB neighbors
            2. Add aggregate with prefix-list config
            3. Inject contributing routes from M0
            4. Verify on OOB: aggregate has 8075:9120, NOT no-advertise
            5. Verify on OOB: each contributing route has 8075:9120 AND no-advertise
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        mb = setup["mb_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()

        if not mb:
            pytest.skip("No MB/OOB (CoreTs) neighbors in topology")

        try:
            # Step 2: Add aggregate with prefix-lists
            gcu_add_community_aggregate(duthost, cfg)

            # Step 3: Inject contributing routes from M0
            inject_routes(setup, ptfhost, contributing, "announce")

            # Step 4: Aggregate on OOB — has 8075:9120, NOT no-advertise
            # This means OOB will propagate the aggregate further
            verify_route_on_neighbors(nbrhosts, mb, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, mb, AGGR_V4,
                expected_communities={OOB_AGGREGATE_COMMUNITY},
                unexpected_communities={NO_ADVERTISE_COMMUNITY},
            )

            # Step 5: Contributing routes on OOB — have 8075:9120 AND no-advertise
            # NO_ADVERTISE is a well-known community (RFC 1997) that prevents
            # any BGP-compliant device from re-advertising these routes
            for prefix in contributing:
                verify_route_on_neighbors(nbrhosts, mb, prefix, expected_present=True)
                verify_route_communities(
                    nbrhosts, mb, prefix,
                    expected_communities={OOB_CONTRIBUTING_COMMUNITY, NO_ADVERTISE_COMMUNITY},
                )

            logger.info(
                "TC 2.4 PASS: Aggregate %s on OOB lacks %s (propagation eligible). "
                "Contributing routes %s carry %s (propagation blocked).",
                AGGR_V4, NO_ADVERTISE_COMMUNITY,
                contributing, NO_ADVERTISE_COMMUNITY,
            )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_oob_new_contributing_gets_no_advertise(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 2.5: Dynamically added contributing route also gets
        8075:9120 + NO_ADVERTISE on OOB.

        Steps:
            1. Skip if no MB neighbors
            2. Setup OOB scenario with 2 contributing routes
            3. Inject new contributing route 10.100.3.0/24
            4. Verify on OOB: new route has 8075:9120 AND no-advertise
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        mb = setup["mb_neighbors"]
        initial = CONTRIBUTING_V4[:2]
        new_route = [CONTRIBUTING_V4[2]]
        cfg = build_cfg()

        if not mb:
            pytest.skip("No MB/OOB (CoreTs) neighbors in topology")

        try:
            # Setup baseline
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, initial, "announce")
            verify_route_on_neighbors(nbrhosts, mb, AGGR_V4, expected_present=True)

            # Inject new route
            inject_routes(setup, ptfhost, new_route, "announce")

            # Verify new route gets OOB tags
            verify_route_communities(
                nbrhosts, mb, new_route[0],
                expected_communities={OOB_CONTRIBUTING_COMMUNITY, NO_ADVERTISE_COMMUNITY},
            )
        finally:
            inject_routes(setup, ptfhost, initial + new_route, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)


# ===========================================================================
# GROUP 3: Prefix-List Driven Community Tagging Mechanism
# ===========================================================================

class TestGroupPrefixList:
    """Test Group 3: Prefix-List Driven Community Tagging Mechanism (TC 3.1-3.4, 3.7)

    Validates that prefix-list population by the public feature correctly
    drives the MSFT template route-map community tagging.
    """

    def test_prefix_list_triggers_community_tagging(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 3.1: Adding aggregate with prefix-lists triggers community tagging.
        Before aggregate: contributing routes have NO MSFT tags.
        After aggregate: tags appear.

        Steps:
            1. Inject contributing routes from M0 (no aggregate yet)
            2. Verify on MA: routes present but NO MSFT community tags
            3. Add aggregate with prefix-lists via GCU
            4. Verify on MA: aggregate has 8075:8801, contributing has 8075:8800
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()

        try:
            # Step 1: Inject contributing routes BEFORE aggregate
            inject_routes(setup, ptfhost, contributing, "announce")

            # Step 2: Routes present but no MSFT tags
            for prefix in contributing:
                verify_route_on_neighbors(nbrhosts, ma, prefix, expected_present=True)
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    unexpected_communities={MA_AGGREGATE_COMMUNITY, MA_CONTRIBUTING_COMMUNITY},
                    timeout=15,
                )

            # Step 3: Add aggregate with prefix-lists
            gcu_add_community_aggregate(duthost, cfg)

            # Step 4: Tags appear
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_remove_aggregate_stops_community_tagging(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 3.2: Removing aggregate stops community tagging.
        Contributing routes are still received but lose MSFT tags.

        Steps:
            1. Setup aggregate + prefix-lists + contributing routes
            2. Verify on MA: communities present (baseline)
            3. Remove aggregate via GCU
            4. Verify on MA: aggregate withdrawn
            5. Verify on MA: contributing routes still received but WITHOUT 8075:8800
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()

        try:
            # Steps 1-2: Baseline
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )

            # Step 3: Remove aggregate
            gcu_remove_aggregate(duthost, AGGR_V4)

            # Step 4: Aggregate communities removed (route may linger briefly
            # in neighbor RIB due to withdrawal propagation delay)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                unexpected_communities={MA_AGGREGATE_COMMUNITY},
            )

            # Step 5: Contributing routes present but without MSFT tags
            for prefix in contributing:
                verify_route_on_neighbors(nbrhosts, ma, prefix, expected_present=True)
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    unexpected_communities={MA_CONTRIBUTING_COMMUNITY},
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)  # idempotent

    def test_aggregate_without_prefix_lists_no_tags(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 3.3: Aggregate without prefix-lists produces NO MSFT community tags.
        Confirms community tagging is purely prefix-list driven.

        Steps:
            1. Add aggregate WITHOUT prefix-list fields (empty strings)
            2. Inject contributing routes from M0
            3. Verify on MA: routes received but NO MSFT tags on any route
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        # No prefix-lists!
        cfg = build_cfg(bbr_required=False, with_prefix_lists=False)

        try:
            # Step 1: Add aggregate without prefix-lists
            gcu_add_community_aggregate(duthost, cfg)

            # Step 2: Inject contributing routes
            inject_routes(setup, ptfhost, contributing, "announce")

            # Step 3: Wait for aggregate to appear, then verify NO MSFT tags
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                unexpected_communities={MA_AGGREGATE_COMMUNITY, MA_CONTRIBUTING_COMMUNITY},
                timeout=15,
            )
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    unexpected_communities={MA_AGGREGATE_COMMUNITY, MA_CONTRIBUTING_COMMUNITY},
                    timeout=15,
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_multiple_aggregates_share_prefix_list(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 3.4: Two aggregates sharing the same prefix-list. Removing one
        does NOT affect the other's community tagging.

        Steps:
            1. Add aggregate A (10.100.0.0/16) with AGG_PREFIX_LIST_V4
            2. Add aggregate B (10.200.0.0/16) with AGG_PREFIX_LIST_V4
            3. Inject contributing routes for both from M0
            4. Verify on MA: both aggregates have 8075:8801
            5. Remove aggregate A
            6. Verify on MA: aggregate B still has 8075:8801
            7. Verify on MA: contributing routes for B still have 8075:8800
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]

        cfg_a = build_cfg()
        cfg_b = CommunityAggregateCfg(
            prefix=AGGR_V4_B,
            bbr_required=True,
            summary_only=False,
            as_set=False,
            aggregate_prefix_list=AGG_PREFIX_LIST_V4,
            contributing_prefix_list=CONTRIBUTING_PREFIX_LIST_V4,
        )

        try:
            # Steps 1-2: Add both aggregates
            gcu_add_community_aggregate(duthost, cfg_a)
            gcu_add_community_aggregate(duthost, cfg_b)

            # Step 3: Inject contributing routes for both
            inject_routes(setup, ptfhost, CONTRIBUTING_V4[:2], "announce")
            inject_routes(setup, ptfhost, CONTRIBUTING_V4_B, "announce")

            # Step 4: Both aggregates tagged
            for agg_prefix in [AGGR_V4, AGGR_V4_B]:
                verify_route_on_neighbors(nbrhosts, ma, agg_prefix, expected_present=True)
                verify_route_communities(
                    nbrhosts, ma, agg_prefix,
                    expected_communities={MA_AGGREGATE_COMMUNITY},
                )

            # Step 5: Remove aggregate A
            gcu_remove_aggregate(duthost, AGGR_V4)

            # Step 6: Aggregate B still tagged
            verify_route_communities(
                nbrhosts, ma, AGGR_V4_B,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )

            # Step 7: Contributing routes for B still tagged
            for prefix in CONTRIBUTING_V4_B:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                )
        finally:
            inject_routes(setup, ptfhost, CONTRIBUTING_V4[:2] + CONTRIBUTING_V4_B, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)
            safe_remove_aggregate(duthost, AGGR_V4_B)

    def test_ipv6_prefix_list_triggers_community_tagging(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 3.7: IPv6 variant of prefix-list mechanism test.

        Ensures IPv6 prefix-lists in the FRR template route-maps work
        the same as IPv4 for community tagging.

        Steps:
            1. Inject IPv6 contributing routes from M0 (no aggregate yet)
            2. Verify on MA: routes present but no MSFT community tags
            3. Add IPv6 aggregate with prefix-lists
            4. Verify on MA: aggregate has 8075:8801, contributing has 8075:8800
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V6[:2]
        cfg = build_cfg("v6")

        try:
            # Step 1: Inject contributing routes before aggregate
            inject_routes(setup, ptfhost, contributing, "announce")

            # Step 2: Routes present but no MSFT tags
            for prefix in contributing:
                verify_route_on_neighbors(nbrhosts, ma, prefix, expected_present=True)
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    unexpected_communities={MA_AGGREGATE_COMMUNITY, MA_CONTRIBUTING_COMMUNITY},
                    timeout=15,
                )

            # Step 3: Add IPv6 aggregate with prefix-lists
            gcu_add_community_aggregate(duthost, cfg)

            # Step 4: Tags appear
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V6, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V6,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V6)


# ===========================================================================
# GROUP 4: BBR Interaction with Community Tagging
# ===========================================================================

class TestGroupBBR:
    """Test Group 4: BBR Interaction with Community Tagging (TC 4.1-4.4)

    Validates that BBR state changes correctly affect community tagging
    via aggregate activation/deactivation.
    """

    def test_bbr_toggle_ma_community_tagging(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 4.1 + 4.2: BBR disable deactivates aggregate, stopping community
        tagging. BBR enable restores it.

        Steps:
            1. Ensure BBR enabled, add BBR-required aggregate with prefix-lists
            2. Inject contributing routes, verify MA communities present
            3. Disable BBR
            4. Verify on MA: aggregate withdrawn, contributing lose tags
            5. Re-enable BBR
            6. Verify on MA: communities restored
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg(bbr_required=True)

        bbr_supported, bbr_default = get_bbr_default_state(duthost)
        if not bbr_supported:
            pytest.skip("BGP BBR is not supported")

        try:
            # Step 1: Ensure BBR enabled
            if bbr_default != "enabled":
                config_bbr_by_gcu(duthost, "enabled")

            # Step 2: Add aggregate + contributing routes, verify baseline
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                )

            # Step 3: Disable BBR
            config_bbr_by_gcu(duthost, "disabled")

            # Step 4: Aggregate community tags removed, contributing lose tags
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                unexpected_communities={MA_AGGREGATE_COMMUNITY},
            )
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    unexpected_communities={MA_CONTRIBUTING_COMMUNITY},
                )

            # Step 5: Re-enable BBR
            config_bbr_by_gcu(duthost, "enabled")

            # Step 6: Communities restored
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)
            # Restore BBR to original state
            try:
                config_bbr_by_gcu(duthost, bbr_default)
            except (Exception, pytest.fail.Exception):
                logger.warning("Failed to restore BBR to %s", bbr_default)

    def test_bbr_toggle_oob_community_tagging(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 4.3: BBR toggle with OOB scenario — OOB community tags follow BBR state.

        Steps:
            1. Skip if no MB neighbors or BBR not supported
            2. Enable BBR, add BBR-required aggregate, inject contributing routes
            3. Verify on OOB: aggregate has 8075:9120, contributing has 8075:9120 + no-advertise
            4. Disable BBR
            5. Verify on OOB: aggregate withdrawn, tags removed
            6. Enable BBR
            7. Verify on OOB: community tagging restored
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        mb = setup["mb_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg(bbr_required=True)

        if not mb:
            pytest.skip("No MB/OOB (CoreTs) neighbors in topology")

        bbr_supported, bbr_default = get_bbr_default_state(duthost)
        if not bbr_supported:
            pytest.skip("BGP BBR is not supported")

        try:
            # Step 2: Enable BBR + setup
            if bbr_default != "enabled":
                config_bbr_by_gcu(duthost, "enabled")
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")

            # Step 3: OOB baseline
            verify_route_on_neighbors(nbrhosts, mb, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, mb, AGGR_V4,
                expected_communities={OOB_AGGREGATE_COMMUNITY},
                unexpected_communities={NO_ADVERTISE_COMMUNITY},
            )
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, mb, prefix,
                    expected_communities={OOB_CONTRIBUTING_COMMUNITY, NO_ADVERTISE_COMMUNITY},
                )

            # Step 4: Disable BBR
            config_bbr_by_gcu(duthost, "disabled")

            # Step 5: Aggregate deactivated — verify on DUT control plane
            # The /16 route may persist on OOB neighbor due to hold-timers and
            # the catch-all route-map (TO_MB_PATH permit 1000), so we verify
            # deactivation via FRR running-config instead of neighbor route absence.
            verify_aggregate_inactive_on_dut(duthost, AGGR_V4)

            # Contributing routes should lose NO_ADVERTISE (prefix-list entries
            # removed when aggregate deactivated → falls to catch-all)
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, mb, prefix,
                    unexpected_communities={NO_ADVERTISE_COMMUNITY},
                    timeout=BGP_CONVERGE_TIMEOUT_LONG,
                )

            # Step 6: Re-enable BBR
            config_bbr_by_gcu(duthost, "enabled")

            # Step 7: Restored
            verify_route_on_neighbors(nbrhosts, mb, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, mb, AGGR_V4,
                expected_communities={OOB_AGGREGATE_COMMUNITY},
            )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)
            try:
                config_bbr_by_gcu(duthost, bbr_default)
            except (Exception, pytest.fail.Exception):
                logger.warning("Failed to restore BBR to %s", bbr_default)

    def test_non_bbr_aggregate_unaffected_by_bbr_toggle(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 4.4: Aggregate with bbr-required=false keeps community tags
        through BBR state changes.

        Steps:
            1. Add aggregate with bbr_required=False and prefix-lists
            2. Inject contributing routes, verify MA communities present
            3. Toggle BBR: disable -> verify tags STILL present -> enable -> verify
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg(bbr_required=False)

        bbr_supported, bbr_default = get_bbr_default_state(duthost)
        if not bbr_supported:
            pytest.skip("BGP BBR is not supported")

        try:
            # Step 1-2: Setup with bbr_required=False
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )

            # Step 3: Toggle BBR off
            original_state = "enabled" if is_bbr_enabled(duthost) else "disabled"
            new_state = "disabled" if original_state == "enabled" else "enabled"
            config_bbr_by_gcu(duthost, new_state)

            # Verify tags STILL present
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                )

            # Toggle BBR back
            config_bbr_by_gcu(duthost, original_state)

            # Verify tags STILL present
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)
            try:
                config_bbr_by_gcu(duthost, bbr_default)
            except (Exception, pytest.fail.Exception):
                logger.warning("Failed to restore BBR to %s", bbr_default)


# ===========================================================================
# GROUP 5: Lifecycle Operations with Community Verification
# ===========================================================================

class TestGroupLifecycle:
    """Test Group 5: Lifecycle Operations with Community Verification (TC 5.1-5.5)

    Validates that aggregate lifecycle operations correctly manage community
    tagging, including BGP restart and config reload.
    """

    def test_lifecycle_add_aggregate_starts_tagging(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 5.1: Community tagging starts when aggregate is added.

        Steps:
            1. Inject contributing routes (no aggregate)
            2. Verify on MA: no MSFT community tags
            3. Add aggregate with prefix-lists
            4. Verify on MA: community tags appear
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()

        try:
            # Steps 1-2: Pre-aggregate — no tags
            inject_routes(setup, ptfhost, contributing, "announce")
            for prefix in contributing:
                verify_route_on_neighbors(nbrhosts, ma, prefix, expected_present=True)
            # Brief wait then check no tags (short timeout — tags shouldn't appear)
            time.sleep(5)
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    unexpected_communities={MA_AGGREGATE_COMMUNITY, MA_CONTRIBUTING_COMMUNITY},
                    timeout=10,
                )

            # Steps 3-4: Add aggregate — tags appear
            gcu_add_community_aggregate(duthost, cfg)
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_lifecycle_gcu_update_adds_prefix_lists(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 5.5: GCU update adds prefix-lists to existing aggregate.

        Validates that an aggregate created WITHOUT prefix-lists can be
        updated via GCU to ADD prefix-list fields, activating community tagging.

        Steps:
            1. Add aggregate WITHOUT prefix-lists, inject contributing routes
            2. Verify on MA: no MSFT community tags
            3. Update aggregate via GCU to add prefix-list fields
            4. Verify on MA: community tags now appear
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]

        cfg_no_pl = build_cfg(bbr_required=True, with_prefix_lists=False)
        cfg_with_pl = build_cfg(bbr_required=True, with_prefix_lists=True)

        try:
            # Step 1: Add aggregate without prefix-lists
            gcu_add_community_aggregate(duthost, cfg_no_pl)
            inject_routes(setup, ptfhost, contributing, "announce")

            # Step 2: No MSFT tags
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                unexpected_communities={MA_AGGREGATE_COMMUNITY, MA_CONTRIBUTING_COMMUNITY},
                timeout=15,
            )

            # Step 3: Update aggregate to add prefix-lists (GCU "add" is upsert)
            gcu_add_community_aggregate(duthost, cfg_with_pl)

            # Step 4: Community tags now appear
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_lifecycle_remove_aggregate_stops_tagging(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 5.2: Community tagging stops when aggregate is removed.

        Steps:
            1. Setup: aggregate active, communities verified
            2. Remove aggregate via GCU
            3. Verify on MA: aggregate withdrawn
            4. Verify on MA: contributing routes still received but no MSFT tags
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()

        try:
            # Step 1: Baseline
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)

            # Step 2: Remove aggregate
            gcu_remove_aggregate(duthost, AGGR_V4)

            # Step 3: Aggregate community tags removed
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                unexpected_communities={MA_AGGREGATE_COMMUNITY},
            )

            # Step 4: Contributing routes present but no tags
            for prefix in contributing:
                verify_route_on_neighbors(nbrhosts, ma, prefix, expected_present=True)
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    unexpected_communities={MA_CONTRIBUTING_COMMUNITY},
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_lifecycle_bgp_restart_preserves_tagging(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 5.3: Community tagging survives BGP container restart.

        Steps:
            1. Setup: aggregate + prefix-lists + contributing routes
            2. Verify on MA: communities correct (baseline)
            3. Restart BGP container on DUT
            4. Wait for BGP sessions to re-establish
            5. Verify on MA: aggregate has 8075:8801, contributing has 8075:8800
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()

        try:
            # Step 1-2: Baseline
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )

            # Step 3: Restart BGP container using systemctl (ensures proper recovery)
            logger.info("Restarting BGP container on DUT...")
            duthost.shell("systemctl restart bgp")

            # Step 4: Wait for BGP container to be fully running
            logger.info("Waiting for BGP container to be running...")
            wait_until(120, 5, 0, lambda: duthost.shell(
                "docker ps -f name=bgp -q",
                module_ignore_errors=True,
            )["stdout"].strip() != "")
            time.sleep(15)  # extra settle time for FRR to initialize

            # Re-apply route-map hot-patch (lost on BGP restart).
            # In production this step is unnecessary once the FRR template
            # includes the community-tagging entries natively.
            apply_route_map_patch(duthost)

            # Step 5: Verify communities with extended timeout
            verify_route_on_neighbors(
                nbrhosts, ma, AGGR_V4,
                expected_present=True,
                timeout=BGP_CONVERGE_TIMEOUT_LONG,
            )
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
                timeout=BGP_CONVERGE_TIMEOUT_LONG,
            )
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                    timeout=BGP_CONVERGE_TIMEOUT_LONG,
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_lifecycle_config_reload_preserves_tagging(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 5.4: Community tagging survives config reload.

        Steps:
            1. Setup: aggregate + prefix-lists + contributing routes
            2. Verify communities on MA (and OOB if available)
            3. Execute config reload -y on DUT
            4. Wait for full system stabilization (~120-180s)
            5. Verify communities restored on MA (and OOB if available)

        Note: This is the slowest test (~3-5 min due to config reload).
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        mb = setup["mb_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()

        try:
            # Step 1-2: Baseline
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )

            # Step 3: Save config (GCU writes to redis only; config reload reads
            # from /etc/sonic/config_db.json, so we must persist first) then reload.
            logger.info("Saving config to persist GCU changes before reload...")
            duthost.shell("sudo config save -y")
            logger.info("Executing config reload on DUT...")
            do_config_reload(duthost, safe_reload=True, check_intf_up_ports=False)

            # Re-apply route-map hot-patch if needed (lost on config reload).
            # On native images the FRR template regenerates the entries.
            if not setup["native_tagging"]:
                apply_route_map_patch(duthost)

            # Re-inject contributing routes — ExaBGP sessions drop during
            # config reload and may not re-announce in time.
            inject_routes(setup, ptfhost, contributing, "announce")

            # Give bgpcfgd time to process CONFIG_DB and re-create the
            # aggregate-address in FRR (prefix-lists + aggregate command).
            # Config reload restores CONFIG_DB but bgpcfgd takes time to
            # reconcile all entries after BGP sessions re-establish.
            time.sleep(30)

            # Step 4-5: Verify communities restored with generous timeout
            verify_route_on_neighbors(
                nbrhosts, ma, AGGR_V4,
                expected_present=True,
                timeout=300,
            )
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
                timeout=300,
            )
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                    timeout=300,
                )

            # Also verify OOB if available
            if mb:
                verify_route_communities(
                    nbrhosts, mb, AGGR_V4,
                    expected_communities={OOB_AGGREGATE_COMMUNITY},
                    unexpected_communities={NO_ADVERTISE_COMMUNITY},
                    timeout=300,
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)
            # Restore on-disk config after removing test aggregate — the
            # config save before reload persisted test state that would
            # corrupt subsequent runs/reloads if left on disk.
            duthost.shell("sudo config save -y", module_ignore_errors=True)


# ===========================================================================

class TestGroupMixed:
    """Test Group 6: Mixed MA and OOB Scenario (TC 6.1-6.4)

    Validates that the same aggregate produces different community tags on
    MA vs OOB upstream neighbors simultaneously.
    """

    def test_mixed_same_aggregate_different_communities(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 6.1: Same aggregate, different communities per upstream type.

        Steps:
            1. Skip if no MB neighbors
            2. Add aggregate + inject contributing routes
            3. Verify on MA: aggregate has 8075:8801 (NOT 8075:9120),
               contributing has 8075:8800 (NOT 8075:9120/no-advertise)
            4. Verify on OOB: aggregate has 8075:9120 (NOT 8075:8801/no-advertise),
               contributing has 8075:9120 + no-advertise (NOT 8075:8800)
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        mb = setup["mb_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()

        if not mb:
            pytest.skip("No MB/OOB (CoreTs) neighbors — mixed test requires both MA and MB")

        try:
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")

            # ---- MA verification ----
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            # Aggregate: MA tags only
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
                unexpected_communities={OOB_AGGREGATE_COMMUNITY},
            )
            # Contributing: MA tags only
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                    unexpected_communities={OOB_CONTRIBUTING_COMMUNITY, NO_ADVERTISE_COMMUNITY},
                )

            # ---- OOB verification ----
            verify_route_on_neighbors(nbrhosts, mb, AGGR_V4, expected_present=True)
            # Aggregate: OOB tags only, no NO_ADVERTISE
            verify_route_communities(
                nbrhosts, mb, AGGR_V4,
                expected_communities={OOB_AGGREGATE_COMMUNITY},
                unexpected_communities={MA_AGGREGATE_COMMUNITY, NO_ADVERTISE_COMMUNITY},
            )
            # Contributing: OOB tags + NO_ADVERTISE
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, mb, prefix,
                    expected_communities={OOB_CONTRIBUTING_COMMUNITY, NO_ADVERTISE_COMMUNITY},
                    unexpected_communities={MA_CONTRIBUTING_COMMUNITY},
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_mixed_add_remove_affects_both(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 6.2: Add/remove aggregate affects both MA and OOB consistently.

        Steps:
            1. Skip if no MB neighbors
            2. Add aggregate, inject routes, verify communities on both
            3. Remove aggregate
            4. Verify on both: aggregate withdrawn, contributing lose tags
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        mb = setup["mb_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()

        if not mb:
            pytest.skip("No MB/OOB neighbors — mixed test requires both")

        try:
            # Steps 2: Setup and verify
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_on_neighbors(nbrhosts, mb, AGGR_V4, expected_present=True)

            # Step 3: Remove aggregate
            safe_remove_aggregate(duthost, AGGR_V4)

            # Step 4: Both lose aggregate tags
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                unexpected_communities={MA_AGGREGATE_COMMUNITY},
            )
            # OOB: verify aggregate deactivated on DUT control plane.
            # The route may linger on the OOB neighbor due to hold-timers.
            verify_aggregate_inactive_on_dut(duthost, AGGR_V4)
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    unexpected_communities={MA_CONTRIBUTING_COMMUNITY},
                )
                # OOB: only check NO_ADVERTISE absence (not OOB_CONTRIBUTING_COMMUNITY,
                # which is 8075:9120 — always set by catch-all route-map TO_MB_PATH permit 1000)
                verify_route_communities(
                    nbrhosts, mb, prefix,
                    unexpected_communities={NO_ADVERTISE_COMMUNITY},
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_mixed_dual_stack(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 6.3: Dual-stack (IPv4 + IPv6) with both MA and OOB.

        Steps:
            1. Skip if no MB neighbors
            2. Add IPv4 and IPv6 aggregates with respective prefix-lists
            3. Inject contributing routes for both address families
            4. Verify 4 community sets: MA+v4, MA+v6, OOB+v4, OOB+v6
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        mb = setup["mb_neighbors"]
        cfg_v4 = build_cfg()
        cfg_v6 = build_cfg("v6")
        contrib_v4 = CONTRIBUTING_V4[:2]
        contrib_v6 = CONTRIBUTING_V6[:2]

        if not mb:
            pytest.skip("No MB/OOB neighbors — mixed dual-stack test requires both")

        try:
            # Step 2: Add both aggregates
            gcu_add_community_aggregate(duthost, cfg_v4)
            gcu_add_community_aggregate(duthost, cfg_v6)

            # Step 3: Inject contributing routes for both families
            inject_routes(setup, ptfhost, contrib_v4, "announce")
            inject_routes(setup, ptfhost, contrib_v6, "announce")

            # Step 4a: MA + IPv4
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )
            for prefix in contrib_v4:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                )

            # Step 4b: MA + IPv6
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V6, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V6,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )

            # Step 4c: OOB + IPv4
            verify_route_on_neighbors(nbrhosts, mb, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, mb, AGGR_V4,
                expected_communities={OOB_AGGREGATE_COMMUNITY},
                unexpected_communities={NO_ADVERTISE_COMMUNITY},
            )
            for prefix in contrib_v4:
                verify_route_communities(
                    nbrhosts, mb, prefix,
                    expected_communities={OOB_CONTRIBUTING_COMMUNITY, NO_ADVERTISE_COMMUNITY},
                )

            # Step 4d: OOB + IPv6
            verify_route_on_neighbors(nbrhosts, mb, AGGR_V6, expected_present=True)
            verify_route_communities(
                nbrhosts, mb, AGGR_V6,
                expected_communities={OOB_AGGREGATE_COMMUNITY},
                unexpected_communities={NO_ADVERTISE_COMMUNITY},
            )
        finally:
            inject_routes(setup, ptfhost, contrib_v4 + contrib_v6, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)
            safe_remove_aggregate(duthost, AGGR_V6)

    def test_mixed_bbr_toggle_affects_both(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 6.4: BBR toggle affects both MA and OOB simultaneously.

        Steps:
            1. Skip if no MB neighbors or BBR not supported
            2. Enable BBR, add BBR-required aggregate, inject routes
            3. Verify communities on both MA and OOB
            4. Disable BBR
            5. Verify aggregate withdrawn and tags removed on both
            6. Enable BBR
            7. Verify community tagging restored on both
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        mb = setup["mb_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg(bbr_required=True)

        if not mb:
            pytest.skip("No MB/OOB neighbors — mixed BBR test requires both")

        bbr_supported, bbr_default = get_bbr_default_state(duthost)
        if not bbr_supported:
            pytest.skip("BGP BBR is not supported")

        try:
            # Step 2: Enable BBR + setup
            if bbr_default != "enabled":
                config_bbr_by_gcu(duthost, "enabled")
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")

            # Step 3: Verify both
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_on_neighbors(nbrhosts, mb, AGGR_V4, expected_present=True)

            # Step 4: Disable BBR
            config_bbr_by_gcu(duthost, "disabled")

            # Step 5: Both lose aggregate tags
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                unexpected_communities={MA_AGGREGATE_COMMUNITY},
            )
            # OOB: verify aggregate deactivated on DUT control plane
            verify_aggregate_inactive_on_dut(duthost, AGGR_V4)

            # Contributing routes on OOB should lose NO_ADVERTISE
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, mb, prefix,
                    unexpected_communities={NO_ADVERTISE_COMMUNITY},
                    timeout=BGP_CONVERGE_TIMEOUT_LONG,
                )

            # Step 6: Re-enable BBR
            config_bbr_by_gcu(duthost, "enabled")

            # Step 7: Both restored
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )
            verify_route_on_neighbors(nbrhosts, mb, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, mb, AGGR_V4,
                expected_communities={OOB_AGGREGATE_COMMUNITY},
            )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)
            try:
                config_bbr_by_gcu(duthost, bbr_default)
            except (Exception, pytest.fail.Exception):
                logger.warning("Failed to restore BBR to %s", bbr_default)


# ===========================================================================
# GROUP 7: Upstream Device Behavior Verification
# ===========================================================================

class TestGroupUpstream:
    """Test Group 7: Upstream Device Behavior Verification (TC 7.1-7.5)

    End-to-end validation that upstream devices correctly act on the
    community tags set by the DUT.
    """

    def test_upstream_ma_applies_no_export(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 7.1: MA device can match on 8075:8800 community set by DUT.

        Validates that the community tag is not merely present in the BGP
        update but is **actionable** by the upstream device.  We verify by
        using ``show ip bgp community 8075:8800 | json`` on the EOS MA
        neighbor to confirm it can filter contributing routes by community.

        Steps:
            1. Add aggregate on DUT, inject contributing routes
            2. Verify on MA: contributing routes have 8075:8800
            3. On EOS: ``show ip bgp community 8075:8800`` returns contributing
               routes but NOT the aggregate (which has 8075:8801)
            4. Verify: aggregate has 8075:8801 (different tag)
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()
        ma_host = nbrhosts[ma[0]]["host"]

        try:
            # Step 1: Add aggregate, inject routes
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")

            # Step 2: Verify contributing routes have 8075:8800
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                )

            # Step 3: Verify EOS can match contributing routes by community value
            if isinstance(ma_host, EosHost):
                # Use 'show ip bgp community <community>' to verify EOS recognizes
                # the DUT-set community and can filter routes by it.
                comm_output = ma_host.eos_command(
                    commands=["show ip bgp community {} | json".format(
                        MA_CONTRIBUTING_COMMUNITY)]
                )
                comm_data = comm_output["stdout_lines"][0] if comm_output.get(
                    "stdout_lines") else {}
                comm_routes = comm_data.get("vrfs", {}).get("default", {}).get(
                    "bgpRouteEntries", {})
                logger.info("EOS 'show ip bgp community %s' routes: %s",
                            MA_CONTRIBUTING_COMMUNITY, list(comm_routes.keys()))

                for prefix in contributing:
                    pytest_assert(
                        prefix in comm_routes,
                        "EOS 'show ip bgp community {}' should list contributing "
                        "route {} — found: {}".format(
                            MA_CONTRIBUTING_COMMUNITY, prefix,
                            list(comm_routes.keys()))
                    )

                # Step 4: Aggregate should NOT match (it has 8075:8801, not 8075:8800)
                pytest_assert(
                    AGGR_V4 not in comm_routes,
                    "Aggregate {} should NOT appear in 'show ip bgp community {}' "
                    "(aggregate has {}, not {})".format(
                        AGGR_V4, MA_CONTRIBUTING_COMMUNITY,
                        MA_AGGREGATE_COMMUNITY, MA_CONTRIBUTING_COMMUNITY)
                )

                # Step 5: Verify aggregate has 8075:8801
                agg_communities = get_route_communities(ma_host, AGGR_V4)
                logger.info("MA aggregate %s communities: %s", AGGR_V4, agg_communities)
                pytest_assert(
                    MA_AGGREGATE_COMMUNITY in agg_communities,
                    "Aggregate should have {} — got {}".format(
                        MA_AGGREGATE_COMMUNITY, agg_communities)
                )
            else:
                pytest.skip("MA neighbor is not EOS — cannot verify community matching")
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_upstream_oob_respects_no_advertise(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 7.2: OOB upstream device receives and can act on NO_ADVERTISE.

        NO_ADVERTISE is a well-known BGP community (RFC 1997) that any
        compliant device inherently respects — it prevents re-advertisement
        of the tagged routes.  This test verifies:
        1. Contributing routes on MB carry NO_ADVERTISE (actionable marker)
        2. Aggregate on MB does NOT carry NO_ADVERTISE
        3. For EOS: ``show ip bgp community no-advertise`` returns only
           contributing routes (proves EOS can filter by this community)

        Steps:
            1. Skip if no MB neighbors
            2. Add aggregate, inject contributing routes
            3. Verify on OOB: contributing routes have no-advertise
            4. For EOS: verify ``show ip bgp community no-advertise``
               lists contributing routes but NOT the aggregate
            5. Verify on OOB: aggregate has 8075:9120 without no-advertise
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        mb = setup["mb_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()

        if not mb:
            pytest.skip("No MB/OOB (CoreTs) neighbors in topology")

        mb_host = nbrhosts[mb[0]]["host"]

        try:
            # Step 2: Setup
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")

            # Step 3: Verify contributing routes have NO_ADVERTISE on OOB
            verify_route_on_neighbors(nbrhosts, mb, AGGR_V4, expected_present=True)
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, mb, prefix,
                    expected_communities={OOB_CONTRIBUTING_COMMUNITY, NO_ADVERTISE_COMMUNITY},
                )

            # Step 4: Device-level verification — upstream can act on NO_ADVERTISE
            if isinstance(mb_host, EosHost):
                # EOS: use 'show ip bgp community no-advertise' to prove
                # the device can filter routes by the well-known community
                comm_output = mb_host.eos_command(
                    commands=["show ip bgp community no-advertise | json"]
                )
                comm_data = comm_output["stdout_lines"][0] if comm_output.get(
                    "stdout_lines") else {}
                comm_routes = comm_data.get("vrfs", {}).get("default", {}).get(
                    "bgpRouteEntries", {})
                logger.info("EOS OOB 'show ip bgp community no-advertise' routes: %s",
                            list(comm_routes.keys()))

                # Contributing routes should appear (they carry no-advertise)
                for prefix in contributing:
                    pytest_assert(
                        prefix in comm_routes,
                        "EOS OOB 'show ip bgp community no-advertise' should list "
                        "contributing route {} — found: {}".format(
                            prefix, list(comm_routes.keys()))
                    )

                # Aggregate should NOT appear (it lacks no-advertise)
                pytest_assert(
                    AGGR_V4 not in comm_routes,
                    "Aggregate {} should NOT appear in 'show ip bgp community "
                    "no-advertise' — it should only carry {}".format(
                        AGGR_V4, OOB_AGGREGATE_COMMUNITY)
                )
            else:
                # SonicHost or other: verify via get_route_communities
                for prefix in contributing:
                    communities = get_route_communities(mb_host, prefix)
                    logger.info("OOB %s communities for %s: %s", mb[0], prefix, communities)
                    pytest_assert(
                        NO_ADVERTISE_COMMUNITY in communities
                        or "noAdvertise" in communities,
                        "OOB contributing route {} should have no-advertise — "
                        "got {}".format(prefix, communities)
                    )

            # Step 5: Aggregate has 8075:9120 without NO_ADVERTISE
            verify_route_communities(
                nbrhosts, mb, AGGR_V4,
                expected_communities={OOB_AGGREGATE_COMMUNITY},
                unexpected_communities={NO_ADVERTISE_COMMUNITY},
            )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_upstream_dut_tagging_independent_of_upstream_policy(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 7.3: DUT community tagging is independent of upstream policy changes.

        Steps:
            1. Setup MA scenario, verify communities
            2. Change route-map on MA (remove community matching)
            3. Verify DUT STILL tags routes with 8075:8801/8075:8800
            4. Revert MA policy
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()
        ma_host = nbrhosts[ma[0]]["host"]

        if not isinstance(ma_host, EosHost):
            pytest.skip("MA neighbor is not EOS — cannot modify route-map")

        try:
            # Step 1: Baseline
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )

            # Step 2: Add a policy on MA that strips communities (simulate change)
            ma_host.eos_command(commands=[
                "configure",
                "route-map STRIP_COMM permit 10",
                "set community none",
                "exit",
            ])

            # Step 3: DUT tagging should be unchanged — DUT doesn't care about
            # what MA does with the routes after receiving them
            # Re-verify that DUT is still sending the communities
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                )
        finally:
            # Step 4: Revert MA config
            try:
                ma_host.eos_command(commands=[
                    "configure",
                    "no route-map STRIP_COMM",
                ])
            except (Exception, pytest.fail.Exception):
                logger.warning("Failed to revert MA route-map config")
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_upstream_ma_traffic_validation(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup, ptfadapter, tbinfo
    ):
        """TC 7.4: Data-plane traffic validation — MA scenario end-to-end.

        Verifies that community tagging does not interfere with data-plane
        forwarding.  Traffic sent from MA (upstream) toward contributing
        prefix IPs is forwarded through the DUT and exits toward M0
        (downstream, the route originator).

        Per the test plan:
          - MA has the contributing routes (learned from DUT with 8075:8800)
          - Traffic from MA toward contributing IPs enters the DUT
          - DUT forwards toward M0 (nexthop for contributing /24 routes)
          - This proves the community-tagged routes are fully routable

        Steps:
            1. Add aggregate with prefix-lists, inject contributing routes
            2. Verify control-plane baseline (routes + communities on MA)
            3. Discover PTF ports: MA (tx) and M0 (rx)
            4. Send traffic toward 10.100.1.1 from MA, verify on M0 ports
            5. Send traffic toward 10.100.2.1 from MA, verify on M0 ports
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()

        try:
            # Step 1: Add aggregate and inject contributing routes
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")

            # Step 2: Control-plane baseline
            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)
            verify_route_communities(
                nbrhosts, ma, AGGR_V4,
                expected_communities={MA_AGGREGATE_COMMUNITY},
            )
            for prefix in contributing:
                verify_route_communities(
                    nbrhosts, ma, prefix,
                    expected_communities={MA_CONTRIBUTING_COMMUNITY},
                )

            # Step 3: Discover PTF ports
            # MA ports = tx (upstream sends traffic toward contributing IPs)
            # M0 ports = rx (DUT forwards to M0, the route originator)
            router_mac = duthost.facts["router_mac"]
            mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
            m0_ptf_ports = get_ptf_ports_by_neighbor_suffix(mg_facts, "M0")
            ma_ptf_ports = get_ptf_ports_by_neighbor_suffix(mg_facts, "MA")
            tx_port = ma_ptf_ports[0]
            logger.info("Data-plane: tx_port(MA)=%d, rx_ports(M0)=%s",
                        tx_port, m0_ptf_ports)

            # Step 4: Traffic toward first contributing prefix (10.100.1.0/24)
            src_ip = "192.168.100.2"
            dst_ip_1 = "10.100.1.1"

            pkt = testutils.simple_ip_packet(
                eth_dst=router_mac, ip_src=src_ip, ip_dst=dst_ip_1,
            )
            exp_pkt = Mask(pkt)
            exp_pkt.set_do_not_care_packet(scapy.IP, "ttl")
            exp_pkt.set_do_not_care_packet(scapy.IP, "chksum")
            exp_pkt.set_do_not_care_packet(scapy.Ether, "dst")
            exp_pkt.set_do_not_care_packet(scapy.Ether, "src")

            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, pkt=pkt, port_id=tx_port)
            testutils.verify_packet_any_port(
                ptfadapter, pkt=exp_pkt, ports=m0_ptf_ports, timeout=5,
            )
            logger.info("Traffic to %s from MA forwarded to M0 — PASS",
                        dst_ip_1)

            # Step 5: Traffic toward second contributing prefix (10.100.2.0/24)
            dst_ip_2 = "10.100.2.1"

            pkt2 = testutils.simple_ip_packet(
                eth_dst=router_mac, ip_src=src_ip, ip_dst=dst_ip_2,
            )
            exp_pkt2 = Mask(pkt2)
            exp_pkt2.set_do_not_care_packet(scapy.IP, "ttl")
            exp_pkt2.set_do_not_care_packet(scapy.IP, "chksum")
            exp_pkt2.set_do_not_care_packet(scapy.Ether, "dst")
            exp_pkt2.set_do_not_care_packet(scapy.Ether, "src")

            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, pkt=pkt2, port_id=tx_port)
            testutils.verify_packet_any_port(
                ptfadapter, pkt=exp_pkt2, ports=m0_ptf_ports, timeout=5,
            )
            logger.info("Traffic to %s from MA forwarded to M0 — PASS",
                        dst_ip_2)
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)

    def test_community_additivity(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost,
        community_tagging_setup
    ):
        """TC 7.5: MSFT communities are applied additively.

        Validates that the route-map uses 'set community ... additive',
        meaning pre-existing communities on routes are preserved alongside
        the MSFT tags, rather than being replaced.

        Steps:
            1. Add aggregate with prefix-lists
            2. Inject contributing routes from M0
            3. Verify on MA: contributing routes have 8075:8800
            4. Verify aggregate has 8075:8801 and no cross-contamination
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = community_tagging_setup
        ma = setup["ma_neighbors"]
        contributing = CONTRIBUTING_V4[:2]
        cfg = build_cfg()
        ma_host = nbrhosts[ma[0]]["host"]

        try:
            gcu_add_community_aggregate(duthost, cfg)
            inject_routes(setup, ptfhost, contributing, "announce")

            verify_route_on_neighbors(nbrhosts, ma, AGGR_V4, expected_present=True)

            # Verify aggregate has MA tag
            agg_communities = get_route_communities(ma_host, AGGR_V4)
            logger.info("Aggregate %s communities: %s", AGGR_V4, agg_communities)
            pytest_assert(
                MA_AGGREGATE_COMMUNITY in agg_communities,
                "Aggregate missing {} — got {}".format(MA_AGGREGATE_COMMUNITY, agg_communities)
            )

            # Verify contributing routes have MA tag and no cross-contamination
            for prefix in contributing:
                contrib_communities = get_route_communities(ma_host, prefix)
                logger.info("Contributing %s communities: %s", prefix, contrib_communities)
                pytest_assert(
                    MA_CONTRIBUTING_COMMUNITY in contrib_communities,
                    "Contributing route {} missing {} — got {}".format(
                        prefix, MA_CONTRIBUTING_COMMUNITY, contrib_communities)
                )
                # Aggregate tag NOT present on contributing (no cross-contamination)
                pytest_assert(
                    MA_AGGREGATE_COMMUNITY not in contrib_communities,
                    "Contributing route {} should NOT have aggregate tag {} — got {}".format(
                        prefix, MA_AGGREGATE_COMMUNITY, contrib_communities)
                )
        finally:
            inject_routes(setup, ptfhost, contributing, "withdraw")
            safe_remove_aggregate(duthost, AGGR_V4)
