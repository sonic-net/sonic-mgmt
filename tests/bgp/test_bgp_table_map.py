"""
Test BGP table-map FIB filtering (SELECTIVE_ROUTE_DOWNLOAD)

Two complementary test groups:

1. Community-based filtering (SELECTIVE_ROUTE_DOWNLOAD_V4/V6):
   Routes tagged with LOCAL_ANCHOR_ROUTE_COMMUNITY are held in BGP RIB but not
   installed into FIB/ASIC. Requires UpperSpineRouter or SpineRouter+UpstreamLC
   device type — the FRR template generates the table-map on BGP docker restart.

2. Prefix-list based filtering (custom route-map, from Work Item 37441388):
   A custom PREFIX_LIST + ROUTE_MAP is applied directly as table-map via vtysh.
   Matches the configuration in Mohan Nanduri's work item example:
     ip prefix-list BLOCK_20_NET seq 5 permit 20.0.0.0/8 le 32
     route-map FIB_FILTER deny 10 → match ip address prefix-list BLOCK_20_NET
     route-map FIB_FILTER permit 1000
     address-family ipv4 unicast → table-map FIB_FILTER
   These tests do NOT require a specific device type.

Related: Work Item 37441388 (SELECTIVE_ROUTE_DOWNLOAD)

Note: Device type validation tests are in test_bgp_table_map_device_type.py.
"""

import json
import logging
import pytest
import yaml

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.bgp.bgp_helpers import update_routes, get_exabgp_port

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2', 'lrh', 'urh', 'any'),
    pytest.mark.skip_check_dut_health
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse=True)
def skip_multi_asic(duthosts, enum_dut_hostname):
    """Skip this module on multi-ASIC DUTs.

    Helpers here (vtysh, get_bgp_asn, apply/remove_table_map, is_route_in_rib
    excepted - that one is already per-ASIC aware) hard-code the single-ASIC
    'bgp' container/namespace (e.g. 'docker exec bgp ...' with no per-ASIC
    'bgpN'/'-n asicN' targeting), so on multi-ASIC platforms they'd target the
    wrong or nonexistent container and fail before exercising table-map
    behavior at all.
    """
    duthost = duthosts[enum_dut_hostname]
    pytest_require(
        not duthost.is_multi_asic,
        "test_bgp_table_map module requires a single-ASIC DUT "
        "(helpers assume a single 'bgp' container)"
    )


EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000
CONSTANTS_FILE = "/etc/sonic/constants.yml"

# Community-based filtering (SELECTIVE_ROUTE_DOWNLOAD)
BLOCKED_PREFIXES_V4 = ["20.5.10.0/24", "20.10.20.0/24", "20.100.50.0/24"]
PERMITTED_PREFIXES_V4 = ["10.1.0.0/16", "10.5.10.0/24", "192.168.100.0/24"]
BLOCKED_PREFIXES_V6 = ["2001:db8:20:5::/64", "2001:db8:20:10::/64"]
PERMITTED_PREFIXES_V6 = ["2001:db8:10:1::/64", "2001:db8:fe::/64"]

# Prefix-list based filtering — mirrors Work Item 37441388 example config
# IPv4: block all subnets within 20.0.0.0/8 (le 32)
PL_BLOCK_NET_V4 = "BLOCK_20_NET"
PL_BLOCK_PREFIX_V4 = "20.0.0.0/8"
PL_RMAP_V4 = "FIB_FILTER_PL"
PL_BLOCKED_ROUTE_V4 = "20.5.10.0/24"
PL_PERMITTED_ROUTE_V4 = "10.1.0.0/16"

# IPv6: block exactly-/64 subnets within 2a01:20::/32 (ge 64 le 64)
PL_BLOCK_NET_V6 = "BLOCK_TEST_V6"
PL_BLOCK_PREFIX_V6 = "2a01:20::/32"
PL_RMAP_V6 = "FIB_FILTER_PL_V6"
PL_BLOCKED_ROUTE_V6 = "2a01:20:0:1::/64"
PL_PERMITTED_ROUTE_V6 = "2001:db8:10:1::/64"


# ============================================================
# Helpers
# ============================================================

def get_anchor_community(duthost):
    """Read local_anchor_route_community from constants.yml on the DUT."""
    pytest_require(
        duthost.stat(path=CONSTANTS_FILE)["stat"]["exists"],
        "constants.yml not found on DUT, skipping test"
    )
    constants = yaml.safe_load(duthost.shell("cat {}".format(CONSTANTS_FILE))["stdout"])
    try:
        return constants["constants"]["bgp"]["local_anchor_route_community"]
    except KeyError:
        pytest.skip("local_anchor_route_community not defined in constants.yml")


def set_device_type(duthost, device_type, subtype=None):
    """Set DEVICE_METADATA type and subtype in CONFIG_DB."""
    duthost.shell("redis-cli -n 4 HSET 'DEVICE_METADATA|localhost' type {}".format(device_type))
    if subtype:
        duthost.shell("redis-cli -n 4 HSET 'DEVICE_METADATA|localhost' subtype {}".format(subtype))
    else:
        duthost.shell("redis-cli -n 4 HDEL 'DEVICE_METADATA|localhost' subtype",
                      module_ignore_errors=True)


def restart_bgp_and_wait(duthost):
    """Restart the BGP docker(s) so FRR templates are regenerated, then wait for sessions.

    'docker restart' bypasses systemd, so bgp.service's Restart=always drop-in
    fires its own follow-up restart on top of ours, silently consuming a slot
    in systemd's StartLimitBurst counter (default 3 per 20 min) on every call.
    A test module that calls this helper more than a few times per run can
    trip bgp.service into a spurious 'start-limit-hit' failure even though the
    container itself is healthy. Clearing the counter immediately beforehand
    keeps repeated calls from accumulating against that limit.
    """
    if duthost.is_multi_asic:
        for asic_index in duthost.get_frontend_asic_ids():
            duthost.shell("sudo systemctl reset-failed bgp{}".format(asic_index), module_ignore_errors=True)
            duthost.shell("docker restart bgp{}".format(asic_index))
    else:
        duthost.shell("sudo systemctl reset-failed bgp", module_ignore_errors=True)
        duthost.shell("docker restart bgp")
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    bgp_neighbors = config_facts.get("BGP_NEIGHBOR", {})
    # 180s was cutting it close in practice: full-table T1 neighbors (thousands
    # of routes each) can take upward of 3-4 minutes to reach Established on
    # this KVM environment. On the native URH topology (6 confederation
    # neighbors carrying a real ~100k-entry full table each, observed with
    # load average ~4 on the KVM host) even the follow-up 300s budget can be
    # too tight, so bump to 480s to avoid flaking on genuine (slow-but-healthy)
    # convergence rather than a real failure.
    pytest_assert(
        wait_until(480, 10, 30, duthost.check_bgp_session_state, bgp_neighbors),
        "BGP sessions did not re-establish after BGP docker restart"
    )


def bgpcfgd_is_running(duthost):
    """Return True if the bgpcfgd process inside the bgp docker is still alive (didn't crash)."""
    out = duthost.shell(
        "docker exec bgp supervisorctl status bgpcfgd", module_ignore_errors=True
    )["stdout"]
    return "RUNNING" in out


def _bgp_docker_responsive(duthost):
    """Return True if the bgp docker is up and vtysh/bgpcfgd are responsive.

    Deliberately does NOT check neighbor session state. Some device types
    (e.g. LeafRouter) render a peer-group template that is fundamentally
    incompatible with this native URH confederation topology's real peers
    (drops the per-neighbor fast timers this topology's peers require), so
    sessions never re-establish under that device type on this testbed -
    that is expected/unrelated to what device-type-gating tests actually check.
    """
    out = duthost.shell("docker ps --filter name=bgp --format '{{.Status}}'",
                        module_ignore_errors=True)["stdout"]
    if "Up" not in out:
        return False
    vtysh_out = duthost.shell("docker exec bgp vtysh -c 'show version'", module_ignore_errors=True)
    return vtysh_out["rc"] == 0 and bgpcfgd_is_running(duthost)


def restart_bgp_and_wait_responsive(duthost):
    """Restart the bgp docker and wait only for it to come back up and be responsive.

    Use this instead of restart_bgp_and_wait() when the test intentionally
    applies a device type whose BGP sessions are not expected to (re)converge
    on this topology - e.g. a disallowed/filtered 'LeafRouter' probe. Session
    convergence is irrelevant there: the test only cares whether bgpcfgd
    renders config (e.g. table-map presence/absence) correctly, which only
    requires bgpd/bgpcfgd to be up and processing CONFIG_DB.
    """
    duthost.shell("sudo systemctl reset-failed bgp", module_ignore_errors=True)
    duthost.shell("docker restart bgp")
    pytest_assert(
        wait_until(60, 5, 10, _bgp_docker_responsive, duthost),
        "bgp docker did not come back up/responsive after restart"
    )


def is_route_in_rib(duthost, prefix, ip_version=4):
    """Return True if prefix is in BGP RIB on all frontend ASICs."""
    ip_ver = "ipv4" if ip_version == 4 else "ipv6"
    for asic_index in duthost.get_frontend_asic_ids():
        asic_ns = "-n asic{}".format(asic_index) if duthost.is_multi_asic else ""
        cmd = "vtysh {} -c 'show bgp {} {}'".format(asic_ns, ip_ver, prefix)
        output = duthost.shell(cmd, module_ignore_errors=True)["stdout"]
        if "Network not in table" in output or not output.strip():
            return False
    return True


def is_route_in_fib(duthost, prefix):
    """Return True if prefix is installed in FIB (APPL_DB ROUTE_TABLE) on all frontend ASICs."""
    for asic_index in duthost.get_frontend_asic_ids():
        asic_ns = "-n asic{}".format(asic_index) if duthost.is_multi_asic else ""
        cmd = "sonic-db-cli {} APPL_DB hgetall \"ROUTE_TABLE:{}\"".format(asic_ns, prefix)
        output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].strip().replace("'", '"')
        route_info = json.loads(output) if output else {}
        if not route_info or route_info.get("blackhole") == "true":
            return False
    return True


# ============================================================
# Module-level Fixtures
# ============================================================

@pytest.fixture(scope="module")
def anchor_community(duthosts, enum_dut_hostname):
    """Read LOCAL_ANCHOR_ROUTE_COMMUNITY value from DUT constants.yml."""
    duthost = duthosts[enum_dut_hostname]
    return get_anchor_community(duthost)


def _has_template_table_map(duthost):
    """Return True if bgpd.conf already contains table-map (generated by FRR template)."""
    result = duthost.shell(
        "docker exec bgp grep -q 'table-map SELECTIVE_ROUTE_DOWNLOAD_V4' /etc/frr/bgpd.conf 2>/dev/null",
        module_ignore_errors=True
    )
    return result["rc"] == 0


def _apply_selective_route_download_vtysh(duthost):
    """
    Apply SELECTIVE_ROUTE_DOWNLOAD_V4/V6 route-maps and table-map via vtysh.

    Used as a fallback when the FRR template doesn't generate the table-map
    (e.g., KVM testbeds using bgpcfgd dynamic neighbor configuration instead
    of peer-group.conf.j2 templates).
    """
    asn = get_bgp_asn(duthost)
    community = get_anchor_community(duthost)

    # Define community-list
    vtysh(duthost, "bgp community-list standard LOCAL_ANCHOR_ROUTE_COMMUNITY permit {}".format(community))

    # Define route-maps
    vtysh(duthost, "route-map SELECTIVE_ROUTE_DOWNLOAD_V4 deny 10",
          "match community LOCAL_ANCHOR_ROUTE_COMMUNITY")
    vtysh(duthost, "route-map SELECTIVE_ROUTE_DOWNLOAD_V4 permit 1000")
    vtysh(duthost, "route-map SELECTIVE_ROUTE_DOWNLOAD_V6 deny 10",
          "match community LOCAL_ANCHOR_ROUTE_COMMUNITY")
    vtysh(duthost, "route-map SELECTIVE_ROUTE_DOWNLOAD_V6 permit 1000")

    # Apply as table-map
    apply_table_map(duthost, asn, "SELECTIVE_ROUTE_DOWNLOAD_V4", ip_version=4)
    apply_table_map(duthost, asn, "SELECTIVE_ROUTE_DOWNLOAD_V6", ip_version=6)
    logger.info("Applied SELECTIVE_ROUTE_DOWNLOAD_V4/V6 table-map via vtysh (template fallback)")


def _remove_selective_route_download_vtysh(duthost):
    """Remove the vtysh-applied table-map and route-maps (cleanup for fallback path)."""
    asn = get_bgp_asn(duthost)
    remove_table_map(duthost, asn, "SELECTIVE_ROUTE_DOWNLOAD_V4", ip_version=4)
    remove_table_map(duthost, asn, "SELECTIVE_ROUTE_DOWNLOAD_V6", ip_version=6)
    vtysh(duthost, "no route-map SELECTIVE_ROUTE_DOWNLOAD_V4")
    vtysh(duthost, "no route-map SELECTIVE_ROUTE_DOWNLOAD_V6")
    vtysh(duthost, "no bgp community-list standard LOCAL_ANCHOR_ROUTE_COMMUNITY")


@pytest.fixture(scope="module", params=["UpperSpineRouter", "UpperRegionalHub"])
def setup_table_map_device_type(request, duthosts, enum_dut_hostname):
    """
    Set device type to UpperSpineRouter or UpperRegionalHub (both parametrized)
    so FRR templates generate `table-map SELECTIVE_ROUTE_DOWNLOAD_V4/V6` in
    address-family config.

    On topologies where bgpd.conf is generated from bgpd.main.conf.j2 only
    (e.g., KVM t1-lag using bgpcfgd dynamic neighbors), the template does not
    render peer-group.conf.j2, so table-map is not written to bgpd.conf.
    In that case, we fall back to applying the route-map and table-map directly
    via vtysh so the filtering logic is still exercised.

    Restores original device type and removes any vtysh-applied config after
    the module completes.
    """
    duthost = duthosts[enum_dut_hostname]
    device_type = request.param

    original_type = duthost.shell(
        "redis-cli -n 4 HGET 'DEVICE_METADATA|localhost' type",
        module_ignore_errors=True
    )["stdout"].strip() or "ToRRouter"
    original_subtype = duthost.shell(
        "redis-cli -n 4 HGET 'DEVICE_METADATA|localhost' subtype",
        module_ignore_errors=True
    )["stdout"].strip() or None

    used_vtysh_fallback = False
    try:
        logger.info("Setting device type to {} to enable table-map".format(device_type))
        set_device_type(duthost, device_type)
        restart_bgp_and_wait(duthost)

        if _has_template_table_map(duthost):
            logger.info("table-map generated by FRR template in bgpd.conf")
        else:
            logger.info("table-map not in bgpd.conf (bgpcfgd topology) — applying via vtysh")
            _apply_selective_route_download_vtysh(duthost)
            used_vtysh_fallback = True

        yield duthost
    finally:
        if used_vtysh_fallback:
            _remove_selective_route_download_vtysh(duthost)
        logger.info("Restoring device type to {}/{}".format(original_type, original_subtype))
        set_device_type(duthost, original_type, original_subtype)
        restart_bgp_and_wait(duthost)
        logger.info("Device type restored")


@pytest.fixture(scope="module")
def exabgp_setup(duthosts, nbrhosts, tbinfo, enum_dut_hostname):
    """Get PTF IP, ExaBGP ports, and next-hop IPs for route injection."""
    duthost = duthosts[enum_dut_hostname]
    ptf_ip = tbinfo["ptf_ip"]

    exabgp_ports, _ = get_exabgp_port(duthost, nbrhosts, tbinfo, EXABGP_BASE_PORT, is_random=True)
    exabgp_ports_v6, _ = get_exabgp_port(duthost, nbrhosts, tbinfo, EXABGP_BASE_PORT_V6, is_random=True)

    cfg_props = tbinfo["topo"]["properties"]["configuration_properties"]["common"]
    nhipv4 = cfg_props.get("nhipv4", "10.10.246.254")
    nhipv6 = cfg_props.get("nhipv6", "fc0a::ff")

    return {
        "ptf_ip": ptf_ip,
        "exabgp_port": exabgp_ports[0],
        "exabgp_port_v6": exabgp_ports_v6[0],
        "nhipv4": nhipv4,
        "nhipv6": nhipv6,
    }


# ============================================================
# Tests: FIB Filtering
# ============================================================

def test_table_map_basic_deny(duthosts, enum_dut_hostname,
                              setup_table_map_device_type, exabgp_setup, anchor_community):
    """
    Route WITH LOCAL_ANCHOR_ROUTE_COMMUNITY is received into BGP RIB but blocked from FIB.

    SELECTIVE_ROUTE_DOWNLOAD_V4 seq 10: deny community LOCAL_ANCHOR_ROUTE_COMMUNITY.
    Route must be visible in 'show bgp ipv4 <prefix>' but absent from APPL_DB ROUTE_TABLE.
    """
    duthost = duthosts[enum_dut_hostname]
    prefix = BLOCKED_PREFIXES_V4[0]
    route = {"prefix": prefix, "nexthop": exabgp_setup["nhipv4"], "community": anchor_community}

    try:
        update_routes("announce", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)

        # Wait for route to reach BGP RIB (confirms ExaBGP session and BGP UPDATE worked)
        pytest_assert(
            wait_until(60, 3, 5, is_route_in_rib, duthost, prefix, 4),
            "Route {} not received in BGP RIB".format(prefix)
        )

        # Route must NOT be installed in FIB — table-map blocks it
        pytest_assert(
            not is_route_in_fib(duthost, prefix),
            "Route {} carrying anchor community should be blocked from FIB by table-map".format(prefix)
        )
        logger.info("PASS: Route {} with anchor community blocked from FIB".format(prefix))
    finally:
        update_routes("withdraw", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)


def test_table_map_basic_permit(duthosts, enum_dut_hostname,
                                setup_table_map_device_type, exabgp_setup, anchor_community):
    """
    Route WITHOUT anchor community is received into BGP RIB and installed in FIB.

    SELECTIVE_ROUTE_DOWNLOAD_V4 seq 1000: permit (fallthrough for all other routes).
    Route must be visible in both 'show bgp ipv4' and APPL_DB ROUTE_TABLE.
    """
    duthost = duthosts[enum_dut_hostname]
    prefix = PERMITTED_PREFIXES_V4[0]
    route = {"prefix": prefix, "nexthop": exabgp_setup["nhipv4"]}  # no community

    try:
        update_routes("announce", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)

        pytest_assert(
            wait_until(60, 3, 5, is_route_in_rib, duthost, prefix, 4),
            "Route {} not received in BGP RIB".format(prefix)
        )
        pytest_assert(
            wait_until(30, 3, 0, is_route_in_fib, duthost, prefix),
            "Route {} without anchor community should be installed in FIB".format(prefix)
        )
        logger.info("PASS: Route {} without anchor community installed in FIB".format(prefix))
    finally:
        update_routes("withdraw", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)


def test_table_map_ipv6(duthosts, enum_dut_hostname,
                        setup_table_map_device_type, exabgp_setup, anchor_community):
    """
    IPv6 route WITH anchor community is blocked from FIB by SELECTIVE_ROUTE_DOWNLOAD_V6.

    Same community-based filtering applies for address-family ipv6.
    """
    duthost = duthosts[enum_dut_hostname]
    prefix = BLOCKED_PREFIXES_V6[0]
    route = {"prefix": prefix, "nexthop": exabgp_setup["nhipv6"], "community": anchor_community}

    try:
        update_routes("announce", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port_v6"], route)

        pytest_assert(
            wait_until(60, 3, 5, is_route_in_rib, duthost, prefix, 6),
            "IPv6 route {} not received in BGP RIB".format(prefix)
        )
        pytest_assert(
            not is_route_in_fib(duthost, prefix),
            "IPv6 route {} with anchor community should be blocked from FIB".format(prefix)
        )
        logger.info("PASS: IPv6 route {} with anchor community blocked from FIB".format(prefix))
    finally:
        update_routes("withdraw", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port_v6"], route)


def test_table_map_mixed_filtering(duthosts, enum_dut_hostname,
                                   setup_table_map_device_type, exabgp_setup, anchor_community):
    """
    Multiple routes simultaneously: blocked (with anchor community) and permitted (no community).

    Verifies that table-map correctly handles each prefix independently based on
    community attribute, matching the dRH use case of selectively installing routes.
    """
    duthost = duthosts[enum_dut_hostname]
    ptf_ip = exabgp_setup["ptf_ip"]
    port = exabgp_setup["exabgp_port"]
    nhip = exabgp_setup["nhipv4"]

    blocked_routes = [
        {"prefix": p, "nexthop": nhip, "community": anchor_community}
        for p in BLOCKED_PREFIXES_V4
    ]
    permitted_routes = [
        {"prefix": p, "nexthop": nhip}
        for p in PERMITTED_PREFIXES_V4
    ]
    all_routes = blocked_routes + permitted_routes

    try:
        for route in all_routes:
            update_routes("announce", ptf_ip, port, route)

        # Wait for all routes to appear in RIB
        for prefix in BLOCKED_PREFIXES_V4 + PERMITTED_PREFIXES_V4:
            pytest_assert(
                wait_until(60, 3, 5, is_route_in_rib, duthost, prefix, 4),
                "Route {} not received in BGP RIB".format(prefix)
            )

        # Blocked routes must NOT be in FIB
        for prefix in BLOCKED_PREFIXES_V4:
            pytest_assert(
                not is_route_in_fib(duthost, prefix),
                "Blocked route {} should not be installed in FIB".format(prefix)
            )

        # Permitted routes must be in FIB
        for prefix in PERMITTED_PREFIXES_V4:
            pytest_assert(
                wait_until(30, 3, 0, is_route_in_fib, duthost, prefix),
                "Permitted route {} should be installed in FIB".format(prefix)
            )

        logger.info("PASS: Mixed filtering verified ({} blocked, {} permitted)".format(
            len(BLOCKED_PREFIXES_V4), len(PERMITTED_PREFIXES_V4)))
    finally:
        for route in all_routes:
            update_routes("withdraw", ptf_ip, port, route)


# ============================================================
# Helpers: Prefix-list based filtering via vtysh
# ============================================================

def vtysh(duthost, *commands):
    """Run a sequence of vtysh commands inside 'configure terminal' on the BGP container."""
    cmd_args = " ".join(["-c '{}'".format(c) for c in ["configure terminal"] + list(commands)])
    duthost.shell("docker exec bgp vtysh {}".format(cmd_args))


def get_bgp_asn(duthost):
    """Return the DUT's BGP ASN from running config."""
    output = duthost.shell("docker exec bgp vtysh -c 'show running-config' | grep 'router bgp'")["stdout"]
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("router bgp"):
            return line.split()[2]
    pytest.fail("Could not determine BGP ASN from running config")


def apply_table_map(duthost, asn, rmap_name, ip_version=4):
    """Apply table-map to BGP address-family via vtysh."""
    af = "address-family ipv4 unicast" if ip_version == 4 else "address-family ipv6 unicast"
    vtysh(duthost, "router bgp {}".format(asn), af, "table-map {}".format(rmap_name))


def remove_table_map(duthost, asn, rmap_name, ip_version=4):
    """Remove table-map from BGP address-family via vtysh."""
    af = "address-family ipv4 unicast" if ip_version == 4 else "address-family ipv6 unicast"
    vtysh(duthost, "router bgp {}".format(asn), af, "no table-map {}".format(rmap_name))


def configure_prefix_list_vtysh(duthost, name, seq, action, prefix, ge=None, le=None):
    """Create an ip/ipv6 prefix-list entry via vtysh."""
    af = "ipv6" if ":" in prefix else "ip"
    ge_le = ""
    if ge is not None:
        ge_le += " ge {}".format(ge)
    if le is not None:
        ge_le += " le {}".format(le)
    vtysh(duthost, "{} prefix-list {} seq {} {} {}{}".format(
        af, name, seq, action, prefix, ge_le))


def configure_route_map_vtysh(duthost, name, seq, action, match_prefix_list=None, ip_version=4):
    """Create a route-map entry with optional prefix-list match via vtysh."""
    vtysh(duthost, "route-map {} {} {}".format(name, action, seq))
    if match_prefix_list:
        match_cmd = ("match ip address prefix-list {}" if ip_version == 4
                     else "match ipv6 address prefix-list {}").format(match_prefix_list)
        vtysh(duthost, "route-map {} {} {}".format(name, action, seq), match_cmd)


def remove_prefix_list_vtysh(duthost, name, ip_version=4):
    """Remove all entries of an ip/ipv6 prefix-list via vtysh."""
    af = "ipv6" if ip_version == 6 else "ip"
    vtysh(duthost, "no {} prefix-list {}".format(af, name))


def remove_route_map_vtysh(duthost, name):
    """Remove all entries of a route-map via vtysh."""
    vtysh(duthost, "no route-map {}".format(name))


# ============================================================
# Fixture: Prefix-list based table-map setup
# ============================================================

@pytest.fixture(scope="function")
def setup_prefix_list_table_map(duthosts, enum_dut_hostname, exabgp_setup):
    """
    Configure a prefix-list + route-map and apply as table-map directly via vtysh.
    Mirrors Work Item 37441388 example:
      ip prefix-list BLOCK_20_NET seq 5 permit 20.0.0.0/8 le 32
      route-map FIB_FILTER_PL deny 10 → match ip address prefix-list BLOCK_20_NET
      route-map FIB_FILTER_PL permit 1000
      address-family ipv4 unicast → table-map FIB_FILTER_PL

    Does NOT require a specific device type — table-map is applied directly.
    """
    duthost = duthosts[enum_dut_hostname]
    asn = get_bgp_asn(duthost)

    try:
        # IPv4: block 20.0.0.0/8 le 32
        configure_prefix_list_vtysh(duthost, PL_BLOCK_NET_V4, 5, "permit", PL_BLOCK_PREFIX_V4, le=32)
        configure_route_map_vtysh(duthost, PL_RMAP_V4, 10, "deny", PL_BLOCK_NET_V4, ip_version=4)
        configure_route_map_vtysh(duthost, PL_RMAP_V4, 1000, "permit", ip_version=4)
        apply_table_map(duthost, asn, PL_RMAP_V4, ip_version=4)

        # IPv6: block 2a01:20::/32 exactly /64 (ge 64 le 64)
        configure_prefix_list_vtysh(duthost, PL_BLOCK_NET_V6, 10, "permit", PL_BLOCK_PREFIX_V6, ge=64, le=64)
        configure_route_map_vtysh(duthost, PL_RMAP_V6, 10, "deny", PL_BLOCK_NET_V6, ip_version=6)
        configure_route_map_vtysh(duthost, PL_RMAP_V6, 1000, "permit", ip_version=6)
        apply_table_map(duthost, asn, PL_RMAP_V6, ip_version=6)

        logger.info("Prefix-list table-map configured (IPv4: {}, IPv6: {})".format(
            PL_RMAP_V4, PL_RMAP_V6))
        yield duthost
    finally:
        remove_table_map(duthost, asn, PL_RMAP_V4, ip_version=4)
        remove_table_map(duthost, asn, PL_RMAP_V6, ip_version=6)
        remove_route_map_vtysh(duthost, PL_RMAP_V4)
        remove_route_map_vtysh(duthost, PL_RMAP_V6)
        remove_prefix_list_vtysh(duthost, PL_BLOCK_NET_V4, ip_version=4)
        remove_prefix_list_vtysh(duthost, PL_BLOCK_NET_V6, ip_version=6)
        logger.info("Prefix-list table-map cleaned up")


# ============================================================
# Tests: Prefix-list based filtering (Work Item 37441388)
# ============================================================

def test_table_map_prefix_list_deny(duthosts, enum_dut_hostname,
                                    setup_prefix_list_table_map, exabgp_setup):
    """
    IPv4 route matching prefix-list BLOCK_20_NET is blocked from FIB.

    Config (from Work Item 37441388):
      ip prefix-list BLOCK_20_NET seq 5 permit 20.0.0.0/8 le 32
      route-map FIB_FILTER_PL deny 10 → match ip address prefix-list BLOCK_20_NET
      route-map FIB_FILTER_PL permit 1000
      table-map FIB_FILTER_PL

    20.5.10.0/24 is within 20.0.0.0/8 → deny → in RIB, NOT in FIB.
    """
    duthost = duthosts[enum_dut_hostname]
    route = {"prefix": PL_BLOCKED_ROUTE_V4, "nexthop": exabgp_setup["nhipv4"]}

    try:
        update_routes("announce", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)

        pytest_assert(
            wait_until(60, 3, 5, is_route_in_rib, duthost, PL_BLOCKED_ROUTE_V4, 4),
            "Route {} not received in BGP RIB".format(PL_BLOCKED_ROUTE_V4)
        )
        pytest_assert(
            not is_route_in_fib(duthost, PL_BLOCKED_ROUTE_V4),
            "Route {} matches BLOCK_20_NET — should be blocked from FIB by table-map".format(
                PL_BLOCKED_ROUTE_V4)
        )
        logger.info("PASS: {} blocked from FIB by prefix-list table-map".format(PL_BLOCKED_ROUTE_V4))
    finally:
        update_routes("withdraw", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)


def test_table_map_prefix_list_permit(duthosts, enum_dut_hostname,
                                      setup_prefix_list_table_map, exabgp_setup):
    """
    IPv4 route NOT matching prefix-list BLOCK_20_NET is installed in FIB.

    10.1.0.0/16 is outside 20.0.0.0/8 → hits permit 1000 → in RIB AND in FIB.
    """
    duthost = duthosts[enum_dut_hostname]
    route = {"prefix": PL_PERMITTED_ROUTE_V4, "nexthop": exabgp_setup["nhipv4"]}

    try:
        update_routes("announce", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)

        pytest_assert(
            wait_until(60, 3, 5, is_route_in_rib, duthost, PL_PERMITTED_ROUTE_V4, 4),
            "Route {} not received in BGP RIB".format(PL_PERMITTED_ROUTE_V4)
        )
        pytest_assert(
            wait_until(30, 3, 0, is_route_in_fib, duthost, PL_PERMITTED_ROUTE_V4),
            "Route {} does not match BLOCK_20_NET — should be installed in FIB".format(
                PL_PERMITTED_ROUTE_V4)
        )
        logger.info("PASS: {} permitted to FIB (no prefix-list match)".format(PL_PERMITTED_ROUTE_V4))
    finally:
        update_routes("withdraw", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port"], route)


def test_table_map_ipv6_prefix_list_deny(duthosts, enum_dut_hostname,
                                         setup_prefix_list_table_map, exabgp_setup):
    """
    IPv6 route matching prefix-list BLOCK_TEST_V6 is blocked from FIB.

    Config (from Work Item 37441388):
      ipv6 prefix-list BLOCK_TEST_V6 seq 10 permit 2a01:20::/32 ge 64 le 64
      route-map FIB_FILTER_PL_V6 deny 10 → match ipv6 address prefix-list BLOCK_TEST_V6
      route-map FIB_FILTER_PL_V6 permit 1000
      table-map FIB_FILTER_PL_V6

    2a01:20:0:1::/64 is within 2a01:20::/32 and exactly /64 → blocked from FIB.
    """
    duthost = duthosts[enum_dut_hostname]
    route = {"prefix": PL_BLOCKED_ROUTE_V6, "nexthop": exabgp_setup["nhipv6"]}

    try:
        update_routes("announce", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port_v6"], route)

        pytest_assert(
            wait_until(60, 3, 5, is_route_in_rib, duthost, PL_BLOCKED_ROUTE_V6, 6),
            "IPv6 route {} not received in BGP RIB".format(PL_BLOCKED_ROUTE_V6)
        )
        pytest_assert(
            not is_route_in_fib(duthost, PL_BLOCKED_ROUTE_V6),
            "IPv6 route {} matches BLOCK_TEST_V6 — should be blocked from FIB".format(
                PL_BLOCKED_ROUTE_V6)
        )
        logger.info("PASS: IPv6 {} blocked from FIB by prefix-list table-map".format(
            PL_BLOCKED_ROUTE_V6))
    finally:
        update_routes("withdraw", exabgp_setup["ptf_ip"], exabgp_setup["exabgp_port_v6"], route)
