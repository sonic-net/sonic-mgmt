"""
Test: sai_ecmp_group_members_increment for Broadcom DNX platforms.

Validates that sai_ecmp_group_members_increment=8 is present in the active
config.bcm for all DNX ASICs, and (when oper-up interfaces are available)
verifies FEC allocation via syncd syslog and CRM counters.
"""

import re
import time
import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

ECMP_INCREMENT = 8
TEST_ROUTE_PREFIX = "10.100.0.0/24"
CRM_POLL_WAIT = 15

pytestmark = [
    pytest.mark.asic('broadcom'),
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_syslog_marker(duthost):
    """Insert a marker into syslog and return it."""
    marker = "ECMP_TEST_{}".format(int(time.time()))
    duthost.shell("logger -t ECMP_TEST '{}'".format(marker))
    time.sleep(1)
    return marker


def collect_fec_logs(duthost, syncd_name, marker):
    """Return list of num_fec(N) values from syslog after marker."""
    cmd = ("awk '/{marker}/,0' /var/log/syslog | "
           "grep '{syncd}.*num_fec'").format(marker=marker, syncd=syncd_name)
    result = duthost.shell(cmd, module_ignore_errors=True)
    values = []
    for line in result.get("stdout_lines", []):
        m = re.search(r'num_fec\((\d+)\)', line)
        if m:
            values.append(int(m.group(1)))
    return values


def get_crm_nhg_member_used(asichost):
    """Return CRM nexthop_group_member used count via direct Redis query.

    Uses sonic-db-cli instead of asichost.count_crm_resources() to avoid
    repeated 'crm show resources all' text parsing during polling loops.
    """
    cmd = "{} COUNTERS_DB HGET CRM:STATS crm_stats_nexthop_group_member_used".format(
        asichost.sonic_db_cli)
    try:
        result = asichost.command(cmd)
        val = result.get("stdout", "").strip()
        if val and val != "None":
            return int(val)
    except Exception:
        # CRM DB query may fail on platforms without CRM support; return None to indicate unknown
        pass
    return None


def find_oper_up_intf(asichost, tbinfo):
    """Find an oper-up routed interface on this ASIC.

    Returns (intf_name, peer_ip) or None.
    Same discovery logic as crm_interface fixture in tests/crm/conftest.py:
    PortChannels first, then routed Ethernet.
    """
    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)
    intf_status = asichost.show_interface(command='status')['ansible_facts']['int_status']

    # Check portchannels first
    for pc in mg_facts.get("minigraph_portchannels", {}):
        if pc in intf_status and intf_status[pc].get('oper_state') == 'up':
            # Find its IPv4 address
            for entry in mg_facts.get("minigraph_portchannel_interfaces", []):
                if entry.get("attachto") == pc and "." in entry.get("addr", ""):
                    return (pc, entry.get("peer_addr", ""))

    # Then routed ethernet
    for entry in mg_facts.get("minigraph_interfaces", []):
        intf = entry.get("attachto", "")
        if intf in intf_status and intf_status[intf].get('oper_state') == 'up':
            if "." in entry.get("addr", ""):
                return (intf, entry.get("peer_addr", ""))

    return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_ecmp_increment_config_present(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Verify sai_ecmp_group_members_increment=8 in active config.bcm on each ASIC."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    missing_asics = []
    for idx in range(duthost.num_asics()):
        asichost = duthost.asic_instance(idx)
        syncd = asichost.get_docker_name("syncd")

        # Read sai.profile to find config.bcm path
        profile = duthost.shell(
            "docker exec {} cat /etc/sai.d/sai.profile".format(syncd),
            module_ignore_errors=True).get("stdout", "")
        config_path = None
        for line in profile.splitlines():
            if "SAI_INIT_CONFIG_FILE" in line:
                config_path = line.split("=", 1)[-1].strip()
                break
        if not config_path:
            missing_asics.append(idx)
            continue

        result = duthost.shell(
            "docker exec {} grep sai_ecmp_group_members_increment {}".format(syncd, config_path),
            module_ignore_errors=True)
        expected = "sai_ecmp_group_members_increment={}".format(ECMP_INCREMENT)
        if result["rc"] == 0 and expected in result["stdout"]:
            logger.info("ASIC %d: %s in %s", idx, expected, config_path)
        else:
            logger.warning("ASIC %d: property NOT found in %s", idx, config_path)
            missing_asics.append(idx)

    pytest_assert(
        len(missing_asics) == 0,
        "sai_ecmp_group_members_increment={} missing on ASICs: {}".format(ECMP_INCREMENT, missing_asics))


def test_ecmp_increment_fec_lifecycle(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                      enum_frontend_asic_index, tbinfo):
    """
    3-phase FEC allocation lifecycle:
      Phase 1: 2-NH ECMP route  → syslog num_fec(ECMP_INCREMENT),  CRM delta > 0
      Phase 2: (ECMP_INCREMENT+1)-NH route → syslog num_fec(2*ECMP_INCREMENT), CRM delta grows
      Phase 3: Delete route     → CRM returns to baseline
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    asichost = duthost.asic_instance(enum_frontend_asic_index)
    syncd_name = asichost.get_docker_name("syncd")

    # Need an oper-up interface; orchagent won't program NHGs for unreachable NHs
    intf_info = find_oper_up_intf(asichost, tbinfo)
    if intf_info is None:
        pytest.skip("No oper-up routed interface on ASIC {} — "
                    "cannot program ECMP groups".format(enum_frontend_asic_index))
    intf_name, peer_ip = intf_info
    logger.info("Using interface %s (peer %s) on ASIC %s", intf_name, peer_ip, enum_frontend_asic_index)

    test_subnet = "10.99.1.1/24"
    nhop_ips = []

    # Save original CRM polling interval before any mutations
    crm_summary = duthost.command("crm show summary", module_ignore_errors=True).get("stdout", "")
    parsed = re.findall(r'Polling Interval:\s+(\d+)\s+second', crm_summary)
    original_poll_interval = int(parsed[0]) if parsed else 300
    logger.info("Original CRM polling interval: %ds", original_poll_interval)

    try:
        # Best-effort pre-cleanup in case a previous run left state behind
        duthost.command("{} route del {}".format(asichost.ip_cmd, TEST_ROUTE_PREFIX), module_ignore_errors=True)
        duthost.command("{} addr del {} dev {}".format(asichost.ip_cmd, test_subnet, intf_name),
                        module_ignore_errors=True)

        # Setup: add subnet, static ARP entries, configure CRM polling
        duthost.command("{} addr add {} dev {}".format(asichost.ip_cmd, test_subnet, intf_name),
                        module_ignore_errors=True)
        for i in range(2, 2 + ECMP_INCREMENT + 1):
            ip = "10.99.1.{}".format(i)
            mac = "00:01:02:03:05:{:02x}".format(i)
            duthost.command("{} neigh replace {} lladdr {} dev {}".format(
                asichost.ip_cmd, ip, mac, intf_name))
            nhop_ips.append(ip)
        logger.info("Created %d next-hop IPs on %s", len(nhop_ips), intf_name)

        duthost.command("crm config polling interval 10", module_ignore_errors=True)

        def _crm_ready():
            return get_crm_nhg_member_used(asichost) is not None
        pytest_assert(wait_until(360, 10, 10, _crm_ready), "CRM stats not populated after 360s")

        crm_baseline = get_crm_nhg_member_used(asichost)
        pytest_assert(crm_baseline is not None, "CRM baseline is None after _crm_ready passed")
        logger.info("CRM baseline: nhg_member_used=%s", crm_baseline)

        # Phase 1: 2-NH route
        logger.info("=== PHASE 1: Create 2-NH ECMP route ===")
        marker1 = get_syslog_marker(duthost)
        nhops_str = " ".join(["nexthop via {}".format(ip) for ip in nhop_ips[:2]])
        duthost.command("{} route add {} {}".format(asichost.ip_cmd, TEST_ROUTE_PREFIX, nhops_str))
        time.sleep(CRM_POLL_WAIT)

        fec1 = collect_fec_logs(duthost, syncd_name, marker1)
        logger.info("Phase 1 FEC: %s", fec1)
        pytest_assert(ECMP_INCREMENT in fec1,
                      "Phase 1: Expected num_fec({}), got {}".format(ECMP_INCREMENT, fec1))

        crm1 = get_crm_nhg_member_used(asichost)
        pytest_assert(crm1 is not None and crm1 > crm_baseline,
                      "Phase 1: CRM did not increase ({} -> {})".format(crm_baseline, crm1))

        # Phase 2: grow to ECMP_INCREMENT+1 NHs (exceeds single-slot allocation)
        logger.info("=== PHASE 2: Grow to 9-NH ECMP route ===")
        duthost.command("{} route del {}".format(asichost.ip_cmd, TEST_ROUTE_PREFIX), module_ignore_errors=True)

        def _route_removed():
            result = duthost.command(
                "{} route show {}".format(asichost.ip_cmd, TEST_ROUTE_PREFIX), module_ignore_errors=True)
            return TEST_ROUTE_PREFIX not in result.get("stdout", "")
        pytest_assert(wait_until(30, 2, 0, _route_removed),
                      "Phase 2: Route {} not removed within 30s".format(TEST_ROUTE_PREFIX))

        # Place marker after delete so Phase 2 logs only capture the 9-NH add
        marker2 = get_syslog_marker(duthost)
        nhops_str = " ".join(["nexthop via {}".format(ip) for ip in nhop_ips[:ECMP_INCREMENT + 1]])
        duthost.command("{} route add {} {}".format(asichost.ip_cmd, TEST_ROUTE_PREFIX, nhops_str))
        time.sleep(CRM_POLL_WAIT)

        fec2 = collect_fec_logs(duthost, syncd_name, marker2)
        logger.info("Phase 2 FEC: %s", fec2)
        pytest_assert(any(v == 2 * ECMP_INCREMENT for v in fec2),
                      "Phase 2: Expected num_fec({}), got {}".format(2 * ECMP_INCREMENT, fec2))

        crm2 = get_crm_nhg_member_used(asichost)
        pytest_assert(crm2 is not None and crm2 > crm1,
                      "Phase 2: CRM did not grow ({} -> {})".format(crm1, crm2))

        # Phase 3: delete route, CRM returns to baseline
        logger.info("=== PHASE 3: Delete route ===")
        duthost.command("{} route del {}".format(asichost.ip_cmd, TEST_ROUTE_PREFIX), module_ignore_errors=True)

        def _crm_back_to_baseline():
            val = get_crm_nhg_member_used(asichost)
            return val is not None and val == crm_baseline
        pytest_assert(wait_until(60, 5, 5, _crm_back_to_baseline),
                      "Phase 3: CRM not back to baseline ({}) within 60s".format(crm_baseline))

        crm3 = get_crm_nhg_member_used(asichost)
        logger.info("Phase 3 CRM: %s (baseline %s)", crm3, crm_baseline)

        logger.info("ALL PHASES PASSED: increment=%d verified via syslog + CRM", ECMP_INCREMENT)

    finally:
        # Cleanup regardless of pass/fail
        duthost.command("{} route del {}".format(asichost.ip_cmd, TEST_ROUTE_PREFIX),
                        module_ignore_errors=True)
        for ip in nhop_ips:
            duthost.command("{} neigh del {} dev {}".format(asichost.ip_cmd, ip, intf_name),
                            module_ignore_errors=True)
        duthost.command("{} addr del {} dev {}".format(asichost.ip_cmd, test_subnet, intf_name),
                        module_ignore_errors=True)
        duthost.command(
            "crm config polling interval {}".format(original_poll_interval),
            module_ignore_errors=True)
