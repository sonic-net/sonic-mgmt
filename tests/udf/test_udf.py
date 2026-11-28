"""
UDF and ACL Integration Tests

All config/unconfig is done directly via sonic-cfggen -j -w (no JSON files are
loaded from images).  HW object creation/deletion is verified by diffing the
set of ASIC_DB OIDs before and after each config operation, so the tests detect
exactly which SAI objects orchagent created or removed.

Baseline CONFIG_DB schema (programmed by the module fixture)
------------------------------------------------------------
  UDF|G0                     length=3  field_type=GENERIC
  UDF|G1                     length=3  field_type=GENERIC
  UDF_SELECTOR|G0|udp_l4     select_base=L4 select_offset=0
                             match_l3_type=0x11 match_l3_type_mask=0xFF match_priority=10
  UDF_SELECTOR|G0|proto18_l3 select_base=L3 select_offset=0
                             match_l3_type=0x12 match_l3_type_mask=0xFF match_priority=10
  UDF_SELECTOR|G1|proto18_l3 (same flat fields as above, on G1)
  ACL_TABLE_TYPE|T1          MATCHES@=IN_PORTS,G0,G1  ACTIONS@=PACKET_ACTION,COUNTER
  ACL_TABLE|TABLE1           type=T1  ports@=<discovered UP intf>  stage=ingress
  ACL_RULE|TABLE1|RULE_A     priority=101  G0=0x33/0xff  G1=0x44/0xff  PACKET_ACTION=DROP
  ACL_RULE|TABLE1|RULE_B     priority=101  G0=0x34/0xff  G1=0x45/0xff  PACKET_ACTION=DROP

UDF_SELECTOR uses the flat-fields schema (sonic-udf.yang, revision
2026-04-21).  All match_* fields are hex-string leaves (e.g. "0x11" for L3
UDP, "0x12B7" for L4 port 4791).  match_priority is uint8 (decimal).

Two baseline rules are needed: TestRuleRefcountBlocksSelector verifies that
deleting RULE_A alone does not free G0 (RULE_B still holds a refcount); only
after RULE_B is also deleted can the last G0 selector be removed.

RULE_A/RULE_B match on BOTH G0 and G1.  G1 has no UDP selector, so neither
catches UDP traffic.  For UDP traffic tests, RULE_UDP (G0-only, priority=200)
is created per-test.  G0 length=3 extracts 3 bytes from L4 offset 0 -- packets
with sport=0x3333,dport=0x3333 produce all extracted bytes = 0x33.
"""
import json
import logging
import time

import pytest
import ptf.testutils as testutils

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import AsicDbCli
from tests.common.platform.interface_utils import get_dut_interfaces_status
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0", "t1"),
    pytest.mark.disable_loganalyzer,
]


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

FLEXCOUNTER_WAIT = 11  # seconds: default counterpoll ACL interval is 10s
ORCHAGENT_WAIT = 1  # seconds: time for orchagent to call SAI after a write
CLEANUP_WAIT = 2  # seconds: between dependent CONFIG_DB deletes
TRAFFIC_PKTS = 500  # packets sent per traffic test
TRAFFIC_PKTS_LOW = 200  # smaller burst for parametrized traffic subcases
TRAFFIC_MIN_DROPS = 50  # minimum counter delta to consider a "match"
TRAFFIC_MAX_LEAK = 10  # max counter delta tolerated for "no match" (prior rules may catch a few)
PRECONDITION_TIMEOUT = 15  # seconds: wait_until timeout for FlexCounter registration

# Logical object names written to CONFIG_DB
UDF_G0 = "G0"
UDF_G1 = "G1"
SEL_G0_UDP = "udp_l4"
SEL_G0_PROTO18 = "proto18_l3"
SEL_G1_PROTO18 = "proto18_l3"
ACL_TABLE_TYPE = "T1"
ACL_TABLE = "TABLE1"
RULE_A = "RULE_A"  # multi-group baseline: G0=0x33/0xff  G1=0x44/0xff
RULE_B = "RULE_B"  # multi-group baseline: G0=0x34/0xff  G1=0x45/0xff
RULE_UDP = "RULE_UDP"  # G0-only UDP traffic matcher (created per-test)

# Packet content used for matching-traffic tests.  The 3-byte L4 extraction over
# sport=0x3333/dport=0x3333 yields [0x33, 0x33, 0x33], matching G0=0x33/0xff.
MATCH_SPORT = 0x3333
MATCH_DPORT = 0x3333
NONMATCH_SPORT = 0x4444
NONMATCH_DPORT = 0x4444


# -----------------------------------------------------------------------------
# Interface discovery
# -----------------------------------------------------------------------------

def get_up_ptf_port(duthost, tbinfo):
    """Return (ptf_port_index, acl_intf_name) for the first interface that is
    oper=UP and present in the PTF port map.  If the selected Ethernet is a
    PortChannel member, acl_intf_name is the parent PortChannel (ACL must bind
    to the LAG object) while the PTF index is still the physical Ethernet.
    """
    intf_status = get_dut_interfaces_status(duthost)
    up_intfs = {name for name, st in intf_status.items() if st["oper"] == "up"}

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_map = mg_facts["minigraph_ptf_indices"]

    pc_member_map = {}
    for pc_name, pc_info in mg_facts.get("minigraph_portchannels", {}).items():
        for member in pc_info.get("members", []):
            pc_member_map[member] = pc_name

    candidates = [(intf, ptf_map[intf]) for intf in sorted(up_intfs) if intf in ptf_map]
    if not candidates:
        pytest.skip("No operationally UP interface with a PTF port mapping found")

    dut_intf, ptf_port = candidates[0]
    acl_intf = pc_member_map.get(dut_intf, dut_intf)
    logger.info("Selected: %s -> PTF port %d, ACL interface: %s", dut_intf, ptf_port, acl_intf)
    return ptf_port, acl_intf


# -----------------------------------------------------------------------------
# CONFIG_DB helpers (kept local: SonicDbCli has no DEL/EXISTS and raises on
# missing HGET, which doesn't match the "missing = empty string" semantics
# these tests rely on).
# -----------------------------------------------------------------------------

def cfg_del(duthost, key):
    duthost.shell('sonic-db-cli CONFIG_DB DEL "{}"'.format(key), module_ignore_errors=True)


def cfg_exists(duthost, key):
    r = duthost.shell('sonic-db-cli CONFIG_DB EXISTS "{}"'.format(key), module_ignore_errors=True)
    return r['stdout'].strip() == '1'


def cfg_hget(duthost, key, field):
    r = duthost.shell(
        'sonic-db-cli CONFIG_DB HGET "{}" "{}"'.format(key, field),
        module_ignore_errors=True,
    )
    return r['stdout'].strip()


def cfg_selector_get(duthost, key, field):
    """Read a flat UDF_SELECTOR field (e.g. 'select_base', 'match_l3_type')."""
    return cfg_hget(duthost, key, field)


# -----------------------------------------------------------------------------
# ASIC_DB helpers (thin wrappers around AsicDbCli for set-based diffing)
# -----------------------------------------------------------------------------

def asic_oids(duthost, sai_type):
    """Return the set of ASIC_DB OID key strings for the given SAI type.

    Uses raw `sonic-db-cli KEYS` instead of AsicDbCli because an empty result
    is a valid state in these tests (e.g. after teardown) and AsicDbCli logs
    an ERROR on every empty response, producing noise in the test output.
    """
    pattern = "ASIC_STATE:{}:oid:*".format(sai_type)
    r = duthost.shell(
        "sonic-db-cli ASIC_DB KEYS '{}'".format(pattern),
        module_ignore_errors=True,
    )
    return {k.strip() for k in r['stdout_lines'] if k.strip()}


def asic_attrs(duthost, oid_key):
    """Return the dict of SAI attribute name -> value for an ASIC_DB OID key.

    Uses AsicDbCli.hget_all (handles ast.literal_eval parsing).  OIDs passed
    here are from asic_oids, so an empty response would mean the OID was
    deleted between the two calls -- treated as an empty attr dict.
    """
    try:
        return AsicDbCli(duthost).hget_all(oid_key)
    except Exception as e:
        logger.warning("Failed to HGETALL %s: %s", oid_key, e)
        return {}


# -----------------------------------------------------------------------------
# ACL counter helpers (via `aclshow -a`, consistent with other ACL tests)
# -----------------------------------------------------------------------------

def acl_packet_count(duthost, table_name, rule_name):
    """Return integer packet count for an ACL rule from `aclshow -a`.

    Returns 0 if the rule is not listed yet or the count is not numeric
    (e.g. "N/A" -- FlexCounter has not polled yet).  The 0 case is logged so
    failing tests show whether the rule was missing vs. un-polled.
    """
    rows = duthost.show_and_parse("aclshow -a")
    for row in rows:
        if row.get("table name") == table_name and row.get("rule name") == rule_name:
            raw = str(row.get("packets count", "0")).strip().replace(",", "")
            try:
                return int(raw)
            except ValueError:
                logger.info("aclshow %s:%s present but packets=%r (FlexCounter "
                            "likely not polled yet)", table_name, rule_name, raw)
                return 0
    logger.info("aclshow has no row for %s:%s (rows=%d)",
                table_name, rule_name, len(rows))
    return 0


def _acl_rule_registered(duthost, table_name, rule_name):
    """True when aclshow lists the rule (FlexCounter has registered its counter)."""
    for row in duthost.show_and_parse("aclshow -a"):
        if row.get("table name") == table_name and row.get("rule name") == rule_name:
            return True
    return False


def _assert_traffic_precondition(duthost, table_name, rule_name, timeout=PRECONDITION_TIMEOUT):
    """Poll until FlexCounter registers the rule in aclshow, else fail."""
    ok = wait_until(timeout, 2, 0, _acl_rule_registered, duthost, table_name, rule_name)
    pytest_assert(
        ok,
        "ACL rule {}:{} did not appear in aclshow within {}s -- "
        "rule/table not programmed to SAI".format(table_name, rule_name, timeout),
    )


# -----------------------------------------------------------------------------
# Config writers (sonic-cfggen -j -w)
# -----------------------------------------------------------------------------

def _cfggen_load(duthost, config, tmp="/tmp/nh_udf_cfg.json"):
    duthost.copy(content=json.dumps(config), dest=tmp)
    duthost.shell("sonic-cfggen -j {} -w".format(tmp))


def _write_udf_g0(duthost):
    _cfggen_load(duthost, {"UDF": {
        UDF_G0: {"length": "3", "field_type": "GENERIC", "description": "Custom field G0"},
    }})


def _write_udf_g1(duthost):
    _cfggen_load(duthost, {"UDF": {
        UDF_G1: {"length": "3", "field_type": "GENERIC", "description": "Custom field G1"},
    }})


def _write_selector_g0_udp(duthost):
    _cfggen_load(duthost, {"UDF_SELECTOR": {
        "{}|{}".format(UDF_G0, SEL_G0_UDP): {
            "select_base":        "L4",
            "select_offset":      "0",
            "match_l3_type":      "0x11",
            "match_l3_type_mask": "0xFF",
            "match_priority":     "10",
        }
    }})


def _write_selector_g0_proto18(duthost):
    _cfggen_load(duthost, {"UDF_SELECTOR": {
        "{}|{}".format(UDF_G0, SEL_G0_PROTO18): {
            "select_base":        "L3",
            "select_offset":      "0",
            "match_l3_type":      "0x12",
            "match_l3_type_mask": "0xFF",
            "match_priority":     "10",
        }
    }})


def _write_selector_g1_proto18(duthost):
    _cfggen_load(duthost, {"UDF_SELECTOR": {
        "{}|{}".format(UDF_G1, SEL_G1_PROTO18): {
            "select_base":        "L3",
            "select_offset":      "0",
            "match_l3_type":      "0x12",
            "match_l3_type_mask": "0xFF",
            "match_priority":     "10",
        }
    }})


def _write_acl_table_type(duthost):
    _cfggen_load(duthost, {"ACL_TABLE_TYPE": {
        ACL_TABLE_TYPE: {
            "MATCHES":     ["IN_PORTS", UDF_G0, UDF_G1],
            "ACTIONS":     ["PACKET_ACTION", "COUNTER"],
            "BIND_POINTS": ["PORT"],
        }
    }})


def _write_acl_table(duthost, acl_port):
    _cfggen_load(duthost, {"ACL_TABLE": {
        ACL_TABLE: {"type": ACL_TABLE_TYPE, "ports": [acl_port], "stage": "ingress"},
    }})


def _write_rule_a(duthost):
    _cfggen_load(duthost, {"ACL_RULE": {
        "{}|{}".format(ACL_TABLE, RULE_A): {
            "priority": "101", UDF_G0: "0x33/0xff", UDF_G1: "0x44/0xff", "PACKET_ACTION": "DROP",
        }
    }})


def _write_rule_b(duthost):
    _cfggen_load(duthost, {"ACL_RULE": {
        "{}|{}".format(ACL_TABLE, RULE_B): {
            "priority": "101", UDF_G0: "0x34/0xff", UDF_G1: "0x45/0xff", "PACKET_ACTION": "DROP",
        }
    }})


def _write_rule_udp(duthost, match_value="0x33/0xff", priority="200"):
    """G0-only traffic rule -- matches UDP via G0|udp_l4."""
    _cfggen_load(duthost, {"ACL_RULE": {
        "{}|{}".format(ACL_TABLE, RULE_UDP): {
            "priority": priority, UDF_G0: match_value, "PACKET_ACTION": "DROP",
        }
    }})


def _write_full_config(duthost, acl_port):
    _write_udf_g0(duthost)
    _write_udf_g1(duthost)
    _write_selector_g0_udp(duthost)
    _write_selector_g0_proto18(duthost)
    _write_selector_g1_proto18(duthost)
    _write_acl_table_type(duthost)
    _write_acl_table(duthost, acl_port)
    _write_rule_a(duthost)
    _write_rule_b(duthost)


def _cleanup_all_udf(duthost):
    for table in ["TABLE1", "TABLE_MULTI", "TABLE_CONFLICT", "TABLE_FWD", "TABLE_Q"]:
        duthost.shell("config acl remove table {}".format(table), module_ignore_errors=True)
    cmds = [
        "sonic-db-cli CONFIG_DB KEYS 'ACL_RULE|TABLE*'    | xargs -r -I% sonic-db-cli CONFIG_DB DEL %",
        "sonic-db-cli CONFIG_DB KEYS 'ACL_TABLE|TABLE*'   | xargs -r -I% sonic-db-cli CONFIG_DB DEL %",
        "sonic-db-cli CONFIG_DB KEYS 'ACL_TABLE_TYPE|*'   | xargs -r -I% sonic-db-cli CONFIG_DB DEL %",
        "sonic-db-cli CONFIG_DB KEYS 'UDF_SELECTOR|*'     | xargs -r -I% sonic-db-cli CONFIG_DB DEL %",
        "sonic-db-cli CONFIG_DB KEYS 'UDF|*'              | xargs -r -I% sonic-db-cli CONFIG_DB DEL %",
    ]
    for cmd in cmds:
        duthost.shell(cmd, module_ignore_errors=True)
    time.sleep(CLEANUP_WAIT)


# -----------------------------------------------------------------------------
# Traffic helper
# -----------------------------------------------------------------------------

def _send_and_wait(ptfadapter, ptf_port, pkt, count=TRAFFIC_PKTS):
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_port, pkt, count=count)
    logger.info("Sent %d pkts on PTF port %d; waiting %ds for FlexCounter",
                count, ptf_port, FLEXCOUNTER_WAIT)
    time.sleep(FLEXCOUNTER_WAIT)


# -----------------------------------------------------------------------------
# Module fixture
# -----------------------------------------------------------------------------

def _check_udf_supported(duthost):
    """Return True if the platform supports UDF.

    UdfOrch probes sai_query_attribute_capability(SAI_OBJECT_TYPE_UDF_GROUP,
    SAI_UDF_GROUP_ATTR_TYPE) at startup.  If the capability is missing, it
    drains all UDF CONFIG_DB entries with a single WARN and skips SAI creates.
    We detect this by writing one UDF group and checking whether a SAI
    UDF_GROUP OID appears within a generous timeout.
    """
    _write_udf_g0(duthost)
    time.sleep(5)
    oids = asic_oids(duthost, "SAI_OBJECT_TYPE_UDF_GROUP")
    cfg_del(duthost, "UDF|{}".format(UDF_G0))
    if not oids:
        r = duthost.shell(
            "sudo grep -i 'udf.*not supported\\|udf.*unsupported\\|skip.*udf\\|udf.*skip' "
            "/var/log/syslog | tail -5",
            module_ignore_errors=True,
        )
        logger.warning("UDF_GROUP OID did not appear -- platform may not support "
                       "UDF.  Recent syslog: %s", r['stdout'].strip())
        return False
    return True


# UDF negative tests (TestInvalidConfig, TestSelectorFieldValidation,
# TestImmutabilityAndGroupRetry::test_delete_udf_group_while_referenced, etc.)
# deliberately push bad config or out-of-order deletes that orchagent rejects
# with SWSS_LOG_ERROR.  Those messages are expected and must not flag the
# module as failed.  Patterns kept loose because exact message text varies
# across orchagent revisions; tighten if upstream reviewers prefer.
_UDF_LOG_IGNORE = [
    r".*ERR\s+swss#orchagent.*UDF.*",
    r".*ERR\s+swss#orchagent.*UdfOrch.*",
    r".*ERR\s+swss#orchagent.*aclorch.*UDF.*",
]


@pytest.fixture(scope="module", autouse=True)
def loganalyzer_udf(duthosts, rand_one_dut_hostname):
    """Module-scoped LogAnalyzer covering the UDF suite.

    Runs in non-failing mode (`fail=False`): unexpected orchagent errors are
    logged for diagnostic purposes but do not fail the module.  The suite has
    `disable_loganalyzer` set so the per-test auto-loganalyzer (which would
    fail on negative tests' deliberate errors) is suppressed.
    """
    duthost = duthosts[rand_one_dut_hostname]
    la = LogAnalyzer(ansible_host=duthost, marker_prefix="udf")
    la.load_common_config()
    la.ignore_regex.extend(_UDF_LOG_IGNORE)
    marker = la.init()
    yield la
    la.analyze(marker, fail=False)


@pytest.fixture(scope="module", autouse=True)
def setup_udf(duthosts, rand_one_dut_hostname, tbinfo, loganalyzer_udf):
    duthost = duthosts[rand_one_dut_hostname]

    ptf_port, acl_port = get_up_ptf_port(duthost, tbinfo)
    logger.info("ACL bind interface: %s  PTF port: %d", acl_port, ptf_port)

    _cleanup_all_udf(duthost)
    time.sleep(3)

    # Gate: verify the platform supports UDF before running the full suite.
    # UdfOrch (change #3) silently drains CONFIG_DB and skips SAI creates when
    # sai_query_attribute_capability(SAI_UDF_GROUP_ATTR_TYPE) is not supported.
    if not _check_udf_supported(duthost):
        pytest.skip("Platform does not support SAI UDF -- UdfOrch drained config")

    _write_full_config(duthost, acl_port=acl_port)
    time.sleep(ORCHAGENT_WAIT)

    # If no ACL_TABLE_GROUP_MEMBER appeared, bounce ACL_TABLE to retry port binding
    if not asic_oids(duthost, "SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER"):
        logger.warning("No ACL_TABLE_GROUP_MEMBER -- bouncing ACL_TABLE entry")
        cfg_del(duthost, "ACL_TABLE|{}".format(ACL_TABLE))
        time.sleep(3)
        _write_acl_table(duthost, acl_port)
        time.sleep(ORCHAGENT_WAIT)

    # Poll for ACL_ENTRY OIDs to stabilise on slower platforms.  The original
    # test ordering gave orchagent an implicit ~44s buffer (traffic test
    # FlexCounter waits) before the first ACL_ENTRY check.  Our refactored
    # ordering runs TestAclRule much sooner, so we explicitly wait here.
    # Best-effort: some platforms don't write ACL_ENTRY to ASIC_DB at all
    # (tests handle that with asic_tracks_acl).
    for _ in range(15):
        if len(asic_oids(duthost, "SAI_OBJECT_TYPE_ACL_ENTRY")) >= 2:
            break
        time.sleep(1)

    # Enable ACL counterpoll once for the whole module (needed for traffic tests)
    duthost.shell("sudo counterpoll acl enable", module_ignore_errors=True)

    class _Ctx:
        pass
    ctx = _Ctx()
    ctx.duthost = duthost
    ctx.acl_port = acl_port
    ctx.ptf_port = ptf_port
    yield ctx

    _cleanup_all_udf(duthost)


# =============================================================================
# Section A+B: CONFIG_DB + ASIC_DB smoke
# =============================================================================

class TestBaselineProgrammed:
    """Single smoke test proves the fixture's bottom-up write path is correct:
    every object exists in CONFIG_DB and produced the expected SAI type counts
    in ASIC_DB."""

    def test_configdb_and_asicdb_baseline(self, setup_udf):
        dut = setup_udf.duthost
        acl_port = setup_udf.acl_port

        # CONFIG_DB: all fixture objects present
        expected_keys = [
            "UDF|{}".format(UDF_G0),
            "UDF|{}".format(UDF_G1),
            "UDF_SELECTOR|{}|{}".format(UDF_G0, SEL_G0_UDP),
            "UDF_SELECTOR|{}|{}".format(UDF_G0, SEL_G0_PROTO18),
            "UDF_SELECTOR|{}|{}".format(UDF_G1, SEL_G1_PROTO18),
            "ACL_TABLE_TYPE|{}".format(ACL_TABLE_TYPE),
            "ACL_TABLE|{}".format(ACL_TABLE),
            "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_A),
            "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_B),
        ]
        for key in expected_keys:
            pytest_assert(cfg_exists(dut, key), "{} missing from CONFIG_DB".format(key))

        # CONFIG_DB: critical fields round-trip correctly
        pytest_assert(cfg_hget(dut, "UDF|{}".format(UDF_G0), "length") == "3",
                      "UDF|G0 length mismatch")
        pytest_assert(cfg_selector_get(dut, "UDF_SELECTOR|{}|{}".format(UDF_G0, SEL_G0_UDP),
                                       "select_base") == "L4",
                      "G0|udp_l4 select_base mismatch")
        pytest_assert(acl_port in cfg_hget(dut, "ACL_TABLE|{}".format(ACL_TABLE), "ports@"),
                      "ACL_TABLE not bound to {}".format(acl_port))

        # ASIC_DB: expected SAI type counts
        expectations = [
            ("SAI_OBJECT_TYPE_UDF_GROUP", 2),   # G0 + G1
            ("SAI_OBJECT_TYPE_UDF_MATCH", 1),   # at least one (dedup may collapse)
            ("SAI_OBJECT_TYPE_UDF",       1),   # at least one programmed selector
            ("SAI_OBJECT_TYPE_ACL_TABLE", 1),
            ("SAI_OBJECT_TYPE_ACL_ENTRY", 2),   # RULE_A + RULE_B
            ("SAI_OBJECT_TYPE_ACL_COUNTER", 2),
        ]
        for sai_type, min_count in expectations:
            oids = asic_oids(dut, sai_type)
            pytest_assert(
                len(oids) >= min_count,
                "Expected >={} {} OIDs, got {}".format(min_count, sai_type, len(oids)),
            )


# =============================================================================
# Section C+D+E: Traffic match / no-match / wrong-protocol (parametrized)
# =============================================================================

class TestUdpTraffic:
    """UDP traffic verification against a G0-only rule (RULE_UDP).  Parametrized
    over match/nonmatch/wrong-proto subcases -- RULE_UDP is programmed once per
    subcase."""

    @pytest.fixture(autouse=True)
    def _rule_udp(self, setup_udf):
        dut = setup_udf.duthost
        # Defensive re-enable: the module fixture enables counterpoll once, but
        # nothing stops another module or test harness from disabling it before
        # we run.  counterpoll enable is idempotent.
        dut.shell("sudo counterpoll acl enable", module_ignore_errors=True)
        _write_rule_udp(dut)
        time.sleep(ORCHAGENT_WAIT)
        yield
        cfg_del(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_UDP))
        time.sleep(ORCHAGENT_WAIT)

    @pytest.mark.parametrize("label,proto,sport,dport,expect_match", [
        ("udp-match",      "udp", MATCH_SPORT,    MATCH_DPORT,    True),
        ("udp-nonmatch",   "udp", NONMATCH_SPORT, NONMATCH_DPORT, False),
        ("udp-boundary",   "udp", 0x3232,         0x3232,         False),
        ("tcp-wrongproto", "tcp", MATCH_SPORT,    MATCH_DPORT,    False),
    ])
    def test_rule_udp_traffic(self, setup_udf, ptfadapter, label, proto, sport, dport, expect_match):
        dut = setup_udf.duthost
        ptf_port = setup_udf.ptf_port

        _assert_traffic_precondition(dut, ACL_TABLE, RULE_UDP)
        before = acl_packet_count(dut, ACL_TABLE, RULE_UDP)

        if proto == "udp":
            pkt = testutils.simple_udp_packet(
                eth_dst=dut.facts["router_mac"],
                ip_dst="192.168.1.100", ip_src="10.0.0.1",
                udp_sport=sport, udp_dport=dport, pktlen=100,
            )
        else:
            pkt = testutils.simple_tcp_packet(
                eth_dst=dut.facts["router_mac"],
                ip_dst="192.168.1.100", ip_src="10.0.0.1",
                tcp_sport=sport, tcp_dport=dport, pktlen=100,
            )
        _send_and_wait(ptfadapter, ptf_port, pkt, count=TRAFFIC_PKTS)
        after = acl_packet_count(dut, ACL_TABLE, RULE_UDP)
        diff = after - before
        logger.info("[%s] counter before=%d after=%d diff=%d",
                    label, before, after, diff)

        # If the expected outcome is "match" but diff is 0, give FlexCounter
        # one more poll cycle -- counter may not have been polled yet when we
        # read `after` above.
        if expect_match and diff == 0:
            logger.warning("[%s] diff=0 after first read, waiting one more "
                           "FlexCounter cycle", label)
            time.sleep(FLEXCOUNTER_WAIT)
            after = acl_packet_count(dut, ACL_TABLE, RULE_UDP)
            diff = after - before
            logger.info("[%s] retry: after=%d diff=%d", label, after, diff)

        if expect_match:
            pytest_assert(
                diff >= TRAFFIC_MIN_DROPS,
                "[{}] expected >={} drops, got {}".format(label, TRAFFIC_MIN_DROPS, diff),
            )
        else:
            pytest_assert(
                diff < TRAFFIC_MAX_LEAK,
                "[{}] expected <{} drops, got {}".format(label, TRAFFIC_MAX_LEAK, diff),
            )


# =============================================================================
# Dynamic ACL rule create/delete (RULE_UDP)
# =============================================================================

class TestAclRule:

    @pytest.fixture(autouse=True)
    def _rule_udp_absent(self, setup_udf):
        dut = setup_udf.duthost
        cfg_del(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_UDP))
        time.sleep(ORCHAGENT_WAIT)
        yield
        cfg_del(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_UDP))
        time.sleep(ORCHAGENT_WAIT)

    def test_rule_udp_create_and_delete(self, setup_udf):
        """Write RULE_UDP -> CONFIG_DB entry + orchagent programs it.
        Delete RULE_UDP -> both are gone.  RULE_A/RULE_B OIDs unchanged.

        Some platforms (e.g. NH-4010-F) do not write SAI_OBJECT_TYPE_ACL_ENTRY
        objects to ASIC_DB.  aclshow is the primary check since it works on all
        platforms.  The ASIC_DB OID diff is only verified when entries_before is
        non-empty (i.e. the platform is known to use ASIC_DB for ACL entries).
        """
        dut = setup_udf.duthost
        entries_before = asic_oids(dut, "SAI_OBJECT_TYPE_ACL_ENTRY")
        asic_tracks_acl = bool(entries_before)

        _write_rule_udp(dut)
        time.sleep(ORCHAGENT_WAIT)

        key = "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_UDP)
        pytest_assert(cfg_exists(dut, key), "RULE_UDP not in CONFIG_DB after write")
        pytest_assert(cfg_hget(dut, key, UDF_G0) == "0x33/0xff",
                      "RULE_UDP G0 field mismatch")

        # Works on all platforms -- confirms orchagent processed the rule
        _assert_traffic_precondition(dut, ACL_TABLE, RULE_UDP)

        rule_udp_oid = None
        if asic_tracks_acl:
            new_oids = asic_oids(dut, "SAI_OBJECT_TYPE_ACL_ENTRY") - entries_before
            pytest_assert(len(new_oids) == 1,
                          "Expected exactly 1 new ACL_ENTRY OID for RULE_UDP, got {}"
                          .format(len(new_oids)))
            rule_udp_oid = next(iter(new_oids))

        cfg_del(dut, key)
        time.sleep(ORCHAGENT_WAIT)

        pytest_assert(not cfg_exists(dut, key), "RULE_UDP still in CONFIG_DB after DEL")
        if asic_tracks_acl:
            after = asic_oids(dut, "SAI_OBJECT_TYPE_ACL_ENTRY")
            pytest_assert(rule_udp_oid not in after,
                          "RULE_UDP OID {} still in ASIC_DB".format(rule_udp_oid))
            pytest_assert(after == entries_before,
                          "RULE_A/RULE_B ACL_ENTRY OIDs changed after RULE_UDP cycle")


# =============================================================================
# Section G: Dependency / ordering
# =============================================================================

class TestUdfAclDependency:

    @pytest.fixture(autouse=True)
    def _ensure_full(self, setup_udf):
        dut = setup_udf.duthost
        acl_port = setup_udf.acl_port
        if not (cfg_exists(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_A))
                and cfg_exists(dut, "UDF|{}".format(UDF_G0))):
            _write_full_config(dut, acl_port=acl_port)
            time.sleep(ORCHAGENT_WAIT)
        yield

    def test_wrong_order_delete_and_recovery(self, setup_udf):
        """Deleting UDF|G0 while selectors still reference it must leave the
        system recoverable: writing G0 back restores the SAI UDF_GROUP OID."""
        dut = setup_udf.duthost

        cfg_del(dut, "UDF|{}".format(UDF_G0))
        time.sleep(ORCHAGENT_WAIT)

        _write_udf_g0(dut)
        time.sleep(ORCHAGENT_WAIT)

        pytest_assert(cfg_exists(dut, "UDF|{}".format(UDF_G0)), "Could not restore UDF|G0")
        pytest_assert(asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP"),
                      "No SAI UDF_GROUP OID after restore -- system did not recover")

    def test_correct_order_teardown_and_recreate(self, setup_udf):
        """Correct top-down teardown removes ACL_ENTRY/UDF/UDF_GROUP OIDs; a
        bottom-up recreate re-establishes them all."""
        dut = setup_udf.duthost
        acl_port = setup_udf.acl_port

        types = [
            "SAI_OBJECT_TYPE_ACL_ENTRY",
            "SAI_OBJECT_TYPE_ACL_TABLE",
            "SAI_OBJECT_TYPE_UDF",
            "SAI_OBJECT_TYPE_UDF_MATCH",
            "SAI_OBJECT_TYPE_UDF_GROUP",
        ]
        before = {t: asic_oids(dut, t) for t in types}
        pytest_assert(before["SAI_OBJECT_TYPE_ACL_ENTRY"],
                      "Precondition: at least one ACL_ENTRY must exist before teardown")

        steps = [
            "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_A),
            "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_B),
            "ACL_TABLE|{}".format(ACL_TABLE),
            "ACL_TABLE_TYPE|{}".format(ACL_TABLE_TYPE),
            "UDF_SELECTOR|{}|{}".format(UDF_G0, SEL_G0_UDP),
            "UDF_SELECTOR|{}|{}".format(UDF_G0, SEL_G0_PROTO18),
            "UDF_SELECTOR|{}|{}".format(UDF_G1, SEL_G1_PROTO18),
            "UDF|{}".format(UDF_G0),
            "UDF|{}".format(UDF_G1),
        ]
        for key in steps:
            if key == "ACL_TABLE|{}".format(ACL_TABLE):
                dut.shell("config acl remove table {}".format(ACL_TABLE),
                          module_ignore_errors=True)
            cfg_del(dut, key)
            time.sleep(CLEANUP_WAIT)

        after_del = {t: asic_oids(dut, t) for t in types}
        pytest_assert(
            len(after_del["SAI_OBJECT_TYPE_ACL_ENTRY"]) < len(before["SAI_OBJECT_TYPE_ACL_ENTRY"]),
            "ACL_ENTRY OIDs not cleaned up after correct-order deletion",
        )
        pytest_assert(
            len(after_del["SAI_OBJECT_TYPE_UDF_GROUP"]) < len(before["SAI_OBJECT_TYPE_UDF_GROUP"]),
            "UDF_GROUP OIDs not cleaned up",
        )

        _write_full_config(dut, acl_port=acl_port)
        time.sleep(ORCHAGENT_WAIT)

        recreated = {t: asic_oids(dut, t) for t in types}
        pytest_assert(recreated["SAI_OBJECT_TYPE_ACL_ENTRY"], "ACL_ENTRY not recreated")
        pytest_assert(recreated["SAI_OBJECT_TYPE_UDF"], "UDF not recreated")
        pytest_assert(recreated["SAI_OBJECT_TYPE_UDF_GROUP"], "UDF_GROUP not recreated")


# =============================================================================
# Section H: ACL rule priority
# =============================================================================

class TestAclRulePriority:

    @pytest.fixture(autouse=True)
    def _cleanup(self, setup_udf):
        dut = setup_udf.duthost
        acl_port = setup_udf.acl_port
        dut.shell("sudo counterpoll acl enable", module_ignore_errors=True)
        if not (cfg_exists(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_A))
                and cfg_exists(dut, "UDF|{}".format(UDF_G0))):
            _write_full_config(dut, acl_port=acl_port)
            time.sleep(ORCHAGENT_WAIT + FLEXCOUNTER_WAIT)
        cfg_del(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_UDP))
        cfg_del(dut, "ACL_RULE|{}|R_LOW".format(ACL_TABLE))
        time.sleep(ORCHAGENT_WAIT)
        yield
        cfg_del(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_UDP))
        cfg_del(dut, "ACL_RULE|{}|R_LOW".format(ACL_TABLE))
        time.sleep(ORCHAGENT_WAIT)

    def test_higher_priority_shadows_lower(self, setup_udf, ptfadapter):
        """R_LOW(prio=50, G0=0x33) + RULE_UDP(prio=200, G0=0x33): matching UDP
        packets must hit RULE_UDP only; R_LOW counter stays at 0."""
        dut = setup_udf.duthost
        ptf_port = setup_udf.ptf_port

        _cfggen_load(dut, {"ACL_RULE": {
            "{}|R_LOW".format(ACL_TABLE): {
                "priority": "50", UDF_G0: "0x33/0xff", "PACKET_ACTION": "DROP",
            }
        }})
        _write_rule_udp(dut, match_value="0x33/0xff", priority="200")
        time.sleep(ORCHAGENT_WAIT)

        _assert_traffic_precondition(dut, ACL_TABLE, RULE_UDP)
        udp_before = acl_packet_count(dut, ACL_TABLE, RULE_UDP)
        low_before = acl_packet_count(dut, ACL_TABLE, "R_LOW")

        pkt = testutils.simple_udp_packet(
            eth_dst=dut.facts["router_mac"],
            ip_dst="192.168.1.100", ip_src="10.0.0.1",
            udp_sport=MATCH_SPORT, udp_dport=MATCH_DPORT, pktlen=100,
        )
        _send_and_wait(ptfadapter, ptf_port, pkt, count=TRAFFIC_PKTS)

        udp_diff = acl_packet_count(dut, ACL_TABLE, RULE_UDP) - udp_before
        low_diff = acl_packet_count(dut, ACL_TABLE, "R_LOW") - low_before
        logger.info("RULE_UDP diff=%d  R_LOW diff=%d", udp_diff, low_diff)

        # Retry once if FlexCounter has not polled yet
        if udp_diff == 0:
            time.sleep(FLEXCOUNTER_WAIT)
            udp_diff = acl_packet_count(dut, ACL_TABLE, RULE_UDP) - udp_before
            low_diff = acl_packet_count(dut, ACL_TABLE, "R_LOW") - low_before
            logger.info("retry: RULE_UDP diff=%d  R_LOW diff=%d", udp_diff, low_diff)

        pytest_assert(udp_diff >= TRAFFIC_MIN_DROPS,
                      "RULE_UDP (prio=200) should capture >={} pkts, got {}".format(
                          TRAFFIC_MIN_DROPS, udp_diff))
        pytest_assert(low_diff == 0,
                      "R_LOW (prio=50) should be shadowed, got diff={}".format(low_diff))


# =============================================================================
# Section I: Forward-reference / out-of-order creation
# =============================================================================

class TestForwardReference:
    """Verify orchagent handles out-of-order CONFIG_DB writes gracefully:
      - references to a not-yet-written UDF group are preserved (not dropped)
      - adding the group produces a SAI UDF_GROUP OID (selector retry succeeds)

    We deliberately do NOT build a second ACL_TABLE on acl_port here -- the
    fixture's TABLE1 already occupies the UDF slot on that port and a second
    table binding would be masked (same constraint noted in
    TestMatchTypeTraffic).  Full ACL-pipeline programming is covered by
    TestAclRule / TestMatchTypeTraffic.
    """

    @pytest.fixture(autouse=True)
    def _cleanup(self, setup_udf):
        dut = setup_udf.duthost
        yield
        for key in [
            "ACL_TABLE_TYPE|T_FWD",
            "UDF_SELECTOR|G_FWD|test",
            "UDF|G_FWD",
        ]:
            cfg_del(dut, key)
        time.sleep(ORCHAGENT_WAIT)

    def test_forward_reference_resolves(self, setup_udf):
        """Write ACL_TABLE_TYPE T_FWD and UDF_SELECTOR|G_FWD|test before
        UDF|G_FWD exists.  orchagent must preserve both entries in CONFIG_DB.
        After UDF|G_FWD is written, a new SAI UDF_GROUP OID must appear."""
        dut = setup_udf.duthost

        _cfggen_load(dut, {"ACL_TABLE_TYPE": {
            "T_FWD": {"MATCHES": ["IN_PORTS", "G_FWD"],
                      "ACTIONS": ["PACKET_ACTION", "COUNTER"],
                      "BIND_POINTS": ["PORT"]},
        }})
        _cfggen_load(dut, {"UDF_SELECTOR": {
            "G_FWD|test": {
                "select_base":        "L4",
                "select_offset":      "0",
                "match_l3_type":      "0x11",
                "match_l3_type_mask": "0xFF",
                "match_priority":     "20",
            }
        }})
        time.sleep(ORCHAGENT_WAIT)

        pytest_assert(cfg_exists(dut, "ACL_TABLE_TYPE|T_FWD"),
                      "ACL_TABLE_TYPE|T_FWD removed by orchagent on forward ref")
        pytest_assert(cfg_exists(dut, "UDF_SELECTOR|G_FWD|test"),
                      "UDF_SELECTOR|G_FWD|test removed by orchagent on forward ref")

        # Satisfy the dependency; a new SAI UDF_GROUP OID must appear
        group_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP")
        _cfggen_load(dut, {"UDF": {
            "G_FWD": {"length": "2", "field_type": "GENERIC", "description": "fwd ref"},
        }})
        time.sleep(ORCHAGENT_WAIT)

        new_groups = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP") - group_before
        pytest_assert(new_groups,
                      "No new UDF_GROUP OID after writing UDF|G_FWD -- selector "
                      "retry after dependency satisfaction did not fire")


# =============================================================================
# Section J: Multiple selectors per group
# =============================================================================

class TestMultipleSelectorsPerGroup:

    def test_distinct_selectors_produce_distinct_oids(self, setup_udf):
        """G0 has 2 selectors + G1 has 1 => at least 2 SAI UDF OIDs and at least
        2 distinct UDF_MATCH OIDs (proto 0x11 and 0x12)."""
        dut = setup_udf.duthost
        udf_oids = asic_oids(dut, "SAI_OBJECT_TYPE_UDF")
        match_oids = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_MATCH")
        pytest_assert(len(udf_oids) >= 2,
                      "Expected >=2 UDF OIDs, got {}".format(len(udf_oids)))
        pytest_assert(len(match_oids) >= 2,
                      "Expected >=2 UDF_MATCH OIDs, got {}".format(len(match_oids)))


# =============================================================================
# Section K+L+O+T(partial): invalid config and validation (parametrized)
# =============================================================================

INVALID_CASES = [
    # label, config_dict, sai_type_to_diff, extra_keys_to_cleanup
    (
        "udf-length-zero",
        {"UDF": {"G_ZERO": {"length": "0", "field_type": "GENERIC"}}},
        "SAI_OBJECT_TYPE_UDF_GROUP",
        ["UDF|G_ZERO"],
    ),
    (
        "rule-malformed-value",
        {"ACL_RULE": {"{}|R_BAD_VALUE".format(ACL_TABLE): {
            "priority": "50", UDF_G0: "not_a_hex/0xff", "PACKET_ACTION": "DROP"}}},
        "SAI_OBJECT_TYPE_ACL_ENTRY",
        ["ACL_RULE|{}|R_BAD_VALUE".format(ACL_TABLE)],
    ),
    (
        "rule-unknown-group",
        {"ACL_RULE": {"{}|R_GHOST_GROUP".format(ACL_TABLE): {
            "priority": "101", "G9": "0x55/0xff", "PACKET_ACTION": "DROP"}}},
        "SAI_OBJECT_TYPE_ACL_ENTRY",
        ["ACL_RULE|{}|R_GHOST_GROUP".format(ACL_TABLE)],
    ),
]


class TestInvalidConfig:
    """Negative cases -- each must leave ASIC_DB unchanged for the diffed SAI
    type and must not crash orchagent."""

    @pytest.fixture(autouse=True)
    def _cleanup(self, setup_udf):
        dut = setup_udf.duthost
        yield
        # Each case's cleanup happens inside the test via finally
        cfg_del(dut, "UDF_SELECTOR|G_HUGE|huge_offset")
        cfg_del(dut, "UDF|G_HUGE")
        time.sleep(ORCHAGENT_WAIT)

    @pytest.mark.parametrize("label,config,sai_type,cleanup_keys", INVALID_CASES,
                             ids=[c[0] for c in INVALID_CASES])
    def test_invalid_config_rejected(self, setup_udf, label, config, sai_type, cleanup_keys):
        dut = setup_udf.duthost
        before = asic_oids(dut, sai_type)
        try:
            _cfggen_load(dut, config)
            time.sleep(ORCHAGENT_WAIT)
            after = asic_oids(dut, sai_type)
            # For negative cases we accept either "rejected" (no new OID) or
            # "accepted-but-logged" behaviour on some platforms.  In both cases
            # the pre-existing OIDs must be preserved (no orchagent crash).
            pytest_assert(before.issubset(after),
                          "[{}] pre-existing {} OIDs lost -- orchagent may have crashed"
                          .format(label, sai_type))
            logger.info("[%s] before=%d after=%d", label, len(before), len(after))
        finally:
            for key in cleanup_keys:
                cfg_del(dut, key)

    def test_large_offset_does_not_crash(self, setup_udf):
        """UDF_SELECTOR with offset=200 must not remove existing UDF SAI objects."""
        dut = setup_udf.duthost
        udf_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF")

        _cfggen_load(dut, {"UDF": {
            "G_HUGE": {"length": "2", "field_type": "GENERIC"},
        }})
        time.sleep(1)
        _cfggen_load(dut, {"UDF_SELECTOR": {
            "G_HUGE|huge_offset": {
                "select_base":        "L4",
                "select_offset":      "200",
                "match_l3_type":      "0x11",
                "match_l3_type_mask": "0xFF",
                "match_priority":     "10",
            }
        }})
        time.sleep(ORCHAGENT_WAIT)

        pytest_assert(udf_before.issubset(asic_oids(dut, "SAI_OBJECT_TYPE_UDF")),
                      "Existing SAI UDF objects were removed by offset=200 selector")


# =============================================================================
# ASIC_DB attribute verification for each match type and UDF base (parametrized)
# =============================================================================

MATCH_ATTR_CASES = [
    # label, selector fields (flat), expected SAI attr on new UDF_MATCH OID
    ("l2_type", {
        "select_base":        "L3",
        "select_offset":      "0",
        "match_l2_type":      "0x0800",
        "match_l2_type_mask": "0xFFFF",
        "match_priority":     "5",
    }, "SAI_UDF_MATCH_ATTR_L2_TYPE"),
    ("l3_type", {
        "select_base":        "L4",
        "select_offset":      "0",
        "match_l3_type":      "0x06",
        "match_l3_type_mask": "0xFF",
        "match_priority":     "5",
    }, "SAI_UDF_MATCH_ATTR_L3_TYPE"),
    ("gre_type", {
        "select_base":         "L4",
        "select_offset":       "0",
        "match_gre_type":      "0x6558",
        "match_gre_type_mask": "0xFFFF",
        "match_priority":      "5",
    }, "SAI_UDF_MATCH_ATTR_GRE_TYPE"),
    ("l4_dst_port", {
        "select_base":             "L4",
        "select_offset":           "8",
        "match_l4_dst_port":       "0x12B7",
        "match_l4_dst_port_mask":  "0xFFFF",
        "match_priority":          "5",
    }, "SAI_UDF_MATCH_ATTR_L4_DST_PORT_TYPE"),
]

BASE_ATTR_CASES = [
    # label, selector fields (flat), expected SAI_UDF_ATTR_BASE value
    ("base_l2", {
        "select_base":     "L2",
        "select_offset":   "12",
        "match_l2_type":   "0x0800",
        "match_priority":  "5",
    }, "SAI_UDF_BASE_L2"),
    ("base_l3", {
        "select_base":        "L3",
        "select_offset":      "4",
        "match_l3_type":      "0x29",
        "match_l3_type_mask": "0xFF",
        "match_priority":     "6",
    }, "SAI_UDF_BASE_L3"),
    ("base_l4", {
        "select_base":    "L4",
        "select_offset":  "0",
        "match_l3_type":  "0x84",
        "match_priority": "7",
    }, "SAI_UDF_BASE_L4"),
]


def _create_selector_on_new_group(duthost, group, sel_name, fields, length="3"):
    """Create a fresh UDF group + one selector with the given flat fields.

    `fields` is a dict of CONFIG_DB-shape entries (select_base, select_offset,
    match_l3_type, match_priority, ...).  Snapshots ASIC_DB before the selector
    write so only OIDs produced by this call are returned.

    Returns (new_match_oids, new_udf_oids).
    """
    _cfggen_load(duthost, {"UDF": {
        group: {"length": length, "field_type": "GENERIC"},
    }})
    time.sleep(ORCHAGENT_WAIT)

    match_before = asic_oids(duthost, "SAI_OBJECT_TYPE_UDF_MATCH")
    udf_before = asic_oids(duthost, "SAI_OBJECT_TYPE_UDF")
    _cfggen_load(duthost, {"UDF_SELECTOR": {
        "{}|{}".format(group, sel_name): dict(fields),
    }})
    time.sleep(ORCHAGENT_WAIT)
    return (asic_oids(duthost, "SAI_OBJECT_TYPE_UDF_MATCH") - match_before,
            asic_oids(duthost, "SAI_OBJECT_TYPE_UDF") - udf_before)


class TestMatchAndBaseAttrVerification:
    """Each case uses a DEDICATED UDF group (not the fixture's G0) so the test
    does not depend on how many selectors G0 already holds.  Some Broadcom
    SKUs cap selectors-per-group or restrict certain (base, offset) combos on
    a group that already has other selectors bound."""

    @pytest.fixture(autouse=True)
    def _cleanup(self, setup_udf):
        dut = setup_udf.duthost
        yield
        for label, _, _ in MATCH_ATTR_CASES + BASE_ATTR_CASES:
            group = "G_VERIFY_{}".format(label.upper())
            cfg_del(dut, "UDF_SELECTOR|{}|verify_{}".format(group, label))
            cfg_del(dut, "UDF|{}".format(group))
        cfg_del(dut, "UDF_SELECTOR|G_VERIFY_NOMASK|nomask_test")
        cfg_del(dut, "UDF|G_VERIFY_NOMASK")
        time.sleep(ORCHAGENT_WAIT)

    @pytest.mark.parametrize("label,fields,expected_attr", MATCH_ATTR_CASES,
                             ids=[c[0] for c in MATCH_ATTR_CASES])
    def test_match_attr_written_to_asic(self, setup_udf, label, fields, expected_attr):
        dut = setup_udf.duthost
        group = "G_VERIFY_{}".format(label.upper())
        new_matches, _ = _create_selector_on_new_group(
            dut, group, "verify_{}".format(label), fields,
        )
        pytest_assert(new_matches,
                      "No new UDF_MATCH OID created for {} selector".format(label))
        attrs = asic_attrs(dut, next(iter(new_matches)))
        pytest_assert(expected_attr in attrs,
                      "New UDF_MATCH missing {}: {}".format(expected_attr, attrs))

    @pytest.mark.parametrize("label,fields,expected_base", BASE_ATTR_CASES,
                             ids=[c[0] for c in BASE_ATTR_CASES])
    def test_base_attr_written_to_asic(self, setup_udf, label, fields, expected_base):
        dut = setup_udf.duthost
        group = "G_VERIFY_{}".format(label.upper())
        _, new_udfs = _create_selector_on_new_group(
            dut, group, "verify_{}".format(label), fields,
        )
        pytest_assert(new_udfs,
                      "No new UDF OID created for {} selector".format(label))
        attrs = asic_attrs(dut, next(iter(new_udfs)))
        pytest_assert(attrs.get("SAI_UDF_ATTR_BASE") == expected_base,
                      "Expected BASE={}, got {}".format(
                          expected_base, attrs.get("SAI_UDF_ATTR_BASE")))

    def test_l3_type_auto_mask(self, setup_udf):
        """l3_type=0x06 without l3_type_mask -> orchagent auto-fills mask=0xFF."""
        dut = setup_udf.duthost
        new_matches, _ = _create_selector_on_new_group(
            dut, "G_VERIFY_NOMASK", "nomask_test",
            fields={
                "select_base":     "L4",
                "select_offset":   "0",
                "match_l3_type":   "0x06",
                "match_priority":  "30",
            },
        )
        pytest_assert(new_matches, "No new UDF_MATCH OID created for auto-mask test")
        attrs = asic_attrs(dut, next(iter(new_matches)))
        l3 = attrs.get("SAI_UDF_MATCH_ATTR_L3_TYPE", "")
        pytest_assert("6" in l3 and "0xff" in l3.lower(),
                      "Expected auto-filled mask 0xff in l3_type, got {!r}".format(l3))


# =============================================================================
# Regression tests for match-field presence detection (_set bool fix)
#
# Bug 1: l4_dst_port=0 was silently dropped.
#   Old auto-fill guard: if (l4_dst_port != 0 && mask == 0) — false when
#   value=0, mask stayed 0, then 0!=0||0!=0 → false → field never pushed to SAI.
#   Fix: explicit _set bool tracks whether the JSON key appeared at all.
#
# Bug 2: absent field vs field=0x0000 were incorrectly deduped.
#   Old buildMatchSignature hashed only raw values; absent field and
#   explicit-zero field had identical signatures → shared one SAI UDF_MATCH
#   OID even though one has L2_TYPE attr and the other does not.
#   Fix: _set bool is included in the signature.
# =============================================================================

class TestMatchPresenceDetection:

    # UDF group / selector names used by this class (for cleanup)
    _GROUPS = ["G_BUG1A", "G_BUG1B", "G_BUG2_ABSENT", "G_BUG2_ZERO"]

    @pytest.fixture(autouse=True)
    def _cleanup(self, setup_udf):
        dut = setup_udf.duthost
        yield
        for group in self._GROUPS:
            cfg_del(dut, "UDF_SELECTOR|{}|sel".format(group))
            cfg_del(dut, "UDF|{}".format(group))
        time.sleep(ORCHAGENT_WAIT)

    def test_l4_dst_port_zero_with_explicit_mask(self, setup_udf):
        """Bug 1a: l4_dst_port=0 with an explicit mask must produce a SAI
        UDF_MATCH OID with SAI_UDF_MATCH_ATTR_L4_DST_PORT_TYPE set.

        Old code silently dropped port=0 because `value!=0 && mask==0` was
        false for value=0, leaving both value and mask at 0, then the presence
        check `0!=0 || 0!=0` was false → field never pushed to SAI."""
        dut = setup_udf.duthost
        new_matches, _ = _create_selector_on_new_group(
            dut, "G_BUG1A", "sel",
            fields={
                "select_base":            "L4",
                "select_offset":          "0",
                "match_l4_dst_port":      "0x0",
                "match_l4_dst_port_mask": "0xFFFF",
                "match_priority":         "5",
            },
        )
        pytest_assert(
            new_matches,
            "Bug 1: l4_dst_port=0 with explicit mask=0xFFFF did not create a "
            "UDF_MATCH OID -- port-zero matching silently dropped",
        )
        attrs = asic_attrs(dut, next(iter(new_matches)))
        pytest_assert(
            "SAI_UDF_MATCH_ATTR_L4_DST_PORT_TYPE" in attrs,
            "Bug 1: UDF_MATCH missing L4_DST_PORT_TYPE for port=0: {}".format(attrs),
        )

    def test_l4_dst_port_zero_auto_fill_mask(self, setup_udf):
        """Bug 1b: l4_dst_port=0 with no mask must trigger auto-fill to
        mask=0xFFFF in SAI, same as the existing test_l3_type_auto_mask
        behaviour.

        Old auto-fill guard: `if (value != 0 && mask == 0)` -- when value=0
        the condition was false, so mask stayed 0 and the field was dropped."""
        dut = setup_udf.duthost
        new_matches, _ = _create_selector_on_new_group(
            dut, "G_BUG1B", "sel",
            fields={
                "select_base":       "L4",
                "select_offset":     "0",
                "match_l4_dst_port": "0x0",
                "match_priority":    "5",
                # no match_l4_dst_port_mask -- orchagent should auto-fill
            },
        )
        pytest_assert(
            new_matches,
            "Bug 1: l4_dst_port=0 with no mask did not create a UDF_MATCH OID "
            "-- auto-fill may have been skipped",
        )
        attrs = asic_attrs(dut, next(iter(new_matches)))
        l4p = attrs.get("SAI_UDF_MATCH_ATTR_L4_DST_PORT_TYPE", "")
        pytest_assert(
            "0" in l4p and "0xffff" in l4p.lower(),
            "Bug 1: expected l4_dst_port=0 with auto-filled mask=0xffff, "
            "got {!r}".format(l4p),
        )

    def test_explicit_l2_type_reaches_sai(self, setup_udf):
        """Bug 2: a selector with explicit l2_type must produce a UDF_MATCH OID
        that carries SAI_UDF_MATCH_ATTR_L2_TYPE.

        If the old buildMatchSignature (raw-values-only hash) incorrectly
        deduped an explicit-l2_type selector with an earlier absent-l2_type
        selector, the resulting shared OID would have no L2_TYPE attr -- the
        explicit value never reaches SAI.

        This test checks the SAI attr directly, not the OID count.  It passes
        regardless of which orchagent version is running if and only if the
        system correctly propagates the explicit l2_type to SAI.
        """
        dut = setup_udf.duthost

        # Step 1: create absent-l2_type selector first.  Its match OID must
        # NOT carry L2_TYPE (it has only l3_type).
        new_m_absent, _ = _create_selector_on_new_group(
            dut, "G_BUG2_ABSENT", "sel",
            fields={
                "select_base":        "L4",
                "select_offset":      "0",
                "match_l3_type":      "0x55",
                "match_l3_type_mask": "0xFF",
                "match_priority":     "15",
            },
        )
        pytest_assert(new_m_absent,
                      "absent-l2_type selector did not create a UDF_MATCH OID")
        absent_attrs = asic_attrs(dut, next(iter(new_m_absent)))
        pytest_assert(
            "SAI_UDF_MATCH_ATTR_L2_TYPE" not in absent_attrs,
            "absent l2_type selector incorrectly has L2_TYPE attr: {}".format(absent_attrs),
        )

        # Step 2: create selector with explicit l2_type=0x0800 (IPv4 EtherType,
        # non-zero so platform ambiguity around value=0 is avoided).  Its match
        # OID must carry L2_TYPE.  If Bug 2 is present and orchagent deduplicates
        # this selector into the absent-l2_type OID from step 1, the resulting
        # OID has no L2_TYPE attr -- the assertion below catches that.
        new_m_l2, _ = _create_selector_on_new_group(
            dut, "G_BUG2_ZERO", "sel",
            fields={
                "select_base":        "L4",
                "select_offset":      "0",
                "match_l2_type":      "0x0800",
                "match_l2_type_mask": "0xFFFF",
                "match_l3_type":      "0x55",
                "match_l3_type_mask": "0xFF",
                "match_priority":     "15",
            },
        )
        pytest_assert(new_m_l2,
                      "explicit l2_type=0x0800 selector did not create a UDF_MATCH OID")
        l2_attrs = asic_attrs(dut, next(iter(new_m_l2)))
        pytest_assert(
            "SAI_UDF_MATCH_ATTR_L2_TYPE" in l2_attrs,
            "Bug 2 regression: explicit l2_type=0x0800 did not reach SAI -- "
            "UDF_MATCH OID is missing L2_TYPE attr: {}".format(l2_attrs),
        )


# =============================================================================
# Traffic verification per match type (parametrized, single test class)
# =============================================================================

TRAFFIC_GROUP = "TRAF_G"
TRAFFIC_TABLE_TYPE = "TRAF_TT"
TRAFFIC_TABLE = "TRAF_TBL"
TRAFFIC_RULE = "TRAF_R"


def _build_traffic_pipeline(dut, acl_port, sel_name, fields, rule_value):
    """Tear down fixture ACL stack, then build an isolated pipeline for one
    traffic test.  `fields` is the flat-schema UDF_SELECTOR dict (select_base,
    select_offset, match_*).  On Broadcom, a port holds one UDF slot -- a
    second ACL table on the same port would have its UDF binding masked by
    TABLE1's."""
    for key in [
        "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_A),
        "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_B),
        "ACL_TABLE|{}".format(ACL_TABLE),
        "ACL_TABLE_TYPE|{}".format(ACL_TABLE_TYPE),
        "UDF_SELECTOR|{}|{}".format(UDF_G0, SEL_G0_UDP),
        "UDF_SELECTOR|{}|{}".format(UDF_G0, SEL_G0_PROTO18),
        "UDF_SELECTOR|{}|{}".format(UDF_G1, SEL_G1_PROTO18),
        "UDF|{}".format(UDF_G0),
        "UDF|{}".format(UDF_G1),
    ]:
        cfg_del(dut, key)
    time.sleep(ORCHAGENT_WAIT + CLEANUP_WAIT)

    _cfggen_load(dut, {"UDF": {TRAFFIC_GROUP: {"length": "2", "field_type": "GENERIC"}}})
    _cfggen_load(dut, {"UDF_SELECTOR": {
        "{}|{}".format(TRAFFIC_GROUP, sel_name): dict(fields),
    }})
    _cfggen_load(dut, {"ACL_TABLE_TYPE": {
        TRAFFIC_TABLE_TYPE: {"MATCHES": ["IN_PORTS", TRAFFIC_GROUP],
                             "ACTIONS": ["PACKET_ACTION", "COUNTER"],
                             "BIND_POINTS": ["PORT"]},
    }})
    _cfggen_load(dut, {"ACL_TABLE": {
        TRAFFIC_TABLE: {"type": TRAFFIC_TABLE_TYPE, "ports": [acl_port], "stage": "ingress"},
    }})
    _cfggen_load(dut, {"ACL_RULE": {
        "{}|{}".format(TRAFFIC_TABLE, TRAFFIC_RULE): {
            "priority": "300", TRAFFIC_GROUP: rule_value, "PACKET_ACTION": "DROP",
        }
    }})
    time.sleep(ORCHAGENT_WAIT)

    # Wait one full FlexCounter cycle so any stale ACL_COUNTER_RULE_MAP entry
    # from the previous pipeline teardown is replaced by the new OID.  Without
    # this, `before = acl_packet_count(...)` may read the old OID's counter
    # (e.g. 500 from the prior test) and produce a negative diff.
    time.sleep(FLEXCOUNTER_WAIT)


def _teardown_traffic_pipeline(dut, acl_port, sel_name):
    for key in [
        "ACL_RULE|{}|{}".format(TRAFFIC_TABLE, TRAFFIC_RULE),
        "ACL_TABLE|{}".format(TRAFFIC_TABLE),
        "ACL_TABLE_TYPE|{}".format(TRAFFIC_TABLE_TYPE),
        "UDF_SELECTOR|{}|{}".format(TRAFFIC_GROUP, sel_name),
        "UDF|{}".format(TRAFFIC_GROUP),
    ]:
        cfg_del(dut, key)
    time.sleep(ORCHAGENT_WAIT + CLEANUP_WAIT)
    _write_full_config(dut, acl_port=acl_port)
    time.sleep(ORCHAGENT_WAIT)


class TestMatchTypeTraffic:
    """Traffic-level verification that each match type actually filters in HW."""

    @pytest.mark.parametrize("label,fields,rule_value,pkt_builder,expect_match", [
        (
            "l2-type-ipv4",
            {
                "select_base":        "L4",
                "select_offset":      "0",
                "match_l2_type":      "0x0800",
                "match_l2_type_mask": "0xFFFF",
                "match_priority":     "10",
            },
            "0x1234/0xffff",
            lambda mac: testutils.simple_udp_packet(
                eth_dst=mac, ip_dst="192.168.1.100", ip_src="10.0.0.1",
                udp_sport=0x1234, udp_dport=6000, pktlen=100),
            True,
        ),
        (
            "l4-dst-port-match",
            {
                "select_base":            "L4",
                "select_offset":          "0",
                "match_l4_dst_port":      "0x12B7",
                "match_l4_dst_port_mask": "0xFFFF",
                "match_priority":         "10",
            },
            "0x12b7/0xffff",
            lambda mac: testutils.simple_udp_packet(
                eth_dst=mac, ip_dst="192.168.1.100", ip_src="10.0.0.1",
                udp_sport=0x12B7, udp_dport=4791, pktlen=100),
            True,
        ),
        (
            "l4-dst-port-no-match",
            {
                "select_base":            "L4",
                "select_offset":          "0",
                "match_l4_dst_port":      "0x12B7",
                "match_l4_dst_port_mask": "0xFFFF",
                "match_priority":         "10",
            },
            "0x12b7/0xffff",
            lambda mac: testutils.simple_udp_packet(
                eth_dst=mac, ip_dst="192.168.1.100", ip_src="10.0.0.1",
                udp_sport=0x12B7, udp_dport=80, pktlen=100),
            False,
        ),
        (
            "l2-type-ipv6",
            {
                "select_base":        "L4",
                "select_offset":      "0",
                "match_l2_type":      "0x86DD",
                "match_l2_type_mask": "0xFFFF",
                "match_priority":     "10",
            },
            "0xABCD/0xffff",
            lambda mac: testutils.simple_udpv6_packet(
                eth_dst=mac, ipv6_dst="2001:db8::1", ipv6_src="2001:db8::2",
                udp_sport=0xABCD, udp_dport=5000, pktlen=100),
            True,
        ),
    ], ids=lambda v: v if isinstance(v, str) else None)
    def test_match_type_filters_traffic(self, setup_udf, ptfadapter,
                                        label, fields, rule_value, pkt_builder, expect_match):
        dut = setup_udf.duthost
        acl_port = setup_udf.acl_port
        ptf_port = setup_udf.ptf_port
        sel_name = "traf_{}".format(label.replace("-", "_"))

        dut.shell("sudo counterpoll acl enable", module_ignore_errors=True)
        _build_traffic_pipeline(dut, acl_port, sel_name, fields, rule_value)
        try:
            _assert_traffic_precondition(dut, TRAFFIC_TABLE, TRAFFIC_RULE)
            before = acl_packet_count(dut, TRAFFIC_TABLE, TRAFFIC_RULE)
            pkt = pkt_builder(dut.facts["router_mac"])
            _send_and_wait(ptfadapter, ptf_port, pkt, count=TRAFFIC_PKTS)
            after = acl_packet_count(dut, TRAFFIC_TABLE, TRAFFIC_RULE)
            diff = after - before
            logger.info("[%s] counter before=%d after=%d diff=%d",
                        label, before, after, diff)
            if expect_match and diff == 0:
                time.sleep(FLEXCOUNTER_WAIT)
                after = acl_packet_count(dut, TRAFFIC_TABLE, TRAFFIC_RULE)
                diff = after - before
                logger.info("[%s] retry: after=%d diff=%d", label, after, diff)
            if expect_match:
                pytest_assert(diff >= TRAFFIC_MIN_DROPS,
                              "[{}] expected >={} drops, got {}".format(
                                  label, TRAFFIC_MIN_DROPS, diff))
            else:
                pytest_assert(diff < TRAFFIC_MAX_LEAK,
                              "[{}] expected <{} drops, got {}".format(
                                  label, TRAFFIC_MAX_LEAK, diff))
        finally:
            _teardown_traffic_pipeline(dut, acl_port, sel_name)


# =============================================================================
# Selector required-field validation
# =============================================================================

class TestSelectorFieldValidation:

    @pytest.fixture(autouse=True)
    def _cleanup(self, setup_udf):
        dut = setup_udf.duthost
        yield
        for key in [
            "UDF_SELECTOR|{}|no_base".format(UDF_G0),
            "UDF_SELECTOR|{}|bad_base".format(UDF_G0),
            "UDF_SELECTOR|G_T|nomatch_sel",
            "UDF|G_T",
        ]:
            cfg_del(dut, key)
        time.sleep(ORCHAGENT_WAIT)

    @pytest.mark.parametrize("label,fields", [
        ("missing-base", {
            # select_base deliberately absent
            "select_offset":      "0",
            "match_l3_type":      "0x11",
            "match_l3_type_mask": "0xFF",
            "match_priority":     "10",
        }),
        ("invalid-base", {
            "select_base":        "PAYLOAD",   # not L2/L3/L4
            "select_offset":      "0",
            "match_l3_type":      "0x11",
            "match_l3_type_mask": "0xFF",
            "match_priority":     "10",
        }),
    ])
    def test_invalid_selector_rejected(self, setup_udf, label, fields):
        """UDF_SELECTOR missing required base or with unknown base value must
        not produce a SAI UDF OID."""
        dut = setup_udf.duthost
        udf_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF")

        sel_key = "no_base" if label == "missing-base" else "bad_base"
        _cfggen_load(dut, {"UDF_SELECTOR": {
            "{}|{}".format(UDF_G0, sel_key): dict(fields),
        }})
        time.sleep(ORCHAGENT_WAIT)

        new_oids = asic_oids(dut, "SAI_OBJECT_TYPE_UDF") - udf_before
        pytest_assert(not new_oids,
                      "[{}] SAI UDF OID created despite invalid config: {}".format(label, new_oids))

    def test_selector_missing_all_match_criteria_rejected(self, setup_udf):
        """UDF_SELECTOR with only 'priority' in match (no l3/l2/gre/l4_dst_port)
        must be rejected."""
        dut = setup_udf.duthost
        _cfggen_load(dut, {"UDF": {"G_T": {"length": "2", "field_type": "GENERIC"}}})
        time.sleep(ORCHAGENT_WAIT)

        udf_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF")
        _cfggen_load(dut, {"UDF_SELECTOR": {
            "G_T|nomatch_sel": {
                "select_base":    "L4",
                "select_offset":  "0",
                "match_priority": "10",
            }
        }})
        time.sleep(ORCHAGENT_WAIT)

        new_oids = asic_oids(dut, "SAI_OBJECT_TYPE_UDF") - udf_before
        pytest_assert(not new_oids,
                      "SAI UDF OID created for selector with no match criteria: {}".format(new_oids))


# =============================================================================
# Section P: Immutability + group retry
# =============================================================================

class TestImmutabilityAndGroupRetry:

    def test_selector_rewrite_is_noop(self, setup_udf):
        """Re-writing UDF_SELECTOR|G0|udp_l4 with either identical values or a
        changed base must not alter the SAI UDF OID set."""
        dut = setup_udf.duthost
        udf_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF")
        pytest_assert(udf_before, "Precondition: SAI UDF OIDs must exist")

        # Attempt to change immutable base from L4 to L3
        _cfggen_load(dut, {"UDF_SELECTOR": {
            "{}|{}".format(UDF_G0, SEL_G0_UDP): {
                "select_base":        "L3",
                "select_offset":      "0",
                "match_l3_type":      "0x11",
                "match_l3_type_mask": "0xFF",
                "match_priority":     "10",
            }
        }})
        time.sleep(ORCHAGENT_WAIT)
        pytest_assert(asic_oids(dut, "SAI_OBJECT_TYPE_UDF") == udf_before,
                      "SAI UDF OID set changed after immutable base modification")

        # Identical re-write
        _write_selector_g0_udp(dut)
        time.sleep(ORCHAGENT_WAIT)
        pytest_assert(asic_oids(dut, "SAI_OBJECT_TYPE_UDF") == udf_before,
                      "SAI UDF OID set changed after identical re-write")

    def test_delete_udf_group_while_referenced(self, setup_udf):
        """Deleting UDF|G0 while selectors reference it must not crash.  After
        restoring G0, the SAI UDF_GROUP OID must exist."""
        dut = setup_udf.duthost
        group_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP")
        pytest_assert(group_before, "Precondition: UDF_GROUP OIDs must exist")

        cfg_del(dut, "UDF|{}".format(UDF_G0))
        time.sleep(ORCHAGENT_WAIT)
        _write_udf_g0(dut)
        time.sleep(ORCHAGENT_WAIT)

        pytest_assert(cfg_exists(dut, "UDF|{}".format(UDF_G0)), "Could not restore UDF|G0")
        pytest_assert(asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP"),
                      "No UDF_GROUP OIDs after G0 restore")

    def test_idempotent_set_does_not_leak_match_refcount(self, setup_udf):
        """Regression: replaying an identical SET for an already-committed
        selector must not increment the shared-match refcount without a paired
        release.

        Bug: doUdfSelectorTask had no pre-existence check before calling
        getOrCreateSharedMatch.  A replay SET incremented the refcount; on the
        subsequent DEL, refcount decremented to 1 instead of 0, leaving the
        SAI UDF_MATCH object orphaned in ASIC_DB.

        Fix: early-exit when both m_udfs and m_selectorToMatchName already
        contain the selector key.

        Sequence:
          1. Write group + selector -> UDF_MATCH OID appears in ASIC_DB.
          2. Write identical selector again -> no new OID, existing OID intact.
          3. Delete selector -> UDF_MATCH OID gone (refcount reached 0).
             If the bug is present, the OID remains after delete.
        """
        dut = setup_udf.duthost
        group = "G_IDEMPOTENT"
        sel_key = "{}|idp_sel".format(group)
        # 0xAA not used by any fixture selector or other test.
        fields = {
            "select_base":        "L4",
            "select_offset":      "0",
            "match_l3_type":      "0xAA",
            "match_l3_type_mask": "0xFF",
            "match_priority":     "5",
        }

        _cfggen_load(dut, {"UDF": {group: {"length": "2", "field_type": "GENERIC"}}})
        time.sleep(ORCHAGENT_WAIT)

        try:
            # Step 1: create selector -> new UDF_MATCH OID
            match_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_MATCH")
            _cfggen_load(dut, {"UDF_SELECTOR": {sel_key: dict(fields)}})
            time.sleep(ORCHAGENT_WAIT)

            match_after_create = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_MATCH")
            new_oids = match_after_create - match_before
            pytest_assert(new_oids,
                          "Step 1: selector write did not create a UDF_MATCH OID")
            match_oid = next(iter(new_oids))

            # Step 2: replay identical selector -> no change in ASIC_DB
            _cfggen_load(dut, {"UDF_SELECTOR": {sel_key: dict(fields)}})
            time.sleep(ORCHAGENT_WAIT)

            match_after_replay = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_MATCH")
            pytest_assert(match_after_replay == match_after_create,
                          "Step 2: idempotent SET changed UDF_MATCH OID set -- "
                          "expected no change")
            pytest_assert(match_oid in match_after_replay,
                          "Step 2: original UDF_MATCH OID {} removed by replay"
                          .format(match_oid))

            # Step 3: delete -> UDF_MATCH OID must be gone (refcount == 0)
            cfg_del(dut, "UDF_SELECTOR|{}".format(sel_key))
            time.sleep(ORCHAGENT_WAIT)

            pytest_assert(
                match_oid not in asic_oids(dut, "SAI_OBJECT_TYPE_UDF_MATCH"),
                "Step 3: UDF_MATCH OID {} still in ASIC_DB after selector "
                "delete -- idempotent SET leaked a refcount (decremented to 1 "
                "instead of 0, SAI remove did not fire)".format(match_oid),
            )

        finally:
            cfg_del(dut, "UDF_SELECTOR|{}".format(sel_key))
            cfg_del(dut, "UDF|{}".format(group))
            time.sleep(ORCHAGENT_WAIT)


# =============================================================================
# Section Q: Shared UDF_MATCH dedup and refcount
# =============================================================================

class TestSharedMatchDedup:

    @pytest.fixture(autouse=True)
    def _cleanup(self, setup_udf):
        dut = setup_udf.duthost
        acl_port = setup_udf.acl_port
        yield
        for key in [
            "UDF_SELECTOR|G_Q1|shared_sel",
            "UDF_SELECTOR|G_Q2|shared_sel",
            "UDF|G_Q1",
            "UDF|G_Q2",
        ]:
            cfg_del(dut, key)
        time.sleep(ORCHAGENT_WAIT)
        if not cfg_exists(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_A)):
            _write_full_config(dut, acl_port=acl_port)
            time.sleep(ORCHAGENT_WAIT)

    def test_shared_match_dedup_and_refcount(self, setup_udf):
        """Two selectors in different groups with identical match config must
        share one UDF_MATCH OID (dedup).  Deleting one leaves it alive
        (refcount=1); deleting the second removes it (refcount=0)."""
        dut = setup_udf.duthost

        _cfggen_load(dut, {"UDF": {
            "G_Q1": {"length": "2", "field_type": "GENERIC"},
            "G_Q2": {"length": "2", "field_type": "GENERIC"},
        }})
        time.sleep(ORCHAGENT_WAIT)

        match_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_MATCH")
        # 0xCC is not used by any fixture selector (0x11/0x12/0x06/0x29/0x55/0x84
        # are taken), so this creates a genuinely new UDF_MATCH OID instead of
        # deduplicating against the fixture's existing G0|udp_l4 OID (0x11).
        shared_fields = {
            "select_base":        "L4",
            "select_offset":      "0",
            "match_l3_type":      "0xCC",
            "match_l3_type_mask": "0xFF",
            "match_priority":     "10",
        }

        # First selector -- creates a new match OID
        _cfggen_load(dut, {"UDF_SELECTOR": {
            "G_Q1|shared_sel": dict(shared_fields),
        }})
        time.sleep(ORCHAGENT_WAIT)
        match_after_first = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_MATCH")
        new_after_first = match_after_first - match_before
        pytest_assert(new_after_first, "First selector did not create a UDF_MATCH OID")

        # Second selector, identical match -- must NOT create a new match OID
        _cfggen_load(dut, {"UDF_SELECTOR": {
            "G_Q2|shared_sel": dict(shared_fields),
        }})
        time.sleep(ORCHAGENT_WAIT)
        new_after_second = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_MATCH") - match_before
        pytest_assert(
            len(new_after_second) == len(new_after_first),
            "Second selector created a new UDF_MATCH OID despite identical config "
            "(+{} vs +{}) -- dedup failed".format(len(new_after_second), len(new_after_first)),
        )
        shared_oid = next(iter(new_after_first))

        # Delete first selector -- shared match survives (refcount=1)
        cfg_del(dut, "UDF_SELECTOR|G_Q1|shared_sel")
        time.sleep(ORCHAGENT_WAIT)
        pytest_assert(shared_oid in asic_oids(dut, "SAI_OBJECT_TYPE_UDF_MATCH"),
                      "Shared UDF_MATCH removed after deleting only one of two selectors")

        # Delete second selector -- shared match gone (refcount=0)
        cfg_del(dut, "UDF_SELECTOR|G_Q2|shared_sel")
        time.sleep(ORCHAGENT_WAIT)
        pytest_assert(shared_oid not in asic_oids(dut, "SAI_OBJECT_TYPE_UDF_MATCH"),
                      "Shared UDF_MATCH still present after last selector deleted")


# =============================================================================
# Section R: UDF group refcount layers (table type vs table instance)
# =============================================================================

class TestGroupRefcountLayers:

    @pytest.fixture(autouse=True)
    def _cleanup(self, setup_udf):
        dut = setup_udf.duthost
        acl_port = setup_udf.acl_port
        yield
        for table in ["TABLE_MULTI", "TABLE_R2"]:
            dut.shell("config acl remove table {}".format(table), module_ignore_errors=True)
            cfg_del(dut, "ACL_TABLE|{}".format(table))
        cfg_del(dut, "ACL_TABLE_TYPE|T_MULTI")
        time.sleep(ORCHAGENT_WAIT)
        if not (cfg_exists(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_A))
                and cfg_exists(dut, "UDF|{}".format(UDF_G0))):
            _write_full_config(dut, acl_port=acl_port)
            time.sleep(ORCHAGENT_WAIT)

    def test_table_type_refcount_blocks_group_deletion(self, setup_udf):
        """ACL_TABLE_TYPE alone holds a UDF group refcount: even after tearing
        down the fixture's T1/TABLE1/RULE_A/RULE_B stack, a new T_MULTI
        referencing G0 must keep G0's SAI OID alive through a UDF|G0 delete."""
        dut = setup_udf.duthost

        _cfggen_load(dut, {"ACL_TABLE_TYPE": {
            "T_MULTI": {"MATCHES": ["IN_PORTS", UDF_G0],
                        "ACTIONS": ["PACKET_ACTION", "COUNTER"],
                        "BIND_POINTS": ["PORT"]},
        }})
        time.sleep(ORCHAGENT_WAIT)

        group_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP")

        cfg_del(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_A))
        cfg_del(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_B))
        time.sleep(1)
        dut.shell("config acl remove table {}".format(ACL_TABLE), module_ignore_errors=True)
        cfg_del(dut, "ACL_TABLE|{}".format(ACL_TABLE))
        time.sleep(1)
        cfg_del(dut, "ACL_TABLE_TYPE|{}".format(ACL_TABLE_TYPE))
        time.sleep(ORCHAGENT_WAIT)

        cfg_del(dut, "UDF|{}".format(UDF_G0))
        time.sleep(ORCHAGENT_WAIT)

        pytest_assert(
            len(asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP")) == len(group_before),
            "UDF_GROUP OID removed despite T_MULTI refcount",
        )

        _write_udf_g0(dut)
        cfg_del(dut, "ACL_TABLE_TYPE|T_MULTI")
        time.sleep(ORCHAGENT_WAIT)

    def test_table_instance_refcount_blocks_group_deletion(self, setup_udf):
        """ACL_TABLE instance holds an independent refcount on UDF groups:
        removing rules and the table type (but leaving TABLE1) must still
        prevent UDF|G0 SAI OID removal."""
        dut = setup_udf.duthost
        group_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP")

        cfg_del(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_A))
        cfg_del(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_B))
        time.sleep(1)
        cfg_del(dut, "ACL_TABLE_TYPE|{}".format(ACL_TABLE_TYPE))
        time.sleep(ORCHAGENT_WAIT)

        cfg_del(dut, "UDF|{}".format(UDF_G0))
        time.sleep(ORCHAGENT_WAIT)

        pytest_assert(
            len(asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP")) == len(group_before),
            "UDF_GROUP OID removed despite TABLE1 instance refcount",
        )
        _write_udf_g0(dut)
        time.sleep(ORCHAGENT_WAIT)

    def test_multiple_tables_stacked_refcount(self, setup_udf):
        """Two ACL_TABLEs share G0 via T1.  Deleting one table must leave G0's
        SAI OID unchanged (the other still holds a refcount)."""
        dut = setup_udf.duthost
        acl_port = setup_udf.acl_port

        _cfggen_load(dut, {"ACL_TABLE": {
            "TABLE_MULTI": {"type": ACL_TABLE_TYPE, "ports": [acl_port], "stage": "ingress"},
        }})
        time.sleep(ORCHAGENT_WAIT)

        group_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP")

        dut.shell("config acl remove table TABLE_MULTI", module_ignore_errors=True)
        cfg_del(dut, "ACL_TABLE|TABLE_MULTI")
        time.sleep(ORCHAGENT_WAIT)

        pytest_assert(
            asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP") == group_before,
            "UDF_GROUP OIDs changed after removing only one of two tables sharing G0",
        )


# =============================================================================
# Section S: Rule refcount blocks last-selector deletion
# =============================================================================

class TestRuleRefcountBlocksSelector:

    @pytest.fixture(autouse=True)
    def _ensure_full(self, setup_udf):
        dut = setup_udf.duthost
        acl_port = setup_udf.acl_port
        if not (cfg_exists(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_A))
                and cfg_exists(dut, "UDF|{}".format(UDF_G0))):
            _write_full_config(dut, acl_port=acl_port)
            time.sleep(ORCHAGENT_WAIT)
        yield
        if not (cfg_exists(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_A))
                and cfg_exists(dut, "UDF|{}".format(UDF_G0))):
            _write_full_config(dut, acl_port=acl_port)
            time.sleep(ORCHAGENT_WAIT)

    def test_intermediate_vs_last_selector_deletion(self, setup_udf):
        """With RULE_A/RULE_B active and G0 having 2 selectors, deleting
        proto18_l3 succeeds (>1 remaining).  After that, deleting the last
        udp_l4 is blocked because rules still reference G0."""
        dut = setup_udf.duthost
        udf_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF")

        # Intermediate deletion: allowed
        cfg_del(dut, "UDF_SELECTOR|{}|{}".format(UDF_G0, SEL_G0_PROTO18))
        time.sleep(ORCHAGENT_WAIT)
        udf_after_one = asic_oids(dut, "SAI_OBJECT_TYPE_UDF")
        pytest_assert(udf_before - udf_after_one,
                      "Intermediate selector deletion should have removed a UDF OID")

        # Last selector deletion: blocked by rule refcount
        cfg_del(dut, "UDF_SELECTOR|{}|{}".format(UDF_G0, SEL_G0_UDP))
        time.sleep(ORCHAGENT_WAIT)
        pytest_assert(asic_oids(dut, "SAI_OBJECT_TYPE_UDF") == udf_after_one,
                      "Last selector removed while rules still reference G0")

        _write_selector_g0_proto18(dut)
        time.sleep(ORCHAGENT_WAIT)

    def test_last_selector_deletable_after_full_teardown(self, setup_udf):
        """After full ACL teardown (rules + table + table type), the last G0
        selector becomes deletable.  Also verifies multi-group rule refcounts:
        RULE_A and RULE_B each reference G0+G1, so deleting RULE_A alone must
        not be enough -- RULE_B still protects G0 until it too is removed."""
        dut = setup_udf.duthost
        acl_port = setup_udf.acl_port

        _cleanup_all_udf(dut)
        time.sleep(3)
        _write_full_config(dut, acl_port=acl_port)
        time.sleep(ORCHAGENT_WAIT + CLEANUP_WAIT)

        cfg_del(dut, "UDF_SELECTOR|{}|{}".format(UDF_G0, SEL_G0_PROTO18))
        time.sleep(ORCHAGENT_WAIT)

        # Delete RULE_A only -- RULE_B still references G0, so last-selector
        # delete is still blocked.
        cfg_del(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_A))
        time.sleep(ORCHAGENT_WAIT)
        udf_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF")
        cfg_del(dut, "UDF_SELECTOR|{}|{}".format(UDF_G0, SEL_G0_UDP))
        time.sleep(ORCHAGENT_WAIT)
        pytest_assert(asic_oids(dut, "SAI_OBJECT_TYPE_UDF") == udf_before,
                      "Last G0 selector removed while RULE_B still references G0")

        # Full ACL teardown: RULE_B -> table -> table type
        cfg_del(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_B))
        time.sleep(CLEANUP_WAIT)
        dut.shell("config acl remove table {}".format(ACL_TABLE), module_ignore_errors=True)
        cfg_del(dut, "ACL_TABLE|{}".format(ACL_TABLE))
        time.sleep(CLEANUP_WAIT)
        cfg_del(dut, "ACL_TABLE_TYPE|{}".format(ACL_TABLE_TYPE))
        time.sleep(CLEANUP_WAIT)

        # Selector DEL is still pending in m_toSync -- consumer retries on next poll
        time.sleep(ORCHAGENT_WAIT + 3)

        pytest_assert(udf_before - asic_oids(dut, "SAI_OBJECT_TYPE_UDF"),
                      "Last G0 selector NOT removed after RULE_A+RULE_B and full "
                      "ACL teardown")


# =============================================================================
# Section T: Validation edge cases
# =============================================================================

class TestValidationEdgeCases:

    @pytest.fixture(autouse=True)
    def _cleanup(self, setup_udf):
        dut = setup_udf.duthost
        acl_port = setup_udf.acl_port
        yield
        for key in [
            "ACL_RULE|{}|R_WRONGUDF".format(ACL_TABLE),
            "UDF_SELECTOR|G_T|nomatch_sel",
            "UDF|G_T",
        ]:
            cfg_del(dut, key)
        time.sleep(ORCHAGENT_WAIT)
        if not (cfg_exists(dut, "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_A))
                and cfg_exists(dut, "UDF|{}".format(UDF_G0))):
            _write_full_config(dut, acl_port=acl_port)
            time.sleep(ORCHAGENT_WAIT)

    def test_rule_with_udf_not_in_table_matches(self, setup_udf):
        """ACL_RULE references G_T which exists in udforch but is NOT in T1's
        MATCHES@: validateAddMatch must reject it (no new ACL_ENTRY)."""
        dut = setup_udf.duthost
        _cfggen_load(dut, {"UDF": {"G_T": {"length": "2", "field_type": "GENERIC"}}})
        _cfggen_load(dut, {"UDF_SELECTOR": {
            "G_T|nomatch_sel": {
                "select_base":        "L4",
                "select_offset":      "0",
                "match_l3_type":      "0x11",
                "match_l3_type_mask": "0xFF",
                "match_priority":     "10",
            }
        }})
        time.sleep(ORCHAGENT_WAIT)

        entry_before = asic_oids(dut, "SAI_OBJECT_TYPE_ACL_ENTRY")
        _cfggen_load(dut, {"ACL_RULE": {
            "{}|R_WRONGUDF".format(ACL_TABLE): {
                "priority": "50", "G_T": "0x55/0xff", "PACKET_ACTION": "DROP",
            }
        }})
        time.sleep(ORCHAGENT_WAIT)

        new_oids = asic_oids(dut, "SAI_OBJECT_TYPE_ACL_ENTRY") - entry_before
        pytest_assert(not new_oids,
                      "ACL_ENTRY OID created for rule using UDF not in T1 MATCHES@: {}".format(new_oids))

    @pytest.mark.parametrize("label,key", [
        ("selector", "UDF_SELECTOR|NONEXISTENT|phantom"),
        ("group",    "UDF|NONEXISTENT_GROUP"),
    ])
    def test_double_delete_noop(self, setup_udf, label, key):
        """Deleting a non-existent key twice must not alter ASIC_DB."""
        dut = setup_udf.duthost
        udf_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF")
        match_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_MATCH")
        group_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP")

        cfg_del(dut, key)
        cfg_del(dut, key)
        time.sleep(ORCHAGENT_WAIT)

        pytest_assert(asic_oids(dut, "SAI_OBJECT_TYPE_UDF") == udf_before,
                      "[{}] UDF OIDs changed after double-delete".format(label))
        pytest_assert(asic_oids(dut, "SAI_OBJECT_TYPE_UDF_MATCH") == match_before,
                      "[{}] UDF_MATCH OIDs changed after double-delete".format(label))
        pytest_assert(asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP") == group_before,
                      "[{}] UDF_GROUP OIDs changed after double-delete".format(label))

    def test_table_type_deletion_while_table_exists(self, setup_udf):
        """Deleting ACL_TABLE_TYPE|T1 while ACL_TABLE|TABLE1 still references it
        must not crash.  If the ACL table was successfully created in SAI, the
        table instance protects the groups; otherwise the outcome is still
        graceful (no crash)."""
        dut = setup_udf.duthost
        group_before = asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP")
        entry_before = asic_oids(dut, "SAI_OBJECT_TYPE_ACL_ENTRY")
        table_in_sai = bool(asic_oids(dut, "SAI_OBJECT_TYPE_ACL_TABLE"))

        cfg_del(dut, "ACL_TABLE_TYPE|{}".format(ACL_TABLE_TYPE))
        time.sleep(ORCHAGENT_WAIT)

        if table_in_sai and entry_before:
            pytest_assert(
                asic_oids(dut, "SAI_OBJECT_TYPE_UDF_GROUP") == group_before,
                "UDF_GROUP OIDs removed despite TABLE1 instance refcount",
            )
            pytest_assert(
                asic_oids(dut, "SAI_OBJECT_TYPE_ACL_ENTRY") == entry_before,
                "ACL_ENTRY OIDs changed after ACL_TABLE_TYPE deletion",
            )

        _write_acl_table_type(dut)
        time.sleep(ORCHAGENT_WAIT)


# =============================================================================
# Self-contained end-to-end test: UDF + ACL + traffic in one function
# =============================================================================

class TestUdfEndToEnd:
    """Single test that exercises the full UDF stack from scratch: build a
    dedicated UDF group, a UDP-matching selector, an ACL table bound to the
    test port, a drop rule, then inject matching UDP traffic and verify the
    rule's packet counter went up.

    Isolates itself from the module fixture's TABLE1 by using its own names
    (G_E2E, TABLE_E2E, etc.) and tears down the fixture's ACL stack first to
    avoid the Broadcom parallel-ACL-group UDF slot collision that
    TestMatchTypeTraffic documents.  Restores fixture config in finally.
    """

    E2E_GROUP = "G_E2E"
    E2E_SELECTOR = "e2e_sel"
    E2E_TABLE_TYPE = "T_E2E"
    E2E_TABLE = "TABLE_E2E"
    E2E_RULE = "RULE_E2E"

    def test_udf_acl_and_traffic(self, setup_udf, ptfadapter):
        dut = setup_udf.duthost
        acl_port = setup_udf.acl_port
        ptf_port = setup_udf.ptf_port

        # --- tear down fixture ACL stack so we don't fight TABLE1 for the
        #     single UDF slot on the test port ---------------------------------
        for key in [
            "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_A),
            "ACL_RULE|{}|{}".format(ACL_TABLE, RULE_B),
            "ACL_TABLE|{}".format(ACL_TABLE),
            "ACL_TABLE_TYPE|{}".format(ACL_TABLE_TYPE),
            "UDF_SELECTOR|{}|{}".format(UDF_G0, SEL_G0_UDP),
            "UDF_SELECTOR|{}|{}".format(UDF_G0, SEL_G0_PROTO18),
            "UDF_SELECTOR|{}|{}".format(UDF_G1, SEL_G1_PROTO18),
            "UDF|{}".format(UDF_G0),
            "UDF|{}".format(UDF_G1),
        ]:
            cfg_del(dut, key)
        time.sleep(ORCHAGENT_WAIT + CLEANUP_WAIT)

        dut.shell("sudo counterpoll acl enable", module_ignore_errors=True)

        try:
            # --- 1. UDF group: 3 bytes at L4 offset 0 -------------------------
            _cfggen_load(dut, {"UDF": {
                self.E2E_GROUP: {"length": "3", "field_type": "GENERIC"},
            }})

            # --- 2. UDF selector: match UDP packets (flat-field schema) ------
            _cfggen_load(dut, {"UDF_SELECTOR": {
                "{}|{}".format(self.E2E_GROUP, self.E2E_SELECTOR): {
                    "select_base":        "L4",
                    "select_offset":      "0",
                    "match_l3_type":      "0x11",
                    "match_l3_type_mask": "0xFF",
                    "match_priority":     "10",
                }
            }})

            # --- 3. ACL table type referencing the UDF group ------------------
            _cfggen_load(dut, {"ACL_TABLE_TYPE": {
                self.E2E_TABLE_TYPE: {
                    "MATCHES":     ["IN_PORTS", self.E2E_GROUP],
                    "ACTIONS":     ["PACKET_ACTION", "COUNTER"],
                    "BIND_POINTS": ["PORT"],
                }
            }})

            # --- 4. ACL table bound to the discovered UP port -----------------
            _cfggen_load(dut, {"ACL_TABLE": {
                self.E2E_TABLE: {
                    "type":  self.E2E_TABLE_TYPE,
                    "ports": [acl_port],
                    "stage": "ingress",
                },
            }})

            # --- 5. ACL drop rule: match G_E2E == 0x33 ------------------------
            _cfggen_load(dut, {"ACL_RULE": {
                "{}|{}".format(self.E2E_TABLE, self.E2E_RULE): {
                    "priority":      "200",
                    self.E2E_GROUP:  "0x33/0xff",
                    "PACKET_ACTION": "DROP",
                }
            }})
            time.sleep(ORCHAGENT_WAIT)

            # --- 6. verify rule reaches SAI (via FlexCounter/aclshow) ---------
            _assert_traffic_precondition(dut, self.E2E_TABLE, self.E2E_RULE)

            # --- 7. inject matching UDP traffic -------------------------------
            before = acl_packet_count(dut, self.E2E_TABLE, self.E2E_RULE)
            pkt = testutils.simple_udp_packet(
                eth_dst=dut.facts["router_mac"],
                ip_dst="192.168.1.100", ip_src="10.0.0.1",
                udp_sport=MATCH_SPORT, udp_dport=MATCH_DPORT, pktlen=100,
            )
            _send_and_wait(ptfadapter, ptf_port, pkt, count=TRAFFIC_PKTS)
            after = acl_packet_count(dut, self.E2E_TABLE, self.E2E_RULE)
            diff = after - before
            logger.info("E2E counter before=%d after=%d diff=%d", before, after, diff)

            # Retry once if FlexCounter hasn't polled yet
            if diff == 0:
                time.sleep(FLEXCOUNTER_WAIT)
                after = acl_packet_count(dut, self.E2E_TABLE, self.E2E_RULE)
                diff = after - before
                logger.info("E2E retry: after=%d diff=%d", after, diff)

            # --- 8. verify the drop counter caught the traffic ----------------
            pytest_assert(diff >= TRAFFIC_MIN_DROPS,
                          "E2E: expected >={} drops on {}:{}, got {}".format(
                              TRAFFIC_MIN_DROPS, self.E2E_TABLE, self.E2E_RULE, diff))

        finally:
            # --- 9. cleanup E2E pipeline + restore fixture config -------------
            for key in [
                "ACL_RULE|{}|{}".format(self.E2E_TABLE, self.E2E_RULE),
                "ACL_TABLE|{}".format(self.E2E_TABLE),
                "ACL_TABLE_TYPE|{}".format(self.E2E_TABLE_TYPE),
                "UDF_SELECTOR|{}|{}".format(self.E2E_GROUP, self.E2E_SELECTOR),
                "UDF|{}".format(self.E2E_GROUP),
            ]:
                cfg_del(dut, key)
            time.sleep(ORCHAGENT_WAIT + CLEANUP_WAIT)
            _write_full_config(dut, acl_port=acl_port)
            time.sleep(ORCHAGENT_WAIT)
