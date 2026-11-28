"""
Data-plane and ASIC-DB tests for the POLICER_ACTION ACL rule action.

POLICER_ACTION (SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER) lets a CONFIG_DB ACL rule
attach a POLICER and compose it with a packet action on the same rule. It must be
advertised in a custom ACL_TABLE_TYPE's ACTIONS (the built-in L3/L3V6 types do not
include it), so these tests define a custom POLICER_L3 table type that matches both
IPv4 and IPv6 traffic.

Covered:
  * compose + counter (test_policer_compose_and_counter, parametrized IPv4/IPv6): a
    FORWARD + POLICER rule rate-limits matched traffic, while the ACL rule counter
    still counts every matched packet (pre-policer == offered, not == forwarded).
  * CIR rate (test_policer_cir_rate): a burst offered above CIR is capped near CIR
    (rx_pps measurement), while an un-policed FORWARD rule is not limited.
  * shared single OID (test_policer_shared_single_oid): one POLICER referenced by
    two ACL rules resolves to a single refcounted SAI policer object; a second
    binding does not create a second OID, the object survives deletion of one
    binding, and it is freed only when the POLICER config itself is removed.
  * deferral (test_policer_rule_before_policer): a rule referencing a not-yet-created
    POLICER is deferred until the POLICER appears, then polices.
  * release (test_policer_release_on_removal): unbinding the POLICER returns the flow
    to its un-policed rate while the rule keeps forwarding.
  * shared aggregate (test_policer_shared_aggregate): one POLICER on two rules meters
    the aggregate of both flows, not per-rule (sub-additive).
  * redirect compose (test_policer_compose_redirect): a REDIRECT + POLICER rule both
    redirects and rate-limits the matched flow.
  * CIR update (test_policer_cir_update): raising a bound POLICER's CIR raises the
    enforced forwarded rate.
  * two-rate (test_policer_two_rate_tcm): a tr_tcm POLICER forwards green+yellow and
    drops red.
  * byte mode (test_policer_bytes_mode): a bytes meter_type POLICER rate-limits by
    bandwidth (large frames).
  * shared with mirror (test_policer_shared_with_mirror_session): one POLICER referenced
    by both a MIRROR_SESSION and an ACL rule resolves to a single refcounted SAI policer
    object; the mirror binding does not create a second OID (capability-gated on mirror
    support).
  * config reload (test_policer_survives_config_reload): a POLICER + POLICER_ACTION rule
    persisted with `config save` is re-programmed after a YANG-validated `config reload`
    and still polices the matched flow.
  * bound cannot delete (test_policer_bound_cannot_delete): a POLICER bound by an active
    POLICER_ACTION rule is ref-held -- deleting it is deferred until the rule is removed.
"""
import datetime
import json
import logging
import time

import pytest

from ptf.mask import Mask
import ptf.packet as scapy
import ptf.testutils as testutils

from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.utilities import get_all_upstream_neigh_type, get_neighbor_ptf_port_list, is_ipv6_only_topology
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),        # custom ACL table type is exercised on t0
    pytest.mark.disable_loganalyzer,   # loganalyzer is driven explicitly below
]

BASE_DIR = "acl/policer"
TABLE_TYPE_SRC = BASE_DIR + "/policer_acl_table.json"
TABLE_TYPE_DST = "/tmp/policer_acl_table.json"
POLICER_SRC = BASE_DIR + "/policer_config.json"
POLICER_DST = "/tmp/policer_config.json"
RULES_SRC = BASE_DIR + "/policer_acl_rules.json"
RULES_DST = "/tmp/policer_acl_rules.json"

TABLE_NAME = "POLICER_TABLE"
TABLE_TYPE_NAME = "POLICER_L3"

METER_RULE = "RULE_METER"
METER_RULE_V6 = "RULE_METER_V6"
METER_POLICER = "test_policer_meter"
SHARE_POLICER = "test_policer_share"

# FORWARD + policer rules match TCP traffic to these IPs; the policer CIR/CBS are
# small (see policer_config.json) so a burst well above CIR is largely policed.
METER_DST_IP = "103.23.2.1"
METER_DST_IPV6 = "103:23:2:1::1"
SHARE_DST_IP_A = "103.23.2.2"
SHARE_DST_IP_B = "103.23.2.3"
OFFERED_PKTS = 2000

# CIR rate measurement: a burst offered well above CIR is sent as fast as PTF allows;
# the policer caps the received rate to CIR-scale (rx_pps = received / send_duration),
# far below the un-policed control FORWARD rule.
RATE_POLICER = "test_policer_rate"
RATE_DST_IP = "103.23.2.4"
RATE_NP_DST_IP = "103.23.2.5"
RATE_CIR_PPS = 300
# CoPP-style rate measurement (mirrors ptftests/py3/copp_tests.py): offer at a controlled rate
# well above CIR for a fixed interval and measure the received rate over that whole window, so the
# policer's steady-state rate -- not a sub-second burst -- is measured, and re-measure a few times
# (CoPP wraps its runner in wait_until) to absorb transient PTF send-rate variance.
RATE_SEND_PPS = 2000            # target offered rate (>> CIR)
RATE_SEND_INTERVAL_SEC = 4      # fixed measurement window
RATE_SEND_BATCH = 25            # packets per send call (amortize PTF per-call overhead)
RATE_MEASURE_RETRIES = 3        # re-measure attempts before failing
# Received-rate acceptance around CIR. With a fixed-interval measurement the policed flow settles
# near CIR (the CBS burst amortizes over the window), so the band is far tighter than a
# sub-second measurement allowed.
RATE_CIR_LOW = 0.5
RATE_CIR_HIGH = 2.0
# Un-policed control must clear CIR by this factor (else the send is too slow to exercise the
# policer); a policed flow must be a clear fraction of the same flow when un-policed.
RATE_NO_POLICER_FACTOR = 2.0
RATE_POLICED_FRACTION = 0.5

LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"


def _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo):
    """DUTs that must receive config: both ToRs on dualtor-aa, else the selected DUT."""
    if "dualtor-aa" in tbinfo["topo"]["name"] and rand_unselected_dut is not None:
        return [rand_selected_dut, rand_unselected_dut]
    return [rand_selected_dut]


def clear_acl_counter(dut):
    dut.shell("aclshow -c")


def read_acl_counter(dut, rule_name, table_name=TABLE_NAME):
    """Return the 'packets count' for a rule on a single DUT (pre-policer match count)."""
    counters = dut.show_and_parse("aclshow -a -r {} -t {}".format(rule_name, table_name))
    for counter in counters:
        if counter["rule name"] == rule_name and counter["table name"] == table_name:
            return int(counter["packets count"])
    return 0


def read_acl_counter_sum(duts, rule_name):
    """Sum a rule's match counter across the configured DUTs (dualtor-aa splits traffic)."""
    time.sleep(2)  # allow the acl counterpoll (set to 1s below) to refresh
    return sum(read_acl_counter(dut, rule_name) for dut in duts)


def _asic_policer_keys(dut):
    """ASIC_DB keys of the SAI policer objects currently present."""
    out = dut.shell('sonic-db-cli ASIC_DB keys "ASIC_STATE:SAI_OBJECT_TYPE_POLICER:*"')["stdout"]
    return [line.strip() for line in out.splitlines() if line.strip()]


def _policer_cir(dut, key):
    """SAI_POLICER_ATTR_CIR value for an ASIC_DB policer key ('' when the key is unknown)."""
    if not key:
        return ""
    return dut.shell("sonic-db-cli ASIC_DB hget '{}' SAI_POLICER_ATTR_CIR".format(key))["stdout"].strip()


def get_asic_policer_count(dut):
    """Number of SAI policer objects currently present in ASIC_DB."""
    return len(_asic_policer_keys(dut))


def get_asic_acl_rule_count(dut):
    """Number of SAI ACL entries (programmed rules) currently present in ASIC_DB."""
    out = dut.shell('sonic-db-cli ASIC_DB keys "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:*"')["stdout"]
    return len([line for line in out.splitlines() if line.strip()])


def _acl_ingress_action_list(dut):
    """Advertised ingress ACL actions (STATE_DB ACL_STAGE_CAPABILITY_TABLE), for capability-driven
    gating. Empty list when the platform publishes no capability (then callers fall through to a
    runtime probe instead of gating on the static list)."""
    out = dut.shell("sonic-db-cli STATE_DB hget 'ACL_STAGE_CAPABILITY_TABLE|INGRESS' action_list",
                    module_ignore_errors=True)["stdout"].strip()
    return [a.strip() for a in out.split(",") if a.strip()]


def _switch_mirror_capable(dut):
    """True if the platform advertises mirroring (STATE_DB SWITCH_CAPABILITY MIRROR), for
    capability-driven gating of the shared mirror-session policer test."""
    out = dut.shell("sonic-db-cli STATE_DB hget 'SWITCH_CAPABILITY|switch' MIRROR",
                    module_ignore_errors=True)["stdout"].strip()
    return out.lower() == "true"


def _wait_programmed(dut, base_pol, n_pol, base_rules, n_rules, what="config"):
    """Poll ASIC_DB (instead of a fixed sleep) until n_pol policer objects and n_rules ACL
    entries relative to the captured baselines are programmed."""
    ok = wait_until(30, 2, 0,
                    lambda: (get_asic_policer_count(dut) == base_pol + n_pol
                             and get_asic_acl_rule_count(dut) == base_rules + n_rules))
    pytest_assert(ok, "{}: ASIC did not converge (policers {}/{}, rules {}/{})".format(
        what, get_asic_policer_count(dut) - base_pol, n_pol,
        get_asic_acl_rule_count(dut) - base_rules, n_rules))


STATE_ACL_RULE_TABLE = "ACL_RULE_TABLE"


def _acl_rule_status(dut, rule, table=TABLE_NAME):
    """STATE_DB programming status of an ACL rule as published by AclOrch: 'Active' once fully
    programmed, 'Pending creation' while deferred, '' when absent. This is the standard sonic-mgmt
    way to confirm ACL programming (STATE_DB ACL_RULE_TABLE, written by AclOrch::setAclRuleStatus),
    rather than a raw ASIC_DB entry count."""
    return dut.shell("sonic-db-cli STATE_DB hget '{}|{}|{}' status".format(
        STATE_ACL_RULE_TABLE, table, rule), module_ignore_errors=True)["stdout"].strip()


def _wait_rules_active(dut, rules, table=TABLE_NAME, timeout=30):
    """Wait until every named rule is Active in STATE_DB. AclOrch marks a POLICER_ACTION rule Active
    only once its POLICER exists and is bound, so this also confirms the policer binding."""
    ok = wait_until(timeout, 2, 0,
                    lambda: all(_acl_rule_status(dut, r, table) == "Active" for r in rules))
    pytest_assert(ok, "ACL rules {} did not become Active in STATE_DB (statuses: {})".format(
        list(rules), {r: _acl_rule_status(dut, r, table) for r in rules}))


def _wait_rules_removed(dut, rules, table=TABLE_NAME, timeout=30):
    """Wait until every named rule is gone from STATE_DB ACL_RULE_TABLE."""
    ok = wait_until(timeout, 2, 0,
                    lambda: all(not _acl_rule_status(dut, r, table) for r in rules))
    pytest_assert(ok, "ACL rules {} were not removed from STATE_DB".format(list(rules)))


def _new_policer_oid(dut, before_keys, timeout=20):
    """Wait for exactly one new SAI policer OID (relative to before_keys) and return it. This scopes
    the policer-lifecycle checks to the OID this test created -- policers have no STATE_DB table
    (PolicerOrch never writes STATE_DB), so a scoped ASIC_DB OID is the only observation point, and
    scoping to the specific OID keeps it immune to any other policer churn."""
    ok = wait_until(timeout, 2, 0, lambda: len(set(_asic_policer_keys(dut)) - before_keys) == 1)
    pytest_assert(ok, "the POLICER config should create exactly one new SAI policer object "
                      "(new OIDs: {})".format(list(set(_asic_policer_keys(dut)) - before_keys)))
    return next(iter(set(_asic_policer_keys(dut)) - before_keys))


def _policer_oids(dut):
    """Current set of SAI policer OIDs in ASIC_DB."""
    return set(_asic_policer_keys(dut))


@pytest.fixture(scope="module")
def setup_counterpoll_interval(rand_selected_dut, rand_unselected_dut, tbinfo):
    """Poll ACL counters every 1s (10s by default) so match counts settle quickly."""
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    for dut in duts:
        dut.shell("counterpoll acl interval 1000")
    time.sleep(10)
    yield
    for dut in duts:
        dut.shell("counterpoll acl interval 10000")


@pytest.fixture(scope="module", autouse=True)
def remove_dataacl_table(rand_selected_dut, rand_unselected_dut, tbinfo):
    """Remove DATAACL to free TCAM for the custom policer table, then restore it."""
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    table = "DATAACL"
    saved = None
    output = rand_selected_dut.shell('sonic-cfggen -d --var-json "ACL_TABLE"')["stdout"]
    try:
        tables = json.loads(output)
        if table in tables:
            saved = {table: tables[table]}
    except ValueError:
        # sonic-cfggen produced no parseable ACL_TABLE JSON (e.g. an empty config): there is
        # nothing to save, so leave saved = None (set above) and skip the remove/restore below.
        logger.debug("setup_acl_table: no parseable ACL_TABLE JSON to save; skipping save/restore")
    if saved is None:
        yield
        return
    logger.info("Removing ACL table %s to free TCAM", table)
    for dut in duts:
        dut.shell("config acl remove table {}".format(table))
    yield
    logger.info("Restoring ACL table %s", table)
    restore = "sonic-cfggen -a '{}' -w".format(json.dumps({"ACL_TABLE": saved}))
    for dut in duts:
        dut.shell(restore)


@pytest.fixture(scope="function")
def setup_policer_table(rand_selected_dut, rand_unselected_dut, tbinfo):
    """Load the custom POLICER_L3 table type and create an ingress table bound to the
    downstream Vlan member ports (a custom ACL table type binds to PORT/PORTCHANNEL)."""
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    bind_ports = ",".join(list(mg_facts["minigraph_vlans"].values())[0]["members"])
    for dut in duts:
        dut.copy(src=TABLE_TYPE_SRC, dest=TABLE_TYPE_DST)
        dut.shell("sonic-cfggen -j {} -w".format(TABLE_TYPE_DST))

    loganalyzer = LogAnalyzer(ansible_host=rand_selected_dut, marker_prefix="acl_policer")
    loganalyzer.load_common_config()
    try:
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_CREATE_RE]
        loganalyzer.ignore_regex = [r".*"]
        with loganalyzer:
            for dut in duts:
                dut.shell("config acl add table {} {} -s ingress -p {}".format(
                    TABLE_NAME, TABLE_TYPE_NAME, bind_ports))
    except LogAnalyzerError as err:
        for dut in duts:
            dut.shell("config acl remove table {}".format(TABLE_NAME))
        raise err

    yield

    for dut in duts:
        dut.shell("config acl remove table {}".format(TABLE_NAME))
        dut.shell("sonic-db-cli CONFIG_DB del 'ACL_TABLE_TYPE|{}'".format(TABLE_TYPE_NAME))
        # Defensive: drop any policer this module may have created.
        dut.shell("sonic-db-cli CONFIG_DB del 'POLICER|{}'".format(METER_POLICER))
        dut.shell("sonic-db-cli CONFIG_DB del 'POLICER|{}'".format(RATE_POLICER))
        dut.shell("sonic-db-cli CONFIG_DB del 'POLICER|{}'".format(SHARE_POLICER))


@pytest.fixture(scope="function")
def setup_meter_rules(rand_selected_dut, rand_unselected_dut, tbinfo, setup_policer_table):
    """Load the meter POLICER and the FORWARD + POLICER compose rules (v4 and v6)."""
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    for dut in duts:
        dut.copy(src=POLICER_SRC, dest=POLICER_DST)
        dut.copy(src=RULES_SRC, dest=RULES_DST)
        dut.shell("sonic-cfggen -j {} -w".format(POLICER_DST))
        dut.shell("sonic-cfggen -j {} -w".format(RULES_DST))
    yield
    for dut in duts:
        dut.shell("acl-loader delete {}".format(TABLE_NAME))
        dut.shell("sonic-db-cli CONFIG_DB del 'POLICER|{}'".format(METER_POLICER))
        dut.shell("sonic-db-cli CONFIG_DB del 'POLICER|{}'".format(RATE_POLICER))


def _uplink_ptf_indices(dut, tbinfo, mg_facts, mg_unselected=None):
    """PTF indices of the upstream (uplink) ports the matched traffic egresses on."""
    dst = []
    if len(mg_facts["minigraph_portchannels"]):
        for _, pc in mg_facts["minigraph_portchannels"].items():
            for member in pc["members"]:
                dst.append(mg_facts["minigraph_ptf_indices"][member])
                if mg_unselected is not None:
                    dst.append(mg_unselected["minigraph_ptf_indices"][member])
    else:
        for neigh in get_all_upstream_neigh_type(tbinfo["topo"]["type"]):
            dst.extend(get_neighbor_ptf_port_list(dut, neigh, tbinfo))
    return dst


def _uplink_nexthop(dut, mg_facts):
    """An IPv4 next-hop address learned on an uplink PortChannel (or None if none is resolved).

    ACL redirect is targeted at a next-hop IP -- resolved through routing -- rather than at a LAG
    object: an ACL redirect whose target is a LAG object does not egress on Broadcom, whereas a
    next-hop target egresses correctly and portably across ASICs. Any uplink PortChannel neighbor
    is a valid redirect next hop.
    """
    for name, pc in mg_facts["minigraph_portchannels"].items():
        if not pc.get("members"):
            continue
        keys = dut.shell("sonic-db-cli APPL_DB keys 'NEIGH_TABLE:{}:*'".format(name),
                         module_ignore_errors=True)["stdout"].strip().splitlines()
        for k in keys:
            parts = k.split(":", 2)  # NEIGH_TABLE:<intf>:<ip>; maxsplit keeps IPv6 colons intact
            if len(parts) == 3 and "." in parts[2] and ":" not in parts[2]:
                return parts[2]
    return None


def _build_meter_packet(ip_version, router_mac):
    """Return (pkt, exp_mask) for the compose test for the given IP version."""
    if ip_version == "ipv4":
        pkt = testutils.simple_tcp_packet(eth_dst=router_mac, ip_src="192.168.0.3",
                                          ip_dst=METER_DST_IP, tcp_sport=8888, tcp_dport=9999)
        exp = Mask(pkt)
        exp.set_do_not_care_scapy(scapy.Ether, "dst")
        exp.set_do_not_care_scapy(scapy.Ether, "src")
        exp.set_do_not_care_scapy(scapy.IP, "ttl")
        exp.set_do_not_care_scapy(scapy.IP, "chksum")
    else:
        pkt = testutils.simple_tcpv6_packet(eth_dst=router_mac, ipv6_src="fc02:1000::3",
                                            ipv6_dst=METER_DST_IPV6, tcp_sport=8888, tcp_dport=9999)
        exp = Mask(pkt)
        exp.set_do_not_care_scapy(scapy.Ether, "dst")
        exp.set_do_not_care_scapy(scapy.Ether, "src")
        exp.set_do_not_care_scapy(scapy.IPv6, "hlim")
    return pkt, exp


def _measure_rx_pps(ptfadapter, pkt, exp, src_idx, dst_indices):
    """CoPP-style rate-controlled, fixed-interval rate measurement: offer 'pkt' at ~RATE_SEND_PPS
    for RATE_SEND_INTERVAL_SEC seconds and return (received, rx_pps, tx_pps) computed over the
    actual elapsed window, so the policer's steady-state rate (not a sub-second burst) is measured.
    Mirrors the ptftests copp_tests.py rate-limited send loop."""
    ptfadapter.dataplane.flush()
    gap = float(RATE_SEND_BATCH) / float(RATE_SEND_PPS)
    sent = 0
    start = datetime.datetime.now()
    end = start + datetime.timedelta(seconds=RATE_SEND_INTERVAL_SEC)
    while datetime.datetime.now() < end:
        testutils.send(ptfadapter, pkt=pkt, port_id=src_idx, count=RATE_SEND_BATCH)
        sent += RATE_SEND_BATCH
        time.sleep(gap)
    elapsed = (datetime.datetime.now() - start).total_seconds() or 1e-6
    received = testutils.count_matched_packets_all_ports(
        ptfadapter, exp_packet=exp, ports=dst_indices, timeout=5)
    return received, received / elapsed, sent / elapsed


@pytest.mark.parametrize("ip_version", ["ipv4", "ipv6"])
def test_policer_compose_and_counter(rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter,
                                     ip_version, setup_meter_rules, setup_counterpoll_interval):
    """
    A FORWARD + POLICER rule rate-limits matched traffic, and the ACL rule counter
    counts every matched packet (pre-policer): counter == offered, not == forwarded.
    Runs for both IPv4 and IPv6 matched flows.
    """
    dut = rand_selected_dut
    if dut.facts["asic_type"] == "vs":
        pytest.skip("Dataplane policing is not modeled on the vs platform")
    if ip_version == "ipv4" and is_ipv6_only_topology(tbinfo):
        pytest.skip("IPv4 traffic is not applicable on an IPv6-only topology")

    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    mg_unselected = None
    if "dualtor" in tbinfo["topo"]["name"]:
        vlan_name = list(mg_facts["minigraph_vlans"].keys())[0]
        router_mac = dut.get_dut_iface_mac(vlan_name)
        if "dualtor-aa" in tbinfo["topo"]["name"] and rand_unselected_dut is not None:
            mg_unselected = rand_unselected_dut.get_extended_minigraph_facts(tbinfo)
    else:
        router_mac = dut.facts["router_mac"]

    src_port = list(mg_facts["minigraph_vlans"].values())[0]["members"][0]
    src_idx = mg_facts["minigraph_ptf_indices"][src_port]
    dst_indices = _uplink_ptf_indices(dut, tbinfo, mg_facts, mg_unselected)
    pytest_assert(dst_indices, "Could not resolve any uplink PTF port for verification")

    rule = METER_RULE if ip_version == "ipv4" else METER_RULE_V6
    pkt, exp = _build_meter_packet(ip_version, router_mac)

    for d in duts:
        clear_acl_counter(d)
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, pkt=pkt, port_id=src_idx, count=OFFERED_PKTS)
    forwarded = testutils.count_matched_packets_all_ports(
        ptfadapter, exp_packet=exp, ports=dst_indices, timeout=5)
    matched = read_acl_counter_sum(duts, rule)
    logger.info("policer compose [%s]: offered=%d matched(counter)=%d forwarded=%d",
                ip_version, OFFERED_PKTS, matched, forwarded)

    pytest_assert(matched >= OFFERED_PKTS * 0.99,
                  "ACL rule counter should count matched packets pre-policer (~= offered): "
                  "offered={} counter={}".format(OFFERED_PKTS, matched))
    pytest_assert(matched > forwarded,
                  "ACL rule counter must reflect matched (pre-policer) packets, not the "
                  "forwarded/policed count: counter={} forwarded={}".format(matched, forwarded))
    pytest_assert(forwarded < OFFERED_PKTS,
                  "policer did not drop any excess (metering not applied): "
                  "forwarded={} offered={}".format(forwarded, OFFERED_PKTS))
    pytest_assert(forwarded > 0,
                  "policer dropped all traffic (looks like a base drop, not metering): "
                  "forwarded=0")


def test_policer_cir_rate(rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter,
                          setup_meter_rules, setup_counterpoll_interval):
    """
    CIR check: a burst offered well above CIR is capped by the policer to a
    received rate near CIR, while the same traffic matched by an un-policed FORWARD rule
    is not rate-limited.
    """
    dut = rand_selected_dut
    if dut.facts["asic_type"] == "vs":
        pytest.skip("Dataplane policing is not modeled on the vs platform")

    mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    mg_unselected = None
    if "dualtor" in tbinfo["topo"]["name"]:
        vlan_name = list(mg_facts["minigraph_vlans"].keys())[0]
        router_mac = dut.get_dut_iface_mac(vlan_name)
        if "dualtor-aa" in tbinfo["topo"]["name"] and rand_unselected_dut is not None:
            mg_unselected = rand_unselected_dut.get_extended_minigraph_facts(tbinfo)
    else:
        router_mac = dut.facts["router_mac"]

    src_port = list(mg_facts["minigraph_vlans"].values())[0]["members"][0]
    src_idx = mg_facts["minigraph_ptf_indices"][src_port]
    dst_indices = _uplink_ptf_indices(dut, tbinfo, mg_facts, mg_unselected)
    pytest_assert(dst_indices, "Could not resolve any uplink PTF port for verification")

    def _pkt(dst_ip):
        p = testutils.simple_tcp_packet(eth_dst=router_mac, ip_src="192.168.0.3",
                                        ip_dst=dst_ip, tcp_sport=8888, tcp_dport=9999)
        m = Mask(p)
        m.set_do_not_care_scapy(scapy.Ether, "dst")
        m.set_do_not_care_scapy(scapy.Ether, "src")
        m.set_do_not_care_scapy(scapy.IP, "ttl")
        m.set_do_not_care_scapy(scapy.IP, "chksum")
        return p, m

    np_pkt, np_exp = _pkt(RATE_NP_DST_IP)
    pol_pkt, pol_exp = _pkt(RATE_DST_IP)

    low = RATE_CIR_PPS * RATE_CIR_LOW
    high = RATE_CIR_PPS * RATE_CIR_HIGH
    # Only the rx rates are read after the loop; the tx rates are reassigned each
    # iteration before use, so they need no pre-loop initialization.
    np_rx_pps = pol_rx_pps = 0.0
    # Re-measure a few times and accept the first in-band sample (CoPP wraps its runner in
    # wait_until for the same reason): a single transient PTF send-rate blip must not fail the test.
    for attempt in range(RATE_MEASURE_RETRIES):
        _, np_rx_pps, np_tx_pps = _measure_rx_pps(ptfadapter, np_pkt, np_exp, src_idx, dst_indices)
        _, pol_rx_pps, pol_tx_pps = _measure_rx_pps(ptfadapter, pol_pkt, pol_exp, src_idx, dst_indices)
        logger.info("policer CIR [attempt %d/%d]: cir=%d np_rx_pps=%.0f (tx=%.0f) "
                    "policed_rx_pps=%.0f (tx=%.0f)", attempt + 1, RATE_MEASURE_RETRIES,
                    RATE_CIR_PPS, np_rx_pps, np_tx_pps, pol_rx_pps, pol_tx_pps)
        if (np_rx_pps > RATE_CIR_PPS * RATE_NO_POLICER_FACTOR
                and pol_rx_pps < np_rx_pps * RATE_POLICED_FRACTION
                and low <= pol_rx_pps <= high):
            break

    pytest_assert(np_rx_pps > RATE_CIR_PPS * RATE_NO_POLICER_FACTOR,
                  "un-policed rate {:.0f} pps is not well above CIR {} pps; PTF send too slow "
                  "to exercise the policer".format(np_rx_pps, RATE_CIR_PPS))
    pytest_assert(pol_rx_pps < np_rx_pps * RATE_POLICED_FRACTION,
                  "policed rate {:.0f} pps is not materially below the un-policed rate {:.0f} pps; "
                  "policer is not rate-limiting".format(pol_rx_pps, np_rx_pps))
    pytest_assert(low <= pol_rx_pps <= high,
                  "policed rate {:.0f} pps is outside the CIR-scale band [{:.0f}, {:.0f}]".format(
                      pol_rx_pps, low, high))


def test_policer_shared_single_oid(rand_selected_dut, setup_policer_table):
    """
    One POLICER referenced by two ACL rules resolves to a single refcounted SAI
    policer object: the second binding does not create a second OID, the object
    survives deletion of one binding, and it is freed only when the POLICER config
    itself is removed. Refcount is a per-ASIC property, so this runs on the
    selected DUT.
    """
    dut = rand_selected_dut

    def add_rule(name, dst_ip):
        key = "ACL_RULE|{}|{}".format(TABLE_NAME, name)
        dut.shell("sonic-db-cli CONFIG_DB hset '{}' PRIORITY 9990 DST_IP {}/32 "
                  "PACKET_ACTION FORWARD POLICER_ACTION {}".format(key, dst_ip, SHARE_POLICER))

    def del_rule(name):
        dut.shell("sonic-db-cli CONFIG_DB del 'ACL_RULE|{}|{}'".format(TABLE_NAME, name))

    def del_policer():
        dut.shell("sonic-db-cli CONFIG_DB del 'POLICER|{}'".format(SHARE_POLICER))

    before = _policer_oids(dut)
    try:
        # The SAI policer object is created when the POLICER config appears.
        dut.shell("sonic-db-cli CONFIG_DB hset 'POLICER|{}' meter_type packets mode sr_tcm "
                  "cir 100 cbs 100 red_packet_action drop".format(SHARE_POLICER))
        pol_oid = _new_policer_oid(dut, before)

        # First ACL binding -> rule Active, still exactly one policer OID (ours).
        add_rule("RULE_SHARE_A", SHARE_DST_IP_A)
        _wait_rules_active(dut, ["RULE_SHARE_A"])
        pytest_assert(_policer_oids(dut) - before == {pol_oid},
                      "binding an ACL rule must not create a second policer OID")

        # Second ACL binding of the SAME policer -> still exactly the one shared OID.
        add_rule("RULE_SHARE_B", SHARE_DST_IP_B)
        _wait_rules_active(dut, ["RULE_SHARE_B"])
        pytest_assert(_policer_oids(dut) - before == {pol_oid},
                      "a shared policer must resolve to a single OID, not one per binding")

        # Remove one binding -> policer must survive (still referenced by rule B / its config).
        del_rule("RULE_SHARE_A")
        _wait_rules_removed(dut, ["RULE_SHARE_A"])
        pytest_assert(pol_oid in _policer_oids(dut),
                      "policer must survive while another rule still binds it")

        # Remove the last binding -> config still present, so the OID stays.
        del_rule("RULE_SHARE_B")
        _wait_rules_removed(dut, ["RULE_SHARE_B"])
        pytest_assert(pol_oid in _policer_oids(dut),
                      "policer OID lifetime follows its config, not its bindings")

        # Remove the POLICER config -> OID is freed.
        del_policer()
        pytest_assert(wait_until(20, 2, 0, lambda: pol_oid not in _policer_oids(dut)),
                      "policer OID must be freed once its config is removed")
    finally:
        del_rule("RULE_SHARE_A")
        del_rule("RULE_SHARE_B")
        del_policer()


# ---------------------------------------------------------------------------
# Additional data-plane coverage. Each test builds and tears down its own POLICER
# and ACL_RULE(s) in CONFIG_DB on the custom POLICER_L3 table from setup_policer_table,
# so they stay independent of the JSON-loaded compose/rate rules above.
# ---------------------------------------------------------------------------

DEFER_DST_IP = "103.23.2.6"
DEFER_DST_IPV6 = "103:23:2:6::1"
RELEASE_DST_IP = "103.23.2.7"
REDIRECT_DST_IP = "103.23.2.8"
UPDATE_DST_IP = "103.23.2.9"
TR_DST_IP = "103.23.2.10"
BYTES_DST_IP = "103.23.2.11"
RELOAD_DST_IP = "103.23.2.12"
BOUND_DST_IP = "103.23.2.13"

DEFER_POLICER = "test_policer_defer"
RELEASE_POLICER = "test_policer_release"
REDIRECT_POLICER = "test_policer_redirect"
UPDATE_POLICER = "test_policer_update"
TR_POLICER = "test_policer_tr"
BYTES_POLICER = "test_policer_bytes"
RELOAD_POLICER = "test_policer_reload"
BOUND_POLICER = "test_policer_bound"


def _add_policer(dut, name, **fields):
    """Create/overwrite a POLICER in CONFIG_DB from keyword fields."""
    args = " ".join("{} {}".format(k, v) for k, v in fields.items())
    dut.shell("sonic-db-cli CONFIG_DB hset 'POLICER|{}' {}".format(name, args))


def _del_policer(dut, name):
    dut.shell("sonic-db-cli CONFIG_DB del 'POLICER|{}'".format(name))


def _del_rule(dut, rule):
    dut.shell("sonic-db-cli CONFIG_DB del 'ACL_RULE|{}|{}'".format(TABLE_NAME, rule))


def _add_forward_policer_rule(dut, rule, priority, dst_ip, policer, ip_version="ipv4"):
    """FORWARD + POLICER rule matching TCP to dst_ip (IPv4 /32 or IPv6 /128)."""
    key = "ACL_RULE|{}|{}".format(TABLE_NAME, rule)
    if ip_version == "ipv6":
        match = "DST_IPV6 {}/128 NEXT_HEADER 6".format(dst_ip)
    else:
        match = "DST_IP {}/32 IP_PROTOCOL 6".format(dst_ip)
    dut.shell("sonic-db-cli CONFIG_DB hset '{}' PRIORITY {} {} "
              "PACKET_ACTION FORWARD POLICER_ACTION {}".format(key, priority, match, policer))


def _tcp_pkt(router_mac, dst_ip, ip_version="ipv4", pktlen=None):
    """Return (pkt, exp_mask) for a TCP packet to dst_ip for the given IP version."""
    if ip_version == "ipv6":
        kwargs = dict(eth_dst=router_mac, ipv6_src="fc02:1000::3", ipv6_dst=dst_ip,
                      tcp_sport=8888, tcp_dport=9999)
        if pktlen is not None:
            kwargs["pktlen"] = pktlen
        pkt = testutils.simple_tcpv6_packet(**kwargs)
        exp = Mask(pkt)
        exp.set_do_not_care_scapy(scapy.Ether, "dst")
        exp.set_do_not_care_scapy(scapy.Ether, "src")
        exp.set_do_not_care_scapy(scapy.IPv6, "hlim")
    else:
        kwargs = dict(eth_dst=router_mac, ip_src="192.168.0.3", ip_dst=dst_ip,
                      tcp_sport=8888, tcp_dport=9999)
        if pktlen is not None:
            kwargs["pktlen"] = pktlen
        pkt = testutils.simple_tcp_packet(**kwargs)
        exp = Mask(pkt)
        exp.set_do_not_care_scapy(scapy.Ether, "dst")
        exp.set_do_not_care_scapy(scapy.Ether, "src")
        exp.set_do_not_care_scapy(scapy.IP, "ttl")
        exp.set_do_not_care_scapy(scapy.IP, "chksum")
    return pkt, exp


def _forwarded(ptfadapter, pkt, exp, src_idx, dst_indices, count=OFFERED_PKTS):
    """Send count packets from src_idx and return how many matched on dst_indices."""
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, pkt=pkt, port_id=src_idx, count=count)
    return testutils.count_matched_packets_all_ports(
        ptfadapter, exp_packet=exp, ports=dst_indices, timeout=5)


def _endpoints(dut, rand_unselected_dut, tbinfo):
    """(mg_facts, router_mac, src_idx, dst_indices) for downstream->uplink test traffic."""
    mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    mg_unselected = None
    if "dualtor" in tbinfo["topo"]["name"]:
        vlan_name = list(mg_facts["minigraph_vlans"].keys())[0]
        router_mac = dut.get_dut_iface_mac(vlan_name)
        if "dualtor-aa" in tbinfo["topo"]["name"] and rand_unselected_dut is not None:
            mg_unselected = rand_unselected_dut.get_extended_minigraph_facts(tbinfo)
    else:
        router_mac = dut.facts["router_mac"]
    src_port = list(mg_facts["minigraph_vlans"].values())[0]["members"][0]
    src_idx = mg_facts["minigraph_ptf_indices"][src_port]
    dst_indices = _uplink_ptf_indices(dut, tbinfo, mg_facts, mg_unselected)
    return mg_facts, router_mac, src_idx, dst_indices


@pytest.mark.parametrize("ip_version", ["ipv4", "ipv6"])
def test_policer_rule_before_policer(rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter,
                                     setup_policer_table, setup_counterpoll_interval, ip_version):
    """A rule that references a not-yet-created POLICER is deferred (not programmed in the ASIC
    and traffic un-policed); once the POLICER is created the deferred rule is programmed and
    traffic is policed. Exercised for both IPv4 and IPv6 match keys."""
    dut = rand_selected_dut
    if dut.facts["asic_type"] == "vs":
        pytest.skip("Dataplane policing is not modeled on the vs platform")
    if ip_version == "ipv4" and is_ipv6_only_topology(tbinfo):
        pytest.skip("No IPv4 endpoints on an IPv6-only topology")
    dst_ip = DEFER_DST_IPV6 if ip_version == "ipv6" else DEFER_DST_IP
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    _, router_mac, src_idx, dst_indices = _endpoints(dut, rand_unselected_dut, tbinfo)
    pytest_assert(dst_indices, "Could not resolve any uplink PTF port for verification")
    pkt, exp = _tcp_pkt(router_mac, dst_ip, ip_version)
    try:
        for d in duts:
            _add_forward_policer_rule(d, "RULE_DEFER", 9990, dst_ip, DEFER_POLICER, ip_version)
        # The referenced policer does not exist yet: the rule must stay deferred -- its STATE_DB
        # status never reaches 'Active' within the poll window (AclOrch keeps it 'Pending creation').
        pytest_assert(
            not wait_until(10, 2, 0, lambda: _acl_rule_status(dut, "RULE_DEFER") == "Active"),
            "a rule referencing a missing policer must be deferred (not Active) in STATE_DB")
        deferred = _forwarded(ptfadapter, pkt, exp, src_idx, dst_indices)
        pytest_assert(deferred >= OFFERED_PKTS * 0.9,
                      "a deferred rule must not police traffic: "
                      "forwarded={} offered={}".format(deferred, OFFERED_PKTS))
        for d in duts:
            _add_policer(d, DEFER_POLICER, meter_type="packets", mode="sr_tcm",
                         cir="100", cbs="100", red_packet_action="drop")
        _wait_rules_active(dut, ["RULE_DEFER"])
        policed = _forwarded(ptfadapter, pkt, exp, src_idx, dst_indices)
        pytest_assert(policed < deferred * 0.5,
                      "once the policer exists the deferred rule must be programmed and police "
                      "traffic: policed={} deferred={}".format(policed, deferred))
    finally:
        for d in duts:
            _del_rule(d, "RULE_DEFER")
            _del_policer(d, DEFER_POLICER)


def test_policer_release_on_removal(rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter,
                                    setup_policer_table, setup_counterpoll_interval):
    """Unbinding the POLICER from a rule releases the policer; the same matched flow returns
    to its un-policed rate while the rule keeps forwarding it."""
    dut = rand_selected_dut
    if dut.facts["asic_type"] == "vs":
        pytest.skip("Dataplane policing is not modeled on the vs platform")
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    _, router_mac, src_idx, dst_indices = _endpoints(dut, rand_unselected_dut, tbinfo)
    pytest_assert(dst_indices, "Could not resolve any uplink PTF port for verification")
    pkt, exp = _tcp_pkt(router_mac, RELEASE_DST_IP)
    try:
        for d in duts:
            _add_policer(d, RELEASE_POLICER, meter_type="packets", mode="sr_tcm",
                         cir="100", cbs="100", red_packet_action="drop")
            _add_forward_policer_rule(d, "RULE_RELEASE", 9990, RELEASE_DST_IP, RELEASE_POLICER)
        _wait_rules_active(dut, ["RULE_RELEASE"])
        policed = _forwarded(ptfadapter, pkt, exp, src_idx, dst_indices)
        pytest_assert(policed < OFFERED_PKTS * 0.5,
                      "traffic must be policed while the policer is bound: "
                      "forwarded={} offered={}".format(policed, OFFERED_PKTS))
        # Re-program the same rule as FORWARD-only (policer unbound); the rule stays Active while
        # the POLICER config (and its SAI OID) persists -- see test_policer_shared_single_oid /
        # test_policer_bound_cannot_delete for the OID-lifetime proof.
        for d in duts:
            _del_rule(d, "RULE_RELEASE")
            key = "ACL_RULE|{}|RULE_RELEASE".format(TABLE_NAME)
            d.shell("sonic-db-cli CONFIG_DB hset '{}' PRIORITY 9990 DST_IP {}/32 IP_PROTOCOL 6 "
                    "PACKET_ACTION FORWARD".format(key, RELEASE_DST_IP))
        # Only the binding is gone -- the matched flow returns to its un-policed rate.
        _wait_rules_active(dut, ["RULE_RELEASE"])
        released = _forwarded(ptfadapter, pkt, exp, src_idx, dst_indices)
        pytest_assert(released >= OFFERED_PKTS * 0.9,
                      "after the policer is unbound the flow must return to its un-policed rate: "
                      "forwarded={} offered={}".format(released, OFFERED_PKTS))
    finally:
        for d in duts:
            _del_rule(d, "RULE_RELEASE")
            _del_policer(d, RELEASE_POLICER)


def test_policer_shared_aggregate(rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter,
                                  setup_policer_table, setup_counterpoll_interval):
    """One POLICER shared by two ACL rules meters the AGGREGATE of both matched flows:
    the combined forwarded count stays near a single flow's, not the sum of the two."""
    dut = rand_selected_dut
    if dut.facts["asic_type"] == "vs":
        pytest.skip("Dataplane policing is not modeled on the vs platform")
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    _, router_mac, src_idx, dst_indices = _endpoints(dut, rand_unselected_dut, tbinfo)
    pytest_assert(dst_indices, "Could not resolve any uplink PTF port for verification")
    pkt_a, exp_a = _tcp_pkt(router_mac, SHARE_DST_IP_A)
    pkt_b, exp_b = _tcp_pkt(router_mac, SHARE_DST_IP_B)
    try:
        for d in duts:
            _add_policer(d, SHARE_POLICER, meter_type="packets", mode="sr_tcm",
                         cir="100", cbs="100", red_packet_action="drop")
            _add_forward_policer_rule(d, "RULE_SHARE_A", 9990, SHARE_DST_IP_A, SHARE_POLICER)
            _add_forward_policer_rule(d, "RULE_SHARE_B", 9989, SHARE_DST_IP_B, SHARE_POLICER)
        _wait_rules_active(dut, ["RULE_SHARE_A", "RULE_SHARE_B"])
        one = _forwarded(ptfadapter, pkt_a, exp_a, src_idx, dst_indices)
        pytest_assert(one > 0, "flow A should forward its policed share: forwarded=0")
        time.sleep(3)  # let the shared token bucket refill before the aggregate measurement
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, pkt=pkt_a, port_id=src_idx, count=OFFERED_PKTS)
        testutils.send(ptfadapter, pkt=pkt_b, port_id=src_idx, count=OFFERED_PKTS)
        both = (testutils.count_matched_packets_all_ports(
                    ptfadapter, exp_packet=exp_a, ports=dst_indices, timeout=5)
                + testutils.count_matched_packets_all_ports(
                    ptfadapter, exp_packet=exp_b, ports=dst_indices, timeout=5))
        pytest_assert(both < one * 1.8,
                      "a shared policer must meter the aggregate of both flows, not per-rule "
                      "(sub-additive): both={} single={}".format(both, one))
    finally:
        for d in duts:
            _del_rule(d, "RULE_SHARE_A")
            _del_rule(d, "RULE_SHARE_B")
            _del_policer(d, SHARE_POLICER)


def test_policer_compose_redirect(rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter,
                                  setup_policer_table, setup_counterpoll_interval):
    """A REDIRECT + POLICER rule sends the matched flow to a chosen next hop and rate-limits it.

    Gating is by capability query only -- no behaviour-based masking. The test is skipped solely
    when the platform does not advertise the required ingress ACL actions (REDIRECT_ACTION and
    POLICER_ACTION) in STATE_DB ACL_STAGE_CAPABILITY_TABLE, or when no uplink next hop is resolved
    to redirect to. Where the actions are advertised the test asserts real behaviour: a plain
    redirect to the next hop must egress an uplink (precondition), and the composed REDIRECT+POLICER
    rule must both redirect (pre-policer ACL counter ~= offered) and police (egress < offered). Any
    functional failure is surfaced (never skipped) so a genuine redirect or compose bug is caught.

    The redirect target is a next-hop IP, not a LAG/port: an ACL redirect targeting a LAG object
    does not egress on Broadcom, whereas a next-hop target resolves through routing and egresses
    correctly, so the next-hop form is the portable, upstream-robust redirect target.
    """
    dut = rand_selected_dut
    if dut.facts["asic_type"] == "vs":
        pytest.skip("Dataplane policing is not modeled on the vs platform")
    actions = _acl_ingress_action_list(dut)
    if actions and not {"REDIRECT_ACTION", "POLICER_ACTION"}.issubset(actions):
        pytest.skip("Platform does not advertise REDIRECT_ACTION+POLICER_ACTION at ingress: {}".format(actions))
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    mg_facts, router_mac, src_idx, dst_indices = _endpoints(dut, rand_unselected_dut, tbinfo)
    nexthop = _uplink_nexthop(dut, mg_facts)
    if not nexthop:
        pytest.skip("No resolved uplink next hop available to redirect to")
    pkt, exp = _tcp_pkt(router_mac, REDIRECT_DST_IP)
    base_pol, base_rules = get_asic_policer_count(dut), get_asic_acl_rule_count(dut)

    # Precondition: a plain REDIRECT (no policer) to the next hop must egress an uplink. This
    # isolates a redirect limitation from a policer-compose limitation. REDIRECT_DST_IP has no
    # normal route, so any uplink egress is attributable to the redirect action.
    try:
        for d in duts:
            base_key = "ACL_RULE|{}|RULE_REDIRECT_BASE".format(TABLE_NAME)
            d.shell("sonic-db-cli CONFIG_DB hset '{}' PRIORITY 9991 DST_IP {}/32 IP_PROTOCOL 6 "
                    "PACKET_ACTION 'REDIRECT:{}'".format(base_key, REDIRECT_DST_IP, nexthop))
        _wait_rules_active(dut, ["RULE_REDIRECT_BASE"])
        base_redirected = _forwarded(ptfadapter, pkt, exp, src_idx, dst_indices)
    finally:
        for d in duts:
            _del_rule(d, "RULE_REDIRECT_BASE")
    pytest_assert(base_redirected > 0,
                  "precondition failed: a plain REDIRECT to next hop {} did not egress any uplink "
                  "(redirected={} offered={})".format(nexthop, base_redirected, OFFERED_PKTS))

    # Composed REDIRECT + POLICER: the same flow is redirected to the next hop and rate-limited.
    try:
        for d in duts:
            _add_policer(d, REDIRECT_POLICER, meter_type="packets", mode="sr_tcm",
                         cir="100", cbs="100", red_packet_action="drop")
            key = "ACL_RULE|{}|RULE_REDIRECT".format(TABLE_NAME)
            d.shell("sonic-db-cli CONFIG_DB hset '{}' PRIORITY 9990 DST_IP {}/32 IP_PROTOCOL 6 "
                    "PACKET_ACTION 'REDIRECT:{}' POLICER_ACTION {}".format(
                        key, REDIRECT_DST_IP, nexthop, REDIRECT_POLICER))
        _wait_programmed(dut, base_pol, 1, base_rules, 1, "redirect + policer rule")
        for d in duts:
            clear_acl_counter(d)
        redirected = _forwarded(ptfadapter, pkt, exp, src_idx, dst_indices)
        matched = read_acl_counter_sum(duts, "RULE_REDIRECT")
        logger.info("redirect+policer: nexthop=%s base_redirected=%d redirected=%d matched(counter)=%d offered=%d",
                    nexthop, base_redirected, redirected, matched, OFFERED_PKTS)
        pytest_assert(matched >= OFFERED_PKTS * 0.9,
                      "REDIRECT + POLICER rule must match the flow (pre-policer counter ~= offered): "
                      "counter={} offered={}".format(matched, OFFERED_PKTS))
        pytest_assert(0 < redirected < OFFERED_PKTS,
                      "matched traffic must egress the redirect next hop and be policed: "
                      "redirected={} offered={}".format(redirected, OFFERED_PKTS))
    finally:
        for d in duts:
            _del_rule(d, "RULE_REDIRECT")
            _del_policer(d, REDIRECT_POLICER)


MIRROR_SHARE_POLICER = "test_policer_mirror_share"
MIRROR_SHARE_SESSION = "test_mirror_share_sess"
MIRROR_SHARE_DST_IP = "103.23.2.14"
MIRROR_ERSPAN_DST = "103.23.9.9"


def test_policer_shared_with_mirror_session(rand_selected_dut, setup_policer_table):
    """One POLICER referenced by BOTH a MIRROR_SESSION and an ACL POLICER_ACTION rule resolves to a
    single refcounted SAI policer object: the mirror binding does not create a second OID, the object
    survives removal of the ACL binding while the mirror still references it, and it is freed only
    when the POLICER config itself is removed. Refcount is a per-ASIC property, so this runs on the
    selected DUT.

    Capability-gated (no masking): skipped unless the platform advertises mirroring
    (SWITCH_CAPABILITY MIRROR) and the ingress POLICER_ACTION ACL action.
    """
    dut = rand_selected_dut
    if dut.facts["asic_type"] == "vs":
        pytest.skip("Policer OID lifecycle is not modeled on the vs platform")
    if not _switch_mirror_capable(dut):
        pytest.skip("Platform does not advertise mirroring (SWITCH_CAPABILITY MIRROR)")
    actions = _acl_ingress_action_list(dut)
    if actions and "POLICER_ACTION" not in actions:
        pytest.skip("Platform does not advertise POLICER_ACTION at ingress: {}".format(actions))

    def add_mirror():
        dut.shell("sonic-db-cli CONFIG_DB hset 'MIRROR_SESSION|{}' src_ip 10.1.0.32 dst_ip {} "
                  "gre_type 0x88be dscp 8 ttl 100 queue 0 policer {}".format(
                      MIRROR_SHARE_SESSION, MIRROR_ERSPAN_DST, MIRROR_SHARE_POLICER))

    def del_mirror():
        dut.shell("sonic-db-cli CONFIG_DB del 'MIRROR_SESSION|{}'".format(MIRROR_SHARE_SESSION))

    def add_acl_rule():
        key = "ACL_RULE|{}|RULE_MIRROR_SHARE".format(TABLE_NAME)
        dut.shell("sonic-db-cli CONFIG_DB hset '{}' PRIORITY 9990 DST_IP {}/32 IP_PROTOCOL 6 "
                  "PACKET_ACTION FORWARD POLICER_ACTION {}".format(
                      key, MIRROR_SHARE_DST_IP, MIRROR_SHARE_POLICER))

    def del_acl_rule():
        dut.shell("sonic-db-cli CONFIG_DB del 'ACL_RULE|{}|RULE_MIRROR_SHARE'".format(TABLE_NAME))

    def del_policer():
        dut.shell("sonic-db-cli CONFIG_DB del 'POLICER|{}'".format(MIRROR_SHARE_POLICER))

    before = _policer_oids(dut)
    try:
        # The SAI policer object is created when the POLICER config appears.
        dut.shell("sonic-db-cli CONFIG_DB hset 'POLICER|{}' meter_type packets mode sr_tcm "
                  "cir 100 cbs 100 red_packet_action drop".format(MIRROR_SHARE_POLICER))
        pol_oid = _new_policer_oid(dut, before)

        # A MIRROR_SESSION referencing the SAME policer must share the object, not create a new OID.
        add_mirror()
        time.sleep(3)
        pytest_assert(_policer_oids(dut) - before == {pol_oid},
                      "a MIRROR_SESSION referencing the policer must not create a second policer OID")

        # An ACL rule referencing the SAME policer -> rule Active, still exactly the one shared OID.
        add_acl_rule()
        _wait_rules_active(dut, ["RULE_MIRROR_SHARE"])
        pytest_assert(_policer_oids(dut) - before == {pol_oid},
                      "a policer shared by a mirror session and an ACL rule must resolve to one OID")

        # Remove the ACL binding -> the policer must survive (mirror session + config still hold it).
        del_acl_rule()
        _wait_rules_removed(dut, ["RULE_MIRROR_SHARE"])
        pytest_assert(pol_oid in _policer_oids(dut),
                      "the shared policer must survive removal of the ACL binding")

        # Remove the mirror binding -> config still present, so the OID stays.
        del_mirror()
        time.sleep(3)
        pytest_assert(pol_oid in _policer_oids(dut),
                      "policer OID lifetime follows its config, not its bindings")

        # Remove the POLICER config -> OID is freed.
        del_policer()
        pytest_assert(wait_until(20, 2, 0, lambda: pol_oid not in _policer_oids(dut)),
                      "policer OID must be freed once its config is removed")
    finally:
        del_acl_rule()
        del_mirror()
        del_policer()


def test_policer_cir_update(rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter,
                            setup_policer_table, setup_counterpoll_interval):
    """Raising a bound POLICER's CIR raises the enforced rate on the already-bound rule."""
    dut = rand_selected_dut
    if dut.facts["asic_type"] == "vs":
        pytest.skip("Dataplane policing is not modeled on the vs platform")
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    _, router_mac, src_idx, dst_indices = _endpoints(dut, rand_unselected_dut, tbinfo)
    pytest_assert(dst_indices, "Could not resolve any uplink PTF port for verification")
    pkt, exp = _tcp_pkt(router_mac, UPDATE_DST_IP)
    before_keys = _policer_oids(dut)
    try:
        for d in duts:
            _add_policer(d, UPDATE_POLICER, meter_type="packets", mode="sr_tcm",
                         cir="100", cbs="100", red_packet_action="drop")
            _add_forward_policer_rule(d, "RULE_UPDATE", 9990, UPDATE_DST_IP, UPDATE_POLICER)
        _wait_rules_active(dut, ["RULE_UPDATE"])
        pol_key = next(iter(_policer_oids(dut) - before_keys), None)
        old_cir = _policer_cir(dut, pol_key)
        low = _forwarded(ptfadapter, pkt, exp, src_idx, dst_indices)
        pytest_assert(low < OFFERED_PKTS * 0.5,
                      "flow must be policed at the low CIR: forwarded={} offered={}".format(
                          low, OFFERED_PKTS))
        for d in duts:
            d.shell("sonic-db-cli CONFIG_DB hset 'POLICER|{}' cir 100000 cbs 100000".format(
                UPDATE_POLICER))
        # The update is an in-place SAI attribute set (no new object); poll until the ASIC CIR
        # attribute reflects the raised value before re-measuring.
        if pol_key:
            pytest_assert(wait_until(30, 2, 0, lambda: _policer_cir(dut, pol_key) != old_cir),
                          "raising the policer CIR must update the ASIC policer attribute")
        else:
            time.sleep(5)
        high = _forwarded(ptfadapter, pkt, exp, src_idx, dst_indices)
        pytest_assert(high > low * 1.5,
                      "raising the bound policer's CIR must raise the forwarded rate: "
                      "low={} high={}".format(low, high))
        pytest_assert(high >= OFFERED_PKTS * 0.9,
                      "at a high CIR the flow should be essentially un-policed: "
                      "forwarded={} offered={}".format(high, OFFERED_PKTS))
    finally:
        for d in duts:
            _del_rule(d, "RULE_UPDATE")
            _del_policer(d, UPDATE_POLICER)


def test_policer_two_rate_tcm(rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter,
                              setup_policer_table, setup_counterpoll_interval):
    """A two-rate (tr_tcm) POLICER forwards the conforming (green+yellow) portion and drops
    the excess (red) of a flow offered above PIR."""
    dut = rand_selected_dut
    if dut.facts["asic_type"] == "vs":
        pytest.skip("Dataplane policing is not modeled on the vs platform")
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    _, router_mac, src_idx, dst_indices = _endpoints(dut, rand_unselected_dut, tbinfo)
    pytest_assert(dst_indices, "Could not resolve any uplink PTF port for verification")
    pkt, exp = _tcp_pkt(router_mac, TR_DST_IP)
    try:
        for d in duts:
            _add_policer(d, TR_POLICER, meter_type="packets", mode="tr_tcm",
                         cir="100", cbs="100", pir="200", pbs="200",
                         green_packet_action="forward", yellow_packet_action="forward",
                         red_packet_action="drop")
            _add_forward_policer_rule(d, "RULE_TR", 9990, TR_DST_IP, TR_POLICER)
        _wait_rules_active(dut, ["RULE_TR"])
        forwarded = _forwarded(ptfadapter, pkt, exp, src_idx, dst_indices)
        pytest_assert(0 < forwarded < OFFERED_PKTS * 0.9,
                      "tr_tcm policer must forward the conforming (green+yellow) portion and drop "
                      "the rest (red): forwarded={} offered={}".format(forwarded, OFFERED_PKTS))
    finally:
        for d in duts:
            _del_rule(d, "RULE_TR")
            _del_policer(d, TR_POLICER)


def test_policer_bytes_mode(rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter,
                            setup_policer_table, setup_counterpoll_interval):
    """A byte-mode (meter_type=bytes) POLICER rate-limits by bandwidth: a large-frame flow
    offered well above the byte CIR is largely dropped."""
    dut = rand_selected_dut
    if dut.facts["asic_type"] == "vs":
        pytest.skip("Dataplane policing is not modeled on the vs platform")
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    _, router_mac, src_idx, dst_indices = _endpoints(dut, rand_unselected_dut, tbinfo)
    pytest_assert(dst_indices, "Could not resolve any uplink PTF port for verification")
    pkt, exp = _tcp_pkt(router_mac, BYTES_DST_IP, pktlen=1400)
    try:
        for d in duts:
            _add_policer(d, BYTES_POLICER, meter_type="bytes", mode="sr_tcm",
                         cir="50000", cbs="50000", red_packet_action="drop")
            _add_forward_policer_rule(d, "RULE_BYTES", 9990, BYTES_DST_IP, BYTES_POLICER)
        _wait_rules_active(dut, ["RULE_BYTES"])
        forwarded = _forwarded(ptfadapter, pkt, exp, src_idx, dst_indices)
        pytest_assert(0 < forwarded < OFFERED_PKTS * 0.5,
                      "byte-mode policer must rate-limit large-frame traffic by bandwidth: "
                      "forwarded={} offered={}".format(forwarded, OFFERED_PKTS))
    finally:
        for d in duts:
            _del_rule(d, "RULE_BYTES")
            _del_policer(d, BYTES_POLICER)


def test_policer_survives_config_reload(rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter,
                                        setup_policer_table, setup_counterpoll_interval):
    """A POLICER + FORWARD/POLICER rule persisted with `config save` is re-programmed after a
    `config reload` and still polices the matched flow -- proving the POLICER_ACTION field
    round-trips through config save and a YANG-validated reload."""
    dut = rand_selected_dut
    if dut.facts["asic_type"] == "vs":
        pytest.skip("Dataplane policing is not modeled on the vs platform")
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    _, router_mac, src_idx, dst_indices = _endpoints(dut, rand_unselected_dut, tbinfo)
    pytest_assert(dst_indices, "Could not resolve any uplink PTF port for verification")
    pkt, exp = _tcp_pkt(router_mac, RELOAD_DST_IP)
    # Snapshot each DUT's persisted config so teardown restores the box to its original state.
    # The module fixtures mutate CONFIG_DB only at runtime, so this on-disk copy is pristine.
    backups = {d: "/tmp/config_db_policer_reload_{}.json".format(d.hostname) for d in duts}
    for d in duts:
        d.shell("cp /etc/sonic/config_db.json {}".format(backups[d]))
    try:
        base_pol, base_rules = get_asic_policer_count(dut), get_asic_acl_rule_count(dut)
        for d in duts:
            _add_policer(d, RELOAD_POLICER, meter_type="packets", mode="sr_tcm",
                         cir="100", cbs="100", red_packet_action="drop")
            _add_forward_policer_rule(d, "RULE_RELOAD", 9990, RELOAD_DST_IP, RELOAD_POLICER)
        _wait_programmed(dut, base_pol, 1, base_rules, 1, "reload rule before save")
        before = _forwarded(ptfadapter, pkt, exp, src_idx, dst_indices)
        pytest_assert(before < OFFERED_PKTS * 0.5,
                      "flow must be policed before reload: forwarded={} offered={}".format(
                          before, OFFERED_PKTS))
        # Persist the running config (custom table + POLICER + POLICER_ACTION rule, DATAACL
        # already removed at runtime) and reload from it.
        for d in duts:
            d.shell("config save -y")
            config_reload(d, config_source="config_db", safe_reload=True, wait_for_bgp=True)
        # counterpoll interval is not part of config_db.json; re-apply the fast interval.
        for d in duts:
            d.shell("counterpoll acl interval 1000")
        time.sleep(10)
        # The persisted POLICER and rule must be re-programmed after the reload...
        pytest_assert(
            wait_until(60, 3, 0,
                       lambda: get_asic_policer_count(dut) >= base_pol + 1
                       and get_asic_acl_rule_count(dut) >= base_rules + 1),
            "the POLICER and POLICER_ACTION rule must survive config reload and be re-programmed")
        # ...and still police the same flow.
        after = _forwarded(ptfadapter, pkt, exp, src_idx, dst_indices)
        pytest_assert(after < OFFERED_PKTS * 0.5,
                      "the flow must still be policed after config reload: "
                      "forwarded={} offered={}".format(after, OFFERED_PKTS))
    finally:
        for d in duts:
            # Restore the original persisted config and reload back to the pristine baseline
            # (this drops the test POLICER, rule and custom table in one shot).
            d.shell("cp {} /etc/sonic/config_db.json".format(backups[d]))
            config_reload(d, config_source="config_db", safe_reload=True, wait_for_bgp=True)
            d.shell("rm -f {}".format(backups[d]))
            # The restored config re-adds DATAACL; drop it again so the module-scoped
            # remove_dataacl_table invariant (free TCAM) holds for any later test.
            d.shell("config acl remove table DATAACL")


def test_policer_bound_cannot_delete(rand_selected_dut, rand_unselected_dut, tbinfo,
                                     setup_policer_table, setup_counterpoll_interval):
    """A POLICER referenced by an active POLICER_ACTION rule is ref-held: deleting the POLICER
    while it is bound must NOT remove the SAI policer object; it is freed only once the rule
    that references it is removed (swss PolicerOrch ref-count guard)."""
    dut = rand_selected_dut
    if dut.facts["asic_type"] == "vs":
        pytest.skip("Policer object lifecycle is not modeled on the vs platform")
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    before = _policer_oids(dut)
    try:
        for d in duts:
            _add_policer(d, BOUND_POLICER, meter_type="packets", mode="sr_tcm",
                         cir="100", cbs="100", red_packet_action="drop")
            _add_forward_policer_rule(d, "RULE_BOUND", 9990, BOUND_DST_IP, BOUND_POLICER)
        _wait_rules_active(dut, ["RULE_BOUND"])
        pol_oid = next(iter(_policer_oids(dut) - before))
        # Delete the POLICER from CONFIG_DB while the rule still references it.
        for d in duts:
            _del_policer(d, BOUND_POLICER)
        # The bound policer must NOT be freed: its SAI object stays for the whole poll window.
        pytest_assert(
            not wait_until(15, 3, 0, lambda: pol_oid not in _policer_oids(dut)),
            "a POLICER bound by an active ACL rule must not be deleted from the ASIC")
        # Remove the referencing rule; the deferred policer deletion can now complete.
        for d in duts:
            _del_rule(d, "RULE_BOUND")
        pytest_assert(
            wait_until(20, 3, 0, lambda: pol_oid not in _policer_oids(dut)),
            "once the referencing rule is removed the policer must be freed from the ASIC")
    finally:
        for d in duts:
            _del_rule(d, "RULE_BOUND")
            _del_policer(d, BOUND_POLICER)
