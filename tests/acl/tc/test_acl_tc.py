"""
Data-plane and ASIC-DB tests for the TC_ACTION (SAI_ACL_ENTRY_ATTR_ACTION_SET_TC) ACL rule action.

TC_ACTION sets the internal traffic class (0..255, an sai_uint8_t) of matched packets, steering
them to the egress queue mapped from that TC (the default TC->queue map is identity). It is a
composable/additive QoS action: it accompanies a forwarding action (e.g. FORWARD) on the same
rule rather than being exclusive (AclRulePacket::validate excludes SET_TC from its single
exclusive-action check), and must be advertised in a custom ACL_TABLE_TYPE's
ACTIONS (the built-in L3/L3V6 types do not include it), so these tests define a custom TC_L3
table type that matches both IPv4 and IPv6 traffic.

Covered:
  * programmed (test_acl_tc_action_programmed, ipv4/ipv6): a FORWARD + TC_ACTION rule becomes
    Active in STATE_DB and the ASIC_DB ACL entry carries SAI_ACL_ENTRY_ATTR_ACTION_SET_TC=<tc>.
  * invalid rejected (test_acl_tc_action_invalid_rejected): a rule with an out-of-range (256) or
    non-numeric (ABC) TC value is rejected by AclOrch and never becomes Active.
  * dataplane (test_acl_tc_action_dataplane, ipv4/ipv6): matched traffic egresses on the queue
    mapped from the configured TC (UC<tc>), while an unmatched control flow does not.
"""
import json
import logging
import time

import pytest

from ptf.mask import Mask
import ptf.packet as scapy
import ptf.testutils as testutils

from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.utilities import wait_until, is_ipv6_only_topology

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),        # custom ACL table type is exercised on t0
    pytest.mark.disable_loganalyzer,   # invalid-value rules log ERROR by design; assert explicitly
]

BASE_DIR = "acl/tc"
TABLE_TYPE_SRC = BASE_DIR + "/tc_acl_table.json"
TABLE_TYPE_DST = "/tmp/tc_acl_table.json"
RULES_SRC = BASE_DIR + "/tc_acl_rules.json"
RULES_DST = "/tmp/tc_acl_rules.json"

TABLE_NAME = "TC_TABLE"
TABLE_TYPE_NAME = "TC_L3"

TC_RULE = "RULE_TC"
TC_RULE_V6 = "RULE_TC_V6"
TC_VAL = 3                       # configured traffic class -> egress queue UC3

TC_DST_IP = "103.23.2.1"         # matched by RULE_TC (see tc_acl_rules.json)
TC_DST_IPV6 = "103:23:2:1::1"    # matched by RULE_TC_V6
CTRL_DST_IP = "103.23.2.20"      # routed to uplink but matched by no rule (keeps its default TC)
CTRL_DST_IPV6 = "103:23:2:20::1"  # IPv6 control flow (matched by no rule)
OFFERED_PKTS = 1000

LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
STATE_ACL_RULE_TABLE = "ACL_RULE_TABLE"


def _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo):
    """DUTs that must receive config: both ToRs on dualtor-aa, else the selected DUT."""
    if "dualtor-aa" in tbinfo["topo"]["name"] and rand_unselected_dut is not None:
        return [rand_selected_dut, rand_unselected_dut]
    return [rand_selected_dut]


def _acl_ingress_action_list(dut):
    """Advertised ingress ACL actions (STATE_DB ACL_STAGE_CAPABILITY_TABLE), for capability gating.
    Empty list when the platform publishes no capability (callers then fall through to a runtime
    probe on rule programming instead of gating on the static list)."""
    out = dut.shell("sonic-db-cli STATE_DB hget 'ACL_STAGE_CAPABILITY_TABLE|INGRESS' action_list",
                    module_ignore_errors=True)["stdout"].strip()
    return [a.strip() for a in out.split(",") if a.strip()]


def _skip_if_tc_unsupported(dut):
    """Skip only when the platform explicitly advertises its ingress actions and TC_ACTION is not
    among them. If nothing is advertised, proceed and let rule programming be the probe."""
    actions = _acl_ingress_action_list(dut)
    if actions and "TC_ACTION" not in actions:
        pytest.skip("Platform does not advertise TC_ACTION at ingress: {}".format(actions))


def _acl_rule_status(dut, rule, table=TABLE_NAME):
    """STATE_DB programming status of an ACL rule as published by AclOrch: 'Active' once fully
    programmed, 'Pending creation' while deferred, '' when absent."""
    return dut.shell("sonic-db-cli STATE_DB hget '{}|{}|{}' status".format(
        STATE_ACL_RULE_TABLE, table, rule), module_ignore_errors=True)["stdout"].strip()


def _wait_rules_active(dut, rules, table=TABLE_NAME, timeout=30):
    """Wait until every named rule is Active in STATE_DB."""
    ok = wait_until(timeout, 2, 0,
                    lambda: all(_acl_rule_status(dut, r, table) == "Active" for r in rules))
    pytest_assert(ok, "ACL rules {} did not become Active in STATE_DB (statuses: {})".format(
        list(rules), {r: _acl_rule_status(dut, r, table) for r in rules}))


def _asic_acl_entry_keys(dut):
    """ASIC_DB keys of the SAI ACL entries currently programmed."""
    out = dut.shell('sonic-db-cli ASIC_DB keys "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:*"')["stdout"]
    return [line.strip() for line in out.splitlines() if line.strip()]


def _acl_entry_tc_present(dut, tc_val):
    """True if some ASIC_DB ACL entry carries SAI_ACL_ENTRY_ATTR_ACTION_SET_TC with tc_val.
    The u8 action parameter is serialized by syncd as its decimal value (e.g. '3'); match on the
    value containing str(tc_val) to stay robust to any enable/parameter wrapping across vendors."""
    for key in _asic_acl_entry_keys(dut):
        val = dut.shell(
            "sonic-db-cli ASIC_DB hget '{}' SAI_ACL_ENTRY_ATTR_ACTION_SET_TC".format(key),
            module_ignore_errors=True)["stdout"].strip()
        if val and str(tc_val) in val:
            return True
    return False


def _uplink_ptf_indices(dut, tbinfo, mg_facts, mg_unselected=None):
    """PTF indices of the upstream (uplink) ports the matched traffic egresses on."""
    dst = []
    for _, pc in mg_facts["minigraph_portchannels"].items():
        for member in pc["members"]:
            dst.append(mg_facts["minigraph_ptf_indices"][member])
            if mg_unselected is not None:
                dst.append(mg_unselected["minigraph_ptf_indices"][member])
    return dst


def _uplink_dut_ports(mg_facts):
    """DUT-side uplink PortChannel member port names -- the egress ports whose per-queue
    counters are read to confirm the TC-mapped queue placement."""
    ports = []
    for _, pc in mg_facts["minigraph_portchannels"].items():
        ports.extend(pc.get("members", []))
    return ports


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


def _tcp_pkt(router_mac, dst_ip, ip_version="ipv4"):
    """Return (pkt, exp_mask) for a TCP packet to dst_ip for the given IP version."""
    if ip_version == "ipv6":
        pkt = testutils.simple_tcpv6_packet(eth_dst=router_mac, ipv6_src="fc02:1000::3",
                                            ipv6_dst=dst_ip, tcp_sport=8888, tcp_dport=9999)
        exp = Mask(pkt)
        exp.set_do_not_care_scapy(scapy.Ether, "dst")
        exp.set_do_not_care_scapy(scapy.Ether, "src")
        exp.set_do_not_care_scapy(scapy.IPv6, "hlim")
    else:
        pkt = testutils.simple_tcp_packet(eth_dst=router_mac, ip_src="192.168.0.3",
                                          ip_dst=dst_ip, tcp_sport=8888, tcp_dport=9999)
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


def _sum_uc_queue(dut, ports, queue):
    """Sum the UC<queue> transmitted-packet counter (`show queue counters <port>`) across ports."""
    txq = "UC{}".format(queue)
    total = 0
    for port in ports:
        output = dut.shell("show queue counters {}".format(port))["stdout_lines"]
        for line in output:
            fields = line.split()
            if len(fields) >= 3 and fields[0] == port and fields[1] == txq:
                count = fields[2].replace(",", "")
                # A freshly polled queue can render 'N/A' before its first sample; treat as 0.
                total += int(count) if count.isdigit() else 0
    return total


@pytest.fixture(scope="module", autouse=True)
def remove_dataacl_table(rand_selected_dut, rand_unselected_dut, tbinfo):
    """Remove DATAACL to free TCAM for the custom TC table, then restore it."""
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    table = "DATAACL"
    saved = None
    output = rand_selected_dut.shell('sonic-cfggen -d --var-json "ACL_TABLE"')["stdout"]
    try:
        tables = json.loads(output)
        if table in tables:
            saved = {table: tables[table]}
    except ValueError:
        # sonic-cfggen produced no parseable ACL_TABLE JSON (e.g. an empty config): nothing to
        # save, so leave saved = None and skip the remove/restore handled below.
        saved = None
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
def setup_tc_table(rand_selected_dut, rand_unselected_dut, tbinfo):
    """Load the custom TC_L3 table type and create an ingress table bound to the downstream
    Vlan member ports (a custom ACL table type binds to PORT/PORTCHANNEL)."""
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    # Skip cleanly BEFORE creating the table: a platform that doesn't support SET_TC may reject a
    # TC_ACTION table at creation, which would fail this fixture rather than skip the test.
    _skip_if_tc_unsupported(rand_selected_dut)
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    bind_ports = ",".join(list(mg_facts["minigraph_vlans"].values())[0]["members"])
    for dut in duts:
        dut.copy(src=TABLE_TYPE_SRC, dest=TABLE_TYPE_DST)
        dut.shell("sonic-cfggen -j {} -w".format(TABLE_TYPE_DST))

    loganalyzer = LogAnalyzer(ansible_host=rand_selected_dut, marker_prefix="acl_tc")
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


@pytest.fixture(scope="function")
def setup_tc_rules(rand_selected_dut, rand_unselected_dut, tbinfo, setup_tc_table):
    """Load the FORWARD + TC_ACTION compose rules (v4 and v6)."""
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    for dut in duts:
        dut.copy(src=RULES_SRC, dest=RULES_DST)
        dut.shell("sonic-cfggen -j {} -w".format(RULES_DST))
    yield
    for dut in duts:
        dut.shell("acl-loader delete {}".format(TABLE_NAME))


@pytest.fixture(scope="module")
def setup_counterpoll(rand_selected_dut, rand_unselected_dut, tbinfo):
    """Poll ACL and queue counters every 1s (10s by default) so counts settle quickly."""
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)
    for dut in duts:
        dut.shell("counterpoll acl interval 1000")
        dut.shell("counterpoll queue enable", module_ignore_errors=True)
        dut.shell("counterpoll queue interval 1000", module_ignore_errors=True)
    time.sleep(5)
    yield
    for dut in duts:
        dut.shell("counterpoll acl interval 10000")
        dut.shell("counterpoll queue interval 10000", module_ignore_errors=True)


@pytest.mark.parametrize("ip_version", ["ipv4", "ipv6"])
def test_acl_tc_action_programmed(rand_selected_dut, rand_unselected_dut, tbinfo,
                                  ip_version, setup_tc_rules):
    """A FORWARD + TC_ACTION rule becomes Active and the ASIC_DB ACL entry carries
    SAI_ACL_ENTRY_ATTR_ACTION_SET_TC set to the configured traffic class."""
    dut = rand_selected_dut
    if ip_version == "ipv4" and is_ipv6_only_topology(tbinfo):
        pytest.skip("IPv4 rule is not applicable on an IPv6-only topology")

    rule = TC_RULE if ip_version == "ipv4" else TC_RULE_V6
    _wait_rules_active(dut, [rule])
    pytest_assert(
        _acl_entry_tc_present(dut, TC_VAL),
        "no ASIC_DB ACL entry carries SAI_ACL_ENTRY_ATTR_ACTION_SET_TC={}".format(TC_VAL))


def test_acl_tc_action_invalid_rejected(rand_selected_dut, rand_unselected_dut, tbinfo,
                                        setup_tc_table):
    """A rule with an out-of-range (256) or non-numeric (ABC) TC value is rejected by AclOrch and
    never becomes Active (AclRulePacket::validateAddAction parses TC as sai_uint8_t)."""
    dut = rand_selected_dut
    duts = _config_duts(rand_selected_dut, rand_unselected_dut, tbinfo)

    bad = {"RULE_TC_BADVAL": "256", "RULE_TC_BADSTR": "ABC"}
    try:
        for rule, tc in bad.items():
            for d in duts:
                key = "ACL_RULE|{}|{}".format(TABLE_NAME, rule)
                d.shell("sonic-db-cli CONFIG_DB hset '{}' PRIORITY 9990 DST_IP {}/32 "
                        "IP_PROTOCOL 6 PACKET_ACTION FORWARD TC_ACTION {}".format(
                            key, CTRL_DST_IP, tc))
        for rule in bad:
            pytest_assert(
                not wait_until(10, 2, 0, lambda r=rule: _acl_rule_status(dut, r) == "Active"),
                "rule {} with an invalid TC value must be rejected (never Active)".format(rule))
    finally:
        for rule in bad:
            for d in duts:
                d.shell("sonic-db-cli CONFIG_DB del 'ACL_RULE|{}|{}'".format(TABLE_NAME, rule))


@pytest.mark.parametrize("ip_version", ["ipv4", "ipv6"])
def test_acl_tc_action_dataplane(rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter,
                                 ip_version, setup_tc_rules, setup_counterpoll):
    """Matched traffic (FORWARD + TC_ACTION=TC_VAL) egresses on the TC-mapped queue (UC<TC_VAL>),
    while an unmatched control flow (its default TC) does not use that queue."""
    dut = rand_selected_dut
    if dut.facts["asic_type"] == "vs":
        pytest.skip("Queue scheduling is not modeled on the vs platform")
    if ip_version == "ipv4" and is_ipv6_only_topology(tbinfo):
        pytest.skip("IPv4 rule is not applicable on an IPv6-only topology")

    mg_facts, router_mac, src_idx, dst_indices = _endpoints(dut, rand_unselected_dut, tbinfo)
    pytest_assert(dst_indices, "Could not resolve any uplink PTF port for verification")
    egress_ports = _uplink_dut_ports(mg_facts)
    pytest_assert(egress_ports, "Could not resolve any uplink DUT egress port for queue counters")

    rule = TC_RULE if ip_version == "ipv4" else TC_RULE_V6
    _wait_rules_active(dut, [rule])

    dst_ip = TC_DST_IP if ip_version == "ipv4" else TC_DST_IPV6
    ctrl_ip = CTRL_DST_IP if ip_version == "ipv4" else CTRL_DST_IPV6
    match_pkt, match_exp = _tcp_pkt(router_mac, dst_ip, ip_version)
    ctrl_pkt, ctrl_exp = _tcp_pkt(router_mac, ctrl_ip, ip_version)

    # Matched flow: must be forwarded AND land on the TC-mapped queue UC<TC_VAL>. Poll the queue
    # counter (counterpoll refreshes on an interval) rather than reading once after a fixed delay.
    dut.shell("sonic-clear queuecounters")
    time.sleep(2)
    forwarded = _forwarded(ptfadapter, match_pkt, match_exp, src_idx, dst_indices)
    pytest_assert(forwarded > 0, "matched FORWARD + TC rule did not forward any packet")
    wait_until(20, 3, 2, lambda: _sum_uc_queue(dut, egress_ports, TC_VAL) >= forwarded * 0.9)
    tc_q_match = _sum_uc_queue(dut, egress_ports, TC_VAL)
    logger.info("tc dataplane [%s]: forwarded=%d UC%d(after match)=%d",
                ip_version, forwarded, TC_VAL, tc_q_match)
    pytest_assert(
        tc_q_match >= forwarded * 0.9,
        "matched traffic must egress on the TC-mapped queue UC{}: UC{}={} forwarded={}".format(
            TC_VAL, TC_VAL, tc_q_match, forwarded))

    # Control flow (matched by no rule -> keeps its default TC): must NOT use UC<TC_VAL>.
    dut.shell("sonic-clear queuecounters")
    time.sleep(2)
    ctrl_fwd = _forwarded(ptfadapter, ctrl_pkt, ctrl_exp, src_idx, dst_indices)
    time.sleep(8)  # allow at least one counterpoll cycle so any UC<TC_VAL> usage would surface
    tc_q_ctrl = _sum_uc_queue(dut, egress_ports, TC_VAL)
    logger.info("tc dataplane [%s]: ctrl_forwarded=%d UC%d(after ctrl)=%d",
                ip_version, ctrl_fwd, TC_VAL, tc_q_ctrl)
    pytest_assert(
        tc_q_ctrl <= max(10, ctrl_fwd * 0.1),
        "unmatched control flow must not use the TC-mapped queue UC{}: UC{}={} ctrl_forwarded={}".format(
            TC_VAL, TC_VAL, tc_q_ctrl, ctrl_fwd))
