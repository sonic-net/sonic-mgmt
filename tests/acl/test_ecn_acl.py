import pytest
import time
import json
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.ptf_runner import ptf_runner
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('t0', 't1', 't2')]

ACL_TABLE_NAME = "ECN_TEST"
ACL_TABLE_TYPE = "ECN_TEST_TYPE"
ACL_RULE_NAME = "MARK_UDP_5000"
UDP_SPORT = 5000
UDP_DPORT = 6000


def _discover_uplinks(duthost, tbinfo):
    """Pick two routed physical ports (same IP family) with reachable neighbors.

    Topology/platform-agnostic: derives everything from minigraph facts instead
    of hard-coding port names or neighbor IPs, so the test fits any topo. IPv4
    is preferred when available, otherwise IPv6.
    Returns (ip_version, ingress_dict, egress_dict) where each dict has
    port / peer / ptf_idx.
    """
    mg = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_idx = mg['minigraph_ptf_indices']
    cand = {'ipv4': [], 'ipv6': []}
    for intf in mg.get('minigraph_interfaces', []):
        port = intf.get('attachto')
        addr = str(intf.get('addr', ''))
        peer = intf.get('peer_addr')
        if not port or not peer or port not in ptf_idx:
            continue
        fam = 'ipv6' if ':' in addr else 'ipv4'
        if any(c['port'] == port for c in cand[fam]):
            continue
        cand[fam].append({'port': port, 'peer': str(peer), 'ptf_idx': ptf_idx[port]})
    for fam in ('ipv4', 'ipv6'):
        if len(cand[fam]) >= 2:
            logger.info("ECN DP using %s uplinks: ingress=%s egress=%s",
                        fam, cand[fam][0], cand[fam][1])
            return fam, cand[fam][0], cand[fam][1]
    pytest.skip("No two routed uplink ports with neighbors found for ECN DP test")
    return None


@pytest.fixture(scope="module")
def setup_ecn(duthosts, rand_one_dut_hostname, ptfhost, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    fam, ing, egr = _discover_uplinks(duthost, tbinfo)
    router_mac = duthost.facts['router_mac']
    ip_match = "SRC_IPV6" if fam == 'ipv6' else "SRC_IP"

    # Use a custom ACL table type that explicitly declares the ECN action.
    # This works on every platform, including those where the built-in L3
    # table action list is mandatory at creation (e.g. Broadcom); COUNTER is
    # included because a per-rule counter is created by default.
    cfg = {
        "ACL_TABLE_TYPE": {
            ACL_TABLE_TYPE: {
                "MATCHES": [ip_match, "L4_SRC_PORT"],
                "ACTIONS": ["PACKET_ACTION", "ECN_ACTION", "COUNTER"],
                "BIND_POINTS": ["PORT"],
            }
        },
        "ACL_TABLE": {
            ACL_TABLE_NAME: {
                "policy_desc": "ECN marking test",
                "type": ACL_TABLE_TYPE,
                "stage": "ingress",
                "ports": [ing['port']],
            }
        },
        "ACL_RULE": {
            "{}|{}".format(ACL_TABLE_NAME, ACL_RULE_NAME): {
                "PRIORITY": "9990",
                "L4_SRC_PORT": str(UDP_SPORT),
                "ECN_ACTION": "3",
            }
        },
    }
    duthost.copy(content=json.dumps(cfg), dest="/tmp/ecn_acl.json")
    duthost.shell("sudo sonic-cfggen -j /tmp/ecn_acl.json --write-to-db")
    time.sleep(3)

    yield {
        "duthost": duthost,
        "ip_version": fam,
        "router_mac": router_mac,
        "src_idx": ing['ptf_idx'],
        "dst_idx": egr['ptf_idx'],
        "src_ip": ing['peer'],   # ingress neighbor -> uRPF-friendly source
        "dst_ip": egr['peer'],   # egress neighbor  -> deterministic egress port
    }

    duthost.shell("redis-cli -n 4 DEL 'ACL_RULE|{}|{}'".format(ACL_TABLE_NAME, ACL_RULE_NAME),
                  module_ignore_errors=True)
    duthost.shell("redis-cli -n 4 DEL 'ACL_TABLE|{}'".format(ACL_TABLE_NAME),
                  module_ignore_errors=True)
    duthost.shell("redis-cli -n 4 DEL 'ACL_TABLE_TYPE|{}'".format(ACL_TABLE_TYPE),
                  module_ignore_errors=True)
    duthost.shell("rm -f /tmp/ecn_acl.json", module_ignore_errors=True)


def test_ecn_acl_control_plane(setup_ecn):
    duthost = setup_ecn['duthost']
    out = duthost.shell("show acl rule {} {}".format(ACL_TABLE_NAME, ACL_RULE_NAME))['stdout']
    logger.info("show acl rule:\n%s", out)
    # ECN_ACTION must render as "ECN: <val>" under Action (acl_loader fix), not
    # leak as the raw key, and the rule must be programmed to hardware (Active).
    pytest_assert("ECN: 3" in out, "ECN action not shown under Action column: %s" % out)
    pytest_assert("ECN_ACTION" not in out, "raw ECN_ACTION key leaked into display: %s" % out)
    pytest_assert("Active" in out, "ECN rule not Active (ASIC not programmed): %s" % out)


def test_ecn_acl_data_plane(ptfhost, setup_ecn):
    params = {
        'ip_version': setup_ecn['ip_version'],
        'src_port': setup_ecn['src_idx'],
        'dst_port': setup_ecn['dst_idx'],
        'router_mac': setup_ecn['router_mac'],
        'src_ip': setup_ecn['src_ip'],
        'dst_ip': setup_ecn['dst_ip'],
        'udp_sport': UDP_SPORT,
        'udp_dport': UDP_DPORT,
    }
    logger.info("PTF params: %s", params)
    ptf_runner(
        ptfhost,
        "ptftests",
        "ecn_acl_ptftest.ECNMarkingTest",
        platform_dir="ptftests",
        params=params,
        log_file="/tmp/ecn_acl_ptftest.log")
