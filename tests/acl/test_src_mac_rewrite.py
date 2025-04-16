"""
Tests Acl to modify inner src mac to ENI mac in SONiC.
"""

import os
import time
import logging
import pytest
import ptf.testutils as testutils
from ptf import mask
import ptf.packet as scapy
from scapy.all import Ether
from collections import defaultdict
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
]

DEFAULT_VNI = 1000
ACL_COUNTERS_UPDATE_INTERVAL = 10
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
ACL_REMOVE_RULES_FILE = "acl_rules_del.json"
ACL_ADD_RULES_FILE = "acltb_test_rules_srcmac_rewrite.j2"
ACL_RULES_FILE = 'acl_config.json'
TMP_DIR = '/tmp'
ACTION_FORWARD = 'FORWARD'
ACTION_DROP = 'DROP'
INGRESS = 'ingress'
EGRESS = 'egress'
IPV4 = 'ipv4'
IPV6 = 'ipv6'

ACL_TABLE_NAME = "INNER_SRC_MAC_REWRITE_TABLE"
ACL_TABLE_TYPE = "INNER_SRC_MAC_REWRITE_TYPE"

LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
LOG_EXPECT_ACL_TABLE_REMOVE_RE = ".*Successfully deleted ACL table.*"


def check_rule_counters(duthost):
    """
    Check if Acl rule counters initialized

    Args:
        duthost: DUT host object
    Returns:
        Bool value
    """
    res = duthost.shell("aclshow -a")['stdout_lines']
    if len(res) <= 2 or [line for line in res if 'N/A' in line]:
        return False
    else:
        return True


def get_acl_counter(duthost, table_name, rule_name, timeout=ACL_COUNTERS_UPDATE_INTERVAL):
    """
    Get ACL counter packets value.

    Args:
        duthost: DUT host object
        table_name: ACL Table name
        rule_name: ACL rule name
        timeout: Timeout for ACL counters to update

    Returns:
        ACL counter value for packets as int, or 0 if not available
    """
    # Wait for orchagent to update the ACL counters
    time.sleep(timeout)
    result = duthost.show_and_parse('aclshow -a')

    if not result:
        pytest.fail("Failed to retrieve ACL counter for {}|{}".format(table_name, rule_name))

    for rule in result:
        if table_name == rule.get('table name') and rule_name == rule.get('rule name'):
            pkt_count = rule.get('packets count', '0')
            try:
                return int(pkt_count)
            except ValueError:
                logger.warning(f"ACL counter for {table_name}|{rule_name} is not an integer: '{pkt_count}', returning 0")
                return 0

    pytest.fail("ACL rule {} not found in table {}".format(rule_name, table_name))


@pytest.fixture(scope='module')
def prepare_test_port(rand_selected_dut, tbinfo):
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)

    ports = list(mg_facts['minigraph_portchannels'])
    if not ports:
        ports = mg_facts["minigraph_acls"]["DataAcl"]

    dut_port = ports[0] if ports else None

    if not dut_port:
        pytest.skip('No portchannels nor dataacl ports found')
    if "Ethernet" in dut_port:
        dut_eth_port = dut_port
    elif "PortChannel" in dut_port:
        dut_eth_port = mg_facts["minigraph_portchannels"][dut_port]["members"][0]
    ptf_src_port = mg_facts["minigraph_ptf_indices"][dut_eth_port]

    topo = tbinfo["topo"]["type"]
    # Get the list of upstream ports
    upstream_ports = defaultdict(list)
    upstream_port_ids = []
    for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        if (topo == "t0" and "T1" in neighbor["name"]):
            upstream_ports[neighbor['namespace']].append(interface)
            upstream_port_ids.append(port_id)

    return ptf_src_port, upstream_port_ids, dut_port


def setup_acl_table(duthost, prepare_test_port):
    table_name = ACL_TABLE_NAME
    _, _, dut_port = prepare_test_port

    cmd = "config acl add table {} {} -s {} -p {}".format(
            ACL_TABLE_NAME,
            ACL_TABLE_TYPE,
            "egress",
            dut_port
        )
    
    logger.info("Creating ACL table {} for testing".format(table_name))
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="TestAclSrcMacRewrite")
    loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_CREATE_RE]
    try:
        with loganalyzer:
            duthost.shell(cmd)
    except LogAnalyzerError:
        # Todo: cleanup
        pytest.fail("Failed to create ACL table {}".format(table_name))


def remove_acl_table(duthost):
    table_name = ACL_TABLE_NAME
    cmd = "config acl remove table {}".format(table_name)

    logger.info("Removing ACL table {}".format(table_name))
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="TestAclSrcMacRewrite")
    loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_REMOVE_RE]

    try:
        with loganalyzer:
            duthost.shell(cmd)
    except LogAnalyzerError:
        # Todo: cleanup
        pytest.fail("Failed to remove ACL table {}".format(table_name))   


def setup_acl_rules(duthost, inner_src_ip, vni, action, new_src_mac):
    table_name = ACL_TABLE_NAME

    extra_vars = {
        'table_name': table_name,
        'vni': vni,
        'inner_src_ip': inner_src_ip,
        'action': action,
        'new_src_mac': new_src_mac
        }
    dest_path = os.path.join(TMP_DIR, ACL_RULES_FILE)
    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)
    duthost.file(path=dest_path, state='absent')
    duthost.template(src=os.path.join(TEMPLATES_DIR, ACL_ADD_RULES_FILE), dest=dest_path)
    logger.info("Creating ACL rule matching src_ip {} action {}".format(inner_src_ip, action))
    duthost.shell("config load -y {}".format(dest_path))

    if duthost.facts['asic_type'] != 'vs':
        pytest_assert(wait_until(60, 2, 0, check_rule_counters, duthost), "Acl rule counters are not ready")


def remove_acl_rules(self, duthost):
    table_name = ACL_TABLE_NAME
    duthost.copy(src=os.path.join(FILES_DIR, ACL_REMOVE_RULES_FILE), dest=TMP_DIR)
    remove_rules_dut_path = os.path.join(TMP_DIR, ACL_REMOVE_RULES_FILE)
    duthost.command("acl-loader update full {} --table_name {}".format(remove_rules_dut_path, table_name))
    time.sleep(5)


def test_modify_inner_src_mac_egress(duthost, ptfadapter, prepare_test_port):
    # Define test parameters
    inner_dst_ip = "192.168.0.2"
    inner_src_ip = "192.168.0.1"
    vni_id = 5000
    original_inner_src_mac = "00:66:77:88:99:aa"
    modified_inner_src_mac = "00:11:22:33:44:55"
    outer_src_mac = "00:11:22:33:44:66"
    outer_dst_mac = duthost.facts['router_mac']    # MAC address should be router_mac rather than ptf mac
    outer_src_ip = "10.1.1.1"
    outer_dst_ip = "20.1.1.1"
    table_name = ACL_TABLE_NAME
    RULE_1 = 'rule_1'

    ptf_src_port, ptf_dst_ports, dut_port = prepare_test_port

    setup_acl_rules(duthost, inner_src_ip, vni_id, ACTION_FORWARD, modified_inner_src_mac)
    # Create VXLAN-encapsulated packet sent by server
    inner_pkt = testutils.simple_udp_packet(
            eth_dst=duthost.facts['router_mac'],
            eth_src=original_inner_src_mac,
            ip_src=inner_src_ip,
            ip_dst=inner_dst_ip,
            ip_id=0,
            ip_ihl=5,
            udp_sport=1234,
            udp_dport=4321,
            ip_ttl=121)
    pkt = testutils.simple_vxlan_packet(
        eth_dst=outer_dst_mac,
        eth_src=outer_src_mac,
        ip_src=outer_src_ip,
        ip_dst=outer_dst_ip,
        udp_sport=1234,
        udp_dport=4789,
        vxlan_vni=vni_id,
        inner_frame=inner_pkt
    )

    expected_pkt = mask.Mask(pkt)

    # Mask outer Ethernet
    expected_pkt.set_do_not_care_scapy(Ether, 'dst')
    expected_pkt.set_do_not_care_scapy(Ether, 'src')

    count_before = get_acl_counter(duthost, table_name, RULE_1, timeout=0)
    # Send packet from server into the DUT
    testutils.send(ptfadapter, ptf_src_port, pkt)
    time.sleep(2)
    result = testutils.dp_poll(ptfadapter, exp_pkt=expected_pkt, port_number=ptf_src_port, timeout=2)
    count_after = get_acl_counter(duthost, table_name, RULE_1)

    logger.info("Verify Acl counter incremented {} > {}".format(count_after, count_before))
    pytest_assert(count_after >= count_before + 1,
                  "Unexpected results, counter_after {} > counter_before {}"
                  .format(count_after, count_before))
    
    # Check and extract inner source MAC
    if result:
        actual_pkt = scapy.Ether(result.packet)

        # Get the second Ethernet header (inner Ethernet)
        inner_eth = actual_pkt.getlayer(scapy.Ether, 1)
        inner_src_mac = inner_eth.src if inner_eth else None

        print(f"Inner source MAC: {inner_src_mac}")

        assert inner_src_mac == modified_inner_src_mac, f"Expected {modified_inner_src_mac},got {inner_src_mac}"
    else:
        assert False, "No packet received on port 0"

    # Verify ACL counter incremented, confirming rule was applied
    result = duthost.shell("show acl counter TEST_TABLE RULE_MODIFY_INNER_SRC_MAC")
    assert "1" in result['stdout'], "ACL counter not incremented as expected"
    remove_acl_rules(duthost)
    remove_acl_table(duthost)
