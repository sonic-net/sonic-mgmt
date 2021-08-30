import ipaddress
import logging
import random
import pytest
import os
import time
import json

from ptf.mask import Mask
import ptf.packet as scapy

from tests.common.fixtures.ptfhost_utils import remove_ip_addresses # lgtm[py/unused-import]
import ptf.testutils as testutils
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
]

LOG_ERROR_INSUFFICIENT_RESOURCES = ".*SAI_STATUS_INSUFFICIENT_RESOURCES.*"

ACL_JSON_FILE_SRC = "acl/null_route/acl.json"
ACL_JSON_FILE_DEST = "/host/" + os.path.basename(ACL_JSON_FILE_SRC)

ACL_TABLE_NAME_V4 = "NULL_ROUTE_ACL_TABLE_V4"
ACL_TABLE_NAME_V6 = "NULL_ROUTE_ACL_TABLE_V6"

NULL_ROUTE_HELPER = "null_route_helper"

DST_IP = {
    4: "192.168.0.2",
    6: "fc02:1000::2"
}

FORWARD = "FORWARD"
DROP = "DROP"

TEST_DATA = [
    # src_ip, action, expected_result
    ("1.2.3.4", "", FORWARD), # Should be forwared in default
    ("fc03:1001::1", "", FORWARD), # Should be forwared in default

    ("1.2.3.4", "block {} 1.2.3.4".format(ACL_TABLE_NAME_V4), DROP), # Verify block ipv4 without prefix len
    ("1.2.3.4", "unblock {} 1.2.3.4/32".format(ACL_TABLE_NAME_V4), FORWARD), # Verify unblock ipv4 with prefix len
    ("1.2.3.4", "block {} 1.2.3.4/32".format(ACL_TABLE_NAME_V4), DROP), # Verify block ipv4 with prefix len
    ("1.2.3.4", "block {} 1.2.3.4/32".format(ACL_TABLE_NAME_V4), DROP), # Verify double-block dosen't cause issue
    ("1.2.3.4", "unblock {} 1.2.3.4/32".format(ACL_TABLE_NAME_V4), FORWARD), # Verify unblock ipv4 with prefix len
    ("1.2.3.4", "unblock {} 1.2.3.4/32".format(ACL_TABLE_NAME_V4), FORWARD), # Verify double-unblock doesn't cause issue

    ("fc03:1000::1", "block {} fc03:1000::1".format(ACL_TABLE_NAME_V6), DROP), # Verify block ipv6 without prefix len
    ("fc03:1000::1", "unblock {} fc03:1000::1/128".format(ACL_TABLE_NAME_V6), FORWARD), # Verify unblock ipv6 with prefix len
    ("fc03:1000::1", "block {} fc03:1000::1/128".format(ACL_TABLE_NAME_V6), DROP), # Verify block ipv6 with prefix len
    ("fc03:1000::1", "block {} fc03:1000::1/128".format(ACL_TABLE_NAME_V6), DROP), # Verify double-block dosen't cause issue
    ("fc03:1000::1", "unblock {} fc03:1000::1/128".format(ACL_TABLE_NAME_V6), FORWARD), # Verify unblock ipv4 with prefix len
    ("fc03:1000::1", "unblock {} fc03:1000::1/128".format(ACL_TABLE_NAME_V6), FORWARD), # Verify double-unblock doesn't cause issue
]


@pytest.fixture(scope="module", autouse=True)
def skip_on_dualtor_testbed(tbinfo):
    if 'dualtor' in tbinfo['topo']['name']:
        pytest.skip("Skip running on dualtor testbed")


@pytest.fixture(scope="module", autouse=True)
def remove_dataacl_table(rand_selected_dut):
    """
    Remove DATAACL to free TCAM resources
    """
    TABLE_NAME = "DATAACL"
    lines = rand_selected_dut.shell(cmd="show acl table {}".format(TABLE_NAME))['stdout_lines']
    data_acl_existing = False
    for line in lines:
        if TABLE_NAME in line:
            data_acl_existing = True
            break
    if not data_acl_existing:
        yield
        return
    # Remove DATAACL
    logger.info("Removing ACL table {}".format(TABLE_NAME))
    rand_selected_dut.shell(cmd="config acl remove table {}".format(TABLE_NAME))
    yield
    # Recover DATAACL
    config_db_json = "/etc/sonic/config_db.json"
    output = rand_selected_dut.shell("sonic-cfggen -j {} --var-json \"ACL_TABLE\"".format(config_db_json))['stdout']
    try:
        entry = json.loads(output)[TABLE_NAME]
        cmd_create_table = "config acl add table {} {} -p {} -s {}".format(TABLE_NAME, entry['type'], \
             ",".join(entry['ports']), entry['stage'])
        logger.info("Restoring ACL table {}".format(TABLE_NAME))
        rand_selected_dut.shell(cmd_create_table)
    except Exception as e:
        pytest.fail(str(e))


def remove_acl_table(duthost):
    """
    A helper function to remove ACL table for testing
    """
    cmds= [
        "config acl remove table {}".format(ACL_TABLE_NAME_V4),
        "config acl remove table {}".format(ACL_TABLE_NAME_V6)
    ]
    logger.info("Removing ACL table for testing")
    duthost.shell_cmds(cmds=cmds)


@pytest.fixture(scope="module")
def create_acl_table(rand_selected_dut, tbinfo):
    """
    Create two ACL tables on DUT for testing.
    """
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    # Get the list of LAGs
    port_channels = ",".join(mg_facts["minigraph_portchannels"].keys())
    cmds = [
        "config acl add table {} L3 -p {}".format(ACL_TABLE_NAME_V4, port_channels),
        "config acl add table {} L3V6 -p {}".format(ACL_TABLE_NAME_V6, port_channels)
    ]
    logger.info("Creating ACL table for testing")
    loganalyzer = LogAnalyzer(ansible_host=rand_selected_dut, marker_prefix="null_route_helper")
    loganalyzer.match_regex = [LOG_ERROR_INSUFFICIENT_RESOURCES]

    # Skip test case if ACL table created failed due to insufficient resources
    try:
        with loganalyzer:
            rand_selected_dut.shell_cmds(cmds=cmds)
    except LogAnalyzerError:
        skip_msg = "ACL table creation failed due to insufficient resources, test case will be skipped"
        logger.error(skip_msg)
        remove_acl_table(rand_selected_dut)
        pytest.skip(skip_msg)

    yield

    remove_acl_table(rand_selected_dut)


@pytest.fixture(scope="module")
def apply_pre_defined_rules(rand_selected_dut, create_acl_table):
    """
    This is to apply some ACL rules as production does
    """
    rand_selected_dut.copy(src=ACL_JSON_FILE_SRC, dest=ACL_JSON_FILE_DEST)
    rand_selected_dut.shell("acl-loader update full " + ACL_JSON_FILE_DEST)
    # Wait 5 seconds for ACL rule creation
    time.sleep(5)
    yield
    # Clear ACL rules
    rand_selected_dut.shell('sonic-db-cli CONFIG_DB keys "ACL_RULE|{}*" | xargs sonic-db-cli CONFIG_DB del'.format(ACL_TABLE_NAME_V4))
    rand_selected_dut.shell('sonic-db-cli CONFIG_DB keys "ACL_RULE|{}*" | xargs sonic-db-cli CONFIG_DB del'.format(ACL_TABLE_NAME_V6))


@pytest.fixture(scope="module")
def setup_ptf(rand_selected_dut, ptfhost, tbinfo):
    """
    Add ipv4 and ipv6 address to a port on ptf.
    """
    dst_ports = {}
    vlan_name = ""
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    for vlan_info in mg_facts["minigraph_vlan_interfaces"]:
        ip_ver =  ipaddress.ip_network(vlan_info['addr'], False).version
        dst_ports[ip_ver] = str(ipaddress.ip_address(vlan_info['addr']) + 1) + '/' + str(vlan_info['prefixlen'])
        vlan_name = vlan_info['attachto']

    vlan_port = mg_facts['minigraph_vlans'][vlan_name]['members'][0]
    dst_ports['port'] = mg_facts['minigraph_ptf_indices'][vlan_port]

    logger.info("Setting up ptf for testing")
    ptfhost.shell("ifconfig eth{} {}".format(dst_ports['port'], dst_ports[4]))
    ptfhost.shell("ifconfig eth{} inet6 add {}".format(dst_ports['port'], dst_ports[6]))

    yield dst_ports
    ptfhost.shell("ifconfig eth{} 0.0.0.0".format(dst_ports['port']))
    ptfhost.shell("ifconfig eth{} inet6 del {}".format(dst_ports['port'], dst_ports[6]))


def generate_packet(src_ip, dst_ip, dst_mac):
    """
    Build ipv4 and ipv6 packets/expected_packets for testing.
    """
    if ipaddress.ip_network(unicode(src_ip), False).version == 4:
        pkt = testutils.simple_ip_packet(eth_dst=dst_mac, ip_src=src_ip, ip_dst=dst_ip)
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
    else:
        pkt = testutils.simple_tcpv6_packet(eth_dst=dst_mac, ipv6_src=src_ip, ipv6_dst=dst_ip)
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")

    return pkt, exp_pkt


def send_and_verify_packet(ptfadapter, pkt, exp_pkt, tx_port, rx_port, expected_action):
    """
    Send packet with ptfadapter and verify if packet is forwarded or dropped as expected.
    """
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, pkt=pkt, port_id=tx_port)
    if expected_action == FORWARD:
        testutils.verify_packet(ptfadapter, pkt=exp_pkt, port_id=rx_port, timeout=5)
    else:
        testutils.verify_no_packet(ptfadapter, pkt=exp_pkt, port_id=rx_port, timeout=5)


def test_null_route_helper(rand_selected_dut, tbinfo, ptfadapter, apply_pre_defined_rules, setup_ptf):
    """
    Test case to verify script null_route_helper.
    Some packets are generated as defined in TEST_DATA and sent to DUT, and verify if packet is forwarded or dropped as expected.
    """
    ptf_port_info = setup_ptf
    rx_port = ptf_port_info['port']
    router_mac = rand_selected_dut.facts["router_mac"]
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    portchannel_members = []
    for _, v in mg_facts["minigraph_portchannels"].items():
        portchannel_members += v['members']

    ptf_t1_interfaces = []
    for port in portchannel_members:
        ptf_t1_interfaces.append(mg_facts['minigraph_ptf_indices'][port])

    # Run testing as defined in TEST_DATA
    for test_item in TEST_DATA:
        src_ip = test_item[0]
        action = test_item[1]
        expected_result = test_item[2]
        ip_ver = ipaddress.ip_network(unicode(src_ip), False).version
        logger.info("Testing with src_ip = {} action = {} expected_result = {}"
                .format(src_ip, action, expected_result))
        pkt, exp_pkt = generate_packet(src_ip, DST_IP[ip_ver], router_mac)
        if action != "":
            rand_selected_dut.shell(NULL_ROUTE_HELPER + " " + action)
            time.sleep(1)

        send_and_verify_packet(ptfadapter, pkt, exp_pkt, random.choice(ptf_t1_interfaces), rx_port, expected_result)
