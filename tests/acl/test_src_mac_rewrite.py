"""
Tests Acl to modify inner src mac to ENI mac in SONiC.
"""

import os
import time
import logging
import pytest
import ipaddress
import json
import ptf.testutils as testutils
from ptf import mask
from ptf.packet import Ether, IP, UDP, VXLAN, simple_vxlan_packet

from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # lgtm[py/unused-import]
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

from abc import abstractmethod

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

@pytest.fixture(scope="module")
def setup_ports_and_portchannels(duthost):
    # Ensure all ports and PortChannels are up
    ports = ["Ethernet0", "Ethernet4", "Ethernet8", "Ethernet12"]  # Example ports
    portchannels = ["PortChannel1", "PortChannel2"]  # Example PortChannels
    
    for port in ports + portchannels:
        duthost.shell("sudo config interface startup {port}")
    

def cleanup_ports_and_portchannels(duthost):
    # Cleanup PortChannels after test (optional)
    portchannels = ["PortChannel1", "PortChannel2"]
    for po in portchannels:
        duthost.shell("sudo config portchannel del {po}")

def setup_acl_table(duthost):
    table_name = ACL_TABLE_NAME
    ports = ["Ethernet0", "Ethernet4", "Ethernet8", "Ethernet12"]
    portchannels = ["PortChannel1", "PortChannel2"]
    cmd = "config acl add table {} {} -s {} -p {}".format(
            ACL_TABLE_NAME,
            ACL_TABLE_TYPE,
            "egress"
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

    # Bind ACL table to specific ports and PortChannels
    
    for port in ports + portchannels:
        duthost.shell("sudo config acl bind table table_name {port}")

def remove_acl_table(duthost):
    table_name = ACL_TABLE_NAME
    cmd = "config acl remove table {}".format(table_name)
    ports = ["Ethernet0", "Ethernet4", "Ethernet8", "Ethernet12"]
    portchannels = ["PortChannel1", "PortChannel2"]

    logger.info("Removing ACL table {}".format(table_name))
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="TestAclSrcMacRewrite")
    loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_REMOVE_RE]

    try:
        with loganalyzer:
            duthost.shell(cmd)
    except LogAnalyzerError:
        # Todo: cleanup
        pytest.fail("Failed to remove ACL table {}".format(table_name))   

    for port in ports + portchannels:
        duthost.shell(f"sudo config acl unbind table TEST_TABLE {port}")

def setup_acl_rules(duthost, inner_src_ip, vni, action, new_src_mac):
    table_name = ACL_TABLE_NAME

    extra_vars = {
        'table_name': table_name,
        'vni': vni,
        'inner_src_ip': inner_src_ip,
        'action': action,
        'new_src_mac' : new_src_mac
        }
    dest_path = os.path.join(TMP_DIR, ACL_RULES_FILE)
    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)
    duthost.file(path=dest_path, state='absent')
    duthost.template(src=os.path.join(TEMPLATES_DIR, ACL_ADD_RULES_FILE), dest=dest_path)
    logger.info("Creating ACL rule matching src_ip {} action {}".format(inner_src_ip, action))
    duthost.shell("config load -y {}".format(dest_path))

    if duthost.facts['asic_type'] != 'vs':
        pytest_assert(wait_until(60, 2, 0, check_rule_counters, duthost), "Acl rule counters are not ready")

def remove_acl_rules(self, duthost, stage, ip_ver):
    table_name = ACL_TABLE_NAME
    duthost.copy(src=os.path.join(FILES_DIR, ACL_REMOVE_RULES_FILE), dest=TMP_DIR)
    remove_rules_dut_path = os.path.join(TMP_DIR, ACL_REMOVE_RULES_FILE)
    duthost.command("acl-loader update full {} --table_name {}".format(remove_rules_dut_path, table_name))
    time.sleep(5)

def test_modify_inner_src_mac_egress(duthost, ptfadapter, setup_acl_rule):
    # Define test parameters
    inner_src_ip = "192.168.1.1"
    vni_id = 5000
    original_inner_src_mac = "00:66:77:88:99:aa"
    modified_inner_src_mac = "00:11:22:33:44:55"
    outer_src_mac = "00:11:22:33:44:66"
    outer_dst_mac = "00:aa:bb:cc:dd:ee"
    outer_src_ip = "10.1.1.1"
    outer_dst_ip = "20.1.1.1"

    # Create VXLAN-encapsulated packet sent by server
    pkt = simple_vxlan_packet(
        eth_dst=outer_dst_mac,
        eth_src=outer_src_mac,
        ip_src=outer_src_ip,
        ip_dst=outer_dst_ip,
        udp_sport=1234,
        udp_dport=4789,
        vni=vni_id,
        inner_frame=Ether(src=original_inner_src_mac, dst='00:bb:cc:dd:ee:ff')/IP(src=inner_src_ip, dst='192.168.2.1')
    )

    # Define expected modified packet on egress
    expected_pkt = simple_vxlan_packet(
        eth_dst=outer_dst_mac,
        eth_src=outer_src_mac,
        ip_src=outer_src_ip,
        ip_dst=outer_dst_ip,
        udp_sport=1234,
        udp_dport=4789,
        vni=vni_id,
        inner_frame=Ether(src=modified_inner_src_mac, dst='00:bb:cc:dd:ee:ff')/IP(src=inner_src_ip, dst='192.168.2.1')
    )

    # Send packet from server into the DUT
    send(ptfadapter, 0, pkt)

    time.sleep(2)

    # Verify the modified packet is received at egress
    verify_packet(ptfadapter, expected_pkt, 1)

    # Verify ACL counter incremented, confirming rule was applied
    result = duthost.shell("show acl counter TEST_TABLE RULE_MODIFY_INNER_SRC_MAC")
    assert "1" in result['stdout'], "ACL counter not incremented as expected"
