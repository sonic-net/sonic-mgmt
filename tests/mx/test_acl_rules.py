from __future__ import unicode_literals

import ipaddress
import pytest
import time

from ptf import testutils
from ptf.mask import Mask
import ptf.packet as scapy

from tests.common.helpers.assertions import pytest_assert, pytest_require
from mx_utils import create_vlan, remove_vlan, get_vlan_config

pytestmark = [
    pytest.mark.topology('mx'),
]

ACL_COUNTERS_UPDATE_INTERVAL_IN_SEC = 10

ACL_TABLE_TYPE_L3 = "L3"
ACL_TABLE_TYPE_L3V6 = "L3V6"

ACL_STAGE_INGRESS = "ingress"
ACL_STAGE_EGRESS = "egress"

ACL_TABLE_BMC_NORTHBOUND = "BMC_ACL_NORTHBOUND"

ACL_RULE_SRC_FILE = "mx/config/acl_rules.json"
ACL_RULE_DST_FILE = "/tmp/acl_rules.json"


def add_acl_table(duthost, table_name, table_type, ports, stage):
    duthost.shell("sudo config acl add table {} {} -p {} -s {}"
                  .format(table_name, table_type, ','.join(ports), stage))


def remove_acl_table(duthost, table_name):
    duthost.shell("sudo config acl remove table {}".format(table_name))


def add_acl_rule(duthost, table_name):
    duthost.copy(src=ACL_RULE_SRC_FILE, dest=ACL_RULE_DST_FILE)
    duthost.shell("acl-loader update full --table_name {} {}".format(table_name, ACL_RULE_DST_FILE))


def remove_acl_rule(duthost, table_name):
    duthost.shell("acl-loader delete {}".format(table_name))


def get_acl_counter(duthost, table_name, rule_name, timeout=ACL_COUNTERS_UPDATE_INTERVAL_IN_SEC):
    time.sleep(timeout)  # Wait for orchagent to update the ACL counters
    result = duthost.show_and_parse('aclshow -a')
    for rule in result:
        if table_name == rule['table name'] and rule_name == rule['rule name']:
            return int(rule['packets count']) if rule['packets count'] != 'N/A' else 0
    raise Exception("Failed to retrieve acl counter for {}|{}".format(table_name, rule_name))


def pick_port_from_vlan(vlan_config, vlan_id, count=1):
    pytest_require(vlan_id in vlan_config, "vlan_id not in vlan_config")
    vlan_subnet = vlan_config[vlan_id]['prefix']
    vlan_interface = vlan_subnet.split('/')[0]
    vlan_members = vlan_config[vlan_id]['members']
    pytest_require(count <= len(vlan_members),
                   "Require too much ports. Vlan has {} ports, requires {} ports".format(vlan_members, count))
    ip_generator = ipaddress.ip_network(vlan_subnet, strict=False).hosts()
    ports = []
    for i in range(0, count):
        ip_addr = next(ip_generator)
        if format(ip_addr) == vlan_interface:
            ip_addr = next(ip_generator)
        ports.append({'port_id': vlan_members[i], 'ip_addr': ip_addr})
    return ports


def parse_vlan_interface(vlan_config, vlan_id):
    pytest_require(vlan_id in vlan_config, "vlan_id not in vlan_config")
    vlan_subnet = vlan_config[vlan_id]['prefix']
    vlan_interface = vlan_subnet.split('/')[0]
    return vlan_interface


def build_exp_pkt(input_pkt):
    exp_pkt = Mask(input_pkt)
    exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
    if input_pkt.haslayer('IP'):
        exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
    else:
        exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
    return exp_pkt


def test_bmc_northbound_acl_v4(duthost, ptfhost, ptfadapter, function_fixture_remove_all_vlans,
                               mx_common_setup_teardown):
    router_mac = duthost.facts['router_mac']
    dut_index_port, _, vlan_configs = mx_common_setup_teardown
    vlan_config = get_vlan_config(vlan_configs, 4)
    create_vlan(duthost, vlan_config, dut_index_port)
    add_acl_table(duthost, ACL_TABLE_BMC_NORTHBOUND, ACL_TABLE_TYPE_L3,
                  ["Vlan" + vlan_id for vlan_id in vlan_config], ACL_STAGE_INGRESS)
    add_acl_rule(duthost, ACL_TABLE_BMC_NORTHBOUND)

    try:
        # verify each acl rule
        vlan223_port = pick_port_from_vlan(vlan_config, "223")[0]
        test_pkts = {
            'RULE_1': testutils.simple_tcp_packet(eth_dst=router_mac, ip_src=vlan223_port['ip_addr']),
            'RULE_2': testutils.simple_tcp_packet(eth_dst=router_mac, ip_dst=vlan223_port['ip_addr']),
            'RULE_3': testutils.simple_tcp_packet(eth_dst=router_mac, ip_dst=parse_vlan_interface(vlan_config, "220")),
            'RULE_4': testutils.simple_tcp_packet(eth_dst=router_mac, ip_dst=parse_vlan_interface(vlan_config, "221")),
            'RULE_5': testutils.simple_tcp_packet(eth_dst=router_mac, ip_dst=parse_vlan_interface(vlan_config, "222")),
        }
        for rule_name, pkt in test_pkts.items():
            verify_acl_rule(duthost, ptfadapter, ACL_TABLE_BMC_NORTHBOUND, rule_name, pkt,
                            src_port_id=vlan_config["220"]["members"][0])

        # verify members of VLAN_220 cannot send packet to members of VLAN_220
        src_port, dst_port = pick_port_from_vlan(vlan_config, "220", 2)
        send_and_verify_traffic(duthost, ptfhost, ptfadapter, src_port, dst_port, expect_behavior="drop")

        # verify members of VLAN_220 cannot send packet to members of VLAN_221
        src_port = pick_port_from_vlan(vlan_config, "220")[0]
        dst_port = pick_port_from_vlan(vlan_config, "221")[0]
        send_and_verify_traffic(duthost, ptfhost, ptfadapter, src_port, dst_port, expect_behavior="drop")

        # verify members of VLAN_220 can send packet to members of VLAN_223 (rack mamager Vlan)
        src_port = pick_port_from_vlan(vlan_config, "220")[0]
        dst_port = pick_port_from_vlan(vlan_config, "223")[0]
        send_and_verify_traffic(duthost, ptfhost, ptfadapter, src_port, dst_port, expect_behavior="accept")
    finally:
        remove_acl_rule(duthost, ACL_TABLE_BMC_NORTHBOUND)
        remove_acl_table(duthost, ACL_TABLE_BMC_NORTHBOUND)
        remove_vlan(duthost, vlan_config, dut_index_port)


def verify_acl_rule(duthost, ptfadapter, table_name, rule_name, pkt, src_port_id):
    count_before = get_acl_counter(duthost, table_name, rule_name)
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, pkt=pkt, port_id=src_port_id)
    count_after = get_acl_counter(duthost, table_name, rule_name)
    pytest_assert(count_after == count_before + 1,
                  "counter_after {} != counter_before {} + 1".format(count_after, count_before))


def send_and_verify_traffic(duthost, ptfhost, ptfadapter, src_port, dst_port, expect_behavior):
    try:
        router_mac = duthost.facts['router_mac']
        ptfhost.add_ip_to_dev("eth" + str(src_port['port_id']), src_port['ip_addr'])
        ptfhost.add_ip_to_dev("eth" + str(dst_port['port_id']), dst_port['ip_addr'])
        pkt = testutils.simple_tcp_packet(eth_dst=router_mac, ip_src=src_port['ip_addr'], ip_dst=dst_port['ip_addr'])
        exp_pkt = build_exp_pkt(pkt)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, pkt=pkt, port_id=src_port['port_id'])
        if expect_behavior == "accept":
            testutils.verify_packet(ptfadapter, exp_pkt, dst_port['port_id'], timeout=10)
        elif expect_behavior == "drop":
            testutils.verify_no_packet(ptfadapter, exp_pkt, dst_port['port_id'], timeout=10)
    finally:
        ptfhost.remove_ip_addresses()
