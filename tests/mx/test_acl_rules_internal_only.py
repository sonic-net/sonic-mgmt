from __future__ import unicode_literals

import copy
import ipaddress
import json
import logging
import os
import pytest
import random
import re
import sys
import time
import yaml

from functools import reduce
import jinja2
from ptf import testutils
from ptf.mask import Mask
import ptf.packet as scapy
from scapy.layers.dhcp6 import DHCP6_Solicit

from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py  # noqa F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, capture_and_check_packet_on_dut
from tests.common.gu_utils import apply_patch, expect_op_success, generate_tmpfile, delete_tmpfile
from mx_utils import create_vlan, get_vlan_config, remove_all_vlans
from config.generate_acl_rules import (
    acl_entry,
    ACL_ACTION_ACCEPT,
    ACL_ACTION_DROP,
    DHCPV6_SERVER_PORT,
    DHCPV6_MULTICAST_IP,
    ETHERTYPE_IPV6,
    ICMP_TYPE_ECHO_REQUEST,
    ICMP_TYPE_ECHO_REPLY,
    ICMP_CODE_ECHO_REQUEST,
    ICMP_CODE_ECHO_REPLY,
    ICMPV6_TYPE_ECHO_REQUEST,
    ICMPV6_TYPE_ECHO_REPLY,
    ICMPV6_TYPE_ROUTER_SOLICITATION,
    ICMPV6_TYPE_NEIGHBOR_SOLICITATION,
    ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT,
    ICMPV6_CODE_ECHO_REQUEST,
    ICMPV6_CODE_ECHO_REPLY,
    ICMPV6_CODE_ROUTER_SOLICITATION,
    ICMPV6_CODE_NEIGHBOR_SOLICITATION,
    ICMPV6_CODE_NEIGHBOR_ADVERTISEMENT,
    IP_PROTOCOL_TCP,
    IP_PROTOCOL_UDP,
    IP_PROTOCOL_ICMPV6,
    IP_PROTOCOL_MAP,
    TCP_FLAG_ACK,
    TCP_FLAG_SYN,
)

pytestmark = [
    pytest.mark.topology('mx'),
]

ACL_PACKET_ACTION_DROP = "DROP"
ACL_PACKET_ACTION_FORWARD = "FORWARD"

ACL_TABLE_TYPE_L3 = "L3"
ACL_TABLE_TYPE_L3V6 = "L3V6"
ACL_TABLE_TYPE_BMC = "BMCDATA"
ACL_TABLE_TYPE_BMC_V6 = "BMCDATAV6"

ACL_STAGE_INGRESS = "ingress"
ACL_STAGE_EGRESS = "egress"

ACL_TABLE_TYPE_SRC_FILE = "mx/config/bmc_acl_table_types.json"
ACL_TABLE_TYPE_DST_FILE = "/tmp/acl_table_types.json"

ACL_TABLE_BMC_NORTHBOUND = "bmc_acl_northbound"
ACL_TABLE_BMC_NORTHBOUND_V6 = "bmc_acl_northbound_v6"
ACL_TABLE_BMC_SOUTHBOUND_V6 = "bmc_acl_southbound_v6"

ACL_RULE_SRC_FILE_PREFIX = "mx/config/auto_generated_files"
ACL_RULE_DST_FILE = "/tmp/bmc_acl_rules.json"

RACK_TOPO_FILE_BMC_OTW = "mx/config/bmc_otw_topo.yaml"
RACK_TOPO_FILE_BMC_ARES = "mx/config/bmc_ares_topo.yaml"

SAMPLE_UPSTREAM_IPV4_ADDR = "1.1.1.1"
SAMPLE_UPSTREAM_IPV4_PREFIX = 32
SAMPLE_UPSTREAM_IPV6_ADDR = "fc03::1"
SAMPLE_UPSTREAM_IPV6_PREFIX = 128

DHCP_MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"
DHCP_IP_DEFAULT_ROUTE = "0.0.0.0"
DHCP_IP_BROADCAST = "255.255.255.255"
DHCP_UDP_CLIENT_PORT = 68
DHCP_UDP_SERVER_PORT = 67

DHCPV6_MAC_MULTICAST = "33:33:00:01:00:02"
DHCPV6_IP_MULTICAST = "ff02::1:2"
DHCPV6_IP_LINK_LOCAL_PREFIX = "fe80::/10"
DHCPV6_UDP_CLIENT_PORT = 546
DHCPV6_UDP_SERVER_PORT = 547

# Northbound v6 AD-HOC isolation ACL rule seq: 2001-3000 (pri: 7999-7000)
NTH_AD_HOC_IOSLATION_SEQ_START = 2001
# Northbound v6 AD_HOC Allow TCP SYN_ACK ACL rule seq: 3001-3999 (pri: 6999-6001)
NTH_AD_HOC_ALLOW_TCP_SYNACK_SEQ_START = 3001
# Northbound v6 AD_HOC drop TCP SYN rule seq: 4000 (pri: 6000)
NTH_AD_HOC_DROP_TCP_SYN_SEQ = 4000
# Northbound v6 AD_HOC allow protocol traffic ACL rule seq: 4001-5000 (pri: 5999-5000)
NTH_AD_HOC_ALLOW_PROTOCOL_SEQ_START = 4001
# Northbound v6 AD_HOC allow DHCPv6 multicast ACL rule seq: 4901 (pri: 5099)
NTH_AD_HOC_ALLOW_DHCPV6_MULTICAST_SEQ = 4901
# Northbound v6 AD_HOC allow ICMPv6 echo ACL rule seq:4911-4990 (pri: 5089-5010)
NTH_AD_HOC_ALLOW_ICMPV6_ECHO_SEQ_START = 4911
# Northbound v6 AD_HOC allow ICMPv6 router solicitation ACL rule seq: 4996 (pri: 5004)
NTH_AD_HOC_ALLOW_ICMPV6_RS_SEQ = 4996
# Northbound v6 AD_HOC allow ICMPv6 neighbor solicitation ACL rule seq: 4997 (pri: 5003)
NTH_AD_HOC_ALLOW_ICMPV6_NS_SEQ = 4997
# Northbound v6 AD_HOC allow ICMPv6 neighbor advertisement ACL rule seq: 4998 (pri: 5002)
NTH_AD_HOC_ALLOW_ICMPV6_NA_SEQ = 4998

# Southbound v6 AD-HOC isolation ACL rule seq: 2001-3000 (pri: 7999-7000)
STH_AD_HOC_ISOLATION_SEQ_START = 2001
# Southbound v6 AD_HOC allow protocol traffic ACL rule seq: 3001-4000 (pri: 6999-6000)
STH_AD_HOC_ALLOW_PROTOCOL_SEQ_START = 3001


def add_acl_table(duthost, table_name, table_type, ports, stage):
    duthost.shell("sudo config acl add table {} {} -p {} -s {}"
                  .format(table_name, table_type, ','.join(ports), stage))


def remove_acl_table(duthost, table_name):
    duthost.shell("sudo config acl remove table {}".format(table_name))


def add_acl_rule(duthost, src_file, table_name, confirm_active=True):
    duthost.copy(src=src_file, dest=ACL_RULE_DST_FILE)
    duthost.shell("acl-loader update full --table_name {} {}".format(table_name, ACL_RULE_DST_FILE))
    if confirm_active and not wait_until(60, 5, 0, all_acl_rule_active, duthost, table_name):
        pytest.fail("Not all the ACL rules are active after 60 seconds.")


def all_acl_rule_active(duthost, table_name=None):
    cmd = "show acl rule {} | grep -wE 'FORWARD|DROP'".format(table_name if table_name else '')
    rules = duthost.shell(cmd)["stdout_lines"]
    return all(re.search(r'\bActive\b', rule, re.IGNORECASE) for rule in rules)


def remove_acl_rule(duthost, table_name):
    duthost.shell("acl-loader delete {}".format(table_name))


def gcu_add_acl_rule(duthost, table_name, rules):
    json_patch = [{
        "op": "add",
        "path": "/ACL_RULE/{}|{}".format(table_name, rule_name),
        "value": rule_value,
    } for rule_name, rule_value in rules.items()]
    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def gcu_remove_acl_rule(duthost, table_name, rule_names):
    json_patch = [{
        "op": "remove",
        "path": "/ACL_RULE/{}|{}".format(table_name, rule_name),
    } for rule_name in rule_names]
    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def build_gcu_acl_rule_patch(seq_id, action, ethertype=None, interfaces=None, ip_protocol=None,
                             src_ip=None, dst_ip=None, src_ipv6=None, dst_ipv6=None,
                             l4_src_port=None, l4_dst_port=None):
    rule_name = "RULE_{}".format(seq_id)
    rule_value = {
        "PACKET_ACTION": action,
        "PRIORITY": str(10000 - seq_id),
    }
    if ethertype:
        rule_value["ETHER_TYPE"] = str(ethertype)
    if interfaces:
        rule_value["IN_PORTS"] = ",".join(interfaces)
    if ip_protocol:
        rule_value["IP_PROTOCOL"] = str(ip_protocol)
    if src_ip:
        rule_value["SRC_IP"] = str(src_ip)
    if dst_ip:
        rule_value["DST_IP"] = str(dst_ip)
    if src_ipv6:
        rule_value["SRC_IPV6"] = str(src_ipv6)
    if dst_ipv6:
        rule_value["DST_IPV6"] = str(dst_ipv6)
    if l4_src_port:
        rule_value["L4_SRC_PORT_RANGE" if l4_src_port.get_mode() == L4Ports.MODE_RANGE_RANDOM else "L4_SRC_PORT"] = str(l4_src_port)
    if l4_dst_port:
        rule_value["L4_DST_PORT_RANGE" if l4_dst_port.get_mode() == L4Ports.MODE_RANGE_RANDOM else "L4_DST_PORT"] = str(l4_dst_port)
    return {rule_name: rule_value}


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


class PowerShelfInfo:
    def __init__(self, id, rm, bmc_hosts):
        self.id = id
        self.rm = rm
        self.bmc_hosts = bmc_hosts

    def __str__(self):
        return json.dumps(self.__dict__, ensure_ascii=False)


class PortInfo:
    def __init__(self, port_name, port_alias, ptf_port_id,
                 ipv4_addr=None, ipv4_prefix=None,
                 ipv6_addr=None, ipv6_prefix=None, **kwargs):
        self.port_name = port_name
        self.port_alias = port_alias
        self.ptf_port_id = ptf_port_id
        self.ipv4_addr = ipv4_addr
        self.ipv4_prefix = ipv4_prefix
        self.ipv6_addr = ipv6_addr
        self.ipv6_prefix = ipv6_prefix
        self.__dict__.update(kwargs)

    def __str__(self):
        return json.dumps(self.__dict__, ensure_ascii=False)


class L4Ports:
    MODE_RANGE_RANDOM = "L4_PORT_RANGE"
    MODE_SINGLE_RANDOM = "L4_SINGLE_RANDOM_PORT"
    MODE_SINGLE_SSH = "L4_SINGLE_SSH"
    MODE_SINGLE_HTTPS = "L4_SINGLE_HTTPS"

    TCP_SSH_PORT = 22
    TCP_HTTPS_PORT = 443

    def __init__(self, lo=0, hi=0, mode=MODE_SINGLE_RANDOM):
        self.lo = lo
        self.hi = hi
        self.mode = mode

    def __str__(self):
        return self.format_config_db()

    @classmethod
    def rand(cls, mode, lo=1024, hi=65535):
        if mode == cls.MODE_SINGLE_RANDOM:
            return cls.rand_single(lo, hi)
        elif mode == cls.MODE_RANGE_RANDOM:
            return cls.rand_range(lo, hi)
        elif mode == cls.MODE_SINGLE_SSH:
            return cls(L4Ports.TCP_SSH_PORT, L4Ports.TCP_SSH_PORT, cls.MODE_SINGLE_SSH)
        elif mode == cls.MODE_SINGLE_HTTPS:
            return cls(L4Ports.TCP_HTTPS_PORT, L4Ports.TCP_HTTPS_PORT, cls.MODE_SINGLE_HTTPS)
        else:
            raise ValueError("Invalid mode: {}".format(mode))

    @classmethod
    def rand_single(cls, lo=1024, hi=65535):
        port = random.randint(lo, hi)
        return cls(port, port, cls.MODE_SINGLE_RANDOM)

    @classmethod
    def rand_range(cls, lo=1024, hi=65535):
        range_lo, range_hi = sorted(random.sample(range(lo, hi), 2))
        return cls(range_lo, range_hi, cls.MODE_RANGE_RANDOM)

    def format_acl_loader(self):
        if self.lo == self.hi:
            return str(self.lo)
        return "{}..{}".format(self.lo, self.hi)

    def format_config_db(self):
        if self.lo == self.hi:
            return str(self.lo)
        return "{}-{}".format(self.lo, self.hi)

    def get_mode(self):
        return self.mode

    def sample_port(self):
        return random.sample(range(self.lo, self.hi + 1), 1)[0]


def verify_traffic(ptfadapter, dst_ptf_port_ids, exp_pkt, expect_behavior):
    if expect_behavior == "accept":
        if len(dst_ptf_port_ids) == 1:
            testutils.verify_packet(ptfadapter, exp_pkt, dst_ptf_port_ids[0], timeout=10)
        else:
            testutils.verify_packet_any_port(ptfadapter, exp_pkt, dst_ptf_port_ids, timeout=10)
    elif expect_behavior == "drop":
        if sys.version_info.major == 2:
            # Python2 env is using ptf=0.9.1 which doesn't support timeout parameter.
            # However ptf module doesn't contain a __version__ variable, so we can only check by Python version.
            if len(dst_ptf_port_ids) == 1:
                testutils.verify_no_packet(ptfadapter, exp_pkt, dst_ptf_port_ids[0], timeout=10)
            else:
                testutils.verify_no_packet_any(ptfadapter, exp_pkt, dst_ptf_port_ids)
        else:
            if len(dst_ptf_port_ids) == 1:
                testutils.verify_no_packet(ptfadapter, exp_pkt, dst_ptf_port_ids[0], timeout=10)
            else:
                testutils.verify_no_packet_any(ptfadapter, exp_pkt, dst_ptf_port_ids, timeout=10)


def send_and_verify_traffic_v4(duthost, ptfadapter, src, dsts, expect_behavior, pkt=None):
    router_mac = duthost.facts['router_mac']
    if pkt is None:
        pkt = testutils.simple_tcp_packet(eth_dst=router_mac, ip_src=src.ipv4_addr, ip_dst=dsts[0].ipv4_addr, tcp_flags="")
    exp_pkt = build_exp_pkt(pkt)
    for host in [src] + dsts:
        duthost.shell("timeout 1 ping -c 1 -w 1 {}".format(host.ipv4_addr), module_ignore_errors=True)
    ptfadapter.dataplane.flush()
    dsts_str = json.dumps(dsts, default=lambda x: str(x))
    logging.info("Start to Verify traffic between {} and {}, expect behavior is {}".format(src, dsts_str, expect_behavior))
    testutils.send(ptfadapter, pkt=pkt, port_id=src.ptf_port_id)
    dst_ptf_port_ids = [dst.ptf_port_id for dst in dsts]
    verify_traffic(ptfadapter, dst_ptf_port_ids, exp_pkt, expect_behavior)
    logging.info("Verify traffic between {} and {} passed, expect behavior is {}".format(src, dsts_str, expect_behavior))


def send_and_verify_traffic_v6(duthost, ptfadapter, src, dsts, expect_behavior, pkt=None):
    router_mac = duthost.facts['router_mac']
    if pkt is None:
        pkt = testutils.simple_tcpv6_packet(eth_dst=router_mac, ipv6_src=src.ipv6_addr, ipv6_dst=dsts[0].ipv6_addr, tcp_flags="")
    exp_pkt = build_exp_pkt(pkt)
    for host in [src] + dsts:
        duthost.shell("timeout 1 ping6 -c 1 -w 1 {}".format(host.ipv6_addr), module_ignore_errors=True)
    ptfadapter.dataplane.flush()
    dsts_str = json.dumps(dsts, default=lambda x: str(x))
    logging.info("Start to Verify traffic between {} and {}, expect behavior is {}".format(src, dsts_str, expect_behavior))
    testutils.send(ptfadapter, pkt=pkt, port_id=src.ptf_port_id)
    dst_ptf_port_ids = [dst.ptf_port_id for dst in dsts]
    verify_traffic(ptfadapter, dst_ptf_port_ids, exp_pkt, expect_behavior)
    logging.info("Verify traffic between {} and {} passed, expect behavior is {}".format(src, dsts_str, expect_behavior))


@pytest.fixture(scope='module', autouse=True)
def setup_custom_acl_table(duthost):
    duthost.copy(src=ACL_TABLE_TYPE_SRC_FILE, dest=ACL_TABLE_TYPE_DST_FILE)
    duthost.shell("sonic-cfggen -j {} -w".format(ACL_TABLE_TYPE_DST_FILE))


@pytest.fixture(scope='module', autouse=True)
def setup_python_library_on_dut(duthost, creds):
    http_proxy = creds.get('proxy_env', {}).get('http_proxy', '')
    https_proxy = creds.get('proxy_env', {}).get('https_proxy', '')
    cmd = "http_proxy={} https_proxy={} pip3 install ptf".format(http_proxy, https_proxy)
    duthost.shell(cmd)
    yield
    cmd = "pip3 uninstall -y ptf"
    duthost.shell(cmd, module_ignore_errors=True)


def prod_bmc_otw_basic_acl_set_nth(vlan_interfaces_ipv6: list):
    """
    Construct production BMC OTW basic dynamic ACL rule set on northbound direction
    """
    acl_set = {
        f"{NTH_AD_HOC_DROP_TCP_SYN_SEQ}_AD_HOC_TCP_SYN": json.dumps(
            acl_entry(NTH_AD_HOC_DROP_TCP_SYN_SEQ, action=ACL_ACTION_DROP, ethertype=ETHERTYPE_IPV6,
                      ip_protocol=IP_PROTOCOL_TCP, tcp_flags=[TCP_FLAG_SYN])
        ),
        f"{NTH_AD_HOC_ALLOW_DHCPV6_MULTICAST_SEQ}_AD_HOC_DHCPV6_MULTICAST": json.dumps(
            acl_entry(NTH_AD_HOC_ALLOW_DHCPV6_MULTICAST_SEQ, action=ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV6,
                      ip_protocol=IP_PROTOCOL_UDP, dst_ip=DHCPV6_MULTICAST_IP, l4_dst_port=DHCPV6_SERVER_PORT)
        ),
        f"{NTH_AD_HOC_ALLOW_ICMPV6_RS_SEQ}_AD_HOC_ICMPV6_ROUTER_SOLICITATION": json.dumps(
            acl_entry(NTH_AD_HOC_ALLOW_ICMPV6_RS_SEQ, action=ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV6,
                      ip_protocol=IP_PROTOCOL_ICMPV6, icmp_type=ICMPV6_TYPE_ROUTER_SOLICITATION, icmp_code=ICMPV6_CODE_ROUTER_SOLICITATION)
        ),
        f"{NTH_AD_HOC_ALLOW_ICMPV6_NS_SEQ}_AD_HOC_ICMPV6_NEIGHBOR_SOLICITATION": json.dumps(
            acl_entry(NTH_AD_HOC_ALLOW_ICMPV6_NS_SEQ, action=ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV6,
                      ip_protocol=IP_PROTOCOL_ICMPV6, icmp_type=ICMPV6_TYPE_NEIGHBOR_SOLICITATION, icmp_code=ICMPV6_CODE_NEIGHBOR_SOLICITATION)
        ),
        f"{NTH_AD_HOC_ALLOW_ICMPV6_NA_SEQ}_AD_HOC_ICMPV6_NEIGHBOR_ADVERTISEMENT": json.dumps(
            acl_entry(NTH_AD_HOC_ALLOW_ICMPV6_NA_SEQ, action=ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV6,
                      ip_protocol=IP_PROTOCOL_ICMPV6, icmp_type=ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT, icmp_code=ICMPV6_CODE_NEIGHBOR_ADVERTISEMENT)
        ),
    }
    seq_id = NTH_AD_HOC_ALLOW_ICMPV6_ECHO_SEQ_START
    for ipv6_addr in vlan_interfaces_ipv6:
        acl_set[f'{seq_id}_AD_HOC_ICMPV6_ECHO_REQUEST'] = json.dumps(
            acl_entry(seq_id, action=ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV6,
                      ip_protocol=IP_PROTOCOL_ICMPV6, dst_ip=ipv6_addr + "/128",
                      icmp_type=ICMPV6_TYPE_ECHO_REQUEST, icmp_code=ICMPV6_CODE_ECHO_REQUEST)
        )
        seq_id += 5
        acl_set[f'{seq_id}_AD_HOC_ICMPV6_ECHO_REPLY'] = json.dumps(
            acl_entry(seq_id, action=ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV6,
                      ip_protocol=IP_PROTOCOL_ICMPV6, dst_ip=ipv6_addr + "/128",
                      icmp_type=ICMPV6_TYPE_ECHO_REPLY, icmp_code=ICMPV6_CODE_ECHO_REPLY)
        )
        seq_id += 5
    return acl_set


def prod_bmc_isolation_nth(seq_id: int, bmc: PortInfo):
    """
    Construct production dynamic ACL rule for BMC isolation on northbound direction
    """
    return {
        f'{seq_id}_AD_HOC_BMC_ISOLATION': json.dumps(
            acl_entry(seq_id, action=ACL_ACTION_DROP, ethertype=ETHERTYPE_IPV6, interfaces=[bmc.port_name])
        )
    }


def prod_bmc_isolation_sth(seq_id: int, bmc: PortInfo):
    """
    Construct production dynamic ACL rule for BMC isolation on southbound direction
    """
    return {
        f'{seq_id}_AD_HOC_BMC_ISOLATION': json.dumps(
            acl_entry(seq_id, action=ACL_ACTION_DROP, ethertype=ETHERTYPE_IPV6, dst_ip=bmc.ipv6_addr + "/128")
        )
    }


def prod_allow_tcpv6_synack_nth(seq_id: int, upstream: PortInfo,
                                l4_src_port: L4Ports = None, l4_dst_port: L4Ports = None):
    """
    Construct production dynamic ACL rule for allowing TCP SYN-ACK packet on northbound direction
    """
    if l4_src_port:
        l4_src_port = l4_src_port.format_acl_loader()
    if l4_dst_port:
        l4_dst_port = l4_dst_port.format_acl_loader()
    return {
        f'{seq_id}_AD_HOC_ALLOW_TCP_SYNACK': json.dumps(
            acl_entry(seq_id, action=ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV6,
                      ip_protocol=IP_PROTOCOL_TCP, tcp_flags=[TCP_FLAG_SYN, TCP_FLAG_ACK],
                      dst_ip=upstream.ipv6_addr + "/128",
                      l4_src_port=l4_src_port, l4_dst_port=l4_dst_port)
        )
    }


def prod_allow_tcpv6_nth(seq_id: int, upstream: PortInfo,
                         l4_src_port: L4Ports = None, l4_dst_port: L4Ports = None):
    """
    Construct production dynamic ACL rule for allowing TCPv6 traffic on northbound direction
    """
    if l4_src_port:
        l4_src_port = l4_src_port.format_acl_loader()
    if l4_dst_port:
        l4_dst_port = l4_dst_port.format_acl_loader()
    return {
        f'{seq_id}_AD_HOC_ALLOW_TCPV6': json.dumps(
            acl_entry(seq_id, action=ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV6,
                      ip_protocol=IP_PROTOCOL_TCP, dst_ip=upstream.ipv6_addr + "/128",
                      l4_src_port=l4_src_port, l4_dst_port=l4_dst_port)
        )
    }


def prod_allow_tcpv6_sth(seq_id: int, upstream: PortInfo,
                         l4_src_port: L4Ports = None, l4_dst_port: L4Ports = None):
    """
    Construct production dynamic ACL rule for allowing TCPv6 traffic on southbound direction
    """
    if l4_src_port:
        l4_src_port = l4_src_port.format_acl_loader()
    if l4_dst_port:
        l4_dst_port = l4_dst_port.format_acl_loader()
    return {
        f'{seq_id}_AD_HOC_ALLOW_TCPV6': json.dumps(
            acl_entry(seq_id, action=ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV6,
                      ip_protocol=IP_PROTOCOL_TCP, src_ip=upstream.ipv6_addr + "/128",
                      l4_src_port=l4_src_port, l4_dst_port=l4_dst_port)
        )
    }


def prod_allow_icmpv6_echo_nth(seq_id: int, upstream: PortInfo):
    """
    Construct production dynamic ACL rule for allowing ICMPv6 echo (reply) on northbound direction
    """
    return {
        f'{seq_id}_AD_HOC_ALLOW_ICMPV6_ECHO': json.dumps(
            acl_entry(seq_id, action=ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV6,
                      ip_protocol=IP_PROTOCOL_ICMPV6, dst_ip=upstream.ipv6_addr + "/128",
                      icmp_type=ICMPV6_TYPE_ECHO_REPLY, icmp_code=ICMPV6_CODE_ECHO_REPLY)
        )
    }


def prod_allow_icmpv6_echo_sth(seq_id: int, upstream: PortInfo):
    """
    Construct production dynamic ACL rule for allowing ICMPv6 echo (request) on southbound direction
    """
    return {
        f'{seq_id}_AD_HOC_ALLOW_ICMPV6_ECHO': json.dumps(
            acl_entry(seq_id, action=ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV6,
                      ip_protocol=IP_PROTOCOL_ICMPV6, src_ip=upstream.ipv6_addr + "/128",
                      icmp_type=ICMPV6_TYPE_ECHO_REQUEST, icmp_code=ICMPV6_CODE_ECHO_REQUEST)
        )
    }


def get_vlan_interfaces_ipv6(duthost):
    vlan_cfg = duthost.get_vlan_brief()
    vlan_intf_ipv6 = []
    for _, vlan_info in vlan_cfg.items():
        vlan_intf_ipv6 += [gateway6.split('/')[0] for gateway6 in vlan_info.get('interface_ipv6', [])]
    return vlan_intf_ipv6


class BmcOtwAclRulesBase:

    def rand_bmc_from_vlan_members(self, bmc_hosts, vlan_members):
        """
        Rand one bmc from bmc_hosts whose port_name is in vlan_members
        """
        for bmc in self.shuffle_ports(bmc_hosts):
            if bmc.port_name in vlan_members:
                return bmc
        return None

    def shuffle_ports(self, pool, max_len=0):
        pool = copy.deepcopy(pool)  # Avoid changing the order in original list
        random.shuffle(pool)
        if max_len == 0 or max_len > len(pool):
            max_len = len(pool)
        idx = 0
        while idx < max_len:
            yield pool[idx]
            idx += 1

    def shuffle_src_dst_pairs(self, pool, max_len=0):
        pool = copy.deepcopy(pool)  # Avoid changing the order in original list
        random.shuffle(pool)
        idx = 0
        while idx + 1 < len(pool):
            if max_len > 0 and idx / 2 >= max_len:
                return
            yield pool[idx], pool[idx + 1]
            idx += 2

    def rand_one(self, pool):
        return copy.copy(random.sample(pool, 1)[0])

    def filter_shelf_with_rm_ipv6(self, shelfs):
        return [shelf for shelf in shelfs if shelf.rm.ipv6_addr is not None]

    def get_shelf_by_bmc(self, shelfs, target_bmc):
        for shelf in shelfs:
            for bmc in shelf.bmc_hosts:
                if bmc.port_name == target_bmc.port_name:
                    return shelf
        return None

    @pytest.fixture(scope="class")
    def setup_teardown(self, duthost, ptfhost, rack_topo_file, mx_common_setup_teardown, port_alias_to_name, port_alias_to_ptf_index):
        # load rack topo
        with open(rack_topo_file) as f:
            rack_topo = yaml.safe_load(f)

        shelfs_topo = rack_topo['shelfs']
        shelfs = []
        for shelf_topo in shelfs_topo:
            shelf_topo['rm']['port_name'] = port_alias_to_name[shelf_topo['rm']['port_alias']]
            shelf_topo['rm']['ptf_port_id'] = port_alias_to_ptf_index[shelf_topo['rm']['port_alias']]
            shelf_rm = PortInfo(**shelf_topo['rm'])
            shelf_bmc_hosts = []
            for bmc_gp in shelf_topo['bmc']:
                for bmc_info in bmc_gp['hosts']:
                    bmc_info['port_name'] = port_alias_to_name[bmc_info['port_alias']]
                    bmc_info['ptf_port_id'] = port_alias_to_ptf_index[bmc_info['port_alias']]
                    bmc_host = PortInfo(**bmc_info)
                    shelf_bmc_hosts.append(bmc_host)
            shelfs.append(PowerShelfInfo(shelf_topo['id'], shelf_rm, shelf_bmc_hosts))
        rms = [shelf.rm for shelf in shelfs]
        bmc_hosts = reduce(lambda x, y: x + y, [shelf.bmc_hosts for shelf in shelfs])
        upstream_ports = [PortInfo(
            port_name=port_alias_to_name[alias],
            port_alias=alias,
            ptf_port_id=port_alias_to_ptf_index[alias],
            ipv4_addr=SAMPLE_UPSTREAM_IPV4_ADDR,
            ipv4_prefix=SAMPLE_UPSTREAM_IPV4_PREFIX,
            ipv6_addr=SAMPLE_UPSTREAM_IPV6_ADDR,
            ipv6_prefix=SAMPLE_UPSTREAM_IPV6_PREFIX
        ) for alias in rack_topo['config']['upstream']['port_aliases']]

        # setup vlan
        remove_all_vlans(duthost)
        dut_index_port, _, vlan_configs = mx_common_setup_teardown
        vlan_config = get_vlan_config(vlan_configs, rack_topo['config']['vlan_count'])
        create_vlan(duthost, vlan_config, dut_index_port)

        # setup arp_responder
        ptfhost.remove_ip_addresses()
        arp_responder_conf = {}
        for host in bmc_hosts + rms:
            ptf_iface = 'eth{}'.format(host.ptf_port_id)
            arp_responder_conf[ptf_iface] = [host.ipv4_addr]
            if host.ipv6_addr is not None:
                arp_responder_conf[ptf_iface].append(host.ipv6_addr)
        with open("/tmp/from_t1.json", "w") as fp:
            json.dump(arp_responder_conf, fp)
        ptfhost.copy(src="/tmp/from_t1.json", dest="/tmp/from_t1.json")
        ptfhost.host.options["variable_manager"].extra_vars.update({"arp_responder_args": ""})
        ptfhost.template(src="templates/arp_responder.conf.j2", dest="/etc/supervisor/conf.d/arp_responder.conf")
        ptfhost.shell("supervisorctl reread && supervisorctl update")
        ptfhost.shell("supervisorctl restart arp_responder")

        # setup acl tables and acl rules
        acl_tables = rack_topo['config']['acl_tables']
        if ACL_TABLE_BMC_NORTHBOUND in acl_tables:
            add_acl_table(duthost, acl_tables[ACL_TABLE_BMC_NORTHBOUND], ACL_TABLE_TYPE_BMC,
                          ["Vlan" + vlan_id for vlan_id in vlan_config], ACL_STAGE_INGRESS)
        if ACL_TABLE_BMC_NORTHBOUND_V6 in acl_tables:
            add_acl_table(duthost, acl_tables[ACL_TABLE_BMC_NORTHBOUND_V6], ACL_TABLE_TYPE_BMC_V6,
                          ["Vlan" + vlan_id for vlan_id in vlan_config], ACL_STAGE_INGRESS)
        if ACL_TABLE_BMC_SOUTHBOUND_V6 in acl_tables:
            add_acl_table(duthost, acl_tables[ACL_TABLE_BMC_SOUTHBOUND_V6], ACL_TABLE_TYPE_BMC_V6,
                          [port.port_name for port in upstream_ports], ACL_STAGE_INGRESS)

        yield rack_topo, shelfs, bmc_hosts, upstream_ports

        # stop and remove arp_responder
        ptfhost.shell("supervisorctl stop arp_responder")
        ptfhost.shell("rm -f /tmp/from_t1.json")
        ptfhost.shell("rm -f /etc/supervisor/conf.d/arp_responder.conf")
        ptfhost.shell("supervisorctl reread && supervisorctl update")

        # remove acl tables
        if ACL_TABLE_BMC_NORTHBOUND in acl_tables:
            remove_acl_table(duthost, acl_tables[ACL_TABLE_BMC_NORTHBOUND])
        if ACL_TABLE_BMC_NORTHBOUND_V6 in acl_tables:
            remove_acl_table(duthost, acl_tables[ACL_TABLE_BMC_NORTHBOUND_V6])
        if ACL_TABLE_BMC_SOUTHBOUND_V6 in acl_tables:
            remove_acl_table(duthost, acl_tables[ACL_TABLE_BMC_SOUTHBOUND_V6])

        # remove vlan
        remove_all_vlans(duthost)

    @pytest.fixture(scope="function", autouse=True)
    def setup_static_acl_rules(self, duthost, setup_teardown):
        rack_topo, _, _, _ = setup_teardown
        acl_tables = rack_topo['config']['acl_tables']
        static_acl_rule_file = os.path.join(ACL_RULE_SRC_FILE_PREFIX, rack_topo['config']['static_acl_rule_file'])
        # setup acl rules
        if ACL_TABLE_BMC_NORTHBOUND in acl_tables:
            add_acl_rule(duthost, static_acl_rule_file, acl_tables[ACL_TABLE_BMC_NORTHBOUND])
        if ACL_TABLE_BMC_NORTHBOUND_V6 in acl_tables:
            add_acl_rule(duthost, static_acl_rule_file, acl_tables[ACL_TABLE_BMC_NORTHBOUND_V6])
        if ACL_TABLE_BMC_SOUTHBOUND_V6 in acl_tables:
            add_acl_rule(duthost, static_acl_rule_file, acl_tables[ACL_TABLE_BMC_SOUTHBOUND_V6])
        # clear existing arp/ndp table before test
        duthost.command("sonic-clear arp")
        duthost.command("sonic-clear ndp")

        yield

        # remove acl rules
        if ACL_TABLE_BMC_NORTHBOUND in acl_tables:
            remove_acl_rule(duthost, acl_tables[ACL_TABLE_BMC_NORTHBOUND])
        if ACL_TABLE_BMC_NORTHBOUND_V6 in acl_tables:
            remove_acl_rule(duthost, acl_tables[ACL_TABLE_BMC_NORTHBOUND_V6])
        if ACL_TABLE_BMC_SOUTHBOUND_V6 in acl_tables:
            remove_acl_rule(duthost, acl_tables[ACL_TABLE_BMC_SOUTHBOUND_V6])

    def setup_dynamic_v6_acl_rules_by_acl_loader(self, duthost, rack_topo, dynamic_northbound_v6, dynamic_southbound_v6):
        if 'dynamic_acl_rule_template_file' not in rack_topo['config']:
            pytest.skip("No dynamic acl rule template file")
        dynamic_acl_rule_template_file = rack_topo['config']['dynamic_acl_rule_template_file']

        acl_tables = rack_topo['config']['acl_tables']
        if ACL_TABLE_BMC_NORTHBOUND_V6 not in acl_tables or ACL_TABLE_BMC_SOUTHBOUND_V6 not in acl_tables:
            pytest.skip("No IPv6 ACL tables")

        j2_env = jinja2.Environment(loader=jinja2.FileSystemLoader(ACL_RULE_SRC_FILE_PREFIX))
        j2_tpl = j2_env.get_template(dynamic_acl_rule_template_file)
        dynamic_acl_rule_file = os.path.join(ACL_RULE_SRC_FILE_PREFIX, 'dynamic_acl_rules.json')
        with open(dynamic_acl_rule_file, 'w') as fout:
            fout.write(j2_tpl.render(dynamic_northbound_v6=dynamic_northbound_v6, dynamic_southbound_v6=dynamic_southbound_v6))

        add_acl_rule(duthost, dynamic_acl_rule_file, acl_tables[ACL_TABLE_BMC_NORTHBOUND_V6])
        add_acl_rule(duthost, dynamic_acl_rule_file, acl_tables[ACL_TABLE_BMC_SOUTHBOUND_V6])
        # clear existing arp/ndp table before test
        duthost.command("sonic-clear arp")
        duthost.command("sonic-clear ndp")

    def build_gcu_dynamic_acl_rule_patch(self, bmc, upstream, bmc_l4_ports, upstream_l4_ports, ip_protocol=None):
        seq_id = 3000
        bmc_northbound_v6_dynamic_rules = build_gcu_acl_rule_patch(
            seq_id, action=ACL_PACKET_ACTION_FORWARD, ethertype=ETHERTYPE_IPV6,
            interfaces=[bmc.port_name], ip_protocol=ip_protocol,
            src_ipv6=bmc.ipv6_addr + "/128", dst_ipv6=upstream.ipv6_addr + "/128",
            l4_src_port=bmc_l4_ports, l4_dst_port=upstream_l4_ports)
        bmc_southbound_v6_dynamic_rules = build_gcu_acl_rule_patch(
            seq_id, action=ACL_PACKET_ACTION_FORWARD, ethertype=ETHERTYPE_IPV6, ip_protocol=ip_protocol,
            src_ipv6=upstream.ipv6_addr + "/128", dst_ipv6=bmc.ipv6_addr + "/128",
            l4_src_port=upstream_l4_ports, l4_dst_port=bmc_l4_ports)
        return bmc_northbound_v6_dynamic_rules, bmc_southbound_v6_dynamic_rules

    @pytest.mark.parametrize("disguise", ["none", "dst_shelf_rm", "upstream"])
    def test_bmc_otw_req_1_v4(self, duthost, ptfadapter, setup_teardown, disguise):
        """
        Request 1: BMCs are not allowed to communicate with each other
        Test:
          1. [No disguise] BMC cannot use it's own IP as SRC_IP to send packet to other BMC
          2. [BMC disguise itself as RM of target power-shelf] BMC cannot use dest shelf RM's
             IP as SRC_IP to send packet to other BMC
          3. [BMC disguise itself as upstream service] BMC cannot use upstream service's IP
             as SRC_IP to send packet to other BMC
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        for src_bmc, dst_bmc in self.shuffle_src_dst_pairs(bmc_hosts, max_len=10):
            if disguise == "dst_shelf_rm":
                dst_shelf = self.get_shelf_by_bmc(shelfs, dst_bmc)
                src_bmc.ipv4_addr = dst_shelf.rm.ipv4_addr
                src_bmc.ipv4_prefix = dst_shelf.rm.ipv4_prefix
            elif disguise == "upstream":
                src_bmc.ipv4_addr = SAMPLE_UPSTREAM_IPV4_ADDR
                src_bmc.ipv4_prefix = SAMPLE_UPSTREAM_IPV4_PREFIX
            send_and_verify_traffic_v4(duthost, ptfadapter, src_bmc, [dst_bmc], expect_behavior="drop")

    @pytest.mark.parametrize("disguise", ["none", "dst_shelf_rm", "upstream"])
    def test_bmc_otw_req_1_v6(self, duthost, ptfadapter, setup_teardown, disguise):
        """
        Request 1: BMCs are not allowed to communicate with each other
        Test:
          1. [No disguise] BMC cannot use it's own IP as SRC_IP to send packet to other BMC
          2. [BMC disguise itself as RM of target power-shelf] BMC cannot use dest shelf RM's
             IP as SRC_IP to send packet to other BMC
          3. [BMC disguise itself as upstream service] BMC cannot use upstream service's IP
             as SRC_IP to send packet to other BMC
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        shelfs_v6 = self.filter_shelf_with_rm_ipv6(shelfs)
        if disguise == "dst_shelf_rm" and len(shelfs_v6) == 0:
            pytest.skip("No shelf has IPv6 address configured on RM")
        for src_bmc, dst_bmc in self.shuffle_src_dst_pairs(bmc_hosts, max_len=10):
            if disguise == "dst_shelf_rm":
                dst_shelf = self.get_shelf_by_bmc(shelfs, dst_bmc)
                if dst_shelf.rm.ipv6_addr is None:
                    continue
                src_bmc.ipv6_addr = dst_shelf.rm.ipv6_addr
                src_bmc.ipv6_prefix = dst_shelf.rm.ipv6_prefix
            elif disguise == "upstream":
                src_bmc.ipv6_addr = SAMPLE_UPSTREAM_IPV6_ADDR
                src_bmc.ipv6_prefix = SAMPLE_UPSTREAM_IPV6_PREFIX
            send_and_verify_traffic_v6(duthost, ptfadapter, src_bmc, [dst_bmc], expect_behavior="drop")

    def test_bmc_otw_req_2_v6(self, duthost, ptfadapter, setup_teardown):
        """
        Request 2: Direct access is not allowed from outside to BMC by default
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        for rand_bmc in self.shuffle_ports(bmc_hosts, max_len=10):
            upstream = self.rand_one(upstream_ports)
            send_and_verify_traffic_v6(duthost, ptfadapter, upstream, [rand_bmc], expect_behavior="drop")

    def test_bmc_otw_req_3_v4(self, duthost, ptfadapter, setup_teardown):
        """
        Request 3: Direct access is not allowed from BMC to outside by default.
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        for rand_bmc in self.shuffle_ports(bmc_hosts, max_len=10):
            send_and_verify_traffic_v4(duthost, ptfadapter, rand_bmc, upstream_ports, expect_behavior="drop")

    def test_bmc_otw_req_3_v6(self, duthost, ptfadapter, setup_teardown):
        """
        Request 3: Direct access is not allowed from BMC to outside by default.
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        for rand_bmc in self.shuffle_ports(bmc_hosts, max_len=10):
            send_and_verify_traffic_v6(duthost, ptfadapter, rand_bmc, upstream_ports, expect_behavior="drop")

    @pytest.mark.parametrize("l4_port_mode", [L4Ports.MODE_SINGLE_RANDOM, L4Ports.MODE_RANGE_RANDOM, L4Ports.MODE_SINGLE_SSH, L4Ports.MODE_SINGLE_HTTPS])
    def test_bmc_otw_req_4_v6_tcp(self, duthost, ptfadapter, setup_teardown, l4_port_mode):
        """
        Request 4: Direct access is conditional allowed after loading AD-HOC ACL rules
        Request 5: Direct access to BMC can be only initiate from remote server
        This testcase covers both Request 4 and 5.
        TEST 1: [TCP] Setup full ACL rules (including AD-HOC) via acl-loader, verify:
            a. BMC cannot send TCP SYN packet to upstream
            b. BMC can send TCP SYN_ACK and ACK packet to upstream
            c. upstream can send TCP SYN, SYN_ACK and ACK packet to BMC
        """
        rack_topo, _, bmc_hosts, upstream_ports = setup_teardown
        vlan_interfaces_ipv6 = get_vlan_interfaces_ipv6(duthost)
        for rand_bmc in self.shuffle_ports(bmc_hosts, max_len=5):
            rand_upstream = self.rand_one(upstream_ports)
            bmc_l4_ports = L4Ports.rand(l4_port_mode)
            upstream_l4_ports = L4Ports.rand(l4_port_mode)
            dynamic_northbound_v6 = {
                **prod_allow_tcpv6_synack_nth(NTH_AD_HOC_ALLOW_TCP_SYNACK_SEQ_START, rand_upstream, l4_src_port=bmc_l4_ports),
                **prod_allow_tcpv6_nth(NTH_AD_HOC_ALLOW_PROTOCOL_SEQ_START, rand_upstream, l4_src_port=bmc_l4_ports),
                **prod_bmc_otw_basic_acl_set_nth(vlan_interfaces_ipv6),
            }
            dynamic_southbound_v6 = {
                **prod_allow_tcpv6_sth(STH_AD_HOC_ALLOW_PROTOCOL_SEQ_START, rand_upstream, l4_dst_port=bmc_l4_ports),
            }
            self.setup_dynamic_v6_acl_rules_by_acl_loader(duthost, rack_topo, dynamic_northbound_v6, dynamic_southbound_v6)
            for tcp_flags in ["S", "SA", "A"]:
                northbound_pkt = testutils.simple_tcpv6_packet(
                    eth_dst=duthost.facts['router_mac'],
                    ipv6_src=rand_bmc.ipv6_addr,
                    ipv6_dst=rand_upstream.ipv6_addr,
                    tcp_sport=bmc_l4_ports.sample_port(),
                    tcp_dport=upstream_l4_ports.sample_port(),
                    tcp_flags=tcp_flags,
                )
                if tcp_flags == "S":
                    send_and_verify_traffic_v6(duthost, ptfadapter, rand_bmc, upstream_ports, expect_behavior="drop", pkt=northbound_pkt)
                else:
                    send_and_verify_traffic_v6(duthost, ptfadapter, rand_bmc, upstream_ports, expect_behavior="accept", pkt=northbound_pkt)
            for tcp_flags in ["S", "SA", "A"]:
                southbound_pkt = testutils.simple_tcpv6_packet(
                    eth_dst=duthost.facts['router_mac'],
                    ipv6_src=rand_upstream.ipv6_addr,
                    ipv6_dst=rand_bmc.ipv6_addr,
                    tcp_sport=upstream_l4_ports.sample_port(),
                    tcp_dport=bmc_l4_ports.sample_port(),
                    tcp_flags=tcp_flags,
                )
                send_and_verify_traffic_v6(duthost, ptfadapter, rand_upstream, [rand_bmc], expect_behavior="accept", pkt=southbound_pkt)

    def test_bmc_otw_req_4_v6_icmpv6_echo(self, duthost, ptfadapter, setup_teardown):
        """
        Request 4: Direct access is conditional allowed after loading AD-HOC ACL rules
        TEST 2: [ICMP] Setup full ACL rules (including AD-HOC) via acl-loader, verify:
            a. Upstream can send ICMPv6 Echo Request packet to BMC.
            b. BMC can send ICMPv6 Echo Reply packet to upstream.
        """
        rack_topo, _, bmc_hosts, upstream_ports = setup_teardown
        vlan_interfaces_ipv6 = get_vlan_interfaces_ipv6(duthost)
        for rand_bmc in self.shuffle_ports(bmc_hosts, max_len=5):
            rand_upstream = self.rand_one(upstream_ports)
            dynamic_northbound_v6 = {
                **prod_allow_icmpv6_echo_nth(NTH_AD_HOC_ALLOW_PROTOCOL_SEQ_START, rand_upstream),
                **prod_bmc_otw_basic_acl_set_nth(vlan_interfaces_ipv6),
            }
            dynamic_southbound_v6 = {
                **prod_allow_icmpv6_echo_sth(STH_AD_HOC_ALLOW_PROTOCOL_SEQ_START, rand_upstream),
            }
            self.setup_dynamic_v6_acl_rules_by_acl_loader(duthost, rack_topo, dynamic_northbound_v6, dynamic_southbound_v6)
            northbound_pkt = testutils.simple_icmpv6_packet(
                eth_dst=duthost.facts['router_mac'],
                ipv6_src=rand_bmc.ipv6_addr,
                ipv6_dst=rand_upstream.ipv6_addr,
                icmp_type=ICMPV6_TYPE_ECHO_REPLY
            )
            southbound_pkt = testutils.simple_icmpv6_packet(
                eth_dst=duthost.facts['router_mac'],
                ipv6_src=rand_upstream.ipv6_addr,
                ipv6_dst=rand_bmc.ipv6_addr,
                icmp_type=ICMPV6_TYPE_ECHO_REQUEST
            )
            send_and_verify_traffic_v6(duthost, ptfadapter, rand_bmc, upstream_ports, expect_behavior="accept", pkt=northbound_pkt)
            send_and_verify_traffic_v6(duthost, ptfadapter, rand_upstream, [rand_bmc], expect_behavior="accept", pkt=southbound_pkt)

    def test_bmc_otw_req_4_v6_icmpv6_echo_bmc2mx(self, duthost, ptfadapter, mx_common_setup_teardown, setup_teardown):
        """
        Request 4: Direct access is conditional allowed after loading AD-HOC ACL rules
        TEST 3: [Potential] Ping6 between Mx and BMC is allowed when AD-HOC rules are applied on Mx.
            a. BMC can send ICMPv6 Echo Reply to Mx. (Allow Mx ping6 BMC)
            b. BMC can send ICMPv6 Echo Request to Mx. (Allow BMC ping6 Mx)
        """
        rack_topo, _, bmc_hosts, _ = setup_teardown
        vlan_interfaces_ipv6 = get_vlan_interfaces_ipv6(duthost)
        router_mac = duthost.facts['router_mac']
        self.setup_dynamic_v6_acl_rules_by_acl_loader(duthost, rack_topo, prod_bmc_otw_basic_acl_set_nth(vlan_interfaces_ipv6), {})
        for vlan_name, vlan_info in duthost.get_vlan_brief().items():
            vlan_members = vlan_info["members"]
            vlan_interfaces_ipv6 = vlan_info.get('interface_ipv6', [])
            if not vlan_interfaces_ipv6:
                logging.info(f"No IPv6 gateway IP on {vlan_name}, skip this vlan")
                continue
            vlan_ip6 = vlan_interfaces_ipv6[0].split('/')[0]
            rand_bmc = self.rand_bmc_from_vlan_members(bmc_hosts, vlan_members)
            if rand_bmc is None:
                logging.info(f"No BMC found in {vlan_name}, skip this vlan")
                continue

            def func(pkts):
                pytest_assert(len([pkt for pkt in pkts if pkt[scapy.IPv6].tc == test_ipv6_tc]) > 0, "Didn't get packet with expected ipv6 tc")
            test_ipv6_tc = 136
            with capture_and_check_packet_on_dut(duthost=duthost, pkts_filter='"icmp6[icmp6type]==icmp6-echo"', pkts_validator=func, wait_time=1):
                logging.info("Send icmp6 echo request packet from ptf ipv6:%s to DUT vlan ipv6:%s" % (rand_bmc.ipv6_addr, vlan_ip6))
                req_pkt = testutils.simple_icmpv6_packet(eth_dst=router_mac, ipv6_src=rand_bmc.ipv6_addr, ipv6_dst=vlan_ip6,
                                                         ipv6_tc=test_ipv6_tc, icmp_type=ICMPV6_TYPE_ECHO_REQUEST, icmp_code=ICMPV6_CODE_ECHO_REQUEST)
                ptfadapter.dataplane.flush()
                testutils.send(ptfadapter, pkt=req_pkt, port_id=rand_bmc.ptf_port_id)
            with capture_and_check_packet_on_dut(duthost=duthost, pkts_filter='"icmp6[icmp6type]==icmp6-echoreply"', pkts_validator=func, wait_time=1):
                logging.info("Send icmp6 echo reply packet from ptf ipv6:%s to DUT vlan ipv6:%s" % (rand_bmc.ipv6_addr, vlan_ip6))
                req_pkt = testutils.simple_icmpv6_packet(eth_dst=router_mac, ipv6_src=rand_bmc.ipv6_addr, ipv6_dst=vlan_ip6,
                                                         ipv6_tc=test_ipv6_tc, icmp_type=ICMPV6_TYPE_ECHO_REPLY, icmp_code=ICMPV6_CODE_ECHO_REPLY)
                ptfadapter.dataplane.flush()
                testutils.send(ptfadapter, pkt=req_pkt, port_id=rand_bmc.ptf_port_id)

    @pytest.mark.xfail(reason="Expect fail until ICMPv6 ACL Yang model is fixed")
    @pytest.mark.parametrize("ip_protocol", [IP_PROTOCOL_TCP, IP_PROTOCOL_UDP])
    @pytest.mark.parametrize("l4_port_mode", [L4Ports.MODE_SINGLE_RANDOM, L4Ports.MODE_RANGE_RANDOM])
    def test_bmc_otw_req_4_v6_gcu_inc_update(self, duthost, ptfadapter, setup_teardown, ip_protocol, l4_port_mode):
        """
        Request 4: Direct access is conditional allowed after loading AD-HOC ACL rules
        TEST 2: Incrementally setup AD-HOC ACL rules via GCU
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        acl_tables = rack_topo['config']['acl_tables']
        for rand_bmc in self.shuffle_ports(bmc_hosts, max_len=5):
            rand_upstream = self.rand_one(upstream_ports)
            bmc_l4_ports = L4Ports.rand(l4_port_mode)
            upstream_l4_ports = L4Ports.rand(l4_port_mode)
            bmc_northbound_v6_dynamic_rules, bmc_southbound_v6_dynamic_rules = \
                self.build_gcu_dynamic_acl_rule_patch(rand_bmc, rand_upstream, bmc_l4_ports, upstream_l4_ports, IP_PROTOCOL_MAP[ip_protocol])
            try:
                gcu_add_acl_rule(duthost, acl_tables[ACL_TABLE_BMC_NORTHBOUND_V6], bmc_northbound_v6_dynamic_rules)
                gcu_add_acl_rule(duthost, acl_tables[ACL_TABLE_BMC_SOUTHBOUND_V6], bmc_southbound_v6_dynamic_rules)
                if ip_protocol == IP_PROTOCOL_TCP:
                    northbound_pkt = testutils.simple_tcpv6_packet(eth_dst=duthost.facts['router_mac'], ipv6_src=rand_bmc.ipv6_addr, ipv6_dst=rand_upstream.ipv6_addr,
                                                                   tcp_sport=bmc_l4_ports.sample_port(), tcp_dport=upstream_l4_ports.sample_port())
                    southbound_pkt = testutils.simple_tcpv6_packet(eth_dst=duthost.facts['router_mac'], ipv6_src=rand_upstream.ipv6_addr, ipv6_dst=rand_bmc.ipv6_addr,
                                                                   tcp_sport=upstream_l4_ports.sample_port(), tcp_dport=bmc_l4_ports.sample_port())
                elif ip_protocol == IP_PROTOCOL_UDP:
                    northbound_pkt = testutils.simple_udpv6_packet(eth_dst=duthost.facts['router_mac'], ipv6_src=rand_bmc.ipv6_addr, ipv6_dst=rand_upstream.ipv6_addr,
                                                                   udp_sport=bmc_l4_ports.sample_port(), udp_dport=upstream_l4_ports.sample_port())
                    southbound_pkt = testutils.simple_udpv6_packet(eth_dst=duthost.facts['router_mac'], ipv6_src=rand_upstream.ipv6_addr, ipv6_dst=rand_bmc.ipv6_addr,
                                                                   udp_sport=upstream_l4_ports.sample_port(), udp_dport=bmc_l4_ports.sample_port())
                send_and_verify_traffic_v6(duthost, ptfadapter, rand_bmc, upstream_ports, expect_behavior="accept", pkt=northbound_pkt)
                send_and_verify_traffic_v6(duthost, ptfadapter, rand_upstream, [rand_bmc], expect_behavior="accept", pkt=southbound_pkt)
            finally:
                gcu_remove_acl_rule(duthost, acl_tables[ACL_TABLE_BMC_NORTHBOUND_V6], bmc_northbound_v6_dynamic_rules.keys())
                gcu_remove_acl_rule(duthost, acl_tables[ACL_TABLE_BMC_SOUTHBOUND_V6], bmc_southbound_v6_dynamic_rules.keys())

    def test_bmc_otw_req_6_v4_mx2bmc(self, duthost, ptfadapter, mx_common_setup_teardown, setup_teardown):
        # Considering remove this testcase because Mx2BMC traffic doesn't affected by ACL.
        """
        Request 6: Mx allows inter-access between the directly connected BMC and itself.
        TEST 1: Verify Mx can send ICMP packet to BMC
        """
        ptf_idx_to_port_name, _, _ = mx_common_setup_teardown
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        cmd_tpl = "python3 -c \"from ptf import testutils; import scapy.all as scapy2; " \
                  "scapy2.sendp(testutils.simple_icmp_packet(ip_dst='{}'), iface='{}')\""
        for rand_bmc in self.shuffle_ports(bmc_hosts, max_len=10):
            pkt = testutils.simple_icmp_packet(ip_dst='{}'.format(rand_bmc.ipv4_addr))
            exp_pkt = build_exp_pkt(pkt)
            cmd = cmd_tpl.format(rand_bmc.ipv4_addr, ptf_idx_to_port_name[rand_bmc.ptf_port_id])
            ptfadapter.dataplane.flush()
            duthost.shell(cmd)
            testutils.verify_packet(ptfadapter, exp_pkt, rand_bmc.ptf_port_id, timeout=10)

    def test_bmc_otw_req_6_v4_bmc2mx(self, duthost, ptfadapter, setup_teardown):
        """
        Request 5: Mx allows inter-access between the directly connected BMC and itself.
        TEST 2: Ping between Mx and BMC is allowed by default.
            a. BMC can send ICMP Echo Reply to Mx. (Allow Mx ping BMC)
            b. BMC can send ICMP Echo Request to Mx. (Allow BMC ping Mx)
        """
        _, _, bmc_hosts, _ = setup_teardown
        router_mac = duthost.facts['router_mac']
        for vlan_name, vlan_info in duthost.get_vlan_brief().items():
            vlan_members = vlan_info["members"]
            vlan_prefix = vlan_info["interface_ipv4"][0]
            vlan_ip = vlan_prefix.split("/")[0]
            rand_bmc = self.rand_bmc_from_vlan_members(bmc_hosts, vlan_members)
            if rand_bmc is None:
                logging.info(f"No BMC found in {vlan_name}, skip this vlan")
                continue

            def func(pkts):
                pytest_assert(len([pkt for pkt in pkts if pkt[scapy.IP].tos == test_ipv4_tos]) > 0, "Didn't get packet with expected ipv4 tos")
            test_ipv4_tos = 134
            with capture_and_check_packet_on_dut(duthost=duthost, pkts_filter='"icmp[icmptype]==icmp-echo"', pkts_validator=func):
                logging.info("Send icmp echo request packet from ptf ip:%s to DUT vlan ip:%s" % (rand_bmc.ipv4_addr, vlan_ip))
                req_pkt = testutils.simple_icmp_packet(eth_dst=router_mac, ip_src=rand_bmc.ipv4_addr, ip_dst=vlan_ip,
                                                       ip_tos=test_ipv4_tos, icmp_type=ICMP_TYPE_ECHO_REQUEST, icmp_code=ICMP_CODE_ECHO_REQUEST)
                ptfadapter.dataplane.flush()
                testutils.send(ptfadapter, pkt=req_pkt, port_id=rand_bmc.ptf_port_id)
            with capture_and_check_packet_on_dut(duthost=duthost, pkts_filter='"icmp[icmptype] == icmp-echoreply"', pkts_validator=func):
                logging.info("Send icmp echo reply packet from ptf ip:%s to DUT vlan ip:%s" % (rand_bmc.ipv4_addr, vlan_ip))
                req_pkt = testutils.simple_icmp_packet(eth_dst=router_mac, ip_src=rand_bmc.ipv4_addr, ip_dst=vlan_ip,
                                                       ip_tos=test_ipv4_tos, icmp_type=ICMP_TYPE_ECHO_REPLY, icmp_code=ICMP_CODE_ECHO_REPLY)
                ptfadapter.dataplane.flush()
                testutils.send(ptfadapter, pkt=req_pkt, port_id=rand_bmc.ptf_port_id)

    def test_bmc_otw_req_7_v4_same_shelf(self, duthost, ptfadapter, setup_teardown):
        """
        Request 7: Mx allows directly connected RM and directly connected BMCs to access each other
        TEST 1: BMC can communicate with RM in the same shelf
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        for shelf in shelfs:
            for rand_bmc in self.shuffle_ports(shelf.bmc_hosts, max_len=5):
                send_and_verify_traffic_v4(duthost, ptfadapter, rand_bmc, [shelf.rm], expect_behavior="accept")
                send_and_verify_traffic_v4(duthost, ptfadapter, shelf.rm, [rand_bmc], expect_behavior="accept")

    @pytest.mark.parametrize("disguise", ["none", "dst_shelf_bmc", "dst_rm", "upstream"])
    def test_bmc_otw_req_7_v4_diff_shelf(self, duthost, ptfadapter, setup_teardown, disguise):
        """
        Request 7: Mx allows directly connected RM and directly connected BMCs to access each other
        TEST 2: BMC cannot send packet to RM in different power-shelf
          2.1 [No disguise] BMC cannot use it's own IP as SRC_IP to send packet
          2.2 [BMC disguise itself as BMC of target power-shelf] BMC cannot use dest shelf BMCs' IP
              as SRC_IP to send packet
          2.3 [BMC disguise itself as RM of target power-shelf] BMC cannot use dest shelf RM's IP
              as SRC_IP to send packet
          2.4 [BMC disguise itself as upstream service] BMC cannot use upstream service's IP as
              SRC_IP to send packet
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        if len(shelfs) <= 1:
            pytest.skip("Only one shelf on the rack")
        for bmc_shelf in shelfs:
            for rm_shelf in shelfs:
                if bmc_shelf.id != rm_shelf.id:
                    src_bmc = self.rand_one(bmc_shelf.bmc_hosts)
                    if disguise == "dst_shelf_bmc":
                        dst_shelf_bmc = self.rand_one(rm_shelf.bmc_hosts)
                        src_bmc.ipv4_addr = dst_shelf_bmc.ipv4_addr
                        src_bmc.ipv4_prefix = dst_shelf_bmc.ipv4_prefix
                    elif disguise == "dst_rm":
                        src_bmc.ipv4_addr = rm_shelf.rm.ipv4_addr
                        src_bmc.ipv4_prefix = rm_shelf.rm.ipv4_prefix
                    elif disguise == "upstream":
                        src_bmc.ipv4_addr = SAMPLE_UPSTREAM_IPV4_ADDR
                        src_bmc.ipv4_prefix = SAMPLE_UPSTREAM_IPV4_PREFIX
                    send_and_verify_traffic_v4(duthost, ptfadapter, src_bmc, [rm_shelf.rm], expect_behavior="drop")

    def test_bmc_otw_req_7_v6_same_shelf(self, duthost, ptfadapter, setup_teardown):
        """
        Request 6: Mx allows directly connected RM and directly connected BMCs to access each other
        TEST 1: BMC can communicate with RM in the same shelf
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        shelfs_v6 = self.filter_shelf_with_rm_ipv6(shelfs)
        if len(shelfs_v6) < 1:
            pytest.skip("No shelf has IPv6 address configured on RM")
        for shelf in shelfs_v6:
            for rand_bmc in self.shuffle_ports(shelf.bmc_hosts, max_len=5):
                send_and_verify_traffic_v6(duthost, ptfadapter, rand_bmc, [shelf.rm], expect_behavior="accept")
                send_and_verify_traffic_v6(duthost, ptfadapter, shelf.rm, [rand_bmc], expect_behavior="accept")

    @pytest.mark.parametrize("disguise", ["none", "dst_shelf_bmc", "dst_rm", "upstream"])
    def test_bmc_otw_req_7_v6_diff_shelf(self, duthost, ptfadapter, setup_teardown, disguise):
        """
        Request 6: Mx allows directly connected RM and directly connected BMCs to access each other
        TEST 2: BMC cannot send packet to RM in different power-shelf
          2.1 [No disguise] BMC cannot use it's own IP as SRC_IP to send packet
          2.2 [BMC disguise itself as BMC of target power-shelf] BMC cannot use dest shelf BMCs' IP
              as SRC_IP to send packet
          2.3 [BMC disguise itself as RM of target power-shelf] BMC cannot use dest shelf RM's IP
              as SRC_IP to send packet
          2.4 [BMC disguise itself as upstream service] BMC cannot use upstream service's IP as
              SRC_IP to send packet
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        shelfs_v6 = self.filter_shelf_with_rm_ipv6(shelfs)
        if len(shelfs) <= 1:
            pytest.skip("Only one power-shelf on the rack")
        if len(shelfs_v6) == 0:
            pytest.skip("No power-shelf has IPv6 address configured on RM")
        for bmc_shelf in shelfs:
            for rm_shelf in shelfs_v6:
                if bmc_shelf.id != rm_shelf.id:
                    src_bmc = self.rand_one(bmc_shelf.bmc_hosts)
                    if disguise == "dst_shelf_bmc":
                        dst_shelf_bmc = self.rand_one(rm_shelf.bmc_hosts)
                        src_bmc.ipv6_addr = dst_shelf_bmc.ipv6_addr
                        src_bmc.ipv6_prefix = dst_shelf_bmc.ipv6_prefix
                    elif disguise == "dst_rm":
                        src_bmc.ipv6_addr = rm_shelf.rm.ipv6_addr
                        src_bmc.ipv6_prefix = rm_shelf.rm.ipv6_prefix
                    elif disguise == "upstream":
                        src_bmc.ipv6_addr = SAMPLE_UPSTREAM_IPV6_ADDR
                        src_bmc.ipv6_prefix = SAMPLE_UPSTREAM_IPV6_PREFIX
                    send_and_verify_traffic_v6(duthost, ptfadapter, src_bmc, [rm_shelf.rm], expect_behavior="drop")

    def test_bmc_otw_ip2me_bgpv6(self, duthost, setup_teardown):
        """
        Potential Request 1: BGPv6 between Mx and M0 should be allowed by static ACL rules
        Apply static ACL rules on Mx, then restart BGP. Verify BGPv6 session can be established.
        """
        # Shutdown BGPv6 neighbors
        bgp_neigh = duthost.bgp_facts()['ansible_facts']['bgp_neighbors']
        neigh_v6 = [neigh_ip for neigh_ip in bgp_neigh.keys() if ipaddress.ip_address(neigh_ip).version == 6]
        if len(neigh_v6) == 0:
            pytest.skip("No BGPv6 neighbor")
        for neigh_ip in neigh_v6:
            duthost.command("config bgp shutdown neigh {}".format(neigh_ip))
        duthost.command("sonic-clear arp")
        duthost.command("sonic-clear ndp")
        # Startup BGPv6 neighbors
        for neigh_ip in neigh_v6:
            duthost.command("config bgp startup neigh {}".format(neigh_ip))
        time.sleep(10)  # wait for BGPv6 session to be established
        bgp_neigh = duthost.bgp_facts()['ansible_facts']['bgp_neighbors']
        for neigh_ip, neigh_fact in bgp_neigh.items():
            pytest_assert(neigh_fact['state'].lower() == 'established', "BGPv6 session with {} is not established".format(neigh_ip))

    def test_bmc_otw_allow_dhcp_v4_broadcast_bmc2mx(self, duthost, ptfadapter, setup_teardown):
        """
        Potential Request 2: DHCPv4 and DHCPv6 traffic between BMC and Mx should be allowed by static ACL rules
        Send DHCPv4 broadcast packet from BMCs. Verify DHCPv4 packet can be received by Mx.
        """
        _, _, bmc_hosts, _ = setup_teardown
        for vlan_name, vlan_info in duthost.get_vlan_brief().items():
            vlan_members = vlan_info["members"]
            rand_bmc = self.rand_bmc_from_vlan_members(bmc_hosts, vlan_members)
            if rand_bmc is None:
                logging.info("No BMC found in %s, skip this vlan" % vlan_name)
                continue

            def func(pkts):
                pytest_assert(len([pkt for pkt in pkts if pkt[scapy.BOOTP].xid == test_xid]) > 0, "Didn't get packet with expected BOOTP xid")
            bmc_mac = ptfadapter.dataplane.get_mac(0, rand_bmc.ptf_port_id).decode('utf-8')

            test_xid = 123
            with capture_and_check_packet_on_dut(
                duthost=duthost,
                interface=rand_bmc.port_name,
                pkts_filter="ether src %s and udp dst port %s" % (bmc_mac, DHCP_UDP_SERVER_PORT),
                pkts_validator=func
            ):
                req_pkt = scapy.Ether(dst=DHCP_MAC_BROADCAST, src=bmc_mac) \
                    / scapy.IP(src=DHCP_IP_DEFAULT_ROUTE, dst=DHCP_IP_BROADCAST) \
                    / scapy.UDP(sport=DHCP_UDP_CLIENT_PORT, dport=DHCP_UDP_SERVER_PORT) \
                    / scapy.BOOTP(chaddr=bmc_mac, xid=test_xid) \
                    / scapy.DHCP(options=[("message-type", "discover"), "end"])
                ptfadapter.dataplane.flush()
                testutils.send_packet(ptfadapter, pkt=req_pkt, port_id=rand_bmc.ptf_port_id)

    def test_bmc_otw_allow_dhcp_v4_unicast_bmc2mx(self, duthost, ptfadapter, setup_teardown):
        """
        Potential Request 2: DHCPv4 and DHCPv6 traffic between BMC and Mx should be allowed by static ACL rules
        Send DHCPv4 unicast packet from BMCs. Verify DHCPv4 packet can be received by Mx.
        """
        _, _, bmc_hosts, _ = setup_teardown
        for vlan_name, vlan_info in duthost.get_vlan_brief().items():
            vlan_members = vlan_info["members"]
            rand_bmc = self.rand_bmc_from_vlan_members(bmc_hosts, vlan_members)
            if rand_bmc is None:
                logging.info("No BMC found in %s, skip this vlan" % vlan_name)
                continue

            def func(pkts):
                pytest_assert(len([pkt for pkt in pkts if pkt[scapy.BOOTP].xid == test_xid]) > 0, "Didn't get packet with expected BOOTP xid")
            bmc_mac = ptfadapter.dataplane.get_mac(0, rand_bmc.ptf_port_id).decode('utf-8')

            vlan_prefix = vlan_info["interface_ipv4"][0]
            vlan_ip = vlan_prefix.split("/")[0]
            test_xid = 124
            with capture_and_check_packet_on_dut(
                duthost=duthost,
                interface=rand_bmc.port_name,
                pkts_filter="ether src %s and udp dst port %s" % (bmc_mac, DHCP_UDP_SERVER_PORT),
                pkts_validator=func
            ):
                req_pkt = scapy.Ether(dst=duthost.facts['router_mac'], src=bmc_mac) \
                    / scapy.IP(src=rand_bmc.ipv4_addr, dst=vlan_ip) \
                    / scapy.UDP(sport=DHCP_UDP_CLIENT_PORT, dport=DHCP_UDP_SERVER_PORT) \
                    / scapy.BOOTP(chaddr=bmc_mac, xid=test_xid) \
                    / scapy.DHCP(options=[("message-type", "force_renew"), "end"])
                ptfadapter.dataplane.flush()
                testutils.send_packet(ptfadapter, pkt=req_pkt, port_id=rand_bmc.ptf_port_id)

    def test_bmc_otw_allow_dhcp_v6_multicast_bmc2mx(self, duthost, ptfadapter, setup_teardown):
        """
        Potential Request 2: When BMC-OTW feature enabled, BMC should be able to acquire IPv6 address via DHCPv6
        Send DHCPv6 multicast packet from BMCs. Verify DHCPv6 packet can be received by Mx.
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        vlan_interfaces_ipv6 = get_vlan_interfaces_ipv6(duthost)
        self.setup_dynamic_v6_acl_rules_by_acl_loader(duthost, rack_topo, prod_bmc_otw_basic_acl_set_nth(vlan_interfaces_ipv6), {})
        for vlan_name, vlan_info in duthost.get_vlan_brief().items():
            vlan_members = vlan_info["members"]
            rand_bmc = self.rand_bmc_from_vlan_members(bmc_hosts, vlan_members)
            if rand_bmc is None:
                logging.info("No BMC found in %s, skip this vlan" % vlan_name)
                continue

            def func(pkts):
                pytest_assert(len([pkt for pkt in pkts if pkt[DHCP6_Solicit].trid == test_trid]) > 0, "Didn't get packet with expected transaction id")
            bmc_mac = ptfadapter.dataplane.get_mac(0, rand_bmc.ptf_port_id).decode('utf-8')

            test_trid = 119
            with capture_and_check_packet_on_dut(
                duthost=duthost,
                interface=rand_bmc.port_name,
                pkts_filter="ether src %s and udp dst port %s" % (bmc_mac, DHCPV6_UDP_SERVER_PORT),
                pkts_validator=func
            ):
                cmd_get_link_local_ipv6_addr = "ip addr show %s | grep inet6 | grep 'scope link' | awk '{print $2}' | cut -d '/' -f1" % rand_bmc.port_name
                link_local_ipv6_addr = duthost.shell(cmd_get_link_local_ipv6_addr)["stdout"]
                pytest_assert(
                    link_local_ipv6_addr is not None and ipaddress.IPv6Address(link_local_ipv6_addr) in ipaddress.IPv6Network(DHCPV6_IP_LINK_LOCAL_PREFIX),
                    "Didn't get packet with expected transaction id"
                )
                req_pkt = scapy.Ether(dst=DHCPV6_MAC_MULTICAST, src=bmc_mac) \
                    / scapy.IPv6(src=link_local_ipv6_addr, dst=DHCPV6_IP_MULTICAST) \
                    / scapy.UDP(sport=DHCPV6_UDP_CLIENT_PORT, dport=DHCPV6_UDP_SERVER_PORT) \
                    / DHCP6_Solicit(trid=test_trid)
                ptfadapter.dataplane.flush()
                testutils.send_packet(ptfadapter, pkt=req_pkt, port_id=rand_bmc.ptf_port_id)

    def test_bmc_otw_bmc_isolation_v6(self, duthost, ptfadapter, setup_teardown):
        """
        BMC-Isolation [PoC]: Verify IPv6 ACL rules for BMC-level isolation
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        vlan_interfaces_ipv6 = get_vlan_interfaces_ipv6(duthost)
        for rand_bmc in self.shuffle_ports(bmc_hosts, max_len=5):
            rand_upstream = self.rand_one(upstream_ports)
            dynamic_northbound_v6 = {
                **prod_bmc_isolation_nth(NTH_AD_HOC_IOSLATION_SEQ_START, rand_bmc),
                **prod_allow_icmpv6_echo_nth(NTH_AD_HOC_ALLOW_PROTOCOL_SEQ_START, rand_upstream),
                **prod_bmc_otw_basic_acl_set_nth(vlan_interfaces_ipv6),
            }
            dynamic_southbound_v6 = {
                **prod_bmc_isolation_sth(STH_AD_HOC_ISOLATION_SEQ_START, rand_bmc),
                **prod_allow_icmpv6_echo_sth(STH_AD_HOC_ALLOW_PROTOCOL_SEQ_START, rand_upstream),
            }
            self.setup_dynamic_v6_acl_rules_by_acl_loader(duthost, rack_topo, dynamic_northbound_v6, dynamic_southbound_v6)
            northbound_pkt = testutils.simple_icmpv6_packet(eth_dst=duthost.facts['router_mac'], ipv6_src=rand_bmc.ipv6_addr,
                                                            ipv6_dst=rand_upstream.ipv6_addr, icmp_type=ICMPV6_TYPE_ECHO_REPLY)
            southbound_pkt = testutils.simple_icmpv6_packet(eth_dst=duthost.facts['router_mac'], ipv6_src=rand_upstream.ipv6_addr,
                                                            ipv6_dst=rand_bmc.ipv6_addr, icmp_type=ICMPV6_TYPE_ECHO_REQUEST)
            # Since we have isolation rule for BMC, the ICMPv6 ECHO packets should be dropped
            send_and_verify_traffic_v6(duthost, ptfadapter, rand_bmc, upstream_ports, expect_behavior="drop", pkt=northbound_pkt)
            send_and_verify_traffic_v6(duthost, ptfadapter, rand_upstream, [rand_bmc], expect_behavior="drop", pkt=southbound_pkt)


class TestBmcOtwAclRules(BmcOtwAclRulesBase):

    @pytest.fixture(scope="class", autouse=True)
    def rack_topo_file(self):
        return RACK_TOPO_FILE_BMC_OTW


class TestBmcAresAclRules(BmcOtwAclRulesBase):

    @pytest.fixture(scope="class", autouse=True)
    def rack_topo_file(self):
        return RACK_TOPO_FILE_BMC_ARES

    @pytest.fixture(scope="function", autouse=True)
    def skip_req_4_tests(self, request):
        if 'req_4' in request.node.name:
            pytest.skip("Ares Mx doesn't support Req 4 (dynamic ACL)")

    @pytest.fixture(scope="function", autouse=True)
    def skip_bmc_isolation(self, request):
        if 'bmc_isolation' in request.node.name:
            pytest.skip("Ares Mx doesn't support BMC-Isolation")
