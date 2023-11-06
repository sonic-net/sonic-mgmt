from __future__ import unicode_literals

import copy
import json
import logging
import os
import pytest
import random
import re
import sys
import yaml

from functools import reduce
import jinja2
from ptf import testutils
from ptf.mask import Mask
import ptf.packet as scapy

from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py  # noqa F401
from tests.common.utilities import wait_until
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, generate_tmpfile, delete_tmpfile
from mx_utils import create_vlan, get_vlan_config, remove_all_vlans
from config.generate_acl_rules import (
    acl_entry,
    ACL_ACTION_ACCEPT,
    ETHERTYPE_IPV6,
    IP_PROTOCOL_TCP,
    IP_PROTOCOL_UDP,
    IP_PROTOCOL_MAP,
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

L4_PORT_MODE_SINGLE = "L4_SINGLE_PORT"
L4_PORT_MODE_RANGE = "L4_PORT_RANGE"


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
        rule_value["L4_SRC_PORT_RANGE" if l4_src_port.mode() == L4Ports.MODE_RANGE else "L4_SRC_PORT"] = str(l4_src_port)
    if l4_dst_port:
        rule_value["L4_DST_PORT_RANGE" if l4_dst_port.mode() == L4Ports.MODE_RANGE else "L4_DST_PORT"] = str(l4_dst_port)
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
    MODE_SINGLE = "L4_SINGLE_PORT"
    MODE_RANGE = "L4_PORT_RANGE"

    def __init__(self, lo=0, hi=0):
        self.lo = lo
        self.hi = hi

    def __str__(self):
        return self.format_config_db()

    @classmethod
    def rand(cls, mode, lo=1024, hi=65535):
        if mode == cls.MODE_SINGLE:
            return cls.rand_single(lo, hi)
        elif mode == cls.MODE_RANGE:
            return cls.rand_range(lo, hi)
        else:
            raise ValueError("Invalid mode: {}".format(mode))

    @classmethod
    def rand_single(cls, lo=1024, hi=60000):
        port = random.randint(lo, hi)
        return cls(port, port)

    @classmethod
    def rand_range(cls, lo=1024, hi=60000):
        range_lo, range_hi = sorted(random.sample(range(lo, hi), 2))
        return cls(range_lo, range_hi)

    def format_acl_loader(self):
        if self.lo == self.hi:
            return str(self.lo)
        return "{}..{}".format(self.lo, self.hi)

    def format_config_db(self):
        if self.lo == self.hi:
            return str(self.lo)
        return "{}-{}".format(self.lo, self.hi)

    def mode(self):
        if self.lo == self.hi:
            return self.MODE_SINGLE
        return self.MODE_RANGE

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


class BmcOtwAclRulesBase:

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
        # clear existing arp/fdb/ndp table before test
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

    def setup_dynamic_v6_acl_rules_by_acl_loader(self, duthost, rack_topo, bmc, upstream, bmc_l4_ports, upstream_l4_ports, ip_protocol=None):
        if 'dynamic_acl_rule_template_file' not in rack_topo['config']:
            pytest.skip("No dynamic acl rule template file")
        dynamic_acl_rule_template_file = rack_topo['config']['dynamic_acl_rule_template_file']

        acl_tables = rack_topo['config']['acl_tables']
        if ACL_TABLE_BMC_NORTHBOUND_V6 not in acl_tables or ACL_TABLE_BMC_SOUTHBOUND_V6 not in acl_tables:
            pytest.skip("No IPv6 ACL tables")

        seq_id = 3000
        dynamic_northbound_v6 = {
            '{}_AD_HOC'.format(seq_id): json.dumps(acl_entry(
                seq_id, action=ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV6,
                interfaces=[bmc.port_name], ip_protocol=ip_protocol,
                src_ip=bmc.ipv6_addr + "/128", dst_ip=upstream.ipv6_addr + "/128",
                l4_src_port=bmc_l4_ports.format_acl_loader(),
                l4_dst_port=upstream_l4_ports.format_acl_loader()
            )),
        }
        dynamic_southbound_v6 = {
            '{}_AD_HOC'.format(seq_id): json.dumps(acl_entry(
                seq_id, action=ACL_ACTION_ACCEPT, ethertype=ETHERTYPE_IPV6, ip_protocol=ip_protocol,
                src_ip=upstream.ipv6_addr + "/128", dst_ip=bmc.ipv6_addr + "/128",
                l4_src_port=upstream_l4_ports.format_acl_loader(),
                l4_dst_port=bmc_l4_ports.format_acl_loader()
            )),
        }

        j2_env = jinja2.Environment(loader=jinja2.FileSystemLoader(ACL_RULE_SRC_FILE_PREFIX))
        j2_tpl = j2_env.get_template(dynamic_acl_rule_template_file)
        dynamic_acl_rule_file = os.path.join(ACL_RULE_SRC_FILE_PREFIX, 'dynamic_acl_rules.json')
        with open(dynamic_acl_rule_file, 'w') as fout:
            fout.write(j2_tpl.render(dynamic_northbound_v6=dynamic_northbound_v6, dynamic_southbound_v6=dynamic_southbound_v6))

        add_acl_rule(duthost, dynamic_acl_rule_file, acl_tables[ACL_TABLE_BMC_NORTHBOUND_V6])
        add_acl_rule(duthost, dynamic_acl_rule_file, acl_tables[ACL_TABLE_BMC_SOUTHBOUND_V6])

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

    def test_bmc_otw_req_1_v4_src_ip_bmc(self, duthost, ptfadapter, setup_teardown):
        """
        Request 1: BMCs are not allowed to communicate with each other
        Test 1: BMCs cannot use it's own IP as SRC_IP to send packet to other BMC
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        for src_bmc, dst_bmc in self.shuffle_src_dst_pairs(bmc_hosts, max_len=10):
            send_and_verify_traffic_v4(duthost, ptfadapter, src_bmc, [dst_bmc], expect_behavior="drop")

    def test_bmc_otw_req_1_v4_src_ip_rm(self, duthost, ptfadapter, setup_teardown):
        """
        Request 1: BMCs are not allowed to communicate with each other
        TEST 2: BMCs cannot use RM IP as SRC_IP to send packet to other BMC
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        for shelf in shelfs:
            for src_bmc, dst_bmc in self.shuffle_src_dst_pairs(shelf.bmc_hosts, max_len=5):
                src_bmc.ipv4_addr = shelf.rm.ipv4_addr
                src_bmc.ipv4_prefix = shelf.rm.ipv4_prefix
                send_and_verify_traffic_v4(duthost, ptfadapter, src_bmc, [dst_bmc], expect_behavior="drop")

    def test_bmc_otw_req_1_v4_src_ip_upstream(self, duthost, ptfadapter, setup_teardown):
        """
        Request 1: BMCs are not allowed to communicate with each other
        TEST 3: BMCs cannot use upstream IP as SRC_IP to send packet to other BMC
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        for src_bmc, dst_bmc in self.shuffle_src_dst_pairs(bmc_hosts, max_len=10):
            src_bmc.ipv4_addr = SAMPLE_UPSTREAM_IPV4_ADDR
            src_bmc.ipv4_prefix = SAMPLE_UPSTREAM_IPV4_PREFIX
            send_and_verify_traffic_v4(duthost, ptfadapter, src_bmc, [dst_bmc], expect_behavior="drop")

    def test_bmc_otw_req_1_v6_src_ip_bmc(self, duthost, ptfadapter, setup_teardown):
        """
        Request 1: BMCs are not allowed to communicate with each other
        Test 1: BMCs cannot use it's own IP as SRC_IP to send packet to other BMC
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        for src_bmc, dst_bmc in self.shuffle_src_dst_pairs(bmc_hosts, max_len=10):
            send_and_verify_traffic_v6(duthost, ptfadapter, src_bmc, [dst_bmc], expect_behavior="drop")

    def test_bmc_otw_req_1_v6_src_ip_rm(self, duthost, ptfadapter, setup_teardown):
        """
        Request 1: BMCs are not allowed to communicate with each other
        TEST 2: BMCs cannot use RM IP as SRC_IP to send packet to other BMC
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        shelfs_v6 = self.filter_shelf_with_rm_ipv6(shelfs)
        if len(shelfs_v6) == 0:
            pytest.skip("No shelf has IPv6 address configured on RM")
        for shelf in shelfs_v6:
            for src_bmc, dst_bmc in self.shuffle_src_dst_pairs(shelf.bmc_hosts, max_len=5):
                src_bmc.ipv6_addr = shelf.rm.ipv6_addr
                src_bmc.ipv6_prefix = shelf.rm.ipv6_prefix
                send_and_verify_traffic_v6(duthost, ptfadapter, src_bmc, [dst_bmc], expect_behavior="drop")

    def test_bmc_otw_req_1_v6_src_ip_upstream(self, duthost, ptfadapter, setup_teardown):
        """
        Request 1: BMCs are not allowed to communicate with each other
        TEST 3: BMCs cannot use upstream IP as SRC_IP to send packet to other BMC
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        for src_bmc, dst_bmc in self.shuffle_src_dst_pairs(bmc_hosts, max_len=10):
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

    @pytest.mark.parametrize("ip_protocol", [IP_PROTOCOL_TCP, IP_PROTOCOL_UDP])
    @pytest.mark.parametrize("l4_port_mode", [L4Ports.MODE_SINGLE, L4Ports.MODE_RANGE])
    def test_bmc_otw_req_4_v6_acl_loader_full_update(self, duthost, ptfadapter, setup_teardown, ip_protocol, l4_port_mode):
        """
        Request 4: Direct access is conditional allowed after loading AD-HOC ACL rules
        TEST 1: Setup full ACL rules (including AD-HOC) via acl-loader
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        for rand_bmc in self.shuffle_ports(bmc_hosts, max_len=5):
            rand_upstream = self.rand_one(upstream_ports)
            bmc_l4_ports = L4Ports.rand(l4_port_mode)
            upstream_l4_ports = L4Ports.rand(l4_port_mode)
            self.setup_dynamic_v6_acl_rules_by_acl_loader(duthost, rack_topo, rand_bmc, rand_upstream, bmc_l4_ports, upstream_l4_ports, ip_protocol)
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

    @pytest.mark.xfail(reason="Expect fail until ICMPv6 ACL Yang model is fixed")
    @pytest.mark.parametrize("ip_protocol", [IP_PROTOCOL_TCP, IP_PROTOCOL_UDP])
    @pytest.mark.parametrize("l4_port_mode", [L4Ports.MODE_SINGLE, L4Ports.MODE_RANGE])
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

    def test_bmc_otw_req_5_v4(self, duthost, ptfadapter, mx_common_setup_teardown, setup_teardown):
        """
        Request 5: Mx allows inter-access between the directly connected BMC and itself.
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

    def test_bmc_otw_req_5_v6(self, duthost, ptfadapter, mx_common_setup_teardown, setup_teardown):
        """
        Request 5: Mx allows inter-access between the directly connected BMC and itself.
        """
        ptf_idx_to_port_name, _, _ = mx_common_setup_teardown
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        cmd_tpl = "python3 -c \"from ptf import testutils; import scapy.all as scapy2; " \
                  "scapy2.sendp(testutils.simple_icmpv6_packet(ipv6_dst='{}'), iface='{}')\""
        for rand_bmc in self.shuffle_ports(bmc_hosts, max_len=10):
            pkt = testutils.simple_icmpv6_packet(ipv6_dst='{}'.format(rand_bmc.ipv6_addr))
            exp_pkt = build_exp_pkt(pkt)
            cmd = cmd_tpl.format(rand_bmc.ipv6_addr, ptf_idx_to_port_name[rand_bmc.ptf_port_id])
            ptfadapter.dataplane.flush()
            duthost.shell(cmd)
            testutils.verify_packet(ptfadapter, exp_pkt, rand_bmc.ptf_port_id, timeout=10)

    def test_bmc_otw_req_6_v4_same_shelf(self, duthost, ptfadapter, setup_teardown):
        """
        Request 6: Mx allows directly connected RM and directly connected BMCs to access each other
        TEST 1: BMC can communicate with RM in the same shelf
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        for shelf in shelfs:
            for rand_bmc in self.shuffle_ports(shelf.bmc_hosts, max_len=5):
                send_and_verify_traffic_v4(duthost, ptfadapter, rand_bmc, [shelf.rm], expect_behavior="accept")
                send_and_verify_traffic_v4(duthost, ptfadapter, shelf.rm, [rand_bmc], expect_behavior="accept")

    def test_bmc_otw_req_6_v4_diff_shelf(self, duthost, ptfadapter, setup_teardown):
        """
        Request 5: Mx allows directly connected RM and directly connected BMCs to access each other
        TEST 2: BMC cannot communicate with RM in the different shelf
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        if len(shelfs) <= 1:
            pytest.skip("Only one shelf on the rack")
        for bmc_shelf in shelfs:
            for rm_shelf in shelfs:
                if bmc_shelf.id != rm_shelf.id:
                    rand_bmc = self.rand_one(bmc_shelf.bmc_hosts)
                    send_and_verify_traffic_v4(duthost, ptfadapter, rand_bmc, [rm_shelf.rm], expect_behavior="drop")
                    send_and_verify_traffic_v4(duthost, ptfadapter, rm_shelf.rm, [rand_bmc], expect_behavior="drop")

    def test_bmc_otw_req_6_v6_same_shelf(self, duthost, ptfadapter, setup_teardown):
        """
        Request 5: Mx allows directly connected RM and directly connected BMCs to access each other
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

    def test_bmc_otw_req_6_v6_diff_shelf(self, duthost, ptfadapter, setup_teardown):
        """
        Request 5: Mx allows directly connected RM and directly connected BMCs to access each other
        TEST 2: BMC cannot communicate with RM in the different shelf
        """
        rack_topo, shelfs, bmc_hosts, upstream_ports = setup_teardown
        shelfs_v6 = self.filter_shelf_with_rm_ipv6(shelfs)
        if len(shelfs_v6) < 2:
            pytest.skip("Less than 2 shelf has IPv6 address configured on RM")
        for bmc_shelf in shelfs_v6:
            for rm_shelf in shelfs_v6:
                if bmc_shelf.id != rm_shelf.id:
                    rand_bmc = self.rand_one(bmc_shelf.bmc_hosts)
                    send_and_verify_traffic_v6(duthost, ptfadapter, rand_bmc, [rm_shelf.rm], expect_behavior="drop")
                    send_and_verify_traffic_v6(duthost, ptfadapter, rm_shelf.rm, [rand_bmc], expect_behavior="drop")


class TestBmcOtwStaticAclRules(BmcOtwAclRulesBase):

    @pytest.fixture(scope="class", autouse=True)
    def rack_topo_file(self):
        return RACK_TOPO_FILE_BMC_OTW


class TestBmcAresAclRules(BmcOtwAclRulesBase):

    @pytest.fixture(scope="class", autouse=True)
    def rack_topo_file(self):
        return RACK_TOPO_FILE_BMC_ARES

    @pytest.fixture(scope="function", autouse=True)
    def skip_ipv6_tests(self, request):
        if 'v6' in request.node.name:
            pytest.skip("No IPv6 ACL rules configured on Ares Mx")
