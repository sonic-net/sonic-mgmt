from __future__ import unicode_literals

import copy
import json
import os
import pytest
import random
import yaml

from functools import reduce
from ptf import testutils
from ptf.mask import Mask
import ptf.packet as scapy

from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py  # noqa F401
from mx_utils import create_vlan, get_vlan_config, remove_all_vlans

pytestmark = [
    pytest.mark.topology('mx'),
]

ACL_TABLE_TYPE_L3 = "L3"
ACL_TABLE_TYPE_L3V6 = "L3V6"
ACL_TABLE_TYPE_BMC = "BMCDATA"
ACL_TABLE_TYPE_BMC_V6 = "BMCDATAV6"

ACL_STAGE_INGRESS = "ingress"
ACL_STAGE_EGRESS = "egress"

ACL_TABLE_TYPE_SRC_FILE = "mx/config/bmc_acl_table_types.json"
ACL_TABLE_TYPE_DST_FILE = "/tmp/acl_table_types.json"

ACL_TABLE_BMC_NORTHBOUND = "BMC_ACL_NORTHBOUND"
ACL_TABLE_BMC_NORTHBOUND_V6 = "BMC_ACL_NORTHBOUND_V6"
ACL_TABLE_BMC_SOUTHBOUND_V6 = "BMC_ACL_SOUTHBOUND_V6"

ACL_RULE_SRC_FILE_PREFIX = "mx/config/"
ACL_RULE_DST_FILE = "/tmp/bmc_acl_rules.json"

RACK_TOPO_FILE_BMC_OTW = "mx/config/bmc_otw_topo.yaml"
RACK_TOPO_FILE_BMC_ARES = "mx/config/bmc_ares_topo.yaml"

SAMPLE_UPSTREAM_IPV4_ADDR = "1.1.1.1"
SAMPLE_UPSTREAM_IPV4_PREFIX = 32
SAMPLE_UPSTREAM_IPV6_ADDR = "fc03::1"
SAMPLE_UPSTREAM_IPV6_PREFIX = 128


def add_acl_table(duthost, table_name, table_type, ports, stage):
    duthost.shell("sudo config acl add table {} {} -p {} -s {}"
                  .format(table_name, table_type, ','.join(ports), stage))


def remove_acl_table(duthost, table_name):
    duthost.shell("sudo config acl remove table {}".format(table_name))


def add_acl_rule(duthost, src_file, table_name):
    duthost.copy(src=src_file, dest=ACL_RULE_DST_FILE)
    duthost.shell("acl-loader update full --table_name {} {}".format(table_name, ACL_RULE_DST_FILE))


def remove_acl_rule(duthost, table_name):
    duthost.shell("acl-loader delete {}".format(table_name))


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
    def __init__(self, rm, bmc_hosts):
        self.rm = rm
        self.bmc_hosts = bmc_hosts


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


def send_and_verify_traffic_v4(duthost, ptfadapter, src, dsts, expect_behavior, pkt=None):
    router_mac = duthost.facts['router_mac']
    if pkt is None:
        pkt = testutils.simple_tcp_packet(eth_dst=router_mac, ip_src=src.ipv4_addr, ip_dst=dsts[0].ipv4_addr, tcp_flags="")
    exp_pkt = build_exp_pkt(pkt)
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, pkt=pkt, port_id=src.ptf_port_id)
    dst_ptf_port_ids = [dst.ptf_port_id for dst in dsts]
    if expect_behavior == "accept":
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, dst_ptf_port_ids, timeout=10)
    elif expect_behavior == "drop":
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, dst_ptf_port_ids, timeout=10)


def send_and_verify_traffic_v6(duthost, ptfadapter, src, dsts, expect_behavior, pkt=None):
    router_mac = duthost.facts['router_mac']
    if pkt is None:
        pkt = testutils.simple_tcpv6_packet(eth_dst=router_mac, ipv6_src=src.ipv6_addr, ipv6_dst=dsts[0].ipv6_addr, tcp_flags="")
    exp_pkt = build_exp_pkt(pkt)
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, pkt=pkt, port_id=src.ptf_port_id)
    dst_ptf_port_ids = [dst.ptf_port_id for dst in dsts]
    if expect_behavior == "accept":
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, dst_ptf_port_ids, timeout=10)
    elif expect_behavior == "drop":
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, dst_ptf_port_ids, timeout=10)


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

    def rand_one(self, pool):
        return copy.copy(random.sample(pool, 1)[0])

    def rand_src_dst(self, pool):
        rand_idx = random.sample(range(len(pool)), 2)
        return copy.copy(pool[rand_idx[0]]), copy.copy(pool[rand_idx[1]])

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
            shelfs.append(PowerShelfInfo(shelf_rm, shelf_bmc_hosts))
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

        # refresh arp/ndp entry before traffic testing to improve stability
        for host in bmc_hosts + rms:
            duthost.shell("timeout 1 ping -c 1 -w 1 {}".format(host.ipv4_addr), module_ignore_errors=True)
            if host.ipv6_addr is not None:
                duthost.shell("timeout 1 ping6 -c 1 -w 1 {}".format(host.ipv6_addr), module_ignore_errors=True)

        # setup acl tables and acl rules
        acl_rule_file_name = os.path.join(ACL_RULE_SRC_FILE_PREFIX, rack_topo['config']['acl_rule_file_name'])
        if ACL_TABLE_BMC_NORTHBOUND in rack_topo['config']['acl_tables']:
            add_acl_table(duthost, ACL_TABLE_BMC_NORTHBOUND, ACL_TABLE_TYPE_BMC,
                          ["Vlan" + vlan_id for vlan_id in vlan_config], ACL_STAGE_INGRESS)
            add_acl_rule(duthost, acl_rule_file_name, ACL_TABLE_BMC_NORTHBOUND)
        if ACL_TABLE_BMC_NORTHBOUND_V6 in rack_topo['config']['acl_tables']:
            add_acl_table(duthost, ACL_TABLE_BMC_NORTHBOUND_V6, ACL_TABLE_TYPE_BMC_V6,
                          ["Vlan" + vlan_id for vlan_id in vlan_config], ACL_STAGE_INGRESS)
            add_acl_rule(duthost, acl_rule_file_name, ACL_TABLE_BMC_NORTHBOUND_V6)
        if ACL_TABLE_BMC_SOUTHBOUND_V6 in rack_topo['config']['acl_tables']:
            add_acl_table(duthost, ACL_TABLE_BMC_SOUTHBOUND_V6, ACL_TABLE_TYPE_BMC_V6,
                          [port.port_name for port in upstream_ports], ACL_STAGE_INGRESS)
            add_acl_rule(duthost, acl_rule_file_name, ACL_TABLE_BMC_SOUTHBOUND_V6)

        yield shelfs, bmc_hosts, upstream_ports

        # stop and remove arp_responder
        ptfhost.shell("supervisorctl stop arp_responder")
        ptfhost.shell("rm -f /tmp/from_t1.json")
        ptfhost.shell("rm -f /etc/supervisor/conf.d/arp_responder.conf")
        ptfhost.shell("supervisorctl reread && supervisorctl update")

        # remove acl tables and acl rules
        if ACL_TABLE_BMC_NORTHBOUND in rack_topo['config']['acl_tables']:
            remove_acl_rule(duthost, ACL_TABLE_BMC_NORTHBOUND)
            remove_acl_table(duthost, ACL_TABLE_BMC_NORTHBOUND)
        if ACL_TABLE_BMC_NORTHBOUND_V6 in rack_topo['config']['acl_tables']:
            remove_acl_rule(duthost, ACL_TABLE_BMC_NORTHBOUND_V6)
            remove_acl_table(duthost, ACL_TABLE_BMC_NORTHBOUND_V6)
        if ACL_TABLE_BMC_SOUTHBOUND_V6 in rack_topo['config']['acl_tables']:
            remove_acl_rule(duthost, ACL_TABLE_BMC_SOUTHBOUND_V6)
            remove_acl_table(duthost, ACL_TABLE_BMC_SOUTHBOUND_V6)

        # remove vlan
        remove_all_vlans(duthost)

    def test_bmc_otw_req_1_v4_src_ip_bmc(self, duthost, ptfadapter, setup_teardown):
        """
        Request 1: BMCs are not allowed to communicate with each other
        Test 1: BMCs cannot use it's own IP as SRC_IP to send packet to other BMC
        """
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        for _ in range(10):
            src_bmc, dst_bmc = self.rand_src_dst(bmc_hosts)
            send_and_verify_traffic_v4(duthost, ptfadapter, src_bmc, [dst_bmc], expect_behavior="drop")

    def test_bmc_otw_req_1_v4_src_ip_rm(self, duthost, ptfadapter, setup_teardown):
        """
        Request 1: BMCs are not allowed to communicate with each other
        TEST 2: BMCs cannot use RM IP as SRC_IP to send packet to other BMC
        """
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        for shelf in shelfs:
            for _ in range(5):
                src_bmc, dst_bmc = self.rand_src_dst(shelf.bmc_hosts)
                src_bmc.ipv4_addr = shelf.rm.ipv4_addr
                src_bmc.ipv4_prefix = shelf.rm.ipv4_prefix
                send_and_verify_traffic_v4(duthost, ptfadapter, src_bmc, [dst_bmc], expect_behavior="drop")

    def test_bmc_otw_req_1_v4_src_ip_upstream(self, duthost, ptfadapter, setup_teardown):
        """
        Request 1: BMCs are not allowed to communicate with each other
        TEST 3: BMCs cannot use upstream IP as SRC_IP to send packet to other BMC
        """
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        for _ in range(10):
            src_bmc, dst_bmc = self.rand_src_dst(bmc_hosts)
            src_bmc.ipv4_addr = SAMPLE_UPSTREAM_IPV4_ADDR
            src_bmc.ipv4_prefix = SAMPLE_UPSTREAM_IPV4_PREFIX
            send_and_verify_traffic_v4(duthost, ptfadapter, src_bmc, [dst_bmc], expect_behavior="drop")

    def test_bmc_otw_req_1_v6_src_ip_bmc(self, duthost, ptfadapter, setup_teardown):
        """
        Request 1: BMCs are not allowed to communicate with each other
        Test 1: BMCs cannot use it's own IP as SRC_IP to send packet to other BMC
        """
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        for _ in range(10):
            src_bmc, dst_bmc = self.rand_src_dst(bmc_hosts)
            send_and_verify_traffic_v6(duthost, ptfadapter, src_bmc, [dst_bmc], expect_behavior="drop")

    def test_bmc_otw_req_1_v6_src_ip_rm(self, duthost, ptfadapter, setup_teardown):
        """
        Request 1: BMCs are not allowed to communicate with each other
        TEST 2: BMCs cannot use RM IP as SRC_IP to send packet to other BMC
        """
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        for shelf in shelfs:
            if shelf.rm.ipv6_addr is None:
                continue
            for _ in range(5):
                src_bmc, dst_bmc = self.rand_src_dst(shelf.bmc_hosts)
                src_bmc.ipv6_addr = shelf.rm.ipv6_addr
                src_bmc.ipv6_prefix = shelf.rm.ipv6_prefix
                send_and_verify_traffic_v6(duthost, ptfadapter, src_bmc, [dst_bmc], expect_behavior="drop")

    def test_bmc_otw_req_1_v6_src_ip_upstream(self, duthost, ptfadapter, setup_teardown):
        """
        Request 1: BMCs are not allowed to communicate with each other
        TEST 3: BMCs cannot use upstream IP as SRC_IP to send packet to other BMC
        """
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        for _ in range(10):
            src_bmc, dst_bmc = self.rand_src_dst(bmc_hosts)
            src_bmc.ipv6_addr = SAMPLE_UPSTREAM_IPV6_ADDR
            src_bmc.ipv6_prefix = SAMPLE_UPSTREAM_IPV6_PREFIX
            send_and_verify_traffic_v6(duthost, ptfadapter, src_bmc, [dst_bmc], expect_behavior="drop")

    def test_bmc_otw_req_2_v6(self, duthost, ptfadapter, setup_teardown):
        """
        Request 2: Direct access is not allowed from outside to BMC by default
        """
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        for _ in range(10):
            src_upstream = self.rand_one(upstream_ports)
            dst_bmc = self.rand_one(bmc_hosts)
            send_and_verify_traffic_v6(duthost, ptfadapter, src_upstream, [dst_bmc], expect_behavior="drop")

    def test_bmc_otw_req_3_v4(self, duthost, ptfadapter, setup_teardown):
        """
        Request 3: Direct access is not allowed from BMC to outside by default.
        """
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        for _ in range(10):
            src_bmc = self.rand_one(bmc_hosts)
            send_and_verify_traffic_v4(duthost, ptfadapter, src_bmc, upstream_ports, expect_behavior="drop")

    def test_bmc_otw_req_3_v6(self, duthost, ptfadapter, setup_teardown):
        """
        Request 3: Direct access is not allowed from BMC to outside by default.
        """
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        for _ in range(10):
            src_bmc = self.rand_one(bmc_hosts)
            send_and_verify_traffic_v6(duthost, ptfadapter, src_bmc, upstream_ports, expect_behavior="drop")

    @pytest.mark.skip(reason="TODO: Will implement this function when write test to verify ad-hoc ACL rules")
    def test_bmc_otw_req_4_v6(self):
        """
        Request 4: Direct access is conditional allowed after NetFlowManager calls specific Mx gNMI API
        """
        pass

    def test_bmc_otw_req_5_v4(self, duthost, ptfadapter, mx_common_setup_teardown, setup_teardown):
        """
        Request 5: Mx allows inter-access between the directly connected BMC and itself.
        """
        ptf_idx_to_port_name, _, _ = mx_common_setup_teardown
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        cmd_tpl = "python3 -c \"from ptf import testutils; import scapy.all as scapy2; " \
                  "scapy2.sendp(testutils.simple_icmp_packet(ip_dst='{}'), iface='{}')\""
        for _ in range(10):
            dst = self.rand_one(bmc_hosts)
            pkt = testutils.simple_icmp_packet(ip_dst='{}'.format(dst.ipv4_addr))
            exp_pkt = build_exp_pkt(pkt)
            cmd = cmd_tpl.format(dst.ipv4_addr, ptf_idx_to_port_name[dst.ptf_port_id])
            ptfadapter.dataplane.flush()
            duthost.shell(cmd)
            testutils.verify_packet(ptfadapter, exp_pkt, dst.ptf_port_id, timeout=10)

    def test_bmc_otw_req_5_v6(self, duthost, ptfadapter, mx_common_setup_teardown, setup_teardown):
        """
        Request 5: Mx allows inter-access between the directly connected BMC and itself.
        """
        ptf_idx_to_port_name, _, _ = mx_common_setup_teardown
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        cmd_tpl = "python3 -c \"from ptf import testutils; import scapy.all as scapy2; " \
                  "scapy2.sendp(testutils.simple_icmpv6_packet(ipv6_dst='{}'), iface='{}')\""
        for _ in range(10):
            dst = self.rand_one(bmc_hosts)
            pkt = testutils.simple_icmpv6_packet(ipv6_dst='{}'.format(dst.ipv6_addr))
            exp_pkt = build_exp_pkt(pkt)
            cmd = cmd_tpl.format(dst.ipv6_addr, ptf_idx_to_port_name[dst.ptf_port_id])
            ptfadapter.dataplane.flush()
            duthost.shell(cmd)
            testutils.verify_packet(ptfadapter, exp_pkt, dst.ptf_port_id, timeout=10)

    def test_bmc_otw_req_6_v4_same_shelf(self, duthost, ptfadapter, setup_teardown):
        """
        Request 6: Mx allows directly connected RM and directly connected BMCs to access each other
        TEST 1: BMC can communicate with RM in the same shelf
        """
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        for shelf in shelfs:
            for _ in range(5):
                rand_bmc = self.rand_one(shelf.bmc_hosts)
                send_and_verify_traffic_v4(duthost, ptfadapter, rand_bmc, [shelf.rm], expect_behavior="accept")
                send_and_verify_traffic_v4(duthost, ptfadapter, shelf.rm, [rand_bmc], expect_behavior="accept")

    def test_bmc_otw_req_6_v4_diff_shelf(self, duthost, ptfadapter, setup_teardown):
        """
        Request 5: Mx allows directly connected RM and directly connected BMCs to access each other
        TEST 2: BMC cannot communicate with RM in the different shelf
        """
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        if len(shelfs) <= 1:
            pytest.skip("Skip this test because there is only one shelf")
        for _ in range(10):
            bmc_shelf, rm_shelf = self.rand_src_dst(shelfs)
            rand_bmc = self.rand_one(bmc_shelf.bmc_hosts)
            send_and_verify_traffic_v4(duthost, ptfadapter, rand_bmc, [rm_shelf.rm], expect_behavior="drop")
            send_and_verify_traffic_v4(duthost, ptfadapter, rm_shelf.rm, [rand_bmc], expect_behavior="drop")

    def test_bmc_otw_req_6_v6_same_shelf(self, duthost, ptfadapter, setup_teardown):
        """
        Request 5: Mx allows directly connected RM and directly connected BMCs to access each other
        TEST 1: BMC can communicate with RM in the same shelf
        """
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        shelfs_v6 = list(filter(lambda s: s.rm.ipv6_addr is not None, shelfs))
        for shelf in shelfs_v6:
            for _ in range(5):
                rand_bmc = self.rand_one(shelf.bmc_hosts)
                send_and_verify_traffic_v6(duthost, ptfadapter, rand_bmc, [shelf.rm], expect_behavior="accept")
                send_and_verify_traffic_v6(duthost, ptfadapter, shelf.rm, [rand_bmc], expect_behavior="accept")

    def test_bmc_otw_req_6_v6_diff_shelf(self, duthost, ptfadapter, setup_teardown):
        """
        Request 5: Mx allows directly connected RM and directly connected BMCs to access each other
        TEST 2: BMC cannot communicate with RM in the different shelf
        """
        shelfs, bmc_hosts, upstream_ports = setup_teardown
        shelfs_v6 = list(filter(lambda s: s.rm.ipv6_addr is not None, shelfs))
        if len(shelfs_v6) <= 1:
            pytest.skip("Skip this test since there is only one shelf rm has ipv6 address")
        for _ in range(10):
            bmc_shelf, rm_shelf = self.rand_src_dst(shelfs_v6)
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
