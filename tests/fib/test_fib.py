import pytest
from netaddr import *
import time
import json
import logging
import requests
from ptf_runner import ptf_runner
from datetime import datetime 

logger = logging.getLogger(__name__)

HASH_KEYS = ['src-ip', 'dst-ip', 'src-port', 'dst-port', 'ingress-port']
SRC_IP_RANGE = ['8.0.0.0', '8.255.255.255']
DST_IP_RANGE = ['9.0.0.0', '9.255.255.255']
SRC_IPV6_RANGE = ['20D0:A800:0:00::', '20D0:A800:0:00::FFFF']
DST_IPV6_RANGE = ['20D0:A800:0:01::', '20D0:A800:0:01::FFFF']

g_vars = {}

def build_fib(duthost, config_facts, fibfile, t):

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    duthost.shell("redis-dump -d 0 -k 'ROUTE*' -y > /tmp/fib.{}.txt".format(t))
    duthost.fetch(src="/tmp/fib.{}.txt".format(t), dest="/tmp/fib")

    po = config_facts.get('PORTCHANNEL', {})
    ports = config_facts.get('PORT', {})

    with open("/tmp/fib/{}/tmp/fib.{}.txt".format(duthost.hostname, t)) as fp, \
         open(fibfile, 'w') as ofp:
        fib = json.load(fp)

        for k, v in fib.items():
            skip = False
            prefix = k.split(':', 1)[1]
            ifnames = v['value']['ifname'].split(',')
            nh = v['value']['nexthop']

            oports = []
            for ifname in ifnames:
                if po.has_key(ifname):
                    oports.append([str(mg_facts['minigraph_port_indices'][x]) for x in po[ifname]['members']])
                else:
                    if ports.has_key(ifname):
                        oports.append([str(mg_facts['minigraph_port_indices'][ifname])])
                    else:
                        logger.info("Route point to non front panel port {}:{}".format(k, v))
                        skip = True
            # skip direct attached subnet
            if nh == '0.0.0.0' or nh == '::':
                skip = True

            if not skip:
                ofp.write("{}".format(prefix))
                for op in oports:
                    ofp.write(" [{}]".format(" ".join(op)))
                ofp.write("\n")
            else:
                ofp.write("{} []\n".format(prefix))

def get_router_interface_ports(config_facts, testbed):
    """
    get all physical ports associated with router interface (physical router interface, port channel router interface and vlan router interface)
    """

    ports = config_facts.get('INTERFACE', {}).keys()
    portchannels_member_ports = []
    vlan_untag_ports = []
    portchannels_name = config_facts.get('PORTCHANNEL_INTERFACE', {}).keys()
    if portchannels_name:
        for po_name in portchannels_name:
            for port_name in config_facts.get('PORTCHANNEL', {})[po_name]['members']:
                portchannels_member_ports.append(port_name)
    if 't0' in testbed['topo']['name']:
        vlans = config_facts.get('VLAN_INTERFACE', {}).keys()
        for vlan in vlans:
            vlan_member_info = config_facts.get('VLAN_MEMBER', {}).get(vlan, {})
            if vlan_member_info:
                for port_name, tag_mode in vlan_member_info.items():
                    if tag_mode['tagging_mode'] == 'untagged':
                        vlan_untag_ports.append(port_name)

    router_interface_ports = ports + portchannels_member_ports + vlan_untag_ports

    return router_interface_ports

@pytest.mark.parametrize("ipv4, ipv6, mtu", [pytest.param(True, True, 1514)])
def test_fib(testbed, duthost, ptfhost, ipv4, ipv6, mtu):

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

    t = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')

    ofpname = "/tmp/fib/{}/tmp/fib_info.{}.txt".format(duthost.hostname, t)

    build_fib(duthost, config_facts, ofpname, t)

    ptfhost.copy(src=ofpname, dest="/root/fib_info.txt")
    ptfhost.copy(src="ptftests", dest="/root")
    logging.info("run ptf test")

    # do not test load balancing for vs platform as kernel 4.9
    # can only do load balance base on L3
    meta = config_facts.get('DEVICE_METADATA')
    if meta['localhost']['platform'] == 'x86_64-kvm_x86_64-r0':
        test_balancing = False
    else:
        test_balancing = True

    testbed_type = testbed['topo']['name']
    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")
    log_file = "/tmp/fib_test.FibTest.ipv4.{}.ipv6.{}.{}.log".format(ipv4, ipv6, t)
    logging.info("PTF log file: %s" % log_file)
    ptf_runner(ptfhost,
                "ptftests",
                "fib_test.FibTest",
                platform_dir="ptftests",
                params={"testbed_type": testbed_type,
                        "router_mac": router_mac,
                        "fib_info": "/root/fib_info.txt",
                        "ipv4": ipv4,
                        "ipv6": ipv6,
                        "testbed_mtu": mtu,
                        "test_balancing": test_balancing },
                log_file=log_file,
                socket_recv_size=16384)


class TestHash():
    hash_keys = HASH_KEYS
    t = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')

    @pytest.fixture(scope="class", autouse=True)
    def setup_hash(self, testbed, duthost, ptfhost):
        global g_vars

        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

        ofpname = "/tmp/fib/{}/tmp/fib_info.{}.txt".format(duthost.hostname, self.t)

        build_fib(duthost, config_facts, ofpname, self.t)

        ptfhost.copy(src=ofpname, dest="/root/fib_info.txt")
        ptfhost.copy(src="ptftests", dest="/root")
        logging.info("run ptf test")

        # do not test load balancing on L4 port on vs platform as kernel 4.9
        # can only do load balance base on L3
        meta = config_facts.get('DEVICE_METADATA')
        if meta['localhost']['platform'] == 'x86_64-kvm_x86_64-r0':
            self.hash_keys.remove('src-port')
            self.hash_keys.remove('dst-port')

        g_vars['testbed_type'] = testbed['topo']['name']
        g_vars['router_mac'] = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")

        in_ports_name = get_router_interface_ports(config_facts, testbed)
        g_vars['in_ports'] = [config_facts.get('port_index_map', {})[p] for p in in_ports_name]

    def test_hash_ipv4(self, ptfhost):
        log_file = "/tmp/hash_test.HashTest.ipv4.{}.log".format(self.t)
        logging.info("PTF log file: %s" % log_file)
        src_ip_range = SRC_IP_RANGE
        dst_ip_range = DST_IP_RANGE

        ptf_runner(ptfhost,
                "ptftests",
                "hash_test.HashTest",
                platform_dir="ptftests",
                params={"testbed_type": g_vars['testbed_type'],
                        "router_mac": g_vars['router_mac'],
                        "fib_info": "/root/fib_info.txt",
                        "src_ip_range": ",".join(src_ip_range),
                        "dst_ip_range": ",".join(dst_ip_range),
                        "in_ports": g_vars['in_ports'],
                        "hash_keys": self.hash_keys },
                log_file=log_file,
                socket_recv_size=16384)

    def test_hash_ipv6(self, ptfhost):
        log_file = "/tmp/hash_test.HashTest.ipv6.{}.log".format(self.t)
        logging.info("PTF log file: %s" % log_file)
        src_ip_range = SRC_IPV6_RANGE
        dst_ip_range = DST_IPV6_RANGE

        ptf_runner(ptfhost,
                "ptftests",
                "hash_test.HashTest",
                platform_dir="ptftests",
                params={"testbed_type": g_vars['testbed_type'],
                        "router_mac": g_vars['router_mac'],
                        "fib_info": "/root/fib_info.txt",
                        "src_ip_range": ",".join(src_ip_range),
                        "dst_ip_range": ",".join(dst_ip_range),
                        "in_ports": g_vars['in_ports'],
                        "hash_keys": self.hash_keys },
                log_file=log_file,
                socket_recv_size=16384)
