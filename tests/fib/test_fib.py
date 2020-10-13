import pytest
import time
import json
import logging
import tempfile

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner
from datetime import datetime

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

# Usually src-mac, dst-mac, vlan-id are optional hash keys. Not all the platform supports these optional hash keys. Not enable these three by default.
# HASH_KEYS = ['src-ip', 'dst-ip', 'src-port', 'dst-port', 'ingress-port', 'src-mac', 'dst-mac', 'ip-proto', 'vlan-id']
HASH_KEYS = ['src-ip', 'dst-ip', 'src-port', 'dst-port', 'ingress-port', 'ip-proto']
SRC_IP_RANGE = ['8.0.0.0', '8.255.255.255']
DST_IP_RANGE = ['9.0.0.0', '9.255.255.255']
SRC_IPV6_RANGE = ['20D0:A800:0:00::', '20D0:A800:0:00::FFFF']
DST_IPV6_RANGE = ['20D0:A800:0:01::', '20D0:A800:0:01::FFFF']
VLANIDS = range(1032, 1279)
VLANIP = '192.168.{}.1/24'
PTF_QLEN = 2000


@pytest.fixture(scope="module")
def config_facts(duthost):
    return duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']


@pytest.fixture(scope='module')
def build_fib(duthost, ptfhost, config_facts):

    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    duthost.shell("redis-dump -d 0 -k 'ROUTE*' -y > /tmp/fib.{}.txt".format(timestamp))
    duthost.fetch(src="/tmp/fib.{}.txt".format(timestamp), dest="/tmp/fib")

    po = config_facts.get('PORTCHANNEL', {})
    ports = config_facts.get('PORT', {})

    tmp_fib_info = tempfile.NamedTemporaryFile()
    with open("/tmp/fib/{}/tmp/fib.{}.txt".format(duthost.hostname, timestamp)) as fp:
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
            if nh == '0.0.0.0' or nh == '::' or nh == "":
                skip = True

            if not skip:
                tmp_fib_info.write("{}".format(prefix))
                for op in oports:
                    tmp_fib_info.write(" [{}]".format(" ".join(op)))
                tmp_fib_info.write("\n")
            else:
                tmp_fib_info.write("{} []\n".format(prefix))
    tmp_fib_info.flush()

    ptfhost.copy(src=tmp_fib_info.name, dest="/root/fib_info.txt")


def get_vlan_untag_ports(config_facts):
    """
    get all untag vlan ports
    """
    vlan_untag_ports = []
    vlans = config_facts.get('VLAN_INTERFACE', {}).keys()
    for vlan in vlans:
        vlan_member_info = config_facts.get('VLAN_MEMBER', {}).get(vlan, {})
        if vlan_member_info:
            for port_name, tag_mode in vlan_member_info.items():
                if tag_mode['tagging_mode'] == 'untagged':
                    vlan_untag_ports.append(port_name)

    return vlan_untag_ports


def get_router_interface_ports(config_facts, tbinfo):
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
    if 't0' in tbinfo['topo']['name']:
        vlan_untag_ports = get_vlan_untag_ports(config_facts)

    router_interface_ports = ports + portchannels_member_ports + vlan_untag_ports

    return router_interface_ports


@pytest.mark.parametrize("ipv4, ipv6, mtu", [pytest.param(True, True, 1514)])
def test_basic_fib(tbinfo, duthost, ptfhost, ipv4, ipv6, mtu, config_facts, build_fib):

    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')

    # do not test load balancing for vs platform as kernel 4.9
    # can only do load balance base on L3
    if duthost.facts['asic_type'] in ["vs"]:
        test_balancing = False
    else:
        test_balancing = True

    logging.info("run ptf test")
    testbed_type = tbinfo['topo']['name']
    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")
    log_file = "/tmp/fib_test.FibTest.ipv4.{}.ipv6.{}.{}.log".format(ipv4, ipv6, timestamp)
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
                qlen=PTF_QLEN,
                socket_recv_size=16384)


@pytest.fixture(scope="module")
def setup_hash(tbinfo, duthost, config_facts):
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')

    setup_info = {}

    # TODO
    hash_keys = HASH_KEYS[:]    # Copy from global var to avoid side effects of multiple iterations
    if 'dst-mac' in hash_keys:
        hash_keys.remove('dst-mac')

    # do not test load balancing on L4 port on vs platform as kernel 4.9
    # can only do load balance base on L3
    if duthost.facts['asic_type'] in ["vs"]:
        if 'src-port' in hash_keys:
            hash_keys.remove('src-port')
        if 'dst-port' in hash_keys:
            hash_keys.remove('dst-port')
    if duthost.facts['asic_type'] in ["mellanox"]:
        if 'ip-proto' in hash_keys:
            hash_keys.remove('ip-proto')
    if duthost.facts['asic_type'] in ["barefoot"]:
        if 'ingress-port' in hash_keys:
            hash_keys.remove('ingress-port')
    setup_info['hash_keys'] = hash_keys

    setup_info['testbed_type'] = tbinfo['topo']['name']
    setup_info['router_mac'] = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")

    vlan_untag_ports = get_vlan_untag_ports(config_facts)
    in_ports_name = get_router_interface_ports(config_facts, tbinfo)
    setup_info['in_ports'] = [config_facts.get('port_index_map', {})[p] for p in in_ports_name]

    # add some vlan for hash_key vlan-id test
    if 't0' in setup_info['testbed_type'] and 'vlan-id' in hash_keys:
        for vlan in VLANIDS:
            duthost.shell('config vlan add {}'.format(vlan))
            for port in vlan_untag_ports:
                duthost.shell('config vlan member add {} {}'.format(vlan, port))
            duthost.shell('config interface ip add Vlan{} '.format(vlan) + VLANIP.format(vlan%256))
        time.sleep(5)

    yield setup_info

    # remove added vlan
    if 't0' in setup_info['testbed_type'] and 'vlan-id' in hash_keys:
        for vlan in VLANIDS:
            duthost.shell('config interface ip remove Vlan{} '.format(vlan) + VLANIP.format(vlan%256))
            for port in vlan_untag_ports:
                duthost.shell('config vlan member del {} {}'.format(vlan, port))
            duthost.shell('config vlan del {}'.format(vlan))
        time.sleep(5)


@pytest.fixture(params=["ipv4", "ipv6"])
def ipver(request):
    return request.param


def test_hash(setup_hash, ptfhost, build_fib, ipver):
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/hash_test.HashTest.{}.{}.log".format(ipver, timestamp)
    logging.info("PTF log file: %s" % log_file)
    if ipver == "ipv4":
        src_ip_range = SRC_IP_RANGE
        dst_ip_range = DST_IP_RANGE
    elif ipver == "ipv6":
        src_ip_range = SRC_IPV6_RANGE
        dst_ip_range = DST_IPV6_RANGE

    ptf_runner(ptfhost,
            "ptftests",
            "hash_test.HashTest",
            platform_dir="ptftests",
            params={"testbed_type": setup_hash['testbed_type'],
                    "router_mac": setup_hash['router_mac'],
                    "fib_info": "/root/fib_info.txt",
                    "src_ip_range": ",".join(src_ip_range),
                    "dst_ip_range": ",".join(dst_ip_range),
                    "in_ports": setup_hash['in_ports'],
                    "vlan_ids": VLANIDS,
                    "hash_keys": setup_hash['hash_keys']},
            log_file=log_file,
            qlen=PTF_QLEN,
            socket_recv_size=16384)
