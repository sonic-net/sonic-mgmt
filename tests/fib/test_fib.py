import time
import json
import logging
import tempfile
import random

from datetime import datetime

import pytest
import requests

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory, change_mac_addresses   # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner
from tests.common.helpers.assertions import pytest_assert
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_random_side
from tests.common.dualtor.mux_simulator_control import mux_server_url

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
DEFAULT_MUX_SERVER_PORT = 8080

PTF_TEST_PORT_MAP = '/root/ptf_test_port_map.json'


@pytest.fixture(scope='module')
def config_facts(duthosts):
    return duthosts.config_facts(source='running')


@pytest.fixture(scope='module')
def minigraph_facts(duthosts, tbinfo):
    return duthosts.get_extended_minigraph_facts(tbinfo)


def get_fib_info(duthost, cfg_facts, mg_facts):
    """Get parsed FIB information from redis DB.

    Args:
        duthost (SonicHost): Object for interacting with DUT.
        cfg_facts (dict): Configuration facts.
        mg_facts (dict): Minigraph facts.

    Returns:
        dict: Map of prefix to PTF ports that are connected to DUT output ports.
            {
                '192.168.0.0/21': [],
                '192.168.8.0/25': [[58 59] [62 63] [66 67] [70 71]],
                '192.168.16.0/25': [[58 59] [62 63] [66 67] [70 71]],
                ...
                '20c0:c2e8:0:80::/64': [[58 59] [62 63] [66 67] [70 71]],
                '20c1:998::/64': [[58 59] [62 63] [66 67] [70 71]],
                ...
            }
    """
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    duthost.shell("redis-dump -d 0 -k 'ROUTE*' -y > /tmp/fib.{}.txt".format(timestamp))
    duthost.fetch(src="/tmp/fib.{}.txt".format(timestamp), dest="/tmp/fib")

    po = cfg_facts.get('PORTCHANNEL', {})
    ports = cfg_facts.get('PORT', {})

    fib_info = {}
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
                    oports.append([str(mg_facts['minigraph_ptf_indices'][x]) for x in po[ifname]['members']])
                else:
                    if ports.has_key(ifname):
                        oports.append([str(mg_facts['minigraph_ptf_indices'][ifname])])
                    else:
                        logger.info("Route point to non front panel port {}:{}".format(k, v))
                        skip = True

            # skip direct attached subnet
            if nh == '0.0.0.0' or nh == '::' or nh == "":
                skip = True

            if not skip:
                fib_info[prefix] = oports
            else:
                fib_info[prefix] = []
    return fib_info


def gen_fib_info_file(ptfhost, fib_info, filename):
    tmp_fib_info = tempfile.NamedTemporaryFile()
    for prefix, oports in fib_info.items():
        tmp_fib_info.write(prefix)
        if oports:
            for op in oports:
                tmp_fib_info.write(' [{}]'.format(' '.join(op)))
        else:
            tmp_fib_info.write(' []')
        tmp_fib_info.write('\n')
    tmp_fib_info.flush()
    ptfhost.copy(src=tmp_fib_info.name, dest=filename)


@pytest.fixture(scope='module')
def fib_info_files(duthosts, ptfhost, config_facts, minigraph_facts):
    files = []
    for dut_index, duthost in enumerate(duthosts):
        fib_info = get_fib_info(duthost, config_facts[duthost.hostname], minigraph_facts[duthost.hostname])
        filename = '/root/fib_info_dut{}.txt'.format(dut_index)
        gen_fib_info_file(ptfhost, fib_info, filename)
        files.append(filename)

    return files


@pytest.fixture(scope='module')
def disabled_ptf_ports(tbinfo):
    ports = set()
    for ptf_map in tbinfo['topo']['ptf_map_disabled'].values():
        for ptf_port_index in ptf_map.values():
            ports.add(ptf_port_index)
    return ports


@pytest.fixture(scope='module')
def vlan_ptf_ports(duthosts, config_facts, tbinfo):
    ports = set()
    for dut_index, duthost in enumerate(duthosts):
        for vlan_members in config_facts[duthost.hostname].get('VLAN_MEMBER', {}).values():
            for intf in vlan_members.keys():
                dut_port_index = config_facts[duthost.hostname]['port_index_map'][intf]
                ports.add(tbinfo['topo']['ptf_map'][str(dut_index)][str(dut_port_index)])
    return ports


@pytest.fixture(scope='module')
def router_macs(duthosts):
    mac_addresses = []
    for duthost in duthosts:
        mac_addresses.append(duthost.facts['router_mac'])
    return mac_addresses


# For dualtor
@pytest.fixture(scope='module')
def vlan_macs(duthosts, config_facts):
    mac_addresses = []
    for duthost in duthosts:
        dut_vlan_mac = None
        for vlan in config_facts[duthost.hostname].get('VLAN', {}).values():
            if 'mac' in vlan:
                dut_vlan_mac = vlan['mac']
                break
        if not dut_vlan_mac:
            dut_vlan_mac = duthost.facts['router_mac']
        mac_addresses.append(dut_vlan_mac)
    return mac_addresses


def set_mux_side(tbinfo, mux_server_url, side):
    if 'dualtor' in tbinfo['topo']['name']:
        res = requests.post(mux_server_url, json={"active_side": side})
        pytest_assert(res.status_code==200, 'Failed to set active side: {}'.format(res.text))
        return res.json()   # Response is new mux_status of all mux Y-cables.
    return {}


@pytest.fixture
def set_mux_random(tbinfo, mux_server_url):
    return set_mux_side(tbinfo, mux_server_url, 'random')


@pytest.fixture
def set_mux_same_side(tbinfo, mux_server_url):
    return set_mux_side(tbinfo, mux_server_url, random.choice(['upper_tor', 'lower_tor']))


@pytest.fixture
def get_mux_status(tbinfo, mux_server_url):
    if 'dualtor' in tbinfo['topo']['name']:
        res = requests.get(mux_server_url)
        pytest_assert(res.status_code==200, 'Failed to get mux status: {}'.format(res.text))
        return res.json()
    return {}


@pytest.fixture
def ptf_test_port_map(ptfhost, tbinfo, disabled_ptf_ports, vlan_ptf_ports, router_macs, vlan_macs, get_mux_status):
    active_dut_map = {}
    if get_mux_status:
        for mux_status in get_mux_status.values():
            active_dut_index = 0 if mux_status['active_side'] == 'upper_tor' else 1
            active_dut_map[str(mux_status['port_index'])] = active_dut_index

    logger.info('router_macs={}'.format(router_macs))
    logger.info('vlan_macs={}'.format(vlan_macs))
    logger.info('vlan_ptf_ports={}'.format(vlan_ptf_ports))
    logger.info('disabled_ptf_ports={}'.format(disabled_ptf_ports))
    logger.info('active_dut_map={}'.format(active_dut_map))

    ports_map = {}
    for ptf_port, dut_intf_map in tbinfo['topo']['ptf_dut_intf_map'].items():
        if int(ptf_port) in disabled_ptf_ports:
            continue

        target_dut_index = None
        target_mac = None
        if int(ptf_port) in vlan_ptf_ports:    # PTF port connected to VLAN interface of DUT
            if active_dut_map:  # dualtor topology
                # If PTF port is connected to VLAN interface of dualToR DUTs, the PTF port index should be
                # same as DUT port index. Base on this fact to find out dut index of active side.
                target_dut_index = active_dut_map[ptf_port]
                target_mac = vlan_macs[target_dut_index]

        if not target_dut_index:
            target_dut_index = int(dut_intf_map.keys()[0])
        if not target_mac:
            target_mac = router_macs[target_dut_index]
        ports_map[ptf_port] = {'target_dut': target_dut_index, 'target_mac': target_mac}

    ptfhost.copy(content=json.dumps(ports_map), dest=PTF_TEST_PORT_MAP)
    return PTF_TEST_PORT_MAP


@pytest.mark.parametrize("ipv4, ipv6, mtu", [pytest.param(True, True, 1514)])
def test_basic_fib(duthosts, ptfhost, ipv4, ipv6, mtu, fib_info_files, router_macs, set_mux_random, ptf_test_port_map):
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')

    # do not test load balancing for vs platform as kernel 4.9
    # can only do load balance base on L3
    if duthosts[0].facts['asic_type'] in ["vs"]:
        test_balancing = False
    else:
        test_balancing = True

    logging.info("run ptf test")
    log_file = "/tmp/fib_test.FibTest.ipv4.{}.ipv6.{}.{}.log".format(ipv4, ipv6, timestamp)
    logging.info("PTF log file: %s" % log_file)
    ptf_runner(ptfhost,
                "ptftests",
                "fib_test.FibTest",
                platform_dir="ptftests",
                params={"fib_info_files": fib_info_files[:2],  # Test at most 2 DUTs
                        "ptf_test_port_map": ptf_test_port_map,
                        "router_macs": router_macs,
                        "ipv4": ipv4,
                        "ipv6": ipv6,
                        "testbed_mtu": mtu,
                        "test_balancing": test_balancing },
                log_file=log_file,
                qlen=PTF_QLEN,
                socket_recv_size=16384)


def get_vlan_untag_ports(duthosts, config_facts):
    """
    get all untag vlan ports
    """
    vlan_untag_ports = {}
    for duthost in duthosts:
        ports = []
        vlans = config_facts.get('VLAN_INTERFACE', {}).keys()
        for vlan in vlans:
            vlan_member_info = config_facts[duthost.hostname].get('VLAN_MEMBER', {}).get(vlan, {})
            if vlan_member_info:
                for port_name, tag_mode in vlan_member_info.items():
                    if tag_mode['tagging_mode'] == 'untagged':
                        ports.append(port_name)
        vlan_untag_ports[duthost.hostname] = ports
    return vlan_untag_ports


@pytest.fixture(scope="module")
def hash_keys(duthost):
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
    # removing ingress-port and ip-proto from hash_keys not supported by Marvell SAI
    if duthost.facts['platform'] in ['armhf-nokia_ixs7215_52x-r0']:
        if 'ip-proto' in hash_keys:
            hash_keys.remove('ip-proto')
        if 'ingress-port' in hash_keys:
            hash_keys.remove('ingress-port')

    return hash_keys


def configure_vlan(duthost, ports):
    for vlan in VLANIDS:
        duthost.shell('config vlan add {}'.format(vlan))
        for port in ports:
            duthost.shell('config vlan member add {} {}'.format(vlan, port))
        duthost.shell('config interface ip add Vlan{} '.format(vlan) + VLANIP.format(vlan%256))
    time.sleep(5)


def unconfigure_vlan(duthost, ports):
    for vlan in VLANIDS:
        for port in ports:
            duthost.shell('config vlan member del {} {}'.format(vlan, port))
        duthost.shell('config interface ip remove Vlan{} '.format(vlan) + VLANIP.format(vlan%256))
        duthost.shell('config vlan del {}'.format(vlan))
    time.sleep(5)


@pytest.fixture
def setup_vlan(tbinfo, duthosts, config_facts, hash_keys):

    vlan_untag_ports = get_vlan_untag_ports(duthosts, config_facts)
    need_to_clean_vlan = False

    # add some vlan for hash_key vlan-id test
    if tbinfo['topo']['type'] == 't0' and 'dualtor' not in tbinfo['topo']['name'] and 'vlan-id' in hash_keys:
        for duthost in duthosts:
            configure_vlan(duthost, vlan_untag_ports[duthost.hostname])
        need_to_clean_vlan = True

    yield

    # remove added vlan
    if need_to_clean_vlan:
        for duthost in duthosts:
            unconfigure_vlan(duthost, vlan_untag_ports[duthost.hostname])


@pytest.fixture(params=["ipv4", "ipv6"])
def ipver(request):
    return request.param


def test_hash(fib_info_files, setup_vlan, hash_keys, ptfhost, ipver, router_macs, set_mux_same_side, ptf_test_port_map):
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/hash_test.HashTest.{}.{}.log".format(ipver, timestamp)
    logging.info("PTF log file: %s" % log_file)
    if ipver == "ipv4":
        src_ip_range = SRC_IP_RANGE
        dst_ip_range = DST_IP_RANGE
    else:
        src_ip_range = SRC_IPV6_RANGE
        dst_ip_range = DST_IPV6_RANGE

    ptf_runner(ptfhost,
            "ptftests",
            "hash_test.HashTest",
            platform_dir="ptftests",
            params={"fib_info_files": fib_info_files[:2],   # Test at most 2 DUTs
                    "ptf_test_port_map": ptf_test_port_map,
                    "hash_keys": hash_keys,
                    "src_ip_range": ",".join(src_ip_range),
                    "dst_ip_range": ",".join(dst_ip_range),
                    "router_macs": router_macs,
                    "vlan_ids": VLANIDS},
            log_file=log_file,
            qlen=PTF_QLEN,
            socket_recv_size=16384)
