import sys
import time
import threading
import Queue
import yaml
import json
import random
import logging

from collections import OrderedDict
from natsort import natsorted
from netaddr import IPNetwork

import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner
from tests.common.utilities import wait_until
from tests.common.reboot import reboot

"""
    During vrf testing, a vrf basic configuration need to be setup before any tests,
    and cleanup after all tests. Both of the two tasks should be called only once.

    A module-scoped fixture `setup_vrf` is added to accompilsh the setup/cleanup tasks.
    We want to use ansible_adhoc/tbinfo fixtures during the setup/cleanup stages, but
        1. Injecting fixtures to xunit-style setup/teardown functions is not support by
            [now](https://github.com/pytest-dev/pytest/issues/5289).
        2. Calling a fixture function directly is deprecated.
    So, we prefer a fixture rather than xunit-style setup/teardown functions.
"""

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

# global variables
g_vars = {}

# helper functions
def get_vlan_members(vlan_name, cfg_facts):
    tmp_member_list = []

    for m in cfg_facts['VLAN_MEMBER'].keys():
        v, port = m.split('|')
        if vlan_name == v:
            tmp_member_list.append(port)

    return natsorted(tmp_member_list)

def get_pc_members(portchannel_name, cfg_facts):
    tmp_member_list = []

    for m in cfg_facts['PORTCHANNEL_MEMBER'].keys():
        pc, port = m.split('|')
        if portchannel_name == pc:
            tmp_member_list.append(port)

    return natsorted(tmp_member_list)

def get_intf_ips(interface_name, cfg_facts):
    prefix_to_intf_table_map = {
        'Vlan': 'VLAN_INTERFACE',
        'PortChannel': 'PORTCHANNEL_INTERFACE',
        'Ethernet': 'INTERFACE',
        'Loopback': 'LOOPBACK_INTERFACE'
    }

    intf_table_name = None

    ip_facts = {
        'ipv4': [],
        'ipv6': []
    }

    for pfx, t_name in prefix_to_intf_table_map.iteritems():
        if pfx in interface_name:
            intf_table_name = t_name
            break

    if intf_table_name is None:
        return ip_facts

    for intf in cfg_facts[intf_table_name]:
        if '|' in intf:
            if_name, ip = intf.split('|')
            if if_name == interface_name:
                ip = IPNetwork(ip)
                if ip.version == 4:
                    ip_facts['ipv4'].append(ip)
                else:
                    ip_facts['ipv6'].append(ip)

    return ip_facts

def get_cfg_facts(duthost):
    tmp_facts = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])  # return config db contents(running-config)

    port_name_list_sorted = natsorted(tmp_facts['PORT'].keys())
    port_index_map = {}
    for idx, val in enumerate(port_name_list_sorted):
        port_index_map[val] = idx

    tmp_facts['config_port_indices'] = port_index_map

    return tmp_facts

def get_host_facts(duthost):
    return duthost.setup()['ansible_facts']

def get_vrf_intfs(cfg_facts):
    intf_tables = ['INTERFACE', 'PORTCHANNEL_INTERFACE', 'VLAN_INTERFACE', 'LOOPBACK_INTERFACE']
    vrf_intfs = {}

    for table in intf_tables:
        for intf, attrs in cfg_facts.get(table, {}).iteritems():
            if '|' not in intf:
                vrf = attrs['vrf_name']
                if vrf not in vrf_intfs:
                    vrf_intfs[vrf] = {}
                vrf_intfs[vrf][intf] = get_intf_ips(intf, cfg_facts)

    return vrf_intfs

def get_vrf_ports(cfg_facts):
    '''
    :return: vrf_member_port_indices, vrf_intf_member_port_indices
    '''

    vlan_member = cfg_facts['VLAN_MEMBER'].keys()
    pc_member = cfg_facts['PORTCHANNEL_MEMBER'].keys()
    member = vlan_member + pc_member

    vrf_intf_member_port_indices = {}
    vrf_member_port_indices = {}

    vrf_intfs = get_vrf_intfs(cfg_facts)

    for vrf, intfs in vrf_intfs.iteritems():
        vrf_intf_member_port_indices[vrf] = {}
        vrf_member_port_indices[vrf] = []

        for intf in intfs:
            vrf_intf_member_port_indices[vrf][intf] = natsorted(
                    [ cfg_facts['config_port_indices'][m.split('|')[1]] for m in filter(lambda m: intf in m, member) ]
                )
            vrf_member_port_indices[vrf].extend(vrf_intf_member_port_indices[vrf][intf])

        vrf_member_port_indices[vrf] = natsorted(vrf_member_port_indices[vrf])

    return vrf_intf_member_port_indices, vrf_member_port_indices

def ex_ptf_runner(ptf_runner, exc_queue, **kwargs):
    '''
    With this simple warpper function, we could use a Queue to store the
    exception infos and check it later in main thread.

    Example:
        refer to test 'test_vrf_swss_warm_reboot'
    '''
    try:
        ptf_runner(**kwargs)
    except Exception:
        exc_queue.put(sys.exc_info())

def finalize_warmboot(duthost, comp_list=None, retry=30, interval=5):
    '''
    Check if componets finish warmboot(reconciled).
    '''
    DEFAULT_COMPONENT_LIST = ['orchagent', 'neighsyncd']
    EXP_STATE = 'reconciled'

    comp_list = comp_list or DEFAULT_COMPONENT_LIST

    # wait up to $retry * $interval secs
    for _ in range(retry):
        for comp in comp_list:
            state =  duthost.shell('/usr/bin/redis-cli -n 6 hget "WARM_RESTART_TABLE|{}" state'.format(comp), module_ignore_errors=True)['stdout']
            logger.info("{} : {}".format(comp, state))
            if EXP_STATE == state:
                comp_list.remove(comp)
        if len(comp_list) == 0:
            break
        time.sleep(interval)
        logger.info("Slept {} seconds!".format(interval))

    return  comp_list

def check_interface_status(duthost, up_ports):
    intf_facts = duthost.interface_facts(up_ports=up_ports)['ansible_facts']
    if len(intf_facts['ansible_interface_link_down_ports']) != 0:
        logger.info("Some ports went down: {} ...".format(intf_facts['ansible_interface_link_down_ports']))
        return False
    return True

def check_bgp_peer_state(duthost, vrf, peer_ip, expected_state):
    peer_info = json.loads(duthost.shell("vtysh -c 'show bgp vrf {} neighbors {} json'".format(vrf, peer_ip))['stdout'])

    logger.debug("Vrf {} bgp peer {} infos: {}".format(vrf, peer_ip, peer_info))

    try:
        peer_state = peer_info[peer_ip].get('bgpState', 'Unknown')
    except Exception as e:
        peer_state = 'Unknown'
    if  peer_state != expected_state:
        logger.info("Vrf {} bgp peer {} is {}, exptected {}!".format(vrf, peer_ip, peer_state, expected_state))
        return False

    return True

def check_bgp_facts(duthost, cfg_facts):
    result = {}
    for neigh in cfg_facts['BGP_NEIGHBOR']:
        if '|' not in neigh:
            vrf = 'default'
            peer_ip = neigh
        else:
            vrf, peer_ip = neigh.split('|')

        result[(vrf, peer_ip)] = check_bgp_peer_state(duthost, vrf, peer_ip, expected_state='Established')

    return all(result.values())

def setup_vrf_cfg(duthost, localhost, cfg_facts):
    '''
    setup vrf configuration on dut before test suite
    '''

    # FIXME
    # For vrf testing, we should create a new vrf topology
    # might named to be 't0-vrf', deploy with minigraph templates.
    #
    # But currently vrf related schema does not properly define in minigraph.
    # So we generate and deploy vrf basic configuration with a vrf jinja2 template,
    # later should move to minigraph or a better way(VRF and BGP cli).

    from copy import deepcopy
    cfg_t0 = deepcopy(cfg_facts)

    cfg_t0.pop('config_port_indices', None)

    # get members from Vlan1000, and move half of them to Vlan2000 in vrf basic cfg
    ports = get_vlan_members('Vlan1000', cfg_facts)

    vlan_ports = {'Vlan1000': ports[:len(ports)/2],
                  'Vlan2000': ports[len(ports)/2:]}

    extra_vars = {'cfg_t0': cfg_t0,
                  'vlan_ports': vlan_ports}

    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)

    duthost.template(src="vrf/vrf_config_db.j2", dest="/tmp/config_db_vrf.json")
    duthost.shell("cp /tmp/config_db_vrf.json /etc/sonic/config_db.json")

    reboot(duthost, localhost)


def setup_vlan_peer(duthost, ptfhost, cfg_facts):
    '''
    setup vlan peer ip addresses on peer port(ptf).

    Example:
    vid         local-port  peer-port    peer-macvlan-dev   peer-namespace    peer-ip
    Vlan1000    Ethernet1   eth1         e1mv1              ns1000            192.168.0.2/21
                                                                              FC00:192::2/117
    Vlan2000    Ethernet13  eth13        e13mv1             ns2000            192.168.0.2/21
                                                                              FC00:192::2/117
    '''
    vlan_peer_ips = {}
    vlan_peer_vrf2ns_map = {}

    for vlan in cfg_facts['VLAN'].keys():
        ns = 'ns' + vlan.strip('Vlan')
        vrf = cfg_facts['VLAN_INTERFACE'][vlan]['vrf_name']
        vlan_peer_vrf2ns_map[vrf] = ns

        vlan_port = get_vlan_members(vlan, cfg_facts)[0]
        vlan_peer_port = cfg_facts['config_port_indices'][vlan_port]

        # deploy peer namespace on ptf
        ptfhost.shell("ip netns add {}".format(ns))

        # bind port to namespace
        ptfhost.shell("ip link add e{}mv1 link eth{} type macvlan mode bridge".format(vlan_peer_port, vlan_peer_port))
        ptfhost.shell("ip link set e{}mv1 netns {}".format(vlan_peer_port, ns))
        ptfhost.shell("ip netns exec {} ip link set dev e{}mv1 up".format(ns, vlan_peer_port))

        # setup peer ip on ptf
        if (vrf, vlan_peer_port) not in vlan_peer_ips:
            vlan_peer_ips[(vrf, vlan_peer_port)] = {'ipv4': [], 'ipv6': []}

        vlan_ips = get_intf_ips(vlan, cfg_facts)
        for ver, ips in vlan_ips.iteritems():
            for ip in ips:
                neigh_ip = IPNetwork("{}/{}".format(ip.ip+1, ip.prefixlen))
                ptfhost.shell("ip netns exec {} ip address add {} dev e{}mv1".format(ns, neigh_ip, vlan_peer_port))

                # ping to trigger neigh resolving
                ping_cmd = 'ping' if neigh_ip.version ==4 else 'ping6'
                duthost.shell("{} -I {} {} -c 1 -f -W1".format(ping_cmd, vrf, neigh_ip.ip), module_ignore_errors=True)

            vlan_peer_ips[(vrf, vlan_peer_port)][ver].append(neigh_ip)

    return vlan_peer_ips, vlan_peer_vrf2ns_map

def cleanup_vlan_peer(ptfhost, vlan_peer_vrf2ns_map):
    for vrf, ns in vlan_peer_vrf2ns_map.iteritems():
        ptfhost.shell("ip netns del {}".format(ns))

def gen_vrf_fib_file(vrf, tbinfo, ptfhost, dst_intfs, \
                     render_file, limited_podset_number=10, limited_tor_number=10):
    extra_vars = {
        'testbed_type': tbinfo['topo']['name'],
        'props': g_vars['props'],
        'intf_member_indices': g_vars['vrf_intf_member_port_indices'][vrf],
        'dst_intfs': dst_intfs,
        'limited_podset_number': limited_podset_number,
        'limited_tor_number': limited_tor_number
    }

    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)

    ptfhost.template(src="vrf/vrf_fib.j2", dest=render_file)

def gen_vrf_neigh_file(vrf, ptfhost, render_file):
    extra_vars = {
        'intf_member_indices': g_vars['vrf_intf_member_port_indices'][vrf],
        'intf_ips': g_vars['vrf_intfs'][vrf]
    }

    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)

    ptfhost.template(src="vrf/vrf_neigh.j2", dest=render_file)

# fixtures
@pytest.fixture(scope="module")
def host_facts(duthost):
    return get_host_facts(duthost)

@pytest.fixture(scope="module")
def cfg_facts(duthost):
    return get_cfg_facts(duthost)

def restore_config_db(localhost, duthost, ptfhost):
    # In case something went wrong in previous reboot, wait until the DUT is accessible to ensure that
    # the `mv /etc/sonic/config_db.json.bak /etc/sonic/config_db.json` is executed on DUT.
    # If the DUT is still inaccessible after timeout, we may have already lose the DUT. Something sad happened.
    localhost.wait_for(host=g_vars["dut_ip"],
                        port=22,
                        state='started',
                        search_regex='OpenSSH_[\\w\\.]+ Debian',
                        timeout=180)   # Similiar approach to increase the chance that the next line get executed.
    duthost.shell("mv /etc/sonic/config_db.json.bak /etc/sonic/config_db.json")
    reboot(duthost, localhost)

    if 'vlan_peer_vrf2ns_map' in g_vars:
        cleanup_vlan_peer(ptfhost, g_vars['vlan_peer_vrf2ns_map'])

@pytest.fixture(scope="module", autouse=True)
def setup_vrf(tbinfo, duthost, ptfhost, localhost, host_facts):

    # backup config_db.json
    duthost.shell("mv /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")

    ## Setup global variables
    global g_vars

    try:
        ## Setup dut
        g_vars["dut_ip"] = duthost.host.options["inventory_manager"].get_host(duthost.hostname).vars["ansible_host"]
        duthost.critical_services = ["swss", "syncd", "database", "teamd", "bgp"]  # Don't care about 'pmon' and 'lldp' here
        cfg_t0 = get_cfg_facts(duthost)  # generate cfg_facts for t0 topo

        setup_vrf_cfg(duthost, localhost, cfg_t0)

        # Generate cfg_facts for t0-vrf topo, should not use cfg_facts fixture here. Otherwise, the cfg_facts
        # fixture will be executed before setup_vrf and will have the original non-VRF config facts.
        cfg_facts = get_cfg_facts(duthost)

        duthost.shell("sonic-clear arp")
        duthost.shell("sonic-clear nd")
        duthost.shell("sonic-clear fdb all")

        with open("../ansible/vars/topo_{}.yml".format(tbinfo['topo']['name']), 'r') as fh:
            g_vars['topo_properties'] = yaml.safe_load(fh)

        g_vars['props'] = g_vars['topo_properties']['configuration_properties']['common']

        g_vars['vlan_peer_ips'], g_vars['vlan_peer_vrf2ns_map'] = setup_vlan_peer(duthost, ptfhost, cfg_facts)

        g_vars['vrf_intfs'] = get_vrf_intfs(cfg_facts)

        g_vars['vrf_intf_member_port_indices'], g_vars['vrf_member_port_indices'] = get_vrf_ports(cfg_facts)

    except Exception as e:
        # Ensure that config_db is restored.
        # If exception is raised in setup, the teardown code won't be executed. That's why we need to capture
        # exception and do cleanup here in setup part (code before 'yield').
        logger.error("Exception raised in setup: {}".format(repr(e)))
        logger.error(json.dumps(traceback.format_exception(*sys.exc_info()), indent=2))

        restore_config_db(localhost, duthost, ptfhost)

        # Setup failed. There is no point to continue running the cases.
        pytest.fail("VRF testing setup failed")    # If this line is hit, script execution will stop here

    # --------------------- Testing -----------------------
    yield

    # --------------------- Teardown -----------------------
    restore_config_db(localhost, duthost, ptfhost)


@pytest.fixture
def partial_ptf_runner(request, ptfhost, tbinfo, host_facts):
    def _partial_ptf_runner(testname, **kwargs):
        params = {'testbed_type': tbinfo['topo']['name'],
                  'router_mac': host_facts['ansible_Ethernet0']['macaddress']}
        params.update(kwargs)
        ptf_runner(host=ptfhost,
                   testdir="ptftests",
                   platform_dir="ptftests",
                   testname=testname,
                   params=params,
                   log_file="/tmp/{}.{}.log".format(request.cls.__name__, request.function.__name__))
    return _partial_ptf_runner


# tests
class TestVrfCreateAndBind():
    def test_vrf_in_kernel(self, duthost, cfg_facts):
        # verify vrf in kernel
        res = duthost.shell("ip link show type vrf | grep Vrf")

        for vrf in cfg_facts['VRF'].keys():
            assert vrf in res['stdout'], "%s should be created in kernel!" % vrf

        for vrf, intfs in g_vars['vrf_intfs'].iteritems():
            for intf in intfs:
                res = duthost.shell("ip link show %s" % intf)
                assert vrf in res['stdout'], "The master dev of interface %s should be %s !" % (intf, vrf)

    def test_vrf_in_appl_db(self, duthost, cfg_facts):
        # verify vrf in app_db
        for vrf in cfg_facts['VRF'].keys():
            res = duthost.shell("redis-cli -n 0 keys VRF_TABLE:%s" % vrf)
            assert vrf in res['stdout'], "%s should be added in APPL_DB!" % vrf

        for vrf, intfs in g_vars['vrf_intfs'].iteritems():
            for intf in intfs:
                res = duthost.shell("redis-cli -n 0 hgetall \"INTF_TABLE:%s\"" % intf)
                assert vrf in res['stdout'], "The vrf of interface %s should be %s !" % (intf, vrf)

    def test_vrf_in_asic_db(self, duthost, cfg_facts):
        # verify vrf in asic_db
        vrf_count = len(cfg_facts['VRF'].keys()) + 1  # plus default virtual router
        res = duthost.shell("redis-cli -n 1 keys *VIRTUAL_ROUTER*")
        assert len(res['stdout_lines']) == vrf_count


class TestVrfNeigh():
    def test_ping_lag_neigh(self, duthost, cfg_facts):
        for neigh in cfg_facts['BGP_NEIGHBOR']:
            if '|' not in neigh:
                continue

            vrf, neigh_ip = neigh.split('|')
            if IPNetwork(neigh_ip).version == 4:
                ping_cmd = 'ping'
            else:
                ping_cmd = 'ping6'

            cmd = "{} {} -I {} -c 3 -f".format(ping_cmd, neigh_ip, vrf)

            duthost.shell(cmd)

    def test_ping_vlan_neigh(self, duthost):
        for (vrf, _), neigh_ips in g_vars['vlan_peer_ips'].iteritems():
            for ver, ips in neigh_ips.iteritems():
                ping_cmd = 'ping' if ver == 'ipv4' else 'ping6'
                for ip in ips:
                    duthost.shell("{} {} -c 3 -I {} -f".format(ping_cmd, ip.ip, vrf))

    def test_vrf1_neigh_ip_fwd(self, ptfhost, partial_ptf_runner):
        gen_vrf_neigh_file('Vrf1', ptfhost, render_file="/tmp/vrf1_neigh.txt")

        partial_ptf_runner(
            testname="vrf_test.FwdTest",
            fwd_info="/tmp/vrf1_neigh.txt",
            src_ports=g_vars['vrf_member_port_indices']['Vrf1']
        )

    def test_vrf2_neigh_ip_fwd(self, ptfhost, partial_ptf_runner):
        gen_vrf_neigh_file('Vrf2', ptfhost, render_file="/tmp/vrf2_neigh.txt")

        partial_ptf_runner(
            testname="vrf_test.FwdTest",
            fwd_info="/tmp/vrf2_neigh.txt",
            src_ports=g_vars['vrf_member_port_indices']['Vrf2']
        )

class TestVrfFib():

    @pytest.fixture(scope="class", autouse=True)
    def setup_fib_test(self, ptfhost, tbinfo):
        gen_vrf_fib_file('Vrf1', tbinfo, ptfhost,
                    dst_intfs=['PortChannel0001', 'PortChannel0002'],
                    render_file='/tmp/vrf1_fib.txt')

        gen_vrf_fib_file('Vrf2', tbinfo, ptfhost,
                    dst_intfs=['PortChannel0003', 'PortChannel0004'],
                    render_file='/tmp/vrf2_fib.txt')

    def test_show_bgp_summary(self, duthost, cfg_facts):
        props = g_vars['props']
        route_count = props['podset_number'] * props['tor_number'] * props['tor_subnet_number']

        for vrf in cfg_facts['VRF']:

            bgp_summary_string = duthost.shell("show bgp vrf {} summary json".format(vrf))['stdout']
            bgp_summary = json.loads(bgp_summary_string)

            for info in bgp_summary.itervalues():
                for peer, attr in info['peers'].iteritems():
                    prefix_count = attr['prefixReceivedCount']
                    assert int(prefix_count) == route_count, "%s should received %s route prefixs!" % (peer, route_count)

    def test_vrf1_fib(self, partial_ptf_runner):
        partial_ptf_runner(
            testname="vrf_test.FibTest",
            fib_info="/tmp/vrf1_fib.txt",
            src_ports=g_vars['vrf_member_port_indices']['Vrf1']
        )

    def test_vrf2_fib(self, partial_ptf_runner):
        partial_ptf_runner(
            testname="vrf_test.FibTest",
            fib_info="/tmp/vrf2_fib.txt",
            src_ports=g_vars['vrf_member_port_indices']['Vrf2']
        )


class TestVrfIsolation():

    @pytest.fixture(scope="class", autouse=True)
    def setup_vrf_isolation(self, ptfhost, tbinfo):
        gen_vrf_fib_file('Vrf1', tbinfo, ptfhost,
                    dst_intfs=['PortChannel0001', 'PortChannel0002'],
                    render_file='/tmp/vrf1_fib.txt')

        gen_vrf_fib_file('Vrf2', tbinfo, ptfhost,
                    dst_intfs=['PortChannel0003', 'PortChannel0004'],
                    render_file='/tmp/vrf2_fib.txt')

        gen_vrf_neigh_file('Vrf1', ptfhost, render_file="/tmp/vrf1_neigh.txt")

        gen_vrf_neigh_file('Vrf2', ptfhost, render_file="/tmp/vrf2_neigh.txt")

    def test_neigh_isolate_vrf1_from_vrf2(self, partial_ptf_runner):
        # send packets from Vrf1
        partial_ptf_runner(
            testname="vrf_test.FwdTest",
            fwd_info="/tmp/vrf2_neigh.txt",
            pkt_action='drop',
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )

    def test_neigh_isolate_vrf2_from_vrf1(self, partial_ptf_runner):
        # send packets from Vrf2
        partial_ptf_runner(
            testname="vrf_test.FwdTest",
            fwd_info="/tmp/vrf1_neigh.txt",
            pkt_action='drop',
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf2']['Vlan2000']
        )

    def test_fib_isolate_vrf1_from_vrf2(self, partial_ptf_runner):
        # send packets from Vrf1
        partial_ptf_runner(
            testname="vrf_test.FibTest",
            fib_info="/tmp/vrf2_fib.txt",
            pkt_action='drop',
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )

    def test_fib_isolate_vrf2_from_vrf1(self, partial_ptf_runner):
        # send packets from Vrf2
        partial_ptf_runner(
            testname="vrf_test.FibTest",
            fib_info="/tmp/vrf1_fib.txt",
            pkt_action='drop',
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf2']['Vlan2000']
        )


class TestVrfAclRedirect():
    c_vars = {}

    @pytest.fixture(scope="class", autouse=True)
    def setup_acl_redirect(self, duthost, cfg_facts):
        # -------- Setup ----------

        # make sure neighs from Vlan2000 are resolved
        vlan_peer_port = g_vars['vrf_intf_member_port_indices']['Vrf2']['Vlan2000'][0]
        vlan_neigh_ip = g_vars['vlan_peer_ips'][('Vrf2', vlan_peer_port)]['ipv4'][0]
        duthost.shell("ping {} -I {} -c 3 -f".format(vlan_neigh_ip.ip, 'Vrf2'))

        vrf_intf_ports = g_vars['vrf_intf_member_port_indices']
        src_ports = [vrf_intf_ports['Vrf1']['Vlan1000'][0]]
        dst_ports = [vrf_intf_ports['Vrf1']['PortChannel0001']]

        pc1_intf_ips = get_intf_ips('PortChannel0001', cfg_facts)
        pc1_v4_neigh_ips = [ str(ip.ip+1) for ip in pc1_intf_ips['ipv4'] ]
        pc1_v6_neigh_ips = [ str(ip.ip+1) for ip in pc1_intf_ips['ipv6'] ]

        pc2_if_name = 'PortChannel0002'
        pc2_if_ips = get_intf_ips(pc2_if_name, cfg_facts)
        pc2_v4_neigh_ips = [ (pc2_if_name, str(ip.ip+1)) for ip in pc2_if_ips['ipv4'] ]
        pc2_v6_neigh_ips = [ (pc2_if_name, str(ip.ip+1)) for ip in pc2_if_ips['ipv6'] ]

        pc4_if_name = 'PortChannel0004'
        pc4_if_ips = get_intf_ips(pc4_if_name, cfg_facts)
        pc4_v4_neigh_ips = [ (pc4_if_name, str(ip.ip+1)) for ip in pc4_if_ips['ipv4'] ]
        pc4_v6_neigh_ips = [ (pc4_if_name, str(ip.ip+1)) for ip in pc4_if_ips['ipv6'] ]

        redirect_dst_ips = pc2_v4_neigh_ips + pc4_v4_neigh_ips
        redirect_dst_ipv6s = pc2_v6_neigh_ips + pc4_v6_neigh_ips
        redirect_dst_ports = []
        redirect_dst_ports.append(vrf_intf_ports['Vrf1'][pc2_if_name])
        redirect_dst_ports.append(vrf_intf_ports['Vrf2'][pc4_if_name])

        self.c_vars['src_ports'] = src_ports
        self.c_vars['dst_ports'] = dst_ports
        self.c_vars['redirect_dst_ports'] = redirect_dst_ports
        self.c_vars['pc1_v4_neigh_ips'] = pc1_v4_neigh_ips
        self.c_vars['pc1_v6_neigh_ips'] = pc1_v6_neigh_ips

        # load acl redirect configuration
        extra_vars = {
            'src_port': get_vlan_members('Vlan1000', cfg_facts)[0],
            'redirect_dst_ips': redirect_dst_ips,
            'redirect_dst_ipv6s': redirect_dst_ipv6s
        }
        duthost.host.options['variable_manager'].extra_vars.update(extra_vars)
        duthost.template(src="vrf/vrf_acl_redirect.j2", dest="/tmp/vrf_acl_redirect.json")
        duthost.shell("config load -y /tmp/vrf_acl_redirect.json")

        # -------- Testing ----------
        yield

        # -------- Teardown ----------
        duthost.shell("redis-cli -n 4 del 'ACL_RULE|VRF_ACL_REDIRECT_V4|rule1'")
        duthost.shell("redis-cli -n 4 del 'ACL_RULE|VRF_ACL_REDIRECT_V6|rule1'")
        duthost.shell("redis-cli -n 4 del 'ACL_TABLE|VRF_ACL_REDIRECT_V4'")
        duthost.shell("redis-cli -n 4 del 'ACL_TABLE|VRF_ACL_REDIRECT_V6'")

    def test_origin_ports_recv_no_pkts_v4(self, partial_ptf_runner):
        # verify origin dst ports should not receive packets any more
        partial_ptf_runner(
            testname="vrf_test.FwdTest",
            pkt_action='drop',
            src_ports=self.c_vars['src_ports'],
            dst_ports=self.c_vars['dst_ports'],
            dst_ips=self.c_vars['pc1_v4_neigh_ips']
        )

    def test_origin_ports_recv_no_pkts_v6(self, partial_ptf_runner):
        # verify origin dst ports should not receive packets any more
        partial_ptf_runner(
            testname="vrf_test.FwdTest",
            pkt_action='drop',
            src_ports=self.c_vars['src_ports'],
            dst_ports=self.c_vars['dst_ports'],
            dst_ips=self.c_vars['pc1_v6_neigh_ips']
        )

    def test_redirect_to_new_ports_v4(self, partial_ptf_runner):
        # verify redicect ports should receive packets
        partial_ptf_runner(
            testname="vrf_test.FwdTest",
            src_ports=self.c_vars['src_ports'],
            dst_ports=self.c_vars['redirect_dst_ports'],
            test_balancing=True,
            balancing_test_times=1000,
            balancing_test_ratio=1.0,  # test redirect balancing
            dst_ips=self.c_vars['pc1_v4_neigh_ips']
        )

    def test_redirect_to_new_ports_v6(self, partial_ptf_runner):
        # verify redicect ports should receive packets
        partial_ptf_runner(
            testname="vrf_test.FwdTest",
            src_ports=self.c_vars['src_ports'],
            dst_ports=self.c_vars['redirect_dst_ports'],
            test_balancing=True,
            balancing_test_times=1000,
            balancing_test_ratio=1.0,  # test redirect balancing
            dst_ips=self.c_vars['pc1_v6_neigh_ips']
        )


class TestVrfLoopbackIntf():

    c_vars = {}
    announce_prefix = '10.10.10.0/26'

    @pytest.fixture(scope="class", autouse=True)
    def setup_vrf_loopback(self, ptfhost, cfg_facts, tbinfo):
        # -------- Setup ----------
        lb0_ip_facts = get_intf_ips('Loopback0', cfg_facts)
        vlan1000_ip_facts = get_intf_ips('Vlan1000', cfg_facts)
        lb2_ip_facts = get_intf_ips('Loopback2', cfg_facts)
        vlan2000_ip_facts = get_intf_ips('Vlan2000', cfg_facts)

        self.c_vars['lb0_ip_facts'] = lb0_ip_facts
        self.c_vars['lb2_ip_facts'] = lb2_ip_facts
        self.c_vars['vlan1000_ip_facts'] = vlan1000_ip_facts
        self.c_vars['vlan2000_ip_facts'] = vlan2000_ip_facts

        # deploy routes to loopback
        for ver, ips in lb0_ip_facts.iteritems():
            for vlan_ip in vlan1000_ip_facts[ver]:
                nexthop = vlan_ip.ip
                break
            for ip in ips:
                ptfhost.shell("ip netns exec {} ip route add {} nexthop via {} ".format(g_vars['vlan_peer_vrf2ns_map']['Vrf1'], ip, nexthop))

        for ver, ips in lb2_ip_facts.iteritems():
            for vlan_ip in vlan2000_ip_facts[ver]:
                nexthop = vlan_ip.ip
                break
            for ip in ips:
                ptfhost.shell("ip netns exec {} ip route add {} nexthop via {} ".format(g_vars['vlan_peer_vrf2ns_map']['Vrf2'], ip, nexthop))

        # -------- Testing ----------
        yield

        # -------- Teardown ----------
        # routes on ptf could be flushed when remove vrfs
        pass

    def test_ping_vrf1_loopback(self, ptfhost, duthost):
        for ver, ips in self.c_vars['lb0_ip_facts'].iteritems():
            for ip in ips:
                if ip.version == 4:
                    # FIXME Within a vrf, currently ping(4) does not support using
                    # an ip of loopback intface as source(it complains 'Cannot assign
                    # requested address'). An alternative is ping the loopback address
                    # from ptf
                    ptfhost.shell("ip netns exec {} ping {} -c 3 -f -W2".format(g_vars['vlan_peer_vrf2ns_map']['Vrf1'], ip.ip))
                else:
                    neigh_ip6 = self.c_vars['vlan1000_ip_facts']['ipv6'][0].ip + 1
                    duthost.shell("ping6 {} -I Vrf1 -I {} -c 3 -f -W2".format(neigh_ip6, ip.ip))

    def test_ping_vrf2_loopback(self, ptfhost, duthost):
        for ver, ips in self.c_vars['lb2_ip_facts'].iteritems():
            for ip in ips:
                if ip.version == 4:
                    # FIXME Within a vrf, currently ping(4) does not support using
                    # an ip of loopback intface as source(it complains 'Cannot assign
                    # requested address'). An alternative is ping the loopback address
                    # from ptf
                    ptfhost.shell("ip netns exec {} ping {} -c 3 -f -W2".format(g_vars['vlan_peer_vrf2ns_map']['Vrf2'], ip.ip))
                else:
                    neigh_ip6 = self.c_vars['vlan2000_ip_facts']['ipv6'][0].ip + 1
                    duthost.shell("ping6 {} -I Vrf2 -I {} -c 3 -f -W2".format(neigh_ip6, ip.ip))

    @pytest.fixture
    def setup_bgp_with_loopback(self, duthost, ptfhost, cfg_facts):

        # ----------- Setup ----------------

        # FIXME Create a dummy bgp session.
        # Workaroud to overcome the bgp socket issue.
        # When there are only vrf bgp sessions and
        # net.ipv4.tcp_l3mdev_accept=1, bgpd(7.0) does
        # not create bgp socket for sessions.
        duthost.shell("vtysh -c 'config terminal' -c 'router bgp 65444'")

        # vrf1 args, vrf2 use the same as vrf1
        peer_range     = IPNetwork(cfg_facts['BGP_PEER_RANGE']['BGPSLBPassive']['ip_range'][0])
        ptf_speaker_ip = IPNetwork("{}/{}".format(peer_range[1], peer_range.prefixlen))
        vlan_port      = get_vlan_members('Vlan1000', cfg_facts)[0]
        vlan_peer_port = cfg_facts['config_port_indices'][vlan_port]
        ptf_direct_ip  = g_vars['vlan_peer_ips'][('Vrf1', vlan_peer_port)]['ipv4'][0]

        # add route to ptf_speaker_ip
        for (vrf, vlan_peer_port), ips in g_vars['vlan_peer_ips'].iteritems():
            nh = ips['ipv4'][0].ip
            duthost.shell("vtysh -c 'configure terminal' -c 'ip route {} {} vrf {}'".format(peer_range, nh , vrf))
            duthost.shell("ping {} -I {} -c 3 -f -W2".format(nh, vrf))

        # add speaker ips to ptf macvlan ports
        for vrf, vlan_peer_port in g_vars['vlan_peer_ips']:
            ns = g_vars['vlan_peer_vrf2ns_map'][vrf]
            ptfhost.shell("ip netns exec {} ip address add {} dev e{}mv1".format(ns, ptf_speaker_ip, vlan_peer_port))

        res = duthost.shell("sonic-cfggen -m -d -y /etc/sonic/constants.yml -v \"constants.deployment_id_asn_map[DEVICE_METADATA['localhost']['deployment_id']]\"")
        bgp_speaker_asn = res['stdout']

        exabgp_dir = "/root/exabgp"

        ptfhost.file(path=exabgp_dir, state="directory")

        extra_vars = {
            'exabgp_dir': exabgp_dir,
            'announce_prefix': self.announce_prefix,
            'peer_asn'  : cfg_facts['DEVICE_METADATA']['localhost']['bgp_asn'],
            'my_asn'    : bgp_speaker_asn,
            'speaker_ip': ptf_speaker_ip.ip,
            'direct_ip' : ptf_direct_ip.ip,
            'namespace' : g_vars['vlan_peer_vrf2ns_map'].values(),
            'lo_addr'   : get_intf_ips('Loopback0', cfg_facts)['ipv4'][0].ip
        }
        ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
        ptfhost.template(src="vrf/bgp_speaker/config.j2", dest="%s/%s" % (exabgp_dir, 'config.ini'))

        # deploy start script
        ptfhost.template(src="vrf/bgp_speaker/start.j2", dest="%s/%s" % (exabgp_dir, 'start.sh'), mode="u+rwx")

        # kill exabgp if any
        ptfhost.shell("pkill exabgp || true")

        # start exabgp instance
        ptfhost.shell("bash %s/start.sh" % exabgp_dir)

        # ensure exabgp started
        ptfhost.shell("pgrep exabgp")

        # make sure routes announced to bgp neighbors
        time.sleep(10)

        # -------- Testing ----------

        yield

        # -------- Teardown ---------

        # del route to ptf_speaker_ip on dut
        for (vrf, vlan_peer_port), ips in g_vars['vlan_peer_ips'].iteritems():
            duthost.shell("vtysh -c 'configure terminal' -c 'no ip route {} {} vrf {}'".format(peer_range, ips['ipv4'][0], vrf))

        # kill exabgp
        ptfhost.shell("pkill exabgp || true")

        # del speaker ips from ptf ports
        for vrf, vlan_peer_port in g_vars['vlan_peer_ips']:
            ns = g_vars['vlan_peer_vrf2ns_map'][vrf]
            ptfhost.shell("ip netns exec {} ip address del {} dev e{}mv1".format(ns, ptf_speaker_ip, vlan_peer_port))

        # FIXME workround to overcome the bgp socket issue
        #duthost.shell("vtysh -c 'config terminal' -c 'no router bgp 65444'")

    @pytest.mark.usefixtures('setup_bgp_with_loopback')
    def test_bgp_with_loopback(self, duthost, cfg_facts):
        peer_range = IPNetwork(cfg_facts['BGP_PEER_RANGE']['BGPSLBPassive']['ip_range'][0])
        ptf_speaker_ip = IPNetwork("{}/{}".format(peer_range[1], peer_range.prefixlen))

        for vrf in cfg_facts['VRF']:
            bgp_info = json.loads(duthost.shell("vtysh -c 'show bgp vrf {} summary json'".format(vrf))['stdout'])
            route_info = duthost.shell("vtysh -c 'show bgp vrf {} ipv4 {}'".format(vrf, self.announce_prefix))
            # Verify bgp sessions are established
            assert bgp_info['ipv4Unicast']['peers'][str(ptf_speaker_ip.ip)]['state'] == 'Established', \
                   "Bgp peer {} should be Established!".format(ptf_speaker_ip.ip)
            # Verify accepted prefixes of the dynamic neighbors are correct
            assert bgp_info['ipv4Unicast']['peers'][str(ptf_speaker_ip.ip)]['prefixReceivedCount'] == 1


class TestVrfWarmReboot():
    @pytest.fixture(scope="class", autouse=True)
    def setup_vrf_warm_reboot(self, ptfhost, tbinfo):
        # -------- Setup ----------
        gen_vrf_fib_file('Vrf1', tbinfo, ptfhost,
                         dst_intfs=['PortChannel0001', 'PortChannel0002'],
                         render_file='/tmp/vrf1_fib.txt',
                         limited_podset_number=50,
                         limited_tor_number=16)

        # -------- Testing ----------
        yield

        # -------- Teardown ----------
        #FIXME Might need cold reboot if test failed?
        pass

    def test_vrf_swss_warm_reboot(self, duthost, cfg_facts, partial_ptf_runner):
        # enable swss warm-reboot
        duthost.shell("config warm_restart enable swss")

        exc_que = Queue.Queue()
        params = {
            'ptf_runner': partial_ptf_runner,
            'exc_queue': exc_que,  # use for store exception infos
            'testname': 'vrf_test.FibTest',
            'fib_info': "/tmp/vrf1_fib.txt",
            'src_ports': g_vars['vrf_member_port_indices']['Vrf1']
        }

        traffic_in_bg = threading.Thread(target=ex_ptf_runner, kwargs=params)

        # send background traffic
        traffic_in_bg.start()
        logger.info("Start transmiting packets...")

        # start swss warm-reboot
        duthost.shell("service swss restart")
        logger.info("Warm reboot swss...")

        # wait until background traffic finished
        traffic_in_bg.join()
        logger.info("Transmit done.")

        passed = True
        if exc_que.qsize() != 0:
            passed = False
            exc_type, exc_obj, exc_trace = exc_que.get()
        assert passed == True, "Traffic Test Failed \n {}".format(str(exc_obj))

        # wait until components finish reconcile
        tbd_comp_list = finalize_warmboot(duthost)
        assert len(tbd_comp_list) == 0, \
               "Some components didn't finish reconcile: {} ...".format(tbd_comp_list)

        # basic check after warm reboot
        assert wait_until(300, 20, duthost.critical_services_fully_started), \
               "All critical services should fully started!{}".format(duthost.critical_services)

        up_ports = [p for p, v in cfg_facts['PORT'].items() if v.get('admin_status', None) == 'up' ]
        assert wait_until(300, 20, check_interface_status, duthost, up_ports), \
               "All interfaces should be up!"

    def test_vrf_system_warm_reboot(self, duthost, cfg_facts, partial_ptf_runner):
        exc_que = Queue.Queue()
        params = {
            'ptf_runner': partial_ptf_runner,
            'exc_queue': exc_que,  # use for store exception infos
            'testname': 'vrf_test.FibTest',
            'fib_info': "/tmp/vrf1_fib.txt",
            'src_ports': g_vars['vrf_member_port_indices']['Vrf1']
        }
        traffic_in_bg = threading.Thread(target=ex_ptf_runner, kwargs=params)

        # send background traffic
        traffic_in_bg.start()
        logger.info("Start transmiting packets...")

        # start system warm-reboot
        logger.info("Warm reboot ...")
        reboot(duthost, localhost, reboot_type="warm")

        # wait until background traffic finished
        traffic_in_bg.join()
        logger.info("Transmit done.")

        passed = True
        if exc_que.qsize() != 0:
            passed = False
            exc_type, exc_obj, exc_trace = exc_que.get()
        assert passed == True, "Test Failed: \n Exception infos => {}".format(str(exc_obj))

        # wait until components finish reconcile
        comp_list = ['orchagent', 'neighsyncd', 'bgp']
        tbd_comp_list = finalize_warmboot(duthost, comp_list=comp_list)
        assert len(tbd_comp_list) == 0, "Some components didn't finish reconcile: {} ...".format(tbd_comp_list)

        # basic check after warm reboot
        assert wait_until(300, 20, duthost.critical_services_fully_started), "Not all critical services are fully started"

        up_ports = [p for p, v in cfg_facts['PORT'].items() if v.get('admin_status', None) == 'up' ]
        assert wait_until(300, 20, check_interface_status, duthost, up_ports), "Not all interfaces are up"


class TestVrfCapacity():
    VRF_CAPACITY    = 1000

    # limit the number of vrfs to be covered to limit script execution time
    TEST_COUNT      = 100

    src_base_vid  = 2000
    dst_base_vid  = 3000

    ipnet1          = IPNetwork("192.1.1.0/31")
    ipnet2          = IPNetwork("192.2.1.0/31")

    vrf_name_tpl    = "Vrf_cap_{}"

    sub_if_name_tpl = "e{}.v{}"  # should not include 'eth'

    route_prefix    = "200.200.200.0/24"

    cleanup_method  = 'reboot'  # reboot or remove

    @pytest.fixture(scope="class")
    def vrf_count(self, request):
        vrf_capacity = request.config.option.vrf_capacity or self.VRF_CAPACITY  # get cmd line option value, use default if none

        return vrf_capacity - 3  # minus global(default) VRF and Vrf1/Vrf2

    @pytest.fixture(scope="class")
    def random_vrf_list(self, vrf_count, request):
        test_count = request.config.option.vrf_test_count or self.TEST_COUNT  # get cmd line option value, use default if none

        return sorted(random.sample(xrange(1, vrf_count+1), min(test_count, vrf_count)))

    @pytest.fixture(scope="class", autouse=True)
    def setup_vrf_capacity(self, duthost, ptfhost, localhost, cfg_facts, vrf_count, random_vrf_list, request):
        """
        Setup $VRF_CAPACITY(minus global VRF and Vrf1/Vrf2) vrfs,
        2 vlan interfaces per vrf,
        1 ip address per vlan interface,
        1 static route per vrf, it set $route_prefix(200.200.200.0/24) next_hop point to vlan_2's neigh ip,
        use the 2rd member port of Vlan1000/2000 as trunk port.

        Example:
        VRF         RIFs        Vlan_Member_Port    IP              Neighbor_IP(on PTF)     Static_Route
        Vrf_Cap_1   Vlan2001    Ethernet2           192.1.1.0/31    192.1.1.1/31            ip route 200.200.200.0/24 192.2.1.1 vrf Vrf_Cap_1
                    Vlan3001    Ethernet14          192.2.1.0/31    192.2.1.1/31
        Vrf_Cap_2   Vlan2002    Ethernet2           192.1.1.2/31    192.1.1.3/31            ip route 200.200.200.0/24 192.2.1.3 vrf Vrf_Cap_2
                    Vlan3002    Ethernet14          192.2.1.2/31    192.2.1.3/31
        ...

        """

        # -------- Setup ----------

        duthost.shell("logger -p INFO -- '-------- {} start!!! ---------'".format(request.cls.__name__))

        # increase ipv4 neigh threshold to 2k
        duthost.shell("sysctl -w net.ipv4.neigh.default.gc_thresh3=2048")

        # use 2rd member port of Vlan1000/Vlan2000 as trunk port
        dut_port1 = get_vlan_members('Vlan1000', cfg_facts)[1]
        dut_port2 = get_vlan_members('Vlan2000', cfg_facts)[1]
        ptf_port1 = g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000'][1]
        ptf_port2 = g_vars['vrf_intf_member_port_indices']['Vrf2']['Vlan2000'][1]

        # base ip range to be assigned to vlan rif
        ip1 = self.ipnet1
        ip2 = self.ipnet2

        # setup $vrf_count vrfs on dut
        dut_extra_vars = {
            'vrf_count':    vrf_count,
            'src_base_vid': self.src_base_vid,
            'dst_base_vid': self.dst_base_vid,
            'vrf_name_tpl': self.vrf_name_tpl,
            'ip1':          ip1,
            'ip2':          ip2,
            'dut_port1':    dut_port1,
            'dut_port2':    dut_port2,
            'route_prefix': self.route_prefix,
            'op_code':      'add'
        }
        duthost.host.options['variable_manager'].extra_vars.update(dut_extra_vars)

        cfg_attrs_map = OrderedDict()
        # In wrost case(1k vrfs, 2k rifs), remove a vlan could take 60~80ms
        # ("VlanMgr::removeHostVlan ip link del Vlan{{vlan_id}} && bridge vlan del vid {{vlan_id}} dev Bridge self" take most of the time)
        # So wait up to 5(s) + 80(ms) * 2(vlans per vrf) * vrf_count when remove vlans
        cfg_attrs_map['vlan']           = {'add_sleep_time': 2, 'remove_sleep_time': 5 + 0.08 * 2 * vrf_count}
        # In wrost case(1k vrfs, 2k rifs), remove a vlan member from vlan could take 160~220ms
        # ("vlanmgrd::removeHostVlanMember /sbin/bridge vlan show dev <devname>" take most of the time)
        # So wait up to 5(s) + 220(ms) * 2(2 vlan members per vrf) * vrf_count
        cfg_attrs_map['vlan_member']    = {'add_sleep_time': 2, 'remove_sleep_time': 5 + 0.2 * 2 * vrf_count}
        # In wrost case(1k vrfs, 2k rifs), remove a vrf could take 6~10ms
        # So wait up to 5(s) + 10(ms) * vrf_count when remove vrfs
        cfg_attrs_map['vrf']            = {'add_sleep_time': 2, 'remove_sleep_time': 5 + 0.01 * vrf_count}
        # In wrost case(1k vrfs, 2k rifs), remove a rif could take 30~40ms
        # ("IntfMgr::getIntfIpCount ip address show <alias> master <vrfName>" take most of the time)
        # So wait up to 5(s) + 40(ms) * 2(rifs per vrf) * vrf_count when remove rifs
        cfg_attrs_map['vrf_intf']       = {'add_sleep_time': 2, 'remove_sleep_time': 5 + 0.04 * 2 * vrf_count}
        cfg_attrs_map['vlan_intf']      = {'add_sleep_time': 2, 'remove_sleep_time': 5}

        for cfg_name, attrs in cfg_attrs_map.iteritems():
            src_template = 'vrf/vrf_capacity_{}_cfg.j2'.format(cfg_name)
            render_file = '/tmp/vrf_capacity_{}_cfg.json'.format(cfg_name)
            duthost.template(src=src_template, dest=render_file)
            duthost.shell("sonic-cfggen -j {} --write-to-db".format(render_file))

            time.sleep(attrs['add_sleep_time'])

        # setup static routes
        duthost.template(src='vrf/vrf_capacity_route_cfg.j2', dest='/tmp/vrf_capacity_route_cfg.sh', mode="0755")
        duthost.shell("/tmp/vrf_capacity_route_cfg.sh")

        # setup peer ip addresses on ptf
        ptf_extra_vars = {
            'vrf_count':        vrf_count,
            'src_base_vid':     self.src_base_vid,
            'dst_base_vid':     self.dst_base_vid,
            'sub_if_name_tpl':  self.sub_if_name_tpl,
            'ip1':              ip1,
            'ip2':              ip2,
            'ptf_port1':        ptf_port1,
            'ptf_port2':        ptf_port2,
            'random_vrf_list':  random_vrf_list
        }
        ptfhost.host.options['variable_manager'].extra_vars.update(ptf_extra_vars)
        ptfhost.template(src='vrf/vrf_capacity_ptf_cfg.j2', dest='/tmp/vrf_capacity_ptf_cfg.sh', mode="0755")
        ptfhost.shell('/tmp/vrf_capacity_ptf_cfg.sh')

        # ping to trigger neigh resolving, also acitvate the static routes
        dut_extra_vars.update({
            'random_vrf_list':  random_vrf_list,
            'count':            1,
            'timeout':          1
        })
        duthost.host.options['variable_manager'].extra_vars.update(dut_extra_vars)
        duthost.template(src='vrf/vrf_capacity_ping.j2', dest='/tmp/vrf_capacity_neigh_learning.sh', mode="0755")
        duthost.shell('/tmp/vrf_capacity_neigh_learning.sh', module_ignore_errors=True)

        # wait for route/neigh entries apply to asic
        time.sleep(5)

        # -------- Testing ----------
        yield

        # -------- Teardown ----------

        # remove cfg on ptf
        ptfhost.shell("ip address flush dev eth{}".format(ptf_port1))
        ptfhost.shell("ip address flush dev eth{}".format(ptf_port2))
        ptfhost.template(src='vrf/vrf_capacity_del_ptf_cfg.j2', dest='/tmp/vrf_capacity_del_ptf_cfg.sh', mode="0755")
        ptfhost.shell('/tmp/vrf_capacity_del_ptf_cfg.sh')

        duthost.shell("config interface startup {}".format(dut_port1))
        duthost.shell("config interface startup {}".format(dut_port2))

        # remove cfg on dut
        if self.cleanup_method == 'reboot':
            reboot(duthost, localhost)

        else:
            duthost.shell("config interface shutdown {}".format(dut_port1))
            duthost.shell("config interface shutdown {}".format(dut_port2))

            # flush macs, arps and neighbors
            duthost.shell("sonic-clear arp")
            duthost.shell("sonic-clear fdb all")

            # remove static routes
            dut_extra_vars['op_code'] = 'del'
            duthost.host.options['variable_manager'].extra_vars.update(dut_extra_vars)
            duthost.template(src='vrf/vrf_capacity_route_cfg.j2', dest='/tmp/vrf_capacity_route_cfg.sh', mode="0755")
            duthost.shell('/tmp/vrf_capacity_route_cfg.sh')

            # remove ip addr, intf, vrf, vlan member, vlan cfgs
            for cfg_name, attrs in reversed(cfg_attrs_map.items()):
                src_template = 'vrf/vrf_capacity_{}_cfg.j2'.format(cfg_name)
                render_file = '/tmp/vrf_capacity_del_{}_cfg.json'.format(cfg_name)
                duthost.template(src=src_template, dest=render_file)
                duthost.shell("sonic-cfggen -j {} --write-to-db".format(render_file))

                time.sleep(attrs['remove_sleep_time'])

        duthost.shell("logger -p INFO -- '-------- {} end!!! ---------'".format(request.cls.__name__))

    def test_ping(self, duthost, random_vrf_list):
        dut_extra_vars = {
            'vrf_name_tpl':     self.vrf_name_tpl,
            'random_vrf_list':  random_vrf_list,
            'ip1':              self.ipnet1,
            'ip2':              self.ipnet2
        }
        duthost.host.options['variable_manager'].extra_vars.update(dut_extra_vars)
        duthost.template(src='vrf/vrf_capacity_ping.j2', dest='/tmp/vrf_capacity_ping.sh', mode="0755")

        duthost.shell('/tmp/vrf_capacity_ping.sh')

    def test_ip_fwd(self, partial_ptf_runner, random_vrf_list):
        ptf_port1 = g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000'][1]
        ptf_port2 = g_vars['vrf_intf_member_port_indices']['Vrf2']['Vlan2000'][1]
        dst_ips = [str(IPNetwork(self.route_prefix)[1])]

        partial_ptf_runner(
            testname="vrf_test.CapTest",
            src_ports=[ptf_port1],
            dst_ports=[[ptf_port2]],
            dst_ips=dst_ips,
            random_vrf_list=random_vrf_list,
            src_base_vid=self.src_base_vid,
            dst_base_vid=self.dst_base_vid
        )


class TestVrfUnbindIntf():
    c_vars = {
        'rebind_intf': True  # rebind interface during teardown stage
    }

    @pytest.fixture(scope="class", autouse=True)
    def setup_vrf_unbindintf(self, duthost, ptfhost, tbinfo, cfg_facts):
        # -------- Setup ----------
        duthost.shell("config interface vrf unbind PortChannel0001")

        # wait for neigh/route flush
        time.sleep(5)

        # -------- Testing ----------
        yield

        # -------- Teardown ----------
        if self.c_vars['rebind_intf']:
            self.rebind_intf(duthost)
            wait_until(120, 10, check_bgp_facts, duthost, cfg_facts)

    def rebind_intf(self, duthost):
        duthost.shell("config interface vrf bind PortChannel0001 Vrf1")
        for ver, ips in g_vars['vrf_intfs']['Vrf1']['PortChannel0001'].iteritems():
            for ip in ips:
                duthost.shell("config interface ip add PortChannel0001 {}".format(ip))

    @pytest.fixture(scope='class')
    def setup_vrf_rebind_intf(self, duthost, cfg_facts):
        self.rebind_intf(duthost)
        self.c_vars['rebind_intf'] = False  # Mark to skip rebind interface during teardown

        # check bgp session state after rebind
        assert wait_until(120, 10, check_bgp_facts, duthost, cfg_facts), \
               "Bgp sessions should be re-estabalished after Portchannel0001 rebind to Vrf"

    def test_pc1_ip_addr_flushed(self, duthost):
        ip_addr_show = duthost.shell("ip addr show PortChannel0001")['stdout']
        for ver, ips in g_vars['vrf_intfs']['Vrf1']['PortChannel0001'].iteritems():
            for ip in ips:
                assert str(ip) not in ip_addr_show, "The ip addresses on PortChannel0001 should be flushed after unbind from vrf."

    def test_pc1_neigh_flushed(self, duthost):
        # verify ipv4
        show_arp = duthost.shell("show arp")['stdout']
        assert 'PortChannel0001' not in show_arp, "The arps on PortChannel0001 should be flushed after unbind from vrf."

        # FIXME
        # ipv6 neighbors do not seem to be flushed by kernel whenever remove ipv6 addresses
        # from interface. So comment out the test of ipv6 neigh flushed.

        # # verify ipv6
        # show_ndp = duthost.shell("show ndp")['stdout']
        # assert 'PortChannel0001' not in show_ndp, "The neighbors on PortChannel0001 should be flushed after unbind from vrf."

    def test_pc1_neigh_flushed_by_traffic(self, partial_ptf_runner):
        pc1_neigh_ips = []
        for ver, ips in g_vars['vrf_intfs']['Vrf1']['PortChannel0001'].iteritems():
            for ip in ips:
                pc1_neigh_ips.append(str(ip.ip+1))

        partial_ptf_runner(
            testname="vrf_test.FwdTest",
            pkt_action='drop',
            dst_ips=pc1_neigh_ips,
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000'],
            dst_ports=[g_vars['vrf_intf_member_port_indices']['Vrf1']['PortChannel0001']],
            ipv4=True,
            ipv6=False
        )

    def test_pc1_routes_flushed(self, ptfhost, tbinfo, partial_ptf_runner):
        gen_vrf_fib_file('Vrf1', tbinfo, ptfhost,
                         dst_intfs=['PortChannel0001'],
                         render_file="/tmp/unbindvrf_fib_1.txt")

        # Send packet from downlink to uplink, port channel1 should no longer receive any packets
        partial_ptf_runner(
            testname="vrf_test.FibTest",
            pkt_action='drop',
            fib_info="/tmp/unbindvrf_fib_1.txt",
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )

    def test_pc2_neigh(self, partial_ptf_runner):
        pc2_neigh_ips = []
        for ver, ips in g_vars['vrf_intfs']['Vrf1']['PortChannel0002'].iteritems():
            for ip in ips:
                pc2_neigh_ips.append(str(ip.ip+1))

        partial_ptf_runner(
            testname="vrf_test.FwdTest",
            pkt_action='fwd',
            dst_ips=pc2_neigh_ips,
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000'],
            dst_ports=[g_vars['vrf_intf_member_port_indices']['Vrf1']['PortChannel0002']]
        )

    def test_pc2_fib(self, ptfhost, tbinfo, partial_ptf_runner):
        gen_vrf_fib_file('Vrf1', tbinfo, ptfhost,
                         dst_intfs=['PortChannel0002'],
                         render_file="/tmp/unbindvrf_fib_2.txt")

        partial_ptf_runner(
            testname="vrf_test.FibTest",
            fib_info="/tmp/unbindvrf_fib_2.txt",
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )


    @pytest.mark.usefixtures('setup_vrf_rebind_intf')
    def test_pc1_neigh_after_rebind(self, partial_ptf_runner):
        pc1_neigh_ips = []
        for ver, ips in g_vars['vrf_intfs']['Vrf1']['PortChannel0001'].iteritems():
            for ip in ips:
                pc1_neigh_ips.append(str(ip.ip+1))

        partial_ptf_runner(
            testname="vrf_test.FwdTest",
            pkt_action='fwd',
            dst_ips=pc1_neigh_ips,
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000'],
            dst_ports=[g_vars['vrf_intf_member_port_indices']['Vrf1']['PortChannel0001']],
            ipv4=True,
            ipv6=False
        )

    @pytest.mark.usefixtures('setup_vrf_rebind_intf')
    def test_vrf1_fib_after_rebind(self, ptfhost, tbinfo, partial_ptf_runner):
        gen_vrf_fib_file('Vrf1', tbinfo, ptfhost,
                         dst_intfs=['PortChannel0001', 'PortChannel0002'],
                         render_file='/tmp/rebindvrf_vrf1_fib.txt')

        partial_ptf_runner(
            testname="vrf_test.FibTest",
            fib_info="/tmp/rebindvrf_vrf1_fib.txt",
            src_ports=g_vars['vrf_member_port_indices']['Vrf1']
        )

class TestVrfDeletion():
    c_vars = {
        'restore_vrf': True
    }

    def restore_vrf(self, duthost):
        duthost.shell("config vrf add Vrf1")
        for intf, ip_facts in g_vars['vrf_intfs']['Vrf1'].iteritems():
            duthost.shell("config interface vrf bind %s Vrf1" % intf)
            for ver, ips in ip_facts.iteritems():
                for ip in ips:
                    duthost.shell("config interface ip add {} {}".format(intf, ip))

    @pytest.fixture(scope="class", autouse=True)
    def setup_vrf_deletion(self, duthost, ptfhost, tbinfo, cfg_facts):
        # -------- Setup ----------
        gen_vrf_fib_file('Vrf1', tbinfo, ptfhost,
                    dst_intfs=['PortChannel0001', 'PortChannel0002'],
                    render_file="/tmp/vrf1_fib.txt")

        gen_vrf_fib_file('Vrf2', tbinfo, ptfhost,
                    dst_intfs=['PortChannel0003', 'PortChannel0004'],
                    render_file="/tmp/vrf2_fib.txt")

        gen_vrf_neigh_file('Vrf1', ptfhost, render_file="/tmp/vrf1_neigh.txt")

        gen_vrf_neigh_file('Vrf2', ptfhost, render_file="/tmp/vrf2_neigh.txt")

        duthost.shell("config vrf del Vrf1")

        # -------- Testing ----------
        yield

        # -------- Teardown ----------
        if self.c_vars['restore_vrf']:
            self.restore_vrf(duthost)
            wait_until(120, 10, check_bgp_facts, duthost, cfg_facts)

    @pytest.fixture(scope='class')
    def setup_vrf_restore(self, duthost, cfg_facts):
        self.restore_vrf(duthost)
        self.c_vars['restore_vrf'] = False  # Mark to skip restore vrf during teardown

        # check bgp session state after restore
        assert wait_until(120, 10, check_bgp_facts, duthost, cfg_facts), \
               "Bgp sessions should be re-estabalished after restore Vrf1"

    def test_pc1_ip_addr_flushed(self, duthost):
        show_interfaces = duthost.shell("show ip interfaces")['stdout']
        assert 'PortChannel0001' not in show_interfaces, "The ip addr of PortChannel0001 should be flushed after Vrf1 is deleted."

    def test_pc2_ip_addr_flushed(self, duthost):
        show_interfaces = duthost.shell("show ip interfaces")['stdout']
        assert 'PortChannel0002' not in show_interfaces, "The ip addr of PortChannel0002 should be flushed after Vrf1 is deleted."

    def test_vlan1000_ip_addr_flushed(self, duthost):
        show_interfaces = duthost.shell("show ip interfaces")['stdout']
        assert 'Vlan1000' not in show_interfaces, "The ip addr of Vlan1000 should be flushed after Vrf1 is deleted."

    def test_loopback0_ip_addr_flushed(self, duthost):
        show_interfaces = duthost.shell("show ip interfaces")['stdout']
        assert 'Loopback0' not in show_interfaces, "The ip addr of Loopback0 should be flushed after Vrf1 is deleted."

    def test_vrf1_neighs_flushed(self, duthost):
        ip_neigh_show = duthost.shell("ip neigh show vrf Vrf1", module_ignore_errors=True)['stdout']
        assert '' == ip_neigh_show, "The neighbors on Vrf1 should be flushed after Vrf1 is deleted."

    def test_vrf1_neighs_flushed_by_traffic(self, partial_ptf_runner):
        partial_ptf_runner(
            testname="vrf_test.FwdTest",
            pkt_action='drop',
            fwd_info="/tmp/vrf1_neigh.txt",
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )

    def test_vrf1_routes_flushed(self, partial_ptf_runner):
        partial_ptf_runner(
            testname="vrf_test.FibTest",
            pkt_action='drop',
            fib_info="/tmp/vrf1_fib.txt",
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )

    def test_vrf2_neigh(self, partial_ptf_runner):
        partial_ptf_runner(
            testname="vrf_test.FwdTest",
            fwd_info="/tmp/vrf2_neigh.txt",
            src_ports= g_vars['vrf_intf_member_port_indices']['Vrf2']['Vlan2000']
        )

    def test_vrf2_fib(self, partial_ptf_runner):
        partial_ptf_runner(
            testname="vrf_test.FibTest",
            fib_info="/tmp/vrf2_fib.txt",
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf2']['Vlan2000']
        )

    @pytest.mark.usefixtures('setup_vrf_restore')
    def test_vrf1_neigh_after_restore(self, partial_ptf_runner):
        partial_ptf_runner(
            testname="vrf_test.FwdTest",
            fwd_info="/tmp/vrf1_neigh.txt",
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )

    @pytest.mark.usefixtures('setup_vrf_restore')
    def test_vrf1_fib_after_resotre(self, partial_ptf_runner):
        partial_ptf_runner(
            testname="vrf_test.FibTest",
            fib_info="/tmp/vrf1_fib.txt",
            src_ports=g_vars['vrf_intf_member_port_indices']['Vrf1']['Vlan1000']
        )
