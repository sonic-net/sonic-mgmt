import os
import time
import yaml
import pytest
import sys
from spytest import st
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(script_dir, '../common/'))

import tortuga_common_utils as common_obj

CONFIGS_FILE = 'bgp_basic_cfg.yaml'

####################
#                  #
#    D1 = spine0      #
#    D2 = spine1      #
#    D3 = leaf0      #
#    D4 = leaf1      #
#                  #
####################

def config_frr(dut, commands):

    if not isinstance(commands, list):
        commands = [commands]

    st.log("Configuring on frr: {}".format(commands))
    with open("/tmp/spytest_frr.conf", "w") as fd:
        fd.write("\n".join(commands))
    st.upload_file_to_dut(dut, "/tmp/spytest_frr.conf", "/tmp/spytest_frr.conf")

    st.config(dut, "docker cp /tmp/spytest_frr.conf bgp:/")
    st.config(dut, "docker exec bgp bash -c 'vtysh -f /spytest_frr.conf'")

######################################################################
#          eBGP             eBGP           iBGP                      #
#  spine0 ---default--- leaf0 ---Vrf01--- spine1 ---Vrf02--- leaf1             #
#                                                                    #
######################################################################

@pytest.fixture(scope="module", autouse=True)
def setup_teardown_bgp_vrf():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    update_path = common_obj.modify_config_file(dir_path + '/' + CONFIGS_FILE, vars)

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_frr(node, config['bgp']['config'])
            common_obj.config_static(node, 'sonic', True, update_path)

    count = 5    
    st.show(nodes['spine0'], 'sudo ping -c {} {} -q'.format(count, '10.1.1.2'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['leaf0'], 'sudo ping -I Vrf01 -c {} {} -q'.format(count, '20.1.1.2'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['spine1'], 'sudo ping -I Vrf02 -c {} {} -q'.format(count, '30.1.1.2'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['spine0'], 'sudo ping -c {} {} -q'.format(count, '10::2'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['leaf0'], 'sudo ping -I Vrf01 -c {} {} -q'.format(count, '20::2'), skip_tmpl=True, skip_error_check=True)

    yield 'setup_teardown_bgp_vrf'

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_frr(node, config['bgp']['deconfig'])
            common_obj.config_static(node, 'sonic', False, update_path)

def test_bgp_vrf_interface_flap_check():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    cmds = ['sudo config interface ip rem {} 20.1.1.1/24'.format(vars.D3D2P1),
           'sudo config interface shutdown {}'.format(vars.D3D2P1)]
    for cmd in cmds:
        cmd_output = st.config(nodes['leaf0'], cmd)

    time.sleep(1)

    # check route table for Vrf01 instance is not exists
    cmd = 'show ip route vrf Vrf01'
    cmd_output = st.config(nodes['leaf0'], cmd)

    parsed_output = st.parse_show(nodes['leaf0'], cmd, cmd_output, 'show_ip_route.tmpl')
    for path in parsed_output:
        if path['type'] == 'B' and path['ip_address'] == "192.168.1.3/32":
            st.report_fail("test_case_failed", nodes['leaf0'])


    cmds = ['sudo config interface startup {}'.format(vars.D3D2P1),
            'sudo config interface vrf bind {} Vrf01'.format(vars.D3D2P1),
            'sudo config interface ip add {} 20.1.1.1/24'.format(vars.D3D2P1)]

    for cmd in cmds:
        cmd_output = st.config(nodes['leaf0'], cmd)

    time.sleep(1)
    st.show(nodes['leaf0'], 'sudo ping -I Vrf01 -c 5 {} -q'.format('20.1.1.2'), skip_tmpl=True, skip_error_check=True)

    prefix_present = False
    cmd = 'show ip route vrf Vrf01'
    cmd_output = st.config(nodes['leaf0'], cmd)
    parsed_output = st.parse_show(nodes['leaf0'], cmd, cmd_output, 'show_ip_route.tmpl')
    for path in parsed_output:
        if path['type'] == 'B' and path['selected'] == '>' and path['ip_address'] == "192.168.1.3/32" and path['nexthop'] == "20.1.1.2":
            prefix_present = True

    if prefix_present != True:
        st.report_fail("test_case_failed", nodes['leaf0'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])

def test_bgp_vrf_delete_vrf_instance():
    """
    Verify delete and add of vrf instance of same name has no impact
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    cmd = 'no router bgp 2002 vrf Vrf01'
    config_frr(nodes['leaf0'], cmd)
 
    cmd = 'sudo config vrf del Vrf01'
    st.config(nodes['leaf0'], cmd)

    time.sleep(10)

    cmd = 'show vrf'
    cmd_output = st.config(nodes['leaf0'], cmd)
    if "Vrf01" in  str(cmd_output.encode('ascii','ignore')):
        st.report_fail("test_case_failed", nodes['leaf0'])

    cmds = ['sudo config vrf add Vrf01',
            'sudo config interface vrf bind {} Vrf01'.format(vars.D3D2P1),
            'sudo config interface ip add {} 20.1.1.1/24'.format(vars.D3D2P1)]
    for cmd in cmds:        
        st.config(nodes['leaf0'], cmd)

    time.sleep(10)
    st.show(nodes['leaf0'], 'sudo ping -I Vrf01 -c 5 {} -q'.format('20.1.1.2'), skip_tmpl=True, skip_error_check=True)

    cmds = ['router bgp 2002 vrf Vrf01',
        'no bgp ebgp-requires-policy',
        'no bgp network import-check',
        'neighbor 20.1.1.2 remote-as 1003',
        'neighbor 20.1.1.2 update-source 20.1.1.1',
        'neighbor 20.1.1.2 timers 3 10',
        'neighbor 20::2 remote-as 1003',
        'neighbor 20::2 update-source 20::1',
        'neighbor 20::2 timers 3 10',
        'address-family ipv4 unicast',
        'redistribute connected',
        'exit-address-family',
        'address-family ipv6 unicast',
        'neighbor 20::2 activate',
        'redistribute connected',
        'exit-address-family',
        'exit']

    config_frr(nodes['leaf0'], cmds)

    time.sleep(5)

    prefix_present = False
    cmd = 'show ip route vrf Vrf01'
    cmd_output = st.config(nodes['leaf0'], cmd)
    parsed_output = st.parse_show(nodes['leaf0'], cmd, cmd_output, 'show_ip_route.tmpl')
    for path in parsed_output:
        if path['type'] == 'B' and path['selected'] == '>' and path['ip_address'] == "192.168.1.3/32" and path['nexthop'] == "20.1.1.2":
            prefix_present = True

    if prefix_present != True:
        st.report_fail("test_case_failed", nodes['leaf0'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])

def test_bgp_vrf_verify_route_map_change_in_vrf():
    """
    Verify that Changing route-map configurations(match/set clauses) on
    the fly it takes immediate effect.
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    # Add route-map to prepend 9009 as for all incoming routes from 20.1.1.2 peer
    cmds = ['ip prefix-list allow_list permit any',
        'route-map ALLOW_PREFIX permit 10',
        'match ip address prefix-list allow_list',
        'set as-path prepend 9009',
        'router bgp 2002 vrf Vrf01',
        'address-family ipv4 unicast',
        'neighbor 20.1.1.2 route-map ALLOW_PREFIX in']

    config_frr(nodes['leaf0'], cmds)

    time.sleep(5)

    #validate incoming route is prepend with 9009 as value
    cmd = 'show bgp vrf Vrf01 ipv4 unicast neighbors 20.1.1.2 routes'
    cmd_output = st.show(nodes['leaf0'], "vtysh -c '{}'".format(cmd))
    if "9009 1003" not in str(cmd_output):
        st.report_fail("test_case_failed", nodes['leaf0'])

    # configure to prepend AS value to 8008
    cmds = ['route-map ALLOW_PREFIX permit 10',
        'set as-path prepend 8008']

    config_frr(nodes['leaf0'], cmds)

    time.sleep(5)

    #validate incoming route is prepend with 8008 as value
    cmd = 'show bgp vrf Vrf01 ipv4 unicast neighbors 20.1.1.2 routes'
    cmd_output = st.show(nodes['leaf0'], "vtysh -c '{}'".format(cmd))
    if "8008 1003" not in str(cmd_output):
        st.report_fail("test_case_failed", nodes['leaf0'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])

def test_bgp_vrf_verify_dynamic_imported_routes_adv_to_iBGP():
    """
    Verify that dynamically imported routes are further advertised
    to iBGP peers
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    # import Vrf01 vrf routes to Vrf02 of iBGP
    cmds = ['router bgp 1004 vrf Vrf02',
        'address-family ipv4 unicast',
        'import vrf Vrf01',
        'exit-address-family',
        'exit']

    config_frr(nodes['spine1'], cmds)

    time.sleep(2)

    prefix_present = False
    cmd = 'show ip route vrf Vrf02'
    cmd_output = st.config(nodes['leaf1'], cmd)
    parsed_output = st.parse_show(nodes['leaf1'], cmd, cmd_output, 'show_ip_route.tmpl')
    for path in parsed_output:
        if path['type'] == 'B' and path['selected'] == '>' and path['ip_address'] == "20.1.1.0/24" and path['nexthop'] == "30.1.1.1":
            prefix_present = True

    if prefix_present != True:
        st.report_fail("test_case_failed", nodes['leaf1'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])

def test_bgp_verify_local_routes_as_bestpath_over_eBGP():
    """
    Verify that locally imported routes are selected as best path over eBGP imported
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    # check best path for 192.168.1.3 is set as 20.1.1.2
    prefix_present = False
    cmd = 'show ip route vrf Vrf01'
    cmd_output = st.show(nodes['leaf0'], "vtysh -c '{}'".format(cmd))
    parsed_output = st.parse_show(nodes['leaf0'], cmd, cmd_output, 'show_ip_route.tmpl')
    for path in parsed_output:
        if ((path['type'] == 'B') and (path['selected'] == '>') and (path['ip_address'] == "192.168.1.3/32") and (path['nexthop'] == "20.1.1.2")):
            prefix_present = True

    if prefix_present != True:
        st.report_fail("test_case_failed", nodes['leaf0'])

    # Add a static route of IP learned through eBGP
    cmds = ['sudo config interface vrf bind Loopback4 Vrf01',
            'sudo config interface ip add Loopback4 192.168.1.3/32']

    for cmd in cmds:
        st.config(nodes['leaf0'], cmd)

    time.sleep(10)
    prefix_present = False

    # check BGP route is un-selected local route is seleted.
    cmd = 'show ip route vrf Vrf01'
    cmd_output = st.show(nodes['leaf0'], "vtysh -c '{}'".format(cmd))
    parsed_output = st.parse_show(nodes['leaf0'], cmd, cmd_output, 'show_ip_route.tmpl')
    for path in parsed_output:
        if ((path['type'] == 'C') and (path['selected'] == '>') and (path['ip_address'] == "192.168.1.3/32") and (path['nexthop'] != "20.1.1.2")):
            prefix_present = True

    if prefix_present != True:
        st.report_fail("test_case_failed", nodes['leaf0'])

    # Remove loopback configuration
    cmd = 'sudo config interface vrf unbind Loopback4'
    st.config(nodes['leaf0'], cmd)

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])

def test_bgp_vrf_bestpath_selection_algo_for_import():
    """
    Verify BGP best path selection algorithm works fine when
    routes are imported from default to Vrf01.
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    # check best path for 192.168.1.3 is set as 20.1.1.2
    cmd = 'show ip route vrf Vrf01'
    prefix_present = False
    cmd_output = st.show(nodes['leaf0'], "vtysh -c '{}'".format(cmd))
    parsed_output = st.parse_show(nodes['leaf0'], cmd, cmd_output, 'show_ip_route.tmpl')
    for path in parsed_output:
        if ((path['type'] == 'B') and (path['ip_address'] == "192.168.1.3/32") and (path['nexthop'] == "20.1.1.2")):
            prefix_present = True

    if prefix_present != True:
        st.report_fail("test_case_failed", nodes['leaf0'])

    # configure same loopback address which is learnt from BGP peer.
    cmd = 'sudo config interface ip add Loopback4 192.168.1.3/32'
    st.config(nodes['leaf0'], cmd)

    time.sleep(5)

    # import default vrf to Vrf01, check learned BGP peer is overwirtten with loopback addres
    cmds = ['router bgp 2002 vrf Vrf01',
            'address-family ipv4 unicast',
            'import vrf default']

    config_frr(nodes['leaf0'], cmds)

    prefix_present = False
    cmd = 'show ip route vrf Vrf01'
    cmd_output = st.config(nodes['leaf0'], cmd)
    parsed_output = st.parse_show(nodes['leaf0'], cmd, cmd_output, 'show_ip_route.tmpl')
    for path in parsed_output:
        if path['type'] == 'B' and  path['ip_address'] == "192.168.1.3/32" and path['interface'] == "Loopback4":
            prefix_present = True

    if prefix_present != True:
        st.report_fail("test_case_failed", nodes['leaf0'])

    # verify that all vrf instances fall back
    #     to backup path, if primary link goes down.

    # remove loopback address, check it fallback to BGP route
    cmd = 'sudo config interface ip rem Loopback4 192.168.1.3/32'
    st.config(nodes['leaf0'], cmd)

    time.sleep(5)

    # Route will fall back to backup path
    prefix_present = False
    cmd = 'show ip route vrf Vrf01'
    cmd_output = st.config(nodes['leaf0'], cmd)
    parsed_output = st.parse_show(nodes['leaf0'], cmd, cmd_output, 'show_ip_route.tmpl')
    for path in parsed_output:
        if ((path['type'] == 'B') and (path['ip_address'] == "192.168.1.3/32") and (path['nexthop'] == "20.1.1.2")):
            prefix_present = True

    if prefix_present != True:
        st.report_fail("test_case_failed", nodes['leaf0'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])

def test_bgp_vrf_verify_ecmp_on_vrf():
    """
    Verify ECMP for imported routes from different VRFs, check with max-paths <>
    and choosing the path limit based on that number
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    # import default vrf to Vrf01, check learned BGP peer is overwirtten with loopback addres
    cmds = ['router bgp 2002 vrf Vrf01',
            'address-family ipv4 unicast',
            'import vrf default']

    config_frr(nodes['leaf0'], cmds)

    time.sleep(1)

    cmd = 'show ip route vrf Vrf01 192.168.1.1'
    cmd_output = st.config(nodes['leaf0'], cmd)

    if str(cmd_output.encode('ascii','ignore')).count(', via') == 2:
        st.log("ECMP has two path to reach 192.168.1.1")
    else:
        st.report_fail("test_case_failed", nodes['leaf0'])

    #check both nexthop are present in route table
    if ('* 10.1.1.1, via {}'.format(vars.D3D1P1) not in str(cmd_output.encode('ascii','ignore')) or
        "via eth4" not in str(cmd_output.encode('ascii','ignore'))):
        st.report_fail("test_case_failed", nodes['leaf0'])

    # configure ECMP to select one path
    cmds = ['router bgp 2002 vrf Vrf01',
            'address-family ipv4 unicast',
            'maximum-paths 1']

    config_frr(nodes['leaf0'], cmds)

    time.sleep(1)

    cmd = 'show ip route vrf Vrf01 192.168.1.1'
    cmd_output = st.config(nodes['leaf0'], cmd)

    if str(cmd_output.encode('ascii','ignore')).count(', via') > 1:
        st.report_fail("test_case_failed", nodes['leaf0'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])

def test_bgp_vrf_changing_vrf_locally():
    """
    Verify VRF name is locally significant, delete existing VRF and
    add VRF with different name
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    cmd = 'no router bgp 2002 vrf Vrf01'
    config_frr(nodes['leaf0'], cmd)

    time.sleep(1)

    cmd = 'sudo config vrf del Vrf01'
    st.config(nodes['leaf0'], cmd)

    time.sleep(10)

    cmd = 'show vrf'
    cmd_output = st.config(nodes['leaf0'], cmd)
    if "Vrf01" in  str(cmd_output.encode('ascii','ignore')):
        st.report_fail("test_case_failed", nodes['leaf0'])

    cmds = ['sudo config vrf add Vrf10',
            'sudo config interface vrf bind {} Vrf10'.format(vars.D3D2P1),
            'sudo config interface ip add {} 20.1.1.1/24'.format(vars.D3D2P1)]
    for cmd in cmds:        
        st.config(nodes['leaf0'], cmd)

    # deleting a vrf and adding different vrf for an interface is
    # taking time for an interface to come up. Added a precautionary time check to avoid
    # failure of testcase, can be optimised.
    cmd = 'show ip interface'
    for i in range (0, 12, 1):
        cmd_output = st.config(nodes['leaf0'], cmd)
        if "Vrf10" not in  str(cmd_output.encode('ascii','ignore')):
            time.sleep(10)
        else:
            break

    cmd = 'show ip interface'
    cmd_output = st.config(nodes['leaf0'], cmd)
    if "Vrf10" not in  str(cmd_output.encode('ascii','ignore')):
        st.report_fail("test_case_failed", nodes['leaf0'])

    st.show(nodes['leaf0'], 'sudo ping -I Vrf10 -c 5 {} -q'.format('20.1.1.2'), skip_tmpl=True, skip_error_check=True)

    cmds = [
        'router bgp 2002 vrf Vrf10',
        'no bgp ebgp-requires-policy',
        'no bgp network import-check',
        'neighbor 20.1.1.2 remote-as 1003',
        'neighbor 20.1.1.2 update-source 20.1.1.1',
        'neighbor 20.1.1.2 timers 3 10',
        'neighbor 20::2 remote-as 1003',
        'neighbor 20::2 update-source 20::1',
        'neighbor 20::2 timers 3 10',
        'address-family ipv4 unicast',
        'redistribute connected',
        'exit-address-family',
        'address-family ipv6 unicast',
        'neighbor 20::2 activate',
        'redistribute connected',
        'exit-address-family'
    ]

    config_frr(nodes['leaf0'], cmds)

    time.sleep(10)
    cmd = 'show ip route vrf Vrf10'
    prefix_present = False
    cmd_output = st.config(nodes['leaf0'], cmd)
    parsed_output = st.parse_show(nodes['leaf0'], cmd, cmd_output, 'show_ip_route.tmpl')
    for path in parsed_output:
        if path['type'] == 'B' and path['selected'] == '>' and path['ip_address'] == "192.168.1.3/32":
            prefix_present = True

    if prefix_present != True:
        st.report_fail("test_case_failed", nodes['leaf0'])

    # clean Vrf10 from router, since it is not cleaned as a part of default cleanup
    cmd = 'no router bgp 2002 vrf Vrf10'
    config_frr(nodes['leaf0'], cmd)

    time.sleep(1)

    cmd = 'sudo config vrf del Vrf10'
    st.config(nodes['leaf0'], cmd)

    time.sleep(10)

    # configure back Vrf01, since fixer code will try to unconfigure Vrf01 instance
    # and it may fail.
    cmds = [
        'sudo config vrf add Vrf01',
        'sudo config interface vrf bind {} Vrf01'.format(vars.D3D2P1),
        'sudo config interface vrf bind Loopback1 Vrf01',
        'sudo config interface vrf bind {} Vrf01'.format(vars.D3D2P2),
        'sudo config interface vrf bind Loopback3 Vrf01',
        'sudo config interface ip add {} 20.1.1.1/24'.format(vars.D3D2P1),
        'sudo config interface ip add {} 20::1/64'.format(vars.D3D2P2),
        'sudo config interface ip add Loopback1 192.168.0.2/32',
        'sudo config interface ip add Loopback3 192::1:2/128'
    ]

    for cmd in cmds:        
        st.config(nodes['leaf0'], cmd)

    time.sleep(10)

    cmds = [
        'router bgp 2002 vrf Vrf01',
        'no bgp ebgp-requires-policy',
        'no bgp network import-check',
        'neighbor 20.1.1.2 remote-as 1003',
        'neighbor 20.1.1.2 update-source 20.1.1.1',
        'neighbor 20.1.1.2 timers 3 10',
        'neighbor 20::2 remote-as 1003',
        'neighbor 20::2 update-source 20::1',
        'neighbor 20::2 timers 3 10',
        'address-family ipv4 unicast',
        'redistribute connected',
        'exit-address-family',
        'address-family ipv6 unicast',
        'neighbor 20::2 activate',
        'redistribute connected',
        'exit-address-family',
        'exit'
    ]

    config_frr(nodes['leaf0'], cmds)

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
