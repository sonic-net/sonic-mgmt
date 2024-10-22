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
            common_obj.config_frr(node, config['bgp']['config'])
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
            common_obj.config_frr(node, config['bgp']['deconfig'])
            common_obj.config_static(node, 'sonic', False, update_path)

def setup_bgp_vrf_network_scale(node, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    domain = 'vtysh'

    with open(dir_path + '/' + 'bgp_vrf_route_scale.yaml') as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            common_obj.config_node(nodes[node], config_list[node]['bgp']['config'], domain)
        else:
            common_obj.config_node(nodes[node], config_list[node]['bgp']['deconfig'], domain)

# This testcases are added intended to check BGP VRF feature.
#########################################
# Testcases
#########################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_bgp_vfr_nbr_reach():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    #1. Ping end to end loopback address of BGP neighbours
    # Ping Loopback address of BGP neighbour
    cmd = "ping -c 5 192.168.1.1"
    cmd_output = st.config(nodes['leaf0'], cmd)
    if "0% packet loss" in str(cmd_output.encode('ascii','ignore')):
        st.log("Ping to spine0 is Sucessful")
    else:
        st.report_fail("test_case_failed", nodes['leaf0'])

    cmd = "ping -I Vrf01 -c 5 192.168.1.3"
    cmd_output = st.config(nodes['leaf0'], cmd)
    if "0% packet loss" in str(cmd_output.encode('ascii','ignore')):
        st.log("Ping to spine1 is Sucessful")
    else:
        st.report_fail("test_case_failed", nodes['leaf0'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])

def test_bgp_vrf_validate_route():
    """
    2. Check routes are installed in respective VRF 
       Check Loopback route is installed in repsective VRF of neighbouring BGP peer
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    cmd = "show ip route vrf Vrf01 192.168.1.3"
    cmd_output = st.config(nodes['leaf0'], cmd)

    if len(cmd_output) > 0 and '20.1.1.2, via {}'.format(vars.D3D2P1) in str(cmd_output.encode('ascii','ignore')):
        st.log("VRF route is available")
    else:
        st.report_fail("test_case_failed", nodes['leaf0'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])

def test_bgp_vrf_scale_check():
    """
    3. scale test, installing 10 prefix in 20 milli sec
       Need to check how to delete installed prefix.
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    setup_bgp_vrf_network_scale('spine1')
    time.sleep(1/50)

    for i in range(1, 11, 1):
        cmd = 'show ip route vrf Vrf01 1.1.1.{}'.format(i)
        cmd_output = st.config(nodes['leaf0'], cmd)
        if len(cmd_output) > 0 and '20.1.1.2, via {}'.format(vars.D3D2P1) in str(cmd_output.encode('ascii','ignore')):
            st.log("VRF route is available")
        else:
            st.report_fail("test_case_failed", nodes['leaf0'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])

def test_check_routers_are_unambiguous():
    """
    5. Within each VRF, each address must be unambiguous on DUT
       Add two static route of same IP with different static route to VRF
       should install only one IP in the RIB table.
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    cmds = ['ip route 13.1.1.0/24 Null0 vrf Vrf01',
            'router bgp 2002 vrf Vrf01',
            'address-family ipv4 unicast',
            'redistribute static',
            'exit-address-family',
            'exit']

    common_obj.config_frr(nodes['leaf0'], cmds)

    cmd_output = st.show(nodes['leaf0'], "vtysh -c 'show ip route vrf Vrf01'")
    if "13.1.1.0/24" not in str(cmd_output):
        st.report_fail("test_case_failed", nodes['leaf0'])

    cmds = ['ip route 13.1.1.0/24 Null0 tag 100 vrf Vrf01',
            'router bgp 2002 vrf Vrf01',
            'address-family ipv4 unicast',
            'redistribute static',
            'exit-address-family',
            'exit']

    common_obj.config_frr(nodes['leaf0'], cmds)

    cmd_output = st.show(nodes['leaf0'], "vtysh -c 'show ip route vrf Vrf01 13.1.1.0'")
    if str(cmd_output).count("13.1.1.0") > 1 or "tag 100" not in str(cmd_output):
        st.report_fail("test_case_failed", nodes['leaf0'])

    #6. check adding of same route in default VRF is allowed
    cmds = ['ip route 13.1.1.0/24 Null0',
        'router bgp 1002',
        'address-family ipv4 unicast',
        'redistribute static',
        'exit-address-family',
        'exit']
    common_obj.config_frr(nodes['leaf0'], cmds)

    cmd_output = st.show(nodes['leaf0'], "vtysh -c 'show ip route'")
    if "13.1.1.0/24" not in str(cmd_output):
        st.report_fail("test_case_failed", nodes['leaf0'])

    #7. check this routes are learnt by respective BGP 
    # Check in spine0 route is installed in default instance.
    cmd = "show ip route 13.1.1.0"
    cmd_output = st.config(nodes['spine0'], cmd)

    if len(cmd_output) > 0 and '10.1.1.2, via {}'.format(vars.D1D3P1) in str(cmd_output):
        st.log("default vrf route is available")
    else:
        st.report_fail("test_case_failed", nodes['spine0'])

    cmd = "show ip route vrf Vrf01 13.1.1.0"
    cmd_output = st.config(nodes['spine1'], cmd)
    if len(cmd_output) > 0 and '20.1.1.1, via {}'.format(vars.D2D3P1) in str(cmd_output):
        st.log("VRF route is available")
    else:
        st.report_fail("test_case_failed", nodes['spine1'])

    #Add route map to match 13.1.1.0 and prepend AS with 9009 to Vrf01
    cmds = ['ip prefix-list allow_list permit 13.1.1.0/24',
        'route-map ALLOW_PREFIX permit 10',
        'match ip address prefix-list allow_list',
        'set as-path prepend 9009',
        'router bgp 2002 vrf Vrf01',
        'address-family ipv4 unicast',
        'neighbor 20.1.1.2 route-map ALLOW_PREFIX out']

    common_obj.config_frr(nodes['leaf0'], cmds)

    #check 9009 is present in spine1
    cmd = "vtysh -c 'show bgp vrf Vrf01 ipv4 neighbors 20.1.1.1 routes'"
    cmd_output = st.show(nodes['spine1'], cmd)

    if "2002 9009" not in str(cmd_output):
        st.report_fail("test_case_failed", nodes['spine1'])

    #check 9009 is not present in spine0
    cmd = "vtysh -c 'show bgp ipv4 neighbors 10.1.1.2 routes'"
    cmd_output = st.show(nodes['spine0'], cmd)

    if "2002 9009" in str(cmd_output):
        st.report_fail("test_case_failed", nodes['spine0'])

    cmd = 'no route-map ALLOW_PREFIX'
    common_obj.config_frr(nodes['leaf0'], cmd)
    cmd = 'no ip prefix-list allow_list permit 13.1.1.0/24'
    common_obj.config_frr(nodes['leaf0'], cmd)

    cmd = 'no ip route 13.1.1.0/24 Null0 tag 100 vrf Vrf01'
    common_obj.config_frr(nodes['leaf0'], cmd)
    cmd = 'no ip route 13.1.1.0/24 Null0'
    common_obj.config_frr(nodes['leaf0'], cmd)

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])

def test_bgp_vrf_check_static_route_redist():
    """
     9. Advertise same set of prefixes from different VRFs
    10. Redistribute Static routes and verify on remote routers
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    # configure 15.1.1.0/24 in Vrf01 instance of spine1.
    cmds = ['ip route 15.1.1.0/24 Null0 vrf Vrf01',
            'router bgp 1003 vrf Vrf01',
            'address-family ipv4 unicast',
            'redistribute static',
            'exit-address-family',
            'exit']
    common_obj.config_frr(nodes['spine1'], cmds)

    # configure 15.1.1.0/24 in default instance of spine0.
    cmds = ['ip route 15.1.1.0/24 Null0',
            'router bgp 1001',
            'address-family ipv4 unicast',
            'redistribute static',
            'exit-address-family',
            'exit']
    common_obj.config_frr(nodes['spine0'], cmds)

    # check same route from spine1 and spine0 of different instance is
    # installed in leaf0 of default and Vrf02 instance
    cmd = "show ip route vrf Vrf01 15.1.1.0"

    cmd_output = st.config(nodes['leaf0'], cmd)
    if len(cmd_output) > 0 and '20.1.1.2, via {}'.format(vars.D3D2P1) in str(cmd_output):
        st.log("VRF route is available")
    else:
        st.report_fail("test_case_failed", nodes['leaf0'])

    cmd = "show ip route 15.1.1.0"
    cmd_output = st.config(nodes['leaf0'], cmd)

    if len(cmd_output) > 0 and '10.1.1.1, via {}'.format(vars.D3D1P1) in str(cmd_output):
        st.log("default vrf route is available")
    else:
        st.report_fail("test_case_failed", nodes['leaf0'])

    cmd = 'no ip route 15.1.1.0/24 Null0'
    common_obj.config_frr(nodes['spine0'], cmd)
    cmd = 'no ip route 15.1.1.0/24 Null0 vrf Vrf01'
    common_obj.config_frr(nodes['spine1'], cmd)

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])

def test_bgp_vrf_static_route_inter_vrf_comm():
    """
    14. Verify inter-vrf communication between eBGP peer
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    cmds = ['ip route 30.1.1.0/24 {} nexthop-vrf Vrf01'.format(vars.D3D2P1),
            'router bgp 1002',
            'address-family ipv4 unicast',
            'redistribute static',
            'exit-address-family',
            'exit']
    common_obj.config_frr(nodes['leaf0'], cmds)

    cmd = "show ip route 30.1.1.0"

    cmd_output = st.config(nodes['leaf0'], cmd)

    if len(cmd_output) > 0 and 'directly connected, {}'.format(vars.D3D2P1) in str(cmd_output):
        st.log("VRF route is available")
    else:
        st.report_fail("test_case_failed", nodes['leaf0'])

    cmd = "show ip route 30.1.1.0"
    cmd_output = st.config(nodes['spine0'], cmd)

    if len(cmd_output) > 0 and '10.1.1.2, via {}'.format(vars.D1D3P1) in str(cmd_output):
        st.log("default vrf route is available")
    else:
        st.report_fail("test_case_failed", nodes['spine0'])

    cmd = 'no ip route 30.1.1.0/24 {} nexthop-vrf Vrf01'.format(vars.D3D2P1)
    common_obj.config_frr(nodes['leaf0'], cmd)

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])

def test_bgp_vrf_check_ibgp_vrf_conn():
    """
    13. Verify intra-vrf and inter-vrf communication between
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    # check leaf1 loopback address is present in spine1 Vrf02 route table
    cmd = 'show ip route vrf Vrf02 192.168.1.4'
    cmd_output = st.config(nodes['spine1'], cmd)
    if len(cmd_output) > 0 and '* 30.1.1.2, via {}'.format(vars.D2D4P1) in str(cmd_output):
        st.log("vrf route is available")
    else:
        st.report_fail("test_case_failed", nodes['spine1'])

    # ping loopback addres of leaf1
    cmd = "ping -I Vrf02 -c 5 192.168.1.4"
    cmd_output = st.config(nodes['spine1'], cmd)
    if "0% packet loss" in str(cmd_output.encode('ascii','ignore')):
        st.log("Ping to spine1 is Sucessful")
    else:
        st.report_fail("test_case_failed", nodes['spine1'])

    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
