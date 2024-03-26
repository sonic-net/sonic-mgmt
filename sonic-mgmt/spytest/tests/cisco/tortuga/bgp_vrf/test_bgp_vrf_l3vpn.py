import os
import time
import yaml
import pytest
from spytest import st

pytest.fixture(scope='module', autouse=True)
def box_service_module_hooks(request):
    global vars
    global dut_list
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    yield

@pytest.fixture(scope='function', autouse=True)
def box_service_func_hooks(request):
    yield

# TODO: Parameterize the configs. For now, use static configs
CONFIGS_FILE = 'bgp_basic_cfg.yaml'

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)

####################
#                  #
#    D1 = CE1      #
#    D2 = PE1      #
#    D3 = P1       #
#    D4 = PE2      #
#                  #
####################

######################################################################
#          eBGP             eBGP           iBGP                      #
#  CE1 ---default--- PE1 ---Vrf01--- P1 ---Vrf02--- PE2              #
#                                                                    #
######################################################################
def config_static(node, config_domain, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3
    nodes['PE2'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)

@pytest.fixture(scope="module", autouse=True)
def setup_teardown_bgp_vrf():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3
    nodes['PE2'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            # Disabling drake so that there are no automatic underlay configs
            # Check drake agent is running before disabling it.
            cmd = 'systemctl status drake'
            cmd_output = st.config(nodes[node], cmd)
            if "Active: active (running)" in str(cmd_output.encode('ascii','ignore')):
                st.config(nodes[node], "systemctl stop drake", skip_error_check=False, conf=True)
                st.config(nodes[node], "no router bgp", type='vtysh', skip_error_check=False, conf=True)

            config_static(node, 'sonic')
            config_static(node, 'bgp')

    count = 5    
    st.show(nodes['CE1'], 'sudo ping -c {} {} -q'.format(count, '10.1.1.2'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['PE1'], 'sudo ping -I Vrf01 -c {} {} -q'.format(count, '20.1.1.2'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['P1'], 'sudo ping -I Vrf02 -c {} {} -q'.format(count, '30.1.1.2'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['CE1'], 'sudo ping -c {} {} -q'.format(count, '10::2'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['PE1'], 'sudo ping -I Vrf01 -c {} {} -q'.format(count, '20::2'), skip_tmpl=True, skip_error_check=True)

    yield 'setup_teardown_bgp_vrf'

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp', add=False)
            config_static(node, 'sonic', add=False)

def setup_bgp_vrf_network_scale(node, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3
    nodes['PE2'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    domain = 'vtysh'

    with open(dir_path + '/' + 'bgp_vrf_route_scale.yaml') as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node]['bgp']['config'], domain)
        else:
            config_node(nodes[node], config_list[node]['bgp']['deconfig'], domain)

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
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3
    nodes['PE2'] = vars.D4

    #1. Ping end to end loopback address of BGP neighbours
    # Ping Loopback address of BGP neighbour
    cmd = "ping -c 5 192.168.1.1"
    cmd_output = st.config(nodes['PE1'], cmd)
    if "0% packet loss" in str(cmd_output.encode('ascii','ignore')):
        st.log("Ping to CE1 is Sucessful")
    else:
        st.report_fail("test_case_failed", nodes['PE1'])

    cmd = "ping -I Vrf01 -c 5 192.168.1.3"
    cmd_output = st.config(nodes['PE1'], cmd)
    if "0% packet loss" in str(cmd_output.encode('ascii','ignore')):
        st.log("Ping to P1 is Sucessful")
    else:
        st.report_fail("test_case_failed", nodes['PE1'])

    st.report_pass('test_case_passed', nodes['CE1'])
    st.report_pass('test_case_passed', nodes['PE1'])
    st.report_pass('test_case_passed', nodes['P1'])
    st.report_pass('test_case_passed', nodes['PE2'])

def test_bgp_vrf_validate_route():
    """
    2. Check routes are installed in respective VRF 
       Check Loopback route is installed in repsective VRF of neighbouring BGP peer
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3
    nodes['PE2'] = vars.D4

    cmd = "show ip route vrf Vrf01 192.168.1.3"
    cmd_output = st.config(nodes['PE1'], cmd)

    if len(cmd_output) > 0 and "20.1.1.2, via Ethernet8" in str(cmd_output.encode('ascii','ignore')):
        st.log("VRF route is available")
    else:
        st.report_fail("test_case_failed", nodes['PE1'])

    st.report_pass('test_case_passed', nodes['CE1'])
    st.report_pass('test_case_passed', nodes['PE1'])
    st.report_pass('test_case_passed', nodes['P1'])
    st.report_pass('test_case_passed', nodes['PE2'])

def test_bgp_vrf_scale_check():
    """
    3. scale test, installing 10 prefix in 20 milli sec
       Need to check how to delete installed prefix.
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3
    nodes['PE2'] = vars.D4

    setup_bgp_vrf_network_scale('P1')
    time.sleep(1/50)

    for i in range(1, 11, 1):
        cmd = f'show ip route vrf Vrf01 1.1.1.{i}'
        cmd_output = st.config(nodes['PE1'], cmd)
        if len(cmd_output) > 0 and "20.1.1.2, via Ethernet8" in str(cmd_output.encode('ascii','ignore')):
            st.log("VRF route is available")
        else:
            st.report_fail("test_case_failed", nodes['PE1'])

    st.report_pass('test_case_passed', nodes['CE1'])
    st.report_pass('test_case_passed', nodes['PE1'])
    st.report_pass('test_case_passed', nodes['P1'])
    st.report_pass('test_case_passed', nodes['PE2'])

def test_check_routers_are_unambiguous():
    """
    5. Within each VRF, each address must be unambiguous on DUT
       Add two static route of same IP with different static route to VRF
       should install only one IP in the RIB table.
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3
    nodes['PE2'] = vars.D4

    cmds = ['ip route 13.1.1.0/24 Null0 vrf Vrf01',
            'router bgp 2002 vrf Vrf01',
            'address-family ipv4 unicast',
            'redistribute static',
            'exit-address-family',
            'exit']
    for cmd in cmds:
        st.vtysh_config(nodes['PE1'], cmd)

    cmd_output = st.vtysh(nodes['PE1'], "show ip route vrf Vrf01")
    if "13.1.1.0/24" not in str(cmd_output):
        st.report_fail("test_case_failed", nodes['PE1'])

    cmds = ['ip route 13.1.1.0/24 Null0 tag 100 vrf Vrf01',
            'router bgp 2002 vrf Vrf01',
            'address-family ipv4 unicast',
            'redistribute static',
            'exit-address-family',
            'exit']

    for cmd in cmds:
        st.vtysh_config(nodes['PE1'], cmd)

    cmd_output = st.vtysh(nodes['PE1'], "show ip route vrf Vrf01 13.1.1.0")
    if str(cmd_output).count("13.1.1.0") > 1 or "tag 100" not in str(cmd_output):
        st.report_fail("test_case_failed", nodes['PE1'])

    #6. check adding of same route in default VRF is allowed
    cmds = ['ip route 13.1.1.0/24 Null0',
        'router bgp 1002',
        'address-family ipv4 unicast',
        'redistribute static',
        'exit-address-family',
        'exit']
    for cmd in cmds:
        st.vtysh_config(nodes['PE1'], cmd)

    cmd_output = st.vtysh(nodes['PE1'], "show ip route")
    if "13.1.1.0/24" not in str(cmd_output):
        st.report_fail("test_case_failed", nodes['PE1'])

    #7. check this routes are learnt by respective BGP 
    # Check in CE1 route is installed in default instance.
    cmd = "show ip route 13.1.1.0"
    cmd_output = st.config(nodes['CE1'], cmd)

    if len(cmd_output) > 0 and "10.1.1.2, via Ethernet0" in str(cmd_output):
        st.log("default vrf route is available")
    else:
        st.report_fail("test_case_failed", nodes['CE1'])

    cmd = "show ip route vrf Vrf01 13.1.1.0"
    cmd_output = st.config(nodes['P1'], cmd)
    if len(cmd_output) > 0 and "20.1.1.1, via Ethernet0" in str(cmd_output):
        st.log("VRF route is available")
    else:
        st.report_fail("test_case_failed", nodes['P1'])

    #Add route map to match 13.1.1.0 and prepend AS with 9009 to Vrf01
    cmds = ['ip prefix-list allow_list permit 13.1.1.0/24',
        'route-map ALLOW_PREFIX permit 10',
        'match ip address prefix-list allow_list',
        'set as-path prepend 9009',
        'router bgp 2002 vrf Vrf01',
        'address-family ipv4 unicast',
        'neighbor 20.1.1.2 route-map ALLOW_PREFIX out']

    for cmd in cmds:
        st.vtysh_config(nodes['PE1'], cmd)

    #check 9009 is present in P1
    cmd = "show bgp vrf Vrf01 ipv4 neighbors 20.1.1.1 routes"
    cmd_output = st.vtysh(nodes['P1'], cmd)

    if "2002 9009" not in str(cmd_output):
        st.report_fail("test_case_failed", nodes['P1'])

    #check 9009 is not present in CE1
    cmd = "show bgp ipv4 neighbors 10.1.1.2 routes"
    cmd_output = st.vtysh(nodes['CE1'], cmd)

    if "2002 9009" in str(cmd_output):
        st.report_fail("test_case_failed", nodes['CE1'])

    st.report_pass('test_case_passed', nodes['CE1'])
    st.report_pass('test_case_passed', nodes['PE1'])
    st.report_pass('test_case_passed', nodes['P1'])
    st.report_pass('test_case_passed', nodes['PE2'])

def test_bgp_vrf_check_static_route_redist():
    """
     9. Advertise same set of prefixes from different VRFs
    10. Redistribute Static routes and verify on remote routers
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3
    nodes['PE2'] = vars.D4

    # configure 15.1.1.0/24 in Vrf01 instance of P1.
    cmds = ['ip route 15.1.1.0/24 Null0 vrf Vrf01',
            'router bgp 1003 vrf Vrf01',
            'address-family ipv4 unicast',
            'redistribute static',
            'exit-address-family',
            'exit']
    for cmd in cmds:
        st.vtysh_config(nodes['P1'], cmd)

    # configure 15.1.1.0/24 in default instance of CE1.
    cmds = ['ip route 15.1.1.0/24 Null0',
            'router bgp 1001',
            'address-family ipv4 unicast',
            'redistribute static',
            'exit-address-family',
            'exit']
    for cmd in cmds:
        st.vtysh_config(nodes['CE1'], cmd)

    # check same route from P1 and CE1 of different instance is
    # installed in PE1 of default and Vrf02 instance
    cmd = "show ip route vrf Vrf01 15.1.1.0"

    cmd_output = st.config(nodes['PE1'], cmd)
    if len(cmd_output) > 0 and "20.1.1.2, via Ethernet8" in str(cmd_output):
        st.log("VRF route is available")
    else:
        st.report_fail("test_case_failed", nodes['PE1'])

    cmd = "show ip route 15.1.1.0"
    cmd_output = st.config(nodes['PE1'], cmd)

    if len(cmd_output) > 0 and "10.1.1.1, via Ethernet0" in str(cmd_output):
        st.log("default vrf route is available")
    else:
        st.report_fail("test_case_failed", nodes['PE1'])

    st.report_pass('test_case_passed', nodes['CE1'])
    st.report_pass('test_case_passed', nodes['PE1'])
    st.report_pass('test_case_passed', nodes['P1'])
    st.report_pass('test_case_passed', nodes['PE2'])

def test_bgp_vrf_static_route_inter_vrf_comm():
    """
    14. Verify inter-vrf communication between eBGP peer
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3
    nodes['PE2'] = vars.D4

    cmds = ['ip route 30.1.1.0/24 Ethernet8 nexthop-vrf Vrf01',
            'router bgp 1002',
            'address-family ipv4 unicast',
            'redistribute static',
            'exit-address-family',
            'exit']
    for cmd in cmds:
        st.vtysh_config(nodes['PE1'], cmd)

    cmd = "show ip route 30.1.1.0"

    cmd_output = st.config(nodes['PE1'], cmd)

    if len(cmd_output) > 0 and "directly connected, Ethernet8" in str(cmd_output):
        st.log("VRF route is available")
    else:
        st.report_fail("test_case_failed", nodes['PE1'])

    cmd = "show ip route 30.1.1.0"
    cmd_output = st.config(nodes['CE1'], cmd)

    if len(cmd_output) > 0 and "10.1.1.2, via Ethernet0" in str(cmd_output):
        st.log("default vrf route is available")
    else:
        st.report_fail("test_case_failed", nodes['CE1'])

    st.report_pass('test_case_passed', nodes['CE1'])
    st.report_pass('test_case_passed', nodes['PE1'])
    st.report_pass('test_case_passed', nodes['P1'])
    st.report_pass('test_case_passed', nodes['PE2'])

def test_bgp_vrf_check_ibgp_vrf_conn():
    """
    13. Verify intra-vrf and inter-vrf communication between
    """
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3
    nodes['PE2'] = vars.D4

    # check PE2 loopback address is present in P1 Vrf02 route table
    cmd = 'show ip route vrf Vrf02 192.168.1.4'
    cmd_output = st.config(nodes['P1'], cmd)
    if len(cmd_output) > 0 and "* 30.1.1.2, via Ethernet8" in str(cmd_output):
        st.log("vrf route is available")
    else:
        st.report_fail("test_case_failed", nodes['P1'])

    # ping loopback addres of PE2
    cmd = "ping -I Vrf02 -c 5 192.168.1.4"
    cmd_output = st.config(nodes['P1'], cmd)
    if "0% packet loss" in str(cmd_output.encode('ascii','ignore')):
        st.log("Ping to P1 is Sucessful")
    else:
        st.report_fail("test_case_failed", nodes['P1'])

    st.report_pass('test_case_passed', nodes['CE1'])
    st.report_pass('test_case_passed', nodes['PE1'])
    st.report_pass('test_case_passed', nodes['P1'])
    st.report_pass('test_case_passed', nodes['PE2'])
