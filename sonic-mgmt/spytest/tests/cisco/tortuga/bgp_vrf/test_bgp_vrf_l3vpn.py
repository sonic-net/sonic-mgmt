import os
import time
import yaml
import pytest
from spytest import st

pytest.fixture(scope='module', autouse=True)
def box_service_module_hooks(request):
    global vars
    global dut_list
    dut_list = [vars.D1, vars.D2, vars.D3]
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
#                  #
####################

######################################################################
#                                                                    #
#  CE1 ---default--- PE1 ---Vrf01--- P1                              #
#                                                                    #
######################################################################
def config_static(node, config_domain, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3

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

@pytest.fixture()
def setup_teardown_bgp_vrf():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3

    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            # Disabling drake so that there are no automatic underlay configs
            st.config(nodes[node], "systemctl stop drake", skip_error_check=False, conf=True)
            st.config(nodes[node], "no router bgp", type='vtysh', skip_error_check=False, conf=True)

            config_static(node, 'sonic')
            config_static(node, 'bgp')

    count = 5    
    st.show(nodes['CE1'], 'sudo ping -c {} {} -q'.format(count, '10.1.1.2'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['PE1'], 'sudo ping -I Vrf01 -c {} {} -q'.format(count, '20.1.1.2'), skip_tmpl=True, skip_error_check=True)

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

    dir_path = os.path.dirname(os.path.realpath(__file__))

    domain = 'vtysh'

    with open(dir_path + '/' + 'bgp_vrf_route_scale.yaml') as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node]['bgp']['config'], domain)
        else:
            config_node(nodes[node], config_list[node]['bgp']['deconfig'], domain)

@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_bgp_vfr_nbr_reach(setup_teardown_bgp_vrf):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3

    ce1_pe1_ip = "10.1.1.1"
    pe1_ce1_ip = "10.1.1.2"

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

#2. Check routes are installed in respective VRF 
# Check Loopback route is installed in repsective VRF of neighbouring BGP peer
def test_bgp_vrf_validate_route(setup_teardown_bgp_vrf):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3

    cmd = "show ip route vrf Vrf01 192.168.1.3"
    cmd_output = st.config(nodes['PE1'], cmd)

    if len(cmd_output) != 0:
        if "20.1.1.2, via Ethernet8" in str(cmd_output.encode('ascii','ignore')):
            st.log("VRF route is available")
        else:
            st.report_fail("test_case_failed", nodes['PE1'])
    else:
        st.report_fail("test_case_failed", nodes['PE1'])

# 3. scale test, installing 10 prefix in 20 milli sec
# Need to check how to delete installed prefix.
def test_bgp_vrf_scale_check(setup_teardown_bgp_vrf):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['CE1'] = vars.D1
    nodes['PE1'] = vars.D2
    nodes['P1'] = vars.D3

    setup_bgp_vrf_network_scale('P1')
    time.sleep(1/50)

    cmd = "show ip route vrf Vrf01 1.1.1.10"
    cmd_output = st.config(nodes['PE1'], cmd)
    if len(cmd_output) != 0:
        if "20.1.1.2, via Ethernet8" in str(cmd_output.encode('ascii','ignore')):
            st.log("VRF route is available")
        else:
            st.report_fail("test_case_failed", nodes['PE1'])
    else:
        st.report_fail("test_case_failed", nodes['PE1'])
