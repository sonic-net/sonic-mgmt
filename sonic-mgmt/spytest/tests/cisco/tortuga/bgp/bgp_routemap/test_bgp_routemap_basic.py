######################################################################
# BGP test case(s) to validate the route-map for these scenario
# 1. To verify functionality of route map application after route has been installed
#    test_ft_bgp_rmap
# 2. To verify functioning of route-map to filter incoming IPv4 prefix(s)
#    test_bgp_route_map_with_community
######################################################################

import os
import time
import yaml
import pytest
from spytest import st

import apis.routing.ip as ipapi
# TODO: to be restored after the upstream bgpapi has been addressed and
# the local bgp.py is removed.
# import apis.routing.bgp as bgpapi
import tests.cisco.tortuga.bgp.bgp as bgpapi

pytest.fixture(scope='module', autouse=True)
def box_service_module_hooks(request):
    global vars
    global bgp_cli_type, vtysh_cli_type
    global dut_list
    dut_list = [vars.D1, vars.D2, vars.D3]

    bgp_cli_type = st.get_ui_type()
    # bgp_cli_type = "click"
    if bgp_cli_type == 'click':
        bgp_cli_type = 'vtysh'
    vtysh_cli_type = bgp_cli_type
    yield

@pytest.fixture(scope='function', autouse=True)
def box_service_func_hooks(request):
    yield

CONFIGS_FILE = 'bgp_cfg.yaml'

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

######################################################################
#                                                                    #
#  SD1 ---default--- SD3 ---default--- SD2                           #
#                                                                    #
######################################################################

def config_static(node, config_domain, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['SD1'] = vars.D1
    nodes['SD3'] = vars.D3

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
def setup_teardown_bgp():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['SD1'] = vars.D1
    nodes['SD3'] = vars.D3

    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            st.config(nodes[node], "systemctl stop drake", skip_error_check=False, conf=True)
            st.config(nodes[node], "no router bgp", type='vtysh', skip_error_check=False, conf=True)
            '''
            # Disabling drake so that there are no automatic underlay configs
            # Check drake agent is running before disabling it.
            cmd = 'systemctl status drake'
            cmd_output = st.config(nodes[node], cmd)
            if "Active:  active (running)" in str(cmd_output.encode('ascii','ignore')):
                st.config(nodes[node], "systemctl stop drake", skip_error_check=False, conf=True)
                st.config(nodes[node], "no router bgp", type='vtysh', skip_error_check=False, conf=True)
            '''

            config_static(node, 'sonic')
            config_static(node, 'bgp')

    count = 5    
    st.show(nodes['SD1'], 'sudo ping -c {} {} -q'.format(count, '10.1.3.3'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['SD3'], 'sudo ping -c {} {} -q'.format(count, '10.1.3.1'), skip_tmpl=True, skip_error_check=True)

    yield 'setup_teardown_bgp'

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp', add=False)
            config_static(node, 'sonic', add=False)


######################################################################
# Test Cases
######################################################################

# testcase #1: To verify functionality of route map application after route has been installed
def test_ft_bgp_rmap(setup_teardown_bgp):
    """
    Verify a route map application after route has been installed
    """
    global bgp_cli_type, vtysh_cli_type

    bgp_cli_type = st.get_ui_type()
    vtysh_cli_type = bgp_cli_type

    vars = st.get_testbed_vars()

    nodes = {}
    nodes['SD1'] = vars.D1
    nodes['SD3'] = vars.D3

    # Getting topo info
    # NOTE: D1 is spine D3 is leaf by default

    leaf_name  = nodes['SD3']
    spine_name = nodes['SD1']
    leaf_as    = 3003
    spine_as   = 1001

    network1 = '134.5.6.0/24'

    # Advertise a network to peer
    n1 = bgpapi.advertise_bgp_network(leaf_name, leaf_as, network1, cli_type=vtysh_cli_type)
    n1 = ipapi.verify_ip_route(spine_name, ip_address=network1)
    if n1:
        st.log("Advertised route present")

    # Create access-list test-access-list1 and deny the network
    ipapi.config_access_list(leaf_name, 'test-access-list1', network1, 'deny', seq_num="5")
    # Create a route-map to deny the network advertisement
    ipapi.config_route_map_match_ip_address(leaf_name, 'test-rmap', 'deny', '10', 'test-access-list1')

    # Add route-map to advertised network
    bgpapi.advertise_bgp_network(leaf_name, leaf_as, network1, 'test-rmap', cli_type=vtysh_cli_type)

    # Verify the network on spine
    n1 = ipapi.verify_ip_route(spine_name, ip_address=network1)
    if not n1:
        result = True
    else:
        st.generate_tech_support([leaf_name, spine_name], "ft_bgp_rmap")
        result = False

    # Clear applied configs
    ipapi.config_route_map_mode(leaf_name, 'test-rmap', 'permit', '10', config='no')
    ipapi.config_access_list(leaf_name, 'test-access-list1', network1, 'deny', config='no', seq_num="5")

    bgpapi.advertise_bgp_network(leaf_name, leaf_as, network1, 'test-rmap', config='no', cli_type=vtysh_cli_type)

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


# testcase #2: To verify functioning of route-map to filter incoming IPv4 prefix(s)
def test_bgp_route_map_with_community(setup_teardown_bgp):
    """
    Verify functioning of route-map to filter incoming IPv4 prefix(s)
    """
    result = True

    global bgp_cli_type, vtysh_cli_type

    bgp_cli_type = st.get_ui_type()
    vtysh_cli_type = bgp_cli_type

    vars = st.get_testbed_vars()

    nodes = {}
    nodes['SD1'] = vars.D1
    nodes['SD3'] = vars.D3
    dut1_as = 1001
    dut3_as = 3003

    dut1_addr_ipv4 = '10.1.3.1'
    static_rt      = '40.1.1.1/32'
    static_rt_ip   = '40.1.1.1'
    static_rt_mlen = '32'
    rmap_community = '100:100'

    ipapi.config_route_map(nodes['SD3'], route_map='rmap1', config='yes',
                           sequence='10', community=rmap_community)
    ipapi.create_static_route(nodes['SD1'], next_hop='blackhole', static_ip=static_rt)

    bgpapi.config_bgp(dut=nodes['SD1'], local_as=dut1_as, config='yes',
                      config_type_list=["redist"], redistribute='static', cli_type="")
    bgpapi.config_bgp(dut=nodes['SD3'], local_as=dut3_as, 
                      neighbor=dut1_addr_ipv4,
                      addr_family='ipv4', config='yes',
                      config_type_list=["routeMap"], routeMap='rmap1',
                      diRection='in', cli_type="")

    # Check the show command in leaf
    output = bgpapi.show_bgp_ipvx_prefix(nodes['SD3'], prefix=static_rt_ip, masklen=static_rt_mlen, family='ipv4')
    st.log(output)
    # there is only one record
    for x in output or {}:
        if ((x['peerip'].find(dut1_addr_ipv4)) != -1) and (x['community'] == rmap_community):
            result = True
            break
        else:
            result = False

    ipapi.config_route_map(dut=nodes['SD3'], route_map='rmap1', config='no',
                           sequence='10')
    ipapi.delete_static_route(dut=nodes['SD1'], next_hop='blackhole', static_ip=static_rt)
    if result:
        st.report_pass("operation_successful")
    else:
        st.report_fail("operation_failed")
