import os
import yaml
import pytest
from spytest import st
import apis.system.box_services as boxserv_obj

##
## config: eBGP + ECMP
##  Topology : 2x Spine + 2 Leafs
##
##  SD1 -- Spine0  - D1
##  SD1 -- Spine1  - D2
##  SD2 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4
##

pytest.fixture(scope="module", autouse=True)
def box_service_module_hooks(request):
    global vars
    global dut_list
    vars = st.ensure_min_topology("D1D3:4","D1D4:4","D2D3:4","D2D4:4")
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    yield

@pytest.fixture(scope="function", autouse=True)
def box_service_func_hooks(request):
    yield

CONFIGS_FILE = 'vxlan_l2vni_configs.yaml'
LEAF0_VXLAN_IP = '10.200.200.200'
LEAF1_VXLAN_IP = '10.200.200.201'

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

def config_static(node, config_domain, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

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


def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)


####################
@pytest.fixture()
def setup_teardown_l2vni():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')

    # Make sure links are up by pinging, sometimes packet exchange doesn't happen on sim till pings are initiated
    st.wait(5)
    count = 5
    st.show(nodes['leaf0'], 'sudo ping -c {} {} -q'.format(count, '10.200.200.201'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['leaf1'], 'sudo ping -c {} {} -q'.format(count, '10.200.200.200'), skip_tmpl=True, skip_error_check=True)

    yield 'setup_teardown_l2vni'

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)


def verify_vtep_state (nodes):
    leaf0_vtep_ip = LEAF0_VXLAN_IP
    leaf1_vtep_ip = LEAF1_VXLAN_IP

    leaf0_output = st.show(nodes['leaf0'], "show vxlan remotevtep", skip_tmpl=True)

    leaf0_parsed = st.parse_show(nodes['leaf0'], "show vxlan remotevtep",
                                 leaf0_output, "show_vxlan_remote.tmpl")

    leaf1_output = st.show(nodes['leaf1'], "show vxlan remotevtep", skip_tmpl=True)

    leaf1_parsed = st.parse_show(nodes['leaf1'], "show vxlan remotevtep",
                                 leaf1_output, "show_vxlan_remote.tmpl")

    if len(leaf0_parsed) == 0:
        report_fail(nodes['leaf0'], msg='No remote VTEP found in leaf0')

    vtep_num = 0
    for path in leaf0_parsed:
        vtep_num += 1
        if path['tun_src'] != 'EVPN':
            report_fail(nodes['leaf0'], msg='Unexpected tunnel type {} in leaf0'.format(path['tun_type']))
        if path['src_vtep'] != leaf0_vtep_ip:
            report_fail(nodes['leaf0'], msg='No local vtep {} found in leaf0'.format(leaf0_vtep_ip))
        if path['dst_vtep'] != leaf1_vtep_ip:
            report_fail(nodes['leaf0'], msg='Unexpected vtep {} found in leaf0'.format(path['rem_vtep']))
        if path['tun_status'] != 'oper_up':
            report_fail(nodes['leaf0'], msg='Tunnel is not in up status in leaf0')
    if vtep_num != 1:
        report_fail(nodes['leaf0'], msg='Incorrect number of VTEPs found in leaf0')

    if len(leaf1_parsed) == 0:
        report_fail(nodes['leaf1'], msg='No remote VTEP found in leaf1')
    vtep_num = 0
    for path in leaf1_parsed:
        vtep_num += 1
        if path['tun_src'] != 'EVPN':
            report_fail(nodes['leaf1'], msg='Unexpected tunnel type {} in leaf1'.format(path['tun_type']))
        if path['src_vtep'] != leaf1_vtep_ip:
            report_fail(nodes['leaf1'], msg='No local vtep {} found in leaf1'.format(leaf1_vtep_ip))
        if path['dst_vtep'] != leaf0_vtep_ip:
            report_fail(nodes['leaf1'], msg='Unexpected vtep {} found in leaf1'.format(path['rem_vtep']))
        if path['tun_status'] != 'oper_up':
            report_fail(nodes['leaf1'], msg='Tunnel is not in up status in leaf1')
    if vtep_num != 1:
        report_fail(nodes['leaf1'], msg='Incorrect number of VTEPs found in leaf1')

def run_traffic_test (nodes):
    # TBD:
    # ping test
    # traffic test
    # BUM test
    st.wait(1)
    #report_fail(nodes['leaf0'], msg='Traffic test failed')

@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass

def test_l2vni_vtep_setup (setup_teardown_l2vni):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    st.wait(60)

    verify_vtep_state(nodes)
    run_traffic_test(nodes)

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])


def test_l2vni_vtep_delete_add (setup_teardown_l2vni):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    st.wait(60)

    verify_vtep_state(nodes)
    run_traffic_test(nodes)

    test_node = 'leaf0'
    config_static(test_node, 'bgp', add=False)
    config_static(test_node, 'sonic', add=False)
    st.wait(10)
    config_static(test_node, 'sonic', add=True)
    config_static(test_node, 'bgp', add=True)
    st.wait(10)

    # Make sure links are up by pinging, sometimes packet exchange doesn't happen on sim till pings are initiated
    count = 5
    st.show(nodes['leaf0'], 'sudo ping -c {} {} -q'.format(count, '10.200.200.201'), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['leaf1'], 'sudo ping -c {} {} -q'.format(count, '10.200.200.200'), skip_tmpl=True, skip_error_check=True)

    st.wait(30)

    verify_vtep_state(nodes)
    run_traffic_test(nodes)

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
    st.report_pass('test_case_passed', nodes['spine0'])
    st.report_pass('test_case_passed', nodes['spine1'])
