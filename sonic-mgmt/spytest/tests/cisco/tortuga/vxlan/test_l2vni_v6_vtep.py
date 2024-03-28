import os
import yaml
import pytest
from spytest import st
import vxlan_utils as vu
import apis.system.box_services as boxserv_obj

##
##  Topology : 2 Spine + 2 Leafs + 2 Host
##
##  SD1 -- Leaf0   - D1
##  SD2 -- Leaf1   - D2
##
##  SD3 -- Spine0  - D3
##  SD4 -- Spine1  - D4
##
##

V6_VTEP_CONFIG_FILE = 'vxlan_l2vni_v6_vtep_configs.yaml'

REMOTE_VTEP_COUNT = '1'
SPINE0_VTEP_IP = 'fd27::2cb:8b5a:196'
SPINE1_VTEP_IP = 'fd27::234:377f:6b3'
LEAF0_VTEP_IP  = 'fd27::280:10f1:25f'
LEAF1_VTEP_IP  = 'fd27::22d:b87f:214b'

pytest.fixture(scope="module", autouse=True)
def box_service_module_hooks(request):
    global vars
    global dut_list
    vars = st.ensure_min_topology("D1D3:1", "D1D4:1", "D2D3:1", "D2D4:1")
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    yield


@pytest.fixture(scope="function", autouse=True)
def box_service_func_hooks(request):
    yield


def config_node(node, config, type='', skip_errors=False):
    if type:
        st.config(node, config, type=type, skip_error_check = skip_errors, conf=True)
    else:
        st.config(node, config, skip_error_check = skip_errors, conf=True)


def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail(msg, dut)


def config_static(node, config_domain, add=True):
    vars = st.get_testbed_vars()

    nodes = {}

    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    dir_path = os.path.dirname(os.path.realpath(__file__))

    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(dir_path + '/' + V6_VTEP_CONFIG_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain, skip_errors=True)


@pytest.fixture(scope='module', autouse=True)
def setup_and_teardown():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(dir_path + '/' + V6_VTEP_CONFIG_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            # Disabling drake so that there are no automatic underlay configs
            st.config(nodes[node], "systemctl stop drake", skip_error_check=False, conf=True)
            st.config(nodes[node], "no router bgp", type='vtysh', skip_error_check=False, conf=True)

            config_static(node, 'sonic')
            config_static(node, 'bgp')

    # sleep for 40 seconds for BGP to converge
    st.wait(40)

    yield 'setup_and_teardown'

    with open(dir_path + '/' + V6_VTEP_CONFIG_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp', add=False)
            config_static(node, 'sonic', add=False)


def verify_vtep_state(nodes):
    '''
    root@sonic:/home/cisco# show vxlan remotevtep
    +---------------------+--------------------+-------------------+--------------+
    | SIP                 | DIP                | Creation Source   | OperStatus   |
    +=====================+====================+===================+==============+
    | fd27::22d:b87f:214b | fd27::280:10f1:25f | EVPN              | oper_up      |
    +---------------------+--------------------+-------------------+--------------+
    Total count : 1

    '''
    for node in ['leaf0', 'leaf1']:
        dut = nodes[node]
        expected_sip = LEAF0_VTEP_IP if node == 'leaf0' else LEAF1_VTEP_IP
        expected_dip = LEAF1_VTEP_IP if node == 'leaf0' else LEAF0_VTEP_IP

        output = st.config(dut, "show vxlan remotevtep")
        output_parsed = st.parse_show(dut, "show vxlan remotevtep", output, "show_vxlan_remote.tmpl")

        for vtep in output_parsed:
	    # Test 1: Verify if the State is UP - oper_up
            if vtep['tun_status'] == 'oper_up':
                st.log("Tunnel State is up. Status : oper_up", dut)
            elif vtep['tun_status'] == 'oper_down':
                # Waiting for 10 more seconds for the operational status to come up
                # If not then fail the test
                st.wait(10)
                if vtep['tun_status'] == 'oper_up':
                    st.log("Tunnel State is up. Status : oper_up", dut)
                else:
                    report_fail(dut, msg='Tunnel State is not up. Status : oper_down')
            else:
                report_fail(dut, msg='Tunnel State is not set')

	    # Test 2: Verify SIP and DIP
            if vtep['src_vtep'] == expected_sip:
                st.log("Source vtep validated", dut)
            else:
                report_fail(dut, msg='Source vtep is not as expected. Found {} Expected {}'.format(vtep['src_vtep'], expected_sip))
            if vtep['dst_vtep'] == expected_dip:
                st.log("Destination vtep validated", dut)
            else:
                report_fail(dut, msg='Source vtep is not as expected. Found {} Expected {}'.format(vtep['dst_vtep'], expected_dip))

	    # Test 3: Verify if the Total Count is 1
            if vtep['total_count'] == REMOTE_VTEP_COUNT:
                st.log("All remote VTEPs detected", dut)
            else:
                report_fail(dut, msg='Remote Vteps discovered count not as expected. Found {} Expected {}'.format(vtep['total_count'], REMOTE_VTEP_COUNT))


def test_v6_vtep_basic():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    # Test remote vtep status on LEAF0 and LEAF1
    verify_vtep_state(nodes)
    st.report_pass("test_case_passed", nodes['leaf0'])
    st.report_pass("test_case_passed", nodes['leaf1'])


def test_v6_vtep_delete_add_sonic():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    verify_vtep_state(nodes)

    st.banner("Removing sonic configs on LEAF0")
    test_node = 'leaf0'
    config_static(test_node, 'sonic', add=False)
    st.wait(10)
    config_static(test_node, 'sonic', add=True)
    st.wait(40)
    st.banner("Restored sonic configs on LEAF0")

    verify_vtep_state(nodes)
    st.report_pass("test_case_passed", nodes['leaf0'])
    st.report_pass("test_case_passed", nodes['leaf1'])


def test_v6_vtep_delete_add_bgp():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    verify_vtep_state(nodes)

    st.banner("Removing BGP configs on LEAF1")
    test_node = 'leaf1'
    config_static(test_node, 'bgp', add=False)
    st.wait(10)
    config_static(test_node, 'bgp', add=True)
    st.wait(40)
    st.banner("Restored BGP configs on LEAF1")

    verify_vtep_state(nodes)
    st.report_pass("test_case_passed", nodes['leaf0'])
    st.report_pass("test_case_passed", nodes['leaf1'])


def test_v6_vtep_delete_add_all_configs():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    verify_vtep_state(nodes)

    st.banner("Removed Sonic & BGP configs on LEAF0")
    test_node = 'leaf0'
    config_static(test_node, 'bgp', add=False)
    config_static(test_node, 'sonic', add=False)
    st.wait(10)
    config_static(test_node, 'sonic', add=True)
    config_static(test_node, 'bgp', add=True)
    st.wait(40)
    st.banner("Restored BGP Sonic & configs on LEAF1")

    verify_vtep_state(nodes)
    st.report_pass("test_case_passed", nodes['leaf0'])
    st.report_pass("test_case_passed", nodes['leaf1'])


def test_v6_vtep_port_flap():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    verify_vtep_state(nodes)

    st.banner("Flapping Spine links on LEAF0")
    st.config(nodes['leaf0'], "config interface shutdown Ethernet0")
    st.config(nodes['leaf0'], "config interface shutdown Ethernet16")
    st.wait(10)
    st.config(nodes['leaf0'], "config interface startup Ethernet0")
    st.config(nodes['leaf0'], "config interface startup Ethernet16")
    st.wait(40)
    st.banner("Spine links restored on LEAF0")

    verify_vtep_state(nodes)
    st.report_pass("test_case_passed", nodes['leaf0'])
    st.report_pass("test_case_passed", nodes['leaf1'])


#@pytest.mark.skip(reason="Sometimes the tests fail due to zebra crash, cannot enable till it is fixed")
def test_v6_vtep_multiple_vni():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    verify_vtep_state(nodes)

    l2vni = {'vlan2' : {'vlan' : '2', 'members' : ['Ethernet40'], 'vni' : '2222'},
             'vlan3' : {'vlan' : '3', 'members' : ['Ethernet48'], 'vni' : '3333'},
             'vlan4' : {'vlan' : '4', 'members' : ['Ethernet56'], 'vni' : '4444'}}

    # Start Configuration
    '''
    a. add vlan
    '''
    for _,value in l2vni.items():
        vu.config_vlan(nodes['leaf0'], value['vlan'],  value['members'])
        vu.config_vlan(nodes['leaf1'], value['vlan'],  value['members'])

    '''
    b. add vlan to vni map
    '''
    for _,value in l2vni.items():
        vu.config_vxlan_map(nodes['leaf0'], 'Vtep', value['vni'], vlan=value['vlan'])
        vu.config_vxlan_map(nodes['leaf1'], 'Vtep', value['vni'], vlan=value['vlan'])

    # sleep for 30 seconds for BGP to converge
    st.wait(30)

    verify_vtep_state(nodes)

    leaf0_output = st.show(nodes['leaf0'], 'show bgp l2vpn evpn vni', type='vtysh', skip_tmpl=True, skip_error_check=True)
    leaf0_parsed = st.parse_show(nodes['leaf0'], 'show bgp l2vpn evpn vni', leaf0_output, 'show_bgp_l2vpn_evpn_vni.tmpl')

    leaf1_output = st.show(nodes['leaf1'], 'show bgp l2vpn evpn vni', type='vtysh', skip_tmpl=True, skip_error_check=True)
    leaf1_parsed = st.parse_show(nodes['leaf1'], 'show bgp l2vpn evpn vni', leaf1_output, 'show_bgp_l2vpn_evpn_vni.tmpl')

    vlans = ['2222', '3333', '4444', '2727']
    for path in leaf0_parsed:
        if path['vlan_id'] not in vlans:
            report_fail(nodes['leaf0'], msg='Vlan not found')
        if path['vni_type'] != 'L2':
            report_fail(nodes['leaf0'], msg='Vlan Type is not L2')

    for path in leaf1_parsed:
        if path['vlan_id'] not in vlans:
            report_fail(nodes['leaf1'], msg='Vlan not found')
        if path['vni_type'] != 'L2':
            report_fail(nodes['leaf1'], msg='Vlan Type is not L2')

    '''
    b. remove vlan to vni map
    '''
    for _,value in l2vni.items():
        vu.config_vxlan_map(nodes['leaf0'], 'Vtep', value['vni'], vlan=value['vlan'], add=False)
        vu.config_vxlan_map(nodes['leaf1'], 'Vtep', value['vni'], vlan=value['vlan'], add=False)

    '''
    a. remove vlan
    '''
    for _,value in l2vni.items():
        vu.config_vlan(nodes['leaf0'], value['vlan'],  value['members'], add=False)
        vu.config_vlan(nodes['leaf1'], value['vlan'],  value['members'], add=False)

    st.report_pass('test_case_passed', nodes['leaf0'])
    st.report_pass('test_case_passed', nodes['leaf1'])
