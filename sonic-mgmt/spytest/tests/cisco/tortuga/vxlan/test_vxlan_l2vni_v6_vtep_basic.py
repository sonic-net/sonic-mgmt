import os
import yaml
import pytest
from spytest import st
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

V6_VTEP_CONFIG_FILE = 'vxlan_v6_vtep_configs.yaml'

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
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain,  skip_errors=True)


@pytest.fixture()
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

            config_static(node, 'sonic')
            config_static(node, 'bgp')

    yield 'setup_and_teardown'

    with open(dir_path + '/' + V6_VTEP_CONFIG_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp', add=False)
            config_static(node, 'sonic', add=False)


def verify_vtep_state(dut, expected_sip, expected_dip):
    '''
    root@sonic:/home/cisco# show vxlan remotevtep
    +---------------------+--------------------+-------------------+--------------+
    | SIP                 | DIP                | Creation Source   | OperStatus   |
    +=====================+====================+===================+==============+
    | fd27::22d:b87f:214b | fd27::280:10f1:25f | EVPN              | oper_up      |
    +---------------------+--------------------+-------------------+--------------+
    Total count : 1

    '''
    output = st.config(dut, "show vxlan remotevtep")
    output_parsed = st.parse_show(dut, "show vxlan remotevtep", output, "show_vxlan_remote.tmpl")

    for vtep in output_parsed:
        # Test 1: Verify if the State is UP - oper_up
        if vtep['tun_status'] == 'oper_up':
            st.log("Tunnel State is up. Status : oper_up", dut)
        else:
            report_fail(dut, msg='Tunnel State is not up. Status : oper_down')

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


@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_v6_vtep_basic(setup_and_teardown):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    # sleep for 40 seconds for BGP to converge
    st.wait(40)

    # Test remote vtep status on LEAF0
    verify_vtep_state(nodes['leaf0'], LEAF0_VTEP_IP, LEAF1_VTEP_IP)
    st.report_pass("test_case_passed", "for leaf0")

    # Test remote vtep status on LEAF1
    verify_vtep_state(nodes['leaf1'], LEAF1_VTEP_IP, LEAF0_VTEP_IP)
    st.report_pass("test_case_passed", "for leaf1")
