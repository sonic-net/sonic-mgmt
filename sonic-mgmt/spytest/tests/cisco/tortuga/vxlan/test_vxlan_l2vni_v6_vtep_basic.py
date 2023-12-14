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
    output = st.show(dut, "show vxlan remotevtep")
    output_parsed = st.parse_show(dut, "show vxlan remotevtep", output, "show_vxlan_remotevtep.tmpl")

    for vtep in output_parsed:
        # Test 1: Verify if the State is UP - oper_up
        if vtep['tun_status'] == 'oper_up':
            st.log("Tunnel State oper_up UP", dut)
        else:
            st.log("Tunnel State Error: NOT oper_up",dut)
            st.error("Tunnel State Error: NOT oper_up",dut)
            st.report_fail("test_case_failed",dut)

        # Test 2: Verify SIP and DIP
        if vtep['src_vtep'] == expected_sip:
            st.log("Source vtep validated", dut)
        else:
            st.log("Source vtep expected {} found {} ".format(expected_sip, vtep['src_vtep']), dut)
            st.error("Source vtep expected {} found {} ".format(expected_sip, vtep['src_vtep']), dut)
            st.report_fail("test_case_failed",dut)

        if vtep['dst_vtep'] == expected_dip:
            st.log("Destination vtep validated", dut)
        else:
            st.log("Destination vtep expected {} found {} ".format(expected_dip, vtep['dst_vtep']), dut)
            st.error("Destination vtep expected {} found {} ".format(expected_dip, vtep['dst_vtep']), dut)
            st.report_fail("test_case_failed",dut)

        # Test 3: Verify if the Total Count is 1
        if vtep['total_count'] == 1:
            st.log("All remote VTEPs detected", dut)
        else:
            st.log("All remote VTEPs have not been discovered. Discovered {} VTEPs".format(vtep['total_count']), dut)
            st.error("All remote VTEPs have not been discovered. Discovered {} VTEPs".format(vtep['total_count']), dut)
            st.report_fail("test_case_failed",dut)


def setup_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)
    st.wait(2)

def cleanup_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)
    st.wait(2)

@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_v6_vtep_basic():
    vars   = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0']  = vars.D1
    nodes['leaf1']  = vars.D2
    nodes['spine0'] = vars.D3
    nodes['spine1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(dir_path + '/' + V6_VTEP_CONFIG_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            setup_node(nodes[node], config['sonic'], '')
            st.wait(10)
            setup_node(nodes[node], config['bgp'], 'vtysh')
            st.wait(10)

    st.wait(30)
    verify_vtep_state(nodes['leaf0'], LEAF0_VTEP_IP, LEAF1_VTEP_IP)
    st.report_pass("VTEP check on LEAF0 passed", dut)

    verify_vtep_state(nodes['leaf1'], LEAF1_VTEP_IP, LEAF0_VTEP_IP)
    st.report_pass("VTEP check on LEAF1 passed", dut)
