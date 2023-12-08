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

V6_VTEP_CONFIG_FILE = 'vxlan_l2vni_v6_vtep_configs.yaml'

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


def verify_vtep_state (_dut_list):
    '''
    root@sonic:/home/cisco# show vxlan remotevtep
    +---------------------+--------------------+-------------------+--------------+
    | SIP                 | DIP                | Creation Source   | OperStatus   |
    +=====================+====================+===================+==============+
    | fd27::22d:b87f:214b | fd27::280:10f1:25f | EVPN              | oper_up      |
    +---------------------+--------------------+-------------------+--------------+
    Total count : 1
    '''
    for _dut in _dut_list:
        output = st.config(_dut, "show vxlan remotevtep | grep oper_up")
        st.wait(2)
        st.log(output,_dut)

        # Test 1: Verify if the State is UP - oper_up
        if "EVPN" in str(output.encode('ascii','ignore')):
            st.log("EVPN State oper_up UP", _dut)
        else:
            st.log("EVPN State Error: NOT oper_up",_dut)
            st.error("EVPN State Error: NOT oper_up",_dut)
            st.report_fail("test_case_failed",_dut)
        st.report_pass("Tunnel State Check : test_case_passed", _dut)

        # Test 2: Verify if the Total Count is 1
        output = st.config(_dut, "show vxlan remotevtep | grep 'Total count :'")
        st.wait(2)
        st.log(output,_dut)

        #remote_vtep_count = int(re.search(r'Total count : (\d+)', str(output.encode('ascii','ignore'))).group(1))
        if '1' in str(output.encode('ascii','ignore')):
            st.log("All remote VTEPs detected", _dut)
        else:
            st.error("All remote VTEPs have not been discovered. Discovered 1 VTEPs", _dut)
            st.report_fail("test_case_failed",_dut)
        st.report_pass("Tunnel Count Check : test_case_passed", _dut)


def setup_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

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
            if 'host' not in node:
                setup_node(nodes[node], config['bgp'], 'vtysh')

    # Test1-3 : Verify Vtep State for L0 and L1
    leaf_nodes = [nodes['leaf0'], nodes['leaf1']]
    verify_vtep_state(leaf_nodes)

    # Configurations Clean up
    for dut in dut_list:
        st.clear_config(dut)
        st.wait(20)
