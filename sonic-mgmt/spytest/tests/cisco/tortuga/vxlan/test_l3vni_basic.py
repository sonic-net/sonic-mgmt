import os
import yaml
import pytest
from spytest import st
import apis.routing.bgp as bgpapi

pytest.fixture(scope="module", autouse=True)
def box_service_module_hooks(request):
    global vars
    global dut_list
    vars = st.ensure_min_topology("D1D3:1",  "D1D4:1", "D2D3:1",  "D2D4:1")
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]
    yield

@pytest.fixture(scope="function", autouse=True)
def box_service_func_hooks(request):
    yield

CONFIGS_FILE = 'vxlan_l3vni_configs.yaml'

def setup_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass

####################
#                  #
#    D1 = Leaf0    #
#    D2 = Leaf1    #
#    D3 = Spine0   #
#    D4 = Spine1   #
#                  #
####################

####################################################################
#                                                                  #
#   leaf0.Ethernet0-11.11.11.2  ---- spine0.Ethernet0-11.11.11.1   #
#   leaf1.Ethernet12-11.11.12.2 ---- spine0.Ethernet8-11.11.12.1   #
#                                                                  #
####################################################################
def test_l3vni_basic_config():

    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D1
    nodes['leaf1'] = vars.D2
    nodes['spine0'] = vars.D3
    nodes['spine1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(dir_path + '/' + CONFIGS_FILE) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            setup_node(nodes[node], config['sonic'], '')
            setup_node(nodes[node], config['bgp'], 'vtysh')

    count = 5
    st.show(nodes['leaf0'], "sudo ping -c {} {} -q".format(count, '11.11.11.1'))
    st.show(nodes['leaf1'], "sudo ping -c {} {} -q".format(count, '11.11.12.1'))

    
    st.report_pass("test_case_passed")
