import os
import yaml
import pytest
from spytest import st, utils
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

'''
Example on how to take a copy of config within the dut - Also on how to execute commands on DUT
st.upload_file_to_dut(dut, file_path, "/tmp/00-copp.config.json")
command = "sudo cp /tmp/00-copp.config.json /etc/sonic/copp_config.json"
st.config(dut, command)

'''

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

CONFIGS_FILE = 'base_config.yaml'
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
