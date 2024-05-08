import os
import yaml
import pytest

from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import vxlan_utils as vxlan_obj

##
##  Topology : 1 Spine(D1) + 1 Leaf(D3)
##
##  SD1 -- Spine0  - D1
##  SD2 -- Spine1  - D2
##  SD3 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4
##

## tgen Stream Config
data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def initial_setup():
    vars = st.get_testbed_vars()
    ### Check dut is HW or SIM ###
    dut_type = vxlan_obj.check_hw_or_sim(st.get_dut_names()[0])

    if  dut_type == "sim":
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "500"
        ### Using lower line rate for SIM tgen ###
        data.rate_percent = "0.01"
        data.circuit_endpoint_type = "ipv4"
        data.frame_size = "100"
    else:
        data.mode ="create"
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "2000"
        data.rate_percent = "10"
        data.circuit_endpoint_type = "ipv4"
        data.frame_size = "1000"
    yield
    st.log("Module config done")


data.d3t1p1_ip_addr = "100.100.100.101"
data.t1d3p1_ip_addr = "100.100.100.100"
data.t1d3p1_mac_addr = "00:0a:01:00:11:01"

data.d3t1p2_ip_addr = "100.100.200.101"
data.t1d3p2_ip_addr = "100.100.200.100"
data.t1d3p2_mac_addr = "00:0a:01:00:12:01"

CONFIGS_FILE = 'test_subint_basic_template.yaml'

subint_id1 = ".10"
subint_id2 = ".20"
subint_vlan1 = "10"
subint_vlan2 = "20"
subint_prefix1 = "100.100.100.101/24"
subint_prefix2 = "100.100.200.101/24"
subint_ip1 = "100.100.100.100"
subint_ip2 = "100.100.200.100"


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

    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)


def config_subint(node, add=True):
    vars = st.get_testbed_vars()

    idx_rm = vars.D1D3P1.index("ernet")
    short_name = vars.D1D3P1[:idx_rm] + vars.D1D3P1[idx_rm + len("ernet"):]

    if add:
        st.config(node, "config subinterface add {}{} {}".format(short_name, subint_id1, subint_vlan1))
        st.config(node, "config subinterface add {}{} {}".format(short_name, subint_id2, subint_vlan2))
        st.config(node, "config interface ip add {}{} {}".format(short_name, subint_id1, subint_prefix1))
        st.config(node, "config interface ip add {}{} {}".format(short_name, subint_id2, subint_prefix2))
    else:
        st.config(node, "config interface ip remove {}{} {}".format(short_name, subint_id2, subint_prefix2))
        st.config(node, "config interface ip remove {}{} {}".format(short_name, subint_id1, subint_prefix1))
        st.config(node, "config subinterface del {}{}".format(short_name, subint_id2))
        st.config(node, "config subinterface del {}{}".format(short_name, subint_id1))


def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)


def router_preconfig_cleanup():
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())


@pytest.fixture(scope="module", autouse=True)
def subint_config_hooks():
    global handles
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    config_subint(vars.D1)

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'sonic')
            st.wait(2)

    yield subint_config_hooks

    config_subint(vars.D1, add=False)

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            config_static(node, 'sonic', add=False)
            st.wait(2)

    #router_preconfig_cleanup()
    vxlan_obj.remove_temp_config(updated_config_file)
    
    
def run_subint_ping_test():

    st.wait(30)
    ###Get TGEN Handles ###
    handles = vxlan_obj.tgen_preconfig({"src_endpoint": {"port" : "T1D3P1", "host_ip": data.t1d3p1_ip_addr, "gateway": data.d3t1p1_ip_addr, "mac" : data.t1d3p1_mac_addr }, 
                                        "dst_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d3t1p2_ip_addr, "mac" : data.t1d3p2_mac_addr }},
                                        "raw",data)
    if handles == False:
        st.report_fail('tgen1 subint ping failed')

    st.wait(30)
    ###Get TGEN Handles ###
    handles = vxlan_obj.tgen_preconfig({"src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d3t1p2_ip_addr, "mac" : data.t1d3p2_mac_addr }, 
                                        "dst_endpoint": {"port" : "T1D3P1", "host_ip": data.t1d3p1_ip_addr, "gateway": data.d3t1p1_ip_addr, "mac" : data.t1d3p1_mac_addr }},
                                        "raw",data)
    
    if handles == False:
        st.report_fail('tgen2 subint ping failed')
    else:
        st.report_pass('test_case_passed')  
    
    
def test_l2vni_subint_basic():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    run_subint_ping_test()
    

def test_l2vni_subint_delete_add():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    test_node = 'spine0'
    config_subint(vars.D1, add=False)
    config_static(test_node, 'sonic', add=False)

    st.wait(10)
    config_subint(vars.D1)
    config_static(test_node, 'sonic', add=True)
   
    run_subint_ping_test()


