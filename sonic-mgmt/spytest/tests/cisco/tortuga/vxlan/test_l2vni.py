import os
import yaml
import pytest

from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import vxlan_utils as vxlan_obj

##
## config: eBGP + ECMP
##  Topology : 2x Spine + 2 Leafs
##
##  SD1 -- Spine0  - D1
##  SD1 -- Spine1  - D2
##  SD2 -- Leaf0   - D3
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
        data.pkts_per_burst = "100"
        ### Using lower line rate for SIM tgen ###
        data.rate_percent = "0.005"
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

data.d3t1_ip_addr = "1.1.1.3"
data.t1d3_ip_addr = "1.1.1.2"
data.t1d3_mac_addr = "00:0a:01:00:11:01"

data.d4t1_ip_addr = "1.1.1.2"
data.t1d4_ip_addr = "1.1.1.3"
data.t1d4_mac_addr = "00:0a:01:00:12:01"

CONFIGS_FILE = 'vxlan_l2vni_config_template.yaml'
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

    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)

def router_preconfig_cleanup():
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())

@pytest.fixture(scope="module", autouse=True)
def vxlan_config_hooks():
    global handles
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
    st.wait(60)
    ###Get TGEN Handles ###
    handles = vxlan_obj.tgen_preconfig({"src_endpoint": {"port" : "T1D3P1", "host_ip": data.t1d3_ip_addr, "gateway": data.d3t1_ip_addr, "mac" : data.t1d3_mac_addr }, 
                                        "dst_endpoint" : {"port" : "T1D4P1","host_ip": data.t1d4_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4_mac_addr }},
                                        "raw",data)
    if handles == False:
        st.report_fail('tgen preconfig failed')
    yield vxlan_config_hooks

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)
    #router_preconfig_cleanup()
    vxlan_obj.remove_temp_config(updated_config_file)
    
def test_l2vni_vtep_setup ():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    vxlan_obj.verify_vtep_state({"LEAF0_VXLAN_IP":LEAF0_VXLAN_IP,"LEAF1_VXLAN_IP":LEAF1_VXLAN_IP})
    result = run_traffic_test(handles)
    if result:
        st.report_pass('test_case_passed')  
    else:
        st.log("one or more traffic test failed")
        st.report_fail('test_case_failed')
        
#Skipping for now till we fix the traffic failure issue after vtep add and del 
def test_l2vni_vtep_delete_add ():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    vxlan_obj.verify_vtep_state({"LEAF0_VXLAN_IP":LEAF0_VXLAN_IP,"LEAF1_VXLAN_IP":LEAF1_VXLAN_IP})

    test_node = 'leaf0'
    config_static(test_node, 'bgp', add=False)
    config_static(test_node, 'sonic', add=False)
    st.wait(10)
    config_static(test_node, 'sonic', add=True)
    config_static(test_node, 'bgp', add=True)
   
    st.wait(60)

    vxlan_obj.verify_vtep_state({"LEAF0_VXLAN_IP":LEAF0_VXLAN_IP,"LEAF1_VXLAN_IP":LEAF1_VXLAN_IP})
    result = run_traffic_test(handles)
    if result:
        st.report_pass('test_case_passed')  
    else:
        st.log("one or more traffic test failed")
        st.report_fail('test_case_failed')

def clear_counters():
    for dut in st.get_dut_names():
        if "leaf" in dut:
            st.config(dut, " sonic-clear counters")
            st.config(dut, " sonic-clear tunnelcounters")

def run_traffic_test(handles):
    # traffic test
    flag = False
    for item in ['unicast', "broadcast", "unknownunicast", "multicast"]:
        clear_counters()
        get_cli_out()
        result = vxlan_obj.traffic_test_burst(item,handles) 
        st.wait(5)
        get_cli_out()
        if result:
            st.banner("{} traffic test passed".format(item))
            flag = True
        else:
            st.banner("{} traffic test failed".format(item))
            flag = False
    return flag

def get_cli_out():
    cmds = ["show mac", "show arp", "show int counters", "show vxlan counters"]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            for item in cmds:
                output = st.config(dut, item)
                st.log(output)

    
    
