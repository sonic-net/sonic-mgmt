import os
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import apis.routing.vrf as vrf_obj
import vxlan_utils as vxlan_obj

##
## config: eBGP + ECMP
##  Topology : 2x Spine + 2 Leafs
##
##  SD1 -- Spine0  - D1
##  SD2 -- Spine1  - D2
##  SD3 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4
##  T1  -- SPT
##
##  SPT data0 (tp1) --- SD3 ------ SD4 --- SPT data1 (tp3)
##  SPT data2 (tp2) --- SD3 ------ SD4 --- SPT data3 (tp4)
##  tp1: SPT data0
##  tp2: SPT data1
##  tp3: SPT data2
##  tp4: SPT data3

data = SpyTestDict()
#### Config template file ####
CONFIGS_FILE = "vxlan_l2vni_sag_irg_config_template.yaml"

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
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "2000"
        data.rate_percent = "10"
        data.circuit_endpoint_type = "ipv4"
        data.frame_size = "1000"
    yield 
    
## Tgen Stream Config
data.d3tp1_ip_addr = "100.200.200.1"
data.tp1d3_ip_addr = "100.200.200.2"
data.tp1d3_mac_addr = "00:0a:01:00:11:01"

data.d4tp2_ip_addr = "100.200.200.1"
data.tp2d4_ip_addr = "100.200.200.3"
data.tp2d4_mac_addr = "00:0a:01:00:12:01"

data.d3tp3_ip_addr = "200.200.200.1"
data.tp3d3_ip_addr = "200.200.200.2"
data.tp3d3_mac_addr = "00:0a:01:00:11:02"

data.d4tp4_ip_addr = "200.200.200.1"
data.tp4d4_ip_addr = "200.200.200.3"
data.tp4d4_mac_addr = "00:0a:01:00:12:02"

LEAF0_VXLAN_IP = '10.200.200.200'
LEAF1_VXLAN_IP = '10.200.200.201'

####################
@pytest.fixture()
def setup_teardown_l2vni_sag():
    vars = st.get_testbed_vars()
    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
        st.wait(60)
    # Make sure links are up by pinging, sometimes packet exchange doesn't happen on sim till pings are initiated
    count = 5
    st.show('leaf0', 'sudo ping -c {} {} -q'.format(count, '10.200.200.201'), skip_tmpl=True, skip_error_check=True)
    st.show('leaf1', 'sudo ping -c {} {} -q'.format(count, '10.200.200.200'), skip_tmpl=True, skip_error_check=True)

    yield 'setup_teardown_l2vni_sag'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)
            st.wait(2)
    #router_preconfig_cleanup()
    ### Remove the temp config file after the test ###
    vxlan_obj.remove_temp_config(updated_config_file)
    
def test_l2vni_sym_irb_sag_with_traffic(setup_teardown_l2vni_sag, traffic_setup):
    
    st.banner("Start to test sag with ping and traffic")
    
    ## Verify Vtep state
    vxlan_obj.verify_vtep_state({"LEAF0_VXLAN_IP":LEAF0_VXLAN_IP,"LEAF1_VXLAN_IP":LEAF1_VXLAN_IP})
    ## Run Traffic: Bi-directional Burst of 100 Packets
    result = vxlan_obj.check_traffic(traffic_setup)
	
    if result:
        st.report_pass("test_case_passed", "test_l2vni_sym_irb_sag_with_traffic passed")
    else:
        st.report_fail("test_case_failed", "test_l2vni_sym_irb_sag_with_traffic failed")

@pytest.fixture(scope="function")
def traffic_setup():
    ### Config tgen interface and get tg handle, port handle and interface handles ###
    int_dict = {"T1D3P1": {"host_ip": data.tp1d3_ip_addr, "gateway": data.d3tp1_ip_addr, "mac" : data.tp1d3_mac_addr }, 
                "T1D3P2" : {"host_ip": data.tp3d3_ip_addr, "gateway": data.d3tp3_ip_addr, "mac" : data.tp3d3_mac_addr },
                "T1D4P1": {"host_ip": data.tp2d4_ip_addr, "gateway": data.d4tp2_ip_addr, "mac" : data.tp2d4_mac_addr},
                "T1D4P2": {"host_ip": data.tp4d4_ip_addr, "gateway": data.d4tp4_ip_addr, "mac" :data.tp4d4_mac_addr}}
    handles = vxlan_obj.config_tgen_interface(int_dict)
    ### Generate Traffic item and Ping test , get tg handle, stream id and port handles ###
    # T1D3P1 --- l2vni --- T1D4P1
    # T1D3P2 --- l2vni --- T1D4P2
    # T1D3P1 --- SAG + vrf + SAG ---T1D3P2
    # T1D3P1 --- SAG + L3VNI +SAG ---T1D4P2
    # T1D3P2 --- SAG + L3VNI +SAG ---T1D4P1
    stream_list = [("T1D3P1","T1D4P1"), ("T1D3P1", "T1D3P2"),("T1D3P1", "T1D4P2"),("T1D3P2", "T1D4P2"),("T1D3P2", "T1D4P1")]
    streams = vxlan_obj.config_traffic_item(stream_list, handles, int_dict, data, ping=False)
    yield streams

def router_preconfig_cleanup():
    vrf_obj.clear_vrf_configuration(st.get_dut_names())
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=True, conf=True)
    else:
        st.config(node, config, skip_error_check=True, conf=True)

def config_static(node, config_domain, add=True):
    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(node, config_list[node][config_domain]['config'], domain)
        else:
            config_node(node, config_list[node][config_domain]['deconfig'], domain)

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)
