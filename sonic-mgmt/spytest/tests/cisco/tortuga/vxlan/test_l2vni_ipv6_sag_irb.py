import os
import yaml
import pytest

from spytest import st, tgapi, SpyTestDict

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
##  SPT data0 (tp1) --- SD3 ------ SD4 --- SPT data1 (tp2)
##  SPT data2 (tp3) --- SD3 ------ SD4 --- SPT data3 (tp4)
##  tp1: SPT data0
##  tp2: SPT data1
##  tp3: SPT data2
##  tp4: SPT data3

## Spirent Stream Config
data = SpyTestDict()
data.my_dut_list = None
data.local = None
data.remote = None

#Tgen Stream Config
data.d3tp1_ip6_addr = "2002:db8:1::1"
data.tp1d3_ip6_addr = "2002:db8:1::2"
data.tp1d3_mac_addr = "00:0a:01:00:11:01"

data.d4tp2_ip6_addr = "2002:db8:1::1"
data.tp2d4_ip6_addr = "2002:db8:1::3"
data.tp2d4_mac_addr = "00:0a:01:00:12:01"

data.d3tp3_ip6_addr = "2003:db8:1::1"
data.tp3d3_ip6_addr = "2003:db8:1::2"
data.tp3d3_mac_addr = "00:0a:01:00:11:02"

data.d4tp4_ip6_addr = "2003:db8:1::1"
data.tp4d4_ip6_addr = "2003:db8:1::3"
data.tp4d4_mac_addr = "00:0a:01:00:12:02"

LEAF0_VXLAN_IP = '2001:db8:1::1'
LEAF1_VXLAN_IP = '2001:db8:1::3'

SAG1_VLAN = '3'
SAG2_VLAN = '4'

SAG_MAC = "00:11:22:33:44:55"
SAG1_IP = data.d3tp3_ip6_addr
SAG2_IP = data.d3tp1_ip6_addr
VRF_NAME = "Vrf43"
VRF_VLAN = "43"
VRF_VNI = "5043"

data.pkts_per_burst = "500"
data.mask = "24"
data.counters_threshold = 10
data.tgen_stats_threshold = 20
data.tgen_rate_pps = '100'
data.tgen_l3_len = '500'
data.traffic_run_time = 20
data.clear_parallel = True
data.transmit_mode = "single_burst"
data.rate_percent = "0.01"
data.circuit_endpoint_type = "ipv6"
data.frame_size = "100"
data.vlan_id = "100"

CONFIGS_FILE = 'vxlan_l2vni_ipv6_sag_irb_configs.yaml'

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
            if 'deconfig2' in config_list[node][config_domain]:
                st.wait(5)
                config_node(node, config_list[node][config_domain]['deconfig2'], domain)

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)

####################
@pytest.fixture(scope="module", autouse=True)
def setup_teardown_l2vni_sag():
    vars = st.get_testbed_vars()
    global updated_config_file
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            '''
            #Check if its needed
            # Disabling drake so that there are no automatic underlay configs
            st.config(nodes[node], "systemctl stop drake", skip_error_check=False, conf=True)
            st.config(nodes[node], "no router bgp", type='vtysh', skip_error_check=False, conf=True)
            '''
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
            st.wait(2)
 
    #Make sure links are up by pinging, sometimes packet exchange doesn't happen on sim till pings are initiated
    st.wait(5)
    count = 5
    st.show(nodes['leaf0'], 'sudo ping -c {} {} -q'.format(count, LEAF1_VXLAN_IP), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['leaf1'], 'sudo ping -c {} {} -q'.format(count, LEAF0_VXLAN_IP), skip_tmpl=True, skip_error_check=True)
    
    yield 'setup_teardown_l2vni_sag'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)
            st.wait(2)
    
    ### Remove the temp config file after the test ###
    vxlan_obj.remove_temp_config(updated_config_file)

def traffic_setup():
    global handles
    ### Config tgen interface and get tg handle, port handle and interface handles ###
    int_dict = {"T1D3P1": {"host_ip": data.tp1d3_ip6_addr, "gateway": data.d3tp1_ip6_addr, "mac" : data.tp1d3_mac_addr },
                "T1D3P2" : {"host_ip": data.tp3d3_ip6_addr, "gateway": data.d3tp3_ip6_addr, "mac" : data.tp3d3_mac_addr },
                "T1D4P1": {"host_ip": data.tp2d4_ip6_addr, "gateway": data.d4tp2_ip6_addr, "mac" : data.tp2d4_mac_addr},
                "T1D4P2": {"host_ip": data.tp4d4_ip6_addr, "gateway": data.d4tp4_ip6_addr, "mac" :data.tp4d4_mac_addr}}
    handles = vxlan_obj.config_tgen_interface(int_dict, 'ipv6')
    ### Generate Traffic item and Ping test , get tg handle, stream id and port handles ###
    # T1D3P1 --- l2vni --- T1D4P1
    # T1D3P2 --- l2vni --- T1D4P2
    # T1D3P1 --- SAG + vrf + SAG ---T1D3P2
    # T1D3P1 --- SAG + L3VNI +SAG ---T1D4P2
    # T1D3P2 --- SAG + L3VNI +SAG ---T1D4P1
    stream_list = [("T1D3P1","T1D4P1"), ("T1D3P1", "T1D3P2"),("T1D3P1", "T1D4P2"),("T1D3P2", "T1D4P2"),("T1D3P2", "T1D4P1")]
    streams = vxlan_obj.config_traffic_item(stream_list, handles, int_dict, data, ping=True)
    return streams, handles

def traffic_cleanup(streams, handles):
    int_dict = {"T1D3P1": {"host_ip": data.tp1d3_ip6_addr, "gateway": data.d3tp1_ip6_addr, "mac" : data.tp1d3_mac_addr },
                "T1D3P2" : {"host_ip": data.tp3d3_ip6_addr, "gateway": data.d3tp3_ip6_addr, "mac" : data.tp3d3_mac_addr },
                "T1D4P1": {"host_ip": data.tp2d4_ip6_addr, "gateway": data.d4tp2_ip6_addr, "mac" : data.tp2d4_mac_addr},
                "T1D4P2": {"host_ip": data.tp4d4_ip6_addr, "gateway": data.d4tp4_ip6_addr, "mac" :data.tp4d4_mac_addr}}

    vxlan_obj.cleanup_traffic(int_dict, streams, handles)

def test_l2vni_ipv6_sym_irb_sag_with_traffic():

    st.banner("Start to test sag with ping and traffic")
    streams, handles = traffic_setup()
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2 
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP)

    ## Run Traffic: Bi-directional Ping and Burst of 500 Packets
    result = vxlan_obj.check_traffic(streams, timeout=10)
    traffic_cleanup(streams, handles)

    if result:
	st.report_pass('test_case_passed', 'test_l2vni_ipv6_sym_irb_sag_with_traffic')
    else:
	st.report_fail('test_case_failed', 'test_l2vni_ipv6_sym_irb_sag_with_traffic')

def test_l2vni_ipv6_sym_irb_sag_change_ip():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    st.banner("Start to test sag ip change")

    ## Verify Vtep state
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP)

    '''
    remove existed SAG IP
    '''
    st.config(nodes['leaf0'], 'sudo config interface ip rem {} {}/24'.format('Vlan' + SAG1_VLAN, SAG1_IP))
    st.config(nodes['leaf1'], 'sudo config interface ip rem {} {}/24'.format('Vlan' + SAG1_VLAN, SAG1_IP))

    '''
    change to new SAG IP
    '''
    old_sag1_ip = data.d3tp3_ip6_addr
    new_sag_ip = "2003:db8:1::10"
    st.config(nodes['leaf0'], 'sudo config interface ip add {} {}/24'.format('Vlan' + SAG1_VLAN, new_sag_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip add {} {}/24'.format('Vlan' + SAG1_VLAN, new_sag_ip))

    data.d3tp3_ip6_addr = new_sag_ip
    data.d4tp4_ip6_addr = new_sag_ip
    streams, handles = traffic_setup()

    ## Verify Vtep state
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP)

    ## Run Traffic: Bi-directional Ping and Burst of 500 Packets
    result = vxlan_obj.check_traffic(streams, timeout=10)
    traffic_cleanup(streams, handles)

    ## recover SAG ip
    data.d3tp3_ip6_addr = old_sag1_ip
    data.d4tp4_ip6_addr = old_sag1_ip
    '''
    remove SAG IP
    '''
    st.config(nodes['leaf0'], 'sudo config interface ip rem {} {}/24'.format('Vlan' + SAG1_VLAN, new_sag_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip rem {} {}/24'.format('Vlan' + SAG1_VLAN, new_sag_ip))

    '''
    recover to old SAG IP
    '''
    st.config(nodes['leaf0'], 'sudo config interface ip add {} {}/24'.format('Vlan' + SAG1_VLAN, old_sag1_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip add {} {}/24'.format('Vlan' + SAG1_VLAN, old_sag1_ip))

    if result:
        st.report_pass("test_case_passed", "test_l2vni_ipv6_sym_irb_sag_change_ip passed")
    else:
        st.report_fail("test_case_failed", "test_l2vni_ipv6_sym_irb_sag_change_ip failed")

def test_l2vni_ipv6_sym_irb_sag_change_mac():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    st.banner("Start to test sag mac change")

    ## Verify Vtep state
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP)    

    '''
    remove SAG MAC
    '''
    st.config(nodes['leaf0'], 'sudo config static-anycast-gateway mac_address del')
    st.config(nodes['leaf1'], 'sudo config static-anycast-gateway mac_address del')

    '''
    add new SAG MAC
    '''
    new_sag_mac = "00:22:44:66:88:99"
    st.config(nodes['leaf0'], 'sudo config static-anycast-gateway mac_address add {}'.format(new_sag_mac))
    st.config(nodes['leaf1'], 'sudo config static-anycast-gateway mac_address add {}'.format(new_sag_mac))

    streams, handles = traffic_setup()

    ## Verify Vtep state
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP)
    ## Run Traffic: Bi-directional Burst of 100 Packets
    result = vxlan_obj.check_traffic(streams, timeout=10)

    traffic_cleanup(streams, handles)

    '''
    remove SAG MAC
    '''
    st.config(nodes['leaf0'], 'sudo config static-anycast-gateway mac_address del')
    st.config(nodes['leaf1'], 'sudo config static-anycast-gateway mac_address del')

    '''
    recover SAG MAC
    '''
    st.config(nodes['leaf0'], 'sudo config static-anycast-gateway mac_address add {}'.format(SAG_MAC))
    st.config(nodes['leaf1'], 'sudo config static-anycast-gateway mac_address add {}'.format(SAG_MAC))

    if result:
        st.report_pass("test_case_passed", "test_l2vni_ipv6_sym_irb_sag_change_mac passed")
    else:
        st.report_fail("test_case_failed", "test_l2vni_ipv6_sym_irb_sag_change_mac failed")

def test_l2vni_ipv6_sym_irb_sag_unbind_vrf():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    st.banner("Start to test unbind vrf")

    ## Verify Vtep state
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP)

    '''
    unbind vlan from vrf
    '''
    st.config(nodes['leaf0'], 'sudo config interface vrf unbind {}'.format('Vlan' + SAG1_VLAN))
    st.config(nodes['leaf0'], 'sudo config interface vrf unbind {}'.format('Vlan' + SAG2_VLAN))
    st.config(nodes['leaf1'], 'sudo config interface vrf unbind {}'.format('Vlan' + SAG1_VLAN))
    st.config(nodes['leaf1'], 'sudo config interface vrf unbind {}'.format('Vlan' + SAG2_VLAN))

    st.wait(2)
    '''
    Remove VRF
    a. Remove all config from FRR
    b. Remove from SONiC
    '''
    config_static(nodes['leaf0'], 'bgp', add=False)
    st.config(nodes['leaf0'], 'sudo config vrf del {}'.format(VRF_NAME))

    config_static(nodes['leaf1'], 'bgp', add=False)
    st.config(nodes['leaf1'], 'sudo config vrf del {}'.format(VRF_NAME))

    st.wait(2)

    '''
    Add VRF
    a. Add in SONiC
    b. Add all config in FRR
    '''
    config_static(nodes['leaf0'], 'bgp')
    st.config(nodes['leaf0'], 'sudo config vrf add {}'.format(VRF_NAME))

    config_static(nodes['leaf1'], 'bgp')
    st.config(nodes['leaf1'], 'sudo config vrf add {}'.format(VRF_NAME))

    '''
    re-bind vlan to vrf
    '''
    st.config(nodes['leaf0'], 'sudo config interface vrf bind {} {}'.format('Vlan' + SAG1_VLAN, VRF_NAME))
    st.config(nodes['leaf0'], 'sudo config interface vrf bind {} {}'.format('Vlan' + SAG2_VLAN, VRF_NAME))
    st.config(nodes['leaf1'], 'sudo config interface vrf bind {} {}'.format('Vlan' + SAG1_VLAN, VRF_NAME))
    st.config(nodes['leaf1'], 'sudo config interface vrf bind {} {}'.format('Vlan' + SAG2_VLAN, VRF_NAME))

    st.config(nodes['leaf0'], 'sudo config interface vrf bind {} {}'.format('Vlan' + VRF_VLAN, VRF_NAME))
    st.config(nodes['leaf1'], 'sudo config interface vrf bind {} {}'.format('Vlan' + VRF_VLAN, VRF_NAME))
    '''
    re-config vrf to vni map
    '''
    st.config(nodes['leaf0'], 'sudo config vrf add_vrf_vni_map {} {}'.format(VRF_NAME, VRF_VNI))
    st.config(nodes['leaf1'], 'sudo config vrf add_vrf_vni_map {} {}'.format(VRF_NAME, VRF_VNI))

    '''
    re-config SAG IP
    '''
    st.config(nodes['leaf0'], 'sudo config interface ip add {} {}/24'.format('Vlan' + SAG1_VLAN, data.d3tp3_ip6_addr))
    st.config(nodes['leaf1'], 'sudo config interface ip add {} {}/24'.format('Vlan' + SAG1_VLAN, data.d4tp4_ip6_addr))

    st.config(nodes['leaf0'], 'sudo config interface ip add {} {}/24'.format('Vlan' + SAG2_VLAN, data.d3tp1_ip6_addr))
    st.config(nodes['leaf1'], 'sudo config interface ip add {} {}/24'.format('Vlan' + SAG2_VLAN, data.d4tp2_ip6_addr))

    '''
    re-enable SAG
    '''
    st.config(nodes['leaf0'], 'sudo config vlan static-anycast-gateway enable {}'.format(SAG1_VLAN))
    st.config(nodes['leaf1'], 'sudo config vlan static-anycast-gateway enable {}'.format(SAG1_VLAN))

    st.config(nodes['leaf0'], 'sudo config vlan static-anycast-gateway enable {}'.format(SAG2_VLAN))
    st.config(nodes['leaf1'], 'sudo config vlan static-anycast-gateway enable {}'.format(SAG2_VLAN))

    streams, handles = traffic_setup()

    ## Verify Vtep state
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP)

    ## Run Traffic: Bi-directional Burst of 100 Packets
    result = vxlan_obj.check_traffic(streams, timeout=10)

    traffic_cleanup(streams, handles)

    if result:
        st.report_pass("test_case_passed", "test_l2vni_ipv6_sym_irb_sag_unbind_vrf passed")
    else:
        st.report_fail("test_case_failed", "test_l2vni_ipv6_sym_irb_sag_unbind_vrf failed")

def test_l2vni_ipv6_sym_irb_sag_del_add_vlan_member():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    st.banner("Start to test remove/add vlan member")

    ## Verify Vtep state
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP)

    leaf0_vlan_member = vxlan_obj.get_replacement(vars, "D3T1P2")
    leaf1_vlan_member = vxlan_obj.get_replacement(vars, "D4T1P2")

    '''
    remove vlan member
    '''
    st.config(nodes['leaf0'], 'sudo config vlan member del {} {}'.format(SAG1_VLAN, leaf0_vlan_member))
    st.config(nodes['leaf1'], 'sudo config vlan member del {} {}'.format(SAG1_VLAN, leaf1_vlan_member))

    st.wait(1)

    '''
    re-add vlan member
    '''
    st.config(nodes['leaf0'], 'sudo config vlan member add -u {} {}'.format(SAG1_VLAN, leaf0_vlan_member))
    st.config(nodes['leaf1'], 'sudo config vlan member add -u {} {}'.format(SAG1_VLAN, leaf1_vlan_member))

    streams, handles = traffic_setup()

    ## Verify Vtep state
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP)

    ## Run Traffic: Bi-directional Burst of 100 Packets
    result = vxlan_obj.check_traffic(streams, timeout=10)

    traffic_cleanup(streams, handles)

    if result:
        st.report_pass("test_case_passed", "test_l2vni_ipv6_sym_irb_sag_del_add_vlan_member passed")
    else:
        st.report_fail("test_case_failed", "test_l2vni_ipv6_sym_irb_sag_del_add_vlan_member failed")

