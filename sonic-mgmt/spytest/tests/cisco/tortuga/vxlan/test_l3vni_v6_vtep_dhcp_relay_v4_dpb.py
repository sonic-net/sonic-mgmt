from spytest import st, tgapi, SpyTestDict
import os
import yaml
import pytest
import vxlan_utils as vxlan_obj
import vxlan_utils_dhcp_relay as dhcp_relay_obj

######################################################################################
## config: eBGP + ECMP
##
##  Topology : 2x Spine + 2 Leafs
##
##  SD1 -- Spine0  - D1
##  SD2 -- Spine1  - D2
##  SD3 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4
##
######################################################################################

vlan2  = "2"
vlan3  = "3"
vlan4  = "4"

dhcpserverv4_b2 = "30.30.30.99"
dhcpserverv4_a4 = "50.50.50.99"

LEAF0_VXLAN_IP = '2000:1::1'
LEAF1_VXLAN_IP = '2000:1::2'

VRF_NAME1 = "Vrf101"
VRF_NAME2 = "Vrf102"

DUMMY_VLAN1 = "101"
DUMMY_VLAN2 = "102"

leaf0_loopback = "Loopback3"
leaf1_loopback = "Loopback4"

leaf0_prefix = "3.3.3.3/32"
leaf1_prefix = "4.4.4.4/32"

vlan2_prefix = "20.20.20.1/24"
vlan3_prefix = "30.30.30.1/24"
vlan4_prefix = "40.40.40.1/24"
vlan5_prefix = "50.50.50.1/24"


CONFIGS_FILE = 'test_l3vni_v6_vtep_dhcp_relay_v4.yaml'
data = SpyTestDict()
data.config_vrfs = []


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
            if 'deconfig0' in config_list[node][config_domain]:
                st.wait(5)
                config_node(node, config_list[node][config_domain]['deconfig0'], domain)

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)


#################################################
## VTEP6 configs based on HW device 
#################################################

@pytest.fixture(scope="module", autouse=True)
def setup_teardown_l3vni_sag():

    ### Check dut is HW or SIM ###
    dut_type = vxlan_obj.check_hw_or_sim(st.get_dut_names()[0])

    st.log("test_l3vni_vtep6_sag_dhcp_relay_tc1_DPB dut_type={}".format(dut_type))
    if dut_type != "sim":
        pytest.skip("test_l3vni_vtep6_sag_dhcp_relay_tc1_DPB is only supported on SIM", allow_module_level=True)
        return

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
            #Disabling drake so that there are no automatic underlay configs
            st.config(nodes[node], "systemctl stop drake", skip_error_check=False, conf=True)
            st.config(nodes[node], "no router bgp", type='vtysh', skip_error_check=False, conf=True)
            '''
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
            st.wait(2)
 
    data.config_vrfs.append(VRF_NAME1)
 
    st.log("config_l3vni_int_vrf1 {}".format(data.config_vrfs))
 
    #Make sure links are up by pinging, sometimes packet exchange doesn't happen on sim till pings are initiated
    st.wait(10)
    count = 5
    st.show(nodes['leaf0'], 'sudo ping -c {} {} -q'.format(count, LEAF1_VXLAN_IP), skip_tmpl=True, skip_error_check=True)
    st.show(nodes['leaf1'], 'sudo ping -c {} {} -q'.format(count, LEAF0_VXLAN_IP), skip_tmpl=True, skip_error_check=True)
    
    yield 'setup_teardown_l3vni_sag'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)
            st.wait(2)

    st.log("config_l3vni_int_vrf2 {}".format(data.config_vrfs))

    for vrf in data.config_vrfs:
        vxlan_obj.config_vrf(nodes['leaf0'], vrf, add=False)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf, add=False)
    data.config_vrfs = []
    
    ### Remove the temp config file after the test ###
    vxlan_obj.remove_temp_config(updated_config_file)



######################################################################################
##  VTEP6-L3VNI-TC1: 1 dhcp relay on non default vrf with breakout
######################################################################################
##
##  HOST0/dhcp_client --- SD3/Leaf0 --- EVPN --- SD4/Leaf1 --- HOST1/dhcp_server
##
##  <Vrf101>
##                        VLAN2                  VLAN2
##                  20.20.20.1/24 ------       20.20.20.1/24
##                        VLAN3        |         VLAN3
##                  30.30.30.1/24      ------> 30.30.30.1/24
##                                             30.30.30.99 --- DHCP SERVER
##
##                                               VLAN4
##                  50.50.50.99(EMPTY) <------ 40.40.40.1/24
##
##
##  <Leaf0>   config dhcp_relay ipv4 helper add 2 30.30.30.99 
##  <Leaf1>   config dhcp_relay ipv4 helper add 4 50.50.50.99 
##
######################################################################################


def test_l3vni_vtep6_sag_dhcp_relay_tc1_DPB():

    st.banner("Start on test_l3vni_vtep6_sag_dhcp_relay_tc1_DPB")
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2 
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan2, member=vars.D3T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf0_loopback, breakout=True,  add=True)
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan3, member=vars.D3T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf0_loopback, breakout=False, add=True) 

    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan2, member=vars.D4T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf1_loopback, breakout=False, add=True)
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan3, member=vars.D4T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf1_loopback, breakout=False, add=True)
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan4, member=vars.D4T1P3, vrf=VRF_NAME1, prefix=vlan4_prefix, loopback=leaf1_loopback, breakout=False, add=True)

    st.wait(30) 
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP)
    
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D3, vlan2, dhcpserverv4_b2)
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D4, vlan4, dhcpserverv4_a4)
   
    result = dhcp_relay_obj.dhcp_l3vni_ipv4_setup_server_client(dual_servers=False, linksel=True, leaf0_clients=1)
    
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D4, vlan4, dhcpserverv4_a4, add=False)
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D3, vlan2, dhcpserverv4_b2, add=False)
    
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan4, member=vars.D4T1P3, vrf=VRF_NAME1, prefix=vlan4_prefix, loopback=leaf1_loopback, breakout=False, add=False)
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan3, member=vars.D4T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf1_loopback, breakout=False, add=False)
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan2, member=vars.D4T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf1_loopback, breakout=False, add=False)

    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan3, member=vars.D3T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf0_loopback, breakout=False, add=False)
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan2, member=vars.D3T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf0_loopback, breakout=True,  add=False)

    if result:
	st.report_pass('test_case_passed', 'test_l3vni_vtep6_sag_dhcp_relay_tc1_DPB')
    else:
	st.report_fail('test_case_failed', 'test_l3vni_vtep6_sag_dhcp_relay_tc1_DPB')
