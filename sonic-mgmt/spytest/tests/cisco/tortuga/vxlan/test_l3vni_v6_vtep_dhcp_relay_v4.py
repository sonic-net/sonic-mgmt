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
##  TARGET TOPOLOGY: VTEP6-L3VNI + DHCP_RELAY_V4 
######################################################################################
##
##  HOST0/dhcp_client --- SD3/Leaf0 --- EVPN --- SD4/Leaf1 --- HOST1/dhcp_server
##
##  <Vrf101>
##                        VLAN2                  VLAN2
##                  20.20.20.1/24 ------       20.20.20.1/24
##                        VLAN3        |         VLAN3
##                  30.30.30.1/24      |-----> 30.30.30.1/24
##                                     |       30.30.30.99 --- DHCP SERVER B2
##                        VLAN4        |         VLAN4
##                  40.40.40.1/24 ------       40.40.40.1/24
##                        VLAN5        |         VLAN5
##                  50.50.50.1/24 ------       50.50.50.1/24
##  DHCP SERVER A4  50.50.50.99
##
######################################################################################

vlan2  = "2"
vlan3  = "3"
vlan4  = "4"
vlan5  = "5"
vlan10 = "10"

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
            if 'config2' in config_list[node][config_domain]:
                st.wait(5)
                config_node(node, config_list[node][config_domain]['config2'], domain)
        else:
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)
            if 'deconfig2' in config_list[node][config_domain]:
                st.wait(5)
                config_node(node, config_list[node][config_domain]['deconfig2'], domain)
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
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
            st.wait(2)
 
    data.config_vrfs.append(VRF_NAME1)
    data.config_vrfs.append(VRF_NAME2)
 
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



dhcp_scaling_factor = 30 

def config_dhcp_relay_ipv4_scaling(node, vlan, server, add=True):
    vars = st.get_testbed_vars()

    if add:
        for i in range(dhcp_scaling_factor):
            st.config(node, "config vlan add {}".format(int(vlan) + i))
            st.config(node, "config interface ip add Vlan{} 8.8.{}.254/24".format(int(vlan) + i, int(vlan) + i))
            st.config(node, "config vlan dhcp_relay add {} {}".format(int(vlan) + i, server))
    else:
        for i in range(dhcp_scaling_factor):
            st.config(node, "config vlan dhcp_relay del {} {}".format(int(vlan) + i, server))
            st.config(node, "config interface ip rem Vlan{} 8.8.{}.254/24".format(int(vlan) + i, int(vlan) + i))
            st.config(node, "config vlan del {}".format(int(vlan) + i))



######################################################################################
##  VTEP6-L3VNI-TC1: 1 dhcp relay on non default vrf
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


def test_l3vni_vtep6_sag_dhcp_relay_tc1():

    st.banner("Start on test_l3vni_vtep6_sag_dhcp_relay_tc1")
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2 
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan2, member=vars.D3T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf0_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan3, member=vars.D3T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf0_loopback, add=True)  
   
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan2, member=vars.D4T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf1_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan3, member=vars.D4T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf1_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan4, member=vars.D4T1P3, vrf=VRF_NAME1, prefix=vlan4_prefix, loopback=leaf1_loopback, add=True)  
   
    st.wait(30)
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP)
    
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D3, vlan2, dhcpserverv4_b2)
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D4, vlan4, dhcpserverv4_a4)
   
    result = dhcp_relay_obj.dhcp_l3vni_ipv4_setup_server_client(dual_servers=False, linksel=True, leaf0_clients=1)
    
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D4, vlan4, dhcpserverv4_a4, add=False)
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D3, vlan2, dhcpserverv4_b2, add=False)
    
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan4, member=vars.D4T1P3, vrf=VRF_NAME1, prefix=vlan4_prefix, loopback=leaf1_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan3, member=vars.D4T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf1_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan2, member=vars.D4T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf1_loopback, add=False)  
   
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan3, member=vars.D3T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf0_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan2, member=vars.D3T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf0_loopback, add=False)  

    
    if result:
	st.report_pass('test_case_passed', 'test_l3vni_vtep6_sag_dhcp_relay_tc1')
    else:
	st.report_fail('test_case_failed', 'test_l3vni_vtep6_sag_dhcp_relay_tc1')


######################################################################################
##  VTEP6-L3VNI-TC2: 3 dhcp relays on non default vrf
######################################################################################
##
##  HOST0/dhcp_client --- SD3/Leaf0 --- EVPN --- SD4/Leaf1 --- HOST1/dhcp_server
##
##  <Vrf101>
##                        VLAN2                  VLAN2
##                  20.20.20.1/24 ------       20.20.20.1/24
##                        VLAN3        |         VLAN3
##                  30.30.30.1/24      |-----> 30.30.30.1/24
##                                     |       30.30.30.99 --- DHCP SERVER
##                                    +++ 
##                        VLAN4        |
##                  40.40.40.1/24 ------
##                        VLAN5        |
##                  50.50.50.1/24 ------
##                                               VLAN4
##                  50.50.50.99(EMPTY) <------ 40.40.40.1/24
##
##
##  <Leaf0>   config dhcp_relay ipv4 helper add 2 30.30.30.99 
##  <Leaf0>   config dhcp_relay ipv4 helper add 4 30.30.30.99 
##  <Leaf0>   config dhcp_relay ipv4 helper add 5 30.30.30.99 
##
##  <Leaf1>   config dhcp_relay ipv4 helper add 4 50.50.50.99 
##
######################################################################################

def test_l3vni_vtep6_sag_dhcp_relay_tc2():

    st.banner("Start on test_l3vni_vtep6_sag_dhcp_relay_tc2")
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2 
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan2, member=vars.D3T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf0_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan3, member=vars.D3T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf0_loopback, add=True)  

    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan4, member=vars.D3T1P3, vrf=VRF_NAME1, prefix=vlan4_prefix, loopback=leaf0_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan5, member=vars.D3T1P4, vrf=VRF_NAME1, prefix=vlan5_prefix, loopback=leaf0_loopback, add=True)  
   
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan2, member=vars.D4T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf1_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan3, member=vars.D4T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf1_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan4, member=vars.D4T1P3, vrf=VRF_NAME1, prefix=vlan4_prefix, loopback=leaf1_loopback, add=True)  
   
    st.wait(30)
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP)
   
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D3, vlan2, dhcpserverv4_b2)
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D3, vlan4, dhcpserverv4_b2)
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D3, vlan5, dhcpserverv4_b2)
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D4, vlan4, dhcpserverv4_a4)

    result = dhcp_relay_obj.dhcp_l3vni_ipv4_setup_server_client(dual_servers=False, linksel=True, leaf0_clients=3)

    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D4, vlan4, dhcpserverv4_a4, add=False)
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D3, vlan5, dhcpserverv4_b2, add=False)
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D3, vlan4, dhcpserverv4_b2, add=False)
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D3, vlan2, dhcpserverv4_b2, add=False)

    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan5, member=vars.D3T1P4, vrf=VRF_NAME1, prefix=vlan5_prefix, loopback=leaf0_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan4, member=vars.D3T1P3, vrf=VRF_NAME1, prefix=vlan4_prefix, loopback=leaf0_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan3, member=vars.D3T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf0_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan2, member=vars.D3T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf0_loopback, add=False)  

    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan4, member=vars.D4T1P3, vrf=VRF_NAME1, prefix=vlan4_prefix, loopback=leaf1_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan3, member=vars.D4T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf1_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan2, member=vars.D4T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf1_loopback, add=False)  
   
    
    if result:
	st.report_pass('test_case_passed', 'test_l3vni_vtep6_sag_dhcp_relay_tc2')
    else:
	st.report_fail('test_case_failed', 'test_l3vni_vtep6_sag_dhcp_relay_tc2')



######################################################################################
##  VTEP6-L3VNI-TC3: 1 dhcp relay on non default vrf with scaling
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
##                                               VLAN4
##                        VLAN10  ----->
##                        VLAN11  ----->
##                        ........
##
##                                               VLAN4
##                  50.50.50.99(EMPTY) <------ 40.40.40.1/24
##
##  <Leaf0>   config dhcp_relay ipv4 helper add  2 30.30.30.99
##  <Leaf1>   config dhcp_relay ipv4 helper add  4 50.50.50.99
##
##  <Leaf0>   config dhcp_relay ipv4 helper add 10 30.30.30.99
##  <Leaf0>   config dhcp_relay ipv4 helper add 11 30.30.30.99
##  <Leaf0>   config dhcp_relay ipv4 helper add 12 30.30.30.99
##  ........
##
##  <Leaf0>   config dhcp_relay ipv4 helper add 40 30.30.30.99
##
######################################################################################

def test_l3vni_vtep6_sag_dhcp_relay_tc3():

    st.banner("Start on test_l3vni_vtep6_sag_dhcp_relay_tc3")
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

   
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan2, member=vars.D3T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf0_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan3, member=vars.D3T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf0_loopback, add=True)  
   
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan2, member=vars.D4T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf1_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan3, member=vars.D4T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf1_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan4, member=vars.D4T1P3, vrf=VRF_NAME1, prefix=vlan4_prefix, loopback=leaf1_loopback, add=True)  

    st.wait(30)
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP)

    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D3, vlan2, dhcpserverv4_b2)
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D4, vlan4, dhcpserverv4_a4)

    ######### DHCP RELAY SCALING CONFIG ##############

    config_dhcp_relay_ipv4_scaling(vars.D3, vlan10, dhcpserverv4_b2)
    st.wait(60)

    result = dhcp_relay_obj.dhcp_l3vni_ipv4_setup_server_client(dual_servers=False, linksel=True, leaf0_clients=1)

    config_dhcp_relay_ipv4_scaling(vars.D3, vlan10, dhcpserverv4_b2, add=False)
    st.wait(60)

    ######### DHCP RELAY SCALING CONFIG ##############

    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D4, vlan4, dhcpserverv4_a4, add=False)
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D3, vlan2, dhcpserverv4_b2, add=False)

    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan4, member=vars.D4T1P3, vrf=VRF_NAME1, prefix=vlan4_prefix, loopback=leaf1_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan3, member=vars.D4T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf1_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan2, member=vars.D4T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf1_loopback, add=False)  
   
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan3, member=vars.D3T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf0_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan2, member=vars.D3T1P1, vrf=VRF_NAME1, prefix=vlan2_prefix, loopback=leaf0_loopback, add=False)  


    if result:
        st.report_pass('test_case_passed', 'test_l3vni_vtep6_sag_dhcp_relay_tc3')
    else:
        st.report_fail('test_case_failed', 'test_l3vni_vtep6_sag_dhcp_relay_tc3')



######################################################################################
##  VTEP6-L3VNI-TC4: 2 dhcp relays on non 2 default vrf
######################################################################################
##
##  HOST0/dhcp_client --- SD3/Leaf0 --- EVPN --- SD4/Leaf1 --- HOST1/dhcp_server
##
##  <Vrf101>
##                        VLAN3                  VLAN3
##                  30.30.30.1/24      |-----> 30.30.30.1/24
##                                     |       30.30.30.99 --- DHCP SERVER
##                        VLAN4        |         VLAN4
##                  40.40.40.1/24 ------       40.40.40.1/24 (CMONO-NO-PORT)
##
##  <Vrf102>
##                        VLAN2                  VLAN2
##                  20.20.20.1/24      |------ 20.20.20.1/24
##                        VLAN5        |         VLAN5
##                  50.50.50.1/24 <-----       50.50.50.1/24 (CMONO-NO-PORT)
##  DHCP SERVER --- 50.50.50.99 
##
##
##  <Leaf0:Vrf101>   config dhcp_relay ipv4 helper add 4 30.30.30.99 
##  <Leaf1:Vrf102>   config dhcp_relay ipv4 helper add 2 50.50.50.99 
##
##
######################################################################################

def test_l3vni_vtep6_sag_dhcp_relay_tc4():

    st.banner("Start on test_l3vni_vtep6_sag_dhcp_relay_tc4")
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    ######### TOPO CONFIG ADDED ##############

    dhcp_relay_obj.config_l3vni_int_vrf(vars.D3, vrf=VRF_NAME2, dummy_vlan=DUMMY_VLAN2, loopback=None,           prefix=None,         add=True)
    dhcp_relay_obj.config_l3vni_int_vrf(vars.D4, vrf=VRF_NAME2, dummy_vlan=DUMMY_VLAN2, loopback=leaf1_loopback, prefix=leaf1_prefix, add=True)
   
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan3, member=vars.D3T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf0_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan4, member=vars.D3T1P3, vrf=VRF_NAME1, prefix=vlan4_prefix, loopback=leaf0_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan3, member=vars.D4T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf1_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan4, member=vars.D4T1P3, vrf=VRF_NAME1, prefix=vlan4_prefix, loopback=leaf1_loopback, add=True)  

    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan2, member=vars.D3T1P1, vrf=VRF_NAME2, prefix=vlan2_prefix, loopback=leaf0_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan5, member=vars.D3T1P4, vrf=VRF_NAME2, prefix=vlan5_prefix, loopback=leaf0_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan2, member=vars.D4T1P1, vrf=VRF_NAME2, prefix=vlan2_prefix, loopback=leaf1_loopback, add=True)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan5, member=vars.D4T1P4, vrf=VRF_NAME2, prefix=vlan5_prefix, loopback=leaf1_loopback, add=True)  
   

    st.wait(30)
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VXLAN_IP, LEAF1_VXLAN_IP)

   
    ######### DHCP RELAY CONFIG ADDED ##############
   
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D3, vlan4, dhcpserverv4_b2)
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D4, vlan2, dhcpserverv4_a4)


    ###### CaseTC3-A ######

    result_a = dhcp_relay_obj.dhcp_l3vni_ipv4_setup_server_client(dual_servers=True, linksel=True, leaf0_clients=0, dual_clients=1)

    if result_a:
        st.log("test_l3vni_vtep6_dhcp_relays_mvni_tc3_a: basic mvni passed")
    else:
        st.log("test_l3vni_vtep6_dhcp_relays_mvni_tc3_a: basic mvni failed")


    ###### CaseTC3-B ######

    st.config(vars.D3, "sonic-clear arp")
    st.config(vars.D4, "sonic-clear arp")
    st.wait(20)

    result_b = dhcp_relay_obj.dhcp_l3vni_ipv4_setup_server_client(dual_servers=True, linksel=True, leaf0_clients=0, dual_clients=1)

    if result_b:
        st.log("test_l3vni_vtep6_dhcp_relays_mvni_tc3_b: sonic-clear arp passed")
    else:
        st.log("test_l3vni_vtep6_dhcp_relays_mvni_tc3_b: sonic-clear arp failed")

    ###### CaseTC3-C ######

    st.config(vars.D3, "sudo config interface shutdown {}".format(vars.D3T1P1))
    st.config(vars.D3, "sudo config interface shutdown {}".format(vars.D3T1P2))
    st.config(vars.D3, "sudo config interface shutdown {}".format(vars.D3T1P3))
    st.config(vars.D3, "sudo config interface shutdown {}".format(vars.D3T1P4))
    st.wait(5)
    st.config(vars.D3, "sudo config interface startup {}".format(vars.D3T1P1))
    st.config(vars.D3, "sudo config interface startup {}".format(vars.D3T1P2))
    st.config(vars.D3, "sudo config interface startup {}".format(vars.D3T1P3))
    st.config(vars.D3, "sudo config interface startup {}".format(vars.D3T1P4))
    st.wait(5)
    st.config(vars.D4, "sudo config interface shutdown {}".format(vars.D4T1P1))
    st.config(vars.D4, "sudo config interface shutdown {}".format(vars.D4T1P2))
    st.config(vars.D4, "sudo config interface shutdown {}".format(vars.D4T1P3))
    st.config(vars.D4, "sudo config interface shutdown {}".format(vars.D4T1P4))
    st.wait(5)
    st.config(vars.D4, "sudo config interface startup {}".format(vars.D4T1P1))
    st.config(vars.D4, "sudo config interface startup {}".format(vars.D4T1P2))
    st.config(vars.D4, "sudo config interface startup {}".format(vars.D4T1P3))
    st.config(vars.D4, "sudo config interface startup {}".format(vars.D4T1P4))
    st.wait(10)

    result_c = dhcp_relay_obj.dhcp_l3vni_ipv4_setup_server_client(dual_servers=True, linksel=True, leaf0_clients=0, dual_clients=1)

    if result_c:
        st.log("test_l3vni_vtep6_dhcp_relays_mvni_tc3_c: shutdown/startup ints passed")
    else:
        st.log("test_l3vni_vtep6_dhcp_relays_mvni_tc3_c: shutdown/startup ints failed")

    ###### CaseTC3-D ######

    st.config(vars.D4, "sudo config vlan member del {} {}".format(vlan2, vars.D4T1P1))
    st.config(vars.D3, "sudo config vlan member del {} {}".format(vlan4, vars.D3T1P3))
    st.wait(5)
    st.config(vars.D4, "sudo config vlan member add {} -u {}".format(vlan2, vars.D4T1P1))
    st.config(vars.D3, "sudo config vlan member add {} -u {}".format(vlan4, vars.D3T1P3))
    st.wait(5)

    result_d = dhcp_relay_obj.dhcp_l3vni_ipv4_setup_server_client(dual_servers=True, linksel=True, leaf0_clients=0, dual_clients=1)

    if result_d:
        st.log("test_l3vni_vtep6_dhcp_relays_mvni_tc3_d: vlan member del/add passed")
    else:
        st.log("test_l3vni_vtep6_dhcp_relays_mvni_tc3_d: vlan member del/add failed")


    ######### DHCP RELAY CONFIG REMOVAL ##############

    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D3, vlan4, dhcpserverv4_b2, add=False)
    dhcp_relay_obj.config_dhcp_relay_ipv4(vars.D4, vlan2, dhcpserverv4_a4, add=False)


    ######### TOPO CONFIG REMOVAL ##############


    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan3, member=vars.D3T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf0_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan4, member=vars.D3T1P3, vrf=VRF_NAME1, prefix=vlan4_prefix, loopback=leaf0_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan3, member=vars.D4T1P2, vrf=VRF_NAME1, prefix=vlan3_prefix, loopback=leaf1_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan4, member=vars.D4T1P3, vrf=VRF_NAME1, prefix=vlan4_prefix, loopback=leaf1_loopback, add=False)  

    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan2, member=vars.D3T1P1, vrf=VRF_NAME2, prefix=vlan2_prefix, loopback=leaf0_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D3, vlan=vlan5, member=vars.D3T1P4, vrf=VRF_NAME2, prefix=vlan5_prefix, loopback=leaf0_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan2, member=vars.D4T1P1, vrf=VRF_NAME2, prefix=vlan2_prefix, loopback=leaf1_loopback, add=False)  
    dhcp_relay_obj.config_l3vni_int_vlan(vars.D4, vlan=vlan5, member=vars.D4T1P4, vrf=VRF_NAME2, prefix=vlan5_prefix, loopback=leaf1_loopback, add=False)  
   
    dhcp_relay_obj.config_l3vni_int_vrf(vars.D3, vrf=VRF_NAME2, dummy_vlan=DUMMY_VLAN2, loopback=None,           prefix=None,         add=False)
    dhcp_relay_obj.config_l3vni_int_vrf(vars.D4, vrf=VRF_NAME2, dummy_vlan=DUMMY_VLAN2, loopback=leaf1_loopback, prefix=leaf1_prefix, add=False)
   
    st.log("config_l3vni_int_vrf: del vrf after bgp release {}".format(data.config_vrfs))
   
    ######### REVIEW DHCP RELAY CONFIG ##############

    if result_a and result_b and result_c and result_d:
        st.report_pass('test_case_passed', 'test_l3vni_vtep6_sag_dhcp_relay_tc4')
    else:
        st.report_fail('test_case_failed', 'test_l3vni_vtep6_sag_dhcp_relay_tc4')
