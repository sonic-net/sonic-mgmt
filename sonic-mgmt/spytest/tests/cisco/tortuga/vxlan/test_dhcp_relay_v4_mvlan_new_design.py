import os
import yaml
import pytest

from spytest import st, tgapi, SpyTestDict
from dhcpv4_relay_utils import dhcpv4_relay_flag_config_unconfig, check_dhcp4relay_support
import apis.system.basic as basic_obj
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import vxlan_utils as vxlan_obj
import tortuga_common_utils as common_obj

#################################################################
##  Topology : 1 Leaf(D4)
#################################################################
##
##  IPv4: HOST0/dhcp_client - SD4/Leaf0 - HOST1/dhcp_server
##
#################################################################

CONFIGS_FILE = 'test_dhcp_relay_basic_template.yaml'

dhcp_vlan1 = "10"
dhcp_vlan2 = "20"
dhcp_vlan3 = "30"
dhcp_vlan4 = "40"
dhcp_vlan5 = "50"
dhcp_vlan6 = "60"

dhcp_mac_addr1 = "00:0a:01:00:11:01"
dhcp_mac_addr2 = "00:0a:01:00:12:01"
dhcp_mac_addr3 = "00:0a:01:00:13:01"
dhcp_mac_addr4 = "00:0a:01:00:14:01"

dhcp_vlan_ipv4_addr1 = "192.160.10.1"
dhcp_vlan_ipv4_addr2 = "192.160.20.1"
dhcp_vlan_ipv4_addr3 = "192.160.30.1"
dhcp_vlan_ipv4_addr4 = "192.160.40.1"

dhcpserver_ipv4_a = "192.160.20.100"
dhcp_ipv4_assigned_st_a = "192.160.10.60"
dhcp_ipv4_set_a =  {"192.160.10.60", "192.160.10.61","192.160.10.62","192.160.10.63","192.160.10.64", 
                    "192.160.10.65", "192.160.10.66","192.160.10.67","192.160.10.68","192.160.10.69",
                    "192.160.10.70", "192.160.10.71","192.160.10.72","192.160.10.73","192.160.10.74"}

dhcp_ipv4_assigned_st_c = "192.160.50.60"
dhcp_ipv4_set_c =  {"192.160.50.60", "192.160.50.61","192.160.50.62","192.160.50.63","192.160.50.64",
                    "192.160.50.65", "192.160.50.66","192.160.50.67","192.160.50.68","192.160.50.69"}


dhcpserver_ipv4_b = "192.160.40.100"
dhcp_ipv4_assigned_st_b = "192.160.30.80"
dhcp_ipv4_set_b =  {"192.160.30.80", "192.160.30.81","192.160.30.82","192.160.30.83","192.160.30.84",
                    "192.160.30.85", "192.160.30.86","192.160.30.87","192.160.30.88","192.160.30.89",
                    "192.160.30.90", "192.160.30.91","192.160.30.92","192.160.30.93","192.160.30.94"}

dhcp_ipv4_prefix0  = "192.160.10.254/24"
dhcp_ipv4_prefix1  = "192.160.10.1/24"
dhcp_ipv4_prefix2  = "192.160.20.1/24"
dhcp_ipv4_prefix3  = "192.160.30.254/24"
dhcp_ipv4_prefix4  = "192.160.40.1/24"
dhcp_ipv4_prefix5  = "192.160.50.1/24"


def config_dhcp_relay_ipv4_vlan(node, vlan=None, prefix=None, add=True):
    if add:
        st.config(node, "config interface ip add Vlan{} {}".format(vlan, prefix))
    else:
        st.config(node, "config interface ip remove Vlan{} {}".format(vlan, prefix))


def config_dhcp_relay_ipv4_trig(node, vlan=None, dhcpserver_ipv4=None, add=True):
    if add:
        st.config(node, "config dhcpv4_relay add Vlan{} --dhcpv4-servers {}".format(vlan, dhcpserver_ipv4))
    else:
        st.config(node, "config dhcpv4_relay del Vlan{} --dhcpv4-servers {}".format(vlan, dhcpserver_ipv4))


def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)


def router_preconfig_cleanup():
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())


@pytest.fixture(scope="module", autouse=True)
def dhcp_relay_config_hooks():
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
            common_obj.config_static(node, 'sonic', True, updated_config_file)
            st.wait(2)

    dhcp_setup_ipv4_servers(linksel=True, mserver=True)

    yield dhcp_relay_config_hooks

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            common_obj.config_static(node, 'sonic', False, updated_config_file)
            st.wait(2)

    vxlan_obj.remove_temp_config(updated_config_file)



def dhcp_setup_ipv4_servers(linksel=False, mserver=True):
    vars = st.get_testbed_vars()

    # DHCP Server A

    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D3P2")

    h2 = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=dhcpserver_ipv4_a, gateway=dhcp_vlan_ipv4_addr2, 
                                src_mac_addr=dhcp_mac_addr2, arp_send_req='1', control_plane_mtu='9100', vlan='1', vlan_id=dhcp_vlan2,
                                resolve_gateway_mac='false')

    dut_mac = basic_obj.get_ifconfig_ether(vars.D4, 'Vlan{}'.format(dhcp_vlan2))
    st.log("dhcp relay dut_mac {} linksel {}".format(dut_mac, linksel))

    if linksel:
        s_conf2 = tg2.tg_emulation_dhcp_server_config(mode='create', ip_version='4', encapsulation='ethernet_ii_vlan', vlan_id=dhcp_vlan2,
                                                    ipaddress_count='100', ipaddress_pool=[dhcp_ipv4_assigned_st_a, dhcp_ipv4_assigned_st_c], handle=h2['handle'],
                                                    count='1', local_mac=dhcp_mac_addr2, ip_address=dhcpserver_ipv4_a,
                                                    ip_gateway=dhcp_vlan_ipv4_addr2, remote_mac=dut_mac, pool_count=2, 
                                                    subnet_addr_assign=1, subnet='link_selection')
    else:
        s_conf2 = tg2.tg_emulation_dhcp_server_config(mode='create', ip_version='4', encapsulation='ethernet_ii_vlan', vlan_id=dhcp_vlan2,
                                                    ipaddress_count='100', ipaddress_pool=dhcp_ipv4_assigned_st_a, handle=h2['handle'],
                                                    count='1', local_mac=dhcp_mac_addr2, ip_address=dhcpserver_ipv4_a,
                                                    ip_gateway=dhcp_vlan_ipv4_addr2, remote_mac=dut_mac, pool_count=1)

    s_con2 = tg2.tg_emulation_dhcp_server_control(action='connect', dhcp_handle=s_conf2['dhcp_handle'])
    st.log("dhcp relay ipv4 basic server A control {}".format(s_con2))


    # DHCP Server B 

    if mserver:
        tg4, tg_ph_4 = tgapi.get_handle_byname("T1D3P4")

        h4 = tg4.tg_interface_config(port_handle=tg_ph_4, mode='config', intf_ip_addr=dhcpserver_ipv4_b, gateway=dhcp_vlan_ipv4_addr4, 
                            src_mac_addr=dhcp_mac_addr4,
                            arp_send_req='1', control_plane_mtu='9100', vlan='1', vlan_id=dhcp_vlan4,
                            resolve_gateway_mac='false')

        dut_mac = basic_obj.get_ifconfig_ether(vars.D4, 'Vlan{}'.format(dhcp_vlan4))
        st.log("dhcp relay dut_mac {} linksel {}".format(dut_mac, linksel))

        if linksel:
            s_conf4 = tg4.tg_emulation_dhcp_server_config(mode='create', ip_version='4', encapsulation='ethernet_ii_vlan', vlan_id=dhcp_vlan4,
                                                ipaddress_count='100', ipaddress_pool=dhcp_ipv4_assigned_st_b, handle=h4['handle'],
                                                count='1', local_mac=dhcp_mac_addr4, ip_address=dhcpserver_ipv4_b,
                                                ip_gateway=dhcp_vlan_ipv4_addr4, remote_mac=dut_mac, pool_count=1, 
                                                subnet_addr_assign=1, subnet='link_selection')
        else:
            s_conf4 = tg4.tg_emulation_dhcp_server_config(mode='create', ip_version='4', encapsulation='ethernet_ii_vlan', vlan_id=dhcp_vlan4,
                                                ipaddress_count='100', ipaddress_pool=dhcp_ipv4_assigned_st_b, handle=h4['handle'],
                                                count='1', local_mac=dhcp_mac_addr4, ip_address=dhcpserver_ipv4_b,
                                                ip_gateway=dhcp_vlan_ipv4_addr4, remote_mac=dut_mac, pool_count=1)

        s_con4 = tg4.tg_emulation_dhcp_server_control(action='connect', dhcp_handle=s_conf4['dhcp_handle'])
        st.log("dhcp relay ipv4 basic server B control {}".format(s_con4))



def dhcp_setup_ipv4_clients_verify(mhost=True, mclients=2, mserver=True):

    # DHCP Client A

    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D3P1")
    conf1 = tg1.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_1)

    # 'ip_version' is mandatory to configure retry_count
    conf1 = tg1.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_1, retry_count='10', ip_version='4')
    st.log("dhcp relay ipv4 basic client A config {}".format(conf1))

    group1 = tg1.tg_emulation_dhcp_group_config(handle=conf1['handles'], mode='create', encap='ethernet_ii_vlan', vlan_id_count=mclients,
                                              num_sessions=mclients, mac_addr=dhcp_mac_addr1, vlan_id=dhcp_vlan1, vlan_ether_type='0x8100',
                                              dhcp_range_ip_type=4, vlan_id_step=0, gateway_addresses=1, protocol_name='dhcpv4client', dhcp4_broadcast=1)
    st.log("dhcp relay ipv4 basic client A gconfig {}".format(group1))

    tg1.tg_emulation_dhcp_stats(action='clear', port_handle=tg_ph_1)
    cont1 = tg1.tg_emulation_dhcp_control(port_handle=tg_ph_1, action="bind", handle=group1['handle'])
    st.log("dhcp relay ipv4 basic client A bind {}".format(cont1))

    st.wait(20)

    rst1 = tg1.tg_emulation_dhcp_stats(port_handle=tg_ph_1, handle=conf1['handles'], mode='session', ip_version='4')
    st.log("dhcp relay ipv4 basic result on the client A {}".format(rst1))
   
    cnt_a = 0
    cnt_b = 0
    cnt_c = 0

    for key, val in rst1.items():
        if key in 'session':
            for _, val2 in val.items():
                st.log("dhcp relay ipv4 basic client ipAddr {} cnt_a={}".format(val2['Address'], cnt_a))
                if val2['Address'] not in dhcp_ipv4_set_a:
                    st.log("dhcp client A does not be assigned ipv4 addr set_a from dhcp server cnt_a={}".format(cnt_a))
                    tg1.tg_emulation_dhcp_config(mode='reset', handle=conf1['handles'], port_handle=tg_ph_1)
                    return False
                else:
                    cnt_a = cnt_a + 1 
    
    st.log("dhcp relay half PASS cnt_a={}".format(cnt_a))
    
    # DHCP ClientB 
    
    if mhost:
    
        if mserver:
            dhcp_vlan = dhcp_vlan3
        else:
            dhcp_vlan = dhcp_vlan5
 
        tg3, tg_ph_3 = tgapi.get_handle_byname("T1D3P3")
        conf3 = tg1.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_3)

        # 'ip_version' is mandatory to configure retry_count
        conf3 = tg1.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_3, retry_count='10', ip_version='4')
        st.log("dhcp relay ipv4 basic client B config {}".format(conf3))

        group3 = tg3.tg_emulation_dhcp_group_config(handle=conf3['handles'], mode='create', encap='ethernet_ii_vlan', vlan_id_count=mclients,
                                              num_sessions=mclients, mac_addr=dhcp_mac_addr3, vlan_id=dhcp_vlan, vlan_ether_type='0x8100',
                                              dhcp_range_ip_type=4, vlan_id_step=0, gateway_addresses=1, protocol_name='dhcpv4client', dhcp4_broadcast=1)
        st.log("dhcp relay ipv4 basic client B gconfig {}".format(group3))

        tg3.tg_emulation_dhcp_stats(action='clear', port_handle=tg_ph_3)
        cont3 = tg3.tg_emulation_dhcp_control(port_handle=tg_ph_3, action="bind", handle=group3['handle'])
        st.log("dhcp relay ipv4 basic client B bind {}".format(cont3))

        st.wait(20)

        rst3 = tg3.tg_emulation_dhcp_stats(port_handle=tg_ph_3, handle=conf3['handles'], mode='session', ip_version='4')
        st.log("dhcp relay ipv4 basic result on the client B {}".format(rst3))

        for key, val in rst3.items():
            if key in 'session':
                for _, val2 in val.items():
                    st.log("dhcp relay ipv4 basic client ipAddr {} cnt_b={}".format(val2['Address'], cnt_b))
                    if mserver:
                        if val2['Address'] not in dhcp_ipv4_set_b:
                            st.log("dhcp client B does not be assigned ipv4 addr set_b from dhcp server cnt_b={}".format(cnt_b))
                            tg3.tg_emulation_dhcp_config(mode='reset', handle=conf3['handles'], port_handle=tg_ph_3)
                            return False
                        else:
                            cnt_b = cnt_b + 1 
                    else:
                        if val2['Address'] not in dhcp_ipv4_set_c:
                            st.log("dhcp client B does not be assigned ipv4 addr set_c from dhcp server cnt_c={}".format(cnt_c))
                            tg3.tg_emulation_dhcp_config(mode='reset', handle=conf3['handles'], port_handle=tg_ph_3)
                            return False
                        else:
                            cnt_c = cnt_c + 1 
  
        tg3.tg_emulation_dhcp_config(mode='reset', handle=conf3['handles'], port_handle=tg_ph_3)
  
    tg1.tg_emulation_dhcp_config(mode='reset', handle=conf1['handles'], port_handle=tg_ph_1)
  
    st.log("dhcp relay full PASS cnt_a={} cnt_b={} cnt_c={}".format(cnt_a, cnt_b, cnt_c))
    
    return True 





######################################################################
##  IPv4-TC1: 2 dhcp relays on default vrf 
######################################################################
##
##  HOST0/dhcp_client ------- SD3/Leaf0 ------- HOST1/dhcp_server
##
##                    VLAN10             VLAN20:ETH40   192.160.20.100
##                    192.160.10.254/24  192.160.20.1/24
##  <default Vrf>
##                    VLAN30             VLAN40:ETH44   192.160.40.100
##                    192.160.30.254/24  192.160.40.1/24
##
##  config dhcp_relay ipv4 helper add 10 192.160.20.100
##  config dhcp_relay ipv4 helper add 30 192.160.40.100
##
######################################################################

def test_dhcp_relay_ipv4_mvlan_default_vrf_tc1(dhcpv4_relay_flag_config_unconfig):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    if not check_dhcp4relay_support(vars.D3):
        st.log("Skipping: dhcp4relay new design not supported - gracefully passing.")
        return st.report_pass("test_case_passed", "dhcp4relay new design is not there. so gracefully passing")

    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=None, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=None, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan3, members=[vars.D3T1P3], vrf=None, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=None, add=True, tagged=True)    

    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan1, prefix=dhcp_ipv4_prefix0, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan3, prefix=dhcp_ipv4_prefix3, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan2, prefix=dhcp_ipv4_prefix2, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan4, prefix=dhcp_ipv4_prefix4, add=True)

    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan1, dhcpserver_ipv4=dhcpserver_ipv4_a, add=True)
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan3, dhcpserver_ipv4=dhcpserver_ipv4_b, add=True)

    result = dhcp_setup_ipv4_clients_verify(mhost=True, mclients=2)

    if not result:
        st.show(vars.D3, 'sudo ping {} -c 5'.format(dhcpserver_ipv4_a), skip_tmpl=True, skip_error_check=True)
        st.show(vars.D3, 'sudo ping {} -c 5'.format(dhcpserver_ipv4_b), skip_tmpl=True, skip_error_check=True)

    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan1, dhcpserver_ipv4=dhcpserver_ipv4_a, add=False)
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan3, dhcpserver_ipv4=dhcpserver_ipv4_b, add=False)

    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan1, prefix=dhcp_ipv4_prefix0, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan3, prefix=dhcp_ipv4_prefix3, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan2, prefix=dhcp_ipv4_prefix2, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan4, prefix=dhcp_ipv4_prefix4, add=False)

    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=None, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan3, members=[vars.D3T1P3], vrf=None, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=None, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=None, add=False, tagged=True)    


    if result:
        st.report_pass("test_case_passed", "test_dhcp_relay_ipv4_mvlan_default_vrf_tc1 passed")
    else:
        st.report_fail("test_case_failed", "test_dhcp_relay_ipv4_mvlan_default_vrf_tc1 failed")



######################################################################
##  IPv4-TC2: 2 dhcp relays on one non default vrf 
######################################################################
##
##  HOST0/dhcp_client ------- SD3/Leaf0 ------- HOST1/dhcp_server
##
##                    VLAN10             VLAN20:ETH40   192.160.20.100
##                    192.160.10.254/24  192.160.20.1/24
##  <Vrf22>
##                    VLAN30             VLAN40:ETH44   192.160.40.100
##                    192.160.30.254/24  192.160.40.1/24
##
##  config dhcp_relay ipv4 helper add 10 192.160.20.100
##  config dhcp_relay ipv4 helper add 30 192.160.40.100
##
######################################################################

def test_dhcp_relay_ipv4_mvlan_new_vrf_tc2(dhcpv4_relay_flag_config_unconfig):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    if not check_dhcp4relay_support(vars.D3):
        st.log("Skipping: dhcp4relay new design not supported - gracefully passing.")
        return st.report_pass("test_case_passed", "dhcp4relay new design is not there. so gracefully passing")

    vrf_a = 'Vrf22'
    vxlan_obj.config_vrf(nodes['leaf0'], vrf_a) 
    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=vrf_a, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=vrf_a, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan3, members=[vars.D3T1P3], vrf=vrf_a, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=vrf_a, add=True, tagged=True)    
    
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan1, prefix=dhcp_ipv4_prefix0, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan3, prefix=dhcp_ipv4_prefix3, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan2, prefix=dhcp_ipv4_prefix2, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan4, prefix=dhcp_ipv4_prefix4, add=True)
    
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan1, dhcpserver_ipv4=dhcpserver_ipv4_a, add=True)
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan3, dhcpserver_ipv4=dhcpserver_ipv4_b, add=True)
    
    result = dhcp_setup_ipv4_clients_verify(mhost=True, mclients=2)
    
    if not result:
        st.show(vars.D3, 'sudo ping -I {} {} -c 5'.format(vrf_a, dhcpserver_ipv4_a), skip_tmpl=True, skip_error_check=True)
        st.show(vars.D3, 'sudo ping -I {} {} -c 5'.format(vrf_a, dhcpserver_ipv4_b), skip_tmpl=True, skip_error_check=True)
    
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan1, dhcpserver_ipv4=dhcpserver_ipv4_a, add=False)
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan3, dhcpserver_ipv4=dhcpserver_ipv4_b, add=False)
    
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan1, prefix=dhcp_ipv4_prefix0, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan3, prefix=dhcp_ipv4_prefix3, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan2, prefix=dhcp_ipv4_prefix2, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan4, prefix=dhcp_ipv4_prefix4, add=False)

    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=vrf_a, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan3, members=[vars.D3T1P3], vrf=vrf_a, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=vrf_a, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=vrf_a, add=False, tagged=True)    

    vxlan_obj.config_vrf(nodes['leaf0'], vrf_a, add=False)

    if result:
        st.report_pass("test_case_passed", "test_dhcp_relay_ipv4_mvlan_new_vrf_tc2 passed")
    else:
        st.report_fail("test_case_failed", "test_dhcp_relay_ipv4_mvlan_new_vrf_tc2 failed")




######################################################################
##  IPv4-TC3: 2 dhcp relays on 2 non default vrf  
######################################################################
##
##  HOST0/dhcp_client ------- SD3/Leaf0 ------- HOST1/dhcp_server
##
##  <Vrf33>           VLAN10             VLAN20:ETH40   192.160.20.100
##                    192.160.10.254/24  192.160.20.1/24
##  
##  <Vrf36>           VLAN30             VLAN40:ETH44   192.160.40.100
##                    192.160.30.254/24  192.160.40.1/24
##
##  config dhcp_relay ipv4 helper add 10 192.160.20.100
##  config dhcp_relay ipv4 helper add 30 192.160.40.100
##
######################################################################

def test_dhcp_relay_ipv4_mvlan_new_vrf_tc3(dhcpv4_relay_flag_config_unconfig):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    if not check_dhcp4relay_support(vars.D3):
        st.log("Skipping: dhcp4relay new design not supported - gracefully passing.")
        return st.report_pass("test_case_passed", "dhcp4relay new design is not there. so gracefully passing")

    vrf_a = 'Vrf33'
    vxlan_obj.config_vrf(nodes['leaf0'], vrf_a) 
    vrf_b = 'Vrf36'
    vxlan_obj.config_vrf(nodes['leaf0'], vrf_b) 
    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=vrf_a, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=vrf_a, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan3, members=[vars.D3T1P3], vrf=vrf_b, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=vrf_b, add=True, tagged=True)    
    
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan1, prefix=dhcp_ipv4_prefix0, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan3, prefix=dhcp_ipv4_prefix3, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan2, prefix=dhcp_ipv4_prefix2, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan4, prefix=dhcp_ipv4_prefix4, add=True)
    
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan1, dhcpserver_ipv4=dhcpserver_ipv4_a, add=True)
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan3, dhcpserver_ipv4=dhcpserver_ipv4_b, add=True)
    
    result = dhcp_setup_ipv4_clients_verify(mhost=True, mclients=2)
    
    if not result:
        st.show(vars.D3, 'sudo ping -I {} {} -c 5'.format(vrf_a, dhcpserver_ipv4_a), skip_tmpl=True, skip_error_check=True)
        st.show(vars.D3, 'sudo ping -I {} {} -c 5'.format(vrf_b, dhcpserver_ipv4_b), skip_tmpl=True, skip_error_check=True)
    
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan1, dhcpserver_ipv4=dhcpserver_ipv4_a, add=False)
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan3, dhcpserver_ipv4=dhcpserver_ipv4_b, add=False)
    
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan1, prefix=dhcp_ipv4_prefix0, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan3, prefix=dhcp_ipv4_prefix3, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan2, prefix=dhcp_ipv4_prefix2, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan4, prefix=dhcp_ipv4_prefix4, add=False)

    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=vrf_b, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan3, members=[vars.D3T1P3], vrf=vrf_b, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=vrf_a, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=vrf_a, add=False, tagged=True)    

    vxlan_obj.config_vrf(nodes['leaf0'], vrf_b, add=False)
    vxlan_obj.config_vrf(nodes['leaf0'], vrf_a, add=False)

    if result:
        st.report_pass("test_case_passed", "test_dhcp_relay_ipv4_mvlan_new_vrf_tc3 passed")
    else:
        st.report_fail("test_case_failed", "test_dhcp_relay_ipv4_mvlan_new_vrf_tc3 failed")


######################################################################
##  IPv4-TC4: 2 dhcp relays in one default and one non default  
######################################################################
##
##  HOST0/dhcp_client ------- SD3/Leaf0 ------- HOST1/dhcp_server
##
##  <default>         VLAN10             VLAN20:ETH40   192.160.20.100
##                    192.160.10.254/24  192.160.20.1/24
##  
##  <Vrf44>           VLAN30             VLAN40:ETH44   192.160.40.100
##                    192.160.30.254/24  192.160.40.1/24
##
##  config dhcp_relay ipv4 helper add 10 192.160.20.100
##  config dhcp_relay ipv4 helper add 30 192.160.40.100
##
######################################################################

def test_dhcp_relay_ipv4_mvlan_new_vrf_tc4(dhcpv4_relay_flag_config_unconfig):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    if not check_dhcp4relay_support(vars.D3):
        st.log("Skipping: dhcp4relay new design not supported - gracefully passing.")
        return st.report_pass("test_case_passed", "dhcp4relay new design is not there. so gracefully passing")

    vrf_b = 'Vrf44'
    vxlan_obj.config_vrf(nodes['leaf0'], vrf_b) 
    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=None, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=None, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan3, members=[vars.D3T1P3], vrf=vrf_b, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=vrf_b, add=True, tagged=True)    
    
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan1, prefix=dhcp_ipv4_prefix0, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan3, prefix=dhcp_ipv4_prefix3, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan2, prefix=dhcp_ipv4_prefix2, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan4, prefix=dhcp_ipv4_prefix4, add=True)
    
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan1, dhcpserver_ipv4=dhcpserver_ipv4_a, add=True)
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan3, dhcpserver_ipv4=dhcpserver_ipv4_b, add=True)
    
    result = dhcp_setup_ipv4_clients_verify(mhost=True, mclients=2)
    
    if not result:
        st.show(vars.D3, 'sudo ping {} -c 5'.format(dhcpserver_ipv4_a), skip_tmpl=True, skip_error_check=True)
        st.show(vars.D3, 'sudo ping -I {} {} -c 5'.format(vrf_b, dhcpserver_ipv4_b), skip_tmpl=True, skip_error_check=True)
    
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan1, dhcpserver_ipv4=dhcpserver_ipv4_a, add=False)
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan3, dhcpserver_ipv4=dhcpserver_ipv4_b, add=False)
    
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan1, prefix=dhcp_ipv4_prefix0, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan3, prefix=dhcp_ipv4_prefix3, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan2, prefix=dhcp_ipv4_prefix2, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan4, prefix=dhcp_ipv4_prefix4, add=False)

    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=vrf_b, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan3, members=[vars.D3T1P3], vrf=vrf_b, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=None, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=None, add=False, tagged=True)    

    vxlan_obj.config_vrf(nodes['leaf0'], vrf_b, add=False)

    if result:
        st.report_pass("test_case_passed", "test_dhcp_relay_ipv4_mvlan_vrf_tc4 passed")
    else:
        st.report_fail("test_case_failed", "test_dhcp_relay_ipv4_mvlan_vrf_tc4 failed")


######################################################################
##  IPv4-TC5: 2 dhcp relays on default vrf 
######################################################################
##
##  HOST0/dhcp_client ------- SD3/Leaf0 ------- HOST1/dhcp_server
##
##                    VLAN10             VLAN20:ETH40   192.160.20.100
##                    192.160.10.254/24  192.160.20.1/24
##  <default Vrf>
##                    VLAN50            
##                    192.160.50.254/24
##
##  config dhcp_relay ipv4 helper add 10 192.160.20.100
##  config dhcp_relay ipv4 helper add 50 192.160.20.100
##
######################################################################

def test_dhcp_relay_ipv4_mvlan_default_vrf_tc5(dhcpv4_relay_flag_config_unconfig):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    if not check_dhcp4relay_support(vars.D3):
        st.log("Skipping: dhcp4relay new design not supported - gracefully passing.")
        return st.report_pass("test_case_passed", "dhcp4relay new design is not there. so gracefully passing")

    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=None, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=None, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan5, members=[vars.D3T1P3], vrf=None, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=None, add=True, tagged=True)    
    
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan1, prefix=dhcp_ipv4_prefix0, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan5, prefix=dhcp_ipv4_prefix5, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan2, prefix=dhcp_ipv4_prefix2, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan4, prefix=dhcp_ipv4_prefix4, add=True)
    
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan1, dhcpserver_ipv4=dhcpserver_ipv4_a, add=True)
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan5, dhcpserver_ipv4=dhcpserver_ipv4_a, add=True)
    
    result = dhcp_setup_ipv4_clients_verify(mhost=True, mclients=2, mserver=False)
    
    if not result:
        st.show(vars.D3, 'sudo ping {} -c 5'.format(dhcpserver_ipv4_a), skip_tmpl=True, skip_error_check=True)
    
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan1, dhcpserver_ipv4=dhcpserver_ipv4_a, add=False)
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan5, dhcpserver_ipv4=dhcpserver_ipv4_a, add=False)
    
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan1, prefix=dhcp_ipv4_prefix0, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan5, prefix=dhcp_ipv4_prefix5, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan2, prefix=dhcp_ipv4_prefix2, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan4, prefix=dhcp_ipv4_prefix4, add=False)

    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=None, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan5, members=[vars.D3T1P3], vrf=None, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=None, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=None, add=False, tagged=True)    

    
    if result:
        st.report_pass("test_case_passed", "test_dhcp_relay_ipv4_mvlan_default_vrf_tc5 passed")
    else:
        st.report_fail("test_case_failed", "test_dhcp_relay_ipv4_mvlan_default_vrf_tc5 failed")



######################################################################
##  IPv4-TC6: 2 dhcp relays on one non default vrf 
######################################################################
##
##  HOST0/dhcp_client ------- SD3/Leaf0 ------- HOST1/dhcp_server
##
##                    VLAN10             VLAN20:ETH40   192.160.20.100
##                    192.160.10.254/24  192.160.20.1/24
##  <Vrf66>
##                    VLAN50            
##                    192.160.50.254/24
##
##  config dhcp_relay ipv4 helper add 10 192.160.20.100
##  config dhcp_relay ipv4 helper add 50 192.160.20.100
##
######################################################################

def test_dhcp_relay_ipv4_mvlan_new_vrf_tc6(dhcpv4_relay_flag_config_unconfig):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    if not check_dhcp4relay_support(vars.D3):
        st.log("Skipping: dhcp4relay new design not supported - gracefully passing.")
        return st.report_pass("test_case_passed", "dhcp4relay new design is not there. so gracefully passing")

    vrf_a = 'Vrf66'
    vxlan_obj.config_vrf(nodes['leaf0'], vrf_a) 
    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=vrf_a, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=vrf_a, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan5, members=[vars.D3T1P3], vrf=vrf_a, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=vrf_a, add=True, tagged=True)    
    
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan1, prefix=dhcp_ipv4_prefix0, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan5, prefix=dhcp_ipv4_prefix5, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan2, prefix=dhcp_ipv4_prefix2, add=True)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan4, prefix=dhcp_ipv4_prefix4, add=True)
    
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan1, dhcpserver_ipv4=dhcpserver_ipv4_a, add=True)
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan5, dhcpserver_ipv4=dhcpserver_ipv4_a, add=True)
    
    result = dhcp_setup_ipv4_clients_verify(mhost=True, mclients=2, mserver=False)
    
    if not result:
        st.show(vars.D3, 'sudo ping -I {} {} -c 5'.format(vrf_a, dhcpserver_ipv4_a), skip_tmpl=True, skip_error_check=True)
    
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan1, dhcpserver_ipv4=dhcpserver_ipv4_a, add=False)
    config_dhcp_relay_ipv4_trig(vars.D3, vlan=dhcp_vlan5, dhcpserver_ipv4=dhcpserver_ipv4_a, add=False)
    
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan1, prefix=dhcp_ipv4_prefix0, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan5, prefix=dhcp_ipv4_prefix5, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan2, prefix=dhcp_ipv4_prefix2, add=False)
    config_dhcp_relay_ipv4_vlan(vars.D3, vlan=dhcp_vlan4, prefix=dhcp_ipv4_prefix4, add=False)

    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=vrf_a, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan5, members=[vars.D3T1P3], vrf=vrf_a, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=vrf_a, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=vrf_a, add=False, tagged=True)    

    vxlan_obj.config_vrf(nodes['leaf0'], vrf_a, add=False)

    if result:
        st.report_pass("test_case_passed", "test_dhcp_relay_ipv4_mvlan_new_vrf_tc6 passed")
    else:
        st.report_fail("test_case_failed", "test_dhcp_relay_ipv4_mvlan_new_vrf_tc6 failed")
