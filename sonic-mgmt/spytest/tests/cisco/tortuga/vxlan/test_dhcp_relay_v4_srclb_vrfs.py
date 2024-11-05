import os
import yaml
import pytest

from spytest import st, tgapi, SpyTestDict
import apis.system.basic as basic_obj
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import vxlan_utils as vxlan_obj
import tortuga_common_utils as common_obj

####################################################################
##
##  Topology : 1 Leaf(D3)
##
##  IPv4: HOST0/dhcp_client - SD3/Leaf0 - HOST1/dhcp_server
##
####################################################################

CONFIGS_FILE = 'test_dhcp_relay_basic_template.yaml'

loopback_a = "Loopback11"
loopback_prefix1 = "11.11.11.11/32"
loopback_b = "Loopback22"
loopback_prefix2 = "22.22.22.22/32"

sag_mac_addr = "00:11:22:33:44:55"

dhcp_vlan1 = "10"
dhcp_vlan2 = "20"
dhcp_vlan3 = "30"
dhcp_vlan4 = "40"
dhcp_vlan5 = "50"

dhcp_mac_addr1 = "00:0a:01:00:11:01"
dhcp_mac_addr2 = "00:0a:01:00:12:01"
dhcp_mac_addr3 = "00:0a:01:00:13:01"
dhcp_mac_addr4 = "00:0a:01:00:14:01"
dhcp_mac_addr5 = "00:0a:01:00:15:01"

dhcp_vlan_ipv4_addr1 = "192.168.10.1"
dhcp_vlan_ipv4_addr2 = "192.168.20.1"
dhcp_vlan_ipv4_addr3 = "192.168.30.1"
dhcp_vlan_ipv4_addr4 = "192.168.40.1"
dhcp_vlan_ipv4_addr5 = "192.168.50.1"

dhcpserver_ipv4_a = "192.168.20.100"
dhcp_ipv4_assigned_st_a = "192.168.10.60"
dhcp_ipv4_set_a =  {"192.168.10.60", "192.168.10.61","192.168.10.62","192.168.10.63","192.168.10.64", 
                    "192.168.10.65", "192.168.10.66","192.168.10.67","192.168.10.68","192.168.10.69",
                    "192.168.10.70", "192.168.10.71","192.168.10.72","192.168.10.73","192.168.10.74"}

dhcp_ipv4_assigned_st_c = "192.168.50.60"
dhcp_ipv4_set_c =  {"192.168.50.60", "192.168.50.61","192.168.50.62","192.168.50.63","192.168.50.64",
                    "192.168.50.65", "192.168.50.66","192.168.50.67","192.168.50.68","192.168.50.69"}

dhcpserver_ipv4_b = "192.168.40.100"
dhcp_ipv4_assigned_st_b = "192.168.30.80"
dhcp_ipv4_set_b =  {"192.168.30.80", "192.168.30.81","192.168.30.82","192.168.30.83","192.168.30.84",
                    "192.168.30.85", "192.168.30.86","192.168.30.87","192.168.30.88","192.168.30.89",
                    "192.168.30.90", "192.168.30.91","192.168.30.92","192.168.30.93","192.168.30.94"}


dhcp_ipv4_prefix0  = "192.168.10.254/24"
dhcp_ipv4_prefix1  = "192.168.10.1/24"
dhcp_ipv4_prefix2  = "192.168.20.1/24"
dhcp_ipv4_prefix3  = "192.168.30.254/24"
dhcp_ipv4_prefix4  = "192.168.40.1/24"
dhcp_ipv4_prefix5  = "192.168.50.1/24"


def config_loopback_vrf(node, loopback=None, prefix=None, vrf=None, add=True):
    if add:
        if vrf:
            st.config(node, "config interface vrf bind {} {}".format(loopback, vrf))
        if prefix:
            st.config(node, "config interface ip add {} {}".format(loopback, prefix))
    else: 
        if prefix:
            st.config(node, "config interface ip remove {} {}".format(loopback, prefix))
        if vrf:
            st.config(node, "config interface vrf unbind {}".format(loopback))


def config_dhcp_relay_ipv4_sag(node, loopback1=loopback_a, loopback2=None, cvlan1=dhcp_vlan1, cvlan2=None, add=True):

    if add:
        st.config(node, "config static-anycast-gateway mac_address add {}".format(sag_mac_addr))
        st.config(node, "config vlan static-anycast-gateway enable {}".format(cvlan1))
        st.config(node, "config vlan dhcp-relay-src add {} {}".format(cvlan1, loopback1))

        if loopback2:
            st.config(node, "config vlan static-anycast-gateway enable {}".format(cvlan2))
            st.config(node, "config vlan dhcp-relay-src add {} {}".format(cvlan2, loopback2))
    else: 
        if loopback2:
            st.config(node, "config vlan dhcp-relay-src del {}".format(cvlan2))
            st.config(node, "config vlan static-anycast-gateway disable {}".format(cvlan2))

        st.config(node, "config vlan dhcp-relay-src del {}".format(cvlan1))
        st.config(node, "config vlan static-anycast-gateway disable {}".format(cvlan1))
        st.config(node, "config static-anycast-gateway mac_address del")


def config_dhcp_relay_ipv4_vlans(node, cvlan1=dhcp_vlan1, cvlan2=None, svlan1=dhcp_vlan2, svlan2=None, add=True):
    if add:
        st.config(node, "config interface ip add Vlan{} {}".format(svlan1, dhcp_ipv4_prefix2))
        if svlan2:
            st.config(node, "config interface ip add Vlan{} {}".format(svlan2, dhcp_ipv4_prefix4))

        st.config(node, "config interface ip add Vlan{} {}".format(cvlan1, dhcp_ipv4_prefix0))
        if cvlan2:
            if cvlan2 == dhcp_vlan3:
                st.config(node, "config interface ip add Vlan{} {}".format(cvlan2, dhcp_ipv4_prefix3))
            else:
                st.config(node, "config interface ip add Vlan{} {}".format(cvlan2, dhcp_ipv4_prefix5))
    else:
        if cvlan2:
            if cvlan2 == dhcp_vlan3:
                st.config(node, "config interface ip remove Vlan{} {}".format(cvlan2, dhcp_ipv4_prefix3))
            else:
                st.config(node, "config interface ip remove Vlan{} {}".format(cvlan2, dhcp_ipv4_prefix5))
        st.config(node, "config interface ip remove Vlan{} {}".format(cvlan1, dhcp_ipv4_prefix0))

        st.config(node, "config interface ip remove Vlan{} {}".format(svlan1, dhcp_ipv4_prefix2))
        if svlan2:
            st.config(node, "config interface ip remove Vlan{} {}".format(svlan2, dhcp_ipv4_prefix4))


def config_dhcp_relay_ipv4_trigs(node, cvlan1=dhcp_vlan1, cvlan2=None, add=True):
    if add:
        if cvlan2:
            st.config(node, "config vlan dhcp_relay add {} {}".format(cvlan2, dhcpserver_ipv4_b))
        st.config(node, "config vlan dhcp_relay add {} {}".format(cvlan1, dhcpserver_ipv4_a))
    else:
        if cvlan2:
            st.config(node, "config vlan dhcp_relay del {} {}".format(cvlan2, dhcpserver_ipv4_b))
        st.config(node, "config vlan dhcp_relay del {} {}".format(cvlan1, dhcpserver_ipv4_a))


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
                                                    ipaddress_count='30', ipaddress_pool=[dhcp_ipv4_assigned_st_a, dhcp_ipv4_assigned_st_c], handle=h2['handle'],
                                                    count='1', local_mac=dhcp_mac_addr2, ip_address=dhcpserver_ipv4_a,
                                                    ip_gateway=dhcp_vlan_ipv4_addr2, remote_mac=dut_mac, pool_count=2, 
                                                    subnet_addr_assign=1, subnet='link_selection')
    else:
        s_conf2 = tg2.tg_emulation_dhcp_server_config(mode='create', ip_version='4', encapsulation='ethernet_ii_vlan', vlan_id=dhcp_vlan2,
                                                    ipaddress_count='30', ipaddress_pool=dhcp_ipv4_assigned_st_a, handle=h2['handle'],
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
                                                ipaddress_count='30', ipaddress_pool=dhcp_ipv4_assigned_st_b, handle=h4['handle'],
                                                count='1', local_mac=dhcp_mac_addr4, ip_address=dhcpserver_ipv4_b,
                                                ip_gateway=dhcp_vlan_ipv4_addr4, remote_mac=dut_mac, pool_count=1, 
                                                subnet_addr_assign=1, subnet='link_selection')
        else:
            s_conf4 = tg4.tg_emulation_dhcp_server_config(mode='create', ip_version='4', encapsulation='ethernet_ii_vlan', vlan_id=dhcp_vlan4,
                                                ipaddress_count='30', ipaddress_pool=dhcp_ipv4_assigned_st_b, handle=h4['handle'],
                                                count='1', local_mac=dhcp_mac_addr4, ip_address=dhcpserver_ipv4_b,
                                                ip_gateway=dhcp_vlan_ipv4_addr4, remote_mac=dut_mac, pool_count=1)

        s_con4 = tg4.tg_emulation_dhcp_server_control(action='connect', dhcp_handle=s_conf4['dhcp_handle'])
        st.log("dhcp relay ipv4 basic server B control {}".format(s_con4))



def dhcp_setup_ipv4_clients_verify(mhost=False, mclients=2):

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
        if key == 'session':
            for _, val2 in val.items():
                st.log("dhcp relay ipv4 basic client ipAddr {} cnt_a={}".format(val2['Address'], cnt_a))
                if val2['Address'] not in dhcp_ipv4_set_a:
                    st.log("dhcp client A does not be assigned ipv4 addr set_a from dhcp server")
                    return False
                else:
                    cnt_a = cnt_a + 1 
    
    
    # DHCP ClientB 
    
    if mhost:
    
        dhcp_vlan = dhcp_vlan3
 
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
            if key == 'session':
                for _, val2 in val.items():
                    st.log("dhcp relay ipv4 basic client ipAddr {}".format(val2['Address']))
                    if val2['Address'] not in dhcp_ipv4_set_b:
                        st.log("dhcp client B does not be assigned ipv4 addr set_b from dhcp server")
                        return False
                    else:
                        cnt_b = cnt_b + 1 
    
    
    st.log("dhcp relay full PASS cnt_a={} cnt_b={} cnt_c={}".format(cnt_a, cnt_b, cnt_c))
    
    return True 





######################################################################
##  IPv4-TC1: one dhcp relay in default vrf 
######################################################################
##
##  HOST0/dhcp_client ------- SD3/Leaf0 ------- HOST1/dhcp_server
##
##  <default Vrf>
##                    VLAN10             VLAN20:ETH40   192.168.20.100
##                    192.168.10.254/24  192.168.20.1/24
##
##                    RELAY_AGENT as LOOPBACK: 11.11.11.11
##                    LINKSELECT  as SAG IP:   192.168.10.254
##
##  config static-anycast-gateway mac_address add 00:11:22:33:44:55
##  config vlan static-anycast-gateway enable 10
##  config vlan dhcp_relay add 10 192.168.20.100
##
######################################################################

def test_dhcp_relay_ipv4_default_vrf_srclb_vrfs_tc1():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    config_loopback_vrf(nodes['leaf0'], loopback=loopback_a, prefix=loopback_prefix1, vrf=None, add=True)
    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=None, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=None, add=True, tagged=True)    
    
    config_dhcp_relay_ipv4_vlans(vars.D3, cvlan1=dhcp_vlan1, cvlan2=None, svlan1=dhcp_vlan2, svlan2=None, add=True)
    config_dhcp_relay_ipv4_sag(vars.D3, loopback1=loopback_a, loopback2=None, cvlan1=dhcp_vlan1, cvlan2=None, add=True)
    config_dhcp_relay_ipv4_trigs(vars.D3, cvlan1=dhcp_vlan1, cvlan2=None, add=True)
    
    result = dhcp_setup_ipv4_clients_verify(mhost=False, mclients=2)
    
    config_dhcp_relay_ipv4_trigs(vars.D3, cvlan1=dhcp_vlan1, cvlan2=None, add=False)
    config_dhcp_relay_ipv4_sag(vars.D3, loopback1=loopback_a, loopback2=None, cvlan1=dhcp_vlan1, cvlan2=None, add=False)
    config_dhcp_relay_ipv4_vlans(vars.D3, cvlan1=dhcp_vlan1, cvlan2=None, svlan1=dhcp_vlan2, svlan2=None, add=False)

    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=None, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=None, add=False, tagged=True)    

    config_loopback_vrf(nodes['leaf0'], loopback=loopback_a, prefix=loopback_prefix1, vrf=None, add=False)
    
    if result:
        st.report_pass("test_case_passed", "test_dhcp_relay_ipv4_default_vrf_srclb_vrfs_tc1 passed")
    else:
        st.report_fail("test_case_failed", "test_dhcp_relay_ipv4_default_vrf_srclb_vrfs_tc1 failed")



######################################################################
##  IPv4-TC2: one dhcp relay in non default vrf 
######################################################################
##
##  HOST0/dhcp_client ------- SD3/Leaf0 ------- HOST1/dhcp_server
##  <Vrf01>
##                    VLAN10/SAG      VLAN20         192.168.20.100
##                    192.168.10.254/24  192.168.20.1/24
##
##                    RELAY_AGENT as LOOPBACK: 11.11.11.11
##                    LINKSELECT  as SAG IP:   192.168.10.254
##
##  config interface vrf bind Loopback0 Vrf01/Vlan10/Vlan20
##  config static-anycast-gateway mac_address add 00:11:22:33:44:55
##  config vlan static-anycast-gateway enable 10
##  config vlan dhcp_relay add 10 192.168.20.100
##
######################################################################

def test_dhcp_relay_ipv4_one_non_default_vrf_srclb_vrfs_tc2():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    vrf_a = 'Vrf01'
    vxlan_obj.config_vrf(nodes['leaf0'], vrf_a) 
    config_loopback_vrf(nodes['leaf0'], loopback=loopback_a, prefix=loopback_prefix1, vrf=vrf_a, add=True)
    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=vrf_a, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=vrf_a, add=True, tagged=True)    
    
    config_dhcp_relay_ipv4_vlans(vars.D3, cvlan1=dhcp_vlan1, cvlan2=None, svlan1=dhcp_vlan2, svlan2=None, add=True)
    config_dhcp_relay_ipv4_sag(vars.D3, loopback1=loopback_a, loopback2=None, cvlan1=dhcp_vlan1, cvlan2=None, add=True)
    config_dhcp_relay_ipv4_trigs(vars.D3, cvlan1=dhcp_vlan1, cvlan2=None, add=True)
    
    result = dhcp_setup_ipv4_clients_verify(mhost=False, mclients=2)
    
    config_dhcp_relay_ipv4_trigs(vars.D3, cvlan1=dhcp_vlan1, cvlan2=None, add=False)
    config_dhcp_relay_ipv4_sag(vars.D3, loopback1=loopback_a, loopback2=None, cvlan1=dhcp_vlan1, cvlan2=None, add=False)
    config_dhcp_relay_ipv4_vlans(vars.D3, cvlan1=dhcp_vlan1, cvlan2=None, svlan1=dhcp_vlan2, svlan2=None, add=False)

    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=vrf_a, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=vrf_a, add=False, tagged=True)    

    config_loopback_vrf(nodes['leaf0'], loopback=loopback_a, prefix=loopback_prefix1, vrf=vrf_a, add=False)
    vxlan_obj.config_vrf(nodes['leaf0'], vrf_a, add=False)

    if result:
        st.report_pass("test_case_passed", "test_dhcp_relay_ipv4_one_non_default_vrf_srclb_vrfs_tc2 passed")
    else:
        st.report_fail("test_case_failed", "test_dhcp_relay_ipv4_one_non_default_vrf_srclb_vrfs_tc2 failed")




######################################################################
##  IPv4-TC3: one dhcp relay in each two non default vrfs with 2 clients  
######################################################################
##
##  HOST0/dhcp_client ------- SD3/Leaf0 ------- HOST1/dhcp_server
##  <Vrf01>
##                    VLAN10/SAG      VLAN20         192.168.20.100
##                    192.168.10.254/24  192.168.20.1/24
##                    RELAY_AGENT as LOOPBACK: 11.11.11.11
##                    LINKSELECT  as SAG IP:   192.168.10.254
##  <Vrf02>
##                    VLAN30/SAG      VLAN40         192.168.40.100
##                    192.168.30.254/24  192.168.40.1/24
##                    RELAY_AGENT as LOOPBACK: 22.22.22.22
##                    LINKSELECT  as SAG IP:   192.168.30.254
##
##  config interface vrf bind Loopback0 Vrf01/Vlan10/Vlan20
##  config interface vrf bind Loopback0 Vrf02/Vlan30/Vlan40
##  config static-anycast-gateway mac_address add 00:11:22:33:44:55
##  config vlan static-anycast-gateway enable 10
##  config vlan static-anycast-gateway enable 30
##  config vlan dhcp-relay-src add 10 Loopback11
##  config vlan dhcp-relay-src add 30 Loopback22
##  config vlan dhcp_relay add 10 192.168.20.100
##  config vlan dhcp_relay add 30 192.168.40.100
##
######################################################################

def test_dhcp_relay_ipv4_two_non_default_vrf_srclb_vrfs_tc3():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    vrf_a = 'Vrf01'
    vrf_b = 'Vrf02'
    
    vxlan_obj.config_vrf(nodes['leaf0'], vrf_a) 
    vxlan_obj.config_vrf(nodes['leaf0'], vrf_b) 
    
    config_loopback_vrf(nodes['leaf0'], loopback=loopback_a, prefix=loopback_prefix1, vrf=vrf_a, add=True)
    config_loopback_vrf(nodes['leaf0'], loopback=loopback_b, prefix=loopback_prefix2, vrf=vrf_b, add=True)
    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=vrf_a, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=vrf_a, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan3, members=[vars.D3T1P3], vrf=vrf_b, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=vrf_b, add=True, tagged=True)    
    
    config_dhcp_relay_ipv4_vlans(vars.D3, cvlan1=dhcp_vlan1, cvlan2=dhcp_vlan3, svlan1=dhcp_vlan2, svlan2=dhcp_vlan4, add=True)
    config_dhcp_relay_ipv4_sag(vars.D3, loopback1=loopback_a, loopback2=loopback_b, cvlan1=dhcp_vlan1, cvlan2=dhcp_vlan3, add=True)
    config_dhcp_relay_ipv4_trigs(vars.D3, cvlan1=dhcp_vlan1, cvlan2=dhcp_vlan3, add=True)
    
    result = dhcp_setup_ipv4_clients_verify(mhost=True, mclients=2)
    
    config_dhcp_relay_ipv4_trigs(vars.D3, cvlan1=dhcp_vlan1, cvlan2=dhcp_vlan3, add=False)
    config_dhcp_relay_ipv4_sag(vars.D3, loopback1=loopback_a, loopback2=loopback_b, cvlan1=dhcp_vlan1, cvlan2=dhcp_vlan3, add=False)
    config_dhcp_relay_ipv4_vlans(vars.D3, cvlan1=dhcp_vlan1, cvlan2=dhcp_vlan3, svlan1=dhcp_vlan2, svlan2=dhcp_vlan4, add=False)

    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=vrf_b, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan3, members=[vars.D3T1P3], vrf=vrf_b, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=vrf_a, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=vrf_a, add=False, tagged=True)    

    config_loopback_vrf(nodes['leaf0'], loopback=loopback_b, prefix=loopback_prefix2, vrf=vrf_b, add=False)
    config_loopback_vrf(nodes['leaf0'], loopback=loopback_a, prefix=loopback_prefix1, vrf=vrf_a, add=False)

    vxlan_obj.config_vrf(nodes['leaf0'], vrf_b, add=False)
    vxlan_obj.config_vrf(nodes['leaf0'], vrf_a, add=False)

    if result:
        st.report_pass("test_case_passed", "test_dhcp_relay_ipv4_two_non_default_vrf_srclb_vrfs_tc3 passed")
    else:
        st.report_fail("test_case_failed", "test_dhcp_relay_ipv4_two_non_default_vrf_srclb_vrfs_tc3 failed")


######################################################################
##  IPv4-TCX: one dhcp relay in each two non default vrfs with 8x2 clients  
######################################################################
##
##  HOST0/dhcp_client ------- SD3/Leaf0 ------- HOST1/dhcp_server
##  <Vrf01>
##                    VLAN10/SAG      VLAN20         192.168.20.100
##                    192.168.10.254/24  192.168.20.1/24
##                    RELAY_AGENT as LOOPBACK: 11.11.11.11
##                    LINKSELECT  as SAG IP:   192.168.10.254
##  <Vrf02>
##                    VLAN30/SAG      VLAN40         192.168.40.100
##                    192.168.30.254/24  192.168.40.1/24
##                    RELAY_AGENT as LOOPBACK: 22.22.22.22
##                    LINKSELECT  as SAG IP:   192.168.30.254
##
##  config interface vrf bind Loopback0 Vrf01/Vlan10/Vlan20
##  config interface vrf bind Loopback0 Vrf02/Vlan30/Vlan40
##  config static-anycast-gateway mac_address add 00:11:22:33:44:55
##  config vlan static-anycast-gateway enable 10
##  config vlan static-anycast-gateway enable 30
##  config vlan dhcp-relay-src add 10 Loopback11
##  config vlan dhcp-relay-src add 30 Loopback22
##  config vlan dhcp_relay add 10 192.168.20.100
##  config vlan dhcp_relay add 30 192.168.40.100
##
######################################################################

def test_dhcp_relay_ipv4_two_non_default_vrf_srclb_vrfs_tc4():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    vrf_a = 'Vrf01'
    vrf_b = 'Vrf02'
    
    vxlan_obj.config_vrf(nodes['leaf0'], vrf_a) 
    vxlan_obj.config_vrf(nodes['leaf0'], vrf_b) 
    
    config_loopback_vrf(nodes['leaf0'], loopback=loopback_a, prefix=loopback_prefix1, vrf=vrf_a, add=True)
    config_loopback_vrf(nodes['leaf0'], loopback=loopback_b, prefix=loopback_prefix2, vrf=vrf_b, add=True)
    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=vrf_a, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=vrf_a, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan3, members=[vars.D3T1P3], vrf=vrf_b, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=vrf_b, add=True, tagged=True)    
    
    config_dhcp_relay_ipv4_vlans(vars.D3, cvlan1=dhcp_vlan1, cvlan2=dhcp_vlan3, svlan1=dhcp_vlan2, svlan2=dhcp_vlan4, add=True)
    config_dhcp_relay_ipv4_sag(vars.D3, loopback1=loopback_a, loopback2=loopback_b, cvlan1=dhcp_vlan1, cvlan2=dhcp_vlan3, add=True)
    config_dhcp_relay_ipv4_trigs(vars.D3, cvlan1=dhcp_vlan1, cvlan2=dhcp_vlan3, add=True)
    
    result = dhcp_setup_ipv4_clients_verify(mhost=True, mclients=8)
    
    config_dhcp_relay_ipv4_trigs(vars.D3, cvlan1=dhcp_vlan1, cvlan2=dhcp_vlan3, add=False)
    config_dhcp_relay_ipv4_sag(vars.D3, loopback1=loopback_a, loopback2=loopback_b, cvlan1=dhcp_vlan1, cvlan2=dhcp_vlan3, add=False)
    config_dhcp_relay_ipv4_vlans(vars.D3, cvlan1=dhcp_vlan1, cvlan2=dhcp_vlan3, svlan1=dhcp_vlan2, svlan2=dhcp_vlan4, add=False)

    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan4, members=[vars.D3T1P4], vrf=vrf_b, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan3, members=[vars.D3T1P3], vrf=vrf_b, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan2, members=[vars.D3T1P2], vrf=vrf_a, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcp_vlan1, members=[vars.D3T1P1], vrf=vrf_a, add=False, tagged=True)    

    config_loopback_vrf(nodes['leaf0'], loopback=loopback_b, prefix=loopback_prefix2, vrf=vrf_b, add=False)
    config_loopback_vrf(nodes['leaf0'], loopback=loopback_a, prefix=loopback_prefix1, vrf=vrf_a, add=False)

    vxlan_obj.config_vrf(nodes['leaf0'], vrf_b, add=False)
    vxlan_obj.config_vrf(nodes['leaf0'], vrf_a, add=False)

    if result:
        st.report_pass("test_case_passed", "test_dhcp_relay_ipv4_two_non_default_vrf_srclb_vrfs_tc4 passed")
    else:
        st.report_fail("test_case_failed", "test_dhcp_relay_ipv4_two_non_default_vrf_srclb_vrfs_tc4 failed")

