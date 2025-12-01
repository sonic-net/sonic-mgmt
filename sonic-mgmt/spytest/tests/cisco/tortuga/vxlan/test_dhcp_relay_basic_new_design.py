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

##
##  Topology : 2 Leafs(D3 & D4)
##
##  IPv4: HOST0/dhcp_client - SD3/Leaf0 - HOST1/dhcp_server
##

CONFIGS_FILE = 'test_dhcp_relay_basic_template.yaml'

dhcprelay_vlan1 = "10"
dhcprelay_vlan2 = "20"

dhcpclientv4_mac_addr = "00:0a:01:00:11:01"
dhcpserverv4_mac_addr = "00:0a:01:00:12:01"
dhcpclientv6_mac_addr = "00:0a:01:00:13:01"
dhcpserverv6_mac_addr = "00:0a:01:00:14:01"

dhcpserver_ipv4 = "192.160.20.100"
dhcp_ipv4_assigned1 = "192.160.10.66"
dhcp_ipv4_assigned2 = "192.160.10.67"
dhcprelay_ipv4_prefix1 = "192.160.10.1/24"
dhcprelay_ipv4_prefix2 = "192.160.20.1/24"
dhcprelay_ipv4_prefix2_vrf = "192.160.20.0/24"
dhcpclient_vlan_ipv4_addr = "192.160.10.1"
dhcpserver_vlan_ipv4_addr = "192.160.20.1"


def config_dhcp_relay_ipv4_vrf(node, add=True):

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            common_obj.config_static(node, 'bgp', True, updated_config_file)
        else:
            common_obj.config_static(node, 'bgp', False, updated_config_file)
        st.wait(2)

def config_dhcp_relay_ipv4(node, add=True):
    if add:
        st.config(node, "config interface ip add Vlan{} {}".format(dhcprelay_vlan1, dhcprelay_ipv4_prefix1))
        st.config(node, "config interface ip add Vlan{} {}".format(dhcprelay_vlan2, dhcprelay_ipv4_prefix2))
        st.config(node, "config dhcpv4_relay add Vlan{} --dhcpv4-servers {}".format(dhcprelay_vlan1, dhcpserver_ipv4))
    else:
        st.config(node, "config dhcpv4_relay del Vlan{} --dhcpv4-servers {}".format(dhcprelay_vlan1, dhcpserver_ipv4))
        st.config(node, "config interface ip remove Vlan{} {}".format(dhcprelay_vlan2, dhcprelay_ipv4_prefix2))
        st.config(node, "config interface ip remove Vlan{} {}".format(dhcprelay_vlan1, dhcprelay_ipv4_prefix1))


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

    yield dhcp_relay_config_hooks

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            common_obj.config_static(node, 'sonic', False, updated_config_file)
            st.wait(2)

    vxlan_obj.remove_temp_config(updated_config_file)



def dhcp_setup_verify_ipv4(linksel=False):
    vars = st.get_testbed_vars()

    # DHCP Server Config with switch
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D3P2")
    h1 = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=dhcpserver_ipv4, gateway=dhcpserver_vlan_ipv4_addr, src_mac_addr=dhcpserverv4_mac_addr,
                                arp_send_req='1', control_plane_mtu='9100', vlan='1', vlan_id=dhcprelay_vlan2,
                                resolve_gateway_mac='false')

    dut_mac = basic_obj.get_ifconfig_ether(vars.D3, 'Vlan{}'.format(dhcprelay_vlan2))
    st.log("dhcp relay dut_mac {}".format(dut_mac))

    if linksel:
        s_conf2 = tg2.tg_emulation_dhcp_server_config(mode='create', ip_version='4', encapsulation='ethernet_ii_vlan', vlan_id=dhcprelay_vlan2,
                                                    ipaddress_count='30', ipaddress_pool=dhcp_ipv4_assigned1, handle=h1['handle'],
                                                    count='1', local_mac=dhcpserverv4_mac_addr, ip_address=dhcpserver_ipv4,
                                                    ip_gateway=dhcpserver_vlan_ipv4_addr, remote_mac=dut_mac, pool_count=1, 
                                                    subnet_addr_assign=1, subnet='link_selection')
    else:
        s_conf2 = tg2.tg_emulation_dhcp_server_config(mode='create', ip_version='4', encapsulation='ethernet_ii_vlan', vlan_id=dhcprelay_vlan2,
                                                    ipaddress_count='30', ipaddress_pool=dhcp_ipv4_assigned1, handle=h1['handle'],
                                                    count='1', local_mac=dhcpserverv4_mac_addr, ip_address=dhcpserver_ipv4,
                                                    ip_gateway=dhcpserver_vlan_ipv4_addr, remote_mac=dut_mac, pool_count=1)

    s_con2 = tg2.tg_emulation_dhcp_server_control(action='connect', dhcp_handle=s_conf2['dhcp_handle'])
    st.log("dhcp relay ipv4 basic server control {}".format(s_con2))


    # DHCP Client Config(Port Based)
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D3P1")
    conf1 = tg1.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_1)

    # 'ip_version' is mandatory to configure retry_count
    conf1 = tg1.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_1, retry_count='10', ip_version='4')
    st.log("dhcp relay ipv4 basic client config {}".format(conf1))

    group1 = tg1.tg_emulation_dhcp_group_config(handle=conf1['handles'], mode='create', encap='ethernet_ii_vlan', vlan_id_count='2',
                                              num_sessions='2', mac_addr=dhcpclientv4_mac_addr, vlan_id=dhcprelay_vlan1, vlan_ether_type='0x8100',
                                              dhcp_range_ip_type=4, vlan_id_step=0, gateway_addresses=1, protocol_name='dhcpv4client', dhcp4_broadcast=1)
    st.log("dhcp relay ipv4 basic client gconfig {}".format(group1))

    tg1.tg_emulation_dhcp_stats(action='clear', port_handle=tg_ph_1)


    cont1 = tg1.tg_emulation_dhcp_control(port_handle=tg_ph_1, action="bind", handle=group1['handle'])
    st.log("dhcp relay ipv4 basic client bind {}".format(cont1))

    st.wait(15)

    rst1 = tg1.tg_emulation_dhcp_stats(port_handle=tg_ph_1, handle=conf1['handles'], mode='session', ip_version='4')
    st.log("dhcp relay ipv4 basic client result {}".format(rst1))

    for key, val in rst1.items():
        if key == 'session':
            for _, val2 in val.items():
                st.log("dhcp relay ipv4 basic client ipaddr {}".format(val2['Address']))
                if val2['Address'] not in [dhcp_ipv4_assigned1, dhcp_ipv4_assigned2]:
                    st.log("dhcp relay ipv4 basic fail on assigning the ip")
                    return False

    st.log("dhcp relay ipv4 basic pass on assigning the ip")

    return True 


######################################################################
##  IPv4 2VLANS:
######################################################################
##
##  HOST0/dhcp_client ------- SD3/Leaf0 ------- HOST1/dhcp_server
##                    VLAN10           VLAN20         192.160.20.100
##                    192.160.10.1/24  192.160.20.1/24
##                    RELAY_AGENT
##
##  config vlan dhcp_relay add 10 192.160.20.100
##
######################################################################

def test_dhcp_relay_ipv4_2vlans(dhcpv4_relay_flag_config_unconfig):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    if not check_dhcp4relay_support(vars.D3):
        st.log("Skipping: dhcp4relay new design not supported - gracefully passing.")
        return st.report_pass("test_case_passed", "dhcp4relay new design is not there. so gracefully passing")

    for dut in st.get_dut_names():
        output = st.config(dut, "show vlan brief")
        st.log(output)
        st.wait(3)

    vxlan_obj.config_vlan(nodes['leaf0'], dhcprelay_vlan1, members=[vars.D3T1P1], vrf=None, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcprelay_vlan2, members=[vars.D3T1P2], vrf=None, add=True, tagged=True)    
    
    config_dhcp_relay_ipv4(vars.D3)
    
    result = dhcp_setup_verify_ipv4()
    
    config_dhcp_relay_ipv4(vars.D3, add=False)

    vxlan_obj.config_vlan(nodes['leaf0'], dhcprelay_vlan2, members=[vars.D3T1P2], vrf=None, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcprelay_vlan1, members=[vars.D3T1P1], vrf=None, add=False, tagged=True)    
    
    if result:
        st.report_pass("test_case_passed", "test_dhcp_relay_ipv4_2vlans passed")
    else:
        st.report_fail("test_case_failed", "test_dhcp_relay_ipv4_2vlans failed")


######################################################################
##  IPv4 2VLANS on new SINGLE VRF:
######################################################################
##
##  HOST0/dhcp_client ------- SD3/Leaf0 ------- HOST1/dhcp_server
##                    VLAN10           VLAN20         192.160.20.100
##                    192.160.10.1/24  192.160.20.1/24
##                    RELAY_AGENT
##
##  config interface vrf bind Vlan10 Vrf01
##  config interface vrf bind Vlan20 Vrf01
##  config vlan dhcp_relay add 10 192.160.20.100
##
######################################################################

def test_dhcp_relay_ipv4_single_vrf(dhcpv4_relay_flag_config_unconfig):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    if not check_dhcp4relay_support(vars.D3):
        st.log("Skipping: dhcp4relay new design not supported - gracefully passing.")
        return st.report_pass("test_case_passed", "dhcp4relay new design is not there. so gracefully passing")

    for dut in st.get_dut_names():
        output = st.config(dut, "show vlan brief")
        st.log(output)
        output = st.config(dut, "show vrf")
        st.log(output)

    vrf = 'Vrf01'
    
    vxlan_obj.config_vrf(nodes['leaf0'], vrf) 
    vxlan_obj.config_vlan(nodes['leaf0'], dhcprelay_vlan1, members=[vars.D3T1P1], vrf=vrf, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcprelay_vlan2, members=[vars.D3T1P2], vrf=vrf, add=True, tagged=True)    
    
    config_dhcp_relay_ipv4(vars.D3)
    
    result = dhcp_setup_verify_ipv4()
    
    config_dhcp_relay_ipv4(vars.D3, add=False)

    vxlan_obj.config_vlan(nodes['leaf0'], dhcprelay_vlan2, members=[vars.D3T1P2], vrf=vrf, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcprelay_vlan1, members=[vars.D3T1P1], vrf=vrf, add=False, tagged=True)    
    vxlan_obj.config_vrf(nodes['leaf0'], vrf, add=False) 
 
    if result:
        st.report_pass("test_case_passed", "test_dhcp_relay_ipv4_single_vrf passed")
    else:
        st.report_fail("test_case_failed", "test_dhcp_relay_ipv4_single_vrf failed")


"""
@pytest.mark.skip(reason="not required for tortuga beta")
def test_dhcp_relay_ipv4_diff_vrf(dhcpv4_relay_flag_config_unconfig):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    if not check_dhcp4relay_support(vars.D3):
        st.log("Skipping: dhcp4relay new design not supported - gracefully passing.")
        return st.report_pass("test_case_passed", "dhcp4relay new design is not there. so gracefully passing")

    vrf1 = 'Vrf01'
    vrf2 = 'Vrf02'
    
    vxlan_obj.config_vrf(nodes['leaf0'], vrf1) 
    vxlan_obj.config_vrf(nodes['leaf0'], vrf2) 
    vxlan_obj.config_vlan(nodes['leaf0'], dhcprelay_vlan1, members=[vars.D3T1P1], vrf=vrf1, add=True, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcprelay_vlan2, members=[vars.D3T1P2], vrf=vrf2, add=True, tagged=True)    
    
    config_dhcp_relay_ipv4(vars.D3)
    config_dhcp_relay_ipv4_vrf(vars.D3)
    
    result = dhcp_setup_verify_ipv4(linksel=True)
    
    config_dhcp_relay_ipv4_vrf(vars.D3, add=False)
    config_dhcp_relay_ipv4(vars.D3, add=False)

    vxlan_obj.config_vlan(nodes['leaf0'], dhcprelay_vlan2, members=[vars.D3T1P2], vrf=vrf2, add=False, tagged=True)    
    vxlan_obj.config_vlan(nodes['leaf0'], dhcprelay_vlan1, members=[vars.D3T1P1], vrf=vrf1, add=False, tagged=True)    
    vxlan_obj.config_vrf(nodes['leaf0'], vrf2, add=False) 
    vxlan_obj.config_vrf(nodes['leaf0'], vrf1, add=False) 
 
    if result:
        st.report_pass("test_case_passed", "test_dhcp_relay_ipv4_diff_vrf passed")
    else:
        st.report_fail("test_case_failed", "test_dhcp_relay_ipv4_diff_vrf failed")
"""
