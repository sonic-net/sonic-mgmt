import os
import yaml
import pytest

from spytest import st, tgapi, SpyTestDict
import vxlan_utils as vxlan_obj
import apis.system.basic as basic_obj
import tortuga_common_utils as common_obj

##
##  Topology : 2 Spine + 2 Leafs + 2 Host
##
##  SD1 -- Spine0   - D1
##  SD2 -- Spine1   - D2
##
##  SD3 -- Leaf0  - D3
##  SD4 -- Leaf1  - D4
##
##

CONFIGS_FILE = 'vxlan_l2vni_v6_vtep_configs_template.yaml'

SPINE0_VTEP_IP = 'fd27::2cb:8b5a:196'
SPINE1_VTEP_IP = 'fd27::234:377f:6b3'
LEAF0_VTEP_IP  = 'fd27::280:10f1:25f'
LEAF1_VTEP_IP  = 'fd27::22d:b87f:214b'

dhcprelay_vlan2 = "100"

dhcpclientv6_mac_addr = "00:0a:01:00:13:02"
dhcpserverv6_mac_addr = "00:0a:01:00:14:02"

dhcpserver_ipv6 = "2001::1"
dhcp_ipv6_assigned_start = "2001::66"
dhcp_ipv6_set = {"2001:0:0:0:0:0:0:66", "2001:0:0:0:0:0:0:67", "2001:0:0:0:0:0:0:68", "2001:0:0:0:0:0:0:69"}
dhcprelay_ipv6_prefix1 = "2001::254/64"
dhcprelay_ipv6_prefix2 = "2001::254/64"
dhcpserver_vlan_ipv6_addr = "2001::254"


def config_dhcp_relay_feature(node, enable=True):
    if enable:
        st.config(node, "config feature state dhcp_relay enabled")
    else:
        st.config(node, "config feature state dhcp_relay disabled")


def config_dhcp_gateway_ipv6(node, add=True):
    if add:
        st.config(node, "config interface ip add Vlan{} {}".format(dhcprelay_vlan2, dhcpserver_vlan_ipv6_addr))
    else:
        st.config(node, "config interface ip remove Vlan{} {}".format(dhcprelay_vlan2, dhcpserver_vlan_ipv6_addr))


def config_node(node, config, type='', skip_errors=False):
    if type:
        st.config(node, config, type=type, skip_error_check = skip_errors, conf=True)
    else:
        st.config(node, config, skip_error_check = skip_errors, conf=True)


def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail(msg, dut)


@pytest.fixture(scope='module', autouse=True)
def setup_and_teardown():
    global handles
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic', True, updated_config_file)
            common_obj.config_static(node, 'bgp', True, updated_config_file)

    # sleep for 40 seconds for BGP to converge
    st.wait(40)

    yield 'setup_and_teardown'
    
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'bgp', False, updated_config_file)
            common_obj.config_static(node, 'sonic', False, updated_config_file)

    vxlan_obj.remove_temp_config(updated_config_file)



def dhcp_l2vni_ipv6_setup_and_verification():

    st.banner("Start to test VxLAN L2VNI on DHCP v6")

    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    # Test remote vtep status on LEAF0 and LEAF1
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VTEP_IP, LEAF1_VTEP_IP)


    # DHCP Server Config with switch
    tg4, tg_ph_4 = tgapi.get_handle_byname("T1D4P1")
    h4 = tg4.tg_interface_config(port_handle=tg_ph_4, ipv6_prefix_length='64', arp_send_req='1', ipv6_intf_addr=dhcpserver_ipv6,
                                src_mac_addr=dhcpserverv6_mac_addr, ipv6_resolve_gateway_mac='false',
                                mode='config', ipv6_gateway=dhcpserver_vlan_ipv6_addr, vlan_id=dhcprelay_vlan2)

    s_conf4 = tg4.tg_emulation_dhcp_server_config(count='1', mac_addr='00:10:94:00:00:04', server_emulation_mode='DHCPV6',
                                                handle=h4['handle'], prefix_pool_per_server='20', addr_pool_addresses_per_server='20',
                                                addr_pool_start_addr=dhcp_ipv6_assigned_start, prefix_pool_prefix_length='64', mode='create',
                                                prefix_pool_step='1', ip_version='6', 
                                                pool_address_increment='::0.0.0.1', pool_address_increment_step='::0.0.0.1',
                                                addr_pool_step_per_server='1', prefix_pool_start_addr='2001::', addr_pool_prefix_length='64')

    s_con4 = tg4.tg_emulation_dhcp_server_control(action='connect', dhcp_handle=s_conf4['dhcp_handle'], ip_version='6')
    st.log("dhcp relay ipv6 basic server control {}".format(s_con4))


    # DHCP Client Config(Port Based)
    tg3, tg_ph_3 = tgapi.get_handle_byname("T1D3P1")
    conf3 = tg3.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_3, ip_version='6')
    st.log("dhcp relay ipv6 basic client config {}".format(conf3))

    group3 = tg3.tg_emulation_dhcp_group_config(num_sessions='2', dhcp_range_ip_type='6', handle=conf3['handles'],
                                              vlan_id_step=0, vlan_cfi=0, client_mac_addr='00:10:01:00:00:01', mode='create',
                                              dhcp6_client_mode='DHCPV6', protocol_name='dhcpv6client',
                                              mac_addr=dhcpclientv6_mac_addr)
    st.log("dhcp relay ipv6 basic client gconfig {}".format(group3))

    tg3.tg_emulation_dhcp_stats(action='clear', port_handle=tg_ph_3)
    cont3 = tg3.tg_emulation_dhcp_control(port_handle=tg_ph_3, action="bind", handle=group3['handle'], ip_version='6')
    st.log("dhcp relay ipv6 basic client bind {}".format(cont3))

    st.wait(30)

    rst3 = tg3.tg_emulation_dhcp_stats(port_handle=tg_ph_3, handle=conf3['handles'], mode='session', ip_version='6')
    st.log("dhcp relay ipv6 basic client result {}".format(rst3))

    for key, val in rst3.items():
        if key == 'session':
            for _, val2 in val.items():
                st.log("EVPN L2VNI dhcp ipv6 basic client ipaddr {}".format(val2['Address']))
                if val2['Address'] not in dhcp_ipv6_set:
                    st.log("EVPN L2VNI dhcp ipv6 basic fails on assigning the ip")
                    return False

    st.log("EVPN L2VNI dhcp ipv6 basic pass on assigning the ip")

    return True


#########################################################################
##  IPv6 EVPN L2VNI BUM DHCP:
#########################################################################
##
##  HOST0/dhcp_client - SD3/Leaf0 - EVPN - SD4/Leaf1 - HOST1/dhcp_server
##                      VLAN100            VLAN100     2001::6
##
#########################################################################

def test_dhcp_l2vni_ipv6_basic():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    config_dhcp_gateway_ipv6(vars.D4)
    config_dhcp_relay_feature(vars.D3, enable=False)
    config_dhcp_relay_feature(vars.D4, enable=False)

    result = dhcp_l2vni_ipv6_setup_and_verification()

    config_dhcp_relay_feature(vars.D4)
    config_dhcp_relay_feature(vars.D3)
    config_dhcp_gateway_ipv6(vars.D4, add=False)

    if result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')
   
