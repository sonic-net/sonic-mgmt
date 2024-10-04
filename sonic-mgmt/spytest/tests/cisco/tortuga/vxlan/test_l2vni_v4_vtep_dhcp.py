import os
import yaml
import pytest

from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import vxlan_utils as vxlan_obj
import tortuga_common_utils as common_obj

##
## config: eBGP + ECMP
##  Topology : 2x Spine + 2 Leafs
##
##  SD1 -- Spine0  - D1
##  SD2 -- Spine1  - D2
##  SD3 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4
##

CONFIGS_FILE = 'vxlan_l2vni_config_template.yaml'
LEAF0_VXLAN_IP = '10.200.200.200'
LEAF1_VXLAN_IP = '10.200.200.201'

dhcpclientv4_mac_addr = "00:0a:01:00:11:02"
dhcpserverv4_mac_addr = "00:0a:01:00:12:02"

dhcprelay_vlan2 = "2"

dhcpserver_ipv4 = "1.1.1.6"
dhcp_ipv4_assigned_start = "1.1.1.66"
dhcp_ipv4_set = {"1.1.1.66", "1.1.1.67", "1.1.1.68", "1.1.1.69"}
dhcpserver_vlan_ipv4_addr = "1.1.1.254"


def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

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
            common_obj.config_static(node, 'sonic', True, updated_config_file)
            st.wait(2)
            common_obj.config_static(node, 'bgp', True, updated_config_file)

    st.wait(60)
    yield vxlan_config_hooks

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            common_obj.config_static(node, 'bgp', False, updated_config_file)
            st.wait(2)
            common_obj.config_static(node, 'sonic', False, updated_config_file)

    vxlan_obj.remove_temp_config(updated_config_file)
   


def config_dhcp_relay_feature(node, enable=True):
    if enable:
        st.config(node, "config feature state dhcp_relay enabled")
    else:
        st.config(node, "config feature state dhcp_relay disabled")


def config_dhcp_gateway_ipv4(node, add=True):
    if add:
        st.config(node, "config interface ip add Vlan{} {}".format(dhcprelay_vlan2, dhcpserver_vlan_ipv4_addr))
    else:
        st.config(node, "config interface ip remove Vlan{} {}".format(dhcprelay_vlan2, dhcpserver_vlan_ipv4_addr))



def dhcp_l2vni_ipv4_setup_and_verification():

    st.banner("Start to test VxLAN L2VNO with dhcp v4")

    ## Verify Vtep state
    vxlan_obj.verify_vtep_state({"LEAF0_VXLAN_IP":LEAF0_VXLAN_IP,"LEAF1_VXLAN_IP":LEAF1_VXLAN_IP})

    vars = st.get_testbed_vars()

    # DHCP Server Config with switch
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D4P1")
    h2 = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=dhcpserver_ipv4, gateway=dhcpserver_vlan_ipv4_addr, src_mac_addr=dhcpserverv4_mac_addr,
                                arp_send_req='1', control_plane_mtu='9100',
                                resolve_gateway_mac='false')

    dut_mac = '78:D9:E8:36:60:00'
    s_conf2 = tg2.tg_emulation_dhcp_server_config(mode='create', ip_version='4',
                                                ipaddress_count='30', ipaddress_pool=dhcp_ipv4_assigned_start, handle=h2['handle'],
                                                count='1', local_mac=dhcpserverv4_mac_addr, ip_address=dhcpserver_ipv4,
                                                ip_gateway=dhcpserver_vlan_ipv4_addr, remote_mac=dut_mac, pool_count=1,
                                                subnet='link_selection')

    s_con2 = tg2.tg_emulation_dhcp_server_control(action='connect', dhcp_handle=s_conf2['dhcp_handle'])
    st.log("dhcp relay ipv4 basic server control {}".format(s_con2))


    # DHCP Client Config(Port Based)
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D3P1")
    conf1 = tg1.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_1)

    # 'ip_version' is mandatory to configure retry_count
    conf1 = tg1.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_1, retry_count='10', ip_version='4')
    st.log("dhcp relay ipv4 basic client config {}".format(conf1))

    group1 = tg1.tg_emulation_dhcp_group_config(handle=conf1['handles'], mode='create',
                                              num_sessions='2', mac_addr=dhcpclientv4_mac_addr, vlan_ether_type='0x8100',
                                              dhcp_range_ip_type=4, vlan_id_step=0, gateway_addresses=1, protocol_name='dhcpv4client', dhcp4_broadcast=1)
    st.log("dhcp relay ipv4 basic client gconfig {}".format(group1))

    tg1.tg_emulation_dhcp_stats(action='clear', port_handle=tg_ph_1)


    cont1 = tg1.tg_emulation_dhcp_control(port_handle=tg_ph_1, action="bind", handle=group1['handle'])
    st.log("EVPN l2vni dhcp ipv4 basic client bind {}".format(cont1))

    st.wait(15)

    rst1 = tg1.tg_emulation_dhcp_stats(port_handle=tg_ph_1, handle=conf1['handles'], mode='session', ip_version='4')
    st.log("EVPN l2vni dhcp ipv4 basic client result {}".format(rst1))

    for key, val in rst1.items():
        if key == 'session':
            for _, val2 in val.items():
                st.log("EVPN l2vni dhcp ipv4 basic client ipaddr {}".format(val2['Address']))
                if val2['Address'] not in dhcp_ipv4_set:
                    st.log("EVPN l2vni dhcp ipv4 basic fails on assigning the ip")
                    return False

    st.log("EVPN l2vni dhcp ipv4 basic pass on assigning the ip")

    return True


#############################################################################
##  IPv4 EVPN L2VNI BUM DHCP:
#############################################################################
##
##  HOST0/dhcp_client - SD3/Leaf0 - EVPN - SD4/Leaf1 - HOST1/dhcp_server
##                      VLAN2              VLAN2       1.1.1.6
##
#############################################################################
 
def test_dhcp_l2vni_ipv4_basic():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    config_dhcp_gateway_ipv4(vars.D4)
    config_dhcp_relay_feature(vars.D3, enable=False)
    config_dhcp_relay_feature(vars.D4, enable=False)
    
    result = dhcp_l2vni_ipv4_setup_and_verification()

    config_dhcp_relay_feature(vars.D4)
    config_dhcp_relay_feature(vars.D3)
    config_dhcp_gateway_ipv4(vars.D4, add=False)

    if result:
        st.report_pass('test_case_passed')  
    else:
        st.log("one or more traffic test failed")
        st.report_fail('test_case_failed')
