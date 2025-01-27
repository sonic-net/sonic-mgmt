from spytest import st, tgapi, SpyTestDict
import tgen_utils_cmn as tgen_utils
import yaml
import os
import re
import time
import pytest
import vxlan_utils as vxlan_obj

################################################################################
##  DHCP IXIA configs
################################################################################
##  TARGET TOPOLOGY: VTEP6-L3VNI + DHCP_RELAY_V4
################################################################################
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
##
##  DHCP SERVER A4  50.50.50.99
##
################################################################################

vlan2  = "2"
vlan3  = "3"
vlan4  = "4"
vlan5  = "5"
vlan10 = "10"

dhcpv4_mac_addr_a1 = "00:0a:01:00:3a:01"
dhcpv4_mac_addr_a2 = "00:0a:01:00:3b:01"
dhcpv4_mac_addr_a3 = "00:0a:01:00:3c:01"
dhcpv4_mac_addr_a4 = "00:0a:01:00:3d:01"

dut_mac_server1 = '78:D9:E8:36:60:00'
dut_mac_server2 = '78:D9:E8:36:60:01'

dhcpserverv4_a4             = "50.50.50.99"
dhcpserverv4_vlan_a4        = "50.50.50.1"

dhcp_ipv4_assigned_start_b2 = "20.20.20.30"
dhcp_ipv4_set_b2 = {"20.20.20.30", "20.20.20.31", "20.20.20.32", "20.20.20.33", "20.20.20.34", "20.20.20.35"}

dhcp_ipv4_assigned_start_b3 = "30.30.30.30"
dhcp_ipv4_set_b3 = {"30.30.30.30", "30.30.30.31", "30.30.30.32", "30.30.30.33", "30.30.30.34", "30.30.30.35"}

dhcp_ipv4_assigned_start_b4 = "40.40.40.30"
dhcp_ipv4_set_b4 = {"40.40.40.30", "40.40.40.31", "40.40.40.32", "40.40.40.33", "40.40.40.34", "40.40.40.35"}

dhcp_ipv4_assigned_start_b5 = "50.50.50.30"
dhcp_ipv4_set_b5 = {"50.50.50.30", "50.50.50.31", "50.50.50.32", "50.50.50.33", "50.50.50.34", "50.50.50.35"}


dhcpv4_mac_addr_b1 = "00:0a:01:00:4a:01"
dhcpv4_mac_addr_b2 = "00:0a:01:00:4b:01"
dhcpv4_mac_addr_b3 = "00:0a:01:00:4c:01"
dhcpv4_mac_addr_b4 = "00:0a:01:00:4d:01"

dhcpserverv4_b2             = "30.30.30.99"
dhcpserverv4_vlan_b2        = "30.30.30.1"

dhcp_ipv4_assigned_start_a2 = "20.20.20.40"
dhcp_ipv4_set_a2 = {"20.20.20.40", "20.20.20.41", "20.20.20.42", "20.20.20.43", "20.20.20.44", "20.20.20.45"}

dhcp_ipv4_assigned_start_a3 = "30.30.30.40"
dhcp_ipv4_set_a3 = {"30.30.30.40", "30.30.30.41", "30.30.30.42", "30.30.30.43", "30.30.30.44", "30.30.30.45"}

dhcp_ipv4_assigned_start_a4 = "40.40.40.40"
dhcp_ipv4_set_a4 = {"40.40.40.40", "40.40.40.41", "40.40.40.42", "40.40.40.43", "40.40.40.44", "40.40.40.45"}

dhcp_ipv4_assigned_start_a5 = "50.50.50.40"
dhcp_ipv4_set_a5 = {"50.50.50.40", "50.50.50.41", "50.50.50.42", "50.50.50.43", "50.50.50.44", "50.50.50.45"}


VRF_NAME1 = "Vrf101"
VRF_NAME2 = "Vrf102"


def dhcp_l3vni_ipv4_setup_server_client(dual_servers=True, linksel=True, leaf0_clients=0, dual_clients=0, client_cleanup=True):
    vars = st.get_testbed_vars()

    st.log("Start to create L3VNI DHCP Server leaf0_clients={} dual_clients={}".format(leaf0_clients, dual_clients))

    # DHCP Server Config with switch
    tg4, tg_ph_4 = tgapi.get_handle_byname("T1D4P2")
    h4 = tg4.tg_interface_config(port_handle=tg_ph_4, mode='config', intf_ip_addr=dhcpserverv4_b2, gateway=dhcpserverv4_vlan_b2,
                                src_mac_addr=dhcpv4_mac_addr_b2,
                                arp_send_req='1', control_plane_mtu='9100',
                                resolve_gateway_mac='false')

    s_conf4 = tg4.tg_emulation_dhcp_server_config(mode='create', ip_version='4', ipaddress_count='100',
                                                ipaddress_pool=[dhcp_ipv4_assigned_start_a2, dhcp_ipv4_assigned_start_a3, 
                                                dhcp_ipv4_assigned_start_a4, dhcp_ipv4_assigned_start_a5],  
                                                handle=h4['handle'], count='1', local_mac=dhcpv4_mac_addr_b2, ip_address=dhcpserverv4_b2,
                                                ip_gateway=dhcpserverv4_vlan_b2, remote_mac=dut_mac_server1, pool_count=4,
                                                subnet_addr_assign=1, subnet='link_selection')


    s_con4 = tg4.tg_emulation_dhcp_server_control(action='connect', dhcp_handle=s_conf4['dhcp_handle'])
    st.log("dhcp relay ipv4 basic server control {}".format(s_con4))

    st.wait(10)
    st.show(vars.D4, 'sudo ping -I {} {} -c 5'.format(VRF_NAME1, dhcpserverv4_b2), skip_tmpl=True, skip_error_check=True)


    if dual_servers:
        # DHCP Server Config with switch
        tg3, tg_ph_3 = tgapi.get_handle_byname("T1D3P4")
        h3 = tg3.tg_interface_config(port_handle=tg_ph_3, mode='config', intf_ip_addr=dhcpserverv4_a4, gateway=dhcpserverv4_vlan_a4,
                                src_mac_addr=dhcpv4_mac_addr_a4,
                                arp_send_req='1', control_plane_mtu='9100',
                                resolve_gateway_mac='false')

        s_conf3 = tg3.tg_emulation_dhcp_server_config(mode='create', ip_version='4', ipaddress_count='100',
                                                ipaddress_pool=[dhcp_ipv4_assigned_start_b2, dhcp_ipv4_assigned_start_b3, 
                                                dhcp_ipv4_assigned_start_b4, dhcp_ipv4_assigned_start_b5],
                                                handle=h3['handle'], count='1', local_mac=dhcpv4_mac_addr_a4, ip_address=dhcpserverv4_a4,
                                                ip_gateway=dhcpserverv4_vlan_a4, remote_mac=dut_mac_server2, pool_count=4,
                                                subnet_addr_assign=1, subnet='link_selection')

        s_con3 = tg3.tg_emulation_dhcp_server_control(action='connect', dhcp_handle=s_conf3['dhcp_handle'])
        st.log("dhcp relay ipv4 basic server control {}".format(s_con3))

        st.wait(10)
        st.show(vars.D3, 'sudo ping -I {} {} -c 5'.format(VRF_NAME2, dhcpserverv4_a4), skip_tmpl=True, skip_error_check=True)


    if leaf0_clients >= 1:
        result = dhcp_l3vni_ipv4_setup_client('T1D3P1', dhcpv4_mac_addr_a1, dhcp_ipv4_set_a2, client_cleanup)
        if result == False:
            tg4.tg_emulation_dhcp_server_config(mode='reset', handle=s_conf4['dhcp_handle'], port_handle=tg_ph_4)
            return result

    if leaf0_clients >= 2:
        result = dhcp_l3vni_ipv4_setup_client('T1D3P3', dhcpv4_mac_addr_a3, dhcp_ipv4_set_a4, client_cleanup)
        if result == False:
            tg4.tg_emulation_dhcp_server_config(mode='reset', handle=s_conf4['dhcp_handle'], port_handle=tg_ph_4)
            return result

    if leaf0_clients >= 3:
        result = dhcp_l3vni_ipv4_setup_client('T1D3P4', dhcpv4_mac_addr_a4, dhcp_ipv4_set_a5, client_cleanup)
        if result == False:
            tg4.tg_emulation_dhcp_server_config(mode='reset', handle=s_conf4['dhcp_handle'], port_handle=tg_ph_4)
            return result


    if dual_clients >= 1:
        result = dhcp_l3vni_ipv4_setup_client('T1D3P3', dhcpv4_mac_addr_a3, dhcp_ipv4_set_a4, client_cleanup)
        result = dhcp_l3vni_ipv4_setup_client('T1D4P1', dhcpv4_mac_addr_b1, dhcp_ipv4_set_b2, client_cleanup)


    tg4.tg_emulation_dhcp_server_config(mode='reset', handle=s_conf4['dhcp_handle'], port_handle=tg_ph_4)

    if dual_servers:
        tg3.tg_emulation_dhcp_server_config(mode='reset', handle=s_conf3['dhcp_handle'], port_handle=tg_ph_3)

    return result




def dhcp_l3vni_ipv4_setup_client(node_client, dhcpclientv4_mac, ipaddr, client_cleanup=True):

    # DHCP Client Config(Port Based)

    tg1, tg_ph_1 = tgapi.get_handle_byname(node_client)
    conf1 = tg1.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_1)

    # 'ip_version' is mandatory to configure retry_count
    conf1 = tg1.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_1, retry_count='10', ip_version='4')
    st.log("dhcp relay ipv4 basic client config {}".format(conf1))

    group1 = tg1.tg_emulation_dhcp_group_config(handle=conf1['handles'], mode='create',
                                              num_sessions='2', mac_addr=dhcpclientv4_mac, vlan_ether_type='0x8100',
                                              dhcp_range_ip_type=4, vlan_id_step=0, gateway_addresses=1, protocol_name='dhcpv4client', dhcp4_broadcast=1)
    st.log("dhcp relay ipv4 basic client gconfig {}".format(group1))

    tg1.tg_emulation_dhcp_stats(action='clear', port_handle=tg_ph_1)


    cont1 = tg1.tg_emulation_dhcp_control(port_handle=tg_ph_1, action="bind", handle=group1['handle'])
    st.log("EVPN l3vni dhcp ipv4 basic client bind {}".format(cont1))

    st.wait(15)

    rst1 = tg1.tg_emulation_dhcp_stats(port_handle=tg_ph_1, handle=conf1['handles'], mode='session', ip_version='4')
    st.log("EVPN l3vni dhcp ipv4 basic client result {}".format(rst1))

    for key, val in rst1.items():
        if key == 'session':
            for _, val2 in val.items():
                st.log("EVPN l3vni dhcp ipv4 basic client ipaddr {}".format(val2['Address']))
                if val2['Address'] not in ipaddr:
                    st.log("EVPN l3vni dhcp ipv4 basic fails on assigning the ip")
                    tg1.tg_emulation_dhcp_config(mode='reset', handle=conf1['handles'], port_handle=tg_ph_1)
                    return False

    st.log("EVPN l3vni dhcp ipv4 basic pass on assigning the ip from {} to SD3 or SD4".format(node_client))

    if client_cleanup:
        tg1.tg_emulation_dhcp_config(mode='reset', handle=conf1['handles'], port_handle=tg_ph_1)
    else:
        st.log("EVPN l3vni dhcp client SD3-{} standby".format(node_client))


    return True


#################################################
## DHCP RELAY configs
#################################################


def config_dhcp_relay_ipv4(node, vlan, server, add=True):
    vars = st.get_testbed_vars()

    if add:
        st.config(node, "config vlan dhcp_relay add {} {}".format(vlan, server))
    else:
        st.config(node, "config vlan dhcp_relay del {} {}".format(vlan, server))

def config_l3vni_int_vrf(node, vrf=None, dummy_vlan=None, loopback=None, prefix=None, add=True):
    if add:
        if vrf:
            st.config(node, "config vrf add {}".format(vrf))
        if dummy_vlan:
            st.config(node, "config vlan add {}".format(dummy_vlan))
            st.config(node, "config interface vrf bind Vlan{} {}".format(dummy_vlan, vrf))
            st.config(node, "config vxlan map add VXLAN {} 5{}".format(dummy_vlan, dummy_vlan))
            st.config(node, "config vrf add_vrf_vni_map {} 5{}".format(vrf, dummy_vlan))
        if loopback:
            st.config(node, "config interface vrf bind {} {}".format(loopback, vrf))
            st.config(node, "config interface ip add {} {}".format(loopback, prefix))
    else:
        if loopback:
            st.config(node, "config interface ip rem {} {}".format(loopback, prefix))
            st.config(node, "config interface vrf unbind {}".format(loopback))
        if dummy_vlan:
            st.config(node, "config vrf del_vrf_vni_map {}".format(vrf))
            st.config(node, "config vxlan map del VXLAN {} 5{}".format(dummy_vlan, dummy_vlan))
            st.config(node, "config interface vrf unbind Vlan{}".format(dummy_vlan, vrf))
            st.config(node, "config vlan del {}".format(dummy_vlan))

def config_l3vni_int_vlan(node, vlan=None, member=None, vrf=None, prefix=None, loopback=None, breakout=False, add=True):
    if add:
        if vlan:
            st.config(node, "config vlan add {}".format(vlan))
        if member:
            if breakout:
                st.config(node, "show int breakout")
                st.config(node, "config interface breakout {} \"2x200G\" -yfl".format(member))
                st.config(node, "config interface startup {}_1".format(member))
                st.config(node, "config vlan member add -u {} {}_1".format(vlan, member))
            else: 
                st.config(node, "config vlan member add -u {} {}".format(vlan, member))
        if vlan:
            st.config(node, "config vxlan map add VXLAN {} 500{}".format(vlan, vlan))
        if vrf:
            st.config(node, "config interface vrf bind Vlan{} {}".format(vlan, vrf))
        if prefix:
            st.config(node, "config interface ip add Vlan{} {}".format(vlan, prefix))
        if vlan:
            st.config(node, "config vlan static-anycast-gateway enable {}".format(vlan))
        if loopback:
            st.config(node, "config vlan dhcp-relay-src add {} {}".format(vlan, loopback))
    else: 
        if loopback:
            st.config(node, "config vlan dhcp-relay-src del {}".format(vlan))
        if vlan:
            st.config(node, "config vlan static-anycast-gateway disable {}".format(vlan))
        if prefix:
            st.config(node, "config interface ip rem Vlan{} {}".format(vlan, prefix))
        if vrf:
            st.config(node, "config interface vrf unbind Vlan{}".format(vlan))
        if vlan:
            st.config(node, "config vxlan map del VXLAN {} 500{}".format(vlan, vlan))
        if member:
            if breakout:
                st.config(node, "config vlan member del {} {}_1".format(vlan, member))
                st.config(node, "config interface breakout {} \"1x400G\" -yfl".format(member))
                st.config(node, "config interface startup {}".format(member))
            else: 
                st.config(node, "config vlan member del {} {}".format(vlan, member))
        if vlan:
            st.config(node, "config vlan del {}".format(vlan))

