###############################################################################

#Script Title : Syslog source interface over default and non default vrf
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com

###############################################################################

import pytest

from spytest import st
from syslog_vars import data
import apis.system.basic as basic_obj
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import apis.switching.portchannel as pc_obj
import apis.system.rsyslog as log_obj
import apis.routing.vrf as vrf_obj
from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient

def module_config():
    result = rsyslog_server()
    if result is False:
        st.error("Module config Failed - Unable to configure Sonic DUT as a rsyslog server")
        pytest.skip()
    result = st.exec_all([[dut1_config],[dut2_config],[dut3_config]])
    if result is False:
        st.error("Module config Failed - IP address/Portchannel/Vlan configuration failed")
        #base_interfaces(config = 'no')
        pytest.skip()

def module_unconfig():
    st.exec_all(True,[[ip_obj.delete_ip_interface, data.dut1_client, data.mgmt_intf, data.dut1_mgmt_ipv6[0], data.dut1_mgmt_ipv6_subnet, 'ipv6'],
                         [ip_obj.delete_ip_interface, data.dut2_server, data.mgmt_intf, data.dut2_mgmt_ipv6[0], data.dut2_mgmt_ipv6_subnet, 'ipv6']])
    st.exec_all([[dut1_unconfig],[dut2_unconfig]])

def rsyslog_server(**kwargs):
    st.log("Configuring DUT2 as rsyslog server configuration")
    copy_files_to_server()
    basic_obj.copy_file_to_local_path(data.dut2_server, data.server_src_path, data.server_dst_path)
    st.log("Restart the server after modifying the conf file")
    result = basic_obj.systemctl_restart_service(data.dut2_server, 'rsyslog', max_wait=10, skip_error_check=True)
    return result

def dut1_config(config = ''):

    result = 0
    st.log('On DUT1 physical interface IPv4 and IPv6 addresses on it')
    result = ip_obj.config_ip_addr_interface(data.dut1_client, data.d1_d2_ports[0], data.dut1_dut2_ipv6[0], data.dut1_dut2_ipv6_subnet,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut1_client, data.d1_d2_ports[0], data.dut1_dut2_ip[0], data.dut1_dut2_ip_subnet,'ipv4')

    st.log('On DUT1 configure vlan and IPv4 and IPv6 addresses on it')
    result = vlan_obj.create_vlan(data.dut1_client, data.dut1_dut2_vlan[0])
    result = vlan_obj.add_vlan_member(data.dut1_client,data.dut1_dut2_vlan[0],data.d1_d2_ports[1],True,True)
    result = ip_obj.config_ip_addr_interface(data.dut1_client, 'Vlan'+data.dut1_dut2_vlan[0], data.dut1_dut2_ipv6[1], data.dut1_dut2_ipv6_subnet,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut1_client, 'Vlan'+data.dut1_dut2_vlan[0], data.dut1_dut2_ip[1], data.dut1_dut2_ip_subnet,'ipv4')

    st.log('On DUT1 configure portchannel and IPv4 and IPv6 addresses on it')
    result = pc_obj.create_portchannel(data.dut1_client, data.portchannel)
    result = pc_obj.add_portchannel_member(data.dut1_client, data.portchannel,[data.d1_d2_ports[2],data.d1_d2_ports[3]])
    result = ip_obj.config_ip_addr_interface(data.dut1_client, data.portchannel, data.dut1_dut2_ipv6[2], data.dut1_dut2_ipv6_subnet,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut1_client, data.portchannel, data.dut1_dut2_ip[2], data.dut1_dut2_ip_subnet,'ipv4')

    st.log('On DUT1 configure loopback and IPv4 and IPv6 addresses on it')
    result = ip_obj.configure_loopback(data.dut1_client, config = 'yes', loopback_name = data.dut1_loopback[0])
    result = ip_obj.config_ip_addr_interface(data.dut1_client, data.dut1_loopback[0], data.dut1_loopback_ipv6[0], data.dut1_loopback_ipv6_subnet,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut1_client, data.dut1_loopback[0], data.dut1_loopback_ip[0], data.dut1_loopback_ip_subnet,'ipv4')

    st.log('IPv4 and IPv6 static routes for loopback reachability')
    ip_obj.create_static_route(data.dut1_client, data.dut2_dut1_ip[0], data.dut2_loopback_ip[0]+'/32',family = 'ipv4')
    ip_obj.create_static_route(data.dut1_client, data.dut2_dut1_ipv6[0], data.dut2_loopback_ipv6[0]+'/128',family = 'ipv6')

    return result

def dut1_unconfig(config = ''):

    result = 0
    st.banner('Unconfigure IPv4 and IPv6 addresses on the loopback interfaces')
    result = ip_obj.delete_ip_interface(data.dut1_client, data.dut1_loopback[0], data.dut1_loopback_ipv6[0], data.dut1_loopback_ipv6_subnet,'ipv6')
    result = ip_obj.delete_ip_interface(data.dut1_client, data.dut1_loopback[0], data.dut1_loopback_ip[0], data.dut1_loopback_ip_subnet,'ipv4')
    result = ip_obj.configure_loopback(data.dut1_client, config = 'no', loopback_name = data.dut1_loopback[0])

    st.banner('Unconfigure IPv4 and IPv6 addresses on portchannel of DUT1')
    result = ip_obj.delete_ip_interface(data.dut1_client, data.portchannel, data.dut1_dut2_ipv6[2], data.dut1_dut2_ipv6_subnet,'ipv6')
    result = ip_obj.delete_ip_interface(data.dut1_client, data.portchannel, data.dut1_dut2_ip[2], data.dut1_dut2_ip_subnet,'ipv4')
    result = pc_obj.add_del_portchannel_member(data.dut1_client, data.portchannel,[data.d1_d2_ports[2],data.d1_d2_ports[3]],'del')
    result = pc_obj.delete_portchannel(data.dut1_client, data.portchannel)

    st.log('On DUT1 unconfigure vlan and IPv4 and IPv6 addresses on it')
    result = ip_obj.delete_ip_interface(data.dut1_client, 'Vlan'+data.dut1_dut2_vlan[0], data.dut1_dut2_ipv6[1], data.dut1_dut2_ipv6_subnet,'ipv6')
    result = ip_obj.delete_ip_interface(data.dut1_client, 'Vlan'+data.dut1_dut2_vlan[0], data.dut1_dut2_ip[1], data.dut1_dut2_ip_subnet,'ipv4')
    result = vlan_obj.delete_vlan_member(data.dut1_client,data.dut1_dut2_vlan[0],data.d1_d2_ports[1],True)
    result = vlan_obj.create_vlan(data.dut1_client, data.dut1_dut2_vlan[0])

    st.banner('Unconfigure IPv4 and IPv6 addresses on physical interface of DUT1')
    result = ip_obj.delete_ip_interface(data.dut1_client, data.d1_d2_ports[0], data.dut1_dut2_ipv6[0], data.dut1_dut2_ipv6_subnet,'ipv6')
    result = ip_obj.delete_ip_interface(data.dut1_client, data.d1_d2_ports[0], data.dut1_dut2_ip[0], data.dut1_dut2_ip_subnet,'ipv4')

    st.log('Unconfigure IPv6 address on management interface of DUT1')
    result = ip_obj.delete_ip_interface(data.dut1_client, data.mgmt_intf, data.dut1_mgmt_ipv6[0], data.dut1_mgmt_ipv6_subnet,'ipv6')

    return result

def dut2_config(config = ''):

    result = 0
    st.log('On DUT2 add IPv4 and IPv6 addresses to physical interface')
    result = ip_obj.config_ip_addr_interface(data.dut2_server, data.d2_d1_ports[0], data.dut2_dut1_ipv6[0], data.dut2_dut1_ipv6_subnet, 'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut2_server, data.d2_d1_ports[0], data.dut2_dut1_ip[0], data.dut2_dut1_ip_subnet, 'ipv4')

    st.log('On DUT2 configure vlan and add IPv4 and IPv6 addresses to it')
    result = vlan_obj.create_vlan(data.dut2_server, data.dut1_dut2_vlan[0])
    result = vlan_obj.add_vlan_member(data.dut2_server,data.dut1_dut2_vlan[0], data.d2_d1_ports[1],True,True)
    result = ip_obj.config_ip_addr_interface(data.dut2_server, 'Vlan'+data.dut1_dut2_vlan[0], data.dut2_dut1_ipv6[1], data.dut2_dut1_ipv6_subnet, 'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut2_server, 'Vlan'+data.dut1_dut2_vlan[0], data.dut2_dut1_ip[1], data.dut2_dut1_ip_subnet, 'ipv4')

    st.log('On DUT2 configure portchannel and add IPv4 and IPv6 addresses to it')
    result = pc_obj.create_portchannel(data.dut2_server, data.portchannel)
    result = pc_obj.add_portchannel_member(data.dut2_server, data.portchannel,[data.d2_d1_ports[2],data.d2_d1_ports[3]])
    result = ip_obj.config_ip_addr_interface(data.dut2_server, data.portchannel, data.dut2_dut1_ipv6[2], data.dut2_dut1_ipv6_subnet, 'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut2_server, data.portchannel, data.dut2_dut1_ip[2], data.dut2_dut1_ip_subnet, 'ipv4')

    st.log('On DUT2 configure loopback and add IPv4 and IPv6 addresses to it')
    result = ip_obj.configure_loopback(data.dut2_server, config = 'yes', loopback_name = data.dut2_loopback[0])
    result = ip_obj.config_ip_addr_interface(data.dut2_server, data.dut2_loopback[0], data.dut2_loopback_ipv6[0], data.dut2_loopback_ipv6_subnet,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut2_server, data.dut2_loopback[0], data.dut2_loopback_ip[0], data.dut2_loopback_ip_subnet,'ipv4')

    st.log('IPv4 and IPv6 static routes for loopback reachability')
    ip_obj.create_static_route(data.dut2_server, data.dut1_dut2_ip[0], data.dut1_loopback_ip[0]+'/32',family = 'ipv4')
    ip_obj.create_static_route(data.dut2_server, data.dut1_dut2_ipv6[0], data.dut1_loopback_ipv6[0]+'/128',family = 'ipv6')

    ####
    ip_obj.config_ip_addr_interface(data.dut2_server, data.d2_d3_ports[0], data.dut2_dut3_ip[0], data.dut2_dut3_ip_subnet,'ipv4')
    ip_obj.config_ip_addr_interface(data.dut2_server, data.d2_d3_ports[0], data.dut2_dut3_ipv6[0], data.dut2_dut3_ipv6_subnet,'ipv6')

    result = vlan_obj.create_vlan(data.dut2_server, data.dut2_dut3_vlan[0])
    result = vlan_obj.add_vlan_member(data.dut2_server,data.dut2_dut3_vlan[0], data.d2_d3_ports[1],True,True)
    result = ip_obj.config_ip_addr_interface(data.dut2_server, 'Vlan'+data.dut2_dut3_vlan[0], data.dut2_dut3_ipv6[1], data.dut2_dut3_ipv6_subnet, 'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut2_server, 'Vlan'+data.dut2_dut3_vlan[0], data.dut2_dut3_ip[1], data.dut2_dut3_ip_subnet, 'ipv4')

    st.log('On DUT2 configure portchannel and IPv4 and IPv6 addresses on it')
    result = pc_obj.create_portchannel(data.dut2_server, data.portchannel_2)
    result = pc_obj.add_portchannel_member(data.dut2_server, data.portchannel_2,[data.d2_d3_ports[2],data.d2_d3_ports[3]])
    result = ip_obj.config_ip_addr_interface(data.dut2_server, data.portchannel_2, data.dut2_dut3_ipv6[2], data.dut2_dut3_ipv6_subnet,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut2_server, data.portchannel_2, data.dut2_dut3_ip[2], data.dut2_dut3_ip_subnet,'ipv4')

    st.log('On DUT2 configure loopback and IPv4 and IPv6 addresses on it')
    result = ip_obj.configure_loopback(data.dut2_server, config = 'yes', loopback_name = data.dut2_loopback[1])
    result = ip_obj.config_ip_addr_interface(data.dut2_server, data.dut2_loopback[1], data.dut2_loopback_ipv6[1], data.dut2_loopback_ipv6_subnet,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut2_server, data.dut2_loopback[1], data.dut2_loopback_ip[1], data.dut2_loopback_ip_subnet,'ipv4')

    st.log('IPv4 and IPv6 static routes for loopback reachability')
    ip_obj.create_static_route(data.dut2_server, data.dut3_dut2_ip[0], data.dut3_loopback_ip[0]+'/32',family = 'ipv4')
    ip_obj.create_static_route(data.dut2_server, data.dut3_dut2_ipv6[0], data.dut3_loopback_ipv6[0]+'/128',family = 'ipv6')

    return result

def dut2_unconfig(config = ''):

    result = 0
    st.log('On DUT2 unconfigure loopback and remove IPv4 and IPv6 addresses on it')
    result = ip_obj.delete_ip_interface(data.dut2_server, data.dut2_loopback[0], data.dut2_loopback_ipv6[0], data.dut2_loopback_ipv6_subnet,'ipv6')
    result = ip_obj.delete_ip_interface(data.dut2_server, data.dut2_loopback[0], data.dut2_loopback_ip[0], data.dut2_loopback_ip_subnet,'ipv4')
    result = ip_obj.configure_loopback(data.dut2_server, config = 'no', loopback_name = data.dut2_loopback[0])

    st.log('On DUT2 unconfigure portchannel and remove IPv4 and IPv6 addresses on it')
    result = ip_obj.delete_ip_interface(data.dut2_server, data.portchannel, data.dut2_dut1_ipv6[2], data.dut2_dut1_ipv6_subnet, 'ipv6')
    result = ip_obj.delete_ip_interface(data.dut2_server, data.portchannel, data.dut2_dut1_ip[2], data.dut2_dut1_ip_subnet, 'ipv4')
    result = pc_obj.add_del_portchannel_member(data.dut2_server, data.portchannel,[data.d2_d1_ports[2],data.d2_d1_ports[3]],'del')
    result = pc_obj.delete_portchannel(data.dut2_server, data.portchannel)

    st.log('On DUT2 unconfigure vlan and remove IPv4 and IPv6 addresses on it')
    result = ip_obj.delete_ip_interface(data.dut2_server, 'Vlan'+data.dut1_dut2_vlan[0], data.dut2_dut1_ipv6[1], data.dut2_dut1_ipv6_subnet, 'ipv6')
    result = ip_obj.delete_ip_interface(data.dut2_server, 'Vlan'+data.dut1_dut2_vlan[0], data.dut2_dut1_ip[1], data.dut2_dut1_ip_subnet, 'ipv4')
    result = vlan_obj.delete_vlan_member(data.dut2_server,data.dut1_dut2_vlan[0], data.d2_d1_ports[1],True)
    result = vlan_obj.delete_vlan(data.dut2_server, data.dut1_dut2_vlan[0])

    st.log('On DUT2 remove IPv4 and IPv6 addresses on physical interface')
    result = ip_obj.delete_ip_interface(data.dut2_server, data.d2_d1_ports[0], data.dut2_dut1_ipv6[0], data.dut2_dut1_ipv6_subnet, 'ipv6')
    result = ip_obj.delete_ip_interface(data.dut2_server, data.d2_d1_ports[0], data.dut2_dut1_ip[0], data.dut2_dut1_ip_subnet, 'ipv4')

    st.log('On DUT2 remove IPv4 and IPv6 addresses on management interface')
    result = ip_obj.delete_ip_interface(data.dut2_server, data.mgmt_intf, data.dut2_mgmt_ipv6[0], data.dut2_mgmt_ipv6_subnet, 'ipv6')

    return result

def dut3_config(config = ''):
    st.log('On DUT3 physical interface IPv4 and IPv6 addresses on it')
    vrf_obj.config_vrf(dut = data.dut3_client, vrf_name = data.dut3_vrf_phy, config = 'yes')
    vrf_obj.bind_vrf_interface(dut = data.dut3_client, vrf_name = data.dut3_vrf_phy, intf_name = data.d3_d2_ports[0], config = 'yes')
    result = ip_obj.config_ip_addr_interface(data.dut3_client, data.d3_d2_ports[0], data.dut3_dut2_ipv6[0], data.dut3_dut2_ipv6_subnet,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut3_client, data.d3_d2_ports[0], data.dut3_dut2_ip[0], data.dut3_dut2_ip_subnet,'ipv4')
    result = vlan_obj.create_vlan(data.dut3_client, data.dut2_dut3_vlan[0])
    result = vlan_obj.add_vlan_member(data.dut3_client,data.dut2_dut3_vlan[0],data.d3_d2_ports[1],True,True)
    st.log('On DUT3 configure vlan and IPv4 and IPv6 addresses on it')
    vrf_obj.config_vrf(dut = data.dut3_client, vrf_name = data.dut3_vrf_vlan, config = 'yes')
    vrf_obj.bind_vrf_interface(dut = data.dut3_client, vrf_name = data.dut3_vrf_vlan, intf_name = 'Vlan'+data.dut2_dut3_vlan[0], config = 'yes')
    result = ip_obj.config_ip_addr_interface(data.dut3_client, 'Vlan'+data.dut2_dut3_vlan[0], data.dut3_dut2_ipv6[1], data.dut3_dut2_ipv6_subnet,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut3_client, 'Vlan'+data.dut2_dut3_vlan[0], data.dut3_dut2_ip[1], data.dut3_dut2_ip_subnet,'ipv4')
    st.log('On DUT3 configure portchannel and IPv4 and IPv6 addresses on it')
    result = pc_obj.create_portchannel(data.dut3_client, data.portchannel_2)
    result = pc_obj.add_portchannel_member(data.dut3_client, data.portchannel_2,[data.d3_d2_ports[2],data.d3_d2_ports[3]])
    vrf_obj.config_vrf(dut = data.dut3_client, vrf_name = data.dut3_vrf_pc, config = 'yes')
    vrf_obj.bind_vrf_interface(dut = data.dut3_client, vrf_name = data.dut3_vrf_pc, intf_name = data.portchannel_2, config = 'yes')
    result = ip_obj.config_ip_addr_interface(data.dut3_client, data.portchannel_2, data.dut3_dut2_ipv6[2], data.dut3_dut2_ipv6_subnet,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut3_client, data.portchannel_2, data.dut3_dut2_ip[2], data.dut3_dut2_ip_subnet,'ipv4')

    st.log('On DUT3 configure loopback and IPv4 and IPv6 addresses on it')
    result = ip_obj.configure_loopback(data.dut3_client, config = 'yes', loopback_name = data.dut3_loopback[1])
    vrf_obj.config_vrf(dut = data.dut3_client, vrf_name = data.dut3_vrf_phy, config = 'yes')
    vrf_obj.bind_vrf_interface(dut = data.dut3_client, vrf_name = data.dut3_vrf_phy, intf_name = data.dut3_loopback[1], config = 'yes')
    result = ip_obj.config_ip_addr_interface(data.dut3_client, data.dut3_loopback[1], data.dut3_loopback_ipv6[1], data.dut3_loopback_ipv6_subnet,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut3_client, data.dut3_loopback[1], data.dut3_loopback_ip[1], data.dut3_loopback_ip_subnet,'ipv4')

    st.log('IPv4 and IPv6 static routes for loopback reachability')
    ip_obj.create_static_route(data.dut3_client, data.dut2_dut3_ip[0], data.dut2_loopback_ip[1]+'/32',family = 'ipv4',interface = data.d3_d2_ports[0], vrf = data.dut3_vrf_phy)
    ip_obj.create_static_route(data.dut3_client, data.dut2_dut3_ipv6[0], data.dut2_loopback_ipv6[1]+'/128',family = 'ipv6',interface = data.d3_d2_ports[0], vrf = data.dut3_vrf_phy)
    return result

def config_server(**kwargs):
    mgmt_intf =  kwargs.get('mgmt_intf',None)
    phy =  kwargs.get('phy',None)
    vlan =  kwargs.get('vlan',None)
    pc =  kwargs.get('pc',None)
    loop_bk =  kwargs.get('loop_bk',None)
    #source_intf =  kwargs.get('source_intf','')
    #remote_port =  kwargs.get('remote_port','')
    #source_intf_name =  kwargs.get('source_intf_name',None)
    vrf =  kwargs.get('vrf',None)
    config =  kwargs.get('config','')
    family =  kwargs.get('family','ip')
    if mgmt_intf != None:
        host = st.get_mgmt_ip(data.dut2_server) if family != 'ipv6' else data.dut2_mgmt_ipv6[0]
        result = log_obj.config_remote_syslog_server(dut = data.dut1_client, host = host, config = config)
        return result
    if phy != None:
        if vrf != None:
            host = data.dut2_dut3_ip[0] if family != 'ipv6' else data.dut2_dut3_ipv6[0]
            result = log_obj.config_remote_syslog_server(dut = data.dut3_client, host = host, config = config, source_intf = data.d3_d2_ports[0], vrf = data.dut3_vrf_phy)
        else:
            host = data.dut2_dut1_ip[0] if family != 'ipv6' else data.dut2_dut1_ipv6[0]
            result = log_obj.config_remote_syslog_server(dut = data.dut1_client, host = host, config = config, source_intf = data.d1_d2_ports[0])
        return result
    if vlan != None:
        if vrf != None:
            host = data.dut2_dut3_ip[1] if family != 'ipv6' else data.dut2_dut3_ipv6[1]
            result = log_obj.config_remote_syslog_server(dut = data.dut3_client, host = host, config = config, source_intf = 'Vlan'+data.dut2_dut3_vlan[0], vrf = data.dut3_vrf_vlan)
        else:
            host = data.dut2_dut1_ip[1] if family != 'ipv6' else data.dut2_dut1_ipv6[1]
            result = log_obj.config_remote_syslog_server(dut = data.dut1_client, host = host, config = config, source_intf = 'Vlan'+data.dut1_dut2_vlan[0])
        return result
    if pc != None:
        if vrf != None:
            host = data.dut2_dut3_ip[2] if family != 'ipv6' else data.dut2_dut3_ipv6[2]
            result = log_obj.config_remote_syslog_server(dut = data.dut3_client, host = host, config = config, source_intf = data.portchannel_2, vrf = data.dut3_vrf_pc)
        else:
            host = data.dut2_dut1_ip[2] if family != 'ipv6' else data.dut2_dut1_ipv6[2]
            result = log_obj.config_remote_syslog_server(dut = data.dut1_client, host = host, config = config, source_intf = data.portchannel)
        return result
    if loop_bk != None:
        if vrf != None:
            host = data.dut2_loopback_ip[1] if family != 'ipv6' else data.dut2_loopback_ipv6[1]
            result = log_obj.config_remote_syslog_server(dut = data.dut3_client, host = host, config = config, source_intf = data.dut3_loopback[1], vrf = data.dut3_vrf_phy)
        else:
            host = data.dut2_loopback_ip[0] if family != 'ipv6' else data.dut2_loopback_ipv6[0]
            result = log_obj.config_remote_syslog_server(dut = data.dut1_client, host = host, config = config, source_intf = data.dut1_loopback[0])
        return result

def verify_server(**kwargs):
    mgmt_intf =  kwargs.get('mgmt_intf',None)
    phy =  kwargs.get('phy',None)
    vlan =  kwargs.get('vlan',None)
    pc =  kwargs.get('pc',None)
    loop_bk =  kwargs.get('loop_bk',None)
    #source_intf =  kwargs.get('source_intf','')
    #remote_port =  kwargs.get('remote_port','')
    #source_intf_name =  kwargs.get('source_intf_name',None)
    vrf =  kwargs.get('vrf',None)
    config =  kwargs.get('config','')
    family =  kwargs.get('family','ip')
    if mgmt_intf != None:
        host = st.get_mgmt_ip(data.dut2_server) if family != 'ipv6' else data.dut2_mgmt_ipv6[0]
        result = log_obj.verify_remote_syslog_server(dut = data.dut1_client, host = host, config = config)
        return result
    if phy != None:
        if vrf != None:
            host = data.dut2_dut3_ip[0] if family != 'ipv6' else data.dut2_dut3_ipv6[0]
            result = log_obj.verify_remote_syslog_server(dut = data.dut3_client, host = host, source_intf = data.d3_d2_ports[0], vrf = data.dut3_vrf_phy)
        else:
            host = data.dut2_dut1_ip[0] if family != 'ipv6' else data.dut2_dut1_ipv6[0]
            result = log_obj.verify_remote_syslog_server(dut = data.dut1_client, host = host, source_intf = data.d1_d2_ports[0])
        return result
    if vlan != None:
        if vrf != None:
            host = data.dut2_dut3_ip[1] if family != 'ipv6' else data.dut2_dut3_ipv6[1]
            result = log_obj.verify_remote_syslog_server(dut = data.dut3_client, host = host, source_intf = 'Vlan'+data.dut2_dut3_vlan[0], vrf = data.dut3_vrf_vlan)
        else:
            host = data.dut2_dut1_ip[1] if family != 'ipv6' else data.dut2_dut1_ipv6[1]
            result = log_obj.verify_remote_syslog_server(dut = data.dut1_client, host = host, source_intf = 'Vlan'+data.dut1_dut2_vlan[0])
        return result
    if pc != None:
        if vrf != None:
            host = data.dut2_dut3_ip[2] if family != 'ipv6' else data.dut2_dut3_ipv6[2]
            result = log_obj.verify_remote_syslog_server(dut = data.dut3_client, host = host, source_intf = data.portchannel_2, vrf = data.dut3_vrf_pc)
        else:
            host = data.dut2_dut1_ip[2] if family != 'ipv6' else data.dut2_dut1_ipv6[2]
            result = log_obj.verify_remote_syslog_server(dut = data.dut1_client, host = host, source_intf = data.portchannel)
        return result
    if loop_bk != None:
        if vrf != None:
            host = data.dut2_loopback_ip[1] if family != 'ipv6' else data.dut2_loopback_ipv6[1]
            result = log_obj.verify_remote_syslog_server(dut = data.dut3_client, host = host, source_intf = data.dut3_loopback[1], vrf = data.dut3_vrf_phy)
        else:
            host = data.dut2_loopback_ip[0] if family != 'ipv6' else data.dut2_loopback_ipv6[0]
            result = log_obj.verify_remote_syslog_server(dut = data.dut1_client, host = host, source_intf = data.dut1_loopback[0])
        return result

def copy_files_to_server():
    st.log("Scp the resyslog.conf file from the current location to /tmp on the server")
    ssh = SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    #ssh.connect(dut_ip, username='admin', password='broadcom')
    ssh.connect(st.get_mgmt_ip(data.dut2_server), username='admin', password=st.get_credentials(data.dut2_server)[3])
    ssh.exec_command('sudo -i')
    scp = SCPClient(ssh.get_transport())
    for file in data.syslog_file_path:
        scp.put(file,"/tmp")
    scp.close()
