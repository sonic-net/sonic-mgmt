
from spytest import st, utils

from dhcprelay_ipunnumbered_vars import *
from dhcprelay_ipunnumbered_vars import data

import apis.switching.portchannel as pc
import apis.switching.vlan as vlan_api
import apis.routing.ip as ip_api
import apis.routing.dhcp_relay as dhcp_relay
import apis.system.basic as basic_api
import apis.system.interface as interface_api
import apis.routing.ospf as ospf_obj
import apis.qos.copp as copp_api
from utilities import parallel
from utilities.utils import retry_api

from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient


def dhcp_relay_base_config():
    ###################################################
    hdrMsg("########## BASE Config Starts ########")
    ###################################################
    config_ip()
    config_ospf()
    config_ipunnumbered()
    result = verify_ospf()
    if not result:
        st.error('OSPF neighbor is not up between dut3 and dut1')
        #config_ipunnumbered(config='no')
        #config_ospf(config='no')
        #config_ip(config='no')
        return False
    # Install and Configure DHCP server
    result1 = dhcp_server_config()
    result2 = check_ping_dhcpserver(data.dut2)
    if False in [result1,result2]:
        st.error('Either ping to dhcp server or dhcp server configuration failed')
        #config_ipunnumbered(config='no')
        #config_ospf(config='no')
        #config_ip(config='no')
        return False
    config_dhcpRelay()

    ###################################################
    hdrMsg("########## BASE Config End ########")
    ###################################################
    return True

def dhcp_relay_base_deconfig():
    ###################################################
    hdrMsg("########## BASE De-Config Starts ########")
    ###################################################
    config_dhcpRelay(action='remove')
    config_ipunnumbered(config='no')
    config_ospf(config='no')
    config_ip(config='no')
    dhcp_server_unconfig()
    ###################################################
    hdrMsg("########## BASE De-Config End ########")
    ###################################################

def config_ip(config='yes'):
    if config == 'yes':
        api_name = ip_api.config_ip_addr_interface
        config_str = "Configure"
    else:
        api_name = ip_api.delete_ip_interface
        config_str = "Delete"

    hdrMsg("Bring-up the port on dut3 which is connected to dhcp server ")
    interface_api.interface_operation(data.dut3, data.dhcp_server_port, operation="startup")

    ##########################################################################
    hdrMsg("IP-config: {} IP address between dut2 interface {} and dut3 interface {}".format(config_str,data.d2d3_ports,data.d3d2_ports))
    ##########################################################################
    utils.exec_all(True, [[api_name, data.dut2, data.d2d3_ports[0], dut2_3_ip_list[0], mask_24],[api_name, data.dut3, data.d3d2_ports[0], dut3_2_ip_list[0], mask_24]])

    if config == 'yes':
        st.banner('Install L2 DHCP rules on dhcp client device')
        copp_api.bind_class_action_copp_policy(data.dut4, classifier='copp-system-dhcpl2', action_group='copp-system-dhcp')
        ##########################################################################
        hdrMsg("Create loopback interfaces on dut1, dut2 and dut3")
        ##########################################################################
        parallel.exec_parallel(True, [data.dut1,data.dut2,data.dut3], ip_api.configure_loopback,[{'loopback_name': 'Loopback1'}] * 3)

        ##########################################################################
        hdrMsg("Loopback-config: {} IP address on Loopback interface".format(config_str))
        ##########################################################################
        utils.exec_all(True, [[api_name, data.dut1, "Loopback1", dut1_loopback_ip_list[0], '32'],[api_name, data.dut2, "Loopback1", dut2_loopback_ip_list[0], '32'],[api_name, data.dut3, "Loopback1", dut3_loopback_ip_list[0], '32']])

        ##########################################
        hdrMsg("config required vlan to test on dut2 and dut4")
        ##########################################
        utils.exec_all(True, [[vlan_api.create_vlan, data.dut2, ['100']],[vlan_api.create_vlan, data.dut4, ['100']]])    
        vlan_api.create_vlan( data.dut4, ['200','300'])
        
        ##########################################
        hdrMsg("Add vlan members")
        ##########################################
        utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut2,'100',data.d2d4_ports[0],True],[vlan_api.add_vlan_member, data.dut4,'100',data.d4d2_ports[0],True]])
        
        #########################################################
        hdrMsg("LAG-Config: Create portchannel on dut2 and dut4")
        #########################################################
        utils.exec_all(True, [[pc.create_portchannel, data.dut2,['PortChannel12']],[pc.create_portchannel, data.dut4,['PortChannel12']]])

        #########################################################
        hdrMsg("LAG-Config: add member ports to portchannel")
        #########################################################
        utils.exec_all(True, [[pc.add_del_portchannel_member, data.dut2,'PortChannel12',data.d2d4_ports[2],'add'],[pc.add_del_portchannel_member, data.dut4,'PortChannel12',data.d4d2_ports[2],'add']])

        #########################################################
        hdrMsg("LAG-Config: Create portchannel on dut3 and dut1")
        #########################################################
        utils.exec_all(True, [[pc.create_portchannel, data.dut3,['PortChannel14']],[pc.create_portchannel, data.dut1,['PortChannel14']]])

        #########################################################
        hdrMsg("LAG-Config: add member ports to portchannel")
        #########################################################
        utils.exec_all(True, [[pc.add_del_portchannel_member, data.dut3,'PortChannel14',data.d3d1_ports[0],'add'],[pc.add_del_portchannel_member, data.dut1,'PortChannel14',data.d1d3_ports[0],'add']])

        ip_api.config_ip_addr_interface(data.dut2,'Vlan100', dut2_4_ip_list[0],mask_24)
        ip_api.config_ip_addr_interface(data.dut2,data.d2d4_ports[1], dut2_4_ip_list[1],mask_24)
        ip_api.config_ip_addr_interface(data.dut2,'PortChannel12', dut2_4_ip_list[2],mask_24)
        ip_api.config_ip_addr_interface(data.dut1, 'PortChannel14', data.dhcp_server_ipv6, mask_v6,family='ipv6')
        
        #########################################
        hdrMsg("Add vlan members on DUT4")
        #########################################
        vlan_api.add_vlan_member(data.dut4,'200',data.d4d2_ports[1])
        vlan_api.add_vlan_member(data.dut4,'300','PortChannel12')
        
        st.exec_all( [[create_static_route_dut2],[create_static_route_dut3]])
    else:
        st.banner('Remove L2 DHCP rules on dhcp client device')
        copp_api.bind_class_action_copp_policy(data.dut4, classifier='copp-system-dhcpl2', action_group='copp-system-dhcp',config='no')
        ##########################################################################
        hdrMsg("Loopback-config: {} IP address on Loopback interface".format(config_str))
        ##########################################################################
        utils.exec_all(True, [[api_name, data.dut1, "Loopback1", dut1_loopback_ip_list[0], '32'],[api_name, data.dut2, "Loopback1", dut2_loopback_ip_list[0], '32'],[api_name, data.dut3, "Loopback1", dut3_loopback_ip_list[0], '32']])

        ##########################################################################
        hdrMsg("Delete loopback interfaces on dut1, dut2 and dut3")
        ##########################################################################
        parallel.exec_parallel(True, [data.dut1,data.dut2,data.dut3], ip_api.configure_loopback,[{'loopback_name': 'Loopback1','config':'no'}] * 3)

        st.exec_all( [[delete_static_route_dut2],[delete_static_route_dut3]])

        hdrMsg(" Remove all ip configs on dut2")
        ip_api.delete_ip_interface(data.dut2,'Vlan100', dut2_4_ip_list[0],mask_24)
        ip_api.delete_ip_interface(data.dut2,data.d2d4_ports[1], dut2_4_ip_list[1],mask_24)
        ip_api.delete_ip_interface(data.dut2,'PortChannel12', dut2_4_ip_list[2],mask_24)
        ip_api.delete_ip_interface(data.dut1, 'PortChannel14', data.dhcp_server_ipv6, mask_v6,family='ipv6')

        ###########################################################
        hdrMsg("LAG-unConfig: delete member ports to portchannel")
        ###########################################################
        utils.exec_all(True, [[pc.add_del_portchannel_member, data.dut2,'PortChannel12',data.d2d4_ports[2],'del'],[pc.add_del_portchannel_member, data.dut4,'PortChannel12',data.d4d2_ports[2],'del']])
        utils.exec_all(True, [[pc.add_del_portchannel_member, data.dut3,'PortChannel14',data.d3d1_ports[0],'del'],[pc.add_del_portchannel_member, data.dut1,'PortChannel14',data.d1d3_ports[0],'del']])
        
        vlan_api.delete_vlan_member(data.dut4,'300','PortChannel12')
        #######################################################
        hdrMsg("LAG-UnConfig: Delete portchannel on dut2 and dut4")
        #######################################################
        utils.exec_all(True, [[pc.delete_portchannel, data.dut2,['PortChannel12']],[pc.delete_portchannel, data.dut4,['PortChannel12']]])
        utils.exec_all(True, [[pc.delete_portchannel, data.dut3,['PortChannel14']],[pc.delete_portchannel, data.dut1,['PortChannel14']]])

        ########################################
        hdrMsg("Delete vlan member ports")
        ########################################
        utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut2,'100',data.d2d4_ports[0],True],[vlan_api.delete_vlan_member, data.dut4,'100',data.d4d2_ports[0],True]])
        vlan_api.delete_vlan_member(data.dut4,'200',data.d4d2_ports[1])
        
        ####################################
        hdrMsg("Unconfig vlan fron dut2 and dut4")
        ###################################
        utils.exec_all(True, [[vlan_api.delete_vlan, data.dut2, ['100']],[vlan_api.delete_vlan, data.dut4, ['100']]])
        vlan_api.delete_vlan (data.dut4, ['200','300'])

def config_ospf(config='yes'):
    if config == 'yes':
        hdrMsg('Configure ospf between DUT1 and DUT3')
        utils.exec_all(True,[[ospf_obj.config_ospf_router_id, data.dut1, dut1_ospf_router_id, 'default', '','yes'],
                        [ospf_obj.config_ospf_router_id, data.dut3, dut3_ospf_router_id, 'default', '','yes']])

        utils.exec_all(True,[[ospf_obj.config_ospf_network, data.dut1, dut1_loopback_ip_list[0]+'/'+ip_loopback_prefix, 0, 'default', '','yes'],
                             [ospf_obj.config_ospf_network, data.dut3, dut3_loopback_ip_list[0]+'/'+ip_loopback_prefix, 0, 'default', '','yes']])


        utils.exec_all(True,[[ospf_obj.config_interface_ip_ospf_network_type, data.dut1, 'PortChannel14','point-to-point','default','yes'],
                             [ospf_obj.config_interface_ip_ospf_network_type, data.dut3, 'PortChannel14','point-to-point','default','yes']])

        ospf_obj.config_ospf_router_redistribute(data.dut3, 'connected')
    else:
        hdrMsg('UnConfig ospf between DUT1 and DUT3')

        utils.exec_all(True,[[ospf_obj.config_interface_ip_ospf_network_type, data.dut1, 'PortChannel14','point-to-point','default','no'],
                             [ospf_obj.config_interface_ip_ospf_network_type, data.dut3, 'PortChannel14','point-to-point','default','no']])

        utils.exec_all(True,[[ospf_obj.config_ospf_router, data.dut1, 'default', '','no'],
                             [ospf_obj.config_ospf_router, data.dut3, 'default', '','no']])


def config_ipunnumbered(config='yes'):
    if config == 'yes':
        hdrMsg('Configure IP unnumbered on Physical interfaces between DUT1 and DUT3')
        dict1 = {'family':'ipv4', 'action':'add','interface':'PortChannel14', 'loop_back':'Loopback1'}
        dict2 = {'family':'ipv4', 'action':'add','interface':'PortChannel14', 'loop_back':'Loopback1'}
        parallel.exec_parallel(True, [data.dut1, data.dut3], ip_api.config_unnumbered_interface, [dict1, dict2])
    else:
        hdrMsg('UnConfig IP unnumbered on Physical interfaces between DUT1 and DUT3')
        dict1 = {'family':'ipv4', 'action':'del','interface':'PortChannel14', 'loop_back':'Loopback1'}
        dict2 = {'family':'ipv4', 'action':'del','interface':'PortChannel14', 'loop_back':'Loopback1'}
        parallel.exec_parallel(True, [data.dut1, data.dut3], ip_api.config_unnumbered_interface, [dict1, dict2])

def config_dhcpRelay(action='add'):
    hdrMsg("Configure dhcp relay on DUT2")
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=data.dhcp_server_ip,vlan='Vlan100',action=action)
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.d2d4_ports[1], IP=data.dhcp_server_ip,action=action)
    dhcp_relay.dhcp_relay_config(data.dut2, interface='PortChannel12', IP=data.dhcp_server_ip,action=action)


def hdrMsg(msg):
    st.log("\n######################################################################" \
    " \n %s \n######################################################################"%msg)


def check_ping_dhcpserver(dut):
    hdrMsg("Verify reachabality to dhcp server drom dut2")
    result =ip_api.ping(dut, data.dhcp_server_ip)
    if result is False:
        st.error("Dhcp server is not reachable from dut2")
        return False
    return True

def print_topology():
    ######################################################
    hdrMsg(" #####  DHCP Relay over ipunnumbered Topology  ######")
    ######################################################
    topology = r"""




[DHCP CLient-DUT4]------ DUT2[DHCP Relay] ---------- DUT3 ------------ DUT1(DHCP SERVER)



    """
    st.log(topology)

def failMsg(msg, debug='no'):
    st.error("\n++++++++++++++++++++++++++++++++++++++++++++++" \
             " \n FAILED : {} \n++++++++++++++++++++++++++++++++++++++++++++++".format(msg))


def check_dhcp_client(interface='',network_pool='',family='ipv4',entry=True):
    if family == 'ipv4':
        ip = basic_api.get_ifconfig_inet(data.dut4,interface)
    else:
        ip = basic_api.get_ifconfig_inet6(data.dut4,interface)
        if len(ip) > 0:
            for ip_item in ip:
                if 'fe80' in ip_item:
                    ip.remove(ip_item)
    if len(ip) == 0:
        if entry is True:
            st.error("{} address assignment failed on {}".format(family,interface))
            return False
        else:
            st.log(" {} address did not get assigned as expected on {}".format(family,interface))
            return True
    else:
        if entry is False:
            st.error(" {} address got assigned on {} which is not expected".format(family,interface))
            return False
        else:
            ip_add = ip[0]
            if family == 'ipv4':
                ip = ip_add.split('.')[:-1]
                network_octet = ".".join(ip) +'.'
            else:
                network_octet = ip_add.split("::")[0] + "::"
            if interface == data.d4d2_ports[1] and family =='ipv4':
                data.ip_add_phy = ip_add
            else:
                data.ip_add_phy_v6 = ip_add.rstrip()
            st.log("offered_ip {}".format(ip_add))
            if str(network_octet) != str(network_pool):
                st.error("{} IP_address_assignment not in expected subnet on {}".format(family,interface))
                return False
    return True


def dhcp_server_config():
    '''
    1. Install dhcp package
    2. Update dhcp files - dhcpd6.conf  dhcpd.conf  isc-dhcp-server
    3. Add static routes
    4.Restart dhcp process
    '''
    hdrMsg("Installing and configuring the dhcp server on dut1")
    dut = data.dut1
    copy_files_to_dut(st.get_mgmt_ip(dut))
#    st.config(dut,'sudo mv /tmp/'+data.dhcp_files[0]+' /etc/default/'+server_filename,skip_error_check=True)
#    st.config(dut,'sudo mv /tmp/'+data.dhcp_files[1]+' /etc/dhcp/',skip_error_check=True)
#    st.config(dut,'sudo mv /tmp/'+data.dhcp_files[2]+' /etc/dhcp/',skip_error_check=True)
    basic_api.move_file_to_local_path(dut, '/tmp/'+data.dhcp_files[0], '/etc/default/'+server_filename, sudo=True, skip_error_check=True)
    basic_api.move_file_to_local_path(dut, '/tmp/'+data.dhcp_files[1], '/etc/dhcp/', sudo=True, skip_error_check=True)
    basic_api.move_file_to_local_path(dut, '/tmp/'+data.dhcp_files[2], '/etc/dhcp/', sudo=True, skip_error_check=True)

    for ip in route_list:
        ip_api.create_static_route(dut, next_hop= dut3_loopback_ip_list[0],static_ip=ip)

    basic_api.deploy_package(dut, mode='update')
    basic_api.deploy_package(dut, options='-o Dpkg::Options::=\"--force-confold\"', packane_name='isc-dhcp-server', mode='install',skip_verify_package=True)
    #st.config(dut, "systemctl restart isc-dhcp-server")
    st.wait(2)
    ps_aux = basic_api.get_ps_aux(data.dut1, "dhcpd")
    if len(ps_aux) > 1:
        hdrMsg("dhcp server is up and running in dut1")
        return True
    #st.config(dut, "systemctl restart isc-dhcp-server")
    basic_api.service_operations_by_systemctl(dut, operation='restart', service='isc-dhcp-server')
    ps_aux = basic_api.get_ps_aux(data.dut1, "dhcpd")
    st.wait(2)
    if len(ps_aux) < 1:
        hdrMsg("dhcp server is not up and running in dut1")
        return False
    return True

def dhcp_server_unconfig():
    dut = data.dut1
    hdrMsg("Stoping the dhcp server on dut1")
    #st.config(dut, "systemctl stop isc-dhcp-server")
    basic_api.service_operations_by_systemctl(dut, operation='stop', service='isc-dhcp-server')
    for ip in route_list:
        ip_api.delete_static_route(dut, next_hop= dut3_loopback_ip_list[0],static_ip=ip)


def copy_files_to_dut(dut_ip,username='admin',password='broadcom'):
    ssh = SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(dut_ip, username=username, password=st.get_credentials(data.dut1)[3])
    #ssh.connect(dut_ip, username=username, password='broadcom')
    ssh.exec_command('sudo -i')
    scp = SCPClient(ssh.get_transport())
    for dhcp_conf_file in data.dhcp_files_path:
        scp.put(dhcp_conf_file,"/tmp")
    scp.close()

def verify_ospf():
    hdrMsg("Verifying ospf neighbors on dut1 and dut3")
    result1 = retry_api(ospf_obj.verify_ospf_neighbor_state,data.dut3,ospf_links=['PortChannel14'], states=['Full'],retry_count=10,delay=20)
    result2 = retry_api(ospf_obj.verify_ospf_neighbor_state,data.dut1,ospf_links=['PortChannel14'], states=['Full'],retry_count=10,delay=20)
    if False in [result1,result2]:
        st.error("Ospf sneighbors did not come up between dut1 and dut3")
        return False
    return True

def create_static_route_dut2():
    ##########################################################
    hdrMsg("Create static route on dut2 ")
    ##########################################################
    ip_api.create_static_route(data.dut2, next_hop=dut3_2_ip_list[0],static_ip='{}/32'.format(dut1_loopback_ip_list[0]))
    ip_api.create_static_route(data.dut2, next_hop=dut3_2_ip_list[0],static_ip='{}/32'.format(dut3_loopback_ip_list[0]))

def create_static_route_dut3():
    ##########################################################
    hdrMsg("Create static route on dut3 ")
    ##########################################################
    ip_api.create_static_route(data.dut3, next_hop=dut2_3_ip_list[0],static_ip='{}'.format(route_list[0]))
    ip_api.create_static_route(data.dut3, next_hop=dut2_3_ip_list[0],static_ip='{}'.format(route_list[1]))
    ip_api.create_static_route(data.dut3, next_hop=dut2_3_ip_list[0],static_ip='{}'.format(route_list[3]))
    ip_api.create_static_route(data.dut3, next_hop=dut2_3_ip_list[0],static_ip='{}'.format(route_list[4]))

def delete_static_route_dut2():
    ##########################################################
    hdrMsg("Delete static route on dut2 ")
    ##########################################################
    ip_api.delete_static_route(data.dut2, next_hop=dut3_2_ip_list[0],static_ip='{}/32'.format(dut1_loopback_ip_list[0]))
    ip_api.delete_static_route(data.dut2, next_hop=dut3_2_ip_list[0],static_ip='{}/32'.format(dut3_loopback_ip_list[0]))

def delete_static_route_dut3():
    ##########################################################
    hdrMsg("Delete static route on dut3 ")
    ##########################################################
    ip_api.delete_static_route(data.dut3, next_hop=dut2_3_ip_list[0],static_ip='{}'.format(route_list[0]))
    ip_api.delete_static_route(data.dut3, next_hop=dut2_3_ip_list[0],static_ip='{}'.format(route_list[1]))
    ip_api.delete_static_route(data.dut3, next_hop=dut2_3_ip_list[0],static_ip='{}'.format(route_list[3]))
    ip_api.delete_static_route(data.dut3, next_hop=dut2_3_ip_list[0],static_ip='{}'.format(route_list[4]))


