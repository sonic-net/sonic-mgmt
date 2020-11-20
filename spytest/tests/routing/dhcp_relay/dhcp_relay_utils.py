
from spytest import st,utils, mutils

from dhcp_relay_vars import *
from dhcp_relay_vars import data
import apis.switching.portchannel as pc
import apis.switching.vlan as vlan_api
import apis.routing.ip as ip_api
import apis.routing.evpn as evpn
import apis.routing.bgp as bgp_api
import apis.routing.ip_bgp as ip_bgp
import apis.routing.vrf as vrf_api
import apis.routing.dhcp_relay as dhcp_relay
import apis.system.basic as basic_api
import apis.system.interface as interface_api
import apis.system.connection as con_obj
import apis.qos.copp as copp_api
from utilities import parallel
from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient
import re

def dhcp_relay_base_config():
    ###################################################
    hdrMsg("########## BASE Config Starts ########")
    ###################################################
    config_ip()
    config_bgp()
    result = verify_bgp()
    if not result:
        st.error('BGP neighbor is not up between dut1 to dut2')
        #config_bgp(config='no')
        #config_ip(config='no')
        return False
    config_leafInterface()
    config_vxLan()
    result = verify_vxlan()

    if not result:
        debug_vxlan_dhcp_relay()
        #config_vxLan(config='no')
        #config_leafInterface(config='no')
        #config_bgp(config='no')
        #config_ip(config='no')
        return False
    # Install and Configure DHCP server
    result1 = dhcp_server_config()
    result2 = check_ping_dhcpserver(data.dut2)
    if False in [result1,result2]:
        st.error('Either ping to server or dhcp server configuration failed')
        debug_vxlan_dhcp_relay()
        #config_vxLan(config='no')
        #config_leafInterface(config='no')
        #config_bgp(config='no')
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
    config_vxLan(config='no')
    config_leafInterface(config='no')
    config_bgp(config='no')
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

    st.log("Bring-up the port on dut3 which is connected to dhcp server ")
    interface_api.interface_operation(data.dut3, data.dhcp_server_port, operation="startup")
    ##########################################################################
    hdrMsg("IP-config: {} IP address between dut1 interface {} and dut2 interface {}".format(config_str,data.d1d2_ports,data.d2d1_ports))
    ##########################################################################
    utils.exec_all(True, [[api_name, data.dut1, data.d1d2_ports[0], dut1_2_ip_list[0], mask],[api_name, data.dut2, data.d2d1_ports[0], dut2_1_ip_list[0], mask]])
    utils.exec_all(True, [[api_name, data.dut1, data.d1d2_ports[0], dut1_2_ipv6_list[0], mask_v6,'ipv6'],[api_name, data.dut2, data.d2d1_ports[0], dut2_1_ipv6_list[0], mask_v6,'ipv6']])

    ##########################################################################
    hdrMsg("IP-config: {} IP address between dut1 interface {} and dut3 interface {}".format(config_str,data.d1d3_ports,data.d3d1_ports))
    ##########################################################################
    utils.exec_all(True, [[api_name, data.dut1, data.d1d3_ports[0], dut1_3_ip_list[0], mask],[api_name, data.dut3, data.d3d1_ports[0], dut3_1_ip_list[0], mask]])
    utils.exec_all(True, [[api_name, data.dut1, data.d1d3_ports[0], dut1_3_ipv6_list[0], mask_v6,'ipv6'],[api_name, data.dut3, data.d3d1_ports[0], dut3_1_ipv6_list[0], mask_v6,'ipv6']])

    ##########################################################################
    hdrMsg("IP-config: {} IP address between dut2 interface {} and dut4 interface {}".format(config_str,data.d2d4_ports,data.d4d2_ports))
    ##########################################################################
    #utils.exec_all(True, [[api_name, data.dut2, data.d2d4_ports[0], dut2_4_ip_list[0], mask]])

    ##########################################################################
    #hdrMsg("IP-config: {} IP address between dut3 interface {} and dhcp server".format(config_str,data.dhcp_server_port))
    ##########################################################################
    #utils.exec_all(True, [[api_name, data.dut3, data.dhcp_server_port, data.dut3_server_ip_list[0], mask_1]])

    if config == 'yes':
        st.banner('Install L2 DHCP rules on dhcp client device')
        copp_api.bind_class_action_copp_policy(data.dut4, classifier='copp-system-dhcpl2', action_group='copp-system-dhcp')
        ##########################################################################
        hdrMsg("Create loopback interfaces on dut1, dut2 and dut3")
        ##########################################################################
        parallel.exec_parallel(True, [data.dut1,data.dut2,data.dut3], ip_api.configure_loopback,[{'loopback_name': 'Loopback1'}] * 3)
        parallel.exec_parallel(True, [data.dut1,data.dut2,data.dut3], ip_api.configure_loopback,[{'loopback_name': 'Loopback2'}] * 3)

        ##########################################################################
        hdrMsg("Loopback-config: {} IP address on Loopback interface".format(config_str))
        ##########################################################################
        utils.exec_all(True, [[api_name, data.dut1, "Loopback1", dut1_loopback_ip_list[0], '32'],[api_name, data.dut2, "Loopback1", dut2_loopback_ip_list[0], '32'],[api_name, data.dut3, "Loopback1", dut3_loopback_ip_list[0], '32']])
        utils.exec_all(True, [[api_name, data.dut1, "Loopback2", dut1_loopback_ip_list[1], '32'],[api_name, data.dut2, "Loopback2", dut2_loopback_ip_list[1], '32'],[api_name, data.dut3, "Loopback2", dut3_loopback_ip_list[1], '32']])

        ##########################################################################
        hdrMsg("Create static route on dut1, dut2 and dut3")
        ##########################################################################
        ip_api.create_static_route(data.dut1, next_hop=dut2_1_ip_list[0],static_ip='{}/32'.format(dut2_loopback_ip_list[0]))
        ip_api.create_static_route(data.dut1, next_hop=dut3_1_ip_list[0],static_ip='{}/32'.format(dut3_loopback_ip_list[0]))
        ip_api.create_static_route(data.dut2, next_hop=dut1_2_ip_list[0],static_ip='{}/32'.format(dut1_loopback_ip_list[0]))
        ip_api.create_static_route(data.dut3, next_hop=dut1_3_ip_list[0],static_ip='{}/32'.format(dut1_loopback_ip_list[0]))
    else:
        st.banner('Remove L2 DHCP rules on dhcp client device')
        copp_api.bind_class_action_copp_policy(data.dut4, classifier='copp-system-dhcpl2', action_group='copp-system-dhcp',config='no')
        ##########################################################################
        hdrMsg("Loopback-config: {} IP address on Loopback interface".format(config_str))
        ##########################################################################
        utils.exec_all(True, [[api_name, data.dut1, "Loopback1", dut1_loopback_ip_list[0], '32'],[api_name, data.dut2, "Loopback1", dut2_loopback_ip_list[0], '32'],[api_name, data.dut3, "Loopback1", dut3_loopback_ip_list[0], '32']])
        utils.exec_all(True, [[api_name, data.dut1, "Loopback2", dut1_loopback_ip_list[1], '32'],[api_name, data.dut2, "Loopback2", dut2_loopback_ip_list[1], '32'],[api_name, data.dut3, "Loopback2", dut3_loopback_ip_list[1], '32']])

        ##########################################################################
        hdrMsg("Delete loopback interfaces on dut1, dut2 and dut3")
        ##########################################################################
        parallel.exec_parallel(True, [data.dut1,data.dut2,data.dut3], ip_api.configure_loopback,[{'loopback_name': 'Loopback1','config':'no'}] * 3)
        parallel.exec_parallel(True, [data.dut1,data.dut2,data.dut3], ip_api.configure_loopback,[{'loopback_name': 'Loopback2','config':'no'}] * 3)

        ##########################################################################
        hdrMsg("delete static route on dut1, dut2 and dut3")
        ##########################################################################
        ip_api.delete_static_route(data.dut1, next_hop=dut2_1_ip_list[0],static_ip='{}/32'.format(dut2_loopback_ip_list[0]))
        ip_api.delete_static_route(data.dut1, next_hop=dut3_1_ip_list[0],static_ip='{}/32'.format(dut3_loopback_ip_list[0]))
        ip_api.delete_static_route(data.dut2, next_hop=dut1_2_ip_list[0],static_ip='{}/32'.format(dut1_loopback_ip_list[0]))
        ip_api.delete_static_route(data.dut3, next_hop=dut1_3_ip_list[0],static_ip='{}/32'.format(dut1_loopback_ip_list[0]))


def config_bgp(config='yes'):
    if config == 'yes':
        ##########################################################################
        hdrMsg("BGP-config: Configure BGP underlay between dut1,dut2 and dut3")
        ##########################################################################

        ##########################################################################
        hdrMsg("BGP-config: Configure  EBGP sessions between dut1 <--> dut2 and dut1 <--> dut3 ")
        ##########################################################################
        update = 'update_src' if st.get_ui_type(data.dut1) == 'click' else 'update_src_intf'
        dict1 = {'local_as':dut1_AS, 'remote_as':dut2_AS,'neighbor':dut2_loopback_ip_list[0],'config_type_list': ['neighbor','ebgp_mhop',update,'connect'], 'ebgp_mhop':'2',update:'Loopback1','connect':'3'}
        dict2 = {'local_as':dut2_AS, 'remote_as':dut1_AS,'neighbor':dut1_loopback_ip_list[0],'config_type_list': ['neighbor','ebgp_mhop',update,'connect'],'ebgp_mhop':'2',update:'Loopback1','connect':'3'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])


        dict1 = {'local_as':dut1_AS, 'remote_as':dut3_AS,'neighbor':dut3_loopback_ip_list[0],'config_type_list': ['neighbor','ebgp_mhop',update,'connect'], 'ebgp_mhop':'2',update:'Loopback1','connect':'3'}
        dict2 = {'local_as':dut3_AS, 'remote_as': dut1_AS,'neighbor': dut1_loopback_ip_list[0],'config_type_list': ['neighbor','ebgp_mhop',update,'connect'], 'ebgp_mhop':'2',update:'Loopback1','connect':'3'}
        parallel.exec_parallel(True, [data.dut1, data.dut3], bgp_api.config_bgp, [dict1, dict2])

        utils.exec_all(True, [[bgp_api.config_bgp_router,data.dut1,dut1_AS, '', '3', '9', 'yes'],
                              [bgp_api.config_bgp_router,data.dut2,dut2_AS, '', '3', '9', 'yes'],
                              [bgp_api.config_bgp_router,data.dut3,dut3_AS, '', '3', '9', 'yes']])

        evpn.config_bgp_evpn(dut=data.dut1,neighbor =dut2_loopback_ip_list[0],config='yes',config_type_list =["activate"],local_as=dut1_AS,remote_as =dut2_AS)
        evpn.config_bgp_evpn(dut=data.dut1,neighbor =dut3_loopback_ip_list[0],config='yes',config_type_list =["activate"],local_as=dut1_AS,remote_as =dut3_AS)

        evpn.config_bgp_evpn(dut=data.dut2,neighbor =dut1_loopback_ip_list[0],config='yes',config_type_list =["activate"],local_as=dut2_AS,remote_as=dut1_AS)
        evpn.config_bgp_evpn(dut=data.dut3,neighbor =dut1_loopback_ip_list[0],config='yes',config_type_list =["activate"],local_as=dut3_AS,remote_as=dut1_AS)
        evpn.config_bgp_evpn(dut=data.dut1,config = 'yes',config_type_list=["advertise_all_vni"],local_as=dut1_AS)
        evpn.config_bgp_evpn(dut=data.dut2,config = 'yes',config_type_list=["advertise_all_vni"],local_as=dut2_AS)
        evpn.config_bgp_evpn(dut=data.dut3,config = 'yes',config_type_list=["advertise_all_vni"],local_as=dut3_AS)
    else:
        ##########################################################################
        hdrMsg("BGP-Deconfig: Delete BGP routers globally from all DUTs")
        ##########################################################################
        dict1 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'local_as':dut1_AS, 'config': 'no'}
        dict2 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'local_as':dut2_AS, 'config': 'no'}
        dict3 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'local_as':dut3_AS, 'config': 'no'}
        parallel.exec_parallel(True, [data.dut1,data.dut2,data.dut3], bgp_api.config_bgp, [dict1, dict2, dict3])


def config_leafInterface(config='yes'):
    if config == 'yes':
        ##################################################################
        hdrMsg("Step01: VRF-Config- Configure VRF on dut2 and dut3 ")
        ##################################################################
        dict1 = {'vrf_name':vrf_name, 'config': 'yes'}
        parallel.exec_parallel(True, [data.dut2, data.dut3], vrf_api.config_vrf, [dict1, dict1])
        if data.inter_vni:
            vrf_api.config_vrf(data.dut2, vrf_name=vrf_blue, config='yes')

        st.log("config vlan for vteps")
        vlan_api.create_vlan(data.dut2, ['500'])
        vlan_api.create_vlan(data.dut2, ['100'])
        vlan_api.create_vlan(data.dut2, ['600'])
        vlan_api.create_vlan(data.dut4, ['100'])
        vlan_api.create_vlan(data.dut3, ['500'])

        st.log("Add vlan members")
        vlan_api.add_vlan_member(data.dut2,'500',data.d2d4_ports[0],tagging_mode=True)
        vlan_api.add_vlan_member(data.dut2,'100',data.d2d4_ports[0],tagging_mode=True)
        vlan_api.add_vlan_member(data.dut4,'100',data.d4d2_ports[0],tagging_mode=True)

        st.log("LAG-Config: Create portchannel on dut2 and dut4")
        pc.create_portchannel(data.dut2, ['PortChannel12'])
        pc.create_portchannel(data.dut4, ['PortChannel12'])

        st.log("LAG-Config: add member ports to portchannel")
        pc.add_del_portchannel_member(data.dut2, 'PortChannel12',data.d2d4_ports[2],'add')
        pc.add_del_portchannel_member(data.dut4, 'PortChannel12',data.d4d2_ports[2],'add')
        #########################################################ata.########
        hdrMsg("Step02: bind-VRF-to-interface- on dut2 and dut3 devices")
        #################################################################
        vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_name, intf_name ='Vlan500',skip_error='True')
        vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_name, intf_name ='Vlan100',skip_error='True')
        if data.inter_vni:
            vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_blue, intf_name ='Vlan600',skip_error='True')
            vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_blue, intf_name =data.d2d4_ports[1],skip_error='True')
            #vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_blue, intf_name=src_intf_diff_vni, skip_error='True')
            #ip_api.config_ip_addr_interface(data.dut2,src_intf_diff_vni,'100.100.100.200','32')
            #ip_api.config_ip_addr_interface(data.dut2, src_intf_diff_vni, '4000::200', '128',family="ipv6")
        else:
            vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_name, intf_name =data.d2d4_ports[1],skip_error='True')
        vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_name, intf_name ='PortChannel12',skip_error='True')
        vrf_api.bind_vrf_interface(data.dut3,vrf_name =vrf_name, intf_name ='Vlan500',skip_error='True')
        vrf_api.bind_vrf_interface(data.dut3,vrf_name =vrf_name, intf_name =data.dhcp_server_port,skip_error='True')
        vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name=src_intf_same_vni, skip_error='True')

        ip_api.config_ip_addr_interface(data.dut2,src_intf_same_vni,'100.100.100.100','32')
        ip_api.config_ip_addr_interface(data.dut2, src_intf_same_vni, '4000::10', '128',family="ipv6")
        ip_api.config_ip_addr_interface(data.dut2,'Vlan500', '22.22.1.1',mask_24)
        ip_api.config_ip_addr_interface(data.dut2, 'Vlan500', '1212::1', mask_v6,family='ipv6')
        ip_api.config_ip_addr_interface(data.dut2,'Vlan100', dut2_4_ip_list[0],mask_24)
        ip_api.config_ip_addr_interface(data.dut2,'Vlan100', dut2_4_ipv6_list[0],mask_v6,family="ipv6")
        ip_api.config_ip_addr_interface(data.dut2,data.d2d4_ports[1], dut2_4_ip_list[1],mask_24)
        ip_api.config_ip_addr_interface(data.dut2,data.d2d4_ports[1], dut2_4_ipv6_list[1],mask_v6,family="ipv6")
        ip_api.config_ip_addr_interface(data.dut2,'PortChannel12', dut2_4_ip_list[2],mask_24)
        ip_api.config_ip_addr_interface(data.dut2,'PortChannel12', dut2_4_ipv6_list[2],mask_v6,family="ipv6")
        ip_api.config_ip_addr_interface(data.dut3,'Vlan500', '33.33.1.1',mask_24)
        ip_api.config_ip_addr_interface(data.dut3, 'Vlan500', '1313::1', mask_v6,family='ipv6')
        ip_api.config_ip_addr_interface(data.dut3,data.dhcp_server_port,data.dut3_server_ip_list[0],mask_24)
        ip_api.config_ip_addr_interface(data.dut3,data.dhcp_server_port,data.dut3_server_ipv6_list[0],mask_v6,family="ipv6")

    else:
        hdrMsg("Step02: Remove all the configs")
        ip_api.delete_ip_interface(data.dut2,'Vlan500', '22.22.1.1',mask_24)
        ip_api.delete_ip_interface(data.dut2, 'Vlan500', '1212::1', mask_v6,family='ipv6')
        ip_api.delete_ip_interface(data.dut2,'Vlan100', dut2_4_ip_list[0],mask_24)
        ip_api.delete_ip_interface(data.dut2,'Vlan100', dut2_4_ipv6_list[0],mask_v6,family="ipv6")
        ip_api.delete_ip_interface(data.dut2,data.d2d4_ports[1], dut2_4_ip_list[1],mask_24)
        ip_api.delete_ip_interface(data.dut2,data.d2d4_ports[1], dut2_4_ipv6_list[1],mask_v6,family="ipv6")
        ip_api.delete_ip_interface(data.dut2,'PortChannel12', dut2_4_ip_list[2],mask_24)
        ip_api.delete_ip_interface(data.dut2,'PortChannel12', dut2_4_ipv6_list[2],mask_v6,family="ipv6")
        ip_api.delete_ip_interface(data.dut3,'Vlan500', '33.33.1.1',mask_24)
        ip_api.delete_ip_interface(data.dut3, 'Vlan500', '1313::1', mask_v6,family='ipv6')
        ip_api.delete_ip_interface(data.dut3,data.dhcp_server_port,data.dut3_server_ip_list[0],mask_24)
        ip_api.delete_ip_interface(data.dut3,data.dhcp_server_port,data.dut3_server_ipv6_list[0],mask_v6,family="ipv6")
        ip_api.delete_ip_interface(data.dut2,src_intf_same_vni,'100.100.100.100','32')
        ip_api.delete_ip_interface(data.dut2, src_intf_same_vni, '4000::10', '128',family="ipv6")

        #########################################################ata.########
        hdrMsg("Step02: unbind-VRF-to-interface- on dut2 and dut3 devices")
        #################################################################
        vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_name, intf_name ='Vlan500',config = 'no',skip_error='True')
        vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_name, intf_name ='Vlan100',config = 'no',skip_error='True')
        if data.inter_vni:
            #ip_api.delete_ip_interface(data.dut2,src_intf_diff_vni,'100.100.100.200','32')
            #ip_api.delete_ip_interface(data.dut2, src_intf_diff_vni, '4000::200', '128',family="ipv6")
            #vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_blue, intf_name=src_intf_diff_vni,config = 'no', skip_error='True')
            vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_blue, intf_name ='Vlan600', config='no', skip_error='True')
            vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_blue, intf_name =data.d2d4_ports[1], config='no', skip_error='True')
        else:
            vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_name, intf_name =data.d2d4_ports[1],config = 'no',skip_error='True')
        vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_name, intf_name ='PortChannel12',config = 'no',skip_error='True')
        vrf_api.bind_vrf_interface(data.dut3,vrf_name =vrf_name, intf_name ='Vlan500',config = 'no',skip_error='True')
        vrf_api.bind_vrf_interface(data.dut3,vrf_name =vrf_name, intf_name =data.dhcp_server_port,config = 'no',skip_error='True')
        vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name=src_intf_same_vni,config = 'no', skip_error='True')

        st.log("LAG-unConfig: delete member ports to portchannel")
        pc.add_del_portchannel_member(data.dut2, 'PortChannel12',data.d2d4_ports[2],'del')
        pc.add_del_portchannel_member(data.dut4, 'PortChannel12',data.d4d2_ports[2],'del')

        st.log("LAG-UnConfig: Delete portchannel on dut2")
        pc.delete_portchannel(data.dut2, ['PortChannel12'])
        pc.delete_portchannel(data.dut4, ['PortChannel12'])
        ##################################################################
        hdrMsg("Step01: VRF-Config- Configure VRF on dut2 and dut3 ")
        ##################################################################
        st.log("Delete vlan member ports")
        vlan_api.delete_vlan_member(data.dut2,'500',data.d2d4_ports[0],tagging_mode=True)
        vlan_api.delete_vlan_member(data.dut2,'100',data.d2d4_ports[0],tagging_mode=True)
        vlan_api.delete_vlan_member(data.dut4,'100',data.d4d2_ports[0],tagging_mode=True)

        st.log("Unconfig vlan for vteps")
        vlan_api.delete_vlan(data.dut2, ['500'])
        vlan_api.delete_vlan(data.dut2, ['600'])
        vlan_api.delete_vlan(data.dut2, ['100'])
        vlan_api.delete_vlan(data.dut4, ['100'])
        vlan_api.delete_vlan(data.dut3, ['500'])

        dict1 = {'vrf_name':vrf_name, 'config': 'no'}
        parallel.exec_parallel(True, [data.dut2, data.dut3], vrf_api.config_vrf, [dict1, dict1])
        if data.inter_vni:
            vrf_api.config_vrf(data.dut2, vrf_name=vrf_blue, config='no')


def config_vxLan(config='yes'):
    if config == 'yes':
        ##################################################################
        hdrMsg("Step01: config vtep on all leaf nodes ")
        ##################################################################
        evpn.create_overlay_intf(data.dut2, "vtepLeaf1",dut2_loopback_ip_list[1])
        evpn.create_overlay_intf(data.dut3, "vtepLeaf2",dut3_loopback_ip_list[1])

        st.log("config evpn nvo instance on all leaf nodes")
        evpn.create_evpn_instance(data.dut2, "nvoLeaf1", "vtepLeaf1")
        evpn.create_evpn_instance(data.dut3, "nvoLeaf1", "vtepLeaf2")

        evpn.map_vlan_vni(data.dut2, "vtepLeaf1", "500", "500")
        evpn.map_vrf_vni(data.dut2, vrf_name,vtep_name="vtepLeaf1", vni="500")
        if data.inter_vni:
            evpn.map_vlan_vni(data.dut2, "vtepLeaf1", "600", "600")
            evpn.map_vrf_vni(data.dut2, vrf_blue,vtep_name="vtepLeaf1", vni="600")

        evpn.map_vlan_vni(data.dut3, "vtepLeaf2", "500", "500")
        evpn.map_vrf_vni(data.dut3, vrf_name,vtep_name="vtepLeaf2", vni="500")

        ##########################################################################
        hdrMsg("BGP-config: Configure bgp on DUT2 for Vtep ")
        ##########################################################################
        bgp_api.config_bgp(data.dut2,local_as=dut2_AS,vrf_name=vrf_name,config = 'yes',config_type_list =["redist"], redistribute ='connected')
        bgp_api.config_bgp(data.dut2,local_as=dut2_AS,vrf_name=vrf_name,config = 'yes',config_type_list =["redist"], redistribute ='connected',addr_family ='ipv6')
        bgp_api.config_bgp(data.dut2,local_as=dut2_AS,config = 'yes',config_type_list =["redist"], redistribute ='connected')
        evpn.config_bgp_evpn(data.dut2,vrf_name=vrf_name,config ='yes',config_type_list=["advertise_ipv4_vrf"],local_as=dut2_AS,advertise_ipv4='unicast')
        evpn.config_bgp_evpn(data.dut2,vrf_name=vrf_name,config ='yes',config_type_list=["advertise_ipv6_vrf"],local_as=dut2_AS,advertise_ipv6='unicast')

        if data.inter_vni:
            bgp_api.config_bgp(data.dut2, local_as=dut2_AS, vrf_name=vrf_name, addr_family ='ipv4', config_type_list=["import_vrf"], import_vrf_name=vrf_blue)
            bgp_api.config_bgp(data.dut2, local_as=dut2_AS, vrf_name=vrf_blue, config_type_list =["redist"], redistribute ='connected')
            bgp_api.config_bgp(data.dut2, local_as=dut2_AS, vrf_name=vrf_blue, config_type_list =["redist"], redistribute ='connected',addr_family ='ipv6')
            evpn.config_bgp_evpn(data.dut2, local_as=dut2_AS, vrf_name=vrf_blue, config ='yes', config_type_list=["advertise_ipv4_vrf"], advertise_ipv4='unicast')
            evpn.config_bgp_evpn(data.dut2, local_as=dut2_AS, vrf_name=vrf_blue, config ='yes', config_type_list=["advertise_ipv6_vrf"], advertise_ipv6='unicast')
            bgp_api.config_bgp(data.dut2, local_as=dut2_AS, vrf_name=vrf_blue, addr_family ='ipv4', config_type_list=["import_vrf"], import_vrf_name=vrf_name)

        bgp_api.config_bgp(data.dut3,local_as=dut3_AS,vrf_name=vrf_name,config = 'yes',config_type_list =["redist"], redistribute ='connected')
        bgp_api.config_bgp(data.dut3,local_as=dut3_AS,vrf_name=vrf_name,config = 'yes',config_type_list =["redist"], redistribute ='connected',addr_family ='ipv6')
        bgp_api.config_bgp(data.dut3,local_as=dut3_AS,config = 'yes',config_type_list =["redist"], redistribute ='connected')
        evpn.config_bgp_evpn(data.dut3,vrf_name=vrf_name,config ='yes',config_type_list=["advertise_ipv4_vrf"],local_as=dut3_AS,advertise_ipv4='unicast')
        evpn.config_bgp_evpn(data.dut3,vrf_name=vrf_name,config ='yes',config_type_list=["advertise_ipv6_vrf"],local_as=dut3_AS,advertise_ipv6='unicast')
    else:
        ##################################################################
        hdrMsg("Step01: Unconfig vtep on all leaf nodes ")
        ##################################################################
        evpn.map_vrf_vni(data.dut2, vrf_name, vtep_name="vtepLeaf1",vni="500",config='no')
        evpn.map_vrf_vni(data.dut3, vrf_name, vtep_name="vtepLeaf2",vni="500",config='no')
        evpn.map_vlan_vni(data.dut2, "vtepLeaf1", "500", "500",config='no')
        evpn.map_vlan_vni(data.dut3, "vtepLeaf2", "500", "500",config='no')
        if data.inter_vni:
            evpn.map_vrf_vni(data.dut2, vrf_blue,vtep_name='vtepLeaf1', vni="600", config='no')
            evpn.map_vlan_vni(data.dut2, "vtepLeaf1", "600", "600", config='no')

        evpn.create_evpn_instance(data.dut2, "nvoLeaf1", "vtepLeaf1", config='no')
        evpn.create_evpn_instance(data.dut3, "nvoLeaf1", "vtepLeaf2", config='no')

        evpn.create_overlay_intf(data.dut2, "vtepLeaf1",dut2_loopback_ip_list[1],config='no')
        evpn.create_overlay_intf(data.dut3, "vtepLeaf2",dut3_loopback_ip_list[1],config='no')

        dict1 = {'local_as':dut2_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':vrf_name}
        dict2 = {'local_as':dut3_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':vrf_name}
        parallel.exec_parallel(True, [data.dut2,data.dut3], bgp_api.config_bgp, [dict1,dict2])
        if data.inter_vni:
            bgp_api.config_bgp(data.dut2, local_as=dut2_AS, config_type_list=["removeBGP"], removeBGP='yes', config='no', vrf_name=vrf_blue)


def config_dhcpRelay(action='add'):
    st.log('Configure dhcp relay on leaf1')
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=data.dhcp_server_ip,vlan='Vlan100',action=action,vrf_name =vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.d2d4_ports[1], IP=data.dhcp_server_ip,action=action,vrf_name =vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface='PortChannel12', IP=data.dhcp_server_ip,action=action,vrf_name =vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=data.dhcp_server_ipv6,vlan='Vlan100',action=action,family='ipv6',vrf_name =vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.d2d4_ports[1], IP=data.dhcp_server_ipv6,action=action,family='ipv6',vrf_name =vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface='PortChannel12', IP=data.dhcp_server_ipv6,action=action,family='ipv6',vrf_name =vrf_name)

def hdrMsg(msg):
    st.log("\n######################################################################" \
    " \n %s \n######################################################################"%msg)

def retry_api(func,args,**kwargs):
    retry_count = kwargs.get("retry_count", 25)
    delay = kwargs.get("delay", 5)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if func(args,**kwargs):
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False

def retry_parallel(func,dict_list=[],dut_list=[],retry_count=5,delay=1):
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        result = parallel.exec_parallel(True,dut_list,func,dict_list)
        if False not in result[0]:
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False

def verify_bgp():
    ###########################################################
    hdrMsg("BGP verify: Verify BGP sessions are up on dut1")
    ############################################################

    result = retry_api(ip_bgp.check_bgp_session,data.dut1,nbr_list=[dut2_loopback_ip_list[0],dut3_loopback_ip_list[0]],state_list=['Established','Established'])
    if result is False:
        ip_api.ping(data.dut1, addresses=dut2_loopback_ip_list[0], count=5)
        ip_api.ping(data.dut1, addresses=dut3_loopback_ip_list[0], count=5)

        f1=lambda x: st.generate_tech_support(data.dut1, 'SPINE')
        f2=lambda x: st.generate_tech_support(data.dut2, 'LEAF1')
        f3=lambda x: st.generate_tech_support(data.dut3, 'LEAF2')
        [res, exceptions] = st.exec_all([[f1, 1], [f2, 1], [f3, 1]])

        st.error("one or more BGP sessions did not come up between dut1 and dut4")
        return False
    return True

def verify_vxlan():
    ###########################################################
    hdrMsg("verify Vxlan: Verify vxlan tunnels are up on dut2 and dut3")
    ############################################################
    result1 = retry_api(evpn.verify_vxlan_tunnel_status, data.dut2, src_vtep=dut2_loopback_ip_list[1], rem_vtep_list=[dut3_loopback_ip_list[1]], exp_status_list=['oper_up'])
    result2 = retry_api(evpn.verify_vxlan_tunnel_status, data.dut3, src_vtep=dut3_loopback_ip_list[1], rem_vtep_list=[dut2_loopback_ip_list[1]], exp_status_list=['oper_up'])
    if result1 is False or result2 is False:
        st.error("Vxlan tunnel did not come up between dut2 and dut3")
        return False
    return True

def check_ping_dhcpserver(dut):
    st.log('Verify reachabality to dhcp server from leaf1')
    result =ip_api.ping(dut, data.dhcp_server_ip,interface=vrf_name)
    if result is False:
        ip_api.traceroute(dut,addresses=data.dhcp_server_ip,vrf_name =vrf_name)
        result = retry_api(ip_api.ping, dut, addresses=data.dhcp_server_ip,interface=vrf_name)
        if result is False:
            st.error("Dhcp server is not reachable from leaf1 even after retry")                
            ip_api.traceroute(dut,addresses=data.dhcp_server_ip,vrf_name =vrf_name)
            return False
    
    result =ip_api.ping(dut, data.dhcp_server_ipv6,interface=vrf_name,family='ipv6')
    if result is False:
        ip_api.traceroute(dut,addresses=data.dhcp_server_ipv6,family='ipv6',vrf_name =vrf_name)
        result = retry_api(ip_api.ping, dut, addresses=data.dhcp_server_ipv6,interface=vrf_name,family='ipv6')
        if result is False:
            st.error("Dhcp server is not reachable from leaf1 even after retry")    
            ip_api.traceroute(dut,addresses=data.dhcp_server_ipv6,family='ipv6',vrf_name =vrf_name) 
            return False            
    return True

def print_topology():
    ######################################################
    hdrMsg(" #####  DHCP Relay over VTEP Topology  ######")
    ######################################################
    topology = r"""



                               DUT1[Spine]
                                 / \
      1-router port             /   \       1-router port
                               /     \
                              /       \
                             /         \
                            /           \
[DHCP CLient]------ DUT2[leaf1]        DUT3[leaf2] ---- (DHCP SERVER)



    """
    st.log(topology)

def failMsg(msg, debug='no'):
    st.error("\n++++++++++++++++++++++++++++++++++++++++++++++" \
             " \n FAILED : {} \n++++++++++++++++++++++++++++++++++++++++++++++".format(msg))
    if debug == 'yes':
        debug_vxlan_dhcp_relay()


def debug_vxlan_dhcp_relay():
    def leaf1():
        ip_api.show_ip_route(data.dut2)
        ip_api.show_ip_route(data.dut2, vrf_name =vrf_name)
        ip_api.show_ip_route(data.dut2,family='ipv6')
        ip_api.show_ip_route(data.dut2,family='ipv6',vrf_name =vrf_name)
        ip_api.get_interface_ip_address(data.dut2)
        ip_api.get_interface_ip_address(data.dut2,family='ipv6')
        evpn.verify_vxlan_tunnel_status(data.dut2,dut2_loopback_ip_list[1],[dut3_loopback_ip_list[1]],['oper_up'])
        ip_bgp.check_bgp_session(data.dut2)
        #for intf in data.relay_port:
        #    dhcp_relay.get_dhcp_relay_statistics(data.dut2,interface=intf)
        #for intf in data.relay_port:
        #    dhcp_relay.get_dhcp_relay_statistics(data.dut2,family='ipv6',interface=intf)
        
    def leaf2():
        ip_api.show_ip_route(data.dut3)
        ip_api.show_ip_route(data.dut3, vrf_name =vrf_name)
        ip_api.show_ip_route(data.dut3,family='ipv6')
        ip_api.show_ip_route(data.dut3,family='ipv6',vrf_name =vrf_name)
        ip_api.get_interface_ip_address(data.dut3)
        ip_api.get_interface_ip_address(data.dut3,family='ipv6')
        evpn.verify_vxlan_tunnel_status(data.dut3,dut3_loopback_ip_list[1],[dut2_loopback_ip_list[1]],['oper_up'])
        ip_bgp.check_bgp_session(data.dut3)     
        
    def spine():
        ip_api.show_ip_route(data.dut1)
        ip_api.show_ip_route(data.dut1,family='ipv6')
        ip_api.get_interface_ip_address(data.dut1)
        ip_api.get_interface_ip_address(data.dut1,family='ipv6')
        ip_bgp.check_bgp_session(data.dut1)

    utils.exec_all(True, [[leaf1], [leaf2], [spine]])


def check_dhcp_client(interface='',network_pool='',family='ipv4',entry=True):
    if False and re.search(r'Eth', interface, re.I):
        ip = list()
        ip_family = 'ipv4' if family=='ipv4' else 'ipv6'
        cmd_op = ip_api.get_interface_ip_address(data.dut4, interface_name=interface, family=ip_family)
        for item in cmd_op:
            if 'ipaddr' in item and 'fe80' not in item['ipaddr']:
                ip.append(item['ipaddr'].split('/')[0])
    else:
        if family == 'ipv4':
            ip = basic_api.get_ifconfig_inet(data.dut4,interface)
        else:
            ip = basic_api.get_ifconfig_inet6(data.dut4,interface)
            if len(ip) > 0:
                for ip_item in ip:
                    if 'fe80' in ip_item:
                        ip.remove(ip_item)
    st.log(ip)
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

            if family == 'ipv4':
                ################################################
                hdrMsg("Verify ping to default gateway from client")
                ################################################
                index = data.client_port.index(interface)
                ip = data.client_port_ip[index] if family == 'ipv4' else  data.client_port_ipv6[index]
                result = ip_api.ping(data.dut4,ip,family=family)
                if result is False:
                    st.error("Ping to {} Default failed for client connected to {}".format(family,interface))
                    return False
    return True


def check_dhcp_relay_interface_config(dut,interface=None,server_ip=None,family='ipv4'):
    if not dhcp_relay.verify_dhcp_relay(dut,interface, server_ip,family=family):
        st.error("{} IP_Helper_address_config_failed".format(family))
        return False
    return True

def check_dhcp_relay_statistics(dut,interface = "", family = "ipv4",expected='non_zero'):
    hdrMsg("Verify DHCP relay statistics on Leaf")
    ret_val = True
    if family == 'ipv4':
        client_stat_key = "dhcp_discover_msgs_received_by_the_relay_agent"
        server_stat_key = "dhcp_ack_msgs_sent_by_the_relay_agent"
    else:
        client_stat_key = "dhcpv6_solic_msgs_rcvd_by_the_relay_agent"
        server_stat_key = 'dhcpv6_reply_msgs_sent_by_the_relay_agent'
    stats = dhcp_relay.get_dhcp_relay_statistics(dut,interface = interface, family = family)
    st.log(stats)
    if stats:
        pkts_relayed_server_to_client = stats[0][server_stat_key]
        pkts_relayed_client_to_server = stats[0][client_stat_key]
        if str(expected) == '0':
            if  int(pkts_relayed_server_to_client) != int(0) :
                st.log("Counter {} statistics not  zero".format(server_stat_key))
                #ret_val = False
            if int(pkts_relayed_client_to_server) != int(0):
                st.error("Counter {} statistics not zero".format(client_stat_key))
                ret_val = False
        else:
            if  int(pkts_relayed_server_to_client) == int(0) :
                st.log("Counter {} not incremented".format(server_stat_key))
                #ret_val = False
            if int(pkts_relayed_client_to_server) == int(0):
                st.error("Counter {} not incremented".format(client_stat_key))
                ret_val = False
    else:
        ret_val = False
    return ret_val


def start_packet_capture(**kwargs):
    # tcpdump -U -i enp11s0f1 -nn -vvv port 67 and src 100.100.100.100 and 'udp[32:4] = 0x64646464' and 'udp[316:4] = 0xc0a8c864' > ~/op_file &
    # tcpdump -U -i enp11s0f1 -vvv -nn port 67 and src 200.200.200.200 and 'udp[32:4] = 0xc8c8c8c8' and '(udp[316:4] = 0xc0a8c801 or udp[322:4] = 0xc0a8c801)'
    # tcpdump -U -i enp11s0f1 -vvv -nn port 67 and src 100.100.100.100 and 'udp[32:4] = 0x64646464' and '(udp[316:4] = 0xc0a80001 or udp[322:4] = 0xc0a80001)'
    ip = kwargs.get('ip',st.get_mgmt_ip(data.dut1))
    username = kwargs.get('username', 'admin')
    password = kwargs.get('password', st.get_credentials(data.dut1)[3])
    family = kwargs.get('family','ipv4')
    output_file = kwargs.get('output_file', '{}_captured_packet_buffer'.format(family))

    if kwargs['intf'] != None:
        interface = kwargs['intf']
        if '/' in interface:
            interface = st.get_other_names(data.dut1,[interface])[0]
        filter = '-i ' + interface + ' -vvv -nn '
    port = kwargs.get('port', '67')
    filter = filter + 'port ' + port
    if kwargs.get('src_ip', None):
        filter = filter + ' and src ' + kwargs['src_ip']

    if kwargs.get('giaddr', None):
        hex_ip = ''.join([hex(int(i))[2:].zfill(2) for i in kwargs['giaddr'].split('.')])
        filter = filter + ' and \'udp[32:4] = 0x' + hex_ip + '\''

    if kwargs.get('link_select', None):
        hex_ip = ''.join([hex(int(i))[2:].zfill(2) for i in kwargs['link_select'].split('.')])
        filter = filter + ' and \'(udp[316:4] = 0x' + hex_ip + ' or udp[322:4] = 0x' + hex_ip + ')\''

    ssh_obj = con_obj.connect_to_device(ip, username, password, 'ssh')
    if ssh_obj:
        prompt = ssh_obj.find_prompt()
        command = 'sudo tcpdump -U ' + filter + ' > ' + output_file + ' &'
        st.log(command)
        output = ssh_obj.send_command(command, expect_string="{}|#|$".format(prompt))
        st.log(output)
        con_obj.ssh_disconnect(ssh_obj)
        if not output:
            return False


def validate_packet(**kwargs):
    ip = st.get_mgmt_ip(data.dut1)
    username = kwargs.get('username', 'admin')
    password = kwargs.get('password', st.get_credentials(data.dut1)[3])
    family = kwargs.get('family','ipv4')
    output_file = kwargs.get('output_file', '{}_captured_packet_buffer'.format(family))
    ret_val = False
    ssh_obj = con_obj.connect_to_device(ip, username, password, 'ssh')
    if ssh_obj:
        prompt = ssh_obj.find_prompt()
        command = 'sudo pkill tcpdump'
        st.log(command)
        output = ssh_obj.send_command(command, expect_string="{}|#|$".format(prompt))
        st.log(output)

        command = 'sudo cat ' + output_file
        st.log(command)
        output = ssh_obj.send_command(command, expect_string="{}|#|$".format(prompt))
        st.log(output)

        command = 'sudo cat ' + output_file + ' | wc -l'
        st.log(command)
        output = ssh_obj.send_command(command, expect_string="{}|#|$".format(prompt))
        st.log(output)
        num_of_packets = mutils.remove_last_line_from_string(output)
        st.log(num_of_packets)
        if int(num_of_packets) > 1:
            prompt = ssh_obj.find_prompt()
            command = 'sudo rm -f {}'.format(output_file)
            st.log(command)
            output = ssh_obj.send_command(command, expect_string="{}|#|$".format(prompt))
            st.log(output)
            ret_val= True
        con_obj.ssh_disconnect(ssh_obj)
    return ret_val



def killall_dhclient(dut):
    basic_api.killall_process(dut, name='dhclient', skip_error_check=True)
    basic_api.delete_file_from_local_path(dut, filename='/var/lib/dhcp/dhclient.leases', skip_error_check=True)
    basic_api.delete_file_from_local_path(dut, filename='/var/lib/dhcp/dhclient6.leases', skip_error_check=True)
    #st.config(dut,'killall dhclient',skip_error_check=True)
    #st.config(dut,'rm /var/lib/dhcp/dhclient.leases',skip_error_check=True)
    #st.config(dut, 'rm /var/lib/dhcp/dhclient6.leases',skip_error_check=True)


def dhcp_server_config():
    '''
    1. Install dhcp package
    2. Update dhcp files - dhcpd6.conf  dhcpd.conf  isc-dhcp-server
    3. create vlan, member and configure IPv4 and IPv6.
    4. Add static routes
    5.Restart dhcp process
    '''
    hdrMsg("Installing and configuring the dhcp server on dut1")
    dut = data.dut1
    vlan = '50'
    vlan_int = 'Vlan50'
    vlan_api.create_vlan(dut, [vlan])
    vlan_api.add_vlan_member(dut, vlan, data.d1d3_ports[1])
    ip_api.config_ip_addr_interface(dut,'Vlan50', data.dhcp_server_ip,mask_24)
    ip_api.config_ip_addr_interface(dut, 'Vlan50', data.dhcp_server_ipv6, mask_v6,family='ipv6')
    for ip,ip6 in zip(route_list,route_list_6):
        ip_api.create_static_route(dut, next_hop= data.dut3_server_ip_list[0],static_ip=ip)
        ip_api.create_static_route(dut, next_hop= data.dut3_server_ipv6_list[0],static_ip=ip6,family='ipv6')

    copy_files_to_dut(st.get_mgmt_ip(dut))
#    st.config(dut,'sudo mv /tmp/'+data.dhcp_files[0]+' /etc/default/',skip_error_check=True)
#    st.config(dut,'sudo mv /tmp/'+data.dhcp_files[1]+' /etc/dhcp/',skip_error_check=True)
#   st.config(dut,'sudo mv /tmp/'+data.dhcp_files[2]+' /etc/dhcp/',skip_error_check=True)
    basic_api.move_file_to_local_path(dut, '/tmp/'+data.dhcp_files[0], '/etc/default/', sudo=True, skip_error_check=True)
    basic_api.move_file_to_local_path(dut, '/tmp/'+data.dhcp_files[1], '/etc/dhcp/', sudo=True, skip_error_check=True)
    basic_api.move_file_to_local_path(dut, '/tmp/'+data.dhcp_files[2], '/etc/dhcp/', sudo=True, skip_error_check=True)

    basic_api.deploy_package(dut, mode='update')
    basic_api.deploy_package(dut, options='-o Dpkg::Options::=\"--force-confold\"', packane_name='isc-dhcp-server', mode='install',skip_verify_package=True)

    #st.config(dut, "systemctl restart isc-dhcp-server")
    st.wait(2)
    ps_aux = basic_api.get_ps_aux(data.dut1, "dhcpd")
    if len(ps_aux) > 1:
        hdrMsg("dhcp server is up and running in dut1")
        return True
#    st.config(dut, "systemctl restart isc-dhcp-server")
    basic_api.service_operations_by_systemctl(dut, operation='restart', service='isc-dhcp-server')
    st.wait(2)
    ps_aux = basic_api.get_ps_aux(data.dut1, "dhcpd")
    if len(ps_aux) < 1:
        hdrMsg("dhcp server is not up and running in dut1")        
        return False
    return True
    
def dhcp_server_unconfig():
    hdrMsg("Stoping the dhcp server on dut1")
    dut = data.dut1
    vlan = '50'
    vlan_int = 'Vlan50'
#    st.config(dut, "systemctl stop isc-dhcp-server")
    basic_api.service_operations_by_systemctl(dut, operation='stop', service='isc-dhcp-server')
    for ip,ip6 in zip(route_list,route_list_6):
        ip_api.delete_static_route(dut, next_hop= data.dut3_server_ip_list[0],static_ip=ip)
        ip_api.delete_static_route(dut, next_hop= data.dut3_server_ipv6_list[0],static_ip=ip6,family='ipv6')
    ip_api.delete_ip_interface(dut,'Vlan50', data.dhcp_server_ip,mask_24)
    ip_api.delete_ip_interface(dut, 'Vlan50', data.dhcp_server_ipv6, mask_v6,family='ipv6')
    vlan_api.delete_vlan_member(dut, vlan, data.d1d3_ports[1])
    vlan_api.delete_vlan(dut, [vlan])
    
def copy_files_to_dut(dut_ip,username='admin',password='broadcom'):
    ssh = SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(dut_ip, username=username, password=st.get_credentials(data.dut1)[3])
    ssh.exec_command('sudo -i')
    scp = SCPClient(ssh.get_transport())
    for dhcp_conf_file in data.dhcp_files_path:
        scp.put(dhcp_conf_file,"/tmp")
    scp.close()



##############Scale Test Case lib

def config_client_intf():

    qtr_client_intf = data.vlan_intf_count / 4
    #assign IP address and enable dhcp relay
    oct4 = data.oct4
    oct3 = data.oct3
    v4_addr = '{}.{}.{}'.format(data.vlan_intf_nw, oct3, oct4)
    v4_subnet = data.vlan_intf_ip_pl
    num_of_hosts = 2 ** (32-v4_subnet)
    num_of_subnets = 2 ** (v4_subnet - 24)
    max_oct3 = (256 / num_of_subnets) * (num_of_subnets - 1) + 1

    v6_var_part = 1000
    v6_addr = '{}{}::1'.format(data.vlan_intf_nw6, v6_var_part)
    v6_subnet = data.vlan_intf_ip_pl6
#    vrf_name = data.vrf_name
#    vrf_blue = data.vrf_blue
#    src_intf_same_vni = 'Loopback3'
    data.dhcp_server_info = list()

    for i in range(0,4):
       data.dhcp_server_info.append(dict())
    for i in range(0,4):
        data.dhcp_server_info[i]['server_ip'] = '{}.{}'.format(data.server_nw, i+100)
        data.dhcp_server_info[i]['server_ip6'] = '{}::{}'.format(data.server_nw6, i+100)

    vlan_range = str(data.start_vlan) + ' ' + str(data.end_vlan)
    vlan_api.config_vlan_range(data.dut2, vlan_range=vlan_range)
    vlan_api.config_vlan_range_members(data.dut2, vlan_range=vlan_range, port=data.d2_tg_1)

    st.log('Configure IP address on interface connected to TGEN Server')
    vrf_api.bind_vrf_interface(data.dut3,vrf_name=vrf_name, intf_name=data.d3_tg_1,skip_error='True')
    ip_api.config_ip_addr_interface(data.dut3, interface_name=data.d3_tg_1, ip_address=data.d3_tg_1_ip, subnet='24')
    ip_api.config_ip_addr_interface(data.dut3, interface_name=data.d3_tg_1, ip_address=data.d3_tg_1_ip6, subnet='64', family='ipv6')


    for vlan_id in range(data.start_vlan, data.end_vlan+1):
        vlan_intf = 'Vlan' + str(vlan_id)

        if vlan_id < data.start_vlan + qtr_client_intf:
            vrf_api.bind_vrf_interface(data.dut2,vrf_name=vrf_name, intf_name=vlan_intf, skip_error='True')
            if not 'pool_ip_start' in data.dhcp_server_info[0]:
                data.dhcp_server_info[0]['server_mac'] = '00:00:00:00:ab:00'
                data.dhcp_server_info[0]['pool_ip_start'] = '{}.{}.{}'.format(data.vlan_intf_nw, oct3,2)
                data.dhcp_server_info[0]['addr_strategy'] = 'gateway'
                data.dhcp_server_info[0]['pool_count'] = qtr_client_intf
            extra_option = {}
            extra_option6 = {}
        elif vlan_id < data.start_vlan + 2*qtr_client_intf:
            vrf_api.bind_vrf_interface(data.dut2,vrf_name=vrf_name, intf_name=vlan_intf, skip_error='True')
            if not 'pool_ip_start' in data.dhcp_server_info[1]:
                data.dhcp_server_info[1]['server_mac'] = '00:00:00:00:ab:01'
                data.dhcp_server_info[1]['pool_ip_start'] = '{}.{}.{}'.format(data.vlan_intf_nw, oct3,2)
                data.dhcp_server_info[1]['pool_count'] = qtr_client_intf
                data.dhcp_server_info[1]['addr_strategy'] = 'gateway'
            extra_option = {'src_interface': src_intf_same_vni}
            extra_option6 = {'src_interface': src_intf_same_vni}
        elif vlan_id < data.start_vlan + 3*qtr_client_intf:
            if vlan_id < (data.start_vlan + 3*qtr_client_intf) - qtr_client_intf/2:
                vrf_api.bind_vrf_interface(data.dut2,vrf_name=vrf_name, intf_name=vlan_intf, skip_error='True')
            else:
                vrf_api.bind_vrf_interface(data.dut2,vrf_name=vrf_blue, intf_name=vlan_intf, skip_error='True')
            if not 'pool_ip_start' in data.dhcp_server_info[2]:
                data.dhcp_server_info[2]['server_mac'] = '00:00:00:00:ab:02'
                data.dhcp_server_info[2]['pool_ip_start'] = '{}.{}.{}'.format(data.vlan_intf_nw, oct3,2)
                data.dhcp_server_info[2]['pool_count'] = qtr_client_intf
                data.dhcp_server_info[2]['addr_strategy'] = 'link_selection'
            extra_option = {'src_interface': src_intf_same_vni, 'link_select': 'yes'}
            extra_option6 = {}
        elif vlan_id < data.start_vlan + 4*qtr_client_intf:
            if vlan_id < (data.start_vlan + 4*qtr_client_intf) - qtr_client_intf/2:
                vrf_api.bind_vrf_interface(data.dut2,vrf_name=vrf_name, intf_name=vlan_intf, skip_error='True')
                extra_option = {'vrf_select': ''}
                extra_option6 = {}
                if not 'pool_ip_start' in data.dhcp_server_info[3]:
                    data.dhcp_server_info[3]['server_mac'] = '00:00:00:00:ab:03'
                    data.dhcp_server_info[3]['pool_ip_start'] = '{}.{}.{}'.format(data.vlan_intf_nw, oct3,2)
                    data.dhcp_server_info[3]['pool_count'] = qtr_client_intf/2
                    data.dhcp_server_info[3]['addr_strategy'] = 'vpn_id'
                    data.dhcp_server_info[3]['vpn_id'] = vrf_name
            else:
                vrf_api.bind_vrf_interface(data.dut2,vrf_name=vrf_blue, intf_name=vlan_intf, skip_error='True')
                extra_option = {'src_interface': src_intf_same_vni, 'link_select': 'yes', 'vrf_select': ''}
                extra_option6 = {}
                if not 'pool_ip_start_1' in data.dhcp_server_info[3]:
                    data.dhcp_server_info[3]['pool_ip_start_1'] = '{}.{}.{}'.format(data.vlan_intf_nw, oct3,2)
                    data.dhcp_server_info[3]['vpn_id_1'] = vrf_blue

        ip_api.config_ip_addr_interface(data.dut2, interface_name=vlan_intf, ip_address=v4_addr, subnet=v4_subnet)
        ip_api.config_ip_addr_interface(data.dut2, interface_name=vlan_intf, ip_address=v6_addr, subnet=v6_subnet, family='ipv6')

        dhcp_relay.dhcp_relay_config(data.dut2, interface=vlan_intf, IP=[data.dhcp_server_info[0]['server_ip'],data.dhcp_server_info[1]['server_ip'],data.dhcp_server_info[2]['server_ip'],data.dhcp_server_info[3]['server_ip']], action='add', vrf_name=vrf_name, **extra_option)
        dhcp_relay.dhcp_relay_config(data.dut2, interface=vlan_intf, IP=[data.dhcp_server_info[0]['server_ip6'],data.dhcp_server_info[1]['server_ip6'],data.dhcp_server_info[2]['server_ip6'],data.dhcp_server_info[3]['server_ip6']], action='add', vrf_name=vrf_name, family='ipv6', **extra_option6)

        oct4 += num_of_hosts
        if oct4 > max_oct3:
            oct3 += 1
            oct4 = 1
        v4_addr = '{}.{}.{}'.format(data.vlan_intf_nw, oct3, oct4)

        v6_var_part += 1
        v6_addr = '{}{}::1'.format(data.vlan_intf_nw6, v6_var_part)



def reset_dhcp_server():
    server_port = data.tg_d3_1
    server_port_handle = data.tg_d3_1_ph
    for i in range(0,4):
        server_port.tg_emulation_dhcp_server_config(mode='reset',handle=data.dhcp_server_config[i]['dhcp_handle'])



def config_dhcp_server(address_strategy='gateway'):
    ip_version = '4'
    gateway_ip = data.d3_tg_1_ip
    gateway_mac = str(data.d3_tg_1_mac)
    server_pool = '{}.{}'.format(data.server_nw,'150')
    relay_pool_step = '0.0.0.{}'.format(2 ** (32-data.vlan_intf_ip_pl))
    relay_pool_plen = data.vlan_intf_ip_pl
    server_port = data.tg_d3_1
    server_port_handle = data.tg_d3_1_ph

    #server_port.tg_emulation_dhcp_server_config(mode='reset',handle=dhcp_server_config['dhcp_handle'])
    data.dhcp_server_config = list()
    data.dhcp_relay_config = list()
    for i in range(0,4):
        server_ip = data.dhcp_server_info[i]['server_ip']
        server_mac = data.dhcp_server_info[i]['server_mac']
        address_strategy = data.dhcp_server_info[i]['addr_strategy']
        relay_pool_count = data.dhcp_server_info[i]['pool_count']
        relay_pool_address = data.dhcp_server_info[i]['pool_ip_start']

        dsc = server_port.tg_emulation_dhcp_server_config(port_handle=server_port_handle, mode='create', ip_version=ip_version, encapsulation='ETHERNET_II', count=1, local_mac=server_mac, ip_address=server_ip, ip_gateway=gateway_ip, remote_mac=gateway_mac, ipaddress_count='5', ipaddress_pool=server_pool,assign_strategy=address_strategy)
        if address_strategy == 'vpn_id':
            relay_pool_address_1 = data.dhcp_server_info[i]['pool_ip_start_1']
            drc = server_port.tg_emulation_dhcp_server_relay_agent_config(mode='create', handle=dsc['dhcp_handle'], relay_agent_pool_count=relay_pool_count, relay_agent_ipaddress_pool=relay_pool_address, prefix_length=relay_pool_plen, relay_agent_pool_step=relay_pool_step, vpn_id_type='nvt_ascii', vpn_id=vrf_name)
            drc_1 = server_port.tg_emulation_dhcp_server_relay_agent_config(mode='create', handle=dsc['dhcp_handle'], relay_agent_pool_count=relay_pool_count, relay_agent_ipaddress_pool=relay_pool_address_1, prefix_length=relay_pool_plen, relay_agent_pool_step=relay_pool_step, vpn_id_type='nvt_ascii', vpn_id=vrf_blue)
            data.dhcp_relay_config.append(drc)
            data.dhcp_relay_config.append(drc_1)
        else:
            drc = server_port.tg_emulation_dhcp_server_relay_agent_config(mode='create', handle=dsc['dhcp_handle'], relay_agent_pool_count=relay_pool_count, relay_agent_ipaddress_pool=relay_pool_address, prefix_length=relay_pool_plen, relay_agent_pool_step=relay_pool_step)
            data.dhcp_relay_config.append(drc)

        data.dhcp_server_config.append(dsc)
        server_port.tg_emulation_dhcp_server_control(action='connect', dhcp_handle=dsc['dhcp_handle'])
#       server_port.tg_save_xml(filename='/home/cs403178/dhcp.xml')



def reset_dhcp_client():
    client_port = data.tg_d2_1
    client_port_handle = data.tg_d2_1_ph
    client_port.tg_emulation_dhcp_config(mode='reset', port_handle=client_port_handle, handle=data.dhcp_client_config['handles'])

def config_dhcp_client():
    client_port = data.tg_d2_1
    client_port_handle = data.tg_d2_1_ph
    v4_subnet = data.vlan_intf_ip_pl
    num_of_sessions =  data.clients_per_intf

    data.dhcp_client_config = client_port.tg_emulation_dhcp_config(mode='create', port_handle=client_port_handle, retry_count=3)
    st.log(data.dhcp_client_config)
    for vlan_id in range(data.start_vlan, data.end_vlan+1):
        data.dhcp_group_config = client_port.tg_emulation_dhcp_group_config(handle=data.dhcp_client_config['handles'], mode='create', encap='ethernet_ii_vlan', vlan_id_count = '1', num_sessions=num_of_sessions, mac_addr='00:10:94:00:00:01', vlan_id = vlan_id, dhcp_range_ip_type=4, gateway_addresses=0, enable_auto_retry='true', retry_attempts=3)

    st.log(data.dhcp_group_config)


def start_dhcp_client(ip_version=4, action='bind'):
    client_port = data.tg_d2_1
    client_port_handle = data.tg_d2_1_ph
    client_port.tg_emulation_dhcp_control(port_handle=client_port_handle, action=action, ip_version=ip_version)


def verify_dhcp_client_stats(ip_version=4, stats_type=None, total_bound=0, total_renew=0):
    client_port = data.tg_d2_1
    client_port_handle = data.tg_d2_1_ph
    dhcp_stats = client_port.tg_emulation_dhcp_stats(port_handle=client_port_handle, ip_version=ip_version, mode='aggregate')
    st.log('currently_bound: {}, bound_renewed: {}'.format(int(dhcp_stats['aggregate']['currently_bound']), int(dhcp_stats['aggregate']['bound_renewed'])))
    if stats_type == 'bind':
        ret_value = True if int(dhcp_stats['aggregate']['currently_bound']) == total_bound else False
    if stats_type == 'renew':
        ret_value = True if int(dhcp_stats['aggregate']['currently_bound']) == total_bound and int(dhcp_stats['aggregate']['bound_renewed']) >= total_renew else False

    if not ret_value:
        st.log(dhcp_stats)
        return False
    return True

def dump_dhcp_client_stats():
    client_port = data.tg_d2_1
    client_port_handle = data.tg_d2_1_ph
    dhcp_stats = client_port.tg_emulation_dhcp_stats(port_handle=client_port_handle, ip_version=4, mode='detailed_session')
    st.log(dhcp_stats)
    for client_intf in dhcp_stats[client_port_handle]['group'].keys():
        for session in dhcp_stats[client_port_handle]['group'][client_intf].keys():
            if isinstance(dhcp_stats[client_port_handle]['group'][client_intf][session], dict):
                if 'ipv4_addr' in dhcp_stats[client_port_handle]['group'][client_intf][session] and 'vlan_id' in dhcp_stats[client_port_handle]['group'][client_intf][session] and dhcp_stats[client_port_handle]['group'][client_intf][session]['ipv4_addr'] == '0.0.0.0':
                    st.log('Vlan: {}, IP Addr: {}'.format(dhcp_stats[client_port_handle]['group'][client_intf][session]['vlan_id'], dhcp_stats[client_port_handle]['group'][client_intf][session]['ipv4_addr']))
    return dhcp_stats



