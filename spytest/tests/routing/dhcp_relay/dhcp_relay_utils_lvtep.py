from dhcp_relay_vars_lvtep import *
from dhcp_relay_vars_lvtep import data
from spytest import st,utils
import apis.switching.portchannel as pc
import apis.switching.vlan as vlan_api
import apis.routing.ip as ip_api
import apis.routing.evpn as evpn
from utilities import parallel
import apis.routing.bgp as bgp_api
import apis.routing.ip_bgp as ip_bgp
from spytest.tgen.tgen_utils import *
import apis.routing.vrf as vrf_api
import apis.routing.dhcp_relay as dhcp_relay
import apis.system.basic as basic_api
import apis.system.interface as interface_api
import utilities.utils as utils_obj
import apis.system.connection as con_obj
import apis.switching.mclag as mclag
from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient
import apis.qos.copp as copp_api

def dhcp_relay_base_config():
    ###################################################
    hdrMsg("########## BASE Config Starts ########")
    ###################################################
    config_ip()
    config_bgp()
    result = verify_bgp()
    if not result:
        #config_bgp(config='no')
        #config_ip(config='no')
        return False
    config_leafInterface()
    config_vxLan()
    lvtep_configs()
    result = verify_vxlan()
    if not result:
        #lvtep_configs(config='no')
        #config_vxLan(config='no')
        #config_leafInterface(config='no')
        #config_bgp(config='no')
        #config_ip(config='no')
        return False
    # Install and Configure DHCP server
    result5 = dhcp_server_config()

    result1 = pc.verify_portchannel_member_state(data.dut4, data.client_lag, [data.d4d2_ports[0],data.d4d5_ports[1]])
    result2 = pc.verify_portchannel_member_state(data.dut2, data.iccp_lag, [data.d2d5_ports[0]])
    result3 = pc.verify_portchannel_member_state(data.dut4, data.client_lag_l3, [data.d4d2_ports[2],data.d4d5_ports[2]])

    result4 = check_ping_dhcpserver(data.dut2)
    if False in [result1,result2,result3,result4,result5]:
        debug_vxlan_dhcp_relay()
#        lvtep_configs(config='no')
#        config_vxLan(config='no')
#        config_leafInterface(config='no')
#        config_bgp(config='no')
#        config_ip(config='no')
        return False
    [res, exceptions] = utils.exec_all(True, [[config_dhcpRelay], [config_dhcpRelay_lvtep]])
    ###################################################
    hdrMsg("########## BASE Config End ########")
    ###################################################
    return True

def dhcp_relay_base_deconfig():
    ###################################################
    hdrMsg("########## BASE De-Config Starts ########")
    ###################################################
    config_dhcpRelay_lvtep(action='remove')
    config_dhcpRelay(action='remove')
    lvtep_configs(config='no')
    config_vxLan(config='no')
    config_bgp(config='no')
    config_leafInterface(config='no')
    config_ip(config='no')
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

        dict1 = {'next_hop': dut3_1_ip_list[0], 'static_ip': dut3_loopback_ip_list[0] + '/32'}
        dict2 = {'next_hop': dut1_2_ip_list[0], 'static_ip': dut1_loopback_ip_list[0] + '/32'}
        dict3 = {'next_hop': dut1_3_ip_list[0], 'static_ip': dut1_loopback_ip_list[0] + '/32'}

        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], ip_api.create_static_route, [dict1, dict2, dict3])

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

        dict1 = {'next_hop' : dut3_1_ip_list[0],'static_ip' : dut3_loopback_ip_list[0]+'/32'}
        dict2 = {'next_hop' : dut1_2_ip_list[0],'static_ip' : dut1_loopback_ip_list[0]+'/32'}
        dict3 = {'next_hop' : dut3_1_ip_list[0],'static_ip' : dut1_loopback_ip_list[0]+'/32'}

        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], ip_api.delete_static_route, [dict1, dict2, dict3])


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

        def f1():
            evpn.config_bgp_evpn(dut=data.dut1,neighbor =dut2_loopback_ip_list[0],config='yes',config_type_list =["activate"],local_as=dut1_AS,remote_as =dut2_AS)
            evpn.config_bgp_evpn(dut=data.dut1,neighbor =dut3_loopback_ip_list[0],config='yes',config_type_list =["activate"],local_as=dut1_AS,remote_as =dut3_AS)
            evpn.config_bgp_evpn(dut=data.dut1,config = 'yes',config_type_list=["advertise_all_vni"],local_as=dut1_AS)
        def f2():
            evpn.config_bgp_evpn(dut=data.dut2,neighbor =dut1_loopback_ip_list[0],config='yes',config_type_list =["activate"],local_as=dut2_AS,remote_as=dut1_AS)
            evpn.config_bgp_evpn(dut=data.dut2, config='yes', config_type_list=["advertise_all_vni"], local_as=dut2_AS)
        def f3():
            evpn.config_bgp_evpn(dut=data.dut3,neighbor =dut1_loopback_ip_list[0],config='yes',config_type_list =["activate"],local_as=dut3_AS,remote_as=dut1_AS)
            evpn.config_bgp_evpn(dut=data.dut3,config = 'yes',config_type_list=["advertise_all_vni"],local_as=dut3_AS)
        [res, exceptions] = utils.exec_all(True, [[f1], [f2], [f3]])

    else:
        ##########################################################################
        hdrMsg("BGP-Deconfig: Delete BGP routers globally from all DUTs")
        ##########################################################################
        dict1 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no'}
        parallel.exec_parallel(True, [data.dut1,data.dut2,data.dut3], bgp_api.config_bgp, [dict1, dict1,dict1])


def config_leafInterface(config='yes'):
    if config == 'yes':
        def f1():
            vlan_api.create_vlan(data.dut2, ['500'])
            vlan_api.create_vlan(data.dut2, ['100'])
            pc.create_portchannel(data.dut2, [data.client_lag])
            pc.add_del_portchannel_member(data.dut2, data.client_lag, data.d2d4_ports[0], 'add')
            vlan_api.add_vlan_member(data.dut2,'100',data.client_lag)

        def f2():
            vlan_api.create_vlan(data.dut4, ['100'])
            vlan_api.create_vlan(data.dut3, ['500'])
            pc.create_portchannel(data.dut4, [data.client_lag])
            pc.add_del_portchannel_member(data.dut4, data.client_lag, data.d4d2_ports[0], 'add')
            vlan_api.add_vlan_member(data.dut4, '100', data.client_lag)

        ##################################################################
        hdrMsg("Step01: VRF-Config- Configure VRF on dut2 and dut3 ")
        ##################################################################
        dict1 = {'vrf_name':vrf_name, 'config': 'yes'}
        parallel.exec_parallel(True, [data.dut2, data.dut3], vrf_api.config_vrf, [dict1, dict1])

        st.log("config vlan,portchannels")
        [res, exceptions] = utils.exec_all(True, [[f1], [f2]])

        #########################################################ata.########
        hdrMsg("Step02: bind-VRF-to-interface- on dut2 and dut3 devices")
        #################################################################
        def f3():
            vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_name, intf_name ='Vlan500',skip_error='True')
            ip_api.config_ip_addr_interface(data.dut2,'Vlan500', '22.22.1.1',mask_24)
            ip_api.config_ip_addr_interface(data.dut2, 'Vlan500', '1212::1', mask_v6,family='ipv6')

        def f4():
            vrf_api.bind_vrf_interface(data.dut3,vrf_name =vrf_name, intf_name ='Vlan500',skip_error='True')
            ip_api.config_ip_addr_interface(data.dut3,'Vlan500', '33.33.1.1',mask_24)
            ip_api.config_ip_addr_interface(data.dut3, 'Vlan500', '1313::1', mask_v6,family='ipv6')

        [res, exceptions] = utils.exec_all(True, [[f3], [f4]])

        vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_name, intf_name =data.d2d4_ports[1],skip_error='True')
        vrf_api.bind_vrf_interface(data.dut3,vrf_name =vrf_name, intf_name =data.dhcp_server_port,skip_error='True')
        vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name='Loopback3', skip_error='True')

        vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name='Vlan100', skip_error='True')
        ip_api.config_ip_addr_interface(data.dut2, 'Vlan100', dut2_4_ip_list[0], mask_24)
        ip_api.config_ip_addr_interface(data.dut2, 'Vlan100', dut2_4_ipv6_list[0], mask_v6, family="ipv6")

        ip_api.config_ip_addr_interface(data.dut2, "Loopback3", dut2_loopback_ip, '32')
        ip_api.config_ip_addr_interface(data.dut2, "Loopback3", dut2_loopback_ip6, '128',family="ipv6")

        ip_api.config_ip_addr_interface(data.dut2,data.d2d4_ports[1], dut2_4_ip_list[1],mask_24)
        ip_api.config_ip_addr_interface(data.dut2,data.d2d4_ports[1], dut2_4_ipv6_list[1],mask_v6,family="ipv6")

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
        ip_api.delete_ip_interface(data.dut3,'Vlan500', '33.33.1.1',mask_24)
        ip_api.delete_ip_interface(data.dut3, 'Vlan500', '1313::1', mask_v6,family='ipv6')
        ip_api.delete_ip_interface(data.dut3,data.dhcp_server_port,data.dut3_server_ip_list[0],mask_24)
        ip_api.delete_ip_interface(data.dut3,data.dhcp_server_port,data.dut3_server_ipv6_list[0],mask_v6,family="ipv6")
        ip_api.delete_ip_interface(data.dut2, "Loopback3", dut2_loopback_ip, '32')
        ip_api.delete_ip_interface(data.dut2, "Loopback3", dut2_loopback_ip6, '128',family="ipv6")

        #########################################################ata.########
        hdrMsg("Step02: unbind-VRF-to-interface- on dut2 and dut3 devices")
        #################################################################
        vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_name, intf_name ='Vlan500',config = 'no',skip_error='True')
        vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_name, intf_name ='Vlan100',config = 'no',skip_error='True')
        vrf_api.bind_vrf_interface(data.dut2,vrf_name =vrf_name, intf_name =data.d2d4_ports[1],config = 'no',skip_error='True')
        vrf_api.bind_vrf_interface(data.dut3,vrf_name =vrf_name, intf_name ='Vlan500',config = 'no',skip_error='True')
        vrf_api.bind_vrf_interface(data.dut3,vrf_name =vrf_name, intf_name =data.dhcp_server_port,config = 'no',skip_error='True')
        vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name='Loopback3',config = 'no', skip_error='True')

        vlan_api.delete_vlan_member(data.dut2,'100',data.client_lag)
        vlan_api.delete_vlan_member(data.dut4,'100',data.client_lag)
        st.log("LAG-unConfig: delete member ports to portchannel")
        pc.add_del_portchannel_member(data.dut2, data.client_lag,data.d2d4_ports[0],'del')
        pc.add_del_portchannel_member(data.dut4, data.client_lag,data.d4d2_ports[0],'del')

        ##################################################################
        hdrMsg("Step01: VRF-Config- Configure VRF on dut2 and dut3 ")
        ##################################################################

        st.log("Unconfig vlan for vteps")
        vlan_api.delete_vlan(data.dut2, ['500'])
        vlan_api.delete_vlan(data.dut2, ['100'])
        vlan_api.delete_vlan(data.dut4, ['100'])
        vlan_api.delete_vlan(data.dut3, ['500'])
        st.log("LAG-UnConfig: Delete portchannel on dut2")
        pc.delete_portchannel(data.dut2, [data.client_lag])
        pc.delete_portchannel(data.dut4, [data.client_lag])
        dict1 = {'vrf_name':vrf_name, 'config': 'no'}
        parallel.exec_parallel(True, [data.dut2, data.dut3], vrf_api.config_vrf, [dict1, dict1])


def config_vxLan(config='yes'):
    if config == 'yes':
        ##################################################################
        hdrMsg("Step01: config vtep on all leaf nodes ")
        ##################################################################
        def f1():
            evpn.create_overlay_intf(data.dut2, "vtepLeaf1",dut2_loopback_ip_list[1] )
            evpn.create_evpn_instance(data.dut2, "nvoLeaf1", "vtepLeaf1" )
            evpn.map_vlan_vni(data.dut2, "vtepLeaf1", "500", "500")
            evpn.map_vrf_vni(data.dut2, vrf_name, vtep_name='vtepLeaf1',vni='500')
        def f2():
            evpn.create_overlay_intf(data.dut3, "vtepLeaf2",dut3_loopback_ip_list[1] )
            evpn.create_evpn_instance(data.dut3, "nvoLeaf1", "vtepLeaf2")
            evpn.map_vlan_vni(data.dut3, "vtepLeaf2", "500", "500")
            evpn.map_vrf_vni(data.dut3, vrf_name, vtep_name='vtepLeaf2',vni='500')

        def f3():
            bgp_api.config_bgp(data.dut2,local_as=dut2_AS,vrf_name=vrf_name,config = 'yes',config_type_list =["redist"], redistribute ='connected')
            bgp_api.config_bgp(data.dut2,local_as=dut2_AS,vrf_name=vrf_name,config = 'yes',config_type_list =["redist"], redistribute ='connected',addr_family ='ipv6')
            bgp_api.config_bgp(data.dut2,local_as=dut2_AS,config = 'yes',config_type_list =["redist"], redistribute ='connected')
            evpn.config_bgp_evpn(data.dut2,vrf_name=vrf_name,config ='yes',config_type_list=["advertise_ipv4_vrf"],local_as=dut2_AS,advertise_ipv4='unicast')
            evpn.config_bgp_evpn(data.dut2,vrf_name=vrf_name,config ='yes',config_type_list=["advertise_ipv6_vrf"],local_as=dut2_AS,advertise_ipv6='unicast')

        def f4():
            bgp_api.config_bgp(data.dut3,local_as=dut3_AS,vrf_name=vrf_name,config = 'yes',config_type_list =["redist"], redistribute ='connected')
            bgp_api.config_bgp(data.dut3,local_as=dut3_AS,vrf_name=vrf_name,config = 'yes',config_type_list =["redist"], redistribute ='connected',addr_family ='ipv6')
            bgp_api.config_bgp(data.dut3,local_as=dut3_AS,config = 'yes',config_type_list =["redist"], redistribute ='connected')
            evpn.config_bgp_evpn(data.dut3,vrf_name=vrf_name,config ='yes',config_type_list=["advertise_ipv4_vrf"],local_as=dut3_AS,advertise_ipv4='unicast')
            evpn.config_bgp_evpn(data.dut3,vrf_name=vrf_name,config ='yes',config_type_list=["advertise_ipv6_vrf"],local_as=dut3_AS,advertise_ipv6='unicast')

        [res, exceptions] = utils.exec_all(True, [[f1], [f2]])

        ##########################################################################
        hdrMsg("BGP-config: Configure bgp on DUT2 for Vtep ")
        ##########################################################################
        [res, exceptions] = utils.exec_all(True, [[f3], [f4]])

    else:
        ##################################################################
        hdrMsg("Step01: Unconfig vtep on all leaf nodes ")
        ##################################################################
        def f1():
            evpn.map_vrf_vni(data.dut2, vrf_name, vtep_name='vtepLeaf1',vni='500',config='no')
            evpn.map_vlan_vni(data.dut2, "vtepLeaf1", "500", "500",config='no')
            evpn.create_evpn_instance(data.dut2, "nvoLeaf1", "vtepLeaf1", config='no')
            evpn.create_overlay_intf(data.dut2, "vtepLeaf1", dut2_loopback_ip_list[1], config='no')
        def f2():
            evpn.map_vrf_vni(data.dut3, vrf_name,vtep_name='vtepLeaf2',vni='500',config='no')
            evpn.map_vlan_vni(data.dut3, "vtepLeaf2", "500", "500",config='no')
            evpn.create_evpn_instance(data.dut3, "nvoLeaf1", "vtepLeaf2", config='no')
            evpn.create_overlay_intf(data.dut3, "vtepLeaf2",dut3_loopback_ip_list[1] ,config='no')

        [res, exceptions] = utils.exec_all(True, [[f1], [f2]])

        dict1 = {'local_as':dut2_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':vrf_name}
        dict2 = {'local_as':dut3_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':vrf_name}
        dict3 = {'local_as':dut5_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':vrf_name}

        parallel.exec_parallel(True, [data.dut2,data.dut3,data.dut5], bgp_api.config_bgp, [dict1,dict2,dict3])

        dict1 = {'local_as': dut2_AS, 'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no'}
        dict2 = {'local_as': dut3_AS, 'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no'}
        dict3 = {'local_as': dut5_AS, 'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no'}

        parallel.exec_parallel(True, [data.dut2, data.dut3, data.dut5], bgp_api.config_bgp, [dict1, dict2,dict3])

def config_dhcpRelay(action='add'):
    st.log('Configure/unconfigure dhcp relay on leaf1')

    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=data.dhcp_server_ip,vlan='Vlan100',action=action,skip_error_check=True,vrf_name=vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.d2d4_ports[1], IP=data.dhcp_server_ip,action=action,skip_error_check=True,vrf_name=vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan200', IP=data.dhcp_server_ip,action=action,skip_error_check=True,vrf_name=vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan100', IP=data.dhcp_server_ipv6,vlan='Vlan100',action=action,family='ipv6',skip_error_check=True,vrf_name=vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface=data.d2d4_ports[1], IP=data.dhcp_server_ipv6,action=action,family='ipv6',skip_error_check=True,vrf_name=vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut2, interface='Vlan200', IP=data.dhcp_server_ipv6,action=action,family='ipv6',skip_error_check=True,vrf_name=vrf_name)
    if action == 'add' :
        for intf in data.relay_port:
            dhcp_relay.dhcp_relay_option_config(data.dut2,src_interface='Loopback3',interface=intf ,option='src-intf',action=action,family='ipv6',skip_error_check=True)
            dhcp_relay.dhcp_relay_option_config(data.dut2,src_interface='Loopback3',interface=intf ,option='src-intf',action=action,skip_error_check=True)
        dhcp_relay.dhcp_relay_option_config(data.dut2, interface=data.client_lag_l3, option='link-select')


def config_dhcpRelay_lvtep(action='add'):
    st.log('Configure/unconfigure dhcp relay on leaf2')
    dhcp_relay.dhcp_relay_config(data.dut5, interface='Vlan100', IP=data.dhcp_server_ip,vlan='Vlan100',action=action,skip_error_check=True,vrf_name=vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut5, interface='Vlan200', IP=data.dhcp_server_ip,action=action,skip_error_check=True,vrf_name=vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut5, interface='Vlan100', IP=data.dhcp_server_ipv6,vlan='Vlan100',action=action,family='ipv6',skip_error_check=True,vrf_name=vrf_name)
    dhcp_relay.dhcp_relay_config(data.dut5, interface='Vlan200', IP=data.dhcp_server_ipv6,action=action,family='ipv6',skip_error_check=True,vrf_name=vrf_name)
    if action == 'add' :
        for intf in data.relay_port:
            if intf == data.relay_port[1]: continue
            dhcp_relay.dhcp_relay_option_config(data.dut5,src_interface='Loopback3',interface=intf,option='src-intf',action=action,family='ipv6',skip_error_check=True)
            dhcp_relay.dhcp_relay_option_config(data.dut5,src_interface='Loopback3',interface=intf,option='src-intf',action=action,skip_error_check=True)
        dhcp_relay.dhcp_relay_option_config(data.dut5, interface=data.client_lag_l3, option='link-select')


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

        st.error("one or more BGP sessions did not come up between dut1 and dut4")
        return False
    return True

def verify_vxlan():
    ###########################################################
    hdrMsg("verify Vxlan: Verify vxlan tunnels are up on dut2 and dut3")
    ############################################################
    result1 = retry_api(evpn.verify_vxlan_tunnel_status, data.dut2, src_vtep=dut2_loopback_ip_list[1], rem_vtep_list=[dut3_loopback_ip_list[1]], exp_status_list=['oper_up'])
    result2 = retry_api(evpn.verify_vxlan_tunnel_status, data.dut5, src_vtep=dut2_loopback_ip_list[1], rem_vtep_list=[dut3_loopback_ip_list[1]], exp_status_list=['oper_up'])

    result3 = retry_api(evpn.verify_vxlan_tunnel_status, data.dut3, src_vtep=dut3_loopback_ip_list[1], rem_vtep_list=[dut2_loopback_ip_list[1]], exp_status_list=['oper_up'])
    if False in [result1,result2,result3]:
        st.error("Vxlan tunnel did not come up between lvtep and dut3")
        return False
    return True

def check_ping_dhcpserver(dut):
    st.log('Verify reachabality to dhcp server from leaf1')
    result =ip_api.ping(dut, data.dhcp_server_ip,interface=vrf_name,source_ip=dut2_loopback_ip)
    if result is False:
        ip_api.traceroute(dut,addresses=data.dhcp_server_ip,vrf_name=vrf_name)
        result = retry_api(ip_api.ping, dut, addresses=data.dhcp_server_ip,interface=vrf_name,source_ip=dut2_loopback_ip)
        if result is False:
            st.error("Dhcp server is not reachable from leaf1 even after retry")
            ip_api.traceroute(dut,addresses=data.dhcp_server_ip,vrf_name=vrf_name)
            return False
    
    result =ip_api.ping(dut, data.dhcp_server_ipv6,interface=vrf_name,family='ipv6',source_ip=dut2_loopback_ip6)
    if result is False:
        ip_api.traceroute(dut,addresses=data.dhcp_server_ipv6,family='ipv6',vrf_name=vrf_name) 
        result = retry_api(ip_api.ping, dut, addresses=data.dhcp_server_ipv6,interface=vrf_name,family='ipv6',source_ip=dut2_loopback_ip6)
        if result is False:
            st.error("Dhcp server is not reachable from leaf1 even after retry")
            ip_api.traceroute(dut,addresses=data.dhcp_server_ipv6,family='ipv6',vrf_name=vrf_name)
            return False
    return True
    
def print_topology():
    ######################################################
    hdrMsg(" #####  DHCP Relay over VTEP Topology  ######")
    ######################################################
    topology = r"""



                            DUT1[Spine]
                           /       / \
      1-router port       /       /   \       1-router port
                         /       /     \
                        /       /       \
                       /       /         \
                      /       /           \
[DUT4]--------[DUT2_leaf1-DUT5_leaf2] DUT3[leaf3] ---- (DHCP SERVER)
[DHCP Client]


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
            '''
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
            '''
    return True


def check_dhcp_relay_interface_config(dut,interface=None,server_ip=None,family='ipv4'):
    if not dhcp_relay.verify_dhcp_relay(dut,interface, server_ip,family=family):
        st.error("{} IP_Helper_address_config_failed".format(family))
        return False
    return True

def check_dhcp_relay_statistics(dut,interface = "", family = "ipv4",expected='non_zero'):
    hdrMsg("Verify DHCP relay statistics on Leaf")
    ret_val = True
    return True
    #return check_dhcp_relay_statistics_2(dut, interface, family, expected)

def check_dhcp_relay_statistics_2(dut,interface = "", family = "ipv4",expected='non_zero'):
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
        filter = '-i ' + kwargs['intf'] + ' -vvv -nn '
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
        num_of_packets = utils_obj.remove_last_line_from_string(output)
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

def lvtep_configs(config='yes'):

    if config == 'yes':
        utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut1, data.d1d5_ports[0], dut1_5_ip_list[0], mask],
                              [ip_api.config_ip_addr_interface, data.dut5, data.d5d1_ports[0], dut5_1_ip_list[0],
                               mask]])
        utils.exec_all(True, [
            [ip_api.config_ip_addr_interface, data.dut1, data.d1d5_ports[0], dut1_5_ipv6_list[0], mask_v6, 'ipv6'],
            [ip_api.config_ip_addr_interface, data.dut5, data.d5d1_ports[0], dut5_1_ipv6_list[0], mask_v6, 'ipv6']])
        dict1 = {'vrf_name': vrf_name, 'config': 'yes'}
        parallel.exec_parallel(True, [data.dut5], vrf_api.config_vrf, [dict1])
        parallel.exec_parallel(True, [data.dut5], ip_api.configure_loopback, [{'loopback_name': 'Loopback1'}])
        parallel.exec_parallel(True, [data.dut5], ip_api.configure_loopback, [{'loopback_name': 'Loopback2'}])

        utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut5, "Loopback1", dut5_loopback_ip_list[0], '32']])
        utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut5, "Loopback2", dut5_loopback_ip_list[1], '32']])

        ip_api.create_static_route(data.dut1, next_hop=dut5_1_ip_list[0],static_ip='{}/32'.format(dut5_loopback_ip_list[0]))
        ip_api.create_static_route(data.dut5, next_hop=dut1_5_ip_list[0],static_ip='{}/32'.format(dut1_loopback_ip_list[0]))
        # BGP Config

        ##########################################################################
        hdrMsg("BGP-config: Configure  EBGP sessions between dut1 <--> dut5")
        ##########################################################################
        update = 'update_src' if st.get_ui_type(data.dut1) == 'click' else 'update_src_intf'
        dict1 = {'local_as': dut1_AS, 'remote_as': dut5_AS, 'neighbor': dut5_loopback_ip_list[0],
                 'config_type_list': ['neighbor', 'ebgp_mhop', update,'connect'], 'ebgp_mhop': '2',
                 update: 'Loopback1','connect':'3'}
        dict2 = {'local_as': dut5_AS, 'remote_as': dut1_AS, 'neighbor': dut1_loopback_ip_list[0],
                 'config_type_list': ['neighbor', 'ebgp_mhop',update,'connect'], 'ebgp_mhop': '2',
                 update: 'Loopback1','connect':'3'}
        parallel.exec_parallel(True, [data.dut1, data.dut5], bgp_api.config_bgp, [dict1, dict2])
        bgp_api.config_bgp_router(data.dut5,dut5_AS, '', '3', '9', 'yes')
        evpn.config_bgp_evpn(dut=data.dut1,neighbor =dut5_loopback_ip_list[0],config='yes',config_type_list =["activate"],local_as=dut1_AS,remote_as=dut5_AS)
        evpn.config_bgp_evpn(dut=data.dut5, neighbor=dut1_loopback_ip_list[0], config='yes', config_type_list=["activate"],local_as=dut5_AS,remote_as=dut1_AS)
        evpn.config_bgp_evpn(dut=data.dut5, config='yes', config_type_list=["advertise_all_vni"], local_as=dut5_AS)

        # Config Leaf interface

        st.log("Add vlan members")
        # Config Leaf interface
        vlan_api.create_vlan(data.dut5, ['500'])
        vlan_api.create_vlan(data.dut5, ['100'])
        vlan_api.create_vlan(data.dut5, ['200'])
        vlan_api.create_vlan(data.dut4, ['200'])
        vlan_api.create_vlan(data.dut2, ['200'])

        # ============= MC lag================
        pc.create_portchannel(data.dut5, [data.client_lag])

        utils.exec_all(True, [[pc.add_del_portchannel_member, data.dut5, data.client_lag, data.d5d4_ports[1], 'add'],
                              [pc.add_del_portchannel_member, data.dut4, data.client_lag, data.d4d5_ports[1], 'add']])
        vlan_api.add_vlan_member(data.dut5,'100',data.client_lag)

        vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name='Vlan500', skip_error='True')
        vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name='Vlan100', skip_error='True')
        vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name='Vlan200', skip_error='True')
        vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name='Loopback3', skip_error='True')
        vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name='Vlan200', skip_error='True')

        ip_api.config_ip_addr_interface(data.dut5, "Loopback3", '100.100.100.101', '32')

        ip_api.config_ip_addr_interface(data.dut5, "Loopback3", dut5_loopback_ip6, '128', family="ipv6")
        ip_api.config_ip_addr_interface(data.dut5, 'Vlan500', '22.22.1.1', mask_24)
        ip_api.config_ip_addr_interface(data.dut5, 'Vlan500', '1212::1', mask_v6, family='ipv6')
        ip_api.config_ip_addr_interface(data.dut5, 'Vlan100', dut5_4_ip_list[0], mask_24)
        ip_api.config_ip_addr_interface(data.dut5, 'Vlan100', dut5_4_ipv6_list[0], mask_v6, family="ipv6")
        ip_api.config_ip_addr_interface(data.dut5, 'Vlan200', dut5_4_ip_list[2], mask_24)
        ip_api.config_ip_addr_interface(data.dut5, 'Vlan200', dut5_4_ipv6_list[2], mask_v6, family="ipv6")
        ip_api.config_ip_addr_interface(data.dut2, 'Vlan200', dut2_4_ip_list[2], mask_24)
        ip_api.config_ip_addr_interface(data.dut2, 'Vlan200', dut2_4_ipv6_list[2], mask_v6, family="ipv6")
        #ip_api.config_ip_addr_interface(data.dut5, data.client_lag, dut5_4_ip_list[2], mask_24)
        #ip_api.config_ip_addr_interface(data.dut5, data.client_lag, dut5_4_ipv6_list[2], mask_v6, family="ipv6")

        st.log("create port channel interface b/w LVTEP leaf 1 and leaf 2 for iccpd data ports")
        utils.exec_all(True, [[pc.create_portchannel, data.dut2, data.iccp_lag],
                              [pc.create_portchannel, data.dut5, data.iccp_lag]])
        utils.exec_all(True, [[pc.add_portchannel_member, data.dut2, data.iccp_lag, data.d2d5_ports[0]],
                               [pc.add_portchannel_member, data.dut5, data.iccp_lag, data.d5d2_ports[0]]])

        utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut2, '500', data.iccp_lag, True],
                              [vlan_api.add_vlan_member, data.dut5, '500', data.iccp_lag, True]])
        utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut2, '100', data.iccp_lag, True],
                              [vlan_api.add_vlan_member, data.dut5, '100', data.iccp_lag, True]])
        utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut2, '200', data.iccp_lag, True],
                              [vlan_api.add_vlan_member, data.dut5, '200', data.iccp_lag, True]])
        utils.exec_all(True, [[vlan_api.add_vlan_member, data.dut5, '200', data.d5d4_ports[0], True],
                              [vlan_api.add_vlan_member, data.dut4, '200', data.d4d5_ports[0], True]])

        st.log("Configure IP address b/w LVTEP Leaf 1 and Leaf 2 to establish ICCPD control path")
        utils.exec_all(True, [[ip_api.config_ip_addr_interface, data.dut2, data.d2d5_ports[2], dut2_5_ip_list[0], '24'],
                              [ip_api.config_ip_addr_interface, data.dut5, data.d5d2_ports[2], dut5_2_ip_list[0],'24']])

        st.log("configuring mc-lag in leaf 1 and leaf 2")
        mclag.config_domain(data.dut2, mlag_domain_id, local_ip=dut2_5_ip_list[0], peer_ip=dut5_2_ip_list[0],
                            peer_interface=data.iccp_lag)
        mclag.config_domain(data.dut5, mlag_domain_id, local_ip=dut5_2_ip_list[0], peer_ip=dut2_5_ip_list[0],
                            peer_interface=data.iccp_lag)

        mclag.config_interfaces(data.dut2, mlag_domain_id, data.client_lag, config = "add")
        mclag.config_interfaces(data.dut5, mlag_domain_id, data.client_lag, config = "add")
        #vlan_api.add_vlan_member(data.dut5, '500', data.d5d4_ports[0], tagging_mode=True)

        # L3 PortChannel
        def f5():
            # Create PO and members
            pc.create_portchannel(data.dut2, [data.client_lag_l3])
            pc.add_del_portchannel_member(data.dut2, data.client_lag_l3, data.d2d4_ports[2], 'add')
            vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name=data.client_lag_l3, skip_error='True')

        def f6():
            # Create PO and members
            pc.create_portchannel(data.dut5, [data.client_lag_l3])
            pc.add_del_portchannel_member(data.dut5, data.client_lag_l3, data.d5d4_ports[2], 'add')
            vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name=data.client_lag_l3, skip_error='True')

        def f7():
            # Create PO and members
            pc.create_portchannel(data.dut4, [data.client_lag_l3])
            pc.add_del_portchannel_member(data.dut4, data.client_lag_l3, data.d4d2_ports[2], 'add')
            pc.add_del_portchannel_member(data.dut4, data.client_lag_l3, data.d4d5_ports[2], 'add')

        [res, exceptions] = utils.exec_all(True, [[f5], [f6], [f7]])


        def f8():
            ip_api.create_static_route(data.dut2, next_hop='55.10.10.2', static_ip='{}/24'.format('100.100.100.101'), vrf=vrf_name)
            ip_api.config_ip_addr_interface(data.dut2, data.client_lag_l3, dut2_4_ip_list[3], mask_24)
            ip_api.config_ip_addr_interface(data.dut2, data.client_lag_l3, dut2_4_ipv6_list[3], mask_v6, family="ipv6")
            mclag.config_interfaces(data.dut2, mlag_domain_id, data.client_lag_l3, config="add")
            dhcp_relay.dhcp_relay_config(data.dut2, interface=data.client_lag_l3, IP=data.dhcp_server_ip,  action='add', vrf_name=vrf_name)
            dhcp_relay.dhcp_relay_config(data.dut2, interface=data.client_lag_l3, IP=data.dhcp_server_ipv6, action='add', family='ipv6', vrf_name=vrf_name)
            #dhcp_relay.dhcp_relay_option_config(data.dut2,src_interface='Loopback3',interface=data.client_lag_l3 ,option='src-intf',action='add',skip_error_check=True)
            #dhcp_relay.dhcp_relay_option_config(data.dut2,src_interface='Loopback3',interface=data.client_lag_l3 ,option='src-intf',action='add',family='ipv6',skip_error_check=True)

        def f9():
            ip_api.create_static_route(data.dut5, next_hop='55.10.10.1',  static_ip='{}/24'.format(dut2_loopback_ip), vrf=vrf_name)
            ip_api.config_ip_addr_interface(data.dut5, data.client_lag_l3, dut5_4_ip_list[3], mask_24)
            ip_api.config_ip_addr_interface(data.dut5, data.client_lag_l3, dut5_4_ipv6_list[3], mask_v6, family="ipv6")
            mclag.config_interfaces(data.dut5, mlag_domain_id, data.client_lag_l3, config="add")
            dhcp_relay.dhcp_relay_config(data.dut5, interface=data.client_lag_l3, IP=data.dhcp_server_ip,  action='add', vrf_name=vrf_name)
            dhcp_relay.dhcp_relay_config(data.dut5, interface=data.client_lag_l3, IP=data.dhcp_server_ipv6, action='add', family='ipv6', vrf_name=vrf_name)
            #dhcp_relay.dhcp_relay_option_config(data.dut5,src_interface='Loopback3',interface=data.client_lag_l3 ,option='src-intf',action='add',skip_error_check=True)
            #dhcp_relay.dhcp_relay_option_config(data.dut5,src_interface='Loopback3',interface=data.client_lag_l3 ,option='src-intf',action='add',family='ipv6',skip_error_check=True)

        [res, exceptions] = utils.exec_all(True, [[f8], [f9]])

        # Configure transport vlan between MCLAG leaf nodes for orphan port routes
        def f10():
            vlan_api.create_vlan(data.dut2, ['5'])
            intf = 'Vlan5'
            ipadd = '55.10.10.1'
            ipv6addr = '5555::1'
            mclag.config_uniqueip(data.dut2, op_type='add', vlan=intf)
            vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name=intf, skip_error='True')
            ip_api.config_ip_addr_interface(data.dut2, intf, ipadd, mask_24)
            ip_api.config_ip_addr_interface(data.dut2, intf, ipv6addr, mask_v6, family="ipv6")
            ip_api.create_static_route(data.dut2, next_hop= '5555::2',static_ip='{}/128'.format(dut5_loopback_ip6),vrf = vrf_name,family="ipv6")
            vlan_api.add_vlan_member(data.dut2, '5', data.iccp_lag, True)


        def f11():
            vlan_api.create_vlan(data.dut5, ['5'])
            intf = 'Vlan5'
            ipadd = '55.10.10.2'
            ipv6addr = '5555::2'

            mclag.config_uniqueip(data.dut5, op_type='add', vlan=intf)
            vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name=intf, skip_error='True')
            ip_api.config_ip_addr_interface(data.dut5, intf, ipadd, mask_24)
            ip_api.config_ip_addr_interface(data.dut5, intf, ipv6addr, mask_v6, family="ipv6")
            ip_api.create_static_route(data.dut5, next_hop= '5555::1',static_ip='{}/128'.format(dut2_loopback_ip6),vrf = vrf_name,family="ipv6")
            vlan_api.add_vlan_member(data.dut5, '5', data.iccp_lag, True)

        [res, exceptions] = utils.exec_all(True, [[f10], [f11]])
        ip_api.create_static_route(data.dut5, next_hop= '55.10.10.1',static_ip='{}/24'.format(data.server_pool[1]+'0'),vrf = vrf_name)

        # VTEP configuration
        # =====================
        evpn.create_overlay_intf(data.dut5, "vtepLeaf1", dut2_loopback_ip_list[1])

        st.log("config evpn nvo instance on all leaf nodes")
        evpn.create_evpn_instance(data.dut5, "nvoLeaf1", "vtepLeaf1")

        evpn.map_vlan_vni(data.dut5, "vtepLeaf1", "500", "500")
        evpn.map_vrf_vni(data.dut5, vrf_name, vtep_name='vtepLeaf1',vni='500')

        ##########################################################################
        hdrMsg("BGP-config: Configure bgp on DUT2 for Vtep ")
        ##########################################################################
        bgp_api.config_bgp(data.dut5, local_as=dut5_AS, vrf_name=vrf_name, config='yes', config_type_list=["redist"],
                           redistribute='connected')
        bgp_api.config_bgp(data.dut5, local_as=dut5_AS, vrf_name=vrf_name, config='yes', config_type_list=["redist"],
                           redistribute='connected', addr_family='ipv6')
        bgp_api.config_bgp(data.dut5, local_as=dut5_AS, config='yes', config_type_list=["redist"],
                           redistribute='connected')
        evpn.config_bgp_evpn(data.dut5, vrf_name=vrf_name, config='yes', config_type_list=["advertise_ipv4_vrf"],
                             local_as=dut5_AS, advertise_ipv4='unicast')
        evpn.config_bgp_evpn(data.dut5, vrf_name=vrf_name, config='yes', config_type_list=["advertise_ipv6_vrf"],
                             local_as=dut5_AS, advertise_ipv6='unicast')

        # Verify PortChannel status on client
        # Verify mclag status
    else:
        ip_api.delete_static_route(data.dut5, next_hop= '55.10.10.1',static_ip='{}/24'.format(data.server_pool[1]+'0'),vrf = vrf_name)

        # L3 PortChannel

        def f8():

            dhcp_relay.dhcp_relay_config(data.dut2, interface=data.client_lag_l3, IP=data.dhcp_server_ip,  action='remove')
            dhcp_relay.dhcp_relay_config(data.dut2, interface=data.client_lag_l3, IP=data.dhcp_server_ipv6, action='remove', family='ipv6')
            mclag.config_interfaces(data.dut2, mlag_domain_id, data.client_lag_l3, config="del")
            ip_api.delete_ip_interface(data.dut2, data.client_lag_l3, dut2_4_ip_list[3], mask_24)
            ip_api.delete_ip_interface(data.dut2, data.client_lag_l3, dut2_4_ipv6_list[3], mask_v6, family="ipv6")
        def f9():
            dhcp_relay.dhcp_relay_config(data.dut5, interface=data.client_lag_l3, IP=data.dhcp_server_ip,  action='remove')
            dhcp_relay.dhcp_relay_config(data.dut5, interface=data.client_lag_l3, IP=data.dhcp_server_ipv6, action='remove', family='ipv6')
            mclag.config_interfaces(data.dut5, mlag_domain_id, data.client_lag_l3, config="del")
            ip_api.delete_ip_interface(data.dut5, data.client_lag_l3, dut5_4_ip_list[3], mask_24)
            ip_api.delete_ip_interface(data.dut5, data.client_lag_l3, dut5_4_ipv6_list[3], mask_v6, family="ipv6")

        [res, exceptions] = utils.exec_all(True, [[f8], [f9]])
        def f5():
            # Create PO and members
            pc.delete_portchannel_member(data.dut2, data.client_lag_l3, data.d2d4_ports[2])
            vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name=data.client_lag_l3, config = 'no', skip_error='True')
            pc.delete_portchannel(data.dut2, [data.client_lag_l3])


        def f6():
            # Create PO and members
            pc.delete_portchannel_member(data.dut5, data.client_lag_l3, data.d5d4_ports[2])
            vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name=data.client_lag_l3, config = 'no', skip_error='True')
            pc.delete_portchannel(data.dut5, [data.client_lag_l3])


        def f7():
            # Create PO and members
            pc.delete_portchannel_member(data.dut4, data.client_lag_l3, data.d4d2_ports[2])
            pc.delete_portchannel_member(data.dut4, data.client_lag_l3, data.d4d5_ports[2])
            pc.delete_portchannel(data.dut4, [data.client_lag_l3])

        [res, exceptions] = utils.exec_all(True, [[f5], [f6], [f7]])

        ##########################################################################
        hdrMsg("UnConfigure transport vlan between MCLAG leaf nodes for orphan port routes")
        ##########################################################################

        def f10():
            intf = 'Vlan5'
            ipadd = '55.10.10.1'
            ipv6addr = '5555::1'

            vlan_api.delete_vlan_member(data.dut2, '5', data.iccp_lag, True)
            ip_api.delete_ip_interface(data.dut2, intf, ipadd, mask_24)
            ip_api.delete_static_route(data.dut2, next_hop= '5555::2',static_ip='{}/128'.format(dut5_loopback_ip6),vrf = vrf_name,family="ipv6")
            ip_api.delete_ip_interface(data.dut2, intf, ipv6addr, mask_v6, family="ipv6")
            vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name=intf, config = 'no',skip_error='True')
            mclag.config_uniqueip(data.dut2, op_type='del', vlan=intf)
            vlan_api.delete_vlan(data.dut2, ['5'])

        def f11():
            intf = 'Vlan5'
            ipadd = '55.10.10.2'
            ipv6addr = '5555::2'

            vlan_api.delete_vlan_member(data.dut5, '5', data.iccp_lag, True)
            ip_api.delete_ip_interface(data.dut5, intf, ipadd, mask_24)
            ip_api.delete_static_route(data.dut5, next_hop= '5555::1',static_ip='{}/128'.format(dut2_loopback_ip6),vrf = vrf_name,family="ipv6")
            ip_api.delete_ip_interface(data.dut5, intf, ipv6addr, mask_v6, family="ipv6")
            vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name=intf, config = 'no',skip_error='True')
            mclag.config_uniqueip(data.dut5, op_type='del', vlan=intf)
            vlan_api.delete_vlan(data.dut5, ['5'])

        [res, exceptions] = utils.exec_all(True, [[f10], [f11]])
        ###########################
        # Unconfig Vxlan
        evpn.map_vrf_vni(data.dut5, vrf_name, vtep_name='vtepLeaf1',vni='500',config = 'no')
        evpn.map_vlan_vni(data.dut5, "vtepLeaf1", "500", "500",config = 'no')
        evpn.create_evpn_instance(data.dut5, "nvoLeaf1", "vtepLeaf1",config = 'no')
        evpn.create_overlay_intf(data.dut5, "vtepLeaf1", dut2_loopback_ip_list[1],config = 'no')

        # Unconfig MCLAG
        utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut2, '500', data.iccp_lag, True],
                              [vlan_api.delete_vlan_member, data.dut5, '500', data.iccp_lag, True]])
        utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut2, '100', data.iccp_lag, True],
                              [vlan_api.delete_vlan_member, data.dut5, '100', data.iccp_lag, True]])
        utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut2, '200', data.iccp_lag, True],
                              [vlan_api.delete_vlan_member, data.dut5, '200', data.iccp_lag, True]])
        utils.exec_all(True, [[vlan_api.delete_vlan_member, data.dut5, '200', data.d5d4_ports[0], True],
                              [vlan_api.delete_vlan_member, data.dut4, '200', data.d4d5_ports[0], True]])
        vlan_api.delete_vlan_member(data.dut5,'100',data.client_lag)
        mclag.config_interfaces(data.dut2, mlag_domain_id, data.client_lag, config = "del")
        mclag.config_interfaces(data.dut5, mlag_domain_id, data.client_lag, config = "del")

        utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut2, data.d2d5_ports[2], dut2_5_ip_list[0], '24'],
                              [ip_api.delete_ip_interface, data.dut5, data.d5d2_ports[2], dut5_2_ip_list[0], '24']])

        st.log("unconfiguring mc-lag in leaf 1 and leaf 2")
        mclag.config_domain(data.dut2, mlag_domain_id, local_ip=dut2_5_ip_list[0], peer_ip=dut5_2_ip_list[0],
                            peer_interface=data.iccp_lag,config='del')
        mclag.config_domain(data.dut5, mlag_domain_id, local_ip=dut5_2_ip_list[0], peer_ip=dut2_5_ip_list[0],
                            peer_interface=data.iccp_lag,config='del')

        st.log("delete port channel interface b/w LVTEP leaf 1 and leaf 2 for iccpd data ports")
        utils.exec_all(True, [[pc.delete_portchannel_member, data.dut2, data.iccp_lag, data.d2d5_ports[0]],
                               [pc.delete_portchannel_member, data.dut5, data.iccp_lag, data.d5d2_ports[0]]])
        utils.exec_all(True, [[pc.delete_portchannel, data.dut2, data.iccp_lag],
                              [pc.delete_portchannel, data.dut5, data.iccp_lag]])

        ip_api.delete_ip_interface(data.dut5, "Loopback3", '100.100.100.101', '32')
        ip_api.delete_ip_interface(data.dut5, "Loopback3", dut5_loopback_ip6, '128', family="ipv6")
        ip_api.delete_ip_interface(data.dut5, 'Vlan500', '22.22.1.1', mask_24)
        ip_api.delete_ip_interface(data.dut5, 'Vlan500', '1212::1', mask_v6, family='ipv6')
        ip_api.delete_ip_interface(data.dut5, 'Vlan100', dut5_4_ip_list[0], mask_24)
        ip_api.delete_ip_interface(data.dut5, 'Vlan100', dut5_4_ipv6_list[0], mask_v6, family="ipv6")

        ip_api.delete_ip_interface(data.dut5, 'Vlan200', dut5_4_ip_list[2], mask_24)
        ip_api.delete_ip_interface(data.dut5, 'Vlan200', dut5_4_ipv6_list[2], mask_v6, family="ipv6")
        ip_api.delete_ip_interface(data.dut2, 'Vlan200', dut2_4_ip_list[2], mask_24)
        ip_api.delete_ip_interface(data.dut2, 'Vlan200', dut2_4_ipv6_list[2], mask_v6, family="ipv6")
        vrf_api.bind_vrf_interface(data.dut2, vrf_name=vrf_name, intf_name='Vlan200', skip_error='True',config = 'no')

        utils.exec_all(True, [[pc.add_del_portchannel_member, data.dut5, data.client_lag, data.d5d4_ports[1], 'del'],
                              [pc.add_del_portchannel_member, data.dut4, data.client_lag, data.d4d5_ports[1], 'del']])
        vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name='Vlan200', skip_error='True',config = 'no')
        vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name='Vlan500', skip_error='True',config = 'no')
        vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name='Vlan100', skip_error='True',config = 'no')
        vrf_api.bind_vrf_interface(data.dut5, vrf_name=vrf_name, intf_name='Loopback3', skip_error='True',config = 'no')
        st.log("delete vlan port membership on leaf 1 and leaf 2 o lvtep")
        pc.delete_portchannel(data.dut5, [data.client_lag])

        vlan_api.delete_vlan(data.dut5, ['500'])
        vlan_api.delete_vlan(data.dut5, ['200'])
        vlan_api.delete_vlan(data.dut5, ['100'])
        vlan_api.delete_vlan(data.dut2, ['200'])
        vlan_api.delete_vlan(data.dut4, ['200'])

        # Unconfig BGP
        ##########################################################################
        hdrMsg("BGP-config: Configure  EBGP sessions between dut1 <--> dut5")
        ##########################################################################

        update = 'update_src' if st.get_ui_type(data.dut1) == 'click' else 'update_src_intf'
        dict1 = {'local_as': dut1_AS, 'neighbor': dut5_loopback_ip_list[0],
                 'config_type_list': [update], update: 'Loopback1', 'config':'no'}
        dict2 = {'local_as': dut5_AS, 'neighbor': dut1_loopback_ip_list[0],
                 'config_type_list': [update], update: 'Loopback1', 'config':'no'}
        parallel.exec_parallel(True, [data.dut1, data.dut5], bgp_api.config_bgp, [dict1, dict2])

        utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut1, data.d1d5_ports[0], dut1_5_ip_list[0], mask],
                              [ip_api.delete_ip_interface, data.dut5, data.d5d1_ports[0], dut5_1_ip_list[0], mask]])
        utils.exec_all(True, [
            [ip_api.delete_ip_interface, data.dut1, data.d1d5_ports[0], dut1_5_ipv6_list[0], mask_v6, 'ipv6'],
            [ip_api.delete_ip_interface, data.dut5, data.d5d1_ports[0], dut5_1_ipv6_list[0], mask_v6, 'ipv6']])

        # Unconfig IP and vlans.
        utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut5, "Loopback1", dut5_loopback_ip_list[0], '32']])
        utils.exec_all(True, [[ip_api.delete_ip_interface, data.dut5, "Loopback2", dut5_loopback_ip_list[1], '32']])
        parallel.exec_parallel(True, [data.dut5], ip_api.configure_loopback,
                                   [{'loopback_name': 'Loopback1', 'config': 'no'}])
        parallel.exec_parallel(True, [data.dut5], ip_api.configure_loopback,
                                   [{'loopback_name': 'Loopback2', 'config': 'no'}])

        ip_api.delete_static_route(data.dut1, next_hop=dut5_1_ip_list[0],
                                       static_ip='{}/32'.format(dut5_loopback_ip_list[0]))
        ip_api.delete_static_route(data.dut5, next_hop=dut1_5_ip_list[0],
                                       static_ip='{}/32'.format(dut1_loopback_ip_list[0]))
        dict1 = {'vrf_name': vrf_name, 'config': 'no'}
        parallel.exec_parallel(True, [data.dut5], vrf_api.config_vrf, [dict1])
        dhcp_server_unconfig()

def dhcp_server_config():
    '''
    1. Install dhcp package
    2. Update dhcp files - dhcpd6.conf  dhcpd.conf  isc-dhcp-server
    3. create vlan, member and configure IPv4 and IPv6.
    4. Add static routes
    5.Restart dhcp process
    '''
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
#    st.config(dut,'sudo mv /tmp/'+data.dhcp_files[2]+' /etc/dhcp/',skip_error_check=True)
    basic_api.move_file_to_local_path(dut, '/tmp/'+data.dhcp_files[0], '/etc/default/', sudo=True, skip_error_check=True)
    basic_api.move_file_to_local_path(dut, '/tmp/'+data.dhcp_files[1], '/etc/dhcp/', sudo=True, skip_error_check=True)
    basic_api.move_file_to_local_path(dut, '/tmp/'+data.dhcp_files[2], '/etc/dhcp/', sudo=True, skip_error_check=True)

    basic_api.deploy_package(dut, mode='update')
    basic_api.deploy_package(dut, options='-o Dpkg::Options::=\"--force-confold\"', packane_name='isc-dhcp-server', mode='install',skip_verify_package=True)

    #st.config(dut, "systemctl restart isc-dhcp-server")
    st.wait(2)
    ps_aux = basic_api.get_ps_aux(data.dut1, "dhcpd")
    if len(ps_aux) > 1:
        return True
    return False

def dhcp_server_unconfig():
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

def killall_dhclient(dut):
    basic_api.killall_process(dut, name='dhclient', skip_error_check=True)
    basic_api.delete_file_from_local_path(dut, filename='/var/lib/dhcp/dhclient.leases', skip_error_check=True)
    basic_api.delete_file_from_local_path(dut, filename='/var/lib/dhcp/dhclient6.leases', skip_error_check=True)
    #st.config(dut,'killall dhclient',skip_error_check=True)
    #st.config(dut,'rm /var/lib/dhcp/dhclient.leases',skip_error_check=True)
    #st.config(dut, 'rm /var/lib/dhcp/dhclient6.leases',skip_error_check=True)

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

