from spytest import st,utils
from pbr_vars import data
import apis.system.port as port_api
import apis.switching.portchannel as pc
import apis.switching.vlan as vlan_api
import apis.routing.ip as ip_api
import apis.routing.bgp as bgp_api
import apis.routing.ip_bgp as ip_bgp
import apis.routing.vrf as vrf_api
import apis.routing.ospf as ospf_api
from apis.routing import arp
from utilities import parallel
from spytest.tgen.tgen_utils import validate_tgen_traffic
import apis.system.basic as basic_api
import apis.qos.acl as acl_api
import apis.qos.acl_dscp as acl_dscp_api
from spytest.utils import filter_and_select
import apis.system.reboot as reboot_api
import apis.system.interface as intf_api
import struct
import socket
import sys

def get_tc_name(level=1):
    return sys._getframe(level).f_code.co_name

def pbr_base_config():
    ###################################################
    st.banner("########## BASE Config Starts ########")
    ###################################################
    debug_enable()
    config_lag()
    config_vlan()
    result = verify_lag()
    if not result:
        return False
    api_list = [[config_tgen],[config_dut]]
    ret_val = parallel.exec_all(True, api_list, True)
    if ret_val[0][1] is False:
        return False
    ###################################################
    st.banner("########## BASE Config End ########")
    ###################################################
    return True

def config_dut():
    config_vrf()
    config_ip()
    config_static_leak_dut2()
    config_bgp()
    result = verify_bgp()
    if not result:
        return False
    config_ospf()
    result = verify_ospf()
    if not result:
        return False
    config_static_arp()
    access_list_base()
    classifier_config_base()
    policy_config_base()


def config_tgen():
    config_stream(config='yes')

def deconfig_dut():
    if not data.scale_complete:
        policy_config_base('no')
        classifier_config_base('no')
    access_list_base('no')
    config_static_arp('no')
    config_static_leak_dut2('no')
    config_ospf('no')
    config_bgp('no')
    config_ip('no')
    config_vrf('no')
    config_vlan('no')
    config_lag('no')

def deconfig_tgen():
    config_stream('no')

def pbr_base_deconfig():
    ###################################################
    st.banner("########## BASE De-Config Starts ########")
    ###################################################
    debug_enable(config='no')
    api_list = [[deconfig_tgen], [deconfig_dut]]
    parallel.exec_all(True, api_list, True)
    ###################################################
    st.banner("########## BASE De-Config End ########")
    ###################################################
    return True



def debug_enable(config='yes'):
    pass



def config_lag(config='yes'):
    if config == 'yes':
        member_flag = 'add'
        ###################################################
        st.banner("LAG-Config: Configure {} between D1 and D2 with 2 member ports".format(data.lag_intf))
        ###################################################

        utils.exec_all(True, [[pc.create_portchannel, data.dut1, [data.lag_intf], False],
                              [pc.create_portchannel, data.dut2, [data.lag_intf], False]])
    else:
        member_flag = 'del'

    ###################################################################
    st.banner("LAG-Config: {} member ports to {} on D1 and D3".format(member_flag,data.lag_intf))
    ###################################################################
    utils.exec_all(True, [[pc.add_del_portchannel_member, data.dut1,data.lag_intf,data.d1d2_ports[0:2],member_flag],
                          [pc.add_del_portchannel_member, data.dut2, data.lag_intf,data.d2d1_ports[0:2],member_flag]])

    if config == 'no':
        ###################################################################
        st.banner("{} Port-channels from all duts".format(member_flag))
        ###################################################################
        utils.exec_all(True, [[pc.delete_portchannel, data.dut1, [data.lag_intf]],
                              [pc.delete_portchannel, data.dut2, [data.lag_intf]]])


def verify_lag():
    ###################################################################
    st.banner("Verify Port-Channels are UP on DUT1 and DUT2")
    ###################################################################
    ret_val = True;
    err_list = []
    result = retry_api(pc.verify_portchannel_state, data.dut1, portchannel=data.lag_intf,retry_count=10)
    if result is False:
        err_list.append("{} did not come up on dut1".format(data.lag_intf))
        ret_val = False
    return ret_val



def config_vlan(config='yes'):
    if config == 'yes':
        ###################################################################
        st.banner("Vlan-Config: Configure Vlans {},{},{} on D1 and {},{} on D2".format(data.d1tg_vlan_id,data.lag_vlan_id,data.access_vlan_id,
                                                                                       data.lag_vlan_id,data.access_vlan_id))
        ###################################################################
        utils.exec_all(True, [[vlan_api.create_vlan, data.dut1, [data.d1tg_vlan_id,data.lag_vlan_id,data.access_vlan_id]],
                              [vlan_api.create_vlan, data.dut2, [data.lag_vlan_id,data.access_vlan_id]]])

        ###################################################################
        st.banner("Vlan-Config: Configure port between D1 and D2 as untagged on vlan {}".format(data.access_vlan_id))
        ###################################################################
        utils.exec_all(True,[[vlan_api.add_vlan_member,data.dut1,data.access_vlan_id,[data.d1d2_ports[2]],False],
                             [vlan_api.add_vlan_member,data.dut2,data.access_vlan_id,[data.d2d1_ports[2]],False]])

        ###################################################################
        st.banner("Vlan-Config: Configure lag port {} between D1 and D2 as tagged on vlan {}".format(data.lag_intf,data.lag_vlan_id))
        ###################################################################
        utils.exec_all(True,[[vlan_api.add_vlan_member,data.dut1,data.lag_vlan_id,[data.lag_intf], True],
                             [vlan_api.add_vlan_member,data.dut2,data.lag_vlan_id,[data.lag_intf], True]])

        ###################################################################
        st.banner("Vlan-Config: Configure a tagged Vlan member between D1 and Tgen on vlan {}".format(data.d1tg_vlan_id))
        ###################################################################
        vlan_api.add_vlan_member(data.dut1,data.d1tg_vlan_id,[data.d1tg_ports[0]], True)

        data.tg_d1_dest_mac = basic_api.get_ifconfig(data.dut1,data.d1tg_vlan_intf)[0]['mac']
        data.tg_d1_dest_mac_phy = basic_api.get_ifconfig(data.dut1, data.d1tg_ports[0])[0]['mac']

    else:
        ###################################################################
        st.banner("Vlan-DeConfig: Remove all Vlan membership from ports on all DUTs")
        ###################################################################
        utils.exec_all(True,[[vlan_api.delete_vlan_member,data.dut1,data.access_vlan_id,[data.d1d2_ports[2]]],
                             [vlan_api.delete_vlan_member,data.dut2,data.access_vlan_id,[data.d2d1_ports[2]]]])

        utils.exec_all(True,[[vlan_api.delete_vlan_member,data.dut1,data.lag_vlan_id,[data.lag_intf],True],
                             [vlan_api.delete_vlan_member,data.dut2,data.lag_vlan_id,[data.lag_intf],True]])

        vlan_api.delete_vlan_member(data.dut1,data.d1tg_vlan_id, [data.d1tg_ports[0]],True)

        ###################################################################
        st.banner("Vlan-DeConfig: Delete Vlans on all DUTs")
        ###################################################################
        utils.exec_all(True, [[vlan_api.delete_vlan, data.dut1, [data.d1tg_vlan_id,data.lag_vlan_id,data.access_vlan_id]],
                              [vlan_api.delete_vlan, data.dut2, [data.lag_vlan_id,data.access_vlan_id]]])



def config_vrf(config='yes'):
    if config == 'yes':
        ###################################################################
        st.banner("VRF-Config: Configure VRF {} and {} on all DUTs".format(data.phy_vrf,data.access_vrf))
        ###################################################################
        dict1 = {'vrf_name': data.phy_vrf, 'skip_error': True}
        parallel.exec_parallel(True,data.dut_list, vrf_api.config_vrf, [dict1]*len(data.dut_list))
        dict1 = {'vrf_name': data.access_vrf, 'skip_error': True}
        parallel.exec_parallel(True,data.dut_list, vrf_api.config_vrf, [dict1]*len(data.dut_list))

    ###################################################################
    st.banner("VRF-Config : Bind VRF {} to Vlan {} on D1 and D2".format(data.access_vrf,data.access_vlan_intf))
    ###################################################################

    dict1 = {'vrf_name':[data.access_vrf], 'intf_name': data.access_vlan_intf,'skip_error':True,'config':config}
    parallel.exec_parallel(True, data.dut_list, vrf_api.bind_vrf_interface, [dict1]*2)

    ###################################################################
    st.banner("VRF-Config : Bind VRF {} to phy l3 port on D1 and D2".format(data.phy_vrf))
    ###################################################################

    dict1 = {'vrf_name':[data.phy_vrf], 'intf_name': data.d1d2_ports[3],'skip_error':True,'config':config}
    dict2 = {'vrf_name': [data.phy_vrf], 'intf_name': data.d2d1_ports[3], 'skip_error': True, 'config': config}
    parallel.exec_parallel(True, data.dut_list, vrf_api.bind_vrf_interface, [dict1,dict2])

    if config == 'no':
        ###################################################################
        st.banner("VRF-Config: Delete VRF on all DUTs")
        ###################################################################
        dict1 = {'vrf_name':data.phy_vrf, 'skip_error': True,'config':'no'}
        parallel.exec_parallel(True,data.dut_list, vrf_api.config_vrf, [dict1]*len(data.dut_list))
        dict1 = {'vrf_name':data.access_vrf, 'skip_error': True,'config':'no'}
        parallel.exec_parallel(True,data.dut_list, vrf_api.config_vrf, [dict1]*len(data.dut_list))



def config_ip(config='yes'):
    if config == 'yes':
        api_name = ip_api.config_ip_addr_interface
        config_str = "Configure"
    else:
        api_name = ip_api.delete_ip_interface
        config_str = "Delete"

    ###################################################################
    st.banner("IP-Config: {} ip/ipv6 addresses on {} between D1 and D2 ".format(config_str,data.lag_vlan_intf))
    ###################################################################

    utils.exec_all(True, [[api_name, data.dut1,data.lag_vlan_intf, data.lag_ip_list[0], data.mask_v4],
                          [api_name, data.dut2, data.lag_vlan_intf, data.lag_ip_list[1], data.mask_v4]])

    utils.exec_all(True, [[api_name, data.dut1,data.lag_vlan_intf, data.lag_ipv6_list[0], data.mask_v6,'ipv6'],
                          [api_name, data.dut2, data.lag_vlan_intf, data.lag_ipv6_list[1], data.mask_v6,'ipv6']])

    ###################################################################
    st.banner("IP-Config: {} ip/ipv6 addresses on {}  between D1 and D2 ".format(config_str,data.access_vlan_intf))
    ###################################################################

    utils.exec_all(True, [[api_name, data.dut1, data.access_vlan_intf, data.vlan_ip_list[0], data.mask_v4],
                          [api_name, data.dut2, data.access_vlan_intf, data.vlan_ip_list[1], data.mask_v4]])

    utils.exec_all(True, [[api_name, data.dut1, data.access_vlan_intf, data.vlan_ipv6_list[0], data.mask_v6,'ipv6'],
                          [api_name, data.dut2, data.access_vlan_intf, data.vlan_ipv6_list[1], data.mask_v6,'ipv6']])

    ###################################################################
    st.banner("IP-Config: {} ip/ipv6 addresses on physical port between D1 and D2 ".format(config_str))
    ###################################################################

    utils.exec_all(True, [[api_name, data.dut1, data.d1d2_ports[3], data.phy_ip_list[0], data.mask_v4],
                          [api_name, data.dut2, data.d2d1_ports[3], data.phy_ip_list[1], data.mask_v4]])

    utils.exec_all(True, [[api_name, data.dut1, data.d1d2_ports[3], data.phy_ipv6_list[0], data.mask_v6,'ipv6'],
                          [api_name, data.dut2, data.d2d1_ports[3], data.phy_ipv6_list[1], data.mask_v6,'ipv6']])

    ###################################################################
    st.banner("IP-Config: {} ip/ipv6 addresses on D1,D2 and Tgen port ".format(config_str))
    ###################################################################

    utils.exec_all(True, [[api_name, data.dut1, data.d1tg_vlan_intf, data.d1tg_ip_list[0], data.mask_v4],
                          [api_name, data.dut2, data.d2tg_ports[0], data.d2tg_ip_list[0], data.mask_v4]])

    utils.exec_all(True, [[api_name, data.dut1, data.d1tg_vlan_intf, data.d1tg_ipv6_list[0], data.mask_v6,'ipv6'],
                          [api_name, data.dut2, data.d2tg_ports[0], data.d2tg_ipv6_list[0], data.mask_v6,'ipv6']])


def config_bgp(config='yes'):
    if config == 'yes':
        utils.exec_all(True,[[ip_api.config_route_map_global_nexthop,data.dut1, 'rmap_v6','10','yes'],
                             [ip_api.config_route_map_global_nexthop,data.dut2, 'rmap_v6','10','yes']])
        for vrf in data.vrf_list:
            ##########################################################################
            st.banner("BGP-config: Configure BGP routers on D1 and D2")
            ##########################################################################
            dict1 = {'local_as':data.d1_as,'router_id':data.d1_router_id,'config_type_list':['router_id'],'vrf_name':vrf}
            dict2 = {'local_as':data.d2_as,'router_id':data.d2_router_id,'config_type_list':['router_id'],'vrf_name':vrf}
            if vrf == 'default':
                del dict1['vrf_name']; del dict2['vrf_name']
            parallel.exec_parallel(True, data.dut_list, bgp_api.config_bgp, [dict1, dict2])

            ##########################################################################
            st.banner("BGP-config: Configure eBGP neighbors between D1 and D2")
            ##########################################################################
            if vrf == 'default':
                d1_nbr = data.lag_ip_list[1];d1_nbr_v6 = data.lag_ipv6_list[1];d2_nbr=data.lag_ip_list[0];d2_nbr_v6=data.lag_ipv6_list[0]
            elif vrf == data.access_vrf:
                d1_nbr = data.vlan_ip_list[1]; d1_nbr_v6 = data.vlan_ipv6_list[1]; d2_nbr = data.vlan_ip_list[0]; d2_nbr_v6 = data.vlan_ipv6_list[0]
            else:
                d1_nbr = data.phy_ip_list[1]; d1_nbr_v6 = data.phy_ipv6_list[1]; d2_nbr = data.phy_ip_list[0];d2_nbr_v6 = data.phy_ipv6_list[0]
            dict1 = {'config_type_list': ['neighbor'], 'remote_as': data.d2_as, 'neighbor': d1_nbr,'local_as':data.d1_as,'vrf_name':vrf}
            dict2 = {'config_type_list': ['neighbor'], 'remote_as': data.d1_as, 'neighbor': d2_nbr,'local_as':data.d2_as,'vrf_name':vrf}
            if vrf == 'default':
                del dict1['vrf_name']; del dict2['vrf_name']
            parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

            dict1 = {'config_type_list': ['neighbor','activate',"routeMap"], 'remote_as': data.d2_as, 'neighbor': d1_nbr_v6,
                     'local_as':data.d1_as,'addr_family':'ipv6','vrf_name':vrf,'routeMap':'rmap_v6', 'diRection':'in'}
            dict2 = {'config_type_list': ['neighbor','activate'], 'remote_as': data.d1_as, 'neighbor': d2_nbr_v6,
                     'local_as':data.d2_as,'addr_family':'ipv6','vrf_name':vrf}
            if vrf == 'default':
                del dict1['vrf_name']; del dict2['vrf_name']
            parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    else:
        temp_vrf_list = list()
        temp_vrf_list = data.vrf_list[::-1]
        for vrf in temp_vrf_list:
            ##########################################################################
            st.banner("BGP-Deconfig: Delete BGP routers globally from all DUTs")
            ##########################################################################
            dict1 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','local_as':data.d1_as,'vrf_name':vrf}
            dict2 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','local_as': data.d2_as,'vrf_name':vrf}
            if vrf == 'default':
                del dict1['vrf_name']; del dict2['vrf_name']
            parallel.exec_parallel(True, data.dut_list, bgp_api.config_bgp, [dict1,dict2])


def verify_bgp():
    ###########################################################
    st.banner("BGP verify: Verify BGP sessions are up on dut1")
    ############################################################
    for vrf in data.vrf_list:
        if vrf == 'default': nbr_list= [data.lag_ip_list[1],data.lag_ipv6_list[1]]
        if vrf == data.access_vrf: nbr_list= [data.vlan_ip_list[1],data.vlan_ipv6_list[1]]
        if vrf == data.phy_vrf: nbr_list =[data.phy_ip_list[1],data.phy_ipv6_list[1]]
        result = retry_api(ip_bgp.check_bgp_session,data.dut1,nbr_list=nbr_list,
                           state_list=['Established']*2,vrf_name=vrf,retry_count=30,delay=1)
        if result is False:
            st.error("VRF {} one or more BGP sessions did not come up on DUT1".format(vrf))
            return False
    return True

def advertise_bgp_routes(config='yes'):
    config_str = 'Advertise' if config == 'yes' else 'Withdraw'
    #################################################
    st.banner("{}  BGP routes from D2".format(config_str))
    #################################################
    for vrf in data.vrf_list:
        dict1 = {'config_type_list': ['network'], 'network': '{}/24'.format(data.dest_ip_nw),'local_as': data.d2_as,'config':config,'vrf_name':vrf}
        if vrf == 'default': del dict1['vrf_name']
        parallel.exec_parallel(True, [data.dut2], bgp_api.config_bgp, [dict1])
        dict1 = {'config_type_list': ['network'], 'network': '{}/64'.format(data.dest_ipv6_nw),'local_as': data.d2_as,'addr_family':'ipv6','config':config,'vrf_name':vrf}
        if vrf == 'default': del dict1['vrf_name']
        parallel.exec_parallel(True, [data.dut2], bgp_api.config_bgp, [dict1])


def access_list_base(config='yes'):
    if config == 'yes':
        ###############################################
        st.banner("Configure ip/Ipv6 premit and deny access-lists")
        ###############################################
        if 'rest' in st.get_ui_type():
            v4_str='/32';v6_str ='/128'
        else:
            v4_str = v6_str = ''
        acl_api.create_acl_table(data.dut1, name=data.ip_permit_acl, stage='INGRESS', type='ip', ports=[])
        acl_api.create_acl_table(data.dut1, name=data.ip_deny_acl, stage='INGRESS', type='ip', ports=[])
        acl_api.create_acl_table(data.dut1, name=data.ipv6_permit_acl, stage='INGRESS', type='ipv6', ports=[])
        acl_api.create_acl_table(data.dut1, name=data.ipv6_deny_acl, stage='INGRESS', type='ipv6', ports=[])
        acl_api.create_acl_rule(data.dut1,acl_type='ip',rule_name=data.ip_permit_acl,rule_seq='10',packet_action='permit',table_name=data.ip_permit_acl,
                                src_ip=data.d1tg_ip_list[1]+v4_str,dst_ip=data.d2tg_ip_list[1]+v4_str,host_1= 'host',host_2='host',l4_protocol='ip')
        acl_api.create_acl_rule(data.dut1,acl_type='ip', rule_name=data.ip_deny_acl, rule_seq='10', packet_action='deny',table_name=data.ip_deny_acl,
                            src_ip=data.d1tg_ip_list[1]+v4_str, dst_ip=data.d2tg_ip_list[1]+v4_str,host_1= 'host',host_2='host',l4_protocol='ip')
        acl_api.create_acl_rule(data.dut1,acl_type='ip', rule_name=data.ip_deny_acl, rule_seq='20', packet_action='permit',table_name=data.ip_deny_acl,
                            src_ip='11.11.11.3'+v4_str, dst_ip='any',host_1= 'host',l4_protocol='ip')
        acl_api.create_acl_rule(data.dut1,acl_type='ipv6', rule_name=data.ipv6_permit_acl, rule_seq='10', packet_action='permit',table_name=data.ipv6_permit_acl,
                           src_ip=data.d1tg_ipv6_list[1]+v6_str, dst_ip=data.d2tg_ipv6_list[1]+v6_str,host_1= 'host',host_2='host',l4_protocol='ipv6')
        acl_api.create_acl_rule(data.dut1,acl_type='ipv6', rule_name=data.ipv6_deny_acl, rule_seq='10', packet_action='deny',table_name=data.ipv6_deny_acl,
                           src_ip=data.d1tg_ipv6_list[1]+v6_str, dst_ip=data.d2tg_ipv6_list[1]+v6_str,host_1= 'host',host_2='host',l4_protocol='ipv6')
        acl_api.create_acl_rule(data.dut1,acl_type='ipv6', rule_name=data.ipv6_deny_acl, rule_seq='20', packet_action='permit',table_name=data.ipv6_deny_acl,
                            src_ip='1111::3'+v6_str, dst_ip='any',host_1= 'host',l4_protocol='ipv6')


        ###############################################
        st.banner("Configure mac access-lists with ethertype ip and ipv6")
        ###############################################
        acl_api.create_acl_table(data.dut1, name=data.acl_l2, stage='INGRESS', type='mac', ports=[])
        acl_api.create_acl_rule(data.dut1,acl_type='mac',rule_name=data.acl_l2,rule_seq='10',packet_action='permit',table_name=data.acl_l2,
                                src_mac=data.src_mac[data.tgd1_handles[0]]+'/')

    else:
        ###############################################
        st.banner("Delete all IP/IPv6 access-lists")
        ###############################################
        acl_api.delete_acl_table(data.dut1,acl_table_name=data.ip_permit_acl,acl_type='ip')
        acl_api.delete_acl_table(data.dut1, acl_table_name=data.ipv6_permit_acl, acl_type='ipv6')
        acl_api.delete_acl_table(data.dut1, acl_table_name=data.ip_deny_acl, acl_type='ip')
        acl_api.delete_acl_table(data.dut1, acl_table_name=data.ipv6_deny_acl, acl_type='ipv6')
        acl_api.delete_acl_table(data.dut1, acl_table_name=data.acl_l2, acl_type='mac')

def classifier_config_base(config='yes'):
    if config =='yes':
        ###############################################
        st.banner("Configure Classifiers for ip/ipv6 for permit acl")
        ###############################################
        acl_dscp_api.config_classifier_table(data.dut1,enable='create',class_name=data.class_permit_ip,match_type='acl',
                                             class_criteria='acl',criteria_value=data.ip_permit_acl,acl_type='ip')
        acl_dscp_api.config_classifier_table(data.dut1,enable='create',class_name=data.class_permit_ipv6,match_type='acl',
                                             class_criteria='acl',criteria_value=data.ipv6_permit_acl,acl_type='ipv6')
        ###############################################
        st.banner("Configure Classifiers for ip/ipv6 for deny acl")
        ###############################################
        acl_dscp_api.config_classifier_table(data.dut1,enable='create',class_name=data.class_deny_ip,match_type='acl',
                                             class_criteria='acl',criteria_value=data.ip_deny_acl,acl_type='ip')
        acl_dscp_api.config_classifier_table(data.dut1,enable='create',class_name=data.class_deny_ipv6,match_type='acl',
                                             class_criteria='acl',criteria_value=data.ipv6_deny_acl,acl_type='ipv6')

        ###############################################
        st.banner("Configure Classifiers with multiple match fields for ip/ipv6")
        ###############################################
        acl_dscp_api.config_classifier_table(data.dut1,enable='create',class_name=data.class_fields_tcp_ip,match_type='fields',
                                             class_criteria=['--src-ip','--dst-ip','--ip-proto',
                                                             '--src-port','--dst-port','--tcp-flags'],
                                             criteria_value=[data.d1tg_ip_list[1],
                                                             data.d2tg_ip_list[1],'tcp',data.src_tcp,data.dst_tcp,'syn not-psh'])
        acl_dscp_api.config_classifier_table(data.dut1,enable='create',class_name=data.class_fields_udp_ip,match_type='fields',
                                             class_criteria=['--src-ip','--dst-ip','--ip-proto',
                                                             '--src-port','--dst-port'],
                                             criteria_value=[data.d1tg_ip_list[1],
                                                             data.d2tg_ip_list[1],'udp',data.src_udp,data.dst_udp])
        acl_dscp_api.config_classifier_table(data.dut1,enable='create',class_name=data.class_fields_tcp_ipv6,match_type='fields',
                                             class_criteria=['--src-ipv6','--dst-ipv6','--ip-proto',
                                                             '--src-port','--dst-port','--tcp-flags'],
                                             criteria_value=[data.d1tg_ipv6_list[1],
                                                             data.d2tg_ipv6_list[1],'tcp',data.src_tcp,data.dst_tcp,'syn not-psh'])
        acl_dscp_api.config_classifier_table(data.dut1,enable='create',class_name=data.class_fields_udp_ipv6,match_type='fields',
                                             class_criteria=['--src-ipv6','--dst-ipv6','--ip-proto',
                                                             '--src-port','--dst-port'],
                                             criteria_value=[data.d1tg_ipv6_list[1],
                                                             data.d2tg_ipv6_list[1],'udp',data.src_udp,data.dst_udp])
        ###############################################
        st.banner("Configure Classifiers with l2 access-list and fields type")
        ###############################################
        acl_dscp_api.config_classifier_table(data.dut1,enable='create',class_name=data.class_l2_acl,match_type='acl',
                                             class_criteria='acl',criteria_value=data.acl_l2,acl_type='mac')
        acl_dscp_api.config_classifier_table(data.dut1,enable='create',class_name=data.class_l2_fields,match_type='fields',
                                             class_criteria=['--src-mac'],criteria_value=[data.src_mac[data.tgd1_handles[0]]])


    else:
        ###############################################
        st.banner("Delete Classifiers")
        ###############################################
        acl_dscp_api.config_classifier_table(data.dut1,enable='del',class_name=data.class_permit_ip,match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut1, enable='del', class_name=data.class_permit_ipv6, match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut1, enable='del', class_name=data.class_deny_ip, match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut1, enable='del', class_name=data.class_deny_ipv6, match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut1, enable='del', class_name=data.class_l2_acl, match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut1, enable='del', class_name=data.class_fields_tcp_ip, match_type='fields')
        acl_dscp_api.config_classifier_table(data.dut1, enable='del', class_name=data.class_fields_tcp_ipv6, match_type='fields')
        acl_dscp_api.config_classifier_table(data.dut1, enable='del', class_name=data.class_fields_udp_ip, match_type='fields')
        acl_dscp_api.config_classifier_table(data.dut1, enable='del', class_name=data.class_fields_udp_ipv6, match_type='fields')
        acl_dscp_api.config_classifier_table(data.dut1, enable='del', class_name=data.class_l2_fields, match_type='fields')


def policy_config_base(config='yes'):
    if config =='yes':
        ###############################################
        st.banner("Configure policy map with ip and ipv6 flows for interface level")
        ###############################################
        acl_dscp_api.config_flow_update_table(data.dut1,flow='add',policy_name=data.policy_class_port,policy_type='forwarding',
                                              class_name=data.class_permit_ip,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.vlan_ip_list[1],data.phy_ip_list[1]],
                                              vrf_name=[data.access_vrf,data.phy_vrf],
                                              next_hop_priority=[30,20])
        acl_dscp_api.config_flow_update_table(data.dut1,flow='update', policy_name=data.policy_class_port, policy_type='forwarding',
                                              class_name=data.class_permit_ip,priority_option='interface',set_interface='null')
        acl_dscp_api.config_flow_update_table(data.dut1,flow='add',policy_name=data.policy_class_port,policy_type='forwarding',
                                              class_name=data.class_permit_ipv6,flow_priority=20,priority_option='next-hop',
                                              next_hop=[data.vlan_ipv6_list[1],data.phy_ipv6_list[1],data.lag_ipv6_list[1]],
                                              vrf_name=[data.access_vrf,data.phy_vrf],
                                              next_hop_priority=[40,30],version='ipv6')
        acl_dscp_api.config_flow_update_table(data.dut1,flow='update', policy_name=data.policy_class_port, policy_type='forwarding',
                                              class_name=data.class_permit_ipv6,
                                              priority_option='interface', set_interface='null')

        ###############################################
        st.banner("Configure policy map with ip and ipv6 flows for vlan level")
        ###############################################
        acl_dscp_api.config_flow_update_table(data.dut1,flow='add',policy_name=data.policy_class_vlan,policy_type='forwarding',
                                              class_name=data.class_permit_ip,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.phy_ip_list[1],data.lag_ip_list[1]],
                                              vrf_name=[data.phy_vrf,''],
                                              next_hop_priority=[30,20])
        acl_dscp_api.config_flow_update_table(data.dut1,flow='update', policy_name=data.policy_class_vlan, policy_type='forwarding',
                                              class_name=data.class_permit_ip,
                                              priority_option='interface', set_interface='null')
        acl_dscp_api.config_flow_update_table(data.dut1,flow='add',policy_name=data.policy_class_vlan,policy_type='forwarding',
                                              class_name=data.class_permit_ipv6,flow_priority=20,priority_option='next-hop',
                                              next_hop=[data.phy_ipv6_list[1],data.lag_ipv6_list[1]],
                                              vrf_name=[data.phy_vrf,''],
                                              next_hop_priority=[40,30,20],version='ipv6')
        acl_dscp_api.config_flow_update_table(data.dut1,flow='update',policy_name=data.policy_class_vlan, policy_type='forwarding',
                                              class_name=data.class_permit_ipv6,
                                              priority_option='interface', set_interface='null')
        ###############################################
        st.banner("Configure poliy map with ip and ipv6 flows for global level")
        ###############################################
        acl_dscp_api.config_flow_update_table(data.dut1,flow='add',policy_name=data.policy_class_global,policy_type='forwarding',
                                              class_name=data.class_permit_ip,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.vlan_ip_list[1],data.lag_ip_list[1]],
                                              vrf_name=[data.access_vrf,''],
                                              next_hop_priority=[30,20])
        acl_dscp_api.config_flow_update_table(data.dut1,flow='update', policy_name=data.policy_class_global, policy_type='forwarding',
                                              class_name=data.class_permit_ip,
                                              priority_option='interface', set_interface='null')
        acl_dscp_api.config_flow_update_table(data.dut1,flow='add',policy_name=data.policy_class_global,policy_type='forwarding',
                                              class_name=data.class_permit_ipv6,flow_priority=20,priority_option='next-hop',
                                              next_hop=[data.vlan_ipv6_list[1],data.lag_ipv6_list[1]],
                                              vrf_name=[data.access_vrf,''],
                                              next_hop_priority=[40,30],version='ipv6')
        acl_dscp_api.config_flow_update_table(data.dut1,flow='update', policy_name=data.policy_class_global, policy_type='forwarding',
                                              class_name=data.class_permit_ipv6,
                                              priority_option='interface', set_interface='null')
        ####################################################
        st.banner("Configure policy map with deny ip/ipv6 flows")
        ####################################################
        acl_dscp_api.config_flow_update_table(data.dut1,flow='add',policy_name=data.policy_class_deny,policy_type='forwarding',
                                              class_name=data.class_deny_ip,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.vlan_ip_list[1]],
                                              vrf_name=[data.access_vrf],
                                              next_hop_priority=[30])
        acl_dscp_api.config_flow_update_table(data.dut1,flow='add',policy_name=data.policy_class_deny,policy_type='forwarding',
                                              class_name=data.class_deny_ipv6,flow_priority=20,priority_option='next-hop',
                                              next_hop=[data.vlan_ipv6_list[1]],
                                              vrf_name=[data.access_vrf],
                                              next_hop_priority=[40],version='ipv6')
        ####################################################
        st.banner("Configure policy map with fields based classifiers for TCP based")
        ####################################################
        acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name=data.policy_class_fields_tcp,
                                              policy_type='forwarding',
                                              class_name=data.class_fields_tcp_ip, flow_priority=10, priority_option='next-hop',
                                              next_hop=[data.vlan_ip_list[1], data.phy_ip_list[1]],
                                              vrf_name=[data.access_vrf, data.phy_vrf],
                                              next_hop_priority=[30, 20])
        acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name=data.policy_class_fields_tcp,
                                              policy_type='forwarding',
                                              class_name=data.class_fields_tcp_ipv6, flow_priority=20, priority_option='next-hop',
                                              next_hop=[data.vlan_ipv6_list[1], data.phy_ipv6_list[1]],
                                              vrf_name=[data.access_vrf, data.phy_vrf],
                                              next_hop_priority=[40, 30], version='ipv6')
        ####################################################
        st.banner("Configure policy map with fields based classifiers for UDP based")
        ####################################################
        acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name=data.policy_class_fields_udp,
                                              policy_type='forwarding',
                                              class_name=data.class_fields_udp_ip, flow_priority=10, priority_option='next-hop',
                                              next_hop=[data.vlan_ip_list[1], data.phy_ip_list[1]],
                                              vrf_name=[data.access_vrf, data.phy_vrf])
        acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name=data.policy_class_fields_udp,
                                              policy_type='forwarding',
                                              class_name=data.class_fields_udp_ipv6, flow_priority=20, priority_option='next-hop',
                                              next_hop=[data.vlan_ipv6_list[1], data.phy_ipv6_list[1]],
                                              vrf_name=[data.access_vrf, data.phy_vrf], version='ipv6')
        #######################################################
        st.banner("Configure VRF test policy and qod/monitoring policy")
        #######################################################
        acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name='policy_vrf',
                                              policy_type='forwarding',
                                              class_name=data.class_permit_ip, flow_priority=10,
                                              priority_option='next-hop',
                                              next_hop=[data.lag_ip_list[1], data.vlan_ip_list[1], data.phy_ip_list[1]],
                                              vrf_name=['default', data.access_vrf, ''],
                                              next_hop_priority=[30, 20, 10])
        acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name='policy_vrf',
                                              policy_type='forwarding',
                                              class_name=data.class_permit_ipv6, flow_priority=10,
                                              priority_option='next-hop',
                                              next_hop=[data.lag_ipv6_list[1], data.vlan_ipv6_list[1],
                                                        data.phy_ipv6_list[1]],
                                              vrf_name=['default', data.access_vrf, ''],
                                              next_hop_priority=[40, 30, 20], version='ipv6')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name='policy_qos',
                                              policy_type='qos',
                                              class_name=data.class_permit_ip, flow_priority=10,
                                              priority_option='--police',
                                              cir=300000000, cbs=300000000, pir=300000000, pbs=300000000)
        acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name='policy_qos',
                                              policy_type='qos',
                                              class_name=data.class_permit_ipv6, flow_priority=10,
                                              priority_option='--police',
                                              cir=300000000, cbs=300000000, pir=300000000, pbs=300000000)

        acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name='policy_monitoring',
                                              policy_type='monitoring',
                                              class_name=data.class_permit_ip, flow_priority=10)
        acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name='policy_monitoring',
                                              policy_type='monitoring',
                                              class_name=data.class_permit_ipv6, flow_priority=10)

        ####################################################
        st.banner("Configure policy map mapping L2 acl and L2 classifier fields")
        ####################################################
        acl_dscp_api.config_flow_update_table(data.dut1,flow='add',policy_name=data.policy_l2_acl,policy_type='forwarding',
                                              class_name=data.class_l2_acl,flow_priority=10,priority_option='interface',
                                              set_interface=data.lag_intf)
        acl_dscp_api.config_flow_update_table(data.dut1,flow='add',policy_name=data.policy_l2_fields,policy_type='forwarding',
                                              class_name=data.class_l2_fields,flow_priority=10,priority_option='interface',
                                              set_interface=data.d1tg_ports[1])

    else:
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_class_port,
                                              class_name=data.class_permit_ip, policy_type='forwarding')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_class_port,
                                              class_name=data.class_permit_ipv6, policy_type='forwarding')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_class_vlan,
                                              class_name=data.class_permit_ip, policy_type='forwarding')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_class_vlan,
                                              class_name=data.class_permit_ipv6, policy_type='forwarding')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_class_global,
                                              class_name=data.class_permit_ip, policy_type='forwarding')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_class_global,
                                              class_name=data.class_permit_ipv6, policy_type='forwarding')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_class_deny,
                                              class_name=data.class_deny_ip, policy_type='forwarding')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_class_deny,
                                              class_name=data.class_deny_ipv6, policy_type='forwarding')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_class_fields_tcp,
                                              class_name=data.class_fields_tcp_ip, policy_type='forwarding')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_class_fields_tcp,
                                              class_name=data.class_fields_tcp_ipv6, policy_type='forwarding')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_class_fields_udp,
                                              class_name=data.class_fields_udp_ip, policy_type='forwarding')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_class_fields_udp,
                                              class_name=data.class_fields_udp_ipv6, policy_type='forwarding')

        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name='policy_vrf',
                                              class_name=data.class_permit_ip, policy_type='forwarding')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name='policy_vrf',
                                              class_name=data.class_permit_ipv6, policy_type='forwarding')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name='policy_qos',
                                              class_name=data.class_permit_ip, policy_type='qos')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name='policy_qos',
                                              class_name=data.class_permit_ipv6, policy_type='qos')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name='policy_monitoring',
                                              class_name=data.class_permit_ip, policy_type='monitoring')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name='policy_monitoring',
                                              class_name=data.class_permit_ipv6, policy_type='monitoring')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_l2_acl,
                                              class_name=data.class_l2_acl, policy_type='forwarding')
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_l2_fields,
                                              class_name=data.class_l2_fields, policy_type='forwarding')
        acl_dscp_api.config_policy_table(data.dut1,enable='del',policy_name=data.policy_class_port)
        acl_dscp_api.config_policy_table(data.dut1, enable='del', policy_name=data.policy_class_vlan)
        acl_dscp_api.config_policy_table(data.dut1, enable='del', policy_name=data.policy_class_global)
        acl_dscp_api.config_policy_table(data.dut1, enable='del', policy_name=data.policy_class_deny)
        acl_dscp_api.config_policy_table(data.dut1, enable='del', policy_name=data.policy_class_fields_tcp)
        acl_dscp_api.config_policy_table(data.dut1, enable='del', policy_name=data.policy_class_fields_udp)
        acl_dscp_api.config_policy_table(data.dut1, enable='del', policy_name='policy_vrf')
        acl_dscp_api.config_policy_table(data.dut1, enable='del', policy_name='policy_qos')
        acl_dscp_api.config_policy_table(data.dut1, enable='del', policy_name='policy_monitoring')
        acl_dscp_api.config_policy_table(data.dut1, enable='del', policy_name=data.policy_l2_acl)
        acl_dscp_api.config_policy_table(data.dut1, enable='del', policy_name=data.policy_l2_fields)



def verify_base_classifier(match_type='filter'):
    #############################################
    st.banner('Verify all Classifier configs ')
    #############################################
    match_acl = list()
    match_field = list()
    if st.get_ui_type() != 'klish':
        v4_str ='/32'
        v6_str = '/128'
    else:
        v4_str ='';v6_str=''


    for classifier,prio in zip([data.class_permit_ip, data.class_permit_ipv6],[10,20]):
        for policy in [data.policy_class_global, data.policy_class_vlan, data.policy_class_port]:
            match_acl.append({'class_name': classifier, 'match_type': 'acl', 'policy_name': policy, 'priority_val': prio})
    match_acl.append({'class_name': data.class_deny_ip, 'match_type': 'acl', 'policy_name': data.policy_class_deny,
                  'priority_val': '10'})
    match_acl.append({'class_name': data.class_deny_ipv6, 'match_type': 'acl', 'policy_name': data.policy_class_deny,
                  'priority_val': '20'})

    match_field.append(
        {'class_name': data.class_fields_tcp_ip, 'match_type': 'fields', 'policy_name': data.policy_class_fields_tcp,
         'priority_val': '10',
         'ip_protocol_val': 'tcp', 'src_port_val': data.src_tcp, 'dst_port_val': data.dst_tcp,
         'tcp_flags_type': 'syn not-psh',
         'src_ip_val': str(data.d1tg_ip_list[1]+v4_str) ,
         'dst_ip_val': str(data.d2tg_ip_list[1]+v4_str) })

    match_field.append(
        {'class_name': data.class_fields_tcp_ipv6, 'match_type': 'fields', 'policy_name': data.policy_class_fields_tcp,
         'priority_val': '20',
         'ip_protocol_val': 'tcp', 'src_port_val': data.src_tcp, 'dst_port_val': data.dst_tcp,
         'tcp_flags_type': 'syn not-psh',
         'src_ipv6_val': str(data.d1tg_ipv6_list[1]+v6_str),
         'dst_ipv6_val': str(data.d2tg_ipv6_list[1]+v6_str)})

    match_field.append(
        {'class_name': data.class_fields_udp_ip, 'match_type': 'fields', 'policy_name': data.policy_class_fields_udp,
         'priority_val': '10',
         'ip_protocol_val': 'udp', 'src_port_val': data.src_udp, 'dst_port_val': data.dst_udp,
         'src_ip_val': str(data.d1tg_ip_list[1]+v4_str),
         'dst_ip_val': str(data.d2tg_ip_list[1]+v4_str)})

    match_field.append(
        {'class_name': data.class_fields_udp_ipv6, 'match_type': 'fields', 'policy_name': data.policy_class_fields_udp,
         'priority_val': '20',
         'ip_protocol_val': 'udp', 'src_port_val': data.src_udp, 'dst_port_val': data.dst_udp,
         'src_ipv6_val': str(data.d1tg_ipv6_list[1]+v6_str),
         'dst_ipv6_val': str(data.d2tg_ipv6_list[1]+v6_str)})

    match = match_acl + match_field

    if match_type != 'filter':
        result = acl_dscp_api.verify(data.dut1,'classifier',verify_list=match)
        if not result:
            failMsg('Classifier verification failed')
            return False
    else:
        result = acl_dscp_api.verify(data.dut1,match_type='acl',verify_list=match_acl)
        if not result:
            failMsg('Classifier verification failed for acl type ')
            return False
        result = acl_dscp_api.verify(data.dut1,match_type='fields',verify_list=match_field)
        if not result:
            failMsg('Classifier verification failed for field type ')
            return False

    return True

def verify_base_policy(match_type='all'):
    #############################################
    st.banner('Verify all Policy configs ')
    #############################################

    match_port = [{'policy_name':data.policy_class_port,'policy_type':'forwarding','class_name':data.class_permit_ip,
               'next_hop':data.vlan_ip_list[1],'next_hop_vrf':data.access_vrf},
                  {'policy_name':data.policy_class_port,'policy_type':'forwarding','class_name':data.class_permit_ip,
               'next_hop':data.phy_ip_list[1],'next_hop_vrf':data.phy_vrf},
                  {'policy_name':data.policy_class_port,'policy_type':'forwarding','class_name':data.class_permit_ip,
               'next_hop_interface':'null'},
                  {'policy_name':data.policy_class_port,'policy_type':'forwarding','class_name':data.class_permit_ipv6,
               'next_hop':data.vlan_ipv6_list[1],'next_hop_vrf':data.access_vrf},
                  {'policy_name':data.policy_class_port,'policy_type':'forwarding','class_name':data.class_permit_ipv6,
               'next_hop':data.phy_ipv6_list[1],'next_hop_vrf':data.phy_vrf},
                  {'policy_name':data.policy_class_port,'policy_type':'forwarding','class_name':data.class_permit_ipv6,
               'next_hop_interface':'null'}]

    match_vlan = [{'policy_name':data.policy_class_vlan,'policy_type':'forwarding','class_name':data.class_permit_ip,
               'next_hop':data.phy_ip_list[1],'next_hop_vrf':data.phy_vrf},
                  {'policy_name':data.policy_class_vlan,'policy_type':'forwarding','class_name':data.class_permit_ip,
               'next_hop':data.lag_ip_list[1],'next_hop_vrf':''},
                  {'policy_name':data.policy_class_vlan,'policy_type':'forwarding','class_name':data.class_permit_ip,
               'next_hop_interface':'null'},
                  {'policy_name':data.policy_class_vlan,'policy_type':'forwarding','class_name':data.class_permit_ipv6,
               'next_hop':data.phy_ipv6_list[1],'next_hop_vrf':data.phy_vrf},
                  {'policy_name':data.policy_class_vlan,'policy_type':'forwarding','class_name':data.class_permit_ipv6,
               'next_hop':data.lag_ipv6_list[1],'next_hop_vrf':''},
                  {'policy_name':data.policy_class_vlan,'policy_type':'forwarding','class_name':data.class_permit_ipv6,
               'next_hop_interface':'null'}]

    match_global = [{'policy_name':data.policy_class_global,'policy_type':'forwarding','class_name':data.class_permit_ip,
               'next_hop':data.vlan_ip_list[1],'next_hop_vrf':data.access_vrf},
                  {'policy_name':data.policy_class_global,'policy_type':'forwarding','class_name':data.class_permit_ip,
               'next_hop':data.lag_ip_list[1],'next_hop_vrf':''},
                  {'policy_name':data.policy_class_global,'policy_type':'forwarding','class_name':data.class_permit_ip,
               'next_hop_interface':'null'},
                  {'policy_name':data.policy_class_global,'policy_type':'forwarding','class_name':data.class_permit_ipv6,
               'next_hop':data.vlan_ipv6_list[1],'next_hop_vrf':data.access_vrf},
                  {'policy_name':data.policy_class_global,'policy_type':'forwarding','class_name':data.class_permit_ipv6,
               'next_hop':data.lag_ipv6_list[1],'next_hop_vrf':''},
                  {'policy_name':data.policy_class_global,'policy_type':'forwarding','class_name':data.class_permit_ipv6,
               'next_hop_interface':'null'}]

    match_tcp =[{'policy_name':data.policy_class_fields_tcp,'policy_type':'forwarding','class_name':data.class_fields_tcp_ip,
               'next_hop':data.vlan_ip_list[1],'next_hop_vrf':data.access_vrf},
                  {'policy_name':data.policy_class_fields_tcp,'policy_type':'forwarding','class_name':data.class_fields_tcp_ip,
               'next_hop':data.phy_ip_list[1],'next_hop_vrf':data.phy_vrf},
                  {'policy_name':data.policy_class_fields_tcp,'policy_type':'forwarding','class_name':data.class_fields_tcp_ipv6,
               'next_hop':data.vlan_ipv6_list[1],'next_hop_vrf':data.access_vrf},
                  {'policy_name':data.policy_class_fields_tcp,'policy_type':'forwarding','class_name':data.class_fields_tcp_ipv6,
               'next_hop':data.phy_ipv6_list[1],'next_hop_vrf':data.phy_vrf}]

    match_udp =[{'policy_name':data.policy_class_fields_udp,'policy_type':'forwarding','class_name':data.class_fields_udp_ip,
               'next_hop':data.vlan_ip_list[1],'next_hop_vrf':data.access_vrf},
                  {'policy_name':data.policy_class_fields_udp,'policy_type':'forwarding','class_name':data.class_fields_udp_ip,
               'next_hop':data.phy_ip_list[1],'next_hop_vrf':data.phy_vrf},
                  {'policy_name':data.policy_class_fields_udp,'policy_type':'forwarding','class_name':data.class_fields_udp_ipv6,
               'next_hop':data.vlan_ipv6_list[1],'next_hop_vrf':data.access_vrf},
                  {'policy_name':data.policy_class_fields_udp,'policy_type':'forwarding','class_name':data.class_fields_udp_ipv6,
               'next_hop':data.phy_ipv6_list[1],'next_hop_vrf':data.phy_vrf}]

    match_deny=[{'policy_name':data.policy_class_deny,'policy_type':'forwarding','class_name':data.class_deny_ip,
               'next_hop':data.vlan_ip_list[1],'next_hop_vrf':data.access_vrf},
                  {'policy_name':data.policy_class_deny,'policy_type':'forwarding','class_name':data.class_deny_ipv6,
               'next_hop':data.vlan_ipv6_list[1],'next_hop_vrf':data.access_vrf}]

    match = match_port + match_vlan + match_global + match_tcp + match_udp + match_deny
    if match_type == 'all':
        result = acl_dscp_api.verify(data.dut1, 'policy', verify_list=match)
        if not result:
            failMsg('Policy verification failed')
            return False
    else:
        for match_list in [match_port,match_vlan,match_global,match_tcp,match_udp,match_deny]:
            result = acl_dscp_api.verify(data.dut1, verify_list=match_list,policy_name=match_list[0]['policy_name'])
            if not result:
                failMsg('Policy verification failed')
                return False


    return True




def config_ospf(config='yes'):
    if config == 'yes':
        #################################################
        st.banner("Configure OSPF neighbors between D1 and D2")
        #################################################
        for vrf in data.vrf_list:
            dict1 = {'router_id': data.d1_router_id,'vrf':vrf}
            dict2 = {'router_id': data.d2_router_id,'vrf':vrf}
            parallel.exec_parallel(True, [data.dut1,data.dut2], ospf_api.config_ospf_router_id, [dict1, dict2])

        dict1 = {'interfaces':[data.lag_vlan_intf,data.access_vlan_intf,data.d1d2_ports[3]],'ospf_area':'0.0.0.0'}
        dict2 = {'interfaces': [data.lag_vlan_intf, data.access_vlan_intf, data.d2d1_ports[3]], 'ospf_area': '0.0.0.0'}
        parallel.exec_parallel(True,[data.dut1,data.dut2],ospf_api.config_interface_ip_ospf_area,[dict1,dict2])

    else:
        ######################################
        st.banner("Remove OSPF config")
        ######################################
        for vrf in data.vrf_list:
            dict1 = {'config':'no','vrf':vrf}
            parallel.exec_parallel(True,[data.dut1,data.dut2],ospf_api.config_ospf_router,[dict1]*2)


def verify_ospf():
    ###############################################
    st.banner("Verify OSPF session comes up")
    ###############################################

    result = retry_api(ospf_api.verify_ospf_neighbor_state, data.dut1, ospf_links = [data.lag_vlan_intf],
                       states = ['Full'],vrf='default',retry_count=6,delay=10)
    if not result:
        failMsg("OSPF session did not come up on Default Vrf")
        return False

    result = retry_api(ospf_api.verify_ospf_neighbor_state, data.dut1, ospf_links = [data.access_vlan_intf],
                       states = ['Full'],vrf=data.access_vrf,retry_count=6,delay=10)
    if not result:
        failMsg("OSPF session did not come up on {}".format(data.access_vrf))
        return False

    result = retry_api(ospf_api.verify_ospf_neighbor_state, data.dut1, ospf_links = [data.d1d2_ports[3]],
                       states = ['Full'],vrf=data.phy_vrf,retry_count=6,delay=10)
    if not result:
        failMsg("OSPF session did not come up on {}".format(data.phy_vrf))
        return False

    return True


def advertise_ospf_routes(config='yes'):
    config_str = 'Advertise' if config == 'yes' else 'Withdraw'
    #################################################
    st.banner("{}  OSPF routes from D2".format(config_str))
    #################################################
    ospf_api.redistribute_into_ospf(data.dut2, 'connected',config=config)
    ospf_api.redistribute_into_ospf(data.dut2, 'static', config=config,vrf_name=data.access_vrf)
    ospf_api.redistribute_into_ospf(data.dut2, 'static', config=config,vrf_name=data.phy_vrf)


def config_static_routes(config='yes'):
    config_str = 'Add' if config == 'yes' else 'Remove'
    #################################################
    st.banner("{} static route to destination nw on D1".format(config_str))
    #################################################
    if config == 'yes':
        ip_api.create_static_route(data.dut1,static_ip="{}/{}".format(data.dest_ip_nw,data.mask_v4),next_hop=data.lag_ip_list[1])
        ip_api.create_static_route_nexthop_vrf(data.dut1, next_hop=data.access_vlan_intf,static_ip='{}/{}'.format(data.dest_ip_nw,data.mask_v4),
                                               vrf_name=data.access_vrf, config='yes')
        ip_api.create_static_route_nexthop_vrf(data.dut1, next_hop=data.d1d2_ports[3],
                                               static_ip='{}/{}'.format(data.dest_ip_nw, data.mask_v4),
                                               vrf_name=data.phy_vrf, config='yes')
        ip_api.create_static_route(data.dut1, static_ip="{}/{}".format(data.dest_ipv6_nw,data.mask_v6), next_hop=data.lag_ipv6_list[1],family='ipv6')
        ip_api.create_static_route_nexthop_vrf(data.dut1, next_hop=data.access_vlan_intf,static_ip='{}/{}'.format(data.dest_ipv6_nw,data.mask_v6),
                                               vrf_name=data.access_vrf, config='yes',family='ipv6')
        ip_api.create_static_route_nexthop_vrf(data.dut1, next_hop=data.d1d2_ports[3],
                                               static_ip='{}/{}'.format(data.dest_ipv6_nw, data.mask_v6),
                                               vrf_name=data.phy_vrf, config='yes',family='ipv6')
    else:
        ip_api.delete_static_route(data.dut1,static_ip="{}/{}".format(data.dest_ip_nw,data.mask_v4),next_hop=data.lag_ip_list[1])
        ip_api.create_static_route_nexthop_vrf(data.dut1, next_hop=data.access_vlan_intf,static_ip='{}/{}'.format(data.dest_ip_nw,data.mask_v4),
                                               vrf_name=data.access_vrf, config='no')
        ip_api.create_static_route_nexthop_vrf(data.dut1, next_hop=data.d1d2_ports[3],
                                               static_ip='{}/{}'.format(data.dest_ip_nw, data.mask_v4),
                                               vrf_name=data.phy_vrf, config='no')
        ip_api.delete_static_route(data.dut1, static_ip="{}/{}".format(data.dest_ipv6_nw,data.mask_v6), next_hop=data.lag_ipv6_list[1],family='ipv6')
        ip_api.create_static_route_nexthop_vrf(data.dut1, next_hop=data.access_vlan_intf,static_ip='{}/{}'.format(data.dest_ipv6_nw,data.mask_v6),
                                               vrf_name=data.access_vrf, config='no',family='ipv6')
        ip_api.create_static_route_nexthop_vrf(data.dut1, next_hop=data.d1d2_ports[3],
                                               static_ip='{}/{}'.format(data.dest_ipv6_nw, data.mask_v6),
                                               vrf_name=data.phy_vrf, config='no',family='ipv6')

def config_static_leak_dut2(config='yes'):
    #########################################################
    st.banner('Configure Static route leak on D2 to each destination prefixes from D1')
    #########################################################
    for vrf in [data.phy_vrf,data.access_vrf]:
        ip_api.create_static_route_nexthop_vrf(data.dut2, next_hop= data.d2tg_ip_list[1],static_ip='{}/{}'.format(data.dest_ip_nw,data.mask_v4),vrf_name=vrf,
                                           nhopvrf="default", config=config)
    for vrf in [data.phy_vrf,data.access_vrf]:
        ip_api.create_static_route_nexthop_vrf(data.dut2,next_hop= data.d2tg_ipv6_list[1], static_ip='{}/{}'.format(data.dest_ipv6_nw,data.mask_v6),vrf_name=vrf,
                                           nhopvrf="default", family='ipv6',config=config)


def config_static_arp(config='yes'):
    if config == 'yes':
        arp.add_static_arp(data.dut2, data.d2tg_ip_list[1], data.src_mac[data.tgd2_handles[0]], interface=data.d2tg_ports[0])
        arp.config_static_ndp(data.dut2,data.d2tg_ipv6_list[1],data.src_mac[data.tgd2_handles[0]],data.d2tg_ports[0],operation="add")
    else:
        arp.delete_static_arp(data.dut2, data.d2tg_ip_list[1])
        arp.config_static_ndp(data.dut2, data.d2tg_ipv6_list[1], data.src_mac[data.tgd2_handles[0]], data.d2tg_ports[0],
                              operation="del")



def verify_next_hop_protocol(type='static'):
    if type == 'bgp': route_type='B'
    if type == 'ospf': route_type = 'O'
    if type == 'static': route_type = 'S'
    if type == 'ospf':
        verify_ospf()
    result = retry_api(ip_api.verify_ip_route,data.dut1, ip_address='{}/{}'.format(data.dest_ip_nw,data.mask_v4), interface=data.lag_vlan_intf, type=route_type,delay=2)
    if not result:
        failMsg('Next-hop protocol verification Failed for {}'.format(type))
        return False
    if type != 'ospf':
        result = retry_api(ip_api.verify_ip_route,data.dut1, ip_address='{}/{}'.format(data.dest_ipv6_nw, data.mask_v6),interface=data.lag_vlan_intf,type=route_type, family='ipv6'
                           ,delay=2)
        if not result:
            failMsg('IPV6 Next-hop protocol verification Failed for {}'.format(type))
            return False
    result = retry_api(ip_api.verify_ip_route,data.dut1, ip_address='{}/{}'.format(data.dest_ip_nw,data.mask_v4), interface=data.access_vlan_intf, type=route_type,vrf_name=data.access_vrf
                       ,delay=2)
    if not result:
        failMsg('{} Next-hop protocol verification Failed for {}'.format(data.access_vrf,type))
        return False
    if type != 'ospf':
        result = retry_api(ip_api.verify_ip_route,data.dut1, ip_address='{}/{}'.format(data.dest_ipv6_nw, data.mask_v6),interface=data.access_vlan_intf, type=route_type, family='ipv6',vrf_name=data.access_vrf
                           ,delay=2)
        if not result:
            failMsg('{} IPv6 Next-hop protocol verification Failed for {}'.format(data.access_vrf,type))
            return False
    result = retry_api(ip_api.verify_ip_route,data.dut1, ip_address='{}/{}'.format(data.dest_ip_nw,data.mask_v4), interface=data.d1d2_ports[3], type=route_type,vrf_name=data.phy_vrf
                       ,delay=2)
    if not result:
        failMsg('{} Next-hop protocol verification Failed for {}'.format(data.phy_vrf,type))
        return False
    if type != 'ospf':
        result = retry_api(ip_api.verify_ip_route,data.dut1, ip_address='{}/{}'.format(data.dest_ipv6_nw, data.mask_v6),interface=data.d1d2_ports[3], type=route_type, family='ipv6',vrf_name=data.phy_vrf
                           ,delay=2)
        if not result:
            failMsg('{} IPv6 Next-hop protocol verification Failed for {}'.format(data.phy_vrf,type))
            return False

    return True


def advertise_routes(type):
    if type == 'bgp':
        advertise_bgp_routes()
    elif type == 'ospf':
        advertise_ospf_routes()
    else:
        config_static_routes()

def withdraw_routes(type):
    if type == 'bgp':
        advertise_bgp_routes('no')
    elif type == 'ospf':
        advertise_ospf_routes('no')
    else:
        config_static_routes('no')


def verify_pbr_basic_001(type,scope='port',source_vrf='default',verify_null=True,param_dict={},withdraw=True,trigger_test=False,check_counters=True,dut_counters=True,level=2):

    err_list=[]
    tc_result = True
    tc_name = get_tc_name(level);tech_support=True

    class_name_v4 = param_dict.get('class_name_v4',data.class_permit_ip)
    class_name_v6 = param_dict.get('class_name_v6',data.class_permit_ipv6)
    interface = param_dict.get('interface',None)
    policy_name = param_dict.get('policy_name')
    nh_sequence = param_dict['nh_sequence']
    nh_sequence_ipv6 = param_dict['nh_sequence_ipv6']
    nh_vrf_sequence = param_dict['nh_vrf_sequence']
    nh_flap_sequence = param_dict['nh_flap_sequence']

    stream_scope = 'phy' if scope == 'port' else 'vlan_global'
    stream = 'both' if type != 'ospf' else 'ipv4'
    flow_list = [class_name_v4,class_name_v6] if type != 'ospf' else [class_name_v4]


    if not trigger_test:
        advertise_routes(type)
        ######################################
        st.banner('Verify next-hop protocol is {}'.format(type))
        ######################################
        result = verify_next_hop_protocol(type)
        if not result:
            err ='Not all nexthop are of type {}'.format(type)
            failMsg(err,tech_support,tc_name);err_list.append(err);tc_result=False;tech_support=False

        ######################################
        st.banner('Bind service policy to {} level'.format(scope))
        ######################################
        if interface:
            acl_dscp_api.config_service_policy_table(data.dut1,interface_name=interface,service_policy_name=policy_name,
                                                 policy_kind='bind',policy_type='forwarding')
        else:
            acl_dscp_api.config_service_policy_table(data.dut1,service_policy_name=policy_name,
                                                     policy_kind='bind', policy_type='forwarding')


        ######################################
        st.banner('Verify policy got applied as expected at  {} level'.format(scope))
        ######################################
        intf = 'Switch' if scope == 'global' else interface
        match = {'policy_name':policy_name,'policy_type':'forwarding','interface':intf,'stage':'Ingress'}
        result = acl_dscp_api.verify(data.dut1,policy_name=policy_name,verify_list=[match])
        if not result:
            err ='Interface {} not bound to policy'.format(intf)
            failMsg(err,tech_support,tc_name);tech_support=False;err_list.append(err);tc_result=False


        ######################################
        st.banner('Start Traffic')
        ######################################
        run_traffic(action='start',version=stream,scope=stream_scope)
    ######################################
    st.banner('Verify Traffic gets forwarded with service-policy applied to {}'.format(interface))
    ######################################
    result = verify_traffic()
    if not result:
        err ='Traffic dropped with service policy applied at {} level'.format(scope)
        failMsg(err,tech_support,tc_name);tech_support=False;err_list.append(err);tc_result=False

    for nh_ip,nh_ipv6,nh_intf,vrf,iteration in zip(nh_sequence,nh_sequence_ipv6,nh_flap_sequence,nh_vrf_sequence,range(len(nh_flap_sequence))):
        nh_list = [nh_ip,nh_ipv6] if type != 'ospf' else [nh_ip]

        ######################################
        st.banner('Verify {} is selected as nexthop as per applied service policy'.format(nh_list))
        ######################################
        result = verify_selected_next_hop(scope,policy_name,flow_list,nh_list=nh_list,nh_vrf=[vrf]*len(flow_list),interface=interface,check_counters=check_counters)
        if not result:
            err = '{} not selected as nexthop as per seriv policy'.format(nh_list)
            failMsg(err,tech_support,tc_name);tech_support=False;err_list.append(err);tc_result = False
        if dut_counters:
            ######################################
            st.banner('Verify interface counters and check traffic forwarded on correct interface')
            ######################################
            nh = [data.d1d2_ports[0],data.d1d2_ports[1]] if nh_intf == data.lag_intf else [nh_intf]
            result = verify_traffic_counters(nh)
            if not result:
                err = 'Traffic not forwarded via {}'.format(nh_intf)
                failMsg(err, tech_support, tc_name);
                tech_support = False; err_list.append(err);tc_result = False
        if iteration != int(len(nh_flap_sequence)) - 1 or verify_null:
            ######################################
            st.banner('Bring down next-hop and verify next best nexthop is selected')
            ######################################
            port_api.shutdown(data.dut1,[nh_intf])
    if verify_null:
        ######################################
        st.banner('Verify NULL interface selected')
        ######################################
        result = verify_selected_next_hop(scope,policy_name,flow_list,nh_list=['null']*len(flow_list),interface=interface,check_counters=check_counters)
        if not result:
            err ='Null interface not selected'
            failMsg(err,tech_support,tc_name);tech_support=False;err_list.append(err);tc_result=False
            data['FtOpSoRoPbr32313'] = False
        ######################################
        st.banner('Verify traffic gets dropped')
        ######################################
        result = verify_traffic(exp_ratio=0)
        if not result:
            err ='Traffic not dropped with Null interface selected'
            failMsg(err,tech_support,tc_name);tech_support=False;err_list.append(err);tc_result=False
            data['FtOpSoRoPbr32313'] = False
        ######################################
        st.banner('Remove NULL interface from Flows and verify traffic gets forwarded as per routing table')
        ######################################
        for class_name in flow_list:
            acl_dscp_api.config_flow_update_table(data.dut1, flow='update', policy_name=policy_name,
                                              policy_type='forwarding',
                                              class_name=class_name,
                                              priority_option='interface', set_interface='null',config='no')

        result = verify_traffic()
        if not result:
            err ='Traffic not forwarded after removing NULL interface from flow'
            failMsg(err,tech_support,tc_name);tech_support=False;err_list.append(err);tc_result=False
            data['FtOpSoRoPbr32313'] = False
        ######################################
        st.banner('Re-Add NULL interface and verify traffic gets dropped')
        ######################################
        for class_name in flow_list:
            acl_dscp_api.config_flow_update_table(data.dut1, flow='update', policy_name=policy_name,
                                              policy_type='forwarding',
                                              class_name=class_name,
                                              priority_option='interface', set_interface='null')
        result = verify_traffic(exp_ratio=0)
        if not result:
            err ='Traffic not dropped after deleting and adding back NULL interface'
            failMsg(err,tech_support,tc_name);tech_support=False;err_list.append(err);tc_result=False
            data['FtOpSoRoPbr32313'] = False

    ######################################
    st.banner("Bring back all nexthop interfaces")
    ########################################
    port_api.noshutdown(data.dut1, nh_flap_sequence)
    if type == 'ospf': verify_ospf()
    if not trigger_test:
        ######################################
        st.banner('Remove service policy')
        ######################################
        if scope != 'global':
            acl_dscp_api.config_service_policy_table(data.dut1,interface_name=interface,service_policy_name=policy_name,
                                                 policy_kind='unbind',policy_type='forwarding')
        else:
            acl_dscp_api.config_service_policy_table(data.dut1,service_policy_name=policy_name,
                                                     policy_kind='unbind', policy_type='forwarding')
    
        ######################################
        st.banner('Verify Traffic forwarded as per routing table nexthop interface')
        ######################################
        result = verify_traffic()
        if not result:
            err ='Traffic not forwarded as per routing table after unbinding service-policy'
            failMsg(err,tech_support,tc_name);tech_support=False;err_list.append(err);tc_result=False
    
        if source_vrf == 'default':
            nexthop_intf = [data.d1d2_ports[0],data.d1d2_ports[1]]
        elif source_vrf == data.access_vrf:
            nexthop_intf = [data.d1d2_ports[2]]
        else:
            nexthop_intf = [data.d1d2_ports[3]]

        if dut_counters:
            result = verify_traffic_counters(nexthop_intf)
            if not result:
                err ='Traffic not forwarded as per routing table next-hop intf {}'.format(nexthop_intf)
                failMsg(err,tech_support,tc_name);tech_support=False;err_list.append(err);tc_result=False

        run_traffic(action='stop',scope=stream_scope)
        if withdraw:
            withdraw_routes(type)

    if not tc_result:
        return tc_result,err_list[0]

    return True,None


def verify_selected_next_hop(scope,policy,flow_list,nh_list=[],nh_vrf=[],interface='',check_counters=True):
    match_dict_list = []

    if 'null' in nh_list:
        for flow in flow_list:
            match = {'policy_name':policy,'class_name':flow,'next_hop_interface':'null' ,'selected':'Selected','flow_state':'(Active)'}
            match_dict_list.append(match)
    else:
        for flow, nh, vrf in zip(flow_list, nh_list, nh_vrf):
            match = {'policy_name':policy,'class_name':flow,'next_hop':nh,'selected':'Selected','next_hop_vrf':vrf,'flow_state':'(Active)'}
            match_dict_list.append(match)

    if scope != 'global':
        result = retry_api(acl_dscp_api.verify,data.dut1,service_policy_interface=interface,verify_list=match_dict_list,retry_count=5,delay=1)
        if not result:
            failMsg("nexthop Selection check failed")
            return False
    else:
        result = retry_api(acl_dscp_api.verify,data.dut1,service_policy_name=policy,verify_list=match_dict_list,retry_count=5,delay=1)
        if not result:
            failMsg("nexthop Selection check failed")
            return False

    if check_counters:
        result = verify_policy_counters_incrementing(policy,flow_list,interface)
        if not result:
            failMsg("Policy counters verification Failed")
            return False
    return True

def verify_policy_counters_incrementing(policy,flow_list,interface=None,increment=True):
    if interface:
        acl_dscp_api.config_service_policy_table(data.dut1,policy_kind='clear_interface',interface_name=interface,stage='in')
    else:
        acl_dscp_api.config_service_policy_table(data.dut1, policy_kind='clear_policy',service_policy_name=policy)
    ####################################
    st.banner('Verify service policy counters increments')
    ####################################
    packet_count = {}
    match_list = list()
    for flow in flow_list:
        match  ={'policy_name':policy,'class_name':flow}
        match_list.append(match)

    for iteration in range(2):
        iteration = iteration + 1
        if interface:
            output = acl_dscp_api.show(data.dut1,interface_name=interface)
        else:
            output = acl_dscp_api.show(data.dut1, service_policy_name=policy)

        if output:
            for match_1 in match_list:
                entry_v4 = filter_and_select(output,None,match=match_1)
                if entry_v4:
                    packet_count['{}_{}'.format(match_1['class_name'],iteration)] = int(entry_v4[0]['match_pkts_val'])
                    st.log("{} Policy Packet Match Count : {} packets".
                           format(match_1['class_name'],packet_count['{}_{}'.format(match_1['class_name'],iteration)]))
                else:
                    st.error("####### Packet count entry not found     #######")
                    return False
        else:
            st.error("Empty output")
            return False
        if iteration == 1 :
            st.wait(10, 'Wait for fetching packet match count')

    if increment:
        for flow in flow_list:
            if packet_count['{}_2'.format(flow)] == packet_count['{}_1'.format(flow)]:
               st.error("{} policy match counters not incremented".format(flow))
               return False
        st.log('\n>>>>>>>>> Policy Match counters incremented as expected <<<<<<<<<<<\n')
    else:
        for flow in flow_list:
            if packet_count['{}_2'.format(flow)] != packet_count['{}_1'.format(flow)]:
                st.error("{} policy match counters incremented".format(flow))
                return False
    return True


def verify_traffic_counters(nexthop_intf=[]):
    #######################################################
    st.banner("Verify Traffic gets forwarded on nexthop interfaces {}".format(nexthop_intf))
    #######################################################
    ingress_intf = data.d1tg_ports[0]
    intf_api.clear_interface_counters(data.dut1)
    st.wait(3,'wait for traffic counters to stabilise')
    output = intf_api.get_interface_counter_value(data.dut1, [ingress_intf]+ nexthop_intf, ['rx_ok', 'tx_ok'])
    ingress_count = int(output[ingress_intf]['rx_ok'])
    egress_count = 0
    for intf in nexthop_intf: egress_count += int(output[intf]['tx_ok'])
    pkt_diff = abs(ingress_count-egress_count)
    st.log(" Ingress Packet count : {} packets ".format(ingress_count))
    st.log(" Egress Packet count on {} : {} packets ".format(nexthop_intf,egress_count))
    if egress_count < 1000:
        failMsg('Traffic did not forward via nexthop interfaces {}'.format(nexthop_intf))
        return False
    return True


def config_stream(config='yes'):
    if config == 'yes':
        data.tg_d1_dest_mac = str(data.tg_d1_dest_mac)
        data.tg1.tg_traffic_control(action='reset', port_handle=data.tg_handles)
        data.stream_handles = {}
        data.stream_details = {}
        ##########################################################################
        st.banner("TGEN: Configure tagged ipv4 TCP Stream")
        ##########################################################################
        ipv4_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tgd1_handles[0]], mac_dst=data.tg_d1_dest_mac,
                                                 l2_encap='ethernet_ii_vlan',
                                                 vlan="enable", vlan_id=data.d1tg_vlan_id,
                                                 rate_pps=data.traffic_rate, \
                                                 mode='create', port_handle=data.tg_handles[0],
                                                 transmit_mode='continuous',
                                                 l3_protocol='ipv4', ip_src_addr=data.d1tg_ip_list[1] \
                                                 , ip_dst_addr=data.d2tg_ip_list[1], mac_discovery_gw=data.d1tg_ip_list[0],
                                                 l4_protocol='tcp',tcp_src_port=data.src_tcp,tcp_dst_port=data.dst_tcp,tcp_syn_flag=1,
                                                 tcp_psh_flag=0)
        data.stream_handles['pbr_ipv4_tcp_stream'] = ipv4_stream['stream_id']
        data.stream_details[data.stream_handles['pbr_ipv4_tcp_stream']] = "IPv4 traffic session SRC-MAC:{}" \
                                                                           " DEST-MAC:{} VLAN-ID:{} SRC-IP:{} " \
                                                                           " DEST IP:{} " \
                                                                           "Rate:{} fps".format(data.src_mac[data.tgd1_handles[0]],data.tg_d1_dest_mac,
                                                                                                data.d1tg_vlan_id,data.d1tg_ip_list[1],data.d2tg_ip_list[1],
                                                                                                data.traffic_rate)

        ##########################################################################
        st.banner("TGEN: Configure tagged ipv4 UDP Stream")
        ##########################################################################
        ipv4_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tgd1_handles[0]], mac_dst=data.tg_d1_dest_mac,
                                                 l2_encap='ethernet_ii_vlan',
                                                 vlan="enable", vlan_id=data.d1tg_vlan_id,
                                                 rate_pps=data.traffic_rate, \
                                                 mode='create', port_handle=data.tg_handles[0],
                                                 transmit_mode='continuous',
                                                 l3_protocol='ipv4', ip_src_addr=data.d1tg_ip_list[1] \
                                                 , ip_dst_addr=data.d2tg_ip_list[1], mac_discovery_gw=data.d1tg_ip_list[0],
                                                 l4_protocol='udp',udp_src_port=data.src_udp,udp_dst_port=data.dst_udp)
        data.stream_handles['pbr_ipv4_udp_stream'] = ipv4_stream['stream_id']
        data.stream_details[data.stream_handles['pbr_ipv4_udp_stream']] = "IPv4 traffic session SRC-MAC:{}" \
                                                                           " DEST-MAC:{} VLAN-ID:{} SRC-IP:{} " \
                                                                           " DEST IP:{} " \
                                                                           "Rate:{} fps".format(data.src_mac[data.tgd1_handles[0]],data.tg_d1_dest_mac,
                                                                                                data.d1tg_vlan_id,data.d1tg_ip_list[1],data.d2tg_ip_list[1],
                                                                                                data.traffic_rate)



        ##########################################################################
        st.banner("TGEN: Configure tagged ipv6 TCP Stream")
        ##########################################################################
        ipv6_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tgd1_handles[0]], mac_dst=data.tg_d1_dest_mac,
                                                 l2_encap='ethernet_ii_vlan',
                                                 vlan="enable", vlan_id=data.d1tg_vlan_id,
                                                 rate_pps=data.traffic_rate, \
                                                 mode='create', port_handle=data.tg_handles[0],
                                                 transmit_mode='continuous',
                                                 l3_protocol='ipv6', ipv6_src_addr=data.d1tg_ipv6_list[1] \
                                                 , ipv6_dst_addr=data.d2tg_ipv6_list[1], mac_discovery_gw=data.d1tg_ipv6_list[0],
                                                 l4_protocol='tcp',tcp_src_port=data.src_tcp,tcp_dst_port=data.dst_tcp,tcp_syn_flag=1,tcp_psh_flag=0)
        data.stream_handles['pbr_ipv6_tcp_stream'] = ipv6_stream['stream_id']
        data.stream_details[data.stream_handles['pbr_ipv6_tcp_stream']] = "IPv6 traffic session SRC-MAC:{}" \
                                                                           " DEST-MAC:{} VLAN-ID:{} SRC-IP:{} " \
                                                                           " DEST IP:{} " \
                                                                           "Rate:{} fps".format(data.src_mac[data.tgd1_handles[0]],data.tg_d1_dest_mac,
                                                                                                data.d1tg_vlan_id,data.d1tg_ipv6_list[1],data.d2tg_ipv6_list[1],
                                                                                                data.traffic_rate)

        ##########################################################################
        st.banner("TGEN: Configure tagged ipv6 UDP Stream")
        ##########################################################################
        ipv6_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tgd1_handles[0]], mac_dst=data.tg_d1_dest_mac,
                                                 l2_encap='ethernet_ii_vlan',
                                                 vlan="enable", vlan_id=data.d1tg_vlan_id,
                                                 rate_pps=data.traffic_rate, \
                                                 mode='create', port_handle=data.tg_handles[0],
                                                 transmit_mode='continuous',
                                                 l3_protocol='ipv6', ipv6_src_addr=data.d1tg_ipv6_list[1] \
                                                 , ipv6_dst_addr=data.d2tg_ipv6_list[1], mac_discovery_gw=data.d1tg_ipv6_list[0],
                                                 l4_protocol='udp',udp_src_port=data.src_udp,udp_dst_port=data.dst_udp)
        data.stream_handles['pbr_ipv6_udp_stream'] = ipv6_stream['stream_id']
        data.stream_details[data.stream_handles['pbr_ipv6_udp_stream']] = "IPv6 traffic session SRC-MAC:{}" \
                                                                           " DEST-MAC:{} VLAN-ID:{} SRC-IP:{} " \
                                                                           " DEST IP:{} " \
                                                                           "Rate:{} fps".format(data.src_mac[data.tgd1_handles[0]],data.tg_d1_dest_mac,
                                                                                                data.d1tg_vlan_id,data.d1tg_ipv6_list[1],data.d2tg_ipv6_list[1],
                                                                                                data.traffic_rate)


        #########################################################################
        st.banner("Configure TCP streams for phy L3 port")
        #########################################################################

        ipv4_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tgd1_handles[0]], mac_dst=data.tg_d1_dest_mac_phy,
                                                 l2_encap='ethernet_ii',
                                                 rate_pps=data.traffic_rate, \
                                                 mode='create', port_handle=data.tg_handles[0],
                                                 transmit_mode='continuous',
                                                 l3_protocol='ipv4', ip_src_addr=data.d1tg_ip_list[1] \
                                                 , ip_dst_addr=data.d2tg_ip_list[1], mac_discovery_gw=data.d1tg_ip_list[0],
                                                 l4_protocol='tcp',tcp_src_port=data.src_tcp,tcp_dst_port=data.dst_tcp,tcp_syn_flag=1,
                                                 tcp_psh_flag=0)
        data.stream_handles['pbr_ipv4_tcp_stream_phy'] = ipv4_stream['stream_id']
        data.stream_details[data.stream_handles['pbr_ipv4_tcp_stream_phy']] = "IPv4 traffic session SRC-MAC:{}" \
                                                                           " DEST-MAC:{} SRC-IP:{} " \
                                                                           " DEST IP:{} " \
                                                                           "Rate:{} fps".format(data.src_mac[data.tgd1_handles[0]],data.tg_d1_dest_mac_phy,
                                                                                                data.d1tg_ip_list[1],data.d2tg_ip_list[1],
                                                                                                data.traffic_rate)


        ipv6_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tgd1_handles[0]], mac_dst=data.tg_d1_dest_mac_phy,
                                                 l2_encap='ethernet_ii',
                                                 rate_pps=data.traffic_rate, \
                                                 mode='create', port_handle=data.tg_handles[0],
                                                 transmit_mode='continuous',
                                                 l3_protocol='ipv6', ipv6_src_addr=data.d1tg_ipv6_list[1] \
                                                 , ipv6_dst_addr=data.d2tg_ipv6_list[1], mac_discovery_gw=data.d1tg_ipv6_list[0],
                                                 l4_protocol='tcp',tcp_src_port=data.src_tcp,tcp_dst_port=data.dst_tcp,tcp_syn_flag=1,tcp_psh_flag=0)
        data.stream_handles['pbr_ipv6_tcp_stream_phy'] = ipv6_stream['stream_id']
        data.stream_details[data.stream_handles['pbr_ipv6_tcp_stream_phy']] = "IPv6 traffic session SRC-MAC:{}" \
                                                                           " DEST-MAC:{} SRC-IP:{} " \
                                                                           " DEST IP:{} " \
                                                                           "Rate:{} fps".format(data.src_mac[data.tgd1_handles[0]],data.tg_d1_dest_mac_phy,
                                                                                                data.d1tg_ipv6_list[1],data.d2tg_ipv6_list[1],
                                                                                                data.traffic_rate)

        ##########################################################################
        st.banner("TGEN: Configure L2 stream with ipv4 and ipv6 header on D1T1")
        ##########################################################################

        data.l2_streams = []

        ipv4_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tgd1_handles[0]], mac_dst=data.dst_mac_l2,
                                                 l2_encap='ethernet_ii_vlan',
                                                 vlan="enable", vlan_id=data.d1tg_vlan_id,
                                                 rate_pps=data.traffic_rate, \
                                                 mode='create', port_handle=data.tg_handles[0],
                                                 transmit_mode='continuous')
        data.stream_handles['pbr_ipv4_l2_stream'] = ipv4_stream['stream_id']
        data.l2_streams.append(data.stream_handles['pbr_ipv4_l2_stream'])
        data.stream_details[data.stream_handles['pbr_ipv4_l2_stream']] = "IPv4 traffic session SRC-MAC:{}" \
                                                                           " DEST-MAC:{} VLAN-ID:{} " \
                                                                           "Rate:{} fps".format(data.src_mac[data.tgd1_handles[0]],data.tg_d1_dest_mac,
                                                                                                data.d1tg_vlan_id, data.traffic_rate)


        #########################################################
        st.banner("Config L2 Broadcast and Multicast Streams")
        #########################################################

        multicast_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tgd1_handles[0]], mac_dst='01:00:5E:00:00:01',
                                                 l2_encap='ethernet_ii_vlan',
                                                 vlan="enable", vlan_id=data.d1tg_vlan_id,
                                                 rate_pps=data.traffic_rate,
                                                 mode='create', port_handle=data.tg_handles[0],
                                                 transmit_mode='continuous')
        data.stream_handles['multicast'] = multicast_stream['stream_id']

        broadcast_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tgd1_handles[0]],
                                                      mac_dst='FF:FF:FF:FF:FF:FF',
                                                      l2_encap='ethernet_ii_vlan',
                                                      vlan="enable", vlan_id=data.d1tg_vlan_id,
                                                      rate_pps=data.traffic_rate,
                                                      mode='create', port_handle=data.tg_handles[0],
                                                      transmit_mode='continuous')
        data.stream_handles['broadcast'] = broadcast_stream['stream_id']

    else:
        ##########################################################################
        st.banner("TGEN-DeConfig: Delete Traffic Streams on all TG ports ")
        ##########################################################################

        data.tg1.tg_traffic_control(action='reset', port_handle=data.tg_handles)

def run_traffic(action='start',version='both',protocol='tcp',scope='vlan_global'):
    str_append = '_phy' if scope != 'vlan_global' else ''
    if version == 'both':
        stream_handle = [data.stream_handles['pbr_{}_{}_stream{}'.format(version,protocol,str_append)] for version in ['ipv4','ipv6']]
    else:
        stream_handle = [data.stream_handles['pbr_{}_{}_stream{}'.format(version,protocol,str_append)]]

    if action =='start': st.log(" #### Starting Traffic for  streams #####")
    if action == 'stop': st.log(" #### Stopping Traffic for streams  #####")
    for stream in stream_handle:
        st.log("HANDLE :{} ---> {}".format(stream,data.stream_details[stream]))
    if action == 'start':
        data.tg1.tg_traffic_control(action='clear_stats',port_handle=data.tg_handles)
        data.tg1.tg_traffic_control(action='run', stream_handle=stream_handle)
    else:
        data.tg1.tg_traffic_control(action='stop', stream_handle=stream_handle)



def verify_traffic(src_tg_obj=None,dest_tg_obj=None,src_port=None,dest_port=None,exp_ratio=1,comp_type='packet_rate',**kwargs):
    ret_val= True
    if src_tg_obj is None: src_tg_obj = data.tg1
    if dest_tg_obj is None : dest_tg_obj = data.tg2
    if src_port is None : src_port = data.tgd1_ports[0]
    if dest_port is None: dest_port = data.tgd2_ports[0]
    traffic_data = {
        '1': {
            'tx_ports': [src_port] if type(src_port) is str else list(src_port),
            'tx_obj': [src_tg_obj],
            'exp_ratio': [exp_ratio],
            'rx_ports': [dest_port] if type(dest_port) is str else list(dest_port),
            'rx_obj': [dest_tg_obj]
        }
    }
    traffic_data['1']['tx_obj'] = traffic_data['1']['tx_obj']*len(traffic_data['1']['tx_ports'])
    traffic_data['1']['rx_obj'] = traffic_data['1']['rx_obj'] * len(traffic_data['1']['rx_ports'])
    delay = kwargs.pop('delay',data.delay_factor)
    retry_count = kwargs.pop('retry_count',1)
    for iteration in range(retry_count):
        st.log("\n>>>>   ITERATION : {} <<<<<\n".format(iteration+1))
        aggregate_result = validate_tgen_traffic(traffic_details=traffic_data, mode='aggregate', comp_type=comp_type, delay_factor=delay)
        if aggregate_result:
            st.log('Traffic verification passed ')
            ret_val = True
            break
        else:
            ret_val =False
            st.log('Traffic verification Failed ')
            continue
    return ret_val



def retry_api(func,args,**kwargs):
    retry_count = kwargs.get("retry_count", 5)
    delay = kwargs.get("delay", 1)
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


def retry_null_output(func,args,**kwargs):
    retry_count = kwargs.get("retry_count", 5)
    delay = kwargs.get("delay", 1)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if len(func(args,**kwargs)) == 0:
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False

def retry_output_count(func,args,**kwargs):
    retry_count = kwargs.get("retry_count", 5)
    delay = kwargs.get("delay", 1)
    exp_count = kwargs.get("count", data.max_mroutes)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    if 'count' in kwargs: del kwargs['count']
    output = None
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        output = func(args,**kwargs)
        if len(output) == exp_count:
            return True,output
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False,output


def failMsg(msg,tech_support=False,tc_name='',debug=True):
    st.error("\n++++++++++++++++++++++++++++++++++++++++++++++" \
    " \n FAILED : {} \n++++++++++++++++++++++++++++++++++++++++++++++".format(msg))
    if debug:
        debug_pbr_failure()
    if tech_support:
        st.generate_tech_support(dut=None,name=tc_name)


def debug_pbr_failure():
    pass




def pbr_trigger_case():
    tech_support = True
    tc_result=True;err_list=[]
    tc_name = get_tc_name(2)
    if data.scope_trigger =='port':
        scope = 'port';
        mode = 'classifier_fields'
        param_dict = {'interface': data.d1tg_ports[0],
                      'policy_name': data.policy_class_fields_tcp,
                      'class_name_v4': data.class_fields_tcp_ip,
                      'class_name_v6': data.class_fields_tcp_ipv6,
                      'nh_sequence': [data.vlan_ip_list[1], data.phy_ip_list[1]],
                      'nh_sequence_ipv6': [data.vlan_ipv6_list[1], data.phy_ipv6_list[1]],
                      'nh_flap_sequence': [data.d1d2_ports[2], data.d1d2_ports[3]],
                      'nh_vrf_sequence': [data.access_vrf, data.phy_vrf]}

    elif data.scope_trigger == 'vlan':
        scope = 'vlan';
        mode = 'classifier_acl'
        param_dict = {'interface': data.d1tg_vlan_intf,
                      'policy_name': data.policy_class_port,
                      'class_name_v4': data.class_permit_ip,
                      'class_name_v6': data.class_permit_ipv6,
                      'nh_sequence': [data.vlan_ip_list[1], data.phy_ip_list[1]],
                      'nh_sequence_ipv6': [data.vlan_ipv6_list[1], data.phy_ipv6_list[1]],
                      'nh_flap_sequence': [data.d1d2_ports[2], data.d1d2_ports[3]],
                      'nh_vrf_sequence': [data.access_vrf, data.phy_vrf]}
    else:
        scope = 'global';
        mode = 'classifier_fields'
        param_dict = {'interface': None,
                      'policy_name': data.policy_class_fields_tcp,
                      'class_name_v4': data.class_fields_tcp_ip,
                      'class_name_v6': data.class_fields_tcp_ipv6,
                      'nh_sequence': [data.vlan_ip_list[1], data.phy_ip_list[1]],
                      'nh_sequence_ipv6': [data.vlan_ipv6_list[1], data.phy_ipv6_list[1]],
                      'nh_flap_sequence': [data.d1d2_ports[2], data.d1d2_ports[3]],
                      'nh_vrf_sequence': [data.access_vrf, data.phy_vrf]}

    ###################################################################
    st.banner("Bind service policy at {} level with {}".format(scope, mode))
    ###################################################################

    # Verify show policy
    # Verify show classifier
    if param_dict['interface']:
        acl_dscp_api.config_service_policy_table(data.dut1, interface_name=param_dict['interface'],
                                                 service_policy_name=param_dict['policy_name'],
                                                 policy_kind='bind', policy_type='forwarding')

    else:
        acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name=param_dict['policy_name'],
                                                 policy_kind='bind', policy_type='forwarding')

    ###################################################################
    st.banner("Verify Nexthop is selected as per policy map and traffic gets forwarded")
    ###################################################################

    result = verify_selected_next_hop(scope=scope, policy=param_dict['policy_name'],
                                      flow_list=[param_dict['class_name_v4'], param_dict['class_name_v6']],
                                      nh_list=[param_dict['nh_sequence'][0], param_dict['nh_sequence_ipv6'][0]],
                                      nh_vrf=[param_dict['nh_vrf_sequence'][0]] * 2,interface=param_dict['interface'],
                                      check_counters=False)
    if not result:
        err = 'Expected nexthop not selected as per policy map at {}'.format(scope)
        failMsg(err,tech_support,tc_name);tech_support=False
        if param_dict['interface']:
            acl_dscp_api.config_service_policy_table(data.dut1, interface_name=param_dict['interface'],
                                                     service_policy_name=param_dict['policy_name'],
                                                     policy_kind='unbind', policy_type='forwarding')

        else:
            acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name=param_dict['policy_name'],
                                                     policy_kind='unbind', policy_type='forwarding')
        st.report_fail('test_case_failure_message',err)

    ###################################################################
    st.banner("Verify Traffic after applying service-policy")
    ###################################################################
    if not verify_traffic():
        err = 'Traffic not forwarded with service policy applied'
        failMsg(err,tech_support,tc_name);tech_support=False; err_list.append(err);
        tc_result = False;

    ###################################################################
    st.banner("Config save")
    ###################################################################
    bgp_api.enable_docker_routing_config_mode(data.dut1)
    reboot_api.config_save(data.dut1)
    reboot_api.config_save(data.dut1,'vtysh')

    for trigger in ['reboot','config_reload','docker_restart','warmboot']:
        ###################################################################
        st.banner("Perform {}".format(trigger))
        ###################################################################
        if trigger == 'reboot':
            tc = 'FtOpSoRoPbr333'
            st.reboot(data.dut1,'fast')
        elif trigger == 'config_reload':
            tc ='FtOpSoRoPbr331'
            reboot_api.config_reload(data.dut1)
        elif trigger == 'docker_restart':
            tc ='FtOpSoRoPbr334'
            basic_api.service_operations_by_systemctl(data.dut1,'swss','restart')
            result = retry_api(basic_api.get_system_status,data.dut1, retry_count=30, delay=3)
            if not result:
                err = "SWSS container did not come up after restart"
                failMsg(err);
                err_list.append(err);
                tc_result = False;
        else:
            tc ='FtOpSoRoPbr332'
            reboot_api.config_warm_restart(data.dut1,oper = "enable", tasks = ["system", "bgp"])
            st.reboot(data.dut1, 'warm')
        st.wait(5, 'wait for ports to come up')
        ###################################################################
        st.banner("Verify nexthop gets selected for traffic forwarding after {}".format(trigger))
        ###################################################################

        result, err = verify_pbr_basic_001(type='bgp', scope=scope, param_dict=param_dict,verify_null=False,trigger_test=True,dut_counters=False,
                                           check_counters=False,level=3)
        if result:
            st.report_tc_pass(tc, 'tc_passed')
        else:
            err = err + ' after {}'.format(trigger)
            failMsg(err);err_list.append(err);tc_result=False

        if not tc_result:
            ###################################################################
            st.banner("Unbind policy")
            ###################################################################
            if param_dict['interface']:
                acl_dscp_api.config_service_policy_table(data.dut1, interface_name=param_dict['interface'],
                                                         service_policy_name=param_dict['policy_name'],
                                                         policy_kind='unbind', policy_type='forwarding')

            else:
                acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name=param_dict['policy_name'],
                                                         policy_kind='unbind', policy_type='forwarding')

            return False, err_list[0]

    ###################################################################
    st.banner("Unbind policy")
    ###################################################################
    if param_dict['interface']:
        acl_dscp_api.config_service_policy_table(data.dut1, interface_name=param_dict['interface'],
                                                 service_policy_name=param_dict['policy_name'],
                                                 policy_kind='unbind', policy_type='forwarding')

    else:
        acl_dscp_api.config_service_policy_table(data.dut1, service_policy_name=param_dict['policy_name'],
                                                 policy_kind='unbind', policy_type='forwarding')


    return True,None



def scale_base_config():
    #################################
    st.banner("Scale Base config Start")
    #################################
    data.src_ip_list = range_ipv4(data.d1tg_ip_list[1],data.max_classifier,mask=32)
    policy_config_base('no')
    classifier_config_base('no')
    #################################
    st.banner("Configure max {} classifiers".format(data.max_classifier))
    #################################
    for class_name,src_ip in zip(data.classifier_names,data.src_ip_list):
        acl_dscp_api.config_classifier_table(data.dut1, enable='create', class_name=class_name,
                                         match_type='fields', class_criteria=['--src-ip'],
                                         criteria_value=[src_ip])
    #################################
    st.banner("Configure max {} policy with {} classifiers mapped".format(data.max_policy,data.max_classifier))
    #################################

    for policy,flow in zip(data.policy_names,data.classifier_names):
        acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name=policy,
                                          policy_type='forwarding',
                                          class_name=flow, flow_priority=10, priority_option='next-hop',
                                          next_hop=[data.vlan_ip_list[1]],
                                          vrf_name=[data.access_vrf],
                                          next_hop_priority=[30])

    ##################################
    st.banner("Configure {} sections in policy {}".format(data.max_policy_sections,data.policy_names[0]))
    ##################################
    for flow in data.classifier_names[1:int(data.max_policy_sections)]:
        acl_dscp_api.config_flow_update_table(data.dut1, flow='add', policy_name=data.policy_names[0],
                                          policy_type='forwarding',
                                          class_name=flow, flow_priority=10, priority_option='next-hop',
                                          next_hop=[data.vlan_ip_list[1]],
                                          vrf_name=[data.access_vrf],
                                          next_hop_priority=[30])


    #################################
    st.banner("Configure Traffic stream to match each classifier rules")
    #################################
    data.scale_streams = []
    ipv4_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tgd1_handles[0]], mac_dst=data.tg_d1_dest_mac,
                                             l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id=data.d1tg_vlan_id,
                                             rate_pps=data.traffic_rate, \
                                             mode='create', port_handle=data.tg_handles[0],
                                             transmit_mode='continuous',
                                             l3_protocol='ipv4', ip_src_addr=data.d1tg_ip_list[1] ,ip_src_mode='increment',
                                             ip_src_count=data.max_policy_sections,ip_src_step='0.0.0.1'\
                                             , ip_dst_addr=data.d2tg_ip_list[1], mac_discovery_gw=data.d1tg_ip_list[0],
                                             l4_protocol='tcp', tcp_src_port=data.src_tcp, tcp_dst_port=data.dst_tcp,
                                             tcp_syn_flag=1,tcp_psh_flag=0)
    data.scale_stream = ipv4_stream['stream_id']

    data.scale_streams.append(data.scale_stream)

    #################################
    st.banner("Scale Base config End ")
    #################################


def scale_base_deconfig():
    #################################
    st.banner("Scale Cleanup Start")
    #################################

    for flow in data.classifier_names[1:int(data.max_policy_sections)]:
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=data.policy_names[0],
                                          policy_type='forwarding',
                                          class_name=flow, flow_priority=10)

    for policy,flow in zip(data.policy_names,data.classifier_names):
        acl_dscp_api.config_flow_update_table(data.dut1, flow='del', policy_name=policy,
                                          policy_type='forwarding',class_name=flow, flow_priority=10)


    for class_name in data.classifier_names:
        acl_dscp_api.config_classifier_table(data.dut1, enable='del', class_name=class_name)

    #################################
    st.banner("Scale Cleanup End ")
    #################################



def ip_to_int(ipstr):
    return struct.unpack('!I', socket.inet_aton(ipstr))[0]


def int_to_ip(n):
    return socket.inet_ntoa(struct.pack('!I', n))

def incr_ipv4(ipaddr, mask=32, step=1):
    # To separate the mask if provided with ip.
    ipaddr,save_mask = [ipaddr, ''] if ipaddr.find('/') == -1 else ipaddr.split('/')
    ip_int = ip_to_int(ipaddr)
    # Saving the diff value.
    ip_int_old = ip_int
    ip_int >>= 32 - mask
    ip_int <<= 32 - mask
    ip_diff = ip_int_old - ip_int
    # Actual logic.
    ip_int >>= 32 - mask
    ip_int += step
    ip_int <<= 32 - mask
    ip_int += ip_diff
    ipaddr = int_to_ip(ip_int)
    ipaddr = '/'.join([ipaddr,save_mask]) if save_mask != '' else ipaddr
    return ipaddr

def range_ipv4(start_ip, count, mask=32):
    ip_list = []
    for _ in range(count):
        ip_list.append(start_ip)
        start_ip = incr_ipv4(start_ip, mask)
    return ip_list
