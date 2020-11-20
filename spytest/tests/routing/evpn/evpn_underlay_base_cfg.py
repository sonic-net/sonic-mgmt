#############################################################################
#Script Title : EVPN 5549 Underlay
#Author       : Meenal Annamalai
#Mail-id      : meenal.annamalai@broadcom.com
#############################################################################

from spytest import st, utils, SpyTestDict

import apis.routing.ip as ipfeature
import apis.switching.portchannel as pch
import apis.system.interface as Intf
import apis.system.basic as basic_obj
import apis.routing.bgp as bgp_obj
import apis.routing.ip_bgp as ip_bgp
import apis.routing.evpn as evpn_api

import apis.routing.bgp as Bgp
import apis.routing.ip as ip

from utilities import parallel

from evpn import disable_debugs, enable_debugs
from evpn import setup_vxlan, setup_l2vni, setup_l3vni
from evpn import evpn_dict, retry_api, get_num_of_bfd_sessions_up

data = SpyTestDict()
leaf1 = SpyTestDict()
spine1 = SpyTestDict()
leaf2 = SpyTestDict()

data.maskv6 = '127'

data.spine1_loopback1 = '11.11.11.11'
data.spine2_loopback2 = '22.22.22.22'
data.leaf1_loopback1 = '1.1.1.1'

data.spine_loopback_list = ['%s.%s.%s.2'%(x, x, x) for x in range(1,3)]
data.leaf_loopback_list = ['%s.%s.%s.2'%(x, x, x) for x in range(3,7)]

data.spine1_ipv6_list = ['1001:1::', '1001:1::2', '1001:1::4', '1001:1::6']
data.spine2_ipv6_list = ['1002:2::', '1002:2::2', '1002:2::4', '1002:2::6']

data.leaf_spine1_ipv6_list = ['1001:1::1', '1001:1::3', '1001:1::5', '1001:1::7']
data.leaf_spine2_ipv6_list = ['1002:2::1', '1002:2::3', '1002:2::5', '1002:2::7']

data.spine1_ipv6_list2 = ['2001:1::0', '2001:1::2', '2001:1::4', '2001:1::6']
data.spine2_ipv6_list2 = ['2002:2::0', '2002:2::2', '2002:2::4', '2002:2::6']

data.leaf_spine1_ipv6_list2 = ['2001:1::1', '2001:1::3', '2001:1::5', '2001:1::7']
data.leaf_spine2_ipv6_list2 = ['2002:2::1', '2002:2::3', '2002:2::5', '2002:2::7']

data.bgp_spine_local_as = ['100','200']
data.bgp_leaf_local_as = ['300', '400', '500', '600']


def make_global_vars():

    global vars
    vars = st.get_testbed_vars()

    data.spine1_port_list1 = [vars.D1D3P1, vars.D1D4P1, vars.D1D5P1, vars.D1D6P1]
    data.spine2_port_list1 = [vars.D2D3P1, vars.D2D4P1, vars.D2D5P1, vars.D2D6P1]
    data.leafs_spine1_port_lst1 = [vars.D3D1P1, vars.D4D1P1, vars.D5D1P1, vars.D6D1P1]
    data.leafs_spine2_port_lst1 = [vars.D3D2P1, vars.D4D2P1, vars.D5D2P1, vars.D6D2P1]

    data.spine1_port_list2 = [vars.D1D3P2, vars.D1D4P2, vars.D1D5P2, vars.D1D6P2]
    data.spine2_port_list2 = [vars.D2D3P2, vars.D2D4P2, vars.D2D5P2, vars.D2D6P2]
    data.leafs_spine1_port_lst2 = [vars.D3D1P2, vars.D4D1P2, vars.D5D1P2, vars.D6D1P2]
    data.leafs_spine2_port_lst2 = [vars.D3D2P2, vars.D4D2P2, vars.D5D2P2, vars.D6D2P2]

    data.spine1_port_list3 = [vars.D1D3P3, vars.D1D4P3, vars.D1D5P3, vars.D1D6P3]
    data.spine2_port_list3 = [vars.D2D3P3, vars.D2D4P3, vars.D2D5P3, vars.D2D6P3]
    data.leafs_spine1_port_lst3 = [vars.D3D1P3, vars.D4D1P3, vars.D5D1P3, vars.D6D1P3]
    data.leafs_spine2_port_lst3 = [vars.D3D2P3, vars.D4D2P3, vars.D5D2P3, vars.D6D2P3]

    data.spine1_port_list4 = [vars.D1D3P4, vars.D1D4P4, vars.D1D5P4, vars.D1D6P4]
    data.spine2_port_list4 = [vars.D2D3P4, vars.D2D4P4, vars.D2D5P4, vars.D2D6P4]
    data.leafs_spine1_port_lst4 = [vars.D3D1P4, vars.D4D1P4, vars.D5D1P4, vars.D6D1P4]
    data.leafs_spine2_port_lst4 = [vars.D3D2P4, vars.D4D2P4, vars.D5D2P4, vars.D6D2P4]

    data.spine1_leaf1_po_intf_list = [vars.D1D3P2, vars.D1D3P3]
    data.spine1_leaf2_po_intf_list = [vars.D1D4P2, vars.D1D4P3]
    data.spine1_leaf3_po_intf_list = [vars.D1D5P2, vars.D1D5P3]
    data.spine1_leaf4_po_intf_list = [vars.D1D6P2, vars.D1D6P3]
    data.spine1_all_lfs_po_intf_list = [data.spine1_leaf1_po_intf_list, data.spine1_leaf2_po_intf_list, data.spine1_leaf3_po_intf_list, data.spine1_leaf4_po_intf_list]
    data.leaf1_spine1_po_intf_list = [vars.D3D1P2, vars.D3D1P3]
    data.leaf2_spine1_po_intf_list = [vars.D4D1P2, vars.D4D1P3]
    data.leaf3_spine1_po_intf_list = [vars.D5D1P2, vars.D5D1P3]
    data.leaf4_spine1_po_intf_list = [vars.D6D1P2, vars.D6D1P3]

    data.spine2_leaf1_po_intf_list = [vars.D2D3P2, vars.D2D3P3]
    data.spine2_leaf2_po_intf_list = [vars.D2D4P2, vars.D2D4P3]
    data.spine2_leaf3_po_intf_list = [vars.D2D5P2, vars.D2D5P3]
    data.spine2_leaf4_po_intf_list = [vars.D2D6P2, vars.D2D6P3]
    data.spine2_all_lfs_po_intf_list = [data.spine2_leaf1_po_intf_list, data.spine2_leaf2_po_intf_list, data.spine2_leaf3_po_intf_list, data.spine2_leaf4_po_intf_list]
    data.leaf1_spine2_po_intf_list = [vars.D3D2P2, vars.D3D2P3]
    data.leaf2_spine2_po_intf_list = [vars.D4D2P2, vars.D4D2P3]
    data.leaf3_spine2_po_intf_list = [vars.D5D2P2, vars.D5D2P3]
    data.leaf4_spine2_po_intf_list = [vars.D6D2P2, vars.D6D2P3]

    data.leaf1_po_list =  ["PortChannel13","PortChannel23"]
    data.leaf2_po_list =  ["PortChannel14","PortChannel24"]
    data.leaf3_po_list =  ["PortChannel15","PortChannel25"]
    data.leaf4_po_list =  ["PortChannel16","PortChannel26"]
    data.spine1_po_list = ["PortChannel13","PortChannel14","PortChannel15","PortChannel16"]
    data.spine2_po_list = ["PortChannel23","PortChannel24","PortChannel25","PortChannel26"]
    data.leafs_spine1_po_lst1 = ["PortChannel13", "PortChannel14", "PortChannel15", "PortChannel16"]
    data.leafs_spine2_po_lst1 = ["PortChannel23", "PortChannel24", "PortChannel25", "PortChannel26"]

    data.leaf_nodes_list = [vars.D3, vars.D4, vars.D5, vars.D6]
    data.spine_nodes_list = [vars.D1, vars.D2]

    globals().update(data)


def create_evpn_5549_config():
    setup_evpn_5549()
    setup_vxlan()
    setup_l2vni()
    setup_l3vni()


def setup_evpn_5549():

    global vars
    vars = st.get_testbed_vars()
    make_global_vars()

    ############################################################################################
    hdrMsg("\n########## BASE CONFIGS ############\n")
    ############################################################################################

    ############################################################################################
    hdrMsg("\n########## Enable debugs ############\n")
    ############################################################################################
    enable_debugs()

    ############################################################################################
    hdrMsg("\n########## Configure Port-channel and portchannel members ############\n")
    ############################################################################################

    st.log("create port channel interface b/w leaf and spine nodes")
    utils.exec_all(True, [[pch.create_portchannel, data.leaf_nodes_list[0], data.leaf1_po_list],
                    [pch.create_portchannel, data.leaf_nodes_list[1], data.leaf2_po_list],
                    [pch.create_portchannel, data.leaf_nodes_list[2], data.leaf3_po_list],
                    [pch.create_portchannel, data.leaf_nodes_list[3], data.leaf4_po_list],
                    [pch.create_portchannel, data.spine_nodes_list[0], data.spine1_po_list],
                    [pch.create_portchannel, data.spine_nodes_list[1], data.spine2_po_list]])

    st.log("Add members to port channel created b/w leaf and spine nodes")
    utils.exec_all(True, [[pch.add_portchannel_member, data.leaf_nodes_list[0], data.leaf1_po_list[0], data.leaf1_spine1_po_intf_list],
                          [pch.add_portchannel_member, data.leaf_nodes_list[1], data.leaf2_po_list[0], data.leaf2_spine1_po_intf_list],
                          [pch.add_portchannel_member, data.leaf_nodes_list[2], data.leaf3_po_list[0], data.leaf3_spine1_po_intf_list],
                          [pch.add_portchannel_member, data.leaf_nodes_list[3], data.leaf4_po_list[0], data.leaf4_spine1_po_intf_list]])

    utils.exec_all(True, [[pch.add_portchannel_member, data.leaf_nodes_list[0], data.leaf1_po_list[1], data.leaf1_spine2_po_intf_list],
                          [pch.add_portchannel_member, data.leaf_nodes_list[1], data.leaf2_po_list[1], data.leaf2_spine2_po_intf_list],
                          [pch.add_portchannel_member, data.leaf_nodes_list[2], data.leaf3_po_list[1], data.leaf3_spine2_po_intf_list],
                          [pch.add_portchannel_member, data.leaf_nodes_list[3], data.leaf4_po_list[1], data.leaf4_spine2_po_intf_list]])

    for po1,po2,intf_list1,intf_list2 in zip(data.spine1_po_list,data.spine2_po_list,data.spine1_all_lfs_po_intf_list,data.spine2_all_lfs_po_intf_list):
        utils.exec_all(True, [[pch.add_portchannel_member,data.spine_nodes_list[0], po1, intf_list1],
                          [pch.add_portchannel_member, data.spine_nodes_list[1], po2, intf_list2]])

    st.log("Enable portchannel interface on all leaf and spine nodes")
    utils.exec_all(True, [[Intf.interface_operation, data.leaf_nodes_list[0], data.leaf1_po_list, "startup"],
                          [Intf.interface_operation, data.leaf_nodes_list[1], data.leaf2_po_list, "startup"],
                          [Intf.interface_operation, data.leaf_nodes_list[2], data.leaf3_po_list, "startup"],
                          [Intf.interface_operation, data.leaf_nodes_list[3], data.leaf4_po_list, "startup"],
                          [Intf.interface_operation, data.spine_nodes_list[0], data.spine1_po_list, "startup"],
                          [Intf.interface_operation, data.spine_nodes_list[1], data.spine2_po_list, "startup"]])

    ############################################################################################
    hdrMsg("\n####### Configure IP address on link1 of all the DUTs ##############\n")
    ############################################################################################

    utils.exec_all(True, [[ipfeature.config_interface_ip6_link_local, vars.D1, data.spine1_port_list1], [ipfeature.config_interface_ip6_link_local, vars.D2, data.spine2_port_list1]])

    utils.exec_all(True, [[ipfeature.config_interface_ip6_link_local, vars.D3, data.leafs_spine1_port_lst1[0]], [ipfeature.config_interface_ip6_link_local, vars.D4, data.leafs_spine1_port_lst1[1]], [ipfeature.config_interface_ip6_link_local, vars.D5, data.leafs_spine1_port_lst1[2]],[ipfeature.config_interface_ip6_link_local, vars.D6, data.leafs_spine1_port_lst1[3]]])

    utils.exec_all(True, [[ipfeature.config_interface_ip6_link_local, vars.D3, data.leafs_spine2_port_lst1[0]], [ipfeature.config_interface_ip6_link_local, vars.D4, data.leafs_spine2_port_lst1[1]], [ipfeature.config_interface_ip6_link_local, vars.D5, data.leafs_spine2_port_lst1[2]],[ipfeature.config_interface_ip6_link_local, vars.D6, data.leafs_spine2_port_lst1[3]]])

    ############################################################################################
    hdrMsg("\n########## Configure IP address on link2 (LAG) of all the DUTs ##############\n")
    ############################################################################################
    utils.exec_all(True, [[ipfeature.config_interface_ip6_link_local, vars.D1, data.spine1_po_list], [ipfeature.config_interface_ip6_link_local, vars.D2, data.spine2_po_list]])

    utils.exec_all(True, [[ipfeature.config_interface_ip6_link_local, vars.D3, data.leaf1_po_list[0]], [ipfeature.config_interface_ip6_link_local, vars.D4, data.leaf2_po_list[0]], [ipfeature.config_interface_ip6_link_local, vars.D5, data.leaf3_po_list[0]], [ipfeature.config_interface_ip6_link_local, vars.D6, data.leaf4_po_list[0]]])

    utils.exec_all(True, [[ipfeature.config_interface_ip6_link_local, vars.D3, data.leaf1_po_list[1]], [ipfeature.config_interface_ip6_link_local, vars.D4, data.leaf2_po_list[1]], [ipfeature.config_interface_ip6_link_local, vars.D5, data.leaf3_po_list[1]], [ipfeature.config_interface_ip6_link_local, vars.D6, data.leaf4_po_list[1]]])


    ############################################################################################
    hdrMsg("\n####### Configure IP address on link3 of all the DUTs ##############\n")
    ############################################################################################

    for ipv6_1,ipv6_2,po1,po2 in zip(data.spine1_ipv6_list, data.spine2_ipv6_list,data.spine1_port_list4, data.spine2_port_list4):
        utils.exec_all(True,[[ipfeature.config_ip_addr_interface,vars.D1, po1, ipv6_1 , data.maskv6,'ipv6'],[ipfeature.config_ip_addr_interface,vars.D2, po2, ipv6_2, data.maskv6,'ipv6']])

    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,vars.D3, data.leafs_spine1_port_lst4[0], data.leaf_spine1_ipv6_list[0], data.maskv6,'ipv6'],[ipfeature.config_ip_addr_interface,vars.D4, data.leafs_spine1_port_lst4[1], data.leaf_spine1_ipv6_list[1], data.maskv6,'ipv6'], [ipfeature.config_ip_addr_interface,vars.D5, data.leafs_spine1_port_lst4[2], data.leaf_spine1_ipv6_list[2] , data.maskv6,'ipv6'], [ipfeature.config_ip_addr_interface,vars.D6, data.leafs_spine1_port_lst4[3], data.leaf_spine1_ipv6_list[3] , data.maskv6,'ipv6']])

    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,vars.D3, data.leafs_spine2_port_lst4[0], data.leaf_spine2_ipv6_list[0], data.maskv6,'ipv6'],[ipfeature.config_ip_addr_interface,vars.D4, data.leafs_spine2_port_lst4[1], data.leaf_spine2_ipv6_list[1], data.maskv6,'ipv6'], [ipfeature.config_ip_addr_interface,vars.D5, data.leafs_spine2_port_lst4[2], data.leaf_spine2_ipv6_list[2], data.maskv6,'ipv6'], [ipfeature.config_ip_addr_interface,vars.D6, data.leafs_spine2_port_lst4[3], data.leaf_spine2_ipv6_list[3], data.maskv6,'ipv6']])

    ############################################################################################
    hdrMsg("\n########## Enable router bgp and configure router id ##############\n")
    ############################################################################################

    dict1 = {'local_as': data.bgp_leaf_local_as[0],'router_id':data.leaf_loopback_list[0],'config_type_list':['router_id']}
    dict2 = {'local_as': data.bgp_leaf_local_as[1],'router_id':data.leaf_loopback_list[1],'config_type_list':['router_id']}
    dict3 = {'local_as': data.bgp_leaf_local_as[2],'router_id':data.leaf_loopback_list[2],'config_type_list':['router_id']}
    dict4 = {'local_as': data.bgp_leaf_local_as[3],'router_id':data.leaf_loopback_list[3],'config_type_list':['router_id']}

    parallel.exec_parallel(True, data.leaf_nodes_list, bgp_obj.config_bgp, [dict1,dict2,dict3,dict4])

    dict1 = {'local_as':data.bgp_spine_local_as[0],'router_id':data.spine_loopback_list[0], 'config_type_list':['router_id']}
    dict2 = {'local_as':data.bgp_spine_local_as[1],'router_id':data.spine_loopback_list[1],'config_type_list':['router_id']}

    parallel.exec_parallel(True, data.spine_nodes_list, bgp_obj.config_bgp, [dict1,dict2])

    ############################################################################################
    hdrMsg(" \n######### Configure BGP neighbor for link1 on all spines and leafs ##########\n")
    ############################################################################################
    dict1 = {'local_as':data.bgp_spine_local_as[0], 'config': 'yes',  'config_type_list':["multipath-relax"]}
    dict2 = {'local_as':data.bgp_spine_local_as[1], 'config': 'yes',  'config_type_list':["multipath-relax"]}
    parallel.exec_parallel(True,data.spine_nodes_list,bgp_obj.config_bgp,[dict1,dict2])

    dict = {}
    for i in range(0,4):
        dict[i] = {'local_as':data.bgp_leaf_local_as[i], 'config': 'yes',  'config_type_list':["multipath-relax"]}
    dict_lst = [dict[x] for x in range(0,4)]
    parallel.exec_parallel(True,data.leaf_nodes_list,bgp_obj.config_bgp,dict_lst)

    for intf1,intf2 in zip(data.spine1_port_list1,data.spine2_port_list1):
       if evpn_dict['cli_mode'] == 'click':
           dict1 = {'local_as':data.bgp_spine_local_as[0],'config':'yes','config_type_list':["remote-as"],'remote_as':'external','interface':intf1}
           dict2 = {'local_as':data.bgp_spine_local_as[1],'config':'yes','config_type_list':["remote-as"],'remote_as':'external','interface':intf2}
           parallel.exec_parallel(True,data.spine_nodes_list,bgp_obj.config_bgp,[dict1,dict2])
           dict1 = {'local_as':data.bgp_spine_local_as[0],'config':'yes','config_type_list':["connect"],'neighbor':intf1,'connect':"1"}
           dict2 = {'local_as':data.bgp_spine_local_as[1],'config':'yes','config_type_list':["connect"],'neighbor':intf2,'connect':"1"}
           parallel.exec_parallel(True,data.spine_nodes_list,bgp_obj.config_bgp,[dict1,dict2])
       elif evpn_dict['cli_mode'] == 'klish':
           dict1 = {'local_as':data.bgp_spine_local_as[0],'config':'yes','config_type_list':["neighbor","connect"],'remote_as':'external','neighbor':intf1, \
               'addr_family':"ipv6",'connect':"1"}
           dict2 = {'local_as':data.bgp_spine_local_as[1],'config':'yes','config_type_list':["neighbor","connect"],'remote_as':'external','neighbor':intf2,'connect':"1"}
           parallel.exec_parallel(True,data.spine_nodes_list,bgp_obj.config_bgp,[dict1,dict2])

       dict1 = {'local_as':data.bgp_spine_local_as[0], 'config': 'yes', 'config_type_list':["activate"], 'neighbor':intf1,'remote_as':'external'}
       dict2 = {'local_as':data.bgp_spine_local_as[1], 'config': 'yes', 'config_type_list':["activate"], 'neighbor':intf2,'remote_as':'external'}
       parallel.exec_parallel(True,data.spine_nodes_list,evpn_api.config_bgp_evpn,[dict1,dict2])

    for port_lst1 in [data.leafs_spine1_port_lst1, data.leafs_spine2_port_lst1]:
       if evpn_dict['cli_mode'] == 'click':
          dict = {}
          for i in range(0,4):
              dict[i] ={'local_as':data.bgp_leaf_local_as[i],'config':'yes','config_type_list':["remote-as"],'remote_as':'external','interface':port_lst1[i]}
          dict_lst = [dict[x] for x in range(0,4)]
          parallel.exec_parallel(True,data.leaf_nodes_list,bgp_obj.config_bgp,dict_lst)
          dict = {}
          for i in range(0,4):
              dict[i] ={'local_as':data.bgp_leaf_local_as[i],'config':'yes','config_type_list':["connect"],'neighbor':port_lst1[i],'connect':"1"}
          dict_lst = [dict[x] for x in range(0,4)]
          parallel.exec_parallel(True,data.leaf_nodes_list,bgp_obj.config_bgp,dict_lst)
       elif evpn_dict['cli_mode'] == 'klish':
          for i in range(0,4):
              dict[i] ={'local_as':data.bgp_leaf_local_as[i],'config':'yes','config_type_list':["neighbor","connect"],'remote_as':'external', \
                  'addr_family':"ipv6",'neighbor':port_lst1[i],'connect':"1"}
          dict_lst = [dict[x] for x in range(0,4)]
          parallel.exec_parallel(True,data.leaf_nodes_list,bgp_obj.config_bgp,dict_lst)

       dict = {}
       for i in range(0,4):
           dict[i] = {'local_as':data.bgp_leaf_local_as[i], 'config': 'yes',  'config_type_list':["activate"], 'neighbor':port_lst1[i],'remote_as':'external'}
       dict_lst = [dict[x] for x in range(0,4)]
       parallel.exec_parallel(True,data.leaf_nodes_list,evpn_api.config_bgp_evpn,dict_lst)

    ############################################################################################
    hdrMsg(" \n######### Configure BGP neighbor for link2 on all spines and leafs ##########\n")
    ############################################################################################
    for intf1,intf2,j in zip(data.spine1_po_list,data.spine2_po_list,range(0,4)):
       if evpn_dict['cli_mode'] == 'click':
          dict1 = {'local_as':data.bgp_spine_local_as[0],'config':'yes','config_type_list':["remote-as"],'remote_as':data.bgp_leaf_local_as[j],'interface' :intf1}
          dict2 = {'local_as':data.bgp_spine_local_as[1],'config':'yes','config_type_list':["remote-as"],'remote_as':data.bgp_leaf_local_as[j],'interface' :intf2}
          parallel.exec_parallel(True,data.spine_nodes_list,bgp_obj.config_bgp,[dict1,dict2])
          dict1 = {'local_as':data.bgp_spine_local_as[0],'config':'yes','config_type_list':["connect"],'neighbor' :intf1,'connect':"1"}
          dict2 = {'local_as':data.bgp_spine_local_as[1],'config':'yes','config_type_list':["connect"],'neighbor' :intf2,'connect':"1"}
          parallel.exec_parallel(True,data.spine_nodes_list,bgp_obj.config_bgp,[dict1,dict2])
       elif evpn_dict['cli_mode'] == 'klish':
          dict1 = {'local_as':data.bgp_spine_local_as[0],'config':'yes','config_type_list':["neighbor","connect"],'remote_as':data.bgp_leaf_local_as[j], \
              'addr_family':"ipv6",'neighbor' :intf1,'connect':"1"}
          dict2 = {'local_as':data.bgp_spine_local_as[1],'config':'yes','config_type_list':["neighbor","connect"],'remote_as':data.bgp_leaf_local_as[j], \
              'addr_family':"ipv6",'neighbor' :intf2,'connect':"1"}
          parallel.exec_parallel(True,data.spine_nodes_list,bgp_obj.config_bgp,[dict1,dict2])

       dict1 = {'local_as':data.bgp_spine_local_as[0], 'config': 'yes', 'config_type_list':["activate"], 'neighbor':intf1,'remote_as':data.bgp_leaf_local_as[j]}
       dict2 = {'local_as':data.bgp_spine_local_as[1], 'config': 'yes', 'config_type_list':["activate"], 'neighbor':intf2,'remote_as':data.bgp_leaf_local_as[j]}
       parallel.exec_parallel(True,data.spine_nodes_list,evpn_api.config_bgp_evpn,[dict1,dict2])

    for j,port_lst1 in zip(range(0,2),[data.leafs_spine1_po_lst1, data.leafs_spine2_po_lst1]):
       if evpn_dict['cli_mode'] == 'click':
          dict = {}
          for i in range(0,4):
              dict[i] = {'local_as':data.bgp_leaf_local_as[i],'config':'yes','config_type_list':["remote-as"],'remote_as':data.bgp_spine_local_as[j],'interface':port_lst1[i]}
          dict_lst = [dict[x] for x in range(0,4)]
          parallel.exec_parallel(True,data.leaf_nodes_list,bgp_obj.config_bgp,dict_lst)
          dict = {}
          for i in range(0,4):
              dict[i] = {'local_as':data.bgp_leaf_local_as[i],'config':'yes','config_type_list':["connect"],'neighbor':port_lst1[i],'connect':"1"}
          dict_lst = [dict[x] for x in range(0,4)]
          parallel.exec_parallel(True,data.leaf_nodes_list,bgp_obj.config_bgp,dict_lst)
       elif evpn_dict['cli_mode'] == 'klish':
          dict = {}
          for i in range(0,4):
              dict[i] = {'local_as':data.bgp_leaf_local_as[i], 'config': 'yes',  'config_type_list':["neighbor","connect"], 'remote_as': data.bgp_spine_local_as[j], 'neighbor' : port_lst1[i],'addr_family':"ipv6",'connect':"1"}
          dict_lst = [dict[x] for x in range(0,4)]
          parallel.exec_parallel(True,data.leaf_nodes_list,bgp_obj.config_bgp,dict_lst)

       dict = {}
       for i in range(0,4):
           dict[i] = {'local_as':data.bgp_leaf_local_as[i], 'config': 'yes',  'config_type_list':["activate"],'neighbor':port_lst1[i],'remote_as': data.bgp_spine_local_as[j]}
       dict_lst = [dict[x] for x in range(0,4)]
       parallel.exec_parallel(True,data.leaf_nodes_list,evpn_api.config_bgp_evpn,dict_lst)

    ############################################################################################
    hdrMsg(" \n######### Configure BGP neighbor for link3 on all spines and leafs ##########\n")
    ############################################################################################
    for ipv6_1,ipv6_2,j in zip(data.leaf_spine1_ipv6_list, data.leaf_spine2_ipv6_list,range(0,4)):
       dict1 = {'local_as':data.bgp_spine_local_as[0], 'config': 'yes',  'config_type_list':["neighbor","connect"], 'remote_as':data.bgp_leaf_local_as[j], 'neighbor' : ipv6_1,'addr_family':"ipv6",'connect':"1"}
       dict2 = {'local_as':data.bgp_spine_local_as[1], 'config': 'yes',  'config_type_list':["neighbor","connect"], 'remote_as':data.bgp_leaf_local_as[j], 'neighbor' : ipv6_2,'addr_family':"ipv6",'connect':"1"}
       parallel.exec_parallel(True,data.spine_nodes_list,bgp_obj.config_bgp,[dict1,dict2])

       dict1 = {'local_as':data.bgp_spine_local_as[0], 'config': 'yes', 'config_type_list':["activate"], 'neighbor':ipv6_1,'remote_as':data.bgp_leaf_local_as[j]}
       dict2 = {'local_as':data.bgp_spine_local_as[1], 'config': 'yes', 'config_type_list':["activate"], 'neighbor':ipv6_2,'remote_as':data.bgp_leaf_local_as[j]}
       parallel.exec_parallel(True,data.spine_nodes_list,evpn_api.config_bgp_evpn,[dict1,dict2])

    for ipv6_lst1,j in zip([data.spine1_ipv6_list,data.spine2_ipv6_list],range(0,2)):
        dict = {}
        for i in range(0,4):
            dict[i] = {'local_as':data.bgp_leaf_local_as[i], 'config': 'yes', 'config_type_list':["neighbor","connect"], 'remote_as':data.bgp_spine_local_as[j], 'neighbor' : ipv6_lst1[i],'addr_family':"ipv6",'connect':"1"}
        dict_lst = [dict[x] for x in range(0,4)]
        parallel.exec_parallel(True,data.leaf_nodes_list,bgp_obj.config_bgp,dict_lst)

        dict = {}
        for i in range(0,4):
            dict[i] = {'local_as':data.bgp_leaf_local_as[i], 'config': 'yes',  'config_type_list':["activate"], 'neighbor':ipv6_lst1[i],'remote_as':data.bgp_spine_local_as[j]}
        dict_lst = [dict[x] for x in range(0,4)]
        parallel.exec_parallel(True,data.leaf_nodes_list,evpn_api.config_bgp_evpn,dict_lst)

    dict1 = {'local_as':data.bgp_spine_local_as[0], 'config': 'yes', 'config_type_list':["advertise_all_vni"]}
    dict2 = {'local_as':data.bgp_spine_local_as[1], 'config': 'yes', 'config_type_list':["advertise_all_vni"]}
    parallel.exec_parallel(True,data.spine_nodes_list,evpn_api.config_bgp_evpn,[dict1,dict2])
    dict = {}
    for i in range(0,4):
        dict[i] = {'local_as':data.bgp_leaf_local_as[i], 'config': 'yes', 'config_type_list':["advertise_all_vni"]}
    dict_lst = [dict[x] for x in range(0,4)]
    parallel.exec_parallel(True,data.leaf_nodes_list,evpn_api.config_bgp_evpn,dict_lst)

    ############################################################################################
    hdrMsg(" \n####### Verify BGP neighborship on Spine1 and Spine2 ##############\n")
    ############################################################################################
    if not retry_api(ip_bgp.check_bgp_session,vars.D1,nbr_list=data.spine1_port_list1,state_list=['Established']*4,retry_count=9,delay=5):
        st.error("########## BGP neighborship between Spine 1 towards Leafs is not Up ##########")
    if not retry_api(ip_bgp.check_bgp_session,vars.D2,nbr_list=data.spine2_port_list1,state_list=['Established']*4,retry_count=9,delay=5):
        st.error("########## BGP neighborship between Spine 2 towards Leaf is not Up ##########")
    evpn_verify1 = { "neighbor": data.leaf_spine1_ipv6_list+data.spine1_port_list1+data.spine1_po_list, "updown": ["up"]*12}
    evpn_verify2 = { "neighbor": data.leaf_spine2_ipv6_list+data.spine2_port_list1+data.spine2_po_list, "updown": ["up"]*12}

    st.log("verify BGP EVPN neighborship for ipv6 global address, router port & L3 PortChannel b/w Spine towards Leaf ndoes")
    parallel.exec_parallel(True, data.spine_nodes_list, evpn_api.verify_bgp_l2vpn_evpn_summary,[evpn_verify1,evpn_verify2])

    ############################################################################################
    hdrMsg(" \n####### Configure loopback interface ##############\n")
    ############################################################################################

    dict={}
    for i in range(0,6):
        dict[i] = {'loopback_name':'Loopback1', 'config':'yes'}
    dict_lst = [dict[x] for x in range(0,6)]

    parallel.exec_parallel(True,data.spine_nodes_list+data.leaf_nodes_list,ipfeature.configure_loopback,dict_lst)

    utils.exec_all(True,[[ipfeature.config_ip_addr_interface, vars.D1, 'Loopback1', data.spine_loopback_list[0], 32, 'ipv4'], [ipfeature.config_ip_addr_interface, vars.D2, 'Loopback1', data.spine_loopback_list[1], 32, 'ipv4'], [ipfeature.config_ip_addr_interface, vars.D3, 'Loopback1', data.leaf_loopback_list[0], 32, 'ipv4'], [ipfeature.config_ip_addr_interface, vars.D4, 'Loopback1', data.leaf_loopback_list[1], 32, 'ipv4'], [ipfeature.config_ip_addr_interface, vars.D5, 'Loopback1', data.leaf_loopback_list[2], 32, 'ipv4'], [ipfeature.config_ip_addr_interface, vars.D6, 'Loopback1', data.leaf_loopback_list[3], 32, 'ipv4']])

    ############################################################################################
    hdrMsg(" \n####### Redistribute connected route in to bgp ##############\n")
    ############################################################################################
    dict = {}
    for i,as1 in zip(range(0,6),data.bgp_spine_local_as+data.bgp_leaf_local_as):
        dict[i] = {'local_as':as1, 'config_type_list':['redist'],'redistribute':'connected'}

    dict_lst = [dict[x] for x in range(0,6)]
    parallel.exec_parallel(True,data.spine_nodes_list+data.leaf_nodes_list,bgp_obj.config_bgp,dict_lst)

    ############################################################################################
    hdrMsg(" \n####### Verify ip route shows IPv6 NH ##############\n")
    ############################################################################################
    x={}
    for i, dut, port in zip(range(0,4), data.leaf_nodes_list, data.leafs_spine1_port_lst1):
        x[i]=basic_obj.get_ifconfig_inet6(dut, port)

    for i,ip in zip(range(0,4),data.leaf_loopback_list):
        if not retry_api(ipfeature.verify_ip_route,vars.D1, type='B', nexthop = x[i][0].strip(), ip_address = ip+'/32',retry_count=9,delay=1):
            st.report_fail("ip_routing_int_create_fail", ip)

    ############################################################################################
    hdrMsg(" \n####### Configure BFD on BGP unnumbered sessions ##############\n")
    ############################################################################################

    for intf1,intf2 in zip(data.spine1_port_list1,data.spine2_port_list1):
       dict1 = {'local_as':data.bgp_spine_local_as[0], 'config': 'yes',  'config_type_list':["bfd"], 'interface' : intf1,'remote_as':'external'}
       dict2 = {'local_as':data.bgp_spine_local_as[1], 'config': 'yes',  'config_type_list':["bfd"], 'interface' : intf2,'remote_as':'external'}
       parallel.exec_parallel(True,data.spine_nodes_list,bgp_obj.config_bgp,[dict1,dict2])

    for port_lst1 in [data.leafs_spine1_port_lst1, data.leafs_spine2_port_lst1]:
        dict = {}
        for i in range(0,4):
            dict[i] = {'local_as':data.bgp_leaf_local_as[i], 'config': 'yes',  'config_type_list':["bfd"], 'remote_as':'external', 'interface' : port_lst1[i]}
        dict_lst = [dict[x] for x in range(0,4)]
        parallel.exec_parallel(True,data.leaf_nodes_list,bgp_obj.config_bgp, dict_lst)

    for intf1,intf2,j in zip(data.spine1_po_list,data.spine2_po_list,range(0,4)):
       dict1 = {'local_as':data.bgp_spine_local_as[0], 'config': 'yes',  'config_type_list':["bfd"], 'remote_as':data.bgp_leaf_local_as[j], 'interface' : intf1}
       dict2 = {'local_as':data.bgp_spine_local_as[1], 'config': 'yes',  'config_type_list':["bfd"], 'remote_as':data.bgp_leaf_local_as[j], 'interface' : intf2}
       parallel.exec_parallel(True,data.spine_nodes_list,bgp_obj.config_bgp,[dict1,dict2])

    for j,port_lst1 in zip(range(0,2),[data.leafs_spine1_po_lst1, data.leafs_spine2_po_lst1]):
        dict = {}
        for i in range(0,4):
            dict[i] = {'local_as':data.bgp_leaf_local_as[i], 'config': 'yes',  'config_type_list':["bfd"], 'remote_as': data.bgp_spine_local_as[j], 'interface' : port_lst1[i]}
        dict_lst = [dict[x] for x in range(0,4)]
        parallel.exec_parallel(True,data.leaf_nodes_list,bgp_obj.config_bgp,dict_lst)

    for ipv6_1,ipv6_2,j in zip(data.leaf_spine1_ipv6_list, data.leaf_spine2_ipv6_list,range(0,4)):
       dict1 = {'local_as':data.bgp_spine_local_as[0], 'config': 'yes',  'config_type_list':["bfd"], 'neighbor' : ipv6_1,'remote_as':data.bgp_leaf_local_as[j]}
       dict2 = {'local_as':data.bgp_spine_local_as[1], 'config': 'yes',  'config_type_list':["bfd"], 'neighbor' : ipv6_2,'remote_as':data.bgp_leaf_local_as[j]}
       parallel.exec_parallel(True,data.spine_nodes_list,bgp_obj.config_bgp,[dict1,dict2])

    for ipv6_lst1,j in zip([data.spine1_ipv6_list,data.spine2_ipv6_list],range(0,2)):
        dict = {}
        for i in range(0,4):
            dict[i] = {'local_as':data.bgp_leaf_local_as[i], 'config': 'yes', 'config_type_list':["bfd"], 'remote_as':data.bgp_spine_local_as[j], 'neighbor' : ipv6_lst1[i]}
        dict_lst = [dict[x] for x in range(0,4)]
        parallel.exec_parallel(True,data.leaf_nodes_list,bgp_obj.config_bgp,dict_lst)

    n1 = get_num_of_bfd_sessions_up(vars.D1)
    n2 = get_num_of_bfd_sessions_up(vars.D2)
    if n1 >= 8 and n2 >= 8:
        st.log('PASS: Total number of BFD sesions found is {} so expected min no of BFD session 8 found in Spine 1'.format(n1))
        st.log('PASS: Total number of BFD sesions found is {} so expected min no of BFD session 8 found in Spine 2'.format(n2))
    else:
        st.error('FAIL: Min number of BFD sesions expected 8 but found {} sessions in Spine 1'.format(n1))
        st.error('FAIL: Min number of BFD sesions expected 8 but found {} sessions in Spine 2'.format(n2))
        st.report_fail("base_config_verification_failed")

def cleanup_evpn_5549():

    make_global_vars()
    global vars
    vars = st.get_testbed_vars()
    ############################################################################################
    hdrMsg("Delete router bgp on dut1 and dut2")
    ############################################################################################
    dict1 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no'}

    parallel.exec_parallel(True, data.spine_nodes_list, bgp_obj.config_bgp, [dict1,dict1])
    parallel.exec_parallel(True, data.leaf_nodes_list, bgp_obj.config_bgp, [dict1,dict1,dict1,dict1])

    ############################################################################################
    hdrMsg("\n####### Unconfigure IP address on link1 of all the DUTs ##############\n")
    ############################################################################################

    utils.exec_all(True, [[ipfeature.config_interface_ip6_link_local, vars.D1, data.spine1_port_list1, 'disable'], [ipfeature.config_interface_ip6_link_local, vars.D2, data.spine2_port_list1, 'disable']])

    utils.exec_all(True, [[ipfeature.config_interface_ip6_link_local, vars.D3, data.leafs_spine1_port_lst1[0], 'disable'], [ipfeature.config_interface_ip6_link_local, vars.D4, data.leafs_spine1_port_lst1[1], 'disable'], [ipfeature.config_interface_ip6_link_local, vars.D5, data.leafs_spine1_port_lst1[2], 'disable'],[ipfeature.config_interface_ip6_link_local, vars.D6, data.leafs_spine1_port_lst1[3], 'disable']])

    utils.exec_all(True, [[ipfeature.config_interface_ip6_link_local, vars.D3, data.leafs_spine2_port_lst1[0], 'disable'], [ipfeature.config_interface_ip6_link_local, vars.D4, data.leafs_spine2_port_lst1[1],'disable'], [ipfeature.config_interface_ip6_link_local, vars.D5, data.leafs_spine2_port_lst1[2],'disable'],[ipfeature.config_interface_ip6_link_local, vars.D6, data.leafs_spine2_port_lst1[3],'disable']])

    ############################################################################################
    hdrMsg("\n########## Unconfigure IP address on link2 (LAG) of all the DUTs ##############\n")
    ############################################################################################

    utils.exec_all(True, [[ipfeature.config_interface_ip6_link_local, vars.D1, data.spine1_po_list, 'disable'], [ipfeature.config_interface_ip6_link_local, vars.D2, data.spine2_po_list, 'disable']])

    utils.exec_all(True, [[ipfeature.config_interface_ip6_link_local, vars.D3, data.leaf1_po_list[0], 'disable'], [ipfeature.config_interface_ip6_link_local, vars.D4, data.leaf2_po_list[0], 'disable'], [ipfeature.config_interface_ip6_link_local, vars.D5, data.leaf3_po_list[0], 'disable'],[ipfeature.config_interface_ip6_link_local, vars.D6, data.leaf4_po_list[0], 'disable']])

    utils.exec_all(True, [[ipfeature.config_interface_ip6_link_local, vars.D3, data.leaf1_po_list[1], 'disable'], [ipfeature.config_interface_ip6_link_local, vars.D4, data.leaf2_po_list[1], 'disable'], [ipfeature.config_interface_ip6_link_local, vars.D5, data.leaf3_po_list[1], 'disable'],[ipfeature.config_interface_ip6_link_local, vars.D6, data.leaf4_po_list[1], 'disable']])

    ############################################################################################
    hdrMsg("\n####### Unconfigure IP address on link3 of all the DUTs ##############\n")
    ############################################################################################

    for ipv6_1,ipv6_2,po1,po2 in zip(data.spine1_ipv6_list, data.spine2_ipv6_list,data.spine1_port_list4, data.spine2_port_list4):
        utils.exec_all(True,[[ipfeature.delete_ip_interface,vars.D1, po1, ipv6_1 , data.maskv6,'ipv6'],[ipfeature.delete_ip_interface,vars.D2, po2, ipv6_2, data.maskv6,'ipv6']])

    utils.exec_all(True,[[ipfeature.delete_ip_interface,vars.D3, data.leafs_spine1_port_lst4[0], data.leaf_spine1_ipv6_list[0], data.maskv6,'ipv6'],[ipfeature.delete_ip_interface,vars.D4, data.leafs_spine1_port_lst4[1], data.leaf_spine1_ipv6_list[1], data.maskv6,'ipv6'], [ipfeature.delete_ip_interface,vars.D5, data.leafs_spine1_port_lst4[2], data.leaf_spine1_ipv6_list[2] , data.maskv6,'ipv6'], [ipfeature.delete_ip_interface,vars.D6, data.leafs_spine1_port_lst4[3], data.leaf_spine1_ipv6_list[3] , data.maskv6,'ipv6']])

    utils.exec_all(True,[[ipfeature.delete_ip_interface,vars.D3, data.leafs_spine2_port_lst4[0], data.leaf_spine2_ipv6_list[0], data.maskv6,'ipv6'],[ipfeature.delete_ip_interface,vars.D4, data.leafs_spine2_port_lst4[1], data.leaf_spine2_ipv6_list[1], data.maskv6,'ipv6'], [ipfeature.delete_ip_interface,vars.D5, data.leafs_spine2_port_lst4[2], data.leaf_spine2_ipv6_list[2], data.maskv6,'ipv6'], [ipfeature.delete_ip_interface,vars.D6, data.leafs_spine2_port_lst4[3], data.leaf_spine2_ipv6_list[3], data.maskv6,'ipv6']])

    ############################################################################################
    hdrMsg("\n########## Delete Port-channel and portchannel members ############\n")
    ############################################################################################

    st.log("Add members to port channel created b/w leaf and spine nodes")
    utils.exec_all(True, [[pch.delete_portchannel_member, data.leaf_nodes_list[0], data.leaf1_po_list[0], data.leaf1_spine1_po_intf_list],
                          [pch.delete_portchannel_member, data.leaf_nodes_list[1], data.leaf2_po_list[0], data.leaf2_spine1_po_intf_list],
                          [pch.delete_portchannel_member, data.leaf_nodes_list[2], data.leaf3_po_list[0], data.leaf3_spine1_po_intf_list],
                          [pch.delete_portchannel_member, data.leaf_nodes_list[3], data.leaf4_po_list[0], data.leaf4_spine1_po_intf_list]])

    utils.exec_all(True, [[pch.delete_portchannel_member, data.leaf_nodes_list[0], data.leaf1_po_list[1], data.leaf1_spine2_po_intf_list],
                          [pch.delete_portchannel_member, data.leaf_nodes_list[1], data.leaf2_po_list[1], data.leaf2_spine2_po_intf_list],
                          [pch.delete_portchannel_member, data.leaf_nodes_list[2], data.leaf3_po_list[1], data.leaf3_spine2_po_intf_list],
                          [pch.delete_portchannel_member, data.leaf_nodes_list[3], data.leaf4_po_list[1], data.leaf4_spine2_po_intf_list]])

    for po1,po2,intf_list1,intf_list2 in zip(data.spine1_po_list,data.spine2_po_list,data.spine1_all_lfs_po_intf_list,data.spine2_all_lfs_po_intf_list):
        utils.exec_all(True, [[pch.delete_portchannel_member, data.spine_nodes_list[0], po1, intf_list1],
                          [pch.delete_portchannel_member, data.spine_nodes_list[1], po2, intf_list2]])

    for i in range(0,2):
        utils.exec_all(True, [[pch.delete_portchannel, data.leaf_nodes_list[0], data.leaf1_po_list[i]],
                    [pch.delete_portchannel, data.leaf_nodes_list[1], data.leaf2_po_list[i]],
                    [pch.delete_portchannel, data.leaf_nodes_list[2], data.leaf3_po_list[i]],
                    [pch.delete_portchannel, data.leaf_nodes_list[3], data.leaf4_po_list[i]]])

    for i in range(0,4):
        utils.exec_all(True,
                    [[pch.delete_portchannel, data.spine_nodes_list[0], data.spine1_po_list[i]],
                    [pch.delete_portchannel, data.spine_nodes_list[1], data.spine2_po_list[i]]])

    ############################################################################################
    hdrMsg(" \n########### Unconfigure loopback interface ##############\n")
    ############################################################################################

    utils.exec_all(True,[[ipfeature.delete_ip_interface, vars.D1, 'Loopback1', data.spine_loopback_list[0], 32, 'ipv4'], [ipfeature.delete_ip_interface, vars.D2, 'Loopback1', data.spine_loopback_list[1], 32, 'ipv4'], [ipfeature.delete_ip_interface, vars.D3, 'Loopback1', data.leaf_loopback_list[0], 32, 'ipv4'], [ipfeature.delete_ip_interface, vars.D4, 'Loopback1', data.leaf_loopback_list[1], 32, 'ipv4'], [ipfeature.delete_ip_interface, vars.D5, 'Loopback1', data.leaf_loopback_list[2], 32, 'ipv4'], [ipfeature.delete_ip_interface, vars.D6, 'Loopback1', data.leaf_loopback_list[3], 32, 'ipv4']])

    dict={}
    for i in range(0,6):
        dict[i] = {'loopback_name':'Loopback1', 'config':'no'}
    dict_lst = [dict[x] for x in range(0,6)]

    parallel.exec_parallel(True,data.spine_nodes_list+data.leaf_nodes_list,ipfeature.configure_loopback,dict_lst)

    ############################################################################################
    hdrMsg("\n########## Disable debugs ############\n")
    ############################################################################################
    disable_debugs()

def hdrMsg(msg):
    st.log("\n######################################################################" \
    " \n%s\n######################################################################"%msg)

def debug_cmds2():
    global vars
    ############################################################################################
    hdrMsg(" \n######### Debugs ##########\n")
    ############################################################################################
    utils.exec_all(True, [[Bgp.show_bgp_ipv4_summary_vtysh, vars.D1], [Bgp.show_bgp_ipv4_summary_vtysh, vars.D2]])
    utils.exec_all(True, [[ip.show_ip_route, vars.D1], [ip.show_ip_route, vars.D2],
                          [ip.show_ip_route, vars.D3],[ip.show_ip_route, vars.D6]])
    utils.exec_all(True, [[ip.show_ip_route, vars.D1, "ipv6"], [ip.show_ip_route, vars.D2, "ipv6"],
                          [ip.show_ip_route, vars.D3, "ipv6"],[ip.show_ip_route, vars.D6, "ipv6"]])

