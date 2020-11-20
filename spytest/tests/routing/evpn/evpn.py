import os

from spytest import st, utils
from spytest.tgen.tg import tgen_obj_dict
from spytest.tgen.tgen_utils import validate_tgen_traffic

import apis.routing.evpn as Evpn
import apis.switching.vlan as Vlan
import apis.switching.portchannel as pch
import apis.system.interface as Intf
import apis.routing.bgp as Bgp
import apis.routing.ip as ip
import apis.routing.vrf as vrf
import apis.switching.pvst as pvst
import apis.common.asic_bcm as asicapi
import apis.switching.mac as Mac
from apis.system import basic
import apis.routing.bfd as Bfd

from utilities import parallel

evpn_dict = {"leaf1" : {"intf_ip_list" : ["13.13.1.1", "13.13.2.1", "13.13.3.1", "13.13.4.1",
                                          "23.23.1.1", "23.23.2.1", "23.23.3.1","23.23.4.1"],
                        "loop_ip_list" : ["3.3.3.1", "3.3.3.2"], "local_as" : "300",
                        "tenant_l2_vlan_list" : ["100","101","102"], "vlan_list" : ["13","23"],
                        "rem_as_list" : ["100","200"], "ve_intf_list" : ["Vlan13","Vlan23"],
                        "pch_intf_list" : ["PortChannel13","PortChannel23"],
                        "l3_vni_list": ["500", "501", "502"],
                        "tenant_l3_vlan_list": ["300", "301", "302"],
                        "l3_vni_name_list": ["Vlan500", "Vlan501", "Vlan502"],
                        "l3_vni_ip_list": ["33.33.1.1", "33.33.2.1", "33.33.3.1"],
                        "l3_vni_ipmask_list": ["24", "24", "24"],
                        "l3_vni_ip_net" : ["33.33.1.0/24","33.33.2.0/24","33.33.3.0/24"],
                        "l3_tenant_ip_list": ["30.1.1.1", "30.1.2.1", "30.1.3.1"],
                        "l3_tenant_ip_net" : ["30.1.1.0/24","30.1.2.0/24","30.1.3.0/24"],
                        "l3_vni_ipv6_list": ["3301::1", "3302::1", "3303::1"],
                        "l3_vni_ipv6_net" : ["3301::/96", "3302::/96", "3303::/96"],
                        "l3_vni_ipv6mask_list": ["96", "96", "96"],
                        "l3_tenant_ipv6_list": ["3001::1", "3002::1", "3003::1"],
                        "l3_tenant_ipv6_net" : ["3001::/96","3002::/96","3003::/96/24"],
                        "vrf_name_list": ["Vrf1", "Vrf2", "Vrf3"],
                        "tenant_l2_vlan_name_list": ["Vlan100", "Vlan101", "Vlan102"],
                        "vtepName" : "vtepLeaf1", "nvoName" : "nvoLeaf1",
                        "tenant_mac_l2": "00.02.33.00.00.01", "tenant_mac_v4": "00.04.33.00.00.01",
                        "tenant_mac_v6": "00.06.33.00.00.01","tenant_v4_ip": "30.1.1.2", "tenant_v6_ip": "3001::2"},
             "leaf2" : {"intf_ip_list" : ["14.14.1.1", "14.14.2.1", "14.14.3.1", "14.14.4.1",
                                          "24.24.1.1", "24.24.2.1", "24.24.3.1","24.24.4.1"],
                        "loop_ip_list" : ["4.4.4.1", "4.4.4.2"], "local_as" : "400",
                        "tenant_l2_vlan_list" : ["100","101","102"], "vlan_list" : ["14","24"],
                        "rem_as_list" : ["100","200"], "ve_intf_list" : ["Vlan14","Vlan24"],
                        "pch_intf_list" : ["PortChannel14","PortChannel24"],
                        "l3_vni_list": ["500", "501", "502"],
                        "tenant_l3_vlan_list": ["400", "401", "402"],
                        "l3_vni_name_list": ["Vlan500", "Vlan501", "Vlan502"],
                        "l3_vni_ip_list": ["44.44.1.1", "44.44.2.1", "44.44.3.1"],
                        "l3_vni_ipmask_list": ["24", "24", "24"],
                        "l3_vni_ip_net" : ["44.44.1.0/24","44.44.2.0/24","44.44.3.0/24"],
                        "l3_tenant_ip_list": ["40.1.1.1", "40.1.2.1", "40.1.3.1"],
                        "l3_tenant_ip_net" : ["40.1.1.0/24","40.1.2.0/24","40.1.3.0/24"],
                        "l3_vni_ipv6_list": ["4401::1", "4402::1", "4403::1"],
                        "l3_vni_ipv6_net" : ["4401::/96", "4402::/96", "4403::/96"],
                        "l3_vni_ipv6mask_list": ["96", "96", "96"],
                        "l3_tenant_ipv6_list": ["4001::1", "4002::1", "4003::1"],
                        "l3_tenant_ipv6_net" : ["4001::/96","4002::/96","4003::/96/24"],
                        "vrf_name_list": ["Vrf1", "Vrf2", "Vrf3"],
                        "tenant_l2_vlan_name_list": ["Vlan100", "Vlan101", "Vlan102"],
                        "vtepName" : "vtepLeaf2", "nvoName" : "nvoLeaf2",
                        "tenant_mac_l2" : "00.02.44.00.00.01", "tenant_mac_v4": "00.04.44.00.00.01",
                        "tenant_mac_v6" : "00.06.44.00.00.01", "tenant_v4_ip" : "40.1.1.2",
                        "tenant_v6_ip" : "4001::2"},
             "leaf3" : {"intf_ip_list" : ["15.15.1.1", "15.15.2.1", "15.15.3.1", "15.15.4.1",
                                          "25.25.1.1", "25.25.2.1", "25.25.3.1","25.25.4.1"],
                        "loop_ip_list" : ["5.5.5.1", "5.5.5.2"], "local_as" : "500",
                        "tenant_l2_vlan_list" : ["100","101","102"], "vlan_list" : ["15","25"],
                        "rem_as_list" : ["100","200"], "ve_intf_list" : ["Vlan15","Vlan25"],
                        "pch_intf_list" : ["PortChannel15","PortChannel25"],
                        "l3_vni_list": ["500", "501", "502"],
                        "tenant_l3_vlan_list": ["510", "511", "512"],
                        "l3_vni_name_list": ["Vlan500", "Vlan501", "Vlan502"],
                        "l3_vni_ip_list": ["55.55.1.1", "55.55.2.1", "55.55.3.1"],
                        "l3_vni_ipmask_list": ["24", "24", "24"],
                        "l3_vni_ip_net" : ["55.55.1.0/24","55.55.2.0/24","55.55.3.0/24"],
                        "l3_tenant_ip_list": ["50.1.1.1", "50.1.2.1", "50.1.3.1"],
                        "l3_tenant_ip_net" : ["50.1.1.0/24","50.1.2.0/24","50.1.3.0/24"],
                        "l3_vni_ipv6_list": ["5501::1", "5502::1", "5503::1"],
                        "l3_vni_ipv6_net" : ["5501::/96", "5502::/96", "5503::/96"],
                        "l3_vni_ipv6mask_list": ["96", "96", "96"],
                        "l3_tenant_ipv6_list": ["5001::1", "5002::1", "5003::1"],
                        "l3_tenant_ipv6_net" : ["5001::/96","5002::/96","5003::/96/24"],
                        "vrf_name_list": ["Vrf1", "Vrf2", "Vrf3"],
                        "tenant_l2_vlan_name_list": ["Vlan100", "Vlan101", "Vlan102"],
                        "vtepName" : "vtepLeaf3", "nvoName" : "nvoLeaf3",
                        "tenant_mac_l2": "00.02.55.00.00.01", "tenant_mac_l2_2": "00.03.55.00.00.01", "tenant_mac_v4" : "00.04.55.00.00.01",
                        "tenant_mac_v6" : "00.06.55.00.00.01", "tenant_v4_ip": "50.1.1.2",
                        "tenant_v6_ip": "5001::2","tenant_mac_l2_colon": "00:02:55:00:00:01"},
             "leaf4" : {"intf_ip_list" : ["16.16.1.1", "16.16.2.1", "16.16.3.1", "16.16.4.1",
                                          "26.26.1.1", "26.26.2.1", "26.26.3.1","26.26.4.1"],
                        "loop_ip_list" : ["6.6.6.1", "6.6.6.2"], "local_as" : "600",
                        "tenant_l2_vlan_list" : ["100","101","102"], "vlan_list" : ["16","26"],
                        "rem_as_list" : ["100","200"], "ve_intf_list" : ["Vlan16","Vlan26"],
                        "pch_intf_list" : ["PortChannel16","PortChannel26"],
                        "l3_vni_list": ["500", "501", "502"],
                        "tenant_l3_vlan_list": ["600", "601", "602"],
                        "l3_vni_name_list": ["Vlan500", "Vlan501", "Vlan502"],
                        "l3_vni_ip_list": ["66.66.1.1", "66.66.2.1", "66.66.3.1"],
                        "l3_vni_ipmask_list": ["24", "24", "24"],
                        "l3_vni_ip_net" : ["66.66.1.0/24","66.66.2.0/24","66.66.3.0/24"],
                        "l3_tenant_ip_list": ["60.1.1.1", "60.1.2.1", "60.1.3.1"],
                        "l3_tenant_ip_net" : ["60.1.1.0/24","60.1.2.0/24","60.1.3.0/24"],
                        "l3_vni_ipv6_list": ["6601::1", "6602::1", "6603::1"],
                        "l3_vni_ipv6_net" : ["6601::/96", "6602::/96", "6603::/96"],
                        "l3_vni_ipv6mask_list": ["96", "96", "96"],
                        "l3_tenant_ipv6_list": ["6001::1", "6002::1", "6003::1"],
                        "l3_tenant_ipv6_net" : ["6001::/96","6002::/96","6003::/96/24"],
                        "vrf_name_list": ["Vrf1", "Vrf2", "Vrf3"],
                        "tenant_l2_vlan_name_list": ["Vlan100", "Vlan101", "Vlan102"],
                        "vtepName" : "vtepLeaf4", "nvoName" : "nvoLeaf4",
                        "tenant_mac_l2": "00.02.66.00.00.01", "tenant_mac_l2_2": "00.03.66.00.00.01", "tenant_mac_v4" : "00.04.66.00.00.01",
                        "tenant_mac_v6" : "00.06.66.00.00.01", "tenant_v4_ip": "60.1.1.2",
                        "tenant_v6_ip": "6001::2","tenant_mac_l2_colon": "00:02:66:00:00:01"
                        },
             "spine1": {"intf_ip_list": ["13.13.1.0", "13.13.2.0", "13.13.3.0", "13.13.4.0",
                                         "14.14.1.0", "14.14.2.0", "14.14.3.0", "14.14.4.0",
                                         "15.15.1.0", "15.15.2.0", "15.15.3.0", "15.15.4.0",
                                         "16.16.1.0", "16.16.2.0", "16.16.3.0", "16.16.4.0"], "local_as" : "100",
                        "loop_ip_list" : ["1.1.1.1", "1.1.1.2"], "vlan_list" : ["13","14","15","16"],
                        "rem_as_list" : ["300","400","500","600"],
                        "ve_intf_list" : ["Vlan13","Vlan14","Vlan15","Vlan16"],
                        "pch_intf_list" : ["PortChannel13","PortChannel14","PortChannel15","PortChannel16"]},
             "spine2" : {"intf_ip_list" : ["23.23.1.0", "23.23.2.0", "23.23.3.0","23.23.4.0",
                                           "24.24.1.0", "24.24.2.0", "24.24.3.0","24.24.4.0",
                                           "25.25.1.0", "25.25.2.0", "25.25.3.0","25.25.4.0",
                                           "26.26.1.0", "26.26.2.0", "26.26.3.0","26.26.4.0"], "local_as" : "200",
                        "loop_ip_list" : ["2.2.2.1", "2.2.2.2"], "vlan_list" : ["23","24","25","26"],
                        "rem_as_list" : ["300","400","500","600"],
                        "ve_intf_list" : ["Vlan23","Vlan24","Vlan25","Vlan26"],
                        "pch_intf_list" : ["PortChannel23","PortChannel24","PortChannel25","PortChannel26"]}
             }


vrf_input1 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0]}
vrf_input2 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],"config":"no"}

vrf_bind1 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
             "intf_name":evpn_dict["leaf1"]["l3_vni_name_list"][0],"skip_error":"yes"}
vrf_bind2 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],
             "intf_name":evpn_dict["leaf2"]["l3_vni_name_list"][0],"skip_error":"yes"}
vrf_bind3 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
             "intf_name":evpn_dict["leaf3"]["l3_vni_name_list"][0],"skip_error":"yes"}
vrf_bind4 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
             "intf_name":evpn_dict["leaf4"]["l3_vni_name_list"][0],"skip_error":"yes"}

vrf_bind5 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
              "intf_name":evpn_dict["leaf1"]["l3_vni_name_list"][0],"skip_error":"yes","config":"no"}
vrf_bind6 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],
              "intf_name":evpn_dict["leaf2"]["l3_vni_name_list"][0],"skip_error":"yes","config":"no"}
vrf_bind7 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
              "intf_name":evpn_dict["leaf3"]["l3_vni_name_list"][0],"skip_error":"yes","config":"no"}
vrf_bind8 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
              "intf_name":evpn_dict["leaf4"]["l3_vni_name_list"][0],"skip_error":"yes","config":"no"}

vrf_bind9  = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],"skip_error":"yes"}
vrf_bind10 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],"skip_error":"yes"}
vrf_bind11 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],"skip_error":"yes"}
vrf_bind12 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],"skip_error":"yes"}

vrf_bind13 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}
vrf_bind14 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}
vrf_bind15 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}
vrf_bind16 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}

vrf_vni1 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
            "vni":evpn_dict["leaf1"]["l3_vni_list"][0]}
vrf_vni2 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
            "vni":evpn_dict["leaf1"]["l3_vni_list"][0],"config":"no"}

bgp_in1 = {"router_id": evpn_dict['spine1']['loop_ip_list'][0], "local_as": evpn_dict['spine1']['local_as'],
              "config_type_list": ["multipath-relax"]}
bgp_in2 = {"router_id": evpn_dict['spine2']['loop_ip_list'][0], "local_as": evpn_dict['spine2']['local_as'],
              "config_type_list": ["multipath-relax"]}
bgp_in3 = {"router_id": evpn_dict['leaf1']['loop_ip_list'][0], "local_as": evpn_dict['leaf1']['local_as'],
              "config_type_list": ["multipath-relax"]}
bgp_in4 = {"router_id": evpn_dict['leaf2']['loop_ip_list'][0], "local_as": evpn_dict['leaf2']['local_as'],
              "config_type_list": ["multipath-relax"]}
bgp_in5 = {"router_id": evpn_dict['leaf3']['loop_ip_list'][0], "local_as": evpn_dict['leaf3']['local_as'],
              "config_type_list": ["multipath-relax"]}
bgp_in6 = {"router_id": evpn_dict['leaf4']['loop_ip_list'][0], "local_as": evpn_dict['leaf4']['local_as'],
              "config_type_list": ["multipath-relax"]}

bgp_input1 = {"router_id": evpn_dict['spine1']['loop_ip_list'][0], "local_as": evpn_dict['spine1']['local_as'],
              "neighbor": evpn_dict["leaf1"]["loop_ip_list"][0], "ebgp_mhop": '2',
              "config_type_list": ["neighbor", "redist", "ebgp_mhop","update_src","connect"],
              "remote_as": evpn_dict['spine1']['rem_as_list'][0],"connect":'1',
              "redistribute": "connected", "update_src": evpn_dict['spine1']['loop_ip_list'][0],"keepalive":'3',"holdtime":"9"}

bgp_input2 = {"router_id": evpn_dict['spine2']['loop_ip_list'][0], "local_as": evpn_dict['spine2']['local_as'],
              "neighbor": evpn_dict["leaf1"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
              "config_type_list": ["neighbor", "redist", "ebgp_mhop","update_src","connect"],
              "remote_as": evpn_dict['spine2']['rem_as_list'][0], "redistribute": "connected",
              "update_src": evpn_dict['spine2']['loop_ip_list'][0],"keepalive":'3',"holdtime":"9"}

bgp_input3 = {"router_id": evpn_dict['leaf1']['loop_ip_list'][0], "local_as": evpn_dict['leaf1']['local_as'],
              "neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "remote_as": evpn_dict['leaf1']['rem_as_list'][0], "redistribute": "connected",
              "update_src": evpn_dict['leaf1']['loop_ip_list'][0],"keepalive":'3',"holdtime":"9"}

bgp_input4 = {"router_id": evpn_dict['leaf2']['loop_ip_list'][0], "local_as": evpn_dict['leaf2']['local_as'],
              "neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "remote_as": evpn_dict['leaf2']['rem_as_list'][0], "redistribute": "connected",
              "update_src": evpn_dict['leaf2']['loop_ip_list'][0],"keepalive":'3',"holdtime":"9"}

bgp_input5 = {"router_id": evpn_dict['leaf3']['loop_ip_list'][0], "local_as": evpn_dict['leaf3']['local_as'],
              "neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "remote_as": evpn_dict['leaf3']['rem_as_list'][0], "redistribute": "connected",
              "update_src": evpn_dict['leaf3']['loop_ip_list'][0],"keepalive":'3',"holdtime":"9"}

bgp_input6 = {"router_id": evpn_dict['leaf4']['loop_ip_list'][0], "local_as": evpn_dict['leaf4']['local_as'],
              "neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "remote_as": evpn_dict['leaf4']['rem_as_list'][0], "redistribute": "connected",
              "update_src": evpn_dict['leaf4']['loop_ip_list'][0],"keepalive":'3',"holdtime":"9"}

bgp_input7 = {"neighbor": evpn_dict["leaf2"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "update_src": evpn_dict['spine1']['loop_ip_list'][0],"local_as": evpn_dict['spine1']['local_as'],
              "remote_as": evpn_dict['spine1']['rem_as_list'][1],"keepalive":'3',"holdtime":"9"}

bgp_input8 = {"neighbor": evpn_dict["leaf2"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "update_src": evpn_dict['spine2']['loop_ip_list'][0],"local_as": evpn_dict['spine2']['local_as'],
              "remote_as": evpn_dict['spine2']['rem_as_list'][1],"keepalive":'3',"holdtime":"9"}

bgp_input9 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "update_src": evpn_dict['leaf1']['loop_ip_list'][0],"local_as": evpn_dict['leaf1']['local_as'],
              "remote_as": evpn_dict['leaf1']['rem_as_list'][1],"keepalive":'3',"holdtime":"9"}

bgp_input10 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
               "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
               "update_src": evpn_dict['leaf2']['loop_ip_list'][0],"local_as": evpn_dict['leaf2']['local_as'],
               "remote_as": evpn_dict['leaf2']['rem_as_list'][1],"keepalive":'3',"holdtime":"9"}

bgp_input11 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
               "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
               "update_src": evpn_dict['leaf3']['loop_ip_list'][0],"local_as": evpn_dict['leaf3']['local_as'],
               "remote_as": evpn_dict['leaf3']['rem_as_list'][1],"keepalive":'3',"holdtime":"9"}

bgp_input12 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
               "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
               "update_src": evpn_dict['leaf4']['loop_ip_list'][0],"local_as": evpn_dict['leaf4']['local_as'],
               "remote_as": evpn_dict['leaf4']['rem_as_list'][1],"keepalive":'3',"holdtime":"9"}

bgp_input13 = {"neighbor": evpn_dict["leaf3"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
               "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
               "update_src": evpn_dict['spine1']['loop_ip_list'][0],"local_as": evpn_dict['spine1']['local_as'],
               "remote_as": evpn_dict['spine1']['rem_as_list'][2],"keepalive":'3',"holdtime":"9"}

bgp_input14 = {"neighbor": evpn_dict["leaf3"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
               "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
               "update_src": evpn_dict['spine2']['loop_ip_list'][0],"local_as": evpn_dict['spine2']['local_as'],
               "remote_as": evpn_dict['spine2']['rem_as_list'][2],"keepalive":'3',"holdtime":"9"}

bgp_input15 = {"neighbor": evpn_dict["leaf4"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
               "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
               "update_src": evpn_dict['spine1']['loop_ip_list'][0],"local_as": evpn_dict['spine1']['local_as'],
               "remote_as": evpn_dict['spine1']['rem_as_list'][3],"keepalive":'3',"holdtime":"9"}

bgp_input16 = {"neighbor": evpn_dict["leaf4"]["loop_ip_list"][0], "ebgp_mhop": '2',"connect":'1',
               "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
               "update_src": evpn_dict['spine2']['loop_ip_list'][0],"local_as": evpn_dict['spine2']['local_as'],
               "remote_as": evpn_dict['spine2']['rem_as_list'][3],"keepalive":'3',"holdtime":"9"}

bgp_input17 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['spine1']['local_as'],
               "config" : "no", "removeBGP" : "yes"}

bgp_input18 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['spine2']['local_as'],
               "config" : "no", "removeBGP" : "yes"}

bgp_input19 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf1']['local_as'],
               "config" : "no", "removeBGP" : "yes"}

bgp_input20 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf2']['local_as'],
               "config" : "no", "removeBGP" : "yes"}

bgp_input21 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf3']['local_as'],
               "config" : "no", "removeBGP" : "yes"}

bgp_input22 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf4']['local_as'],
               "config" : "no", "removeBGP" : "yes"}

bgp_input23 = {'local_as': evpn_dict['leaf1']['local_as'],'config' : 'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf1"]["vrf_name_list"][0]}
bgp_input24 = {'local_as': evpn_dict['leaf2']['local_as'],'config' : 'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf2"]["vrf_name_list"][0]}
bgp_input25 = {'local_as': evpn_dict['leaf3']['local_as'],'config' : 'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0]}
bgp_input26 = {'local_as': evpn_dict['leaf4']['local_as'],'config' : 'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0]}

bgp_input27 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf1']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf1"]["vrf_name_list"][0]}
bgp_input28 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf2']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf2"]["vrf_name_list"][0]}
bgp_input29 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf3']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf3"]["vrf_name_list"][0]}
bgp_input30 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf4']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf4"]["vrf_name_list"][0]}

bgp_input31 = {"config_type_list" :["network"],"local_as": evpn_dict['leaf1']['local_as'],
               "network":evpn_dict["leaf1"]["loop_ip_list"][1]+'/32',"config" : "yes"}
bgp_input32 = {"config_type_list" :["network"],"local_as": evpn_dict['leaf2']['local_as'],
               "network":evpn_dict["leaf2"]["loop_ip_list"][1]+'/32',"config" : "yes"}
bgp_input33 = {"config_type_list" :["network"],"local_as": evpn_dict['leaf3']['local_as'],
               "network":evpn_dict["leaf3"]["loop_ip_list"][1]+'/32',"config" : "yes"}
bgp_input34 = {"config_type_list" :["network"],"local_as": evpn_dict['leaf4']['local_as'],
               "network":evpn_dict["leaf4"]["loop_ip_list"][1]+'/32',"config" : "yes"}

bgp_input35 = {'local_as': evpn_dict['leaf1']['local_as'],'config' : 'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf1"]["vrf_name_list"][0],'addr_family':'ipv6'}
bgp_input36 = {'local_as': evpn_dict['leaf2']['local_as'],'config' : 'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf2"]["vrf_name_list"][0],'addr_family':'ipv6'}
bgp_input37 = {'local_as': evpn_dict['leaf3']['local_as'],'config' : 'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0],'addr_family':'ipv6'}
bgp_input38 = {'local_as': evpn_dict['leaf4']['local_as'],'config' : 'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0],'addr_family':'ipv6'}

bgp_input39 = {"config_type_list" :["import-check"],"local_as": evpn_dict['leaf1']['local_as'],"config" : "yes"}
bgp_input40 = {"config_type_list" :["import-check"],"local_as": evpn_dict['leaf2']['local_as'],"config" : "yes"}
bgp_input41 = {"config_type_list" :["import-check"],"local_as": evpn_dict['leaf3']['local_as'],"config" : "yes"}
bgp_input42 = {"config_type_list" :["import-check"],"local_as": evpn_dict['leaf4']['local_as'],"config" : "yes"}

evpn_input1 = {"neighbor": evpn_dict["leaf1"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["leaf1"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['spine1']['local_as']}

evpn_in1 = {"neighbor": evpn_dict["leaf1"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["leaf1"]["local_as"],
               "config_type_list": ["advertise_all_vni"],"local_as": evpn_dict['spine1']['local_as']}

evpn_input1_1 = {"neighbor": evpn_dict["leaf1"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["leaf1"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['spine2']['local_as']}

evpn_in2 = {"neighbor": evpn_dict["leaf1"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["leaf1"]["local_as"],
               "config_type_list": ["advertise_all_vni"],"local_as": evpn_dict['spine2']['local_as']}

evpn_input2 = {"neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["spine1"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['leaf1']['local_as']}

evpn_in3 = {"neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["spine1"]["local_as"],
               "config_type_list": ["advertise_all_vni"],"local_as": evpn_dict['leaf1']['local_as']}

evpn_input2_1 = {"neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["spine1"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['leaf2']['local_as']}

evpn_in4 = {"neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["spine1"]["local_as"],
               "config_type_list": ["advertise_all_vni"],"local_as": evpn_dict['leaf2']['local_as']}

evpn_input2_2 = {"neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["spine1"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['leaf3']['local_as']}

evpn_in5 = {"neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["spine1"]["local_as"],
               "config_type_list": ["advertise_all_vni"],"local_as": evpn_dict['leaf3']['local_as']}

evpn_input2_3 = {"neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["spine1"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['leaf4']['local_as']}

evpn_in6 = {"neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["spine1"]["local_as"],
               "config_type_list": ["advertise_all_vni"],"local_as": evpn_dict['leaf4']['local_as']}

evpn_input3 = {"neighbor": evpn_dict["leaf2"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["leaf2"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['spine1']['local_as']}

evpn_input3_1 = {"neighbor": evpn_dict["leaf2"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["leaf2"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['spine2']['local_as']}

evpn_input4 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["spine2"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['leaf1']['local_as']}

evpn_input4_1 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["spine2"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['leaf2']['local_as']}

evpn_input4_2 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["spine2"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['leaf3']['local_as']}

evpn_input4_3 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["spine2"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['leaf4']['local_as']}

evpn_input5 = {"neighbor": evpn_dict["leaf3"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["leaf3"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['spine1']['local_as']}

evpn_input5_1 = {"neighbor": evpn_dict["leaf3"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["leaf3"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['spine2']['local_as']}

evpn_input6 = {"neighbor": evpn_dict["leaf4"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["leaf4"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['spine1']['local_as']}

evpn_input6_1 = {"neighbor": evpn_dict["leaf4"]["loop_ip_list"][0], "config": "yes","remote_as": evpn_dict["leaf4"]["local_as"],
               "config_type_list": ["activate"],"local_as": evpn_dict['spine2']['local_as']}

evpn_input13 = {'config' : 'yes','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf1"]["vrf_name_list"][0],"local_as": evpn_dict['leaf1']['local_as'],
                'l3_vni_id':evpn_dict["leaf1"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf1"]["vtepName"]}
evpn_input14 = {'config' : 'yes','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf2"]["vrf_name_list"][0],"local_as": evpn_dict['leaf2']['local_as'],
                'l3_vni_id':evpn_dict["leaf2"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf2"]["vtepName"]}
evpn_input15 = {'config' : 'yes','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0],"local_as": evpn_dict['leaf3']['local_as'],
                'l3_vni_id':evpn_dict["leaf3"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf3"]["vtepName"]}
evpn_input16 = {'config' : 'yes','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0],"local_as": evpn_dict['leaf4']['local_as'],
                'l3_vni_id':evpn_dict["leaf4"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf4"]["vtepName"]}

evpn_input17 = {'config' : 'remove_vrf','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf1"]["vrf_name_list"][0],
                'l3_vni_id':evpn_dict["leaf1"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf1"]["vtepName"]}
evpn_input18 = {'config' : 'remove_vrf','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf2"]["vrf_name_list"][0],
                'l3_vni_id':evpn_dict["leaf2"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf2"]["vtepName"]}
evpn_input19 = {'config' : 'remove_vrf','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0],
                'l3_vni_id':evpn_dict["leaf3"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf3"]["vtepName"]}
evpn_input20 = {'config' : 'remove_vrf','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0],
                'l3_vni_id':evpn_dict["leaf4"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf4"]["vtepName"]}

evpn_input21 = {'local_as': evpn_dict['leaf1']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf1"]["vrf_name_list"][0]}
evpn_input22 = {'local_as': evpn_dict['leaf2']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf2"]["vrf_name_list"][0]}
evpn_input23 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0]}
evpn_input24 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0]}

evpn_input25 = {'config' : 'remove_vrf','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf1"]["vrf_name_list"][0],"local_as": evpn_dict['leaf1']['local_as'],
                'l3_vni_id':evpn_dict["leaf1"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf1"]["vtepName"]}
evpn_input26 = {'config' : 'remove_vrf','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf2"]["vrf_name_list"][0],"local_as": evpn_dict['leaf2']['local_as'],
                'l3_vni_id':evpn_dict["leaf2"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf2"]["vtepName"]}
evpn_input27 = {'config' : 'remove_vrf','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0],"local_as": evpn_dict['leaf3']['local_as'],
                'l3_vni_id':evpn_dict["leaf3"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf3"]["vtepName"]}
evpn_input28 = {'config' : 'remove_vrf','config_type_list':["vrf_vni"],
                'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0],"local_as": evpn_dict['leaf4']['local_as'],
                'l3_vni_id':evpn_dict["leaf4"]["l3_vni_list"][0], "vtep_name":evpn_dict["leaf4"]["vtepName"]}

evpn_input29 = {"config": "no","config_type_list": ["advertise_all_vni"]}

evpn_input30 = {'local_as': evpn_dict['leaf1']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf1"]["vrf_name_list"][0]}
evpn_input31 = {'local_as': evpn_dict['leaf2']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf2"]["vrf_name_list"][0]}
evpn_input32 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0]}
evpn_input33 = {'local_as': evpn_dict['leaf4']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf4"]["vrf_name_list"][0]}

evpn_verify1 = {"identifier": evpn_dict["spine1"]["loop_ip_list"][0],
                "neighbor": [evpn_dict["leaf1"]["loop_ip_list"][0], evpn_dict["leaf2"]["loop_ip_list"][0],
                             evpn_dict["leaf3"]["loop_ip_list"][0], evpn_dict["leaf4"]["loop_ip_list"][0]],
                "updown": ["up", "up", "up", "up"]}
evpn_verify2 = {"identifier": evpn_dict["spine2"]["loop_ip_list"][0],
                "neighbor": [evpn_dict["leaf1"]["loop_ip_list"][0], evpn_dict["leaf2"]["loop_ip_list"][0],
                             evpn_dict["leaf3"]["loop_ip_list"][0], evpn_dict["leaf4"]["loop_ip_list"][0]],
                "updown": ["up", "up", "up", "up"]}
evpn_verify3 = {"identifier": evpn_dict["leaf1"]["loop_ip_list"][0],
                "neighbor": [evpn_dict["spine1"]["loop_ip_list"][0], evpn_dict["spine2"]["loop_ip_list"][0]],
                "updown": ["up", "up"]}
evpn_verify4 = {"identifier": evpn_dict["leaf2"]["loop_ip_list"][0],
                "neighbor": [evpn_dict["spine1"]["loop_ip_list"][0], evpn_dict["spine2"]["loop_ip_list"][0]],
                "updown": ["up", "up"]}
evpn_verify5 = {"identifier": evpn_dict["leaf3"]["loop_ip_list"][0],
                "neighbor": [evpn_dict["spine1"]["loop_ip_list"][0], evpn_dict["spine2"]["loop_ip_list"][0]],
                "updown": ["up", "up"]}
evpn_verify6 = {"identifier": evpn_dict["leaf4"]["loop_ip_list"][0],
                "neighbor": [evpn_dict["spine1"]["loop_ip_list"][0], evpn_dict["spine2"]["loop_ip_list"][0]],
                "updown": ["up", "up"]}
stream_dict = {}
count = 1
#d5_tg_port1,d6_tg_port1 = "",""
tg_dict = {}
han_dict = {}
current_stream_dict = {}


def create_glob_vars():
    global vars, tg, d3_tg_ph1, d3_tg_ph2, d4_tg_ph1, d4_tg_ph2, d5_tg_ph1, d5_tg_ph2, d6_tg_ph1, d6_tg_ph2
    global d4_tg_port1, d5_tg_port1,d6_tg_port1
    vars = st.ensure_min_topology("D1D3:4","D1D4:4","D1D5:2","D1D6:4",
                                  "D2D3:4","D2D4:4","D2D5:4","D2D6:4",
                                  "D3T1:2","D4T1:2","D5T1:2","D6T1:2",
                                  "D3CHIP:TD3", "D4CHIP:TD3", "D5CHIP:TD3", "D6CHIP:TD3")

    tg = tgen_obj_dict[vars['tgen_list'][0]]
    d3_tg_ph1, d3_tg_ph2 = tg.get_port_handle(vars.T1D3P1), tg.get_port_handle(vars.T1D3P2)
    d4_tg_ph1, d4_tg_ph2 = tg.get_port_handle(vars.T1D4P1), tg.get_port_handle(vars.T1D4P2)
    d5_tg_ph1, d5_tg_ph2 = tg.get_port_handle(vars.T1D5P1), tg.get_port_handle(vars.T1D5P2)
    d6_tg_ph1, d6_tg_ph2 = tg.get_port_handle(vars.T1D6P1), tg.get_port_handle(vars.T1D6P2)
    d4_tg_port1,d5_tg_port1,d6_tg_port1 = vars.T1D4P1, vars.T1D5P1, vars.T1D6P1

    tg_dict['tg'] = tgen_obj_dict[vars['tgen_list'][0]]
    tg_dict['d3_tg_ph1'],tg_dict['d3_tg_ph2'] = tg.get_port_handle(vars.T1D3P1),tg.get_port_handle(vars.T1D3P2)
    tg_dict['d4_tg_ph1'],tg_dict['d4_tg_ph2'] = tg.get_port_handle(vars.T1D4P1),tg.get_port_handle(vars.T1D4P2)
    tg_dict['d5_tg_ph1'],tg_dict['d5_tg_ph2'] = tg.get_port_handle(vars.T1D5P1),tg.get_port_handle(vars.T1D5P2)
    tg_dict['d6_tg_ph1'],tg_dict['d6_tg_ph2'] = tg.get_port_handle(vars.T1D6P1),tg.get_port_handle(vars.T1D6P2)
    tg_dict['d5_tg_port1'],tg_dict['d6_tg_port1'] = vars.T1D5P1, vars.T1D6P1
    tg_dict['d3_tg_port1'],tg_dict['d4_tg_port1'] = vars.T1D3P1, vars.T1D4P1
    tg_dict['tgen_rate_pps'] = '1000'
    tg_dict['frame_size'] = '1000'
    tg_dict['dut_6_mac_pattern'] = '00:02:66:00:00:'
    tg_dict['d5_tg_local_as'] = '50'
    tg_dict['d6_tg_local_as'] = '60'
    tg_dict['num_routes_1'] = '100'
    tg_dict['prefix_1'] = '100.1.1.0'
    tg_dict['prefix_2'] = '200.1.1.0'

    evpn_dict["leaf_node_list"] = [vars.D3, vars.D4, vars.D5, vars.D6]
    evpn_dict["mlag_node_list"] = [vars.D3, vars.D4]
    evpn_dict["spine_node_list"] = [vars.D1, vars.D2]
#    evpn_dict["mclag_node"] = [vars.D7]
    evpn_dict["bgp_node_list"] = [vars.D1, vars.D2, vars.D3, vars.D4, vars.D5, vars.D6]
    evpn_dict["leaf1"]["intf_list_spine"] = [vars.D3D1P1, vars.D3D1P2, vars.D3D1P3, vars.D3D1P4,
                                          vars.D3D2P1, vars.D3D2P2, vars.D3D2P3, vars.D3D2P4]
    evpn_dict["leaf1"]["intf_list_tg"] = [vars.D3T1P1, vars.D3T1P2]
    evpn_dict["leaf2"]["intf_list_spine"] = [vars.D4D1P1, vars.D4D1P2, vars.D4D1P3, vars.D4D1P4,
                                          vars.D4D2P1, vars.D4D2P2, vars.D4D2P3, vars.D4D2P4]
    evpn_dict["leaf2"]["intf_list_tg"] = [vars.D4T1P1, vars.D4T1P2]
    evpn_dict["leaf3"]["intf_list_spine"] = [vars.D5D1P1, vars.D5D1P2, vars.D5D1P3, vars.D5D1P4,
                                          vars.D5D2P1, vars.D5D2P2, vars.D5D2P3, vars.D5D2P4]
    evpn_dict["leaf3"]["intf_list_tg"] = [vars.D5T1P1, vars.D5T1P2]
    evpn_dict["leaf4"]["intf_list_spine"] = [vars.D6D1P1, vars.D6D1P2, vars.D6D1P3, vars.D6D1P4,
                                          vars.D6D2P1, vars.D6D2P2, vars.D6D2P3, vars.D6D2P4]
    evpn_dict["leaf4"]["intf_list_tg"] = [vars.D6T1P1, vars.D6T1P2]
    evpn_dict["spine1"]["intf_list_leaf"] = [vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4,
                                             vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4,
                                             vars.D1D5P1, vars.D1D5P2, vars.D1D5P3, vars.D1D5P4,
                                             vars.D1D6P1, vars.D1D6P2, vars.D1D6P3, vars.D1D6P4]
    evpn_dict["spine2"]["intf_list_leaf"] = [vars.D2D3P1, vars.D2D3P2, vars.D2D3P3, vars.D2D3P4,
                                             vars.D2D4P1, vars.D2D4P2, vars.D2D4P3, vars.D2D4P4,
                                             vars.D2D5P1, vars.D2D5P2, vars.D2D5P3, vars.D2D5P4,
                                             vars.D2D6P1, vars.D2D6P2, vars.D2D6P3, vars.D2D6P4]
    evpn_dict["leaf_base_mac_list"] = pvst.get_duts_mac_address(evpn_dict["leaf_node_list"])
    evpn_dict["dut5_gw_mac"] = basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac']
    evpn_dict["dut6_gw_mac"] = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']

    for key in evpn_dict["leaf_base_mac_list"]:
        evpn_dict["leaf_base_mac_list"][key]=convert_base_mac(evpn_dict["leaf_base_mac_list"][key])

    evpn_dict["ipv4_static_route"] = "123.1.1.0/24"
    evpn_dict["ipv6_static_route"] = "1230::/96"

    if os.getenv("SPYTEST_FORCE_CLICK_UI"):
        evpn_dict["cli_mode"]="click"
    elif st.get_ui_type() == "klish":
        evpn_dict["cli_mode"]="klish"
    elif st.get_ui_type() == "click":
        evpn_dict["cli_mode"]="click"
    elif st.get_ui_type() in ["rest-put","rest-patch"]:
        evpn_dict["cli_mode"] = "klish"

def setup_underlay():

    #st.log("create VLANs required for VE interface b/w leaf and spine")
    #utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vlan_list"][0]],
    #                      [Vlan.create_vlan, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vlan_list"][0]],
    #                      [Vlan.create_vlan, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vlan_list"][0]],
    #                      [Vlan.create_vlan, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vlan_list"][0]],
    #                      [Vlan.create_vlan, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["vlan_list"][0]],
    #                      [Vlan.create_vlan, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["vlan_list"][0]]])
    #utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vlan_list"][1]],
    #                      [Vlan.create_vlan, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vlan_list"][1]],
    #                      [Vlan.create_vlan, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vlan_list"][1]],
    #                      [Vlan.create_vlan, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vlan_list"][1]],
    #                      [Vlan.create_vlan, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["vlan_list"][1]],
    #                      [Vlan.create_vlan, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["vlan_list"][1]]])
    #utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["vlan_list"][2]],
    #                      [Vlan.create_vlan, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["vlan_list"][2]]])
    #utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["vlan_list"][3]],
    #                      [Vlan.create_vlan, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["vlan_list"][3]]])

    #st.log("Bind VLAN to port required for VE interface b/w leaf and spine")
    #utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vlan_list"][0],
    #                    evpn_dict["leaf1"]["intf_list_spine"][3]],
    #                    [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vlan_list"][0],
    #                    evpn_dict["leaf2"]["intf_list_spine"][3]],
    #                    [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vlan_list"][0],
    #                    evpn_dict["leaf3"]["intf_list_spine"][3]],
    #                    [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vlan_list"][0],
    #                    evpn_dict["leaf4"]["intf_list_spine"][3]],
    #                    [Vlan.add_vlan_member, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["vlan_list"][0],
    #                    evpn_dict["spine1"]["intf_list_leaf"][3]],
    #                    [Vlan.add_vlan_member, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["vlan_list"][0],
    #                    evpn_dict["spine2"]["intf_list_leaf"][3]]])
    #utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vlan_list"][1],
    #                    evpn_dict["leaf1"]["intf_list_spine"][7]],
    #                    [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vlan_list"][1],
    #                    evpn_dict["leaf2"]["intf_list_spine"][7]],
    #                    [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vlan_list"][1],
    #                    evpn_dict["leaf3"]["intf_list_spine"][7]],
    #                    [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vlan_list"][1],
    #                    evpn_dict["leaf4"]["intf_list_spine"][7]],
    #                    [Vlan.add_vlan_member, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["vlan_list"][1],
    #                    evpn_dict["spine1"]["intf_list_leaf"][7]],
    #                    [Vlan.add_vlan_member, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["vlan_list"][1],
    #                    evpn_dict["spine2"]["intf_list_leaf"][7]]])
    #utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["vlan_list"][2],
    #                    evpn_dict["spine1"]["intf_list_leaf"][11]],
    #                    [Vlan.add_vlan_member, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["vlan_list"][2],
    #                    evpn_dict["spine2"]["intf_list_leaf"][11]]])
    #utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["vlan_list"][3],
    #                    evpn_dict["spine1"]["intf_list_leaf"][15]],
    #                    [Vlan.add_vlan_member, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["vlan_list"][3],
    #                    evpn_dict["spine2"]["intf_list_leaf"][15]]])

    st.log("create port channel interface b/w leaf and spine nodes")
    utils.exec_all(True, [[pch.create_portchannel, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["pch_intf_list"]]])

    st.log("Add members to port channel created b/w leaf and spine nodes")
    utils.exec_all(True, [[pch.add_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][0], evpn_dict["leaf1"]["intf_list_spine"][:2]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][0], evpn_dict["leaf2"]["intf_list_spine"][:2]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][0], evpn_dict["leaf3"]["intf_list_spine"][:2]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["pch_intf_list"][0], evpn_dict["leaf4"]["intf_list_spine"][:2]],
                          [pch.add_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][0], evpn_dict["spine1"]["intf_list_leaf"][:2]],
                          [pch.add_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][0], evpn_dict["spine2"]["intf_list_leaf"][:2]]])
    utils.exec_all(True, [[pch.add_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][1], evpn_dict["leaf1"]["intf_list_spine"][4:6]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][1], evpn_dict["leaf2"]["intf_list_spine"][4:6]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][1], evpn_dict["leaf3"]["intf_list_spine"][4:6]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["pch_intf_list"][1], evpn_dict["leaf4"]["intf_list_spine"][4:6]],
                          [pch.add_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][1], evpn_dict["spine1"]["intf_list_leaf"][4:6]],
                          [pch.add_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][1], evpn_dict["spine2"]["intf_list_leaf"][4:6]]])
    utils.exec_all(True, [[pch.add_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][2], evpn_dict["spine1"]["intf_list_leaf"][8:10]],
                          [pch.add_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][2], evpn_dict["spine2"]["intf_list_leaf"][8:10]]])
    utils.exec_all(True, [[pch.add_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][3], evpn_dict["spine1"]["intf_list_leaf"][12:14]],
                          [pch.add_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][3], evpn_dict["spine2"]["intf_list_leaf"][12:14]]])

    st.log("Enable portchannel interface on all leaf and spine nodes")
    utils.exec_all(True, [[Intf.interface_operation, evpn_dict["leaf_node_list"][0],
                                                    evpn_dict["leaf1"]["pch_intf_list"], "startup"],
                          [Intf.interface_operation, evpn_dict["leaf_node_list"][1],
                                                    evpn_dict["leaf2"]["pch_intf_list"], "startup"],
                          [Intf.interface_operation, evpn_dict["leaf_node_list"][2],
                                                    evpn_dict["leaf3"]["pch_intf_list"], "startup"],
                          [Intf.interface_operation, evpn_dict["leaf_node_list"][3],
                                                    evpn_dict["leaf4"]["pch_intf_list"], "startup"],
                          [Intf.interface_operation, evpn_dict["spine_node_list"][0],
                                                    evpn_dict["spine1"]["pch_intf_list"], "startup"],
                          [Intf.interface_operation, evpn_dict["spine_node_list"][1],
                                                    evpn_dict["spine2"]["pch_intf_list"], "startup"]])

    st.log("create loopback interface on all leaf nodes")
    input = {"loopback_name" : "Loopback1"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"]+evpn_dict["spine_node_list"],
                           ip.configure_loopback, [input,input,input,input,input,input])
    input = {"loopback_name" : "Loopback2"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],
                           ip.configure_loopback, [input,input,input,input])

    st.log("Assign IP address to loopback interface on all leaf nodes")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                           "Loopback1", evpn_dict["leaf1"]["loop_ip_list"][0], '32'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                           "Loopback1", evpn_dict["leaf2"]["loop_ip_list"][0], '32'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
                           "Loopback1", evpn_dict["leaf3"]["loop_ip_list"][0], '32'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
                           "Loopback1", evpn_dict["leaf4"]["loop_ip_list"][0], '32'],
                          [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
                           "Loopback1", evpn_dict["spine1"]["loop_ip_list"][0], '32'],
                          [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
                           "Loopback1", evpn_dict["spine2"]["loop_ip_list"][0], '32']])
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                           "Loopback2", evpn_dict["leaf1"]["loop_ip_list"][1], '32'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                           "Loopback2", evpn_dict["leaf2"]["loop_ip_list"][1], '32'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
                           "Loopback2", evpn_dict["leaf3"]["loop_ip_list"][1], '32'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
                           "Loopback2", evpn_dict["leaf4"]["loop_ip_list"][1], '32']])

    st.log("Assign IP address for portchannel interface between leaf and spine")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][0], evpn_dict["leaf1"]["intf_ip_list"][0], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][0], evpn_dict["leaf2"]["intf_ip_list"][0], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][0], evpn_dict["leaf3"]["intf_ip_list"][0], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["pch_intf_list"][0], evpn_dict["leaf4"]["intf_ip_list"][0], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][0], evpn_dict["spine1"]["intf_ip_list"][0], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][0], evpn_dict["spine2"]["intf_ip_list"][0], '31']])
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][1], evpn_dict["leaf1"]["intf_ip_list"][4], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][1], evpn_dict["leaf2"]["intf_ip_list"][4], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][1], evpn_dict["leaf3"]["intf_ip_list"][4], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["pch_intf_list"][1], evpn_dict["leaf4"]["intf_ip_list"][4], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][1], evpn_dict["spine1"]["intf_ip_list"][4], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][1], evpn_dict["spine2"]["intf_ip_list"][4], '31']])
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][2], evpn_dict["spine1"]["intf_ip_list"][8], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][2], evpn_dict["spine2"]["intf_ip_list"][8], '31']])
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][3], evpn_dict["spine1"]["intf_ip_list"][12], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][3], evpn_dict["spine2"]["intf_ip_list"][12], '31']])

    st.log("Assign IP address for router interface between leaf and spine")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["intf_list_spine"][2], evpn_dict["leaf1"]["intf_ip_list"][2],'31'],
                        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["intf_list_spine"][2], evpn_dict["leaf2"]["intf_ip_list"][2],'31'],
                        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
                        evpn_dict["leaf3"]["intf_list_spine"][2], evpn_dict["leaf3"]["intf_ip_list"][2],'31'],
                        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
                        evpn_dict["leaf4"]["intf_list_spine"][2], evpn_dict["leaf4"]["intf_ip_list"][2],'31'],
                        [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
                        evpn_dict["spine1"]["intf_list_leaf"][2], evpn_dict["spine1"]["intf_ip_list"][2], '31'],
                        [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
                        evpn_dict["spine2"]["intf_list_leaf"][2], evpn_dict["spine2"]["intf_ip_list"][2], '31']])
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["intf_list_spine"][6], evpn_dict["leaf1"]["intf_ip_list"][6],'31'],
                        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["intf_list_spine"][6], evpn_dict["leaf2"]["intf_ip_list"][6],'31'],
                        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
                        evpn_dict["leaf3"]["intf_list_spine"][6], evpn_dict["leaf3"]["intf_ip_list"][6],'31'],
                        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
                        evpn_dict["leaf4"]["intf_list_spine"][6], evpn_dict["leaf4"]["intf_ip_list"][6],'31'],
                        [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
                        evpn_dict["spine1"]["intf_list_leaf"][6], evpn_dict["spine1"]["intf_ip_list"][6], '31'],
                        [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
                        evpn_dict["spine2"]["intf_list_leaf"][6], evpn_dict["spine2"]["intf_ip_list"][6], '31']])
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
                        evpn_dict["spine1"]["intf_list_leaf"][10], evpn_dict["spine1"]["intf_ip_list"][10], '31'],
                        [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
                        evpn_dict["spine2"]["intf_list_leaf"][10], evpn_dict["spine2"]["intf_ip_list"][10], '31']])
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
                        evpn_dict["spine1"]["intf_list_leaf"][14], evpn_dict["spine1"]["intf_ip_list"][14], '31'],
                        [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
                        evpn_dict["spine2"]["intf_list_leaf"][14], evpn_dict["spine2"]["intf_ip_list"][14], '31']])

    st.log("Assign IP address for the 4th interface between leaf and spine")
    #utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
    #                       evpn_dict["leaf1"]["ve_intf_list"][0], evpn_dict["leaf1"]["intf_ip_list"][3], '31'],
    #                      [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
    #                       evpn_dict["leaf2"]["ve_intf_list"][0], evpn_dict["leaf2"]["intf_ip_list"][3], '31'],
    #                      [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
    #                       evpn_dict["leaf3"]["ve_intf_list"][0], evpn_dict["leaf3"]["intf_ip_list"][3], '31'],
    #                      [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
    #                       evpn_dict["leaf4"]["ve_intf_list"][0], evpn_dict["leaf4"]["intf_ip_list"][3], '31'],
    #                      [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
    #                       evpn_dict["spine1"]["ve_intf_list"][0], evpn_dict["spine1"]["intf_ip_list"][3], '31'],
    #                      [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
    #                       evpn_dict["spine2"]["ve_intf_list"][0], evpn_dict["spine2"]["intf_ip_list"][3], '31']])
    #utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
    #                       evpn_dict["leaf1"]["ve_intf_list"][1], evpn_dict["leaf1"]["intf_ip_list"][7], '31'],
    #                      [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
    #                       evpn_dict["leaf2"]["ve_intf_list"][1], evpn_dict["leaf2"]["intf_ip_list"][7], '31'],
    #                      [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
    #                       evpn_dict["leaf3"]["ve_intf_list"][1], evpn_dict["leaf3"]["intf_ip_list"][7], '31'],
    #                      [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
    #                       evpn_dict["leaf4"]["ve_intf_list"][1], evpn_dict["leaf4"]["intf_ip_list"][7], '31'],
    #                      [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
    #                       evpn_dict["spine1"]["ve_intf_list"][1], evpn_dict["spine1"]["intf_ip_list"][7], '31'],
    #                      [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
    #                       evpn_dict["spine2"]["ve_intf_list"][1], evpn_dict["spine2"]["intf_ip_list"][7], '31']])
    #utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
    #                       evpn_dict["spine1"]["ve_intf_list"][2], evpn_dict["spine1"]["intf_ip_list"][11], '31'],
    #                      [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
    #                       evpn_dict["spine2"]["ve_intf_list"][2], evpn_dict["spine2"]["intf_ip_list"][11], '31']])
    #utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
    #                       evpn_dict["spine1"]["ve_intf_list"][3], evpn_dict["spine1"]["intf_ip_list"][15], '31'],
    #                      [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
    #                       evpn_dict["spine2"]["ve_intf_list"][3], evpn_dict["spine2"]["intf_ip_list"][15], '31']])
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["intf_list_spine"][3], evpn_dict["leaf1"]["intf_ip_list"][3], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["intf_list_spine"][3], evpn_dict["leaf2"]["intf_ip_list"][3], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["intf_list_spine"][3], evpn_dict["leaf3"]["intf_ip_list"][3], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["intf_list_spine"][3], evpn_dict["leaf4"]["intf_ip_list"][3], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][3], evpn_dict["spine1"]["intf_ip_list"][3], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][3], evpn_dict["spine2"]["intf_ip_list"][3], '31']])
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["intf_list_spine"][7], evpn_dict["leaf1"]["intf_ip_list"][7], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["intf_list_spine"][7], evpn_dict["leaf2"]["intf_ip_list"][7], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["intf_list_spine"][7], evpn_dict["leaf3"]["intf_ip_list"][7], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["intf_list_spine"][7], evpn_dict["leaf4"]["intf_ip_list"][7], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][7], evpn_dict["spine1"]["intf_ip_list"][7], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][7], evpn_dict["spine2"]["intf_ip_list"][7], '31']])
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][11], evpn_dict["spine1"]["intf_ip_list"][11], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][11], evpn_dict["spine2"]["intf_ip_list"][11], '31']])
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][15], evpn_dict["spine1"]["intf_ip_list"][15], '31'],
                          [ip.config_ip_addr_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][15], evpn_dict["spine2"]["intf_ip_list"][15], '31']])


    st.log("crate static route to reach loopback")
    utils.exec_all(True, [[ip.create_static_route, evpn_dict["bgp_node_list"][0],
            evpn_dict["leaf1"]["intf_ip_list"][0],evpn_dict["leaf1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][1],
             evpn_dict["leaf1"]["intf_ip_list"][4], evpn_dict["leaf1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][2],
            evpn_dict["spine1"]["intf_ip_list"][0], evpn_dict["spine1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][3],
            evpn_dict["spine1"]["intf_ip_list"][4], evpn_dict["spine1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][4],
            evpn_dict["spine1"]["intf_ip_list"][8], evpn_dict["spine1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][5],
            evpn_dict["spine1"]["intf_ip_list"][12], evpn_dict["spine1"]["loop_ip_list"][0]+"/32"]])
    utils.exec_all(True, [[ip.create_static_route, evpn_dict["bgp_node_list"][0],
            evpn_dict["leaf1"]["intf_ip_list"][2],evpn_dict["leaf1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][1],
             evpn_dict["leaf1"]["intf_ip_list"][6], evpn_dict["leaf1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][2],
            evpn_dict["spine1"]["intf_ip_list"][2], evpn_dict["spine1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][3],
            evpn_dict["spine1"]["intf_ip_list"][6], evpn_dict["spine1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][4],
            evpn_dict["spine1"]["intf_ip_list"][10], evpn_dict["spine1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][5],
            evpn_dict["spine1"]["intf_ip_list"][14], evpn_dict["spine1"]["loop_ip_list"][0]+"/32"]])
    utils.exec_all(True, [[ip.create_static_route, evpn_dict["bgp_node_list"][0],
            evpn_dict["leaf1"]["intf_ip_list"][3],evpn_dict["leaf1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][1],
             evpn_dict["leaf1"]["intf_ip_list"][7], evpn_dict["leaf1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][2],
            evpn_dict["spine1"]["intf_ip_list"][3], evpn_dict["spine1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][3],
            evpn_dict["spine1"]["intf_ip_list"][7], evpn_dict["spine1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][4],
            evpn_dict["spine1"]["intf_ip_list"][11], evpn_dict["spine1"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][5],
            evpn_dict["spine1"]["intf_ip_list"][15], evpn_dict["spine1"]["loop_ip_list"][0]+"/32"]])
    utils.exec_all(True, [[ip.create_static_route, evpn_dict["bgp_node_list"][0],
            evpn_dict["leaf2"]["intf_ip_list"][0],evpn_dict["leaf2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][1],
             evpn_dict["leaf2"]["intf_ip_list"][4], evpn_dict["leaf2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][2],
            evpn_dict["spine2"]["intf_ip_list"][0], evpn_dict["spine2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][3],
            evpn_dict["spine2"]["intf_ip_list"][4], evpn_dict["spine2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][4],
            evpn_dict["spine2"]["intf_ip_list"][8], evpn_dict["spine2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][5],
            evpn_dict["spine2"]["intf_ip_list"][12], evpn_dict["spine2"]["loop_ip_list"][0]+"/32"]])
    utils.exec_all(True, [[ip.create_static_route, evpn_dict["bgp_node_list"][0],
            evpn_dict["leaf2"]["intf_ip_list"][2],evpn_dict["leaf2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][1],
             evpn_dict["leaf2"]["intf_ip_list"][6], evpn_dict["leaf2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][2],
            evpn_dict["spine2"]["intf_ip_list"][2], evpn_dict["spine2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][3],
            evpn_dict["spine2"]["intf_ip_list"][6], evpn_dict["spine2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][4],
            evpn_dict["spine2"]["intf_ip_list"][10], evpn_dict["spine2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][5],
            evpn_dict["spine2"]["intf_ip_list"][14], evpn_dict["spine2"]["loop_ip_list"][0]+"/32"]])
    utils.exec_all(True, [[ip.create_static_route, evpn_dict["bgp_node_list"][0],
            evpn_dict["leaf2"]["intf_ip_list"][3],evpn_dict["leaf2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][1],
             evpn_dict["leaf2"]["intf_ip_list"][7], evpn_dict["leaf2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][2],
            evpn_dict["spine2"]["intf_ip_list"][3], evpn_dict["spine2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][3],
            evpn_dict["spine2"]["intf_ip_list"][7], evpn_dict["spine2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][4],
            evpn_dict["spine2"]["intf_ip_list"][11], evpn_dict["spine2"]["loop_ip_list"][0]+"/32"],
            [ip.create_static_route, evpn_dict["bgp_node_list"][5],
            evpn_dict["spine2"]["intf_ip_list"][15], evpn_dict["spine2"]["loop_ip_list"][0]+"/32"]])
    utils.exec_all(True, [[ip.create_static_route, evpn_dict["spine_node_list"][0],
                           evpn_dict["leaf3"]["intf_ip_list"][0], evpn_dict["leaf3"]["loop_ip_list"][0]+"/32"],
                          [ip.create_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf3"]["intf_ip_list"][4], evpn_dict["leaf3"]["loop_ip_list"][0]+"/32"]])
    utils.exec_all(True, [[ip.create_static_route, evpn_dict["spine_node_list"][0],
                           evpn_dict["leaf3"]["intf_ip_list"][2], evpn_dict["leaf3"]["loop_ip_list"][0]+"/32"],
                          [ip.create_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf3"]["intf_ip_list"][6], evpn_dict["leaf3"]["loop_ip_list"][0]+"/32"]])
    utils.exec_all(True, [[ip.create_static_route, evpn_dict["spine_node_list"][0],
                           evpn_dict["leaf3"]["intf_ip_list"][3], evpn_dict["leaf3"]["loop_ip_list"][0]+"/32"],
                          [ip.create_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf3"]["intf_ip_list"][7], evpn_dict["leaf3"]["loop_ip_list"][0]+"/32"]])
    utils.exec_all(True, [[ip.create_static_route, evpn_dict["spine_node_list"][0],
                           evpn_dict["leaf4"]["intf_ip_list"][0], evpn_dict["leaf4"]["loop_ip_list"][0]+"/32"],
                          [ip.create_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf4"]["intf_ip_list"][4], evpn_dict["leaf4"]["loop_ip_list"][0]+"/32"]])
    utils.exec_all(True, [[ip.create_static_route, evpn_dict["spine_node_list"][0],
                           evpn_dict["leaf4"]["intf_ip_list"][2], evpn_dict["leaf4"]["loop_ip_list"][0]+"/32"],
                          [ip.create_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf4"]["intf_ip_list"][6], evpn_dict["leaf4"]["loop_ip_list"][0]+"/32"]])
    utils.exec_all(True, [[ip.create_static_route, evpn_dict["spine_node_list"][0],
                           evpn_dict["leaf4"]["intf_ip_list"][3], evpn_dict["leaf4"]["loop_ip_list"][0]+"/32"],
                          [ip.create_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf4"]["intf_ip_list"][7], evpn_dict["leaf4"]["loop_ip_list"][0]+"/32"]])

    st.log("configure BGP multi-path relax and disable ebgp connected route check so that recursive route comes up")
    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Bgp.config_bgp,
                           [bgp_in1,bgp_in2,bgp_in3,bgp_in4,bgp_in5,bgp_in6])

    if evpn_dict["cli_mode"] == "klish":
        dict1 = {"local_as":evpn_dict['spine1']['local_as'],"config_type_list":["disable_ebgp_connected_route_check"],"config":"yes"}
        dict2 = {"local_as":evpn_dict['spine2']['local_as'],"config_type_list":["disable_ebgp_connected_route_check"],"config":"yes"}
        dict3 = {"local_as":evpn_dict['leaf1']['local_as'],"config_type_list":["disable_ebgp_connected_route_check"],"config":"yes"}
        dict4 = {"local_as":evpn_dict['leaf2']['local_as'],"config_type_list":["disable_ebgp_connected_route_check"],"config":"yes"}
        dict5 = {"local_as":evpn_dict['leaf3']['local_as'],"config_type_list":["disable_ebgp_connected_route_check"],"config":"yes"}
        dict6 = {"local_as":evpn_dict['leaf4']['local_as'],"config_type_list":["disable_ebgp_connected_route_check"],"config":"yes"}
        parallel.exec_parallel(True,evpn_dict["bgp_node_list"][0:6],Evpn.config_bgp_evpn,[dict1,dict2,dict3,dict4,dict5,dict6])

    st.log("configure BGP neighbors")
    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Bgp.config_bgp,
                           [bgp_input1,bgp_input2,bgp_input3,bgp_input4,bgp_input5,bgp_input6])

    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Bgp.config_bgp,
                           [bgp_input7,bgp_input8,bgp_input9,bgp_input10,bgp_input11,bgp_input12])
    parallel.exec_parallel(True, evpn_dict["spine_node_list"], Bgp.config_bgp,[bgp_input13,bgp_input14])
    parallel.exec_parallel(True, evpn_dict["spine_node_list"], Bgp.config_bgp,[bgp_input15,bgp_input16])

    st.log("configure network command to advertise VTEP ip in each leaf nodes under router BGP")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], Bgp.config_bgp,[bgp_input31,bgp_input32,
                           bgp_input33,bgp_input34])

    st.log("configure network import check in all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], Bgp.config_bgp,[bgp_input39,bgp_input40,
                           bgp_input41,bgp_input42])

    st.log("configure BGP EVPN neighbors")
    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Evpn.config_bgp_evpn,
                           [evpn_input1, evpn_input1_1, evpn_input2, evpn_input2_1, evpn_input2_2, evpn_input2_3])

    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Evpn.config_bgp_evpn,
                           [evpn_in1, evpn_in2, evpn_in3, evpn_in4, evpn_in5, evpn_in6])

    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Evpn.config_bgp_evpn,
                           [evpn_input3, evpn_input3_1, evpn_input4, evpn_input4_1, evpn_input4_2, evpn_input4_3])
    parallel.exec_parallel(True, evpn_dict["spine_node_list"], Evpn.config_bgp_evpn, [evpn_input5, evpn_input5_1])
    parallel.exec_parallel(True, evpn_dict["spine_node_list"], Evpn.config_bgp_evpn, [evpn_input6, evpn_input6_1])



def setup_vxlan():

    st.log("config vtep on all leaf nodes")
    utils.exec_all(True, [[Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf1"]["loop_ip_list"][1]],
                        [Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["vtepName"], evpn_dict["leaf2"]["loop_ip_list"][1]],
                        [Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][2],
                        evpn_dict["leaf3"]["vtepName"], evpn_dict["leaf3"]["loop_ip_list"][1]],
                        [Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][3],
                        evpn_dict["leaf4"]["vtepName"], evpn_dict["leaf4"]["loop_ip_list"][1]]])

    if evpn_dict['cli_mode'] != "klish":
        st.log("config evpn nvo instance on all leaf nodes")
        utils.exec_all(True, [[Evpn.create_evpn_instance, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["nvoName"], evpn_dict["leaf1"]["vtepName"]],
                          [Evpn.create_evpn_instance, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["nvoName"], evpn_dict["leaf2"]["vtepName"]],
                          [Evpn.create_evpn_instance, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["nvoName"], evpn_dict["leaf3"]["vtepName"]],
                          [Evpn.create_evpn_instance, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["nvoName"], evpn_dict["leaf4"]["vtepName"]]])


def setup_l2vni():

    st.log("create tenant L2 VLANs on all leaf nodes")
    utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l2_vlan_list"]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l2_vlan_list"]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l2_vlan_list"]]])

    st.log("Bind tenant L2 VLANs to port on all leaf nodes")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l2_vlan_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0],True]])
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["intf_list_tg"][1],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l2_vlan_list"][1], evpn_dict["leaf2"]["intf_list_tg"][1],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l2_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][1],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l2_vlan_list"][1], evpn_dict["leaf4"]["intf_list_tg"][1],True]])

    st.log("Add L2 vlan to VNI mapping")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0]]])


def setup_l3vni():

    st.log("create Vrf on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], vrf.config_vrf,[vrf_input1,
                           vrf_input1, vrf_input1, vrf_input1])

    st.log("create VLANs for L3VNI on all leaf nodes")
    utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["l3_vni_list"][0]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["l3_vni_list"][0]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["l3_vni_list"][0]]])

    st.log("create tenant L3 VLANs on all leaf nodes")
    utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"]]])

    st.log("Bind L3VNI VLANs to port on all leaf nodes")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["l3_vni_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["l3_vni_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["l3_vni_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Bind tenant L3 VLANs to port on all leaf nodes")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Bind Vrf to L3VNI interfaces on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],
                           vrf.bind_vrf_interface,[vrf_bind1,vrf_bind2, vrf_bind3, vrf_bind4])

    st.log("Bind Vrf to L3VNI tenant interfaces on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],
                           vrf.bind_vrf_interface,[vrf_bind9,vrf_bind10, vrf_bind11, vrf_bind12])

    st.log("Assign IP address to L3VNI interface on all leaf nodes")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["l3_vni_name_list"][0],
            evpn_dict["leaf1"]["l3_vni_ip_list"][0], evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["l3_vni_name_list"][0],
            evpn_dict["leaf2"]["l3_vni_ip_list"][0], evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["l3_vni_name_list"][0],
            evpn_dict["leaf3"]["l3_vni_ip_list"][0], evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["l3_vni_name_list"][0],
            evpn_dict["leaf4"]["l3_vni_ip_list"][0], evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

    st.log("Assign IP address to L3VNI tenant interface on all leaf nodes")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf1"]["l3_tenant_ip_list"][0], evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
            "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf2"]["l3_tenant_ip_list"][0], evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf3"]["l3_tenant_ip_list"][0], evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0], evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

    st.log("Assign IPv6 address to L3VNI interface on all leaf nodes")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["l3_vni_name_list"][0],
            evpn_dict["leaf1"]["l3_vni_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["l3_vni_name_list"][0],
            evpn_dict["leaf2"]["l3_vni_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["l3_vni_name_list"][0],
            evpn_dict["leaf3"]["l3_vni_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["l3_vni_name_list"][0],
            evpn_dict["leaf4"]["l3_vni_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log("Assign IPv6 address to L3VNI tenant interface on all leaf nodes")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
            "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log("Add L3 vlan to VNI mapping")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf1"]["l3_vni_list"][0],
            evpn_dict["leaf1"]["l3_vni_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
            evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["l3_vni_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
            evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["l3_vni_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["l3_vni_list"][0]]])

    st.log("Add Vrf to VNI map on all leaf nodes")
    utils.exec_all(True, [[Evpn.map_vrf_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vrf_name_list"][0], evpn_dict["leaf1"]["l3_vni_list"][0],
            'yes', evpn_dict["leaf1"]["vtepName"]],
            [Evpn.map_vrf_vni, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["vrf_name_list"][0], evpn_dict["leaf2"]["l3_vni_list"][0],
            'yes', evpn_dict["leaf2"]["vtepName"]],
            [Evpn.map_vrf_vni, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["vrf_name_list"][0], evpn_dict["leaf3"]["l3_vni_list"][0],
            'yes', evpn_dict["leaf3"]["vtepName"]],
            [Evpn.map_vrf_vni, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["vrf_name_list"][0], evpn_dict["leaf4"]["l3_vni_list"][0],
            'yes', evpn_dict["leaf4"]["vtepName"]]])


    #st.log("Add FRR level global VRF and VNI config")
    #parallel.exec_parallel(True, evpn_dict["leaf_node_list"], Evpn.config_bgp_evpn, [evpn_input13,evpn_input14,evpn_input15,evpn_input16])

    st.log("Add FRR VRF redist connected config for ipv4 and ipv6 AF")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], Bgp.config_bgp, [bgp_input23,bgp_input24,bgp_input25,bgp_input26])
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], Bgp.config_bgp, [bgp_input35,bgp_input36,bgp_input37,bgp_input38])

    st.log("Add FRR VRF advertise ipv4 & ipv6 unicast config")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], Evpn.config_bgp_evpn, [evpn_input21,evpn_input22,evpn_input23,evpn_input24])
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], Evpn.config_bgp_evpn, [evpn_input30,evpn_input31,evpn_input32,evpn_input33])

def cleanup_l2vni():

    st.log("Delete L2 vlan to VNI mapping")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], "1", "no"],
                          [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                           "1", "no"],
                          [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                           "1", "no"],
                          [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                           "1", "no"]])

    st.log("Remove tenant L2 VLAN binding from all leaf nodes")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l2_vlan_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0],True]])
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["intf_list_tg"][1],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l2_vlan_list"][1], evpn_dict["leaf2"]["intf_list_tg"][1],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l2_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][1],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l2_vlan_list"][1], evpn_dict["leaf4"]["intf_list_tg"][1],True]])

    st.log("Remove L2 VNI VLANs from all leaf nodes")
    utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"]],
                    [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["tenant_l2_vlan_list"]],
                    [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["tenant_l2_vlan_list"]],
                    [Vlan.delete_vlan, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["tenant_l2_vlan_list"]]])


def cleanup_l3vni():

    st.log("Remove Vrf to VNI map on all leaf nodes")

    utils.exec_all(True, [[Evpn.map_vrf_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vrf_name_list"][0], evpn_dict["leaf1"]["l3_vni_list"][0],
            'no', evpn_dict["leaf1"]["vtepName"]],
            [Evpn.map_vrf_vni, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["vrf_name_list"][0], evpn_dict["leaf2"]["l3_vni_list"][0],
            'no', evpn_dict["leaf2"]["vtepName"]],
            [Evpn.map_vrf_vni, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["vrf_name_list"][0], evpn_dict["leaf3"]["l3_vni_list"][0],
            'no', evpn_dict["leaf3"]["vtepName"]],
            [Evpn.map_vrf_vni, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["vrf_name_list"][0], evpn_dict["leaf4"]["l3_vni_list"][0],
            'no', evpn_dict["leaf4"]["vtepName"]]])


    st.log("Delete L3 vlan to VNI mapping")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf1"]["l3_vni_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0], "1", "no"],
                          [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
                           evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["l3_vni_list"][0],
                           "1", "no"],
                          [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
                           evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["l3_vni_list"][0],
                           "1", "no"],
                          [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
                           evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["l3_vni_list"][0],
                           "1", "no"]])

    st.log("Remove L3VNI VLAN binding from all leaf nodes")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["l3_vni_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["l3_vni_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["l3_vni_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Remove L3 tenant VLAN port binding from all leaf nodes")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Remove IP address of L3VNI interface from all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
        evpn_dict["leaf1"]["l3_vni_name_list"][0], evpn_dict["leaf1"]["l3_vni_ip_list"][0],
        evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
        evpn_dict["leaf2"]["l3_vni_name_list"][0], evpn_dict["leaf2"]["l3_vni_ip_list"][0],
        evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][0], evpn_dict["leaf3"]["l3_vni_ip_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf4"]["l3_vni_name_list"][0], evpn_dict["leaf4"]["l3_vni_ip_list"][0],
        evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

    st.log("Remove IP address of L3VNI tenant interface from all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
        "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["l3_tenant_ip_list"][0],
        evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
        "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["l3_tenant_ip_list"][0],
        evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], evpn_dict["leaf3"]["l3_tenant_ip_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf4"]["l3_tenant_ip_list"][0],
        evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

    st.log("Remove IPv6 address of L3VNI interface from all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
        evpn_dict["leaf1"]["l3_vni_name_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
        evpn_dict["leaf2"]["l3_vni_name_list"][0], evpn_dict["leaf2"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][0], evpn_dict["leaf3"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        evpn_dict["leaf4"]["l3_vni_name_list"][0], evpn_dict["leaf4"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log("Remove IPv6 address of L3VNI tenant interface from all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
        "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0],
        evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
        "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0],
        evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
        "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0],
        evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log("Un-Bind Vrf from L3VNI interfaces on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], vrf.bind_vrf_interface,[vrf_bind5,
                           vrf_bind6, vrf_bind7, vrf_bind8])

    st.log("Un-Bind Vrf from L3VNI tenant interfaces on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], vrf.bind_vrf_interface,[vrf_bind13,
                           vrf_bind14, vrf_bind15, vrf_bind16])

    st.log("Remove BGP neighbors for L3 tenant vrf")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], Bgp.config_bgp,
                           [bgp_input27, bgp_input28, bgp_input29, bgp_input30])

    st.log("Remove Vrf on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], vrf.config_vrf,
                           [vrf_input2, vrf_input2, vrf_input2, vrf_input2])

    st.log("Remove L3 VNI VLANs from all leaf nodes")
    utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["l3_vni_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["l3_vni_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["l3_vni_list"][0]]])

    st.log("Remove L3 VNI tenant VLANs from all leaf nodes")
    utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]]])
    utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][1]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][1]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][1]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][1]]])
    utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][2]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][2]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][2]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["tenant_l3_vlan_list"][2]]])

    #st.log("Remove FRR level global VRF and VNI config")
    #parallel.exec_parallel(True, evpn_dict["leaf_node_list"], Evpn.config_bgp_evpn,
    #                       [evpn_input25,evpn_input26,evpn_input27,evpn_input28])


def cleanup_vxlan():

    if evpn_dict['cli_mode'] != "klish":
        st.log("Remove evpn nvo instance from all leaf nodes")
        utils.exec_all(True, [[Evpn.create_evpn_instance, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["nvoName"], evpn_dict["leaf1"]["vtepName"], "no"],
                          [Evpn.create_evpn_instance, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["nvoName"], evpn_dict["leaf2"]["vtepName"], "no"],
                          [Evpn.create_evpn_instance, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["nvoName"], evpn_dict["leaf3"]["vtepName"], "no"],
                          [Evpn.create_evpn_instance, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["nvoName"], evpn_dict["leaf4"]["vtepName"], "no"]])

    st.log("Remove vtep from all leaf nodes")
    utils.exec_all(True, [[Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf1"]["loop_ip_list"][1], "no"],
                          [Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["vtepName"], evpn_dict["leaf2"]["loop_ip_list"][1], "no"],
                          [Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["vtepName"], evpn_dict["leaf3"]["loop_ip_list"][1], "no"],
                          [Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["vtepName"], evpn_dict["leaf4"]["loop_ip_list"][1], "no"]])

def cleanup_underlay():

    st.log("Remove BGP neighbors")
    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Bgp.config_bgp,
                           [bgp_input17, bgp_input18, bgp_input19, bgp_input20, bgp_input21, bgp_input22])

    st.log("Remove static route to reach loopback")
    utils.exec_all(True, [[ip.delete_static_route, evpn_dict["bgp_node_list"][0],
                           evpn_dict["leaf1"]["intf_ip_list"][0], evpn_dict["leaf1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf1"]["intf_ip_list"][4], evpn_dict["leaf1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][2],
                           evpn_dict["spine1"]["intf_ip_list"][0], evpn_dict["spine1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][3],
                           evpn_dict["spine1"]["intf_ip_list"][4], evpn_dict["spine1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][4],
                           evpn_dict["spine1"]["intf_ip_list"][8], evpn_dict["spine1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][5],
                           evpn_dict["spine1"]["intf_ip_list"][12], evpn_dict["spine1"]["loop_ip_list"][0] + "/32"]])
    utils.exec_all(True, [[ip.delete_static_route, evpn_dict["bgp_node_list"][0],
                           evpn_dict["leaf1"]["intf_ip_list"][2], evpn_dict["leaf1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf1"]["intf_ip_list"][6], evpn_dict["leaf1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][2],
                           evpn_dict["spine1"]["intf_ip_list"][2], evpn_dict["spine1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][3],
                           evpn_dict["spine1"]["intf_ip_list"][6], evpn_dict["spine1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][4],
                           evpn_dict["spine1"]["intf_ip_list"][10], evpn_dict["spine1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][5],
                           evpn_dict["spine1"]["intf_ip_list"][14], evpn_dict["spine1"]["loop_ip_list"][0] + "/32"]])
    utils.exec_all(True, [[ip.delete_static_route, evpn_dict["bgp_node_list"][0],
                           evpn_dict["leaf1"]["intf_ip_list"][3], evpn_dict["leaf1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf1"]["intf_ip_list"][7], evpn_dict["leaf1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][2],
                           evpn_dict["spine1"]["intf_ip_list"][3], evpn_dict["spine1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][3],
                           evpn_dict["spine1"]["intf_ip_list"][7], evpn_dict["spine1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][4],
                           evpn_dict["spine1"]["intf_ip_list"][11], evpn_dict["spine1"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][5],
                           evpn_dict["spine1"]["intf_ip_list"][15], evpn_dict["spine1"]["loop_ip_list"][0] + "/32"]])
    utils.exec_all(True, [[ip.delete_static_route, evpn_dict["bgp_node_list"][0],
                           evpn_dict["leaf2"]["intf_ip_list"][0], evpn_dict["leaf2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf2"]["intf_ip_list"][4], evpn_dict["leaf2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][2],
                           evpn_dict["spine2"]["intf_ip_list"][0], evpn_dict["spine2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][3],
                           evpn_dict["spine2"]["intf_ip_list"][4], evpn_dict["spine2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][4],
                           evpn_dict["spine2"]["intf_ip_list"][8], evpn_dict["spine2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][5],
                           evpn_dict["spine2"]["intf_ip_list"][12], evpn_dict["spine2"]["loop_ip_list"][0] + "/32"]])
    utils.exec_all(True, [[ip.delete_static_route, evpn_dict["bgp_node_list"][0],
                           evpn_dict["leaf2"]["intf_ip_list"][2], evpn_dict["leaf2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf2"]["intf_ip_list"][6], evpn_dict["leaf2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][2],
                           evpn_dict["spine2"]["intf_ip_list"][2], evpn_dict["spine2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][3],
                           evpn_dict["spine2"]["intf_ip_list"][6], evpn_dict["spine2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][4],
                           evpn_dict["spine2"]["intf_ip_list"][10], evpn_dict["spine2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][5],
                           evpn_dict["spine2"]["intf_ip_list"][14], evpn_dict["spine2"]["loop_ip_list"][0] + "/32"]])
    utils.exec_all(True, [[ip.delete_static_route, evpn_dict["bgp_node_list"][0],
                           evpn_dict["leaf2"]["intf_ip_list"][3], evpn_dict["leaf2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf2"]["intf_ip_list"][7], evpn_dict["leaf2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][2],
                           evpn_dict["spine2"]["intf_ip_list"][3], evpn_dict["spine2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][3],
                           evpn_dict["spine2"]["intf_ip_list"][7], evpn_dict["spine2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][4],
                           evpn_dict["spine2"]["intf_ip_list"][11], evpn_dict["spine2"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][5],
                           evpn_dict["spine2"]["intf_ip_list"][15], evpn_dict["spine2"]["loop_ip_list"][0] + "/32"]])
    utils.exec_all(True, [[ip.delete_static_route, evpn_dict["spine_node_list"][0],
                           evpn_dict["leaf3"]["intf_ip_list"][0], evpn_dict["leaf3"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf3"]["intf_ip_list"][4], evpn_dict["leaf3"]["loop_ip_list"][0] + "/32"]])
    utils.exec_all(True, [[ip.delete_static_route, evpn_dict["spine_node_list"][0],
                           evpn_dict["leaf3"]["intf_ip_list"][2], evpn_dict["leaf3"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf3"]["intf_ip_list"][6], evpn_dict["leaf3"]["loop_ip_list"][0] + "/32"]])
    utils.exec_all(True, [[ip.delete_static_route, evpn_dict["spine_node_list"][0],
                           evpn_dict["leaf3"]["intf_ip_list"][3], evpn_dict["leaf3"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf3"]["intf_ip_list"][7], evpn_dict["leaf3"]["loop_ip_list"][0] + "/32"]])
    utils.exec_all(True, [[ip.delete_static_route, evpn_dict["spine_node_list"][0],
                           evpn_dict["leaf4"]["intf_ip_list"][0], evpn_dict["leaf4"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf4"]["intf_ip_list"][4], evpn_dict["leaf4"]["loop_ip_list"][0] + "/32"]])
    utils.exec_all(True, [[ip.delete_static_route, evpn_dict["spine_node_list"][0],
                           evpn_dict["leaf4"]["intf_ip_list"][2], evpn_dict["leaf4"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf4"]["intf_ip_list"][6], evpn_dict["leaf4"]["loop_ip_list"][0] + "/32"]])
    utils.exec_all(True, [[ip.delete_static_route, evpn_dict["spine_node_list"][0],
                           evpn_dict["leaf4"]["intf_ip_list"][3], evpn_dict["leaf4"]["loop_ip_list"][0] + "/32"],
                          [ip.delete_static_route, evpn_dict["bgp_node_list"][1],
                           evpn_dict["leaf4"]["intf_ip_list"][7], evpn_dict["leaf4"]["loop_ip_list"][0] + "/32"]])

    st.log("Remove IP address for VE interface between leaf and spine")
    #utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
    #                       evpn_dict["leaf1"]["ve_intf_list"][0], evpn_dict["leaf1"]["intf_ip_list"][3], '31'],
    #                      [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
    #                       evpn_dict["leaf2"]["ve_intf_list"][0], evpn_dict["leaf2"]["intf_ip_list"][3], '31'],
    #                      [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
    #                       evpn_dict["leaf3"]["ve_intf_list"][0], evpn_dict["leaf3"]["intf_ip_list"][3], '31'],
    #                      [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
    #                       evpn_dict["leaf4"]["ve_intf_list"][0], evpn_dict["leaf4"]["intf_ip_list"][3], '31'],
    #                      [ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
    #                       evpn_dict["spine1"]["ve_intf_list"][0], evpn_dict["spine1"]["intf_ip_list"][3], '31'],
    #                      [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
    #                       evpn_dict["spine2"]["ve_intf_list"][0], evpn_dict["spine2"]["intf_ip_list"][3], '31']])
    #utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
    #                       evpn_dict["leaf1"]["ve_intf_list"][1], evpn_dict["leaf1"]["intf_ip_list"][7], '31'],
    #                      [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
    #                       evpn_dict["leaf2"]["ve_intf_list"][1], evpn_dict["leaf2"]["intf_ip_list"][7], '31'],
    #                      [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
    #                       evpn_dict["leaf3"]["ve_intf_list"][1], evpn_dict["leaf3"]["intf_ip_list"][7], '31'],
    #                      [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
    #                       evpn_dict["leaf4"]["ve_intf_list"][1], evpn_dict["leaf4"]["intf_ip_list"][7], '31'],
    #                      [ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
    #                       evpn_dict["spine1"]["ve_intf_list"][1], evpn_dict["spine1"]["intf_ip_list"][7], '31'],
    #                      [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
    #                       evpn_dict["spine2"]["ve_intf_list"][1], evpn_dict["spine2"]["intf_ip_list"][7], '31']])
    #utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
    #                       evpn_dict["spine1"]["ve_intf_list"][2], evpn_dict["spine1"]["intf_ip_list"][11], '31'],
    #                      [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
    #                       evpn_dict["spine2"]["ve_intf_list"][2], evpn_dict["spine2"]["intf_ip_list"][11], '31']])
    #utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
    #                       evpn_dict["spine1"]["ve_intf_list"][3], evpn_dict["spine1"]["intf_ip_list"][15], '31'],
    #                      [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
    #                       evpn_dict["spine2"]["ve_intf_list"][3], evpn_dict["spine2"]["intf_ip_list"][15], '31']])

    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["intf_list_spine"][3], evpn_dict["leaf1"]["intf_ip_list"][3], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["intf_list_spine"][3], evpn_dict["leaf2"]["intf_ip_list"][3], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["intf_list_spine"][3], evpn_dict["leaf3"]["intf_ip_list"][3], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["intf_list_spine"][3], evpn_dict["leaf4"]["intf_ip_list"][3], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][3], evpn_dict["spine1"]["intf_ip_list"][3], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][3], evpn_dict["spine2"]["intf_ip_list"][3], '31']])
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["intf_list_spine"][7], evpn_dict["leaf1"]["intf_ip_list"][7], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["intf_list_spine"][7], evpn_dict["leaf2"]["intf_ip_list"][7], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["intf_list_spine"][7], evpn_dict["leaf3"]["intf_ip_list"][7], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["intf_list_spine"][7], evpn_dict["leaf4"]["intf_ip_list"][7], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][7], evpn_dict["spine1"]["intf_ip_list"][7], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][7], evpn_dict["spine2"]["intf_ip_list"][7], '31']])
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][11], evpn_dict["spine1"]["intf_ip_list"][11], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][11], evpn_dict["spine2"]["intf_ip_list"][11], '31']])
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][15], evpn_dict["spine1"]["intf_ip_list"][15], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][15], evpn_dict["spine2"]["intf_ip_list"][15], '31']])


    st.log("Remove IP address of router interface between leaf and spine")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["intf_list_spine"][2], evpn_dict["leaf1"]["intf_ip_list"][2], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["intf_list_spine"][2], evpn_dict["leaf2"]["intf_ip_list"][2], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["intf_list_spine"][2], evpn_dict["leaf3"]["intf_ip_list"][2], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["intf_list_spine"][2], evpn_dict["leaf4"]["intf_ip_list"][2], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][2], evpn_dict["spine1"]["intf_ip_list"][2], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][2], evpn_dict["spine2"]["intf_ip_list"][2], '31']])
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["intf_list_spine"][6], evpn_dict["leaf1"]["intf_ip_list"][6], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["intf_list_spine"][6], evpn_dict["leaf2"]["intf_ip_list"][6], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["intf_list_spine"][6], evpn_dict["leaf3"]["intf_ip_list"][6], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["intf_list_spine"][6], evpn_dict["leaf4"]["intf_ip_list"][6], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][6], evpn_dict["spine1"]["intf_ip_list"][6], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][6], evpn_dict["spine2"]["intf_ip_list"][6], '31']])
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][10], evpn_dict["spine1"]["intf_ip_list"][10], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][10], evpn_dict["spine2"]["intf_ip_list"][10], '31']])
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][14], evpn_dict["spine1"]["intf_ip_list"][14], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][14], evpn_dict["spine2"]["intf_ip_list"][14], '31']])

    st.log("Remove IP address for portchannel interface between leaf and spine")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][0], evpn_dict["leaf1"]["intf_ip_list"][0], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][0], evpn_dict["leaf2"]["intf_ip_list"][0], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][0], evpn_dict["leaf3"]["intf_ip_list"][0], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["pch_intf_list"][0], evpn_dict["leaf4"]["intf_ip_list"][0], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][0], evpn_dict["spine1"]["intf_ip_list"][0], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][0], evpn_dict["spine2"]["intf_ip_list"][0], '31']])
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][1], evpn_dict["leaf1"]["intf_ip_list"][4], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][1], evpn_dict["leaf2"]["intf_ip_list"][4], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][1], evpn_dict["leaf3"]["intf_ip_list"][4], '31'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["pch_intf_list"][1], evpn_dict["leaf4"]["intf_ip_list"][4], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][1], evpn_dict["spine1"]["intf_ip_list"][4], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][1], evpn_dict["spine2"]["intf_ip_list"][4], '31']])
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][2], evpn_dict["spine1"]["intf_ip_list"][8], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][2], evpn_dict["spine2"]["intf_ip_list"][8], '31']])
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][3], evpn_dict["spine1"]["intf_ip_list"][12], '31'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][3], evpn_dict["spine2"]["intf_ip_list"][12], '31']])

    st.log("Remove IP address of loopback interface from all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           "Loopback1", evpn_dict["leaf1"]["loop_ip_list"][0], '32'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           "Loopback1", evpn_dict["leaf2"]["loop_ip_list"][0], '32'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
                           "Loopback1", evpn_dict["leaf3"]["loop_ip_list"][0], '32'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
                           "Loopback1", evpn_dict["leaf4"]["loop_ip_list"][0], '32'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
                           "Loopback1", evpn_dict["spine1"]["loop_ip_list"][0], '32'],
                          [ip.delete_ip_interface, evpn_dict["spine_node_list"][1],
                           "Loopback1", evpn_dict["spine2"]["loop_ip_list"][0], '32']])
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           "Loopback2", evpn_dict["leaf1"]["loop_ip_list"][1], '32'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           "Loopback2", evpn_dict["leaf2"]["loop_ip_list"][1], '32'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
                           "Loopback2", evpn_dict["leaf3"]["loop_ip_list"][1], '32'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
                           "Loopback2", evpn_dict["leaf4"]["loop_ip_list"][1], '32']])

    st.log("Remove loopback interface from all leaf nodes")
    input = {"loopback_name": "Loopback1", "config": "no"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"] + evpn_dict["spine_node_list"],
                           ip.configure_loopback, [input, input, input, input, input, input])
    input = {"loopback_name": "Loopback2", "config": "no"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],
                           ip.configure_loopback, [input, input, input, input])

    st.log("Remove members from port channel created b/w leaf and spine nodes")
    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][0], evpn_dict["leaf1"]["intf_list_spine"][:2]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][0], evpn_dict["leaf2"]["intf_list_spine"][:2]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][0], evpn_dict["leaf3"]["intf_list_spine"][:2]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["pch_intf_list"][0], evpn_dict["leaf4"]["intf_list_spine"][:2]],
                          [pch.delete_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][0], evpn_dict["spine1"]["intf_list_leaf"][:2]],
                          [pch.delete_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][0], evpn_dict["spine2"]["intf_list_leaf"][:2]]])
    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][1], evpn_dict["leaf1"]["intf_list_spine"][4:6]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][1], evpn_dict["leaf2"]["intf_list_spine"][4:6]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][1], evpn_dict["leaf3"]["intf_list_spine"][4:6]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["pch_intf_list"][1], evpn_dict["leaf4"]["intf_list_spine"][4:6]],
                          [pch.delete_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][1], evpn_dict["spine1"]["intf_list_leaf"][4:6]],
                          [pch.delete_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][1], evpn_dict["spine2"]["intf_list_leaf"][4:6]]])
    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][2], evpn_dict["spine1"]["intf_list_leaf"][8:10]],
                          [pch.delete_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][2], evpn_dict["spine2"]["intf_list_leaf"][8:10]]])
    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][3], evpn_dict["spine1"]["intf_list_leaf"][12:14]],
                          [pch.delete_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][3], evpn_dict["spine2"]["intf_list_leaf"][12:14]]])

    st.log("Remove port channel interface created b/w leaf and spine nodes")
    for i in range(0,2):
        utils.exec_all(True, [[pch.delete_portchannel, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["pch_intf_list"][i]],
                    [pch.delete_portchannel, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["pch_intf_list"][i]],
                    [pch.delete_portchannel, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["pch_intf_list"][i]],
                    [pch.delete_portchannel, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["pch_intf_list"][i]]])

    for i in range(0,4):
        utils.exec_all(True,
                    [[pch.delete_portchannel, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["pch_intf_list"][i]],
                    [pch.delete_portchannel, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["pch_intf_list"][i]]])


    st.log("Remove VLAN binding of VE interface b/w leaf and spine")
   # utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
   #                        evpn_dict["leaf1"]["vlan_list"][0], evpn_dict["leaf1"]["intf_list_spine"][3]],
   #                       [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
   #                        evpn_dict["leaf2"]["vlan_list"][0], evpn_dict["leaf2"]["intf_list_spine"][3]],
   #                       [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
   #                        evpn_dict["leaf3"]["vlan_list"][0], evpn_dict["leaf3"]["intf_list_spine"][3]],
   #                       [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
   #                        evpn_dict["leaf4"]["vlan_list"][0], evpn_dict["leaf4"]["intf_list_spine"][3]],
   #                       [Vlan.delete_vlan_member, evpn_dict["spine_node_list"][0],
   #                        evpn_dict["spine1"]["vlan_list"][0], evpn_dict["spine1"]["intf_list_leaf"][3]],
   #                       [Vlan.delete_vlan_member, evpn_dict["spine_node_list"][1],
   #                        evpn_dict["spine2"]["vlan_list"][0], evpn_dict["spine2"]["intf_list_leaf"][3]]])
   # utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
   #                        evpn_dict["leaf1"]["vlan_list"][1], evpn_dict["leaf1"]["intf_list_spine"][7]],
   #                       [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
   #                        evpn_dict["leaf2"]["vlan_list"][1], evpn_dict["leaf2"]["intf_list_spine"][7]],
   #                       [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
   #                        evpn_dict["leaf3"]["vlan_list"][1], evpn_dict["leaf3"]["intf_list_spine"][7]],
   #                       [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
   #                        evpn_dict["leaf4"]["vlan_list"][1], evpn_dict["leaf4"]["intf_list_spine"][7]],
   #                       [Vlan.delete_vlan_member, evpn_dict["spine_node_list"][0],
   #                        evpn_dict["spine1"]["vlan_list"][1], evpn_dict["spine1"]["intf_list_leaf"][7]],
   #                       [Vlan.delete_vlan_member, evpn_dict["spine_node_list"][1],
   #                        evpn_dict["spine2"]["vlan_list"][1], evpn_dict["spine2"]["intf_list_leaf"][7]]])
   # utils.exec_all(True,
   #               [[Vlan.delete_vlan_member, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["vlan_list"][2],
   #                 evpn_dict["spine1"]["intf_list_leaf"][11]],
   #                [Vlan.delete_vlan_member, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["vlan_list"][2],
   #                 evpn_dict["spine2"]["intf_list_leaf"][11]]])
   #utils.exec_all(True,
   #               [[Vlan.delete_vlan_member, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["vlan_list"][3],
   #                 evpn_dict["spine1"]["intf_list_leaf"][15]],
   #                [Vlan.delete_vlan_member, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["vlan_list"][3],
   #                 evpn_dict["spine2"]["intf_list_leaf"][15]]])

    st.log("Remove VLAN used for VE interface b/w and spine nodes")
   #utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vlan_list"][0]],
   #                      [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vlan_list"][0]],
   #                      [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vlan_list"][0]],
   #                      [Vlan.delete_vlan, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vlan_list"][0]],
   #                      [Vlan.delete_vlan, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["vlan_list"][0]],
   #                      [Vlan.delete_vlan, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["vlan_list"][0]]])
   #utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["vlan_list"][1]],
   #                      [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vlan_list"][1]],
   #                      [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vlan_list"][1]],
   #                      [Vlan.delete_vlan, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vlan_list"][1]],
   #                      [Vlan.delete_vlan, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["vlan_list"][1]],
   #                      [Vlan.delete_vlan, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["vlan_list"][1]]])
   #utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["vlan_list"][2]],
   #                      [Vlan.delete_vlan, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["vlan_list"][2]]])
   #utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["vlan_list"][3]],
   #                       [Vlan.delete_vlan, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["vlan_list"][3]]])

def convert_base_mac(mac):
    mac = mac.lower()
    mac = mac[0:2]+":"+mac[2:4]+":"+mac[4:6]+":"+mac[6:8]+":"+mac[8:10]+":"+mac[10:12]
    return mac

def enable_debugs():
    global vars
    cmd = "debug zebra rib detailed \n  debug zebra nht detailed \n debug vrf \n debug zebra fpm \n debug zebra events \n debug zebra dplane detailed\n"
    utils.exec_all(True,[[st.vtysh_config,vars.D1,cmd],[st.vtysh_config,vars.D2,cmd]])

def disable_debugs():
    global vars
    cmd = "no debug zebra rib \n no debug zebra nht \n no debug vrf \n no debug zebra fpm \n no debug zebra events \n no debug zebra dplane \n"
    utils.exec_all(True,[[st.vtysh_config,vars.D1,cmd],[st.vtysh_config,vars.D2,cmd]])

def hdrMsg(msg):
    st.log("\n######################################################################" \
    " \n%s\n######################################################################"%msg)

def retry_api(func,args,**kwargs):
    retry_count = kwargs.get("retry_count", 5)
    delay = kwargs.get("delay", 5)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if func(args,**kwargs):
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retrying again"%delay)
            st.wait(delay)
    return False

def retry_api_false(func,args,**kwargs):
    retry_count = kwargs.get("retry_count", 5)
    delay = kwargs.get("delay", 5)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if not func(args,**kwargs):
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retrying again"%delay)
            st.wait(delay)
    return False

'''
def create_stream(traffic_type, port_han_list=[],def_param=True, rate=1000, **kwargs):

    global tg, d5_tg_ph1, d6_tg_ph1,count,stream_dict

    if 'src_mac_count_list' in kwargs:
        src_mac_count_list = kwargs['src_mac_count_list']
    else:
        src_mac_count_list = ['10','10']
    if 'dst_mac_count_list' in kwargs:
        dst_mac_count_list = kwargs['dst_mac_count_list']
    else:
        dst_mac_count_list = ['10','10']
    if 'src_ip_count_list' in kwargs:
        src_ip_count_list = kwargs['src_ip_count_list']
    else:
        src_ip_count_list = ['10','10']
    if 'dst_ip_count_list' in kwargs:
        dst_ip_count_list = kwargs['dst_ip_count_list']
    else:
        dst_ip_count_list = ['10','10']


    if traffic_type == "l2":
        if not def_param:
            if 'frame_size_list' in kwargs:
                 frame_size_list=kwargs['frame_size_list']
            else:
                 frame_size_list=['1000','1000']
            for ph, smac, dmac, vlan, smac_count, dmac_count,frame_size in \
                    zip(port_han_list, kwargs["src_mac_list"], kwargs["dst_mac_list"],
                        kwargs["vlan_id_list"], kwargs["src_mac_count_list"], kwargs["dst_mac_count_list"], frame_size_list):
                stream = tg.tg_traffic_config(mac_src=smac, mac_dst=dmac, vlan="enable",
                                    rate_pps=rate, mode='create', port_handle=ph, l2_encap='ethernet_ii_vlan',
                                    vlan_id=vlan,transmit_mode='continuous', mac_src_count=smac_count,
                                    mac_dst_count=dmac_count, mac_src_mode="increment", mac_dst_mode="increment",
                                    mac_src_step="00.00.00.00.00.01", mac_dst_step="00.00.00.00.00.01",frame_size=frame_size)
                stream_dict[str(count)] = stream['stream_id']
                count=count+1
        else:
            port1 = d5_tg_ph1
            for ph, vlan,src_mac_cnt,dst_mac_cnt in zip([d5_tg_ph1,d6_tg_ph1], [evpn_dict["leaf3"]["tenant_l2_vlan_list"][0]] * 2,src_mac_count_list,dst_mac_count_list):
                if ph == port1:
                    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_l2"], vlan="enable",
                                    mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"], rate_pps=1000, mode='create',
                                    port_handle=ph, l2_encap='ethernet_ii_vlan', vlan_id=vlan,
                                    transmit_mode='continuous', mac_src_count=src_mac_cnt, mac_dst_count=dst_mac_cnt,
                                    mac_src_mode="increment", mac_dst_mode="increment",
                                    mac_src_step="00.00.00.00.00.01", mac_dst_step="00.00.00.00.00.01")
                else:
                    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_l2"], vlan="enable",
                                    mac_dst=evpn_dict["leaf3"]["tenant_mac_l2"], rate_pps=1000, mode='create',
                                    port_handle=ph, l2_encap='ethernet_ii_vlan', vlan_id=vlan,
                                    transmit_mode='continuous', mac_src_count=src_mac_cnt, mac_dst_count=dst_mac_cnt,
                                    mac_src_mode="increment", mac_dst_mode="increment",
                                    mac_src_step="00.00.00.00.00.01", mac_dst_step="00.00.00.00.00.01")
                stream_dict[str(count)] = stream['stream_id']
                count = count+1
    elif traffic_type=="ipv4":
        if not def_param:
            for ph, smac, smac_count, dmac, sip, dip, sip_step, dip_step, dip_count,vlan,gw_ip in \
                    zip(port_han_list, kwargs["src_mac_list"], kwargs["src_mac_count_list"],
                        kwargs["dst_mac_list"], kwargs["src_ip_list"],
                        kwargs["dst_ip_list"], kwargs["src_ip_step_list"], kwargs["dst_ip_step_list"],
                        kwargs["dst_ip_count_list"],kwargs["vlan_id_list"],kwargs["gw_ip_list"]):
                stream=tg.tg_traffic_config(mac_src=smac, mac_src_count=smac_count,
                        mac_dst=dmac, rate_pps=rate, mode='create', port_handle=ph, l2_encap='ethernet_ii_vlan',
                        transmit_mode='continuous', ip_src_addr=sip, ip_src_count=smac_count, ip_src_step=sip_step,
                        ip_dst_addr=dip, ip_dst_count=dip_count, ip_dst_step=dip_step, l3_protocol= 'ipv4',
                        l3_length='512',vlan_id=vlan,vlan="enable",mac_src_mode="increment",mac_discovery_gw=gw_ip,
                        mac_src_step="00.00.00.00.00.01",ip_src_mode="increment",ip_dst_mode="increment")
                stream_dict[str(count)] = stream['stream_id']
                count=count+1
                han = tg.tg_interface_config(port_handle=ph, mode='config',
                                intf_ip_addr=sip, gateway=gw_ip, vlan='1', vlan_id=vlan,
                                vlan_id_step='0',arp_send_req='1', gateway_step='0.0.0.0',
                                intf_ip_addr_step='0.0.0.1', count=smac_count, src_mac_addr=smac)
                tg.tg_arp_control(handle=han["handle"], arp_target='all')
                if han_dict.get(ph, None):
                    han_dict[ph].append(han["handle"])
                else:
                    han_dict[ph] = han["handle"]
        else:
            port1 = d5_tg_ph1
            for ph, dmac, vlan,ipv4_src_count,ipv4_dest_count in zip([d5_tg_ph1, d6_tg_ph1],kwargs["dst_mac_list"],
                                [evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
                                evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]],src_ip_count_list,dst_ip_count_list):
                if ph == port1:
                    stream=tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_v4"],
                        mac_dst=dmac, rate_pps=rate, mode='create', port_handle=ph, l2_encap='ethernet_ii_vlan',
                        transmit_mode='continuous', ip_src_addr=evpn_dict["leaf3"]["tenant_v4_ip"],
                        ip_src_count=ipv4_src_count, ip_src_step="0.0.0.1", ip_dst_addr=evpn_dict["leaf4"]["tenant_v4_ip"],
                        ip_dst_count=ipv4_dest_count, ip_dst_step="0.0.0.1", l3_protocol= 'ipv4',l3_length='512',
                        vlan_id=vlan,vlan="enable",ip_src_mode="increment",ip_dst_mode="increment",
                        mac_discovery_gw=evpn_dict["leaf3"]["l3_tenant_ip_list"][0])
                    han = tg.tg_interface_config(port_handle=ph, mode='config',
                                    intf_ip_addr=evpn_dict["leaf3"]["tenant_v4_ip"],
                                    gateway=evpn_dict["leaf3"]["l3_tenant_ip_list"][0], vlan='1',
                                    vlan_id=vlan,vlan_id_step='0', arp_send_req='1', gateway_step='0.0.0.0',
                                    intf_ip_addr_step='0.0.0.1', count=ipv4_src_count,
                                    src_mac_addr=evpn_dict["leaf3"]["tenant_mac_v4"])
                    tg.tg_arp_control(handle=han["handle"], arp_target='all')
                else:
                    stream=tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_v4"],
                        mac_dst=dmac, rate_pps=rate, mode='create', port_handle=ph, l2_encap='ethernet_ii_vlan',
                        transmit_mode='continuous', ip_src_addr=evpn_dict["leaf4"]["tenant_v4_ip"],
                        ip_src_count=10, ip_src_step="0.0.0.1", ip_dst_addr=evpn_dict["leaf3"]["tenant_v4_ip"],
                        ip_dst_count=10, ip_dst_step="0.0.0.1", l3_protocol= 'ipv4',l3_length='512',
                        vlan_id=vlan,vlan="enable",mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ip_list"][0],
                        ip_src_mode="increment",ip_dst_mode="increment")
                    han = tg.tg_interface_config(port_handle=ph, mode='config',
                                    intf_ip_addr=evpn_dict["leaf4"]["tenant_v4_ip"],
                                    gateway=evpn_dict["leaf4"]["l3_tenant_ip_list"][0], vlan='1',
                                    vlan_id=vlan,vlan_id_step='0', arp_send_req='1', gateway_step='0.0.0.0',
                                    intf_ip_addr_step='0.0.0.1', count=ipv4_src_count,
                                    src_mac_addr=evpn_dict["leaf4"]["tenant_mac_v4"])
                    tg.tg_arp_control(handle=han["handle"], arp_target='all')
                stream_dict[str(count)] = stream['stream_id']
                count=count+1
                if han_dict.get(ph, None):
                    han_dict[ph].append(han["handle"])
                else:
                    han_dict[ph] = han["handle"]
    elif traffic_type=="ipv6":
        if not def_param:
            for ph, smac, smac_count, dmac, sip, dip, sip_step, dip_step, dip_count,vlan,gw_ip in \
                    zip(port_han_list, kwargs["src_mac_list"], kwargs["src_mac_count_list"],
                        kwargs["dst_mac_list"], kwargs["src_ip_list"],
                        kwargs["dst_ip_list"], kwargs["src_ip_step_list"], kwargs["dst_ip_step_list"],
                        kwargs["dst_ip_count_list"],kwargs["vlan_id_list"],kwargs["gw_ip_list"]):
                stream=tg.tg_traffic_config(mac_src=smac, mac_src_count=smac_count,
                        mac_dst=dmac, rate_pps=rate, mode='create', port_handle=ph, l2_encap='ethernet_ii_vlan',
                        transmit_mode='continuous', ipv6_src_addr=sip, ipv6_src_count=smac_count,
                        ipv6_src_step=sip_step,ipv6_dst_addr=dip, ipv6_dst_count=dip_count,
                        ipv6_dst_step=dip_step, l3_protocol= 'ipv6', l3_length='512', vlan_id=vlan,
                        vlan="enable",mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                        ipv6_src_mode="increment",ipv6_dst_mode="increment",mac_discovery_gw=gw_ip)
                stream_dict[str(count)] = stream['stream_id']
                count = count + 1
                han = tg.tg_interface_config(port_handle=ph, mode='config', ipv6_intf_addr=sip,
                                ipv6_prefix_length='96', ipv6_gateway=gw_ip, src_mac_addr=smac,
                                arp_send_req='1',vlan='1', vlan_id=vlan, vlan_id_step='0',count=smac_count,
                                ipv6_intf_addr_step='0::1',ipv6_gateway_step='0::0')
                tg.tg_arp_control(handle=han["handle"], arp_target='all')
                if han_dict.get(ph, None):
                    han_dict[ph].append(han["handle"])
                else:
                    han_dict[ph] = han["handle"]
        else:
            port1 = d5_tg_ph1
            for ph, dmac, vlan,sip_count,dip_count in zip([d5_tg_ph1, d6_tg_ph1],kwargs["dst_mac_list"],
                                [evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
                                evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]],src_ip_count_list,dst_ip_count_list):
                if ph == port1:
                    stream=tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_v6"], mac_src_count=sip_count,
                        mac_dst=dmac, rate_pps=rate, mode='create', port_handle=ph, l2_encap='ethernet_ii_vlan',
                        transmit_mode='continuous', ipv6_src_addr=evpn_dict["leaf3"]["tenant_v6_ip"],
                        ipv6_src_count=sip_count, ipv6_src_step="00::1", ipv6_dst_addr=evpn_dict["leaf4"]["tenant_v6_ip"],
                        ipv6_dst_count=dip_count, ipv6_dst_step="00::1", l3_protocol= 'ipv6',l3_length='512',
                        vlan_id=vlan,vlan="enable",mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                        ipv6_src_mode="increment",ipv6_dst_mode="increment",
                        mac_discovery_gw=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0])
                    han = tg.tg_interface_config(port_handle=ph, mode='config',
                                    ipv6_intf_addr=evpn_dict["leaf3"]["tenant_v6_ip"], ipv6_prefix_length='96',
                                    ipv6_gateway=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0],
                                    src_mac_addr=evpn_dict["leaf3"]["tenant_mac_v6"],
                                    arp_send_req='1', vlan='1', vlan_id=vlan, vlan_id_step='0',
                                    count=sip_count, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
                    tg.tg_arp_control(handle=han["handle"], arp_target='all')
                else:
                    stream=tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_v6"], mac_src_count=sip_count,
                        mac_dst=dmac, rate_pps=rate, mode='create', port_handle=ph, l2_encap='ethernet_ii_vlan',
                        transmit_mode='continuous', ipv6_src_addr=evpn_dict["leaf4"]["tenant_v6_ip"],
                        ipv6_src_count=sip_count, ipv6_src_step="00::1", ipv6_dst_addr=evpn_dict["leaf3"]["tenant_v6_ip"],
                        ipv6_dst_count=dip_count, ipv6_dst_step="00::1", l3_protocol= 'ipv6',l3_length='512',
                        vlan_id=vlan,vlan="enable",mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                        ipv6_src_mode="increment",ipv6_dst_mode="increment",
                        mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0])
                    han = tg.tg_interface_config(port_handle=ph, mode='config',
                                    ipv6_intf_addr=evpn_dict["leaf4"]["tenant_v6_ip"], ipv6_prefix_length='96',
                                    ipv6_gateway=evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0],
                                    src_mac_addr=evpn_dict["leaf4"]["tenant_mac_v6"],
                                    arp_send_req='1', vlan='1', vlan_id=vlan, vlan_id_step='0',
                                    count=sip_count,ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
                    tg.tg_arp_control(handle=han["handle"], arp_target='all')
                stream_dict[str(count)] = stream['stream_id']
                count=count+1
                if han_dict.get(ph, None):
                    han_dict[ph].append(han["handle"])
                else:
                    han_dict[ph] = han["handle"]
'''

def create_stream():
    global tg, d5_tg_ph1, d6_tg_ph1,count,stream_dict

    dut5_gateway_mac = evpn_dict["dut5_gw_mac"]
    dut6_gateway_mac = evpn_dict["dut6_gw_mac"]
    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_l2"], vlan="enable",
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"], rate_pps=1000, mode='create',
                                  port_handle=d5_tg_ph1, l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],mac_src_count=10,
                                  mac_dst_count=10,mac_src_mode="increment", mac_dst_mode="increment",
                                  mac_src_step="00.00.00.00.00.01", mac_dst_step="00.00.00.00.00.01")
    stream1 = stream['stream_id']
    st.log("L2 stream {} is created for Tgen port {}".format(stream1,vars.T1D5P1))

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_l2"], vlan="enable",
                                  mac_dst=evpn_dict["leaf3"]["tenant_mac_l2"], rate_pps=1000, mode='create',
                                  port_handle=d6_tg_ph1, l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],mac_src_count=10,
                                  mac_dst_count=10,mac_src_mode="increment", mac_dst_mode="increment",
                                  mac_src_step="00.00.00.00.00.01", mac_dst_step="00.00.00.00.00.01")
    stream2 = stream['stream_id']
    st.log("L2 stream {} is created for Tgen port {}".format(stream2, vars.T1D6P1))

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_v4"],
                                  mac_dst=dut5_gateway_mac, rate_pps=1000, mode='create', port_handle=d5_tg_ph1,
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous', ip_src_count=10,
                                  ip_src_addr=evpn_dict["leaf3"]["tenant_v4_ip"],ip_src_step="0.0.0.1",
                                  ip_dst_addr=evpn_dict["leaf4"]["tenant_v4_ip"],ip_dst_count=10,ip_dst_step="0.0.0.1",
                                  l3_protocol='ipv4',l3_length='512',ip_src_mode="increment",ip_dst_mode="increment",
                                  vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], vlan="enable",
                                  mac_discovery_gw=evpn_dict["leaf3"]["l3_tenant_ip_list"][0])
    stream3 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream3, vars.T1D5P1))

    han = tg.tg_interface_config(port_handle=d5_tg_ph1, mode='config',intf_ip_addr=evpn_dict["leaf3"]["tenant_v4_ip"],
                                 gateway=evpn_dict["leaf3"]["l3_tenant_ip_list"][0], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=10,
                                 src_mac_addr=evpn_dict["leaf3"]["tenant_mac_v4"])
    host1 = han["handle"]
    #tg.tg_arp_control(handle=host1, arp_target='all')
    st.log("Ipv4 host {} is created for Tgen port {}".format(host1, vars.T1D5P1))

    stream=tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_v4"],
                        mac_dst=dut6_gateway_mac, rate_pps=1000, mode='create', port_handle=d6_tg_ph1,
                        l2_encap='ethernet_ii_vlan',transmit_mode='continuous',ip_src_count=10,
                        ip_src_addr=evpn_dict["leaf4"]["tenant_v4_ip"],ip_src_step="0.0.0.1",
                        ip_dst_addr=evpn_dict["leaf3"]["tenant_v4_ip"],ip_dst_count=10, ip_dst_step="0.0.0.1",
                        l3_protocol= 'ipv4',l3_length='512',ip_src_mode="increment",ip_dst_mode="increment",
                        vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],vlan="enable",
                        mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ip_list"][0])
    stream4 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream4, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=d6_tg_ph1, mode='config',intf_ip_addr=evpn_dict["leaf4"]["tenant_v4_ip"],
                                 gateway=evpn_dict["leaf4"]["l3_tenant_ip_list"][0], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=10,
                                 src_mac_addr=evpn_dict["leaf4"]["tenant_mac_v4"])
    host2 = han["handle"]
    #tg.tg_arp_control(handle=host2, arp_target='all')
    st.log("Ipv4 host {} is created for Tgen port {}".format(host2, vars.T1D6P1))

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_v6"], mac_src_count=10,
                                  mac_dst=dut5_gateway_mac, rate_pps=1000, mode='create', port_handle=d5_tg_ph1,
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr=evpn_dict["leaf3"]["tenant_v6_ip"],ipv6_src_count=10,
                                  ipv6_src_step="00::1",ipv6_dst_addr=evpn_dict["leaf4"]["tenant_v6_ip"],
                                  ipv6_dst_count=10, ipv6_dst_step="00::1", l3_protocol='ipv6', l3_length='512',
                                  vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], vlan="enable",
                                  mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  ipv6_src_mode="increment", ipv6_dst_mode="increment",
                                  mac_discovery_gw=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0])
    stream5 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream5, vars.T1D5P1))

    han = tg.tg_interface_config(port_handle=d5_tg_ph1, mode='config',
                                 ipv6_intf_addr=evpn_dict["leaf3"]["tenant_v6_ip"], ipv6_prefix_length='96',
                                 ipv6_gateway=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0],
                                 src_mac_addr=evpn_dict["leaf3"]["tenant_mac_v6"],
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=10, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host3 = han["handle"]
    #tg.tg_arp_control(handle=host3, arp_target='all')
    st.log("Ipv6 host {} is created for Tgen port {}".format(host3, vars.T1D5P1))

    stream=tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_v6"], mac_src_count=10,
                        mac_dst=dut6_gateway_mac, rate_pps=1000, mode='create', port_handle=d6_tg_ph1,
                        l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                        ipv6_src_addr=evpn_dict["leaf4"]["tenant_v6_ip"],ipv6_src_count=10,
                        ipv6_src_step="00::1", ipv6_dst_addr=evpn_dict["leaf3"]["tenant_v6_ip"],
                        ipv6_dst_count=10, ipv6_dst_step="00::1", l3_protocol= 'ipv6',l3_length='512',
                        vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],vlan="enable",
                        mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                        ipv6_src_mode="increment",ipv6_dst_mode="increment",
                        mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0])
    stream6 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream6, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=d6_tg_ph1, mode='config',
                                 ipv6_intf_addr=evpn_dict["leaf4"]["tenant_v6_ip"], ipv6_prefix_length='96',
                                 ipv6_gateway=evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0],
                                 src_mac_addr=evpn_dict["leaf4"]["tenant_mac_v6"],
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=10,ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host4 = han["handle"]
    #tg.tg_arp_control(handle=host4, arp_target='all')
    st.log("Ipv6 host {} is created for Tgen port {}".format(host4, vars.T1D6P1))

    stream_dict["all"]=[stream1,stream2,stream3,stream4,stream5,stream6]
    stream_dict["l2"]=[stream1,stream2]
    stream_dict["l3"]=[stream3,stream4,stream5,stream6]
    stream_dict["l3_v4host_1"] = host1
    stream_dict["l3_v4host_2"] = host2
    stream_dict["l3_v6host_1"] = host3
    stream_dict["l3_v6host_2"] = host4
    '''
    stream_dict["tx_stream_all"] = [stream_dict["l2_def_" + tg_dict['d5_tg_ph1']],
                                    stream_dict["ipv4_def_" + tg_dict['d5_tg_ph1']],
                                    stream_dict["ipv6_def_" + tg_dict['d5_tg_ph1']]]
    stream_dict["rx_stream_all"] = [stream_dict["l2_def_" + tg_dict['d6_tg_ph1']],
                                    stream_dict["ipv4_def_" + tg_dict['d6_tg_ph1']],
                                    stream_dict["ipv6_def_" + tg_dict['d6_tg_ph1']]]
    stream_dict["tx_stream_l3"] = [stream_dict["ipv4_def_" + tg_dict['d5_tg_ph1']],
                                   stream_dict["ipv6_def_" + tg_dict['d5_tg_ph1']]]
    stream_dict["rx_stream_l3"] = [stream_dict["ipv4_def_" + tg_dict['d6_tg_ph1']],
                                   stream_dict["ipv6_def_" + tg_dict['d6_tg_ph1']]]
    stream_dict["tx_stream_l2"] = stream_dict["l2_def_" + tg_dict['d5_tg_ph1']]
    stream_dict["rx_stream_l2"] = stream_dict["l2_def_" + tg_dict['d6_tg_ph1']]
    stream_dict["tx_stream_ipv4"] = stream_dict["ipv4_def_"+tg_dict['d5_tg_ph1']]
    stream_dict["rx_stream_ipv4"] = stream_dict["ipv4_def_"+tg_dict['d6_tg_ph1']]
    stream_dict["tx_stream_ipv6"] = stream_dict["ipv6_def_" + tg_dict['d5_tg_ph1']]
    stream_dict["rx_stream_ipv6"] = stream_dict["ipv6_def_" + tg_dict['d6_tg_ph1']]
    '''
    stream = tg.tg_traffic_config(mac_src='00:10:00:05:01:01', vlan="enable",
                                  mac_dst='00:10:00:06:01:01', rate_pps=1000, mode='create',
                                  port_handle=d5_tg_ph1, l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  vlan_id=200,mac_src_count=10,mac_dst_count=10,mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream7 = stream['stream_id']
    st.log("L2 stream {} is created for testcase 3214 at Tgen port {}".format(stream7,vars.T1D5P1))

    stream = tg.tg_traffic_config(mac_src='00:10:00:06:01:01', vlan="enable",
                                  mac_dst='00:10:00:05:01:01', rate_pps=1000, mode='create',
                                  port_handle=d6_tg_ph1, l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  vlan_id=200,mac_src_count=10,mac_dst_count=10,mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream8 = stream['stream_id']
    st.log("L2 stream {} is created for testcase 3214 at Tgen port {}".format(stream8, vars.T1D6P1))

    stream_dict["l2_3214"]=[stream7,stream8]
    '''
    stream_dict["tx_stream_l2_3214"] = stream_dict["l2_3214_" + tg_dict['d5_tg_ph1']]
    stream_dict["rx_stream_l2_3214"] = stream_dict["l2_3214_" + tg_dict['d6_tg_ph1']]
    '''
    stream = tg.tg_traffic_config(mac_src='00:10:00:05:01:01', vlan="enable",
                                  mac_dst='00:44:11:00:00:01', rate_pps=1000, mode='create',
                                  port_handle=d5_tg_ph1, l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0])
    stream9 = stream['stream_id']
    st.log("L2 stream {} is created for testcase 32219 at Tgen port {}".format(stream9, vars.T1D5P1))

    stream = tg.tg_traffic_config(mac_src='00:44:11:00:00:01', vlan="enable",
                                  mac_dst='00:10:00:05:01:01', rate_pps=1000, mode='create',
                                  port_handle=d6_tg_ph1, l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  vlan_id=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0])
    stream10 = stream['stream_id']
    st.log("L2 stream {} is created for testcase 32219 at Tgen port {}".format(stream10, vars.T1D6P1))

    stream = tg.tg_traffic_config(mac_src='00:44:11:00:00:01', vlan="enable",
                                  mac_dst='00:10:00:05:01:01', rate_pps=1000, mode='create',
                                  port_handle=tg_dict['d5_tg_ph2'], l2_encap='ethernet_ii_vlan',
                                  transmit_mode='continuous',vlan_id=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0])
    stream11 = stream['stream_id']
    st.log("L2 stream {} is created for testcase 32219 at Tgen port {}".format(stream11, vars.T1D5P2))

    stream_dict["l2_32219_1"] = [stream9,stream10]
    stream_dict["l2_32219_2"] = [stream11]

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d5_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream12 = stream['stream_id']
    st.log("L2 stream {} is created for testcase 32220 at Tgen port {}".format(stream12, vars.T1D5P1))
    stream_dict["l2_32220_1"] = stream12

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf3"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d6_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream13 = stream['stream_id']
    st.log("L2 stream {} is created for testcase 32220 at Tgen port {}".format(stream13, vars.T1D6P1))
    stream_dict["l2_32220_2"] = stream13

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d4_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream14 = stream['stream_id']
    st.log("L2 stream {} is created for testcase 32220 at Tgen port {}".format(stream13, vars.T1D4P1))
    stream_dict["l2_32220_3"] = stream14

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_l2"], mac_dst="ff:ff:ff:ff:ff:ff",
                                  rate_pps=tg_dict['tgen_rate_pps'], mode='create',
                                  port_handle=tg_dict["d5_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], transmit_mode='continuous')
    stream15 = stream['stream_id']
    st.log("L2 stream {} is created for testcase 32216 at Tgen port {}".format(stream13, vars.T1D5P1))
    stream_dict["l2_32216"] = stream15

    stream=tg.tg_traffic_config(mac_src='00:10:14:05:01:01',
                        mac_dst=dut5_gateway_mac, rate_pps=1000, mode='create', port_handle=d5_tg_ph1,
                        l2_encap='ethernet_ii_vlan',transmit_mode='continuous',ip_src_count=1,
                        ip_src_addr='50.1.1.100',ip_src_step="0.0.0.1",
                        ip_dst_addr='60.1.1.100',ip_dst_count=1, ip_dst_step="0.0.0.1",
                        l3_protocol= 'ipv4',l3_length='512',ip_src_mode="increment",ip_dst_mode="increment",
                        vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],vlan="enable",
                        mac_discovery_gw=evpn_dict["leaf3"]["l3_tenant_ip_list"][0])
    stream16 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream16, vars.T1D5P1))

    han = tg.tg_interface_config(port_handle=d5_tg_ph1, mode='config',intf_ip_addr='50.1.1.100',
                                 gateway=evpn_dict["leaf3"]["l3_tenant_ip_list"][0], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr='00:10:14:05:01:01')
    host5 = han["handle"]
    #tg.tg_arp_control(handle=host5, arp_target='all')
    st.log("Ipv4 host {} is created for Tgen port {}".format(host5, vars.T1D5P1))

    stream=tg.tg_traffic_config(mac_src='00:10:14:06:01:01',
                        mac_dst=dut6_gateway_mac, rate_pps=1000, mode='create', port_handle=d6_tg_ph1,
                        l2_encap='ethernet_ii_vlan',transmit_mode='continuous',ip_src_count=1,
                        ip_src_addr='60.1.1.100',ip_src_step="0.0.0.1",
                        ip_dst_addr='50.1.1.100',ip_dst_count=1, ip_dst_step="0.0.0.1",
                        l3_protocol= 'ipv4',l3_length='512',ip_src_mode="increment",ip_dst_mode="increment",
                        vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],vlan="enable",
                        mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ip_list"][0])
    stream17 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream17, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=d6_tg_ph1, mode='config',intf_ip_addr='60.1.1.100',
                                 gateway=evpn_dict["leaf4"]["l3_tenant_ip_list"][0], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr='00:10:14:06:01:01')
    host6 = han["handle"]
    #tg.tg_arp_control(handle=host6, arp_target='all')
    st.log("Ipv4 host {} is created for Tgen port {}".format(host6, vars.T1D6P1))

    stream = tg.tg_traffic_config(mac_src='00:10:16:05:01:01', mac_src_count=1,
                                  mac_dst=dut5_gateway_mac, rate_pps=1000, mode='create', port_handle=d5_tg_ph1,
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='5001::100',ipv6_src_count=1,
                                  ipv6_src_step="00::1",ipv6_dst_addr='6001::100',
                                  ipv6_dst_count=1, ipv6_dst_step="00::1", l3_protocol='ipv6', l3_length='512',
                                  vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][1], vlan="enable",
                                  mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  ipv6_src_mode="increment", ipv6_dst_mode="increment",
                                  mac_discovery_gw=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0])
    stream18 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream18, vars.T1D5P1))

    han = tg.tg_interface_config(port_handle=d5_tg_ph1, mode='config',
                                 ipv6_intf_addr='5001::100', ipv6_prefix_length='96',
                                 ipv6_gateway=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0],
                                 src_mac_addr='00:10:16:05:01:01',arp_send_req='1', vlan='1',
                                 vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host7 = han["handle"]
    #tg.tg_arp_control(handle=host7, arp_target='all')
    st.log("Ipv6 host {} is created for Tgen port {}".format(host7, vars.T1D5P1))

    stream=tg.tg_traffic_config(mac_src='00:10:16:06:01:01', mac_src_count=1,
                        mac_dst=dut6_gateway_mac, rate_pps=1000, mode='create', port_handle=d6_tg_ph1,
                        l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                        ipv6_src_addr='6001::100',ipv6_src_count=1,
                        ipv6_src_step="00::1", ipv6_dst_addr='5001::100',
                        ipv6_dst_count=1, ipv6_dst_step="00::1", l3_protocol= 'ipv6',l3_length='512',
                        vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],vlan="enable",
                        mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                        ipv6_src_mode="increment",ipv6_dst_mode="increment",
                        mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0])
    stream19 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream19, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=d6_tg_ph1, mode='config',
                                 ipv6_intf_addr='6001::100', ipv6_prefix_length='96',
                                 ipv6_gateway=evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0],
                                 src_mac_addr='00:10:16:06:01:01',arp_send_req='1', vlan='1',
                                 vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],
                                 vlan_id_step='0',count=1,ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host8 = han["handle"]
    #tg.tg_arp_control(handle=host8, arp_target='all')
    st.log("Ipv6 host {} is created for Tgen port {}".format(host8, vars.T1D6P1))
    stream_dict["l3_32426"] = [stream16,stream17,stream18,stream19]
    stream_dict["v4host_1_32426"] = host5
    stream_dict["v4host_2_32426"] = host6
    stream_dict["v6host_1_32426"] = host7
    stream_dict["v6host_2_32426"] = host8

    stream=tg.tg_traffic_config(mac_src='00:00:14:05:01:01',
                        mac_dst=dut5_gateway_mac, rate_pps=1000, mode='create', port_handle=d5_tg_ph1,
                        l2_encap='ethernet_ii_vlan',transmit_mode='continuous',ip_src_count=1,
                        ip_src_addr='19.1.1.100',ip_src_step="0.0.0.1",
                        ip_dst_addr='20.1.1.100',ip_dst_count=1, ip_dst_step="0.0.0.1",
                        l3_protocol= 'ipv4',l3_length='512',ip_src_mode="increment",ip_dst_mode="increment",
                        vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],vlan="enable",
                        mac_discovery_gw="19.1.1.3")
    stream20 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream20, vars.T1D5P1))

    han = tg.tg_interface_config(port_handle=d5_tg_ph1, mode='config',intf_ip_addr='19.1.1.100',
                                 gateway="19.1.1.3", vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr='00:00:14:05:01:01')
    host9 = han["handle"]
    #tg.tg_arp_control(handle=host9, arp_target='all')
    st.log("Ipv4 host {} is created for Tgen port {}".format(host9, vars.T1D5P1))

    stream=tg.tg_traffic_config(mac_src='00:00:14:06:01:01',
                        mac_dst=dut6_gateway_mac, rate_pps=1000, mode='create', port_handle=d6_tg_ph2,
                        l2_encap='ethernet_ii_vlan',transmit_mode='continuous',ip_src_count=1,
                        ip_src_addr='20.1.1.100',ip_src_step="0.0.0.1",
                        ip_dst_addr='19.1.1.100',ip_dst_count=1, ip_dst_step="0.0.0.1",
                        l3_protocol= 'ipv4',l3_length='512',ip_src_mode="increment",ip_dst_mode="increment",
                        vlan_id=evpn_dict["leaf4"]["tenant_l2_vlan_list"][1],vlan="enable",
                        mac_discovery_gw="20.1.1.4")
    stream21 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream21, vars.T1D6P2))

    han = tg.tg_interface_config(port_handle=d6_tg_ph2, mode='config',intf_ip_addr='20.1.1.100',
                                 gateway="20.1.1.4", vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["leaf4"]["tenant_l2_vlan_list"][1],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr='00:00:14:06:01:01')
    host10 = han["handle"]
    #tg.tg_arp_control(handle=host10, arp_target='all')
    st.log("Ipv4 host {} is created for Tgen port {}".format(host10, vars.T1D6P2))
    stream_dict["l3_32417"] = [stream20,stream21]
    stream_dict["v4host_1_32417"] = host9
    stream_dict["v4host_2_32417"] = host10

    stream = tg.tg_traffic_config(mac_src='00:10:00:05:01:01', vlan="enable",
                                  mac_dst='00:10:00:06:01:01', rate_pps=1000, mode='create',
                                  port_handle=d5_tg_ph1, l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  vlan_id=200,mac_src_count=10,mac_dst_count=10,mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream22 = stream['stream_id']
    st.log("L2 stream {} is created for Tgen port {}".format(stream22,vars.T1D5P1))

    stream = tg.tg_traffic_config(mac_src='00:10:00:06:01:01', vlan="enable",
                                  mac_dst='00:10:00:05:01:01', rate_pps=1000, mode='create',
                                  port_handle=d6_tg_ph1, l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  vlan_id=200,mac_src_count=10,mac_dst_count=10,mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream23 = stream['stream_id']
    st.log("L2 stream {} is created for Tgen port {}".format(stream23, vars.T1D6P1))
    stream_dict["l2_32227"] = [stream22,stream23]

    stream = tg.tg_traffic_config(mode='create', port_handle=d5_tg_ph1,transmit_mode="continuous",
                                  rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000', l2_encap='ethernet_ii_vlan',
                                  vlan="enable", vlan_id='200', vlan_id_count='10', vlan_id_mode="increment",
                                  vlan_id_step='1',mac_src=evpn_dict["leaf3"]["tenant_mac_l2"],
                                  mac_src_mode="increment", mac_src_step="00:00:00:00:00:01",mac_src_count='10',
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"], mac_dst_mode="increment",
                                  mac_dst_step="00:00:00:00:00:01",mac_dst_count='10')
    stream24 = stream['stream_id']
    st.log("L2 stream {} is created for Tgen port {}".format(stream24, vars.T1D5P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=d6_tg_ph1, transmit_mode="continuous",
                                  rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000', l2_encap='ethernet_ii_vlan',
                                  vlan="enable", vlan_id='200', vlan_id_count='10', vlan_id_mode="increment",
                                  vlan_id_step='1', mac_src=evpn_dict["leaf4"]["tenant_mac_l2"],
                                  mac_src_mode="increment", mac_src_step="00:00:00:00:00:01", mac_src_count='10',
                                  mac_dst=evpn_dict["leaf3"]["tenant_mac_l2"], mac_dst_mode="increment",
                                  mac_dst_step="00:00:00:00:00:01", mac_dst_count='10')
    stream25 = stream['stream_id']
    st.log("L2 stream {} is created for Tgen port {}".format(stream25, vars.T1D6P1))
    stream_dict["l2_32218"] = [stream24,stream25]

    stream=tg.tg_traffic_config(mac_src='00:10:41:05:01:01',
                        mac_dst=dut5_gateway_mac, rate_pps=1000, mode='create', port_handle=d5_tg_ph1,
                        l2_encap='ethernet_ii_vlan',transmit_mode='continuous',ip_src_count=1,
                        ip_src_addr='50.1.1.101',ip_src_step="0.0.0.1",
                        ip_dst_addr='60.1.2.100',ip_dst_count=1, ip_dst_step="0.0.0.1",
                        l3_protocol= 'ipv4',l3_length='512',ip_src_mode="increment",ip_dst_mode="increment",
                        vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],vlan="enable",
                        mac_discovery_gw=evpn_dict["leaf3"]["l3_tenant_ip_list"][0])
    stream26 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream26, vars.T1D5P1))

    han = tg.tg_interface_config(port_handle=d5_tg_ph1, mode='config',intf_ip_addr='50.1.1.101',
                                 gateway=evpn_dict["leaf3"]["l3_tenant_ip_list"][0], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr='00:10:41:05:01:01')
    host11 = han["handle"]
    #tg.tg_arp_control(handle=host11, arp_target='all')
    st.log("Ipv4 host {} is created for Tgen port {}".format(host11, vars.T1D5P1))

    stream=tg.tg_traffic_config(mac_src='00:10:41:06:01:01',
                        mac_dst=dut6_gateway_mac, rate_pps=1000, mode='create', port_handle=d6_tg_ph1,
                        l2_encap='ethernet_ii_vlan',transmit_mode='continuous',ip_src_count=1,
                        ip_src_addr='60.1.2.100',ip_src_step="0.0.0.1",
                        ip_dst_addr='50.1.1.101',ip_dst_count=1, ip_dst_step="0.0.0.1",
                        l3_protocol= 'ipv4',l3_length='512',ip_src_mode="increment",ip_dst_mode="increment",
                        vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],vlan="enable",
                        mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ip_list"][1])
    stream27 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream27, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=d6_tg_ph1, mode='config',intf_ip_addr='60.1.2.100',
                                 gateway=evpn_dict["leaf4"]["l3_tenant_ip_list"][1], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr='00:10:41:06:01:01')
    host12 = han["handle"]
    #tg.tg_arp_control(handle=host12, arp_target='all')
    st.log("Ipv4 host {} is created for Tgen port {}".format(host12, vars.T1D6P1))

    stream = tg.tg_traffic_config(mac_src='00:10:61:05:01:01', mac_src_count=1,
                                  mac_dst=dut5_gateway_mac, rate_pps=1000, mode='create', port_handle=d5_tg_ph1,
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='5001::101',ipv6_src_count=1,
                                  ipv6_src_step="00::1",ipv6_dst_addr='6002::100',
                                  ipv6_dst_count=1, ipv6_dst_step="00::1", l3_protocol='ipv6', l3_length='512',
                                  vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], vlan="enable",
                                  mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  ipv6_src_mode="increment", ipv6_dst_mode="increment",
                                  mac_discovery_gw=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0])
    stream28 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream28, vars.T1D5P1))

    han = tg.tg_interface_config(port_handle=d5_tg_ph1, mode='config',
                                 ipv6_intf_addr='5001::101', ipv6_prefix_length='96',
                                 ipv6_gateway=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0],
                                 src_mac_addr='00:10:61:05:01:01',arp_send_req='1', vlan='1',
                                 vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')

    host13 = han["handle"]
    #tg.tg_arp_control(handle=host13, arp_target='all')
    st.log("Ipv6 host {} is created for Tgen port {}".format(host13, vars.T1D5P1))

    stream=tg.tg_traffic_config(mac_src='00:10:61:06:01:01', mac_src_count=1,
                        mac_dst=dut6_gateway_mac, rate_pps=1000, mode='create', port_handle=d6_tg_ph1,
                        l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                        ipv6_src_addr='6002::100',ipv6_src_count=1,
                        ipv6_src_step="00::1", ipv6_dst_addr='5001::101',
                        ipv6_dst_count=1, ipv6_dst_step="00::1", l3_protocol= 'ipv6',l3_length='512',
                        vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],vlan="enable",
                        mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                        ipv6_src_mode="increment",ipv6_dst_mode="increment",
                        mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ipv6_list"][1])
    stream29 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream29, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=d6_tg_ph1, mode='config',
                                 ipv6_intf_addr='6002::100', ipv6_prefix_length='96',
                                 ipv6_gateway=evpn_dict["leaf4"]["l3_tenant_ipv6_list"][1],
                                 src_mac_addr='00:10:61:06:01:01',arp_send_req='1', vlan='1',
                                 vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][1],
                                 vlan_id_step='0',count=1,ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')

    host14 = han["handle"]
    #tg.tg_arp_control(handle=host14, arp_target='all')
    st.log("Ipv6 host {} is created for Tgen port {}".format(host14, vars.T1D6P1))
    stream_dict["l3_32412"] = [stream26,stream27,stream28,stream29]
    stream_dict["v4host_1_32412"] = host11
    stream_dict["v4host_2_32412"] = host12
    stream_dict["v6host_1_32412"] = host13
    stream_dict["v6host_2_32412"] = host14

def create_evpn_config():
    setup_underlay()
    setup_vxlan()
    setup_l2vni()
    setup_l3vni()


def start_traffic(stream_han_list=[],port_han_list=[],action="run"):
    global tg,d5_tg_ph1, d6_tg_ph1
    if action=="run":
        tg.tg_traffic_control(action="run", stream_handle=stream_han_list)
    else:
        if port_han_list:
            tg.tg_traffic_control(action="stop", port_handle=port_han_list)
        else:
            tg.tg_traffic_control(action="stop", stream_handle=stream_han_list)


def clear_stats(port_han_list=[]):
    global tg,d5_tg_ph1,d6_tg_ph1

    if port_han_list:
        tg.tg_traffic_control(action='clear_stats',port_handle=port_han_list)
    else:
        tg.tg_traffic_control(action='clear_stats',port_handle=[d5_tg_ph1,d6_tg_ph1])


def verify_traffic(tx_port="", rx_port="", tx_ratio=1, rx_ratio=1,
                       mode="aggregate", field="packet_rate", **kwargs):
    '''
    :param tx_port:
    :param rx_port:
    :param tx_ratio:
    :param rx_ratio:
    :param mode:
    :param field:
    :param kwargs:
    :param tx_stream_list:
    :param rx_stream_list:
    :return:
    '''

    global tg,stream_dict,d5_tg_port1,d6_tg_port1

    if not tx_port:
        tx_port=d5_tg_port1
    if not rx_port:
        rx_port=d6_tg_port1

    traffic_details = {
            '1': {
                'tx_ports': [tx_port],
                'tx_obj': [tg],
                'exp_ratio': [tx_ratio],
                'rx_ports': [rx_port],
                'rx_obj': [tg],
#                'stream_list': [tuple(kwargs["tx_stream_list"])]
            },
            '2': {
                'tx_ports': [rx_port],
                'tx_obj': [tg],
                'exp_ratio': [rx_ratio],
                'rx_ports': [tx_port],
                'rx_obj': [tg],
#                'stream_list': [tuple(kwargs["rx_stream_list"])]
            }
    }

    return validate_tgen_traffic(traffic_details=traffic_details, mode=mode, comp_type=field,tolerance_factor=2)


def reset_tgen(port_han_list=[]):
    global tg, d5_tg_ph1, d6_tg_ph1

    if port_han_list:
        tg.tg_traffic_control(action="reset", port_handle=port_han_list)
    else:
        tg.tg_traffic_control(action="reset", port_handle=[d5_tg_ph1,d6_tg_ph1])

'''
def create_stream_l2_multiVlans():
   tg = tg_dict['tg']
   for (src, dst, ph_src, ph_dst) in zip([evpn_dict["leaf3"]["tenant_mac_l2"], evpn_dict["leaf4"]["tenant_mac_l2"]], [evpn_dict["leaf4"]["tenant_mac_l2"], evpn_dict["leaf3"]["tenant_mac_l2"]], [tg_dict['d5_tg_ph1'], tg_dict['d6_tg_ph1']],[tg_dict['d6_tg_ph1'], tg_dict['d5_tg_ph1']]):
      stream = tg.tg_traffic_config(mode='create', port_handle=ph_src, port_handle2=ph_dst, \
                     transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000', \
                     l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='200', vlan_id_count='10', \
                     vlan_id_mode="increment", vlan_id_step='1',\
                     mac_src=src, mac_src_mode="increment", mac_src_step="00:00:00:00:00:01",
                     mac_src_count='10', \
                     mac_dst=dst, mac_dst_mode="increment", mac_dst_step="00:00:00:00:00:01",
                     mac_dst_count='10')

def create_stream_l2_multiVlans_macScale():
   tg = tg_dict['tg']
   for (src, dst, ph_src, ph_dst) in zip([evpn_dict["leaf3"]["tenant_mac_l2"], evpn_dict["leaf4"]["tenant_mac_l2"]], [evpn_dict["leaf4"]["tenant_mac_l2"], evpn_dict["leaf3"]["tenant_mac_l2"]], [tg_dict['d5_tg_ph1'], tg_dict['d6_tg_ph1']],[tg_dict['d6_tg_ph1'], tg_dict['d5_tg_ph1']]):
      stream = tg.tg_traffic_config(mode='create', port_handle=ph_src, port_handle2=ph_dst,
                     transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000', \
                     l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='200', vlan_id_count='1', \
                     vlan_id_mode="increment", vlan_id_step='1',\
                     mac_src=src, mac_src_mode="increment", mac_src_step="00:00:00:00:00:01",
                     mac_src_count='10000', \
                     mac_dst=dst, mac_dst_mode="increment", mac_dst_step="00:00:00:00:00:01",
                     mac_dst_count='10000',high_speed_result_analysis=0, enable_stream_only_gen='0')

   for (src, dst, ph_src, ph_dst) in zip([evpn_dict["leaf3"]["tenant_mac_l2_2"], evpn_dict["leaf4"]["tenant_mac_l2_2"]], [evpn_dict["leaf4"]["tenant_mac_l2_2"], evpn_dict["leaf3"]["tenant_mac_l2_2"]], [tg_dict['d5_tg_ph2'], tg_dict['d6_tg_ph2']],[tg_dict['d6_tg_ph2'], tg_dict['d5_tg_ph2']]):
      stream = tg.tg_traffic_config(mode='create', port_handle=ph_src, port_handle2=ph_dst,
                     transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000', \
                     l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='105', vlan_id_count='1', \
                     vlan_id_mode="increment", vlan_id_step='1',\
                     mac_src=src, mac_src_mode="increment", mac_src_step="00:00:00:00:00:01",
                     mac_src_count='10000', \
                     mac_dst=dst, mac_dst_mode="increment", mac_dst_step="00:00:00:00:00:01",
                     mac_dst_count='10000',high_speed_result_analysis=0, enable_stream_only_gen='0')
'''

def debug_cmds_Underlay():
    global vars
    vars = st.get_testbed_vars()
    ############################################################################################
    hdrMsg(" \n######### Debugs for Underlay ##########\n")
    ############################################################################################
    utils.exec_all(True, [[Bgp.show_bgp_ipv4_summary_vtysh,vars.D1],[Bgp.show_bgp_ipv4_summary_vtysh,vars.D2]])
    utils.exec_all(True, [[ip.show_ip_route,vars.D1],[ip.show_ip_route,vars.D2]])
    utils.exec_all(True, [[ip.show_ip_route, vars.D1,"ipv6"], [ip.show_ip_route, vars.D2,"ipv6"]])
    utils.exec_all(True, [[pch.get_portchannel_list,vars.D1],[pch.get_portchannel_list,vars.D2],
                          [pch.get_portchannel_list,vars.D3],[pch.get_portchannel_list,vars.D4],
                          [pch.get_portchannel_list,vars.D5],[pch.get_portchannel_list,vars.D6]])
    ############################################################################################
    hdrMsg(" \n######### Debug END - Debugs for Underlay failure ##########\n")
    ############################################################################################


def debug_vxlan_cmds(dut1,dut2,test='TC'):
    ############################################################################################
    hdrMsg(" \n######### Debugs for vxlan failure ##########\n")
    ############################################################################################
    st.log("VxLAN Failure at - " + str(test))
    st.log("Debugs on "+ dut1)
    input = {"return_output" : "False"}
    utils.exec_all(True, [[Evpn.get_tunnel_list, dut1],[Evpn.get_tunnel_list, dut2]])
    parallel.exec_parallel(True, [dut1,dut2],Evpn.verify_vxlan_vlanvnimap,[input,input])
    parallel.exec_parallel(True, [dut1,dut2],Evpn.verify_vxlan_vrfvnimap,[input,input])
    input1={"return_output" : "False", "identifier" : evpn_dict["leaf4"]["loop_ip_list"][1]}
    input2 = {"return_output": "False", "identifier": evpn_dict["leaf3"]["loop_ip_list"][1]}
    parallel.exec_parallel(True, [dut1,dut2],Evpn.verify_vxlan_evpn_remote_vni_id,[input1,input2])
    parallel.exec_parallel(True, [dut1, dut2], Evpn.verify_vxlan_evpn_remote_mac_id,[input1, input2])
    parallel.exec_parallel(True, [dut1, dut2], Evpn.verify_bgp_l2vpn_evpn_route,[input, input])
    utils.exec_all(True, [[asicapi.read_l2, dut1], [asicapi.read_l2, dut2]])
    ############################################################################################
    hdrMsg(" \n######### Debug END - Debugs for vxlan failure ##########\n")
    ############################################################################################


def debug_traffic(dut1,dut2,test='TC'):
    global vars
    vars = st.get_testbed_vars()
    ############################################################################################
    hdrMsg(" \n######### Debugs for traffic failure ##########\n")
    ############################################################################################
    st.log("Traffic Failure at - " + str(test))
    st.log("Clearing all counters on Dut1 and Dut2\n")
    input1={"confirm" : "y"}
    parallel.exec_parallel(True, [vars.D1,vars.D2,dut1,dut2], Intf.clear_interface_counters,
                           [input1,input1,input1,input1])
    st.wait(2)
    utils.exec_all(True, [[Intf.show_interface_counters_all,dut1],[Intf.show_interface_counters_all,dut2],
                          [Intf.show_interface_counters_all,vars.D1],[Intf.show_interface_counters_all,vars.D2]])
    utils.exec_all(True, [[asicapi.read_l2,dut1],[asicapi.read_l2,dut2]])
    utils.exec_all(True, [[ip.show_ip_route,dut1],[ip.show_ip_route,dut2],[ip.show_ip_route,vars.D1],
                          [ip.show_ip_route,vars.D2]])
    utils.exec_all(True, [[asicapi.bcmcmd_l3_defip_show,dut1],[asicapi.bcmcmd_l3_defip_show,dut2]])
    utils.exec_all(True, [[asicapi.bcm_cmd_l3_intf_show,dut1],[asicapi.bcm_cmd_l3_intf_show,dut2]])
    ############################################################################################
    hdrMsg(" \n######### Debug END - Debugs for traffic failure ##########\n")
    ############################################################################################

def mac_list_from_bcmcmd_l2show(dut):
    res=asicapi.read_l2(dut)
    mac_list=[]
    for l in res:
       mac_list.append(l['mac'])
    return mac_list

def filter_mac_list(dut,pattern):
    mac_lst = mac_list_from_bcmcmd_l2show(dut)
    exp_mac_lst=[]
    for i in mac_lst:
        if pattern in i:
            exp_mac_lst.append(i)
    return exp_mac_lst

def add_l2vni_Leaf_3_4():
    hdrMsg("Add the L2vni mapping in Leaf-3 & Leaf-4")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0]]])

def l3vni_Ipv4_add():
    hdrMsg("Assign IP address to L3VNI interface on all leaf nodes")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["l3_vni_name_list"][0],
            evpn_dict["leaf1"]["l3_vni_ip_list"][0], evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["l3_vni_name_list"][0],
            evpn_dict["leaf2"]["l3_vni_ip_list"][0], evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["l3_vni_name_list"][0],
            evpn_dict["leaf3"]["l3_vni_ip_list"][0], evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["l3_vni_name_list"][0],
            evpn_dict["leaf4"]["l3_vni_ip_list"][0], evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

def l3vni_Ipv4_tenant_add():
    hdrMsg("Assign IP address to L3VNI tenant interface on all leaf nodes")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf1"]["l3_tenant_ip_list"][0], evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
            "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf2"]["l3_tenant_ip_list"][0], evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf3"]["l3_tenant_ip_list"][0], evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["l3_tenant_ip_list"][0], evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])


def l3vni_Ipv6_add():
    hdrMsg("Assign IPv6 address to L3VNI interface on all leaf nodes")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["l3_vni_name_list"][0],
            evpn_dict["leaf1"]["l3_vni_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["l3_vni_name_list"][0],
            evpn_dict["leaf2"]["l3_vni_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["l3_vni_name_list"][0],
            evpn_dict["leaf3"]["l3_vni_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            evpn_dict["leaf4"]["l3_vni_name_list"][0],
            evpn_dict["leaf4"]["l3_vni_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

def l3vni_Ipv6_tenant_add():
    hdrMsg("Assign IPv6 address to L3VNI tenant interface on all leaf nodes")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
            "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][2],
            "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][3],
            "Vlan"+evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

def cleanup_l2vni_Leaf_3_4():
    hdrMsg("Delete the L2vni mapping in Leaf-3 & Leaf-4")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                           "1", "no"],
                          [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                           "1", "no"]])


def l3vni_Ipv4_del():
    hdrMsg("Remove IP address of L3VNI interface from all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["l3_vni_name_list"][0], evpn_dict["leaf1"]["l3_vni_ip_list"][0],
                           evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["l3_vni_name_list"][0], evpn_dict["leaf2"]["l3_vni_ip_list"][0],
                           evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["l3_vni_name_list"][0], evpn_dict["leaf3"]["l3_vni_ip_list"][0],
                           evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["l3_vni_name_list"][0], evpn_dict["leaf4"]["l3_vni_ip_list"][0],
                           evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

def l3vni_Ipv4_tenant_del():
    hdrMsg("Remove IP address of L3VNI tenant interface from all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           "Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                           evpn_dict["leaf1"]["l3_tenant_ip_list"][0],
                           evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           "Vlan" + evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                           evpn_dict["leaf2"]["l3_tenant_ip_list"][0],
                           evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
                           "Vlan" + evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
                           evpn_dict["leaf3"]["l3_tenant_ip_list"][0],
                           evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
                           "Vlan" + evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                           evpn_dict["leaf4"]["l3_tenant_ip_list"][0],
                           evpn_dict["leaf4"]["l3_vni_ipmask_list"][0]]])

def l3vni_Ipv6_del():

    hdrMsg("Remove IPv6 address of L3VNI interface from all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["l3_vni_name_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6_list"][0],
                           evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0], "ipv6"],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["l3_vni_name_list"][0], evpn_dict["leaf2"]["l3_vni_ipv6_list"][0],
                           evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0], "ipv6"],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["l3_vni_name_list"][0], evpn_dict["leaf3"]["l3_vni_ipv6_list"][0],
                           evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0], "ipv6"],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["l3_vni_name_list"][0], evpn_dict["leaf4"]["l3_vni_ipv6_list"][0],
                           evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0], "ipv6"]])

def l3vni_Ipv6_tenant_del():
    hdrMsg("Remove IPv6 address of L3VNI tenant interface from all leaf nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           "Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                           evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0],
                           evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0], "ipv6"],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           "Vlan" + evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                           evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0],
                           evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0], "ipv6"],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
                           "Vlan" + evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
                           evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0],
                           evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0], "ipv6"],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][3],
                           "Vlan" + evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                           evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0],
                           evpn_dict["leaf4"]["l3_vni_ipv6mask_list"][0], "ipv6"]])

def get_num_of_bfd_sessions_up(dut):
    res = Bfd.get_bfd_peers_brief(dut)
    sessions_up = []

    for l1 in res:
        if 'up' in l1['status'] or 'UP' in l1['status']:
            sessions_up.append(l1['peeraddress'])
    st.log('Sessions UP: '+str(sessions_up))
    return len(sessions_up)

def check_ecmp(intf_list):

    #make_global_vars()
    #intf_list = data.leaf3_po_list+[vars.D5D1P1, vars.D5D2P1]
    intf_list1 = intf_list
    counter = 0
    Intf.clear_interface_counters(vars.D5, confirm="y")
    st.wait(3)
    for intf in intf_list1:
        DUT_tx_value = Evpn.get_port_counters(vars.D5, intf,"tx_bps")
        if " KB/s" in DUT_tx_value[0]['tx_bps']:
            st.log("PASS:Traffic is flowing through interface {}".format(intf))
            counter+=1
        else:
            st.log("Traffic is not flowing through interface {}".format(intf))

    st.log("Traffic is flowing through " + str(counter) + " paths")
    return counter

def delete_host():
    for key,val in han_dict.items():
        st.log('Deleting Hosts for ports '+ str(key) + ', ' + str(val))
        tg.tg_interface_config(port_handle=key, handle=val, mode='destroy')
        han_dict.pop(key)

def incrementMac(mac, step):
    step = step.replace(':', '').replace(".", '')
    mac = mac.replace(':', '').replace(".", '')
    nextMac = int(mac, 16) + int(step, 16)
    return ':'.join(("%012X" % nextMac)[i:i + 2] for i in range(0, 12, 2))


def verify_mac_count(dut,mac_count,match_type="greater"):
    count = Mac.get_mac_count(dut)
    if match_type == "greater":
        if int(count) >= int(mac_count):
            return True
        else:
            return False
    elif match_type == "lesser":
        if int(count) <= int(mac_count):
            return True
        else:
            return False
    elif match_type == "equal":
        if int(count) == int(mac_count):
            return True
        else:
            return False
    else:
        st.log("specify valid value for argument \"match_type:\"")
    return False
