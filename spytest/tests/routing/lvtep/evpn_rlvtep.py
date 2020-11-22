import apis.routing.evpn as Evpn
import apis.switching.vlan as Vlan
import apis.switching.portchannel as pch
import apis.system.interface as Intf
import apis.routing.bgp as Bgp
import apis.routing.ospf as ospf
import apis.routing.ip as ip
import apis.routing.vrf as vrf
from spytest import st, utils
from utilities import parallel
from spytest.tgen.tg import *
from spytest.tgen.tgen_utils import *
import apis.system.port as port
import apis.switching.pvst as pvst
import apis.common.asic_bcm as asicapi
import apis.switching.mclag as mclag
import apis.routing.sag as sag
import apis.switching.mac as Mac
from apis.routing import arp
from apis.system import basic
import re
from spytest.utils import filter_and_select


evpn_dict = {"leaf1" : {"intf_ip_list" : ["13.13.1.1", "13.13.2.1", "13.13.3.1", "13.13.4.1",
                                          "23.23.1.1", "23.23.2.1", "23.23.3.1","23.23.4.1"],
                        "loop_ip_list" : ["3.3.3.1", "3.3.3.2","34.34.34.1"], "local_as" : "300",
                        "iccpd_ip_list" : ["3.4.1.0","3.4.1.1"],"ospf_nw" : "3.3.3.0/24",
                        "tenant_l2_vlan_list" : ["100","101","102"], "vlan_list" : ["13","23"],
                        "rem_as_list" : ["100","200"], "ve_intf_list" : ["Vlan13","Vlan23"],
                        "pch_intf_list" : ["PortChannel13","PortChannel23"],
                        "iccpd_pch_intf_list" : ["PortChannel34"],
                        "mlag_pch_intf_list" : ["PortChannel10"],
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
                        "tenant_mac_v6": "00.06.33.00.00.01","tenant_v4_ip": "30.1.1.2", "tenant_v6_ip": "3001::2",
                        "tenant_mac_l2_colon" : "00:02:33:00:00:0A"},
             "leaf2" : {"intf_ip_list" : ["14.14.1.1", "14.14.2.1", "14.14.3.1", "14.14.4.1",
                                          "24.24.1.1", "24.24.2.1", "24.24.3.1","24.24.4.1"],
                        "loop_ip_list" : ["4.4.4.1", "4.4.4.2","34.34.34.1"], "local_as" : "400",
                        "iccpd_ip_list" : ["3.4.1.1","3.4.1.0"], "ospf_nw" : "4.4.4.0/24",
                        "tenant_l2_vlan_list" : ["100","101","102"], "vlan_list" : ["14","24"],
                        "rem_as_list" : ["100","200"], "ve_intf_list" : ["Vlan14","Vlan24"],
                        "pch_intf_list" : ["PortChannel14","PortChannel24"],
                        "iccpd_pch_intf_list" : ["PortChannel34"],
                        "mlag_pch_intf_list" : ["PortChannel10"],
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
                        "l3_vni_list": ["500", "501", "502"], "ospf_nw" : "5.5.5.0/24",
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
                        "tenant_mac_l2": "00.02.55.00.00.01", "tenant_mac_v4" : "00.04.55.00.00.01",
                        "tenant_mac_v6" : "00.06.55.00.00.01", "tenant_v4_ip": "50.1.1.2",
                        "tenant_v6_ip": "5001::2","tenant_mac_l2_colon": "00:02:55:00:00:0a"},
             "leaf4" : {"intf_ip_list" : ["16.16.1.1", "16.16.2.1", "16.16.3.1", "16.16.4.1",
                                          "26.26.1.1", "26.26.2.1", "26.26.3.1","26.26.4.1"],
                        "loop_ip_list" : ["6.6.6.1", "6.6.6.2"], "local_as" : "600",
                        "tenant_l2_vlan_list" : ["100","101","102"], "vlan_list" : ["16","26"],
                        "rem_as_list" : ["100","200"], "ve_intf_list" : ["Vlan16","Vlan26"],
                        "pch_intf_list" : ["PortChannel16","PortChannel26"],
                        "l3_vni_list": ["500", "501", "502"], "ospf_nw" : "6.6.6.0/24",
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
                        "tenant_mac_l2": "00.02.66.00.00.01", "tenant_mac_v4" : "00.04.66.00.00.01",
                        "tenant_mac_v6" : "00.06.66.00.00.01", "tenant_v4_ip": "60.1.1.2",
                        "tenant_v6_ip": "6001::2","tenant_mac_l2_colon":"00:02:66:00:00:0a"
                        },
             "mlag_node": {"tenant_mac_l2": "00.02.77.00.00.01", "tenant_mac_v4" : "00.04.77.00.00.01",
                        "tenant_mac_v6" : "00.06.77.00.00.01", "nonsag_tenant_v4_ip": "70.1.1.2",
                        "nonsag_tenant_v6_ip": "7001::2", "sag_tenant_v4_ip": "120.1.1.2",
                        "sag_tenant_v6_ip": "1201::2"
                        },
             "l3_vni_sag": {"l3_vni_sagip_list": ["120.1.1.1", "120.1.2.1"],
                        "l3_vni_sagip_net": ["120.1.1.0/24", "120.1.2.0/24"],
                        "l3_vni_sagvlan_list": ["450", "451"],
                        "l3_vni_sagvlanname_list": ["Vlan450", "Vlan451"],
                        "l3_vni_sagip_mac": ["00:00:00:04:01:03", "00:00:00:04:02:03"],
                        "l3_vni_sagipv6_list": ["1201::1", "1202::1"],
                        "l3_vni_sagipv6_net": ["1201::/96", "1202::/96"],
                        "l3_vni_sagipv6_mac": ["00:00:00:06:01:03", "00:00:00:06:02:03"],
                        },
             "spine1": {"intf_ip_list": ["13.13.1.0", "13.13.2.0", "13.13.3.0", "13.13.4.0",
                                         "14.14.1.0", "14.14.2.0", "14.14.3.0", "14.14.4.0",
                                         "15.15.1.0", "15.15.2.0", "15.15.3.0", "15.15.4.0",
                                         "16.16.1.0", "16.16.2.0", "16.16.3.0", "16.16.4.0"], "local_as" : "100",
                        "loop_ip_list" : ["1.1.1.1", "1.1.1.2"], "vlan_list" : ["13","14","15","16"],
                        "rem_as_list" : ["300","400","500","600"], "ospf_nw" : "1.1.1.0/24",
                        "ve_intf_list" : ["Vlan13","Vlan14","Vlan15","Vlan16"],
                        "pch_intf_list" : ["PortChannel13","PortChannel14","PortChannel15","PortChannel16"]},
             "spine2" : {"intf_ip_list" : ["23.23.1.0", "23.23.2.0", "23.23.3.0","23.23.4.0",
                                           "24.24.1.0", "24.24.2.0", "24.24.3.0","24.24.4.0",
                                           "25.25.1.0", "25.25.2.0", "25.25.3.0","25.25.4.0",
                                           "26.26.1.0", "26.26.2.0", "26.26.3.0","26.26.4.0"], "local_as" : "200",
                        "loop_ip_list" : ["2.2.2.1", "2.2.2.2"], "vlan_list" : ["23","24","25","26"],
                        "rem_as_list" : ["300","400","500","600"], "ospf_nw" : "2.2.2.0/24",
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

vrf_bind17 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}
vrf_bind18 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}

vrf_vni1 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
            "vni":evpn_dict["leaf1"]["l3_vni_list"][0]}
vrf_vni2 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
            "vni":evpn_dict["leaf1"]["l3_vni_list"][0],"config":"no"}

keep_alive = "3";hold_down="9"
bgp_input1 = {"router_id": evpn_dict['spine1']['loop_ip_list'][0], "local_as": evpn_dict['spine1']['local_as'],
              "neighbor": evpn_dict["leaf1"]["loop_ip_list"][0], "ebgp_mhop": '2',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "remote_as": evpn_dict['spine1']['rem_as_list'][0],"connect":'1',
              "update_src": evpn_dict['spine1']['loop_ip_list'][0]}

bgp_input2 = {"router_id": evpn_dict['spine2']['loop_ip_list'][0], "local_as": evpn_dict['spine2']['local_as'],
              "neighbor": evpn_dict["leaf1"]["loop_ip_list"][0], "ebgp_mhop": '2',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "remote_as": evpn_dict['spine2']['rem_as_list'][0],"connect":'1',
              "update_src": evpn_dict['spine2']['loop_ip_list'][0]}

bgp_input3 = {"router_id": evpn_dict['leaf1']['loop_ip_list'][0], "local_as": evpn_dict['leaf1']['local_as'],
              "neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "ebgp_mhop": '2',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "remote_as": evpn_dict['leaf1']['rem_as_list'][0],"connect":'1',
              "update_src": evpn_dict['leaf1']['loop_ip_list'][0]}

bgp_input4 = {"router_id": evpn_dict['leaf2']['loop_ip_list'][0], "local_as": evpn_dict['leaf2']['local_as'],
              "neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "ebgp_mhop": '2',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "remote_as": evpn_dict['leaf2']['rem_as_list'][0],"connect":'1',
              "update_src": evpn_dict['leaf2']['loop_ip_list'][0]}

bgp_input5 = {"router_id": evpn_dict['leaf3']['loop_ip_list'][0], "local_as": evpn_dict['leaf3']['local_as'],
              "neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "ebgp_mhop": '2',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "remote_as": evpn_dict['leaf3']['rem_as_list'][0],"connect":'1',
              "update_src": evpn_dict['leaf3']['loop_ip_list'][0]}

bgp_input6 = {"router_id": evpn_dict['leaf4']['loop_ip_list'][0], "local_as": evpn_dict['leaf4']['local_as'],
              "neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "ebgp_mhop": '2',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "remote_as": evpn_dict['leaf4']['rem_as_list'][0],"connect":'1',
              "update_src": evpn_dict['leaf4']['loop_ip_list'][0]}

bgp_input7 = {"neighbor": evpn_dict["leaf2"]["loop_ip_list"][0], "ebgp_mhop": '2',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "update_src": evpn_dict['spine1']['loop_ip_list'][0],"connect":'1',
              "remote_as": evpn_dict['spine1']['rem_as_list'][1],"local_as": evpn_dict['spine1']['local_as']}

bgp_input8 = {"neighbor": evpn_dict["leaf2"]["loop_ip_list"][0], "ebgp_mhop": '2',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "update_src": evpn_dict['spine2']['loop_ip_list'][0],"connect":'1',
              "remote_as": evpn_dict['spine2']['rem_as_list'][1],"local_as": evpn_dict['spine2']['local_as']}

bgp_input9 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "ebgp_mhop": '2',
              "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
              "update_src": evpn_dict['leaf1']['loop_ip_list'][0],"connect":'1',
              "remote_as": evpn_dict['leaf1']['rem_as_list'][1],"local_as": evpn_dict['leaf1']['local_as']}

bgp_input10 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "ebgp_mhop": '2',
               "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
               "update_src": evpn_dict['leaf2']['loop_ip_list'][0],"connect":'1',
               "remote_as": evpn_dict['leaf2']['rem_as_list'][1],"local_as": evpn_dict['leaf2']['local_as']}

bgp_input11 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "ebgp_mhop": '2',
               "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
               "update_src": evpn_dict['leaf3']['loop_ip_list'][0],"connect":'1',
               "remote_as": evpn_dict['leaf3']['rem_as_list'][1],"local_as": evpn_dict['leaf3']['local_as']}

bgp_input12 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "ebgp_mhop": '2',
               "config_type_list": ["neighbor", "ebgp_mhop","update_src","connect"],
               "update_src": evpn_dict['leaf4']['loop_ip_list'][0],"connect":'1',
               "remote_as": evpn_dict['leaf4']['rem_as_list'][1],"local_as": evpn_dict['leaf4']['local_as']}

bgp_input13 = {"neighbor": evpn_dict["leaf3"]["loop_ip_list"][0], "ebgp_mhop": '2',
               "config_type_list": ["neighbor", "ebgp_mhop","update_src"],
               "update_src": evpn_dict['spine1']['loop_ip_list'][0],
               "remote_as": evpn_dict['spine1']['rem_as_list'][2],"local_as": evpn_dict['spine1']['local_as']}

bgp_input14 = {"neighbor": evpn_dict["leaf3"]["loop_ip_list"][0], "ebgp_mhop": '2',
               "config_type_list": ["neighbor", "ebgp_mhop","update_src"],
               "update_src": evpn_dict['spine2']['loop_ip_list'][0],
               "remote_as": evpn_dict['spine2']['rem_as_list'][2],"local_as": evpn_dict['spine2']['local_as']}

bgp_input15 = {"neighbor": evpn_dict["leaf4"]["loop_ip_list"][0], "ebgp_mhop": '2',
               "config_type_list": ["neighbor", "ebgp_mhop","update_src"],
               "update_src": evpn_dict['spine1']['loop_ip_list'][0],
               "remote_as": evpn_dict['spine1']['rem_as_list'][3],"local_as": evpn_dict['spine1']['local_as']}

bgp_input16 = {"neighbor": evpn_dict["leaf4"]["loop_ip_list"][0], "ebgp_mhop": '2',
               "config_type_list": ["neighbor", "ebgp_mhop","update_src"],
               "update_src": evpn_dict['spine2']['loop_ip_list'][0],
               "remote_as": evpn_dict['spine2']['rem_as_list'][3],"local_as": evpn_dict['spine2']['local_as']}

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
               "network":evpn_dict["leaf1"]["loop_ip_list"][2]+'/32',"config" : "yes"}
bgp_input32 = {"config_type_list" :["network"],"local_as": evpn_dict['leaf2']['local_as'],
               "network":evpn_dict["leaf2"]["loop_ip_list"][2]+'/32',"config" : "yes"}
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

evpn_input1 = {"neighbor": evpn_dict["leaf1"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['leaf1']['local_as'],
               "local_as":evpn_dict['spine1']['local_as'],"config_type_list": ["activate", "advertise_all_vni"]}

evpn_input1_1 = {"neighbor": evpn_dict["leaf1"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['leaf1']['local_as'],
               "config_type_list": ["activate", "advertise_all_vni"],"local_as": evpn_dict['spine2']['local_as']}

evpn_input2 = {"neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['spine1']['local_as'],
               "local_as":evpn_dict['leaf1']['local_as'],"config_type_list": ["activate", "advertise_all_vni"]}

evpn_input2_1 = {"neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['spine1']['local_as'],
               "config_type_list": ["activate", "advertise_all_vni"],"local_as": evpn_dict['leaf2']['local_as']}

evpn_input2_2 = {"neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['spine1']['local_as'],
               "config_type_list": ["activate", "advertise_all_vni"],"local_as": evpn_dict['leaf3']['local_as']}

evpn_input2_3 = {"neighbor": evpn_dict["spine1"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['spine1']['local_as'],
               "config_type_list": ["activate", "advertise_all_vni"],"local_as": evpn_dict['leaf4']['local_as']}

evpn_input3 = {"neighbor": evpn_dict["leaf2"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['leaf2']['local_as'],
               "local_as": evpn_dict['spine1']['local_as'],"config_type_list": ["activate"]}

evpn_input3_1 = {"neighbor": evpn_dict["leaf2"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['leaf2']['local_as'],
               "config_type_list": ["activate"],"local_as": evpn_dict['spine2']['local_as']}

evpn_input4 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['spine2']['local_as'],
               "local_as":evpn_dict['leaf1']['local_as'],"config_type_list": ["activate"]}

evpn_input4_1 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['spine2']['local_as'],
               "config_type_list": ["activate"],"local_as": evpn_dict['leaf2']['local_as']}

evpn_input4_2 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['spine2']['local_as'],
               "config_type_list": ["activate"],"local_as": evpn_dict['leaf3']['local_as']}

evpn_input4_3 = {"neighbor": evpn_dict["spine2"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['spine2']['local_as'],
               "config_type_list": ["activate"],"local_as": evpn_dict['leaf4']['local_as']}

evpn_input5 = {"neighbor": evpn_dict["leaf3"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['leaf3']['local_as'],
               "local_as": evpn_dict['spine1']['local_as'],"config_type_list": ["activate"]}

evpn_input5_1 = {"neighbor": evpn_dict["leaf3"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['leaf3']['local_as'],
               "config_type_list": ["activate"],"local_as": evpn_dict['spine2']['local_as']}

evpn_input6 = {"neighbor": evpn_dict["leaf4"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['leaf4']['local_as'],
               "local_as": evpn_dict['spine1']['local_as'],"config_type_list": ["activate"]}

evpn_input6_1 = {"neighbor": evpn_dict["leaf4"]["loop_ip_list"][0], "config": "yes","remote_as":evpn_dict['leaf4']['local_as'],
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

    global vars, tg, d3_tg_ph1, d3_tg_ph2, d4_tg_ph1, d4_tg_ph2, d5_tg_ph1, d5_tg_ph2, d6_tg_ph1, d6_tg_ph2, d7_tg_ph1, d7_tg_ph2
    global d4_tg_port1, d5_tg_port1,d6_tg_port1, d7_tg_port1
    vars = st.ensure_min_topology("D1D3:4","D1D4:4","D1D5:2","D1D6:4",
                                  "D2D3:4","D2D4:4","D2D5:4","D2D6:4",
                                  "D3T1:2","D4T1:2","D5T1:2","D6T1:2","D3D4:3","D3D7:1","D4D7:1","D7T1:2",
                                  "D3CHIP:TD3", "D4CHIP:TD3", "D5CHIP:TD3", "D6CHIP:TD3")

    tg = tgen_obj_dict[vars['tgen_list'][0]]
    d3_tg_ph1, d3_tg_ph2 = tg.get_port_handle(vars.T1D3P1), tg.get_port_handle(vars.T1D3P2)
    d4_tg_ph1, d4_tg_ph2 = tg.get_port_handle(vars.T1D4P1), tg.get_port_handle(vars.T1D4P2)
    d5_tg_ph1, d5_tg_ph2 = tg.get_port_handle(vars.T1D5P1), tg.get_port_handle(vars.T1D5P2)
    d6_tg_ph1, d6_tg_ph2 = tg.get_port_handle(vars.T1D6P1), tg.get_port_handle(vars.T1D6P2)
    d7_tg_ph1, d7_tg_ph2 = tg.get_port_handle(vars.T1D7P1), tg.get_port_handle(vars.T1D7P2)
    d4_tg_port1,d5_tg_port1,d6_tg_port1 = vars.T1D4P1, vars.T1D5P1, vars.T1D6P1
    d7_tg_port1,d7_tg_port2 = vars.T1D7P1,vars.T1D7P2

    tg_dict['tg'] = tgen_obj_dict[vars['tgen_list'][0]]
    tg_dict['d3_tg_ph1'],tg_dict['d3_tg_ph2'] = tg.get_port_handle(vars.T1D3P1),tg.get_port_handle(vars.T1D3P2)
    tg_dict['d4_tg_ph1'],tg_dict['d4_tg_ph2'] = tg.get_port_handle(vars.T1D4P1),tg.get_port_handle(vars.T1D4P2)
    tg_dict['d5_tg_ph1'],tg_dict['d5_tg_ph2'] = tg.get_port_handle(vars.T1D5P1),tg.get_port_handle(vars.T1D5P2)
    tg_dict['d6_tg_ph1'],tg_dict['d6_tg_ph2'] = tg.get_port_handle(vars.T1D6P1),tg.get_port_handle(vars.T1D6P2)
    tg_dict['d7_tg_ph1'],tg_dict['d7_tg_ph2'] = tg.get_port_handle(vars.T1D7P1),tg.get_port_handle(vars.T1D7P2)
    tg_dict['d5_tg_port1'],tg_dict['d6_tg_port1'] = vars.T1D5P1, vars.T1D6P1
    tg_dict['d3_tg_port1'],tg_dict['d4_tg_port1'] = vars.T1D3P1, vars.T1D4P1
    tg_dict['d7_tg_port1'],tg_dict['d7_tg_port2'] = vars.T1D7P1, vars.T1D7P2
    tg_dict['tgen_rate_pps'] = '1000'
    tg_dict['frame_size'] = '1000'
    tg_dict['dut_6_mac_pattern'] = '00:02:66:00:00:'
    tg_dict['d5_tg_local_as'] = '50'
    tg_dict['d6_tg_local_as'] = '60'
    tg_dict['num_routes_1'] = '100'
    tg_dict['prefix_1'] = '100.1.1.0'
    tg_dict['prefix_2'] = '200.1.1.0'
    tg_dict['mlag_domain_id'] = '2'

    evpn_dict["leaf_node_list"] = [vars.D3, vars.D4, vars.D5, vars.D6]
    evpn_dict["mlag_node_list"] = [vars.D3, vars.D4]
    evpn_dict["spine_node_list"] = [vars.D1, vars.D2]
    evpn_dict["mlag_client"] = [vars.D7]
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

    evpn_dict["leaf1"]["iccpd_ncintf_list"] = [vars.D3D4P3]
    evpn_dict["leaf2"]["iccpd_ncintf_list"] = [vars.D4D3P3]
    evpn_dict["leaf1"]["iccpd_cintf_list"] = ["Loopback4"]
    evpn_dict["leaf2"]["iccpd_cintf_list"] = ["Loopback4"]
    evpn_dict["leaf1"]["iccpd_dintf_list"] = [vars.D3D4P1,vars.D3D4P2]
    evpn_dict["leaf2"]["iccpd_dintf_list"] = [vars.D4D3P1,vars.D4D3P2]
    evpn_dict["leaf1"]["mlag_intf_list"] = [vars.D3D7P1]
    evpn_dict["leaf2"]["mlag_intf_list"] = [vars.D4D7P1]
    evpn_dict["mlag_intf_list"] = [vars.D7D3P1,vars.D7D4P1]
    evpn_dict["mlag_tg_list"] = [vars.D7T1P1, vars.D7T1P2]

    evpn_dict["spine1"]["intf_list_leaf"] = [vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4,
                                             vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4,
                                             vars.D1D5P1, vars.D1D5P2, vars.D1D5P3, vars.D1D5P4,
                                             vars.D1D6P1, vars.D1D6P2, vars.D1D6P3, vars.D1D6P4]
    evpn_dict["spine2"]["intf_list_leaf"] = [vars.D2D3P1, vars.D2D3P2, vars.D2D3P3, vars.D2D3P4,
                                             vars.D2D4P1, vars.D2D4P2, vars.D2D4P3, vars.D2D4P4,
                                             vars.D2D5P1, vars.D2D5P2, vars.D2D5P3, vars.D2D5P4,
                                             vars.D2D6P1, vars.D2D6P2, vars.D2D6P3, vars.D2D6P4]
    evpn_dict["leaf_base_mac_list"] = pvst.get_duts_mac_address(evpn_dict["leaf_node_list"])
    evpn_dict["dut6_gw_mac"] = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']

    for key in evpn_dict["leaf_base_mac_list"]:
        evpn_dict["leaf_base_mac_list"][key]=convert_base_mac(evpn_dict["leaf_base_mac_list"][key])

    evpn_dict["ipv4_static_route"] = "123.1.1.0/24"
    evpn_dict["ipv6_static_route"] = "1230::/96"

    evpn_dict["l2_traffic_loss_orphon"]=0
    evpn_dict["l2_traffic_loss_orphon_reboot"]=0
    evpn_dict["l2_traffic_loss_ccep"]=0
    evpn_dict["bum_traffic_loss_ccep"]=0
    evpn_dict["l2_traffic_loss_orphon_fastreboot"]=0
    evpn_dict["l3_traffic_loss_ccep1"]=0
    evpn_dict["l3_traffic_loss_ccep2"]=0
    evpn_dict["l3_traffic_loss_ccep3"]=0
    evpn_dict["l3_traffic_loss_ccep"]=0
    evpn_dict["del_res_timer"] = "120"
    evpn_dict["l3_del_res_timer"] = "130"
    evpn_dict["orphanpo_del_res_timer"] = "135"
    evpn_dict["l3_traffic_loss_ccep11"]=0
    evpn_dict["l3_traffic_loss_ccep12"]=0
    evpn_dict["l3_traffic_loss_ccep13"]=0
    evpn_dict["l3_traffic_loss_ccep_reload"]=0
    if os.getenv("SPYTEST_FORCE_CLICK_UI"):
        evpn_dict["cli_mode"]="click"
        evpn_dict["traffic_duration"]=240
    elif st.get_ui_type() == "klish":
        evpn_dict["cli_mode"]="klish"
        evpn_dict["traffic_duration"]=410
    elif st.get_ui_type() == "click":
        evpn_dict["cli_mode"]="click"
        evpn_dict["traffic_duration"]=240
    elif st.get_ui_type() in ["rest-put","rest-patch"]:
        evpn_dict["cli_mode"] = "klish"
        evpn_dict["traffic_duration"]=410


def setup_underlay():
    st.log("create port channel interface b/w leaf and spine nodes")
    utils.exec_all(True, [[pch.create_portchannel, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["spine_node_list"][0], evpn_dict["spine1"]["pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["spine_node_list"][1], evpn_dict["spine2"]["pch_intf_list"]]])

    st.log("create port channel interface b/w leaf 1 and leaf 2 for iccpd data ports")
    utils.exec_all(True, [[pch.create_portchannel, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["iccpd_pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["iccpd_pch_intf_list"]]])

    st.log("create port channel for MLAG client interface b/w leaf 1 and client switch")
    utils.exec_all(True, [[pch.create_portchannel, evpn_dict["mlag_node_list"][0], evpn_dict["leaf1"]["mlag_pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["mlag_client"][0], evpn_dict["leaf1"]["mlag_pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["mlag_node_list"][1], evpn_dict["leaf2"]["mlag_pch_intf_list"]]])

    st.log("adding mc lag member ports in leaf 1 and leaf 2")
    utils.exec_all(True, [[pch.add_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], evpn_dict["leaf1"]["iccpd_dintf_list"][0:2]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], evpn_dict["leaf2"]["iccpd_dintf_list"][0:2]]])

    st.log("adding mc lag client ports in leaf 1 and leaf 2 and also in MCLAG client switch")
    utils.exec_all(True, [[pch.add_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], evpn_dict["leaf1"]["mlag_intf_list"][0]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], evpn_dict["leaf2"]["mlag_intf_list"][0]],
                          [pch.add_portchannel_member, evpn_dict["mlag_client"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], evpn_dict["mlag_intf_list"][0:2]]])

    st.log("Add members to port channel created b/w leaf and spine nodes")
    utils.exec_all(True, [[pch.add_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][0], evpn_dict["leaf1"]["intf_list_spine"][:3]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][0], evpn_dict["leaf2"]["intf_list_spine"][:3]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][0], evpn_dict["leaf3"]["intf_list_spine"][:3]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["pch_intf_list"][0], evpn_dict["leaf4"]["intf_list_spine"][:3]],
                          [pch.add_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][0], evpn_dict["spine1"]["intf_list_leaf"][:3]],
                          [pch.add_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][0], evpn_dict["spine2"]["intf_list_leaf"][:3]]])
    utils.exec_all(True, [[pch.add_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][1], evpn_dict["leaf1"]["intf_list_spine"][4:7]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][1], evpn_dict["leaf2"]["intf_list_spine"][4:7]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][1], evpn_dict["leaf3"]["intf_list_spine"][4:7]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["pch_intf_list"][1], evpn_dict["leaf4"]["intf_list_spine"][4:7]],
                          [pch.add_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][1], evpn_dict["spine1"]["intf_list_leaf"][4:7]],
                          [pch.add_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][1], evpn_dict["spine2"]["intf_list_leaf"][4:7]]])
    utils.exec_all(True, [[pch.add_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][2], evpn_dict["spine1"]["intf_list_leaf"][8:11]],
                          [pch.add_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][2], evpn_dict["spine2"]["intf_list_leaf"][8:11]]])
    utils.exec_all(True, [[pch.add_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][3], evpn_dict["spine1"]["intf_list_leaf"][12:15]],
                          [pch.add_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][3], evpn_dict["spine2"]["intf_list_leaf"][12:15]]])

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
    input = {"loopback_name" : "Loopback3"}
    parallel.exec_parallel(True, evpn_dict["mlag_node_list"],
                           ip.configure_loopback, [input,input])
    input = {"loopback_name" : "Loopback4"}
    parallel.exec_parallel(True, evpn_dict["mlag_node_list"],
                           ip.configure_loopback, [input,input])

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

    st.log("Configure IP address on Loopback 3 to be used for LVTEP source address")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                           "Loopback3", evpn_dict["leaf1"]["loop_ip_list"][2], '32'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                           "Loopback3", evpn_dict["leaf2"]["loop_ip_list"][2], '32']])

    st.log("Configure IP address b/w Leaf 1 and Leaf 2 to establish ICCPD control path")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["iccpd_cintf_list"][0], evpn_dict["leaf1"]["iccpd_ip_list"][0],'32'],
                        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["iccpd_cintf_list"][0], evpn_dict["leaf2"]["iccpd_ip_list"][0],'32']])

    st.log("configure BGP neighbors")
    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Bgp.config_bgp,
                           [bgp_input1,bgp_input2,bgp_input3,bgp_input4,bgp_input5,bgp_input6])
    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Bgp.config_bgp,
                           [bgp_input7,bgp_input8,bgp_input9,bgp_input10,bgp_input11,bgp_input12])
    parallel.exec_parallel(True, evpn_dict["spine_node_list"], Bgp.config_bgp,[bgp_input13,bgp_input14])
    parallel.exec_parallel(True, evpn_dict["spine_node_list"], Bgp.config_bgp,[bgp_input15,bgp_input16])

    utils.exec_all(True, [[Bgp.config_bgp_router,evpn_dict["bgp_node_list"][0],"100", '',keep_alive,hold_down,'yes'],
                          [Bgp.config_bgp_router,evpn_dict["bgp_node_list"][1],"200", '',keep_alive,hold_down,'yes'],
                          [Bgp.config_bgp_router,evpn_dict["bgp_node_list"][2],"300", '',keep_alive,hold_down,'yes'],
                          [Bgp.config_bgp_router,evpn_dict["bgp_node_list"][3],"400", '',keep_alive,hold_down,'yes'],
                          [Bgp.config_bgp_router,evpn_dict["bgp_node_list"][4],"500", '',keep_alive,hold_down,'yes'],
                          [Bgp.config_bgp_router,evpn_dict["bgp_node_list"][5],"600", '',keep_alive,hold_down,'yes']])

    st.log("configure network import check in all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], Bgp.config_bgp,[bgp_input39,bgp_input40,
                           bgp_input41,bgp_input42])

    st.log("configure BGP EVPN neighbors")
    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Evpn.config_bgp_evpn,
                           [evpn_input1, evpn_input1_1, evpn_input2, evpn_input2_1, evpn_input2_2, evpn_input2_3])
    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Evpn.config_bgp_evpn,
                           [evpn_input3, evpn_input3_1, evpn_input4, evpn_input4_1, evpn_input4_2, evpn_input4_3])
    parallel.exec_parallel(True, evpn_dict["spine_node_list"], Evpn.config_bgp_evpn, [evpn_input5, evpn_input5_1])
    parallel.exec_parallel(True, evpn_dict["spine_node_list"], Evpn.config_bgp_evpn, [evpn_input6, evpn_input6_1])


def setup_ospf_unnumbered():
    st.log("########## Add portchannel interface to Unnumbered on all spine and leaf nodes ##########")
    for i in range(2):
        spine1_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["spine1"]["pch_intf_list"][i],
                                 'loop_back': 'Loopback1'}
        spine2_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["spine2"]["pch_intf_list"][i],
                                 'loop_back': 'Loopback1'}
        leaf1_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["leaf1"]["pch_intf_list"][i],
                        'loop_back': 'Loopback1'}
        leaf2_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["leaf2"]["pch_intf_list"][i],
                       'loop_back': 'Loopback1'}
        leaf3_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["leaf3"]["pch_intf_list"][i],
                       'loop_back': 'Loopback1'}
        leaf4_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["leaf4"]["pch_intf_list"][i],
                       'loop_back': 'Loopback1'}
        parallel.exec_parallel(True, evpn_dict["spine_node_list"] + evpn_dict["leaf_node_list"],
                               ip.config_unnumbered_interface, [spine1_input, spine2_input,
                                                                leaf1_input, leaf2_input, leaf3_input, leaf4_input])

    for i in range(2,4):
        spine1_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["spine1"]["pch_intf_list"][i],
                            'loop_back': 'Loopback1'}
        spine2_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["spine2"]["pch_intf_list"][i],
                            'loop_back': 'Loopback1'}
        parallel.exec_parallel(True, evpn_dict["spine_node_list"],
                               ip.config_unnumbered_interface, [spine1_input, spine2_input])

    st.log("########## Add router port to unnumbered in all spine and leaf nodes ##########")
    for i in range(3, 8, 4):
        spine1_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["spine1"]["intf_list_leaf"][i],
                        'loop_back': 'Loopback1'}
        spine2_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["spine2"]["intf_list_leaf"][i],
                        'loop_back': 'Loopback1'}
        leaf1_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["leaf1"]["intf_list_spine"][i],
                       'loop_back': 'Loopback1'}
        leaf2_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["leaf2"]["intf_list_spine"][i],
                       'loop_back': 'Loopback1'}
        leaf3_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["leaf3"]["intf_list_spine"][i],
                       'loop_back': 'Loopback1'}
        leaf4_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["leaf4"]["intf_list_spine"][i],
                       'loop_back': 'Loopback1'}
        parallel.exec_parallel(True, evpn_dict["spine_node_list"] + evpn_dict["leaf_node_list"],
                               ip.config_unnumbered_interface, [spine1_input, spine2_input,
                                                                leaf1_input, leaf2_input, leaf3_input, leaf4_input])

    for i in range(11, 16,4):
        spine1_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["spine1"]["intf_list_leaf"][i],
                        'loop_back': 'Loopback1'}
        spine2_input = {'family': 'ipv4', 'action': 'add', 'interface': evpn_dict["spine2"]["intf_list_leaf"][i],
                        'loop_back': 'Loopback1'}
        parallel.exec_parallel(True, evpn_dict["spine_node_list"],ip.config_unnumbered_interface,
                               [spine1_input, spine2_input])

    st.log("########## configure ospf in all spine and leaf nodes ##########")
    utils.exec_all(True, [[ospf.config_ospf_router_id, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["loop_ip_list"][0], 'default', '', 'yes'],
                          [ospf.config_ospf_router_id, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["loop_ip_list"][0], 'default', '', 'yes'],
                          [ospf.config_ospf_router_id, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["loop_ip_list"][0], 'default', '', 'yes'],
                          [ospf.config_ospf_router_id, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["loop_ip_list"][0], 'default', '', 'yes'],
                          [ospf.config_ospf_router_id, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["loop_ip_list"][0], 'default', '', 'yes'],
                          [ospf.config_ospf_router_id, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["loop_ip_list"][0], 'default', '', 'yes']])

    utils.exec_all(True, [[ospf.config_ospf_network, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["ospf_nw"], 0, 'default', '','yes'],
                          [ospf.config_ospf_network, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["ospf_nw"], 0, 'default', '', 'yes'],
                          [ospf.config_ospf_network, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["ospf_nw"], 0, 'default', '', 'yes'],
                          [ospf.config_ospf_network, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["ospf_nw"], 0, 'default', '', 'yes'],
                          [ospf.config_ospf_network, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["ospf_nw"], 0, 'default', '', 'yes'],
                          [ospf.config_ospf_network, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["ospf_nw"], 0, 'default', '', 'yes']])

    for i in range(2):
        utils.exec_all(True, [[ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][i],'point-to-point', 'default', 'yes'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][i], 'point-to-point', 'default', 'yes'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][i], 'point-to-point', 'default', 'yes'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][i], 'point-to-point', 'default', 'yes'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][i], 'point-to-point', 'default', 'yes'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["pch_intf_list"][i], 'point-to-point', 'default', 'yes']])

    for i in range(2,4):
        utils.exec_all(True, [[ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][i],'point-to-point', 'default', 'yes'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][i], 'point-to-point', 'default', 'yes']])

    for i in range(3,8,4):
        utils.exec_all(True, [[ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][i],'point-to-point', 'default', 'yes'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][i], 'point-to-point', 'default', 'yes'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["intf_list_spine"][i], 'point-to-point', 'default', 'yes'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["intf_list_spine"][i], 'point-to-point', 'default', 'yes'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["intf_list_spine"][i], 'point-to-point', 'default', 'yes'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["intf_list_spine"][i], 'point-to-point', 'default', 'yes']])

    for i in range(11,16,4):
        utils.exec_all(True, [[ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][i],'point-to-point', 'default', 'yes'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][i], 'point-to-point', 'default', 'yes']])

    utils.exec_all(True, [[ospf.config_ospf_router_redistribute, evpn_dict["spine_node_list"][0], 'connected'],
                          [ospf.config_ospf_router_redistribute, evpn_dict["spine_node_list"][1], 'connected'],
                          [ospf.config_ospf_router_redistribute, evpn_dict["leaf_node_list"][0], 'connected'],
                          [ospf.config_ospf_router_redistribute, evpn_dict["leaf_node_list"][1], 'connected'],
                          [ospf.config_ospf_router_redistribute, evpn_dict["leaf_node_list"][2], 'connected'],
                          [ospf.config_ospf_router_redistribute, evpn_dict["leaf_node_list"][3], 'connected']])


def setup_vxlan():
    st.log("config vtep on all leaf nodes")
    utils.exec_all(True, [[Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf1"]["loop_ip_list"][2]],
                        [Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["vtepName"], evpn_dict["leaf2"]["loop_ip_list"][2]],
                        [Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][2],
                        evpn_dict["leaf3"]["vtepName"], evpn_dict["leaf3"]["loop_ip_list"][1]],
                        [Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][3],
                        evpn_dict["leaf4"]["vtepName"], evpn_dict["leaf4"]["loop_ip_list"][1]]])

    if evpn_dict['cli_mode'] == "click":
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

    st.log("Add L2 non SAG vlan to VNI mapping")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0]]])

    Vlan.create_vlan(evpn_dict["mlag_client"][0],evpn_dict["leaf1"]["tenant_l2_vlan_list"][0])

    st.log("config l2 tenant vlan membershp for mc-lag iccpd link for data forwarding over mc-lag")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                        evpn_dict['leaf1']['iccpd_pch_intf_list'][0],True],
                        [Vlan.add_vlan_member, evpn_dict["mlag_client"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                        evpn_dict['mlag_tg_list'][0],True],
                        [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                        evpn_dict['leaf2']['iccpd_pch_intf_list'][0],True]])

    st.log("config L2 tenant vlan membershp for mc-lag client interface in leaf 1 and leaf 2 and also in client switch")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True],
                        [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                        evpn_dict["leaf2"]["mlag_pch_intf_list"][0],True],
                        [Vlan.add_vlan_member, evpn_dict["mlag_client"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True]])

    st.log("create VLANs for sag l3 tenant interfaces")
    utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][3],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]]])

    st.log("Bind SAG configured VLANs to port on all leaf nodes")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Add SAG vlan to VNI mapping")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vtepName"], evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
            evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
            evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
            evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]]])

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

    st.log("create tenant L3 VLANs on LVTEP nodes used for similar L3 network across LVTEP peers")
    utils.exec_all(True, [[Vlan.create_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0]],
                          [Vlan.create_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0]]])

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

    dict1 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],"config":"yes",
             "intf_name":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"skip_error":"yes"}
    dict2 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],"config":"yes",
             "intf_name":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"skip_error":"yes"}
    dict3 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],"config":"yes",
             "intf_name":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"skip_error":"yes"}
    dict4 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],"config":"yes",
             "intf_name":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"skip_error":"yes"}

    st.log("Bind Vrf to L3VNI interfaces on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],
                           vrf.bind_vrf_interface,[dict1,dict2,dict3,dict4])

    st.log("Configure SAG mac on all leaf nodes")
    dict1 = {"mac":evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0], "config":"add"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],
                           sag.config_sag_mac, [dict1,dict1,dict1,dict1])

    dict1 = {"config":"enable"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],sag.config_sag_mac, [dict1,dict1,dict1,dict1])
    dict1 = {"config":"enable","ip_type":'ipv6'}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],sag.config_sag_mac, [dict1,dict1,dict1,dict1])

    Vlan.create_vlan(evpn_dict["mlag_client"][0],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0])

    st.log("config l3 tenant vlan membershp for mc-lag iccpd link for data forwarding over mc-lag")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["mlag_client"][0],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],evpn_dict["mlag_tg_list"][0],True]])


    st.log("config L3 tenant vlan membershp for mc-lag client interface in leaf 1 and leaf 2 and also in client switch")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True],
                        [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1], evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True],
                        [Vlan.add_vlan_member, evpn_dict["mlag_client"][0], evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True]])

    st.log("Assign IP anycast address to L3 SAG tenant interface on all leaf nodes")
    sag.config_sag_ip(evpn_dict["leaf_node_list"][0],interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], mask="24",config="add")

    sag.config_sag_ip(evpn_dict["leaf_node_list"][1],interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], mask="24",config="add")

    sag.config_sag_ip(evpn_dict["leaf_node_list"][2],interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], mask="24",config="add")

    sag.config_sag_ip(evpn_dict["leaf_node_list"][3],interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], mask="24",config="add")

    st.log("Assign IPv6 address to L3 SAG tenant interface on all leaf nodes")
    sag.config_sag_ip(evpn_dict["leaf_node_list"][0],interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0], mask="96",config="add")

    sag.config_sag_ip(evpn_dict["leaf_node_list"][1],interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0], mask="96",config="add")

    sag.config_sag_ip(evpn_dict["leaf_node_list"][2],interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0], mask="96",config="add")

    sag.config_sag_ip(evpn_dict["leaf_node_list"][3],interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0], mask="96",config="add")

def setup_mclag():
    st.log("Bind tenant L3 VLANs to ICCPD link on LVTEP nodes for similar L3 config across LVTEP peers")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],True]])

    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],True]])

    st.log("Bind L3 VNI VLAN to ICCPD link on LVTEP nodes to handle orphon traffic scenarios")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["l3_vni_list"][0], evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],True]])

    st.log("Bind tenant L3 VLANs to MLAG client port on LVTEP nodes to handle scale test BGP session to TGEN port")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["mlag_pch_intf_list"],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["mlag_pch_intf_list"],True]])

    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["mlag_pch_intf_list"],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["mlag_pch_intf_list"],True]])

    st.log("Bind L3 VNI VLAN to MLAG client port to handle scale test BGP session to TGEN port")
    utils.exec_all(True, [[Vlan.add_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["mlag_pch_intf_list"],True],
                          [Vlan.add_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["l3_vni_list"][0], evpn_dict["leaf2"]["mlag_pch_intf_list"],True]])

    st.log("configuring mc-lag in leaf 1 and leaf 2")
    dict1 = {'domain_id':tg_dict['mlag_domain_id'], 'local_ip':evpn_dict['leaf1']['iccpd_ip_list'][0],
            'peer_ip':evpn_dict['leaf1']['iccpd_ip_list'][1], 'peer_interface':evpn_dict['leaf1']['iccpd_pch_intf_list'][0]}
    dict2 = {'domain_id':tg_dict['mlag_domain_id'], 'local_ip':evpn_dict['leaf2']['iccpd_ip_list'][0],
            'peer_ip':evpn_dict['leaf2']['iccpd_ip_list'][1], 'peer_interface':evpn_dict['leaf2']['iccpd_pch_intf_list'][0]}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][0:2],mclag.config_domain,[dict1, dict2])

    dict1 = {'domain_id':tg_dict['mlag_domain_id'], 'interface_list':evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
            'config':'add'}
    dict2 = {'domain_id':tg_dict['mlag_domain_id'], 'interface_list':evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
            'config':'add'}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][0:2],mclag.config_interfaces,[dict1, dict2])

    vrf_bind1 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
             "intf_name":"Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],"skip_error":"yes"}
    vrf_bind2 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],
             "intf_name":"Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],"skip_error":"yes"}

    st.log("Bind Vrf to L3VNI interfaces on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2],
                           vrf.bind_vrf_interface,[vrf_bind1,vrf_bind2])

    st.log("Assign IP address to L3VNI tenant interface on LVTEP node for similar L3 network across LVTEP peers")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
            "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf2"]["l3_tenant_ip_list"][0], evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf1"]["l3_tenant_ip_list"][0], evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]]])

    st.log("Assign IPv6 address to L3VNI tenant interface on LVTEP node for similar L3 network across LVTEP peers")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
            "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    if evpn_dict['cli_mode'] == "klish":
        st.log("No shutdown the MLAG client and ICCPD Portchannel in LVTEP nodes and client switch")
        utils.exec_all(True, [[Intf.interface_operation, evpn_dict["mlag_node_list"][0], evpn_dict["leaf1"]["mlag_pch_intf_list"],"startup"],
                      [Intf.interface_operation, evpn_dict["mlag_client"][0],    evpn_dict["leaf1"]["mlag_pch_intf_list"],"startup"],
                      [Intf.interface_operation, evpn_dict["mlag_node_list"][1], evpn_dict["leaf2"]["mlag_pch_intf_list"],"startup"]])
        utils.exec_all(True, [[Intf.interface_operation, evpn_dict["mlag_node_list"][0], evpn_dict["leaf1"]["iccpd_pch_intf_list"],"startup"],
                      [Intf.interface_operation, evpn_dict["mlag_node_list"][1], evpn_dict["leaf2"]["iccpd_pch_intf_list"],"startup"]])


def cleanup_mclag():
    st.log("Remove tenant L3 VLANs to ICCPD link on LVTEP nodes used for similar L3 network across LVTEP peers")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],True]])

    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],True]])

    st.log("Remove binding of L3 VNI VLAN to ICCPD link on LVTEP nodes used for orphon traffic scenarios")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["l3_vni_list"][0], evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],True]])

    st.log("Remove binding of tenant L3 VLANs to MLAG client port on LVTEP nodes to handle scale test BGP session to TGEN port")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["mlag_pch_intf_list"],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["mlag_pch_intf_list"],True]])

    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["mlag_pch_intf_list"],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["mlag_pch_intf_list"],True]])

    st.log("Remove binding of L3 VNI VLAN to MLAG client port to handle scale test BGP session to TGEN port")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["mlag_pch_intf_list"],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["l3_vni_list"][0], evpn_dict["leaf2"]["mlag_pch_intf_list"],True]])

    st.log("Remove IPv4 address of L3VNI interface on LVTEP node used for similar L3 network across LVTEP peers")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
            "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf2"]["l3_tenant_ip_list"][0], evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
            [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf1"]["l3_tenant_ip_list"][0], evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]]])

    st.log("Remove IPv6 address of L3VNI interface on LVTEP node used for similar L3 network across LVTEP peers")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
            "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log("removing mc-lag in leaf 1 and leaf 2")
    dict1 = {'domain_id':tg_dict['mlag_domain_id'], 'interface_list':evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
            'config':'del'}
    dict2 = {'domain_id':tg_dict['mlag_domain_id'], 'interface_list':evpn_dict["leaf2"]["mlag_pch_intf_list"][0],
            'config':'del'}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][0:2],mclag.config_interfaces,[dict1, dict2])

    dict1 = {'domain_id':tg_dict['mlag_domain_id'], 'config':'del'}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][0:2],mclag.config_domain, [dict1, dict1])



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

    st.log("Delete SAG vlan to VNI mapping on all leaf nodes")
    utils.exec_all(True, [[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vtepName"], evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
            evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],"1", "no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
            evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],"1", "no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
            evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],"1", "no"],
            [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["vtepName"],
            evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],"1", "no"]])

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

    st.log("remove L2 tenant vlan membershp for mc-lag client interface in leaf 1 and leaf 2 and also in client switch")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True],
                        [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                        evpn_dict["leaf2"]["mlag_pch_intf_list"][0],True],
                        [Vlan.delete_vlan_member, evpn_dict["mlag_client"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True]])

    st.log("remove L2 tenant vlan membershp for iccpd PO interface in leaf 1 and leaf 2 and also in client switch")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                        evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],True],
                        [Vlan.delete_vlan_member, evpn_dict["mlag_client"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                        evpn_dict["mlag_tg_list"][0],True],
                        [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                        evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],True]])

    st.log("Remove L2 VNI VLANs from all leaf nodes")
    utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"]],
                    [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["tenant_l2_vlan_list"]],
                    [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["tenant_l2_vlan_list"]],
                    [Vlan.delete_vlan, evpn_dict["mlag_client"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"]],
                    [Vlan.delete_vlan, evpn_dict["leaf_node_list"][3], evpn_dict["leaf4"]["tenant_l2_vlan_list"]]])

    st.log("Remove SAG configured VLANs binding to port on all leaf nodes")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["leaf4"]["intf_list_tg"][0],True]])

    st.log("Remove VLANs for sag l3 tenant interfaces")
    utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][3],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]]])


def cleanup_l3vni():
    st.log("remove L3 tenant vlan membershp for mc-lag client interface in leaf 1 and leaf 2 and also in client switch")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True],
                        [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True],
                        [Vlan.delete_vlan_member, evpn_dict["mlag_client"][0],evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                        evpn_dict["leaf1"]["mlag_pch_intf_list"][0],True]])

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
                          [Vlan.delete_vlan_member, evpn_dict["mlag_client"][0],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], evpn_dict["mlag_tg_list"][0],True],
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
    parallel.exec_parallel(True, evpn_dict["mlag_node_list"], vrf.bind_vrf_interface,[vrf_bind17,vrf_bind18])

    st.log("Remove SAG mac on all leaf nodes")
    dict1 = {"mac":evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0], "config":"remove"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],
                           sag.config_sag_mac, [dict1,dict1,dict1,dict1])

    dict1 = {"config":"disable"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],
                           sag.config_sag_mac, [dict1,dict1,dict1,dict1])
    dict1 = {"config":"disable","ip_type":'ipv6'}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],sag.config_sag_mac, [dict1,dict1,dict1,dict1])

    st.log("Remove SAG ipv4 on all leaf nodes")
    dict1 = {"interface":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            "gateway":evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], "mask":"24","config":"remove"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],
            sag.config_sag_ip, [dict1,dict1,dict1,dict1])

    st.log("Remove SAG ipv6 on all leaf nodes")
    dict1 = {"interface":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            "gateway":evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0], "mask":"96","config":"remove"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],
            sag.config_sag_ip, [dict1,dict1,dict1,dict1])

    dict1 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],"config":"no",
             "intf_name":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"skip_error":"yes"}
    dict2 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],"config":"no",
             "intf_name":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"skip_error":"yes"}
    dict3 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],"config":"no",
             "intf_name":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"skip_error":"yes"}
    dict4 = {"vrf_name" : evpn_dict["leaf4"]["vrf_name_list"][0],"config":"no",
             "intf_name":evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],"skip_error":"yes"}

    st.log("Remove vrf bind to SAG interfaces on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],
                           vrf.bind_vrf_interface,[dict1,dict2,dict3,dict4])

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

    st.log("remove L3 tenant vlan membershp for iccpd PO interface in leaf 1 and leaf 2 and also in client switch")
    utils.exec_all(True, [[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],True]])

    st.log("Remove L3 VNI tenant VLANs from all leaf nodes and mlag client")
    utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["mlag_client"][0],
                           evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]],
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

    st.log("Delete tenant L3 VLANs on LVTEP nodes used for similar L3 network across LVTEP peers")
    utils.exec_all(True, [[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0]]])

    if evpn_dict['cli_mode'] != "klish":
        st.log("Remove FRR level global VRF and VNI config")
        parallel.exec_parallel(True, evpn_dict["leaf_node_list"], Evpn.config_bgp_evpn,
                           [evpn_input25,evpn_input26,evpn_input27,evpn_input28])

def cleanup_vxlan():

    if evpn_dict['cli_mode'] == "click":
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


def cleanup_ospf_unnumbered():
    st.log("########## Remove ospf config ##########")
    utils.exec_all(True,[[ospf.config_ospf_router, evpn_dict["spine_node_list"][0], 'default', '','no'],
                         [ospf.config_ospf_router, evpn_dict["spine_node_list"][1], 'default', '','no'],
                         [ospf.config_ospf_router, evpn_dict["leaf_node_list"][0], 'default', '','no'],
						 [ospf.config_ospf_router, evpn_dict["leaf_node_list"][1], 'default', '','no'],
						 [ospf.config_ospf_router, evpn_dict["leaf_node_list"][2], 'default', '','no'],
						 [ospf.config_ospf_router, evpn_dict["leaf_node_list"][3], 'default', '','no']])

    for i in range(2):
        utils.exec_all(True, [[ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][i],'point-to-point', 'default', 'no'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][i], 'point-to-point', 'default', 'no'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][i], 'point-to-point', 'default', 'no'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][i], 'point-to-point', 'default', 'no'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][i], 'point-to-point', 'default', 'no'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["pch_intf_list"][i], 'point-to-point', 'default', 'no']])

    for i in range(2,4):
        utils.exec_all(True, [[ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][i],'point-to-point', 'default', 'no'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][i], 'point-to-point', 'default', 'no']])

    for i in range(3,8,4):
        utils.exec_all(True, [[ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][i],'point-to-point', 'default', 'no'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][i], 'point-to-point', 'default', 'no'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["intf_list_spine"][i], 'point-to-point', 'default', 'no'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["intf_list_spine"][i], 'point-to-point', 'default', 'no'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["intf_list_spine"][i], 'point-to-point', 'default', 'no'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["intf_list_spine"][i], 'point-to-point', 'default', 'no']])

    for i in range(11,16,4):
        utils.exec_all(True, [[ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["intf_list_leaf"][i],'point-to-point', 'default', 'no'],
                          [ospf.config_interface_ip_ospf_network_type, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["intf_list_leaf"][i], 'point-to-point', 'default', 'no']])

    st.log("########## Remove portchannel interface from Unnumbered in all spine and leaf nodes ##########")
    for i in range(2):
        spine1_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["spine1"]["pch_intf_list"][i],
                        'loop_back': 'Loopback1'}
        spine2_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["spine2"]["pch_intf_list"][i],
                        'loop_back': 'Loopback1'}
        leaf1_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["leaf1"]["pch_intf_list"][i],
                       'loop_back': 'Loopback1'}
        leaf2_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["leaf2"]["pch_intf_list"][i],
                       'loop_back': 'Loopback1'}
        leaf3_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["leaf3"]["pch_intf_list"][i],
                       'loop_back': 'Loopback1'}
        leaf4_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["leaf4"]["pch_intf_list"][i],
                       'loop_back': 'Loopback1'}
        parallel.exec_parallel(True, evpn_dict["spine_node_list"] + evpn_dict["leaf_node_list"],
                               ip.config_unnumbered_interface, [spine1_input, spine2_input,
                                                                leaf1_input, leaf2_input, leaf3_input, leaf4_input])

    for i in range(2,4):
        spine1_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["spine1"]["pch_intf_list"][i],
                        'loop_back': 'Loopback1'}
        spine2_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["spine2"]["pch_intf_list"][i],
                        'loop_back': 'Loopback1'}
        parallel.exec_parallel(True, evpn_dict["spine_node_list"],
                               ip.config_unnumbered_interface, [spine1_input, spine2_input])

    st.log("########## Remove router port from unnumbered in all spine and leaf nodes ##########")
    for i in range(3, 8, 4):
        spine1_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["spine1"]["intf_list_leaf"][i],
                        'loop_back': 'Loopback1'}
        spine2_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["spine1"]["intf_list_leaf"][i],
                        'loop_back': 'Loopback1'}
        leaf1_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["leaf1"]["intf_list_spine"][i],
                       'loop_back': 'Loopback1'}
        leaf2_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["leaf2"]["intf_list_spine"][i],
                       'loop_back': 'Loopback1'}
        leaf3_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["leaf3"]["intf_list_spine"][i],
                       'loop_back': 'Loopback1'}
        leaf4_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["leaf4"]["intf_list_spine"][i],
                       'loop_back': 'Loopback1'}
        parallel.exec_parallel(True, evpn_dict["spine_node_list"] + evpn_dict["leaf_node_list"],
                               ip.config_unnumbered_interface, [spine1_input, spine2_input,
                                                                leaf1_input, leaf2_input, leaf3_input, leaf4_input])

    for i in range(11, 16,4):
        spine1_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["spine1"]["intf_list_leaf"][i],
                        'loop_back': 'Loopback1'}
        spine2_input = {'family': 'ipv4', 'action': 'del', 'interface': evpn_dict["spine1"]["intf_list_leaf"][i],
                        'loop_back': 'Loopback1'}
        parallel.exec_parallel(True, evpn_dict["spine_node_list"],ip.config_unnumbered_interface,
                               [spine1_input, spine2_input])

def cleanup_5549_underlay_mclag():
    st.log("Remove IP address b/w Leaf 1 and Leaf 2 used for ICCPD control path")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["iccpd_cintf_list"][0], evpn_dict["leaf1"]["iccpd_ip_list"][0],'32'],
                        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["iccpd_cintf_list"][0], evpn_dict["leaf2"]["iccpd_ip_list"][0],'32']])

    st.log("delete port channel for MLAG client interface b/w leaf 2 and client switch")
    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], evpn_dict["leaf1"]["mlag_intf_list"][0]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], evpn_dict["leaf2"]["mlag_intf_list"][0]],
                          [pch.delete_portchannel_member, evpn_dict["mlag_client"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], evpn_dict["mlag_intf_list"][0:2]]])

    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], evpn_dict["leaf1"]["iccpd_dintf_list"][0:2]],
                          [Vlan.delete_vlan,evpn_dict["mlag_client"][0],evpn_dict["leaf1"]["tenant_l3_vlan_list"][0]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], evpn_dict["leaf2"]["iccpd_dintf_list"][0:2]]])

    utils.exec_all(True, [[pch.delete_portchannel, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"]],
                          [pch.delete_portchannel, evpn_dict["mlag_client"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"]],
                          [pch.delete_portchannel, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["mlag_pch_intf_list"]]])

    mclag.config_interfaces(evpn_dict["leaf_node_list"][0], tg_dict['mlag_domain_id'],
                            evpn_dict['leaf1']['iccpd_pch_intf_list'][0], config="del")
    mclag.config_interfaces(evpn_dict["leaf_node_list"][1], tg_dict['mlag_domain_id'],
                            evpn_dict['leaf2']['iccpd_pch_intf_list'][0], config="del")
    mclag.config_domain(evpn_dict["leaf_node_list"][0], tg_dict['mlag_domain_id'],
                        config='del')
    mclag.config_domain(evpn_dict["leaf_node_list"][1], tg_dict['mlag_domain_id'],
                        config='del')

    utils.exec_all(True, [[pch.delete_portchannel, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"]],
                          [pch.delete_portchannel, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["iccpd_pch_intf_list"]],
                          [Vlan.delete_vlan,evpn_dict["mlag_client"][0],evpn_dict["leaf1"]["tenant_l2_vlan_list"][0]]])

    st.log("Remove Loopback3 IP on LVTEP nodes")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           "Loopback3", evpn_dict["leaf1"]["loop_ip_list"][2], '32'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           "Loopback3", evpn_dict["leaf2"]["loop_ip_list"][2], '32']])
    st.log("Remove Loopback3 on LVTEP nodes")
    input = {"loopback_name": "Loopback3", "config": "no"}
    parallel.exec_parallel(True, evpn_dict["mlag_node_list"],
                           ip.configure_loopback, [input, input])

    st.log("Remove Loopback4 on LVTEP nodes")
    input = {"loopback_name": "Loopback4", "config": "no"}
    parallel.exec_parallel(True, evpn_dict["mlag_node_list"],
                           ip.configure_loopback, [input, input])


def cleanup_underlay():

    st.log("Remove BGP neighbors")
    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], Bgp.config_bgp,
                           [bgp_input17, bgp_input18, bgp_input19, bgp_input20, bgp_input21, bgp_input22])

    st.log("Remove IP address b/w Leaf 1 and Leaf 2 used for ICCPD control path")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["iccpd_cintf_list"][0], evpn_dict["leaf1"]["iccpd_ip_list"][0],'32'],
                        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["iccpd_cintf_list"][0], evpn_dict["leaf2"]["iccpd_ip_list"][0],'32']])

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

    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           "Loopback3", evpn_dict["leaf1"]["loop_ip_list"][2], '32'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           "Loopback3", evpn_dict["leaf2"]["loop_ip_list"][2], '32']])

    st.log("Remove loopback interface from all leaf nodes")
    input = {"loopback_name": "Loopback1", "config": "no"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"] + evpn_dict["spine_node_list"],
                           ip.configure_loopback, [input, input, input, input, input, input])
    input = {"loopback_name": "Loopback2", "config": "no"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"],
                           ip.configure_loopback, [input, input, input, input])

    input = {"loopback_name": "Loopback3", "config": "no"}
    parallel.exec_parallel(True, evpn_dict["mlag_node_list"],
                           ip.configure_loopback, [input, input])

    input = {"loopback_name": "Loopback4", "config": "no"}
    parallel.exec_parallel(True, evpn_dict["mlag_node_list"],
                           ip.configure_loopback, [input, input])

    st.log("delete port channel for MLAG client interface b/w leaf 2 and client switch")
    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], evpn_dict["leaf1"]["mlag_intf_list"][0]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], evpn_dict["leaf2"]["mlag_intf_list"][0]],
                          [pch.delete_portchannel_member, evpn_dict["mlag_client"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], evpn_dict["mlag_intf_list"][0:2]]])

    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], evpn_dict["leaf1"]["iccpd_dintf_list"][0:2]],
                          [Vlan.delete_vlan,evpn_dict["mlag_client"][0],evpn_dict["leaf1"]["tenant_l2_vlan_list"][0]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], evpn_dict["leaf2"]["iccpd_dintf_list"][0:2]]])

    utils.exec_all(True, [[pch.delete_portchannel, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"]],
                          [Vlan.delete_vlan,evpn_dict["mlag_client"][0],evpn_dict["leaf1"]["tenant_l3_vlan_list"][0]],
                          [pch.delete_portchannel, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["iccpd_pch_intf_list"]]])

    utils.exec_all(True, [[pch.delete_portchannel, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"]],
                          [pch.delete_portchannel, evpn_dict["mlag_client"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"]],
                          [pch.delete_portchannel, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["mlag_pch_intf_list"]]])

    st.log("Remove members from port channel created b/w leaf and spine nodes")
    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][0], evpn_dict["leaf1"]["intf_list_spine"][:3]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][0], evpn_dict["leaf2"]["intf_list_spine"][:3]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][0], evpn_dict["leaf3"]["intf_list_spine"][:3]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["pch_intf_list"][0], evpn_dict["leaf4"]["intf_list_spine"][:3]],
                          [pch.delete_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][0], evpn_dict["spine1"]["intf_list_leaf"][:3]],
                          [pch.delete_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][0], evpn_dict["spine2"]["intf_list_leaf"][:3]]])
    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][1], evpn_dict["leaf1"]["intf_list_spine"][4:7]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][1], evpn_dict["leaf2"]["intf_list_spine"][4:7]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][1], evpn_dict["leaf3"]["intf_list_spine"][4:7]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][3],
                           evpn_dict["leaf4"]["pch_intf_list"][1], evpn_dict["leaf4"]["intf_list_spine"][4:7]],
                          [pch.delete_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][1], evpn_dict["spine1"]["intf_list_leaf"][4:7]],
                          [pch.delete_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][1], evpn_dict["spine2"]["intf_list_leaf"][4:7]]])
    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][2], evpn_dict["spine1"]["intf_list_leaf"][8:11]],
                          [pch.delete_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][2], evpn_dict["spine2"]["intf_list_leaf"][8:11]]])
    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][3], evpn_dict["spine1"]["intf_list_leaf"][12:15]],
                          [pch.delete_portchannel_member, evpn_dict["spine_node_list"][1],
                           evpn_dict["spine2"]["pch_intf_list"][3], evpn_dict["spine2"]["intf_list_leaf"][12:15]]])

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

    dict1 = {'domain_id':tg_dict['mlag_domain_id'], 'interface_list':evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],
            'config':'del'}
    dict2 = {'domain_id':tg_dict['mlag_domain_id'], 'interface_list':evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],
            'config':'del'}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][0:2],mclag.config_interfaces,[dict1, dict2])

    dict1 = {'domain_id':tg_dict['mlag_domain_id'],'config':'del'}
    parallel.exec_parallel(True,evpn_dict["leaf_node_list"][0:2],mclag.config_domain,[dict1, dict1])

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

def create_stream(traffic_type, port_han_list=[],def_param=True, rate=1000, **kwargs):

    global tg, d7_tg_ph1, d6_tg_ph1,count,stream_dict

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
            port1 = d7_tg_ph1
            for ph, vlan,smac_count,dmac_count in zip([d7_tg_ph1,d6_tg_ph1],
                                           [evpn_dict["leaf4"]["tenant_l2_vlan_list"][0]] * 2,
                                           src_mac_count_list,dst_mac_count_list):
                if ph == port1:
                    stream = tg.tg_traffic_config(mac_src=evpn_dict["mlag_node"]["tenant_mac_l2"], vlan="enable",
                                    mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"], rate_pps=1000, mode='create',
                                    port_handle=ph, l2_encap='ethernet_ii_vlan', vlan_id=vlan,
                                    transmit_mode='continuous', mac_src_count=smac_count, mac_dst_count=dmac_count,
                                    mac_src_mode="increment", mac_dst_mode="increment",
                                    mac_src_step="00.00.00.00.00.01", mac_dst_step="00.00.00.00.00.01")
                else:
                    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_l2"], vlan="enable",
                                    mac_dst=evpn_dict["mlag_node"]["tenant_mac_l2"], rate_pps=1000, mode='create',
                                    port_handle=ph, l2_encap='ethernet_ii_vlan', vlan_id=vlan,
                                    transmit_mode='continuous', mac_src_count=smac_count, mac_dst_count=dmac_count,
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
            port1 = d7_tg_ph1
            for ph, dmac, vlan,ipv4_src_count,ipv4_dest_count in zip([d7_tg_ph1, d6_tg_ph1],kwargs["dst_mac_list"],
                                [evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]],src_ip_count_list,dst_ip_count_list):
                if ph == port1:
                    stream=tg.tg_traffic_config(mac_src=evpn_dict["mlag_node"]["tenant_mac_v4"],
                        mac_dst=dmac, rate_pps=rate, mode='create', port_handle=ph, l2_encap='ethernet_ii_vlan',
                        transmit_mode='continuous', ip_src_addr=evpn_dict["mlag_node"]["sag_tenant_v4_ip"],
                        ip_src_count=ipv4_src_count, ip_src_step="0.0.0.1", ip_dst_addr=evpn_dict["leaf4"]["tenant_v4_ip"],
                        ip_dst_count=ipv4_dest_count, ip_dst_step="0.0.0.1", l3_protocol= 'ipv4',l3_length='512',
                        vlan_id=vlan,vlan="enable",ip_src_mode="increment",ip_dst_mode="increment",
                        mac_discovery_gw=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0])
                    han = tg.tg_interface_config(port_handle=ph, mode='config',
                                    intf_ip_addr=evpn_dict["mlag_node"]["sag_tenant_v4_ip"],
                                    gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], vlan='1',
                                    vlan_id=vlan,vlan_id_step='0', arp_send_req='1', gateway_step='0.0.0.0',
                                    intf_ip_addr_step='0.0.0.1', count=ipv4_src_count,
                                    src_mac_addr=evpn_dict["mlag_node"]["tenant_mac_v4"])
                    tg.tg_arp_control(handle=han["handle"], arp_target='all')
                else:
                    stream=tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_v4"],
                        mac_dst=dmac, rate_pps=rate, mode='create',
                        port_handle=ph, l2_encap='ethernet_ii_vlan',
                        transmit_mode='continuous', ip_src_addr=evpn_dict["leaf4"]["tenant_v4_ip"],
                        ip_src_count=10, ip_src_step="0.0.0.1", ip_dst_addr=evpn_dict["mlag_node"]["sag_tenant_v4_ip"],
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
            port1 = d7_tg_ph1
            for ph, dmac, vlan,sip_count,dip_count in zip([d7_tg_ph1, d6_tg_ph1],kwargs["dst_mac_list"],
                                [evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                evpn_dict["leaf4"]["tenant_l3_vlan_list"][0]],src_ip_count_list,dst_ip_count_list):
                if ph == port1:
                    stream=tg.tg_traffic_config(mac_src=evpn_dict["mlag_node"]["tenant_mac_v6"], mac_src_count=sip_count,
                        mac_dst=dmac, rate_pps=rate, mode='create', port_handle=ph, l2_encap='ethernet_ii_vlan',
                        transmit_mode='continuous', ipv6_src_addr=evpn_dict["mlag_node"]["sag_tenant_v6_ip"],
                        ipv6_src_count=sip_count, ipv6_src_step="00::1", ipv6_dst_addr=evpn_dict["leaf4"]["tenant_v6_ip"],
                        ipv6_dst_count=dip_count, ipv6_dst_step="00::1", l3_protocol= 'ipv6',l3_length='512',
                        vlan_id=vlan,vlan="enable",mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                        ipv6_src_mode="increment",ipv6_dst_mode="increment",
                        mac_discovery_gw=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0])
                    han = tg.tg_interface_config(port_handle=ph, mode='config',
                                    ipv6_intf_addr=evpn_dict["mlag_node"]["sag_tenant_v6_ip"], ipv6_prefix_length='96',
                                    ipv6_gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0],
                                    src_mac_addr=evpn_dict["mlag_node"]["tenant_mac_v6"],
                                    arp_send_req='1', vlan='1', vlan_id=vlan, vlan_id_step='0',
                                    count=sip_count, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
                    tg.tg_arp_control(handle=han["handle"], arp_target='all')
                else:
                    stream=tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_v6"], mac_src_count=sip_count,
                        mac_dst=dmac, rate_pps=rate, mode='create', port_handle=ph, l2_encap='ethernet_ii_vlan',
                        transmit_mode='continuous', ipv6_src_addr=evpn_dict["leaf4"]["tenant_v6_ip"],
                        ipv6_src_count=sip_count, ipv6_src_step="00::1",
                        ipv6_dst_addr=evpn_dict["mlag_node"]["sag_tenant_v6_ip"],
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


def start_traffic(stream_han_list=[],port_han_list=[],action="run"):
    global tg,d7_tg_ph1, d6_tg_ph1, d3_tg_ph1,d4_tg_ph1,d5_tg_ph1, vars
    if action=="run":
        if port_han_list:
            tg.tg_traffic_control(action="run", port_handle=port_han_list)
            if tg.tg_type == 'ixia':
                st.wait(10)
        else:
            tg.tg_traffic_control(action="run", stream_handle=stream_han_list)
            if tg.tg_type == 'ixia':
                st.wait(5)
            else:
                st.wait(10)
    else:
        tg.tg_traffic_control(action="stop", stream_handle=stream_han_list)



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

    global tg,stream_dict,d7_tg_port1,d6_tg_port1

    if not tx_port:
        tx_port=d7_tg_port1
    if not rx_port:
        rx_port=d6_tg_port1

    if mode == "streamblock":
        traffic_details = {
            '1': {
                'tx_ports': [tx_port],
                'tx_obj': [tg],
                'exp_ratio': tx_ratio,
                'rx_ports': [rx_port],
                'rx_obj': [tg],
#                'stream_list': kwargs["tx_stream_list"]
            },
            '2': {
                'tx_ports': [rx_port],
                'tx_obj': [tg],
                'exp_ratio': rx_ratio,
                'rx_ports': [tx_port],
                'rx_obj': [tg],
#                'stream_list': kwargs["rx_stream_list"]
            },
        }
    else:
        traffic_details = {
            '1': {
                'tx_ports': [tx_port],
                'tx_obj': [tg],
                'exp_ratio': [tx_ratio],
                'rx_ports': [rx_port],
                'rx_obj': [tg],
            },
            '2': {
                'tx_ports': [rx_port],
                'tx_obj': [tg],
                'exp_ratio': [rx_ratio],
                'rx_ports': [tx_port],
                'rx_obj': [tg],
            },
        }
    return validate_tgen_traffic(traffic_details=traffic_details, mode=mode, comp_type=field,tolerance_factor=2)

def reset_tgen(port_han_list=[]):
    global tg, d3_tg_ph1, d4_tg_ph1, d6_tg_ph1, d7_tg_ph1

    if port_han_list:
        tg.tg_traffic_control(action="reset", port_handle=port_han_list)
    else:
        tg.tg_traffic_control(action="reset", port_handle=[d3_tg_ph1,d4_tg_ph1,d6_tg_ph1,d7_tg_ph1])


def create_stream_l2_multiVlans():
   tg = tg_dict['tg']
   for (src, dst, ph_src, ph_dst) in zip([evpn_dict["leaf3"]["tenant_mac_l2"], evpn_dict["leaf4"]["tenant_mac_l2"]], [evpn_dict["leaf4"]["tenant_mac_l2"], evpn_dict["leaf3"]["tenant_mac_l2"]], [tg_dict['d5_tg_ph1'], tg_dict['d6_tg_ph1']],[tg_dict['d6_tg_ph1'], tg_dict['d5_tg_ph1']]):
      stream = tg.tg_traffic_config(mode='create', port_handle=ph_src, port_handle2=ph_dst,
                     transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000', \
                     l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='200', vlan_id_count='10', \
                     vlan_id_mode="increment", vlan_id_step='1',\
                     mac_src=src, mac_src_mode="increment", mac_src_step="00:00:00:00:00:01",
                     mac_src_count='10', \
                     mac_dst=dst, mac_dst_mode="increment", mac_dst_step="00:00:00:00:00:01",
                     mac_dst_count='10')

def debug_cmds_Underlay():
    global vars
    vars = st.get_testbed_vars()
    ############################################################################################
    hdrMsg(" \n######### Debugs for Underlay ##########\n")
    ############################################################################################
    Bgp.show_bgp_ipv4_summary_vtysh(vars.D1,'default')
    Bgp.show_bgp_ipv4_summary_vtysh(vars.D2,'default')
    ip.show_ip_route(vars.D1, "ipv4","vtysh", None)
    ip.show_ip_route(vars.D1, "ipv6","vtysh", None)
    pch.get_all_interface_portchannel(vars.D1)
    ip.show_ip_route(vars.D2, "ipv4","vtysh", None)
    pch.get_all_interface_portchannel(vars.D2)
    pch.get_all_interface_portchannel(vars.D3)
    pch.get_all_interface_portchannel(vars.D4)
    pch.get_all_interface_portchannel(vars.D6)
    ############################################################################################
    hdrMsg(" \n######### Debug END - Debugs for Underlay failure ##########\n")
    ############################################################################################


def debug_vxlan_cmds(dut1,dut2):
    ############################################################################################
    hdrMsg(" \n######### Debugs for vxlan failure ##########\n")
    ############################################################################################
    st.log("Debugs on "+ dut1)
    Evpn.verify_vxlan_vlanvnimap(dut1,return_output="yes")
    Evpn.verify_vxlan_vrfvnimap(dut1,return_output="yes")
    Evpn.verify_vxlan_evpn_remote_vni_id(dut1,return_output="yes")
    Evpn.verify_vxlan_evpn_remote_mac_id(dut1,return_output="yes")
    Evpn.verify_bgp_l2vpn_evpn_route(dut1,return_output="yes")
    asicapi.bcmcmd_show(dut1, 'l2 show')
    #st.show(dut1, "bcmcmd 'l2 show'",skip_tmpl=True)
    st.log("Debugs on "+ dut2)
    Evpn.verify_vxlan_vlanvnimap(dut2,return_output="yes")
    Evpn.verify_vxlan_vrfvnimap(dut2,return_output="yes")
    Evpn.verify_vxlan_evpn_remote_vni_id(dut2,return_output="yes")
    Evpn.verify_vxlan_evpn_remote_mac_id(dut2,return_output="yes")
    Evpn.verify_bgp_l2vpn_evpn_route(dut2,return_output="yes")
    asicapi.bcmcmd_show(dut2, 'l2 show')
    #st.show(dut2, "bcmcmd 'l2 show'",skip_tmpl=True)
    if dut1 == vars.D6 or dut2 == vars.D6:
        if dut1 == vars.D3 or dut2 == vars.D3:
            st.log("-------- Checking for other LVTEP peer Node 2 --------\n")
            Evpn.verify_vxlan_vlanvnimap(vars.D4,return_output="yes")
            Evpn.verify_vxlan_vrfvnimap(vars.D4,return_output="yes")
            Evpn.verify_vxlan_evpn_remote_vni_id(vars.D4,return_output="yes")
            Evpn.verify_bgp_l2vpn_evpn_route(vars.D4,return_output="yes")
        elif dut1 == vars.D4 or dut2 == vars.D4:
            st.log("-------- Checking for other LVTEP peer Node 1 --------\n")
            Evpn.verify_vxlan_vlanvnimap(vars.D3,return_output="yes")
            Evpn.verify_vxlan_vrfvnimap(vars.D3,return_output="yes")
            Evpn.verify_vxlan_evpn_remote_vni_id(vars.D3,return_output="yes")
            Evpn.verify_bgp_l2vpn_evpn_route(vars.D3,return_output="yes")
    ############################################################################################
    hdrMsg(" \n######### Debug END - Debugs for vxlan failure ##########\n")
    ############################################################################################

def debug_lvtep_trafic():
    global vars
    ############################################################################################
    hdrMsg(" \n###### checking which LVTEP peer node is Rx traffic over VxLAN tunnel ########\n")
    ############################################################################################
    Intf.clear_interface_counters(vars.D4)
    arp.show_arp(vars.D4, None, None)
    arp.show_ndp(vars.D4, None)
    st.wait(1)
    Intf.show_interface_counters_all(vars.D4)
    Intf.clear_interface_counters(vars.D3)
    arp.show_arp(vars.D3, None, None)
    arp.show_ndp(vars.D3, None)
    st.wait(1)
    Intf.show_interface_counters_all(vars.D3)

def debug_traffic(dut1,dut2):
    global vars
    vars = st.get_testbed_vars()
    ############################################################################################
    hdrMsg(" \n######### Debugs for traffic failure ##########\n")
    ############################################################################################
    sag.verify_sag(dut1,return_output="yes")
    sag.verify_sag(dut1,return_output="yes",ip_type="ipv6")
    sag.verify_sag(dut2,return_output="yes")
    sag.verify_sag(dut2,return_output="yes",ip_type="ipv6")
    arp.show_arp(dut1, None, None)
    arp.show_ndp(dut1, None)
    arp.show_arp(dut2, None, None)
    arp.show_ndp(dut2, None)
    if dut1 == vars.D6 or dut2 == vars.D6:
        Intf.show_interface_counters_all(vars.D6)
        if dut1 == vars.D3 or dut2 == vars.D3:
            st.log("-------- Checking for other LVTEP peer Node 2 --------\n")
            arp.show_arp(vars.D4, None, None)
            arp.show_ndp(vars.D4, None)
            Mac.get_mac(vars.D4)
            Intf.show_interface_counters_all(vars.D4)
        elif dut1 == vars.D4 or dut2 == vars.D4:
            st.log("-------- Checking for other LVTEP peer Node 1 --------\n")
            arp.show_arp(vars.D3, None, None)
            arp.show_ndp(vars.D3, None)
            Mac.get_mac(vars.D3)
            Intf.show_interface_counters_all(vars.D3)
    st.log("Debugs on "+ dut1)
    port.get_interface_counters_all(dut1)
    asicapi.bcmcmd_show(dut1, 'l2 show')
    #st.show(dut1, "bcmcmd 'l2 show'",skip_tmpl=True)
    ip.show_ip_route(dut1, "ipv4","vtysh", None)
    asicapi.bcmcmd_show(dut1, 'l3 defip show')
    #st.show(dut1, "bcmcmd 'l3 defip show'",skip_tmpl=True)
    st.log("Debugs on "+ dut2)
    port.get_interface_counters_all(dut2)
    asicapi.bcmcmd_show(dut2, 'l2 show')
    asicapi.bcmcmd_show(dut2, 'l3 defip show')
    #st.show(dut2, "bcmcmd 'l2 show'",skip_tmpl=True)
    #st.show(dut2, "bcmcmd 'l3 defip show'",skip_tmpl=True)
    ip.show_ip_route(dut2, "ipv4","vtysh", None)
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
    res=st.vtysh_show(dut,"show bfd peers brief")
    sessions_up = []

    for l1 in res:
        if 'up' in l1['status'] or 'UP' in l1['status']:
            sessions_up.append(l1['peeraddress'])
    st.log('Sessions UP: '+str(sessions_up))
    return len(sessions_up)

def reset_host():
    if vars.tgen_list[0] == 'ixia-01':
        for key,val in han_dict.items():
            tg.tg_interface_config(port_handle=key, handle=val, mode='destroy')
            han_dict.pop(key)

def lvtep_orphon_port_l2_streams():
    tg = tg_dict['tg']
    for (src, dst, ph_src, ph_dst) in zip([evpn_dict["leaf1"]["tenant_mac_l2"], evpn_dict["leaf4"]["tenant_mac_l2"]], [evpn_dict["leaf4"]["tenant_mac_l2"], evpn_dict["leaf1"]["tenant_mac_l2"]], [tg_dict['d3_tg_ph1'], tg_dict['d6_tg_ph1']],[tg_dict['d6_tg_ph1'], tg_dict['d3_tg_ph1']]):
       stream = tg.tg_traffic_config(mode='create', port_handle=ph_src, port_handle2=ph_dst,
                     transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000', \
                     l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1', \
                     vlan_id_mode="increment", vlan_id_step='1',\
                     mac_src=src, mac_src_mode="increment", mac_src_step="00:00:00:00:00:01",
                     mac_src_count='1', \
                     mac_dst=dst, mac_dst_mode="increment", mac_dst_step="00:00:00:00:00:01",
                     mac_dst_count='1')

def lvtep_l2_streams():
    tg = tg_dict['tg']
    for (src, dst, ph_src, ph_dst) in zip([evpn_dict["mlag_node"]["tenant_mac_l2"], evpn_dict["leaf4"]["tenant_mac_l2"]], [evpn_dict["leaf4"]["tenant_mac_l2"], evpn_dict["mlag_node"]["tenant_mac_l2"]], [tg_dict['d7_tg_ph1'], tg_dict['d6_tg_ph1']],[tg_dict['d6_tg_ph1'], tg_dict['d7_tg_ph1']]):
       stream = tg.tg_traffic_config(mode='create', port_handle=ph_src, port_handle2=ph_dst,
                     transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000', \
                     l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1', \
                     vlan_id_mode="increment", vlan_id_step='1',\
                     mac_src=src, mac_src_mode="increment", mac_src_step="00:00:00:00:00:01",
                     mac_src_count='1', \
                     mac_dst=dst, mac_dst_mode="increment", mac_dst_step="00:00:00:00:00:01",
                     mac_dst_count='1')

def delete_host():
    if tg_dict["tg"].tg_type == 'ixia':
        for key,val in han_dict.items():
            st.log('Deleting Hosts for ports '+ str(key) + ', ' + str(val))
            tg_dict["tg"].tg_interface_config(port_handle=key, handle=val, mode='destroy')
            han_dict.pop(key)
    elif tg_dict["tg"].tg_type == 'stc':
        handle_list = [tg_dict["d3_tg_ph1"], tg_dict["d4_tg_ph1"], tg_dict["d5_tg_ph1"],
                       tg_dict["d6_tg_ph1"],tg_dict["d7_tg_ph1"]]
        tg_dict["tg"].tg_interface_config(port_handle=handle_list,mode='destroy')

def get_interfaces_counters(dut, interface=None, property=None, cli_type="click"):
    cli_type=evpn_dict["cli_mode"]
    Intf.clear_interface_counters(dut,cli_type=cli_type)
    if cli_type == "click":
        st.wait(3)
        return Intf.show_interfaces_counters(dut, interface=interface, property=property, cli_type=cli_type)
    elif cli_type == "klish":
        dict1 = {}
        value = Evpn.get_port_rate_inklish(dut,prt=interface,cntr=property)
        if "KB/s" in value:
            value = value.split(" ")[0]
        elif "MB/s" in value:
            value = value.split(" ")[0]
            value = float(value)*1024
        elif "B/s" in value:
            value = value.split(" ")[0]
        dict2 = {}
        dict2[property] = value
        return [dict2]

def setup_5549_mlag_underlay():
    st.log("create port channel interface b/w leaf 1 and leaf 2 for iccpd data ports")
    utils.exec_all(True, [[pch.create_portchannel, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["iccpd_pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["iccpd_pch_intf_list"]]])

    st.log("create port channel for MLAG client interface b/w leaf 1 and client switch")
    utils.exec_all(True, [[pch.create_portchannel, evpn_dict["mlag_node_list"][0], evpn_dict["leaf1"]["mlag_pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["mlag_client"][0], evpn_dict["leaf1"]["mlag_pch_intf_list"]],
                    [pch.create_portchannel, evpn_dict["mlag_node_list"][1], evpn_dict["leaf2"]["mlag_pch_intf_list"]]])

    st.log("adding mc lag member ports in leaf 1 and leaf 2")
    utils.exec_all(True, [[pch.add_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], evpn_dict["leaf1"]["iccpd_dintf_list"][0:2]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], evpn_dict["leaf2"]["iccpd_dintf_list"][0:2]]])

    st.log("adding mc lag client ports in leaf 1 and leaf 2 and also in MCLAG client switch")
    utils.exec_all(True, [[pch.add_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], evpn_dict["leaf1"]["mlag_intf_list"][0]],
                          [pch.add_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], evpn_dict["leaf2"]["mlag_intf_list"][0]],
                          [pch.add_portchannel_member, evpn_dict["mlag_client"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], evpn_dict["mlag_intf_list"][0:2]]])

    input = {"loopback_name" : "Loopback3"}
    parallel.exec_parallel(True, evpn_dict["mlag_node_list"],
                           ip.configure_loopback, [input,input])

    st.log("Configure IP address on Loopback 3 to be used for LVTEP source address")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                           "Loopback3", evpn_dict["leaf1"]["loop_ip_list"][2], '32'],
                          [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                           "Loopback3", evpn_dict["leaf2"]["loop_ip_list"][2], '32']])

    st.log("Configure IP address b/w Leaf 1 and Leaf 2 to establish ICCPD control path")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["iccpd_cintf_list"][0], evpn_dict["leaf1"]["iccpd_ip_list"][0],'32'],
                        [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["iccpd_cintf_list"][0], evpn_dict["leaf2"]["iccpd_ip_list"][0],'32']])


def cleanup_5549_mlag_underlay():

    st.log("Remove IP address b/w Leaf 1 and Leaf 2 used for ICCPD control path")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                        evpn_dict["leaf1"]["iccpd_cintf_list"][0], evpn_dict["leaf1"]["iccpd_ip_list"][0],'32'],
                        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                        evpn_dict["leaf2"]["iccpd_cintf_list"][0], evpn_dict["leaf2"]["iccpd_ip_list"][0],'32']])

    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
                           "Loopback3", evpn_dict["leaf1"]["loop_ip_list"][2], '32'],
                          [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
                           "Loopback3", evpn_dict["leaf2"]["loop_ip_list"][2], '32']])

    st.log("Remove loopback interface from all leaf nodes")
    input = {"loopback_name": "Loopback3", "config": "no"}
    parallel.exec_parallel(True, evpn_dict["mlag_node_list"],
                           ip.configure_loopback, [input, input])

    st.log("Delete port channel for MLAG client interface b/w leaf 2 and client switch")
    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], evpn_dict["leaf1"]["mlag_intf_list"][0]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["mlag_pch_intf_list"][0], evpn_dict["leaf2"]["mlag_intf_list"][0]],
                          [pch.delete_portchannel_member, evpn_dict["mlag_client"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"][0], evpn_dict["mlag_intf_list"][0:2]]])

    utils.exec_all(True, [[pch.delete_portchannel_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], evpn_dict["leaf1"]["iccpd_dintf_list"][0:2]],
                          [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"][0], evpn_dict["leaf2"]["iccpd_dintf_list"][0:2]]])

    utils.exec_all(True, [[pch.delete_portchannel, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["iccpd_pch_intf_list"]],
                          [pch.delete_portchannel, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["iccpd_pch_intf_list"]]])

    utils.exec_all(True, [[pch.delete_portchannel, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"]],
                          [pch.delete_portchannel, evpn_dict["mlag_client"][0],
                           evpn_dict["leaf1"]["mlag_pch_intf_list"]],
                          [pch.delete_portchannel, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["mlag_pch_intf_list"]]])

    Vlan.delete_vlan(evpn_dict["mlag_client"][0],evpn_dict["leaf1"]["tenant_l2_vlan_list"][0])
    Vlan.delete_vlan(evpn_dict["mlag_client"][0],evpn_dict["leaf1"]["tenant_l3_vlan_list"][0])

    mclag.config_interfaces(evpn_dict["leaf_node_list"][0], tg_dict['mlag_domain_id'],
                            evpn_dict['leaf1']['iccpd_pch_intf_list'][0], config="del")
    mclag.config_interfaces(evpn_dict["leaf_node_list"][1], tg_dict['mlag_domain_id'],
                            evpn_dict['leaf2']['iccpd_pch_intf_list'][0], config="del")
    mclag.config_domain(evpn_dict["leaf_node_list"][0], tg_dict['mlag_domain_id'],
                        config='del')
    mclag.config_domain(evpn_dict["leaf_node_list"][1], tg_dict['mlag_domain_id'],
                        config='del')

def lvtep_multi_l2_streams():
    tg = tg_dict['tg']
    for (src, dst, ph_src, ph_dst) in zip([evpn_dict["mlag_node"]["tenant_mac_l2"], evpn_dict["leaf4"]["tenant_mac_l2"]], [evpn_dict["leaf4"]["tenant_mac_l2"], evpn_dict["mlag_node"]["tenant_mac_l2"]], [tg_dict['d7_tg_ph1'], tg_dict['d6_tg_ph1']],[tg_dict['d6_tg_ph1'], tg_dict['d7_tg_ph1']]):
       stream = tg.tg_traffic_config(mode='create', port_handle=ph_src, port_handle2=ph_dst,
                     transmit_mode="continuous", rate_pps='20000', frame_size='1000', \
                     l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1', \
                     vlan_id_mode="increment", vlan_id_step='1',\
                     mac_src=src, mac_src_mode="increment", mac_src_step="00:00:00:00:00:01",
                     mac_src_count='30', \
                     mac_dst=dst, mac_dst_mode="increment", mac_dst_step="00:00:00:00:00:01",
                     mac_dst_count='30', length_mode='fixed')

def check_ecmp(intf_list,dut="",rate=100.0):
    if dut:
        dut=vars.D4
    else:
        dut=vars.D3

    intf_list1 = intf_list
    counter = 0
    Intf.clear_interface_counters(dut)
    if evpn_dict["cli_mode"] == "click":
        st.wait(1)
    for intf in intf_list1:
        DUT_tx_value = Evpn.get_port_counters(dut, intf,"tx_bps")
        tx_val = DUT_tx_value[0]['tx_bps'].split(" ")
        if " MB/s" in DUT_tx_value[0]['tx_bps']:
            st.log("PASS:Traffic is flowing through interface {} at the rate of {}".format(intf,float(tx_val[0])))
            counter+=1
        elif " KB/s" in DUT_tx_value[0]['tx_bps'] and float(tx_val[0]) > rate:
            st.log("PASS:Traffic is flowing through interface {} at the rate of {}".format(intf,float(tx_val[0])))
            counter+=1
        else:
            st.log("Traffic is not flowing through interface {} as rate shown as {}".format(intf,float(tx_val[0])))

    st.log("Traffic is flowing through " + str(counter) + " paths")
    return counter

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


def verify_bum_forwarder(dut,intf_list):
    interface=""
    path=0
    port.clear_interface_counters(dut)
    st.wait(3)
    if evpn_dict["cli_mode"] == "click":
        output = port.get_interface_counters_all(dut,cli_type='click')
    elif evpn_dict["cli_mode"] == "klish":
        st.wait(18,"waiting for 20 sec before checking interface rate in klish")
        ### tx_mbps field is not populated from REST output and hence script exception seen
        ### Forcing it to execute in klish for ui-types=rest-put|rest-patch as well
        output = port.get_interface_counters_all(dut, cli_type='klish')

    for intf in intf_list:
        if evpn_dict["cli_mode"] == "click":
            st.log("########### check \"tx_bps\" of interface: {} "
               "are non-zero ###########".format(intf))
            tx_value = filter_and_select(output, ["tx_bps"], {'iface': intf})
            if " KB/s" in tx_value[0]['tx_bps']:
                st.log("PASS:Traffic is flowing through interface {}".format(intf))
                interface=intf
                path+=1
            else:
                st.log("Traffic is not flowing through interface {}".format(intf))
        elif evpn_dict["cli_mode"] == "klish":
            st.log("########### check \"tx_mbps\" of interface: {} "
               "are non-zero ###########".format(intf))
            tx_value = filter_and_select(output, ["tx_mbps"], {'iface': intf})
            if float(tx_value[0]['tx_mbps']) > 0.1:
                st.log("PASS:Traffic is flowing through interface {}".format(intf))
                interface=intf
                path+=1
            else:
                st.log("Traffic is not flowing through interface {}".format(intf))
    return path,interface

def get_mclag_lvtep_common_mac():
    output1 = mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id="2",return_output="yes")
    output2 = mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id="2",return_output="yes")
    if isinstance(output1,list) and isinstance(output2,list):
        if len(output1) > 0 and len(output2) > 0:
            if evpn_dict['cli_mode'] == "click":
                if output1[0]["node_role"] == "Active":
                    mac = basic.get_ifconfig(evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["l3_vni_name_list"][0])[0]['mac']
                elif output2[0]["node_role"] == "Active":
                    mac = basic.get_ifconfig(evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["l3_vni_name_list"][0])[0]['mac']
                elif output1[0]["node_role"] == "Standby" and output2[0]["node_role"] == "Standby":
                    hdrMsg("FAIL : None of the MC-LAG peer node in Active state now")
                    mac = basic.get_ifconfig(evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["l3_vni_name_list"][0])[0]['mac']
            if evpn_dict['cli_mode'] == "klish":
                if output1[0]["node_role"] == "active":
                    mac = basic.get_ifconfig(evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["l3_vni_name_list"][0])[0]['mac']
                elif output2[0]["node_role"] == "active":
                    mac = basic.get_ifconfig(evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["l3_vni_name_list"][0])[0]['mac']
                elif output1[0]["node_role"] == "standby" and output2[0]["node_role"] == "standby":
                    hdrMsg("FAIL : None of the MC-LAG peer node in Active state now")
                    mac = basic.get_ifconfig(evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["l3_vni_name_list"][0])[0]['mac']
        elif len(output1) == 0 or len(output2) == 0:
            mac = "00:00:01:02:03:04"
            hdrMsg("FAIL : show mclag output is not as per template, traffic failure will be seen with this invalid common router MAC pls debug")
    elif isinstance(output1,bool) or isinstance(output2,bool):
        if output1 is False or output2 is False:
            mac = "00:00:01:02:03:04"
            hdrMsg("FAIL : show mclag returns empty output, traffic failure will be seen with this invalid common router MAC pls debug")
    return mac

def incrementMac(mac, step):
    step = step.replace(':', '').replace(".", '')
    mac = mac.replace(':', '').replace(".", '')
    nextMac = int(mac, 16) + int(step, 16)
    return ':'.join(("%012X" % nextMac)[i:i + 2] for i in range(0, 12, 2))


def config_evpn_lvtep():
    setup_underlay()
    setup_ospf_unnumbered()
    setup_vxlan()
    setup_l2vni()
    setup_l3vni()
    setup_mclag()


def create_stream_lvtep():

    dut6_gateway_mac = evpn_dict["dut6_gw_mac"]
    tg = tg_dict["tg"]
    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d3_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',
                                  mac_src=[evpn_dict["leaf1"]["tenant_mac_l2"]],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"])
    stream1 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream1, vars.T1D3P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d3_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',
                                  mac_src=[evpn_dict["leaf4"]["tenant_mac_l2"]],
                                  mac_dst=evpn_dict["leaf1"]["tenant_mac_l2"])
    stream2 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream2, vars.T1D6P1))
    stream_dict["l2_32311"] = [stream1,stream2]
    '''
    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                     transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                     l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                     vlan_id_mode="increment", vlan_id_step='1',mac_src=evpn_dict["mlag_node"]["tenant_mac_l2"],
                     mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"])
    stream3 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream3, vars.T1D7P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d7_tg_ph1'],
                     transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                     l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                     vlan_id_mode="increment", vlan_id_step='1',mac_src=evpn_dict["leaf4"]["tenant_mac_l2"],
                     mac_dst=evpn_dict["mlag_node"]["tenant_mac_l2"])
    stream4 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream4, vars.T1D6P1))
    stream_dict["l2_3232"] = [stream3, stream4]

    stream = tg.tg_traffic_config(mac_src='00:00:14:05:01:01',mac_dst=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d7_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ip_src_addr='120.1.1.100',ip_dst_addr='60.1.1.100',l3_protocol='ipv4',l3_length='512',
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan="enable",
                                  mac_discovery_gw=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0])
    stream5 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream5, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config',intf_ip_addr='120.1.1.100',
                                 gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr='00:00:14:05:01:01')
    host1 = han["handle"]
    han_dict["1"] = host1
    st.log("Ipv4 host {} is created for Tgen port {}".format(host1, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:00:14:06:01:01', mac_dst=dut6_gateway_mac,
                              rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                              ip_src_addr='60.1.1.100', ip_dst_addr='120.1.1.100', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ip_list"][0])
    stream6 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream6, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config', intf_ip_addr='60.1.1.100',
                             gateway=evpn_dict["leaf4"]["l3_tenant_ip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:00:14:06:01:01')
    host2 = han["handle"]
    han_dict["2"] = host2
    st.log("Ipv4 host {} is created for Tgen port {}".format(host2, vars.T1D6P1))
    stream_dict["ipv4_3237"]=[stream5,stream6]
    stream_dict["ipv4_3237_2"] = stream6
    stream_dict["v4host_3237_1"] = host1
    stream_dict["v4host_3237_2"] = host2

    stream = tg.tg_traffic_config(mac_src='00:00:77:04:00:01', mac_dst=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d7_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='1201::10',ipv6_dst_addr='6001::10',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  vlan="enable",mac_discovery_gw='1201::1')
    stream7 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream7, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config',ipv6_intf_addr='1201::10',
                                 ipv6_prefix_length='96',ipv6_gateway='1201::1',src_mac_addr='00:00:77:04:00:01',
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host3 = han["handle"]
    han_dict["3"] = host3
    st.log("Ipv6 host {} is created for Tgen port {}".format(host3, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:00:66:04:00:01', mac_dst=dut6_gateway_mac,
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='6001::10',ipv6_dst_addr='1201::10',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                  vlan="enable",mac_discovery_gw='6001::1')
    stream8 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream8, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config',ipv6_intf_addr='6001::10',
                                 ipv6_prefix_length='96',ipv6_gateway='6001::1',src_mac_addr='00:00:66:04:00:01',
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host4 = han["handle"]
    han_dict["4"] = host4
    st.log("Ipv6 host {} is created for Tgen port {}".format(host4, vars.T1D6P1))
    stream_dict["ipv6_3234"] = [stream7,stream8]
    stream_dict["v6host_3234_1"] = host3
    stream_dict["v6host_3234_2"] = host4
    '''
    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:76:01:01:01',mac_dst='00:10:76:06:01:02')
    stream9 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream9, vars.T1D7P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d7_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:76:06:01:01',mac_dst='00:10:76:01:01:02')
    stream10 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream10, vars.T1D6P1))
    stream_dict["l2_32337"] = [stream9,stream10]

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d3_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:20:16:01:01:01',mac_dst='00:20:16:06:01:02')
    stream11 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream11, vars.T1D3P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d3_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:20:16:06:01:01', mac_dst='00:20:16:01:01:02')
    stream12 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream12, vars.T1D6P1))
    stream_dict["l2_32339"] = [stream11,stream12]

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:16:01:01:01',mac_dst='00:10:16:06:01:01')
    stream13 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream13, vars.T1D7P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d7_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:16:06:01:01',mac_dst='00:10:16:01:01:01')
    stream14 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream14, vars.T1D6P1))
    stream_dict["l2_32335"] = [stream13,stream14]

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d3_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:16:01:01:01',mac_dst='00:10:16:06:01:01')
    stream15 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream15, vars.T1D3P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d3_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:16:06:01:01',mac_dst='00:10:16:01:01:01')
    stream16 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream16, vars.T1D6P1))
    stream_dict["l2_32336"] = [stream15,stream16]

    han = tg.tg_interface_config(port_handle=tg_dict['d4_tg_ph1'], mode='config',ipv6_intf_addr='4001::11',
                                 ipv6_prefix_length='96',ipv6_gateway='4001::1',
                                 src_mac_addr=evpn_dict["leaf2"]["tenant_mac_v6"],arp_send_req='1', vlan='1',
                                 vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host9 = han["handle"]
    han_dict["9"] = host9
    stream = tg.tg_traffic_config(mac_src='00:00:14:06:01:02', mac_dst=dut6_gateway_mac,
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',port_handle2=tg_dict['d7_tg_ph1'],
                                  ipv6_src_addr='6001::11',ipv6_dst_addr='4001::11',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                  vlan="enable",mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0])
    stream21 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream21, vars.T1D6P1))
    stream_dict["ipv6_32317"] = stream21
    stream_dict["v6host_32317"] = host9

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",vlan_id='451',
                                  mac_src='00:10:16:01:01:02',mac_dst='00:10:16:06:01:03')
    stream22 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream22, vars.T1D7P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d7_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",vlan_id='451',
                                  mac_src='00:10:16:06:01:02',mac_dst='00:10:16:01:01:03')
    stream23 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream23, vars.T1D6P1))
    stream_dict["l2_32343"] = [stream22,stream23]

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d5_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream24= stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream24, vars.T1D5P1))
    stream_dict["l2_32331_1"] = stream24

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf3"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d6_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream25 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream25, vars.T1D6P1))
    stream_dict["l2_32331_2"] = stream25

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d7_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream26 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream26, vars.T1D7P1))
    stream_dict["l2_32331_3"] = stream26

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d7_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream27 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream27, vars.T1D7P1))
    stream_dict["l2_32333_1"] = stream27

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d4_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream28 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream28, vars.T1D4P1))
    stream_dict["l2_32333_2"] = stream28

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d3_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream29 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream29, vars.T1D3P1))
    stream_dict["l2_32333_3"] = stream29

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d3_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',
                                  mac_src='00:00:00:33:33:33', mac_dst='00:00:00:77:33:33')
    stream32 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream32, vars.T1D3P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',
                                  mac_dst='00:00:00:33:33:33', mac_src='00:00:00:77:33:33')
    stream33 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream33, vars.T1D7P1))
    stream_dict["l2_32314"] = [stream32,stream33]

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps='1000', frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',
                                  mac_src=evpn_dict["mlag_node"]["tenant_mac_l2"],mac_src_mode="increment",
                                  mac_src_step="00:00:00:00:00:01",mac_src_count='15',
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],mac_dst_mode="increment",
                                  mac_dst_step="00:00:00:00:00:01",mac_dst_count='15', length_mode='fixed')
    stream38 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream38, vars.T1D7P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d7_tg_ph1'],
                              transmit_mode="continuous", rate_pps='1000', frame_size='1000',
                              l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                              vlan_id_mode="increment", vlan_id_step='1',
                              mac_src=evpn_dict["leaf4"]["tenant_mac_l2"], mac_src_mode="increment",
                              mac_src_step="00:00:00:00:00:01", mac_src_count='15',
                              mac_dst=evpn_dict["mlag_node"]["tenant_mac_l2"], mac_dst_mode="increment",
                              mac_dst_step="00:00:00:00:00:01", mac_dst_count='15', length_mode='fixed')
    stream39 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream39, vars.T1D6P1))
    stream_dict["l2_3281"] = [stream38,stream39]

    stream = tg.tg_traffic_config(mac_src='00:77:14:05:01:01', mac_dst=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                              rate_pps=1000, mode='create', port_handle=tg_dict['d7_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',port_handle2=tg_dict['d6_tg_ph1'],
                              ip_src_addr='120.1.1.200', ip_dst_addr='60.1.1.200', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],
                                  mac_src_count=15,mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  ip_src_count=15,ip_src_step='0.0.0.1',ip_src_mode="increment",
                                  ip_dst_count=15,ip_dst_step='0.0.0.1',ip_dst_mode="increment")
    stream40 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream40, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config', intf_ip_addr='120.1.1.200',
                             gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=15,
                             src_mac_addr='00:77:14:05:01:01')
    host12 = han["handle"]
    han_dict["12"] = host12
    st.log("Ipv4 host {} is created for Tgen port {}".format(host12, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:66:14:06:01:01', mac_dst=dut6_gateway_mac,
                              rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',port_handle2=tg_dict['d7_tg_ph1'],
                              ip_src_addr='60.1.1.200', ip_dst_addr='120.1.1.200', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ip_list"][0],
                              mac_src_count=15,mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  ip_src_count=15,ip_src_step='0.0.0.1',ip_src_mode="increment",
                                  ip_dst_count=15,ip_dst_step='0.0.0.1',ip_dst_mode="increment")
    stream41 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream41, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config', intf_ip_addr='60.1.1.200',
                             gateway=evpn_dict["leaf4"]["l3_tenant_ip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=15,
                             src_mac_addr='00:66:14:06:01:01')
    host13 = han["handle"]
    han_dict["13"] = host13
    st.log("Ipv4 host {} is created for Tgen port {}".format(host13, vars.T1D6P1))
    stream_dict["ipv4_3281"] = [stream40,stream41]
    stream_dict["v4host_3281_1"] = host12
    stream_dict["v4host_3281_2"] = host13

    stream = tg.tg_traffic_config(mac_src='00:77:16:01:01:01', mac_dst=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d7_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='1201::200',ipv6_dst_addr='6001::200',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  vlan="enable",mac_discovery_gw='1201::1',
                                  mac_src_count=15,mac_src_mode="increment", mac_src_step="00.00.00.00.00.01",
                                  ipv6_src_count=15, ipv6_src_mode="increment", ipv6_src_step="::1",
                                  ipv6_dst_count=15,ipv6_dst_mode="increment", ipv6_dst_step="::1")
    stream42 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream42, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config',ipv6_intf_addr='1201::200',
                                 ipv6_prefix_length='96',ipv6_gateway='1201::1',src_mac_addr='00:77:16:01:01:01',
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                 vlan_id_step='0',count=15, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host14 = han["handle"]
    han_dict["14"] = host14
    st.log("Ipv6 host {} is created for Tgen port {}".format(host14, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:66:16:06:01:01', mac_dst=dut6_gateway_mac,
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='6001::200',ipv6_dst_addr='1201::200',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                  vlan="enable",mac_discovery_gw='6001::1',
                                  mac_src_count=15,mac_src_mode="increment", mac_src_step="00.00.00.00.00.01",
                                  ipv6_src_count=15, ipv6_src_mode="increment", ipv6_src_step="::1",
                                  ipv6_dst_count=15,ipv6_dst_mode="increment", ipv6_dst_step="::1")
    stream43 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream43, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config',ipv6_intf_addr='6001::200',
                                 ipv6_prefix_length='96',ipv6_gateway='6001::1',src_mac_addr='00:66:16:06:01:01',
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=15, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host15 = han["handle"]
    han_dict["15"] = host15
    st.log("Ipv6 host {} is created for Tgen port {}".format(host15, vars.T1D6P1))
    stream_dict["ipv6_3281"] = [stream42,stream43]
    stream_dict["v6host_3281_1"] = host14
    stream_dict["v6host_3281_2"] = host15


def create_stream_mclag():

    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
    mclag_active_node_rmac = get_mclag_lvtep_common_mac()
    tg = tg_dict["tg"]
    stream = tg.tg_traffic_config(mac_src='00:00:14:04:04:01', mac_dst=mclag_active_node_rmac,
                              rate_pps=1000, mode='create', port_handle=tg_dict['d4_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',port_handle2=tg_dict['d6_tg_ph1'],
                              ip_src_addr='40.1.1.10', ip_dst_addr='60.1.1.10', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict["leaf2"]["l3_tenant_ip_list"][0])
    stream17 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream17, vars.T1D4P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d4_tg_ph1'], mode='config', intf_ip_addr='40.1.1.10',
                             gateway=evpn_dict["leaf2"]["l3_tenant_ip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:00:14:04:04:01')
    host5 = han["handle"]
    han_dict["5"] = host5
    st.log("Ipv4 host {} is created for Tgen port {}".format(host5, vars.T1D4P1))

    stream = tg.tg_traffic_config(mac_src='00:00:14:06:04:01', mac_dst=dut6_gateway_mac,
                              rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',port_handle2=tg_dict['d4_tg_ph1'],
                              ip_src_addr='60.1.1.10', ip_dst_addr='40.1.1.10', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ip_list"][0])
    stream18 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream18, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config', intf_ip_addr='60.1.1.10',
                             gateway=evpn_dict["leaf4"]["l3_tenant_ip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:00:14:06:04:01')
    host6 = han["handle"]
    han_dict["6"] = host6
    st.log("Ipv4 host {} is created for Tgen port {}".format(host6, vars.T1D6P1))
    stream_dict["ipv4_32313"]=[stream17,stream18]
    stream_dict["v4host_32313_1"] = host5
    stream_dict["v4host_32313_2"] = host6

    stream = tg.tg_traffic_config(mac_src='00:10:14:04:06:01', mac_dst=mclag_active_node_rmac,
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d4_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',port_handle2=tg_dict['d6_tg_ph1'],
                                  ipv6_src_addr='4001::10',ipv6_dst_addr='6001::10',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                  vlan="enable",mac_discovery_gw=evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0])
    stream19 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream19, vars.T1D4P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d4_tg_ph1'], mode='config',ipv6_intf_addr='4001::10',
                                 ipv6_prefix_length='96',ipv6_gateway=evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0],
                                 src_mac_addr='00:10:14:04:06:01',arp_send_req='1', vlan='1',
                                 vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host7 = han["handle"]
    han_dict["7"] = host7
    st.log("Ipv6 host {} is created for Tgen port {}".format(host7, vars.T1D4P1))

    stream = tg.tg_traffic_config(mac_src='00:10:14:06:06:01', mac_dst=dut6_gateway_mac,
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',port_handle2=tg_dict['d4_tg_ph1'],
                                  ipv6_src_addr='6001::10',ipv6_dst_addr='4001::10',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                  vlan="enable",mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0])
    stream20 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream20, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config',ipv6_intf_addr='6001::10',
                                 ipv6_prefix_length='96',ipv6_gateway=evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0],
                                 src_mac_addr='00:10:14:06:06:01',arp_send_req='1', vlan='1',
                                 vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host8 = han["handle"]
    han_dict["8"] = host8
    st.log("Ipv6 host {} is created for Tgen port {}".format(host8, vars.T1D6P1))
    stream_dict["ipv6_32312"] = [stream19, stream20]
    stream_dict["v6host_32312_1"] = host7
    stream_dict["v6host_32312_2"] = host8

    stream = tg.tg_traffic_config(mac_src='00:00:14:11:01:01', mac_dst=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                              rate_pps=1000, mode='create', port_handle=tg_dict['d7_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                              ip_src_addr='120.1.1.100', ip_dst_addr='30.1.1.100', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0])
    stream30 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream30, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config', intf_ip_addr='120.1.1.100',
                             gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:00:14:11:01:01')
    host10 = han["handle"]
    han_dict["10"] = host10
    st.log("Ipv4 host {} is created for Tgen port {}".format(host10, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:00:14:06:01:01', mac_dst=mclag_active_node_rmac,
                              rate_pps=1000, mode='create', port_handle=tg_dict['d3_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                              ip_src_addr='30.1.1.100', ip_dst_addr='120.1.1.100', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict['leaf1']['l3_tenant_ip_list'][0])
    stream31 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream31, vars.T1D3P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d3_tg_ph1'], mode='config', intf_ip_addr='30.1.1.100',
                             gateway=evpn_dict['leaf1']['l3_tenant_ip_list'][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:00:14:06:01:01')
    host11 = han["handle"]
    han_dict["11"] = host11
    st.log("Ipv4 host {} is created for Tgen port {}".format(host11, vars.T1D3P1))
    stream_dict["ipv4_32314"] = [stream30,stream31]
    stream_dict["v4host_32314_1"] = host10
    stream_dict["v4host_32314_2"] = host11

def create_stream_lvtep_5549():

    dut6_gateway_mac = evpn_dict["dut6_gw_mac"]
    tg = tg_dict["tg"]
    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d3_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',
                                  mac_src=[evpn_dict["leaf1"]["tenant_mac_l2"]],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"])
    stream1 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream1, vars.T1D3P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d3_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',
                                  mac_src=[evpn_dict["leaf4"]["tenant_mac_l2"]],
                                  mac_dst=evpn_dict["leaf1"]["tenant_mac_l2"])
    stream2 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream2, vars.T1D6P1))
    stream_dict["l2_32311"] = [stream1,stream2]
    '''
    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                     transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                     l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                     vlan_id_mode="increment", vlan_id_step='1',mac_src=evpn_dict["mlag_node"]["tenant_mac_l2"],
                     mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"])
    stream3 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream3, vars.T1D7P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d7_tg_ph1'],
                     transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                     l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                     vlan_id_mode="increment", vlan_id_step='1',mac_src=evpn_dict["leaf4"]["tenant_mac_l2"],
                     mac_dst=evpn_dict["mlag_node"]["tenant_mac_l2"])
    stream4 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream4, vars.T1D6P1))
    stream_dict["l2_3232"] = [stream3, stream4]

    stream = tg.tg_traffic_config(mac_src='00:00:14:05:01:01',mac_dst=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d7_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ip_src_addr='120.1.1.100',ip_dst_addr='60.1.1.100',l3_protocol='ipv4',l3_length='512',
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan="enable",
                                  mac_discovery_gw=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0])
    stream5 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream5, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config',intf_ip_addr='120.1.1.100',
                                 gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr='00:00:14:05:01:01')
    host1 = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(host1, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:00:14:06:01:01', mac_dst=dut6_gateway_mac,
                              rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                              ip_src_addr='60.1.1.100', ip_dst_addr='120.1.1.100', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ip_list"][0])
    stream6 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream6, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config', intf_ip_addr='60.1.1.100',
                             gateway=evpn_dict["leaf4"]["l3_tenant_ip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:00:14:06:01:01')
    host2 = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(host2, vars.T1D6P1))
    stream_dict["ipv4_3237"]=[stream5,stream6]
    stream_dict["ipv4_3237_2"] = stream6
    stream_dict["v4host_3237_1"] = host1
    stream_dict["v4host_3237_2"] = host2

    stream = tg.tg_traffic_config(mac_src='00:00:77:04:00:01', mac_dst=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d7_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='1201::10',ipv6_dst_addr='6001::10',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  vlan="enable",mac_discovery_gw='1201::1')
    stream7 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream7, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config',ipv6_intf_addr='1201::10',
                                 ipv6_prefix_length='96',ipv6_gateway='1201::1',src_mac_addr='00:00:77:04:00:01',
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host3 = han["handle"]
    st.log("Ipv6 host {} is created for Tgen port {}".format(host3, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:00:66:04:00:01', mac_dst=dut6_gateway_mac,
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='6001::10',ipv6_dst_addr='1201::10',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                  vlan="enable",mac_discovery_gw='6001::1')
    stream8 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream8, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config',ipv6_intf_addr='6001::10',
                                 ipv6_prefix_length='96',ipv6_gateway='6001::1',src_mac_addr='00:00:66:04:00:01',
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host4 = han["handle"]
    st.log("Ipv6 host {} is created for Tgen port {}".format(host4, vars.T1D6P1))
    stream_dict["ipv6_3234"] = [stream7,stream8]
    stream_dict["v6host_3234_1"] = host3
    stream_dict["v6host_3234_2"] = host4
    '''
    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:76:01:01:01',mac_dst='00:10:76:06:01:02')
    stream9 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream9, vars.T1D7P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d7_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:76:06:01:01',mac_dst='00:10:76:01:01:02')
    stream10 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream10, vars.T1D6P1))
    stream_dict["l2_32337"] = [stream9,stream10]

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d3_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:16:01:01:01',mac_dst='00:10:16:06:01:01')
    stream15 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream15, vars.T1D3P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d3_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:16:06:01:01',mac_dst='00:10:16:01:01:01')
    stream16 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream16, vars.T1D6P1))
    stream_dict["l2_32336"] = [stream15,stream16]

    han = tg.tg_interface_config(port_handle=tg_dict['d4_tg_ph1'], mode='config',ipv6_intf_addr='4001::11',
                                 ipv6_prefix_length='96',ipv6_gateway='4001::1',
                                 src_mac_addr=evpn_dict["leaf2"]["tenant_mac_v6"],arp_send_req='1', vlan='1',
                                 vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    stream_dict["v6host_32317"] = han["handle"]
    han_dict["1"] = han["handle"]

    stream = tg.tg_traffic_config(mac_src='00:00:14:06:01:02', mac_dst=dut6_gateway_mac,
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',port_handle2=tg_dict['d7_tg_ph1'],
                                  ipv6_src_addr='6001::11',ipv6_dst_addr='4001::11',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                  vlan="enable",mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0])
    stream21 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream21, vars.T1D6P1))
    stream_dict["ipv6_32317"] = stream21

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",vlan_id='451',
                                  mac_src='00:10:16:01:01:02',mac_dst='00:10:16:06:01:03')
    stream22 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream22, vars.T1D7P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d7_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",vlan_id='451',
                                  mac_src='00:10:16:06:01:02',mac_dst='00:10:16:01:01:03')
    stream23 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream23, vars.T1D6P1))
    stream_dict["l2_32343"] = [stream22,stream23]

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d5_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream24= stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream24, vars.T1D5P1))
    stream_dict["l2_32331_1"] = stream24

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf4"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf3"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d6_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["leaf4"]["tenant_l2_vlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream25 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream25, vars.T1D6P1))
    stream_dict["l2_32331_2"] = stream25

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d7_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream26 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream26, vars.T1D7P1))
    stream_dict["l2_32331_3"] = stream26

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d7_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream27 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream27, vars.T1D7P1))
    stream_dict["l2_32333_1"] = stream27

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d4_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream28 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream28, vars.T1D4P1))
    stream_dict["l2_32333_2"] = stream28

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],rate_pps=1000, mode='create',
                                  port_handle=tg_dict["d3_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], transmit_mode='continuous',
                                  mac_src_count=10, mac_dst_count=10, mac_src_mode="increment",
                                  mac_dst_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  mac_dst_step="00.00.00.00.00.01")
    stream29 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream29, vars.T1D3P1))
    stream_dict["l2_32333_3"] = stream29

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d3_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",port_handle2=tg_dict['d7_tg_ph1'],
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',
                                  mac_src='00:00:00:33:33:33', mac_dst='00:00:00:77:33:33')
    stream32 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream32, vars.T1D3P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",port_handle2=tg_dict['d3_tg_ph1'],
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',
                                  mac_dst='00:00:00:33:33:33', mac_src='00:00:00:77:33:33')
    stream33 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream33, vars.T1D7P1))
    stream_dict["l2_32314"] = [stream32,stream33]

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps='1000', frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',
                                  mac_src=evpn_dict["mlag_node"]["tenant_mac_l2"],mac_src_mode="increment",
                                  mac_src_step="00:00:00:00:00:01",mac_src_count='15',
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"],mac_dst_mode="increment",
                                  mac_dst_step="00:00:00:00:00:01",mac_dst_count='15', length_mode='fixed')
    stream38 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream38, vars.T1D7P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d7_tg_ph1'],
                              transmit_mode="continuous", rate_pps='1000', frame_size='1000',
                              l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                              vlan_id_mode="increment", vlan_id_step='1',
                              mac_src=evpn_dict["leaf4"]["tenant_mac_l2"], mac_src_mode="increment",
                              mac_src_step="00:00:00:00:00:01", mac_src_count='15',
                              mac_dst=evpn_dict["mlag_node"]["tenant_mac_l2"], mac_dst_mode="increment",
                              mac_dst_step="00:00:00:00:00:01", mac_dst_count='15', length_mode='fixed')
    stream39 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream39, vars.T1D6P1))
    stream_dict["l2_3281"] = [stream38,stream39]

    stream = tg.tg_traffic_config(mac_src='00:77:14:05:01:01', mac_dst=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                              rate_pps=1000, mode='create', port_handle=tg_dict['d7_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                              ip_src_addr='120.1.1.200', ip_dst_addr='60.1.1.200', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0],
                                  mac_src_count=15,mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  ip_src_count=15,ip_src_step='0.0.0.1',ip_src_mode="increment",
                                  ip_dst_count=15,ip_dst_step='0.0.0.1',ip_dst_mode="increment")
    stream40 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream40, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config', intf_ip_addr='120.1.1.200',
                             gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=15,
                             src_mac_addr='00:77:14:05:01:01')
    host12 = han["handle"]
    han_dict["2"] = han["handle"]

    st.log("Ipv4 host {} is created for Tgen port {}".format(host12, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:66:14:06:01:01', mac_dst=dut6_gateway_mac,
                              rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                              ip_src_addr='60.1.1.200', ip_dst_addr='120.1.1.200', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ip_list"][0],
                              mac_src_count=15,mac_src_mode="increment",mac_src_step="00.00.00.00.00.01",
                                  ip_src_count=15,ip_src_step='0.0.0.1',ip_src_mode="increment",
                                  ip_dst_count=15,ip_dst_step='0.0.0.1',ip_dst_mode="increment")
    stream41 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream41, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config', intf_ip_addr='60.1.1.200',
                             gateway=evpn_dict["leaf4"]["l3_tenant_ip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=15,
                             src_mac_addr='00:66:14:06:01:01')
    host13 = han["handle"]
    han_dict["3"] = han["handle"]

    st.log("Ipv4 host {} is created for Tgen port {}".format(host13, vars.T1D6P1))
    stream_dict["ipv4_3281"] = [stream40,stream41]
    stream_dict["ipv4_3281_2"] = stream41
    stream_dict["v4host_3281_1"] = host12
    stream_dict["v4host_3281_2"] = host13

    stream = tg.tg_traffic_config(mac_src='00:77:16:01:01:01', mac_dst=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d7_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='1201::200',ipv6_dst_addr='6001::200',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  vlan="enable",mac_discovery_gw='1201::1',
                                  mac_src_count=15,mac_src_mode="increment", mac_src_step="00.00.00.00.00.01",
                                  ipv6_src_count=15, ipv6_src_mode="increment", ipv6_src_step="::1",
                                  ipv6_dst_count=15,ipv6_dst_mode="increment", ipv6_dst_step="::1")
    stream42 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream42, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config',ipv6_intf_addr='1201::200',
                                 ipv6_prefix_length='96',ipv6_gateway='1201::1',src_mac_addr='00:77:16:01:01:01',
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                 vlan_id_step='0',count=15, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host14 = han["handle"]
    han_dict["4"] = han["handle"]
    st.log("Ipv6 host {} is created for Tgen port {}".format(host14, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:66:16:06:01:01', mac_dst=dut6_gateway_mac,
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='6001::200',ipv6_dst_addr='1201::200',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                  vlan="enable",mac_discovery_gw='6001::1',
                                  mac_src_count=15,mac_src_mode="increment", mac_src_step="00.00.00.00.00.01",
                                  ipv6_src_count=15, ipv6_src_mode="increment", ipv6_src_step="::1",
                                  ipv6_dst_count=15,ipv6_dst_mode="increment", ipv6_dst_step="::1")
    stream43 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream43, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config',ipv6_intf_addr='6001::200',
                                 ipv6_prefix_length='96',ipv6_gateway='6001::1',src_mac_addr='00:66:16:06:01:01',
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=15, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host15 = han["handle"]
    han_dict["5"] = han["handle"]
    st.log("Ipv6 host {} is created for Tgen port {}".format(host15, vars.T1D6P1))
    stream_dict["ipv6_3281"] = [stream42,stream43]
    stream_dict["v6host_3281_1"] = host14
    stream_dict["v6host_3281_2"] = host15

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                              transmit_mode="continuous", rate_pps='1000', frame_size='1000',
                              l2_encap='ethernet_ii_vlan', vlan="enable",
                              vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan_id_count='1',
                              vlan_id_mode="increment", vlan_id_step='1',mac_src='00:10:16:01:F1:01',
                              mac_dst='00:10:16:06:F1:02',length_mode='fixed')
    stream44 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream44, vars.T1D7P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d7_tg_ph1'],
                              transmit_mode="continuous", rate_pps='1000', frame_size='1000',
                              l2_encap='ethernet_ii_vlan', vlan="enable",
                              vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan_id_count='1',
                              vlan_id_mode="increment", vlan_id_step='1',mac_src='00:10:16:06:F1:01',
                              mac_dst='00:10:16:01:F1:02',length_mode='fixed')
    stream45 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream45, vars.T1D6P1))
    stream_dict["l2_32113"] = [stream44,stream45]

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d4_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',
                                  mac_src=[evpn_dict["leaf2"]["tenant_mac_l2"]],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"])
    stream46 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream46, vars.T1D3P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d4_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',
                                  mac_src=[evpn_dict["leaf4"]["tenant_mac_l2"]],
                                  mac_dst=evpn_dict["leaf2"]["tenant_mac_l2"])
    stream47 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream47, vars.T1D6P1))
    stream_dict["l2_372_1"] = [stream46,stream47]

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:16:01:01:01',mac_dst='00:10:16:06:01:01')
    stream48 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream48, vars.T1D7P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d7_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size='1000',
                                  l2_encap='ethernet_ii_vlan', vlan="enable",
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:16:06:01:01',mac_dst='00:10:16:01:01:01')
    stream49 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream49, vars.T1D6P1))
    stream_dict["l2_372_2"] = [stream48,stream49]

def create_stream_mclag_5549():

    dut6_gateway_mac = basic.get_ifconfig(vars.D6, vars.D6T1P1)[0]['mac']
    mclag_active_node_rmac = get_mclag_lvtep_common_mac()
    tg = tg_dict["tg"]
    stream = tg.tg_traffic_config(mac_src='00:00:14:04:04:01', mac_dst=mclag_active_node_rmac,
                              rate_pps=1000, mode='create', port_handle=tg_dict['d4_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',port_handle2=tg_dict['d6_tg_ph1'],
                              ip_src_addr='40.1.1.10', ip_dst_addr='60.1.1.10', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict["leaf2"]["l3_tenant_ip_list"][0])
    stream17 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream17, vars.T1D4P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d4_tg_ph1'], mode='config', intf_ip_addr='40.1.1.10',
                             gateway=evpn_dict["leaf2"]["l3_tenant_ip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:00:14:04:04:01')
    host5 = han["handle"]
    han_dict["6"] = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(host5, vars.T1D4P1))

    stream = tg.tg_traffic_config(mac_src='00:00:14:06:04:01', mac_dst=dut6_gateway_mac,
                              rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',port_handle2=tg_dict['d4_tg_ph1'],
                              ip_src_addr='60.1.1.10', ip_dst_addr='40.1.1.10', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ip_list"][0])
    stream18 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream18, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config', intf_ip_addr='60.1.1.10',
                             gateway=evpn_dict["leaf4"]["l3_tenant_ip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:00:14:06:04:01')
    host6 = han["handle"]
    han_dict["7"] = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(host6, vars.T1D6P1))
    stream_dict["ipv4_32313"]=[stream17,stream18]
    stream_dict["v4host_32313_1"] = host5
    stream_dict["v4host_32313_2"] = host6

    stream = tg.tg_traffic_config(mac_src='00:10:14:04:06:01', mac_dst=mclag_active_node_rmac,
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d4_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='4001::10',ipv6_dst_addr='6001::10',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                  vlan="enable",mac_discovery_gw=evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0])
    stream19 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream19, vars.T1D4P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d4_tg_ph1'], mode='config',ipv6_intf_addr='4001::10',
                                 ipv6_prefix_length='96',ipv6_gateway=evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0],
                                 src_mac_addr='00:10:14:04:06:01',arp_send_req='1', vlan='1',
                                 vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host7 = han["handle"]
    han_dict["8"] = han["handle"]
    tg.tg_arp_control(handle=host7, arp_target='all')
    st.log("Ipv6 host {} is created for Tgen port {}".format(host7, vars.T1D4P1))

    stream = tg.tg_traffic_config(mac_src='00:10:14:06:06:01', mac_dst=dut6_gateway_mac,
                                  rate_pps=1000, mode='create', port_handle=tg_dict['d6_tg_ph1'],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',
                                  ipv6_src_addr='6001::10',ipv6_dst_addr='4001::10',l3_protocol='ipv6',
                                  l3_length='512',vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                  vlan="enable",mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0])
    stream20 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream20, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config',ipv6_intf_addr='6001::10',
                                 ipv6_prefix_length='96',ipv6_gateway=evpn_dict["leaf4"]["l3_tenant_ipv6_list"][0],
                                 src_mac_addr='00:10:14:06:06:01',arp_send_req='1', vlan='1',
                                 vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host8 = han["handle"]
    han_dict["9"] = han["handle"]
    st.log("Ipv6 host {} is created for Tgen port {}".format(host8, vars.T1D6P1))
    stream_dict["ipv6_32312"] = [stream19, stream20]
    stream_dict["v6host_32312_1"] = host7
    stream_dict["v6host_32312_2"] = host8

    stream = tg.tg_traffic_config(mac_src='00:00:14:11:01:01', mac_dst=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                              rate_pps=1000, mode='create', port_handle=tg_dict['d7_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                              ip_src_addr='120.1.1.100', ip_dst_addr='30.1.1.100', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0])
    stream30 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream30, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config', intf_ip_addr='120.1.1.100',
                             gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:00:14:11:01:01')
    host10 = han["handle"]
    han_dict["10"] = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(host10, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:00:14:06:01:01', mac_dst=mclag_active_node_rmac,
                              rate_pps=1000, mode='create', port_handle=tg_dict['d3_tg_ph1'],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                              ip_src_addr='30.1.1.100', ip_dst_addr='120.1.1.100', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict['leaf1']['l3_tenant_ip_list'][0])
    stream31 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream31, vars.T1D3P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d3_tg_ph1'], mode='config', intf_ip_addr='30.1.1.100',
                             gateway=evpn_dict['leaf1']['l3_tenant_ip_list'][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:00:14:06:01:01')
    host11 = han["handle"]
    han_dict["11"] = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(host11, vars.T1D3P1))
    stream_dict["ipv4_32314"] = [stream30,stream31]
    stream_dict["v4host_32314_1"] = host10
    stream_dict["v4host_32314_2"] = host11

def remove_sameip_add_uniqueip():

    st.log("Remove IP address of L3VNI tenant interface from LVTEP nodes before MCLAG unique IP config")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
        "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["l3_tenant_ip_list"][0],
        evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
        "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["l3_tenant_ip_list"][0],
        evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]]])

    st.log("Remove IPv6 address of L3VNI tenant interface from LVTEP nodes before MCLAG unique IP config")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
        "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0],
        evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
        "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0],
        evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    dict1 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}
    dict2 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}
    st.log("Un-Bind Vrf from L3VNI interfaces on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], vrf.bind_vrf_interface,[dict1,dict2])


    dict1  = {"op_type" : "add","vlan":"Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0]}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2],mclag.config_uniqueip,[dict1,dict1])

    dict1  = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],"skip_error":"yes"}
    dict2 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],"skip_error":"yes"}

    st.log("Bind Vrf to L3VNI tenant interfaces on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2],vrf.bind_vrf_interface,[dict1,dict2])

    st.log("Assign IP address to L3VNI tenant interface on LVTEP node for similar L3 network across LVTEP peers")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf1"]["l3_tenant_ip_list"][0], evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            "30.1.1.2", evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]]])

    st.log("Assign IPv6 address to L3VNI tenant interface on LVTEP node for similar L3 network across LVTEP peers")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            "3001::2", evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

def remove_uniqueip_add_sameip():

    st.log("Remove IP address to L3VNI tenant interface unique IP config across LVTEP peers")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf1"]["l3_tenant_ip_list"][0], evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
            [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            "30.1.1.2", evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]]])

    st.log("Remove IPv6 address to L3VNI tenant interface unique IP config across LVTEP peers")
    utils.exec_all(True, [[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            "3001::2", evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    dict1 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}
    dict2 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}
    st.log("Un-Bind Vrf from L3VNI interfaces on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], vrf.bind_vrf_interface,[dict1,dict2])

    dict1  = {"op_type" : "del","vlan":"Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0]}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2],mclag.config_uniqueip,[dict1,dict1])

    dict1 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],"skip_error":"yes"}
    dict2 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],"skip_error":"yes"}
    st.log("Un-Bind Vrf from L3VNI interfaces on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], vrf.bind_vrf_interface,[dict1,dict2])

    st.log("Assign IP address to L3VNI tenant interface on LVTEP node for similar L3 network across LVTEP peers")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf1"]["l3_tenant_ip_list"][0], evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            "30.1.1.1", evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]]])

    st.log("Assign IPv6 address to L3VNI tenant interface on LVTEP node for similar L3 network across LVTEP peers")
    utils.exec_all(True, [[ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][0],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
            [ip.config_ip_addr_interface, evpn_dict["leaf_node_list"][1],
            "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
            "3001::1", evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

def debug_mclag_uniqueip():
    global vars
    vars = st.get_testbed_vars()
    Evpn.show_mclag_uniqueip(vars.D3,mclag_id="2")
    Evpn.show_mclag_uniqueip(vars.D4,mclag_id="2")

def debug_ip_neigh():
    global vars
    ############################################################################################
    hdrMsg(" \n######### Debug for ip -4 and ip -6 neigh show ##########\n")
    ############################################################################################
    Evpn.show_ip_neigh(vars.D3)
    Evpn.show_ip_neigh(vars.D4)
    Evpn.show_ip_neigh(vars.D6)

def linktrack_config():
    hdrMsg(" \n####### Step: Enabling up link tracking on LVTEP nodes ##############\n")
    utils.exec_all(True, [[Evpn.create_linktrack,evpn_dict["leaf_node_list"][0],"track1","yes"],
            [Evpn.create_linktrack,evpn_dict["leaf_node_list"][1],"track1","yes"]])

    hdrMsg(" \n####### Step: Configuring the up link tracking ports ##############\n")
    for interface1 in [evpn_dict["leaf1"]["intf_list_spine"][3], \
        evpn_dict["leaf1"]["intf_list_spine"][7]]+evpn_dict["leaf1"]["pch_intf_list"][0:2]:
        Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0],"track1",interface1,"2",
            downinterface=evpn_dict["leaf1"]["intf_list_tg"][0])

    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0], \
        "track1",evpn_dict["leaf1"]["intf_list_spine"][3],"2",description="uplink_protection")

    for interface1 in [evpn_dict["leaf2"]["intf_list_spine"][3], \
        evpn_dict["leaf2"]["intf_list_spine"][7]]+evpn_dict["leaf2"]["pch_intf_list"][0:2]:
        Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1],"track1",interface1,"2",
            downinterface=evpn_dict["leaf2"]["intf_list_tg"][0])

    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1],"track1", \
        evpn_dict["leaf2"]["intf_list_spine"][3],"2",description="uplink_protection")

    hdrMsg("\n####### Enable delay restore timer config ##############\n")
    drt = {"domain_id": "2", "delay_restore_timer":evpn_dict["del_res_timer"],"cli_type": "klish"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2], mclag.config_domain,[drt,drt])


def linktrack_unconfig():

    hdrMsg(" \n####### Step: Removing uplink tracking ports in LVTEP nodes ##############\n")
    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0],"track1",evpn_dict["leaf1"]["intf_list_spine"][7],
        "2","no",description="uplink_protection")
    Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1],"track1",evpn_dict["leaf2"]["pch_intf_list"][1],
        "2","no",downinterface=evpn_dict["leaf2"]["intf_list_tg"][0])

    hdrMsg("\n####### Disable uplink tracking ##############\n")
    utils.exec_all(True, [[Evpn.create_linktrack,evpn_dict["leaf_node_list"][0],"track1","no"],
            [Evpn.create_linktrack,evpn_dict["leaf_node_list"][1],"track1","no"]])

    hdrMsg("\n####### Disable delay restore timer config ##############\n")
    drt = {"domain_id": "2", "delay_restore_timer":evpn_dict["del_res_timer"],"cli_type": "klish","config":"del"}
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"][0:2], mclag.config_domain,[drt,drt])

def create_stream_delay_restore():
    dut6_gateway_mac = evpn_dict["dut6_gw_mac"]
    tg = tg_dict["tg"]
    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d3_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", frame_size='528',duration=evpn_dict["traffic_duration"],
                                  l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',rate_pps=100000,
                                  mac_src=[evpn_dict["leaf1"]["tenant_mac_l2"]],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"])
    stream1 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream1, vars.T1D3P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d3_tg_ph1'],
                                  transmit_mode="continuous", frame_size='528',duration=evpn_dict["traffic_duration"],
                                  l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',rate_pps=100000,
                                  mac_src=[evpn_dict["leaf4"]["tenant_mac_l2"]],
                                  mac_dst=evpn_dict["leaf1"]["tenant_mac_l2"])
    stream2 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream2, vars.T1D6P1))
    stream_dict["l2_32311"] = [stream1,stream2]

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d4_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", frame_size='528',duration=evpn_dict["traffic_duration"],
                                  l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',rate_pps=100000,
                                  mac_src=[evpn_dict["leaf2"]["tenant_mac_l2"]],
                                  mac_dst=evpn_dict["leaf4"]["tenant_mac_l2"])
    stream3 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream3, vars.T1D3P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d4_tg_ph1'],
                                  transmit_mode="continuous", frame_size='528',duration=evpn_dict["traffic_duration"],
                                  l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='100', vlan_id_count='1',
                                  vlan_id_mode="increment", vlan_id_step='1',rate_pps=100000,
                                  mac_src=[evpn_dict["leaf4"]["tenant_mac_l2"]],
                                  mac_dst=evpn_dict["leaf2"]["tenant_mac_l2"])
    stream4 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream4, vars.T1D6P1))
    stream_dict["l2_372_1"] = [stream3,stream4]

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", frame_size='528',duration=evpn_dict["traffic_duration"],
                                  l2_encap='ethernet_ii_vlan', vlan="enable",rate_pps=100000,
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:16:01:01:01',mac_dst='00:10:16:06:01:01')
    stream5 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream5, vars.T1D7P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d7_tg_ph1'],
                                  transmit_mode="continuous", frame_size='528',duration=evpn_dict["traffic_duration"],
                                  l2_encap='ethernet_ii_vlan', vlan="enable",rate_pps=100000,
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:16:06:01:01',mac_dst='00:10:16:01:01:01')
    stream6 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream6, vars.T1D6P1))
    stream_dict["l2_372_2"] = [stream5,stream6]

    stream = tg.tg_traffic_config(mac_src='00:00:14:05:01:01',mac_dst=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                                  mode='create', port_handle=tg_dict['d7_tg_ph1'],rate_pps=50000,duration=evpn_dict["traffic_duration"],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',port_handle2=tg_dict['d6_tg_ph1'],
                                  ip_src_addr='120.1.1.100',ip_dst_addr='60.1.1.100',l3_protocol='ipv4',l3_length='512',
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan="enable",
                                  mac_discovery_gw=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0])
    stream7 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream7, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config',intf_ip_addr='120.1.1.100',
                                 gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr='00:00:14:05:01:01')
    host1 = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(host1, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:00:14:06:01:01', mac_dst=dut6_gateway_mac,
                              mode='create', port_handle=tg_dict['d6_tg_ph1'],rate_pps=50000,duration=evpn_dict["traffic_duration"],
                              l2_encap='ethernet_ii_vlan', transmit_mode='continuous',port_handle2=tg_dict['d7_tg_ph1'],
                              ip_src_addr='60.1.1.100', ip_dst_addr='120.1.1.100', l3_protocol='ipv4', l3_length='512',
                              vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], vlan="enable",
                              mac_discovery_gw=evpn_dict["leaf4"]["l3_tenant_ip_list"][0])
    stream8 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream8, vars.T1D6P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d6_tg_ph1'], mode='config', intf_ip_addr='60.1.1.100',
                             gateway=evpn_dict["leaf4"]["l3_tenant_ip_list"][0], vlan='1', vlan_id_step='0',
                             vlan_id=evpn_dict["leaf4"]["tenant_l3_vlan_list"][0], arp_send_req='1',
                             gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1,
                             src_mac_addr='00:00:14:06:01:01')
    host2 = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(host2, vars.T1D6P1))
    stream_dict["ipv4_3237"]=[stream7,stream8]
    stream_dict["v4host_3237_1"] = host1
    stream_dict["v4host_3237_2"] = host2

    stream = tg.tg_traffic_config(mac_src='00:00:24:05:01:01',mac_dst=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                                  mode='create', port_handle=tg_dict['d7_tg_ph1'],rate_pps=50000,duration=evpn_dict["traffic_duration"],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',port_handle2=tg_dict['d6_tg_ph1'],
                                  ip_src_addr='120.1.1.101',ip_dst_addr='60.1.1.100',l3_protocol='ipv4',l3_length='512',
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan="enable",
                                  mac_discovery_gw=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0])
    stream9 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream9, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config',intf_ip_addr='120.1.1.101',
                                 gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr='00:00:24:05:01:01')
    host3 = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(host3, vars.T1D7P1))

    stream = tg.tg_traffic_config(mac_src='00:00:34:05:01:01',mac_dst=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                                  mode='create', port_handle=tg_dict['d7_tg_ph1'],rate_pps=50000,duration=evpn_dict["traffic_duration"],
                                  l2_encap='ethernet_ii_vlan',transmit_mode='continuous',port_handle2=tg_dict['d6_tg_ph1'],
                                  ip_src_addr='120.1.1.102',ip_dst_addr='60.1.1.100',l3_protocol='ipv4',l3_length='512',
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0], vlan="enable",
                                  mac_discovery_gw=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0])
    stream10 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream10, vars.T1D7P1))

    han = tg.tg_interface_config(port_handle=tg_dict['d7_tg_ph1'], mode='config',intf_ip_addr='120.1.1.102',
                                 gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr='00:00:34:05:01:01')
    host4 = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(host4, vars.T1D7P1))
    stream_dict["ipv4_3238"]=[stream9,stream10]
    stream_dict["v4host_3238_1"] = host3
    stream_dict["v4host_3238_2"] = host4

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d7_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", frame_size='528',duration=evpn_dict["traffic_duration"],
                                  l2_encap='ethernet_ii_vlan', vlan="enable",rate_pps=100000,
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:76:01:01:01',mac_dst='00:10:76:06:01:02')
    stream11 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream11, vars.T1D7P1))

    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d7_tg_ph1'],
                                  transmit_mode="continuous", frame_size='528',duration=evpn_dict["traffic_duration"],
                                  l2_encap='ethernet_ii_vlan', vlan="enable",rate_pps=100000,
                                  vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  mac_src='00:10:76:06:01:01',mac_dst='00:10:76:01:01:02')
    stream12 = stream["stream_id"]
    st.log("host to send L2 stream {} is created for Tgen port {}".format(stream12, vars.T1D6P1))
    stream_dict["l2_32337"] = [stream11,stream12]

def delay_restore_check(dut,ccep,domain="2"):
    result = False
    if "PortChannel" in ccep:
        for i in range(1,40):
            time = [];updown=[]
            updown = pch.get_portchannel(dut,portchannel_name=ccep,cli_type="klish")
            time = mclag.verify_domain(dut=dut,domain_id=domain,cli_type="klish",return_output="yes")
            if isinstance(time,list) and isinstance(updown,list):
                if time[0]['delay_restore_left_timer'] != '' and updown[0]['state'] == "D":
                    st.log("\n \n #### delay restore timer left {} sec; retry : {} #### \n".format(time[0]['delay_restore_left_timer'],i))
                    st.wait(2)
                elif time[0]['delay_restore_left_timer'] == '' and updown[0]['state'] == "U":
                    hdrMsg("#### PASS: delay restore timer left 0 sec; downlink port state is : {} retry {}".format(updown[0]['state'],i))
                    result = True
                    break
                elif time[0]['delay_restore_left_timer'] != '' and updown[0]['state'] == "U":
                    st.error("FAIL: delay restore timer left {} sec; downlink port state is :{} retry {}".format(time[0]['delay_restore_left_timer'],updown[0]['state'],i))
                    break
                else:
                    st.log("# delay restore timer left {} sec; downlink port state is : {}, retry {}".format(time[0]['delay_restore_left_timer'],updown[0]['state'],i))
                    st.wait(2)
            elif isinstance(time,bool) and isinstance(updown,bool):
                st.log("#### FAIL: show command is blank, delay restore timer left is {} ; downlink port state is : {} ####".format(time,updown))
                return result
            if i == 39:
                st.log("Delay Restore Check failed, max retry attempt reached, waited 78 secs")
    else:
        for i in range(1,40):
            time = [];updown=[]
            updown = port.get_status(dut, port=ccep,cli_type="klish")
            time = mclag.verify_domain(dut=dut,domain_id=domain,cli_type="klish",return_output="yes")
            if isinstance(time,list) and isinstance(updown,list):
                if time[0]['delay_restore_left_timer'] != '' and updown[0]['oper'] == "down":
                    st.log("\n \n #### delay restore timer left {} sec; retry : {} #### \n".format(time[0]['delay_restore_left_timer'],i))
                    st.wait(2)
                elif time[0]['delay_restore_left_timer'] == '' and updown[0]['oper'] == "up":
                    hdrMsg("#### PASS: delay restore timer left 0 sec; downlink port state is : {} retry {}".format(updown[0]['oper'],i))
                    result = True
                    break
                elif time[0]['delay_restore_left_timer'] != '' and updown[0]['oper'] == "up":
                    st.error("FAIL: delay restore timer left {} sec; downlink port state is :{} retry {}".format(time[0]['delay_restore_left_timer'],updown[0]['oper'],i))
                    break
                else:
                    st.log("# delay restore timer left {} sec; downlink port state is : {}, retry {}".format(time[0]['delay_restore_left_timer'],updown[0]['oper'],i))
                    st.wait(2)
            elif isinstance(time,bool) or len(updown) == 0:
                st.log("#### FAIL: show command is blank, delay restore timer left is {} ; downlink port state is : {} ####".format(time,updown))
                return result
            if i == 39:
                st.log("Delay Restore Check failed, max retry attempt reached, waited 78 secs")

    return result

def session_status_check(dut,domain="2"):
    result = False
    max_range = 24
    for i in range(1,max_range+1):
        status=[]
        status = mclag.verify_domain(dut=dut,domain_id=domain,cli_type="klish",return_output="yes")
        if isinstance(status,list):
            if status[0]['session_status'] != "up":
                st.log("\n \n ######### Session status : {} ; retry : {} ########".format(status[0]['session_status'],i))
                ip.get_interface_ip_address(dut, interface_name=None, family="ipv4")
                ip.get_interface_ip_address(dut, interface_name=None, family="ipv6")
                Evpn.get_tunnel_list(dut)
                st.wait(5)
            elif status[0]['session_status'] == "up":
                result = True
                hdrMsg("PASS: Session status come up fine after {} secs ".format(i*5))
                break
        elif isinstance(status,bool):
            st.log("#### FAIL: show command is blank, session status is : {} ####".format(status))
            return result
        if i == 25:
            st.log("MCLAG Session Status Check failed, max retry attempt reached, waited 125 secs")
    if not result:
        hdrMsg("FAIL: Session status did not come up even after waiting for {} sec".format(max_range*5))
    return result

def debug_delay_restore(dut):
    st.show(dut, "sudo debugsh -c ORCHAGENT -e show system internal orchagent delayrestore global",skip_tmpl=True)

def get_traffic_loss_inpercent(tg_port_ph,stream_id,dest_tg_ph=''):
    global vars
    tg = tg_dict['tg']
    tx_stats = tg_dict["tg"].tg_traffic_stats(mode='streams',streams=stream_id,port_handle=tg_port_ph)
    tx_count = tx_stats[tg_port_ph]['stream'][stream_id]['tx']['total_pkts']
    if tg_dict["tg"].tg_type == 'stc':
        rx_count = tx_stats[tg_port_ph]['stream'][stream_id]['rx']['total_pkts']
    if tg_dict["tg"].tg_type == 'ixia':
        if dest_tg_ph == '':
            dest_tg_ph = tg_dict['d6_tg_ph1']
        rx_count = tx_stats[dest_tg_ph]['stream'][stream_id]['rx']['total_pkts']
    pkts_loss = int(tx_count) - int(rx_count)
    if int(tx_count) == 0:
        loss_percent = 1.0
    else:
        loss_percent = float(pkts_loss)/int(tx_count)
    st.log("Tx Pkts : {}, Rx Pkts : {}, Pkts lost : {}, loss % = {}, stream id: {}".format(tx_count,rx_count,pkts_loss,loss_percent,stream_id))
    return loss_percent

def verify_empty_arp_nd_table(result):
    if result == []:
        return False
    elif result[0]['address'] == '':
        return False
    elif result[0]['address'] != '':
        return True

