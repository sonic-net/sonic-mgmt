import json
import re
from spytest import st, utils, tgapi
import apis.routing.evpn as Evpn
import apis.switching.vlan as Vlan
import apis.switching.portchannel as pch
import apis.system.interface as Intf
import apis.routing.bgp as Bgp
import apis.routing.ip as ip
import apis.routing.vrf as vrf
from apis.system import basic
from utilities import parallel
import apis.common.asic_bcm as asicapi

d5_tg_ph1,d6_tg_ph1 = None, None

dscp_to_tc_map_1 = {"0" : "1", "1" : "1", "2" : "1", "3" : "3",
                    "4" : "4", "5" : "2", "6" : "1", "7" : "1",
                    "8" : "0", "9" : "1", "10": "1", "11": "1",
                    "12": "1", "13": "1", "14": "1", "15": "1",
                    "16": "1", "17": "1", "18": "1", "19": "1",
                    "20": "4", "21": "1", "22": "5", "23": "1",
                    "24": "1", "25": "1", "26": "1", "27": "1",
                    "28": "1", "29": "1", "30": "1", "31": "1",
                    "32": "1", "33": "1", "34": "1", "35": "1",
                    "36": "1", "37": "1", "38": "1", "39": "1",
                    "40": "1", "41": "1", "42": "1", "43": "1",
                    "44": "1", "45": "1", "46": "5", "47": "1",
                    "48": "6", "49": "1", "50": "1", "51": "1",
                    "52": "1", "53": "1", "54": "1", "55": "1",
                    "56": "1", "57": "1", "58": "1", "59": "1",
                    "60": "1", "61": "1", "62": "1", "63": "1"}
evpn_dict = {"leaf1" : {"intf_ipv6_list" : ["1001:2::2"],
                        "loop_ip_list" : ["2.2.2.1","2.2.2.2"], "local_as" : "200",
                        "tenant_l2_vlan_list" : ["100","101","102"], "vlan_list" : ["12"],
                        "rem_as_list" : ["100"], "ve_intf_list" : ["Vlan13"],
                        "pch_intf_list" : ["PortChannel12"],
                        "l3_vni_list": ["500", "501", "502"],
                        "tenant_l3_vlan_list": ["200", "201", "202"],
                        "l3_vni_name_list": ["Vlan500", "Vlan501", "Vlan502"],
                        "l3_vni_ip_list": ["22.22.1.1", "22.22.2.1", "22.22.3.1"],
                        "l3_vni_ipmask_list": ["24", "24", "24"],
                        "l3_vni_ip_net" : ["22.22.1.0/24","22.22.2.0/24","22.22.3.0/24"],
                        "l3_tenant_ip_list": ["20.1.1.1", "20.1.2.1", "20.1.3.1"],
                        "l3_tenant_ip_net" : ["20.1.1.0/24","20.1.2.0/24","20.1.3.0/24"],
                        "l3_vni_ipv6_list": ["2221::1", "2222::1", "2223::1"],
                        "l3_vni_ipv6_net" : ["2221::/96", "2222::/96", "2223::/96"],
                        "l3_vni_ipv6mask_list": ["96", "96", "96"],
                        "l3_tenant_ipv6_list": ["2001::1", "2002::1", "2003::1"],
                        "l3_tenant_ipv6_net" : ["2001::/96","2002::/96","2003::/96"],
                        "vrf_name_list": ["Vrf1", "Vrf2", "Vrf3"],
                        "tenant_l2_vlan_name_list": ["Vlan100", "Vlan101", "Vlan102"],
                        "vtepName" : "vtepLeaf1", "nvoName" : "nvoLeaf1",
                        "tenant_mac_l2": ["00.02.22.00.00.01","00.02.22.00.00.22"],
                        "tenant_mac_l2_2": ["00.02.22.22.00.01","00.02.22.22.00.22"],
                        "tenant_mac_v4": ["00.04.22.00.00.01","00.04.22.00.00.22"],
                        "tenant_mac_v4_2": ["00.04.22.22.00.01","00.04.22.22.00.22"],
                        "tenant_mac_v6": ["00.06.22.00.00.01","00.06.22.00.00.22"],
                        "tenant_mac_v6_2": ["00.06.22.22.00.01","00.06.22.22.00.22"],
                        "tenant_v4_ip": ["20.1.1.2","30.1.1.3","40.1.1.3"],
                        "tenant_v4_ip_2": ["20.2.2.2","30.2.2.3","40.2.2.3"],
                        "tenant_v6_ip": ["2001::2","3001::3","4001::3"],
                        "tenant_v6_ip_2": ["2002::2","3002::3","4002::3"],
                        "tenant_mac_v4_colon": "00:04:22:00:00:01","tenant_mac_v6_colon": "00:06:22:00:00:01",
                        "tenant_mac_v4_colon_2": "00:04:22:22:00:01","tenant_mac_v6_colon_2": "00:06:22:22:00:01"},
             "leaf2" : {"intf_ipv6_list" : ["1001:3::2"],
                        "loop_ip_list" : ["3.3.3.1","3.3.3.2"], "local_as" : "300",
                        "tenant_l2_vlan_list" : ["100","101","102"], "vlan_list" : ["13"],
                        "rem_as_list" : ["100"], "ve_intf_list" : ["Vlan13"],
                        "pch_intf_list" : ["PortChannel13"],
                        "l3_vni_list": ["500", "501", "502"],
                        "tenant_l3_vlan_list": ["300", "301", "302"],
                        "l3_vni_name_list": ["Vlan500", "Vlan501", "Vlan502"],
                        "l3_vni_ip_list": ["33.33.1.1", "33.33.2.1", "33.33.3.1"],
                        "l3_vni_ipmask_list": ["24", "24", "24"],
                        "l3_vni_ip_net" : ["33.33.1.0/24","33.33.2.0/24","33.33.3.0/24"],
                        "l3_tenant_ip_list": ["30.1.1.1", "30.1.2.1", "30.1.3.1"],
                        "l3_tenant_ip_net" : ["30.1.1.0/24","30.1.2.0/24","30.1.3.0/24"],
                        "l3_vni_ipv6_list": ["3331::1", "3332::1", "3333::1"],
                        "l3_vni_ipv6_net" : ["3331::/96", "3332::/96", "3333::/96"],
                        "l3_vni_ipv6mask_list": ["96", "96", "96"],
                        "l3_tenant_ipv6_list": ["3001::1", "3002::1", "3003::1"],
                        "l3_tenant_ipv6_net" : ["3001::/96","3002::/96","3003::/96/24"],
                        "vrf_name_list": ["Vrf1", "Vrf2", "Vrf3"],
                        "tenant_l2_vlan_name_list": ["Vlan100", "Vlan101", "Vlan102"],
                        "vtepName" : "vtepLeaf2", "nvoName" : "nvoLeaf2",
                        "tenant_mac_l2" : ["00.02.33.00.00.01","00.02.33.00.00.33"],
                        "tenant_mac_l2_2" : ["00.02.33.33.00.01","00.02.33.33.00.33"],
                        "tenant_mac_v4": ["00.04.33.00.00.01","00.04.33.00.00.33"],
                        "tenant_mac_v4_2": ["00.04.33.33.00.01","00.04.33.33.00.33"],
                        "tenant_mac_v6" : ["00.06.33.00.00.01","00.06.33.00.00.33"],
                        "tenant_mac_v6_2" : ["00.06.33.33.00.01","00.06.33.33.00.33"],
                        "tenant_v4_ip" : ["30.1.1.2","20.1.1.3","40.1.1.3"],
                        "tenant_v4_ip_2" : ["30.2.2.2","20.2.2.3","40.2.2.3"],
                        "tenant_v6_ip" : ["3001::2","2001::3","4001::3"],
                        "tenant_v6_ip_2" : ["3002::2","2002::3","4002::3"],
                        "tenant_mac_v6_colon_2": ["00:06:33:33:00:01","00:06:33:33:00:33"]},
             "leaf3" : {"intf_ipv6_list" : ["1001:4::2"],
                        "loop_ip_list" : ["4.4.4.1","4.4.4.2"], "local_as" : "400",
                        "tenant_l2_vlan_list" : ["100","101","102"], "vlan_list" : ["13"],
                        "rem_as_list" : ["100"], "ve_intf_list" : ["Vlan14"],
                        "pch_intf_list" : ["PortChannel14"],
                        "l3_vni_list": ["500", "501", "502"],
                        "tenant_l3_vlan_list": ["400", "401", "402"],
                        "l3_vni_name_list": ["Vlan500", "Vlan501", "Vlan502"],
                        "l3_vni_ip_list": ["44.44.1.1", "44.44.2.1", "44.44.3.1"],
                        "l3_vni_ipmask_list": ["24", "24", "24"],
                        "l3_vni_ip_net" : ["44.44.1.0/24","44.44.2.0/24","44.44.3.0/24"],
                        "l3_tenant_ip_list": ["40.1.1.1", "40.1.2.1", "40.1.3.1"],
                        "l3_tenant_ip_net" : ["40.1.1.0/24","40.1.2.0/24","40.1.3.0/24"],
                        "l3_vni_ipv6_list": ["4441::1", "4442::1", "4443::1"],
                        "l3_vni_ipv6_net" : ["4441::/96", "4442::/96", "4443::/96"],
                        "l3_vni_ipv6mask_list": ["96", "96", "96"],
                        "l3_tenant_ipv6_list": ["4001::1", "4002::1", "4003::1"],
                        "l3_tenant_ipv6_net" : ["4001::/96","4002::/96","4003::/96/24"],
                        "vrf_name_list": ["Vrf1", "Vrf2", "Vrf3"],
                        "tenant_l2_vlan_name_list": ["Vlan100", "Vlan101", "Vlan102"],
                        "vtepName" : "vtepLeaf3", "nvoName" : "nvoLeaf3",
                        "tenant_mac_l2" : ["00.02.44.00.00.01","00.02.44.00.00.44"],
                        "tenant_mac_l2_2" : ["00.02.44.44.00.01","00.02.44.44.00.44"],
                        "tenant_mac_v4": ["00.04.44.00.00.01","00.04.44.00.00.44"],
                        "tenant_mac_v4_2": ["00.04.44.44.00.01","00.04.44.44.00.44"],
                        "tenant_mac_v6" : ["00.06.44.00.00.01","00.06.44.00.00.44"],
                        "tenant_mac_v6_2" : ["00.06.44.44.00.01","00.06.44.44.00.44"],
                        "tenant_v4_ip" : ["40.1.1.2","20.1.1.3","30.1.1.3"],
                        "tenant_v4_ip_2" : ["40.2.2.2","20.2.2.3","30.2.2.3"],
                        "tenant_v6_ip" : ["4001::2","2001::3","3001::3"],
                        "tenant_mac_v6_colon_2" : ["00:06:44:44:00:01","00:06:44:44:00:44"],
                        "tenant_v6_ip_2" : ["4002::2","2002::3","3002::3"]},
             "spine1": {"intf_ipv6_list" : ["1001:2::1","1001:3::1","1001:4::1"], "local_as" : "100",
                        "loop_ip_list" : ["1.1.1.1", "1.1.1.2"], "vlan_list" : ["13","14","15"],
                        "rem_as_list" : ["200","300","400"],"ve_intf_list" : ["Vlan12","Vlan13","Vlan14"],
                        "pch_intf_list" : ["PortChannel12","PortChannel13","PortChannel14"]}
             }

vrf_input1 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0]}
vrf_input2 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],"config":"no"}

vrf_bind1 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
             "intf_name":evpn_dict["leaf1"]["l3_vni_name_list"][0],"skip_error":"yes"}
vrf_bind2 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],
             "intf_name":evpn_dict["leaf2"]["l3_vni_name_list"][0],"skip_error":"yes"}
vrf_bind3 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
             "intf_name":evpn_dict["leaf3"]["l3_vni_name_list"][0],"skip_error":"yes"}

vrf_bind5 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
              "intf_name":evpn_dict["leaf1"]["l3_vni_name_list"][0],"skip_error":"yes","config":"no"}
vrf_bind6 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],
              "intf_name":evpn_dict["leaf2"]["l3_vni_name_list"][0],"skip_error":"yes","config":"no"}
vrf_bind7 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
              "intf_name":evpn_dict["leaf3"]["l3_vni_name_list"][0],"skip_error":"yes","config":"no"}

vrf_bind9  = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],"skip_error":"yes"}
vrf_bind10 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],"skip_error":"yes"}
vrf_bind11 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],"skip_error":"yes"}

vrf_bind13 = {"vrf_name" : evpn_dict["leaf1"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}
vrf_bind14 = {"vrf_name" : evpn_dict["leaf2"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}
vrf_bind15 = {"vrf_name" : evpn_dict["leaf3"]["vrf_name_list"][0],
             "intf_name": "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],"skip_error":"yes","config":"no"}

bgp_input23 = {'local_as': evpn_dict['leaf1']['local_as'],'config' : 'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf1"]["vrf_name_list"][0]}
bgp_input24 = {'local_as': evpn_dict['leaf2']['local_as'],'config' : 'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf2"]["vrf_name_list"][0]}
bgp_input25 = {'local_as': evpn_dict['leaf3']['local_as'],'config' : 'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0]}

bgp_input27 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf1']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf1"]["vrf_name_list"][0]}
bgp_input28 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf2']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf2"]["vrf_name_list"][0]}
bgp_input29 = {"config_type_list": ["removeBGP"], "local_as": evpn_dict['leaf3']['local_as'],
               "config" : "no", "removeBGP" : "yes","vrf_name":evpn_dict["leaf3"]["vrf_name_list"][0]}

bgp_input35 = {'local_as': evpn_dict['leaf1']['local_as'],'config' : 'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf1"]["vrf_name_list"][0],'addr_family':'ipv6'}
bgp_input36 = {'local_as': evpn_dict['leaf2']['local_as'],'config' : 'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf2"]["vrf_name_list"][0],'addr_family':'ipv6'}
bgp_input37 = {'local_as': evpn_dict['leaf3']['local_as'],'config' : 'yes',
               'config_type_list':["redist"],'redistribute':'connected',
               'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0],'addr_family':'ipv6'}

evpn_input21 = {'local_as': evpn_dict['leaf1']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf1"]["vrf_name_list"][0]}
evpn_input22 = {'local_as': evpn_dict['leaf2']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf2"]["vrf_name_list"][0]}
evpn_input23 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes','advertise_ipv4' : 'unicast',
                'config_type_list':["advertise_ipv4_vrf"],'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0]}

evpn_input30 = {'local_as': evpn_dict['leaf1']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf1"]["vrf_name_list"][0]}
evpn_input31 = {'local_as': evpn_dict['leaf2']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf2"]["vrf_name_list"][0]}
evpn_input32 = {'local_as': evpn_dict['leaf3']['local_as'],'config':'yes','advertise_ipv6' : 'unicast',
                'config_type_list':["advertise_ipv6_vrf"],'vrf_name':evpn_dict["leaf3"]["vrf_name_list"][0]}

stream_dict = {}
count = 1
tg_dict = {}
han_dict = {}

def create_glob_vars():
    global vars
    vars = st.ensure_min_topology("D1D2:4","D1D3:4","D1D4:4","D2T1:2","D3T1:2","D4T1:2",
                                  "D2CHIP:TD3", "D3CHIP:TD3", "D4CHIP:TD3")

    tg_dict["tg"], tg_dict['d2_tg_ph1'] = tgapi.get_handle_byname("T1D2P1")
    tg_dict["tg"], tg_dict['d2_tg_ph2'] = tgapi.get_handle_byname("T1D2P2")
    tg_dict["tg"], tg_dict['d3_tg_ph1'] = tgapi.get_handle_byname("T1D3P1")
    tg_dict["tg"], tg_dict['d3_tg_ph2'] = tgapi.get_handle_byname("T1D3P2")
    tg_dict["tg"], tg_dict['d4_tg_ph1'] = tgapi.get_handle_byname("T1D4P1")
    tg_dict["tg"], tg_dict['d4_tg_ph2'] = tgapi.get_handle_byname("T1D4P2")
    tg_dict['d2_tg_port1'],tg_dict['d2_tg_port2'] = vars.T1D2P1, vars.T1D2P2
    tg_dict['d3_tg_port1'],tg_dict['d3_tg_port2'] = vars.T1D3P1, vars.T1D3P2
    tg_dict['d4_tg_port1'], tg_dict['d4_tg_port2'] = vars.T1D4P1, vars.T1D4P2

    tg_dict['tgen_rate_pps'] = '1000'
    tg_dict['frame_size'] = '1000'
    tg_dict["cap_frames"] = "500"
    evpn_dict["leaf_node_list"] = [vars.D2, vars.D3,vars.D4]
    evpn_dict["spine_node_list"] = [vars.D1]
    evpn_dict["bgp_node_list"] = [vars.D1, vars.D2, vars.D3,vars.D4]
    evpn_dict["leaf1"]["intf_list_spine"] = [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D1P4]
    evpn_dict["leaf1"]["intf_list_tg"] = [vars.D2T1P1, vars.D2T1P2]
    evpn_dict["leaf2"]["intf_list_spine"] = [vars.D3D1P1, vars.D3D1P2, vars.D3D1P3, vars.D3D1P4]
    evpn_dict["leaf2"]["intf_list_tg"] = [vars.D3T1P1, vars.D3T1P2]
    evpn_dict["leaf3"]["intf_list_spine"] = [vars.D4D1P1, vars.D4D1P2, vars.D4D1P3, vars.D4D1P4]
    evpn_dict["leaf3"]["intf_list_tg"] = [vars.D4T1P1, vars.D4T1P2]

    evpn_dict["spine1"]["intf_list_leaf"] = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4,
                                             vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4,
                                             vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4]
    evpn_dict["dut2_gw_mac"] = basic.get_ifconfig(vars.D2, vars.D2T1P1)[0]['mac']
    evpn_dict["dut3_gw_mac"] = basic.get_ifconfig(vars.D3, vars.D3T1P1)[0]['mac']
    evpn_dict["dut4_gw_mac"] = basic.get_ifconfig(vars.D4, vars.D4T1P1)[0]['mac']


def leaf1_setup_vxlan():

    st.log("config vtep in DUT2 node")
    Evpn.create_overlay_intf(dut=evpn_dict["leaf_node_list"][0],vtep_name=evpn_dict["leaf1"]["vtepName"],
                             ip_addr=evpn_dict["leaf1"]["loop_ip_list"][1])


def leaf2_setup_vxlan():

    st.log("config vtep in DUT3 node")
    Evpn.create_overlay_intf(dut=evpn_dict["leaf_node_list"][1],vtep_name=evpn_dict["leaf2"]["vtepName"],
                             ip_addr=evpn_dict["leaf2"]["loop_ip_list"][1])


def leaf3_setup_vxlan():

    st.log("config vtep in DUT4 node")
    Evpn.create_overlay_intf(dut=evpn_dict["leaf_node_list"][2],vtep_name=evpn_dict["leaf3"]["vtepName"],
                             ip_addr=evpn_dict["leaf3"]["loop_ip_list"][1])


def leaf1_setup_l2vni():
    st.log("create tenant L2 VLANs in DUT2 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][0],vlan_list=evpn_dict["leaf1"]["tenant_l2_vlan_list"])

    st.log("Bind tenant L2 VLANs to port in DUT2 node")
    for i in [0,1]:
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][0],vlan=evpn_dict["leaf1"]["tenant_l2_vlan_list"][i],
                         port_list=evpn_dict["leaf1"]["intf_list_tg"][0], tagging_mode=True)
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][0], vlan=evpn_dict["leaf1"]["tenant_l2_vlan_list"][i],
                             port_list=evpn_dict["leaf1"]["intf_list_tg"][1],tagging_mode=True)

    st.log("Add L2 vlan to VNI mapping in DUT2 node")
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][0],vtep_name=evpn_dict["leaf1"]["vtepName"],
                      vlan_id=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                      vni_id=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0])


def leaf2_setup_l2vni():
    st.log("create tenant L2 VLANs in DUT3 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][1],vlan_list=evpn_dict["leaf2"]["tenant_l2_vlan_list"])

    st.log("Bind tenant L2 VLANs to port in DUT3 node")
    for i in [0,1]:
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][1],vlan=evpn_dict["leaf2"]["tenant_l2_vlan_list"][i],
                         port_list=evpn_dict["leaf2"]["intf_list_tg"][0], tagging_mode=True)
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][1], vlan=evpn_dict["leaf2"]["tenant_l2_vlan_list"][i],
                             port_list=evpn_dict["leaf2"]["intf_list_tg"][1], tagging_mode=True)

    st.log("Add L2 vlan to VNI mapping in DUT3 node")
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][1],vtep_name=evpn_dict["leaf2"]["vtepName"],
                      vlan_id=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                      vni_id=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0])


def leaf3_setup_l2vni():
    st.log("create tenant L2 VLANs in DUT4 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][2],vlan_list=evpn_dict["leaf3"]["tenant_l2_vlan_list"])

    st.log("Bind tenant L2 VLANs to port in DUT4 node")
    for i in [0,1]:
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][2],vlan=evpn_dict["leaf3"]["tenant_l2_vlan_list"][i],
                         port_list=evpn_dict["leaf3"]["intf_list_tg"][0], tagging_mode=True)
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][2], vlan=evpn_dict["leaf3"]["tenant_l2_vlan_list"][i],
                         port_list=evpn_dict["leaf3"]["intf_list_tg"][1],tagging_mode=True)

    st.log("Add L2 vlan to VNI mapping in DUT4 node")
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][2],vtep_name=evpn_dict["leaf3"]["vtepName"],
                      vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                      vni_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0])


def leaf1_setup_l3vni():

    st.log("create Vrf in DUT2 node")
    vrf.config_vrf(dut=evpn_dict["leaf_node_list"][0],vrf_name= evpn_dict["leaf1"]["vrf_name_list"][0])

    st.log("create VLANs for L3VNI in DUT2 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][0],vlan_list=evpn_dict["leaf1"]["l3_vni_list"][0])

    st.log("create tenant L3 VLANs in DUT2 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][0],vlan_list=evpn_dict["leaf1"]["tenant_l3_vlan_list"])

    st.log("Bind L3VNI and tenant L3 VLANs to port in DUT2 node")
    for vlan in [evpn_dict["leaf1"]["l3_vni_list"][0],evpn_dict["leaf1"]["tenant_l3_vlan_list"][0]]:
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][0], vlan=vlan,
                             port_list=evpn_dict["leaf1"]["intf_list_tg"][0], tagging_mode=True)
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][0], vlan=evpn_dict["leaf1"]["l3_vni_list"][0],
                         port_list=evpn_dict["leaf1"]["intf_list_tg"][1], tagging_mode=True)
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][0], vlan=evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                         port_list=evpn_dict["leaf1"]["intf_list_tg"][1])

    st.log("Bind Vrf to L3VNI interfaces in DUT2 node")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                           intf_name=evpn_dict["leaf1"]["l3_vni_name_list"][0],skip_error="yes")

    st.log("Bind Vrf to L3VNI tenant interfaces in DUT2 node")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][0], vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                           intf_name="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], skip_error="yes")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][0], vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                           intf_name="Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][1], skip_error="yes")

    st.log("Assign IP address to L3VNI interface in DUT2 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                ip_address=evpn_dict["leaf1"]["l3_vni_ip_list"][0],
                                subnet=evpn_dict["leaf1"]["l3_vni_ipmask_list"][0])

    st.log("Assign IP address to L3VNI tenant interface in DUT2 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name="Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                                ip_address=evpn_dict["leaf1"]["l3_tenant_ip_list"][0],
                                subnet=evpn_dict["leaf1"]["l3_vni_ipmask_list"][0])
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name="Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                                ip_address=evpn_dict["leaf1"]["l3_tenant_ip_list"][1],
                                subnet=evpn_dict["leaf1"]["l3_vni_ipmask_list"][0])

    st.log("Assign IPv6 address to L3VNI interface in DUT2 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                ip_address=evpn_dict["leaf1"]["l3_vni_ipv6_list"][0],
                                subnet=evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0], family="ipv6")

    st.log("Assign IPv6 address to L3VNI tenant interface in DUT2 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                                ip_address=evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0],
                                subnet=evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],family="ipv6")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name="Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                                ip_address=evpn_dict["leaf1"]["l3_tenant_ipv6_list"][1],
                                subnet=evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0], family="ipv6")

    st.log("Add L3 vlan to VNI mapping in DUT2 node")
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][0],vtep_name=evpn_dict["leaf1"]["vtepName"],
                      vlan_id=evpn_dict["leaf1"]["l3_vni_list"][0],vni_id=evpn_dict["leaf1"]["l3_vni_list"][0])

    st.log("Add Vrf to VNI map in DUT2 node")
    Evpn.map_vrf_vni(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                     vni=evpn_dict["leaf1"]["l3_vni_list"][0],config='yes', vtep_name=evpn_dict["leaf1"]["vtepName"])

    st.log("Add FRR VRF redist connected config for ipv4 and ipv6 AF in DUT2 node")
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0],local_as=evpn_dict['leaf1']['local_as'],config='yes',
                   config_type_list=["redist"],redistribute='connected',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0])
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0],local_as=evpn_dict['leaf1']['local_as'],config='yes',
                   config_type_list=["redist"],redistribute='connected',
                   vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],addr_family='ipv6')

    st.log("Add FRR VRF advertise ipv4 & ipv6 unicast config in DUT2 node")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][0],local_as=evpn_dict['leaf1']['local_as'],
                         config='yes',advertise_ipv4='unicast',config_type_list=["advertise_ipv4_vrf"],
                         vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0])
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][0],local_as=evpn_dict['leaf1']['local_as'],
                         config='yes',advertise_ipv6='unicast',config_type_list=["advertise_ipv6_vrf"],
                         vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0])


def leaf2_setup_l3vni():

    st.log("create Vrf in DUT3 node")
    vrf.config_vrf(dut=evpn_dict["leaf_node_list"][1],vrf_name= evpn_dict["leaf2"]["vrf_name_list"][0])

    st.log("create VLANs for L3VNI in DUT3 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][1],vlan_list=evpn_dict["leaf2"]["l3_vni_list"][0])

    st.log("create tenant L3 VLANs in DUT3 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][1],vlan_list=evpn_dict["leaf2"]["tenant_l3_vlan_list"])

    st.log("Bind L3VNI and tenant L3 VLANs to port in DUT3 node")
    for vlan in [evpn_dict["leaf2"]["l3_vni_list"][0],evpn_dict["leaf2"]["tenant_l3_vlan_list"][0]]:
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][1], vlan=vlan,
                             port_list=evpn_dict["leaf2"]["intf_list_tg"][0], tagging_mode=True)
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][1],vlan=evpn_dict["leaf2"]["l3_vni_list"][0],
                         port_list=evpn_dict["leaf2"]["intf_list_tg"][1], tagging_mode=True)
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][1],vlan=evpn_dict["leaf2"]["tenant_l3_vlan_list"][1],
                         port_list=evpn_dict["leaf2"]["intf_list_tg"][1])

    st.log("Bind Vrf to L3VNI interfaces in DUT3 node")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                           intf_name=evpn_dict["leaf2"]["l3_vni_name_list"][0],skip_error="yes")

    st.log("Bind Vrf to L3VNI tenant interfaces in DUT3 node")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][1], vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                           intf_name="Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], skip_error="yes")

    st.log("Assign IP address to L3VNI interface in DUT3 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][1],
                                interface_name=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                                ip_address=evpn_dict["leaf2"]["l3_vni_ip_list"][0],
                                subnet=evpn_dict["leaf2"]["l3_vni_ipmask_list"][0])

    st.log("Assign IP address to L3VNI tenant interface in DUT3 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][1],
                                interface_name="Vlan" + evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                ip_address=evpn_dict["leaf2"]["l3_tenant_ip_list"][0],
                                subnet=evpn_dict["leaf2"]["l3_vni_ipmask_list"][0])

    st.log("Assign IPv6 address to L3VNI interface in DUT3 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][1],
                                interface_name=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                                ip_address=evpn_dict["leaf2"]["l3_vni_ipv6_list"][0],
                                subnet=evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0], family="ipv6")

    st.log("Assign IPv6 address to L3VNI tenant interface in DUT3 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][1],
                                interface_name="Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                ip_address=evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0],
                                subnet=evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0],family="ipv6")

    st.log("Add L3 vlan to VNI mapping in DUT3 node")
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][1],vtep_name=evpn_dict["leaf2"]["vtepName"],
                      vlan_id=evpn_dict["leaf2"]["l3_vni_list"][0],vni_id=evpn_dict["leaf2"]["l3_vni_list"][0])

    st.log("Add Vrf to VNI map in in DUT3 node")
    Evpn.map_vrf_vni(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                     vni=evpn_dict["leaf2"]["l3_vni_list"][0],config='yes', vtep_name=evpn_dict["leaf2"]["vtepName"])

    st.log("Add FRR VRF redist connected config for ipv4 and ipv6 AF in DUT3 node")
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1],local_as=evpn_dict['leaf2']['local_as'],config='yes',
                   config_type_list=["redist"],redistribute='connected',vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0])
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1],local_as=evpn_dict['leaf2']['local_as'],config='yes',
                   config_type_list=["redist"],redistribute='connected',
                   vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],addr_family='ipv6')

    st.log("Add FRR VRF advertise ipv4 & ipv6 unicast config in DUT3 node")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][1],local_as=evpn_dict['leaf2']['local_as'],
                         config='yes',advertise_ipv4='unicast',config_type_list=["advertise_ipv4_vrf"],
                         vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0])
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][1],local_as=evpn_dict['leaf2']['local_as'],
                         config='yes',advertise_ipv6='unicast',config_type_list=["advertise_ipv6_vrf"],
                         vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0])


def leaf3_setup_l3vni():

    st.log("create Vrf in DUT4 node")
    vrf.config_vrf(dut=evpn_dict["leaf_node_list"][2],vrf_name= evpn_dict["leaf3"]["vrf_name_list"][0])

    st.log("create VLANs for L3VNI in DUT4 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][2],vlan_list=evpn_dict["leaf3"]["l3_vni_list"][0])

    st.log("create tenant L3 VLANs in DUT4 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][2],vlan_list=evpn_dict["leaf3"]["tenant_l3_vlan_list"])

    st.log("Bind L3VNI and tenant L3 VLANs to port in DUT4 node")
    for vlan in [evpn_dict["leaf3"]["l3_vni_list"][0],evpn_dict["leaf3"]["tenant_l3_vlan_list"][0]]:
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][2], vlan=vlan,
                             port_list=evpn_dict["leaf3"]["intf_list_tg"][0], tagging_mode=True)
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][2], vlan=evpn_dict["leaf3"]["l3_vni_list"][0],
                         port_list=evpn_dict["leaf3"]["intf_list_tg"][1], tagging_mode=True)
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][2], vlan=evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
                         port_list=evpn_dict["leaf3"]["intf_list_tg"][1])

    st.log("Bind Vrf to L3VNI interfaces in DUT4 node")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][2],vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                           intf_name=evpn_dict["leaf3"]["l3_vni_name_list"][0],skip_error="yes")

    st.log("Bind Vrf to L3VNI tenant interfaces in DUT4 node")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][2], vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                           intf_name="Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], skip_error="yes")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][2], vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                           intf_name="Vlan" + evpn_dict["leaf3"]["tenant_l3_vlan_list"][1], skip_error="yes")

    st.log("Assign IP address to L3VNI interface in DUT4 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],
                                interface_name=evpn_dict["leaf3"]["l3_vni_name_list"][0],
                                ip_address=evpn_dict["leaf3"]["l3_vni_ip_list"][0],
                                subnet=evpn_dict["leaf3"]["l3_vni_ipmask_list"][0])

    st.log("Assign IP address to L3VNI tenant interface in DUT4 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],
                                interface_name="Vlan" + evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_list"][0],
                                subnet=evpn_dict["leaf3"]["l3_vni_ipmask_list"][0])
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],
                                interface_name="Vlan" + evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_list"][1],
                                subnet=evpn_dict["leaf3"]["l3_vni_ipmask_list"][0])

    st.log("Assign IPv6 address to L3VNI interface in DUT4 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],
                                interface_name=evpn_dict["leaf3"]["l3_vni_name_list"][0],
                                ip_address=evpn_dict["leaf3"]["l3_vni_ipv6_list"][0],
                                subnet=evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0], family="ipv6")

    st.log("Assign IPv6 address to L3VNI tenant interface in DUT4 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],
                                interface_name="Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0],
                                subnet=evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],family="ipv6")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],
                                interface_name="Vlan" + evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][1],
                                subnet=evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0], family="ipv6")

    st.log("Add L3 vlan to VNI mapping in DUT4 node")
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][2],vtep_name=evpn_dict["leaf3"]["vtepName"],
                      vlan_id=evpn_dict["leaf3"]["l3_vni_list"][0],vni_id=evpn_dict["leaf3"]["l3_vni_list"][0])

    st.log("Add Vrf to VNI map in DUT4 node")
    Evpn.map_vrf_vni(dut=evpn_dict["leaf_node_list"][2],vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                     vni=evpn_dict["leaf3"]["l3_vni_list"][0],config='yes', vtep_name=evpn_dict["leaf3"]["vtepName"])

    st.log("Add FRR VRF redist connected config for ipv4 and ipv6 AF in DUT4 node")
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],config='yes',
                   config_type_list=["redist"],redistribute='connected',vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0])
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],config='yes',
                   config_type_list=["redist"],redistribute='connected',
                   vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],addr_family='ipv6')

    st.log("Add FRR VRF advertise ipv4 & ipv6 unicast config in DUT4 node")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],
                         config='yes',advertise_ipv4='unicast',config_type_list=["advertise_ipv4_vrf"],
                         vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0])
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],
                         config='yes',advertise_ipv6='unicast',config_type_list=["advertise_ipv6_vrf"],
                         vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0])


def spine_verify_evpn():
    global vars
    return Evpn.verify_bgp_l2vpn_evpn_summary(dut=evpn_dict["spine_node_list"][0],
                                       identifier=evpn_dict["spine1"]["loop_ip_list"][1],
                                       neighbor=evpn_dict["spine1"]["pch_intf_list"]+
                                                [vars.D1D2P1,vars.D1D2P4,vars.D1D3P1,
                                                 vars.D1D3P4,vars.D1D4P1,vars.D1D4P4],
                                       updown=["up", "up", "up","up","up", "up", "up","up","up"])


def leaf1_verify_evpn():
    global vars
    return Evpn.verify_bgp_l2vpn_evpn_summary(dut=evpn_dict["leaf_node_list"][0],
                                       identifier=evpn_dict["leaf1"]["loop_ip_list"][1],
                                       neighbor=evpn_dict["leaf1"]["pch_intf_list"]+[vars.D2D1P1,vars.D2D1P4],
                                       updown=["up", "up", "up"])


def leaf2_verify_evpn():
    global vars
    return Evpn.verify_bgp_l2vpn_evpn_summary(dut=evpn_dict["leaf_node_list"][1],
                                       identifier=evpn_dict["leaf2"]["loop_ip_list"][1],
                                       neighbor=evpn_dict["leaf2"]["pch_intf_list"]+[vars.D3D1P1,vars.D3D1P4],
                                       updown=["up", "up", "up"])


def leaf3_verify_evpn():
    global vars
    return Evpn.verify_bgp_l2vpn_evpn_summary(dut=evpn_dict["leaf_node_list"][2],
                                       identifier=evpn_dict["leaf3"]["loop_ip_list"][1],
                                       neighbor=evpn_dict["leaf3"]["pch_intf_list"]+[vars.D4D1P1,vars.D4D1P4],
                                       updown=["up", "up", "up"])


def leaf1_verify_vxlan():
    return Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][0],
                                           src_vtep=evpn_dict["leaf1"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf2"]["loop_ip_list"][1],
                                                          evpn_dict["leaf3"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_up'] * 2)


def leaf2_verify_vxlan():
    return Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][1],
                                           src_vtep=evpn_dict["leaf2"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf1"]["loop_ip_list"][1],
                                                          evpn_dict["leaf3"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_up'] * 2)


def leaf3_verify_vxlan():
    return Evpn.verify_vxlan_tunnel_status(dut=evpn_dict["leaf_node_list"][2],
                                           src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf1"]["loop_ip_list"][1],
                                                          evpn_dict["leaf2"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_up'] * 2)


def cleanup_l2vni():

    st.log("Delete L2 vlan to VNI mapping")
    st.exec_all([[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], "1", "no"],
                          [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                           "1", "no"],
                          [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                           "1", "no"]])

    st.log("Remove tenant L2 VLAN binding from all leaf nodes")
    st.exec_all([[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l2_vlan_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True]])
    st.exec_all([[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l2_vlan_list"][1], evpn_dict["leaf1"]["intf_list_tg"][1],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l2_vlan_list"][1], evpn_dict["leaf2"]["intf_list_tg"][1],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l2_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][1],True]])
    st.exec_all([[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][1],
                  evpn_dict["leaf1"]["intf_list_tg"][0], True],
                 [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                  evpn_dict["leaf2"]["tenant_l2_vlan_list"][1], evpn_dict["leaf2"]["intf_list_tg"][0], True],
                 [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                  evpn_dict["leaf3"]["tenant_l2_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][0], True]])
    st.exec_all([[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                  evpn_dict["leaf1"]["intf_list_tg"][1], True],
                 [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                  evpn_dict["leaf2"]["tenant_l2_vlan_list"][0], evpn_dict["leaf2"]["intf_list_tg"][1], True],
                 [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                  evpn_dict["leaf3"]["tenant_l2_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][1], True]])
    st.log("Remove L2 VNI VLANs from all leaf nodes")
    st.exec_all([[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0], evpn_dict["leaf1"]["tenant_l2_vlan_list"]],
                    [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["tenant_l2_vlan_list"]],
                    [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["tenant_l2_vlan_list"]]])


def cleanup_l3vni():
    st.log("Remove Vrf to VNI map on all leaf nodes")
    st.exec_all([[Evpn.map_vrf_vni, evpn_dict["leaf_node_list"][0],
            evpn_dict["leaf1"]["vrf_name_list"][0], evpn_dict["leaf1"]["l3_vni_list"][0],
            'no', evpn_dict["leaf1"]["vtepName"]],
            [Evpn.map_vrf_vni, evpn_dict["leaf_node_list"][1],
            evpn_dict["leaf2"]["vrf_name_list"][0], evpn_dict["leaf2"]["l3_vni_list"][0],
            'no', evpn_dict["leaf2"]["vtepName"]],
            [Evpn.map_vrf_vni, evpn_dict["leaf_node_list"][2],
            evpn_dict["leaf3"]["vrf_name_list"][0], evpn_dict["leaf3"]["l3_vni_list"][0],
            'no', evpn_dict["leaf3"]["vtepName"]]])

    st.log("Delete L3 vlan to VNI mapping")
    st.exec_all([[Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf1"]["l3_vni_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0], "1", "no"],
                          [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][1], evpn_dict["leaf2"]["vtepName"],
                           evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["l3_vni_list"][0],
                           "1", "no"],
                          [Evpn.map_vlan_vni, evpn_dict["leaf_node_list"][2], evpn_dict["leaf3"]["vtepName"],
                           evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["l3_vni_list"][0],
                           "1", "no"]])

    st.log("Remove L3VNI VLAN binding from all leaf nodes")
    st.exec_all([[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["l3_vni_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["l3_vni_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True]])
    st.exec_all([[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                  evpn_dict["leaf1"]["l3_vni_list"][0], evpn_dict["leaf1"]["intf_list_tg"][1], True],
                 [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                  evpn_dict["leaf2"]["l3_vni_list"][0], evpn_dict["leaf2"]["intf_list_tg"][1], True],
                 [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                  evpn_dict["leaf3"]["l3_vni_list"][0], evpn_dict["leaf3"]["intf_list_tg"][1], True]])

    st.log("Remove L3 tenant VLAN port binding from all leaf nodes")
    st.exec_all([[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["intf_list_tg"][0],True],
                          [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], evpn_dict["leaf3"]["intf_list_tg"][0],True]])
    st.exec_all([[Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][0],
                  evpn_dict["leaf1"]["tenant_l3_vlan_list"][1], evpn_dict["leaf1"]["intf_list_tg"][1]],
                 [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][1],
                  evpn_dict["leaf2"]["tenant_l3_vlan_list"][1], evpn_dict["leaf2"]["intf_list_tg"][1]],
                 [Vlan.delete_vlan_member, evpn_dict["leaf_node_list"][2],
                  evpn_dict["leaf3"]["tenant_l3_vlan_list"][1], evpn_dict["leaf3"]["intf_list_tg"][1]]])

    st.log("Remove IP address of L3VNI interface from all leaf nodes")
    st.exec_all([[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
        evpn_dict["leaf1"]["l3_vni_name_list"][0], evpn_dict["leaf1"]["l3_vni_ip_list"][0],
        evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
        evpn_dict["leaf2"]["l3_vni_name_list"][0], evpn_dict["leaf2"]["l3_vni_ip_list"][0],
        evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][0], evpn_dict["leaf3"]["l3_vni_ip_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]]])

    st.log("Remove IP address of L3VNI tenant interface from all leaf nodes")
    st.exec_all([[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
        "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["l3_tenant_ip_list"][0],
        evpn_dict["leaf1"]["l3_vni_ipmask_list"][0]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
        "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["l3_tenant_ip_list"][0],
        evpn_dict["leaf2"]["l3_vni_ipmask_list"][0]],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], evpn_dict["leaf3"]["l3_tenant_ip_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipmask_list"][0]]])

    st.log("Remove IPv6 address of L3VNI interface from all leaf nodes")
    st.exec_all([[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
        evpn_dict["leaf1"]["l3_vni_name_list"][0], evpn_dict["leaf1"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
        evpn_dict["leaf2"]["l3_vni_name_list"][0], evpn_dict["leaf2"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        evpn_dict["leaf3"]["l3_vni_name_list"][0], evpn_dict["leaf3"]["l3_vni_ipv6_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log("Remove IPv6 address of L3VNI tenant interface from all leaf nodes")
    st.exec_all([[ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
        "Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0],
        evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
        "Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0],
        evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0],"ipv6"],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
        "Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0],
        evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],"ipv6"]])

    st.log("Un-Bind Vrf from L3VNI interfaces on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], vrf.bind_vrf_interface,[vrf_bind5,
                           vrf_bind6, vrf_bind7])

    st.log("Un-Bind Vrf from L3VNI tenant interfaces on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], vrf.bind_vrf_interface,[vrf_bind13,
                           vrf_bind14, vrf_bind15])

    st.log("Remove Vrf on all leaf nodes")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], vrf.config_vrf,
                           [vrf_input2, vrf_input2, vrf_input2])

    st.log("Remove L3 VNI VLANs from all leaf nodes")
    st.exec_all([[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["l3_vni_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["l3_vni_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["l3_vni_list"][0]]])

    st.log("Remove L3 VNI tenant VLANs from all leaf nodes")
    st.exec_all([[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][0]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][0]]])
    st.exec_all([[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][1]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][1]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][1]]])
    st.exec_all([[Vlan.delete_vlan, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["tenant_l3_vlan_list"][2]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["tenant_l3_vlan_list"][2]],
                          [Vlan.delete_vlan, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["tenant_l3_vlan_list"][2]]])

    st.log("Remove BGP neighbors for L3 tenant vrf")
    parallel.exec_parallel(True, evpn_dict["leaf_node_list"], Bgp.config_bgp,
                           [bgp_input27, bgp_input28, bgp_input29])


def cleanup_vxlan():

    st.log("Remove vtep from all leaf nodes")
    st.exec_all([[Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["vtepName"], evpn_dict["leaf1"]["loop_ip_list"][1], "no"],
                          [Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["vtepName"], evpn_dict["leaf2"]["loop_ip_list"][1], "no"],
                          [Evpn.create_overlay_intf, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["vtepName"], evpn_dict["leaf3"]["loop_ip_list"][1], "no"]])


def hdrMsg(msg):
    st.log("\n######################################################################" \
    " \n%s\n######################################################################"%msg)


def create_stream():
    rate_pkts = 1000
    l3_len = 512
    duration=5
    dut2_gateway_mac = evpn_dict["dut2_gw_mac"]
    dut3_gateway_mac = evpn_dict["dut3_gw_mac"]
    dut4_gateway_mac = evpn_dict["dut4_gw_mac"]
    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_l2"][0], vlan="enable",
                                             vlan_user_priority="2",mac_dst=evpn_dict["leaf2"]["tenant_mac_l2"][0],
                                             rate_pps=rate_pkts, mode='create',port_handle=tg_dict["d2_tg_ph1"],
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                             duration=duration,port_handle2=tg_dict["d3_tg_ph1"])
    stream1 = stream['stream_id']
    st.log("L2 stream {} towards DUT3 TgenPort1 with PCP value 2 is created at DUT2 Tgenport1"
           " {}".format(stream1,vars.T1D2P1))
    stream_dict["l2_1"] = [stream1]

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf2"]["tenant_mac_l2"][0], vlan="enable",
                                  mac_dst=evpn_dict["leaf1"]["tenant_mac_l2"][0], rate_pps=rate_pkts, mode='create',
                                  port_handle=tg_dict["d3_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                                  duration=duration,port_handle2=tg_dict["d2_tg_ph1"])
    stream2 = stream['stream_id']
    st.log("L2 stream {} towards DUT2 TgenPort1 with PCP value 0 is created at DUT3 "
           "TgenPort1 {}".format(stream2, vars.T1D3P1))
    stream_dict["l2_2"] = [stream2]

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_l2_2"][0],
                                  mac_dst=evpn_dict["leaf3"]["tenant_mac_l2_2"][0], rate_pps=rate_pkts, mode='create',
                                  port_handle=tg_dict["d2_tg_ph2"], l2_encap='ethernet_ii',
                                  duration=duration,port_handle2=tg_dict["d4_tg_ph2"])
    stream3 = stream['stream_id']
    st.log("Untagged L2 stream {} towards DUT4 TgenPort2 is created at DUT2 TgenPort2 {}".format(stream3, vars.T1D2P2))
    stream_dict["l2_3"] = [stream3]

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_l2_2"][0],
                                  mac_dst=evpn_dict["leaf1"]["tenant_mac_l2_2"][0], rate_pps=rate_pkts, mode='create',
                                  port_handle=tg_dict["d4_tg_ph2"], l2_encap='ethernet_ii',
                                  duration=duration,port_handle2=tg_dict["d2_tg_ph2"])
    stream4 = stream['stream_id']
    st.log("Untagged L2 stream {} towards DUT2 TgenPort2 is created at DUT4 TgenPort2 {}".format(stream4, vars.T1D4P2))
    stream_dict["l2_4"] = [stream4]

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_v4"][1], vlan="enable",
                                             vlan_user_priority="2",mac_dst=evpn_dict["leaf2"]["tenant_mac_v4"][1],
                                             rate_pps=rate_pkts, mode='create',port_handle=tg_dict["d2_tg_ph1"],
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                             ip_src_addr=evpn_dict["leaf1"]["tenant_v4_ip"][0],ip_dscp="30",
                                             ip_dst_addr=evpn_dict["leaf2"]["tenant_v4_ip"][1],
                                             l3_protocol='ipv4',l3_length=l3_len,duration=duration,
                                             port_handle2=tg_dict["d3_tg_ph1"],
                                             mac_discovery_gw=evpn_dict["leaf2"]["tenant_v4_ip"][1])
    stream5 = stream['stream_id']
    st.log("L2 tagged with IPv4 header stream {} towards DUT3 TgenPort1 with DSCP value 30 is created at DUT2"
           " TgenPort1 {}".format(stream5,vars.T1D2P1))
    stream_dict["l2_5"] = [stream5]

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d2_tg_ph1"], mode='config',
                                 intf_ip_addr=evpn_dict["leaf1"]["tenant_v4_ip"][0],
                                 gateway=evpn_dict["leaf2"]["tenant_v4_ip"][1], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr=evpn_dict["leaf1"]["tenant_mac_v4"][1])
    host1 = han["handle"]
    han_dict["l2_host1"] = host1
    st.log("Tagged Ipv4 host {} for same network is created at DUT2 TgenPort1 {}".format(host1, vars.T1D2P1))

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf2"]["tenant_mac_v4"][1], vlan="enable",
                                  mac_dst=evpn_dict["leaf1"]["tenant_mac_v4"][1], rate_pps=rate_pkts, mode='create',
                                  port_handle=tg_dict["d3_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                                  ip_src_addr=evpn_dict["leaf2"]["tenant_v4_ip"][1],
                                  ip_dst_addr=evpn_dict["leaf1"]["tenant_v4_ip"][0],
                                  l3_protocol='ipv4',l3_length=l3_len,duration=duration,
                                             port_handle2=tg_dict["d2_tg_ph1"],
                                  mac_discovery_gw=evpn_dict["leaf1"]["tenant_v4_ip"][0])
    stream6 = stream['stream_id']
    st.log("L2 Tagged with IPv4 header stream {} towards DUT2 TgenPort1 with DSCP value 0 is created at DUT3"
           " TgenPort1 {}".format(stream6,vars.T1D3P1))
    stream_dict["l2_6"] = [stream6]

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d3_tg_ph1"], mode='config',
                                 intf_ip_addr=evpn_dict["leaf2"]["tenant_v4_ip"][1],
                                 gateway=evpn_dict["leaf1"]["tenant_v4_ip"][0], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr=evpn_dict["leaf2"]["tenant_mac_v4"][1])
    host2 = han["handle"]
    han_dict["l2_host2"] = host2
    st.log("Tagged Ipv4 host {} for same network is created at DUT3 TgenPort1 {}".format(host2, vars.T1D3P1))

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_v4_2"][1],
                                  mac_dst=evpn_dict["leaf3"]["tenant_mac_v4_2"][1], rate_pps=rate_pkts, mode='create',
                                  port_handle=tg_dict["d2_tg_ph2"],
                                  ip_src_addr=evpn_dict["leaf1"]["tenant_v4_ip_2"][0],
                                  ip_dst_addr=evpn_dict["leaf3"]["tenant_v4_ip_2"][1],
                                  l3_protocol='ipv4',l3_length=l3_len,duration=duration,ip_dscp="40",
                                  mac_discovery_gw=evpn_dict["leaf3"]["tenant_v4_ip_2"][1],
                                  port_handle2=tg_dict["d4_tg_ph2"])
    stream7 = stream['stream_id']
    st.log("Untagged L2 with IPv4 header stream {} towards DUT4 TgenPort2 with DSCP value 40 is created at DUT2 "
           "TgenPort2 {}".format(stream7,vars.T1D2P2))
    stream_dict["l2_7"] = [stream7]

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d2_tg_ph2"], mode='config',
                                 intf_ip_addr=evpn_dict["leaf1"]["tenant_v4_ip_2"][0],
                                 gateway=evpn_dict["leaf3"]["tenant_v4_ip_2"][1], arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr=evpn_dict["leaf1"]["tenant_mac_v4_2"][1])
    host3 = han["handle"]
    han_dict["l2_host3"] = host3
    st.log("Untagged Ipv4 host {} for same network is created at DUT2 TgenPort2 {}".format(host3, vars.T1D2P2))

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_v4_2"][1],
                                  mac_dst=evpn_dict["leaf1"]["tenant_mac_v4_2"][1], rate_pps=rate_pkts, mode='create',
                                  port_handle=tg_dict["d4_tg_ph2"],
                                  ip_src_addr=evpn_dict["leaf3"]["tenant_v4_ip_2"][1],
                                  ip_dst_addr=evpn_dict["leaf1"]["tenant_v4_ip_2"][0],
                                  l3_protocol='ipv4',l3_length=l3_len,duration=duration,
                                  mac_discovery_gw=evpn_dict["leaf1"]["tenant_v4_ip_2"][0],
                                  port_handle2=tg_dict["d2_tg_ph2"])
    stream8 = stream['stream_id']
    st.log("Untagged L2 with IPv4 header stream {} towards DUT2 TgenPort2 with DSCP value 0 is created at DUT4 "
           "TgenPort2 {}".format(stream8,vars.T1D4P2))
    stream_dict["l2_8"] = [stream8]

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d4_tg_ph2"], mode='config',
                                 intf_ip_addr=evpn_dict["leaf3"]["tenant_v4_ip_2"][1],
                                 gateway=evpn_dict["leaf1"]["tenant_v4_ip_2"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr=evpn_dict["leaf3"]["tenant_mac_v4_2"][1])
    host4 = han["handle"]
    han_dict["l2_host4"] = host4
    st.log("Untagged Ipv4 host {} for same network is created at DUT4 TgenPort2 {}".format(host4, vars.T1D4P2))

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_v6"][1], vlan="enable",
                                             vlan_user_priority="2",mac_dst=evpn_dict["leaf2"]["tenant_mac_v6"][1],
                                             rate_pps=rate_pkts, mode='create',port_handle=tg_dict["d2_tg_ph1"],
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                             ipv6_src_addr=evpn_dict["leaf1"]["tenant_v6_ip"][0],
                                             ipv6_dst_addr=evpn_dict["leaf2"]["tenant_v6_ip"][1],
                                             l3_protocol='ipv6',l3_length=l3_len,duration=duration,
                                             ipv6_traffic_class="120",port_handle2=tg_dict["d3_tg_ph1"],
                                             mac_discovery_gw=evpn_dict["leaf2"]["tenant_v6_ip"][1])
    stream9 = stream['stream_id']
    st.log("Tagged L2 with IPv6 header stream {} towards DUT3 TgenPort1 with TOS 120 is created at DUT2 "
           "TgenPort1 {}".format(stream9,vars.T1D2P1))
    stream_dict["l2_9"] = [stream9]

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d2_tg_ph1"], mode='config',
                                 ipv6_intf_addr=evpn_dict["leaf1"]["tenant_v6_ip"][0],
                                 ipv6_gateway=evpn_dict["leaf2"]["tenant_v6_ip"][1], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],arp_send_req='1',
                                 ipv6_gateway_step='0::1',ipv6_intf_addr_step='0::1', count=1,
                                 src_mac_addr=evpn_dict["leaf1"]["tenant_mac_v6"][1],ipv6_prefix_length='96')
    host5 = han["handle"]
    han_dict["l2_host5"] = host5
    st.log("Tagged Ipv6 host {} for same network is created at DUT2 TgenPort1 {}".format(host5, vars.T1D2P1))

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf2"]["tenant_mac_v6"][1], vlan="enable",
                                  mac_dst=evpn_dict["leaf1"]["tenant_mac_v6"][1], rate_pps=rate_pkts, mode='create',
                                  port_handle=tg_dict["d3_tg_ph1"], l2_encap='ethernet_ii_vlan',
                                  vlan_id=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                                  ipv6_src_addr=evpn_dict["leaf2"]["tenant_v6_ip"][1],
                                  ipv6_dst_addr=evpn_dict["leaf1"]["tenant_v6_ip"][0],
                                  l3_protocol='ipv6',l3_length=l3_len,duration=duration,
                                  mac_discovery_gw=evpn_dict["leaf1"]["tenant_v6_ip"][0],
                                  port_handle2=tg_dict["d2_tg_ph1"])
    stream10 = stream['stream_id']
    st.log("Tagged L2 with IPv6 header stream {} towards DUT2 TgenPort1 with TOS 0 is created at DUT3 "
           "TgenPort1 {}".format(stream10,vars.T1D3P1))
    stream_dict["l2_10"] = [stream10]

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d3_tg_ph1"], mode='config',
                                 ipv6_intf_addr=evpn_dict["leaf2"]["tenant_v6_ip"][1],
                                 ipv6_gateway=evpn_dict["leaf1"]["tenant_v6_ip"][0], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],arp_send_req='1',
                                 ipv6_gateway_step='0::1',ipv6_intf_addr_step='0::1', count=1,
                                 src_mac_addr=evpn_dict["leaf2"]["tenant_mac_v6"][1],ipv6_prefix_length='96')
    host6 = han["handle"]
    han_dict["l2_host6"] = host6
    st.log("Tagged Ipv6 host {} for same network is created at DUT3 TgenPort1 {}".format(host6, vars.T1D3P1))

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_v6_2"][1],
                                  mac_dst=evpn_dict["leaf3"]["tenant_mac_v6_2"][1], rate_pps=rate_pkts, mode='create',
                                  port_handle=tg_dict["d2_tg_ph2"], l2_encap='ethernet_ii',
                                  ipv6_src_addr=evpn_dict["leaf1"]["tenant_v6_ip_2"][0],
                                  ipv6_dst_addr=evpn_dict["leaf3"]["tenant_v6_ip_2"][1],
                                  l3_protocol='ipv6',l3_length=l3_len,duration=duration,ipv6_traffic_class="160",
                                  mac_discovery_gw=evpn_dict["leaf3"]["tenant_v6_ip_2"][1],
                                  port_handle2=tg_dict["d4_tg_ph2"])
    stream11 = stream['stream_id']
    st.log("Untagged L2 with IPv6 header stream {} towards DUT4 TgenPort2 with TOS 160 is created at DUT2"
           " TgenPort2 {}".format(stream11,vars.T1D2P2))
    stream_dict["l2_11"] = [stream11]

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d2_tg_ph2"], mode='config',
                                 ipv6_intf_addr=evpn_dict["leaf1"]["tenant_v6_ip_2"][0],
                                 ipv6_gateway=evpn_dict["leaf3"]["tenant_v6_ip_2"][1],arp_send_req='1',
                                 ipv6_gateway_step='0::1',ipv6_intf_addr_step='0::1', count=1,
                                 src_mac_addr=evpn_dict["leaf1"]["tenant_mac_v6_2"][1],ipv6_prefix_length='96')
    host7 = han["handle"]
    han_dict["l2_host7"] = host7
    st.log("Untagged Ipv6 host {} for same network is created at DUT2 TgenPort2 {}".format(host7, vars.T1D2P2))

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_v6_2"][1],
                                  mac_dst=evpn_dict["leaf1"]["tenant_mac_v6_2"][1], rate_pps=rate_pkts, mode='create',
                                  port_handle=tg_dict["d4_tg_ph2"], l2_encap='ethernet_ii',
                                  vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                                  ipv6_src_addr=evpn_dict["leaf3"]["tenant_v6_ip_2"][1],
                                  ipv6_dst_addr=evpn_dict["leaf1"]["tenant_v6_ip_2"][0],
                                  l3_protocol='ipv6',l3_length=l3_len,duration=duration,
                                  mac_discovery_gw=evpn_dict["leaf1"]["tenant_v6_ip_2"][0],
                                  port_handle2=tg_dict["d2_tg_ph2"])
    stream12 = stream['stream_id']
    st.log("Untagged L2 with IPv6 header stream {} towards DUT2 TgenPort2 with TOS 0 is created at DUT4 "
           "TgenPort2 {}".format(stream12,vars.T1D4P2))
    stream_dict["l2_12"] = [stream12]

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d4_tg_ph2"], mode='config',
                                 ipv6_intf_addr=evpn_dict["leaf3"]["tenant_v6_ip_2"][1],
                                 ipv6_gateway=evpn_dict["leaf1"]["tenant_v6_ip_2"][0], arp_send_req='1',
                                 ipv6_gateway_step='0::1',ipv6_intf_addr_step='0::1', count=1,
                                 src_mac_addr=evpn_dict["leaf3"]["tenant_mac_v6_2"][1],ipv6_prefix_length='96')
    host8 = han["handle"]
    han_dict["l2_host8"] = host8
    st.log("Untagged Ipv6 host {} for same network is created at DUT2 TgenPort2 {}".format(host8, vars.T1D4P2))

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_v4"][0],mac_dst=dut2_gateway_mac,
                                  rate_pps=rate_pkts, mode='create',port_handle=tg_dict["d2_tg_ph1"],
                                  l2_encap='ethernet_ii_vlan',
                                  ip_src_addr=evpn_dict["leaf1"]["tenant_v4_ip"][0],
                                  ip_dst_addr=evpn_dict["leaf2"]["tenant_v4_ip"][0],
                                  l3_protocol='ipv4',l3_length=l3_len,ip_dscp="32",
                                  vlan_id=evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], vlan="enable",
                                  mac_discovery_gw=evpn_dict["leaf1"]["l3_tenant_ip_list"][0],duration=duration,
                                  port_handle2=tg_dict["d3_tg_ph1"])
    stream13 = stream['stream_id']
    st.log("Tagged Ipv4 stream {} towards DUT3 TgenPort1 with DSCP value 32 is created at DUT2 "
           "TgenPort1 {}".format(stream13, vars.T1D2P1))
    stream_dict["v4_1"] = [stream13]

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d2_tg_ph1"], mode='config',
                                 intf_ip_addr=evpn_dict["leaf1"]["tenant_v4_ip"][0],
                                 gateway=evpn_dict["leaf1"]["l3_tenant_ip_list"][0], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr=evpn_dict["leaf1"]["tenant_mac_v4"][0])
    host9 = han["handle"]
    han_dict["v4_host1"] = host9
    st.log("Tagged Ipv4 host {} is created at DUT2 TgenPort1 {}".format(host9, vars.T1D2P1))

    stream=tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf2"]["tenant_mac_v4"][0],
                                           mac_dst=dut3_gateway_mac, rate_pps=rate_pkts, mode='create',
                                           port_handle=tg_dict["d3_tg_ph1"],l2_encap='ethernet_ii_vlan',
                                           ip_src_addr=evpn_dict["leaf2"]["tenant_v4_ip"][0],
                                           ip_dst_addr=evpn_dict["leaf1"]["tenant_v4_ip"][0],
                                           l3_protocol= 'ipv4',l3_length=l3_len,
                                           vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],vlan="enable",
                                           mac_discovery_gw=evpn_dict["leaf2"]["l3_tenant_ip_list"][0],
                                           duration=duration,port_handle2=tg_dict["d2_tg_ph1"])
    stream14 = stream['stream_id']
    st.log("Tagged Ipv4 stream {} towards DUT2 TgenPort1 with DSCP 0 is created at DUT3"
           " TgenPort1 {}".format(stream14, vars.T1D3P1))
    stream_dict["v4_2"] = [stream14]

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d3_tg_ph1"], mode='config',
                                 intf_ip_addr=evpn_dict["leaf2"]["tenant_v4_ip"][0],
                                 gateway=evpn_dict["leaf2"]["l3_tenant_ip_list"][0], vlan='1',vlan_id_step='0',
                                 vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr=evpn_dict["leaf2"]["tenant_mac_v4"][0])
    host10 = han["handle"]
    han_dict["v4_host2"] = host10
    st.log("Tagged Ipv4 host {} is created at DUT3 TgenPort1 {}".format(host10, vars.T1D3P1))

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d2_tg_ph2"], mode='config',
                                 intf_ip_addr=evpn_dict["leaf1"]["tenant_v4_ip_2"][0],
                                 gateway=evpn_dict["leaf1"]["l3_tenant_ip_list"][0],arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr=evpn_dict["leaf1"]["tenant_mac_v4_2"][0])
    host11 = han["handle"]
    han_dict["v4_host3"] = host11
    st.log("Untagged Ipv4 host {} is created at DUT2 TgenPort2 {}".format(host11, vars.T1D2P2))

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d4_tg_ph2"], mode='config',
                                 intf_ip_addr=evpn_dict["leaf3"]["tenant_v4_ip_2"][0],
                                 gateway=evpn_dict["leaf3"]["l3_tenant_ip_list"][0], arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr=evpn_dict["leaf3"]["tenant_mac_v4_2"][0])
    host12 = han["handle"]
    han_dict["v4_host4"] = host12
    st.log("Untagged Ipv4 host {} is created at DUT4 TgenPort2 {}".format(host12, vars.T1D4P2))

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d2_tg_ph1"], mode='config',
                                 ipv6_intf_addr=evpn_dict["leaf1"]["tenant_v6_ip"][0], ipv6_prefix_length='96',
                                 ipv6_gateway=evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0],
                                 src_mac_addr=evpn_dict["leaf1"]["tenant_mac_v6"][0],
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host13 = han["handle"]
    han_dict["v6_host1"] = host13
    st.log("Tagged Ipv6 host {} is created at DUT2 TgenPort1 {}".format(host13, vars.T1D2P1))

    stream=tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf2"]["tenant_mac_v6"][0],
                                           mac_dst=dut3_gateway_mac, rate_pps=rate_pkts, mode='create',
                                           port_handle=tg_dict["d3_tg_ph1"],l2_encap='ethernet_ii_vlan',
                                           ipv6_src_addr=evpn_dict["leaf2"]["tenant_v6_ip"][0],
                                           ipv6_dst_addr=evpn_dict["leaf1"]["tenant_v6_ip"][0],
                                           l3_protocol= 'ipv6',l3_length=l3_len,duration=duration,
                                           vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],vlan="enable",
                                           mac_discovery_gw=evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0],
                                           port_handle2=tg_dict["d2_tg_ph1"])
    stream18 = stream['stream_id']
    st.log("Tagged Ipv6 stream {} towards DUT2 TgenPort1 with TOS 0 is created at DUT3 "
           "TgenPort1 {}".format(stream18, vars.T1D3P1))
    stream_dict["v6_2"] = [stream18]

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d3_tg_ph1"], mode='config',
                                 ipv6_intf_addr=evpn_dict["leaf2"]["tenant_v6_ip"][0], ipv6_prefix_length='96',
                                 ipv6_gateway=evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0],
                                 src_mac_addr=evpn_dict["leaf2"]["tenant_mac_v6"][0],
                                 arp_send_req='1', vlan='1', vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                 vlan_id_step='0',count=1,ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host14 = han["handle"]
    han_dict["v6_host2"] = host14
    st.log("Tagged Ipv6 host {} is created at DUT3 TgenPort1 {}".format(host14, vars.T1D3P1))

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_v6_2"][0],
                                  mac_dst=dut2_gateway_mac, rate_pps=rate_pkts, mode='create',
                                  port_handle=tg_dict["d2_tg_ph2"],l2_encap='ethernet_ii',
                                  ipv6_src_addr=evpn_dict["leaf1"]["tenant_v6_ip_2"][0],
                                  ipv6_dst_addr=evpn_dict["leaf3"]["tenant_v6_ip_2"][0],
                                  l3_protocol='ipv6', l3_length=l3_len,duration=duration,
                                  mac_discovery_gw=evpn_dict["leaf1"]["l3_tenant_ipv6_list"][1],
                                  ipv6_traffic_class="80",port_handle2=tg_dict["d4_tg_ph2"])
    stream19 = stream['stream_id']
    st.log("Untagged Ipv6 stream {} towards DUT4 TgenPort2 with TOS 80 is created at DUT2 "
           "TgenPort2 {}".format(stream19, vars.T1D2P2))
    stream_dict["v6_3"] = [stream19]

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d2_tg_ph2"], mode='config',
                                 ipv6_intf_addr=evpn_dict["leaf1"]["tenant_v6_ip_2"][0], ipv6_prefix_length='96',
                                 ipv6_gateway=evpn_dict["leaf1"]["l3_tenant_ipv6_list"][1],
                                 src_mac_addr=evpn_dict["leaf1"]["tenant_mac_v6_2"][0],arp_send_req='1',
                                 count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host15 = han["handle"]
    han_dict["v6_host3"] = host15
    st.log("Untagged Ipv6 host {} is created at DUT2 TgenPort2 {}".format(host15, vars.T1D2P2))

    stream=tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_v6_2"][0],
                                           mac_dst=dut4_gateway_mac, rate_pps=rate_pkts, mode='create',
                                           port_handle=tg_dict["d4_tg_ph2"],l2_encap='ethernet_ii',duration=duration,
                                           ipv6_src_addr=evpn_dict["leaf3"]["tenant_v6_ip_2"][0],
                                           ipv6_dst_addr=evpn_dict["leaf1"]["tenant_v6_ip_2"][0],
                                           l3_protocol= 'ipv6',l3_length=l3_len,
                                           mac_discovery_gw=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][1],
                                           port_handle2=tg_dict["d2_tg_ph2"],ipv6_traffic_class="88")
    stream20 = stream['stream_id']
    st.log("Untagged Ipv6 stream {} towards DUT2 TgenPort2 with TOS 88 is created at DUT4 "
           "TgenPort2 {}".format(stream20, vars.T1D4P2))
    stream_dict["v6_4"] = [stream20]

    han = tg_dict["tg"].tg_interface_config(port_handle=tg_dict["d4_tg_ph2"], mode='config',
                                 ipv6_intf_addr=evpn_dict["leaf3"]["tenant_v6_ip_2"][0], ipv6_prefix_length='96',
                                 ipv6_gateway=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][1],
                                 src_mac_addr=evpn_dict["leaf3"]["tenant_mac_v6_2"][0],
                                 arp_send_req='1',count=1,ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host16 = han["handle"]
    han_dict["v6_host4"] = host16
    st.log("Untagged Ipv6 host {} is created at DUT4 TgenPort2 {}".format(host16, vars.T1D4P2))

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_l2"][0], vlan="enable",
                                             vlan_user_priority="2",mac_dst=evpn_dict["leaf2"]["tenant_mac_l2"][0],
                                             rate_pps=rate_pkts, mode='create',port_handle=tg_dict["d2_tg_ph1"],
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=600,vlan_id_count='3419',vlan_id_mode="increment",
                                             vlan_id_step='1',duration=duration,port_handle2=tg_dict["d3_tg_ph1"],
                                             high_speed_result_analysis=1,enable_stream_only_gen=0, enable_stream=0)
    stream23 = stream['stream_id']
    st.log("L2 tagged scale stream {} towards DUT3 TgenPort1 is created at DUT2 "
           "TgenPort1 {}".format(stream23,vars.T1D2P1))
    stream_dict["scale_1"] = [stream23]

    stream = tg_dict["tg"].tg_traffic_config(mac_src=evpn_dict["leaf2"]["tenant_mac_l2"][0], vlan="enable",
                                             vlan_user_priority="4",mac_dst=evpn_dict["leaf1"]["tenant_mac_l2"][0],
                                             rate_pps=rate_pkts, mode='create',port_handle=tg_dict["d3_tg_ph1"],
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=600,vlan_id_count='3419',vlan_id_mode="increment",
                                             vlan_id_step='1',duration=duration,port_handle2=tg_dict["d2_tg_ph1"],
                                             high_speed_result_analysis=1,enable_stream_only_gen=0, enable_stream=0)
    stream24 = stream['stream_id']
    st.log("L2 tagged scale stream {} towards DUT2 TgenPort1 is created at DUT3 "
           "TgenPort1 {}".format(stream24,vars.T1D3P1))
    stream_dict["scale_2"] = [stream24]
    stream=tg_dict["tg"].tg_traffic_config(port_handle=tg_dict["d2_tg_ph1"], mode='create',vlan="enable",
                                l2_encap='ethernet_ii_vlan',vlan_id=evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                         mac_src=evpn_dict["leaf1"]["tenant_mac_v4"][0],mac_dst=dut2_gateway_mac,
                         rate_pps=rate_pkts, l3_protocol='ipv4',port_handle2=tg_dict["d3_tg_ph1"],
                         ip_src_addr=evpn_dict["leaf1"]["tenant_v4_ip"][0],
                                ip_dst_addr=evpn_dict["leaf2"]["tenant_v4_ip"][0],
                         l4_protocol="icmp",icmp_type="8",icmp_code="0",ip_dscp="46",
                                mac_discovery_gw=evpn_dict["leaf1"]["l3_tenant_ip_list"][0] ,duration="5")
    stream25 = stream["stream_id"]
    st.log("######## stream {} for pingv4 request is created at DUT2 TgenPort1 ########".format(stream25))
    stream_dict["v4ping_1"] = [stream25]

    stream=tg_dict["tg"].tg_traffic_config(port_handle=tg_dict["d3_tg_ph1"], mode='create',
                         mac_src=evpn_dict["leaf2"]["tenant_mac_v6"][0],mac_dst=dut3_gateway_mac,
                         rate_pps=rate_pkts, l3_protocol='ipv6',l2_encap='ethernet_ii_vlan',
                         vlan_id=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],vlan="enable",
                         ipv6_src_addr=evpn_dict["leaf2"]["tenant_v6_ip"][0],port_handle2=tg_dict["d2_tg_ph1"],
                                ipv6_dst_addr=evpn_dict["leaf1"]["tenant_v6_ip"][0],
                         ipv6_traffic_class="192",l4_protocol="icmp",icmpv6_type="128",
                         icmpv6_code="0",duration="5",mac_discovery_gw=evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0])
    stream26 = stream["stream_id"]
    st.log("######## stream {} for pingv6 is created at DUT3 TgenPort1########".format(stream26))
    stream_dict["v6ping_1"] = [stream26]
    stream=tg_dict["tg"].tg_traffic_config(port_handle=tg_dict["d2_tg_ph1"],
                                           mac_src=evpn_dict["leaf1"]["tenant_mac_v4"][0],
                         mac_dst="ff:ff:ff:ff:ff:ff",rate_pps=rate_pkts, mode='create', l2_encap='ethernet_ii_vlan',
                         transmit_mode='continuous',l3_protocol='arp',vlan="enable",
                         vlan_id=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],vlan_user_priority="2",
                         arp_src_hw_addr=evpn_dict["leaf1"]["tenant_mac_v4"][0], arp_dst_hw_addr="00:00:00:00:00:00",
                         arp_operation='arpRequest', ip_src_addr=evpn_dict["leaf1"]["tenant_v4_ip"][0],
                         ip_dst_addr=evpn_dict["leaf2"]["tenant_v4_ip"][1],duration="5")
    stream27=stream["stream_id"]
    st.log("######## stream {} for ARP request is created for port {} ########".format(stream27,vars.T1D2P1))
    stream_dict["arp"] = [stream27]
    stream=tg_dict["tg"].tg_traffic_config(port_handle=tg_dict["d3_tg_ph1"], mode='create',
                         mac_src=evpn_dict["leaf2"]["tenant_mac_v6_2"][0],mac_dst="ff:ff:ff:ff:ff:ff",
                         rate_pps=rate_pkts,transmit_mode='continuous', l3_protocol='ipv6',
                         ipv6_src_addr=evpn_dict["leaf2"]["tenant_v6_ip_2"][0],ipv6_dst_addr="ff02::1",
                         ipv6_traffic_class="64",l4_protocol="icmp",icmpv6_type="136",
                         icmpv6_target_address=evpn_dict["leaf1"]["tenant_v6_ip_2"][1],
                         l2_encap='ethernet_ii_vlan',vlan_id=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],duration="5")
    stream28 = stream["stream_id"]
    st.log("######## stream {} for ND solicitation with TOS 64 is created for DUT3 "
           "Tgenport1 {} ########".format(stream28,vars.T1D3P1))
    stream_dict["nd"] = [stream28]

    stream = tg_dict["tg"].tg_traffic_config(port_handle=tg_dict["d3_tg_ph1"], mode='create',
                                  mac_src=evpn_dict["leaf2"]["tenant_mac_v6_2"][1], mac_dst="ff:ff:ff:ff:ff:ff",
                                  rate_pps=rate_pkts, transmit_mode='continuous', l3_protocol='ipv6',
                                  ipv6_src_addr=evpn_dict["leaf2"]["tenant_v6_ip_2"][0], ipv6_dst_addr="ff02::1",
                                  ipv6_traffic_class="144", l4_protocol="icmp", icmpv6_type="136",
                                  icmpv6_target_address=evpn_dict["leaf1"]["tenant_v6_ip_2"][1],
                                  l2_encap='ethernet_ii_vlan',vlan_id=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],duration="5")
    stream29 = stream["stream_id"]
    st.log("######## stream {} for ND solicitation with TOS 144 is created for DUT3 "
           "Tgenport1 {} ########".format(stream29,vars.T1D3P1))
    stream_dict["nd_2"] = [stream29]


def start_traffic(stream_han_list=[],port_han_list=[],action="run"):
    if action=="run":
        if tg_dict["tg"].tg_type == 'stc':
            tg_dict["tg"].tg_traffic_control(action="run", stream_handle=stream_han_list,duration="5")
        else:
            tg_dict["tg"].tg_traffic_control(action="run", stream_handle=stream_han_list)
    else:
        if port_han_list:
            tg_dict["tg"].tg_traffic_control(action="stop", port_handle=port_han_list)
        else:
            tg_dict["tg"].tg_traffic_control(action="stop", stream_handle=stream_han_list)


def clear_stats(port_han_list=[]):
    if port_han_list:
        tg_dict["tg"].tg_traffic_control(action='clear_stats',port_handle=port_han_list)
    else:
        tg_dict["tg"].tg_traffic_control(action='clear_stats',port_handle=[d5_tg_ph1,d6_tg_ph1])


def verify_traffic(tx_port="", rx_port="", tx_ratio=1, rx_ratio=1,
                       mode="streamblock", field="packet_count", **kwargs):
    '''
    :param tx_port:
    :param rx_port:
    :param tx_ratio:
    :param rx_ratio:
    :param mode:
    :param field:
    :param kwargs["tx_stream_list"]:
    :param kwargs["rx_stream_list"]:
    :return:
    '''

    if not tx_port:
        tx_port=tg_dict["d2_tg_port1"]
    if not rx_port:
        rx_port=tg_dict["d3_tg_port1"]

    traffic_details = {
            '1': {
                'tx_ports': [tx_port],
                'tx_obj': [tg_dict["tg"]],
                'exp_ratio': [tx_ratio],
                'rx_ports': [rx_port],
                'rx_obj': [tg_dict["tg"]],
                'stream_list': [tuple(kwargs["tx_stream_list"])]
            },
            '2': {
                'tx_ports': [rx_port],
                'tx_obj': [tg_dict["tg"]],
                'exp_ratio': [rx_ratio],
                'rx_ports': [tx_port],
                'rx_obj': [tg_dict["tg"]],
                'stream_list': [tuple(kwargs["rx_stream_list"])]
            }
    }

    return tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode=mode, comp_type=field, tolerance_factor=1)


def reset_tgen(port_han_list=[]):
    if port_han_list:
        tg_dict["tg"].tg_traffic_control(action="reset", port_handle=port_han_list)
    else:
        tg_dict["tg"].tg_traffic_control(action="reset", port_handle=[d5_tg_ph1,d6_tg_ph1])


def spine_setup_5549():

    st.log("create port channel interface b/w spine and all leaf nodes")
    for portchannel in [evpn_dict["spine1"]["pch_intf_list"][0],evpn_dict["spine1"]["pch_intf_list"][1],
                        evpn_dict["spine1"]["pch_intf_list"][2]]:
        pch.create_portchannel(dut=evpn_dict["spine_node_list"][0],portchannel_list=portchannel)

    st.log("Add members to port channel created b/w spine and all leaf nodes")
    for portchannel,member in zip([evpn_dict["spine1"]["pch_intf_list"][0],evpn_dict["spine1"]["pch_intf_list"][1],
                                   evpn_dict["spine1"]["pch_intf_list"][2]],
                                  [evpn_dict["spine1"]["intf_list_leaf"][1:3],
                                   evpn_dict["spine1"]["intf_list_leaf"][5:7],
                                   evpn_dict["spine1"]["intf_list_leaf"][9:11]]):
        pch.add_portchannel_member(dut=evpn_dict["spine_node_list"][0],portchannel=portchannel,members=member)

    st.log("Enable portchannel interface b/w spine and all leaf nodes")
    Intf.interface_operation(dut=evpn_dict["spine_node_list"][0],
                             interfaces=evpn_dict["spine1"]["pch_intf_list"], operation="startup")

    ############################################################################################
    hdrMsg("\n####### Configure IPv6 link local address for link1 b/w spine and all leaf ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["spine_node_list"][0],
                                       interface_list=[evpn_dict["spine1"]["intf_list_leaf"][0],
                                                       evpn_dict["spine1"]["intf_list_leaf"][4],
                                                       evpn_dict["spine1"]["intf_list_leaf"][8]])

    ############################################################################################
    hdrMsg("\n########## Configure IPv6 link local address for LAG(link 2 & 3) b/w spine and all leaf#############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["spine_node_list"][0],
                                       interface_list=evpn_dict["spine1"]["pch_intf_list"])

    ############################################################################################
    hdrMsg("\n####### Configure IPv6 address for link4 b/w spine and all leaf ##############\n")
    ############################################################################################
    for interface,ipv6 in zip([evpn_dict["spine1"]["intf_list_leaf"][3],evpn_dict["spine1"]["intf_list_leaf"][7],
                               evpn_dict["spine1"]["intf_list_leaf"][11]],
                              [evpn_dict["spine1"]["intf_ipv6_list"][0],evpn_dict["spine1"]["intf_ipv6_list"][1],
                               evpn_dict["spine1"]["intf_ipv6_list"][2]]):
        ip.config_ip_addr_interface(dut=evpn_dict["spine_node_list"][0],interface_name=interface,ip_address=ipv6,
                                    subnet="127",family='ipv6')

    ############################################################################################
    hdrMsg("\n########## Enable router bgp and configure router id in DUT1 node ##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["bgp_node_list"][0],local_as=evpn_dict["spine1"]["local_as"],
                   router_id=evpn_dict["spine1"]["loop_ip_list"][1],config="yes",
                   config_type_list=['router_id',"multipath-relax"])

    spine_link_list = [evpn_dict["spine1"]["intf_list_leaf"][0], evpn_dict["spine1"]["pch_intf_list"][0],
                       evpn_dict["spine1"]["intf_list_leaf"][3], evpn_dict["spine1"]["intf_list_leaf"][4],
                       evpn_dict["spine1"]["pch_intf_list"][1], evpn_dict["spine1"]["intf_list_leaf"][7],
                       evpn_dict["spine1"]["intf_list_leaf"][8], evpn_dict["spine1"]["pch_intf_list"][2],
                       evpn_dict["spine1"]["intf_list_leaf"][11]]
    for link1 in spine_link_list:
        Bgp.config_bgp(dut=evpn_dict["bgp_node_list"][0], local_as=evpn_dict["spine1"]["local_as"],config='yes',
                           config_type_list=["neighbor"], remote_as='external', neighbor=link1)
        Evpn.config_bgp_evpn(dut=evpn_dict["bgp_node_list"][0],local_as=evpn_dict["spine1"]["local_as"], config='yes',
                             config_type_list=["activate"],remote_as='external',neighbor=link1)

    Evpn.config_bgp_evpn(dut=evpn_dict["bgp_node_list"][0], local_as=evpn_dict["spine1"]["local_as"], config='yes',
                         config_type_list=["advertise_all_vni"])

    ############################################################################################
    hdrMsg(" \n####### Configure loopback interface in DUT1 ##############\n")
    ############################################################################################
    ip.configure_loopback(dut=evpn_dict["spine_node_list"][0],loopback_name='Loopback1', config='yes')
    ip.config_ip_addr_interface(dut=evpn_dict["bgp_node_list"][0],interface_name='Loopback1',
                                ip_address=evpn_dict["spine1"]["loop_ip_list"][1],subnet=32)

    ############################################################################################
    hdrMsg(" \n####### Redistribute connected route in to bgp in DUT1 ##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["spine_node_list"][0],local_as=evpn_dict["spine1"]["local_as"],
                   config_type_list=['redist'],redistribute='connected')


def leaf1_setup_5549():
    st.log("create port channel interface b/w leaf1 and spine nodes")
    pch.create_portchannel(dut=evpn_dict["leaf_node_list"][0],portchannel_list=evpn_dict["leaf1"]["pch_intf_list"][0])

    st.log("Add members to port channel created b/w leaf1 and spine nodes")
    pch.add_portchannel_member(dut=evpn_dict["leaf_node_list"][0],portchannel=evpn_dict["leaf1"]["pch_intf_list"][0],
                               members=evpn_dict["leaf1"]["intf_list_spine"][1:3])

    st.log("Enable portchannel interface on all leaf1 and spine nodes")
    Intf.interface_operation(dut=evpn_dict["leaf_node_list"][0],
                             interfaces=evpn_dict["leaf1"]["pch_intf_list"], operation="startup")

    ############################################################################################
    hdrMsg("\n####### Configure IPv6 link local address for link1 b/w leaf1 and spine ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["leaf_node_list"][0],
                                       interface_list=[evpn_dict["leaf1"]["intf_list_spine"][0]])

    ############################################################################################
    hdrMsg("\n########## Configure IPv6 link local address for LAG(link 2 & 3) b/w leaf1 and spine ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["leaf_node_list"][0],
                                       interface_list=evpn_dict["leaf1"]["pch_intf_list"])

    ############################################################################################
    hdrMsg("\n####### Configure IPv6 address for link4 b/w leaf1 and spine ##############\n")
    ############################################################################################
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name=evpn_dict["leaf1"]["intf_list_spine"][3],
                                ip_address=evpn_dict["leaf1"]["intf_ipv6_list"][0],subnet="127",family='ipv6')

    ############################################################################################
    hdrMsg("\n########## Enable router bgp and configure router id in DUT2 ##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0],local_as=evpn_dict["leaf1"]["local_as"],
                   router_id=evpn_dict["leaf1"]["loop_ip_list"][1],config="yes",
                   config_type_list=['router_id',"multipath-relax"])

    for link1 in [evpn_dict["leaf1"]["intf_list_spine"][0], evpn_dict["leaf1"]["pch_intf_list"][0],
                  evpn_dict["leaf1"]["intf_list_spine"][3]]:
        Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0], local_as=evpn_dict["leaf1"]["local_as"],config='yes',
                           config_type_list=["neighbor"], remote_as='external', neighbor=link1)
        Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][0],local_as=evpn_dict["leaf1"]["local_as"], config='yes',
                             config_type_list=["activate"],remote_as='external',neighbor=link1)

    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][0], local_as=evpn_dict["leaf1"]["local_as"], config='yes',
                         config_type_list=["advertise_all_vni"])

    ############################################################################################
    hdrMsg(" \n####### Configure loopback interface in DUT2##############\n")
    ############################################################################################
    ip.configure_loopback(dut=evpn_dict["leaf_node_list"][0],loopback_name='Loopback1', config='yes')
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],interface_name='Loopback1',
                                ip_address=evpn_dict["leaf1"]["loop_ip_list"][1],subnet=32)

    ############################################################################################
    hdrMsg(" \n####### Redistribute connected route in to bgp in DUT2##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0],local_as=evpn_dict["leaf1"]["local_as"],
                   config_type_list=['redist'],redistribute='connected')


def leaf2_setup_5549():
    st.log("create port channel interface b/w leaf2 and spine nodes")
    pch.create_portchannel(dut=evpn_dict["leaf_node_list"][1],portchannel_list=evpn_dict["leaf2"]["pch_intf_list"][0])

    st.log("Add members to port channel created b/w leaf2 and spine nodes")
    pch.add_portchannel_member(dut=evpn_dict["leaf_node_list"][1],portchannel=evpn_dict["leaf2"]["pch_intf_list"][0],
                               members=evpn_dict["leaf2"]["intf_list_spine"][1:3])

    st.log("Enable portchannel interface on all leaf2 and spine nodes")
    Intf.interface_operation(dut=evpn_dict["leaf_node_list"][1],
                             interfaces=evpn_dict["leaf2"]["pch_intf_list"], operation="startup")

    ############################################################################################
    hdrMsg("\n####### Configure IPv6 link local address for link1 b/w leaf2 and spine ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["leaf_node_list"][1],
                                       interface_list=[evpn_dict["leaf2"]["intf_list_spine"][0]])

    ############################################################################################
    hdrMsg("\n########## Configure IPv6 link local address for LAG(link 2 & 3) b/w leaf2 and spine ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["leaf_node_list"][1],
                                       interface_list=evpn_dict["leaf2"]["pch_intf_list"])

    ############################################################################################
    hdrMsg("\n####### Configure IPv6 address for link4 b/w leaf2 and spine ##############\n")
    ############################################################################################
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][1],
                                interface_name=evpn_dict["leaf2"]["intf_list_spine"][3],
                                ip_address=evpn_dict["leaf2"]["intf_ipv6_list"][0],subnet="127",family='ipv6')

    ############################################################################################
    hdrMsg("\n########## Enable router bgp and configure router id in DUT3##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1],local_as=evpn_dict["leaf2"]["local_as"],
                   router_id=evpn_dict["leaf2"]["loop_ip_list"][1],config="yes",
                   config_type_list=['router_id',"multipath-relax"])

    for link1 in [evpn_dict["leaf2"]["intf_list_spine"][0], evpn_dict["leaf2"]["pch_intf_list"][0],
                  evpn_dict["leaf2"]["intf_list_spine"][3]]:
        Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1], local_as=evpn_dict["leaf2"]["local_as"],config='yes',
                           config_type_list=["neighbor"], remote_as='external', neighbor=link1)
        Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][1],local_as=evpn_dict["leaf2"]["local_as"], config='yes',
                             config_type_list=["activate"],remote_as='external',neighbor=link1)

    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][1], local_as=evpn_dict["leaf2"]["local_as"], config='yes',
                         config_type_list=["advertise_all_vni"])

    ############################################################################################
    hdrMsg(" \n####### Configure loopback interface in DUT3##############\n")
    ############################################################################################
    ip.configure_loopback(dut=evpn_dict["leaf_node_list"][1],loopback_name='Loopback1', config='yes')
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][1],interface_name='Loopback1',
                                ip_address=evpn_dict["leaf2"]["loop_ip_list"][1],subnet=32)

    ############################################################################################
    hdrMsg(" \n####### Redistribute connected route in to bgp in DUT3##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1],local_as=evpn_dict["leaf2"]["local_as"],
                   config_type_list=['redist'],redistribute='connected')


def leaf3_setup_5549():
    st.log("create port channel interface b/w leaf3 and spine nodes")
    pch.create_portchannel(dut=evpn_dict["leaf_node_list"][2],portchannel_list=evpn_dict["leaf3"]["pch_intf_list"][0])

    st.log("Add members to port channel created b/w leaf3 and spine nodes")
    pch.add_portchannel_member(dut=evpn_dict["leaf_node_list"][2],portchannel=evpn_dict["leaf3"]["pch_intf_list"][0],
                               members=evpn_dict["leaf3"]["intf_list_spine"][1:3])

    st.log("Enable portchannel interface b/w leaf3 and spine nodes")
    Intf.interface_operation(dut=evpn_dict["leaf_node_list"][2],
                             interfaces=evpn_dict["leaf3"]["pch_intf_list"], operation="startup")

    ############################################################################################
    hdrMsg("\n####### Configure IPv6 link local address for link1 b/w leaf3 and spine ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["leaf_node_list"][2],
                                       interface_list=[evpn_dict["leaf3"]["intf_list_spine"][0]])

    ############################################################################################
    hdrMsg("\n########## Configure IPv6 link local address for LAG(link 2 & 3) b/w leaf3 and spine ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["leaf_node_list"][2],
                                       interface_list=evpn_dict["leaf3"]["pch_intf_list"])

    ############################################################################################
    hdrMsg("\n####### Configure IPv6 address for link4 b/w leaf3 and spine ##############\n")
    ############################################################################################
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],
                                interface_name=evpn_dict["leaf3"]["intf_list_spine"][3],
                                ip_address=evpn_dict["leaf3"]["intf_ipv6_list"][0],subnet="127",family='ipv6')

    ############################################################################################
    hdrMsg("\n########## Enable router bgp and configure router id in DUT4##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict["leaf3"]["local_as"],
                   router_id=evpn_dict["leaf3"]["loop_ip_list"][1],config="yes",
                   config_type_list=['router_id',"multipath-relax"])

    for link1 in [evpn_dict["leaf3"]["intf_list_spine"][0], evpn_dict["leaf3"]["pch_intf_list"][0],
                  evpn_dict["leaf3"]["intf_list_spine"][3]]:
        Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2], local_as=evpn_dict["leaf3"]["local_as"],config='yes',
                           config_type_list=["neighbor"], remote_as='external', neighbor=link1)
        Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict["leaf3"]["local_as"], config='yes',
                             config_type_list=["activate"],remote_as='external',neighbor=link1)

    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], local_as=evpn_dict["leaf3"]["local_as"], config='yes',
                         config_type_list=["advertise_all_vni"])

    ############################################################################################
    hdrMsg(" \n####### Configure loopback interface in DUT4##############\n")
    ############################################################################################
    ip.configure_loopback(dut=evpn_dict["leaf_node_list"][2],loopback_name='Loopback1', config='yes')
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],interface_name='Loopback1',
                                ip_address=evpn_dict["leaf3"]["loop_ip_list"][1],subnet=32)

    ############################################################################################
    hdrMsg(" \n####### Redistribute connected route in to bgp in DUT4##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict["leaf3"]["local_as"],
                   config_type_list=['redist'],redistribute='connected')


def cleanup_evpn_5549():
    global vars
    vars = st.get_testbed_vars()

    dict1 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no'}
    parallel.exec_parallel(True, evpn_dict["bgp_node_list"],
                           Bgp.config_bgp, [dict1, dict1, dict1, dict1,dict1,dict1])

    ############################################################################################
    hdrMsg("\n####### Unconfigure IP address of first link b/w spine and leaf nodes ##############\n")
    ############################################################################################
    st.exec_all([[ip.config_interface_ip6_link_local, vars.D1,
                           [evpn_dict["spine1"]["intf_list_leaf"][0],evpn_dict["spine1"]["intf_list_leaf"][4],
                            evpn_dict["spine1"]["intf_list_leaf"][8]],'disable'],
                          [ip.config_interface_ip6_link_local, vars.D2,
                           evpn_dict["leaf1"]["intf_list_spine"][0], 'disable'],
                          [ip.config_interface_ip6_link_local, vars.D3,
                           evpn_dict["leaf2"]["intf_list_spine"][0], 'disable'],
                          [ip.config_interface_ip6_link_local, vars.D4,
                           evpn_dict["leaf3"]["intf_list_spine"][0], 'disable']])

    ############################################################################################
    hdrMsg("\n########## Unconfigure IP address of LAG(link2 and link3) b/w spine and leaf nodes ##############\n")
    ############################################################################################
    st.exec_all([[ip.config_interface_ip6_link_local, vars.D1,
                           evpn_dict["spine1"]["pch_intf_list"], 'disable'],
                          [ip.config_interface_ip6_link_local, vars.D2,
                           evpn_dict["leaf1"]["pch_intf_list"] , 'disable'],
                          [ip.config_interface_ip6_link_local, vars.D3,
                           evpn_dict["leaf2"]["pch_intf_list"] , 'disable'],
                          [ip.config_interface_ip6_link_local, vars.D4,
                           evpn_dict["leaf3"]["pch_intf_list"] , 'disable']])

    ############################################################################################
    hdrMsg("\n####### Unconfigure IP address of link4 b/w spine and leaf nodes ##############\n")
    ############################################################################################
    st.exec_all([
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][0],
         evpn_dict["leaf1"]["intf_list_spine"][3], evpn_dict["leaf1"]["intf_ipv6_list"][0], "127", 'ipv6'],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][1],
         evpn_dict["leaf2"]["intf_list_spine"][3], evpn_dict["leaf2"]["intf_ipv6_list"][0], "127", 'ipv6'],
        [ip.delete_ip_interface, evpn_dict["leaf_node_list"][2],
         evpn_dict["leaf3"]["intf_list_spine"][3], evpn_dict["leaf3"]["intf_ipv6_list"][0], "127", 'ipv6'],
        [ip.delete_ip_interface, evpn_dict["spine_node_list"][0],
         evpn_dict["spine1"]["intf_list_leaf"][3], evpn_dict["spine1"]["intf_ipv6_list"][0], "127", 'ipv6']])

    for i,j in zip([7,11],[1,2]):
        ip.delete_ip_interface(evpn_dict["spine_node_list"][0],evpn_dict["spine1"]["intf_list_leaf"][i],
                               evpn_dict["spine1"]["intf_ipv6_list"][j], "127", 'ipv6')

    ############################################################################################
    hdrMsg("\n########## Delete Port-channel and portchannel members ############\n")
    ############################################################################################
    utils.exec_all(True,
                   [[pch.delete_portchannel_member, evpn_dict["leaf_node_list"][0],
                     evpn_dict["leaf1"]["pch_intf_list"][0], evpn_dict["leaf1"]["intf_list_spine"][1:3]],
                    [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][1],
                     evpn_dict["leaf2"]["pch_intf_list"][0], evpn_dict["leaf2"]["intf_list_spine"][1:3]],
                    [pch.delete_portchannel_member, evpn_dict["leaf_node_list"][2],
                     evpn_dict["leaf3"]["pch_intf_list"][0], evpn_dict["leaf3"]["intf_list_spine"][1:3]],
                    [pch.delete_portchannel_member, evpn_dict["spine_node_list"][0],
                     evpn_dict["spine1"]["pch_intf_list"][0],evpn_dict["spine1"]["intf_list_leaf"][1:3]]])

    for pintf, intf in zip([evpn_dict["spine1"]["pch_intf_list"][1], evpn_dict["spine1"]["pch_intf_list"][2]],
                         [evpn_dict["spine1"]["intf_list_leaf"][5:7], evpn_dict["spine1"]["intf_list_leaf"][9:11]]):
        pch.delete_portchannel_member(evpn_dict["spine_node_list"][0], pintf, intf)

    st.exec_all([[pch.delete_portchannel, evpn_dict["leaf_node_list"][0],
                           evpn_dict["leaf1"]["pch_intf_list"][0]],
                          [pch.delete_portchannel, evpn_dict["leaf_node_list"][1],
                           evpn_dict["leaf2"]["pch_intf_list"][0]],
                          [pch.delete_portchannel, evpn_dict["leaf_node_list"][2],
                           evpn_dict["leaf3"]["pch_intf_list"][0]],
                          [pch.delete_portchannel, evpn_dict["spine_node_list"][0],
                           evpn_dict["spine1"]["pch_intf_list"][0]]])
    for pintf in [evpn_dict["spine1"]["pch_intf_list"][1],evpn_dict["spine1"]["pch_intf_list"][2]]:
        pch.delete_portchannel(evpn_dict["spine_node_list"][0],pintf)

    ############################################################################################
    hdrMsg(" \n########### Unconfigure loopback interface ##############\n")
    ############################################################################################
    utils.exec_all(True,
                   [[ip.delete_ip_interface, vars.D1, 'Loopback1',
                     evpn_dict["spine1"]["loop_ip_list"][1] , 32, 'ipv4'],
                    [ip.delete_ip_interface, vars.D2, 'Loopback1',
                     evpn_dict["leaf1"]["loop_ip_list"][1], 32, 'ipv4'],
                    [ip.delete_ip_interface, vars.D3, 'Loopback1',
                     evpn_dict["leaf2"]["loop_ip_list"][1], 32, 'ipv4'],
                    [ip.delete_ip_interface, vars.D4, 'Loopback1',
                     evpn_dict["leaf3"]["loop_ip_list"][1] , 32, 'ipv4']])

    input25 = {'loopback_name': 'Loopback1', 'config': 'no'}
    parallel.exec_parallel(True, evpn_dict["bgp_node_list"], ip.configure_loopback,
                           [input25,input25,input25,input25,input25,input25])


def create_evpn_5549_config():
    st.exec_all([[spine_setup_5549], [leaf1_setup_5549], [leaf2_setup_5549], [leaf3_setup_5549]])
    st.exec_all([[leaf1_setup_vxlan], [leaf2_setup_vxlan], [leaf3_setup_vxlan]])
    st.exec_all([[leaf1_setup_l2vni], [leaf2_setup_l2vni], [leaf3_setup_l2vni]])
    st.exec_all([[leaf1_setup_l3vni], [leaf2_setup_l3vni], [leaf3_setup_l3vni]])


def apply_acl_config(dut, config):
    json_config = json.dumps(config)
    json.loads(json_config)
    st.apply_json2(dut, json_config)


def verify_queuing(dut,port_list,queue,val_list=["3000"],tol_list=["2500"]):
    success = True
    for port in port_list:
        fil_out= Intf.show_queue_counters(dut, port, queue)
        if not fil_out:
            st.error('port: {} and queue name: {} not found in output: {}'.format(port,queue,fil_out))
            return False

        # avoid lint issue
        if not val_list or not tol_list:
            st.error('invalid val_list {} or tol_list {}'.format(val_list, tol_list))
            return False
        param,val,tol = ['pkts_count',val_list[0],tol_list[0]]

        fil_out = fil_out[0]
        for param,val,tol in zip(['pkts_count'],val_list,tol_list):
            try:
                fil_out[param] = re.sub(",","",fil_out[param])
                int(fil_out[param])
            except ValueError:
                st.error('cannot get integer value from obtained string: {}'.format(fil_out[param]))
                return False

        if int(fil_out[param])<=int(val)+int(tol) and int(fil_out[param])>=int(val)-int(tol):
            st.log('obtained value: {} is in the range b/w {} and {} as expected for param: {}'
                   'in queue: {}'.format(int(fil_out[param]),int(val)-int(tol),
                    int(val)+int(tol),param,queue))
            return True

        st.error('obtained value: {} is NOT in the range b/w {} and {} for param: {}'
                 'in queue: {}'.format(int(fil_out[param]), int(val) - int(tol),
                                int(val) + int(tol), param, queue))
        success = False
    return True if success else False


def clear_intf_counters():
    global vars
    st.log("Clearing interface counters on all DUTs\n")
    input1={"confirm" : "y"}
    parallel.exec_parallel(True, [vars.D1,vars.D2,vars.D3,vars.D4], Intf.clear_interface_counters,
                           [input1,input1,input1,input1])

def debug_traffic():
    global vars
    ############################################################################################
    hdrMsg(" \n######### Start debug commands for traffic failure ##########\n")
    ############################################################################################
    utils.exec_all(True, [[Intf.show_interface_counters_all,vars.D1],[Intf.show_interface_counters_all,vars.D2],
                          [Intf.show_interface_counters_all,vars.D3],[Intf.show_interface_counters_all,vars.D4]])
    utils.exec_all(True, [[asicapi.bcmcmd_l3_defip_show,vars.D1],[asicapi.bcmcmd_l3_defip_show,vars.D2],
                          [asicapi.bcmcmd_l3_defip_show,vars.D3],[asicapi.bcmcmd_l3_defip_show,vars.D4]])
    utils.exec_all(True, [[asicapi.bcm_cmd_l3_intf_show,vars.D1],[asicapi.bcm_cmd_l3_intf_show,vars.D2],
                          [asicapi.bcm_cmd_l3_intf_show,vars.D3],[asicapi.bcm_cmd_l3_intf_show,vars.D4]])
    ############################################################################################
    hdrMsg(" \n######### END debug commands for traffic failure ##########\n")
    ############################################################################################