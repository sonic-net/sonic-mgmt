from spytest.dicts import SpyTestDict
from spytest import st, tgapi
import apis.routing.evpn as Evpn
import apis.switching.vlan as Vlan
import apis.switching.portchannel as pch
import apis.system.interface as Intf
import apis.routing.bgp as Bgp
import apis.routing.ip as ip
import apis.routing.vrf as vrf
from apis.system import basic
import apis.routing.sag as sag
import apis.switching.mclag as mclag
from tabulate import tabulate
import apis.system.port as port_api
from utilities.utils import retry_api
import apis.switching.mclag as mc_lag
import apis.routing.ospf as ospf
import apis.routing.bfd as bfd
import apis.routing.route_map as rmap_api


data = SpyTestDict()
data.l2vni = '400'
data.ipv4_routes = 20000
data.ipv6_routes = 4000
data.ipv4_routes_per_port = data.ipv4_routes/2
data.ipv6_routes_per_port = data.ipv6_routes/2

d5_tg_ph1,d6_tg_ph1 = None, None

evpn_dict = {"leaf1" : {"intf_ipv6_list" : ["1001:3::0","1002:3::0"],
                        "loop_ip_list" : ["33.33.33.33","3.3.3.2"], "local_as" : "300",
                        "tenant_l2_vlan_list" : ["100","101","102"], "vlan_list" : ["13","23"],
                        "rem_as_list" : ["100","200","600"], "ve_intf_list" : ["Vlan13","Vlan23"],
                        "pch_intf_list" : ["PortChannel13","PortChannel23"],
                        "l3_vni_list": ["500", "501", "502"],
                        "tenant_l3_vlan_list": ["300", "301", "302"],
                        "l3_vni_name_list": ["Vlan500", "Vlan501", "Vlan502"],
                        "l3_vni_ip_list": ["33.33.1.1", "33.33.2.1", "33.33.3.1"],
                        "l3_vni_ipmask_list": ["24", "24", "24"],
                        "l3_vni_ip_net" : ["33.33.1.0/24","33.33.2.0/24","33.33.3.0/24"],
                        "l3_tenant_ip_list": ["30.1.1.1", "30.2.2.1", "30.1.3.1"],
                        "l3_tenant_ip_net" : ["30.1.1.0/24","30.2.2.0/24","30.1.3.0/24"],
                        "l3_vni_ipv6_list": ["3331::1", "3332::1", "3333::1"],
                        "l3_vni_ipv6_net" : ["3331::/96", "3332::/96", "3333::/96"],
                        "l3_vni_ipv6mask_list": ["96", "96", "96"],
                        "l3_tenant_ipv6_list": ["3001::1", "3002::1", "3003::1"],
                        "l3_tenant_ipv6_net" : ["3001::/96","3002::/96","3003::/96"],
                        "vrf_name_list": ["Vrf1", "Vrf2", "Vrf3"],
                        "tenant_l2_vlan_name_list": ["Vlan100", "Vlan101", "Vlan102"],
                        "vtepName" : "vtepLeaf1", "nvoName" : "nvoLeaf1",
                        "tenant_mac_l2": ["00.02.33.00.00.01","00.02.33.00.00.22"],
                        "tenant_mac_l2_2": ["00.02.33.33.00.01","00.02.33.33.00.22"],
                        "tenant_mac_v4": ["00.04.33.00.00.01","00.04.33.00.00.22","00.04.33.00.00.33"],
                        "tenant_mac_v4_2": ["00.04.33.33.00.01","00.04.33.33.00.22"],
                        "tenant_mac_v6": ["00.06.33.00.00.01","00.06.33.00.00.22","00.06.33.00.00.33"],
                        "tenant_mac_v6_2": ["00.06.33.33.00.01","00.06.33.33.00.22"],
                        "tenant_v4_ip": ["30.1.1.2","30.1.2.3","30.1.3.2"],
                        "tenant_v4_ip_2": ["30.2.2.2","30.2.2.3","50.2.2.3"],
                        "tenant_v6_ip": ["3001::2","3002::2","3003::2"],
                        "tenant_v6_ip_2": ["3002::2","3002::3","5002::3"],
                        "tenant_mac_v4_colon": "00:04:33:00:00:01","tenant_mac_v6_colon": "00:06:33:00:00:01",
                        "tenant_mac_v4_colon_2": "00:04:33:33:00:01","tenant_mac_v6_colon_2": "00:06:33:33:00:01",
                        "iccpd_ip_list" : ["3.4.1.1","3.4.1.2"],"iccpd_pch_intf_list" : ["PortChannel34"],
                        "mlag_pch_intf_list" : ["PortChannel10"]},
             "leaf2" : {"intf_ipv6_list" : ["1001:4::0","1002:4::0"],
                        "loop_ip_list" : ["33.33.33.33","3.3.3.2"], "local_as" : "400",
                        "tenant_l2_vlan_list" : ["100","101","102"], "vlan_list" : ["14","24"],
                        "rem_as_list" : ["100","200","600"], "ve_intf_list" : ["Vlan14","Vlan24"],
                        "pch_intf_list" : ["PortChannel14","PortChannel24"],
                        "l3_vni_list": ["500", "501", "502"],
                        "tenant_l3_vlan_list": ["400", "301", "402"],
                        "l3_vni_name_list": ["Vlan500", "Vlan501", "Vlan502"],
                        "l3_vni_ip_list": ["44.44.1.1", "33.33.2.2", "44.44.3.1"],
                        "l3_vni_ipmask_list": ["24", "24", "24"],
                        "l3_vni_ip_net" : ["44.44.1.0/24","33.33.2.0/24","44.44.3.0/24"],
                        "l3_tenant_ip_list": ["40.1.1.1", "30.2.2.2", "40.1.3.1"],
                        "l3_tenant_ip_net" : ["40.1.1.0/24","30.2.2.0/24","40.1.3.0/24"],
                        "l3_vni_ipv6_list": ["4441::1", "4442::2", "4443::1"],
                        "l3_vni_ipv6_net" : ["4441::/96", "4442::/96", "4443::/96"],
                        "l3_vni_ipv6mask_list": ["96", "96", "96"],
                        "l3_tenant_ipv6_list": ["4001::1", "3002::2", "4003::1"],
                        "l3_tenant_ipv6_net" : ["4001::/96","3002::/96","4003::/96"],
                        "vrf_name_list": ["Vrf1", "Vrf2", "Vrf3"],
                        "tenant_l2_vlan_name_list": ["Vlan100", "Vlan101", "Vlan102"],
                        "vtepName" : "vtepLeaf2", "nvoName" : "nvoLeaf2",
                        "tenant_mac_l2" : ["00.02.44.00.00.01","00.02.44.00.00.22"],
                        "tenant_mac_l2_2" : ["00.02.44.44.00.01","00.02.44.44.00.22"],
                        "tenant_mac_v4": ["00.04.44.00.00.01","00.04.44.00.00.22"],
                        "tenant_mac_v4_2": ["00.04.44.44.00.01","00.04.44.44.00.22"],
                        "tenant_mac_v6" : ["00.06.44.00.00.01","00.06.44.00.00.22"],
                        "tenant_mac_v6_2" : ["00.06.44.44.00.01","00.06.44.44.00.22"],
                        "tenant_v4_ip" : ["40.1.1.2","30.1.2.3","50.1.1.3"],
                        "tenant_v4_ip_2" : ["40.2.2.2","30.2.2.3","50.2.2.3"],
                        "tenant_v6_ip" : ["4001::2","3001::3","5001::3"],
                        "tenant_v6_ip_2" : ["4002::2","3002::3","5002::3"],
                        "tenant_mac_v6_colon_2": ["00:06:44:44:00:01","00:06:44:44:00:33"],
                        "iccpd_ip_list": ["3.4.1.2", "3.4.1.1"], "iccpd_pch_intf_list": ["PortChannel34"],
                        "mlag_pch_intf_list": ["PortChannel10"]},
             "leaf3" : {"intf_ipv6_list" : ["1001:5::0","1002:5::0"],
                        "loop_ip_list" : ["5.5.5.1","5.5.5.2"], "local_as" : "500",
                        "tenant_l2_vlan_list" : ["100","101","102"], "vlan_list" : ["15","25"],
                        "rem_as_list" : ["100","200","1500"], "ve_intf_list" : ["Vlan15","Vlan25"],
                        "pch_intf_list" : ["PortChannel15","PortChannel25"],
                        "l3_vni_list": ["500", "501", "502"],
                        "tenant_l3_vlan_list": ["510", "511", "512"],
                        "l3_vni_name_list": ["Vlan500", "Vlan501", "Vlan502"],
                        "l3_vni_ip_list": ["55.55.1.1", "55.55.2.1", "55.55.3.1"],
                        "l3_vni_ipmask_list": ["24", "24", "24"],
                        "l3_vni_ip_net" : ["55.55.1.0/24","55.55.2.0/24","55.55.3.0/24"],
                        "l3_tenant_ip_list": ["50.1.1.1", "50.1.2.1", "50.1.3.1"],
                        "l3_tenant_ip_net" : ["50.1.1.0/24","50.1.2.0/24","50.1.3.0/24"],
                        "l3_vni_ipv6_list": ["5551::1", "5552::1", "5553::1"],
                        "l3_vni_ipv6_net" : ["5551::/96", "5552::/96", "5553::/96"],
                        "l3_vni_ipv6mask_list": ["96", "96", "96"],
                        "l3_tenant_ipv6_list": ["5001::1", "5002::1", "5003::1"],
                        "l3_tenant_ipv6_net" : ["5001::/96","5002::/96","5003::/96/24"],
                        "vrf_name_list": ["Vrf1", "Vrf2", "Vrf3"],
                        "tenant_l2_vlan_name_list": ["Vlan100", "Vlan101", "Vlan102"],
                        "vtepName" : "vtepLeaf3", "nvoName" : "nvoLeaf3",
                        "tenant_mac_l2" : ["00.02.55.00.00.01","00.02.55.00.00.22"],
                        "tenant_mac_l2_2" : ["00.02.55.55.00.01","00.02.55.55.00.22"],
                        "tenant_mac_v4": ["00.04.55.00.00.01","00.04.55.00.00.22"],
                        "tenant_mac_v4_2": ["00.04.55.55.00.01","00.04.55.55.00.22"],
                        "tenant_mac_v6" : ["00.06.55.00.00.01","00.06.55.00.00.22"],
                        "tenant_mac_v6_2" : ["00.06.55.55.00.01","00.06.55.55.00.22"],
                        "tenant_v4_ip" : ["50.1.1.2","50.1.2.2","40.1.1.3"],
                        "tenant_v4_ip_2" : ["50.2.2.2","30.2.2.3","40.2.2.3"],
                        "tenant_v6_ip" : ["5001::2","5002::2","3001::3"],
                        "tenant_mac_v6_colon_2" : ["00:06:55:55:00:01","00:06:55:55:00:22"],
                        "tenant_v6_ip_2" : ["5002::2","3002::3","4002::3"],
                        "v4_prefix":["150.1.0.0"],"v6_prefix":["1501:1:2::"]},
             "spine1": {"intf_ipv6_list" : ["1001:3::1","1001:4::1","1001:5::1"], "local_as" : "100",
                        "loop_ip_list" : ["1.1.1.1", "1.1.1.2"], "vlan_list" : ["13","14","15"],
                        "rem_as_list" : ["300","400","500"],"ve_intf_list" : ["Vlan13","Vlan14","Vlan15"],
                        "pch_intf_list" : ["PortChannel13","PortChannel14","PortChannel15"]},
             "spine2": {"intf_ipv6_list" : ["1002:3::1","1002:4::1","1002:5::1"], "local_as" : "200",
                        "loop_ip_list" : ["2.2.2.1", "2.2.2.2"], "vlan_list" : ["23","24","25"],
                        "rem_as_list" : ["300","400","500"],"ve_intf_list" : ["Vlan23","Vlan24","Vlan25"],
                        "pch_intf_list" : ["PortChannel23","PortChannel24","PortChannel25"]},
             "mlag_node": {"tenant_mac_l2": "00.02.66.00.00.01", "tenant_mac_v4" : "00.04.66.00.00.01",
                        "tenant_mac_v6" : "00.06.66.00.00.01", "l3_tenant_ip_list": ["30.2.2.3","60.1.1.1"],
                        "l3_tenant_ipv6_list": ["3002::3","6002::1"], "sag_tenant_v4_ip": "120.1.1.2",
                        "sag_tenant_v6_ip": "1201::2","tenant_v4_ip_2":["60.1.1.2"],
                           "tenant_v6_ip_2" : ["6002::2"],"local_as" : "600","rem_as_list" : ["300","400","1600"],
                           "loop_ip_list": ["6.6.6.1"],"v4_prefix":["160.1.0.0"],"v6_prefix":["1601:1:2::"],
                        "tenant_l3_vlan_list" : ["600"]},
             "l3_vni_sag": {"l3_vni_sagip_list": ["120.1.1.1", "120.1.2.1"],
                        "l3_vni_sagip_net": ["120.1.1.0/24", "120.1.2.0/24"],
                        "l3_vni_sagvlan_list": ["450", "451"],"mlag_domain_id":"2",
                        "l3_vni_sagvlanname_list": ["Vlan450", "Vlan451"],
                        "l3_vni_sagip_mac": ["00:04:12:01:01:01", "00:04:12:01:12:01"],
                        "l3_vni_sagipv6_list": ["1201::1", "1202::1"],
                        "l3_vni_sagipv6_net": ["1201::/96", "1202::/96"],
                        "l3_vni_sagipv6_mac": ["00:06:12:01:12:01", "00:06:12:01:12:01"],
                        },
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
    vars = st.ensure_min_topology("D1D3:4","D1D4:4","D1D5:4","D2D3:4", "D2D4:4", "D2D5:4", "D3T1:2",
                                  "D4T1:2", "D5T1:2","D3D4:3", "D3D6:1", "D4D6:1", "D6T1:2",
                                  "D3CHIP:TD3", "D4CHIP:TD3", "D5CHIP:TD3")
    tg_dict["tg"], tg_dict['d3_tg_ph1'] = tgapi.get_handle_byname("T1D3P1")
    tg_dict["tg"], tg_dict['d3_tg_ph2'] = tgapi.get_handle_byname("T1D3P2")
    tg_dict["tg"], tg_dict['d4_tg_ph1'] = tgapi.get_handle_byname("T1D4P1")
    tg_dict["tg"], tg_dict['d4_tg_ph2'] = tgapi.get_handle_byname("T1D4P2")
    tg_dict["tg"], tg_dict['d5_tg_ph1'] = tgapi.get_handle_byname("T1D5P1")
    tg_dict["tg"], tg_dict['d5_tg_ph2'] = tgapi.get_handle_byname("T1D5P2")
    tg_dict["tg"], tg_dict['d6_tg_ph1'] = tgapi.get_handle_byname("T1D6P1")
    tg_dict["tg"], tg_dict['d6_tg_ph2'] = tgapi.get_handle_byname("T1D6P2")
    tg_dict['d3_tg_port1'],tg_dict['d3_tg_port2'] = vars.T1D3P1, vars.T1D3P2
    tg_dict['d4_tg_port1'],tg_dict['d4_tg_port2'] = vars.T1D4P1, vars.T1D4P2
    tg_dict['d5_tg_port1'], tg_dict['d5_tg_port2'] = vars.T1D5P1, vars.T1D5P2
    tg_dict['d6_tg_port1'], tg_dict['d6_tg_port2'] = vars.T1D6P1, vars.T1D6P2
    evpn_dict["mlag_node_list"] = [vars.D3,vars.D4]
    evpn_dict["mlag_client"] = [vars.D6]
    evpn_dict["mlag_tg_list"] = [vars.D6T1P1, vars.D6T1P2]
    evpn_dict["mlag_intf_list"] = [vars.D6D3P1,vars.D6D4P1]
    evpn_dict["leaf1"]["iccpd_cintf_list"] = ["Loopback4"]
    evpn_dict["leaf2"]["iccpd_cintf_list"] = ["Loopback4"]
    evpn_dict["leaf1"]["iccpd_dintf_list"] = [vars.D3D4P1,vars.D3D4P2]
    evpn_dict["leaf2"]["iccpd_dintf_list"] = [vars.D4D3P1,vars.D4D3P2]
    evpn_dict["leaf1"]["mlag_intf_list"] = [vars.D3D6P1]
    evpn_dict["leaf2"]["mlag_intf_list"] = [vars.D4D6P1]
    tg_dict['tgen_rate_pps'] = '20000'
    tg_dict['frame_size'] = '1000'
    tg_dict["cap_frames"] = "500"
    evpn_dict["leaf_node_list"] = [vars.D3, vars.D4,vars.D5]
    evpn_dict["spine_node_list"] = [vars.D1,vars.D2]
    evpn_dict["bgp_node_list"] = [vars.D1, vars.D2, vars.D3,vars.D4,vars.D5]
    evpn_dict["leaf1"]["intf_list_spine"] = [vars.D3D1P1, vars.D3D1P2, vars.D3D1P3, vars.D3D1P4,
                                             vars.D3D2P1, vars.D3D2P2, vars.D3D2P3, vars.D3D2P4]
    evpn_dict["leaf1"]["intf_list_tg"] = [vars.D3T1P1, vars.D3T1P2]
    evpn_dict["leaf2"]["intf_list_spine"] = [vars.D4D1P1, vars.D4D1P2, vars.D4D1P3, vars.D4D1P4,
                                             vars.D4D2P1, vars.D4D2P2, vars.D4D2P3, vars.D4D2P4]
    evpn_dict["leaf2"]["intf_list_tg"] = [vars.D4T1P1, vars.D4T1P2]
    evpn_dict["leaf3"]["intf_list_spine"] = [vars.D5D1P1, vars.D5D1P2, vars.D5D1P3, vars.D5D1P4,
                                             vars.D5D2P1, vars.D5D2P2, vars.D5D2P3, vars.D5D2P4]
    evpn_dict["leaf3"]["intf_list_tg"] = [vars.D5T1P1, vars.D5T1P2]
    evpn_dict["spine1"]["intf_list_leaf"] = [vars.D1D3P1, vars.D1D3P2, vars.D1D3P3, vars.D1D3P4,
                                             vars.D1D4P1, vars.D1D4P2, vars.D1D4P3, vars.D1D4P4,
                                             vars.D1D5P1, vars.D1D5P2, vars.D1D5P3, vars.D1D5P4]
    evpn_dict["spine2"]["intf_list_leaf"] = [vars.D2D3P1, vars.D2D3P2, vars.D2D3P3, vars.D2D3P4,
                                             vars.D2D4P1, vars.D2D4P2, vars.D2D4P3, vars.D2D4P4,
                                             vars.D2D5P1, vars.D2D5P2, vars.D2D5P3, vars.D2D5P4]
    evpn_dict["dut3_gw_mac"] = basic.get_ifconfig(vars.D3, vars.D3T1P1)[0]['mac']
    evpn_dict["dut4_gw_mac"] = basic.get_ifconfig(vars.D4, vars.D4T1P1)[0]['mac']
    evpn_dict["dut5_gw_mac"] = basic.get_ifconfig(vars.D5, vars.D5T1P1)[0]['mac']
    evpn_dict["dut6_gw_mac"] = basic.get_ifconfig(vars.D6, vars.D6T1P2)[0]['mac']



def leaf1_setup_vxlan():

    st.log("config vtep in DUT3 node")
    Evpn.create_overlay_intf(dut=evpn_dict["leaf_node_list"][0],vtep_name=evpn_dict["leaf1"]["vtepName"],
                             ip_addr=evpn_dict["leaf1"]["loop_ip_list"][1])


def leaf2_setup_vxlan():

    st.log("config vtep in DUT4 node")
    Evpn.create_overlay_intf(dut=evpn_dict["leaf_node_list"][1],vtep_name=evpn_dict["leaf2"]["vtepName"],
                             ip_addr=evpn_dict["leaf2"]["loop_ip_list"][1])


def leaf3_setup_vxlan():

    st.log("config vtep in DUT5 node")
    Evpn.create_overlay_intf(dut=evpn_dict["leaf_node_list"][2],vtep_name=evpn_dict["leaf3"]["vtepName"],
                             ip_addr=evpn_dict["leaf3"]["loop_ip_list"][1])


def leaf1_setup_l2vni():
    st.log("create tenant L2 VLANs in DUT3 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][0],vlan_list=evpn_dict["leaf1"]["tenant_l2_vlan_list"])

    st.log("Bind tenant L2 VLANs to port in DUT3 node")
    for i in [0,1]:
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][0],vlan=evpn_dict["leaf1"]["tenant_l2_vlan_list"][i],
                         port_list=evpn_dict["leaf1"]["intf_list_tg"][0], tagging_mode=True)
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][0], vlan=evpn_dict["leaf1"]["tenant_l2_vlan_list"][i],
                             port_list=evpn_dict["leaf1"]["intf_list_tg"][1],tagging_mode=True)

    st.log("Add L2 vlan to VNI mapping in DUT3 node")
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][0],vtep_name=evpn_dict["leaf1"]["vtepName"],
                      vlan_id=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                      vni_id=evpn_dict["leaf1"]["tenant_l2_vlan_list"][0])
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][0],vlan_list=[evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                     evpn_dict["leaf1"]["tenant_l3_vlan_list"][1]])
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][0],vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                         port_list=evpn_dict["leaf1"]["intf_list_tg"][0])
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][0],vlan=evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                         port_list=evpn_dict["leaf1"]["intf_list_tg"][0],tagging_mode=True)
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][0],vtep_name=evpn_dict["leaf1"]["vtepName"],
                      vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                      vni_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0])


def leaf2_setup_l2vni():
    st.log("create tenant L2 VLANs in DUT4 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][1],vlan_list=evpn_dict["leaf2"]["tenant_l2_vlan_list"])

    st.log("Bind tenant L2 VLANs to port in DUT4 node")
    for i in [0,1]:
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][1],vlan=evpn_dict["leaf2"]["tenant_l2_vlan_list"][i],
                         port_list=evpn_dict["leaf2"]["intf_list_tg"][0], tagging_mode=True)
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][1], vlan=evpn_dict["leaf2"]["tenant_l2_vlan_list"][i],
                             port_list=evpn_dict["leaf2"]["intf_list_tg"][1], tagging_mode=True)

    st.log("Add L2 vlan to VNI mapping in DUT4 node")
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][1],vtep_name=evpn_dict["leaf2"]["vtepName"],
                      vlan_id=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0],
                      vni_id=evpn_dict["leaf2"]["tenant_l2_vlan_list"][0])
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][1],vlan_list=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0])
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][1],vlan=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                         port_list=evpn_dict["leaf2"]["intf_list_tg"][0])
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][1],vtep_name=evpn_dict["leaf2"]["vtepName"],
                      vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                      vni_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0])


def leaf3_setup_l2vni():
    st.log("create tenant L2 VLANs in DUT5 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][2],vlan_list=evpn_dict["leaf3"]["tenant_l2_vlan_list"])

    st.log("Bind tenant L2 VLANs to port in DUT5 node")
    for i in [0,1]:
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][2],vlan=evpn_dict["leaf3"]["tenant_l2_vlan_list"][i],
                         port_list=evpn_dict["leaf3"]["intf_list_tg"][0], tagging_mode=True)
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][2], vlan=evpn_dict["leaf3"]["tenant_l2_vlan_list"][i],
                         port_list=evpn_dict["leaf3"]["intf_list_tg"][1],tagging_mode=True)
    st.log("Add L2 vlan to VNI mapping in DUT5 node")
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][2],vtep_name=evpn_dict["leaf3"]["vtepName"],
                      vlan_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0],
                      vni_id=evpn_dict["leaf3"]["tenant_l2_vlan_list"][0])
    for vlan_id in [evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],evpn_dict["leaf3"]["tenant_l3_vlan_list"][1]]:
        Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][2],vlan_list=vlan_id)
    for vlan_id in [evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],evpn_dict["leaf3"]["tenant_l3_vlan_list"][1]]:
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][2],vlan=vlan_id,
                             port_list=evpn_dict["leaf3"]["intf_list_tg"][0],tagging_mode=True)
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][2],vtep_name=evpn_dict["leaf3"]["vtepName"],
                      vlan_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                      vni_id=evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0])


def leaf1_setup_l3vni():

    st.log("create Vrf in DUT3 node")
    vrf.config_vrf(dut=evpn_dict["leaf_node_list"][0],vrf_name= evpn_dict["leaf1"]["vrf_name_list"][0])

    st.log("create VLANs for L3VNI in DUT3 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][0],vlan_list=evpn_dict["leaf1"]["l3_vni_list"][0])

    st.log("create tenant L3 VLANs in DUT3 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][0],vlan_list=evpn_dict["leaf1"]["tenant_l3_vlan_list"])

    st.log("Bind L3VNI and tenant L3 VLANs to port in DUT3 node")
    for vlan in [evpn_dict["leaf1"]["l3_vni_list"][0],evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                 evpn_dict["leaf1"]["tenant_l3_vlan_list"][2]]:
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][0], vlan=vlan,
                             port_list=evpn_dict["leaf1"]["intf_list_tg"][0], tagging_mode=True)
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][0], vlan=evpn_dict["leaf1"]["l3_vni_list"][0],
                         port_list=evpn_dict["leaf1"]["intf_list_tg"][1], tagging_mode=True)
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][0], vlan=evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                         port_list=evpn_dict["leaf1"]["intf_list_tg"][1])

    st.log("Bind Vrf to L3VNI interfaces in DUT3 node")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                           intf_name=evpn_dict["leaf1"]["l3_vni_name_list"][0],skip_error="yes")
    st.log("Bind Vrf to L3VNI tenant interfaces in DUT3 node")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][0], vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                           intf_name="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0], skip_error="yes")
    st.log("Bind SAG interface to VRF in DUT3")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][0], vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                           intf_name=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],skip_error="yes")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][0], vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                           intf_name="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][2], skip_error="yes")
    st.log("Assign IP anycast address to L3 SAG tenant interface in DUT3")
    sag.config_sag_ip(evpn_dict["leaf_node_list"][0],interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], mask="24",config="add")

    st.log("Assign IPv6 address to L3 SAG tenant interface in DUT3")
    sag.config_sag_ip(evpn_dict["leaf_node_list"][0],interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0], mask="96",config="add")

    st.log("Assign IP address to L3VNI interface in DUT3 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                ip_address=evpn_dict["leaf1"]["l3_vni_ip_list"][0],
                                subnet=evpn_dict["leaf1"]["l3_vni_ipmask_list"][0])

    st.log("Assign IP address to L3VNI tenant interface in DUT3 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name="Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                                ip_address=evpn_dict["leaf1"]["l3_tenant_ip_list"][0],
                                subnet=evpn_dict["leaf1"]["l3_vni_ipmask_list"][0])
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name="Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][2],
                                ip_address=evpn_dict["leaf1"]["l3_tenant_ip_list"][2],
                                subnet=evpn_dict["leaf1"]["l3_vni_ipmask_list"][2])

    st.log("Assign IPv6 address to L3VNI interface in DUT3 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name=evpn_dict["leaf1"]["l3_vni_name_list"][0],
                                ip_address=evpn_dict["leaf1"]["l3_vni_ipv6_list"][0],
                                subnet=evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0], family="ipv6")

    st.log("Assign IPv6 address to L3VNI tenant interface in DUT3 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                                ip_address=evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0],
                                subnet=evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],family="ipv6")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][2],
                                ip_address=evpn_dict["leaf1"]["l3_tenant_ipv6_list"][2],
                                subnet=evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][2],family="ipv6")

    st.log("Add L3 vlan to VNI mapping in DUT3 node")
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][0],vtep_name=evpn_dict["leaf1"]["vtepName"],
                      vlan_id=evpn_dict["leaf1"]["l3_vni_list"][0],vni_id=evpn_dict["leaf1"]["l3_vni_list"][0])

    st.log("Add Vrf to VNI map in DUT3 node")
    Evpn.map_vrf_vni(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                     vni=evpn_dict["leaf1"]["l3_vni_list"][0],config='yes', vtep_name=evpn_dict["leaf1"]["vtepName"])

    st.log("Add FRR VRF redist connected config for ipv4 and ipv6 AF in DUT3 node")
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0],local_as=evpn_dict['leaf1']['local_as'],config='yes',
                   config_type_list=["redist"],redistribute='connected',vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0])
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0],local_as=evpn_dict['leaf1']['local_as'],config='yes',
                   config_type_list=["redist"],redistribute='connected',
                   vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],addr_family='ipv6')

    st.log("Add FRR VRF advertise ipv4 & ipv6 unicast config in DUT3 node")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][0],local_as=evpn_dict['leaf1']['local_as'],
                         config='yes',advertise_ipv4='unicast',config_type_list=["advertise_ipv4_vrf"],
                         vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0])
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][0],local_as=evpn_dict['leaf1']['local_as'],
                         config='yes',advertise_ipv6='unicast',config_type_list=["advertise_ipv6_vrf"],
                         vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0])
    st.log("configure ebgp session b/w leaf1 and mclag client node")
    for neigh in [evpn_dict["mlag_node"]["l3_tenant_ip_list"][0],evpn_dict["mlag_node"]["l3_tenant_ipv6_list"][0]]:
        Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0], local_as=evpn_dict["leaf1"]["local_as"], config='yes',
                   config_type_list=["neighbor",'bfd','connect'],remote_as='external', neighbor=neigh,
                   vrf_name=evpn_dict['leaf1']['vrf_name_list'][0],connect=1)
    #for neigh,rt_map,family in zip([evpn_dict["mlag_node"]["l3_tenant_ip_list"][0],evpn_dict["mlag_node"]["l3_tenant_ipv6_list"][0]],
    #                        ['set_sag_nh','set_sag_nhv6'],['ipv4','ipv6']):
    #    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0], local_as=evpn_dict["leaf1"]["local_as"], config='yes',
    #               config_type_list=["routeMap"],routeMap=rt_map,remote_as='external', neighbor=neigh,
    #               vrf_name=evpn_dict['leaf1']['vrf_name_list'][0],connect=1,diRection='out',addr_family=family)
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0], local_as=evpn_dict["leaf1"]["local_as"], config='yes',
                   config_type_list=["activate"], neighbor=evpn_dict["mlag_node"]["l3_tenant_ipv6_list"][0],
                   addr_family="ipv6",vrf_name=evpn_dict['leaf1']['vrf_name_list'][0])
    st.log("Configure SAG in DUT3 node")
    sag.config_sag_mac(dut=evpn_dict["leaf_node_list"][0],mac=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                       config="add")
    sag.config_sag_mac(evpn_dict["leaf_node_list"][0],config="enable")
    sag.config_sag_mac(evpn_dict["leaf_node_list"][0],config="enable",ip_type="ipv6")


def leaf2_setup_l3vni():

    st.log("create Vrf in DUT4 node")
    vrf.config_vrf(dut=evpn_dict["leaf_node_list"][1],vrf_name= evpn_dict["leaf2"]["vrf_name_list"][0])

    st.log("create VLANs for L3VNI in DUT4 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][1],vlan_list=evpn_dict["leaf2"]["l3_vni_list"][0])

    st.log("create tenant L3 VLANs in DUT4 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][1],vlan_list=evpn_dict["leaf2"]["tenant_l3_vlan_list"])

    st.log("Bind L3VNI and tenant L3 VLANs to port in DUT4 node")
    for vlan in [evpn_dict["leaf2"]["l3_vni_list"][0],evpn_dict["leaf2"]["tenant_l3_vlan_list"][0]]:
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][1], vlan=vlan,
                             port_list=evpn_dict["leaf2"]["intf_list_tg"][0], tagging_mode=True)
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][1],vlan=evpn_dict["leaf2"]["l3_vni_list"][0],
                         port_list=evpn_dict["leaf2"]["intf_list_tg"][1], tagging_mode=True)
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][1],vlan=evpn_dict["leaf2"]["tenant_l3_vlan_list"][1],
                         port_list=evpn_dict["leaf2"]["intf_list_tg"][1])

    st.log("Bind Vrf to L3VNI interfaces in DUT4 node")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                           intf_name=evpn_dict["leaf2"]["l3_vni_name_list"][0],skip_error="yes")
    st.log("Bind Vrf to L3VNI tenant interfaces in DUT4 node")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][1], vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                           intf_name="Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0], skip_error="yes")
    st.log("Bind SAG interface to VRF in DUT4")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][1], vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                           intf_name=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],skip_error="yes")
    st.log("Assign IP anycast address to L3 SAG tenant interface in DUT4")
    sag.config_sag_ip(evpn_dict["leaf_node_list"][1],interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], mask="24",config="add")

    st.log("Assign IPv6 address to L3 SAG tenant interface in DUT4")
    sag.config_sag_ip(evpn_dict["leaf_node_list"][1],interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0], mask="96",config="add")

    st.log("Assign IP address to L3VNI interface in DUT4 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][1],
                                interface_name=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                                ip_address=evpn_dict["leaf2"]["l3_vni_ip_list"][0],
                                subnet=evpn_dict["leaf2"]["l3_vni_ipmask_list"][0])

    st.log("Assign IP address to L3VNI tenant interface in DUT4 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][1],
                                interface_name="Vlan" +evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                ip_address=evpn_dict["leaf2"]["l3_tenant_ip_list"][0],
                                subnet=evpn_dict["leaf2"]["l3_vni_ipmask_list"][0])

    st.log("Assign IPv6 address to L3VNI interface in DUT4 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][1],
                                interface_name=evpn_dict["leaf2"]["l3_vni_name_list"][0],
                                ip_address=evpn_dict["leaf2"]["l3_vni_ipv6_list"][0],
                                subnet=evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0], family="ipv6")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][1],
                                interface_name="Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                ip_address=evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0],
                                subnet=evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0],family="ipv6")

    st.log("Add L3 vlan to VNI mapping in DUT4 node")
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][1],vtep_name=evpn_dict["leaf2"]["vtepName"],
                      vlan_id=evpn_dict["leaf2"]["l3_vni_list"][0],vni_id=evpn_dict["leaf2"]["l3_vni_list"][0])

    st.log("Add Vrf to VNI map in in DUT4 node")
    Evpn.map_vrf_vni(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                     vni=evpn_dict["leaf2"]["l3_vni_list"][0],config='yes', vtep_name=evpn_dict["leaf2"]["vtepName"])

    st.log("Add FRR VRF redist connected config for ipv4 and ipv6 AF in DUT4 node")
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1],local_as=evpn_dict['leaf2']['local_as'],config='yes',
                   config_type_list=["redist"],redistribute='connected',vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0])
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1],local_as=evpn_dict['leaf2']['local_as'],config='yes',
                   config_type_list=["redist"],redistribute='connected',
                   vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],addr_family='ipv6')

    st.log("Add FRR VRF advertise ipv4 & ipv6 unicast config in DUT4 node")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][1],local_as=evpn_dict['leaf2']['local_as'],
                         config='yes',advertise_ipv4='unicast',config_type_list=["advertise_ipv4_vrf"],
                         vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0])
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][1],local_as=evpn_dict['leaf2']['local_as'],
                         config='yes',advertise_ipv6='unicast',config_type_list=["advertise_ipv6_vrf"],
                         vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0])
    st.log("configure ebgp session b/w leaf2 and mclag client node")
    for neigh in [evpn_dict["mlag_node"]["l3_tenant_ip_list"][0],evpn_dict["mlag_node"]["l3_tenant_ipv6_list"][0]]:
        Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1], local_as=evpn_dict["leaf2"]["local_as"], config='yes',
                   config_type_list=["neighbor",'bfd','connect'],remote_as='external', neighbor=neigh,
                   vrf_name=evpn_dict['leaf1']['vrf_name_list'][0],connect=1)
    #for neigh,rt_map,family in zip([evpn_dict["mlag_node"]["l3_tenant_ip_list"][0],evpn_dict["mlag_node"]["l3_tenant_ipv6_list"][0]],
    #                        ['set_sag_nh','set_sag_nhv6'],['ipv4','ipv6']):
    #    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1], local_as=evpn_dict["leaf2"]["local_as"], config='yes',
    #               config_type_list=["routeMap"],routeMap=rt_map,remote_as='external', neighbor=neigh,
    #               vrf_name=evpn_dict['leaf1']['vrf_name_list'][0],connect=1,diRection='out',addr_family=family)
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1], local_as=evpn_dict["leaf2"]["local_as"], config='yes',
                   config_type_list=["activate"], neighbor=evpn_dict["mlag_node"]["l3_tenant_ipv6_list"][0],
                   addr_family="ipv6",vrf_name=evpn_dict['leaf1']['vrf_name_list'][0])
    st.log("Configure SAG in DUT4 node")
    sag.config_sag_mac(dut=evpn_dict["leaf_node_list"][1],mac=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                       config="add")
    sag.config_sag_mac(evpn_dict["leaf_node_list"][1],config="enable")
    sag.config_sag_mac(evpn_dict["leaf_node_list"][1],config="enable",ip_type="ipv6")


def leaf3_setup_l3vni():

    st.log("create Vrf in DUT5 node")
    vrf.config_vrf(dut=evpn_dict["leaf_node_list"][2],vrf_name= evpn_dict["leaf3"]["vrf_name_list"][0])

    st.log("create VLANs for L3VNI in DUT5 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][2],vlan_list=evpn_dict["leaf3"]["l3_vni_list"][0])

    st.log("create tenant L3 VLANs in DUT5 node")
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][2],vlan_list=evpn_dict["leaf3"]["tenant_l3_vlan_list"])

    st.log("Bind L3VNI and tenant L3 VLANs to port in DUT5 node")
    for vlan in [evpn_dict["leaf3"]["l3_vni_list"][0],evpn_dict["leaf3"]["tenant_l3_vlan_list"][0]]:
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][2], vlan=vlan,
                             port_list=evpn_dict["leaf3"]["intf_list_tg"][0], tagging_mode=True)
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][2], vlan=evpn_dict["leaf3"]["l3_vni_list"][0],
                         port_list=evpn_dict["leaf3"]["intf_list_tg"][1], tagging_mode=True)
    Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][2], vlan=evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
                         port_list=evpn_dict["leaf3"]["intf_list_tg"][1])

    st.log("Bind Vrf to L3VNI interfaces in DUT5 node")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][2],vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                           intf_name=evpn_dict["leaf3"]["l3_vni_name_list"][0],skip_error="yes")

    st.log("Bind Vrf to L3VNI tenant interfaces in DUT5 node")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][2], vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                           intf_name="Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0], skip_error="yes")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][2], vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                           intf_name="Vlan" + evpn_dict["leaf3"]["tenant_l3_vlan_list"][1], skip_error="yes")
    st.log("Bind SAG interface to VRF in DUT5")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][2], vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                           intf_name=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],skip_error="yes")
    st.log("Assign IP anycast address to L3 SAG tenant interface in DUT5")
    sag.config_sag_ip(evpn_dict["leaf_node_list"][2],interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0], mask="24",config="add")

    st.log("Assign IPv6 address to L3 SAG tenant interface in DUT5")
    sag.config_sag_ip(evpn_dict["leaf_node_list"][2],interface=evpn_dict["l3_vni_sag"]["l3_vni_sagvlanname_list"][0],
            gateway=evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0], mask="96",config="add")

    st.log("Assign IP address to L3VNI interface in DUT5 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],
                                interface_name=evpn_dict["leaf3"]["l3_vni_name_list"][0],
                                ip_address=evpn_dict["leaf3"]["l3_vni_ip_list"][0],
                                subnet=evpn_dict["leaf3"]["l3_vni_ipmask_list"][0])

    st.log("Assign IP address to L3VNI tenant interface in DUT5 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],
                                interface_name="Vlan" + evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_list"][0],
                                subnet=evpn_dict["leaf3"]["l3_vni_ipmask_list"][0])
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],
                                interface_name="Vlan" + evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ip_list"][1],
                                subnet=evpn_dict["leaf3"]["l3_vni_ipmask_list"][0])

    st.log("Assign IPv6 address to L3VNI interface in DUT5 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],
                                interface_name=evpn_dict["leaf3"]["l3_vni_name_list"][0],
                                ip_address=evpn_dict["leaf3"]["l3_vni_ipv6_list"][0],
                                subnet=evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0], family="ipv6")

    st.log("Assign IPv6 address to L3VNI tenant interface in DUT5 node")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],
                                interface_name="Vlan"+evpn_dict["leaf3"]["tenant_l3_vlan_list"][0],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][0],
                                subnet=evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0],family="ipv6")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],
                                interface_name="Vlan" + evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
                                ip_address=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][1],
                                subnet=evpn_dict["leaf3"]["l3_vni_ipv6mask_list"][0], family="ipv6")

    st.log("Add L3 vlan to VNI mapping in DUT5 node")
    Evpn.map_vlan_vni(dut=evpn_dict["leaf_node_list"][2],vtep_name=evpn_dict["leaf3"]["vtepName"],
                      vlan_id=evpn_dict["leaf3"]["l3_vni_list"][0],vni_id=evpn_dict["leaf3"]["l3_vni_list"][0])

    st.log("Add Vrf to VNI map in DUT5 node")
    Evpn.map_vrf_vni(dut=evpn_dict["leaf_node_list"][2],vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],
                     vni=evpn_dict["leaf3"]["l3_vni_list"][0],config='yes', vtep_name=evpn_dict["leaf3"]["vtepName"])

    st.log("Add FRR VRF redist connected config for ipv4 and ipv6 AF in DUT5 node")
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],config='yes',
                   config_type_list=["redist"],redistribute='connected',vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0])
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],config='yes',
                   config_type_list=["redist"],redistribute='connected',
                   vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],addr_family='ipv6')

    st.log("Add FRR VRF advertise ipv4 & ipv6 unicast config in DUT5 node")
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],
                         config='yes',advertise_ipv4='unicast',config_type_list=["advertise_ipv4_vrf"],
                         vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0])
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],
                         config='yes',advertise_ipv6='unicast',config_type_list=["advertise_ipv6_vrf"],
                         vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0])
    st.log("Configure SAG in DUT5 node")
    sag.config_sag_mac(dut=evpn_dict["leaf_node_list"][2],mac=evpn_dict["l3_vni_sag"]["l3_vni_sagip_mac"][0],
                       config="add")
    sag.config_sag_mac(evpn_dict["leaf_node_list"][2],config="enable")
    sag.config_sag_mac(evpn_dict["leaf_node_list"][2],config="enable",ip_type="ipv6")


def leaf1_mlag_config():
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][0],vlan_list=evpn_dict["leaf2"]["tenant_l3_vlan_list"][0])
    for vlan_id,port_name in zip([evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                  evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                                  evpn_dict["leaf1"]["l3_vni_list"][0],
                                  evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                                  evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                  evpn_dict["leaf1"]["l3_vni_list"][0],
                                  evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                  evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                                  evpn_dict["leaf1"]["tenant_l3_vlan_list"][1]],
                                 [evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],
                                  evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                                  evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],
                                  evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],
                                  evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],
                                  evpn_dict["leaf1"]["mlag_pch_intf_list"],
                                  evpn_dict["leaf1"]["mlag_pch_intf_list"],
                                  evpn_dict["leaf1"]["mlag_pch_intf_list"],
                                  evpn_dict["leaf1"]["mlag_pch_intf_list"],
                                  evpn_dict["leaf1"]["mlag_pch_intf_list"],
                                  evpn_dict["leaf1"]["iccpd_pch_intf_list"][0]]):
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][0],vlan=vlan_id,port_list=port_name,tagging_mode=True)
    st.log("configure MCLAG domain in leaf1")
    mclag.config_domain(dut=evpn_dict["leaf_node_list"][0],domain_id=evpn_dict["l3_vni_sag"]['mlag_domain_id'],
                        local_ip=evpn_dict['leaf1']['iccpd_ip_list'][0],
                        peer_ip=evpn_dict['leaf1']['iccpd_ip_list'][1],
                        peer_interface=evpn_dict['leaf1']['iccpd_pch_intf_list'][0],delay_restore_timer=600)
    mclag.config_interfaces(dut=evpn_dict["leaf_node_list"][0],domain_id=evpn_dict["l3_vni_sag"]['mlag_domain_id'],
                            interface_list=evpn_dict["leaf1"]["mlag_pch_intf_list"][0],config='add')
    mclag.config_mclag_system_mac(evpn_dict["leaf_node_list"][0], domain_id=evpn_dict["l3_vni_sag"]['mlag_domain_id'], mac="00:11:33:33:44:66")
    mclag.config_gw_mac(evpn_dict["leaf_node_list"][0], mac="00:11:22:33:88:99")
    st.log("configure unique ip in leaf1")
    mc_lag.config_uniqueip(evpn_dict["leaf_node_list"][0], op_type="add",
                    vlan="Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][1])

    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][0], vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                           intf_name="Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][1], skip_error="yes")
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name="Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                                ip_address=evpn_dict["leaf1"]["l3_tenant_ip_list"][1],
                                subnet=evpn_dict["leaf1"]["l3_vni_ipmask_list"][0])
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],
                                interface_name="Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                                ip_address=evpn_dict["leaf1"]["l3_tenant_ipv6_list"][1],
                                subnet=evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0], family="ipv6")

    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                           intf_name="Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][0])
    for intf_name,ip_addr,subnet,addr_type in zip(["Vlan" + evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                                   "Vlan" + evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                                   evpn_dict["leaf1"]["iccpd_cintf_list"][0]],
                                                  [evpn_dict["leaf2"]["l3_tenant_ip_list"][0],
                                                   evpn_dict["leaf2"]["l3_tenant_ipv6_list"][0],
                                                   evpn_dict["leaf1"]["iccpd_ip_list"][0]],
                                                  [evpn_dict["leaf1"]["l3_vni_ipmask_list"][0],
                                                   evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0],"32"],
                                                  ["ipv4","ipv6","ipv4"]):
        ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],interface_name=intf_name,
                                    ip_address=ip_addr,subnet=subnet,family=addr_type)
    pch.create_portchannel(dut=evpn_dict["leaf_node_list"][0],
                           portchannel_list=evpn_dict["leaf1"]["mlag_pch_intf_list"]+
                                            evpn_dict["leaf1"]["iccpd_pch_intf_list"])
    for pch_name,mem_port in zip([evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],
                                     evpn_dict["leaf1"]["mlag_pch_intf_list"][0]],
                                    [evpn_dict["leaf1"]["iccpd_dintf_list"][0:2],
                                     evpn_dict["leaf1"]["mlag_intf_list"][0]]):
        pch.add_portchannel_member(dut=evpn_dict["leaf_node_list"][0],portchannel=pch_name,members=mem_port)
    Intf.interface_operation(dut=evpn_dict["mlag_node_list"][0],
                             interfaces=evpn_dict["leaf1"]["mlag_pch_intf_list"]
                                        +evpn_dict["leaf1"]["iccpd_pch_intf_list"], operation="startup")


def leaf2_mlag_config():
    Vlan.create_vlan(dut=evpn_dict["leaf_node_list"][1],vlan_list=[evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                                                                   evpn_dict["leaf1"]["tenant_l3_vlan_list"][1]])
    for vlan_id,port_name in zip([evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                                  evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                                  evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                  evpn_dict["leaf2"]["l3_vni_list"][0],
                                  evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                                  evpn_dict["leaf2"]["tenant_l3_vlan_list"][0],
                                  evpn_dict["leaf2"]["l3_vni_list"][0],
                                  evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                                  evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                                  evpn_dict["leaf1"]["tenant_l3_vlan_list"][1]],
                                 [evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],
                                  evpn_dict["leaf1"]["mlag_pch_intf_list"][0],
                                  evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],
                                  evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],
                                  evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],
                                  evpn_dict["leaf1"]["mlag_pch_intf_list"],
                                  evpn_dict["leaf1"]["mlag_pch_intf_list"],
                                  evpn_dict["leaf1"]["mlag_pch_intf_list"],
                                  evpn_dict["leaf1"]["mlag_pch_intf_list"],
                                  evpn_dict["leaf1"]["mlag_pch_intf_list"],
                                  evpn_dict["leaf1"]["iccpd_pch_intf_list"][0]]):
        Vlan.add_vlan_member(dut=evpn_dict["leaf_node_list"][1],vlan=vlan_id,port_list=port_name,tagging_mode=True)
    st.log("configure MCLAG domain in leaf2")
    mclag.config_domain(dut=evpn_dict["leaf_node_list"][1],domain_id=evpn_dict["l3_vni_sag"]['mlag_domain_id'],
                        local_ip=evpn_dict['leaf2']['iccpd_ip_list'][0],
                        peer_ip=evpn_dict['leaf2']['iccpd_ip_list'][1],
                        peer_interface=evpn_dict['leaf2']['iccpd_pch_intf_list'][0],delay_restore_timer=600)
    mclag.config_interfaces(dut=evpn_dict["leaf_node_list"][1],domain_id=evpn_dict["l3_vni_sag"]['mlag_domain_id'],
                            interface_list=evpn_dict["leaf2"]["mlag_pch_intf_list"][0],config='add')
    mclag.config_mclag_system_mac(evpn_dict["leaf_node_list"][1], domain_id=evpn_dict["l3_vni_sag"]['mlag_domain_id'],
                                  mac="00:11:33:33:44:66")
    mclag.config_gw_mac(evpn_dict["leaf_node_list"][1], mac="00:11:22:33:88:99")
    mc_lag.config_uniqueip(evpn_dict["leaf_node_list"][1], op_type="add",
                    vlan="Vlan" + evpn_dict["leaf2"]["tenant_l3_vlan_list"][1])
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][1], vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                           intf_name="Vlan" + evpn_dict["leaf2"]["tenant_l3_vlan_list"][1], skip_error="yes")

    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][1],
                                interface_name="Vlan" +evpn_dict["leaf2"]["tenant_l3_vlan_list"][1],
                                ip_address=evpn_dict["leaf2"]["l3_tenant_ip_list"][1],
                                subnet=evpn_dict["leaf2"]["l3_vni_ipmask_list"][0])
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][1],
                                interface_name="Vlan"+evpn_dict["leaf2"]["tenant_l3_vlan_list"][1],
                                ip_address=evpn_dict["leaf2"]["l3_tenant_ipv6_list"][1],
                                subnet=evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0],family="ipv6")
    vrf.bind_vrf_interface(dut=evpn_dict["leaf_node_list"][1],vrf_name=evpn_dict["leaf2"]["vrf_name_list"][0],
                           intf_name="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][0])
    for intf_name,ip_addr,subnet,addr_type in zip(["Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                                                   "Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][0],
                                                   evpn_dict["leaf2"]["iccpd_cintf_list"][0]],
                                                  [evpn_dict["leaf1"]["l3_tenant_ip_list"][0],
                                                   evpn_dict["leaf1"]["l3_tenant_ipv6_list"][0],
                                                   evpn_dict["leaf2"]["iccpd_ip_list"][0]],
                                                  [evpn_dict["leaf2"]["l3_vni_ipmask_list"][0],
                                                   evpn_dict["leaf2"]["l3_vni_ipv6mask_list"][0],"32"],
                                                  ["ipv4","ipv6","ipv4"]):
        ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][1],interface_name=intf_name,
                                    ip_address=ip_addr,subnet=subnet,family=addr_type)
    pch.create_portchannel(dut=evpn_dict["leaf_node_list"][1],
                           portchannel_list=evpn_dict["leaf2"]["mlag_pch_intf_list"]+
                                            evpn_dict["leaf2"]["iccpd_pch_intf_list"])
    for pch_name,mem_port in zip([evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],
                                     evpn_dict["leaf2"]["mlag_pch_intf_list"][0]],
                                    [evpn_dict["leaf2"]["iccpd_dintf_list"][0:2],
                                     evpn_dict["leaf2"]["mlag_intf_list"][0]]):
        pch.add_portchannel_member(dut=evpn_dict["leaf_node_list"][1],portchannel=pch_name,members=mem_port)
    Intf.interface_operation(dut=evpn_dict["mlag_node_list"][1],
                             interfaces=evpn_dict["leaf2"]["mlag_pch_intf_list"]
                                        +evpn_dict["leaf2"]["iccpd_pch_intf_list"], operation="startup")


def client_mclag_config():
    for vlan_id in [evpn_dict["leaf1"]["tenant_l2_vlan_list"][0],
                    evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0],
                    evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                    evpn_dict["mlag_node"]["tenant_l3_vlan_list"][0]]:
        Vlan.create_vlan(dut=evpn_dict["mlag_client"][0], vlan_list=vlan_id)
    vrf.config_vrf(dut=evpn_dict["mlag_client"][0],vrf_name= evpn_dict["leaf1"]["vrf_name_list"][0])
    for vlan_id,port_name in zip([evpn_dict["leaf1"]["tenant_l2_vlan_list"][0]]*2+
                                 [evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]]*2+
                                 [evpn_dict["leaf1"]["tenant_l3_vlan_list"][1]],
                                 [evpn_dict['mlag_tg_list'][0],evpn_dict["leaf1"]["mlag_pch_intf_list"][0]]*2+
                                  [evpn_dict["leaf1"]["mlag_pch_intf_list"][0]]):
        Vlan.add_vlan_member(dut=evpn_dict["mlag_client"][0], vlan=vlan_id,port_list=port_name, tagging_mode=True)
    Vlan.add_vlan_member(dut=evpn_dict["mlag_client"][0], vlan=evpn_dict["mlag_node"]["tenant_l3_vlan_list"][0],
                         port_list=evpn_dict['mlag_tg_list'][1], tagging_mode=True)
    pch.create_portchannel(dut=evpn_dict["mlag_client"][0],portchannel_list=evpn_dict["leaf1"]["mlag_pch_intf_list"])
    for pch_name,mem_port in zip([evpn_dict["leaf1"]["mlag_pch_intf_list"][0]]*2,
                                 [evpn_dict["mlag_intf_list"][0:2]]):
        pch.add_portchannel_member(dut=evpn_dict["mlag_client"][0],portchannel=pch_name,members=mem_port)
    Intf.interface_operation(dut=evpn_dict["mlag_client"][0], interfaces=evpn_dict["leaf1"]["mlag_pch_intf_list"],
                             operation="startup")
    for intf_name in [evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],evpn_dict["mlag_node"]["tenant_l3_vlan_list"][0],
                      evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]]:
        vrf.bind_vrf_interface(dut=evpn_dict["mlag_client"][0],vrf_name=evpn_dict["leaf1"]["vrf_name_list"][0],
                           config="yes",intf_name="Vlan" + intf_name)
    for interf,ip_addr in zip(["Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                               "Vlan" + evpn_dict["mlag_node"]["tenant_l3_vlan_list"][0],
                               "Vlan" + evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]],
                              [evpn_dict["mlag_node"]["l3_tenant_ip_list"][0],
                               evpn_dict["mlag_node"]["l3_tenant_ip_list"][1],
                               evpn_dict['mlag_node']["sag_tenant_v4_ip"]]):
        ip.config_ip_addr_interface(dut=evpn_dict["mlag_client"][0], interface_name=interf,
                                ip_address=ip_addr, subnet=evpn_dict["leaf1"]["l3_vni_ipmask_list"][0])
    for interf,ip_addr in zip(["Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                               "Vlan" + evpn_dict["mlag_node"]["tenant_l3_vlan_list"][0],
                               "Vlan" + evpn_dict["l3_vni_sag"]["l3_vni_sagvlan_list"][0]],
                              [evpn_dict["mlag_node"]["l3_tenant_ipv6_list"][0],
                               evpn_dict["mlag_node"]["l3_tenant_ipv6_list"][1],
                               evpn_dict['mlag_node']["sag_tenant_v6_ip"]]):
        ip.config_ip_addr_interface(dut=evpn_dict["mlag_client"][0],
                                interface_name=interf, ip_address=ip_addr,
                                subnet=evpn_dict["leaf1"]["l3_vni_ipv6mask_list"][0], family="ipv6")

    st.log("create route-map to set ip/ipv6 nexthop as SAG ip")
    rmap = rmap_api.RouteMap("set_sag_nh")
    rmap.add_permit_sequence('10')
    rmap.add_sequence_set_ipv4_next_hop('10', evpn_dict["l3_vni_sag"]["l3_vni_sagip_list"][0])
    rmap.execute_command(evpn_dict["mlag_client"][0])

    rmap = rmap_api.RouteMap("set_sag_nhv6")
    rmap.add_permit_sequence('10')
    rmap.add_sequence_set_ipv6_next_hop_prefer_global('10')
    rmap.add_sequence_set_ipv6_next_hop_global('10', evpn_dict["l3_vni_sag"]["l3_vni_sagipv6_list"][0])
    rmap.execute_command(evpn_dict["mlag_client"][0])

    st.log("configure ebgp session b/w mclag client and leaf nodes")
    for neigh,rem_as in zip([evpn_dict["leaf1"]["l3_tenant_ip_list"][1],evpn_dict["leaf1"]["l3_tenant_ipv6_list"][1],
                             evpn_dict["leaf2"]["l3_tenant_ip_list"][1],evpn_dict["leaf2"]["l3_tenant_ipv6_list"][1]],
                            [evpn_dict["mlag_node"]["rem_as_list"][0]]*2+[evpn_dict["mlag_node"]["rem_as_list"][1]]*2):
        Bgp.config_bgp(dut=evpn_dict["mlag_client"][0], local_as=evpn_dict["mlag_node"]["local_as"], config='yes',
                   config_type_list=["neighbor",'bfd','connect'], remote_as=rem_as, vrf_name=evpn_dict['leaf1']['vrf_name_list'][0],
                       neighbor=neigh,connect=1)
    for neigh in [evpn_dict["leaf1"]["l3_tenant_ipv6_list"][1],evpn_dict["leaf2"]["l3_tenant_ipv6_list"][1]]:
        Bgp.config_bgp(dut=evpn_dict["mlag_client"][0], local_as=evpn_dict["mlag_node"]["local_as"], config='yes',
                   config_type_list=["activate"], neighbor=neigh,addr_family="ipv6",
                   vrf_name=evpn_dict['leaf1']['vrf_name_list'][0])

    for neigh,rem_as,family,rt_map in zip([evpn_dict["leaf1"]["l3_tenant_ip_list"][1],evpn_dict["leaf1"]["l3_tenant_ipv6_list"][1],
                             evpn_dict["leaf2"]["l3_tenant_ip_list"][1],evpn_dict["leaf2"]["l3_tenant_ipv6_list"][1]],
                            [evpn_dict["mlag_node"]["rem_as_list"][0]]*2+[evpn_dict["mlag_node"]["rem_as_list"][1]]*2,
                            ['ipv4','ipv6']*2,["set_sag_nh",'set_sag_nhv6']*2):
        Bgp.config_bgp(dut=evpn_dict["mlag_client"][0], local_as=evpn_dict["mlag_node"]["local_as"], config='yes',
                   config_type_list=['routeMap','max_path_ebgp'],max_path_ebgp=1,diRection='in',
                       routeMap=rt_map,addr_family=family, remote_as=rem_as, vrf_name=evpn_dict['leaf1']['vrf_name_list'][0],
                       neighbor=neigh)


def spine1_verify_evpn():
    global vars
    return retry_api(Evpn.verify_bgp_l2vpn_evpn_summary,dut=evpn_dict["spine_node_list"][0],
                                       identifier=evpn_dict["spine1"]["loop_ip_list"][1],
                                       neighbor=evpn_dict["spine1"]["pch_intf_list"]+
                                                [vars.D1D3P1,vars.D1D3P4,vars.D1D4P1,
                                                 vars.D1D4P4,vars.D1D5P1,vars.D1D5P4],
                                       updown=["up", "up", "up","up","up", "up", "up","up","up"])


def spine2_verify_evpn():
    global vars
    return retry_api(Evpn.verify_bgp_l2vpn_evpn_summary,dut=evpn_dict["spine_node_list"][1],
                                       identifier=evpn_dict["spine2"]["loop_ip_list"][1],
                                       neighbor=evpn_dict["spine2"]["pch_intf_list"]+
                                                [vars.D2D3P1,vars.D1D3P4,vars.D1D4P1,
                                                 vars.D1D4P4,vars.D1D5P1,vars.D1D5P4],
                                       updown=["up", "up", "up","up","up", "up", "up","up","up"])


def leaf1_verify_evpn():
    global vars
    return retry_api(Evpn.verify_bgp_l2vpn_evpn_summary,dut=evpn_dict["leaf_node_list"][0],
                                       identifier=evpn_dict["leaf1"]["loop_ip_list"][1],
                                       neighbor=evpn_dict["leaf1"]["pch_intf_list"]+[vars.D3D1P1,vars.D3D1P4],
                                       updown=["up", "up", "up"])


def leaf2_verify_evpn():
    global vars
    return retry_api(Evpn.verify_bgp_l2vpn_evpn_summary,dut=evpn_dict["leaf_node_list"][1],
                                       identifier=evpn_dict["leaf2"]["loop_ip_list"][1],
                                       neighbor=evpn_dict["leaf2"]["pch_intf_list"]+[vars.D4D1P1,vars.D4D1P4],
                                       updown=["up", "up", "up"])


def leaf3_verify_evpn():
    global vars
    return retry_api(Evpn.verify_bgp_l2vpn_evpn_summary,dut=evpn_dict["leaf_node_list"][2],
                                       identifier=evpn_dict["leaf3"]["loop_ip_list"][1],
                                       neighbor=evpn_dict["leaf3"]["pch_intf_list"]+[vars.D5D1P1,vars.D5D1P4],
                                       updown=["up", "up", "up"])


def leaf1_verify_vxlan():
    return retry_api(Evpn.verify_vxlan_tunnel_status,dut=evpn_dict["leaf_node_list"][0],
                                           src_vtep=evpn_dict["leaf1"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf3"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_up'])


def leaf2_verify_vxlan():
    return retry_api(Evpn.verify_vxlan_tunnel_status,dut=evpn_dict["leaf_node_list"][1],
                                           src_vtep=evpn_dict["leaf2"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf3"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_up'])


def leaf3_verify_vxlan():
    return retry_api(Evpn.verify_vxlan_tunnel_status,dut=evpn_dict["leaf_node_list"][2],
                                           src_vtep=evpn_dict["leaf3"]["loop_ip_list"][1],
                                           rem_vtep_list=[evpn_dict["leaf1"]["loop_ip_list"][1]],
                                           exp_status_list=['oper_up'])


def hdrMsg(msg):
    st.log("\n######################################################################" \
    " \n%s\n######################################################################"%msg)


def create_stream():
    l3_len = 512
    tg=tg_dict["tg"]
    dut5_gateway_mac = evpn_dict["dut5_gw_mac"]
    dut6_gateway_mac = evpn_dict["dut6_gw_mac"]
    mclag_active_node_rmac = get_mclag_lvtep_common_mac()
    evpn_dict["active_mac"] = mclag_active_node_rmac
    evpn_dict["orphan_mac"] = basic.get_ifconfig(vars.D3, "Vlan" + evpn_dict["leaf1"]["tenant_l3_vlan_list"][2])[0][
        'mac']
    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d6_tg_ph1'], port_handle2=tg_dict['d5_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size=tg_dict["frame_size"],
                                  l2_encap='ethernet_ii_vlan', vlan="enable",vlan_id='2000', vlan_id_count=data.l2vni,
                                  vlan_id_mode="increment", vlan_id_step='1',
                                  mac_src=evpn_dict["mlag_node"]["tenant_mac_l2"],
                                  mac_dst=evpn_dict["leaf3"]["tenant_mac_l2"][0],
                                  mac_dst_step="00.00.00.00.00.01",mac_dst_count=data.l2vni,
                                  enable_stream_only_gen=0,enable_stream=0,high_speed_result_analysis=1)

    stream1 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream1, vars.T1D6P1))
    stream_dict["l2_1"] = [stream1]
    stream_dict["l2_unknown"] = stream_dict["l2_1"]
    stream = tg.tg_traffic_config(mode='create', port_handle=tg_dict['d5_tg_ph1'], port_handle2=tg_dict['d6_tg_ph1'],
                                  transmit_mode="continuous", rate_pps=tg_dict['tgen_rate_pps'], frame_size=tg_dict["frame_size"],
                                  l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id='2000', vlan_id_count=data.l2vni,
                                  vlan_id_mode="increment", vlan_id_step='1',
                                  mac_src=evpn_dict["leaf3"]["tenant_mac_l2"][0],
                                  mac_dst=evpn_dict["mlag_node"]["tenant_mac_l2"],
                                  mac_dst_step="00.00.00.00.00.01",mac_dst_count=data.l2vni,
                                  enable_stream_only_gen=0,enable_stream=0,high_speed_result_analysis=1)
    stream2 = stream["stream_id"]
    st.log("L2 stream {} is created for Tgen port {}".format(stream2, vars.T1D5P1))
    stream_dict["l2_2"] = [stream2]
    stream_dict["l2_known"] = stream_dict["l2_1"] + stream_dict["l2_2"]

    stream = tg.tg_traffic_config(mac_src=evpn_dict["mlag_node"]["tenant_mac_v4"], enable_stream_only_gen=0,
                                  enable_stream=0,high_speed_result_analysis=1,mac_dst=dut6_gateway_mac,
                                  vlan='enable',vlan_id=evpn_dict["mlag_node"]["tenant_l3_vlan_list"][0],
                                  rate_pps=tg_dict['tgen_rate_pps'], mode='create',l2_encap='ethernet_ii_vlan',
                                  port_handle=tg_dict['d6_tg_ph2'],transmit_mode='continuous',
                                  l3_protocol='ipv4', ip_src_addr=evpn_dict["mlag_node"]["v4_prefix"][0],
                                  ip_dst_addr=evpn_dict["leaf3"]["v4_prefix"][0],
                                  mac_discovery_gw=evpn_dict["mlag_node"]["l3_tenant_ip_list"][1], ip_dst_step='0.0.1.0',
                                  ip_dst_mode='increment', ip_dst_count=data.ipv4_routes_per_port,port_handle2=tg_dict['d5_tg_ph1'])
    stream3 = stream['stream_id']
    stream_dict["v4scale_1"] = [stream3]
    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_v4"][0], enable_stream_only_gen=0,
                                  enable_stream=0,high_speed_result_analysis=1,mac_dst=dut5_gateway_mac,
                                  vlan='enable',vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
                                  l2_encap='ethernet_ii_vlan', rate_pps=tg_dict['tgen_rate_pps'], mode='create',
                                  port_handle=tg_dict['d5_tg_ph1'],transmit_mode='continuous',
                                  l3_protocol='ipv4', ip_src_addr=evpn_dict["leaf3"]["v4_prefix"][0],
                                  ip_dst_addr=evpn_dict["mlag_node"]["v4_prefix"][0],
                                  mac_discovery_gw=evpn_dict["leaf3"]["l3_tenant_ip_list"][1], ip_dst_step='0.0.1.0',
                                  ip_dst_mode='increment', ip_dst_count=data.ipv4_routes_per_port,port_handle2=tg_dict['d6_tg_ph2'])
    stream4 = stream['stream_id']
    stream_dict["v4scale_2"] = [stream4]
    stream = tg.tg_traffic_config(mac_src=evpn_dict["mlag_node"]["tenant_mac_v6"],enable_stream_only_gen=0 ,
                                  enable_stream=0,high_speed_result_analysis=1,mac_dst=dut6_gateway_mac,
                                  vlan='enable',vlan_id=evpn_dict["mlag_node"]["tenant_l3_vlan_list"][0],
                                  rate_pps=tg_dict['tgen_rate_pps'], mode='create',l2_encap='ethernet_ii_vlan',
                                  port_handle=tg_dict['d6_tg_ph2'],transmit_mode='continuous',
                                  l3_protocol='ipv6', ipv6_src_addr=evpn_dict["mlag_node"]["v6_prefix"][0],
                                  ipv6_dst_addr=evpn_dict["leaf3"]["v6_prefix"][0],port_handle2=tg_dict['d5_tg_ph1'],
                                  mac_discovery_gw=evpn_dict["mlag_node"]["l3_tenant_ipv6_list"][1],
                                  ipv6_dst_step='0:0:0:1::0',ipv6_dst_mode='increment', ipv6_dst_count=data.ipv6_routes_per_port)
    stream5 = stream['stream_id']
    stream_dict["v6scale_1"] = [stream5]
    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf3"]["tenant_mac_v6_2"][1],enable_stream_only_gen=0 ,
                                  enable_stream=0,high_speed_result_analysis=1,mac_dst=dut5_gateway_mac,
                                  vlan='enable', vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][1],
                                  l2_encap='ethernet_ii_vlan', rate_pps=tg_dict['tgen_rate_pps'], mode='create',
                                  port_handle=tg_dict['d5_tg_ph1'],transmit_mode='continuous',
                                  l3_protocol='ipv6', ipv6_src_addr=evpn_dict["leaf3"]["v6_prefix"][0],
                                  ipv6_dst_addr=evpn_dict["mlag_node"]["v6_prefix"][0],
                                  port_handle2=tg_dict['d6_tg_ph2'],
                                  mac_discovery_gw=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][1], ipv6_dst_step='0:0:0:1::0',
                                  ipv6_dst_mode='increment', ipv6_dst_count=data.ipv6_routes_per_port)
    stream6 = stream['stream_id']
    stream_dict["v6scale_2"] = [stream6]
    stream_dict['scale'] = stream_dict['v4scale_1'] +stream_dict['v4scale_2']+stream_dict['v6scale_1'] +stream_dict['v6scale_2']

    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_v4"][2], enable_stream_only_gen=0,
                                  enable_stream=0,high_speed_result_analysis=1,mac_dst=evpn_dict["orphan_mac"],
                                  vlan='enable',vlan_id=evpn_dict["leaf1"]["tenant_l3_vlan_list"][2],
                                  rate_pps=tg_dict['tgen_rate_pps'], mode='create',l2_encap='ethernet_ii_vlan',
                                  port_handle=tg_dict['d3_tg_ph1'],transmit_mode='continuous',
                                  l3_protocol='ipv4', ip_src_addr=evpn_dict["leaf1"]["tenant_v4_ip"][2],
                                  ip_dst_addr=evpn_dict["leaf3"]["v4_prefix"][0],
                                  mac_discovery_gw=evpn_dict["leaf1"]["l3_tenant_ip_list"][2],
                                  port_handle2=tg_dict['d5_tg_ph1'])
    stream7 = stream['stream_id']
    stream_dict["v4orphan_1"] = [stream7]
    host = tg.tg_interface_config(port_handle=tg_dict["d3_tg_ph1"], mode='config',
                                   intf_ip_addr=evpn_dict["leaf1"]["tenant_v4_ip"][2],
                                   vlan_id=evpn_dict["leaf1"]["tenant_l3_vlan_list"][2], vlan='1',
                                   gateway=evpn_dict["leaf1"]["l3_tenant_ip_list"][2],
                                   src_mac_addr=evpn_dict["leaf1"]["tenant_mac_v4"][2],
                                   arp_send_req='1', netmask='255.255.255.0')
    han_dict["v4orphan_host"] = host["handle"]
    stream = tg.tg_traffic_config(mac_src=evpn_dict["leaf1"]["tenant_mac_v6"][2],enable_stream_only_gen=0 ,
                                  enable_stream=0,high_speed_result_analysis=1,mac_dst=evpn_dict["orphan_mac"],
                                  vlan='enable',vlan_id=evpn_dict["leaf1"]["tenant_l3_vlan_list"][2],
                                  rate_pps=tg_dict['tgen_rate_pps'], mode='create',l2_encap='ethernet_ii_vlan',
                                  port_handle=tg_dict['d3_tg_ph1'],transmit_mode='continuous',
                                  l3_protocol='ipv6', ipv6_src_addr=evpn_dict["leaf1"]["tenant_v6_ip"][2],
                                  ipv6_dst_addr=evpn_dict["leaf3"]["v6_prefix"][0],port_handle2=tg_dict['d5_tg_ph1'],
                                  mac_discovery_gw=evpn_dict["leaf1"]["l3_tenant_ipv6_list"][2])
    stream8 = stream['stream_id']
    stream_dict["v6orphan_1"] = [stream8]
    host = tg.tg_interface_config(port_handle=tg_dict["d3_tg_ph1"], mode='config',
                                   ipv6_intf_addr=evpn_dict["leaf1"]["tenant_v6_ip"][2],
                                   vlan_id=evpn_dict["leaf1"]["tenant_l3_vlan_list"][2], vlan='1',
                                   src_mac_addr=evpn_dict["leaf1"]["tenant_mac_v6"][2],arp_send_req='1',
                                   ipv6_prefix_length='96', ipv6_gateway=evpn_dict["leaf1"]["l3_tenant_ipv6_list"][2])
    han_dict["v6orphan_host"] = host["handle"]
    stream_dict['orphan_traffic']= stream_dict['v4orphan_1']


def start_traffic(stream_han_list=[],port_han_list=[],action="run"):
    if action=="run":
        if tg_dict["tg"].tg_type == 'stc':
            tg_dict["tg"].tg_traffic_control(action="run", stream_handle=stream_han_list)
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
        tg_dict["tg"].tg_traffic_control(action='clear_stats',port_handle=[d5_tg_ph1,d5_tg_ph1])


def verify_traffic(tx_port="", rx_port="", tx_ratio=1, rx_ratio=1,
                       field="packet_count",direction="2", **kwargs):
    '''
    :param tx_port:
    :param rx_port:
    :param tx_ratio:
    :param rx_ratio:
    :param field:
    :param direction:
    :param kwargs["tx_stream_list"]:
    :param kwargs["rx_stream_list"]:
    :return:
    '''

    if not tx_port:
        tx_port=tg_dict["d6_tg_port1"]
    if not rx_port:
        rx_port=tg_dict["d5_tg_port1"]

    if int(direction) == 2:
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
    else:
        traffic_details = {
            '1': {
                'tx_ports': [tx_port],
                'tx_obj': [tg_dict["tg"]],
                'exp_ratio': [tx_ratio],
                'rx_ports': [rx_port],
                'rx_obj': [tg_dict["tg"]],
                'stream_list': [tuple(kwargs["tx_stream_list"])]
            }
        }
    return tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode="streamblock",
                                       comp_type=field, tolerance_factor=1)


def reset_tgen(port_han_list=[]):
    if port_han_list:
        tg_dict["tg"].tg_traffic_control(action="reset", port_handle=port_han_list)
    else:
        tg_dict["tg"].tg_traffic_control(action="reset", port_handle=[d5_tg_ph1,d5_tg_ph1])


def spine1_setup_5549():

    st.log("create port channel interface b/w spine1 and all leaf nodes")
    for portchannel in [evpn_dict["spine1"]["pch_intf_list"][0],evpn_dict["spine1"]["pch_intf_list"][1],
                        evpn_dict["spine1"]["pch_intf_list"][2]]:
        pch.create_portchannel(dut=evpn_dict["spine_node_list"][0],portchannel_list=portchannel)

    st.log("Add members to port channel created b/w spine1 and all leaf nodes")
    for portchannel,member in zip([evpn_dict["spine1"]["pch_intf_list"][0],evpn_dict["spine1"]["pch_intf_list"][1],
                                   evpn_dict["spine1"]["pch_intf_list"][2]],
                                  [evpn_dict["spine1"]["intf_list_leaf"][1:3],
                                   evpn_dict["spine1"]["intf_list_leaf"][5:7],
                                   evpn_dict["spine1"]["intf_list_leaf"][9:11]]):
        pch.add_portchannel_member(dut=evpn_dict["spine_node_list"][0],portchannel=portchannel,members=member)

    st.log("Enable portchannel interface b/w spine1 and all leaf nodes")
    Intf.interface_operation(dut=evpn_dict["spine_node_list"][0],
                             interfaces=evpn_dict["spine1"]["pch_intf_list"], operation="startup")

    ############################################################################################
    hdrMsg("\n####### Configure IPv6 link local address b/w spine1 and all leaf ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["spine_node_list"][0],
                                       interface_list=[evpn_dict["spine1"]["intf_list_leaf"][0],
                                                       evpn_dict["spine1"]["intf_list_leaf"][3],
                                                       evpn_dict["spine1"]["intf_list_leaf"][4],
                                                       evpn_dict["spine1"]["intf_list_leaf"][7],
                                                       evpn_dict["spine1"]["intf_list_leaf"][8],
                                                       evpn_dict["spine1"]["intf_list_leaf"][11]])
    ############################################################################################
    hdrMsg("\n########## Configure IPv6 link local address for LAG(link 2 & 3) b/w spine1 and all leaf#############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["spine_node_list"][0],
                                       interface_list=evpn_dict["spine1"]["pch_intf_list"])

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
        Bgp.config_bgp(dut=evpn_dict["bgp_node_list"][0], local_as=evpn_dict["spine1"]["local_as"],config='yes',
                           config_type_list=["bfd"], remote_as='external', interface=link1)
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
    Bgp.config_bgp_always_compare_med(dut=evpn_dict["spine_node_list"][0], local_asn=evpn_dict["spine1"]["local_as"])


def spine2_setup_5549():

    st.log("create port channel interface b/w spine2 and all leaf nodes")
    for portchannel in [evpn_dict["spine2"]["pch_intf_list"][0],evpn_dict["spine2"]["pch_intf_list"][1],
                        evpn_dict["spine2"]["pch_intf_list"][2]]:
        pch.create_portchannel(dut=evpn_dict["spine_node_list"][1],portchannel_list=portchannel)

    st.log("Add members to port channel created b/w spine2 and all leaf nodes")
    for portchannel,member in zip([evpn_dict["spine2"]["pch_intf_list"][0],evpn_dict["spine2"]["pch_intf_list"][1],
                                   evpn_dict["spine2"]["pch_intf_list"][2]],
                                  [evpn_dict["spine2"]["intf_list_leaf"][1:3],
                                   evpn_dict["spine2"]["intf_list_leaf"][5:7],
                                   evpn_dict["spine2"]["intf_list_leaf"][9:11]]):
        pch.add_portchannel_member(dut=evpn_dict["spine_node_list"][1],portchannel=portchannel,members=member)

    st.log("Enable portchannel interface b/w spine2 and all leaf nodes")
    Intf.interface_operation(dut=evpn_dict["spine_node_list"][1],
                             interfaces=evpn_dict["spine2"]["pch_intf_list"], operation="startup")

    ############################################################################################
    hdrMsg("\n####### Configure IPv6 link local address b/w spine2 and all leaf ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["spine_node_list"][1],
                                       interface_list=[evpn_dict["spine2"]["intf_list_leaf"][0],
                                                       evpn_dict["spine2"]["intf_list_leaf"][3],
                                                       evpn_dict["spine2"]["intf_list_leaf"][4],
                                                       evpn_dict["spine2"]["intf_list_leaf"][7],
                                                       evpn_dict["spine2"]["intf_list_leaf"][8],
                                                       evpn_dict["spine2"]["intf_list_leaf"][11]])
    ############################################################################################
    hdrMsg("\n########## Configure IPv6 link local address for LAG(link 2 & 3) b/w spine2 and all leaf#############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["spine_node_list"][1],
                                       interface_list=evpn_dict["spine2"]["pch_intf_list"])

    ############################################################################################
    hdrMsg("\n########## Enable router bgp and configure router id in DUT2 node ##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["bgp_node_list"][1],local_as=evpn_dict["spine2"]["local_as"],
                   router_id=evpn_dict["spine2"]["loop_ip_list"][1],config="yes",
                   config_type_list=['router_id',"multipath-relax"])

    spine_link_list = [evpn_dict["spine2"]["intf_list_leaf"][0], evpn_dict["spine2"]["pch_intf_list"][0],
                       evpn_dict["spine2"]["intf_list_leaf"][3], evpn_dict["spine2"]["intf_list_leaf"][4],
                       evpn_dict["spine2"]["pch_intf_list"][1], evpn_dict["spine2"]["intf_list_leaf"][7],
                       evpn_dict["spine2"]["intf_list_leaf"][8], evpn_dict["spine2"]["pch_intf_list"][2],
                       evpn_dict["spine2"]["intf_list_leaf"][11]]
    for link1 in spine_link_list:
        Bgp.config_bgp(dut=evpn_dict["bgp_node_list"][1], local_as=evpn_dict["spine2"]["local_as"],config='yes',
                           config_type_list=["neighbor"], remote_as='external', neighbor=link1)
        Bgp.config_bgp(dut=evpn_dict["bgp_node_list"][1], local_as=evpn_dict["spine2"]["local_as"],config='yes',
                           config_type_list=["bfd"], remote_as='external', interface=link1)
        Evpn.config_bgp_evpn(dut=evpn_dict["bgp_node_list"][1],local_as=evpn_dict["spine2"]["local_as"], config='yes',
                             config_type_list=["activate"],remote_as='external',neighbor=link1)

    Evpn.config_bgp_evpn(dut=evpn_dict["bgp_node_list"][1], local_as=evpn_dict["spine2"]["local_as"], config='yes',
                         config_type_list=["advertise_all_vni"])

    ############################################################################################
    hdrMsg(" \n####### Configure loopback interface in DUT2 ##############\n")
    ############################################################################################
    ip.configure_loopback(dut=evpn_dict["spine_node_list"][1],loopback_name='Loopback1', config='yes')
    ip.config_ip_addr_interface(dut=evpn_dict["bgp_node_list"][1],interface_name='Loopback1',
                                ip_address=evpn_dict["spine2"]["loop_ip_list"][1],subnet=32)

    ############################################################################################
    hdrMsg(" \n####### Redistribute connected route in to bgp in DUT2 ##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["spine_node_list"][1],local_as=evpn_dict["spine2"]["local_as"],
                   config_type_list=['redist'],redistribute='connected')
    Bgp.config_bgp_always_compare_med(dut=evpn_dict["spine_node_list"][1], local_asn=evpn_dict["spine2"]["local_as"])


def leaf1_setup_5549():
    st.log("create port channel interface b/w leaf1 and spine nodes")
    pch.create_portchannel(dut=evpn_dict["leaf_node_list"][0],portchannel_list=evpn_dict["leaf1"]["pch_intf_list"])

    st.log("Add members to port channel created b/w leaf1 and spine nodes")
    for pch_name,mem_port in zip(evpn_dict["leaf1"]["pch_intf_list"],[evpn_dict["leaf1"]["intf_list_spine"][1:3],
                                                                      evpn_dict["leaf1"]["intf_list_spine"][5:7]]):
        pch.add_portchannel_member(dut=evpn_dict["leaf_node_list"][0],portchannel=pch_name,members=mem_port)

    st.log("Enable portchannel interface on all leaf1 and spine nodes")
    Intf.interface_operation(dut=evpn_dict["leaf_node_list"][0],
                             interfaces=evpn_dict["leaf1"]["pch_intf_list"], operation="startup")

    ############################################################################################
    hdrMsg("\n####### Configure IPv6 link local address b/w leaf1 and spine ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["leaf_node_list"][0],
                                       interface_list=[evpn_dict["leaf1"]["intf_list_spine"][0],
                                                       evpn_dict["leaf1"]["intf_list_spine"][3],
                                                       evpn_dict["leaf1"]["intf_list_spine"][4],
                                                       evpn_dict["leaf1"]["intf_list_spine"][7]])
    ############################################################################################
    hdrMsg("\n########## Configure IPv6 link local address for LAG(link 2 & 3) b/w leaf1 and spine ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["leaf_node_list"][0],
                                       interface_list=evpn_dict["leaf1"]["pch_intf_list"])

    ############################################################################################
    hdrMsg("\n########## Enable router bgp and configure router id in DUT3 ##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0],local_as=evpn_dict["leaf1"]["local_as"],
                   router_id=evpn_dict["leaf1"]["loop_ip_list"][1],config="yes",
                   config_type_list=['router_id',"multipath-relax","max_path_ebgp"],max_path_ebgp=10)
    Bgp.config_bgp_max_med(dut=evpn_dict["leaf_node_list"][0],config="yes",local_asn=evpn_dict["leaf1"]["local_as"],
                           on_start_time=660,on_start_med=4294967295)
    for link1 in [evpn_dict["leaf1"]["intf_list_spine"][0], evpn_dict["leaf1"]["intf_list_spine"][3],
                  evpn_dict["leaf1"]["intf_list_spine"][4],evpn_dict["leaf1"]["intf_list_spine"][7]]\
                 +evpn_dict["leaf1"]["pch_intf_list"]:
        Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0], local_as=evpn_dict["leaf1"]["local_as"],config='yes',
                           config_type_list=["neighbor"], remote_as='external', neighbor=link1)
        Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0], local_as=evpn_dict["leaf1"]["local_as"],config='yes',
                           config_type_list=["bfd"], remote_as='external', interface=link1)
        Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][0],local_as=evpn_dict["leaf1"]["local_as"], config='yes',
                             config_type_list=["activate"],remote_as='external',neighbor=link1)
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][0], local_as=evpn_dict["leaf1"]["local_as"], config='yes',
                         config_type_list=["advertise_all_vni"])
    Evpn.create_linktrack(evpn_dict["leaf_node_list"][0], "track1", config='yes')
    for intf in evpn_dict["leaf1"]["pch_intf_list"]:
        Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][0], "track1", intf, "90")

    ############################################################################################
    hdrMsg(" \n####### Configure loopback interface in DUT3##############\n")
    ############################################################################################
    ip.configure_loopback(dut=evpn_dict["leaf_node_list"][0],loopback_name='Loopback1', config='yes')
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][0],interface_name='Loopback1',
                                ip_address=evpn_dict["leaf1"]["loop_ip_list"][1],subnet=32)

    ############################################################################################
    hdrMsg(" \n####### Redistribute connected route in to bgp in DUT3##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][0],local_as=evpn_dict["leaf1"]["local_as"],
                   config_type_list=['redist'],redistribute='connected')


def leaf2_setup_5549():
    st.log("create port channel interface b/w leaf2 and spine nodes")
    pch.create_portchannel(dut=evpn_dict["leaf_node_list"][1],portchannel_list=evpn_dict["leaf2"]["pch_intf_list"])

    st.log("Add members to port channel created b/w leaf2 and spine nodes")
    for pch_name,mem_port in zip(evpn_dict["leaf2"]["pch_intf_list"],[evpn_dict["leaf2"]["intf_list_spine"][1:3],
                                                                      evpn_dict["leaf2"]["intf_list_spine"][5:7]]):
        pch.add_portchannel_member(dut=evpn_dict["leaf_node_list"][1],portchannel=pch_name,members=mem_port)

    st.log("Enable portchannel interface on all leaf2 and spine nodes")
    Intf.interface_operation(dut=evpn_dict["leaf_node_list"][1],
                             interfaces=evpn_dict["leaf2"]["pch_intf_list"], operation="startup")

    ############################################################################################
    hdrMsg("\n####### Configure IPv6 link local address b/w leaf2 and spine ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["leaf_node_list"][1],
                                       interface_list=[evpn_dict["leaf2"]["intf_list_spine"][0],
                                                       evpn_dict["leaf2"]["intf_list_spine"][3],
                                                       evpn_dict["leaf2"]["intf_list_spine"][4],
                                                       evpn_dict["leaf2"]["intf_list_spine"][7]])
    ############################################################################################
    hdrMsg("\n########## Configure IPv6 link local address for LAG(link 2 & 3) b/w leaf1 and spine ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["leaf_node_list"][1],
                                       interface_list=evpn_dict["leaf2"]["pch_intf_list"])

    ############################################################################################
    hdrMsg("\n########## Enable router bgp and configure router id in DUT4##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1],local_as=evpn_dict["leaf2"]["local_as"],
                   router_id=evpn_dict["leaf2"]["loop_ip_list"][1],config="yes",
                   config_type_list=['router_id',"multipath-relax","max_path_ebgp"],max_path_ebgp=10)
    Bgp.config_bgp_max_med(dut=evpn_dict["leaf_node_list"][1],config="yes",local_asn=evpn_dict["leaf2"]["local_as"],
                           on_start_time=660,on_start_med=4294967295)
    for link1 in [evpn_dict["leaf2"]["intf_list_spine"][0], evpn_dict["leaf2"]["intf_list_spine"][3],
                  evpn_dict["leaf2"]["intf_list_spine"][4],evpn_dict["leaf2"]["intf_list_spine"][7]] \
                 +evpn_dict["leaf2"]["pch_intf_list"]:
        Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1], local_as=evpn_dict["leaf2"]["local_as"],config='yes',
                           config_type_list=["neighbor"], remote_as='external', neighbor=link1)
        Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1], local_as=evpn_dict["leaf2"]["local_as"],config='yes',
                           config_type_list=["bfd"], remote_as='external', interface=link1)
        Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][1],local_as=evpn_dict["leaf2"]["local_as"], config='yes',
                             config_type_list=["activate"],remote_as='external',neighbor=link1)

    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][1], local_as=evpn_dict["leaf2"]["local_as"], config='yes',
                         config_type_list=["advertise_all_vni"])
    Evpn.create_linktrack(evpn_dict["leaf_node_list"][1], "track1", config='yes')
    for intf in evpn_dict["leaf2"]["pch_intf_list"]:
        Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1], "track1",intf, "90")
    #Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1], "track1",evpn_dict["leaf2"]["intf_list_spine"][4] , "20")
    #Evpn.update_linktrack_interface(evpn_dict["leaf_node_list"][1], "track1", evpn_dict["leaf2"]["intf_list_spine"][7], "20")

    ############################################################################################
    hdrMsg(" \n####### Configure loopback interface in DUT4##############\n")
    ############################################################################################
    ip.configure_loopback(dut=evpn_dict["leaf_node_list"][1],loopback_name='Loopback1', config='yes')
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][1],interface_name='Loopback1',
                                ip_address=evpn_dict["leaf2"]["loop_ip_list"][1],subnet=32)

    ############################################################################################
    hdrMsg(" \n####### Redistribute connected route in to bgp in DUT4##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][1],local_as=evpn_dict["leaf2"]["local_as"],
                   config_type_list=['redist'],redistribute='connected')


def leaf3_setup_5549():
    st.log("create port channel interface b/w leaf3 and spine nodes")
    pch.create_portchannel(dut=evpn_dict["leaf_node_list"][2],portchannel_list=evpn_dict["leaf3"]["pch_intf_list"])

    st.log("Add members to port channel created b/w leaf3 and spine nodes")
    for pch_name,mem_port in zip(evpn_dict["leaf3"]["pch_intf_list"],[evpn_dict["leaf3"]["intf_list_spine"][1:3],
                                                                      evpn_dict["leaf3"]["intf_list_spine"][5:7]]):
        pch.add_portchannel_member(dut=evpn_dict["leaf_node_list"][2],portchannel=pch_name,members=mem_port)

    st.log("Enable portchannel interface b/w leaf3 and spine nodes")
    Intf.interface_operation(dut=evpn_dict["leaf_node_list"][2],
                             interfaces=evpn_dict["leaf3"]["pch_intf_list"], operation="startup")

    ############################################################################################
    hdrMsg("\n####### Configure IPv6 link local address b/w leaf3 and spine ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["leaf_node_list"][2],
                                       interface_list=[evpn_dict["leaf3"]["intf_list_spine"][0],
                                                       evpn_dict["leaf3"]["intf_list_spine"][3],
                                                       evpn_dict["leaf3"]["intf_list_spine"][4],
                                                       evpn_dict["leaf3"]["intf_list_spine"][7]])
    ############################################################################################
    hdrMsg("\n########## Configure IPv6 link local address for LAG(link 2 & 3) b/w leaf3 and spine ##############\n")
    ############################################################################################
    ip.config_interface_ip6_link_local(dut=evpn_dict["leaf_node_list"][2],
                                       interface_list=evpn_dict["leaf3"]["pch_intf_list"])

    ############################################################################################
    hdrMsg("\n########## Enable router bgp and configure router id in DUT5##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict["leaf3"]["local_as"],
                   router_id=evpn_dict["leaf3"]["loop_ip_list"][1],config="yes",
                   config_type_list=['router_id',"multipath-relax",'max_path_ebgp'],max_path_ebgp=10)
    Bgp.config_bgp_max_med(dut=evpn_dict["leaf_node_list"][2],config="yes",local_asn=evpn_dict["leaf3"]["local_as"],
                           on_start_time=660,on_start_med=4294967295)
    for link1 in [evpn_dict["leaf3"]["intf_list_spine"][0],evpn_dict["leaf3"]["intf_list_spine"][3],
                  evpn_dict["leaf3"]["intf_list_spine"][4],evpn_dict["leaf3"]["intf_list_spine"][7]]\
                 +evpn_dict["leaf3"]["pch_intf_list"]:
        Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2], local_as=evpn_dict["leaf3"]["local_as"],config='yes',
                           config_type_list=["neighbor"], remote_as='external', neighbor=link1)
        Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2], local_as=evpn_dict["leaf3"]["local_as"],config='yes',
                           config_type_list=["bfd"], remote_as='external', interface=link1)
        Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict["leaf3"]["local_as"], config='yes',
                             config_type_list=["activate"],remote_as='external',neighbor=link1)
    Evpn.config_bgp_evpn(dut=evpn_dict["leaf_node_list"][2], local_as=evpn_dict["leaf3"]["local_as"], config='yes',
                         config_type_list=["advertise_all_vni"])
    ############################################################################################
    hdrMsg(" \n####### Configure loopback interface in DUT5##############\n")
    ############################################################################################
    ip.configure_loopback(dut=evpn_dict["leaf_node_list"][2],loopback_name='Loopback1', config='yes')
    ip.config_ip_addr_interface(dut=evpn_dict["leaf_node_list"][2],interface_name='Loopback1',
                                ip_address=evpn_dict["leaf3"]["loop_ip_list"][1],subnet=32)
    ############################################################################################
    hdrMsg(" \n####### Redistribute connected route in to bgp in DUT5##############\n")
    ############################################################################################
    Bgp.config_bgp(dut=evpn_dict["leaf_node_list"][2],local_as=evpn_dict["leaf3"]["local_as"],
                   config_type_list=['redist'],redistribute='connected')


def spine1_bgpgr_config():
    Bgp.config_bgp_graceful_restart(vars.D1,local_asn=evpn_dict["spine1"]["local_as"],
                                    config="add", preserve_state="yes")
    Bgp.clear_ip_bgp_vtysh(vars.D1)


def spine2_bgpgr_config():
    Bgp.config_bgp_graceful_restart(vars.D2,local_asn=evpn_dict["spine2"]["local_as"],
                                    config="add", preserve_state="yes")
    Bgp.clear_ip_bgp_vtysh(vars.D2)


def leaf1_bgpgr_config():
    Bgp.config_bgp_graceful_restart(vars.D3,local_asn=evpn_dict["leaf1"]["local_as"],
                                    config="add", preserve_state="yes")
    Bgp.clear_ip_bgp_vtysh(vars.D3)


def leaf2_bgpgr_config():
    Bgp.config_bgp_graceful_restart(vars.D4,local_asn=evpn_dict["leaf2"]["local_as"],
                                    config="add", preserve_state="yes")
    Bgp.clear_ip_bgp_vtysh(vars.D4)


def leaf3_bgpgr_config():
    Bgp.config_bgp_graceful_restart(vars.D5,local_asn=evpn_dict["leaf3"]["local_as"],
                                    config="add", preserve_state="yes")
    Bgp.clear_ip_bgp_vtysh(vars.D5)


def client_emulate_bgp():
    Bgp.config_bgp(evpn_dict["mlag_client"][0],local_as=evpn_dict['mlag_node']['local_as'],
                   neighbor=evpn_dict["mlag_node"]["tenant_v4_ip_2"][0],config_type_list=["neighbor","connect"],
                   remote_as=evpn_dict["mlag_node"]["rem_as_list"][2],connect="3",
                   vrf_name=evpn_dict['leaf1']['vrf_name_list'][0])
    Bgp.config_bgp(evpn_dict["mlag_client"][0],addr_family="ipv6",local_as=evpn_dict['mlag_node']['local_as'],
                   neighbor=evpn_dict["mlag_node"]["tenant_v6_ip_2"][0],
                   config_type_list=["neighbor","connect","activate"],
                   remote_as=evpn_dict["mlag_node"]["rem_as_list"][2],connect="3",
                    vrf_name=evpn_dict['leaf1']['vrf_name_list'][0])

def leaf3_emulate_bgp():
    Bgp.config_bgp(evpn_dict["leaf_node_list"][2],local_as=evpn_dict['leaf3']['local_as'],
                   neighbor=evpn_dict["leaf3"]["tenant_v4_ip"][1],config_type_list=["neighbor","connect"],remote_as=1500,
                   vrf_name=evpn_dict['leaf3']['vrf_name_list'][0],connect="3")
    Bgp.config_bgp(evpn_dict["leaf_node_list"][2],addr_family="ipv6",local_as=evpn_dict['leaf3']['local_as'],
                   neighbor=evpn_dict["leaf3"]["tenant_v6_ip"][1],config_type_list=["neighbor","connect","activate"],
                   remote_as=1500,connect="3",vrf_name=evpn_dict['leaf3']['vrf_name_list'][0])


def tgen_emulate_bgp():
    tg = tg_dict['tg']
    host1 = tg.tg_interface_config(port_handle=tg_dict["d6_tg_ph2"], mode='config',
                                   intf_ip_addr=evpn_dict["mlag_node"]["tenant_v4_ip_2"][0],
                                   vlan_id=evpn_dict["mlag_node"]["tenant_l3_vlan_list"][0], vlan='1',
                                   gateway=evpn_dict["mlag_node"]["l3_tenant_ip_list"][1],
                                   src_mac_addr=evpn_dict["mlag_node"]["tenant_mac_v4"],
                                   arp_send_req='1', netmask='255.255.255.0')
    host2 = tg.tg_interface_config(port_handle=tg_dict["d5_tg_ph1"], mode='config',
                                   intf_ip_addr=evpn_dict["leaf3"]["tenant_v4_ip"][1],
                                   vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][1], vlan='1',
                                   gateway=evpn_dict["leaf3"]["l3_tenant_ip_list"][1],
                                   src_mac_addr=evpn_dict["leaf3"]["tenant_mac_v4_2"][0],arp_send_req='1',
                                   netmask='255.255.255.0')
    bgp_r1 = tg.tg_emulation_bgp_config(handle=host1['handle'], mode='enable', active_connect_enable='1',
                                        local_as=evpn_dict["mlag_node"]["rem_as_list"][2],
                                        remote_as=evpn_dict["mlag_node"]["local_as"],
                                        remote_ip_addr=evpn_dict["mlag_node"]["l3_tenant_ip_list"][1])
    bgp_r2 = tg.tg_emulation_bgp_config(handle=host2['handle'], mode='enable', active_connect_enable='1',
                                        local_as=evpn_dict["leaf3"]["rem_as_list"][2],
                                        remote_as=evpn_dict["leaf3"]["local_as"],
                                        remote_ip_addr=evpn_dict["leaf3"]["l3_tenant_ip_list"][1])
    bgp_rout1 = tg.tg_emulation_bgp_route_config(handle=bgp_r1['handle'], mode='add', num_routes=data.ipv4_routes_per_port,
                                                 prefix=evpn_dict["mlag_node"]["v4_prefix"][0],
                                                 as_path='as_seq:'+evpn_dict["mlag_node"]["rem_as_list"][2])
    bgp_rout2 = tg.tg_emulation_bgp_route_config(handle=bgp_r2['handle'], mode='add', num_routes=data.ipv4_routes_per_port,
                                                 prefix=evpn_dict["leaf3"]["v4_prefix"][0],
                                                 as_path='as_seq:'+evpn_dict["leaf3"]["rem_as_list"][2])
    tg.tg_emulation_bgp_control(handle=bgp_r1['handle'], mode='start')
    tg.tg_emulation_bgp_control(handle=bgp_r2['handle'], mode='start')
    host3 = tg.tg_interface_config(port_handle=tg_dict["d6_tg_ph2"], mode='config',
                                   ipv6_intf_addr=evpn_dict["mlag_node"]["tenant_v6_ip_2"][0],
                                   vlan_id=evpn_dict["mlag_node"]["tenant_l3_vlan_list"][0], vlan='1',
                                   src_mac_addr=evpn_dict["mlag_node"]["tenant_mac_v6"],arp_send_req='1',
                                   ipv6_prefix_length='96', ipv6_gateway=evpn_dict["mlag_node"]["l3_tenant_ipv6_list"][1])
    host4 = tg.tg_interface_config(port_handle=tg_dict["d5_tg_ph1"], mode='config',
                                   ipv6_intf_addr=evpn_dict["leaf3"]["tenant_v6_ip"][1],
                                   vlan_id=evpn_dict["leaf3"]["tenant_l3_vlan_list"][1], vlan='1',
                                   src_mac_addr=evpn_dict["leaf3"]["tenant_mac_v6_2"][0],arp_send_req='1',
                                   ipv6_prefix_length='96', ipv6_gateway=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][1])
    bgp_r3 = tg.tg_emulation_bgp_config(handle=host3['handle'], mode='enable', active_connect_enable='1',
                                        local_as=evpn_dict["mlag_node"]["rem_as_list"][2],
                                        remote_as=evpn_dict["mlag_node"]["local_as"],
                                        remote_ipv6_addr=evpn_dict["mlag_node"]["l3_tenant_ipv6_list"][1],
                                        ip_version='6')
    bgp_r4 = tg.tg_emulation_bgp_config(handle=host4['handle'], mode='enable', active_connect_enable='1',
                                        local_as=evpn_dict["leaf3"]["rem_as_list"][2],
                                        remote_as=evpn_dict["leaf3"]["local_as"],
                                        remote_ipv6_addr=evpn_dict["leaf3"]["l3_tenant_ipv6_list"][1],
                                        ip_version='6')
    bgp_rout3 = tg.tg_emulation_bgp_route_config(handle=bgp_r3['handle'], mode='add', num_routes=data.ipv6_routes_per_port,
                                                 prefix=evpn_dict["mlag_node"]["v6_prefix"][0],
                                                 as_path='as_seq:'+evpn_dict["mlag_node"]["rem_as_list"][2],ip_version='6')
    bgp_rout4 = tg.tg_emulation_bgp_route_config(handle=bgp_r4['handle'], mode='add', num_routes=data.ipv6_routes_per_port,
                                                 prefix=evpn_dict["leaf3"]["v6_prefix"][0],
                                                 as_path='as_seq:'+evpn_dict["leaf3"]["rem_as_list"][2],ip_version='6')
    tg.tg_emulation_bgp_control(handle=bgp_r3['handle'], mode='start')
    tg.tg_emulation_bgp_control(handle=bgp_r4['handle'], mode='start')


def leaf1_scale_l2vni():
    st.log("create vlans from 2000 to 3000 in Leaf1")
    vlan_range_start = '2000'
    vlan_range_end = int(vlan_range_start) + int(data.l2vni)
    Vlan.config_vlan_range(evpn_dict["leaf_node_list"][0], vlan_range="{} {}".format(vlan_range_start,vlan_range_end),
                           config="add",cli_type="click")
    for port_name in [evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],evpn_dict["leaf1"]["mlag_pch_intf_list"]]:
        Vlan.config_vlan_range_members(evpn_dict["leaf_node_list"][0],
                                       vlan_range="{} {}".format(vlan_range_start,vlan_range_end),
                                       port=port_name, config='add',cli_type="click")
    Evpn.map_vlan_vni(evpn_dict["leaf_node_list"][0], vtep_name=evpn_dict["leaf1"]["vtepName"],
                      vlan_id="2000", vni_id="2000", range_val=data.l2vni)


def leaf2_scale_l2vni():
    st.log("create vlans from 2000 to 3000 in Leaf2")
    vlan_range_start = '2000'
    vlan_range_end = int(vlan_range_start) + int(data.l2vni)
    Vlan.config_vlan_range(evpn_dict["leaf_node_list"][1], vlan_range="{} {}".format(vlan_range_start,vlan_range_end),
                           config="add",cli_type="click")
    for port_name in [evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],evpn_dict["leaf2"]["mlag_pch_intf_list"]]:
        Vlan.config_vlan_range_members(evpn_dict["leaf_node_list"][1],
                                       vlan_range="{} {}".format(vlan_range_start,vlan_range_end),
                                       port=port_name, config='add',cli_type="click")
    Evpn.map_vlan_vni(evpn_dict["leaf_node_list"][1], vtep_name=evpn_dict["leaf2"]["vtepName"],
                      vlan_id="2000", vni_id="2000", range_val=data.l2vni)


def leaf3_scale_l2vni():
    st.log("create vlans from 2000 to 3000 in Leaf3")
    vlan_range_start = '2000'
    vlan_range_end = int(vlan_range_start) + int(data.l2vni)
    Vlan.config_vlan_range(evpn_dict["leaf_node_list"][2], vlan_range="{} {}".format(vlan_range_start,vlan_range_end)
                           , config="add",cli_type="click")
    Vlan.config_vlan_range_members(evpn_dict["leaf_node_list"][2], vlan_range="{} {}".format(vlan_range_start,vlan_range_end),
                               port=evpn_dict["leaf3"]["intf_list_tg"][0], config='add',cli_type="click")
    Evpn.map_vlan_vni(evpn_dict["leaf_node_list"][2], vtep_name=evpn_dict["leaf3"]["vtepName"],
                      vlan_id="2000", vni_id="2000", range_val=data.l2vni)


def client_scale_l2vni():
    vlan_range_start = '2000'
    vlan_range_end = int(vlan_range_start) + int(data.l2vni)
    Vlan.config_vlan_range(evpn_dict["mlag_client"][0], vlan_range="{} {}".format(vlan_range_start,vlan_range_end),
                           config="add",cli_type="click")
    for port_name in [evpn_dict["mlag_tg_list"][0],evpn_dict["leaf1"]["mlag_pch_intf_list"]]:
        Vlan.config_vlan_range_members(evpn_dict["mlag_client"][0],
                                       vlan_range="{} {}".format(vlan_range_start, vlan_range_end),
                                       port=port_name, config='add',cli_type="click")


def create_evpn_5549_config():
    st.exec_all([[spine1_setup_5549], [spine2_setup_5549], [leaf1_setup_5549],
                 [leaf2_setup_5549], [leaf3_setup_5549]])
    st.exec_all([[leaf1_setup_vxlan], [leaf2_setup_vxlan], [leaf3_setup_vxlan]])
    st.exec_all([[leaf1_setup_l2vni], [leaf2_setup_l2vni], [leaf3_setup_l2vni]])
    st.exec_all([[leaf1_setup_l3vni], [leaf2_setup_l3vni], [leaf3_setup_l3vni]])
    st.exec_all([[leaf1_mlag_config], [leaf2_mlag_config], [client_mclag_config]])
    #st.exec_all([[spine1_bgpgr_config],[spine2_bgpgr_config], [leaf1_bgpgr_config],
    #             [leaf2_bgpgr_config], [leaf3_bgpgr_config]])
    st.exec_all([[client_emulate_bgp], [leaf3_emulate_bgp]])
    st.exec_all([[leaf1_scale_l2vni],[leaf2_scale_l2vni],[leaf3_scale_l2vni],[client_scale_l2vni]])
    #st.exec_all([[leaf1_bfd_config],[leaf2_bfd_config],[client_bfd_config]])


def get_mclag_lvtep_common_mac():
    cli_type = st.get_ui_type()
    output1 = mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id="2",return_output="yes")
    output2 = mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id="2",return_output="yes")
    if isinstance(output1,list) and isinstance(output2,list):
        if len(output1) > 0 and len(output2) > 0:
            if cli_type == "click":
                if output1[0]["node_role"] == "Active":
                    mac = basic.get_ifconfig(evpn_dict["leaf_node_list"][0],
                                             evpn_dict["leaf1"]["l3_vni_name_list"][0])[0]['mac']
                elif output2[0]["node_role"] == "Active":
                    mac = basic.get_ifconfig(evpn_dict["leaf_node_list"][1],
                                             evpn_dict["leaf2"]["l3_vni_name_list"][0])[0]['mac']
                elif output1[0]["node_role"] == "Standby" and output2[0]["node_role"] == "Standby":
                    hdrMsg("FAIL : None of the MC-LAG peer node in Active state now")
                    mac = basic.get_ifconfig(evpn_dict["leaf_node_list"][0],
                                             evpn_dict["leaf1"]["l3_vni_name_list"][0])[0]['mac']
            elif cli_type == "klish":
                if output1[0]["node_role"] == "active":
                    mac = basic.get_ifconfig(evpn_dict["leaf_node_list"][0],
                                             evpn_dict["leaf1"]["l3_vni_name_list"][0])[0]['mac']
                elif output2[0]["node_role"] == "active":
                    mac = basic.get_ifconfig(evpn_dict["leaf_node_list"][1],
                                             evpn_dict["leaf2"]["l3_vni_name_list"][0])[0]['mac']
                elif output1[0]["node_role"] == "standby" and output2[0]["node_role"] == "standby":
                    hdrMsg("FAIL : None of the MC-LAG peer node in Active state now")
                    mac = basic.get_ifconfig(evpn_dict["leaf_node_list"][0],
                                             evpn_dict["leaf1"]["l3_vni_name_list"][0])[0]['mac']
        elif len(output1) == 0 or len(output2) == 0:
            mac = "00:00:01:02:03:04"
            hdrMsg("FAIL : show mclag output is not as per template, traffic failure will be "
                   "seen with this invalid common router MAC pls debug")
    elif isinstance(output1,bool) or isinstance(output2,bool):
        if output1 is False or output2 is False:
            mac = "00:00:01:02:03:04"
            hdrMsg("FAIL : show mclag returns empty output, traffic failure will be seen with "
                   "this invalid common router MAC pls debug")
    return mac


def tabulate_results(results=[]):
    st.banner("Convergence Table :")
    st.log("L2 VNI : {}".format(data.l2vni))
    st.log("IPv4 Routes : {}".format(data.ipv4_routes))
    st.log("IPv4 Routes : {}".format(data.ipv6_routes))
    sample_list = ["Sample-{} (sec)".format(i + 1) for i in range(data.iteration_count)]
    for item in results:
        table = tabulate(item,headers=["Testcase", "TRIGGER"]+ sample_list + ["Average (sec)"], tablefmt="grid")
        st.log("\n\n" + table)


def get_average_convergence(input,trigger):
    total = 0
    sample_count = data.iteration_count
    for iter in range(sample_count):
        if input['convergence_{}'.format(iter)] != None:
            sample_time = float(input['convergence_{}'.format(iter)])
            total += sample_time
    average = float(total)/float(sample_count)
    average = round(average,4)
    data['table_{}'.format(trigger)].append(average)



def get_mlag_active_stdby(state='Active'):
    st.log(">>>>> Get Active/Standby Mlag peers <<<<<")
    data['active'] = None
    data['stdby'] = None
    result1 = mclag.verify_domain(evpn_dict["leaf_node_list"][0],domain_id=evpn_dict["l3_vni_sag"]['mlag_domain_id'],
                        session_status='OK',mclag_intfs=1, peer_link_inf=evpn_dict["leaf1"]["iccpd_pch_intf_list"][0],node_role=state)
    result2 = mclag.verify_domain(evpn_dict["leaf_node_list"][1],domain_id=evpn_dict["l3_vni_sag"]['mlag_domain_id'],
                        session_status='OK',mclag_intfs=1,peer_link_inf=evpn_dict["leaf2"]["iccpd_pch_intf_list"][0],node_role=state)
    if result1 and not result2:
        data['active'] = evpn_dict["leaf_node_list"][0]
        data['stdby'] = evpn_dict["leaf_node_list"][1]
    elif not result1 and result2:
        data['active'] = evpn_dict["leaf_node_list"][1]
        data['stdby'] = evpn_dict["leaf_node_list"][0]
    else:
        st.error("Both MLAG peers claims as {}".format(state))
        return False
    st.log("Active Node - {}" .format(data['active']))
    st.log("STandby Node - {}".format(data['stdby']))
    return




def convergence_measure(tc,trigger,streams,iteration):
    traffic_rate=tg_dict['tgen_rate_pps']
    streams = [streams] if type(streams) is not list else list(streams)
    direction= '1' if 'l2_unknown'in tc else '2'

    ####################################
    st.log("\n\n>>>>>>> Start Traffic <<<<<<<\n\n")
    ####################################
    st.exec_all([[Intf.clear_interface_counters, evpn_dict["leaf_node_list"][0]],
                 [Intf.clear_interface_counters, evpn_dict["leaf_node_list"][1]],
                 [Intf.clear_interface_counters, evpn_dict["leaf_node_list"][2]],
                 [Intf.clear_interface_counters, evpn_dict["mlag_client"][0]],
                 [Intf.clear_interface_counters, evpn_dict["spine_node_list"][0]],
                 [Intf.clear_interface_counters, evpn_dict["spine_node_list"][1]]])

    clear_stats([tg_dict["d3_tg_ph1"],tg_dict['d6_tg_ph1'],tg_dict['d6_tg_ph2'], tg_dict['d5_tg_ph1']])
    if 'l2_known' not in tc:
        start_traffic(stream_han_list=streams)
    else:
        start_traffic(stream_han_list=streams[1])
        st.wait(5,'Wait for Macs to learn before sending unicast traffic from Mlag client')
        start_traffic(stream_han_list=streams[0])

    tx_tgen = tg_dict["d6_tg_ph1"];tx_tgen_port = vars.T1D6P1

    tx_stream  = rx_stream = streams
    if tc == 'l2_known': tx_stream = streams[0];rx_stream=streams[1]
    if tc == 'l3_symmetric':
        tx_stream = [stream_dict['v4_sym'][0],stream_dict['v6_sym'][0]]
        rx_stream = [stream_dict['v4_sym'][1],stream_dict['v6_sym'][1]]
    if tc == 'scale':
        tx_tgen = tg_dict["d6_tg_ph2"];
        tx_tgen_port = vars.T1D6P2
        tx_stream = stream_dict['v4scale_1'] + stream_dict['v6scale_1']
        rx_stream = stream_dict['v4scale_2'] + stream_dict['v6scale_2']
        if not retry_api(verify_installed_routes):
            return False
    if tc == 'orphan_traffic':
        tx_tgen = tg_dict["d3_tg_ph1"];
        tx_tgen_port = vars.T1D3P1
        direction = '1'
        if not retry_api(verify_installed_routes):
            return False

    if iteration == 1:
        #####################################################################
        st.log("\n\n>>>>>>>>>> Verify Traffic getting forwarded before doing Triggers <<<<<<<<\n\n")
        #####################################################################
        if not retry_api(verify_traffic,tx_port=tx_tgen_port,rx_port=vars.T1D5P1,field='packet_rate',tx_stream_list=tx_stream,rx_stream_list=rx_stream,mode='aggregate',
                              direction=direction,retry_count=3):
            st.error("Traffic Dropped before doing {}".format(trigger))
            return False
        ################################################
        st.log("\n\nStop and restart traffic after clearing tgen stats\n\n")
        ################################################
        tg_dict['tg'].tg_traffic_control(action='stop', stream_handle=streams)
        clear_stats([tg_dict["d3_tg_ph1"], tg_dict['d6_tg_ph1'],tg_dict['d6_tg_ph2'], tg_dict['d5_tg_ph1']])
        st.exec_all([[Intf.clear_interface_counters, evpn_dict["leaf_node_list"][0]],
                     [Intf.clear_interface_counters, evpn_dict["leaf_node_list"][1]],
                     [Intf.clear_interface_counters, evpn_dict["leaf_node_list"][2]],
                     [Intf.clear_interface_counters, evpn_dict["mlag_client"][0]],
                     [Intf.clear_interface_counters, evpn_dict["spine_node_list"][0]],
                     [Intf.clear_interface_counters, evpn_dict["spine_node_list"][1]]])
        start_traffic(stream_han_list=streams)
        st.wait(15)
    if tc == 'scale':retry_api(verify_ecmp_hashing,evpn_dict['mlag_client'][0],evpn_dict["mlag_intf_list"],retry_count=5)
    ##########################################################
    st.log("\n\n>>>>>>>> Perform Trigger {} ,Iteration-{} <<<<<<\n\n".format(trigger,iteration))
    ##########################################################

    if trigger == 'link_down_active':
        port_api.shutdown(data['active'],evpn_dict['leaf1']["mlag_intf_list"])
    elif trigger == 'link_up_active':
        port_api.noshutdown(data['active'], evpn_dict['leaf1']["mlag_intf_list"])
    elif trigger == 'link_down_stdby':
        port_api.shutdown(data['stdby'], evpn_dict['leaf2']["mlag_intf_list"])
    elif trigger == 'link_up_stdby':
        port_api.noshutdown(data['stdby'], evpn_dict['leaf2']["mlag_intf_list"])
    elif trigger == 'link_down_uplink':
        port_api.shutdown(data['active'],evpn_dict['leaf1']["pch_intf_list"][0])
    elif trigger == 'link_up_uplink':
        port_api.noshutdown(data['active'],evpn_dict['leaf1']["pch_intf_list"][0])
        st.wait(90, 'Wait for uplink track timer to expire')
    elif trigger == 'reboot_active_node':
        st.reboot(data['active'])
        st.exec_all([[leaf1_verify_vxlan], [leaf2_verify_vxlan]])
        st.wait(660, 'Wait for max-med to expire')
    elif trigger == 'reboot_stdby_node':
        st.reboot(data['stdby'])
        st.exec_all([[leaf1_verify_vxlan], [leaf2_verify_vxlan]])
        st.wait(660, 'Wait for max-med to expire')
    elif trigger == 'reboot_spine':
        st.reboot(evpn_dict['spine_node_list'][0])
        st.wait(120,'Wait for MED on-startup timer to expire on Leaf nodes')
    elif trigger == 'shut_all_uplinks_active':
        port_api.shutdown(data['active'],evpn_dict['leaf1']["intf_list_spine"])

    if tc == 'scale':
        if not retry_api(verify_installed_routes):
            return False
    ####################################################
    st.log("\n\n>>>>>>> Verify Traffic recovered after Trigger <<<<<<<<<\n\n")
    ####################################################

    if not retry_api(verify_traffic,tx_port=tx_tgen_port,rx_port=vars.T1D5P1,field='packet_rate',tx_stream_list=tx_stream,rx_stream_list=rx_stream,mode='aggregate',
                          direction=direction,retry_count=5):
        st.error("Traffic not recovered after {}".format(trigger))
        return False
    #####################################################
    st.log("\n\n>>>>>> Stop Traffic for convergence measurement <<<<<<<<\n\n")
    #####################################################
    tg_dict['tg'].tg_traffic_control(action='stop',stream_handle=streams)
    st.wait(5,'Wait for 5 sec after stopping traffic')

    total_tx_count,total_rx_count = get_traffic_counters(tx_tgen,tx_stream)

    if int(total_rx_count) == 0:
        st.error("Traffic Failed: RX port did not receive any packets after {}".format(trigger))
        return False
    drop = abs(float(total_tx_count) - float(total_rx_count))
    total_tx_streams = float(len(tx_stream))
    convergence_time = (float(drop)/float(traffic_rate))/total_tx_streams
    convergence_time = round(convergence_time,4)
    st.log("Traffic Convergence time : {} sec".format(convergence_time))
    return convergence_time



def get_traffic_counters(tx_handle,tx_stream,**kwargs):
    rx_handle = kwargs.get('rx_handle',tg_dict['d5_tg_ph1'])
    total_tx_count = 0
    total_rx_count = 0
    mode='streams' if 'stc' in vars.T1 else 'stream'
    tx_count = tg_dict['tg'].tg_traffic_stats(port_handle=tx_handle, mode=mode)
    if 'stc' not in vars.T1:
        rx_count = tg_dict['tg'].tg_traffic_stats(port_handle=rx_handle, mode=mode)
    for traffic_item in tx_stream:
        total_tx_count += int(tx_count[tx_handle]['stream'][traffic_item]['tx']['total_pkts'])
        if 'stc' not in vars.T1:
            total_rx_count += int(rx_count[rx_handle]['stream'][traffic_item]['rx']['total_pkts'])
        else:
            total_rx_count += int(tx_count[tx_handle]['stream'][traffic_item]['rx']['total_pkts'])
    st.log("Total Tx pkt count : {}".format(total_tx_count))
    st.log("Total Rx pkt count : {}".format(total_rx_count))
    return total_tx_count,total_rx_count


def verify_installed_routes():
    v4_leaf1_count = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][0], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp')
    v4_leaf2_count = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][1], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp')
    v6_leaf1_count = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][0], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp',
                                version='ipv6')
    v6_leaf2_count = ospf.fetch_ip_route_summary(evpn_dict["leaf_node_list"][1], vrf=evpn_dict['leaf1']['vrf_name_list'][0], key='ebgp',
                                version='ipv6')
    st.log('Leaf1 IPv4 routes : {}'.format(v4_leaf1_count))
    st.log('Leaf2 IPv4 routes : {}'.format(v4_leaf2_count))
    st.log('Leaf1 IPv6 routes : {}'.format(v6_leaf1_count))
    st.log('Leaf2 IPv6 routes : {}'.format(v6_leaf2_count))

    if int(v4_leaf1_count) < data.ipv4_routes or int(v4_leaf2_count) < data.ipv4_routes:
        st.error("MAx ipv4 routes not installed")
        return False
    if int(v6_leaf1_count) < data.ipv6_routes or int(v6_leaf2_count) < data.ipv6_routes:
        st.error("MAx ipv6 routes not installed")
        return False
    return True


def verify_ecmp_hashing(dut,ecmp_intf_list=[],total_streams=2):
    ret_val = True
    tolerance = 0.2
    total_paths = len(ecmp_intf_list)
    exp_rate_per_path = (int(tg_dict['tgen_rate_pps'])*total_streams)/total_paths
    exp_rate = exp_rate_per_path *tolerance
    for intf in ecmp_intf_list:
        output =  port_api.get_interface_counters_all(dut,port=intf)
        if output:
            tx_rate = int(output[0]['tx_pps'])
            if tx_rate < exp_rate:
                st.error("Traffic did not hash through ECMP path {}".format(intf))
                ret_val=False
    return ret_val


def convergence_ecmp(dut,port_flap_list,streams,iteration):
    traffic_rate=tg_dict['tgen_rate_pps']
    streams = [streams] if type(streams) is not list else list(streams)
    direction= '1'
    result = True;
    tech_support =False

    data['table_data_{}'.format(iteration)] = ['Iteration-{}'.format(iteration)]
    ####################################
    st.log("\n\n>>>>>>> Start Traffic <<<<<<<\n\n")
    ####################################
    st.exec_all([[Intf.clear_interface_counters, evpn_dict["leaf_node_list"][0]],
                 [Intf.clear_interface_counters, evpn_dict["leaf_node_list"][1]],
                 [Intf.clear_interface_counters, evpn_dict["leaf_node_list"][2]],
                 [Intf.clear_interface_counters, evpn_dict["mlag_client"][0]],
                 [Intf.clear_interface_counters, evpn_dict["spine_node_list"][0]],
                 [Intf.clear_interface_counters, evpn_dict["spine_node_list"][1]]])

    clear_stats([tg_dict["d3_tg_ph1"],tg_dict['d6_tg_ph1'],tg_dict['d6_tg_ph2'], tg_dict['d5_tg_ph1']])

    tx_tgen = tg_dict["d5_tg_ph1"];
    tx_tgen_port = vars.T1D5P1
    rx_stream = stream_dict['v4scale_1'] + stream_dict['v6scale_1']
    tx_stream = stream_dict['v4scale_2'] + stream_dict['v6scale_2']
    if not retry_api(verify_installed_routes):
        result = False
        if tech_support:st.generate_tech_support(dut=None,name='ecmp_convergene_onfail')
        tech_support = False

    start_traffic(stream_han_list=streams)
    #####################################################################
    st.log("\n\n>>>>>>>>>> Verify Traffic getting forwarded before doing Triggers <<<<<<<<\n\n")
    #####################################################################
    if not retry_api(verify_traffic,tx_port=tx_tgen_port,rx_port=vars.T1D6P2,field='packet_rate',tx_stream_list=tx_stream,rx_stream_list=rx_stream,mode='aggregate',
                          direction=direction,retry_count=3):
        st.error("Traffic Dropped before doing ecmp triggers")
        result =  False
        if tech_support:st.generate_tech_support(dut=None,name='ecmp_convergene_onfail')
        tech_support = False

    for port in port_flap_list[:-1]:
        ################################################
        st.log("\n\nStop and restart traffic after clearing tgen stats\n\n")
        ################################################
        tg_dict['tg'].tg_traffic_control(action='stop', stream_handle=streams)
        clear_stats([tg_dict["d3_tg_ph1"], tg_dict['d6_tg_ph1'],tg_dict['d6_tg_ph2'], tg_dict['d5_tg_ph1']])
        st.exec_all([[Intf.clear_interface_counters, evpn_dict["leaf_node_list"][0]],
                     [Intf.clear_interface_counters, evpn_dict["leaf_node_list"][1]],
                     [Intf.clear_interface_counters, evpn_dict["leaf_node_list"][2]],
                     [Intf.clear_interface_counters, evpn_dict["mlag_client"][0]],
                     [Intf.clear_interface_counters, evpn_dict["spine_node_list"][0]],
                     [Intf.clear_interface_counters, evpn_dict["spine_node_list"][1]]])
        start_traffic(stream_han_list=streams)
        st.wait(5)

        ##########################################################
        st.log("\n\n>>>>>>>> Shutdown port {} <<<<<<\n\n".format(port))
        ##########################################################
        port_api.shutdown(dut,port)
        ####################################################
        st.log("\n\n>>>>>>> Verify Traffic recovered after Trigger <<<<<<<<<\n\n")
        ####################################################
        if not retry_api(verify_traffic,tx_port=tx_tgen_port,rx_port=vars.T1D6P2,field='packet_rate',tx_stream_list=tx_stream,rx_stream_list=rx_stream,mode='aggregate',
                          direction=direction,retry_count=5):
            st.error("Traffic not recovered after shutdown of {}".format(port))
            result = False
            if tech_support: st.generate_tech_support(dut=None, name='ecmp_convergene_onfail')
            tech_support = False
        #####################################################
        st.log("\n\n>>>>>> Stop Traffic for convergence measurement <<<<<<<<\n\n")
        #####################################################
        tg_dict['tg'].tg_traffic_control(action='stop',stream_handle=streams)
        st.wait(5,'Wait for 5 sec after stopping traffic')

        total_tx_count,total_rx_count = get_traffic_counters(tx_tgen,tx_stream,rx_handle=tg_dict['d6_tg_ph2'])

        if int(total_rx_count) == 0:
            st.error("Traffic Failed: RX port did not receive any packets after {}".format(port))
            result =False
            if tech_support: st.generate_tech_support(dut=None, name='ecmp_convergene_onfail')
            tech_support = False
        if result:
            drop = abs(float(total_tx_count) - float(total_rx_count))
            total_tx_streams = float(len(tx_stream))
            convergence_time = (float(drop)/float(traffic_rate))/total_tx_streams
            convergence_time = round(convergence_time,4)
            st.log("Traffic Convergence time : {} sec".format(convergence_time))

            if convergence_time > 1.0:
                st.error("Convergence time {} more than expected".format(convergence_time))
                result = False
                if tech_support: st.generate_tech_support(dut=None, name='ecmp_convergene_onfail')
                tech_support = False
        else:
            convergence_time = 'Fail'
            if tech_support: st.generate_tech_support(dut=None, name='ecmp_convergene_onfail')
            tech_support = False;result=False

        data['table_data_{}'.format(iteration)].append(convergence_time)

    for port in port_flap_list[::-1][1:]:
        ################################################
        st.log("\n\nStop and restart traffic after clearing tgen stats\n\n")
        ################################################
        tg_dict['tg'].tg_traffic_control(action='stop', stream_handle=streams)
        clear_stats([tg_dict["d3_tg_ph1"], tg_dict['d6_tg_ph1'],tg_dict['d6_tg_ph2'], tg_dict['d5_tg_ph1']])
        st.exec_all([[Intf.clear_interface_counters, evpn_dict["leaf_node_list"][0]],
                     [Intf.clear_interface_counters, evpn_dict["leaf_node_list"][1]],
                     [Intf.clear_interface_counters, evpn_dict["leaf_node_list"][2]],
                     [Intf.clear_interface_counters, evpn_dict["mlag_client"][0]],
                     [Intf.clear_interface_counters, evpn_dict["spine_node_list"][0]],
                     [Intf.clear_interface_counters, evpn_dict["spine_node_list"][1]]])
        start_traffic(stream_han_list=streams)
        st.wait(5)
        ##########################################################
        st.log("\n\n>>>>>>>> Bring back port {} admin up<<<<<<\n\n".format(port))
        ##########################################################
        port_api.noshutdown(dut,port)
        ####################################################
        st.log("\n\n>>>>>>> Verify Traffic recovered after Trigger <<<<<<<<<\n\n")
        ####################################################
        if not retry_api(verify_traffic,tx_port=tx_tgen_port,rx_port=vars.T1D6P2,field='packet_rate',tx_stream_list=tx_stream,rx_stream_list=rx_stream,mode='aggregate',
                          direction=direction,retry_count=5):
            st.error("Traffic not recovered after shutdown of {}".format(port))
            result = False
            if tech_support: st.generate_tech_support(dut=None, name='ecmp_convergene_onfail')
            tech_support = False
        #####################################################
        st.log("\n\n>>>>>> Stop Traffic for convergence measurement <<<<<<<<\n\n")
        #####################################################
        tg_dict['tg'].tg_traffic_control(action='stop',stream_handle=streams)
        st.wait(5, 'Wait for 5 sec after stopping traffic')
        total_tx_count,total_rx_count = get_traffic_counters(tx_tgen,tx_stream,rx_handle=tg_dict['d6_tg_ph2'])

        if int(total_rx_count) == 0:
            st.error("Traffic Failed: RX port did not receive any packets after {}".format(port))
            result =False
            if tech_support: st.generate_tech_support(dut=None, name='ecmp_convergene_onfail')
            tech_support = False
        if result:
            drop = abs(float(total_tx_count) - float(total_rx_count))
            total_tx_streams = float(len(tx_stream))
            convergence_time = (float(drop)/float(traffic_rate))/total_tx_streams
            convergence_time = round(convergence_time,4)
            st.log("Traffic Convergence time : {} sec".format(convergence_time))
            if convergence_time > 1.0:
                st.error("Convergence time {} more than expected".format(convergence_time))
                result = False
                if tech_support: st.generate_tech_support(dut=None, name='ecmp_convergene_onfail')
                tech_support = False
        else:
            convergence_time = 'Fail'
            if tech_support: st.generate_tech_support(dut=None, name='ecmp_convergene_onfail')
            tech_support = False;result=False
        data['table_data_{}'.format(iteration)].append(convergence_time)

    return result


def leaf1_bfd_config():
    bfd.configure_bfd(evpn_dict['leaf_node_list'][0],interface="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                      vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],neighbor_ip=evpn_dict['mlag_node']['l3_tenant_ip_list'][0],
                      multiplier='3', rx_intv='1300', tx_intv='1300')

    bfd.configure_bfd(evpn_dict['leaf_node_list'][0],interface="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                      vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],local_address=evpn_dict['leaf1']["l3_tenant_ipv6_list"][1],
                    neighbor_ip =evpn_dict['mlag_node']['l3_tenant_ipv6_list'][0] ,multiplier='3', rx_intv='1300', tx_intv='1300')

def leaf2_bfd_config():
    bfd.configure_bfd(evpn_dict['leaf_node_list'][1],interface="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                      vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],neighbor_ip=evpn_dict['mlag_node']['l3_tenant_ip_list'][0],
                      multiplier='3', rx_intv='1300', tx_intv='1300')

    bfd.configure_bfd(evpn_dict['leaf_node_list'][1],interface="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                      vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],neighbor_ip=evpn_dict['mlag_node']['l3_tenant_ipv6_list'][0],
                      local_address =evpn_dict['leaf2']['l3_tenant_ipv6_list'][1] ,multiplier='3', rx_intv='1300', tx_intv='1300')

def client_bfd_config():
    bfd.configure_bfd(evpn_dict["mlag_client"][0],interface="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                      vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],neighbor_ip=evpn_dict['leaf1']["l3_tenant_ip_list"][1],
                      multiplier='3', rx_intv='1300', tx_intv='1300')

    bfd.configure_bfd(evpn_dict["mlag_client"][0],interface="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                      vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],neighbor_ip=evpn_dict['leaf1']["l3_tenant_ipv6_list"][1],
                      local_address =evpn_dict['mlag_node']['l3_tenant_ipv6_list'][0] ,multiplier='3', rx_intv='1300', tx_intv='1300')

    bfd.configure_bfd(evpn_dict["mlag_client"][0],interface="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                      vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],neighbor_ip= evpn_dict['leaf2']["l3_tenant_ip_list"][1],
                      multiplier='3', rx_intv='1300', tx_intv='1300')

    bfd.configure_bfd(evpn_dict["mlag_client"][0],interface="Vlan"+evpn_dict["leaf1"]["tenant_l3_vlan_list"][1],
                      vrf_name=evpn_dict["leaf3"]["vrf_name_list"][0],local_address=evpn_dict['mlag_node']['l3_tenant_ipv6_list'][0],
                      neighbor_ip =evpn_dict['leaf2']['l3_tenant_ipv6_list'][1] ,multiplier='3', rx_intv='1300', tx_intv='1300')


def revert_trigger_change(trigger,iteration):

    if trigger == 'shut_all_uplinks_active':
        port_api.noshutdown(data['active'], evpn_dict['leaf1']["intf_list_spine"])
        st.wait(30,'Wait for uplink tracking timer to expire and verify BGP sessions to re-establish')
        if not leaf1_verify_evpn : st.error('BGP sessions did not come up after flapping uplinks')

    if iteration < data.iteration_count:
        ######################################
        st.log(">>>> Revert back the configs before next iteration <<<<")
        ########################################
        if trigger == 'link_down_active':
            port_api.noshutdown(data['active'],evpn_dict['leaf1']["mlag_intf_list"])
        elif trigger == 'link_up_active':
            port_api.shutdown(data['active'], evpn_dict['leaf1']["mlag_intf_list"])
        elif trigger == 'link_down_stdby':
            port_api.noshutdown(data['stdby'], evpn_dict['leaf2']["mlag_intf_list"])
        elif trigger == 'link_up_stdby':
            port_api.shutdown(data['stdby'], evpn_dict['leaf2']["mlag_intf_list"])
        elif trigger == 'link_down_uplink':
            port_api.noshutdown(data['active'],evpn_dict['leaf1']["pch_intf_list"][0])
            st.wait(60, 'Wait for uplink track timer to expire')
        elif trigger == 'link_up_uplink':
            port_api.shutdown(data['active'],evpn_dict['leaf1']["pch_intf_list"][0])
    else:
        return
