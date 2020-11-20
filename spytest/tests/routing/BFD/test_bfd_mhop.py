#############################################################################
# Script Title : BGP BFD Multihop, Static single hop BFD and Static Multi hop BFD with L2 LAG and L3 LAG
# Author       : Gangadhara Sahu
# Mail-id      : gangadhara.sahu@broadcom.com
#############################################################################
import pytest
from spytest import st, utils
from apis.routing import ip as ip_api
from apis.routing import bgp
from apis.routing import ip_bgp
from apis.routing import bfd
from apis.routing import arp
from apis.system import port
from apis.switching import vlan as vlan_api
from apis.switching import portchannel as pc
from bfd_lag_vars import *
from spytest.tgen.tg import *
from apis.system import basic
from utilities import parallel
from apis.system.switch_configuration import get_running_config
import apis.routing.vrf as vrf_api
import apis.system.reboot as reboot_api
import apis.system.interface as intf_obj
import utilities.utils as utils_api

data = SpyTestDict()
data.streams = {}

def hdrMsg(msg):
    st.log("\n######################################################################" \
    " \n %s \n######################################################################"%msg)


@pytest.fixture(scope="module", autouse=True)
def bgp_base_config(request):
    global vars, tg1, dut1, dut2, dut3, dut4, D1_ports, D2_ports, D3_ports, flap_dut, flap_ports, tg_handles, D1_port, D3_port, D1_ports_vrf, D3_ports_vrf, flap_ports_vrf, tg_handles_vrf, D1_port_vrf, D3_port_vrf, dut_list
    vars = st.ensure_min_topology("D1D2:6", "D1T1:2", "D2T1:2","D1D3:4","D3T1:2")
    tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    dut1 = vars.dut_list[0]
    data.shop2mhopconfig = False
    data.shopunconfig = False
    dut_list = [dut1]
    if l2_switch == 'yes':
        dut2 = vars.dut_list[1]
        dut3 = vars.dut_list[2]
        dut4 = vars.dut_list[3]
        dut_list.extend([dut2, dut3, dut4])
        D1_ports = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1T1P1]
        D2_ports = [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D3P1, vars.D2D3P2, vars.D2D3P3]
        D3_ports = [vars.D3D2P1, vars.D3D2P2, vars.D3D2P3, vars.D3T1P1]
        flap_dut = dut2 ; flap_ports = [vars.D2D3P1, vars.D2D3P2, vars.D2D3P3]
        tg_handles = [tg1.get_port_handle(vars.T1D1P1), tg1.get_port_handle(vars.T1D3P1), tg1.get_port_handle(vars.T1D4P1)]
        D1_port = [vars.D1D4P1,vars.D1D4P2,vars.D1D4P3]
        D3_port = [vars.D4D1P1,vars.D4D1P2,vars.D4D1P3,vars.D3T1P1]
    else:
        dut3 = vars.dut_list[1]
        dut4 = vars.dut_list[2]
        dut_list.extend([dut3, dut4])
        D1_ports = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1T1P1]
        D3_ports = [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2T1P1]
        flap_dut = dut3; flap_ports = D3_ports[0:-1]
        tg_handles = [tg1.get_port_handle(vars.T1D1P1), tg1.get_port_handle(vars.T1D2P1), tg1.get_port_handle(vars.T1D3P1)]
        D1_port = [vars.D1D3P1,vars.D1D3P2,vars.D1D3P3]
        D3_port = [vars.D3D1P1,vars.D3D1P2,vars.D3D1P3,vars.D3T1P1]

        D1_ports_vrf = [vars.D1D2P4, vars.D1D2P5, vars.D1D2P6, vars.D1T1P2]
        D3_ports_vrf = [vars.D2D1P4, vars.D2D1P5, vars.D2D1P6, vars.D2T1P2]
        flap_ports_vrf = D3_ports_vrf[0:-1]
        tg_handles_vrf = [tg1.get_port_handle(vars.T1D1P2), tg1.get_port_handle(vars.T1D2P2),
                                                   tg1.get_port_handle(vars.T1D3P2)]
        D1_port_vrf = [vars.D1D3P4]
        D3_port_vrf = [vars.D3D1P4, "", "", vars.D3T1P2]

    multi_hop_config()
    multi_hop_config(vrfname=user_vrf_name)
    yield
    multi_hop_deconfig()
    multi_hop_deconfig(vrfname=user_vrf_name)


def return_vars(vrfname='default'):
    if vrfname == 'default':
        return access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, D1_port, \
                D3_port, lo_name, peer_v4, peer_v6, lag_name1, lag_name2, lag_name3, lag_name4, dut1_lo_ip, dut3_lo_ip,\
                dut4_lo_ip, dut1_lo_ipv6, dut3_lo_ipv6, dut4_lo_ipv6
    else:
        return access_vlan_vrf, access_vlan_name_vrf, trunk_vlan_vrf, trunk_vlan_name_vrf, D1_ports_vrf, D3_ports_vrf,\
                tg_handles_vrf, D1_port_vrf, D3_port_vrf, lo_name_vrf, peer_v4_vrf, peer_v6_vrf, lag_name1_vrf, \
                lag_name2_vrf, lag_name3_vrf, lag_name4_vrf, dut1_lo_ip_vrf, dut3_lo_ip_vrf, dut4_lo_ip_vrf, \
                dut1_lo_ipv6_vrf, dut3_lo_ipv6_vrf, dut4_lo_ipv6_vrf


def multi_hop_config(vrfname='default'):
    '''
    Mult-hop module config part
    :param vrfname:
    :return:
    '''

    ############################################################################################
    hdrMsg(" Assigning local vars based on the vrf config either default or non default vrf ")
    ############################################################################################
    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, D1_port, D3_port, \
    lo_name, peer_v4, peer_v6, lag_name1, lag_name2, lag_name3, lag_name4, \
    dut1_lo_ip, dut3_lo_ip, dut4_lo_ip, dut1_lo_ipv6, dut3_lo_ipv6, dut4_lo_ipv6 = return_vars(vrfname)

    ############################################################################################
    hdrMsg(" Base line config starts or module config starts here, Step-C1: Configure Vlan %s on dut1 ,dut3"%access_vlan)
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True, [[vlan_api.create_vlan,dut1,access_vlan], [vlan_api.create_vlan,dut3,access_vlan], [vlan_api.create_vlan,dut2,access_vlan]])
    elif l2_switch == 'no':
        utils.exec_all(True, [[vlan_api.create_vlan,dut1,access_vlan], [vlan_api.create_vlan,dut3,access_vlan]])

    ############################################################################################
    hdrMsg("Step-C2: Configure Vlans %s on dut1 , dut2 , dut3 for trunk ports"%trunk_vlan)
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True, [[vlan_api.create_vlan,dut1,trunk_vlan[0]], [vlan_api.create_vlan,dut2,trunk_vlan[0]], [vlan_api.create_vlan,dut3,trunk_vlan[0]]])
        utils.exec_all(True, [[vlan_api.create_vlan,dut1,trunk_vlan[1]], [vlan_api.create_vlan,dut2,trunk_vlan[1]], [vlan_api.create_vlan,dut3,trunk_vlan[1]]])
        utils.exec_all(True, [[vlan_api.create_vlan,dut1,trunk_vlan[2]], [vlan_api.create_vlan,dut2,trunk_vlan[2]], [vlan_api.create_vlan,dut3,trunk_vlan[2]]])
    elif l2_switch == 'no':
        utils.exec_all(True, [[vlan_api.create_vlan,dut1,trunk_vlan[0]], [vlan_api.create_vlan,dut3,trunk_vlan[0]]])
        utils.exec_all(True, [[vlan_api.create_vlan,dut1,trunk_vlan[1]], [vlan_api.create_vlan,dut3,trunk_vlan[1]]])
        utils.exec_all(True, [[vlan_api.create_vlan,dut1,trunk_vlan[2]], [vlan_api.create_vlan,dut3,trunk_vlan[2]]])

    if vrfname != 'default':
        dict1 = {'vrf_name': user_vrf_name, 'skip_error': True}
        parallel.exec_parallel(True, [dut1, dut3, dut4], vrf_api.config_vrf, [dict1, dict1, dict1])
        ############################################################################################
        hdrMsg("Step-C5_VRF: Bind to vrf and configure ip address %s on dut1 and %s on dut3 for vlan %s" \
               % (dut1_lagip_list[0], dut3_lagip_list[0], access_vlan_vrf))
        ############################################################################################
        # for i,vlan,ip1,ip2 in zip(range(0,data.max_ecmp),data.dut1_vlan_scl,data.dut1_ecmp_ip,data.dut2_ecmp_ip):
        dict1 = {'vrf_name': user_vrf_name, 'intf_name': access_vlan_name_vrf, 'skip_error': True}
        dict2 = {'vrf_name': user_vrf_name, 'intf_name': access_vlan_name_vrf, 'skip_error': True}
        parallel.exec_parallel(True, [dut1, dut3], vrf_api.bind_vrf_interface, [dict1, dict2])

        ############################################################################################
        hdrMsg("Step-C6_VRF: Bind to vrf for ip address %s on dut1 and %s on dut3 for vlans %s" \
               % (dut1_lagip_list[2:], dut3_lagip_list[2:], trunk_vlan_vrf))
        ############################################################################################
        for vlan in trunk_vlan_name_vrf:
            dict1 = {'vrf_name': user_vrf_name, 'intf_name': vlan, 'skip_error': True}
            dict2 = {'vrf_name': user_vrf_name, 'intf_name': vlan, 'skip_error': True}
            parallel.exec_parallel(True, [dut1, dut3], vrf_api.bind_vrf_interface, [dict1, dict2])

        dict1 = {'vrf_name': user_vrf_name, 'intf_name': D1_ports[3], 'skip_error': True}
        dict2 = {'vrf_name': user_vrf_name, 'intf_name': D3_ports[3], 'skip_error': True}
        parallel.exec_parallel(True, [dut1, dut3], vrf_api.bind_vrf_interface, [dict1, dict2])
        vrf_api.bind_vrf_interface(dut4, vrf_name=vrfname, intf_name=D3_port[3],skip_error=True)

    ############################################################################################
    hdrMsg("Step-C3: Configure LACP interfaces with name %s and %s on dut1 ,dut2"%(lag_name1,lag_name2))
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True, [[pc.create_portchannel,dut1,[lag_name1],False], [pc.create_portchannel,dut2,[lag_name1],False]])
        utils.exec_all(True, [[pc.create_portchannel,dut1,[lag_name2],False,"1"], [pc.create_portchannel,dut2,[lag_name2],False,"1"]])
    elif l2_switch == 'no':
        utils.exec_all(True, [[pc.create_portchannel,dut1,[lag_name1],False], [pc.create_portchannel,dut3,[lag_name1],False]])
        utils.exec_all(True, [[pc.create_portchannel,dut1,[lag_name2],False,"1"], [pc.create_portchannel,dut3,[lag_name2],False,"1"]])

    ############################################################################################
    hdrMsg("Step-C4: Adding member ports for the port-channel %s and %s on dut1 ,dut2"%(lag_name1,lag_name2))
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True, [[pc.add_portchannel_member,dut1,lag_name1,[D1_ports[0]]], [pc.add_portchannel_member,dut2,lag_name1,[D2_ports[0]]] ])
        utils.exec_all(True, [[pc.add_portchannel_member,dut1,lag_name2,D1_ports[1:3]], [pc.add_portchannel_member,dut2,lag_name2,D2_ports[1:3]] ])
    elif l2_switch == 'no':
        utils.exec_all(True, [[pc.add_portchannel_member,dut1,lag_name1,[D1_ports[0]]], [pc.add_portchannel_member,dut3,lag_name1,[D3_ports[0]]] ])
        utils.exec_all(True, [[pc.add_portchannel_member,dut1,lag_name2,D1_ports[1:3]], [pc.add_portchannel_member,dut3,lag_name2,D3_ports[1:3]] ])

    ############################################################################################
    hdrMsg("Step-C5: Configure %s on dut1 and %s on dut3 as access port with vlan %s"\
           % (D1_ports[0],D3_ports[0],access_vlan))
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True, [[vlan_api.add_vlan_member,dut1,access_vlan,lag_name1, False], [vlan_api.add_vlan_member,dut2,access_vlan,[lag_name1,D2_ports[3]], False], [vlan_api.add_vlan_member,dut3,access_vlan,D3_ports[0],False] ])
    elif l2_switch == 'no':
        utils.exec_all(True, [[vlan_api.add_vlan_member,dut1,access_vlan,lag_name1, False], [vlan_api.add_vlan_member,dut3,access_vlan,lag_name1, False] ])

    ############################################################################################
    hdrMsg("Step-C6: Configure %s on dut1 and %s on dut3 as trunk port with vlans %s" \
           % (D1_ports[2],D3_ports[2],trunk_vlan))
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True, [[vlan_api.add_vlan_member,dut1,trunk_vlan[0],lag_name2,True], [vlan_api.add_vlan_member,dut2,trunk_vlan[0],[lag_name2,D2_ports[5]],True], [vlan_api.add_vlan_member,dut3,trunk_vlan[0],D3_ports[2],True]])
        utils.exec_all(True, [[vlan_api.add_vlan_member,dut1,trunk_vlan[1],lag_name2,True], [vlan_api.add_vlan_member,dut2,trunk_vlan[1],[lag_name2,D2_ports[5]],True], [vlan_api.add_vlan_member,dut3,trunk_vlan[1],D3_ports[2],True]])
        utils.exec_all(True, [[vlan_api.add_vlan_member,dut1,trunk_vlan[2],lag_name2,True], [vlan_api.add_vlan_member,dut2,trunk_vlan[2],[lag_name2,D2_ports[5]],True], [vlan_api.add_vlan_member,dut3,trunk_vlan[2],D3_ports[2],True]])

    elif l2_switch == 'no':
        utils.exec_all(True, [[vlan_api.add_vlan_member,dut1,trunk_vlan[0],lag_name2,True], [vlan_api.add_vlan_member,dut3,trunk_vlan[0],lag_name2,True] ])
        utils.exec_all(True, [[vlan_api.add_vlan_member,dut1,trunk_vlan[1],lag_name2,True], [vlan_api.add_vlan_member,dut3,trunk_vlan[1],lag_name2,True] ])
        utils.exec_all(True, [[vlan_api.add_vlan_member,dut1,trunk_vlan[2],lag_name2,True], [vlan_api.add_vlan_member,dut3,trunk_vlan[2],lag_name2,True] ])

    ############################################################################################
    hdrMsg("Step-C7: Configure ip address %s on dut1 and %s on dut3 for vlan %s"\
           % (dut1_lagip_list[0],dut3_lagip_list[0], access_vlan))
    ############################################################################################
    utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,access_vlan_name,dut1_lagip_list[0],ip_mask,"ipv4"], [ip_api.config_ip_addr_interface,dut3,access_vlan_name,dut3_lagip_list[0],ip_mask,"ipv4"] ])

    ############################################################################################
    hdrMsg("Step-C8: Configure ipv6 address %s on dut1 and %s on dut3 for vlan %s" \
           % (dut1_lagipv6_list[0], dut3_lagipv6_list[0], access_vlan))
    ############################################################################################
    utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,access_vlan_name,dut1_lagipv6_list[0],ipv6_mask,"ipv6"], [ip_api.config_ip_addr_interface,dut3,access_vlan_name,dut3_lagipv6_list[0],ipv6_mask,"ipv6"]])

    ############################################################################################
    hdrMsg("Step-C9: Configure ip address %s on dut1 and %s on dut3 for vlans %s" \
           % (dut1_lagip_list[2:5],dut3_lagip_list[2:5],trunk_vlan))
    ############################################################################################
    utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,trunk_vlan_name[0],dut1_lagip_list[2],ip_mask,"ipv4"], [ip_api.config_ip_addr_interface,dut3,trunk_vlan_name[0],dut3_lagip_list[2],ip_mask,"ipv4"]])
    utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,trunk_vlan_name[1],dut1_lagip_list[3],ip_mask,"ipv4"], [ip_api.config_ip_addr_interface,dut3,trunk_vlan_name[1],dut3_lagip_list[3],ip_mask,"ipv4"]])
    utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,trunk_vlan_name[2],dut1_lagip_list[4],ip_mask,"ipv4"], [ip_api.config_ip_addr_interface,dut3,trunk_vlan_name[2],dut3_lagip_list[4],ip_mask,"ipv4"]])

    ############################################################################################
    hdrMsg("Step-C10: Configure ipv6 address %s on dut1 and %s on dut3 for vlans %s" \
           % (dut1_lagipv6_list[2:5], dut3_lagipv6_list[2:5], trunk_vlan))
    ############################################################################################
    utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,trunk_vlan_name[0],dut1_lagipv6_list[2],ipv6_mask,"ipv6"], [ip_api.config_ip_addr_interface,dut3,trunk_vlan_name[0],dut3_lagipv6_list[2],ipv6_mask,"ipv6"]])
    utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,trunk_vlan_name[1],dut1_lagipv6_list[3],ipv6_mask,"ipv6"], [ip_api.config_ip_addr_interface,dut3,trunk_vlan_name[1],dut3_lagipv6_list[3],ipv6_mask,"ipv6"]])
    utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,trunk_vlan_name[2],dut1_lagipv6_list[4],ipv6_mask,"ipv6"], [ip_api.config_ip_addr_interface,dut3,trunk_vlan_name[2],dut3_lagipv6_list[4],ipv6_mask,"ipv6"]])

    ############################################################################################
    hdrMsg("Step-C11: Configure BGP dut1 locals-as %s with router-id %s & dut3 locals-as %s with router-id %s"%(dut1_as,dut1_router_id,dut3_as,dut3_router_id))
    ############################################################################################
    if vrfname == 'default':

        dict1 = {'local_as': dut1_as, 'router_id': dut1_router_id, 'config_type_list': ['router_id']}
        dict2 = {'local_as': dut3_as, 'router_id': dut3_router_id, 'config_type_list': ['router_id']}
        parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])
        dict1 = {'neighbor': dut3_lagip_list[0], 'remote_as': dut3_as, 'config_type_list': ["neighbor"],
                 'keepalive': keep_alive, 'holdtime': hold_down, 'local_as': dut1_as}
        dict2 = {'neighbor': dut1_lagip_list[0], 'remote_as': dut1_as, 'config_type_list': ["neighbor"],
                 'keepalive': keep_alive, 'holdtime': hold_down, 'local_as': dut3_as}
        parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])

       ############################################################################################
        hdrMsg("Step-C13: Configure eBGP neighbors %s on dut1 and %s on dut3" % (
        dut3_lagip_list[0:2], dut1_lagip_list[0:2]))
        ############################################################################################
        dict1 = {"neighbor":dut3_lagip_list[0],"config":'yes',"config_type_list":['connect','activate'],"connect":'1',"addr_family":"ipv4","local_as":dut1_as}
        dict2 = {"neighbor":dut1_lagip_list[0],"config":'yes',"config_type_list":['connect','activate'],"connect":'1',"addr_family":"ipv4","local_as":dut3_as}
        parallel.exec_parallel(True,[dut1,dut3],bgp.config_bgp,[dict1,dict2])

        ############################################################################################
        hdrMsg("Step-C14: Configure ipv4 peer-group on dut1 and dut3")
        ############################################################################################
        utils.exec_all(True, [[bgp.create_bgp_peergroup,dut1,dut1_as,peer_v4,dut3_as,keep_alive,hold_down], [bgp.create_bgp_peergroup,dut3,dut3_as,peer_v4,dut1_as,keep_alive,hold_down]])

        ############################################################################################
        hdrMsg("Step-C15: Configure neighbors %s under peer-group %s on dut1 "%(dut3_lagip_list[2:5],peer_v4))
        ############################################################################################
        utils.exec_all(True, [[bgp.create_bgp_neighbor_use_peergroup,dut1,dut1_as,peer_v4,dut3_lagip_list[2],"ipv4"], [bgp.create_bgp_neighbor_use_peergroup,dut3,dut3_as,peer_v4,dut1_lagip_list[2],"ipv4"]])
        utils.exec_all(True, [[bgp.create_bgp_neighbor_use_peergroup,dut1,dut1_as,peer_v4,dut3_lagip_list[3],"ipv4"], [bgp.create_bgp_neighbor_use_peergroup,dut3,dut3_as,peer_v4,dut1_lagip_list[3],"ipv4"]])
        utils.exec_all(True, [[bgp.create_bgp_neighbor_use_peergroup,dut1,dut1_as,peer_v4,dut3_lagip_list[4],"ipv4"], [bgp.create_bgp_neighbor_use_peergroup,dut3,dut3_as,peer_v4,dut1_lagip_list[4],"ipv4"]])

        ############################################################################################
        hdrMsg("Step-C17: Configure eBGP+ neighbors %s on dut1 and %s on dut3" % (dut3_lagipv6_list[0:2], dut1_lagipv6_list[0:2]))
        ############################################################################################
        utils.exec_all(True, [[bgp.create_bgp_neighbor,dut1,dut1_as,dut3_lagipv6_list[0],dut3_as,keep_alive,hold_down,"","ipv6"], [bgp.create_bgp_neighbor,dut3,dut3_as,dut1_lagipv6_list[0],dut1_as,keep_alive,hold_down,"","ipv6"]])

        dict1 = {"neighbor":dut3_lagipv6_list[0],"config":'yes',"config_type_list":['connect'],"connect":'1',"addr_family":"ipv6","local_as":dut1_as}
        dict2 = {"neighbor":dut1_lagipv6_list[0],"config":'yes',"config_type_list":['connect'],"connect":'1',"addr_family":"ipv6","local_as":dut3_as}
        parallel.exec_parallel(True,[dut1,dut3],bgp.config_bgp,[dict1,dict2])


        ############################################################################################
        hdrMsg("Step-C18: Configure ipv6 peer-group on dut1 and dut3")
        ############################################################################################
        utils.exec_all(True, [[bgp.create_bgp_peergroup,dut1,dut1_as,peer_v6,dut3_as,keep_alive,hold_down], [bgp.create_bgp_peergroup,dut3,dut3_as,peer_v6, dut1_as,keep_alive,hold_down]])

        ############################################################################################
        hdrMsg("Step-C20: Configure neighbors %s under peer-group %s on dut3 & %s under peer-group %s on dut1"%(dut1_lagipv6_list[2:5],peer_v6,dut3_lagipv6_list[2:5],peer_v6))
        ############################################################################################
        utils.exec_all(True, [[bgp.create_bgp_neighbor_use_peergroup,dut1,dut1_as,peer_v6,dut3_lagipv6_list[2],"ipv6"], [bgp.create_bgp_neighbor_use_peergroup,dut3,dut3_as,peer_v6,dut1_lagipv6_list[2],"ipv6"]])
        utils.exec_all(True, [[bgp.create_bgp_neighbor_use_peergroup,dut1,dut1_as,peer_v6,dut3_lagipv6_list[3],"ipv6"], [bgp.create_bgp_neighbor_use_peergroup,dut3,dut3_as,peer_v6,dut1_lagipv6_list[3],"ipv6"]])
        utils.exec_all(True, [[bgp.create_bgp_neighbor_use_peergroup,dut1,dut1_as,peer_v6,dut3_lagipv6_list[4],"ipv6"], [bgp.create_bgp_neighbor_use_peergroup,dut3,dut3_as,peer_v6,dut1_lagipv6_list[4],"ipv6"]])

        ############################################################################################
        hdrMsg("Step-C35: Configure route-map in dut1 & dut3 to program link local address for traffic forwarding")
        ############################################################################################
        ip_api.config_route_map_global_nexthop(dut1,'rmap_v6',config='yes')
        bgp.config_bgp(dut1, local_as=dut1_as, config_type_list=["routeMap"], routeMap='rmap_v6', diRection='in',
                       neighbor=dut3_lagipv6_list[0], addr_family='ipv6')
        bgp.config_bgp(dut1, local_as=dut1_as, config_type_list=["routeMap"], routeMap='rmap_v6', diRection='in',
                       neighbor=peer_v6, addr_family='ipv6',peergroup=peer_v6)
    else:
        dict1 = {'vrf_name': vrfname, 'local_as': dut1_as, 'router_id': dut1_router_id, 'config_type_list': ['router_id']}
        dict2 = {'vrf_name': vrfname, 'local_as': dut3_as, 'router_id': dut3_router_id, 'config_type_list': ['router_id']}
        parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])
        dict1 = {'neighbor': dut3_lagip_list[0], 'remote_as': dut3_as, 'config_type_list': ["neighbor"],
                 'keepalive': keep_alive, 'holdtime': hold_down, 'local_as': dut1_as, 'vrf_name': vrfname}
        dict2 = {'neighbor': dut1_lagip_list[0], 'remote_as': dut1_as, 'config_type_list': ["neighbor"],
                 'keepalive': keep_alive, 'holdtime': hold_down, 'local_as': dut3_as, 'vrf_name': vrfname}
        parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])

        for nbr_1, nbr_3 in zip(dut3_lagip_list[2:5], dut1_lagip_list[2:5]):
            dict1 = {'peergroup': peer_v4_vrf, 'config_type_list': ['peergroup'], 'remote_as': dut3_as,
                     'neighbor': nbr_1, 'local_as': dut1_as, 'vrf_name': vrfname}
            dict2 = {'peergroup': peer_v4_vrf, 'config_type_list': ['peergroup'], 'remote_as': dut1_as,
                     'neighbor': nbr_3, 'local_as': dut3_as, 'vrf_name': vrfname}
            parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])

        dict1 = {'config_type_list': ['connect'], 'remote_as': dut3_as, 'local_as': dut1_as, 'vrf_name': vrfname,
                 'neighbor': peer_v4_vrf, 'connect': 1, 'keepalive': keep_alive, 'holdtime': hold_down, 'peergroup': peer_v4_vrf}
        dict2 = {'config_type_list': ['connect'], 'remote_as': dut1_as, 'local_as': dut3_as, 'vrf_name': vrfname,
                 'neighbor': peer_v4_vrf, 'connect': 1, 'keepalive': keep_alive, 'holdtime': hold_down, 'peergroup': peer_v4_vrf}
        parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])

        dict1 = {'vrf_name': user_vrf_name, "neighbor":dut3_lagip_list[0],"config":'yes',
                 "config_type_list":['connect'],"connect":'1',"addr_family":"ipv4","local_as":dut1_as}
        dict2 = {'vrf_name': user_vrf_name, "neighbor":dut1_lagip_list[0],"config":'yes',
                 "config_type_list":['connect'],"connect":'1',"addr_family":"ipv4","local_as":dut3_as}
        parallel.exec_parallel(True,[dut1,dut3],bgp.config_bgp,[dict1,dict2])
        ip_api.config_route_map_global_nexthop(dut1, 'rmap_v6', config='yes')
        dict1 = {'vrf_name': user_vrf_name, 'local_as': dut1_as, 'neighbor': dut3_lagipv6_list[0], 'remote_as': dut3_as,
                 'config_type_list': ["neighbor", "connect", 'activate', 'routeMap'], 'routeMap': 'rmap_v6',
                 'diRection': 'in', 'connect': 1, 'addr_family': 'ipv6'}
        dict2 = {'vrf_name': user_vrf_name, 'local_as': dut3_as, 'neighbor': dut1_lagipv6_list[0], 'remote_as': dut1_as,
                 'config_type_list': ["neighbor", "connect", 'activate'], 'connect': 1, 'addr_family': 'ipv6'}
        parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])

        ############################################################################################
        hdrMsg("Step-C15_VRF: Configure neighbors %s under peer-group %s on dut1 " % (dut3_lagipv6_list[2:5], peer_v6_vrf))
        ############################################################################################
        for nbr_1, nbr_3 in zip(dut3_lagipv6_list[2:5], dut1_lagipv6_list[2:5]):
            dict1 = {'vrf_name': vrfname, 'local_as': dut1_as, 'peergroup': peer_v6_vrf,
                     'config_type_list': ['peergroup', 'activate'],
                     'remote_as': dut3_as, 'neighbor': nbr_1, 'addr_family': 'ipv6'}
            dict2 = {'vrf_name': vrfname, 'local_as': dut3_as, 'peergroup': peer_v6_vrf,
                     'config_type_list': ['peergroup', 'activate'],
                     'remote_as': dut1_as, 'neighbor': nbr_3, 'addr_family': 'ipv6'}
            parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])
        dict1 = {'peergroup': peer_v6_vrf, 'config_type_list': ['connect'], 'remote_as': dut3_as, 'local_as': dut1_as,
                 'neighbor': peer_v6_vrf, 'connect': 1, 'keepalive': keep_alive, 'holdtime': hold_down, 'vrf_name': vrfname}
        dict2 = {'peergroup': peer_v6_vrf, 'config_type_list': ['connect'], 'remote_as': dut1_as, 'local_as': dut3_as,
                 'neighbor': peer_v6_vrf, 'connect': 1, 'keepalive': keep_alive, 'holdtime': hold_down, 'vrf_name': vrfname}
        parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])



    ############################################################################################
    hdrMsg("Step-C26: Configuring the redistributed connected and max-ptah 1 on dut1 nad dut2 ")
    ############################################################################################
    dict1 = {'vrf_name':vrfname, "local_as":dut1_as,"config":'yes',"config_type_list":["redist",'max_path_ebgp'],"redistribute":'connected',"addr_family":"ipv4","max_path_ebgp":1}
    dict2 = {'vrf_name':vrfname, "local_as":dut3_as,"config":'yes',"config_type_list":["redist",'max_path_ebgp'],"redistribute":'connected',"addr_family":"ipv4","max_path_ebgp":1}
    dict3 = {'vrf_name':vrfname, "router_id":dut4_router_id,"local_as":dut3_as,"config":'yes',"config_type_list":["redist",'max_path_ebgp'],"redistribute":'connected',"addr_family":"ipv4","max_path_ebgp":1}
    parallel.exec_parallel(True,[dut1,dut3,dut4],bgp.config_bgp,[dict1,dict2,dict3])

    dict1 = {'vrf_name':vrfname, "local_as":dut1_as,"config":'yes',"config_type_list":["redist",'max_path_ebgp'],"redistribute":'connected',"addr_family":"ipv6","max_path_ebgp":1}
    dict2 = {'vrf_name':vrfname, "local_as":dut3_as,"config":'yes',"config_type_list":["redist",'max_path_ebgp'],"redistribute":'connected',"addr_family":"ipv6","max_path_ebgp":1}
    dict3 = {'vrf_name':vrfname, "local_as":dut3_as,"config":'yes',"config_type_list":["redist",'max_path_ebgp'],"redistribute":'connected',"addr_family":"ipv6","max_path_ebgp":1}
    parallel.exec_parallel(True,[dut1,dut3,dut4],bgp.config_bgp,[dict1,dict2,dict3])

    ############################################################################################
    hdrMsg("Step-C28: Config ip address %s and ipv6 address %s on dut1 tg port " % (dut1_tg_ip,dut1_tg_ipv6))
    ############################################################################################
    utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,D1_ports[3],dut1_tg_ip,ip_mask,"ipv4"], [ip_api.config_ip_addr_interface,dut3,D3_ports[3],dut3_tg_ip,ip_mask,"ipv4"], [ip_api.config_ip_addr_interface,dut4,D3_port[3],dut4_tg_ip,ip_mask,"ipv4"] ])
    utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,D1_ports[3],dut1_tg_ipv6,ipv6_mask,"ipv6"], [ip_api.config_ip_addr_interface,dut3,D3_ports[3],dut3_tg_ipv6,ipv6_mask,"ipv6"], [ip_api.config_ip_addr_interface,dut4,D3_port[3],dut4_tg_ipv6,ipv6_mask,"ipv6"] ])
    if vrfname == 'default':
        dict1 = {"loopback_name":lo_name,"config":"yes"}
        parallel.exec_parallel(True,[dut1,dut3,dut4],ip_api.configure_loopback,[dict1,dict1,dict1])
    else:
        dict1 = {'vrf_name': user_vrf_name, 'intf_name': lo_name, 'skip_error': True}
        dict2 = {'vrf_name': user_vrf_name, 'intf_name': lo_name, 'skip_error': True}
        dict3 = {'vrf_name': user_vrf_name, 'intf_name': lo_name, 'skip_error': True}
        parallel.exec_parallel(True, [dut1, dut3, dut4], vrf_api.bind_vrf_interface, [dict1, dict2, dict3])

    utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,lo_name,dut1_lo_ipv6,lo_v6mask,"ipv6"],[ip_api.config_ip_addr_interface,dut3,lo_name,dut3_lo_ipv6,lo_v6mask,"ipv6"] ])
    utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,lo_name,dut1_lo_ip,lo_mask,"ipv4"],[ip_api.config_ip_addr_interface,dut3,lo_name,dut3_lo_ip,lo_mask,"ipv4"] ])
    ###########################################################################################
    hdrMsg("Step C29: Disable bgp fast-external-failover and trigger link failure again")
    ###########################################################################################
    dict1 = {'vrf_name':vrfname, "local_as": dut1_as,'fast_external_failover':'', 'config_type_list': ["fast_external_failover"],'config':'no'}
    dict2 = {'vrf_name':vrfname, "local_as": dut3_as,'fast_external_failover':'', 'config_type_list': ["fast_external_failover"],'config':'no'}
    dict3 = {'vrf_name':vrfname, "local_as": dut3_as,'fast_external_failover':'', 'config_type_list': ["fast_external_failover"],'config':'no'}
    parallel.exec_parallel(True, [dut1, dut3,dut4], bgp.config_bgp,[dict1, dict2,dict3])

    if convergence_test == "yes":
        ############################################################################################
        hdrMsg("Step-C30: Get mac for D1T1P1 from dut1, add static ARP/ND in dut3 and dut4")
        ############################################################################################
        D1_tg1_mac = basic.get_ifconfig(dut1,D1_ports[3])[0]['mac']
        utils.exec_all(True, [[arp.add_static_arp,dut3,tg_dut3_ip,tg_dut3_mac,D3_ports[3]],[arp.add_static_arp,dut4,tg_dut4_ip,tg_dut4_mac,D3_port[3]] ])
        utils.exec_all(True,[[arp.config_static_ndp,dut3,tg_dut3_ipv6,tg_dut3_mac,D3_ports[3],"add"],[arp.config_static_ndp,dut4,tg_dut4_ipv6,tg_dut4_mac,D3_port[3],"add"]])

        ############################################################################################
        hdrMsg("Step-C31: Configure ipv4 and ipv6 L3 streams on T1D1P1 to destination %s ,%s on T1D3P1"%(tg_dut3_ip,tg_dut3_ipv6))
        ############################################################################################
        if vrfname == 'default':
            tg1.tg_traffic_control(action='reset',port_handle=tg_handles)

        stream1_v4 = tg1.tg_traffic_config(mac_src = tg_dut1_mac,mac_dst=D1_tg1_mac,rate_pps=traffic_rate,\
            mode='create',port_handle=tg_handles[0],transmit_mode='continuous',l3_protocol='ipv4', ip_src_addr=tg_dut1_ip\
                          ,ip_dst_addr=tg_dut3_ip, mac_discovery_gw=dut1_tg_ip)
        stream1_v4_handle = stream1_v4['stream_id']

        stream1_v6 = tg1.tg_traffic_config(mac_src = tg_dut1_mac,mac_dst=D1_tg1_mac,rate_pps=traffic_rate,\
            mode='create',port_handle=tg_handles[0],transmit_mode='continuous',l3_protocol='ipv6', ipv6_src_addr=tg_dut1_ipv6\
                          ,ipv6_dst_addr=tg_dut3_ipv6, mac_discovery_gw=dut1_tg_ipv6)
        stream1_v6_handle = stream1_v6['stream_id']
        if vrfname == 'default':
            data.streams['stream1_handle_list'] = [stream1_v4_handle,stream1_v6_handle]
        else:
            data.streams['stream1_handle_list_vrf'] = [stream1_v4_handle, stream1_v6_handle]

        stream_v4 = tg1.tg_traffic_config(mac_src = tg_dut1_mac,mac_dst=D1_tg1_mac,rate_pps=traffic_rate,\
            mode='create',port_handle=tg_handles[0],transmit_mode='continuous',l3_protocol='ipv4', ip_src_addr=tg_dut1_ip\
                          ,ip_dst_addr=tg_dut4_ip, mac_discovery_gw=dut1_tg_ip)
        stream_v4_handle = stream_v4['stream_id']

        stream_v6 = tg1.tg_traffic_config(mac_src = tg_dut1_mac,mac_dst=D1_tg1_mac,rate_pps=traffic_rate,\
            mode='create',port_handle=tg_handles[0],transmit_mode='continuous',l3_protocol='ipv6', ipv6_src_addr=tg_dut1_ipv6\
                          ,ipv6_dst_addr=tg_dut4_ipv6, mac_discovery_gw=dut1_tg_ipv6)
        stream_v6_handle = stream_v6['stream_id']
        if vrfname == 'default':
            data.streams['stream_handle_list'] = [stream_v4_handle,stream_v6_handle]
        else:
            data.streams['stream_handle_list_vrf'] = [stream_v4_handle, stream_v6_handle]

    ############################################################################################
    hdrMsg("Step-C32: Configure LACP interfaces with name %s and %s on dut1 ,dut4"%(lag_name3,lag_name4))
    ############################################################################################
    utils.exec_all(True, [[pc.create_portchannel,dut1,[lag_name3,lag_name4],False], [pc.create_portchannel,dut4,[lag_name3,lag_name4],False]])
    if vrfname != 'default':

        ############################################################################################
        hdrMsg("Step-C6_VRF: Bind to vrf for ip address %s on dut1 and %s on dut3 for portchannels %s" \
               % (dut1_lagip_list[2:], dut3_lagip_list[2:], [lag_name3,lag_name3]))
        ############################################################################################
        for pochannel in [lag_name3, lag_name4]:
            dict1 = {'vrf_name': user_vrf_name, 'intf_name': pochannel, 'skip_error': True}
            dict2 = {'vrf_name': user_vrf_name, 'intf_name': pochannel, 'skip_error': True}
            parallel.exec_parallel(True, [dut1, dut4], vrf_api.bind_vrf_interface, [dict1, dict2])

    ip_api.config_ip_addr_interface(dut4,lo_name,dut4_lo_ip,lo_mask,"ipv4")
    ip_api.config_ip_addr_interface(dut4,lo_name,dut4_lo_ipv6,lo_v6mask,"ipv6")
    ############################################################################################
    hdrMsg("Step-C33: Adding member ports for the port-channel %s and %s on dut1 ,dut4"%(lag_name3,lag_name4))
    ############################################################################################
    utils.exec_all(True, [[pc.add_portchannel_member,dut1,lag_name3,[D1_port[0]]], [pc.add_portchannel_member,dut4,lag_name3,[D3_port[0]]] ])
    if vrfname == 'default':
        utils.exec_all(True, [[pc.add_portchannel_member,dut1,lag_name4,D1_port[1:3]], [pc.add_portchannel_member,dut4,lag_name4,D3_port[1:3]] ])

    ############################################################################################
    hdrMsg("Step-C34: Configure ip address on l3 port-channel in dut1 and dut4")
    ############################################################################################
    utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,lag_name3,dut1_l3lagip_list[0],ip_mask,"ipv4"], [ip_api.config_ip_addr_interface,dut4,lag_name3,dut3_l3lagip_list[0],ip_mask,"ipv4"]])
    if vrfname == 'default':
        utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,lag_name4,dut1_l3lagip_list[1],ip_mask,"ipv4"], [ip_api.config_ip_addr_interface,dut4,lag_name4,dut3_l3lagip_list[1],ip_mask,"ipv4"]])

    utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,lag_name3,dut1_l3lagipv6_list[0],ipv6_mask,"ipv6"], [ip_api.config_ip_addr_interface,dut4,lag_name3,dut3_l3lagipv6_list[0],ipv6_mask,"ipv6"]])
    if vrfname == 'default':
        utils.exec_all(True, [[ip_api.config_ip_addr_interface,dut1,lag_name4,dut1_l3lagipv6_list[1],ipv6_mask,"ipv6"], [ip_api.config_ip_addr_interface,dut4,lag_name4,dut3_l3lagipv6_list[1],ipv6_mask,"ipv6"]])

    ############################################################################################
    hdrMsg("Step-C35: Configure eBGP neighbors %s on dut1 and %s on dut4"%(dut3_l3lagip_list[0],dut1_l3lagip_list[0]))
    ############################################################################################
    utils.exec_all(True, [[bgp.create_bgp_neighbor,dut1,dut1_as,dut3_l3lagip_list[0],dut3_as,keep_alive,hold_down,"","ipv4",vrfname], [bgp.create_bgp_neighbor,dut4,dut3_as,dut1_l3lagip_list[0],dut1_as,keep_alive,hold_down,"","ipv4",vrfname]])
    if vrfname == 'default':
        utils.exec_all(True, [[bgp.create_bgp_neighbor,dut1,dut1_as,dut3_l3lagip_list[1],dut3_as,keep_alive,hold_down,"","ipv4",vrfname], [bgp.create_bgp_neighbor,dut4,dut3_as,dut1_l3lagip_list[1],dut1_as,keep_alive,hold_down,"","ipv4",vrfname]])

    dict1 = {'vrf_name':vrfname, "neighbor":dut3_l3lagip_list[0],"config":'yes',"config_type_list":['connect'],"connect":'1',"addr_family":"ipv4","local_as":dut1_as}
    dict2 = {'vrf_name':vrfname, "neighbor":dut1_l3lagip_list[0],"config":'yes',"config_type_list":['connect'],"connect":'1',"addr_family":"ipv4","local_as":dut3_as}
    parallel.exec_parallel(True,[dut1,dut4],bgp.config_bgp,[dict1,dict2])

    if vrfname == 'default':
        dict1 = {'vrf_name':vrfname, "neighbor":dut3_l3lagip_list[1],"config":'yes',"config_type_list":['connect'],"connect":'1',"addr_family":"ipv4","local_as":dut1_as}
        dict2 = {'vrf_name':vrfname, "neighbor":dut1_l3lagip_list[1],"config":'yes',"config_type_list":['connect'],"connect":'1',"addr_family":"ipv4","local_as":dut3_as}
        parallel.exec_parallel(True,[dut1,dut4],bgp.config_bgp,[dict1,dict2])

    ############################################################################################
    hdrMsg("Step-C36: Configure eBGP+ neighbors %s on dut1 and %s on dut4" % (
    dut3_l3lagipv6_list[0], dut1_l3lagipv6_list[0]))
    ############################################################################################

    utils.exec_all(True, [[bgp.create_bgp_neighbor,dut1,dut1_as,dut3_l3lagipv6_list[0],dut3_as,keep_alive,hold_down,"","ipv6",vrfname], [bgp.create_bgp_neighbor,dut4,dut3_as,dut1_l3lagipv6_list[0],dut1_as,keep_alive,hold_down,"","ipv6",vrfname]])
    if vrfname == 'default':
        utils.exec_all(True, [[bgp.create_bgp_neighbor,dut1,dut1_as,dut3_l3lagipv6_list[1],dut3_as,keep_alive,hold_down,"","ipv6",vrfname], [bgp.create_bgp_neighbor,dut4,dut3_as,dut1_l3lagipv6_list[1],dut1_as,keep_alive,hold_down,"","ipv6",vrfname]])

    dict1 = {'vrf_name':vrfname, "neighbor":dut3_l3lagipv6_list[0],"config":'yes',"config_type_list":['connect'],"connect":'1',"addr_family":"ipv6","local_as":dut1_as}
    dict2 = {'vrf_name':vrfname, "neighbor":dut1_l3lagipv6_list[0],"config":'yes',"config_type_list":['connect'],"connect":'1',"addr_family":"ipv6","local_as":dut3_as}
    parallel.exec_parallel(True,[dut1,dut4],bgp.config_bgp,[dict1,dict2])
    if vrfname == 'default':
        dict1 = {'vrf_name':vrfname, "neighbor":dut3_l3lagipv6_list[1],"config":'yes',"config_type_list":['connect'],"connect":'1',"addr_family":"ipv6","local_as":dut1_as}
        dict2 = {'vrf_name':vrfname, "neighbor":dut1_l3lagipv6_list[1],"config":'yes',"config_type_list":['connect'],"connect":'1',"addr_family":"ipv6","local_as":dut3_as}
        parallel.exec_parallel(True,[dut1,dut4],bgp.config_bgp,[dict1,dict2])

    bgp.config_bgp(dut1, vrf_name=vrfname ,local_as=dut1_as, config_type_list=["routeMap"], routeMap='rmap_v6', diRection='in',
                   neighbor=dut3_l3lagipv6_list[0], addr_family='ipv6')
    if vrfname == 'default':
        bgp.config_bgp(dut1, local_as=dut1_as, config_type_list=["routeMap"], routeMap='rmap_v6', diRection='in',
                       neighbor=dut3_l3lagipv6_list[1], addr_family='ipv6')

    ret_val=True

    ############################################################################################
    hdrMsg("Step-C37: Verify the portchannel status b/w dut1 and dut2 & Verify BGP sessions are UP")
    ############################################################################################
    if l2_switch == 'yes':
        for lag in [lag_name1, lag_name2]:
            result = pc.verify_portchannel_state(dut1, lag)
            if not result:
                st.log("FAILED : dut1 LAG interface %s does not exist" % lag)
                ret_val = False
            else:
                st.log("PASSED : dut1 LAG interface %s has come up" % lag)
            result = pc.verify_portchannel_state(dut2, lag)
            if not result:
                st.log("FAILED : dut1 LAG interface %s does not exist" % lag)
                ret_val = False
            else:
                st.log("PASSED : dut1 LAG interface %s has come up" % lag)
        if ret_val is False:
            st.error("LAG b/w DUT1 and DUT2 did not come up, so aborting the script run")
            st.report_fail('module_config_failed', 'LAG is not up b/w DUT1 and DUT2 in BASE config')

    elif l2_switch == 'no':
        for lag in [lag_name1, lag_name2]:
            result = pc.verify_portchannel_state(dut1, lag)
            if not result:
                st.log("FAILED : dut1 LAG interface %s does not exist" % lag)
                ret_val = False
            else:
                st.log("PASSED : dut1 LAG interface %s has come up" % lag)
        for lag in [lag_name1, lag_name2]:
            result = pc.verify_portchannel_state(dut3, lag)
            if not result:
                st.log("FAILED : dut3 LAG interface %s does not exist" % lag)
                ret_val = False
            else:
                st.log("PASSED : dut3 LAG interface %s has come up" % lag)
        if ret_val is False:
            st.error("LAG b/w DUT1 and DUT3 did not come up, so aborting the script run")
            st.report_fail('module_config_failed', 'LAG is not up b/w DUT1 and DUT3 in BASE config')

    if vrfname != 'default':
        result = retry_api(ip_bgp.check_bgp_session,dut1,nbr_list=[dut3_lagip_list[0]]+dut3_lagip_list[2:]+[dut3_lagipv6_list[0]]+dut3_lagipv6_list[2:],state_list=['Established'] * 7,vrf_name=user_vrf_name,retry_count=25,delay=2)
    else:
        result = retry_api(ip_bgp.check_bgp_session, dut1, nbr_list=[dut3_lagip_list[0]] + dut3_lagip_list[2:] + [
            dut3_lagipv6_list[0]] + dut3_lagipv6_list[2:], state_list=['Established'] * 8,
                           retry_count=25, delay=2)
    result =True
    if result is False:
        st.error("BGP b/w DUT1 and DUT3 did not come up, so aborting the script run..")
        st.report_fail('module_config_failed', 'One or more BGP sessions did not come up')
    ############################################################################################
    hdrMsg(" Base line config or module config ends here ")
    ############################################################################################


def multi_hop_deconfig(vrfname='default'):
    '''
    Multi-hop un config part
    :param vrfname:
    :return:
    '''

    ############################################################################################
    hdrMsg(" Base line deconfig or module deconfig starts here ")
    ############################################################################################
    ############################################################################################
    hdrMsg(" Assigning local vars based on the vrf config either default or non default vrf ")
    ############################################################################################
    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, D1_port, D3_port, \
    lo_name, peer_v4, peer_v6, lag_name1, lag_name2, lag_name3, lag_name4, dut1_lo_ip, dut3_lo_ip, dut4_lo_ip,\
    dut1_lo_ipv6, dut3_lo_ipv6, dut4_lo_ipv6 = return_vars(vrfname)

    if convergence_test == "no":
        ############################################################################################
        hdrMsg("Step-DC1: Remove arp and ipv6 neighbor entry on dut3 and dut4")
        ############################################################################################
        utils.exec_all(True, [[arp.delete_static_arp,dut3,tg_dut3_ip],[arp.delete_static_arp,dut4,tg_dut4_ip] ])
        utils.exec_all(True, [[arp.config_static_ndp,dut3,tg_dut3_ipv6, tg_dut3_mac, D3_ports[3],"del"],[arp.config_static_ndp,dut4,tg_dut4_ipv6, tg_dut4_mac, D3_port[3],"del"] ])
    ############################################################################################
    hdrMsg("Step-DC2: Remove ip address %s and ipv6 address %s on dut1 tg port " % (dut1_tg_ip,dut1_tg_ipv6))
    ############################################################################################
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,D1_ports[3],dut1_tg_ip,ip_mask], [ip_api.delete_ip_interface,dut3,D3_ports[3],dut3_tg_ip,ip_mask], [ip_api.delete_ip_interface,dut4,D3_port[3],dut4_tg_ip,ip_mask] ])
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,D1_ports[3],dut1_tg_ipv6,ipv6_mask,"ipv6"], [ip_api.delete_ip_interface,dut3,D3_ports[3],dut3_tg_ipv6,ipv6_mask,"ipv6"], [ip_api.delete_ip_interface,dut4,D3_port[3],dut4_tg_ipv6,ipv6_mask,"ipv6"] ])

    ############################################################################################
    hdrMsg("Step-DC4: Remove vlan member port for lag1 and than remove member port from lag1 ")
    ############################################################################################
    if l2_switch == 'yes':
        vlan_api.delete_vlan_member(dut1, access_vlan, [lag_name1])
        pc.delete_portchannel_member(dut1, lag_name1, [D1_ports[0]])
    elif l2_switch == 'no':
        utils.exec_all(True, [[vlan_api.delete_vlan_member,dut1,access_vlan,[lag_name1]],[vlan_api.delete_vlan_member,dut3,access_vlan,[lag_name1]] ])
        utils.exec_all(True, [[pc.delete_portchannel_member,dut1,lag_name1,[D1_ports[0]]],[pc.delete_portchannel_member,dut3,lag_name1,[D3_ports[0]]] ])

    if l2_switch == 'yes':
        ############################################################################################
        hdrMsg("Step-DC4: Remove LAG 1 in DUT 1 and remove access vlan member in dut 3")
        ############################################################################################
        utils.exec_all(True, [[pc.delete_portchannel,dut1,[lag_name1]], [vlan_api.delete_vlan_member,dut3,access_vlan,[D3_ports[0]]] ])
    elif l2_switch == 'no':
        utils.exec_all(True, [[pc.delete_portchannel,dut1,[lag_name1]], [pc.delete_portchannel,dut3,[lag_name1]] ])

    ############################################################################################
    hdrMsg("Step-DC5: Remove memebr ports from the trunk vlan in dut1 and dut3")
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True, [[vlan_api.delete_vlan_member,dut1,trunk_vlan[0],[lag_name2]], [vlan_api.delete_vlan_member,dut3,trunk_vlan[0],[D3_ports[2]]] ])
        utils.exec_all(True, [[vlan_api.delete_vlan_member,dut1,trunk_vlan[1],[lag_name2]], [vlan_api.delete_vlan_member,dut3,trunk_vlan[1],[D3_ports[2]]] ])
        utils.exec_all(True, [[vlan_api.delete_vlan_member,dut1,trunk_vlan[2],[lag_name2]], [vlan_api.delete_vlan_member,dut3,trunk_vlan[2],[D3_ports[2]]] ])
    elif l2_switch == 'no':
        utils.exec_all(True, [[vlan_api.delete_vlan_member,dut1,trunk_vlan[0],[lag_name2]], [vlan_api.delete_vlan_member,dut3,trunk_vlan[0],[lag_name2]] ])
        utils.exec_all(True, [[vlan_api.delete_vlan_member,dut1,trunk_vlan[1],[lag_name2]], [vlan_api.delete_vlan_member,dut3,trunk_vlan[1],[lag_name2]] ])
        utils.exec_all(True, [[vlan_api.delete_vlan_member,dut1,trunk_vlan[2],[lag_name2]], [vlan_api.delete_vlan_member,dut3,trunk_vlan[2],[lag_name2]] ])

    ############################################################################################
    hdrMsg("Step DC8: Remove the port channel2 in dut 1")
    ############################################################################################
    if l2_switch == 'yes':
        pc.delete_portchannel_member(dut1, lag_name2, D1_ports[1:3])
        pc.delete_portchannel(dut1,[lag_name2])
    elif l2_switch == 'no':
        utils.exec_all(True, [[pc.delete_portchannel_member,dut1,lag_name2,D1_ports[1:3]],[pc.delete_portchannel_member,dut3,lag_name2,D3_ports[1:3]] ])
        utils.exec_all(True, [[pc.delete_portchannel,dut1,[lag_name2]],[pc.delete_portchannel,dut3,[lag_name2]] ])

    ############################################################################################
    hdrMsg("Step-DC9: Remove ip address %s on dut1 and %s on dut3 for vlan %s"\
           % (dut1_lagip_list[0],dut3_lagip_list[0], access_vlan))
    ############################################################################################
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,access_vlan_name,dut1_lagip_list[0],ip_mask], [ip_api.delete_ip_interface,dut3,access_vlan_name,dut3_lagip_list[0],ip_mask] ])

    ############################################################################################
    hdrMsg("Step-DC10: Remove ip address %s on dut1 and %s on dut3 for vlans %s" \
           % (dut1_lagip_list[2:5],dut3_lagip_list[2:5],trunk_vlan))
    ############################################################################################
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,trunk_vlan_name[0],dut1_lagip_list[2],ip_mask], [ip_api.delete_ip_interface,dut3,trunk_vlan_name[0],dut3_lagip_list[2],ip_mask] ])
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,trunk_vlan_name[1],dut1_lagip_list[3],ip_mask], [ip_api.delete_ip_interface,dut3,trunk_vlan_name[1],dut3_lagip_list[3],ip_mask] ])
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,trunk_vlan_name[2],dut1_lagip_list[4],ip_mask], [ip_api.delete_ip_interface,dut3,trunk_vlan_name[2],dut3_lagip_list[4],ip_mask] ])

    ############################################################################################
    hdrMsg("Step-DC11: Remove ipv6 address %s on dut1 and %s on dut3 for vlan %s" \
           % (dut1_lagipv6_list[0], dut3_lagipv6_list[0], access_vlan))
    ############################################################################################
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,access_vlan_name,dut1_lagipv6_list[0],ipv6_mask,"ipv6"], [ip_api.delete_ip_interface,dut3,access_vlan_name,dut3_lagipv6_list[0],ipv6_mask,"ipv6"] ])

    ############################################################################################
    hdrMsg("Step-DC12: Remove ipv6 address %s on dut1 and %s on dut3 for vlans %s" \
           % (dut1_lagipv6_list[2:5], dut3_lagipv6_list[2:5], trunk_vlan))
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,trunk_vlan_name[0],dut1_lagipv6_list[2],ipv6_mask,"ipv6"], [ip_api.delete_ip_interface,dut3,trunk_vlan_name[0],dut3_lagipv6_list[2],ipv6_mask,"ipv6"], [pc.delete_portchannel_member,dut2,lag_name1,[D2_ports[0]]] ])
    elif l2_switch == 'no':
        utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,trunk_vlan_name[0],dut1_lagipv6_list[2],ipv6_mask,"ipv6"], [ip_api.delete_ip_interface,dut3,trunk_vlan_name[0],dut3_lagipv6_list[2],ipv6_mask,"ipv6"] ])

    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,trunk_vlan_name[1],dut1_lagipv6_list[3],ipv6_mask,"ipv6"], [ip_api.delete_ip_interface,dut3,trunk_vlan_name[1],dut3_lagipv6_list[3],ipv6_mask,"ipv6"] ])
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,trunk_vlan_name[2],dut1_lagipv6_list[4],ipv6_mask,"ipv6"], [ip_api.delete_ip_interface,dut3,trunk_vlan_name[2],dut3_lagipv6_list[4],ipv6_mask,"ipv6"] ])

    ############################################################################################
    hdrMsg("Step-DC13: Remove Vlan %s on dut1 ,dut3"%access_vlan)
    ############################################################################################
    if vrfname != 'default':
        for vlan in trunk_vlan_name_vrf:
            dict1 = {'vrf_name': user_vrf_name, 'intf_name': vlan, 'skip_error': True, 'config': 'no'}
            dict2 = {'vrf_name': user_vrf_name, 'intf_name': vlan, 'skip_error': True, 'config': 'no'}
            parallel.exec_parallel(True, [dut1, dut3], vrf_api.bind_vrf_interface, [dict1, dict2])

        dict1 = {'vrf_name': user_vrf_name, 'intf_name': D1_ports[3], 'skip_error': True, 'config': 'no'}
        dict2 = {'vrf_name': user_vrf_name, 'intf_name': D3_ports[3], 'skip_error': True, 'config': 'no'}
        parallel.exec_parallel(True, [dut1, dut3], vrf_api.bind_vrf_interface, [dict1, dict2])
        vrf_api.bind_vrf_interface(dut4, vrf_name=vrfname, intf_name=D3_port[3], skip_error=True)

        dict1 = {'vrf_name': user_vrf_name, 'intf_name': access_vlan_name_vrf, 'skip_error': True, 'config': 'no'}
        dict2 = {'vrf_name': user_vrf_name, 'intf_name': access_vlan_name_vrf, 'skip_error': True, 'config': 'no'}
        parallel.exec_parallel(True, [dut1, dut3], vrf_api.bind_vrf_interface, [dict1, dict2])

    utils.exec_all(True, [[vlan_api.delete_vlan,dut1,access_vlan], [vlan_api.delete_vlan,dut3,access_vlan] ])

    ############################################################################################
    hdrMsg("Step-DC14: Remove Vlans %s on dut1 , dut2 , dut3 for trunk ports"%trunk_vlan)
    ############################################################################################
    if l2_switch == 'yes':
        utils.exec_all(True, [[vlan_api.delete_vlan,dut1,trunk_vlan[0]], [vlan_api.delete_vlan,dut3,trunk_vlan[0]], [vlan_api.delete_vlan_member,dut2,trunk_vlan[0],[lag_name2,D2_ports[5]]] ])
        utils.exec_all(True, [[vlan_api.delete_vlan,dut1,trunk_vlan[1]], [vlan_api.delete_vlan,dut3,trunk_vlan[1]], [vlan_api.delete_vlan_member,dut2,trunk_vlan[1],[lag_name2,D2_ports[5]]] ])
        utils.exec_all(True, [[vlan_api.delete_vlan,dut1,trunk_vlan[2]], [vlan_api.delete_vlan,dut3,trunk_vlan[2]], [vlan_api.delete_vlan_member,dut2,trunk_vlan[2],[lag_name2,D2_ports[5]]] ])
    elif l2_switch == 'no':
        utils.exec_all(True, [[vlan_api.delete_vlan,dut1,trunk_vlan[0]], [vlan_api.delete_vlan,dut3,trunk_vlan[0]] ])
        utils.exec_all(True, [[vlan_api.delete_vlan,dut1,trunk_vlan[1]], [vlan_api.delete_vlan,dut3,trunk_vlan[1]] ])
        utils.exec_all(True, [[vlan_api.delete_vlan,dut1,trunk_vlan[2]], [vlan_api.delete_vlan,dut3,trunk_vlan[2]] ])

    ############################################################################################
    hdrMsg("##### Remove eBGP+ neighbors btween dut1 and dut3 ##########")
    ############################################################################################
    utils.exec_all(True, [[bgp.config_router_bgp_mode,dut1,dut1_as,'disable', vrfname], [bgp.config_router_bgp_mode,dut3,dut3_as,'disable',vrfname] ])
    if l2_switch == 'yes':
        utils.exec_all(True, [[bgp.config_router_bgp_mode,dut3,dut1_as,'disable',vrfname], [ip_api.config_route_map_global_nexthop,dut1,'rmap_v6','10','no'], [vlan_api.delete_vlan_member,dut2,access_vlan,[lag_name1,D2_ports[3]]] ])
    elif l2_switch == 'no':
        utils.exec_all(True, [[bgp.config_router_bgp_mode,dut3,dut1_as,'disable',vrfname], [ip_api.config_route_map_global_nexthop,dut1,'rmap_v6','10','no'] ])

    if l2_switch == 'yes':
        ############################################################################################
        hdrMsg("Step DC22: Remove the port channel in dut 2")
        ############################################################################################
        utils.exec_all(True, [[pc.delete_portchannel_member,dut2,lag_name2,D2_ports[1:3]], [pc.delete_portchannel,dut1,[lag_name2]] ])

        ############################################################################################
        hdrMsg("Step-DC24: Remove Vlans %s on dut2" %([access_vlan]+trunk_vlan))
        ############################################################################################
        for vlan in [access_vlan]+trunk_vlan:
            vlan_api.delete_vlan(dut2,vlan)

        ############################################################################################
        hdrMsg("Step-DC25: Remove LACP interfaces with name %s and %s on dut1 ,dut2"%(lag_name1,lag_name2))
        ############################################################################################
        pc.delete_portchannel(dut2,portchannel_list=[lag_name1, lag_name2])

    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,lo_name,dut1_lo_ip,lo_mask],[ip_api.delete_ip_interface,dut3,lo_name,dut3_lo_ip,lo_mask]])
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,lo_name,dut1_lo_ipv6,lo_v6mask,'ipv6'],[ip_api.delete_ip_interface,dut3,lo_name,dut3_lo_ipv6,lo_v6mask,'ipv6']])

    ############################################################################################
    hdrMsg("Step-C26: Delete ip address on l3 port-channel in dut1 and dut4")
    ############################################################################################
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,lag_name3,dut1_l3lagip_list[0],ip_mask,"ipv4"], [ip_api.delete_ip_interface,dut4,lag_name3,dut3_l3lagip_list[0],ip_mask,"ipv4"] ])
    if vrfname == 'default':
        utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,lag_name4,dut1_l3lagip_list[1],ip_mask,"ipv4"], [ip_api.delete_ip_interface,dut4,lag_name4,dut3_l3lagip_list[1],ip_mask,"ipv4"] ])

    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,lag_name3,dut1_l3lagipv6_list[0],ipv6_mask,"ipv6"], [ip_api.delete_ip_interface,dut4,lag_name3,dut3_l3lagipv6_list[0],ipv6_mask,"ipv6"] ])
    if vrfname == 'default':
        utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,lag_name4,dut1_l3lagipv6_list[1],ipv6_mask,"ipv6"], [ip_api.delete_ip_interface,dut4,lag_name4,dut3_l3lagipv6_list[1],ipv6_mask,"ipv6"] ])

    ip_api.delete_ip_interface(dut4,lo_name,dut4_lo_ip,lo_mask)
    ip_api.delete_ip_interface(dut4,lo_name,dut4_lo_ipv6,lo_v6mask,"ipv6")
    if vrfname == 'default':
        dict1 = {"loopback_name":lo_name,"config":"no"}
        parallel.exec_parallel(True,[dut1,dut3,dut4],ip_api.configure_loopback,[dict1,dict1,dict1])
    else:
        dict1 = {'vrf_name': user_vrf_name, 'intf_name': lo_name, 'skip_error': True, 'config': 'no'}
        dict2 = {'vrf_name': user_vrf_name, 'intf_name': lo_name, 'skip_error': True, 'config': 'no'}
        dict3 = {'vrf_name': user_vrf_name, 'intf_name': lo_name, 'skip_error': True, 'config': 'no'}
        parallel.exec_parallel(True, [dut1, dut3, dut4], vrf_api.bind_vrf_interface, [dict1, dict2, dict3])

    bgp.config_router_bgp_mode(dut4,dut3_as,'disable')
    ############################################################################################
    hdrMsg("Step C27: Remove the port channel %s and %s in dut 1 and dut 3"%(lag_name3,lag_name4))
    ############################################################################################
    if vrfname == 'default':
        utils.exec_all(True, [[pc.delete_portchannel_member,dut4,lag_name3,D3_port[0]], [pc.delete_portchannel_member,dut1,lag_name3,D1_port[0]] ])
        utils.exec_all(True, [[pc.delete_portchannel,dut4,[lag_name3]], [pc.delete_portchannel,dut1,[lag_name3]] ])
        utils.exec_all(True, [[pc.delete_portchannel_member,dut4,lag_name4,D3_port[1:3]], [pc.delete_portchannel_member,dut1,lag_name4,D1_port[1:3]] ])
        utils.exec_all(True, [[pc.delete_portchannel,dut4,[lag_name4]], [pc.delete_portchannel,dut1,[lag_name4]] ])
    else:
        for pochannel in [lag_name3, lag_name4]:
            dict1 = {'vrf_name': user_vrf_name, 'intf_name': pochannel, 'skip_error': True, 'config': 'no'}
            dict2 = {'vrf_name': user_vrf_name, 'intf_name': pochannel, 'skip_error': True, 'config': 'no'}
            parallel.exec_parallel(True, [dut1, dut4], vrf_api.bind_vrf_interface, [dict1, dict2])

    ############################################################################################
    hdrMsg(" Base line deconfig or module deconfig ends here ")
    ############################################################################################


@pytest.fixture(scope="function")
def bfd_func_001(request,bgp_base_config):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    hdrMsg("### CLEANUP ###")


@pytest.fixture(scope="function")
def bfd_func_001_default(request,bgp_base_config):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    hdrMsg("### CLEANUP ###")
    vrfname = 'default'
    ############################################################################################
    hdrMsg(" Assigning local vars based on the vrf config either default or non default vrf ")
    ############################################################################################
    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, D1_port, D3_port, \
    lo_name, peer_v4, peer_v6, lag_name1, lag_name2, lag_name3, lag_name4, \
    dut1_lo_ip, dut3_lo_ip, dut4_lo_ip, dut1_lo_ipv6, dut3_lo_ipv6, dut4_lo_ipv6 = return_vars(vrfname)

    bfd_nbrs_dut1 = [dut3_lagip_list[0]]
    non_bfd_nbrs_dut1 = dut3_lagip_list[2:]
    bfd_nbrs_dut3 = [dut1_lagip_list[0]]
    non_bfd_nbrs_dut3 = dut1_lagip_list[2:]
    addr_family = 'ipv4'
    mask = ip_mask
    tg_dest = tg_dest_nw
    ipv6_bfd_nbrs_dut1 = [dut3_lagipv6_list[0]]
    ipv6_non_bfd_nbrs_dut1 = dut3_lagipv6_list[2:]
    ipv6_bfd_nbrs_dut3 = [dut1_lagipv6_list[0]]
    ipv6_non_bfd_nbrs_dut3 = dut1_lagipv6_list[2:]
    ipv6_addr_family = 'ipv6'
    ipv6_tg_dest = tg_dest_nw_v6
    intf_list = [access_vlan_name]
    non_bfd_intf_list = trunk_vlan_name

    ############################################################################################
    hdrMsg("Step-C1: Remove BFD neighbors %s on dut3 and %s on dut1" % (dut1_lo_ip, dut3_lo_ip))
    ############################################################################################

    dict1 = {'vrf_name': vrfname, 'local_address': dut1_lo_ip, 'neighbor_ip': dut3_lo_ip, 'multihop': "yes",
             'config': "no"}
    dict2 = {'vrf_name': vrfname, 'local_address': dut3_lo_ip, 'neighbor_ip': dut1_lo_ip, 'multihop': "yes",
             'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name': vrfname, 'local_address': dut1_lo_ipv6, 'neighbor_ip': dut3_lo_ipv6, 'multihop': "yes",
             'config': "no"}
    dict2 = {'vrf_name': vrfname, 'local_address': dut3_lo_ipv6, 'neighbor_ip': dut1_lo_ipv6, 'multihop': "yes",
             'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])


    dict1 = {'vrf_name': vrfname, 'local_asn': dut1_as, 'neighbor_ip': bfd_nbrs_dut1[0], 'config': "no"}
    dict2 = {'vrf_name': vrfname, 'local_asn': dut3_as, 'neighbor_ip': bfd_nbrs_dut3[0], 'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name': vrfname, 'local_asn': dut1_as, 'neighbor_ip': ipv6_bfd_nbrs_dut1[0], 'config': "no"}
    dict2 = {'vrf_name': vrfname, 'local_asn': dut3_as, 'neighbor_ip': ipv6_bfd_nbrs_dut3[0], 'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': vrfname, 'interface': access_vlan_name, 'neighbor_ip': bfd_nbrs_dut1[0], 'config': "no"}
    dict2 = {'vrf_name': vrfname, 'interface': access_vlan_name, 'neighbor_ip': bfd_nbrs_dut3[0], 'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name': vrfname, 'interface': access_vlan_name, 'neighbor_ip': ipv6_bfd_nbrs_dut1[0], 'config': "no"}
    dict2 = {'vrf_name': vrfname, 'interface': access_vlan_name, 'neighbor_ip': ipv6_bfd_nbrs_dut3[0], 'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': vrfname, 'local_asn': dut1_as, 'neighbor_ip': non_bfd_nbrs_dut1[0], 'config': "no"}
    dict2 = {'vrf_name': vrfname, 'local_asn': dut3_as, 'neighbor_ip': non_bfd_nbrs_dut3[0], 'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name': vrfname, 'local_asn': dut1_as, 'neighbor_ip': non_bfd_nbrs_dut1[1], 'config': "no"}
    dict2 = {'vrf_name': vrfname, 'local_asn': dut3_as, 'neighbor_ip': non_bfd_nbrs_dut3[1], 'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name': vrfname, 'local_asn': dut1_as, 'neighbor_ip': non_bfd_nbrs_dut1[2], 'config': "no"}
    dict2 = {'vrf_name': vrfname, 'local_asn': dut3_as, 'neighbor_ip': non_bfd_nbrs_dut3[2], 'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg("Step-C2: Remove BFD for BGP neighbor %s on dut3" % non_bfd_nbrs_dut3)
    ###########################################################################################
    dict1 = {'vrf_name': vrfname, 'interface': non_bfd_intf_list[0], 'neighbor_ip': non_bfd_nbrs_dut1[0],
             'config': "no", 'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx}
    dict2 = {'vrf_name': vrfname, 'interface': non_bfd_intf_list[0], 'neighbor_ip': non_bfd_nbrs_dut3[0],
             'config': "no", 'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name': vrfname, 'interface': non_bfd_intf_list[1], 'neighbor_ip': non_bfd_nbrs_dut1[1],
             'config': "no", 'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx}
    dict2 = {'vrf_name': vrfname, 'interface': non_bfd_intf_list[1], 'neighbor_ip': non_bfd_nbrs_dut3[1],
             'config': "no", 'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name': vrfname, 'interface': non_bfd_intf_list[2], 'neighbor_ip': non_bfd_nbrs_dut1[2],
             'config': "no", 'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx}
    dict2 = {'vrf_name': vrfname, 'interface': non_bfd_intf_list[2], 'neighbor_ip': non_bfd_nbrs_dut3[2],
             'config': "no", 'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])


@pytest.mark.sanity
def test_bfd_lag_001(bfd_func_001_default):
    ###########################################################################################
    hdrMsg("TC01: Verify eBGP Single hop BFD and Static Multi hop BFD with L2 LAG operation in dual stack")
    ###########################################################################################
    result = verify_bfd_lag1()
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdFn031','eBGP-BFD-SHOP-&-STATIC-MHOP','L2-LAG-&-DUAL-STACK')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdFn031','eBGP-BFD-SHOP-&-STATIC-MHOP','L2-LAG-&-DUAL-STACK')


@pytest.fixture(scope="function")
def bfd_func_001_vrf(request,bgp_base_config):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    hdrMsg("### CLEANUP ###")
    vrfname = user_vrf_name
    ############################################################################################
    hdrMsg(" Assigning local vars based on the vrf config either default or non default vrf ")
    ############################################################################################
    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, D1_port, D3_port, \
    lo_name, peer_v4, peer_v6, lag_name1, lag_name2, lag_name3, lag_name4, \
    dut1_lo_ip, dut3_lo_ip, dut4_lo_ip, dut1_lo_ipv6, dut3_lo_ipv6, dut4_lo_ipv6 = return_vars(vrfname)

    bfd_nbrs_dut1 = [dut3_lagip_list[0]]; non_bfd_nbrs_dut1 = dut3_lagip_list[2:]
    bfd_nbrs_dut3 = [dut1_lagip_list[0]]; non_bfd_nbrs_dut3 = dut1_lagip_list[2:]
    addr_family = 'ipv4';mask=ip_mask;tg_dest = tg_dest_nw;
    ipv6_bfd_nbrs_dut1 = [dut3_lagipv6_list[0]]; ipv6_non_bfd_nbrs_dut1 = dut3_lagipv6_list[2:]
    ipv6_bfd_nbrs_dut3 = [dut1_lagipv6_list[0]]; ipv6_non_bfd_nbrs_dut3 = dut1_lagipv6_list[2:]
    ipv6_addr_family = 'ipv6'; ipv6_tg_dest = tg_dest_nw_v6;
    intf_list = [access_vlan_name]
    non_bfd_intf_list = trunk_vlan_name

    ############################################################################################
    hdrMsg("Step-C1: Remove BFD neighbors %s on dut3 and %s on dut1"%(dut1_lo_ip,dut3_lo_ip))
    ############################################################################################
    dict1 = {'vrf_name': vrfname, 'interface': lo_name, 'local_address': dut1_lo_ip, 'neighbor_ip': dut3_lo_ip,
             'multihop': "yes", 'config': "no"}
    dict2 = {'vrf_name': vrfname, 'interface': lo_name, 'local_address': dut3_lo_ip, 'neighbor_ip': dut1_lo_ip,
             'multihop': "yes", 'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name': vrfname, 'interface': lo_name, 'local_address': dut1_lo_ipv6, 'neighbor_ip': dut3_lo_ipv6,
             'multihop': "yes", 'config': "no"}
    dict2 = {'vrf_name': vrfname, 'interface': lo_name, 'local_address': dut3_lo_ipv6, 'neighbor_ip': dut1_lo_ipv6,
             'multihop': "yes", 'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1={'vrf_name':vrfname,'local_asn':dut1_as,'neighbor_ip':bfd_nbrs_dut1[0],'config':"no"}
    dict2={'vrf_name':vrfname,'local_asn':dut3_as,'neighbor_ip':bfd_nbrs_dut3[0],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    dict1={'vrf_name':vrfname,'local_asn':dut1_as,'neighbor_ip':ipv6_bfd_nbrs_dut1[0],'config':"no"}
    dict2={'vrf_name':vrfname,'local_asn':dut3_as,'neighbor_ip':ipv6_bfd_nbrs_dut3[0],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    dict1={'vrf_name':vrfname,'interface':access_vlan_name,'neighbor_ip':bfd_nbrs_dut1[0],'config':"no"}
    dict2={'vrf_name':vrfname,'interface':access_vlan_name,'neighbor_ip':bfd_nbrs_dut3[0],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    dict1={'vrf_name':vrfname,'interface':access_vlan_name,'neighbor_ip':ipv6_bfd_nbrs_dut1[0],'config':"no"}
    dict2={'vrf_name':vrfname,'interface':access_vlan_name,'neighbor_ip':ipv6_bfd_nbrs_dut3[0],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    dict1={'vrf_name':vrfname,'local_asn':dut1_as,'neighbor_ip':non_bfd_nbrs_dut1[0],'config':"no"}
    dict2={'vrf_name':vrfname,'local_asn':dut3_as,'neighbor_ip':non_bfd_nbrs_dut3[0],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    dict1={'vrf_name':vrfname,'local_asn':dut1_as,'neighbor_ip':non_bfd_nbrs_dut1[1],'config':"no"}
    dict2={'vrf_name':vrfname,'local_asn':dut3_as,'neighbor_ip':non_bfd_nbrs_dut3[1],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    dict1={'vrf_name':vrfname,'local_asn':dut1_as,'neighbor_ip':non_bfd_nbrs_dut1[2],'config':"no"}
    dict2={'vrf_name':vrfname,'local_asn':dut3_as,'neighbor_ip':non_bfd_nbrs_dut3[2],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step-C2: Remove BFD for BGP neighbor %s on dut3"%non_bfd_nbrs_dut3)
    ###########################################################################################
    dict1={'vrf_name':vrfname,'interface':non_bfd_intf_list[0],'neighbor_ip':non_bfd_nbrs_dut1[0],'config':"no",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    dict2={'vrf_name':vrfname,'interface':non_bfd_intf_list[0],'neighbor_ip':non_bfd_nbrs_dut3[0],'config':"no",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    dict1={'vrf_name':vrfname,'interface':non_bfd_intf_list[1],'neighbor_ip':non_bfd_nbrs_dut1[1],'config':"no",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    dict2={'vrf_name':vrfname,'interface':non_bfd_intf_list[1],'neighbor_ip':non_bfd_nbrs_dut3[1],'config':"no",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    dict1={'vrf_name':vrfname,'interface':non_bfd_intf_list[2],'neighbor_ip':non_bfd_nbrs_dut1[2],'config':"no",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    dict2={'vrf_name':vrfname,'interface':non_bfd_intf_list[2],'neighbor_ip':non_bfd_nbrs_dut3[2],'config':"no",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])


@pytest.mark.sanity
def test_bfd_single_hop_static_mhop_functionality_over_lag(bfd_func_001_vrf):
    ###########################################################################################
    hdrMsg("TC01: Verify eBGP Single hop BFD and Static Multi hop BFD with L2 LAG operation in dual stack")
    ###########################################################################################
    result = verify_bfd_lag1(vrfname=user_vrf_name)
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdVrfFn010 FtOpSoRoBfdVrfFn011 FtOpSoRoBfdVrfFn015','eBGP-BFD-SHOP-&-STATIC-MHOP-VRF','L2-LAG-&-DUAL-STACK')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdVrfFn010 FtOpSoRoBfdVrfFn011 FtOpSoRoBfdVrfFn015','eBGP-BFD-SHOP-&-STATIC-MHOP-VRF','L2-LAG-&-DUAL-STACK')


@pytest.mark.sanity
def test_bfd_lag_004(bfd_func_001):
    ###########################################################################################
    hdrMsg("TC01: Verify eBGP BFD Single hop with fast failover disabled and L3 LAG operation in dual stack")
    ###########################################################################################
    result = verify_bfd_lag4()
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdFn027','eBGP-BFD-SHOP-&-MHOP-Fastfailover-disabled','L3-LAG-&-DUAL-STACK')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdFn027','eBGP-BFD-SHOP-&-MHOP-Fastfailover-disabled','L3-LAG-&-DUAL-STACK')


@pytest.mark.sanity
def test_bfd_lag_002(bfd_func_001):
    ###########################################################################################
    hdrMsg("TC02: Verify static single hop BFD, static multi BFD with L2 LAG operation and dual stack")
    ###########################################################################################
    result = verify_bfd_lag2()
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdFn067','STATIC-BFD-SHOP-MHOP','L2-LAG-&-DUAL-STACK')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdFn067','STATIC-BFD-SHOP-MHOP','L2-LAG-&-DUAL-STACK')


@pytest.mark.sanity
def test_bfd_lag_002_vrf(bfd_func_001):
    ###########################################################################################
    hdrMsg("TC02: Verify static single hop BFD, static multi BFD with L2 LAG operation and dual stack")
    ###########################################################################################
    result = verify_bfd_lag2(vrfname=user_vrf_name)
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdVrfFn003','STATIC-BFD-SHOP-MHOP','L2-LAG-&-DUAL-STACK')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdVrfFn003','STATIC-BFD-SHOP-MHOP','L2-LAG-&-DUAL-STACK')


@pytest.mark.sanity
def test_bfd_lag_005(bfd_func_001):
    ###########################################################################################
    hdrMsg("TC03: Verify eBGP Single hop BFD with fast failover enabled and BFD session timeout")
    ###########################################################################################
    result = verify_bfd_lag5()
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdVrfFn018 FtOpSoRoBfdVrfFn012','eBGP-BFD-VRF-SHOP-FAST-FAILOVER','L2-LAG-&-DUAL-STACK')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdVrfFn018 FtOpSoRoBfdVrfFn012','eBGP-BFD-VRF-SHOP-FAST-FAILOVER','L2-LAG-&-DUAL-STACK')


@pytest.mark.sanity
def test_bfd_single_hop_mhop_klish(bfd_func_001):
    ###########################################################################################
    hdrMsg("TC01: Verify eBGP Single hop BFD and Static Multi hop BFD with L2 LAG operation in dual stack using klish")
    ###########################################################################################
    result = verify_bfd_lag12(vrfname=user_vrf_name)
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdVrfFn022 FtOpSoRoBfdVrfFn023 FtOpSoRoBfdVrfFn024','eBGP-BFD-SHOP-&-STATIC-MHOP-VRF','L2-LAG-&-DUAL-STACK')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdVrfFn022 FtOpSoRoBfdVrfFn023 FtOpSoRoBfdVrfFn024','eBGP-BFD-SHOP-&-STATIC-MHOP-VRF','L2-LAG-&-DUAL-STACK')


@pytest.mark.sanity
def test_bfd_lag_003(bfd_func_001):
    ###########################################################################################
    hdrMsg("TC03: Verify iBGP Single hop BFD and Static Multi hop BFD with dual stack")
    ###########################################################################################
    result = verify_bfd_lag3()
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdFn022','iBGP-BFD-SHOP-&-STATIC-MHOP','L2-LAG-&-DUAL-STACK')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdFn022','iBGP-BFD-SHOP-&-STATIC-MHOP','L2-LAG-&-DUAL-STACK')


@pytest.mark.sanity
def test_bfd_lag_006(bfd_func_001):
    ###########################################################################################
    hdrMsg("TC03: Verify eBGP dynamic multi-hop BFD over vrf on l2 LAG")
    ###########################################################################################
    result = verify_bfd_lag6()
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdVrfFn005 FtOpSoRoBfdVrfFn006 FtOpSoRoBfdVrfFn008','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdVrfFn005 FtOpSoRoBfdVrfFn006 FtOpSoRoBfdVrfFn008','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK')


@pytest.fixture(scope="function")
def bfd_func_011_vrf(request,bgp_base_config):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    hdrMsg("### CLEANUP ###")
    vrfname = user_vrf_name
    ############################################################################################
    hdrMsg(" Assigning local vars based on the vrf config either default or non default vrf ")
    ############################################################################################
    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, D1_port, D3_port, \
    lo_name, peer_v4, peer_v6, lag_name1, lag_name2, lag_name3, lag_name4, \
    dut1_lo_ip, dut3_lo_ip, dut4_lo_ip, dut1_lo_ipv6, dut3_lo_ipv6, dut4_lo_ipv6 = return_vars(user_vrf_name)

    ############################################################################################
    hdrMsg("Step-T5: Un configure BFD and BGP over ipv6 un numbered interfaces")
    ############################################################################################
    # Get DUT link local addresses
    rt_link_local_addr = utils.exec_all(True, [[ip_api.get_link_local_addresses, vars.D1, access_vlan_name],
                                                     [ip_api.get_link_local_addresses, vars.D2, access_vlan_name]])

    d1_prt_link_local = rt_link_local_addr[0][0]
    d2_prt_link_local = rt_link_local_addr[0][1]

    dict1 = {'vrf_name': user_vrf_name, 'interface': lo_name, 'local_address': dut1_lo_ipv6,
             'neighbor_ip': dut3_lo_ipv6, 'multihop': "yes", 'config': "no"}
    dict2 = {'vrf_name': user_vrf_name, 'interface': lo_name, 'local_address': dut3_lo_ipv6,
             'neighbor_ip': dut1_lo_ipv6, 'multihop': "yes", 'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    utils.exec_all(True, [[ip_api.config_interface_ip6_link_local, dut1, access_vlan_name,'disable'],
                          [ip_api.config_interface_ip6_link_local, dut3, access_vlan_name,'disable']])

    utils.exec_all(True, [[bgp.config_router_bgp_mode, dut1, dut1_as, 'disable',user_vrf_name],
                          [bgp.config_router_bgp_mode, dut3, dut3_as, 'disable',user_vrf_name]])


    ############################################################################################
    hdrMsg("Step-RC1: Configure ip address %s on dut1 and %s on dut3 for vlan %s" \
           % (dut1_lagip_list[0], dut3_lagip_list[0], access_vlan))
    ############################################################################################
    utils.exec_all(True,
                   [[ip_api.config_ip_addr_interface, dut1, access_vlan_name, dut1_lagip_list[0], ip_mask, "ipv4"],
                    [ip_api.config_ip_addr_interface, dut3, access_vlan_name, dut3_lagip_list[0], ip_mask, "ipv4"]])

    ############################################################################################
    hdrMsg("Step-RC2: Configure ipv6 address %s on dut1 and %s on dut3 for vlan %s" \
           % (dut1_lagipv6_list[0], dut3_lagipv6_list[0], access_vlan))
    ############################################################################################
    utils.exec_all(True,
                   [[ip_api.config_ip_addr_interface, dut1, access_vlan_name, dut1_lagipv6_list[0], ipv6_mask, "ipv6"],
                    [ip_api.config_ip_addr_interface, dut3, access_vlan_name, dut3_lagipv6_list[0], ipv6_mask, "ipv6"]])

    ############################################################################################
    hdrMsg("Step-RC3: Configure ip address %s on dut1 and %s on dut3 for vlans %s" \
           % (dut1_lagip_list[2:5], dut3_lagip_list[2:5], trunk_vlan))
    ############################################################################################
    utils.exec_all(True,
                   [[ip_api.config_ip_addr_interface, dut1, trunk_vlan_name[0], dut1_lagip_list[2], ip_mask, "ipv4"],
                    [ip_api.config_ip_addr_interface, dut3, trunk_vlan_name[0], dut3_lagip_list[2], ip_mask, "ipv4"]])
    utils.exec_all(True,
                   [[ip_api.config_ip_addr_interface, dut1, trunk_vlan_name[1], dut1_lagip_list[3], ip_mask, "ipv4"],
                    [ip_api.config_ip_addr_interface, dut3, trunk_vlan_name[1], dut3_lagip_list[3], ip_mask, "ipv4"]])
    utils.exec_all(True,
                   [[ip_api.config_ip_addr_interface, dut1, trunk_vlan_name[2], dut1_lagip_list[4], ip_mask, "ipv4"],
                    [ip_api.config_ip_addr_interface, dut3, trunk_vlan_name[2], dut3_lagip_list[4], ip_mask, "ipv4"]])

    ############################################################################################
    hdrMsg("Step-RC4: Configure ipv6 address %s on dut1 and %s on dut3 for vlans %s" \
           % (dut1_lagipv6_list[2:5], dut3_lagipv6_list[2:5], trunk_vlan))
    ############################################################################################
    utils.exec_all(True, [
        [ip_api.config_ip_addr_interface, dut1, trunk_vlan_name[0], dut1_lagipv6_list[2], ipv6_mask, "ipv6"],
        [ip_api.config_ip_addr_interface, dut3, trunk_vlan_name[0], dut3_lagipv6_list[2], ipv6_mask, "ipv6"]])
    utils.exec_all(True, [
        [ip_api.config_ip_addr_interface, dut1, trunk_vlan_name[1], dut1_lagipv6_list[3], ipv6_mask, "ipv6"],
        [ip_api.config_ip_addr_interface, dut3, trunk_vlan_name[1], dut3_lagipv6_list[3], ipv6_mask, "ipv6"]])
    utils.exec_all(True, [
        [ip_api.config_ip_addr_interface, dut1, trunk_vlan_name[2], dut1_lagipv6_list[4], ipv6_mask, "ipv6"],
        [ip_api.config_ip_addr_interface, dut3, trunk_vlan_name[2], dut3_lagipv6_list[4], ipv6_mask, "ipv6"]])


@pytest.mark.sanity
def test_bfd_lag_011_bgp_unnumbered(bfd_func_011_vrf):
    ###########################################################################################
    hdrMsg("TC03: Verify BFD over bgp unnumbered with dynamic single hop and static multi-hop over vrf on l2 LAG")
    ###########################################################################################
    result = verify_bfd_lag11()
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdVrfFn020 FtOpSoRoBfdVrfFn021','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdVrfFn020 FtOpSoRoBfdVrfFn021','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK')


@pytest.mark.sanity
def test_bfd_lag_007_clear_bgp_config_reload(bfd_func_001):
    ###########################################################################################
    hdrMsg("TC03: Verify config reload and clear bgp on eBGP dynamic multi-hop BFD over vrf on l2 LAG")
    ###########################################################################################
    result = verify_bfd_lag7()
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdVrfFn025 FtOpSoRoBfdVrfFn033','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdVrfFn025 FtOpSoRoBfdVrfFn033','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK')


@pytest.mark.sanity
def test_bfd_lag_008_fast_reboot(bfd_func_001):
    ###########################################################################################
    hdrMsg("TC03: Verify fast reboot eBGP dynamic multi-hop BFD over vrf on l2 LAG")
    ###########################################################################################
    result = verify_bfd_lag9('fast_reboot')
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdVrfFn035','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdVrfFn035','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK')


@pytest.mark.sanity
def test_bfd_lag_009_container_restart(bfd_func_001):
    ###########################################################################################
    hdrMsg("TC03: Verify fast reboot and container restart eBGP dynamic multi-hop BFD over vrf on l2 LAG")
    ###########################################################################################
    result = verify_bfd_lag9('container_restart')
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdVrfFn034','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdVrfFn034','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK')


@pytest.mark.sanity
def test_bfd_lag_010_save_and_reload(bfd_func_001):
    ###########################################################################################
    hdrMsg("TC03: Verify save and  reboot dynamic multi-hop BFD over vrf on l2 LAG")
    ###########################################################################################
    result = verify_bfd_lag9('save_and_reload')
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdVrfFn037','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdVrfFn037','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK')


def test_bfd_lag_012_warm_reboot(bfd_func_001):
    ###########################################################################################
    hdrMsg("TC03: Verify save and  reboot dynamic multi-hop BFD over vrf on l2 LAG")
    ###########################################################################################
    result = verify_bfd_lag9('warm_reboot')
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdVrfFn031','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK-WARM-REBOOT')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdVrfFn031','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK-WARM-REBOOT')


def test_bfd_lag_013_cold_restart(bfd_func_001):
    ###########################################################################################
    hdrMsg("TC03: Verify save and  reboot dynamic multi-hop BFD over vrf on l2 LAG")
    ###########################################################################################
    result = verify_bfd_lag9('cold_restart')
    if result:
        st.report_pass('bfd_pass_tcid','FtOpSoRoBfdVrfFn032','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK-COLD-RESTART')
    else:
        st.report_fail('bfd_fail_tcid','FtOpSoRoBfdVrfFn032','eBGP-BFD-VRF-MHOP','L2-LAG-&-DUAL-STACK-COLD-RESTART')


def convergence_measure(dut,intf_to_flap,version='both',dest='d3'):
    multiplier=2.0
    if dest == 'd4':
        stream = data.streams['stream_handle_list']
    elif dest == 'd3':
        stream = data.streams['stream1_handle_list']
    elif dest == 'd3vrf':
        stream = data.streams['stream1_handle_list_vrf']
    elif dest == 'd4vrf':
        stream = data.streams['stream_handle_list_vrf']
    if dest == 'd3' or dest == 'd4':
        tg1.tg_traffic_control(action='clear_stats', port_handle=tg_handles)
    else:
        tg1.tg_traffic_control(action='clear_stats', port_handle=tg_handles_vrf)
    tg1.tg_traffic_control(action='run',stream_handle=stream)
    st.wait(2)
    st.log("Bring down port %s on DUT %s"%(intf_to_flap,dut))
    if isinstance(intf_to_flap,list):
        port.shutdown(dut,[intf_to_flap[0],intf_to_flap[1]])
    elif isinstance(intf_to_flap,str):
        port.shutdown(dut,[intf_to_flap])
    st.wait(int(hold_down))

    if 'ixia' in vars['tgen_list'][0]:
        key_val = 'raw_pkt_count'
    else:
        key_val = 'pkt_count'

    tg1.tg_traffic_control(action='stop',stream_handle=stream)
    if dest == 'd3' or dest == 'd4':
        tx_count = tg1.tg_traffic_stats(port_handle=tg_handles[0], mode='aggregate')[tg_handles[0]]['aggregate']['tx'][key_val]
    else:
        tx_count = tg1.tg_traffic_stats(port_handle=tg_handles_vrf[0], mode='aggregate')[tg_handles_vrf[0]]['aggregate']['tx'][
            key_val]

    if dest == 'd4':
        rx_count = tg1.tg_traffic_stats(port_handle=tg_handles[2], mode='aggregate')[tg_handles[2]]['aggregate']['rx'][key_val]
    elif dest == 'd3':
        rx_count = tg1.tg_traffic_stats(port_handle=tg_handles[1], mode='aggregate')[tg_handles[1]]['aggregate']['rx'][key_val]
    elif dest == 'd4vrf':
        rx_count = tg1.tg_traffic_stats(port_handle=tg_handles_vrf[2], mode='aggregate')[tg_handles_vrf[2]]['aggregate']['rx'][key_val]
    elif dest == 'd3vrf':
        rx_count = tg1.tg_traffic_stats(port_handle=tg_handles_vrf[1], mode='aggregate')[tg_handles_vrf[1]]['aggregate']['rx'][key_val]
    if 'ixia' in vars['tgen_list'][0]:
        if dest == 'd3' or dest == 'd4':
            tg1.tg_traffic_control(action='clear_stats', port_handle=tg_handles)
        else:
            tg1.tg_traffic_control(action='clear_stats', port_handle=tg_handles_vrf)

    if int(rx_count) == 0:
        st.log("Bring up port %s on DUT %s" % (intf_to_flap, dut))
        port.noshutdown(dut, intf_to_flap)
        st.log("Traffic Failed: TG Rx port did not receive any packets and TG Tx Pkt count is %s"%tx_count)
        if dest == 'd3' or dest == 'd3vrf':
            bfd.debug_bgp_bfd([dut1, dut3])
        elif dest == 'd4' or dest == 'd4vrf':
            bfd.debug_bgp_bfd([dut1, dut4])
        return False
    else:
        drop = float(tx_count) - float(rx_count)
        convergence_time = (float(drop)/float(traffic_rate))*1000
        st.log("Bring up port %s on DUT %s" % (intf_to_flap, dut))
        if isinstance(intf_to_flap,list):
            port.noshutdown(dut,[intf_to_flap[0],intf_to_flap[1]])
        elif isinstance(intf_to_flap,str):
            port.noshutdown(dut,[intf_to_flap])
        st.log("================================ CALCULATION =============================================")
        st.log("Tx frames = %s and Rx frames = %s "%(float(tx_count),float(rx_count)))
        st.log("Drop frames = %s and Traffic Rate = %s "%(float(drop),int(traffic_rate)))
        st.log("convergence time in msec = %s and we need to divide it by two as we have ipv4 and ipv6 flows "%convergence_time)
        st.log("================================ END =============================================")
        st.log("Traffic Convergence time : %s msec" % (convergence_time/multiplier))
        return (convergence_time/multiplier)


def verify_bfd_lag1(vrfname='default'):
    '''

    :param vrfname:
    :return:
    '''
    ############################################################################################
    hdrMsg(" Assigning local vars based on the vrf config either default or non default vrf ")
    ############################################################################################
    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, D1_port, D3_port, \
    lo_name, peer_v4, peer_v6, lag_name1, lag_name2, lag_name3, lag_name4, \
    dut1_lo_ip, dut3_lo_ip, dut4_lo_ip, dut1_lo_ipv6, dut3_lo_ipv6, dut4_lo_ipv6 = return_vars(vrfname)

    bfd_nbrs_dut1 = [dut3_lagip_list[0]]; non_bfd_nbrs_dut1 = dut3_lagip_list[2:]
    bfd_nbrs_dut3 = [dut1_lagip_list[0]]; non_bfd_nbrs_dut3 = dut1_lagip_list[2:]
    addr_family = 'ipv4';mask=ip_mask;tg_dest = tg_dest_nw;
    ipv6_bfd_nbrs_dut1 = [dut3_lagipv6_list[0]]; ipv6_non_bfd_nbrs_dut1 = dut3_lagipv6_list[2:]
    ipv6_bfd_nbrs_dut3 = [dut1_lagipv6_list[0]]; ipv6_non_bfd_nbrs_dut3 = dut1_lagipv6_list[2:]
    ipv6_addr_family = 'ipv6'; ipv6_tg_dest = tg_dest_nw_v6;
    intf_list = [access_vlan_name]
    non_bfd_intf_list = trunk_vlan_name

    ret_val = True
    if vrfname == 'default':
        dict1={'vrf_name':vrfname,'local_asn':dut1_as,'neighbor_ip':bfd_nbrs_dut1[0],'config':"yes"}
        dict2={'vrf_name':vrfname,'local_asn':dut3_as,'neighbor_ip':bfd_nbrs_dut3[0],'config':"yes"}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
        dict1={'vrf_name':vrfname,'local_asn':dut1_as,'neighbor_ip':ipv6_bfd_nbrs_dut1[0],'config':"yes"}
        dict2={'vrf_name':vrfname,'local_asn':dut3_as,'neighbor_ip':ipv6_bfd_nbrs_dut3[0],'config':"yes"}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

        ###########################################################################################
        hdrMsg("Step-C1: Verify ebgp single hop BFD session show up peer type as dynamic for %s in dut1 towards dut3"%bfd_nbrs_dut1)
        ###########################################################################################
        result = retry_api(bfd.verify_bfd_peer,dut1,peer=[bfd_nbrs_dut1[0],ipv6_bfd_nbrs_dut1[0]],interface=[intf_list[0],intf_list[0]],status=['up','up'],local_addr=["",ipv6_bfd_nbrs_dut3[0]],peer_type=["dynamic","dynamic"],retry_count=3,delay=1)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" %(bfd_nbrs_dut1[0],ipv6_bfd_nbrs_dut1[0]))
            ret_val = False

        dict1={'local_asn':dut1_as,'neighbor_ip':bfd_nbrs_dut1[0],'config':"no"}
        dict2={'local_asn':dut3_as,'neighbor_ip':bfd_nbrs_dut3[0],'config':"no"}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
        dict1={'local_asn':dut1_as,'neighbor_ip':ipv6_bfd_nbrs_dut1[0],'config':"no"}
        dict2={'local_asn':dut3_as,'neighbor_ip':ipv6_bfd_nbrs_dut3[0],'config':"no"}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

        if convergence_test == "yes":
            port.shutdown(dut1,[D1_ports[0]]);port.noshutdown(dut1,[D1_ports[0]])
            st.wait(2)
            ###########################################################################################
            hdrMsg("Step-C52: Verify routing table to check if destination network %s installed with next-hop %s"%(tg_dest,non_bfd_intf_list[0]) )
            ###########################################################################################
            result = ip_api.verify_ip_route(dut1,ip_address="%s/%s"%(tg_dest,mask),interface=non_bfd_intf_list[0], family=addr_family)
            if result:
                st.log("DUT1: Destination route %s installed with nexthop interface %s "%(tg_dest,non_bfd_intf_list[0]))
            else:
                st.log("INFO : DUT1: Destination route %s not installed with nexthop interface %s " % (tg_dest, non_bfd_intf_list[0]))
            ###########################################################################################
            hdrMsg("Step-C53: Verify routing table to check if destination network %s installed with next-hop %s"%(ipv6_tg_dest,non_bfd_intf_list[0]) )
            ###########################################################################################
            result = ip_api.verify_ip_route(dut1,ip_address="%s/%s"%(ipv6_tg_dest,ipv6_mask),interface=non_bfd_intf_list[0], family=ipv6_addr_family)
            if result:
                st.log("DUT1: Destination route %s installed with nexthop interface %s "%(ipv6_tg_dest,non_bfd_intf_list[0]))
            else:
                st.log("INFO : DUT1: Destination route %s not installed with nexthop interface %s " % (ipv6_tg_dest, non_bfd_intf_list[0]))
            ###########################################################################################
            hdrMsg("Step-C54: Measure Traffic convergence without BFD by shutting dut2<---> dut3 port" )
            ###########################################################################################
            #converged = convergence_measure(flap_dut,lag_name2,version="both",dest='d3')
            converged = convergence_measure(flap_dut,D3_ports[1:3],version="both",dest='d3')
            st.log(" >>>>> Traffic Convergence without BFD for L2 LAG case: %s ms <<<<<<" % converged)


    ###########################################################################################
    hdrMsg("Step-C1: Enable BFD for BGP neighbor %s on dut1 and %s on dut3"%(bfd_nbrs_dut1,bfd_nbrs_dut3))
    ###########################################################################################
    dict1={'vrf_name':vrfname,'local_asn':dut1_as,'neighbor_ip':bfd_nbrs_dut1[0],'config':"yes"}
    dict2={'vrf_name':vrfname,'local_asn':dut3_as,'neighbor_ip':bfd_nbrs_dut3[0],'config':"yes"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    dict1={'vrf_name':vrfname,'interface':access_vlan_name,'neighbor_ip':bfd_nbrs_dut1[0],'config':"yes",'multiplier':multiplier1,'rx_intv':bfd_rx1,'tx_intv':bfd_tx1}
    dict2={'vrf_name':vrfname,'interface':access_vlan_name,'neighbor_ip':bfd_nbrs_dut3[0],'config':"yes",'multiplier':multiplier2,'rx_intv':bfd_rx2,'tx_intv':bfd_tx2}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step-C2: Enable BFD for BGP neighbor %s on dut1 and %s on dut3 "%(ipv6_bfd_nbrs_dut1,ipv6_bfd_nbrs_dut3))
    ###########################################################################################
    dict1={'vrf_name':vrfname,'local_asn':dut1_as,'neighbor_ip':ipv6_bfd_nbrs_dut1[0],'config':"yes"}
    dict2={'vrf_name':vrfname,'local_asn':dut3_as,'neighbor_ip':ipv6_bfd_nbrs_dut3[0],'config':"yes"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    dict1={'vrf_name':vrfname,'interface':access_vlan_name,'neighbor_ip':ipv6_bfd_nbrs_dut1[0],'config':"yes",'multiplier':multiplier61,'rx_intv':bfd_rx61,'tx_intv':bfd_tx61}
    dict2={'vrf_name':vrfname,'interface':access_vlan_name,'neighbor_ip':ipv6_bfd_nbrs_dut3[0],'config':"yes",'multiplier':multiplier62,'rx_intv':bfd_rx62,'tx_intv':bfd_tx62}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step-C3: Enable BFD for BGP neighbor %s on dut1 "%non_bfd_nbrs_dut1)
    ###########################################################################################
    dict1={'vrf_name':vrfname,'local_asn':dut1_as,'neighbor_ip':non_bfd_nbrs_dut1[0],'config':"yes"}
    dict2={'vrf_name':vrfname,'local_asn':dut3_as,'neighbor_ip':non_bfd_nbrs_dut3[0],'config':"yes"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    dict1={'vrf_name':vrfname,'local_asn':dut1_as,'neighbor_ip':non_bfd_nbrs_dut1[1],'config':"yes"}
    dict2={'vrf_name':vrfname,'local_asn':dut3_as,'neighbor_ip':non_bfd_nbrs_dut3[1],'config':"yes"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    dict1={'vrf_name':vrfname,'local_asn':dut1_as,'neighbor_ip':non_bfd_nbrs_dut1[2],'config':"yes"}
    dict2={'vrf_name':vrfname,'local_asn':dut3_as,'neighbor_ip':non_bfd_nbrs_dut3[2],'config':"yes"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step-C4: Enable BFD for BGP neighbor %s on dut3"%non_bfd_nbrs_dut3)
    ###########################################################################################
    dict1={'vrf_name':vrfname,'interface':non_bfd_intf_list[0],'neighbor_ip':non_bfd_nbrs_dut1[0],'config':"yes",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    dict2={'vrf_name':vrfname,'interface':non_bfd_intf_list[0],'neighbor_ip':non_bfd_nbrs_dut3[0],'config':"yes",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    dict1={'vrf_name':vrfname,'interface':non_bfd_intf_list[1],'neighbor_ip':non_bfd_nbrs_dut1[1],'config':"yes",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    dict2={'vrf_name':vrfname,'interface':non_bfd_intf_list[1],'neighbor_ip':non_bfd_nbrs_dut3[1],'config':"yes",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    dict1={'vrf_name':vrfname,'interface':non_bfd_intf_list[2],'neighbor_ip':non_bfd_nbrs_dut1[2],'config':"yes",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    dict2={'vrf_name':vrfname,'interface':non_bfd_intf_list[2],'neighbor_ip':non_bfd_nbrs_dut3[2],'config':"yes",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step-C5: Enable BFD for BGP neighbor %s on dut1 and %s in dut3"%(dut3_lo_ip,dut1_lo_ip))
    ###########################################################################################
    if vrfname == user_vrf_name:
        dict1={'vrf_name':vrfname,'interface':lo_name, 'local_address':dut1_lo_ip,'neighbor_ip':dut3_lo_ip,'multihop':"yes",'noshut':"yes"}
        dict2={'vrf_name':vrfname,'interface':lo_name, 'local_address':dut3_lo_ip,'neighbor_ip':dut1_lo_ip,'multihop':"yes",'noshut':"yes"}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    else:
        dict1={'vrf_name':vrfname,'local_address':dut1_lo_ip,'neighbor_ip':dut3_lo_ip,'multihop':"yes",'noshut':"yes"}
        dict2={'vrf_name':vrfname,'local_address':dut3_lo_ip,'neighbor_ip':dut1_lo_ip,'multihop':"yes",'noshut':"yes"}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step-C6: Enable BFD for BGP neighbor %s on dut1 and %s in dut3"%(dut3_lo_ipv6,dut1_lo_ipv6))
    ###########################################################################################
    if vrfname == user_vrf_name:
        dict1={'vrf_name':vrfname,'interface':lo_name, 'local_address':dut1_lo_ipv6,'neighbor_ip':dut3_lo_ipv6,'multihop':"yes",'noshut':"yes"}
        dict2={'vrf_name':vrfname,'interface':lo_name, 'local_address':dut3_lo_ipv6,'neighbor_ip':dut1_lo_ipv6,'multihop':"yes",'noshut':"yes"}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    else:
        dict1={'vrf_name':vrfname,'local_address':dut1_lo_ipv6,'neighbor_ip':dut3_lo_ipv6,'multihop':"yes",'noshut':"yes"}
        dict2={'vrf_name':vrfname,'local_address':dut3_lo_ipv6,'neighbor_ip':dut1_lo_ipv6,'multihop':"yes",'noshut':"yes"}
        parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step-C7: Verify BFD single hop session shows up peer type as configured for %s in dut1 towards dut3"%bfd_nbrs_dut1)
    ###########################################################################################
    result = retry_api(bfd.verify_bfd_peer, dut1, peer=[bfd_nbrs_dut1[0], ipv6_bfd_nbrs_dut1[0]],
                       interface=[intf_list[0], intf_list[0]], status=['up', 'up'], vrf_name=vrfname,
                       rx_interval=[[bfd_rx1, bfd_rx2], [bfd_rx61, bfd_rx62]],
                       tx_interval=[[bfd_tx1, bfd_tx2], [bfd_tx61, bfd_tx62]],
                       multiplier=[[multiplier1, multiplier2], [multiplier61, multiplier62]],
                       local_addr=["", ipv6_bfd_nbrs_dut3[0]], peer_type=["configured", "configured"],retry_count=3,delay=1)

    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" %(bfd_nbrs_dut1[0],ipv6_bfd_nbrs_dut1[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C8: Verify ebgp multihop BFD session shows up peer type as configured for %s and %s in dut1"%(dut3_lo_ip,dut3_lo_ipv6))
    ###########################################################################################
    result = retry_api(bfd.verify_bfd_peer,dut1,peer=[dut3_lo_ip,dut3_lo_ipv6],local_addr=[dut1_lo_ip,dut1_lo_ipv6],status=['up','up'],multihop=["yes","yes"],vrf_name=vrfname,retry_count=3,delay=1,peer_type=["configured","configured"])
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" %(dut3_lo_ip,dut3_lo_ipv6))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C9: Verify BFD state under BGP neighbors %s on dut1 towards dut3"%bfd_nbrs_dut1)
    ###########################################################################################
    for peer in bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, neighborip=peer, state='Established', vrf=vrfname, retry_count=3, delay=1)
        if result:
            st.log("PASSED : BGP neighbor state and BFD state is as expected for %s"%peer)
        else:
            st.log("FAILED:BGP neighbor state or BFD state is incorrect for %s"%peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step-C10: Verify BFD state under BGP neighbors %s on dut1 towards dut3"%ipv6_bfd_nbrs_dut1)
    ###########################################################################################
    for peer in ipv6_bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=peer,state='Established',vrf=vrfname,retry_count=3,delay=1)
        if result:
            st.log("PASSED: BGP neighbor state and BFD state is as expected for %s"%peer)
        else:
            st.log("FAILED:BGP neighbor state or BFD state is incorrect for %s"%peer)
            ret_val = False
    dict1 = {} ; dict3 = {}
    if vrfname == user_vrf_name:
        dict1 = bfd.verify_bfd_peer(dut1,peer=dut3_lo_ip,local_addr=dut1_lo_ip,multihop="yes",return_dict="",vrf_name=vrfname,interface=lo_name)
        dict3 = bfd.verify_bfd_peer(dut3,peer=dut1_lo_ip,local_addr=dut3_lo_ip,multihop="yes",return_dict="",vrf_name=vrfname,interface=lo_name)
    else:
        dict1 = bfd.verify_bfd_peer(dut1, peer=dut3_lo_ip, local_addr=dut1_lo_ip, multihop="yes", return_dict="",vrf_name=vrfname)
        dict3 = bfd.verify_bfd_peer(dut3, peer=dut1_lo_ip, local_addr=dut3_lo_ip, multihop="yes", return_dict="",vrf_name=vrfname)

    ###########################################################################################
    hdrMsg("Step-C13: Verify BFD mhop peer %s local id in dut1 if same remote id in dut3"%dut3_lo_ip)
    ###########################################################################################
    if dict1 and dict3:
        if dict1[0]['local_id'] == dict3[0]['remote_id']:
            st.log("PASSED : BFD mhop peer local id in dut1 is same dut3 remote id %s" %dict1[0]['local_id'])
        else:
            st.log("FAILED : BFD mhop peer local id %s in dut1 is not same dut3 remote id %s" %(dict1[0]['local_id'],dict3[0]['remote_id']))
    else:
        st.log("FAILED : BFD mhop peer local id in dut1 is not same as dut3 remote id")

    ###########################################################################################
    hdrMsg("Step-C14: Verify BFD mhop peer %s label in dut1 is same as configured string "%dut3_lo_ip)
    ###########################################################################################

    dict1 = {} ; dict3 = {}
    if vrfname == user_vrf_name:
        dict1 = bfd.verify_bfd_peer(dut1,peer=dut3_lo_ipv6,local_addr=dut1_lo_ipv6,multihop="yes",return_dict="",vrf_name=vrfname,interface=lo_name)
        dict3 = bfd.verify_bfd_peer(dut3,peer=dut1_lo_ipv6,local_addr=dut3_lo_ipv6,multihop="yes",return_dict="",vrf_name=vrfname,interface=lo_name)
    else:
        dict1 = bfd.verify_bfd_peer(dut1, peer=dut3_lo_ipv6, local_addr=dut1_lo_ipv6, multihop="yes", return_dict="",vrf_name=vrfname)
        dict3 = bfd.verify_bfd_peer(dut3, peer=dut1_lo_ipv6, local_addr=dut3_lo_ipv6, multihop="yes", return_dict="",vrf_name=vrfname)

    ###########################################################################################
    hdrMsg("Step-C15: Verify BFD mhop peer %s local id in dut1 if same remote id in dut3"%dut3_lo_ipv6)
    ###########################################################################################
    if dict1 and dict3:
        if dict1[0]['local_id'] == dict3[0]['remote_id']:
            st.log("PASSED : BFD mhop peer local id in dut1 is same dut3 remote id %s" %dict1[0]['local_id'])
        else:
            st.log("FAILED : BFD mhop peer local id %s in dut1 is not same dut3 remote id %s" %(dict1[0]['local_id'],dict3[0]['remote_id']))
    else:
        st.log("FAILED : BFD mhop peer local id in dut1 is not same as dut3 remote id")

    ###########################################################################################
    hdrMsg("Step-C16: Verify BFD mhop peer %s label in dut1 is same as configured string "%dut3_lo_ipv6)
    ###########################################################################################

    ###########################################################################################
    hdrMsg("Step-C17: shutdown the LAG port %s used for BFD access vlan in dut1"%lag_name1)
    ###########################################################################################
    port.shutdown(dut1,[lag_name1])
    ###########################################################################################
    hdrMsg("Step-C18: shutdown the one member port in lag %s used for trunk vlan"%lag_name2)
    ###########################################################################################
    port.shutdown(dut1,[D1_ports[1]])
    st.wait(1)
    ###########################################################################################
    hdrMsg("Step-C19: Verify BFD session is down for %s and %s in dut1"%(ipv6_bfd_nbrs_dut1,bfd_nbrs_dut1))
    ###########################################################################################
    for peer,intf in zip(ipv6_bfd_nbrs_dut1,intf_list):
        result = retry_api(bfd.verify_bfd_peer,dut1,vrf_name=vrfname,peer=peer,status='down',rx_interval=[[bfd_rx61,bfd_rx62]],tx_interval=[[bfd_tx61,bfd_tx62]],multiplier=[[multiplier61,multiplier62]],interface=intf,retry_count=10,delay=1)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s" %peer)
            ret_val = False
    for peer,intf in zip(bfd_nbrs_dut1,intf_list):
        result = retry_api(bfd.verify_bfd_peer,dut1,vrf_name=vrfname,peer=bfd_nbrs_dut1[0],status='down',rx_interval=[[bfd_rx1,bfd_rx2]],tx_interval=[[bfd_tx1,bfd_tx2]],multiplier=[[multiplier1,multiplier2]],interface=intf,retry_count=5,delay=1)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s" %peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step-C21: Verify BFD state under BFP neighbors %s on dut1" % bfd_nbrs_dut1)
    ###########################################################################################
    for peer in bfd_nbrs_dut1:
        result = ip_bgp.verify_bgp_neighbor(dut1,neighborip=peer,state='Established',vrf=vrfname)
        if result is False:
            st.log("PASS: BGP neighbor %s went down due to reason BFD down"%peer)
        else:
            st.log("FAILED : BGP neighbor %s did not go down with BFD down reason "%peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step-C22: Verify BFD state under BFP neighbors %s on dut1" % ipv6_bfd_nbrs_dut1)
    ###########################################################################################
    for peer in ipv6_bfd_nbrs_dut1:
        result = ip_bgp.verify_bgp_neighbor(dut1,neighborip=peer,state='Established',vrf=vrfname)
        if result is False:
            st.log("PASS: BGP neighbor %s went down due to reason BFD down"%peer)
        else:
            st.log("FAILED : BGP neighbor %s did not go down with BFD down reason "%peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step-C23: Verify other BGP neighbors are still in Established state %s"% non_bfd_nbrs_dut1)
    ###########################################################################################
    for peer in non_bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=peer,state='Established',vrf=vrfname,retry_count=9,delay=2)
        if result:
            st.log("PASSED : BGP neighbor %s  in ESTABLISHED state"% peer)
        else:
            st.log("FAILED: BGP neighbor %s not in Established state"%peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step-C24: Verify other BGP neighbors are still in Established state %s"% ipv6_non_bfd_nbrs_dut1)
    ###########################################################################################
    for peer in ipv6_non_bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=peer,state='Established',vrf=vrfname,retry_count=9,delay=2)
        if result:
            st.log("PASSED : BGP neighbor %s  in ESTABLISHED state"% peer)
        else:
            st.log("FAILED: BGP neighbor %s not in Established state"%peer)
            ret_val = False
    if not ret_val:
        basic.get_techsupport(dut_list, 'test_bfd_lag_001_port_flap')
    ###########################################################################################
    hdrMsg("Step-C27: Bringup down member port in lag %s used for trunk vlan"%lag_name2)
    ###########################################################################################
    port.noshutdown(dut1,[D1_ports[1]])
    ###########################################################################################
    hdrMsg("Step-C28: Bringup the LAG port %s used for BFD access vlan in dut1"%lag_name1)
    ###########################################################################################
    port.noshutdown(dut1,[lag_name1])

    ###########################################################################################
    hdrMsg("Step-C29: Verify BFD state under BGP neighbors %s comes up fine on dut1 under BGP" % bfd_nbrs_dut1)
    ###########################################################################################
    for peer in bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=peer,state='Established',vrf=vrfname,retry_count=9,delay=1)
        if result:
            st.log("PASSED : BGP peer %s in Established state" % peer)
        else:
            st.log("FAILED: BGP peer %s not in Established state"%peer)
            st.report_fail('bfd_fail_tcid', 'FtOpSoRoBfdFn031', 'eBGP-BFD-SHOP-&-STATIC-MHOP', 'L2-LAG-&-DUAL-STACK')
            ret_val=False

    ###########################################################################################
    hdrMsg("Step-C30: Verify BFD state under BGP neighbors %s on dut1 towards dut3"%ipv6_bfd_nbrs_dut1)
    ###########################################################################################
    for peer in ipv6_bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=peer,state='Established',vrf=vrfname,retry_count=9,delay=1)
        if result:
            st.log("BGP neighbor state and BFD state is as expected for %s"%peer)
        else:
            st.log("FAILED:BGP neighbor state or BFD state is incorrect for %s"%peer)
            st.report_fail('bfd_fail_tcid', 'FtOpSoRoBfdFn031', 'eBGP-BFD-SHOP-&-STATIC-MHOP', 'L2-LAG-&-DUAL-STACK')
            ret_val = False

    ###########################################################################################
    hdrMsg("Step-C31: Verify BFD state comes up for neighbor %s" % bfd_nbrs_dut1)
    ###########################################################################################
    result = bfd.verify_bfd_peer(dut1,peer=[bfd_nbrs_dut1[0],ipv6_bfd_nbrs_dut1[0]],interface=[intf_list[0],intf_list[0]],status=['up','up'],vrf_name=vrfname,rx_interval=[[bfd_rx1,bfd_rx2],[bfd_rx61,bfd_rx62]],tx_interval=[[bfd_tx1,bfd_tx2],[bfd_tx61,bfd_tx62]],multiplier=[[multiplier1,multiplier2],[multiplier61,multiplier62]])
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %si and %s" %(bfd_nbrs_dut1[0],ipv6_bfd_nbrs_dut1[0]))
        st.report_fail('bfd_fail_tcid', 'FtOpSoRoBfdFn031', 'eBGP-BFD-SHOP-&-STATIC-MHOP', 'L2-LAG-&-DUAL-STACK')
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C32: Removing the port-channel member %s for LAG %s in dut1 "%(D1_ports[0],lag_name1))
    ###########################################################################################
    pc.delete_portchannel_member(dut1, lag_name1, [D1_ports[0]])

    ###########################################################################################
    hdrMsg("Step-C33: Verify BFD state under BFP neighbors %s and %s on dut1" % (bfd_nbrs_dut1,ipv6_bfd_nbrs_dut1))
    ###########################################################################################
    for peer in bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=peer,bfdstatus='Up',vrf=vrfname,retry_count=2,delay=1)
        if result is False:
            st.log("PASSED : BGP neighbor %s went down as expected sinc BFD is down"%peer)
        else:
            st.log("FAILED : BGP neighbor %s did not go down after BFD went down"%peer)
            ret_val = False

    for peer in ipv6_bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=peer,bfdstatus='Up',vrf=vrfname,retry_count=2,delay=1)
        if result is False:
            st.log("PASSED : BGP neighbor %s went down as expected since BFD is down"%peer)
        else:
            st.log("FAILED : BGP neighbor %s did not go down after BFD went down"%peer)
            ret_val = False

    result = bfd.verify_bfd_peer(dut1, peer=[bfd_nbrs_dut1[0], ipv6_bfd_nbrs_dut1[0]],
                                 interface=[intf_list[0], intf_list[0]], status=['up', 'up'], vrf_name=vrfname)
    if result is True:
        st.log("FAILED : BFD session parameters mismatch for %si and %s" % (bfd_nbrs_dut1[0], ipv6_bfd_nbrs_dut1[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C34: Verify BFD state and eBGP multi-hop state is still up for neighbor %s"%dut3_lo_ip)
    ###########################################################################################
    if vrfname == user_vrf_name:
        result = bfd.verify_bfd_peer(dut1,peer=dut3_lo_ip,local_addr=dut1_lo_ip,status='up',multihop='yes',vrf_name=vrfname,interface=lo_name)
    else:
        result = bfd.verify_bfd_peer(dut1, peer=dut3_lo_ip, local_addr=dut1_lo_ip, status='up', multihop='yes', vrf_name=vrfname)
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s" %dut3_lo_ip)
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C35: Verify BFD state and eBGP multi-hop state is still up for neighbor %s"%dut3_lo_ipv6)
    ###########################################################################################
    if vrfname == user_vrf_name:
        result = bfd.verify_bfd_peer(dut1,peer=dut3_lo_ipv6,local_addr=dut1_lo_ipv6,status='up',multihop='yes',vrf_name=vrfname,interface=lo_name)
    else:
        result = bfd.verify_bfd_peer(dut1, peer=dut3_lo_ipv6, local_addr=dut1_lo_ipv6, status='up', multihop='yes', vrf_name=vrfname)
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s" %dut3_lo_ipv6)
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C36: Verify other BGP neighbors are still in Established state %s"% non_bfd_nbrs_dut1)
    ###########################################################################################
    for peer in non_bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=peer,state='Established',vrf=vrfname,retry_count=9,delay=1)
        if result:
            st.log("PASSED: BGP neighbor %s is in ESTABLISHED state as expected"% peer)
        else:
            st.log("FAILED: BGP neighbor %s not in Established state"%peer)
            ret_val = False

    if not ret_val:
        basic.get_techsupport(dut_list, 'test_bfd_lag_001_portchannel_port_remove')
    ###########################################################################################
    hdrMsg("Step-C37: Readding the port-channel member %s for LAG %s in dut1 "%(D1_ports[0],lag_name1))
    ###########################################################################################
    pc.add_portchannel_member(dut1, portchannel=lag_name1, members=[D1_ports[0]])

    ###########################################################################################
    hdrMsg("Step-C38: Verify BFD state under BGP neighbors %s comes up back on dut1 under BGP" % bfd_nbrs_dut1)
    ###########################################################################################
    for peer in bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=peer,state='Established',vrf=vrfname,retry_count=9,delay=1)
        if result:
            st.log("BGP peer %s in Established state" % peer)
        else:
            st.log("FAILED: BGP peer %s not in Established state"%peer)
            ret_val=False

    ###########################################################################################
    hdrMsg("Step-C39: Verify BFD state comes up for neighbor %s" % bfd_nbrs_dut1)
    ###########################################################################################
    for peer, intf in zip(bfd_nbrs_dut1, intf_list):
        result = utils_api.retry_api(bfd.verify_bfd_peer, dut1, peer=peer, interface=intf, status='up',vrf_name=vrfname)
        if result is False:
            st.log("FAILED : BFD session not UP for %s" % peer)
            ret_val = False

    ############################################################################################
    hdrMsg("Step-C40: Remove ports %s as untagged port on vlan %s in dut1" % (lag_name1,access_vlan))
    ############################################################################################
    vlan_api.delete_vlan_member(dut1, access_vlan, [lag_name1])

    ############################################################################################
    hdrMsg("Step-C41: Adding back the port %s as untagged port on vlan %s in dut1" % (lag_name1,access_vlan))
    ############################################################################################
    vlan_api.add_vlan_member(dut1,access_vlan,lag_name1, False)

    ###########################################################################################
    hdrMsg("Step-C42: Verify BFD state for BGP neighbors %s and %s"% (bfd_nbrs_dut1,ipv6_bfd_nbrs_dut1))
    ###########################################################################################
    for peer in bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=peer,state='Established',vrf=vrfname,retry_count=8,delay=1)
        if result:
            st.log("BGP neighbor %s is still down after polling for 8 seconds"%peer)
        else:
            st.log("FAILED : BGP neighbor %s did not come up after lag is added to the vlan"%peer)
            ret_val = False

    for peer in ipv6_bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=peer,state='Established',vrf=vrfname,retry_count=8,delay=1)
        if result:
            st.log("BGP neighbor %s is still down after polling for 8 seconds"%peer)
        else:
            st.log("FAILED : BGP neighbor %s did not come up after lag is added to the vlan"%peer)
            ret_val = False

    if convergence_test == "yes" and 'ixia' in vars['tgen_list'][0]:
        if vrfname == 'default':
            tg1.tg_traffic_control(action='clear_stats', port_handle=tg_handles)
        else:
            tg1.tg_traffic_control(action='clear_stats', port_handle=tg_handles_vrf)

    ###########################################################################################
    hdrMsg("Step-C43: Verify BFD state and eBGP multi-hop state is still up for neighbor %s"%dut3_lo_ip)
    ###########################################################################################
    if vrfname == user_vrf_name:
        result = retry_api(bfd.verify_bfd_peer,dut1,peer=dut3_lo_ip,local_addr=dut1_lo_ip,status='up',multihop='yes',vrf_name=vrfname,interface=lo_name,retry_count=6,delay=2)
    else:
        result = retry_api(bfd.verify_bfd_peer, dut1, peer=dut3_lo_ip, local_addr=dut1_lo_ip, status='up',multihop='yes', vrf_name=vrfname, retry_count=6, delay=2)
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s" %dut3_lo_ip)
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C44: Verify BFD state and eBGP multi-hop state is still up for neighbor %s"%dut3_lo_ipv6)
    ###########################################################################################
    if vrfname == user_vrf_name:
        result = retry_api(bfd.verify_bfd_peer,dut1,peer=dut3_lo_ipv6,local_addr=dut1_lo_ipv6,status='up',multihop='yes',vrf_name=vrfname,interface=lo_name,retry_count=6,delay=2)
    else:
        result = retry_api(bfd.verify_bfd_peer, dut1, peer=dut3_lo_ipv6, local_addr=dut1_lo_ipv6, status='up',multihop='yes', vrf_name=vrfname, retry_count=6, delay=2)
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s" %dut3_lo_ipv6)
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C45: Verify BFD session comes up for %s in dut1 towards dut3"%bfd_nbrs_dut1)
    ###########################################################################################
    for peer,intf in zip(bfd_nbrs_dut1,intf_list):
        result = bfd.verify_bfd_peer(dut1,peer=peer,interface=intf,status='up',vrf_name=vrfname)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s" %peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step-C46: Verify BFD state and eBGP multi-hop uptime for peer %s"%dut3_lo_ip)
    ###########################################################################################
    result = True
    if vrfname == user_vrf_name:
        dict = bfd.verify_bfd_peer(dut1,peer=dut3_lo_ip,local_addr=dut1_lo_ip,multihop="yes",return_dict="",vrf_name=vrfname,interface=lo_name)
    else:
        dict = bfd.verify_bfd_peer(dut1, peer=dut3_lo_ip, local_addr=dut1_lo_ip, multihop="yes", return_dict="",vrf_name=vrfname)
    dict1 = dict1[0] if dict else {}
    if dict1 and dict1['uptimesec'] != '':
        if dict1['uptimemin'] != '':
            if int(dict1['uptimemin']) == 0 and int(dict1['uptimesec']) < 2:
                result = False
        elif dict1['uptimemin'] == '':
            if int(dict1['uptimesec']) < 2:
                result = False
    else:
        st.log("FAILED : BFD session is down for %s in dut1" %dut3_lo_ip)
        result = False

    if result is False:
        st.log("FAILED : BFD session has flapped or down for %s in dut1" %dut3_lo_ip)
        ret_val = False
    else:
        st.log("PASSED : BFD session did not flap for %s " %dut3_lo_ip)

    ###########################################################################################
    hdrMsg("Step-C47: Verify BFD state and eBGP multi-hop uptime for peer %s"%dut3_lo_ipv6)
    ###########################################################################################
    result = True
    if vrfname == user_vrf_name:
        dict = bfd.verify_bfd_peer(dut1,peer=dut3_lo_ipv6,local_addr=dut1_lo_ipv6,multihop="yes",return_dict="",vrf_name=vrfname,interface=lo_name)
    else:
        dict = bfd.verify_bfd_peer(dut1, peer=dut3_lo_ipv6, local_addr=dut1_lo_ipv6, multihop="yes", return_dict="",vrf_name=vrfname)
    dict1 = dict[0] if dict else {}
    if dict1 and dict1['uptimesec'] != '':
        if dict1['uptimemin'] != '':
            if int(dict1['uptimemin']) == 0 and int(dict1['uptimesec']) < 2:
                result = False
        elif dict1['uptimemin'] == '':
            if int(dict1['uptimesec']) < 2:
                result = False
    else:
        st.log("FAILED : BFD session is down for %s in dut1" %dut3_lo_ip)
        result = False

    if result is False:
        st.log("FAILED : BFD session has flapped or down for %s in dut1" %dut3_lo_ipv6)
        ret_val = False
    else:
        st.log("PASSED : BFD session did not flap for %s " %dut3_lo_ipv6)

    if convergence_test == "yes":
        ###########################################################################################
        hdrMsg("Step-C25: Verify routing table to check if destination network %s installed with next best next-hop interface %s" % (tg_dest, non_bfd_intf_list[0]))
        ###########################################################################################
        if vrfname == 'default':
            result = ip_api.verify_ip_route(dut1, ip_address="%s/%s" % (tg_dest, mask), interface=non_bfd_intf_list[0], family=addr_family)
        else:
            result = ip_api.verify_ip_route(dut1, ip_address="%s/%s" % (tg_dest, mask), interface=non_bfd_intf_list[0],
                                            family=addr_family,vrf_name=user_vrf_name)
        if result:
            st.log("DUT1: Destination route %s installed with nexthop interface %s " % (tg_dest,non_bfd_intf_list[0]))
        else:
            st.log("INFO :DUT1: Destination route %s not installed with nexthop interface %s " % (tg_dest, non_bfd_intf_list[0]))
        ###########################################################################################
        hdrMsg("Step-C26:Verify routing table to check if destination network %s installed with next best nxt-hp interface %s" %(ipv6_tg_dest,non_bfd_intf_list[0]))
        ###########################################################################################
        if vrfname == 'default':
            result = ip_api.verify_ip_route(dut1, ip_address="%s/%s" % (ipv6_tg_dest, ipv6_mask), interface=non_bfd_intf_list[0], family=ipv6_addr_family)
        else:
            result = ip_api.verify_ip_route(dut1, ip_address="%s/%s" % (ipv6_tg_dest, ipv6_mask),
                                            interface=non_bfd_intf_list[0], family=ipv6_addr_family,vrf_name=user_vrf_name)
        if result:
            st.log("DUT1: Destination route %s installed with nexthop interface %s " % (ipv6_tg_dest,non_bfd_intf_list[0]))
        else:
            st.log("INFO :DUT1: Destination route %s not installed with nexthop interface %s " % (ipv6_tg_dest, non_bfd_intf_list[0]))
        ###########################################################################################
        hdrMsg("Step-C47: Measure Traffic convergence with BFD enabled by shutting dut2<---> dut3 port" )
        ###########################################################################################
        #converged_bfd = convergence_measure(flap_dut,lag_name2,version="both",dest='d3')
        if vrfname == 'default':
            converged_bfd = convergence_measure(flap_dut,D3_ports[1:3],version="both",dest='d3')
        else:
            converged_bfd = convergence_measure(flap_dut, D3_ports[1:3], version="both", dest='d3vrf')

    if converged_bfd is not False:
        if int(converged_bfd) > 1000 and int(bfd_rx) < 20 and int(bfd_tx) < 20 and int(multiplier) < 4:
            st.error("FAILED : Traffic convergence with BFD taking more time for L2 LAG case")
            ret_val = False
        else:
            st.log("PASSED : BFD Traffic convergence test passed for L2 LAG")
    else:
        st.error("FAILED : Traffic was not received by the destination STC port")
        ret_val = False

    return ret_val


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
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False


def verify_bfd_lag3(mode='ibgp_mhop_bfd',version='dual_stack'):

    bfd_nbrs_dut1 = [dut3_lagip_list[0]]; non_bfd_nbrs_dut1 = dut3_lagip_list[2:]
    bfd_nbrs_dut3 = [dut1_lagip_list[0]]; non_bfd_nbrs_dut3 = dut1_lagip_list[2:]
    addr_family = 'ipv4';mask=ip_mask;tg_dest = tg_dest_nw;

    ipv6_bfd_nbrs_dut1 = [dut3_lagipv6_list[0]]; ipv6_non_bfd_nbrs_dut1 = dut3_lagipv6_list[2:]
    ipv6_bfd_nbrs_dut3 = [dut1_lagipv6_list[0]]; ipv6_non_bfd_nbrs_dut3 = dut1_lagipv6_list[2:]
    ipv6_addr_family = 'ipv6'; ipv6_tg_dest = tg_dest_nw_v6;

    intf_list = [access_vlan_name]
    non_bfd_intf_list = trunk_vlan_name

    ############################################################################################
    hdrMsg("Step C1: Remove eBGP+ neighbors between dut1 and dut3 which is conigured as per base line config ##########")
    ############################################################################################
    utils.exec_all(True, [[bgp.config_router_bgp_mode, dut1, dut1_as, 'disable',user_vrf_name],
                          [bgp.config_router_bgp_mode, dut3, dut3_as, 'disable',user_vrf_name]])
    data.shopunconfig = True
    utils.exec_all(True, [[bgp.config_router_bgp_mode,dut1,dut1_as,'disable'], [bgp.config_router_bgp_mode,dut3,dut3_as,'disable'] ])

    ############################################################################################
    hdrMsg("Step-C3: Configure iBGP router on dut1 locals-as %s  with router-id %s"%(dut1_as,dut3_router_id))
    ############################################################################################
    dict1 = {'local_as': dut1_as, 'router_id': dut1_router_id, 'config_type_list': ['router_id']}
    dict2 = {'local_as': dut1_as, 'router_id': dut3_router_id, 'config_type_list': ['router_id']}
    parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])
    dict1 = {'neighbor': dut3_lagip_list[0], 'remote_as': dut1_as, 'config_type_list': ["neighbor"],
             'keepalive': keep_alive, 'holdtime': hold_down, 'local_as': dut1_as}
    dict2 = {'neighbor': dut1_lagip_list[0], 'remote_as': dut1_as, 'config_type_list': ["neighbor"],
             'keepalive': keep_alive, 'holdtime': hold_down, 'local_as': dut1_as}
    parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])
    ############################################################################################
    hdrMsg("Step-C4: Configure iBGP neighbors %s on dut1 and %s on dut3"%(dut3_lagip_list[0],dut1_lagip_list[0]))
    ############################################################################################
    dict1 = {"neighbor": dut3_lagip_list[0], "config": 'yes', "config_type_list": ['connect','activate'], "connect": '1',
             "addr_family": "ipv4", "local_as": dut1_as}
    dict2 = {"neighbor": dut1_lagip_list[0], "config": 'yes', "config_type_list": ['connect','activate'], "connect": '1',
             "addr_family": "ipv4", "local_as": dut1_as}
    parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])
    ############################################################################################
    hdrMsg(" Configure static route to bring up iBGP mhop neighbors in dut1 ")
    ############################################################################################
    utils.exec_all(True, [[ip_api.create_static_route,dut1,dut3_lagip_list[0],'%s/%s'%(dut3_lo_ip,lo_mask),"vtysh","ipv4"],[ip_api.create_static_route,dut3,dut1_lagip_list[0],'%s/%s'%(dut1_lo_ip,lo_mask),"vtysh","ipv4"]])
    ############################################################################################
    hdrMsg("Step-C5: Configure iBGP mhop neighbors %s on dut1 and %s on dut3" % (dut3_lo_ipv6,dut1_lo_ipv6))
    ############################################################################################
    utils.exec_all(True, [[bgp.create_bgp_neighbor,dut1,dut1_as,dut3_lo_ip,dut1_as,keep_alive,hold_down,"","ipv4"],[bgp.create_bgp_neighbor,dut3,dut1_as,dut1_lo_ip,dut1_as,keep_alive,hold_down,"","ipv4"] ])
    dict1={'neighbor':dut3_lo_ip,'local_as':dut1_as,'config':'yes','config_type_list':['update_src'],'update_src':dut1_lo_ip}
    dict2={'neighbor':dut1_lo_ip,'local_as':dut1_as,'config':'yes','config_type_list':['update_src'],'update_src':dut3_lo_ip}
    parallel.exec_parallel(True,[dut1,dut3],bgp.config_bgp,[dict1,dict2])
    ############################################################################################
    hdrMsg("Step-C5: Configure iBGP neighbors %s on dut1 and %s on dut3" % (dut3_lagipv6_list[0], dut1_lagipv6_list[0]))
    ############################################################################################
    utils.exec_all(True, [[bgp.create_bgp_neighbor,dut1,dut1_as,dut3_lagipv6_list[0],dut1_as,keep_alive,hold_down,"","ipv6"],[bgp.create_bgp_neighbor,dut3,dut1_as,dut1_lagipv6_list[0],dut1_as,keep_alive,hold_down,"","ipv6"] ])

    dict1 = {"neighbor": dut3_lagipv6_list[0], "config": 'yes', "config_type_list": ['connect','activate'], "connect": '1',
             "addr_family": "ipv6", "local_as": dut1_as}
    dict2 = {"neighbor": dut1_lagipv6_list[0], "config": 'yes', "config_type_list": ['connect','activate'], "connect": '1',
             "addr_family": "ipv6", "local_as": dut1_as}
    parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])
    ############################################################################################
    hdrMsg(" Configure static route to bring up iBGP mhop neighbors in dut3")
    ############################################################################################
    utils.exec_all(True, [[ip_api.create_static_route,dut1,dut3_lagipv6_list[0],'%s/%s'%(dut3_lo_ipv6,lo_v6mask),"vtysh","ipv6"],[ip_api.create_static_route,dut3,dut1_lagipv6_list[0],'%s/%s'%(dut1_lo_ipv6,lo_v6mask),"vtysh","ipv6"]])
    ############################################################################################
    hdrMsg("Step-C5: Configure iBGP mhop neighbors %s on dut1 and %s on dut3" % (dut3_lo_ipv6,dut1_lo_ipv6))
    ############################################################################################
    utils.exec_all(True, [[bgp.create_bgp_neighbor,dut1,dut1_as,dut3_lo_ipv6,dut1_as,keep_alive,hold_down,"","ipv6"],[bgp.create_bgp_neighbor,dut3,dut1_as,dut1_lo_ipv6,dut1_as,keep_alive,hold_down,"","ipv6"] ])
    dict1={'neighbor':dut3_lo_ipv6,'local_as':dut1_as,'config':'yes','config_type_list':['update_src'],'update_src':dut1_lo_ipv6}
    dict2={'neighbor':dut1_lo_ipv6,'local_as':dut1_as,'config':'yes','config_type_list':['update_src'],'update_src':dut3_lo_ipv6}
    parallel.exec_parallel(True,[dut1,dut3],bgp.config_bgp,[dict1,dict2])

    ret_val = True
    ###########################################################################################
    hdrMsg("Step-C6: Enable BFD for BGP neighbor %s on dut1 "%bfd_nbrs_dut1)
    ###########################################################################################
    dict1={'local_asn':dut1_as,'neighbor_ip':bfd_nbrs_dut1[0],'config':"yes"}
    dict2={'local_asn':dut1_as,'neighbor_ip':bfd_nbrs_dut3[0],'config':"yes"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step-C7: Enable BFD for BGP neighbor %s on dut3"%bfd_nbrs_dut3)
    ###########################################################################################
    dict1={'interface':access_vlan_name,'neighbor_ip':bfd_nbrs_dut1[0],'config':"yes",'multiplier':multiplier1,'rx_intv':bfd_rx1,'tx_intv':bfd_tx1}
    dict2={'interface':access_vlan_name,'neighbor_ip':bfd_nbrs_dut3[0],'config':"yes",'multiplier':multiplier2,'rx_intv':bfd_rx2,'tx_intv':bfd_tx2}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step-C9: Enable BFD for BGP neighbor %s on dut3"%ipv6_bfd_nbrs_dut3)
    ###########################################################################################
    dict1={'local_asn':dut1_as,'neighbor_ip':ipv6_bfd_nbrs_dut1[0],'config':"yes"}
    dict2={'local_asn':dut1_as,'neighbor_ip':ipv6_bfd_nbrs_dut3[0],'config':"yes"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    dict1={'interface':access_vlan_name,'neighbor_ip':ipv6_bfd_nbrs_dut1[0],'config':"yes",'multiplier':multiplier61,'rx_intv':bfd_rx61,'tx_intv':bfd_tx61}
    dict2={'interface':access_vlan_name,'neighbor_ip':ipv6_bfd_nbrs_dut3[0],'config':"yes",'multiplier':multiplier62,'rx_intv':bfd_rx62,'tx_intv':bfd_tx62}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step-C10: Verify BFD session comes up for %s in dut1 towards dut3"%bfd_nbrs_dut1)
    ###########################################################################################
    result = retry_api(bfd.verify_bfd_peer,dut1,peer=[bfd_nbrs_dut1[0],ipv6_bfd_nbrs_dut1[0]],interface=[intf_list[0],intf_list[0]],status=['up','up'],rx_interval=[[bfd_rx1,bfd_rx2],[bfd_rx61,bfd_rx62]],tx_interval=[[bfd_tx1,bfd_tx2],[bfd_tx61,bfd_tx62]],multiplier=[[multiplier1,multiplier2],[multiplier61,multiplier62]],local_addr=["",ipv6_bfd_nbrs_dut3[0]],retry_count=2,delay=1)

    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" %(bfd_nbrs_dut1[0],ipv6_bfd_nbrs_dut1[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C12: Verify BFD state under BGP neighbors %s on dut1 towards dut3"%bfd_nbrs_dut1)
    ###########################################################################################
    for peer in bfd_nbrs_dut1:
        result =ip_bgp.verify_bgp_neighbor(dut1,neighborip=peer,state='Established')
        if result:
            st.log("BGP neighbor state and BFD state is as expected for %s"%peer)
        else:
            st.log("FAILED:BGP neighbor state or BFD state is incorrect for %s"%peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step-C13: Verify BFD state under BGP neighbors %s on dut1 towards dut3"%ipv6_bfd_nbrs_dut1)
    ###########################################################################################
    for peer in ipv6_bfd_nbrs_dut1:
        result =ip_bgp.verify_bgp_neighbor(dut1,neighborip=peer,state='Established')
        if result:
            st.log("BGP neighbor state and BFD state is as expected for %s"%peer)
        else:
            st.log("FAILED:BGP neighbor state or BFD state is incorrect for %s"%peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step-C14: Verify routing table to check if destination network %s installed with next-hop %s"%(tg_dest,intf_list[0]) )
    ###########################################################################################
    result = ip_api.verify_ip_route(dut1,ip_address="%s/%s"%(dut3_lo_ip,mask),interface=intf_list[0], family=addr_family)
    if result is False:
        st.log("PASS: DUT1 Destination route %s not installed with nexthop interface %s "%(dut3_lo_ip,intf_list[0]))
    else:
        st.log("FAIL: DUT1 Destination route %s installed with nexthop interface %s " % (dut3_lo_ip, intf_list[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C15: Verify routing table to check if destination network %s installed with next-hop %s"%(tg_dest,intf_list[0]) )
    ###########################################################################################
    result = ip_api.verify_ip_route(dut1,ip_address="%s/%s"%(dut3_lo_ipv6,mask),interface=intf_list[0], family=addr_family)
    if result is False:
        st.log("PASS: DUT1 Destination route %s not installed with nexthop interface %s "%(dut3_lo_ipv6,intf_list[0]))
    else:
        st.log("FAIL: DUT1 Destination route %s installed with nexthop interface %s " % (dut3_lo_ipv6, intf_list[0]))
        ret_val = False
    basic.add_user_log_in_frr(dut1, "bfd.log")
    basic.debug_bfdconfig_using_frrlog(dut=dut3,config="yes",log_file_name="bfd.log")

    ###########################################################################################
    hdrMsg("Step-C16: shutdown the interface %s used for BFD access vlan in dut1 and verify the BFD debug messages"%lag_name1)
    ###########################################################################################
    port.shutdown(dut1,[lag_name1])
    st.wait(1)
    output = basic.return_user_log_from_frr(dut3,"bfd.log")
    bfd_v4_arlo_log = "BFD: state-change: [mhop:no peer:%s interface:%s] up -> down reason:control-expired"%(bfd_nbrs_dut3[0],intf_list[0])
    bfd_v6_arlo_log = "BFD: state-change: [mhop:no peer:%s local:%s interface:%s] up -> down reason:control-expired"%(ipv6_bfd_nbrs_dut3[0],ipv6_bfd_nbrs_dut1[0],intf_list[0])
    bfd_v4_buzznik_log = "BFD: state-change: [mhop:no peer:%s local:0.0.0.0 vrf:default ifname:%s] up -> down reason:control-expired"%(bfd_nbrs_dut3[0],intf_list[0])
    bfd_v6_buzznik_log = "BFD: state-change: [mhop:no peer:%s local:%s vrf:default ifname:%s] up -> down reason:control-expired"%(ipv6_bfd_nbrs_dut3[0],ipv6_bfd_nbrs_dut1[0],intf_list[0])

    bfd_v4_buzznik_log_1 = "up -> down reason:control-expired"
    bfd_v6_buzznik_log_1 = "up -> down reason:control-expired"

    if bfd_v4_arlo_log not in output and bfd_v4_buzznik_log not in output and bfd_v4_buzznik_log_1 not in output:
        st.log("FAILED : dut 3 BFD log not generated for Single hop BFD IPv4 session %s"%bfd_nbrs_dut1[0])
        ret_val = False
    elif bfd_v6_arlo_log not in output and bfd_v6_buzznik_log not in output and bfd_v6_buzznik_log_1 not in output:
        st.log("FAILED : dut 3 BFD log not generated for Single hop BFD IPv6 session %s"%ipv6_bfd_nbrs_dut1[0])
        ret_val = False
    else:
        st.log("PASSED : dut 3 BFD log got generated for Single hop BFD IPv4 session %s and single hop IPv6 session %s"%(bfd_nbrs_dut1[0],ipv6_bfd_nbrs_dut1[0]))

    ###########################################################################################
    hdrMsg("Step-C17: Verify BFD session is down for %s in dut1 towards dut3"%ipv6_bfd_nbrs_dut1)
    ###########################################################################################
    for peer,intf in zip(ipv6_bfd_nbrs_dut1,intf_list):
        result = bfd.verify_bfd_peer(dut1,peer=peer,interface=intf,status='down',rx_interval=[[bfd_rx61,bfd_rx62]],tx_interval=[[bfd_tx61,bfd_tx62]],multiplier=[[multiplier61,multiplier62]])
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s" %peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step-C18: Verify BFD session is down for %s in dut1 towards dut3"%bfd_nbrs_dut1)
    ###########################################################################################
    for peer,intf in zip(bfd_nbrs_dut1,intf_list):
        result = bfd.verify_bfd_peer(dut1,peer=peer,interface=intf,status='down',rx_interval=[[bfd_rx1,bfd_rx2]],tx_interval=[[bfd_tx1,bfd_tx2]],multiplier=[[multiplier1,multiplier2]])
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s" %peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step-C20: Verify BFD state under BFP neighbors %s on dut1" % bfd_nbrs_dut1)
    ###########################################################################################
    for peer in bfd_nbrs_dut1:
        result = ip_bgp.verify_bgp_neighbor(dut1,neighborip=peer,state='Established')
        if result is False:
            st.log("PASS: BGP neighbor %s went down as expected sinc BFD is down"%peer)
        else:
            st.log("FAILED : BGP neighbor %s did not go down after BFD went down"%peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step-C21: Verify BFD state under BFP neighbors %s on dut1" % ipv6_bfd_nbrs_dut1)
    ###########################################################################################
    for peer in ipv6_bfd_nbrs_dut1:
        result = ip_bgp.verify_bgp_neighbor(dut1,neighborip=peer,state='Established')
        if result is False:
            st.log("PASS: BGP neighbor %s went down as expected sinc BFD is down"%peer)
        else:
            st.log("FAILED : BGP neighbor %s did not go down after BFD went down"%peer)
            ret_val = False

    ###########################################################################################
    hdrMsg("Step-C23: Bringup the interface %s used for BFD access vlan in dut1"%lag_name1)
    ###########################################################################################
    port.noshutdown(dut1,[lag_name1])
    basic.debug_bfdconfig_using_frrlog(dut=dut3,config="no",log_file_name="bfd.log")
    basic.remove_user_log_in_frr(dut3,"bfd.log")
    ###########################################################################################
    hdrMsg("Step-C24: Verify BFD state under BGP neighbors %s comes up fine on dut1 under BGP" % bfd_nbrs_dut1)
    ###########################################################################################
    for peer in bfd_nbrs_dut1:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=peer,state='Established',retry_count=9,delay=1)
        if result:
            st.log("BGP peer %s in Established state" % peer)
        else:
            st.log("FAILED: BGP peer %s not in Established state"%peer)
            ret_val=False

    ###########################################################################################
    hdrMsg("Step-C25: Verify BFD state comes up for neighbor %s" % bfd_nbrs_dut1)
    ###########################################################################################
    result = bfd.verify_bfd_peer(dut1,peer=[bfd_nbrs_dut1[0],ipv6_bfd_nbrs_dut1[0]],interface=[intf_list[0],intf_list[0]],status=['up','up'],rx_interval=[[bfd_rx1,bfd_rx2],[bfd_rx61,bfd_rx62]],tx_interval=[[bfd_tx1,bfd_tx2],[bfd_tx61,bfd_tx62]],multiplier=[[multiplier1,multiplier2],[multiplier61,multiplier62]])
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" %(bfd_nbrs_dut1[0],ipv6_bfd_nbrs_dut1[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C27: Verify BFD state under BGP neighbors %s comes up back on dut1 under BGP" % ipv6_bfd_nbrs_dut1)
    ###########################################################################################
    for peer in ipv6_bfd_nbrs_dut1:
        result = ip_bgp.verify_bgp_neighbor(dut1,neighborip=peer,state='Established')
        if result:
            st.log("BGP peer %s in Established state" % peer)
        else:
            st.log("FAILED: BGP peer %s not in Established state"%peer)
            ret_val=False
    if not ret_val:
        basic.get_techsupport(filename='FtOpSoRoBfdFn022')

    ###########################################################################################
    hdrMsg("Step-C28: Remove BFD for single hop eBGP neighbor %s on dut1 & %s on dut3"%(bfd_nbrs_dut1,bfd_nbrs_dut3))
    ###########################################################################################
    dict1={'local_asn':dut1_as,'neighbor_ip':bfd_nbrs_dut1[0],'config':"no"}
    dict2={'local_asn':dut1_as,'neighbor_ip':bfd_nbrs_dut3[0],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step-C29: Remove BFD for single hop eBGP neighbor %s on dut1 & %s in dut3"%(ipv6_bfd_nbrs_dut1,ipv6_bfd_nbrs_dut3))
    ###########################################################################################
    dict1={'local_asn':dut1_as,'neighbor_ip':ipv6_bfd_nbrs_dut1[0],'config':"no"}
    dict2={'local_asn':dut1_as,'neighbor_ip':ipv6_bfd_nbrs_dut3[0],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step-C30: Remove BFD timer for BGP ipv4 neighbor %s on dut1 and %s in dut3 "%(bfd_nbrs_dut1,bfd_nbrs_dut3))
    ###########################################################################################
    dict1={'interface':access_vlan_name,'neighbor_ip':bfd_nbrs_dut1[0],'config':"no"}
    dict2={'interface':access_vlan_name,'neighbor_ip':bfd_nbrs_dut3[0],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step-C31: Remove BFD timers for BGP ipv6 neighbor %s on dut1 & %s in dut3 "%(ipv6_bfd_nbrs_dut1,ipv6_bfd_nbrs_dut3))
    ###########################################################################################
    dict1={'interface':access_vlan_name,'neighbor_ip':ipv6_bfd_nbrs_dut1[0],'config':"no"}
    dict2={'interface':access_vlan_name,'neighbor_ip':ipv6_bfd_nbrs_dut3[0],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])

    ############################################################################################
    hdrMsg("Step-C32: Remove iBGP mhop neighbors %s on dut1 and %s on dut3" % (dut3_lo_ipv6,dut1_lo_ipv6))
    ############################################################################################
    utils.exec_all(True, [[bgp.delete_bgp_neighbor,dut1,dut1_as,dut3_lo_ip,dut1_as],[bgp.delete_bgp_neighbor,dut3,dut1_as,dut1_lo_ip,dut1_as]])

    ############################################################################################
    hdrMsg("Step-C33: Remove iBGP mhop neighbors %s on dut1 and %s on dut3" % (dut3_lo_ipv6,dut1_lo_ipv6))
    ############################################################################################
    utils.exec_all(True, [[bgp.delete_bgp_neighbor,dut1,dut1_as,dut3_lo_ipv6,dut1_as],[bgp.delete_bgp_neighbor,dut3,dut1_as,dut1_lo_ipv6,dut1_as]])

    ############################################################################################
    hdrMsg("Step-C34: Delete static route in dut1 and dut3")
    ############################################################################################
    utils.exec_all(True, [[ip_api.delete_static_route,dut1,dut3_lagip_list[0],'%s/%s'%(dut3_lo_ip,lo_mask),"ipv4","vtysh"],[ip_api.delete_static_route,dut3,dut1_lagip_list[0],'%s/%s'%(dut1_lo_ip,lo_mask),"ipv4","vtysh"]])
    utils.exec_all(True, [[ip_api.delete_static_route,dut1,dut3_lagipv6_list[0],'%s/%s'%(dut3_lo_ipv6,lo_mask),"ipv6","vtysh"],[ip_api.delete_static_route,dut3,dut1_lagipv6_list[0],'%s/%s'%(dut1_lo_ipv6,lo_mask),"ipv6","vtysh"]])

    return ret_val


def verify_bfd_lag2(vrfname='default'):
    ############################################################################################
    hdrMsg(" Assigning local vars based on the vrf config either default or non default vrf ")
    ############################################################################################
    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, D1_port, D3_port, \
    lo_name, peer_v4, peer_v6, lag_name1, lag_name2, lag_name3, lag_name4, \
    dut1_lo_ip, dut3_lo_ip, dut4_lo_ip, dut1_lo_ipv6, dut3_lo_ipv6, dut4_lo_ipv6 = return_vars(vrfname)

    bfd_nbrs_dut1 = [dut3_lagip_list[0]]
    non_bfd_nbrs_dut1 = dut3_lagip_list[2:]
    bfd_nbrs_dut3 = [dut1_lagip_list[0]]
    non_bfd_nbrs_dut3 = dut1_lagip_list[2:]
    addr_family = 'ipv4'
    mask = ip_mask
    tg_dest = tg_dest_nw
    lodest = dut3_lo_ip
    lomask = lo_mask

    ipv6_bfd_nbrs_dut1 = [dut3_lagipv6_list[0]]
    ipv6_non_bfd_nbrs_dut1 = dut3_lagipv6_list[2:]
    ipv6_bfd_nbrs_dut3 = [dut1_lagipv6_list[0]]
    ipv6_non_bfd_nbrs_dut3 = dut1_lagipv6_list[2:]
    ipv6_addr_family = 'ipv6'
    ipv6_tg_dest = tg_dest_nw_v6
    ipv6_lodest = dut3_lo_ipv6
    ipv6_lomask = lo_v6mask
    intf_list = [access_vlan_name]
    non_bfd_intf_list = trunk_vlan_name

    # flap_intf = D2_ports[3]
    if vrfname == 'default':
        flap_intf = flap_ports
    else:
        flap_intf = flap_ports_vrf

    ret_val = True
    ###########################################################################################
    hdrMsg("Step-C3: Enable static single hop BFD IPv4 neighbor %s on dut1 and %s on dut3"%(bfd_nbrs_dut1[0],bfd_nbrs_dut3[0]))
    ###########################################################################################
    dict1 = {'vrf_name': vrfname, 'interface': intf_list[0], 'local_address': bfd_nbrs_dut3[0], 'neighbor_ip': bfd_nbrs_dut1[0],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes"}
    dict2 = {'vrf_name': vrfname, 'interface': intf_list[0], 'local_address': bfd_nbrs_dut1[0], 'neighbor_ip': bfd_nbrs_dut3[0],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes"}

    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg("Step-C4: Enable static single hop BFD IPv4 neighbor %s on dut1 and %s on dut3 using interface option"%(non_bfd_nbrs_dut1[0], non_bfd_nbrs_dut3[0]))
    ###########################################################################################
    dict1 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[0], 'neighbor_ip': non_bfd_nbrs_dut1[0],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes",
             'local_address': non_bfd_nbrs_dut3[0]}
    dict2 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[0], 'neighbor_ip': non_bfd_nbrs_dut3[0],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes",
             'local_address': non_bfd_nbrs_dut1[0]}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg("Step-C5: Enable static single hop BFD IPv6 neighbor %s on dut1 and %s on dut3" %(ipv6_bfd_nbrs_dut1[0], ipv6_bfd_nbrs_dut3[0]))
    ###########################################################################################
    dict1 = {'vrf_name': vrfname,  'interface': intf_list[0], 'local_address': ipv6_bfd_nbrs_dut3[0], 'neighbor_ip': ipv6_bfd_nbrs_dut1[0],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes"}
    dict2 = {'vrf_name': vrfname,  'interface': intf_list[0], 'local_address': ipv6_bfd_nbrs_dut1[0], 'neighbor_ip': ipv6_bfd_nbrs_dut3[0],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes"}

    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg("Step-C6: Enable static single hop BFD IPv6 neighbor %s on dut1 and %s on dut3" %(ipv6_non_bfd_nbrs_dut1[0], ipv6_non_bfd_nbrs_dut3[0]))
    ###########################################################################################
    dict1 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[0], 'neighbor_ip': ipv6_non_bfd_nbrs_dut1[0],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes",
             'local_address': ipv6_non_bfd_nbrs_dut3[0]}
    dict2 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[0], 'neighbor_ip': ipv6_non_bfd_nbrs_dut3[0],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes",
             'local_address': ipv6_non_bfd_nbrs_dut1[0]}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg("Step-C7: Enable static single hop BFD IPv4 neighbor %s with echo mode on dut1 towards dut3" %
           non_bfd_nbrs_dut1[1])
    ###########################################################################################
    dict1 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[1], 'local_address': non_bfd_nbrs_dut3[1], 'neighbor_ip': non_bfd_nbrs_dut1[1],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes", 'echo_mode_enable': "yes",
             'echo_intv': bfd_echo_tx}
    dict2 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[1], 'local_address': non_bfd_nbrs_dut1[1], 'neighbor_ip': non_bfd_nbrs_dut3[1],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes", 'echo_mode_enable': "yes",
             'echo_intv': bfd_echo_tx}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    ###########################################################################################
    hdrMsg("Step-C8: Enable static single hop BFD IPv4 neighbor %s with echo mode on dut3" % non_bfd_nbrs_dut1[2])
    ###########################################################################################
    dict1 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[2], 'neighbor_ip': non_bfd_nbrs_dut1[2],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes",
             'local_address': non_bfd_nbrs_dut3[2], 'echo_mode_enable': "yes", 'echo_intv': bfd_echo_tx}
    dict2 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[2], 'neighbor_ip': non_bfd_nbrs_dut3[2],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes",
             'local_address': non_bfd_nbrs_dut1[2], 'echo_mode_enable': "yes", 'echo_intv': bfd_echo_tx}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg(
        "Step-C9: Enable static single hop BFD IPv6 neighbor %s on dut1 with echo mode towards dut3" % ipv6_non_bfd_nbrs_dut1[1])
    ###########################################################################################
    dict1 = {'vrf_name': vrfname,'interface': trunk_vlan_name[1], 'local_address': ipv6_non_bfd_nbrs_dut3[1], 'neighbor_ip': ipv6_non_bfd_nbrs_dut1[1],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes", 'echo_mode_enable': "yes",
             'echo_intv': bfd_echo_tx}
    dict2 = {'vrf_name': vrfname,'interface': trunk_vlan_name[1], 'local_address': ipv6_non_bfd_nbrs_dut1[1], 'neighbor_ip': ipv6_non_bfd_nbrs_dut3[1],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes", 'echo_mode_enable': "yes",
             'echo_intv': bfd_echo_tx}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg("Step-C10: Enable static single hop BFD IPv6 neighbor %s with echo mode on dut3" % ipv6_non_bfd_nbrs_dut1[2])
    ###########################################################################################
    dict1 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[2], 'neighbor_ip': ipv6_non_bfd_nbrs_dut1[2],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes",
             'local_address': ipv6_non_bfd_nbrs_dut3[2], 'echo_mode_enable': "yes", 'echo_intv': bfd_echo_tx}
    dict2 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[2], 'neighbor_ip': ipv6_non_bfd_nbrs_dut3[2],
             'multiplier': multiplier, 'rx_intv': bfd_rx, 'tx_intv': bfd_tx, 'noshut': "yes",
             'local_address': ipv6_non_bfd_nbrs_dut1[2], 'echo_mode_enable': "yes", 'echo_intv': bfd_echo_tx}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg(
        "Step-C11: Enable/disable mulitple times static single hop BFD IPv4 neighbor %s with echo mode on dut1 towards dut3" %
        non_bfd_nbrs_dut1[1])
    ###########################################################################################
    for cnt in range(1, 2):
        ##########################################################################################
        hdrMsg("Step-CS11: Enable/disable static single hop BFD IPv4 neighbor in DUT 1 for count %s" % cnt)
        ##########################################################################################
        bfd.configure_bfd(dut1, vrf_name=vrfname,  interface=trunk_vlan_name[1], local_address=non_bfd_nbrs_dut3[1], neighbor_ip=non_bfd_nbrs_dut1[1],
                          echo_mode_disable="yes")
        bfd.configure_bfd(dut1, vrf_name=vrfname, interface=trunk_vlan_name[1], local_address=non_bfd_nbrs_dut3[1],
                          neighbor_ip=non_bfd_nbrs_dut1[1],
                          echo_mode_enable="yes")
        bfd.configure_bfd(dut1, vrf_name=vrfname, interface=trunk_vlan_name[2], neighbor_ip=non_bfd_nbrs_dut1[2],
                          local_address=non_bfd_nbrs_dut3[2], echo_mode_disable="yes")

        bfd.configure_bfd(dut1, vrf_name=vrfname, interface=trunk_vlan_name[2], neighbor_ip=non_bfd_nbrs_dut1[2],
                          local_address=non_bfd_nbrs_dut3[2], echo_mode_enable="yes")

    ###########################################################################################
    hdrMsg(
        "Step-C12: Enable/disable mulitple time static single hop BFD IPv6 neighbor %s on dut1 with echo mode towards dut3" %
        ipv6_non_bfd_nbrs_dut3[1])
    ###########################################################################################
    for cnt in range(1, 2):
        ##########################################################################################
        hdrMsg("Step-CS12: Enable/disable static single hop BFD IPv6 neighbor in DUT 1 for count %s" % cnt)
        ##########################################################################################
        bfd.configure_bfd(dut1, vrf_name=vrfname, interface=trunk_vlan_name[1], local_address=ipv6_non_bfd_nbrs_dut3[1],
                          neighbor_ip=ipv6_non_bfd_nbrs_dut1[1], echo_mode_disable="yes")
        bfd.configure_bfd(dut1, vrf_name=vrfname, interface=trunk_vlan_name[1], local_address=ipv6_non_bfd_nbrs_dut3[1],
                          neighbor_ip=ipv6_non_bfd_nbrs_dut1[1], echo_mode_enable="yes")
        bfd_nbrs_dut1_interface = intf_list[0]

        bfd.configure_bfd(dut1, vrf_name=vrfname, interface=trunk_vlan_name[2], neighbor_ip=ipv6_non_bfd_nbrs_dut1[2],
                          local_address=ipv6_non_bfd_nbrs_dut3[2], echo_mode_disable="yes")

        bfd.configure_bfd(dut1, vrf_name=vrfname, interface=trunk_vlan_name[2], neighbor_ip=ipv6_non_bfd_nbrs_dut1[2],
                          local_address=ipv6_non_bfd_nbrs_dut3[2], echo_mode_enable="yes")

    ###########################################################################################
    hdrMsg("Step-C13: Verify static singlehop BFD session show up peer type as configured for peer %s and %s" % (
    bfd_nbrs_dut1[0], non_bfd_nbrs_dut1[0]))
    ###########################################################################################
    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=vrfname, peer=[bfd_nbrs_dut1[0], non_bfd_nbrs_dut1[0]],
                       status=['up', 'up'], local_addr=[bfd_nbrs_dut3[0], non_bfd_nbrs_dut3[0]],
                       rx_interval=[[bfd_rx, bfd_rx], [bfd_rx, bfd_rx]],
                       tx_interval=[[bfd_tx, bfd_tx], [bfd_tx, bfd_tx]],
                       multiplier=[[multiplier, multiplier], [multiplier, multiplier]],
                       interface=[intf_list[0], trunk_vlan_name[0]], retry_count=4, delay=2,
                       peer_type=["configured", "configured"])
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s using local-address option" % bfd_nbrs_dut3[0])
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C14:Verify static singlehop BFD session show up peer type as configured for peer %s and %s" % (
    ipv6_bfd_nbrs_dut1[0], ipv6_non_bfd_nbrs_dut1[0]))
    ###########################################################################################
    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=vrfname,
                       peer=[ipv6_bfd_nbrs_dut1[0], ipv6_non_bfd_nbrs_dut1[0]], status=['up', 'up'],
                       local_addr=[ipv6_bfd_nbrs_dut3[0], ipv6_non_bfd_nbrs_dut3[0]],
                       rx_interval=[[bfd_rx, bfd_rx], [bfd_rx, bfd_rx]],
                       tx_interval=[[bfd_tx, bfd_tx], [bfd_tx, bfd_tx]],
                       multiplier=[[multiplier, multiplier], [multiplier, multiplier]],
                       interface=[intf_list[0], trunk_vlan_name[0]], retry_count=4, delay=2,
                       peer_type=["configured", "configured"])
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s using local-address option" % bfd_nbrs_dut3[0])
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C15: Verify ebgp single-hop BFD session comes up with echo mode for peer %s and %s" % (
    non_bfd_nbrs_dut1[0], ipv6_non_bfd_nbrs_dut1[0]))
    ###########################################################################################
    result1 = bfd.verify_bfd_peer(dut1, vrf_name=vrfname, peer=[non_bfd_nbrs_dut1[0], ipv6_non_bfd_nbrs_dut1[0]],
                                 status=['up', 'up'], local_addr=[non_bfd_nbrs_dut3[0], ipv6_non_bfd_nbrs_dut3[0]],
                                 rx_interval=[[bfd_rx, bfd_rx], [bfd_rx, bfd_rx]],
                                 tx_interval=[[bfd_tx, bfd_tx], [bfd_tx, bfd_tx]],
                                 multiplier=[[multiplier, multiplier], [multiplier, multiplier]],
                                 echo_tx_interval=[["0", "50"], ["0", "50"]],
                                 interface=[trunk_vlan_name[0], trunk_vlan_name[0]])
    result2 = bfd.verify_bfd_peer(dut1, vrf_name=vrfname, peer=[non_bfd_nbrs_dut1[0], ipv6_non_bfd_nbrs_dut1[0]],
                                 status=['up', 'up'], local_addr=[non_bfd_nbrs_dut3[0], ipv6_non_bfd_nbrs_dut3[0]],
                                 rx_interval=[[bfd_rx, bfd_rx], [bfd_rx, bfd_rx]],
                                 tx_interval=[[bfd_tx, bfd_tx], [bfd_tx, bfd_tx]],
                                 multiplier=[[multiplier, multiplier], [multiplier, multiplier]],
                                 echo_tx_interval=[["50", "50"], ["50", "50"]],
                                 interface=[trunk_vlan_name[0], trunk_vlan_name[0]])
    result = result1 or result2
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s using local-address option" % bfd_nbrs_dut3[0])
        ret_val = False
    result = bfd.verify_bfd_counters(dut1, vrf_name=vrfname, cntrlpktout="1", cntrlpktin="1",
                                     peeraddress=non_bfd_nbrs_dut1[0])
    if result is False:
        st.log("FAILED : BFD IPv4 echo mode control pkt counter for peer address %s" % non_bfd_nbrs_dut1[0])
        ret_val = False

    result = bfd.verify_bfd_counters(dut1, vrf_name=vrfname, cntrlpktout="1", cntrlpktin="1",
                                     peeraddress=ipv6_non_bfd_nbrs_dut1[0])
    if result is False:
        st.log("FAILED : BFD IPv4 echo mode control pkt counter for peer address %s" % ipv6_non_bfd_nbrs_dut1[0])
        ret_val = False
    ###########################################################################################
    hdrMsg("Step-C16: Verify ebgp single-hop BFD session comes up with echo mode for peer %s and %s" % (
    non_bfd_nbrs_dut1[1], ipv6_non_bfd_nbrs_dut1[1]))
    ###########################################################################################
    result = bfd.verify_bfd_peer(dut1, vrf_name=vrfname, peer=[non_bfd_nbrs_dut1[1], ipv6_non_bfd_nbrs_dut1[1]],
                                 status=['up', 'up'], local_addr=[non_bfd_nbrs_dut3[1], ipv6_non_bfd_nbrs_dut3[1]],
                                 rx_interval=[[bfd_rx, bfd_rx], [bfd_rx, bfd_rx]],
                                 tx_interval=[[bfd_tx, bfd_tx], [bfd_tx, bfd_tx]],
                                 multiplier=[[multiplier, multiplier], [multiplier, multiplier]],
                                 echo_tx_interval=[[bfd_echo_tx, bfd_echo_tx], [bfd_echo_tx, bfd_echo_tx]])
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" % (
        non_bfd_nbrs_dut1[1], ipv6_non_bfd_nbrs_dut1[1]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C17: Trigger link failure on L2 switch between dut2 and dut3 for vlan %s" % flap_intf[0])
    ###########################################################################################
    port.shutdown(flap_dut, [flap_intf[0]])

    ###########################################################################################
    hdrMsg("Step-C18: Verify BFD state and eBGP single-hop state is still up for neighbor %s" % dut4_lo_ip)
    ###########################################################################################
    x = 1
    y = 1
    while x <= 3:
        dict1 = bfd.verify_bfd_peer(dut1, vrf_name=vrfname, peer=bfd_nbrs_dut1[0], local_addr=bfd_nbrs_dut3[0],
                                    interface=intf_list[0], return_dict="")
        if dict1 and dict1[0]['diagnostics'] in ["control detection time expired", "neighbor signaled session down", "DETECTION_TIMEOUT"]:
            st.log(
                "PASSED : BFD session diagnostics parameter match for %s using local-address option" % bfd_nbrs_dut1[0])
            break
        x = x + 1

    while y <= 3:
        dict2 = bfd.verify_bfd_peer(dut1, vrf_name=vrfname, peer=ipv6_bfd_nbrs_dut1[0], interface=intf_list[0],
                                    local_addr=ipv6_bfd_nbrs_dut3[0], return_dict="")
        if dict2 and dict2[0]['diagnostics'] in ["control detection time expired", "neighbor signaled session down", "DETECTION_TIMEOUT"]:
            st.log("PASSED : BFD session diagnostics parameter match for %s using local-address option" %
                   ipv6_bfd_nbrs_dut1[0])
            break
        y = y + 1

    if x == 4:
        st.log(
            "FAILED : BFD session diagnostics parameter mismatch for %s using local-address option" % bfd_nbrs_dut1[0])
        ret_val = False
    elif y == 4:
        st.log("FAILED : BFD session diagnostics parameter mismatch for %s using local-address option" %
               ipv6_bfd_nbrs_dut1[0])
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C19: Re-enable port on L2 switch between dut2 and dut3 for vlan %s" % flap_intf[0])
    ###########################################################################################
    port.noshutdown(flap_dut, [flap_intf[0]])

    ###########################################################################################
    hdrMsg("Step-C20: shutdown trunk port on L2 switch between dut2 and dut3 for vlan %s" % flap_intf[1:3])
    ###########################################################################################
    port.shutdown(flap_dut, flap_intf[1:3])

    x = 1
    y = 1
    while x <= 3:
        dict1 = bfd.verify_bfd_peer(dut1, vrf_name=vrfname, peer=non_bfd_nbrs_dut1[1], local_addr=non_bfd_nbrs_dut3[1],
                                    interface=trunk_vlan_name[1], return_dict="")
        if dict1 and dict1[0]['diagnostics'] in ["control detection time expired", "neighbor signaled session down", "echo function failed", "DETECTION_TIMEOUT", "ECHO_FAILED", "NEIGHBOR_SIGNALED_DOWN"]:
            st.log("PASSED : BFD session diagnostics parameter match for %s using local-address option" %
                   non_bfd_nbrs_dut1[1])
            break
        x = x + 1

    while y <= 3:
        dict2 = bfd.verify_bfd_peer(dut1, vrf_name=vrfname, peer=ipv6_non_bfd_nbrs_dut1[1], interface=trunk_vlan_name[1],
                                    local_addr=ipv6_non_bfd_nbrs_dut3[1], return_dict="")
        if dict2 and dict2[0]['diagnostics'] in ["control detection time expired", "neighbor signaled session down", "echo function failed", "DETECTION_TIMEOUT", "ECHO_FAILED", "NEIGHBOR_SIGNALED_DOWN"]:
            st.log("PASSED : BFD session diagnostics parameter match for %s using local-address option" %
                   ipv6_non_bfd_nbrs_dut1[1])
            break
        y = y + 1

    if x == 4:
        st.log(
            "FAILED : BFD session diagnostics parameter mismatch for %s using local-address option" % bfd_nbrs_dut1[0])
        ret_val = False
    elif y == 4:
        st.log("FAILED : BFD session diagnostics parameter mismatch for %s using local-address option" %
               ipv6_bfd_nbrs_dut1[0])
        ret_val = False

    ###########################################################################################
    hdrMsg("Step-C21: Bringup trunk port on L2 switch between dut2 and dut3 for vlan %s" % flap_intf[1:3])
    ###########################################################################################
    port.noshutdown(flap_dut, flap_intf[1:3])

    ###########################################################################################
    hdrMsg("Step-C22: Shuting down the single hop static BFD session in DUT 3 for peer %s" % bfd_nbrs_dut1[0])
    ###########################################################################################
    bfd.configure_bfd(dut3, vrf_name=vrfname, interface=intf_list[0], local_address=bfd_nbrs_dut1[0], neighbor_ip=bfd_nbrs_dut3[0],
                      shutdown="yes")
    bfd.configure_bfd(dut3, vrf_name=vrfname, interface=intf_list[0], local_address=ipv6_bfd_nbrs_dut1[0], neighbor_ip=ipv6_bfd_nbrs_dut3[0],
                      shutdown="yes")

    ###########################################################################################
    hdrMsg(
        "Step-C23: Verify BFD peer dignostic info in DUT 1 for neighbor %s after partner shutting down the bfd session" %
        bfd_nbrs_dut1[0])
    ###########################################################################################
    x = 1
    y = 1
    while x <= 3:
        dict1 = bfd.verify_bfd_peer(dut1, vrf_name=vrfname, peer=bfd_nbrs_dut1[0], local_addr=bfd_nbrs_dut3[0],
                                    interface=intf_list[0], return_dict="")
        if dict1 and dict1[0]['diagnostics'] in ["control detection time expired", "neighbor signaled session down", "DETECTION_TIMEOUT", "NEIGHBOR_SIGNALED_DOWN"]:
            st.log(
                "PASSED : BFD session diagnostics parameter match for %s using local-address option" % bfd_nbrs_dut1[0])
            break
        x = x + 1

    while y <= 3:
        dict2 = bfd.verify_bfd_peer(dut1, vrf_name=vrfname, peer=ipv6_bfd_nbrs_dut1[0], interface=intf_list[0],
                                    local_addr=ipv6_bfd_nbrs_dut3[0], return_dict="")
        if dict2 and dict2[0]['diagnostics'] in ["control detection time expired", "neighbor signaled session down", "DETECTION_TIMEOUT", "NEIGHBOR_SIGNALED_DOWN"]:
            st.log("PASSED : BFD session diagnostics parameter match for %s using local-address option" %
                   ipv6_bfd_nbrs_dut1[0])
            break
        y = y + 1

    if x == 4:
        st.log("FAILED : BFD session diagnostics parameter mismatch for %s after shutdown" % bfd_nbrs_dut1[0])
        ret_val = False
    elif y == 4:
        st.log("FAILED : BFD session diagnostics parameter mismatch for %s after shutdown" % ipv6_bfd_nbrs_dut1[0])
        ret_val = False

    bfd.configure_bfd(dut3, vrf_name=vrfname, interface=intf_list[0], local_address=bfd_nbrs_dut1[0], neighbor_ip=bfd_nbrs_dut3[0],
                      noshut="yes")
    bfd.configure_bfd(dut3, vrf_name=vrfname, interface=intf_list[0], local_address=ipv6_bfd_nbrs_dut1[0], neighbor_ip=ipv6_bfd_nbrs_dut3[0],
                      noshut="yes")

    ############################################################################################
    hdrMsg("Step-C25: Remove BFD neighbors %s on dut3 and %s on dut1" % (bfd_nbrs_dut1[0], bfd_nbrs_dut3[0]))
    ############################################################################################
    dict1 = {'vrf_name': vrfname, 'interface': intf_list[0], 'local_address': bfd_nbrs_dut3[0], 'neighbor_ip': bfd_nbrs_dut1[0], 'config': "no"}
    dict2 = {'vrf_name': vrfname, 'interface': intf_list[0], 'local_address': bfd_nbrs_dut1[0], 'neighbor_ip': bfd_nbrs_dut3[0], 'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': vrfname, 'interface': intf_list[0], 'local_address': ipv6_bfd_nbrs_dut3[0], 'neighbor_ip': ipv6_bfd_nbrs_dut1[0],
             'config': "no"}
    dict2 = {'vrf_name': vrfname, 'interface': intf_list[0], 'local_address': ipv6_bfd_nbrs_dut1[0], 'neighbor_ip': ipv6_bfd_nbrs_dut3[0],
             'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[0], 'neighbor_ip': non_bfd_nbrs_dut1[0], 'config': "no",
             'local_address': non_bfd_nbrs_dut3[0]}
    dict2 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[0], 'neighbor_ip': non_bfd_nbrs_dut3[0], 'config': "no",
             'local_address': non_bfd_nbrs_dut1[0]}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[0], 'neighbor_ip': ipv6_non_bfd_nbrs_dut1[0],
             'config': "no", 'local_address': ipv6_non_bfd_nbrs_dut3[0]}
    dict2 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[0], 'neighbor_ip': ipv6_non_bfd_nbrs_dut3[0],
             'config': "no", 'local_address': ipv6_non_bfd_nbrs_dut1[0]}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[1], 'local_address': non_bfd_nbrs_dut3[1], 'neighbor_ip': non_bfd_nbrs_dut1[1],
             'config': "no"}
    dict2 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[1], 'local_address': non_bfd_nbrs_dut1[1], 'neighbor_ip': non_bfd_nbrs_dut3[1],
             'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[1], 'local_address': ipv6_non_bfd_nbrs_dut3[1], 'neighbor_ip': ipv6_non_bfd_nbrs_dut1[1],
             'config': "no"}
    dict2 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[1], 'local_address': ipv6_non_bfd_nbrs_dut1[1], 'neighbor_ip': ipv6_non_bfd_nbrs_dut3[1],
             'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[2], 'neighbor_ip': non_bfd_nbrs_dut1[2], 'config': "no",
             'local_address': non_bfd_nbrs_dut3[2]}
    dict2 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[2], 'neighbor_ip': non_bfd_nbrs_dut3[2], 'config': "no",
             'local_address': non_bfd_nbrs_dut1[2]}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[2], 'neighbor_ip': ipv6_non_bfd_nbrs_dut1[2],
             'config': "no", 'local_address': ipv6_non_bfd_nbrs_dut3[2]}
    dict2 = {'vrf_name': vrfname, 'interface': trunk_vlan_name[2], 'neighbor_ip': ipv6_non_bfd_nbrs_dut3[2],
             'config': "no", 'local_address': ipv6_non_bfd_nbrs_dut1[2]}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    return ret_val


def verify_bfd_lag4():
    ret_val = True
    for lag in [lag_name3, lag_name4]:
        result = pc.verify_portchannel_state(dut4, lag)
        if not result:
            st.error("Failed: L3 LAG b/w DUT1 and DUT4 did not come up, so aborting the script run")
            return False
        else:
            st.log("PASSED : dut4 L3 LAG interface %s has come up" % lag)

    ###########################################################################################
    hdrMsg("Step T1: Configure BFD for EBGP neighbors on dut1 and dut2")
    ###########################################################################################
    dict1 = {"local_asn": dut1_as,'neighbor_ip': [dut3_l3lagip_list[0],dut3_l3lagipv6_list[0]], 'config': 'yes'}
    dict2 = {"local_asn": dut3_as,'neighbor_ip': [dut1_l3lagip_list[0],dut1_l3lagipv6_list[0]], 'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut4], bfd.configure_bfd, [dict1, dict2])

    dict1 = {"local_asn": dut1_as,'neighbor_ip': [dut3_l3lagip_list[1],dut3_l3lagipv6_list[1]], 'config': 'yes'}
    dict2 = {"local_asn": dut3_as,'neighbor_ip': [dut1_l3lagip_list[1],dut1_l3lagipv6_list[1]], 'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut4], bfd.configure_bfd, [dict1, dict2])

    dict1={'interface':lag_name3,'neighbor_ip':dut3_l3lagip_list[0],'config':"yes",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    dict2={'interface':lag_name3,'neighbor_ip':dut1_l3lagip_list[0],'config':"yes",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    parallel.exec_parallel(True,[dut1,dut4],bfd.configure_bfd,[dict1,dict2])
    dict1={'interface':lag_name4,'neighbor_ip':dut3_l3lagip_list[1],'config':"yes",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    dict2={'interface':lag_name4,'neighbor_ip':dut1_l3lagip_list[1],'config':"yes",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    parallel.exec_parallel(True,[dut1,dut4],bfd.configure_bfd,[dict1,dict2])

    dict1={'interface':lag_name3,'neighbor_ip':dut3_l3lagipv6_list[0],'config':"yes",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    dict2={'interface':lag_name3,'neighbor_ip':dut1_l3lagipv6_list[0],'config':"yes",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    parallel.exec_parallel(True,[dut1,dut4],bfd.configure_bfd,[dict1,dict2])
    dict1={'interface':lag_name4,'neighbor_ip':dut3_l3lagipv6_list[1],'config':"yes",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    dict2={'interface':lag_name4,'neighbor_ip':dut1_l3lagipv6_list[1],'config':"yes",'multiplier':multiplier,'rx_intv':bfd_rx,'tx_intv':bfd_tx}
    parallel.exec_parallel(True,[dut1,dut4],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step T2: Verify BGP and BFD session is UP ")
    ###########################################################################################
    for nbr in [dut3_l3lagip_list[0],dut3_l3lagipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,state='Established',retry_count=5,delay=2)
        if result is False:
            st.log("FAILED:BGP neighbor state is incorrect for %s"%nbr)
            ret_val = False

    result = retry_api(bfd.verify_bfd_peer,dut1,peer=[dut3_l3lagip_list[0],dut3_l3lagipv6_list[0]],interface=[lag_name3]*2,status=['up']*2,retry_count=2,delay=1)
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" %(dut3_l3lagip_list[0],dut3_l3lagipv6_list[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T3: Trigger link failure by shutting down the physical interface on dut2")
    ###########################################################################################
    port.shutdown(dut1,[lag_name3])
    ###########################################################################################
    hdrMsg("Step T4: Verify BGP session goes down immediately because of fast-externel-failover, not BFD")
    ###########################################################################################
    for nbr in [dut3_l3lagip_list[0],dut3_l3lagipv6_list[0]]:
        result=retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,bgpdownreason="BFD down received",retry_count=2,delay=1)
        if result is False:
            st.log("FAILED:BGP neighbor state is incorrect for %s"%nbr)
            ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut3_l3lagip_list[0], dut3_l3lagipv6_list[0]],
                       interface=[lag_name3] * 2, status=['down'] * 2, retry_count=2, delay=1)
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_l3lagip_list[0], dut3_l3lagipv6_list[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T5: Bring up the interface back and verify BGP and BFD sessions are UP again")
    ###########################################################################################
    port.noshutdown(dut1,[lag_name3])

    for nbr in [dut3_l3lagip_list[0], dut3_l3lagipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,state='Established',retry_count=10,delay=3)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" %(dut3_l3lagip_list[0],dut3_l3lagipv6_list[0]))
            ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut3_l3lagip_list[0], dut3_l3lagipv6_list[0]],
                       interface=[lag_name3] * 2, status=['up'] * 2, retry_count=2, delay=1)
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_l3lagip_list[0], dut3_l3lagipv6_list[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T6: Disable bgp fast-external-failover and trigger link failure again")
    ###########################################################################################
    dict1 = {"local_as": dut1_as,'fast_external_failover':'', 'config_type_list': ["fast_external_failover"],'config':'yes'}
    dict2 = {"local_as": dut3_as,'fast_external_failover':'', 'config_type_list': ["fast_external_failover"],'config':'yes'}
    parallel.exec_parallel(True, [dut1, dut4], bgp.config_bgp, [dict1, dict2])

    port.shutdown(dut1,D1_port[1:3])
    ###########################################################################################
    hdrMsg("Step T7: Verify BGP goes down because of BFD down reason, since fast-failover is disabled")
    ###########################################################################################
    for nbr in [dut3_l3lagip_list[1], dut3_l3lagipv6_list[1]]:
        result=retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,bgpdownreason="Interface down",retry_count=3,delay=1)
        if result is False:
            st.log("FAILED:BGP neighbor state is incorrect for %s"%nbr)
            ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut3_l3lagip_list[1], dut3_l3lagipv6_list[1]],
                       interface=[lag_name4] * 2, status=['down'] * 2, retry_count=2, delay=1)
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_l3lagip_list[1], dut3_l3lagipv6_list[1]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T8: Bring up the interface back and verify BGP and BFD sessions are UP again")
    ###########################################################################################
    port.noshutdown(dut1,D1_port[1:3])

    dict1 = {"local_as": dut1_as,'fast_external_failover':'', 'config_type_list': ["fast_external_failover"],'config':'no'}
    dict2 = {"local_as": dut3_as,'fast_external_failover':'', 'config_type_list': ["fast_external_failover"],'config':'no'}
    parallel.exec_parallel(True, [dut1, dut4], bgp.config_bgp, [dict1, dict2])

    for nbr in [dut3_l3lagip_list[0], dut3_l3lagipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor,dut1,neighborip=nbr,state='Established',retry_count=10,delay=3)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" %(dut3_l3lagip_list[0],dut3_l3lagipv6_list[0]))
            ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, peer=[dut3_l3lagip_list[1], dut3_l3lagipv6_list[1]],
                       interface=[lag_name4] * 2, status=['up'] * 2, retry_count=2, delay=1)
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_l3lagip_list[1], dut3_l3lagipv6_list[1]))
        ret_val = False

    if convergence_test == "yes":
        port.shutdown(dut1,[D1_port[0]]);port.noshutdown(dut1,[D1_port[0]])
        st.wait(2)
        ###########################################################################################
        hdrMsg("Step-C11: Verify routing table to check if destination network %s installed with next-hop %s"%(tg_dest_l3lag_nw,lag_name4))
        ###########################################################################################
        result = ip_api.verify_ip_route(dut1,ip_address="%s/%s"%(tg_dest_l3lag_nw,ip_mask),interface=lag_name4, family="ipv4")
        if result:
            st.log("DUT1: Destination route %s installed with nexthop interface %s "%(tg_dest_l3lag_nw,lag_name4))
        else:
            st.log("FAILED : DUT1: Destination route %s not installed with nexthop interface %s " % (tg_dest_l3lag_nw,lag_name4))
        ###########################################################################################
        hdrMsg("Step-C12: Verify routing table to check if destination network %s installed with next-hop %s"%(tg_dest_l3lag_nw_v6,lag_name4))
        ###########################################################################################
        result = ip_api.verify_ip_route(dut1,ip_address="%s/%s"%(tg_dest_l3lag_nw_v6,ipv6_mask),interface=lag_name4, family="ipv6")
        if result:
            st.log("DUT1: Destination route %s installed with nexthop interface %s "%(tg_dest_l3lag_nw_v6,lag_name4))
        else:
            st.log("FAILED : DUT1: Destination route %s not installed with nexthop interface %s " % (tg_dest_l3lag_nw_v6,lag_name4))
        ###########################################################################################
        hdrMsg("Step-C47: Measure Traffic convergence with BFD enabled by shutting dut1<---> dut4 port" )
        ###########################################################################################
        #converged_bfd = convergence_measure(dut4,lag_name4,version="both",dest='d4')
        converged_bfd = convergence_measure(dut4,D3_port[1:3],version="both",dest='d4')
    ###########################################################################################
    hdrMsg("Step T9: Remove BFD for EBGP neighbors on dut1 and dut4")
    ###########################################################################################
    dict1 = {"local_asn": dut1_as,'neighbor_ip': [dut3_l3lagip_list[0],dut3_l3lagipv6_list[0]], 'config': 'no'}
    dict2 = {"local_asn": dut3_as,'neighbor_ip': [dut1_l3lagip_list[0],dut1_l3lagipv6_list[0]], 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut4], bfd.configure_bfd, [dict1, dict2])
    dict1 = {"local_asn": dut1_as,'neighbor_ip': [dut3_l3lagip_list[1],dut3_l3lagipv6_list[1]], 'config': 'no'}
    dict2 = {"local_asn": dut3_as,'neighbor_ip': [dut1_l3lagip_list[1],dut1_l3lagipv6_list[1]], 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut4], bfd.configure_bfd, [dict1, dict2])

    dict1={'interface':lag_name3,'neighbor_ip':dut3_l3lagip_list[0],'config':"no"}
    dict2={'interface':lag_name3,'neighbor_ip':dut1_l3lagip_list[0],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut4],bfd.configure_bfd,[dict1,dict2])
    dict1={'interface':lag_name4,'neighbor_ip':dut3_l3lagip_list[1],'config':"no"}
    dict2={'interface':lag_name4,'neighbor_ip':dut1_l3lagip_list[1],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut4],bfd.configure_bfd,[dict1,dict2])

    dict1={'interface':lag_name3,'neighbor_ip':dut3_l3lagipv6_list[0],'config':"no"}
    dict2={'interface':lag_name3,'neighbor_ip':dut1_l3lagipv6_list[0],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut4],bfd.configure_bfd,[dict1,dict2])
    dict1={'interface':lag_name4,'neighbor_ip':dut3_l3lagipv6_list[1],'config':"no"}
    dict2={'interface':lag_name4,'neighbor_ip':dut1_l3lagipv6_list[1],'config':"no"}
    parallel.exec_parallel(True,[dut1,dut4],bfd.configure_bfd,[dict1,dict2])

    if convergence_test == "yes":
        port.shutdown(dut1,[D1_port[0]]);port.noshutdown(dut1,[D1_port[0]])
        st.wait(2)
        ###########################################################################################
        hdrMsg("Step-C11: Verify routing table to check if destination network %s installed with next-hop %s"%(tg_dest_l3lag_nw,lag_name4))
        ###########################################################################################
        result = ip_api.verify_ip_route(dut1,ip_address="%s/%s"%(tg_dest_l3lag_nw,ip_mask),interface=lag_name4, family="ipv4")
        if result:
            st.log("DUT1: Destination route %s installed with nexthop interface %s "%(tg_dest_l3lag_nw,lag_name4))
        else:
            st.log("FAILED : DUT1: Destination route %s not installed with nexthop interface %s " % (tg_dest_l3lag_nw,lag_name4))
        ###########################################################################################
        hdrMsg("Step-C12: Verify routing table to check if destination network %s installed with next-hop %s"%(tg_dest_l3lag_nw_v6,lag_name4))
        ###########################################################################################
        result = ip_api.verify_ip_route(dut1,ip_address="%s/%s"%(tg_dest_l3lag_nw_v6,ipv6_mask),interface=lag_name4, family="ipv6")
        if result:
            st.log("DUT1: Destination route %s installed with nexthop interface %s "%(tg_dest_l3lag_nw_v6,lag_name4))
        else:
            st.log("FAILED : DUT1: Destination route %s not installed with nexthop interface %s " % (tg_dest_l3lag_nw_v6,lag_name4))
        ###########################################################################################
        hdrMsg("Step-C50: Measure Traffic convergence without BFD by shutting dut1<---> dut4 port" )
        ###########################################################################################
        #converged = convergence_measure(dut4,lag_name4,version="both",dest='d4')
        converged = convergence_measure(dut4,D3_port[1:3],version="both",dest='d4')
        st.log(" >>>>> Traffic Convergence with BFD for L3 LAG case: %s ms  <<<<<<"% converged_bfd)
        st.log(" >>>>> Traffic Convergence without BFD for L3 LAG case: %s ms <<<<<<" % converged)

        if converged_bfd is not False:
            if int(converged_bfd) > 1000 and int(bfd_rx) < 20 and int(bfd_tx) < 20 and int(multiplier) < 4:
                st.error("FAILED : Traffic convergence with BFD taking more time for L3 LAG case")
                ret_val=False
            else:
                st.log("PASSED : BFD Traffic convergence test passed for L3 LAG")
        else:
            st.error("FAILED : Traffic was not received by the destination STC port")
            ret_val=False

    ############################################################################################
    hdrMsg("Step-C10: Remove eBGP neighbors %s on dut1 and %s on dut4" % (dut3_l3lagip_list[0],dut1_l3lagip_list[0]))
    ############################################################################################
    utils.exec_all(True, [[bgp.delete_bgp_neighbor,dut1,dut1_as,dut3_l3lagip_list[0],dut3_as],[bgp.delete_bgp_neighbor,dut4,dut3_as,dut1_l3lagip_list[0],dut1_as]])
    utils.exec_all(True, [[bgp.delete_bgp_neighbor,dut1,dut1_as,dut3_l3lagip_list[1],dut3_as],[bgp.delete_bgp_neighbor,dut4,dut3_as,dut1_l3lagip_list[1],dut1_as]])
    ############################################################################################
    hdrMsg("Step-C11: Remove eBGP neighbors %s on dut1 and %s on dut4" % (dut3_l3lagipv6_list[0], dut1_l3lagipv6_list[0]))
    ############################################################################################
    utils.exec_all(True, [[bgp.delete_bgp_neighbor,dut1,dut1_as,dut3_l3lagipv6_list[0],dut3_as],[bgp.delete_bgp_neighbor,dut4,dut3_as,dut1_l3lagipv6_list[0],dut1_as]])
    utils.exec_all(True, [[bgp.delete_bgp_neighbor,dut1,dut1_as,dut3_l3lagipv6_list[1],dut3_as],[bgp.delete_bgp_neighbor,dut4,dut3_as,dut1_l3lagipv6_list[1],dut1_as]])

    ############################################################################################
    hdrMsg("Step-C12: Adding static route for mhop bfd to come up")
    ############################################################################################
    utils.exec_all(True, [[ip_api.create_static_route,dut1,dut3_l3lagip_list[0],'%s/%s'%(dut4_lo_ip,lo_mask),"vtysh","ipv4"],[ip_api.create_static_route,dut4,dut1_l3lagip_list[0],'%s/%s'%(dut1_lo_ip,lo_mask),"vtysh","ipv4"]])
    utils.exec_all(True, [[ip_api.create_static_route,dut1,dut3_l3lagipv6_list[0],'%s/%s'%(dut4_lo_ipv6,lo_v6mask),"vtysh","ipv6"],[ip_api.create_static_route,dut4,dut1_l3lagipv6_list[0],'%s/%s'%(dut1_lo_ipv6,lo_v6mask),"vtysh","ipv6"]])

    ############################################################################################
    hdrMsg("Step-C13: config BGP mhop in dut1 and dut4")
    ############################################################################################
    dict1={'neighbor':dut4_lo_ip,'local_as':dut1_as,'config':'yes','config_type_list':['neighbor','update_src','ebgp_mhop'],'update_src':dut1_lo_ip,'ebgp_mhop':"2",'remote_as':dut3_as}
    dict2={'neighbor':dut1_lo_ip,'local_as':dut3_as,'config':'yes','config_type_list':['neighbor','update_src','ebgp_mhop'],'update_src':dut4_lo_ip,'ebgp_mhop':"2",'remote_as':dut1_as}
    parallel.exec_parallel(True,[dut1,dut4],bgp.config_bgp,[dict1,dict2])

    dict1={'neighbor':dut4_lo_ipv6,'local_as':dut1_as,'config':'yes','config_type_list':['neighbor','update_src','ebgp_mhop'],'update_src':dut1_lo_ipv6,'ebgp_mhop':"2",'remote_as':dut3_as}
    dict2={'neighbor':dut1_lo_ipv6,'local_as':dut3_as,'config':'yes','config_type_list':['neighbor','update_src','ebgp_mhop'],'update_src':dut4_lo_ipv6,'ebgp_mhop':"2",'remote_as':dut1_as}
    parallel.exec_parallel(True,[dut1,dut4],bgp.config_bgp,[dict1,dict2])

    ############################################################################################
    hdrMsg("Step-C14: config BFD mhop in dut1 and dut4")
    ############################################################################################
    dict1={'local_asn':dut1_as,'neighbor_ip':[dut4_lo_ip,dut4_lo_ipv6],'config':"yes"}
    dict2={'local_asn':dut3_as,'neighbor_ip':[dut1_lo_ip,dut1_lo_ipv6],'config':"yes"}
    parallel.exec_parallel(True,[dut1,dut4],bfd.configure_bfd,[dict1,dict2])

    ###########################################################################################
    hdrMsg("Step-C15: Verify ebgp multihop BFD session comes up for %s and %s in dut1 and also check BFD debug messages"%(dut4_lo_ip,dut4_lo_ipv6))
    ###########################################################################################
    for nbr in [dut4_lo_ip,dut4_lo_ipv6]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, neighborip=nbr, state='Established', retry_count=10, delay=3)
        if result is False:
            st.log("FAILED : BGP session parameters mismatch for %s" % (nbr))
            ret_val = False

    result = retry_api(bfd.verify_bfd_peer,dut1,peer=[dut4_lo_ip,dut4_lo_ipv6],local_addr=[dut1_lo_ip,dut1_lo_ipv6],status=['up','up'],multihop=["yes","yes"],retry_count=5,delay=2,peer_type=["dynamic","dynamic"])
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" %(dut4_lo_ip,dut4_lo_ipv6))
        ret_val = False

    if not ret_val:
        basic.get_techsupport(dut_list, 'test_bfd_lag_001_port_flap')

    basic.add_user_log_in_frr(dut1, "bfd.log")
    basic.debug_bfdconfig_using_frrlog(dut=dut1,config="yes",log_file_name="bfd.log")
    bfd.configure_bfd(dut=dut4,local_address=dut4_lo_ip,neighbor_ip=dut1_lo_ip,shutdown="yes",multihop="yes")
    bfd.configure_bfd(dut=dut4,local_address=dut4_lo_ipv6,neighbor_ip=dut1_lo_ipv6,shutdown="yes",multihop="yes")

    output = basic.return_user_log_from_frr(dut1,"bfd.log")
    bfd_v4_arlo_log = "BFD: state-change: [mhop:yes peer:%s local:%s] up -> down reason:neighbor-down"%(dut4_lo_ip,dut1_lo_ip)
    bfd_v6_arlo_log = "BFD: state-change: [mhop:yes peer:%s local:%s] up -> down reason:neighbor-down"%(dut4_lo_ipv6,dut1_lo_ipv6)
    bfd_v4_buzznik_log = "BFD: state-change: [mhop:yes peer:%s local:%s vrf:default] up -> down reason:neighbor-down"%(dut4_lo_ip,dut1_lo_ip)
    bfd_v6_buzznik_log = "BFD: state-change: [mhop:yes peer:%s local:%s vrf:default] up -> down reason:neighbor-down"%(dut4_lo_ipv6,dut1_lo_ipv6)
    if bfd_v4_buzznik_log not in output and bfd_v4_arlo_log not in output:
        st.log("FAILED : BFD log not generated for Multi hop BFD IPv4 session %s in dut 1"%dut4_lo_ip)
        ret_val = False
    elif bfd_v6_buzznik_log not in output and bfd_v6_arlo_log not in output:
        st.log("FAILED : BFD log not generated for Multi hop BFD IPv6 session %s in dut 1"%dut4_lo_ipv6)
        ret_val = False
    else:
        st.log("PASSED : DUT1 BFD log got generated for Multi hop BFD IPv4 session %s and Multi hop IPv6 session %s"%(dut4_lo_ip,dut1_lo_ipv6))

    basic.debug_bfdconfig_using_frrlog(dut=dut1,config="no",log_file_name="bfd.log")
    basic.remove_user_log_in_frr(dut1,"bfd.log")
    ############################################################################################
    hdrMsg("Step-C16: Delete static route in dut1 and dut4")
    ############################################################################################
    utils.exec_all(True, [[ip_api.delete_static_route,dut1,dut3_l3lagip_list[0],'%s/%s'%(dut4_lo_ip,lo_mask),"ipv4","vtysh"],[ip_api.delete_static_route,dut4,dut1_l3lagip_list[0],'%s/%s'%(dut1_lo_ip,lo_mask),"ipv4","vtysh"]])
    utils.exec_all(True, [[ip_api.delete_static_route,dut1,dut3_l3lagipv6_list[0],'%s/%s'%(dut4_lo_ipv6,lo_v6mask),"ipv6","vtysh"],[ip_api.delete_static_route,dut4,dut1_l3lagipv6_list[0],'%s/%s'%(dut1_lo_ipv6,lo_v6mask),"ipv6","vtysh"]])

    ############################################################################################
    hdrMsg("Step-C17: Delete BGP mhop in dut1 and dut4")
    ############################################################################################
    utils.exec_all(True, [[bgp.delete_bgp_neighbor,dut1,dut1_as,dut4_lo_ip,dut1_as],[bgp.delete_bgp_neighbor,dut4,dut3_as,dut1_lo_ip,dut1_as]])
    utils.exec_all(True, [[bgp.delete_bgp_neighbor,dut1,dut1_as,dut4_lo_ipv6,dut1_as],[bgp.delete_bgp_neighbor,dut4,dut3_as,dut1_lo_ipv6,dut1_as]])

    ############################################################################################
    hdrMsg("Step-C18: Delete BFD mhop in dut4")
    ############################################################################################
    bfd.configure_bfd(dut=dut4,local_address=dut4_lo_ip,neighbor_ip=dut1_lo_ip,config="no",multihop="yes")
    bfd.configure_bfd(dut=dut4,local_address=dut4_lo_ipv6,neighbor_ip=dut1_lo_ipv6,config="no",multihop="yes")

    return ret_val


def verify_bfd_lag5():
    ret_val = True
    for lag in [lag_name1_vrf, lag_name2_vrf]:
        result = pc.verify_portchannel_state(dut1, lag)
        if not result:
            st.error("Failed: L1 LAG b/w DUT1 and DUT1 did not come up, so aborting the script run")
            return False
        else:
            st.log("PASSED : dut1 L1 LAG interface %s has come up" % lag)

    ###########################################################################################
    hdrMsg("Step T1: Configure BFD for EBGP neighbors on dut1 and dut2")
    ###########################################################################################
    dict1 = {'vrf_name':user_vrf_name, "local_asn": dut1_as, 'neighbor_ip': [dut3_lagip_list[0], dut3_lagipv6_list[0]], 'config': 'yes'}
    dict2 = {'vrf_name':user_vrf_name, "local_asn": dut3_as, 'neighbor_ip': [dut1_lagip_list[0], dut1_lagipv6_list[0]], 'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name':user_vrf_name, "local_asn": dut1_as, 'neighbor_ip': [dut3_lagip_list[2], dut3_lagipv6_list[2]], 'config': 'yes'}
    dict2 = {'vrf_name':user_vrf_name, "local_asn": dut3_as, 'neighbor_ip': [dut1_lagip_list[2], dut1_lagipv6_list[2]], 'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name':user_vrf_name, 'interface': access_vlan_name_vrf, 'neighbor_ip': dut3_lagip_list[0], 'config': "yes", 'multiplier': multiplier,
             'rx_intv': bfd_rx, 'tx_intv': bfd_tx}
    dict2 = {'vrf_name':user_vrf_name, 'interface': access_vlan_name_vrf, 'neighbor_ip': dut1_lagip_list[0], 'config': "yes", 'multiplier': multiplier,
             'rx_intv': bfd_rx, 'tx_intv': bfd_tx}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name':user_vrf_name, 'interface': trunk_vlan_name_vrf[0], 'neighbor_ip': dut3_lagip_list[2], 'config': "yes", 'multiplier': multiplier,
             'rx_intv': bfd_rx, 'tx_intv': bfd_tx}
    dict2 = {'vrf_name':user_vrf_name, 'interface': trunk_vlan_name_vrf[0], 'neighbor_ip': dut1_lagip_list[2], 'config': "yes", 'multiplier': multiplier,
             'rx_intv': bfd_rx, 'tx_intv': bfd_tx}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name':user_vrf_name, 'interface': access_vlan_name_vrf, 'neighbor_ip': dut3_lagipv6_list[0], 'config': "yes", 'multiplier': multiplier,
             'rx_intv': bfd_rx, 'tx_intv': bfd_tx}
    dict2 = {'vrf_name':user_vrf_name, 'interface': access_vlan_name_vrf, 'neighbor_ip': dut1_lagipv6_list[0], 'config': "yes", 'multiplier': multiplier,
             'rx_intv': bfd_rx, 'tx_intv': bfd_tx}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name':user_vrf_name, 'interface': trunk_vlan_name_vrf[0], 'neighbor_ip': dut3_lagipv6_list[2], 'config': "yes", 'multiplier': multiplier,
             'rx_intv': bfd_rx, 'tx_intv': bfd_tx}
    dict2 = {'vrf_name':user_vrf_name, 'interface': trunk_vlan_name_vrf[0], 'neighbor_ip': dut1_lagipv6_list[2], 'config': "yes", 'multiplier': multiplier,
             'rx_intv': bfd_rx, 'tx_intv': bfd_tx}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg("Step T2: Verify BGP and BFD session is UP ")
    ###########################################################################################
    for nbr in [dut3_lagip_list[0], dut3_lagipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                           retry_count=5, delay=2)
        if result is False:
            st.log("FAILED:BGP neighbor state is incorrect for %s" % nbr)
            ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=[dut3_lagip_list[0], dut3_lagipv6_list[0]],
                       interface=[access_vlan_name_vrf] * 2, status=['up'] * 2, retry_count=2, delay=1)
    if result is False:
        st.log(
            "FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lagip_list[0], dut3_lagipv6_list[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T3: Trigger link failure by shtting down the physical interface on dut2")
    ###########################################################################################
    port.shutdown(dut3, [flap_ports_vrf[0]])
    ###########################################################################################
    hdrMsg("Step T4: Verify BGP session goes down immediately because of fast-externel-failover, not BFD")
    ###########################################################################################
    for nbr in [dut3_lagip_list[0], dut3_lagipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, bgpdownreason="BFD down received",
                           retry_count=2, delay=1)
        if result is False:
            st.log("FAILED:BGP neighbor state is incorrect for %s" % nbr)
            ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name,
                       peer=[dut3_lagip_list[0], dut3_lagipv6_list[0]],
                       interface=[access_vlan_name_vrf] * 2, status=['down'] * 2, retry_count=5, delay=1)
    if result is False:
        st.log(
            "FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lagip_list[0], dut3_lagipv6_list[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T5: Bring up the interface back and verify BGP and BFD sessions are UP again")
    ###########################################################################################
    port.noshutdown(dut3, [flap_ports_vrf[0]])

    for nbr in [dut3_lagip_list[0], dut3_lagipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                           retry_count=10, delay=3)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" % (
            dut3_lagip_list[0], dut3_lagipv6_list[0]))
            ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name,
                       peer=[dut3_lagip_list[0], dut3_lagipv6_list[0]],
                       interface=[access_vlan_name_vrf] * 2, status=['up'] * 2, retry_count=2, delay=1)
    if result is False:
        st.log(
            "FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lagip_list[0], dut3_lagipv6_list[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T6: Enable bgp fast-external-failover and trigger link failure again")
    ###########################################################################################
    dict1 = {'vrf_name':user_vrf_name, "local_as": dut1_as, 'fast_external_failover': '', 'config_type_list': ["fast_external_failover"],
             'config': 'yes'}
    dict2 = {'vrf_name':user_vrf_name, "local_as": dut3_as, 'fast_external_failover': '', 'config_type_list': ["fast_external_failover"],
             'config': 'yes'}
    parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])

    port.shutdown(dut1, D1_ports_vrf[1:3])
    ###########################################################################################
    hdrMsg("Step T7: Verify BGP goes down because of Interface down reason, since fast-failover is enabled")
    ###########################################################################################
    result_flag = 0
    for nbr in [dut3_lagip_list[2], dut3_lagipv6_list[2]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, bgpdownreason="Interface down",
                           retry_count=3, delay=1)
        if result is False:
            result_flag = 1
            break
    if result_flag:
        for nbr in [dut3_lagip_list[2], dut3_lagipv6_list[2]]:
            result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr,
                               bgpdownreason="Waiting for NHT",
                               retry_count=3, delay=1)
            if result is False:
                st.log("FAILED:BGP neighbor state is incorrect for %s" % nbr)
                ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name,
                       peer=[dut3_lagip_list[2], dut3_lagipv6_list[2]],
                       interface=[trunk_vlan_name_vrf[0]] * 2, status=['down'] * 2, retry_count=2, delay=1)
    if result is False:
        st.log(
            "FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lagip_list[2], dut3_lagipv6_list[2]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T8: Bring up the interface back and verify BGP and BFD sessions are UP again")
    ###########################################################################################
    port.noshutdown(dut1, D1_ports_vrf[1:3])

    dict1 = {'vrf_name':user_vrf_name, "local_as": dut1_as, 'fast_external_failover': '', 'config_type_list': ["fast_external_failover"],
             'config': 'no'}
    dict2 = {'vrf_name':user_vrf_name, "local_as": dut3_as, 'fast_external_failover': '', 'config_type_list': ["fast_external_failover"],
             'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])

    for nbr in [dut3_lagip_list[2], dut3_lagipv6_list[2]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                           retry_count=10, delay=3)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" % (
            dut3_lagip_list[2], dut3_lagipv6_list[2]))
            ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name,
                       peer=[dut3_lagip_list[2], dut3_lagipv6_list[2]],
                       interface=[trunk_vlan_name_vrf[0]] * 2, status=['up'] * 2, retry_count=2, delay=1)
    if result is False:
        st.log(
            "FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lagip_list[2], dut3_lagipv6_list[2]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T9: Do BFD shutdown under BFD for %s and verify BGP BFD sessions for %s didnot go down "%(dut3_lagip_list[0],dut3_lagipv6_list[0]))
    ###########################################################################################
    bfd.configure_bfd(dut1,interface=access_vlan_name_vrf,neighbor_ip=dut3_lagip_list[0],shutdown='', vrf_name=user_vrf_name)

    st.log("Verify only ipv4 BFD peer goes down and ipv6 on same interface is UP")
    result = ip_bgp.verify_bgp_neighbor(dut1, neighborip=dut3_lagip_list[0],state='Established',vrf=user_vrf_name)
    if result is False:
        st.log('bgp_bfd_params failed for DUT {} for ip list {} for {}'.format(dut1, dut3_lagip_list[0], user_vrf_name))
        ret_val = False

    result = ip_bgp.verify_bgp_neighbor(dut1, neighborip=dut3_lagipv6_list[0], state='Established',vrf=user_vrf_name)
    if result is False:
        st.log('bgp_bfd_params  failed for DUT {} for ip list {} for {}'.format(dut1, dut3_lagipv6_list[0], user_vrf_name))
        ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name,
                       peer=[dut3_lagip_list[0], dut3_lagipv6_list[0]],
                       interface=[access_vlan_name_vrf] * 2, status=['shutdown', 'up'], retry_count=2, delay=1)
    if result is False:
        st.log(
            "FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lagip_list[0], dut3_lagipv6_list[0]))
        ret_val = False

    st.log("Bring BFD peer %s also down and verify BGP session goes down"%dut3_lagipv6_list[0])
    bfd.configure_bfd(dut1, interface=access_vlan_name_vrf, neighbor_ip=dut3_lagipv6_list[0], shutdown='', vrf_name=user_vrf_name)

    result = ip_bgp.verify_bgp_neighbor(dut1, neighborip=dut3_lagipv6_list[0],state='Established', vrf=user_vrf_name)
    if result is False:
        st.log('bgp_bfd_params failed for DUT {} for ip list {} for {}'.format(dut1, dut3_lagipv6_list[0], user_vrf_name))
        ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name,
                       peer=[dut3_lagip_list[0], dut3_lagipv6_list[0]],
                       interface=[access_vlan_name_vrf] * 2, status=['shutdown', 'shutdown'], retry_count=2, delay=1)
    if result is False:
        st.log(
            "FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lagip_list[0], dut3_lagipv6_list[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T10: Do BFD no-shutdown under BFD and verify BGP BFD sessions %s comes up"%[dut3_lagip_list[0],dut3_lagipv6_list[0]])
    ###########################################################################################
    bfd.configure_bfd(dut1,interface=access_vlan_name_vrf, neighbor_ip=dut3_lagip_list[0], noshut='', vrf_name=user_vrf_name)
    bfd.configure_bfd(dut1, interface=access_vlan_name_vrf, neighbor_ip=dut3_lagipv6_list[0], noshut='', vrf_name=user_vrf_name)
    st.wait(2)
    result = ip_bgp.verify_bgp_neighbor(dut1, neighborip=dut3_lagip_list[0],vrf=user_vrf_name,state='Established')
    if result is False:
        st.log('bgp_bfd_params failed for DUT {} for ip list {} for {}'.format(dut1, dut3_lagip_list[0], user_vrf_name))
        ret_val = False

    result = ip_bgp.verify_bgp_neighbor(dut1, neighborip=dut3_lagipv6_list[0], vrf=user_vrf_name,state='Established')
    if result is False:
        st.log('bgp_bfd_params failed for DUT {} for ip list {} for {}'.format(dut1, dut3_lagipv6_list[0], user_vrf_name))
        ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name,
                       peer=[dut3_lagip_list[0], dut3_lagipv6_list[0]],
                       interface=[access_vlan_name_vrf] * 2, status=['up', 'up'], retry_count=2, delay=1)
    if result is False:
        st.log(
            "FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lagip_list[0], dut3_lagipv6_list[0]))
        ret_val = False

    ###########################################################################################
    hdrMsg("StepT11: Remove BFD for BGP neighbors and Verify autocreated BFD peers still continue to exist as static BFD peers")
    ###########################################################################################
    bfd.configure_bfd(dut1,vrf_name=user_vrf_name, local_asn=dut1_as, neighbor_ip=dut3_lagip_list[0:1] + dut3_lagipv6_list[0:1],config='no')
    result = bfd.verify_bfd_peer(dut1,peer=[dut3_lagip_list[0],dut3_lagipv6_list[0]],status=['up']*2,
                                 rx_interval=[['100','100']]*2, vrf_name=user_vrf_name,
                                 tx_interval = [['100', '100']]*2)
    if result is False:
        st.log('bgp_bfd_params failed for DUT {} for {}'.format(dut1, user_vrf_name))
        basic.get_techsupport(filename="FtOpSoRoBfdVrfFn012_18")
        ret_val = False

    ###########################################################################################
    hdrMsg("StepT12: Re-enable BFD  under BGP neighbors and verify BFD session comes up with already configured timers")
    ###########################################################################################

    bfd.configure_bfd(dut1, vrf_name=user_vrf_name, local_asn=dut1_as, neighbor_ip=dut3_lagip_list[0:1] + dut3_lagipv6_list[0:1])
    result = retry_api(bfd.verify_bfd_peer,dut1,peer=dut3_lagip_list[0:1]+dut3_lagipv6_list[0:1],status=['up']*4,
                                 rx_interval=[['100','100'],['100','100']]*2, vrf_name=user_vrf_name,
                                 tx_interval = [['100', '100'], ['100','100']] * 2,retry_count=3,delay=1)
    if result is False:
        st.log('bgp_bfd_params failed for DUT {} for {}'.format(dut1,user_vrf_name))
        ret_val = False

    ###########################################################################################
    hdrMsg("StepT12: Remove port from lag and check BFD session goes down as BGP session goes down as neighbor unreachable ")
    ###########################################################################################
    pc.delete_portchannel_member(dut1, lag_name1_vrf, [D1_ports_vrf[0]])

    for nbr in [dut3_lagip_list[0], dut3_lagipv6_list[0]]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr,
                           bgpdownreason="Waiting for NHT", retry_count=3, delay=1)
        if result is False:
            st.log("FAILED:BGP neighbor state is incorrect for %s" % nbr)
            ret_val = False

    pc.add_portchannel_member(dut1, lag_name1_vrf, [D1_ports_vrf[0]])

    result = retry_api(bfd.verify_bfd_peer,dut1,peer=dut3_lagip_list[0:1]+dut3_lagipv6_list[0:1],status=['up']*4,
                                 rx_interval=[['100','100'],['100','100']]*2, vrf_name=user_vrf_name,
                                 tx_interval = [['100', '100'], ['100','100']] * 2,retry_count=3,delay=1)
    if result is False:
        st.log('bgp_bfd_params failed for DUT {} for {}'.format(dut1,user_vrf_name))
        ret_val = False

    if convergence_test == "yes":
        port.shutdown(dut1, [D1_ports_vrf[0]]);
        port.noshutdown(dut1, [D1_ports_vrf[0]])
        st.wait(2)
        ###########################################################################################
        hdrMsg("Step-C11: Verify routing table to check if destination network %s installed with next-hop %s" % (
        tg_dest_nw, trunk_vlan_name_vrf[0]))
        ###########################################################################################
        result = retry_api(ip_api.verify_ip_route, dut1, vrf_name=user_vrf_name, ip_address="%s/%s" % (tg_dest_nw, ip_mask), interface=trunk_vlan_name_vrf[0],
                                        family="ipv4", retry_count=3,delay=1)

        if result:
            st.log("DUT1: Destination route %s installed with nexthop interface %s " % (tg_dest_nw, trunk_vlan_name_vrf[0]))
        else:
            st.log("FAILED : DUT1: Destination route %s not installed with nexthop interface %s " % (
            tg_dest_nw, trunk_vlan_name_vrf[0]))
            ret_val = False
        ###########################################################################################
        hdrMsg("Step-C12: Verify routing table to check if destination network %s installed with next-hop %s" % (
        tg_dest_nw_v6, trunk_vlan_name_vrf[0]))
        ###########################################################################################
        result =  retry_api(ip_api.verify_ip_route, dut1, vrf_name=user_vrf_name, ip_address="%s/%s" % (tg_dest_nw_v6, ipv6_mask),
                                        interface=trunk_vlan_name_vrf[0], family="ipv6", retry_count=3,delay=1)
        if result:
            st.log("DUT1: Destination route %s installed with nexthop interface %s " % (tg_dest_nw_v6, trunk_vlan_name_vrf[0]))
        else:
            st.log("FAILED : DUT1: Destination route %s not installed with nexthop interface %s " % (
            tg_dest_nw_v6, trunk_vlan_name_vrf[0]))
            ret_val = False
        ###########################################################################################
        hdrMsg("Step-C47: Measure Traffic convergence with BFD enabled by shutting dut1<---> dut4 port")
        ###########################################################################################
        # converged_bfd = convergence_measure(dut4,lag_name4,version="both",dest='d4')
        converged_bfd = convergence_measure(dut1, D1_ports_vrf[1:3], version="both", dest='d3vrf')
    ###########################################################################################
    hdrMsg("Step T9: Remove BFD for EBGP neighbors on dut1 and dut4")
    ###########################################################################################
    dict1 = {'vrf_name':user_vrf_name, "local_asn": dut1_as, 'neighbor_ip': dut3_lagip_list[0], 'config': 'no'}
    dict2 = {'vrf_name':user_vrf_name, "local_asn": dut3_as, 'neighbor_ip': dut1_lagip_list[0], 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name':user_vrf_name, "local_asn": dut1_as, 'neighbor_ip': dut3_lagip_list[2], 'config': 'no'}
    dict2 = {'vrf_name':user_vrf_name, "local_asn": dut3_as, 'neighbor_ip': dut1_lagip_list[2], 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name':user_vrf_name, 'interface': access_vlan_name_vrf, 'neighbor_ip': dut3_lagipv6_list[0], 'config': "no"}
    dict2 = {'vrf_name':user_vrf_name, 'interface': access_vlan_name_vrf, 'neighbor_ip': dut1_lagipv6_list[0], 'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name':user_vrf_name, 'interface': trunk_vlan_name_vrf[0], 'neighbor_ip': dut3_lagipv6_list[2], 'config': "no"}
    dict2 = {'vrf_name':user_vrf_name, 'interface': trunk_vlan_name_vrf[0], 'neighbor_ip': dut1_lagipv6_list[2], 'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': user_vrf_name, "local_asn": dut1_as, 'neighbor_ip': dut3_lagipv6_list[0], 'config': 'no'}
    dict2 = {'vrf_name': user_vrf_name, "local_asn": dut3_as, 'neighbor_ip': dut1_lagipv6_list[0], 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name': user_vrf_name, "local_asn": dut1_as, 'neighbor_ip': dut3_lagipv6_list[2], 'config': 'no'}
    dict2 = {'vrf_name': user_vrf_name, "local_asn": dut3_as, 'neighbor_ip': dut1_lagipv6_list[2], 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': user_vrf_name, 'interface': access_vlan_name_vrf, 'neighbor_ip': dut3_lagip_list[0],
             'config': "no"}
    dict2 = {'vrf_name': user_vrf_name, 'interface': access_vlan_name_vrf, 'neighbor_ip': dut1_lagip_list[0],
             'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name': user_vrf_name, 'interface': trunk_vlan_name_vrf[0], 'neighbor_ip': dut3_lagip_list[2],
             'config': "no"}
    dict2 = {'vrf_name': user_vrf_name, 'interface': trunk_vlan_name_vrf[0], 'neighbor_ip': dut1_lagip_list[2],
             'config': "no"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    if convergence_test == "yes":
        dict1 = {'vrf_name': user_vrf_name, "local_as": dut1_as, 'fast_external_failover': '',
                 'config_type_list': ["fast_external_failover"],
                 'config': 'yes'}
        dict2 = {'vrf_name': user_vrf_name, "local_as": dut3_as, 'fast_external_failover': '',
                 'config_type_list': ["fast_external_failover"],
                 'config': 'yes'}
        parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])

        port.shutdown(dut1, [D1_ports_vrf[0]]);
        port.noshutdown(dut1, [D1_ports_vrf[0]])
        st.wait(2)
        dict1 = {'vrf_name': user_vrf_name, "local_as": dut1_as, 'fast_external_failover': '',
                 'config_type_list': ["fast_external_failover"],
                 'config': 'no'}
        dict2 = {'vrf_name': user_vrf_name, "local_as": dut3_as, 'fast_external_failover': '',
                 'config_type_list': ["fast_external_failover"],
                 'config': 'no'}
        parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])
        ###########################################################################################
        hdrMsg("Step-C11: Verify routing table to check if destination network %s installed with next-hop %s" % (
        tg_dest_nw, trunk_vlan_name_vrf[0]))
        ###########################################################################################
        result =  retry_api(ip_api.verify_ip_route, dut1, vrf_name=user_vrf_name, ip_address="%s/%s" % (tg_dest_nw, ip_mask), interface=trunk_vlan_name_vrf[0],
                                        family="ipv4", retry_count=5,delay=1)
        if result:
            st.log("DUT1: Destination route %s installed with nexthop interface %s " % (tg_dest_nw, trunk_vlan_name_vrf[0]))
        else:
            st.log("FAILED : DUT1: Destination route %s not installed with nexthop interface %s " % (
            tg_dest_nw, trunk_vlan_name_vrf[0]))
            ret_val = False
        ###########################################################################################
        hdrMsg("Step-C12: Verify routing table to check if destination network %s installed with next-hop %s" % (
        tg_dest_nw_v6, lag_name4))
        ###########################################################################################
        result =  retry_api(ip_api.verify_ip_route, dut1, vrf_name=user_vrf_name, ip_address="%s/%s" % (tg_dest_nw_v6, ipv6_mask),
                                        interface=trunk_vlan_name_vrf[0], family="ipv6", retry_count=3,delay=1)
        if result:
            st.log("DUT1: Destination route %s installed with nexthop interface %s " % (tg_dest_nw_v6, trunk_vlan_name_vrf[0]))
        else:
            st.log("FAILED : DUT1: Destination route %s not installed with nexthop interface %s " % (
            tg_dest_nw_v6, trunk_vlan_name_vrf[0]))
            ret_val = False
        ###########################################################################################
        hdrMsg("Step-C50: Measure Traffic convergence without BFD by shutting dut1<---> dut4 port")
        ###########################################################################################
        # converged = convergence_measure(dut4,lag_name4,version="both",dest='d4')
        converged = convergence_measure(dut1, D1_ports_vrf[1:3], version="both", dest='d3vrf')
        st.log(" >>>>> Traffic Convergence with BFD for L3 LAG case: %s ms  <<<<<<" % converged_bfd)
        st.log(" >>>>> Traffic Convergence without BFD for L3 LAG case: %s ms <<<<<<" % converged)

        if converged_bfd is not False:
            if int(converged_bfd) > 1000 and int(bfd_rx) < 20 and int(bfd_tx) < 20 and int(multiplier) < 4:
                st.error("FAILED : Traffic convergence with BFD taking more time for L3 LAG case")
                ret_val = False
            else:
                st.log("PASSED : BFD-VRF Traffic convergence test passed for L3 LAG")
        else:
            st.error("FAILED : Traffic was not received by the destination STC port")
            ret_val = False
    return ret_val


def config_ebgp_mhop_over_l2lag():
    '''
    Module config on D1 D3 is configured with single hop ebgp , this API converts single hop ebgp sessions
    to multi hop ebgp sessions to test mhop bfd.

    :return:
    '''

    ############################################################################################
    hdrMsg(" Single hop ebgp sessions between D1 and D3 are changing to multi hop ebgp sessions on non default vrf ")
    ############################################################################################
    # data.shop2mhopconfig = True

    ############################################################################################
    hdrMsg(" Assigning local vars based on the vrf config either default or non default vrf ")
    ############################################################################################
    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, D1_port, D3_port, \
    lo_name, peer_v4, peer_v6, lag_name1, lag_name2, lag_name3, lag_name4, \
    dut1_lo_ip, dut3_lo_ip, dut4_lo_ip, dut1_lo_ipv6, dut3_lo_ipv6, dut4_lo_ipv6 = return_vars(user_vrf_name)

    if data.shopunconfig == False:
        utils.exec_all(True, [[bgp.config_router_bgp_mode, dut1, dut1_as, 'disable',user_vrf_name],
                          [bgp.config_router_bgp_mode, dut3, dut3_as, 'disable',user_vrf_name]])


    ############################################################################################
    hdrMsg("Step-C1: Adding static route for mhop bfd to come up")
    ############################################################################################
    for nbrindex in [0,2,3,4]:
        utils.exec_all(True, [
            [ip_api.create_static_route, dut1, dut3_lagip_list[nbrindex], '%s/%s' % (dut3_lo_ip, lo_mask), "vtysh", "ipv4",None,user_vrf_name],
            [ip_api.create_static_route, dut3, dut1_lagip_list[nbrindex], '%s/%s' % (dut1_lo_ip, lo_mask), "vtysh", "ipv4",None,user_vrf_name]])
        utils.exec_all(True, [
            [ip_api.create_static_route, dut1, dut3_lagipv6_list[nbrindex], '%s/%s' % (dut3_lo_ipv6, lo_v6mask), "vtysh",
             "ipv6",None,user_vrf_name],
            [ip_api.create_static_route, dut3, dut1_lagipv6_list[nbrindex], '%s/%s' % (dut1_lo_ipv6, lo_v6mask), "vtysh",
             "ipv6",None,user_vrf_name]])

    ############################################################################################
    hdrMsg("Step-C2: config BGP mhop in dut1 and dut3")
    ############################################################################################
    dict1 = {'vrf_name': user_vrf_name, 'neighbor': dut3_lo_ip, 'local_as': dut1_as, 'config': 'yes',
             'config_type_list': ['neighbor', 'update_src', 'ebgp_mhop', 'connect'],"connect":'1', 'update_src': dut1_lo_ip, 'ebgp_mhop': "2",
             'remote_as': dut3_as,'keepalive':keep_alive,'holdtime':hold_down}
    dict2 = {'vrf_name': user_vrf_name, 'neighbor': dut1_lo_ip, 'local_as': dut3_as, 'config': 'yes',
             'config_type_list': ['neighbor', 'update_src', 'ebgp_mhop', 'connect'],"connect":'1', 'update_src': dut3_lo_ip, 'ebgp_mhop': "2",
             'remote_as': dut1_as,'keepalive':keep_alive,'holdtime':hold_down}
    parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])

    dict1 = {'vrf_name': user_vrf_name, 'neighbor': dut3_lo_ipv6, 'local_as': dut1_as, 'config': 'yes',
             'config_type_list': ['neighbor', 'update_src', 'ebgp_mhop', 'connect'],"connect":'1', 'update_src': dut1_lo_ipv6, 'ebgp_mhop': "2",
             'remote_as': dut3_as,'keepalive':keep_alive,'holdtime':hold_down}
    dict2 = {'vrf_name': user_vrf_name, 'neighbor': dut1_lo_ipv6, 'local_as': dut3_as, 'config': 'yes',
             'config_type_list': ['neighbor', 'update_src', 'ebgp_mhop', 'connect'],"connect":'1', 'update_src': dut3_lo_ipv6, 'ebgp_mhop': "2",
             'remote_as': dut1_as,'keepalive':keep_alive,'holdtime':hold_down}
    parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])

    dict1 = {'vrf_name': user_vrf_name, "local_as": dut1_as, "config": 'yes', "config_type_list": ["redist"],
             "redistribute": 'connected', "addr_family": "ipv4"}
    dict2 = {'vrf_name': user_vrf_name, "local_as": dut3_as, "config": 'yes', "config_type_list": ["redist"],
             "redistribute": 'connected', "addr_family": "ipv4"}
    parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])

    dict1 = {'vrf_name': user_vrf_name, "local_as": dut1_as, "config": 'yes', "config_type_list": ["redist"],
             "redistribute": 'connected', "addr_family": "ipv6"}
    dict2 = {'vrf_name': user_vrf_name, "local_as": dut3_as, "config": 'yes', "config_type_list": ["redist"],
             "redistribute": 'connected', "addr_family": "ipv6"}
    parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])


def verify_bfd_lag6():
    '''

    :return:
    '''
    ret_val = True
    ############################################################################################
    hdrMsg(" Assigning local vars based on the vrf config either default or non default vrf ")
    ############################################################################################
    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, D1_port, D3_port, \
    lo_name, peer_v4, peer_v6, lag_name1, lag_name2, lag_name3, lag_name4, \
    dut1_lo_ip, dut3_lo_ip, dut4_lo_ip, dut1_lo_ipv6, dut3_lo_ipv6, dut4_lo_ipv6 = return_vars(user_vrf_name)

    for lag in [lag_name1, lag_name2]:
        result = pc.verify_portchannel_state(dut1, lag)
        if not result:
            st.error("L1 LAG b/w DUT1 and DUT1 did not come up, so aborting the script run")
            return False
        else:
            st.log("PASSED : dut1 L1 LAG interface %s has come up" % lag)

    if data.shop2mhopconfig == False:
        config_ebgp_mhop_over_l2lag()

    D1_tg1_mac = basic.get_ifconfig(dut1, D1_ports[3])[0]['mac']
    stream1_v4_1 = tg1.tg_traffic_config(mac_src=tg_dut1_mac, mac_dst=D1_tg1_mac, rate_pps=traffic_rate, \
                                       mode='create', port_handle=tg_handles[0], transmit_mode='continuous',
                                       l3_protocol='ipv4', ip_src_addr=tg_dut1_ip \
                                       , ip_dst_addr='30.30.30.1',ip_dst_mode='increment',ip_dst_count=200,
                                        mac_discovery_gw=dut1_tg_ip)
    stream1_v4_handle_1 = stream1_v4_1['stream_id']
    for nbrindex in [0, 2, 3, 4]:
        ip_api.create_static_route( dut1, dut3_lagip_list[nbrindex], '%s/%s' % (
        '30.30.30.0', 24), "vtysh", "ipv4", None, user_vrf_name)
    ip_api.create_static_route(dut3, tg_dut3_ip, '%s/%s' % (
        '30.30.30.0', 24), "vtysh", "ipv4", None, user_vrf_name)
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_handles[0])
    tg1.tg_traffic_control(action='run',stream_handle=stream1_v4_handle_1)
    st.wait(5)
    tg1.tg_traffic_control(action='stop', stream_handle=stream1_v4_handle_1)
    result = verify_traffic_hash(dut1,[lag_name1,lag_name2],10,D1_ports[3])
    if result is False:
        st.log("FAILED : Traffic distribution is failed")
        ret_val = False

    ############################################################################################
    hdrMsg("Step-C1: config BFD mhop in dut1 and dut4")
    ############################################################################################
    dict1 = {'vrf_name': user_vrf_name, 'local_asn': dut1_as, 'neighbor_ip': [dut3_lo_ip, dut3_lo_ipv6], 'config': "yes"}
    dict2 = {'vrf_name': user_vrf_name, 'local_asn': dut3_as, 'neighbor_ip': [dut1_lo_ip, dut1_lo_ipv6], 'config': "yes"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg("Step T2: Verify BGP and BFD sessions are UP")
    ###########################################################################################

    for nbr in [dut3_lo_ip, dut3_lo_ipv6]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                           retry_count=10, delay=3)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" % (
                dut3_lagip_list[0], dut3_lagipv6_list[0]))
            ret_val = False

    ###########################################################################################
    hdrMsg(
        "Step-T3: Verify ebgp multihop BFD session comes up for %s and %s in dut1 and also check BFD debug messages" % (
        dut3_lo_ip, dut3_lo_ipv6))
    ###########################################################################################
    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=[dut3_lo_ip, dut3_lo_ipv6],
                       local_addr=[dut1_lo_ip, dut1_lo_ipv6], status=['up', 'up'], multihop=["yes", "yes"],
                       retry_count=5, delay=2, peer_type=["dynamic", "dynamic"])
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lo_ip, dut3_lo_ipv6))
        ret_val = False
    basic.add_user_log_in_frr(dut1, "bfd.log")
    basic.debug_bfdconfig_using_frrlog(dut=dut1, config="yes", log_file_name="bfd.log")
    bfd.configure_bfd(dut=dut3, vrf_name=user_vrf_name,interface=lo_name, local_address=dut3_lo_ip, neighbor_ip=dut1_lo_ip, shutdown="yes", multihop="yes")
    bfd.configure_bfd(dut=dut3, vrf_name=user_vrf_name,interface=lo_name, local_address=dut3_lo_ipv6, neighbor_ip=dut1_lo_ipv6, shutdown="yes", multihop="yes")

    output = basic.return_user_log_from_frr(dut1, "bfd.log")
    bfd_v4_arlo_log = "BFD: state-change: [mhop:yes peer:%s local:%s] up -> down reason:neighbor-down" % (
    dut3_lo_ip, dut1_lo_ip)
    bfd_v6_arlo_log = "BFD: state-change: [mhop:yes peer:%s local:%s] up -> down reason:neighbor-down" % (
    dut3_lo_ipv6, dut1_lo_ipv6)
    bfd_v4_buzznik_log = "BFD: state-change: [mhop:yes peer:%s local:%s vrf:Vrf-101] up -> down reason:neighbor-down" % (
    dut3_lo_ip, dut1_lo_ip)
    bfd_v6_buzznik_log = "BFD: state-change: [mhop:yes peer:%s local:%s vrf:Vrf-101] up -> down reason:neighbor-down" % (
    dut3_lo_ipv6, dut1_lo_ipv6)
    if bfd_v4_buzznik_log not in output and bfd_v4_arlo_log not in output:
        st.log("FAILED : BFD log not generated for Multi hop BFD IPv4 session %s in dut 1" % dut3_lo_ip)
        ret_val = False
    elif bfd_v6_buzznik_log not in output and bfd_v6_arlo_log not in output:
        st.log("FAILED : BFD log not generated for Multi hop BFD IPv6 session %s in dut 1" % dut3_lo_ipv6)
        ret_val = False
    else:
        st.log("PASSED : DUT1 BFD log got generated for Multi hop BFD IPv4 session %s and Multi hop IPv6 session %s" % (
        dut3_lo_ip, dut1_lo_ipv6))

    basic.debug_bfdconfig_using_frrlog(dut=dut1, config="no", log_file_name="bfd.log")
    basic.remove_user_log_in_frr(dut1, "bfd.log")
    bfd.configure_bfd(dut=dut3, vrf_name=user_vrf_name, interface=lo_name, local_address=dut3_lo_ip, neighbor_ip=dut1_lo_ip,
                      noshut="yes", multihop="yes")
    bfd.configure_bfd(dut=dut3, vrf_name=user_vrf_name, interface=lo_name, local_address=dut3_lo_ipv6, neighbor_ip=dut1_lo_ipv6,
                      noshut="yes", multihop="yes")

    ###########################################################################################
    hdrMsg("Step T4: Trigger link failure by shtting down the physical interface on dut2")
    ###########################################################################################
    port.shutdown(dut3, flap_ports_vrf)
    ###########################################################################################
    hdrMsg("Step T5: Verify BGP session goes down immediately because of BFD down")
    ###########################################################################################
    for nbr in [dut3_lo_ip, dut3_lo_ipv6]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr,
                           bgpdownreason="BFD down received", retry_count=5, delay=1)
        if result is False:
            st.log("FAILED:BGP neighbor state is incorrect for %s" % nbr)
            ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=[dut3_lo_ip, dut3_lo_ipv6],
                       local_addr=[dut1_lo_ip, dut1_lo_ipv6], status=['up', 'up'], multihop=["yes", "yes"],
                       retry_count=5, delay=2, peer_type=["dynamic", "dynamic"])
    if result is True:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lo_ip, dut3_lo_ipv6))
        basic.get_techsupport(dut_list, 'test_bfd_lag_006_port_flap')
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T6: Bring up the interface back and verify BGP and BFD sessions are UP again")
    ###########################################################################################
    port.noshutdown(dut3, flap_ports_vrf)

    for nbr in [dut3_lo_ip, dut3_lo_ipv6]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                           retry_count=10, delay=3)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" % (
                dut3_lagip_list[0], dut3_lagipv6_list[0]))
            ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=[dut3_lo_ip, dut3_lo_ipv6],
                       local_addr=[dut1_lo_ip, dut1_lo_ipv6], status=['up', 'up'], multihop=["yes", "yes"],
                       retry_count=5, delay=2, peer_type=["dynamic", "dynamic"])
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lo_ip, dut3_lo_ipv6))
        ret_val = False

    converged = convergence_measure(dut1, D1_ports[0], version="both", dest='d3vrf')
    st.log(" >>>>> Traffic Convergence with BFD for L3 LAG case: %s ms  <<<<<<" % converged)

    ###########################################################################################
    hdrMsg("Step T7: Bring up the ebgp mhop bfd on interface by unconfig lag_name1_vrf ")
    ###########################################################################################
    port.shutdown(dut1, [lag_name2])
    utils.exec_all(True, [[pc.delete_portchannel_member, dut1, lag_name1, [D1_ports[0]]],
                          [pc.delete_portchannel_member, dut3, lag_name1, [D3_ports[0]]]])

    utils.exec_all(True, [[ip_api.delete_ip_interface, dut1, access_vlan_name, dut1_lagip_list[0], ip_mask],
                          [ip_api.delete_ip_interface, dut3, access_vlan_name, dut3_lagip_list[0], ip_mask]])

    utils.exec_all(True, [[ip_api.delete_ip_interface, dut1, access_vlan_name, dut1_lagipv6_list[0], ipv6_mask, "ipv6"],
                          [ip_api.delete_ip_interface, dut3, access_vlan_name, dut3_lagipv6_list[0], ipv6_mask,
                           "ipv6"]])

    dict1 = {'vrf_name': user_vrf_name, 'intf_name': D1_ports[0], 'skip_error': True}
    dict2 = {'vrf_name': user_vrf_name, 'intf_name': D3_ports[0], 'skip_error': True}
    parallel.exec_parallel(True, [dut1, dut3], vrf_api.bind_vrf_interface, [dict1, dict2])

    utils.exec_all(True,
                   [[ip_api.config_ip_addr_interface, dut1, D1_ports[0], dut1_lagip_list[0], ip_mask, "ipv4"],
                    [ip_api.config_ip_addr_interface, dut3, D3_ports[0], dut3_lagip_list[0], ip_mask, "ipv4"]])
    utils.exec_all(True,
                   [[ip_api.config_ip_addr_interface, dut1, D1_ports[0], dut1_lagipv6_list[0], ipv6_mask, "ipv6"],
                    [ip_api.config_ip_addr_interface, dut3, D3_ports[0], dut3_lagipv6_list[0], ipv6_mask, "ipv6"]])

    ###########################################################################################
    hdrMsg("Step T8: Verify BGP and BFD sessions are UP")
    ###########################################################################################

    for nbr in [dut3_lo_ip, dut3_lo_ipv6]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                           retry_count=10, delay=3)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" % (
                dut3_lagip_list[0], dut3_lagipv6_list[0]))
            ret_val = False

    ###########################################################################################
    hdrMsg(
        "Step-C9: Verify ebgp multihop BFD session comes up for %s and %s in dut1 and also check BFD debug messages" % (
        dut3_lo_ip, dut3_lo_ipv6))
    ###########################################################################################
    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=[dut3_lo_ip, dut3_lo_ipv6],
                       local_addr=[dut1_lo_ip, dut1_lo_ipv6], status=['up', 'up'], multihop=["yes", "yes"],
                       retry_count=5, delay=2, peer_type=["dynamic", "dynamic"])
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lo_ip, dut3_lo_ipv6))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T10: Trigger link failure by shtting down the physical interface on dut2")
    ###########################################################################################
    port.shutdown(dut3, [flap_ports_vrf[0]])
    ###########################################################################################
    hdrMsg("Step T9: Verify BGP session goes down immediately because of BFD down")
    ###########################################################################################
    for nbr in [dut3_lo_ip, dut3_lo_ipv6]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr,
                           bgpdownreason="BFD down received", retry_count=2, delay=1)
        if result is False:
            st.log("FAILED:BGP neighbor state is incorrect for %s" % nbr)
            ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=[dut3_lo_ip, dut3_lo_ipv6],
                       local_addr=[dut1_lo_ip, dut1_lo_ipv6], status=['up', 'up'], multihop=["yes", "yes"],
                       retry_count=5, delay=2, peer_type=["dynamic", "dynamic"])
    if result is True:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lo_ip, dut3_lo_ipv6))
        ret_val = False

    ###########################################################################################
    hdrMsg("Step T11: Bring up the interface back and verify BGP and BFD sessions are UP again")
    ###########################################################################################
    port.noshutdown(dut3, [flap_ports_vrf[0]])

    for nbr in [dut3_lo_ip, dut3_lo_ipv6]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                           retry_count=10, delay=3)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" % (
                dut3_lagip_list[0], dut3_lagipv6_list[0]))
            ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=[dut3_lo_ip, dut3_lo_ipv6],
                       local_addr=[dut1_lo_ip, dut1_lo_ipv6], status=['up', 'up'], multihop=["yes", "yes"],
                       retry_count=5, delay=2, peer_type=["dynamic", "dynamic"])
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lo_ip, dut3_lo_ipv6))
        ret_val = False

    bfd.configure_bfd(dut=dut3, vrf_name=user_vrf_name, interface=lo_name, local_address=dut3_lo_ip,
                      neighbor_ip=dut1_lo_ip, shutdown="yes", multihop="yes")
    bfd.configure_bfd(dut=dut3, vrf_name=user_vrf_name, interface=lo_name, local_address=dut3_lo_ipv6,
                      neighbor_ip=dut1_lo_ipv6, shutdown="yes", multihop="yes")
    ###########################################################################################
    hdrMsg("Step T12: Verify BGP up and BFD sessions are down")
    ###########################################################################################

    for nbr in [dut3_lo_ip, dut3_lo_ipv6]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                           retry_count=10, delay=3)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" % (
                dut3_lagip_list[0], dut3_lagipv6_list[0]))
            ret_val = False

    ###########################################################################################
    hdrMsg(
        "Step-T13: Verify ebgp multihop BFD session goes down for %s and %s in dut1 and also check BFD debug messages" % (
            dut3_lo_ip, dut3_lo_ipv6))
    ###########################################################################################
    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=[dut3_lo_ip, dut3_lo_ipv6],
                       local_addr=[dut1_lo_ip, dut1_lo_ipv6], status=['down', 'down'], multihop=["yes", "yes"],
                       retry_count=5, delay=2, peer_type=["dynamic", "dynamic"])
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lo_ip, dut3_lo_ipv6))
        ret_val = False

    bfd.configure_bfd(dut=dut3, vrf_name=user_vrf_name, interface=lo_name, local_address=dut3_lo_ip,
                      neighbor_ip=dut1_lo_ip,
                      noshut="yes", multihop="yes")
    bfd.configure_bfd(dut=dut3, vrf_name=user_vrf_name, interface=lo_name, local_address=dut3_lo_ipv6,
                      neighbor_ip=dut1_lo_ipv6,
                      noshut="yes", multihop="yes")
    ###########################################################################################
    hdrMsg("Step T14: Verify BGP and BFD sessions are UP")
    ###########################################################################################

    for nbr in [dut3_lo_ip, dut3_lo_ipv6]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                           retry_count=10, delay=3)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" % (
                dut3_lagip_list[0], dut3_lagipv6_list[0]))
            ret_val = False

    ###########################################################################################
    hdrMsg(
        "Step-C15: Verify ebgp multihop BFD session comes up for %s and %s in dut1 and also check BFD debug messages" % (
            dut3_lo_ip, dut3_lo_ipv6))
    ###########################################################################################
    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=[dut3_lo_ip, dut3_lo_ipv6],
                       local_addr=[dut1_lo_ip, dut1_lo_ipv6], status=['up', 'up'], multihop=["yes", "yes"],
                       retry_count=5, delay=2, peer_type=["dynamic", "dynamic"])
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lo_ip, dut3_lo_ipv6))
        ret_val = False

    port.noshutdown(dut1, [lag_name2])
    converged = convergence_measure(dut1, D1_ports[0], version="both", dest='d3vrf')
    st.log(" >>>>> Traffic Convergence with BFD for L3 LAG case: %s ms  <<<<<<" % converged)
    ###########################################################################################
    hdrMsg("Step T16: Reconfig and bring up the ebgp mhop bfd on lag_name1_vrf ")
    ###########################################################################################
    utils.exec_all(True,
                   [[ip_api.delete_ip_interface, dut1, D1_ports[0], dut1_lagip_list[0], ip_mask, "ipv4"],
                    [ip_api.delete_ip_interface, dut3, D3_ports[0], dut3_lagip_list[0], ip_mask, "ipv4"]])
    utils.exec_all(True,
                   [[ip_api.delete_ip_interface, dut1, D1_ports[0], dut1_lagipv6_list[0], ipv6_mask, "ipv6"],
                    [ip_api.delete_ip_interface, dut3, D3_ports[0], dut3_lagipv6_list[0], ipv6_mask, "ipv6"]])

    dict1 = {'vrf_name': user_vrf_name, 'intf_name': D1_ports[0], 'skip_error': True, 'config': 'no'}
    dict2 = {'vrf_name': user_vrf_name, 'intf_name': D3_ports[0], 'skip_error': True, 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut3], vrf_api.bind_vrf_interface, [dict1, dict2])

    utils.exec_all(True, [[pc.add_portchannel_member, dut1, lag_name1, [D1_ports[0]]],
                          [pc.add_portchannel_member, dut3, lag_name1, [D3_ports[0]]]])

    utils.exec_all(True, [[ip_api.config_ip_addr_interface, dut1, access_vlan_name, dut1_lagip_list[0], ip_mask],
                          [ip_api.config_ip_addr_interface, dut3, access_vlan_name, dut3_lagip_list[0], ip_mask]])

    utils.exec_all(True, [[ip_api.config_ip_addr_interface, dut1, access_vlan_name, dut1_lagipv6_list[0], ipv6_mask, "ipv6"],
                          [ip_api.config_ip_addr_interface, dut3, access_vlan_name, dut3_lagipv6_list[0], ipv6_mask,
                           "ipv6"]])
    return ret_val


def verify_bfd_lag7():
    '''
    This function verifies config reload clear bgp fast reboot and bgp conatiner restart
    :return:
    '''
    ret_val =  True
    ############################################################################################
    hdrMsg(" Assigning local vars based on the vrf config either default or non default vrf ")
    ############################################################################################
    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, D1_port, D3_port, \
    lo_name, peer_v4, peer_v6, lag_name1, lag_name2, lag_name3, lag_name4, \
    dut1_lo_ip, dut3_lo_ip, dut4_lo_ip, dut1_lo_ipv6, dut3_lo_ipv6, dut4_lo_ipv6 = return_vars(user_vrf_name)

    for lag in [lag_name1, lag_name2]:
        result = pc.verify_portchannel_state(dut1, lag)
        if not result:
            st.error("Failed: L1 LAG b/w DUT1 and DUT1 did not come up, so aborting the script run")
            return False
        else:
            st.log("PASSED : dut1 L1 LAG interface %s has come up" % lag)

    if data.shop2mhopconfig == False:
        config_ebgp_mhop_over_l2lag()

    ############################################################################################
    hdrMsg("Step-C1: config BFD mhop in dut1 and dut4")
    ############################################################################################
    dict1 = {'vrf_name': user_vrf_name, 'local_asn': dut1_as, 'neighbor_ip': [dut3_lo_ip, dut3_lo_ipv6],
             'config': "yes"}
    dict2 = {'vrf_name': user_vrf_name, 'local_asn': dut3_as, 'neighbor_ip': [dut1_lo_ip, dut1_lo_ipv6],
             'config': "yes"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg("Step T1: Verify BGP and BFD sessions are UP")
    ###########################################################################################

    for nbr in [dut3_lo_ip, dut3_lo_ipv6]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                           retry_count=10, delay=3)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" % (
                dut3_lagip_list[0], dut3_lagipv6_list[0]))
            ret_val = False
            return False
    debug_bfd_ping(user_vrf_name)
    for testreloads in ['config_reload', 'clear_bgp', None]:
        ###########################################################################################
        hdrMsg(
            "Step-T2: Verify ebgp multihop BFD session comes up for %s and %s in dut1 and also check BFD debug messages" % (
            dut3_lo_ip, dut3_lo_ipv6))
        ###########################################################################################
        result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=[dut3_lo_ip, dut3_lo_ipv6],
                           local_addr=[dut1_lo_ip, dut1_lo_ipv6], status=['up', 'up'], multihop=["yes", "yes"],
                           retry_count=10, delay=3, peer_type=["dynamic", "dynamic"])
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lo_ip, dut3_lo_ipv6))
            ret_val = False

        ###########################################################################################
        hdrMsg("Step T3: Verify BGP and BFD sessions are UP")
        ###########################################################################################

        for nbr in [dut3_lo_ip, dut3_lo_ipv6]:
            result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                               retry_count=10, delay=3)
            if result is False:
                st.log("FAILED : BFD session parameters mismatch for %s and %s" % (
                    dut3_lagip_list[0], dut3_lagipv6_list[0]))
                ret_val = False
        if ret_val == False:
            break
        if testreloads == 'config_reload':
            bgp.enable_docker_routing_config_mode(dut1)
            reboot_api.config_save(dut1)
            reboot_api.config_save(dut1, shell='vtysh')
            #st.reboot(dut1)

        if testreloads == 'config_reload':
            ###########################################################################################
            hdrMsg("Step RT1: Config reload scenario started")
            ###########################################################################################
            st.log('######------Config reload with BFD-VRF------######')
            st.log("Config reload the DUT")
            reboot_api.config_save_reload(vars.D1)
        elif testreloads == 'clear_bgp':
            ###########################################################################################
            hdrMsg("Step RT2: clear bgp scenario started")
            ###########################################################################################
            bgp.clear_ip_bgp_vtysh(dut1)
            st.log("clear ipv4 bgp neighbors")
            bgp.clear_ip_bgp_vrf_vtysh(dut1, user_vrf_name)
            st.log("clear ipv6 bgp neighbors")
            bgp.clear_ip_bgp_vrf_vtysh(dut1, user_vrf_name, family='ipv6')
    if ret_val == False:
        debug_bfd_ping(user_vrf_name)
    return ret_val


def debug_bfd_ping(vrfname='default'):
    '''
    This API issues show running config and ping
    :param vrfname:
    :return:
    '''
    st.log("Dubug commands starts")
    runn_config = [[get_running_config, dutindex] for dutindex in [dut1,dut3,dut4]]
    utils.exec_all(True, runn_config)

    for family in ['ipv4', 'ipv6']:
        dict1 = {'family': family, 'vrf_name': vrfname}
        parallel.exec_parallel(True, [dut1, dut3], ip_api.show_ip_route, [dict1, dict1])

    if vrfname != 'default':
        ip_api.ping(dut1, dut3_lo_ip_vrf, 'ipv4', interface=user_vrf_name)
        ip_api.ping(dut1, dut3_lo_ipv6_vrf, 'ipv6', interface=user_vrf_name)
        for ipindex in [0,2,3,4]:
            ip_api.ping(dut1, dut3_lagip_list[ipindex], 'ipv4', interface=user_vrf_name)
            ip_api.ping(dut1, dut3_lagipv6_list[ipindex], 'ipv6', interface=user_vrf_name)
    else:
        ip_api.ping(dut1, dut3_lo_ip, 'ipv4')
        ip_api.ping(dut1, dut3_lo_ipv6, 'ipv6')
        for ipindex in [0,2,3,4]:
            ip_api.ping(dut1, dut3_lagip_list[ipindex], 'ipv4')
            ip_api.ping(dut1, dut3_lagipv6_list[ipindex], 'ipv6')
    st.log(" End of Dubug commands")


def verify_bfd_lag9(args):
    '''
    This function verifies bgp container restart,warm rebbot and cold restart based on args
    :return:
    '''
    ret_val =  True
    ############################################################################################
    hdrMsg(" Assigning local vars based on the vrf config either default or non default vrf ")
    ############################################################################################
    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, D1_port, D3_port, \
    lo_name, peer_v4, peer_v6, lag_name1, lag_name2, lag_name3, lag_name4, \
    dut1_lo_ip, dut3_lo_ip, dut4_lo_ip, dut1_lo_ipv6, dut3_lo_ipv6, dut4_lo_ipv6 = return_vars(user_vrf_name)

    for lag in [lag_name1, lag_name2]:
        result = pc.verify_portchannel_state(dut1, lag)
        if not result:
            st.error("Failed: L1 LAG b/w DUT1 and DUT1 did not come up, so aborting the script run")
            return False
        else:
            st.log("PASSED : dut1 L1 LAG interface %s has come up" % lag)

    data.shopunconfig = False
    config_ebgp_mhop_over_l2lag()

    ############################################################################################
    hdrMsg("Step-C1: config BFD mhop in dut1 and dut4")
    ############################################################################################
    dict1 = {'vrf_name': user_vrf_name, 'local_asn': dut1_as, 'neighbor_ip': [dut3_lo_ip, dut3_lo_ipv6],
             'config': "yes"}
    dict2 = {'vrf_name': user_vrf_name, 'local_asn': dut3_as, 'neighbor_ip': [dut1_lo_ip, dut1_lo_ipv6],
             'config': "yes"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg("Step T1: Verify BGP and BFD sessions are UP")
    ###########################################################################################

    for nbr in [dut3_lo_ip, dut3_lo_ipv6]:
        result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                           retry_count=10, delay=3)
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" % (
                dut3_lagip_list[0], dut3_lagipv6_list[0]))
            ret_val = False
            return False
    reboot_api.config_save(dut1)
    reboot_api.config_save(dut1, shell='vtysh')
    #debug_bfd_ping(user_vrf_name)
    for testreloads in [args, None]:
        if not testreloads: st.wait(60)
        ###########################################################################################
        hdrMsg(
            "Step-T2: Verify ebgp multihop BFD session comes up for %s and %s in dut1 and also check BFD debug messages" % (
            dut3_lo_ip, dut3_lo_ipv6))
        ###########################################################################################
        result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=[dut3_lo_ip, dut3_lo_ipv6],
                           local_addr=[dut1_lo_ip, dut1_lo_ipv6], status=['up', 'up'], multihop=["yes", "yes"],
                           retry_count=10, delay=3, peer_type=["dynamic", "dynamic"])
        if result is False:
            st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lo_ip, dut3_lo_ipv6))
            ret_val = False

        ###########################################################################################
        hdrMsg("Step T3: Verify BGP and BFD sessions are UP")
        ###########################################################################################

        for nbr in [dut3_lo_ip, dut3_lo_ipv6]:
            result = retry_api(ip_bgp.verify_bgp_neighbor, dut1, vrf=user_vrf_name, neighborip=nbr, state='Established',
                               retry_count=10, delay=3)
            if result is False:
                st.log("FAILED : BFD session parameters mismatch for %s and %s" % (
                    dut3_lagip_list[0], dut3_lagipv6_list[0]))
                ret_val = False
        if testreloads == 'container_restart':
            ###########################################################################################
            hdrMsg("Step RT1: Stop and Start the BGP container")
            ###########################################################################################
            basic.service_operations_by_systemctl(dut1, 'bgp', 'restart')
        if testreloads == 'warm_reboot':
            ###########################################################################################
            hdrMsg("Step RT1: Performing warm reboot")
            ###########################################################################################
            st.reboot(dut1, "warm")
        if testreloads == 'cold_restart':
            ###########################################################################################
            hdrMsg("Step RT1: Performing cold restart")
            ###########################################################################################
            st.log("About to power off power to switch")
            st.do_rps(vars.D1, "Off")
            st.log("About to Power ON switch")
            st.do_rps(vars.D1, "On")
        if testreloads == 'save_and_reload':
            ###########################################################################################
            hdrMsg("Step RT1: Perform save and relaod with BFD VRF")
            ###########################################################################################
            st.reboot(dut1)
        if testreloads == 'fast_reboot':
            ###########################################################################################
            hdrMsg("Step RT1: fast reboot scenario started")
            ###########################################################################################
            st.reboot(dut1, 'fast')
    if ret_val == False:
        debug_bfd_ping(user_vrf_name)
    return ret_val


def verify_bfd_lag11():
    '''
    Verify ipv6 BGP unnumbered with bfd vrf
    :return:
    '''
    ret_val = True
    ############################################################################################
    hdrMsg(" Assigning local vars based on the vrf config either default or non default vrf ")
    ############################################################################################
    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, D1_port, D3_port, \
    lo_name, peer_v4, peer_v6, lag_name1, lag_name2, lag_name3, lag_name4, \
    dut1_lo_ip, dut3_lo_ip, dut4_lo_ip, dut1_lo_ipv6, dut3_lo_ipv6, dut4_lo_ipv6 = return_vars(user_vrf_name)

    ret_val = True
    utils.exec_all(True, [[bgp.config_router_bgp_mode, dut1, dut1_as, 'disable',user_vrf_name],
                          [bgp.config_router_bgp_mode, dut3, dut3_as, 'disable',user_vrf_name]])


    ############################################################################################
    hdrMsg("Step-T1: Remove ip address %s on dut1 and %s on dut3 for vlan %s"\
           % (dut1_lagip_list[0],dut3_lagip_list[0], access_vlan))
    ############################################################################################
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,access_vlan_name,dut1_lagip_list[0],ip_mask], [ip_api.delete_ip_interface,dut3,access_vlan_name,dut3_lagip_list[0],ip_mask] ])

    ############################################################################################
    hdrMsg("Step-T2: Remove ip address %s on dut1 and %s on dut3 for vlans %s" \
           % (dut1_lagip_list[2:5],dut3_lagip_list[2:5],trunk_vlan))
    ############################################################################################
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,trunk_vlan_name[0],dut1_lagip_list[2],ip_mask], [ip_api.delete_ip_interface,dut3,trunk_vlan_name[0],dut3_lagip_list[2],ip_mask] ])
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,trunk_vlan_name[1],dut1_lagip_list[3],ip_mask], [ip_api.delete_ip_interface,dut3,trunk_vlan_name[1],dut3_lagip_list[3],ip_mask] ])
    utils.exec_all(True, [[ip_api.delete_ip_interface,dut1,trunk_vlan_name[2],dut1_lagip_list[4],ip_mask], [ip_api.delete_ip_interface,dut3,trunk_vlan_name[2],dut3_lagip_list[4],ip_mask] ])

    ############################################################################################
    hdrMsg("Step-T3: Remove ipv6 address %s on dut1 and %s on dut3 for vlan %s" \
           % (dut1_lagipv6_list[0], dut3_lagipv6_list[0], access_vlan))
    ############################################################################################
    utils.exec_all(True, [[ip_api.delete_ip_interface, dut1, access_vlan_name, dut1_lagipv6_list[0], ipv6_mask, "ipv6"],
                          [ip_api.delete_ip_interface, dut3, access_vlan_name, dut3_lagipv6_list[0], ipv6_mask,
                           "ipv6"]])

    ############################################################################################
    hdrMsg("Step-T4: Remove ipv6 address %s on dut1 and %s on dut3 for vlans %s" \
           % (dut1_lagipv6_list[2:5], dut3_lagipv6_list[2:5], trunk_vlan))
    ############################################################################################
    utils.exec_all(True,
                   [[ip_api.delete_ip_interface, dut1, trunk_vlan_name[0], dut1_lagipv6_list[2], ipv6_mask, "ipv6"],
                   [ip_api.delete_ip_interface, dut3, trunk_vlan_name[0], dut3_lagipv6_list[2], ipv6_mask, "ipv6"]])
    utils.exec_all(True,
                   [[ip_api.delete_ip_interface, dut1, trunk_vlan_name[1], dut1_lagipv6_list[3], ipv6_mask, "ipv6"],
                    [ip_api.delete_ip_interface, dut3, trunk_vlan_name[1], dut3_lagipv6_list[3], ipv6_mask, "ipv6"]])
    utils.exec_all(True,
                   [[ip_api.delete_ip_interface, dut1, trunk_vlan_name[2], dut1_lagipv6_list[4], ipv6_mask, "ipv6"],
                    [ip_api.delete_ip_interface, dut3, trunk_vlan_name[2], dut3_lagipv6_list[4], ipv6_mask, "ipv6"]])

    utils.exec_all(True, [[ip_api.config_interface_ip6_link_local, dut1, access_vlan_name],
                          [ip_api.config_interface_ip6_link_local, dut3, access_vlan_name]])

    # Get DUT link local addresses
    rt_link_local_addr = utils.exec_all(True, [[ip_api.get_link_local_addresses, vars.D1, access_vlan_name],
                                                     [ip_api.get_link_local_addresses, vars.D2, access_vlan_name]])

    d1_prt_link_local = rt_link_local_addr[0][0]
    d2_prt_link_local = rt_link_local_addr[0][1]
    dict1 = {'vrf_name': user_vrf_name, 'addr_family': 'ipv6', 'local_as': dut1_as,
             'remote_as': 'external', 'config_type_list': ["remote-as", "activate",'connect','bfd'],"connect":'1', 'interface': access_vlan_name,
             'neighbor': access_vlan_name}
    dict2 = {'vrf_name': user_vrf_name, 'addr_family': 'ipv6', 'local_as': dut3_as,
             'remote_as': 'external', 'config_type_list': ["remote-as", "activate",'connect','bfd'],"connect":'1', 'interface': access_vlan_name,
             'neighbor': access_vlan_name}
    parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])

    if not utils.poll_wait(bgp.verify_bgp_summary, 20, dut1, family='ipv6', vrf=user_vrf_name, neighbor=access_vlan_name, state='Established'):
        st.log("Failed to form BGP unnumbered peering using IPv6 link local on a VLAN")
        ret_val = False

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=d2_prt_link_local, local_addr=d1_prt_link_local,
                       interface=access_vlan_name, status='up', retry_count=2, delay=1)
    if result is False:
        st.log('Failed: bfd_fail_reason BFD session did not come up over ipv6 bgp unnumberd address')
        ret_val = False

    dict1 = {'vrf_name': user_vrf_name, "local_as": dut1_as, "config": 'yes', "config_type_list": ["redist"],
             "redistribute": 'connected', "addr_family": "ipv6"}
    dict2 = {'vrf_name': user_vrf_name, "local_as": dut3_as, "config": 'yes', "config_type_list": ["redist"],
             "redistribute": 'connected', "addr_family": "ipv6"}
    parallel.exec_parallel(True, [dut1, dut3], bgp.config_bgp, [dict1, dict2])

    dict1 = {'vrf_name': user_vrf_name, 'interface': lo_name, 'local_address': dut1_lo_ipv6,
             'neighbor_ip': dut3_lo_ipv6, 'multihop': "yes", 'noshut': "yes"}
    dict2 = {'vrf_name': user_vrf_name, 'interface': lo_name, 'local_address': dut3_lo_ipv6,
             'neighbor_ip': dut1_lo_ipv6, 'multihop': "yes", 'noshut': "yes"}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    result = retry_api(bfd.verify_bfd_peer, dut1, vrf_name=user_vrf_name, peer=dut3_lo_ipv6,
                       local_addr=dut1_lo_ipv6, status='up', multihop="yes",
                       retry_count=10, delay=3, peer_type="configured", interface=lo_name)
    if result is False:
        st.log("FAILED : BFD session parameters mismatch for %s and %s" % (dut3_lo_ip, dut3_lo_ipv6))
        ret_val = False

    return ret_val


def verify_traffic_hash(dut, port_list, pkts_per_port,tx_port):
    ret_val = True
    int_cntr_1 = intf_obj.show_interface_counters_all(dut)
    intf_count_dict = {}
    for port in port_list:
        for counter_dict in int_cntr_1:
            if counter_dict['iface'] == port:
                try:
                    intf_count_dict[port] = int(counter_dict['tx_ok'].replace(',',''))
                except:
                    st.log('Failed: invalid_traffic_stats')
                    ret_val = False
                if not (intf_count_dict[port] >= pkts_per_port):
                    intf_obj.show_interface_counters_detailed(dut, tx_port)
                    st.log("Failed: traffic_not_hashed on DUT {}".format(dut))
                    ret_val = False
    return ret_val


def verify_bfd_lag12(vrfname='default'):
    '''

    :param vrfname:
    :return:
    '''
    ############################################################################################
    hdrMsg(" Assigning local vars based on the vrf config either default or non default vrf ")
    ############################################################################################
    access_vlan, access_vlan_name, trunk_vlan, trunk_vlan_name, D1_ports, D3_ports, tg_handles, D1_port, D3_port, \
    lo_name, peer_v4, peer_v6, lag_name1, lag_name2, lag_name3, lag_name4, \
    dut1_lo_ip, dut3_lo_ip, dut4_lo_ip, dut1_lo_ipv6, dut3_lo_ipv6, dut4_lo_ipv6 = return_vars(vrfname)

    bfd_nbrs_dut1 = [dut3_lagip_list[0]];
    non_bfd_nbrs_dut1 = dut3_lagip_list[2:]
    bfd_nbrs_dut3 = [dut1_lagip_list[0]];
    non_bfd_nbrs_dut3 = dut1_lagip_list[2:]
    addr_family = 'ipv4';
    mask = ip_mask;
    tg_dest = tg_dest_nw;
    ipv6_bfd_nbrs_dut1 = [dut3_lagipv6_list[0]];
    ipv6_non_bfd_nbrs_dut1 = dut3_lagipv6_list[2:]
    ipv6_bfd_nbrs_dut3 = [dut1_lagipv6_list[0]];
    ipv6_non_bfd_nbrs_dut3 = dut1_lagipv6_list[2:]
    ipv6_addr_family = 'ipv6';
    ipv6_tg_dest = tg_dest_nw_v6;
    intf_list = [access_vlan_name]
    non_bfd_intf_list = trunk_vlan_name

    ret_val = True
    ###########################################################################################
    hdrMsg("Step-C1: Enable BFD for BGP neighbor %s on dut1 and %s on dut3" % (bfd_nbrs_dut1, bfd_nbrs_dut3))
    ###########################################################################################
    dict1 = {'vrf_name': vrfname, 'local_asn': dut1_as, 'neighbor_ip': bfd_nbrs_dut1[0], 'config': "yes",
             'cli_type': 'klish'}
    dict2 = {'vrf_name': vrfname, 'local_asn': dut3_as, 'neighbor_ip': bfd_nbrs_dut3[0], 'config': "yes",
             'cli_type': 'klish'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict1 = {'vrf_name': vrfname, 'interface': access_vlan_name, 'neighbor_ip': bfd_nbrs_dut1[0], 'config': "yes",
             'multiplier': multiplier1, 'rx_intv': bfd_rx1, 'tx_intv': bfd_tx1, 'cli_type': 'klish'}
    dict2 = {'vrf_name': vrfname, 'interface': access_vlan_name, 'neighbor_ip': bfd_nbrs_dut3[0], 'config': "yes",
             'multiplier': multiplier2, 'rx_intv': bfd_rx2, 'tx_intv': bfd_tx2, 'cli_type': 'klish'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict11 = bfd.verify_bfd_peer(dut1, peer=[bfd_nbrs_dut1[0], bfd_nbrs_dut1[0]], return_dict="", cli_type='klish')
    dict33 = bfd.verify_bfd_peer(dut3, peer=[bfd_nbrs_dut3[0], bfd_nbrs_dut3[0]], return_dict="", cli_type='klish')
    ###########################################################################################
    hdrMsg("Step-C13: Verify BFD mhop peer %s local id in dut1 if same remote id in dut3" % dut3_lo_ip)
    ###########################################################################################

    if len(dict11) != 0:
        for dict1 in dict11:
            if dict1['peer'] == bfd_nbrs_dut1[0]:
                if dict1['status'] == 'up' and dict1['multiplier'] == ['3', '3'] and \
                        dict1['interface'] == access_vlan_name:
                    st.log("PASSED : BFD shop peer local id in dut1 is same dut3 remote id %s" % dict1['local_id'])
                else:
                    st.log("FAILED : BFD shop peer status is not %s and dut1 is interface %s not correct" % (
                    dict1['status'], dict1['interface']))
                    ret_val = False
    else:
        st.log("FAILED : BFD shop peers not updated ")
        ret_val = False

    dict1 = {'vrf_name': vrfname, 'local_asn': dut1_as, 'neighbor_ip': bfd_nbrs_dut1[0], 'config': "no",
             'cli_type': 'klish'}
    dict2 = {'vrf_name': vrfname, 'local_asn': dut3_as, 'neighbor_ip': bfd_nbrs_dut3[0], 'config': "no",
             'cli_type': 'klish'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    dict1 = {'vrf_name': vrfname, 'interface': access_vlan_name, 'neighbor_ip': bfd_nbrs_dut1[0], 'config': "no",
             'cli_type': 'klish'}
    dict2 = {'vrf_name': vrfname, 'interface': access_vlan_name, 'neighbor_ip': bfd_nbrs_dut3[0], 'config': "no",
             'cli_type': 'klish'}
    parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    ###########################################################################################
    hdrMsg("Step-C5: Enable BFD for BGP neighbor %s on dut1 and %s in dut3" % (dut3_lo_ip, dut1_lo_ip))
    ###########################################################################################
    if vrfname == user_vrf_name:
        dict1 = {'vrf_name': vrfname, 'interface': lo_name, 'local_address': dut1_lo_ip, 'neighbor_ip': dut3_lo_ip,
                 'multihop': "yes", 'noshut': "yes", 'cli_type': 'klish'}
        dict2 = {'vrf_name': vrfname, 'interface': lo_name, 'local_address': dut3_lo_ip, 'neighbor_ip': dut1_lo_ip,
                 'multihop': "yes", 'noshut': "yes", 'cli_type': 'klish'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    else:
        dict1 = {'vrf_name': vrfname, 'local_address': dut1_lo_ip, 'neighbor_ip': dut3_lo_ip, 'multihop': "yes",
                 'noshut': "yes", 'cli_type': 'klish'}
        dict2 = {'vrf_name': vrfname, 'local_address': dut3_lo_ip, 'neighbor_ip': dut1_lo_ip, 'multihop': "yes",
                 'noshut': "yes", 'cli_type': 'klish'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    dict11 = bfd.verify_bfd_peer(dut1, peer=[dut3_lo_ip, dut3_lo_ip], return_dict="", cli_type='klish')
    dict33 = bfd.verify_bfd_peer(dut3, peer=[dut1_lo_ip, dut1_lo_ip], return_dict="", cli_type='klish')

    ###########################################################################################
    hdrMsg("Step-C13: Verify BFD mhop peer %s local id in dut1 if same remote id in dut3" % dut3_lo_ip)
    ###########################################################################################
    if len(dict11) != 0:
        for dict1 in dict11:
            if dict1['peer'] == dut3_lo_ip:
                if dict1['status'] == 'up' and dict1['local_addr'] == dut1_lo_ip and \
                        dict1['peer'] == dut3_lo_ip and dict1['interface'] == lo_name:
                    st.log("PASSED : BFD mhop peer local id in dut1 is same dut3 remote id %s" % dict1['local_id'])
                else:
                    st.log("FAILED : BFD mhop peer status %s and dut1 is interface %s not correct" % (
                    dict1['status'], dict1['interface']))
                    ret_val = False
    else:
        st.log("FAILED : BFD mhop peers not updated ")
        ret_val = False

    ############################################################################################
    hdrMsg("Step-C48: Remove BFD neighbors %s on dut3 and %s on dut1" % (dut1_lo_ip, dut3_lo_ip))
    ############################################################################################
    if vrfname == user_vrf_name:
        dict1 = {'vrf_name': vrfname, 'interface': lo_name, 'local_address': dut1_lo_ip, 'neighbor_ip': dut3_lo_ip,
                 'multihop': "yes", 'config': "no", 'cli_type': 'klish'}
        dict2 = {'vrf_name': vrfname, 'interface': lo_name, 'local_address': dut3_lo_ip, 'neighbor_ip': dut1_lo_ip,
                 'multihop': "yes", 'config': "no", 'cli_type': 'klish'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])
    else:
        dict1 = {'vrf_name': vrfname, 'local_address': dut1_lo_ip, 'neighbor_ip': dut3_lo_ip, 'multihop': "yes",
                 'config': "no", 'cli_type': 'klish'}
        dict2 = {'vrf_name': vrfname, 'local_address': dut3_lo_ip, 'neighbor_ip': dut1_lo_ip, 'multihop': "yes",
                 'config': "no", 'cli_type': 'klish'}
        parallel.exec_parallel(True, [dut1, dut3], bfd.configure_bfd, [dict1, dict2])

    return ret_val
