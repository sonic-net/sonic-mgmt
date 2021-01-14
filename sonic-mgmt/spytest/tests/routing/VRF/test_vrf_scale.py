##############################################################################

#Script Title : VRF Lite scale
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com

###############################################################################

import pytest
import os
import ipaddress

from spytest import st,utils

from vrf_vars import * #all the variables used for vrf testcases
from vrf_vars import data
import vrf_lib as loc_lib
from utilities import parallel

import apis.switching.mac as mac_api
import apis.switching.vlan as vlan_api

import apis.routing.ip as ip_api
import apis.routing.vrf as vrf_api
import apis.routing.bgp as bgp_api
import apis.routing.ip_bgp as ip_bgp

import apis.system.port as port_api
import apis.system.reboot as reboot_api
import apis.system.basic as basic_obj

from spytest.tgen.tg import tgen_obj_dict
from spytest.tgen.tgen_utils import validate_tgen_traffic


#Topology:
#------#TG#----(2links)----#DUT1#----(4links)----#DUT2#----(2links)-----#TG#-------#

def initialize_topology():
# code for ensuring min topology
    st.log("Initialize.............................................................................................................")
    vars = st.ensure_min_topology("D1D2:4", "D1T1:2", "D2T1:2")
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    utils.exec_all(True,[[bgp_api.enable_docker_routing_config_mode,data.dut1], [bgp_api.enable_docker_routing_config_mode,data.dut2]])
    data.d1_dut_ports = [vars.D1D2P1]
    data.d2_dut_ports = [vars.D2D1P1]
    data.dut1_tg1_ports = [vars.D1T1P1]
    data.dut2_tg1_ports = [vars.D2T1P1]
    data.tg_dut1_hw_port = vars.T1D1P1
    data.tg_dut2_hw_port = vars.T1D2P1
    data.tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    data.tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    data.tg_dut1_p1 = data.tg1.get_port_handle(vars.T1D1P1)
    data.tg_dut2_p1 = data.tg2.get_port_handle(vars.T1D2P1)
    data.d1_p1_intf_v4 = {}
    data.d1_p1_intf_v6 = {}
    data.d2_p1_intf_v4 = {}
    data.d2_p1_intf_v6 = {}
    data.stream_list_scale = {}
    data.stream = []
    data.dut1_dut2_ip_list = ip_range('5.0.0.1',2,1000)
    data.dut2_dut1_ip_list = ip_range('5.0.0.2',2,1000)
    data.dut1_tg_host = '6.0.0.1'
    data.tg_dut1_host = '6.0.0.2'
    data.dut2_tg_host = '7.0.0.1'
    data.tg_dut2_host = '7.0.0.2'
    data.tg_dut1_stream_start = ip_range('6.0.0.3',3,1000)
    data.tg_dut2_stream_start = ip_range('7.0.0.3',3,1000)
    data.intf_list = []
    for vlan in dut1_dut2_vlan_scale:
        data.intf_list.append('Vlan'+vlan)

@pytest.fixture(scope='module', autouse = True)
def prologue_epilogue():
    initialize_topology()
    #import pdb; pdb.set_trace()
    #import code; code.interact(local=globals())
    base_config()
    yield
    base_unconfig()

def base_config():
    ###############################################################################################################################

    st.log('###### ----- Taking backup for unconfig ------######')
    src_path = "/etc/sonic/config_db.json"
    dst_path = "/etc/sonic/default.json"
    #cmd = 'cp /etc/sonic/config_db.json /etc/sonic/default.json'
    utils.exec_all(True,[[basic_obj.copy_file_to_local_path,data.dut1,src_path,dst_path], [basic_obj.copy_file_to_local_path,data.dut2, src_path, dst_path]])
    ###############################################################################################################################

    st.log('###### ----- Loading json file with vrf and IP address config ------######')
    curr_path = os.getcwd()
    json_file_dut1 = curr_path+"/routing/VRF/vrf_scale_dut1.json"
    st.apply_files(data.dut1, [json_file_dut1])

    json_file_dut2 = curr_path+"/routing/VRF/vrf_scale_dut2.json"
    st.apply_files(data.dut2, [json_file_dut2])

    utils.exec_all(True,[[st.apply_files,data.dut1,[json_file_dut1]], [st.apply_files,data.dut2,[json_file_dut2]]])

    st.log('######------Configure vlans and add members------######')
    utils.exec_all(True,[[vlan_api.config_vlan_range,data.dut1,'1 999','add'], [vlan_api.config_vlan_range,data.dut2,'1 999','add']])
    utils.exec_all(True,[[vlan_api.config_vlan_range_members,data.dut1,'1 999',data.d1_dut_ports[0],'add'], [vlan_api.config_vlan_range_members,data.dut2,'1 999',data.d2_dut_ports[0],'add']])

    ###############################################################################################################################

    st.log('######----- Configure IP on DUT--TG interface------######')
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.dut1_tg1_ports[0],data.dut1_tg_host,'16','ipv4'], [ip_api.config_ip_addr_interface,data.dut2,data.dut2_tg1_ports[0],data.dut2_tg_host,'16','ipv4']])

    ###############################################################################################################################

    st.log('######----- Configure hosts and create traffic streams for all VRFs------######')
    host_config()
    gateway_mac = mac_api.get_sbin_intf_mac(data.dut1, data.dut1_tg1_ports[0])

    data.stream = data.tg1.tg_traffic_config(port_handle = data.tg_dut1_p1, mode = 'create', duration = '5', transmit_mode = 'continuous', length_mode = 'fixed', port_handle2 = data.tg_dut2_p1, rate_pps = 1000, mac_src = '00.00.00.11.12.53', mac_dst = gateway_mac, ip_src_addr = data.tg_dut1_stream_start[0], ip_dst_addr=data.tg_dut2_stream_start[0], l3_protocol='ipv4',ip_src_mode = 'increment', ip_src_count = 1000, ip_src_step ='0.0.0.1')
    data.stream_list_scale.update({'pc_v4_stream':data.stream['stream_id']})
    st.wait(30)

def base_unconfig():
    ###############################################################################################################################

    st.log('######------Unconfigure static routes on 900 VRFs-----######')
    for vrf,dut1_as,dut2_as in zip(vrf_list[899:1000],dut1_as_scale[0:100],dut2_as_scale[0:100]):
        dict1 = {'vrf_name':vrf,'local_as':dut1_as,'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
        dict2 = {'vrf_name':vrf,'local_as':dut2_as,'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    ###############################################################################################################################

    st.log('######------Unconfigure static routes on 900 VRFs-----######')
    dict1 = {'dest_list':data.tg_dut2_stream_start[0:425],'next_hop_list':data.dut2_dut1_ip_list[0:425],'vrf_list':vrf_list[0:425],'config':'no'}
    dict2 = {'dest_list':data.tg_dut2_stream_start[0:425],'vrf_list':vrf_list[0:425],'config':'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_static_route, [dict1, dict2])
    st.wait(30)

    st.log('######----- UnConfigure IP on DUT--TG interface------######')
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.dut1_tg1_ports[0],data.dut1_tg_host,'16','ipv4','remove'], [ip_api.config_ip_addr_interface,data.dut2,data.dut2_tg1_ports[0],data.dut2_tg_host,'16','ipv4','remove']])

    dict1 = {'dest_list':data.tg_dut2_stream_start[425:899],'next_hop_list':data.dut2_dut1_ip_list[425:899],'vrf_list':vrf_list[425:899],'config':'no'}
    dict2 = {'dest_list':data.tg_dut2_stream_start[425:899],'vrf_list':vrf_list[425:899],'config':'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_static_route, [dict1, dict2])
    st.wait(30)

    ###############################################################################################################################

    st.log('###### ----- Laoding back the config_db file ------######')
    #cmd = 'cp /etc/sonic/default.json /etc/sonic/config_db.json'
    src_path = "/etc/sonic/default.json"
    dst_path = "/etc/sonic/config_db.json"
    utils.exec_all(True,[[basic_obj.copy_file_to_local_path,data.dut1,src_path,dst_path], [basic_obj.copy_file_to_local_path,data.dut2, src_path, dst_path]])
    utils.exec_all(True,[[st.reboot,data.dut1,'fast'], [st.reboot,data.dut2,'fast']])

    ###############################################################################################################################

    host_config(config = 'no')

@pytest.fixture(scope="function")
def vrf_fixture_vrf_scale(request,prologue_epilogue):
    yield
    dict1 = {'vrf_name':['Vrf-red'],'skip_error':True,'config':'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.config_vrf, [dict1, dict1])

def test_vrf_scale(vrf_fixture_vrf_scale):

    result = 0
    ###############################################################################################################################

    if not vrf_api.verify_vrf(data.dut2, vrfname = vrf_list):
        st.log('VRF creation failed on DUT2')
        result += 1

    ###############################################################################################################################

    st.log('######------Flap the underlying interface and reverify the VRF-----######')
    port_api.shutdown(data.dut1, data.d1_dut_ports)
    port_api.noshutdown(data.dut1, data.d1_dut_ports)

    st.wait(5)

    ###############################################################################################################################

    if not vrf_api.verify_vrf(data.dut1, vrfname = vrf_list):
        st.log('Binding of VRF to interfaces failed on DUT1')
        result += 1

    ###############################################################################################################################

    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.log('Interface binding failed for 1000 VRFs')
        st.report_fail('test_case_failed')

def test_vrf_route_leak():

    result = 0
    ###############################################################################################################################

    st.log('######------Configure static routes on 900 VRFs-----######')
    dict1 = {'dest_list':data.tg_dut2_stream_start[0:425],'next_hop_list':data.dut2_dut1_ip_list[0:425],'vrf_list':vrf_list[0:425]}
    dict2 = {'dest_list':data.tg_dut2_stream_start[0:425],'vrf_list':vrf_list[0:425]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_static_route, [dict1, dict2])
    st.wait(30)

    dict1 = {'dest_list':data.tg_dut2_stream_start[425:899],'next_hop_list':data.dut2_dut1_ip_list[425:899],'vrf_list':vrf_list[425:899]}
    dict2 = {'dest_list':data.tg_dut2_stream_start[425:899],'vrf_list':vrf_list[425:899]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_static_route, [dict1, dict2])
    st.wait(30)

    ###############################################################################################################################

    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list_scale.values(), duration = 5)

    traffic_details = {'1': {'tx_ports' : [data.tg_dut1_hw_port],'tx_obj' : [data.tg1],'exp_ratio' : [1],'rx_ports' : [data.tg_dut2_hw_port],'rx_obj' : [data.tg2]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list_scale.values())
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')

    if not aggrResult:
        st.log('IPv4 Traffic on 1000 VRF with route leak failed')
        result += 1

    ###############################################################################################################################

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('Traffic on VRF with static route leak failed')
        st.report_fail('test_case_failed')

def test_vrf_bgp():
    result = 0
    ###############################################################################################################################

    st.log('######------Configure BGP on 100 VRFs-----######')
    for vrf, dut1_ip, dut2_ip, dut1_as, dut2_as in zip(vrf_list[899:1000], data.dut1_dut2_ip_list[899:1000], data.dut2_dut1_ip_list[899:1000], dut1_as_scale[0:100], dut2_as_scale[0:100]):
        dict1 = {'vrf_name': vrf, 'router_id': dut1_router_id, 'local_as': dut1_as, 'neighbor': dut2_ip, 'remote_as': dut2_as, 'config_type_list': ['neighbor']}
        dict2 = {'vrf_name': vrf, 'router_id': dut2_router_id, 'local_as': dut2_as, 'neighbor': dut1_ip, 'remote_as': dut1_as, 'config_type_list': ['neighbor']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
        dict1 = {'vrf_name': vrf, 'local_as': dut1_as, 'neighbor': dut2_ip, 'remote_as': dut2_as, 'connect': '3', 'config_type_list': ['activate', 'nexthop_self', 'connect']}
        dict2 = {'vrf_name': vrf, 'local_as': dut2_as, 'neighbor': dut1_ip, 'remote_as': dut1_as, 'connect': '3', 'config_type_list': ['activate', 'nexthop_self', 'connect']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    ###############################################################################################################################

    st.log('######------Verify the BGP neighbors have come up -----######')
    if not utils.poll_wait(ip_bgp.verify_bgp_neighbor, 60, data.dut1, neighborip=data.dut2_dut1_ip_list[899], state='Established', vrf=vrf_list[899]):
        st.log('IPv4 BGP session on VRF-899 did not come up')
        result += 1

    if not utils.poll_wait(ip_bgp.verify_bgp_neighbor, 60, data.dut1, neighborip=data.dut2_dut1_ip_list[950], state='Established', vrf=vrf_list[950]):
        st.log('IPv4 BGP session on VRF-950 did not come up')
        result += 1

    ###############################################################################################################################

    st.log('######------Clear BGP and reverify  -----######')
    bgp_api.clear_ip_bgp_vrf_vtysh(data.dut1, vrf_list[899], family='ipv4')
    st.log('######------Time taken for BGP to come up after clear -----######')
    st.wait(10)
    if not utils.poll_wait(ip_bgp.verify_bgp_neighbor, 60, data.dut1, neighborip=data.dut2_dut1_ip_list[899], state='Established', vrf=vrf_list[899]):
        st.log('IPv4 BGP session on VRF-899 did not come up')
        result += 1

    ###############################################################################################################################

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('BGP neighborship on 100 VRFs failed')
        st.report_fail('test_case_failed')

def test_vrf_reload():
    result = 0
    ###############################################################################################################################

    reboot_api.config_save(data.dut1)
    st.vtysh(data.dut1,"copy running startup")
    st.reboot(data.dut1, 'fast')

    ###############################################################################################################################

    if not vrf_api.verify_vrf(data.dut1, vrfname = vrf_list):
        st.log('Binding of VRF to interfaces failed on DUT1')
        result += 1

    ###############################################################################################################################

    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('Save and reload with VRF configuration failed')
        st.report_fail('test_case_failed')

def ipaddresslist():
    st.log('######----- Generate 1000 IPs between the DUTs ------######')
    start = ipaddress.IPv4Address(u'1.1.1.1')
    end = ipaddress.IPv4Address(u'1.1.4.231')
    ipaddress_list = [start]
    temp = start
    while temp != end:
        temp += 1
        ipaddress_list.append(temp)

    return ipaddress_list

def ip_incr(ip,octet):
   ip_list = ip.split(".")
   ip_list[octet] = str(int(ip_list[octet]) + 1)
   return '.'.join(ip_list)

def ip_range(ip,octet,scl):
    ip_list = [ip]
    ip2 = ip
    i = 1
    j = int(ip.split(".")[octet])
    while i < scl:
        if j == 255:
            ip = ip_incr(ip, octet-1)
            j = int(ip.split(".")[octet])
            ip2 = ip
            ip_list.append(ip2)
            i += 1
        else:
            ip2 = ip_incr(ip2, octet)
            ip_list.append(ip2)
            i += 1
            j += 1
    return ip_list

def vrf_static_route(dut,**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''
    if 'next_hop_list' in kwargs:
        next_hop_list = kwargs['next_hop_list']
    if 'vrf_list' in kwargs:
        vrf_list = kwargs['vrf_list']
    if 'dest_list' in kwargs:
        dest_list = kwargs['dest_list']
    my_cmd = ''
    if dut == data.dut1:
        for dest,vrf,next_hop in zip(dest_list,vrf_list,next_hop_list):
            my_cmd += '{} ip route {}/32 {} nexthop-vrf {} \n'.format(config,dest,next_hop,vrf)
    if dut == data.dut2:
        for dest,vrf in zip(dest_list,vrf_list):
            my_cmd += '{} ip route {}/32 7.0.0.2 nexthop-vrf default vrf {} \n'.format(config,dest,vrf)
    st.vtysh_config(dut,my_cmd)
    return True

def host_config(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'
    if config.lower() == 'yes':
        st.log('######----- Configure host on TG for DUT1 and DUT2 ------######')
        intf_hand_v4 = data.tg1.tg_interface_config(port_handle = data.tg_dut1_p1, mode ='config',intf_ip_addr = data.tg_dut1_host, gateway = data.dut1_tg_host, netmask = '255.255.0.0',arp_send_req = '1')
        data.d1_p1_intf_v4.update({data.tg_dut1_host:intf_hand_v4})
        intf_hand_v4 = data.tg2.tg_interface_config(port_handle = data.tg_dut2_p1, mode ='config',intf_ip_addr = data.tg_dut2_host, gateway = data.dut2_tg_host, netmask = '255.255.0.0',arp_send_req = '1')
        data.d2_p1_intf_v4.update({data.tg_dut2_host:intf_hand_v4})
    else:
        data.tg1.tg_interface_config(port_handle = data.tg_dut1_p1, handle=data.d1_p1_intf_v4.get(data.tg_dut1_host)['handle'], mode='destroy')
        data.tg1.tg_interface_config(port_handle = data.tg_dut2_p1, handle=data.d2_p1_intf_v4.get(data.tg_dut2_host)['handle'], mode='destroy')

# frr_path = os.getcwd()
    # apply_file = True
    # res1 = True
    # frr_apply_path = frr_path+"/routing/frr.frr"
    # result = st.apply_files(vars.D1, [frr_apply_path])

