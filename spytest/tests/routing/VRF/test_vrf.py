##################################################################################
#Script Title : VRF Lite
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com
#################################################################################

import pytest
from spytest import st,utils

from vrf_vars import * #all the variables used for vrf testcase
from vrf_vars import data
import vrf_lib as loc_lib
from utilities import parallel
from apis.system import basic

import apis.switching.portchannel as pc_api

import apis.routing.ip as ip_api
import apis.routing.vrf as vrf_api
import apis.routing.bgp as bgp_api
import apis.routing.ip_bgp as ip_bgp
import apis.routing.arp as arp_api

import apis.system.reboot as reboot_api

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
    data.d1_dut_ports = [vars.D1D2P1,vars.D1D2P2, vars.D1D2P3, vars.D1D2P4]
    data.d2_dut_ports = [vars.D2D1P1, vars.D2D1P2,vars.D2D1P3, vars.D2D1P4]
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
    data.d1_p1_bgp_v4 = {}
    data.d1_p1_bgp_v6 = {}
    data.d2_p1_bgp_v4 = {}
    data.d2_p1_bgp_v6 = {}
    data.stream_list = {}

@pytest.fixture(scope='module', autouse = True)
def prologue_epilogue():
    initialize_topology()
    loc_lib.vrf_base_config()
    # import pdb; pdb.set_trace()
    # import code; code.interact(local=globals())
    yield
    #loc_lib.vrf_base_unconfig()

@pytest.mark.sanity
def test_VrfFun001_06():
    st.log('#######################################################################################################################')
    st.log('######------ Combining FtRtVrfFun001 and FtRtVrfFun006-----######')
    st.log('######------ FtRtVrfFun001: Verify address family IPv4 and IPv6 in VRF instance-----######')
    st.log('######------FtRtVrfFun006: Configure multiple interfaces to a VRF and configure same interface to multiple VRFs-----######')
    st.log('#######################################################################################################################')

    ###############################################################################################################################

    result = 0
    output = vrf_api.get_vrf_verbose(dut = data.dut1,vrfname = vrf_name[0])
    if vrf_name[0] in output['vrfname']:
        st.log('VRF configured on DUT1 is as expected',vrf_name[0])
    else:
        st.log('VRF name configured on DUT1 is as not expected',vrf_name[0])
        result += 1
    for value in output['interfaces']:
        if data.d1_dut_ports[0] or dut1_loopback[0] or data.dut1_loopback[1] or value == 'Vlan1':
            st.log('Bind to VRF is as expected',value)
        else:
            st.log('Bind to VRF is not as expected',value)
            result += 1
    output = vrf_api.get_vrf_verbose(dut = data.dut2,vrfname = vrf_name[0])
    if vrf_name[0] in output['vrfname']:
        st.log('VRF configured on DUT1 is as expected',vrf_name[0])
    else:
        st.log('VRF name configured on DUT1 is as not expected',vrf_name[0])
        result += 1
    for value in output['interfaces']:
        if data.d2_dut_ports[0] or dut2_loopback[0] or value == 'Vlan6':
            st.log('Bind to VRF is as expected',value)
        else:
            st.log('Bind to VRF is not as expected',value)
            result += 1
    if not ip_api.verify_interface_ip_address(data.dut1, 'PortChannel10' ,dut1_dut2_vrf_ip[0]+'/24', vrfname = vrf_name[2]):
        st.log('IPv4 address configuration on portchannel interface failed')
        result += 1
    if not ip_api.verify_interface_ip_address(data.dut2, 'PortChannel10' ,dut2_dut1_vrf_ipv6[0]+'/64', vrfname = vrf_name[2],family='ipv6'):
        st.log('IPv6 address configuration on portchannel interface failed')
        result += 1
    if arp_api.get_arp_count(data.dut1, vrf = vrf_name[1]) < 2:
        st.log('ARP entry for VRF-102 not as expected on DUT1')
        result += 1
    if arp_api.get_arp_count(data.dut2, vrf = vrf_name[1]) < 2:
        st.log('ARP entry for VRF-102 not as expected on DUT2')
        result += 1
    if arp_api.get_ndp_count(data.dut1, vrf = vrf_name[1]) < 2:
        st.log('NDP entry for VRF-102 not as expected on DUT1')
        result += 1
    if arp_api.get_ndp_count(data.dut2, vrf = vrf_name[1]) < 2:
        st.log('NDP entry for VRF-102 not as expected on DUT2')
        result += 1
    if not loc_lib.verify_bgp(phy = '1',ip = 'ipv6'):
        st.log('IPv6 BGP session on VRF-101 did not come up')
        result += 1
    if not loc_lib.verify_bgp(ve = '1',ip = 'ipv4'):
        st.log('IPv4 BGP session on VRF-102 did not come up')
        result += 1
    if not loc_lib.verify_bgp(ve = '1',ip = 'ipv6'):
        st.log('IPv6 BGP session on VRF-102 did not come up')
        result += 1
    if not loc_lib.verify_bgp(pc = '1',ip = 'ipv4'):
        st.log('IPv4 BGP session on VRF-103 did not come up')
        result += 1
    if not loc_lib.verify_bgp(pc = '1',ip = 'ipv6'):
        st.log('IPv6 BGP session on VRF-103 did not come up')
        result += 1
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

#@pytest.mark.depends('test_VrfFun001_06')
def lib_test_VrfFun002():
    result = 0
    loc_lib.clear_tg()
    st.log('Verify ping and traceroute on physical interface on non default vrf for both IPv4 and IPv6')
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ip[0], interface= vrf_name[0], count = 2):
        st.log('IPv4 Ping from Vrf-101-DUT1 to Vrf-101-DUT2 failed')
        result += 1
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ip[0], vrf_name= vrf_name[0], timeout = 3):
        st.log('IPv4 Traceroute from Vrf-101-DUT1 to Vrf-101-DUT2 failed')
        result += 1
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', interface= vrf_name[0], count = 2):
        st.log('IPv6 Ping from Vrf-101-DUT1 to Vrf-101-DUT2 failed')
        result += 1
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', vrf_name= vrf_name[0], timeout = 3):
        st.log('IPv6 Traceroute from Vrf-101-DUT1 to Vrf-101-DUT2 failed')
        result += 1
    if not ip_api.verify_ip_route(data.dut1, vrf_name = vrf_name[0], type='B', nexthop = tg1_dut1_vrf_ip[0], interface = 'Vlan'+dut1_tg1_vlan[0]):
        st.log('IPv4 routes on VRF-101, not learnt on DUT1')
        result += 1
    if not ip_api.verify_ip_route(data.dut2, vrf_name = vrf_name[0], type='B', nexthop = dut1_dut2_vrf_ip[0], interface = data.d2_dut_ports[0]):
        st.log('IPv4 routes on VRF-101, not learnt on DUT2')
        result += 1
    loc_lib.clear_tg()
    if not ip_api.verify_ip_route(data.dut1, vrf_name = vrf_name[0], type='B', nexthop = tg1_dut1_vrf_ipv6[0], interface = 'Vlan'+dut1_tg1_vlan[0], family = 'ipv6'):
        st.log('IPv6 routes on VRF-101, not learnt on DUT1')
        result += 1
    if not ip_api.verify_ip_route(data.dut2, vrf_name = vrf_name[0], type='B', nexthop = dut1_dut2_vrf_ipv6[0], interface = data.d2_dut_ports[0], family = 'ipv6'):
        st.log('IPv6 routes on VRF-101, not learnt on DUT2')
        result += 1
    return result

@pytest.mark.sanity
#@pytest.mark.depends('test_VrfFun001_06')
def test_VrfFun002():
    st.log('#######################################################################################################################')
    st.log('######------FtRtVrfFun002: Bind/unbind/rebind VRF to a physical interface -----######')
    st.log('#######################################################################################################################')
    result = 0
    st.log('######------Unbind and rebind DUT1 <--> DUT2 physical interfaces to vrf and config v4 and v6 addresses------######')
    loc_lib.dut_vrf_bind(phy = '1', config = 'no')
    loc_lib.dut_vrf_bind(phy = '1')
    result = lib_test_VrfFun002()
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('BGP is not converging after unbind/bind on physical interface')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

def lib_test_VrfFun003():

    ###############################################################################################################################
    result = 0
    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.get('ve_v4_stream'), duration = '2')
    st.log('Verify ping and traceroute on virtual interface non-default vrf for both IPv4 and IPv6')
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ip[0], interface= vrf_name[1], count = 2):
        st.log('IPv4 Ping from Vrf-102-DUT1 to vrf DUT2-102 failed')
        result += 1
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ip[0], vrf_name= vrf_name[1], timeout = 3):
        st.log('IPv4 Traceroute Vrf-102-DUT1 to vrf DUT2-102 failed')
        result += 1
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', interface= vrf_name[1], count = 2):
        st.log('IPv6 Ping Vrf-102-DUT1 to vrf DUT2-102 failed')
        result += 1
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', vrf_name= vrf_name[1], timeout = 3):
        st.log('IPv6 Traceroute Vrf-102-DUT1 to vrf DUT2-102 failed')
        result += 1
    if not ip_api.verify_ip_route(data.dut1, vrf_name = vrf_name[1], type='B', nexthop = tg1_dut1_vrf_ip[1], interface = 'Vlan'+dut1_tg1_vlan[1]):
        st.log('IPv4 routes on VRF-102, not learnt on DUT1')
        result += 1
    if not ip_api.verify_ip_route(data.dut2, vrf_name = vrf_name[1], type='B', nexthop = dut1_dut2_vrf_ip[0], interface = 'Vlan'+dut2_dut1_vlan[0]):
        st.log('IPv4 routes on VRF-102, not learnt on DUT2')
        result += 1
    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('ve_v4_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.get('ve_v4_stream'))
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if not aggrResult:
        st.log('IPv4 Traffic on VRF-102 bound to virtual interfaces failed')
        result += 1
    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.get('ve_v6_stream'), duration = '2')
    if not ip_api.verify_ip_route(data.dut1, vrf_name = vrf_name[1], type='B', nexthop = tg1_dut1_vrf_ipv6[1], interface = 'Vlan'+dut1_tg1_vlan[1],family='ipv6'):
        st.log('IPv6 routes on VRF-102, not learnt on DUT1')
        result += 1
    if not ip_api.verify_ip_route(data.dut2, vrf_name = vrf_name[1], type='B', nexthop = dut1_dut2_vrf_ipv6[0], interface = 'Vlan'+dut2_dut1_vlan[0],family='ipv6'):
        st.log('IPv6 routes on VRF-102, not learnt on DUT2')
        result += 1
    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('ve_v6_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.get('ve_v6_stream'))
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if not aggrResult:
        st.log('IPv4 Traffic on VRF-102 bound to virtual interfaces failed')
        result += 1
    return result

@pytest.mark.sanity
#@pytest.mark.depends('test_VrfFun001_06')
def test_VrfFun003():

    st.log('#######################################################################################################################')
    st.log('######------FtRtVrfFun003: Bind/unbind/rebind VRF to a virtual interface -----######')
    st.log('#######################################################################################################################')

    result = 0
    st.log('######------Unbind DUT1 <--> DUT2 physical interfaces to vrf and config v4 and v6 addresses------######')
    loc_lib.dut_vrf_bind(ve = '1', config = 'no')
    st.log('######------Rebind DUT1 <--> DUT2 physical interfaces to vrf and config v4 and v6 addresses------######')
    loc_lib.dut_vrf_bind(ve = '1')
    result = lib_test_VrfFun003()
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('BGP is not converging after unbind/bind on virtual interface')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

def lib_test_VrfFun004():
    result = 0
    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.values(), duration = '2')
    st.log('Verify ping and traceroute on portchannel non-default vrf for both IPv4 and IPv6')
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ip[0], interface= vrf_name[2], count = 2):
        st.log('IPv4 Ping from Vrf-103-DUT1 to Vrf-103-DUT2 failed')
        result += 1
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ip[0], vrf_name= vrf_name[2], timeout = 3):
        st.log('IPv4 Traceroute from Vrf-103-DUT1 to Vrf-103-DUT2 failed')
        result += 1
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', interface= vrf_name[2], count = 2):
        st.log('IPv6 Ping from Vrf-103-DUT1 to Vrf-103-DUT2 failed')
        result += 1
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', vrf_name= vrf_name[2], timeout = 3):
        st.log('IPv6 Traceroute from Vrf-103-DUT1 to Vrf-103-DUT2 failed')
        result += 1
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut1, vrf_name = vrf_name[2], type='B', nexthop = tg1_dut1_vrf_ip[2], interface = 'Vlan'+dut1_tg1_vlan[2], retry_count= 2, delay= 5):
        st.log('IPv4 routes on VRF-103, not learnt on DUT1')
        result += 1
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, vrf_name = vrf_name[2], type='B', nexthop = dut1_dut2_vrf_ip[0], interface = 'PortChannel10', retry_count= 2, delay= 5):
        st.log('IPv4 routes on VRF-103, not learnt on DUT2')
        result += 1
    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('pc_v4_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = [data.stream_list.values()])
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if not aggrResult:
        st.log('IPv4 Traffic on VRF-103 bound to port channel failed')
        result += 1
    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.values(), duration = '2')
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut1, family='ipv6', vrf_name = vrf_name[2], type='B', nexthop = tg1_dut1_vrf_ipv6[2], interface = 'Vlan'+dut1_tg1_vlan[2], retry_count= 2, delay= 5):
        st.log('IPv6 routes on VRF-103, not learnt on DUT1')
        result += 1
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, family='ipv6', vrf_name = vrf_name[2], type='B', nexthop = dut1_dut2_vrf_ipv6[0], interface = 'PortChannel10',retry_count= 2, delay= 5):
        st.log('IPv6 routes on VRF-103, not learnt on DUT2')
        result += 1
    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('pc_v6_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.get('pc_v6_stream'))
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if not aggrResult:
        st.log('IPv6 Traffic on VRF-103 bound to port channel failed')
        result += 1
    return result

@pytest.mark.sanity
#@pytest.mark.depends('test_VrfFun001_06')
def test_VrfFun004():
    st.log('#######################################################################################################################')
    st.log('######------FtRtVrfFun004: Bind/unbind/rebind VRF to a port channel interface -----######')
    st.log('#######################################################################################################################')

    result = 0
    st.log('######------Unbind DUT1 <--> DUT2 physical interfaces to vrf and config v4 and v6 addresses------######')
    loc_lib.dut_vrf_bind(pc = '1', config = 'no')
    st.log('Verify ping and traceroute on portchannel global vrf for both IPv4 and IPv6')
    utils.exec_all(True, [[pc_api.create_portchannel, data.dut1, 'PortChannel10'], [pc_api.create_portchannel, data.dut2, 'PortChannel10']])
    utils.exec_all(True, [[pc_api.add_portchannel_member, data.dut1, 'PortChannel10',data.d1_dut_ports[2]], [pc_api.add_portchannel_member, data.dut2, 'PortChannel10',data.d2_dut_ports[2]]])
    utils.exec_all(True, [[pc_api.add_portchannel_member, data.dut1, 'PortChannel10',data.d1_dut_ports[3]], [pc_api.add_portchannel_member, data.dut2, 'PortChannel10',data.d2_dut_ports[3]]])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'PortChannel10',dut1_dut2_vrf_ip[0],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2, 'PortChannel10', dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'PortChannel10',dut1_dut2_vrf_ipv6[0],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2, 'PortChannel10', dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ip[0], count = 2):
        st.log('IPv4 Ping from Portchannel10-DUT1 to Portchannel10-DUT2 failed')
        result += 1
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ip[0],timeout = 3):
        st.log('IPv4 Traceroute from Portchannel10-DUT1 to Portchannel10-DUT2 failed')
        result += 1
    if not ip_api.ping(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', count = 2):
        st.log('IPv6 Ping from Portchannel10-DUT1 to Portchannel10-DUT2 failed')
        result += 1
    if not ip_api.traceroute(data.dut1, dut2_dut1_vrf_ipv6[0], family='ipv6', timeout = 3):
        st.log('IPv6 Traceroute from Portchannel10-DUT1 to Portchannel10-DUT2 failed')
        result += 1
    st.log('######------Delete the member port and port-channel------######')
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'PortChannel10',dut1_dut2_vrf_ip[0],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2, 'PortChannel10', dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'PortChannel10',dut1_dut2_vrf_ipv6[0],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2, 'PortChannel10', dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
    utils.exec_all(True, [[pc_api.add_del_portchannel_member, data.dut1, 'PortChannel10',data.d1_dut_ports[2],'del'], [pc_api.add_del_portchannel_member, data.dut2, 'PortChannel10',data.d2_dut_ports[2],'del']])
    utils.exec_all(True, [[pc_api.add_del_portchannel_member, data.dut1, 'PortChannel10',data.d1_dut_ports[3],'del'], [pc_api.add_del_portchannel_member, data.dut2, 'PortChannel10',data.d2_dut_ports[3],'del']])
    utils.exec_all(True, [[pc_api.delete_portchannel, data.dut1, 'PortChannel10'], [pc_api.delete_portchannel, data.dut2, 'PortChannel10']])
    st.log('######------Rebind DUT1 <--> DUT2 physical interfaces to vrf and config v4 and v6 addresses------######')
    loc_lib.dut_vrf_bind(pc = '1')
    result = lib_test_VrfFun004()
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('BGP is not converging after unbind/bind on portchannel')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def vrf_fixture_tc_07_08(request,prologue_epilogue):
    yield
    st.log('######------Delete the physical interface from port channel------######')
    pc_api.add_del_portchannel_member(data.dut1, 'PortChannel10', data.d1_dut_ports[0], flag='del')
    pc_api.add_del_portchannel_member(data.dut2, 'PortChannel10', data.d2_dut_ports[0], flag='del')
    st.log('######------Bind DUT1 <--> DUT2 one physical interface to vrf-101 and config v4 and v6 addresses------######')
    dict1 = {'vrf_name':vrf_name[0], 'intf_name':data.d1_dut_ports[0],'skip_error':True}
    dict2 = {'vrf_name':vrf_name[0], 'intf_name':data.d2_dut_ports[0],'skip_error':True}
    parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.d1_dut_ports[0],dut1_dut2_vrf_ip[0],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2,data.d2_dut_ports[0], dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.d1_dut_ports[0],dut1_dut2_vrf_ipv6[0],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2,data.d2_dut_ports[0], dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,dut1_loopback[0],dut1_loopback_ip[0],dut1_loopback_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2,dut2_loopback[0],dut2_loopback_ip[0],dut2_loopback_ip_subnet,'ipv4']])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,dut1_loopback[0],dut1_loopback_ipv6[0],dut1_loopback_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2,dut2_loopback[0],dut2_loopback_ipv6[0],dut2_loopback_ipv6_subnet,'ipv6']])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_tg1_vlan[0],dut1_tg1_vrf_ip[0],dut1_tg1_vrf_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[0], dut2_tg1_vrf_ip[0], dut2_tg1_vrf_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_tg1_vlan[0],dut1_tg1_vrf_ipv6[0],dut1_tg1_vrf_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[0], dut2_tg1_vrf_ipv6[0], dut2_tg1_vrf_ipv6_subnet, 'ipv6']])

@pytest.mark.functionality
#@pytest.mark.depends('test_VrfFun001_06')
def test_VrfFun_07_08(vrf_fixture_tc_07_08):

    st.log('#######################################################################################################################')
    st.log('######------FtRtVrfFun007: Dynamically change port membership from one non-default VRF to another-----######')
    st.log('######------FtRtVrfFun008: Dynamically modify port channel interfaces in a vrf -----######')
    st.log('#######################################################################################################################')
    result = 0
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_tg1_vlan[0],dut1_tg1_vrf_ip[0],dut1_tg1_vrf_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[0], dut2_tg1_vrf_ip[0], dut2_tg1_vrf_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_tg1_vlan[0],dut1_tg1_vrf_ipv6[0],dut1_tg1_vrf_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[0], dut2_tg1_vrf_ipv6[0], dut2_tg1_vrf_ipv6_subnet, 'ipv6']])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,data.d1_dut_ports[0],dut1_dut2_vrf_ip[0],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2,data.d2_dut_ports[0], dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,data.d1_dut_ports[0],dut1_dut2_vrf_ipv6[0],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2,data.d2_dut_ports[0], dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,dut1_loopback[0],dut1_loopback_ip[0],dut1_loopback_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2,dut2_loopback[0],dut2_loopback_ip[0],dut2_loopback_ip_subnet,'ipv4']])
    utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,dut1_loopback[0],dut1_loopback_ipv6[0],dut1_loopback_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2,dut2_loopback[0],dut2_loopback_ipv6[0],dut2_loopback_ipv6_subnet,'ipv6']])
    st.log('######------Unbind DUT2 <--> DUT1 one physical interface from vrf-101------######')
    vrf_api.bind_vrf_interface(dut = data.dut1, vrf_name = vrf_name[0], intf_name = data.d1_dut_ports[0], skip_error = True, config = 'no')
    vrf_api.bind_vrf_interface(dut = data.dut2, vrf_name = vrf_name[0], intf_name = data.d2_dut_ports[0], skip_error = True, config = 'no')
    st.log('######------Add the physical ports to the port channel------######')
    pc_api.add_del_portchannel_member(data.dut1, 'PortChannel10', data.d1_dut_ports[0], flag = 'add')
    pc_api.add_del_portchannel_member(data.dut2, 'PortChannel10', data.d2_dut_ports[0], flag = 'add')
    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.get('pc_v6_stream'), duration = '2')
    if not pc_api.verify_portchannel(data.dut1, 'PortChannel10'):
        st.log('Port channel not up after adding memebers from another vrf')
        result += 1
    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('pc_v6_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.get('pc_v6_stream'))
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if not aggrResult:
        st.log('IPv6 Traffic on Port channel failed')
        result += 1
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('Changing port membership from one vrf to another vrf failed')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

@pytest.mark.functionality
#@pytest.mark.depends('test_VrfFun001_06')
def test_VrfFun_34_46():

    st.log('#######################################################################################################################')
    st.log('######------Combining FtRtVrfFun005, FtRtVrfFun034 and FtRtVrfFun046 -----######')
    st.log('#######################################################################################################################')
    result = 0
    bgp_api.clear_ip_bgp_vrf_vtysh(data.dut1, vrf_name[0], family = 'ipv4')
    bgp_api.clear_ip_bgp_vrf_vtysh(data.dut1, vrf_name[0], family = 'ipv6')
    bgp_api.clear_ip_bgp_vrf_vtysh(data.dut1, vrf_name[1], family = 'ipv4')
    bgp_api.clear_ip_bgp_vrf_vtysh(data.dut1, vrf_name[1], family = 'ipv6')
    bgp_api.clear_ip_bgp_vrf_vtysh(data.dut1, vrf_name[2], family = 'ipv4')
    bgp_api.clear_ip_bgp_vrf_vtysh(data.dut1, vrf_name[2], family = 'ipv6')
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, vrf_name = vrf_name[1], type='B', nexthop = dut1_dut2_vrf_ip[0], interface = 'Vlan'+dut2_dut1_vlan[0], retry_count= 2, delay= 5):
        st.log('IPv4 routes on VRF-102, not learnt on DUT2')
        result += 1
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, vrf_name = vrf_name[1], type='B', nexthop = dut1_dut2_vrf_ipv6[0], interface = 'Vlan'+dut2_dut1_vlan[0],family='ipv6',retry_count= 2, delay= 5):
        st.log('IPv6 routes on VRF-102, not learnt on DUT2')
        result += 1
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, family='ipv6', vrf_name = vrf_name[2], type='B', nexthop = dut1_dut2_vrf_ipv6[0], interface = 'PortChannel10',retry_count= 2, delay= 5):
        st.log('IPv6 routes on VRF-103, not learnt on DUT2')
        result += 1
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

def vrf_tc_38_39_48():
    st.log('IPv6 BGP session did not come up, after delete/add IPv6 IBGP and EBGP config.')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = dut2_dut1_vrf_ipv6[0], remote_as = dut2_as[2], config_type_list =['neighbor'])
    st.log('######------Readd EBGP IPv6 neighbor configuration from all the VRFs  ------######')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = tg1_dut1_vrf_ipv6[2], remote_as = dut1_tg_as, config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = dut2_dut1_vrf_ipv6[0], remote_as = dut2_as[2], config_type_list =['activate','nexthop_self'])
    st.log('######------Readd EBGP IPv6 neighbor configuration from all the VRFs  ------######')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = tg1_dut1_vrf_ipv6[2], remote_as = dut1_tg_as, config_type_list =['activate'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], local_as = dut1_as[2], config = 'yes', addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=tg1_dut1_vrf_ipv6[2])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], local_as = dut1_as[2], config = 'yes', addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut2_dut1_vrf_ipv6[0])

@pytest.mark.functionality
#@pytest.mark.depends('test_VrfFun001_06')
def test_VrfFun_38_39_48():

    st.log('#######################################################################################################################')
    st.log('######------Combined  FtRtVrfFun038, FtRtVrfFun039 and FtRtVrfFun048-----######')
    st.log('######------FtRtVrfFun038 Verify IBGP neighbor for BGPv6 in vrf for ipv6 -----######')
    st.log('######------FtRtVrfFun039 Verify EBGP neighbor for BGPv6 in vrf for ipv6 -----######')
    st.log('######------FtRtVrfFun048 Verify BGP4+ route-map functionality in non-default VRF -----######')
    st.log('#######################################################################################################################')
    result = 0
    st.log('######------Remove IBGP IPv6 neighbor configuration from all the VRFs  ------######')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6', local_as = dut1_as[2], neighbor = dut2_dut1_vrf_ipv6[0], remote_as = dut2_as[2], config = 'no', config_type_list =['neighbor'])
    st.log('######------Readd IBGP IPv6 neighbor configuration from all the VRFs  ------######')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = dut2_dut1_vrf_ipv6[0], remote_as = dut2_as[2], config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = dut2_dut1_vrf_ipv6[0], remote_as = dut2_as[2], config_type_list =['activate','nexthop_self'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], local_as = dut1_as[2], config = 'yes', addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut2_dut1_vrf_ipv6[0])
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, family='ipv6', vrf_name = vrf_name[2], type='B', nexthop = dut1_dut2_vrf_ipv6[0], interface = 'PortChannel10',retry_count= 2, delay= 10):
        st.log('IPv6 routes on VRF-102, not learnt on DUT2')
        result += 1
        basic.get_techsupport(filename='test_VrfFun_38_39_48_ipv6_routes')
    st.log('######------Remove EBGP IPv6 neighbor configuration from all the VRFs  ------######')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6', local_as = dut1_as[2], neighbor = tg1_dut1_vrf_ipv6[2], remote_as = dut1_tg_as, config = 'no', config_type_list =['neighbor'])
    st.log('######------Readd EBGP IPv6 neighbor configuration from all the VRFs  ------######')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = tg1_dut1_vrf_ipv6[2], remote_as = dut1_tg_as, config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], addr_family ='ipv6',  config = 'yes', local_as = dut1_as[2], neighbor = tg1_dut1_vrf_ipv6[2], remote_as = dut1_tg_as, config_type_list =['activate'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], local_as = dut1_as[2], config = 'yes', addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=tg1_dut1_vrf_ipv6[2])
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, family='ipv6', vrf_name = vrf_name[2], type='B', nexthop = dut1_dut2_vrf_ipv6[0], interface = 'PortChannel10',retry_count= 3, delay= 10):
        st.log('IPv6 routes on VRF-102, not learnt on DUT2')
        result += 1
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        vrf_tc_38_39_48()
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def vrf_fixture_tc_31_43(request,prologue_epilogue):
    yield
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = dut2_dut1_vrf_ip[0], remote_as = dut2_as[0], config = 'no', config_type_list =['redist'], redistribute ='connected')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2],local_as = dut1_as[2], addr_family ='ipv6', neighbor = dut2_dut1_vrf_ipv6[0], remote_as = dut2_as[2], config = 'no', config_type_list =['redist'], redistribute ='connected')

@pytest.mark.functionality
#@pytest.mark.depends('test_VrfFun001_06')
def test_VrfFun_31_43(vrf_fixture_tc_31_43):
    st.log('#######################################################################################################################')
    st.log('######------Combined FtRtVrfFun031 and FtRtVrfFun043 -----######')
    st.log('######------FtRtVrfFun031 Redistribute connected IPv4 routes into IBGP in non-default vrf -----######')
    st.log('######------FtRtVrfFun043 Redistribute connected IPv6 routes into IBGP in non-default vrf -----######')
    st.log('#######################################################################################################################')

    result = 0
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = dut2_dut1_vrf_ip[0], remote_as = dut2_as[0], config = 'yes', config_type_list =['redist'], redistribute ='connected')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2],local_as = dut1_as[2], addr_family ='ipv6', neighbor = dut2_dut1_vrf_ipv6[0], remote_as = dut2_as[2], config = 'yes', config_type_list =['redist'], redistribute ='connected')
    st.wait(5)
    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.get('pc_v6_stream'), duration = '2')
    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('pc_v6_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.get('pc_v6_stream'))
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if not aggrResult:
        st.log('IPv6 Traffic on VRF-103 failed')
        result += 1
    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.get('phy_v4_stream'), duration = '2')
    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('phy_v4_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.get('phy_v4_stream'))
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if not aggrResult:
        st.log('IPv4 Traffic on VRF-101 failed')
        result += 1
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('Redistribute connected IPv4 and IPv6 routes into IBGP in VRF-103 failed')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

def vrf_tc_26_27():
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = tg1_dut1_vrf_ip[0], remote_as = dut1_tg_as,  config = 'yes',config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = tg1_dut1_vrf_ip[0], remote_as = dut1_tg_as,  config = 'yes',config_type_list =['activate'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = dut2_dut1_vrf_ip[0], remote_as = dut2_as[0], config = 'yes', config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = dut2_dut1_vrf_ip[0], remote_as = dut2_as[0], config = 'yes', config_type_list =['activate','nexthop_self'])

#@pytest.mark.depends('test_VrfFun001_06')
def test_VrfFun_26_27():
    st.log('#######################################################################################################################')
    st.log('######------Combined FtRtVrfFun026 and FtRtVrfFun027 -----######')
    st.log('######------ FtRtVrfFun026: Verify IBGP neighbor for BGPv4 in vrf -----######')
    st.log('######------FtRtVrfFun027 Verify EBGP neighbor for BGPv4 in vrf for ipv4 -----######')
    st.log('#######################################################################################################################')

    result = 0
    st.log('######------Remove EBGP IPv4 neighbor configuration from all the VRFs  ------######')
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0], local_as = dut1_as[0], neighbor = dut2_dut1_vrf_ip[0], remote_as = dut2_as[0], config = 'no', config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = dut2_dut1_vrf_ip[0], remote_as = dut2_as[0], config = 'yes', config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = dut2_dut1_vrf_ip[0], remote_as = dut2_as[0], config = 'yes', config_type_list =['activate','nexthop_self'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0], local_as = dut1_as[0], neighbor = tg1_dut1_vrf_ip[0], remote_as = dut1_tg_as, config = 'no', config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = tg1_dut1_vrf_ip[0], remote_as = dut1_tg_as,  config = 'yes',config_type_list =['neighbor'])
    bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0],local_as = dut1_as[0], neighbor = tg1_dut1_vrf_ip[0], remote_as = dut1_tg_as,  config = 'yes',config_type_list =['activate'])
    st.wait(5)
    if not ip_api.verify_ip_route(data.dut1, vrf_name = vrf_name[0], type='B', nexthop = tg1_dut1_vrf_ip[0], interface = 'Vlan'+dut1_tg1_vlan[0]):
        st.log('IPv4 routes on VRF-101, not learnt on DUT1')
        result += 1
    if not ip_api.verify_ip_route(data.dut2, vrf_name = vrf_name[0], type='B', nexthop = dut1_dut2_vrf_ip[0], interface = data.d2_dut_ports[0]):
        st.log('IPv4 routes on VRF-101, not learnt on DUT2')
        result += 1
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('IPv4 BGP session did not come up, after delete/add IPv4 IBGP and EBGP config')
        vrf_tc_26_27()
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def vrf_fixture_tc_28_36_43_47(request,prologue_epilogue):
    #1234
    yield
    # import pdb; pdb.set_trace()
    # import code; code.interact(local=globals())
    #for nbr_1,nbr_2 in zip(dut2_dut1_vrf_ip[0:2],dut1_dut2_vrf_ip[0:2]):
    # dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'peergroup':'peergroup_v4','config_type_list':['peergroup']}
    # dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'peergroup':'peergroup_v4','config_type_list':['peergroup']}
    # parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    # for nbr_1,nbr_2 in zip(dut2_dut1_vrf_ipv6[0:2],dut1_dut2_vrf_ipv6[0:2]):
    # dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'peergroup':'peergroup_v6','config_type_list':['peergroup'],'addr_family':'ipv6'}
    # dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'peergroup':'peergroup_v6','config_type_list':['peergroup'],'addr_family':'ipv6'}
    # parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    bgp_api.activate_bgp_neighbor(data.dut1, dut1_as[1], dut2_dut1_vrf_ip[1], family="ipv4", config='no',vrf=vrf_name[1], remote_asn=dut2_as[1])
    bgp_api.activate_bgp_neighbor(data.dut1, dut1_as[1], dut2_dut1_vrf_ipv6[1], family="ipv6", config='no',vrf=vrf_name[1], remote_asn=dut2_as[1])
    dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[1],'remote_as':dut2_as[1],'config_type_list':['neighbor']}
    dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[1],'remote_as':dut1_as[1],'config_type_list':['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    bgp_api.activate_bgp_neighbor(data.dut2, dut2_as[1], dut1_dut2_vrf_ip[1], family="ipv4", config='no',vrf=vrf_name[1], remote_asn=dut1_as[1])
    bgp_api.activate_bgp_neighbor(data.dut2, dut2_as[1], dut1_dut2_vrf_ipv6[1], family="ipv6", config='no',vrf=vrf_name[1], remote_asn=dut1_as[1])
    dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[1],'remote_as':dut2_as[1],'addr_family':'ipv6','config_type_list':['neighbor']}
    dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[1],'remote_as':dut1_as[1],'addr_family':'ipv6','config_type_list':['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

@pytest.mark.functionality
#@pytest.mark.depends('test_VrfFun001_06')
def test_VrfFun_28_36_43_47(vrf_fixture_tc_28_36_43_47):
    st.log('#######################################################################################################################')
    st.log('######------FtRtVrfFun026 Verify the EBGP peer connection and route advertisement under IPV4 address-family in non-default vrf -----######')
    st.log('######------FtRtVrfFun036 Verify BGP peer-group for IPv4 address family on non-default VRF -----######')
    st.log('######------FtRtVrfFun043 Verify the EBGP peer connection and route advertisement under IPV6 address-family in non-default vrf -----######')
    st.log('######------FtRtVrfFun047 Verify BGP peer-group for IPv6 address family with EBGP neighbors non-default VRF-----######')
    st.log('#######################################################################################################################')
    result = 0
    st.log('Configuring Vlan102 as another neighbor in VRF-102')
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[1],'remote_as':dut2_as[1],'config_type_list':['neighbor']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[1],'remote_as':dut1_as[1],'config_type_list':['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[1],'remote_as':dut2_as[1],'config_type_list':['activate','nexthop_self']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[1],'remote_as':dut1_as[1],'config_type_list':['activate','nexthop_self']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    st.log('Configuring Vlan102 as another neighbor in VRF-102')
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[1],'remote_as':dut2_as[1],'addr_family':'ipv6','config_type_list':['neighbor']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[1],'remote_as':dut1_as[1],'addr_family':'ipv6','config_type_list':['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[1],'remote_as':dut2_as[1],'addr_family':'ipv6','config_type_list':['activate','nexthop_self']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[1],'remote_as':dut1_as[1],'addr_family':'ipv6','config_type_list':['activate','nexthop_self']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    st.log('Configuring IPv4 peer group for Vlan101 and Vlan 102')
    for nbr_1,nbr_2 in zip(dut2_dut1_vrf_ip[0:2],dut1_dut2_vrf_ip[0:2]):
        dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'peergroup':'peergroup_v4','config_type_list':['peergroup'],'remote_as':dut2_as[1],'neighbor':nbr_1}
        dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'peergroup':'peergroup_v4','config_type_list':['peergroup'],'remote_as':dut1_as[1],'neighbor':nbr_2}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    st.log('Configuring IPv6 peer group for Vlan101 and Vlan 102')
    for nbr_1,nbr_2 in zip(dut2_dut1_vrf_ipv6[0:2],dut1_dut2_vrf_ipv6[0:2]):
        dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'peergroup':'peergroup_v6','config_type_list':['peergroup'],'remote_as':dut2_as[1],'neighbor':nbr_1,'addr_family':'ipv6'}
        dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'peergroup':'peergroup_v6','config_type_list':['peergroup'],'remote_as':dut1_as[1],'neighbor':nbr_2,'addr_family':'ipv6'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    if not ip_bgp.verify_bgp_neighbor(data.dut1, neighborip = dut2_dut1_vrf_ip[1], state='Established', vrf = vrf_name[1]):
        st.log('IPv6 IBGP neighbor did not come up on VRF-102 after peer-group configuration')
        result += 1
    loc_lib.clear_tg()
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.get('ve_v4_stream'), duration = '2')
    traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [[data.stream_list.get('ve_v4_stream')]]}}
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.get('ve_v4_stream'))
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if not aggrResult:
        st.log('IPv4 Traffic on VRF-102 failed after peer-group configuration')
        result += 1
    if not ip_bgp.verify_bgp_neighbor(data.dut1, neighborip = dut2_dut1_vrf_ipv6[1], state='Established', vrf = vrf_name[1]):
        st.log('IPv6 IBGP neighbor did not come up on VRF-102 after peer-group configuration')
        result += 1
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('Peer group verification for IPv4 and IPv6 in VRF-102 failed')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def vrf_fixture_tc_35_49(request,prologue_epilogue):
    yield
    st.log('UnConfigure max path iBGP for IPv4 is 2 in DUT1 and 8 in DUT2')
    dict1 = {'vrf_name':vrf_name[1],'local_as': dut1_as[1], 'max_path_ibgp': '', 'config_type_list': ["max_path_ibgp"], 'config' : 'no'}
    dict2 = {'vrf_name':vrf_name[1],'local_as': dut2_as[1], 'max_path_ibgp': '', 'config_type_list': ["max_path_ibgp"], 'config' : 'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[1],'remote_as':dut2_as[1],'config_type_list':['neighbor']}
    dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[1],'remote_as':dut1_as[1],'config_type_list':['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    ###############################################################################################################################
    st.log('UnConfigure max path iBGP for IPv6 is 2 in DUT1 and 8 in DUT2')
    dict1 = {'vrf_name':vrf_name[1],'local_as': dut1_as[1], 'max_path_ibgp': '', 'config_type_list': ["max_path_ibgp"],'addr_family' : 'ipv6', 'config' : 'no'}
    dict2 = {'vrf_name':vrf_name[1],'local_as': dut2_as[1], 'max_path_ibgp': '', 'config_type_list': ["max_path_ibgp"],'addr_family' : 'ipv6', 'config' : 'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    bgp_api.config_bgp(dut = data.dut2, vrf_name = vrf_name[1], local_as = dut1_as[1], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut1_dut2_vrf_ipv6[0])
    dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[1],'addr_family':'ipv6','remote_as':dut2_as[1],'config_type_list':['neighbor']}
    dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[1],'addr_family':'ipv6','remote_as':dut1_as[1],'config_type_list':['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])


#@pytest.mark.depends('test_VrfFun001_06')
def test_VrfFun_35_49(vrf_fixture_tc_35_49):
    st.log('#######################################################################################################################')
    st.log('######------FtRtVrfFun035 IPv4 ECMP in non-default vrf along with route leak into another vrf -----######')
    st.log('######------FtRtVrfFun049 IPv6 ECMP in non-default vrf along with route leak into another vrf -----######')
    st.log('#######################################################################################################################')
    result = 0
    st.log('Configure max path iBGP for IPv4 is 2 in DUT1 and 8 in DUT2')
    dict1 = {'vrf_name':vrf_name[1],'local_as': dut1_as[1], 'max_path_ibgp': 2, 'config_type_list': ["max_path_ibgp"]}
    dict2 = {'vrf_name':vrf_name[1],'local_as': dut2_as[1], 'max_path_ibgp': 8, 'config_type_list': ["max_path_ibgp"]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    st.log('Configuring Vlan102 as another neighbor in VRF-102')
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[1],'remote_as':dut2_as[1],'config_type_list':['neighbor']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[1],'remote_as':dut1_as[1],'config_type_list':['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[1],'remote_as':dut2_as[1],'config_type_list':['activate','nexthop_self']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[1],'remote_as':dut1_as[1],'config_type_list':['activate','nexthop_self']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, vrf_name = vrf_name[1], type='B', nexthop = dut1_dut2_vrf_ip[0], interface = 'Vlan'+dut2_dut1_vlan[0]):
        st.log('IPv4 routes on VRF-102, not learnt on DUT2')
        result += 1
        basic.get_techsupport(filename='test_VrfFun_35_49_ipv4_routes')

    st.log('Configure max path iBGP for IPv6 is 2 in DUT1 and 8 in DUT2')
    dict1 = {'vrf_name':vrf_name[1],'local_as': dut1_as[1], 'max_path_ibgp': 2, 'config_type_list': ["max_path_ibgp"],'addr_family' : 'ipv6'}
    dict2 = {'vrf_name':vrf_name[1],'local_as': dut2_as[1], 'max_path_ibgp': 8, 'config_type_list': ["max_path_ibgp"],'addr_family' : 'ipv6'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    st.log('for BGPv4+ Configuring Vlan102 as another neighbor in VRF-102')
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[1],'remote_as':dut2_as[1],'addr_family':'ipv6','config_type_list':['neighbor']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[1],'remote_as':dut1_as[1],'addr_family':'ipv6','config_type_list':['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[1],'remote_as':dut2_as[1],'addr_family':'ipv6','config_type_list':['activate','nexthop_self']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[1],'remote_as':dut1_as[1],'addr_family':'ipv6','config_type_list':['activate','nexthop_self']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    bgp_api.config_bgp(dut = data.dut2, vrf_name = vrf_name[1], local_as = dut1_as[1], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut1_dut2_vrf_ipv6[1])
    bgp_api.config_bgp(dut = data.dut2, vrf_name = vrf_name[1], local_as = dut1_as[1], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut1_dut2_vrf_ipv6[0])
    if not loc_lib.retry_api(ip_api.verify_ip_route, dut = data.dut2, vrf_name = vrf_name[1], type='B', nexthop = dut1_dut2_vrf_ipv6[1], interface = 'Vlan'+dut2_dut1_vlan[1],family='ipv6'):
        st.log('IPv6 routes on VRF-102, not learnt on DUT2')
        result += 1
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('Multipath IBGP verification for IPv4 and IPv6 in VRF-102 failed')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def vrf_fixture_tc_10_12_14(request,prologue_epilogue):
    yield
    st.log('######------Delete the static routes configured on all VRFs------######')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ip[0], dut2_tg1_vrf_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[0], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ip[0], dut1_tg1_vrf_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[0],'no']])
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ipv6[0], dut2_tg1_vrf_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[0], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ipv6[0], dut1_tg1_vrf_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[0],'no']])

    ###############################################################################################################################

    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ip[1], dut2_tg1_vrf_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[1], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ip[1], dut1_tg1_vrf_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[1],'no']])
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ipv6[1], dut2_tg1_vrf_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[1], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ipv6[1], dut1_tg1_vrf_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[1],'no']])

    ###############################################################################################################################

    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ip[2], dut2_tg1_vrf_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[2], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ip[2], dut1_tg1_vrf_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[2],'no']])
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ipv6[2], dut2_tg1_vrf_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[2], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ipv6[2], dut1_tg1_vrf_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[2],'no']])

    ###############################################################################################################################

    loc_lib.dut_vrf_bgp(phy = '1')
    loc_lib.dut_vrf_bgp(ve = '1')
    loc_lib.dut_vrf_bgp(pc = '1')
    loc_lib.tg_vrf_bgp(phy = '1')
    loc_lib.tg_vrf_bgp(ve = '1')
    loc_lib.tg_vrf_bgp(pc = '1')

@pytest.mark.functionality
#@pytest.mark.depends('test_VrfFun001_06')
def test_VrfFun_10_12_14(vrf_fixture_tc_10_12_14):

    st.log('#######################################################################################################################')
    st.log('######------FtRtVrfFun0010: Add/delete static route under vrf with next hop as physical interface-----######')
    st.log('######------FtRtVrfFun0012: Add/delete static route under vrf with next hop as virtual interface -----######')
    st.log('######------FtRtVrfFun0014: Add/delete static route under vrf with next hop as port channel -----######')
    st.log('#######################################################################################################################')

    result = 0
    loc_lib.dut_vrf_bgp(phy = '1', config = 'no')
    loc_lib.dut_vrf_bgp(ve = '1', config = 'no')
    loc_lib.dut_vrf_bgp(pc = '1', config = 'no')
    st.log('######------Configure IPv4 static routes on VRF-101------######')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ip[0], dut2_tg1_vrf_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[0], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ip[0], dut1_tg1_vrf_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[0],'']])
    if not ip_api.ping(data.dut1, dut2_tg1_vrf_ip[0], interface= vrf_name[0], count = 2):
        st.log('IPv4 Ping from Vrf-101-DUT1 to Vrf-101-DUT2 failed after static route configuration')
        result += 1
    st.log('######------Configure IPv6 static routes on VRF-101------######')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ipv6[0], dut2_tg1_vrf_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[0], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ipv6[0], dut1_tg1_vrf_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[0],'']])
    if not ip_api.ping(data.dut1, dut2_tg1_vrf_ipv6[0], interface= vrf_name[0], count = 2, family='ipv6'):
        st.log('IPv6 Ping from Vrf-101-DUT1 to Vrf-101-DUT2 failed after static route configuration')
        result += 1
    st.log('######------Configure IPv4 static routes on VRF-102------######')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ip[1], dut2_tg1_vrf_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[1], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ip[1], dut1_tg1_vrf_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[1],'']])
    if not ip_api.ping(data.dut1, dut2_tg1_vrf_ip[1], interface= vrf_name[1], count = 2):
        st.log('IPv4 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 failed after static route configuration')
        result += 1
    st.log('######------Configure IPv6 static routes on VRF-102------######')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ipv6[1], dut2_tg1_vrf_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[1], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ipv6[1], dut1_tg1_vrf_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[1],'']])
    if not ip_api.ping(data.dut1, dut2_tg1_vrf_ipv6[1], family='ipv6', interface= vrf_name[1], count = 2):
        st.log('IPv6 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 failed after static route configuration')
        result += 1
    st.log('######------Configure IPv4 static routes on VRF-103------######')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ip[2], dut2_tg1_vrf_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[2], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ip[2], dut1_tg1_vrf_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[2],'']])
    if not ip_api.ping(data.dut1, dut2_tg1_vrf_ip[2], interface= vrf_name[2], count = 2):
        st.log('IPv4 Ping from Vrf-103-DUT1 to Vrf-103-DUT2 failed after static route configuration')
        result += 1
    st.log('######------Configure IPv6 static routes on VRF-103------######')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_tg1_vrf_ipv6[2], dut2_tg1_vrf_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[2], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_tg1_vrf_ipv6[2], dut1_tg1_vrf_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[2],'']])
    if not ip_api.ping(data.dut1, dut2_tg1_vrf_ipv6[2], family='ipv6', interface= vrf_name[2], count = 2):
        st.log('IPv6 Ping from Vrf-103-DUT1 to Vrf-103-DUT2 failed after static route configuration')
        result += 1
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('Static route between VRFs failed for VRf-101, VRF-102 and VRF-103')
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def vrf_fixture_tc_29_30_41_42_54_55(request,prologue_epilogue):
    yield
    st.log('######------Delete Loopback as BGP neighbor------######')
    dict1 = {'vrf_name':vrf_name[1],'local_as':'104','config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':'105','config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    utils.exec_all(True,[[ip_api.config_static_route_vrf, data.dut1, dut2_loopback_ip[1], dut2_loopback_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[1], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_loopback_ip[1], dut1_loopback_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[1],'no']])
    dict1 = {'vrf_name':vrf_name[2],'local_as':'106','config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
    dict2 = {'vrf_name':vrf_name[2],'local_as':'107','config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_loopback_ipv6[2], dut2_loopback_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[2], 'no'], [ip_api.config_static_route_vrf,data.dut2, dut1_loopback_ipv6[2], dut1_loopback_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[2],'no']])
    loc_lib.dut_vrf_bgp(ve = '1')
    loc_lib.dut_vrf_bgp(pc = '1')
    loc_lib.tg_vrf_bgp(ve = '1')
    loc_lib.tg_vrf_bgp(pc = '1')

#@pytest.mark.depends('test_VrfFun001_06')
def test_VrfFun_29_30_41_42_54_55(vrf_fixture_tc_29_30_41_42_54_55):

    st.log('#######################################################################################################################')
    st.log('######------FtRtVrfFun029: Verify multihop EBGP under IPv4 address-family in non-default vrfe-----######')
    st.log('######------FtRtVrfFun030: Add/delete non-default vrf with both single hop and multihop EBGP sessions e-----######')
    st.log('######------FtRtVrfFun041: Verify multihop EBGP under IPv6 address-family in non-default vrfe-----######')
    st.log('######------FtRtVrfFun042: Add/delete non-default vrf with both single hop and multihop EBGP sessions for IPv6 address family-----######')
    st.log('######------FtRtVrfFun054: IPv4 forwarding with default route in default vrf and also in non-default vrf-----######')
    st.log('######------FtRtVrfFun055: IPv6 forwarding with default route in default vrf and also in non-default vrf-----######')
    st.log('#######################################################################################################################')

    result = 0
    loc_lib.dut_vrf_bgp(ve = '1', config = 'no')
    st.log('######------Configure EBGP between DUTs------######')
    st.log('######------Add Loopback as BGP neighbor------######')
    dict1 = {'vrf_name':vrf_name[1],'local_as':'104','neighbor':dut2_loopback_ip[1],'remote_as':'105','config_type_list':['neighbor']}
    dict2 = {'vrf_name':vrf_name[1],'local_as':'105','neighbor':dut1_loopback_ip[1],'remote_as':'104','config_type_list':['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[1],'local_as':'104','neighbor':dut2_loopback_ip[1],'remote_as':'105','config_type_list':['activate','update_src','ebgp_mhop'],'update_src':dut1_loopback_ip[1],'ebgp_mhop':'1'}
    dict2 = {'vrf_name':vrf_name[1],'local_as':'105','neighbor':dut1_loopback_ip[1],'remote_as':'104','config_type_list':['activate','update_src','ebgp_mhop'],'update_src':dut2_loopback_ip[1],'ebgp_mhop':'1'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    st.log('######------Configure static routes on VRF-102------######')
    utils.exec_all(True,[[ip_api.config_static_route_vrf, data.dut1, dut2_loopback_ip[1], dut2_loopback_ip_subnet, dut2_dut1_vrf_ip[0],'ipv4',vrf_name[1], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_loopback_ip[1], dut1_loopback_ip_subnet, dut1_dut2_vrf_ip[0],'ipv4',vrf_name[1],'']])
    if not ip_api.ping(data.dut1, dut2_loopback_ip[1], interface= vrf_name[1], count = 2):
        st.log('IPv6 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 failed after static route configuration to loopback interface')
        result += 1
    if not ip_bgp.verify_bgp_neighbor(data.dut1, neighborip = dut2_loopback_ip[1], state='Established', vrf = vrf_name[1]):
        st.log('IPv4 routes on VRF-102 over the loopback, not learnt on DUT2')
        result += 1
    dict1 = {'vrf_name':vrf_name[1],'local_as':'104','config_type_list':['redist'],'redistribute':'connected'}
    dict2 = {'vrf_name':vrf_name[1],'local_as':'105','config_type_list':['redist'],'redistribute':'connected'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    loc_lib.dut_vrf_bgp(pc = '1', config = 'no')
    st.log('######------Add Loopback as BGP neighbor for vrf-103------######')
    dict1 = {'vrf_name':vrf_name[2],'local_as':'106','neighbor':dut2_loopback_ipv6[2],'remote_as':'107','addr_family':'ipv6','config_type_list':['neighbor']}
    dict2 = {'vrf_name':vrf_name[2],'local_as':'107','neighbor':dut1_loopback_ipv6[2],'remote_as':'106','addr_family':'ipv6','config_type_list':['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[2],'local_as':'106','neighbor':dut2_loopback_ipv6[2],'remote_as':'107','addr_family':'ipv6','config_type_list':['activate','update_src','ebgp_mhop'],'update_src':dut1_loopback_ipv6[2],'ebgp_mhop':'1'}
    dict2 = {'vrf_name':vrf_name[2],'local_as':'107','neighbor':dut1_loopback_ipv6[2],'remote_as':'106','addr_family':'ipv6','config_type_list':['activate','update_src','ebgp_mhop'],'update_src':dut2_loopback_ipv6[2],'ebgp_mhop':'1'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    st.log('######------Configure static routes for vrf-103------######')
    utils.exec_all(True,[[ip_api.config_static_route_vrf,data.dut1, dut2_loopback_ipv6[2], dut2_loopback_ipv6_subnet, dut2_dut1_vrf_ipv6[0],'ipv6',vrf_name[2], ''], [ip_api.config_static_route_vrf,data.dut2, dut1_loopback_ipv6[2], dut1_loopback_ipv6_subnet, dut1_dut2_vrf_ipv6[0],'ipv6',vrf_name[2],'']])
    if not ip_api.ping(data.dut1, dut2_loopback_ipv6[2], interface= vrf_name[2], family='ipv6', count = 2):
        st.log('IPv6 Ping from Vrf-102-DUT1 to Vrf-102-DUT2 failed after static route configuration to loopback interface')
        result += 1
    if not ip_bgp.verify_bgp_neighbor(data.dut1, neighborip = dut2_loopback_ipv6[2], state='Established', vrf = vrf_name[2]):
        st.log('IPv4 routes on VRF-102 over the loopback, not learnt on DUT2')
        result += 1
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('Static route between VRFs failed for VRf-101, VRF-102 and VRF-103')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def vrf_fixture_tc_20_24_25_32_33_44_45(request,prologue_epilogue):
    yield
    dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[0],'remote_as':dut2_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[0],'remote_as':dut1_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut2_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'config':'no','vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut1_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    ###############################################################################################################################

    dict1 = {'config':'no','vrf_name':vrf_name[2],'local_as':dut1_as[2],'neighbor':dut2_dut1_vrf_ip[0],'remote_as':dut2_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'config':'no','vrf_name':vrf_name[2],'local_as':dut2_as[2],'neighbor':dut1_dut2_vrf_ip[0],'remote_as':dut1_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'config':'no','vrf_name':vrf_name[2],'local_as':dut1_as[2],'neighbor':dut2_dut1_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut2_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'config':'no','vrf_name':vrf_name[2],'local_as':dut2_as[2],'neighbor':dut1_dut2_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut1_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    #dict1 = {'vrf_name':'default','local_as':dut1_as[1],'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
    #dict2 = {'vrf_name':'default','local_as':dut2_as[1],'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
    #parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    ###############################################################################################################################
    #port_api.noshutdown(data.dut1, ['Vlan2','Vlan3'])

#@pytest.mark.depends('test_VrfFun001_06')
def test_VrfFun_20_24_25_32_33_44_45(vrf_fixture_tc_20_24_25_32_33_44_45):

    st.log('#######################################################################################################################')
    st.log('######------FtRtVrfFun020: IPv4 static route leak from non-default vrf to another non-default vrf-----######')
    st.log('######------FtRtVrfFun024: IPv6 static route leak from non-default vrf to another non-default vrf-----######')
    st.log('######------FtRtVrfFun025: Import same route from VRF A to VRF B, C and D -----######')
    st.log('#######################################################################################################################')

    result = 0
    #port_api.shutdown(data.dut1, ['Vlan2','Vlan3'])
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[0],'remote_as':dut2_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[0],'remote_as':dut1_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut2_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut1_as[1],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    #import_interface = data.d2_dut_ports[0]+'(vrf '+vrf_name[0]+')'
    ip_api.show_ip_route(data.dut2, family="ipv4", shell="sonic", vrf_name=vrf_name[1])
    ip_api.show_ip_route(data.dut2, family="ipv6", shell="sonic", vrf_name=vrf_name[1])
    dict1 = {'vrf_name':vrf_name[2],'local_as':dut1_as[2],'neighbor':dut2_dut1_vrf_ip[0],'remote_as':dut2_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'vrf_name':vrf_name[2],'local_as':dut2_as[2],'neighbor':dut1_dut2_vrf_ip[0],'remote_as':dut1_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    dict1 = {'vrf_name':vrf_name[2],'local_as':dut1_as[2],'neighbor':dut2_dut1_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut2_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    dict2 = {'vrf_name':vrf_name[2],'local_as':dut2_as[2],'neighbor':dut1_dut2_vrf_ipv6[0],'addr_family':'ipv6','remote_as':dut1_as[2],'config_type_list':['import_vrf'],'import_vrf_name':vrf_name[0]}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
    #import_interface = data.d2_dut_ports[0]+'(vrf '+vrf_name[0]+')'
    ip_api.show_ip_route(data.dut2, family="ipv4", shell="sonic", vrf_name=vrf_name[2])
    ip_api.show_ip_route(data.dut2, family="ipv6", shell="sonic", vrf_name=vrf_name[2])
    if not loc_lib.verify_bgp(ve = '1',ip = 'ipv4'):
        st.log('IPv4 BGP session on VRF-102 did not come up')
        result += 1
    if not loc_lib.verify_bgp(ve = '1',ip = 'ipv6'):
        st.log('IPv6 BGP session on VRF-102 did not come up')
        result += 1
    if not loc_lib.verify_bgp(pc = '1',ip = 'ipv4'):
        st.log('IPv4 BGP session on VRF-103 did not come up')
        result += 1
    if not loc_lib.verify_bgp(pc = '1',ip = 'ipv6'):
        st.log('IPv6 BGP session on VRF-103 did not come up')
        result += 1
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('Static route between VRFs failed for VRf-101, VRF-102 and VRF-103')
        #debug_bgp_vrf()
        st.report_fail('test_case_failed')

#@pytest.mark.depends('test_VrfFun001_06')
def test_VrfFun_05_50():

    st.log('######################################################################################################################')
    st.log('######------FtRtVrfFun005 Configure overlapping IP addresses belonging to different VRFs -----######')
    st.log('######------FtRtVrfFun050	Verify non-default vrf after cold reboot -----######')
    st.log('#######################################################################################################################')

    result = 0
    if not loc_lib.retry_api(loc_lib.verify_bgp, ve = '1',ip = 'ipv4'):
        st.log('IPv4 BGP session on VRF-102 did not come up')
        result += 1
    if not loc_lib.retry_api(loc_lib.verify_bgp, ve = '1',ip = 'ipv6'):
        st.log('IPv6 BGP session on VRF-102 did not come up')
        result += 1
    if not loc_lib.retry_api(loc_lib.verify_bgp, pc = '1',ip = 'ipv4'):
        st.log('IPv4 BGP session on VRF-103 did not come up')
        result += 1
    if not loc_lib.retry_api(loc_lib.verify_bgp, pc = '1',ip = 'ipv6'):
        st.log('IPv6 BGP session on VRF-103 did not come up')
        result += 1
    reboot_api.config_save(data.dut1)
    reboot_api.config_save(data.dut1,shell='vtysh')
    st.reboot(data.dut1, 'fast')
    st.log('Waiting for the sessions to come up')
    st.wait(40)
    if not loc_lib.retry_api(loc_lib.verify_bgp, ve = '1',ip = 'ipv4'):
        st.log('IPv4 BGP session on VRF-102 did not come up')
        result += 1
    if not loc_lib.retry_api(loc_lib.verify_bgp, ve = '1',ip = 'ipv6'):
        st.log('IPv6 BGP session on VRF-102 did not come up')
        result += 1
    if not loc_lib.retry_api(loc_lib.verify_bgp, pc = '1',ip = 'ipv4'):
        st.log('IPv4 BGP session on VRF-103 did not come up')
        result += 1
    if not loc_lib.retry_api(loc_lib.verify_bgp, pc = '1',ip = 'ipv6'):
        st.log('IPv6 BGP session on VRF-103 did not come up')
        result += 1
    if result == 0:
        st.report_pass('test_case_passed')
    else:
        st.log('Save and reload with VRF configuration failed')
        loc_lib.debug_bgp_vrf()
        st.report_fail('test_case_failed')
