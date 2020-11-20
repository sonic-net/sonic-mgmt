###############################################################################
#Script Title : BGP Dynamic Discovery and BGP unnumbered
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com

###############################################################################

import pytest
from spytest import st,utils
import utilities.common as utils
from spytest.tgen.tg import *
from spytest.tgen.tgen_utils import *

from dyndis_vars import * #all the variables used for the testcases
from dyndis_vars import data
import dyndis_lib as loc_lib
from utilities import parallel

import apis.routing.ip as ip_obj
import apis.routing.bgp as bgp_obj
import apis.routing.arp as arp_obj
import apis.routing.bfd as bfd_obj
import apis.system.port as port_obj
import apis.system.basic as basic_obj
import apis.system.reboot as reboot_obj

from spytest.tgen.tg import *
from spytest.tgen.tgen_utils import *


#Topology:
#------#TG#----(2links)----#DUT1#----(4links)----#DUT2#----(2links)-----#TG#---------#

def initialize_topology():
    st.log("Script Starts Here!. Initialize......................................................................................")
    vars = st.ensure_min_topology("D1D2:4","D2D3:4","D1T1:2", "D3T1:2")
    data.dut_list = st.get_dut_names()
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    data.dut3 = data.dut_list[2]
    utils.exec_all(True,[[bgp_obj.enable_docker_routing_config_mode,data.dut1], [bgp_obj.enable_docker_routing_config_mode,data.dut2], [bgp_obj.enable_docker_routing_config_mode,data.dut3]])
    data.d1_d2_ports = [vars.D1D2P1,vars.D1D2P2,vars.D1D2P3,vars.D1D2P4]
    data.d2_d1_ports = [vars.D2D1P1,vars.D2D1P2,vars.D2D1P3,vars.D2D1P4]
    data.d2_d3_ports = [vars.D2D3P1,vars.D2D3P2,vars.D2D3P3,vars.D2D3P4]
    data.d3_d2_ports = [vars.D3D2P1,vars.D3D2P2,vars.D3D2P3,vars.D3D2P4]
    data.dut1_tg_ports = [vars.D1T1P1,vars.D1T1P2]
    data.dut3_tg_ports = [vars.D3T1P1,vars.D3T1P2]
    data.tg_dut1_ports = [vars.T1D1P1,vars.T1D1P2]
    data.tg_dut3_ports = [vars.T1D3P1,vars.T1D3P2]
    data.tg = tgen_obj_dict[vars['tgen_list'][0]]
    data.tg_dut1_p1 = data.tg.get_port_handle(vars.T1D1P1)
    data.tg_dut3_p1 = data.tg.get_port_handle(vars.T1D3P1)
    data.tg_dut1_p2 = data.tg.get_port_handle(vars.T1D1P2)
    data.tg_dut3_p2 = data.tg.get_port_handle(vars.T1D3P2)
    data.d1_stream_list = {}
    data.d1_stream_list_vrf = {}
    data.d3_stream_list = {}
    if 'ixia' in vars['tgen_list'][0]:
        data.tgen_type='ixia'
        data.delay_factor = 2
    else:
        data.tgen_type = 'stc'
        data.delay_factor = 1

@pytest.fixture(scope='module', autouse = True)
def prologue_epilogue():
    initialize_topology()
    loc_lib.tg_streams()
    loc_lib.module_config()
    global bgp_cli_type
    bgp_cli_type = st.get_ui_type()
    if bgp_cli_type == 'click':
        bgp_cli_type = 'vtysh'
    # import pdb; pdb.set_trace()
    # import code; code.interact(local=globals())
    yield
    #loc_lib.module_unconfig()
    #loc_lib.reset_streams()

@pytest.fixture(scope="function")
def fixture_test_03_04_08_18_24(request,prologue_epilogue): 
    yield
    st.log('Unconfigure BFD on BGP unnumbered session')
    dict1 = {'config':'no', 'local_as':dut1_as,'config_type_list': ['bfd'],'interface': 'PortChannel1','remote_as':dut2_as}
    dict2 = {'config':'no', 'local_as':dut2_as,'config_type_list': ['bfd'],'interface': 'PortChannel1','remote_as':dut1_as}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])

@pytest.mark.sanity
def test_03_04_08_18_24(fixture_test_03_04_08_18_24):

    ###########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun003 - Verify BGP unnumbered and listen range over port channel')
    pc_dut1_linklocal = ip_obj.get_link_local_addresses(dut = data.dut1, interface = 'PortChannel1')
    if len(pc_dut1_linklocal) == 0:
        st.log("Link local address not present over port channel")
        result += 1
    else:
        if not arp_obj.verify_ndp(dut = data.dut2, inet6_address = pc_dut1_linklocal[0]):
            st.error("Failed to resolve NDP for link local address over portchannel")
            result += 1
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = ['PortChannel1','*'+dut3_dut2_ipv6[0]], state='Established', retry_count= 10, delay= 13):
        st.error("Failed to form BGP unnumbered and Dynamic neighbor session over portchannel")
        ip_obj.ping(data.dut2, dut3_dut2_ipv6[0],family='ipv6', count = 2)
        result += 1
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, 10, data.dut2, family='ipv4', shell=bgp_cli_type, neighbor = '*'+dut3_dut2_ip[0], state='Established'):
        st.error("Failed to form Dynamic IPv4 BGP neighbor session over portchannel")
        ip_obj.ping(data.dut2, dut3_dut2_ip[0],family='ipv4', count = 2)
        result += 1
    pc_dut2_linklocal = ip_obj.get_link_local_addresses(dut = data.dut2, interface = 'PortChannel1')
    if len(pc_dut2_linklocal) == 0:
        st.error("Link local address not present over port channel")
        result += 1
    else:
        if not loc_lib.retry_api(ip_obj.verify_ip_route, data.dut1, type='B', nexthop = pc_dut2_linklocal[0], interface = 'PortChannel1',ip_address = dut3_tg1_network_v4[0],family = "ipv4",retry_count= 5, delay= 10):
            st.error('IPv4 routes over portchannel not learnt usingBGP unnumbered')
            loc_lib.debug_failure()
            result += 1
        if not loc_lib.retry_api(ip_obj.verify_ip_route, data.dut1, type='B', nexthop = pc_dut2_linklocal[0], interface = 'PortChannel1',ip_address = dut3_tg1_network_v6[0],family = "ipv6",retry_count= 5, delay= 10):
            st.error('IPv4 routes over portchannel not learnt usingBGP unnumbered')
            loc_lib.debug_failure()
            result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], count = 2,retry_count= 5,
                             delay= 10, source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ipv6[0], family='ipv6', count = 2,
                             retry_count= 5, delay= 10, source_ip=dut1_tg_ipv6[0]):
        st.error('IPv6 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over portchannel with BGP unnumbered and Dynamic Discovery failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun003','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun003','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    ##########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun018 - Verify BGP unnumbered session with redistribute connected')
    loc_lib.redistribute_routes(config = 'no')
    loc_lib.redistribute_routes()
    if not ip_obj.ping(data.dut1, dut3_tg_ip[0], count = 2, source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ipv6[0], family='ipv6', count = 2, source_ip=dut1_tg_ipv6[0]):
        st.error('IPv6 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over vlan with BGP unnumbered and Dynamic Discovery failed after removing and adding redistribute connected')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun018','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun018','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    #########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun004 - Verify BGP unnumbered along with listen limit over port channel')
    st.log("Reduce the limit and verify the neighbor is removed")
    bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as, limit = 1)
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, 10, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = 'PortChannel1', state='Established'):
        st.error("Failed to form Dynamic neighbor session over portchannel after reducing the limit to 1")
        result += 1
    st.log("Increase the limit and verify the neighbor")
    bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as, limit = 2)
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, 10, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = ['PortChannel1','*'+dut3_dut2_ipv6[0]], state='Established'):
        st.error("Failed to form BGP unnumbered and Dynamic neighbor session over portchannel")
        ip_obj.ping(data.dut2, dut3_dut2_ipv6[0], family='ipv6', count = 2)
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun004','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun004','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    #########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun024 - Verify BFD on BGP unnumbered session')
    st.log('Configure BFD on BGP unnumbered session')
    pc_dut2_linklocal = ip_obj.get_link_local_addresses(dut = data.dut2, interface = 'PortChannel1')
    dict1 = {'config':'yes', 'local_as':dut1_as,'config_type_list': ['bfd'],'interface': 'PortChannel1','remote_as':dut2_as}
    dict2 = {'config':'yes', 'local_as':dut2_as,'config_type_list': ['bfd'],'interface': 'PortChannel1','remote_as':dut1_as}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    if not loc_lib.retry_api(bfd_obj.verify_bfd_peer, data.dut2, peer = pc_dut1_linklocal[0], local_addr = pc_dut2_linklocal[0], interface = 'PortChannel1', status= 'up', retry_count= 2, delay= 2):
        st.error('Failed to form BFD session over BGP unnumbered session')
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun024','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun024','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    #########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun008 - Verify BGP unnumbered session along with route map')
    st.log('Add a route map to block all IPv6 addresses')
    ip_obj.config_ip_prefix_list(data.dut2, 'bgp-prefix-list', tg_dut3_ipv6[0]+'/64', family = 'ipv6', action='deny', seq_num='10')
    ip_obj.config_route_map_match_ip_address(data.dut2, 'bgp-route-map', 'deny', '10','bgp-prefix-list','ipv6', type = 'prefix-list')
    bgp_obj.config_bgp(dut = data.dut2, local_as = dut2_as, config = 'yes', addr_family ='ipv6', config_type_list=["routeMap"], routeMap='bgp-route-map', diRection='in', neighbor='PortChannel1')
    pc_dut2_linklocal = ip_obj.get_link_local_addresses(dut = data.dut2, interface = 'PortChannel1')
    if len(pc_dut2_linklocal) == 0:
        st.error("Link local address not present over port channel")
        result+=1
    else:
        if utils.poll_wait(ip_obj.verify_ip_route, 2, data.dut3, type='B', nexthop = pc_dut2_linklocal[0], interface = 'PortChannel3', ip_address = dut1_tg1_network_v6[0], family = "ipv6") == False:
            st.log('As expected, All IPv6 BGP routes are denied after applying route map on BGP unnumbered session')
        else:
            st.error('IPv6 BGP routes not denied after applying route map')
            loc_lib.debug_failure()
            result += 1
    st.log('Remove the route map and verify traffic')
    bgp_obj.config_bgp(dut = data.dut2, local_as = dut2_as, config = 'no', addr_family ='ipv6', config_type_list=["routeMap"], routeMap='bgp-route-map', diRection='in', neighbor='PortChannel1')
    bgp_obj.activate_bgp_neighbor(data.dut2,dut2_as,'PortChannel1','ipv6',remote_asn = dut1_as)
    bgp_obj.activate_bgp_neighbor(data.dut2,dut2_as,'PortChannel1','ipv4',remote_asn = dut1_as)
    ip_obj.config_ip_prefix_list(data.dut2, 'bgp-prefix-list', tg_dut3_ipv6[0]+'/64', family = 'ipv6', action='deny', config = 'no', seq_num='10')
    ip_obj.config_route_map_mode(data.dut2, 'bgp-route-map', 'deny', '10', config='no')
    if not ip_obj.ping(data.dut1, dut3_tg_ip[0], count = 2, source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ipv6[0], family='ipv6', count = 2, source_ip=dut1_tg_ipv6[0]):
        st.error('IPv6 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over portchannel with BGP unnumbered and Dynamic Discovery failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun008','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun008','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

def test_10_16():

    ########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun010 - Verify BGP unnumbered along with listen range and modify the session to static neighbor')
    st.log("Remove listen range from DUT2")
    bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as, neighbor_address = '2.0.1.0', subnet = dut3_dut2_ip_subnet, peer_grp_name = 'd2d3_v4_peer', limit = 2, config = 'no')
    bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as, neighbor_address = '2001::', subnet = dut3_dut2_ipv6_subnet, peer_grp_name = 'd2d3_v6_peer', limit = 2, config = 'no')
    bgp_obj.config_bgp(dut = data.dut2, local_as = dut2_as, config_type_list = ['router_id'], router_id = dut2_router_id)
    bgp_obj.create_bgp_peergroup(data.dut2, dut2_as,'d2d3_v4_peer',dut3_as,60,180,None,'default','ipv4',neighbor_ip = dut3_dut2_ip[0])
    bgp_obj.create_bgp_peergroup(data.dut2, dut2_as,'d2d3_v6_peer',dut3_as,60,180,None,'default','ipv6',neighbor_ip = dut3_dut2_ipv6[0])
    bgp_obj.activate_bgp_neighbor(data.dut2,dut2_as,dut3_dut2_ip[0],'ipv4',remote_asn = dut3_as)
    bgp_obj.activate_bgp_neighbor(data.dut2,dut2_as,dut3_dut2_ipv6[0],'ipv6',remote_asn = dut3_as)
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv4', shell=bgp_cli_type, neighbor = dut3_dut2_ip[0], state='Established', retry_count= 10, delay= 13):
        st.error("Failed to form Normal IPv4 BGP neighbor session over port channel after removing dynamic neighbor")
        ip_obj.ping(data.dut2, dut3_dut2_ip[0], family='ipv4', count = 2)
        result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], count = 2, retry_count= 5,
                             delay= 10, source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ipv6[0], family='ipv6', count = 2,
                             retry_count= 5, delay= 10, source_ip=dut1_tg_ipv6[0]):
        st.error('IPv6 Ping from DUT1 to DUT3 failed')
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun010','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun010','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

   #########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun015 - Verify BGP unnumbered session after adding and removing BGP configuration globally')
    st.log('Remove BGP configuration on DUT2')
    port_obj.noshutdown(data.dut1, [data.d1_d2_ports[0],data.d1_d2_ports[1],data.d1_d2_ports[2],data.d1_d2_ports[3]])
    port_obj.noshutdown(data.dut2, [data.d2_d1_ports[0],data.d2_d1_ports[1],data.d2_d1_ports[2],data.d2_d1_ports[3]])
    port_obj.noshutdown(data.dut2, [data.d2_d3_ports[0],data.d2_d3_ports[1],data.d2_d3_ports[2],data.d2_d3_ports[3]])
    port_obj.noshutdown(data.dut3, [data.d3_d2_ports[0],data.d3_d2_ports[1],data.d3_d2_ports[2],data.d3_d2_ports[3]])
    bgp_obj.config_bgp(dut = data.dut2, config = 'no', local_as = dut2_as, removeBGP = 'yes', config_type_list = ['removeBGP'])
    st.log('Configure BGP Unnumbered peer on DUT2')
    bgp_obj.config_bgp(dut = data.dut2, local_as = dut2_as, config_type_list = ['router_id'], router_id = dut2_router_id)
    bgp_obj.config_bgp(dut = data.dut2, addr_family = 'ipv6', local_as = dut2_as, remote_as = dut1_as, config_type_list = ['remote-as'], interface = 'PortChannel1', neighbor = 'PortChannel1')
    bgp_obj.activate_bgp_neighbor(data.dut2,dut2_as,'PortChannel1','ipv6',remote_asn = dut1_as)
    bgp_obj.activate_bgp_neighbor(data.dut2,dut2_as,'PortChannel1','ipv4',remote_asn = dut1_as)
    st.banner('Configure peergrougs on DUT2')
    bgp_obj.create_bgp_peergroup(data.dut2, dut2_as,'d2d3_v4_peer',dut3_as,60,180,None,'default','ipv4')
    bgp_obj.create_bgp_peergroup(data.dut2, dut2_as,'d2d3_v6_peer',dut3_as,60,180,None,'default','ipv6')
    st.banner('Configure BGP listen range on DUT2 for Ipv4 and Ipv6 addresses')
    bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as, neighbor_address = '2.0.1.0', subnet = dut3_dut2_ip_subnet, peer_grp_name = 'd2d3_v4_peer', limit = 2, config = 'yes')
    bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as, neighbor_address = '2001::', subnet = dut3_dut2_ipv6_subnet, peer_grp_name = 'd2d3_v6_peer', limit = 2, config = 'yes')
    bgp_obj.config_address_family_redistribute(dut = data.dut2, local_asn = dut2_as,mode_type = 'ipv4',mode = 'unicast',value = 'connected',config ='yes')
    bgp_obj.config_address_family_redistribute(dut = data.dut2, local_asn = dut2_as,mode_type = 'ipv6',mode = 'unicast',value = 'connected',config ='yes')
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = '*'+dut3_dut2_ipv6[0], state='Established', retry_count= 10, delay= 13):
        st.error("Failed to form BGP Dynamic neighbor session")
        ip_obj.ping(data.dut2, dut3_dut2_ipv6[0],family='ipv6', count = 2)
        result += 1
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, 10, data.dut2, family='ipv4', shell=bgp_cli_type, neighbor = '*'+dut3_dut2_ip[0], state='Established'):
        st.error("Failed to form Dynamic IPv4 BGP neighbor session over portchannel")
        ip_obj.ping(data.dut2, dut3_dut2_ip[0],family='ipv4', count = 2)
        result += 1
    st.log('Waiting for routes to stabilize')
    st.wait(10)
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], count = 2, retry_count= 5,
                             delay= 10, source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ipv6[0], family='ipv6', count = 2,
                             retry_count= 5, delay= 10, source_ip=dut1_tg_ipv6[0]):
        st.error('IPv6 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over port channel after clear IPv4 and IPv6 neighbors')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun016','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun016','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

def test_02_09():

    ##########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun002 - Verify BGP unnumbered and listen range over vlan')
    loc_lib.base_interfaces(ve = '1')
    loc_lib.bgp_unnumbered(ve = '1')
    port_obj.shutdown(data.dut1, [data.d1_d2_ports[0],data.d1_d2_ports[1]])
    st.log('Get the link local IPv6 addresses')
    ve_dut1_linklocal = ip_obj.get_link_local_addresses(dut = data.dut1, interface = 'Vlan'+dut1_dut2_vlan)
    if len(ve_dut1_linklocal) == 0:
        st.error("Link local address not present over vlan")
        result+=1
    else:
        if not arp_obj.verify_ndp(dut = data.dut2, inet6_address = ve_dut1_linklocal[0]):
            st.error("Failed to resolve NDP for link local address over vlan")
            result += 1
        if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = ['Vlan'+dut1_dut2_vlan,'*'+dut3_dut2_ipv6[0]], state='Established', retry_count= 10, delay= 13):
            st.error("Failed to form BGP unnumbered session using IPv6 link local address over vlan")
            ip_obj.ping(data.dut2, dut3_dut2_ipv6[0], family='ipv6', count = 2)
            result += 1
    ve_dut2_linklocal = ip_obj.get_link_local_addresses(dut = data.dut2, interface = 'Vlan'+dut1_dut2_vlan)
    if len(ve_dut2_linklocal) == 0:
        st.error("Link local address not present over vlan")
        result+=1
    else:
        if not ip_obj.verify_ip_route(data.dut1, type='B', nexthop = ve_dut2_linklocal[0], interface = 'Vlan'+dut1_dut2_vlan, ip_address = dut3_tg1_network_v4[0],family = "ipv4"):
            st.error('IPv4 routes over vlan not learnt using BGP unnumbered')
            loc_lib.debug_failure()
            result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ip[0], count = 2, source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ipv6[0], family='ipv6', count = 2, source_ip=dut1_tg_ipv6[0]):
        st.error('IPv6 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over vlan with BGP unnumbered and Dynamic Discovery failed')
        loc_lib.debug_failure()
        result += 1
    port_obj.noshutdown(data.dut1, [data.d1_d2_ports[0],data.d1_d2_ports[1]])
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun002','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun002','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

def test_13_14_15():

    #########################################################################################################################################
    # import pdb; pdb.set_trace()
    # import code; code.interact(local=globals())
    result = 0
    st.banner('FtOpSoRoDynFun013 - Verify BGP unnumbered after enabling and disabling IPv6 at the interface')
    st.banner('FtOpSoRoDynFun015 - Verify BGP session after clear ndp')
    port_obj.shutdown(data.dut1, [data.d1_d2_ports[2], data.d1_d2_ports[3]])
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = 'PortChannel1', state='Established', retry_count= 10, delay= 13):
        st.error("Failed to form BGP unnumbered session over portchannel")
        result += 1
    st.log('Disable auto generated link local on port channel')
    utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, data.dut1, 'PortChannel1', 'disable'],[ip_obj.config_interface_ip6_link_local, data.dut2, 'PortChannel1', 'disable']])
    st.log('Enable auto generated link local back')
    utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, data.dut1, 'PortChannel1', 'enable'],[ip_obj.config_interface_ip6_link_local, data.dut2, 'PortChannel1', 'enable']])
    st.log('Clear ndp on DUT2')
    arp_obj.clear_ndp_table(data.dut2)
    st.log('Wait for ndp entires to be learned back')
    st.wait(5)
    pc_dut1_linklocal = ip_obj.get_link_local_addresses(dut = data.dut1, interface = 'PortChannel1')
    if len(pc_dut1_linklocal) == 0:
        st.error("Link local address not present over port channel")
        result+=1
    else:
        if not loc_lib.retry_api(arp_obj.verify_ndp, data.dut2, inet6_address = pc_dut1_linklocal[0], retry_count= 2, delay= 5):
            st.error("Failed to resolve NDP for link local address over portchannel")
            result += 1
    pc_dut2_linklocal = ip_obj.get_link_local_addresses(dut = data.dut2, interface = 'PortChannel1')
    if len(pc_dut2_linklocal) == 0:
        st.error("Link local address not present over port channel")
        result+=1
    else:
        if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = 'PortChannel1', state='Established', retry_count= 10, delay= 13):
            st.error("Failed to form BGP unnumbered session using IPv6 link local address over vlan")
            ip_obj.ping(data.dut2, dut3_dut2_ipv6[0], family='ipv6', count = 2)
            result += 1
        if not loc_lib.retry_api(ip_obj.verify_ip_route, data.dut1, type='B', nexthop = pc_dut2_linklocal[0], interface = 'PortChannel1',ip_address = dut3_tg1_network_v4[0],family = "ipv4", retry_count= 2, delay= 5) :
            st.error('IPv4 routes over portchannel not learnt usingBGP unnumbered')
            loc_lib.debug_failure()
            result += 1
        if not loc_lib.retry_api(ip_obj.verify_ip_route, data.dut1, type='B', nexthop = pc_dut2_linklocal[0], interface = 'PortChannel1',ip_address = dut3_tg1_network_v6[0],family = "ipv6", retry_count= 2, delay= 5):
            st.error('IPv4 routes over portchannel not learnt usingBGP unnumbered')
            loc_lib.debug_failure()
            result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ip[0], count = 2, source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ipv6[0], family='ipv6', count = 2, source_ip=dut1_tg_ipv6[0]):
        st.error('IPv6 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over port channel after disable and enabling link local at the interface failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun013','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun013','test_case_failed')
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun015','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun015','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    #########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun014 - Verify BGP unnumbered session after clear bgp neighbor')
    st.log('Clear BGP ipv4 and IPv6 neighbor')
    port_obj.noshutdown(data.dut1, [data.d1_d2_ports[2], data.d1_d2_ports[3]])
    bgp_obj.clear_ipv6_bgp_vtysh(data.dut2, value="*")
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = '*'+dut3_dut2_ipv6[0], state='Established', retry_count= 10, delay= 13):
        st.error("Failed to form BGP unnumbered and Dynamic neighbor session over portchannel")
        result += 1
    bgp_obj.clear_ip_bgp_vtysh(data.dut2, value="*")
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv4', shell=bgp_cli_type, neighbor = '*'+dut3_dut2_ip[0], state='Established', retry_count= 10, delay= 13):
        st.error("Failed to form Dynamic IPv4 BGP neighbor session over portchannel")
        result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ip[0], count = 2, source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ipv6[0], family='ipv6', count = 2, source_ip=dut1_tg_ipv6[0]):
        st.error('IPv6 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over port channel after clear IPv4 and IPv6 neighbors')
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun014','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun014','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def fixture_test_06_07_11(request,prologue_epilogue):
    yield
    ip_obj.delete_ip_interface(dut = data.dut1, interface_name='PortChannel1',ip_address = dut1_link_local_addr, subnet = '64', family = "ipv6")
    utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, data.dut1, 'PortChannel1', 'enable'],[ip_obj.config_interface_ip6_link_local, data.dut2, 'PortChannel1', 'enable']])

def test_06_07_11(fixture_test_06_07_11):

    #########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun006 - Verify BGP session with manually configured link local along with listen range')
    st.log('Disable auto generated link local and Manually configure link local addresses on the port channel')
    utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, data.dut1, 'PortChannel1', 'disable'],[ip_obj.config_interface_ip6_link_local, data.dut2, 'PortChannel1', 'disable']])
    utils.exec_all(True, [[ip_obj.config_ip_addr_interface,data.dut1,'PortChannel1', dut1_link_local_addr,'64', "ipv6", 'add'],[ip_obj.config_ip_addr_interface,data.dut2,'PortChannel1', dut2_link_local_addr, '64', "ipv6", 'add']])
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over portchannel with BGP unnumbered and Dynamic Discovery failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun006','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun006','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    #########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun007 - Verify BGP session with manually configured link local along with listen limit')
    st.log("Reduce the limit and verify the neighbor is removed")
    bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as, limit = 1)
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = 'PortChannel1', state='Established', retry_count= 2, delay= 5):
        st.error("Failed to form Dynamic neighbor session over portchannel after reducing the limit to 1")
        result += 1
    st.log("Increase the limit and verify the neighbor")
    bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as, limit = 2)
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = ['PortChannel1','*'+dut3_dut2_ipv6[0]], state='Established', retry_count= 2, delay= 5):
        st.error("Failed to form BGP unnumbered and Dynamic neighbor session over portchannel")
        ip_obj.ping(data.dut2, dut3_dut2_ipv6[0], family='ipv6', count = 2)
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun007','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun007','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    #########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun011 - Verify BGP session with manually configured link local on the other side')
    st.log('Enable the interfaces to take auto generated link local address and remove manually configured link local address from DUT2')
    ip_obj.delete_ip_interface(dut = data.dut2,interface_name='PortChannel1',ip_address = dut2_link_local_addr, subnet = '64', family = "ipv6")
    ip_obj.config_interface_ip6_link_local(dut = data.dut2, interface_list = 'PortChannel1', action ='enable')
    pc_dut2_linklocal = ip_obj.get_link_local_addresses(dut = data.dut2, interface = 'PortChannel1')
    if len(pc_dut2_linklocal) == 0:
        st.error("Link local address not present over port channel")
        result+=1
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over portchannel with BGP unnumbered and Dynamic Discovery failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun011','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun011','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def fixture_test_01_12_05(request,prologue_epilogue):
    yield
    st.log('Unconfig for testcase - FtOpSoRoDynFun005 - Verify BGP unnumbered along with peer group')
    st.log('Unconfig physical and vlan interface configuration')
    loc_lib.bgp_unnumbered(phy = '1', config = 'no')
    loc_lib.base_interfaces(phy = '1', config = 'no')
    loc_lib.bgp_unnumbered(ve = '1', config = 'no')
    loc_lib.base_interfaces(ve = '1', config = 'no')

def test_01_12_05(fixture_test_01_12_05):

    ##########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun001 - Verify BGP unnumbered and listen range over physical interface')
    port_obj.shutdown(data.dut1, [data.d1_d2_ports[0],data.d1_d2_ports[1], data.d1_d2_ports[3]])
    loc_lib.base_interfaces(phy = '1')
    loc_lib.bgp_unnumbered(phy = '1')
    st.log('Get the link local IPv6 addresses')
    phy_dut1_linklocal = ip_obj.get_link_local_addresses(dut = data.dut1, interface = data.d1_d2_ports[2])
    if len(phy_dut1_linklocal) == 0:
        st.error("Link local address not present over physical interface")
        result+=1
    else:
        if not arp_obj.verify_ndp(dut = data.dut2, inet6_address = phy_dut1_linklocal[0]):
            st.error("Failed to resolve NDP for link local address over physical interface")
            result += 1
        if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = [data.d2_d1_ports[2],'*'+dut3_dut2_ipv6[0]], state='Established', retry_count= 10, delay= 13):
            st.error("Failed to form BGP unnumbered and Dynamic neighbor session over physical interface")
            ip_obj.ping(data.dut2, dut3_dut2_ipv6[0], family='ipv6', count = 2)
            result += 1
    phy_dut2_linklocal = ip_obj.get_link_local_addresses(dut = data.dut2, interface = data.d2_d1_ports[2])
    if len(phy_dut2_linklocal) == 0:
        st.error("Link local address not present over physical interface")
        result+=1
    else:
        if not utils.poll_wait(ip_obj.verify_ip_route, 5, data.dut1, type='B', nexthop = phy_dut2_linklocal[0], interface = data.d1_d2_ports[2],ip_address = dut3_tg1_network_v4[0],family = "ipv4"):
            st.error('IPv4 routes over physical interface not learnt using BGP unnumbered')
            loc_lib.debug_failure()
            result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ip[0], count = 2, source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ipv6[0], family='ipv6', count = 2, source_ip=dut1_tg_ipv6[0]):
        st.error('IPv6 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic()
    port_obj.noshutdown(data.dut1, [data.d1_d2_ports[0],data.d1_d2_ports[1],data.d1_d2_ports[2],data.d1_d2_ports[3]])
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over physical interface with BGP unnumbered and Dynamic Discovery failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun001','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun001','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    ##########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun012 - Verify ECMP with BGP unnumbered')
    st.log('Enable physical and vlan interfaces, enable port channel interfaces an verify traffic takes port channel')
    st.log('Configure ebgp multi-path under IPv6 address family for ECMP')
    dict1 = {'addr_family':'ipv6','local_as':dut1_as,'config_type_list': ['max_path_ebgp'], 'max_path_ebgp': '3'}
    dict2 = {'addr_family':'ipv6','local_as':dut2_as,'config_type_list': ['max_path_ebgp'], 'max_path_ebgp': '3'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    st.log('Configure ebgp multi-path under IPv4 address family for ECMP')
    dict1 = {'addr_family':'ipv4','local_as':dut1_as,'config_type_list': ['max_path_ebgp'], 'max_path_ebgp': '3'}
    dict2 = {'addr_family':'ipv4','local_as':dut2_as,'config_type_list': ['max_path_ebgp'], 'max_path_ebgp': '3'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    if not utils.poll_wait(ip_obj.verify_ip_route, 5, data.dut1, type='B', nexthop = phy_dut2_linklocal[0], interface = data.d1_d2_ports[2],ip_address = dut3_tg1_network_v4[0],family = "ipv4"):
        st.error("Failed to form BGP unnumbered and Dynamic neighbor session over portchannel in ECMP")
        loc_lib.debug_failure()
        result += 1
    if not utils.poll_wait(ip_obj.verify_ip_route, 5, data.dut1, type='B', nexthop = phy_dut2_linklocal[0], interface = data.d1_d2_ports[2],ip_address = dut3_tg1_network_v6[0],family = "ipv6"):
        st.error("Failed to form BGP unnumbered and Dynamic neighbor session over portchannel in ECMP")
        loc_lib.debug_failure()
        result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ip[0], count = 2):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ipv6[0], family='ipv6', count = 2):
        st.error('IPv6 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic with BGP unnumbered and Dynamic Discovery failed after ebgp multi-path configuration')
        loc_lib.debug_failure()
        result += 1
    st.log('Unconfigure ebgp multi-path under IPv6 address family for ECMP')
    dict1 = {'config':'no','addr_family':'ipv6','local_as':dut1_as,'config_type_list': ['max_path_ebgp'], 'max_path_ebgp': '3'}
    dict2 = {'config':'no','addr_family':'ipv6','local_as':dut2_as,'config_type_list': ['max_path_ebgp'], 'max_path_ebgp': '3'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    st.log('Unonfigure ebgp multi-path under IPv6 address family for ECMP')
    dict1 = {'config':'no','addr_family':'ipv4','local_as':dut1_as,'config_type_list': ['max_path_ebgp'], 'max_path_ebgp': '3'}
    dict2 = {'config':'no','addr_family':'ipv4','local_as':dut2_as,'config_type_list': ['max_path_ebgp'], 'max_path_ebgp': '3'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    if not ip_obj.ping(data.dut1, dut3_tg_ip[0], count = 2,source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ipv6[0], family='ipv6', count = 2, source_ip=dut1_tg_ipv6[0]):
        st.error('IPv6 Ping from DUT1 to DUT3 failed')
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun012','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun012','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    ##########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun005 - Verify BGP unnumbered along with peer group')
    st.log('Create peer groups and add neighbors for BGP unnumbered sessions')
    bgp_obj.create_bgp_peergroup(data.dut1, dut1_as,'d1d2_v6_peer',dut2_as,neighbor_ip = data.d1_d2_ports[2])
    bgp_obj.create_bgp_peergroup(data.dut2, dut2_as,'d1d2_v6_peer',dut1_as,neighbor_ip = data.d2_d1_ports[2])
    bgp_obj.activate_bgp_neighbor(data.dut1,dut1_as,data.d1_d2_ports[2],'ipv6',remote_asn = dut2_as)
    bgp_obj.activate_bgp_neighbor(data.dut2,dut2_as,data.d2_d1_ports[2],'ipv6',remote_asn = dut1_as)
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = data.d2_d1_ports[2], state='Established', retry_count= 10, delay= 13):
        st.error("Failed to form BGP unnumbered session using IPv6 link local address over physical interface")
        result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ip[0], count = 2, source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not ip_obj.ping(data.dut1, dut3_tg_ipv6[0], family='ipv6', count = 2, source_ip=dut1_tg_ipv6[0]):
        st.error('IPv6 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        st.error('IPv4 traffic over portchannel with BGP unnumbered and Dynamic Discovery failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun005','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun005','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def fixture_test_reboot_dynamic_niegh(request,prologue_epilogue):
    yield
    loc_lib.vrf_bgp_dynamic_neigh(config = 'no')
    loc_lib.vrf_bgp_unnumbered(config = 'no')
    loc_lib.config_vrf_base(config = 'no')

def test_reboot_dynamic_niegh():

    #################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynReb001 - Verify BGP unnumbererd and listen range on default and non default vrf after a fast reboot')
    loc_lib.config_vrf_base()
    loc_lib.vrf_tg_interfaces()
    loc_lib.tg_streams_vrf()
    loc_lib.vrf_bgp_unnumbered()
    vrf_dut1_linklocal = ip_obj.get_link_local_addresses(dut = data.dut1, interface = data.d1_d2_ports[3])
    loc_lib.vrf_bgp_dynamic_neigh()
    if len(vrf_dut1_linklocal) == 0:
        st.error("Link local address not present over VRF")
        result += 1
    else:
        if not arp_obj.verify_ndp(dut = data.dut2, inet6_address = vrf_dut1_linklocal[0]):
            st.error("Failed to resolve NDP for link local address over VRF")
            result += 1
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = [data.d2_d1_ports[3],'*'+dut3_dut2_ipv6[0]], state='Established',vrf = dut2_vrf, retry_count= 10, delay= 13):
        st.error("Failed to form BGP unnumbered and Dynamic neighbor session over non default VRF")
        ip_obj.ping(data.dut2, dut3_dut2_ipv6[0], family='ipv6', count = 2)
        result += 1
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv4', shell=bgp_cli_type, neighbor = '*'+dut3_dut2_ip[0], state='Established',vrf = dut2_vrf, retry_count= 10, delay= 13):
        st.error("Failed to form Dynamic IPv4 BGP neighbor session over non default VRF")
        ip_obj.ping(data.dut2, dut3_dut2_ip[0], family='ipv4', count = 2)
        result += 1
    vrf_dut2_linklocal = ip_obj.get_link_local_addresses(dut = data.dut2, interface = data.d2_d1_ports[3])
    if len(vrf_dut2_linklocal) == 0:
        st.error("Link local address not present over non default VRF")
        result += 1
    else:
        if not utils.poll_wait(ip_obj.verify_ip_route, 5, data.dut1, type='B', nexthop = vrf_dut2_linklocal[0], interface = data.d1_d2_ports[3],ip_address = dut3_tg1_network_v4_vrf[0],family = "ipv4", vrf_name = dut1_vrf):
            st.error('IPv4 routes over non default VRF not learnt using BGP unnumbered')
            loc_lib.debug_failure()
            result += 1
        if not utils.poll_wait(ip_obj.verify_ip_route, 5, data.dut1, type='B', nexthop = vrf_dut2_linklocal[0], interface = data.d1_d2_ports[3],ip_address = dut3_tg1_network_v6_vrf[0],family = "ipv6", vrf_name = dut1_vrf):
            st.error('IPv6 routes over non default VRF not learnt using BGP unnumbered')
            loc_lib.debug_failure()
            result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[1], interface = dut1_vrf, count = 2, retry_count= 5, delay= 10):
        st.error('IPv4 Ping from Vrf-red-DUT1 to Vrf-green-DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic_vrf()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over non default VRF with BGP unnumbered and Dynamic Discovery failed')
        result += 1

    #################################################################################################################################
    st.log("Save the running config in sonic and vtysh modes")
    reboot_obj.config_save(data.dut2)
    reboot_obj.config_save(data.dut2, 'vtysh')
    st.reboot(data.dut2, 'fast')
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = [data.d2_d1_ports[3],'*'+dut3_dut2_ipv6[0]], state='Established',vrf = dut2_vrf, retry_count= 10, delay= 13):
        st.error("Failed to form BGP unnumbered and IPv6 Dynamic neighbor BGP session over non default VRF")
        result += 1
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv4', shell=bgp_cli_type, neighbor = '*'+dut3_dut2_ip[0], state='Established',vrf = dut2_vrf, retry_count= 10, delay= 13):
        st.error("Failed to form Dynamic IPv4 BGP neighbor session over non default VRF")
        result += 1
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = 'PortChannel1', state='Established', retry_count= 10, delay= 13):
        st.error("Failed to form BGP unnumbered and Dynamic neighbor session over default VRF")
        result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[1], interface = dut1_vrf, count = 2, retry_count= 2, delay= 5):
        st.error('IPv4 Ping from Vrf-red-DUT1 to Vrf-green-DUT3 failed')
        result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], family='ipv4', count = 2,
                             retry_count= 5, delay= 5, source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic_vrf()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over non default VRF with BGP unnumbered and Dynamic Discovery failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over default VRF with BGP unnumbered and Dynamic Discovery failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynReb001','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynReb001','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

def test_config_reload_dynamic_neigh(fixture_test_reboot_dynamic_niegh):

    #################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynReb003 - Verify BGP unnumbererd and listen range on default and non default vrf after a config reload')
    reboot_obj.config_save(data.dut2)
    st.vtysh(data.dut2,"copy running startup")
    reboot_obj.config_reload(data.dut2)
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = [data.d2_d1_ports[3],'*'+dut3_dut2_ipv6[0]], state='Established',vrf = dut2_vrf, retry_count= 10, delay= 13):
        st.error("Failed to form BGP unnumbered and Dynamic neighbor session over non default VRF")
        result += 1
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv4', shell=bgp_cli_type, neighbor = '*'+dut3_dut2_ip[0], state='Established',vrf = dut2_vrf, retry_count= 10, delay= 13):
        st.error("Failed to form Dynamic IPv4 BGP neighbor session over non default VRF")
        result += 1
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = ['PortChannel1','*'+dut3_dut2_ipv6[0]], state='Established', retry_count= 10, delay= 13):
        st.error("Failed to form BGP unnumbered and Dynamic neighbor session over default VRF")
        result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[1], interface = dut1_vrf, count = 2, retry_count= 2, delay= 5):
        st.error('IPv4 Ping from Vrf-red-DUT1 to Vrf-green-DUT3 failed')
        result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], family='ipv4', count = 2,
                             retry_count= 2, delay= 5, source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic_vrf()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over non default VRF with BGP unnumbered and Dynamic Discovery failed')
        result += 1
    aggrResult = loc_lib.send_verify_traffic()
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over default VRF with BGP unnumbered and Dynamic Discovery failed')
        loc_lib.debug_failure()
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynReb003','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynReb003','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def fixture_test_17_22(request,prologue_epilogue):
    yield
    dict1 = {'config':'no','addr_family':'ipv6','local_as':dut1_as,'remote_as':dut2_as,'neighbor': dut2_dut1_ipv6[0],'config_type_list': ['nexthop_self']}
    dict2 = {'config':'no','addr_family':'ipv6','local_as':dut2_as,'remote_as':dut1_as,'neighbor': dut1_dut2_ipv6[0],'config_type_list': ['nexthop_self']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    dict1 = {'config':'no','addr_family':'ipv6','local_as':dut1_as,'remote_as':dut2_as,'neighbor': dut2_dut1_ipv6[0],'config_type_list': ['no_neigh'],'no_neigh':'no'}
    dict2 = {'config':'no','addr_family':'ipv6','local_as':dut2_as,'remote_as':dut1_as,'neighbor': dut1_dut2_ipv6[0],'config_type_list': ['no_neigh'],'no_neigh':'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    dict1 = {'config':'no','addr_family':'ipv4','local_as':dut1_as,'remote_as':dut2_as,'neighbor': dut2_dut1_ip[0],'config_type_list': ['activate','nexthop_self']}
    dict2 = {'config':'no','addr_family':'ipv4','local_as':dut2_as,'remote_as':dut1_as,'neighbor': dut1_dut2_ip[0],'config_type_list': ['activate','nexthop_self']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    dict1 = {'config':'no','addr_family':'ipv4','local_as':dut1_as,'remote_as':dut2_as,'neighbor': dut2_dut1_ip[0],'config_type_list': ['no_neigh'],'no_neigh':'no'}
    dict2 = {'config':'no','addr_family':'ipv4','local_as':dut2_as,'remote_as':dut1_as,'neighbor': dut1_dut2_ip[0],'config_type_list': ['no_neigh'],'no_neigh':'no'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])    
    utils.exec_all(True, [[ip_obj.config_ip_addr_interface,data.dut1,'PortChannel1', dut1_dut2_ipv6[0],'127','ipv6','remove'],[ip_obj.config_ip_addr_interface,data.dut2,'PortChannel1', dut2_dut1_ipv6[0], '127', 'ipv6', 'remove']])
    utils.exec_all(True, [[ip_obj.config_ip_addr_interface,data.dut1,'PortChannel1', dut1_dut2_ip[0],'31','ipv4','remove'],[ip_obj.config_ip_addr_interface,data.dut2,'PortChannel1', dut2_dut1_ip[0], '31', 'ipv4', 'remove']])

def test_17_22(fixture_test_17_22):

    #####################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun017 -  Configure global IPv6 address along with unnumbered session')
    st.banner('FtOpSoRoDynFun022 -  Verify BGP session with /127 and /31 addresses')
    st.log("Configure IPv4 and IPv6 addresses")
    utils.exec_all(True, [[ip_obj.config_ip_addr_interface,data.dut1,'PortChannel1', dut1_dut2_ipv6[0],'127','ipv6','add'],[ip_obj.config_ip_addr_interface,data.dut2,'PortChannel1', dut2_dut1_ipv6[0], '127', 'ipv6', 'add']])
    utils.exec_all(True, [[ip_obj.config_ip_addr_interface,data.dut1,'PortChannel1', dut1_dut2_ip[0],'31','ipv4','add'],[ip_obj.config_ip_addr_interface,data.dut2,'PortChannel1', dut2_dut1_ip[0], '31', 'ipv4', 'add']])
    if not ip_obj.verify_interface_ip_address(data.dut1,interface_name = 'PortChannel1', ip_address = dut1_dut2_ipv6[0]+'/127', family = 'ipv6'):
        st.error('Failed to manually configure global IPv6 address on DUT1')
        result += 1
    if not ip_obj.verify_interface_ip_address(data.dut1,interface_name = 'PortChannel1', ip_address = dut1_dut2_ip[0]+'/31', family = 'ipv4'):
        st.error('Failed to manually configure Ipv4 address on DUT1')
        result += 1
    dict1 = {'config':'yes','addr_family':'ipv6','local_as':dut1_as,'remote_as':dut2_as,'neighbor': dut2_dut1_ipv6[0],'config_type_list': ['neighbor']}
    dict2 = {'config':'yes','addr_family':'ipv6','local_as':dut2_as,'remote_as':dut1_as,'neighbor': dut1_dut2_ipv6[0],'config_type_list': ['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    dict1 = {'config':'yes','addr_family':'ipv6','local_as':dut1_as,'neighbor': dut2_dut1_ipv6[0],
             'config_type_list': ['nexthop_self','connect'],'nexthop_self':dut1_dut2_ipv6[0],'connect' : '3'}
    dict2 = {'config':'yes','addr_family':'ipv6','local_as':dut2_as,'neighbor': dut1_dut2_ipv6[0],
             'config_type_list': ['nexthop_self','connect'],'nexthop_self':dut2_dut1_ipv6[0],'connect' : '3'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    dict1 = {'local_asn':dut1_as,'neighbor_ip': dut2_dut1_ipv6[0],'family':'ipv6','config':'yes', 'vrf':'default','remote_asn':dut2_as}
    dict2 = {'local_asn':dut2_as,'neighbor_ip': dut1_dut2_ipv6[0],'family':'ipv6','config':'yes', 'vrf':'default','remote_asn':dut1_as}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.activate_bgp_neighbor, [dict1, dict2])
    dict1 = {'config':'yes','addr_family':'ipv4','local_as':dut1_as,'remote_as':dut2_as,'neighbor': dut2_dut1_ip[0],'config_type_list': ['neighbor']}
    dict2 = {'config':'yes','addr_family':'ipv4','local_as':dut2_as,'remote_as':dut1_as,'neighbor': dut1_dut2_ip[0],'config_type_list': ['neighbor']}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    dict1 = {'config':'yes','addr_family':'ipv4','local_as':dut1_as,'neighbor': dut2_dut1_ip[0],
             'config_type_list': ['nexthop_self','connect'],'nexthop_self':dut1_dut2_ip[0],'connect' : '3'}
    dict2 = {'config':'yes','addr_family':'ipv4','local_as':dut2_as,'neighbor': dut1_dut2_ip[0],
             'config_type_list': ['nexthop_self','connect'],'nexthop_self':dut2_dut1_ip[0],'connect' : '3'}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    dict1 = {'local_asn':dut1_as,'neighbor_ip': dut2_dut1_ip[0],'family':'ipv4','config':'yes', 'vrf':'default','remote_asn':dut2_as}
    dict2 = {'local_asn':dut2_as,'neighbor_ip': dut1_dut2_ip[0],'family':'ipv4','config':'yes', 'vrf':'default','remote_asn':dut1_as}
    parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.activate_bgp_neighbor, [dict1, dict2])
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, 10, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = dut1_dut2_ipv6[0], state='Established'):
        st.error("Failed to form BGPv4 session over portchannel")
        result += 1
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, 10, data.dut2, family='ipv4', shell=bgp_cli_type, neighbor = dut1_dut2_ip[0], state='Established'):
        st.error("Failed to form BGPv4 session over portchannel")
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun017','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun017','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def fixture_test_docker_restart(request,prologue_epilogue):
    yield
    reboot_obj.config_warm_restart(data.dut2, oper = "disable")
    dict1 = {'local_asn':dut1_as,'config':'del','preserve_state':'1'}
    dict2 = {'local_asn':dut2_as,'config':'del','preserve_state':'1'}
    dict3 = {'local_asn':dut3_as,'config':'del','preserve_state':'1'}
    parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], bgp_obj.config_bgp_graceful_restart, [dict1, dict2, dict3])

def test_docker_restart(fixture_test_docker_restart):

    #################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynReb004 - Verify BGP unnumbererd and listen range on default vrf after a docker restart')
    st.log(" Add graceful restart and preserve_state state configuration")
    dict1 = {'local_asn':dut1_as,'config':'add','preserve_state':'1'}
    dict2 = {'local_asn':dut2_as,'config':'add','preserve_state':'1'}
    dict3 = {'local_asn':dut3_as,'config':'add','preserve_state':'1'}
    parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], bgp_obj.config_bgp_graceful_restart, [dict1, dict2, dict3])
    st.log("######## clearing BGP neighbors after configuring graceful restart ###########")
    utils.exec_all(True, [[bgp_obj.clear_ip_bgp_vtysh, data.dut1], [bgp_obj.clear_ip_bgp_vtysh, data.dut2],
                          [bgp_obj.clear_ip_bgp_vtysh, data.dut3]])
    st.log("Verify the BGP sessions on DUT2")
    data.tg.tg_traffic_control(action = 'run', stream_handle = data.d1_stream_list.values())
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = ['PortChannel1','*'+dut3_dut2_ipv6[0]], state='Established', retry_count= 10, delay= 13):
        st.error("Failed to form BGP unnumbered and Dynamic neighbor session over default VRF")
        result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], family='ipv4', count = 2,
                             retry_count= 2, delay= 5, source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ipv6[0], family='ipv6', count = 2,
                             retry_count= 2, delay= 5, source_ip=dut1_tg_ipv6[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    reboot_obj.config_warm_restart(data.dut2, oper = "enable")
    reboot_obj.config_save(data.dut2)
    reboot_obj.config_save(data.dut2, 'vtysh')
    traffic_details = {'1': {'tx_ports' : [data.tg_dut1_ports[0]],'tx_obj' : [data.tg],'exp_ratio' : [1,1],'rx_ports' : [data.tg_dut3_ports[0]],'rx_obj' : [data.tg], 'stream_list' : [data.d1_stream_list.values()]}}
    basic_obj.service_operations_by_systemctl(data.dut2, "bgp", "restart")
    basic_obj.poll_for_system_status(data.dut2, iteration=5, delay=2)
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut2, family='ipv6', shell=bgp_cli_type, neighbor = ['PortChannel1','*'+dut3_dut2_ipv6[0]], state='Established', retry_count= 10, delay= 13):
        st.error("Failed to form BGP unnumbered and Dynamic neighbor session over default VRF")
        result += 1
    data.tg.tg_traffic_control(action = 'stop', stream_handle = data.d1_stream_list.values())
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ip[0], family='ipv4', count = 2,
                             retry_count= 2, delay= 5, source_ip=dut1_tg_ip[0]):
        st.error('IPv4 Ping from DUT1 to DUT3 failed')
        result += 1
    if not loc_lib.retry_api(ip_obj.ping, data.dut1, addresses = dut3_tg_ipv6[0], family='ipv6', count = 2,
                             retry_count= 2, delay= 5, source_ip=dut1_tg_ipv6[0]):
        st.error('IPv6 Ping from DUT1 to DUT3 failed')
        result += 1
    aggrResult = validate_tgen_traffic(traffic_details = traffic_details, mode = 'streamblock', comp_type = 'packet_count', delay_factor = data.delay_factor, tolerance_factor=0)
    if not aggrResult:
        st.error('IPv4 and IPv6 traffic over default VRF with BGP unnumbered and Dynamic Discovery failed')
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynReb004','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynReb004','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

@pytest.fixture(scope="function")
def fixture_test_19_20_21_23(request,prologue_epilogue):
    yield
    st.log('Unconfig for testcase - 19, 20, 21')
    #loc_lib.bgp_unconfig()
    utils.exec_all(True,[[ip_obj.delete_static_route, data.dut1, dut2_dut1_ip[2], dut3_tg1_network_v4[0],'sonic','ipv4'],
                        [ip_obj.delete_static_route, data.dut3, dut2_dut3_ip[3], dut1_tg1_network_v4[0],'sonic','ipv4']])
    utils.exec_all(True,[[ip_obj.delete_static_route, data.dut1, dut2_dut1_ip[2], dut2_dut3_network_v4_static[0],'sonic','ipv4'],
                        [ip_obj.delete_static_route, data.dut3, dut2_dut3_ip[3], dut1_dut2_network_v4_static[0],'sonic','ipv4']])
    ip_obj.delete_static_route(dut = data.dut2, next_hop = dut3_dut2_ip[3], static_ip = dut3_tg1_network_v4[0], shell='sonic', family='ipv4')
    ip_obj.delete_static_route(dut = data.dut2, next_hop = dut1_dut2_ip[2], static_ip = dut1_tg1_network_v4[0], shell='sonic', family='ipv4')
    utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut1, data.d1_d2_ports[2], dut1_dut2_ip[2], dut1_dut2_ip_subnet,'ipv4'], [ip_obj.delete_ip_interface, data.dut2, data.d2_d1_ports[2], dut2_dut1_ip[2], dut2_dut1_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut2, data.d2_d3_ports[3], dut2_dut3_ip[3], dut2_dut3_ip_subnet,'ipv4'], [ip_obj.delete_ip_interface, data.dut3,data.d3_d2_ports[3], dut3_dut2_ip[3], dut3_dut2_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut1, data.d1_d2_ports[2], dut1_dut2_ipv6[2], dut1_dut2_ipv6_subnet,'ipv6'], [ip_obj.delete_ip_interface, data.dut2, data.d2_d1_ports[2], dut2_dut1_ipv6[2], dut2_dut1_ipv6_subnet, 'ipv6']])
    utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut2, data.d2_d3_ports[3], dut2_dut3_ipv6[3], dut2_dut3_ipv6_subnet,'ipv6'], [ip_obj.delete_ip_interface, data.dut3,data.d3_d2_ports[3], dut3_dut2_ipv6[3], dut3_dut2_ipv6_subnet, 'ipv6']])

def test_19_20_21_23(fixture_test_19_20_21_23):
    #########################################################################################################################################
    result = 0
    st.banner('FtOpSoRoDynFun019 - Verify multihop BGP session along with listen range')
    st.banner('FtOpSoRoDynFun021 - Verify multihop BGP session after modifying the neighbor address')
    loc_lib.bgp_unconfig()
    loc_lib.base_interfaces(pc = '1',config = 'no')
    loc_lib.bgp_router_id()
    loc_lib.redistribute_routes()
    port_obj.noshutdown(data.dut2, [data.d2_d3_ports[0],data.d2_d3_ports[1],data.d2_d3_ports[2],data.d2_d3_ports[3]])
    port_obj.noshutdown(data.dut3, [data.d3_d2_ports[0],data.d3_d2_ports[1],data.d3_d2_ports[2],data.d3_d2_ports[3]])
    st.log('Configure IPv4 and IPv6 addresses on interfaces between DUT1,DUT2,DUT3')
    utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut1, data.d1_d2_ports[2], dut1_dut2_ip[2], dut1_dut2_ip_subnet,'ipv4'], [ip_obj.config_ip_addr_interface, data.dut2, data.d2_d1_ports[2], dut2_dut1_ip[2], dut2_dut1_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut2, data.d2_d3_ports[3], dut2_dut3_ip[3], dut2_dut3_ip_subnet,'ipv4'], [ip_obj.config_ip_addr_interface, data.dut3,data.d3_d2_ports[3], dut3_dut2_ip[3], dut3_dut2_ip_subnet, 'ipv4']])
    utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut1, data.d1_d2_ports[2], dut1_dut2_ipv6[2], dut1_dut2_ipv6_subnet,'ipv6'], [ip_obj.config_ip_addr_interface, data.dut2, data.d2_d1_ports[2], dut2_dut1_ipv6[2], dut2_dut1_ipv6_subnet, 'ipv6']])
    utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut2, data.d2_d3_ports[3], dut2_dut3_ipv6[3], dut2_dut3_ipv6_subnet,'ipv6'], [ip_obj.config_ip_addr_interface, data.dut3,data.d3_d2_ports[3], dut3_dut2_ipv6[3], dut3_dut2_ipv6_subnet, 'ipv6']])
    st.log('Configure IPv4 static routes on all the DUTs')
    utils.exec_all(True,[[ip_obj.create_static_route, data.dut1, dut2_dut1_ip[2], dut3_tg1_network_v4[0],'ipv4'],
                        [ip_obj.create_static_route, data.dut3, dut2_dut3_ip[3], dut1_tg1_network_v4[0],'ipv4']])
    utils.exec_all(True,[[ip_obj.create_static_route, data.dut1, dut2_dut1_ip[2], dut2_dut3_network_v4_static[0],'ipv4'],
                        [ip_obj.create_static_route, data.dut3, dut2_dut3_ip[3], dut1_dut2_network_v4_static[0],'ipv4']])
    ip_obj.create_static_route(dut = data.dut2, next_hop = dut3_dut2_ip[3], static_ip = dut3_tg1_network_v4[0], shell='sonic', family='ipv4')
    ip_obj.create_static_route(dut = data.dut2, next_hop = dut1_dut2_ip[2], static_ip = dut1_tg1_network_v4[0], shell='sonic', family='ipv4')
    st.log('Configure IPv6 static routes on all the DUTs')
    utils.exec_all(True,[[ip_obj.create_static_route, data.dut1, dut2_dut1_ipv6[2], dut3_tg1_network_v6[0],"vtysh",'ipv6'],
                        [ip_obj.create_static_route, data.dut3, dut2_dut3_ipv6[3], dut1_tg1_network_v6[0],"vtysh",'ipv6']])
    utils.exec_all(True,[[ip_obj.create_static_route, data.dut1, dut2_dut1_ipv6[2], dut2_dut3_network_v6_static[0],"vtysh",'ipv6'],
                        [ip_obj.create_static_route, data.dut3, dut2_dut3_ipv6[3], dut1_dut2_network_v6_static[0],"vtysh",'ipv6']])
    ip_obj.create_static_route(dut = data.dut2, next_hop = dut3_dut2_ipv6[3], static_ip = dut3_tg1_network_v6[0], shell='sonic', family='ipv6')
    ip_obj.create_static_route(dut = data.dut2, next_hop = dut1_dut2_ipv6[2], static_ip = dut1_tg1_network_v6[0], shell='sonic', family='ipv6')
    st.log('Configure IPv4 and IPv6 BGP multihop sessions on DUT1 and DUT3')
    bgp_obj.create_bgp_peergroup(data.dut1, dut1_as,'d1d3_multi_peer',dut3_as,60,180,None,'default','ipv4', update_src = dut1_dut2_ip[2], ebgp_multihop = '2')
    bgp_obj.create_bgp_peergroup(data.dut1, dut1_as,'d1d3_multi_peer_6',dut3_as,60,180,None,'default','ipv6', update_src = dut1_dut2_ipv6[2], ebgp_multihop = '2')
    bgp_obj.create_bgp_peergroup(data.dut3, dut3_as,'d1d3_multi_peer',dut1_as,60,180,None,'default','ipv4',neighbor_ip = dut1_dut2_ip[2],update_src = dut3_dut2_ip[3], ebgp_multihop = '2')
    bgp_obj.create_bgp_peergroup(data.dut3, dut3_as,'d1d3_multi_peer_6',dut1_as,60,180,None,'default','ipv6',neighbor_ip = dut1_dut2_ipv6[2], update_src = dut3_dut2_ipv6[3], ebgp_multihop = '2')
    st.log('Configure BGP listen range on DUT1 for IPv4 and IPv6 addresses')
    bgp_obj.config_bgp_listen_range(dut = data.dut1, local_asn = dut1_as, neighbor_address = '2.0.0.0', subnet = '16', peer_grp_name = 'd1d3_multi_peer', config = 'yes')
    bgp_obj.config_bgp_listen_range(dut = data.dut1, local_asn = dut1_as, neighbor_address = '2004::', subnet = '64', peer_grp_name = 'd1d3_multi_peer_6', config = 'yes')
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut1, family='ipv4', shell=bgp_cli_type, neighbor = '*'+dut3_dut2_ip[3], state='Established', retry_count= 10, delay= 20):
        st.error("Failed to form BGP multihop session with listen range")
        ip_obj.ping(data.dut1, dut3_dut2_ip[3], family='ipv4', count = 2)
        result += 1
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut1, family='ipv6', shell=bgp_cli_type, neighbor = '*'+dut3_dut2_ipv6[3], state='Established', retry_count= 10, delay= 20):
        st.error("Failed to form BGP multihop session with listen range")
        ip_obj.ping(data.dut1, dut3_dut2_ipv6[3], family='ipv6', count = 2)
        result += 1
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun019','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun019','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

    #########################################################################################################################################

    result = 0
    st.banner('FtOpSoRoDynFun020 - Verify multihop BGP session after removing and adding listen range for multihop neighbor')
    st.banner('FtOpSoRoDynFun023 - Verify BGP along with listen range after configuring multiple IP addresses on the interface')
    bgp_obj.config_bgp_listen_range(dut = data.dut1, local_asn = dut1_as, neighbor_address = '2.0.4.0', subnet = '24', peer_grp_name = 'd1d3_multi_peer', config = 'no')
    bgp_obj.config_bgp_listen_range(dut = data.dut1, local_asn = dut1_as, neighbor_address = '2004::', subnet = '64', peer_grp_name = 'd1d3_multi_peer_6', config = 'no')
    bgp_obj.config_bgp_listen_range(dut = data.dut1, local_asn = dut1_as, neighbor_address = '2.0.4.0', subnet = '24', peer_grp_name = 'd1d3_multi_peer', config = 'yes')
    bgp_obj.config_bgp_listen_range(dut = data.dut1, local_asn = dut1_as, neighbor_address = '2004::', subnet = '64', peer_grp_name = 'd1d3_multi_peer_6',config = 'yes')
    if not loc_lib.retry_api(bgp_obj.verify_bgp_summary, data.dut1, family='ipv4', shell=bgp_cli_type, neighbor = '*'+dut3_dut2_ip[3], state='Established', retry_count= 10, delay= 13):
        st.error("Failed to form BGP multihop session with listen range")
        ip_obj.ping(data.dut1, dut3_dut2_ip[3], family='ipv4', count = 2)
        result += 1
    aggrResult = loc_lib.send_verify_traffic()
    if result == 0 :
        st.report_tc_pass('FtOpSoRoDynFun020','test_case_passed')
    else:
        st.report_tc_fail('FtOpSoRoDynFun020','test_case_failed')
    if result == 0 :
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

