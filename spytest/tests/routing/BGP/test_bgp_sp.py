#   BGP SP Topology Test cases
#   Author: Naveena Suvarna (naveen.suvarna@broadcom.com)

import copy
import pytest
from spytest import st, SpyTestDict
import apis.routing.ip as ipapi
import apis.routing.bgp as bgpapi
import apis.routing.route_map as rmapapi
from BGP.bgpsplib import BGPSP



@pytest.fixture(scope="module", autouse=True)
def bgp_sp_module_hooks(request):
    global bgp_cli_type
    st.ensure_min_topology('D1D2:4', 'D1D3:4', 'D1D4:4', 'D2D3:4', 'D2D4:4', 'D3D4:4')
    bgp_cli_type = st.get_ui_type()
    if bgp_cli_type == 'click':
        bgp_cli_type = 'vtysh'
    bgp_cli_type = 'klish' if bgp_cli_type in ["rest-patch", "rest-put"] else bgp_cli_type
    BGPSP.bgp_sp_setup_testbed_topology()

    pre_config = True
    if pre_config :
       BGPSP.bgp_sp_config_ip_topology_on_testbed()

    BGPSP.bgp_sp_cleanup_bgp_routers()

    yield

    pre_config = True
    if pre_config :
       BGPSP.bgp_sp_cleanup_bgp_routers()
       BGPSP.bgp_sp_unconfig_ip_topology_on_testbed()

    BGPSP.bgp_sp_clear_testbed_topology()


@pytest.fixture(scope="function")
def bgp_sp_func_hooks(request):
    #
    yield
    #


#--------------------------------------- BASE TEST BASE -------------------------------------------

@pytest.fixture(scope='class')
def bgp_sp_base_class_hook(request):
    BGPSP.bgp_sp_cleanup_bgp_routers()
    yield
    BGPSP.bgp_sp_cleanup_bgp_routers()


@pytest.mark.usefixtures('bgp_sp_base_class_hook')
class TestBGPSP:

    def test_bgp_sp_topolog_interface_ip_ping(self):

        st.banner("BGP SP - SP Topology interface ping test")

        result = True
        result = BGPSP.bgp_sp_interface_address_ping_test(vrf='default', addr_family='all', ping_count=3)

        result_str = "PASSED" if result else "FAILED"
        st.banner("BGP SP - SP Topology interface ping test {}".format(result_str))

        if result:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")



#------------------------------------- LINEAR TOPO eBGP iBGP iBGP eBGP TEST CLASS -----------------------------------

@pytest.fixture(scope='class')
def bgp_sp_linear_topo_ebgp_ibgp_class_hook(request):

    pre_config = True
    if pre_config :
        BGPSP.bgp_sp_cleanup_bgp_routers()
        result = BGPSP.bgp_sp_linear_topo_bgp_config_unconfig(sess_type='eBGPiBGPeBGP', addr_family='all', config='yes')
        if not result :
           st.log("BGP SP - Linear Topo bgp config and neighbor session test failed")
           st.report_fail("operation_failed")

    yield

    if pre_config :
        BGPSP.bgp_sp_linear_topo_bgp_config_unconfig(sess_type='eBGPiBGPeBGP', addr_family='all', config='no')
        BGPSP.bgp_sp_cleanup_bgp_routers()


@pytest.mark.usefixtures('bgp_sp_linear_topo_ebgp_ibgp_class_hook')
class TestBGP_LINEAR_EBGP_IBGP:

    def test_bgp_sp_four_node_linear_ebgp_ibgp_session(self):

        st.banner("BGP SP - 4 Node Linear EBGP IBGP EBGP session test START")
        result = True

        linear_topo = BGPSP.bgp_sp_dut_get_saved_linear_topo()
        BGPSP.bgp_sp_show_topo_path(linear_topo)

        if not BGPSP.bgp_sp_test_topo_present(topo_path=linear_topo, dut_count=4,  segment_count=3) :
            st.log("BGP SP - Test case topo requirement FAILED")
            st.report_env_fail("test_case_not_executed")
            return

        #start_dut = linear_topo['start_dut']
        #dut_list = linear_topo['dut_list']

        result_str = "PASSED" if result else "FAILED"
        st.banner("BGP SP - 4 Node Linear EBGP IBGP EBGP session test {}".format(result_str))

        if result:
            st.report_pass("test_case_passed")
        #else:
            #st.report_fail("test_case_failed")

    @pytest.mark.advance
    def test_bgp_linear_ebgp_ibgp_route_advanced(self):

        st.banner("BGP SP - 4 Node Linear EBGP IBGP EBGP session advanced test START")
        result = True

        linear_topo = BGPSP.bgp_sp_dut_get_saved_linear_topo()
        BGPSP.bgp_sp_show_topo_path(linear_topo)

        if not BGPSP.bgp_sp_test_topo_present(topo_path=linear_topo, dut_count=4,  segment_count=3) :
            st.log("BGP SP - Test case topo requirement FAILED")
            st.report_env_fail("test_case_not_executed")
            return

        dut_list = linear_topo['dut_list']
        #BGPSP.bgp_sp_show_dut_bgp_running_config(dut_list)

        reduced_topo = SpyTestDict()
        reduced_topo['leftebgpdut'] = BGPSP.bgp_sp_get_dut_device(dut_list[0])
        reduced_topo['leftibgpdut'] = BGPSP.bgp_sp_get_dut_device(dut_list[1])
        reduced_topo['rightibgpdut'] = BGPSP.bgp_sp_get_dut_device(dut_list[2])
        reduced_topo['rightebgpdut'] = BGPSP.bgp_sp_get_dut_device(dut_list[3])
        reduced_topo['linear_path'] = linear_topo

        #request.cls.local_topo = reduced_topo
        self.local_topo = reduced_topo

        #Common config items
        prefix_list_201 = ipapi.PrefixList("201_network")
        prefix_list_201.add_match_permit_sequence('201.1.1.0/24', seq_num="1")
        prefix_list_202 = ipapi.PrefixList("202_network")
        prefix_list_202.add_match_permit_sequence('202.1.1.0/24', seq_num="2")
        prefix_list_203 = ipapi.PrefixList("203_network")
        prefix_list_203.add_match_permit_sequence('203.1.1.0/24', seq_num="3")
        prefix_list_204 = ipapi.PrefixList("204_network")
        prefix_list_204.add_match_permit_sequence('204.1.1.0/24', seq_num="4")
        prefix_list_205 = ipapi.PrefixList("205_network")
        prefix_list_205.add_match_permit_sequence('205.1.1.0/24', seq_num="5")
        prefix_list_100 = ipapi.PrefixList("100_network")
        prefix_list_100.add_match_permit_sequence('100.1.1.0/24', seq_num="6")

        aspath_acl = bgpapi.ASPathAccessList("ASPATH")
        aspath_acl.add_match_permit_sequence(['(_3000_)+'])
        aspath_acl.add_match_permit_sequence(['(_4000_)+'])

        #Left eBGP node config items and commands
        leftebgprmap = rmapapi.RouteMap("test_community")
        leftebgprmap.add_permit_sequence('10')
        leftebgprmap.add_sequence_match_prefix_list('10', '202_network')
        leftebgprmap.add_sequence_set_community('10', ['55:5555'])
        leftebgprmap.add_permit_sequence('15')
        leftebgprmap.add_sequence_match_prefix_list('15', '204_network')
        leftebgprmap.add_sequence_set_as_path_prepend('15', ['2000', '3000'])
        leftebgprmap.add_permit_sequence('18')
        leftebgprmap.add_sequence_match_prefix_list('18', '205_network')
        leftebgprmap.add_sequence_set_as_path_prepend('18', ['2000', '4000'])
        leftebgprmap.add_permit_sequence('20')

        leftebgpdutcmd = prefix_list_201.config_command_string()
        leftebgpdutcmd += prefix_list_202.config_command_string()
        leftebgpdutcmd += prefix_list_204.config_command_string()
        leftebgpdutcmd += prefix_list_205.config_command_string()
        leftebgpdutcmd += leftebgprmap.config_command_string()

        leftebgpnetworklistipv4 = ['200.1.1.0/24', '201.1.1.0/24', '202.1.1.0/24', '203.1.1.0/24', '204.1.1.0/24', '205.1.1.0/24']
        leftebgpnetworklistipv6 = ['200:1::/64']

        #Left iBGP node config items and commands
        leftibgprmap1 = rmapapi.RouteMap("test_community")
        leftibgprmap1.add_permit_sequence('10')
        leftibgprmap1.add_sequence_match_prefix_list('10', '201_network')
        leftibgprmap1.add_sequence_set_community('10', ['no-advertise'])
        leftibgprmap1.add_permit_sequence('15')
        leftibgprmap1.add_sequence_match_prefix_list('15', '202_network')
        leftibgprmap1.add_sequence_set_community('15', ['44:4444 additive'])
        #FIXME: Make additive keyword into proper API
        leftibgprmap1.add_permit_sequence('18')
        leftibgprmap1.add_sequence_match_prefix_list('18', '100_network')
        leftibgprmap1.add_sequence_set_as_path_prepend('18', ['65111'])
        leftibgprmap1.add_permit_sequence('20')

        leftibgprmap2 = rmapapi.RouteMap("test_community_1")
        leftibgprmap2.add_permit_sequence('10')
        leftibgprmap2.add_sequence_match_prefix_list('10', '203_network')
        leftibgprmap2.add_sequence_set_community('10', ['no-export'])
        leftibgprmap2.add_permit_sequence('20')

        leftibgpdutcmd = prefix_list_201.config_command_string()
        leftibgpdutcmd += prefix_list_202.config_command_string()
        leftibgpdutcmd += prefix_list_203.config_command_string()
        leftibgpdutcmd += prefix_list_100.config_command_string()
        leftibgpdutcmd += leftibgprmap1.config_command_string()
        leftibgpdutcmd += leftibgprmap2.config_command_string()

        #Right eBGP node config items and commands
        rightebgprmap = rmapapi.RouteMap("ASP")
        rightebgprmap.add_deny_sequence('10')
        rightebgprmap.add_sequence_match_bgp_aspath_list('10', 'ASPATH')
        rightebgprmap.add_permit_sequence('20')

        rightebgpdutcmd = aspath_acl.config_command_string()
        rightebgpdutcmd += rightebgprmap.config_command_string()

        BGPSP.bgp_sp_dut_bgp_network_advertise_config_unconfig(dut_list[0], leftebgpnetworklistipv4)
        BGPSP.bgp_sp_dut_bgp_network_advertise_config_unconfig(dut_list[0], leftebgpnetworklistipv6, addr_family='ipv6')
        BGPSP.bgp_sp_dut_bgp_network_advertise_config_unconfig(dut_list[1], ['100.1.1.0/24'])
        BGPSP.bgp_sp_dut_bgp_network_advertise_config_unconfig(dut_list[3], ['100.1.1.0/24'])

        st.config(reduced_topo['leftebgpdut'], leftebgpdutcmd,type=bgp_cli_type)
        st.config(reduced_topo['leftibgpdut'], leftibgpdutcmd,type=bgp_cli_type)
        st.config(reduced_topo['rightebgpdut'], rightebgpdutcmd,type=bgp_cli_type)


        result = True
        bgpapi.show_ip_bgp_route(self.local_topo['leftebgpdut'])
        bgpapi.show_ip_bgp_route(self.local_topo['leftibgpdut'])
        bgpapi.show_ip_bgp_route(self.local_topo['rightibgpdut'])
        bgpapi.show_ip_bgp_route(self.local_topo['rightebgpdut'])

        link_idx = 0
        #configure route-maps and other commands on relevat DUTs
        seg0_data = self.local_topo['linear_path']['segment'][0][link_idx]
        left_ebgp_asn = BGPSP.bgp_sp_get_bgp_asn(seg0_data['lcl_dut'])
        left_ebgp_ip = BGPSP.bgp_sp_dut_get_link_local_ip(seg0_data['lcl_dut'], seg0_data['lcl_link'], 'ipv4')
        left_ebgp_nbr_ip = BGPSP.bgp_sp_dut_get_link_remote_ip(seg0_data['lcl_dut'], seg0_data['lcl_link'], 'ipv4')
        bgpapi.config_bgp(dut=self.local_topo['leftebgpdut'], local_as=left_ebgp_asn, neighbor=left_ebgp_nbr_ip, config='yes',
                          config_type_list=["routeMap"], routeMap='test_community', diRection='out')

        seg1_data = self.local_topo['linear_path']['segment'][1][link_idx]
        left_ibgp_asn = BGPSP.bgp_sp_get_bgp_asn(seg1_data['lcl_dut'])
        left_ibgp_ipv6 = BGPSP.bgp_sp_dut_get_link_local_ip(seg1_data['lcl_dut'], seg1_data['lcl_link'], 'ipv6')
        left_ibgp_nbr_ip = BGPSP.bgp_sp_dut_get_link_remote_ip(seg1_data['lcl_dut'], seg1_data['lcl_link'], 'ipv4')
        route_20x_correct_nhop = BGPSP.bgp_sp_dut_get_link_local_ip(seg1_data['lcl_dut'], seg1_data['lcl_link'], 'ipv4')
        bgpapi.create_bgp_next_hop_self(self.local_topo['leftibgpdut'], left_ibgp_asn, 'ipv4', left_ibgp_nbr_ip, config='yes')
        bgpapi.config_bgp(dut=self.local_topo['leftibgpdut'], local_as=left_ibgp_asn, neighbor=left_ibgp_nbr_ip, config='yes',
                          config_type_list=["routeMap"], routeMap='test_community', diRection='out')
        bgpapi.config_bgp(dut=self.local_topo['leftibgpdut'], local_as=left_ibgp_asn, neighbor=left_ebgp_ip, config='yes',
                          config_type_list=["routeMap"], routeMap='test_community_1', diRection='in')

        seg2_data = self.local_topo['linear_path']['segment'][2][link_idx]
        right_ibgp_asn = BGPSP.bgp_sp_get_bgp_asn(seg2_data['lcl_dut'])
        right_ebgp_asn = BGPSP.bgp_sp_get_bgp_asn(seg2_data['rmt_dut'])
        right_ebgp_nbr_ip = BGPSP.bgp_sp_dut_get_link_local_ip(seg2_data['lcl_dut'], seg2_data['lcl_link'], 'ipv4')
        right_ebgp_ip = BGPSP.bgp_sp_dut_get_link_remote_ip(seg2_data['lcl_dut'], seg2_data['lcl_link'], 'ipv4')
        bgpapi.config_bgp(dut=self.local_topo['rightibgpdut'], local_as=right_ibgp_asn, neighbor=right_ebgp_ip, config='yes',
                          config_type_list=["removePrivateAs"])
        bgpapi.config_bgp(dut=self.local_topo['rightebgpdut'], local_as=right_ebgp_asn, neighbor=right_ebgp_nbr_ip, config='yes',
                          config_type_list=["routeMap"], routeMap='ASP', diRection='in')
        route_100_correct_nhop = BGPSP.bgp_sp_dut_get_link_remote_ip(seg2_data['lcl_dut'], seg2_data['lcl_link'], 'ipv4')

        prefix_list_v6200 = ipapi.PrefixList("v6_200_network", family='ipv6')
        prefix_list_v6200.add_match_permit_sequence('200:1::/64', seq_num="7")
        test_v6_nhop_rmap = rmapapi.RouteMap("test_v6_nhop")
        test_v6_nhop_rmap.add_permit_sequence('10')
        test_v6_nhop_rmap.add_sequence_match_prefix_list('10', 'v6_200_network', family='ipv6')
        test_v6_nhop_rmap.add_sequence_set_ipv6_next_hop_global('10', left_ibgp_ipv6)

        rightibgpdutcmd = prefix_list_v6200.config_command_string() + test_v6_nhop_rmap.config_command_string()
        st.config(self.local_topo['rightibgpdut'], rightibgpdutcmd,type=bgp_cli_type)
        bgpapi.config_bgp(dut=self.local_topo['rightibgpdut'], local_as=right_ibgp_asn, neighbor=left_ibgp_ipv6,
                          addr_family ='ipv6', config='yes',
                          config_type_list=["routeMap"], routeMap='test_v6_nhop', diRection='in')
        #end

        st.wait(2)

        res = ipapi.verify_ip_route(self.local_topo['rightibgpdut'],
                                        type='B', ip_address='100.1.1.0/24', nexthop=route_100_correct_nhop)
        if not res:
            st.log("100 network nexthop did not match")
            result = False
        else:
            st.log("Test to verify eBGP preferred over iBGP passed")

        res = ipapi.verify_ip_route(self.local_topo['rightibgpdut'],
                                       type='B', ip_address='200.1.1.0/24', nexthop=route_20x_correct_nhop)
        if not res:
            st.log("200 network nexthop did not match")
            result = False
        else:
            st.log("Test to verify next hop self passed")

        res = ipapi.verify_ip_route(self.local_topo['rightebgpdut'],
                                       type='B', ip_address='201.1.1.0/24')
        if res:
            st.log("201 still advertised, fail")
            result = False
        else:
            st.log("Test to verify NO_ADVERTISE community passed")

        # st.wait(30)
        # output = bgpapi.show_bgp_ipvx_prefix(self.local_topo['rightibgpdut'], prefix="202.1.1.0",
        #                                      masklen=24, family='ipv4')
        # if not output or '55:5555' not in output[0]['community']:
        #     st.log('community not appended')
        #     result = False
        # else:
        #     st.log("Test to verify community append passed")

        res = ipapi.verify_ip_route(self.local_topo['rightebgpdut'],
                                    type='B', ip_address='203.1.1.0/24')
        if res:
            st.log("203 still advertised, fail")
            result = False
        else:
            st.log("Test to verify NO_EXPORT community passed")

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['rightebgpdut'], family='ipv4',
                                           match={'network': '200.1.1.0/24'},
                                           select=['network', 'as_path'])
        if not output or str(left_ebgp_asn) in output[0]['as_path']:
            st.log('private as not removed')
            result = False
        else:
            st.log("Test to verify remove_private_as passed")

        res = bgpapi.verify_ip_bgp_route(self.local_topo['rightebgpdut'], network="204.1.1.0/24")
        if res:
            st.log("204 still advertised, fail")
            result = False
        else:
            st.log("Test to verify as path filter passed")

        res = bgpapi.verify_ip_bgp_route(self.local_topo['rightibgpdut'], family='ipv6',
                                         network="200:1::/64", next_hop=left_ibgp_ipv6)
        if not res:
            st.log("200:1::/64 next hop did not change, fail")
            result = False
        else:
            st.log("Test to verify IPv6 nhop through route-map in passed")

        # unconfigure route-maps and other commands on relevat DUTs
        bgpapi.config_bgp(dut=self.local_topo['leftebgpdut'], local_as=left_ebgp_asn, neighbor=left_ebgp_nbr_ip,
                          config='no',
                          config_type_list=["routeMap"], routeMap='test_community', diRection='out', cli_type=bgp_cli_type)

        bgpapi.create_bgp_next_hop_self(self.local_topo['leftibgpdut'], left_ibgp_asn, 'ipv4', left_ibgp_nbr_ip,
                                        config='no', cli_type=bgp_cli_type)
        bgpapi.config_bgp(dut=self.local_topo['leftibgpdut'], local_as=left_ibgp_asn, neighbor=left_ibgp_nbr_ip,
                          config='no',
                          config_type_list=["routeMap"], routeMap='test_community', diRection='out', cli_type=bgp_cli_type)
        bgpapi.config_bgp(dut=self.local_topo['leftibgpdut'], local_as=left_ibgp_asn, neighbor=left_ebgp_ip,
                          config='no',
                          config_type_list=["routeMap"], routeMap='test_community_1', diRection='in', cli_type=bgp_cli_type)

        bgpapi.config_bgp(dut=self.local_topo['rightibgpdut'], local_as=right_ibgp_asn, neighbor=right_ebgp_ip,
                          config='no',
                          config_type_list=["removePrivateAs"], cli_type=bgp_cli_type)
        bgpapi.config_bgp(dut=self.local_topo['rightebgpdut'], local_as=right_ebgp_asn, neighbor=right_ebgp_nbr_ip,
                          config='no',
                          config_type_list=["routeMap"], routeMap='ASP', diRection='in', cli_type=bgp_cli_type)

        bgpapi.config_bgp(dut=self.local_topo['rightibgpdut'], local_as=right_ibgp_asn, neighbor=left_ibgp_ipv6,
                          addr_family='ipv6', config='no',
                          config_type_list=["routeMap"], routeMap='test_v6_nhop', diRection='in', cli_type=bgp_cli_type)

        rightibgpdutcmd =  test_v6_nhop_rmap.unconfig_command_string() + prefix_list_v6200.unconfig_command_string()
        #rightibgpdutcmd = prefix_list_v6200.unconfig_command_string() + test_v6_nhop_rmap.unconfig_command_string()
        st.config(self.local_topo['rightibgpdut'], rightibgpdutcmd,type=bgp_cli_type)

        # end

        # Unconfigure networks from DUTs
        BGPSP.bgp_sp_dut_bgp_network_advertise_config_unconfig(dut_list[0], leftebgpnetworklistipv4, config='no')
        BGPSP.bgp_sp_dut_bgp_network_advertise_config_unconfig(dut_list[0], leftebgpnetworklistipv6, addr_family='ipv6', config='no')
        BGPSP.bgp_sp_dut_bgp_network_advertise_config_unconfig(dut_list[1], ['100.1.1.0/24'], config='no')
        BGPSP.bgp_sp_dut_bgp_network_advertise_config_unconfig(dut_list[3], ['100.1.1.0/24'], config='no')


        #Left eBGP node config items and commands
        leftebgpdutcmd = leftebgprmap.unconfig_command_string()
        leftebgpdutcmd += prefix_list_201.unconfig_command_string()
        leftebgpdutcmd += prefix_list_202.unconfig_command_string()
        leftebgpdutcmd += prefix_list_204.unconfig_command_string()
        leftebgpdutcmd += prefix_list_205.unconfig_command_string()


        #Left iBGP node config items and commands
        leftibgpdutcmd = leftibgprmap1.unconfig_command_string()
        leftibgpdutcmd += leftibgprmap2.unconfig_command_string()
        leftibgpdutcmd += prefix_list_201.unconfig_command_string()
        leftibgpdutcmd += prefix_list_202.unconfig_command_string()
        leftibgpdutcmd += prefix_list_203.unconfig_command_string()
        leftibgpdutcmd += prefix_list_100.unconfig_command_string()


        #Right eBGP node config items and commands
        rightebgpdutcmd = rightebgprmap.unconfig_command_string()
        rightebgpdutcmd += aspath_acl.unconfig_command_string()


        st.config(reduced_topo['leftebgpdut'], leftebgpdutcmd,type=bgp_cli_type)
        st.config(reduced_topo['leftibgpdut'], leftibgpdutcmd,type=bgp_cli_type)
        #st.config(reduced_topo['rightibgpdut'], rightibgpdutcmd,type=bgp_cli_type)
        st.config(reduced_topo['rightebgpdut'], rightebgpdutcmd,type=bgp_cli_type)


        if result:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")



#------------------------------------ LINEAR TOPO eBGP TEST CLASS --------------------------------

@pytest.fixture(scope='class')
def bgp_sp_linear_topo_ebgp_class_hook(request):

    pre_config = True
    if pre_config :
        BGPSP.bgp_sp_cleanup_bgp_routers()
        result = BGPSP.bgp_sp_linear_topo_bgp_config_unconfig(sess_type='eBGP', addr_family='all', config='yes')
        if not result :
           st.log("BGP SP - Linear Topo ebgp config and neighbor session test failed")
           st.report_fail("operation_failed")

    yield

    pre_config = True
    if pre_config :
        BGPSP.bgp_sp_linear_topo_bgp_config_unconfig(sess_type='eBGP', addr_family='all', config='no')
        BGPSP.bgp_sp_cleanup_bgp_routers()


@pytest.mark.usefixtures('bgp_sp_linear_topo_ebgp_class_hook')
class TestBGP_LINEAR_EBGP:

    def test_bgp_sp_three_node_linear_ebgp_med_rmap(self):

        st.banner("BGP SP - 3 Node Linear EBGP session MED test START")
        result = True

        linear_topo = BGPSP.bgp_sp_dut_get_saved_linear_topo()
        BGPSP.bgp_sp_show_topo_path(linear_topo)

        if not BGPSP.bgp_sp_test_topo_present(topo_path=linear_topo, dut_count=3,  segment_count=2) :
            st.log("BGP SP - Test case topo requirement FAILED")
            st.report_env_fail("test_case_not_executed")
            return

        #start_dut = linear_topo['start_dut']
        #dut_list = linear_topo['dut_list']

        link_idx = 0
        left_dut = linear_topo['segment'][0][link_idx]['lcl_dut']
        mid_dut = linear_topo['segment'][1][link_idx]['lcl_dut']
        right_dut = linear_topo['segment'][1][link_idx]['rmt_dut']
        lr_dut_list = [left_dut, right_dut]
        rmap_name = 'rmap_med_metric'

        #tb_left_dut = BGPSP.bgp_sp_get_dut_device(left_dut)
        #tb_mid_dut = BGPSP.bgp_sp_get_dut_device(mid_dut)
        #tb_right_dut = BGPSP.bgp_sp_get_dut_device(right_dut)

        #BGPSP.bgp_sp_show_dut_bgp_running_config(dut_list)

        if result :
            st.log("BGP SP - Configure route map {} in {}".format(left_dut, rmap_name))
            result = BGPSP.bgp_sp_route_map_config_unconfig(left_dut, rmap_name, 'permit', '10', metric='111')

        if result :
            st.log("BGP SP - Configure route map {} in {}".format(right_dut, rmap_name))
            result = BGPSP.bgp_sp_route_map_config_unconfig(right_dut,  rmap_name, 'permit', '10', metric='333')

        if result :
            st.log("BGP SP - Configure deterministic med in {}".format(mid_dut))
            result = BGPSP.bgp_sp_bgp_deterministic_med_config_unconfig(list([mid_dut]))

        if result :
            st.log("BGP SP - Configure always compare med in {}".format(mid_dut))
            result = BGPSP.bgp_sp_bgp_compare_med_config_unconfig(list([mid_dut]))

        nw_prefixes = { 'ipv4': [], 'ipv6': []}
        addr_family_list = BGPSP.bgp_sp_get_address_family_list("all")
        selected_metric ={'metric' : '0', 'status_code': '*>'}

        for afmly in addr_family_list:

            bgp_nw_prefixes = BGPSP.bgp_sp_get_dut_static_network_prefixes(left_dut, afmly)
            nw_prefixes[afmly] = bgp_nw_prefixes
            dest_list = BGPSP.bgp_sp_ip_prefix_list_to_route_prefix_list(bgp_nw_prefixes, afmly)

            if len(dest_list) == 0 :
                st.log("BGP SP - Route List for {} empty for prefix {}".format(afmly, dest_list))
                result = False

            if result :
                st.log("BGP SP - Configure {} network on nodes".format(afmly))
                result = BGPSP.bgp_sp_bgp_network_advertise_config_unconfig(lr_dut_list, bgp_nw_prefixes, addr_family=afmly)

            if result :
                st.log("BGP SP - Verify {} routes {} show 0 metric".format(mid_dut, dest_list))
                BGPSP.bgp_sp_bgp_verify_routes_in_dut_list([mid_dut], dest_list, afmly, present='yes')

                selected_metric['metric'] = '0'
                result = BGPSP.bgp_sp_bgp_ip_routes_matching([mid_dut], dest_list, afmly, selected_metric)

            if result :
                nbr_list = BGPSP.bgp_sp_get_bgp_neigbour_ip_between_duts(left_dut, mid_dut, afmly)
                st.log("BGP SP - Configure rmap {} to {} nbrs {}".format(rmap_name, left_dut, nbr_list))
                result = BGPSP.bgp_sp_bgp_neighbor_route_map_config_unconfig(left_dut, nbr_list, rmap_name, 'out', afmly)

            if result :
                st.log("BGP SP - Verify {} routes {} show rmap metric".format(mid_dut, dest_list))
                selected_metric['metric'] = '0'
                result = BGPSP.bgp_sp_bgp_ip_routes_matching([mid_dut], dest_list, afmly, selected_metric)

            if result :
                st.log("BGP SP - change metric in {} rmap {}".format(right_dut, rmap_name))
                result = BGPSP.bgp_sp_route_map_config_unconfig(right_dut, rmap_name, 'permit', '10', metric='33')

            if result :
                nbr_list = BGPSP.bgp_sp_get_bgp_neigbour_ip_between_duts(right_dut, mid_dut, afmly)
                st.log("BGP SP - Configure rmap {} to {} nbrs {}".format(rmap_name, right_dut, nbr_list))
                result = BGPSP.bgp_sp_bgp_neighbor_route_map_config_unconfig(right_dut, nbr_list, rmap_name, 'out', afmly)

            if result :
                st.wait(5)
                st.log("BGP SP - Verify {} routes {} show rmap metric".format(mid_dut, dest_list))
                selected_metric['metric'] = '33'
                result = BGPSP.bgp_sp_bgp_ip_routes_matching([mid_dut], dest_list, afmly, selected_metric)

            if result :
                st.wait(5)
                st.log("BGP SP - change metric in {} rmap {}".format(right_dut, rmap_name))
                result = BGPSP.bgp_sp_route_map_config_unconfig(right_dut, rmap_name, 'permit', '10', metric='333')

            if result :
                st.wait(5)
                st.log("BGP SP - Verify {} routes {} show rmap metric".format(mid_dut, dest_list))
                selected_metric['metric'] = '111'
                result = BGPSP.bgp_sp_bgp_ip_routes_matching([mid_dut], dest_list, afmly, selected_metric)

            if result :
                st.log("BGP SP - change metric in {} rmap {}".format(right_dut, rmap_name))
                result = BGPSP.bgp_sp_route_map_config_unconfig(right_dut, rmap_name, 'permit', '10', metric='3')

            if result :
                st.wait(5)
                st.log("BGP SP - Verify {} routes {} show rmap metric".format(mid_dut, dest_list))
                selected_metric['metric'] = '3'
                result = BGPSP.bgp_sp_bgp_ip_routes_matching([mid_dut], dest_list, afmly, selected_metric)

            if not result :
                break

        BGPSP.bgp_sp_bgp_deterministic_med_config_unconfig(list([mid_dut]), config='no')
        BGPSP.bgp_sp_bgp_compare_med_config_unconfig(list([mid_dut]), config='no')

        for afmly in addr_family_list:
            nbr_list = BGPSP.bgp_sp_get_bgp_neigbour_ip_between_duts(left_dut, mid_dut, afmly)
            BGPSP.bgp_sp_bgp_neighbor_route_map_config_unconfig(left_dut, nbr_list, rmap_name, 'out', afmly,
                                                            config='no')

            nbr_list = BGPSP.bgp_sp_get_bgp_neigbour_ip_between_duts(right_dut, mid_dut, afmly)
            BGPSP.bgp_sp_bgp_neighbor_route_map_config_unconfig(right_dut, nbr_list, rmap_name, 'out', afmly,
                                                            config='no')

        BGPSP.bgp_sp_route_map_config_unconfig(left_dut, rmap_name, config='no')
        BGPSP.bgp_sp_route_map_config_unconfig(right_dut, rmap_name, config='no')

        for afmly in addr_family_list:
            if len(nw_prefixes[afmly]) == 0 : continue
            BGPSP.bgp_sp_bgp_network_advertise_config_unconfig(lr_dut_list, nw_prefixes[afmly], addr_family=afmly, config='no')

        result_str = "PASSED" if result else "FAILED"
        st.banner("BGP SP - 3 Node Linear EBGP session MED test {}".format(result_str))

        if result:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")



#------------------------------------ LINEAR TOPO iBGP TEST CLASS --------------------------------

@pytest.fixture(scope='class')
def bgp_sp_linear_topo_ibgp_class_hook(request):

    pre_config = True
    if pre_config :
        BGPSP.bgp_sp_cleanup_bgp_routers()
        result = BGPSP.bgp_sp_linear_topo_bgp_config_unconfig(sess_type='iBGP', addr_family='all', config='yes')
        if not result :
           st.log("BGP SP - Linear Topo ibgp config and neighbor session test failed")
           st.report_fail("operation_failed")

    yield

    pre_config = True
    if pre_config :
        BGPSP.bgp_sp_linear_topo_bgp_config_unconfig(sess_type='iBGP', addr_family='all', config='no')
        BGPSP.bgp_sp_cleanup_bgp_routers()


@pytest.mark.usefixtures('bgp_sp_linear_topo_ibgp_class_hook')
class TestBGP_LINEAR_IBGP:

    def test_bgp_sp_four_node_bgp_cluster_route(self):

        st.banner("BGP SP - Four Node Linear iBGP Clustor Route Test START")
        result = True

        linear_topo = BGPSP.bgp_sp_dut_get_saved_linear_topo()
        BGPSP.bgp_sp_show_topo_path(linear_topo)

        if not BGPSP.bgp_sp_test_topo_present(topo_path=linear_topo, dut_count=4,  segment_count=3) :
            st.log("BGP SP - Test case topo requirement FAILED")
            st.report_env_fail("test_case_not_executed")
            return

        #start_dut = linear_topo['start_dut']
        #dut_list = linear_topo['dut_list']

        #BGPSP.bgp_sp_show_dut_bgp_running_config(dut_list)

        # c1--r1---r2---c2
        link_idx = 0
        c1_dut = linear_topo['segment'][0][link_idx]['lcl_dut']
        r1_dut = linear_topo['segment'][0][link_idx]['rmt_dut']

        r2_dut = linear_topo['segment'][2][link_idx]['lcl_dut']
        c2_dut = linear_topo['segment'][2][link_idx]['rmt_dut']

        addr_family_list = BGPSP.bgp_sp_get_address_family_list("all")

        bgp_nw_prefixes = { c1_dut : { 'ipv4': [], 'ipv6': []},
                            c2_dut : { 'ipv4': [], 'ipv6': []} }

        bgp_rt_prefixes = { c1_dut : { 'ipv4': [], 'ipv6': []},
                            c2_dut : { 'ipv4': [], 'ipv6': []} }

        bgp_rr_nbr = { r1_dut : { 'ipv4': [], 'ipv6': []},
                       r2_dut : { 'ipv4': [], 'ipv6': []} }

        if result :
            for dut in [c1_dut, c2_dut] :
                for afmly in addr_family_list:
                    nw_prefixes =  BGPSP.bgp_sp_get_dut_static_network_prefixes(dut, afmly)
                    bgp_nw_prefixes[dut][afmly] = nw_prefixes
                    rt_prefixes = BGPSP.bgp_sp_ip_prefix_list_to_route_prefix_list(nw_prefixes, afmly)
                    bgp_rt_prefixes[dut][afmly] = rt_prefixes
                    st.log("BGP SP - Configure {} network on nodes".format(bgp_nw_prefixes[dut][afmly]))
                    result = BGPSP.bgp_sp_bgp_network_advertise_config_unconfig([dut], nw_prefixes, addr_family=afmly)

        if result :
            st.log("BGP SP - Configure {} client to client reflection".format(r1_dut))
            result = BGPSP.bgp_sp_bgp_ctoc_reflection_config_unconfig(r1_dut, cli_type=bgp_cli_type)

        if result :
            st.log("BGP SP - Configure {} client to client reflection".format(r2_dut))
            result = BGPSP.bgp_sp_bgp_ctoc_reflection_config_unconfig(r2_dut, cli_type=bgp_cli_type)

        if result :
            for afmly in addr_family_list:
               rt_prefixes = bgp_rt_prefixes[c1_dut][afmly]

               if result :
                   st.log("BGP SP - Verify {} has routes {}".format(r1_dut, rt_prefixes))
                   result = BGPSP.bgp_sp_bgp_ip_routes_matching([r1_dut], rt_prefixes, afmly)

               if result :
                   st.log("BGP SP - Verify {} doesnt have routes {}".format(r2_dut, rt_prefixes))
                   result = BGPSP.bgp_sp_bgp_ip_routes_not_matching([r2_dut], rt_prefixes, afmly)

               if result :
                   st.log("BGP SP - Verify {} doesnt have routes {}".format(c2_dut, rt_prefixes))
                   result = BGPSP.bgp_sp_bgp_ip_routes_not_matching([c2_dut], rt_prefixes, afmly)

               rt_prefixes = bgp_rt_prefixes[c2_dut][afmly]
               if result :
                   st.log("BGP SP - Verify {} has routes {}".format(r2_dut, rt_prefixes))
                   result = BGPSP.bgp_sp_bgp_ip_routes_matching([r2_dut], rt_prefixes, afmly)

               if result :
                   st.log("BGP SP - Verify {} doesnt have routes {}".format(r1_dut, rt_prefixes))
                   result = BGPSP.bgp_sp_bgp_ip_routes_not_matching([r1_dut], rt_prefixes, afmly)

               if result :
                   st.log("BGP SP - Verify {} doesnt have routes {}".format(c1_dut, rt_prefixes))
                   result = BGPSP.bgp_sp_bgp_ip_routes_not_matching([c1_dut], rt_prefixes, afmly)

               if result :
                   st.log("BGP SP - Configure redistribute connected in {}".format(r1_dut))
                   result = BGPSP.bgp_sp_bgp_redistribute_connected_config_unconfig([r1_dut], afmly)

               if result :
                   nbr_list = BGPSP.bgp_sp_get_bgp_neigbour_ip_between_duts(r1_dut, c1_dut, afmly)
                   bgp_rr_nbr[r1_dut][afmly] = nbr_list
                   st.log("BGP SP - Configure {} {} nbrs {} as reflector client".format(r1_dut, c1_dut, nbr_list))
                   result = BGPSP.bgp_sp_bgp_neighbor_route_reflector_config_unconfig(r1_dut, nbr_list, afmly, cli_type=bgp_cli_type)

               if result :
                   nbr_list = BGPSP.bgp_sp_get_bgp_neigbour_ip_between_duts(r2_dut, c2_dut, afmly)
                   bgp_rr_nbr[r2_dut][afmly] = nbr_list
                   st.log("BGP SP - Configure {} {} nbrs {} as reflector client".format(r2_dut, c2_dut, nbr_list))
                   result = BGPSP.bgp_sp_bgp_neighbor_route_reflector_config_unconfig(r2_dut, nbr_list, afmly, cli_type=bgp_cli_type)

               rt_prefixes = bgp_rt_prefixes[c1_dut][afmly]
               if result :
                   st.wait(5)
                   st.log("BGP SP - Verify {} {} {} has routes {}".format(r1_dut, r2_dut, c2_dut, rt_prefixes))
                   result = BGPSP.bgp_sp_bgp_ip_routes_matching([r1_dut, r2_dut, c2_dut], rt_prefixes, afmly)

               if result :
                   for ip_prefix in rt_prefixes:
                       tb_dut = BGPSP.bgp_sp_get_dut_device(c2_dut)
                       entries = bgpapi.show_bgp_ip_prefix(tb_dut, ip_prefix, afmly)
                       st.log("BGP SP - {} ".format(entries))

               if not result :
                   break

        for dut in [c1_dut, c2_dut] :
           for afmly in addr_family_list:
               nw_prefixes = bgp_nw_prefixes[dut][afmly]
               if len (nw_prefixes) == 0 : continue
               BGPSP.bgp_sp_bgp_network_advertise_config_unconfig([dut], nw_prefixes, addr_family=afmly, config='no')

        for dut in [r1_dut, r2_dut] :
           for afmly in addr_family_list:
               nbr_list = bgp_rr_nbr[dut][afmly]
               if len (nbr_list) == 0 : continue
               BGPSP.bgp_sp_bgp_neighbor_route_reflector_config_unconfig(dut, nbr_list, addr_family=afmly, config='no', cli_type=bgp_cli_type)
               BGPSP.bgp_sp_bgp_redistribute_connected_config_unconfig([r1_dut], afmly, config='no')
           #BGPSP.bgp_sp_bgp_ctoc_reflection_config_unconfig(dut, config='no')

        result_str = "PASSED" if result else "FAILED"
        st.banner("BGP SP - Four Node Linear iBGP Clustor Route Test {}".format(result_str))

        if result:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")


#----------------------------------- STAR TOPO iBGP TEST CLASS ---------------------------

@pytest.fixture(scope='class')
def bgp_sp_star_topo_ibgp_class_hook(request):

    pre_config = True
    if pre_config :
        BGPSP.bgp_sp_cleanup_bgp_routers()
        if BGPSP.bgp_sp_get_dut_count() >= 3 :
            result = BGPSP.bgp_sp_star_topo_bgp_config_unconfig(sess_type='iBGP', addr_family='all', config='yes')
            if not result :
               st.log("BGP SP - Star Topo ibgp config and neighbor session test failed")
               st.report_fail("operation_failed")

    yield

    pre_config = True
    if pre_config :
        if BGPSP.bgp_sp_get_dut_count() >= 3 :
            BGPSP.bgp_sp_star_topo_bgp_config_unconfig(sess_type='iBGP', addr_family='all', config='no')
        BGPSP.bgp_sp_cleanup_bgp_routers()


@pytest.mark.usefixtures('bgp_sp_star_topo_ibgp_class_hook')
class TestBGP_STAR_IBGP:

    def test_bgp_sp_star_ibgp_route_reflector_ipv46(self):

        st.banner("BGP SP - Star topology iBGP route reflector  IPv4 IPv6 Test START ")
        result = True

        star_topo = BGPSP.bgp_sp_dut_get_saved_star_topo()
        BGPSP.bgp_sp_show_topo_path(star_topo)

        if not BGPSP.bgp_sp_test_topo_present(topo_path=star_topo, dut_count=3,  segment_count=2) :
            st.log("BGP SP - Test case topo requirement FAILED")
            st.report_env_fail("test_case_not_executed")
            return

        core_dut = star_topo['start_dut']
        dut_list = star_topo['dut_list']
        spoke_dut_list = copy.deepcopy(dut_list)
        spoke_dut_list.remove(core_dut)

        st.log("BGP SP - Core dut {} and spokes {}".format(core_dut, spoke_dut_list))

        core_asn = BGPSP.bgp_sp_get_bgp_asn(core_dut)
        #tb_core_dut = BGPSP.bgp_sp_get_dut_device(core_dut)

        afmly_list = BGPSP.bgp_sp_get_address_family_list("all")
        rt_prefixes = { 'ipv4' :[], 'ipv6' :[]}

        for spoke_dut in spoke_dut_list :
            for afmly in afmly_list:
                prefixes = BGPSP.bgp_sp_get_dut_null_nhop_static_route_prefixes(spoke_dut, afmly)
                rt_prefixes[afmly] += BGPSP.bgp_sp_ip_prefix_list_to_route_prefix_list(prefixes, afmly)

        if result :
            st.log("BGP SP - Configure redistribute static on all spoke nodes")
            result = BGPSP.bgp_sp_bgp_redistribute_connected_config_unconfig([core_dut], 'all', 'unicast', 'default', 'yes')

        if result :
            result = BGPSP.bgp_sp_bgp_redistribute_static_config_unconfig(spoke_dut_list, 'all', 'unicast', 'default', 'yes')

        if result :
            st.log("BGP SP - verify spokes does not have other spokes network")
            for afmly in afmly_list:
                result = BGPSP.bgp_sp_verify_no_bgp_ip_routes(spoke_dut_list, rt_prefixes[afmly], afmly)
                if not result :
                    st.log("BGP SP - routei no check failed ")
                    break

        if result :
            st.log("BGP SP - Configure {} client to client reflection".format(core_dut))
            result = BGPSP.bgp_sp_bgp_ctoc_reflection_config_unconfig(core_dut)

        if result :
            st.log("BGP SP - Configuring client reflection on {} bgp asn {}".format(core_dut, core_asn))
            result = BGPSP.bgp_sp_bgp_neighbor_route_reflector_config_unconfig(core_dut, nbr_list=[], addr_family='all' )

        if result :
            st.wait(5)
            st.log("BGP SP - verify every spoke has other spokes network due to root reflection")
            for afmly in afmly_list:
                result = BGPSP.bgp_sp_verify_bgp_ip_routes(spoke_dut_list, rt_prefixes[afmly], afmly)
                if not result :
                    st.log("BGP SP - Route reflector iBGP session check Failed")
                    break

        BGPSP.bgp_sp_bgp_ctoc_reflection_config_unconfig(core_dut, vrf='default', config='no')
        BGPSP.bgp_sp_bgp_neighbor_route_reflector_config_unconfig(core_dut, nbr_list=[], addr_family='all', config='no')
        BGPSP.bgp_sp_bgp_redistribute_connected_config_unconfig([core_dut], 'all', 'unicast', 'default', 'no')
        BGPSP.bgp_sp_bgp_redistribute_static_config_unconfig(spoke_dut_list, 'all', 'unicast', 'default', 'no')

        result_str = "PASSED" if result else "FAILED"
        st.banner("BGP SP - Star topology iBGP route reflector test {}".format(result_str))

        if result:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

    def test_bgp_sp_star_ibgp_route_reflector_bgp_clear(self):

        st.banner("BGP SP - Star topology iBGP route reflector bgp clear test START ")
        result = True

        star_topo = BGPSP.bgp_sp_dut_get_saved_star_topo()
        BGPSP.bgp_sp_show_topo_path(star_topo)

        if not BGPSP.bgp_sp_test_topo_present(topo_path=star_topo, dut_count=3,  segment_count=2) :
            st.log("BGP SP - Test case topo requirement FAILED")
            st.report_env_fail("test_case_not_executed")
            return

        core_dut = star_topo['start_dut']
        dut_list = star_topo['dut_list']
        spoke_dut_list = copy.deepcopy(dut_list)
        spoke_dut_list.remove(core_dut)

        st.log("BGP SP - Core dut {} and spokes {}".format(core_dut, spoke_dut_list))

        core_asn = BGPSP.bgp_sp_get_bgp_asn(core_dut)
        #tb_core_dut = BGPSP.bgp_sp_get_dut_device(core_dut)

        afmly_list = BGPSP.bgp_sp_get_address_family_list("all")
        rt_prefixes = { 'ipv4' :[], 'ipv6' :[]}

        for spoke_dut in spoke_dut_list :
            for afmly in afmly_list:
                prefixes = BGPSP.bgp_sp_get_dut_null_nhop_static_route_prefixes(spoke_dut, afmly)
                rt_prefixes[afmly] += BGPSP.bgp_sp_ip_prefix_list_to_route_prefix_list(prefixes, afmly)

        if result :
            st.log("BGP SP - Configure redistribute static on all spoke nodes")
            result = BGPSP.bgp_sp_bgp_redistribute_connected_config_unconfig([core_dut], 'all', 'unicast', 'default', 'yes')

        if result :
            result = BGPSP.bgp_sp_bgp_redistribute_static_config_unconfig(spoke_dut_list, 'all', 'unicast', 'default', 'yes')

        if result :
            st.log("BGP SP - Configure {} client to client reflection".format(core_dut))
            result = BGPSP.bgp_sp_bgp_ctoc_reflection_config_unconfig(core_dut)

        if result :
            st.log("BGP SP - Configuring client reflection on {} bgp asn {}".format(core_dut, core_asn))
            result = BGPSP.bgp_sp_bgp_neighbor_route_reflector_config_unconfig(core_dut, nbr_list=[], addr_family='all' )

        if result :
            st.wait(60)
            st.log("BGP SP - verify every spoke has other spokes network due to root reflection")
            for afmly in afmly_list:
                result = BGPSP.bgp_sp_verify_bgp_ip_routes(spoke_dut_list, rt_prefixes[afmly], afmly)
                if not result :
                    st.log("BGP SP - Route reflector iBGP session check Failed")
                    break

        if result :
            st.log("BGP SP - Clear BGP on all Nodes")
            result = BGPSP.bgp_sp_clear_bgp(dut_list, addr_family="all")

        if result :
            st.wait(5)
            result = BGPSP.bgp_sp_verify_all_bgp_sessions(dut_list, addr_family='all')
            if not result :
                st.log("BGP SP - BGP sessions not up upon clear BGP")

        if result :
            st.log("BGP SP - verify spoke has other spokes network after bgp clear")
            for afmly in afmly_list:
                result = BGPSP.bgp_sp_verify_bgp_ip_routes(spoke_dut_list, rt_prefixes[afmly], afmly)
                if not result :
                    st.log("BGP SP - Route reflector iBGP session check Failed")
                    break

        BGPSP.bgp_sp_bgp_ctoc_reflection_config_unconfig(core_dut, vrf='default', config='no')
        BGPSP.bgp_sp_bgp_neighbor_route_reflector_config_unconfig(core_dut, nbr_list=[], addr_family='all', config='no')
        BGPSP.bgp_sp_bgp_redistribute_connected_config_unconfig([core_dut], 'all', 'unicast', 'default', 'no')
        BGPSP.bgp_sp_bgp_redistribute_static_config_unconfig(spoke_dut_list, 'all', 'unicast', 'default', 'no')

        result_str = "PASSED" if result else "FAILED"
        st.banner("BGP SP - Star topology iBGP route reflector test {}".format(result_str))

        if result:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

    def test_bgp_sp_star_ibgp_route_reflector_bgp_sess_flap(self):

        st.banner("BGP SP - Star topology iBGP route reflector bgp session flap test START ")
        result = True
        dut_int_shut = False

        star_topo = BGPSP.bgp_sp_dut_get_saved_star_topo()
        BGPSP.bgp_sp_show_topo_path(star_topo)

        if not BGPSP.bgp_sp_test_topo_present(topo_path=star_topo, dut_count=3,  segment_count=2) :
            st.log("BGP SP - Test case topo requirement FAILED")
            st.report_env_fail("test_case_not_executed")
            return

        core_dut = star_topo['start_dut']
        dut_list = star_topo['dut_list']
        spoke_dut_list = copy.deepcopy(dut_list)
        spoke_dut_list.remove(core_dut)

        st.log("BGP SP - Core dut {} and spokes {}".format(core_dut, spoke_dut_list))

        core_asn = BGPSP.bgp_sp_get_bgp_asn(core_dut)
        #tb_core_dut = BGPSP.bgp_sp_get_dut_device(core_dut)

        afmly_list = BGPSP.bgp_sp_get_address_family_list("all")
        rt_prefixes = { 'ipv4' :[], 'ipv6' :[]}

        for spoke_dut in spoke_dut_list :
            for afmly in afmly_list:
                prefixes = BGPSP.bgp_sp_get_dut_null_nhop_static_route_prefixes(spoke_dut, afmly)
                rt_prefixes[afmly] += BGPSP.bgp_sp_ip_prefix_list_to_route_prefix_list(prefixes, afmly)

        if result :
            st.log("BGP SP - Configure redistribute static on all spoke nodes")
            result = BGPSP.bgp_sp_bgp_redistribute_connected_config_unconfig([core_dut], 'all', 'unicast', 'default', 'yes')

        if result :
            result = BGPSP.bgp_sp_bgp_redistribute_static_config_unconfig(spoke_dut_list, 'all', 'unicast', 'default', 'yes')

        if result :
            st.log("BGP SP - Configure {} client to client reflection".format(core_dut))
            result = BGPSP.bgp_sp_bgp_ctoc_reflection_config_unconfig(core_dut)

        if result :
            st.log("BGP SP - Configuring client reflection on {} bgp asn {}".format(core_dut, core_asn))
            result = BGPSP.bgp_sp_bgp_neighbor_route_reflector_config_unconfig(core_dut, nbr_list=[], addr_family='all' )


        if result :
            st.wait(60)
            st.log("BGP SP - verify every spoke has other spokes network due to root reflection")
            for afmly in afmly_list:
                result = BGPSP.bgp_sp_verify_bgp_ip_routes(spoke_dut_list, rt_prefixes[afmly], afmly)
                if not result :
                    st.log("BGP SP - Route reflector iBGP session check Failed")
                    break

        if result :
            st.log("BGP SP - Flap BGP BGP session by interface down")
            dut_int_shut = True
            for _, segt_data_links in star_topo['segment'].items():
                segt_data = segt_data_links[0]
                lcl_dut = segt_data['lcl_dut']
                dut_link_list = BGPSP.bgp_sp_dut_get_all_links(lcl_dut)
                for lcl_link in dut_link_list:
                    result = BGPSP.bgp_sp_dut_interface_shut_noshut(lcl_dut, lcl_link, shut='yes')
                    #BGPSP.bgp_sp_show_dut_if_cmd_logs(lcl_dut)
                    if not result :
                        st.log("BGP SP - {} {} shutdown Failed".format(lcl_dut, lcl_link))
                        break
                break

        if result :
            st.log("BGP SP - Verify All sesions are down due to timeout")
            st.log("BGP SP -  waiting for session timeout.....")
            st.wait(70)
            result = BGPSP.bgp_sp_verify_all_bgp_sessions(dut_list, addr_family='all', state='down')
            if result :
                st.log("BGP SP - Route reflector bgp session down check Failed")
                result = False
            result = True

        if result :
            st.log("BGP SP - verify spokes do not have other spokes network after interface down")
            for afmly in afmly_list:
                result = BGPSP.bgp_sp_verify_no_bgp_ip_routes(spoke_dut_list, rt_prefixes[afmly], afmly, threaded_run=False)
                if not result :
                    st.log("BGP SP - routei no check failed ")
                    break

        if result :
            st.log("BGP SP - Bring up all interfaces again after session down")
            for _, segt_data_links in star_topo['segment'].items():
                segt_data = segt_data_links[0]
                lcl_dut = segt_data['lcl_dut']
                dut_link_list = BGPSP.bgp_sp_dut_get_all_links(lcl_dut)
                for lcl_link in dut_link_list:
                    result = BGPSP.bgp_sp_dut_interface_shut_noshut(lcl_dut, lcl_link, shut='no')
                    #BGPSP.bgp_sp_show_dut_if_cmd_logs(lcl_dut)
                    if not result :
                        st.log("BGP SP - {} {} shutdown Failed".format(lcl_dut, lcl_link))
                        break
                if not result : dut_int_shut = False
                break

        if result :
            st.log("BGP SP - verify bgp sessions are up after interfaces up....")
            st.wait(10)
            result = BGPSP.bgp_sp_verify_all_bgp_sessions(dut_list, addr_family='all')
            if not result :
                st.log("BGP SP - Route reflector bgp session up check Failed")

        if result :
            st.log("BGP SP - verify every spoke has other spokes network due to root reflection")
            for afmly in afmly_list:
                result = BGPSP.bgp_sp_verify_bgp_ip_routes(spoke_dut_list, rt_prefixes[afmly], afmly, threaded_run=False)
                if not result :
                    st.log("BGP SP - Route reflector iBGP session check Failed")
                    break

        BGPSP.bgp_sp_bgp_ctoc_reflection_config_unconfig(core_dut, vrf='default', config='no')
        BGPSP.bgp_sp_bgp_neighbor_route_reflector_config_unconfig(core_dut, nbr_list=[], addr_family='all', config='no')
        BGPSP.bgp_sp_bgp_redistribute_connected_config_unconfig([core_dut], 'all', 'unicast', 'default', 'no')
        BGPSP.bgp_sp_bgp_redistribute_static_config_unconfig(spoke_dut_list, 'all', 'unicast', 'default', 'no')

        if dut_int_shut :
            st.log("BGP SP - Flap BGP BGP session by interface up")
            for _, segt_data_links in star_topo['segment'].items():
                segt_data = segt_data_links[0]
                lcl_dut = segt_data['lcl_dut']
                dut_link_list = BGPSP.bgp_sp_dut_get_all_links(lcl_dut)
                for lcl_link in dut_link_list:
                    temp_result = BGPSP.bgp_sp_dut_interface_shut_noshut(lcl_dut, lcl_link, shut='no')
                    #BGPSP.bgp_sp_show_dut_if_cmd_logs(lcl_dut)
                    if not temp_result :
                        st.log("BGP SP - {} {} shutdown Failed".format(lcl_dut, lcl_link))
                        break
                #dut_int_shut = False
                break

        result_str = "PASSED" if result else "FAILED"
        st.banner("BGP SP - Star topology iBGP route reflector bgp session flap test {}".format(result_str))

        if result:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

