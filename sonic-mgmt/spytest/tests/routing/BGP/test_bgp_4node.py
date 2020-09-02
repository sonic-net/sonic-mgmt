# BGP 4 node topology test cases
import pytest

from spytest import st

import apis.routing.ip as ipapi
import apis.routing.bgp as bgpapi
import BGP.bgp4nodelib as bgp4nodelib

from utilities.common import poll_wait

@pytest.fixture(scope="module", autouse=True)
def bgp_module_hooks(request):
    bgp_pre_config()
    yield
    bgp_pre_config_cleanup()

# bgp module level pre config function
def bgp_pre_config():
    global topo
    st.banner("BGP MODULE CONFIG - START")
    st.log("Ensure minimum linear 4-node topology")
    st.ensure_min_topology('D1D2:1', 'D2D3:1', 'D3D4:1')
    bgp4nodelib.l3_ipv4v6_address_config_unconfig(config='yes', config_type='all')
    # Ping Verification
    if not bgp4nodelib.l3tc_vrfipv4v6_address_ping_test(config_type='all', ping_count=3):
        st.error("Ping failed in between DUTs")
        st.report_fail('test_case_failed')
    topo = bgp4nodelib.get_confed_topology_info()
    st.log(topo)
    st.banner("BGP MODULE CONFIG - END")

# bgp module level pre config cleanup function
def bgp_pre_config_cleanup():
    st.banner("BGP MODULE CONFIG CLEANUP - START")
    bgp4nodelib.l3_ipv4v6_address_config_unconfig(config='no')
    st.banner("BGP MODULE CONFIG CLEANUP - END")


@pytest.fixture(scope="function")
def bgp_func_hooks(request):
    yield

@pytest.mark.bgp_ft
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_bgp_ebgp_multihop_4byteASN():
    """

    Verify the functioning of ebgp multihop command with 4 byte ASN
    """
    #On DUT1 and DUT3, create BGP with 4byte ASN
    dut1_as = 6500001
    dut1 = topo['dut_list'][0]
    dut3_as = 6500002
    dut3 = topo['dut_list'][2]

    #Configure bgp on DUT1 and add DUT3 as neighbor with ebgp-multihop ttl set to 5
    bgpapi.config_bgp(dut1, local_as= dut1_as, neighbor=topo['D3D2P1_ipv4'], remote_as =dut3_as, config_type_list=["neighbor","ebgp_mhop"], ebgp_mhop='5')
    #Add static route to DUT3 neighbor
    ipapi.create_static_route(dut1, topo['D1D2P1_neigh_ipv4'], "{}/24".format(topo['D3D2P1_ipv4']))
    #Configure bgp on DUT3 and add DUT1 as neighbor with ebgp-multihop ttl set to 5
    bgpapi.config_bgp(dut3, local_as= dut3_as, neighbor=topo['D1D2P1_ipv4'], remote_as =dut1_as, config_type_list=["neighbor","ebgp_mhop"], ebgp_mhop='5')
    #Add static route to DUT1 neighbor
    ipapi.create_static_route(dut3, topo['D3D2P1_neigh_ipv4'], "{}/24".format(topo['D1D2P1_ipv4']))

    result = bgpapi.verify_bgp_summary(dut1, family='ipv4', neighbor=topo['D3D2P1_ipv4'], state='Established')

    #Clear applied configs
    bgpapi.cleanup_router_bgp(dut1)
    bgpapi.cleanup_router_bgp(dut3)
    ipapi.delete_static_route(dut1, topo['D1D2P1_neigh_ipv4'], "{}/24".format(topo['D3D2P1_ipv4']))
    ipapi.delete_static_route(dut3, topo['D3D2P1_neigh_ipv4'], "{}/24".format(topo['D1D2P1_ipv4']))

    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

################################################################################
#BGP Confederation test cases  - START

def bgp_confed_pre_config():
    st.banner("BGP CONFED CLASS CONFIG - START")
    bgp4nodelib.l3tc_vrfipv4v6_confed_bgp_config(config='yes')
    # BGP Neighbour Verification
    if not poll_wait(bgp4nodelib.l3tc_vrfipv4v6_address_confed_bgp_check, 10, config_type='all'):
        st.error("Neighbour is failed to Establish between DUTs")
        st.report_fail('test_case_failed')
    st.log("Getting all topology info related to connectivity / TG and other parameters between duts")
    st.banner("BGP CONFED CLASS CONFIG - END")

def bgp_confed_pre_config_cleanup():
    st.banner("BGP CONFED CLASS CONFIG CLEANUP - START")
    bgp4nodelib.l3tc_vrfipv4v6_confed_bgp_config(config='no')
    st.banner("BGP RIF CLASS CONFIG CLEANUP - END")

@pytest.fixture(scope='class')
def bgp_confed_class_hook(request):
    bgp_confed_pre_config()
    yield
    bgp_confed_pre_config_cleanup()

#TestBGPConfed class
@pytest.mark.usefixtures('bgp_confed_class_hook')
class TestBGPConfed():

    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_pass
    def test_ipv6_confed_route_distribution(self):
        st.log("Verify the config of BGP v6 confederation and router advertisement")

        st.log("Advertise a network from DUT1 and check if it's learnt on confed peer DUT3")
        dut1_name = topo['dut_list'][0]
        dut3_name = topo['dut_list'][2]
        network_ipv4 = '131.5.6.0/24'
        network_ipv6 = '2000:1::0/64'

        #Advertise a network to peer

        bgpapi.config_bgp_network_advertise(dut1_name, topo['D1_as'], network_ipv4)
        bgpapi.config_bgp_network_advertise(dut1_name, topo['D1_as'], network_ipv6, addr_family='ipv6', config='yes')
        entries = bgpapi.get_ip_bgp_route(dut3_name, family="ipv4", network=network_ipv4)
        entries1 = bgpapi.get_ip_bgp_route(dut3_name, family="ipv6", network="2000:1::/64")

        bgpapi.config_bgp_network_advertise(dut1_name, topo['D1_as'], network_ipv4, config='no' )
        bgpapi.config_bgp_network_advertise(dut1_name, topo['D1_as'], network_ipv6, addr_family='ipv6', config='no')
        if entries and entries1:
            st.log("Advertised route present on DUT3")
        else:
            st.log("Advertised route not present on DUT3")
            st.report_fail("test_case_failed")

        st.report_pass("test_case_passed")

    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_pass
    def test_ipv6_confed_with_rr(self):
        st.log("Verify the behavior of route-reflector within a confederation of BGPv6 peers")
        st.log("Consider the right confed iBGP_as and check RR functionality between the 3 iBGP routers")

        network_ipv4 = '131.6.6.0/24'
        network_ipv6 = '3000:1::0/64'
        #IBGP as is one of D2/D3/D4 asn
        iBGP_as=topo['D2_as']

        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv4)
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv6, addr_family='ipv6', config='yes')

        st.log("Check the network on the 3rd IBGP peer is not learnt becaue RR is not configured")
        entries = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv4", network=network_ipv4)
        entries1 = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv6", network="3000:1::/64")

        if entries and entries1:
           st.log("Routes learnt on the 3rd IBGP peer withour configuring RR")
           bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv4, config='no' )
           bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv6, addr_family='ipv6', config='no')
           st.report_fail("test_case_failed")

        st.log(" Now configure RR")
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv4', topo['D3D4P1_neigh_ipv4'], 'yes')
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv6', topo['D3D4P1_neigh_ipv6'], 'yes')

        st.wait(10)
        st.log("Now the routes should be learnt on the 3rd IBGP peer")
        entries2 = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv4", network=network_ipv4)
        entries3 = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv6", network="3000:1::/64")

        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv4, config='no' )
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv6, addr_family='ipv6', config='no')
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv4', topo['D3D4P1_neigh_ipv4'], 'no')
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv6', topo['D3D4P1_neigh_ipv6'], 'no')

        if not entries2 and not entries3:
           st.report_fail("test_case_failed")

        st.report_pass("test_case_passed")

    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_fail
    def test_confed_route_distribution_with_rmap(self):
        st.log("Verify the behavior of route-maps over confederation peers")
        result = True

        network1 = '134.5.6.0/24'
        network2 = '134.5.7.0/24'
        network3 = '134.5.8.0'

        #Create route-map and permit network3
        ipapi.config_route_map_match_ip_address(topo['dut_list'][0], 'test-rmap', 'permit', '10', 'test-access-list1')
        #Add set option to prepend as-path 200
        ipapi.config_route_map_set_aspath(topo['dut_list'][0], 'test-rmap', 'permit', '10', '200')
        #Create access-list test-access-list1
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list1', network3+'/24', 'permit')

        #Advertise two networks from leaf
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network1, 'test-rmap')
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network2, 'test-rmap')
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network3+'/24', 'test-rmap')

        #In route-map, deny network1
        ipapi.config_route_map_match_ip_address(topo['dut_list'][0], 'test-rmap', 'deny', '20', 'test-access-list2')
        #Create access-list test-access-list2
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list2', network1, 'deny')

        #In route-map, permit network2
        ipapi.config_route_map_match_ip_address(topo['dut_list'][0], 'test-rmap', 'permit', '30', 'test-access-list3')
        #Create access-list test-access-list3
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list3', network2, 'permit')

        #verify that the neighbor has the as-path prepended
        output = bgpapi.show_bgp_ipvx_prefix(topo['dut_list'][1], prefix=network3, masklen=topo['D1_as'])
        st.log(output)
        for x in output:  # type: basestring
            as_path = x['peerasn']
            as_path = as_path.split()
            for each in as_path:
                if each == "200":
                    result = True

        #verify that network1 is not present in bgp routes
        n1 = ipapi.verify_ip_route(topo['dut_list'][1],ip_address=network1)
        if (n1 == False):
            result = result & True
        else:
            result = result & False

        #verify that network2 is present in bgp routes
        n2 = ipapi.verify_ip_route(topo['dut_list'][1],ip_address=network2)
        if (n2):
            result = result & True
        else:
            result = result & False

        #CLear applied configs
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list3', network2, 'permit', config='no')
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list2', network1, 'deny', config='no')
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list1', network3+'/24', 'permit', config='no')

        ipapi.config_route_map_mode(topo['dut_list'][0], 'test-rmap', 'permit', '10', config='no')

        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network1, 'test-rmap', config='no')
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network2, 'test-rmap', config='no')
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network3+'/24', 'test-rmap', config='no')

        if result:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

#BGP Confederation test cases  - END
################################################################################

