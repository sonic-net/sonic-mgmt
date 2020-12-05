# BGP 4 node topology test cases
import pytest

from spytest import st, utils

import apis.routing.ip as ipapi
import apis.routing.bgp as bgpapi
import BGP.bgp4nodelib as bgp4nodelib
from spytest.utils import exec_all
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
        st.error("Ping failed between DUTs")
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
    # On DUT1 and DUT3, create BGP with 4byte ASN
    dut1_as = 6500001
    dut1 = topo['dut_list'][0]
    dut3_as = 6500002
    dut3 = topo['dut_list'][2]
    result = 0
    wait_timer = 150

    st.banner("Verify the ebgp multihop functionality with 4 byte AS Number")

    # Configure bgp on DUT1 and configure DUT3 as neighbor with ebgp-multihop ttl set to 5
    st.log("Configure eBGP on DUT1 with Neighbor as DUT3 with multihop set to maximum hops of 5")
    bgpapi.config_bgp(dut1, local_as=dut1_as, neighbor=topo['D3D2P1_ipv4'], remote_as=dut3_as, config_type_list=["neighbor","ebgp_mhop"], ebgp_mhop='5')

    # Add static route towards neighbor DUT3
    st.log("Add static route towards DUT3")
    ipapi.create_static_route(dut1, topo['D1D2P1_neigh_ipv4'], "{}/24".format(topo['D3D2P1_ipv4']))

    # Configure bgp on DUT3 and configure DUT1 as neighbor with ebgp-multihop ttl set to 5
    st.log("Configure eBGP on DUT3 with DUT1 as Neighbor with multihop set to maximum hops of 5")
    bgpapi.config_bgp(dut3, local_as=dut3_as, neighbor=topo['D1D2P1_ipv4'], remote_as=dut1_as, config_type_list=["neighbor","ebgp_mhop"], ebgp_mhop='5')

    # Add static route towards neighbor DUT1
    st.log("Add static route towards DUT1")
    ipapi.create_static_route(dut3, topo['D3D2P1_neigh_ipv4'], "{}/24".format(topo['D1D2P1_ipv4']))

    st.log("Verify BGP neighborship on DUT1")
    #result = bgpapi.verify_bgp_summary(dut1, family='ipv4', neighbor=topo['D3D2P1_ipv4'], state='Established')
    if not utils.poll_wait(bgpapi.verify_bgp_summary, wait_timer, dut1, family='ipv4', neighbor=topo['D3D2P1_ipv4'],
                           state='Established'):
        st.log("Failed to form BGP eBGP multihop peering with 4byte ASN")
        result += 1
    if result == 0:
        st.log("Pass: BGP neighborship established between DUT1 and DUT3")
    else:
        st.error("Fail: BGP neighborship not established between DUT1 and DUT3")
        st.banner("Collecting techsupport")
        exec_all(True, [[st.generate_tech_support, topo['dut_list'][0], "test_ft_bgp_ebgp_multihop_4byteASN"],
                        [st.generate_tech_support, topo['dut_list'][1], "test_ft_bgp_ebgp_multihop_4byteASN"],
                        [st.generate_tech_support, topo['dut_list'][2], "test_ft_bgp_ebgp_multihop_4byteASN"]])

    #Clear applied configs
    st.banner("Cleanup for TestFunction")
    bgpapi.cleanup_router_bgp(dut1)
    bgpapi.cleanup_router_bgp(dut3)
    ipapi.delete_static_route(dut1, topo['D1D2P1_neigh_ipv4'], "{}/24".format(topo['D3D2P1_ipv4']))
    ipapi.delete_static_route(dut3, topo['D3D2P1_neigh_ipv4'], "{}/24".format(topo['D1D2P1_ipv4']))

    if result == 0:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

################################################################################
# BGP Confederation test cases  - START

def bgp_confed_pre_config():
    st.banner("BGP CONFED CLASS CONFIG - START")
    bgp4nodelib.l3tc_vrfipv4v6_confed_bgp_config(config='yes')
    # BGP Neighbour Verification
    if not poll_wait(bgp4nodelib.l3tc_vrfipv4v6_address_confed_bgp_check, 10, config_type='all'):
        st.error("Neighborship failed to Establish between DUTs")
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

# TestBGPConfed class
@pytest.mark.usefixtures('bgp_confed_class_hook')
class TestBGPConfed():

    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_pass
    def test_ipv6_confed_route_distribution(self):
        st.banner("Verify the config of BGP v6 confederation and router advertisement")

        st.log("Advertise a network from DUT1 and check if it is learnt on confederation peer DUT3")
        dut1_name = topo['dut_list'][0]
        dut3_name = topo['dut_list'][2]
        network_ipv4 = '131.5.6.0/24'
        network_ipv6 = '2000:1::0/64'

        # Advertise a network to peer

        bgpapi.config_bgp_network_advertise(dut1_name, topo['D1_as'], network_ipv4, network_import_check=True)
        bgpapi.config_bgp_network_advertise(dut1_name, topo['D1_as'], network_ipv6, addr_family='ipv6', config='yes', network_import_check=True)
        entries = bgpapi.get_ip_bgp_route(dut3_name, family="ipv4", network=network_ipv4)
        entries1 = bgpapi.get_ip_bgp_route(dut3_name, family="ipv6", network="2000:1::/64")
        if entries and entries1:
            st.log("Pass: Routes advertised by DUT1 found on DUT3")
        else:
            st.error("Fail: Route advertised by DUT1 not found on DUT3")
            st.banner("Collecting techsupport")
            exec_all(True, [[st.generate_tech_support, topo['dut_list'][0], "test_ipv6_confed_route_distribution"],
                            [st.generate_tech_support, topo['dut_list'][1], "test_ipv6_confed_route_distribution"],
                            [st.generate_tech_support, topo['dut_list'][2], "test_ipv6_confed_route_distribution"]])

        # Clear applied configs
        st.banner("Cleanup for TestFunction")
        bgpapi.config_bgp_network_advertise(dut1_name, topo['D1_as'], network_ipv4, config='no' )
        bgpapi.config_bgp_network_advertise(dut1_name, topo['D1_as'], network_ipv6, addr_family='ipv6', config='no')

        if entries and entries1:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_pass
    def test_ipv6_confed_with_rr(self):
        st.banner("Verify Route Reflector behavior within a confederation of BGP v6 peers")
        st.banner("Consider the right confederation iBGP AS and check Route Reflector functionality between the 3 iBGP Routers")

        network_ipv4 = '131.6.6.0/24'
        network_ipv6 = '3000:1::0/64'
        # iBGP AS is one of D2/D3/D4 ASN
        iBGP_as=topo['D2_as']

        st.log("Advertise an IPv4 and an IPv6 network from DUT2 through BGP")
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv4, network_import_check=True)
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv6, addr_family='ipv6', config='yes', network_import_check=True)

        st.log("Check the network on the 3rd iBGP peer DUT4 is not learnt because Route Reflector is not configured on peer DUT3")
        entries = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv4", network=network_ipv4)
        entries1 = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv6", network="3000:1::/64")

        if not entries and not entries1:
            st.log("Pass: DUT4 did not learn routes without configuring Route Reflector on peer DUT3")
        else:
            st.error("Fail: DUT4 learned route without configuring Route Reflector on peer DUT3")
            st.banner("Collecting techsupport")
            exec_all(True, [[st.generate_tech_support, topo['dut_list'][1], "test_ipv6_confed_with_rr"],
                            [st.generate_tech_support, topo['dut_list'][2], "test_ipv6_confed_with_rr"],
                            [st.generate_tech_support, topo['dut_list'][3], "test_ipv6_confed_with_rr"]])
            # Clear applied configurations
            st.banner("Cleanup for TestFunction")
            bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv4, config='no' )
            bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv6, addr_family='ipv6', config='no')
            st.report_fail("test_case_failed")

        st.log("Now configure Route Reflector on DUT3")
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv4', topo['D3D4P1_neigh_ipv4'], 'yes')
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv6', topo['D3D4P1_neigh_ipv6'], 'yes')

        st.wait(10)
        st.log("Now the routes should be learnt on the 3rd IBGP peer DUT4")
        entries2 = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv4", network=network_ipv4)
        entries3 = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv6", network="3000:1::/64")
        if entries2 and entries3:
            st.log("Pass: DUT4 learned the routes advertised by peer DUT2")
        else:
            st.error("Fail: DUT4 did not learn the routes advertised by peer DUT2")
            st.banner("Collecting techsupport")
            exec_all(True, [[st.generate_tech_support, topo['dut_list'][1], "test_ipv6_confed_with_rr"],
                           [st.generate_tech_support, topo['dut_list'][2], "test_ipv6_confed_with_rr"],
                           [st.generate_tech_support, topo['dut_list'][3], "test_ipv6_confed_with_rr"]])

        # Clear applied configurations
        st.banner("Cleanup for TestFunction")
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv4, config='no' )
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv6, addr_family='ipv6', config='no')
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv4', topo['D3D4P1_neigh_ipv4'], 'no')
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv6', topo['D3D4P1_neigh_ipv6'], 'no')

        if entries2 and entries3:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

    @pytest.mark.rmap
    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_fail
    def test_confed_route_distribution_with_rmap(self):
        st.banner("Verify the behavior of Route-Maps over confederation peers")
        result = False

        network1 = '134.5.6.0/24'
        network2 = '134.5.7.0/24'
        network3 = '134.5.8.0'
        as_path = '200'
        access_list1 = 'test-access-list1'
        access_list2 = 'test-access-list2'
        access_list3 = 'test-access-list3'

        st.log("Create access-lists and a route-map in DUT1, add to it permit, deny and AS-path prepending policies")
        # Create access-list test-access-list1
        ipapi.config_access_list(topo['dut_list'][0], access_list1, network3+'/24', 'permit', seq_num="1")
        # Create route-map and permit network3
        ipapi.config_route_map_match_ip_address(topo['dut_list'][0], 'test-rmap', 'permit', '10', access_list1)

        # Add set option to prepend as-path 200
        ipapi.config_route_map_set_aspath(topo['dut_list'][0], 'test-rmap', 'permit', '10', as_path)

        # Create access-list test-access-list2
        ipapi.config_access_list(topo['dut_list'][0], access_list2, network1, 'deny', seq_num="2")
        # In route-map, deny network1
        ipapi.config_route_map_match_ip_address(topo['dut_list'][0], 'test-rmap', 'deny', '20', access_list2)

        # Create access-list test-access-list3
        ipapi.config_access_list(topo['dut_list'][0], access_list3, network2, 'permit', seq_num="3")
        # In route-map, permit network2
        ipapi.config_route_map_match_ip_address(topo['dut_list'][0], 'test-rmap', 'permit', '30', access_list3)

        # Advertise three networks from leaf
        st.log("Advertise the networks from DUT1 through BGP and associate with the route-map")
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network1, 'test-rmap', network_import_check=True)
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network2, 'test-rmap', network_import_check=True)
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network3+'/24', 'test-rmap', network_import_check=True)

        st.log("Verify in peer DUT2 the network configured in {} has the AS-path prepended".format(access_list1))
        # Verify that the neighbor has the as-path prepended
        output = bgpapi.show_bgp_ipvx_prefix(topo['dut_list'][1], prefix=network3, masklen=topo['D1_as'])
        for x in output:  # type: basestring
            peer_asn = x['peerasn']
            peer_asn = peer_asn.split()
            for each in peer_asn:
                if each == as_path:
                    result = True
        if result:
            st.log("Pass: AS-Path {} found to be prepended with network {}/24".format(as_path, network3))
        else:
            st.error("Fail: AS-Path {} not found to be prepended".format(as_path))

        # Verify that network1 is not present in ip route table
        st.log("Verify that peer DUT2 not learnt the network configured as 'deny' in {}".format(access_list2))
        n1 = ipapi.verify_ip_route(topo['dut_list'][1], ip_address=network1)
        if n1 is False:
            result = result & True
            st.log("Pass: DUT2 did not learn network {}".format(network1))
        else:
            result = result & False
            st.error("Fail: DUT2 learned the network {}".format(network1))

        # Verify that network2 is present in ip route table
        st.log("Verify that peer DUT2 learnt the network configured as 'permit' in {}".format(access_list3))
        n2 = ipapi.verify_ip_route(topo['dut_list'][1], ip_address=network2)
        if n2:
            result = result & True
            st.log("Pass: DUT2 learned the network {}".format(network2))
        else:
            result = result & False
            st.error("Fail: DUT2 did not learn network {}".format(network2))

        if not result:
            st.banner("Collecting techsupport")
            exec_all(True, [[st.generate_tech_support, topo['dut_list'][0], "test_confed_route_distribution_with_rmap"],
                            [st.generate_tech_support, topo['dut_list'][1], "test_confed_route_distribution_with_rmap"]])

        ipapi.config_route_map_mode(topo['dut_list'][0], 'test-rmap', 'permit', '10', config='no')

        # Clear applied configurations
        st.banner("Cleanup for TestFunction")
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list3', network2, 'permit', config='no', seq_num="3")
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list2', network1, 'deny', config='no', seq_num="2")
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list1', network3+'/24', 'permit', config='no', seq_num="1")

        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network1, 'test-rmap', config='no')
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network2, 'test-rmap', config='no')
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network3+'/24', 'test-rmap', config='no')

        if result:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

# BGP Confederation test cases  - END
################################################################################
