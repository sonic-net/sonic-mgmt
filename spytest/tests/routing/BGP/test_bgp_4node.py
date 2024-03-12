# BGP 4 node topology test cases
import pytest

from spytest import st, SpyTestDict

import apis.routing.bgp as bgpapi
import apis.routing.ip as ipapi
import BGP.bgp4nodelib as bgp4nodelib

from utilities.common import ExecAllFunc

bgp_4node_data = SpyTestDict()
bgp_4node_data.dut1_as = 65001
bgp_4node_data.dut2_as = 65002
bgp_4node_data.dut3_as = 65003
bgp_4node_data.dut4_as = 65004
bgp_4node_data.network1 = '172.16.2.2/32'
bgp_4node_data.network2 = '172.16.4.4/32'
bgp_4node_data.aggr_route = '172.16.0.0/16'
bgp_4node_data.aggr_route1 = '6002:1::/64'
bgp_4node_data.wait_timer = 150
bgp_4node_data.network3 = '6002:1::1/128'
bgp_4node_data.network4 = '6002:1::2/128'
bgp_4node_data.network5 = '50.50.50.50/32'
bgp_4node_data.network6 = '60.60.60.60/32'
bgp_4node_data.network7 = '70.70.70.70/32'

bgp_4node_data.dut1_as_4byte = 4294967292
bgp_4node_data.dut2_as_4byte = 4294967293
bgp_4node_data.dut3_as_4byte = 4294967294
bgp_4node_data.dut4_as_4byte = 4294967295
bgp_4node_data.loopback0 = 'Loopback0'
bgp_4node_data.loopback0_addr6 = '6002:1::3/128'
bgp_4node_data.loopback0_addr6_net = '6002:1::3'
bgp_4node_data.loopback1 = 'Loopback1'
bgp_4node_data.loopback1_addr4 = '172.16.5.5/32'
bgp_4node_data.loopback1_addr4_net = '172.16.5.5'
bgp_4node_data.loopback1_addr6 = '7002:1::3/128'
bgp_4node_data.loopback1_addr6_net = '7002:1::3'
bgp_4node_data.d2d4_ip = "10.5.0.1"
bgp_4node_data.d4d2_ip = "10.5.0.4"
bgp_4node_data.d4network = "172.16.50.50/32"


@pytest.fixture(scope="module", autouse=True)
def bgp_module_hooks(request):
    global sub_intf
    sub_intf = st.get_args("routed_sub_intf")
    bgp_pre_config()
    yield
    bgp_pre_config_cleanup()

# bgp module level pre config function


def bgp_pre_config():
    global topo
    st.banner("BGP MODULE CONFIG - START")
    st.ensure_min_topology('D1D2:1', 'D2D3:1', 'D2D4:1', 'D3D4:1', 'D3D1:1')
    if sub_intf is not True:
        bgp4nodelib.l3_ipv4v6_address_config_unconfig(config='yes', config_type='all')
    else:
        bgp4nodelib.l3_ipv4v6_address_config_unconfig_sub_intf(config='yes', config_type='all')
    # Ping Verification
    if not bgp4nodelib.l3tc_vrfipv4v6_address_ping_test(config_type='all', ping_count=3):
        msg = st.error("Ping failed between DUTs")
        st.report_fail('msg', msg)
    topo = bgp4nodelib.get_confed_topology_info()
    st.log(topo)
    st.banner("BGP MODULE CONFIG - END")

# bgp module level pre config cleanup function


def bgp_pre_config_cleanup():
    st.banner("BGP MODULE CONFIG CLEANUP - START")
    if sub_intf is not True:
        bgp4nodelib.l3_ipv4v6_address_config_unconfig(config='no')
    else:
        bgp4nodelib.l3_ipv4v6_address_config_unconfig_sub_intf(config='no')
    st.banner("BGP MODULE CONFIG CLEANUP - END")


@pytest.fixture(scope="function")
def bgp_func_hooks(request):
    yield


################################################################################
# BGP Confederation test cases  - START


def bgp_confed_pre_config():
    st.banner("BGP CONFED CLASS CONFIG - START")
    bgp4nodelib.l3tc_vrfipv4v6_confed_bgp_config(config='yes')
    # BGP Neighbour Verification
    if not st.poll_wait(bgp4nodelib.l3tc_vrfipv4v6_address_confed_bgp_check, 10, config_type='all'):
        msg = st.error("Neighborship failed to Establish between DUTs")
        st.report_fail('msg', msg)
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
    @pytest.mark.inventory(feature='Regression', release='Arlo+')
    @pytest.mark.inventory(testcases=['ft_bgp_confedv6_config_adv'])
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
        errs = []
        if entries and entries1:
            st.log("Pass: Routes advertised by DUT1 found on DUT3")
        else:
            errs.append(st.error("Fail: Route advertised by DUT1 not found on DUT3"))
            st.banner("Collecting techsupport")
            st.generate_tech_support(topo['dut_list'][0:3], "test_ipv6_confed_route_distribution")

        # Clear applied configs
        st.banner("Cleanup for TestFunction")
        bgpapi.config_bgp_network_advertise(dut1_name, topo['D1_as'], network_ipv4, config='no')
        bgpapi.config_bgp_network_advertise(dut1_name, topo['D1_as'], network_ipv6, addr_family='ipv6', config='no')

        st.report_result(errs)

    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_pass
    @pytest.mark.inventory(feature='Regression', release='Arlo+')
    @pytest.mark.inventory(testcases=['ft_bgp_confedv6_route_reflector'])
    def test_ipv6_confed_with_rr(self):
        st.banner("Verify Route Reflector behavior within a confederation of BGP v6 peers")
        st.banner("Consider the right confederation iBGP AS and check Route Reflector functionality between the 3 iBGP Routers")

        network_ipv4 = '131.6.6.0/24'
        network_ipv6 = '3000:1::0/64'
        # iBGP AS is one of D2/D3/D4 ASN
        iBGP_as = topo['D2_as']

        st.log("Advertise an IPv4 and an IPv6 network from DUT2 through BGP")
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv4, network_import_check=True)
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv6, addr_family='ipv6', config='yes', network_import_check=True)

        st.log("Check the network on the 3rd iBGP peer DUT4 is not learnt because Route Reflector is not configured on peer DUT3")
        entries = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv4", network=network_ipv4)
        entries1 = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv6", network="3000:1::/64")

        if not entries and not entries1:
            st.log("Pass: DUT4 did not learn routes without configuring Route Reflector on peer DUT3")
        else:
            msg = st.error("Fail: DUT4 learned route without configuring Route Reflector on peer DUT3")
            st.banner("Collecting techsupport")
            st.generate_tech_support(topo['dut_list'][1:4], "test_ipv6_confed_with_rr")
            # Clear applied configurations
            st.banner("Cleanup for TestFunction")
            bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv4, config='no')
            bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv6, addr_family='ipv6', config='no')
            st.report_fail('msg', msg)

        st.log("Now configure Route Reflector on DUT3")
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv4', topo['D3D4P1_neigh_ipv4'], 'yes')
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv6', topo['D3D4P1_neigh_ipv6'], 'yes')

        st.wait(10)
        st.log("Now the routes should be learnt on the 3rd IBGP peer DUT4")
        entries2 = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv4", network=network_ipv4)
        entries3 = bgpapi.get_ip_bgp_route(topo['dut_list'][3], family="ipv6", network="3000:1::/64")
        errs = []
        if entries2 and entries3:
            st.log("Pass: DUT4 learned the routes advertised by peer DUT2")
        else:
            errs.append(st.error("Fail: DUT4 did not learn the routes advertised by peer DUT2"))
            st.banner("Collecting techsupport")
            st.generate_tech_support(topo['dut_list'][1:4], "test_ipv6_confed_with_rr")

        # Clear applied configurations
        st.banner("Cleanup for TestFunction")
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv4, config='no')
        bgpapi.config_bgp_network_advertise(topo['dut_list'][1], iBGP_as, network_ipv6, addr_family='ipv6', config='no')
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv4', topo['D3D4P1_neigh_ipv4'], 'no')
        bgpapi.create_bgp_route_reflector_client(topo.dut_list[2], iBGP_as, 'ipv6', topo['D3D4P1_neigh_ipv6'], 'no')

        st.report_result(errs)

    @pytest.mark.rmap
    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_fail
    @pytest.mark.inventory(feature='Regression', release='Arlo+')
    @pytest.mark.inventory(testcases=['ft_bgp_confedv6_route_maps_filter'])
    def test_confed_route_distribution_with_rmap(self):
        st.banner("Verify the behavior of Route-Maps over confederation peers")
        errs = []

        network1 = '134.5.6.0/24'
        network2 = '134.5.7.0/24'
        network3 = '134.5.8.0'
        as_path = '200'
        access_list1 = 'test-access-list1'
        access_list2 = 'test-access-list2'
        access_list3 = 'test-access-list3'

        st.log("Create access-lists and a route-map in DUT1, add to it permit, deny and AS-path prepending policies")
        # Create access-list test-access-list1
        ipapi.config_access_list(topo['dut_list'][0], access_list1, network3 + '/24', 'permit', seq_num="1")
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
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network3 + '/24', 'test-rmap', network_import_check=True)

        st.log("Verify in peer DUT2 the network configured in {} has the AS-path prepended".format(access_list1))
        # Verify that the neighbor has the as-path prepended
        output = bgpapi.show_bgp_ipvx_prefix(topo['dut_list'][1], prefix=network3, masklen=topo['D1_as'])
        result = False
        for x in output or {}:
            peer_asn = x['peerasn']
            peer_asn = peer_asn.split()
            for each in peer_asn:
                if each == as_path:
                    result = True
                    break
        if result:
            st.log("Pass: AS-Path {} found to be prepended with network {}/24".format(as_path, network3))
        else:
            errs.append(st.error("Fail: AS-Path {} not found to be prepended".format(as_path)))

        # Verify that network1 is not present in ip route table
        st.log("Verify that peer DUT2 not learnt the network configured as 'deny' in {}".format(access_list2))
        n1 = ipapi.verify_ip_route(topo['dut_list'][1], ip_address=network1)
        if n1 is False:
            st.log("Pass: DUT2 did not learn network {}".format(network1))
        else:
            errs.append(st.error("Fail: DUT2 learned the network {}".format(network1)))

        # Verify that network2 is present in ip route table
        st.log("Verify that peer DUT2 learnt the network configured as 'permit' in {}".format(access_list3))
        n2 = ipapi.verify_ip_route(topo['dut_list'][1], ip_address=network2)
        if n2:
            st.log("Pass: DUT2 learned the network {}".format(network2))
        else:
            errs.append(st.error("Fail: DUT2 did not learn network {}".format(network2)))

        if errs:
            st.banner("Collecting techsupport")
            st.generate_tech_support(topo['dut_list'][0:2], "test_confed_route_distribution_with_rmap")

        ipapi.config_route_map_mode(topo['dut_list'][0], 'test-rmap', 'permit', '10', config='no')

        # Clear applied configurations
        st.banner("Cleanup for TestFunction")
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list3', network2, 'permit', config='no', seq_num="3")
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list2', network1, 'deny', config='no', seq_num="2")
        ipapi.config_access_list(topo['dut_list'][0], 'test-access-list1', network3 + '/24', 'permit', config='no', seq_num="1")

        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network1, 'test-rmap', config='no')
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network2, 'test-rmap', config='no')
        bgpapi.advertise_bgp_network(topo['dut_list'][0], topo['D1_as'], network3 + '/24', 'test-rmap', config='no')

        st.report_result(errs)

# BGP Confederation test cases  - END
################################################################################


@pytest.mark.inventory(feature='Regression', release='Buzznik3.2.0')
@pytest.mark.inventory(testcases=['ft_bgp_ibgp_RR_Loop'])
def test_ft_bgp_ibgp_RR_Loop(hooks_test_ft_bgp_ibgp_RR_Loop):
    """
    Verify the functioning of iBGP Route-Reflector cluster loop
    """
    err_list = []

    vars = st.get_testbed_vars()
    topo['D1D3P1'] = vars['D1D3P1']
    topo['D3D1P1'] = vars['D3D1P1']
    topo['D1D3P1_ipv4'] = "11.4.0.1"
    topo['D3D1P1_ipv4'] = "11.4.0.2"

    dict1 = {"interface_name": topo['D1D3P1'], "ip_address": topo['D1D3P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "add"}
    dict2 = {"interface_name": topo['D3D1P1'], "ip_address": topo['D3D1P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "add"}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][2]], ipapi.config_ip_addr_interface, [dict1, dict2])

    st.banner("Verify the functioning of iBGP Route-Reflector cluster loop --- Start")
    st.log("Configure IPv4 iBGP peering on DUT1,DUT2 and DUT3 ")

    dict1 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D2D1P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}
    dict2 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D1D2P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}
    dict3 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D2D3P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}

    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][1], **dict2), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][2], **dict3)])

    dict1 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D3D1P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}
    dict2 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D3D2P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}
    dict3 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D1D3P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}
    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][1], **dict2), ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][2], **dict3)])

    dict1 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D2D1P1_ipv4']}
    dict2 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D3D2P1_ipv4']}
    dict3 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D1D3P1_ipv4']}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][1], topo['dut_list'][2]], bgpapi.create_bgp_route_reflector_client, [dict1, dict2, dict3])

    dict1 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D3D1P1_ipv4']}
    dict2 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D1D2P1_ipv4']}
    dict3 = {"local_asn": bgp_4node_data.dut1_as, "addr_family": "ipv4", "nbr_ip": topo['D2D3P1_ipv4']}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][1], topo['dut_list'][2]], bgpapi.create_bgp_route_reflector_client, [dict1, dict2, dict3])

    output = st.exec_all([
        ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][0], family='ipv4', neighbor=[topo['D2D1P1_ipv4'], topo['D3D1P1_ipv4']], state='Established'),
        ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][1], family='ipv4', neighbor=[topo['D1D2P1_ipv4'], topo['D3D2P1_ipv4']], state='Established'),
        ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][2], family='ipv4', neighbor=[topo['D2D3P1_ipv4'], topo['D1D3P1_ipv4']], state='Established')
    ])[0]
    if not all(output):
        err = st.error("Failed to form IPv4 eBGP peering")
        err_list.append(err)

    bgpapi.config_bgp_network_advertise(topo['dut_list'][2], bgp_4node_data.dut1_as, bgp_4node_data.network1, config='yes', network_import_check=True)
    st.wait(5, 'wait time for the route learning in neighbor')

    if not bgpapi.get_ip_bgp_route(topo['dut_list'][0], network=bgp_4node_data.network1):
        err = st.error("failed to learn adv IPv4 aggr route")
        err_list.append(err)
    if not bgpapi.get_ip_bgp_route(topo['dut_list'][1], network=bgp_4node_data.network1):
        err = st.error("failed to learn adv IPv4 aggr route")
        err_list.append(err)

    net1 = bgpapi.fetch_ip_bgp_route(topo['dut_list'][2], match={'next_hop': '0.0.0.0'}, select=['network', 'next_hop'])
    if not net1:
        err = st.error("route not originated from source dut")
        err_list.append(err)

    if not (net1[0]['next_hop'] == '0.0.0.0'):
        st.error("adv route reached source routers, RR cluster loop verification failed")
    st.banner("Verify the functioning of iBGP Route-Reflector cluster loop --- end")

    if err_list:
        err = st.error("iBGP Route-Reflector cluster loop verificaiton is failed.")
        err_list.insert(0, err)

    st.report_result(err_list, first_only=True)


@pytest.fixture(scope="function")
def hooks_test_ft_bgp_ibgp_RR_Loop():
    yield
    st.exec_all([[bgpapi.cleanup_router_bgp, topo['dut_list'][0]], [bgpapi.cleanup_router_bgp, topo['dut_list'][1]], [bgpapi.cleanup_router_bgp, topo['dut_list'][2]]])
    dict1 = {"interface_name": topo['D1D3P1'], "ip_address": topo['D1D3P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "remove"}
    dict2 = {"interface_name": topo['D3D1P1'], "ip_address": topo['D3D1P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "remove"}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][2]], ipapi.config_ip_addr_interface, [dict1, dict2])


@pytest.mark.inventory(feature='Regression', release='Buzznik3.5.1')
@pytest.mark.inventory(testcases=['ft_bgp_ebgp_community_map'])
@pytest.mark.inventory(release='Cyrus4.0.0', testcases=['test_ft_bgp_ebgp_community_sub'])
def test_ft_bgp_ebgp_community_map(hooks_test_ft_bgp_ebgp_community_map):
    """  Verify the functioning of eBGP communities  """
    err_list = []

    test_case_id = ["test_ft_bgp_ebgp_community_sub"]

    vars = st.get_testbed_vars()
    topo['D1D3P1'] = vars['D1D3P1']
    topo['D3D1P1'] = vars['D3D1P1']
    topo['D1D3P1_ipv4'] = "11.4.0.1"
    topo['D3D1P1_ipv4'] = "11.4.0.2"

    dict1 = {"interface_name": topo['D1D3P1'], "ip_address": topo['D1D3P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "add"}
    dict2 = {"interface_name": topo['D3D1P1'], "ip_address": topo['D3D1P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "add"}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][2]], ipapi.config_ip_addr_interface, [dict1, dict2])

    st.banner("Verify the functioning of eBGP communities --- Start")
    st.banner("Step1 -- Configure IPv4/v6 BGP peering on DUT1,DUT2,DUT3 and DUT4 ")

    bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as, neighbor=topo['D3D2P1_ipv6'], addr_family='ipv6', remote_as=bgp_4node_data.dut3_as, config_type_list=["neighbor", "activate"])
    bgpapi.config_bgp(topo['dut_list'][2], local_as=bgp_4node_data.dut3_as, neighbor=topo['D2D3P1_ipv6'], addr_family='ipv6', remote_as=bgp_4node_data.dut2_as, config_type_list=["neighbor", "activate"])
    dict1 = {"local_as": bgp_4node_data.dut1_as, "neighbor": topo['D3D1P1_ipv4'], "remote_as": bgp_4node_data.dut3_as, "config_type_list": ["neighbor", "activate"]}
    dict2 = {"local_as": bgp_4node_data.dut2_as, "neighbor": topo['D3D2P1_ipv4'], "remote_as": bgp_4node_data.dut3_as, "config_type_list": ["neighbor", "activate"]}
    dict3 = {"local_as": bgp_4node_data.dut3_as, "neighbor": topo['D1D3P1_ipv4'], "remote_as": bgp_4node_data.dut1_as, "config_type_list": ["neighbor", "activate"]}
    dict4 = {"local_as": bgp_4node_data.dut4_as, "neighbor": topo['D3D4P1_ipv4'], "remote_as": bgp_4node_data.dut3_as, "config_type_list": ["neighbor", "activate"]}

    st.exec_all([ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][0], **dict1),
                 ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][1], **dict2),
                 ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][2], **dict3),
                 ExecAllFunc(bgpapi.config_bgp, topo['dut_list'][3], **dict4)])

    bgpapi.config_bgp(topo['dut_list'][2], local_as=bgp_4node_data.dut3_as, neighbor=topo['D2D3P1_ipv4'], remote_as=bgp_4node_data.dut2_as, config_type_list=["neighbor", "activate"])
    bgpapi.config_bgp(topo['dut_list'][2], local_as=bgp_4node_data.dut3_as, neighbor=topo['D4D3P1_ipv4'], remote_as=bgp_4node_data.dut4_as, config_type_list=["neighbor", "activate"])
    bgpapi.advertise_bgp_network(topo['dut_list'][0], bgp_4node_data.dut1_as, bgp_4node_data.network1, network_import_check=True)

    st.banner("Step2 -- BGP community configuration in DUT1 using ip prefix list and route-maps ")
    ipapi.config_access_list(topo['dut_list'][0], 'LOOPBACK', bgp_4node_data.network1, 'permit', seq_num="7")

    ipapi.config_route_map_match_ip_address(topo['dut_list'][0], 'SET_COMMUNITY', 'permit', '10', 'LOOPBACK')
    ipapi.config_route_map(topo['dut_list'][0], 'SET_COMMUNITY', sequence='10', community='64984:0', metric=50)

    bgpapi.config_bgp(topo['dut_list'][0], local_as=bgp_4node_data.dut1_as, neighbor=topo['D3D1P1_ipv4'], config='yes', addr_family='ipv4', config_type_list=["routeMap"], routeMap='SET_COMMUNITY', diRection='out')

    output = st.exec_all([ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][0], family='ipv4', neighbor=topo['D3D1P1_ipv4'], state='Established'),
                          ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][1], family='ipv4', neighbor=topo['D3D2P1_ipv4'], state='Established'),
                          ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][2], family='ipv4', neighbor=[topo['D2D3P1_ipv4'], topo['D1D3P1_ipv4'], topo['D4D3P1_ipv4']], state='Established'),
                          ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer, topo['dut_list'][3], family='ipv4', neighbor=topo['D3D4P1_ipv4'], state='Established')])[0]
    if not all(output):
        err = st.error("Failed to form IPv4 eBGP peering")
        err_list.append(err)

    bgpapi.config_bgp_community_list(topo['dut_list'][2], community_type='standard', community_name='comm_test', action='permit', community_num='64984:0')
    ipapi.config_route_map(topo['dut_list'][0], 'SET_COMMUNITY', sequence='10', community='64984:0 local-as')
    st.wait(30)
    st.banner("verifying  that the communities are added from the route for out-bound")
    n2 = bgpapi.get_ip_bgp_community(topo['dut_list'][2], route='172.16.2.2/32', community='64984:0 localAs')
    if not n2:
        st.error("failed to learn IPv4 route")
    else:
        prepend_as = n2[0]['community']
        if (prepend_as == '64984:0 localAs'):
            st.log("BGP community verification is successful")
        else:
            err = st.error("BGP community verification is failed")
            err_list.append(err)

    ipapi.config_route_map(topo['dut_list'][0], 'SET_COMMUNITY', sequence='10', delcommunity='local-as')
    st.wait(30)
    st.banner("verifying  that the sub set of communities removed or not")
    result1 = True
    n2 = bgpapi.get_ip_bgp_community(topo['dut_list'][2], route='172.16.2.2/32', community='64984:0')
    if not n2:
        st.error("failed to learn bgp route")
    else:
        prepend_as = n2[0]['community']
        if (prepend_as == '64984:0'):
            st.log("verifying that the sub set of BGP communities removed successful")
        else:
            err = st.error("verifying that the sub set of BGP communities remove failed")
            err_list.append(err)
            result1 = False
    if result1:
        st.banner("TC Pass: {}".format(test_case_id[0]))
        st.report_pass("test_case_id_passed", test_case_id[0])
    else:
        st.banner("TC Fail:  {}, {}".format(test_case_id[0], 'Community subset is not deleted'))
        st.report_fail("test_case_id_failed", test_case_id[0])

    st.banner("Applying route-map to a BGP neighbor in out bound direction")
    ipapi.config_route_map(topo['dut_list'][0], 'SET_COMMUNITY', sequence='10', community='none')
    st.wait(30)
    st.banner("verifying  that the communities are removed from the route for out-bound")
    n2 = bgpapi.get_ip_bgp_community(topo['dut_list'][2], route='172.16.2.2/32', community=' ')
    if n2:
        err = st.error("community attributes are not cleared using route-map community as none")
        err_list.append(err)
    else:
        st.log("BGP communities removed successfully with community none")

    st.banner("Applying route-map to a BGP neighbor in in bound direction")
    ipapi.config_route_map(topo['dut_list'][0], 'SET_COMMUNITY', sequence='10', community='64984:0 local-as')
    ipapi.config_route_map(topo['dut_list'][2], 'SET_COMMUNITY', sequence='10', community='none')
    bgpapi.config_bgp(topo['dut_list'][2], local_as=bgp_4node_data.dut3_as, neighbor=topo['D1D3P1_ipv4'], config='yes', addr_family='ipv4', config_type_list=["routeMap"], routeMap='SET_COMMUNITY', diRection='in')
    st.wait(30)
    st.banner("verifying  that the communities are removed from the route for in-bound")
    n2 = bgpapi.get_ip_bgp_community(topo['dut_list'][2], route='172.16.2.2/32', community='64984:0 localAs')
    if n2:
        err = st.error("community attributes are not cleared using route-map community as none")
        err_list.append(err)
    else:
        st.log("BGP communities removed successfully with community none")

        ipapi.config_access_list(topo['dut_list'][1], 'LOOPBACK', topo['D2D1P1_ipv6'].split('::')[0] + "::/64",
                                 'permit', family='ipv6', seq_num="7")
        ipapi.config_route_map(topo['dut_list'][1], 'SET_COMMUNITY_1', sequence='10', community='64984:0 local-as',
                               metric=50)
        ipapi.config_route_map(topo['dut_list'][2], 'SET_COMMUNITY_1', sequence='10', metric=50)

        bgpapi.config_bgp(topo['dut_list'][1], local_as=bgp_4node_data.dut2_as, neighbor=topo['D3D2P1_ipv6'],
                          config='yes', addr_family='ipv6', config_type_list=["routeMap", "redist"],
                          routeMap='SET_COMMUNITY_1', diRection='out', redistribute='connected')
        ipapi.config_route_map_match_ip_address(topo['dut_list'][2], 'SET_COMMUNITY_1', 'permit', '10', None,
                                                family='ipv6', community='comm_test')

        output = st.exec_all([ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer,
                                          topo['dut_list'][1], family='ipv6', neighbor=topo['D3D2P1_ipv6'],
                                          state='Established'),
                              ExecAllFunc(st.poll_wait, bgpapi.verify_bgp_summary, bgp_4node_data.wait_timer,
                                          topo['dut_list'][2], family='ipv6', neighbor=topo['D2D3P1_ipv6'],
                                          state='Established')])[0]
        if not all(output):
            err = st.error("Failed to form IPv6 eBGP peering")
            err_list.append(err)
        st.banner("verifying  that the communities are added from the v6 route for out-bound")
        n2 = bgpapi.get_ip_bgp_community(topo['dut_list'][2], route=topo['D2D1P1_ipv6'].split('::')[0] + "::/64",
                                         family='ipv6', community='64984:0 localAs')
        if not n2:
            st.error("failed to learn IPv6 route")
        else:
            prepend_as = n2[0]['community']
            if (prepend_as == '64984:0 localAs'):
                st.log("BGP community verification is successful fot v6")
            else:
                err = st.error("BGP community verification is failed for v6")
                err_list.append(err)
        st.banner("Applying route-map community none to BGP v6 routes in out bound direction")
        ipapi.config_route_map(topo['dut_list'][2], 'SET_COMMUNITY_1', sequence='10', community='none')
        st.wait(30)
        st.banner("verifying  that the communities are removed from the route for out-bound")
        n2 = bgpapi.get_ip_bgp_community(topo['dut_list'][2], route=topo['D2D1P1_ipv6'].split('::')[0] + "::/64",
                                         family='ipv6', community=' ')
        if n2:
            err = st.error("community attributes are not cleared using route-map community as none")
            err_list.append(err)
        else:
            st.log("BGP communities removed successfully with community none")

        st.banner("Applying route-map to a BGP v6 route in in bound direction")
        ipapi.config_route_map(topo['dut_list'][1], 'SET_COMMUNITY', sequence='10', community='64984:0 local-as')
        ipapi.config_route_map(topo['dut_list'][2], 'SET_COMMUNITY', sequence='10', community='none')
        bgpapi.config_bgp(topo['dut_list'][2], local_as=bgp_4node_data.dut3_as, neighbor=topo['D2D3P1_ipv6'],
                          config='yes', addr_family='ipv6', config_type_list=["routeMap"], routeMap='SET_COMMUNITY',
                          diRection='in')
        st.wait(30)
        st.banner("verifying  that the communities are removed from the v6 route for in-bound")
        n2 = bgpapi.get_ip_bgp_community(topo['dut_list'][2], route='172.16.2.2/32', community='64984:0 localAs')
        if n2:
            err = st.error("community attributes are not cleared using route-map community as none")
            err_list.append(err)
        else:
            st.log("BGP communities removed successfully with community none")

    if err_list:
        err = st.error("BGP community based as-path prepend verification is failed.")
        err_list.insert(0, err)

    st.report_result(err_list, first_only=True)


@pytest.fixture(scope="function")
def hooks_test_ft_bgp_ebgp_community_map():
    yield
    st.exec_all([[bgpapi.cleanup_router_bgp, topo['dut_list'][0]], [bgpapi.cleanup_router_bgp, topo['dut_list'][1]],
                 [bgpapi.cleanup_router_bgp, topo['dut_list'][2]], [bgpapi.cleanup_router_bgp, topo['dut_list'][3]]])
    dict1 = {"interface_name": topo['D1D3P1'], "ip_address": topo['D1D3P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "remove"}
    dict2 = {"interface_name": topo['D3D1P1'], "ip_address": topo['D3D1P1_ipv4'], "subnet": "24", "family": "ipv4", "config": "remove"}
    st.exec_each2([topo['dut_list'][0], topo['dut_list'][2]], ipapi.config_ip_addr_interface, [dict1, dict2])

    ipapi.config_route_map(topo['dut_list'][0], 'SET_COMMUNITY', config='no')
    ipapi.config_access_list(topo['dut_list'][0], 'LOOPBACK', "", mode="", config='no')
    bgpapi.config_bgp_community_list(topo['dut_list'][2], community_type='standard', community_name='comm_test', action='permit', community_num='64984:0', config='no')
    ipapi.config_route_map(topo['dut_list'][2], 'SET_COMMUNITY_1', sequence='10', metric=50, config='no')
