import pytest

from spytest import st, tgapi, SpyTestDict

import apis.routing.ip as ipapi
import apis.routing.bgp as bgpapi
import apis.switching.vlan as vlanapi
import apis.system.logging as slog_obj
import apis.switching.portchannel as poapi
import BGP.bgplib as bgplib

import utilities.common as utils

vtysh_cli_type = "vtysh"

@pytest.fixture(scope="module", autouse=True)
def bgp_module_hooks(request):
    global bgp_cli_type
    st.ensure_min_topology('D1D2:1', 'D1T1:1', 'D2T1:1')
    bgplib.init_resource_data(st.get_testbed_vars())
    #bgp_cli_type = st.get_ui_type()
    bgp_cli_type = "click"
    if bgp_cli_type == 'click':
        bgp_cli_type = 'vtysh'
    bgp_pre_config()
    yield
    bgp_pre_config_cleanup()


# bgp module level pre config function
def bgp_pre_config():
    global topo
    st.banner("Running with {} CLI RUN".format(bgp_cli_type))
    st.banner("BGP MODULE CONFIG - START")
    ipapi.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    vlanapi.clear_vlan_configuration(st.get_dut_names())
    poapi.clear_portchannel_configuration(st.get_dut_names())
    if not st.is_community_build():
        # loopback config
        bgplib.l3tc_vrfipv4v6_address_leafspine_loopback_config_unconfig(config='yes', config_type='all')
    # TG Configuration
    bgplib.l3tc_vrfipv4v6_address_leafspine_tg_config_unconfig(config='yes', config_type='all')
    bgplib.l3tc_vrfipv4v6_address_leafspine_tg_bgp_config(config='yes', config_type='all')
    st.banner("BGP MODULE CONFIG - END")


# bgp module level pre config cleanup function
def bgp_pre_config_cleanup():
    st.banner("BGP MODULE CONFIG CLEANUP - START")
    if not st.is_community_build():
        # loopback unconfig
        bgplib.l3tc_vrfipv4v6_address_leafspine_loopback_config_unconfig(config='no')
    # TG  uconfiguration
    bgplib.l3tc_vrfipv4v6_address_leafspine_tg_config_unconfig(config='no')
    bgplib.l3tc_vrfipv4v6_address_leafspine_tg_bgp_config(config='no')
    ipapi.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    vlanapi.clear_vlan_configuration(st.get_dut_names())
    poapi.clear_portchannel_configuration(st.get_dut_names())
    st.banner("BGP MODULE CONFIG CLEANUP - END")


@pytest.fixture(scope="function")
def bgp_func_hooks(request):
    yield


"""
BGP common test cases class - START

add common bgp test casesfunctions (common to TestBGPRif or other non rif test classes
pick specific cases in derived classes
this is a abstract class with test cases and test should be run from this class
only it has to be run from derived classes.

**DONTs**
*dont* name member functions of TestBGPCommon starting test.have test member functions in derived class only
*dont* add fixtures in base class. add fixtures only in derived class.
"""


class TestBGPCommon:
    def ft_bgp_clear(self):
        """

        Validate clear ip bgp & sonic-clear functionality
        """
        st.log("Clearing bgp neighbors from sonic cli")
        [out, exceptions] = utils.exec_foreach(bgplib.fast_start, topo.dut_list, bgpapi.clear_ip_bgp)
        st.log([out, exceptions])
        if not utils.poll_wait(bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_check, 20, config_type='all'):
            st.error("Neighbour is failed to Establish between Spine - Leaf")
            st.report_fail('test_case_failed')
        st.log("Clearing bgp neighbors from FRR cli")
        [out, exceptions] = utils.exec_foreach(bgplib.fast_start, topo.dut_list, bgpapi.clear_bgp_vtysh)
        st.log([out, exceptions])
        if not utils.poll_wait(bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_check, 20, config_type='all'):
            st.error("Neighbour is failed to Establish between Spine - Leaf")
            st.report_fail('test_case_failed')
        st.report_pass("test_case_passed")

    def ft_bgp_peer_traffic_check(self):
        """

        Traffic validation between Leaf Routers.
        """
        TG_D1 = topo.tg_dut_list_name[0]
        TG_D2 = topo.tg_dut_list_name[1]
        tg_ob = topo['T1{}P1_tg_obj'.format(TG_D1)]
        tg_ob.tg_traffic_control(port_handle=topo["T1{}P1_ipv4_tg_ph".format(TG_D1)], action='clear_stats')
        tg_ob.tg_traffic_control(port_handle=topo["T1{}P1_ipv4_tg_ph".format(TG_D2)], action='clear_stats')
        bgp_handle = topo['T1{}P1_ipv4_tg_bh'.format(TG_D1)]
        tc_fail_flag = 0
        spine_as = int(bgplib.data['spine_as'])
        st.log("Advertising Routes from one of the Leaf Router")
        bgp_route = tg_ob.tg_emulation_bgp_route_config(handle=bgp_handle['handle'], mode='add', num_routes='100',
                                                        prefix='121.1.1.0', as_path='as_seq:1')
        bgp_ctrl = tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='start')
        st.log("Check for route count in neighbour, before update delay timer configuration")
        bgp_summary_spine_before_timer = bgpapi.show_bgp_ipv4_summary(topo.dut_list[1])
        rib_entries_before_update_timer = bgp_summary_spine_before_timer[0]['ribentries']
        st.log('RIB entries before update delay configuration : {}'.format(rib_entries_before_update_timer))
        st.log("Configure Update delay timer on one of the Leaf router")
        bgpapi.create_bgp_update_delay(topo.dut_list[0], spine_as, '60',cli_type=bgp_cli_type)
        st.log("Do clear ip bgp to validate the update delay timer")
        bgpapi.clear_bgp_vtysh(topo.dut_list[0], address_family="ipv4")
        if not utils.poll_wait(bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_check, 20, config_type='ipv4'):
            st.error("Neighbour is failed to Establish between Spine - Leaf after clear ip bgp")
            tc_fail_flag = 1
        bgp_summary_spine_before_timer = bgpapi.show_bgp_ipv4_summary(topo.dut_list[1])
        rib_entries_before_update_timer = bgp_summary_spine_before_timer[0]['ribentries']
        st.log('RIB entries before update delay timer expiry : {}'.format(rib_entries_before_update_timer))
        if int(rib_entries_before_update_timer) >= 100:
            st.error('Routes advertised to peer DUT, proir to update delay timer expiry')
            tc_fail_flag = 1

        # Sleep for update delay timer and the check the route count in neighbour
        st.wait(60)
        bgp_summary_spine_after_update_timer = bgpapi.show_bgp_ipv4_summary(topo.dut_list[1])
        rib_entries_after_update_timer = bgp_summary_spine_after_update_timer[0]['ribentries']
        st.log('RIB Entries after update delay timer expiry : {}'.format(rib_entries_after_update_timer))
        if int(rib_entries_after_update_timer) < 100:
            st.error('Routes are not advertised to peer DUT, even after the update delay timer expiry')
            tc_fail_flag = 1
        st.log("Initiating the Ipv4 traffic for those Routes from another Leaf Router")
        src_handle = 'handle'
        if tg_ob.tg_type == 'ixia':
            src_handle = 'ipv4_handle'
        tr1 = tg_ob.tg_traffic_config(port_handle=topo['T1{}P1_ipv4_tg_ph'.format(TG_D2)],
                                      emulation_src_handle=topo['T1{}P1_ipv4_tg_ih'.format(TG_D2)][src_handle],
                                      emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type='ipv4',
                                      mode='create',
                                      transmit_mode='single_burst', pkts_per_burst='2000', length_mode='fixed',
                                      rate_pps=1000)
        stream_id1 = tr1['stream_id']
        tg_ob.tg_traffic_control(action='run', handle=stream_id1)
        tg_ob.tg_traffic_control(action='stop', port_handle=topo['T1{}P1_ipv4_tg_ph'.format(TG_D2)])
        st.wait(5)
        tg1_stats = tgapi.get_traffic_stats(tg_ob, port_handle=topo["T1{}P1_ipv4_tg_ph".format(TG_D1)])
        tg2_stats = tgapi.get_traffic_stats(tg_ob, port_handle=topo["T1{}P1_ipv4_tg_ph".format(TG_D2)])
        if not (int(tg2_stats.tx.total_packets) and int(tg1_stats.rx.total_packets)):
            st.error('Recieved ZERO stats.')
            tc_fail_flag = 1
        else:
            percent_rx = float(int(tg1_stats.rx.total_packets) - int(tg2_stats.tx.total_packets)) / int(
                tg2_stats.tx.total_packets) * 100
            st.log('tg1_stats.rx.total_packets : {}'.format(tg1_stats.rx.total_packets))
            st.log('tg2_stats.tx.total_packets : {}'.format(tg2_stats.tx.total_packets))
            st.log('percent_rx : {}'.format(percent_rx))
            if int(tg1_stats.rx.total_packets) < int(tg2_stats.tx.total_packets)*0.95:
                tc_fail_flag = 1
        tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='stop')
        bgpapi.create_bgp_update_delay(topo.dut_list[0], spine_as, '0', cli_type=bgp_cli_type)
        if tc_fail_flag:
            st.report_fail("traffic_verification_failed")
        st.report_pass('test_case_passed')

    def ft_bgp_graceful_restart_and_aware_routers(self):
        """
        Verify the BGP peering between a graceful restart capable and graceful restart aware routers.
        """

        st.banner("Verify the BGP peering between a graceful restart capable and graceful restart aware routers.")
        # Getting topo info between an spine and leaf
        info = SpyTestDict()
        info = bgplib.get_tg_topology_leafspine_bgp(dut_type = 'spine-leaf', max_tg_links= '0', nodes='2')
        # NOTE: D1 is spine and D2 is leaf by default

        leaf_name = info['D2']
        spine_name = info['D1']

        # Configure graceful restart capability on the Leaf router
        bgpapi.config_bgp_graceful_restart(leaf_name, local_asn=info['D2_as'], user_command='preserve-fw-state',
                                           config='add', cli_type=bgp_cli_type)

        # Verify bgp neighbors
        result = bgpapi.verify_bgp_summary(leaf_name, family='ipv4', neighbor=info['D1D2P1_ipv4'], state='Established')
        if not result:
            bgplib.show_bgp_neighbors([leaf_name, spine_name], af='ipv4')

        # Delete the graceful restart capability
        bgpapi.config_bgp_graceful_restart(leaf_name, local_asn=info['D2_as'], user_command='preserve-fw-state',
                                           config='delete', cli_type=bgp_cli_type)

        if result:
            st.log("BGP adjacency verified between graceful restart capable and aware router")
            st.report_pass("test_case_passed")
        else:
            st.log("Failed to form BGP peering between graceful restart capable and aware router")
            st.report_fail("bgp_ip_peer_establish_fail", info['D1D2P1_ipv4'])

    def ft_bgp_ipv4_no_route_aggregation_for_exact_prefix_match(self):
        """
        Verify that when the 'aggregate-address' command creates a summary address, incoming networks that
        exactly match that prefix are not aggregated.
        """
        st.banner("Verify that when the 'aggregate-address' command creates a summary address, "
                  "incoming networks that exactly match that prefix are not aggregated.")
        # Getting topo info between an spine and leaf
        aggr_route = "122.1.1.0/24"
        info = SpyTestDict()
        info = bgplib.get_tg_topology_leafspine_bgp(dut_type='spine-leaf', max_tg_links='1', nodes='2')
        # NOTE: D1 is spine and D2 is leaf by default

        leaf_name = info['D2']
        spine_name = info['D1']
        TG_D2 = 'D2'

        # Verify bgp neighbors between leaf and Tg
        result = bgpapi.verify_bgp_summary(leaf_name, family='ipv4', neighbor=info['T1D2P1_ipv4'], state='Established')

        if not result:
            bgplib.show_bgp_neighbors([leaf_name, spine_name], af='ipv4')
            st.report_fail("test_case_failed")

        # Configure the route aggregation on the Leaf router
        bgpapi.create_bgp_aggregate_address(leaf_name, local_asn=info['D2_as'], address_range=aggr_route,
                                            family="ipv4", config="add", cli_type=bgp_cli_type)
        tg_ob = info['T1{}P1_tg_obj'.format(TG_D2)]
        bgp_handle = info['T1{}P1_ipv4_tg_bh'.format(TG_D2)]
        st.log("Advertising Routes from the Leaf Router")
        bgp_route = tg_ob.tg_emulation_bgp_route_config(handle=bgp_handle['handle'], mode='add', num_routes='4',
                                                        prefix='122.1.1.0', as_path='as_seq:1')

        st.log("BGPROUTE: "+str(bgp_route))
        st.log("Advertise those routes from Ixia")
        ctrl1=tg_ob.tg_bgp_routes_control(handle=bgp_handle['handle'], route_handle=bgp_route['handle'],
                                          mode='readvertise')
        st.log("TR_CTRL: "+str(ctrl1))
        st.wait(5)

        # Verify the prefix on spine
        entries = bgpapi.get_ip_bgp_route(spine_name, family="ipv4", network=aggr_route)

        if not entries:
            bgpapi.create_bgp_aggregate_address(leaf_name, local_asn=info['D2_as'], address_range=aggr_route,
                                                family="ipv4", config="delete", cli_type=bgp_cli_type)
            st.report_fail("bgp_route_info", aggr_route, "not found")
        AS_PATH_STRING = str(entries[0]['as_path'])
        asn = AS_PATH_STRING.split(" ")

        # If the route is aggregated the as_path will have only the peer-asn if not the whole as_path
        if not int(asn[0]) == info['D2_as'] and len(asn) > 1:
            bgpapi.create_bgp_aggregate_address(leaf_name, local_asn=info['D2_as'], address_range=aggr_route,
                                                family="ipv4", config="delete", cli_type=bgp_cli_type)
            st.report_fail("bgp_aggregation_pass", aggr_route)
        bgpapi.create_bgp_aggregate_address(leaf_name, local_asn=info['D2_as'], address_range=aggr_route,
                                            family="ipv4", config="delete", cli_type=bgp_cli_type)
        bgp_route1 = tg_ob.tg_emulation_bgp_route_config(handle=bgp_handle['handle'], mode='remove', num_routes='4',
                                                         prefix='122.1.1.0', as_path='as_seq:1')
        st.report_pass("test_case_passed")

    def ft_bgp_ipv4_route_aggregation_atomic_aggregate_without_as_set(self):
        """
        Verify that the AGGREGATOR and ATOMIC AGGREGATE attribute is included when an AS_SET is not configured
        in aggregation.
        """
        st.banner("Verify that the AGGREGATOR and ATOMIC AGGREGATE attribute is included when an AS_SET "
                  "is not configured in aggregation.")
        aggr_route = "123.1.0.0/16"
        info = SpyTestDict()
        info = bgplib.get_tg_topology_leafspine_bgp(dut_type = 'spine-leaf', max_tg_links='1', nodes='2')
        # NOTE: D1 is spine and D2 is leaf by default

        leaf_name = info['D2']
        spine_name = info['D1']
        TG_D2 = 'D2'

        # Verify bgp neighbors between leaf and Tg
        result = bgpapi.verify_bgp_summary(leaf_name, family='ipv4', neighbor=info['T1D2P1_ipv4'], state='Established')

        if not result:
            bgplib.show_bgp_neighbors([leaf_name, spine_name], af='ipv4')
            st.report_fail("test_case_failed")

        # Configure the route aggregation on the Leaf router
        bgpapi.create_bgp_aggregate_address(leaf_name, local_asn=info['D2_as'], address_range=aggr_route,
                                            summary="summary-only", family="ipv4", config="add", cli_type=bgp_cli_type)
        st.log(" clear the syslog file")
        slog_obj.clear_logging(spine_name)
        # Enable zebra logs
        bgpapi.bgp_debug_config(spine_name, message="updates", prefix=aggr_route)
        string = "bgp#supervisord:"

        tg_ob=info['T1{}P1_tg_obj'.format(TG_D2)]
        bgp_handle = info['T1{}P1_ipv4_tg_bh'.format(TG_D2)]
        st.log("Configure routes to be advertised from Ixia")
        bgp_route = tg_ob.tg_emulation_bgp_route_config(handle=bgp_handle['handle'], mode='add', num_routes='4',
                                                        prefix='123.1.1.0', as_path='as_seq:1')
        st.log("Advertise those routes from Ixia")
        ctrl1=tg_ob.tg_bgp_routes_control(handle=bgp_handle['handle'], route_handle=bgp_route['handle'],
                                          mode='readvertise')
        st.log("TR_CTRL: "+str(ctrl1))
        st.wait(5)

        st.log("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
        st.log(slog_obj.show_logging(spine_name, lines=200))
        st.log("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")

        st.log("Verify logs on spine to check if aggregator and atomic ")
        log_msg = slog_obj.get_logging_count(spine_name, filter_list=['{}'.format(string), 'atomic-aggregate',
                                                                      'aggregated by {}'.format(info['D2_as']),
                                                                      'path {}'.format(info['D2_as'])])

        st.log("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
        st.log(log_msg)
        st.log("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")

        bgpapi.create_bgp_aggregate_address(leaf_name, local_asn=info['D2_as'], address_range=aggr_route,
                                            summary="summary-only", family="ipv4", config="delete", cli_type=bgp_cli_type)
        bgp_route1 = tg_ob.tg_emulation_bgp_route_config(handle=bgp_handle['handle'], mode='remove', num_routes='4',
                                                         prefix='123.1.1.0', as_path='as_seq:1')
        if not log_msg:
            st.report_fail("bgp_aggregation_fail", aggr_route)
        st.report_pass("test_case_passed")

    def ft_bgp_ipv6_route_aggregation_with_as_set(self):
        """
        Verify that aggregation of ipv6 prefixes occurs correctly with as-set keyword
        """
        st.banner("Verify that aggregation of ipv6 prefixes occurs correctly with as-set keyword")
        aggr_route = "6002:1::0/64"
        info = SpyTestDict()
        info = bgplib.get_tg_topology_leafspine_bgp(dut_type = 'spine-leaf', max_tg_links= '1', nodes='2')
        # NOTE: D1 is spine and D2 is leaf by default

        leaf_name = info['D2']
        spine_name = info['D1']
        TG_D2 = 'D2'

        # Configure the route aggregation on the Leaf router
        bgpapi.create_bgp_aggregate_address(leaf_name, local_asn=info['D2_as'], address_range=aggr_route,
                                            summary="summary-only", as_set="as-set", family="ipv6", config="add", cli_type=bgp_cli_type)
        tg_ob=info['T1{}P1_tg_obj'.format(TG_D2)]
        bgp_handle = info['T1{}P1_ipv6_tg_bh'.format(TG_D2)]

        # Starting the BGP device.
        bgp_ctrl=tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='start')
        st.log("BGPCTRL: "+str(bgp_ctrl))
        # Verified at neighbor.
        # Verify bgp neighbors between leaf and Tg
        result = bgpapi.verify_bgp_summary(leaf_name, family='ipv6', neighbor=info['T1D2P1_ipv6'], state='Established')

        if not result:
            bgplib.show_bgp_neighbors([leaf_name, spine_name], af='ipv6')
            st.report_fail("test_case_failed")
        st.log("BGP neighbors established.")
        st.log("Advertising Routes from the Leaf Router")

        bgp_route_ipv6 = tg_ob.tg_emulation_bgp_route_config(handle=bgp_handle['handle'], mode='add', ip_version='6',
                                                             num_routes='4', prefix='6002:1::0', as_path='as_seq:1')
        st.log("BGPROUTE: "+str(bgp_route_ipv6))

        bgp_ctrl = tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='start')

        ctrl1=tg_ob.tg_bgp_routes_control(handle=bgp_handle['handle'], route_handle=bgp_route_ipv6['handle'],
                                          mode='readvertise')
        st.log("TR_CTRL: "+str(ctrl1))
        st.wait(10)

        # Verify the prefix on spine
        st.log("Verify the prefix on spine")
        entries = bgpapi.get_ip_bgp_route(spine_name, family="ipv6", network="6002:1::/64")

        if not entries:
            bgpapi.create_bgp_aggregate_address(leaf_name, local_asn=info['D2_as'], address_range=aggr_route,
                                                summary="summary-only", as_set="as-set", family="ipv6",
                                                config="delete", cli_type=bgp_cli_type)
            st.report_fail("bgp_route_info", aggr_route, "not found")

        AS_PATH_STRING = str(entries[0]['as_path'])
        asn = AS_PATH_STRING.split(" ")

        # If the route is aggregated the as_path will have the whole as_path because of as-set configuration
        if not int(asn[0]) == info['D2_as'] and len(asn) > 1:
            bgpapi.create_bgp_aggregate_address(leaf_name, local_asn=info['D2_as'], address_range=aggr_route,
                                                summary="summary-only", as_set="as-set", family="ipv6",
                                                config="delete", cli_type=bgp_cli_type)
            st.report_fail("bgp_aggregation_fail", aggr_route)
        bgpapi.create_bgp_aggregate_address(leaf_name, local_asn=info['D2_as'], address_range=aggr_route,
                                            summary="summary-only", as_set="as-set", family="ipv6",
                                            config="delete", cli_type=bgp_cli_type)
        bgp_route_ipv6_rem = tg_ob.tg_emulation_bgp_route_config(handle=bgp_handle['handle'], mode='remove',
                                                                 ip_version='6', num_routes='4', prefix='6002:1::0',
                                                                 as_path='as_seq:1')
        st.report_pass("test_case_passed")

    def ft_bgp_route_aggregation_4byteASN(self):
        """
        Validate AS4_Aggregate attribute w.r.to the BGP 4-byte ASN Feature
        """
        aggr_route = "151.1.0.0/16"
        info = SpyTestDict()
        info = bgplib.get_tg_topology_leafspine_bgp(dut_type='spine-leaf', max_tg_links='1', nodes='2')
        # NOTE: D1 is spine and D2 is leaf by default

        leaf_name = info['D2']
        spine_name = info['D1']
        TG_D2 = 'D2'

        # Verify bgp neighbors between leaf and Tg
        if not utils.poll_wait(bgpapi.verify_bgp_summary, 30, leaf_name, family='ipv4', neighbor=info['T1D2P1_ipv4'],
                               state='Established'):
            bgplib.show_bgp_neighbors([leaf_name, spine_name], af='ipv4')
            st.error("Neighbour is failed to Establish between Leaf - TG")
            st.report_fail('test_case_failed')

        # Configure the route aggregation on the Leaf router
        bgpapi.create_bgp_aggregate_address(leaf_name, local_asn=info['D2_as'], address_range=aggr_route,
                                            summary="summary-only", as_set="as-set", family="ipv4", config="add", cli_type=bgp_cli_type)
        tg_ob=info['T1{}P1_tg_obj'.format(TG_D2)]
        bgp_handle = info['T1{}P1_ipv4_tg_bh'.format(TG_D2)]

        st.log("Advertising Routes from the Leaf Router")
        bgp_route = tg_ob.tg_emulation_bgp_route_config(handle=bgp_handle['handle'], mode='add', num_routes='4',
                                                        prefix='151.1.1.0', as_path='as_seq:1')
        st.log("Advertise those routes from Ixia")
        ctrl1=tg_ob.tg_bgp_routes_control(handle=bgp_handle['handle'], route_handle=bgp_route['handle'],
                                          mode='readvertise')
        st.log("TR_CTRL: "+str(ctrl1))
        st.wait(10)

        # Verify the prefix on spine
        entries = bgpapi.get_ip_bgp_route(spine_name, family="ipv4", network=aggr_route)

        if not entries:
            bgpapi.create_bgp_aggregate_address(leaf_name, local_asn=info['D2_as'], address_range=aggr_route,
                                                summary="summary-only", as_set="as-set", family="ipv4",
                                                config="delete", cli_type=bgp_cli_type)
            st.report_fail("bgp_route_info", aggr_route, "not found")
        AS_PATH_STRING = str(entries[0]['as_path'])
        asn = AS_PATH_STRING.split(" ")

        # Since as-set is set, as-path will have the whole path for the aggregated route including the 4-byte AS.
        if not int(asn[0]) == info['D2_as'] and len(asn)>1:
            bgpapi.create_bgp_aggregate_address(leaf_name, local_asn=info['D2_as'], address_range=aggr_route,
                                                summary="summary-only", as_set="as-set", family="ipv4",
                                                config="delete", cli_type=bgp_cli_type)
            st.report_fail("bgp_aggregation_fail", aggr_route)
        bgpapi.create_bgp_aggregate_address(leaf_name, local_asn=info['D2_as'], address_range=aggr_route,
                                            summary="summary-only", as_set="as-set", family="ipv4",
                                            config="delete", cli_type=bgp_cli_type)
        st.report_pass("test_case_passed")


"""
BGP common test cases class  - END
"""


"""
BGP Neighbor over regular router interface fixture, class and test cases  - START
"""


def bgp_rif_pre_config():
    global topo
    st.banner("BGP RIF CLASS CONFIG - START")
    # underlay config
    bgplib.l3tc_underlay_config_unconfig(config='yes', config_type='phy')
    bgplib.l3tc_vrfipv4v6_address_leafspine_config_unconfig(config='yes', config_type='all')
    # Ping Verification
    if not bgplib.l3tc_vrfipv4v6_address_leafspine_ping_test(config_type='all', ping_count=3):
        st.error("Ping failed in between Spine - Leaf")
        st.report_fail('test_case_failed')
    bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_config(config='yes')

    bgplib.l3tc_vrfipv4v6_address_leafspine_tg_bgp_config(config='yes', config_type='all', class_reconfig='Yes')
    st.wait(10)

    # BGP Neighbour Verification
    if not utils.poll_wait(bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_check, 10, config_type='all'):
        st.error("Neighbour is failed to Establish between Spine - Leaf")
        st.report_fail('test_case_failed')
    st.log("Getting all topology info related to connectivity / TG and other parameters between duts")
    topo = bgplib.get_leaf_spine_topology_info()
    st.banner("BGP RIF CLASS CONFIG - END")


def bgp_rif_pre_config_cleanup():
    st.banner("BGP RIF CLASS CONFIG CLEANUP - START")
    bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_config(config='no')
    bgplib.l3tc_vrfipv4v6_address_leafspine_config_unconfig(config='no')
    # cleanup underlay config
    bgplib.l3tc_underlay_config_unconfig(config='no', config_type='phy')
    st.banner("BGP RIF CLASS CONFIG CLEANUP - END")


@pytest.fixture(scope='class')
def bgp_rif_class_hook(request):
    bgp_rif_pre_config()
    yield
    bgp_rif_pre_config_cleanup()


# TestBGPRif class
@pytest.mark.usefixtures('bgp_rif_class_hook')
class TestBGPRif(TestBGPCommon):

    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_pass
    def test_ft_bgp_v6_link_local_bgp(self):
        """

        Verify that BGP peer session is established with v6 link local address
        """

        # Getting topo info between an spine and leaf
        info = SpyTestDict()
        info = bgplib.get_tg_topology_leafspine_bgp(dut_type='spine-leaf', max_tg_links='0', nodes='2')
        # NOTE: D1 is spine and D2 is leaf by default

        leaf_name = info['D2']
        spine_name = info['D1']

        result = bgpapi.create_bgp_neighbor_interface(leaf_name, info['D2_as'], info['D2D1P1'], info['D1_as'], 'ipv6', cli_type=bgp_cli_type)
        if not result:
            st.error("Failed to enable BGP on interface {}".format(info['D2D1P1']))
            st.report_fail('test_case_failed')

        result = bgpapi.create_bgp_neighbor_interface(spine_name, info['D1_as'], info['D1D2P1'], info['D2_as'], 'ipv6', cli_type=bgp_cli_type)
        if not result:
            # Clear the previous config
            bgpapi.create_bgp_neighbor_interface(leaf_name, info['D2_as'], info['D2D1P1'], info['D1_as'], 'ipv6', 'no', cli_type=bgp_cli_type)
            st.error("Failed to enable BGP on interface {}".format(info['D1D2P1']))
            st.report_fail('test_case_failed')

        # Verify bgp session on interface
        if not utils.poll_wait(bgpapi.verify_bgp_summary, 130, leaf_name, family='ipv6', neighbor=info['D2D1P1'],
                               state='Established'):
            # show neighbors for debug in case of failure and Clear all config
            utils.exec_all(True, [[bgpapi.show_bgp_ipv6_neighbor_vtysh, leaf_name], [bgpapi.show_bgp_ipv6_neighbor_vtysh, spine_name]])
            bgpapi.create_bgp_neighbor_interface(leaf_name, info['D2_as'], info['D2D1P1'], info['D1_as'], 'ipv6', 'no', cli_type=bgp_cli_type)
            bgpapi.create_bgp_neighbor_interface(spine_name, info['D1_as'], info['D1D2P1'], info['D2_as'], 'ipv6', 'no', cli_type=bgp_cli_type)
            st.error("BGP Neighbor failed to Establish between DUT and Partner")
            st.report_fail('operation_failed')
        utils.exec_all(True, [[bgpapi.show_bgp_ipv6_neighbor_vtysh, leaf_name],
                              [bgpapi.show_bgp_ipv6_neighbor_vtysh, spine_name]])
        bgpapi.create_bgp_neighbor_interface(leaf_name, info['D2_as'], info['D2D1P1'], info['D1_as'], 'ipv6', 'no', cli_type=bgp_cli_type)
        bgpapi.create_bgp_neighbor_interface(spine_name, info['D1_as'], info['D1D2P1'], info['D2_as'], 'ipv6', 'no', cli_type=bgp_cli_type)
        st.report_pass("test_case_passed")

    @pytest.mark.bgp_clear
    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_pass
    def test_ft_bgp_clear(self):
        TestBGPCommon.ft_bgp_clear(self)

    @pytest.mark.bgp_traffic
    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_fail
    def test_ft_bgp_peer_traffic_check(self):
        TestBGPCommon.ft_bgp_peer_traffic_check(self)

    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_pass
    def test_ft_bgp_graceful_restart_and_aware_routers(self):
        TestBGPCommon.ft_bgp_graceful_restart_and_aware_routers(self)

    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_fail
    def test_ft_bgp_ipv4_no_route_aggregation_for_exact_prefix_match(self):
        TestBGPCommon.ft_bgp_ipv4_no_route_aggregation_for_exact_prefix_match(self)

    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_fail
    def test_ft_bgp_ipv4_route_aggregation_atomic_aggregate_without_as_set(self):
        TestBGPCommon.ft_bgp_ipv4_route_aggregation_atomic_aggregate_without_as_set(self)

    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_fail
    def test_bgp_route_aggregation_4byteASN(self):
        TestBGPCommon.ft_bgp_route_aggregation_4byteASN(self)

    @pytest.mark.bgp_ft
    def test_ft_bgp_ipv6_route_aggregation_with_as_set(self):
        TestBGPCommon.ft_bgp_ipv6_route_aggregation_with_as_set(self)

    @pytest.mark.bgp_ft
    def test_ft_bgp_v4_dyn_nbr(self):
        """
        Verify that BGP peering is formed with dynamic neighbors having 4btye ASN
        """

        # Getting topo info between an spine and leaf
        info = SpyTestDict()
        info = bgplib.get_tg_topology_leafspine_bgp(dut_type='spine-leaf', max_tg_links='0', nodes='2')
        # NOTE: D1 is spine D2 is leaf by default

        leaf_name = info['D2']
        spine_name = info['D1']

        # Configure an ip address on Spine
        spine_ipv4 = '45.45.45.45'
        ipapi.config_ip_addr_interface(spine_name, info['D1D2P1'], spine_ipv4, 24)

        # Configure an ip address on Leaf
        leaf_ipv4 = '45.45.45.46'
        ipapi.config_ip_addr_interface(leaf_name, info['D2D1P1'], leaf_ipv4, 24)
        # if bgp_cli_type == "klish":
        #     bgpapi.config_bgp_peer_group(leaf_name, info['D2_as'], 'leaf_spine', config="yes", cli_type=vtysh_cli_type)
        # Add a listen range on Leaf
        listen_range = '45.45.45.0'
        bgpapi.config_bgp_listen(leaf_name, info['D2_as'], listen_range, 24, 'leaf_spine', 0, cli_type=bgp_cli_type)

        # Add neighbor on Spine
        bgpapi.create_bgp_neighbor_use_peergroup(spine_name, info['D1_as'], 'spine_leaf', leaf_ipv4, cli_type=bgp_cli_type)

        # Verify bgp neighbors
        result = bgpapi.verify_bgp_summary(leaf_name, family='ipv4', neighbor='*'+spine_ipv4, state='Established')
        if not result:
            bgplib.show_bgp_neighbors([leaf_name, spine_name], af='ipv4')
        # Clear applied configs

        # Delete listen range
        bgpapi.config_bgp_listen(leaf_name, info['D2_as'], listen_range, 24, 'leaf_spine', 0, 'no', cli_type=bgp_cli_type)

        # Delete the neighbor from Spine
        bgpapi.delete_bgp_neighbor(spine_name, info['D1_as'], leaf_ipv4, info['D2_as'], cli_type=bgp_cli_type)

        # Delete ip address from Leaf
        ipapi.delete_ip_interface(leaf_name, info['D2D1P1'], leaf_ipv4, 24)

        # Delete ip address from Spine
        ipapi.delete_ip_interface(spine_name, info['D1D2P1'], spine_ipv4, 24)
        # if bgp_cli_type == "klish":
        #     bgpapi.config_bgp_peer_group(leaf_name, info['D2_as'], 'leaf_spine', config="no", cli_type=bgp_cli_type)
        if result:
            st.log("BGP adjacency verified")
            st.report_pass("test_case_passed")
        else:
            st.log("Failed to form BGP peering using dynamic ipv4 neighbors")
            st.report_fail("test_case_failed")

    @pytest.mark.bgp_ft
    def test_ft_bgp_v6_dyn_nbr(self):
        """
        Verify that ipv6 BGP peering is formed with dynamic neighbors
        """

        # Getting topo info between an spine and leaf
        info = SpyTestDict()
        info = bgplib.get_tg_topology_leafspine_bgp(dut_type='spine-leaf', max_tg_links='0', nodes='2')
        # NOTE: D1 is spine D2 is leaf by default

        leaf_name = info['D2']
        spine_name = info['D1']

        # Configure an ip address on Spine
        spine_ipv6 = '2001::1'
        ipapi.config_ip_addr_interface(spine_name, info['D1D2P1'], spine_ipv6, 64, family='ipv6')

        # Configure an ip address on Leaf
        leaf_ipv6 = '2001::2'
        ipapi.config_ip_addr_interface(leaf_name, info['D2D1P1'], leaf_ipv6, 64, family='ipv6')

        # Add a listen range on Leaf
        listen_range = '2001::0'
        bgpapi.config_bgp_listen(leaf_name, info['D2_as'], listen_range, 64, 'leaf_spine6', 0, cli_type=bgp_cli_type)

        # Add neighbor on Spine
        bgpapi.create_bgp_neighbor_use_peergroup(spine_name, info['D1_as'], 'spine_leaf6', leaf_ipv6, family='ipv6', cli_type=bgp_cli_type)

        # Verify dynamic bgp neighbors
        result = bgpapi.verify_bgp_summary(leaf_name, family='ipv6', neighbor='*'+spine_ipv6, state='Established')
        if not result:
            bgplib.show_bgp_neighbors([leaf_name, spine_name], af='ipv6')
        # Clear applied configs

        # Delete listen range
        bgpapi.config_bgp_listen(leaf_name, info['D2_as'], listen_range, 64, 'leaf_spine6', 0, 'no', cli_type=bgp_cli_type)

        # Delete the neighbor from Spine
        bgpapi.delete_bgp_neighbor(spine_name, info['D1_as'], leaf_ipv6, info['D2_as'], cli_type=bgp_cli_type)

        # Delete ip address from Leaf
        ipapi.delete_ip_interface(leaf_name, info['D2D1P1'], leaf_ipv6, 64, family='ipv6')

        # Delete ip address from Spine
        ipapi.delete_ip_interface(spine_name, info['D1D2P1'], spine_ipv6, 64, family='ipv6')

        if result:
            st.log("BGP adjacency verified")
            st.report_pass("test_case_passed")
        else:
            st.log("Failed to form BGP peering using dynamic ipv6 neighbors")
            st.report_fail("test_case_failed")

    @pytest.mark.bgp_ft
    def test_ft_bgp_v4_max_dyn_nbr(self):
        """

        Verify that BGP peering is established with maximum supported dynamic neighbors with maximum listen
        ranges at once
        """
        # Getting topo info between an spine and leaf
        info = SpyTestDict()
        info = bgplib.get_tg_topology_leafspine_bgp(dut_type='spine-leaf', max_tg_links='0', nodes='2')
        # NOTE: D1 is spine D2 is leaf by default

        leaf_name = info['D2']
        spine_name = info['D1']

        result = True

        # Set listen limit
        # NOTE: Setting a limit to max dynamic neighbors. It can be set to any value, but the test case execution
        # time increases

        limit = 5
        bgpapi.config_bgp_listen(leaf_name,info['D2_as'], 0, 0, 'leaf_spine', limit,cli_type=bgp_cli_type)

        # Apply Configs:
        # Add IP addresses on leaf and spine
        # Add neighbor on spine
        # Add listen range on leaf
        for i in range(1, limit+1):
            leaf_ipaddr  = '{}.0.5.1'.format(20+i)
            spine_ipaddr = '{}.0.5.2'.format(20+i)
            listen_range = '{}.0.5.0'.format(20+i)
            ipapi.config_ip_addr_interface(spine_name, info['D1D2P1'], spine_ipaddr, 24)
            ipapi.config_ip_addr_interface(leaf_name, info['D2D1P1'], leaf_ipaddr, 24)
            bgpapi.config_bgp_listen(leaf_name, info['D2_as'], listen_range, 24, 'leaf_spine', 0,cli_type=bgp_cli_type)
            bgpapi.create_bgp_neighbor_use_peergroup(spine_name, info['D1_as'], 'spine_leaf', leaf_ipaddr)
            # Verify dynamic bgp neighbors
            result = result & (bgpapi.verify_bgp_summary(leaf_name, family='ipv4', neighbor='*'+spine_ipaddr,
                                                         state='Established'))
            if not result:
                bgplib.show_bgp_neighbors([leaf_name, spine_name], af='ipv4')

        # Clear applied configs

        # Delete listen limit
        bgpapi.config_bgp_listen(leaf_name, info['D2_as'], 0, 0, 'leaf_spine', limit, 'no',cli_type=bgp_cli_type)

        for i in range(1, limit+1):
            leaf_ipaddr = '{}.0.5.1'.format(20+i)
            spine_ipaddr = '{}.0.5.2'.format(20+i)
            listen_range = '{}.0.5.0'.format(20+i)
            # Delete listen range
            bgpapi.config_bgp_listen(leaf_name, info['D2_as'], listen_range, 24, 'leaf_spine', 0, 'no',cli_type=bgp_cli_type)
            # Delete the neighbor from Spine
            bgpapi.delete_bgp_neighbor(spine_name, info['D1_as'], leaf_ipaddr, info['D2_as'])
            # Delete ip address from Leaf
            ipapi.delete_ip_interface(leaf_name, info['D2D1P1'], leaf_ipaddr, 24)
            # Delete ip address from Spine
            ipapi.delete_ip_interface(spine_name, info['D1D2P1'], spine_ipaddr, 24)

        if result:
            st.log("BGP adjacency verified")
            st.report_pass("test_case_passed")
        else:
            st.log("Failed to form BGP peering using max dynamic ipv4 neighbors")
            st.report_fail("test_case_failed")


    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_pass
    def test_ft_bgp_rmap(self):
        """

        Verify a route map application after route has been installed
        """

        # Getting topo info
        info = SpyTestDict()
        info = bgplib.get_tg_topology_leafspine_bgp(dut_type='spine-leaf', max_tg_links='0', nodes='2')
        # NOTE: D1 is spine D2 is leaf by default

        leaf_name = info['D2']
        spine_name = info['D1']
        network1 = '134.5.6.0/24'

        # Advertise a network to peer
        n1 = bgpapi.advertise_bgp_network(leaf_name, info['D2_as'], network1, cli_type=vtysh_cli_type)
        n1 = ipapi.verify_ip_route(spine_name,ip_address=network1)
        if n1:
            st.log("Advertised route present")

        # Create a route-map to deny the network advertisement
        ipapi.config_route_map_match_ip_address(leaf_name, 'test-rmap', 'deny', '10', 'test-access-list1')
        # Create access-list test-access-list1 and deny the network
        ipapi.config_access_list(leaf_name, 'test-access-list1', network1, 'deny')
        # Add route-map to advertised network
        bgpapi.advertise_bgp_network(leaf_name, info['D2_as'], network1, 'test-rmap', cli_type=vtysh_cli_type)

        # Verify the network on spine
        n1 = ipapi.verify_ip_route(spine_name, ip_address=network1)
        if not n1:
            result = True
        else:
            result = False
        # Clear applied configs
        ipapi.config_access_list(leaf_name, 'test-access-list1', network1, 'deny', config='no')
        ipapi.config_route_map_mode(leaf_name, 'test-rmap', 'permit', '10', config='no')
        bgpapi.advertise_bgp_network(leaf_name, info['D2_as'], network1, 'test-rmap', config='no', cli_type=vtysh_cli_type)

        if result:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")


    @pytest.mark.bgp_ft
    @pytest.mark.community
    @pytest.mark.community_fail
    def test_ft_bgp_rmap_out(self):
        """

        Verify a route map with multiple match and set option in out direction
        """

        # Getting topo info
        info = SpyTestDict()
        info = bgplib.get_tg_topology_leafspine_bgp(dut_type = 'spine-leaf', max_tg_links= '0', nodes='2')
        # NOTE: D1 is spine D2 is leaf by default

        leaf_name = info['D2']
        spine_name = info['D1']

        result = True

        network1 = '134.5.6.0/24'
        network2 = '134.5.7.0/24'
        network3 = '134.5.8.0'

        # Create route-map and permit network3
        ipapi.config_route_map_match_ip_address(leaf_name, 'test-rmap', 'permit', '10', 'test-access-list1')
        # Add set option to prepend as-path 200
        ipapi.config_route_map_set_aspath(leaf_name, 'test-rmap', 'permit', '10', '200')
        # Create access-list test-access-list1
        ipapi.config_access_list(leaf_name, 'test-access-list1', network3+'/24', 'permit')

        # Advertise two networks from leaf
        bgpapi.advertise_bgp_network(leaf_name, info['D2_as'], network1, 'test-rmap', cli_type=vtysh_cli_type)
        bgpapi.advertise_bgp_network(leaf_name, info['D2_as'], network2, 'test-rmap', cli_type=vtysh_cli_type)
        bgpapi.advertise_bgp_network(leaf_name, info['D2_as'], network3+'/24', 'test-rmap', cli_type=vtysh_cli_type)

        # In route-map, deny network1
        ipapi.config_route_map_match_ip_address(leaf_name, 'test-rmap', 'deny', '20', 'test-access-list2')
        # Create access-list test-access-list2
        ipapi.config_access_list(leaf_name, 'test-access-list2', network1, 'deny')

        # In route-map, permit network2
        ipapi.config_route_map_match_ip_address(leaf_name, 'test-rmap', 'permit', '30', 'test-access-list3')
        # Create access-list test-access-list3
        ipapi.config_access_list(leaf_name, 'test-access-list3', network2, 'permit')

        # verify that the neighbor has the as-path prepended
        output = bgpapi.show_bgp_ipvx_prefix(spine_name, prefix=network3, masklen=24)
        st.log(output)
        for x in output:  # type: basestring
            as_path = x['peerasn']
            as_path = as_path.split()
            for each in as_path:
                if each == "200":
                    result = True

        # verify that network1 is not present in bgp routes
        n1 = ipapi.verify_ip_route(spine_name,ip_address=network1)
        if not n1:
            result = result & True
        else:
            result = result & False

        # verify that network2 is present in bgp routes
        n2 = ipapi.verify_ip_route(spine_name,ip_address=network2)
        if n2:
            result = result & True
        else:
            result = result & False

        # CLear applied configs
        ipapi.config_access_list(leaf_name, 'test-access-list3', network2, 'permit', config='no')
        ipapi.config_access_list(leaf_name, 'test-access-list2', network1, 'deny', config='no')
        ipapi.config_access_list(leaf_name, 'test-access-list1', network3+'/24', 'permit', config='no')

        ipapi.config_route_map_mode(leaf_name, 'test-rmap', 'permit', '10', config='no')

        bgpapi.advertise_bgp_network(leaf_name, info['D2_as'], network1, 'test-rmap', config='no', cli_type=vtysh_cli_type)
        bgpapi.advertise_bgp_network(leaf_name, info['D2_as'], network2, 'test-rmap', config='no', cli_type=vtysh_cli_type)
        bgpapi.advertise_bgp_network(leaf_name, info['D2_as'], network3+'/24', 'test-rmap', config='no', cli_type=vtysh_cli_type)

        if result:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

    @pytest.mark.regression
    def test_ft_bgp_ebgp_confed(self):
        """
        Author : seshareddy.koilkonda@broadcom.com
        Verify the functionality of route-maps with confederation peers
        """
        TG_D1 = topo.tg_dut_list_name[0]
        tg_ob = topo['T1{}P1_tg_obj'.format(TG_D1)]
        bgp_handle = topo['T1{}P1_ipv4_tg_bh'.format(TG_D1)]
        info = SpyTestDict()
        info = bgplib.get_tg_topology_leafspine_bgp(dut_type='spine-leaf', max_tg_links='1', nodes='2')
        spine_name = info['D1']
        leaf_name = info['D2']
        spine_as = info['D1_as']
        leaf_as = info['D2_as']
        confed_identifier = 65000
        tc_fail_flag = 0

        bgpapi.config_bgp(leaf_name, config='yes', config_type_list='', local_as=leaf_as,
                          conf_identf=confed_identifier,cli_type=vtysh_cli_type)
        bgpapi.config_bgp(leaf_name, config='yes', config_type_list='', local_as=leaf_as, conf_peers=spine_as,cli_type=vtysh_cli_type)
        bgpapi.config_bgp(spine_name, config='yes', config_type_list='', local_as=spine_as,
                          conf_identf=confed_identifier,cli_type=vtysh_cli_type)
        bgpapi.config_bgp(spine_name, config='yes', config_type_list='', local_as=spine_as, conf_peers=leaf_as,cli_type=vtysh_cli_type)

        ipapi.config_route_map_match_ip_address(spine_name, 'confed-rmap', 'permit', '10', 'confed-access-list1')
        ipapi.config_access_list(spine_name, 'confed-access-list1', '125.5.1.0/16', 'permit')
        bgpapi.config_bgp(spine_name, local_as=spine_as, neighbor=info['D2D1P1_ipv4'], config_type_list=["routeMap"],
                          routeMap='confed-rmap', diRection='out',cli_type=vtysh_cli_type)
        bgpapi.create_bgp_next_hop_self(spine_name, spine_as, 'ipv4', info['D2D1P1_ipv4'])

        st.log("Advertising the route map matching routes from the Spine DUT i.e. they should "
               "be advertised on Leaf node")
        tg_ob.tg_emulation_bgp_route_config(handle=bgp_handle['handle'], mode='add', num_routes='20',
                                            prefix='125.5.1.0', as_path='as_seq:1')
        tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='start')

        n1 = ipapi.verify_ip_route(topo.dut_list[1], ip_address='125.5.5.0/24')
        if not n1:
            st.error('Route-map matching prefexis from the Spine DUT are not advertised to leaf DUT.')
            tc_fail_flag = 1

        st.log("Advertising the route-map non matching routes from the Spine DUT i.e. they should not be "
               "advertised on Leaf node.")
        tg_ob.tg_emulation_bgp_route_config(handle=bgp_handle['handle'], mode='add', num_routes='20',
                                            prefix='126.5.1.0', as_path='as_seq:1')
        tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='start')

        n1 = ipapi.verify_ip_route(topo.dut_list[1], ip_address='126.5.5.0/24')
        n2 = ipapi.verify_ip_route(topo.dut_list[0], ip_address='126.5.5.0/24')
        if (n1 == True) or (n2 == False):
            st.error('Route check failed for the scenario, route-map non matching prefexis from the Spine DUT')
            tc_fail_flag = 1

        # Unconfig section
        tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='stop')
        ipapi.config_route_map_mode(topo.dut_list[0], 'confed-rmap', 'permit', '10', config='no')
        ipapi.config_access_list(topo.dut_list[0], 'confed-access-list1', '121.5.1.0/16', 'permit', config='no')
        bgpapi.config_bgp(topo.dut_list[0], local_as=spine_as, config='no', neighbor=info['D2D1P1_ipv4'],
                          config_type_list=["routeMap"], routeMap='confed-rmap', diRection='out',cli_type=vtysh_cli_type)
        bgpapi.create_bgp_next_hop_self(topo.dut_list[0], spine_as, 'ipv4', info['D2D1P1_ipv4'], 'no', 'no')

        if tc_fail_flag:
            st.report_fail('test_case_failed')
        st.report_pass('test_case_passed')


"""
BGP Neighbor over regular router interface fixture, class and test cases  - END
"""


"""
BGP IPv4 and IPv6 router distribution and filtering TCs: Start
"""
@pytest.fixture(scope='class')
def bgp_ipvx_route_adv_filter_fixture(request):
    """
    Prepare base for router advertisement and filtering TCs
    Pick first spine, first leaf and first link between them and create reduced topo
    The following will be changed to API based eventually.
    Currently implemented like this to progress on TC
    """
    reduced_topo = dict()
    reduced_topo['dut1'] = topo.spine_list[0]
    reduced_topo['dut2'] = topo.leaf_list[0]
    reduced_topo['dut1_index'] = 1 + topo.dut_list.index(topo.spine_list[0])
    reduced_topo['dut2_index'] = 1 + topo.dut_list.index(topo.leaf_list[0])
    reduced_topo['dut1_as'] = "{}".format(topo['D{}_as'.format(reduced_topo['dut1_index'])])
    reduced_topo['dut2_as'] = "{}".format(topo['D{}_as'.format(reduced_topo['dut2_index'])])
    reduced_topo['dut1_addr_ipv4'] = topo[
        'D{}D{}P1_ipv4'.format(reduced_topo['dut1_index'], reduced_topo['dut2_index'])]
    reduced_topo['dut2_addr_ipv4'] = topo[
        'D{}D{}P1_ipv4'.format(reduced_topo['dut2_index'], reduced_topo['dut1_index'])]
    reduced_topo['dut1_addr_ipv6'] = topo[
        'D{}D{}P1_ipv6'.format(reduced_topo['dut1_index'], reduced_topo['dut2_index'])]
    reduced_topo['dut2_addr_ipv6'] = topo[
        'D{}D{}P1_ipv6'.format(reduced_topo['dut2_index'], reduced_topo['dut1_index'])]
    reduced_topo['dut1_outif'] = topo[
        'D{}D{}P1'.format(reduced_topo['dut1_index'], reduced_topo['dut2_index'])]
    reduced_topo['dut2_outif'] = topo[
        'D{}D{}P1'.format(reduced_topo['dut1_index'], reduced_topo['dut2_index'])]

    request.cls.local_topo = reduced_topo

    config_items = {}

    bgplib.configure_base_for_route_adv_and_filter(reduced_topo['dut1'], reduced_topo['dut2'], reduced_topo,
                                                   config_items)

    yield reduced_topo

    bgplib.unconfigure_base_for_route_adv_and_filter(reduced_topo['dut1'], reduced_topo['dut2'], reduced_topo,
                                                     config_items)


@pytest.mark.usefixtures('bgp_rif_class_hook', 'bgp_ipvx_route_adv_filter_fixture')
class TestBGPIPvxRouteAdvertisementFilter:
    local_topo = dict()

    def configure_base_for_filter_prefix_on_community(self, peer_grp4_name, config, cli_type="vtysh"):
        bgpapi.config_bgp(dut=self.local_topo['dut1'], local_as=self.local_topo['dut1_as'], config=config,
                          config_type_list=["redist"], redistribute='static',cli_type=cli_type)
        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'],
                          neighbor=peer_grp4_name, addr_family='ipv4', config=config,
                          config_type_list=["routeMap"], routeMap='rmap1', diRection='in',cli_type=cli_type)

    @pytest.mark.community
    @pytest.mark.community_pass
    def test_redistribute_connected_ipv4(self, bgp_ipvx_route_adv_filter_fixture):

        bgpapi.config_address_family_redistribute(self.local_topo['dut1'], self.local_topo['dut1_as'],
                                                  'ipv4', 'unicast', "connected", config='yes', cli_type=bgp_cli_type)

        output = ipapi.fetch_ip_route(self.local_topo['dut1'], match={'type': 'C'}, select=['ip_address'])
        list_of_connected_network_on_dut1 = list(x['ip_address'] for x in output)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv4',
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut1_as']) in x['as_path']]

        list_of_learned_routes_on_dut2_from_dut1 = list(x['network'] for x in output)

        st.log('List of connected network on dut1:' + str(list_of_connected_network_on_dut1))
        st.log('List of network learnt on dut2 from dut1:' + str(list_of_learned_routes_on_dut2_from_dut1))

        if set(list_of_connected_network_on_dut1).issubset(set(list_of_learned_routes_on_dut2_from_dut1)):
            result = True
        else:
            result = False

        bgpapi.config_address_family_redistribute(self.local_topo['dut1'], self.local_topo['dut1_as'],
                                                  'ipv4', 'unicast', "connected", config='no', cli_type=bgp_cli_type)

        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    @pytest.mark.community
    @pytest.mark.community_pass
    def test_redistribute_static_ipv4(self, bgp_ipvx_route_adv_filter_fixture):

        ipapi.create_static_route(self.local_topo['dut1'], self.local_topo['dut1_outif'], '100.1.1.1/32', family='ipv4')

        output = ipapi.fetch_ip_route(self.local_topo['dut1'], match={'type': 'S'}, select=['ip_address'])
        list_of_static_network_on_dut1 = list(x['ip_address'] for x in output)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv4',
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut1_as']) in x['as_path']]

        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)

        st.log('List of static route on dut1' + str(list_of_static_network_on_dut1))
        st.log('List of network redistributed to dut2 from dut1' + str(list_of_learned_routes_on_dut2_by_dut1))

        bgpapi.config_address_family_redistribute(self.local_topo['dut1'], self.local_topo['dut1_as'],
                                                  'ipv4', 'unicast', "static", config='yes', cli_type=bgp_cli_type)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv4',
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut1_as']) in x['as_path']]

        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)

        st.log('List of static route on dut1' + str(list_of_static_network_on_dut1))
        st.log('List of network redistributed to dut2 from dut1' + str(list_of_learned_routes_on_dut2_by_dut1))

        if set(list_of_static_network_on_dut1).issubset(set(list_of_learned_routes_on_dut2_by_dut1)):
            st.log('static on dut1 is subset of dut1 learned route on dut2')
            result = True
        else:
            st.log('static on dut1 is not a subset of dut1 learned route on dut2')
            result = False

        bgpapi.config_address_family_redistribute(self.local_topo['dut1'], self.local_topo['dut1_as'],
                                                  'ipv4', 'unicast', "static", config='no', cli_type=bgp_cli_type)

        ipapi.delete_static_route(self.local_topo['dut1'], self.local_topo['dut1_outif'], '100.1.1.1/32', family='ipv4')

        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    @pytest.mark.community
    @pytest.mark.community_pass
    def test_distribute_list_in_ipv4(self, bgp_ipvx_route_adv_filter_fixture):

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv4',
                                           match={'next_hop': self.local_topo['dut1_addr_ipv4']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut1_as']) in x['as_path']]

        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)
        if '102.1.1.0/24' in list_of_learned_routes_on_dut2_by_dut1:
            st.log("route learnt")
        else:
            st.log("route not learnt")

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv4',
                          config='yes',
                          neighbor=self.local_topo['dut1_addr_ipv4'],
                          config_type_list=["distribute_list"], distribute_list='11', diRection='in',cli_type=vtysh_cli_type)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv4',
                                           match={'next_hop': self.local_topo['dut1_addr_ipv4']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut1_as']) in x['as_path']]

        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)
        if '102.1.1.0/24' in list_of_learned_routes_on_dut2_by_dut1:
            st.log("route not suppressed")
            result = False
        else:
            st.log("route suppressed")
            result = True

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv4',
                          config='no',
                          neighbor=self.local_topo['dut1_addr_ipv4'],
                          config_type_list=["distribute_list"], distribute_list='11', diRection='in',cli_type=vtysh_cli_type)

        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    @pytest.mark.community
    @pytest.mark.community_pass
    def test_filter_list_in_ipv4(self, bgp_ipvx_route_adv_filter_fixture):

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv4',
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut1_as']) in x['as_path']]

        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)
        if len(list_of_learned_routes_on_dut2_by_dut1):
            st.log("route received for as {}".format(self.local_topo['dut1_as']))
        else:
            st.log("route not learnt")

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv4',
                          config='yes',
                          neighbor=self.local_topo['dut1_addr_ipv4'],
                          config_type_list=["filter_list"], filter_list='FILTER', diRection='in',cli_type=vtysh_cli_type)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv4',
                                           match={'next_hop': self.local_topo['dut1_addr_ipv4']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut1_as']) in x['as_path']]

        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)
        if len(list_of_learned_routes_on_dut2_by_dut1) != 0:
            st.log("still having routes from as {}".format(self.local_topo['dut1_as']))
            result = False
        else:
            st.log("no routes from as {}".format(self.local_topo['dut1_as']))
            result = True

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv4',
                          config='no',
                          neighbor=self.local_topo['dut1_addr_ipv4'],
                          config_type_list=["filter_list"], filter_list='FILTER', diRection='in',cli_type=vtysh_cli_type)

        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    @pytest.mark.community
    @pytest.mark.community_pass
    def test_prefix_list_out_ipv4(self, bgp_ipvx_route_adv_filter_fixture):

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut1'], family='ipv4',
                                           match={'next_hop': self.local_topo['dut2_addr_ipv4']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut2_as']) in x['as_path']]

        list_of_learned_routes_on_dut1_by_dut2 = list(x['network'] for x in output)
        if '202.1.1.0/24' in list_of_learned_routes_on_dut1_by_dut2:
            st.log("route learnt")
        else:
            st.log("route not learnt")
        if bgp_cli_type == "klish":
            ipapi.config_ip_prefix_list(self.local_topo['dut2'], 'PREFIXOUT', '202.1.1.0/24', family="ipv4", action="deny", cli_type=bgp_cli_type)
            ipapi.config_ip_prefix_list(self.local_topo['dut2'], 'PREFIXOUT', 'any', family="ipv4", action="permit", cli_type=bgp_cli_type)

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv4',
                          config='yes',
                          neighbor=self.local_topo['dut1_addr_ipv4'],
                          config_type_list=["prefix_list"], prefix_list='PREFIXOUT', diRection='out',cli_type=bgp_cli_type)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut1'], family='ipv4',
                                           match={'next_hop': self.local_topo['dut2_addr_ipv4']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut2_as']) in x['as_path']]

        list_of_learned_routes_on_dut1_by_dut2 = list(x['network'] for x in output)
        if '202.1.1.0/24' in list_of_learned_routes_on_dut1_by_dut2:
            st.log("route not suppressed")
            result = False
        else:
            st.log("route suppressed")
            result = True

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv4',
                          config='no',
                          neighbor=self.local_topo['dut1_addr_ipv4'],
                          config_type_list=["prefix_list"], prefix_list='PREFIXOUT', diRection='out',cli_type=bgp_cli_type)

        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    @pytest.mark.community
    @pytest.mark.community_pass
    def test_default_originate_ipv4(self, bgp_ipvx_route_adv_filter_fixture):

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut1'], family='ipv4',
                                           match={'next_hop': self.local_topo['dut2_addr_ipv4']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut2_as']) in x['as_path']]

        list_of_learned_routes_on_dut1_by_dut2 = list(x['network'] for x in output)
        if '0.0.0.0/0' in list_of_learned_routes_on_dut1_by_dut2:
            st.log("route learnt")
        else:
            st.log("route not learnt")

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv4',
                          config='yes',
                          neighbor=self.local_topo['dut1_addr_ipv4'],
                          config_type_list=["default_originate"], routeMap='UseGlobal',cli_type=vtysh_cli_type)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut1'], family='ipv4',
                                           match={'next_hop': self.local_topo['dut2_addr_ipv4']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut2_as']) in x['as_path']]

        list_of_learned_routes_on_dut1_by_dut2 = list(x['network'] for x in output)
        if '0.0.0.0/0' in list_of_learned_routes_on_dut1_by_dut2:
            st.log("default route advertised")
            result = True
        else:
            st.log("default route not advertised")
            result = False

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv4',
                          config='no',
                          neighbor=self.local_topo['dut1_addr_ipv4'],
                          config_type_list=["default_originate"], routeMap='UseGlobal',cli_type=vtysh_cli_type)

        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    @pytest.mark.community
    @pytest.mark.community_pass
    def test_route_map_in_ipv4(self, bgp_ipvx_route_adv_filter_fixture):

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv4',
                                           match={'next_hop': self.local_topo['dut1_addr_ipv4']},
                                           select=['network', 'local_pref', 'metric'])

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv4',
                          config='yes',
                          neighbor=self.local_topo['dut1_addr_ipv4'],
                          config_type_list=["routeMap"], routeMap='SETPROPS', diRection='in',cli_type=vtysh_cli_type)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv4',
                                           match={'next_hop': self.local_topo['dut1_addr_ipv4']},
                                           select=['network', 'local_pref', 'metric'])

        metric = [x for x in output if x['network'] == '102.1.1.0/24'][0]['metric']

        local_pref = [x for x in output if x['network'] == '101.1.1.0/24'][0]['local_pref']

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv4',
                          config='no',
                          neighbor=self.local_topo['dut1_addr_ipv4'],
                          config_type_list=["routeMap"], routeMap='SETPROPS', diRection='in',cli_type=vtysh_cli_type)

        if metric == '400' and local_pref == '200':
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    @pytest.mark.community
    @pytest.mark.community_pass
    def test_redistribute_connected_ipv6(self, bgp_ipvx_route_adv_filter_fixture):

        bgpapi.config_address_family_redistribute(self.local_topo['dut1'], self.local_topo['dut1_as'],
                                                  'ipv6', 'unicast', "connected", config='yes', cli_type=bgp_cli_type)

        output = ipapi.fetch_ip_route(self.local_topo['dut1'], family='ipv6', match={'type': 'C'},
                                      select=['ip_address'])

        output = [x for x in output if not x['ip_address'].startswith('fe80')]
        list_of_connected_network_on_dut1 = list(x['ip_address'] for x in output)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv6',
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut1_as']) in x['as_path']]
        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)

        st.log('List of connected network on dut1')
        st.log(list_of_connected_network_on_dut1)
        st.log('List of network redistributed to dut2 from dut1')
        st.log(list_of_learned_routes_on_dut2_by_dut1)

        if set(list_of_connected_network_on_dut1).issubset(set(list_of_learned_routes_on_dut2_by_dut1)):
            result = True
        else:
            result = False

        bgpapi.config_address_family_redistribute(self.local_topo['dut1'], self.local_topo['dut1_as'],
                                                  'ipv6', 'unicast', "connected", config='no', cli_type=bgp_cli_type)

        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    def test_redistribute_static_ipv6(self, bgp_ipvx_route_adv_filter_fixture):

        ipapi.create_static_route(self.local_topo['dut1'], self.local_topo['dut1_outif'], '100:1::1:1/128',
                                  family='ipv6')

        output = ipapi.fetch_ip_route(self.local_topo['dut1'], family='ipv6', match={'type': 'S'},
                                      select=['ip_address'])
        list_of_static_network_on_dut1 = list(x['ip_address'] for x in output)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv6',
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut1_as']) in x['as_path']]
        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)

        st.log('List of static route on dut1' + str(list_of_static_network_on_dut1))
        st.log('List of network redistributed to dut2 from dut1' + str(list_of_learned_routes_on_dut2_by_dut1))

        bgpapi.config_address_family_redistribute(self.local_topo['dut1'], self.local_topo['dut1_as'],
                                                  'ipv6', 'unicast', "static", config='yes', cli_type=bgp_cli_type)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv6',
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut1_as']) in x['as_path']]

        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)

        st.log('List of static route on dut1' + str(list_of_static_network_on_dut1))
        st.log('List of network redistributed to dut2 from dut1' + str(list_of_learned_routes_on_dut2_by_dut1))

        if set(list_of_static_network_on_dut1).issubset(set(list_of_learned_routes_on_dut2_by_dut1)):
            st.log('static on dut1 is subset of dut1 learned route on dut2')
            result = True
        else:
            st.log('static on dut1 is not a subset of dut1 learned route on dut2')
            result = False

        bgpapi.config_address_family_redistribute(self.local_topo['dut1'], self.local_topo['dut1_as'],
                                                  'ipv6', 'unicast', "static", config='no', cli_type=bgp_cli_type)

        ipapi.delete_static_route(self.local_topo['dut1'], self.local_topo['dut1_outif'], '100:1::1:1/128',
                                  family='ipv6')

        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    @pytest.mark.community
    @pytest.mark.community_pass
    def test_distribute_list_in_ipv6(self, bgp_ipvx_route_adv_filter_fixture):

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv6',
                                           match={'next_hop': self.local_topo['dut1_addr_ipv6']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut1_as']) in x['as_path']]

        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)
        if '102:1::/64' in list_of_learned_routes_on_dut2_by_dut1:
            st.log("route learnt")
        else:
            st.log("route not learnt")

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv6',
                          config='yes',
                          neighbor=self.local_topo['dut1_addr_ipv6'],
                          config_type_list=["distribute_list"], distribute_list='12', diRection='in',cli_type=vtysh_cli_type)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv6',
                                           match={'next_hop': self.local_topo['dut1_addr_ipv6']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut1_as']) in x['as_path']]

        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)
        if '102:1::/64' in list_of_learned_routes_on_dut2_by_dut1:
            st.log("route not suppressed")
            result = False
        else:
            st.log("route suppressed")
            result = True

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv6',
                          config='no',
                          neighbor=self.local_topo['dut1_addr_ipv6'],
                          config_type_list=["distribute_list"], distribute_list='12', diRection='in',cli_type=vtysh_cli_type)

        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    @pytest.mark.community
    @pytest.mark.community_pass
    def test_filter_list_in_ipv6(self, bgp_ipvx_route_adv_filter_fixture):

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv6',
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut1_as']) in x['as_path']]

        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)
        if len(list_of_learned_routes_on_dut2_by_dut1):
            st.log("route received for as {}".format(self.local_topo['dut1_as']))
        else:
            st.log("route not learnt")

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv6',
                          config='yes',
                          neighbor=self.local_topo['dut1_addr_ipv6'],
                          config_type_list=["filter_list"], filter_list='FILTER', diRection='in',cli_type=vtysh_cli_type)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv6',
                                           match={'next_hop': self.local_topo['dut1_addr_ipv6']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut1_as']) in x['as_path']]

        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)
        if len(list_of_learned_routes_on_dut2_by_dut1) != 0:
            st.log("still having routes from as {}".format(self.local_topo['dut1_as']))
            result = False
        else:
            st.log("no routes from as {}".format(self.local_topo['dut1_as']))
            result = True

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv6',
                          config='no',
                          neighbor=self.local_topo['dut1_addr_ipv6'],
                          config_type_list=["filter_list"], filter_list='FILTER', diRection='in',cli_type=vtysh_cli_type)

        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    @pytest.mark.community
    @pytest.mark.community_pass
    def test_prefix_list_out_ipv6(self, bgp_ipvx_route_adv_filter_fixture):

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut1'], family='ipv6',
                                           match={'next_hop': self.local_topo['dut2_addr_ipv6']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut2_as']) in x['as_path']]

        list_of_learned_routes_on_dut1_by_dut2 = list(x['network'] for x in output)
        if '202:1::/64' in list_of_learned_routes_on_dut1_by_dut2:
            st.log("route learnt")
        else:
            st.log("route not learnt")
        if bgp_cli_type == "klish":
            ipapi.config_ip_prefix_list(self.local_topo['dut2'], 'PREFIXOUT6', '202:1::/64', family="ipv6", action="deny", cli_type=bgp_cli_type)
            ipapi.config_ip_prefix_list(self.local_topo['dut2'], 'PREFIXOUT6', 'any', family="ipv6", action="permit", cli_type=bgp_cli_type)
        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv6',
                          config='yes',
                          neighbor=self.local_topo['dut1_addr_ipv6'],
                          config_type_list=["prefix_list"], prefix_list='PREFIXOUT6', diRection='out',cli_type=bgp_cli_type)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut1'], family='ipv6',
                                           match={'next_hop': self.local_topo['dut2_addr_ipv6']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut2_as']) in x['as_path']]

        list_of_learned_routes_on_dut1_by_dut2 = list(x['network'] for x in output)
        if '202:1::/64' in list_of_learned_routes_on_dut1_by_dut2:
            st.log("route not suppressed")
            result = False
        else:
            st.log("route suppressed")
            result = True

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv6',
                          config='no',
                          neighbor=self.local_topo['dut1_addr_ipv6'],
                          config_type_list=["prefix_list"], prefix_list='PREFIXOUT6', diRection='out',cli_type=bgp_cli_type)

        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    @pytest.mark.community
    @pytest.mark.community_pass
    def test_filter_list_out_ipv6(self, bgp_ipvx_route_adv_filter_fixture):

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut1'], family='ipv6',
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut2_as']) in x['as_path']]

        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)
        if len(list_of_learned_routes_on_dut2_by_dut1):
            st.log("route received for as {}".format(self.local_topo['dut2_as']))
        else:
            st.log("route not learnt")

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv6',
                          config='yes',
                          neighbor=self.local_topo['dut1_addr_ipv6'],
                          config_type_list=["filter_list"], filter_list='FILTER6', diRection='out',cli_type=vtysh_cli_type)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut1'], family='ipv6',
                                           match={'next_hop': self.local_topo['dut2_addr_ipv6']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut2_as']) in x['as_path']]

        list_of_learned_routes_on_dut2_by_dut1 = list(x['network'] for x in output)
        if len(list_of_learned_routes_on_dut2_by_dut1) != 0:
            st.log("still having routes from as {}".format(self.local_topo['dut2_as']))
            result = False
        else:
            st.log("no routes from as {}".format(self.local_topo['dut2_as']))
            result = True

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv6',
                          config='no',
                          neighbor=self.local_topo['dut1_addr_ipv6'],
                          config_type_list=["filter_list"], filter_list='FILTER6', diRection='out',cli_type=vtysh_cli_type)

        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    def test_default_originate_ipv6(self, bgp_ipvx_route_adv_filter_fixture):

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut1'], family='ipv6',
                                           match={'next_hop': self.local_topo['dut2_addr_ipv6']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut2_as']) in x['as_path']]
        list_of_learned_routes_on_dut1_by_dut2 = list(x['network'] for x in output)
        if '::/0' in list_of_learned_routes_on_dut1_by_dut2:
            st.log("route learnt")
        else:
            st.log("route not learnt")

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv6',
                          config='yes',
                          neighbor=self.local_topo['dut1_addr_ipv6'],
                          config_type_list=["default_originate"], routeMap='UseGlobal',cli_type=bgp_cli_type)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut1'], family='ipv6',
                                           match={'next_hop': self.local_topo['dut2_addr_ipv6']},
                                           select=['network', 'as_path'])

        output = [x for x in output if "{}".format(self.local_topo['dut2_as']) in x['as_path']]
        list_of_learned_routes_on_dut1_by_dut2 = list(x['network'] for x in output)
        if '::/0' in list_of_learned_routes_on_dut1_by_dut2:
            st.log("default route advertised")
            result = True
        else:
            st.log("default route not advertised")
            result = False

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv6',
                          config='no',
                          neighbor=self.local_topo['dut1_addr_ipv6'],
                          config_type_list=["default_originate"], routeMap='UseGlobal',cli_type=bgp_cli_type)

        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    @pytest.mark.community
    @pytest.mark.community_pass
    def test_route_map_in_ipv6(self, bgp_ipvx_route_adv_filter_fixture):

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv6',
                                           match={'next_hop': self.local_topo['dut1_addr_ipv6']},
                                           select=['network', 'local_pref', 'metric'])

        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv6',
                          config='yes',
                          neighbor=self.local_topo['dut1_addr_ipv6'],
                          config_type_list=["routeMap"], routeMap='SETPROPS6', diRection='in',cli_type=vtysh_cli_type)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv6',
                                           match={'next_hop': self.local_topo['dut1_addr_ipv6']},
                                           select=['network',  'local_pref', 'metric'])
        metric = bgplib.get_route_attribute(output, 'metric', network='102:1::/64')
        local_pref = bgplib.get_route_attribute(output, 'local_pref', network='101:1::/64')
        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'], addr_family='ipv6',
                          config='yes',
                          neighbor=self.local_topo['dut1_addr_ipv6'],
                          config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in',cli_type=vtysh_cli_type)

        if metric == '6400' and local_pref == '6200':
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    # testcase: FtOtSoRtBgp4Fn016, To verify functioning of route-map to filter incoming IPv4 prefix(s)
    # on community from dynamic neighbors
    @pytest.mark.bgp_rtmap_comm
    @pytest.mark.community
    @pytest.mark.community_pass
    def test_bgp_route_map_with_community(self, bgp_ipvx_route_adv_filter_fixture):
        result = True
        ipapi.config_route_map(dut=self.local_topo['dut2'], route_map='rmap1', config='yes',
                               sequence='10', community='100:100')
        ipapi.create_static_route(dut=self.local_topo['dut1'], next_hop='blackhole', static_ip='40.1.1.1/32')
        self.configure_base_for_filter_prefix_on_community('leaf_spine', 'yes')
        # Check the show command in leaf
        output = bgpapi.show_bgp_ipvx_prefix(self.local_topo['dut2'], prefix="40.1.1.1",
                                             masklen=32, family='ipv4')
        st.log(output)
        # there is only one record
        for x in output:  # type: basestring
            if ((x['peerip'].find('11.1.1.2')) != -1) and (x['community'] == '100:100'):
                result = True
            else:
                result = False
        self.configure_base_for_filter_prefix_on_community('leaf_spine', 'no')
        ipapi.config_route_map(dut=self.local_topo['dut2'], route_map='rmap1', config='no',
                               community='100:100')
        ipapi.delete_static_route(dut=self.local_topo['dut1'], next_hop='blackhole', static_ip='40.1.1.1/32')
        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    # testcase: FtOtSoRtBgp4Fn014, Verify that BGP peering with dynamic neighbors established with update source option.
    @pytest.mark.bgp_nbr_updsrc
    @pytest.mark.community
    @pytest.mark.community_pass
    def test_bgp_ebgp4_nbr_update_source(self, bgp_ipvx_route_adv_filter_fixture):
        result = True
        # configure update source for both the duts
        # Note: Currently, leaf spine topology has a fixed neighbor formation (peer-group leaf_spine and spine_leaf)
        # Since in sonic, we must have neighbor which is same as update-source, we will use this nbr as the source.
        # basically, we will use update-source on the same neighbor, which has been created using leaf spine topology.
        bgpapi.config_bgp(dut=self.local_topo['dut1'], local_as=self.local_topo['dut1_as'],
                          neighbor=self.local_topo['dut2_addr_ipv4'], config='yes',
                          update_src=self.local_topo['dut1_addr_ipv4'], config_type_list=["update_src"],cli_type=bgp_cli_type)
        bgpapi.config_bgp(dut=self.local_topo['dut1'], local_as=self.local_topo['dut1_as'],
                          neighbor=self.local_topo['dut2_addr_ipv4'], config='yes',
                          config_type_list=["ebgp_mhop"], ebgp_mhop='2',cli_type=bgp_cli_type)
        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'],
                          neighbor=self.local_topo['dut1_addr_ipv4'], config='yes',
                          update_src=self.local_topo['dut2_addr_ipv4'],
                          config_type_list=["update_src"],cli_type=bgp_cli_type)
        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'],
                          neighbor=self.local_topo['dut1_addr_ipv4'], config='yes',
                          config_type_list=["ebgp_mhop"], ebgp_mhop='2',cli_type=bgp_cli_type)
        # clear bgp neighbors before checking for neighbor state again.
        bgpapi.clear_ip_bgp_vtysh(dut=self.local_topo['dut1'], value="*")
        bgpapi.clear_ip_bgp_vtysh(dut=self.local_topo['dut2'], value="*")
        if not utils.poll_wait(bgpapi.verify_bgp_summary, 30, self.local_topo['dut1'], family='ipv4',
                               neighbor=self.local_topo['dut2_addr_ipv4'], state='Established'):
            bgplib.show_bgp_neighbors([self.local_topo['dut1'], self.local_topo['dut2']], af='ipv4')
            st.error("BGP Neighbor failed to Establish between DUT1 and DUT2")
            st.log("{} - Neighbor {} is failed to Establish".format(self.local_topo['dut1'],
                                                                    self.local_topo['dut2_addr_ipv4']))
            result = False

        # cleanup the testcase
        bgpapi.config_bgp(dut=self.local_topo['dut1'], local_as=self.local_topo['dut1_as'],
                          neighbor=self.local_topo['dut2_addr_ipv4'], config='no',
                          update_src=self.local_topo['dut1_addr_ipv4'],
                          config_type_list=["update_src"],cli_type=bgp_cli_type)
        bgpapi.config_bgp(dut=self.local_topo['dut1'], local_as=self.local_topo['dut1_as'],
                          neighbor=self.local_topo['dut2_addr_ipv4'], config='no',
                          config_type_list=["ebgp_mhop"], ebgp_mhop='2',cli_type=bgp_cli_type)
        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'],
                          neighbor=self.local_topo['dut1_addr_ipv4'], config='no',
                          update_src=self.local_topo['dut2_addr_ipv4'],
                          config_type_list=["update_src"],cli_type=bgp_cli_type)
        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'],
                          neighbor=self.local_topo['dut1_addr_ipv4'], config='no',
                          config_type_list=["ebgp_mhop"], ebgp_mhop='2',cli_type=bgp_cli_type)
        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    # testcase: FtOtSoRtBgp4Fn015, Verify eBGP authentication.
    @pytest.mark.bgp_nbr_auth
    def test_bgp_ebgp4_nbr_authentication(self, bgp_ipvx_route_adv_filter_fixture):
        result = True
        # configure password for both the duts
        bgpapi.config_bgp(dut=self.local_topo['dut1'], local_as=self.local_topo['dut1_as'],
                          neighbor=self.local_topo['dut2_addr_ipv4'], config='yes', password='broadcom',
                          config_type_list=["pswd"],cli_type=bgp_cli_type)
        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'],
                          neighbor=self.local_topo['dut1_addr_ipv4'], config='yes', password='broadcom',
                          config_type_list=["pswd"],cli_type=bgp_cli_type)

        # clear bgp neighbors before checking for neighbor state again.
        bgpapi.clear_ip_bgp_vtysh(dut=self.local_topo['dut1'], value="*")
        bgpapi.clear_ip_bgp_vtysh(dut=self.local_topo['dut2'], value="*")

        if not utils.poll_wait(bgpapi.verify_bgp_summary, 30, self.local_topo['dut1'], family='ipv4',
                               neighbor=self.local_topo['dut2_addr_ipv4'], state='Established'):
            bgplib.show_bgp_neighbors([self.local_topo['dut1'], self.local_topo['dut2']], af='ipv4')
            st.error("BGP Neighbor failed to Establish between DUT1 and DUT2")
            st.log("{} - Neighbor {} is failed to Establish".format(self.local_topo['dut1'],
                                                                    self.local_topo['dut2_addr_ipv4']))
            result = False
        # Verify neighbors formation after rebooting Dut1
        st.log("Verification of neighbor formation after reboot.")
        # below API will change routing mode to split and save the sonic config.
        bgpapi.enable_docker_routing_config_mode(dut=self.local_topo['dut1'])
        st.vtysh(self.local_topo['dut1'], "copy running-config startup-config")
        st.reboot(self.local_topo['dut1'], 'fast')
        st.wait(3)
        if not utils.poll_wait(bgpapi.verify_bgp_summary, 30, self.local_topo['dut1'], family='ipv4',
                               neighbor=self.local_topo['dut2_addr_ipv4'], state='Established'):
            bgplib.show_bgp_neighbors([self.local_topo['dut1'], self.local_topo['dut2']], af='ipv4')
            st.error("BGP Neighbor failed to Establish between DUT1 and DUT2")
            st.log("{} - Neighbor {} is failed to Establish".format(self.local_topo['dut1'],
                                                                    self.local_topo['dut2_addr_ipv4']))
            result = False
        # cleanup the testcase
        bgpapi.config_bgp(dut=self.local_topo['dut1'], local_as=self.local_topo['dut1_as'],
                          neighbor=self.local_topo['dut2_addr_ipv4'], config='no', password='broadcom',
                          config_type_list=["pswd"],cli_type=bgp_cli_type)
        bgpapi.config_bgp(dut=self.local_topo['dut2'], local_as=self.local_topo['dut2_as'],
                          neighbor=self.local_topo['dut1_addr_ipv4'], config='no', password='broadcom',
                          config_type_list=["pswd"],cli_type=bgp_cli_type)
        if result:
            st.report_pass("operation_successful")
        else:
            st.report_fail("operation_failed")

    # testcase: FtOtSoRtBgp4Fn015, Verify eBGP traffic for ipv6.
    @pytest.mark.bgp_ebgp6_traffic
    def test_bgp_ebgp6_traffic(self, bgp_ipvx_route_adv_filter_fixture):
        result = True
        TG_D1 = topo.tg_dut_list_name[0]
        TG_D2 = topo.tg_dut_list_name[1]
        tg_ob = topo['T1{}P1_tg_obj'.format(TG_D1)]
        bgp_handle = topo['T1{}P1_ipv6_tg_bh'.format(TG_D1)]
        tg_d1_ip = topo['T1{}P1_ipv6'.format(TG_D1)]
        tg_d2_ip = topo['T1{}P1_ipv6'.format(TG_D2)]
        tc_fail_flag = 0
        spine_as = int(bgplib.data['spine_as'])
        st.log("Advertising 500 IPv6 Routes from TG connected to DUT1")
        bgp_route = tg_ob.tg_emulation_bgp_route_config(handle=bgp_handle['handle'], mode='add', ip_version='6',
                                                        num_routes='500', prefix='1001::1', as_path='as_seq:1')
        bgp_ctrl = tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='start')
        # Sleep for update delay timer and the check the route count in neighbour
        st.wait(15)
        if not utils.poll_wait(bgpapi.verify_bgp_neighborship, 120, topo.dut_list[0], family="ipv6", shell="sonic",
                        neighbor=self.local_topo['dut2_addr_ipv6'], state='Established', asn=self.local_topo['dut1_as']):
            utils.exec_all(True, [[bgpapi.show_bgp_ipv6_neighbor_vtysh, topo.dut_list[0]],
                                  [bgpapi.show_bgp_ipv6_neighbor_vtysh, topo.dut_list[1]]])
            st.error("BGP Neighbor failed to Establish between DUT1 and TG")
            st.log("{} - Neighbor {} is failed to Establish".format(topo.dut_list[0],
                                                                    self.local_topo['dut2_addr_ipv6']))
            result = False
        bgp_summary_spine_after_update_timer = bgpapi.show_bgp_ipv6_summary(topo.dut_list[1])
        rib_entries_after_update_timer = bgp_summary_spine_after_update_timer[0]['ribentries']
        st.log('RIB Entries after update delay timer expiry : {}'.format(rib_entries_after_update_timer))
        if int(rib_entries_after_update_timer) < 500:
            st.error('Routes are not advertised to peer DUT, even after the update delay timer expiry')
            tc_fail_flag = 1
        st.log("Initiating the Ipv6 traffic for those Routes from TG connected to DUT2")
        src_handle = 'handle'
        if tg_ob.tg_type == 'ixia':
            src_handle = 'ipv6_handle'
        tr1 = tg_ob.tg_traffic_config(port_handle=topo['T1{}P1_ipv6_tg_ph'.format(TG_D2)],
                                      emulation_src_handle=topo['T1{}P1_ipv6_tg_ih'.format(TG_D2)][src_handle],
                                      emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type='ipv6',
                                      mode='create',
                                      transmit_mode='single_burst', pkts_per_burst='2000', length_mode='fixed',
                                      rate_pps=1000)
        stream_id1 = tr1['stream_id']
        tg_ob.tg_traffic_control(action='run', handle=stream_id1)
        st.wait(20)
        tg1_stats = tgapi.get_traffic_stats(tg_ob, port_handle=topo["T1{}P1_ipv6_tg_ph".format(TG_D1)])
        tg2_stats = tgapi.get_traffic_stats(tg_ob, port_handle=topo["T1{}P1_ipv6_tg_ph".format(TG_D2)])
        if not (int(tg2_stats.tx.total_packets) and int(tg1_stats.rx.total_packets)):
            st.error('Received ZERO stats.')
            tc_fail_flag = 1
        else:
            percent_rx = float(int(tg1_stats.rx.total_packets) - int(tg2_stats.tx.total_packets)) / int(
                tg2_stats.tx.total_packets) * 100
            st.log('tg1_stats.rx.total_packets : {}'.format(tg1_stats.rx.total_packets))
            st.log('tg2_stats.tx.total_packets : {}'.format(tg2_stats.tx.total_packets))
            st.log('percent_rx : {}'.format(percent_rx))
            if int(tg1_stats.rx.total_packets) < int(tg2_stats.tx.total_packets)*0.95:
                tc_fail_flag = 1
        tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='stop')
        if tc_fail_flag:
            st.report_fail("traffic_verification_failed")
        st.report_pass('test_case_passed')

        TG_D1 = topo.tg_dut_list_name[0]
        TG_D2 = topo.tg_dut_list_name[1]
        tg_ob = topo['T1{}P1_tg_obj'.format(TG_D2)]
        bgp_handle = topo['T1{}P1_ipv6_tg_bh'.format(TG_D2)]
        tc_fail_flag = 0
        leaf_as = int(bgplib.data['leaf_as'])
        st.log("Advertising 500 IPv6 Routes from TG connected to DUT2")
        bgp_route = tg_ob.tg_emulation_bgp_route_config(handle=bgp_handle['handle'], mode='add', ip_version='6',
                                                        num_routes='500', prefix='1002::1', as_path='as_seq:2')
        bgp_ctrl = tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='start')
        # Check for route count in neighbour, before update delay timer expiry
        # Sleep for update delay timer and the check the route count in neighbour
        st.wait(15)
        if not utils.poll_wait(bgpapi.verify_bgp_neighborship, 120, topo.dut_list[0], family="ipv6", shell="sonic",
                               neighbor=self.local_topo['dut2_addr_ipv6'], state='Established',
                               asn=self.local_topo['dut1_as']):
            utils.exec_all(True, [[bgpapi.show_bgp_ipv6_neighbor_vtysh, topo.dut_list[0]],
                                  [bgpapi.show_bgp_ipv6_neighbor_vtysh, topo.dut_list[1]]])
            st.error("BGP Neighbor failed to Establish between DUT1 and TG")
            st.log("{} - Neighbor {} is failed to Establish".format(topo.dut_list[0],
                                                                    self.local_topo['dut2_addr_ipv6']))
            result = False
        bgp_summary_spine_after_update_timer = bgpapi.show_bgp_ipv6_summary(topo.dut_list[0])
        rib_entries_after_update_timer = bgp_summary_spine_after_update_timer[0]['ribentries']
        st.log('RIB Entries after update delay timer expiry : {}'.format(rib_entries_after_update_timer))
        if int(rib_entries_after_update_timer) < 1000:
            st.error('Routes are not advertised to peer DUT, even after the update delay timer expiry')
            tc_fail_flag = 1
        st.log("Initiating the Ipv6 traffic for those Routes from TG connected to DUT1")
        src_handle = 'handle'
        if tg_ob.tg_type == 'ixia':
            src_handle = 'ipv6_handle'
        tr1 = tg_ob.tg_traffic_config(port_handle=topo['T1{}P1_ipv6_tg_ph'.format(TG_D1)],
                                      emulation_src_handle=topo['T1{}P1_ipv6_tg_ih'.format(TG_D1)][src_handle],
                                      emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type='ipv6',
                                      mode='create',
                                      transmit_mode='single_burst', pkts_per_burst='2000', length_mode='fixed',
                                      rate_pps=1000)
        stream_id1 = tr1['stream_id']
        tg_ob.tg_traffic_control(action='run', handle=stream_id1)
        st.wait(20)
        tg1_stats = tgapi.get_traffic_stats(tg_ob, port_handle=topo["T1{}P1_ipv6_tg_ph".format(TG_D2)])
        tg2_stats = tgapi.get_traffic_stats(tg_ob, port_handle=topo["T1{}P1_ipv6_tg_ph".format(TG_D1)])
        if not (int(tg2_stats.tx.total_packets) and int(tg1_stats.rx.total_packets)):
            st.error('Received ZERO stats.')
            tc_fail_flag = 1
        else:
            percent_rx = float(int(tg1_stats.rx.total_packets) - int(tg2_stats.tx.total_packets)) / int(
                tg2_stats.tx.total_packets) * 100
            st.log('tg1_stats.rx.total_packets : {}'.format(tg1_stats.rx.total_packets))
            st.log('tg2_stats.tx.total_packets : {}'.format(tg2_stats.tx.total_packets))
            st.log('percent_rx : {}'.format(percent_rx))
            if int(tg1_stats.rx.total_packets) < int(tg2_stats.tx.total_packets)*0.95:
                tc_fail_flag = 1
        tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='stop')
        if tc_fail_flag:
            st.report_fail("traffic_verification_failed")
        st.report_pass('test_case_passed')
        # below API will change routing mode to split and save the sonic config.
        bgpapi.enable_docker_routing_config_mode(dut=topo.dut_list[0])
        st.vtysh(topo.dut_list[0], "copy running-config startup-config")
        st.reboot(topo.dut_list[0], 'fast')
        st.wait(3)
        if not utils.poll_wait(bgpapi.verify_ipv6_bgp_summary, 120, topo.dut_list[0],
                               neighbor=self.local_topo['dut2_addr_ipv6'], state='500'):
            utils.exec_all(True, [[bgpapi.show_bgp_ipv6_neighbor_vtysh, topo.dut_list[0]],
                                  [bgpapi.show_bgp_ipv6_neighbor_vtysh, topo.dut_list[1]]])
            st.error("BGP Neighbor failed to Establish between DUT1 and DUT2")
            st.log("{} - Neighbor {} is failed to Establish".format(topo.dut_list[0],
                                                                    self.local_topo['dut2_addr_ipv6']))
            result = False
        bgp_summary_spine_after_update_timer = bgpapi.show_bgp_ipv6_summary(topo.dut_list[0])
        rib_entries_after_update_timer = bgp_summary_spine_after_update_timer[0]['ribentries']
        st.log('RIB Entries after reboot : {}'.format(rib_entries_after_update_timer))
        # without BGP helper, after reboot, no routes sent by DUT2 will be seen in dut1.
        if int(rib_entries_after_update_timer) < 500:
            st.error('Routes are not advertised to peer DUT, even after the update delay timer expiry')
            tc_fail_flag = 1
        if tc_fail_flag:
            st.report_fail("traffic_verification_failed")
        st.report_pass('test_case_passed')

    # testcase: FtOtSoRtBgpPlFn002, Verify ipv6 route aggregation.
    def test_route_aggregate_ipv6(self, bgp_ipvx_route_adv_filter_fixture):
        limit = 3
        ip6_rt_list = ["2018:3:1::/64", "2018:3:2::/64", "2018:3:3::/64", "2018:3:4::/64"]
        ip6_adr_list = ["2019:1::1", "2019:2::1", "2019:3::1", "2019:4::1"]
        aggr_addr = "2018:3::/32"

        for i in range(0, limit):
            ipapi.create_static_route(self.local_topo['dut1'], 'blackhole', ip6_rt_list[i], family='ipv6')

        # configure aggregate address prefix
        bgpapi.create_bgp_aggregate_address(self.local_topo['dut1'], local_asn=self.local_topo['dut1_as'],
                                            address_range=aggr_addr, summary=True, family="ipv6", config="add",cli_type=bgp_cli_type)

        my_cmd = 'router bgp\n'
        my_cmd += 'address-family ipv6 unicast\n'
        my_cmd += 'redistribute static\n'
        my_cmd += 'end'
        st.vtysh_config(self.local_topo['dut1'], my_cmd)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut1'], family='ipv6')
        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv6',
                                           select=['network', 'as_path', 'next_hop'])

        list_of_learned_routes_on_dut2_by_dut = list(x['network'] for x in output)

        if set(ip6_rt_list).isdisjoint(set(list_of_learned_routes_on_dut2_by_dut)):
            st.log("Routes falling under aggregate prefix are not distributed")
            aggregation = True
        else:
            st.log("Routes falling under aggregate prefix are distributed")
            aggregation = False

        if (aggr_addr in list_of_learned_routes_on_dut2_by_dut) and aggregation:
            st.log("Aggregation happened")
            result = True
        else:
            st.log("Aggregation not happened")
            result = False

        bgpapi.create_bgp_aggregate_address(self.local_topo['dut1'], local_asn=self.local_topo['dut1_as'],
                                            address_range=aggr_addr, summary=True, family="ipv6", config="delete",cli_type=bgp_cli_type)

        for i in range(0, limit):
            ipapi.delete_static_route(self.local_topo['dut1'], 'blackhole', ip6_rt_list[i], family='ipv6')

        my_cmd = 'router bgp\n'
        my_cmd += 'address-family ipv6 unicast\n'
        my_cmd += 'no redistribute static\n'
        my_cmd += 'end'
        st.vtysh_config(self.local_topo['dut1'], my_cmd)

        if result:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

    # testcase: FtOtSoRtBgpPlFn005, verify static blackhole route redistribution with metric set in route-map
    def test_static_blackhole_rt_redistribute_with_routemap_ipv6(self, bgp_ipvx_route_adv_filter_fixture):
        ipapi.create_static_route(self.local_topo['dut1'], 'Null0', '2012:1::/64', family='ipv6')
        ipapi.config_route_map(dut=self.local_topo['dut1'], route_map='rmap_blackhole', config='yes', sequence='10',
                               metric='50')
        my_cmd = 'router bgp\n'
        my_cmd += 'address-family ipv6 unicast\n'
        my_cmd += 'redistribute static route-map rmap_blackhole\n'
        my_cmd += 'end'
        st.vtysh_config(self.local_topo['dut1'], my_cmd)

        output = bgpapi.fetch_ip_bgp_route(self.local_topo['dut2'], family='ipv6',
                                           select=['network', 'as_path', 'metric'])

        metric = bgplib.get_route_attribute(output, 'metric', network = '2012:1::/64')
        if metric == '50':
            st.log('static blackhole route with metric 50 redistributed from dut1 to dut2')
            result = True
        else:
            st.log('static blackhole route is not learned on dut2')
            result = False

        my_cmd = 'router bgp\n'
        my_cmd += 'address-family ipv6 unicast\n'
        my_cmd += 'no redistribute static route-map rmap_blackhole\n'
        my_cmd += 'end'
        st.vtysh_config(self.local_topo['dut1'], my_cmd)

        ipapi.config_route_map(dut=self.local_topo['dut1'], route_map='rmap_blackhole', config='no', sequence='10', metric='50')
        ipapi.delete_static_route(self.local_topo['dut1'], 'Null0', '2012:1::/64', family='ipv6')

        if result:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")


"""
BGP IPv4 and IPv6 router distribution and filtering TCs: End

"""


"""
BGP Neighbor over VE over LAG fixture, class and test cases  - START

"""


def bgp_ve_lag_pre_config():
    global topo
    st.banner("BGP VE LAG CLASS CONFIG - START")

    # underlay config - configure ve over lag
    bgplib.l3tc_underlay_config_unconfig(config='yes', config_type='veLag')

    # config ip on underlay interface
    bgplib.l3tc_vrfipv4v6_address_leafspine_config_unconfig(config='yes', config_type='all')

    # Ping Verification
    if not bgplib.l3tc_vrfipv4v6_address_leafspine_ping_test(config_type='all', ping_count=3):
        st.error("Ping failed in between Spine - Leaf")
        st.report_fail('test_case_failed')
    bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_config(config='yes')

    bgplib.l3tc_vrfipv4v6_address_leafspine_tg_bgp_config(config='yes', config_type='all', class_reconfig='Yes')
    st.wait(10)

    # BGP Neighbour Verification
    if not utils.poll_wait(bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_check, 10, config_type='all'):
        st.error("Neighbour is failed to Establish between Spine - Leaf")
        st.report_fail('test_case_failed')

    st.log("Getting all topology info related to connectivity / TG and other parameters between duts")
    topo = bgplib.get_leaf_spine_topology_info()
    st.banner("BGP VE LAG CLASS CONFIG - END")


def bgp_ve_lag_pre_config_cleanup():
    st.banner("BGP VE LAG CLASS CONFIG CLEANUP - START")
    bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_config(config='no', config_type='veLag')
    bgplib.l3tc_vrfipv4v6_address_leafspine_config_unconfig(config='no')
    bgplib.l3tc_underlay_config_unconfig(config='no', config_type='veLag')
    st.banner("BGP VE LAG CLASS CONFIG CLEANUP - END")


@pytest.fixture(scope='class')
def bgp_ve_lag_class_hook(request):
    bgp_ve_lag_pre_config()
    yield
    bgp_ve_lag_pre_config_cleanup()


# TestBGPVeLag Class
@pytest.mark.usefixtures('bgp_ve_lag_class_hook')
class TestBGPVeLag(TestBGPCommon):

    # test v4 and v6 neighbors
    @pytest.mark.bgp_clear
    @pytest.mark.bgp_ft
    # tests both v4 and v6 neighbors
    def test_ft_bgp_clear(self):
        TestBGPCommon.ft_bgp_clear(self)
        # tests both v4 and v6 neighbors

    @pytest.mark.bgp_traffic
    @pytest.mark.bgp_ft
    def test_ft_bgp_peer_traffic_check(self):
        TestBGPCommon.ft_bgp_peer_traffic_check(self)


"""
BGP Neighbor over VE over LAG fixture, class and test cases  - END
"""


"""
BGP Neighbor over L3 over LAG fixture, class and test cases  - START
"""


def bgp_l3_lag_pre_config():
    global topo
    st.banner("BGP L3 OVER LAG CLASS CONFIG - START")

    # underlay config - configure ve over lag
    bgplib.l3tc_underlay_config_unconfig(config='yes', config_type='l3Lag')

    # config ip on underlay interface
    bgplib.l3tc_vrfipv4v6_address_leafspine_config_unconfig(config='yes', config_type='all')

    # Ping Verification
    if not bgplib.l3tc_vrfipv4v6_address_leafspine_ping_test(config_type='all', ping_count=3):
        st.error("Ping failed in between Spine - Leaf")
        st.report_fail('test_case_failed')
    bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_config(config='yes')

    bgplib.l3tc_vrfipv4v6_address_leafspine_tg_bgp_config(config='yes', config_type='all', class_reconfig='Yes')
    st.wait(10)

    # BGP Neighbour Verification
    if not utils.poll_wait(bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_check, 10, config_type='all'):
        st.error("Neighbour is failed to Establish between Spine - Leaf")
        st.report_fail('test_case_failed')
    st.log("Getting all topology info related to connectivity / TG and other parameters between duts")
    topo = bgplib.get_leaf_spine_topology_info()

    st.banner("BGP L3 LAG CLASS CONFIG - END")


def bgp_l3_lag_pre_config_cleanup():
    st.banner("BGP L3 OVER LAG CLASS CONFIG CLEANUP - START")
    bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_config(config='no')
    bgplib.l3tc_vrfipv4v6_address_leafspine_config_unconfig(config='no')
    bgpapi.cleanup_bgp_config(st.get_dut_names())
    ipapi.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    bgplib.l3tc_underlay_config_unconfig(config='no', config_type='l3Lag')
    st.banner("BGP L3 OVER LAG CLASS CONFIG CLEANUP - END")


@pytest.fixture(scope='class')
def bgp_l3_lag_class_hook(request):
    bgp_l3_lag_pre_config()
    yield
    bgp_l3_lag_pre_config_cleanup()

# TestBGPVeLag Class
@pytest.mark.usefixtures('bgp_l3_lag_class_hook')
class TestBGPL3Lag(TestBGPCommon):
    @pytest.mark.bgp_l3lag_traffic
    def test_ft_bgp_l3lag_peer_traffic_check(self):
        TestBGPCommon.ft_bgp_peer_traffic_check(self)


"""
BGP Neighbor In L3 Over LAG fixture, class and test cases  - END
"""

