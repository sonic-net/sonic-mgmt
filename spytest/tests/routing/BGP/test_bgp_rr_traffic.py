import pytest

from spytest import st, tgapi
from spytest.utils import poll_wait

import apis.routing.ip as ipapi
import apis.routing.bgp as bgpapi
import BGP.bgplib as bgplib


@pytest.fixture(scope="module", autouse=True)
def bgp_module_hooks(request):
    global bgp_cli_type
    st.ensure_min_topology('D1D2:1', 'D1T1:1', 'D2T1:1')
    bgp_cli_type = st.get_ui_type()
    if bgp_cli_type == 'click':
        bgp_cli_type = 'vtysh'
    bgplib.init_resource_data(st.get_testbed_vars())
    bgp_pre_config()
    yield
    bgp_pre_config_cleanup()


# bgp module level pre config function
def bgp_pre_config():
    global topo
    st.banner("BGP MODULE CONFIG - START")
    # loopback config
    bgplib.l3tc_vrfipv4v6_address_leafspine_loopback_config_unconfig(config='yes', config_type='all')
    # TG Configuration
    bgplib.l3tc_vrfipv4v6_address_leafspine_tg_config_unconfig(config='yes', config_type='all')
    st.banner("BGP MODULE CONFIG - END")

# bgp module level pre config cleanup function
def bgp_pre_config_cleanup():
    st.banner("BGP MODULE CONFIG CLEANUP - START")

    # loopback unconfig
    bgplib.l3tc_vrfipv4v6_address_leafspine_loopback_config_unconfig(config='no')

    # TG  uconfiguration
    bgplib.l3tc_vrfipv4v6_address_leafspine_tg_config_unconfig(config='no')

    st.banner("BGP MODULE CONFIG CLEANUP - END")

@pytest.fixture(scope="function")
def bgp_func_hooks(request):
    yield



################################################################################
# BGP Route Reflector with traffic fixture, class and test cases  - START
def bgp_rr_traffic_pre_config():
    global topo
    st.banner("BGP RR WITH TRAFFIC CLASS CONFIG - START")

    # underlay config - configure physical interfaces
    bgplib.l3tc_underlay_config_unconfig(config='yes')

    # config ip on underlay interface
    bgplib.l3tc_vrfipv4v6_address_leafspine_config_unconfig(config='yes', config_type='all')

    # Ping Verification
    if not bgplib.l3tc_vrfipv4v6_address_leafspine_ping_test(config_type='all', ping_count=3):
        st.error("Ping failed in between Spine - Leaf")
        st.report_fail('test_case_failed')

    bgplib.l3tc_vrfipv4v6_address_leafspine_rr_tg_bgp_config(config='yes', rr_enable='true')
    bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_config(config='yes', rr_enable='true')
    # BGP Neighbor Verification
    if not poll_wait(bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_check, 10, config_type='all'):
        st.error("Neighbour is failed to Establish between Spine - Leaf")
        st.report_fail('test_case_failed')

    st.log("Getting all topology info related to connectivity / TG and other parameters between duts")
    topo = bgplib.get_leaf_spine_topology_info()
    st.banner("BGP RR WITH TRAFFIC CLASS CONFIG - END")


def bgp_rr_traffic_pre_config_cleanup():
    st.banner("BGP RR WITH TRAFFIC CLASS CONFIG CLEANUP - START")
    bgplib.l3tc_vrfipv4v6_address_leafspine_bgp_config(config='no', rr_enable='true')
    bgplib.l3tc_vrfipv4v6_address_leafspine_config_unconfig(config='no')
    bgpapi.cleanup_router_bgp(st.get_dut_names())
    ipapi.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    bgplib.l3tc_underlay_config_unconfig(config='no')
    bgplib.l3tc_vrfipv4v6_address_leafspine_rr_tg_bgp_config(config='no', rr_enable='true')
    st.banner("BGP RR WITH TRAFFIC CLASS CONFIG CLEANUP - END")


@pytest.fixture(scope='class')
def bgp_rr_traffic_class_hook(request):
    bgp_rr_traffic_pre_config()
    yield
    bgp_rr_traffic_pre_config_cleanup()


# Route Reflector with traffic Class
@pytest.mark.usefixtures('bgp_rr_traffic_class_hook')
class TestBGPRrTraffic():

    @pytest.mark.bgp_rr_traffic
    def test_ft_bgp_rr_traffic_check(self):
        TG_D1 = topo.tg_dut_list_name[0]
        TG_D2 = topo.tg_dut_list_name[1]
        tg_ob = topo['T1{}P1_tg_obj'.format(TG_D1)]
        bgp_handle = topo['T1{}P1_ipv4_tg_bh'.format(TG_D1)]
        tc_fail_flag = 0
        spine_as = int(bgplib.data['spine_as'])
        tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='stop')
        st.wait(10)
        st.log("Advertising Routes from one of the Leaf Router")
        bgp_route = tg_ob.tg_emulation_bgp_route_config(handle=bgp_handle['handle'], mode='add', num_routes='100',
                                                        prefix='121.1.1.0', as_path='as_seq:1')
        tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='start')

        # Sleep for some time and the check the route count in neighbour
        st.wait(10)
        bgp_summary = bgpapi.show_bgp_ipv4_summary(topo.dut_list[1])
        rib_entries = bgp_summary[0]['ribentries']
        st.log('RIB Entries : {}'.format(rib_entries))
        # when route-reflector is not configured at server(spine), we should not learn anything at
        # route-reflector-client (leaf node), ideally, route count should be 0.
        if int(rib_entries) > 10:
            st.error('iBGP Routes are advertised to iBGP peer DUT, even when route-reflector-client is not configured')
            tc_fail_flag = 1
        # now configure route-reflector-client at spine node
        result = bgpapi.create_bgp_route_reflector_client(topo.dut_list[0], spine_as, 'ipv4', 'spine_leaf', 'yes')
        if not result:
            st.log("Configuring client reflection on {} {} bgp {} Failed".format(topo.dut_list[0], 'ipv4', spine_as))
            tc_fail_flag = 1
        bgpapi.create_bgp_next_hop_self(topo.dut_list[0], spine_as, 'ipv4', 'spine_leaf', 'yes', 'yes',cli_type=bgp_cli_type)
        st.wait(15)
        bgp_summary = bgpapi.show_bgp_ipv4_summary(topo.dut_list[1])
        rib_entries = bgp_summary[0]['ribentries']
        st.log('RIB Entries : {}'.format(rib_entries))
        if int(rib_entries) < 100:
            st.error('iBGP Routes are not advertised to route-reflector-client')
            tc_fail_flag = 1

        st.log("Initiating the Ipv4 traffic for those Routes from another Leaf Router")
        tr1 = tg_ob.tg_traffic_config(port_handle=topo['T1{}P1_ipv4_tg_ph'.format(TG_D2)],
                                      emulation_src_handle=topo['T1{}P1_ipv4_tg_ih'.format(TG_D2)]['handle'],
                                      emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type='ipv4',
                                      mode='create',
                                      transmit_mode='single_burst', pkts_per_burst='2000', length_mode='fixed',
                                      rate_pps=1000)
        stream_id1 = tr1['stream_id']
        tg_ob.tg_traffic_control(action='run', handle=stream_id1)
        st.tg_wait(20)
        tg1_stats = tgapi.get_traffic_stats(tg_ob, port_handle=topo["T1{}P1_ipv4_tg_ph".format(TG_D1)])
        tg2_stats = tgapi.get_traffic_stats(tg_ob, port_handle=topo["T1{}P1_ipv4_tg_ph".format(TG_D2)])
        if not (int(tg2_stats.tx.total_packets) and int(tg1_stats.rx.total_packets)):
            st.error('Received ZERO stats.')
            tc_fail_flag = 1
        else:
            percent_rx = float(int(tg1_stats.rx.total_packets) - int(tg2_stats.tx.total_packets)) / int(
                tg2_stats.tx.total_packets) * 100
            st.log('tg1_stats.rx.total_packets : {}'.format(tg1_stats.rx.total_packets))
            st.log('tg2_stats.tx.total_packets : {}'.format(tg2_stats.tx.total_packets))
            st.log('percent_rx : {}'.format(percent_rx))
            if percent_rx > 0.5:
                tc_fail_flag = 1
        tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='stop')
        if tc_fail_flag:
            st.report_fail("traffic_verification_failed")
        st.report_pass('test_case_passed')

    @pytest.mark.bgp6_rr_traffic
    def test_ft_bgp6_rr_traffic_check(self):
        TG_D1 = topo.tg_dut_list_name[0]
        TG_D2 = topo.tg_dut_list_name[1]
        tg_ob = topo['T1{}P1_tg_obj'.format(TG_D1)]
        bgp_handle = topo['T1{}P1_ipv6_tg_bh'.format(TG_D1)]
        tc_fail_flag = 0
        spine_as = int(bgplib.data['spine_as'])
        st.log("Advertising Routes from one of the Leaf Router")
        bgp_route = tg_ob.tg_emulation_bgp_route_config(handle=bgp_handle['handle'], mode='add',  ip_version='6',
                                                        num_routes='100',
                                                        prefix='1001::1', as_path='as_seq:1')
        tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='start')

        # Sleep for some time and the check the route count in neighbour
        st.wait(10)
        bgp_summary = bgpapi.show_bgp_ipv6_summary(topo.dut_list[1])
        rib_entries = bgp_summary[0]['ribentries']
        st.log('RIB Entries : {}'.format(rib_entries))
        # when route-reflector is not configured at server(spine), we should not learn anything at
        # route-reflector-client (leaf node), ideally, route count should be 0.
        if int(rib_entries) > 10:
            st.error('iBGP Routes are advertised to iBGP peer DUT, even when route-reflector-client is not configured')
            tc_fail_flag = 1
        # now configure route-reflector-client at spine node
        result = bgpapi.create_bgp_route_reflector_client(topo.dut_list[0], spine_as, 'ipv6', 'spine_leaf6', 'yes')
        if not result:
            st.log("Configuring client reflection on {} {} bgp {} Failed".format(topo.dut_list[0], 'ipv6', spine_as))
            tc_fail_flag = 1
        bgpapi.create_bgp_next_hop_self(topo.dut_list[0], spine_as, 'ipv6', 'spine_leaf6', 'yes', 'yes',cli_type=bgp_cli_type)
        st.wait(15)
        bgp_summary = bgpapi.show_bgp_ipv6_summary(topo.dut_list[1])
        rib_entries = bgp_summary[0]['ribentries']
        st.log('RIB Entries : {}'.format(rib_entries))
        if int(rib_entries) < 100:
            st.error('iBGP Routes are not advertised to route-reflector-client')
            tc_fail_flag = 1

        st.log("Initiating the Ipv6 traffic for those Routes from another Leaf Router")
        tr1 = tg_ob.tg_traffic_config(port_handle=topo['T1{}P1_ipv6_tg_ph'.format(TG_D2)],
                                      emulation_src_handle=topo['T1{}P1_ipv6_tg_ih'.format(TG_D2)]['handle'],
                                      emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type='ipv6',
                                      mode='create',
                                      transmit_mode='single_burst', pkts_per_burst='2000', length_mode='fixed',
                                      rate_pps=1000)
        stream_id1 = tr1['stream_id']
        tg_ob.tg_traffic_control(action='run', handle=stream_id1)
        st.tg_wait(20)
        tg1_stats = tgapi.get_traffic_stats(tg_ob, port_handle=topo["T1{}P1_ipv6_tg_ph".format(TG_D1)])
        tg2_stats = tgapi.get_traffic_stats(tg_ob, port_handle=topo["T1{}P1_ipv6_tg_ph".format(TG_D2)])
        if not (int(tg2_stats.tx.total_packets) and int(tg1_stats.rx.total_packets)):
            st.error('Received ZERO stats.')
            tc_fail_flag = 1
        else:
            percent_rx = float(int(tg2_stats.tx.total_packets) - int(tg1_stats.rx.total_packets)) / int(
                tg2_stats.tx.total_packets) * 100
            st.log('tg1_stats.rx.total_packets : {}'.format(tg1_stats.rx.total_packets))
            st.log('tg2_stats.tx.total_packets : {}'.format(tg2_stats.tx.total_packets))
            st.log('percent_rx : {}'.format(percent_rx))
            if percent_rx > 0.5:
                tc_fail_flag = 1
        tg_ob.tg_emulation_bgp_control(handle=bgp_handle['handle'], mode='stop')
        if tc_fail_flag:
            st.report_fail("traffic_verification_failed")
        st.report_pass('test_case_passed')


    # BGP Neighbor In L3 Over LAG fixture, class and test cases  - END
################################################################################
