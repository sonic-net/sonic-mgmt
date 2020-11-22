import pytest
from spytest import st, utils
from spytest.dicts import SpyTestDict
import apis.routing.ip as ip_obj
import apis.routing.arp as arp_obj
import apis.routing.bgp as bgp_obj
import apis.system.reboot as reboot_obj
from spytest.utils import random_vlan_list
import apis.switching.vlan as vlan_obj
import apis.routing.bfd as bfd_obj
import apis.switching.portchannel as pc_obj
import apis.system.interface as intf_obj
import apis.system.basic as basic_obj
import apis.system.switch_configuration as sc_obj
from utilities import parallel
import utilities.utils as utils_obj
import apis.routing.vrf as vrf_api
from spytest.tgen.tg import tgen_obj_dict
from spytest.tgen.tgen_utils import validate_tgen_traffic

dut = dict()



def bgp_unnum_initialize_variables():
    global data
    data = SpyTestDict()
    data.shell_sonic = "sonic"
    data.shell_vtysh = "vtysh"
    data.vlan_li = random_vlan_list(2)
    data.vlan_in_1 = "Vlan{}".format(str(data.vlan_li[0]))
    data.vlan_in_2 = "Vlan{}".format(str(data.vlan_li[1]))
    data.d1_ip6_adr1_l = ["2231:1:23::48", "5512::4", "7E31:21::48", "4141:1::2"]
    data.d2_ip6_adr1_l = ["2231:1:23::49", "5512::5", "7E31:21::49", "4141:1::23"]
    data.d1d2_ip6_adr1_mask_l = ["78", "96", "64", "88"]
    data.d1d2_ip6_adr1_rt = ["2231:1:23::", "5512::", "7E31:21::", "4141:1::"]
    data.ip6_addr_manual_ll = ["FE80:0:0:0:201:5FF:FE00:500", "FE80:0:0:0:204:5FF:FE00:500",
                               "FE80:0:0:0:210:5FF:FE00:500"]
    data.tg_ip4_addr_l = ["23.1.0.1", "55.1.1.1"]
    data.tgd_ip4_addr_l = ["23.1.0.2", "55.1.1.2"]
    data.tg_ip4_addr_mask_l = ["24", "24"]
    data.tg_ip4_addr_rt_l = ["23.1.0.0", "55.1.1.0"]
    data.tg_ip6_addr_l = ["33f1::1", "8911:1::12"]
    data.tgd_ip6_addr_l = ["33f1::2", "8911:1::13"]
    data.tg_ip6_addr_mask_l = ["64", "64"]
    data.tg_ip6_addr_rt_l = ["33f1::", "8911:1::"]
    data.d1_local_as = "10012"
    data.d2_local_as = "20012"
    data.d1_rid = "100.0.1.2"
    data.d2_rid = "200.0.1.2"
    data.wait = 10
    data.vrf_name = 'Vrf-102'
    data.portchannel_name = "PortChannel9"
    data.wait_timer = 120 if not st.is_dry_run() else 1


def get_handles():
    tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    tg_ph_1 = tg1.get_port_handle(vars.T1D1P1)
    tg_ph_2 = tg2.get_port_handle(vars.T1D2P1)
    tg1.tg_traffic_control(action="reset", port_handle=tg_ph_1)
    tg2.tg_traffic_control(action="reset", port_handle=tg_ph_2)
    return (tg1, tg2, tg_ph_1, tg_ph_2)


@pytest.fixture(scope="module", autouse=True)
def bgp_unnum_module_config(request):
    global bgp_cli_type
    bgp_cli_type = st.get_ui_type()
    if bgp_cli_type == 'click':
        bgp_cli_type = 'vtysh'
    bgp_unnum_initialize_variables()
    bgp_unnum_pre_config()
    yield
    bgp_unnum_post_config()


@pytest.fixture(scope="function", autouse=True)
def cmds_func_hooks(request):
    yield
    if ('test_ft_bgp_unnumbered_rr' in request.node.name) or (
            'test_ft_bgp_unnumbered_manual_ll' in request.node.name) or (
            'test_ft_bgp_unnumbered_nondefault_vrf' in request.node.name):
        st.log('######------Configure Unnumbered BGP peers on port based------######')
        bgp_unnumbered_neighbour_config()


@pytest.mark.bgp_unnum_regression
def test_ft_bgp_unnumbered_peer_basic():
    # ################ Author Details ################
    # Name: Kiran Vedula
    # Email: kiran-kumar.vedula@broadcom.com
    # ################################################
    utils_obj.banner_log('FtOtSoRtBgpUnFn001,FtOtSoRtBgpUnFn002,FtOtSoRtBgpUnFn018,FtOtSoRtBgpUnFn019')
    st.log('######------Configure Unnumbered BGP peers------######')
    result = 0
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=vars.D1D2P1,
                           state='Established'):
        st.log("Failed to form BGP unnumbered peering using IPv6 link local")
        result += 1
    bgp_obj.config_bgp_neighbor_properties(vars.D1, data.d1_local_as, vars.D1D2P1, family="ipv6", neighbor_shutdown='',
                                           no_form='')
    if utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=vars.D1D2P1,
                       state='Established'):
        st.log("unnumbered BGP peering is established even after shutdown")
        result += 1
    bgp_obj.config_bgp_neighbor_properties(vars.D1, data.d1_local_as, vars.D1D2P1, family="ipv6", neighbor_shutdown='',
                                           no_form='no')
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=vars.D1D2P1,
                           state='Established'):
        st.log("Failed to form BGP unnumbered peering using IPv6 link local after no shutdown")
        result += 1
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=data.vlan_in_1,
                           state='Established'):
        st.log("Failed to form BGP unnumbered peering using IPv6 link local on a VLAN")
        result += 1
    # Get show ndp output
    st.log('######------shut/no shut link with unnumbered BGP------######')
    utils.exec_all(True, [[arp_obj.show_ndp, vars.D1, None], [arp_obj.show_ndp, vars.D2, None]])
    intf_obj.interface_operation(vars.D1, vars.D1D2P1, operation="shutdown", skip_verify=True)
    st.wait(data.wait)
    intf_obj.interface_status_show(vars.D1, vars.D1D2P1)
    intf_obj.interface_operation(vars.D1, vars.D1D2P1, operation="startup", skip_verify=True)
    st.wait(data.wait)
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=vars.D1D2P1,
                           state='Established'):
        st.log("Failed to form BGP unnumbered peering using IPv6 link local")
        result += 1
    if result == 0:
        st.report_pass("test_case_passed")
    else:
        st.log("BGP IPv6 unnumbered neighborship failure")
        st.report_fail("test_case_failed")


@pytest.mark.bgp_unnum_regression
def test_ft_bgp_unnumbered_clear_bgp_ndp():
    # ################ Author Details ################
    # Name: Kiran Vedula
    # Email: kiran-kumar.vedula@broadcom.com
    # ################################################
    utils_obj.banner_log('FtOtSoRtBgpUnFn004,FtOtSoRtBgpUnFn005,FtOtSoRtBgpUnFn007')
    result = 0
    st.log('######------Clear BGP on both nodes------######')
    utils.exec_all(True, [[arp_obj.clear_ndp_table, vars.D1], [arp_obj.clear_ndp_table, vars.D2]])
    utils.exec_all(True, [[arp_obj.show_ndp, vars.D1], [arp_obj.show_ndp, vars.D2]])
    utils.exec_all(True, [[bgp_obj.clear_ip_bgp_vtysh, vars.D1], [bgp_obj.clear_ip_bgp_vtysh, vars.D2]])
    utils.exec_all(True, [[arp_obj.show_ndp, vars.D1], [arp_obj.show_ndp, vars.D2]])
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=vars.D1D2P1,
                           state='Established'):
        st.log("Failed to form BGP unnumbered peering after clear NDP/BGP")
        result += 1
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D2, family='ipv6', shell=bgp_cli_type, neighbor=vars.D2D1P1,
                           state='Established'):
        st.log("Failed to form BGP unnumbered peering after clear NDP/BGP")
        result += 1
    utils.exec_all(True, [[ip_obj.config_ipv6, vars.D1, "disable"], [ip_obj.config_ipv6, vars.D2, "disable"]])
    utils.exec_all(True, [[bgp_obj.clear_ip_bgp_vtysh, vars.D1], [bgp_obj.clear_ip_bgp_vtysh, vars.D2]])
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D2, family='ipv6', shell=bgp_cli_type, neighbor=vars.D2D1P1,
                           state='Active'):
        st.log("BGP unnumbered peers established even after disable IPv6")
        result += 1
    utils.exec_all(True, [[ip_obj.config_ipv6, vars.D1, "enable"], [ip_obj.config_ipv6, vars.D2, "enable"]])
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D2, family='ipv6', shell=bgp_cli_type, neighbor=vars.D2D1P1,
                           state='Established'):
        st.log("Failed to form BGP unnumbered peering after enable IPv6")
        result += 1
    if result == 0:
        st.report_pass("test_case_passed")
    else:
        st.log("BGP unnumbered neighborship failed after config state toggle")
        st.report_fail("test_case_failed")


@pytest.mark.bgp_unnum_regression
def test_ft_bgp_unnumbered_bfd():
    utils_obj.banner_log('FtOtSoRtBgpUnFn006')
    # ################ Author Details ################
    # Name: Kiran Vedula
    # Email: kiran-kumar.vedula@broadcom.com
    # ################################################
    result = 0
    st.log('######------Enable BFD on unnumbered BGP peers------######')
    dict1 = {'config': 'yes', 'local_asn': data.d1_local_as, 'neighbor_ip': vars.D1D2P1, 'interface': vars.D1D2P1}
    dict2 = {'config': 'yes', 'local_asn': data.d2_local_as, 'neighbor_ip': vars.D2D1P1, 'interface': vars.D2D1P1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], bfd_obj.configure_bfd, [dict1, dict2])
    if not utils.poll_wait(bfd_obj.verify_bfd_peers_brief, data.wait_timer, vars.D2, peeraddress=d1_prt_link_local[0],
                           ouraddress=d2_prt_link_local[0], status="UP"):
        st.log("Failed to get BFD status Up")
        result += 1
    if result == 0:
        st.report_pass("test_case_passed")
    else:
        st.log("BGP unnumbered neighborship failure")
        st.report_fail("test_case_failed")


@pytest.mark.bgp_unnum_regression
def test_ft_bgp_unnumbered_pc_mem_add_rem():
    # ################ Author Details ################
    # Name: Kiran Vedula
    # Email: kiran-kumar.vedula@broadcom.com
    # ################################################
    utils_obj.banner_log('FtOtSoRtBgpUnFn003,FtOtSoRtBgpUnFn008')
    result = 0
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6',
                           shell=bgp_cli_type, neighbor=data.portchannel_name, state='Established'):
        st.log("Failed to form BGP unnumbered peering using IPv6 link local")
        result += 1
    ip_obj.config_interface_ip6_link_local(vars.D1, data.portchannel_name, 'disable')
    pc_obj.add_del_portchannel_member(vars.D1, data.portchannel_name, [vars.D1D2P3, vars.D1D2P4], 'del')
    st.wait(data.wait)
    pc_obj.add_del_portchannel_member(vars.D1, data.portchannel_name, [vars.D1D2P3, vars.D1D2P4], 'add')
    ip_obj.config_interface_ip6_link_local(vars.D1, data.portchannel_name, 'enable')
    st.wait(data.wait)
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6',
                           shell=bgp_cli_type, neighbor=data.portchannel_name, state='Established'):
        st.log("Failed to form BGP unnumbered peering using IPv6 link local")
        result += 1
    if result == 0:
        st.report_pass("test_case_passed")
    else:
        st.log("BGP unnumbered neighborship failed after PC member del and re-add")
        st.report_fail("test_case_failed")


@pytest.mark.bgp_unnum_regression1
def test_ft_bgp_unnumbered_traffic():
    """
    # ################ Author Details ################
    # Name: Sesha Reddy Koilkonda
    # Email: seshareddy.koilkonda@broadcom.com
    # ################################################
    :return:
    """
    utils_obj.banner_log('FtOtSoRtBgpUnFn021')
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()
    dut1_mac = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.tg_ip4_addr_l[0],
                                 gateway=data.tgd_ip4_addr_l[0], src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    h2 = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.tg_ip4_addr_l[1],
                                 gateway=data.tgd_ip4_addr_l[1], src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    # Advertise a network to peer
    network = '55.1.1.0/24'
    bgp_obj.advertise_bgp_network(vars.D2, data.d2_local_as, network)
    stream_tg1 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode="single_burst",
                                       length_mode='fixed', pkts_per_burst=1000, mac_src='00.00.00.11.12.53',
                                       mac_dst=dut1_mac,
                                       l3_protocol='ipv4', ip_src_addr=data.tg_ip4_addr_l[0],
                                       ip_dst_addr=data.tg_ip4_addr_l[1], port_handle2=tg_ph_2)
    stream_id = stream_tg1['stream_id']
    tg1.tg_traffic_control(action='run', stream_handle=stream_id)
    st.wait(5)
    tg1.tg_traffic_control(action='stop', stream_handle=stream_id)
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg1],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [tg2],
            'stream_list': [(stream_id)],
        }
    }
    # verify statistics
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    tg2.tg_interface_config(port_handle=tg_ph_2, handle=h2['handle'], mode='destroy')
    bgp_obj.advertise_bgp_network(vars.D2, data.d2_local_as, network, config='no')
    if aggrResult:
        st.log("IPv4 traffic over BGPv6 unnumbered neighbour is passed")
        st.report_pass("test_case_passed")
    else:
        st.error("IPv4 traffic over BGPv6 unnumbered neighbour is failed.")
        st.report_fail("test_case_failed")


@pytest.mark.bgp_unnum_regression
def test_ft_bgp_unnumbered_rmap():
    """
    # ################ Author Details ################
    # Name: Sesha Reddy Koilkonda
    # Email: seshareddy.koilkonda@broadcom.com
    # ################################################
    :return:
    """
    utils_obj.banner_log('FtOtSoRtBgpUnFn010,FtOtSoRtBgpUnFn016')
    result = 0
    network_ipv6 = '6002:1::0/64'

    bgp_obj.config_bgp(config='yes', dut=vars.D2, local_as=data.d2_local_as, addr_family='ipv6', neighbor=vars.D2D1P1,
                       weight='35000', config_type_list=["weight"])
    bgp_obj.config_bgp_network_advertise(vars.D1, data.d1_local_as, network_ipv6, addr_family='ipv6', config='yes', network_import_check=True)
    st.wait(60)
    n1 = ip_obj.verify_ip_route(vars.D2, family='ipv6', shell='sonic', ip_address='6002:1::/64')
    if (n1 is False):
        st.error("Failed to advertise the ipv6 network to the peer")
        result += 1
    bgp_obj.get_ip_bgp_route(vars.D2, family="ipv6", network="6002:1/64")
    # Add route-map to advertised network
    ip_obj.config_access_list(vars.D1, 'Ubgp-access-list1', network_ipv6, 'deny', family='ipv6', seq_num="1")
    ip_obj.config_route_map_match_ip_address(vars.D1, 'Ubgp-rmap', 'deny', '10', 'Ubgp-access-list1', family='ipv6')
    bgp_obj.advertise_bgp_network(vars.D1, data.d1_local_as, network_ipv6, 'Ubgp-rmap', family='ipv6')
    # verify route-map to advertised network
    n1 = ip_obj.verify_ip_route(vars.D2, family='ipv6', shell='sonic', ip_address='6002:1::/64')
    if (n1 is True):
        st.error("Advertised network is not filtered by the configured route map")
        result += 1
    else:
        st.log("As expected, advertised network is filtered by the route map.")
    # Veirfy the BGP unnumbered neighbourship post r-map config
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=vars.D1D2P1,
                           state='Established'):
        st.error("Failed to form BGP unnumbered peering using IPv6 link local, with the route map configuration.")
        result += 1
    # Unconfig the r-map and verify the BGP neighbourship
    ip_obj.config_route_map_mode(vars.D1, 'Ubgp-rmap', 'deny', '10', config='no')
    ip_obj.config_access_list(vars.D1, 'Ubgp-access-list1', network_ipv6, 'deny', config='no', family='ipv6', seq_num="1")
    bgp_obj.config_bgp(config='no', dut=vars.D2, local_as=data.d2_local_as, addr_family='ipv6', neighbor=vars.D2D1P1,
                       weight='35000', config_type_list=["weight"])
    bgp_obj.config_bgp_network_advertise(vars.D1, data.d1_local_as, network_ipv6, addr_family='ipv6', config='no')
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=vars.D1D2P1,
                           state='Established'):
        st.error("Failed to form BGP unnumbered peering using IPv6 link local, after route map un-configuration.")
        result += 1
    if result == 0:
        st.report_pass("test_case_passed")
    else:
        st.error("BGP unnumbered neighborship failed with the route map configuration.")
        st.report_fail("test_case_failed")


@pytest.mark.bgp_unnum_regression
def test_ft_bgp_unnumbered_rr():
    """
    # ################ Author Details ################
    # Name: Sesha Reddy Koilkonda
    # Email: seshareddy.koilkonda@broadcom.com
    # ################################################
    :return:
    """
    utils_obj.banner_log('FtOtSoRtBgpUnFn011,FtOtSoRtBgpUnFn012')
    result = 0

    bgp_obj.cleanup_router_bgp(st.get_dut_names())
    dict1 = {'config': 'yes', 'router_id': data.d1_rid, 'addr_family': 'ipv6', 'local_as': data.d1_local_as,
             'remote_as': 'internal', 'config_type_list': ["remote-as", "activate"], 'interface': vars.D1D2P1,
             'neighbor': vars.D1D2P1}
    dict2 = {'config': 'yes', 'router_id': data.d2_rid, 'addr_family': 'ipv6', 'local_as': data.d1_local_as,
             'remote_as': 'internal', 'config_type_list': ["remote-as", "activate"], 'interface': vars.D2D1P1,
             'neighbor': vars.D2D1P1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], bgp_obj.config_bgp, [dict1, dict2])
    result_rr = bgp_obj.create_bgp_route_reflector_client(vars.D1, data.d1_local_as, 'ipv6', vars.D1D2P1, 'yes')
    if not result_rr:
        st.error(
            "BGP SP - Configuring client reflection on {} {} bgp {} Failed".format(vars.D1, 'ipv6', data.d1_local_as))
        result += 1
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=vars.D1D2P1,
                           state='Established'):
        st.error("Failed to form iBGP unnumbered peering using IPv6 link local with Route-reflector-client config")
        result += 1
    # Unconfiguration
    bgp_obj.create_bgp_route_reflector_client(vars.D1, data.d1_local_as, 'ipv6', vars.D1D2P1, config='no')

    bgp_obj.cleanup_router_bgp(st.get_dut_names())
    if result == 0:
        st.report_pass("test_case_passed")
    else:
        st.error("BGP unnumbered neighborship failed with the Route-reflector-client configuration failed.")
        st.report_fail("test_case_failed")


@pytest.mark.bgp_unnum_regression
def test_ft_bgp_unnumbered_manual_ll():
    """
    # ################ Author Details ################
    # Name: Sesha Reddy Koilkonda
    # Email: seshareddy.koilkonda@broadcom.com
    # ################################################
    :return:
    """
    utils_obj.banner_log('FtOtSoRtBgpUnFn013,FtOtSoRtBgpUnFn014,FtOtSoRtBgpUnFn015')
    result = 0
    # Configure the Link-local manually on Dut1 and auto link-local on DUT2 and verify the neighbourship.
    bgp_obj.cleanup_router_bgp(st.get_dut_names())
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1D2P1, data.ip6_addr_manual_ll[0], 96, family='ipv6')
    dict1 = {'config': 'yes', 'router_id': data.d1_rid, 'addr_family': 'ipv6', 'local_as': data.d1_local_as,
             'remote_as': 'external', 'config_type_list': ["remote-as", "activate"], 'interface': vars.D1D2P1,
             'neighbor': vars.D1D2P1}
    dict2 = {'config': 'yes', 'router_id': data.d2_rid, 'addr_family': 'ipv6', 'local_as': data.d2_local_as,
             'remote_as': 'external', 'config_type_list': ["remote-as", "activate"], 'interface': vars.D2D1P1,
             'neighbor': vars.D2D1P1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], bgp_obj.config_bgp, [dict1, dict2])
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=vars.D1D2P1,
                           state='Established'):
        st.error(
            "Failed to form BGP unnumbered peering using IPv6 link local with the Manual-Auto link-local address combination.")
        result += 1
    # with the manual link-local on Dut1 and configure the link-local on DUT2 also manually and verify the neighbourship.
    bgp_obj.cleanup_router_bgp(st.get_dut_names())
    ip_obj.config_ip_addr_interface(vars.D2, vars.D2D1P1, data.ip6_addr_manual_ll[1], 96, family='ipv6')
    parallel.exec_parallel(True, [vars.D1, vars.D2], bgp_obj.config_bgp, [dict1, dict2])
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=vars.D1D2P1,
                           state='Established'):
        st.error(
            "Failed to form BGP unnumbered peering using IPv6 link local with the manual-manual link-local address combination.")
        result += 1
    # update the manual link-local on Dut2 and verify the neighbourship.
    bgp_obj.cleanup_router_bgp(st.get_dut_names())
    data.ip6_addr_ll3 = 'FE80:0:0:0:204:5FF:FE00:500'
    ip_obj.config_ip_addr_interface(vars.D2, vars.D2D1P1, data.ip6_addr_manual_ll[2], 96, family='ipv6')
    parallel.exec_parallel(True, [vars.D1, vars.D2], bgp_obj.config_bgp, [dict1, dict2])
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=vars.D1D2P1,
                           state='Established'):
        st.error(
            "Failed to form BGP unnumbered peering using IPv6 link local, after uodating the manual link-local address on peer DUT..")
        result += 1
    bgp_obj.cleanup_router_bgp(st.get_dut_names())
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1D2P1, data.ip6_addr_manual_ll[0], 96, family='ipv6', config='remove')
    ip_obj.config_ip_addr_interface(vars.D2, vars.D2D1P1, data.ip6_addr_manual_ll[1], 96, family='ipv6', config='remove')
    ip_obj.config_ip_addr_interface(vars.D2, vars.D2D1P1, data.ip6_addr_manual_ll[2], 96, family='ipv6', config='remove')
    if result == 0:
        st.report_pass("test_case_passed")
    else:
        st.error("BGP unnumbered neighborship failed with the manual link-local address configuration.")
        st.report_fail("test_case_failed")


@pytest.mark.bgp_unnum_regression
def test_ft_bgp_unnumbered_nondefault_vrf():
    """
    # ################ Author Details ################
    # Name: Sesha Reddy Koilkonda
    # Email: seshareddy.koilkonda@broadcom.com
    # ################################################
    :return:
    """
    utils_obj.banner_log("FtOtSoRtBgpUnFn016,FtOtSoRtBgpUnFn017")
    result = 0
    bgp_obj.cleanup_router_bgp(st.get_dut_names())
    dict1 = {'vrf_name': data.vrf_name, 'skip_error': True}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.config_vrf, [dict1, dict1])
    utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, vars.D1, vars.D1D2P1,"disable"],
                          [ip_obj.config_interface_ip6_link_local, vars.D2, vars.D2D1P1, "disable"]])
    dict1 = {'vrf_name': data.vrf_name, 'intf_name': vars.D1D2P1, 'skip_error': True}
    dict2 = {'vrf_name': data.vrf_name, 'intf_name': vars.D2D1P1, 'skip_error': True}

    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])
    utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, vars.D1, vars.D1D2P1],
                          [ip_obj.config_interface_ip6_link_local, vars.D2, vars.D2D1P1]])
    utils.exec_all(True, [[ip_obj.get_interface_ip_address, vars.D1, None, "ipv6"],
                          [ip_obj.get_interface_ip_address, vars.D2, None, "ipv6"]])
    dict1 = {'vrf_name': data.vrf_name, 'router_id': data.d1_rid, 'local_as': data.d1_local_as, 'addr_family': 'ipv6',
             'neighbor': vars.D1D2P1, 'remote_as': 'external', 'config_type_list': ["remote-as", "activate"],
             'interface': vars.D1D2P1}
    dict2 = {'vrf_name': data.vrf_name, 'router_id': data.d2_rid, 'local_as': data.d2_local_as, 'addr_family': 'ipv6',
             'neighbor': vars.D2D1P1, 'remote_as': 'external', 'config_type_list': ["remote-as", "activate"],
             'interface': vars.D2D1P1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], bgp_obj.config_bgp, [dict1, dict2])

    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=vars.D1D2P1,
                           vrf=data.vrf_name, state='Established'):
        st.error("BGP unnumbered neighbourship with the non-default vrf configuration failed.")
        result += 1
    st.log('######------Save and reboot------######')
    reboot_obj.config_save(vars.D1, "sonic")
    reboot_obj.config_save(vars.D1, "vtysh")

    st.reboot(vars.D1)
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=vars.D1D2P1,
                           vrf=data.vrf_name, state='Established'):
        st.error("BGP unnumbered neighbourship with the non-default vrf configuration failed after save and reboot.")
        result += 1
    st.log('######------Config reload with BGP unnumbered------######')
    st.log("Config reload the DUT")
    reboot_obj.config_save_reload(vars.D1)
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D1, family='ipv6', shell=bgp_cli_type, neighbor=vars.D1D2P1,
                           vrf=data.vrf_name, state='Established'):
        st.error("BGP unnumbered neighbourship with the non-default vrf configuration failed after config reload.")
        result += 1
    # unconfig part:

    dict1 = {'vrf_name': data.vrf_name, 'local_as': data.d1_local_as, 'config': 'no', 'removeBGP': 'yes',
             'config_type_list': ['removeBGP']}
    dict2 = {'vrf_name': data.vrf_name, 'local_as': data.d2_local_as, 'config': 'no', 'removeBGP': 'yes',
             'config_type_list': ['removeBGP']}
    parallel.exec_parallel(True, [vars.D1, vars.D2], bgp_obj.config_bgp, [dict1, dict2])
    utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, vars.D1, vars.D1D2P1, "disable"],
                          [ip_obj.config_interface_ip6_link_local, vars.D2, vars.D2D1P1, "disable"]])
    dict1 = {'vrf_name': data.vrf_name, 'intf_name': vars.D1D2P1, 'skip_error': True, 'config': 'no'}
    dict2 = {'vrf_name': data.vrf_name, 'intf_name': vars.D2D1P1, 'skip_error': True, 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])
    dict1 = {'vrf_name': data.vrf_name, 'skip_error': True, 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.config_vrf, [dict1, dict1])
    bgp_obj.cleanup_router_bgp(st.get_dut_names())
    utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, vars.D1, d1_int_ipv6_list],
                          [ip_obj.config_interface_ip6_link_local, vars.D2, d2_int_ipv6_list]])
    if result == 0:
        st.report_pass("test_case_passed")
    else:
        st.error("BGP unnumbered neighborship failed with the non-default vrf configuration.")
        st.report_fail("test_case_failed")




@pytest.mark.bgp_unnum_regression
def test_ft_bgp_unnumbered_warmboot():
    # ################ Author Details ################
    # Name: Kiran Vedula
    # Email: kiran-kumar.vedula@broadcom.com
    # ################################################
    utils_obj.banner_log('FtOtSoRtBgpUnFn009')
    utils.exec_all(True, [[bgp_obj.show_bgp_ipv6_summary_vtysh, vars.D1],
                          [bgp_obj.show_bgp_ipv6_summary_vtysh, vars.D2]])
    utils.exec_all(True, [[arp_obj.show_ndp, vars.D1, None], [arp_obj.show_ndp, vars.D2, None]])
    result = 0
    st.log('######------Warm reboot with BGP unnumbered------######')
    platform = basic_obj.get_hwsku(vars.D1)
    common_constants = st.get_datastore(vars.D1, "constants", "default")
    if not platform.lower() in common_constants['WARM_REBOOT_SUPPORTED_PLATFORMS']:
        st.error("Warm-Reboot is not supported for this platform {}".format(platform))
        st.report_unsupported('Warmboot_unsupported_platform', platform)
    reboot_obj.config_save(vars.D1, "sonic")
    reboot_obj.config_save(vars.D1, "vtysh")
    st.reboot(vars.D1, 'warm')
    st.wait(data.wait)
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D2, family='ipv6', shell=bgp_cli_type,
                           neighbor=vars.D2D1P1, state='Established'):
        st.log("Failed to form BGP unnumbered peering after warm reboot")
        result += 1
    st.wait(data.wait)
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D2, family='ipv6', shell=bgp_cli_type,
                           neighbor=data.vlan_in_1,state='Established'):
        st.log("Failed to form BGP unnumbered peering after warm reboot")
        result += 1
    st.wait(data.wait)
    if not utils.poll_wait(bgp_obj.verify_bgp_summary, data.wait_timer, vars.D2, family='ipv6', shell=bgp_cli_type,
                           neighbor=data.portchannel_name, state='Established'):
        st.log("Failed to form BGP unnumbered peering after warm reboot")
        result += 1
    if result == 0:
        st.report_pass("test_case_passed")
    else:
        st.log("BGP unnumbered neighborship failed warm reboot")
        utils.exec_all(True, [[arp_obj.show_ndp, vars.D1, None], [arp_obj.show_ndp, vars.D2, None]])
        utils.exec_all(True, [[bgp_obj.show_bgp_ipv6_neighbor_vtysh, vars.D1],
                              [bgp_obj.show_bgp_ipv6_neighbor_vtysh, vars.D2]])
        st.report_fail("test_case_failed")

def bgp_unnum_pre_config():
    global vars
    vars = st.ensure_min_topology("D1D2:4", "D1T1:2", "D2T1:2")
    global dut1_rt_int_mac, dut2_rt_int_mac, d1_prt_link_local, \
           d2_prt_link_local, d1_int_ipv6_list, d2_int_ipv6_list
    # For debugging purpose, checking 'running config' before proceeding for module config
    utils.exec_all(True, [[sc_obj.get_running_config, vars.D1], [sc_obj.get_running_config, vars.D2]])
    # For debugging purpose, checking 'routing interfaces' before proceeding for module config
    # utils.exec_all(True, [[ip_obj.get_interface_ip_address, vars.D1, None, "ipv6"],
    #                       [ip_obj.get_interface_ip_address, vars.D2, None, "ipv6"]])
    pc_obj.config_portchannel(vars.D1, vars.D2, data.portchannel_name, [vars.D1D2P3, vars.D1D2P4],
                              [vars.D2D1P3, vars.D2D1P4], config='add', thread=True)
    # vlan config
    utils.exec_all(True, [[vlan_obj.create_vlan, vars.D1, [data.vlan_li[0], data.vlan_li[1]]],
                          [vlan_obj.create_vlan, vars.D2, [data.vlan_li[0], data.vlan_li[1]]]])
    utils.exec_all(True, [
        [vlan_mem_cfg, vars.D1, [[data.vlan_li[0], vars.D1D2P2, True], [data.vlan_li[1], vars.D1D2P2, True]]],
        [vlan_mem_cfg, vars.D2, [[data.vlan_li[0], vars.D2D1P2, True], [data.vlan_li[1], vars.D2D1P2, True]]]])
    d1_int_ipv6_list = [vars.D1D2P1, data.vlan_in_1, data.vlan_in_2, data.portchannel_name]
    d2_int_ipv6_list = [vars.D2D1P1, data.vlan_in_1, data.vlan_in_2, data.portchannel_name]
    utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, vars.D1, d1_int_ipv6_list],
                          [ip_obj.config_interface_ip6_link_local, vars.D2, d2_int_ipv6_list]])
    # TG connected int ipv6 address config
    utils.exec_all(True, [[ip_obj.config_ip_addr_interface, vars.D1, vars.D1T1P2, data.tgd_ip6_addr_l[0],
                           data.tg_ip6_addr_mask_l[0], "ipv6", 'add'], [ip_obj.config_ip_addr_interface, vars.D2,
                                                                        vars.D2T1P2, data.tgd_ip6_addr_l[1],
                                                                        data.tg_ip6_addr_mask_l[1], "ipv6", 'add']])
    utils.exec_all(True, [[ip_obj.config_ip_addr_interface, vars.D1, vars.D1T1P1, data.tgd_ip4_addr_l[0],
                           data.tg_ip4_addr_mask_l[0], "ipv4", 'add'], [ip_obj.config_ip_addr_interface, vars.D2,
                                                                        vars.D2T1P1, data.tgd_ip4_addr_l[1],
                                                                        data.tg_ip4_addr_mask_l[1], "ipv4", 'add']])
    # Get DUT mac address
    [rt_int_mac, exceptions] = utils.exec_all(True, [[basic_obj.get_ifconfig_ether, vars.D1, vars.D1D2P1],
                                                     [basic_obj.get_ifconfig_ether, vars.D2, vars.D2D1P1]])
    for value in exceptions:
        if value is not None:
            st.log("Exceptions observed {}".format(value))
            st.error("Exceptions observed while getting mac address of routing interface")
    dut1_rt_int_mac = rt_int_mac[0]
    dut2_rt_int_mac = rt_int_mac[1]
    # Get DUT link local addresses
    [rt_link_local_addr, exceptions] = utils.exec_all(True, [[ip_obj.get_link_local_addresses, vars.D1, vars.D1D2P1],
                                                             [ip_obj.get_link_local_addresses, vars.D2, vars.D2D1P1]])
    for value in exceptions:
        if value is not None:
            st.log("Exceptions observed {}".format(value))
            st.error("Exceptions observed while getting mac address of routing interface")
    d1_prt_link_local = rt_link_local_addr[0]
    d2_prt_link_local = rt_link_local_addr[1]
    st.log("######------Get show ndp output------######")
    utils.exec_all(True, [[arp_obj.show_ndp, vars.D1, None], [arp_obj.show_ndp, vars.D2, None]])
    bgp_unnumbered_neighbour_config()


def bgp_unnumbered_neighbour_config():
    """
    This proc is for the BGP peering with Port-Based, Vlan-Based, Lag interfaces.
    :return:
    """
    st.log('######------Configure Unnumbered BGP peers on port based------######')
    dict1 = {'peergroup': 'peer_v6', 'router_id': data.d1_rid, 'addr_family': 'ipv6', 'local_as': data.d1_local_as,
             'remote_as': 'external', 'config_type_list': ['peergroup', "activate"], 'neighbor': vars.D1D2P1,
             'interface': vars.D2D1P1}
    dict2 = {'peergroup': 'peer_v6', 'router_id': data.d2_rid, 'addr_family': 'ipv6', 'local_as': data.d2_local_as,
             'remote_as': 'external', 'config_type_list': ['peergroup', "activate"], 'neighbor': vars.D2D1P1,
             'interface': vars.D2D1P1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], bgp_obj.config_bgp, [dict1, dict2])
    st.log('######------Configure Unnumbered BGP peers on PC------######')
    dict1 = {'router_id': data.d1_rid, 'addr_family': 'ipv6', 'local_as': data.d1_local_as,
             'remote_as': 'external', 'config_type_list': ["remote-as", "activate"], 'interface': data.portchannel_name,
             'neighbor': data.portchannel_name}
    dict2 = {'router_id': data.d2_rid, 'addr_family': 'ipv6', 'local_as': data.d2_local_as,
             'remote_as': 'external', 'config_type_list': ["remote-as", "activate"], 'interface': data.portchannel_name,
             'neighbor': data.portchannel_name}
    parallel.exec_parallel(True, [vars.D1, vars.D2], bgp_obj.config_bgp, [dict1, dict2])
    st.log('######------Configure Unnumbered BGP peers on VLAN------######')
    dict1 = {'router_id': data.d1_rid, 'addr_family': 'ipv6', 'local_as': data.d1_local_as,
             'remote_as': 'external', 'config_type_list': ["remote-as", "activate"], 'interface': data.vlan_in_1,
             'neighbor': data.vlan_in_1}
    dict2 = {'router_id': data.d2_rid, 'addr_family': 'ipv6', 'local_as': data.d2_local_as,
             'remote_as': 'external', 'config_type_list': ["remote-as", "activate"], 'interface': data.vlan_in_1,
             'neighbor': data.vlan_in_1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], bgp_obj.config_bgp, [dict1, dict2])


def bgp_unnum_post_config():
    vars = st.get_testbed_vars()
    bgp_obj.cleanup_router_bgp(st.get_dut_names())
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='ipv4', skip_error_check=True)
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='ipv6', skip_error_check=True)
    utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, vars.D1, d1_int_ipv6_list, "disable"],
                          [ip_obj.config_interface_ip6_link_local, vars.D2, d2_int_ipv6_list, "disable"]])
    vlan_obj.clear_vlan_configuration(st.get_dut_names())
    pc_obj.clear_portchannel_configuration(st.get_dut_names())

    st.log("Cleaning up routing interfaces configured on TG")
    st.log("Stopping the TG traffic again, if in case of any failures in test function misses the stop operation")


def vlan_mem_cfg(dut, data):
    if type(data) == list and len(data) > 0:
        for vlan, port, mode in data:
            vlan_obj.add_vlan_member(dut, vlan, port, tagging_mode=mode)
        return True
    return False
