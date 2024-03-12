
import random
import math
import re
import pytest

from spytest import st, tgapi, SpyTestDict

import apis.routing.ip as ipfeature
import apis.switching.vlan as vlan_obj
import apis.switching.portchannel as pc_obj
import apis.system.basic as basic_obj
import apis.common.asic as asicapi
import apis.routing.bgp as bgpfeature
import apis.system.interface as intf_obj
import apis.routing.route_map as rmap_obj
import apis.routing.arp as arp_obj

from utilities.common import random_vlan_list
from utilities.utils import rif_support_check, report_tc_fail

vars = dict()
data = SpyTestDict()
data.ip4_addr = ["192.168.1.1", "192.168.1.2", "192.168.2.1", "192.168.2.2", "192.168.3.1", "192.168.3.3",
                 "192.168.4.1", "192.168.4.2", "192.168.5.1", "192.168.5.2", "192.168.6.1", "192.168.6.2"]
data.ip4_addr_rt = ["192.168.1.0", "192.168.2.0", "192.168.3.0", "192.168.4.0", "192.168.5.0", "192.168.6.0"]
data.ip6_addr = ["2001::1", "2001::2", "3301::1", "3301::2", "4441::1", "4441::2", "5551::1", "5551::2", "6661::1",
                 "6661::2", "7771::1", "7771::2"]
data.ip6_addr_rt = ["2001::", "3301::", "4441::", "5551::", "6661::", "7771::"]
data.loopback_1 = ["11.11.11.1", "22.22.22.1", "33.33.33.1"]
data.loopback6_1 = ["7767:12::2", "6671:230f:12::f", "9109:2cd1:341::3"]
data.af_ipv4 = "ipv4"
data.af_ipv6 = "ipv6"
data.shell_sonic = "sonic"
data.shell_vtysh = "vtysh"
data.vlan_1 = str(random_vlan_list()[0])
data.vlan_2 = str(random_vlan_list()[0])
data.vlan_int_1 = "Vlan{}".format(data.vlan_1)
data.vlan_int_2 = "Vlan{}".format(data.vlan_2)
data.port_channel = "PortChannel100"
data.tg_mac1 = "00:00:00:EA:23:0F"
data.tg_mac2 = "00:00:11:0A:45:33"
data.static_ip6_rt_drop = "blackhole"
data.static_ip6_rt = "6661::/64"
data.static_ip_rt = "192.168.5.0/24"
data.as_num = 100
data.remote_as_num = 200
data.routemap = "preferGlobal"
data.wait_tgstats = 2
data.no_of_ports = 8
data.ipv4_mask = '24'
data.ipv6_mask = '96'
data.host1_mac = "00:00:01:00:00:01"
data.host2_mac = "00:00:02:00:00:02"
data.host1_vlan = "100"
data.host2_vlan = "101"
data.vlan1_ip = "10.10.10.2"
data.vlan2_ip = "10.10.11.3"
data_t1d1_ip = "10.10.10.1"
data.d2t1_ip = "20.20.20.1"
data.t1d2_ip = "20.20.20.2"
data.d1_static_route = "20.20.20.0/24"
data.d2_static_route = "10.10.10.0/24"


@pytest.fixture(scope="module", autouse=True)
def ip_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1T1:2", "D2T1:2", "D1D2:4")
    platform = basic_obj.get_hwsku(vars.D1)
    data.rif_supported_1 = rif_support_check(vars.D1, platform=platform.lower())
    platform = basic_obj.get_hwsku(vars.D2)
    data.rif_supported_2 = rif_support_check(vars.D2, platform=platform.lower())
    data.rate_pps = tgapi.normalize_pps(2000)
    data.pkts_per_burst = tgapi.normalize_pps(2000)

    # delete me
    st.log(data.ip4_addr)
    st.log(data.ip6_addr)
    # delete me

    # IP module configuration
    st.log("Vlan routing configuration on D1D2P1,D2D1P1")
    vlan_obj.create_vlan(vars.D1, data.vlan_1)
    vlan_obj.add_vlan_member(vars.D1, data.vlan_1, [vars.D1D2P1], tagging_mode=True)
    vlan_obj.create_vlan(vars.D2, data.vlan_1)
    vlan_obj.add_vlan_member(vars.D2, data.vlan_1, [vars.D2D1P1], tagging_mode=True)
    ipfeature.config_ip_addr_interface(vars.D1, data.vlan_int_1, data.ip4_addr[2], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D1, data.vlan_int_1, data.ip6_addr[2], 96, family=data.af_ipv6)
    ipfeature.config_ip_addr_interface(vars.D2, data.vlan_int_1, data.ip4_addr[3], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D2, data.vlan_int_1, data.ip6_addr[3], 96, family=data.af_ipv6)
    st.log("Port routing configuration on port-channel")
    data.dut1_pc_members = [vars.D1D2P2, vars.D1D2P3]
    data.dut2_pc_members = [vars.D2D1P2, vars.D2D1P3]
    pc_obj.create_portchannel(vars.D1, data.port_channel)
    pc_obj.add_portchannel_member(vars.D1, data.port_channel, data.dut1_pc_members)
    pc_obj.create_portchannel(vars.D2, data.port_channel)
    pc_obj.add_portchannel_member(vars.D2, data.port_channel, data.dut2_pc_members)
    ipfeature.config_ip_addr_interface(vars.D1, data.port_channel, data.ip4_addr[4], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D2, data.port_channel, data.ip4_addr[5], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D1, data.port_channel, data.ip6_addr[4], 96, family=data.af_ipv6)
    ipfeature.config_ip_addr_interface(vars.D2, data.port_channel, data.ip6_addr[5], 96, family=data.af_ipv6)
    st.log("port routing configuration on  D1D2P4,D2D1P4")
    ipfeature.config_ip_addr_interface(vars.D1, vars.D1D2P4, data.ip4_addr[6], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D2, vars.D2D1P4, data.ip4_addr[7], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D1, vars.D1D2P4, data.ip6_addr[6], 96, family=data.af_ipv6)
    ipfeature.config_ip_addr_interface(vars.D2, vars.D2D1P4, data.ip6_addr[7], 96, family=data.af_ipv6)
    st.log("configuring the dut1 ports connected to TGen with ip addresses")
    ipfeature.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.ip4_addr[1], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D1, vars.D1T1P2, data.ip6_addr[1], 96, family=data.af_ipv6)
    ipfeature.create_static_route(vars.D1, data.ip6_addr[7], data.static_ip6_rt, shell=data.shell_vtysh,
                                  family=data.af_ipv6)
    ipfeature.create_static_route(vars.D1, data.ip4_addr[7], data.static_ip_rt, shell=data.shell_vtysh,
                                  family=data.af_ipv4)
    st.log("configuring the dut2 ports connected to TGen with ip addresses")
    ipfeature.config_ip_addr_interface(vars.D2, vars.D2T1P1, data.ip4_addr[8], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D2, vars.D2T1P2, data.ip6_addr[8], 96, family=data.af_ipv6)
    yield
    ipfeature.delete_static_route(vars.D1, data.ip4_addr[7], data.static_ip_rt, shell=data.shell_vtysh,
                                  family=data.af_ipv4)
    ipfeature.delete_static_route(vars.D1, data.ip6_addr[7], data.static_ip6_rt, shell=data.shell_vtysh,
                                  family=data.af_ipv6)
    ipfeature.clear_ip_configuration(st.get_dut_names())
    ipfeature.clear_ip_configuration(st.get_dut_names(), 'ipv6')
    vlan_obj.clear_vlan_configuration(st.get_dut_names())
    pc_obj.clear_portchannel_configuration(st.get_dut_names())


@pytest.fixture(scope="function", autouse=True)
def ip_func_hooks(request):
    yield


def delete_bgp_router(dut, router_id, as_num):
    """
    :param router_id:
    :type router_id:
    :param as_num:
    :type as_num:
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    st.log("delete bgp router info")
    bgpfeature.config_bgp_router(dut, as_num, router_id=router_id, config='no')


def create_bgp_neighbor_route_map_config(dut, local_asn, neighbor_ip, routemap):
    rmap = rmap_obj.RouteMap(routemap)
    rmap.add_permit_sequence('10')
    rmap.add_sequence_set_ipv6_next_hop_prefer_global('10')
    rmap.execute_command(dut)
    bgpfeature.config_bgp(dut, addr_family='ipv6', local_as=local_asn, neighbor=neighbor_ip, routeMap=routemap, diRection='in', config='yes', config_type_list=["routeMap"])
    bgpfeature.config_bgp(dut, addr_family='ipv6', local_as=local_asn, neighbor=neighbor_ip, routeMap=routemap, diRection='out', config='yes', config_type_list=["routeMap"])
    return


def create_v4_route(route_count):
    dut = vars.D1

    route_count = tgapi.normalize_hosts(route_count)
    ipfeature.show_ip_route(dut)
    ipfeature.get_interface_ip_address(dut)
    intf_obj.interface_status_show(dut)

    bgpfeature.create_bgp_router(dut, data.as_num, '')
    bgpfeature.create_bgp_neighbor(dut, data.as_num, data.ip4_addr[0], data.remote_as_num)

    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D2P1")
    tg = tg_handler["tg"]
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    dut_rt_int_mac1 = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config', intf_ip_addr=data.ip4_addr[0],
                                gateway=data.ip4_addr[1], src_mac_addr=data.tg_mac1, arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config', intf_ip_addr=data.ip4_addr[9],
                                gateway=data.ip4_addr[8], src_mac_addr=data.tg_mac2, arp_send_req='1')
    st.log("INTFCONF: " + str(h2))
    # Ping from tgen to DUT.
    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=h1['handle'], dst_ip=data.ip4_addr[1],
                            ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")

    conf_var = {'mode': 'enable',
                'active_connect_enable': '1',
                'local_as': '200',
                'remote_as': '100',
                'remote_ip_addr': data.ip4_addr[1]
                }
    route_var = {'mode': 'add',
                 'num_routes': route_count,
                 'prefix': '121.1.1.0',
                 'as_path': 'as_seq:1'
                 }
    ctrl_start = {'mode': 'start'}

    # Configuring the BGP router.
    bgp_rtr1 = tgapi.tg_bgp_config(tg=tg,
                                   handle=h1['handle'],
                                   conf_var=conf_var,
                                   route_var=route_var,
                                   ctrl_var=ctrl_start)

    st.log("BGP_HANDLE: " + str(bgp_rtr1))
    st.log("waiting for 10 sec to get the BGP neighbor started before going for another TG operation")
    st.wait(10)
    # Verified at neighbor.
    tr1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create', transmit_mode='single_burst',
                               pkts_per_burst=data.pkts_per_burst,
                               length_mode='fixed', rate_pps=data.rate_pps, l3_protocol='ipv4', mac_src=data.tg_mac1,
                               mac_dst=dut_rt_int_mac1, ip_src_addr=data.ip4_addr[0],
                               ip_dst_addr=data.ip4_addr[9])
    st.log("TRAFCONF: " + str(tr1))
    res = tg.tg_traffic_control(action='run', stream_handle=tr1['stream_id'])
    st.log("TR_CTRL: " + str(res))
    tg.tg_traffic_control(action='stop', stream_handle=tr1['stream_id'])
    st.log("Checking the stats and verifying the traffic flow")
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg_handler["tg"]],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [tg_handler["tg"]],
        }
    }
    # verify statistics
    aggrResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count', retry=1)
    if not aggrResult:
        return False

    return True


@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoRtIpv4Fn003'])
def test_l3_v4_route_po_1():
    dut = vars.D1
    asicapi.dump_vlan(dut)
    asicapi.dump_l2(dut)
    asicapi.dump_trunk(dut)

    ret = create_v4_route(30000)
    if (ret):
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


def create_v6_route(route_count):
    dut = vars.D1

    route_count = tgapi.normalize_hosts(route_count)
    ipfeature.show_ip_route(dut, family='ipv6')
    ipfeature.get_interface_ip_address(dut, family='ipv6')

    bgpfeature.create_bgp_router(dut, data.as_num, '')
    bgpfeature.create_bgp_neighbor(dut, data.as_num, data.ip6_addr[0], data.remote_as_num, family="ipv6")
    create_bgp_neighbor_route_map_config(dut, data.as_num, data.ip6_addr[0], data.routemap)

    tg_handler = tgapi.get_handles_byname("T1D1P2", "T1D2P2")
    tg = tg_handler["tg"]
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    dut_rt_int_mac1 = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config', ipv6_intf_addr=data.ip6_addr[0],
                                ipv6_prefix_length='64', ipv6_gateway=data.ip6_addr[1],
                                src_mac_addr=data.tg_mac1, arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config', ipv6_intf_addr=data.ip6_addr[9],
                                ipv6_prefix_length='64', ipv6_gateway=data.ip6_addr[8],
                                src_mac_addr=data.tg_mac2, arp_send_req='1')
    st.log("INTFCONF: " + str(h2))

    # Ping from tgen to DUT.
    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=h1['handle'], dst_ip=data.ip6_addr[1],
                            ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")

    bgp_conf = tg.tg_emulation_bgp_config(handle=h1['handle'], mode='enable', ip_version='6',
                                          active_connect_enable='1', local_as=data.as_num, remote_as=data.remote_as_num, remote_ipv6_addr=data.ip6_addr[1])

    tg.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', ip_version='6',
                                     num_routes=route_count, prefix='3300:1::', as_path='as_seq:1')
    tg.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')

    # Configuring the BGP router.
    st.log("BGP neighborship established.")
    tr1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create', transmit_mode='single_burst',
                               pkts_per_burst=data.pkts_per_burst,
                               length_mode='fixed', rate_pps=data.rate_pps, l3_protocol='ipv6', mac_src=data.tg_mac1,
                               mac_dst=dut_rt_int_mac1, ipv6_src_addr=data.ip6_addr[0],
                               ipv6_dst_addr=data.ip6_addr[9])
    st.log("TRAFCONF: " + str(tr1))

    res = tg.tg_traffic_control(action='run', stream_handle=tr1['stream_id'])
    st.log("TR_CTRL: " + str(res))
    tg.tg_traffic_control(action='stop', stream_handle=tr1['stream_id'])
    st.log("Checking the stats and verifying the traffic flow")
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P2],
            'tx_obj': [tg_handler["tg"]],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P2],
            'rx_obj': [tg_handler["tg"]],
        }
    }
    # verify statistics
    aggrResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if not aggrResult:
        return False
    else:
        return True


@pytest.mark.ip_basic_ping
@pytest.mark.community
@pytest.mark.community_fail
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_ping_vlan '])
@pytest.mark.inventory(testcases=['ft_ipv6_address_check '])
@pytest.mark.inventory(testcases=['ft_ipv4_address_check '])
def test_ft_ping_v4_v6_vlan():
    # Objective - Verify that IPv6 & Ipv4 ping is successful over vlan routing interfaces.
    st.log("Checking IPv4 ping from {} to {} over vlan routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping(vars.D1, data.ip4_addr[3], family=data.af_ipv4, count=1):
        st.report_fail("ping_fail", data.ip4_addr[2], data.ip4_addr[3])
    st.log("Checking IPv6 ping from {} to {} over vlan routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping(vars.D2, data.ip6_addr[2], family=data.af_ipv6, count=1):
        st.report_fail("ping_fail", data.ip6_addr[3], data.ip6_addr[2])
    st.report_pass("test_case_passed")


@pytest.mark.ip_basic_ping
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_ping_after_ip_change'])
@pytest.mark.inventory(testcases=['ft_ping6_after_ip_change'])
@pytest.mark.inventory(testcases=['ft_ip6_address_check_pc'])
@pytest.mark.inventory(testcases=['ft_ip_address_check_pc'])
@pytest.mark.inventory(release='Buzznik', testcases=['CETA_SONIC_40640'])
def test_ft_ping_v4_v6_after_ip_change_pc():
    # Objective - Verify that ping is successful between L3 interfaces when Ip address is removed and new ip
    # is assigned
    result = True
    st.log("In {} check portchannel is UP or not".format(vars.D2))
    if not pc_obj.verify_portchannel_state(vars.D2, data.port_channel, state="up"):
        st.report_fail("portchannel_state_fail", data.port_channel, vars.D2, "Up")
    st.log("Checking IPv4 ping from {} to {} over portchannel routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping_poll(vars.D1, data.ip4_addr[5], family=data.af_ipv4, iter=5, count=1):
        st.report_fail("ping_fail", data.ip4_addr[4], data.ip4_addr[5])
    st.log("Checking IPv6 ping from {} to {} over portchannel routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping_poll(vars.D2, data.ip6_addr[4], family=data.af_ipv6, iter=5, count=1):
        st.report_fail("ping_fail", data.ip6_addr[5], data.ip6_addr[4])
    st.log("Removing the Ipv4 address on portchannel")
    ipfeature.delete_ip_interface(vars.D1, data.port_channel, data.ip4_addr[4], 24, family=data.af_ipv4)
    ipfeature.delete_ip_interface(vars.D2, data.port_channel, data.ip4_addr[5], 24, family=data.af_ipv4)
    st.log("Removing the Ipv6 address on portchannel")
    ipfeature.delete_ip_interface(vars.D1, data.port_channel, data.ip6_addr[4], 96, family=data.af_ipv6)
    ipfeature.delete_ip_interface(vars.D2, data.port_channel, data.ip6_addr[5], 96, family=data.af_ipv6)
    st.log("configuring new Ipv4 address on portchannel")
    ipfeature.config_ip_addr_interface(vars.D1, data.port_channel, data.ip4_addr[10], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D2, data.port_channel, data.ip4_addr[11], 24, family=data.af_ipv4)
    st.log("configuring new Ipv6 address on portchannel")
    ipfeature.config_ip_addr_interface(vars.D1, data.port_channel, data.ip6_addr[10],
                                       96, family=data.af_ipv6)
    st.log("configuring  Ipv6 neighbour address on portchannel")
    if not arp_obj.config_static_ndp(vars.D1, data.ip6_addr[11], data.tg_mac1, data.port_channel):
        st.log("Failed to config ipv6 neigbour address on portchannel")
    if not arp_obj.verify_ndp(vars.D1, inet6_address=data.ip6_addr[11], interface=data.port_channel):
        result = False
        report_tc_fail("CETA_SONIC_40640", "msg", "Failed to validate ipv6 address on portchannel")
    st.log("unconfiguring  Ipv6 neighbour address on portchannel")
    if not arp_obj.config_static_ndp(vars.D1, data.ip6_addr[11], data.tg_mac1, data.port_channel, operation="del"):
        st.log("Failed to unconfig ipv6 neigbour address on portchannel")
    ipfeature.config_ip_addr_interface(vars.D2, data.port_channel, data.ip6_addr[11], 96, family=data.af_ipv6)
    st.log("After Ipv4 address change, checking IPv4 ping from {} to {} over portchannel "
           "routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping_poll(vars.D1, data.ip4_addr[11], family=data.af_ipv4, iter=5, count=1):
        st.report_fail("ping_fail", data.ip4_addr[10], data.ip4_addr[11])
    st.log("After Ipv6 address change, checking IPv6 ping from {} to {} over portchannel "
           "routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping_poll(vars.D1, data.ip6_addr[11], family=data.af_ipv6, iter=5, count=1):
        st.report_fail("ping_fail", data.ip6_addr[10], data.ip6_addr[11])
    if not result:
        st.report_fail("test_case_failed")
    st.report_pass("test_case_passed")


@pytest.mark.ip6_basic
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_ip6_connected_host_traffic_forward'])
@pytest.mark.inventory(testcases=['ft_ip6_static_route_traffic_fwd_blackhole '])
@pytest.mark.inventory(testcases=['ft_ip6_static_route_traffic_forward '])
@pytest.mark.inventory(feature='RIF Counters', release='Cyrus4.0.0', testcases=['RIF_COUNT_FUNC_0031'])
def test_ft_ip6_static_route_traffic_forward_blackhole():
    # Objective - Verify the Ipv6 traffic forwarding over static route.
    tg_handler = tgapi.get_handles_byname("T1D1P2", "T1D2P2")
    tg = tg_handler["tg"]
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    dut_rt_int_mac1 = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P2)
    h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config', ipv6_intf_addr=data.ip6_addr[0],
                                ipv6_prefix_length='64', ipv6_gateway=data.ip6_addr[1],
                                src_mac_addr=data.tg_mac1, arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config', ipv6_intf_addr=data.ip6_addr[9],
                                ipv6_prefix_length='64', ipv6_gateway=data.ip6_addr[8],
                                src_mac_addr=data.tg_mac2, arp_send_req='1')
    st.log("INTFCONF: " + str(h2))

    # Ping from tgen to DUT.
    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=h1['handle'], dst_ip=data.ip6_addr[1],
                            ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")

    tr1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create', transmit_mode='single_burst',
                               pkts_per_burst=data.pkts_per_burst,
                               length_mode='fixed', rate_pps=data.rate_pps, l3_protocol='ipv6', mac_src=data.tg_mac1,
                               mac_dst=dut_rt_int_mac1, ipv6_src_addr=data.ip6_addr[0],
                               ipv6_dst_addr=data.ip6_addr[9])
    st.log("TRAFCONF: " + str(tr1))

    res = tg.tg_traffic_control(action='run', stream_handle=tr1['stream_id'])
    st.log("TR_CTRL: " + str(res))
    tg.tg_traffic_control(action='stop', stream_handle=tr1['stream_id'])
    st.log("Checking the stats and verifying the traffic flow")
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P2],
            'tx_obj': [tg_handler["tg"]],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P2],
            'rx_obj': [tg_handler["tg"]],
        }
    }
    # verify statistics
    aggrResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if data.rif_supported_1 and data.rif_supported_2:
        st.banner("Validating RIF Counters for ipv6 Traffic")
        tx = {'dut': vars.D1, 'interface': vars.D1D2P4, 'count_type': 'tx_ok'}
        rx = {'dut': vars.D2, 'interface': vars.D2D1P4, 'count_type': 'rx_ok'}
        result_1 = rifcounter_validation(tx=tx, rx=rx)
    else:
        st.report_tc_unsupported("RIF_COUNT_FUNC_001", "rif_counters_update", "unsupported", "Physical-Interface")
    if aggrResult is False:
        intf_obj.show_specific_interface_counters(vars.D2, [vars.D2D1P4, vars.D2T1P1, vars.D2T1P2])
        intf_obj.show_specific_interface_counters(vars.D1, [vars.D1D2P4, vars.D1T1P1, vars.D1T1P2])
        st.report_fail("traffic_verification_failed")
    ipfeature.delete_static_route(vars.D1, data.ip6_addr[7], data.static_ip6_rt, shell=data.shell_vtysh,
                                  family=data.af_ipv6)
    st.log("Create a static route with nexthop as blackhole")
    ipfeature.create_static_route(vars.D1, data.static_ip6_rt_drop, data.static_ip6_rt, shell=data.shell_vtysh,
                                  family=data.af_ipv6)
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    res = tg.tg_traffic_control(action='run', stream_handle=tr1['stream_id'])
    st.log("TR_CTRL: " + str(res))
    tg.tg_traffic_control(action='stop', stream_handle=tr1['stream_id'])
    st.log("Checking the stats and verifying the traffic flow")
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P2],
            'tx_obj': [tg_handler["tg"]],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P2],
            'rx_obj': [tg_handler["tg"]],
        }
    }

    # verify statistics
    aggrResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if data.rif_supported_1 and data.rif_supported_2:
        result_2 = rifcounter_validation(tx=tx, rx=rx)
        if result_1 is False or result_2 is False:
            report_tc_fail("RIF_COUNT_FUNC_031", "rif_counters_update", "Failed", "Physical_Interface")
        else:
            st.report_tc_pass("RIF_COUNT_FUNC_031", "rif_counters_update", "Successful", "Physical_Interface")
    else:
        st.report_tc_unsupported("RIF_COUNT_FUNC_031", "rif_counters_update", "unsupported", "Physical-Interface")

    if aggrResult is True:
        st.report_fail("traffic_verification_failed")
    st.report_pass("test_case_passed")


@pytest.mark.ip_basic13
@pytest.mark.inventory(feature='RIF Counters', release='Cyrus4.0.0')
@pytest.mark.inventory(feature='Regression', release='Arlo+', testcases=['ft_ip_static_route_traffic_forward'])
@pytest.mark.inventory(testcases=['RIF_COUNT_FUNC_021'])
@pytest.mark.inventory(testcases=['RIF_COUNT_FUNC_001'])
def test_ft_ip_static_route_traffic_forward():
    # Objective - Verify the Ipv4 traffic forwarding over IPv4 static route.
    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D2P1")
    result = 0
    tg = tg_handler["tg"]
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    dut_rt_int_mac1 = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config', intf_ip_addr=data.ip4_addr[0],
                                gateway=data.ip4_addr[1], src_mac_addr=data.tg_mac1, arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config', intf_ip_addr=data.ip4_addr[9],
                                gateway=data.ip4_addr[8], src_mac_addr=data.tg_mac2, arp_send_req='1')
    st.log("INTFCONF: " + str(h2))
    # Ping from tgen to DUT.
    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=h1['handle'], dst_ip=data.ip4_addr[1],
                            ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")
    tr1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create', transmit_mode='single_burst',
                               pkts_per_burst=data.pkts_per_burst,
                               length_mode='fixed', rate_pps=data.rate_pps, l3_protocol='ipv4', mac_src=data.tg_mac1,
                               mac_dst=dut_rt_int_mac1, ip_src_addr=data.ip4_addr[0],
                               ip_dst_addr=data.ip4_addr[9])
    st.log("TRAFCONF: " + str(tr1))
    res = tg.tg_traffic_control(action='run', stream_handle=tr1['stream_id'])
    st.log("TR_CTRL: " + str(res))
    st.log("Checking the stats and verifying the traffic flow")
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg_handler["tg"]],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [tg_handler["tg"]],
        }
    }
    # verify statistics
    aggrResult1 = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    tg.tg_traffic_control(action='stop', stream_handle=tr1['stream_id'])
    if data.rif_supported_1 and data.rif_supported_2:
        st.banner("Validating ipv4 RIF counters on Physical Port")
        tx = {'dut': vars.D1, 'interface': vars.D1D2P4, 'count_type': 'tx_ok'}
        rx = {'dut': vars.D2, 'interface': vars.D2D1P4, 'count_type': 'rx_ok'}
        result1 = rifcounter_validation(tx=tx, rx=rx)
        intf_obj.interface_operation(vars.D1, interfaces=vars.D1D2P4)
        st.wait(5, "Waiting for port operational convergence")
        intf_obj.interface_operation(vars.D1, interfaces=vars.D1D2P4, operation='startup')
        intf_obj.poll_for_interface_status(vars.D1, interface=vars.D1D2P4, property='oper', value='up', iteration=5, delay=2)
        f1 = lambda: intf_obj.clear_interface_counters(vars.D1, rif=True)
        f2 = lambda: intf_obj.clear_interface_counters(vars.D2, rif=True)
        st.exec_all([[f1], [f2]])
        tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])
        tg.tg_traffic_control(action='run', stream_handle=tr1['stream_id'])
        tg.tg_traffic_control(action='stop', stream_handle=tr1['stream_id'])
        aggrResult2 = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
        result2 = rifcounter_validation(tx=tx, rx=rx)
        st.exec_all([[f1], [f2]])
    else:
        aggrResult2 = result1 = result2 = True
        st.report_tc_unsupported("RIF_COUNT_FUNC_001", "rif_counters_update", "unsupported", "Physical-Interface")
        st.report_tc_unsupported("RIF_COUNT_FUNC_021", "rif_counters_update", "unsupported", "Phy_Shut_noShut")

    if aggrResult2 is False or result2 is False:
        report_tc_fail("RIF_COUNT_FUNC_021", "rif_counters_update", "Failed", "Phy_Shut_noShut")
        result += 1
    else:
        st.report_tc_pass("RIF_COUNT_FUNC_021", "rif_counters_update", "Successful", "Phy_Shut_noShut")

    if result1 is False:
        report_tc_fail("RIF_COUNT_FUNC_001", "rif_counters_update", "Failed", "Physical_Interface")
        result += 1
    else:
        st.report_tc_pass("RIF_COUNT_FUNC_001", "rif_counters_update", "Successful", "Physical_Interface")

    if aggrResult1 is False:
        intf_obj.show_interface_counters_all(vars.D2)
        intf_obj.show_interface_counters_all(vars.D1)
        result += 1

    if result == 0:
        st.report_pass("test_case_passed")
    else:
        st.banner("Verification of Ipv4 traffic forwarding over IPv4 static route Failed")
        st.report_fail("test_case_failed")


@pytest.mark.ip_basic_L2_L3_translation
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_ip_L2_L3_translation'])
@pytest.mark.inventory(testcases=['ft_ip6_L2_L3_translation'])
def test_ft_ip_v4_v6_L2_L3_translation():
    # Objective - Verify that L2 port to IPv4 L3 port transition and vice-versa is successful.
    st.log("Checking IPv4 ping from {} to {} over  routing interface".format(vars.D1, vars.D2))
    st.wait(5, 'adding delay after creating routing interface')
    if not ipfeature.ping(vars.D1, data.ip4_addr[7], family=data.af_ipv4, count=3):
        st.report_fail("ping_fail", data.ip4_addr[6], data.ip4_addr[7])
    st.log("Checking IPv6 ping from {} to {} over vlan routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping(vars.D2, data.ip6_addr[6], family=data.af_ipv6, count=3):
        st.report_fail("ping_fail", data.ip6_addr[7], data.ip6_addr[6])
    st.log("L3 to L2 port transition")
    st.log("Removing the static routes")
    ipfeature.delete_static_route(vars.D1, data.static_ip6_rt_drop, data.static_ip6_rt, shell=data.shell_vtysh, family=data.af_ipv6)
    ipfeature.delete_static_route(vars.D1, data.ip4_addr[7], data.static_ip_rt, shell=data.shell_vtysh, family=data.af_ipv4)
    ipfeature.delete_static_route(vars.D1, data.ip6_addr[7], data.static_ip6_rt, shell=data.shell_vtysh, family=data.af_ipv6)
    st.log("Removing ipv4,ipv6 address from interface")
    ipfeature.delete_ip_interface(vars.D1, vars.D1D2P4, data.ip4_addr[6], 24, family=data.af_ipv4)
    ipfeature.delete_ip_interface(vars.D2, vars.D2D1P4, data.ip4_addr[7], 24, family=data.af_ipv4)
    ipfeature.delete_ip_interface(vars.D1, vars.D1D2P4, data.ip6_addr[6], 96, family=data.af_ipv6)
    ipfeature.delete_ip_interface(vars.D2, vars.D2D1P4, data.ip6_addr[7], 96, family=data.af_ipv6)
    ipfeature.delete_ip_interface(vars.D1, vars.D1T1P1, data.ip4_addr[1], 24, family=data.af_ipv4)
    ipfeature.delete_ip_interface(vars.D2, vars.D2T1P1, data.ip4_addr[8], 24, family=data.af_ipv4)
    st.log("Vlan creation and port association configuration")
    vlan_obj.create_vlan(vars.D1, data.vlan_2)
    st.log("Adding back to back connecting ports to vlan {}".format(data.vlan_2))
    vlan_obj.add_vlan_member(vars.D1, data.vlan_2, [vars.D1D2P4], tagging_mode=True)
    vlan_obj.create_vlan(vars.D2, data.vlan_2)
    vlan_obj.add_vlan_member(vars.D2, data.vlan_2, [vars.D2D1P4], tagging_mode=True)
    st.log("Adding TG connecting ports to vlan {}".format(data.vlan_1))
    vlan_obj.add_vlan_member(vars.D1, data.vlan_2, vars.D1T1P1, tagging_mode=True)
    vlan_obj.add_vlan_member(vars.D2, data.vlan_2, vars.D2T1P1, tagging_mode=True)
    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D2P1")
    tg = tg_handler["tg"]
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    tr2 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], mode='create', rate_pps=data.rate_pps,
                               mac_src_mode="fixed",
                               transmit_mode="single_burst", pkts_per_burst=data.pkts_per_burst,
                               length_mode='fixed', l2_encap='ethernet_ii_vlan',
                               vlan_id=data.vlan_2, mac_dst_mode="fixed",
                               vlan="enable",
                               mac_src="00:a1:bb:cc:dd:01",
                               mac_dst="00:b1:bb:cc:dd:01")
    st.log("TRAFCONF: " + str(tr2))
    res = tg.tg_traffic_control(action='run', stream_handle=tr2['stream_id'])
    tg.tg_traffic_control(action='stop', stream_handle=tr2['stream_id'])
    st.wait(data.wait_tgstats)
    st.log("TR_CTRL: " + str(res))
    st.log("Fetching TGen statistics")
    stats_tg1 = tgapi.get_traffic_stats(tg_handler["tg"], mode="aggregate", port_handle=tg_handler["tg_ph_2"])
    total_tx_tg1 = stats_tg1.tx.total_packets
    stats_tg2 = tgapi.get_traffic_stats(tg_handler["tg"], mode="aggregate", port_handle=tg_handler["tg_ph_1"])
    total_rx_tg2 = stats_tg2.rx.total_packets
    st.log("total_tx_tg1 = {}".format(total_tx_tg1))
    total_tx_tg1_95_percentage = int(total_tx_tg1) * 0.95
    st.log("total_tx_tg1_95_percentage= {}".format(total_tx_tg1_95_percentage))
    st.log("total_rx_tg2 = {}".format(total_rx_tg2))
    if int(total_tx_tg1_95_percentage) > int(total_rx_tg2):
        st.report_fail("traffic_verification_failed")
    st.log("Removing vlan configuration")
    vlan_obj.delete_vlan_member(vars.D1, data.vlan_2, [vars.D1D2P4, vars.D1T1P1], True)
    vlan_obj.delete_vlan_member(vars.D2, data.vlan_2, [vars.D2D1P4, vars.D2T1P1], True)
    st.log("L2 to L3 port transition")
    ipfeature.config_ip_addr_interface(vars.D1, vars.D1D2P4, data.ip4_addr[6], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D2, vars.D2D1P4, data.ip4_addr[7], 24, family=data.af_ipv4)
    ipfeature.create_static_route(vars.D1, data.ip4_addr[7], data.static_ip_rt, shell=data.shell_vtysh, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D1, vars.D1D2P4, data.ip6_addr[6], 96, family=data.af_ipv6)
    ipfeature.config_ip_addr_interface(vars.D2, vars.D2D1P4, data.ip6_addr[7], 96, family=data.af_ipv6)
    ipfeature.create_static_route(vars.D1, data.static_ip6_rt_drop, data.static_ip6_rt, shell=data.shell_vtysh, family=data.af_ipv6)
    st.log("Checking IPv4 ping from {} to {} over routing interface".format(vars.D1, vars.D2))
    st.wait(5, 'adding delay after creating routing interface')
    if not ipfeature.ping(vars.D1, data.ip4_addr[7], family=data.af_ipv4, count=3):
        st.report_fail("ping_fail", data.ip4_addr[6], data.ip4_addr[7])
    st.log("Checking IPv6 ping from {} to {} over vlan routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping(vars.D2, data.ip6_addr[6], family=data.af_ipv6, count=3):
        st.report_fail("ping_fail", data.ip6_addr[7], data.ip6_addr[6])
    ipfeature.delete_static_route(vars.D1, data.static_ip6_rt_drop, data.static_ip6_rt, shell=data.shell_vtysh, family=data.af_ipv6)
    ipfeature.create_static_route(vars.D1, data.ip6_addr[7], data.static_ip6_rt, shell=data.shell_vtysh, family=data.af_ipv6)
    st.report_pass("test_case_passed")


@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Buzznik')
@pytest.mark.inventory(testcases=['ipv4_intf_order'])
@pytest.mark.inventory(testcases=['ipv6_intf_order'])
def test_ft_verify_interfaces_order(ft_verify_interfaces_order_hooks):
    '''
    @author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    ipv4_intf_order :  Verify order of interfaces in "show ip interfaces"
    ipv6_intf_order :  Verify order of interfaces in "show ipv6 interfaces'
    Verify order of interfaces in "show ip/ipv6 interfaces" in sorted order or not

    :return:
    '''
    err_list = []
    st.log("This test is to ensure that interfaces are listed in sorted order by 'interface name' in 'show ip/ipv6 "
           "interfaces'")
    free_ports = st.get_free_ports(vars.D1)
    if len(free_ports) < data.no_of_ports:
        data.no_of_ports = len(free_ports)
    data.req_ports = random.sample(free_ports, data.no_of_ports)
    ipv4_addr = data.ip4_addr[11] + '/' + data.ipv4_mask
    ipv6_addr = data.ip6_addr[0] + '/' + data.ipv6_mask
    intf_list = []
    for i in range(int(math.ceil(float(data.no_of_ports) / 2))):
        _, ipv4_addr = ipfeature.increment_ip_addr(ipv4_addr, "network")
        ipfeature.config_ip_addr_interface(vars.D1, interface_name=data.req_ports[i], ip_address=ipv4_addr.split('/')[0],
                                           subnet=data.ipv4_mask, family="ipv4")
    for i in range(int(math.floor(float(data.no_of_ports) / 2))):
        _, ipv6_addr = ipfeature.increment_ip_addr(ipv6_addr, "network", family="ipv6")
        ipfeature.config_ip_addr_interface(vars.D1, interface_name=data.req_ports[i + int(math.ceil(float(data.no_of_ports) / 2))],
                                           ip_address=ipv6_addr.split('/')[0], subnet=data.ipv6_mask, family="ipv6")
    output = ipfeature.get_interface_ip_address(vars.D1)
    for each in output:
        if each['interface'] == 'Management0':
            continue
        intf_list.append(each['interface'])
    temp = lambda text: int(text) if text.isdigit() else text
    alphanum_key = lambda key: [temp(c) for c in re.split('([0-9]+)', key)]
    intf_list_sorted = sorted(intf_list, key=alphanum_key)
    if intf_list == intf_list_sorted:
        st.log("Ipv4 interfaces are in sorted order")
    else:
        err = st.error("Ipv4 interfaces are not in soretd order")
        err_list.append(err)
    del intf_list[:]
    del intf_list_sorted[:]
    output = ipfeature.get_interface_ip_address(vars.D1, family="ipv6")
    for each in output:
        if each['interface'] == 'Management0':
            continue
        intf_list.append(each['interface'])
    temp = lambda text: int(text) if text.isdigit() else text
    alphanum_key = lambda key: [temp(c) for c in re.split('([0-9]+)', key)]
    intf_list_sorted = sorted(intf_list, key=alphanum_key)
    if intf_list == intf_list_sorted:
        st.log("Ipv6 interfaces are in sorted order")
    else:
        err = st.error("Ipv6 interfaces are not in sorted order")
        err_list.append(err)

    st.report_result(err_list)


@pytest.fixture(scope="function")
def ft_verify_interfaces_order_hooks():
    yield
    ipv4_addr = data.ip4_addr[11] + '/' + data.ipv4_mask
    ipv6_addr = data.ip6_addr[0] + '/' + data.ipv6_mask
    for i in range(int(math.ceil(float(data.no_of_ports) / 2))):
        _, ipv4_addr = ipfeature.increment_ip_addr(ipv4_addr, "network")
        ipfeature.delete_ip_interface(vars.D1, interface_name=data.req_ports[i], ip_address=ipv4_addr.split('/')[0],
                                      subnet=data.ipv4_mask, family="ipv4")
    for i in range(int(math.floor(float(data.no_of_ports) / 2))):
        _, ipv6_addr = ipfeature.increment_ip_addr(ipv6_addr, "network", family="ipv6")
        ipfeature.delete_ip_interface(vars.D1, interface_name=data.req_ports[i + int(math.ceil(float(data.no_of_ports) / 2))],
                                      ip_address=ipv6_addr.split('/')[0], subnet=data.ipv6_mask, family="ipv6")


@pytest.fixture(scope="function")
def ceta_31902_fixture(request):
    ipfeature.config_ip_addr_interface(vars.D1, vars.D1T1P2, data.ip6_addr[1],
                                       96, family=data.af_ipv6, config="remove")
    vlan_obj.create_vlan(vars.D1, [data.host1_vlan, data.host2_vlan])
    vlan_obj.create_vlan(vars.D2, [data.host1_vlan])
    vlan_obj.add_vlan_member(vars.D1, data.host1_vlan, [vars.D1T1P1, vars.D1T1P2], tagging_mode=True)
    vlan_obj.add_vlan_member(vars.D1, data.host2_vlan, [vars.D1T1P1, vars.D1T1P2], tagging_mode=True)
    vlan_obj.add_vlan_member(vars.D2, data.host1_vlan, [vars.D2T1P1], tagging_mode=True)
    ipfeature.config_ip_addr_interface(vars.D1, "Vlan" + data.host1_vlan, data.vlan1_ip, 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D1, "Vlan" + data.host2_vlan, data.vlan2_ip, 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D2, "Vlan" + data.host1_vlan, data.d2t1_ip, 24, family=data.af_ipv4)
    ipfeature.create_static_route(dut=vars.D2, next_hop=data.ip4_addr[2],
                                  static_ip=data.d2_static_route, interface=data.vlan_int_1)
    ipfeature.create_static_route(dut=vars.D1, next_hop=data.ip4_addr[3],
                                  static_ip=data.d1_static_route, interface=data.vlan_int_1)
    yield
    ipfeature.delete_static_route(dut=vars.D2, next_hop=data.ip4_addr[2],
                                  static_ip=data.d2_static_route, interface=data.vlan_int_1)
    ipfeature.delete_static_route(dut=vars.D1, next_hop=data.ip4_addr[3],
                                  static_ip=data.d1_static_route, interface=data.vlan_int_1)
    ipfeature.delete_ip_interface(vars.D1, "Vlan" + data.host1_vlan, data.vlan1_ip, "24", family="ipv4")
    ipfeature.delete_ip_interface(vars.D1, "Vlan" + data.host2_vlan, data.vlan2_ip, "24", family="ipv4")
    ipfeature.delete_ip_interface(vars.D2, "Vlan" + data.host1_vlan, data.d2t1_ip, 24, family="ipv4")
    vlan_obj.delete_vlan_member(vars.D1, data.host1_vlan, [vars.D1T1P1, vars.D1T1P2], True)
    vlan_obj.delete_vlan_member(vars.D1, data.host2_vlan, [vars.D1T1P1, vars.D1T1P2], True)
    vlan_obj.delete_vlan_member(vars.D2, data.host1_vlan, [vars.D2T1P1], True)
    vlan_obj.delete_vlan(vars.D1, [data.host1_vlan, data.host2_vlan])
    vlan_obj.delete_vlan(vars.D2, [data.host1_vlan])
    ipfeature.config_ip_addr_interface(vars.D1, vars.D1T1P2, data.ip6_addr[1], 96, family=data.af_ipv6)


def rifcounter_validation(tx={}, rx={}, verify_count_check=True, update_count_check=False, zero_count_check=False, tolerance=0.9):
    """
    Helper function to validate the rif counters.
    rifcounter_validation(tx_intf={'dut':rifcounter.dut1,'interface':'Ethernet1','count_type':'tx_ok'}, rx_intf={'dut':rifcounter.dut1,'interface':'Ethernet2','count_type':'tx_ok'})
    :param dut:
    :param tx_intf:
    :param rx_intf:
    :return:
    """
    dut1 = tx['dut']
    dut2 = rx['dut']
    tx_intf = tx['interface']
    rx_intf = rx['interface']
    tx_intf_count_type = tx['count_type']
    rx_intf_count_type = rx['count_type']
    result = False
    if str(dut1) == str(dut2):
        tx_count_val = intf_obj.show_interfaces_counters(dut=vars.D1, interface=[tx_intf], rif='yes')
        rx_count_val = intf_obj.show_interfaces_counters(dut=vars.D1, interface=[rx_intf], rif='yes')
        if not (tx_count_val and rx_count_val):
            st.error("Interface RIF Counters are not retrieved")
            return result
        if not (tx_count_val[0][tx_intf_count_type] and rx_count_val[0][rx_intf_count_type]):
            st.error("Interface RIF Counters for counter_type {} and {} not updated".format(tx_intf_count_type, rx_intf_count_type))
            return result
        tx_intf_count_val = int(tx_count_val[0][tx_intf_count_type].replace(',', ''))
        rx_intf_count_val = int(rx_count_val[0][rx_intf_count_type].replace(',', ''))
    else:
        count_output = st.exec_all([[intf_obj.show_interfaces_counters, vars.D1, [tx_intf], '', 'yes'], [intf_obj.show_interfaces_counters, vars.D2, [rx_intf], '', 'yes']])
        d1_count_val = count_output[0][0]
        d2_count_val = count_output[0][1]
        if not (d1_count_val and d2_count_val):
            st.error("Interface RIF Counters are not retrieved")
            return result
        if not (d1_count_val[0][tx_intf_count_type] and d2_count_val[0][rx_intf_count_type]):
            st.error(st.error("Interface RIF Counters for counter_type {} and {} not updated".format(tx_intf_count_type, rx_intf_count_type)))
            return result
        tx_intf_count_val = int(d1_count_val[0][tx_intf_count_type].replace(',', ''))
        rx_intf_count_val = int(d2_count_val[0][rx_intf_count_type].replace(',', ''))
    if zero_count_check:
        if not (tx_intf_count_val == 0 and rx_intf_count_val == 0):
            st.error("RIF counters are not reset to zero")
            return result
        else:
            st.log("RIF counters are reset to zero")
            return True
    if update_count_check:
        if not (tx_intf_count_val > 0 and rx_intf_count_val > 0):
            st.error("RIF counters are not updated")
            return result
        else:
            st.log("RIF counters are updated")
            return True
    if verify_count_check:
        if tx_intf_count_val >= tolerance * rx_intf_count_val:
            result = True
        else:
            return result
    return result
