
import random
import math
import re
import pytest

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list

import apis.routing.ip as ipfeature
import apis.switching.vlan as vlan_obj
import apis.switching.portchannel as pc_obj
import apis.system.basic as basic_obj
import apis.switching.portchannel as portchannel_obj
import apis.common.asic as asicapi
import apis.routing.bgp as bgpfeature

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
data.rate_pps = 2000
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

@pytest.fixture(scope="module", autouse=True)
def ip_module_hooks(request):
    global vars, tg_handler, tg
    # Min topology verification
    st.log("Ensuring minimum topology")
    vars = st.ensure_min_topology("D1T1:2", "D2T1:2", "D1D2:4")

    # Initialize TG and TG port handlers
    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D1P2", "T1D2P1", "T1D2P2")
    tg = tg_handler["tg"]

    # IP module configuration
    st.log("Vlan routing configuration on D1D2P1,D2D1P1")
    vlan_obj.create_vlan(vars.D1, data.vlan_1)
    vlan_obj.add_vlan_member(vars.D1, data.vlan_1, [vars.D1D2P1], tagging_mode=True)
    vlan_obj.create_vlan(vars.D2, data.vlan_1)
    vlan_obj.add_vlan_member(vars.D2, data.vlan_1, [vars.D2D1P1], tagging_mode=True)
    ipfeature.config_ip_addr_interface(vars.D1, data.vlan_int_1, data.ip4_addr[2], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D1, data.vlan_int_1, data.ip6_addr[2], 96, family=data.af_ipv6)
    ipfeature.config_ip_addr_interface(vars.D2, data.vlan_int_1, data.ip4_addr[3],24, family = data.af_ipv4)
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
    st.log("configuring the dut1 ports connected to ixias with ip addresses")
    ipfeature.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.ip4_addr[1], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D1, vars.D1T1P2, data.ip6_addr[1], 96, family=data.af_ipv6)
    ipfeature.create_static_route(vars.D1, data.ip6_addr[7], data.static_ip6_rt, shell=data.shell_vtysh,
                              family=data.af_ipv6)
    ipfeature.create_static_route(vars.D1, data.ip4_addr[7], data.static_ip_rt, shell=data.shell_vtysh,
                                  family=data.af_ipv4)
    st.log("configuring the dut2 ports connected to ixias with ip addresses")
    ipfeature.config_ip_addr_interface(vars.D2, vars.D2T1P1, data.ip4_addr[8], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D2, vars.D2T1P2, data.ip6_addr[8], 96, family=data.af_ipv6)

    yield
    ipfeature.clear_ip_configuration(st.get_dut_names())
    ipfeature.clear_ip_configuration(st.get_dut_names(), 'ipv6')
    vlan_obj.clear_vlan_configuration(st.get_dut_names())
    portchannel_obj.clear_portchannel_configuration(st.get_dut_names())
    ipfeature.delete_static_route(vars.D1, data.ip4_addr[7], data.static_ip_rt, shell=data.shell_vtysh,
                                  family=data.af_ipv4)
    ipfeature.delete_static_route(vars.D1, data.static_ip6_rt_drop, data.static_ip6_rt, shell=data.shell_vtysh,
                                  family=data.af_ipv6)

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
    my_cmd = "router bgp {}".format(as_num)
    st.vtysh_config(dut, my_cmd)
    my_cmd = "no bgp router-id {}".format(router_id)

def create_bgp_neighbor_route_map_config(dut, local_asn, neighbor_ip, routemap):
    command = "route-map {} permit 10".format(routemap)
    st.vtysh_config(dut, command)
    command = "set ipv6 next-hop prefer-global"
    st.vtysh_config(dut, command)
    command = "router bgp {}".format(local_asn)
    st.vtysh_config(dut, command)
    command = "address-family ipv6 unicast"
    st.vtysh_config(dut, command)
    command = "neighbor {} route-map {} in".format(neighbor_ip, routemap)
    st.vtysh_config(dut, command)
    command = "neighbor {} route-map {} out".format(neighbor_ip, routemap)
    return

def create_v4_route(route_count):
    vars = st.get_testbed_vars()
    dut = vars.D1

    st.show(dut, "show ip interfaces")
    st.show(dut, "show ip route")
    st.show(dut, "show interface status",skip_tmpl=True)

    bgpfeature.create_bgp_router(dut, data.as_num, '')
    bgpfeature.create_bgp_neighbor(dut, data.as_num, data.ip4_addr[0], data.remote_as_num)

    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D2P1")
    tg = tg_handler["tg"]
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    dut_rt_int_mac1 = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config', intf_ip_addr=data.ip4_addr[0], \
                                gateway=data.ip4_addr[1], src_mac_addr=data.tg_mac1, arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config', intf_ip_addr=data.ip4_addr[9], \
                                gateway=data.ip4_addr[8], src_mac_addr=data.tg_mac2, arp_send_req='1')
    st.log("INTFCONF: " + str(h2))
    # Ping from tgen to DUT.
    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=h1['handle'], dst_ip=data.ip4_addr[1], \
                      ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")

    conf_var = { 'mode'                  : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : '200',
                 'remote_as'             : '100',
                 'remote_ip_addr'        : data.ip4_addr[1]
               }
    route_var = { 'mode'       : 'add',
                  'num_routes' :  route_count,
                  'prefix'     : '121.1.1.0',
                  'as_path'    : 'as_seq:1'
                }
    ctrl_start = { 'mode' : 'start'}

    # Configuring the BGP router.
    bgp_rtr1 = tgapi.tg_bgp_config(tg = tg,
        handle    = h1['handle'],
        conf_var  = conf_var,
        route_var = route_var,
        ctrl_var  = ctrl_start)

    st.log("BGP_HANDLE: "+str(bgp_rtr1))
    st.log("waiting for 10 sec to get the BGP neighbor started before going for another TG operation")
    st.wait(10)
    # Verified at neighbor.
    tr1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create', transmit_mode='single_burst',
                               pkts_per_burst=2000, \
                               length_mode='fixed', rate_pps=2000, l3_protocol='ipv4', mac_src=data.tg_mac1, \
                               mac_dst=dut_rt_int_mac1, ip_src_addr=data.ip4_addr[0],
                               ip_dst_addr=data.ip4_addr[9])
    st.log("TRAFCONF: " + str(tr1))
    res = tg.tg_traffic_control(action='run', stream_handle=tr1['stream_id'])
    st.log("TR_CTRL: " + str(res))
    tg.tg_traffic_control(action='stop', stream_handle=tr1['stream_id'])
    st.log("Checking the stats and verifying the traffic flow")
    traffic_details = {
       '1': {
            'tx_ports' : [vars.T1D1P1],
            'tx_obj' : [tg_handler["tg"]],
            'exp_ratio' : [1],
            'rx_ports' : [vars.T1D2P1],
            'rx_obj' : [tg_handler["tg"]],
        }
    }
    #verify statistics
    aggrResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if not aggrResult:
      return False

    return True

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
    vars = st.get_testbed_vars()
    dut = vars.D1

    st.show(dut, "show ipv6 interfaces")
    st.show(dut, "show ipv6 route")

    bgpfeature.create_bgp_router(dut, data.as_num, '')
    bgpfeature.create_bgp_neighbor(dut, data.as_num, data.ip6_addr[0], data.remote_as_num, family="ipv6")
    create_bgp_neighbor_route_map_config(dut, data.as_num, data.ip6_addr[1], data.routemap)

    tg_handler = tgapi.get_handles_byname("T1D1P2", "T1D2P2")
    tg = tg_handler["tg"]
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    dut_rt_int_mac1 = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config', ipv6_intf_addr=data.ip6_addr[0], \
                                ipv6_prefix_length='64', ipv6_gateway=data.ip6_addr[1],
                                src_mac_addr=data.tg_mac1, arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config', ipv6_intf_addr=data.ip6_addr[9], \
                                ipv6_prefix_length='64', ipv6_gateway=data.ip6_addr[8],
                                src_mac_addr=data.tg_mac2, arp_send_req='1')
    st.log("INTFCONF: " + str(h2))

    # Ping from tgen to DUT.
    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=h1['handle'], dst_ip=data.ip6_addr[1], \
                      ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")

    bgp_conf=tg.tg_emulation_bgp_config(handle=h1['handle'], mode='enable', ip_version='6',
        active_connect_enable='1', local_as=data.as_num, remote_as=data.remote_as_num, remote_ipv6_addr=data.ip6_addr[1])

    tg.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', ip_version='6',
        num_routes=route_count, prefix='3300:1::', as_path='as_seq:1')
    tg.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')

    # Configuring the BGP router.
    st.log("BGP neighborship established.")
    tr1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create', transmit_mode='single_burst',
                               pkts_per_burst=2000, \
                               length_mode='fixed', rate_pps=2000, l3_protocol='ipv6', mac_src=data.tg_mac1, \
                               mac_dst=dut_rt_int_mac1, ipv6_src_addr=data.ip6_addr[0],
                               ipv6_dst_addr=data.ip6_addr[9])
    st.log("TRAFCONF: " + str(tr1))

    res = tg.tg_traffic_control(action='run', stream_handle=tr1['stream_id'])
    st.log("TR_CTRL: " + str(res))
    tg.tg_traffic_control(action='stop', stream_handle=tr1['stream_id'])
    st.log("Checking the stats and verifying the traffic flow")
    traffic_details = {
       '1': {
          'tx_ports' : [vars.T1D1P2],
          'tx_obj' : [tg_handler["tg"]],
          'exp_ratio' : [1],
          'rx_ports' : [vars.T1D2P2],
         'rx_obj' : [tg_handler["tg"]],
      }
    }
    # verify statistics
    aggrResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if not aggrResult:
      return False
    else:
      return True

def test_l3_v6_route_po_1():
    dut = vars.D1
    asicapi.dump_vlan(dut)
    asicapi.dump_l2(dut)
    asicapi.dump_trunk(dut)

    ret = create_v6_route(30000)
    if (ret):
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.ip_basic_ping
@pytest.mark.community
@pytest.mark.community_fail
def test_ft_ping_v4_v6_vlan():
    # Objective - Verify that IPv6 & Ipv4 ping is successful over vlan routing interfaces.
    st.log("Checking IPv4 ping from {} to {} over vlan routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping(vars.D1, data.ip4_addr[3], family=data.af_ipv4, count=1):
        st.report_fail("ping_fail",data.ip4_addr[2], data.ip4_addr[3])
    st.log("Checking IPv6 ping from {} to {} over vlan routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping(vars.D2, data.ip6_addr[2], family=data.af_ipv6, count=1):
        st.report_fail("ping_fail",data.ip6_addr[3], data.ip6_addr[2])
    st.report_pass("test_case_passed")


@pytest.mark.ip_basic_ping
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_ping__v4_v6_after_ip_change_pc():
    # Objective - Verify that ping is successful between L3 interfaces when Ip address is removed and new ip
    # is assigned
    st.log("In {} check portchannel is UP or not".format(vars.D2))
    if not pc_obj.verify_portchannel_state(vars.D2, data.port_channel, state="up"):
        st.report_fail("portchannel_state_fail", data.port_channel, vars.D2, "Up")
    st.log("Checking IPv4 ping from {} to {} over portchannel routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping(vars.D1, data.ip4_addr[5], family=data.af_ipv4, count=1):
        st.report_fail("ping_fail",data.ip4_addr[4], data.ip4_addr[5])
    st.log("Checking IPv6 ping from {} to {} over portchannel routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping(vars.D2, data.ip6_addr[4], family=data.af_ipv6, count=1):
        st.report_fail("ping_fail",data.ip6_addr[5], data.ip6_addr[4])
    st.log("Removing the Ipv4 address on portchannel")
    ipfeature.delete_ip_interface(vars.D1, data.port_channel, data.ip4_addr[4],24, family = data.af_ipv4)
    ipfeature.delete_ip_interface(vars.D2, data.port_channel, data.ip4_addr[5], 24, family = data.af_ipv4)
    st.log("Removing the Ipv6 address on portchannel")
    ipfeature.delete_ip_interface(vars.D1, data.port_channel, data.ip6_addr[4], 96, family = data.af_ipv6)
    ipfeature.delete_ip_interface(vars.D2, data.port_channel, data.ip6_addr[5], 96, family = data.af_ipv6)
    st.log("configuring new Ipv4 address on portchannel")
    ipfeature.config_ip_addr_interface(vars.D1, data.port_channel, data.ip4_addr[10], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D2, data.port_channel, data.ip4_addr[11], 24, family=data.af_ipv4)
    st.log("configuring new Ipv6 address on portchannel")
    ipfeature.config_ip_addr_interface(vars.D1, data.port_channel, data.ip6_addr[10],
        96, family = data.af_ipv6)
    ipfeature.config_ip_addr_interface(vars.D2, data.port_channel, data.ip6_addr[11], 96, family=data.af_ipv6)
    st.log("After Ipv4 address change, checking IPv4 ping from {} to {} over portchannel "
               "routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping(vars.D1, data.ip4_addr[11], family=data.af_ipv4, count=1):
        st.report_fail("ping_fail",data.ip4_addr[10],data.ip4_addr[11])
    st.log("After Ipv6 address change, checking IPv6 ping from {} to {} over portchannel "
               "routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping(vars.D1, data.ip6_addr[11], family=data.af_ipv6, count=1):
        st.report_fail("ping_fail",data.ip6_addr[10], data.ip6_addr[11])
    st.report_pass("test_case_passed")

@ pytest.mark.ip6_basic
def test_ft_ip6_static_route_traffic_forward_blackhole():
    # Objective - Verify the Ipv6 traffic forwarding over static route.
    tg_handler = tgapi.get_handles_byname("T1D1P2", "T1D2P2")
    tg = tg_handler["tg"]
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    dut_rt_int_mac1 = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P2)
    h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config', ipv6_intf_addr=data.ip6_addr[0], \
                                ipv6_prefix_length='64', ipv6_gateway=data.ip6_addr[1],
                                src_mac_addr=data.tg_mac1, arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config', ipv6_intf_addr=data.ip6_addr[9], \
                                ipv6_prefix_length='64', ipv6_gateway=data.ip6_addr[8],
                                src_mac_addr=data.tg_mac2, arp_send_req='1')
    st.log("INTFCONF: " + str(h2))

    # Ping from tgen to DUT.
    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=h1['handle'], dst_ip=data.ip6_addr[1], \
                      ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")

    tr1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create', transmit_mode='single_burst',
                               pkts_per_burst=2000, \
                               length_mode='fixed', rate_pps=2000, l3_protocol='ipv6', mac_src=data.tg_mac1, \
                               mac_dst=dut_rt_int_mac1, ipv6_src_addr=data.ip6_addr[0],
                               ipv6_dst_addr=data.ip6_addr[9])
    st.log("TRAFCONF: " + str(tr1))

    res = tg.tg_traffic_control(action='run', stream_handle=tr1['stream_id'])
    st.log("TR_CTRL: " + str(res))
    tg.tg_traffic_control(action='stop', stream_handle=tr1['stream_id'])
    st.log("Checking the stats and verifying the traffic flow")
    traffic_details = {
       '1': {
          'tx_ports' : [vars.T1D1P2],
          'tx_obj' : [tg_handler["tg"]],
          'exp_ratio' : [1],
          'rx_ports' : [vars.T1D2P2],
         'rx_obj' : [tg_handler["tg"]],
      }
    }
    # verify statistics
    aggrResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if not aggrResult:
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
            'tx_ports' : [vars.T1D1P2],
            'tx_obj' : [tg_handler["tg"]],
            'exp_ratio' : [1],
            'rx_ports' : [vars.T1D2P2],
            'rx_obj' : [tg_handler["tg"]],
        }
    }

    # verify statistics
    aggrResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if aggrResult:
     st.report_fail("traffic_verification_failed")
    st.report_pass("test_case_passed")


@pytest.mark.ip_basic13
def test_ft_ip_static_route_traffic_forward():
    # Objective - Verify the Ipv4 traffic forwarding over IPv4 static route.
    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D2P1")
    tg = tg_handler["tg"]
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    dut_rt_int_mac1 = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config', intf_ip_addr=data.ip4_addr[0], \
                                gateway=data.ip4_addr[1], src_mac_addr=data.tg_mac1, arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config', intf_ip_addr=data.ip4_addr[9], \
                                gateway=data.ip4_addr[8], src_mac_addr=data.tg_mac2, arp_send_req='1')
    st.log("INTFCONF: " + str(h2))
    # Ping from tgen to DUT.
    res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=h1['handle'], dst_ip=data.ip4_addr[1], \
                      ping_count='1', exp_count='1')
    if res:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")
    tr1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create', transmit_mode='single_burst',
                               pkts_per_burst=2000, \
                               length_mode='fixed', rate_pps=2000, l3_protocol='ipv4', mac_src=data.tg_mac1, \
                               mac_dst=dut_rt_int_mac1, ip_src_addr=data.ip4_addr[0],
                               ip_dst_addr=data.ip4_addr[9])
    st.log("TRAFCONF: " + str(tr1))
    res = tg.tg_traffic_control(action='run', stream_handle=tr1['stream_id'])
    st.log("TR_CTRL: " + str(res))
    tg.tg_traffic_control(action='stop', stream_handle=tr1['stream_id'])
    st.log("Checking the stats and verifying the traffic flow")
    traffic_details = {
       '1': {
            'tx_ports' : [vars.T1D1P1],
            'tx_obj' : [tg_handler["tg"]],
            'exp_ratio' : [1],
            'rx_ports' : [vars.T1D2P1],
            'rx_obj' : [tg_handler["tg"]],
        }
    }
    #verify statistics
    aggrResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if not aggrResult:
      st.report_fail("traffic_verification_failed")
    st.report_pass("test_case_passed")


@pytest.mark.ip_basic_L2_L3_translation
def test_ft_ip_v4_v6_L2_L3_translation():
    # Objective - Verify that L2 port to IPv4 L3 port transition and vice-versa is successful.
    st.log("Checking IPv4 ping from {} to {} over  routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping(vars.D1, data.ip4_addr[7], family=data.af_ipv4, count=1):
        st.report_fail("ping_fail",data.ip4_addr[6], data.ip4_addr[7])
    st.log("Checking IPv6 ping from {} to {} over vlan routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping(vars.D2, data.ip6_addr[6], family=data.af_ipv6, count=1):
        st.report_fail("ping_fail",data.ip6_addr[7], data.ip6_addr[6])
    st.log("L3 to L2 port transition")
    st.log("Removing ipv4,ipv6 address from interface")
    ipfeature.delete_ip_interface(vars.D1, vars.D1D2P4, data.ip4_addr[6], 24, family=data.af_ipv4)
    ipfeature.delete_ip_interface(vars.D2, vars.D2D1P4, data.ip4_addr[7], 24, family=data.af_ipv4)
    ipfeature.delete_ip_interface(vars.D1, vars.D1D2P4, data.ip6_addr[6], 96, family=data.af_ipv6)
    ipfeature.delete_ip_interface(vars.D2, vars.D2D1P4, data.ip6_addr[7], 96, family=data.af_ipv6)
    ipfeature.delete_ip_interface(vars.D1, vars.D1T1P1, data.ip4_addr[1], 24, family=data.af_ipv4)
    ipfeature.delete_ip_interface(vars.D2, vars.D2T1P1, data.ip4_addr[8], 24, family=data.af_ipv4)
    st.log("Removing the static routes")
    ipfeature.delete_static_route(vars.D1, data.ip4_addr[7], data.static_ip_rt, shell=data.shell_vtysh, family=data.af_ipv4)
    ipfeature.delete_static_route(vars.D1, data.static_ip6_rt_drop, data.static_ip6_rt, shell=data.shell_vtysh, family=data.af_ipv6)
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
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    tr2 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], mode='create', rate_pps="2000",
                           mac_src_mode="fixed",
                           transmit_mode="single_burst", pkts_per_burst=2000,
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
    st.log("Fetching IXIA statistics")
    stats_tg1 = tgapi.get_traffic_stats(tg_handler["tg"], mode="aggregate", port_handle=tg_handler["tg_ph_2"])
    total_tx_tg1 = stats_tg1.tx.total_packets
    stats_tg2 = tgapi.get_traffic_stats(tg_handler["tg"], mode="aggregate", port_handle=tg_handler["tg_ph_1"])
    total_rx_tg2 = stats_tg2.rx.total_packets
    st.log("total_tx_tg1 = {}".format(total_tx_tg1))
    total_tx_tg1_95_percentage = int(total_tx_tg1) * 0.95
    st.log("total_tx_tg1_95_percentage= {}".format(total_tx_tg1_95_percentage))
    st.log("total_rx_tg2 = {}".format(total_rx_tg2))
    if not int(total_tx_tg1_95_percentage) <= int(total_rx_tg2):
        st.report_fail("traffic_verification_failed")
    st.log("Removing vlan configuration")
    vlan_obj.delete_vlan_member(vars.D1, data.vlan_2, [vars.D1D2P4, vars.D1T1P1])
    vlan_obj.delete_vlan_member(vars.D2, data.vlan_2, [vars.D2D1P4, vars.D2T1P1])
    st.log("L2 to L3 port transition")
    ipfeature.config_ip_addr_interface(vars.D1, vars.D1D2P4, data.ip4_addr[6], 24, family=data.af_ipv4)
    ipfeature.config_ip_addr_interface(vars.D2, vars.D2D1P4, data.ip4_addr[7], 24, family=data.af_ipv4)
    ipfeature.create_static_route(vars.D1, data.ip4_addr[7], data.static_ip_rt, shell=data.shell_vtysh, family=data.af_ipv4)
    st.log("Checking IPv4 ping from {} to {} over routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping(vars.D1, data.ip4_addr[7], family=data.af_ipv4, count=1):
        st.report_fail("ping_fail",data.ip4_addr[6], data.ip4_addr[7])
    ipfeature.config_ip_addr_interface(vars.D1, vars.D1D2P4, data.ip6_addr[6], 96, family=data.af_ipv6)
    ipfeature.config_ip_addr_interface(vars.D2, vars.D2D1P4, data.ip6_addr[7], 96, family=data.af_ipv6)
    ipfeature.create_static_route(vars.D1, data.static_ip6_rt_drop, data.static_ip6_rt, shell=data.shell_vtysh, family=data.af_ipv6)
    st.log("Checking IPv6 ping from {} to {} over vlan routing interface".format(vars.D1, vars.D2))
    if not ipfeature.ping(vars.D2, data.ip6_addr[6], family=data.af_ipv6, count=1):
        st.report_fail("ping_fail",data.ip6_addr[7], data.ip6_addr[6])
    st.report_pass("test_case_passed")


@pytest.mark.community
@pytest.mark.community_pass
def test_ft_verify_interfaces_order():
    '''
    @author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    ipv4_intf_order :  Verify order of interfaces in "show ip interfaces"
    ipv6_intf_order :  Verify order of interfaces in "show ipv6 interfaces'
    Verify order of interfaces in "show ip/ipv6 interfaces" in sorted order or not

    :return:
    '''
    flag = 1
    st.log("This test is to ensure that interfaces are listed in sorted order by 'interface name' in 'show ip/ipv6 "
           "interfaces'")
    free_ports = st.get_free_ports(vars.D1)
    if len(free_ports) < data.no_of_ports:
        data.no_of_ports = len(free_ports)
    req_ports  = random.sample(free_ports, data.no_of_ports)
    ipv4_addr = data.ip4_addr[11]+'/'+data.ipv4_mask
    ipv6_addr = data.ip6_addr[0]+'/'+data.ipv6_mask
    intf_list = []
    for i in range(int(math.ceil(float(data.no_of_ports)/2))):
        _, ipv4_addr = ipfeature.increment_ip_addr(ipv4_addr, "network")
        ipfeature.config_ip_addr_interface(vars.D1, interface_name=req_ports[i], ip_address=ipv4_addr.split('/')[0],
                                           subnet=data.ipv4_mask, family="ipv4")
    for i in range(int(math.floor(float(data.no_of_ports)/2))):
        _, ipv6_addr = ipfeature.increment_ip_addr(ipv6_addr, "network", family="ipv6")
        ipfeature.config_ip_addr_interface(vars.D1, interface_name=req_ports[i+int(math.ceil(float(data.no_of_ports)/2))],
                                           ip_address=ipv6_addr.split('/')[0], subnet=data.ipv6_mask, family="ipv6")
    output = ipfeature.get_interface_ip_address(vars.D1)
    for each in output:
        intf_list.append(each['interface'])
    temp = lambda text: int(text) if text.isdigit() else text
    alphanum_key = lambda key: [temp(c) for c in re.split('([0-9]+)', key)]
    intf_list_sorted = sorted(intf_list, key=alphanum_key)
    if intf_list == intf_list_sorted:
        st.log("Ipv4 interfaces are in sorted order")
    else:
        st.error("Ipv4 interfaces are not in soretd order")
        flag = 0
    del intf_list[:]
    del intf_list_sorted[:]
    output = ipfeature.get_interface_ip_address(vars.D1, family="ipv6")
    for each in output:
        intf_list.append(each['interface'])
    temp = lambda text: int(text) if text.isdigit() else text
    alphanum_key = lambda key: [temp(c) for c in re.split('([0-9]+)', key)]
    intf_list_sorted = sorted(intf_list, key=alphanum_key)
    if intf_list == intf_list_sorted:
        st.log("Ipv6 interfaces are in sorted order")
    else:
        st.error("Ipv6 interfaces are not in soretd order")
        flag = 0
    #Unconfig
    ipv4_addr = data.ip4_addr[11] + '/' + data.ipv4_mask
    ipv6_addr = data.ip6_addr[0] + '/' + data.ipv6_mask
    for i in range(int(math.ceil(float(data.no_of_ports)/2))):
        _, ipv4_addr = ipfeature.increment_ip_addr(ipv4_addr, "network")
        ipfeature.delete_ip_interface(vars.D1, interface_name=req_ports[i], ip_address=ipv4_addr.split('/')[0],
                                           subnet=data.ipv4_mask, family="ipv4")
    for i in range(int(math.floor(float(data.no_of_ports)/2))):
        _, ipv6_addr = ipfeature.increment_ip_addr(ipv6_addr, "network", family="ipv6")
        ipfeature.delete_ip_interface(vars.D1, interface_name=req_ports[i+int(math.ceil(float(data.no_of_ports)/2))],
                                      ip_address=ipv6_addr.split('/')[0], subnet=data.ipv6_mask, family="ipv6")
    if flag == 0:
        st.report_fail("test_case_failed")
    st.report_pass("test_case_passed")
