import pytest
import datetime

from spytest import st, tgapi, SpyTestDict
from spytest.utils import filter_and_select
from spytest.utils import poll_wait

import apis.routing.ip as ipfeature
import apis.system.port as papi
import apis.routing.bgp as bgpfeature
import apis.system.interface as interface_obj
import apis.system.basic as basic_obj
import apis.common.asic_bcm as asicapi

data = SpyTestDict()
data.as_num_1 = 100
data.as_num_2 = 200
data.as_num_3 = 300
data.as_num_4 = 400
data.remote_as_num1 = 500
data.dut1_to_tg_port_1_ip = "10.10.10.1"
data.tg_to_dut1_port_1_ip = "10.10.10.2"
data.dut1_to_dut2_port_1_ip = "30.30.30.1"
data.dut2_to_dut1_port_1_ip = "30.30.30.2"
data.dut1_to_dut3_port_1_ip = "40.40.40.1"
data.dut3_to_dut1_port_1_ip = "40.40.40.2"
data.dut2_to_dut4_port_1_ip = "50.50.50.1"
data.dut4_to_dut2_port_1_ip = "50.50.50.2"
data.dut3_to_dut4_port_1_ip = "60.60.60.1"
data.dut4_to_dut3_port_1_ip = "60.60.60.2"
data.dut4_to_tg_port_1_ip = "20.20.20.1"
data.tg_to_dut4_port_1_ip = "20.20.20.2"
data.ip_prefixlen = "24"
data.dut1_to_tg_port_1_ip6 = "1000::1"
data.tg_to_dut1_port_1_ip6 = "1000::2"
data.dut1_to_dut2_port_1_ip6 = "3000::1"
data.dut2_to_dut1_port_1_ip6 = "3000::2"
data.dut1_to_dut3_port_1_ip6 = "4000::1"
data.dut3_to_dut1_port_1_ip6 = "4000::2"
data.dut2_to_dut4_port_1_ip6 = "5000::1"
data.dut4_to_dut2_port_1_ip6 = "5000::2"
data.dut3_to_dut4_port_1_ip6 = "6000::1"
data.dut4_to_dut3_port_1_ip6 = "6000::2"
data.dut4_to_tg_port_1_ip6 = "2000::1"
data.tg_to_dut4_port_1_ip6 = "2000::2"
data.ipv6_prefixlen = "64"
data.test_bgp_route_count = 20000
data.traffic_rate_pps = data.test_bgp_route_count

@pytest.fixture(scope="module", autouse=True)
def l3_performance_enhancements_module_hooks(request):
	global vars
	global tg_handler
	global tg
	global dut1
	global dut2
	global dut3
	global dut4
	global dut1_to_tg_port_1
	global dut1_to_dut2_port_1
	global dut2_to_dut1_port_1
	global dut1_to_dut3_port_1
	global dut3_to_dut1_port_1
	global dut2_to_dut4_port_1
	global dut4_to_dut2_port_1
	global dut3_to_dut4_port_1
	global dut4_to_dut3_port_1
	global dut4_to_tg_port_1
	global hwsku_under_test1
	global hwsku_under_test2
	global hwsku_under_test3
	global hwsku_under_test4
	global def_v4_route_count_d1
	global def_v4_route_count_d4
	global def_v6_route_count_d1
	global def_v6_route_count_d4
	# Min topology verification
	st.log("Ensuring minimum topology")
	vars = st.ensure_min_topology("D1D2:1", "D1D3:1", "D2D4:1", "D3D4:1", "D1T1:1", "D4T1:1")

	# Initialize TG and TG port handlers
	tg_handler = tgapi.get_handles(vars, [vars.T1D1P1, vars.T1D4P1])
	tg = tg_handler["tg"]

	# Test setup details
	dut1 = vars.D1
	dut2 = vars.D2
	dut3 = vars.D3
	dut4 = vars.D4
	dut1_to_tg_port_1 = vars.D1T1P1
	dut1_to_dut2_port_1 = vars.D1D2P1
	dut2_to_dut1_port_1 = vars.D2D1P1
	dut1_to_dut3_port_1 = vars.D1D3P1
	dut3_to_dut1_port_1 = vars.D3D1P1
	dut2_to_dut4_port_1 = vars.D2D4P1
	dut4_to_dut2_port_1 = vars.D4D2P1
	dut3_to_dut4_port_1 = vars.D3D4P1
	dut4_to_dut3_port_1 = vars.D4D3P1
	dut4_to_tg_port_1 = vars.D4T1P1
	hwsku_under_test1 = basic_obj.get_hwsku(dut1)
	hwsku_under_test2 = basic_obj.get_hwsku(dut2)
	hwsku_under_test3 = basic_obj.get_hwsku(dut3)
	hwsku_under_test4 = basic_obj.get_hwsku(dut4)

	# Module Configuration
	st.log("L3 Performance Enhancements Module Configuration.")
	# Configuring v4/v6 routing interfaces on the DUT.
	st.log("Configuring IPv4 routing interfaces.")
	ipfeature.config_ip_addr_interface(dut1, dut1_to_tg_port_1, data.dut1_to_tg_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.config_ip_addr_interface(dut1, dut1_to_dut2_port_1, data.dut1_to_dut2_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.config_ip_addr_interface(dut1, dut1_to_dut3_port_1, data.dut1_to_dut3_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.config_ip_addr_interface(dut2, dut2_to_dut1_port_1, data.dut2_to_dut1_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.config_ip_addr_interface(dut2, dut2_to_dut4_port_1, data.dut2_to_dut4_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.config_ip_addr_interface(dut3, dut3_to_dut1_port_1, data.dut3_to_dut1_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.config_ip_addr_interface(dut3, dut3_to_dut4_port_1, data.dut3_to_dut4_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.config_ip_addr_interface(dut4, dut4_to_dut2_port_1, data.dut4_to_dut2_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.config_ip_addr_interface(dut4, dut4_to_dut3_port_1, data.dut4_to_dut3_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.config_ip_addr_interface(dut4, dut4_to_tg_port_1, data.dut4_to_tg_port_1_ip, data.ip_prefixlen, family="ipv4")

	st.log("Configuring IPv6 routing interfaces.")
	ipfeature.config_ipv6(dut1, action='enable')
	ipfeature.config_ip_addr_interface(dut1, dut1_to_tg_port_1, data.dut1_to_tg_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.config_ip_addr_interface(dut1, dut1_to_dut2_port_1, data.dut1_to_dut2_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.config_ip_addr_interface(dut1, dut1_to_dut3_port_1, data.dut1_to_dut3_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.config_ipv6(dut2, action='enable')
	ipfeature.config_ip_addr_interface(dut2, dut2_to_dut1_port_1, data.dut2_to_dut1_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.config_ip_addr_interface(dut2, dut2_to_dut4_port_1, data.dut2_to_dut4_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.config_ipv6(dut3, action='enable')
	ipfeature.config_ip_addr_interface(dut3, dut3_to_dut1_port_1, data.dut3_to_dut1_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.config_ip_addr_interface(dut3, dut3_to_dut4_port_1, data.dut3_to_dut4_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.config_ipv6(dut4, action='enable')
	ipfeature.config_ip_addr_interface(dut4, dut4_to_dut2_port_1, data.dut4_to_dut2_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.config_ip_addr_interface(dut4, dut4_to_dut3_port_1, data.dut4_to_dut3_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.config_ip_addr_interface(dut4, dut4_to_tg_port_1, data.dut4_to_tg_port_1_ip6, data.ipv6_prefixlen, family="ipv6")

	# Configuring BGP router and v4/v6 neighbors on the DUT.
	st.log("Configuring BGP routers.")
	bgpfeature.create_bgp_router(dut1, data.as_num_1, '')
	bgpfeature.create_bgp_router(dut2, data.as_num_2, '')
	bgpfeature.create_bgp_router(dut3, data.as_num_3, '')
	bgpfeature.create_bgp_router(dut4, data.as_num_4, '')

	st.log("Configuring BGP IPv4 neighbors.")
	bgpfeature.create_bgp_neighbor(dut1, data.as_num_1, data.tg_to_dut1_port_1_ip, data.remote_as_num1)
	bgpfeature.create_bgp_neighbor(dut1, data.as_num_1, data.dut2_to_dut1_port_1_ip, data.as_num_2)
	bgpfeature.create_bgp_neighbor(dut1, data.as_num_1, data.dut3_to_dut1_port_1_ip, data.as_num_3)
	bgpfeature.create_bgp_neighbor(dut2, data.as_num_2, data.dut1_to_dut2_port_1_ip, data.as_num_1)
	bgpfeature.create_bgp_neighbor(dut2, data.as_num_2, data.dut4_to_dut2_port_1_ip, data.as_num_4)
	bgpfeature.create_bgp_neighbor(dut3, data.as_num_3, data.dut1_to_dut3_port_1_ip, data.as_num_1)
	bgpfeature.create_bgp_neighbor(dut3, data.as_num_3, data.dut4_to_dut3_port_1_ip, data.as_num_4)
	bgpfeature.create_bgp_neighbor(dut4, data.as_num_4, data.dut2_to_dut4_port_1_ip, data.as_num_2)
	bgpfeature.create_bgp_neighbor(dut4, data.as_num_4, data.dut3_to_dut4_port_1_ip, data.as_num_3)

	st.log("Configuring BGP IPv6 neighbors.")
	bgpfeature.create_bgp_neighbor(dut1, data.as_num_1, data.tg_to_dut1_port_1_ip6, data.remote_as_num1, family="ipv6")
	bgpfeature.create_bgp_neighbor(dut1, data.as_num_1, data.dut2_to_dut1_port_1_ip6, data.as_num_2, family="ipv6")
	bgpfeature.create_bgp_neighbor(dut1, data.as_num_1, data.dut3_to_dut1_port_1_ip6, data.as_num_3, family="ipv6")
	bgpfeature.create_bgp_neighbor(dut2, data.as_num_2, data.dut1_to_dut2_port_1_ip6, data.as_num_1, family="ipv6")
	bgpfeature.create_bgp_neighbor(dut2, data.as_num_2, data.dut4_to_dut2_port_1_ip6, data.as_num_4, family="ipv6")
	bgpfeature.create_bgp_neighbor(dut3, data.as_num_3, data.dut1_to_dut3_port_1_ip6, data.as_num_1, family="ipv6")
	bgpfeature.create_bgp_neighbor(dut3, data.as_num_3, data.dut4_to_dut3_port_1_ip6, data.as_num_4, family="ipv6")
	bgpfeature.create_bgp_neighbor(dut4, data.as_num_4, data.dut2_to_dut4_port_1_ip6, data.as_num_2, family="ipv6")
	bgpfeature.create_bgp_neighbor(dut4, data.as_num_4, data.dut3_to_dut4_port_1_ip6, data.as_num_3, family="ipv6")

	# st.log("Configuring BGP as-path multipath-relax.")
	bgpfeature.create_bgp_best_path(dut1, data.as_num_1, "as-path multipath-relax")
	bgpfeature.create_bgp_best_path(dut2, data.as_num_2, "as-path multipath-relax")
	bgpfeature.create_bgp_best_path(dut3, data.as_num_3, "as-path multipath-relax")
	bgpfeature.create_bgp_best_path(dut4, data.as_num_4, "as-path multipath-relax")

	# Get the default route count from DUT
	def_v4_route_count_d1 = asicapi.bcmcmd_route_count_hardware(dut1)
	def_v4_route_count_d4 = asicapi.bcmcmd_route_count_hardware(dut4)
	def_v6_route_count_d1 = asicapi.bcmcmd_ipv6_route_count_hardware(dut1)
	def_v6_route_count_d4 = asicapi.bcmcmd_ipv6_route_count_hardware(dut4)

	# Verifying the BGP neighborship
	st.wait(20)
	st.log("Verifying the BGP IPv4 neighborships.")
	if not poll_wait(bgpfeature.verify_bgp_summary, 120, dut1, neighbor=data.dut2_to_dut1_port_1_ip,state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut2_to_dut1_port_1_ip)
	if not poll_wait(bgpfeature.verify_bgp_summary, 120, dut1, neighbor=data.dut3_to_dut1_port_1_ip,state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut3_to_dut1_port_1_ip)
	if not poll_wait(bgpfeature.verify_bgp_summary, 120, dut2, neighbor=data.dut1_to_dut2_port_1_ip,state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut1_to_dut2_port_1_ip)
	if not poll_wait(bgpfeature.verify_bgp_summary, 120, dut2, neighbor=data.dut4_to_dut2_port_1_ip,state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut4_to_dut2_port_1_ip)
	# if not bgpfeature.verify_bgp_summary(dut1, neighbor=data.dut2_to_dut1_port_1_ip, state='Established'):
	# 	st.report_fail("bgp_ip_peer_establish_fail", data.dut2_to_dut1_port_1_ip)
	# if not bgpfeature.verify_bgp_summary(dut1, neighbor=data.dut3_to_dut1_port_1_ip, state='Established'):
	# 	st.report_fail("bgp_ip_peer_establish_fail", data.dut3_to_dut1_port_1_ip)
	# if not bgpfeature.verify_bgp_summary(dut2, neighbor=data.dut1_to_dut2_port_1_ip, state='Established'):
	# 	st.report_fail("bgp_ip_peer_establish_fail", data.dut1_to_dut2_port_1_ip)
	# if not bgpfeature.verify_bgp_summary(dut2, neighbor=data.dut4_to_dut2_port_1_ip, state='Established'):
	# 	st.report_fail("bgp_ip_peer_establish_fail", data.dut4_to_dut2_port_1_ip)
	if not bgpfeature.verify_bgp_summary(dut3, neighbor=data.dut1_to_dut3_port_1_ip, state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut1_to_dut3_port_1_ip)
	if not bgpfeature.verify_bgp_summary(dut3, neighbor=data.dut4_to_dut3_port_1_ip, state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut4_to_dut3_port_1_ip)
	if not bgpfeature.verify_bgp_summary(dut4, neighbor=data.dut2_to_dut4_port_1_ip, state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut2_to_dut4_port_1_ip)
	if not bgpfeature.verify_bgp_summary(dut4, neighbor=data.dut3_to_dut4_port_1_ip, state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut3_to_dut4_port_1_ip)

	st.log("Verifying the BGP IPv6 neighborships.")
	if not bgpfeature.verify_bgp_summary(dut1, family='ipv6', neighbor=data.dut2_to_dut1_port_1_ip6, state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut2_to_dut1_port_1_ip6)
	if not bgpfeature.verify_bgp_summary(dut1, family='ipv6', neighbor=data.dut3_to_dut1_port_1_ip6, state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut3_to_dut1_port_1_ip6)
	if not bgpfeature.verify_bgp_summary(dut2, family='ipv6', neighbor=data.dut1_to_dut2_port_1_ip6, state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut1_to_dut2_port_1_ip6)
	if not bgpfeature.verify_bgp_summary(dut2, family='ipv6', neighbor=data.dut4_to_dut2_port_1_ip6, state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut4_to_dut2_port_1_ip6)
	if not bgpfeature.verify_bgp_summary(dut3, family='ipv6', neighbor=data.dut1_to_dut3_port_1_ip6, state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut1_to_dut3_port_1_ip6)
	if not bgpfeature.verify_bgp_summary(dut3, family='ipv6', neighbor=data.dut4_to_dut3_port_1_ip6, state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut4_to_dut3_port_1_ip6)
	if not bgpfeature.verify_bgp_summary(dut4, family='ipv6', neighbor=data.dut2_to_dut4_port_1_ip6, state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut2_to_dut4_port_1_ip6)
	if not bgpfeature.verify_bgp_summary(dut4, family='ipv6', neighbor=data.dut3_to_dut4_port_1_ip6, state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.dut3_to_dut4_port_1_ip6)

	yield
	# Module Cleanup
	st.log("L3 Performance Enhancements Module Cleanup.")
	st.log("Unconfiguring IPv4 routing interfaces.")
	ipfeature.delete_ip_interface(dut1, dut1_to_tg_port_1, data.dut1_to_tg_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.delete_ip_interface(dut1, dut1_to_dut2_port_1, data.dut1_to_dut2_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.delete_ip_interface(dut1, dut1_to_dut3_port_1, data.dut1_to_dut3_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.delete_ip_interface(dut2, dut2_to_dut1_port_1, data.dut2_to_dut1_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.delete_ip_interface(dut2, dut2_to_dut4_port_1, data.dut2_to_dut4_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.delete_ip_interface(dut3, dut3_to_dut1_port_1, data.dut3_to_dut1_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.delete_ip_interface(dut3, dut3_to_dut4_port_1, data.dut3_to_dut4_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.delete_ip_interface(dut4, dut4_to_dut2_port_1, data.dut4_to_dut2_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.delete_ip_interface(dut4, dut4_to_dut3_port_1, data.dut4_to_dut3_port_1_ip, data.ip_prefixlen, family="ipv4")
	ipfeature.delete_ip_interface(dut4, dut4_to_tg_port_1, data.dut4_to_tg_port_1_ip, data.ip_prefixlen, family="ipv4")

	st.log("Unconfiguring IPv6 routing interfaces.")
	ipfeature.delete_ip_interface(dut1, dut1_to_tg_port_1, data.dut1_to_tg_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.delete_ip_interface(dut1, dut1_to_dut2_port_1, data.dut1_to_dut2_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.delete_ip_interface(dut1, dut1_to_dut3_port_1, data.dut1_to_dut3_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.delete_ip_interface(dut2, dut2_to_dut1_port_1, data.dut2_to_dut1_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.delete_ip_interface(dut2, dut2_to_dut4_port_1, data.dut2_to_dut4_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.delete_ip_interface(dut3, dut3_to_dut1_port_1, data.dut3_to_dut1_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.delete_ip_interface(dut3, dut3_to_dut4_port_1, data.dut3_to_dut4_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.delete_ip_interface(dut4, dut4_to_dut2_port_1, data.dut4_to_dut2_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.delete_ip_interface(dut4, dut4_to_dut3_port_1, data.dut4_to_dut3_port_1_ip6, data.ipv6_prefixlen, family="ipv6")
	ipfeature.delete_ip_interface(dut4, dut4_to_tg_port_1, data.dut4_to_tg_port_1_ip6, data.ipv6_prefixlen, family="ipv6")

	st.log("Unconfiguring BGP IPv4 neighbors.")
	bgpfeature.delete_bgp_neighbor(dut1, data.as_num_1, data.tg_to_dut1_port_1_ip, data.remote_as_num1)
	bgpfeature.delete_bgp_neighbor(dut1, data.as_num_1, data.dut2_to_dut1_port_1_ip, data.as_num_2)
	bgpfeature.delete_bgp_neighbor(dut1, data.as_num_1, data.dut3_to_dut1_port_1_ip, data.as_num_3)
	bgpfeature.delete_bgp_neighbor(dut2, data.as_num_2, data.dut1_to_dut2_port_1_ip, data.as_num_1)
	bgpfeature.delete_bgp_neighbor(dut2, data.as_num_2, data.dut4_to_dut2_port_1_ip, data.as_num_4)
	bgpfeature.delete_bgp_neighbor(dut3, data.as_num_3, data.dut1_to_dut3_port_1_ip, data.as_num_1)
	bgpfeature.delete_bgp_neighbor(dut3, data.as_num_3, data.dut4_to_dut3_port_1_ip, data.as_num_4)
	bgpfeature.delete_bgp_neighbor(dut4, data.as_num_4, data.dut2_to_dut4_port_1_ip, data.as_num_2)
	bgpfeature.delete_bgp_neighbor(dut4, data.as_num_4, data.dut3_to_dut4_port_1_ip, data.as_num_3)

	st.log("Unconfiguring BGP IPv6 neighbors.")
	bgpfeature.delete_bgp_neighbor(dut1, data.as_num_1, data.tg_to_dut1_port_1_ip6, data.remote_as_num1)
	bgpfeature.delete_bgp_neighbor(dut1, data.as_num_1, data.dut2_to_dut1_port_1_ip6, data.as_num_2)
	bgpfeature.delete_bgp_neighbor(dut1, data.as_num_1, data.dut3_to_dut1_port_1_ip6, data.as_num_3)
	bgpfeature.delete_bgp_neighbor(dut2, data.as_num_2, data.dut1_to_dut2_port_1_ip6, data.as_num_1)
	bgpfeature.delete_bgp_neighbor(dut2, data.as_num_2, data.dut4_to_dut2_port_1_ip6, data.as_num_4)
	bgpfeature.delete_bgp_neighbor(dut3, data.as_num_3, data.dut1_to_dut3_port_1_ip6, data.as_num_1)
	bgpfeature.delete_bgp_neighbor(dut3, data.as_num_3, data.dut4_to_dut3_port_1_ip6, data.as_num_4)
	bgpfeature.delete_bgp_neighbor(dut4, data.as_num_4, data.dut2_to_dut4_port_1_ip6, data.as_num_2)
	bgpfeature.delete_bgp_neighbor(dut4, data.as_num_4, data.dut3_to_dut4_port_1_ip6, data.as_num_3)

	st.log("Unconfiguring BGP routers.")
	bgpfeature.cleanup_router_bgp(dut1)
	bgpfeature.cleanup_router_bgp(dut2)
	bgpfeature.cleanup_router_bgp(dut3)
	bgpfeature.cleanup_router_bgp(dut4)

@pytest.fixture(scope="function", autouse=True)
def l3_performance_enhancements_func_hooks(request):
	# Function configuration
	yield
	# Function cleanup

def print_topology(test, message):
	st.log("*********************************************************************************")
	st.log("                                    ---------                                    ")
	st.log("                             -------|   D2   |-------                            ")
	st.log("                            |       ---------        |                           ")
	st.log("                            |                        |                           ")
	st.log("                        ---------                ---------                       ")
	st.log("(BGP routes ->) TG -----|   D1   |               |   D4   |----- TG (<- Traffic) ")
	st.log("                        ---------                ---------                       ")
	st.log("                            |                        |                           ")
	st.log("                            |       ---------        |                           ")
	st.log("                             -------|   D3   |-------                            ")
	st.log("                                    ---------                                    ")
	st.log("*********************************************************************************")
	st.log("D1 : {}".format(hwsku_under_test1))
	st.log("D2 : {}".format(hwsku_under_test2))
	st.log("D3 : {}".format(hwsku_under_test3))
	st.log("D4 : {}".format(hwsku_under_test4))
	st.log("**************************************************************************************")
	st.log("No. Of routes : {}".format(data.test_bgp_route_count))
	st.log("**************************************************************************************")
	st.log("**************************************************************************************")
	st.log("Test scenario : {} : {}".format(test, message))
	st.log("**************************************************************************************")

def check_intf_traffic_counters(dut, port, loopCnt):
	flag = 0
	iter = 1
	p2_txmt = 0

	while iter <= loopCnt:
		output = papi.get_interface_counters_all(dut, port=port)
		output = papi.get_interface_counters_all(dut, port=port)
		for entry in output:
			if entry["iface"] == port:
				DUT_tx_value = entry["tx_pps"]
		p2_txmt = DUT_tx_value
		p2_txmt = p2_txmt.replace("/s","")

		st.log("tx_pps counter value on DUT {} Egress port {} : {}".format(dut,port,p2_txmt))

		if (int(float(p2_txmt)) >= data.traffic_rate_pps-1000):
			flag = 1
			break
		iter = iter+1

	if flag:
		return True
	else:
		return False

def check_bcmcmd_route_count(dut, loopCnt, ipType, defcount, expcount):
	flag = 0
	iter = 1
	while iter <= loopCnt:
		if ipType == "ipv4":
			curr_count = asicapi.bcmcmd_route_count_hardware(dut)
		elif ipType == "ipv6":
			curr_count = asicapi.bcmcmd_ipv6_route_count_hardware(dut)

		route_cnt = int(curr_count) - int(defcount)

		st.log("Learnt route count after iteration {} : {}".format(iter,route_cnt))

		if int(route_cnt) == int(expcount):
			flag = 1
			break
		iter = iter+1

	if flag:
		return True
	else:
		return False

def verify_bgp_route_count(dut,family='ipv4',shell="sonic",**kwargs):
	if family.lower() == 'ipv4':
		output = bgpfeature.show_bgp_ipv4_summary(dut)
	if family.lower() == 'ipv6':
		output = bgpfeature.show_bgp_ipv6_summary(dut)
	st.debug(output)
	if 'neighbor' in kwargs and 'state' in kwargs:
		match = {'neighbor': kwargs['neighbor']}
		try:
			entries = filter_and_select(output, None, match)[0]
		except Exception:
			st.log("ERROR 1")
		if entries['state']:
			if kwargs['state'] == 'Established':
				if entries['state'].isdigit():
					return entries['state']
				else:
					return 0
			else:
				return 0
		else:
			return 0
	else:
		return 0
	return 0

@pytest.fixture(scope="function")
def fixture_v4(request):
	global h1
	global h2
	global ctrl_start
	global ctrl_stop
	global bgp_rtr1
	st.log("Test Fixture Config.")
	# TG ports reset
	st.log("Resetting the TG ports")
	tgapi.traffic_action_control(tg_handler, actions=['reset'])

	# TG protocol interface creation
	st.log("TG protocol interface creation")
	h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config',intf_ip_addr=data.tg_to_dut1_port_1_ip,gateway=data.dut1_to_tg_port_1_ip,arp_send_req='1')
	st.log("INTFCONF: "+str(h1))
	h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config',intf_ip_addr=data.tg_to_dut4_port_1_ip,gateway=data.dut4_to_tg_port_1_ip,arp_send_req='1')
	st.log("INTFCONF: "+str(h2))

	# Configuring BGP on TG interface
	conf_var = {'mode':'enable', 'active_connect_enable':'1', 'local_as':data.remote_as_num1, 'remote_as':data.as_num_1, 'remote_ip_addr':data.dut1_to_tg_port_1_ip}
	route_var = {'mode':'add', 'num_routes':data.test_bgp_route_count, 'prefix':'121.1.1.0', 'as_path':'as_seq:1'}
	ctrl_start = {'mode':'start'}
	ctrl_stop = {'mode':'stop'}

	# Starting the BGP router on TG.
	bgp_rtr1 = tgapi.tg_bgp_config(tg=tg, handle=h1['handle'], conf_var=conf_var, route_var = route_var, ctrl_var=ctrl_start)
	st.log("BGP_HANDLE: "+str(bgp_rtr1))

	# Verifying the BGP neighborship
	st.wait(10)
	st.log("Verifying the BGP neighborships.")
	if not bgpfeature.verify_bgp_summary(dut1, neighbor=data.tg_to_dut1_port_1_ip, state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.tg_to_dut1_port_1_ip)

	yield
	st.log("Test Fixture Cleanup.")
	# Startup the routing interface link.
	if not interface_obj.interface_operation(dut2, dut2_to_dut4_port_1, "startup"):
		st.report_fail('interface_admin_startup_fail', dut2_to_dut4_port_1)
	if not interface_obj.interface_operation(dut3, dut3_to_dut1_port_1, "startup"):
		st.report_fail('interface_admin_startup_fail', dut3_to_dut1_port_1)

	tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], handle=h1['handle'], mode='destroy')
	tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], handle=h2['handle'], mode='destroy')

@pytest.fixture(scope="function")
def fixture_v6(request):
	global h1
	global h2
	global ctrl_start
	global ctrl_stop
	global bgp_rtr1
	st.log("Test Fixture Config.")
	# TG ports reset
	st.log("Resetting the TG ports")
	tgapi.traffic_action_control(tg_handler, actions=['reset'])

	# TG protocol interface creation
	st.log("TG protocol interface creation")
	h1 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], mode='config',ipv6_intf_addr=data.tg_to_dut1_port_1_ip6,ipv6_prefix_length=64,ipv6_gateway=data.dut1_to_tg_port_1_ip6,arp_send_req='1')
	st.log("INTFCONF: "+str(h1))
	h2 = tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], mode='config',ipv6_intf_addr=data.tg_to_dut4_port_1_ip6,ipv6_prefix_length=64,ipv6_gateway=data.dut4_to_tg_port_1_ip6,arp_send_req='1')
	st.log("INTFCONF: "+str(h2))

	# Configuring BGP on TG interface
	conf_var = {'mode':'enable', 'ip_version':'6', 'active_connect_enable':'1', 'local_as':data.remote_as_num1, 'remote_as':data.as_num_1, 'remote_ipv6_addr':data.dut1_to_tg_port_1_ip6}
	route_var = {'mode':'add', 'ip_version':'6', 'num_routes':data.test_bgp_route_count, 'prefix':'3300:1::', 'as_path':'as_seq:1'}
	ctrl_start = {'mode':'start'}
	ctrl_stop = {'mode':'stop'}

	# Starting the BGP router on TG.
	bgp_rtr1 = tgapi.tg_bgp_config(tg=tg, handle=h1['handle'], conf_var=conf_var, route_var = route_var, ctrl_var=ctrl_start)
	st.log("BGP_HANDLE: "+str(bgp_rtr1))

	# Verifying the BGP neighborship
	st.wait(10)
	st.log("Verifying the BGP neighborships.")
	if not bgpfeature.verify_bgp_summary(dut1, family='ipv6', neighbor=data.tg_to_dut1_port_1_ip6, state='Established'):
		st.report_fail("bgp_ip_peer_establish_fail", data.tg_to_dut1_port_1_ip6)

	yield
	st.log("Test Fixture Cleanup.")
	# Startup the routing interface link.
	st.log("Startup the routing interface link.")
	if not interface_obj.interface_operation(dut2, dut2_to_dut4_port_1, "startup"):
		st.report_fail('interface_admin_startup_fail', dut2_to_dut4_port_1)

	tg.tg_interface_config(port_handle=tg_handler["tg_ph_1"], handle=h1['handle'], mode='destroy')
	tg.tg_interface_config(port_handle=tg_handler["tg_ph_2"], handle=h2['handle'], mode='destroy')

def test_ft_l3_performance_enhancements_v4_bgp_clos_topology_route_propagation_time(fixture_v4):
	################# Author Details ################
	# Name: Rakesh Kumar Vooturi
	# Email:  rakesh-kumar.vooturi@broadcom.com
	#################################################
	#
	# Objective - FtOpSoRtPerfFn035 : Measure BGP route propagation time with BGP routes (with ECMP paths) in the CLOS topology
	#
	############### Test bed details ################
	#  TG --- DUT1 --- DUT2 --- DUT3 --- DUT4 --- TG
	#################################################
	print_topology("Route propagation time", "D1 -> D4")

	# Withdraw the routes.
	ctrl1=tg.tg_bgp_routes_control(handle=bgp_rtr1['conf']['handle'], route_handle=bgp_rtr1['route'][0]['handle'], mode='withdraw')
	st.log("TR_CTRL: "+str(ctrl1))

	# Verify the total route count using bcmcmd
	if not check_bcmcmd_route_count(dut1, 50, "ipv4", def_v4_route_count_d1, 0):
		st.report_fail("route_table_not_cleared_by_withdraw_from_tg")

	# Verify the total route count using bcmcmd
	if not check_bcmcmd_route_count(dut4, 50, "ipv4", def_v4_route_count_d4, 0):
		st.report_fail("route_table_not_cleared_by_withdraw_from_tg")

	st.log("#######################################################################################################################################################")
	st.log("# Measuring BGP v4 route propagation time in a CLOS topology")
	st.log("#######################################################################################################################################################")
	# Taking the start time timestamp
	start_time = datetime.datetime.now()

	# Readvertise the routes.
	ctrl1=tg.tg_bgp_routes_control(handle=bgp_rtr1['conf']['handle'], route_handle=bgp_rtr1['route'][0]['handle'], mode='readvertise')
	st.log("TR_CTRL: "+str(ctrl1))

	if not check_bcmcmd_route_count(dut4, 50, "ipv4", def_v4_route_count_d4, data.test_bgp_route_count):
		st.report_fail("route_table_not_updated_by_advertise_from_tg")

	# Taking the end time timestamp
	end_time = datetime.datetime.now()

	# Verify the total route count using bcmcmd
	if not check_bcmcmd_route_count(dut1, 50, "ipv4", def_v4_route_count_d1, data.test_bgp_route_count):
		st.report_fail("route_table_not_updated_by_advertise_from_tg")

	# Time taken for route installation
	st.log("Start Time: {}".format(start_time))
	st.log("End Time: {}".format(end_time))
	time_in_secs = end_time - start_time
	st.log("#######################################################################################################################################################")
	st.log("BGP v4 route propagation time in a CLOS topology in secs = {} ".format(time_in_secs.seconds))
	st.log("#######################################################################################################################################################")

	st.report_pass("test_case_passed")

def test_ft_l3_performance_enhancements_v4_bgp_clos_topology_direct_link_fail_convergence_time(fixture_v4):
	################# Author Details ################
	# Name: Rakesh Kumar Vooturi
	# Email:  rakesh-kumar.vooturi@broadcom.com
	#################################################
	#
	# Objective - FtOpSoRtPerfFn033 : Measure convergence time with BGP routes (with ECMP paths) in case of directly connected link failure
	# Objective - FtOpSoRtPerfFn030 : Performance measurement for BGP Link Failover case - Measure time taken to divert the traffic ( corresponding to BGP routes ) to the back link when active link carrying traffic ( corresponding to BGP routes ) -- goes down.
	#
	############### Test bed details ################
	#  TG --- DUT1 --- DUT2 --- DUT3 --- DUT4 --- TG
	#################################################
	print_topology("Direct link failover time", "D2 -> D4 Link")

	# Verify the total route count using bcmcmd
	if not check_bcmcmd_route_count(dut1, 50, "ipv4", def_v4_route_count_d1, data.test_bgp_route_count):
		st.report_fail("route_table_not_updated_by_advertise_from_tg")

	if not check_bcmcmd_route_count(dut4, 50, "ipv4", def_v4_route_count_d4, data.test_bgp_route_count):
		st.report_fail("route_table_not_updated_by_advertise_from_tg")

	# Configuring traffic stream on the TG interface
	tr1=tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], emulation_src_handle=h2['handle'], emulation_dst_handle=bgp_rtr1['route'][0]['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.traffic_rate_pps, enable_stream_only_gen='0')

	st.log("#######################################################################################################################################################")
	st.log("# Measuring convergence time with BGP v4 routes (with ECMP paths) in case of directly connected link failure")
	st.log("#######################################################################################################################################################")
	# Starting the TG traffic after clearing the DUT counters
	papi.clear_interface_counters(dut1)
	tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
	tg.tg_traffic_control(action="run",handle=tr1['stream_id'])

	# Shutdown the routing interface link.
	st.log("Shutdown the routing interface link.")
	if not interface_obj.interface_operation(dut2, dut2_to_dut4_port_1 , "shutdown"):
		st.report_fail('interface_admin_shut_down_fail', dut2_to_dut4_port_1)

	# Wait for traffic to reroute
	papi.get_interface_counters_all(dut1)
	st.wait(30)
	if not check_intf_traffic_counters(dut1, dut1_to_tg_port_1, 30):
		st.report_fail("ingress_traffic_rate_not_matching_with_egress_rate")

	# Stopping the TG traffic
	tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])

	# Stats fetching
	st.log("Fetching the stats on TG ports")
	tg_1_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_1"])
	tg_2_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_2"])
	total_rx = tg_1_stats.rx.total_packets
	total_tx = tg_2_stats.tx.total_packets

	# Stats verification
	st.log("Sent Packets On TG2: {} and Received Packets On TG1: {}".format(total_tx, total_rx))
	if (int(total_tx) == 0):
		st.log("Traffic verification failed : Failed to send traffic from TG2 to TG1.")
		st.report_fail("traffic_verification_failed")

	time_taken = round((int(total_tx)-int(total_rx))/(int(data.test_bgp_route_count)*1.0),1)

	# Time taken for convergence
	st.log("#######################################################################################################################################################")
	st.log(" Convergence time with BGP v4 routes (with ECMP paths) in case of directly connected link failure in secs = " +str(time_taken))
	st.log("#######################################################################################################################################################")

	st.report_pass("test_case_passed")

def test_ft_l3_performance_enhancements_v6_bgp_clos_topology_direct_link_fail_convergence_time(fixture_v6):
	################# Author Details ################
	# Name: Rakesh Kumar Vooturi
	# Email:  rakesh-kumar.vooturi@broadcom.com
	#################################################
	#
	# Objective - FtOpSoRtPerfFn044 : Performance measurement for BGP v6 Link Failover case - Measure time taken to divert the traffic ( corresponding to BGP routes ) to the back link when active link carrying traffic ( corresponding to BGP routes ) -- goes down.
	#
	############### Test bed details ################
	#  TG --- DUT1 --- DUT2 --- DUT3 --- DUT4 --- TG
	#################################################
	print_topology("Direct link failover time", "D2 -> D4 Link")

	# Verify the total route count using bcmcmd
	if not check_bcmcmd_route_count(dut1, 50, "ipv6", def_v6_route_count_d1, data.test_bgp_route_count):
		st.report_fail("route_table_not_updated_by_advertise_from_tg")

	if not check_bcmcmd_route_count(dut4, 50, "ipv6", def_v6_route_count_d4, data.test_bgp_route_count):
		st.report_fail("route_table_not_updated_by_advertise_from_tg")

	# Configuring traffic stream on the TG interface
	tr1=tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], emulation_src_handle=h2['handle'], emulation_dst_handle=bgp_rtr1['route'][0]['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.traffic_rate_pps, enable_stream_only_gen='0')

	st.log("#######################################################################################################################################################")
	st.log("# Measuring convergence time with BGP v6 routes (with ECMP paths) in case of directly connected link failure")
	st.log("#######################################################################################################################################################")
	# Starting the TG traffic after clearing the DUT counters
	papi.clear_interface_counters(dut1)
	tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
	tg.tg_traffic_control(action="run",handle=tr1['stream_id'])

	# Shutdown the routing interface link.
	st.log("Shutdown the routing interface link.")
	if not interface_obj.interface_operation(dut2, dut2_to_dut4_port_1 , "shutdown"):
		st.report_fail('interface_admin_shut_down_fail', dut2_to_dut4_port_1)

	# Wait for traffic to reroute
	papi.get_interface_counters_all(dut1)
	st.wait(30)
	if not check_intf_traffic_counters(dut1, dut1_to_tg_port_1, 30):
		st.report_fail("ingress_traffic_rate_not_matching_with_egress_rate")

	# Stopping the TG traffic
	tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])

	# Stats fetching
	st.log("Fetching the stats on TG ports")
	tg_1_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_1"])
	tg_2_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_2"])
	total_rx = tg_1_stats.rx.total_packets
	total_tx = tg_2_stats.tx.total_packets

	# Stats verification
	st.log("Sent Packets On TG2: {} and Received Packets On TG1: {}".format(total_tx, total_rx))
	if (int(total_tx) == 0):
		st.log("Traffic verification failed : Failed to send traffic from TG2 to TG1.")
		st.report_fail("traffic_verification_failed")

	time_taken = round((int(total_tx)-int(total_rx))/(int(data.test_bgp_route_count)*1.0),1)

	# Time taken for convergence
	st.log("#######################################################################################################################################################")
	st.log(" Convergence time with BGP v6 routes (with ECMP paths) in case of directly connected link failure in secs = " +str(time_taken))
	st.log("#######################################################################################################################################################")

	st.report_pass("test_case_passed")

def test_ft_l3_performance_enhancements_v4_bgp_clos_topology_indirect_link_fail_convergence_time(fixture_v4):
	################# Author Details ################
	# Name: Rakesh Kumar Vooturi
	# Email:  rakesh-kumar.vooturi@broadcom.com
	#################################################
	#
	# Objective - FtOpSoRtPerfFn034 : Measure convergence time with BGP routes (with ECMP paths) in case of indirectly connected link failure
	#
	############### Test bed details ################
	#  TG --- DUT1 --- DUT2 --- DUT3 --- DUT4 --- TG
	#################################################
	print_topology("Indirect link failover time", "D3 -> D1 Link")

	# Verify the total route count using bcmcmd
	if not check_bcmcmd_route_count(dut1, 50, "ipv4", def_v4_route_count_d1, data.test_bgp_route_count):
		st.report_fail("route_table_not_updated_by_advertise_from_tg")

	if not check_bcmcmd_route_count(dut4, 50, "ipv4", def_v4_route_count_d4, data.test_bgp_route_count):
		st.report_fail("route_table_not_updated_by_advertise_from_tg")

	# Configuring traffic stream on the TG interface
	tr1=tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], emulation_src_handle=h2['handle'], emulation_dst_handle=bgp_rtr1['route'][0]['handle'], circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.traffic_rate_pps, enable_stream_only_gen='0')

	st.log("#######################################################################################################################################################")
	st.log("# Measuring convergence time with BGP v4 routes (with ECMP paths) in case of indirectly connected link failure")
	st.log("#######################################################################################################################################################")
	# Starting the TG traffic after clearing the DUT counters
	papi.clear_interface_counters(dut1)
	tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
	tg.tg_traffic_control(action="run",handle=tr1['stream_id'])

	# Shutdown the routing interface link.
	st.log("Shutdown the routing interface link.")
	if not interface_obj.interface_operation(dut3, dut3_to_dut1_port_1 , "shutdown"):
		st.report_fail('interface_admin_shut_down_fail', dut3_to_dut1_port_1)

	# Wait for traffic to reroute
	papi.get_interface_counters_all(dut1)
	st.wait(30)
	if not check_intf_traffic_counters(dut1, dut1_to_tg_port_1, 30):
		st.report_fail("ingress_traffic_rate_not_matching_with_egress_rate")

	# Stopping the TG traffic
	tg.tg_traffic_control(action='stop', handle=tr1['stream_id'])

	# Stats fetching
	st.log("Fetching the stats on TG ports")
	tg_1_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_1"])
	tg_2_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_2"])
	total_rx = tg_1_stats.rx.total_packets
	total_tx = tg_2_stats.tx.total_packets

	# Stats verification
	st.log("Sent Packets On TG2: {} and Received Packets On TG1: {}".format(total_tx, total_rx))
	if (int(total_tx) == 0):
		st.log("Traffic verification failed : Failed to send traffic from TG2 to TG1.")
		st.report_fail("traffic_verification_failed")

	time_taken = round((int(total_tx)-int(total_rx))/(int(data.test_bgp_route_count)*1.0),1)

	# Time taken for convergence
	st.log("#######################################################################################################################################################")
	st.log(" Convergence time with BGP v4 routes (with ECMP paths) in case of indirectly connected link failure in secs = " +str(time_taken))
	st.log("#######################################################################################################################################################")

	st.report_pass("test_case_passed")
