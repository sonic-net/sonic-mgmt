from spytest.dicts import SpyTestDict

data = SpyTestDict()
data.test_var = 'testing'
data.mac_aging = 10

vrf_name = ['Vrf-'+'%s'%x for x in range (101,105)]
vrf_name_scale = ['Vrf-'+'%s'%x for x in range (1,1000)]
#Vlan
dut1_dut2_vlan = ['%s'%x for x in range (101,105)]
dut2_dut1_vlan = ['%s'%x for x in range (101,105)]

dut1_dut2_vlan_scale = ['%s'%x for x in range (1,1000)]

dut1_tg1_vlan = ['%s'%x for x in range (1,4)]
dut2_tg1_vlan = ['%s'%x for x in range (6,9)]

#Loopback
dut1_loopback = ['Loopback101', 'Loopback102', 'Loopback103']
dut2_loopback = ['Loopback101', 'Loopback102', 'Loopback103']

dut1_loopback_ip =  ['50.0.%s.1'%x for x in range (1,4)]
dut2_loopback_ip =  ['60.0.%s.1'%x for x in range (1,4)]
dut1_loopback_ip_subnet = '32'
dut2_loopback_ip_subnet = '32'

dut1_loopback_ipv6 = ['500%s::1'%x for x in range (1,4)]
dut2_loopback_ipv6 = ['600%s::1'%x for x in range (1,4)]
dut1_loopback_ipv6_subnet = '128'
dut2_loopback_ipv6_subnet = '128'

#DUT and TG IPs
dut1_dut2_vrf_ip = ['3.0.%s.1'%x for x in range(101,105)]
dut2_dut1_vrf_ip = ['3.0.%s.2'%x for x in range(101,105)]
dut1_dut2_vrf_ip_subnet = '24'
dut2_dut1_vrf_ip_subnet = '24'

dut1_dut2_vrf_ipv6 = ['3%s::1'%x for x in range(101,201)]
dut2_dut1_vrf_ipv6 = ['3%s::2'%x for x in range(101,201)]
dut1_dut2_vrf_ipv6_subnet = '64'
dut2_dut1_vrf_ipv6_subnet = '64'

dut1_tg1_vrf_ip = ['1.0.%s.1'%x for x in range (1,4)]
tg1_dut1_vrf_ip = ['1.0.%s.2'%x for x in range (1,4)]
dut1_tg1_vrf_ip_subnet = '24'
tg1_dut1_vrf_ip_subnet = '24'

dut1_tg1_vrf_ipv6 = ['201%s::1'%x for x in range (1,4)]
tg1_dut1_vrf_ipv6 = ['201%s::2'%x for x in range (1,4)]
dut1_tg1_vrf_ipv6_subnet = '64'
tg1_dut1_vrf_ipv6_subnet = '64'

dut2_tg1_vrf_ip = ['6.0.%s.1'%x for x in range (6,9)]
tg1_dut2_vrf_ip = ['6.0.%s.2'%x for x in range (6,9)]
dut2_tg1_vrf_ip_subnet = '24'
tg1_dut2_vrf_ip_subnet = '24'

dut2_tg1_vrf_ipv6 = ['202%s::1'%x for x in range (6,9)]
tg1_dut2_vrf_ipv6 = ['202%s::2'%x for x in range (6,9)]
dut2_tg1_vrf_ipv6_subnet = '64'
tg1_dut2_vrf_ipv6_subnet = '64'

#BGP dut1 parameter
dut1_as = ['%s'%x for x in range (101,201)]
#dut1_as = ['101','101','101']

dut1_router_id = '11.11.11.11'
dut1_keepalive = '60'
dut1_holddown = '180'
dut1_ip_peergroup = 'ip_peergroup'
dut1_ipv6_peergroup = 'ipv6_peergroup'

#BGP dut2 parameters
dut2_as = ['%s'%x for x in range (101,201)]
#dut2_as = ['101','101','101']

dut2_router_id = '22.22.22.22'
dut2_keepalive = '60'
dut2_holddown = '180'
dut2_ip_peergroup = 'ip_peergroup'
dut2_ipv6_peergroup = 'ipv6_peergroup'

#BGP TG parameters
dut1_tg_as = '300'
dut2_tg_as = '300'

#DUT1 traffic parameters
dut1_hosts = '10'
tg_dut1_rate_pps = '2000'
tg_dut1_p1_v4_routes = '50'
tg_dut1_p1_v4_prefix = '10.0.0.1'
tg_dut1_p1_v6_routes = '50'
tg_dut1_p1_v6_prefix = '2110::1'

#DUT2 traffic parameters
dut2_hosts = '10'
tg_dut2_rate_pps = '2000'
tg_dut2_p1_v4_routes = '50'
tg_dut2_p1_v4_route_prefix = '11.0.0.1'
tg_dut2_p1_v6_routes = '50'
tg_dut2_p1_v6_route_prefix = '2111::1'
#
##############################################################################
###############################################################################

vrf_list = ['Vrf-'+'%s'%x for x in range (1,1000)]
dut1_dut2_vlan_list = ['%s'%x for x in range (1,1000)]
dut1_as_scale = ['%s'%x for x in range (1,100)]
dut2_as_scale = ['%s'%x for x in range (101,199)]
dut1_loopback_scale = ['Loopback-'+'%s'%x for x in range (1,100)]
dut2_loopback_scale = ['Loopback-'+'%s'%x for x in range (1,100)]

wait_time_vrf =  400 #400 #130 for 400 intf , 350 for full scl
wait_time_vlan = 2300 #2300 # 2220 for 1000 intf
