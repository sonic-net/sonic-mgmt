from spytest import SpyTestDict

data = SpyTestDict()
data.test_var = 'testing'
data.mac_aging = 10

data.vrf_name = ['Vrf-' + '%s' % x for x in range(101, 105)]
# vrf_name_scale = ['Vrf-'+'%s'%x for x in range (1,1000)]
# Vlan
data.dut1_dut2_vlan = ['%s' % x for x in range(101, 105)]
data.dut2_dut1_vlan = ['%s' % x for x in range(101, 105)]

# dut1_dut2_vlan_scale = ['%s'%x for x in range (1,1000)]

data.dut1_tg1_vlan = ['%s' % x for x in range(11, 14)]
data.dut2_tg1_vlan = ['%s' % x for x in range(16, 19)]

# Loopback
data.dut1_loopback = ['Loopback101', 'Loopback102', 'Loopback103']
data.dut2_loopback = ['Loopback101', 'Loopback102', 'Loopback103']

data.dut1_loopback_ip = ['50.0.%s.1' % x for x in range(1, 4)]
data.dut2_loopback_ip = ['60.0.%s.1' % x for x in range(1, 4)]
data.dut1_loopback_ip_subnet = '32'
data.dut2_loopback_ip_subnet = '32'

data.dut1_loopback_ipv6 = ['500%s::1' % x for x in range(1, 4)]
data.dut2_loopback_ipv6 = ['600%s::1' % x for x in range(1, 4)]
data.dut1_loopback_ipv6_subnet = '128'
data.dut2_loopback_ipv6_subnet = '128'

# DUT and TG IPs
data.dut1_dut2_vrf_ip = ['3.0.%s.1' % x for x in range(101, 105)]
data.dut2_dut1_vrf_ip = ['3.0.%s.2' % x for x in range(101, 105)]
data.dut1_dut2_vrf_ip_subnet = '24'
data.dut2_dut1_vrf_ip_subnet = '24'

data.dut1_dut2_vrf_ipv6 = ['3%s::1' % x for x in range(101, 201)]
data.dut2_dut1_vrf_ipv6 = ['3%s::2' % x for x in range(101, 201)]
data.dut1_dut2_vrf_ipv6_subnet = '64'
data.dut2_dut1_vrf_ipv6_subnet = '64'

data.dut1_tg1_vrf_ip = ['1.0.%s.1' % x for x in range(1, 4)]
data.tg1_dut1_vrf_ip = ['1.0.%s.2' % x for x in range(1, 4)]
data.dut1_tg1_vrf_ip_subnet = '24'
data.tg1_dut1_vrf_ip_subnet = '24'

data.dut1_tg1_vrf_ipv6 = ['201%s::1' % x for x in range(1, 4)]
data.tg1_dut1_vrf_ipv6 = ['201%s::2' % x for x in range(1, 4)]
data.dut1_tg1_vrf_ipv6_subnet = '64'
data.tg1_dut1_vrf_ipv6_subnet = '64'

data.dut2_tg1_vrf_ip = ['6.0.%s.1' % x for x in range(6, 9)]
data.tg1_dut2_vrf_ip = ['6.0.%s.2' % x for x in range(6, 9)]
data.dut2_tg1_vrf_ip_subnet = '24'
data.tg1_dut2_vrf_ip_subnet = '24'

data.dut2_tg1_vrf_ipv6 = ['202%s::1' % x for x in range(6, 9)]
data.tg1_dut2_vrf_ipv6 = ['202%s::2' % x for x in range(6, 9)]
data.dut2_tg1_vrf_ipv6_subnet = '64'
data.tg1_dut2_vrf_ipv6_subnet = '64'

# BGP dut1 parameter
data.dut1_as = ['%s' % x for x in range(101, 201)]
# dut1_as = ['101','101','101']

data.dut1_router_id = '11.11.11.11'
data.dut1_keepalive = '60'
data.dut1_holddown = '180'
data.dut1_ip_peergroup = 'ip_peergroup'
data.dut1_ipv6_peergroup = 'ipv6_peergroup'

# BGP dut2 parameters
data.dut2_as = ['%s' % x for x in range(101, 201)]
# dut2_as = ['101','101','101']

data.dut2_router_id = '22.22.22.22'
data.dut2_keepalive = '60'
data.dut2_holddown = '180'
data.dut2_ip_peergroup = 'ip_peergroup'
data.dut2_ipv6_peergroup = 'ipv6_peergroup'

# BGP TG parameters
data.dut1_tg_as = '300'
data.dut2_tg_as = '300'

# DUT1 traffic parameters
data.dut1_hosts = '10'
data.tg_dut1_rate_pps = '2000'
data.tg_dut1_p1_v4_routes = '50'
data.tg_dut1_p1_v4_prefix = '10.0.0.0'
data.tg_dut1_p1_v6_routes = '50'
data.tg_dut1_p1_v6_prefix = '2110::1'

# DUT2 traffic parameters
data.dut2_hosts = '10'
data.tg_dut2_rate_pps = '2000'
data.tg_dut2_p1_v4_routes = '50'
data.tg_dut2_p1_route_prefix = '11.0.0.0'
data.tg_dut2_p1_v6_routes = '50'
data.tg_dut2_p1_route_prefix = '2111::1'
#
##############################################################################
###############################################################################

# vrf_list = ['Vrf-'+'%s'%x for x in range (1,1000)]
# dut1_dut2_vlan_list = ['%s'%x for x in range (1,1000)]
data.dut1_as_scale = ['%s' % x for x in range(1, 100)]
data.dut2_as_scale = ['%s' % x for x in range(101, 199)]
data.dut1_loopback_scale = ['Loopback-' + '%s' % x for x in range(1, 100)]
data.dut2_loopback_scale = ['Loopback-' + '%s' % x for x in range(1, 100)]

data.wait_time_vrf = 400  # 400 #130 for 400 intf , 350 for full scl
data.wait_time_vlan = 2300  # 2300 # 2220 for 1000 intf
