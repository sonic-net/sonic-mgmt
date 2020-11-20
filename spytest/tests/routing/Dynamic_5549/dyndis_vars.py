###############################################################################
#Script Title : BGP Dynamic Discovery and BGP unnumbered
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com
###############################################################################
from spytest.dicts import SpyTestDict

data = SpyTestDict()
data.test_var = 'testing'

#Loopback
dut1_loopback = 'Loopback1'
dut2_loopback = 'Loopback2'
dut3_loopback = 'Loopback3'

dut1_loopback_ip =  '1.1.1.1'
dut2_loopback_ip =  '2.2.2.2'
dut3_loopback_ip =  '3.3.3.3'

dut1_loopback_ipv6 = '1111::1'
dut2_loopback_ipv6 = '2222::2'
dut2_loopback_ipv6 = '3333::3'

dut1_loopback_ip_subnet = '32'
dut2_loopback_ip_subnet = '32'
dut3_loopback_ip_subnet = '32'

dut1_loopback_ipv6_subnet = '128'
dut2_loopback_ipv6_subnet = '128'
dut3_loopback_ipv6_subnet = '128'

#DUT and TG vlans
dut1_dut2_vlan = '2'
dut2_dut3_vlan = '3'

dut1_tg_vlan = ['11, 12, 13']
dut2_tg_vlan = ['21, 22, 23'] 
dut3_tg_vlan = ['31, 32, 33']

dut1_vrf = 'Vrf-red'
dut2_vrf = 'Vrf-blue'
dut3_vrf = 'Vrf-green'

dut1_loopback = '4.4.4.4'
dut2_loopback = '5.5.5.5'
dut3_loopback = '6.6.6.6'

#DUT and TG IPs
dut1_dut2_ip = ['1.0.%s.2'%x for x in range(1,10)]
dut2_dut1_ip = ['1.0.%s.3'%x for x in range(1,10)]
dut2_dut3_ip = ['2.0.%s.1'%x for x in range(1,10)]
dut3_dut2_ip = ['2.0.%s.2'%x for x in range(1,10)]

dut1_dut2_ip_subnet = '24'
dut2_dut1_ip_subnet = '24'
dut2_dut3_ip_subnet = '24'
dut3_dut2_ip_subnet = '24'

dut1_link_local_addr = 'fe80::3e2c:99ff:fe1e:1111'
dut2_link_local_addr = 'fe80::3e2c:99ff:fe2e:2222'
dut3_link_local_addr = 'fe80::3e2c:99ff:fe3e:3333'

dut1_dut2_ipv6 = ['100%s::2'%x for x in range(1,10)]
dut2_dut1_ipv6 = ['100%s::3'%x for x in range(1,10)]
dut2_dut3_ipv6 = ['200%s::1'%x for x in range(1,10)]
dut3_dut2_ipv6 = ['200%s::2'%x for x in range(1,10)]

dut1_dut3_ip = ['3.0.%s.1'%x for x in range(1,10)]
dut3_dut3_ip = ['3.0.%s.2'%x for x in range(1,10)]

dut1_dut2_ipv6_subnet = '64'
dut2_dut1_ipv6_subnet = '64'
dut2_dut3_ipv6_subnet = '64'
dut3_dut2_ipv6_subnet = '64'

dut1_tg1_network_v4 = ['11.0.1.0/24']
dut2_tg1_network_v4 = ['21.0.1.0/24']
dut3_tg1_network_v4 = ['31.0.1.0/24']
dut1_tg1_network_v6 = ['1101::/64']
dut2_tg1_network_v6 = ['2101::/64']
dut3_tg1_network_v6 = ['3101::/64']

dut1_dut2_network_v4_static = ['1.0.3.0/24']
dut2_dut3_network_v4_static = ['2.0.4.0/24']
dut1_dut2_network_v6_static = ['1003::/64']
dut2_dut3_network_v6_static = ['2004::/64']

dut1_tg1_network_v4_vrf = ['12.0.1.0/24']
dut2_tg1_network_v4_vrf = ['22.0.1.0/24']
dut3_tg1_network_v4_vrf = ['32.0.1.0/24']
dut1_tg1_network_v6_vrf = ['1201::/64']
dut2_tg1_network_v6_vrf = ['2201::/64']
dut3_tg1_network_v6_vrf = ['3201::/64']

dut1_tg_ip = ['%s.0.1.1'%x for x in range (11,15)]
tg_dut1_ip = ['%s.0.1.2'%x for x in range (11,15)]
dut2_tg_ip = ['%s.0.1.1'%x for x in range (21,25)]
tg_dut2_ip = ['%s.0.1.2'%x for x in range (21,25)]
dut3_tg_ip = ['%s.0.1.1'%x for x in range (31,35)]
tg_dut3_ip = ['%s.0.1.2'%x for x in range (31,35)]

dut1_tg_ip_subnet = '24'
tg_dut1_ip_subnet = '24'
dut2_tg_ip_subnet = '24'
tg_dut2_ip_subnet = '24'
dut3_tg_ip_subnet = '24'
tg_dut3_ip_subnet = '24'

dut1_tg_ipv6 = ['%s01::1'%x for x in range (11,15)]
tg_dut1_ipv6 = ['%s01::2'%x for x in range (11,15)]
dut2_tg_ipv6 = ['%s01::1'%x for x in range (21,25)]
tg_dut2_ipv6 = ['%s01::2'%x for x in range (21,25)]
dut3_tg_ipv6 = ['%s01::1'%x for x in range (31,35)]
tg_dut3_ipv6 = ['%s01::2'%x for x in range (31,35)]

dut1_tg_ipv6_subnet = '64'
tg_dut1_ipv6_subnet = '64'
dut2_tg_ipv6_subnet = '64'
tg_dut2_ipv6_subnet = '64'
dut3_tg_ipv6_subnet = '64'
tg_dut3_ipv6_subnet = '64'

#BGP parameters
dut1_as = '100'
dut2_as = '200'
dut3_as = '300'

dut1_as_vrf = '400'
dut2_as_vrf = '500'
dut3_as_vrf = '600'

keep_alive = '3'
hold_down = '9'

dut1_router_id = '11.11.11.11'
dut2_router_id = '22.22.22.22'
dut3_router_id = '33.33.33.33'

dut1_router_id_vrf = '44.44.44.44'
dut2_router_id_vrf = '55.55.55.55'
dut3_router_id_vrf = '66.66.66.66'

#DUT1 traffic parameters
# dut1_hosts = '1'
# tg_dut1_rate_pps = '2000'
# tg_dut1_p1_v4_routes = '100'
# tg_dut1_p1_v4_prefix = '50.0.0.1'
# tg_dut1_p1_v6_routes = '100'
# tg_dut1_p1_v6_prefix = '5000::1'

#DUT3 traffic parameters
# dut3_hosts = '1'
# tg_dut3_rate_pps = '2000'
# tg_dut3_p1_v4_routes = '100'
# tg_dut3_p1_route_prefix = '60.0.0.1'
# tg_dut3_p1_v6_routes = '100'
# tg_dut3_p1_route_prefix = '6000::1'
#
###############################################################################
###############################################################################

