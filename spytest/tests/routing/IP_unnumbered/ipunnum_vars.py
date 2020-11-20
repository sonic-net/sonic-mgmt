###############################################################################
#Script Title : BGP Dynamic Discovery and BGP unnumbered
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com

###############################################################################
from spytest.dicts import SpyTestDict

data = SpyTestDict()
data.test_var = 'testing'

#Loopback
dut1_loopback = ['Loopback%s'%x for x in range(11,20)]
dut2_loopback = ['Loopback%s'%x for x in range(21,30)]
dut3_loopback = ['Loopback%s'%x for x in range(31,40)]

ip_loopback_prefix = '32'
ipv6_loopback_prefix = '128'
ipv6_loopback_prefix = '128'

dut1_loopback_ip = ['1.0.%s.2'%x for x in range(1,10)]
dut2_loopback_ip = ['2.0.%s.2'%x for x in range(1,10)]
dut3_loopback_ip = ['3.0.%s.2'%x for x in range(1,10)]

dut1_loopback_ipv6 = ['100%s::2'%x for x in range(1,10)]
dut2_loopback_ipv6 = ['200%s::2'%x for x in range(1,10)]
dut3_loopback_ipv6 = ['300%s::2'%x for x in range(1,10)]

dut1_dut2_ip = ['4.0.%s.2'%x for x in range(1,10)]
dut2_dut1_ip = ['4.0.%s.3'%x for x in range(1,10)]
dut1_dut2_ipv6 = ['400%s::1'%x for x in range(1,10)]
dut2_dut1_ipv6 = ['400%s::2'%x for x in range(1,10)]

dut1_tg1_network_v4 = ['11.0.1.0/24']
dut2_tg1_network_v4 = ['21.0.1.0/24']
dut3_tg1_network_v4 = ['31.0.1.0/24']

#DUT and TG vlans
dut1_dut2_vlan = '2'
dut2_dut3_vlan = '3'

dut1_tg_vlan = ['11, 12, 13']
dut2_tg_vlan = ['21, 22, 23'] 
dut3_tg_vlan = ['31, 32, 33']

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

keep_alive = '2'
hold_down = '6'

dut1_router_id = '11.11.11.11'
dut2_router_id = '22.22.22.22'
dut3_router_id = '33.33.33.33'

########################################################################
###############################################################################

