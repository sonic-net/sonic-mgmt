###############################################################################
#Script Title : IP unnumbered over non-default vrf vrf and vlan
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com

###############################################################################
from spytest.dicts import SpyTestDict

data = SpyTestDict()
data.test_var = 'testing'

#DUT values
data.dut1_loopback = ['Loopback%s'%x for x in range(1,10)]
data.dut2_loopback = ['Loopback%s'%x for x in range(1,10)]
data.dut1_loopback_ip = ['1.0.%s.2'%x for x in range(1,10)]
data.dut2_loopback_ip = ['2.0.%s.2'%x for x in range(1,10)]
data.dut1_loopback_ipv6 = ['100%s::2'%x for x in range(1,10)]
data.dut2_loopback_ipv6 = ['200%s::2'%x for x in range(1,10)]
data.dut1_ospf_router_id = '5.5.5.5' 
data.dut2_ospf_router_id = '6.6.6.6' 
data.portchannel = 'PortChannel1'
data.ip_loopback_prefix = '32'
data.ipv6_loopback_prefix = '128'
data.dut1_dut2_vlan = ['2', '3']
data.dut1_vrf = ['Vrf-red', 'Vrf-blue', 'Vrf-green']
data.dut1_dut2_ip = ['4.0.%s.2'%x for x in range(1,10)]
data.dut2_dut1_ip = ['4.0.%s.3'%x for x in range(1,10)]
data.dut1_dut2_ipv6 = ['400%s::1'%x for x in range(1,10)]
data.dut2_dut1_ipv6 = ['400%s::2'%x for x in range(1,10)]
data.dut1_dut2_ip_subnet = '25'
data.dut1_dut2_ipv6_subnet = '64'

#Traffic values
data.dut1_tg1_network_v4 = ['11.0.1.0/24']
data.dut2_tg1_network_v4 = ['21.0.1.0/24']
data.dut1_tg_vlan = ['11, 12, 13']
data.dut2_tg_vlan = ['21, 22, 23'] 
data.dut1_tg_ip = ['%s.0.1.1'%x for x in range (11,15)]
data.tg_dut1_ip = ['%s.0.1.2'%x for x in range (11,15)]
data.dut2_tg_ip = ['%s.0.1.1'%x for x in range (21,25)]
data.tg_dut2_ip = ['%s.0.1.2'%x for x in range (21,25)]
data.tg_ip_subnet = '24'
data.dut1_tg_ipv6 = ['%s01::1'%x for x in range (11,15)]
data.tg_dut1_ipv6 = ['%s01::2'%x for x in range (11,15)]
data.dut2_tg_ipv6 = ['%s01::1'%x for x in range (21,25)]
data.tg_dut2_ipv6 = ['%s01::2'%x for x in range (21,25)]
data.tg_ipv6_subnet = '64'