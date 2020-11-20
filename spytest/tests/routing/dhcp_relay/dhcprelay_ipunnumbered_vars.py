from spytest.dicts import SpyTestDict

data = SpyTestDict()

#IP params
mask = '31'
mask_1 = '20'
mask_v6 = '64'
mask_24 = '24'
dut2_3_ip_list = ['12.12.12.2']
dut3_2_ip_list = ['12.12.12.3']
dut1_3_ip_list = ['13.13.13.2']
dut3_1_ip_list = ['13.13.13.3']
dut2_4_ip_list = ['192.168.0.1','20.20.20.1','30.30.30.1']

dut1_loopback_ip_list = ['172.16.40.210']
dut2_loopback_ip_list = ['100.100.100.100']
dut3_loopback_ip_list = ['55.55.55.55']


## Added for IPv6 address
dut2_3_ipv6_list = ['2001::1:1', '2002::2:1', '2003::3:1']
dut3_2_ipv6_list = ['2001::1:2', '2002::2:2', '2003::3:2']
dut1_3_ipv6_list = ['3001::1:1', '3002::2:1', '3003::3:1']
dut3_1_ipv6_list = ['3001::1:2', '3002::2:2', '3003::3:2']
dut2_4_ipv6_list = ['2092::1', '2020::1', '2030::1']

dut2_AS ='200'
dut3_AS ='300'
dut2_router_id = '2.2.2.2'
dut3_router_id = '3.3.3.3'

vrf_name ='Vrf-Red'
vrf_blue ='Vrf-Blue'


route_list =  ['192.168.0.0/24','20.20.20.0/24','192.168.200.0/24','30.30.30.0/24','100.100.100.100/32']
route_list_6 = ['2092::0/64', '2020::0/64', '2200::0/64','2030::0/64','4000::10/128','4000::11/128', '1212::0/64']

dut1_ospf_router_id = '9.9.9.9'
dut3_ospf_router_id = '8.8.8.8'
ip_loopback_prefix ='32'

server_filename ='isc-dhcp-server'

