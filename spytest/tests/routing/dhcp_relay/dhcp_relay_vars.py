from spytest.dicts import SpyTestDict

data = SpyTestDict()

#IP params
mask = '31'
mask_1 = '20'
mask_v6 = '64'
mask_24 = '24'
dut1_2_ip_list = ['12.12.12.0']
dut2_1_ip_list = ['12.12.12.1']
dut1_3_ip_list = ['13.13.13.0']
dut3_1_ip_list = ['13.13.13.1']
dut2_4_ip_list = ['192.168.0.1','20.20.20.1','30.30.30.1']
#dut3_server_ip_list = ['172.16.40.1']
#dut3_server_ipv6_list = ['2072::1']

dut1_loopback_ip_list = ['1.1.1.1','1.1.1.5']
dut2_loopback_ip_list = ['2.2.2.1','2.2.2.5']
dut3_loopback_ip_list = ['3.3.3.1','3.3.3.5','55.55.55.55']


## Added for IPv6 address
dut1_2_ipv6_list = ['2001::1:1', '2002::2:1', '2003::3:1']
dut2_1_ipv6_list = ['2001::1:2', '2002::2:2', '2003::3:2']
dut1_3_ipv6_list = ['3001::1:1', '3002::2:1', '3003::3:1']
dut3_1_ipv6_list = ['3001::1:2', '3002::2:2', '3003::3:2']
dut2_4_ipv6_list = ['2092::1', '2020::1', '2030::1']

dut1_AS ='100'
dut2_AS ='200'
dut3_AS ='300'

"""
dhcp_server_ip_list = ['172.16.0.241']
dhcp_server_ipv6_list = ['2072::241']
dhcp_server_port = 'Ethernet45'
"""
vrf_name ='Vrf-Red'
vrf_blue ='Vrf-Blue'

data.inter_vni = False
src_intf_same_vni = 'Loopback3'
src_intf_diff_vni = 'Loopback4'

route_list =  ['192.168.0.0/24','20.20.20.0/24','192.168.200.0/24','30.30.30.0/24','100.100.100.100/32','100.100.100.101/32','22.22.1.0/24']
route_list_6 = ['2092::0/64', '2020::0/64', '2200::0/64','2030::0/64','4000::10/128','4000::11/128', '1212::0/64']

dut1_ospf_router_id = '9.9.9.9'
dut3_ospf_router_id = '8.8.8.8'
ip_loopback_prefix ='32'


#####Scale Test Vars - Start
data.clients_supported = 2048
data.vlan_intf_index = 2

data.start_vlan = 3500

data.vlan_intf_count_list = [32, 64, 128, 256]
data.vlan_intf_plen_list = [25, 26, 27, 28]

data.vlan_intf_count = data.vlan_intf_count_list[data.vlan_intf_index]
data.end_vlan = data.start_vlan + data.vlan_intf_count - 1

data.clients_per_intf = data.clients_supported / data.vlan_intf_count

data.oct3 = 100
data.oct4 = 1
data.vlan_intf_nw = '172.172'
data.vlan_intf_ip_pl = data.vlan_intf_plen_list[data.vlan_intf_index]

data.vlan_intf_nw6 = '1700:A:B:'
data.vlan_intf_ip_pl6 = 64

data.server_nw = '192.85.100'
data.d3_tg_1_ip = '{}.{}'.format(data.server_nw,'50')

data.server_nw6 = '1928'
data.d3_tg_1_ip6 = '{}::{}'.format(data.server_nw6,'50')
#####Scale Test Vars - End 

