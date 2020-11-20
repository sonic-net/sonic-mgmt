user_vrf_name = 'Vrf-101'
vrf_name = 'default-vrf'

l2_switch = 'no'
#vlan params
access_vlan = "100"
access_vlan_vrf = "104"
access_vlan_name = "Vlan100"
access_vlan_name_vrf = "Vlan104"
trunk_vlan = ["101","102","103"]
trunk_vlan_vrf = ["105","106","107"]
trunk_vlan_name = ["Vlan101","Vlan102","Vlan103"]
trunk_vlan_name_vrf = ["Vlan105","Vlan106","Vlan107"]
dut2_l2_vlan = "200"
dut2_l2_vlan_name = "Vlan200"

#dut_ip params
dut1_ip_list = ['12.12.4.1','12.12.5.1','12.12.1.1','12.12.2.1','12.12.3.1']
dut2_ip_list = ['12.12.4.2','12.12.4.3']
dut3_ip_list = ['12.12.4.2','12.12.5.2','12.12.1.2','12.12.2.2','12.12.3.2']
dut1_tg_ip = '10.10.10.1'
dut3_tg_ip = '20.20.20.1'
ip_mask = '24'

#dut_ipv6 params
dut1_ipv6_list = ['2114::1','2115::1','2111::1','2112::1','2113::1']
dut1_link_local = 'fe80::1234'
dut2_ipv6_list = ['2114::2','2114::3']
dut2_link_local = 'fe80::4567'
dut3_ipv6_list = ['2114::2','2115::2','2111::2','2112::2','2113::2']
dut1_tg_ipv6 = '2300::1'
dut3_tg_ipv6 = '2400::1'
ipv6_mask = '64'

#BFD params
bfd_rx = '300'
bfd_tx = '300'
bfd_echo_tx = '10'


#BGP params
peer_v4 = "peergroup_ipv4"
peer_v6 = "peergroup_ipv6"
peer_v4_vrf = "peergroup_ipv4_vrf"
peer_v6_vrf = "peergroup_ipv6_vrf"
keep_alive = '3'
hold_down = '9'

#dut1
dut1_as = '100'
dut1_router_id = '1.1.1.1'

#dut2
dut2_as = '200'
dut2_router_id = '2.2.2.2'


#dut3
dut3_as = '100'
dut3_router_id = '3.3.3.3'

#TGen params
tg_dut1_ip = '10.10.10.2'
tg_dut3_ip = '20.20.20.2'
tg_dut1_ipv6 = '2300::2'
tg_dut3_ipv6 = '2400::2'
tg_dut1_mac = '00:00:00:11:22:33'
tg_dut3_mac = '00:00:00:11:22:34'
tg_dut1_mac_vrf = '00:00:00:12:23:34'
tg_dut3_mac_vrf = '00:00:00:12:23:35'
traffic_rate = '5000'
tg_dest_nw = "20.20.20.0"
tg_dest_nw_v6 = "2400::"


