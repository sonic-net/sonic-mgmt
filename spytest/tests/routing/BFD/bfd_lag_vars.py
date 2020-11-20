user_vrf_name = 'Vrf-101'
vrf_name = 'default-vrf'

l2_switch = "no"
convergence_test = "yes"
#vlan params
lag_name1 = "PortChannel1"
lag_name2 = "PortChannel2"
lag_name3 = "PortChannel3"
lag_name4 = "PortChannel4"
access_vlan = "100"
access_vlan_name = "Vlan100"
trunk_vlan = ["101","102","103"]
trunk_vlan_name = ["Vlan101","Vlan102","Vlan103"]
dut2_l2_vlan = "200"
dut2_l2_vlan_name = "Vlan200"

#dut_ip params
dut1_lagip_list = ['12.12.1.1','','12.12.3.1','12.12.4.1','12.12.5.1']
dut3_lagip_list = ['12.12.1.2','','12.12.3.2','12.12.4.2','12.12.5.2']
dut1_l3lagip_list = ['13.13.1.1','13.13.3.1','13.13.4.1','13.13.5.1']
dut3_l3lagip_list = ['13.13.1.2','13.13.3.2','13.13.4.2','13.13.5.2']
dut3_ip_to_dut4 = ['34.1.1.1']
dut4_ip_to_dut3 = ['34.1.1.2']
dut1_ip_to_dut4 = ['12.12.1.1']
dut4_ip_to_dut1 = ['34.1.1.2']
dut1_tg_ip = '10.10.10.1'
dut3_tg_ip = '20.20.20.1'
dut4_tg_ip = '40.40.40.1'
ip_mask = '24'
ipv6_mask = '64'
lo_name = 'Loopback1'
lo_mask = '32'
lo_v6mask = '128'
dut1_lo_ip = '11.1.1.1'
dut3_lo_ip = '20.1.1.1'
dut4_lo_ip = '40.1.1.1'
dut1_lo_ipv6 = '2101::1'
dut3_lo_ipv6 = '2201::1'
dut4_lo_ipv6 = '2401::1'

#dut3_ipv6 params
dut1_lagipv6_list = ['2011::1','','2013::1','2014::1','2015::1']
dut3_lagipv6_list = ['2011::2','','2013::2','2014::2','2015::2']
dut1_l3lagipv6_list = ['2111::1','2113::1','2114::1','2115::1']
dut3_l3lagipv6_list = ['2111::2','2113::2','2114::2','2115::2']
dut3_ipv6_to_dut4 = ['2340::1']
dut4_ipv6_to_dut3 = ['2340::2']
dut1_ipv6_to_dut4 = ['2011::1']
dut4_ipv6_to_dut1 = ['2340::2']
dut1_tg_ipv6 = '2100::1'
dut3_tg_ipv6 = '2200::1'
dut4_tg_ipv6 = '2400::1'

#BFD params
bfd_rx = '100'
bfd_tx = '100'
bfd_echo_tx = '100'
multiplier = '3'
bfd_rx1 = '100'
bfd_tx1 = '101'
multiplier1 = '3'
bfd_rx2 = '101'
bfd_tx2 = '100'
multiplier2 = '3'

bfd_rx61 = '100'
bfd_tx61 = '101'
multiplier61 = '3'
bfd_rx62 = '101'
bfd_tx62 = '100'
multiplier62 = '3'

#BGP params
peer_v4 = "peergroup_ipv4"
peer_v6 = "peergroup_ipv6"
keep_alive = '3'
hold_down = '9'
static_wait_time = '10'

#dut1
dut1_as = '100'
dut1_router_id = '1.1.1.1'

#dut3
dut3_as = '300'
dut3_router_id = '2.2.2.2'

#dut4
dut4_as = '400'
dut4_router_id = '4.4.4.4'

#TGen params
tg_dut1_ip = '10.10.10.2'
tg_dut3_ip = '20.20.20.2'
tg_dut4_ip = '40.40.40.2'
tg_dut1_ipv6 = '2100::2'
tg_dut3_ipv6 = '2200::2'
tg_dut4_ipv6 = '2400::2'
tg_dut1_mac = '00:00:00:11:22:33'
tg_dut3_mac = '00:00:00:11:22:34'
tg_dut4_mac = '00:00:00:11:22:45'
traffic_rate = '5000'
tg_dest_nw = "20.20.20.0"
tg_dest_nw_v6 = "2200::"

tg_src_nw = "10.10.10.0"
tg_src_nw_v6 = "2100::"

tg_dest_l3lag_nw = "40.40.40.0"
tg_dest_l3lag_nw_v6 = "2400::"






lag_name1_vrf = "PortChannel5"
lag_name2_vrf = "PortChannel6"
lag_name3_vrf = "PortChannel7"
lag_name4_vrf = "PortChannel8"

access_vlan_vrf = "104"
access_vlan_name_vrf = "Vlan104"
trunk_vlan_vrf = ["105","106","107"]
trunk_vlan_name_vrf = ["Vlan105","Vlan106","Vlan107"]
dut2_l2_vlan_vrf = "201"
dut2_l2_vlan_name_vrf = "Vlan201"

peer_v4_vrf = "peergroup_ipv4_vrf"
peer_v6_vrf = "peergroup_ipv6_vrf"

tg_dut1_mac_vrf = '00:00:00:12:23:33'
tg_dut3_mac_vrf = '00:00:00:12:23:34'
tg_dut4_mac_vrf = '00:00:00:12:23:45'
lo_name_vrf = 'Loopback2'
dut1_lo_ip_vrf = '11.1.1.2'
dut3_lo_ip_vrf = '20.1.1.2'
dut4_lo_ip_vrf = '40.1.1.2'
dut1_lo_ipv6_vrf = '2101::2'
dut3_lo_ipv6_vrf = '2201::2'
dut4_lo_ipv6_vrf = '2401::2'
