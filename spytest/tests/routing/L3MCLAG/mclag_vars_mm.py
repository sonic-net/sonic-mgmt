###Resource file variables
tgen_rate_pps = '1000'
traffic_run_time = 5
po_reconfig_flag = 0

### L2 Data
tg12_vlan = 12
tg22_vlan = 22
access_vlan = 40
trunk_base_vlan = 50
trunk_vlan_count = 3
strm_mac_count = 2
tg_host_count = 1
trunk_vlan_range = str(trunk_base_vlan) + " " + str(trunk_base_vlan + trunk_vlan_count - 1)
default_macage = 600
mac_age = 30
mclag_sys_mac = '00:AC:AC:AC:AC:AC'
### L3 Data
peer1_ip = '10.10.10.1'
peer2_ip = '10.10.10.2'
peer1_ip6 = '1000:10::10:1'
peer2_ip6 = '1000:10::10:2'
peer_link_ip_1 = '20.20.20.1'
peer_link_ip_2 = '20.20.20.2'
v4_mask = '24'
po3_ip_d1 = '30.30.30.1'
po3_ip_d2 = po3_ip_d1
po3_ip_d3 = '30.30.30.3'
po4_ip_d1 = '40.40.40.1'
po4_ip_d2 = '40.40.40.2'
po4_ip_d4 = '40.40.40.4'
po5_ip_d1 = '50.50.50.1'
po5_ip_d2 = '50.50.50.2'
po5_ip_d4 = '50.50.50.4'
po6_ip_d2 = '33.33.33.2'
po6_ip_d3 = '33.33.33.3'
tg11_ip = ['11.11.11.1','11.11.11.100','11.11.11.0/'+ v4_mask]
tg12_ip = ['12.12.12.1','12.12.12.100','12.12.12.0/'+ v4_mask]
tg21_ip = ['21.21.21.2','21.21.21.100','21.21.21.0/'+ v4_mask]
tg22_ip = ['22.22.22.2','22.22.22.100','22.22.22.0/'+ v4_mask]
tg31_ip = ['31.31.31.3','31.31.31.100','31.31.31.0/'+ v4_mask]
tg32_ip = ['32.32.32.3','32.32.32.100','32.32.32.0/'+ v4_mask]
tg41_ip = [po4_ip_d4,'40.40.40.100','40.40.40.0/'+ v4_mask]
tg42_ip = [po5_ip_d4,'50.50.50.100','50.50.50.0/'+ v4_mask]
v6_mask = '64'
po3_ip6_d1 = '2000:30::30:1'
po3_ip6_d2 = po3_ip6_d1
po3_ip6_d3 = '2000:30::30:3'
po4_ip6_d1 = '2000:40::40:1'
po4_ip6_d2 = '2000:40::40:2'
po4_ip6_d4 = '2000:40::40:4'
po5_ip6_d1 = '2000:50::50:1'
po5_ip6_d2 = '2000:50::50:2'
po5_ip6_d4 = '2000:50::50:4'
po6_ip6_d2 = '2000:33::33:2'
po6_ip6_d3 = '2000:33::33:3'
tg11_ip6 = ['2000:11::11:1','2000:11::11:100','2000:11::/'+ v6_mask]
tg12_ip6 = ['2000:12::12:1','2000:12::12:100','2000:12::/'+ v6_mask]
tg21_ip6 = ['2000:21::21:2','2000:21::21:100','2000:21::/'+ v6_mask]
tg22_ip6 = ['2000:22::22:2','2000:22::22:100','2000:22::/'+ v6_mask]
tg31_ip6 = ['2000:31::31:3','2000:31::31:100','2000:31::/'+ v6_mask]
tg32_ip6 = ['2000:32::32:3','2000:32::32:100','2000:32::/'+ v6_mask]
tg41_ip6 = [po4_ip6_d4,'2000:40::40:100','2000:40::/'+ v6_mask]
tg42_ip6 = [po5_ip6_d4,'2000:50::50:100','2000:50::/'+ v6_mask]

### BGP data
bgp_keepalive = 3
bgp_holdtime = 9
lb_ip_d1 = '110.110.110.1'
lb_ip_d2 = '120.120.120.2'
lb_ip_d3 = '130.130.130.3'
lb_ip_d4 = '140.140.140.4'
as_num = 100
as_num_1 = 100
as_num_2 = 200
as_num_3 = 300
as_num_4 = 400

### OSPF Data
po3_ip_nw = '30.30.30.0/24'
po6_ip_nw = '33.33.33.0/24'
po1_ip_nw = '10.10.10.0/24'

### MCLAG Data
mclag_vlan_peer = 200
mclag_vlan = 100
mclag_domain = 123


### Scale Data
access_vlan_scale = 1
trunk_base_vlan_scale = 2
trunk_vlan_count_scale = 4000
strm_mac_count_scale = 10
mac_scale_count = 40000
### Control vlan
mclag_vlan_scale = 4090
peer1_ip_scale = '49.49.49.1'
peer2_ip_scale = '49.49.49.2'