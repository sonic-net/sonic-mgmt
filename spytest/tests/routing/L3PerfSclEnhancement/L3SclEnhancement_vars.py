from spytest.dicts import SpyTestDict

data = SpyTestDict()
data.vlan = '200'
data.vlan1 = 'Vlan200'
data.vlan201 = '201'
data.vlan201_1 = 'Vlan201'
data.vlan202 = '202'
data.vlan202_1 = 'Vlan202'
data.d1d2_1_ip_addr = '12.1.1.1'
data.d2d1_1_ip_addr = '12.1.1.2'
data.d1d2_2_ip_addr = '12.2.1.1'
data.d2d1_2_ip_addr = '12.2.1.2'
data.rtrid1 = '1.1.1.1'
data.rtrid2 = '2.2.2.2'
data.d1t1_ip_addr = '200.1.1.1'
data.d2t1_ip_addr = '200.2.1.1'
data.d1t1_ipv6_addr = '2001:1::1'
data.d2t1_ipv6_addr = '2002:1::1'
data.d1t1_ipv6_addr2 = '2111:1::1'
data.d2t1_ipv6_addr2 = '2222:1::1'
data.t1d1_ipv6_addr = '2001:1::100'
data.t1d2_ipv6_addr = '2002:1::100'
data.t1d1_ipv6_addr2 = '2111:1::100'
data.t1d2_ipv6_addr2 = '2222:1::100'
data.t1d1_ip_addr = '200.1.1.10'
data.t1d2_ip_addr = '200.2.1.10'
data.d1d2_ipv6_addr = '1200::1'
data.d2d1_ipv6_addr = '1200::2'
data.mask = '16'
data.maskv6 = '64'
data.oid_sysName = '1.3.6.1.2.1.1.5.0'
data.ro_community = 'test_community'
data.location = 'hyderabad'
data.oid_dot1qFdbTable = '1.3.6.1.2.1.17.7.1.2.1'
data.mgmt_int = 'eth0'

data.my_dut_list = None
data.local = None
data.remote = None
data.mask = "16"
data.counters_threshold = 10
data.tgen_stats_threshold = 10
data.tgen_rate_pps = '1000'
data.tgen_l3_len = '500'
data.traffic_run_time = 30
data.max_host_1 = 4000
data.max_host_2 = 10000
data.keep_alive = '2'
data.hold_down = '6'

data.ip_list_1 = ['200.1.1.1', '200.1.1.10']
data.ip_list_2 = ['201.%s.0.10'%x for x in range(10,20)]
data.ip_list_3 = ['201.%s.0.1'%x for x in range(10,20)]

data.ipv6_list_2 = ['2001:%s::1'%x for x in range(10,20)]
data.ipv6_list_3 = ['2001:%s::10'%x for x in range(10,20)]

data.num_routes = '63990'
data.prefix1 = '121.1.1.0'
data.prefix2 = '221.1.1.0'
data.prefix3 = '131.1.1.0'
data.prefix4 = '231.1.1.0'
data.prefix_ipv6 = '1121:1::'
data.prefix2_ipv6 = '3121:1::'
data.prefix_list_vrf = ['11.1.1.0','12.1.1.0','13.1.1.0']
data.prefix2_list_vrf = ['22.1.1.0','33.1.1.0','44.1.1.0']
data.prefix_list_ipv6_vrf = ['1111:1::','1222:1::','1333:1::']
data.prefix2_list_ipv6_vrf = ['2111:1::','2222:1::','2333:1::']
data.af_ipv4 = "ipv4"
data.af_ipv6 = "ipv6"
data.shell_sonic = "sonic"
data.shell_vtysh = "vtysh"
data.num_of_routes = 127000
data.num_of_routes2 = 49900
data.num_of_routes_ipv6 = 24990
data.num_of_routes_ipv6_2 = 12490
data.num_of_routes3 = 25000

data.num_of_routes_ipv4_004 = 22990
data.num_of_routes_ipv6_004 = 17990

data.vrf_name = ['Vrf'+'%s'%x for x in range (101,201)]
data.dut1_tg1_vlan = ['%s'%x for x in range (401,404)]
data.dut1_tg1_vlan2 = ['%s'%x for x in range (420,424)]
data.dut2_tg1_vlan = ['%s'%x for x in range (406,409)]
#DUT and TG IPs
data.dut1_dut2_vrf_ip = ['3.0.%s.1'%x for x in range(101,201)]
data.dut2_dut1_vrf_ip = ['3.0.%s.2'%x for x in range(101,201)]
data.dut1_dut2_vrf_ip_subnet = '24'
data.dut2_dut1_vrf_ip_subnet = '24'

data.dut1_dut2_vrf_ipv6 = ['3:%s::1'%x for x in range(101,201)]
data.dut2_dut1_vrf_ipv6 = ['3:%s::2'%x for x in range(101,201)]
data.dut1_dut2_vrf_ipv6_subnet = '64'
data.dut2_dut1_vrf_ipv6_subnet = '64'

data.dut1_tg1_vrf_ip = ['1.0.%s.1'%x for x in range (1,4)]
data.tg1_dut1_vrf_ip = ['1.0.%s.2'%x for x in range (1,4)]
data.dut1_tg1_vrf_ip_subnet = '24'
data.tg1_dut1_vrf_ip_subnet = '24'

data.dut1_tg1_vrf_ipv6 = ['1:%s::1'%x for x in range (1,4)]
data.tg1_dut1_vrf_ipv6 = ['1:%s::2'%x for x in range (1,4)]
data.dut1_tg1_vrf_ipv6_subnet = '64'
data.tg1_dut1_vrf_ipv6_subnet = '64'

data.dut1_tg1_vrf_ipv6_2 = ['22:%s::1'%x for x in range (1,4)]
data.tg1_dut1_vrf_ipv6_2 = ['22:%s::2'%x for x in range (1,4)]

data.dut2_tg1_vrf_ipv6_2 = ['33:%s::1'%x for x in range (1,4)]
data.tg1_dut2_vrf_ipv6_2 = ['33:%s::2'%x for x in range (1,4)]

data.dut2_tg1_vrf_ip = ['6.0.%s.1'%x for x in range (6,9)]
data.tg1_dut2_vrf_ip = ['6.0.%s.2'%x for x in range (6,9)]
data.dut2_tg1_vrf_ip_subnet = '24'
data.tg1_dut2_vrf_ip_subnet = '24'

data.dut2_tg1_vrf_ipv6 = ['6:%s::1'%x for x in range (6,9)]
data.tg1_dut2_vrf_ipv6 = ['6:%s::2'%x for x in range (6,9)]
data.dut2_tg1_vrf_ipv6_subnet = '64'
data.tg1_dut2_vrf_ipv6_subnet = '64'
data.src_mac_list = ['00:0a:01:00:00:01','00:0b:01:00:00:01','00:0c:01:00:00:01']
data.src_mac_list2 = ['00:0d:01:00:00:01','00:0e:01:00:00:01','00:0f:01:00:00:01']
data.retry_count = 8
data.delay = 15
#BGP dut1 parameters
data.dut1_as = ['%s'%x for x in range (101,201)]
data.dut1_router_id = '1.1.1.1'
data.dut1_keepalive = '60'
data.dut1_holddown = '180'
data.dut1_ip_peergroup = 'ip_peergroup'
data.dut1_ipv6_peergroup = 'ipv6_peergroup'

#BGP dut2 parameters
data.dut1_as = ['%s'%x for x in range (101,201)]
data.dut2_as = ['%s'%x for x in range (101,201)]
data.dut2_router_id = '2.2.2.2'
data.dut2_keepalive = '60'
data.dut2_holddown = '180'
data.dut2_ip_peergroup = 'ip_peergroup'
data.dut2_ipv6_peergroup = 'ipv6_peergroup'

#BGP TG parameters
data.dut1_tg_as = ['300','301','302']
data.dut2_tg_as = ['400','401','402']

#DUT1 traffic parameters
data.dut1_hosts = '100'
data.tg_dut1_rate_pps = '2000'
data.tg_dut1_p1_v4_routes = '500'
data.tg_dut1_p1_v4_prefix = '10.0.0.1'
data.tg_dut1_p1_v6_routes = '500'
data.tg_dut1_p1_v6_prefix = '10::1'

#DUT2 traffic parameters
data.dut2_hosts = '100'
data.tg_dut2_rate_pps = '2000'
data.tg_dut2_p1_v4_routes = '500'
data.tg_dut2_p1_v4_route_prefix = '11.0.0.1'
data.tg_dut2_p1_v6_routes = '500'
data.tg_dut2_p1_v6_route_prefix = '11::1'

data.gw_ipv6 = '2001:1::1'
data.src_ipv6 = '2001:1::2'

data.dut1_dut2_vlan = ['%s'%x for x in range (100,110)]
data.dut2_dut1_vlan = ['%s'%x for x in range (100,110)]

data.max_vrf = 941
data.max_vlans = 941
data.vrf_name2 = ['Vrf'+'%s'%x for x in range (1,941)]
data.wait_time =  350 #400 #130 for 400 intf , 350 for full scl
data.wait_time2 = 2220 #2300 # 2220 for 1000 intf
data.dut1_vlan_scl = ['%s'%x for x in range (1,941)]
'''
##Overwriting variable - remove later ###
data.max_vrf = 100
data.max_vlans = 100
data.vrf_name2 = ['Vrf'+'%s'%x for x in range (1,100)]
data.wait_time =  100 #400 #130 for 400 intf , 350 for full scl
data.wait_time2 = 400 #2300 # 2220 for 1000 intf
data.dut1_vlan_scl = ['%s'%x for x in range (1,100)]
'''
data.dut1_vlan_scl_ip = '8.0.0.1'
data.dut2_vlan_scl_ip = '8.0.0.2'
data.dut1_vlan_scl_ipv6 = '8000:1::'
data.tg1_vlan_scl_ip = '8.0.0.100'

data.dut1_vlan_ecmp = ['%s'%x for x in range (101,230)]

data.src_ip = ['8.%s.1.100'%x for x in range (0,5)]
data.dst_ip = ['8.%s.1.1'%x for x in range (0,5)]

data.dut1_ecmp_ip = ['9.1.%s.1'%x for x in range (1,129)]
data.dut2_ecmp_ip = ['9.1.%s.2'%x for x in range (1,129)]
data.dut1_ecmp_ipv6 = ['9000:%s::1'%x for x in range (1,129)]
data.dut2_ecmp_ipv6 = ['9000:%s::2'%x for x in range (1,129)]

data.max_ecmp_static = 10
data.ipv4_scale_static = 10
data.ipv6_scale_static = 10
data.num_of_vrfs = 1

data.max_ecmp = 64
data.max_ecmp_bgp = 64
data.ipv4_scale_ecmp = 256
data.ipv6_scale_ecmp = 256
data.random_number = 6

TH2 = SpyTestDict()
TH2.ipv4_scale = 196000
TH2.ipv6_scale = 32000
TH2.ipv6_scale_abv_64 = 25000
TH2.ipv4_scale_ipv4ipv6 =  80000
TH2.ipv6_scale_ipv4ipv6 =  12000
TH2.wait_time = 140
TH2.delay_time = 10
TH2.retry_time = 11
TH2.perf_time = 5
TH2.max_arp_count = 32000
TH2.max_nd_count = 16000

TH = SpyTestDict()
TH.ipv4_scale = 65000
TH.ipv6_scale = 24000
TH.ipv6_scale_abv_64 = 14000
TH.ipv4_scale_ipv4ipv6 =  24000
TH.ipv6_scale_ipv4ipv6 =  10000
TH.wait_time = 100
TH.delay_time = 10
TH.retry_time = 6
TH.perf_time = 6
TH.max_arp_count = 32000
TH.max_nd_count = 16000

TD3 = SpyTestDict()
#TD3.ipv4_scale = 81000
TD3.ipv4_scale = 128000
#TD3.ipv6_scale = 25600
TD3.ipv6_scale = 64000
TD3.ipv6_scale_abv_64 = 25000
TD3.ipv4_scale_ipv4ipv6 =  24000
TD3.ipv6_scale_ipv4ipv6 =  10000
TD3.wait_time = 120
TD3.delay_time = 7
TD3.retry_time = 8
TD3.perf_time = 3
TD3.max_arp_count = 32000
TD3.max_nd_count = 16000

##### TD2 to be verified #########
TD2 = SpyTestDict()
TD2.ipv4_scale = 65000
TD2.ipv6_scale = 24000
TD2.ipv6_scale_abv_64 = 14000
TD2.ipv4_scale_ipv4ipv6 =  24000
TD2.ipv6_scale_ipv4ipv6 =  10000
TD2.wait_time = 100
TD2.delay_time = 10
TD2.retry_time = 6
TD2.perf_time = 6
TD2.max_arp_count = 32000
TD2.max_nd_count = 16000

############ default ##############
ipv4_scale = 65000
ipv6_scale = 24000
ipv6_scale_abv_64 = 14000
ipv4_scale_ipv4ipv6 =  24000
ipv6_scale_ipv4ipv6 =  10000
wait_time = 100
delay_time = 10
retry_time = 6
perf_time = 6
max_arp_count = 32000
max_nd_count = 16000

