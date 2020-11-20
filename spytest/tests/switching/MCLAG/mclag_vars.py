###Resource file variables
tgen_rate_pps = '1000'
traffic_run_time = 5
po_reconfig_flag = 0

### L2 Data
access_vlan = 80
trunk_base_vlan = 81
trunk_vlan_count = 3
strm_mac_count = 2

default_macage = 600
mac_age = 30

### L3 Data
peer1_lb_ip = '110.110.110.1'
peer2_lb_ip = '110.110.110.2'
peer1_ip = '10.10.10.1'
peer2_ip = '10.10.10.2'
peer_link_ip_1 = '20.20.20.1'
peer_link_ip_2 = '20.20.20.2'
ip_mask = 24

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