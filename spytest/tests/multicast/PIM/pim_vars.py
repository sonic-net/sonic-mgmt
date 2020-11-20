from spytest.dicts import SpyTestDict

def convert_mac_to_dot(mac):
    mac = mac.replace(":","")
    return (mac[0:4] + '.' + mac[4:8] + '.' + mac[8:12]).lower()

data = SpyTestDict()
vrf_name = 'Vrf_RED'
vrf_list = ['default',vrf_name]
igp = 'bgp'

#Interface/Vlan params
data.d1d3_lag_intf =  'PortChannel13'
data.d3d2_lag_intf_1 =  'PortChannel231'
data.d3d2_lag_intf_2 =  'PortChannel232'
data.lag_intf_list = [data.d1d3_lag_intf,data.d3d2_lag_intf_1,data.d3d2_lag_intf_2]

#Default-vrf Vlan params\
data.d1d2_vlan_id = [100]
data.d1d3_vlan_id = [101,102]
data.d1d2_vlan_intf = ['Vlan{}'.format(id) for id in data.d1d2_vlan_id]
data.d1d3_vlan_intf = ['Vlan{}'.format(id) for id in data.d1d3_vlan_id]
data.d1_vlan_id = data.d1d2_vlan_id + data.d1d3_vlan_id
data.d1_vlan_intf = data.d1d2_vlan_intf + data.d1d3_vlan_intf

data.d2d1_vlan_id = [100]
data.d2d4_vlan_id = [200]
data.d2d1_vlan_intf = ['Vlan{}'.format(id) for id in data.d2d1_vlan_id]
data.d2d4_vlan_intf = ['Vlan{}'.format(id) for id in data.d2d4_vlan_id]
data.d2_vlan_id = data.d2d1_vlan_id + data.d2d4_vlan_id
data.d2_vlan_intf = ['Vlan{}'.format(id) for id in data.d2_vlan_id]


data.d3d1_vlan_id = data.d1d3_vlan_id
data.d3d4_vlan_id = [300]
data.d3tg_vlan_id = [301]
data.d3d1_vlan_intf = ['Vlan{}'.format(id) for id in data.d3d1_vlan_id]
data.d3d4_vlan_intf = ['Vlan{}'.format(id) for id in data.d3d4_vlan_id]
data.d3tg_vlan_intf = ['Vlan{}'.format(id) for id in data.d3tg_vlan_id]
data.d3_vlan_id = data.d3d1_vlan_id + data.d3d4_vlan_id + data.d3tg_vlan_id
data.d3_vlan_intf = ['Vlan{}'.format(id) for id in data.d3_vlan_id]

data.d4d3_vlan_id = data.d3d4_vlan_id
data.d4d2_vlan_id = data.d2d4_vlan_id
data.d4d3_vlan_intf = ['Vlan{}'.format(id) for id in data.d4d3_vlan_id]
data.d4d2_vlan_intf = ['Vlan{}'.format(id) for id in data.d4d2_vlan_id]
data.d4_vlan_id = data.d4d2_vlan_id + data.d4d3_vlan_id
data.d4_vlan_intf = ['Vlan{}'.format(id) for id in data.d4_vlan_id]

# User-vrf Vlan params
data.d1d2_vlan_id_vrf = [1100]
data.d1d3_vlan_id_vrf = [1101,1102]
data.d1d2_vlan_intf_vrf = ['Vlan{}'.format(id) for id in data.d1d2_vlan_id_vrf]
data.d1d3_vlan_intf_vrf = ['Vlan{}'.format(id) for id in data.d1d3_vlan_id_vrf]
data.d1_vlan_id_vrf = data.d1d2_vlan_id_vrf + data.d1d3_vlan_id_vrf
data.d1_vlan_intf_vrf = data.d1d2_vlan_intf_vrf + data.d1d3_vlan_intf_vrf

data.d2d1_vlan_id_vrf = [1100]
data.d2d4_vlan_id_vrf = [1200]
data.d2d1_vlan_intf_vrf = ['Vlan{}'.format(id) for id in data.d2d1_vlan_id_vrf]
data.d2d4_vlan_intf_vrf = ['Vlan{}'.format(id) for id in data.d2d4_vlan_id_vrf]
data.d2_vlan_id_vrf = data.d2d1_vlan_id_vrf + data.d2d4_vlan_id_vrf
data.d2_vlan_intf_vrf = ['Vlan{}'.format(id) for id in data.d2_vlan_id_vrf]


data.d3d1_vlan_id_vrf = data.d1d3_vlan_id_vrf
data.d3d4_vlan_id_vrf = [1300]
data.d3tg_vlan_id_vrf = [1301]
data.d3d1_vlan_intf_vrf = ['Vlan{}'.format(id) for id in data.d3d1_vlan_id_vrf]
data.d3d4_vlan_intf_vrf = ['Vlan{}'.format(id) for id in data.d3d4_vlan_id_vrf]
data.d3tg_vlan_intf_vrf = ['Vlan{}'.format(id) for id in data.d3tg_vlan_id_vrf]
data.d3_vlan_id_vrf = data.d3d1_vlan_id_vrf + data.d3d4_vlan_id_vrf + data.d3tg_vlan_id_vrf
data.d3_vlan_intf_vrf = ['Vlan{}'.format(id) for id in data.d3_vlan_id_vrf]

data.d4d3_vlan_id_vrf = data.d3d4_vlan_id_vrf
data.d4d2_vlan_id_vrf = data.d2d4_vlan_id_vrf
data.d4d2_vlan_intf_vrf = ['Vlan{}'.format(id) for id in data.d4d2_vlan_id_vrf]
data.d4d3_vlan_intf_vrf = ['Vlan{}'.format(id) for id in data.d4d3_vlan_id_vrf]
data.d4_vlan_id_vrf = data.d4d2_vlan_id_vrf + data.d4d3_vlan_id_vrf
data.d4_vlan_intf_vrf = ['Vlan{}'.format(id) for id in data.d4_vlan_id_vrf]

data.loopback = 'Loopback1'
data.d1_loopback_ip = '101.101.101.101'
data.d3_loopback_ip = '103.103.103.103'

data.loopback_vrf = 'Loopback2'
data.d1_loopback_ip = '101.101.101.101'
data.d3_loopback_ip = '103.103.103.103'

#IP params
data.mask='24'
data.d1d2_ip = '12.12.1.1'
data.d2d1_ip = '12.12.1.2'
data.d1d3_ip = ['13.13.1.1','13.13.2.1']
data.d3d1_ip = ['13.13.1.2','13.13.2.2']
data.d1d4_ip = '14.14.1.1'
data.d4d1_ip = '14.14.1.2'
data.d2d3_ip = '23.23.1.1'
data.d3d2_ip = '23.23.1.2'
data.d2d4_ip = '24.24.1.1'
data.d4d2_ip = '24.24.1.2'
data.d3d4_ip = '34.34.1.1'
data.d4d3_ip = '34.34.1.2'



#OSPF params
data.ospf_area = 0

#BGP params
data.d1_as = '100'
data.d2_as = '200'
data.d3_as = '300'
data.d4_as = '400'
data.d1_routerid = '1.1.1.1'
data.d2_routerid = '2.2.2.2'
data.d3_routerid = '3.3.3.3'
data.d4_routerid = '4.4.4.4'

data.d1_nbrs = data.d3d1_ip + [data.d2d1_ip,data.d4d1_ip]
data.d2_nbrs = [data.d1d2_ip,data.d3d2_ip,data.d4d2_ip]
data.d3_nbrs = data.d1d3_ip + [data.d2d3_ip]
data.d4_nbrs = [data.d1d4_ip,data.d2d4_ip]

#IGMP params

data.ssm_group_list = ['232.1.1.{}'.format(id+1) for id in range(2)]
data.asm_group_list = ['225.1.1.{}'.format(id+1) for id in range(1)]
data.igmp_group_list = data.ssm_group_list + data.asm_group_list
data.ssm_groups = len(data.ssm_group_list)
data.asm_groups = len(data.asm_group_list)
data.igmp_groups = len(data.igmp_group_list)
data.mcast_source_nw = ['90.0.0.0','91.0.0.0']



#TGEN params
data.d1tg_ip = '90.0.0.1'
data.d2tg_ip = '91.0.0.1'
data.d3tg_ip = '33.33.33.1'
data.d3tg_ip_2 = '33.33.33.10'
data.d4tg_ip = '44.44.44.1'

data.tgd1_ip = '90.0.0.2'
data.tgd2_ip = '91.0.0.2'
data.tgd3_ip_1 = '33.33.33.2'
data.tgd3_ip_2 = '33.33.33.3'
data.tgd4_ip = '44.44.44.2'
data.mcast_sources = [data.tgd1_ip,data.tgd2_ip]

data.tg_mcast_mac = {}
for group in data.igmp_group_list:
    last_octet = int(group.split('.')[-1])
    data.tg_mcast_mac[group] = '01:00:5E:01:01:{}'.format(format(last_octet,'02X'))

data.src_incr_ip ='1.0.0.0'
data.src_incr = '1'
data.traffic_rate = 1000
data.igmp_config = {}
data.groups = {}
data.sources = {}
data.stream_handles = {}
data.stream_details = {}
data.stream_list = []
data.igmp_group_all_handles = {}


#Scale params
data.d1d3_vlan_id_scale = data.d1d3_vlan_id + list(range(103,123))
data.d1d3_vlan_intf_scale = ['Vlan{}'.format(id) for id in data.d1d3_vlan_id_scale]
data.d1d3_ip_scale = data.d1d3_ip + ['13.13.{}.1'.format(i) for i in range(3,23)]
data.d3d1_ip_scale = data.d3d1_ip + ['13.13.{}.2'.format(i) for i in range(3,23)]
data.d2d3_ip_scale = ['13.13.{}.3'.format(i) for i in range(3,23)]
data.d4d3_ip_scale = ['13.13.{}.4'.format(i) for i in range(3,23)]
data.scale_traffic_rate = 10000

data.dynamic_scale_count = 8188
data.static_igmp = 2
data.static_mroute = 2
data.max_pim_nbrs = 64
data.max_mroutes= data.dynamic_scale_count + data.static_igmp + data.static_mroute
data.max_igmp = data.dynamic_scale_count + data.static_mroute
data.mroute_count_per_vrf = data.max_mroutes/2
data.static_mroute_vrf = 1
# Non default params
data.hello_interval = 20
data.hello_interval_vrf = 15
data.hold_time = 30
data.hold_time_vrf = 25
data.join_prune_int = 90

