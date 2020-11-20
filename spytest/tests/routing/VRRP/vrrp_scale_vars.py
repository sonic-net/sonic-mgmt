from spytest.dicts import SpyTestDict
from vrrp_vars import convert_mac_to_dot
import random

data = SpyTestDict()
data.testing ='VRRP'
vrrp_sessions = 128
vrrp_vlan_count = 32
vrrp_per_vlan = int(vrrp_sessions/vrrp_vlan_count)

vlan_list=[]
for i in range(vrrp_vlan_count):
    item = [(i+1) for iter in range(vrrp_per_vlan)]
    vlan_list = vlan_list + item

for i in range(vlan_list[-1]+1,vlan_list[-1]+9):
    vlan_list = vlan_list+ [i]

vlan_intf_list = ['Vlan{}'.format(vlan_id) for vlan_id in vlan_list]

vrrp_vlans = vlan_list[0:vrrp_sessions]
dut1_uplink_vlans = vlan_list[vrrp_sessions:vrrp_sessions+2]
dut2_uplink_vlans = vlan_list[vrrp_sessions+2:vrrp_sessions+4]

vrrp_vlan_intf = vlan_intf_list[0:vrrp_sessions]
dut1_uplink_vlan_intf = vlan_intf_list[vrrp_sessions:vrrp_sessions+2]
dut2_uplink_vlan_intf = vlan_intf_list[vrrp_sessions+2:vrrp_sessions+4]

dut1_vlans = vrrp_vlans + dut1_uplink_vlans
dut2_vlans = vrrp_vlans + dut2_uplink_vlans
dut3_vlans = vrrp_vlans
dut4_vlans = vlan_list[vrrp_sessions:]

dut1_vlan_intf = vrrp_vlan_intf + dut1_uplink_vlan_intf
dut2_vlan_intf = vrrp_vlan_intf + dut2_uplink_vlan_intf
dut3_vlan_intf = vrrp_vlan_intf
dut4_vlan_intf = vlan_intf_list[vrrp_sessions:]


lag_id_list = [ i+1 for i in range(4)]
lag_intf_list = ['PortChannel{}'.format(lag_id) for lag_id in lag_id_list]


#IP params
mask = '24'
dut1_4_ip_list = ['14.14.{}.1'.format(i) for i in range(1,3)]
dut4_1_ip_list = ['14.14.{}.2'.format(i) for i in range(1,3)]
dut2_4_ip_list = ['24.24.{}.1'.format(i) for i in range(1,3)]
dut4_2_ip_list = ['24.24.{}.2'.format(i) for i in range(1,3)]

#VRRP params
vrid_list = [i+1 for i in range(vrrp_sessions)]
ip_octet_list = [i for i in range(25,25+vrrp_sessions) if i !=127]
if len(ip_octet_list) != vrrp_sessions:
  ip_octet_list.append(ip_octet_list[-1]+1)

vrrp_ip_list = []
vip_list = []
vrrp_sec_ip_list =[]
vrrp_ip_nw = []
for session  in range(vrrp_sessions):
    vrrp_ip_list.append(['{}.{}.{}.{}'.format(ip_octet_list[session],ip_octet_list[session],ip_octet_list[session],i) for i in range(1,4)])
    vip_list.append('{}.{}.{}.{}'.format(ip_octet_list[session],ip_octet_list[session],ip_octet_list[session],str(random.randint(5,150))))
    vrrp_sec_ip_list.append('{}.{}.{}.{}'.format(ip_octet_list[session],ip_octet_list[session],ip_octet_list[session],str(random.randint(151,254))))
    vrrp_ip_nw.append('{}.{}.{}.0'.format(ip_octet_list[session], ip_octet_list[session], ip_octet_list[session]))


vmac_list = ['00:00:5E:00:01:{}'.format(format(vrid,'02X')) for vrid in vrid_list]
vmac_list_1 = [convert_mac_to_dot(vmac) for vmac in vmac_list ]
vrrp_priority_list_dut1 = [120] * int(vrrp_sessions/2) +  [80] * int(vrrp_sessions/2)
vrrp_priority_list_dut2 = [80] * int(vrrp_sessions/2) +  [120] * int(vrrp_sessions/2)

#BGP params
dut1_as = '100'
dut1_router_id = '1.1.1.1'
dut2_as = '200'
dut2_router_id = '2.2.2.2'
dut4_as = '400'
dut4_router_id = '4.4.4.4'
peer_v4_1 = 'peer_v4_1'
peer_v4_2 = 'peer_v4_2'


dut4_route_list  = ["201.100.{}.0".format(i) for i in range(1,vrrp_sessions+1)]
dut4_tg_ip_list = ["201.100.{}.1".format(i) for i in range(1,vrrp_sessions+1)]
tg_src_ip_list = [vrrp_ip_list[session][2] for session in range(vrrp_sessions)]
tg_dest_ip_list = ["201.100.{}.2".format(i) for i in range(1,vrrp_sessions+1)]
tg_dest_mac_list = ["00:00:00:12:22:{}".format(format(i,'02X')) for i in range(1,vrrp_sessions+1)]
tg_src_mac_list = ["00:00:00:11:22:{}".format(format(i,'02X')) for i in range(1,vrrp_sessions+1)]

traffic_rate = 500
tg2_src_mac = "00:00:00:44:44:44"
frame_size_bytes = 128
rate_threshold = 5.0


vrrp_secondary_ip =['no','yes','yes','yes']*32
