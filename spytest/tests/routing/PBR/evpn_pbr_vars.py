from spytest.dicts import SpyTestDict

data = SpyTestDict()
#IP params
data.mask31 = '31'
data.mask32 = '32'

data.mask_1 = '20'
data.mask_v6 = '64'
data.mask_24 = '24'


data.loopback1 = 'Loopback1'
data.loopback2 = 'Loopback2'

data.dut1_loopback_ip = ['1.1.1.1','1.1.1.5']
data.dut2_loopback_ip = ['2.2.2.1','2.2.2.5']
data.dut3_loopback_ip = ['3.3.3.1','3.3.3.5']
data.dut4_loopback_ip = ['4.4.4.1','4.4.4.5']
data.dut5_loopback_ip = ['5.5.5.1','5.5.5.5']
data.dut6_loopback_ip = ['6.6.6.1','6.6.6.5']

data.loopback1_ip_list = ['1.1.1.1','2.2.2.1','3.3.3.1','4.4.4.1','5.5.5.1','6.6.6.1']
data.loopback2_ip_list = ['1.1.1.5','2.2.2.5','3.3.3.5','4.4.4.5','5.5.5.5','6.6.6.5']

## Added for IPv6 address
#data.dut1_2_ipv6_list = ['2001::1:1', '2002::2:1', '2003::3:1']
#data.dut2_1_ipv6_list = ['2001::1:2', '2002::2:2', '2003::3:2']
#data.dut1_3_ipv6_list = ['3001::1:1', '3002::2:1', '3003::3:1']
#data.dut3_1_ipv6_list = ['3001::1:2', '3002::2:2', '3003::3:2']
#data.dut2_4_ipv6_list = ['2092::1', '2020::1', '2030::1']

data.link_local_po_s1leaf = []
data.link_local_po_s2leaf = []
data.link_local_po_l1s1 = []
data.link_local_po_l2s2 = []
data.link_local_po_l3spine = []
data.link_local_po_l4spine = []


data.dut1_AS ='100'
data.dut2_AS ='200'
data.dut3_AS ='300'
data.dut4_AS ='400'
data.dut5_AS ='500'
data.dut6_AS ='600'
data.keep_alive = 3
data.hold_down = 9
data.vrf1 ='Vrf-Red'
data.vlan_vrf1 = 'Vlan500'
data.vni_vlan = ['500']
data.mclag_client_vlans = ['100','101']
data.vrf1_ip = ['22.11.1.1','22.12.1.1','22.13.1.1','22.14.1.1']
data.vrf1_ip6 = ['1211::1','1212::1','1213::1','1214::1']
data.vrf_blue ='Vrf-Blue'

data.vtep_names = ["vtepLeaf1","vtepLeaf2","vtepLeaf3","vtepLeaf4"]
data.nvo_names = ["nvoLeaf1","nvoLeaf2","nvoLeaf3","nvoLeaf4"]
data.mlag_domain_id = '1'
data.client_lag = 'PortChannel20'
data.po_leaf2 = 'PortChannel27'
data.client_lag_l3 = 'PortChannel13'
data.iccp_lag = 'PortChannel10'

data.po_s1l1 = 'PortChannel11'
data.po_s1l2 = 'PortChannel12'
data.po_s1l3 = 'PortChannel13'
data.po_s1l4 = 'PortChannel14'

data.po_s2l1 = 'PortChannel21'
data.po_s2l2 = 'PortChannel22'
data.po_s2l3 = 'PortChannel23'
data.po_s2l4 = 'PortChannel24'

data.inter_vni = False
data.src_intf_same_vni = 'Loopback3'
data.src_intf_diff_vni = 'Loopback4'

data.route_list =  ['10.1.1.0','40.1.1.0','0.0.0.0/0']
data.route_list_6 = ['1001::0', '4001::0','4003::0',"0::0/0"]

# Tgen parameters
data.l2_vlan_count = 2
data.l2_mac_count = 2

data.client_mac = ["00.01.07.00.00.01","00.01.07.01.00.01","00.01.07.02.00.01","00.01.07.03.00.01"]
data.leaf5_mac = ["00.01.05.00.00.01"]
data.leaf6_mac = ["00.01.06.00.00.01"]
data.sag_mac = "00:00:00:04:01:03"

data.leaf1_dict = {"tenant_mac_v6"  :    "00.01.01.00.00.02",
         "tenant_mac_v4"  :    "00.01.01.00.00.01",
         "tenant_v4_ip"  :    ["10.1.1.10","192.168.20.20","192.168.10.10","50.1.1.10"],
         "tenant_v6_ip"  :    "1001::10",
         "tenant_vlan_list"  : ["110", "111", "112","113"],
         "tenant_vlan_int": ["Vlan110", "Vlan111", "Vlan112","Vlan113"],
         "tenant_ip_list"  :    ["10.1.1.1", "10.1.2.1", "10.1.3.1","50.1.1.1"],
         "tenant_ipv6_list"  :    ["1001::1", "1002::1", "1003::1","5001::1","5001::10"]}

data.leaf2_dict = {"tenant_mac_v6"  :    "00.02.01.00.00.02",
         "tenant_mac_v4"  :    "00.02.01.00.00.01",
         "tenant_v4_ip"  :    ["20.1.1.10","20.1.2.10","20.1.3.10"],
         "tenant_v6_ip"  :    ["2001::10","2002::10","2003::10"],
         "tenant_vlan_list"  : ["210", "211", "212"],
         "tenant_vlan_int": ["Vlan210", "Vlan211", "Vlan212"],
         "tenant_ip_list"  :    ["20.1.1.1", "20.1.2.1", "20.1.3.1"],
         "tenant_ipv6_list"  :    ["2001::1", "2002::1", "2003::1"]}

data.leaf3_dict = {"tenant_mac_v6"  :    "00.03.01.00.00.02",
         "tenant_mac_v4"  :    "00.03.01.00.00.01",
         "tenant_v4_ip"  :    "30.1.1.10",
         "tenant_v6_ip"  :    "3001::10",
         "tenant_vlan_list"  : ["310", "311", "312"],
         "tenant_vlan_int": ["Vlan310", "Vlan311", "Vlan312"],
         "tenant_ip_list"  :    ["30.1.1.1", "30.1.2.1", "30.1.3.1"],
         "tenant_ipv6_list"  :    ["3001::1", "3002::1", "3003::1"]}

data.leaf4_dict = {"tenant_mac_v6"  :    "00.04.01.00.00.02",
         "tenant_mac_v4"  :    "00.04.01.00.00.01",
         "tenant_v4_ip"  :    "40.1.1.10",
         "tenant_v6_ip"  :    ["4001::10","4003::10"],
         "tenant_vlan_list"  : ["410", "411", "412"],
         "tenant_vlan_int": ["Vlan410", "Vlan411", "Vlan412"],
         "tenant_ip_list"  :    ["40.1.1.1", "40.1.2.1", "40.1.3.1"],
         "tenant_ipv6_list"  :    ["4001::1", "4002::1", "4003::1"]}

data.client_dict = {"tenant_mac_v6"  :    "00.07.01.00.00.01",
         "tenant_v4_ip"  :    "20.1.1.200",
         "tenant_v6_ip"  :    "2001::20",
         "tenant_vlan_list"  : ["210", "211", "212"],
         "tenant_vlan_int": ["Vlan210", "Vlan211", "Vlan212"],
         "tenant_ip_list"  :    ["20.1.1.10", "20.1.2.10", "20.1.3.10"],
         "tenant_ipv6_list"  :    ["2001::10", "2002::10", "2003::10"]}

# System MAC and System GW testcase parameters

data.mclag_gw_mac = "00:11:22:33:88:99"
data.mclag_sys_mac = "00:11:33:33:44:66"
data.tg_dest_mac_list = ["00:00:00:12:22:0a","00:00:02:01:11:0b","00:00:02:01:11:0c","00:00:03:01:33:0d"]


#access-list name definitions -on Leaf1
data.leaf1_leaf2_udp443tcp_acl = 'aclv4_leaf1_leaf2_udp443tcp'
data.leaf1_leaf2_udp443tcp_aclv6 = 'aclv6_leaf1_leaf2_udp443tcp'
data.leaf1_leaf4 = 'aclv4_leaf1_leaf4'
data.leaf1_leaf3_ipprefix20 = 'aclv4_leaf1_leaf3'
data.leafvniacl = 'leaf2vni_aclv4'
data.leafvniaclv6 = 'leafvni_aclv6'

#access-list name definitions -on Leaf2
data.leaf2_leaf3_ipany_acl = 'aclv4_any_leaf2_leaf3'
data.leaf2_leaf3_ipv6_nat_acl = 'aclv6_nat_leaf2_leaf3'
data.leaf2_leaf4_ipv6any_acl = 'aclv6_any_leaf2_leaf4'

#access-list name definitions -on Leaf3
data.leaf3_ip_acl = "leaf3_ip_acl"
data.leaf3_ipv6_acl = "leaf3_ipv6_acl"

#access-list name definitions -on Leaf4
data.leaf4_ip_acl = "leaf4_ip_acl"
data.leaf4_ipv6_acl = "leaf4_ipv6_acl"


#Classifier definitions-on Leaf1
data.class_leaf12_udp443tcp_acl = 'class_leaf12_udp443tcp_acl'
data.class_leaf12_udp443tcp_aclv6 = 'class_leaf12_udp443tcp_aclv6'
data.class_leaf14 = 'class_leaf14'
data.class_leaf13_ipprefix20 = 'class_leaf13_ipprefix20'
data.class_leafvniacl = 'class_leaf2vni_acl'
data.class_leafvniaclv6 = 'class_leafvni_aclv6'


#Classifier definitions-on Leaf2
data.class_leaf23_ipany_acl = 'class_leaf23_ipany'
data.class_leaf23_ipv6_nat = 'class_leaf23_ipv6'
data.class_leaf24_ipv6any_acl = 'class_leaf24_ipv6any'

#Classifier definitions-on Leaf3
data.class_leaf3_ip = 'class_permit_ip_leaf3'
data.class_leaf3_ipv6 = 'class_permit_ipv6_leaf3'

#Classifier definitions-on Leaf4
data.class_leaf4_ip = 'class_permit_ip_leaf4'
data.class_leaf4_ipv6 = 'class_permit_ipv6_leaf4'

#Policy definitions -on Leaf1-4
data.policy_class_leaf1 = 'policy_class_leaf1'
data.policy_class_leaf2 = 'policy_class_leaf2'
data.policy_class_leaf3 = 'policy_class_leaf3'
data.policy_class_leaf4 = 'policy_class_leaf4'
data.policy_class_leaf2vni = 'policy_class_leaf2vni'


#Classifier match fields
data.class_fields_tcp_ip_leaf2 = 'class_fields_tcp_ip_leaf2'
data.class_fields_tcp_ipv6_leaf2 = 'class_fields_tcp_ipv6_leaf2'
data.class_fields_udp_ip_leaf2 = 'class_fields_udp_ip_leaf2'
data.class_fields_udp_ipv6_leaf2 = 'class_fields_udp_ipv6_leaf2'

data.policy_class_fields_tcp = 'policy_class_fields_tcp'
data.policy_class_fields_udp = 'policy_class_fields_udp'

data.mask_v4 = '24'
data.mask_v6 = '64'

data.dut3_acl_ip_list = ['192.168.20.0/24','192.168.10.0/24','4003::0/64']
