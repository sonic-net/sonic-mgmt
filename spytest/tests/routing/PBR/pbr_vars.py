from spytest.dicts import SpyTestDict

data = SpyTestDict()

data.phy_vrf = 'Vrf-RED'
data.access_vrf = 'Vrf-BLUE'
data.vrf_list = ['default',data.access_vrf,data.phy_vrf]
data.lag_intf = 'PortChannel10'

data.lag_vlan_id = '100'
data.access_vlan_id = '200'
data.d1tg_vlan_id = '300'

data.lag_vlan_intf = 'Vlan100'
data.access_vlan_intf = 'Vlan200'
data.d1tg_vlan_intf = 'Vlan300'

data.mask_v4 = '24'
data.mask_v6 = '64'
data.lag_ip_list = ['12.12.1.1','12.12.1.2']
data.vlan_ip_list = ['12.12.2.1','12.12.2.2']
data.phy_ip_list = ['12.12.1.1','12.12.1.2']
data.d1tg_ip_list = ['11.11.11.1','11.11.11.2']
data.d2tg_ip_list = ['22.22.22.1','22.22.22.2']


data.lag_ipv6_list = ['1211::1','1211::2']
data.vlan_ipv6_list = ['1212::1','1212::2']
data.phy_ipv6_list = ['1211::1','1211::2']
data.d1tg_ipv6_list = ['1111::1','1111::2']
data.d2tg_ipv6_list = ['2222::1','2222::2']

data.dest_ip_nw = '22.22.22.0'
data.dest_ipv6_nw = '2222::'

data.d1_router_id = '1.1.1.1'
data.d2_router_id = '2.2.2.2'
#BGP
data.d1_as = '100'
data.d2_as = '200'

#OSPF
data.ospf_area = 0
data.ospf_process = 10


#scale params
data.max_policy = 128
data.max_classifier = 128
data.max_policy_sections = 64
data.policy_names = ['policy_{}'.format(int(id)+1) for id in range(data.max_policy)]
data.classifier_names = ['class_{}'.format(int(id)+1) for id in range(data.max_classifier)]

#TGEN
data.traffic_rate = 2000


data.src_tcp = 300
data.dst_tcp =500
data.src_udp = 900
data.dst_udp = 1200


#access-list name definitions
data.ip_permit_acl = 'ip_permit_acl'
data.ip_deny_acl = 'ip_deny_acl'
data.ipv6_permit_acl = 'ipv6_permit_acl'
data.ipv6_deny_acl = 'ipv6_deny_acl'
data.acl_l2 = 'mac_l2'

#Classifier definitions
data.class_permit_ip = 'class_permit_ip'
data.class_deny_ip = 'class_deny_ip'
data.class_permit_ipv6 = 'class_permit_ipv6'
data.class_deny_ipv6 = 'class_deny_ipv6'
data.class_l2_acl = 'class_l2_acl'
data.class_l2_fields = 'class_l2_fields'

#Policy definitions
data.policy_class_port = 'policy_class_port'
data.policy_class_vlan = 'policy_class_vlan'
data.policy_class_global = 'policy_class_global'
data.policy_class_deny = 'policy_class_deny_ip_ipv6'
data.policy_l2_acl = 'policy_l2_acl'
data.policy_l2_fields = 'policy_l2_fields'

#Classifier match fields
data.class_fields_tcp_ip = 'class_fields_tcp_ip'
data.class_fields_tcp_ipv6 = 'class_fields_tcp_ipv6'
data.class_fields_udp_ip = 'class_fields_udp_ip'
data.class_fields_udp_ipv6 = 'class_fields_udp_ipv6'

data.policy_class_fields_tcp = 'policy_class_fields_tcp'
data.policy_class_fields_udp = 'policy_class_fields_udp'
