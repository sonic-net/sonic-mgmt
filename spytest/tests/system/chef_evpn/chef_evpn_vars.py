from spytest.dicts import SpyTestDict

data = SpyTestDict()
chef_server = SpyTestDict()

chef_server.name = 'chef'
data.role_dir = 'role_files'

data.node_list = ['qt_d1_node','qt_d2_node', 'qt_d3_node', 'qt_d4_node']
data.node_list_mc = ['qt_d1_node_mc', 'qt_d2_node_mc','qt_d3_node_mc']
data.role_list = ['sonic_d1', 'sonic_d2', 'sonic_d3', 'sonic_d4']
data.role_list_mc = ['sonic_d1_mc', 'sonic_d2_mc', 'sonic_d3_mc']
data.role_tc_list = ['tmpl_qt_d1_tc_2.json', 'tmpl_qt_d2_tc_2.json', 'tmpl_qt_d3_tc_2.json', 'tmpl_qt_d4_tc_2.json']
data.role_tc_list_l3 = ['tmpl_qt_d1_tc_l3mclag.json','tmpl_qt_d2_tc_l3mclag.json','tmpl_qt_d3_tc_l3mclag.json']
data.role_tc_list_l2 = ['tmpl_qt_d1_tc_l2mclag.json','tmpl_qt_d2_tc_l2mclag.json','tmpl_qt_d3_tc_l2mclag.json']
data.role_tc_list_mclagdel = ['tmpl_qt_d1_tc_mclag_del.json', 'tmpl_qt_d2_tc_mclag_del.json']
data.role_tc_list_evpn = ['tmpl_qt_d1_evpn.json', 'tmpl_qt_d2_evpn.json', 'tmpl_qt_d3_evpn.json']

data.lbk_ip_list = [['1.1.1.1', '1.1.1.2'], ['2.2.2.1', '2.2.2.2'], ['3.3.3.1', '3.3.3.2'], ['4.4.4.1', '4.4.4.2']]

data.d1_d4_pc_1 = 'PortChannel14'
data.d4_d1_pc_1 = 'PortChannel14'

data.d3_d2_pc_1 = 'PortChannel32'
data.d2_d3_pc_1 = 'PortChannel32'

data.d1_d2_intf_1_ip = '4.4.44.101'
data.d2_d1_intf_1_ip = '4.4.44.102'

data.d1_d2_vlan_1_ip = '4.4.45.101'
data.d2_d1_vlan_1_ip = '4.4.45.102'

data.d1_d4_pc_1_ip = '4.4.46.101'
data.d4_d1_pc_1_ip = '4.4.46.104'

data.d3_d4_intf_1_ip = '4.4.47.103'
data.d4_d3_intf_1_ip = '4.4.47.104'

data.d3_d4_vlan_1_ip = '4.4.48.103'
data.d4_d3_vlan_1_ip = '4.4.48.104'

data.d3_d2_pc_1_ip = '4.4.49.103'
data.d2_d3_pc_1_ip = '4.4.49.102'

data.def_mask_ip = 24

data.d1_d2_intf_1_ip6 = '2002::101'
data.d2_d1_intf_1_ip6 = '2002::102'

data.d3_d4_intf_1_ip6 = '2006::103'
data.d4_d3_intf_1_ip6 = '2006::104'
data.def_mask_ip6 = 64

data.d1_as = 101
data.d2_as = 102
data.d3_as = 103
data.d4_as = 104
