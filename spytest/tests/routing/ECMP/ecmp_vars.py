from spytest.dicts import SpyTestDict

data = SpyTestDict()

###Resource file variables
mask4='24'
mask4_2='16'
mask6='64'
ipv4var='ipv4'
ipv6var='ipv6'
addvar='add'
delvar='del'
removevar='remove'
yesvar='yes'
novar='no'
notvar='Not'
disablevar='disabled'
disablevar2='disable'
enablevar='enable'
downvar='down'
upvar='up'
waitvar=5
rest_waitvar=1
stalevar='STALE'
ecmpv4=['ipv4-src-ip', 'ipv4-dst-ip', 'ipv4-ip-proto', 'ipv4-l4-src-port', 'ipv4-l4-dst-port']
ecmpv6=['ipv6-src-ip', 'ipv6-dst-ip', 'ipv6-next-hdr', 'ipv6-l4-src-port', 'ipv6-l4-dst-port']

gen_tech_support_flag=True
get_more_debugs_flag=True

data.seed_def = '10'
data.seed_range = ['1', '16777215']
data.seed_val = ['26', '42']
data.src_port = '22222'
data.dst_port = '33333'
data.st_ip_1=['91.0.0.0', '91.0.0.0'+'/'+mask4_2, '91.0.0.1']
data.st_ip_2=['92.0.0.0', '92.0.0.0'+'/'+mask4_2, '92.0.0.1']
data.st_ip6_1=['2091:1::', '2091:1::'+'/'+mask6, '2091:1::1']
data.st_ip6_2=['2092:1::', '2092:1::'+'/'+mask6, '2092:1::1']
data.tg_macs=['00:00:ba:ba:41:01', '00:00:ba:ba:42:01', '00:00:ba:ba:51:01', '00:00:ba:ba:52:01']
data.dut1_mac=''
data.dut2_mac=''
data.acl_names=['hash_in', 'hash_out']
data.acl_names6=['hash_in6', 'hash_out6']

data.tg_rate = '1000'
data.tg_count = '80'
data.tg_step = '0.0.0.1'
data.tg_step6 = '::1'
data.tg_framesize = '800'
data.tg_ipttl = '255'
data.convergence_acceptable = '10'

data.ip_1=['11.1.1.1', '11.1.1.10']
data.ip_1_nw=['11.1.1.0', '11.1.1.0'+'/'+mask4]
data.ip_2=['22.1.1.1', '22.1.1.10']
data.ip_2_nw=['22.1.1.0', '22.1.1.0'+'/'+mask4]
data.ip_3=['33.1.1.1', '33.1.1.10']
data.ip_3_nw=['33.1.1.0', '33.1.1.0'+'/'+mask4]
data.ip_4=['44.1.1.1', '44.1.1.10']
data.ip_4_nw=['44.1.1.0', '44.1.1.0'+'/'+mask4]
data.ip_12_1=['12.1.1.1', '12.1.1.2']
data.ip_12_2=['12.1.2.1', '12.1.2.2']
data.ip_13=['13.10.1.1', '13.10.1.3']
data.ip_13_2=['13.30.1.1', '13.30.1.3']
data.ip_14=['14.20.1.1', '14.20.1.4']
data.ip_14_2=['14.40.1.1', '14.40.1.4']
data.ip6_1=['2011:1::1:1', '2011:1::1:10']
data.ip6_1_nw=['2011:1::', '2011:1::'+'/'+mask6]
data.ip6_2=['2022:1::1:1', '2022:1::1:10']
data.ip6_2_nw=['2022:1::', '2022:1::'+'/'+mask6]
data.ip6_3=['2033:1::1:1', '2033:1::1:10']
data.ip6_3_nw=['2033:1::', '2033:1::'+'/'+mask6]
data.ip6_4=['2044:1::1:1', '2044:1::1:10']
data.ip6_4_nw=['2044:1::', '2044:1::'+'/'+mask6]
data.ip6_12_1=['2012:1::1:1', '2012:1::1:2']
data.ip6_12_2=['2012:2::1:1', '2012:2::1:2']
data.ip6_13=['2013:10::1:1', '2013:10::1:3']
data.ip6_13_2=['2013:30::1:1', '2013:30::1:3']
data.ip6_14=['2014:20::1:1', '2014:20::1:4']
data.ip6_14_2=['2014:40::1:1', '2014:40::1:4']

data.ip_1_2=['11.2.1.1', '11.2.1.10']
data.ip_1_2_nw=['11.2.1.0', '11.2.1.0'+'/'+mask4]
data.ip_2_2=['22.2.1.1', '22.2.1.10']
data.ip_2_2_nw=['22.2.1.0', '22.2.1.0'+'/'+mask4]
data.ip_3_2=['33.2.1.1', '33.2.1.10']
data.ip_3_2_nw=['33.2.1.0', '33.2.1.0'+'/'+mask4]
data.ip_4_2=['44.2.1.1', '44.2.1.10']
data.ip_4_2_nw=['44.2.1.0', '44.2.1.0'+'/'+mask4]
data.ip6_1_2=['2011:2::1:1', '2011:2::1:10']
data.ip6_1_2_nw=['2011:2::', '2011:2::'+'/'+mask6]
data.ip6_2_2=['2022:2::1:1', '2022:2::1:10']
data.ip6_2_2_nw=['2022:2::', '2022:2::'+'/'+mask6]
data.ip6_3_2=['2033:2::1:1', '2033:2::1:10']
data.ip6_3_2_nw=['2033:2::', '2033:2::'+'/'+mask6]
data.ip6_4_2=['2044:2::1:1', '2044:2::1:10']
data.ip6_4_2_nw=['2044:2::', '2044:2::'+'/'+mask6]

data.bgp_localas='100'
data.bgp_remoteas='200'
data.bgp_keepalive='3'
data.bgp_holdtime='9'

#Vxlan script variables.
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

data.loopback1_ip_list = ['1.1.1.1','2.2.2.1','3.3.3.1','4.4.4.1','5.5.5.1']
data.loopback2_ip_list = ['1.1.1.5','2.2.2.5','3.3.3.5','4.4.4.5','5.5.5.5']

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
data.keep_alive = 3
data.hold_down = 9
data.vrf1 ='Vrf-Red'
data.vlan_vrf1 = 'Vlan500'
data.vni_vlan = ['500']
data.vrf1_ip = ['22.11.1.1','22.12.1.1','22.13.1.1']
data.vrf1_ip6 = ['1211::1','1212::1','1213::1']
data.vtep_names = ["vtepLeaf1","vtepLeaf2","vtepLeaf3"]
data.nvo_names = ["nvoLeaf1","nvoLeaf2","nvoLeaf3"]

data.po_s1l1 = 'PortChannel11'
data.po_s1l2 = 'PortChannel12'
data.po_s1l3 = 'PortChannel13'

data.po_s2l1 = 'PortChannel21'
data.po_s2l2 = 'PortChannel22'
data.po_s2l3 = 'PortChannel23'

# Tgen parameters
data.l2_vlan_count = 2
data.l2_mac_count = 2

data.leaf1_dict = {"tenant_mac_v6"  :    ["00.01.01.06.01.01", "00.01.01.06.02.01"],
         "tenant_mac_v4"  :   ["00.01.01.00.01.01", "00.01.01.00.02.01"],
         "tenant_v4_ip"  :    ["10.1.1.10","10.1.2.10","50.1.1.10"],
         "tenant_v6_ip"  :    ["1001::10", "1002::10"],
         "tenant_vlan_list"  : ["110", "111",],
         "tenant_vlan_int": ["Vlan110", "Vlan111"],
         "tenant_ip_list"  :    ["10.1.1.1", "10.1.2.1", "50.1.1.1"],
         "tenant_ipv6_list"  :    ["1001::1", "1002::1", "5001::1","5001::10"]}

data.leaf2_dict = {"tenant_mac_v6"  :   ["00.02.01.06.01.01", "00.02.01.06.02.01"],
         "tenant_mac_v4"  :   ["00.02.01.00.01.01", "00.02.01.00.02.01"],
         "tenant_v4_ip"  :    ["20.1.1.10","20.1.2.10"],
         "tenant_v6_ip"  :    ["2001::10","2002::10"],
         "tenant_vlan_list"  : ["210", "211"],
         "tenant_vlan_int": ["Vlan210", "Vlan211"],
         "tenant_ip_list"  :    ["20.1.1.1", "20.1.2.1"],
         "tenant_ipv6_list"  :    ["2001::1", "2002::1"]}

data.leaf3_dict = {"tenant_mac_v6"  :   ["00.03.01.06.01.01", "00.03.01.06.02.01"],
         "tenant_mac_v4"  :   ["00.03.01.00.01.01", "00.03.01.00.02.01"],
         "tenant_v4_ip"  :    ["30.1.1.10", "30.1.2.10"],
         "tenant_v6_ip"  :    ["3001::10","3002::10"],
         "tenant_vlan_list"  : ["310", "311"],
         "tenant_vlan_int": ["Vlan310", "Vlan311"],
         "tenant_ip_list"  :    ["30.1.1.1", "30.1.2.1"],
         "tenant_ipv6_list"  :    ["3001::1", "3002::1"]}

# System MAC and System GW testcase parameters

data.mclag_gw_mac = "00:11:22:33:88:99"
data.mclag_sys_mac = "00:11:33:33:44:66"
data.tg_dest_mac_list = ["00:00:00:12:22:0a","00:00:02:01:11:0b","00:00:02:01:11:0c","00:00:03:01:33:0d"]
