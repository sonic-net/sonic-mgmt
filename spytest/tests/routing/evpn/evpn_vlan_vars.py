from spytest.dicts import SpyTestDict

data = SpyTestDict()
#IP params
mask31 = '31'
mask32 = '32'

mask_1 = '20'
mask_v6 = '64'
mask_24 = '24'

#dut1_2_ip_list = ['12.12.12.0']
#dut2_1_ip_list = ['12.12.12.1']

vlan_s1_l1 = ['10','11']
vlan_s2_l2 = ['20','21']
vlan_s1_l3 = ['30','31']
vlan_s1_l4 = ['40','41']
vlan_s2_l3 = ['35','36']
vlan_s2_l4 = ['45','46']
vlan_l1_l2 = ['1000','1001']


vlanInt_s1_l1 = ['Vlan10','Vlan11']
vlanInt_s2_l2 = ['Vlan20','Vlan21']
vlanInt_s1_l3 = ['Vlan30','Vlan31']
vlanInt_s1_l4 = ['Vlan40','Vlan41']
vlanInt_s2_l3 = ['Vlan35','Vlan36']
vlanInt_s2_l4 = ['Vlan45','Vlan46']
vlanInt_l1_l2 = ['Vlan1000','Vlan1001']

dut1_3_ip_list = ['13.13.13.0','13.13.2.0']
dut3_1_ip_list = ['13.13.13.1','13.13.2.1']
dut1_5_ip_list = ['15.15.15.0','15.15.2.0']
dut5_1_ip_list = ['15.15.15.1','15.15.2.1']
dut1_6_ip_list = ['16.16.16.0','16.16.2.0']
dut6_1_ip_list = ['16.16.16.1','16.16.2.1']

dut3_4_ip_list = ['34.34.34.0','34.34.2.0','34.34.3.0']
dut4_3_ip_list = ['34.34.34.1','34.34.2.1','34.34.3.1']

dut2_4_ip_list = ['24.24.24.0','24.24.2.0']
dut4_2_ip_list = ['24.24.24.1','24.24.2.1']
dut2_5_ip_list = ['25.25.25.0','25.25.2.0']
dut5_2_ip_list = ['25.25.25.1','25.25.2.1']
dut2_6_ip_list = ['26.26.26.0','26.26.2.0']
dut6_2_ip_list = ['26.26.26.1','26.26.2.1']

#dut2_4_ip_list = ['192.168.0.1','20.20.20.1','30.30.30.1']
#dut3_server_ip_list = ['172.16.40.1']
#dut3_server_ipv6_list = ['2072::1']
loopback1 = 'Loopback1'
loopback2 = 'Loopback2'

dut1_loopback_ip = ['1.1.1.1','1.1.1.5']
dut2_loopback_ip = ['2.2.2.1','2.2.2.5']
dut3_loopback_ip = ['3.3.3.1','3.3.3.5']
dut4_loopback_ip = ['4.4.4.1','4.4.4.5']
dut5_loopback_ip = ['5.5.5.1','5.5.5.5']
dut6_loopback_ip = ['6.6.6.1','6.6.6.5']

loopback1_ip_list = ['1.1.1.1','2.2.2.1','3.3.3.1','4.4.4.1','5.5.5.1','6.6.6.1']
loopback2_ip_list = ['1.1.1.5','2.2.2.5','3.3.3.5','3.3.3.5','5.5.5.5','6.6.6.5']

## Added for IPv6 address
dut1_2_ipv6_list = ['2001::1:1', '2002::2:1', '2003::3:1']
dut2_1_ipv6_list = ['2001::1:2', '2002::2:2', '2003::3:2']
dut1_3_ipv6_list = ['3001::1:1', '3002::2:1', '3003::3:1']
dut3_1_ipv6_list = ['3001::1:2', '3002::2:2', '3003::3:2']
dut2_4_ipv6_list = ['2092::1', '2020::1', '2030::1']

link_local_po_s1leaf = []
link_local_po_s2leaf = []
link_local_po_l1s1 = []
link_local_po_l2s2 = []
link_local_po_l3spine = []
link_local_po_l4spine = []


dut1_AS ='100'
dut2_AS ='200'
dut3_AS ='300'
dut4_AS ='400'
dut5_AS ='500'
dut6_AS ='600'
keep_alive = 3
hold_down = 9
vrf1 ='Vrf-Red'
vlan_vrf1 = 'Vlan500'
vni_vlan = ['500']
mclag_client_vlans = ['100','101']
vrf1_ip = ['22.22.1.1','22.22.1.1','33.33.1.1','44.44.1.1']
vrf1_ip6 = ['1212::1','1212::1','1313::1','1414::1']
vrf_blue ='Vrf-Blue'

vtep_names = ["vtepLeaf1","vtepLeaf2","vtepLeaf3","vtepLeaf4"]
nvo_names = ["nvoLeaf1","nvoLeaf2","nvoLeaf3","nvoLeaf4"]
mlag_domain_id = '1'
client_lag = 'PortChannel12'
orphan_lag = 'PortChannel30'
client_lag_l3 = 'PortChannel13'
iccp_lag = 'PortChannel10'

po_s1l1 = 'PortChannel11'
po_s1l3 = 'PortChannel13'
po_s1l4 = 'PortChannel14'

po_s2l2 = 'PortChannel22'
po_s2l3 = 'PortChannel23'
po_s2l4 = 'PortChannel24'

data.inter_vni = False
src_intf_same_vni = 'Loopback3'
src_intf_diff_vni = 'Loopback4'

route_list =  ['192.168.0.0/24','20.20.20.0/24','192.168.200.0/24','30.30.30.0/24','100.100.100.100/32','100.100.100.101/32','22.22.1.0/24']
route_list_6 = ['2092::0/64', '2020::0/64', '2200::0/64','2030::0/64','4000::10/128','4000::11/128', '1212::0/64']

# Tgen parameters
l2_vlan_count = 2
l2_mac_count = 2

client_mac = ["00.01.07.00.00.01","00.01.07.01.00.01","00.01.07.02.00.01","00.01.07.03.00.01"]
leaf5_mac = ["00.01.05.00.00.01"]
leaf6_mac = ["00.01.06.00.00.01"]
sag_mac = "00:00:00:04:01:03"

client_dict = {"tenant_mac_v4" : "00.07.00.00.00.01",
          "tenant_mac_v6" : "00.07.01.00.00.01",
          "tenant_v4_ip" : "70.1.1.20",
          "tenant_v6_ip" : "7001::20",
          "tenant_l2_vlan_list": ["100", "101", "102"],
          "tenant_l2_vlan_int": ["Vlan100", "Vlan101", "Vlan102"],
          "tenant_l3_vlan_list"  : ["200", "201", "202"],
          "tenant_l3_vlan_int": ["Vlan200", "Vlan201", "Vlan202"],
          "l2_tenant_ip_list": ["15.1.1.1"],
          "l2_tenant_ipv6_list": ["1501::1"],
          "l3_tenant_ip_list": ["70.1.1.1", "70.1.2.1", "70.1.3.1"],
          "l3_tenant_ip_list3": ["70.1.1.1", "70.1.2.2", "70.1.3.1"],
          "l3_tenant_ip_list2": ["70.1.1.2", "70.1.2.3", "70.1.3.2"],
          "l3_tenant_ipv6_list2": ["7001::2", "7002::3", "7003::2"],
          "l3_tenant_ipv6_list" : ["7001::1", "7002::1", "7003::1"],
          "l3_tenant_ipv6_list3" : ["7001::1", "7002::2", "7003::1"]}

leaf3_mac = ["00.01.05.00.00.01"]
leaf3_dict  = {"tenant_mac_v4" : "00.05.00.00.00.01",
          "tenant_v4_ip" : "50.0.1.20",
          "l2_tenant_ip_list": ["15.1.1.2"],
          "l2_tenant_ipv6_list": ["1501::2"],
          "l3_tenant_ip_list" : ["50.0.1.1", "50.1.2.1", "50.1.3.1"],
          "tenant_v6_ip" : "5001::2",
          "tenant_l3_vlan_list"  : ["510", "511", "512"],
          "tenant_l3_vlan_int": ["Vlan510", "Vlan511", "Vlan512"],
          "l3_tenant_ipv6_list"  :    ["5001::1", "5002::1", "5003::1"]}

leaf4_mac = ["00.01.06.00.00.01"]
leaf4_dict = {"tenant_mac_v6"  :    "00.06.01.00.00.01",
         "tenant_v4_ip"  :    "60.1.1.20",
         "l3_tenant_ip_list"  :    ["60.1.1.1", "60.1.2.1", "60.1.3.1"],
         "tenant_v6_ip"  :    "6001::20",
         "tenant_l3_vlan_list"  : ["610", "611", "612"],
         "tenant_l3_vlan_int": ["Vlan610", "Vlan611", "Vlan612"],
         "l3_tenant_ipv6_list"  :    ["6001::1", "6002::1", "6003::1"]}

# System MAC and System GW testcase parameters

mclag_gw_mac = "00:11:22:33:88:99"
mclag_sys_mac = "00:11:33:33:44:66"

# IP SLA Configs
threshold = 3
target_vlans = ['2000','200','201','202']
target_vlan_intfs = ['Vlan2000','Vlan200','Vlan201','Vlan202']
mclag_sla_ips_1 = ['11.15.1.1','70.1.1.1','70.1.2.1','70.1.3.1']
mclag_sla_ipv6_1 = ['1511::1','7001::1','7002::1','7003::1']
mclag_sla_ips_2 = ['11.15.1.2','70.1.1.1','70.1.2.2','70.1.3.1']
mclag_sla_ipv6_2 = ['1511::2','7001::1','7002::2','7003::1']
target_ips = ['11.15.1.10','70.1.1.2','70.1.2.3','70.1.3.2']
target_ipv6 = ['1511::10','7001::2','7002::3','7003::2']
target_ips_subnet = ['100.1.1.0','100.1.2.0','200.1.1.0','200.1.2.0']
target_ipv6_subnet = ['1101::','1102::','1201::','1202::']

tcp_ports = ['22','179']
sla_freq = "1"
sla_ids_1 = [str(i) for i in range(1,13)]
sla_ids_2 = [str(i) for i in range(101,113)]
