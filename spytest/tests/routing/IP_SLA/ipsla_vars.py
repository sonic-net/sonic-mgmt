from spytest.dicts import SpyTestDict

data = SpyTestDict()
#IP params
mask31 = '31'
mask32 = '32'
mask_v6 = '64'
mask24 = '24'
vrf1 ='Vrf-Red'
dut1_AS ='100'
dut2_AS ='200'
dut3_AS ='300'
dut4_AS ='400'

threshold = 3
target_vlans = ['100','101','200','201']
target_vlan_intfs = ['Vlan100','Vlan101','Vlan200','Vlan201']
target_ips = ['100.1.1.10','100.1.2.10','200.1.1.10','200.1.2.10']
target_ipv6 = ['1101::10','1102::10','1201::10','1202::10']
target_ips_subnet = ['100.1.1.0','100.1.2.0','200.1.1.0','200.1.2.0']
target_ipv6_subnet = ['1101::','1102::','1201::','1202::']

tcp_ports = ['22','179']
sla_freq = "1"

dut1_3_ip_list = ['13.13.13.0','13.13.2.0']
dut3_1_ip_list = ['13.13.13.1','13.13.2.1']
dut1_3_ipv6_list = ['2013::1:1', '2013::2:1']
dut3_1_ipv6_list = ['2013::1:2', '2013::2:2']

dut1_4_ip_list = ['14.14.14.0','14.14.2.0']
dut4_1_ip_list = ['14.14.14.1','14.14.2.1']
dut1_4_ipv6_list = ['2014::1:1', '2014::2:1']
dut4_1_ipv6_list = ['2014::1:2', '2014::2:2']

dut2_3_ip_list = ['23.23.23.0','23.23.2.0']
dut3_2_ip_list = ['23.23.23.1','23.23.2.1']
dut2_3_ipv6_list = ['2023::1:1', '2023::2:1']
dut3_2_ipv6_list = ['2023::1:2', '2023::2:2']

dut2_4_ip_list = ['24.24.24.0','24.24.2.0']
dut4_2_ip_list = ['24.24.24.1','24.24.2.1']
dut2_4_ipv6_list = ['2024::1:1', '2024::2:1']
dut4_2_ipv6_list = ['2024::1:2', '2024::2:2']

po_s2l1 = 'PortChannel11'
vlanInt_s2_l1 = ['Vlan30','Vlan31']
vlan_s2_l1 = ['30','31']
vlanInt_s1_l1 = ['Vlan40','Vlan41']
vlan_s1_l1 = ['40','41']

client_vlans = [vlan_s1_l1[0],vlan_s2_l1[0]]
vlan_tgen = ['10','20']
vlanInt_tgen = ['Vlan10','Vlan20']
dut3_tg1_ip = ['10.10.10.1','20.20.2.1']
dut3_tg1_ipv6 = ['1010::1:1', '2020::2:1']
dut3_tgen_mac = ["00.00.03.00.00.01","00.00.03.01.00.01","00.00.03.02.00.01","00.00.03.03.00.01"]

tgen_dut3_ips = ['10.10.10.10','20.20.2.10']
tgen_dut3_ipv6 = ['1010::1:10', '2020::2:10']

dut4_tgen_mac = ["00:00:04:00:00:01","00:00:04:01:00:01","00:00:04:02:00:01","00:00:04:03:00:01"]

tgen_dut4_ips = ['100.1.1.100','100.1.2.100','200.1.1.100','200.1.2.100']
tgen_dut4_ipv6 = ['1101::15','1102::15','1201::15','1202::15']

loopback1 = 'Loopback1'
loopback2 = 'Loopback2'

dut1_loopback_ip = ['1.1.1.1','1.1.1.5']
dut2_loopback_ip = ['2.2.2.1','2.2.2.5']
dut3_loopback_ip = ['3.3.3.1','3.3.3.5']
dut4_loopback_ip = ['4.4.4.1','4.4.4.5']
loopback1_ip_list = [dut1_loopback_ip[0],dut2_loopback_ip[0],dut3_loopback_ip[0],dut4_loopback_ip[0]]
## Scale parameters

## MCLAG Parameters
mlag_domain_id = '1'
client_lag = 'PortChannel12'
iccp_lag = 'PortChannel10'

