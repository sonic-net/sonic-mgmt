###############################################################################
#Script Title : Syslog source interface over default and non default vrf
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com

###############################################################################
from spytest.dicts import SpyTestDict

data = SpyTestDict()
data.test_var = 'testing'

data.dut1_loopback = ['Loopback1','Loopback2']
data.dut2_loopback = ['Loopback1','Loopback2']
data.dut3_loopback = ['Loopback1','Loopback2']

data.dut1_loopback_ip =  ['1.1.1.1','11.11.11.11']
data.dut2_loopback_ip =  ['2.2.2.2','22.22.22.22']
data.dut3_loopback_ip =  ['3.3.3.3','33.33.33.33']

data.dut1_loopback_ipv6 = ['1111::1','1100::1']
data.dut2_loopback_ipv6 = ['2222::2','2200::2']
data.dut3_loopback_ipv6 = ['3333::3','3300::3']

data.dut1_loopback_ip_subnet = '32'
data.dut2_loopback_ip_subnet = '32'
data.dut3_loopback_ip_subnet = '32'

data.dut1_loopback_ipv6_subnet = '128'
data.dut2_loopback_ipv6_subnet = '128'
data.dut3_loopback_ipv6_subnet = '128'

data.dut1_dut2_vlan = ['2', '3']
data.dut2_dut3_vlan = ['2', '3']

data.dut3_vrf_phy = 'Vrf-blue'
data.dut3_vrf_pc = 'Vrf-red'
data.dut3_vrf_vlan = 'Vrf-green'

data.dut1_mgmt_ipv6 = ['3300::1','3300::2']
data.dut2_mgmt_ipv6 = ['4400::1','4400::2']
data.dut3_mgmt_ipv6 = ['5500::1','5500::2']

data.dut1_mgmt_ipv6_subnet = '64'
data.dut2_mgmt_ipv6_subnet = '64'
data.dut3_mgmt_ipv6_subnet = '64'

data.dut1_dut2_ip = ['1.0.%s.2'%x for x in range(1,10)]
data.dut2_dut1_ip = ['1.0.%s.3'%x for x in range(1,10)]

data.dut2_dut3_ip = ['2.0.%s.2'%x for x in range(1,10)]
data.dut3_dut2_ip = ['2.0.%s.3'%x for x in range(1,10)]

data.dut1_dut2_ip_subnet = '24'
data.dut2_dut1_ip_subnet = '24'
data.dut2_dut3_ip_subnet = '24'
data.dut3_dut2_ip_subnet = '24'

data.dut1_dut2_ipv6 = ['100%s::2'%x for x in range(1,10)]
data.dut2_dut1_ipv6 = ['100%s::3'%x for x in range(1,10)]

data.dut2_dut3_ipv6 = ['200%s::2'%x for x in range(1,10)]
data.dut3_dut2_ipv6 = ['300%s::3'%x for x in range(1,10)]

data.dut1_dut2_ipv6_subnet = '64'
data.dut2_dut1_ipv6_subnet = '64'
data.dut2_dut3_ipv6_subnet = '64'
data.dut3_dut2_ipv6_subnet = '64'