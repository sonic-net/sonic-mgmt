test_type = 'mix'
max_bfd = 64
dut1_as = '100'
dut2_as = '100'
ip_mask = '24'
ipv6_mask = '64'
max_bfd_vrf = 64
user_vrf_name = 'Vrf-101'

if test_type == 'mix':
    ipv4_bgp = int(max_bfd/2)
    ipv6_bgp = (max_bfd - ipv4_bgp)
    dut1_ip  = ['21.21.{}.1'.format(i) for i in range(ipv4_bgp)]
    dut2_ip = ['21.21.{}.2'.format(i) for i in range(ipv4_bgp)]
    dut1_ipv6  = ['20{}::1'.format(i) for i in range(ipv6_bgp)]
    dut2_ipv6  = ['20{}::2'.format(i) for i in range(ipv6_bgp)]
    vlan_list = range(301, (301 + int(max_bfd/2)))
    vlan_intf = ['Vlan{}'.format(vlan) for vlan in vlan_list]
    ipv4_bgp_vrf = int(max_bfd_vrf/2)
    ipv6_bgp_vrf = (max_bfd_vrf - ipv4_bgp_vrf)
    dut1_ip_vrf  = ['31.31.{}.1'.format(i) for i in range(ipv4_bgp_vrf)]
    dut2_ip_vrf = ['31.31.{}.2'.format(i) for i in range(ipv4_bgp_vrf)]
    dut1_ipv6_vrf  = ['40{}::1'.format(i) for i in range(ipv6_bgp_vrf)]
    dut2_ipv6_vrf  = ['40{}::2'.format(i) for i in range(ipv6_bgp_vrf)]
    vlan_list_vrf = range(601, (601 + int(max_bfd_vrf/2)))
    vlan_intf_vrf = ['Vlan{}'.format(vlan) for vlan in vlan_list_vrf]
elif test_type == 'ipv4':
    ipv4_bgp = max_bfd
    dut1_ip  = ['21.21.{}.1'.format(i) for i in range(ipv4_bgp)]
    dut2_ip  = ['21.21.{}.2'.format(i) for i in range(ipv4_bgp)]
    vlan_list = range(301, (301 + max_bfd))
    vlan_intf = ['Vlan{}'.format(vlan) for vlan in vlan_list]
elif test_type == 'ipv6':
    ipv6_bgp = max_bfd
    dut1_ipv6  = ['20{}::1'.format(i) for i in range(ipv6_bgp)]
    dut2_ipv6  = ['20{}::2'.format(i) for i in range(ipv6_bgp)]
    vlan_list = range(301, (301 + max_bfd))
    vlan_intf = ['Vlan{}'.format(vlan) for vlan in vlan_list]
total_vlans = len(vlan_list)
total_vlans_vrf = len(vlan_list_vrf)
