
def _build(**kwargs):
    kwargs.setdefault("mac_src", '00.00.00.00.00.01')
    kwargs.setdefault("mac_dst", '00.00.00.00.00.02')
    kwargs.setdefault("mac_src_step", '00.00.00.00.00.01')
    kwargs.setdefault("mac_dst_step", '00.00.00.00.00.01')
    kwargs.setdefault("arp_src_hw_addr", '01.00.00.00.00.01')
    kwargs.setdefault("arp_dst_hw_addr", '01.00.00.00.00.02')
    kwargs.setdefault("ip_src_addr", '11.1.1.1')
    kwargs.setdefault("ip_dst_addr", '225.1.1.1')
    kwargs.setdefault("ip_src_step", '0.0.0.1')
    kwargs.setdefault("ip_dst_step", '0.0.0.1')
    kwargs.setdefault("mac_src_count", 20)
    kwargs.setdefault("mac_dst_count", 20)
    kwargs.setdefault("arp_src_hw_count", 20)
    kwargs.setdefault("arp_dst_hw_count", 10)
    kwargs.setdefault("ip_src_count", 20)
    kwargs.setdefault("ip_dst_count", 20)
    kwargs.setdefault("transmit_mode", 'continuous')
    kwargs.setdefault("length_mode", 'fixed')
    kwargs.setdefault("vlan_id", 10)
    kwargs.setdefault("vlan_id_count", 10)
    kwargs.setdefault("vlan_id_step", 3)
    kwargs.setdefault("l2_encap", 'ethernet_ii')
    kwargs.setdefault("frame_size", 64)
    kwargs.setdefault("pkts_per_burst", 10)
    kwargs.setdefault("mode", "create")

    return kwargs

def _build2(index=0):

    if index == 0: return _build()
    if index == 1: return _build(length_mode='random', transmit_mode='single_burst')
    if index == 2: return _build(length_mode='increment', transmit_mode='single_burst', frame_size_step=2000)
    if index == 3: return _build(mac_dst_mode="increment")
    if index == 4: return _build(mac_src_mode="increment", transmit_mode='single_burst')
    if index == 5: return _build(l3_protocol='arp', arp_src_hw_mode="increment", arp_dst_hw_mode="decrement")
    if index == 6: return _build(rate_pps=1, l3_protocol='ipv4', ip_src_mode='increment', ip_dst_mode='decrement')
    if index == 7: return _build(vlan_user_priority="3", l2_encap="ethernet_ii_vlan", vlan_id_mode="increment")
    if index == 8: return _build(vlan="enable", l3_protocol='ipv4', ip_src_addr='1.1.1.1', ip_dst_addr='5.5.5.5',
        ip_dscp="8", high_speed_result_analysis=0, track_by='trackingenabled0 ipv4DefaultPhb0',
        ip_dscp_tracking=1)
    if index == 9: return _build(l2_encap='ethernet_ii', ethernet_value='88CC',
        data_pattern='02 07 04 00 11 97 2F 8E 80 04 07 03 00 11 97 2F 8E 82 06 02 00 78 00 00 00 00 '
        '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
    if index == 10: return _build(l2_encap='ethernet_ii', ethernet_value='8809', data_pattern_mode='fixed',
        data_pattern='02 07 04 00 11 97 2F 8E 80 04 07 03 00 11 97 2F 8E 82 06 02 00 78 00 00 00 00 '
        '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
    if index == 11: return _build(data_pattern='FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 00 2D 01 04 00 C8 00 5A 05 05 '
        '05 05 10 02 0E 01 04 00 01 00 01 02 00 41 04 00 00 00 C8', l3_protocol='ipv4', ip_protocol=6,
         ip_src_addr='1.1.1.1', l4_protocol='tcp', ip_precedence=5, frame_size=103,
        ip_dst_addr='1.1.1.2', tcp_dst_port=179, tcp_src_port=54821, tcp_window=115,
        tcp_seq_num=1115372998, tcp_ack_num=1532875182,tcp_ack_flag=1, tcp_psh_flag=1, ip_ttl=1)
    if index == 12: return _build(l3_protocol='ipv6', data_pattern='01 D1 49 5E 00 08 00 02 00 78 00 01 00 0A 00 03 00 01 00 13 '
        '5F 1F F2 80 00 06 00 06 00 19 00 17 00 18 00 19 00 0C 00 33 ' '00 01 00 00 00 00 00 00 00 00',
        frame_size=116, ipv6_dst_addr="FF02:0:0:0:0:0:1:2", ipv6_src_addr="FE80:0:0:0:201:5FF:FE00:500",
        ipv6_next_header=17, ipv6_traffic_class=224,l4_protocol='udp',udp_dst_port=546,
        udp_src_port=547, ipv6_hop_limit=255)
    if index == 13: return _build(l3_protocol='arp', arp_src_hw_addr="00:00:00:11:11:80",
        arp_dst_hw_addr="00:00:00:00:00:00", arp_operation='arpRequest', ip_src_addr='1.1.1.1', ip_dst_addr='1.1.1.2')
    if index == 14: return _build(l3_protocol='ipv6', data_pattern='FF FF', l4_protocol="icmp", ipv6_dst_addr="fe80::ba6a:97ff:feca:bb98",
        ipv6_src_addr="2001::2", ipv6_next_header=58, icmp_target_addr='2001::2', icmp_type=136, icmp_ndp_nam_o_flag=0,
        icmp_ndp_nam_r_flag=1, icmp_ndp_nam_s_flag=1, ipv6_hop_limit=255)
    if index == 15: return _build(rate_pps=1, l3_protocol='ipv4',ip_src_addr='11.1.1.1', ip_dst_addr='225.1.1.1',ip_protocol=2, \
         l4_protocol='igmp',igmp_msg_type='report',igmp_group_addr='225.1.1.1',high_speed_result_analysis=0)
    if index == 16: return _build(rate_pps=1, l3_protocol='ipv6', ipv6_src_addr='33f1::1', ipv6_dst_addr='7fe9::1', ipv6_dst_step='::1', ipv6_dst_mode='increment', ipv6_dst_count=10)
    return None

def ut_stream_get(index=0, **kws):
    kwargs = _build2(index)
    if kwargs: kwargs.update(kws)
    return kwargs

if __name__ == '__main__':
    print(ut_stream_get(0))
    for i in range(100):
        d = ut_stream_get(i)
        if not d:
            break
        print(d)

