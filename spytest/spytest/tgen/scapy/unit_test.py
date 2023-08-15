#!/bin/sh

''':'
exec $(dirname $0)/../../../bin/python "$0" "$@"
'''

import os
import sys
import json
import time
import logging

from spytest.tgen.tg_scapy import ScapyClient
import utilities.common as utils

if sys.version_info[0] >= 3:
    raw_input = input

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logging.getLogger("Pyro4").setLevel(logging.DEBUG)
logging.getLogger("Pyro4.core").setLevel(logging.DEBUG)


class TGScapyTest(ScapyClient):
    def __init__(self, tg_ip=None, tg_port=8009, tg_port_list=None, dry_run=False):
        ScapyClient.__init__(self, None, tg_ip, tg_port, tg_port_list)
        # os.environ["SCAPY_TGEN_PORTMAP"] = "vde"
        os.environ["SPYTEST_SCAPY_DBG_LVL"] = "100"
        self.scapy_connect(dry_run)

    def __del__(self):
        pass

    def log_call(self, fname, **kwargs):
        pass

    def save_log(self, name, data):
        utils.write_file(os.path.join("client", name), data)


def test_clear(tg):
    port_list = list(tg.tg_port_handle.values())
    tg.tg_traffic_control(action="reset", port_handle=port_list)
    tg.tg_traffic_control(action="clear_stats", port_handle=port_list)
    for tg_ph in port_list:
        tx_stats = tg.tg_traffic_stats(port_handle=tg_ph, mode="aggregate")
        print("TX-STATS", json.dumps(tx_stats))
        rx_stats = tg.tg_traffic_stats(port_handle=tg_ph, mode="aggregate")
        print("RX-STATS", json.dumps(rx_stats))


def test_single_burst(tg, rate_pps=2, stats=True):
    print("============= test_single_burst ==============")
    tg_ph_1 = list(tg.tg_port_handle.values())[0]
    # tg.tg_traffic_config(mac_src='00:00:00:00:10:01', mac_dst='52:54:74:68:8b:d2',
    tg.tg_traffic_config(mac_src='00:00:00:00:00:01', mac_dst='00:00:00:00:00:02',
                         l3_protocol='ipv4', ip_src_addr="1.0.0.1", ip_dst_addr="2.0.0.2",
                         ip_src_mode='increment', ip_dst_mode='increment',
                         rate_pps=rate_pps, mode='create', port_handle=tg_ph_1,
                         transmit_mode='single_burst', pkts_per_burst=10, frame_size=64)
    tg.tg_traffic_control(action='run', port_handle=tg_ph_1)
    if stats:
        time.sleep(2)
        tx_stats = tg.tg_traffic_stats(port_handle=tg_ph_1, mode="aggregate")
        print(tx_stats)


def test_untagged(tg, count=2):
    print("============= test_untagged ==============")
    (tg_ph_1, tg_ph_2) = list(tg.tg_port_handle.values())
    res = tg.tg_traffic_config(mac_src='00.00.10.00.00.02', mac_dst='00.00.10.00.00.01',
                               rate_pps=count, mode='create', mac_src_mode="increment",
                               mac_src_count=20, mac_src_step="00:00:00:00:00:01",
                               port_handle=tg_ph_1, transmit_mode='continuous', frame_size='128')
    tg.tg_traffic_control(action='run', handle=res.stream_id, duration=20)
    time.sleep(2)
    tg.tg_traffic_control(action='stop', port_handle=tg_ph_1)
    tx_stats = tg.tg_traffic_stats(port_handle=tg_ph_1, mode="aggregate")
    print("TX-STATS", json.dumps(tx_stats))
    rx_stats = tg.tg_traffic_stats(port_handle=tg_ph_2, mode="aggregate")
    print("RX-STATS", json.dumps(rx_stats))


def test_tagged(tg, count=2):
    print("============= test_tagged ==============")
    (tg_ph_1, tg_ph_2) = list(tg.tg_port_handle.values())
    tg.tg_traffic_config(mac_src='00.00.00.00.00.01', mac_dst='00.00.00.00.00.02', rate_pps=count, mode='create',
                         port_handle=tg_ph_1, transmit_mode='continuous', l2_encap='ethernet_ii_vlan', vlan_id='10', frame_size='256', vlan="enable")
    tg.tg_traffic_control(action='run', port_handle=tg_ph_1, duration=2)
    time.sleep(5)
    tg.tg_traffic_control(action='stop', port_handle=tg_ph_1)
    tx_stats = tg.tg_traffic_stats(port_handle=tg_ph_1, mode="aggregate")
    print("TX-STATS", json.dumps(tx_stats))
    rx_stats = tg.tg_traffic_stats(port_handle=tg_ph_2, mode="aggregate")
    print("RX-STATS", json.dumps(rx_stats))


def test_capture(tg):
    print("============= test_capture ==============")
    (tg_ph_1, tg_ph_2) = list(tg.tg_port_handle.values())
    tg.tg_traffic_config(mac_src='00.00.00.00.10.01', mac_dst='00.00.00.00.10.02', rate_pps='2', mode='create',
                         port_handle=tg_ph_1, transmit_mode='single_burst', pkts_per_burst=10, frame_size=64)
    tg.tg_packet_control(port_handle=tg_ph_2, action='start')
    tg.tg_traffic_control(action='run', port_handle=tg_ph_1)
    time.sleep(5)
    tg.tg_traffic_control(action='stop', port_handle=tg_ph_1)
    tx_stats = tg.tg_traffic_stats(port_handle=tg_ph_2, mode="aggregate")
    print(tx_stats)
    totPackets = tg.tg_packet_control(port_handle=tg_ph_2, action='stop')
    print(totPackets)
    packet_dict = tg.tg_packet_stats(port_handle=tg_ph_2, format='var')
    print(packet_dict)


def test_interface(tg):
    print("============= test_interface ==============")
    tg_ph_1 = list(tg.tg_port_handle.values())[0]
    res1 = tg.tg_interface_config(port_handle=tg_ph_1, mode='config', arp_send_req='1',
                                  intf_ip_addr='21.1.1.100', gateway='21.1.1.1', src_mac_addr='00:0a:01:01:00:01')
    tg.tg_interface_config(port_handle=tg_ph_1, handle=res1['handle'], mode='destroy')
    res2 = tg.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='12.12.0.2',
                                  gateway='12.12.0.1', netmask='255.255.0.0', vlan=1,
                                  vlan_id=10, vlan_id_step=1, arp_send_req='1', vlan_id_count=10,
                                  gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1)
    print(res2)
    res = tg.tg_interface_config(protocol_handle=res2["handle"], send_ping='1', ping_dst='12.12.0.1')
    print("PING_RES: " + str(res))
    tg.tg_interface_config(port_handle=tg_ph_1, handle=res2['handle'], mode='destroy')


def test_nat(tg):
    tg.tg_interface_config(count=1, arp_send_req=1, intf_ip_addr="12.12.0.2", port_handle="port-1/1", netmask="255.255.0.0", mode="config", gateway_step="0.0.0.0", gateway="12.12.0.1")
    tg.tg_interface_config(count=1, arp_send_req=1, intf_ip_addr="125.56.90.1", port_handle="port-1/2", netmask="255.255.255.0", mode="config", gateway_step="0.0.0.0", gateway="125.56.90.12")
    # mac_src = "00:00:23:11:14:08"
    mac_src = "e2:8d:ab:ee:fb:6c"
    mac_src2 = raw_input()
    if mac_src2:
        mac_src = mac_src2
    res = tg.tg_traffic_config(mac_src=mac_src, mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="129.2.30.12",
                               pkts_per_burst=1, ip_src_addr="12.12.0.2", port_handle="port-1/1", transmit_mode="single_burst",
                               rate_pps=10, mode="create", l3_protocol="ipv4")
    tg.tg_traffic_control(action="run", handle=res["stream_id"])


def test_nat0(tg):
    tg.tg_traffic_control(action="reset", port_handle=['port-1/2', 'port-1/1'])
    tg.tg_traffic_control(action="clear_stats", port_handle=['port-1/2', 'port-1/1'])
    tg.tg_interface_config(count=10, arp_send_req=1, intf_ip_addr="12.12.0.2", port_handle="port-1/1", netmask="255.255.0.0", mode="config", gateway_step="0.0.0.0", gateway="12.12.0.1")
    tg.tg_interface_config(count=10, arp_send_req=1, intf_ip_addr="125.56.90.1", port_handle="port-1/2", netmask="255.255.255.0", mode="config", gateway_step="0.0.0.0", gateway="125.56.90.12")
    tg.tg_traffic_config(mac_src="00:00:23:11:14:08", mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="129.2.30.12", pkts_per_burst=10, ip_src_addr="12.12.0.2", port_handle="port-1/1", transmit_mode="single_burst", rate_pps=10, mode="create", l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:23:11:14:08", l4_protocol="tcp", tcp_src_port=1002, mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="129.2.30.12", pkts_per_burst=10, ip_src_addr="12.12.0.3", port_handle="port-1/1", transmit_mode="single_burst", rate_pps=10, mode="create", tcp_dst_port=3345, l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:23:11:14:08", mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="129.2.30.12", pkts_per_burst=10, ip_src_addr="88.98.128.2", port_handle="port-1/1", transmit_mode="single_burst", rate_pps=10, mode="create", l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:23:11:14:08", l4_protocol="udp", udp_src_port=7781, mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="129.2.30.12", pkts_per_burst=10, ip_src_addr="12.12.0.4", port_handle="port-1/1", transmit_mode="single_burst", rate_pps=10, mode="create", l3_protocol="ipv4", udp_dst_port=8812)
    tg.tg_traffic_config(mac_src="00:00:23:11:14:08", mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="15.15.0.1", pkts_per_burst=10, ip_src_addr="12.12.0.5", port_handle="port-1/1", transmit_mode="single_burst", rate_pps=10, mode="create", l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:23:11:14:08", l4_protocol="udp", udp_src_port=251, mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="129.2.30.12", pkts_per_burst=10, ip_src_addr="12.12.0.11", port_handle="port-1/1", transmit_mode="single_burst", rate_pps=10, mode="create", l3_protocol="ipv4", udp_dst_port=444)
    tg.tg_traffic_config(mac_src="00:00:43:32:1A", mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="125.56.90.12", pkts_per_burst=10, ip_src_addr="129.2.30.12", port_handle="port-1/2", transmit_mode="single_burst", rate_pps=10, mode="create", l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:43:32:1A", l4_protocol="tcp", tcp_src_port=345, mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="125.56.90.13", pkts_per_burst=10, ip_src_addr="129.2.30.12", port_handle="port-1/2", transmit_mode="single_burst", rate_pps=10, mode="create", tcp_dst_port=100, l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:43:32:1A", mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="11.11.11.2", pkts_per_burst=10, ip_src_addr="129.2.30.12", port_handle="port-1/2", transmit_mode="single_burst", rate_pps=10, mode="create", l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:43:32:1A", l4_protocol="udp", udp_src_port=5516, mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="125.56.90.14", pkts_per_burst=10, ip_src_addr="129.2.30.12", port_handle="port-1/2", transmit_mode="single_burst", rate_pps=10, mode="create", l3_protocol="ipv4", udp_dst_port=7811)
    tg.tg_traffic_config(mac_src="00:00:43:32:1A", mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="125.56.90.15", pkts_per_burst=10, ip_src_addr="99.99.99.1", port_handle="port-1/2", transmit_mode="single_burst", rate_pps=10, mode="create", l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:43:32:1A", l4_protocol="udp", udp_src_port=12001, mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="125.56.90.23", pkts_per_burst=10, ip_src_addr="129.2.30.12", port_handle="port-1/2", transmit_mode="single_burst", rate_pps=10, mode="create", l3_protocol="ipv4", udp_dst_port=333)
    tg.tg_traffic_config(mac_src="00:00:43:32:1A", l4_protocol="udp", udp_src_port=12001, mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="125.56.90.23", pkts_per_burst=10, ip_src_addr="129.2.30.12", port_handle="port-1/2", transmit_mode="single_burst", rate_pps=10, mode="create", l3_protocol="ipv4", udp_dst_port=334)
    tg.tg_traffic_config(mac_src="00:00:43:32:1A", l4_protocol="udp", udp_src_port=12001, mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="125.56.90.24", pkts_per_burst=10, ip_src_addr="129.2.30.12", port_handle="port-1/2", transmit_mode="single_burst", rate_pps=10, mode="create", l3_protocol="ipv4", udp_dst_port=333)
    tg.tg_traffic_config(mac_src="00:00:43:32:1A", l4_protocol="udp", udp_src_port=12001, mac_dst="80:a2:35:26:0a:5e", ip_dst_addr="125.56.90.24", pkts_per_burst=10, ip_src_addr="129.2.30.12", port_handle="port-1/2", transmit_mode="single_burst", rate_pps=10, mode="create", l3_protocol="ipv4", udp_dst_port=334)
    tg.tg_traffic_control(action="run", handle="stream-1-0")
    tg.tg_traffic_control(action="run", handle="stream-1-2")
    tg.tg_traffic_control(action="run", handle="stream-2-2")
    tg.tg_traffic_control(action="run", handle="stream-1-1")
    tg.tg_traffic_control(action="stop", port_handle="port-1/1")
    tg.tg_traffic_control(action="run", handle="stream-2-1")
    tg.tg_traffic_control(action="stop", port_handle="port-1/2")


def test_bgp(tg):
    res = tg.tg_interface_config(intf_ip_addr='10.10.10.2', gateway='10.10.10.1', arp_send_req='1', port_handle='port-1', mode='config')
    tg.tg_emulation_bgp_config(handle=res["handle"], local_as=200, active_connect_enable='1', mode='enable', remote_as=100, remote_ip_addr='10.10.10.1')
    tg.tg_emulation_bgp_route_config(handle=res["handle"], prefix='121.1.1.0', num_routes=2, mode='add', as_path='as_seq:1')
    tg.tg_emulation_bgp_control(handle=res["handle"], mode="start")


def test_emulated(tg):
    tg_ph_1 = list(tg.tg_port_handle.values())[0]
    tg.tg_traffic_config(**{'ip_src_count': 1, 'mac_src': '00:0a:01:00:11:01', 'l3_length': '500', 'length_mode': 'fixed', 'mac_dst': '00:00:00:00:00:00', 'port_handle': 'port-1', 'ip_src_addr': '192.168.13.2', 'transmit_mode': 'continuous', 'rate_pps': '1000', 'mode': 'create', 'l3_protocol': 'ipv4'})
    tg.tg_traffic_control(action='run', port_handle=tg_ph_1)


def test_track(tg):
    tg.tg_traffic_config(port_handle='port-1', port_handle2='port-2',
                         tcp_src_port=43, mac_dst="3c:2c:99:d3:a7:af", tcp_dst_port_count=10, ip_dst_addr='2.2.2.2',
                         high_speed_result_analysis=0, ip_dst_mode='fixed', tcp_dst_port=10, tcp_dst_port_step=1, length_mode='fixed',
                         rate_pps=1, tcp_dst_port_mode='incr', ip_src_addr='1.1.1.2', ip_src_mode='fixed', transmit_mode='continuous',
                         frame_size='128', l2_encap='ethernet_ii_vlan', l3_protocol='ipv4', mac_src='00:0a:01:00:00:01', l4_protocol='tcp', mode='create')
    tg.tg_traffic_config(port_handle='port-2', port_handle2='port-1',
                         mac_src='00:0a:01:00:11:02', tcp_src_port_count=10, tcp_src_port_mode='incr', l4_protocol='tcp', tcp_src_port=100,
                         length_mode='fixed', mac_dst="a8:2b:b5:ac:45:1f", tcp_src_port_step=1, ipv6_dst_addr='1001::2',
                         transmit_mode='continuous', high_speed_result_analysis=0, mode='create', frame_size='128',
                         l2_encap='ethernet_ii_vlan', rate_pps=1, l3_protocol='ipv6', ipv6_src_addr='2001::2')
    tg.tg_traffic_control(action='run', duration=10, stream_handle=['stream-1-0', 'stream-2-0'])


def test_main(ipaddr, port=8009):
    tg = TGScapyTest(ipaddr, port, ["1/1", "1/2"])

    test_track(tg)
    raw_input("press any key")

    test_bgp(tg)
    raw_input("press any key")

    test_emulated(tg)
    raw_input("press any key")

    tg.server_control("pre-module-prolog", "mod-0")
    test_clear(tg)
    tg.server_control("post-module-epilog", "mod-0")

    tg.server_control("pre-module-prolog", "mod-2")
    test_single_burst(tg)
    tg.server_control("post-module-epilog", "mod-2")
    raw_input("press any key")

    tg.server_control("pre-module-prolog", "mod-2")
    test_untagged(tg, 10)
    tg.server_control("post-module-epilog", "mod-2")

    raw_input("press any key")
    tg.server_control("pre-module-prolog", "mod-3")
    test_tagged(tg, 10)
    tg.server_control("post-module-epilog", "mod-3")

    raw_input("press any key")
    tg.server_control("pre-module-prolog", "mod-4")
    test_capture(tg)
    tg.server_control("post-module-epilog", "mod-4")

    raw_input("press any key")
    tg.server_control("pre-module-prolog", "mod-5")
    test_interface(tg)
    tg.server_control("post-module-epilog", "mod-5")

    tg.server_control("pre-module-prolog", "mod-6")
    test_nat(tg)
    tg.server_control("post-module-epilog", "mod-6")

    tg.server_control("pre-module-prolog", "mod-7")
    test_bgp(tg)
    tg.server_control("post-module-epilog", "mod-7")

    return tg


def test_main2(ipaddr, port=8009):
    for i in range(100):
        print("TRY {}".format(i))
        ports = ["1/{}".format(j + 1) for j in range(0, 16)]
        tg = TGScapyTest(ipaddr, port, ports)
        raw_input("press any key")
        tg.tg_disconnect()
        raw_input("press any key")


def test_ospf(ipaddr, port=8009):
    tg = TGScapyTest(ipaddr, port, ["1/1", "1/2"], False)
    tg_ph_1 = list(tg.tg_port_handle.values())[0]
    h1 = tg.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr="100.1.0.2", gateway="100.1.0.1",
                                arp_send_req='1', control_plane_mtu='9100')
    print(h1)
    ospf_ses = tg.tg_emulation_ospf_config(handle=h1['handle'], mode='create', session_type='ospfv2', router_id='192.0.0.1',
                                           area_id='0.0.0.0', gateway_ip_addr="100.1.0.1", network_type='broadcast', max_mtu='9100')
    print(ospf_ses)
    # IA = tg.tg_emulation_ospf_route_config(mode='create', type='summary_routes', handle=ospf_ses['handle'],
    # summary_number_of_prefix='10', summary_prefix_start='200.1.0.0',
    # summary_prefix_length='24', summary_prefix_metric='10',
    # router_id='192.0.0.1')
    # print("Summary Routes: " + str(IA))
    E1 = tg.tg_emulation_ospf_route_config(mode='create', type='ext_routes', handle=ospf_ses['handle'],
                                           external_number_of_prefix='10', external_prefix_start='202.1.0.0',
                                           external_prefix_length='24', external_prefix_type='1',
                                           router_id='102.1.0.0')
    # print("External Type-1 Routes: " + str(E1))
    # E2 = tg.tg_emulation_ospf_route_config(mode='create', type='ext_routes', handle=ospf_ses['handle'],
    # external_number_of_prefix='10', external_prefix_start='203.1.0.0',
    # external_prefix_length='24', external_prefix_type='2',
    # router_id='103.1.0.0')
    # print("External Type-2 Routes: " + str(E2))

    res = tg.tg_emulation_ospf_control(mode='start', handle=ospf_ses['handle'])
    print(res)
    time.sleep(30)
    # import pdb;pdb.set_trace()
    res = tg.tg_emulation_ospf_control(mode='stop', handle=ospf_ses['handle'])
    print(res)
    # res = tg.tg_emulation_ospf_route_config(mode='delete', handle=IA['handle']);print(res)
    res = tg.tg_emulation_ospf_route_config(mode='delete', handle=E1['handle'])
    print(res)
    # res = tg.tg_emulation_ospf_route_config(mode='delete', handle=E2['handle']);print(res)
    res = tg.tg_emulation_ospf_config(handle=ospf_ses['handle'], mode='delete')
    print(res)

    # import pdb;pdb.set_trace()
    sys.exit(0)


def test_dhcp(ipaddr, port=8009):
    tg = TGScapyTest(ipaddr, port, ["1/1", "1/2"], False)
    (tg_ph_1, tg_ph_2) = list(tg.tg_port_handle.values())

    # DHCP Server Config with switch
    h1 = tg.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr='1.1.1.1', gateway='1.1.1.2',
                                arp_send_req='1', control_plane_mtu='9100', vlan='1', vlan_id='10',
                                resolve_gateway_mac='false')

    dut_mac = '52:54:00:2a:8d:84'
    s_conf = tg.tg_emulation_dhcp_server_config(mode='create', ip_version='4', encapsulation='ETHERNET_II',
                                                ipaddress_count='30', ipaddress_pool='1.1.1.3', handle=h1['handle'],
                                                count='1', local_mac='00:10:95:00:00:01', ip_address='1.1.1.1',
                                                ip_gateway='1.1.1.2', remote_mac=dut_mac, pool_count=1)

    s_con = tg.tg_emulation_dhcp_server_control(action='connect', dhcp_handle=s_conf['dhcp_handle'])
    print("DHCP Server Control: {}".format(s_con))
    # import pdb;pdb.set_trace()

    # DHCP Client Config(Port Based)
    conf = tg.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_1)
    # 'ip_version' is mandatory to configure retry_count
    # conf = tg.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_1, retry_count='11', ip_version='4')
    print("DHCP Client: {}".format(conf))

    group = tg.tg_emulation_dhcp_group_config(handle=conf['handles'], mode='create', encap='ethernet_ii_vlan', vlan_id_count='20',
                                              num_sessions='20', mac_addr='00:10:94:00:00:01', vlan_id=10, vlan_ether_type='0x8100',
                                              dhcp_range_ip_type=4, vlan_id_step=0, gateway_addresses=1)
    print("DHCP Group Config: {}".format(group))

    tg.tg_emulation_dhcp_stats(action='clear', port_handle=tg_ph_1)
    cont = tg.tg_emulation_dhcp_control(port_handle=tg_ph_1, action="bind", handle=group['handle'])
    print("DHCP Client Control: {}".format(cont))
    tg.tg_emulation_dhcp_stats(port_handle=tg_ph_1, handle=conf['handles'], mode='aggregate', ip_version='4')
    # import pdb;pdb.set_trace()

    cont = tg.tg_emulation_dhcp_control(port_handle=tg_ph_1, action="rebind", handle=group['handle'])
    print("DHCP Client Control: {}".format(cont))
    # import pdb;pdb.set_trace()

    cont = tg.tg_emulation_dhcp_control(port_handle=tg_ph_1, action="renew", handle=group['handle'])
    print("DHCP Client Control: {}".format(cont))
    # import pdb;pdb.set_trace()

    cont = tg.tg_emulation_dhcp_control(port_handle=tg_ph_1, action="release", handle=group['handle'])
    print("DHCP Client Control: {}".format(cont))
    # import pdb;pdb.set_trace()

    # tg.tg_emulation_dhcp_stats(port_handle=tg_ph_1, handle=conf['handles'], mode='aggregate', ip_version='4')
    tg.tg_emulation_dhcp_config(mode='reset', handle=conf['handles'], port_handle=tg_ph_1)
    tg.tg_emulation_dhcp_server_config(mode='reset', handle=s_conf['dhcp_handle'], port_handle=tg_ph_2)

    # import pdb;pdb.set_trace()
    sys.exit(0)


def test_dhcpv6(ipaddr, port=8009):
    tg = TGScapyTest(ipaddr, port, ["1/1", "1/2"], False)
    (tg_ph_1, tg_ph_2) = list(tg.tg_port_handle.values())

    # DHCP Server Config with switch
    h1 = tg.tg_interface_config(port_handle=tg_ph_2, ipv6_prefix_length='64', arp_send_req='1', ipv6_intf_addr='2000::2',
                                src_mac_addr='00:0a:01:00:00:01', ipv6_resolve_gateway_mac='false',
                                vlan='1', mode='config', ipv6_gateway='2000::1', vlan_id='10')

    s_conf = tg.tg_emulation_dhcp_server_config(count='1', mac_addr='00:10:94:00:00:04', server_emulation_mode='DHCPV6',
                                                handle=h1['handle'], prefix_pool_per_server='20', addr_pool_addresses_per_server='20',
                                                addr_pool_start_addr='2000::3', prefix_pool_prefix_length='64', mode='create',
                                                prefix_pool_step='1', ip_version='6', encapsulation='ethernet_ii',
                                                addr_pool_step_per_server='1', prefix_pool_start_addr='2000::', addr_pool_prefix_length='64')
    # import pdb;pdb.set_trace()

    s_con = tg.tg_emulation_dhcp_server_control(action='connect', dhcp_handle=s_conf['dhcp_handle'], ip_version='6')
    print("DHCP Server Control: {}".format(s_con))
    # import pdb;pdb.set_trace()

    # DHCP Client Config(Port Based)
    conf = tg.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_1, ip_version='6')
    print("DHCP Client: {}".format(conf))
    # import pdb;pdb.set_trace()

    group = tg.tg_emulation_dhcp_group_config(num_sessions='20', dhcp_range_ip_type='6', handle=conf['handles'],
                                              vlan_id_step=0, vlan_cfi=0, client_mac_addr='00:10:01:00:00:01', mode='create',
                                              encap='ethernet_ii_vlan', dhcp6_client_mode='DHCPV6', vlan_id=10, mac_addr='00:10:94:00:00:05')
    print("DHCP Group Config: {}".format(group))
    # import pdb;pdb.set_trace()

    tg.tg_emulation_dhcp_stats(action='clear', port_handle=tg_ph_1)
    cont = tg.tg_emulation_dhcp_control(port_handle=tg_ph_1, action="bind", handle=group['handle'], ip_version='6')
    print("DHCP Client Control: {}".format(cont))
    # import pdb;pdb.set_trace()

    cont = tg.tg_emulation_dhcp_control(port_handle=tg_ph_1, action="rebind", handle=group['handle'], ip_version='6')
    print("DHCP Client Control: {}".format(cont))

    # import pdb;pdb.set_trace()
    sys.exit(0)


def test_bgp_2(ipaddr, port=8009):
    tg = TGScapyTest(ipaddr, port, ["1/1", "1/2"], False)
    # (tg_ph_1, tg_ph_2) = list(tg.tg_port_handle.values())
    res = tg.tg_interface_config(intf_ip_addr='10.10.10.2', gateway='10.10.10.1', arp_send_req='1', port_handle='port-1', mode='config')
    tg.tg_emulation_bgp_config(handle=res["handle"], local_as=200, active_connect_enable='1', mode='enable', remote_as=100, remote_ip_addr='10.10.10.1')
    tg.tg_emulation_bgp_route_config(handle=res["handle"], prefix='121.1.1.0', num_routes=2, mode='add', as_path='as_seq:1')
    # import pdb;pdb.set_trace()
    tg.tg_emulation_bgp_control(handle=res["handle"], mode="start")


def test_dot1x(ipaddr, port=8009):
    os.environ["SPYTEST_SCAPY_DOT1X_IMPL"] = "2"
    tg = TGScapyTest(ipaddr, port, ["1/1", "1/2"], False)
    tg_ph_1 = list(tg.tg_port_handle.values())[0]
    res1 = tg.tg_emulation_dot1x_config(username='userp11', eap_auth_method='md5', local_ip_addr='192.168.1.10', port_handle=tg_ph_1,
                                        mode='create', gateway_ip_addr='192.168.1.1', ip_version='ipv4', encapsulation='ethernet_ii', password='userp11', mac_addr='00:00:00:A1:A1:A1')
    res2 = tg.tg_emulation_dot1x_config(username='userp12', eap_auth_method='md5', local_ip_addr='192.168.2.10', port_handle=tg_ph_1,
                                        mode='create', gateway_ip_addr='192.168.2.1', ip_version='ipv4', encapsulation='ethernet_ii', password='userp12', mac_addr='00:00:00:A2:A2:A2')
    tg.tg_emulation_dot1x_control(handle=res1["handle"], mode="start")
    tg.tg_emulation_dot1x_control(handle=res2["handle"], mode="start")
    time.sleep(10)
    tg.tg_emulation_dot1x_control(handle=res1["handle"], mode="stop")
    tg.tg_emulation_dot1x_control(handle=res2["handle"], mode="stop")


def test_sample(ipaddr, port=8009):
    # tg = TGScapyTest(ipaddr, port, ["1/1", "1/2"], False)
    tg = TGScapyTest(ipaddr, port, ["1/1"], False)

    # tg.server_control("pre-module-prolog", "mod-0")
    # test_clear(tg)
    # tg.server_control("post-module-epilog", "mod-0")

    # tg.server_control("pre-module-prolog", "mod-2")
    for _ in range(100):
        # test_clear(tg)
        test_single_burst(tg, 20, False)
        raw_input("press any key")
    # tg.server_control("post-module-epilog", "mod-2")
    raw_input("press any key")


if __name__ == '__main__':
    ipaddr = sys.argv[1] if len(sys.argv) > 1 else "10.250.0.188"
    port = sys.argv[2] if len(sys.argv) > 2 else 8009
    test_sample(ipaddr, port)
    sys.exit(0)
    test_dot1x(ipaddr, port)
    sys.exit(0)
    test_dhcpv6(ipaddr, port)
    test_bgp_2(ipaddr, port)
    test_ospf(ipaddr, port)
    test_ospf(ipaddr, port)
    # test_main2(ipaddr, port)
    # tg = test_main(ipaddr, port)
    tg = TGScapyTest(ipaddr, port, ["1/1", "1/2"])
    test_interface(tg)
    raw_input("press any key")
    tg.tg_disconnect()
