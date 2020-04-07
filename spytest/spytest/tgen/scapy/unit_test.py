import os
import sys
import json
import time
import logging

from spytest.dicts import SpyTestDict
from spytest.tgen.tg_scapy import ScapyClient
import utilities.common as utils

class TGScapyTest(ScapyClient):
    def __init__(self, tg_ip=None, tg_port=8009, tg_port_list=None):
        self.tg_ip = tg_ip
        self.tg_port_list = tg_port_list
        self.tg_port_handle = SpyTestDict()
        ScapyClient.__init__(self, None, tg_port)
        #self.scapy_connect()
        self.scapy_connect(True)

    def log_call(self, fname, **kwargs):
        pass

    def save_log(self, name, data):
        utils.write_file(os.path.join("client", name), data)

def test_clear(tg):
    port_list = tg.tg_port_handle.values()
    tg.tg_traffic_control(action="reset",port_handle=port_list)
    tg.tg_traffic_control(action="clear_stats",port_handle=port_list)
    for tg_ph in port_list:
        tx_stats = tg.tg_traffic_stats(port_handle=tg_ph,mode="aggregate")
        print ("TX-STATS", json.dumps(tx_stats))
        rx_stats = tg.tg_traffic_stats(port_handle=tg_ph,mode="aggregate")
        print ("RX-STATS", json.dumps(rx_stats))

def test_single_burst(tg):
    print("============= test_single_burst ==============")
    (tg_ph_1, tg_ph_2) = tg.tg_port_handle.values()
    tg.tg_traffic_config(mac_src = '00.00.00.00.10.01',mac_dst='00.00.00.00.10.02',rate_pps='2',mode='create',\
       port_handle=tg_ph_1,transmit_mode='single_burst', pkts_per_burst=10, frame_size=64)
    tg.tg_traffic_control(action='run',port_handle=tg_ph_1)
    time.sleep(2)
    tx_stats = tg.tg_traffic_stats(port_handle=tg_ph_1,mode="aggregate")
    print (tx_stats)

def test_untagged(tg, count=2):
    print("============= test_untagged ==============")
    (tg_ph_1, tg_ph_2) = tg.tg_port_handle.values()
    res = tg.tg_traffic_config(mac_src = '00.00.10.00.00.02',mac_dst='00.00.10.00.00.01',
            rate_pps=count,mode='create', mac_src_mode="increment", \
            mac_src_count=20, mac_src_step="00:00:00:00:00:01",
            port_handle=tg_ph_1,transmit_mode='continuous', frame_size='128')
    tg.tg_traffic_control(action='run',handle=res.stream_id,duration=20)
    time.sleep(2)
    tg.tg_traffic_control(action='stop',port_handle=tg_ph_1)
    tx_stats = tg.tg_traffic_stats(port_handle=tg_ph_1,mode="aggregate")
    print ("TX-STATS", json.dumps(tx_stats))
    rx_stats = tg.tg_traffic_stats(port_handle=tg_ph_2,mode="aggregate")
    print ("RX-STATS", json.dumps(rx_stats))

def test_tagged(tg, count=2):
    print("============= test_tagged ==============")
    (tg_ph_1, tg_ph_2) = tg.tg_port_handle.values()
    tg.tg_traffic_config(mac_src = '00.00.00.00.00.01',mac_dst='00.00.00.00.00.02',rate_pps=count,mode='create',\
       port_handle=tg_ph_1,transmit_mode='continuous',l2_encap='ethernet_ii_vlan',vlan_id='10', frame_size='256', vlan="enable")
    tg.tg_traffic_control(action='run',port_handle=tg_ph_1,duration=2)
    time.sleep(5)
    tg.tg_traffic_control(action='stop',port_handle=tg_ph_1)
    tx_stats = tg.tg_traffic_stats(port_handle=tg_ph_1,mode="aggregate")
    print ("TX-STATS", json.dumps(tx_stats))
    rx_stats = tg.tg_traffic_stats(port_handle=tg_ph_2,mode="aggregate")
    print ("RX-STATS", json.dumps(rx_stats))

def test_capture(tg):
    print("============= test_capture ==============")
    (tg_ph_1, tg_ph_2) = tg.tg_port_handle.values()
    tg.tg_traffic_config(mac_src = '00.00.00.00.10.01',mac_dst='00.00.00.00.10.02',rate_pps='2',mode='create',\
       port_handle=tg_ph_1,transmit_mode='single_burst', pkts_per_burst=10, frame_size=64)
    tg.tg_packet_control(port_handle=tg_ph_2,action='start')
    tg.tg_traffic_control(action='run',port_handle=tg_ph_1)
    time.sleep(5)
    tg.tg_traffic_control(action='stop',port_handle=tg_ph_1)
    tx_stats = tg.tg_traffic_stats(port_handle=tg_ph_2,mode="aggregate")
    print (tx_stats)
    totPackets = tg.tg_packet_control(port_handle=tg_ph_2,action='stop')
    print (totPackets)
    packet_dict = tg.tg_packet_stats(port_handle=tg_ph_2,format='var')
    print (packet_dict)

def test_interface(tg):
    print("============= test_interface ==============")
    (tg_ph_1, tg_ph_2) = tg.tg_port_handle.values()
    res1 = tg.tg_interface_config(port_handle=tg_ph_1, mode='config', arp_send_req='1', \
             intf_ip_addr='21.1.1.100', gateway='21.1.1.1', src_mac_addr='00:0a:01:01:00:01')
    tg.tg_interface_config(port_handle=tg_ph_1, handle=res1['handle'], mode='destroy')
    res2 = tg.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='12.12.0.2',
                                         gateway='12.12.0.1', netmask='255.255.0.0', vlan='1',
                                         vlan_id=10, vlan_id_step=0, arp_send_req='1',
                                         gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count='1')
    print(res2)
    res = tg.tg_interface_config(protocol_handle=res2["handle"], send_ping='1', ping_dst='12.12.0.1')
    print("PING_RES: "+str(res))
    tg.tg_interface_config(port_handle=tg_ph_1, handle=res2['handle'], mode='destroy')

def test_nat(tg):
    tg.tg_interface_config(count=1,arp_send_req=1,intf_ip_addr="12.12.0.2",port_handle="port-1/1",netmask="255.255.0.0",mode="config",gateway_step="0.0.0.0",gateway="12.12.0.1")
    tg.tg_interface_config(count=1,arp_send_req=1,intf_ip_addr="125.56.90.1",port_handle="port-1/2",netmask="255.255.255.0",mode="config",gateway_step="0.0.0.0",gateway="125.56.90.12")
    mac_src = "00:00:23:11:14:08"
    mac_src = "e2:8d:ab:ee:fb:6c"
    mac_src2 = raw_input()
    if mac_src2: mac_src = mac_src2
    res = tg.tg_traffic_config(mac_src=mac_src,mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="129.2.30.12",
                pkts_per_burst=1,ip_src_addr="12.12.0.2",port_handle="port-1/1",transmit_mode="single_burst",
                rate_pps=10,mode="create",l3_protocol="ipv4")
    tg.tg_traffic_control(action="run",handle=res["stream_id"])

def test_nat0(tg):
    tg.tg_traffic_control(action="reset",port_handle=['port-1/2', 'port-1/1'])
    tg.tg_traffic_control(action="clear_stats",port_handle=['port-1/2', 'port-1/1'])
    tg.tg_interface_config(count=10,arp_send_req=1,intf_ip_addr="12.12.0.2",port_handle="port-1/1",netmask="255.255.0.0",mode="config",gateway_step="0.0.0.0",gateway="12.12.0.1")
    tg.tg_interface_config(count=10,arp_send_req=1,intf_ip_addr="125.56.90.1",port_handle="port-1/2",netmask="255.255.255.0",mode="config",gateway_step="0.0.0.0",gateway="125.56.90.12")
    tg.tg_traffic_config(mac_src="00:00:23:11:14:08",mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="129.2.30.12",pkts_per_burst=10,ip_src_addr="12.12.0.2",port_handle="port-1/1",transmit_mode="single_burst",rate_pps=10,mode="create",l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:23:11:14:08",l4_protocol="tcp",tcp_src_port=1002,mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="129.2.30.12",pkts_per_burst=10,ip_src_addr="12.12.0.3",port_handle="port-1/1",transmit_mode="single_burst",rate_pps=10,mode="create",tcp_dst_port=3345,l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:23:11:14:08",mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="129.2.30.12",pkts_per_burst=10,ip_src_addr="88.98.128.2",port_handle="port-1/1",transmit_mode="single_burst",rate_pps=10,mode="create",l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:23:11:14:08",l4_protocol="udp",udp_src_port=7781,mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="129.2.30.12",pkts_per_burst=10,ip_src_addr="12.12.0.4",port_handle="port-1/1",transmit_mode="single_burst",rate_pps=10,mode="create",l3_protocol="ipv4",udp_dst_port=8812)
    tg.tg_traffic_config(mac_src="00:00:23:11:14:08",mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="15.15.0.1",pkts_per_burst=10,ip_src_addr="12.12.0.5",port_handle="port-1/1",transmit_mode="single_burst",rate_pps=10,mode="create",l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:23:11:14:08",l4_protocol="udp",udp_src_port=251,mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="129.2.30.12",pkts_per_burst=10,ip_src_addr="12.12.0.11",port_handle="port-1/1",transmit_mode="single_burst",rate_pps=10,mode="create",l3_protocol="ipv4",udp_dst_port=444)
    tg.tg_traffic_config(mac_src="00:00:43:32:1A",mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="125.56.90.12",pkts_per_burst=10,ip_src_addr="129.2.30.12",port_handle="port-1/2",transmit_mode="single_burst",rate_pps=10,mode="create",l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:43:32:1A",l4_protocol="tcp",tcp_src_port=345,mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="125.56.90.13",pkts_per_burst=10,ip_src_addr="129.2.30.12",port_handle="port-1/2",transmit_mode="single_burst",rate_pps=10,mode="create",tcp_dst_port=100,l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:43:32:1A",mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="11.11.11.2",pkts_per_burst=10,ip_src_addr="129.2.30.12",port_handle="port-1/2",transmit_mode="single_burst",rate_pps=10,mode="create",l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:43:32:1A",l4_protocol="udp",udp_src_port=5516,mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="125.56.90.14",pkts_per_burst=10,ip_src_addr="129.2.30.12",port_handle="port-1/2",transmit_mode="single_burst",rate_pps=10,mode="create",l3_protocol="ipv4",udp_dst_port=7811)
    tg.tg_traffic_config(mac_src="00:00:43:32:1A",mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="125.56.90.15",pkts_per_burst=10,ip_src_addr="99.99.99.1",port_handle="port-1/2",transmit_mode="single_burst",rate_pps=10,mode="create",l3_protocol="ipv4")
    tg.tg_traffic_config(mac_src="00:00:43:32:1A",l4_protocol="udp",udp_src_port=12001,mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="125.56.90.23",pkts_per_burst=10,ip_src_addr="129.2.30.12",port_handle="port-1/2",transmit_mode="single_burst",rate_pps=10,mode="create",l3_protocol="ipv4",udp_dst_port=333)
    tg.tg_traffic_config(mac_src="00:00:43:32:1A",l4_protocol="udp",udp_src_port=12001,mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="125.56.90.23",pkts_per_burst=10,ip_src_addr="129.2.30.12",port_handle="port-1/2",transmit_mode="single_burst",rate_pps=10,mode="create",l3_protocol="ipv4",udp_dst_port=334)
    tg.tg_traffic_config(mac_src="00:00:43:32:1A",l4_protocol="udp",udp_src_port=12001,mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="125.56.90.24",pkts_per_burst=10,ip_src_addr="129.2.30.12",port_handle="port-1/2",transmit_mode="single_burst",rate_pps=10,mode="create",l3_protocol="ipv4",udp_dst_port=333)
    tg.tg_traffic_config(mac_src="00:00:43:32:1A",l4_protocol="udp",udp_src_port=12001,mac_dst="80:a2:35:26:0a:5e",ip_dst_addr="125.56.90.24",pkts_per_burst=10,ip_src_addr="129.2.30.12",port_handle="port-1/2",transmit_mode="single_burst",rate_pps=10,mode="create",l3_protocol="ipv4",udp_dst_port=334)
    tg.tg_traffic_control(action="run",handle="stream-1/1-0")
    tg.tg_traffic_control(action="run",handle="stream-1/1-2")
    tg.tg_traffic_control(action="run",handle="stream-1/2-2")
    tg.tg_traffic_control(action="run",handle="stream-1/1-1")
    tg.tg_traffic_control(action="stop",port_handle="port-1/1")
    tg.tg_traffic_control(action="run",handle="stream-1/2-1")
    tg.tg_traffic_control(action="stop",port_handle="port-1/2")

def test_bgp(tg):
    res = tg.tg_interface_config(arp_send_req='1',intf_ip_addr='193.1.1.2',port_handle='port-1/1',netmask='255.255.255.0',mode='config',gateway='193.1.1.1', count=2)
    #tg_interface_config(ipv6_prefix_length='64',arp_send_req='1',ipv6_intf_addr='1093:1:1::2',port_handle='port-1/5',mode='config',ipv6_gateway='1093:1:1::1')
    tg.tg_emulation_bgp_config(handle=res["handle"],local_as=63001,active_connect_enable='1',mode='enable',remote_as=650002,enable_4_byte_as='1',remote_ip_addr='193.1.1.1')

def test_emulated(tg):
    (tg_ph_1, tg_ph_2) = tg.tg_port_handle.values()
    tg.tg_traffic_config(**{'ip_src_count': 1, 'mac_src': '00:0a:01:00:11:01', 'l3_length': '500', 'length_mode': 'fixed', 'mac_dst': '00:00:00:00:00:00', 'port_handle': 'port-1/1', 'ip_src_addr': '192.168.13.2', 'transmit_mode': 'continuous', 'rate_pps': '1000', 'mode': 'create', 'l3_protocol': 'ipv4'})
    tg.tg_traffic_control(action='run',port_handle=tg_ph_1)

def test_main(ipaddr, port=8009):
    logging.basicConfig()
    tg = TGScapyTest(ipaddr, port, ["1/1", "1/2"])
    (tg_ph_1, tg_ph_2) = tg.tg_port_handle.values()

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

if __name__ == '__main__':
    ipaddr = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = sys.argv[2] if len(sys.argv) > 2 else 8009
    tg = test_main(ipaddr, port)
    raw_input("press any key")
    tg.tg_disconnect()

