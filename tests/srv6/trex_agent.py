import os
import re
import ast
import time
import random
import logging
import pprint
import json
import ipaddress
import pdb
import string
import socket
import datetime
from trex_stl_lib.api import *

# test topology
# |-------------- PTF(MC) --------------|
# |                                     |
# |                                    (0)
# |-  PE1--(1)-- P1 --(6)---P2          |
# |      \    /  |  \    /  |  \        |
# |       \ (2)  |   \ (7)  |  (10)     |
# |        \/   (5)   \/    |    \      |
# |        /\    |    /\    |     PE3 --
# |       / (3)  |   / (8)  |   /
# |      /    \  |  /    \  |  /(11)
# |-  PE2--(4)-- P3--(9)----P4
# ingress PE: PE3
# ingress P : P2, P4
# egress  P  : P1, P3
# egress PE : PE1, PE2
# (0-11) : the ports Trex used to send and recv traffic, plz refer to /etc/trex_cfg.yaml for the real Ports name in PTF docker

logger = logging.getLogger(__name__)

ptf_addr = "172.17.0.3"

def generate_payload(length):
    word = ''
    alphabet_size = len(string.letters)
    for i in range(length):
        word += string.letters[(i % alphabet_size)]
    return word

#create a packet with random frame size
def create_single_ip_pkt_with_dscp_and_random_len(dip = "192.168.0.1", dscp=0, dscp_random = False):
    #no need to fill vlan header, trex will do that for us since we are on the backplane.xxx
    #pkt_base  = Ether(src="00:00:00:00:00:01",dst=r127_mac)/Dot1Q(vlan=100)/IP(dst = dip, tos=(dscp<<2))/UDP(dport=5000,sport=5001)
    l2 = Ether(src="00:00:00:00:00:01")
    l3 = IP(src="0.0.0.1", dst = dip, tos=(dscp<<2))
    l4 = UDP(dport=5000,sport=5001)
    pyld_size = max(0, 1500 - len(l3/l4))
    pkt_pyld  = generate_payload(pyld_size)

    pkt_base  = l2/l3/l4/pkt_pyld

    l3_len_fix =-(len(l2))
    l4_len_fix =-(len(l2/l3))

    # vm
    vm = [ STLVmFlowVar(name="fv_rand", min_value=64, max_value=len(pkt_base), size=2, op="random"),
                           STLVmTrimPktSize("fv_rand"), # total packet size
                           STLVmWrFlowVar(fv_name="fv_rand", pkt_offset= "IP.len", add_val=l3_len_fix) # fix ip len
                           #STLVmFixIpv4(offset = "IP"), # fix checksum
                           #STLVmWrFlowVar(fv_name="fv_rand", pkt_offset= "UDP.len", add_val=l4_len_fix) # fix udp len
        ]

    if dscp_random:
        vm.append(STLVmFlowVar(name="ip_tos", min_value=0, max_value=255, size=1, op="random"))
        vm.append(STLVmWrFlowVar(fv_name="ip_tos",pkt_offset= "IP.tos"))

    vm.append(STLVmFixIpv4(offset = "IP"))
    vm.append(STLVmWrFlowVar(fv_name="fv_rand", pkt_offset= "UDP.len", add_val=l4_len_fix))

    return STLPktBuilder(pkt = pkt_base, vm  = vm)

def create_single_ipv6_pkt_with_dscp_and_random_len(dip = "192:168:1:1::1", dscp=0, dscp_random = False):
    #no need to fill vlan header, trex will do that for us since we are on the backplane.xxx
    #pkt_base  = Ether(src="00:00:00:00:00:01",dst=r127_mac)/Dot1Q(vlan=100)/IP(dst = dip, tos=(dscp<<2))/UDP(dport=5000,sport=5001)
    l2 = Ether(src="00:00:00:00:00:01")
    l3 = IPv6(src = "0::1", dst = dip, tc=(dscp<<2))
    l4 = UDP(dport=5000,sport=5001)
    pyld_size = max(0, 1500 - len(l3/l4))
    pkt_pyld  = generate_payload(pyld_size)

    pkt_base  = l2/l3/l4/pkt_pyld

    l3_len_fix =-(len(l2))
    l4_len_fix =-(len(l2/l3))

    # vm
    vm = [ STLVmFlowVar(name="fv_rand", min_value=96, max_value=len(pkt_base), size=2, op="random"),
                           STLVmTrimPktSize("fv_rand"), # total packet size
                           STLVmWrFlowVar(fv_name="fv_rand", pkt_offset= "IPv6.plen", add_val=l4_len_fix) # fix ipv6 payload len
                           #STLVmFixIpv4(offset = "IP"), # fix checksum
                           #STLVmWrFlowVar(fv_name="fv_rand", pkt_offset= "UDP.len", add_val=l4_len_fix) # fix udp len
        ]

    if dscp_random:
        vm.append(STLVmFlowVar(name="ipv6_tc", min_value=0, max_value=255, size=1, op="random"))
        vm.append(STLVmWrFlowVar(fv_name="ipv6_tc", pkt_offset ="IPv6.tc"))

    vm.append(STLVmWrFlowVar(fv_name="fv_rand", pkt_offset= "UDP.len", add_val=l4_len_fix))

    return STLPktBuilder(pkt = pkt_base, vm  = vm)

#create a packet with random frame size
def create_single_ip_pkt_with_dscp_random(dip = "192.168.0.1", dscp=0, frame_size = 64):
    pkt_base  = Ether(src="00:00:00:00:00:01")/IP(dst = dip, tos=(dscp<<2))/UDP(dport=5000,sport=5001)
    pyld_size = frame_size - len(pkt_base)
    pkt_pyld  = generate_payload(pyld_size)

    vm = [
        # src op="random"
        STLVmFlowVar(name="ip_tos", min_value=0, max_value=255, size=1, op="random"),
        STLVmWrFlowVar(fv_name="ip_tos",pkt_offset= "IP.tos"),
        # optional modify dst
        # STLVmFlowVar(name="dst",min_value=dst['start'],max_value=dst['end'],size=4,op="inc"),
        # STLVmWrFlowVar(fv_name="dst",pkt_offset= "IP.dst"),

        # checksum
        STLVmFixIpv4(offset = "IP")
        ]

    return STLPktBuilder(pkt = pkt_base/pkt_pyld, vm  = vm)
def create_single_ipv6_pkt_with_dscp_random(dip = "192:168:1:1::1", dscp=0, frame_size = 96):

    pkt_base  = Ether(src="00:00:00:00:00:01")/IPv6(dst = dip, tc=(dscp<<2))/UDP(dport=5000,sport=5001)
    pyld_size = frame_size - len(pkt_base)
    pkt_pyld  = generate_payload(pyld_size)

    vm = STLScVmRaw( [ STLVmFlowVar(name="ipv6_tc", min_value=0, max_value=255, size=1, op="random"),
                       STLVmWrFlowVar(fv_name="ipv6_tc", pkt_offset ="IPv6.tc")])

    return STLPktBuilder(pkt = pkt_base/pkt_pyld, vm = vm)
# simple packet creation
# 
def create_ip_pkt_with_dscp(dip = "192.168.0.1", dscp=0, frame_size = 64, dscp_random = False):

    src = {'start': "0.0.0.1", 'end': "255.255.255.254"}
    #no need to fill vlan header, trex will do that for us since we are on the backplane.xxx
    #pkt_base  = Ether(src="00:00:00:00:00:01",dst=r127_mac)/Dot1Q(vlan=100)/IP(dst = dip, tos=(dscp<<2))/UDP(dport=5000,sport=5001)
    pkt_base  = Ether(src="00:00:00:00:00:01")/IP(dst = dip, tos=(dscp<<2))/UDP(dport=5000,sport=5001)
    pyld_size = frame_size - len(pkt_base)
    pkt_pyld  = generate_payload(pyld_size) 

    vm = [
        # src op="random"
        STLVmFlowVar(name="src",min_value=src['start'],max_value=src['end'],size=4,op="random"),
        STLVmWrFlowVar(fv_name="src",pkt_offset= "IP.src"),
        # optional modify dst
        # STLVmFlowVar(name="dst",min_value=dst['start'],max_value=dst['end'],size=4,op="inc"),
        # STLVmWrFlowVar(fv_name="dst",pkt_offset= "IP.dst"),

        # checksum
        STLVmFixIpv4(offset = "IP")
        ]

    if dscp_random:
        vm.insert(0, STLVmFlowVar(name="ip_tos", min_value=0, max_value=255, size=1, op="random"))
        vm.insert(1, STLVmWrFlowVar(fv_name="ip_tos",pkt_offset= "IP.tos"))

    return STLPktBuilder(pkt = pkt_base/pkt_pyld, vm  = vm)

def create_ipv6_pkt_with_dscp(dip = "192:168:1:1::1", dscp=0, frame_size = 96, dscp_random = False):

    #src = {'start': "0.0.0.1", 'end': "0.0.1.254"}
    src = {'start': "0.0.0.1", 'end': "255.255.255.254"}
    pkt_base  = Ether(src="00:00:00:00:00:01")/IPv6(dst = dip, tc=(dscp<<2))/UDP(dport=5000,sport=5001)
    pyld_size = frame_size - len(pkt_base)
    pkt_pyld  = generate_payload(pyld_size) 

    vm = [ STLVmFlowVar(name="ip_src", min_value=src['start'], max_value=src['end'], size=4, op="random"),
            STLVmWrFlowVar(fv_name="ip_src", pkt_offset ="IPv6.src",offset_fixup=12 )]

    if dscp_random:
        vm.append(STLVmFlowVar(name="ipv6_tc", min_value=0, max_value=255, size=1, op="random"))
        vm.append(STLVmWrFlowVar(fv_name="ipv6_tc", pkt_offset ="IPv6.tc"))

    return STLPktBuilder(pkt = pkt_base/pkt_pyld, vm = vm)


def create_ip_in_ip6_pkt(uni, dip = "192.168.0.1", dscp=4, frame_size = 128):

    #src = {'start': "0.0.0.1", 'end': "0.0.40.254"}
    src = {'start': "0.0.0.1", 'end': "255.255.255.254"}
    pkt_base  = Ether(src="00:00:00:00:00:01")/IPv6(dst=uni, nh=4)/IP(dst = dip, tos=(dscp<<2))/UDP(dport=5000,sport=5001)
    pyld_size = frame_size - len(pkt_base)
    pkt_pyld  = generate_payload(pyld_size) 

    vm = [
        # src
        STLVmFlowVar(name="src",min_value=src['start'],max_value=src['end'],size=4,op="random"),
        STLVmWrFlowVar(fv_name="src",pkt_offset= "IP.src"),
        # optional modify dst
        #STLVmFlowVar(name="dst",min_value=dst['start'],max_value=dst['end'],size=4,op="inc"),
        #STLVmWrFlowVar(fv_name="dst",pkt_offset= "IP.dst"),

        # checksum
        STLVmFixIpv4(offset = "IP")
        ]

    return STLPktBuilder(pkt = pkt_base/pkt_pyld, vm  = vm)

def create_ipv6_in_ip6_pkt(uni, dip = "192:168:1:1::1", dscp=0, frame_size = 128):

    #src = {'start': "0.0.0.1", 'end': "0.0.40.254"}
    src = {'start': "0.0.0.1", 'end': "255.255.255.254"}
    pkt_base  = Ether(src="00:00:00:00:00:01")/IPv6(dst = uni, nh=41)/IPv6(dst = dip, tc=(dscp<<2))/UDP(dport=5000,sport=5001)
    pyld_size = frame_size - len(pkt_base)
    pkt_pyld  = generate_payload(pyld_size) 

    vm = STLScVmRaw( [ STLVmFlowVar(name="ip_src", min_value=src['start'], max_value=src['end'], size=4, op="random"),
                       STLVmWrFlowVar(fv_name="ip_src", pkt_offset ="IPv6:1.src",offset_fixup=12 )])

    return STLPktBuilder(pkt = pkt_base/pkt_pyld, vm = vm)

def reset_result(result):
    result['ptf_tot_tx'] = 0
    result['ptf_tot_rx'] = 0
    result['P1_tx_to_PE1'] = 0
    result['P1_tx_to_PE2'] = 0
    result['P3_tx_to_PE1'] = 0
    result['P3_tx_to_PE2'] = 0
    result['P2_tx_to_P1'] = 0
    result['P2_tx_to_P3'] = 0
    result['P4_tx_to_P1'] = 0
    result['P4_tx_to_P3'] = 0
    result['PE3_tx_to_P2'] = 0
    result['PE3_tx_to_P4'] = 0

def trex_do_transmit(dip, dscp = 0, uni = "", duration = 10, single_stream = False, ingress_pe="", dscp_random = False):
    result = {}
    reset_result(result)
    print("trex_do_transmit on dip:{}, dscp:{}, uni:{}".format(dip, dscp, uni))

    c = STLClient(server = ptf_addr)
    c.connect()

    if single_stream == True:
        if "." in dip:
            pkt = create_single_ip_pkt_with_dscp_and_random_len(dip, dscp = dscp, dscp_random = dscp_random)
        else:
            pkt = create_single_ipv6_pkt_with_dscp_and_random_len(dip, dscp = dscp, dscp_random = dscp_random)

    else:
        if uni == "":
            if "." in dip:
                pkt =  create_ip_pkt_with_dscp(dip, dscp = dscp, dscp_random = dscp_random)
            else:
                pkt =  create_ipv6_pkt_with_dscp(dip, dscp = dscp, dscp_random = dscp_random)
        else:
            if "." in dip:
                pkt =  create_ip_in_ip6_pkt(uni, dip, dscp = dscp)
            else:
                pkt =  create_ipv6_in_ip6_pkt(uni, dip, dscp = dscp)

    try:
        stream = STLStream(packet=pkt, mode=STLTXCont(pps=1000))

        my_ports = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
 
        #acquire and reset counter
        c.reset(ports = my_ports)
        in_port = 0

        #add the stream
        c.add_streams(stream, ports = my_ports[in_port])
        c.start(ports=[my_ports[in_port]], duration=duration)

        c.wait_on_traffic()
        #wait some time and get the stats
        time.sleep(2)
 
        #get the stats
        stats = c.get_stats()
        if not stats:
            print("trex_do_transmit stats is empty, retry again")
            time.sleep(3)
            stats = c.get_stats()
            if not stats:
                print("trex_do_transmit stats is empty !!")

        #print("trex_do_transmit stats:{}".format(stats))

        #stats example on port
    # 0: {
	# 	'tx_util': 0.0098748502734375,
	# 	'rx_bps': 0.0,
	# 	'obytes': 1040104,
	# 	'rx_pps': 0.0,
	# 	'ipackets': 0,
	# 	'oerrors': 0,
	# 	'rx_util': 0.0,
	# 	'opackets': 10001,
	# 	'tx_pps': 995.4486083984375,
	# 	'tx_bps': 828213.25,
	# 	'ierrors': 0,
	# 	'rx_bps_L1': 0,
	# 	'tx_bps_L1': 987485.0273437499,
	# 	'ibytes': 0
	# },
        if 0 in stats:
            result["ptf_tot_rx"] = int(stats[0]["ipackets"])
            if in_port == 0:
                result["ptf_tot_tx"] = int(stats[0]["opackets"])
        if 1 in stats:
            result['P1_tx_to_PE1'] = int(stats[1]["ipackets"])
        if 2 in stats:
            result['P1_tx_to_PE2'] = int(stats[2]["ipackets"])
        if 3 in stats:
            result['P3_tx_to_PE1'] = int(stats[3]["ipackets"])
        if 4 in stats:
            result['P3_tx_to_PE2'] = int(stats[4]["ipackets"])

        if 6 in stats:
            result['P2_tx_to_P1'] = int(stats[6]["ipackets"])
        if 7 in stats:
            result['P2_tx_to_P3'] = int(stats[7]["ipackets"])
        if 8 in stats:
            result['P4_tx_to_P1'] = int(stats[8]["ipackets"])
        if 9 in stats:
            result['P4_tx_to_P3'] = int(stats[9]["ipackets"])
        if 10 in stats:
            result['PE3_tx_to_P2'] = int(stats[10]["ipackets"])
        if 11 in stats:
            result['PE3_tx_to_P4'] = int(stats[11]["ipackets"])

        c.clear_stats(ports = my_ports)       
    except Exception as e:
        err_str = "trex_do_transmit exp Error: %s" % e
        print(err_str)
    finally:
        c.disconnect()
        print("trex_do_transmit result:{}".format(result))
        return result

def trex_start_transmit(dip, dscp = 0, uni = "", single_stream = False, ingress_pe="", dscp_random = False):
    # result = {}
    # reset_result(result)
    print("trex_start_transmit on dip:{}, dscp:{}, uni:{}".format(dip, dscp, uni))
    c = STLClient(server = ptf_addr)
    c.connect()

    if single_stream == True:
        if "." in dip:
            pkt = create_single_ip_pkt_with_dscp_and_random_len(dip, dscp = dscp, dscp_random = dscp_random)
        else:
            pkt = create_single_ipv6_pkt_with_dscp_and_random_len(dip, dscp = dscp, dscp_random = dscp_random)

    else:
        if uni == "":
            if "." in dip:
                pkt = create_ip_pkt_with_dscp(dip, dscp = dscp, dscp_random = dscp_random)
            else:
                pkt = create_ipv6_pkt_with_dscp(dip, dscp = dscp, dscp_random = dscp_random)
        else:
            if "." in dip:
                pkt =  create_ip_in_ip6_pkt(uni, dip, dscp = dscp)
            else:
                pkt =  create_ipv6_in_ip6_pkt(uni, dip, dscp = dscp)

    try:
        stream = STLStream(packet=pkt, mode=STLTXCont(pps=1000))

        my_ports = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        #acquire and reset counter
        c.reset(ports = my_ports)
 
        in_port = 0

        #add the stream
        c.add_streams(stream, ports = my_ports[in_port])
        c.start(ports=[my_ports[in_port]])

        return c
    except Exception as e:
        err_str = "trex_start_transmit exp Error: %s" % e
        print(err_str)
        return None

def trex_stop_transmit(conn, dip = "", dscp = 0, uni = "", ingress_pe=""):
    result = {}
    reset_result(result)
    print("trex_stop_transmit in")

    try:
        conn.stop()

        time.sleep(2)
        #get the stats
        stats = conn.get_stats()
        if not stats:
            print("trex_stop_transmit stats is empty, retry again")
            time.sleep(3)
            stats = conn.get_stats()
            if not stats:
                print("trex_stop_transmit stats is empty !!")
        #print("trex_stop_transmit stats:{}".format(stats))
        #stats example on port
    # 0: {
	# 	'tx_util': 0.0098748502734375,
	# 	'rx_bps': 0.0,
	# 	'obytes': 1040104,
	# 	'rx_pps': 0.0,
	# 	'ipackets': 0,
	# 	'oerrors': 0,
	# 	'rx_util': 0.0,
	# 	'opackets': 10001,
	# 	'tx_pps': 995.4486083984375,
	# 	'tx_bps': 828213.25,
	# 	'ierrors': 0,
	# 	'rx_bps_L1': 0,
	# 	'tx_bps_L1': 987485.0273437499,
	# 	'ibytes': 0
	# },

        in_port = 0

        if 0 in stats:
            result["ptf_tot_rx"] = int(stats[0]["ipackets"])
            if in_port == 0:
                result["ptf_tot_tx"] = int(stats[0]["opackets"])
        if 1 in stats:
            result['P1_tx_to_PE1'] = int(stats[1]["ipackets"])
        if 2 in stats:
            result['P1_tx_to_PE2'] = int(stats[2]["ipackets"])
        if 3 in stats:
            result['P3_tx_to_PE1'] = int(stats[3]["ipackets"])
        if 4 in stats:
            result['P3_tx_to_PE2'] = int(stats[4]["ipackets"])

        if 6 in stats:
            result['P2_tx_to_P1'] = int(stats[6]["ipackets"])
        if 7 in stats:
            result['P2_tx_to_P3'] = int(stats[7]["ipackets"])
        if 8 in stats:
            result['P4_tx_to_P1'] = int(stats[8]["ipackets"])
        if 9 in stats:
            result['P4_tx_to_P3'] = int(stats[9]["ipackets"])
        if 10 in stats:
            result['PE3_tx_to_P2'] = int(stats[10]["ipackets"])
        if 11 in stats:
            result['PE3_tx_to_P4'] = int(stats[11]["ipackets"])

        conn.clear_stats()     
    except Exception as e:
        err_str = "trex_stop_transmit exp Error: %s" % e
        print(err_str)
    finally:
        conn.disconnect()
        print("trex_stop_transmit result:{}".format(result))
        return result

#cmd demo: {'cmd': 'start/stop/run', 'dip': '192.168.0.1', 'dscp': 2, 'uni': 'fd00:202:203a:fff0:22::', 'duration': 10, 'single_stream': True}
def process_trex_cmd(data, ctx):
    result = {}
    reset_result(result)

    try:
        if "cmd" not in data:
            print("error, request format error")
            return result
        if data["cmd"] != "start" and data["cmd"] != "stop" and data["cmd"] != "run":
            print("error, unsupported cmd:{}".format(data["cmd"]))
            return result
        
        trex_conn = None
        if "trex_conn" in ctx:
            trex_conn = ctx["trex_conn"]

        if trex_conn:
            if data["cmd"] == "start" or data["cmd"] == "run":
                print("error, a transmit is running")
                return result
        else:
            if data["cmd"] == "stop":
                print("error, no transmit is running")
                return result
        
        #get all test data
        dip = data["dip"]
        dscp = 0
        if "dscp" in data:
            dscp = data["dscp"]
        uni = ""
        if "uni" in data:
            uni = data["uni"]
        duration = 10
        if "duration" in data:
            duration = data["duration"]

        single_stream = False
        if "single_stream" in data:
            single_stream = True

        ingress_pe = ""
        if "ingress_pe" in data:
            duration = data["ingress_pe"]

        dscp_random = False
        if "dscp_random" in data:
            dscp_random = True

        if data["cmd"] == "start":
            trex_conn = trex_start_transmit(dip = dip, dscp = dscp, uni = uni, single_stream = single_stream, ingress_pe = ingress_pe, dscp_random = dscp_random)
            ctx["trex_conn"] = trex_conn
            ctx["ingress_pe"] = ingress_pe
        if data["cmd"] == "stop":
            if ingress_pe == "" and "ingress_pe" in ctx:
                ingress_pe = ctx["ingress_pe"]
            result = trex_stop_transmit(trex_conn, dip = dip, dscp = dscp, uni = uni, ingress_pe = ingress_pe)
            del ctx["trex_conn"]
            del ctx["ingress_pe"]
        if data["cmd"] == "run":
            result = trex_do_transmit(dip = dip, dscp = dscp, uni = uni, duration = duration, single_stream = single_stream, ingress_pe = ingress_pe, dscp_random = dscp_random)

    except Exception as e:
        err_str = "process_trex_cmd exp: %s" % e
        print(err_str)

    return result
def main():
    #result = trex_do_transmit(dip = '192.168.0.1', dscp = 2, uni = "fd00:202:203a:fff0:22::")
    #print(result)
    ctx = {}
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 54500))
    server_socket.listen(5)
    while True:
        client_socket = None
        try:
            client_socket, addr = server_socket.accept()
            current_time = datetime.datetime.now()
            print("new conn from:{}, at:{}".format(addr, current_time))

            #wait 5 seconds maximum to receive data
            client_socket.settimeout(5.0)
            data = client_socket.recv(1024)
            if not data:
                client_socket.close()
                client_socket = None
                continue

            json_data = json.loads(data)
            print("conn recv request:{}".format(json_data))
            result = process_trex_cmd(json_data, ctx)
            current_time = datetime.datetime.now()
            print("process request result:{}, at:{}".format(result, current_time))

            client_socket.send(json.dumps(result))
        except Exception as e:
            err_str = "socket Error: %s" % e
            print(err_str)

        if client_socket:
            client_socket.close()


if __name__ == "__main__":
    main()