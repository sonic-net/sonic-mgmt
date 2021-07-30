import os
import re
import sys
import zlib
import time
import copy
import random
import textwrap
import binascii
import socket
import afpacket
import traceback
import ipaddress

from scapy.all import hexdump, L2Socket, sendp
from scapy.packet import Padding
from scapy.layers.l2 import Ether, Dot1Q, ARP
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NA
from scapy.contrib.igmp import IGMP
from scapy.config import Conf
from dicts import SpyTestDict
from utils import Utils
from logger import Logger

try: print("SCAPY VERSION = {}".format(Conf().version))
except Exception: print("SCAPY VERSION = UNKNOWN")

if sys.version_info[0] >= 3:
    unicode = str

this_dir = os.path.join(os.path.dirname(__file__))

#dbg > 1 --- recv/send packet
#dbg > 2 --- recv/send packet summary
#dbg > 3 --- recv/send packet hex

stale_list_ignore = [
    "port_handle",
    "port_handle2",
    "stream_id",
    "mode",
    "rate_percent", #TODO

    #
    "circuit_endpoint_type",
    "enable_stream",
    "enable_stream_only_gen",
    #

    # filtered stats
    "high_speed_result_analysis", #TODO
    "vlan_id_tracking",
    "ip_dscp_tracking",
    "track_by",
    # filtered stats

    "ip_protocol", #TODO

    "vlan_id",
    "vlan_id_mode",
    "vlan_id_step",
    "vlan_id_count",

    "mac_src",
    "mac_src_mode",
    "mac_src_step",
    "mac_src_count",
    "mac_dst",
    "mac_dst_mode",
    "mac_dst_step",
    "mac_dst_count",

    # not needed
    "mac_discovery_gw",

    "udp_src_port",
    "udp_src_port_mode",
    "udp_src_port_step",
    "udp_src_port_count",
    "udp_dst_port",
    "udp_dst_port_mode",
    "udp_dst_port_step",
    "udp_dst_port_count",

    "tcp_src_port",
    "tcp_src_port_mode",
    "tcp_src_port_step",
    "tcp_src_port_count",
    "tcp_dst_port",
    "tcp_dst_port_mode",
    "tcp_dst_port_step",
    "tcp_dst_port_count",

    "arp_src_hw_addr",
    "arp_src_hw_mode",
    "arp_src_hw_step",
    "arp_src_hw_count",
    "arp_dst_hw_addr",
    "arp_dst_hw_mode",
    "arp_dst_hw_step",
    "arp_dst_hw_count",

    "ip_src_addr",
    "ip_src_mode",
    "ip_src_step",
    "ip_src_count",
    "ip_dst_addr",
    "ip_dst_mode",
    "ip_dst_step",
    "ip_dst_count",

    "ipv6_src_addr",
    "ipv6_src_mode",
    "ipv6_src_step",
    "ipv6_src_count",
    "ipv6_dst_addr",
    "ipv6_dst_mode",
    "ipv6_dst_step",
    "ipv6_dst_count",
]

class ScapyPacket(object):

    def __init__(self, iface, dbg=0, dry=False, hex=False, logger=None):
        self.dry = dry
        self.errs = []
        self.logger = logger or Logger(dry)
        try: self.logger.info("SCAPY VERSION = {}".format(Conf().version))
        except Exception: self.logger.info("SCAPY VERSION = UNKNOWN")
        self.utils = Utils(self.dry, logger=self.logger)
        self.max_rate_pps = self.utils.get_env_int("SPYTEST_SCAPY_MAX_RATE_PPS", 100)
        self.dbg = dbg
        self.show_summary = bool(self.dbg > 2)
        self.hex = hex
        self.iface = iface
        self.is_vde = not dry and iface.startswith("vde")
        self.tx_count = 0
        self.rx_count = 0
        self.rx_sock = None
        self.tx_sock = None
        self.finished = False
        self.exabgp_nslist = []
        self.cleanup()
        self.mtu = 9194
        if iface and not self.dry:
            #already init_bridge called in cleanup()
            #self.init_bridge(iface)
            bridge = "{0}-br".format(iface)
            self.os_system("ip link add name {0} type bridge".format(bridge))
            self.os_system("ip link set dev {1} master {0}".format(bridge, iface))
            # let bridge proxy arp packets
            #self.os_system("echo 1 > /proc/sys/net/ipv4/conf/{0}-br/proxy_arp".format(iface))
            self.os_system("ip link set dev {0}-br up".format(iface))
            self.os_system("ip link set dev {0} up".format(iface))
            self.os_system("ip link set dev {0} promisc on".format(iface))
            self.os_system("ip link set dev {0} mtu {1}".format(iface, self.mtu))
            self.os_system("ip link set dev {0}-br mtu {1}".format(iface, self.mtu))
            self.os_system("echo 0 > /sys/class/net/{0}-br/bridge/multicast_snooping".format(iface))
            #self.os_system("ip link del {0}-rx".format(iface))
            self.os_system("ip link add {0}-rx type dummy".format(iface))
            self.os_system("ip link set dev {0}-rx mtu {1}".format(iface, self.mtu))
            self.configure_ipv6(iface)
            self.os_system("tc qdisc del dev {0} ingress".format(iface))
            self.os_system("tc qdisc add dev {0} ingress".format(iface))
            #self.os_system("tc filter del dev {0} parent ffff: protocol all u32 match u8 0 0 action mirred egress mirror dev {0}-rx".format(iface))
            self.os_system("tc filter add dev {0} parent ffff: protocol all u32 match u8 0 0 action mirred egress mirror dev {0}-rx".format(iface))
            self.os_system("ip link set {0}-rx up".format(iface))
            if self.dbg > 5:
                self.os_system("ifconfig")
        self.rx_open()

    def os_system(self, cmd):
        self.logger.info("EXEC: {}".format(cmd))
        return self.utils.exec_cmd(cmd)

    def init_bridge(self, iface):
        if iface and not self.dry:
            bridge = "{0}-br".format(iface)
            self.os_system("ip link set dev {0} down".format(bridge))
            self.os_system("ip link set dev {0} nomaster".format(iface))
            self.os_system("ip link del {0}".format(bridge))
            self.os_system("ip link del {0}-rx".format(iface))
            time.sleep(1)

    def configure_ipv6(self, iface):
        iface_rx = "{0}-rx".format(iface)
        self.os_system("sysctl -w net.ipv6.conf.{}.forwarding=0".format(iface_rx))
        self.os_system("sysctl -w net.ipv6.conf.{}.accept_ra=0".format(iface_rx))
        self.os_system("sysctl -w net.ipv6.conf.{}.forwarding=1".format(iface))
        #self.os_system("sysctl -w net.ipv6.conf.{}.accept_ra=1".format(iface))
        self.os_system("sysctl -w net.ipv6.conf.all.forwarding=0")

    def __del__(self):
        self.logger.info("packet cleanup todo: ", self.iface)
        self.cleanup()

    def error(self, *args, **kwargs):
        msg = self.logger.error(*args, **kwargs)
        self.errs.append(msg)
        return msg

    def banner(self, *args, **kwargs):
        msg = self.logger.banner(*args, **kwargs)
        self.errs.append(msg)
        return msg

    def get_alerts(self):
        errs = []
        errs.extend(self.errs)
        self.errs = []
        return errs

    def clear_stats(self):
        self.tx_count = 0
        self.rx_count = 0

    def close_sock(self, sock):
        try: sock.close()
        except Exception: pass
        return None

    def cleanup(self):
        print("ScapyPacket {} cleanup...".format(self.iface))
        self.logger.info("ScapyPacket {} cleanup...".format(self.iface))
        self.exabgpd_stop_all()
        self.finished = True
        self.rx_sock = self.close_sock(self.rx_sock)
        self.tx_sock = self.close_sock(self.tx_sock)
        self.init_bridge(self.iface)
        self.finished = False

    def rx_open(self):
        if not self.iface or self.dry: return
        ETH_P_ALL = 3
        self.rx_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 12 * 1024)
        self.rx_sock.bind((self.iface+"-rx", 3))
        afpacket.enable_auxdata(self.rx_sock)

    def set_link(self, status):
        msg = "link:{} status:{}".format
        self.logger.debug(msg(iface, status))

    def readp(self, iface):

        if self.dry:
            time.sleep(2)
            return None

        if not self.iface:
            return None

        try:
            data = afpacket.recv(self.rx_sock, 12 * 1024)
        except Exception as exp:
            if self.finished:
                return None
            raise exp
        packet = Ether(data)
        self.rx_count = self.rx_count + 1
        self.trace_stats()

        if self.dbg > 1:
            cmd = "" if not self.show_summary else packet.command()
            msg = "readp:{} len:{} count:{} {}".format
            self.logger.debug(msg(iface, len(data), self.rx_count, cmd))

        if self.dbg > 2:
            self.trace_packet(packet, self.hex)

        return packet

    def sendp(self, pkt, data, iface, stream_name, left):
        self.tx_count = self.tx_count + 1
        self.trace_stats()

        if self.dbg > 2 or (self.dbg > 1 and left != 0):
            cmd = "" if not self.show_summary else pkt.command()
            msg = "sendp:{}:{} len:{} count:{} {}".format
            self.logger.debug(msg(iface, stream_name, len(data), self.tx_count, cmd))

        if self.dbg > 2:
            self.trace_packet(pkt, self.hex)

        if not self.dry:
            if not self.tx_sock:
                try:
                    self.tx_sock = L2Socket(iface)
                except Exception as exp:
                    self.logger.debug("Failed to create L2Socket {} {}".format(iface, exp))

            if self.tx_sock:
                try: return self.tx_sock.send(data)
                except Exception: pass
            try:
                sendp(data, iface=iface, verbose=False)
            except Exception as exp:
                self.logger.debug("Failed to send legacy {} {}".format(iface, exp))
                if self.is_vde: self.os_system("ip link set dev {0} up".format(iface))

    def trace_stats(self):
        #self.logger.debug("Name: {} RX: {} TX: {}".format(self.iface, self.rx_count, self.tx_count))
        pass

    def show_pkt(self, pkt):
        if self.dbg > 4:
            return self.utils.exec_func(pkt.show2)
        if self.dbg > 3:
            return self.utils.exec_func(pkt.summary)
        return ""

    def trace_packet(self, pkt, hex=True, fields=True):
        if not fields and not hex: return
        if isinstance(pkt, str): pkt = Ether(pkt)
        if fields: self.show_pkt(pkt)
        if hex: hexdump(pkt)

    def send_packet(self, pwa, iface, stream_name, left):
        if pwa.padding:
            strpkt = str(pwa.pkt/pwa.padding)
        else:
            strpkt = str(pwa.pkt)

        # insert stream id before CRC
        if pwa.add_signature:
            sid = pwa.stream.get_sid()
            if not sid: sid = "DeadBeef"
            if sid: strpkt = strpkt[:-len(sid)] + sid

        pkt_bytes = self.utils.tobytes(strpkt)
        try:
            crc1 = '{:08x}'.format(socket.htonl(zlib.crc32(pkt_bytes) & 0xFFFFFFFF))
            crc = binascii.unhexlify(crc1)
        except Exception:
            crc = binascii.unhexlify('00' * 4)
        bstr = bytes(strpkt+crc)
        self.sendp(pwa.pkt, bstr, iface, stream_name, left)
        return bstr

    def check(self, pkt):
        pkt.do_build()
        if self.dbg > 3:
            self.show_pkt(pkt)
        return pkt

    def pop_mac(self, d, prop, default):
        val = d.pop(prop, None)
        if not val:
            val = "{}".format(default)
        if isinstance(val, list):
            values = val
        else:
            values = val.split(" ")
        for index,val in enumerate(values):
            values[index] = val.replace(".", ":")
        return values

    def pop_str(self, d, prop, default):
        val = d.pop(prop, None)
        if not val:
            val = "{}".format(default)
        return val

    def pop_int(self, d, prop, default):
        val = d.pop(prop, "{}".format(default))
        try:
            return int(str(val))
        except Exception:
            self.logger.info(traceback.format_exc())

    def pop_hex(self, d, prop, default):
        val = d.pop(prop, "{}".format(default))
        try:
            return int(str(val), 16)
        except Exception:
            self.logger.info(traceback.format_exc())

    def get_int(self, d, prop, default):
        val = d.get(prop, "{}".format(default))
        try:
            return int(str(val))
        except Exception:
            self.logger.info(traceback.format_exc())

    def ensure_int(self, name, value, min_val, max_val):
        if value < 0 or value > 13312:
            msg = "invalid value {} = {} shoud be > {} and < {}"
            msg = msg.format(name, value, min_val, max_val)
            self.error(msg)

    def build_udp(self, kws):
        udp = UDP()
        udp.sport = self.pop_int(kws, "udp_src_port", 0)
        udp.dport = self.pop_int(kws, "udp_dst_port", 0)
        #udp.len
        #udp.chksum
        return udp

    def build_tcp(self, kws):
        tcp = TCP()
        tcp.sport = self.pop_int(kws, "tcp_src_port", 0)
        tcp.dport = self.pop_int(kws, "tcp_dst_port", 0)
        tcp.seq = self.pop_int(kws, "tcp_seq_num", 0)
        tcp.ack = self.pop_int(kws, "tcp_ack_num", 0)
        flags = []
        if self.pop_int(kws, "tcp_syn_flag", 0): flags.append('S')
        if self.pop_int(kws, "tcp_fin_flag", 0): flags.append('F')
        if self.pop_int(kws, "tcp_urg_flag", 0): flags.append('U')
        if self.pop_int(kws, "tcp_psh_flag", 0): flags.append('P')
        if self.pop_int(kws, "tcp_ack_flag", 0): flags.append('A')
        if self.pop_int(kws, "tcp_rst_flag", 0): flags.append('R')
        tcp.flags = "".join(flags)
        #tcp.dataofs
        #tcp.reserved
        tcp.window = self.pop_int(kws, "tcp_window", 0)
        #tcp.chksum
        #tcp.urgptr
        #tcp.options
        return tcp

    def build_icmp(self, kws):
        icmp = ICMP()
        icmp.type = self.pop_int(kws, "icmp_type", 0)
        #icmp.code = Driver.getConstValue(icmpCfg.code)
        #TODO: icmp_type_count, icmp_type_mode
        return icmp

    def build_icmp6(self, kws):
        icmp_type = self.pop_int(kws, "icmp_type", 0)
        if icmp_type == 136:
            icmp = ICMPv6ND_NA()
            icmp.R = self.pop_int(kws, "icmp_ndp_nam_r_flag", 1)
            icmp.S = self.pop_int(kws, "icmp_ndp_nam_s_flag", 0)
            icmp.O = self.pop_int(kws, "icmp_ndp_nam_o_flag", 1)
            icmp.tgt = self.pop_str(kws, "icmp_target_addr", "::")
        else:
            icmp = ICMP()
        return icmp

    def build_igmp(self, kws):
        igmp = IGMP()
        #igmp.mrcode
        igmp.gaddr = self.pop_str(kws, "igmp_group_addr", "0.0.0.0")
        #igmp.chksum = 0
        igmp_msg_type  = self.pop_str(kws, "igmp_msg_type", "report")
        if igmp_msg_type == "report":
            igmp.type = 0x16
        elif igmp_msg_type == "query":
            igmp.type = 0x11
        elif igmp_msg_type == "leave":
            igmp.type = 0x17
        else:
            self.logger.todo("unknown", "igmp_msg_type", igmp_msg_type)
            igmp = None
        return igmp

    def fill_emulation_params(self, stream):

        circuit_endpoint_type = stream.kws.pop("circuit_endpoint_type", None)
        self.logger.debug("stream.kws-0 = {}".format(stream.kws))

        src_info, dst_info = {}, {}
        src_intf = stream.kws.pop("emulation_src_handle", None)
        dst_intf = stream.kws.pop("emulation_dst_handle", None)
        if src_intf:
            ns = "ns_{}_{}".format(src_intf.name, 0)
            src_info = Utils.get_ip_addr_dev("veth1", ns)
            self.logger.debug("src_info = {} {}".format(ns, src_info))
            if circuit_endpoint_type == "ipv4":
                src_info.pop("inet6", "")
            elif circuit_endpoint_type == "ipv6":
                src_info.pop("inet", "")
            stream.kws["mac_src"] = [src_info.get("link/ether", "00:00:00:00:00:00")]
        if dst_intf:
            ns = "ns_{}_{}".format(dst_intf.name, 0)
            dst_info = Utils.get_ip_addr_dev("veth1", ns)
            self.logger.debug("dst_info = {} {}".format(ns, dst_info))
            if circuit_endpoint_type == "ipv4":
                dst_info.pop("inet6", "")
            elif circuit_endpoint_type == "ipv6":
                dst_info.pop("inet", "")
            stream.kws["mac_dst"] = [dst_info.get("link/ether", "00:00:00:00:00:00")]

        # read params from emulation interfaces
        if src_intf:
            intf_ip_addr = src_info.get("inet", "0.0.0.0").split("/")[0]
            intf_ip_addr = src_intf.kws.get("intf_ip_addr", intf_ip_addr)
            ipv6_intf_addr = src_info.get("inet6", "").split("/")[0]
            ipv6_intf_addr = src_intf.kws.get("ipv6_intf_addr", ipv6_intf_addr)
            count = self.utils.intval(src_intf.kws, "count", 1)
            if ipv6_intf_addr:
                stream.kws["l3_protocol"] = "ipv6"
                stream.kws["ipv6_src_addr"] = ipv6_intf_addr
                if count > 1:
                    stream.kws["ipv6_src_count"] = count
                    stream.kws["ipv6_src_mode"] = "increment"
            else:
                stream.kws["l3_protocol"] = "ipv4"
                stream.kws["ip_src_addr"] = intf_ip_addr
                stream.kws["ip_src_count"] = count
                if count > 1:
                    stream.kws["ip_src_count"] = count
                    stream.kws["ip_src_mode"] = "increment"
            #try:
                #stream.kws["mac_src"] = [src_info.get("link/ether", "00:00:00:00:00:00")]
                #stream.kws["mac_dst"] = [self.get_arp_mac(src_intf)]
            #except Exception as exp:
                #self.logger.info(exp)
                #self.logger.info(traceback.format_exc())
            self.logger.debug("updated stream.kws-1 = {}".format(stream.kws))

        if dst_intf:
            intf_ip_addr = dst_info.get("inet", "").split("/")[0]
            intf_ip_addr = dst_intf.kws.get("intf_ip_addr", intf_ip_addr)
            ipv6_intf_addr = dst_info.get("inet6", "").split("/")[0]
            ipv6_intf_addr = dst_intf.kws.get("ipv6_intf_addr", ipv6_intf_addr)
            count = self.utils.intval(dst_intf.kws, "count", 1)
            if ipv6_intf_addr:
                stream.kws["l3_protocol"] = "ipv6"
                stream.kws["ipv6_dst_addr"] = ipv6_intf_addr
                if count > 1:
                    stream.kws["ipv6_dst_count"] = count
                    stream.kws["ipv6_dst_mode"] = "increment"
            else:
                stream.kws["l3_protocol"] = "ipv4"
                stream.kws["ip_dst_addr"] = intf_ip_addr
                if count > 1:
                    stream.kws["ip_dst_count"] = count
                    stream.kws["ip_dst_mode"] = "increment"
            #stream.kws["mac_dst"] = [dst_info.get("link/ether", "00:00:00:00:00:00")]
            self.logger.debug("updated stream.kws-2 = {}".format(stream.kws))

    def build_first(self, stream):

        self.fill_emulation_params(stream)

        kws = copy.deepcopy(stream.kws)

        self.logger.info("=========== build_first this {} = {}".format(stream.stream_id, kws))
        # fill default variables
        mac_src = self.pop_mac(kws, "mac_src", "00:00:01:00:00:01")
        mac_dst = self.pop_mac(kws, "mac_dst", "00:00:00:00:00:00")

        duration = self.pop_int(kws, "duration", 1)
        duration2 = self.pop_int(kws, "duration2", 0)
        rate_percent = self.pop_int(kws, "rate_percent", 0)
        rate_pps = self.pop_int(kws, "rate_pps", 1)
        if rate_percent > 0:
            rate_pps = self.max_rate_pps
            self.banner("rate_percent {} not supported using {} pps".format(rate_percent, rate_pps))
        l2_encap = self.pop_str(kws, "l2_encap", "")
        l3_protocol = self.pop_str(kws, "l3_protocol", "")
        l4_protocol = self.pop_str(kws, "l4_protocol", "")
        vlan_en = self.pop_str(kws, "vlan", "enable")
        vlan_id = self.pop_int(kws, "vlan_id", 0)
        vlan_cfi = self.pop_int(kws, "vlan_cfi", 0)
        vlan_prio = self.pop_int(kws, "vlan_user_priority", 0)
        frame_size = self.pop_int(kws, "frame_size", 64)
        frame_size_min = self.pop_int(kws, "frame_size_min", 64)
        frame_size_max = self.pop_int(kws, "frame_size_max", 9210)
        frame_size_step = self.pop_int(kws, "frame_size_step", 64)
        transmit_mode = self.pop_str(kws, "transmit_mode", "continuous")
        if transmit_mode not in ["continuous", "continuous_burst", "single_burst", "single_pkt"]:
            self.logger.todo("unsupported", "transmit_mode", transmit_mode)
            return None

        data_pattern = self.pop_str(kws, "data_pattern", "")
        pkts_per_burst = self.pop_int(kws, "pkts_per_burst", 1)
        ethernet_value = self.pop_hex(kws, "ethernet_value", 0)
        length_mode = self.pop_str(kws, "length_mode", "fixed")
        l3_length = self.pop_int(kws, "l3_length", 110)
        data_pattern_mode = self.pop_str(kws, "data_pattern_mode", "fixed")

        mac_dst_mode  = kws.get("mac_dst_mode", "fixed").strip()
        if mac_dst_mode not in ["fixed", "increment", "decrement", "list"]:
            self.error("unhandled option mac_dst_mode = {}".format(mac_dst_mode))
        mac_src_mode  = kws.get("mac_src_mode", "fixed").strip()
        if mac_src_mode not in ["fixed", "increment", "decrement", "list"]:
            self.error("unhandled option mac_src_mode = {}".format(mac_src_mode))

        self.ensure_int("l3_length", l3_length, 44, 16365)
        if length_mode in ["random", "increment", "incr"]:
            self.ensure_int("frame_size_min", frame_size_min, 44, 13312)
            self.ensure_int("frame_size_max", frame_size_max, 44, 13312)
            self.ensure_int("frame_size_step", frame_size_step, 0, 13312)
        elif length_mode != "fixed":
            self.error("unhandled option length_mode = {}".format(length_mode))

        if data_pattern_mode != "fixed":
            self.error("unhandled option data_pattern_mode = {}".format(data_pattern_mode))

        # update parsed values
        stream.kws["mac_src"] = mac_src
        stream.kws["mac_dst"] = mac_dst

        pkt = Ether()
        pkt.src = mac_src[0]
        pkt.dst = mac_dst[0]

        if ethernet_value:
            pkt.type = ethernet_value

        # add l3_protocol
        if l3_protocol == "arp":
            arp = ARP()
            arp.hwsrc = self.pop_str(kws, "arp_src_hw_addr", "00:00:01:00:00:02").replace(".", ":")
            arp.hwdst = self.pop_str(kws, "arp_dst_hw_addr", "00:00:00:00:00:00").replace(".", ":")
            arp.psrc  = self.pop_str(kws, "ip_src_addr", "0.0.0.0")
            arp.pdst  = self.pop_str(kws, "ip_dst_addr", "192.0.0.1")
            arp_oper  = self.pop_str(kws, "arp_operation", "arpRequest")
            if arp_oper == "arpRequest":
                arp.op  = 1
            elif arp_oper in ["arpResponse", "arpReply"]:
                arp.op  = 2
            else:
                self.logger.debug("unknown ARP operation: {}".format(arp_oper))
                arp = None
            if arp:
                pkt = self.check(pkt/arp)
        elif l3_protocol == "ipv4":
            ip = IP()
            #ip.id
            #ip.chksum
            ip.src = self.pop_str(kws, "ip_src_addr", "0.0.0.0")
            ip.dst = self.pop_str(kws, "ip_dst_addr", "192.0.0.1")
            ip.ttl = self.pop_int(kws, "ip_ttl", 255)
            #ip.frag
            #ip.len
            #ip.flags
            #ip.options
            proto = self.pop_int(kws, "ip_proto", -1)
            if proto >= 0: ip.proto = proto
            ip_dscp = self.pop_int(kws, "ip_dscp", 0)
            if ip_dscp:
                ip.tos = int(bin(ip_dscp) + "00", 2)
            else:
                ip.tos = ip.tos | (self.pop_int(kws, "ip_precedence", 0) << 5)
                ip.tos = ip.tos | (self.pop_int(kws, "ip_delay", 0) << 4)
                ip.tos = ip.tos | (self.pop_int(kws, "ip_throughput", 0) << 3)
                ip.tos = ip.tos | (self.pop_int(kws, "ip_reliability", 0) << 2)
                ip.tos = ip.tos | (self.pop_int(kws, "ip_cost", 0) << 1)
                ip.tos = ip.tos | (self.pop_int(kws, "ip_reserved", 0) << 0)
            pkt = self.check(pkt/ip)

            # add l4_protocol
            if l4_protocol in ["udp"]:
                udp = self.build_udp(kws)
                pkt = self.check(pkt/udp)
            elif l4_protocol in ["tcp"]:
                tcp = self.build_tcp(kws)
                pkt = self.check(pkt/tcp)
            elif l4_protocol in ["icmp"]:
                icmp = self.build_icmp(kws)
                pkt = self.check(pkt/icmp)
            elif l4_protocol in ["igmp"]:
                igmp = self.build_igmp(kws)
                if igmp:
                    pkt = self.check(pkt/igmp)
            elif l4_protocol:
                self.logger.todo("unsupported-ipv4", "l4_protocol", l4_protocol)
        elif l3_protocol == "ipv6":
            ip6 = IPv6()
            ip6.src = self.pop_str(kws, "ipv6_src_addr", "fe80:0:0:0:0:0:0:12")
            ip6.dst = self.pop_str(kws, "ipv6_dst_addr", "fe80:0:0:0:0:0:0:22")
            ip6.hlim = self.pop_int(kws, "ipv6_hop_limit", 255)
            ip6.tc = self.pop_int(kws, "ipv6_traffic_class", 255)
            nh = self.pop_int(kws, "ipv6_next_header", 0)
            if nh: ip6.nh = nh
            # add l4_protocol
            pkt = self.check(pkt/ip6)
            if l4_protocol in ["udp"]:
                udp = self.build_udp(kws)
                pkt = self.check(pkt/udp)
            elif l4_protocol in ["tcp"]:
                tcp = self.build_tcp(kws)
                pkt = self.check(pkt/tcp)
            elif l4_protocol in ["icmp"]:
                icmp = self.build_icmp6(kws)
                pkt = self.check(pkt/icmp)
            elif l4_protocol in ["igmp"]:
                igmp = self.build_igmp(kws)
                if igmp:
                    pkt = self.check(pkt/igmp)
            elif l4_protocol:
                self.logger.todo("unsupported-ipv6", "l4_protocol", l4_protocol)
        elif l3_protocol:
            self.logger.todo("unsupported", "l3_protocol", l3_protocol)
            return None

        # insert VLAN header if required
        if l2_encap in ["ethernet_ii_vlan", "ethernet_ii"] and vlan_id > 0 and vlan_en == "enable":
            (payload, payload_type) = (pkt.payload, pkt.type)
            pkt.remove_payload()
            pkt.type = 0x8100
            pkt = self.check(pkt/Dot1Q(vlan=vlan_id, id=vlan_cfi, prio=vlan_prio, type=payload_type)/payload)
            #self.trace_packet(pkt)

        # handle transmit_mode
        if transmit_mode == "single_burst":
            left = pkts_per_burst
        elif transmit_mode == "single_pkt":
            left = 1
        else:
            left = rate_pps * duration2

        # append the data pattern if specified
        if data_pattern:
            padding = Padding()
            tmp_pattern = ''.join(c for c in data_pattern if  c not in ' ')
            tmp_pattern = binascii.unhexlify(tmp_pattern)
            padLen = int(frame_size - len(pkt) - 4 - len(padding))
            if len(tmp_pattern) > padLen:
                padding = Padding(tmp_pattern[:padLen])
            else:
                padding = Padding(tmp_pattern)
            pkt = self.check(pkt/padding)

        # update padding length based on frame_size
        add_signature = False
        if length_mode == "fixed":
            padLen = int(frame_size - len(pkt) - 4)
            if padLen > 0:
                padding = Padding(binascii.unhexlify('00' * padLen))
                pkt = self.check(pkt/padding)
                add_signature = True

        # verify unhandled options
        for key, value in kws.items():
            if key not in stale_list_ignore:
                self.error("unhandled option {} = {}".format(key, value))

        pwa = SpyTestDict()
        pwa.add_signature = add_signature
        pwa.pkt = pkt
        pwa.left = left
        pwa.burst_sent = 0
        pwa.pkts_per_burst = pkts_per_burst
        pwa.transmit_mode = transmit_mode
        if rate_pps > self.max_rate_pps:
            self.error("drop the rate from {} to {}".format(rate_pps, self.max_rate_pps))
            rate_pps = self.max_rate_pps
        pwa.rate_pps = rate_pps
        pwa.duration = duration
        pwa.duration2 = duration2
        pwa.stream = stream
        pwa.mac_src_count = 0
        pwa.mac_dst_count = 0
        pwa.arp_src_hw_count = 0
        pwa.arp_dst_hw_count = 0
        pwa.ip_src_count = 0
        pwa.ip_dst_count = 0
        pwa.ipv6_src_count = 0
        pwa.ipv6_dst_count = 0
        pwa.vlan_id_count = 0
        pwa.tcp_src_port_count = 0
        pwa.tcp_dst_port_count = 0
        pwa.udp_src_port_count = 0
        pwa.udp_dst_port_count = 0
        ##self.trace_packet(pkt)
        #self.logger.debug(pwa)

        pwa.length_mode = length_mode
        pwa.frame_size = frame_size
        pwa.frame_size_current = frame_size_min
        pwa.frame_size_min = frame_size_min
        pwa.frame_size_max = frame_size_max
        pwa.frame_size_step = frame_size_step
        self.add_padding(pwa, True)

        return pwa

    def add_padding(self, pwa, first):
        pwa.padding = None
        if pwa.length_mode == "random":
            pktLen = len(pwa.pkt)
            frame_size = random.randrange(pwa.frame_size_min, pwa.frame_size_max+1)
            padLen = int(frame_size - pktLen - 4)
            if padLen > 0:
                pwa.padding = Padding(binascii.unhexlify('00' * padLen))
                pwa.add_signature = True
        elif pwa.length_mode in ["increment", "incr"]:
            pktLen = len(pwa.pkt)
            if first:
                frame_size = pwa.frame_size_min
            else:
                frame_size = pwa.frame_size_current + pwa.frame_size_step
            if frame_size > pwa.frame_size_max:
                pwa.frame_size_current = pwa.frame_size_min
            else:
                pwa.frame_size_current = frame_size
            padLen = int(pwa.frame_size_current - pktLen - 4)
            if padLen > 0:
                pwa.padding = Padding(binascii.unhexlify('00' * padLen))
                pwa.add_signature = True

    def build_next_dma(self, pwa):

        # Change Ether SRC MAC
        mac_src_mode  = pwa.stream.kws.get("mac_src_mode", "fixed").strip()
        mac_src_step  = pwa.stream.kws.get("mac_src_step", "00:00:00:00:00:01")
        mac_src_count  = self.utils.intval(pwa.stream.kws, "mac_src_count", 0)
        if mac_src_mode in ["increment", "decrement"]:
            if mac_src_mode in ["increment"]:
                pwa.pkt[0].src = self.utils.incrementMac(pwa.pkt[0].src, mac_src_step)
            else:
                pwa.pkt[0].src = self.utils.decrementMac(pwa.pkt[0].src, mac_src_step)
            pwa.mac_src_count = pwa.mac_src_count + 1
            if mac_src_count > 0 and pwa.mac_src_count >= mac_src_count:
                pwa.pkt[0].src = pwa.stream.kws["mac_src"][0]
                pwa.mac_src_count = 0
        elif mac_src_mode in ["list"]:
            pwa.mac_src_count = pwa.mac_src_count + 1
            if pwa.mac_src_count >= len(pwa.stream.kws["mac_src"]):
                pwa.pkt[0].src = pwa.stream.kws["mac_src"][0]
                pwa.mac_src_count = 0
            else:
                pwa.pkt[0].src = pwa.stream.kws["mac_src"][pwa.mac_src_count]
        elif mac_src_mode != "fixed":
            self.logger.todo("unhandled", "mac_src_mode", mac_src_mode)

        # Change Ether DST MAC
        mac_dst_mode  = pwa.stream.kws.get("mac_dst_mode", "fixed").strip()
        mac_dst_step  = pwa.stream.kws.get("mac_dst_step", "00:00:00:00:00:01")
        mac_dst_count  = self.utils.intval(pwa.stream.kws, "mac_dst_count", 0)
        if mac_dst_mode in ["increment", "decrement"]:
            if mac_dst_mode in ["increment"]:
                pwa.pkt[0].dst = self.utils.incrementMac(pwa.pkt[0].dst, mac_dst_step)
            else:
                pwa.pkt[0].dst = self.utils.decrementMac(pwa.pkt[0].dst, mac_dst_step)
            pwa.mac_dst_count = pwa.mac_dst_count + 1
            if mac_dst_count > 0 and pwa.mac_dst_count >= mac_dst_count:
                pwa.pkt[0].dst = pwa.stream.kws["mac_dst"][0]
                pwa.mac_dst_count = 0
        elif mac_dst_mode in ["list"]:
            pwa.mac_dst_count = pwa.mac_dst_count + 1
            if pwa.mac_dst_count >= len(pwa.stream.kws["mac_dst"]):
                pwa.pkt[0].dst = pwa.stream.kws["mac_dst"][0]
                pwa.mac_dst_count = 0
            else:
                pwa.pkt[0].dst = pwa.stream.kws["mac_dst"][pwa.mac_dst_count]
        elif mac_dst_mode != "fixed":
            self.logger.todo("unhandled", "mac_dst_mode", mac_dst_mode)

        # Change ARP SRC MAC
        if ARP in pwa.pkt:
            arp_src_hw_mode  = pwa.stream.kws.get("arp_src_hw_mode", "fixed").strip()
            arp_src_hw_step  = pwa.stream.kws.get("arp_src_hw_step", "00:00:00:00:00:01")
            arp_src_hw_count  = self.utils.intval(pwa.stream.kws, "arp_src_hw_count", 0)
            if arp_src_hw_mode in ["increment", "decrement"]:
                if arp_src_hw_mode in ["increment"]:
                    pwa.pkt[ARP].hwsrc = self.utils.incrementMac(pwa.pkt[ARP].hwsrc, arp_src_hw_step)
                else:
                    pwa.pkt[ARP].hwsrc = self.utils.decrementMac(pwa.pkt[ARP].hwsrc, arp_src_hw_step)
                pwa.arp_src_hw_count = pwa.arp_src_hw_count + 1
                if arp_src_hw_count > 0 and pwa.arp_src_hw_count >= arp_src_hw_count:
                    pwa.pkt[ARP].hwsrc = pwa.stream.kws.get("arp_src_hw_addr", "00:00:01:00:00:02").replace(".", ":")
                    pwa.arp_src_hw_count = 0
            elif arp_src_hw_mode != "fixed":
                self.logger.todo("unhandled", "arp_src_hw_mode", arp_src_hw_mode)

        # Change ARP DST MAC
        if ARP in pwa.pkt:
            arp_dst_hw_mode  = pwa.stream.kws.get("arp_dst_hw_mode", "fixed").strip()
            arp_dst_hw_step  = pwa.stream.kws.get("arp_dst_hw_step", "00:00:00:00:00:01")
            arp_dst_hw_count  = self.utils.intval(pwa.stream.kws, "arp_dst_hw_count", 0)
            if arp_dst_hw_mode in ["increment", "decrement"]:
                if arp_dst_hw_mode in ["increment"]:
                    pwa.pkt[ARP].hwdst = self.utils.incrementMac(pwa.pkt[ARP].hwdst, arp_dst_hw_step)
                else:
                    pwa.pkt[ARP].hwdst = self.utils.decrementMac(pwa.pkt[ARP].hwdst, arp_dst_hw_step)
                pwa.arp_dst_hw_count = pwa.arp_dst_hw_count + 1
                if arp_dst_hw_count > 0 and pwa.arp_dst_hw_count >= arp_dst_hw_count:
                    pwa.pkt[ARP].hwdst = pwa.stream.kws.get("arp_dst_hw_addr", "00:00:00:00:00:00").replace(".", ":")
                    pwa.arp_dst_hw_count = 0
            elif arp_dst_hw_mode != "fixed":
                self.logger.todo("unhandled", "arp_dst_hw_mode", arp_dst_hw_mode)

        # Change SRC IP
        if IP in pwa.pkt:
            ip_src_mode  = pwa.stream.kws.get("ip_src_mode", "fixed").strip()
            ip_src_step  = pwa.stream.kws.get("ip_src_step", "0.0.0.1")
            ip_src_count  = self.utils.intval(pwa.stream.kws, "ip_src_count", 0)
            if ip_src_mode in ["increment", "decrement"]:
                if ip_src_mode in ["increment"]:
                    pwa.pkt[IP].src = self.utils.incrementIPv4(pwa.pkt[IP].src, ip_src_step)
                else:
                    pwa.pkt[IP].src = self.utils.decrementIPv4(pwa.pkt[IP].src, ip_src_step)
                pwa.ip_src_count = pwa.ip_src_count + 1
                if ip_src_count > 0 and pwa.ip_src_count >= ip_src_count:
                    pwa.pkt[IP].src = pwa.stream.kws.get("ip_src_addr", "0.0.0.0")
                    pwa.ip_src_count = 0
            elif ip_src_mode != "fixed":
                self.logger.todo("unhandled", "ip_src_mode", ip_src_mode)

        # Change DST IP
        if IP in pwa.pkt:
            ip_dst_mode  = pwa.stream.kws.get("ip_dst_mode", "fixed").strip()
            ip_dst_step  = pwa.stream.kws.get("ip_dst_step", "0.0.0.1")
            ip_dst_count  = self.utils.intval(pwa.stream.kws, "ip_dst_count", 0)
            if ip_dst_mode in ["increment", "decrement"]:
                if ip_dst_mode in ["increment"]:
                    pwa.pkt[IP].dst = self.utils.incrementIPv4(pwa.pkt[IP].dst, ip_dst_step)
                else:
                    pwa.pkt[IP].dst = self.utils.decrementIPv4(pwa.pkt[IP].dst, ip_dst_step)
                pwa.ip_dst_count = pwa.ip_dst_count + 1
                if ip_dst_count > 0 and pwa.ip_dst_count >= ip_dst_count:
                    pwa.pkt[IP].dst = pwa.stream.kws.get("ip_dst_addr", "192.0.0.1")
                    pwa.ip_dst_count = 0
            elif ip_dst_mode != "fixed":
                self.logger.todo("unhandled", "ip_dst_mode", ip_dst_mode)

        # Change SRC IPv6
        if IPv6 in pwa.pkt:
            ipv6_src_mode  = pwa.stream.kws.get("ipv6_src_mode", "fixed").strip()
            ipv6_src_step  = pwa.stream.kws.get("ipv6_src_step", "::1")
            ipv6_src_count  = self.utils.intval(pwa.stream.kws, "ipv6_src_count", 0)
            if ipv6_src_mode in ["increment", "decrement"]:
                if ipv6_src_mode in ["increment"]:
                    pwa.pkt[IPv6].src = self.utils.incrementIPv6(pwa.pkt[IPv6].src, ipv6_src_step)
                else:
                    pwa.pkt[IPv6].src = self.utils.decrementIPv6(pwa.pkt[IPv6].src, ipv6_src_step)
                pwa.ipv6_src_count = pwa.ipv6_src_count + 1
                if ipv6_src_count > 0 and pwa.ipv6_src_count >= ipv6_src_count:
                    pwa.pkt[IPv6].src = pwa.stream.kws.get("ipv6_src_addr", "fe80:0:0:0:0:0:0:12")
                    pwa.ipv6_src_count = 0
            elif ipv6_src_mode != "fixed":
                self.logger.todo("unhandled", "ipv6_src_mode", ipv6_src_mode)

        # Change DST IPv6
        if IPv6 in pwa.pkt:
            ipv6_dst_mode  = pwa.stream.kws.get("ipv6_dst_mode", "fixed").strip()
            ipv6_dst_step  = pwa.stream.kws.get("ipv6_dst_step", "::1")
            ipv6_dst_count  = self.utils.intval(pwa.stream.kws, "ipv6_dst_count", 0)
            if ipv6_dst_mode in ["increment", "decrement"]:
                if ipv6_dst_mode in ["increment"]:
                    pwa.pkt[IPv6].dst = self.utils.incrementIPv6(pwa.pkt[IPv6].dst, ipv6_dst_step)
                else:
                    pwa.pkt[IPv6].dst = self.utils.decrementIPv6(pwa.pkt[IPv6].dst, ipv6_dst_step)
                pwa.ipv6_dst_count = pwa.ipv6_dst_count + 1
                if ipv6_dst_count > 0 and pwa.ipv6_dst_count >= ipv6_dst_count:
                    pwa.pkt[IPv6].dst = pwa.stream.kws.get("ipv6_dst_addr", "fe80:0:0:0:0:0:0:22")
                    pwa.ipv6_dst_count = 0
            elif ipv6_dst_mode != "fixed":
                self.logger.todo("unhandled", "ipv6_dst_mode", ipv6_dst_mode)

        # Change VLAN
        if Dot1Q in pwa.pkt:
            vlan_id_mode  = pwa.stream.kws.get("vlan_id_mode", "fixed").strip()
            vlan_id_step  = self.utils.intval(pwa.stream.kws, "vlan_id_step", 1)
            vlan_id_count  = self.utils.intval(pwa.stream.kws, "vlan_id_count", 0)
            if vlan_id_mode in ["increment", "decrement"]:
                if vlan_id_mode in ["increment"]:
                    pwa.pkt[Dot1Q].vlan = pwa.pkt[Dot1Q].vlan + vlan_id_step
                else:
                    pwa.pkt[Dot1Q].vlan = pwa.pkt[Dot1Q].vlan - vlan_id_step
                pwa.vlan_id_count = pwa.vlan_id_count + 1
                if vlan_id_count > 0 and pwa.vlan_id_count >= vlan_id_count:
                    pwa.pkt[Dot1Q].vlan = self.utils.intval(pwa.stream.kws, "vlan_id", 0)
                    pwa.vlan_id_count = 0
            elif vlan_id_mode != "fixed":
                self.logger.todo("unhandled", "vlan_id_mode", vlan_id_mode)

        # Change TCP SRC PORT
        if TCP in pwa.pkt:
            tcp_src_port_mode  = pwa.stream.kws.get("tcp_src_port_mode", "fixed").strip()
            tcp_src_port_step  = self.utils.intval(pwa.stream.kws, "tcp_src_port_step", 1)
            tcp_src_port_count  = self.utils.intval(pwa.stream.kws, "tcp_src_port_count", 0)
            if tcp_src_port_mode in ["increment", "decrement", "incr", "decr"]:
                if tcp_src_port_mode in ["increment", "incr"]:
                    pwa.pkt[TCP].sport = pwa.pkt[TCP].sport + tcp_src_port_step
                else:
                    pwa.pkt[TCP].sport = pwa.pkt[TCP].sport - tcp_src_port_step
                pwa.tcp_src_port_count = pwa.tcp_src_port_count + 1
                if tcp_src_port_count > 0 and pwa.tcp_src_port_count >= tcp_src_port_count:
                    pwa.pkt[TCP].sport = self.utils.intval(pwa.stream.kws, "tcp_src_port", 0)
                    pwa.tcp_src_port_count = 0
            elif tcp_src_port_mode != "fixed":
                self.logger.todo("unhandled", "tcp_src_port_mode", tcp_src_port_mode)

        # Change TCP DST PORT
        if TCP in pwa.pkt:
            tcp_dst_port_mode  = pwa.stream.kws.get("tcp_dst_port_mode", "fixed").strip()
            tcp_dst_port_step  = self.utils.intval(pwa.stream.kws, "tcp_dst_port_step", 1)
            tcp_dst_port_count  = self.utils.intval(pwa.stream.kws, "tcp_dst_port_count", 0)
            if tcp_dst_port_mode in ["increment", "decrement", "incr", "decr"]:
                if tcp_dst_port_mode in ["increment", "incr"]:
                    pwa.pkt[TCP].dport = pwa.pkt[TCP].sport + tcp_dst_port_step
                else:
                    pwa.pkt[TCP].dport = pwa.pkt[TCP].sport - tcp_dst_port_step
                pwa.tcp_dst_port_count = pwa.tcp_dst_port_count + 1
                if tcp_dst_port_count > 0 and pwa.tcp_dst_port_count >= tcp_dst_port_count:
                    pwa.pkt[TCP].dport = self.utils.intval(pwa.stream.kws, "tcp_dst_port", 0)
                    pwa.tcp_dst_port_count = 0
            elif tcp_dst_port_mode != "fixed":
                self.logger.todo("unhandled", "tcp_dst_port_mode", tcp_dst_port_mode)

        # Change UDP SRC PORT
        if UDP in pwa.pkt:
            udp_src_port_mode  = pwa.stream.kws.get("udp_src_port_mode", "fixed").strip()
            udp_src_port_step  = self.utils.intval(pwa.stream.kws, "udp_src_port_step", 1)
            udp_src_port_count  = self.utils.intval(pwa.stream.kws, "udp_src_port_count", 0)
            if udp_src_port_mode in ["increment", "decrement", "incr", "decr"]:
                if udp_src_port_mode in ["increment", "incr"]:
                    pwa.pkt[UDP].sport = pwa.pkt[UDP].sport + udp_src_port_step
                else:
                    pwa.pkt[UDP].sport = pwa.pkt[UDP].sport - udp_src_port_step
                pwa.udp_src_port_count = pwa.udp_src_port_count + 1
                if udp_src_port_count > 0 and pwa.udp_src_port_count >= udp_src_port_count:
                    pwa.pkt[UDP].sport = self.utils.intval(pwa.stream.kws, "udp_src_port", 0)
                    pwa.udp_src_port_count = 0
            elif udp_src_port_mode != "fixed":
                self.logger.todo("unhandled", "udp_src_port_mode", udp_src_port_mode)

        # Change UDP DST PORT
        if UDP in pwa.pkt:
            udp_dst_port_mode  = pwa.stream.kws.get("udp_dst_port_mode", "fixed").strip()
            udp_dst_port_step  = self.utils.intval(pwa.stream.kws, "udp_dst_port_step", 1)
            udp_dst_port_count  = self.utils.intval(pwa.stream.kws, "udp_dst_port_count", 0)
            if udp_dst_port_mode in ["increment", "decrement", "incr", "decr"]:
                if udp_dst_port_mode in ["increment", "incr"]:
                    pwa.pkt[UDP].dport = pwa.pkt[UDP].sport + udp_dst_port_step
                else:
                    pwa.pkt[UDP].dport = pwa.pkt[UDP].sport - udp_dst_port_step
                pwa.udp_dst_port_count = pwa.udp_dst_port_count + 1
                if udp_dst_port_count > 0 and pwa.udp_dst_port_count >= udp_dst_port_count:
                    pwa.pkt[UDP].dport = self.utils.intval(pwa.stream.kws, "udp_dst_port", 0)
                    pwa.udp_dst_port_count = 0
            elif udp_dst_port_mode != "fixed":
                self.logger.todo("unhandled", "udp_dst_port_mode", udp_dst_port_mode)

        # add padding based on length_mode
        self.add_padding(pwa, False)

        return pwa

    def build_next(self, pwa):
        if self.dbg > 2 or (self.dbg > 1 and pwa.left != 0):
            self.logger.debug("build_next {}/{} {} left={}".format(self.iface, pwa.stream.stream_id, pwa.transmit_mode, pwa.left))

        if pwa.transmit_mode in ["continuous"] and pwa.duration2 > 0:
            if pwa.left <= 0: return None
            pwa.left = pwa.left - 1
            pwa = self.build_next_dma(pwa)
            return pwa

        if pwa.transmit_mode in ["continuous"]:
            pwa = self.build_next_dma(pwa)
            return pwa

        if pwa.transmit_mode in ["continuous_burst"]:
            pwa.burst_sent = pwa.burst_sent + 1
            pwa = self.build_next_dma(pwa)
            return pwa

        if pwa.left > 1:
            pwa = self.build_next_dma(pwa)
            if not pwa: return None

        pwa.burst_sent = pwa.burst_sent + 1

        if pwa.left > 1:
            pwa.left = pwa.left - 1
            return pwa

        return None

    def build_ipg(self, pwa):
        if pwa.burst_sent != 0 and pwa.burst_sent < pwa.pkts_per_burst:
            return 0
        pwa.burst_sent = 0
        pps = self.utils.min_value(pwa.rate_pps, self.max_rate_pps)
        return (1.0 * pwa.pkts_per_burst)/float(pps)

    def match_stream(self, stream, pkt):
        sid = stream.get_sid()
        if not sid: return False
        strpkt = str(pkt)
        if sid == strpkt[-12:-4]:
            self.logger.debug("{}: CMP0: {} {}".format(self.iface, sid, strpkt[-12:-4]))
            return True
        #self.logger.debug("{}: CMP1: {} {}".format(self.iface, sid, strpkt[-12:-4]))
        return False

    def if_delete_cmds(self, index, intf):
        ns = "{}_{}".format(intf.name, index)

        # remove the linux interface
        cmds = textwrap.dedent("""
            ip netns del ns_{0}
            ip link del veth_{0}
        """.format(ns))

        return ns, cmds

    def if_create_cmds(self, index, intf, ip4addr, ip4gw, ip6addr, ip6gw, smac, **kws):
        ns = "{}_{}".format(intf.name, index)

        vlan_enable = self.utils.intval(kws, "vlan", 0)
        vlan_id = self.utils.intval(kws, "vlan_id", 1)
        veth_name = "veth0" if vlan_enable else "veth1"

        begin, finish, verify = "", "", ""

        # remove existing
        _, cmds = self.if_delete_cmds(index, intf)
        begin += cmds

        # create the linux interface
        begin += textwrap.dedent("""
            ip netns add ns_{0}
            ip link add veth_{0} type veth peer name {2}
            ip link set {2} netns ns_{0}
            ip netns exec ns_{0} ethtool --offload {2} rx off  tx off > /dev/null 2>&1
            ip netns exec ns_{0} ip link set dev {2} up
            ip netns exec ns_{0} ethtool --offload {2} rx off tx off
            ip link set dev veth_{0} up
            ip link set dev veth_{0} master {1}-br
        """.format(ns, intf.iface, veth_name))

        if vlan_enable:
            begin += textwrap.dedent("""
                ip netns exec ns_{0} ip link add link veth0 name veth1 type vlan id {1}
                ip netns exec ns_{0} ip link set veth1 up
            """.format(ns, vlan_id))

        # set interface mac address
        if smac != "00:00:00:00:00:00":
            begin += "\nip netns exec ns_{0} ip link set veth1 address {1}".format(ns, smac)

        # assign IPv4 to linux interface
        if ip4addr:
            begin += "\nip netns exec ns_{0} ip addr add {1}/{2} dev veth1".format(ns, ip4addr, 24)
        if ip4gw:
            begin += "\nip netns exec ns_{0} ip route add default via {1}".format(ns, ip4gw)

        # assign IPv6 to linux interface
        if ip6addr:
            ip6prefix = self.utils.intval(intf.kws, "ipv6_prefix_length", 64)
            begin += "\nip netns exec ns_{0} ip -6 addr add {1}/{2} dev veth1".format(ns, ip6addr, ip6prefix)
        if ip6gw:
            begin += "\nip netns exec ns_{0} ip -6 route add default via {1}".format(ns, ip6gw)

        # send Arp request
        arp_send_req = self.utils.intval(kws, "arp_send_req", 1)
        if arp_send_req:
            if ip4gw:
                finish += textwrap.dedent("""
                    ip netns exec ns_{0} arping -c 1 -I veth1 {1}
                """.format(ns, ip4gw))
                verify += textwrap.dedent("""
                    ip netns exec ns_{0} ip neigh show
                """.format(ns))
            if ip6gw:
                finish += textwrap.dedent("""
                    ip netns exec ns_{0} ndisc6 -w 2000 {1} veth1
                """.format(ns, ip6gw))
                if ip6addr:
                    finish += textwrap.dedent("""
                        ip netns exec ns_{0} ndisc6 -w 2000 -s {2} {1} veth1
                    """.format(ns, ip6gw, ip6addr))
                verify += textwrap.dedent("""
                    ip netns exec ns_{0} ip -6 neigh show
                """.format(ns))

        if self.dbg > 1:
            verify += textwrap.dedent("""
                ip netns exec ns_{0} ifconfig veth1
                ip netns exec ns_{0} ip addr ls veth1
            """.format(ns))

        return ns, begin, finish, verify

    def store_cmds(self, cmd_list, b, f, v):
        cmd_list[0].append(b)
        cmd_list[1].append(f)
        cmd_list[2].append(v)

    def change_map(self, ns, is_add):
        pass

    def if_create(self, intf):
        smac = intf.kws.get("src_mac_addr", "00:00:00:00:00:00").replace(".", ":")
        count = self.utils.intval(intf.kws, "count", 1)

        # set IPv4 Address
        ip4addr = intf.kws.get("intf_ip_addr", "")
        ip4addr_step = intf.kws.get("intf_ip_addr_step", "0.0.0.1")
        ip4gw = intf.kws.get("gateway", "")
        ip4gw_step = intf.kws.get("gateway_step", "0.0.0.0")
        cmd_list = [[],[],[]]
        if ip4addr:
            for index in range(count):
                ns, b, f, v = self.if_create_cmds(index, intf, ip4addr, ip4gw, None, None, smac, **intf.kws)
                self.store_cmds(cmd_list, b, f, v)
                self.change_map(ns, True)
                ip4addr = self.utils.incrementIPv4(ip4addr, ip4addr_step)
                if ip4gw: ip4gw = self.utils.incrementIPv4(ip4gw, ip4gw_step)
                if smac != "00:00:00:00:00:00":
                    smac = self.utils.incrementMac(smac, "00:00:00:00:00:01")
        # set IPv6 Address
        ip6addr = intf.kws.get("ipv6_intf_addr", "")
        ip6addr_step = intf.kws.get("ipv6_intf_addr_step", "::1")
        ip6gw = intf.kws.get("ipv6_gateway", "")
        ip6gw_step = intf.kws.get("ipv6_gateway_step", "::0")
        if ip6addr:
            for index in range(count):
                ns, b, f, v = self.if_create_cmds(index, intf, None, None, ip6addr, ip6gw, smac, **intf.kws)
                self.store_cmds(cmd_list, b, f, v)
                self.change_map(ns, True)
                ip6addr = self.utils.incrementIPv6(ip6addr, ip6addr_step)
                if ip6gw: ip6gw = self.utils.incrementIPv6(ip6gw, ip6gw_step)
                if smac != "00:00:00:00:00:00":
                    smac = self.utils.incrementMac(smac, "00:00:00:00:00:01")

        # execute collected commands
        cmds = cmd_list[0]
        if cmd_list[1]:
            cmds.append("sleep 2")
            cmds.extend(cmd_list[1])
        cmds.extend(cmd_list[2])
        self.utils.lshexec(cmds)

    def if_delete(self, intf):
        count = self.utils.intval(intf.kws, "count", 1)
        cmd_list = []
        for index in range(count):
            ns, cmds = self.if_delete_cmds(index, intf)
            cmd_list.append(cmds)
        self.change_map(ns, False)
        self.utils.lshexec(cmd_list)

    def get_my_mac(self, intf, default="00:00:00:00:00:00"):
        ns = "{}_{}".format(intf.name, 0)
        cmd = "ip netns exec ns_{0} cat /sys/class/net/veth1/address".format(ns)
        output = self.utils.cmdexec(cmd).lower()
        self.logger.debug("{} = {}".format(cmd, output))
        return output

    def get_arp_mac(self, intf, default="00:00:00:00:00:00"):
        ipv6gw = intf.kws.get("ipv6_gateway", "")
        ipv4gw = intf.kws.get("gateway", "0.0.0.0")
        ns = "{}_{}".format(intf.name, 0)
        self.logger.debug("get_arp_mac {} {}".format(ipv4gw, ipv6gw))

        # try getting from ARP cache
        try:
            cmd = "ip netns exec ns_{0} cat /proc/net/arp".format(ns)
            output = self.utils.cmdexec(cmd).lower()
            self.logger.debug("{} = \n {}".format(cmd, output))

            cmd = "ip netns exec ns_{0} arp -n {1}".format(ns, ipv4gw)
            output = self.utils.cmdexec(cmd).lower()
            self.logger.debug("{} = \n {}".format(cmd, output))

            return re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", output).groups()[0]
        except Exception as exp:
            self.banner("Fail-1: get_arp_mac {} {} {}".format(ipv4gw, ipv6gw, exp))

        # try getting from arping output
        try:
            cmd = "ip netns exec ns_{0} arping -c 1 -I veth1 {1}".format(ns, ipv4gw)
            output = self.utils.cmdexec(cmd).lower()
            self.logger.debug("{} = \n {}".format(cmd, output))
            return re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", output).groups()[0]
        except Exception as exp:
            self.banner("Fail-2: get_arp_mac {} {} {}".format(ipv4gw, ipv6gw, exp))

        return default

    def ping(self, intf, ping_dst, index=0):
        ns = "{}_{}".format(intf.name, index)

        cmd = "ip netns exec ns_{0} ping -c 1 {1}".format(ns, ping_dst)
        try:
            ip = ipaddress.ip_address(unicode(ping_dst))
            if ip._version == 6:
                cmd = "ip netns exec ns_{0} ping6 -c 1 {1}".format(ns, ping_dst)
        except Exception as exp:
            self.error(exp)

        # execute the command
        return self.utils.cmdexec(cmd)

    def send_arp(self, intf, index=0):
        ns = "{}_{}".format(intf.name, index)
        ip4gw = intf.kws.get("gateway", "0.0.0.0")
        cmd = "ip netns exec ns_{0} arping -c 1 -I veth1 {1}".format(ns, ip4gw)
        return self.utils.cmdexec(cmd)

    def log_large_file(self, fname):
        size = self.utils.wc_l(fname)
        if self.dbg > 2:
            self.logger.info("======= CAT {} LINES {} =====".format(fname, size))
            self.logger.info(self.utils.cat_file(fname))
            self.logger.info("===================================")
        else:
            self.logger.info("======= HEAD {} LINES {} =====".format(fname, size))
            self.logger.info(self.utils.fhead(fname, 50))
            self.logger.info("===================================")
            self.logger.info("======= TAIL {} LINES {} =====".format(fname, size))
            self.logger.info(self.utils.ftail(fname, 50))
            self.logger.info("===================================")

    def exabgpd_file(self, ns, extn):
        return "{}/exabgpd_{}.{}".format(self.logger.logs_dir, ns, extn)

    def exabgpd_stop_all(self):
        self.os_system("ps -ef")
        for pidfile in self.utils.list_files(self.logger.logs_dir, "exabgpd_*.pid"):
            cmd = "pkill -F {}".format(pidfile)
            print(cmd)
            out = self.os_system(cmd)
            print(out)

    def exabgpd_stop(self, ns):
        logfile = self.exabgpd_file(ns, "log")
        pidfile = self.exabgpd_file(ns, "pid")
        self.log_large_file(logfile)
        self.logger.info(self.utils.cat_file(pidfile))
        cmd = "pkill -F {}".format(pidfile)
        self.os_system(cmd)
        if ns in self.exabgp_nslist:
            self.exabgp_nslist.remove(ns)
        return True

    def config_exabgp_one(self, enable, intf, index=0):
        ns = "{}_{}".format(intf.name, index)
        if not enable:
            self.exabgpd_stop(ns)
            return True
        self.exabgp_nslist.append(ns)

        logfile = self.exabgpd_file(ns, "log")
        pidfile = self.exabgpd_file(ns, "pid")
        envfile = self.exabgpd_file(ns, "env")
        cfgfile = self.exabgpd_file(ns, "cfg")

        intf_ip_addr = intf.kws.get("intf_ip_addr", "")
        ipv6_intf_addr = intf.kws.get("ipv6_intf_addr", "")
        if ipv6_intf_addr: intf_ip_addr = ipv6_intf_addr

        remote_ip_addr = intf.bgp_kws.get("remote_ip_addr", "0.0.0.0")
        remote_ipv6_addr = intf.bgp_kws.get("remote_ipv6_addr", "")
        if remote_ipv6_addr: remote_ip_addr = remote_ipv6_addr

        remote_as = self.utils.intval(intf.bgp_kws, "remote_as", 65001)
        local_as = self.utils.intval(intf.bgp_kws, "local_as", 65007)
        #enable_4_byte_as = self.utils.intval(intf.bgp_kws, "enable_4_byte_as", 0)
        #ip_version = self.utils.intval(intf.bgp_kws, "ip_version", 4)

        # create route config
        cmdfile = self.config_exabgp_route(enable, intf, index)

        # build router id from ns
        router_id = ns.replace("_", ".") + ".0"

        cmds = textwrap.dedent("""
            group exabgp {{
                process dump {{
                    encoder json;
                    receive {{
                        parsed;
                        update;
                    }}
                    run /usr/bin/python {4}/exabgp_dump.py;
                }}
                process http-api {{
                    run /usr/bin/python {4}/exabgp_http_api.py {5};
                }}
                neighbor {2} {{
                    router-id {7};
                    local-address {0};
                    peer-as {3};
                    local-as {1};
                    auto-flush false;
                    group-updates true;
                    process announce-routes {{
                        run /usr/bin/python {4}/exabgp_routes.py {6};
                    }}
                }}
            }}
        """.format(intf_ip_addr, local_as, remote_ip_addr, remote_as, this_dir, 5000, cmdfile, router_id))
        self.utils.fwrite(cmds, cfgfile)

        cmds = textwrap.dedent("""
            group exabgp {{
                neighbor {2} {{
                    router-id {6};
                    local-address {0};
                    peer-as {3};
                    local-as {1};
                    auto-flush false;
                    group-updates true;
                    process announce-routes {{
                        run /usr/bin/python {4}/exabgp_routes.py {5};
                    }}
                }}
            }}
        """.format(intf_ip_addr, local_as, remote_ip_addr, remote_as, this_dir, cmdfile, router_id))
        self.utils.fwrite(cmds, cfgfile)

        cmds = textwrap.dedent("""
            #[exabgp.api]
            #pipename = '{0}'

            [exabgp.daemon]
            pid = '{1}'
            daemonize = true
            drop = false
            user = root

            [exabgp.log]
            all = true
            destination = '{2}'
        """.format(ns, pidfile, logfile))
        self.utils.fwrite(cmds, envfile)

        cmds = textwrap.dedent("""
            set -x
            #mkfifo //run/{0}.{{in,out}}
            #chmod 600 //run/{0}.{{in,out}}
            exabgp --env {1} {2}
        """.format(ns, envfile, cfgfile))
        sh_file = self.utils.fwrite(cmds)

        cmds = textwrap.dedent("""
            ip netns exec ns_{0} bash {1}
        """.format(ns, sh_file))
        self.utils.shexec(cmds)

        self.logger.info(self.utils.cat_file(envfile))
        self.logger.info(self.utils.cat_file(cfgfile))
        self.log_large_file(cmdfile)
        time.sleep(5)
        self.logger.info(self.utils.cat_file(pidfile))
        self.log_large_file(logfile)

        return True

    def config_exabgp_route(self, enable, intf, index=0):
        ns = "{}_{}".format(intf.name, index)
        cmdfile = self.exabgpd_file(ns, "cmd")
        cmds = []

        for br in intf.bgp_routes.values():
            if not br.enable: continue
            as_path = br.get("as_path", None)
            as_seq = None
            if as_path and "as_seq:" in as_path:
                try: as_seq = int(as_path.replace("as_path:", ""))
                except Exception: as_seq = None

            num_routes = self.utils.intval(br, "num_routes", 0)
            prefix = br.get("prefix", "")
            if not prefix and num_routes > 0:
                msg = "Prefix not specified num_routes={}".format(num_routes)
                self.error(msg)
            else:
                for _ in range(num_routes):
                    remote_ipv6_addr = intf.bgp_kws.get("remote_ipv6_addr", "")
                    if remote_ipv6_addr:
                        cmd = "announce route {}/128 next-hop self".format(prefix)
                        prefix = self.utils.incrementIPv6(prefix, "0:0:0:1::")
                    else:
                        cmd = "announce route {}/24 next-hop self".format(prefix)
                        prefix = self.utils.incrementIPv4(prefix, "0.0.1.0")
                    # append as-path sequence
                    if as_seq: cmd = cmd + "as-path [{}]".format(as_seq)
                    cmds.append(cmd)
        self.utils.fwrite("\n".join(cmds), cmdfile)
        #############################
        # TODO: batch routes
        # announce attribute next-hop self nlri 100.10.0.0/16 100.20.0.0/16
        #############################
        return cmdfile

    def control_exabgp(self, intf):
        num_routes = self.utils.intval(intf.bgp_kws, "num_routes", 0)
        ns = "{}_{}".format(intf.name, 0)
        prefix = intf.bgp_kws.get("prefix", "")
        if not prefix:
            msg = "Prefix not specified num_routes={}".format(num_routes)
            self.error(msg)
            #return False
        #envfile = self.exabgpd_file(ns, "env")
        for _ in range(num_routes):
            remote_ipv6_addr = intf.bgp_kws.get("remote_ipv6_addr", "")
            if remote_ipv6_addr:
                #cmd = textwrap.dedent("""
                    #ip netns exec ns_{0} exabgpcli --env {1} \
                        #announce route {2}/128 next-hop self
                #""".format(ns, envfile, prefix))
                cmd = textwrap.dedent("""
                    ip netns exec ns_{0} curl -s --form \
                        "command=announce route {1}/128 next-hop self" \
                        http://localhost:{2}/'
                """.format(ns, prefix, 5000))
                prefix = self.utils.incrementIPv6(prefix, "0:0:0:1::")
            else:
                #cmd = textwrap.dedent("""
                    #ip netns exec ns_{0} exabgpcli --env {1} \
                        #announce route {2}/24 next-hop self
                #""".format(ns, envfile, prefix))
                cmd = textwrap.dedent("""
                    ip netns exec ns_{0} curl -s --form \
                        "command=announce route {1}/24 next-hop self" \
                        http://localhost:{2}/'
                """.format(ns, prefix, 5000))
                prefix = self.utils.incrementIPv4(prefix, "0.0.1.0")
            output = self.utils.cmdexec(cmd)
            if "could not send command to ExaBGP" in output:
                self.error(output)
                return False
        return True

    def config_exabgp(self, enable, intf):
        retval = self.config_exabgp_one(enable, intf)
        #if retval and enable:
            #retval = self.control_exabgp(intf)
        return retval

    def apply_bgp(self, op, enable, intf):
        retval = self.config_exabgp(False, intf)
        if enable:
            retval = self.config_exabgp(True, intf)
        return retval

    def apply_bgp_route(self, enable, route):
        route.enable = enable
        return self.apply_bgp("", True, route.intf)

    def config_igmp(self, mode, intf, host):
        ns = "{}_{}".format(intf.name, 0)
        igmp_version = host.get("igmp_version", "v3")
        num_groups = self.utils.intval(host, "grp_num_groups", 1)
        ip4_addr = host.get("grp_ip_addr_start", "224.0.0.1")
        ip4_step = "0.0.1.0"

        self.error("TODO: config_igmp {} = {} {}".format(mode, intf.iface, host))

        # force IGMP version
        if igmp_version == "v2":
            cmd = "ip netns exec ns_{0} echo 2 > /proc/sys/net/ipv4/conf/veth1/force_igmp_version".format(ns)
        else:
            cmd = "ip netns exec ns_{0} echo 3 > /proc/sys/net/ipv4/conf/veth1/force_igmp_version".format(ns)
        self.utils.cmdexec(cmd)

        # add ip addresses
        for _ in range(num_groups):
            if mode in ["start", "join"]:
                cmd = "ip netns exec ns_{0} ip addr add {1}/32 dev veth1 autojoin".format(ns, ip4_addr)
            else:
                cmd = "ip netns exec ns_{0} ip addr del {1}/32 dev veth1".format(ns, ip4_addr)
            self.utils.cmdexec(cmd)
            ip4_addr = self.utils.incrementIPv4(ip4_addr, ip4_step)


if __name__ == '__main__':
    from port import ScapyStream
    from ut_streams import ut_stream_get

    Logger.setup()
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    packet = ScapyPacket(iface, 3, bool(not iface), False)

    #kwargs = ut_stream_get(0)
    #kwargs = ut_stream_get(0, mac_dst_mode='list', mac_dst=["00.00.00.00.00.02", "00.00.00.00.00.04", "00.00.00.00.00.06"])
    #kwargs = ut_stream_get(0, mac_src_mode='list', mac_src="00.00.00.00.00.02 00.00.00.00.00.04 00.00.00.00.00.06")
    kwargs = ut_stream_get(16)
    s = ScapyStream(0, 0, None, None, **kwargs)

    pwa = packet.build_first(s)
    while pwa:
        packet.logger.info("=======================================================")
        packet.logger.info(kwargs)
        packet.logger.info("=======================================================")
        # wait to proceed
        #if iface: raw_input("press any key to send packet")
        packet.send_packet(pwa, iface, "NA", pwa.left)
        pwa = packet.build_next(pwa)
        if pwa: time.sleep(1)

