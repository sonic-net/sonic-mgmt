import os
import zlib
import time
import copy
import random
import binascii
import socket
import afpacket
import traceback

from scapy.all import hexdump, sendp
try:
    from scapy.all import L2Socket
except Exception as exp:
    print(exp)
    from scapy.arch.linux import L2Socket
from scapy.packet import Padding
from scapy.layers.l2 import Ether, Dot1Q, ARP
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NA
from scapy.contrib.igmp import IGMP
from scapy.config import Conf
from scapy.utils import hexstr
from dicts import SpyTestDict
from utils import Utils
from utils import RunTimeException
from logger import Logger
from lock import Lock
from protocol import PacketProtocol
from interface import PacketInterface
from bgp_exabgp import ExaBgp
from dot1x import Dot1x
from dhcps import Dhcps

try:
    print("SCAPY VERSION = {}".format(Conf().version))
except Exception:
    print("SCAPY VERSION = UNKNOWN")

# dbg > 1 --- recv/send packet
# dbg > 2 --- recv/send packet summary
# dbg > 3 --- recv/send packet hex

stale_list_ignore = [
    "debug",
    "port_handle",
    "port_handle2",
    "stream_id",
    "mode",
    "rate_percent",  # TODO

    #
    "enable_stream",
    "enable_stream_only_gen",
    #

    # filtered stats
    "high_speed_result_analysis",  # TODO
    "vlan_id_tracking",
    "ip_dscp_tracking",
    "track_by",
    # filtered stats

    "ip_protocol",  # TODO

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

    def __init__(self, iface, dbg=0, dry=False, logger=None):
        self.dry = dry
        self.errs = []
        self.use_custom_exp = False
        self.logger = logger or Logger(dry)
        try:
            self.logger.info("SCAPY VERSION = {}".format(Conf().version))
        except Exception:
            self.logger.info("SCAPY VERSION = UNKNOWN")
        self.utils = Utils(self.dry, logger=self.logger)
        self.max_rate_pps = self.utils.get_env_int("SPYTEST_SCAPY_MAX_RATE_PPS", 100)
        self.dbg = dbg
        self.show_summary = bool(self.dbg > 2)
        self.hex = bool(os.getenv("SPYTEST_SCAPY_HEXDUMP", "0") != "0")
        self.iface = iface
        self.is_vde = not dry and iface.startswith("vde")
        self.stats_lock = Lock()
        self.tx_count = 0
        self.rx_count = 0
        self.rx_sock = None
        self.tx_sock = None
        self.tx_sock_failed = False
        self.finished = False
        self.mtu = 9194
        self.use_bridge = bool(os.getenv("SPYTEST_SCAPY_USE_BRIDGE", "1") != "0")
        self.logger.info("use_bridge = {}".format(self.use_bridge))
        self.pp = PacketProtocol(self)
        self.pi = PacketInterface(self)
        self.bgp = ExaBgp(self)
        self.dot1x = Dot1x(self)
        self.dhcps = Dhcps(self)
        self.cleanup()
        if iface and not self.dry:
            if self.use_bridge:
                # already init_bridge called in cleanup()
                # self.init_bridge(iface)
                self.os_system("ip link add name {0}-br type bridge".format(iface))
                self.os_system("ip link set dev {0} master {0}-br".format(iface))
                # let bridge proxy arp packets
                # self.os_system("sysctl -w net.ipv4.conf.{0}-br.proxy_arp=1".format(iface))
                self.os_system("ip link set dev {0}-br up".format(iface))
            self.os_system("ip link set dev {0} up".format(iface))
            self.os_system("ip link set dev {0} promisc on".format(iface))
            self.os_system("ip link set dev {0} mtu {1}".format(iface, self.mtu))
            if self.use_bridge:
                self.os_system("ip link set dev {0}-br mtu {1}".format(iface, self.mtu))
                # self.os_system("ip link set dev {0}-br mcast_snooping 0".format(iface))
                # self.os_system("sysctl -w net.ipv4.conf.{0}-br.bridge.multicast_snooping=0".format(iface))
                # self.os_system("echo 0 > /sys/devices/virtual/net/{0}-br/bridge/multicast_querier".format(iface))
                # self.os_system("echo 0 > /sys/devices/virtual/net/{0}-br/bridge/multicast_snooping".format(iface))
            # self.os_system("ip link del {0}-rx".format(iface))
            self.os_system("ip link add {0}-rx type dummy".format(iface))
            self.os_system("ip link set dev {0}-rx mtu {1}".format(iface, self.mtu))
            self.configure_ipv6(iface)
            self.os_system("tc qdisc del dev {0} ingress".format(iface))
            self.os_system("tc qdisc add dev {0} ingress".format(iface))
            # self.os_system("tc filter del dev {0} parent ffff: protocol all u32 match u8 0 0 action mirred egress mirror dev {0}-rx".format(iface))
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
            if self.use_bridge:
                self.os_system("ip link set dev {0}-br down".format(iface))
                self.os_system("ip link set dev {0} nomaster".format(iface))
                self.os_system("ip link del {0}-br".format(iface))
            self.os_system("ip link del {0}-rx".format(iface))
            time.sleep(1)

    def configure_ipv6(self, iface):
        iface_rx = "{0}-rx".format(iface)
        self.os_system("sysctl -w net.ipv6.conf.{}.forwarding=0".format(iface_rx))
        self.os_system("sysctl -w net.ipv6.conf.{}.accept_ra=0".format(iface_rx))
        self.os_system("sysctl -w net.ipv6.conf.{}.forwarding=1".format(iface))
        # self.os_system("sysctl -w net.ipv6.conf.{}.accept_ra=1".format(iface))
        # self.os_system("sysctl -w net.ipv6.conf.all.forwarding=0")

    def __del__(self):
        self.cleanup()

    @staticmethod
    def hex_str(pkt):
        return hexstr(pkt, onlyhex=1)

    def warn(self, *args, **kwargs):
        msg = self.logger.warning(*args, **kwargs)
        self.errs.append(msg)
        return msg

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
        self.stats_lock.acquire()
        self.tx_count = 0
        self.rx_count = 0
        self.stats_lock.release()

    def close_sock(self, sock):
        try:
            sock.close()
        except Exception:
            pass
        return None

    def cleanup(self):
        print("ScapyPacket {} cleanup...".format(self.iface))
        self.logger.info("ScapyPacket {} cleanup...".format(self.iface))
        self.bgp.cleanup()
        self.dot1x.cleanup()
        self.dhcps.cleanup()
        self.finished = True
        self.rx_sock = self.close_sock(self.rx_sock)
        self.tx_sock = self.close_sock(self.tx_sock)
        self.tx_sock_failed = False
        self.init_bridge(self.iface)
        self.finished = False

    def rx_open(self):
        if not self.iface or self.dry:
            return
        ETH_P_ALL = 3
        self.rx_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 12 * 1024)
        try:
            self.rx_sock.bind((self.iface + "-rx", 3))
        except Exception as exp:
            print("Exception in rx_open")
            msg = self.os_system("ifconfig")
            if not self.use_custom_exp:
                raise exp
            raise RunTimeException(exp, msg)
        afpacket.enable_auxdata(self.rx_sock)

    def set_link(self, status):
        msg = "link:{} status:{}".format(self.iface, status)
        self.logger.debug(msg)

    def readp(self, iface, port):

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
        self.stats_lock.acquire()
        self.rx_count = self.rx_count + 1
        self.stats_lock.release()
        self.trace_stats()

        if self.dbg > 1:
            cmd = "" if not self.show_summary else packet.command()
            msg = "readp:{} len:{} count:{} {}".format
            self.logger.debug(msg(iface, len(data), self.rx_count, cmd))

        if self.dbg > 3:
            self.trace_packet(packet, self.hex)

        # handle protocol packets
        self.pp.process(port, packet)

        return packet

    def sendp(self, pkt, data, iface, stream_name, left):
        self.stats_lock.acquire()
        self.tx_count = self.tx_count + 1
        self.stats_lock.release()
        self.trace_stats()

        if self.dbg > 2 or (self.dbg > 1 and left != 0):
            cmd = "" if not self.show_summary else pkt.command()
            msg = "sendp:{}:{} len:{} count:{} {}".format
            self.logger.debug(msg(iface, stream_name, len(data), self.tx_count, cmd))

        if self.dbg > 3:
            self.trace_packet(pkt, self.hex)

        return self.send(data, iface)

    def mkcmd(self, data):
        try:
            pkt = Ether(data)
            cmd = "" if not self.show_summary else pkt.command()
        except Exception:
            cmd = "???"
        return cmd

    def expmsg(self, data, iface, exp, func):
        cmd = self.mkcmd(data)
        return "{}:{} len:{} {} {}".format(func, iface, len(data), cmd, str(exp))

    def send(self, data, iface, trace=False):

        if trace and self.dbg > 2:
            cmd = self.mkcmd(data)
            msg = "send:{} len:{} count:{} {}".format
            self.logger.debug(msg(iface, len(data), self.tx_count, cmd))

        if self.dry:
            return

        if not self.tx_sock:
            try:
                self.tx_sock = L2Socket(iface)
                self.tx_sock_failed = False
            except Exception as exp:
                func = self.logger.debug if self.tx_sock_failed else self.error
                self.tx_sock_failed = True
                func("Failed to create L2Socket {} {}".format(iface, exp))

        err1, err2 = "", ""

        # try sending using sock
        if self.tx_sock:
            try:
                return self.tx_sock.send(data)
            except Exception as exp:
                err1 = self.expmsg(data, iface, exp, "sock-send")

        # try sending using legacy method
        try:
            return sendp(data, iface=iface, verbose=False)
        except Exception as exp:
            err2 = self.expmsg(data, iface, exp, "scapy-sendp")
            if self.is_vde:
                self.os_system("ip link set dev {0} up".format(iface))

        # trace errors
        self.logger.error("Failed to send normal {}".format(err1))
        self.logger.error("Failed to send legacy {}".format(err2))

    def trace_stats(self):
        # self.logger.debug("Name: {} RX: {} TX: {}".format(self.iface, self.rx_count, self.tx_count))
        pass

    def show_pkt(self, pkt, force=False):
        if force:
            self.utils.exec_func(None, pkt.show2)
            return self.utils.exec_func(None, pkt.summary)
        if self.dbg > 4:
            return self.utils.exec_func(None, pkt.show2)
        if self.dbg > 3:
            return self.utils.exec_func(None, pkt.summary)
        return ""

    def trace_packet(self, pkt, hex=True, fields=True, force=False):
        if not fields and not hex:
            return
        if isinstance(pkt, str):
            pkt = Ether(pkt)
        if fields:
            self.show_pkt(pkt, force)
        if hex:
            self.logger.debug(hexdump(pkt, dump=True))

    def send_packet(self, pwa, iface, stream_name, left):
        if pwa.padding:
            strpkt = self.utils.tobytes(pwa.pkt / pwa.padding)
        else:
            strpkt = self.utils.tobytes(pwa.pkt)

        # insert stream id before CRC
        if pwa.add_signature:
            sid = pwa.stream.get_sid()
            sid = sid or "DeadBeef"
            if sid:
                sid = binascii.unhexlify(sid)
                strpkt = strpkt[:-len(sid)] + sid

        try:
            crc1 = '{:08x}'.format(socket.htonl(zlib.crc32(strpkt) & 0xFFFFFFFF))
            crc = binascii.unhexlify(crc1)
        except Exception:
            crc = binascii.unhexlify('00' * 4)
        bstr = strpkt + self.utils.tobytes(crc)
        self.sendp(Ether(bstr), bstr, iface, stream_name, left)
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
        for index, val in enumerate(values):
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

    def get_hex(self, d, prop, default):
        val = d.get(prop, "{}".format(default))
        try:
            return int(str(val), 16)
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
        # udp.len
        # udp.chksum
        return udp

    def build_tcp(self, kws):
        tcp = TCP()
        tcp.sport = self.pop_int(kws, "tcp_src_port", 0)
        tcp.dport = self.pop_int(kws, "tcp_dst_port", 0)
        tcp.seq = self.pop_int(kws, "tcp_seq_num", 0)
        tcp.ack = self.pop_int(kws, "tcp_ack_num", 0)
        flags = []
        if self.pop_int(kws, "tcp_syn_flag", 0):
            flags.append('S')
        if self.pop_int(kws, "tcp_fin_flag", 0):
            flags.append('F')
        if self.pop_int(kws, "tcp_urg_flag", 0):
            flags.append('U')
        if self.pop_int(kws, "tcp_psh_flag", 0):
            flags.append('P')
        if self.pop_int(kws, "tcp_ack_flag", 0):
            flags.append('A')
        if self.pop_int(kws, "tcp_rst_flag", 0):
            flags.append('R')
        tcp.flags = "".join(flags)
        # tcp.dataofs
        # tcp.reserved
        tcp.window = self.pop_int(kws, "tcp_window", 0)
        # tcp.chksum
        # tcp.urgptr
        # tcp.options
        return tcp

    def build_icmp(self, kws):
        icmp = ICMP()
        icmp.type = self.pop_int(kws, "icmp_type", 0)
        # icmp.code = Driver.getConstValue(icmpCfg.code)
        # TODO: icmp_type_count, icmp_type_mode
        return icmp

    def build_icmp6(self, kws):
        icmp_type = self.pop_int(kws, "icmp_type", 0)
        if icmp_type == 136:
            icmp = ICMPv6ND_NA()
            icmp.R = self.pop_int(kws, "icmp_ndp_nam_r_flag", 1)
            icmp.S = self.pop_int(kws, "icmp_ndp_nam_s_flag", 0)
            icmp.O = self.pop_int(kws, "icmp_ndp_nam_o_flag", 1)  # noqa: ignore=E741
            icmp.tgt = self.pop_str(kws, "icmp_target_addr", "::")
        else:
            icmp = ICMP()
        return icmp

    def build_igmp(self, kws):
        igmp = IGMP()
        # igmp.mrcode
        igmp.gaddr = self.pop_str(kws, "igmp_group_addr", "0.0.0.0")
        # igmp.chksum = 0
        igmp_msg_type = self.pop_str(kws, "igmp_msg_type", "report")
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

    def log_stream_kws(self, stream, msg):
        self.logger.debug("{}: {} = {}".format(msg, stream.stream_id, stream.kws))

    def dbg_stream_kws(self, stream, **kwargs):
        stream.kws.setdefault("debug", {})
        for name, value in kwargs.items():
            stream.kws["debug"][name] = value

    def fill_emulation_params(self, stream):

        circuit_endpoint_type = stream.kws.pop("circuit_endpoint_type", "ipv4")
        self.log_stream_kws(stream, "INITIAL")

        src_info, dst_info = {}, {}
        src_intf = stream.kws.pop("emulation_src_handle", None)
        dst_intf = stream.kws.pop("emulation_dst_handle", None)

        if src_intf:
            intf = src_intf.intf
            if src_intf != intf:
                self.logger.debug("SRC Protocol: {} = {}".format(src_intf.handle, src_intf.kws))
                self.logger.debug("SRC Parent: {} = {}".format(intf.handle, intf.kws))

        if dst_intf:
            intf = dst_intf.intf
            if dst_intf != intf:
                self.logger.debug("DST Protocol: {} = {}".format(dst_intf.handle, dst_intf.kws))
                self.logger.debug("DST Parent: {} = {}".format(intf.handle, intf.kws))

        if dst_intf:
            intf = dst_intf.intf
            ns = "{}_{}".format(intf.name, 0)
            dst_info = self.utils.get_ip_addr_dev("veth1", ns)[0]
            self.dbg_stream_kws(stream, dst_ns=ns, dst_info=dst_info)
            if circuit_endpoint_type == "ipv4":
                dst_info.pop("inet6", "")
            elif circuit_endpoint_type == "ipv6":
                dst_info.pop("inet", "")
            stream.kws["mac_dst"] = [dst_info.get("link/ether", "00:00:00:00:00:00")]
            stream.kws["mac_dst"] = "00:00:00:00:00:00"
            self.log_stream_kws(stream, "dst_intf")

        if src_intf:
            intf = src_intf.intf
            ns = "{}_{}".format(intf.name, 0)
            src_info = self.utils.get_ip_addr_dev("veth1", ns)[0]
            self.dbg_stream_kws(stream, src_ns=ns, dst_info=src_info)
            if circuit_endpoint_type == "ipv4":
                src_info.pop("inet6", "")
            elif circuit_endpoint_type == "ipv6":
                src_info.pop("inet", "")
            stream.kws["mac_src"] = [src_info.get("link/ether", "00:00:00:00:00:00")]
            stream.kws["mac_dst"] = self.get_arp_mac(intf, stream.kws["mac_dst"])
            self.log_stream_kws(stream, "src_intf")

        # read params from emulation interfaces
        if src_intf:
            intf = src_intf.intf
            intf_ip_addr = src_info.get("inet", "0.0.0.0").split("/")[0]
            intf_ip_addr = intf.kws.get("intf_ip_addr", intf_ip_addr)
            ipv6_intf_addr = src_info.get("inet6", "").split("/")[0]
            ipv6_intf_addr = intf.kws.get("ipv6_intf_addr", ipv6_intf_addr)
            count = self.utils.intval(intf.kws, "count", 1)
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
            self.log_stream_kws(stream, "src_info")

        if dst_intf:
            intf = dst_intf.intf
            intf_ip_addr = dst_info.get("inet", "").split("/")[0]
            intf_ip_addr = intf.kws.get("intf_ip_addr", intf_ip_addr)
            ipv6_intf_addr = dst_info.get("inet6", "").split("/")[0]
            ipv6_intf_addr = intf.kws.get("ipv6_intf_addr", ipv6_intf_addr)
            count = self.utils.intval(intf.kws, "count", 1)
            if dst_intf.handle.startswith("bgp-route"):
                count = self.utils.intval(dst_intf.kws, "num_routes", 1)
                intf_ip_addr = dst_intf.kws.get("prefix", intf_ip_addr)
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
            self.log_stream_kws(stream, "dst_info")

        self.log_stream_kws(stream, "UPDATED")

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
        l2_encap = self.pop_str(kws, "l2_encap", "ethernet_ii_vlan")
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
        if transmit_mode not in ["continuous", "continuous_burst", "single_burst", "single_pkt", "multi_burst"]:
            self.logger.todo("unsupported", "transmit_mode", transmit_mode)
            return None

        data_pattern = self.pop_str(kws, "data_pattern", "")
        pkts_per_burst = self.pop_int(kws, "pkts_per_burst", 1)
        ethernet_value = self.pop_hex(kws, "ether_type", 0)
        ethernet_value = self.pop_hex(kws, "ethernet_value", ethernet_value)
        length_mode = self.pop_str(kws, "length_mode", "fixed")
        l3_length = self.pop_int(kws, "l3_length", 110)
        data_pattern_mode = self.pop_str(kws, "data_pattern_mode", "fixed")

        mac_dst_mode = kws.get("mac_dst_mode", "fixed").strip()
        if mac_dst_mode not in ["fixed", "increment", "decrement", "list"]:
            self.error("unhandled option mac_dst_mode = {}".format(mac_dst_mode))
        mac_src_mode = kws.get("mac_src_mode", "fixed").strip()
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
            arp.psrc = self.pop_str(kws, "ip_src_addr", "0.0.0.0")
            arp.pdst = self.pop_str(kws, "ip_dst_addr", "192.0.0.1")
            arp_oper = self.pop_str(kws, "arp_operation", "arpRequest")
            if arp_oper == "arpRequest":
                arp.op = 1
            elif arp_oper in ["arpResponse", "arpReply"]:
                arp.op = 2
            else:
                self.logger.debug("unknown ARP operation: {}".format(arp_oper))
                arp = None
            if arp:
                pkt = self.check(pkt / arp)
        elif l3_protocol == "ipv4":
            ip = IP()
            # ip.id
            # ip.chksum
            ip.src = self.pop_str(kws, "ip_src_addr", "0.0.0.0")
            ip.dst = self.pop_str(kws, "ip_dst_addr", "192.0.0.1")
            ip.ttl = self.pop_int(kws, "ip_ttl", 255)
            # ip.frag
            # ip.len
            # ip.flags
            # ip.options
            proto = self.pop_int(kws, "ip_proto", -1)
            if proto >= 0:
                ip.proto = proto
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
            pkt = self.check(pkt / ip)

            # add l4_protocol
            if l4_protocol in ["udp"]:
                udp = self.build_udp(kws)
                pkt = self.check(pkt / udp)
            elif l4_protocol in ["tcp"]:
                tcp = self.build_tcp(kws)
                pkt = self.check(pkt / tcp)
            elif l4_protocol in ["icmp"]:
                icmp = self.build_icmp(kws)
                pkt = self.check(pkt / icmp)
            elif l4_protocol in ["igmp"]:
                igmp = self.build_igmp(kws)
                if igmp:
                    pkt = self.check(pkt / igmp)
            elif l4_protocol:
                self.logger.todo("unsupported-ipv4", "l4_protocol", l4_protocol)
        elif l3_protocol == "ipv6":
            ip6 = IPv6()
            ip6.src = self.pop_str(kws, "ipv6_src_addr", "fe80:0:0:0:0:0:0:12")
            ip6.dst = self.pop_str(kws, "ipv6_dst_addr", "fe80:0:0:0:0:0:0:22")
            ip6.hlim = self.pop_int(kws, "ipv6_hop_limit", 255)
            ip6.tc = self.pop_int(kws, "ipv6_traffic_class", 255)
            nh = self.pop_int(kws, "ipv6_next_header", 0)
            if nh:
                ip6.nh = nh
            # add l4_protocol
            pkt = self.check(pkt / ip6)
            if l4_protocol in ["udp"]:
                udp = self.build_udp(kws)
                pkt = self.check(pkt / udp)
            elif l4_protocol in ["tcp"]:
                tcp = self.build_tcp(kws)
                pkt = self.check(pkt / tcp)
            elif l4_protocol in ["icmp"]:
                icmp = self.build_icmp6(kws)
                pkt = self.check(pkt / icmp)
            elif l4_protocol in ["igmp"]:
                igmp = self.build_igmp(kws)
                if igmp:
                    pkt = self.check(pkt / igmp)
            elif l4_protocol:
                self.logger.todo("unsupported-ipv6", "l4_protocol", l4_protocol)
        elif l3_protocol:
            self.logger.todo("unsupported", "l3_protocol", l3_protocol)
            return None

        # insert VLAN header if required
        if l2_encap in ["ethernet_ii_vlan", "ethernet_ii"] and vlan_id > 0 and vlan_en == "enable":
            payload, payload_type = pkt.payload, pkt.type
            pkt.remove_payload()
            pkt.type = 0x8100
            pkt = self.check(pkt / Dot1Q(vlan=vlan_id, id=vlan_cfi, prio=vlan_prio, type=payload_type) / payload)
            # self.trace_packet(pkt)

        # handle transmit_mode
        if transmit_mode in ["single_burst", "multi_burst"]:
            left = pkts_per_burst
        elif transmit_mode == "single_pkt":
            left = 1
        else:
            left = rate_pps * duration2

        # append the data pattern if specified
        if data_pattern:
            padding = Padding()
            tmp_pattern = ''.join(c for c in data_pattern if c not in ' ')
            tmp_pattern = binascii.unhexlify(tmp_pattern)
            padLen = int(frame_size - len(pkt) - 4 - len(padding))
            if len(tmp_pattern) > padLen:
                padding = Padding(tmp_pattern[:padLen])
            else:
                padding = Padding(tmp_pattern)
            pkt = self.check(pkt / padding)

        # update padding length based on frame_size
        add_signature = False
        if length_mode == "fixed":
            padLen = int(frame_size - len(pkt) - 4)
            if padLen > 0:
                padding = Padding(binascii.unhexlify('00' * padLen))
                pkt = self.check(pkt / padding)
                add_signature = True

        # verify unhandled options
        for key, value in kws.items():
            if key not in stale_list_ignore:
                self.error("unhandled option {} = {}".format(key, value))

        # Adjust the Ether Type
        if pkt.type == 0x9000:
            pkt.type = len(pkt)

        pwa = SpyTestDict()
        pwa.add_signature = add_signature
        pwa.pkt = pkt
        pwa.left = left
        pwa.burst_sent = 0
        pwa.pkts_per_burst = pkts_per_burst
        pwa.transmit_mode = transmit_mode
        if rate_pps > self.max_rate_pps:
            self.warn("drop the rate from {} to {}".format(rate_pps, self.max_rate_pps))
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

        if self.dbg > 3:
            self.trace_packet(pkt)
            self.logger.debug(pwa)

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
            frame_size = random.randrange(pwa.frame_size_min, pwa.frame_size_max + 1)
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
        mac_src_mode = pwa.stream.kws.get("mac_src_mode", "fixed").strip()
        mac_src_step = pwa.stream.kws.get("mac_src_step", "00:00:00:00:00:01")
        mac_src_count = self.utils.intval(pwa.stream.kws, "mac_src_count", 0)
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
        mac_dst_mode = pwa.stream.kws.get("mac_dst_mode", "fixed").strip()
        mac_dst_step = pwa.stream.kws.get("mac_dst_step", "00:00:00:00:00:01")
        mac_dst_count = self.utils.intval(pwa.stream.kws, "mac_dst_count", 0)
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
            arp_src_hw_mode = pwa.stream.kws.get("arp_src_hw_mode", "fixed").strip()
            arp_src_hw_step = pwa.stream.kws.get("arp_src_hw_step", "00:00:00:00:00:01")
            arp_src_hw_count = self.utils.intval(pwa.stream.kws, "arp_src_hw_count", 0)
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
            arp_dst_hw_mode = pwa.stream.kws.get("arp_dst_hw_mode", "fixed").strip()
            arp_dst_hw_step = pwa.stream.kws.get("arp_dst_hw_step", "00:00:00:00:00:01")
            arp_dst_hw_count = self.utils.intval(pwa.stream.kws, "arp_dst_hw_count", 0)
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
            ip_src_mode = pwa.stream.kws.get("ip_src_mode", "fixed").strip()
            ip_src_step = pwa.stream.kws.get("ip_src_step", "0.0.0.1")
            ip_src_count = self.utils.intval(pwa.stream.kws, "ip_src_count", 0)
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
            ip_dst_mode = pwa.stream.kws.get("ip_dst_mode", "fixed").strip()
            ip_dst_step = pwa.stream.kws.get("ip_dst_step", "0.0.0.1")
            ip_dst_count = self.utils.intval(pwa.stream.kws, "ip_dst_count", 0)
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
            ipv6_src_mode = pwa.stream.kws.get("ipv6_src_mode", "fixed").strip()
            ipv6_src_step = pwa.stream.kws.get("ipv6_src_step", "::1")
            ipv6_src_count = self.utils.intval(pwa.stream.kws, "ipv6_src_count", 0)
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
            ipv6_dst_mode = pwa.stream.kws.get("ipv6_dst_mode", "fixed").strip()
            ipv6_dst_step = pwa.stream.kws.get("ipv6_dst_step", "::1")
            ipv6_dst_count = self.utils.intval(pwa.stream.kws, "ipv6_dst_count", 0)
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
            vlan_id_mode = pwa.stream.kws.get("vlan_id_mode", "fixed").strip()
            vlan_id_step = self.utils.intval(pwa.stream.kws, "vlan_id_step", 1)
            vlan_id_count = self.utils.intval(pwa.stream.kws, "vlan_id_count", 0)
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
            tcp_src_port_mode = pwa.stream.kws.get("tcp_src_port_mode", "fixed").strip()
            tcp_src_port_step = self.utils.intval(pwa.stream.kws, "tcp_src_port_step", 1)
            tcp_src_port_count = self.utils.intval(pwa.stream.kws, "tcp_src_port_count", 0)
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
            tcp_dst_port_mode = pwa.stream.kws.get("tcp_dst_port_mode", "fixed").strip()
            tcp_dst_port_step = self.utils.intval(pwa.stream.kws, "tcp_dst_port_step", 1)
            tcp_dst_port_count = self.utils.intval(pwa.stream.kws, "tcp_dst_port_count", 0)
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
            udp_src_port_mode = pwa.stream.kws.get("udp_src_port_mode", "fixed").strip()
            udp_src_port_step = self.utils.intval(pwa.stream.kws, "udp_src_port_step", 1)
            udp_src_port_count = self.utils.intval(pwa.stream.kws, "udp_src_port_count", 0)
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
            udp_dst_port_mode = pwa.stream.kws.get("udp_dst_port_mode", "fixed").strip()
            udp_dst_port_step = self.utils.intval(pwa.stream.kws, "udp_dst_port_step", 1)
            udp_dst_port_count = self.utils.intval(pwa.stream.kws, "udp_dst_port_count", 0)
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
            if pwa.left <= 0:
                return None
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
            if not pwa:
                return None

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
        return (1.0 * pwa.pkts_per_burst) / float(pps)

    def match_stream(self, stream, pkt):
        sid = stream.get_sid()
        if not sid:
            return False
        sid = binascii.unhexlify(sid)
        strpkt = self.utils.tobytes(pkt)
        sig = strpkt[-len(sid) - 4:-4]
        msg = "{} {}".format(binascii.hexlify(sid), binascii.hexlify(sig))
        if sid == sig:
            self.logger.debug("{}: CMP0: {}".format(self.iface, msg))
            return True
        if self.dbg > 2:
            self.logger.debug("{}: CMP1: {}".format(self.iface, msg))
            self.trace_packet(pkt, hex=True, force=True)
        return False

    def if_create(self, intf):
        return self.pi.if_create(intf)

    def if_delete(self, intf, exiting=False):
        if exiting:
            self.bgp.stop()
            self.dot1x.stop()
            self.dhcps.stop()
        return self.pi.if_delete(intf)

    def if_validate(self, intf):
        return self.pi.if_validate(intf)

    def if_send_arp(self, intf):
        return self.pi.if_send_arp(intf)

    def get_arp_mac(self, intf, default, try_cache=True):
        return self.pi.get_arp_mac(intf, default, try_cache)

    def ping(self, intf, ping_dst, index=0):
        return self.pi.ping(intf, ping_dst, index)

    def send_arp(self, intf, index=0):
        return self.pi.send_arp(intf, index)

    def log_large_file(self, fname):
        size = self.utils.wc_l(fname)
        if self.dbg > 2 or size <= 50:
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

    def kill_by_pidfile(self, pidfile, ns=None):
        if not os.path.exists(pidfile):
            return
        self.logger.info(self.utils.cat_file(pidfile))
        cmd = "pkill -F {}".format(pidfile)
        if ns:
            out = self.utils.nsexec(ns, cmd)
        else:
            out = self.utils.cmdexec(cmd)
        self.logger.info(out)
        self.os_system("rm -f {}".format(pidfile))

    def control_bgp(self, op, intf):
        return self.bgp.control(op, intf)

    def control_bgp_route(self, op, route):
        return self.bgp.control_route(op, route)

    def config_igmp(self, mode, intf, host):
        self.pp.igmp_tx(mode, intf, host)

    def control_igmp_querier(self, mode, intf, querier):
        querier.enable = bool(mode == "start")
        self.pp.igmp_tx_query(intf, querier)

    def control_ospf(self, mode, intf, session):
        return True

    def control_dhcpc(self, group, port, **kws):
        params = {"renew": 3, "rebind": 4, "release": 5, "bind": 0}
        param = params.get(kws.get("action"), 0)
        ip_version = self.utils.intval(kws, "ip_version", 4)
        self.pp.dhcp_tx(port, group, param, ip_version=ip_version)
        return True

    def control_dhcps(self, server, intf, **kws):
        if os.getenv("SPYTEST_SCAPY_DHCPS", "1") == "2":
            return self.dhcps.control(server, intf, **kws)
        mode = kws.get("mode", "reset")
        action = kws.get("action", mode)
        ip_version = self.utils.intval(kws, "ip_version", 4)
        ns = "{}_{}".format(intf.name, 0)

        if server.dhcp_relay_agents:
            ent = list(server.dhcp_relay_agents.values())[0]
            start = ent.kws.get("relay_agent_ipaddress_pool", "0.0.0.0")
            step = ent.kws.get("relay_agent_ipaddress_step", "0.0.0.0")
            count = self.utils.intval(ent.kws, "relay_agent_ipaddress_count", 1)
        elif ip_version == 6:
            start = server.kws.get("addr_pool_start_addr", "2000::1")
            start = server.kws.get("ipaddress_pool", start)
            step = server.kws.get("step", "::1")
            count = self.utils.intval(server.kws, "addr_pool_addresses_per_server", 1)
            count = self.utils.intval(server.kws, "ipaddress_count", count)
        else:
            start = server.kws.get("ipaddress_pool", "0.0.0.0")
            step = server.kws.get("ipaddress_step", "0.0.0.1")
            count = self.utils.intval(server.kws, "ipaddress_count", 1)

        end = start
        for _ in range(count):
            if ip_version == 6:
                end = self.utils.incrementIPv6(end, step)
            else:
                end = self.utils.incrementIPv4(end, step)

        # kill existing server if any
        pidfile = self.logger.mkfile("dhcpd", ns, "pid")
        self.kill_by_pidfile(pidfile, ns)

        if action in ["delete", "reset"]:
            return True

        # start dhcpd
        logfile = self.logger.mkfile("dhcpd", ns, "log")
        cmd = "dnsmasq -i veth1 -p0"
        cmd = "{} --dhcp-range={},{}".format(cmd, start, end)
        cmd = "{} --pid-file={}".format(cmd, pidfile)
        cmd = "{} --log-queries".format(cmd)
        cmd = "{} --log-dhcp".format(cmd)
        cmd = "{} --log-facility={}".format(cmd, logfile)
        output = self.utils.nsexec(ns, cmd)
        self.logger.debug("{} -- {}".format(cmd, output))
        if "dnsmasq: bad command line options" in output:
            return False
        self.logger.register_log(logfile)
        return True

    def control_dot1x(self, mode, client):
        if os.getenv("SPYTEST_SCAPY_DOT1X_IMPL", "1") == "2":
            return self.dot1x.control(mode, client)
        if mode in ["start"]:
            client.mode = mode
            client.state = "init"
            self.pp.dot1x_tx(client.port, client)
        elif mode in ["stop", "abort", "logout"]:
            client.state = "logoff"
            self.pp.dot1x_tx(client.port, client)
            client.mode = "stop"
        return True
