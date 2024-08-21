import scapy.all as scapy2
import os
import time
import logging
from threading import Thread

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
scapy2.conf.use_pcap = True


"""
Running on ptf

Put the VIP to be blocked into /tmp/vnet_monitor_block_ips.txt like below

root@2443abfbf6cd:/# cat /tmp/vnet_monitor_block_ips.txt
# Append the VIP to be blocked into this file
# Line starts with # is ignored
192.168.0.2
"""

# The IPs in the block file will be read into blocked_list
BLOCK_FILE = "/tmp/vnet_monitor_block_ips.txt"
DEFAULT_VXLAN_PORT = 65330

# The IP address in this list will not get response
blocked_list = set()


class Interface(object):
    ETH_P_ALL = 0x03
    RCV_TIMEOUT = 1000
    RCV_SIZE = 4096

    def __init__(self, iface):
        self.iface = iface
        self.socket = None
        self.mac_address = scapy2.get_if_hwaddr(iface)
        self.bind()

    def close(self):
        if self.socket:
            self.socket.close()

    def __del__(self):
        if self.socket:
            self.socket.close()

    def bind(self):
        try:
            self.socket = scapy2.conf.L2listen(iface=self.iface, filter='udp and port {}'.format(DEFAULT_VXLAN_PORT))
        except OSError:
            self.socket = None

    def handler(self):
        return self.socket

    def recv(self):
        sniffed = self.socket.recv()
        pkt = sniffed[0]
        binpkt = bytes(pkt)
        return binpkt

    def send(self, data):
        scapy2.sendp(data, iface=self.iface, verbose=False)

    def mac(self):
        return self.mac_address

    def name(self):
        return self.iface


class Poller(object):
    def __init__(self, interface):
        self.thread_handler = None
        self.interface = interface
        self.src_mac = interface.mac()
        self.working = False

    def action(self):
        while self.working and self.interface.handler():
            data = self.interface.recv()
            reply = self.generate_vnet_ping_reply(data, self.src_mac)
            if reply:
                self.interface.send(reply)

    def generate_vnet_ping_reply(self, data, src_mac):
        pkt = scapy2.Ether(data)
        # MAC address
        eth_src = src_mac
        ipver = 4
        try:
            vxlan_layer_1 = scapy2.VXLAN(bytes(pkt['Raw']))
            vxlan_layer_2 = scapy2.VXLAN(bytes(vxlan_layer_1['Raw']))
            eth_dst = vxlan_layer_2.dst
            # IP address
            if 'IP' in vxlan_layer_2:
                ipver = 4
                ip_src = vxlan_layer_2['IP'].src
                ip_dst = vxlan_layer_2['IP'].dst
            else:
                ipver = 6
                ip_src = vxlan_layer_2['IPv6'].src
                ip_dst = vxlan_layer_2['IPv6'].dst
            if ip_src in blocked_list:
                return None
            if ipver == 4:
                reply = scapy2.Ether(dst=eth_dst, src=eth_src) \
                    / scapy2.IP(src=ip_src, dst=ip_dst) / scapy2.UDP(sport=8000, dport=10000) / scapy2.Raw(data[-12:])
            else:
                reply = scapy2.Ether(dst=eth_dst, src=eth_src) \
                    / scapy2.IPv6(src=ip_src, dst=ip_dst) / scapy2.UDP(sport=8000, dport=10000) / scapy2.Raw(data[-12:])

            return reply
        except Exception:
            return None

    def start(self):
        self.working = True
        self.thread_handler = Thread(target=self.action)
        self.thread_handler.start()

    def stop(self):
        if self.thread_handler:
            self.working = False
            self.interface.close()
            self.thread_handler.join()


def read_block_file():
    blocked_list.clear()
    with open(BLOCK_FILE) as f:
        lines = f.readlines()
    for line in lines:
        if line.startswith('#'):
            continue
        blocked_list.add(line.strip())
    print("Add IP {} to block list".format(blocked_list))


def watch_block_file():
    cached_time = 0
    while True:
        time.sleep(1)
        try:
            stamp = os.stat(BLOCK_FILE).st_mtime
            if stamp != cached_time:
                cached_time = stamp
                read_block_file()
        except FileNotFoundError:
            pass


def main():
    pollers = []
    iface_list = scapy2.get_if_list()
    for iface_name in iface_list:
        if iface_name.startswith('eth'):
            poller = Poller(Interface(iface_name))
            poller.start()
            pollers.append(poller)
    watch_block_file()


if __name__ == '__main__':
    main()
