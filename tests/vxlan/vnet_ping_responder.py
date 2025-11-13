import scapy.all as scapy2
import os
import time
import logging
import select

from multiprocessing import Process, Pipe, cpu_count

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
scapy2.conf.use_pcap = True


"""
Running on ptf

Put the VIP to be blocked into /tmp/vnet_monitor_block_ips.txt like below

root@2443abfbf6cd:/# cat /tmp/vnet_monitor_block_ips.txt
# Append the VIP to be blocked into this file
# Lines starting with # are ignored
192.168.0.2
"""

# The IPs in the block file will be read into blocked_list
BLOCK_FILE = "/tmp/vnet_monitor_block_ips.txt"
DEFAULT_VXLAN_PORT = 65330

# One process (block file monitor) will monitor the block file changes. When the file is changed,
# it will read the file and send updates to all consumer processes through pipes.

# The main process (producer) will receive packets on any "eth" interface and sends each received packet
# to one of the consumers through a pipe. It will rotate among consumers in round-robin fashion.

# Consumer processes will receive packets from the producer and also from the block file monitor process.
# When they receive a packet from the producer, they will analyze the packet and if necessary, generate
# a VNET ping reply and send it out on the same interface the packet was received on.
# When they receive an update from the block file monitor process, they will update their cached
# blocked lists.

# Design choice: We used pipes instead of queues for inter-process communication to avoid the locking overhead.


def read_block_file():
    blocked_list = set()
    vip_nh_blocked_list = {}
    with open(BLOCK_FILE) as f:
        lines = f.readlines()
    for line in lines:
        if line.startswith('#'):
            continue
        if ',' in line:
            vip, nh = line.split(',')
            if vip not in vip_nh_blocked_list:
                vip_nh_blocked_list[vip] = set()
            vip_nh_blocked_list[vip].add(nh.strip())
            print("Add VIP/nexthop {}/{} to block list".format(vip, nh.strip()))
        else:
            blocked_list.add(line.strip())
            print("Add IP {} to block list".format(line.strip()))
    return (blocked_list, vip_nh_blocked_list)


def send_update_to_consumers(write_conns, blocked_list, vip_nh_blocked_list):
    for write_conn in write_conns:
        write_conn.send((blocked_list, vip_nh_blocked_list))


def monitor_block_file(write_conns):
    cached_time = 0
    while True:
        time.sleep(1)
        try:
            stamp = os.stat(BLOCK_FILE).st_mtime
            if stamp != cached_time:
                cached_time = stamp
                blocked_list, vip_nh_blocked_list = read_block_file()
                send_update_to_consumers(write_conns, blocked_list, vip_nh_blocked_list)
        except FileNotFoundError:
            pass


def check_vip_nh_blocked(pkt, vip_nh_blocked_list):
    try:
        vxlan_layer_1 = scapy2.VXLAN(bytes(pkt['Raw']))
        if "IP" in vxlan_layer_1:
            ip_dst = vxlan_layer_1["IP"].dst
        else:
            ip_dst = vxlan_layer_1["IPv6"].dst

        if ip_dst in vip_nh_blocked_list:
            ip_dstnh = pkt["IP"].dst
            if ip_dstnh in vip_nh_blocked_list[ip_dst]:
                return True
        return False
    except Exception:
        return False


def generate_vnet_ping_reply(pkt, pkt_bytes, src_mac, blocked_list):
    # MAC address
    eth_src = src_mac
    ipver = 4
    try:
        vxlan_layer_1 = scapy2.VXLAN(bytes(pkt['Raw']))
        vxlan_layer_2 = scapy2.VXLAN(bytes(vxlan_layer_1['Raw']))
        eth_dst = vxlan_layer_2.dst
        # IP address
        if "IP" in vxlan_layer_2:
            ipver = 4
            ip_src = vxlan_layer_2["IP"].src
            ip_dst = vxlan_layer_2["IP"].dst
        else:
            ipver = 6
            ip_src = vxlan_layer_2["IPv6"].src
            ip_dst = vxlan_layer_2["IPv6"].dst
        if ip_src in blocked_list:
            return None
        if ipver == 4:
            reply = scapy2.Ether(dst=eth_dst, src=eth_src) \
                / scapy2.IP(src=ip_src, dst=ip_dst) / scapy2.UDP(sport=8000, dport=10000) \
                / scapy2.Raw(pkt_bytes[-12:])
        else:
            reply = scapy2.Ether(dst=eth_dst, src=eth_src) \
                / scapy2.IPv6(src=ip_src, dst=ip_dst) / scapy2.UDP(sport=8000, dport=10000) \
                / scapy2.Raw(pkt_bytes[-12:])

        return reply
    except Exception:
        return None


def respond_to_ping_requests(block_file_read_conn, packet_read_conn):
    # The IP addresses in this list will not get a response.
    blocked_list = set()
    # The VIP and NH combinations that will be blocked (<VIP>,<NH> pairs in the block file).
    vip_nh_blocked_list = {}
    epoll = select.epoll()  # Only works on Linux
    epoll.register(block_file_read_conn.fileno(), select.EPOLLIN)
    epoll.register(packet_read_conn.fileno(), select.EPOLLIN)
    while True:
        events = epoll.poll()
        for fileno, _ in events:  # No need to check the event type since only EPOLLIN is registered
            if fileno == block_file_read_conn.fileno():
                blocked_list, vip_nh_blocked_list = block_file_read_conn.recv()
            elif fileno == packet_read_conn.fileno():
                iface, pkt_bytes = packet_read_conn.recv()
                pkt = scapy2.Ether(pkt_bytes)
                if not check_vip_nh_blocked(pkt, vip_nh_blocked_list):
                    reply = generate_vnet_ping_reply(pkt, pkt_bytes, scapy2.get_if_hwaddr(iface), blocked_list)
                    if reply:
                        scapy2.sendp(reply, iface=iface, verbose=False)


def create_block_file_monitor_process(consumer_count):
    block_file_write_conns = []
    block_file_read_conns = []
    for _ in range(consumer_count):
        read_conn, write_conn = Pipe(duplex=False)
        block_file_read_conns.append(read_conn)
        block_file_write_conns.append(write_conn)
    block_file_process = Process(target=monitor_block_file, args=(block_file_write_conns,))
    return block_file_process, block_file_read_conns


def create_producer_listen_sockets():
    interfaces = scapy2.get_if_list()
    eth_interfaces = [iface for iface in interfaces if iface.startswith('eth')]
    listen_sockets = []
    for iface in eth_interfaces:
        try:
            sock = scapy2.conf.L2listen(iface=iface, filter='udp and port {}'.format(DEFAULT_VXLAN_PORT))
        except OSError:
            sock = None
        listen_sockets.append(sock)
    epoll = select.epoll()  # Only works on Linux
    for sock in listen_sockets:
        if sock:
            epoll.register(sock.fileno(), select.EPOLLIN)
    fd_to_iface_socket = {}  # Map file descriptor to (interface name, socket)
    for i in range(len(eth_interfaces)):
        if listen_sockets[i]:
            fd_to_iface_socket[listen_sockets[i].fileno()] = (eth_interfaces[i], listen_sockets[i])
    return epoll, fd_to_iface_socket


def create_consumers(consumers_count, block_file_read_conns):
    consumers = []
    packet_read_conns = []
    packet_write_conns = []
    for i in range(consumers_count):
        read_conn, write_conn = Pipe(duplex=False)
        packet_read_conns.append(read_conn)
        packet_write_conns.append(write_conn)
        consumer = Process(target=respond_to_ping_requests, args=(block_file_read_conns[i], packet_read_conns[i]))
        consumers.append(consumer)
    return consumers, packet_write_conns


def main():
    num_cpus = cpu_count()
    consumers_count = max(num_cpus - 2, 1)
    block_file_process, block_file_read_conns = create_block_file_monitor_process(consumers_count)
    epoll, fd_to_iface_socket = create_producer_listen_sockets()
    consumers, packet_write_conns = create_consumers(consumers_count, block_file_read_conns)
    try:
        block_file_process.start()
        for consumer in consumers:
            consumer.start()

        # Producer Loop (hot path)
        consumer_index = 0
        while True:
            events = epoll.poll()
            for fd, _ in events:  # No need to check the event type since only EPOLLIN is registered
                iface, sock = fd_to_iface_socket[fd]
                pkt = bytes(sock.recv())
                # Distribute packets to consumers in round-robin fashion
                packet_write_conns[consumer_index].send((iface, pkt))
                consumer_index = (consumer_index + 1) % consumers_count
    finally:
        block_file_process.terminate()
        for consumer in consumers:
            consumer.terminate()
        # sockets and pipes will be closed automatically on process exit


if __name__ == '__main__':
    main()
