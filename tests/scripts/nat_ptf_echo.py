#!/usr/bin/env python

import socket
import sys


SO_BINDTODEVICE = 25


class TcpServer(object):
    def __init__(self, src_ip, src_port, vrf_src):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b'{}'.format(vrf_src))
        self.sock.settimeout(10)
        self.sock.bind((src_ip, src_port))
        self.sock.listen(5)


class TcpClient(object):
    def __init__(self, dst_ip, dst_port, src_ip, src_port, vrf_src, nat_dst_ip):
        if nat_dst_ip != "None":
                dst_ip = nat_dst_ip
                dst_port = src_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b'{}'.format(vrf_src))
        self.sock.settimeout(10)
        self.sock.bind((src_ip, src_port))
        self.sock.connect((dst_ip, dst_port))


class UdpServer(object):
    def __init__(self, src_ip, src_port, vrf_src):
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b'{}'.format(vrf_src))
        self.sock.settimeout(10)
        self.sock.bind((src_ip, src_port))


class UdpClient(object):
    def __init__(self, dst_ip, dst_port, src_ip, src_port, vrf_src, nat_dst_ip):
        if nat_dst_ip != "None":
                dst_ip = nat_dst_ip
                dst_port = src_port
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b'{}'.format(vrf_src))
        self.server_address = (dst_ip, dst_port)
        self.sock.settimeout(10)
        self.sock.bind((src_ip, src_port))
        

def udp_event_loop(udp_server, udp_client):
    try:
        udp_client.sock.sendto("ping", udp_client.server_address)
        _, address = udp_server.sock.recvfrom(4096)
        udp_server.sock.sendto("pong", address)
        udp_client.sock.recvfrom(4096)
    except  Exception as e:
        print(e)
    finally:
        udp_server.sock.close()
        udp_client.sock.close()


if __name__ == '__main__':
    proto = sys.argv[1]
    dst_ip = sys.argv[2]
    dst_port = int(sys.argv[3])
    src_ip = sys.argv[4]
    src_port = int(sys.argv[5])
    vrf_dst = sys.argv[6]
    vrf_src = sys.argv[7]
    nat_dst_ip = sys.argv[8]
    try:
        if proto == 'tcp':
            tcp_server = TcpServer(dst_ip, dst_port, vrf_dst)
            tcp_client = TcpClient(dst_ip, dst_port, src_ip, src_port, vrf_src, nat_dst_ip)
            client_socket, _ = tcp_server.sock.accept()
            tcp_server.sock.close()
            tcp_client.sock.close()
        if proto == 'udp':
            udp_server = UdpServer(dst_ip, dst_port, vrf_dst)
            udp_client = UdpClient(dst_ip, dst_port, src_ip, src_port, vrf_src, nat_dst_ip)
            udp_event_loop(udp_server, udp_client)
    except Exception as e:
        print(e)
