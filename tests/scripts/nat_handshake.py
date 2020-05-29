#!/usr/bin/env python

import socket
import sys

from scapy.all import *


def tcp_client(dst_ip, dst_port, src_ip, src_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    server_address = (dst_ip, dst_port)
    sock.bind((src_ip, src_port))
    sock.connect(server_address)
    try:
        # Send HTTP GET
        message = "GET / HTTP/1.0\r\nHost: {}\r\n\r\n".format(dst_ip)
        sock.sendall(message)
        # Look for the response
        expected_data = 'html'
        received = False
        while not received:
            data = sock.recv(4096)
            if expected_data in data:
                received = True
    except Exception as e:
        print(e)
    finally:
        sock.close()


def udp_client(dst_ip, dst_port, src_ip, src_port):
    # Create SNMP request
    packet = (IP(src=src_ip, dst=dst_ip)/UDP(sport=src_port, dport=dst_port)
              /SNMP(community="strcommunity",
                    PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))])))
    try:
        send(packet)
    except Exception as e:
        print(e)


def main():
    if len(sys.argv) != 6:
        raise Exception("Failed to get all mandatory options to start echo client")
    try:
        proto = sys.argv[1]
        dst_ip = sys.argv[2]
        dst_port = int(sys.argv[3])
        src_ip = sys.argv[4]
        src_port = int(sys.argv[5])
        if proto == 'tcp':
            tcp_client(dst_ip, dst_port, src_ip, src_port)
        if proto == 'udp':
            udp_client(dst_ip, dst_port, src_ip, src_port)
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
