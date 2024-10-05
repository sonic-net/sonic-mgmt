from scapy.all import Ether, IP, TCP, Raw, sendp
from time import sleep

eth_dst = "22:48:23:27:33:d8"
eth_src = "9a:50:c1:b1:9f:00"
src_ip = "10.0.0.1"
dst_ip = "10.0.0.37"
ip_ttl = 255
tcp_dport = 5000
tcp_sport = 1234

packet = (
    Ether(dst=eth_dst, src=eth_src) /
    IP(src=src_ip, dst=dst_ip, ttl=ip_ttl) /
    TCP(dport=tcp_dport, sport=tcp_sport, flags="S") /
    Raw(load="Hello World" * 100)
)

while True:
    print("Sending 1 SYN packet - {}:{} -> {}:{}".format(src_ip, tcp_sport, dst_ip, tcp_dport))
    sendp(packet, iface="eth0")
    print("\n")
    sleep(0.1)
