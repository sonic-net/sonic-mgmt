#########################################################################
#
# Utils in this file:
# ip_to_int(ipstr)
# int_to_ip(n)
# incr_ipv4(ipaddr, mask=32, step=1)
# range_ipv4(start_ip, count, mask=32)
# network(ipaddr, mask=24)
# ipv6_to_int(ipv6_addr)
# int_to_ipv6(i)
# incr_ipv6(ipaddr, mask=128, step=1)
# range_ipv6(start_ip, count, mask=128)
# variance(expected, actual, tolerance)
# expand_range(list)
#
#########################################################################

import re
import struct
import socket
import binascii

def ip_to_int(ipstr):
    return struct.unpack('!I', socket.inet_aton(ipstr))[0]

def int_to_ip(n):
    return socket.inet_ntoa(struct.pack('!I', n))

def incr_ipv4(ipaddr, mask=32, step=1):
    # To separate the mask if provided with ip.
    ipaddr,save_mask = [ipaddr, ''] if ipaddr.find('/') == -1 else ipaddr.split('/')
    ip_int = ip_to_int(ipaddr)
    # Saving the diff value.
    ip_int_old = ip_int
    ip_int >>= 32 - mask
    ip_int <<= 32 - mask
    ip_diff = ip_int_old - ip_int
    # Actual logic.
    ip_int >>= 32 - mask
    ip_int += step
    ip_int <<= 32 - mask
    ip_int += ip_diff
    ipaddr = int_to_ip(ip_int)
    ipaddr = '/'.join([ipaddr,save_mask]) if save_mask != '' else ipaddr
    return ipaddr

def range_ipv4(start_ip, count, mask=32):
    ip_list = []
    count = int(count)
    mask = int(mask)
    for _ in range(count):
        ip_list.append(start_ip)
        start_ip = incr_ipv4(start_ip, mask)

    return ip_list

def network(ipaddr, mask=24):
    ip_int = ip_to_int(ipaddr)
    ip_int >>= 32 - mask
    ip_int <<= 32 - mask
    return int_to_ip(ip_int)

def ipv6_to_int(ipv6_addr):
    return int(binascii.hexlify(socket.inet_pton(socket.AF_INET6, ipv6_addr)), 16)

def int_to_ipv6(i):
    return socket.inet_ntop(socket.AF_INET6, binascii.unhexlify(hex(i)[2:].replace('L', '')))

def incr_ipv6(ipaddr, mask=128, step=1):
    # To separate the mask if provided with ipv6.
    ipaddr,save_mask = [ipaddr, ''] if ipaddr.find('/') == -1 else ipaddr.split('/')
    ip_int = ipv6_to_int(ipaddr)
    # Saving the diff value.
    ip_int_old = ip_int
    ip_int >>= 128 - mask
    ip_int <<= 128 - mask
    ip_diff = ip_int_old - ip_int
    # Actual logic.
    ip_int >>= 128 - mask
    ip_int += step
    ip_int <<= 128 - mask
    ip_int += ip_diff
    ipaddr = int_to_ipv6(ip_int)
    ipaddr = '/'.join([ipaddr,save_mask]) if save_mask != '' else ipaddr
    return ipaddr

def range_ipv6(start_ip, count, mask=128):
    ip_list = []
    count = int(count)
    mask = int(mask)
    for _ in range(count):
        ip_list.append(start_ip)
        start_ip = incr_ipv6(start_ip, mask)
    return ip_list


def variance(expected, actual, tolerance):
    max_diff = round(float(expected) * tolerance / 100)
    if max_diff == 0 and tolerance != 0:
        max_diff = 1

    low = expected - max_diff
    high = expected + max_diff

    if high >= actual >= low:
        return 0
    else:
        return -1

def expand_range(list):
    VlanVelist = []
    for i in list:
        if "-" in str(i):
            lv = i.split('-')
            lv = [str(i) for i in range(int(lv[0]), int(lv[1]) + 1)]
            VlanVelist = VlanVelist + lv
        else:
            VlanVelist.append(str(i))
    return VlanVelist

def range_ip(start_ip, count, mask=32):
    # start_ip: format can be '1.1.1.1', '1.1.1.1/24', '2000::1', '2000::1/64'.
    # It automatically detects ipv4 or ipv6.
    # return format ['1.1.1.1', '1.1.1.2'], ['1.1.1.1/24', '1.1.1.2/24']
    res = re.search(r'.*:.*',start_ip)
    if res is None:
        ip_list = range_ipv4(start_ip, count, mask)
    else:
        ip_list = range_ipv6(start_ip, count, mask)
    return ip_list

def mcast_ip2mac(mcast_ip):
    mcast_mac =  '01:00:5E:'
    octets = mcast_ip.split('.')
    second_oct = int(octets[1]) & 127
    third_oct = int(octets[2])
    fourth_oct = int(octets[3])
    mcast_mac = mcast_mac + format(second_oct,'02x') + ':' + format(third_oct, '02x') + ':' + format(fourth_oct, '02x')
    return mcast_mac
