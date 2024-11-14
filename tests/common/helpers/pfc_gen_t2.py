#!/usr/bin/env python

"""
Script to generate PFC packets.

"""
import binascii
import sys
import optparse
import logging
import logging.handlers
from socket import socket, AF_PACKET, SOCK_RAW
import time
from ctypes import (
    CDLL,
    POINTER,
    Structure,
    c_int,
    c_size_t,
    c_uint,
    c_uint32,
    c_void_p,
    cast,
    get_errno,
    pointer,
)


class struct_iovec(Structure):
    _fields_ = [
        ("iov_base", c_void_p),
        ("iov_len", c_size_t),
    ]


class struct_msghdr(Structure):
    _fields_ = [
        ("msg_name", c_void_p),
        ("msg_namelen", c_uint32),
        ("msg_iov", POINTER(struct_iovec)),
        ("msg_iovlen", c_size_t),
        ("msg_control", c_void_p),
        ("msg_controllen", c_size_t),
        ("msg_flags", c_int),
    ]


class struct_mmsghdr(Structure):
    _fields_ = [
        ("msg_hdr", struct_msghdr),
        ("msg_len", c_uint)
    ]


# cdll.LoadLibrary("libc.so.6")
libc = CDLL("libc.so.6")
_sendmmsg = libc.sendmmsg
_sendmmsg.argtypes = [c_int, POINTER(struct_mmsghdr), c_uint, c_int]
_sendmmsg.restype = c_int

my_logger = logging.getLogger('MyLogger')
my_logger.setLevel(logging.DEBUG)

fo_logger = logging.getLogger('MyLogger')
fo_logger.setLevel(logging.DEBUG)


def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)

    # complement and mask to 4 byte short
    s = ~s & 0xffff

    return s


def main():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-i", "--interface", type="string", dest="interface",
                      help="Interface list to send packets, seperated by ','", metavar="Interface")
    parser.add_option('-p', "--priority", type="int", dest="priority",
                      help="PFC class enable bitmap.", metavar="Priority", default=-1)
    parser.add_option("-t", "--time", type="int", dest="time",
                      help="Pause time in quanta for global pause or enabled class", metavar="time")
    parser.add_option("-s", "--sendtime", type="int", dest="sendtime",
                      help="Total amount of time to send pkts. -n option is ignored if this is set",
                      metavar="sendtime", default=0)
    parser.add_option("-n", "--num", type="int", dest="num",
                      help="Number of packets to be sent", metavar="number", default=1)
    parser.add_option("-r", "--rsyslog-server", type="string", dest="rsyslog_server",
                      default="127.0.0.1", help="Rsyslog server IPv4 address", metavar="IPAddress")
    parser.add_option('-g', "--global", action="store_true", dest="global_pf",
                      help="Send global pause frames (not PFC)", default=False)
    (options, args) = parser.parse_args()

    if options.interface is None:
        print("Need to specify the interface to send PFC/global pause frame packets.")
        parser.print_help()
        sys.exit(1)

    if options.time > 65535 or options.time < 0:
        print("Quanta is not valid. Need to be in range 0-65535.")
        parser.print_help()
        sys.exit(1)

    if options.global_pf:
        # Send global pause frames
        # -p option should not be set
        if options.priority != -1:
            print("'-p' option is not valid when sending global pause frames ('--global' / '-g')")
            parser.print_help()
            sys.exit(1)
    elif options.priority > 255 or options.priority < 0:
        print("Enable class bitmap is not valid. Need to be in range 0-255.")
        parser.print_help()
        sys.exit(1)

    interfaces = options.interface.split(',')

    length_of_list = len(interfaces)
    sockets = []

    # Configure fanout logging
    fo_handler = logging.handlers.SysLogHandler()
    fo_logger.addHandler(fo_handler)

    # Only a single socket supported for now
    try:
        for i in range(0, length_of_list):
            mysocket = socket(AF_PACKET, SOCK_RAW)
            sockets.append(mysocket)
            fo_logger.debug("Socket number : {} {}".format(i, mysocket.getsockname()))
    except Exception:
        print("Unable to create socket for i %i. Check your permissions" % i)
        sys.exit(1)

    # Configure logging
    handler = logging.handlers.SysLogHandler(address=(options.rsyslog_server, 514))
    my_logger.addHandler(handler)

    for s, interface in zip(sockets, interfaces):
        # todo: check bind return value for possible errors
        s.bind((interface, 0))
        s.setsockopt(263, 20, 1)  # QDISC_BYPASS
        s.setblocking(False)
        fo_logger.debug("Socket bound : {}".format(s.getsockname()))

    """
    Set PFC defined fields and generate the packet

    The Ethernet Frame format for PFC packets is the following:

    Destination MAC |   01:80:C2:00:00:01   |
                    -------------------------
    Source MAC      |      Station MAC      |
                    -------------------------
    Ethertype       |         0x8808        |
                    -------------------------
    OpCode          |         0x0101        |
                    -------------------------
    Class Enable V  | 0x00 E7...E0          |
                    -------------------------
    Time Class 0    |       0x0000          |
                    -------------------------
    Time Class 1    |       0x0000          |
                    -------------------------
    ...
                    -------------------------
    Time Class 7    |       0x0000          |
                    -------------------------
    """
    """
    Set pause frame defined fields and generate the packet

    The Ethernet Frame format for pause frames is the following:

    Destination MAC |   01:80:C2:00:00:01   |
                    -------------------------
    Source MAC      |      Station MAC      |
                    -------------------------
    Ethertype       |        0x8808         |
                    -------------------------
    OpCode          |        0x0001         |
                    -------------------------
    pause time      |        0x0000         |
                    -------------------------
    """
    src_addr = b"\x00\x01\x02\x03\x04\x05"
    dst_addr = b"\x01\x80\xc2\x00\x00\x01"
    if options.global_pf:
        opcode = b"\x00\x01"
    else:
        opcode = b"\x01\x01"
    ethertype = b"\x88\x08"

    packet = dst_addr + src_addr + ethertype + opcode

    if options.global_pf:
        packet = packet + binascii.unhexlify(format(options.time, '04x'))
    else:
        class_enable = options.priority
        class_enable_field = binascii.unhexlify(format(class_enable, '04x'))

        packet = packet + class_enable_field

        for p in range(0, 8):
            if (class_enable & (1 << p)):
                packet = packet + binascii.unhexlify(format(options.time, '04x'))
            else:
                packet = packet + b"\x00\x00"

    # construct mmsg header to send in bulk for minimal latency

    total_packets = max(1000, options.num)
    m_msghdr = (struct_mmsghdr * total_packets)()

    iov = struct_iovec(cast(packet, c_void_p), len(packet))

    msg_iov = pointer(iov)
    msg_iovlen = 1
    msg_control = 0
    msg_controllen = 0

    msg_namelen = 0
    msg_name = cast(None, c_void_p)

    # construct the vector
    for i in range(0, 1000):
        msghdr = struct_msghdr(
                    msg_name, msg_namelen, msg_iov, msg_iovlen,
                    msg_control, msg_controllen, 0)
        m_msghdr[i] = struct_mmsghdr(msghdr)
        i += 1

    pre_str = 'GLOBAL_PF' if options.global_pf else 'PFC'
    fo_str = "Fanout"

    total_num_remaining = options.num
    total_num_sent = 0
    iters = 0
    start_time = time.monotonic()

    if options.sendtime > 0:       # send according to requested period of send time
        if length_of_list > 1:
            num_to_send = 1
        else:
            num_to_send = 1000
        print("Generating Packet(s) over period of %f seconds" % options.sendtime)
        my_logger.debug(pre_str + '_STORM_START')
        while True:
            for s in sockets:
                num_sent = _sendmmsg(s.fileno(), m_msghdr[0], num_to_send, 0)   # direct to c library api
                if num_sent < 0:
                    errno = get_errno()
                    fo_logger.debug(fo_str + ' sendmmsg got errno ' + str(errno) + ' for socket ' +
                                    str(s.getsockname()))
                    break
                else:
                    if num_sent != num_to_send:
                        fo_logger.debug(fo_str + ' sendmmsg iteration ' + str(iters) + ' only sent ' +
                                        str(num_sent) + ' out of requested ' + str(num_to_send) +
                                        ' for socket ' + str(s.getsockname()))
                # Count across all sockets
                total_num_sent += num_sent
            iters += 1
            done_time = time.monotonic()
            elapsed_time = done_time - start_time
            if elapsed_time >= options.sendtime:
                break

        my_logger.debug(pre_str + '_STORM_END')
        fo_logger.debug(fo_str + '_STORM_END_AFTER_RSYSLOG_CALL : sent ' + str(total_num_sent) + ' pkts in ' + str(
            iters) + ' iterations and elapsed time of ' + str(elapsed_time) + ' secs')
    # send according to requested number of pkts
    else:
        if length_of_list > 1:
            num_to_send_max = 1
        else:
            num_to_send_max = 1000
        print("Generating %s Packet(s)" % options.num)
        my_logger.debug(pre_str + '_STORM_START')
        num_sockets = len(sockets)
        total_pkts_sent = [0] * num_sockets
        total_pkts_remaining = [total_num_remaining] * num_sockets
        done = [False] * num_sockets
        keep_sending = True
        test_failed = False
        while keep_sending is True:
            for s in sockets:
                index = sockets.index(s)
                if total_pkts_remaining[index] <= 0:
                    continue
                num_to_send = min(num_to_send_max, total_pkts_remaining[index])
                num_sent = _sendmmsg(s.fileno(), m_msghdr[0], num_to_send, 0)
                if num_sent < 0:
                    errno = get_errno()
                    fo_logger.debug(fo_str + ' sendmmsg got errno ' + str(errno) + ' for socket ' +
                                    str(s.getsockname()))
                    test_failed = True
                    break
                else:
                    if num_sent != num_to_send:
                        fo_logger.debug(fo_str + ' sendmmsg iteration ' + str(iters) +
                                        ' only sent ' + str(num_sent) +
                                        ' out of requested ' + str(num_to_send) + ' for socket ' +
                                        str(s.getsockname()))
                total_pkts_remaining[index] -= num_sent
                total_pkts_sent[index] += num_sent
                if total_pkts_remaining[index] <= 0:
                    done[index] = True
            if test_failed is True:
                break
            iters += 1
            keep_sending = False
            for i in range(0, num_sockets):
                if total_pkts_remaining[i] > 0:
                    keep_sending = True

        done_time = time.monotonic()
        elapsed_time = done_time - start_time

        my_logger.debug(pre_str + '_STORM_END')
        for i in range(0, num_sockets):
            fo_logger.debug(fo_str + '_STORM_END : socket ' + str(i) + ' sent ' + str(total_pkts_sent[i]) + ' pkts')
        fo_logger.debug(fo_str + '_STORM_END_AFTER_RSYSLOG_CALL : ' + str(iters) +
                        ' iterations and elapsed time of ' + str(elapsed_time) + ' secs')

    for s in sockets:
        s.close()
        s.detach()


if __name__ == "__main__":
    main()
