#!/usr/bin/env python

"""
Script to generate PFC packets.

"""
import binascii
import sys
import os
import optparse
import logging
import logging.handlers
from socket import socket, AF_PACKET, SOCK_RAW
from struct import *

my_logger = logging.getLogger('MyLogger')
my_logger.setLevel(logging.DEBUG)

def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w

    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);

    #complement and mask to 4 byte short
    s = ~s & 0xffff

    return s

def main():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-i", "--interface", type="string", dest="interface", help="Interface list to send packets, seperated by ','",metavar="Interface")
    parser.add_option('-p', "--priority", type="int", dest="priority", help="PFC class enable bitmap.", metavar="Priority", default=-1)
    parser.add_option("-t", "--time", type="int", dest="time", help="Pause time in quanta for global pause or enabled class",metavar="time")
    parser.add_option("-n", "--num", type="int", dest="num", help="Number of packets to be sent",metavar="number",default=1)
    parser.add_option("-r", "--rsyslog-server", type="string", dest="rsyslog_server", default="127.0.0.1", help="Rsyslog server IPv4 address",metavar="IPAddress") 
    parser.add_option('-g', "--global", action="store_true", dest="global_pf", help="Send global pause frames (not PFC)", default=False)
    (options, args) = parser.parse_args()

    if options.interface is None:
        print "Need to specify the interface to send PFC/global pause frame packets."
        parser.print_help()
        sys.exit(1)

    if options.time > 65535 or options.time < 0:
        print "Quanta is not valid. Need to be in range 0-65535."
        parser.print_help()
        sys.exit(1)

    if options.global_pf:
        # Send global pause frames
        # -p option should not be set
        if options.priority != -1:
            print "'-p' option is not valid when sending global pause frames ('--global' / '-g')"
            parser.print_help()
            sys.exit(1)
    elif options.priority > 255 or options.priority < 0:
        print "Enable class bitmap is not valid. Need to be in range 0-255."
        parser.print_help()
        sys.exit(1)

    interfaces = options.interface.split(',')

    try:
       sockets = []
       for i in range(0, len(interfaces)):
           sockets.append(socket(AF_PACKET, SOCK_RAW))
    except:
        print "Unable to create socket. Check your permissions"
        sys.exit(1)

    # Configure logging
    handler = logging.handlers.SysLogHandler(address = (options.rsyslog_server,514))
    my_logger.addHandler(handler)

    for s,interface in zip(sockets, interfaces):
        s.bind((interface, 0))

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
    src_addr = "\x01\x02\x03\x04\x05\x06" 
    dst_addr = "\x01\x80\xc2\x00\x00\x01"
    if options.global_pf:
        opcode = "\x00\x01"
    else:
        opcode = "\x01\x01"
    ethertype = "\x88\x08"

    packet = dst_addr + src_addr + ethertype + opcode
    if options.global_pf:
        packet = packet + binascii.unhexlify(format(options.time, '04x'))
    else:
        class_enable = options.priority
        class_enable_field = binascii.unhexlify(format(class_enable, '04x'))

        packet = packet + class_enable_field
        for p in range(0,7):
            if (class_enable & (1<<p)):
                packet = packet + binascii.unhexlify(format(options.time, '04x'))
            else:
                packet = packet + "\x00\x00"

    pre_str = 'GLOBAL_PF' if options.global_pf else 'PFC'
    print "Generating %s Packet(s)" % options.num
    my_logger.debug(pre_str + '_STORM_START')
    iteration = options.num
    while iteration > 0:
        for s in sockets:
            s.send(packet)
        iteration -= 1
    my_logger.debug(pre_str + '_STORM_END')

if __name__ == "__main__":
    main()
