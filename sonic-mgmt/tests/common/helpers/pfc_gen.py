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

logger = logging.getLogger('MyLogger')
logger.setLevel(logging.DEBUG)


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

# Python doesn't expose the `setns()` function manually, so
# we'll use the `ctypes` module to make it available.
from ctypes import cdll
libc = cdll.LoadLibrary('libc.so.6')
setns = libc.setns

# This is just a convenience function that will return the path
# to an appropriate namespace descriptor, give either a path,
# a network namespace name, or a pid.
def get_ns_path(nspath=None, nsname=None, nspid=None):
    if nsname:
        nspath = '/var/run/netns/%s' % nsname
    elif nspid:
        nspath = '/proc/%d/ns/net' % nspid

    return nspath

# This is a context manager that on enter assigns the process to an
# alternate network namespace (specified by name, filesystem path, or pid)
# and then re-assigns the process to its original network namespace on
# exit.
class Namespace (object):
    def __init__(self, nsname=None, nspath=None, nspid=None):
        self.mypath = get_ns_path(nspid=os.getpid())
        self.targetpath = get_ns_path(nspath,
                                  nsname=nsname,
                                  nspid=nspid)

        if not self.targetpath:
            raise ValueError('invalid namespace')

    def __enter__(self):
        # before entering a new namespace, we open a file descriptor
        # in the current namespace that we will use to restore
        # our namespace on exit.
        self.myns = open(self.mypath)
        with open(self.targetpath) as fd:
            setns(fd.fileno(), 0)

    def __exit__(self, *args):
        setns(self.myns.fileno(), 0)
        self.myns.close()


# This is a wrapper for socket.socket() that creates the socket inside the
# specified network namespace.
def nssocket(ns, *args):
    with Namespace(nsname=ns):
        s = socket.socket(*args)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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

    try:
        sockets = []
        for i in range(0, len(interfaces)):
            sockets.append(socket(AF_PACKET, SOCK_RAW))
    except Exception:
        print("Unable to create socket. Check your permissions")
        sys.exit(1)

    # Configure logging
    res = os.system('grep Nexus /etc/os-release')
    if res == 0:
        # For cisco-nexus, we need to use the "management" namespace
        with Namespace(nsname="management"):
            handler = logging.handlers.SysLogHandler(address = (options.rsyslog_server,514))
            my_logger.addHandler(handler)
    else:
        handler = logging.handlers.SysLogHandler(address = (options.rsyslog_server,514))
        my_logger.addHandler(handler)

    for s, interface in zip(sockets, interfaces):
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

    pre_str = 'GLOBAL_PF' if options.global_pf else 'PFC'
    print(("Generating %s Packet(s)" % options.num))
    logger.debug(pre_str + '_STORM_START')
    iteration = options.num
    while iteration > 0:
        for s in sockets:
            s.send(packet)
        iteration -= 1
    logger.debug(pre_str + '_STORM_END')


if __name__ == "__main__":
    main()
