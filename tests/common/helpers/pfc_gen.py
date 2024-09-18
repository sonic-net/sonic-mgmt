#!/usr/bin/env python

"""
Script to generate PFC packets.

"""
import binascii
import sys
import optparse
import logging
import logging.handlers
import time
import multiprocessing

from socket import socket, AF_PACKET, SOCK_RAW

logger = logging.getLogger('MyLogger')
logger.setLevel(logging.DEBUG)

# Maximum number of processes to be created
MAX_PROCESS_NUM = 4


class PacketSender():
    """
    A class to send PFC pause frames
    """
    def __init__(self, interfaces, packet, num, interval):
        # Create RAW socket to send PFC pause frames
        self.sockets = []
        try:
            for interface in interfaces:
                s = socket(AF_PACKET, SOCK_RAW)
                s.bind((interface, 0))
                self.sockets.append(s)
        except Exception as e:
            print("Unable to create socket. Check your permissions: %s" % e)
            sys.exit(1)
        self.packet_num = num
        self.packet_interval = interval
        self.process = None
        self.packet = packet

    def send_packets(self):
        iteration = self.packet_num
        while iteration > 0:
            for s in self.sockets:
                s.send(self.packet)
                if self.packet_interval > 0:
                    time.sleep(self.packet_interval)
            iteration -= 1

    def start(self):
        self.process = multiprocessing.Process(target=self.send_packets)
        self.process.start()

    def stop(self, timeout=None):
        if self.process:
            self.process.join(timeout)
        for s in self.sockets:
            s.close()


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
    parser.add_option("-s", "--send_pfc_frame_interval", type="float", dest="send_pfc_frame_interval",
                      help="Interval sending pfc frame", metavar="send_pfc_frame_interval", default=0)

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

    # Configure logging
    handler = logging.handlers.SysLogHandler(address=(options.rsyslog_server, 514))
    logger.addHandler(handler)

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
    logger.debug(pre_str + '_STORM_DEBUG')

    # Start sending PFC pause frames
    senders = []
    interface_slices = [[] for i in range(MAX_PROCESS_NUM)]
    for i in range(0, len(interfaces)):
        interface_slices[i % MAX_PROCESS_NUM].append(interfaces[i])

    for interface_slice in interface_slices:
        if (interface_slice):
            s = PacketSender(interface_slice, packet, options.num, options.send_pfc_frame_interval)
            s.start()
            senders.append(s)

    logger.debug(pre_str + '_STORM_START')
    # Wait PFC packets to be sent
    for sender in senders:
        sender.stop()

    logger.debug(pre_str + '_STORM_END')


if __name__ == "__main__":
    main()
