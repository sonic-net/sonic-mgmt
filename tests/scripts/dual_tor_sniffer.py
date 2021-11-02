import argparse
import logging
import signal

import scapy.all as scapyall


class Sniffer(object):
    def __init__(self, filter=None, timeout=60, pcap='/tmp/capture.pcap'):
        self.filter = filter
        self.timeout = timeout
        self.packets = []
        self.socket = None
        self.pcap_path = pcap
        signal.signal(signal.SIGINT, self.catch_signals)

    def catch_signals(self, signum, frame):
        self.save_pcap()

    def sniff(self):
        logging.debug("scapy sniffer started: filter={}, timeout={}".format(self.filter, self.timeout))
        scapyall.sniff(
            filter=self.filter,
            prn=self.process_pkt,
            timeout=self.timeout)
        logging.debug("Scapy sniffer ended")

    def process_pkt(self, pkt):
        self.packets.append(pkt)

    def save_pcap(self):
        if not self.packets:
            logging.warning("No packets were captured")

        scapyall.wrpcap(self.pcap_path, self.packets)
        logging.debug("Pcap file dumped to {}".format(self.pcap_path))


def main():
    parser = argparse.ArgumentParser(
        description='''
        Tool for managing the testbeds data in Azure Table Storage.
        '''
    )
    parser.add_argument('-f', '--filter',
        type=str,
        dest='filter',
        default=None,
        help='Capture filter.'
    )
    parser.add_argument('-t', '--timeout',
        type=float,
        dest='timeout',
        default=60.0,
        help='Maximum number of seconds to sniff.'
    )
    parser.add_argument('-p', '--pcap',
        type=str,
        dest='pcap',
        default='/tmp/capture.pcap',
        help='Dump captured packets to the specified pcap file.'
    )
    parser.add_argument('-l', '--log',
        type=str,
        dest='log',
        default='/tmp/capture.log',
        help='Save log to the specified log file'
    )

    args = parser.parse_args()

    logging.basicConfig(
        filename=args.log,
        filemode='w',
        format='%(asctime)s %(levelname)s %(message)s',
        level=logging.DEBUG
    )

    sniffer = Sniffer(filter=args.filter, timeout=args.timeout, pcap=args.pcap)
    sniffer.sniff()
    if sniffer.socket:
        sniffer.socket.close()
    sniffer.save_pcap()


if __name__ == '__main__':
    main()
