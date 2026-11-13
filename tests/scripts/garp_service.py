import argparse
import json
import ptf
import ptf.testutils as testutils
import time

from ipaddress import ip_interface
from scapy.all import conf, Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr
from scapy.arch import get_if_hwaddr


class GarpService:

    def __init__(self, garp_config_file, interval):
        self.garp_config_file = garp_config_file
        self.interval = interval
        self.packets = {}
        self.dataplane = ptf.dataplane_instance

    @staticmethod
    def _as_address_list(value):
        '''
        Normalize a config value that may be absent, a single address, or a list of addresses
        '''
        if not value:
            return []

        if not isinstance(value, (list, tuple)):
            value = [value]

        return [str(ip_interface(addr).ip) for addr in value if addr]

    def gen_garp_packets(self):
        '''
        Read the config file and generate GARP/NA packets for each configured interface

        'target_ip', 'target_ipv6' and 'dst_ipv6' each accept either a single address or a
        list of addresses, so one port can announce an address in several VLAN subnets.
        A 'dst_ipv6' list is paired with 'target_ipv6' by index; a single 'dst_ipv6' is
        used for every IPv6 target.
        '''

        with open(self.garp_config_file) as f:
            garp_config = json.load(f)

        for port, config in list(garp_config.items()):
            intf_name = 'eth{}'.format(port)
            source_mac = get_if_hwaddr(intf_name)
            dut_mac = config['dut_mac']
            source_ips = self._as_address_list(config.get('target_ip'))
            source_ipv6s = self._as_address_list(config.get('target_ipv6'))
            dst_ipv6s = self._as_address_list(config.get('dst_ipv6'))

            packets = []

            # PTF uses Scapy to create packets, so this is ok to create
            # packets through PTF even though we are using Scapy to send the packets
            for source_ip in source_ips:
                packets.append(testutils.simple_arp_packet(
                    eth_src=source_mac,
                    hw_snd=source_mac,
                    ip_snd=source_ip,
                    # Re-use server IP as target IP, since it is within the subnet of the VLAN IP
                    ip_tgt=source_ip,
                    arp_op=2))

            for index, source_ipv6 in enumerate(source_ipv6s):
                if index < len(dst_ipv6s):
                    dst_ipv6 = dst_ipv6s[index]
                elif dst_ipv6s:
                    dst_ipv6 = dst_ipv6s[0]
                else:
                    # No gateway configured for this subnet, fall back to all-nodes multicast
                    dst_ipv6 = 'ff02::1'

                packets.append(Ether(src=source_mac, dst=dut_mac)
                               / IPv6(dst=dst_ipv6, src=source_ipv6)
                               / ICMPv6ND_NA(tgt=source_ipv6, S=1, R=0, O=0)
                               / ICMPv6NDOptSrcLLAddr(type=2, lladdr=source_mac))

            self.packets[intf_name] = packets

    def send_garp_packets(self):
        '''
        For each created GARP packet/interface pair, create an L2 socket.
        Then send every packet through its associated socket according to the self.interval
        '''
        self.gen_garp_packets()

        sockets = {}

        for intf, packet_list in list(self.packets.items()):
            if not packet_list:
                continue
            socket = conf.L2socket(iface=intf)
            sockets[socket] = packet_list

        try:
            while True:
                for socket, packet_list in list(sockets.items()):
                    for packet in packet_list:
                        socket.send(packet)

                if self.interval is None:
                    break

                time.sleep(self.interval)

        finally:
            for socket in list(sockets.keys()):
                socket.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='GARP Service')
    parser.add_argument('--conf', '-c', dest='conf_file', required=False, default='/tmp/garp_conf.json',
                        action='store', help='The configuration file for GARP Service (default "/tmp/garp_conf.json")')
    parser.add_argument('--interval', '-i', dest='interval', required=False, type=int, default=None, action='store',
                        help='The interval at which to re-send GARP messages. '
                        'If None or not specified, messages will only be set once at service startup')
    args = parser.parse_args()
    conf_file = args.conf_file
    interval = args.interval

    garp_service = GarpService(conf_file, interval)
    garp_service.send_garp_packets()
