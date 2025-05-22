import ptf
import ptf.packet as scapy

from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import test_params_get, simple_udp_packet, send_packet

def verify_packet_rx(test, dst_port_list, src_port_ip, dst_port_ip, exp_ip_id, exp_pkt_cnt):
    # Set receiving socket buffers to some big value
    for p in list(test.dataplane.ports.values()):
        p.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 41943040)
    cnt = 0
    pkts = []
    for dst_port_id in dst_port_list:
        recv_pkt = scapy.Ether()
        while recv_pkt:
            received = test.dataplane.poll(
                device_number=0, port_number=dst_port_id, timeout=2)
            if isinstance(received, test.dataplane.PollFailure):
                recv_pkt = None
                break
            recv_pkt = scapy.Ether(received.packet)

            try:
                if recv_pkt[scapy.IP].src == src_port_ip and recv_pkt[scapy.IP].dst == dst_port_ip and \
                        recv_pkt[scapy.IP].id == exp_ip_id:
                    cnt += 1
                    pkts.append(recv_pkt)
            except AttributeError:
                continue
            except IndexError:
                # Ignore captured non-IP packet
                continue
    assert (cnt == exp_pkt_cnt)

class SimpleUdpTraffic(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = test_params_get()

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.port_src = int(self.test_params['src_port_id'])
        self.port_dst = self.test_params['dst_port_id']
        self.mac_src = self.dataplane.get_mac(0, self.port_src)
        self.mac_dst = self.dataplane.get_mac(0, self.port_dst)
        self.ip_src = self.test_params['src_port_ip']
        self.ip_dst = self.test_params['dst_port_ip']
        self.dscp = self.test_params.get('dscp', 8)
        self.pkt_size = self.test_params.get('pkt_size', 1024)
        self.pkt_count = self.test_params.get('pkt_count', 500)
        self.action = self.test_params.get('action', '')
        self.dst_port_list = self.test_params.get('dst_port_id_list', [self.port_dst])
        self.port_src_vlan_id = self.test_params.get('port_src_vlan_id', None)
        self.port_dst_vlan_id = self.test_params.get('port_dst_vlan_id', None)
        self.exp_ip_id = 110

    def construct_pkt(self, sport, dport):
        tos = self.dscp << 2

        pkt_args = {
            'pktlen': self.pkt_size,
            'eth_dst': self.mac_dst,
            'eth_src': self.mac_src,
            'ip_src': self.ip_src,
            'ip_dst': self.ip_dst,
            'ip_tos': tos,
            'udp_sport': sport,
            'udp_dport': dport,
            'ip_ttl': 64,
            'ip_id': self.exp_ip_id
        }
        if self.port_src_vlan_id is not None:
            pkt_args['dl_vlan_enable'] = True
            pkt_args['vlan_vid'] = int(self.port_src_vlan_id)
            pkt_args['vlan_pcp'] = self.dscp
        pkt = simple_udp_packet(**pkt_args)
        exp_pkt_args = {
            'eth_src': self.mac_src,
            'ip_src': self.ip_src,
            'ip_dst': self.ip_dst,
            'ip_tos': tos,
            'udp_sport': sport,
            'udp_dport': dport
        }
        if self.port_dst_vlan_id is not None:
            exp_pkt_args['dl_vlan_enable'] = True
            exp_pkt_args['vlan_vid'] = int(self.port_dst_vlan_id)
            exp_pkt_args['vlan_pcp'] = self.dscp
        exp_pkt = simple_udp_packet(**exp_pkt_args)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "len")

        return pkt, masked_exp_pkt

    def runTest(self):
        pkt, masked_exp_pkt = self.construct_pkt(sport=1024, dport=1024)
        send_packet(self, self.port_src, pkt, self.pkt_count)
        if self.action == 'forward':
            verify_packet_rx(self, self.dst_port_list, self.ip_src, self.ip_dst, self.exp_ip_id, self.pkt_count)
