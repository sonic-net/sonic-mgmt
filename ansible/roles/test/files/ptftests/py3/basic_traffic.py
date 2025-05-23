import ptf
from ptf.base_tests import BaseTest
from ptf.testutils import simple_udp_packet, send_packet, test_params_get


class SimpleUdpTraffic(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = test_params_get()

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.pkt_count = self.test_params.get('pkt_count', 1000)
        self.port_src = int(self.test_params['src_port_id'])
        self.port_dst = self.test_params['dst_port_id']
        self.mac_src = self.dataplane.get_mac(0, self.port_src)
        self.mac_dst = self.dataplane.get_mac(0, self.port_dst)
        self.ip_src = self.test_params['src_port_ip']
        self.ip_dst = self.test_params['dst_port_ip']
        self.dscp = self.test_params.get('dscp', 8)
        self.vlan_id = self.test_params.get('src_port_vlan', None)
        self.pkt_size = self.test_params.get('pkt_size', 1024)

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
            'ip_ttl': 64
        }
        if self.vlan_id is not None:
            pkt_args['dl_vlan_enable'] = True
            pkt_args['vlan_vid'] = int(self.vlan_id)
            pkt_args['vlan_pcp'] = self.dscp
        pkt = simple_udp_packet(**pkt_args)

        return pkt

    def runTest(self):
        pkt = self.construct_pkt(sport=1024, dport=1024)
        send_packet(self, self.port_src, pkt, self.pkt_count)
