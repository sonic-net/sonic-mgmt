import ptf
from ptf.base_tests import BaseTest
from switch import *
import logging
import random

class BGPTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = ptf.testutils.test_params_get()

    def runTest(self):
        BaseTest.setUp(self)
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        random.seed(1)

        router_mac = self.test_params['router_mac']
        destination_ports = range(0, 16)
        # Exclude the port if specified: EthernetX -> X-1
        exclude_port = -1
        if 'exclude_port' in self.test_params:
            exclude_port = int(self.test_params['exclude_port'][8:]) - 1

        pkt_counter = [0] * 16
        total_pkts = 0
        for i in range(16):
            logging.warning(self.dataplane.get_mac(0, i+16))

        for i in xrange(200):
            for j in xrange(16):
                ip_src = '10.0.0.32'
                src_mac = self.dataplane.get_mac(0, 0)
                ip_dst = '192.168.' + str(i) + '.' + str(j*16)

                sport = random.randint(0, 0xffff)
                dport= random.randint(0, 0xffff)

                logging.debug('ip_src: ' + ip_src + ' ip_dst: ' + ip_dst);
                pkt = simple_tcp_packet(
                        eth_dst = router_mac,
                        eth_src = src_mac,
                        ip_src = ip_src,
                        ip_dst = ip_dst,
                        tcp_sport = sport,
                        tcp_dport = dport,
                        ip_ttl = 64)

                exp_pkt = simple_tcp_packet(
                        eth_dst = self.dataplane.get_mac(0, 16),
                        eth_src = router_mac,
                        ip_src = ip_src,
                        ip_dst = ip_dst,
                        tcp_sport = sport,
                        tcp_dport = dport,
                        ip_ttl = 63)

                masked_exp_pkt = ptf.mask.Mask(exp_pkt)
                masked_exp_pkt.set_do_not_care_scapy(ptf.packet.Ether, "dst")

                # Send packet from the first TOR
                send_packet(self, 16, pkt)
                # Receive packet from one of the spines
                (match_index, rcv_pkt) = self.verify_packet_any_port(masked_exp_pkt, destination_ports)
                logging.debug("found expected pkt from port %d", destination_ports[match_index])

                pkt_counter[destination_ports[match_index]] += 1
                total_pkts += 1

        logging.debug("received %d pkts in total", total_pkts)
        for port in destination_ports:
            logging.debug("port %d received %d pkts", port, pkt_counter[port])
            if port == exclude_port:
                continue
            self.assertTrue(pkt_counter[port] > total_pkts / len(destination_ports) * 0.6)

    def verify_packet_any_port(test, pkt, ports=[], device_number=0):
        received = False
        match_index = 0
        (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(
            test,
            device_number = device_number,
            exp_pkt = pkt,
            timeout = 1
        )

        logging.debug("checking for pkt on device %d, port %r", device_number, ports)
        if rcv_port in ports:
            match_index = ports.index(rcv_port)
            received = True

        test.assertTrue(received == True, "Did not receive expected pkt(s) on any of ports %r for device %d" % (ports, device_number))
        return (match_index, rcv_pkt)
