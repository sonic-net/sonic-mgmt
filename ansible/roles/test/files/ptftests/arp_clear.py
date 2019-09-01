import os
import ptf
from ptf.testutils import *
from ptf import config
from ptf.base_tests import BaseTest


class ACSDataplaneTest(BaseTest):
    def setUp(self):
        BaseTest.setUp(self)

        self.test_params = test_params_get()
        print "You specified the following test-params when invoking ptf:"
        print self.test_params

        # shows how to use a filter on all our tests
        add_filter(not_ipv6_filter)

        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        if config["log_dir"] != None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        reset_filters()
        BaseTest.tearDown(self)


class VerifyUnicastARPReply(ACSDataplaneTest):
    """Send a unicast ARP request so that the peer adds the desired ARP entry"""

    def runTest(self):
        acs_mac = self.test_params['acs_mac']
        pkt = simple_arp_packet(
            eth_dst=acs_mac,
            eth_src=self.test_params['fake_mac'],
            arp_op=1,
            ip_snd=self.test_params['fake_ip'],
            ip_tgt=self.test_params['dut_ip'],
            hw_snd=self.test_params['fake_mac'],
            hw_tgt=acs_mac,
        )
        exp_pkt = simple_arp_packet(
            eth_dst=self.test_params['fake_mac'],
            eth_src=acs_mac,
            arp_op=2,
            ip_snd=self.test_params['dut_ip'],
            ip_tgt=self.test_params['fake_ip'],
            hw_tgt=self.test_params['fake_mac'],
            hw_snd=acs_mac,
        )
        send_packet(self, self.test_params['port'], pkt)
        verify_packet(self, exp_pkt, self.test_params['port'])
