import ptf.packet as scapy
import ptf.dataplane as dataplane
import acs_base_test
from ptf.base_tests import BaseTest
from ptf.testutils import *
from ptf.mask import Mask
import scapy.all as scapy2
from time import sleep
from threading import Thread

class FailingTest(BaseTest):
    '''
        Test designed to fail
    '''
    def runTest(self):
            a = 5 / 0
            pass

class SucceessTest(BaseTest):
    '''
        Test designed for success
    '''
    def runTest(self):
            pass

class SendTCP(acs_base_test.ACSDataplaneTest):
    '''
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80
    '''

    def pkt_callback(self, pkt):
        if pkt.haslayer(scapy2.TCP) and pkt.getlayer(scapy2.IP).src == "22.0.0.2":
            self.sniffed_cnt += 1

    def Sniffer(self, interface):
        self.sniffed_cnt = 0
        scapy2.sniff(iface="eth2", prn=self.pkt_callback, store=0, timeout=3)

    def runTest(self):

        pkt = scapy2.Ether()
        pkt /= scapy2.IP(src="21.0.0.2", dst="22.0.0.2")
        pkt /= scapy2.TCP(dport = 80, flags="S", seq=42)
        pkt /= ("badabadaboom")

        t = Thread(target=self.Sniffer, args=("eth2",))
        t.start()
        scapy2.sendp(pkt, iface='eth2')
        sleep(4)
        # fail if no reply
        if self.sniffed_cnt == 0:
            self.assertTrue(False)


        #res = scapy2.sniff(iface="eth2", timeout=3)
        #print res
        #if res:
        #    raise

        #if reply:
        #    raise
        #print "================______====\n"
        #print reply
        #print error
        #print "================______====\n"
        #if reply:
        #    reply.show()
        #(rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(self, device_number=0, port_number=0, timeout=5)
        #send_packet(self, 0, pkt)
        #(rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(self, device_number=0, port_number=0, timeout=5)


#        verify_packet(self, masked_exp_pkt, 1)


        #mpkt = Mask(pkt)
        #mpkt.set_do_not_care(0, 14*8)
        #mpkt.set_do_not_care(16*8, 49*8)
        #verify_packet(self, mpkt, 0)
        #(rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(self, device_number=0, port_number=0, timeout=5)
        #print "================______====\n"
        #y = 0
        #for x in rcv_pkt:
        #    print "%d - %X" % (y, ord(x))
        #    y +=1
"""
(rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(self, device_number=0, timeout=3)
        print "================______====\n"
        y = 0
        for x in rcv_pkt:
            print "%d - %X" % (y, ord(x))
            y +=1

        y = 0
        for x in str(pkt):
            print "%d - %X" % (y, ord(x))
            y +=1
"""


"""

        pkt = scapy.Ether()
        pkt /= scapy.IP(src="21.0.0.2", dst="22.0.0.2")
        pkt /= scapy.TCP(sport = 8192, dport = 80, flags="S", seq=42)
        m = Mask.Mask(pkt)
        m.set_do_not_care_scapy(Ether, 'src')
        m.set_do_not_care_scapy(Ether, 'dst')
        m.set_do_not_care_scapy(IP, 'ttl')
        m.set_do_not_care_scapy(IP, 'len')
        m.set_do_not_care_scapy(IP, 'flags')
        verify_packet(self, pkt, 0);
        verify_packets(<test>, m)


Test ACL permition


import ptf.packet as scapy

import ptf.dataplane as dataplane
import acs_base_test

from ptf.testutils import *
from ptf.mask import Mask


class ACLpermit(acs_base_test.ACSDataplaneTest):
    def runTest(self):
        print "The test is passed"
        pass
       # pkt = simple_ip_packet( eth_dst='00:01:02:03:04:05',
       #                         eth_src='00:06:07:08:09:0a',
       #                         ip_src='192.168.0.1',
       #                         ip_dst='192.168.0.2',
       #                         ip_ttl=64)
       # send_packet(self, port, pkt)

       # pkt = scapy.Ether()
       # pkt /= scapy.IP(src="20.0.0.2", dst="21.0.0.2")
       # pkt /= scapy.TCP()
       # pkt /= ("Yellow Sun")
       # send_packet(self, 1, pkt)
       # verify_packet(self, pkt, 2)
"""
