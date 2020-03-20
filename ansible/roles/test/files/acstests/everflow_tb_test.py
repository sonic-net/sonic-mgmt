'''
Description:    This file contains the Everflow test for SONiC testbed

                Implemented according to the https://github.com/Azure/SONiC/wiki/Everflow-test-plan

Usage:          Examples of how to use:
                ptf --test-dir acstests everflow_tb_test.EverflowTest --platform remote -t 'router_mac="00:02:03:04:05:00";src_port="20";dst_ports="21,22";session_src_ip="1.1.1.1";session_dst_ip="2.2.2.2";session_ttl="64";session_dscp="0";verbose=True'
'''


import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane
import ptf.testutils as testutils
from ptf.base_tests import BaseTest
from ptf.mask import Mask

def reportResults(test_name):
    '''
    @summary Report test result
    '''
    def testDecorator(func):
        def wrapper(*args, **kwargs):
            res = func(*args, **kwargs)
            print 'Test "%s" %s' % (test_name, "PASSED" if res else "FAILED")
            return res
        return wrapper
    return testDecorator


class EverflowTest(BaseTest):
    '''
    @summary: Everflow tests on testbed topo: t1 or t1-lag
    '''

    GRE_PROTOCOL_NUMBER = 47
    PORT_COUNT = 31 # temporary exclude the last port


    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = testutils.test_params_get()


    def gre_type_filter(self, pkt_str):
        '''
        @summaty: Filter GRE packets
        '''
        try:
            pkt = scapy.Ether(pkt_str)

            if scapy.IP not in pkt:
                return False

            return pkt[scapy.IP].proto == self.GRE_PROTOCOL_NUMBER
        except:
            return False


    def setUp(self):
        '''
        @summary: Setup for the test
        '''

        self.dataplane = ptf.dataplane_instance
        self.hwsku = self.test_params['hwsku']
        self.asic_type = self.test_params['asic_type']
        self.router_mac = self.test_params['router_mac']
        self.session_src_ip = self.test_params['session_src_ip']
        self.session_dst_ip = self.test_params['session_dst_ip']
        self.session_ttl = int(self.test_params['session_ttl'])
        self.session_dscp = int(self.test_params['session_dscp'])
        self.src_port = int(float(self.test_params['src_port']))
        self.dst_ports = [int(float(p)) for p in self.test_params['dst_ports'].split(",") if p]
        self.expected_dst_mac = self.test_params.get('expected_dst_mac', None)
        self.expect_received = self.test_params.get('expect_received', True)
        self.acl_stage = self.test_params.get('acl_stage', 'ingress')
        self.mirror_stage = self.test_params.get('mirror_stage', 'ingress')

        testutils.add_filter(self.gre_type_filter)

        self.tests_total = 0
        self.base_pkt = testutils.simple_tcp_packet(
                eth_dst = self.router_mac,
                eth_src = self.dataplane.get_mac(0, 0),
                ip_src = "20.0.0.1",
                ip_dst = "30.0.0.1",
                tcp_sport = 0x1234,
                tcp_dport = 0x50,
                ip_ttl = 64
                )


    def receivePacketOnPorts(self, ports=[], device_number=0):
        '''
        @summary Receive packet on any of specified ports
        '''
        received = False
        match_index = 0
        (rcv_device, rcv_port, rcv_pkt, pkt_time) = testutils.dp_poll(self, device_number=device_number, timeout=1)

        if rcv_port in ports:
            match_index = ports.index(rcv_port)
            received = True

        return (match_index, rcv_pkt, received)


    def sendReceive(self, pkt2send, src_port, destination_ports):
        """
        @summary Send packet and verify it is received/not received on the expected ports
        """

        testutils.send_packet(self, src_port, pkt2send)
        (index, rcv_pkt, received) = self.receivePacketOnPorts(destination_ports)

        self.tests_total += 1

        if not received:
            return False

        scapy_pkt = scapy.Ether(rcv_pkt)

        if scapy.IP not in scapy_pkt:
            return False

        if self.expected_dst_mac and scapy_pkt.dst != self.expected_dst_mac:
            return False

        if scapy_pkt[scapy.IP].src != self.session_src_ip:
            return False

        if scapy_pkt[scapy.IP].dst != self.session_dst_ip:
            return False

        if scapy_pkt[scapy.IP].ttl != self.session_ttl:
            return False

        # TODO: Fanout modifies DSCP. TOS value is olways 0.
        #if (scapy_pkt[scapy.IP].tos >> 2) != self.session_dscp:
        #    return False

        payload = str(scapy_pkt[scapy.GRE].payload)

        if self.asic_type in ["mellanox"]:
            payload = str(scapy_pkt[scapy.GRE].payload)[22:]
        if self.asic_type in ["barefoot"]:
            payload = str(scapy_pkt[scapy.GRE].payload)[12:]

        inner_pkt = scapy.Ether(payload)

        if self.mirror_stage == 'egress':
            pkt2send['IP'].ttl -= 1  # expect mirrored packet on egress has TTL decremented

        masked_inner_pkt = Mask(inner_pkt)
        masked_inner_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_inner_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        if scapy.IP in inner_pkt:
            masked_inner_pkt.set_do_not_care_scapy(scapy.IP, "chksum")

        if scapy.TCP in inner_pkt:
            masked_inner_pkt.set_do_not_care_scapy(scapy.TCP, "chksum")

        return dataplane.match_exp_pkt(masked_inner_pkt, pkt2send)

    def runSendReceiveTest(self, pkt, src_port, dst_ports):
        if self.expect_received:
            return self.sendReceive(pkt, src_port, dst_ports)
        else:
            return not self.sendReceive(pkt, src_port, dst_ports)


    @reportResults("Verify SRC IP match")
    def verifySrcIp(self):
        pkt = self.base_pkt.copy()
        pkt['IP'].src = "20.0.0.10"
        return self.runSendReceiveTest(pkt, self.src_port, self.dst_ports)


    @reportResults("Verify DST IP match")
    def verifyDstIp(self):
        pkt = self.base_pkt.copy()
        pkt['IP'].dst = "30.0.0.10"
        return self.runSendReceiveTest(pkt, self.src_port, self.dst_ports)


    @reportResults("Verify L4 SRC port match")
    def verifyL4SrcPort(self):
        pkt = self.base_pkt.copy()
        pkt['TCP'].sport = 0x1235
        return self.runSendReceiveTest(pkt, self.src_port, self.dst_ports)


    @reportResults("Verify L4 DST port match")
    def verifyL4DstPort(self):
        pkt = self.base_pkt.copy()
        pkt['TCP'].dport = 0x1235
        return self.runSendReceiveTest(pkt, self.src_port, self.dst_ports)


    @reportResults("Verify IP protocol match")
    def verifyIpProtocol(self):
        pkt = self.base_pkt.copy()
        pkt['IP'].proto = 0x7E
        return self.runSendReceiveTest(pkt, self.src_port, self.dst_ports)


    @reportResults("Verify TCP flags match")
    def verifyTcpFlags(self):
        pkt = self.base_pkt.copy()
        pkt['TCP'].flags = 0x12
        return self.runSendReceiveTest(pkt, self.src_port, self.dst_ports)


    @reportResults("Verify L4 SRC port range match")
    def verifyL4SrcPortRange(self):
        pkt = self.base_pkt.copy()
        pkt['TCP'].sport = 4675
        return self.runSendReceiveTest(pkt, self.src_port, self.dst_ports)


    @reportResults("Verify L4 DST port range match")
    def verifyL4DstPortRange(self):
        pkt = self.base_pkt.copy()
        pkt['TCP'].dport = 4675
        return self.runSendReceiveTest(pkt, self.src_port, self.dst_ports)


    @reportResults("Verify IP DSCP match")
    def verifyIpDscp(self):
        pkt = self.base_pkt.copy()
        pkt['IP'].tos = 51 << 2
        return self.runSendReceiveTest(pkt, self.src_port, self.dst_ports)


    def runEverflowTests(self):
        """
        @summary: Crete and send packet to verify each ACL rule
        @return: Number of tests passed
        """

        tests_passed = 0
        self.tests_total = 0

        if self.verifySrcIp():
            tests_passed += 1

        if self.verifyDstIp():
            tests_passed += 1

        if self.verifyL4SrcPort():
            tests_passed += 1

        if self.verifyL4DstPort():
            tests_passed += 1

        if self.verifyIpProtocol():
            tests_passed += 1

        if self.verifyTcpFlags():
            tests_passed += 1

        if self.verifyL4SrcPortRange():
            tests_passed += 1

        if self.verifyL4DstPortRange():
            tests_passed += 1

        if self.verifyIpDscp():
            tests_passed += 1

        return tests_passed, self.tests_total


    def runTest(self):
        """
        @summary: Run Everflow tests
        """
        (tests_passed, tests_total) = self.runEverflowTests()
        print "Passed %d test of %d" % (tests_passed, tests_total)

        assert(tests_passed == tests_total)
