import ptf
from ptf.base_tests import BaseTest
from ptf.testutils import send, simple_eth_packet, test_params_get


class FdbMacLearningTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = test_params_get()        # noqa: F405

    # --------------------------------------------------------------------------
    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.router_mac = self.test_params['router_mac']
        self.dummy_mac_prefix = self.test_params['dummy_mac_prefix']
        self.dut_ptf_ports = self.test_params['dut_ptf_ports']
        self.mac_table = []

    # --------------------------------------------------------------------------
    def populateFdbForInterface(self):
        for dut_port, ptf_port in self.dut_ptf_ports:
            mac = self.dummy_mac_prefix + ":" + "{:02X}".format(ptf_port)
            pkt = simple_eth_packet(eth_dst=self.router_mac,        # noqa: F405
                                    eth_src=mac,
                                    eth_type=0x1234)
            send(self, ptf_port, pkt)
            self.mac_table.append((ptf_port, mac))

    # --------------------------------------------------------------------------
    def runTest(self):
        self.populateFdbForInterface()

    # --------------------------------------------------------------------------
