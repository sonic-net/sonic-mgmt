"""
The SnappiTestParams module allows for modular pass through of test parameters for all Snappi based tests.
"""

from tests.common.snappi_tests.common_helpers import packet_capture


class SnappiTestParams():
    def __init__(self):
        """
        Initialize the SnappiTestParams class

        Params:
            headroom_test_params (array): 2 element array if the associated pfc pause quanta
                                    results in no packet drop [pfc_delay, headroom_result]
            pfc_pause_src_mac (str): PFC pause source MAC address ex. '00:00:00:fa:ce:01'
            set_pfc_class_enable_vec (bool): PFC class enable vector setting
            packet_capture_type (ENUM): packet capture type ex. packet_capture.IP_CAPTURE
            packet_capture_file (str): packet capture file ex. 'capture.pcapng'
            packet_capture_ports (list): packet capture ports on ixia chassis ex. ['Port 1', 'Port 2']
            is_snappi_ingress_port_cap (bool): whether or not the packet capture is on the tgen ingress port, if False,
                                             then pcap is on the tgen egress port
            base_flow_config (dict): base flow configuration
            test_tx_frames (list): number of test frames transmitted for priorities to test ex. [2000, 3000]
                                    for priorities 3 and 4
            duthost1 (obj): DUT 1 in case of multi-dut testbed environment
            rx_port (dict): Contains the details of the rx port
                            ex : {'peer_port': 'Ethernet8','prefix': u'24','asic_value':'asic0'}
            rx_port_id (int): port_id of the rx port ex: 1
            duthost2 (obj): DUT 2 in case of multi-dut testbed environment
            tx_port (dict): Contains the details of the tx port
                            ex: {'peer_port': 'Ethernet12','prefix': u'24','asic_value':'asic1'}
            tx_port_id (int): port_id of the tx port ex: 2
        """
        self.headroom_test_params = None
        self.pfc_pause_src_mac = None
        self.set_pfc_class_enable_vec = True
        self.packet_capture_type = packet_capture.NO_CAPTURE
        self.packet_capture_file = None
        self.packet_capture_ports = None
        self.is_snappi_ingress_port_cap = True
        self.base_flow_config = None
        self.test_tx_frames = 0
        self.duthost1 = None
        self.rx_port = None
        self.rx_port_id = None
        self.duthost2 = None
        self.tx_port = None
        self.tx_port_id = None
