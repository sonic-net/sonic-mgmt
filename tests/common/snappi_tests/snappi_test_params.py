"""
The SnappiTestParams module allows for modular pass through of test parameters for all Snappi based tests.
"""

from tests.common.snappi_tests.common_helpers import packet_capture
from tests.common.snappi_tests.traffic_flow_config import TrafficFlowConfig
from tests.common.snappi_tests.multi_dut_params import MultiDUTParams


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
            buffer_lossless_tx_bytes (dict): number of test bytes held in buffer of switch for
                                    test for lossless priorities ex. {3: 2000, 4: 3000}
            multi_dut_params (MultiDUTParams obj): contains details of duthost objects,
                                                   multidut_ports and other parameters
            test_iterations (int) : No of iterations in the test
                for ex. priorities 3 and 4
            gen_background_traffic (bool): whether or not to generate background traffic (default: True)
            poll_device_runtime (bool): whether or not to poll the device for stats when traffic is running
                                        (default: False)
                for priorities 3 and 4
            gen_background_traffic (bool): whether or not to generate background traffic (default: True)
            ecn_params (dict): ECN parameters
                Dict values:
                    kmin: minimum ECN marking threshold
                    kmax: maximum ECN marking threshold
                    pmax: maximum ECN marking probability
            traffic_flow_config (TrafficFlowConfig obj): traffic flow configuration object
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
        self.buffer_lossless_tx_bytes = {}
        self.multi_dut_params = MultiDUTParams()
        self.test_iterations = 1
        self.gen_background_traffic = True
        self.poll_device_runtime = True
        self.ecn_params = None
        self.traffic_flow_config = TrafficFlowConfig()
