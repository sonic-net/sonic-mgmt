"""
The SnappiTestParams module allows for modular pass through of test parameters for all Snappi based tests.
"""

from tests.common.snappi.common_helpers import packet_capture


class SnappiTestParams():
    def __init__(self):
        """
        Initialize the SnappiTestParams class

        Params:
            headroom_test_params (list): headroom test parameters
            pfc_pause_src_mac (str): PFC pause source MAC address
            pfc_class_enable_vec (ENUM): PFC class enable vector setting
            packet_capture_type (ENUM): packet capture type
            packet_capture_file (str): packet capture file
            packet_capture_ports (list): packet capture ports on ixia chassis
            base_flow_config (dict): base flow configuration
            test_tx_frames (list): number of test frames transmitted for priorities to test ex. [2000, 3000]
                for priorities 3 and 4
        """
        self.headroom_test_params = None
        self.pfc_pause_src_mac = None
        self.set_pfc_class_enable_vec = True
        self.packet_capture_type = packet_capture.NO_CAPTURE
        self.packet_capture_file = None
        self.packet_capture_ports = None
        self.is_tgen_ingress_port_cap = True
        self.base_flow_config = None
        self.test_tx_frames = 0
