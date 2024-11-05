"""
The CiscoPFCPacket module  handles Cisco specific PFC frame checks
"""
from tests.common.snappi_tests.pfc_packet import PFCPacket, PRIO_DEFAULT_LEN


class CiscoPFCPacket(PFCPacket):
    def __init__(self, pfc_frame_bytes=None, cbfc_opcode=None, class_enable_vec=None, class_pause_times=None):
        """
        Initialize the PFCPacket base class

        """
        super().__init__(pfc_frame_bytes, cbfc_opcode, class_enable_vec, class_pause_times)

    def _check_class_pause_times(self):
        """
        Check if class pause times are valid. Both conditions must be met:
        1) class pause times are between 0x0 and 0xFFFF
        2) class pause times are 0 if the corresponding bit in the class enable vector is 0, and vice versa

        Args:

        Returns:
            True if valid class pause times, False otherwise
        """
        for i in range(len(self.class_pause_times)):
            if self.class_pause_times[i] < 0x0 or self.class_pause_times[i] > 0xFFFF:
                return False
            elif self.class_pause_times[i] == 0x0 and self.class_enable_vec[PRIO_DEFAULT_LEN - i - 1] == "1":
                return False

        return True
