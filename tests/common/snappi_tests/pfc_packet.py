"""
The PFCPacket module allows for modular pass through of a PFC Packet's parameters for all Snappi based tests,
and appropriate storage of the PFC Packet's parameters.
"""

import logging
import struct

logger = logging.getLogger(__name__)

PFC_MAC_CONTROL_CODE = 0x8808
PFC_DEST_MAC = "01:80:c2:00:00:01"
PRIO_DEFAULT_LEN = 8


class PFCPacket():
    def __init__(self, pfc_frame_bytes=None, cbfc_opcode=None, class_enable_vec=None, class_pause_times=None):
        """
        Initialize the PFCPacket class

        Params:
            cbfc_opcode (int): Class-based Flow Control (CBFC) opcode
            class_enable_vec (list of int (binary)): class enable vector for PFC frame
                                                    ex. ['0', '0', '1', '0', '0', '0', '0', '0']
            class_pause_times (list of int): class pause times for PFC frame between 0 and 65535 for 8 priorities
            is_valid_frame (bool): True if valid PFC frame, False otherwise
        """
        if pfc_frame_bytes:
            self.read_pfc_frame(pfc_frame_bytes=pfc_frame_bytes)
            self.validate_pfc_frame()
        else:
            self.cbfc_opcode = cbfc_opcode
            self.class_enable_vec = class_enable_vec
            self.class_pause_times = class_pause_times
            self.validate_pfc_frame()

    def read_pfc_frame(self, pfc_frame_bytes):
        """
        Read PFC frame bytes and return the components of the frame, specifically,
        the CBFC opcode, the class enable vector, and the class pause times.

        Args:
            pfc_frame_bytes (bytes): bytes of PFC frame
        Returns:
        """
        cbfc_opcode = struct.unpack(">H", pfc_frame_bytes[0:2])[0]
        class_enable_vec = struct.unpack(">H", pfc_frame_bytes[2:4])[0]
        class_pause_times = []
        for i in range(0, 16, 2):
            class_pause_times.append(struct.unpack(">H", pfc_frame_bytes[i + 4:i + 6])[0])

        self.cbfc_opcode = cbfc_opcode
        self.class_enable_vec = _num_to_class_enable_vec_array(class_enable_vec)
        self.class_pause_times = class_pause_times

    def _check_cbfc_opcode(self):
        """
        Check if CBFC opcode is valid.

        Args:

        Returns:
            True if valid CBFC opcode, False otherwise
        """
        if self.cbfc_opcode == 0x0101:
            return True
        else:
            return False

    def _check_class_enable_vec(self):
        """
        Check if class enable vector is valid i.e. either each bit is 0 or 1.

        Args:
            class_enable_vec (list of chars): class enable vector

        Returns:
            True if valid class enable vector, False otherwise
        """
        valid_options = ["0", "1"]
        for val in self.class_enable_vec:
            if val not in valid_options:
                return False

        return False

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
            if self.class_pause_times[i] < 0x0 and self.class_pause_times[i] > 0xFFFF:
                return False
            elif self.class_pause_times[i] > 0x0 and self.class_enable_vec[PRIO_DEFAULT_LEN - i - 1] == "0":
                return False
            elif self.class_pause_times[i] == 0x0 and self.class_enable_vec[PRIO_DEFAULT_LEN - i - 1] == "1":
                return False

        return True

    def validate_pfc_frame(self):
        """
        Validate the PFC frame. The PFC frame is valid if:
        1) CBFC opcode is 0x0101
        2) class enable vector is valid
        3) class pause times are valid

        Check function subdefinitions for more details.
        """
        is_valid_cbfc_opcode = self._check_cbfc_opcode()
        is_valid_class_enable_vec = self._check_class_enable_vec()
        is_valid_class_pause_times = self._check_class_pause_times()
        if not is_valid_cbfc_opcode or not is_valid_class_enable_vec or not is_valid_class_pause_times:
            self.is_valid_frame = False
        else:
            self.is_valid_frame = True

    def is_valid(self):
        """
        Check if PFC frame is valid.

        Args:

        Returns:
            True if valid PFC frame, False otherwise
        """
        return self.is_valid_frame


# Helper methods
def _num_to_class_enable_vec_array(class_enable_vec_int):
    """
    Convert a class enable vector number (base 10) to a class enable vector array (binary).

    Args:
        class_enable_vec_int (int): class enable vector number (base 10)
    Returns:
        class_enable_vec_array (list of chars): class enable vector array (binary string format)
                                                ex. ['0', '0', '1', '0', '0', '0', '0', '0']
    """
    class_enable_vec_binary = bin(class_enable_vec_int)[2:]

    if len(class_enable_vec_binary) < PRIO_DEFAULT_LEN:
        fill = "0" * (PRIO_DEFAULT_LEN - len(class_enable_vec_binary))
        class_enable_vec_binary = fill + class_enable_vec_binary

    class_enable_vec_array = [val for val in class_enable_vec_binary]

    return class_enable_vec_array
