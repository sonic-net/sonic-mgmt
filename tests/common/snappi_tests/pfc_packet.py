"""
The PFCPacket module allows for modular pass through of a PFC Packet's parameters for all Snappi based tests,
and appropriate storage of the PFC Packet's parameters.
"""


class PFCPacket():
    def __init__(self):
        """
        Initialize the PFCPacket class

        Params:
            cbfc_opcode (int): CBFC opcode
            class_enable_vec (list of int (binary)): class enable vector for PFC frame
                                                    ex. ['0', '0', '1', '0', '0', '0', '0', '0']
            class_pause_times (list of int): class pause times for PFC frame between 0 and 65535 for 8 priorities
        """
        self.cbfc_opcode = 0
        self.class_enable_vec = 0
        self.class_pause_times = 0
