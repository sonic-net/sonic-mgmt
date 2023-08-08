import logging
import struct
import dpkt
from dpkt.utils import mac_to_str

from tests.common.snappi_tests.pfc_packet import PFCPacket

logger = logging.getLogger(__name__)

PFC_MAC_CONTROL_CODE = 0x8808
PFC_DEST_MAC = "01:80:c2:00:00:01"
PRIO_DEFAULT_LEN = 8


def read_pfc_frame(pfc_frame_bytes):
    """
    Read PFC frame bytes and return the components of the frame, specifically,
    the CBFC opcode, the class enable vector, and the class pause times.

    Args:
        pfc_frame_bytes (bytes): bytes of PFC frame

    Returns:
        cbfc_opcode (int): CBFC opcode
        class_enable_vec (int): class enable vector
        class_pause_times (list of ints): class pause times
    """
    cbfc_opcode = struct.unpack(">H", pfc_frame_bytes[0:2])[0]
    class_enable_vec = struct.unpack(">H", pfc_frame_bytes[2:4])[0]
    class_pause_times = []
    for i in range(0, 16, 2):
        class_pause_times.append(struct.unpack(">H", pfc_frame_bytes[i + 4:i + 6])[0])

    pfc_packet = PFCPacket()
    pfc_packet.cbfc_opcode = cbfc_opcode
    pfc_packet.class_enable_vec = num_to_class_enable_vec_array(class_enable_vec)
    pfc_packet.class_pause_times = class_pause_times

    return pfc_packet


def validate_pfc_frame(pfc_pcap_file, SAMPLE_SIZE=100000, UTIL_THRESHOLD=0.8):
    """
    Validate PFC frame by checking the CBFC opcode, class enable vector and class pause times.

    Args:
        pfc_cap: PFC pcap file
        SAMPLE_SIZE: number of packets to sample
        UTIL_THRESHOLD: threshold for PFC utilization to check if enough PFC frames were sent

    Returns:
        True if valid PFC frame, False otherwise
    """
    f = open(pfc_pcap_file, "rb")
    pcap = dpkt.pcapng.Reader(f)

    curPktCount = 0
    curPFCPktCount = 0
    for _, buf in pcap:
        if curPktCount >= SAMPLE_SIZE:
            break
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == PFC_MAC_CONTROL_CODE:
            dest_mac = mac_to_str(eth.dst)
            if dest_mac.lower() != PFC_DEST_MAC:
                return False
            pfc_packet = read_pfc_frame(bytes(eth.data))
            is_valid_cbfc_opcode = check_cbfc_opcode(pfc_packet.cbfc_opcode)
            is_valid_class_enable_vec = check_class_enable_vec(pfc_packet.class_enable_vec)
            is_valid_class_pause_times = check_class_pause_times(pfc_packet.class_pause_times)
            if not is_valid_cbfc_opcode or not is_valid_class_enable_vec or not is_valid_class_pause_times:
                logger.info("PFC frame {} is not valid. Please check the capture file.".format(curPktCount))
                return False
            curPFCPktCount += 1
        curPktCount += 1

    f.close()
    pfc_util = curPktCount / SAMPLE_SIZE

    if curPktCount == 0:
        logger.info("No PFC frames found in the capture file.")
        return False
    elif pfc_util < UTIL_THRESHOLD:
        logger.info("PFC utilization is too low. Please check the capture file.")
        return False

    return True


def check_cbfc_opcode(cbfc_opcode):
    """
    Check if CBFC opcode is valid.

    Args:
        cbfc_opcode (int): CBFC opcode

    Returns:
        True if valid CBFC opcode, False otherwise
    """
    if cbfc_opcode == 0x0101:
        return True
    else:
        return False


def check_class_enable_vec(class_enable_vec):
    """
    Check if class enable vector is valid i.e. either each bit is 0 or 1.

    Args:
        class_enable_vec (list of chars): class enable vector

    Returns:
        True if valid class enable vector, False otherwise
    """
    valid_options = ["0", "1"]
    for val in class_enable_vec:
        if val not in valid_options:
            return False

    return False


def check_class_pause_times(class_pause_times, class_enable_vec):
    """
    Check if class pause times are valid. Both conditions must be met:
    1) class pause times are between 0x0 and 0xFFFF
    2) class pause times are 0 if the corresponding bit in the class enable vector is 0, and vice versa

    Args:
        class_pause_times (list of ints): class pause times
        class_enable_vec (int): class enable vector

    Returns:
        True if valid class pause times, False otherwise
    """
    for i in range(len(class_pause_times)):
        if class_pause_times[i] < 0x0 and class_pause_times[i] > 0xFFFF:
            return False
        elif class_pause_times[i] > 0x0 and class_enable_vec[PRIO_DEFAULT_LEN - i - 1] == "0":
            return False
        elif class_pause_times[i] == 0x0 and class_enable_vec[PRIO_DEFAULT_LEN - i - 1] == "1":
            return False

    return True


def num_to_class_enable_vec_array(class_enable_vec_int):
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
