import logging
import struct
import dpkt
from dpkt.utils import mac_to_str

logger = logging.getLogger(__name__)

PFC_MAC_CONTROL_CODE = 0x8808
SAMPLE_SIZE = 100000
UTIL_THRESHOLD = 0.8
PFC_DEST_MAC = "01:80:c2:00:00:01"


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
    # print("CBFC Opcode:", cbfc_opcode)
    class_enable_vec = struct.unpack(">H", pfc_frame_bytes[2:4])[0]
    # print("Class Enable Vector:", class_enable_vec)
    class_pause_times = []
    for i in range(0, 16, 2):
        class_pause_times.append(struct.unpack(">H", pfc_frame_bytes[i + 4:i + 6])[0])
    # print("Class Pause Times:", [x for x in class_pause_times])

    return cbfc_opcode, class_enable_vec, class_pause_times


def validate_pfc_frame(pfc_cap_file):
    """
    Validate PFC frame by checking the CBFC opcode, class enable vector and class pause times.

    Args:
        pfc_cap: PFC frame bytes

    Returns:
        True if valid PFC frame, False otherwise
    """
    f = open(pfc_cap_file, "rb")
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
            cbfc_opcode, class_enable_vec, class_pause_times = read_pfc_frame(bytes(eth.data))
            is_valid_cbfc_opcode = check_cbfc_opcode(cbfc_opcode)
            is_valid_class_enable_vec = check_class_enable_vec(class_enable_vec)
            is_valid_class_pause_times = check_class_pause_times(class_pause_times)
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
    Check if class enable vector is valid.

    Args:
        class_enable_vec (int): class enable vector

    Returns:
        True if valid class enable vector, False otherwise
    """
    valid_options = [0x0, 0x1, 0x2, 0x4, 0x8, 0x10, 0x18, 0x20, 0x40, 0x80]
    if class_enable_vec in valid_options:
        return True
    else:
        return False


def check_class_pause_times(class_pause_times):
    """
    Check if class pause times are valid.

    Args:
        class_pause_times (list of ints): class pause times

    Returns:
        True if valid class pause times, False otherwise
    """
    for class_pause_time in class_pause_times:
        if class_pause_time < 0x0 and class_pause_time > 0xFFFF:
            return False
    return True
