import logging
import dpkt
from dpkt.utils import mac_to_str

from tests.common.snappi_tests.pfc_packet import PFCPacket

logger = logging.getLogger(__name__)

PFC_MAC_CONTROL_CODE = 0x8808
PFC_DEST_MAC = "01:80:c2:00:00:01"


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
            pfc_packet = PFCPacket(pfc_frame_bytes=bytes(eth.data))
            if not pfc_packet.is_valid():
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
