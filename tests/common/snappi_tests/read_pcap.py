import logging
import dpkt
from dpkt.utils import mac_to_str

from tests.common.snappi_tests.pfc_packet import PFCPacket

logger = logging.getLogger(__name__)

PFC_MAC_CONTROL_CODE = 0x8808
PFC_DEST_MAC = "01:80:c2:00:00:01"


def validate_pfc_frame(pfc_pcap_file, SAMPLE_SIZE=15000, UTIL_THRESHOLD=0.8):
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
    seen_non_zero_cev = False  # Flag for checking if any PFC frame has non-zero class enable vector

    curPktCount = 0
    curPFCPktCount = 0
    for _, buf in pcap:
        if curPktCount >= SAMPLE_SIZE:
            break
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == PFC_MAC_CONTROL_CODE:
            dest_mac = mac_to_str(eth.dst)
            if dest_mac.lower() != PFC_DEST_MAC:
                return False, "Destination MAC address is not 01:80:c2:00:00:01"
            pfc_packet = PFCPacket(pfc_frame_bytes=bytes(eth.data))
            if not pfc_packet.is_valid():
                logger.info("PFC frame {} is not valid. Please check the capture file.".format(curPktCount))
                return False, "PFC frame is not valid"
            cev = [int(i) for i in pfc_packet.class_enable_vec]
            seen_non_zero_cev = True if sum(cev) > 0 else seen_non_zero_cev
            curPFCPktCount += 1
        curPktCount += 1

    if not seen_non_zero_cev:
        logger.info("No PFC frames with non-zero class enable vector found in the capture file.")
        return False, "No PFC frames with non-zero class enable vector found"

    f.close()
    pfc_util = curPktCount / SAMPLE_SIZE

    if curPktCount == 0:
        logger.info("No PFC frames found in the capture file.")
        return False, "No PFC frames found in the capture file"
    elif pfc_util < UTIL_THRESHOLD:
        logger.info("PFC utilization is too low. Please check the capture file.")
        return False, "PFC utilization is too low"

    return True, None


def get_ipv4_pkts(pcap_file_name, protocol_num=61):
    """
    Get IPv4 packets from the pcap/pcapng file

    Args:
        pcap_file_name (str): name of the pcap/pcapng file to store captured packets
        protocol_num (int): protocol number to filter packets. See
                            https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers

    Returns:
        Captured IP packets (list)
    """
    f = open(pcap_file_name, "rb")
    pcap = dpkt.pcapng.Reader(f)

    logger.info("Reading packets from pcap file -> {}".format(pcap_file_name))
    logger.info("Extracting ethernet frames from pcap file")

    ip_pkts = []
    for _, pkt in pcap:
        eth = dpkt.ethernet.Ethernet(pkt)
        if isinstance(eth.data, dpkt.ip.IP):
            if eth.data.p == protocol_num:
                ip_pkts.append(eth.data)

    return ip_pkts


def is_ecn_marked(ip_pkt):
    """
    Determine if an IP packet is ECN congestion marked

    Args:
        ip_pkt (obj): IP packet

    Returns:
        Return if the packet is ECN congestion marked (bool)
    """
    logger.info("Checking if the packet is ECN congestion marked")
    return (ip_pkt.tos & 3) == 3
