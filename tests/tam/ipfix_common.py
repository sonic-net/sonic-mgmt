"""
IPFIX packet structures for TAM Mirror on Drop testing.

This module provides basic IPFIX packet parsing capabilities for validating
TAM Mirror on Drop IPFIX reports.
"""

from scapy.all import Packet, ShortField, IntField, bind_layers, LongField, ByteField
from scapy.layers.inet import UDP


class IPFIXHeader(Packet):
    """
    IPFIX Message Header as defined in RFC 7011.

    The IPFIX Message Header format:
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       Version Number          |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Export Time                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Observation Domain ID                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    name = "IPFIXHeader"
    fields_desc = [
        ShortField("version", 10),          # IPFIX version (10)
        ShortField("length", 0),            # Total length of IPFIX message
        IntField("export_time", 0),         # Time when message was exported
        IntField("sequence_number", 0),     # Sequence number
        IntField("observation_domain_id", 0),  # Observation domain ID
    ]


class PsampModHeader(Packet):
    name = "PsampModHeader"
    fields_desc = [
        ShortField("template_id", 0),
        ShortField("psamp_length", 0),
        LongField("observation_time_ns", 0),
        IntField("switch_id", 0),
        ShortField("egress_port", 0),
        ShortField("ingress_port", 0),
        ByteField("drop_reason_ip", 0),
        ByteField("drop_reason_ep_or_mmu", 0),
        ShortField("user_meta_data", 0),
        ByteField("cos", 0),
        ByteField("variable_length_indicator", 0xFF),
        ShortField("packet_samp_length", 0)
    ]


# Bind IPFIX layers
bind_layers(UDP, IPFIXHeader, dport=4739)  # Standard IPFIX port
bind_layers(IPFIXHeader, PsampModHeader, version=10)  # PsampModHeader
