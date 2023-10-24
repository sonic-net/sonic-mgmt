import ptf
import ptf.dataplane as dataplane
from ptf.base_tests import BaseTest
from ptf.mask import *
from ptf.testutils import *
from ptf.thriftutils import *

import scapy.main
import scapy.contrib
from scapy.packet import *
from scapy.fields import *
from scapy.all import *

DTEL_REPORT_NEXT_PROTO_ETHERNET       = 0
DTEL_REPORT_NEXT_PROTO_DROP           = 1
DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL   = 2

SWITCH_DTEL_EVENT_TYPE_FLOW_STATE_CHANGE = 0
SWITCH_DTEL_EVENT_TYPE_FLOW_REPORT_ALL_PACKETS = 1
SWITCH_DTEL_EVENT_TYPE_FLOW_TCPFLAG = 2
SWITCH_DTEL_EVENT_TYPE_Q_REPORT_THRESHOLD_BREACH = 3
SWITCH_DTEL_EVENT_TYPE_Q_REPORT_TAIL_DROP = 4
SWITCH_DTEL_EVENT_TYPE_DROP_REPORT = 5

UDP_PORT_DTEL_REPORT = 32766
MAX_QUANTIZATION = 30

# Cell is the unit for queue size and it's expressed in bytes
CELL_SIZE = 80
int_l45_encap = 'dscp'

################################################################################
"""
DTel Report Header utilities
"""
class DTEL_REPORT_HDR(Packet):
    name = "DTel Report header"
    fields_desc = [ BitField("ver", 0, 4), BitField("next_proto", 0, 4),
                    BitField("dropped", 0, 1),
                    BitField("congested_queue", 0, 1),
                    BitField("path_tracking_flow", 0, 1),
                    BitField("reserved", 0, 15),
                    BitField("hw_id", 0, 6),
                    IntField("sequence_number", 0),
                    XIntField("timestamp", 0x00000000)]

def dtel_report(packet,
               ver=0,
               next_proto=0,
               dropped=0,
               congested_queue=0,
               path_tracking_flow=0,
               hw_id=0,
               sequence_number=0,
               timestamp=0):
    dtel_report_hdr = DTEL_REPORT_HDR(ver = ver,
                      next_proto = next_proto,
                      dropped = dropped,
                      congested_queue = congested_queue,
                      path_tracking_flow = path_tracking_flow,
                      hw_id = hw_id,
                      sequence_number = sequence_number,
                      timestamp = timestamp)
    return dtel_report_hdr / packet

def ipv4_dtel_pkt(pktlen=0,
                      eth_dst='00:01:02:03:04:05',
                      eth_src='00:06:07:08:09:0a',
                      dl_vlan_enable=False,
                      vlan_vid=0,
                      vlan_pcp=0,
                      dl_vlan_cfi=0,
                      ip_src='192.168.0.1',
                      ip_dst='192.168.0.2',
                      ip_tos=0,
                      ip_ecn=None,
                      ip_dscp=None,
                      ip_ttl=64,
                      ip_id=0x0001,
                      ip_ihl=None,
                      ip_options=False,
                      udp_sport=0,
                      udp_dport=UDP_PORT_DTEL_REPORT,
                      with_udp_chksum=False,
                      ver=0,
                      next_proto=0,
                      dropped=0,
                      congested_queue=0,
                      path_tracking_flow=0,
                      hw_id=0,
                      sequence_number=0,
                      inner_frame=None
                      ):

    telem_pkt = DTEL_REPORT_HDR(ver = ver,
                      next_proto = next_proto,
                      dropped = dropped,
                      congested_queue = congested_queue,
                      path_tracking_flow = path_tracking_flow,
                      hw_id = hw_id,
                      sequence_number = sequence_number)

    if inner_frame:
        telem_pkt = telem_pkt / inner_frame

    udp_pkt = simple_udp_packet(
                      pktlen=pktlen,
                      eth_dst=eth_dst,
                      eth_src=eth_src,
                      dl_vlan_enable=dl_vlan_enable,
                      vlan_vid=vlan_vid,
                      vlan_pcp=vlan_pcp,
                      dl_vlan_cfi=dl_vlan_cfi,
                      ip_src=ip_src,
                      ip_dst=ip_dst,
                      ip_tos=ip_tos,
                      ip_ecn=ip_ecn,
                      ip_dscp=ip_dscp,
                      ip_ttl=ip_ttl,
                      ip_id=ip_id,
                      ip_ihl=ip_ihl,
                      ip_options=ip_options,
                      udp_sport=udp_sport,
                      udp_dport=udp_dport,
                      with_udp_chksum=with_udp_chksum,
                      udp_payload=telem_pkt
    )

    udp_pkt[IP].flags = 0x2
    return udp_pkt

def match_dtel_pkt(exp_pkt, pkt, ignore_tstamp=True, ignore_seq_num=True, ignore_queue_depth=True):
    """
    Compare DTel report packets, ignore the timestamp and sequence number
    values. Just make sure that the timestamp is non-zero.
    """
    #check that received packet has a DTel report header
    dtel_report = pkt.getlayer(DTEL_REPORT_HDR)
    if dtel_report == None:
        #self.logger.error("No DTel report pkt received")
        return False

    #check that timestamp is non-zero
    if dtel_report.timestamp == 0:
        #self.logger.error("Invalid DTel report timestamp")
        return False

    #check that expected packet has a DTel report header
    exp_dtel_report = exp_pkt.getlayer(DTEL_REPORT_HDR)
    if exp_dtel_report == None:
        #self.logger.error("exp_pkt is not DTel report packet")
        return False

    #ignore timestamp
    if ignore_tstamp:
        exp_dtel_report.timestamp = 0
        dtel_report.timestamp = 0

    #ignore sequence number
    if ignore_seq_num:
        exp_dtel_report.sequence_number = 0
        dtel_report.sequence_number = 0

    #ignore queue depth
    try:
        if ignore_queue_depth or (dtel_report.queue_depth <= pkt.len/CELL_SIZE +1):
            exp_dtel_report.queue_depth = 0
            dtel_report.queue_depth = 0
    except AttributeError:
        pass

    #compare
    return dataplane.match_exp_pkt(exp_pkt, pkt)

def verify_dtel_packet(test, pkt, port):
    """
    Check that an expected packet is received
    """
    logging.debug("Checking for pkt on port %r", port)
    (_, rcv_port, rcv_pkt, pkt_time) = \
            test.dataplane.poll(port_number=port, timeout=2, exp_pkt=None)
    test.assertTrue(rcv_pkt != None, "Did not receive pkt on %r" % port)
    # convert rcv_pkt string back to layered pkt
    nrcv = pkt.__class__(rcv_pkt)

    #pkt.show2()
    #nrcv.show2()
    #hexdump(pkt)
    #hexdump(nrcv)
    #print_pkt_diff(pkt, nrcv)
    test.assertTrue(match_dtel_pkt(pkt, nrcv),
                    "Received packet did not match expected packet")

################################################################################
"""
Postcard utilities
"""
class POSTCARD_HDR(Packet):
    name = "Postcard header"
    fields_desc = [ IntField("switch_id", 0x0),
                    ShortField("ingress_port", 0x0),
                    ShortField("egress_port", 0x0),
                    XByteField("queue_id", 0x0),
                    X3BytesField("queue_depth", 0x0),
                    IntField("egress_tstamp", 0x0)]

def bind_postcard_pkt():
    bind_layers(UDP, DTEL_REPORT_HDR, dport=UDP_PORT_DTEL_REPORT)
    bind_layers(DTEL_REPORT_HDR, POSTCARD_HDR,
                next_proto=DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL)
    bind_layers(POSTCARD_HDR, Ether)

def split_postcard_pkt():
    split_layers(UDP, DTEL_REPORT_HDR, dport=UDP_PORT_DTEL_REPORT)
    split_layers(DTEL_REPORT_HDR, POSTCARD_HDR,
                 next_proto=DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL)
    split_layers(POSTCARD_HDR, Ether)

def postcard_report(packet,
                    switch_id=0,
                    ingress_port=0,
                    egress_port=0,
                    queue_id=0,
                    queue_depth=0,
                    egress_tstamp=0):
    postcard_hdr = POSTCARD_HDR(switch_id = switch_id,
                                ingress_port = ingress_port,
                                egress_port = egress_port,
                                queue_id = queue_id,
                                queue_depth = queue_depth,
                                egress_tstamp = egress_tstamp)
    return postcard_hdr / packet

def ignore_postcard_values(exp_pkt, pkt, error_on_zero=False):
    """
    Reset latency values to zero in postcard reports.
    Just make sure the latency and tstamp values are non-zero.
    """
    exp_pkt_postcard_hdr = exp_pkt.getlayer(POSTCARD_HDR)
    pkt_postcard_hdr = pkt.getlayer(POSTCARD_HDR)


    if exp_pkt_postcard_hdr == None or pkt_postcard_hdr == None:
        print "No postcard header in the packet"
        return False

    if error_on_zero and pkt_postcard_hdr.egress_tstamp == 0:
        print "Egress timestamp is zero"
        return False

    exp_pkt_postcard_hdr.egress_tstamp = 0
    pkt_postcard_hdr.egress_tstamp = 0

    return True

def verify_postcard_dtel_packet(test, rcv_pkt, exp_pkt,
                                    ignore_seq_num = True):

    # convert rcv_pkt string back to layered pkt
    nrcv = exp_pkt.__class__(rcv_pkt)
    test.assertTrue(ignore_postcard_values(exp_pkt, nrcv, True),
                    "Received packet did not match expected packet")
    test.assertTrue(match_dtel_pkt(exp_pkt, nrcv,
                                       ignore_seq_num = ignore_seq_num),
                    "Received packet did not match expected packet")
    return nrcv

def verify_postcard_packet(test, exp_pkt, port,
                          ignore_seq_num = True):
    """
    Check that an expected postcard report is received
    while ignoring latency value and timestamp value.
    Just make sure the latency and tstamp values are non-zero.
    """
    logging.debug("Checking for pkt on port %r", port)
    (_, rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(
        port_number=port, timeout=2, exp_pkt=None)
    nrcv = exp_pkt.__class__(rcv_pkt)
    while nrcv[Ether].type == 0x88cc: # ignore LLDP packets
        (_, rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(
            port_number=port, timeout=2, exp_pkt=None)
        nrcv = exp_pkt.__class__(rcv_pkt)
    test.assertTrue(rcv_pkt != None, "Did not receive pkt on %r" % port)
    verify_postcard_dtel_packet(test, rcv_pkt, exp_pkt,
                                    ignore_seq_num = ignore_seq_num)

def receive_postcard_packet(test, exp_pkt, port):
    (_, rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(
        port_number=port, timeout=2, exp_pkt=None)
    nrcv = None
    if rcv_pkt:
        nrcv = exp_pkt.__class__(rcv_pkt)
        while nrcv[Ether].type == 0x88cc: # ignore LLDP packets
            (_, rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(
                port_number=port, timeout=2, exp_pkt=None)
        if rcv_pkt:
            nrcv = verify_postcard_dtel_packet(test, rcv_pkt, exp_pkt)
    return nrcv

################################################################################
"""
Drop utilities
"""
class DROP_HDR(Packet):
    name = "Drop header"
    fields_desc = [ IntField("switch_id", 0x0),
                    ShortField("ingress_port", 0x0),
                    ShortField("egress_port", 0x0),
                    XByteField("queue_id", 0x0),
                    XByteField("drop_reason", 0x0),
                    ShortField("pad", 0x0)]

def bind_drop_pkt():
    bind_layers(UDP, DTEL_REPORT_HDR, dport=UDP_PORT_DTEL_REPORT)
    bind_layers(DTEL_REPORT_HDR, DROP_HDR,
                next_proto=DTEL_REPORT_NEXT_PROTO_DROP)
    bind_layers(DROP_HDR, Ether)

def split_drop_pkt():
    split_layers(UDP, DTEL_REPORT_HDR, dport=UDP_PORT_DTEL_REPORT)
    split_layers(DTEL_REPORT_HDR, DROP_HDR,
                 next_proto=DTEL_REPORT_NEXT_PROTO_DROP)
    split_layers(DROP_HDR, Ether)

def drop_report(packet,
               switch_id=0,
               ingress_port=0,
               egress_port=0,
               queue_id=0,
               drop_reason=0):
    drop_hdr = DROP_HDR(switch_id = switch_id,
                      ingress_port = ingress_port,
                      egress_port = egress_port,
                      queue_id = queue_id,
                      drop_reason = drop_reason,
                      pad = 0)
    return drop_hdr / packet

################################################################################
"""
INT header definitions and utilities
"""

try:
    scapy.main.load_contrib("vxlan")
    scapy.main.load_contrib("geneve")

    VXLAN_GPE = scapy.contrib.vxlan.VXLAN_GPE
    GENEVE = scapy.contrib.geneve.GENEVE
except:
    e = sys.exc_info()[0]
    sys.exit("Scapy loading error: %s" % e)

INT_TYPE_INT                =   0x01

intl45_dscp_default_value   =   0x20
intl45_dscp_default_mask    =   0x20

INT_L45_MARKER              =   0xaaaaaaaabbbbbbbb
int_l45_marker_tcp = INT_L45_MARKER
int_l45_marker_udp = INT_L45_MARKER
int_l45_marker_icmp = INT_L45_MARKER

# Value can be changed using run_p4_tests with
# --test-params "int_l45_encap='dscp'"
# --test-params "int_l45_encap='marker'"
int_l45_encap = 'dscp'

def set_int_l45_dscp(value, mask):
  global intl45_dscp_default_value
  global intl45_dscp_default_mask
  intl45_dscp_default_value = value
  intl45_dscp_default_mask = mask

def get_int_l45_dscp_value():
  return intl45_dscp_default_value

def get_int_l45_dscp_mask():
  return intl45_dscp_default_mask

def set_int_l45_encap(encap):
    global int_l45_encap
    if encap == 'marker' or encap == 'dscp':
        int_l45_encap = encap
        print "Set int_l45_encap = %s" % int_l45_encap

def get_int_l45_encap():
    return int_l45_encap

int_l45_encap_param = test_param_get('int_l45_encap')
if int_l45_encap_param == "marker" or int_l45_encap_param == "dscp":
    set_int_l45_encap(int_l45_encap_param)

def set_int_l45_marker(marker, proto = None):
    if proto == 1 or proto==None:
        global int_l45_marker_icmp
        int_l45_marker_icmp = marker
    if proto == 6 or proto==None:
        global int_l45_marker_tcp
        int_l45_marker_tcp = marker
    if proto == 17 or proto==None:
        global int_l45_marker_udp
        int_l45_marker_udp = marker

def instantiate_payload(cls, s, _underlayer, one_layer=True):
    try:
        p = cls(s, _internal=1, _underlayer=_underlayer)
    except KeyboardInterrupt:
        raise
    except:
        p = conf.raw_layer(s, _internal=1, _underlayer=_underlayer)
    _underlayer.add_payload(p)
    if one_layer:
        if p.payload==None or isinstance(p.payload, NoPayload):
            s=None
        else:
            s=str(p.payload)
            p.remove_payload()
    return (s, p)

def find_INT_hop_info(s, pkt):
    instantiate_payload(pkt.guess_payload_class(s), s, pkt, False)

    # find first instande of INT_hop_info
    used_bytes = len(pkt.self_build()) # just my length
    # we only expect INT_META_HDR after this header
    p = pkt.payload;
    used_bytes += len(p.self_build())

    if not p or p.payload==None or p.payload==NoPayload:
        return

    # remove INT hop infos from int_meta_header
    s=str(p.payload)
    p.remove_payload()
    return (s, p, used_bytes)


class VXLAN_GPE_INT(Packet):
    name = "VXLAN_GPE_INT_header"
    fields_desc = [ XByteField("int_type", 0x01),
                    XByteField("rsvd", 0x00),
                    XByteField("length", 0x00),
                    XByteField("next_proto", 0x03) ]
    def do_dissect_payload(self, s):
        (s, last_header, used_bytes) = find_INT_hop_info(s, self)

        # extract hop info
        while s and used_bytes < self.length * 4:
            s, last_header = instantiate_payload(INT_hop_info, s, last_header)
            used_bytes+=len(last_header)

        # extract ethernet after INT
        if s:
            instantiate_payload(Ether, s, last_header, False)

class GENEVE_INT(Packet):
    name = "GENEVE_INT_header"
    fields_desc = [ XShortField("int_opt", 0x0103),
                    XByteField("int_type", 0x01),
                    BitField("rsvd", 0 , 3),
                    BitField("length", 2, 5)]
    def do_dissect_payload(self, s):
        (s, last_header, used_bytes) = find_INT_hop_info(s, self)

        # extract hop info
        while s and used_bytes < self.length * 4:
            s, last_header = instantiate_payload(INT_hop_info, s, last_header)
            used_bytes+=len(last_header)

        # extract ethernet after INT
        if s:
            instantiate_payload(Ether, s, last_header, False)

class INT_META_HDR(Packet):
    name = "INT_metadata_header"
    fields_desc = [ BitField("ver", 0, 4), BitField("rep", 0, 2),
                    BitField("c", 0, 1), BitField("e", 0, 1),
                    BitField("d", 0, 1),
                    BitField("rsvd1", 0, 2), BitField("ins_cnt", 1, 5),
                    BitField("max_hop_cnt", 32, 8),
                    BitField("total_hop_cnt", 0, 8),
                    ShortField("inst_mask", 0x8000),
                    XShortField("rsvd2_digest", 0x0000)]
    def do_dissect_payload(self, s):
        stack_max_length=bin(self.inst_mask).count("1") * self.total_hop_cnt
        # extract hop info
        stack_length = 0
        last_header = self
        while s and  stack_length < stack_max_length:
            s, last_header = instantiate_payload(INT_hop_info, s, last_header)
            stack_length+=1

        p = conf.raw_layer(s, _internal=1, _underlayer=last_header)
        last_header.add_payload(p)

# INT data header
class INT_hop_info(Packet):
    name = "INT_hop_info"
    fields_desc = [ XBitField("val", 0xFFFFFFFF, 32) ]

class INT_L45_HEAD(Packet):
    name = "INT_L45_HEAD"
    fields_desc = [ XByteField("int_type", INT_TYPE_INT),
                   XByteField("rsvd0", 0x00),
                   XByteField("length", 0x00),
                   XByteField("rsvd1", 0x00) ]
    def do_dissect_payload(self, s):
        (s, last_header, used_bytes) = find_INT_hop_info(s, self)
        # extract hop info
        if get_int_l45_encap() == 'marker':
            stack_len = self.length * 4 - 8 #  marker
        if get_int_l45_encap() == 'dscp':
            stack_len = self.length * 4
        while s and used_bytes < stack_len:
            s, last_header = instantiate_payload(INT_hop_info, s, last_header)
            used_bytes+=len(last_header)

        # extract ethernet after INT
        if s:
            if isinstance(self.underlayer, TCP_INTL45):
                instantiate_payload(self.underlayer.guess_payload_class_real(s),
                                    s, last_header, False)
            elif isinstance(self.underlayer, UDP_INTL45):
                instantiate_payload(self.underlayer.guess_payload_class_real(s),
                                    s, last_header, False)
            elif isinstance(self.underlayer, ICMP_INTL45):
                instantiate_payload(self.underlayer.guess_payload_class_real(s),
                                    s, last_header, False)
            else:
                p = conf.raw_layer(s, _internal=1, _underlayer=last_header)
                last_header.add_payload(p)

class INTL45_MARKER(Packet):
    name = "INTL45_MARKER"
    fields_desc = [ XBitField("marker", INT_L45_MARKER, 64)]

def new_guess_payload(self, payload):
    try:
        p = INTL45_MARKER(str(payload), _internal=1, _underlayer=self)
        if ((isinstance(self, TCP)
           and p[INTL45_MARKER].marker==int_l45_marker_tcp)
           or (isinstance(self, UDP)
           and p[INTL45_MARKER].marker==int_l45_marker_udp)
           or (isinstance(self, ICMP)
           and p[INTL45_MARKER].marker==int_l45_marker_icmp)):
            return INTL45_MARKER
        else:
            return self.original_guess_payload_class(self.payload)
    except:
        return self.original_guess_payload_class(self.payload)


def add_marker_to_l4(l4):
    l4.original_guess_payload_class = l4.guess_payload_class
    l4.guess_payload_class = new_guess_payload

def remove_marker_from_l4(l4):
    l4.guess_payload_class = l4.original_guess_payload_class

class ICMP_INTL45(Packet):
    name = "ICMP_INTL45"
    fields_desc = [ ByteEnumField("type",8, icmptypes),
                    MultiEnumField("code",0, icmpcodes,
                                   depends_on=lambda pkt:pkt.type,fmt="B"),
                    XShortField("chksum", None)]

    def guess_payload_class(self, payload):
        return INT_L45_HEAD

    def guess_payload_class_real(self, payload):
        return ICMP.guess_payload_class(self, payload)

    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2]+chr(ck>>8)+chr(ck&0xff)+p[4:]
        return p

class TCP_INTL45(TCP):
    name = "TCP_INTL45"

    def guess_payload_class(self, payload):
        return INT_L45_HEAD

    def guess_payload_class_real(self, payload):
        return TCP.guess_payload_class(self, payload)

class UDP_INTL45(UDP):
    name = "UDP_INTL45"

    def guess_payload_class(self, payload):
        return INT_L45_HEAD

    def guess_payload_class_real(self, payload):
        return UDP.guess_payload_class(self, payload)

def convert_int_instruction(inst=0x8000):
    if inst & 0x8000 > 0:
        # two's complement
        inst = ~inst + 1
        # return negative of two's complement
        return -(0xFFFF & inst)
    return 0xFFFF & inst

def simple_vxlan_gpe_packet(pktlen=300,
                            eth_dst='00:01:02:03:04:05',
                            eth_src='00:06:07:08:09:0a',
                            dl_vlan_enable=False,
                            vlan_vid=0,
                            vlan_pcp=0,
                            dl_vlan_cfi=0,
                            ip_src='192.168.0.1',
                            ip_dst='192.168.0.2',
                            ip_tos=0,
                            ip_ttl=64,
                            ip_id=0x0001,
                            udp_sport=1234,
                            udp_dport=4790,
                            with_udp_chksum=False,
                            ip_ihl=None,
                            ip_options=False,
                            vxlan_reserved1=0x000000,
                            vxlan_vni = 0xaba,
                            vxlan_reserved2=0x00,
                            inner_frame = None):
    """
    Return a simple dataplane VXLAN packet
    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param udp_sport UDP source port
    @param udp_dport UDP dest port (IANA) = 4790 (VxLAN GPE)
    @param vxlan_reserved1 reserved field (3B)
    @param vxlan_vni VXLAN Network Identifier
    @param vxlan_reserved2 reserved field (1B)
    @param inner_frame The inner Ethernet frame
    Generates a simple VXLAN packet. Users shouldn't assume anything about
    this packet other than that it is a valid ethernet/IP/UDP/VXLAN frame.
    """
    udp_pkt = simple_udp_packet(
        pktlen=0,
        eth_dst=eth_dst,
        eth_src=eth_src,
        ip_dst=ip_dst,
        ip_src=ip_src,
        ip_ttl=ip_ttl,
        udp_sport=udp_sport,
        udp_dport=4790,
        with_udp_chksum=with_udp_chksum,
    )

    vxlan_pkt = udp_pkt / VXLAN_GPE(vni = vxlan_vni)

    if inner_frame:
        pkt = vxlan_pkt / inner_frame
    else:
        pkt = vxlan_pkt / simple_tcp_packet(pktlen = pktlen - len(pkt))

    return pkt

def simple_geneve_packet(pktlen=300,
                         eth_dst='00:01:02:03:04:05',
                         eth_src='00:06:07:08:09:0a',
                         dl_vlan_enable=False,
                         vlan_vid=0,
                         vlan_pcp=0,
                         dl_vlan_cfi=0,
                         ip_src='192.168.0.1',
                         ip_dst='192.168.0.2',
                         ip_tos=0,
                         ip_ttl=64,
                         ip_id=0x0001,
                         udp_sport=1234,
                         udp_dport=6081,
                         with_udp_chksum=True,
                         ip_ihl=None,
                         ip_options=False,
                         genv_version = 0,
                         genv_optionlen = 0,
                         genv_oam = 0,
                         genv_critical = 0,
                         genv_reserved = 0,
                         genv_proto = 0x6558,
                         genv_vni = 0xaba,
                         genv_reserved2 = 0,
                         inner_frame=None):


    """
    Return a simple dataplane GENEVE packet
    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param udp_sport UDP source port
    @param udp_dport UDP dest port (IANA) = 6081 (Geneve)
    @param genv_* geneve header fields
    @param inner_frame The inner Ethernet frame
    Generates a simple Geneve packet. Users shouldn't assume anything about
    this packet other than that it is a valid ethernet/IP/UDP/Geneve frame.
    """
    udp_pkt = simple_udp_packet(
        pktlen=0,
        eth_dst=eth_dst,
        eth_src=eth_src,
        ip_dst=ip_dst,
        ip_src=ip_src,
        ip_ttl=ip_ttl,
        udp_sport=udp_sport,
        udp_dport=6081,
        with_udp_chksum=with_udp_chksum,
    )

    genv_pkt = udp_pkt / GENEVE(vni=genv_vni, optionlen=genv_optionlen)

    if inner_frame:
        pkt = genv_pkt / inner_frame
    else:
        pkt = genv_pkt / simple_tcp_packet(pktlen=pktlen - len(pkt))

    return pkt

def int_meta_hdr_add_hdr(inner_frame,
                         int_inst_mask=0xAC00,
                         int_inst_cnt=4,
                         max_hop_cnt=32):
    int_meta_header = INT_META_HDR(ins_cnt=int_inst_cnt,
                                   max_hop_cnt=max_hop_cnt,
                                   inst_mask=int_inst_mask)
    return int_meta_header / inner_frame

def int_meta_hdr_add_hop_info(Packet,
                                  val=0x7FFFFFFF, incr_cnt=0):
    # Find the start of INT data (following INT_META_HDR)
    meta_hdr = Packet[INT_META_HDR]
    if meta_hdr == None:
        return Packet

    # copy the packet and truncate everything after META_HDR
    new_pkt = Packet.copy()
    new_pkt[INT_META_HDR].remove_payload()
    new_pkt = new_pkt/INT_hop_info(val=val)/Packet[INT_META_HDR].payload
    new_pkt[INT_META_HDR].total_hop_cnt += incr_cnt

    return new_pkt

def ignore_INT_report_val(exp_pkt, pkt, idx_to_ignore,  error_on_zero=False):
    """
    Reset latency values to zero in INT report packets.
    Just make sure latency value is non-zero.
    """
    # assume latency info is the 2nd INT_hop_info, followed by switch_id.
    exp_int_latency = exp_pkt.getlayer(INT_hop_info, idx_to_ignore)
    if exp_int_latency == None:
        print("Expected INT has no %d INT hop info" % idx_to_ignore)
        return False

    int_latency = pkt.getlayer(INT_hop_info, idx_to_ignore)
    if int_latency == None:
        exp_pkt.show2();
        pkt.show2();
        hexdump(exp_pkt)
        hexdump(pkt)
        print("INT hop info %d not valid" % idx_to_ignore)
        return False

    if error_on_zero and int_latency.val == 0:
        print "INT hp value %d is zero." % idx_to_ignore
        return False

    exp_int_latency.val = 0
    int_latency.val = 0

    return True

def ignore_DIGEST_encoding(exp_pkt, pkt, error_on_zero=False):
    """
    Reset latency encodings to zero in DIGEST packets.
    Just make sure latency encoding is non-zero.
    """
    exp_digest_hdr = exp_pkt.getlayer(INT_META_HDR)
    if exp_digest_hdr == None or exp_digest_hdr.d == 0:
        return False

    digest_hdr = pkt.getlayer(INT_META_HDR)
    if digest_hdr == None or digest_hdr.d == 0:
        return False

    if error_on_zero and digest_hdr.rsvd2_digest == 0:
        print "DIGEST encoding is zero"
        return False

    exp_digest_hdr.rsvd2_digest = 0
    digest_hdr.rsvd2_digest = 0

    return True

def verify_int_packet(test, pkt, port, digest=False, ignore_hop_indices=None,
                     ignore_chksum=False):
    """
    Compare INT packets, ignore the latency encoding value.
    Just make sure latency encoding is non-zero.
    """
    logging.debug("Checking for pkt on port %r", port)
    (_, rcv_port, rcv_pkt, pkt_time) = \
        test.dataplane.poll(port_number=port, timeout=2, exp_pkt=None)
    test.assertTrue(rcv_pkt != None, "Did not receive pkt on %r" % port)
    # convert rcv_pkt string back to layered pkt
    nrcv = pkt.__class__(rcv_pkt)

    if (digest):
        digest_hdr = nrcv.getlayer(INT_META_HDR)
        test.assertTrue(digest_hdr!=None and digest_hdr.d==1,
                        "Received packet did not have DIGEST")
        rcv_encoding = digest_hdr.rsvd2_digest
        test.assertTrue(ignore_DIGEST_encoding(pkt, nrcv),
                        "Received packet did not match expected packet")
    rcv_latency = None
    if ignore_hop_indices!=None:
        int_hop_infos = [None] * len(ignore_hop_indices)
        for j in range(0, len(ignore_hop_indices)):
            i = ignore_hop_indices[j]
            int_hop_info = nrcv.getlayer(INT_hop_info, i)
            test.assertTrue(int_hop_info!=None,
                            "Received packet did not have %d th hop info." % i)
            int_hop_infos[j] = int_hop_info.val
            test.assertTrue(ignore_INT_report_val(pkt, nrcv, i),
                            "Received packet did not match expected packet")
    if (not ignore_chksum and (digest or ignore_hop_indices!=None)):
        # validate tcp checksum as it changes when changing packet
        if (pkt.haslayer(TCP_INTL45)):
            # recalculate checksum
            del pkt[TCP_INTL45].chksum
            pkt[TCP_INTL45] = pkt[TCP_INTL45].__class__(str(pkt[TCP_INTL45]))
            del nrcv[TCP_INTL45].chksum
            nrcv[TCP_INTL45] = nrcv[TCP_INTL45].__class__(str(nrcv[TCP_INTL45]))
        if (pkt.haslayer(UDP_INTL45)):
            # recalculate checksum
            del pkt[UDP_INTL45].chksum
            pkt[UDP_INTL45] = pkt[UDP_INTL45].__class__(str(pkt[UDP_INTL45]))
            del nrcv[UDP_INTL45].chksum
            nrcv[UDP_INTL45] = nrcv[UDP_INTL45].__class__(str(nrcv[UDP_INTL45]))
        if (pkt.haslayer(ICMP_INTL45)):
            # recalculate checksum
            del pkt[ICMP_INTL45].chksum
            pkt[ICMP_INTL45] = pkt[ICMP_INTL45].__class__(str(pkt[ICMP_INTL45]))
            del nrcv[ICMP_INTL45].chksum
            nrcv[ICMP_INTL45] = nrcv[ICMP_INTL45].__class__(str(nrcv[ICMP_INTL45]))
        if (pkt.haslayer(UDP)):
            # recalculate checksum
            del pkt[UDP].chksum
            pkt[UDP] = pkt[UDP].__class__(str(pkt[UDP]))
            del nrcv[UDP].chksum
            nrcv[UDP] = nrcv[UDP].__class__(str(nrcv[UDP]))
    if (ignore_chksum):
        ignore_int_l45_chksum(pkt, nrcv)
    test.assertTrue(dataplane.match_exp_pkt(pkt, nrcv),
                    "Received packet did not match expected packet")
    ret = ()
    if digest:
        ret = ret + (rcv_encoding,)
    if ignore_hop_indices != None:
        ret = ret + tuple([int_hop_infos])
    ret = ret + (nrcv,)
    return ret


def prepare_int_l45_bindings(int_dscp=None,
                             int_dscp_mask=None):
    if int_dscp == None:
        int_dscp = get_int_l45_dscp_value()
    if int_dscp_mask == None:
        int_dscp_mask = get_int_l45_dscp_mask()
    if int_l45_encap == 'dscp':
        split_layers(IP, ICMP, frag=0, proto=1)
        split_layers(IP, TCP, frag=0, proto=6)
        split_layers(IP, UDP, frag=0, proto=17)

        int_tos = int_dscp << 2
        int_tos_mask = (int_dscp_mask << 2)
        for tos in range(0, 256):
            if tos & int_tos_mask == int_tos & int_tos_mask:
                bind_layers(IP, ICMP_INTL45, frag=0, proto=1, tos=tos)
                bind_layers(IP, TCP_INTL45, frag=0, proto=6, tos=tos)
                bind_layers(IP, UDP_INTL45, frag=0, proto=17, tos=tos)
            else:
                bind_layers(IP, ICMP, frag=0, proto=1, tos=tos)
                bind_layers(IP, TCP, frag=0, proto=6, tos=tos)
                bind_layers(IP, UDP, frag=0, proto=17, tos=tos)
    elif int_l45_encap == 'marker':
        bind_layers(INTL45_MARKER, INT_L45_HEAD)
        add_marker_to_l4(ICMP)
        add_marker_to_l4(TCP)
        add_marker_to_l4(UDP)

    bind_layers(INT_L45_HEAD, INT_META_HDR, int_type=INT_TYPE_INT)
    bind_layers(INT_META_HDR, INT_hop_info)

    bind_layers(UDP, DTEL_REPORT_HDR, dport=UDP_PORT_DTEL_REPORT)
    bind_layers(DTEL_REPORT_HDR, Ether,
                next_proto=DTEL_REPORT_NEXT_PROTO_ETHERNET)
    bind_layers(DTEL_REPORT_HDR, POSTCARD_HDR,
                next_proto=DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL)
    bind_layers(POSTCARD_HDR, Ether)

def cleanup_int_l45_bindings():
    if int_l45_encap == 'dscp':
      for tos in range(0, 256):
        split_layers(IP, ICMP_INTL45, frag=0, proto=1, tos=tos)
        split_layers(IP, TCP_INTL45, frag=0, proto=6, tos=tos)
        split_layers(IP, UDP_INTL45, frag=0, proto=17, tos=tos)
        split_layers(IP, ICMP, frag=0, proto=1, tos=tos)
        split_layers(IP, TCP, frag=0, proto=6, tos=tos)
        split_layers(IP, UDP, frag=0, proto=17, tos=tos)
    elif int_l45_encap == 'marker':
        split_layers(INTL45_MARKER, INT_L45_HEAD)
        remove_marker_from_l4(ICMP)
        remove_marker_from_l4(TCP)
        remove_marker_from_l4(UDP)

    split_layers(INT_L45_HEAD, INT_META_HDR, int_type=INT_TYPE_INT)
    split_layers(INT_META_HDR, INT_hop_info)

    split_layers(UDP, DTEL_REPORT_HDR, dport=UDP_PORT_DTEL_REPORT)
    split_layers(DTEL_REPORT_HDR, Ether,
                 next_proto=DTEL_REPORT_NEXT_PROTO_ETHERNET)
    split_layers(DTEL_REPORT_HDR, POSTCARD_HDR,
                 next_proto=DTEL_REPORT_NEXT_PROTO_SWITCH_LOCAL)
    split_layers(POSTCARD_HDR, Ether)

    bind_layers(IP, ICMP, frag=0, proto=1)
    bind_layers(IP, TCP, frag=0, proto=6)
    bind_layers(IP, UDP, frag=0, proto=17)


def replace_l4_with_intl45_l4(pkt=None):
    """
    Replaces the L4 in the packet with the L4 that is made for INT L45.
    """
    if pkt == None:
        return None
    payload=None
    proto_param=0
    if pkt.haslayer(UDP):
        temp = pkt.copy()
        udp = pkt[UDP]
        temp[IP].remove_payload()
        pkt = temp / UDP_INTL45(
                    sport=udp.sport,
                    dport=udp.dport,
                    len=udp.len,
                    chksum=udp.chksum
              )
        payload = udp.payload
        proto_param = udp.dport
    elif pkt.haslayer(TCP):
        temp = pkt.copy()
        tcp = pkt[TCP]
        temp[IP].remove_payload()
        pkt = temp / TCP_INTL45(
                    sport=tcp.sport,
                    dport=tcp.dport,
                    seq=tcp.seq,
                    ack=tcp.ack,
                    dataofs=tcp.dataofs,
                    reserved=tcp.reserved,
                    flags=tcp.flags,
                    window=tcp.window,
                    chksum=tcp.chksum,
                    urgptr=tcp.urgptr,
                    options=tcp.options
              )
        payload = tcp.payload
        proto_param = tcp.dport
    elif pkt.haslayer(ICMP):
        temp = pkt.copy()
        icmp = pkt[ICMP]
        temp[IP].remove_payload()
        # force checksum calculation
        del icmp.chksum
        icmp = icmp.__class__(str(icmp))
        pkt = temp / ICMP_INTL45(
                    type=icmp.type,
                    code=icmp.code,
                    chksum=icmp.chksum
              )
        payload = icmp.payload
        icmp.remove_payload();
        icmp_remainder = str(icmp)[4:]
        payload = icmp_remainder + str(payload)
        proto_param = (icmp.type << 8) | icmp.code
    return (pkt, payload, proto_param)

def get_l4_param(pkt=None):
    """
    Gives l4 param and separates upto l4 and its payload
    """
    if pkt == None:
        return None
    payload=None
    proto_param=0
    pkt = pkt.copy()
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        payload = udp.payload
        udp.remove_payload()
        proto_param = udp.dport
    elif pkt.haslayer(TCP):
        tcp = pkt[TCP]
        payload = tcp.payload
        tcp.remove_payload()
        proto_param = tcp.dport
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        # force checksum calculation
        del icmp.chksum
        icmp = icmp.__class__(str(icmp))
        payload = icmp.payload
        pkt[IP].remove_payload();
        icmp_remainder = str(icmp)[4:]
        # regular icmp has 4 bytes after checksum. we don't want it
        pkt = pkt / ICMP_INTL45().__class__(str(icmp)[:4])
        pkt[IP].proto = 1
        payload = icmp_remainder
        proto_param = (icmp.type << 8) | icmp.code
    return (pkt, payload, proto_param)

def int_l45_src_packet(test=None,
                       int_inst_mask=0xAC00,
                       int_inst_cnt=4,
                       max_hop_cnt=32,
                       dscp=None,
                       dscp_mask=None,
                       pkt=None):
    if dscp==None:
        dscp = get_int_l45_dscp_value()
    if dscp_mask == None:
        dscp_mask = get_int_l45_dscp_mask()
    test.assertTrue(pkt!=None and pkt.haslayer(IP) and
                                  (pkt.haslayer(UDP) or
                                  pkt.haslayer(TCP) or
                                  pkt.haslayer(ICMP)),
                    "Cannot find IP or one of UDP, TCP or ICMP in the packet")
    int_l45_head = INT_L45_HEAD()
    int_l45_head.length = 3 # this header(4) + INT meta header (8)
    int_meta_header = INT_META_HDR(ins_cnt=int_inst_cnt,
                                   max_hop_cnt=max_hop_cnt,
                                   inst_mask=int_inst_mask)

    if int_l45_encap == 'marker':
        (pkt, payload, proto_param) = get_l4_param(pkt)
        marker = 0
        if pkt.haslayer(UDP):
            marker=int_l45_marker_udp
        elif pkt.haslayer(TCP):
            marker=int_l45_marker_tcp
        elif pkt.haslayer(ICMP) or pkt.haslayer(ICMP_INTL45):
            marker=int_l45_marker_icmp
        pkt = pkt / INTL45_MARKER(marker=marker)
        int_l45_head.length += 2
    elif int_l45_encap == 'dscp':
        (pkt, payload, proto_param) = replace_l4_with_intl45_l4(pkt)
        dscp = dscp << 2
        dscp_mask = dscp_mask << 2
        tos_mask = (0xFC - dscp_mask) | 0x3
        pkt[IP].tos = (dscp & dscp_mask | (pkt[IP].tos & tos_mask) )

    return pkt / int_l45_head / int_meta_header / payload

def int_l45_packet_add_hop_info(Packet,
                                val=0x7FFFFFFF, incr_cnt=0):
    # Find the start of INT data (following INT_L45_HEAD)
    l45_head = Packet['INT_L45_HEAD']
    if l45_head == None:
        return Packet

    # copy the packet and truncate everything after L45_HEAD
    new_pkt = Packet.copy()
    new_pkt[INT_META_HDR].remove_payload()
    new_pkt = new_pkt/INT_hop_info(val=val)/Packet[INT_META_HDR].payload
    # update all the headers - IP UDP header lens are updated automatically
    new_pkt[INT_META_HDR].total_hop_cnt += incr_cnt
    new_pkt[INT_L45_HEAD].length += 1

    return new_pkt

def int_l45_packet_add_update_digest(Packet, encoding=0xFFFF):
    Packet = Packet.copy()
    Packet[INT_META_HDR].rsvd2_digest = encoding & 0xffff
    Packet[INT_META_HDR].d = 1
    return Packet

def ignore_int_l45_chksum(pkt, nrcv):
    if nrcv.haslayer(TCP_INTL45) and pkt.haslayer(TCP_INTL45):
       nrcv[TCP_INTL45].chksum=0
       pkt[TCP_INTL45].chksum=0
    if nrcv.haslayer(UDP_INTL45) and pkt.haslayer(UDP_INTL45):
       nrcv[UDP_INTL45].chksum=0
       pkt[UDP_INTL45].chksum=0
    if nrcv.haslayer(ICMP_INTL45) and pkt.haslayer(ICMP_INTL45):
       nrcv[ICMP_INTL45].chksum=0
       pkt[ICMP_INTL45].chksum=0
    if pkt.haslayer(TCP):
        pkt[TCP].chksum = 0
        nrcv[TCP].chksum = 0
    if pkt.haslayer(UDP):
        pkt[UDP].chksum = 0
        nrcv[UDP].chksum = 0
    if pkt.haslayer(ICMP):
        pkt[ICMP].chksum = 0
        nrcv[ICMP].chksum = 0

def verify_int_l45_packet_ignore_chksum(test, pkt, port_id):
    """
    Check that an expected packet is received
    port_id can either be a single integer (port_number on default device 0)
    or a tuple of 2 integers (device_number, port_number)
    """
    device, port = port_to_tuple(port_id)
    logging.debug("Checking for pkt on device %d, port %d", device, port)
    (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(
        test, device_number=device, port_number=port, timeout=2, exp_pkt=None
    )
    nrcv = None
    if rcv_pkt:
        # convert rcv_pkt string back to layered pkt
        nrcv = pkt.__class__(rcv_pkt)
        ignore_int_l45_chksum(pkt, nrcv)
    test.assertTrue(str(pkt)==str(nrcv),
                    "Did not receive expected pkt on device %d, port %r"
                    % (device, port))


def verify_int_l45_dtel_packet(test, pkt, port, ignore_chksum=False,
                                    ignore_seq_num=True):
    """
    Check that an expected packet is received
    """
    logging.debug("Checking for pkt on port %r", port)
    (_, rcv_port, rcv_pkt, pkt_time) = \
        test.dataplane.poll(port_number=port, timeout=2, exp_pkt=None)
    nrcv = pkt.__class__(rcv_pkt)
    while nrcv[Ether].type == 0x88cc: # ignore LLDP packets
        (_, rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(
            port_number=port, timeout=2, exp_pkt=None)
        nrcv = pkt.__class__(rcv_pkt)
    test.assertTrue(rcv_pkt != None, "Did not receive pkt on %r" % port)
    # convert rcv_pkt string back to layered pkt
    nrcv = pkt.__class__(rcv_pkt)

    if ignore_chksum:
        ignore_int_l45_chksum(pkt, nrcv)
    test.assertTrue(match_dtel_pkt(pkt, nrcv,
                                       ignore_seq_num = ignore_seq_num),
                    "Received packet did not match expected packet")

def verify_int_lasthop_dtel_report_packet(test, pkt, port,
                                               ignore_chksum=False,
                                              ignore_seq_num=True):
    (_, rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(
        port_number=port, timeout=2, exp_pkt=None)
    nrcv = pkt.__class__(rcv_pkt)
    while nrcv[Ether].type == 0x88cc: # ignore LLDP packets
        (_, rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(
            port_number=port, timeout=2, exp_pkt=None)
        nrcv = pkt.__class__(rcv_pkt)
    test.assertTrue(rcv_pkt != None, "Did not receive pkt on %r" % port)
    if ignore_chksum:
        ignore_int_l45_chksum(pkt, nrcv)
    verify_postcard_dtel_packet(test, str(nrcv), pkt,
                                    ignore_seq_num = ignore_seq_num)

def receive_int_lasthop_dtel_report_packet(test, pkt, port,
                                                ignore_hop_indicies=None,
                                                timeout=2,
                                                ignore_chksum=False):
    """
    Wait for an last hop INT report.
    If received, compared to expected pkt while ignoring INT latency value
    and timestamp value.
    Just make sure the latency and tstamp values are non-zero.
    """
    (_, rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(
        port_number=port, timeout=2, exp_pkt=None)
    if rcv_pkt == None:
        return rcv_pkt
    nrcv = pkt.__class__(rcv_pkt)
    while nrcv[Ether].type == 0x88cc: # ignore LLDP packets
        (_, rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(
            port_number=port, timeout=2, exp_pkt=None)
        nrcv = pkt.__class__(rcv_pkt)
    if rcv_pkt:
        nrcv = pkt.__class__(rcv_pkt)
        #ignore_int_l45_chksum(pkt, nrcv)
        if ignore_chksum:
            ignore_int_l45_chksum(pkt, nrcv)
        nrcv = verify_postcard_dtel_packet(test, str(nrcv), pkt)
    return nrcv

def verify_any_dtel_packet_any_port(test, pkts=[], ports=[],
                                         device_number=0, ignore_chksum=False,
                                        ignore_seq_num=True):
    """
    Check that _any_ of the packet is received on _any_ of the specified ports
    belonging to the given device (default device_number is 0).
    Also verifies that the packet is received on any other ports for this
    device, and that no other packets are received on the device (unless --relax
    is in effect).
    Returns the index of the port on which the packet is recevied.
    """
    received = False
    match_index = 0
    (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(
        test,
        device_number=device_number,
        timeout=5
    )

    logging.debug("Checking for pkt on device %d, port %r",
                  device_number, ports)
    if rcv_port in ports:
        for i in range(0, len(pkts)):
            pkt = pkts[i]
            nrcv = pkt.__class__(rcv_pkt)
            ignore_int_l45_chksum(pkt, nrcv)
            if pkt.haslayer(POSTCARD_HDR):
                if not ignore_postcard_values(pkt, nrcv, True):
                    continue
            if ignore_chksum:
                ignore_int_l45_chksum(pkt, nrcv)
            if match_dtel_pkt(pkt, nrcv, ignore_seq_num = ignore_seq_num):
                match_index = i
                received = True

    test.assertTrue(
        received == True,
        "Did not receive expected pkt(s) on any of ports %r for device %d"
        % (ports, device_number))
    return match_index

def int_port_ids_pack(ingress_port, egress_port):
    hdr_val = (ingress_port << 16) + egress_port
    return hdr_val

def int_port_ids_unpack(hdr_val):
    ingress_port = hdr_val >> 16
    egress_port = hdr_val - (ingress_port << 16)
    return [ingress_port, egress_port]

