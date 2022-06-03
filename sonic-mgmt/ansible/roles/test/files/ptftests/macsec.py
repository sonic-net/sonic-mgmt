import os
import pickle
import cryptography.exceptions
import time

import ptf
import scapy.all as scapy
MACSEC_SUPPORTED = False
if hasattr(scapy, "VERSION") and tuple(map(int, scapy.VERSION.split('.'))) >= (2, 4, 5):
    MACSEC_SUPPORTED = True
if MACSEC_SUPPORTED:
    import scapy.contrib.macsec as scapy_macsec

MACSEC_INFO_FILE = "macsec_info.pickle"

MACSEC_INFOS = {}


def __decap_macsec_pkt(macsec_pkt, sci, an, sak, encrypt, send_sci, pn, xpn_en=False, ssci=None, salt=None):
    sa = scapy_macsec.MACsecSA(sci=sci,
                               an=an,
                               pn=pn,
                               key=sak,
                               icvlen=16,
                               encrypt=encrypt,
                               send_sci=send_sci,
                               xpn_en=xpn_en,
                               ssci=ssci,
                               salt=salt)
    try:
        pkt = sa.decrypt(macsec_pkt)
    except cryptography.exceptions.InvalidTag:
        # Invalid MACsec packets
        return None
    pkt = sa.decap(pkt)
    return pkt


def __macsec_dp_poll(test, device_number=0, port_number=None, timeout=None, exp_pkt=None):
    recent_packets = []
    packet_count = 0
    if timeout is None:
        timeout = ptf.ptfutils.default_timeout
    while True:
        start_time = time.time()
        ret = __origin_dp_poll(
            test, device_number=device_number, port_number=port_number, timeout=timeout, exp_pkt=None)
        timeout -= time.time() - start_time
        # The device number of PTF host is 0, if the target port isn't a injected port(belong to ptf host), Don't need to do MACsec further.
        if isinstance(ret, test.dataplane.PollFailure) or exp_pkt is None or ret.device != 0:
            return ret
        pkt = scapy.Ether(ret.packet)
        if pkt[scapy.Ether].type != 0x88e5:
            if ptf.dataplane.match_exp_pkt(exp_pkt, pkt):
                return ret
            else:
                continue
        if ret.port in MACSEC_INFOS and MACSEC_INFOS[ret.port]:
            encrypt, send_sci, xpn_en, sci, an, sak, ssci, salt = MACSEC_INFOS[ret.port]
            pkt = __decap_macsec_pkt(pkt, sci, an, sak, encrypt,
                                send_sci, 0, xpn_en, ssci, salt)
            if pkt is not None and ptf.dataplane.match_exp_pkt(exp_pkt, pkt):
                return ret
        recent_packets.append(pkt)
        packet_count += 1
        if timeout <= 0:
            break
    return test.dataplane.PollFailure(exp_pkt, recent_packets,packet_count)


if MACSEC_SUPPORTED and os.path.exists(MACSEC_INFO_FILE):
    with open(MACSEC_INFO_FILE, "rb") as f:
        MACSEC_INFOS = pickle.load(f, encoding="bytes")
        if MACSEC_INFOS:
            __origin_dp_poll = ptf.testutils.dp_poll
            ptf.testutils.dp_poll = __macsec_dp_poll
