import os
import pickle
import cryptography.exceptions
import time

import ptf
import ptf.dataplane
import scapy.all as scapy
MACSEC_SUPPORTED = False
if hasattr(scapy, "VERSION") and tuple(map(int, scapy.VERSION.split('.'))) >= (2, 4, 5):
    MACSEC_SUPPORTED = True
if MACSEC_SUPPORTED:
    import scapy.contrib.macsec as scapy_macsec

MACSEC_INFO_FILE = "macsec_info.pickle"
MACSEC_GLOBAL_PN_OFFSET = 1000
MACSEC_GLOBAL_PN_INCR = 100

MACSEC_INFOS = {}


# When the PTF image carries the native MACsec codec (per-port DataPlane
# transforms registered from macsec_info.pickle — see
# ptf.dataplane.NATIVE_MACSEC_CAPABLE, added by sonic-buildimage
# src/ptf-py3.patch), this module must NOT also encrypt: both layers active
# would encrypt every injected frame twice. NATIVE_MACSEC_CAPABLE is only set
# once a DataPlane is constructed, which happens after this module is
# imported — so it must be read lazily at call time, never snapshotted here.
def _native_macsec_active():
    return bool(getattr(ptf.dataplane, "NATIVE_MACSEC_CAPABLE", False))


def macsec_send(test, port_id, pkt, count=1):
    if _native_macsec_active():
        return __origin_send_packet(test, port_id, pkt, count)
    # Check if the port is macsec enabled, if so send the macsec encap/encrypted frame
    global MACSEC_GLOBAL_PN_OFFSET
    global MACSEC_GLOBAL_PN_INCR

    device, port_number = ptf.testutils.port_to_tuple(port_id)
    if port_number in MACSEC_INFOS and MACSEC_INFOS[port_number]:
        encrypt, send_sci, xpn_en, sci, an, sak, ssci, salt, peer_sci, peer_an, peer_ssci, pn = \
                                                                                MACSEC_INFOS[port_number]

        for n in range(count):
            if isinstance(pkt, bytes):
                # If in bytes, convert it to an Ether packet
                pkt = scapy.Ether(pkt)

            # Increment the PN by an offset so that the macsec frames are not late on DUT
            MACSEC_GLOBAL_PN_OFFSET += MACSEC_GLOBAL_PN_INCR
            pn += MACSEC_GLOBAL_PN_OFFSET

            macsec_pkt = encap_macsec_pkt(pkt, peer_sci, peer_an, sak, encrypt, send_sci, pn, xpn_en, peer_ssci, salt)
            # send the packet
            __origin_send_packet(test, port_id, macsec_pkt, 1)
    else:
        # send the packet
        __origin_send_packet(test, port_id, pkt, count)


def encap_macsec_pkt(macsec_pkt, sci, an, sak, encrypt, send_sci, pn, xpn_en=False, ssci=None, salt=None):
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
    macsec_pkt = sa.encap(macsec_pkt)
    pkt = sa.encrypt(macsec_pkt)
    return pkt


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
        return macsec_pkt, False
    pkt = sa.decap(pkt)
    return pkt, True


def __macsec_dp_poll(test, device_number=0, port_number=None, timeout=None, exp_pkt=None):
    if _native_macsec_active():
        return __origin_dp_poll(test, device_number=device_number, port_number=port_number,
                                timeout=timeout, exp_pkt=exp_pkt)
    recent_packets = []
    packet_count = 0
    if timeout is None:
        timeout = ptf.ptfutils.default_timeout
    while True:
        start_time = time.time()
        ret = __origin_dp_poll(
            test, device_number=device_number, port_number=port_number, timeout=timeout, exp_pkt=None)
        timeout -= time.time() - start_time
        # Since we call __origin_dp_poll with exp_pkt=None, it should only ever fail if no packets are received at all.
        # In this case, continue normally until we exceed the timeout value provided to macsec_dp_poll.
        if isinstance(ret, test.dataplane.PollFailure):
            if timeout <= 0:
                break
            else:
                continue
        # The device number of PTF host is 0, if the target port isn't a injected port(belong to ptf host),
        # Don't need to do MACsec further.
        if ret.device != 0:
            return ret
        pkt = scapy.Ether(ret.packet)
        if pkt[scapy.Ether].type != 0x88e5:
            if exp_pkt is None or ptf.dataplane.match_exp_pkt(exp_pkt, pkt):
                return ret
            else:
                continue
        if ret.port in MACSEC_INFOS and MACSEC_INFOS[ret.port]:
            encrypt, send_sci, xpn_en, sci, an, sak, ssci, salt, peer_sci, peer_an, peer_ssci, pn = \
                                                                                         MACSEC_INFOS[ret.port]
            pkt, decap_success = __decap_macsec_pkt(
                pkt, sci, an, sak, encrypt, send_sci, 0, xpn_en, ssci, salt)
            if exp_pkt is None or decap_success and ptf.dataplane.match_exp_pkt(exp_pkt, pkt):
                return ret
        recent_packets.append(pkt)
        packet_count += 1
        if timeout <= 0:
            break
    return test.dataplane.PollFailure(exp_pkt, recent_packets, packet_count)


# Native-codec opt-in: when sonic-mgmt requests native mode (--macsec_ptf_native)
# it drops this marker before launching PTF; the codec-carrying docker-ptf image
# activates its DataPlane transforms and this monkeypatch must stand down
# entirely. Without the marker (the default) this module behaves exactly as
# before, so existing runs are undisturbed even on codec-carrying images.
MACSEC_NATIVE_MODE_FLAG = "/root/macsec_native_codec"

if MACSEC_SUPPORTED and os.path.exists(MACSEC_INFO_FILE) \
        and not os.path.exists(MACSEC_NATIVE_MODE_FLAG):
    with open(MACSEC_INFO_FILE, "rb") as f:
        MACSEC_INFOS = pickle.load(f, encoding="bytes")
        if MACSEC_INFOS:
            __origin_dp_poll = ptf.testutils.dp_poll
            ptf.testutils.dp_poll = __macsec_dp_poll
            __origin_send_packet = ptf.testutils.send_packet
            ptf.testutils.send_packet = macsec_send
