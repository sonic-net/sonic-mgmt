import os
import pickle
import struct
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
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MACSEC_INFO_FILE = "macsec_info.pickle"
# Rewriting the outer src MAC to the peer's MAC is required on Broadcom, where
# the ASIC derives the ingress SCI from {outer_src_MAC, port}. On platforms that
# take the SCI from the SecTAG the rewrite can break SA lookup, so
# create_macsec_info() drops this opt-out marker on non-Broadcom DUTs.
# Default stays rewrite-on so pre-existing pickles keep working.
MACSEC_SMAC_NO_REWRITE_FLAG = "/root/macsec_no_rewrite_outer_smac"
_REWRITE_OUTER_SMAC = not os.path.exists(MACSEC_SMAC_NO_REWRITE_FLAG)
ETH_P_MACSEC = 0x88e5

MACSEC_INFOS = {}
# Per-port next PN to send. Initialized to pn_at_pickle+1 on first use so PTF frames are
# always just ahead of the real peer, rather than a shared global that grows by 100 per
# send and inflates highest_PN on the ASIC far beyond the peer's actual position.
MACSEC_PORT_NEXT_PN = {}
# Per-port SA bundle cache. Pre-computes the AES-GCM key schedule and the
# parts of the SecTAG that are constant for an SA so the hot path only
# touches PN/SL/plaintext per packet.
_SA_CACHE = {}


def _build_sa(port_number):
    """Build and cache an immutable SA bundle for `port_number`.

    The cache key is implicit (port_number); callers must ensure
    MACSEC_INFOS[port_number] is the SA they want before first call.
    """
    encrypt, send_sci, xpn_en, _sci, _an, sak, _ssci, _salt, \
        peer_sci, peer_an, peer_ssci, _pn = MACSEC_INFOS[port_number]

    sak_bytes = sak if isinstance(sak, bytes) else bytes(sak)
    peer_sci_bytes = struct.pack('!Q', peer_sci) if isinstance(peer_sci, int) \
        else peer_sci

    # TCI byte without AN: Ver=0, ES=0, SC=send_sci, SCB=0, E=encrypt,
    # C=encrypt (with default ICV len 16). AN is OR-ed in per-call.
    tci_base = ((1 << 5) if send_sci else 0) \
        | ((1 << 3) if encrypt else 0) \
        | ((1 << 2) if encrypt else 0)

    sa = {
        "encrypt": bool(encrypt),
        "send_sci": bool(send_sci),
        "xpn_en": bool(xpn_en),
        "peer_an": peer_an & 0x3,
        "peer_sci_bytes": peer_sci_bytes,
        "peer_mac_bytes": peer_sci_bytes[:6],
        "aesgcm": AESGCM(sak_bytes),
        "tci_base": tci_base,
        # AAD region length on the wire (outer Ether 14 + SecTAG 6 [+ SCI 8])
    }
    if xpn_en:
        sa["ssci_bytes"] = struct.pack('!L', peer_ssci) \
            if isinstance(peer_ssci, int) else peer_ssci
        sa["salt_bytes"] = _salt
    _SA_CACHE[port_number] = sa
    return sa


def _macsec_encap_encrypt(sa, eth_bytes, send_pn):
    """Build a wire MACsec frame from a cleartext Ether bytes buffer.

    Avoids scapy layer rebuilding and reuses a cached AESGCM cipher so the
    per-packet cost is one AES-GCM encrypt instead of also re-initializing
    the key schedule. Drop-in equivalent of scapy_macsec.MACsecSA.encap+encrypt
    for the wire output bytes.

    eth_bytes layout: dst(6) | src(6) | type(2) | payload(N)
    Returns wire bytes for the encrypted MACsec frame, byte-identical to
    what scapy would produce for the same SA/PN/plaintext.
    """
    outer_macs = eth_bytes[:12]            # outer dst + src (src already overwritten by caller)
    inner_type = eth_bytes[12:14]
    inner_payload = eth_bytes[14:]

    # SecTAG
    tci_an = sa["tci_base"] | sa["peer_an"]
    # SL is set to the byte count after the source MAC (= inner_type + payload)
    # when that count is < 48; else 0. Matches scapy_macsec.MACsecSA.shortlen.
    data_after_macs = 2 + len(inner_payload)
    sl_byte = data_after_macs if data_after_macs < 48 else 0
    pn32 = send_pn & 0xFFFFFFFF
    sectag = struct.pack('!BBI', tci_an, sl_byte, pn32)
    if sa["send_sci"]:
        sectag += sa["peer_sci_bytes"]

    # IV (12 bytes): non-XPN = SCI || PN(32); XPN = (SSCI || PN(64)) XOR salt
    if sa["xpn_en"]:
        tmp_iv = sa["ssci_bytes"] + struct.pack('!Q', send_pn & 0xFFFFFFFFFFFFFFFF)
        iv = bytes(a ^ b for a, b in zip(tmp_iv, sa["salt_bytes"]))
    else:
        iv = sa["peer_sci_bytes"] + struct.pack('!I', pn32)

    aad = outer_macs + struct.pack('!H', ETH_P_MACSEC) + sectag

    if sa["encrypt"]:
        # Confidentiality: plaintext = inner_type + inner_payload; AAD = headers only.
        pt = inner_type + inner_payload
        return aad + sa["aesgcm"].encrypt(iv, pt, aad)
    # Integrity-only: AAD = full frame, plaintext empty, just append the 16-byte tag.
    cleartext = inner_type + inner_payload
    tag = sa["aesgcm"].encrypt(iv, b'', aad + cleartext)
    return aad + cleartext + tag


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
    # Check if the port is macsec enabled; if so send the macsec encap/encrypted frame.
    device, port_number = ptf.testutils.port_to_tuple(port_id)
    if port_number not in MACSEC_INFOS or not MACSEC_INFOS[port_number]:
        __origin_send_packet(test, port_id, pkt, count)
        return

    sa = _SA_CACHE.get(port_number)
    if sa is None:
        sa = _build_sa(port_number)

    if port_number not in MACSEC_PORT_NEXT_PN:
        MACSEC_PORT_NEXT_PN[port_number] = MACSEC_INFOS[port_number][-1] + 1

    # Serialize the input scapy packet ONCE outside the count loop.
    if isinstance(pkt, bytes):
        eth_bytes = pkt
    else:
        eth_bytes = bytes(pkt)
    if _REWRITE_OUTER_SMAC:
        eth_bytes = eth_bytes[:6] + sa["peer_mac_bytes"] + eth_bytes[12:]

    for _ in range(count):
        send_pn = MACSEC_PORT_NEXT_PN[port_number]
        MACSEC_PORT_NEXT_PN[port_number] += 1
        wire = _macsec_encap_encrypt(sa, eth_bytes, send_pn)
        __origin_send_packet(test, port_id, wire, 1)


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


# Native-codec opt-in: when sonic-mgmt requests native mode it drops this
# marker before launching PTF; the codec-carrying docker-ptf image activates
# its DataPlane transforms and this monkeypatch must stand down entirely.
# Without the marker (the default) this module behaves exactly as before,
# so existing topo runs are undisturbed even on codec-carrying images.
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
