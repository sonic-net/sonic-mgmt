# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
MSTP (IEEE 802.1s) BPDU library — pure-stdlib encode/decode + config digest.

No ptf/scapy dependency, so it can be unit-tested locally and imported by both
the PTF test (`mstp_bpdu_test.py`) and the sonic-mgmt side (to compute the
expected MST Configuration Digest for a region).

Validated against a live sonic-stp DUT:
  * the config-digest key + 4096-entry VID->MSTID table match the daemon's
    `mstputil_compute_message_digest` (sonic-stp `mstp/mstp_util.c`,
    key `MSTP_CONFIG_DIGEST_SIGNATURE_KEY` in `include/mstp.h`);
  * the empty region digest equals the IEEE 802.1s reference vector
    `ac36177f50283cd4b83821d8ab26de62`;
  * `parse_mst_bpdu()` decodes a real BPDU captured off a SONiC MST port.

MST BPDU body layout (after the LLC 0x42/0x42/0x03 header), per IEEE 802.1Q:

  off  field                              bytes
  0    protocol identifier (0x0000)       2
  2    protocol version (3 = MSTP)        1
  3    BPDU type (0x02 = RST/MST)         1
  4    CIST flags                         1
  5    CIST root identifier               8   (prio|sysid-ext : MAC)
  13   CIST external path cost            4
  17   CIST regional root identifier      8
  25   CIST port identifier               2
  27   message age (1/256 s)              2
  29   max age                            2
  31   hello time                         2
  33   forward delay                      2
  35   version 1 length (0x00)            1
  36   version 3 length                   2   = 64 + 16*N
  38   MST configuration identifier       51  (selector + name[32] + rev + digest[16])
  89   CIST internal root path cost       4
  93   CIST bridge identifier             8
  101  CIST remaining hops                1
  102  MSTI configuration messages        16 each * N
"""
import hmac
import hashlib
import struct
from typing import Any, Dict, List, Optional   # noqa: F401  (used in type comments)

# IEEE 802.1Q HMAC-MD5 signature key for the MST Configuration Digest. This is
# the same value sonic-stp compiles in (mstp.h `MSTP_CONFIG_DIGEST_SIGNATURE_KEY`).
MST_DIGEST_KEY = bytes([0x13, 0xAC, 0x06, 0xA6, 0x2E, 0x47, 0xFD, 0x51,
                        0xF9, 0x5D, 0x2B, 0xA2, 0x43, 0xCD, 0x03, 0x46])

MST_TABLE_SIZE = 4096          # VID 0..4095; 0 and 4095 are reserved (=> 0)
MST_DST_MAC = "01:80:c2:00:00:00"

# BPDU constants
MST_PROTOCOL_ID = 0x0000
MST_PROTOCOL_VERSION = 0x03    # MSTP
MST_BPDU_TYPE = 0x02           # RST/MST BPDU
MSTI_MSG_LEN = 16
# version-3 length with zero MSTIs: 51 (config id) + 4 + 8 + 1
V3_BASE_LEN = 64


def mst_config_digest(vid_to_mstid):
    """HMAC-MD5 over the 4096-entry MST Configuration Table.

    `vid_to_mstid`: {vid: mstid} for the VIDs mapped to an MSTI; every other VID
    is 0 (CIST). Keys may be int or str (JSON-decoded). Returns 16 raw bytes.
    """
    mapping = {int(k): int(v) for k, v in vid_to_mstid.items()} if vid_to_mstid else {}
    table = bytearray()
    for vid in range(MST_TABLE_SIZE):
        table += struct.pack('!H', mapping.get(vid, 0) & 0xFFFF)
    return hmac.new(MST_DIGEST_KEY, bytes(table), hashlib.md5).digest()


def _bridge_id(priority, sysid_ext, mac):
    """8-byte bridge identifier: 2-byte (priority nibble | 12-bit sysid) + MAC."""
    return struct.pack('!H', (priority & 0xF000) | (sysid_ext & 0x0FFF)) + \
        bytes.fromhex(mac.replace(':', ''))


def build_mst_bpdu(*, cist_flags=0x00,
                   cist_root=(32768, 0, "00:01:02:03:04:05"), cist_ext_cost=0,
                   cist_reg_root=(32768, 0, "00:01:02:03:04:05"), cist_port_id=0x8001,
                   msg_age=0, max_age=20, hello=2, fwd_delay=15,
                   region_name="", revision=0, vid_to_mstid=None,
                   cist_int_cost=0, cist_bridge=(32768, 0, "00:01:02:03:04:05"),
                   cist_rem_hops=20, mstis=None):
    """Build the MST BPDU body (from protocol-id through the last MSTI record).

    Bridge-id tuples are (priority, sysid_ext, mac). `mstis` is a list of dicts:
    {flags, regional_root=(prio, mstid, mac), int_cost, bridge_prio, port_prio, rem_hops}.
    """
    vid_to_mstid = vid_to_mstid or {}
    mstis = mstis or []

    b = struct.pack('!HBB', MST_PROTOCOL_ID, MST_PROTOCOL_VERSION, MST_BPDU_TYPE)
    b += struct.pack('!B', cist_flags)
    b += _bridge_id(*cist_root)
    b += struct.pack('!I', cist_ext_cost)
    b += _bridge_id(*cist_reg_root)
    b += struct.pack('!H', cist_port_id)
    b += struct.pack('!H', (msg_age & 0xFF) << 8)
    b += struct.pack('!H', (max_age & 0xFF) << 8)
    b += struct.pack('!H', (hello & 0xFF) << 8)
    b += struct.pack('!H', (fwd_delay & 0xFF) << 8)
    b += struct.pack('!B', 0x00)                       # version 1 length

    # Version-3 payload
    name = region_name.encode()[:32].ljust(32, b'\x00')
    mst_cfg_id = struct.pack('!B', 0) + name + struct.pack('!H', revision) + \
        mst_config_digest(vid_to_mstid)                # 1 + 32 + 2 + 16 = 51
    v3 = mst_cfg_id + struct.pack('!I', cist_int_cost) + _bridge_id(*cist_bridge) + \
        struct.pack('!B', cist_rem_hops)
    for m in mstis:
        v3 += struct.pack('!B', m.get('flags', 0))
        prio, mstid, mac = m['regional_root']
        v3 += struct.pack('!H', (prio & 0xF000) | (mstid & 0x0FFF)) + \
            bytes.fromhex(mac.replace(':', ''))
        v3 += struct.pack('!I', m.get('int_cost', 0))
        v3 += struct.pack('!B', m.get('bridge_prio', 0x80))   # top nibble = priority/4096
        v3 += struct.pack('!B', m.get('port_prio', 0x80))
        v3 += struct.pack('!B', m.get('rem_hops', 20))

    b += struct.pack('!H', len(v3)) + v3               # version 3 length + payload
    return b


def _mac(b):
    return ':'.join(f'{x:02x}' for x in b)


def parse_mst_bpdu(b):
    # type: (bytes) -> Optional[Dict[str, Any]]
    """Decode an MST BPDU body (bytes starting at the protocol identifier).

    Returns a dict, or None if it isn't an MSTP RST BPDU.
    """
    if len(b) < 36:
        return None
    proto_id, version, btype = struct.unpack('!HBB', b[0:4])
    if proto_id != MST_PROTOCOL_ID or version != MST_PROTOCOL_VERSION or btype != MST_BPDU_TYPE:
        return None
    o = {}  # type: Dict[str, Any]
    o['proto_id'], o['version'], o['type'] = proto_id, version, btype
    o['cist_flags'] = b[4]
    o['cist_root_prio'] = struct.unpack('!H', b[5:7])[0] & 0xF000
    o['cist_root_sysid'] = struct.unpack('!H', b[5:7])[0] & 0x0FFF
    o['cist_root_mac'] = _mac(b[7:13])
    o['cist_ext_cost'] = struct.unpack('!I', b[13:17])[0]
    o['cist_reg_root_mac'] = _mac(b[19:25])
    o['cist_port_id'] = struct.unpack('!H', b[25:27])[0]
    o['msg_age'] = struct.unpack('!H', b[27:29])[0] >> 8
    o['max_age'] = struct.unpack('!H', b[29:31])[0] >> 8
    o['hello'] = struct.unpack('!H', b[31:33])[0] >> 8
    o['fwd_delay'] = struct.unpack('!H', b[33:35])[0] >> 8
    o['v1_len'] = b[35]
    o['v3_len'] = struct.unpack('!H', b[36:38])[0]
    o['fmt_selector'] = b[38]
    o['region_name'] = b[39:71].rstrip(b'\x00').decode(errors='replace')
    o['revision'] = struct.unpack('!H', b[71:73])[0]
    o['digest'] = b[73:89].hex()
    o['cist_int_cost'] = struct.unpack('!I', b[89:93])[0]
    o['cist_bridge_prio'] = struct.unpack('!H', b[93:95])[0] & 0xF000
    o['cist_bridge_mac'] = _mac(b[95:101])
    o['cist_rem_hops'] = b[101]
    mstis = []  # type: List[Dict[str, Any]]
    o['mstis'] = mstis
    off = 102
    while off + MSTI_MSG_LEN <= len(b):
        rr = struct.unpack('!H', b[off + 1:off + 3])[0]
        mstis.append({
            'flags': b[off],
            'regional_root_prio': rr & 0xF000,
            'mstid': rr & 0x0FFF,
            'reg_root_mac': _mac(b[off + 3:off + 9]),
            'int_cost': struct.unpack('!I', b[off + 9:off + 13])[0],
            'bridge_prio': b[off + 13],
            'port_prio': b[off + 14],
            'rem_hops': b[off + 15],
        })
        off += MSTI_MSG_LEN
    return o


if __name__ == "__main__":
    # Self-test: reference vector, round-trip, and the live-captured DUT BPDU.
    assert mst_config_digest({}).hex() == "ac36177f50283cd4b83821d8ab26de62", \
        "empty-region digest must match the IEEE 802.1s reference vector"

    vidmap = {v: 1 for v in (1, 2, 3, 10)}
    vidmap.update({100: 2, 200: 2})
    pkt = build_mst_bpdu(
        cist_root=(4096, 0, "00:aa:bb:cc:dd:ee"),
        cist_reg_root=(4096, 0, "00:aa:bb:cc:dd:ee"),
        region_name="sonic-test-region", revision=1, vid_to_mstid=vidmap,
        cist_bridge=(4096, 0, "00:aa:bb:cc:dd:ee"),
        mstis=[
            {'regional_root': (4096, 1, "00:aa:bb:cc:dd:ee"), 'bridge_prio': 0x10},
            {'regional_root': (8192, 2, "00:aa:bb:cc:dd:ee"), 'int_cost': 200, 'bridge_prio': 0x20, 'rem_hops': 19},
        ])
    d = parse_mst_bpdu(pkt)
    assert d is not None and len(pkt) == 134 and d['v3_len'] == 96
    assert [m['mstid'] for m in d['mstis']] == [1, 2]
    assert d['digest'] == mst_config_digest(vidmap).hex()

    # Real BPDU captured off a SONiC MST port (default region), LLC-stripped.
    live_hex = ("000003027e800000 00e8e49d1000000000 800000 00e8e49d1080e0 00001400"
                "02000f0000004000 6534 2d65382d30302d30302d31302d3964 00000000000000"
                "0000000000000000 0000 ac36177f50283cd4b83821d8ab26de62 00000000 800000"
                "00e8e49d10 14").replace(" ", "")
    live = parse_mst_bpdu(bytes.fromhex(live_hex))
    assert live is not None and live['version'] == 3 and live['type'] == 2 and live['v3_len'] == 64
    assert live['digest'] == "ac36177f50283cd4b83821d8ab26de62"
    assert (live['max_age'], live['hello'], live['fwd_delay']) == (20, 2, 15)
    print("mstp_lib self-test: PASS")
