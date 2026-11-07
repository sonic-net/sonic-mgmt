# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
MSTP (IEEE 802.1s) BPDU PTF test.

MSTP: an 802.3/LLC frame to `01:80:c2:00:00:00` carrying a single RST/MST BPDU (CIST + N MSTI records).
The BPDU encode/decode and the MST Configuration Digest live in `mstp_lib`,
validated against the IEEE 802.1s reference vector and a live sonic-stp capture.

The DUT only treats this sender as *in-region* when the region name, revision
AND the config digest all match its own; the digest is a function of the
VID->MSTID table, so the sonic-mgmt side must configure the DUT region and pass
the same `region_name` / `revision` / `vid_to_mstid` here.

Params (via ptf_runner `-t`):
  test_scenarios   send_cist | send_msti | validate_bpdu_packet |
                   validate_root_bridge | validate_boundary
  send_port        list of DUT ports to transmit on (PTF host ethN)
  capture_port     DUT port to sniff the DUT's own BPDUs on
  region_name, revision, vid_to_mstid (JSON obj)   region identity
  mstis            JSON list of {mstid, priority, mac, int_cost, port_prio, rem_hops, flags}
  cist_root_priority/mac, cist_ext_cost, cist_reg_root_priority/mac,
  cist_bridge_priority/mac, cist_port_priority                 CIST fields
  max_age, hello_time, forward_delay, message_age, cist_remaining_hops   timers
  expected_*       expected values for the validate_* scenarios
"""
import json
import time

from scapy.all import Dot3, LLC, Raw   # noqa: F401

from stp_bpdu_base import StpBpduBase
import mstp_lib


class MstpBpduTest(StpBpduBase):

    BPDU_DST_MAC = mstp_lib.MST_DST_MAC

    # Enough BPDUs to find one from the DUT when other bridges are also
    # advertising on the capture port.
    DUT_BPDU_CAPTURE_COUNT = 5

    # Defaults
    DEFAULT_PRIORITY = 32768
    DEFAULT_MAC = "00:01:02:03:04:05"
    DEFAULT_MAX_AGE = 20
    DEFAULT_HELLO = 2
    DEFAULT_FWD_DELAY = 15
    DEFAULT_REMAINING_HOPS = 20

    # ------------------------------------------------------------ param helpers
    def _json_param(self, name, default):
        v = self.param(name, default)
        if isinstance(v, str):
            try:
                return json.loads(v)
            except (ValueError, TypeError):
                return default
        return v

    def _region(self):
        return (self.param('region_name', ''),
                int(self.param('revision', 0)),
                self._json_param('vid_to_mstid', {}) or {})

    def _cist_kwargs(self):
        name, revision, vid_to_mstid = self._region()
        root_prio = int(self.param('cist_root_priority', self.DEFAULT_PRIORITY))
        root_mac = self.param('cist_root_mac', self.DEFAULT_MAC)
        br_prio = int(self.param('cist_bridge_priority', root_prio))
        br_mac = self.param('cist_bridge_mac', root_mac)
        reg_prio = int(self.param('cist_reg_root_priority', br_prio))
        reg_mac = self.param('cist_reg_root_mac', br_mac)
        # `port_priority` is the PVST-style param name the shared tests pass.
        port_prio = int(self.param('cist_port_priority', self.param('port_priority', 0x80)))
        return dict(
            cist_flags=int(self.param('cist_flags', 0x00)),
            cist_root=(root_prio, 0, root_mac),
            cist_ext_cost=int(self.param('cist_ext_cost', 0)),
            cist_reg_root=(reg_prio, 0, reg_mac),
            cist_port_id=(port_prio << 8) | int(self.param('cist_port_num', 1)),
            msg_age=int(self.param('message_age', 0)),
            max_age=int(self.param('max_age', self.DEFAULT_MAX_AGE)),
            hello=int(self.param('hello_time', self.DEFAULT_HELLO)),
            fwd_delay=int(self.param('forward_delay', self.DEFAULT_FWD_DELAY)),
            region_name=name, revision=revision, vid_to_mstid=vid_to_mstid,
            cist_int_cost=int(self.param('cist_int_cost', 0)),
            cist_bridge=(br_prio, 0, br_mac),
            cist_rem_hops=int(self.param('cist_remaining_hops', self.DEFAULT_REMAINING_HOPS)),
        )

    def _msti_list(self):
        """Normalize the `mstis` JSON list into build_mst_bpdu's record dicts."""
        out = []
        for m in (self._json_param('mstis', []) or []):
            prio = int(m.get('priority', self.DEFAULT_PRIORITY))
            mac = m.get('mac', self.param('cist_bridge_mac', self.DEFAULT_MAC))
            mstid = int(m['mstid'])
            out.append({
                'flags': int(m.get('flags', 0)),
                'regional_root': (prio, mstid, mac),
                'int_cost': int(m.get('int_cost', 0)),
                # bridge/port priority are the 4-bit value in the top nibble
                'bridge_prio': (prio >> 8) & 0xF0,
                'port_prio': int(m.get('port_prio', 0x80)),
                'rem_hops': int(m.get('rem_hops', self.DEFAULT_REMAINING_HOPS)),
            })
        return out

    # ------------------------------------------------------------ build / parse
    def create_bpdu_packet(self, with_mstis=False):
        kw = self._cist_kwargs()
        if with_mstis:
            kw['mstis'] = self._msti_list()
        bpdu = mstp_lib.build_mst_bpdu(**kw)
        src_mac = kw['cist_bridge'][2]
        # 802.3 framing: Dot3 auto-computes the length field; LLC 0x42/0x42/0x03.
        return Dot3(dst=self.BPDU_DST_MAC, src=src_mac) / \
            LLC(dsap=0x42, ssap=0x42, ctrl=0x03) / Raw(load=bytes(bpdu))

    def parse_bpdu_packet(self, packet):
        try:
            raw = bytes(packet)
            if raw[0:6].hex() != self.mac_to_bytes(self.BPDU_DST_MAC).hex():
                return None
            # 14-byte L2 (dst6+src6+len2) + 3-byte LLC (0x42,0x42,0x03) => BPDU at 17.
            if raw[14:17] != b'\x42\x42\x03':
                return None
            return mstp_lib.parse_mst_bpdu(raw[17:])
        except Exception as e:   # noqa: BLE001
            self.logger.info("parse_bpdu_packet error: %s", e)
            return None

    # ---------------------------------------------------------------- scenarios
    def _send_ports(self):
        p = self.param('send_port', [])
        return p if isinstance(p, (list, tuple)) else [p]

    def _capture_port(self):
        """Port to sniff on: explicit `capture_port`, else the first send_port.
        (Must not eagerly index `_send_ports()` — the capture-only scenarios
        pass `capture_port` and no `send_port`.)"""
        cp = self.param('capture_port')
        if cp is not None:
            return cp
        sp = self._send_ports()
        assert sp, "validate scenario needs capture_port or send_port"
        return sp[0]

    def _send_repeatedly(self, pkt):
        """Send `pkt` on every send_port, `send_count` times `send_interval`
        seconds apart. One PTF run then behaves like a neighbour with a real
        hello cadence, instead of a single frame that ages out between runs."""
        count = int(self.param('send_count', 1))
        interval = float(self.param('send_interval', 0))
        for i in range(count):
            for port in self._send_ports():
                self.send_bpdu(port, pkt)
            if interval and i < count - 1:
                time.sleep(interval)

    def scenario_send_cist(self):
        self._send_repeatedly(self.create_bpdu_packet(with_mstis=False))

    # PVST-parity alias: the shared tests drive the superior-BPDU sender thread
    # with scenario "config". For MST that is a (superior, in-region) CIST BPDU;
    # the caller supplies the low cist_*_priority / foreign mac that makes it win.
    scenario_config = scenario_send_cist

    def scenario_tcn(self):
        """Topology-change: a CIST BPDU with the TC flag (0x01) set, to trigger
        an fdb flush on the DUT (MST carries TC in the CIST flags, not a separate
        TCN BPDU as PVST/STP does)."""
        self.test_params['cist_flags'] = int(self.param('cist_flags', 0)) | 0x01
        pkt = self.create_bpdu_packet(with_mstis=False)
        for port in self._send_ports():
            self.send_bpdu(port, pkt)

    def scenario_send_msti(self):
        pkt = self.create_bpdu_packet(with_mstis=True)
        for port in self._send_ports():
            self.send_bpdu(port, pkt)

    def scenario_validate_bpdu_packet(self):
        """Sniff the DUT's own MST BPDU and assert its region/CIST/timer fields."""
        port = self._capture_port()
        bpdu = self.capture_one(port, timeout=int(self.param('capture_duration', 15)))
        assert bpdu is not None, "no MST BPDU captured on port {}".format(port)

        # The DUT's digest is a function of its VID->MSTID table; when the caller
        # doesn't pass an explicit expected_digest, derive it from the region so
        # the sonic-mgmt side needn't recompute it.
        _, _, vid_to_mstid = self._region()
        expected_digest = self.param('expected_digest') or mstp_lib.mst_config_digest(vid_to_mstid).hex()
        checks = {
            'region_name': self.param('expected_region_name'),
            'revision': self.param('expected_revision'),
            'digest': expected_digest,
            'cist_root_mac': self.param('expected_cist_root_mac'),
            'cist_bridge_mac': self.param('expected_cist_bridge_mac'),
            'max_age': self.param('expected_max_age'),
            'hello': self.param('expected_hello_time'),
            'fwd_delay': self.param('expected_forward_delay'),
        }
        for field, expected in checks.items():
            if expected is None:
                continue
            actual = bpdu.get(field)
            if field in ('revision', 'max_age', 'hello', 'fwd_delay'):
                actual, expected = int(actual), int(expected)
            else:
                actual, expected = str(actual).lower(), str(expected).lower()
            assert actual == expected, \
                "BPDU {} mismatch: expected {!r}, got {!r}".format(field, expected, actual)
        self.logger.info("validate_bpdu_packet OK: %s", bpdu)

    def scenario_validate_root_bridge(self):
        """Inject a superior CIST BPDU, then confirm the DUT now reports our
        injected bridge as the CIST root (i.e. accepted us as root)."""
        pkt = self.create_bpdu_packet(with_mstis=bool(self._json_param('mstis', [])))
        for port in self._send_ports():
            self.send_bpdu(port, pkt)

        expected_root = self.param('expected_cist_root_mac',
                                   self.param('cist_root_mac', self.DEFAULT_MAC)).lower()
        capture_port = self._capture_port()
        bpdu = None
        # Retry a few hello intervals for convergence.
        for _ in range(max(1, int(self.param('capture_retries', 3)))):
            bpdu = self.capture_one(capture_port, timeout=int(self.param('capture_duration', 6)))
            if bpdu and bpdu.get('cist_root_mac', '').lower() == expected_root:
                self.logger.info("DUT adopted injected CIST root %s", expected_root)
                return
        raise AssertionError(
            "DUT did not adopt injected CIST root {} (last BPDU: {})".format(expected_root, bpdu))

    def _capture_dut_bpdu(self):
        """Capture a BPDU the DUT originated.

        When `expected_bridge_mac` is given, BPDUs from any other bridge are
        discarded: the fields these scenarios assert are properties of the
        DUT's own advertisement, so validating a neighbour's BPDU would report
        a mismatch that says nothing about the DUT.
        """
        port = self._capture_port()
        timeout = int(self.param('capture_duration', 15))
        want = self.param('expected_bridge_mac')
        if want is None:
            bpdu = self.capture_one(port, timeout=timeout)
            assert bpdu is not None, "no MST BPDU captured on port {}".format(port)
            return bpdu

        want = str(want).lower()
        self.start_capture(port, count=self.DUT_BPDU_CAPTURE_COUNT, timeout=timeout)
        self.stop_capture(join_timeout=timeout + 5)
        captured = list(self.captured_bpdus)
        assert captured, "no MST BPDU captured on port {}".format(port)

        mine = [b for b in captured
                if str(b.get('cist_bridge_mac', '')).lower() == want]
        assert mine, (
            "no MST BPDU from bridge {} on port {}; captured bridges: {}".format(
                want, port, sorted({str(b.get('cist_bridge_mac', 'N/A'))
                                    for b in captured})))
        return mine[-1]

    def scenario_validate_timers(self):
        """Capture the DUT's own BPDU and assert its CIST timer fields."""
        bpdu = self._capture_dut_bpdu()
        for field, param in (('max_age', 'expected_max_age'),
                             ('hello', 'expected_hello_time'),
                             ('fwd_delay', 'expected_forward_delay')):
            expected = self.param(param)
            if expected is None:
                continue
            assert int(bpdu.get(field)) == int(expected), \
                "BPDU {} mismatch: expected {}, got {}".format(field, expected, bpdu.get(field))
        self.logger.info("validate_timers OK: %s", bpdu)

    def scenario_validate_path_cost(self):
        """Capture the DUT's BPDU on a designated port and assert the CIST
        *internal* root path cost (intra-region metric to the regional root)."""
        bpdu = self._capture_dut_bpdu()
        expected = int(self.param('expected_root_path_cost', 0))
        actual = int(bpdu.get('cist_int_cost'))

        # The internal cost is only accumulated for information received from
        # inside the region. If the DUT is still its own regional root, the
        # peer was treated as a boundary and this field is 0 whatever cost is
        # configured, so report the region rather than the number.
        reg_root = str(bpdu.get('cist_reg_root_mac', '')).lower()
        bridge = str(bpdu.get('cist_bridge_mac', '')).lower()
        if expected and actual == 0 and reg_root == bridge:
            raise AssertionError(
                "DUT is still the regional root ({}), so the CIST internal path "
                "cost is 0 by definition: the peer is outside the region. "
                "region={!r} revision={} digest={} external cost={}".format(
                    bridge, bpdu.get('region_name'), bpdu.get('revision'),
                    bpdu.get('digest'), bpdu.get('cist_ext_cost')))

        assert actual == expected, \
            "CIST internal root path cost mismatch: expected {}, got {}".format(expected, actual)
        self.logger.info("validate_path_cost OK: cist_int_cost=%d", actual)

    def scenario_validate_root_bridge_id(self):
        """Capture the DUT's BPDU and assert its CIST bridge id (mac + priority);
        used after the DUT wins the CIST root, so bridge == root."""
        bpdu = self._capture_dut_bpdu()
        exp_mac = self.param('expected_bridge_mac')
        if exp_mac is not None:
            assert str(bpdu.get('cist_bridge_mac')).lower() == str(exp_mac).lower(), \
                "CIST bridge mac mismatch: expected {}, got {}".format(exp_mac, bpdu.get('cist_bridge_mac'))
        exp_prio = self.param('expected_bridge_priority')
        if exp_prio is not None:
            assert int(bpdu.get('cist_bridge_prio')) == int(exp_prio), \
                "CIST bridge priority mismatch: expected {}, got {}".format(exp_prio, bpdu.get('cist_bridge_prio'))
        self.logger.info("validate_root_bridge_id OK: %s", bpdu)

    def scenario_validate_boundary(self):
        """Send a BPDU with a deliberately foreign region (mismatched digest) so
        the DUT marks the port an MST boundary. The digest is derived from
        `vid_to_mstid`, so callers pass a differing map (or region_name/revision);
        the sonic-mgmt side asserts the boundary state via the DB."""
        pkt = self.create_bpdu_packet(with_mstis=bool(self._json_param('mstis', [])))
        for port in self._send_ports():
            self.send_bpdu(port, pkt)

    def scenarios(self):
        return {
            'send_cist': self.scenario_send_cist,
            'send_msti': self.scenario_send_msti,
            'config': self.scenario_config,
            'tcn': self.scenario_tcn,
            'validate_bpdu_packet': self.scenario_validate_bpdu_packet,
            'validate_root_bridge': self.scenario_validate_root_bridge,
            'validate_root_bridge_id': self.scenario_validate_root_bridge_id,
            'validate_timers': self.scenario_validate_timers,
            'validate_path_cost': self.scenario_validate_path_cost,
            'validate_l2_packet': self.scenario_validate_l2_packet,
            'validate_boundary': self.scenario_validate_boundary,
        }
