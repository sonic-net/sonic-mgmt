"""L2 VxLAN sequences no BGP EVPN peer can produce: remote MAC rewrites, a fast-reboot FDB row, a shared underlay,
station moves and high VLAN IDs.

Topology t0 or single-ASIC t2 or lt2 (see the rig). The DUT is a VTEP on its Loopback0; the PTF plays every remote VTEP.
Remote VTEPs, flood lists and remote MACs are written straight to APPL_DB (VXLAN_REMOTE_VNI_TABLE, VXLAN_FDB_TABLE)
through swssconfig, so no BGP EVPN peer is involved and every case exercises orchagent -> SAI -> ASIC only. Each case
here is a sequence the EVPN control plane does not produce (an in-place type rewrite on a schedule, an APPL_DB
FDB_TABLE row, two VTEPs behind one underlay next-hop set) or needs no remote state at all (station moves, high VLAN
IDs). Everything a BGP EVPN peer can drive, the outer header, decap and tag cases included, is in
test_vxlan_evpn_l2.py, through the shipped control plane. On a virtual switch these rows never reach the kernel,
which is its dataplane, so the module's remote-state cases need a hardware switch.

Frames are counted per PTF port by a payload tag, so an echo, a re-flood, a duplicate or a stripped tag is visible (a
first-match check such as verify_packet_any_port cannot see any of those).

Rig (module fixture), built on the t0's first VLAN with at least three members (e.g. Vlan1000), or on a t2 on a
Vlan1000 of neighbor-facing ports borrowed by vxlan_l2_helpers.access_ports and restored after the module:
  * Vlan2000 <-> VNI 12000, VTEP vtep1 on Loopback0, EVPN NVO nvo1.
  * H0 moved from the base VLAN to Vlan2000 untagged; H1 and H2 tagged members of Vlan2000 (they stay untagged in
    the base VLAN). One untagged and two tagged members in the same VNI-mapped VLAN.
  * Remote VTEPs A (100.100.91.1) and B (100.100.92.1) are reached through the default route, so they share
    one underlay next-hop set.

Cases (each asserts one behavior, with a positive control in the same case for every negative reading):
  test_remote_mac_reprogrammed_in_place
           a remote MAC written again onto the VTEP it is on (only its type changes) keeps forwarding, without a gap
  test_remote_mac_replaced_by_local_row
           a remote MAC that an APPL_DB FDB_TABLE row (the fast-reboot FDB restore) puts on a local port is forwarded
           there only, and then behaves as a dynamic local MAC
  test_two_vteps_shared_underlay[a_then_b|b_then_a]
           two VTEPs over one underlay next-hop set each keep their own MACs, in either creation order
  test_high_vid_vlans[vlans_after_rifs|rif_after_vlans]
           VLAN IDs from 3073 up (3073-3080 sampled) are programmed and forward, whether created after or before a
           router interface
  test_station_move_updates_fdb_record[move|round_trip]
           after a station move, a per-port flush of the MAC's new port removes it from hardware

Tagged copies at the PTF: some fanouts drop C-tagged frames from the DUT toward the testserver (a SONiC fanout whose
access ports have no `tpid: 0x9100` classifies the DUT's 802.1Q tag as its own VLAN). The rig measures this once, with
a plain broadcast in Vlan2000 before the VNI map: when the DUT transmits the tagged copies (port TX counters) but the
PTF does not see them, every reading of the tagged members H1/H2 comes from the DUT's port TX counters instead, and a
tag check reads "the DUT transmitted the copy and the PTF saw no untagged one" (a stripped tag passes the fanout).
"""
import contextlib
import logging
import time
from types import SimpleNamespace

import pytest
from natsort import natsorted

from tests.common.utilities import wait_until
from tests.vxlan.vxlan_l2_helpers import (
    BROADCAST_MAC,
    GOOD,
    KNOWN_HARMLESS_LOG,
    L2NHG_DEL_NOISE_LOG,
    MOVE_DEL_LOG,
    N,
    TX_SLACK,
    AsicView,
    Steps,
    access_ports,
    add_remote_vtep,
    add_vxlan,
    asic_count,
    asic_counts,
    asic_vlan_ids,
    capture,
    db_hget,
    db_keys,
    delivered,
    fail_unless_clean,
    fdb_port,
    flush_fdb,
    flush_vlan_fdb,
    hold_arp_refresh,
    kernel_fdb_forget,
    kernel_fdb_port,
    learn_mac,
    local_mac_row,
    log_clean,
    loopback0_ipv4,
    make_tagger,
    member_flood,
    members_tx,
    native_on,
    probe_frame,
    probe_tagged_path,
    raw_payloads,
    remote_mac_row,
    remote_vni_row,
    remove_vxlan,
    resume_arp_refresh,
    rif_to_cycle,
    sai_fdb_calls,
    sairedis_mark,
    send_and_count,
    settled_delta,
    sh,
    stream_and_count,
    summarize,
    swss_apply,
    swss_apply_later,
    swss_apply_later_done,
    swss_apply_later_finished,
    tx_delivered,
    underlay_toward,
    unicast_counts,
    vid_reading,
    vxlan_state_left,
    vxlan_to,
    vxlan_tunnels_to,
    wait_for,
)

pytestmark = [
    pytest.mark.topology("t0", "t2", "lt2"),
]

logger = logging.getLogger(__name__)

VLAN_ID = 2000
VLAN = "Vlan{}".format(VLAN_ID)
VNI = 12000
VTEP_A, VTEP_B = "100.100.91.1", "100.100.92.1"
MAC_A, MAC_B = "02:4c:32:0a:00:01", "02:4c:32:0b:00:01"   # static remote MACs behind A and B

HIGH_VIDS = list(range(3073, 3081))
CTRL_VID = 3000            # below the 3073+ range: the high-VID case's instrument control
NEG_VID = 3500             # never configured: must not forward
N_VID = 10
BASELINE_TYPES = ("TUNNEL", "TUNNEL_MAP_ENTRY", "VLAN", "VLAN_MEMBER", "BRIDGE_PORT")

HARMLESS_LOG = KNOWN_HARMLESS_LOG + L2NHG_DEL_NOISE_LOG

tag = make_tagger("VXL2")


# --------------------------------------------------------------------------------------------------------------------
# rig
# --------------------------------------------------------------------------------------------------------------------
def assert_clean_start(duthost):
    dirty = vxlan_state_left(duthost, ["Vlan{}".format(vid) for vid in [VLAN_ID, CTRL_VID, NEG_VID] + HIGH_VIDS])
    port = db_hget(duthost, "APPL_DB", "SWITCH_TABLE:switch", "vxlan_port")
    if port not in ("", "4789"):
        dirty.append("SWITCH_TABLE:switch vxlan_port={}".format(port))
    for ip in (VTEP_A, VTEP_B):
        if vxlan_tunnels_to(duthost, ip):
            dirty.append("ASIC_DB tunnel to {}".format(ip))
    fail_unless_clean("L2 VxLAN rig", dirty)


@pytest.fixture(scope="module")
def access(duthost, tbinfo, request):
    with access_ports(duthost, tbinfo, request, need=3, want=4) as a:
        yield a


@pytest.fixture(scope="module")
def rig(duthost, ptfadapter, access, request):
    mg = access.mg
    idx = mg["minigraph_ptf_indices"]
    members = access.members
    base_vlan, hosts, canary = access.base_vlan, members[:3], (members[3] if len(members) > 3 else None)
    base_vid = int(base_vlan.replace("Vlan", ""))
    h0, h1, h2 = hosts
    uplink_ports = sorted(p for name, p in idx.items() if name not in access.vlan_members)
    uplink_names = natsorted(name for name in idx if name not in access.vlan_members)
    # Underlay toward the remote VTEPs: both through the same next-hop set (the default route).
    pfx_a, if_a, inj = underlay_toward(duthost, mg, VTEP_A)
    pfx_b, if_b, _ = underlay_toward(duthost, mg, VTEP_B)

    assert_clean_start(duthost)
    r = SimpleNamespace(
        duthost=duthost, mg=mg, base_vlan=base_vlan, base_vid=base_vid, h0=h0, h1=h1, h2=h2,
        p0=idx[h0], p1=idx[h1], p2=idx[h2], port={h0: idx[h0], h1: idx[h1], h2: idx[h2]},
        uplink_ports=uplink_ports, uplink_names=uplink_names, canary=canary, inj_port=inj[0], borrowed=access.borrowed,
        dut_vtep=loopback0_ipv4(mg), router_mac=duthost.facts["router_mac"],
        underlay={VTEP_A: (pfx_a, if_a), VTEP_B: (pfx_b, if_b)}, tagged_hosts=[h1, h2], tagged_at_ptf=True,
        tagged_why="", vs=duthost.facts.get("asic_type") == "vs", arp_held=False)
    base = asic_counts(duthost, BASELINE_TYPES)
    logger.info("rig: base %s, h0/h1/h2 %s/%s/%s (ptf %s/%s/%s), canary %s, uplinks %s, inject on ptf %s, VTEP %s, "
                "underlay %s, ASIC_DB baseline %s", base_vlan, h0, h1, h2, r.p0, r.p1, r.p2, canary, uplink_ports,
                r.inj_port, r.dut_vtep, r.underlay, base)

    built = []
    raw_payloads(ptfadapter)
    try:
        with log_clean(request, duthost, "setup", HARMLESS_LOG):
            sh(duthost, "sudo config vlan add {}".format(VLAN_ID))
            built.append("vlan")
            sh(duthost, "sudo config vlan member del {} {}".format(base_vid, h0))
            built.append("h0_moved")
            sh(duthost, "sudo config vlan member add -u {} {}".format(VLAN_ID, h0))
            sh(duthost, "sudo config vlan member add {} {}".format(VLAN_ID, h1))
            sh(duthost, "sudo config vlan member add {} {}".format(VLAN_ID, h2))
            wait_for(60, 2, lambda: len(db_keys(duthost, "APPL_DB", "VLAN_MEMBER_TABLE:{}:*".format(VLAN))) == 3,
                     "3 members of {} in APPL_DB".format(VLAN))
            wait_for(60, 2, lambda: asic_count(duthost, "VLAN_MEMBER") >= base["VLAN_MEMBER"] + 2,
                     "the {} members in ASIC_DB".format(VLAN))
            time.sleep(3)
            r.tagged_at_ptf, r.tagged_why = probe_tagged_path(r, ptfadapter, r.p0, VLAN_ID, tag("ctag"),
                                                              "02:4c:32:00:00:70")
            built.append("vtep")
            add_vxlan(duthost, r.dut_vtep, [(VLAN_ID, VNI)])
            wait_for(60, 2, lambda: asic_count(duthost, "TUNNEL_MAP_ENTRY") > base["TUNNEL_MAP_ENTRY"],
                     "a new ASIC_DB tunnel map entry")
            time.sleep(5)
        r.arp_held = hold_arp_refresh(duthost)
        yield r
    finally:
        try:
            teardown_rig(request, duthost, r, base, built)
        finally:
            if r.arp_held:
                resume_arp_refresh(duthost)


def teardown_rig(request, duthost, r, base, built):
    """Undo the rig in dependency order, then prove the DUT is back to its baseline. Never `config save`."""
    step = Steps("L2 VxLAN rig teardown")
    step("teardown", lambda: undo_rig(request, duthost, r, base, built, step))
    step.finish()


def undo_rig(request, duthost, r, base, built, step):
    """The rig built in reverse dependency order: remote state, map, NVO, VTEP, members, VLAN, H0 back."""
    with log_clean(request, duthost, "teardown", HARMLESS_LOG):
        step("fdb flush", lambda: flush_vlan_fdb(duthost, VLAN_ID))
        rows = [{k: {}, "OP": "DEL"} for k in
                db_keys(duthost, "APPL_DB", "VXLAN_FDB_TABLE:{}:*".format(VLAN)) +
                db_keys(duthost, "APPL_DB", "VXLAN_REMOTE_VNI_TABLE:{}:*".format(VLAN))]
        if rows:
            step.errors.append("remote state left by a case: {}".format([list(x)[0] for x in rows]))
            step("remote rows", lambda: swss_apply(duthost, rows))
            time.sleep(10)
        if "vtep" in built:
            remove_vxlan(duthost, [(VLAN_ID, VNI)], step)
        if "vlan" in built:
            for port in (r.h1, r.h2, r.h0):
                step("member del " + port, lambda p=port: sh(
                    duthost, "sudo config vlan member del {} {}".format(VLAN_ID, p), check=False))
            moved = 1 if "h0_moved" in built else 0
            step("members gone", lambda: wait_for(
                60, 2, lambda: asic_count(duthost, "VLAN_MEMBER") == base["VLAN_MEMBER"] - moved,
                "the {} members to go from ASIC_DB".format(VLAN)))
            step("vlan del", lambda: sh(duthost, "sudo config vlan del {}".format(VLAN_ID)))
        if "h0_moved" in built:
            step("h0 back", lambda: sh(duthost, "sudo config vlan member add -u {} {}".format(r.base_vid, r.h0)))
        if not wait_until(90, 5, 0, lambda: asic_counts(duthost, BASELINE_TYPES) == base):
            step.errors.append("ASIC_DB not back to baseline: {} -> {}".format(
                base, asic_counts(duthost, BASELINE_TYPES)))
        step.errors.extend("still holds " + x for x in vxlan_state_left(duthost, [VLAN]))
        mode = db_hget(duthost, "CONFIG_DB", "VLAN_MEMBER|{}|{}".format(r.base_vlan, r.h0), "tagging_mode")
        if "h0_moved" in built and mode != "untagged":
            step.errors.append("{} not restored to {} untagged ('{}')".format(r.h0, r.base_vlan, mode))


def static_rows_need_hardware(r):
    if r.vs:
        pytest.skip("on a virtual switch the kernel is the dataplane, and static APPL_DB remote rows never reach it; "
                    "hardware runs these sequences (the EVPN modules install remote MACs through the control plane)")


@pytest.fixture(autouse=True)
def arp_refresh_held(request):
    """No periodic ARP/ND refresh inside a case's counting windows; a swss restart inside a case brings it back."""
    if "rig" in request.fixturenames:
        r = request.getfixturevalue("rig")
        if hold_arp_refresh(r.duthost):
            r.arp_held = True


@pytest.fixture(autouse=True)
def ignore_known_harmless(duthost, loganalyzer):
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(HARMLESS_LOG)


# --------------------------------------------------------------------------------------------------------------------
# per-case remote state
# --------------------------------------------------------------------------------------------------------------------
@contextlib.contextmanager
def remote_vteps(r, order, macs=None):
    """Add remote VTEPs in order (each VTEP's static MACs right after it); remove all of it on exit. When the case
    body failed, a clean-up problem is logged, so the case's own failure stays the verdict."""
    duthost, macs = r.duthost, macs or {}
    added, body_ok = [], False

    def _cleanup():
        step = Steps("remote VTEP clean-up")
        rows = [remote_mac_row(VLAN, m, v, VNI, op="DEL") for m, v in macs.items()]
        if rows:
            step("remote MACs", lambda: swss_apply(duthost, rows))
            time.sleep(3)
        step("fdb flush", lambda: flush_fdb(duthost, "VLAN", str(VLAN_ID)))
        time.sleep(3)
        if added:
            step("remote VTEPs", lambda: swss_apply(
                duthost, [remote_vni_row(VLAN, ip, VNI, op="DEL") for ip in added]))
        step("tunnels gone", lambda: wait_for(
            60, 3, lambda: not any(vxlan_tunnels_to(duthost, ip) for ip in added),
            "ASIC_DB tunnels to {} to go".format(added)))
        step.finish(report=body_ok)

    try:
        for ip in order:
            added.append(ip)
            add_remote_vtep(duthost, VLAN, ip, VNI)
            rows = [remote_mac_row(VLAN, m, v, VNI) for m, v in macs.items() if v == ip]
            if rows:
                swss_apply(duthost, rows)
                for m, v in macs.items():
                    if v == ip:
                        wait_for(30, 2, lambda: len(AsicView(duthost).fdb(m, VLAN_ID)) == 1,
                                 "ASIC_DB FDB entry for remote MAC {}".format(m))
        yield
        body_ok = True
    finally:
        _cleanup()


def learn(r, ptfadapter, port, iface, mac, vid=None):
    learn_mac(ptfadapter, r.duthost, port, iface, VLAN_ID, mac, tag("learn"), vid)


def raw_on_uplinks(r, copies, exclude=()):
    return sum(1 for c in copies if c.kind == "native" and c.port in r.uplink_ports and c.port not in exclude)


# --------------------------------------------------------------------------------------------------------------------
# a remote MAC re-programmed in place
# --------------------------------------------------------------------------------------------------------------------
REPROGRAM_ROUNDS = 5
REPROGRAM_STREAM_S = 30     # 2 s lead, the rewrites (two per round, each one swssconfig run plus 0.3 s), a tail
REPROGRAM_MAX_GAP_S = 1.0   # the stream arrives in bursts 50 ms apart; a longer silence is an outage


def test_remote_mac_reprogrammed_in_place(rig, ptfadapter):
    """A remote MAC that is programmed again onto the remote VTEP it is already on keeps forwarding.

    While known unicast to a static remote MAC runs, the MAC's remote entry is written again REPROGRAM_ROUNDS times
    with only its type changed (static to dynamic and back). orchagent passes each change to the SAI as SETs of the
    attributes of the existing FDB entry, its bridge port and endpoint address among them, with the values they have.
    Every frame must keep leaving encapsulated to the MAC's VTEP with the VLAN's VNI: none anywhere else (a second
    remote VTEP is in the flood list, so a flooded frame shows there), at least 9 in 10 of them, and without a
    silence longer than REPROGRAM_MAX_GAP_S. Afterwards ASIC_DB holds the same single entry on the same bridge port,
    the VxLAN object counts are unchanged and a fresh 40-frame stream is delivered.
    The case fails as not exercised when the rewrites had not all been made by the end of the stream, or when the
    sairedis recording shows fewer SETs of the entry's type (or re-creates) than rounds: the rewrites then never
    reached the SAI.
    """
    static_rows_need_hardware(rig)
    r, d = rig, rig.duthost
    src = "02:4c:32:00:00:60"
    key = "VXLAN_FDB_TABLE:{}:{}".format(VLAN, MAC_A)

    def one_stream(name):
        t = tag(name)
        copies, tx = capture(r, lambda: send_and_count(ptfadapter, r.p0, probe_frame(t, MAC_A, src), N, t),
                             live=r.uplink_names)
        good, other = unicast_counts(copies, r.dut_vtep, VTEP_A, VNI, MAC_A)
        return (delivered(good) and other == 0 and member_flood(r, copies, tx) == 0 and
                raw_on_uplinks(r, copies) == 0), "{} of {} to {} VNI {}, {} other VxLAN. Copies: {}".format(
                    good, N, VTEP_A, VNI, other, summarize(copies))

    with remote_vteps(r, [VTEP_A, VTEP_B], {MAC_A: VTEP_A}):
        ok, text = one_stream("rip0")
        if not ok:
            pytest.fail("known unicast to {} is not delivered before any rewrite, nothing to compare: {}".format(
                MAC_A, text))
        before = AsicView(d).fdb_entries(MAC_A, VLAN_ID)
        counts = asic_counts(d, BASELINE_TYPES)
        mark = sairedis_mark(d)
        t = tag("rip")
        run = swss_apply_later(d, [[remote_mac_row(VLAN, MAC_A, VTEP_A, VNI, mac_type="dynamic")],
                                   [remote_mac_row(VLAN, MAC_A, VTEP_A, VNI)]], REPROGRAM_ROUNDS)
        streamed = False
        try:
            sent, got = stream_and_count(ptfadapter, r.p0, probe_frame(t, MAC_A, src), t, REPROGRAM_STREAM_S)
            in_stream = swss_apply_later_finished(d, run)
            streamed = True
        finally:
            try:
                swss_apply_later_done(d, run)
            except Exception as e:
                if streamed:
                    raise
                logger.error("after the failed stream: %s", e)
        if not in_stream:
            pytest.fail("not exercised: the rewrites of the remote MAC row were still running when the {} s stream "
                        "ended".format(REPROGRAM_STREAM_S))
        calls = sai_fdb_calls(d, MAC_A, mark)
        row_type = db_hget(d, "APPL_DB", key, "type")
        if calls["set_type"] + calls["create"] < REPROGRAM_ROUNDS or row_type != "static":
            pytest.fail("not exercised: {} rewrites of the remote MAC row reached the SAI as {} (the row's type is "
                        "now '{}')".format(2 * REPROGRAM_ROUNDS, calls, row_type))

        def right(c):
            return (c.kind == "vxlan" and c.osrc == r.dut_vtep and c.odst == VTEP_A and c.vni == VNI and
                    c.ivid is None and c.idst == MAC_A)
        times = [when for when, c, _raw in got if right(c)]
        other = [c for _when, c, _raw in got if not right(c)]
        gap = max([b - a for a, b in zip([0.0] + times, times + [float(REPROGRAM_STREAM_S)])] or [REPROGRAM_STREAM_S])
        assert not other and sent * 9 // 10 <= len(times) <= sent and gap <= REPROGRAM_MAX_GAP_S, (
            "known unicast to {} while its remote entry was re-programmed in place {} times (SAI calls {}): {} of {} "
            "frames reached {} VNI {}, longest silence {:.1f} s, {} copies anywhere else: {}".format(
                MAC_A, 2 * REPROGRAM_ROUNDS, calls, len(times), sent, VTEP_A, VNI, gap, len(other), summarize(other)))
        after = AsicView(d).fdb_entries(MAC_A, VLAN_ID)
        now = asic_counts(d, BASELINE_TYPES)
        assert (len(after) == 1 and len(before) == 1 and after[0][0] == before[0][0] and
                after[0][2].get("SAI_FDB_ENTRY_ATTR_ENDPOINT_IP") == before[0][2].get("SAI_FDB_ENTRY_ATTR_ENDPOINT_IP")
                and now == counts), (
            "after the in-place re-programs: ASIC_DB FDB entries of {} {} -> {} (bridge port, endpoint: {} -> {}), "
            "object counts {} -> {}".format(
                MAC_A, len(before), len(after),
                [(e[0], e[2].get("SAI_FDB_ENTRY_ATTR_ENDPOINT_IP")) for e in before],
                [(e[0], e[2].get("SAI_FDB_ENTRY_ATTR_ENDPOINT_IP")) for e in after], counts, now))
        ok, text = one_stream("rip1")
        assert ok, "known unicast to {} after the in-place re-programs: {}".format(MAC_A, text)


# --------------------------------------------------------------------------------------------------------------------
# a MAC replaced between a remote VTEP and a local port
# --------------------------------------------------------------------------------------------------------------------
MAC_R = "02:4c:32:0a:00:6a"           # the MAC that changes sides
REPLACE_SRC = "02:4c:32:00:00:91"     # source of the probes from H1


def to_replaced_mac(r, ptfadapter, name):
    """N known-unicast frames from the tagged member H1 to MAC_R: SimpleNamespace(local, encap, other, flood, text)
    with the copies on H0, the copies encapsulated to VTEP A, every other VxLAN copy and the copies on H2."""
    t = tag(name)
    copies, tx = capture(r, lambda: send_and_count(
        ptfadapter, r.p1, probe_frame(t, MAC_R, REPLACE_SRC, vlan=VLAN_ID), N, t), live=[r.h0] + r.uplink_names)
    encap, other = unicast_counts(copies, r.dut_vtep, VTEP_A, VNI, MAC_R)
    o = SimpleNamespace(local=native_on(copies, r.p0), encap=encap, other=other,
                        flood=member_flood(r, copies, tx, hosts=[r.h2]))
    o.text = "{} of {} on {}, {} encapsulated to {}, {} other VxLAN, {} on {}. Copies: {}".format(
        o.local, N, r.h0, o.encap, VTEP_A, o.other, o.flood, r.h2, summarize(copies))
    return o


def drop_rows(duthost, rows):
    """Clean-up of a case's APPL_DB rows; a failure is logged, so the case's own failure stays the verdict."""
    try:
        swss_apply(duthost, rows)
    except Exception as e:
        logger.error("clean-up of %s failed: %s", [list(row)[0] for row in rows], e)


def fdb_views(r):
    """What ASIC_DB, `show mac` and STATE_DB hold for MAC_R: ([FdbEntry], port or None, (port, type) or None)."""
    d = r.duthost
    key = "FDB_TABLE|{}:{}".format(VLAN, MAC_R)
    state = (db_hget(d, "STATE_DB", key, "port"), db_hget(d, "STATE_DB", key, "type")) if db_keys(
        d, "STATE_DB", key) else None
    return AsicView(d).fdb(MAC_R, VLAN_ID), fdb_port(d, VLAN_ID, MAC_R), state


def is_local_dynamic(r, views):
    entries, shown, state = views
    raw = AsicView(r.duthost).fdb_entries(MAC_R, VLAN_ID)
    if len(raw) != 1 or raw[0][2].get("SAI_FDB_ENTRY_ATTR_ALLOW_MAC_MOVE", "false") != "false":
        return False
    return (len(entries) == 1 and entries[0].bp_type == "SAI_BRIDGE_PORT_TYPE_PORT" and entries[0].port == r.h0 and
            entries[0].fdb_type == "SAI_FDB_ENTRY_TYPE_DYNAMIC" and entries[0].endpoint in ("", "0.0.0.0", "::") and
            state == (r.h0, "dynamic"))


def test_remote_mac_replaced_by_local_row(rig, ptfadapter):
    """A MAC behind a remote VTEP that an APPL_DB FDB_TABLE row puts on a local port is forwarded there only, and
    is then an ordinary dynamic local MAC.

    The MAC is installed behind VTEP A as a remote entry that may move (VXLAN_FDB_TABLE type dynamic). Control: known
    unicast to it from the tagged member H1 is encapsulated to A. An APPL_DB FDB_TABLE row of type dynamic on the
    untagged member H0 is then written for it (as the FDB restore of a fast reboot does), which orchagent passes to
    the SAI as SETs on the existing entry (type dynamic, the local bridge port, MAC move no longer allowed, which
    ASIC_DB must then show). The same move made by learning, with the remote MAC from a BGP EVPN peer, is
    test_vxlan_evpn_l2.py's test_remote_mac_replaced_by_local. Then:
      * ASIC_DB holds one entry for the MAC, dynamic, on H0's bridge port, with no (or an all-zero) endpoint
        address, and STATE_DB names the same port and type;
      * every frame to the MAC leaves on H0 only, none encapsulated;
      * the remote VTEP's withdrawal of the MAC leaves the local entry in place;
      * a flush of H0's port removes the entry from ASIC_DB, `show mac` and STATE_DB, no remote entry comes back,
        and the MAC floods (H0 and VTEP A each get every frame);
      * a frame from the host puts it back on H0, and every frame to it leaves on H0 only again;
      * `show mac` names H0's port for the MAC whenever the databases do (read at every step, judged last, so that
        a display problem does not hide the forwarding steps).
    """
    static_rows_need_hardware(rig)
    r, d = rig, rig.duthost
    shown = []
    with remote_vteps(r, [VTEP_A]):
        try:
            swss_apply(d, [remote_mac_row(VLAN, MAC_R, VTEP_A, VNI, mac_type="dynamic")])
            wait_for(30, 2, lambda: [e.dip for e in AsicView(d).fdb(MAC_R, VLAN_ID)] == [VTEP_A],
                     "ASIC_DB FDB entry of {} on the tunnel to {}".format(MAC_R, VTEP_A))
            o = to_replaced_mac(r, ptfadapter, "rlC")
            if not (delivered(o.encap) and o.other == 0 and o.local == 0 and o.flood == 0):
                pytest.fail("known unicast to the remote MAC {} is not encapsulated to {} only, nothing to compare: {}"
                            .format(MAC_R, VTEP_A, o.text))
            swss_apply(d, [local_mac_row(VLAN, MAC_R, r.h0)])
            wait_until(20, 1, 0, lambda: is_local_dynamic(r, fdb_views(r)))
            views = fdb_views(r)
            shown.append(views[1])
            assert is_local_dynamic(r, views), (
                "{} moved from {} to {} (APPL_DB row): ASIC_DB FDB entries {}, `show mac` port {}, STATE_DB (port, "
                "type) {}; expected one dynamic entry on {} with no endpoint address in all three".format(
                    MAC_R, VTEP_A, r.h0, views[0], views[1], views[2], r.h0))
            o = to_replaced_mac(r, ptfadapter, "rl1")
            assert delivered(o.local) and o.encap == 0 and o.other == 0 and o.flood == 0, (
                "known unicast to {} after it moved from {} to {}: {}".format(MAC_R, VTEP_A, r.h0, o.text))
            # the remote VTEP withdraws the MAC, as it does once the MAC is advertised from here
            swss_apply(d, [remote_mac_row(VLAN, MAC_R, VTEP_A, VNI, op="DEL")])
            wait_for(20, 1, lambda: not db_keys(d, "APPL_DB", "VXLAN_FDB_TABLE:{}:{}".format(VLAN, MAC_R)),
                     "the remote row of {} to go from APPL_DB".format(MAC_R))
            time.sleep(5)
            views = fdb_views(r)
            shown.append(views[1])
            assert is_local_dynamic(r, views), (
                "{} on {}, after {} withdrew its remote entry: ASIC_DB FDB entries {}, `show mac` port {}, STATE_DB "
                "{}; the local entry must stay".format(MAC_R, r.h0, VTEP_A, views[0], views[1], views[2]))
            flush_fdb(d, "PORT", r.h0)
            wait_until(20, 1, 0, lambda: fdb_views(r) == ([], None, None))
            time.sleep(2)
            views = fdb_views(r)
            o = to_replaced_mac(r, ptfadapter, "rl2")
            assert views == ([], None, None) and delivered(o.local) and delivered(o.encap) and o.other == 0, (
                "after a flush of {}: ASIC_DB FDB entries of {} {}, `show mac` port {}, STATE_DB {} (expected none: "
                "the dynamic entry is flushed and no remote entry comes back); unicast to it must flood: {}".format(
                    r.h0, MAC_R, views[0], views[1], views[2], o.text))
            learn(r, ptfadapter, r.p0, r.h0, MAC_R)
            views = fdb_views(r)
            shown.append(views[1])
            o = to_replaced_mac(r, ptfadapter, "rl3")
            assert (is_local_dynamic(r, views) and delivered(o.local) and o.encap == 0 and o.other == 0 and
                    o.flood == 0), (
                "{} learned again on {} after the flush: ASIC_DB FDB entries {}, `show mac` port {}, STATE_DB {}; "
                "unicast to it: {}".format(MAC_R, r.h0, views[0], views[1], views[2], o.text))
        finally:
            drop_rows(d, [remote_mac_row(VLAN, MAC_R, VTEP_A, VNI, op="DEL"), local_mac_row(VLAN, MAC_R, r.h0,
                                                                                            op="DEL")])
    assert shown == [r.h0] * 3, (
        "`show mac` named {} as the port of {} at the three steps where ASIC_DB and STATE_DB had it as a dynamic "
        "entry on {} (after the move, after the remote withdrawal, after it was learned again)".format(
            shown, MAC_R, r.h0))


# --------------------------------------------------------------------------------------------------------------------
# two VTEPs over one underlay
# --------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("order", ["a_then_b", "b_then_a"])
def test_two_vteps_shared_underlay(rig, ptfadapter, order):
    """Two remote VTEPs behind one underlay next-hop set each keep their own MACs, in either creation order.

    If the two tunnels end up sharing one binding, the tunnel bound last wins: both MACs are encapsulated to its DIP.
    """
    static_rows_need_hardware(rig)
    r = rig
    (pa, ia), (pb, ib) = r.underlay[VTEP_A], r.underlay[VTEP_B]
    if ia != ib:
        pytest.fail("geometry: {} via {} {} and {} via {} {} do not share an underlay next-hop set; the case "
                    "cannot test per-tunnel MAC binding here".format(VTEP_A, pa, sorted(ia), VTEP_B, pb, sorted(ib)))
    vteps = [VTEP_A, VTEP_B] if order == "a_then_b" else [VTEP_B, VTEP_A]
    owner = {MAC_A: VTEP_A, MAC_B: VTEP_B}
    with remote_vteps(r, vteps, owner):
        for mac, vtep in owner.items():
            entries = AsicView(r.duthost).fdb(mac, VLAN_ID)
            assert len(entries) == 1 and vtep in (entries[0].dip, entries[0].endpoint), (
                "orchagent programmed {} as {}, not one entry on the tunnel to {}: a SONiC-side problem, not the "
                "per-tunnel binding".format(mac, entries, vtep))
        t = tag("2vB" + order[0])
        bc = send_and_count(ptfadapter, r.p0, probe_frame(t, BROADCAST_MAC, "02:4c:32:00:00:50"), N, t)
        ba, bb = len(vxlan_to(bc, r.dut_vtep, VTEP_A)), len(vxlan_to(bc, r.dut_vtep, VTEP_B))
        assert delivered(ba) and delivered(bb), (
            "control: broadcast reached A {} / B {} of {}. Copies: {}".format(ba, bb, N, summarize(bc)))

        results, bad = {}, []
        for i, mac in enumerate([MAC_A, MAC_B] if order == "a_then_b" else [MAC_B, MAC_A]):
            t = tag("2v{}{}".format(order[0], i))
            copies, tx = capture(r, lambda: send_and_count(
                ptfadapter, r.p0, probe_frame(t, mac, "02:4c:32:00:00:51"), N, t), live=r.uplink_names)
            own = owner[mac]
            to_own = len([c for c in vxlan_to(copies, r.dut_vtep, own) if c.idst == mac and c.vni == VNI])
            to_other = len(vxlan_to(copies, r.dut_vtep)) - to_own
            flooded = member_flood(r, copies, tx)
            raw = raw_on_uplinks(r, copies)
            results[mac] = "to own VTEP {}: {}, elsewhere VxLAN: {}, flooded: {}, raw: {}".format(
                own, to_own, to_other, flooded, raw)
            if not (delivered(to_own) and to_other == 0 and flooded == 0 and raw == 0):
                bad.append(mac)
            logger.info("%s -> %s", mac, results[mac])
        assert not bad, ("two VTEPs over one underlay ({} created first): {}. Both MACs to the VTEP created "
                         "last is the per-tunnel binding defect.".format(vteps[0], results))


# --------------------------------------------------------------------------------------------------------------------
# VLAN IDs 3073+
# --------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("order", ["vlans_after_rifs", "rif_after_vlans"])
def test_high_vid_vlans(rig, ptfadapter, order):
    """VLANs 3073+ on a VxLAN-enabled switch are programmed and forward, whichever of them and a router interface came
    first.

    The failure this guards is a VLAN that `config vlan add` accepts but that never reaches ASIC_DB (a ghost), when
    VLAN IDs and router interfaces compete for the same hardware resources. vlans_after_rifs creates the VLANs on a
    DUT that already has its RIFs; rif_after_vlans removes one PortChannel's addresses first (its RIF goes), creates
    the VLANs, then restores the addresses, so a RIF is allocated while the high VLANs exist.
    VID 3000 is the instrument control; VID 3500 is never configured and must not forward: no copy of it may reach
    any PTF port, in any form.
    """
    r, duthost = rig, rig.duthost
    vids = [CTRL_VID] + HIGH_VIDS
    pc, addrs, neighbors = None, [], []
    if order == "rif_after_vlans":
        cycled = rif_to_cycle(r.mg, [r.inj_port], r.borrowed)
        if not cycled:
            pytest.fail("no PortChannel RIF with BGP neighbors to cycle")
        pc, addrs, neighbors = cycled
    rif0 = asic_count(duthost, "ROUTER_INTERFACE")
    vlan0, member0 = asic_vlan_ids(duthost), asic_count(duthost, "VLAN_MEMBER")
    created, members, removed, unrestored = [], [], [], []

    def _cleanup():
        # Flush the learned MACs while the members exist: deleting a member first makes fdbsyncd's kernel delete of
        # each MAC fail (ERR "updateLocalMac: Failed cmd: bridge fdb del"), because the kernel already dropped it.
        if members:
            for vid in created:
                flush_fdb(duthost, "VLAN", str(vid))
            wait_until(30, 5, 0, lambda: not any(
                "02:4C:33" in line.upper() for line in sh(duthost, "show mac", check=False).splitlines()) and
                sh(duthost, "sudo /sbin/bridge fdb show | grep -ci '02:4c:33'; true", check=False).strip() in ("", "0"))
        for vid, port in members:
            sh(duthost, "sudo config vlan member del {} {}".format(vid, port), check=False)
        time.sleep(3 if members else 0)
        for vid in created:
            sh(duthost, "sudo config vlan del {}".format(vid), check=False)
        for a in removed:
            sh(duthost, "sudo config interface ip add {} {}".format(pc, a), check=False)
        if not wait_until(60, 5, 0, lambda: asic_vlan_ids(duthost) == vlan0):
            unrestored.append("ASIC_DB VLANs {} -> {}".format(sorted(vlan0), sorted(asic_vlan_ids(duthost))))
        if pc and not wait_until(180, 5, 0, lambda: duthost.check_bgp_session_state(neighbors)):
            unrestored.append("BGP to {} over {} not re-established".format(neighbors, pc))
        if unrestored:
            logger.error("high-VID cleanup did not restore the DUT: %s", unrestored)

    try:
        if pc:
            for a in addrs:
                sh(duthost, "sudo config interface ip remove {} {}".format(pc, a))
                removed.append(a)
            wait_for(60, 2, lambda: asic_count(duthost, "ROUTER_INTERFACE") == rif0 - 1,
                     "the {} RIF to go".format(pc))
        for vid in vids:
            sh(duthost, "sudo config vlan add {}".format(vid))
            created.append(vid)
        if not wait_until(45, 5, 0, lambda: set(vids) <= asic_vlan_ids(duthost)):
            ghosts = sorted(set(vids) - asic_vlan_ids(duthost))
            pytest.fail("VLANs {} are configured but not in ASIC_DB (ghosts). Members are not added to a "
                        "ghost.".format(ghosts))
        if pc:
            for a in removed[:]:
                sh(duthost, "sudo config interface ip add {} {}".format(pc, a))
                removed.remove(a)
            wait_for(60, 2, lambda: asic_count(duthost, "ROUTER_INTERFACE") == rif0,
                     "the {} RIF to come back".format(pc))
            wait_for(180, 5, lambda: duthost.check_bgp_session_state(neighbors),
                     "BGP to {} over the re-created {} RIF".format(neighbors, pc))
        for vid in vids:
            for port in (r.h1, r.h2):
                sh(duthost, "sudo config vlan member add {} {}".format(vid, port))
                members.append((vid, port))
        wait_for(60, 2, lambda: asic_count(duthost, "VLAN_MEMBER") >= member0 + 2 * len(vids),
                 "the {} high-VID members in ASIC_DB".format(2 * len(vids)))
        time.sleep(5)

        results, bad = {}, []
        for vid in vids + [NEG_VID]:
            per = []
            for src, dst in ((r.h1, r.h2), (r.h2, r.h1)):
                t = tag("v{}{}".format(vid, src[-1]))
                sa = "02:4c:33:{:02x}:{:02x}:{:02x}".format(vid >> 8, vid & 0xff, r.port[src] & 0xff)

                def send(t=t, sa=sa, src=src, vid=vid):
                    return send_and_count(ptfadapter, r.port[src], probe_frame(t, BROADCAST_MAC, sa, vlan=vid),
                                          N_VID, t)
                if r.tagged_at_ptf:
                    copies = send()
                else:
                    tx, copies = members_tx(r, send, [dst])
                at_dst, problems = vid_reading(copies, r.port[dst], r.p0, vid, vid != NEG_VID)
                per.append(at_dst if r.tagged_at_ptf else tx[dst])
                bad += problems
            results[vid] = per
            # a TX counter also counts a probe the testbed delivered twice and other traffic on the port, so it
            # separates forwarding (about N_VID or more) from not forwarding, and does not bound the count above
            lo = N_VID * 9 // 10
            if vid == NEG_VID:
                ok = all(n == 0 for n in per) if r.tagged_at_ptf else all(n < lo for n in per)
            else:
                ok = all(lo <= n <= N_VID for n in per) if r.tagged_at_ptf else all(n >= lo for n in per)
            if not ok:
                bad.append(vid)
        assert not bad, ("high VLAN IDs ({}): per VID (h1->h2, h2->h1) of {} frames{}: {}; failing: {}. VID {} is the "
                         "control, {} must read 0.".format(
                             order, N_VID, "" if r.tagged_at_ptf else " (DUT TX counters: {})".format(r.tagged_why),
                             results, bad, CTRL_VID, NEG_VID))
    finally:
        _cleanup()
    # reached only when the case itself passed; a failure above keeps its own message and the cleanup is logged
    if unrestored:
        pytest.fail("cleanup did not restore the DUT: {}".format("; ".join(unrestored)))


# --------------------------------------------------------------------------------------------------------------------
# station move
# --------------------------------------------------------------------------------------------------------------------
MOVED_MAC = "02:4c:35:00:00:01"       # the station that moves
CTRL_MAC_H2 = "02:4c:35:00:00:02"     # control station on H2
CTRL_MAC_H1 = "02:4c:35:00:00:03"     # control station on H1
SENDER_MAC = "02:4c:35:00:00:04"      # source of the probes from H0
FLUSH_WAIT_S = 30                     # bound on orchagent running a flush request


def where_does(r, ptfadapter, mac, name):
    """Known unicast to mac from the untagged member: how many copies the DUT transmitted on each tagged member.

    Read from the DUT's per-port unicast TX counters, not from the PTF: on a testbed, a unicast the DUT floods to
    both tagged members can reach only one PTF port (the one that last sourced that MAC), so a PTF capture can
    read a flood as held. An idle window of the same length measures other unicast on those ports, and is
    subtracted. A virtual switch has no fanout and does not feed these counters: there the PTF copies are read.
    """
    t = tag("sm" + name)
    if r.vs:
        copies = send_and_count(ptfadapter, r.p0, probe_frame(t, mac, SENDER_MAC), N, t)
        return native_on(copies, r.p1), native_on(copies, r.p2)
    ports = [r.h1, r.h2]
    d, took, copies = settled_delta(r.duthost, ports, 20, lambda: send_and_count(
        ptfadapter, r.p0, probe_frame(t, mac, SENDER_MAC), N, t))
    idle, _, _ = settled_delta(r.duthost, ports, took + 2, lambda: time.sleep(max(0.0, took - 3)))
    if max(d) < GOOD:
        raise AssertionError("{}: the DUT unicast TX counters of {} moved by {} for {} frames sent: the counters are "
                             "not polling (or the frames were lost), so the hardware cannot be read".format(
                                 t, ports, d, N))
    res = (max(0, d[0] - idle[0]), max(0, d[1] - idle[1]))
    logger.info("%s: DUT unicast TX %s +%d, %s +%d (idle +%d/+%d; PTF saw %d / %d)", t, r.h1, d[0], r.h2, d[1],
                idle[0], idle[1], native_on(copies, r.p1), native_on(copies, r.p2))
    return res


def reading(counts, r):
    """flooded / only <member> from TX counter deltas; up to TX_SLACK packets of other unicast are tolerated."""
    a, b = counts
    if tx_delivered(a) and tx_delivered(b):
        return "flooded"
    if tx_delivered(a) and b <= TX_SLACK:
        return "only " + r.h1
    if tx_delivered(b) and a <= TX_SLACK:
        return "only " + r.h2
    return "unreadable {}".format(counts)


def station_move_cleanup(r, strict):
    """Flush the case's MACs out of the VLAN and check `show mac` no longer holds them, so the next case starts on an
    empty VLAN with no flush request still queued. strict: a clean-up that fails fails the case; otherwise (the case
    has already failed, and that failure is the one to report) it is logged."""
    macs = [MOVED_MAC, CTRL_MAC_H1, CTRL_MAC_H2]
    err = None
    try:
        flush_vlan_fdb(r.duthost, VLAN_ID, timeout=FLUSH_WAIT_S)
    except (AssertionError, RuntimeError) as e:
        err = e
    if r.vs:
        kernel_fdb_forget(r.duthost, VLAN_ID, [MOVED_MAC])
    if err is None:
        try:
            want = {m.lower() for m in macs}
            wait_for(20, 1, lambda: not want & set(sh(r.duthost, "show mac -v {}".format(VLAN_ID)).lower().split()),
                     "{} flushed from Vlan{} in show mac".format(macs, VLAN_ID))
        except AssertionError as e:
            err = e
    time.sleep(3)
    if err is not None:
        if strict:
            raise AssertionError("station move clean-up: {}".format(err))
        logger.error("station move clean-up after a failed case: %s", err)


def flush_port(r, port, gone):
    flush_fdb(r.duthost, "PORT", port)
    wait_for(20, 1, lambda: all(fdb_port(r.duthost, VLAN_ID, m) is None for m in gone),
             "{} flushed from {} in show mac".format(gone, port))
    time.sleep(2)


@pytest.mark.parametrize("path", ["move", "round_trip"])
def test_station_move_updates_fdb_record(rig, ptfadapter, loganalyzer, path):
    """After a station move, a per-port flush of the MAC's current port removes it from hardware.

    With L2 VxLAN on, a per-port flush must remove every MAC that sits on the port, including one that moved there
    from another port. If the move is not tracked, the moved MAC survives the flush of its new port and keeps
    attracting its traffic (stale).
    Hardware is read through the DUT's unicast TX counters of the two members: unicast to a MAC the hardware still
    holds leaves on one port, unicast to a flushed MAC floods to both. A control MAC on the flushed port must flood
    afterwards (the flush reached hardware).

    On a virtual switch the kernel bridge is the dataplane and follows the move by itself, while the vs SAI reports
    no move: the case reads that the kernel and the forwarding follow the station, and leaves the flush of the moved
    FDB record to hardware.
    """
    r = rig
    if loganalyzer:
        loganalyzer[r.duthost.hostname].ignore_regex.extend(MOVE_DEL_LOG)
    flush_fdb(r.duthost, "VLAN", str(VLAN_ID), wait=FLUSH_WAIT_S)
    # orchagent logs the flush once the SAI call returns; the hardware delete may still be running then
    time.sleep(3)
    passed = False
    try:
        learn(r, ptfadapter, r.p1, r.h1, MOVED_MAC, vid=VLAN_ID)
        if r.vs:
            stops = [(r.p2, r.h2)] + ([(r.p1, r.h1)] if path == "round_trip" else [])
            for i, (p, h) in enumerate(stops):
                t = tag("smf{}".format(i))
                send_and_count(ptfadapter, p, probe_frame(t, BROADCAST_MAC, MOVED_MAC, vlan=VLAN_ID), 3, t)
                wait_for(20, 1, lambda: kernel_fdb_port(r.duthost, VLAN_ID, MOVED_MAC) == h,
                         "the kernel bridge to move {} to {}".format(MOVED_MAC, h))
                got = reading(where_does(r, ptfadapter, MOVED_MAC, "v{}".format(i)), r)
                assert got == "only " + h, "the dataplane did not follow the station move ({}, step {}) to {}: {}" \
                    .format(path, i, h, got)
            passed = True
            return
        if path == "move":
            learn(r, ptfadapter, r.p2, r.h2, CTRL_MAC_H2, vid=VLAN_ID)
            learn(r, ptfadapter, r.p2, r.h2, MOVED_MAC, vid=VLAN_ID)       # the station move
            pre = reading(where_does(r, ptfadapter, MOVED_MAC, "m0"), r)
            assert pre == "only " + r.h2, "hardware did not follow the station move to {}: {}".format(r.h2, pre)
            flush_port(r, r.h2, [CTRL_MAC_H2, MOVED_MAC])
            ctrl = reading(where_does(r, ptfadapter, CTRL_MAC_H2, "m1"), r)
            assert ctrl == "flooded", ("control: the H2 control MAC after the {} flush reads '{}', so the flush did "
                                       "not reach hardware and the moved MAC cannot be read".format(r.h2, ctrl))
            subj = reading(where_does(r, ptfadapter, MOVED_MAC, "m2"), r)
            assert subj == "flooded", ("station move: the moved MAC moved {} -> {} survives the {} flush in hardware "
                                       "('{}'): the FDB record did not follow the move".format(
                                           r.h1, r.h2, r.h2, subj))
        else:
            learn(r, ptfadapter, r.p2, r.h2, MOVED_MAC, vid=VLAN_ID)       # move to h2
            learn(r, ptfadapter, r.p2, r.h2, CTRL_MAC_H2, vid=VLAN_ID)     # control on h2
            learn(r, ptfadapter, r.p1, r.h1, MOVED_MAC, vid=VLAN_ID)       # and back to h1
            learn(r, ptfadapter, r.p1, r.h1, CTRL_MAC_H1, vid=VLAN_ID)     # control on h1
            pre = reading(where_does(r, ptfadapter, MOVED_MAC, "r0"), r)
            assert pre == "only " + r.h1, "hardware did not follow the moved MAC back to {}: {}".format(r.h1, pre)
            flush_port(r, r.h2, [CTRL_MAC_H2])
            ctrl2 = reading(where_does(r, ptfadapter, CTRL_MAC_H2, "rY"), r)
            assert ctrl2 == "flooded", "control: the H2 control MAC after the {} flush reads '{}'".format(
                r.h2, ctrl2)
            kept = reading(where_does(r, ptfadapter, MOVED_MAC, "r1"), r)
            assert kept == "only " + r.h1, ("over-delete: a flush of {} removed the moved MAC, which sits on {} ('{}')"
                                            .format(r.h2, r.h1, kept))
            flush_port(r, r.h1, [MOVED_MAC, CTRL_MAC_H1])
            ctrl = reading(where_does(r, ptfadapter, CTRL_MAC_H1, "r2"), r)
            assert ctrl == "flooded", "control: the H1 control MAC after the {} flush reads '{}'".format(r.h1, ctrl)
            subj = reading(where_does(r, ptfadapter, MOVED_MAC, "r3"), r)
            assert subj == "flooded", ("station move round trip: the moved MAC ({} -> {} -> {}) survives the {} "
                                       "flush in hardware ('{}')".format(r.h1, r.h2, r.h1, r.h1, subj))
        passed = True
    finally:
        station_move_cleanup(r, strict=passed)
