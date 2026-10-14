"""L2 EVPN control plane + SAI: remote FRR leaves drive the DUT's VxLAN state, the PTF measures the dataplane.

Remote VTEPs and MACs written straight into APPL_DB never exercise the shipped path: BGP EVPN -> zebra -> kernel ->
fdbsyncd -> APPL_DB -> orchagent -> SAI -> ASIC. This module does, with real BGP EVPN peers; test_vxlan_l2.py keeps
the few sequences the control plane cannot produce. Every case asserts ASIC_DB state and per-port frame counts; FRR
and APPL_DB are read only as gates (control-plane correctness itself is not what this module checks).

Rig (module fixture), topology t0 or single-ASIC t2 or lt2, on the first VLAN with four oper-up members (e.g.
Vlan1000; on a t2, neighbor-facing ports that vxlan_l2_helpers.access_ports borrows and restores):
  * Two members become routed ports to two remote leaves (l1, l2): FRR containers on the test server, each joined to
    its port's PTF interface by a tc redirect (files/vxlan_evpn_l2_leaves.sh), eBGP ipv4 + l2vpn evpn to the DUT.
    The PTF still sees every frame the DUT sends to a leaf, and can inject VxLAN toward the DUT as that leaf.
  * The other two are the DUT's hosts: H0 untagged in VLAN A and tagged in VLAN B; H1 untagged in VLAN B and tagged
    in VLAN A. Every frame the PTF sends enters on H0, on H1 (802.1Q-tagged in VLAN A) or on a leaf port, and the
    fixture first checks that the DUT receives each frame sent on those ports exactly once.
  * DUT: VTEP vtep1 on Loopback0, NVO nvo1, VLAN A <-> VNI A, VLAN B <-> VNI B, BGP to the leaves via vtysh.
  * l1 serves VNI A and VNI B, l2 serves VNI A only, so the flood set differs per VNI.

Cases:
  test_type3_flood_set_per_vni       Type-3 -> ASIC flood set per VNI; BUM reaches each remote VTEP once per frame,
                                     per VNI; a withdrawn Type-3 leaves the flood set and its BUM stops
  test_type2_remote_mac              Type-2 -> ASIC FDB entry on the right tunnel; known unicast both ways;
                                     withdraw removes the entry and the traffic floods again
  test_local_mac_used_by_leaf        BUM a leaf floods to the DUT is delivered locally and never re-encapsulated (split
                                     horizon); a MAC the DUT learns is installed on the leaf, which then sends to it as
                                     known unicast (not flooded) and the DUT delivers it on the learning port; the
                                     learning port leaving the VLAN withdraws it at the leaves, rejoining restores it
  test_sticky_remote_mac_not_displaced_by_local_learn
                                     a MAC a leaf advertises as static (sticky) stays on the leaf's tunnel when H0
                                     sources frames from it
  test_remote_mac_replaced_by_local  a remote MAC that H0 then sources moves to H0 (MAC mobility: the leaf takes the
                                     DUT's route), is forwarded there only, and behaves as a dynamic local MAC
  test_local_mac_replaced_by_remote[dynamic|sticky]
                                     a MAC learned on H0 that a leaf then learns (or adds static) moves to the leaf's
                                     tunnel with the same FDB attributes as any remote MAC of the leaf, is encapsulated
                                     there only, and floods once the leaf withdraws it (sticky: the leaf's FRR must
                                     keep the sticky flag once the MAC Mobility sequence is above 0)
  test_vxlan_udp_port_set_and_deleted
                                     SWITCH_TABLE vxlan_port / vxlan_router_mac set: encap and decap use the port;
                                     the key deleted: the switch's VxLAN attributes go back to their defaults
  test_swss_warm_restart_keeps_evpn  swss warm restart: flood set and remote MACs kept, syncd compareViews 0 ASIC
                                     operations, BUM and unicast still delivered (sonic-net/sonic-swss#4951)
  test_neigh_resolve_after_mac_age_out
                                     an SVI neighbour whose MAC ages out is re-resolved, and once the host answers the
                                     NEIGH_RESOLVE_TABLE request is gone; a resolve request for a neighbour the kernel
                                     has resolved is probed at most twice in 45 s, not retried
  test_remote_vni_withdraw_after_refused_vni
                                     after orchagent refused a remote VNI (VNI 16777215, accepted by the CLI), a Type-3
                                     withdraw of another leaf still removes it from the flood set
Dataplane cases (the remote state comes from the leaves; frames are counted per PTF port by a payload tag):
  test_l2_encap_outer_header[unicast|flood]
                                     the outer header of every copy: programmed TTL whatever the inner TTL, no
                                     fragmentation, valid checksums, UDP port 4789, VXLAN I flag and VNI only, and the
                                     inner frame bit for bit (1514 bytes, IPv6, non-IP, from the tagged member)
  test_l2_encap_outer_dscp_ecn[unicast|flood]
                                     outer DSCP and ECN follow the tunnels' modes (SAI defaults: both copied from an
                                     IP inner frame, else 0)
  test_l2_encap_udp_source_port[unicast|flood]
                                     the UDP source port is one value per inner flow and differs across flows
  test_l2_decap_inner_frame_unchanged
                                     a decapsulated frame is delivered as sent but for its DSCP and TTL, each the
                                     inner value or, in uniform decap mode, the outer one; the ECN is the inner one
  test_l2_decap_rejects[unmapped_vni|other_destination]
                                     VxLAN in a VNI with no VLAN, or addressed to another VTEP, is not delivered to
                                     the VLAN (the other VTEP's frame is routed on to it, still encapsulated)
  test_tagged_member_keeps_tag[local_bum|decap_bum|decap_unicast]
                                     the tagged member keeps the tag on local BUM, decapsulated BUM and decapsulated
                                     unicast

Tagged copies at the PTF: some fanouts drop C-tagged frames from the DUT toward the test server. The rig measures this
once, with a plain broadcast from H0 in VLAN A before the VNI map: when the DUT transmits the tagged copy to H1 (port
TX counters) but the PTF does not see it, the dataplane cases read H1 from its DUT TX counters instead.

On a virtual switch (asic_type vs) the kernel is the dataplane: every case runs, with its APPL_DB, ASIC_DB and
traffic readings, but the decap gates that read "the kernel did not forward this" are not applied, the SWITCH_TABLE
case reads ASIC_DB only (the kernel VxLAN netdevs keep UDP port 4789), the outer header case does not compare the
outer TTL with the tunnels' (the kernel netdev sets its own), and the outer DSCP/ECN case reads only the modes
programmed on the tunnels in ASIC_DB (the kernel netdev, not those tunnels, encapsulates).

The leaves run the stock FRR release image (vxlan_evpn_l2_helpers.DEFAULT_LEAF_IMAGES, the first one the test server
has, else the first it can pull; VXLAN_EVPN_LEAF_IMAGE replaces the list). The module skips when the test server has
none of them and cannot pull one. FRR bgpd without https://github.com/FRRouting/frr/pull/23629 advertises a sticky MAC
without the sticky flag once its MAC Mobility sequence number is above 0, so test_local_mac_replaced_by_remote[sticky]
fails with a leaf that lacks that fix, and says so.

On a DUT with an external PHY (gbsyncd), the swss warm restart case fails if orchagent latches a failed gearbox port
re-create at the warm start, which happens until gbsyncd supports a warm start of swss (sonic-net/sonic-swss#3465 and
sonic-net/sonic-sairedis#1499); its message says whether the EVPN checks passed before that.
"""

import ast
import contextlib
import logging
import re
import time
from types import SimpleNamespace

import ptf.testutils as testutils
import pytest
from scapy.all import ARP, Ether

from tests.common.utilities import get_inventory_files, wait_until
from tests.vxlan.vxlan_l2_helpers import (
    BROADCAST_MAC,
    GOOD,
    KNOWN_HARMLESS_LOG,
    MOVE_DEL_LOG,
    N,
    TX_SLACK,
    TX_UCAST,
    VTEP_NAME,
    VXLAN_UDP_PORT,
    AsicView,
    Steps,
    access_ports,
    asic_count,
    capture,
    collect,
    counter_poll_s,
    db_hget,
    db_keys,
    delivered,
    fdb_port,
    flow_frame,
    flush_fdb,
    inner_tos,
    kernel_fdb_forget,
    kernel_fdb_port,
    kernel_path,
    kernel_rx_packets,
    kernel_vxlan_netdev,
    learn_mac,
    log_clean,
    make_tagger,
    member_delivered,
    member_flood,
    native_on,
    orch_health,
    parse_copy,
    port_counters,
    probe_frame,
    probe_tagged_path,
    raw_payloads,
    remote_fdb_dip,
    send_and_count,
    send_and_read_outer,
    sh,
    summarize,
    swss_apply,
    tx_delivered,
    vxlan_encap_attrs,
    vxlan_frame,
    vxlan_to,
    wait_for,
    wait_state,
)
from tests.vxlan.vxlan_evpn_l2_helpers import (
    STICKY_SEQ_FIX,
    Leaf,
    Leaves,
    RigBuild,
    appl_remote_mac_vtep,
    appl_remote_vnis,
    asic_flood_members,
    assert_clean_start,
    check_ingress_once,
    check_leaf_vteps_unrouted,
    count_after,
    dut_bgp_add_commands,
    dut_has_advertise_all_vni,
    evpn_peer_established,
    pick_rig_ports,
    received_mac_mobility,
    resolve_leaf_image,
    rig_preflight,
    tunnel_bridge_port_learning,
    vtysh,
)
from tests.vxlan.vxlan_swss_warm_restart_helpers import (
    GEARBOX_WARM_RESTART_LOG,
    SWSS_WARM_RESTART_LOG,
    cold_restart_swss,
    has_gearbox,
    swss_warm_restart,
)

pytestmark = [
    pytest.mark.topology("t0", "t2", "lt2"),
]

logger = logging.getLogger(__name__)

VLAN_A, VLAN_B = 2100, 2101
VNI_A, VNI_B = 12100, 12101
VLAN_A_NAME, VLAN_B_NAME = "Vlan{}".format(VLAN_A), "Vlan{}".format(VLAN_B)
RT_ASN = 65000
# name, ASN, VTEP, leaf /31 address, DUT /31 address, (VLAN, VNI) served
LEAF_PLAN = [
    ("l1", 65201, "10.255.91.1", "10.99.0.1", "10.99.0.0", [(VLAN_A, VNI_A), (VLAN_B, VNI_B)]),
    ("l2", 65203, "10.255.92.1", "10.99.0.3", "10.99.0.2", [(VLAN_A, VNI_A)]),
]
MAC_R1, MAC_R2 = "02:4c:45:a1:00:01", "02:4c:45:a2:00:01"   # remote hosts in VNI A behind l1 / l2 (Type-2)
MAC_R1_PEER = "02:4c:45:a1:00:02"                           # another host behind l1, never advertised
MAC_L1_HOST = "02:4c:45:a1:00:09"                           # source of frames l1's own host sends
MAC_UNKNOWN = "02:4c:45:ff:00:01"                           # never learned or advertised anywhere
INJ_OUTER_SMAC = "02:4c:45:ee:00:01"                        # outer source MAC of VxLAN the PTF injects

# MACs that change sides between H0 and l1, one per case (row), so that no MAC moves often enough to trip EVPN
# duplicate address detection (5 moves in 180 s by default)
MAC_STICKY, MAC_TO_LOCAL = "02:4c:45:a1:00:6a", "02:4c:45:a1:00:6c"
MAC_TO_REMOTE = {"dynamic": "02:4c:45:a1:00:6d", "sticky": "02:4c:45:a1:00:6e"}
MAC_M_CTRL = "02:4c:45:a1:00:6b"                           # a MAC l1 advertises with no local history (control)
H1_SRC = "02:4c:45:00:00:91"                               # source of the probes H1 sends

CONVERGE = 120             # seconds for BGP / EVPN state to settle
TX_BUM = ("SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS",)

tag = make_tagger("VXEV")


# --------------------------------------------------------------------------------------------------------------------
# rig
# --------------------------------------------------------------------------------------------------------------------
def our_flood_set(duthost):
    """The rig VLANs' flood members, sorted, duplicates kept (compare against sorted(want))."""
    return [p for p in asic_flood_members(duthost) if p[0] in (VLAN_A, VLAN_B)]


def wait_flood(r, want, timeout, when):
    wait_state(timeout, 3, lambda: our_flood_set(r.duthost) == sorted(want),
               "ASIC flood set == {} {}".format(sorted(want), when), lambda: sorted(our_flood_set(r.duthost)))


@pytest.fixture(scope="module")
def access(duthost, tbinfo, request):
    with access_ports(duthost, tbinfo, request, need=4, want=4) as a:
        yield a


@pytest.fixture(scope="module")
def evpn_rig(duthost, tbinfo, ptfadapter, vmhost, ansible_adhoc, request):
    pre = rig_preflight(vmhost, ansible_adhoc, get_inventory_files(request))
    # after the preflight, so a testbed without a test server borrows no ports
    pick = pick_rig_ports(duthost, request.getfixturevalue("access"))
    idx, ports = pick.idx, pick.ports
    h0, h1 = ports[0], ports[1]
    leaves = [Leaf(name, "eth{}".format(idx[port]), idx[port], port, asn, vtep, ip, dut_ip, vv)
              for (name, asn, vtep, ip, dut_ip, vv), port in zip(LEAF_PLAN, ports[2:])]
    check_leaf_vteps_unrouted(duthost, leaves)
    assert_clean_start(duthost, leaves, (VLAN_A_NAME, VLAN_B_NAME), (VNI_A, VNI_B))
    check_ingress_once(duthost, ptfadapter, {p: idx[p] for p in ports}, ports, tag("rx"))

    group = tbinfo["group-name"]
    lv = Leaves(pre.server, "ptf_{}".format(group), pre.image, leaves, pick.peer_asn, pick.lo, RT_ASN,
                re.sub(r"[^A-Za-z0-9_.-]", "_", group))
    r = SimpleNamespace(
        duthost=duthost, leaves=lv, l1=leaves[0], l2=leaves[1], h0=h0, h1=h1, p_h0=idx[h0], p_h1=idx[h1],
        dut_vtep=pick.lo, router_mac=duthost.facts["router_mac"],
        expect_flood={(VLAN_A, leaves[0].vtep), (VLAN_A, leaves[1].vtep), (VLAN_B, leaves[0].vtep)}, kvx=None,
        dut_asn=pick.dut_asn, all_leaves=leaves, added_aav=None, vs=duthost.facts.get("asic_type") == "vs",
        tagged_hosts=[h1], port={h0: idx[h0], h1: idx[h1]}, canary=None, tagged_at_ptf=True, tagged_why="", rb=None,
        image="")
    lv.install()
    try:
        # before the rig changes the DUT: an image that cannot be had is a missing test-server prerequisite
        image_used = r.image = resolve_leaf_image(lv)
        rb = RigBuild(request, duthost, pick, leaves, lv, RT_ASN, ((VLAN_A, VNI_A), (VLAN_B, VNI_B)))
        r.rb = rb
        added_aav = r.added_aav = not dut_has_advertise_all_vni(duthost)
    except BaseException:
        lv.remove_files()   # nothing on the DUT yet, so no teardown runs
        raise
    logger.info("EVPN rig: base %s, H0 %s (ptf %s), H1 %s (ptf %s), leaves %s, DUT VTEP %s AS %s, image %s, "
                "ASIC_DB baseline %s", pick.base_vlan, h0, r.p_h0, h1, r.p_h1, leaves, r.dut_vtep, pick.dut_asn,
                image_used, rb.base)

    raw_payloads(ptfadapter)
    try:
        with log_clean(request, duthost, "setup"):
            rb.ports_out_of_base()
            rb.leaf_ips()
            rb.vlans()
            rb.member(VLAN_A, h0, True)
            rb.member(VLAN_B, h1, True)
            rb.member(VLAN_A, h1, False)
            rb.member(VLAN_B, h0, False)
            for name in (VLAN_A_NAME, VLAN_B_NAME):
                key = "VLAN_MEMBER_TABLE:{}:*".format(name)
                wait_for(60, 2, lambda k=key: len(db_keys(duthost, "APPL_DB", k)) == 2,
                         "2 members of {} in APPL_DB".format(name))
            # the four hosts left the base VLAN and joined the rig VLANs: the same member count
            wait_for(60, 2, lambda: asic_count(duthost, "VLAN_MEMBER") == rb.base["VLAN_MEMBER"],
                     "the rig VLANs' members in ASIC_DB")
            if not r.vs:     # a virtual testbed has no fanout between the DUT and the PTF
                r.tagged_at_ptf, r.tagged_why = probe_tagged_path(r, ptfadapter, r.p_h0, VLAN_A, tag("ctag"),
                                                                  "02:4c:45:00:00:70")
            rb.vxlan()
            rb.wait_connected()
            rb.bgp(added_aav)
            rb.leaves_up()
            rb.converge(CONVERGE)
            time.sleep(5)
        r.kvx = kernel_vxlan_netdev(duthost, VNI_A)
        if r.kvx is None or kernel_rx_packets(duthost, r.kvx) is None:
            pytest.fail("no readable kernel VxLAN netdev for VNI {}: the hardware-termination gate would be "
                        "off".format(VNI_A))
        logger.info("rig up; kernel VxLAN netdev for VNI %s: %s", VNI_A, r.kvx)
        yield r
    finally:
        rb.teardown()


@pytest.fixture(autouse=True)
def arp_refresh_held(request):
    """No periodic ARP/ND refresh inside a case's counting windows (it adds frames to the hosts' TX counters)."""
    if "evpn_rig" in request.fixturenames:
        request.getfixturevalue("evpn_rig").rb.hold_arp_refresh()


@pytest.fixture(autouse=True)
def ignore_known_harmless(duthost, loganalyzer):
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(KNOWN_HARMLESS_LOG)
        if duthost.facts.get("asic_type") == "vs":
            # the virtual switch's FDB flush removes the kernel entry itself, before fdbsyncd deletes it; and the vs
            # SAI's own FDB table refuses a learn of a MAC SONiC programmed elsewhere and loses track of aged entries
            loganalyzer[duthost.hostname].ignore_regex.extend(MOVE_DEL_LOG + [
                (r".*ERR syncd#syncd: .*create_internal: create failed, object already exists, object type: "
                 r"SAI_OBJECT_TYPE_FDB_ENTRY.*"),
                r".*ERR syncd#syncd: .*remove_internal: not found SAI_OBJECT_TYPE_FDB_ENTRY.*",
                r".*ERR syncd#syncd: .*updateLocalDB: failed to (create|remove) fdb entry.*"])


# --------------------------------------------------------------------------------------------------------------------
# measurements
# --------------------------------------------------------------------------------------------------------------------
def bum_from(r, ptfadapter, name, src, vlan=None):
    """N broadcasts from H0 (802.1Q-tagged when vlan is given); returns the copies."""
    t = tag(name)
    return send_and_count(ptfadapter, r.p_h0, probe_frame(t, BROADCAST_MAC, src, vlan=vlan), N, t)


def per_leaf(r, copies, vni):
    """DUT-emitted VxLAN copies per leaf (on the leaf's PTF port, from the DUT's VTEP, to the leaf's VTEP, in vni)."""
    return {lf.name: len(vxlan_to(copies, r.dut_vtep, lf.vtep, vni, port=lf.ptf_port)) for lf in (r.l1, r.l2)}


def dut_vxlan_other_vni(r, copies, vni):
    return len([c for c in vxlan_to(copies, r.dut_vtep) if c.vni != vni])


def learn_on_h0(r, ptfadapter, mac):
    """Have the DUT learn mac on H0 in VLAN A (untagged)."""
    learn_mac(ptfadapter, r.duthost, r.p_h0, r.h0, VLAN_A, mac, tag("learn"))


def kernel_gate(r, before, sent, what):
    """The decap stayed in hardware; on a virtual switch the kernel is the dataplane, so nothing to read."""
    if r.vs:
        return
    why = kernel_path(r.duthost, r.kvx, before, sent)
    assert not why, "{}: {}".format(what, why)


def leaf_send_and_count(r, ptfadapter, leaf, dst, t, stat=TX_UCAST):
    """leaf's own host sends N frames to dst (untagged: the leaf's first VLAN).

    Returns (PTF copies, DUT TX delta per host port of the stat counters: unicast unless stat says otherwise). A
    virtual switch does not feed its port counters, and has no fanout that could hide a copy from the PTF, so there
    the second item is the PTF copies per host port.
    """
    ports = [r.h0, r.h1]
    if r.vs:
        copies = count_after(ptfadapter, lambda: r.leaves.send(leaf.name, dst, MAC_L1_HOST, N, t), t)
        return copies, {p: native_on(copies, r.port[p]) for p in ports}
    before = kernel_rx_packets(r.duthost, r.kvx)
    tx0 = port_counters(r.duthost, ports, stat)
    copies = count_after(ptfadapter, lambda: r.leaves.send(leaf.name, dst, MAC_L1_HOST, N, t), t)
    time.sleep(2 * counter_poll_s(r.duthost) + 0.5)
    tx1 = port_counters(r.duthost, ports, stat)
    kernel_gate(r, before, N, "decap of {}'s frames".format(leaf.name))
    return copies, {p: tx1[p] - tx0[p] for p in ports}


def add_remote_macs(r, macs):
    """macs: {mac: leaf}. Advertise each from its leaf (VLAN A) and wait for the ASIC FDB entry on its tunnel."""
    for mac, lf in macs.items():
        r.leaves.fdb("add", lf.name, mac, VLAN_A)
    for mac, lf in macs.items():
        wait_for(CONVERGE, 3, lambda: appl_remote_mac_vtep(r.duthost, VLAN_A_NAME, mac) == lf.vtep,
                 "APPL_DB VXLAN_FDB_TABLE {} -> {}".format(mac, lf.vtep))
        wait_state(60, 3, lambda: remote_fdb_dip(r.duthost, mac, VLAN_A) == lf.vtep,
                   "one ASIC_DB FDB entry for {} on the tunnel to {}".format(mac, lf.vtep),
                   lambda: AsicView(r.duthost).fdb(mac, VLAN_A))


def remove_remote_macs(r, macs):
    for mac, lf in macs.items():
        r.leaves.run("fdb", "del", lf.name, mac, VLAN_A, check=False)
    wait_for(CONVERGE, 3, lambda: not any(AsicView(r.duthost).fdb(m, VLAN_A) for m in macs),
             "ASIC_DB FDB entries for {} to go".format(sorted(macs)))


# --------------------------------------------------------------------------------------------------------------------
# cases
# --------------------------------------------------------------------------------------------------------------------
def test_type3_flood_set_per_vni(evpn_rig, ptfadapter):
    """Type-3 routes from two leaves build each VNI's ASIC flood set; BUM is replicated per VNI to exactly those.

    VNI A: l1 and l2. VNI B: l1 only. Withdrawing l2's Type-3 for VNI A (its VxLAN device down) removes l2 from
    VNI A's flood set and its BUM stops; bringing it back restores both.
    """
    r = evpn_rig
    d = r.duthost
    wait_flood(r, r.expect_flood, 60, "after the rig came up")

    copies = bum_from(r, ptfadapter, "t3A", "02:4c:45:00:00:31")
    got = per_leaf(r, copies, VNI_A)
    other = dut_vxlan_other_vni(r, copies, VNI_A)
    # the local copy to tagged H1 is reported, not asserted: tags are test_tagged_member_keeps_tag's reading
    local = native_on(copies, r.p_h1)
    assert delivered(got["l1"]) and delivered(got["l2"]) and other == 0, (
        "VLAN {} BUM from {} ({} frames): VNI {} copies per leaf {}, {} copies in another VNI ({} to {}). "
        "Copies: {}".format(VLAN_A, r.h0, N, VNI_A, got, other, local, r.h1, summarize(copies)))

    copies = bum_from(r, ptfadapter, "t3B", "02:4c:45:00:00:32", vlan=VLAN_B)
    got = per_leaf(r, copies, VNI_B)
    other = dut_vxlan_other_vni(r, copies, VNI_B)
    assert delivered(got["l1"]) and got["l2"] == 0 and other == 0, (
        "VLAN {} BUM from {} ({} frames): VNI {} copies per leaf {} (l2 serves no VNI {}), {} copies in another "
        "VNI ({} untagged to {}). Copies: {}".format(
            VLAN_B, r.h0, N, VNI_B, got, VNI_B, other, native_on(copies, r.p_h1, None), r.h1, summarize(copies)))

    gone = r.expect_flood - {(VLAN_A, r.l2.vtep)}
    restore = Steps("restoring {}'s Type-3".format(r.l2.name))

    def _cleanup():
        # restored even when the withdraw half fails, so the next case starts from the full flood set
        restore("vni up", lambda: r.leaves.vni("up", r.l2.name, VNI_A))
        restore("flood set", lambda: wait_flood(r, r.expect_flood, CONVERGE, "after {}'s Type-3 returns".format(
            r.l2.name)))

    try:
        r.leaves.vni("down", r.l2.name, VNI_A)
        wait_for(CONVERGE, 3, lambda: (VLAN_A_NAME, r.l2.vtep) not in appl_remote_vnis(d),
                 "APPL_DB to drop {}'s remote VNI {} after the withdraw".format(r.l2.name, VNI_A))
        wait_flood(r, gone, 60, "after {}'s Type-3 withdraw".format(r.l2.name))
        copies = bum_from(r, ptfadapter, "t3W", "02:4c:45:00:00:33")
        got = per_leaf(r, copies, VNI_A)
        assert delivered(got["l1"]) and got["l2"] == 0, (
            "after {}'s Type-3 withdraw, VLAN {} BUM ({} frames) per leaf {}: expected l1 only. Copies: {}".format(
                r.l2.name, VLAN_A, N, got, summarize(copies)))
    finally:
        _cleanup()
    restore.finish()
    copies = bum_from(r, ptfadapter, "t3R", "02:4c:45:00:00:34")
    got = per_leaf(r, copies, VNI_A)
    assert delivered(got["l1"]) and delivered(got["l2"]), (
        "after {}'s Type-3 returned, VLAN {} BUM ({} frames) per leaf {}. Copies: {}".format(
            r.l2.name, VLAN_A, N, got, summarize(copies)))


def test_type2_remote_mac(evpn_rig, ptfadapter):
    """A Type-2 MAC from each leaf becomes an ASIC FDB entry on that leaf's tunnel; unicast flows both ways.

    Encap: H0 -> each remote MAC reaches only its own leaf. Decap: the PTF, as l1, sends to a MAC learned on H0,
    which is delivered there only. Withdraw: l1's MAC leaves the ASIC and traffic to it floods to both leaves.
    """
    r = evpn_rig
    d = r.duthost
    macs = {MAC_R1: r.l1, MAC_R2: r.l2}
    restore = Steps("removing the remote MACs")

    def _cleanup():
        restore("remote MACs", lambda: remove_remote_macs(r, macs))

    try:
        add_remote_macs(r, macs)
        for mac, lf in macs.items():
            other = r.l2 if lf is r.l1 else r.l1
            t = tag("t2E" + lf.name)
            copies = send_and_count(ptfadapter, r.p_h0, probe_frame(t, mac, "02:4c:45:00:00:41"), N, t)
            mine = len(vxlan_to(copies, r.dut_vtep, lf.vtep, VNI_A, port=lf.ptf_port))
            theirs = len(vxlan_to(copies, r.dut_vtep, other.vtep))
            wrong = len(vxlan_to(copies, r.dut_vtep)) - mine - theirs
            assert delivered(mine) and theirs == 0 and wrong == 0, (
                "known unicast to {} (Type-2 from {}) from {} ({} frames): {} to {}, {} to {}, {} other VxLAN, "
                "{} on {}. Copies: {}".format(mac, lf.name, r.h0, N, mine, lf.name, theirs, other.name, wrong,
                                              native_on(copies, r.p_h1), r.h1, summarize(copies)))

        local = "02:4c:45:00:00:42"
        learn_on_h0(r, ptfadapter, local)
        t = tag("t2D")
        # inner source: a host behind l1 that l1 never advertised, so the withdraw below reads only MAC_R1's Type-2
        pkt = vxlan_frame(probe_frame(t, local, MAC_R1_PEER), r.router_mac, INJ_OUTER_SMAC, r.l1.vtep, r.dut_vtep,
                          VNI_A)
        before = kernel_rx_packets(d, r.kvx)
        time.sleep(2 * counter_poll_s(d) + 0.5)   # the learning frames above settle in the counters first
        tx0 = port_counters(d, [r.h1], TX_UCAST)
        copies = send_and_count(ptfadapter, r.l1.ptf_port, pkt, N, t)
        time.sleep(2 * counter_poll_s(d) + 0.5)
        # H1 is a tagged member of VLAN A, so a flood to it is read from its TX counter (C-tagged copies can be lost
        # between the DUT and the PTF)
        stray = port_counters(d, [r.h1], TX_UCAST)[r.h1] - tx0[r.h1]
        kernel_gate(r, before, N, "decap from {}".format(r.l1.name))
        got = native_on(copies, r.p_h0, None)
        emitted = len(vxlan_to(copies, r.dut_vtep))
        assert delivered(got) and stray <= TX_SLACK and emitted == 0, (
            "VxLAN from {} to {} learned on {} ({} frames): {} untagged on {}, DUT unicast TX {} on {}, {} DUT VxLAN "
            "copies. Copies: {}".format(r.l1.name, local, r.h0, N, got, r.h0, stray, r.h1, emitted,
                                        summarize(copies)))

        r.leaves.fdb("del", r.l1.name, MAC_R1, VLAN_A)
        wait_for(CONVERGE, 3, lambda: not appl_remote_mac_vtep(d, VLAN_A_NAME, MAC_R1),
                 "APPL_DB VXLAN_FDB_TABLE {} to go after the withdraw".format(MAC_R1))
        wait_state(60, 3, lambda: not AsicView(d).fdb(MAC_R1, VLAN_A),
                   "ASIC_DB FDB entry for {} to go after the withdraw".format(MAC_R1),
                   lambda: AsicView(d).fdb(MAC_R1, VLAN_A))
        assert remote_fdb_dip(d, MAC_R2, VLAN_A) == r.l2.vtep, (
            "withdrawing {} also disturbed {}: ASIC FDB now {}".format(MAC_R1, MAC_R2, AsicView(d).fdb(MAC_R2, VLAN_A)))
        t = tag("t2W")
        copies = send_and_count(ptfadapter, r.p_h0, probe_frame(t, MAC_R1, "02:4c:45:00:00:41"), N, t)
        got = per_leaf(r, copies, VNI_A)
        # the local copy on tagged H1 is reported, not asserted: tags are test_tagged_member_keeps_tag's reading
        assert delivered(got["l1"]) and delivered(got["l2"]), (
            "unicast to withdrawn {} ({} frames) must flood to both leaves: per leaf {}, {} on {}. Copies: "
            "{}".format(MAC_R1, N, got, native_on(copies, r.p_h1), r.h1, summarize(copies)))
    finally:
        _cleanup()
    restore.finish()


def test_local_mac_used_by_leaf(evpn_rig, ptfadapter):
    """A MAC the DUT learns on an access port is installed on the leaf, which then unicasts to it.

    Control first: the leaf's host sends to an unknown MAC, the leaf floods (to the DUT and to l2), and the DUT
    delivers the decapsulated copy on H0 and sends no VxLAN copy of it anywhere: no re-flood to l2 and no echo to l1
    (split horizon, with the flood list built from Type-3 routes). Then H0 sources MAC M; once l1's kernel points M
    at the DUT's VTEP, frames from l1's host to M reach H0 only, and l1 sends no copy to l2 (it used the Type-2
    instead of flooding). H0 then leaves VLAN A: both leaves remove M (the DUT withdrew its Type-2) and l1 floods
    frames to M again, none reaching H0. H0 rejoins and sources M again: the leaves point M at the DUT's VTEP and
    l1's frames to it reach H0 as known unicast.
    """
    r = evpn_rig
    d = r.duthost
    mac = "02:4c:45:00:00:51"
    restore = Steps("removing the leaf host's MAC")
    h0_out = False

    def _cleanup():
        if h0_out:
            restore("{} back in {}".format(r.h0, VLAN_A_NAME), lambda: sh(
                d, "sudo config vlan member add -u {} {}".format(VLAN_A, r.h0)))
        # l1 learned its own host's source MAC on its access port and advertised it
        r.leaves.run("fdb", "del", r.l1.name, MAC_L1_HOST, VLAN_A, check=False)
        flush_fdb(d, "VLAN", str(VLAN_A))
        restore("leaf host MAC", lambda: wait_for(CONVERGE, 3, lambda: not AsicView(d).fdb(MAC_L1_HOST, VLAN_A),
                                                  "ASIC FDB for {} to go".format(MAC_L1_HOST)))

    try:
        for kind, dst, stat in (("unknown unicast", MAC_UNKNOWN, TX_UCAST), ("broadcast", BROADCAST_MAC, TX_BUM)):
            t = tag("lcC" + kind[0])
            copies, tx = leaf_send_and_count(r, ptfadapter, r.l1, dst, t, stat)
            flood_l2 = len(vxlan_to(copies, r.l1.vtep, r.l2.vtep, VNI_A, port=r.l2.ptf_port))
            # the DUT floods the decapsulated BUM; its delivery is read from the DUT's TX counter
            assert delivered(flood_l2) and GOOD <= tx[r.h0], (
                "control: {}'s host {} to {} ({} frames): {} flooded by {} to {}; DUT TX {} (PTF saw {} at {}, {} at "
                "{}). The leaf sender or the capture is not working, so the reading below is void. Copies: "
                "{}".format(r.l1.name, kind, dst, N, flood_l2, r.l1.name, r.l2.name, tx, native_on(copies, r.p_h0),
                            r.h0, native_on(copies, r.p_h1), r.h1, summarize(copies)))
            reflood = {lf.name: len(vxlan_to(copies, r.dut_vtep, lf.vtep, port=lf.ptf_port)) for lf in (r.l1, r.l2)}
            emitted = len(vxlan_to(copies, r.dut_vtep))
            assert emitted == 0, (
                "split horizon: {}'s {} to {}, decapsulated by the DUT, was sent back out as VxLAN {} times (per "
                "leaf {}: to l1 is an echo, to l2 a re-flood). Copies: {}".format(
                    r.l1.name, kind, dst, emitted, reflood, summarize(copies)))

        learn_on_h0(r, ptfadapter, mac)
        entries = AsicView(d).fdb(mac, VLAN_A)
        assert len(entries) == 1 and entries[0].bp_type == "SAI_BRIDGE_PORT_TYPE_PORT" and entries[0].port == r.h0, (
            "{} learned on {}: ASIC_DB FDB {}".format(mac, r.h0, entries))
        for lf in (r.l1, r.l2):
            wait_for(CONVERGE, 3, lambda: r.leaves.remote_mac_dst(lf.name, mac) == r.dut_vtep,
                     "{} to install {} toward the DUT's VTEP {} (the DUT's Type-2)".format(lf.name, mac, r.dut_vtep))

        t = tag("lcU")
        copies, tx = leaf_send_and_count(r, ptfadapter, r.l1, mac, t)
        at_h0 = native_on(copies, r.p_h0, None)
        flood_l2 = len(vxlan_to(copies, r.l1.vtep, r.l2.vtep, port=r.l2.ptf_port))
        emitted = len(vxlan_to(copies, r.dut_vtep))
        assert delivered(at_h0) and tx[r.h1] <= TX_SLACK and flood_l2 == 0 and emitted == 0, (
            "{}'s host to {} (learned on {}, advertised) ({} frames): {} untagged at {} (PTF), DUT unicast TX {}, "
            "{} flooded by {} to {}, {} DUT VxLAN copies. Copies: {}".format(
                r.l1.name, mac, r.h0, N, at_h0, r.h0, tx, flood_l2, r.l1.name, r.l2.name, emitted,
                summarize(copies)))

        h0_out = True
        sh(d, "sudo config vlan member del {} {}".format(VLAN_A, r.h0))
        for lf in (r.l1, r.l2):
            wait_for(CONVERGE, 3, lambda: r.leaves.remote_mac_dst(lf.name, mac) is None,
                     "{} to remove {} once {} left {} (the DUT's Type-2 withdrawn)".format(
                         lf.name, mac, r.h0, VLAN_A_NAME))
        t = tag("lcW")
        copies, tx = leaf_send_and_count(r, ptfadapter, r.l1, mac, t)
        flood_l2 = len(vxlan_to(copies, r.l1.vtep, r.l2.vtep, port=r.l2.ptf_port))
        assert delivered(flood_l2) and native_on(copies, r.p_h0) == 0 and tx[r.h0] <= TX_SLACK, (
            "{} out of {}: {}'s host to {} ({} frames): {} flooded by {} to {} (want all), {} at {} (PTF), DUT "
            "unicast TX {}. Copies: {}".format(r.h0, VLAN_A_NAME, r.l1.name, mac, N, flood_l2, r.l1.name, r.l2.name,
                                               native_on(copies, r.p_h0), r.h0, tx, summarize(copies)))

        sh(d, "sudo config vlan member add -u {} {}".format(VLAN_A, r.h0))
        h0_out = False
        wait_for(60, 2, lambda: bool(db_keys(d, "APPL_DB", "VLAN_MEMBER_TABLE:{}:{}".format(VLAN_A_NAME, r.h0))),
                 "{} back in {} in APPL_DB".format(r.h0, VLAN_A_NAME))
        time.sleep(3)
        learn_on_h0(r, ptfadapter, mac)
        for lf in (r.l1, r.l2):
            wait_for(CONVERGE, 3, lambda: r.leaves.remote_mac_dst(lf.name, mac) == r.dut_vtep,
                     "{} to install {} toward {} again after {} rejoined {}".format(
                         lf.name, mac, r.dut_vtep, r.h0, VLAN_A_NAME))
        t = tag("lcB")
        copies, tx = leaf_send_and_count(r, ptfadapter, r.l1, mac, t)
        at_h0 = native_on(copies, r.p_h0, None)
        flood_l2 = len(vxlan_to(copies, r.l1.vtep, r.l2.vtep, port=r.l2.ptf_port))
        assert delivered(at_h0) and flood_l2 == 0, (
            "{} back in {}: {}'s host to {} ({} frames): {} untagged at {} (PTF), {} flooded by {} to {}. Copies: "
            "{}".format(r.h0, VLAN_A_NAME, r.l1.name, mac, N, at_h0, r.h0, flood_l2, r.l1.name, r.l2.name,
                        summarize(copies)))
    finally:
        _cleanup()
    restore.finish()


# --------------------------------------------------------------------------------------------------------------------
# a MAC that changes sides between a local port and a leaf
# --------------------------------------------------------------------------------------------------------------------
def from_h1(r, ptfadapter, mac, name):
    """N frames from H1 (802.1Q-tagged in VLAN A) to mac: SimpleNamespace(local, to_l1, to_l2, other, text) with the
    untagged copies at H0, the DUT's VxLAN copies to l1 and to l2 in VNI A on their ports, and every other DUT VxLAN
    copy. H1 sends, so that the path to the PTF never learns mac on H0's port from the frames sourced there."""
    t = tag(name)
    copies = send_and_count(ptfadapter, r.p_h1, probe_frame(t, mac, H1_SRC, vlan=VLAN_A), N, t)
    o = SimpleNamespace(local=native_on(copies, r.p_h0, None),
                        to_l1=len(vxlan_to(copies, r.dut_vtep, r.l1.vtep, VNI_A, port=r.l1.ptf_port)),
                        to_l2=len(vxlan_to(copies, r.dut_vtep, r.l2.vtep, VNI_A, port=r.l2.ptf_port)))
    o.other = len(vxlan_to(copies, r.dut_vtep)) - o.to_l1 - o.to_l2
    o.text = "{} frames from {} to {}: {} untagged at {}, {} VxLAN to l1, {} to l2, {} other DUT VxLAN. Copies: {}" \
        .format(N, r.h1, mac, o.local, r.h0, o.to_l1, o.to_l2, o.other, summarize(copies))
    return o


def to_l1_only(o):
    return delivered(o.to_l1) and o.to_l2 == 0 and o.other == 0 and o.local == 0


def to_h0_only(o):
    return delivered(o.local) and o.to_l1 == 0 and o.to_l2 == 0 and o.other == 0


def flooded(o):
    return delivered(o.local) and delivered(o.to_l1) and delivered(o.to_l2) and o.other == 0


def fdb_views(r, mac):
    """What ASIC_DB, `show mac` and STATE_DB hold for mac in VLAN A: ([FdbEntry], port or None, (port, type) or
    None)."""
    d = r.duthost
    key = "FDB_TABLE|{}:{}".format(VLAN_A_NAME, mac.lower())
    state = (db_hget(d, "STATE_DB", key, "port"), db_hget(d, "STATE_DB", key, "type")) if db_keys(
        d, "STATE_DB", key) else None
    return AsicView(d).fdb(mac, VLAN_A), fdb_port(d, VLAN_A, mac), state


def is_local_dynamic(r, views):
    entries, _shown, state = views
    return (len(entries) == 1 and entries[0].bp_type == "SAI_BRIDGE_PORT_TYPE_PORT" and entries[0].port == r.h0 and
            entries[0].fdb_type == "SAI_FDB_ENTRY_TYPE_DYNAMIC" and entries[0].endpoint in ("", "0.0.0.0", "::") and
            state == (r.h0, "dynamic"))


def remote_like(views, ctrl, vtep):
    """mac's views: one entry on the tunnel to vtep with the FDB type and endpoint address of ctrl (another MAC of the
    same leaf and kind, installed with no local history), and no local entry in STATE_DB."""
    entries, _shown, state = views
    return (len(ctrl) == 1 and len(entries) == 1 and state is None and
            (entries[0].bp_type, entries[0].dip) == ("SAI_BRIDGE_PORT_TYPE_TUNNEL", vtep) and
            (entries[0].fdb_type, entries[0].endpoint) == (ctrl[0].fdb_type, ctrl[0].endpoint))


class StickyNotCarried(AssertionError):
    """A MAC a leaf added static reached APPL_DB as an ordinary (dynamic) remote MAC."""


def leaf_mac(r, leaf, mac, static=False):
    """leaf adds mac on its host port; wait for its APPL_DB row (type static for a sticky MAC) and its one ASIC_DB
    entry on the tunnel to the leaf."""
    d = r.duthost
    r.leaves.fdb("add", leaf.name, mac, VLAN_A, static=static)
    key = "VXLAN_FDB_TABLE:{}:{}".format(VLAN_A_NAME, mac.lower())
    wait_for(CONVERGE, 3, lambda: db_hget(d, "APPL_DB", key, "remote_vtep") == leaf.vtep,
             "APPL_DB {} -> {}".format(key, leaf.vtep))
    if static and db_hget(d, "APPL_DB", key, "type") != "static":
        raise StickyNotCarried("not exercised: {} added static on {} reached APPL_DB as type '{}' (the sticky flag is "
                               "not carried to the DUT)".format(mac, leaf.name, db_hget(d, "APPL_DB", key, "type")))
    wait_state(60, 3, lambda: remote_fdb_dip(d, mac, VLAN_A) == leaf.vtep,
               "one ASIC_DB FDB entry for {} on the tunnel to {}".format(mac, leaf.vtep),
               lambda: AsicView(d).fdb(mac, VLAN_A))


def forget(r, macs):
    """Clean-up of a MAC-sides case: l1 drops the MACs, the DUT flushes VLAN A; then no ASIC_DB entry, APPL_DB row or
    leaf FDB entry is left for them or for H1's source, so the next case starts from nothing."""
    d = r.duthost
    every = list(macs) + [H1_SRC]
    for mac in macs:
        r.leaves.run("fdb", "del", r.l1.name, mac, VLAN_A, check=False)
    flush_fdb(d, "VLAN", str(VLAN_A))
    if r.vs:
        kernel_fdb_forget(d, VLAN_A, every)

    def gone():
        return (not any(AsicView(d).fdb(m, VLAN_A) for m in every) and
                not any(appl_remote_mac_vtep(d, VLAN_A_NAME, m) for m in every) and
                not any(r.leaves.remote_mac_dst(lf.name, m) for lf in (r.l1, r.l2) for m in every))
    wait_for(CONVERGE, 3, gone, "ASIC_DB, APPL_DB and leaf FDB entries for {} to go".format(sorted(every)))


def stays(cond, seconds, what, now):
    """Fail on the first reading within `seconds` (every 2 s) where cond() is false: a late event must not undo a
    state that was reached."""
    end = time.time() + seconds
    while time.time() < end:
        if not cond():
            raise AssertionError("{}: no longer true; now: {}".format(what, now()))
        time.sleep(2)


def test_sticky_remote_mac_not_displaced_by_local_learn(evpn_rig, ptfadapter):
    """A MAC that l1 advertises as static (sticky) stays on l1's tunnel when H0 sources frames from it.

    Control: unicast from H1 to the MAC is encapsulated to l1. H0 then sends broadcasts sourced from it. The MAC's
    one ASIC_DB entry must still point at l1, `show mac` must not name H0, the same unicast must still be
    encapsulated to l1 with no copy at H0, and l2 must still send the MAC to l1 (the DUT advertised no move).

    On a virtual switch the vs SAI learns a MAC over a static FDB entry, so its ASIC_DB and dataplane readings need
    hardware; the control plane is still read there: l2 must keep the MAC on l1 for 30 s.
    """
    r = evpn_rig
    restore = Steps("removing the sticky MAC")

    def _cleanup():
        restore("sticky MAC", lambda: forget(r, [MAC_STICKY]))

    try:
        leaf_mac(r, r.l1, MAC_STICKY, static=True)
        o = from_h1(r, ptfadapter, MAC_STICKY, "spC")
        if not to_l1_only(o):
            pytest.fail("control: unicast to the sticky remote MAC {} is not encapsulated to l1 only: {}".format(
                MAC_STICKY, o.text))
        testutils.send(ptfadapter, r.p_h0, probe_frame(tag("spL"), BROADCAST_MAC, MAC_STICKY), count=N)
        time.sleep(5)
        if r.vs:
            stays(lambda: r.leaves.remote_mac_dst(r.l2.name, MAC_STICKY) == r.l1.vtep, 30,
                  "l2 sends the sticky MAC {} to l1 {} after {} sourced it".format(MAC_STICKY, r.l1.vtep, r.h0),
                  lambda: r.leaves.remote_mac_dst(r.l2.name, MAC_STICKY))
        else:
            entries, shown, state = fdb_views(r, MAC_STICKY)
            o = from_h1(r, ptfadapter, MAC_STICKY, "spA")
            at_l2 = r.leaves.remote_mac_dst(r.l2.name, MAC_STICKY)
            assert ([e.dip for e in entries] == [r.l1.vtep] and shown != r.h0 and state is None and to_l1_only(o) and
                    at_l2 == r.l1.vtep), (
                "after {} frames sourced from {} on {}: ASIC_DB FDB entries {}, `show mac` port {}, STATE_DB {}; l2 "
                "sends it to {} (want l1 {}); unicast from {}: {}".format(
                    N, MAC_STICKY, r.h0, entries, shown, state, at_l2, r.l1.vtep, r.h1, o.text))
    finally:
        _cleanup()
    restore.finish()


def test_remote_mac_replaced_by_local(evpn_rig, ptfadapter):
    """A MAC behind l1 that H0 then sources moves to H0, is forwarded there only, and is a dynamic local MAC.

    l1 advertises the MAC. Control: unicast from H1 to it is encapsulated to l1. H0 sources it; then:
      * ASIC_DB holds one dynamic entry on H0's bridge port, with no endpoint address, and STATE_DB names H0 dynamic;
      * l1 points the MAC at the DUT's VTEP (the DUT's route won by MAC mobility), and every frame to it from H1
        leaves on H0 only;
      * a flush of H0's port removes it from ASIC_DB, `show mac` and STATE_DB, no remote entry comes back, both
        leaves drop it, and frames to it flood (H0, l1 and l2 each get every frame);
      * a frame from the host puts it back on H0, and every frame to it leaves on H0 only again;
      * `show mac` names H0 whenever the databases do (read at each of those steps, judged last).

    On a virtual switch the vs SAI reports no move of an existing FDB entry, but its dataplane, the kernel bridge,
    takes the MAC over: there the move is read from the kernel, from l1 (the DUT's Type-2 won by MAC mobility) and
    from the forwarding; the ASIC_DB, STATE_DB and flush readings need hardware.
    """
    r = evpn_rig
    d = r.duthost
    shown = []
    restore = Steps("removing the moved MAC")

    def _cleanup():
        restore("moved MAC", lambda: forget(r, [MAC_TO_LOCAL]))

    try:
        leaf_mac(r, r.l1, MAC_TO_LOCAL)
        o = from_h1(r, ptfadapter, MAC_TO_LOCAL, "rlC")
        if not to_l1_only(o):
            pytest.fail("control: unicast to the remote MAC {} is not encapsulated to l1 only: {}".format(
                MAC_TO_LOCAL, o.text))
        if r.vs:
            t = tag("rlV")
            send_and_count(ptfadapter, r.p_h0, probe_frame(t, BROADCAST_MAC, MAC_TO_LOCAL), 3, t)
            wait_for(20, 1, lambda: kernel_fdb_port(d, VLAN_A, MAC_TO_LOCAL) == r.h0,
                     "the kernel bridge to move {} from l1 to {}".format(MAC_TO_LOCAL, r.h0))
            wait_for(CONVERGE, 3, lambda: r.leaves.remote_mac_dst(r.l1.name, MAC_TO_LOCAL) == r.dut_vtep,
                     "l1 to point {} at the DUT's VTEP {} once the DUT learned it".format(MAC_TO_LOCAL, r.dut_vtep))
            o = from_h1(r, ptfadapter, MAC_TO_LOCAL, "rlv")
            assert to_h0_only(o), "known unicast to {} after it moved from l1 to {}: {}".format(
                MAC_TO_LOCAL, r.h0, o.text)
        else:
            moved_on_hardware(r, ptfadapter, shown)
    finally:
        _cleanup()
    restore.finish()
    assert r.vs or shown == [r.h0] * 2, (
        "`show mac` named {} as the port of {} at the two steps where ASIC_DB and STATE_DB had it as a dynamic entry "
        "on {} (after the move, after it was learned again)".format(shown, MAC_TO_LOCAL, r.h0))


def moved_on_hardware(r, ptfadapter, shown):
    """test_remote_mac_replaced_by_local from H0's first frame on, where the SAI reports the move: the `show mac`
    port at each step where the databases hold the MAC on H0 is appended to shown."""
    d = r.duthost
    learn_on_h0(r, ptfadapter, MAC_TO_LOCAL)
    wait_until(30, 1, 0, lambda: is_local_dynamic(r, fdb_views(r, MAC_TO_LOCAL)))
    views = fdb_views(r, MAC_TO_LOCAL)
    shown.append(views[1])
    assert is_local_dynamic(r, views), (
        "{} moved from l1 to {}: ASIC_DB FDB entries {}, `show mac` port {}, STATE_DB (port, type) {}; expected "
        "one dynamic entry on {} with no endpoint address".format(MAC_TO_LOCAL, r.h0, views[0], views[1], views[2],
                                                                  r.h0))
    wait_for(CONVERGE, 3, lambda: r.leaves.remote_mac_dst(r.l1.name, MAC_TO_LOCAL) == r.dut_vtep,
             "l1 to point {} at the DUT's VTEP {} once the DUT learned it".format(MAC_TO_LOCAL, r.dut_vtep))
    o = from_h1(r, ptfadapter, MAC_TO_LOCAL, "rl1")
    assert to_h0_only(o), "known unicast to {} after it moved from l1 to {}: {}".format(MAC_TO_LOCAL, r.h0, o.text)

    flush_fdb(d, "PORT", r.h0)
    wait_until(30, 1, 0, lambda: fdb_views(r, MAC_TO_LOCAL) == ([], None, None))
    for lf in (r.l1, r.l2):
        wait_for(CONVERGE, 3, lambda: r.leaves.remote_mac_dst(lf.name, MAC_TO_LOCAL) is None,
                 "{} to drop {} after the DUT flushed it".format(lf.name, MAC_TO_LOCAL))
    views = fdb_views(r, MAC_TO_LOCAL)
    o = from_h1(r, ptfadapter, MAC_TO_LOCAL, "rl2")
    assert views == ([], None, None) and flooded(o), (
        "after a flush of {}: ASIC_DB FDB entries of {} {}, `show mac` port {}, STATE_DB {} (expected none); "
        "unicast to it must flood to {}, l1 and l2: {}".format(
            r.h0, MAC_TO_LOCAL, views[0], views[1], views[2], r.h0, o.text))
    learn_on_h0(r, ptfadapter, MAC_TO_LOCAL)
    views = fdb_views(r, MAC_TO_LOCAL)
    shown.append(views[1])
    o = from_h1(r, ptfadapter, MAC_TO_LOCAL, "rl3")
    assert is_local_dynamic(r, views) and to_h0_only(o), (
        "{} learned again on {} after the flush: ASIC_DB FDB entries {}, `show mac` port {}, STATE_DB {}; unicast "
        "to it: {}".format(MAC_TO_LOCAL, r.h0, views[0], views[1], views[2], o.text))


def sticky_dropped_by_leaf(r, leaf, mac):
    """The DUT's bgpd holds mac from leaf with a MAC Mobility sequence above 0 and no sticky flag: the leaf's bgpd
    built the community with the flag and encoded it again with flags 0 for the sequence number. Returns the
    (sequence, sticky) values received when every path reads so, else None (the flag was sent: the DUT lost it)."""
    mm = received_mac_mobility(r.duthost, mac, leaf.vtep)
    logger.info("MAC Mobility (sequence, sticky) the DUT's bgpd holds for %s from %s: %s", mac, leaf.vtep, mm)
    return mm if mm and all(seq > 0 and not sticky for seq, sticky in mm) else None


@pytest.mark.parametrize("kind", ["dynamic", "sticky"])
def test_local_mac_replaced_by_remote(evpn_rig, ptfadapter, loganalyzer, kind):
    """A MAC learned on H0 that l1 then learns (dynamic: a move, l1 advertises a higher sequence) or adds static
    (sticky) is encapsulated to l1, and floods once l1 withdraws it.

    sticky: l1's local sequence for the MAC is 1 after the move, and the MAC must still reach the DUT as static.
    Where l1 itself is seen to advertise it without the sticky flag (the DUT's bgpd holds MM:1 with no sticky flag
    from l1, after the control MAC of sequence 0 arrived sticky), the failure names the leaf's missing STICKY_SEQ_FIX;
    a DUT that receives the flag and installs the MAC dynamic fails as a DUT failure.

    Control: with the MAC learned on H0 and both leaves pointing it at the DUT, unicast from H1 to it leaves on H0
    only. l1 then takes the MAC. ASIC_DB must hold one entry for it on the tunnel to l1, with the FDB type and
    endpoint address of a control MAC that l1 advertises the same way and that was never local; STATE_DB no longer
    lists it as local, and every frame to it is encapsulated to l1 with none at H0. A stale event for the replaced
    local entry must not put the MAC back on H0's port or leave the tunnel entry without its endpoint. l1 then
    withdraws it: ASIC_DB, `show mac` and STATE_DB hold nothing for it, and it floods (H0, l1 and l2 each get every
    frame).
    """
    r = evpn_rig
    sticky = kind == "sticky"
    mac = MAC_TO_REMOTE[kind]
    if loganalyzer:
        # zebra's remote install has already moved the kernel entry off H0 when fdbsyncd deletes the local one
        loganalyzer[r.duthost.hostname].ignore_regex.append(
            r".*ERR swss#fdbsyncd: :- updateLocalMac: Failed cmd: bridge fdb del {} dev .* master dynamic "
            r"extern_learn vlan {}(?: proto \w+)?, res=, ret=255.*".format(mac, VLAN_A))
    restore = Steps("removing the replaced MAC")

    def _cleanup():
        restore("replaced MAC", lambda: forget(r, [mac, MAC_M_CTRL]))

    try:
        leaf_mac(r, r.l1, MAC_M_CTRL, static=sticky)
        ctrl = AsicView(r.duthost).fdb(MAC_M_CTRL, VLAN_A)
        learn_on_h0(r, ptfadapter, mac)
        for lf in (r.l1, r.l2):
            wait_for(CONVERGE, 3, lambda: r.leaves.remote_mac_dst(lf.name, mac) == r.dut_vtep,
                     "{} to install {} toward the DUT's VTEP {}".format(lf.name, mac, r.dut_vtep))
        o = from_h1(r, ptfadapter, mac, "lrC")
        if not to_h0_only(o):
            pytest.fail("control: unicast to the local MAC {} does not leave on {} only: {}".format(
                mac, r.h0, o.text))
        try:
            leaf_mac(r, r.l1, mac, static=sticky)
        except StickyNotCarried as e:
            dropped = sticky_dropped_by_leaf(r, r.l1, mac)
            if dropped is None:
                raise
            pytest.fail("the leaf's FRR ({}) advertises the moved static MAC {} without the sticky flag, MAC Mobility "
                        "(sequence, sticky) received from {}: {}; the leaf needs {} ({})".format(
                            r.image, mac, r.l1.vtep, dropped, STICKY_SEQ_FIX, e))
        wait_until(30, 1, 0, lambda: remote_like(fdb_views(r, mac), ctrl, r.l1.vtep))
        # a stale event for the replaced local entry arrives after the replace, batched with other notifications
        if remote_like(fdb_views(r, mac), ctrl, r.l1.vtep):
            stays(lambda: remote_like(fdb_views(r, mac), ctrl, r.l1.vtep), 2 * counter_poll_s(r.duthost) + 10,
                  "{} on the tunnel to l1 like the control".format(mac), lambda: fdb_views(r, mac))
        views = fdb_views(r, mac)
        o = from_h1(r, ptfadapter, mac, "lr1")
        assert remote_like(views, ctrl, r.l1.vtep) and to_l1_only(o), (
            "{} learned on {}, then taken by l1 ({}): ASIC_DB FDB entries {} (control MAC {} of l1: {}), STATE_DB "
            "local entry {}; expected one entry on the tunnel to {} like the control's and no local one; unicast to "
            "it: {}".format(mac, r.h0, kind, views[0], MAC_M_CTRL, ctrl, views[2], r.l1.vtep, o.text))
        r.leaves.fdb("del", r.l1.name, mac, VLAN_A)
        wait_until(CONVERGE, 3, 0, lambda: fdb_views(r, mac) == ([], None, None))
        views = fdb_views(r, mac)
        o = from_h1(r, ptfadapter, mac, "lr2")
        assert views == ([], None, None) and flooded(o), (
            "after l1 withdrew {}: ASIC_DB FDB entries {}, `show mac` port {}, STATE_DB {} (expected none); unicast "
            "to it must flood to {}, l1 and l2: {}".format(mac, views[0], views[1], views[2], r.h0, o.text))
    finally:
        _cleanup()
    restore.finish()


# --------------------------------------------------------------------------------------------------------------------
# the switch's VxLAN UDP port and router MAC, set and deleted through SWITCH_TABLE
# --------------------------------------------------------------------------------------------------------------------
ALT_VXLAN_PORT = 10789
ALT_ROUTER_MAC = "02:4c:45:ee:00:99"
SWITCH_KEY = "SWITCH_TABLE:switch"


def switch_vxlan_attrs(duthost):
    """(VXLAN_DEFAULT_PORT, VXLAN_DEFAULT_ROUTER_MAC) of the ASIC_DB switch object ('' where not set)."""
    keys = db_keys(duthost, "ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:*")
    if len(keys) != 1:
        return ("?", "?")
    return (db_hget(duthost, "ASIC_DB", keys[0], "SAI_SWITCH_ATTR_VXLAN_DEFAULT_PORT"),
            db_hget(duthost, "ASIC_DB", keys[0], "SAI_SWITCH_ATTR_VXLAN_DEFAULT_ROUTER_MAC").lower())


def appl_switch_table(duthost):
    out = sh(duthost, "sonic-db-cli APPL_DB HGETALL '{}'".format(SWITCH_KEY)).strip()
    return ast.literal_eval(out) if out else {}


def put_switch_table_back(duthost, orig, pre, router_mac):
    """SWITCH_TABLE:switch back to orig, and the switch's VxLAN port and router MAC back to pre, also where a DEL
    does not reach orchagent: the VxLAN fields are first written with their previous values (the switch's own MAC
    where ASIC_DB held no router MAC), then the key is deleted and orig written."""
    want = (pre[0] or str(VXLAN_UDP_PORT), pre[1] or router_mac.lower())

    def back_now():
        port, mac = switch_vxlan_attrs(duthost)
        return port == want[0] and mac != ALT_ROUTER_MAC and (not pre[1] or mac == pre[1])
    if not back_now() or "vxlan_port" in appl_switch_table(duthost):
        swss_apply(duthost, [{SWITCH_KEY: {"vxlan_port": want[0], "vxlan_router_mac": want[1]}, "OP": "SET"}],
                   name="vxlan_evpn_port")
        swss_apply(duthost, [{SWITCH_KEY: {}, "OP": "DEL"}], name="vxlan_evpn_port")
    if orig:
        swss_apply(duthost, [{SWITCH_KEY: orig, "OP": "SET"}], name="vxlan_evpn_port")
    wait_state(30, 2, back_now, "ASIC_DB switch VxLAN port and router MAC back to {}".format(want),
               lambda: switch_vxlan_attrs(duthost))


def test_vxlan_udp_port_set_and_deleted(evpn_rig, ptfadapter, loganalyzer):
    """The switch's VxLAN UDP port and router MAC set through APPL_DB SWITCH_TABLE:switch, then the key deleted.

    Set (vxlan_port 10789, vxlan_router_mac): ASIC_DB's switch object carries both, known unicast to l1's MAC leaves
    as VxLAN to port 10789 (none to 4789), and VxLAN from l1 to port 10789 for a MAC learned on H0 is delivered
    there. Deleted (the whole key, as swssconfig DEL does): the VxLAN UDP port goes back to 4789 and the router MAC
    to its value before the set (or, where the SAI cannot report that value, orchagent says so at the set and keeps
    it), and the same unicast is encapsulated to port 4789. The key's previous fields are written back at the end.
    """
    r, d = evpn_rig, evpn_rig.duthost
    orig = appl_switch_table(d)
    pre = switch_vxlan_attrs(d)
    if "?" in pre:
        pytest.skip("ASIC_DB does not hold exactly one switch object")
    if "vxlan_port" in orig or "vxlan_router_mac" in orig:
        pytest.skip("SWITCH_TABLE:switch already sets the VxLAN port or router MAC ({}): deleting the key would not "
                    "return them to a known value".format(orig))
    if loganalyzer:
        # where the SAI cannot report the router MAC's default (see below)
        loganalyzer[d.hostname].ignore_regex.append(r".*Failed to get default of switch attribute.*")
    marker = "vxlan-udp-port-{}".format(tag("m"))
    sh(d, "logger -t vxlan_evpn_l2 {}".format(marker))
    macs = {MAC_R1: r.l1}
    problems = []
    restore = Steps("SWITCH_TABLE and the remote MAC")

    def _cleanup():
        restore("SWITCH_TABLE", lambda: put_switch_table_back(d, orig, pre, r.router_mac))
        restore("remote MAC", lambda: remove_remote_macs(r, macs))
        flush_fdb(d, "VLAN", str(VLAN_A))

    try:
        add_remote_macs(r, macs)
        local, src = "02:4c:45:00:00:a8", "02:4c:45:00:00:a9"
        learn_on_h0(r, ptfadapter, local)
        swss_apply(d, [{SWITCH_KEY: {"vxlan_port": str(ALT_VXLAN_PORT), "vxlan_router_mac": ALT_ROUTER_MAC},
                        "OP": "SET"}], name="vxlan_evpn_port")
        wait_state(30, 2, lambda: switch_vxlan_attrs(d) == (str(ALT_VXLAN_PORT), ALT_ROUTER_MAC),
                   "ASIC_DB switch VxLAN port {} and router MAC {}".format(ALT_VXLAN_PORT, ALT_ROUTER_MAC),
                   lambda: switch_vxlan_attrs(d))
        t = tag("upE")
        if r.vs:
            logger.info("virtual switch: the port's traffic readings are not taken (the kernel keeps 4789)")
        got = [] if r.vs else collect(ptfadapter, lambda: testutils.send(ptfadapter, r.p_h0, probe_frame(
            t, MAC_R1, src), count=N), lambda raw: raw if t.encode() in raw else None, udp_port=ALT_VXLAN_PORT)
        copies = [c for c, _raw in got]
        logger.info("tag %s: captured %d copies: %s", t, len(copies), summarize(copies))
        good = len(vxlan_to(copies, r.dut_vtep, r.l1.vtep, VNI_A, port=r.l1.ptf_port))
        # parsed for port 10789, a DUT copy to 4789 is native; so is l1's ICMP port unreachable, which quotes the frame
        default = len(vxlan_to([parse_copy(c.port, raw) for c, raw in got if c.kind == "native"], r.dut_vtep))
        if not r.vs and (not delivered(good) or len(vxlan_to(copies, r.dut_vtep)) != good or default):
            problems.append("unicast to {} with port {}: {} VxLAN to l1 on that port, {} other VxLAN, {} VxLAN to port "
                            "{}. Copies: {}".format(MAC_R1, ALT_VXLAN_PORT, good,
                                                    len(vxlan_to(copies, r.dut_vtep)) - good, default,
                                                    VXLAN_UDP_PORT, summarize(copies)))
        t = tag("upD")
        pkt = vxlan_frame(probe_frame(t, local, MAC_R1_PEER), r.router_mac, INJ_OUTER_SMAC, r.l1.vtep, r.dut_vtep,
                          VNI_A, dport=ALT_VXLAN_PORT)
        copies = [] if r.vs else send_and_count(ptfadapter, r.l1.ptf_port, pkt, N, t, udp_port=ALT_VXLAN_PORT)
        at_h0 = native_on(copies, r.p_h0, None)
        if not r.vs and (not delivered(at_h0) or vxlan_to(copies, r.dut_vtep)):
            problems.append("VxLAN from l1 to port {} for {} on {}: {} of {} untagged there, {} DUT VxLAN copies. "
                            "Copies: {}".format(ALT_VXLAN_PORT, local, r.h0, at_h0, N,
                                                len(vxlan_to(copies, r.dut_vtep)), summarize(copies)))

        swss_apply(d, [{SWITCH_KEY: {}, "OP": "DEL"}], name="vxlan_evpn_port")
        wait_until(30, 2, 0, lambda: switch_vxlan_attrs(d)[0] == "4789" and switch_vxlan_attrs(d)[1] != ALT_ROUTER_MAC)
        port, mac = switch_vxlan_attrs(d)
        unreadable = sh(d, "sudo sh -c 'cat /var/log/syslog.1 /var/log/syslog 2>/dev/null' | sed -n '/{}/,$p' | "
                           "grep -c 'Failed to get default of switch attribute'; true".format(marker)).strip()
        # with no router MAC in ASIC_DB before the set, orchagent writes back the value the SAI reported
        restored = mac != ALT_ROUTER_MAC and (not pre[1] or mac == pre[1])
        mac_ok = restored or unreadable not in ("", "0")
        if port != "4789" or not mac_ok:
            problems.append("after the SWITCH_TABLE:switch delete: ASIC_DB VxLAN port '{}' (want 4789), router MAC "
                            "'{}' (want '{}' as before the set, or kept with orchagent's notice that the SAI cannot "
                            "report it: {} notices)".format(port, mac, pre[1], unreadable or 0))
        t = tag("upR")
        copies = send_and_count(ptfadapter, r.p_h0, probe_frame(t, MAC_R1, src), N, t)
        good = len(vxlan_to(copies, r.dut_vtep, r.l1.vtep, VNI_A, port=r.l1.ptf_port))
        if not delivered(good) or len(vxlan_to(copies, r.dut_vtep)) != good:
            problems.append("after the delete: unicast to {}: {} VxLAN to l1 on port 4789, {} other. Copies: {}"
                            .format(MAC_R1, good, len(vxlan_to(copies, r.dut_vtep)) - good, summarize(copies)))
    finally:
        _cleanup()
    restore.finish()
    assert not problems, "SWITCH_TABLE VxLAN port {} / router MAC {}: {}".format(
        ALT_VXLAN_PORT, ALT_ROUTER_MAC, " | ".join(problems))


def test_swss_warm_restart_keeps_evpn(evpn_rig, ptfadapter, duthost, loganalyzer):
    """swss warm restart with EVPN-learned state (sonic-net/sonic-swss#4951): nothing reaches the ASIC, nothing is lost.

    Before and after: the same flood set per VNI and the same remote MAC -> tunnel entries in ASIC_DB, BUM to both
    leaves and unicast to a remote MAC. In between: syncd keeps running and its compareViews reports 0 ASIC
    operations.
    """
    r = evpn_rig
    d = r.duthost
    if r.vs:
        pytest.skip("the vs SAI cannot warm-restore tunnel bridge ports (no SAI_BRIDGE_PORT_ATTR_PORT_ID); hardware "
                    "runs the swss warm restart")
    gearbox = has_gearbox(d)
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(
            SWSS_WARM_RESTART_LOG + (GEARBOX_WARM_RESTART_LOG if gearbox else []))
    unhealthy, err = orch_health(d)
    assert not unhealthy, "orchagent is already latched unhealthy before the warm restart: {}".format(err)
    macs = {MAC_R1: r.l1, MAC_R2: r.l2}
    res = None
    latched = ""
    recovered = True
    restore = Steps("after the warm restart")

    def _cleanup():
        nonlocal latched, recovered
        # orchagent latches a SAI failure it could not handle (PROCESS_HEALTH) until it restarts; with an external PHY a
        # gearbox port create fails at every swss warm start. Whatever the outcome above, recover cold from a latched
        # state.
        if res is not None and not res["cold"]:
            unhealthy, err = orch_health(d)
            if unhealthy:
                latched = err or "unhealthy"
                recovered = cold_restart_swss(d)
                vtysh(d, dut_bgp_add_commands(r.dut_asn, r.all_leaves, RT_ASN, (VNI_A, VNI_B), r.added_aav),
                      check=False)
        restore("remote MACs", lambda: remove_remote_macs(r, macs))

    try:
        add_remote_macs(r, macs)
        wait_flood(r, r.expect_flood, 60, "before the restart")
        pre_fdb = {m: remote_fdb_dip(d, m, VLAN_A) for m in macs}
        # EVPN tunnel bridge ports are created without hardware learning (PortsOrch::addTunnel); the restart must
        # keep it that way
        pre_learn = tunnel_bridge_port_learning(d)
        assert len(pre_learn) == 2 and "SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW" not in pre_learn.values(), (
            "before the restart: the two tunnel bridge ports' FDB learning modes are {}".format(pre_learn))

        def traffic(when):
            copies = bum_from(r, ptfadapter, "wr" + when, "02:4c:45:00:00:61")
            bum = per_leaf(r, copies, VNI_A)
            t = tag("wrU" + when)
            ucopies = send_and_count(ptfadapter, r.p_h0, probe_frame(t, MAC_R1, "02:4c:45:00:00:62"), N, t)
            uni = len(vxlan_to(ucopies, r.dut_vtep, r.l1.vtep, VNI_A, port=r.l1.ptf_port))
            stray = len(vxlan_to(ucopies, r.dut_vtep)) - uni
            assert delivered(bum["l1"]) and delivered(bum["l2"]) and delivered(uni) and stray == 0, (
                "{} the warm restart: BUM per leaf {}, unicast to {} -> {} {} ({} elsewhere), of {}. Copies: {} | "
                "{}".format(when, bum, MAC_R1, r.l1.name, uni, stray, N, summarize(copies), summarize(ucopies)))
        traffic("before")

        marker = "warm-restart-{}".format(tag("wr"))
        res = swss_warm_restart(d, marker)
        logger.info("swss warm restart: %s", {k: v for k, v in res.items() if k != "log"})
        if res["cold"]:
            # the cold recovery restarted bgp too, which drops the vtysh-only BGP config; put it back for the teardown
            vtysh(d, dut_bgp_add_commands(r.dut_asn, r.all_leaves, RT_ASN, (VNI_A, VNI_B), r.added_aav), check=False)
        assert res["orch_reconciled"] and res["fdbsyncd_reconciled"] and not res["error"], (
            "swss warm restart did not reconcile (orchagent {}, fdbsyncd {}; orchagent pid {} -> {}; error '{}'). "
            "orchagent error lines: {} | applyView lines: {}".format(
                res["orch_reconciled"], res["fdbsyncd_reconciled"], res["orch_before"], res["orch_after"] or "none",
                res["error"], res["abort"] or "none", res["log"]))
        assert res["syncd_before"] and res["syncd_before"] == res["syncd_after"], (
            "syncd restarted during a swss warm restart (pid {} -> {})".format(res["syncd_before"], res["syncd_after"]))
        # only the freeze being undone may reach the ASIC: aging back on, learning back on for port bridge ports
        assert (res["compare_views"] == 1 and len(res["ops"]) == res["asic_ops"] and not res["unexpected_ops"]
                and not res["inconsistent"]), (
            "syncd applyView after the swss warm restart: {} compareViews, {} ASIC operations ({} parsed), "
            "unexpected (not the freeze being undone): {}, inconsistent={}. Log: {}".format(
                res["compare_views"], res["asic_ops"], len(res["ops"]), res["unexpected_ops"], res["inconsistent"],
                res["log"]))
        for lf in (r.l1, r.l2):
            wait_for(CONVERGE, 5, lambda: evpn_peer_established(d, lf.ip),
                     "l2vpn evpn session to {} after the warm restart".format(lf.name))

        post_flood = our_flood_set(d)
        post_fdb = {m: remote_fdb_dip(d, m, VLAN_A) for m in macs}
        post_learn = tunnel_bridge_port_learning(d)
        same_learn = sorted(post_learn.values()) == sorted(pre_learn.values())
        assert post_flood == sorted(r.expect_flood) and post_fdb == pre_fdb and same_learn, (
            "EVPN state lost across the swss warm restart: flood set {} -> {}, remote MAC tunnels {} -> {}, tunnel "
            "bridge port learning {} -> {}".format(
                sorted(r.expect_flood), sorted(post_flood), pre_fdb, post_fdb, pre_learn, post_learn))
        r.kvx = kernel_vxlan_netdev(d, VNI_A) or r.kvx
        traffic("after")
    finally:
        _cleanup()
    restore.finish()
    assert recovered, ("swss did not recover after the cold restart that clears orchagent's latched SAI failure "
                       "(PROCESS_HEALTH|orchagent: {})".format(latched))
    assert not latched, (
        "EVPN state and traffic survived the swss warm restart, but orchagent latched a SAI failure during the warm "
        "start (PROCESS_HEALTH|orchagent: {}); swss was restarted cold to recover".format(latched))


# --------------------------------------------------------------------------------------------------------------------
# an SVI neighbour whose MAC ages out: re-resolved, and the resolve request cleared
# --------------------------------------------------------------------------------------------------------------------
SVI_IP, SVI_PREFIX = "10.98.0.1", "10.98.0.1/24"
HOST_IP, HOST_MAC = "10.98.0.10", "02:4c:45:00:00:b1"
RESOLVE_KEY = "NEIGH_RESOLVE_TABLE:{}:{}".format(VLAN_A_NAME, HOST_IP)
AGE_S = 20                 # FDB aging time for the case
ANSWER_AFTER_AGE_S = 25    # the host keeps answering this long after its MAC aged out
REPROBE_WINDOW_S = 45      # a retry every 10 s or more would probe 3 times or more in this window
REPROBE_MAX = 2            # the resolve itself probes once; one more is the kernel's own


def arp(op, src_mac, src_ip, dst_mac, dst_ip, eth_dst):
    return Ether(dst=eth_dst, src=src_mac) / ARP(op=op, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip)


def answer_as_host(r, ptfadapter, stop, check_every=1.0, max_s=600):
    """Answer, as the host, every ARP request for HOST_IP that the DUT sends out H0 from now on, until stop() (called
    every check_every seconds) is true. Returns the times (time.time()) of the requests seen."""
    dp, seen = ptfadapter.dataplane, []
    dp.flush()   # requests queued before this call are not this window's
    start = next_check = time.time()
    while time.time() - start < max_s:
        res = dp.poll(device_number=0, port_number=r.p_h0, timeout=0.2)
        if isinstance(res, dp.PollSuccess):
            pkt = Ether(bytes(res.packet))
            if ARP in pkt and pkt[ARP].op == 1 and pkt[ARP].pdst == HOST_IP and pkt[ARP].psrc == SVI_IP:
                seen.append(time.time())
                testutils.send(ptfadapter, r.p_h0, arp(2, HOST_MAC, HOST_IP, pkt[ARP].hwsrc, SVI_IP, pkt.src))
        if time.time() >= next_check:
            if stop():
                return seen
            next_check = time.time() + check_every
    raise AssertionError("answering ARP as {} did not end within {} s".format(HOST_IP, max_s))


def syslog_since(duthost, marker, pattern):
    return sh(duthost, "sudo sh -c 'cat /var/log/syslog.1 /var/log/syslog 2>/dev/null' | sed -n '/{}/,$p' | "
                       "grep -a -- '{}'; true".format(marker, pattern)).strip()


def test_neigh_resolve_after_mac_age_out(evpn_rig, ptfadapter):
    """An SVI neighbour whose MAC ages out is re-resolved, and its NEIGH_RESOLVE_TABLE request is then cleared; a
    resolve request for a neighbour the kernel has resolved is probed once, not retried.

    VLAN A gets an SVI address and a host on H0 announces itself (ARP request to the SVI): the kernel neighbour, the
    APPL_DB neighbour and the MAC on H0. With the FDB aging time at AGE_S and the host silent, the MAC ages out;
    orchagent then asks for the neighbour to be resolved again (APPL_DB NEIGH_RESOLVE_TABLE, orchagent logs
    processFDBResolve for the MAC), and the PTF answers every ARP request as the host. The age-out is read from that
    log line: the request is deleted as soon as the kernel has the neighbour again, which can be milliseconds after
    the age-out when the host answers at once, too short for a poll of APPL_DB to see. Once the host has answered,
    the neighbour is still there with the host's MAC and the NEIGH_RESOLVE_TABLE request is gone (a request left
    behind is resolved again at every nbrmgrd start, and retried forever by a consumer that retries until the key is
    deleted). Then the aging time goes back, the MAC is on H0 again, and a resolve request for the resolved
    neighbour is written to NEIGH_RESOLVE_TABLE directly: over REPROBE_WINDOW_S the DUT sends at most REPROBE_MAX ARP
    requests for it.
    """
    r = evpn_rig
    d = r.duthost
    prev_age = db_hget(d, "APPL_DB", "SWITCH_TABLE:switch", "fdb_aging_time")
    marker = "neigh-resolve-{}".format(tag("m"))
    restore = Steps("the SVI, the neighbour and the aging time")
    svi = aging = hand_key = False

    def aging_back():
        swss_apply(d, [{"SWITCH_TABLE:switch": {"fdb_aging_time": prev_age or "600"}, "OP": "SET"}],
                   name="vxlan_evpn_age")

    def _cleanup():
        if hand_key:
            restore("resolve request", lambda: swss_apply(d, [{RESOLVE_KEY: {}, "OP": "DEL"}],
                                                          name="vxlan_evpn_resolve"))
        if aging:
            restore("aging time", aging_back)
        if svi:
            restore("neighbour", lambda: sh(d, "sudo ip neigh del {} dev {}; true".format(HOST_IP, VLAN_A_NAME)))
            # with the aging time back, the host's MAC stays learned (and advertised) until a flush
            restore("host MAC", lambda: flush_fdb(d, "VLAN", str(VLAN_A)))
            restore("leaves forget the host", lambda: wait_for(
                CONVERGE, 3, lambda: not any(r.leaves.remote_mac_dst(lf.name, HOST_MAC) for lf in (r.l1, r.l2)),
                "the leaves to drop {}".format(HOST_MAC)))
            restore("SVI address", lambda: sh(d, "sudo config interface ip remove {} {}".format(
                VLAN_A_NAME, SVI_PREFIX)))
            restore("SVI gone", lambda: wait_for(
                60, 2, lambda: not db_keys(d, "APPL_DB", "INTF_TABLE:{}:*".format(VLAN_A_NAME)) and
                not db_keys(d, "APPL_DB", "NEIGH_TABLE:{}:*".format(VLAN_A_NAME)),
                "the SVI of {} and its neighbours to leave APPL_DB".format(VLAN_A_NAME)))
        flush_fdb(d, "VLAN", str(VLAN_A))

    try:
        if db_keys(d, "APPL_DB", RESOLVE_KEY):
            pytest.fail("DUT is not clean: APPL_DB already holds {}".format(RESOLVE_KEY))
        sh(d, "sudo config interface ip add {} {}".format(VLAN_A_NAME, SVI_PREFIX))
        svi = True
        wait_for(60, 2, lambda: bool(db_keys(d, "APPL_DB", "INTF_TABLE:{}:{}".format(VLAN_A_NAME, SVI_PREFIX))),
                 "APPL_DB INTF_TABLE {} {}".format(VLAN_A_NAME, SVI_PREFIX))
        time.sleep(3)
        swss_apply(d, [{"SWITCH_TABLE:switch": {"fdb_aging_time": str(AGE_S)}, "OP": "SET"}], name="vxlan_evpn_age")
        aging = True
        testutils.send(ptfadapter, r.p_h0, arp(1, HOST_MAC, HOST_IP, "00:00:00:00:00:00", SVI_IP, BROADCAST_MAC))
        neigh_key = "NEIGH_TABLE:{}:{}".format(VLAN_A_NAME, HOST_IP)
        wait_for(30, 1, lambda: db_hget(d, "APPL_DB", neigh_key, "neigh").lower() == HOST_MAC,
                 "APPL_DB {} with {}".format(neigh_key, HOST_MAC))
        wait_for(30, 1, lambda: fdb_port(d, VLAN_A, HOST_MAC) == r.h0, "{} learned on {}".format(HOST_MAC, r.h0))
        sh(d, "logger -t vxlan_evpn_l2 {}".format(marker))

        # the age-out is read from orchagent's log, not from its resolve request: the request can be gone before a
        # poll sees it. aged[0] is when the last read that found no age-out started, so the age-out came after it.
        # bracketed so that the logged command line of the read itself cannot match
        logged = "[p]rocessFDBResolve: Resolving ARP for mac: {},".format(HOST_MAC)
        aged, miss = [], [time.time()]

        def aged_long_enough():
            if not aged:
                start = time.time()
                if syslog_since(d, marker, logged):
                    aged.append(miss[0])
                else:
                    miss[0] = start
            return bool(aged) and time.time() - aged[0] >= ANSWER_AFTER_AGE_S
        requests = []
        try:
            requests = answer_as_host(r, ptfadapter, aged_long_enough, max_s=4 * AGE_S + 120)
        except AssertionError:
            pytest.fail("not exercised: orchagent logged no processFDBResolve for {} within {} s with fdb_aging_time "
                        "{} (did it age out?)".format(HOST_MAC, 4 * AGE_S + 120, AGE_S))
        resolved = syslog_since(d, marker, logged) or "no processFDBResolve logged"
        after_age = [t for t in requests if t >= aged[0] - 1]
        wait_until(20, 2, 0, lambda: not db_keys(d, "APPL_DB", RESOLVE_KEY))
        left = db_keys(d, "APPL_DB", RESOLVE_KEY)
        neigh = db_hget(d, "APPL_DB", neigh_key, "neigh").lower()
        assert after_age and neigh == HOST_MAC and not left, (
            "{} aged out and orchagent asked for {} to be resolved again ({}); the host answered {} ARP requests "
            "after the age-out; APPL_DB {} neigh '{}' (want {}); {} {}".format(
                HOST_MAC, HOST_IP, resolved.splitlines()[-1][-160:], len(after_age), neigh_key, neigh, HOST_MAC,
                RESOLVE_KEY, "still present: the resolve request was never cleared" if left else "cleared"))

        # with the aging time at AGE_S, every later age-out raises a resolve request (and a probe) of its own
        aging_back()
        aging = False
        switch = db_keys(d, "ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:*")
        if len(switch) == 1:
            wait_for(30, 1, lambda: db_hget(d, "ASIC_DB", switch[0], "SAI_SWITCH_ATTR_FDB_AGING_TIME") == (
                prev_age or "600"), "ASIC_DB FDB aging time back to {}".format(prev_age or "600"))
        try:
            answer_as_host(r, ptfadapter, lambda: fdb_port(d, VLAN_A, HOST_MAC) == r.h0 and not db_keys(
                d, "APPL_DB", RESOLVE_KEY), max_s=60)
        except AssertionError:
            pytest.fail("not exercised: {} not on {} with no {} within 60 s of the aging time going back".format(
                HOST_MAC, r.h0, RESOLVE_KEY))
        swss_apply(d, [{RESOLVE_KEY: {"mac": HOST_MAC}, "OP": "SET"}], name="vxlan_evpn_resolve")
        hand_key = True
        start = time.time()
        probes = answer_as_host(r, ptfadapter, lambda: time.time() - start >= REPROBE_WINDOW_S)
        assert 1 <= len(probes) <= REPROBE_MAX, (
            "a resolve request for {}, which the kernel has resolved, was probed {} times in {} s (at {} s): want "
            "one probe and at most {} ({})".format(
                HOST_IP, len(probes), REPROBE_WINDOW_S, [round(t - start, 1) for t in probes], REPROBE_MAX,
                "none: the request was not acted on" if not probes else "a retry of a resolved neighbour"))
    finally:
        _cleanup()
    restore.finish()


# --------------------------------------------------------------------------------------------------------------------
# a remote VNI that orchagent refuses must not swallow a later remote VNI withdraw
# --------------------------------------------------------------------------------------------------------------------
VLAN_C, VNI_REFUSED = 2102, 16777215     # the CLI accepts VNI 16777215 (1..16777215); orchagent refuses it
VLAN_C_NAME = "Vlan{}".format(VLAN_C)
REFUSED_VNI_LOG = [r".*swss#orchagent.*[Vv]ni id is too big.*", r".*swss#orchagent.*{}.*".format(VNI_REFUSED)]


def dut_vni_commands(dut_asn, vni, add):
    cmds = ["configure terminal", "router bgp {}".format(dut_asn), "address-family l2vpn evpn"]
    if add:
        cmds += ["vni {}".format(vni), "route-target import {}:{}".format(RT_ASN, vni),
                 "route-target export {}:{}".format(RT_ASN, vni), "exit-vni"]
    else:
        cmds.append("no vni {}".format(vni))
    return cmds + ["exit-address-family", "exit", "end"]


def test_remote_vni_withdraw_after_refused_vni(evpn_rig, ptfadapter, loganalyzer):
    """A Type-3 withdraw is applied after orchagent refused another remote VNI.

    The DUT maps VLAN C to VNI 16777215 and l1 serves that VNI: fdbsyncd writes l1's remote VNI for VLAN C, which
    orchagent refuses (its VNI range ends below 16777215; an orchagent that accepts it, putting l1 in VLAN C's ASIC
    flood set, leaves the case not exercised). Then l2 withdraws its Type-3 for VNI A: l2 must leave VNI A's ASIC
    flood set and its BUM must stop, as in test_type3_flood_set_per_vni. A delete that read the VNI of the last
    remote VNI request instead of its key is dropped here and leaves l2 in the flood set.
    """
    r = evpn_rig
    d = r.duthost
    if loganalyzer:
        loganalyzer[d.hostname].ignore_regex.extend(REFUSED_VNI_LOG)
    gone = r.expect_flood - {(VLAN_A, r.l2.vtep)}
    built = []
    restore = Steps("undoing VLAN C and l2's withdraw")

    def _cleanup():
        if "withdraw" in built:
            restore("vni up", lambda: r.leaves.vni("up", r.l2.name, VNI_A))
        if "bgp" in built:
            restore("bgp vni", lambda: vtysh(d, dut_vni_commands(r.dut_asn, VNI_REFUSED, False), check=False))
        if "map" in built:
            map_key = "VXLAN_TUNNEL_MAP|{}|map_{}_{}".format(VTEP_NAME, VNI_REFUSED, VLAN_C_NAME)
            if db_keys(d, "CONFIG_DB", map_key):
                restore("map del", lambda: sh(d, "sudo config vxlan map del {} {} {}".format(
                    VTEP_NAME, VLAN_C, VNI_REFUSED)))
            restore("VLAN C remote VNI gone", lambda: wait_for(
                CONVERGE, 3, lambda: not [k for k in appl_remote_vnis(d) if k[0] == VLAN_C_NAME],
                "APPL_DB remote VNIs of {} to go".format(VLAN_C_NAME)))
        if "vlan" in built and db_keys(d, "CONFIG_DB", "VLAN|{}".format(VLAN_C_NAME)):
            restore("vlan del", lambda: sh(d, "sudo config vlan del {}".format(VLAN_C)))
        if "leaf" in built:
            # tolerates a missing piece; what is left shows in the next case's gates and the leaves' teardown
            restore("leaf vni", lambda: r.leaves.vni_del(r.l1.name, VLAN_C, VNI_REFUSED, check=False))
        if "withdraw" in built:
            restore("flood set", lambda: wait_flood(r, r.expect_flood, CONVERGE, "after {}'s Type-3 returns".format(
                r.l2.name)))

    try:
        wait_flood(r, r.expect_flood, 60, "before the case")
        # each step is marked before it runs, so that the undo also covers a step that failed half way
        built.append("leaf")
        r.leaves.vni_add(r.l1.name, VLAN_C, VNI_REFUSED)
        built.append("vlan")
        sh(d, "sudo config vlan add {}".format(VLAN_C))
        built.append("map")
        sh(d, "sudo config vxlan map add {} {} {}".format(VTEP_NAME, VLAN_C, VNI_REFUSED))
        built.append("bgp")
        vtysh(d, dut_vni_commands(r.dut_asn, VNI_REFUSED, True))
        key = "VXLAN_REMOTE_VNI_TABLE:{}:{}".format(VLAN_C_NAME, r.l1.vtep)
        if not wait_until(CONVERGE, 3, 0, lambda: db_hget(d, "APPL_DB", key, "vni") == str(VNI_REFUSED)):
            pytest.fail("not exercised: APPL_DB never got {} with vni {} (l1 serves VNI {} and the DUT maps it to "
                        "{}); remote VNIs now {}".format(
                            key, VNI_REFUSED, VNI_REFUSED, VLAN_C_NAME, sorted(appl_remote_vnis(d))))
        time.sleep(5)
        flood_c = [p for p in asic_flood_members(d) if p[0] == VLAN_C]
        if flood_c:
            pytest.fail("not exercised: orchagent accepted l1's remote VNI {} (ASIC flood set of {}: {}), so no "
                        "refused request precedes the withdraw".format(VNI_REFUSED, VLAN_C_NAME, flood_c))
        built.append("withdraw")
        r.leaves.vni("down", r.l2.name, VNI_A)
        wait_for(CONVERGE, 3, lambda: (VLAN_A_NAME, r.l2.vtep) not in appl_remote_vnis(d),
                 "APPL_DB to drop {}'s remote VNI {} after the withdraw".format(r.l2.name, VNI_A))
        wait_flood(r, gone, 60, "after {}'s Type-3 withdraw, which followed the refused remote VNI {}".format(
            r.l2.name, VNI_REFUSED))
        copies = bum_from(r, ptfadapter, "rvW", "02:4c:45:00:00:35")
        got = per_leaf(r, copies, VNI_A)
        assert delivered(got["l1"]) and got["l2"] == 0, (
            "after {}'s Type-3 withdraw, VLAN {} BUM ({} frames) per leaf {}: expected l1 only. Copies: {}".format(
                r.l2.name, VLAN_A, N, got, summarize(copies)))
    finally:
        _cleanup()
    restore.finish()


# --------------------------------------------------------------------------------------------------------------------
# dataplane: outer header of encapsulated frames
# --------------------------------------------------------------------------------------------------------------------
OUTER_N = 3                # copies per inner frame: the outer header is read from each
OUTER_SRC = "02:4c:45:00:00:80"
ENCAP_PATHS = ["unicast", "flood"]


@contextlib.contextmanager
def encap_path(r, path):
    """(inner destination MAC, remote VTEPs that must get a copy): known unicast to l1's advertised MAC, or a broadcast
    in VLAN A, replicated to l1 and l2."""
    if path == "unicast":
        macs = {MAC_R1: r.l1}
        add_remote_macs(r, macs)
        body_ok = False
        try:
            yield MAC_R1, [r.l1.vtep]
            body_ok = True
        finally:
            try:
                remove_remote_macs(r, macs)
            except Exception as e:
                if body_ok:
                    raise
                logger.error("clean-up after a failed case: %s", e)   # the case's own failure stays the verdict
    else:
        yield BROADCAST_MAC, [r.l1.vtep, r.l2.vtep]


def read_outer(r, ptfadapter, vteps, name, port, pkt, t, problems):
    """Send OUTER_N of pkt on PTF port: the Outer of every DUT VxLAN copy. A VTEP that did not get its copies, a copy
    to anywhere else or in another VNI is added to problems."""
    got = send_and_read_outer(ptfadapter, port, pkt, OUTER_N, t, r.dut_vtep)
    per = {v: sum(1 for c, _o in got if c.odst == v and c.vni == VNI_A) for v in vteps}
    if not all(delivered(n, OUTER_N) for n in per.values()) or sum(per.values()) != len(got):
        problems.append("{}: copies per VTEP {} of {} sent, {} other VxLAN copies".format(
            name, per, OUTER_N, len(got) - sum(per.values())))
    return [o for _c, o in got]


def programmed_encap(duthost):
    """The one encap setting every ASIC_DB VxLAN tunnel carries (TTL/DSCP/ECN attributes that orchagent set)."""
    settings = vxlan_encap_attrs(duthost)
    assert len(settings) == 1, "the ASIC_DB VxLAN tunnels do not share one encap setting: {}".format(settings)
    return settings[0]


@pytest.mark.parametrize("path", ENCAP_PATHS)
def test_l2_encap_outer_header(evpn_rig, ptfadapter, path):
    """The outer header of an encapsulated frame is what was configured, whatever the inner frame is.

    Inner frames: IPv4 with TTL 64, 1 and 255, IPv6 with hop limit 2, a non-IP frame, a 1514-byte IPv4 frame, and an
    IPv4 frame from the tagged member H1. For every copy: the outer TTL is the value orchagent programmed on the
    tunnels (pipe mode: independent of the inner TTL), the frame is not fragmented, the IPv4 checksum and lengths are
    right, the UDP destination port is 4789 (a copy to another port is not counted as one), the UDP checksum is zero
    or correct, the VXLAN header has only the I flag set, reserved bits zero and the VLAN's VNI, and the inner frame
    is the frame sent, bit for bit, without its access tag. Not asserted (the encapsulator's choice): IP
    identification, and DF (neither the VXLAN RFC nor a SAI tunnel attribute defines it); the DF values seen are
    logged per inner frame. On a virtual switch the kernel VxLAN netdev sets the outer TTL, so the programmed TTL is
    not compared.
    """
    r = evpn_rig
    with encap_path(r, path) as (dst, vteps):
        cfg = programmed_encap(r.duthost)
        assert cfg.get("TTL_MODE") == "SAI_TUNNEL_TTL_MODE_PIPE_MODEL" and cfg.get("TTL_VAL", "").isdigit(), (
            "the VxLAN tunnels carry no pipe-mode encap TTL in ASIC_DB ({}): no outer TTL is specified".format(cfg))
        ttl = int(cfg["TTL_VAL"])
        frames = [(name, r.p_h0, flow_frame(t, dst, OUTER_SRC, **kw), t, None) for name, t, kw in (
            ("IPv4 TTL 64", tag("ohA"), {}),
            ("IPv4 TTL 1", tag("ohB"), {"ttl": 1}),
            ("IPv4 TTL 255", tag("ohC"), {"ttl": 255}),
            ("IPv6 hop limit 2", tag("ohD"), {"v6": True, "ttl": 2}),
            ("IPv4, 1514 bytes", tag("ohE"), {"size": 1514}))]
        t = tag("ohF")
        frames.append(("non-IP", r.p_h0, probe_frame(t, dst, OUTER_SRC), t, None))
        t = tag("ohG")
        frames.append(("IPv4 from a tagged member", r.p_h1, flow_frame(t, dst, OUTER_SRC, vlan=VLAN_A), t,
                       flow_frame(t, dst, OUTER_SRC)))
        problems, df, ttls = [], {}, set()
        for name, port, pkt, t, untagged in frames:
            want = bytes(untagged if untagged is not None else pkt)
            for o in read_outer(r, ptfadapter, vteps, name, port, pkt, t, problems):
                df.setdefault(name, set()).add(int(o.df))
                ttls.add(o.ttl)
                bad = []
                if o.ttl != ttl and not r.vs:
                    bad.append("outer TTL {} (programmed {})".format(o.ttl, ttl))
                if o.fragmented:
                    bad.append("fragmented")
                if not o.ip_ok:
                    bad.append("IPv4 header checksum or total length wrong")
                if not o.udp_ok:
                    bad.append("UDP length wrong, or a UDP checksum that is neither zero nor correct")
                if o.flags != 0x08 or o.reserved:
                    bad.append("VXLAN flags 0x{:02x}, reserved bits 0x{:x}".format(o.flags, o.reserved))
                if o.vni != VNI_A:
                    bad.append("VNI {}".format(o.vni))
                if o.inner != want:
                    bad.append("inner frame is not the frame sent{} ({} bytes for {}; starts {})".format(
                        " without its tag" if untagged is not None else "", len(o.inner), len(want),
                        o.inner[:38].hex()))
                if bad and "{}: {}".format(name, "; ".join(bad)) not in problems:
                    problems.append("{}: {}".format(name, "; ".join(bad)))
        logger.info("outer DF bit per inner frame (%s, not asserted): %s; outer TTLs %s", path,
                    {k: sorted(v) for k, v in df.items()}, sorted(ttls))
        assert not problems, "outer header ({}, tunnels programmed {}): {}".format(path, cfg, " | ".join(problems))


@pytest.mark.parametrize("path", ENCAP_PATHS)
def test_l2_encap_outer_dscp_ecn(evpn_rig, ptfadapter, path):
    """The outer DSCP and ECN of an encapsulated frame follow the modes programmed on the tunnels.

    orchagent sets neither mode, so the SAI defaults apply: uniform DSCP (the outer DSCP is the inner frame's) and
    standard ECN (the outer ECN is the inner frame's); a non-IP inner frame gets DSCP 0 and ECN 0. Where ASIC_DB
    carries a pipe DSCP mode, the outer DSCP is the programmed value instead. On a virtual switch the kernel VxLAN
    netdev encapsulates, not a SAI tunnel, so there only the ASIC_DB modes are checked.
    """
    r = evpn_rig
    with encap_path(r, path) as (dst, vteps):
        cfg = programmed_encap(r.duthost)
        ecn_mode = cfg.get("ECN_MODE", "SAI_TUNNEL_ENCAP_ECN_MODE_STANDARD")
        assert ecn_mode == "SAI_TUNNEL_ENCAP_ECN_MODE_STANDARD", (
            "the VxLAN tunnels carry ECN mode {}: the outer ECN is not specified by it".format(ecn_mode))
        pipe = cfg.get("DSCP_MODE") == "SAI_TUNNEL_DSCP_MODE_PIPE_MODEL"
        if r.vs:    # the kernel VxLAN netdev encapsulates there, not these tunnels: only their modes are read
            dscp_mode = cfg.get("DSCP_MODE", "SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL")
            assert dscp_mode == "SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL" or (pipe and cfg.get("DSCP_VAL", "").isdigit()), (
                "the VxLAN tunnels carry DSCP mode {} ({}): the outer DSCP is not specified by it".format(
                    dscp_mode, cfg))
            return
        frames = [(name, flow_frame(t, dst, OUTER_SRC, **kw), t) for name, t, kw in (
            ("IPv4 DSCP 0", tag("oqA"), {}),
            ("IPv4 DSCP 46", tag("oqB"), {"tos": 0xb8}),
            ("IPv4 DSCP 10 ECT(1)", tag("oqC"), {"tos": 0x29}),
            ("IPv4 DSCP 46 ECT(0)", tag("oqD"), {"tos": 0xba}),
            ("IPv4 DSCP 0 CE", tag("oqE"), {"tos": 0x03}),
            ("IPv6 DSCP 46 ECT(1)", tag("oqF"), {"v6": True, "tos": 0xb9}))]
        t = tag("oqG")
        frames.append(("non-IP", probe_frame(t, dst, OUTER_SRC), t))
        problems = []
        for name, pkt, t in frames:
            tos = inner_tos(pkt) or 0
            want = (int(cfg.get("DSCP_VAL", 0)) if pipe else tos >> 2, tos & 3)
            got = sorted(set((o.dscp, o.ecn) for o in read_outer(r, ptfadapter, vteps, name, r.p_h0, pkt, t,
                                                                 problems)))
            if got != [want]:
                problems.append("{}: outer (DSCP, ECN) {}, want {}".format(name, got, want))
        assert not problems, "outer DSCP/ECN ({}, tunnels programmed {}; {} DSCP, standard ECN): {}".format(
            path, cfg, "pipe" if pipe else "uniform", " | ".join(problems))


@pytest.mark.parametrize("path", ENCAP_PATHS)
def test_l2_encap_udp_source_port(evpn_rig, ptfadapter, path):
    """The outer UDP source port carries inner-flow entropy: one value per inner flow, different across flows.

    Eight IPv4 flows that differ in addresses and L4 ports, each sent in two separate bursts. Every copy of one flow
    toward one VTEP has the same, non-zero source port, and the eight flows use at least four different ones. The
    value itself comes from the encapsulator's hash (the ASIC; on a virtual switch the kernel VxLAN netdev) and is
    not asserted.
    """
    r = evpn_rig
    flows = [dict(ips=("192.168.{}.1".format(80 + i), "192.168.{}.2".format(90 + i)), sport=1000 + 37 * i,
                  dport=2000 + 53 * i) for i in range(8)]
    with encap_path(r, path) as (dst, vteps):
        problems, ports = [], {}
        for burst in ("a", "b"):
            for i, kw in enumerate(flows):
                t = tag("os{}{}".format(burst, i))
                pkt = flow_frame(t, dst, OUTER_SRC, **kw)
                got = send_and_read_outer(ptfadapter, r.p_h0, pkt, OUTER_N, t, r.dut_vtep)
                for v in vteps:
                    seen = [o.sport for c, o in got if c.odst == v and c.vni == VNI_A]
                    if not delivered(len(seen), OUTER_N):
                        problems.append("flow {} burst {}: {} of {} copies to {}".format(
                            i, burst, len(seen), OUTER_N, v))
                    ports.setdefault((i, v), set()).update(seen)
        unstable = {k: sorted(s) for k, s in ports.items() if len(s) != 1 or 0 in s}
        if unstable:
            problems.append("source port not one non-zero value per (flow, VTEP): {}".format(unstable))
        for v in vteps:
            distinct = set().union(*(s for (_i, vtep), s in ports.items() if vtep == v))
            if len(distinct) < len(flows) // 2:
                problems.append("{} flows toward {} use only the source ports {}".format(
                    len(flows), v, sorted(distinct)))
        assert not problems, "outer UDP source port ({}): {}. Per (flow, VTEP): {}".format(
            path, " | ".join(problems), {k: sorted(s) for k, s in sorted(ports.items())})


# --------------------------------------------------------------------------------------------------------------------
# dataplane: decap
# --------------------------------------------------------------------------------------------------------------------
DECAP_OUTER = {"ttl": 9, "tos": 0x28}     # outer TTL 9, DSCP 10, not ECN-capable: unlike every inner header below
OTHER_VNI = 12999                         # mapped to no VLAN


def inject_from_l1(r, ptfadapter, inner, t, n=N):
    """Send inner as VxLAN in VNI A from l1's VTEP toward the DUT's VTEP, on l1's port; the decap must stay in
    hardware (kernel_gate)."""
    pkt = vxlan_frame(inner, r.router_mac, INJ_OUTER_SMAC, r.l1.vtep, r.dut_vtep, VNI_A)
    before = kernel_rx_packets(r.duthost, r.kvx)
    copies = send_and_count(ptfadapter, r.l1.ptf_port, pkt, n, t)
    kernel_gate(r, before, n, "decap of {}".format(t))
    return copies


def ip_fields(raw):
    """(DSCP, ECN, TTL or hop limit, the frame with those and the IPv4 checksum zeroed, IPv4 checksum valid) of an
    untagged IPv4 or IPv6 frame; None for any other frame."""
    b = bytearray(raw)
    etype = (b[12] << 8) | b[13]
    if etype == 0x0800:
        ihl = (b[14] & 0x0f) * 4
        csum = sum((b[i] << 8) | b[i + 1] for i in range(14, 14 + ihl, 2))
        while csum >> 16:
            csum = (csum & 0xffff) + (csum >> 16)
        tos, ttl = b[15], b[22]
        b[15] = b[22] = b[24] = b[25] = 0
        return tos >> 2, tos & 3, ttl, bytes(b), csum == 0xffff
    if etype == 0x86dd:
        tc, ttl = ((b[14] & 0x0f) << 4) | (b[15] >> 4), b[21]
        b[14] &= 0xf0
        b[15] &= 0x0f
        b[21] = 0
        return tc >> 2, tc & 3, ttl, bytes(b), True
    return None


def test_l2_decap_inner_frame_unchanged(evpn_rig, ptfadapter):
    """A decapsulated frame is delivered as it was encapsulated; only its DSCP and TTL may follow the outer header.

    VxLAN from l1 with outer TTL 9 and DSCP 10 (not ECN-capable) to a MAC learned on the untagged member H0, the inner
    frame: IPv4 TTL 64 DSCP 46 ECT(1), IPv4 TTL 2 DSCP 0 CE, IPv6 hop limit 2 DSCP 46 ECT(0), non-IP. The frame is
    bridged: every byte but the IP DSCP and TTL (and the IPv4 checksum, which must stay valid) arrives as sent, and
    the ECN is the inner one (RFC 6040 with a not-ECN-capable outer). The DSCP and the TTL are each the inner value,
    or the outer value where the tunnels' decap mode for it is uniform (the SAI default); which one is logged.
    """
    r = evpn_rig
    local = "02:4c:45:00:00:a0"
    learn_on_h0(r, ptfadapter, local)
    modes = {k: v for a in AsicView(r.duthost, ("TUNNEL",)).objs["TUNNEL"].values()
             if a.get("SAI_TUNNEL_ATTR_TYPE") == "SAI_TUNNEL_TYPE_VXLAN"
             for k, v in a.items() if k.startswith("SAI_TUNNEL_ATTR_DECAP_") and k.endswith("_MODE")}
    pipe_dscp = modes.get("SAI_TUNNEL_ATTR_DECAP_DSCP_MODE") == "SAI_TUNNEL_DSCP_MODE_PIPE_MODEL"
    pipe_ttl = modes.get("SAI_TUNNEL_ATTR_DECAP_TTL_MODE") == "SAI_TUNNEL_TTL_MODE_PIPE_MODEL"
    frames = [(name, flow_frame(t, local, MAC_R1_PEER, **kw), t) for name, t, kw in (
        ("IPv4 TTL 64 DSCP 46 ECT(1)", tag("dqA"), {"tos": 0xb9}),
        ("IPv4 TTL 2 DSCP 0 CE", tag("dqB"), {"ttl": 2, "tos": 0x03}),
        ("IPv6 hop limit 2 DSCP 46 ECT(0)", tag("dqC"), {"v6": True, "ttl": 2, "tos": 0xba}))]
    t = tag("dqD")
    frames.append(("non-IP", probe_frame(t, local, MAC_R1_PEER), t))
    problems, seen = [], {}
    try:
        for name, inner, t in frames:
            pkt = vxlan_frame(inner, r.router_mac, INJ_OUTER_SMAC, r.l1.vtep, r.dut_vtep, VNI_A, **DECAP_OUTER)
            needle, want = t.encode(), bytes(inner)
            before = kernel_rx_packets(r.duthost, r.kvx)
            got = collect(ptfadapter, lambda: testutils.send(ptfadapter, r.l1.ptf_port, pkt, count=OUTER_N),
                          lambda raw: raw if needle in raw else None)
            why = "" if r.vs else kernel_path(r.duthost, r.kvx, before, OUTER_N)
            at_h0 = [raw for c, raw in got if c.kind == "native" and c.port == r.p_h0 and c.vid is None]
            if why or not delivered(len(at_h0), OUTER_N) or len(got) != len(at_h0):
                problems.append("{}: {} of {} untagged at {}, {} copies elsewhere{}".format(
                    name, len(at_h0), OUTER_N, r.h0, len(got) - len(at_h0), "; " + why if why else ""))
            sent = ip_fields(want)
            for raw in at_h0:
                out = ip_fields(raw)
                if sent is None:
                    ok = raw == want
                else:
                    seen.setdefault(name, set()).add("DSCP {} TTL {}".format(out[0], out[2]) if out else "not IP")
                    ok = (out is not None and out[3] == sent[3] and out[4] and out[1] == sent[1] and
                          out[0] in ({sent[0]} if pipe_dscp else {sent[0], DECAP_OUTER["tos"] >> 2}) and
                          out[2] in ({sent[2]} if pipe_ttl else {sent[2], DECAP_OUTER["ttl"]}))
                if not ok:
                    problems.append("{}: delivered {} for sent {}".format(name, raw[:62].hex(), want[:62].hex()))
                    break
    finally:
        flush_fdb(r.duthost, "VLAN", str(VLAN_A))
    logger.info("decap with outer %s, tunnel decap modes %s: inner DSCP/TTL delivered %s", DECAP_OUTER,
                modes or "not set (SAI default uniform)", {k: sorted(v) for k, v in seen.items()})
    assert not problems, "decap with outer {} (tunnel decap modes {}): {}".format(
        DECAP_OUTER, modes or "not set", " | ".join(problems))


@pytest.mark.parametrize("what", ["unmapped_vni", "other_destination"])
def test_l2_decap_rejects(evpn_rig, ptfadapter, what):
    """A VxLAN frame that is not for this VTEP and a mapped VNI is not delivered to the VLAN.

    unmapped_vni: a broadcast from l1 to the DUT's VTEP in a VNI with no VLAN. other_destination: the same frame in
    VNI A, addressed to l2's VTEP: it is routed on to l2 as an ordinary IP packet, still encapsulated, which is also
    the proof that the DUT received it. The control in both arms is the same broadcast for the DUT's VTEP in VNI A,
    which every member of VLAN A gets.
    """
    r = evpn_rig
    t = tag("njC")
    ctrl, tx = capture(r, lambda: inject_from_l1(r, ptfadapter, probe_frame(t, BROADCAST_MAC, MAC_R1_PEER), t),
                       live=[r.h0])
    at_h0 = native_on(ctrl, r.p_h0, None)
    ok_h1, got_h1 = member_delivered(r, ctrl, tx, r.h1)
    assert delivered(at_h0) and ok_h1, (
        "control: a broadcast from l1 ({}) in VNI {} reached {} {} of {} times, tagged {} {}. Copies: {}".format(
            r.l1.vtep, VNI_A, r.h0, at_h0, N, r.h1, got_h1, summarize(ctrl)))
    t = tag("njX")
    inner = probe_frame(t, BROADCAST_MAC, MAC_R1_PEER)
    if what == "unmapped_vni":
        pkt = vxlan_frame(inner, r.router_mac, INJ_OUTER_SMAC, r.l1.vtep, r.dut_vtep, OTHER_VNI)
    else:
        pkt = vxlan_frame(inner, r.router_mac, INJ_OUTER_SMAC, r.l1.vtep, r.l2.vtep, VNI_A)
    copies, tx = capture(r, lambda: send_and_count(ptfadapter, r.l1.ptf_port, pkt, N, t),
                         live=[r.l2.dut_port] if what == "other_destination" else ())
    at_members = native_on(copies, r.p_h0) + member_flood(r, copies, tx)
    emitted = len(vxlan_to(copies, r.dut_vtep))
    routed = sum(1 for c in copies if c.kind == "vxlan" and c.osrc == r.l1.vtep and c.odst == r.l2.vtep and
                 c.vni == VNI_A and c.port == r.l2.ptf_port)
    problems = []
    if at_members or emitted:
        problems.append("{} copies on the VLAN's members, {} VxLAN copies from the DUT's VTEP".format(
            at_members, emitted))
    if what == "other_destination" and not delivered(routed):
        problems.append("{} of {} routed on toward l2 ({}) still encapsulated".format(routed, N, r.l2.vtep))
    assert not problems, "VxLAN from l1 to {} VNI {} ({}): {}. Copies: {}".format(
        r.l2.vtep if what == "other_destination" else r.dut_vtep,
        OTHER_VNI if what == "unmapped_vni" else VNI_A, what, "; ".join(problems), summarize(copies))


# --------------------------------------------------------------------------------------------------------------------
# dataplane: a tagged member keeps the tag
# --------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("arm", ["local_bum", "decap_bum", "decap_unicast"])
def test_tagged_member_keeps_tag(evpn_rig, ptfadapter, arm):
    """In a VNI-mapped VLAN, copies to the tagged member H1 carry the VLAN tag; the untagged member H0 gets none.

    The untagged member receiving untagged copies, or the VxLAN copy to l1, is the control: it shows the frames were
    delivered, so a missing tag on the tagged member is the defect and not a lost frame. Where the PTF cannot see
    tagged DUT frames (rig docstring), the tagged member passes when the DUT transmitted one copy per frame there and
    the PTF saw no untagged copy: a stripped tag reaches the PTF, so the defect stays visible (a wrong VID would not
    be).
    """
    r = evpn_rig
    t = tag("tk" + {"local_bum": "LB", "decap_bum": "DB", "decap_unicast": "DU"}[arm])
    local = "02:4c:45:00:00:61"
    try:
        if arm == "local_bum":
            copies, tx = capture(r, lambda: send_and_count(
                ptfadapter, r.p_h0, probe_frame(t, BROADCAST_MAC, "02:4c:45:00:00:60"), N, t))
            expect = {r.h1: VLAN_A}
            ctrl = len(vxlan_to(copies, r.dut_vtep, r.l1.vtep, VNI_A))
            assert delivered(ctrl), "control: local broadcast reached l1 {} of {} times. Copies: {}".format(
                ctrl, N, summarize(copies))
        elif arm == "decap_bum":
            frame = probe_frame(t, BROADCAST_MAC, MAC_R1_PEER)
            copies, tx = capture(r, lambda: inject_from_l1(r, ptfadapter, frame, t))
            expect = {r.h0: None, r.h1: VLAN_A}
        else:
            learn_mac(ptfadapter, r.duthost, r.p_h1, r.h1, VLAN_A, local, tag("learn"), VLAN_A)
            copies, tx = capture(r, lambda: inject_from_l1(r, ptfadapter, probe_frame(t, local, MAC_R1_PEER), t))
            expect = {r.h1: VLAN_A}
            stray = native_on(copies, r.p_h0)
            assert stray == 0, "decap unicast to {} on {} also reached {} {} times. Copies: {}".format(
                local, r.h1, r.h0, stray, summarize(copies))
    finally:
        flush_fdb(r.duthost, "VLAN", str(VLAN_A))
    got = {}
    for h, vid in expect.items():
        if tx is None or vid is None:
            got[h] = {"right": native_on(copies, r.port[h], vid), "any": native_on(copies, r.port[h])}
            got[h]["ok"] = delivered(got[h]["right"]) and got[h]["any"] == got[h]["right"]
        else:
            got[h] = {"dut_tx": tx[h], "untagged_at_ptf": native_on(copies, r.port[h], None),
                      "other_tag_at_ptf": native_on(copies, r.port[h]) - native_on(copies, r.port[h], vid)}
            got[h]["ok"] = tx_delivered(tx[h]) and got[h]["other_tag_at_ptf"] == 0
    assert all(g["ok"] for g in got.values()), (
        "tag handling ({}): expected {} (None = untagged); per member: {}{}. Copies: {}".format(
            arm, expect, got, "" if tx is None else " (the tagged member read from the DUT TX counters: {})".format(
                r.tagged_why), summarize(copies)))
