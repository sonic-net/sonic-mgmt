"""Integrated routing and bridging over VxLAN: a VNI-mapped VLAN with an SVI, its remote hosts behind BGP EVPN leaves.

Topology t0 or single-ASIC t2 or lt2. The DUT is a VTEP on its Loopback0. Two FRR leaves on the test server
(files/vxlan_evpn_l2_leaves.sh), l1 (remote VTEP A) and l2 (remote VTEP B), peer eBGP ipv4 + l2vpn evpn with the DUT
over one of its ports, which becomes a routed port with a /29 that holds the DUT's and both leaves' addresses: two
BGP neighbours on one segment, each announcing its own VTEP, so the DUT reaches A and B through two next hops on that
port. Both leaves are joined to the port's PTF interface by tc (what the DUT sends on the port reaches both leaves,
and each keeps what is addressed to its uplink MAC), so the PTF sees every frame the DUT sends to either leaf, and
sends VxLAN toward the DUT as either leaf (its VTEP as the outer source). A copy the DUT encapsulates belongs to a
leaf when its outer destination is that leaf's VTEP and its outer destination MAC that leaf's uplink MAC, on that
port. The remote state reaches the DUT through the shipped path (BGP EVPN -> zebra -> kernel -> fdbsyncd /
neighsyncd / fpmsyncd -> APPL_DB -> orchagent), so the kernel also encapsulates the switch's own ARP, ND and ICMP:
  * type-3: l1 serves VNI 12010, so VTEP A is the flood list of Vlan2010 (l2 joins it in the MAC move case only);
  * type-2 MAC: a host's MAC on l1's host port; type-2 MAC/IP: its IPv4 and IPv6 neighbours on l1's SVI in the VLAN
    as well (zebra installs the remote MAC, then the neighbour);
  * VRF variant: a VRF with the L3 VNI on both leaves. l1 exports an IPv4 prefix (type-5); l2 has a host in an L2 VNI
    that only l2 has, with its SVI in that VRF, so the host's type-2 MAC/IP routes are IPv4 and IPv6 host routes over
    the L3 VNI (symmetric IRB). The remote router MAC is each leaf's own, read from the leaf.
One remote host is installed in the DUT's kernel instead, as zebra would install it but in an order zebra never uses
(test_irb_route_into_vlan[*][remote_neigh_first]). Every case sends 40 frames and counts every copy on every PTF port.

Rig (module fixture, built once per variant) on four oper-up untagged members of the t0's first such VLAN, or on a t2
on neighbor-facing ports that vxlan_l2_helpers.access_ports borrows into a Vlan1000 and restores after the module:
  * one of them is the routed port to l1 and l2;
  * Vlan2010 <-> VNI 12010 with an SVI (IPv4 and IPv6); local hosts H0 and H2 are untagged members;
  * Vlan2011, no VNI, with an SVI; local host H1 is an untagged member.
  Routed traffic from outside enters on an uplink, a next hop of the default route (the cases that send it skip
  when no such port is a PTF port).
  default     both SVIs in the default VRF
  anycast_gw  the default variant with a static anycast gateway MAC on the Vlan2010 SVI
  vrf_l3vni   both SVIs in a VRF that has an L3 VNI (Vlan2110 <-> VNI 13110); IPv4 and IPv6 host routes through VTEP B
              and an IPv4 prefix through VTEP A over the L3 VNI, from the leaves

Cases (each negative reading has a positive control in the same case):
  test_irb_decap_then_route[v4|v6][routed_on|local_vlan]
           a host behind A sends to the gateway MAC: the frame is decapsulated and routed, to an uplink (in the VRF
           variant: to a host route over the L3 VNI) and to a local host in the other VLAN
  test_irb_route_into_vlan[v4|v6][local|remote_neigh_first|remote_mac_first]
           routed traffic into Vlan2010 reaches a local host, and a host behind A encapsulated with the L2 VNI, in
           both orders in which the host's neighbour and its remote MAC can arrive; forwarded by hardware.
           remote_mac_first: l1 advertises the host (type-2 MAC/IP). remote_neigh_first: the host is installed in the
           DUT's kernel, the neighbour before the MAC: zebra always installs the MAC of a type-2 MAC/IP route before
           its neighbour, so the control plane cannot produce this order
  test_irb_remote_host_resolves_gateway[arp_broadcast|arp_unicast|ns_multicast|ns_unicast]
           a host behind A resolves the SVI address: every request is answered, encapsulated to A
  test_irb_switch_resolves_remote_host[v4|v6]
           the switch resolves a host behind A itself, and once l1 advertises the host's MAC routed traffic reaches it
  test_irb_arp_nd_bridged[remote_to_local|local_to_remote|local_to_local][arp_request|arp_reply|ns_multicast|na]
           ARP and ND between two hosts of Vlan2010 are bridged unchanged, exactly once, although the VLAN has an SVI
           (a unicast neighbour advertisement: at most twice, as on any VLAN with an SVI; see the case)
  test_irb_ping_gateway[v4|v6][local|remote]
           a local host and a host behind A ping the SVI address and get every reply
  test_irb_l3vni_encap[host_v4|host_v6|prefix_v4], test_irb_l3vni_decap[v4_from_b|v6_from_b|v4_from_a]
           symmetric IRB (VRF variant): a local host reaches a host route and a prefix over the L3 VNI, and L3 VNI
           traffic from a remote VTEP is routed to a local host
  test_irb_vrf_gateway_traffic_stays_in_vrf[v4|v6]
           (VRF variant) echo requests from a host behind A to the SVI address are answered through the tunnel, and
           no copy leaves the switch unencapsulated
  test_irb_remote_mac_withdrawn_and_readvertised[v4|v6]
           l1 withdraws a host and advertises it again while routed traffic to it runs
  test_irb_routed_traffic_follows_mac_move[v4|v6]
           a host moves from a local port to l1 (VTEP A), to l2 (VTEP B) and back: routed traffic to it goes where its
           MAC now is after every move, and never to where it was

Hardware forwarding is asserted without vendor commands: the destination's neighbour and next hop are in ASIC_DB, and
during the stream the kernel did not transmit on the VLAN netdevs (and on the VxLAN netdevs, for a destination behind
a remote VTEP), did not receive on the VxLAN netdevs and did not receive the stream on the ingress port. A stream the
kernel forwarded moves those counters by its 40 frames;
the switch's own traffic moves them by about 9 in the same window, so the threshold is 19 (vxlan_irb_helpers.py,
KERNEL_SLACK): a counter that moved by 20 or more reads as kernel forwarding. A neighbour refresh pass of the switch
can exceed that on the VLAN and VxLAN netdevs by itself, so where the ingress port is known those counters count only
together with the ingress port's: the kernel cannot forward a stream it did not receive.

On a virtual switch (asic_type vs) the kernel is the dataplane: every case runs with its APPL_DB, ASIC_DB and traffic
readings, and the "forwarded by hardware" gate on the kernel netdev counters is not applied (nor the rig's per-port
ingress check, nor a remote VTEP's oper status, which a virtual switch does not report: its ASIC_DB tunnel is read).

With the remote MAC installed before the neighbour, an orchagent that leaves the neighbour out of ASIC_DB while the
MAC is behind a VxLAN tunnel gives the traffic no hardware path: the remote_mac_first arm fails on that. The withdraw
/ advertise-again and MAC move cases, whose remote hosts the leaves advertise (MAC first), run every step in that
state and fail at the end, naming it.

The leaves run the stock FRR image (vxlan_evpn_l2_helpers.DEFAULT_LEAF_IMAGES; VXLAN_EVPN_LEAF_IMAGE replaces the list).
The module skips when the test server has none of them and cannot pull one, and the VRF variant skips when the test
server's kernel cannot make a VRF device (the leaves' L3 VNI needs one).
"""
import contextlib
import itertools
import json
import logging
import re
import time
from types import SimpleNamespace

import ptf.testutils as testutils
import pytest

from tests.common.helpers.sonic_db import redis_hgetall
from tests.common.utilities import get_inventory_files, wait_until
from tests.vxlan.vxlan_irb_helpers import (
    Native,
    Vxlan,
    asic_l3,
    asic_route,
    capture_frames,
    decode,
    describe,
    echo_request,
    encap_to,
    from_dut,
    ip_bytes,
    is_echo_reply,
    is_resolve_request,
    judge_routed,
    l3_of,
    leaf_later,
    leaf_later_result,
    same_ip,
    kernel_counters,
    kernel_delta,
    kernel_forwarded,
    kernel_neigh,
    local_neigh_cmd,
    mac_bytes,
    neigh_del_cmd,
    neigh_resolved,
    remote_mac_cmd,
    remote_mac_del_cmd,
    remote_neigh_cmd,
    resolve_reply,
    resolve_reply_mac,
    resolve_request,
    route_ports,
    send_paced,
    want_text,
    with_trailer,
)
from tests.vxlan.vxlan_l2_helpers import (
    BROADCAST_MAC,
    KNOWN_HARMLESS_LOG,
    L2NHG_DEL_NOISE_LOG,
    N,
    VTEP_NAME,
    AsicView,
    Steps,
    access_ports,
    asic_count,
    asic_counts,
    db_hget,
    db_keys,
    delivered,
    fdb_port,
    flow_frame,
    flush_fdb,
    kernel_vxlan_netdev,
    learn_mac,
    log_clean,
    make_tagger,
    map_entries_of,
    probe_frame,
    raw_payloads,
    remote_fdb_dip,
    remote_vtep_oper_up,
    sh,
    stream_and_count,
    swss_apply,
    vxlan_frame,
    vxlan_tunnels_to,
    wait_for,
    wait_state,
)
from tests.vxlan.vxlan_evpn_l2_helpers import (
    Leaf,
    Leaves,
    RigBuild,
    appl_remote_mac_vtep,
    appl_remote_vnis,
    assert_clean_start,
    check_ingress_once,
    check_leaf_vteps_unrouted,
    dut_has_advertise_all_vni,
    pick_rig_ports,
    resolve_leaf_image,
    rig_preflight,
    vtysh,
)

pytestmark = [
    pytest.mark.topology("t0", "t2", "lt2"),
]

logger = logging.getLogger(__name__)

VLAN_ID, OTHER_VID, L3_VID = 2010, 2011, 2110
VLAN, OTHER_VLAN, L3_VLAN = "Vlan{}".format(VLAN_ID), "Vlan{}".format(OTHER_VID), "Vlan{}".format(L3_VID)
VNI, L3VNI = 12010, 13110
VRF = "Vrf-irb"
RT_ASN = 65000
# name, ASN, VTEP, leaf address, DUT address, (VLAN, VNI) served from the start; both leaves on the DUT's one routed
# port, in 10.99.0.8/29
LEAF_PLAN = [
    ("l1", 65221, "10.255.95.1", "10.99.0.10", "10.99.0.9", [(VLAN_ID, VNI)]),
    ("l2", 65223, "10.255.96.1", "10.99.0.11", "10.99.0.9", []),
]
LEAF_PLEN = 29
LEAF_SVI = {"l1": {4: "192.168.210.241", 6: "fc00:210::f1"}, "l2": {4: "192.168.210.242", 6: "fc00:210::f2"}}
LEAF_VRF = "vrf-irb"                                        # the leaves' VRF of the L3 VNI
B_VID, B_VNI = 2220, 12220                                  # l2's own L2 VNI, in its VRF (VRF variant)
B_SVI = {4: "192.168.220.1", 6: "fc00:220::1"}
SVI = {4: "192.168.210.1", 6: "fc00:210::1"}
OTHER_SVI = {4: "192.168.211.1", 6: "fc00:211::1"}
PLEN = {4: 24, 6: 64}
HOST = {  # name: (MAC, IPv4, IPv6)
    "h0": ("02:4c:52:00:00:20", "192.168.210.20", "fc00:210::20"),    # local, Vlan2010
    "h2": ("02:4c:52:00:00:22", "192.168.210.22", "fc00:210::22"),    # local, Vlan2010
    "h1": ("02:4c:52:00:01:21", "192.168.211.21", "fc00:211::21"),    # local, Vlan2011
    "rn": ("02:4c:52:0a:00:50", "192.168.210.50", "fc00:210::50"),    # behind A (l1): routed-to host
    "rk": ("02:4c:52:0a:00:51", "192.168.210.51", "fc00:210::51"),    # behind A, in the DUT's kernel only
    "q": ("02:4c:52:0a:00:52", "192.168.210.52", "fc00:210::52"),     # behind A: the requester
    "u": ("02:4c:52:0a:00:53", "192.168.210.53", "fc00:210::53"),     # behind A: the switch resolves it
    "wd": ("02:4c:52:0a:00:54", "192.168.210.54", "fc00:210::54"),    # behind A: withdrawn and advertised again
    "mv": ("02:4c:52:0a:00:55", "192.168.210.55", "fc00:210::55"),    # moves (IPv4 arm): H2's port, A, B
    "mw": ("02:4c:52:0a:00:56", "192.168.210.56", "fc00:210::56"),    # moves (IPv6 arm)
}
LOCAL = {"h0": VLAN, "h2": VLAN, "h1": OTHER_VLAN}
ROUTED = {4: "192.0.2.77", 6: "2001:db8:77::7"}             # beyond the default route
EXT_SRC = {4: "192.0.2.9", 6: "2001:db8:9::9"}               # source of routed traffic that enters on an uplink
EXT_SMAC = "02:4c:52:ee:00:02"
INJ_OUTER_SMAC = "02:4c:52:ee:00:01"                        # outer source MAC of injected VxLAN frames
ANYCAST_MAC = "00:11:22:33:44:55"
L3_HOST = {4: "192.168.220.60", 6: "fc00:220::60"}          # behind B: host routes over the L3 VNI
L3_HOST_MAC = "02:4c:52:0b:00:60"
L3_PREFIX, L3_PREFIX_DST = "198.51.100.0/24", "198.51.100.7"  # behind A: a prefix over the L3 VNI
L3_ROUTES = {"host_v4": (L3_HOST[4] + "/32", "l2"), "host_v6": (L3_HOST[6] + "/128", "l2"),
             "prefix_v4": (L3_PREFIX, "l1")}
CONVERGE = 120             # seconds for BGP / EVPN state to settle

BASELINE_TYPES = ("TUNNEL", "TUNNEL_MAP_ENTRY", "VLAN", "VLAN_MEMBER", "BRIDGE_PORT", "ROUTER_INTERFACE",
                  "VIRTUAL_ROUTER")
HARMLESS_LOG = KNOWN_HARMLESS_LOG + L2NHG_DEL_NOISE_LOG

# The rig is a module fixture that takes its variant as an indirect parameter. The VRF variant is first in the list
# so that it has the same parameter index in the cases that run only there, and pytest builds it once for both.
VARIANTS = ["vrf_l3vni", "default", "anycast_gw"]
EVERY_RIG = pytest.mark.parametrize("rig", VARIANTS, indirect=True)
VRF_RIG = pytest.mark.parametrize("rig", VARIANTS[:1], indirect=True)
FAMILY = pytest.mark.parametrize("v", [4, 6], ids=["v4", "v6"])

_tagger = make_tagger("VXIR")
_tags = itertools.count()


def tag(name):
    """A payload tag no other stream of this run carries, so a late copy of an earlier stream is never counted."""
    return _tagger("{}{}.".format(name, next(_tags)))


def addr(host, v):
    return HOST[host][1 if v == 4 else 2]


def mac_of(host):
    return HOST[host][0]


def leaf_text(lf):
    return "VTEP {} ({}, {})".format("A" if lf.name == "l1" else "B", lf.name, lf.vtep)


# --------------------------------------------------------------------------------------------------------------------
# rig
# --------------------------------------------------------------------------------------------------------------------
RIG_STATE = (("CONFIG_DB", "VRF|{}".format(VRF)),) + tuple(
    ("CONFIG_DB", "VLAN_INTERFACE|{}*".format(vlan)) for vlan in (VLAN, OTHER_VLAN, L3_VLAN)) + tuple(
    ("CONFIG_DB", "VLAN|{}".format(vlan)) for vlan in (OTHER_VLAN, L3_VLAN)) + (
    ("APPL_DB", "VXLAN_VRF_TABLE:*"), ("APPL_DB", "ROUTE_TABLE:{}:*".format(VRF)))


def irb_baseline(duthost):
    return asic_counts(duthost, BASELINE_TYPES)


def cpu_accepts_vxlan(duthost, dut_vtep):
    """Whether the control plane ACL accepts VxLAN to the VTEP address. The kernel's VxLAN netdev decapsulates a
    trapped, still encapsulated ARP or ND frame only then; read for the failure messages, never changed."""
    rule = "INPUT -p udp -d {} --dport 4789 -j ACCEPT".format(dut_vtep)
    check = "sudo iptables -C {r} 2>/dev/null || sudo iptables -C {r} ! -i eth0 2>/dev/null".format(r=rule)
    return duthost.shell(check, module_ignore_errors=True)["rc"] == 0


@pytest.fixture(scope="module")
def access(duthost, tbinfo, request):
    with access_ports(duthost, tbinfo, request, need=4, want=4) as a:
        yield a


@pytest.fixture(scope="module")
def rig(request, duthost, tbinfo, ptfadapter, vmhost, ansible_adhoc):
    variant = request.param
    pre = rig_preflight(vmhost, ansible_adhoc, get_inventory_files(request))
    # after the preflight, so a testbed without a test server borrows no ports
    access = request.getfixturevalue("access")
    pick = pick_rig_ports(duthost, access)
    mg, idx = access.mg, pick.idx
    h0, h2, h1, lport = pick.ports      # H0, H2, H1, and the routed port of both leaves
    leaves = [Leaf(name, "eth{}".format(idx[lport]), idx[lport], lport, asn, vtep, ip, dut_ip, vv, LEAF_PLEN)
              for name, asn, vtep, ip, dut_ip, vv in LEAF_PLAN]
    check_leaf_vteps_unrouted(duthost, leaves)
    assert_clean_start(duthost, leaves, (VLAN, OTHER_VLAN, L3_VLAN), (VNI, L3VNI), more=RIG_STATE)
    if duthost.facts.get("asic_type") != "vs":    # a virtual switch's port RX counters read 0
        check_ingress_once(duthost, ptfadapter, {p: idx[p] for p in pick.ports}, pick.ports, tag("rx"))
    uplink_ports = sorted(p for name, p in idx.items() if name not in access.vlan_members)
    routed_ports = {v: route_ports(duthost, mg, ROUTED[v]) for v in (4, 6)}
    # routed traffic from outside enters on a next hop of the route beyond the default route; without one, only the
    # cases that send it skip (from_uplink)
    inj_port = routed_ports[4][0] if routed_ports[4] else None
    inj_if = next((name for name, p in idx.items() if p == inj_port), None) if inj_port is not None else None
    router_mac = duthost.facts["router_mac"].lower()

    group = tbinfo["group-name"]
    lv = Leaves(pre.server, "ptf_{}".format(group), pre.image, leaves, pick.peer_asn, pick.lo, RT_ASN,
                "irb_" + re.sub(r"[^A-Za-z0-9_.-]", "_", group))
    lv.install()
    try:
        # before the rig changes the DUT: an image that cannot be had is a missing test-server prerequisite
        image_used = resolve_leaf_image(lv)
        if variant == "vrf_l3vni":
            why = leaf_vrf_support(pre.server, lv)
            if why:
                pytest.skip("the leaves' L3 VNI needs VRF devices, and the test server's kernel cannot make one: "
                            "{}".format(why))
        rb = RigBuild(request, duthost, pick, leaves, lv, RT_ASN, [(VLAN_ID, VNI)], baseline=irb_baseline,
                      log_ignore=HARMLESS_LOG, leftovers=RIG_STATE)
        added_aav = not dut_has_advertise_all_vni(duthost)
    except BaseException:
        lv.remove_files()   # nothing on the DUT yet, so no teardown runs
        raise
    r = SimpleNamespace(
        duthost=duthost, variant=variant, vrf=(variant == "vrf_l3vni"), anycast=(variant == "anycast_gw"),
        vs=duthost.facts.get("asic_type") == "vs", lv=lv, rb=rb, l1=leaves[0], l2=leaves[1],
        leaf={lf.name: lf for lf in leaves}, ulmac={}, base_vlan=pick.base_vlan, ifname={"h0": h0, "h1": h1, "h2": h2},
        port={"h0": idx[h0], "h1": idx[h1], "h2": idx[h2]}, uplink_ports=uplink_ports, inj_port=inj_port,
        inj_if=inj_if, dut_vtep=pick.lo, dut_asn=pick.dut_asn, router_mac=router_mac, gw=router_mac,
        other_gw=router_mac, routed=routed_ports, kvx=None, l3kvx=None, flat_tx=[], vx=[], devs=[], rmac={},
        l3_appl={}, l3_routes={}, anycast_before=None, cpu_acl="")
    logger.info("IRB rig [%s]: base %s, hosts %s (ptf %s), leaves %s, uplinks %s, inject on %s (ptf %s), routed "
                "ports %s, VTEP %s AS %s, router MAC %s, image %s, ASIC_DB baseline %s", variant, pick.base_vlan,
                r.ifname, r.port, leaves, uplink_ports, inj_if, r.inj_port, routed_ports, r.dut_vtep, pick.dut_asn,
                router_mac, image_used, rb.base)

    raw_payloads(ptfadapter)
    try:
        with log_clean(request, duthost, "setup", HARMLESS_LOG):
            build_rig(r, ptfadapter, added_aav)
        yield r
    finally:
        rb.teardown()


def extra_vlan(rb, vid):
    """A VLAN the rig's teardown deletes with its own (after their members, before the leaf ports' addresses)."""
    sh(rb.duthost, "sudo config vlan add {}".format(vid))
    rb.built.append(("vlan", vid))


def build_rig(r, ptfadapter, added_aav):
    d, rb = r.duthost, r.rb
    rb.ports_out_of_base()
    rb.leaf_ips()
    rb.vlans()
    extra_vlan(rb, OTHER_VID)
    for h, vid in (("h0", VLAN_ID), ("h2", VLAN_ID), ("h1", OTHER_VID)):
        rb.member(vid, r.ifname[h], True)
    members = rb.base["VLAN_MEMBER"] - len(rb.ports) + 3
    wait_for(60, 2, lambda: asic_count(d, "VLAN_MEMBER") == members, "the rig VLANs' members in ASIC_DB")
    rb.vxlan()
    wait_for(60, 2, lambda: kernel_vxlan_netdev(d, VNI) is not None, "the kernel VxLAN netdev of VNI {}".format(VNI))
    r.kvx = kernel_vxlan_netdev(d, VNI)
    # each undo is registered before its config and tolerates config that is not there; the hooks "first" run in
    # reverse order of registration, so the SVIs go before the VRF's L3 VNI
    if r.vrf:
        rb.on_teardown("after_members", "VRF", lambda: undo_vrf(r))
        rb.on_teardown("first", "L3 VNI", lambda: undo_l3vni(r))
    rb.on_teardown("first", "SVIs", lambda: undo_svis(r))
    if r.vrf:
        vrf_with_l3vni(r)
        for vlan in (VLAN, OTHER_VLAN):
            sh(d, "sudo config interface vrf bind {} {}".format(vlan, VRF))
    for vlan, svi in ((VLAN, SVI), (OTHER_VLAN, OTHER_SVI)):
        for v in (4, 6):
            sh(d, "sudo config interface ip add {} {}/{}".format(vlan, svi[v], PLEN[v]))
    rifs = rb.base["ROUTER_INTERFACE"] + len({lf.dut_port for lf in rb.leaves}) + (3 if r.vrf else 2)
    wait_for(60, 2, lambda: db_keys(d, "APPL_DB", "INTF_TABLE:{}:{}/{}".format(OTHER_VLAN, OTHER_SVI[6], PLEN[6])) and
             asic_count(d, "ROUTER_INTERFACE") >= rifs,
             "the router interfaces of {} and {} in ASIC_DB".format(VLAN, OTHER_VLAN))
    if r.vrf:
        wait_for(60, 2, lambda: db_keys(d, "APPL_DB", "VXLAN_VRF_TABLE:*{}*".format(VRF)) and
                 kernel_vxlan_netdev(d, L3VNI) is not None,
                 "the VRF's L3 VNI in APPL_DB and the kernel VxLAN netdev of VNI {}".format(L3VNI))
        r.l3kvx = kernel_vxlan_netdev(d, L3VNI)
    if r.anycast:
        anycast_gateway_on(r)
    rb.wait_connected()
    rb.bgp(added_aav)
    if r.vrf:
        rb.on_teardown("first", "FRR VRF", lambda: undo_dut_vrf_bgp(r))
        vtysh(d, dut_vrf_bgp_commands(r))
    rb.leaves_up()
    r.ulmac = {lf.name: r.lv.uplink_mac(lf.name) for lf in rb.leaves}
    rb.converge(CONVERGE)
    r.lv.run("svi", "add", "l1", VLAN_ID, "default", *leaf_svi_addrs("l1"))
    if r.vrf:
        leaves_l3(r)
    if r.vs:
        # the vs SAI ages a learned MAC fdb_aging_time after its first frame, however often the host sends, and the
        # age-out makes orchagent re-resolve the host's neighbours by ARP/ND, which the PTF never answers
        age = db_hget(d, "APPL_DB", "SWITCH_TABLE:switch", "fdb_aging_time") or "600"
        rb.on_teardown("first", "FDB aging", lambda: swss_apply(
            d, [{"SWITCH_TABLE:switch": {"fdb_aging_time": age}, "OP": "SET"}], name="vxlan_irb_age"))
        swss_apply(d, [{"SWITCH_TABLE:switch": {"fdb_aging_time": "0"}, "OP": "SET"}], name="vxlan_irb_age")
    # local hosts: MAC learned, neighbour static
    rb.on_teardown("first", "neighbours", lambda: undo_neighbours(r))
    for h, vlan in LOCAL.items():
        learn_mac(ptfadapter, d, r.port[h], r.ifname[h], int(vlan.replace("Vlan", "")), mac_of(h), tag("learn"))
        sh(d, " && ".join(local_neigh_cmd(addr(h, v), mac_of(h), vlan) for v in (4, 6)))
    ips = [addr(h, v) for h in LOCAL for v in (4, 6)]
    wait_state(60, 2, lambda: all(mac and nh for mac, nh in asic_l3(d, ips).values()),
               "the local hosts' neighbours and next hops in ASIC_DB", lambda: asic_l3(d, ips))
    r.vx = [x for x in (r.kvx, r.l3kvx) if x]
    r.flat_tx = [VLAN, OTHER_VLAN] + r.vx
    r.devs = (r.flat_tx + ([r.inj_if] if r.inj_if else []) + [r.ifname[h] for h in ("h0", "h1", "h2")] +
              sorted({lf.dut_port for lf in rb.leaves}))
    if not r.vs:
        kernel_counters(d, r.devs)
    r.cpu_acl = "" if cpu_accepts_vxlan(d, r.dut_vtep) else (
        " (no control plane ACL rule accepting UDP 4789 to {} was found: without one the kernel cannot decapsulate "
        "a trapped frame)".format(r.dut_vtep))
    logger.info("IRB rig [%s] up: gateway MAC %s, kernel VxLAN netdevs %s, leaf uplink MACs %s, leaf router MACs %s, "
                "L3 VNI routes in ASIC_DB %s%s", r.variant, r.gw, r.vx, r.ulmac, r.rmac, r.l3_routes, r.cpu_acl)


def leaf_svi_addrs(leaf):
    return ["{}/{}".format(LEAF_SVI[leaf][v], PLEN[v]) for v in (4, 6)]


def vrf_with_l3vni(r):
    """The VRF, its L3 VNI VLAN mapped to the L3 VNI and bound to it, and the VRF's VNI (undone by undo_l3vni,
    undo_svis and undo_vrf)."""
    d = r.duthost
    sh(d, "sudo config vrf add {}".format(VRF))
    extra_vlan(r.rb, L3_VID)
    sh(d, "sudo config vxlan map add {} {} {}".format(VTEP_NAME, L3_VID, L3VNI))
    sh(d, "sudo config interface vrf bind {} {}".format(L3_VLAN, VRF))
    sh(d, "sudo config vrf add_vrf_vni_map {} {}".format(VRF, L3VNI))


def undo_l3vni(r):
    """The VRF's VNI, then the L3 VNI map, each only if CONFIG_DB has it, and each once orchagent has done it."""
    d = r.duthost
    if db_hget(d, "CONFIG_DB", "VRF|{}".format(VRF), "vni"):
        sh(d, "sudo config vrf del_vrf_vni_map {}".format(VRF))
    wait_for(40, 2, lambda: not db_keys(d, "APPL_DB", "VXLAN_VRF_TABLE:*"), "the VRF's L3 VNI to go from APPL_DB")
    if db_keys(d, "CONFIG_DB", "VXLAN_TUNNEL_MAP|{}|map_{}_{}".format(VTEP_NAME, L3VNI, L3_VLAN)):
        sh(d, "sudo config vxlan map del {} {} {}".format(VTEP_NAME, L3_VID, L3VNI))
    wait_for(60, 2, lambda: not map_entries_of(d, [L3VNI]),
             "the ASIC_DB tunnel map entries of VNI {} to go".format(L3VNI))


def undo_vrf(r):
    d = r.duthost
    if db_keys(d, "CONFIG_DB", "VRF|{}".format(VRF)):
        time.sleep(5)
        sh(d, "sudo config vrf del {}".format(VRF))


def dut_vrf_bgp_commands(r):
    """The VRF's L3 VNI in zebra and a BGP instance in the VRF that imports the leaves' routes over it."""
    return ["configure terminal", "vrf {}".format(VRF), "vni {}".format(L3VNI), "exit-vrf",
            "router bgp {} vrf {}".format(r.dut_asn, VRF), "address-family l2vpn evpn",
            "route-target import {}:{}".format(RT_ASN, L3VNI), "route-target export {}:{}".format(RT_ASN, L3VNI),
            "exit-address-family", "exit", "end"]


def undo_dut_vrf_bgp(r):
    """Remove the VRF's BGP instance and L3 VNI from FRR (vtysh errors on what is not there are ignored), then prove
    neither is left and the routes are gone."""
    d = r.duthost
    # FRR keeps a VRF's BGP instance while the VRF has its L3 VNI, and vtysh stops at the first failing command: the
    # VNI goes first, each in its own call
    vtysh(d, ["configure terminal", "vrf {}".format(VRF), "no vni {}".format(L3VNI), "exit-vrf", "end"], check=False)
    vtysh(d, ["configure terminal", "no router bgp {} vrf {}".format(r.dut_asn, VRF), "end"], check=False)
    running = sh(d, "sudo vtysh -c 'show running-config'", check=False)
    left = [x for x in ("router bgp {} vrf {}".format(r.dut_asn, VRF),) if x in running]
    if re.search(r"^vrf {}\n(?:\s+.*\n)*?\s+vni {}\s*$".format(re.escape(VRF), L3VNI), running, re.M):
        left.append("vrf {} vni {}".format(VRF, L3VNI))
    if left:
        raise RuntimeError("FRR still holds {}".format(left))
    wait_for(40, 2, lambda: not any(db_keys(d, "APPL_DB", appl_route_key(pfx)) for pfx, _leaf in L3_ROUTES.values()),
             "the L3 VNI routes to go from APPL_DB")


def leaf_rmac(r, lf):
    """The router MAC of the leaf's L3 VNI (zebra on the leaf), '' until the L3 VNI is up."""
    try:
        info = json.loads(r.lv.run("show", lf.name, "evpn", "vni", L3VNI, "json", check=False) or "{}")
    except ValueError:
        return ""
    return info.get("routerMac", "").lower() if info.get("state") == "Up" else ""


def appl_route_key(pfx):
    """The APPL_DB ROUTE_TABLE key of pfx in the VRF: fpmsyncd writes a host route (/32, /128) without its length."""
    ip, _, plen = pfx.partition("/")
    return "ROUTE_TABLE:{}:{}".format(VRF, ip if plen == ("128" if ":" in ip else "32") else pfx)


def l3_route_row(r, pfx):
    return redis_hgetall(r.duthost, "APPL_DB", appl_route_key(pfx))


def l3_route_ready(r, pfx, lf):
    row = l3_route_row(r, pfx)
    return (lf.vtep in row.get("nexthop", "") and row.get("vni_label") == str(L3VNI) and
            row.get("router_mac", "").lower() == r.rmac[lf.name])


_VRF_SUPPORT = {}


def leaf_vrf_support(server, lv):
    """'' when the test server's kernel makes VRF devices (the leaves share it), else why not; asked once per test
    server."""
    if server.hostname not in _VRF_SUPPORT:
        out = lv.run("vrfcheck", check=False)
        _VRF_SUPPORT[server.hostname] = "" if "VRF_OK" in out.split() else (
            next((ln for ln in out.splitlines() if ln.startswith("VRF_MISSING")), "") or out.strip()[-200:] or
            "no answer from the leaf script's vrfcheck")
    return _VRF_SUPPORT[server.hostname]


def leaves_l3(r):
    """The L3 VNI VRF on the leaves; l1 exports the prefix (type-5), and l2's host in l2's own L2 VNI, whose SVI is
    in the VRF, gives the IPv4 and IPv6 host routes (type-2 MAC/IP with the L3 VNI). Waits for the leaves' router
    MACs, then for the routes in APPL_DB (the leaf's VTEP, the L3 VNI and the leaf's router MAC) and ASIC_DB."""
    lv, d = r.lv, r.duthost
    leaves, routes = (r.l1, r.l2), L3_ROUTES
    for lf in leaves:
        lv.run("l3vni", "add", lf.name, LEAF_VRF, L3_VID, L3VNI)
    lv.run("prefix", "add", "l1", LEAF_VRF, L3_PREFIX)
    lv.vni_add("l2", B_VID, B_VNI)
    lv.run("svi", "add", "l2", B_VID, LEAF_VRF, *["{}/{}".format(B_SVI[v], PLEN[v]) for v in (4, 6)])
    lv.fdb("add", "l2", L3_HOST_MAC, B_VID)
    lv.run("neigh", "add", "l2", B_VID, L3_HOST_MAC, L3_HOST[4], L3_HOST[6])
    for lf in leaves:
        wait_state(60, 3, lambda: leaf_rmac(r, lf), "{}'s L3 VNI {} up with a router MAC".format(lf.name, L3VNI),
                   lambda: lv.run("show", lf.name, "evpn", "vni", L3VNI, "json", check=False))
        r.rmac[lf.name] = leaf_rmac(r, lf)
    wait_state(CONVERGE, 3, lambda: all(l3_route_ready(r, pfx, r.leaf[leaf]) for pfx, leaf in routes.values()),
               "APPL_DB routes in {} over L3 VNI {} with the leaves' VTEPs and router MACs {}".format(
                   VRF, L3VNI, r.rmac),
               lambda: {pfx: l3_route_row(r, pfx) for pfx, _leaf in routes.values()})
    wait_state(40, 2, lambda: all(asic_route(d, pfx) for pfx, _leaf in routes.values()),
               "the L3 VNI routes in ASIC_DB", lambda: {pfx: asic_route(d, pfx) for pfx, _leaf in routes.values()})
    r.l3_appl = {name: l3_route_row(r, pfx) for name, (pfx, _leaf) in routes.items()}
    r.l3_routes = {name: asic_route(d, pfx) for name, (pfx, _leaf) in routes.items()}


def anycast_gateway_on(r):
    """A static anycast gateway MAC on the Vlan2010 SVI; the variant skips on an image that does not apply one."""
    d = r.duthost
    r.anycast_before = db_hget(d, "CONFIG_DB", "SAG|GLOBAL", "gateway_mac")
    sh(d, "sonic-db-cli CONFIG_DB HSET 'SAG|GLOBAL' gateway_mac {}".format(ANYCAST_MAC))
    sh(d, "sonic-db-cli CONFIG_DB HSET 'VLAN_INTERFACE|{}' static_anycast_gateway true".format(VLAN))

    def rif_macs():
        view = AsicView(d, ("ROUTER_INTERFACE",))
        return {a.get("SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS", "").lower()
                for a in view.objs["ROUTER_INTERFACE"].values()}
    if not wait_until(40, 2, 0, lambda: ANYCAST_MAC in sh(d, "cat /sys/class/net/{}/address".format(VLAN)).lower()):
        pytest.skip("this image does not apply a static anycast gateway MAC to an SVI")
    wait_state(40, 2, lambda: ANYCAST_MAC in rif_macs(),
               "an ASIC_DB router interface with the anycast gateway MAC {}".format(ANYCAST_MAC), rif_macs)
    r.gw = ANYCAST_MAC


def undo_svis(r):
    """The anycast gateway, the SVI addresses, the VRF bindings and what CONFIG_DB keeps of the VLAN interfaces."""
    d = r.duthost
    if r.anycast_before is not None:
        sh(d, "sonic-db-cli CONFIG_DB HSET 'VLAN_INTERFACE|{}' static_anycast_gateway false".format(VLAN))
        time.sleep(3)
        sh(d, "sonic-db-cli CONFIG_DB HDEL 'VLAN_INTERFACE|{}' static_anycast_gateway".format(VLAN))
        sh(d, "sonic-db-cli CONFIG_DB HSET 'SAG|GLOBAL' gateway_mac {}".format(r.anycast_before)
           if r.anycast_before else "sonic-db-cli CONFIG_DB HDEL 'SAG|GLOBAL' gateway_mac")
        time.sleep(3)
    for vlan, svi in ((VLAN, SVI), (OTHER_VLAN, OTHER_SVI)):
        for v in (4, 6):
            sh(d, "sudo config interface ip remove {} {}/{}".format(vlan, svi[v], PLEN[v]), check=False)
    time.sleep(5)
    if r.vrf:
        for vlan in (VLAN, OTHER_VLAN, L3_VLAN):
            sh(d, "sudo config interface vrf unbind {}".format(vlan), check=False)
        time.sleep(5)
    for key in [k for vlan in (VLAN, OTHER_VLAN, L3_VLAN)
                for k in db_keys(d, "CONFIG_DB", "VLAN_INTERFACE|{}".format(vlan)) +
                db_keys(d, "CONFIG_DB", "VLAN_INTERFACE|{}|*".format(vlan))]:
        sh(d, "sonic-db-cli CONFIG_DB DEL '{}'".format(key))


def undo_neighbours(r):
    d = r.duthost
    sh(d, "sudo pkill -f '[p]ing .*-I {}' 2>/dev/null; true".format(VLAN), check=False)
    sh(d, "; ".join(neigh_del_cmd(addr(h, v), LOCAL.get(h, VLAN)) for h in HOST for v in (4, 6)), check=False)
    if r.kvx:
        sh(d, remote_mac_del_cmd(r.kvx, mac_of("rk"), VLAN_ID), check=False)


@pytest.fixture(autouse=True)
def ignore_known_harmless(duthost, loganalyzer):
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(HARMLESS_LOG)


@pytest.fixture(autouse=True)
def local_hosts_known(rig, ptfadapter):
    """Each case starts with the local hosts' MACs just seen on their ports (a learned MAC ages out, and a flush in
    one case must not leave the next one flooding)."""
    for h in LOCAL:
        testutils.send(ptfadapter, rig.port[h], probe_frame(tag("seen"), BROADCAST_MAC, mac_of(h)), count=2)
    time.sleep(1)


# --------------------------------------------------------------------------------------------------------------------
# per-case remote hosts
# --------------------------------------------------------------------------------------------------------------------
def leaf_host_cmds(lf, host, op, ips=True):
    """Leaf script commands that put the host behind lf (op add: its MAC on the leaf's host port, and with ips its
    IPv4 and IPv6 neighbours on the leaf's SVI) or take it away (op del: neighbours, then the MAC)."""
    mac = mac_of(host)
    neigh = ["neigh", op, lf.name, VLAN_ID, mac, addr(host, 4), addr(host, 6)]
    fdb = ["fdb", op, lf.name, mac, VLAN_ID]
    if op == "add":
        return [fdb] + ([neigh] if ips else [])
    return [neigh, fdb]


def leaf_host(r, lf, host, op, ips=True):
    """Advertise the host from lf (type-2 MAC, with ips type-2 MAC/IP) or withdraw it (tolerates its absence)."""
    for args in leaf_host_cmds(lf, host, op, ips):
        r.lv.run(*args, check=(op == "add"))


def wait_remote_mac(r, host, lf):
    d, mac = r.duthost, mac_of(host)
    wait_for(CONVERGE, 2, lambda: appl_remote_mac_vtep(d, VLAN, mac) == lf.vtep,
             "APPL_DB VXLAN_FDB_TABLE {} -> {}".format(mac, lf.vtep))
    wait_state(30, 1, lambda: remote_fdb_dip(d, mac, VLAN_ID) == lf.vtep,
               "the remote MAC {} in ASIC_DB on the tunnel to {}".format(mac, lf.vtep),
               lambda: "ASIC_DB FDB '{}'".format(remote_fdb_dip(d, mac, VLAN_ID)))


def wait_neighs_appl(r, host):
    wait_for(60, 1, lambda: all(db_keys(r.duthost, "APPL_DB", "NEIGH_TABLE:{}:{}".format(VLAN, addr(host, v)))
                                for v in (4, 6)), "the neighbours of {} in APPL_DB".format(host))


def kernel_remote_mac(r, host):
    """The host's MAC behind l1 in the DUT's kernel, as zebra installs a type-2 MAC route; returns once ASIC_DB has
    it on the tunnel to l1."""
    d, mac = r.duthost, mac_of(host)
    sh(d, remote_mac_cmd(r.kvx, mac, r.l1.vtep, VLAN_ID))
    wait_state(30, 1, lambda: remote_fdb_dip(d, mac, VLAN_ID) == r.l1.vtep,
               "the remote MAC {} in ASIC_DB on the tunnel to {}".format(mac, r.l1.vtep),
               lambda: "ASIC_DB FDB '{}', APPL_DB {}".format(
                   remote_fdb_dip(d, mac, VLAN_ID), db_keys(d, "APPL_DB", "VXLAN_FDB_TABLE:{}:{}".format(VLAN, mac))))


def kernel_remote_neigh(r, host):
    """The host's IPv4 and IPv6 neighbours on the SVI in the DUT's kernel, as zebra installs a type-2 MAC/IP route;
    returns once APPL_DB has them. Zebra ignores an externally learned neighbour it did not install."""
    d, mac = r.duthost, mac_of(host)
    for v in (4, 6):
        if d.shell(remote_neigh_cmd(addr(host, v), mac, VLAN), module_ignore_errors=True)["rc"] != 0:
            # an iproute2 without extern_learn: a static neighbour is programmed the same way
            sh(d, local_neigh_cmd(addr(host, v), mac, VLAN))
    wait_neighs_appl(r, host)


def kernel_host_missing(r, host):
    """'' while the DUT's kernel still holds what kernel_remote_neigh and kernel_remote_mac installed for the host
    (zebra ignores entries it did not install, and must leave them), else what is gone."""
    d, mac = r.duthost, mac_of(host)
    fdb = sh(d, "bridge fdb show dev {} 2>/dev/null | grep -i '{}'; true".format(r.kvx, mac))
    missing = []
    if not any("dst {} ".format(r.l1.vtep) in ln + " " and "self" in ln for ln in fdb.splitlines()):
        missing.append("FDB entry {} dst {} on {} (now: '{}')".format(mac, r.l1.vtep, r.kvx, fdb.strip()))
    for v in (4, 6):
        line = kernel_neigh(d, addr(host, v), VLAN)
        if not neigh_resolved(line, mac):
            missing.append("neighbour {} on {} (now: '{}')".format(addr(host, v), VLAN, line))
    return "; ".join(missing)


def kernel_withdraw_cmd(r, host):
    """Withdraw a kernel-installed host as its type-2 routes would go: the neighbours, then the MAC."""
    return "; ".join([neigh_del_cmd(addr(host, v), VLAN) for v in (4, 6)] +
                     [remote_mac_del_cmd(r.kvx, mac_of(host), VLAN_ID)])


def in_asic(r, host, timeout=30):
    """{ip: (neighbour MAC, next hop)} from ASIC_DB for the host, waiting up to timeout for both of each."""
    ips = [addr(host, v) for v in (4, 6)]
    wait_until(timeout, 1, 0, lambda: all(mac and nh for mac, nh in asic_l3(r.duthost, ips).values()))
    return asic_l3(r.duthost, ips)


def advertise(r, host, how):
    """Put a host behind VTEP A. how: mac (l1 advertises its MAC), macip (l1 advertises its MAC and IPs: zebra
    installs the MAC, then the neighbours), kernel_neigh_first (installed in the DUT's kernel: the neighbours reach
    ASIC_DB, then the MAC arrives) or none."""
    if how in ("mac", "macip"):
        leaf_host(r, r.l1, host, "add", ips=(how == "macip"))
        wait_remote_mac(r, host, r.l1)
        if how == "macip":
            wait_neighs_appl(r, host)
            in_asic(r, host, timeout=20)
    elif how == "kernel_neigh_first":
        kernel_remote_neigh(r, host)
        got = in_asic(r, host)
        assert all(mac and nh for mac, nh in got.values()), (
            "the neighbours of {} (MAC not known yet) did not reach ASIC_DB with a next hop: {}".format(host, got))
        kernel_remote_mac(r, host)
        gone = kernel_host_missing(r, host)
        assert not gone, "the kernel entries installed for {} did not stay: {}".format(host, gone)


def withdraw(r, host, how):
    if how == "kernel_neigh_first":
        sh(r.duthost, kernel_withdraw_cmd(r, host), check=False)
        return
    leaf_host(r, r.l1, host, "del")
    if how == "none":
        sh(r.duthost, "; ".join(neigh_del_cmd(addr(host, v), VLAN) for v in (4, 6)), check=False)


def gone_from_asic(r, host):
    return (not any(mac or nh for mac, nh in asic_l3(r.duthost, [addr(host, v) for v in (4, 6)]).values()) and
            remote_fdb_dip(r.duthost, mac_of(host), VLAN_ID) == "")


@contextlib.contextmanager
def remote_hosts(r, hosts):
    """Hosts behind A for one case ({name: how}, see advertise); all of it removed on exit. When the case body
    failed, a clean-up problem is logged, so the case's own failure stays the verdict."""
    d, body_ok = r.duthost, False

    def _cleanup():
        step = Steps("remote host clean-up")
        step("ping", lambda: sh(d, "sudo pkill -f '[p]ing .*-I {}' 2>/dev/null; true".format(VLAN), check=False))
        for host, how in hosts.items():
            step("withdraw " + host, lambda h=host, w=how: withdraw(r, h, w))
        for host, how in hosts.items():
            if not wait_until(30, 2, 0, lambda h=host: gone_from_asic(r, h)):
                rows = db_keys(d, "APPL_DB", "VXLAN_FDB_TABLE:{}:{}".format(VLAN, mac_of(host)))
                step.errors.append(
                    "{} still in ASIC_DB after its withdrawal: neighbours {}, FDB '{}', APPL_DB {}".format(
                        host, asic_l3(d, [addr(host, v) for v in (4, 6)]), remote_fdb_dip(d, mac_of(host), VLAN_ID),
                        rows))
                if rows and how == "kernel_neigh_first":
                    step("remote MAC row", lambda rows=rows: swss_apply(d, [{k: {}, "OP": "DEL"} for k in rows]))
        step.finish(report=body_ok)

    try:
        for host, how in hosts.items():
            advertise(r, host, how)
        yield
        body_ok = True
    finally:
        _cleanup()


# --------------------------------------------------------------------------------------------------------------------
# routed streams
# --------------------------------------------------------------------------------------------------------------------
def from_local(r, host):
    """A local host sending to its gateway."""
    return SimpleNamespace(name=host, port=r.port[host], ingress=r.ifname[host], smac=mac_of(host),
                           dmac=r.gw if LOCAL[host] == VLAN else r.other_gw,
                           sip={4: addr(host, 4), 6: addr(host, 6)}, vni=None, vtep=None)


def from_uplink(r):
    """Routed traffic from outside, entering on an uplink (a next hop toward ROUTED); skips when there is none."""
    if r.inj_port is None:
        pytest.skip("no route toward {} through a port the PTF sees, to send routed traffic from".format(ROUTED[4]))
    return SimpleNamespace(name="an uplink", port=r.inj_port, ingress=r.inj_if, smac=EXT_SMAC, dmac=r.router_mac,
                           sip=EXT_SRC, vni=None, vtep=None)


def from_remote(r, host="q", vni=VNI, lf=None, dmac=None, smac=None, sip=None):
    """A host behind a leaf (default l1): its frames arrive VxLAN-encapsulated on the leaf's port, as the leaf sends
    them."""
    lf = lf or r.l1
    return SimpleNamespace(name="{} behind {} (VNI {})".format(host, leaf_text(lf), vni), port=lf.ptf_port,
                           ingress=lf.dut_port, smac=smac or mac_of(host), dmac=dmac or r.gw,
                           sip=sip or {4: addr(host, 4), 6: addr(host, 6)}, vni=vni, vtep=lf.vtep)


def into_vlan_source(r):
    """Where routed traffic toward Vlan2010 comes from: an uplink, or in the VRF the local host of the other VLAN."""
    return from_local(r, "h1") if r.vrf else from_uplink(r)


def stream_frame(r, t, v, src, dst):
    inner = flow_frame(t, src.dmac, src.smac, v6=(v == 6), ips=(src.sip[v], dst))
    if src.vni is None:
        return inner
    return vxlan_frame(inner, r.router_mac, INJ_OUTER_SMAC, src.vtep, r.dut_vtep, src.vni)


def of_stream(f, dst):
    """A copy of a stream to dst itself, not an ICMP error about it (which quotes the frame, tag included)."""
    l3 = l3_of(f.inner if f.inner is not None else f.outer)
    return l3 is not None and same_ip(l3.dst, dst)


def routed(r, ptfadapter, name, v, src, dst, want):
    """Send N frames from src to dst: SimpleNamespace(good, wrong, elsewhere, soft, text) for where they came out
    (judge_routed) and whether the kernel forwarded them (kernel_forwarded; never read on a virtual switch)."""
    t = tag(name)
    pkt = stream_frame(r, t, v, src, dst)
    k0 = None if r.vs else kernel_counters(r.duthost, r.devs)
    frames = capture_frames(ptfadapter, lambda: send_paced(ptfadapter, src.port, pkt), lambda raw: t.encode() in raw)
    # a stream the kernel forwards to a native destination leaves through a VLAN netdev (the bridge may flood it to
    # the VxLAN netdevs as well); the VxLAN netdevs' TX also carries the switch's own floods, once per flood-list VTEP
    flat_tx = r.flat_tx if isinstance(want, Vxlan) else [VLAN, OTHER_VLAN]
    soft = "" if r.vs else kernel_forwarded(kernel_delta(k0, kernel_counters(r.duthost, r.devs)), flat_tx=flat_tx,
                                            flat_rx=r.vx, ingress=src.ingress)
    frames = [f for f in frames if of_stream(f, dst)]
    good, wrong, elsewhere = judge_routed(frames, want, dst, r.dut_vtep)
    text = "{} of {} from {} to {} came out {}; {} with a wrong header {}; {} elsewhere. Copies: {}".format(
        good, N, src.name, dst, want_text(want), len(wrong), wrong[:3], elsewhere, describe(frames))
    logger.info("stream %s: %s; kernel %s", name, text, soft or "not involved")
    return SimpleNamespace(good=good, wrong=wrong, elsewhere=elsewhere, soft=soft, text=text, frames=frames)


def assert_forwarded(o, what):
    """Every frame came out where it should, once, and by hardware."""
    assert delivered(o.good) and not o.wrong and o.elsewhere == 0, "{}: {}".format(what, o.text)
    assert not o.soft, "{}: delivered, but not by hardware ({}). {}".format(what, o.soft, o.text)


def control(o, what):
    """A positive control: without it the case's reading says nothing about VxLAN."""
    if not (delivered(o.good) and not o.wrong and o.elsewhere == 0):
        pytest.fail("positive control failed, the case cannot be read: {}: {}".format(what, o.text))


def judge_remote(r, o, host, lf, ip, what, no_hw_path):
    """A routed stream to a host the leaf lf advertises: never a copy where the host is not. Then either ASIC_DB has
    the host's MAC on lf's tunnel but neither a neighbour nor a next hop for ip (orchagent leaves out a neighbour
    whose MAC was behind a VxLAN tunnel when the neighbour arrived): recorded in no_hw_path, the stream has no
    hardware path to read; or the neighbour and next hop are there and the stream was forwarded by hardware.
    Returns whether this stream was in the no-hardware-path state."""
    assert not o.wrong and o.elsewhere == 0, "{}: frames came out where the host is not. {}; kernel: {}".format(
        what, o.text, o.soft or "not involved")
    if no_hw_state(r, host, lf, ip):
        no_hw_path.append("{}: {}; kernel: {}".format(what, o.text, o.soft or "not involved"))
        return True
    got = asic_l3(r.duthost, [ip])[ip]
    assert got == (mac_of(host), True), "{}: ASIC_DB has neighbour MAC {}, next hop {} for the host".format(
        what, got[0], got[1])
    assert_forwarded(o, what)
    return False


def no_hw_state(r, host, lf, ip):
    """ASIC_DB has the host's MAC on lf's tunnel but neither a neighbour nor a next hop for ip."""
    return (asic_l3(r.duthost, [ip])[ip] == (None, False) and
            remote_fdb_dip(r.duthost, mac_of(host), VLAN_ID) == lf.vtep)


def fail_if_no_hw_path(dst, no_hw_path):
    if no_hw_path:
        pytest.fail("with the host's MAC behind a VxLAN tunnel, ASIC_DB has no neighbour and no next hop for {}, so "
                    "the routed traffic has no hardware path: {}".format(dst, " | ".join(no_hw_path)))


def to_leaf(r, lf, vni, dmac, smac):
    """Encapsulated to lf: its VTEP with vni, inner dmac / smac, out lf's port to lf's uplink MAC."""
    return Vxlan(lf.vtep, vni, dmac, smac, lf.ptf_port, r.ulmac[lf.name])


def encap_to_leaf(r, f, lf, vni):
    """f is a frame the DUT encapsulated to lf with vni (its VTEP, out its port, to its uplink MAC)."""
    return encap_to(f, r.dut_vtep, lf.vtep, vni, lf.ptf_port, r.ulmac[lf.name])


def far_destination(r, v):
    """(destination, expectation) of a routed destination beyond the two VLANs: out an uplink, or in the VRF variant
    a host route over the L3 VNI through VTEP B. Skips when the testbed has no route out an uplink."""
    if r.vrf:
        pfx, leaf = L3_ROUTES["host_v{}".format(v)]
        if not (l3_route_ready(r, pfx, r.leaf[leaf]) and asic_route(r.duthost, pfx)):
            pytest.fail("the IPv{} host route {} over the L3 VNI is not ready: APPL_DB {}, ASIC_DB {}".format(
                v, pfx, l3_route_row(r, pfx), asic_route(r.duthost, pfx)))
        return L3_HOST[v], to_leaf(r, r.l2, L3VNI, r.rmac["l2"], r.router_mac)
    if not r.routed[v]:
        pytest.skip("no IPv{} route toward {} through a port the PTF sees".format(v, ROUTED[v]))
    return ROUTED[v], Native(r.routed[v], None, r.router_mac)


# --------------------------------------------------------------------------------------------------------------------
# decapsulate, then route
# --------------------------------------------------------------------------------------------------------------------
@EVERY_RIG
@pytest.mark.parametrize("to", ["routed_on", "local_vlan"])
@FAMILY
def test_irb_decap_then_route(rig, ptfadapter, v, to):
    """A frame from a host behind a remote VTEP to the gateway MAC is decapsulated and routed by hardware.

    The host's MAC is advertised by l1 (type-2 MAC), and its frames arrive from l1's VTEP on l1's port.
    routed_on: out an uplink toward a destination beyond the default route (VRF variant: encapsulated again, to the
    VTEP of a host route over the L3 VNI). local_vlan: to a local host in the other VLAN. Either way once, with the
    TTL decremented and the router's source MAC, and nowhere else. Control: the same destination from a local host.
    """
    r = rig
    if to == "routed_on":
        dst, want = far_destination(r, v)
    else:
        dst, want = addr("h1", v), Native([r.port["h1"]], mac_of("h1"), r.other_gw)
    with remote_hosts(r, {"q": "mac"}):
        control(routed(r, ptfadapter, "dc{}".format(v), v, from_local(r, "h0"), dst, want),
                "local host H0 to {} through the SVI".format(dst))
        o = routed(r, ptfadapter, "dr{}".format(v), v, from_remote(r), dst, want)
        assert_forwarded(o, "decapsulate from {} then route to {}".format(leaf_text(r.l1), dst))


# --------------------------------------------------------------------------------------------------------------------
# route into the VNI VLAN
# --------------------------------------------------------------------------------------------------------------------
@EVERY_RIG
@pytest.mark.parametrize("to", ["local", "remote_neigh_first", "remote_mac_first"])
@FAMILY
def test_irb_route_into_vlan(rig, ptfadapter, v, to):
    """Routed traffic into the VNI VLAN reaches a local host natively and a remote host encapsulated, by hardware.

    The remote host's frames leave to its VTEP (A) with the VLAN's VNI, inner destination = the host's MAC, inner
    source = the gateway MAC, TTL decremented, and are not flooded to the local hosts. The host's neighbour and next
    hop must be in ASIC_DB in both arrival orders of its neighbour and its remote MAC.
    remote_mac_first: l1 advertises the host's MAC and IPs (type-2 MAC/IP); zebra installs the MAC, then the
    neighbour. remote_neigh_first: no leaf advertises the host; its neighbours are installed in the DUT's kernel as
    zebra installs a remote neighbour, and once they are in ASIC_DB its MAC on the VxLAN netdev toward A, an order
    that zebra never produces.
    """
    r, src = rig, into_vlan_source(rig)
    if to == "local":
        o = routed(r, ptfadapter, "il{}".format(v), v, src, addr("h0", v),
                   Native([r.port["h0"]], mac_of("h0"), r.gw))
        assert_forwarded(o, "route into {} to the local host H0".format(VLAN))
        return
    host, how = ("rk", "kernel_neigh_first") if to == "remote_neigh_first" else ("rn", "macip")
    dst, vtep = addr(host, v), r.l1.vtep
    with remote_hosts(r, {host: how}):
        mac, nh = asic_l3(r.duthost, [dst])[dst]
        o = routed(r, ptfadapter, "ir{}".format(v), v, src, dst, to_leaf(r, r.l1, VNI, mac_of(host), r.gw))
        on_tunnel = remote_fdb_dip(r.duthost, mac_of(host), VLAN_ID) == vtep
        if how == "kernel_neigh_first":
            gone = kernel_host_missing(r, host)
            assert not gone, ("the host installed in the DUT's kernel lost entries during the case (zebra or another "
                              "agent removed them), so the reading is not the neighbour-first order: {}".format(gone))
        assert mac == mac_of(host) and nh, (
            "ASIC_DB for the remote host {}: neighbour MAC {}, next hop {}; expected the neighbour with MAC {} and a "
            "next hop (MAC on the tunnel to {}: {}); routed traffic: {}; kernel: {}".format(
                dst, mac, nh, mac_of(host), vtep, on_tunnel, o.text, o.soft or "not involved"))
        assert_forwarded(o, "route into {} to {} behind {}".format(VLAN, dst, leaf_text(r.l1)))


# --------------------------------------------------------------------------------------------------------------------
# ARP and ND with the SVI
# --------------------------------------------------------------------------------------------------------------------
def gateway_replies(r, ptfadapter, v, host, unicast):
    """N requests for the SVI address from a local host or a host behind A: (good, wrong, misplaced, text) counting
    the replies that advertise the gateway MAC to the requester, on its port or encapsulated to A."""
    mac, me, svi = mac_of(host), addr(host, v), SVI[v]
    req = resolve_request(v, mac, me, svi, dmac=r.gw if unicast else None)
    local = host in LOCAL
    port, pkt = (r.port[host], req) if local else (
        r.l1.ptf_port, vxlan_frame(req, r.router_mac, INJ_OUTER_SMAC, r.l1.vtep, r.dut_vtep, VNI))
    frames = capture_frames(ptfadapter, lambda: send_paced(ptfadapter, port, pkt), lambda raw: mac_bytes(mac) in raw,
                            quiet=3.0)
    good, wrong, misplaced = 0, [], 0
    for f in frames:
        encap = from_dut(f, r.dut_vtep)
        said = resolve_reply_mac(v, f.inner if encap else f.outer, svi, mac)
        if not said or (f.inner is not None and not encap):
            continue
        right_place = (f.inner is None and f.port == r.port[host]) if local else encap_to_leaf(r, f, r.l1, VNI)
        if not right_place:
            misplaced += 1
        elif said == r.gw:
            good += 1
        else:
            wrong.append(said)
    text = "{} of {} {} {} for {} from {} answered with the gateway MAC {}; {} answers with another MAC {}; {} " \
           "answers in the wrong place".format(
               good, N, "unicast" if unicast else "broadcast" if v == 4 else "multicast",
               "ARP requests" if v == 4 else "neighbour solicitations", svi,
               "local host " + host if local else host + " behind " + leaf_text(r.l1), r.gw, len(wrong),
               sorted(set(wrong)), misplaced)
    logger.info("%s", text)
    return good, wrong, misplaced, text


@EVERY_RIG
@pytest.mark.parametrize("request_kind", ["arp_broadcast", "arp_unicast", "ns_multicast", "ns_unicast"])
def test_irb_remote_host_resolves_gateway(rig, ptfadapter, request_kind):
    """A host behind a remote VTEP (its MAC advertised by l1) resolves the SVI address: each of its ARP requests
    (broadcast, and unicast to the gateway MAC) and neighbour solicitations (multicast, and unicast) gets one reply
    that advertises the gateway MAC, encapsulated to the host's VTEP with the VLAN's VNI. Control: the same request
    from a local host."""
    r = rig
    v, unicast = (4 if request_kind.startswith("arp") else 6), request_kind.endswith("unicast")
    with remote_hosts(r, {"q": "mac"}):
        good, wrong, misplaced, text = gateway_replies(r, ptfadapter, v, "h0", unicast)
        if not delivered(good) or wrong or misplaced:
            pytest.fail("positive control failed, the case cannot be read: " + text)
        good, wrong, misplaced, text = gateway_replies(r, ptfadapter, v, "q", unicast)
        assert delivered(good) and not wrong and misplaced == 0, text + r.cpu_acl


@EVERY_RIG
@FAMILY
def test_irb_switch_resolves_remote_host(rig, ptfadapter, v):
    """The switch resolves a host behind a remote VTEP itself, and routed traffic then reaches the host.

    With nothing known about the host, traffic the switch originates toward it makes the switch send an ARP request
    (neighbour solicitation) encapsulated to the remote VTEP of the VLAN's flood list (A, from l1's type-3 route);
    the reply, sent back through the tunnel to the address the request came from, resolves the kernel neighbour.
    Once l1 then advertises the host's MAC (type-2 MAC), the neighbour and its next hop are in ASIC_DB and routed
    traffic reaches the host by hardware.
    """
    r, d = rig, rig.duthost
    mac, ip, vtep = mac_of("u"), addr("u", v), r.l1.vtep
    with remote_hosts(r, {"u": "none"}):
        ping = "sudo sh -c 'nohup ping -{} -c 12 -i 1 -W 1 -I {} {} </dev/null >/dev/null 2>&1 &'".format(v, VLAN, ip)
        seen = capture_frames(ptfadapter, lambda: sh(d, ping), lambda raw: ip_bytes(ip) in raw, quiet=6.0, max_wait=6.0)
        asked = [f for f in seen if encap_to_leaf(r, f, r.l1, VNI) and is_resolve_request(v, f.inner, ip)]
        assert asked, (
            "the switch sent no {} for {} encapsulated to {} (VNI {}) in 6 s of pinging the host from {}. Frames "
            "naming the address: {}".format("ARP request" if v == 4 else "neighbour solicitation", ip,
                                            leaf_text(r.l1), VNI, VLAN, describe(seen)))
        first = asked[0].inner
        to_ip = SVI[4] if v == 4 else first.payload.src
        reply = vxlan_frame(resolve_reply(v, mac, ip, first.src, to_ip), r.router_mac, INJ_OUTER_SMAC, vtep,
                            r.dut_vtep, VNI)
        send_paced(ptfadapter, r.l1.ptf_port, reply, count=6, chunk=1, pause=0.4)
        wait_until(10, 1, 0, lambda: neigh_resolved(kernel_neigh(d, ip, VLAN), mac))
        line = kernel_neigh(d, ip, VLAN)
        sh(d, "sudo pkill -f '[p]ing .*-I {} {}' 2>/dev/null; true".format(VLAN, ip), check=False)
        assert neigh_resolved(line, mac), (
            "the switch asked for {} ({} requests encapsulated to {}), but 6 replies sent back through the tunnel to "
            "{} did not resolve it: kernel neighbour '{}'{}".format(ip, len(asked), vtep, first.src, line, r.cpu_acl))
        leaf_host(r, r.l1, "u", "add", ips=False)
        wait_remote_mac(r, "u", r.l1)
        got = in_asic(r, "u")[ip]
        assert got == (mac, True), "ASIC_DB for the resolved host {}: neighbour MAC {}, next hop {}".format(
            ip, got[0], got[1])
        o = routed(r, ptfadapter, "sr{}".format(v), v, into_vlan_source(r), ip, to_leaf(r, r.l1, VNI, mac, r.gw))
        assert_forwarded(o, "route to {} behind {}, which the switch resolved itself".format(ip, leaf_text(r.l1)))


# --------------------------------------------------------------------------------------------------------------------
# ARP and ND between hosts of the VLAN
# --------------------------------------------------------------------------------------------------------------------
BRIDGED = {"remote_to_local": ("q", "h0"), "local_to_remote": ("h0", "q"), "local_to_local": ("h0", "h2")}


@EVERY_RIG
@pytest.mark.parametrize("kind", ["arp_request", "arp_reply", "ns_multicast", "na"])
@pytest.mark.parametrize("path", sorted(BRIDGED))
def test_irb_arp_nd_bridged(rig, ptfadapter, path, kind):
    """ARP and ND between two hosts of the VNI VLAN are bridged, although the VLAN has an SVI.

    The remote host's MAC is advertised by l1, and its frames arrive from l1's VTEP on l1's port.
    A broadcast ARP request and a multicast neighbour solicitation for another host reach every other local member
    and, from a local host, the remote VTEP (from the remote VTEP they are not sent back to it); a unicast ARP reply
    and neighbour advertisement reach only their destination. Every copy is the frame that was sent, byte for byte,
    and no copy is anywhere else. The counts are exact: 40 copies of 40 frames at each place, by hardware.

    The unicast neighbour advertisement is read differently, because of what a VLAN with an SVI does to it with or
    without a VNI: the neighbour discovery trap copies the frame to the CPU while hardware bridges it, and the
    kernel bridge forwards its copy as well (the bridge filter rules drop ARP and multicast, not unicast IPv6), so
    the destination can get every advertisement twice on any routed VLAN. That is not a VxLAN behaviour, so this arm
    asserts what the VNI must not add to it: every advertisement arrives at its destination at least once and at
    most twice (40 to 80 copies), encapsulated to the right VTEP when the destination is remote and natively when
    it is local, unchanged, and no copy reaches another host, another VTEP, the tunnel when the destination is local
    or an uplink.
    """
    r = rig
    sender, target = BRIDGED[path]
    v, flood = (4 if kind.startswith("arp") else 6), kind in ("arp_request", "ns_multicast")
    t = tag("br")
    if flood:
        frame = resolve_request(v, mac_of(sender), addr(sender, v), addr(target, v))
    else:
        frame = resolve_reply(v, mac_of(sender), addr(sender, v), mac_of(target), addr(target, v))
    want = with_trailer(frame, t)
    if sender == "q":
        port, pkt = r.l1.ptf_port, vxlan_frame(want, r.router_mac, INJ_OUTER_SMAC, r.l1.vtep, r.dut_vtep, VNI)
    else:
        port, pkt = r.port[sender], want
    local_ports = {h: r.port[h] for h in ("h0", "h2") if h != sender and (flood or h == target)}
    to_vtep = sender != "q" and (flood or target == "q")
    with remote_hosts(r, {"q": "mac"}):
        k0 = None if r.vs else kernel_counters(r.duthost, r.devs)
        frames = capture_frames(ptfadapter, lambda: send_paced(ptfadapter, port, pkt), lambda raw: t.encode() in raw)
        soft = "" if r.vs else kernel_forwarded(kernel_delta(k0, kernel_counters(r.duthost, r.devs)),
                                                flat_tx=[r.kvx] + [r.ifname[h] for h in ("h0", "h2")])
    native = {h: sum(1 for f in frames if f.inner is None and f.port == p and f.raw == want)
              for h, p in local_ports.items()}
    encap = sum(1 for f in frames if encap_to_leaf(r, f, r.l1, VNI) and f.inner_raw == want)
    other = len(frames) - sum(native.values()) - encap
    twice_ok = kind == "na"

    def arrived(n):
        return N <= n <= 2 * N if twice_ok else n == N

    assert all(arrived(n) for n in native.values()) and (arrived(encap) if to_vtep else encap == 0) and other == 0, (
        "{} from {} to {} ({} frames): unchanged copies on the local hosts {} (expected on {}), {} unchanged copies "
        "encapsulated to {} (expected {}), {} changed or misplaced copies; expected {} per place; kernel: {}. "
        "Copies: {}".format(
            kind, sender, target, N, native, sorted(local_ports), encap, leaf_text(r.l1),
            "there" if to_vtep else "none", other,
            "{} to {} copies".format(N, 2 * N) if twice_ok else "exactly {} copies".format(N),
            soft or "forwarded less than half of them", describe(frames)))
    if not twice_ok:
        assert not soft, "{} from {} to {}: delivered, but forwarded by the kernel ({})".format(
            kind, sender, target, soft)


# --------------------------------------------------------------------------------------------------------------------
# ping the SVI address
# --------------------------------------------------------------------------------------------------------------------
@EVERY_RIG
@pytest.mark.parametrize("who", ["local", "remote"])
@FAMILY
def test_irb_ping_gateway(rig, ptfadapter, v, who):
    """A local host and a host behind a remote VTEP (advertised by l1 with its IPs) ping the SVI address: every echo
    request gets one reply, on the local host's port or encapsulated to the remote host's VTEP with the VLAN's VNI,
    and no request or reply leaves the switch anywhere else."""
    r = rig
    host = "h0" if who == "local" else "q"
    mac, t = mac_of(host), tag("pg")
    req = echo_request(v, t, r.gw, mac, addr(host, v), SVI[v])
    port, pkt = (r.port[host], req) if who == "local" else (
        r.l1.ptf_port, vxlan_frame(req, r.router_mac, INJ_OUTER_SMAC, r.l1.vtep, r.dut_vtep, VNI))
    with remote_hosts(r, {"q": "macip"} if who == "remote" else {}):
        frames = capture_frames(ptfadapter, lambda: send_paced(ptfadapter, port, pkt), lambda raw: t.encode() in raw,
                                quiet=3.0)
    if who == "local":
        good = sum(1 for f in frames if f.inner is None and f.port == r.port[host] and is_echo_reply(v, f.outer, mac))
    else:
        good = sum(1 for f in frames if encap_to_leaf(r, f, r.l1, VNI) and is_echo_reply(v, f.inner, mac))
    assert delivered(good) and len(frames) == good, (
        "{} of {} echo requests from {} to {} answered{}; {} other copies of the requests or replies left the switch. "
        "Copies: {}{}".format(good, N, "local host H0" if who == "local" else "a host behind " + leaf_text(r.l1),
                              SVI[v], "" if who == "local" else " encapsulated to {} (VNI {})".format(r.l1.vtep, VNI),
                              len(frames) - good, describe(frames), "" if who == "local" else r.cpu_acl))


# --------------------------------------------------------------------------------------------------------------------
# symmetric IRB: a VRF with an L3 VNI
# --------------------------------------------------------------------------------------------------------------------
@VRF_RIG
@pytest.mark.parametrize("route", sorted(L3_ROUTES))
def test_irb_l3vni_encap(rig, ptfadapter, route):
    """A local host of the VRF reaches a host route (/32, /128: type-2 MAC/IP from l2 with the L3 VNI) and a prefix
    (type-5 from l1) over the L3 VNI: APPL_DB has the route with the leaf's VTEP, the L3 VNI and the leaf's router
    MAC, and the host's frames leave encapsulated to the route's VTEP with the L3 VNI, inner destination = the
    leaf's router MAC, inner source = the router MAC, TTL decremented, by hardware, and nowhere else. Control: the
    same host to a local host of the VRF."""
    r = rig
    v = 6 if route.endswith("v6") else 4
    pfx, leaf = L3_ROUTES[route]
    lf = r.leaf[leaf]
    dst = L3_PREFIX_DST if route.startswith("prefix") else L3_HOST[v]
    assert l3_route_ready(r, pfx, lf), (
        "APPL_DB route {} in {}: {}; expected next hop {} with VNI {} and router MAC {}".format(
            pfx, VRF, l3_route_row(r, pfx), lf.vtep, L3VNI, r.rmac[leaf]))
    assert asic_route(r.duthost, pfx), "the route {} over the L3 VNI {} is not in ASIC_DB".format(pfx, L3VNI)
    control(routed(r, ptfadapter, "lc", v, from_local(r, "h0"), addr("h1", v),
                   Native([r.port["h1"]], mac_of("h1"), r.other_gw)), "local host H0 to local host H1 in the VRF")
    o = routed(r, ptfadapter, "le", v, from_local(r, "h0"), dst, to_leaf(r, lf, L3VNI, r.rmac[leaf], r.router_mac))
    assert_forwarded(o, "local host H0 to {} over the L3 VNI {} through {}".format(dst, L3VNI, leaf_text(lf)))


@VRF_RIG
@pytest.mark.parametrize("arm", ["v4_from_b", "v6_from_b", "v4_from_a"])
def test_irb_l3vni_decap(rig, ptfadapter, arm):
    """Traffic from a remote VTEP with the L3 VNI (inner source = the leaf's router MAC), addressed to the router
    MAC, is decapsulated into the VRF and routed to a local host by hardware: once, with the TTL decremented and the
    gateway's source MAC."""
    r = rig
    v, lf = (6 if arm.startswith("v6") else 4), (r.l1 if arm.endswith("a") else r.l2)
    src = from_remote(r, host="L3 VNI host", vni=L3VNI, lf=lf, dmac=r.router_mac, smac=r.rmac[lf.name], sip=L3_HOST)
    o = routed(r, ptfadapter, "ld", v, src, addr("h0", v), Native([r.port["h0"]], mac_of("h0"), r.gw))
    assert_forwarded(o, "L3 VNI {} from {} to the local host H0".format(L3VNI, leaf_text(lf)))


@VRF_RIG
@FAMILY
def test_irb_vrf_gateway_traffic_stays_in_vrf(rig, ptfadapter, v):
    """Traffic from a host behind a remote VTEP to the SVI address of its VRF is for the switch itself: it is
    answered inside the VRF, and no copy of it leaves the switch unencapsulated (it must not be routed in the default
    VRF and out an uplink). The traffic is echo requests, so that the case reads something when the switch behaves:
    every request gets one reply encapsulated to the host's VTEP with the VLAN's VNI, and neither a request nor a
    reply is seen unencapsulated on any port. A run in which no frame at all is captured fails. The host is advertised
    by l1 with its IPs. Control: the same host's traffic to a local host of the VRF is delivered."""
    r = rig
    mac = mac_of("q")
    with remote_hosts(r, {"q": "macip"}):
        control(routed(r, ptfadapter, "vc", v, from_remote(r), addr("h1", v),
                       Native([r.port["h1"]], mac_of("h1"), r.other_gw)),
                "the remote host to local host H1 in the VRF")
        t = tag("vg")
        pkt = vxlan_frame(echo_request(v, t, r.gw, mac, addr("q", v), SVI[v]), r.router_mac, INJ_OUTER_SMAC,
                          r.l1.vtep, r.dut_vtep, VNI)
        frames = capture_frames(ptfadapter, lambda: send_paced(ptfadapter, r.l1.ptf_port, pkt),
                                lambda raw: t.encode() in raw, quiet=3.0)
    native = [f for f in frames if f.inner is None]
    good = sum(1 for f in frames if encap_to_leaf(r, f, r.l1, VNI) and is_echo_reply(v, f.inner, mac))
    assert not native and delivered(good) and len(frames) == good, (
        "{} echo requests from a host behind {} to the SVI address {} of {}: {} answered encapsulated to {} (VNI "
        "{}), {} copies left the switch unencapsulated on ptf {} (uplinks are ptf {}), {} other copies. Copies: "
        "{}{}".format(N, leaf_text(r.l1), SVI[v], VRF, good, r.l1.vtep, VNI, len(native),
                      sorted({f.port for f in native}), r.uplink_ports, len(frames) - good - len(native),
                      describe(frames), r.cpu_acl))


# --------------------------------------------------------------------------------------------------------------------
# withdraw and advertise again under traffic
# --------------------------------------------------------------------------------------------------------------------
def running(r, ptfadapter, name, v, src, dst, want, seconds, change):
    """Send to dst for `seconds` while the test server runs the leaf script commands `change` about two seconds in:
    (frames sent, [seconds] of the right copies, wrong copies, copies elsewhere). A copy on a local host of the VLAN
    is not counted: between the moment the MAC leaves the FDB and the moment the neighbour leaves, the VLAN may flood
    the frame. Whether the copies came from hardware is not read here. Fails when a leaf command failed."""
    t = tag(name)
    job = leaf_later(r.lv, 2, change)
    sent, got = stream_and_count(ptfadapter, src.port, stream_frame(r, t, v, src, dst), t, seconds)
    leaf_later_result(r.lv, job)
    times, wrong, elsewhere = [], [], 0
    local = (r.port["h0"], r.port["h2"])
    for when, c, raw in got:
        f = decode(c.port, raw)
        if not of_stream(f, dst) or (f.inner is None and f.port in local):
            continue
        good, bad, stray = judge_routed([f], want, dst, r.dut_vtep)
        if good:
            times.append(when)
        wrong += bad
        elsewhere += stray
    logger.info("running stream %s: %d sent, %d right copies (first %.1f s, last %.1f s), %d wrong %s, %d elsewhere",
                name, sent, len(times), times[0] if times else -1, times[-1] if times else -1, len(wrong), wrong[:3],
                elsewhere)
    return sent, times, wrong, elsewhere


@EVERY_RIG
@FAMILY
def test_irb_remote_mac_withdrawn_and_readvertised(rig, ptfadapter, v):
    """A host behind a remote VTEP is withdrawn by l1 and advertised again while routed traffic to it runs.

    Before: every frame reaches the host's VTEP by hardware. While the withdrawal lands (l1 deletes the host's
    neighbours, then its MAC, about 2 s into a 6 s stream), and while the host is advertised again (about 2 s into
    a 12 s stream), a frame reaches the host's VTEP correctly, is dropped, or is flooded inside the VLAN: none is
    sent to another VTEP, with a wrong header, or out an uplink unencapsulated. Once withdrawn (the neighbours and
    the MAC are gone from ASIC_DB) no frame leaves the switch, while the same stream to a local host is delivered.
    Advertised again, the frames reach the host's VTEP until the end of the stream, ASIC_DB has the MAC on its
    tunnel, and every frame of a fresh stream reaches the host's VTEP by hardware.
    As in test_irb_route_into_vlan[remote_mac_first] (l1's type-2 MAC/IP routes install the MAC first), when ASIC_DB
    has the MAC on the tunnel but no neighbour and no next hop for the host, the streams have no hardware path: a
    stage read in that state does not assert hardware delivery (each stage reads the state it ran in), every other
    reading still holds, and the case fails at the end naming that state.
    """
    r, d = rig, rig.duthost
    src, dst, mac = into_vlan_source(rig), addr("wd", v), mac_of("wd")
    want = to_leaf(r, r.l1, VNI, mac, r.gw)
    what = "routed traffic to {} behind {}".format(dst, leaf_text(r.l1))
    no_hw_path = []
    with remote_hosts(r, {"wd": "macip"}):
        # the no-hardware-path state relaxes only the stage it is read in
        before_no_hw = judge_remote(r, routed(r, ptfadapter, "w0", v, src, dst, want), "wd", r.l1, dst,
                                    what + ", before the withdrawal", no_hw_path)
        sent, times, wrong, elsewhere = running(r, ptfadapter, "w1", v, src, dst, want, 6,
                                                leaf_host_cmds(r.l1, "wd", "del"))
        assert (times or before_no_hw) and not wrong and elsewhere == 0, (
            "{} while the host is withdrawn ({} frames): {} reached {} correctly, {} had a wrong header {}, {} left "
            "the switch elsewhere".format(what, sent, len(times), r.l1.vtep, len(wrong), wrong[:3], elsewhere))
        wait_state(30, 2, lambda: gone_from_asic(r, "wd"), "the withdrawn host to go from ASIC_DB",
                   lambda: "neighbours {}, FDB '{}'".format(asic_l3(d, [dst]), remote_fdb_dip(d, mac, VLAN_ID)))
        control(routed(r, ptfadapter, "w2", v, src, addr("h0", v), Native([r.port["h0"]], mac_of("h0"), r.gw)),
                "the same stream to the local host H0")
        o = routed(r, ptfadapter, "w3", v, src, dst, want)
        assert not o.frames, "{}, withdrawn: {} frames still left the switch. {}".format(what, len(o.frames), o.text)
        sent, times, wrong, elsewhere = running(r, ptfadapter, "w4", v, src, dst, want, 12,
                                                leaf_host_cmds(r.l1, "wd", "add"))
        wait_neighs_appl(r, "wd")
        in_asic(r, "wd", timeout=20)
        after_no_hw = no_hw_state(r, "wd", r.l1, dst)
        if after_no_hw:
            no_hw_path.append("{}, while advertised again: {} right copies, last {:.1f} s in".format(
                what, len(times), times[-1] if times else -1))
        assert ((times and times[-1] > 10) or after_no_hw) and not wrong and elsewhere == 0, (
            "{} while the host is advertised again ({} frames over 12 s, advertised about 2 s in): {} reached {} "
            "correctly (last one {:.1f} s in), {} had a wrong header {}, {} left the switch elsewhere".format(
                what, sent, len(times), r.l1.vtep, times[-1] if times else -1, len(wrong), wrong[:3], elsewhere))
        dip = remote_fdb_dip(d, mac, VLAN_ID)
        assert dip == r.l1.vtep, "ASIC_DB after the host is advertised again: the MAC's tunnel '{}'".format(dip)
        judge_remote(r, routed(r, ptfadapter, "w5", v, src, dst, want), "wd", r.l1, dst, what + ", advertised again",
                     no_hw_path)
    fail_if_no_hw_path(dst, no_hw_path)


# --------------------------------------------------------------------------------------------------------------------
# a host that moves between a local port and remote VTEPs
# --------------------------------------------------------------------------------------------------------------------
MOVES = ("local", "l1", "l2", "local")
# one host per family, so that no MAC moves often enough to trip EVPN duplicate address detection (5 in 180 s)
MOVER = {4: "mv", 6: "mw"}


def place_text(r, where):
    return "the local port " + r.ifname["h2"] if where == "local" else leaf_text(r.leaf[where])


def l2_joins_vlan(r):
    """l2 serves VNI 12010 as well, with an SVI in the VLAN: VTEP B joins the VLAN's flood list."""
    d = r.duthost
    r.lv.vni_add("l2", VLAN_ID, VNI)
    r.lv.run("svi", "add", "l2", VLAN_ID, "default", *leaf_svi_addrs("l2"))
    wait_for(CONVERGE, 3, lambda: (VLAN, r.l2.vtep) in appl_remote_vnis(d),
             "APPL_DB VXLAN_REMOTE_VNI_TABLE {}:{}".format(VLAN, r.l2.vtep))
    # a virtual switch reports no oper status for a remote VTEP: there only the ASIC_DB tunnel is read
    wait_for(60, 2, lambda: (r.vs or remote_vtep_oper_up(d, r.l2.vtep)) and vxlan_tunnels_to(d, r.l2.vtep) >= 1,
             "remote VTEP {} {}with an ASIC_DB tunnel".format(r.l2.vtep, "" if r.vs else "oper_up "))


def move_host(r, ptfadapter, host, frm, to):
    """Move the host from frm to `to` (None, local = H2's port, or a leaf name) as the control plane converges:
    leaving the local port, its neighbours go and its MAC is flushed; arriving behind a leaf, that leaf advertises it
    (type-2 MAC/IP; from another leaf a MAC mobility move), then the leaf it left removes it; arriving at the local
    port, the leaf withdraws it, then its frames are learned and its neighbours are local again."""
    d, mac = r.duthost, mac_of(host)
    if to == "local":
        if frm:
            leaf_host(r, r.leaf[frm], host, "del")
            wait_state(30, 1, lambda: gone_from_asic(r, host), "{} to go from ASIC_DB after {} withdrew it".format(
                host, frm), lambda: "neighbours {}, FDB '{}'".format(
                    asic_l3(d, [addr(host, v) for v in (4, 6)]), remote_fdb_dip(d, mac, VLAN_ID)))
        learn_mac(ptfadapter, d, r.port["h2"], r.ifname["h2"], VLAN_ID, mac, tag("learn"))
        sh(d, " && ".join(local_neigh_cmd(addr(host, v), mac, VLAN) for v in (4, 6)))
        return
    lf = r.leaf[to]
    if frm == "local":
        sh(d, "; ".join(neigh_del_cmd(addr(host, v), VLAN) for v in (4, 6)))
        flush_fdb(d, "PORT", r.ifname["h2"])
        wait_for(20, 1, lambda: fdb_port(d, VLAN_ID, mac) is None, "{} to go from {}".format(mac, r.ifname["h2"]))
    leaf_host(r, lf, host, "add")
    wait_remote_mac(r, host, lf)
    wait_neighs_appl(r, host)
    if frm not in (None, "local"):
        leaf_host(r, r.leaf[frm], host, "del")


@EVERY_RIG
@FAMILY
def test_irb_routed_traffic_follows_mac_move(rig, ptfadapter, v):
    """Routed traffic to a host follows the host's MAC: from a local port to remote VTEP A (l1 advertises it), to
    remote VTEP B (l2 advertises it, MAC mobility) and back to the local port (l2 withdraws it).

    l2 first joins the VLAN (VNI 12010 and an SVI), so B is in its flood list for the case. After each move, once
    APPL_DB and ASIC_DB have the MAC at its new place, a stream of 40 routed frames must come out there only: on the
    local port natively, or encapsulated to the right VTEP with the VLAN's VNI, inner destination = the host's MAC,
    inner source = the gateway MAC, TTL decremented. No frame may come out where the MAC was before (the previous
    VTEP, or the local port), at any step: that is a hard failure whatever else is read. On the local port the
    stream must be forwarded by hardware; behind a VTEP it must be forwarded by hardware with the host's neighbour
    and next hop in ASIC_DB.
    When, behind a VTEP, ASIC_DB has the MAC on that tunnel but neither a neighbour nor a next hop for the host
    (orchagent leaves out a neighbour whose MAC is behind a VxLAN tunnel), the traffic has no hardware path. The case
    still runs every move, and fails at the end naming that state.
    """
    r, d = rig, rig.duthost
    host = MOVER[v]
    src, dst, mac = into_vlan_source(rig), addr(host, v), mac_of(host)
    no_hw_path, at, body_ok = [], None, False

    def _cleanup():
        step = Steps("moved host clean-up")
        step("local host", lambda: sh(d, "; ".join(neigh_del_cmd(addr(host, f), VLAN) for f in (4, 6)), check=False))
        for lf in (r.l1, r.l2):
            step("{} host".format(lf.name), lambda lf=lf: leaf_host(r, lf, host, "del"))
        step("fdb flush", lambda: flush_fdb(d, "PORT", r.ifname["h2"]))
        step("host gone", lambda: wait_for(30, 1, lambda: gone_from_asic(r, host) and fdb_port(d, VLAN_ID, mac) is None,
                                           "{} to go from ASIC_DB".format(host)))
        step("l2 SVI", lambda: r.lv.run("svi", "del", "l2", VLAN_ID, check=False))
        step("l2 VNI", lambda: r.lv.vni_del("l2", VLAN_ID, VNI, check=False))
        step("B out of the flood list", lambda: wait_for(
            CONVERGE, 3, lambda: (VLAN, r.l2.vtep) not in appl_remote_vnis(d),
            "{} to leave APPL_DB VXLAN_REMOTE_VNI_TABLE of {}".format(r.l2.vtep, VLAN)))
        if not r.vrf:
            step("tunnel gone", lambda: wait_for(60, 3, lambda: not vxlan_tunnels_to(d, r.l2.vtep),
                                                 "the ASIC_DB tunnel to {} to go".format(r.l2.vtep)))
        step.finish(report=body_ok)

    try:
        l2_joins_vlan(r)
        for i, where in enumerate(MOVES):
            move_host(r, ptfadapter, host, at, where)
            what = "routed traffic to {} after its MAC moved from {} to {}".format(
                dst, place_text(r, at) if at else "nowhere", place_text(r, where))
            at = where
            if where == "local":
                in_asic(r, host, timeout=10)
                o = routed(r, ptfadapter, "mm{}{}".format(v, i), v, src, dst, Native([r.port["h2"]], mac, r.gw))
                assert not o.wrong and o.elsewhere == 0, (
                    "{}: frames came out where the MAC is not. {}; kernel: {}".format(
                        what, o.text, o.soft or "not involved"))
                got = asic_l3(d, [dst])[dst]
                assert got == (mac, True), "{}: ASIC_DB has neighbour MAC {}, next hop {} for the host".format(
                    what, got[0], got[1])
                assert_forwarded(o, what)
                continue
            lf = r.leaf[where]
            in_asic(r, host, timeout=10)
            o = routed(r, ptfadapter, "mm{}{}".format(v, i), v, src, dst, to_leaf(r, lf, VNI, mac, r.gw))
            judge_remote(r, o, host, lf, dst, what, no_hw_path)
        body_ok = True
    finally:
        _cleanup()
    fail_if_no_hw_path(dst, no_hw_path)
