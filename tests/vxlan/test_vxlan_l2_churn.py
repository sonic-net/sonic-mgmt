"""L2 VxLAN config churn: VLANs, VNI maps and RIFs added and removed repeatedly must not leak or leave stale state.

Topology t0 or single-ASIC t2 or lt2. The remote state comes from BGP EVPN, through the rig of test_vxlan_evpn_l2.py
(vxlan_evpn_l2_helpers): two FRR leaves on the test server, l1 (VTEP A) and l2 (VTEP B), each joined to the PTF port of
a DUT routed port, peer eBGP ipv4 + l2vpn evpn with the DUT and serve the churned VNI for the whole module. The DUT is
a VTEP on its Loopback0 (vtep1, EVPN NVO nvo1) with BGP to the leaves, also for the whole module. What the cases churn
is the VLAN and its VNI map: mapping the VNI makes the DUT import the leaves' Type-3 routes (remote VTEPs A and B), the
remote MAC behind A is a Type-2 that l1 advertises (a MAC added to its bridge), and unmapping withdraws them; every
step is waited for in APPL_DB and ASIC_DB. Four ports of the base VLAN (the t0's, or on a t2 a Vlan1000 of
neighbor-facing ports that vxlan_l2_helpers.access_ports borrows and restores) leave it for the module: two are the
leaves' routed ports, two are the hosts H0/H1, untagged members of the churned VLAN, so every copy is visible at the
PTF on any fanout. VxLAN from VTEP A is injected on l1's PTF port.

The leaves' sessions, routed ports and VTEP /32 routes are up for the whole module, so they are part of every baseline;
no case touches them (the RIF cases never cycle a leaf's port or a PortChannel the sessions run over, and check that
the sessions and routes stay).

Every case runs one warm-up cycle first (one-time allocations are allowed), takes the baseline after it, then runs
CYCLES more and compares each cycle's end state with that baseline, layer by layer:

  ASIC_DB   object counts per SAI type (VLAN, VLAN_MEMBER, BRIDGE_PORT, TUNNEL*, ROUTER_INTERFACE, NEXT_HOP_GROUP*,
            L2MC/ISOLATION groups; NEXT_HOP only in the PortChannel arm): what orchagent created and removed. The
            L2MC and isolation group counts stay 0 where orchagent uses per-VTEP tunnels and no Ethernet segment
            exists; they are compared so that a group created and left behind by the churn still shows.
  CRM       COUNTERS_DB CRM:STATS used and available: routes used, next-hop groups and members; neighbors and
            next hops only in the PortChannel arm (elsewhere they drift on their own). Polling is CRM_POLL_S here.
            Only resources that CRM reports are covered; there is no router-interface counter, so a leak of the
            hardware interface table behind a RIF is outside the CRM view.
  stale     after each teardown: no APPL_DB/STATE_DB/ASIC_DB rows, kernel netdevs or bridge FDB entries of the
            churned VLAN/VNI or of this module's MACs, no remote VTEP of the VNI and no tunnel to A or B.

A case stops after STOP_AFTER non-flat judged cycles in a row, and no cycle starts once BUDGET_S has passed since
the module started (recorded as a failure), so a leaking image cannot run the module into the runner's timeout.

Cases:
  test_vlan_vni_churn             VLAN + 2 members + VNI map (remote VTEPs A/B from the leaves' Type-3s) + a remote
                                  MAC from l1's Type-2, traffic (local BUM head-end replication, encap unicast, decap
                                  BUM), then all of it removed: l1 withdraws the MAC, the unmap withdraws the VTEPs.
  test_vlan_member_churn          on a live VNI-mapped VLAN with remote VTEPs, a port is added and removed as an
                                  untagged member, a tagged member and inside a LAG; traffic (local and decapsulated)
                                  reaches exactly the current members and the tunnels, a removed member gets nothing
                                  and its MACs go; the last member is removed with the map present.
  test_rif_churn[portchannel]     on a VNI-mapped setup, a PortChannel RIF's addresses removed and re-added (BGP back
                                  each cycle). Checks software state (ASIC_DB, CRM) and forwarding only.
  test_rif_churn[svi]             the same for an SVI on the VNI-mapped VLAN.
  test_port_rif_churn[port]       on a VNI-mapped setup, a router interface on H1 (out of the VNI-mapped VLAN for the
                                  cycles) created and removed PORT_RIF_CYCLES times; it routes before the first and
                                  after the last cycle, and the counts end where they started.
  test_port_rif_churn[subport]    the same for a VLAN sub-interface of H1.
  test_vlan_recreate_no_stale_macs
                                  a deleted and re-created VLAN with a VNI map has no stale MACs: l1 withdraws its
                                  remote MAC, the VLAN is deleted and re-created, and neither that MAC nor a MAC learned
                                  in the old VLAN is held by the new one; unicast to either floods like a never-seen
                                  control MAC. Covers the MACs SONiC knows about; an entry that exists only in hardware
                                  cannot be created from a test and is not covered.

On a virtual switch (asic_type vs) the kernel is the dataplane: every case runs with its ASIC_DB, CRM, stale-state and
traffic readings, but the gate that reads "the decap stayed in hardware" (the kernel VxLAN netdev's rx counter) is not
applied, nor is the re-create case's trapped-to-the-CPU reading (H0's netdev counts every frame there), and the rig's
check that every PTF frame reaches the DUT once is not run (no fanout between the DUT and the PTF).

The leaves run the stock FRR image (vxlan_evpn_l2_helpers.DEFAULT_LEAF_IMAGES; VXLAN_EVPN_LEAF_IMAGE replaces the list).
The module skips when the test server has none of them and cannot pull one.
"""

import json
import logging
import re
import time
from types import SimpleNamespace

import ptf.testutils as testutils
import pytest

from tests.common.helpers.sonic_db import redis_hgetall
from tests.common.utilities import get_inventory_files, wait_until
from tests.vxlan.vxlan_l2_helpers import (
    BROADCAST_MAC,
    KNOWN_HARMLESS_LOG,
    L2NHG_DEL_NOISE_LOG,
    GOOD,
    N,
    TX_ALL,
    TX_SLACK,
    AsicView,
    Steps,
    access_ports,
    add_vxlan,
    asic_count,
    asic_counts,
    asic_vlan_ids,
    db_hget,
    db_keys,
    delivered,
    fail_unless_clean,
    fdb_port,
    flush_fdb,
    flush_vlan_fdb,
    flow_frame,
    her_counts,
    kernel_path,
    kernel_rx_packets,
    kernel_vxlan_netdev,
    learn_mac,
    log_clean,
    make_tagger,
    native_on,
    orch_health,
    probe_frame,
    ptf_ports_of,
    raw_payloads,
    remote_fdb_dip,
    rif_to_cycle,
    route_nexthop_ifaces,
    send_and_count,
    settled_delta,
    sh,
    summarize,
    unicast_counts,
    vxlan_frame,
    vxlan_to,
    vxlan_tunnels_to,
    wait_for,
    wait_state,
    VTEP_NAME,
    NVO_NAME,
)
from tests.vxlan.vxlan_evpn_l2_helpers import (
    Leaf,
    Leaves,
    RigBuild,
    appl_remote_mac_vtep,
    appl_remote_vnis,
    asic_flood_members,
    assert_clean_start as assert_evpn_clean_start,
    check_ingress_once,
    check_leaf_vteps_unrouted,
    dut_has_advertise_all_vni,
    evpn_peer_established,
    pick_rig_ports,
    resolve_leaf_image,
    rig_preflight,
)

pytestmark = [
    pytest.mark.topology("t0", "t2", "lt2"),
]

logger = logging.getLogger(__name__)

CYCLES = 3                  # judged cycles per case, after one warm-up cycle
STOP_AFTER = 2              # consecutive non-flat cycles that end a case early: a per-cycle leak is clear by then
BUDGET_S = 50 * 60          # no cycle starts this long after the module started (the leaves and BGP included)
VLAN_ID = 2100
VLAN = "Vlan{}".format(VLAN_ID)
VNI = 12100
SVI_ADDR = "172.29.249.1/24"

VTEP_A, VTEP_B = "10.255.91.1", "10.255.92.1"
RT_ASN = 65000
# name, ASN, VTEP, leaf /31 address, DUT /31 address; each leaf serves (VLAN_ID, VNI) for the whole module
LEAF_PLAN = [
    ("l1", 65201, VTEP_A, "10.99.0.1", "10.99.0.0"),
    ("l2", 65203, VTEP_B, "10.99.0.3", "10.99.0.2"),
]
CONVERGE = 120              # seconds for BGP / EVPN state to settle

MAC_PREFIX = "02:4c:36"     # every MAC this module sources or has a leaf advertise
MAC_A = "02:4c:36:0a:00:01"           # remote MAC behind A (l1's Type-2)
MAC_R = "02:4c:36:0a:00:0e"           # remote MAC behind A, for the VLAN re-create case
MAC_L = "02:4c:36:0e:00:01"           # learned on H1, for the VLAN re-create case
MAC_U = "02:4c:36:0e:00:0f"           # never sourced anywhere: the unknown-unicast flood control
INJ_OUTER_SMAC = "02:4c:36:ee:00:01"

CRM_POLL_S = 2
# What each case compares. Neighbors and next hops move on their own (arp_update ages unreachable neighbors out), so
# only the PortChannel arm, whose RIF owns a BGP neighbor and its next hop, compares them. Route "available" is never
# compared: with algorithmic route tables it depends on how prefixes pack, which a BGP flap may change. FDB is never
# compared: the base VLAN learns on its own. L2MC_GROUP: orchagent's per-VLAN flood group, created only where the SAI
# has no per-VTEP tunnels. ISOLATION_GROUP*: EVPN multihoming's local bias. Both stay 0 in this rig on per-VTEP-tunnel
# platforms (no Ethernet segment here).
L2_ASIC = ("VLAN", "VLAN_MEMBER", "BRIDGE_PORT", "TUNNEL", "TUNNEL_MAP", "TUNNEL_MAP_ENTRY", "TUNNEL_TERM_TABLE_ENTRY",
           "ROUTER_INTERFACE", "NEXT_HOP_GROUP", "NEXT_HOP_GROUP_MEMBER", "L2MC_GROUP", "ISOLATION_GROUP",
           "ISOLATION_GROUP_MEMBER")
L2_CRM = r"^crm_stats_(ipv4|ipv6)_route_used$|^crm_stats_nexthop_group(_member)?_(used|available)$"
PROFILES = {
    "l2": (L2_ASIC, re.compile(L2_CRM)),
    "member": (L2_ASIC + ("LAG", "LAG_MEMBER"), re.compile(L2_CRM)),
    "pc": (L2_ASIC + ("NEXT_HOP",),
           re.compile(L2_CRM + r"|^crm_stats_(ipv4|ipv6)_(nexthop|neighbor)_(used|available)$")),
}
RIG_TYPES = ("TUNNEL", "TUNNEL_MAP_ENTRY", "VLAN", "VLAN_MEMBER", "BRIDGE_PORT", "ROUTER_INTERFACE")

# fdbsyncd deletes a dynamic kernel FDB entry of a VLAN that the bridge already removed (ret=255, entry gone). The
# churn deletes VLANs with learned MACs, so this races with every VLAN remove; the state it leaves is what is judged.
FDBSYNCD_DEL_RACE_LOG = [
    r".*ERR swss#fdbsyncd: :- updateLocalMac: Failed cmd: bridge fdb del .* vlan \d+, res=, ret=255.*",
]
CHURN_HARMLESS_LOG = KNOWN_HARMLESS_LOG + FDBSYNCD_DEL_RACE_LOG + L2NHG_DEL_NOISE_LOG

tag = make_tagger("VXCH")


# --------------------------------------------------------------------------------------------------------------------
# instruments
# --------------------------------------------------------------------------------------------------------------------
def crm_stats(duthost, fields):
    out = sh(duthost, "sonic-db-cli COUNTERS_DB HGETALL CRM:STATS")
    stats = {k: int(v) for k, v in re.findall(r"'(crm_stats_[a-z0-9_]+)': '(\d+)'", out) if fields.match(k)}
    if not stats:
        raise AssertionError("COUNTERS_DB CRM:STATS has none of the compared fields: {}".format(out[:300]))
    return stats


def diff(base, now):
    """[(layer, key, base, now)] for every value that differs."""
    out = []
    for layer in ("asic", "crm"):
        b, n = base[layer], now[layer]
        for k in sorted(set(b) | set(n)):
            if b.get(k) != n.get(k):
                out.append((layer, k, b.get(k), n.get(k)))
    return out


def fmt(diffs):
    if not diffs:
        return "flat"
    parts = []
    for layer, k, b, n in diffs:
        d = "" if b is None or n is None else " ({:+d})".format(n - b)
        parts.append("{} {} {} -> {}{}".format(layer, k, b, n, d))
    return "; ".join(parts)


def stable(read, gap, tries=12):
    """A read that returned the same value twice, gap seconds apart."""
    x = read()
    for _ in range(tries):
        time.sleep(gap)
        y = read()
        if y == x:
            return y
        x = y
    raise AssertionError("did not stabilise in {} reads {}s apart; last: {}".format(tries, gap, x))


def baseline(r, profile):
    types, fields = PROFILES[profile]
    return {"asic": stable(lambda: asic_counts(r.duthost, types), 5),
            "crm": stable(lambda: crm_stats(r.duthost, fields), 2 * CRM_POLL_S + 1), "profile": profile}


def settle(r, base, asic_wait=90, crm_wait=40):
    """The end state of a cycle, compared with base: [(layer, key, base, now)] (empty = flat).

    ASIC_DB and CRM are waited for until they equal the baseline (orchagent and the CRM poll lag the CLI).
    """
    types, fields = PROFILES[base["profile"]]
    asic = None
    end = time.time() + asic_wait
    while True:
        asic = asic_counts(r.duthost, types)
        if asic == base["asic"] or time.time() > end:
            break
        time.sleep(3)
    crm = None
    end = time.time() + crm_wait
    while True:
        crm = crm_stats(r.duthost, fields)
        if crm == base["crm"] or time.time() > end:
            break
        time.sleep(CRM_POLL_S)
    return diff(base, {"asic": asic, "crm": crm})


# --------------------------------------------------------------------------------------------------------------------
# rig
# --------------------------------------------------------------------------------------------------------------------
def our_macs_left(duthost):
    """Where this module's MACs are still held: [(place, count)] for every non-zero place."""
    script = ("echo asic $(sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*' | grep -ci '{p}'); "
              "echo state_db $(sonic-db-cli STATE_DB KEYS 'FDB_TABLE|*' | grep -ci '{p}'); "
              "echo appl_db $(sonic-db-cli APPL_DB KEYS 'VXLAN_FDB_TABLE:*' | grep -ci '{p}'); "
              "echo kernel $(sudo /sbin/bridge fdb show 2>/dev/null | grep -ci '{p}')").format(p=MAC_PREFIX)
    left = []
    for line in sh(duthost, script).splitlines():
        toks = line.split()
        if len(toks) == 2 and toks[1].isdigit() and int(toks[1]):
            left.append((toks[0], int(toks[1])))
    return left


def rig_counts(duthost):
    return asic_counts(duthost, RIG_TYPES)


class ChurnRig(RigBuild):
    """The EVPN rig without the churned VLAN and VNI map: the VTEP, the NVO, BGP (with the route targets of VNI) and
    the leaves stay up for the module, and the cases create and remove the VLAN and the map."""

    def vtep(self):
        self.built.append(("vtep",))
        add_vxlan(self.duthost, self.dut_vtep, ())
        for key in ("VXLAN_TUNNEL_TABLE:{}".format(VTEP_NAME), "VXLAN_EVPN_NVO_TABLE:{}".format(NVO_NAME)):
            wait_for(60, 2, lambda: bool(db_keys(self.duthost, "APPL_DB", key)), "APPL_DB " + key)

    def underlay_converged(self, timeout):
        """Each leaf's l2vpn evpn session up and its VTEP routed via its port (no VNI to import into yet)."""
        d = self.duthost
        for lf in self.leaves:
            wait_for(timeout, 5, lambda: evpn_peer_established(d, lf.ip),
                     "l2vpn evpn session to {} ({})".format(lf.name, lf.ip))
            wait_for(timeout, 5, lambda: route_nexthop_ifaces(d, lf.vtep) == ("{}/32".format(lf.vtep), {lf.dut_port}),
                     "the DUT's route to {}'s VTEP {} via {}".format(lf.name, lf.vtep, lf.dut_port))


def leaves_steady(r):
    """Failures if a leaf's session or VTEP route is not as the rig built it ([] = steady)."""
    bad = []
    for lf in (r.l1, r.l2):
        try:
            up = evpn_peer_established(r.duthost, lf.ip)
            route = route_nexthop_ifaces(r.duthost, lf.vtep)
        except Exception as e:  # an unreadable state is a failure of this reading, not of the case's body
            up, route = "unreadable ({})".format(e), None
        if up is not True or route != ("{}/32".format(lf.vtep), {lf.dut_port}):
            bad.append("leaf {}: l2vpn evpn session established {}, route to its VTEP {} {} (want /32 via {})".format(
                lf.name, up, lf.vtep, route, lf.dut_port))
    return bad


@pytest.fixture(scope="module")
def crm_fast_poll(duthost):
    out = sh(duthost, "crm show summary")
    m = re.search(r"Polling Interval: +(\d+) +second", out)
    if not m:
        pytest.fail("cannot read the CRM polling interval: {}".format(out))
    sh(duthost, "crm config polling interval {}".format(CRM_POLL_S))
    time.sleep(2 * CRM_POLL_S + 1)
    try:
        yield
    finally:
        sh(duthost, "crm config polling interval {}".format(m.group(1)), check=False)


@pytest.fixture(scope="module")
def access(duthost, tbinfo, request):
    # H0, H1 and the two leaves' routed ports; the port router interface cases use H1
    with access_ports(duthost, tbinfo, request, need=4, want=4) as a:
        yield a


@pytest.fixture(scope="module")
def churn(duthost, tbinfo, ptfadapter, vmhost, ansible_adhoc, request):
    t0 = time.time()
    pre = rig_preflight(vmhost, ansible_adhoc, get_inventory_files(request))
    # after the preflight, so a testbed without a test server borrows no ports
    acc = request.getfixturevalue("access")
    request.getfixturevalue("crm_fast_poll")
    pick = pick_rig_ports(duthost, acc)
    idx, ports = pick.idx, pick.ports
    h0, h1 = ports[0], ports[1]
    leaves = [Leaf(name, "eth{}".format(idx[port]), idx[port], port, asn, vtep, ip, dut_ip, [(VLAN_ID, VNI)])
              for (name, asn, vtep, ip, dut_ip), port in zip(LEAF_PLAN, ports[2:])]
    vs = duthost.facts.get("asic_type") == "vs"
    check_leaf_vteps_unrouted(duthost, leaves)
    assert_evpn_clean_start(duthost, leaves, (VLAN,), (VNI,), more=(("CONFIG_DB", "PORTCHANNEL|{}".format(MEMBER_PC)),))
    fail_unless_clean("L2 VxLAN churn rig", ["{} holds {} of this module's MACs".format(p, n)
                                             for p, n in our_macs_left(duthost)])
    raw_payloads(ptfadapter)
    if not vs:     # a virtual testbed has no fanout between the DUT and the PTF
        check_ingress_once(duthost, ptfadapter, {p: idx[p] for p in ports}, ports, tag("rx"))

    group = tbinfo["group-name"]
    lv = Leaves(pre.server, "ptf_{}".format(group), pre.image, leaves, pick.peer_asn, pick.lo, RT_ASN,
                re.sub(r"[^A-Za-z0-9_.-]", "_", group))
    r = SimpleNamespace(
        duthost=duthost, mg=acc.mg, base_vlan=pick.base_vlan, base_vid=pick.base_vid, h0=h0, h1=h1, p0=idx[h0],
        p1=idx[h1], borrowed=acc.borrowed, dut_vtep=pick.lo, router_mac=duthost.facts["router_mac"], t0=t0, lv=lv,
        l1=leaves[0], l2=leaves[1], vteps=(VTEP_A, VTEP_B), vs=vs,
        leaf_macs={},     # {mac: leaf} a leaf advertises now; vni_vlan_down withdraws them
        acl={})           # ACL table bindings taken off H1 by the member churn's LAG arm
    lv.install()
    try:
        # before the rig changes the DUT: an image that cannot be had is a missing test-server prerequisite
        image_used = resolve_leaf_image(lv)
        rb = ChurnRig(request, duthost, pick, leaves, lv, RT_ASN, ((VLAN_ID, VNI),), baseline=rig_counts,
                      log_ignore=CHURN_HARMLESS_LOG,
                      leftovers=(("CONFIG_DB", "PORTCHANNEL|{}".format(MEMBER_PC)),))
        added_aav = not dut_has_advertise_all_vni(duthost)
    except BaseException:
        lv.remove_files()   # nothing on the DUT yet, so no teardown runs
        raise
    rb.on_teardown("first", "state left by a case", lambda: undo_case_leftovers(r))
    logger.info("rig: base %s, h0/h1 %s/%s (ptf %s/%s), leaves %s, DUT VTEP %s AS %s, image %s, ASIC_DB %s",
                pick.base_vlan, h0, h1, r.p0, r.p1, leaves, r.dut_vtep, pick.dut_asn, image_used, rb.base)

    try:
        with log_clean(request, duthost, "setup", CHURN_HARMLESS_LOG):
            rb.ports_out_of_base()
            # neighbors behind the moved ports can no longer answer; let them go now rather than age out inside a
            # judged cycle
            sh(duthost, "sudo ip -4 neigh flush dev {v}; sudo ip -6 neigh flush dev {v}; true".format(v=pick.base_vlan))
            time.sleep(10)
            rb.leaf_ips()
            rb.vtep()
            rb.wait_connected()
            rb.bgp(added_aav)
            rb.leaves_up()
            rb.underlay_converged(CONVERGE)
        yield r
    finally:
        rb.teardown()


def undo_case_leftovers(r):
    """Undo what a case left behind (the churned VLAN, a leaf MAC, the member LAG, ACL bindings); raise naming it."""
    d, errors = r.duthost, []
    if db_keys(d, "CONFIG_DB", "VLAN|{}".format(VLAN)) or r.leaf_macs:
        errors.append("{} or leaf MACs {} left by a case".format(VLAN, sorted(r.leaf_macs)))
        errors.extend(vni_vlan_down(r))
    if db_keys(d, "CONFIG_DB", "PORTCHANNEL|{}".format(MEMBER_PC)) or r.acl:
        errors.append("{} or the ACL bindings of {} ({}) left by a case".format(MEMBER_PC, r.h1, r.acl))
        errors.extend(member_remove(r, None))
    if errors:
        raise AssertionError("; ".join(errors))


@pytest.fixture(autouse=True)
def ignore_known_harmless(duthost, loganalyzer):
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(CHURN_HARMLESS_LOG)


# --------------------------------------------------------------------------------------------------------------------
# the churned object: a VNI-mapped VLAN with H0/H1 untagged, remote VTEPs and remote MACs from the leaves
# --------------------------------------------------------------------------------------------------------------------
def vlan_flood_set(duthost):
    """Sorted [(VLAN_ID, remote VTEP)] of the churned VLAN's members on tunnel bridge ports in ASIC_DB."""
    return [p for p in asic_flood_members(duthost) if p[0] == VLAN_ID]


def remote_vteps_left(duthost):
    """The churned VLAN's APPL_DB remote VTEPs and the ASIC_DB tunnels to A and B that still exist."""
    tunnels = AsicView(duthost, ("TUNNEL",)).vxlan_tunnels()
    return db_keys(duthost, "APPL_DB", "VXLAN_REMOTE_VNI_TABLE:{}:*".format(VLAN)) + [
        "ASIC_DB tunnel to {}".format(ip) for ip in (VTEP_A, VTEP_B) if tunnels[ip]]


class VniVlan(object):
    """VLAN_ID with H0/H1 untagged, mapped to VNI: the DUT imports both leaves' Type-3 routes (remote VTEPs A and B),
    and each MAC of macs ({mac: leaf}) is advertised by its leaf (Type-2). vni_vlan_down() undoes whatever up() got
    to."""

    def __init__(self, r, macs=None):
        self.r, self.macs = r, dict(macs or {})
        self.vteps = list(r.vteps)
        self.kvx = None

    def up(self):
        d, r = self.r.duthost, self.r
        sh(d, "sudo config vlan add {}".format(VLAN_ID))
        for h in (r.h0, r.h1):
            sh(d, "sudo config vlan member add -u {} {}".format(VLAN_ID, h))
        wait_for(60, 2, lambda: len(db_keys(d, "APPL_DB", "VLAN_MEMBER_TABLE:{}:*".format(VLAN))) == 2,
                 "2 members of {} in APPL_DB".format(VLAN))
        sh(d, "sudo config vxlan map add {} {} {}".format(VTEP_NAME, VLAN_ID, VNI))
        mkey = "VXLAN_TUNNEL_MAP_TABLE:{}:map_{}_{}".format(VTEP_NAME, VNI, VLAN)
        wait_for(60, 2, lambda: bool(db_keys(d, "APPL_DB", mkey)), "APPL_DB " + mkey)
        wait_for(60, 2, lambda: kernel_vxlan_netdev(d, VNI) is not None,
                 "the kernel VxLAN netdev of VNI {}".format(VNI))
        self.kvx = kernel_vxlan_netdev(d, VNI)
        want = {(VLAN, ip) for ip in self.vteps}
        wait_state(CONVERGE, 2, lambda: appl_remote_vnis(d) == want,
                   "APPL_DB VXLAN_REMOTE_VNI_TABLE == {} (the leaves' Type-3 routes)".format(sorted(want)),
                   lambda: sorted(appl_remote_vnis(d)))
        flood = sorted((VLAN_ID, ip) for ip in self.vteps)
        wait_state(60, 2, lambda: vlan_flood_set(d) == flood,
                   "ASIC_DB flood set of {} == {} (a VLAN member on each remote VTEP's tunnel)".format(VLAN, flood),
                   lambda: vlan_flood_set(d))
        for m, lf in self.macs.items():
            r.leaf_macs[m] = lf
            r.lv.fdb("add", lf.name, m, VLAN_ID)
        for m, lf in self.macs.items():
            wait_for(CONVERGE, 2, lambda: appl_remote_mac_vtep(d, VLAN, m) == lf.vtep,
                     "APPL_DB VXLAN_FDB_TABLE {} -> {} ({}'s Type-2)".format(m, lf.vtep, lf.name))
            wait_state(60, 2, lambda: remote_fdb_dip(d, m, VLAN_ID) == lf.vtep,
                       "one ASIC_DB FDB entry for {} on the tunnel to {}".format(m, lf.vtep),
                       lambda: AsicView(d).fdb(m, VLAN_ID))
        time.sleep(3)
        return self


def vni_vlan_down(r):
    """Undo a VniVlan, in dependency order, from what the DBs and r.leaf_macs hold (whatever up() got to); returns
    the steps that failed."""
    d, step = r.duthost, Steps("teardown of {}".format(VLAN))
    exists = bool(db_keys(d, "CONFIG_DB", "VLAN|{}".format(VLAN)))

    def withdraw(m, lf):
        r.lv.run("fdb", "del", lf.name, m, VLAN_ID)     # raises on a nonzero rc: the MAC stays in r.leaf_macs
        del r.leaf_macs[m]

    # the leaves withdraw their MACs while the VLAN still exists: a VLAN re-created while a leaf still advertises a
    # MAC gets it again, as EVPN intends
    for m, lf in list(r.leaf_macs.items()):
        step("withdraw {} at {}".format(m, lf.name), lambda m=m, lf=lf: withdraw(m, lf))
    # learned MACs go while the members exist (flush_vlan_fdb); a flush request for a VLAN orchagent does not know is
    # an ERR of its own
    if exists:
        step("fdb flush", lambda: flush_fdb(d, "VLAN", str(VLAN_ID)))
    step("our MACs gone", lambda: wait_for(CONVERGE, 2, lambda: not our_macs_left(d),
                                           "this module's MACs to leave ASIC_DB, STATE_DB, APPL_DB, the kernel"))
    if db_keys(d, "CONFIG_DB", "VXLAN_TUNNEL_MAP|{}|map_{}_{}".format(VTEP_NAME, VNI, VLAN)):
        step("map del", lambda: sh(d, "sudo config vxlan map del {} {} {}".format(VTEP_NAME, VLAN_ID, VNI)))
        mpat = "VXLAN_TUNNEL_MAP_TABLE:{}:map_{}_*".format(VTEP_NAME, VNI)
        step("map gone", lambda: wait_for(60, 2, lambda: kernel_vxlan_netdev(d, VNI) is None and not db_keys(
            d, "APPL_DB", mpat), "VNI {} unmapped".format(VNI)))
    # the DUT's VNI is gone, and with it what it imported from the leaves' Type-3 routes
    step("remote VTEPs gone", lambda: wait_state(CONVERGE, 3, lambda: not remote_vteps_left(d),
                                                 "the remote VTEPs of {} and their tunnels to go".format(VLAN),
                                                 lambda: remote_vteps_left(d)))
    for k in db_keys(d, "CONFIG_DB", "VLAN_INTERFACE|{}|*".format(VLAN)):
        step("svi del", lambda k=k: sh(d, "sudo config interface ip remove {} {}".format(VLAN, k.split("|")[2])))
    if exists:
        # anything learned since (the PTF hosts' own ND/DAD frames) goes too, before the members do
        step("vlan fdb empty", lambda: flush_vlan_fdb(d, VLAN_ID))
    for k in db_keys(d, "CONFIG_DB", "VLAN_MEMBER|{}|*".format(VLAN)):
        step("member del", lambda k=k: sh(d, "sudo config vlan member del {} {}".format(VLAN_ID, k.split("|")[2])))
    if db_keys(d, "CONFIG_DB", "VLAN_MEMBER|{}|*".format(VLAN)) == [] and \
            db_keys(d, "CONFIG_DB", "VLAN|{}".format(VLAN)):
        step("members gone", lambda: wait_for(60, 2, lambda: not db_keys(
            d, "APPL_DB", "VLAN_MEMBER_TABLE:{}:*".format(VLAN)), "APPL_DB members of {} to go".format(VLAN)))
        step("vlan del", lambda: sh(d, "sudo config vlan del {}".format(VLAN_ID)))
    step("vlan gone", lambda: wait_for(60, 2, lambda: VLAN_ID not in asic_vlan_ids(d),
                                       "VLAN {} to leave ASIC_DB".format(VLAN_ID)))
    if any(e.startswith("vlan gone") for e in step.errors):
        # evidence for the report: what still references the VLAN object
        logger.error("VLAN %s did not leave ASIC_DB; ASIC_DB holders:\n%s", VLAN, sh(d, (
            "for k in $(sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*' | grep -i '{p}'); "
            "do echo $k; done; sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE:*' | "
            "while read k; do echo \"$k $(sonic-db-cli ASIC_DB HGET \"$k\" "
            "SAI_ROUTER_INTERFACE_ATTR_VLAN_ID)\"; done; "
            "sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_VLAN_MEMBER:*'; "
            "sonic-db-cli STATE_DB KEYS 'FDB_TABLE|*'; sonic-db-cli APPL_DB KEYS 'NEIGH_TABLE:*{v}*'").format(
                p=MAC_PREFIX, v=VLAN), check=False))
    return step.errors


def stale_state(r):
    """What is left of VLAN_ID / VNI and of this module's MACs after a teardown, as a list of findings."""
    d, left = r.duthost, []
    for db, pat in (("CONFIG_DB", "VLAN|{}".format(VLAN)), ("CONFIG_DB", "VLAN_MEMBER|{}|*".format(VLAN)),
                    ("CONFIG_DB", "VXLAN_TUNNEL_MAP|*|map_{}_*".format(VNI)),
                    ("APPL_DB", "VLAN_TABLE:{}".format(VLAN)), ("APPL_DB", "VLAN_MEMBER_TABLE:{}:*".format(VLAN)),
                    ("APPL_DB", "VXLAN_TUNNEL_MAP_TABLE:*:map_{}_*".format(VNI)),
                    ("APPL_DB", "VXLAN_REMOTE_VNI_TABLE:*"), ("APPL_DB", "VXLAN_FDB_TABLE:*"),
                    ("STATE_DB", "VLAN_TABLE|{}".format(VLAN)), ("STATE_DB", "VLAN_MEMBER_TABLE|{}|*".format(VLAN)),
                    ("STATE_DB", "FDB_TABLE|{}:*".format(VLAN))):
        keys = db_keys(d, db, pat)
        if keys:
            left.append("{} {}".format(db, keys[:3]))
    for ip in (VTEP_A, VTEP_B):
        if vxlan_tunnels_to(d, ip):
            left.append("ASIC_DB tunnel to {}".format(ip))
    if VLAN_ID in asic_vlan_ids(d):
        left.append("ASIC_DB VLAN {}".format(VLAN_ID))
    if kernel_vxlan_netdev(d, VNI):
        left.append("kernel VxLAN netdev of VNI {}".format(VNI))
    if sh(d, "ip link show {} >/dev/null 2>&1 && echo yes; true".format(VLAN)).strip() == "yes":
        left.append("kernel netdev {}".format(VLAN))
    left += ["{} holds {} of this module's MACs".format(p, n) for p, n in our_macs_left(d)]
    return left


# --------------------------------------------------------------------------------------------------------------------
# traffic through the churned VLAN
# --------------------------------------------------------------------------------------------------------------------
def inject_from_a(r, ptfadapter, kvx, inner, t):
    """inner as VxLAN from VTEP A, on l1's PTF port: (copies, '' or why it is not a hardware decap (kernel_path); ''
    on a virtual switch, where the kernel is the dataplane)."""
    pkt = vxlan_frame(inner, r.router_mac, INJ_OUTER_SMAC, VTEP_A, r.dut_vtep, VNI)
    if r.vs:
        return send_and_count(ptfadapter, r.l1.ptf_port, pkt, N, t), ""
    before = kernel_rx_packets(r.duthost, kvx)
    copies = send_and_count(ptfadapter, r.l1.ptf_port, pkt, N, t)
    return copies, kernel_path(r.duthost, kvx, before, N)


def check_traffic(r, ptfadapter, vlan, label):
    """Forwarding through the VNI-mapped VLAN (VTEPs A and B, MAC_A behind A): local BUM to every remote VTEP and
    H1, known unicast to MAC_A's VTEP only, BUM from VTEP A to H0 and H1. Returns failure strings ([] = all good)."""
    bad = []
    t = tag(label + "b")
    copies = send_and_count(ptfadapter, r.p0, probe_frame(t, BROADCAST_MAC, "02:4c:36:00:00:10"), N, t)
    per, _other = her_counts(copies, r.dut_vtep, vlan.vteps, VNI)
    local = native_on(copies, r.p1, None)
    if not (all(delivered(n) for n in per.values()) and delivered(local)):
        bad.append("local broadcast from {}: per VTEP {}, untagged on {} {} of {}. Copies: {}".format(
            r.h0, per, r.h1, local, N, summarize(copies)))
    t = tag(label + "u")
    copies = send_and_count(ptfadapter, r.p0, probe_frame(t, MAC_A, "02:4c:36:00:00:11"), N, t)
    good, other = unicast_counts(copies, r.dut_vtep, VTEP_A, VNI, MAC_A)
    flooded = native_on(copies, r.p1)
    if not (delivered(good) and other == 0 and flooded == 0):
        bad.append("unicast to {}: {} to {}, {} other VxLAN, {} flooded to {}. Copies: {}".format(
            MAC_A, good, VTEP_A, other, flooded, r.h1, summarize(copies)))
    t = tag(label + "d")
    copies, why = inject_from_a(r, ptfadapter, vlan.kvx, probe_frame(t, BROADCAST_MAC, "02:4c:36:0a:00:12"), t)
    got = {h: native_on(copies, p, None) for h, p in ((r.h0, r.p0), (r.h1, r.p1))}
    if why or not all(delivered(n) for n in got.values()):
        bad.append("broadcast decapsulated from {}: untagged {} of {}{}. Copies: {}".format(
            VTEP_A, got, N, "; " + why if why else "", summarize(copies)))
    return bad


# --------------------------------------------------------------------------------------------------------------------
# cases
# --------------------------------------------------------------------------------------------------------------------
def judge(name, rows, base):
    """Fail with the whole per-cycle table if a cycle broke, or a judged cycle (1..) is not back to the baseline."""
    lines = ["  cycle {}: {}{}".format(c, fmt(d), "".join("; " + x for x in extra)) for c, d, extra in rows]
    bad = [c for c, d, extra in rows if extra or (c > 0 and d)]
    logger.info("%s, baseline after the warm-up %s:\n%s", name, base, "\n".join(lines))
    assert not bad, "{}: cycles {} broken or not back to the post-warm-up baseline (cycle 0 = warm-up, counts not " \
                    "judged):\n{}".format(name, bad, "\n".join(lines))


def keep_going(r, rows):
    """Whether to start another cycle: not after a broken one, not after STOP_AFTER non-flat judged cycles in a row
    (the leak is clear), and not once the module's time budget is spent (that is recorded as a failure)."""
    if rows[-1][2]:
        return False
    judged = [d for c, d, _ in rows if c > 0]
    if len(judged) >= STOP_AFTER and all(judged[-STOP_AFTER:]):
        return False
    if time.time() - r.t0 > BUDGET_S:
        rows.append((rows[-1][0] + 1, [], ["module time budget ({} s) spent, cycle not run".format(BUDGET_S)]))
        return False
    return True


def test_vlan_vni_churn(churn, ptfadapter):
    """Create a VNI-mapped VLAN with remote VTEPs and a remote MAC, pass traffic, remove it all; CYCLES times after a
    warm-up.

    The remote VTEPs are the leaves' Type-3 routes, imported when the VNI is mapped and withdrawn when it is unmapped;
    the remote MAC is l1's Type-2, advertised after the VTEPs are in place and withdrawn first. Every cycle must
    forward (so a re-created object is really programmed) and end with ASIC_DB and CRM counts equal to the post-warm-up
    baseline and no stale state of the VLAN, the VNI, the remote VTEPs or the module's MACs.
    """
    r, rows, base = churn, [], None
    for c in range(CYCLES + 1):
        if c and not keep_going(r, rows):
            break
        vlan = VniVlan(r, {MAC_A: r.l1})
        extra = []
        try:
            vlan.up()
            extra += check_traffic(r, ptfadapter, vlan, "v{}".format(c))
        finally:
            extra += vni_vlan_down(r)
        extra += ["stale: {}".format(s) for s in stale_state(r)]
        d = []
        if not extra:
            if c == 0:
                base = baseline(r, "l2")
            else:
                d = settle(r, base)
        rows.append((c, d, extra))
    judge("VLAN + VNI map churn", rows, base)


# --------------------------------------------------------------------------------------------------------------------
# VLAN member churn on a live VNI-mapped VLAN
# --------------------------------------------------------------------------------------------------------------------
MEMBER_MODES = ("untagged", "tagged", "portchannel")
MEMBER_PC = "PortChannel2100"         # the LAG that H1 is put in for the portchannel arm
MAC_X = "02:4c:36:0e:00:21"           # learned on the churned member
SRC_H0 = "02:4c:36:00:00:14"          # H0's source for the member readings
LAG_UP_S = 150                        # an LACP fallback LAG with a silent partner comes up after LACP expiry


def member_wait(d, iface, present, members):
    key = "VLAN_MEMBER_TABLE:{}:{}".format(VLAN, iface)
    wait_for(60, 2, lambda: bool(db_keys(d, "APPL_DB", key)) == present and
             asic_count(d, "VLAN_MEMBER") == members,
             "{} {} {} (APPL_DB and {} ASIC_DB VLAN members)".format(
                 iface, "in" if present else "out of", VLAN, members))
    time.sleep(3)


def acl_unbind(r):
    """Take H1 out of the ACL tables bound to it (a port bound to an ACL table cannot join a LAG); r.acl holds what
    acl_rebind puts back."""
    d = r.duthost
    for key in db_keys(d, "CONFIG_DB", "ACL_TABLE|*"):
        ports = db_hget(d, "CONFIG_DB", key, "ports@")
        if r.h1 in ports.split(","):
            r.acl.setdefault(key, ports)
            sh(d, "sonic-db-cli CONFIG_DB HSET '{}' ports@ '{}'".format(
                key, ",".join(p for p in ports.split(",") if p != r.h1)))
    if r.acl:
        time.sleep(5)


def acl_rebind(r):
    for key, ports in list(r.acl.items()):
        sh(r.duthost, "sonic-db-cli CONFIG_DB HSET '{}' ports@ '{}'".format(key, ports))
        del r.acl[key]


def member_add(r, mode, members):
    """Make H1 a member of the churned VLAN: untagged, tagged, or as the only port of an untagged LAG member.
    members: ASIC_DB VLAN_MEMBER count before. Returns the member interface."""
    d, iface = r.duthost, r.h1
    if mode == "portchannel":
        iface = MEMBER_PC
        acl_unbind(r)
        # no LACP partner at the PTF: fallback selects the port once LACP expires
        sh(d, "sudo config portchannel add --fallback true {}".format(MEMBER_PC))
        sh(d, "sudo config portchannel member add {} {}".format(MEMBER_PC, r.h1))
        wait_for(LAG_UP_S, 3, lambda: db_hget(d, "APPL_DB", "LAG_TABLE:{}".format(MEMBER_PC), "oper_status") == "up"
                 and db_hget(d, "APPL_DB", "LAG_MEMBER_TABLE:{}:{}".format(MEMBER_PC, r.h1), "status") == "enabled",
                 "{} up with {} enabled".format(MEMBER_PC, r.h1))
    sh(d, "sudo config vlan member add {}{} {}".format("" if mode == "tagged" else "-u ", VLAN_ID, iface))
    member_wait(d, iface, True, members + 1)
    return iface


def member_remove(r, members):
    """Take H1 (or its LAG) out of the churned VLAN again, from what CONFIG_DB holds, and remove the LAG.
    members: ASIC_DB VLAN_MEMBER count to return to (None: do not wait). Returns the steps that failed."""
    d, step = r.duthost, Steps("member removal")

    def undo():
        for iface in (MEMBER_PC, r.h1):
            if db_keys(d, "CONFIG_DB", "VLAN_MEMBER|{}|{}".format(VLAN, iface)):
                step("member del " + iface, lambda i=iface: sh(
                    d, "sudo config vlan member del {} {}".format(VLAN_ID, i)))
                if members is not None:
                    step("member gone " + iface, lambda i=iface: member_wait(d, i, False, members))
        if db_keys(d, "CONFIG_DB", "PORTCHANNEL_MEMBER|{}|{}".format(MEMBER_PC, r.h1)):
            step("lag member del", lambda: sh(d, "sudo config portchannel member del {} {}".format(MEMBER_PC, r.h1)))
        if db_keys(d, "CONFIG_DB", "PORTCHANNEL|{}".format(MEMBER_PC)):
            step("lag del", lambda: sh(d, "sudo config portchannel del {}".format(MEMBER_PC)))
            step("lag gone", lambda: wait_for(60, 2, lambda: not db_keys(
                d, "APPL_DB", "LAG_TABLE:{}".format(MEMBER_PC)), "{} to go".format(MEMBER_PC)))
        if r.acl:
            step("acl rebind", lambda: acl_rebind(r))
    step("member removal", undo)
    return step.errors


READING_BURSTS = 5
# other traffic H1 may transmit in member_reading's window, which spans its five bursts
READING_SLACK = READING_BURSTS * TX_SLACK


def member_reading(r, ptfadapter, vlan, label):
    """Five bursts of N through the VNI-mapped VLAN inside one TX counter window of H1: a local broadcast from H0,
    known unicast from H0 to MAC_A, a broadcast decapsulated from VTEP A, unicast from H0 to MAC_X, and unicast to
    MAC_X decapsulated from VTEP A.

    Returns (failures of what does not depend on H1's membership, {burst: copies}, H1's DUT TX in the window).
    """
    bad, got = [], {}

    def bursts():
        t = tag(label + "b")
        got["bum"] = send_and_count(ptfadapter, r.p0, probe_frame(t, BROADCAST_MAC, SRC_H0), N, t)
        per, other = her_counts(got["bum"], r.dut_vtep, vlan.vteps, VNI)
        if not all(delivered(n) for n in per.values()) or other:
            bad.append("local broadcast from {}: per VTEP {}, {} other VxLAN. Copies: {}".format(
                r.h0, per, other, summarize(got["bum"])))
        t = tag(label + "u")
        got["uni"] = send_and_count(ptfadapter, r.p0, probe_frame(t, MAC_A, SRC_H0), N, t)
        good, other = unicast_counts(got["uni"], r.dut_vtep, VTEP_A, VNI, MAC_A)
        if not delivered(good) or other:
            bad.append("unicast to {}: {} to {}, {} other VxLAN. Copies: {}".format(
                MAC_A, good, VTEP_A, other, summarize(got["uni"])))
        t = tag(label + "d")
        got["decap"], why = inject_from_a(r, ptfadapter, vlan.kvx, probe_frame(t, BROADCAST_MAC, "02:4c:36:0a:00:12"),
                                          t)
        at_h0, emitted = native_on(got["decap"], r.p0, None), len(vxlan_to(got["decap"], r.dut_vtep))
        if why or not delivered(at_h0) or emitted:
            bad.append("broadcast decapsulated from {}: {} of {} untagged at {}, {} re-encapsulated{}. Copies: {}"
                       .format(VTEP_A, at_h0, N, r.h0, emitted, "; " + why if why else "", summarize(got["decap"])))
        t = tag(label + "x")
        got["to_x"] = send_and_count(ptfadapter, r.p0, probe_frame(t, MAC_X, SRC_H0), N, t)
        t = tag(label + "y")
        got["decap_x"], why = inject_from_a(r, ptfadapter, vlan.kvx, probe_frame(t, MAC_X, "02:4c:36:0a:00:12"), t)
        emitted = len(vxlan_to(got["decap_x"], r.dut_vtep))
        if why or emitted:
            bad.append("unicast to {} decapsulated from {}: {} re-encapsulated{}. Copies: {}".format(
                MAC_X, VTEP_A, emitted, "; " + why if why else "", summarize(got["decap_x"])))

    tx, _took, _ = settled_delta(r.duthost, [r.h1], 40, bursts, TX_ALL)
    logger.info("%s: DUT TX on %s in the window: %d", label, r.h1, tx[0])
    return bad, got, tx[0]


def member_present(r, ptfadapter, vlan, mode, iface, label):
    """Failures of forwarding with H1 a member in mode: H1 gets the local broadcast, the decapsulated broadcast and
    the unicast to the MAC learned on it, local and decapsulated from VTEP A (H0 gets no copy of the latter), not the
    unicast to the remote MAC; a frame from H1 to the remote MAC is encapsulated.

    H1's copies are read from its DUT TX counter, and at the PTF in the form it sees: untagged copies of an untagged
    member, tagged copies of a tagged one where the path to the PTF carries them. Any copy in the other form fails.
    A LAG member also transmits LACP, so there the TX counter is a lower bound and the PTF count is the exact one.
    """
    vid = VLAN_ID if mode == "tagged" else None
    # Taught with unicast to the remote MAC, which leaves only through the tunnel: a broadcast would also leave on H0,
    # and an L2 switch between H0's port and the PTF would learn MAC_X there and drop the later floods to it.
    testutils.send(ptfadapter, r.p1, probe_frame(tag(label + "l"), MAC_A, MAC_X, vlan=vid), count=3)
    wait_for(20, 1, lambda: fdb_port(r.duthost, VLAN_ID, MAC_X) == iface, "{} learned on {}".format(MAC_X, iface))
    bad, got, tx = member_reading(r, ptfadapter, vlan, label)
    seen = {k: native_on(c, r.p1, vid) for k, c in got.items()}
    wrong = {k: native_on(c, r.p1) - seen[k] for k, c in got.items()}
    want = ("bum", "decap", "to_x", "decap_x")
    at_ptf = mode != "tagged" or any(seen[k] for k in want)
    most = None if mode == "portchannel" else len(want) * N + READING_SLACK
    at_h0 = native_on(got["decap_x"], r.p0)
    if (tx < len(want) * GOOD or (most is not None and tx > most) or any(wrong.values()) or seen["uni"] or
            (at_ptf and not all(delivered(seen[k]) for k in want)) or len(vxlan_to(got["to_x"], r.dut_vtep)) or
            at_h0):
        bad.append("{} as a {} member: DUT TX on {} {} for {} bursts of {} (and none of the unicast to {}); at the "
                   "PTF {} {}, in another tag form {}; {} VxLAN copies of the unicast to {}; {} copies at {} of the "
                   "decapsulated unicast to it".format(
                       iface, mode, r.h1, tx, len(want), N, MAC_A, "tagged" if vid else "untagged", seen, wrong,
                       len(vxlan_to(got["to_x"], r.dut_vtep)), MAC_X, at_h0, r.h0))
    t = tag(label + "e")
    copies = send_and_count(ptfadapter, r.p1, probe_frame(t, MAC_A, MAC_X, vlan=vid), N, t)
    good, other = unicast_counts(copies, r.dut_vtep, VTEP_A, VNI, MAC_A)
    if not delivered(good) or other or native_on(copies, r.p0):
        bad.append("unicast from the new member to {}: {} to {}, {} other VxLAN, {} at {}. Copies: {}".format(
            MAC_A, good, VTEP_A, other, native_on(copies, r.p0), r.h0, summarize(copies)))
    return ["{} [{}]".format(b, mode) for b in bad]


def member_absent(r, ptfadapter, vlan, label):
    """Failures of forwarding once H1 is out of the VLAN: its MAC is gone, nothing leaves on H1 (DUT TX and PTF),
    unicast to its MAC decapsulated from VTEP A floods to H0, and H0 and the remote VTEPs get what they got before."""
    d = r.duthost
    gone = wait_until(30, 2, 0, lambda: not AsicView(d).fdb(MAC_X, VLAN_ID) and fdb_port(d, VLAN_ID, MAC_X) is None)
    bad, got, tx = member_reading(r, ptfadapter, vlan, label)
    at_ptf = {k: native_on(c, r.p1) for k, c in got.items()}
    if tx > READING_SLACK or any(at_ptf.values()):
        bad.append("{} is out of {}: DUT TX on it {} (want <= {}), at the PTF {}".format(r.h1, VLAN, tx, READING_SLACK,
                                                                                         at_ptf))
    if not gone:
        bad.append("{} (learned on the removed member) is still in the FDB: {}".format(
            MAC_X, AsicView(d).fdb(MAC_X, VLAN_ID)))
    flooded = native_on(got["decap_x"], r.p0, None)
    if not delivered(flooded):
        bad.append("unicast to {} decapsulated from {}: {} of {} flooded untagged to {}".format(
            MAC_X, VTEP_A, flooded, N, r.h0))
    return ["{} [{}]".format(b, label) for b in bad]


def no_member(r, ptfadapter, vlan, label, members):
    """Remove the last member (H0) with the VNI map and the remote VTEPs in place, read, and put H0 back.

    A broadcast decapsulated from VTEP A has nowhere to go: no copy on any port, none sent back into a tunnel. The
    map and the tunnels to the remote VTEPs stay."""
    d, bad = r.duthost, []
    maps = asic_count(d, "TUNNEL_MAP_ENTRY")
    sh(d, "sudo config vlan member del {} {}".format(VLAN_ID, r.h0))
    try:
        member_wait(d, r.h0, False, members - 1)
        t = tag(label + "n")
        copies, why = inject_from_a(r, ptfadapter, vlan.kvx, probe_frame(t, BROADCAST_MAC, "02:4c:36:0a:00:13"), t)
        gone = [ip for ip in vlan.vteps if not vxlan_tunnels_to(d, ip)]
        if copies or why or gone or asic_count(d, "TUNNEL_MAP_ENTRY") != maps:
            bad.append("{} with no member: a broadcast decapsulated from {} was forwarded ({}){}; tunnels gone {}; "
                       "ASIC_DB tunnel map entries {} -> {}".format(
                           VLAN, VTEP_A, summarize(copies), "; " + why if why else "", gone, maps,
                           asic_count(d, "TUNNEL_MAP_ENTRY")))
    finally:
        sh(d, "sudo config vlan member add -u {} {}".format(VLAN_ID, r.h0))
        member_wait(d, r.h0, True, members)
    return bad


def test_vlan_member_churn(churn, ptfadapter):
    """Members added to and removed from a live VNI-mapped VLAN with remote VTEPs; CYCLES times after a warm-up.

    The VLAN, its VNI map, the remote VTEPs A and B (the leaves' Type-3s) and l1's remote MAC stay up; H0 stays an
    untagged member. Each cycle makes H1 a member and removes it again three times: untagged, tagged, and as the port
    of a LAG (LACP fallback: the PTF runs no LACP). While H1 is a member, local and decapsulated broadcasts and unicast
    to a MAC learned on it, local and decapsulated, reach it, and a frame from it to the remote MAC is encapsulated.
    Once it is removed its MAC is gone, nothing leaves on it, and decapsulated unicast to that MAC floods to H0.
    Throughout, H0 and both remote VTEPs get exactly what they got before. Each cycle ends by removing the last member
    (H0) with the map still present, adding it back and reading the traffic again. The end state of every judged
    cycle must equal the post-warm-up baseline (ASIC_DB object counts with LAGs, CRM), and nothing of the VLAN, the
    VNI, the LAG or the module's MACs may be left at the end.
    """
    r, d = churn, churn.duthost
    if time.time() - r.t0 > BUDGET_S:
        pytest.fail("module time budget ({} s) spent before this case started".format(BUDGET_S))
    modes = MEMBER_MODES
    if r.vs:
        # the vs SAI learns an untagged frame on a LAG member in the member port's own PVID, never the LAG's: no MAC
        # is learned on the LAG there, so the PortChannel arm runs on hardware only
        modes = tuple(m for m in MEMBER_MODES if m != "portchannel")
        logger.info("virtual switch: member arms %s (the PortChannel arm needs hardware)", modes)
    vlan = VniVlan(r, {MAC_A: r.l1})
    rows, base, errors, done = [], None, [], False
    r.lags = asic_count(d, "LAG")
    try:
        vlan.up()
        # H0 is the member that stays: H1 leaves until a cycle adds it
        members = asic_count(d, "VLAN_MEMBER") - 1
        sh(d, "sudo config vlan member del {} {}".format(VLAN_ID, r.h1))
        member_wait(d, r.h1, False, members)
        bad = member_absent(r, ptfadapter, vlan, "ms")
        if bad:
            pytest.fail("the VNI does not forward before any member cycle, nothing to compare: {}".format(bad))
        for c in range(CYCLES + 1):
            if c and not keep_going(r, rows):
                break
            extra = []
            for mode in modes:
                label = "m{}{}".format(c, mode[0])
                try:
                    iface = member_add(r, mode, members)
                    extra += member_present(r, ptfadapter, vlan, mode, iface, label)
                finally:
                    extra += member_remove(r, members)
                extra += member_absent(r, ptfadapter, vlan, label + "r")
                if extra:
                    break
            if not extra:
                extra += no_member(r, ptfadapter, vlan, "m{}".format(c), members)
                extra += member_absent(r, ptfadapter, vlan, "m{}z".format(c))
            diffs = []
            if not extra:
                if c == 0:
                    base = baseline(r, "member")
                else:
                    diffs = settle(r, base)
            rows.append((c, diffs, extra))
        done = True
    finally:
        errors += member_remove(r, None)
        errors += vni_vlan_down(r)
        try:
            errors += ["stale: {}".format(s) for s in stale_state(r)]
            errors += ["stale: CONFIG_DB {}".format(k) for k in db_keys(d, "CONFIG_DB", "PORTCHANNEL*|{}*".format(
                MEMBER_PC))]
            if asic_count(d, "LAG") != r.lags:
                errors.append("stale: ASIC_DB LAGs {} -> {}".format(r.lags, asic_count(d, "LAG")))
        except Exception as e:  # never mask the body's own failure
            errors.append("stale-state read: {}".format(e))
        if errors and not done:
            logger.error("VLAN member churn cleanup after a failure: %s", errors)
    judge("VLAN member churn", rows, base)
    assert not errors, "VLAN member churn cleanup: {}".format(errors)


# --------------------------------------------------------------------------------------------------------------------
# router interface churn next to a live VNI-mapped VLAN
# --------------------------------------------------------------------------------------------------------------------
def pc_under_test(r):
    """A PortChannel with BGP neighbors that holds neither a leaf's port nor a borrowed one: (pc, addresses,
    neighbors). The leaves' sessions run over their own routed ports, so cycling it never touches them."""
    cycled = rif_to_cycle(r.mg, [r.l1.ptf_port, r.l2.ptf_port], r.borrowed)
    if not cycled:
        pytest.fail("no PortChannel RIF with BGP neighbors to cycle")
    return cycled


def key_fields(duthost, key):
    """The fields of a CONFIG_DB key other than the NULL placeholder."""
    return {k: v for k, v in redis_hgetall(duthost, "CONFIG_DB", key).items() if k != "NULL"}


# Runs on the DUT host: the default-VRF APPL_DB routes with a next hop on interface argv[1] (directly or through their
# next-hop group), and the default route's next-hop interfaces.
_ROUTES_VIA = """import json
import sys
from swsscommon.swsscommon import SonicV2Connector

db = SonicV2Connector(use_unix_socket_path=True)
db.connect("APPL_DB")
iface, n, via, default = sys.argv[1], 0, [], []
for k in db.keys("APPL_DB", "ROUTE_TABLE:*") or []:
    a = db.get_all("APPL_DB", k) or dict()
    n += 1
    ifs = a.get("ifname", "")
    if not ifs and a.get("nexthop_group"):
        ifs = db.get("APPL_DB", "NEXTHOP_GROUP_TABLE:" + a["nexthop_group"], "ifname") or ""
    names = [i for i in ifs.split(",") if i]
    prefix = k.split(":", 1)[1]
    if iface in names:
        via.append(prefix)
    if prefix == "0.0.0.0/0":
        default = names
print(json.dumps(dict(n=n, via=sorted(via), default=sorted(default))))
"""


def routes_via(duthost, iface):
    """(APPL_DB prefixes with a next hop on iface, the default route's next-hop interfaces): what a cycled
    PortChannel's BGP neighbors restore. Raises when APPL_DB cannot be read or holds no route."""
    out = sh(duthost, "sudo python3 - {} <<'EOF'\n{}EOF".format(iface, _ROUTES_VIA))
    got = json.loads(out.strip().splitlines()[-1])
    if not got["n"]:
        raise AssertionError("APPL_DB ROUTE_TABLE holds no route")
    return frozenset(got["via"]), frozenset(got["default"])


@pytest.mark.parametrize("kind", ["portchannel", "svi"])
def test_rif_churn(churn, ptfadapter, kind):
    """Remove and re-add a RIF CYCLES times (after a warm-up) while a VLAN is VNI-mapped with remote VTEPs.

    portchannel: a PortChannel's addresses (its RIF goes and comes back; its BGP sessions and their routes in APPL_DB
    must return). svi: an address on the VNI-mapped VLAN. Each cycle must end with ASIC_DB and CRM counts at the
    baseline, the VNI keeps forwarding after every cycle, and the leaves' sessions and VTEP routes never move.
    """
    r, d = churn, churn.duthost
    if kind == "portchannel":
        iface, addrs, neighbors = pc_under_test(r)
        table, profile = "PORTCHANNEL_INTERFACE", "pc"
    else:
        iface, addrs, neighbors = VLAN, [SVI_ADDR], []
        table, profile = "VLAN_INTERFACE", "l2"
    fields = key_fields(d, "{}|{}".format(table, iface)) if kind == "portchannel" else {}
    vlan = VniVlan(r, {MAC_A: r.l1})
    rows, base, errors, removed, done = [], None, [], [], False

    def restore_fields():
        # `config interface ip add` re-creates the interface key as NULL; put back what it carried
        for k, v in fields.items():
            sh(d, "sonic-db-cli CONFIG_DB HSET '{}|{}' '{}' '{}'".format(table, iface, k, v))

    def _cleanup():
        nonlocal errors
        for a in removed:
            try:
                sh(d, "sudo config interface ip add {} {}".format(iface, a))
            except Exception as e:  # reported below
                errors.append("restore {} {}: {}".format(iface, a, e))
        if fields:
            try:
                restore_fields()
            except Exception as e:  # reported below
                errors.append("restore {} fields: {}".format(iface, e))
        errors += vni_vlan_down(r)
        if neighbors and not wait_until(240, 5, 0, lambda: d.check_bgp_session_state(neighbors)):
            errors.append("BGP to {} did not come back".format(neighbors))
        try:
            errors += ["stale: {}".format(s) for s in stale_state(r)]
        except Exception as e:  # never mask the body's own failure
            errors.append("stale-state read: {}".format(e))
        if errors and not done:
            logger.error("RIF churn (%s) cleanup after a failure: %s", kind, errors)

    try:
        vlan.up()
        if kind == "svi":
            n0 = asic_count(d, "ROUTER_INTERFACE")
            sh(d, "sudo config interface ip add {} {}".format(VLAN, SVI_ADDR))
            wait_for(60, 2, lambda: asic_count(d, "ROUTER_INTERFACE") == n0 + 1, "the {} RIF".format(VLAN))
        rif0 = asic_count(d, "ROUTER_INTERFACE")
        bad = check_traffic(r, ptfadapter, vlan, "r{}s".format(kind[0])) + leaves_steady(r)
        if bad:
            pytest.fail("the VNI does not forward before any RIF cycle, nothing to compare: {}".format(bad))
        routes0 = routes_via(d, iface) if neighbors else None
        if neighbors and not routes0[0]:
            pytest.fail("no APPL_DB route has a next hop on {}: its neighbors' return cannot be read".format(iface))
        for c in range(CYCLES + 1):
            if c and not keep_going(r, rows):
                break
            for a in addrs:
                sh(d, "sudo config interface ip remove {} {}".format(iface, a))
                removed.append(a)
            wait_for(60, 2, lambda: asic_count(d, "ROUTER_INTERFACE") == rif0 - 1, "the {} RIF to go".format(iface))
            time.sleep(3)
            for a in list(removed):
                sh(d, "sudo config interface ip add {} {}".format(iface, a))
                removed.remove(a)
            restore_fields()
            wait_for(60, 2, lambda: asic_count(d, "ROUTER_INTERFACE") == rif0, "the {} RIF to come back".format(iface))
            if neighbors:
                wait_for(240, 5, lambda: d.check_bgp_session_state(neighbors),
                         "BGP to {} over the re-created {} RIF".format(neighbors, iface))
                wait_state(180, 5, lambda: routes_via(d, iface) == routes0,
                           "the {} APPL_DB routes via {} and the default route's next hops {} to return".format(
                               len(routes0[0]), iface, sorted(routes0[1])),
                           lambda: routes_via(d, iface))
            extra = check_traffic(r, ptfadapter, vlan, "r{}{}".format(kind[0], c)) + leaves_steady(r)
            diffs = []
            if not extra:
                if c == 0:
                    base = baseline(r, profile)
                else:
                    diffs = settle(r, base, asic_wait=120, crm_wait=90)
            rows.append((c, diffs, extra))
        done = True
    finally:
        _cleanup()
    judge("RIF churn ({} {})".format(kind, iface), rows, base)
    assert not errors, "RIF churn ({}) cleanup: {}".format(kind, errors)


# --------------------------------------------------------------------------------------------------------------------
# router interfaces on a front-panel port and on a sub-interface of it
# --------------------------------------------------------------------------------------------------------------------
PORT_RIF_CYCLES = 30
PORT_RIF_BATCH = 10
PORT_RIF_ADDR = "172.29.248.1/24"
PORT_RIF_HOST = ("02:4c:36:0e:00:31", "172.29.248.2")     # a host on the router interface: MAC, address
PORT_RIF_DST = "192.0.2.77"                               # routed out an uplink
SUBPORT_VID, SUBPORT_OTHER_VID = 2601, 2602
PORT_RIF_SCRIPT = "/tmp/vxlan_l2_churn_rif_cycles.sh"
# $1 cycles of create and remove, each waited for in ASIC_DB. One "FAIL ..." line for the step that failed, then
# "DONE ok=<cycles completed>".
PORT_RIF_SH = r"""#!/bin/bash
rifs(){ sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE:*' | grep -c .; }
w(){ local j; for j in $(seq 300); do [ "$(rifs)" = "$1" ] && return 0; sleep 0.1; done; return 1; }
said(){ tr '\n' ' ' < %(script)s.out | cut -c1-300; }
base=$(rifs); ok=0
for i in $(seq "$1"); do
  { %(add)s; } > %(script)s.out 2>&1 || { echo "FAIL cycle $i: the create command failed: $(said)"; break; }
  w $((base + 1)) || { echo "FAIL cycle $i: create: ASIC_DB router interfaces $(rifs), expected $((base + 1))"; break; }
  { %(rem)s; } > %(script)s.out 2>&1 || { echo "FAIL cycle $i: the remove command failed: $(said)"; break; }
  w "$base" || { echo "FAIL cycle $i: remove: ASIC_DB router interfaces $(rifs), expected $base"; break; }
  ok=$i
done
rm -f %(script)s.out
echo "DONE ok=$ok"
"""


def port_rif_commands(kind, port):
    """(netdev, create commands, remove commands) of the router interface under test."""
    if kind == "port":
        dev, add, rem = port, [], []
    else:
        dev = "Eth{}.{}".format(port.replace("Ethernet", ""), SUBPORT_VID)
        add = ["sudo config subinterface add {} {}".format(dev, SUBPORT_VID)]
        rem = ["sudo config subinterface del {}".format(dev)]
    return (dev, add + ["sudo config interface ip add {} {}".format(dev, PORT_RIF_ADDR)],
            ["sudo config interface ip remove {} {}".format(dev, PORT_RIF_ADDR)] + rem)


def port_rif_clear(d, kind, dev):
    """Remove whatever is left of the router interface under test; returns what could not be removed."""
    table, errors = ("VLAN_SUB_INTERFACE" if kind == "subport" else "INTERFACE"), []
    try:
        if db_keys(d, "CONFIG_DB", "{}|{}|{}".format(table, dev, PORT_RIF_ADDR)):
            sh(d, "sudo config interface ip remove {} {}".format(dev, PORT_RIF_ADDR), check=False)
        if kind == "subport" and db_keys(d, "CONFIG_DB", "{}|{}".format(table, dev)):
            sh(d, "sudo config subinterface del {}".format(dev), check=False)
        for k in db_keys(d, "CONFIG_DB", "{}|{}".format(table, dev)) + \
                db_keys(d, "CONFIG_DB", "{}|{}|*".format(table, dev)):
            sh(d, "sonic-db-cli CONFIG_DB DEL '{}'".format(k), check=False)
    except Exception as e:  # the caller keeps restoring
        errors.append("removing the router interface on {}: {}".format(dev, e))
    return errors


def port_rif_routes(r, ptfadapter, port, vid, uplinks, label):
    """(copies on the uplinks, copies anywhere else, text) for N frames a host on the router interface sends through
    it to PORT_RIF_DST, 802.1Q-tagged vid when given."""
    t = tag(label)
    mac, ip = PORT_RIF_HOST
    copies = send_and_count(ptfadapter, r.mg["minigraph_ptf_indices"][port],
                            flow_frame(t, r.router_mac, mac, ips=(ip, PORT_RIF_DST), vlan=vid), N, t)
    out = sum(native_on(copies, p) for p in uplinks)
    return out, len(copies) - out, "{} of {} on the uplinks, {} elsewhere. Copies: {}".format(
        out, N, len(copies) - out, summarize(copies))


@pytest.mark.parametrize("kind", ["port", "subport"])
def test_port_rif_churn(churn, ptfadapter, kind):
    """Create and remove a router interface on a front-panel port PORT_RIF_CYCLES times while a VLAN is VNI-mapped
    with remote VTEPs.

    The port is H1, taken out of the VNI-mapped VLAN for the cycles (H0 stays its member, the remote VTEPs and MAC
    stay). port: an address on H1. subport: a VLAN sub-interface of H1 with an address. Every create and every remove
    must reach ASIC_DB. Before the first cycle and after the last one the router interface routes: frames a host sends
    to it (with the sub-interface's VLAN tag) leave on an uplink once each and nowhere else, and on a sub-interface
    frames with another VLAN tag are not routed. Afterwards the ASIC_DB and CRM counts are back at the values from
    before the first create, orchagent reports no SAI failure, and with H1 back in the VLAN the VNI still forwards.
    A hardware resource that every create takes and no remove returns is outside the ASIC_DB and CRM view until it
    runs out; a create then fails, which the last routing check, orchagent's health and the log analyzer show.
    """
    r, d = churn, churn.duthost
    port = r.h1
    if kind == "subport" and d.shell("sudo config subinterface --help", module_ignore_errors=True)["rc"] != 0:
        pytest.skip("this image has no sub-interface configuration command")
    uplinks = [p for i in sorted(route_nexthop_ifaces(d, PORT_RIF_DST)[1]) for p in ptf_ports_of(r.mg, i)]
    if not uplinks:
        pytest.skip("no route toward {} through a port the PTF sees".format(PORT_RIF_DST))
    dev, add, rem = port_rif_commands(kind, port)
    vid = SUBPORT_VID if kind == "subport" else None
    vlan = VniVlan(r, {MAC_A: r.l1})
    problems, errors, left_vlan = [], [], False
    rif_start = asic_count(d, "ROUTER_INTERFACE")

    def create():
        rif0 = asic_count(d, "ROUTER_INTERFACE")
        for cmd in add:
            sh(d, cmd)
        wait_for(60, 2, lambda: asic_count(d, "ROUTER_INTERFACE") == rif0 + 1, "the router interface on " + dev)
        time.sleep(3)

    def routes(label):
        out, stray, text = port_rif_routes(r, ptfadapter, port, vid, uplinks, label)
        if not delivered(out) or stray:
            problems.append("{}: frames from a host on {} to {}: {}".format(label, dev, PORT_RIF_DST, text))
        if kind == "subport":
            out, stray, text = port_rif_routes(r, ptfadapter, port, SUBPORT_OTHER_VID, uplinks, label + "x")
            if out or stray:
                problems.append("{}: frames tagged {} (not the sub-interface's {}) were forwarded: {}".format(
                    label, SUBPORT_OTHER_VID, SUBPORT_VID, text))

    def _cleanup():
        nonlocal errors
        sh(d, "rm -f {s} {s}.out".format(s=PORT_RIF_SCRIPT), check=False)
        errors += port_rif_clear(d, kind, dev)
        if left_vlan and not wait_until(60, 2, 0, lambda: asic_count(d, "ROUTER_INTERFACE") == rif_start):
            errors.append("the router interface on {} did not leave ASIC_DB".format(dev))
        errors += vni_vlan_down(r)
        if errors:
            logger.error("%s router interface churn cleanup: %s", kind, errors)

    try:
        vlan.up()
        bad = check_traffic(r, ptfadapter, vlan, "p{}s".format(kind[0]))
        if bad:
            pytest.fail("the VNI does not forward before any router interface cycle, nothing to compare: {}".format(
                bad))
        members = asic_count(d, "VLAN_MEMBER")
        left_vlan = True
        sh(d, "sudo config vlan member del {} {}".format(VLAN_ID, port))
        member_wait(d, port, False, members - 1)
        base = baseline(r, "l2")
        create()
        routes("before")
        for cmd in rem:
            sh(d, cmd)
        wait_for(60, 2, lambda: asic_count(d, "ROUTER_INTERFACE") == base["asic"]["ROUTER_INTERFACE"],
                 "the router interface on {} to go".format(dev))
        if problems:
            pytest.fail("the router interface does not route before any cycle, nothing to compare: {}".format(
                problems))
        d.copy(content=PORT_RIF_SH % {"add": " && ".join(add), "rem": " && ".join(rem), "script": PORT_RIF_SCRIPT},
               dest=PORT_RIF_SCRIPT)
        done = 0
        while done < PORT_RIF_CYCLES and not problems:
            n = min(PORT_RIF_BATCH, PORT_RIF_CYCLES - done)
            out = sh(d, "bash {} {}".format(PORT_RIF_SCRIPT, n), check=False)
            problems.extend(line for line in out.splitlines() if line.startswith("FAIL"))
            m = re.search(r"^DONE ok=(\d+)", out, re.M)
            if not m or int(m.group(1)) != n:
                problems.append("{} of {} cycles ran after {} completed: {}".format(
                    m.group(1) if m else "?", n, done, out[-300:]))
                break
            done += n
            logger.info("%s router interface on %s: %d of %d create/remove cycles", kind, dev, done, PORT_RIF_CYCLES)
        if not problems:
            create()
            routes("after {} cycles".format(done))
            for cmd in rem:
                sh(d, cmd)
            diffs = settle(r, base)
            if diffs:
                problems.append("not back to the counts before the first create: {}".format(fmt(diffs)))
            unhealthy, error = orch_health(d)
            if unhealthy:
                problems.append("orchagent reports a SAI failure: {}".format(error))
            sh(d, "sudo config vlan member add -u {} {}".format(VLAN_ID, port))
            left_vlan = False
            member_wait(d, port, True, members)
            problems.extend(check_traffic(r, ptfadapter, vlan, "p{}e".format(kind[0])))
    finally:
        _cleanup()
    assert not problems, "{} router interface create/remove cycles on {}: {}".format(kind, dev, " | ".join(problems))
    assert not errors, "{} router interface churn cleanup: {}".format(kind, errors)


def flood_reading(r, ptfadapter, mac, label):
    t = tag(label)
    copies = send_and_count(ptfadapter, r.p0, probe_frame(t, mac, "02:4c:36:00:00:13"), N, t)
    to_h1 = native_on(copies, r.p1, None)
    to_a = len([c for c in vxlan_to(copies, r.dut_vtep, VTEP_A, VNI) if c.idst == mac])
    logger.info("unicast to %s from %s: %d untagged to %s, %d to VTEP %s", mac, r.h0, to_h1, r.h1, to_a, VTEP_A)
    return to_h1, to_a, copies


def test_vlan_recreate_no_stale_macs(churn, ptfadapter):
    """A deleted and re-created VLAN with a VNI map has no stale MACs: unicast to its old MACs floods.

    A MAC learned on H1 and a remote MAC that l1 advertises (Type-2) are in the VLAN; l1 withdraws its MAC, and the
    VLAN is deleted and re-created with the same VNI map (the leaves' Type-3s come back, l1 advertises nothing). The
    re-created VLAN must hold neither MAC (APPL_DB, ASIC_DB), and a MAC never seen anywhere is the control: each subject
    MAC must be delivered like it (H1, and VTEP A where unknown unicast reaches remote VTEPs at all). A stale entry
    sends it to one place only; an entry trapping the MAC to the CPU is caught by H0's kernel rx counter, since the
    kernel bridge could still deliver it to H1 (not read on a virtual switch, where that counter sees every frame).
    """
    r, d = churn, churn.duthost
    if time.time() - r.t0 > BUDGET_S:
        pytest.fail("module time budget ({} s) spent before this case started".format(BUDGET_S))
    macs = {MAC_L: "learned on {}".format(r.h1), MAC_R: "remote behind {}".format(VTEP_A)}
    errors, findings, unreadable, done = [], [], [], False
    first = VniVlan(r, {MAC_R: r.l1})
    again = VniVlan(r)
    try:
        first.up()
        learn_mac(ptfadapter, d, r.p1, r.h1, VLAN_ID, MAC_L, tag("learn"))
        # l1 withdraws MAC_R before the VLAN goes (vni_vlan_down): one it still advertised would rightly come back
        errors += vni_vlan_down(r)
        again.up()
        view = AsicView(d)
        held = {m: (view.fdb(m, VLAN_ID), appl_remote_mac_vtep(d, VLAN, m)) for m in macs}
        findings += ["{} ({}) is held by the re-created {}: ASIC_DB {}, APPL_DB remote VTEP '{}'".format(
            m, macs[m], VLAN, asic, appl) for m, (asic, appl) in held.items() if asic or appl]
        k0 = kernel_rx_packets(d, r.h0)
        c_h1, c_a, copies = flood_reading(r, ptfadapter, MAC_U, "rucl")
        k1 = kernel_rx_packets(d, r.h0)
        # H0's netdev rx counts only what reached the CPU, unless the platform mirrors port counters into it (or the
        # kernel is the dataplane)
        cpu_only = not r.vs and k0 is not None and k1 is not None and k1 - k0 < N // 2
        if not delivered(c_h1):
            pytest.fail("control: unknown unicast to {} in the re-created {} reached {} {} of {} times; flooding is "
                        "broken, nothing can be read. Copies: {}".format(MAC_U, VLAN, r.h1, c_h1, N, summarize(copies)))
        if not (delivered(c_a) or c_a == 0):
            pytest.fail("control: unknown unicast to {} reached VTEP {} {} of {} times, neither all nor none: the "
                        "flood to remote VTEPs cannot be read".format(MAC_U, VTEP_A, c_a, N))
        to_vtep = delivered(c_a)
        logger.info("unknown unicast %s reach the remote VTEP (control %d of %d)", "does" if to_vtep else "does not",
                    c_a, N)
        for i, m in enumerate(macs):
            if m == MAC_L and not to_vtep:
                # a stale entry for MAC_L points at H1, which a flood reaches too: with no copy to the VTEP the two
                # read the same
                unreadable.append(m)
                continue
            k0 = kernel_rx_packets(d, r.h0)
            to_h1, to_a, copies = flood_reading(r, ptfadapter, m, "rul{}".format(i))
            k1 = kernel_rx_packets(d, r.h0)
            # an entry that traps the MAC to the CPU can still reach H1 through the kernel bridge
            trapped = cpu_only and k0 is not None and k1 is not None and k1 - k0 >= N // 2
            if trapped or not (delivered(to_h1) and (delivered(to_a) if to_vtep else to_a == 0)):
                findings.append("unicast to {} ({}) in the re-created {}: {} of {} to {}, {} to VTEP {}, {} rx +{} "
                                "(trapped to the CPU: {}); the control MAC got {} / {}. Copies: {}".format(
                                    m, macs[m], VLAN, to_h1, N, r.h1, to_a, VTEP_A, r.h0,
                                    None if k0 is None or k1 is None else k1 - k0, trapped, c_h1, c_a,
                                    summarize(copies)))
        done = True
    finally:
        errors += vni_vlan_down(r)
        try:
            errors += ["stale: {}".format(s) for s in stale_state(r)]
        except Exception as e:  # never mask the body's own failure
            errors.append("stale-state read: {}".format(e))
        if errors and not done:
            logger.error("VLAN re-create cleanup after a failure: %s", errors)
    assert not findings, "stale MACs in the re-created VLAN: {}".format(" | ".join(findings))
    assert not errors, "VLAN re-create teardown: {}".format(errors)
    if unreadable:
        pytest.skip("{} judged clean, but {} cannot be read here: unknown unicast does not reach the remote VTEP, so "
                    "a stale entry on {} looks like a flood".format(
                        [m for m in macs if m not in unreadable], unreadable, r.h1))
