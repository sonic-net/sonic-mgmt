"""L2 VxLAN across a full warm reboot: EVPN-learned remote state, VLAN IDs 3073-4094, FDB and traffic survive it.

Topology t0. The DUT is a VTEP on its Loopback0, and two remote FRR EVPN leaves (l1, l2: files/vxlan_evpn_l2_leaves.sh
on the test server, as in test_vxlan_evpn_l2.py) serve its VNI: their Type-3 routes are its head-end replication list,
their Type-2 routes its remote MACs. One `warm-reboot` per module, in the module fixture; each case asserts one
property of the warm-booted DUT. Remote state crosses the boot the shipped way: APPL_DB restored by the warm start,
BGP back to the leaves, zebra re-installing the kernel FDB and flood list, and fdbsyncd's warm reconcile keeping the
rows the kernel holds again. Not covered: EVPN multihoming state across any warm path, a leaf restarting, and the data
plane during the boot (every reading is taken once orchagent has reconciled, so the length of the traffic gap and any
flooding while the FDB reconciles are not measured).

Rig (module fixture), on the t0's first VLAN with at least four oper-up members (e.g. Vlan1000; the t0 branch of
vxlan_l2_helpers.access_ports):
  * The fourth and fifth members become routed ports to l1 and l2 (eBGP ipv4 + l2vpn evpn, configured on the DUT with
    vtysh), each joined to its port's PTF interface by a tc redirect: the PTF sees every frame the DUT sends to a leaf
    and injects VxLAN toward the DUT as that leaf. With four members there is no l2: l1 alone is the remote VTEP of
    every reading (the flood list holds one leaf, the unicast and decap arms use l1's MACs), and no case skips.
  * Vlan2000 <-> VNI 12000, VTEP vtep1 on Loopback0, EVPN NVO nvo1. H0 moved from the base VLAN to Vlan2000 untagged,
    H1 a tagged member of Vlan2000 (a flood copy there tells a flooded unicast from a known one).
  * The leaves serve VNI 12000 and advertise four remote MACs each (Type-2). A MAC learned on H0.
  * VLANs 3000, 3073-3080 and 4094 with H1 and H2 as tagged members: the bottom of the range above 3072 and its top.
  Encap, decap and head-end replication to the leaves, the leaves' MACs and flood list in the DUT's kernel, and the
  high VLANs must work before the boot, else the module fails in setup (the rig, not the warm boot, is broken).

The DUT's BGP toward the leaves is vtysh-only config, which the reboot loses. The module puts it back as soon as bgpd
runs with its own `router bgp` after the boot, before taking any reading, as a DUT whose saved routing config held the
leaves would come up. With tunnels across the boot, fdbsyncd's reconcile delay (the bgp warm-restart timer, a
CONFIG_DB setting) is set to 300 s for the boot and put back at teardown: the readings right after orchagent reconciles
take a minute or more and must all read the restored rows, and with a 120 s default fdbsyncd could reconcile inside
them, or before zebra has the leaves' state again when bgpd starts late, and delete rows for a timing reason. The
reconcile itself still runs, and the case reads that it kept every row; the readings right after orchagent reconciles
count only if fdbsyncd had not reconciled by their end while the kernel still lacked the leaves' state. The
leaves keep FRR's default graceful-restart mode (helper): whether they hold the DUT's routes while it reboots only
changes how they forward toward the DUT, which nothing here reads (the PTF captures the DUT's VxLAN copies on the leaf
ports and injects the decap traffic itself), and on reconnect each leaf sends its whole table either way.

Older fast-reboot scripts refuse to warm-reboot while ASIC_DB holds any VxLAN tunnel, even without the control-plane
assistant whose leftover tunnel the check is meant for (sonic-net/sonic-buildimage#22560; fixed by
sonic-net/sonic-utilities#4902). The module asks the DUT's own script
(files/fast_reboot_refuses_vxlan.sh). Where it refuses, the module removes the DUT's BGP toward the leaves (their remote
VTEPs and MACs go with it), then the VNI map, the NVO and the VTEP before the reboot (the leaves, the VLANs, their
members, the leaf ports' addresses and the learned MAC stay) and builds them again after it; the case that needs
tunnels across the boot then fails, naming the verdict, since the property the module is named for cannot be read on
such an image. The tunnel-capacity case does not need live tunnels: it adds its VTEPs after the boot.

Case -> property:
  test_warm_reboot_was_warm             new boot, SONIC_BOOT_TYPE=warm, syncd skipped the hard reinit (warm SAI
                                        start), orchagent restore_count + 1 and reconciled. Every later case also
                                        requires it, and syncd still being the process that started warm: a cold start
                                        would hide a warm-start defect
  test_fdb_and_vlans_kept               ASIC_DB right after orchagent reconciles: the same tunnels, tunnel maps,
                                        VLANs, members and bridge ports as just before the reboot, the learned MAC
                                        still on H0 (an ASIC_DB reading: the learned MAC in hardware is read only by
                                        test_tunnels_and_traffic_kept's decap arms)
  test_tunnels_and_traffic_kept         (needs tunnels across the boot) right after orchagent reconciles: APPL_DB's
                                        remote VTEP and MAC rows as before the boot, every remote MAC on its leaf's
                                        tunnel in ASIC_DB, a broadcast reaching every leaf and H1, unicast encap to
                                        sampled remote MACs and hardware decap from each leaf to the learned MAC. Then,
                                        once the DUT's kernel holds the leaves' MACs and flood list again and fdbsyncd
                                        has reconciled: the same rows, the same ASIC_DB tunnel objects (none removed and
                                        created again), the remote MACs, and the same traffic
  test_vxlan_tunnels_added_after_warm_reboot
                                        32 new remote VTEPs added after the warm boot all reach ASIC_DB, come up,
                                        receive head-end replication, unicast encap, and decapsulate to the learned MAC
                                        (a warm start that loses the switch's VxLAN tunnel capacity caps them). They
                                        are static APPL_DB rows through the default route, on top of the leaves: 32
                                        VTEPs from the control plane would need 32 leaves, one routed DUT port each
  test_high_vid_vlans_kept              VLANs 3000, 3073-3080 and 4094 still in ASIC_DB and forwarding, 3500 not
  test_high_vid_vlan_after_warm_reboot  a VLAN 3073+ created after the warm boot reaches ASIC_DB and it and the
                                        restored VLANs all forward
  test_no_crash_across_warm_reboot      no new syncd/orchagent core or restart, no orchagent abort, SAI failure or
                                        "ASIC is in inconsistent state", from before the reboot to the end

On a virtual switch (asic_type vs) the kernel is the dataplane, and a reboot empties it: the leaves' MACs and flood
list are back in the kernel only once zebra has them again. Every case runs with its ASIC_DB, APPL_DB and STATE_DB
readings and the warm-start checks (syncd's warm-start lines are syncd's own, not the SAI's), but the traffic right
after orchagent reconciles is not read (the traffic after fdbsyncd's reconcile is), the decap gate that reads "the
kernel did not forward this" and the remote VTEPs' oper_up (a SAI tunnel notification) are not applied, and the
tunnel-capacity case reads ASIC_DB only (static rows never reach the kernel). Where the image's warm-reboot keeps
the tunnels across the boot, the module skips on a virtual switch: the virtual SAI cannot restore a bridge that has
tunnel bridge ports (reading the bridge's port list during the warm restore fails on a bridge port without a port ID),
so syncd stops and orchagent aborts on its first request.

The warm boot's finalizer runs `config save`, so the module copies config_db.json before it touches anything and puts
the copy back once the finalizer is done (and again at teardown). The rig is then undone in reverse, and
tests/vxlan/conftest.py's config reload loads the copy.
"""
import json
import logging
import os
import re
import time
from types import SimpleNamespace

import pytest

from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import REBOOT_TYPE_WARM, check_warmboot_finalizer_inactive, reboot
from tests.common.utilities import get_inventory_files, wait_until
from tests.vxlan.vxlan_l2_helpers import (
    BROADCAST_MAC,
    KNOWN_HARMLESS_LOG,
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
    her_counts,
    kernel_path,
    kernel_rx_packets,
    kernel_vxlan_netdev,
    learn_mac,
    log_clean,
    make_tagger,
    native_on,
    oper_up_vteps,
    orch_health,
    pid_of,
    probe_frame,
    raw_payloads,
    remote_mac_row,
    remote_vni_row,
    remove_vxlan,
    send_and_count,
    sh,
    summarize,
    swss_apply,
    underlay_toward,
    unicast_counts,
    vid_reading,
    vxlan_frame,
    vxlan_state_left,
    vxlan_to,
    wait_for,
    wait_state,
)
from tests.vxlan.vxlan_evpn_l2_helpers import (
    Leaf,
    Leaves,
    RigBuild,
    appl_remote_mac_vtep,
    appl_remote_vnis,
    assert_clean_start as assert_evpn_clean_start,
    check_ingress_once,
    check_leaf_vteps_unrouted,
    dut_bgp_add_commands,
    dut_bgp_remove_commands,
    dut_has_advertise_all_vni,
    evpn_peer_established,
    pick_rig_ports,
    resolve_leaf_image,
    rig_preflight,
    vtysh,
)

pytestmark = [
    pytest.mark.topology("t0"),
]

logger = logging.getLogger(__name__)

# platform_asic values on which warm reboot with L2 VxLAN has not been validated: data, extended per platform. A
# platform that is not listed runs the module.
WARM_REBOOT_NOT_VALIDATED = ("broadcom-dnx",)

VLAN_ID = 2000
VLAN = "Vlan{}".format(VLAN_ID)
VNI = 12000
INJ_OUTER_SMAC = "02:4c:37:ee:00:01"

RT_ASN = 65000
# name, ASN, VTEP, leaf /31 address, DUT /31 address; every leaf serves (VLAN_ID, VNI)
LEAF_PLAN = [
    ("l1", 65231, "10.255.96.1", "10.99.0.1", "10.99.0.0"),
    ("l2", 65233, "10.255.97.1", "10.99.0.3", "10.99.0.2"),
]
LEAF_MACS = {"l1": ["02:4c:37:a1:00:{:02x}".format(i) for i in range(1, 5)],   # Type-2 from each leaf
             "l2": ["02:4c:37:a2:00:{:02x}".format(i) for i in range(1, 5)]}
UCAST_SAMPLE = [LEAF_MACS["l1"][0], LEAF_MACS["l1"][-1], LEAF_MACS["l2"][-1]]   # unicast encap arms
FLOOD_MAC = "00:00:00:00:00:00"            # zebra's kernel flood-list entry per remote VTEP

POST_VTEPS = ["100.103.{}.1".format(i) for i in range(1, 33)]    # static rows, added after the warm boot
POST_MAC = {ip: "02:4c:38:00:{:02x}:01".format(i) for i, ip in enumerate(POST_VTEPS, 1)}
LEARNED = "02:4c:37:fe:00:01"                                    # learned on H0 before the warm boot

POST_UCAST = [POST_VTEPS[0], POST_VTEPS[5], POST_VTEPS[-1]]
POST_DECAP = [POST_VTEPS[0], POST_VTEPS[-1]]

N = 20                     # frames per unicast arm
N_HER = 10                 # broadcasts per head-end replication arm (one copy per VTEP each)

HIGH_VIDS = list(range(3073, 3081)) + [4094]
CTRL_VID = 3000            # below the 3073+ range: the high-VID instrument control
NEG_VID = 3500             # never configured: must not forward
NEW_VID = 3081             # created after the warm boot
N_VID = 10

CONVERGE = 120             # seconds for BGP / EVPN state to settle
FDB_AGING_S = 3600        # for the module: the learned MAC must outlive the reboot
FDBSYNCD_DEFAULT_TIMER = 120   # fdbsyncd's reconcile delay when CONFIG_DB sets no bgp warm-restart timer
FDBSYNCD_TIMER = 300           # bgp warm-restart timer for the boot, tunnels across only (module docstring)
CFG_BACKUP = "/host/config_db.json.before_vxlan_l2_warm_reboot"
REFUSAL_PROBE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files", "fast_reboot_refuses_vxlan.sh")
LOG_TAG = "vxlan_l2_warm_reboot"

# Syslog lines from before the warm reboot to the end of the module that fail test_no_crash_across_warm_reboot.
CRASH_SIGNATURES = [
    r"ASIC is in inconsistent state",
    r"Aborting orchagent",
    r"Encountered failure in [a-z]+ operation, SAI API",
    r"orchagent.*(terminate called|what\(\))",
    r"(syncd|orchagent).*segfault",
    r"Process .(orchagent|syncd). exited unexpectedly",          # no quotes: log_since single-quotes it
    r"syncd#syncd.*Runtime error",
]
LOG_MARKER_FOUND = "VXWB-MARKER-FOUND"

tag = make_tagger("VXWB")


# --------------------------------------------------------------------------------------------------------------------
# DUT readers
# --------------------------------------------------------------------------------------------------------------------
SNAP_TYPES = ("TUNNEL", "TUNNEL_MAP", "TUNNEL_MAP_ENTRY", "TUNNEL_TERM_TABLE_ENTRY", "VLAN", "VLAN_MEMBER",
              "BRIDGE_PORT")


def asic_snapshot(duthost):
    """({object type: ASIC_DB count}, Counter of VxLAN tunnels by destination ('' = the P2MP source tunnel),
    VxLAN tunnel-termination entries)."""
    counts = asic_counts(duthost, SNAP_TYPES)
    # every t0 has VLANs: zero means ASIC_DB did not answer, not an empty ASIC_DB
    if not counts["VLAN"]:
        raise AssertionError("unreadable ASIC_DB counts: {}".format(counts))
    view = AsicView(duthost, ("TUNNEL", "TUNNEL_TERM_TABLE_ENTRY"))
    terms = sum(1 for a in view.objs["TUNNEL_TERM_TABLE_ENTRY"].values()
                if a.get("SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE") == "SAI_TUNNEL_TYPE_VXLAN")
    return counts, view.vxlan_tunnels(), terms


def tunnel_objects(duthost):
    """{ASIC_DB object id: encap destination} of the VxLAN tunnels: the same ids twice means nothing was removed and
    created again in between."""
    return {oid: a.get("SAI_TUNNEL_ATTR_ENCAP_DST_IP", "")
            for oid, a in AsicView(duthost, ("TUNNEL",)).objs["TUNNEL"].items()
            if a.get("SAI_TUNNEL_ATTR_TYPE") == "SAI_TUNNEL_TYPE_VXLAN"}


def asic_fdb_endpoints(duthost, macs):
    """{mac: [endpoint IP of each ASIC_DB FDB entry for it]} for the given MACs (one read)."""
    view = AsicView(duthost)
    return {m.lower(): [e.endpoint for e in view.fdb(m)] for m in macs}


def appl_rows(duthost, table):
    return {k.split(":", 2)[2].lower() for k in db_keys(duthost, "APPL_DB", "{}:{}:*".format(table, VLAN))}


def appl_remote_state(r):
    """(remote VTEP rows {(vlan, vtep)}, {remote MAC: its row's VTEP}) in APPL_DB, for the leaves' MACs."""
    return (frozenset(appl_remote_vnis(r.duthost)),
            {m: appl_remote_mac_vtep(r.duthost, VLAN, m) for m in sorted(r.remote_macs)})


def kernel_remote(duthost):
    """{(mac, remote VTEP)} of the DUT kernel's FDB entries with a remote destination on the VNI's VxLAN netdev:
    what zebra installs from the leaves' routes (their MACs, and FLOOD_MAC per VTEP for the flood list), and what
    fdbsyncd's warm reconcile keeps rows for."""
    kvx = kernel_vxlan_netdev(duthost, VNI)
    if not kvx:
        return set()
    out = sh(duthost, "bridge -j fdb show dev {} 2>/dev/null; true".format(kvx), check=False)
    try:
        entries = json.loads(out or "[]")
    except ValueError:
        return set()
    return {(e.get("mac", "").lower(), e["dst"]) for e in entries if e.get("dst")}


def expected_kernel(r):
    return ({(m, lf.vtep) for m, lf in r.remote_macs.items()} |
            {(FLOOD_MAC, lf.vtep) for lf in r.leaves})


def fdbsyncd_state(duthost):
    return db_hget(duthost, "STATE_DB", "WARM_RESTART_TABLE|fdbsyncd", "state")


def bgp_ready(duthost, asn):
    """bgpd answers vtysh and holds the DUT's own `router bgp` (its startup config is in)."""
    out = sh(duthost, "sudo vtysh -c 'show running-config' 2>/dev/null; true", check=False)
    return re.search(r"^router bgp {}\b".format(asn), out, re.M) is not None


def sessions_up(r):
    """{leaf: l2vpn evpn session Established} (False when unreadable)."""
    up = {}
    for lf in r.leaves:
        try:
            up[lf.name] = evpn_peer_established(r.duthost, lf.ip)
        except Exception as e:  # a poll condition: bgpd may still be coming up
            logger.debug("l2vpn evpn session to %s unreadable: %s", lf.name, e)
            up[lf.name] = False
    return up


def vteps_ready(r, ips):
    """(ready, detail): every ip with exactly one ASIC_DB VxLAN tunnel to it and (hardware) oper_up."""
    dips = asic_snapshot(r.duthost)[1]
    # a tunnel's oper status comes from a SAI notification that the virtual switch does not send for tunnels
    up = set(ips) if r.vs else oper_up_vteps(r.duthost, ips)
    missing = [ip for ip in ips if dips[ip] != 1 or ip not in up]
    return not missing, "{} of {} with one ASIC_DB tunnel{}; missing {}".format(
        len(ips) - len(missing), len(ips), "" if r.vs else " and oper_up", missing[:8])


def wait_vteps(r, ips, timeout, when):
    """Wait until every ip is ready (vteps_ready) and its remote MAC is in ASIC_DB on it; raise with the last state."""
    duthost = r.duthost

    def fdb_ok():
        f = asic_fdb_endpoints(duthost, [POST_MAC[ip] for ip in ips])
        return all(f[POST_MAC[ip]] == [ip] for ip in ips)
    if not wait_until(timeout, 5, 0, lambda: vteps_ready(r, ips)[0]):
        raise AssertionError("{}: {}".format(when, vteps_ready(r, ips)[1]))
    if not wait_until(60, 5, 0, fdb_ok):
        f = asic_fdb_endpoints(duthost, [POST_MAC[ip] for ip in ips])
        raise AssertionError("{}: remote MACs not in ASIC_DB on their VTEP: {}".format(
            when, {m: v for m, v in f.items() if len(v) != 1}))


def wait_remote_macs(r, timeout, when):
    """Every leaf MAC has its APPL_DB row and one ASIC_DB FDB entry, on its leaf's VTEP."""
    def ok():
        f = asic_fdb_endpoints(r.duthost, r.remote_macs)
        return all(f[m] == [lf.vtep] for m, lf in r.remote_macs.items())
    wait_state(timeout, 3, ok, "{}: the leaves' MACs in ASIC_DB on their leaf's VTEP".format(when),
               lambda: {m: v for m, v in asic_fdb_endpoints(r.duthost, r.remote_macs).items()
                        if v != [r.remote_macs[m].vtep]})


def log_since(duthost, marker, pattern, since):
    """(marker found, syslog lines after marker that match the extended regex pattern), over every syslog file written
    since the DUT epoch `since` (the per-test LogAnalyzer rotates syslog before each case). The marker counts only on
    the logger's own line, not on the lines that log this very command."""
    out = sh(duthost, "sudo sh -c 'fs=$(find /var/log -maxdepth 1 -name \"syslog*\" -newermt @{t}); "
                      "[ -n \"$fs\" ] && for f in $(ls -1tr $fs); do zcat -f \"$f\"; done' | "
                      "awk '/{m}/ && !/ansible|COMMAND=/ && !f {{f=1; print \"{found}\"}} f' | "
                      "grep -a -v -E 'ansible|COMMAND=' | grep -a -E '{found}|{p}'; true".format(
                          t=int(since) - 120, m=marker, found=LOG_MARKER_FOUND, p=pattern),
             check=False).splitlines()
    return LOG_MARKER_FOUND in out, [x for x in out if x != LOG_MARKER_FOUND]


def boot_log(r, pattern):
    """log_since the marker logged just before the warm reboot."""
    return log_since(r.duthost, r.marker, pattern, r.marker_ts)


def cores(duthost):
    """/var/core now. The module diffs it itself across the boot, to name only syncd/orchagent/swss cores in its
    own case; the session-wide core check does not tell which module or process."""
    return set(sh(duthost, "ls /var/core 2>/dev/null; true", check=False).split())


def boot_id(duthost):
    return sh(duthost, "cat /proc/sys/kernel/random/boot_id").strip()


def warm_reboot_refuses_vxlan(duthost):
    """(refuses, verdict): whether this image's warm-reboot exits while ASIC_DB holds a VxLAN tunnel and no
    control-plane assistant is set up, read by running the script's own check (files/fast_reboot_refuses_vxlan.sh).
    An unknown verdict counts as refusing: removing the tunnels first is the run that works either way, and the
    tunnels-kept case then fails on the verdict."""
    dest = "/tmp/{}_refusal_probe.sh".format(LOG_TAG)
    duthost.copy(src=REFUSAL_PROBE, dest=dest, mode="0755")
    out = sh(duthost, "f=$(readlink -f $(PATH=$PATH:/usr/local/bin command -v warm-reboot)); bash {d} \"$f\"; "
                      "rm -f {d}".format(d=dest), check=False).strip()
    verdict = out.splitlines()[-1] if out else "UNKNOWN no output"
    if verdict.startswith("UNKNOWN"):
        logger.warning("could not tell whether warm-reboot refuses with a VxLAN tunnel (%s); removing the tunnels "
                       "before the reboot, so the tunnels-kept case fails", verdict)
    return not verdict.startswith("PROCEEDS"), verdict


def finalizer_done(duthost):
    """warmboot-finalizer (a oneshot) is no longer running and has cleared the system warm-restart flag. A finalizer
    that ended "failed" counts too (logged): the flag reading says whether it did its job."""
    done = check_warmboot_finalizer_inactive(duthost)
    state = sh(duthost, "systemctl is-active warmboot-finalizer.service; true", check=False).strip()
    if not done and state == "failed":
        logger.warning("warmboot-finalizer.service ended in state 'failed'")
        done = True
    return done and db_hget(duthost, "STATE_DB", "WARM_RESTART_ENABLE_TABLE|system", "enable") != "true"


def restore_config_file(duthost):
    """Put back the config_db.json copied before the module changed anything; check it holds no rig."""
    sh(duthost, "sudo test -s {b} && sudo cp {b} /etc/sonic/config_db.json".format(b=CFG_BACKUP))
    left = sh(duthost, "python3 -c \"import json; d = json.load(open('/etc/sonic/config_db.json')); "
                       "print(len(d.get('VXLAN_TUNNEL', {{}})), '{}' in d.get('VLAN', {{}}))\"".format(VLAN)).strip()
    if left != "0 False":
        raise AssertionError("the restored config_db.json still holds the rig (VXLAN_TUNNEL count, {}): {}".format(
            VLAN, left))


# --------------------------------------------------------------------------------------------------------------------
# VxLAN config, the leaves' BGP, and the static remote VTEP rows
# --------------------------------------------------------------------------------------------------------------------
class WarmRig(RigBuild):
    """The EVPN rig, plus VLANs with no VNI (the high VIDs) that the reverse teardown also removes."""

    def vlan(self, vid):
        sh(self.duthost, "sudo config vlan add {}".format(vid))
        self.built.append(("vlan", vid))


def wb_add_vxlan(duthost, dut_vtep):
    add_vxlan(duthost, dut_vtep, [(VLAN_ID, VNI)])
    wait_for(60, 2, lambda: asic_snapshot(duthost)[1][""] >= 1, "the P2MP source tunnel in ASIC_DB")


def pin_fdbsyncd_timer(r):
    """The bgp warm-restart timer (fdbsyncd's reconcile delay) at FDBSYNCD_TIMER for the boot; the teardown puts the
    DUT's own value back (the CONFIG_DB key survives the warm boot)."""
    d, key = r.duthost, "WARM_RESTART|bgp"
    prev = db_hget(d, "CONFIG_DB", key, "bgp_timer")

    def put_back():
        if prev:
            sh(d, "sonic-db-cli CONFIG_DB HSET '{}' bgp_timer {}".format(key, prev))
        else:
            sh(d, "sonic-db-cli CONFIG_DB HDEL '{}' bgp_timer".format(key))
    r.rb.on_teardown("first", "bgp warm-restart timer back to '{}'".format(prev), put_back)
    sh(d, "sonic-db-cli CONFIG_DB HSET '{}' bgp_timer {}".format(key, FDBSYNCD_TIMER))
    r.bgp_timer = FDBSYNCD_TIMER


def wb_remove_evpn(r):
    """The DUT's BGP toward the leaves, then map, NVO, VTEP, each once the one before is gone; then no VxLAN tunnel
    or termination entry left in ASIC_DB (else warm-reboot would refuse)."""
    d = r.duthost
    vtysh(d, dut_bgp_remove_commands(r.dut_asn, r.leaves, [VNI], r.added_aav))
    wait_for(CONVERGE, 3, lambda: not appl_remote_vnis(d) and not db_keys(d, "APPL_DB", "VXLAN_FDB_TABLE:*"),
             "APPL_DB remote VTEPs and MACs to go once the leaves' sessions are removed")
    wait_for(60, 2, lambda: not any(asic_fdb_endpoints(d, r.remote_macs).values()),
             "the leaves' MACs to leave ASIC_DB")
    remove_vxlan(d, [(VLAN_ID, VNI)])
    if not wait_until(90, 5, 0, lambda: not asic_snapshot(d)[2]):
        raise AssertionError("VxLAN termination entries left in ASIC_DB after removing the VTEP (warm-reboot would "
                             "refuse): {}".format(asic_snapshot(d)[2]))


def add_vteps(duthost, ips):
    swss_apply(duthost, [remote_vni_row(VLAN, ip, VNI) for ip in ips], name="vxlan_l2_wb_vni")
    swss_apply(duthost, [remote_mac_row(VLAN, POST_MAC[ip], ip, VNI) for ip in ips], name="vxlan_l2_wb_mac")


def remove_vteps(duthost, ips, timeout=120):
    """Delete the static rows of ips that APPL_DB still holds, then wait for their ASIC_DB tunnels to go."""
    macs = {POST_MAC[ip].lower() for ip in ips}
    have_mac = appl_rows(duthost, "VXLAN_FDB_TABLE") & macs
    if have_mac:
        swss_apply(duthost, [{"VXLAN_FDB_TABLE:{}:{}".format(VLAN, m): {}, "OP": "DEL"} for m in sorted(have_mac)],
                   name="vxlan_l2_wb_mac_del")
        # the tunnels go only once no FDB entry references them
        wait_for(60, 2, lambda: not any(asic_fdb_endpoints(duthost, have_mac).values()),
                 "the static remote MACs' ASIC_DB FDB entries to go")
    have_vni = appl_rows(duthost, "VXLAN_REMOTE_VNI_TABLE") & set(ips)
    if have_vni:
        swss_apply(duthost, [remote_vni_row(VLAN, ip, VNI, op="DEL") for ip in sorted(have_vni)],
                   name="vxlan_l2_wb_vni_del")
    wait_for(timeout, 3, lambda: not set(ips) & set(asic_snapshot(duthost)[1]),
             "the ASIC_DB tunnels to {} .. {} to go".format(ips[0], ips[-1]))
    return len(have_vni), len(have_mac)


# --------------------------------------------------------------------------------------------------------------------
# traffic arms; each returns (ok, detail)
# --------------------------------------------------------------------------------------------------------------------
def her_arm(r, ptfadapter, vteps, name):
    """A broadcast from H0 reaches every VTEP in vteps once per frame (and nothing else by VxLAN), and H1 tagged."""
    t = tag("her" + name)
    copies = send_and_count(ptfadapter, r.p0, probe_frame(t, BROADCAST_MAC, "02:4c:37:ff:00:11"), N_HER, t)
    per, other = her_counts(copies, r.dut_vtep, vteps, VNI)
    h1 = native_on(copies, r.p1, VLAN_ID)
    short = {v: n for v, n in per.items() if not delivered(n, N_HER)}
    ok = not short and other == 0 and delivered(h1, N_HER)
    return ok, "broadcast x{} to {} VTEPs: {} short ({}), {} other VxLAN copies, H1 tagged {}".format(
        N_HER, len(vteps), len(short), dict(list(short.items())[:8]), other, h1)


def ucast_arm(r, ptfadapter, mac, vtep, name):
    """Unicast from H0 to remote MAC mac is encapsulated to vtep with the VLAN's VNI, and only there."""
    t = tag("uc" + name)
    copies = send_and_count(ptfadapter, r.p0, probe_frame(t, mac, "02:4c:37:ff:00:10"), N, t)
    good, other = unicast_counts(copies, r.dut_vtep, vtep, VNI, mac)
    flood = native_on(copies, r.p1)
    ok = delivered(good, N) and other == 0 and flood == 0
    return ok, "unicast x{} to {} ({}): {} to it, {} other VxLAN, {} flooded to H1. Copies: {}".format(
        N, mac, vtep, good, other, flood, summarize(copies))


def decap_arm(r, ptfadapter, vtep, port, inner_src, name):
    """VxLAN unicast from vtep (sent on PTF port) to LEARNED is decapsulated (in hardware: kernel_path) and delivered
    untagged to H0 only."""
    t = tag("dc" + name)
    pkt = vxlan_frame(probe_frame(t, LEARNED, inner_src), r.router_mac, INJ_OUTER_SMAC, vtep, r.dut_vtep, VNI)
    kvx = kernel_vxlan_netdev(r.duthost, VNI)
    before = kernel_rx_packets(r.duthost, kvx)
    copies = send_and_count(ptfadapter, port, pkt, N, t)
    # on a virtual switch the kernel is the dataplane
    why = "" if r.vs else kernel_path(r.duthost, kvx, before, N)
    h0, h1 = native_on(copies, r.p0, None), native_on(copies, r.p1)
    emitted = len(vxlan_to(copies, r.dut_vtep))
    ok = delivered(h0, N) and h1 == 0 and emitted == 0 and not why
    return ok, ("decap unicast x{} from {} to {}: {} untagged to H0, {} to H1 (a flood: the learned MAC is gone), "
                "{} DUT VxLAN copies{}").format(N, vtep, LEARNED, h0, h1, emitted, "; " + why if why else "")


def learn_on_h0(r, ptfadapter):
    learn_mac(ptfadapter, r.duthost, r.p0, r.h0, VLAN_ID, LEARNED, tag("learn"))


def high_vid_arms(r, ptfadapter, vids, name):
    """(ok, detail): each configured VID forwards between the tagged members H1 and H2; NEG_VID does not."""
    results, bad = {}, []
    for vid in list(vids) + [NEG_VID]:
        per = []
        for src, dst in ((r.h1, r.h2), (r.h2, r.h1)):
            t = tag("v{}{}{}".format(name, vid, src[-1]))
            sa = "02:4c:39:{:02x}:{:02x}:{:02x}".format(vid >> 8, vid & 0xff, r.port[src] & 0xff)
            copies = send_and_count(ptfadapter, r.port[src], probe_frame(t, BROADCAST_MAC, sa, vlan=vid), N_VID, t)
            at_dst, problems = vid_reading(copies, r.port[dst], r.p0, vid, vid != NEG_VID)
            per.append(at_dst)
            bad += problems
        results[vid] = per
        ok = all(n == 0 for n in per) if vid == NEG_VID else all(delivered(n, N_VID) for n in per)
        if not ok:
            bad.append(vid)
    return not bad, "per VID (h1->h2, h2->h1) of {} frames: {}; failing: {}".format(N_VID, results, bad)


def leaf_arms(r, ptfadapter, name):
    """The leaves: head-end replication to each, sampled unicast encap, decap from each leaf (inner source one of
    its own MACs, so the frame moves no MAC)."""
    return ([her_arm(r, ptfadapter, r.leaf_vteps, name)] +
            [ucast_arm(r, ptfadapter, m, r.remote_macs[m].vtep, "{}{}".format(name, i))
             for i, m in enumerate(m for m in UCAST_SAMPLE if m in r.remote_macs)] +
            [decap_arm(r, ptfadapter, lf.vtep, lf.ptf_port, LEAF_MACS[lf.name][0], name + lf.name)
             for lf in r.leaves])


def post_boot_readings(r, ptfadapter):
    """Read right after orchagent reconciled (fdbsyncd writes no remote row before its reconcile). Valid only if the
    VxLAN tunnels did not change while the readings were taken, and fdbsyncd had not reconciled by their end while the
    kernel lacked the leaves' state (its reconcile then deletes rows for a timing reason, not a warm-boot one). On a
    virtual switch the traffic is not read here: the kernel holds the leaves' state only once zebra has it again."""
    w = SimpleNamespace(valid=True, invalid_why="", arms=[], appl=None, fdb={})
    d = r.duthost
    w.fdbsyncd_before = fdbsyncd_state(d)
    w.counts, w.dips, w.terms = asic_snapshot(d)
    w.oids = tunnel_objects(d)
    w.learned_on = fdb_port(d, VLAN_ID, LEARNED)
    if r.tunnels_across:
        w.appl = appl_remote_state(r)
        w.fdb = asic_fdb_endpoints(d, r.remote_macs)
        if not r.vs:
            w.arms = leaf_arms(r, ptfadapter, "W")
        w.fdbsyncd_after = fdbsyncd_state(d)
        w.kernel_missing = sorted(expected_kernel(r) - kernel_remote(d))
        dips_after = asic_snapshot(d)[1]
        if w.fdbsyncd_after == "reconciled" and w.kernel_missing:
            w.valid = False
            w.invalid_why = ("fdbsyncd reconciled ('{}' -> '{}') while the readings right after orchagent reconciled "
                             "were taken, and the DUT's kernel still lacked {} of the leaves' state ({}): its "
                             "reconcile deletes those rows, a timing artifact (leaves' BGP put back {} s after the "
                             "reboot started, reconcile delay {} s), not what the warm boot kept".format(
                                 w.fdbsyncd_before, w.fdbsyncd_after, len(w.kernel_missing), w.kernel_missing[:6],
                                 r.bgp_reapplied_s, r.bgp_timer))
        elif dips_after != w.dips:
            w.valid = False
            w.invalid_why = ("the VxLAN tunnels changed while the readings right after orchagent reconciled were "
                             "taken ({} -> {}; fdbsyncd '{}' -> '{}'), so they may not show what the warm boot "
                             "kept".format(dict(w.dips), dict(dips_after), w.fdbsyncd_before, w.fdbsyncd_after))
    return w


# --------------------------------------------------------------------------------------------------------------------
# module fixture: rig, readings before, warm-reboot, readings after
# --------------------------------------------------------------------------------------------------------------------
def assert_clean_wb_start(duthost, leaves):
    dirty = []
    if sh(duthost, "sudo test -e {} && echo yes; true".format(CFG_BACKUP)).strip() == "yes":
        dirty.append("{} exists: an earlier run stopped before its teardown, and /etc/sonic/config_db.json may hold "
                     "its rig (compare the two, restore the copy if so, config reload, delete the copy)".format(
                         CFG_BACKUP))
    dirty += vxlan_state_left(duthost, ["Vlan{}".format(vid) for vid in [CTRL_VID, NEG_VID, NEW_VID] + HIGH_VIDS])
    _, dips, terms = asic_snapshot(duthost)
    if sum(dips.values()) or terms:
        dirty.append("ASIC_DB VxLAN tunnels {} / termination entries {}".format(dict(dips), terms))
    if sh(duthost, "sonic-db-cli STATE_DB HGET 'WARM_RESTART_ENABLE_TABLE|system' enable").strip() == "true":
        dirty.append("the system warm-restart flag is set (a warm boot in progress?)")
    fail_unless_clean("warm-reboot rig", dirty)
    assert_evpn_clean_start(duthost, leaves, (VLAN,), (VNI,))


def require_warm(wb):
    """Fail a case whose reading is not a warm-boot result (see test_warm_reboot_was_warm)."""
    if not wb.warm_ok:
        pytest.fail("not a warm-boot result: {}".format(wb.warm_why))
    if wb.errors:
        pytest.fail("settling after the warm boot failed, so the post-boot state is unknown: {}".format(wb.errors))
    now = pid_of(wb.duthost, "syncd")
    found, cold = boot_log(wb, "performing hard reinit since COLD start")
    if now != wb.syncd_post or not found or cold:
        pytest.fail("syncd is not the process that started warm (pid {} after the boot, {} now; marker in syslog {}; "
                    "cold init lines since the boot {}): a cold SAI init would hide a warm-start defect, so this "
                    "reading would not be the warm-booted SAI's".format(wb.syncd_post, now or "none", found, cold[:2]))


@pytest.fixture(scope="module")
def access(duthost, tbinfo, request):
    # H0, H1, H2 and l1's routed port; l2's when there is a fifth port
    with access_ports(duthost, tbinfo, request, need=4, want=5) as a:
        yield a


@pytest.fixture(scope="module")
def wb(duthost, tbinfo, ptfadapter, localhost, vmhost, ansible_adhoc, request):
    asic = duthost.facts.get("platform_asic")
    if asic in WARM_REBOOT_NOT_VALIDATED or duthost.is_multi_asic:
        pytest.skip("warm reboot with L2 VxLAN is not validated on {} DUTs".format(
            "multi-ASIC" if duthost.is_multi_asic else asic))
    images = duthost.get_image_info()
    cur, nxt = images.get("current"), images.get("next")
    if not cur or cur != nxt:
        pytest.skip("the next boot image ({}) is not the current one ({}): a warm reboot would change the image".format(
            nxt, cur))
    pre = rig_preflight(vmhost, ansible_adhoc, get_inventory_files(request))
    # after the preflight, so a testbed without a test server borrows no ports
    acc = request.getfixturevalue("access")
    pick = pick_rig_ports(duthost, acc)
    idx = pick.idx
    (h0, h1, h2), leaf_ports = acc.members[:3], acc.members[3:5]
    # the ports that leave the base VLAN: H0 (into Vlan2000) and the leaves' routed ports
    pick.ports = [h0] + leaf_ports
    leaves = [Leaf(name, "eth{}".format(idx[port]), idx[port], port, asn, vtep, ip, dut_ip, [(VLAN_ID, VNI)])
              for (name, asn, vtep, ip, dut_ip), port in zip(LEAF_PLAN, leaf_ports)]
    vs = duthost.facts.get("asic_type") == "vs"
    check_leaf_vteps_unrouted(duthost, leaves)
    assert_clean_wb_start(duthost, leaves)
    raw_payloads(ptfadapter)
    senders = [h0, h1, h2] + leaf_ports
    if not vs:     # a virtual testbed has no fanout between the DUT and the PTF
        check_ingress_once(duthost, ptfadapter, {p: idx[p] for p in senders}, senders, tag("rx"))
    # decap from a static VTEP enters on a PTF port behind a next hop toward it (the default route)
    inj = {ip: underlay_toward(duthost, acc.mg, ip)[2][0] for ip in sorted(set(POST_DECAP + [POST_VTEPS[-1]]))}
    timer = db_hget(duthost, "CONFIG_DB", "WARM_RESTART|bgp", "bgp_timer")

    refuses, verdict = warm_reboot_refuses_vxlan(duthost)
    if vs and not refuses:
        pytest.skip("the virtual switch SAI cannot warm-restore tunnel bridge ports (the bridge's port list needs a "
                    "port ID on every bridge port), and this image's warm-reboot keeps VxLAN tunnels across the boot; "
                    "hardware runs the warm reboot")
    group = tbinfo["group-name"]
    lv = Leaves(pre.server, "ptf_{}".format(group), pre.image, leaves, pick.peer_asn, pick.lo, RT_ASN,
                re.sub(r"[^A-Za-z0-9_.-]", "_", group))
    r = SimpleNamespace(duthost=duthost, base_vid=pick.base_vid, h0=h0, h1=h1, h2=h2, p0=idx[h0], p1=idx[h1],
                        port={h0: idx[h0], h1: idx[h1], h2: idx[h2]}, dut_vtep=pick.lo, dut_asn=pick.dut_asn,
                        router_mac=duthost.facts["router_mac"], inj=inj, vs=vs, lv=lv, leaves=leaves,
                        l1=leaves[0], l2=leaves[1] if len(leaves) > 1 else None, leaf_vteps=[lf.vtep for lf in leaves],
                        remote_macs={m: lf for lf in leaves for m in LEAF_MACS[lf.name]},
                        bgp_timer=int(timer) if timer.isdigit() else FDBSYNCD_DEFAULT_TIMER,
                        tunnels_across=not refuses, refusal_verdict=verdict, high_vids=[], high_vid_pre="",
                        warm_ok=False, warm_why="the warm reboot did not run", syncd_post="", orch_post="",
                        marker="", marker_ts=0, reboot_t0=0, reconcile_s=0, bgp_reapplied_s=None, errors=[],
                        window=None, after=None, appl_boot=None, rb=None)
    logger.info("warm-reboot with a VxLAN tunnel and no control-plane assistant: %s; VxLAN tunnels across the warm "
                "boot: %s; fdbsyncd reconcile delay %s s", verdict, r.tunnels_across, r.bgp_timer)
    lv.install()
    try:
        # before the rig changes the DUT: an image that cannot be had is a missing test-server prerequisite
        image_used = resolve_leaf_image(lv)
        r.rb = WarmRig(request, duthost, pick, leaves, lv, RT_ASN, ((VLAN_ID, VNI),))
        r.added_aav = not dut_has_advertise_all_vni(duthost)
    except BaseException:
        lv.remove_files()   # nothing on the DUT yet, so no teardown runs
        raise
    r.bgp_add = dut_bgp_add_commands(r.dut_asn, leaves, RT_ASN, [VNI], r.added_aav)
    r.rb.on_teardown("first", "static remote VTEP rows", lambda: remove_vteps(duthost, POST_VTEPS))
    logger.info("warm-reboot rig: base %s, H0 %s, H1 %s, H2 %s, leaves %s, DUT VTEP %s AS %s, image %s, ASIC_DB "
                "baseline %s", pick.base_vlan, h0, h1, h2, leaves, r.dut_vtep, r.dut_asn, image_used, r.rb.base)
    ready = False
    try:
        sh(duthost, "sudo cp /etc/sonic/config_db.json {}".format(CFG_BACKUP))
        with log_clean(request, duthost, "setup"):
            build_rig(r, ptfadapter)
        readings_before(r, ptfadapter)
        warm_reboot(r, ptfadapter, localhost)
        ready = True
        yield r
    finally:
        teardown(r, report=ready)


def build_rig(r, ptfadapter):
    duthost, rb = r.duthost, r.rb
    rb.ports_out_of_base()
    rb.leaf_ips()
    rb.vlans()
    rb.member(VLAN_ID, r.h0, True)
    rb.member(VLAN_ID, r.h1, False)
    wait_for(60, 2, lambda: len(db_keys(duthost, "APPL_DB", "VLAN_MEMBER_TABLE:{}:*".format(VLAN))) == 2,
             "2 members of {} in APPL_DB".format(VLAN))
    rb.vxlan()
    wait_for(60, 2, lambda: asic_snapshot(duthost)[1][""] >= 1, "the P2MP source tunnel in ASIC_DB")
    rb.wait_connected()
    rb.bgp(r.added_aav)
    rb.leaves_up()
    rb.converge(CONVERGE)
    r.high_vids = [CTRL_VID] + HIGH_VIDS
    for vid in r.high_vids:
        rb.vlan(vid)
    # a high-VID failure before the boot fails only the two high-VID cases; the rest of the module still runs
    if not wait_until(45, 5, 0, lambda: set(r.high_vids) <= asic_vlan_ids(duthost)):
        r.high_vid_pre = ("VLANs {} are configured but not in ASIC_DB before the warm boot (members are not added to "
                          "them)".format(sorted(set(r.high_vids) - asic_vlan_ids(duthost))))
        logger.error("rig: %s", r.high_vid_pre)
    present = [vid for vid in r.high_vids if vid in asic_vlan_ids(duthost)]
    m0 = asic_count(duthost, "VLAN_MEMBER")
    for vid in present:
        for port in (r.h1, r.h2):
            rb.member(vid, port, False)
    wait_for(60, 2, lambda: asic_count(duthost, "VLAN_MEMBER") >= m0 + 2 * len(present),
             "the high-VID members in ASIC_DB")
    # the learned MAC must outlive arming checks, the reboot and the reconcile (default aging 600 s); the package's
    # config reload restores the default
    swss_apply(duthost, [{"SWITCH_TABLE:switch": {"fdb_aging_time": str(FDB_AGING_S)}, "OP": "SET"}],
               name="vxlan_l2_wb_aging")
    for mac, lf in r.remote_macs.items():
        r.lv.fdb("add", lf.name, mac, VLAN_ID)
    wait_remote_macs(r, CONVERGE, "rig: before the warm boot")
    # the post-boot gate reads the kernel; it must read the leaves' state here first
    want = expected_kernel(r)
    wait_state(CONVERGE, 3, lambda: want <= kernel_remote(duthost),
               "rig: the DUT kernel's VxLAN FDB to hold the leaves' MACs and flood list",
               lambda: sorted(want - kernel_remote(duthost)))
    learn_on_h0(r, ptfadapter)


def readings_before(r, ptfadapter):
    """The instruments, on the rig before the boot; each must hold here, or the rig (not the warm boot) is broken."""
    duthost = r.duthost
    bad = [d for ok, d in leaf_arms(r, ptfadapter, "P") if not ok]
    if not r.high_vid_pre:
        ok, d = high_vid_arms(r, ptfadapter, r.high_vids, "P")
        if not ok:
            r.high_vid_pre = "high VIDs did not forward before the warm boot: " + d
            logger.error("rig: %s", r.high_vid_pre)
    if bad:
        pytest.fail("rig: before the warm boot: {}".format(" | ".join(bad)))
    r.cores_pre = cores(duthost)
    r.boot_pre = boot_id(duthost)
    rc = db_hget(duthost, "STATE_DB", "WARM_RESTART_TABLE|orchagent", "restore_count")
    r.restore_pre = int(rc) if rc.isdigit() else 0
    logger.info("before the warm boot: orchagent restore_count %s", r.restore_pre)


def warm_reboot(r, ptfadapter, localhost):
    """The boot and what the cases read about it: the state to keep, the warm reboot, orchagent's reconcile and the
    leaves' BGP put back, the readings right after it, whether it was warm, and the settle."""
    snapshot_before(r, ptfadapter)
    state = reboot_and_wait_reconciled(r, localhost)
    if state:
        try:
            r.window = post_boot_readings(r, ptfadapter)
            logger.info("readings right after orchagent reconciled: %s", vars(r.window))
        except (Exception, pytest.fail.Exception) as e:
            r.errors.append("readings right after orchagent reconciled: {}: {}".format(type(e).__name__, e))
            logger.error("post-boot readings: %s", e)
    r.warm_ok, r.warm_why = warm_verdict(r, state)
    settle_after(r, ptfadapter)


def snapshot_before(r, ptfadapter):
    """The EVPN side and the tunnels out (where warm-reboot refuses them), or the reconcile delay pinned; then the
    state the boot must keep, ASIC_DB read twice the same so nothing was still being torn down or learned."""
    duthost = r.duthost
    if r.tunnels_across:
        pin_fdbsyncd_timer(r)
    else:
        wb_remove_evpn(r)
    learn_on_h0(r, ptfadapter)        # (again) against aging across the reboot
    # warm-reboot freezes orchagent first and exits if it is not ready; check that without freezing it
    wait_for(120, 10, lambda: duthost.shell("docker exec swss /usr/bin/orchagent_restart_check -n -w 2000 -r 3",
                                            module_ignore_errors=True)["rc"] == 0,
             "orchagent to report ready for a warm restart")
    snaps = [asic_snapshot(duthost)]

    def settled():
        snaps.append(asic_snapshot(duthost))
        return snaps[-1] == snaps[-2]
    if not wait_until(30, 5, 5, settled):
        raise AssertionError("ASIC_DB did not settle before the warm reboot: {}".format(snaps[-2:]))
    r.counts_boot, r.dips_boot, r.terms_boot = snaps[-1]
    if r.tunnels_across:
        r.appl_boot = appl_remote_state(r)


def reboot_and_wait_reconciled(r, localhost):
    """The warm reboot, returned from at reconnect; then, polled together, orchagent's reconcile and the leaves' BGP
    config put back as soon as bgpd runs with the DUT's own `router bgp`. Returns 'reconciled' or '' (orchagent not
    reconciled in 600 s)."""
    duthost = r.duthost
    r.marker = "{}-{:04x}-{}".format(LOG_TAG, tag.nonce, int(time.time()))
    r.marker_ts = int(sh(duthost, "date +%s").strip())
    sh(duthost, "logger -t {} '{}'".format(LOG_TAG, r.marker))
    r.reboot_t0 = t0 = time.time()
    reboot(duthost, localhost, reboot_type=REBOOT_TYPE_WARM, return_after_reconnect=True)
    end = time.time() + 600
    state, last = "", ""
    while time.time() < end and not (state and r.bgp_reapplied_s is not None):
        try:
            if r.bgp_reapplied_s is None and bgp_ready(duthost, r.dut_asn):
                vtysh(duthost, r.bgp_add)
                r.bgp_reapplied_s = int(time.time() - t0)
                logger.info("the leaves' BGP config re-applied %d s after the warm reboot started", r.bgp_reapplied_s)
            if not state:
                orch = pid_of(duthost, "orchagent")
                if orch and db_hget(duthost, "STATE_DB", "WARM_RESTART_TABLE|orchagent", "state") == "reconciled":
                    state, r.orch_post, r.syncd_post = "reconciled", orch, pid_of(duthost, "syncd")
                    r.reconcile_s = int(time.time() - t0)
        except Exception as e:  # the DUT is still coming up; keep polling
            last = "{}: {}".format(type(e).__name__, e)
            logger.debug("poll: %s", last)
        time.sleep(3)
    if not state:
        r.reconcile_s = int(time.time() - t0)
    if r.bgp_reapplied_s is None:
        r.errors.append("the leaves' BGP config could not be put back: bgpd did not run with `router bgp {}` or "
                        "refused the config within 600 s of the warm reboot (last error: {})".format(
                            r.dut_asn, last or "none"))
    logger.info("orchagent %s %d s after the warm reboot started (syncd pid %s); leaves' BGP re-applied at %s s",
                state or "NOT reconciled", r.reconcile_s, r.syncd_post, r.bgp_reapplied_s)
    return state


def warm_verdict(r, state):
    """(warm, why not): syslog lines after the marker are the shutdown's and this boot's."""
    duthost = r.duthost
    boot_post = boot_id(duthost)
    found, syncd_lines = boot_log(r, "(skipping|performing) hard reinit since (WARM|COLD) start")
    syncd_warm = [x for x in syncd_lines if "skipping hard reinit" in x]
    syncd_cold = [x for x in syncd_lines if "performing hard reinit" in x]
    rc = db_hget(duthost, "STATE_DB", "WARM_RESTART_TABLE|orchagent", "restore_count")
    restore_post = int(rc) if rc.isdigit() else None
    why = []
    if boot_post == r.boot_pre:
        why.append("the boot id did not change (no reboot)")
    if "SONIC_BOOT_TYPE=warm" not in sh(duthost, "cat /proc/cmdline"):
        why.append("/proc/cmdline has no SONIC_BOOT_TYPE=warm")
    if not found:
        why.append("the marker logged before the reboot is not in syslog (logs kept in RAM?), so the SAI start "
                   "cannot be read")
    elif not syncd_warm or syncd_cold:
        why.append("syncd: {} 'skipping hard reinit since WARM' / {} 'performing hard reinit since COLD' lines "
                   "after the marker".format(len(syncd_warm), len(syncd_cold)))
    if restore_post != r.restore_pre + 1:
        why.append("orchagent restore_count {} -> {}".format(r.restore_pre, restore_post))
    if not state:
        why.append("orchagent did not reconcile within {} s".format(r.reconcile_s))
    return not why, "; ".join(why)


def leaves_back(r):
    """With tunnels across the boot: wait for the DUT's kernel to hold the leaves' MACs and flood list again (zebra,
    from the leaves' routes), and note fdbsyncd's state at that moment: its reconcile keeps only what the kernel
    holds."""
    d = r.duthost
    want = expected_kernel(r)
    a = SimpleNamespace(kernel_ok=wait_until(r.bgp_timer + CONVERGE, 3, 0, lambda: want <= kernel_remote(d)),
                        fdbsyncd_at_kernel=fdbsyncd_state(d), kernel_s=int(time.time() - r.reboot_t0))
    a.kernel_missing = sorted(want - kernel_remote(d))
    logger.info("DUT kernel %s the leaves' state %d s after the warm reboot started (missing %s); fdbsyncd then '%s'",
                "holds" if a.kernel_ok else "does NOT hold", a.kernel_s, a.kernel_missing, a.fdbsyncd_at_kernel)
    return a


def after_reconcile(r, ptfadapter, a):
    """Readings once fdbsyncd has reconciled the restored rows against the kernel."""
    d = r.duthost
    a.reconciled = wait_until(r.bgp_timer + 300, 5, 0, lambda: fdbsyncd_state(d) == "reconciled")
    wait_until(CONVERGE, 5, 0, lambda: all(sessions_up(r).values()))
    a.sessions = sessions_up(r)
    # a reading, not a gate: wait for the state the boot had, and read whatever is there at the timeout
    want_fdb = {m: [lf.vtep] for m, lf in r.remote_macs.items()}
    wait_until(CONVERGE, 3, 0, lambda: (appl_remote_state(r) == r.appl_boot and
                                        asic_snapshot(d)[1] == r.dips_boot and
                                        asic_fdb_endpoints(d, r.remote_macs) == want_fdb))
    a.appl = appl_remote_state(r)
    a.counts, a.dips, a.terms = asic_snapshot(d)
    a.oids = tunnel_objects(d)
    a.fdb = asic_fdb_endpoints(d, r.remote_macs)
    learn_on_h0(r, ptfadapter)
    a.arms = leaf_arms(r, ptfadapter, "R")
    logger.info("readings after fdbsyncd's reconcile: %s", vars(a))


def rebuild_after(r):
    """Where the tunnels were taken out before the boot: VTEP, NVO and map again, and the leaves' state back."""
    if r.bgp_reapplied_s is None:
        raise AssertionError("the leaves' BGP config is not back, so the rig cannot be rebuilt")
    wb_add_vxlan(r.duthost, r.dut_vtep)
    # fdbsyncd writes new remote rows only once its warm reconcile is done
    wait_for(r.bgp_timer + 300, 5, lambda: fdbsyncd_state(r.duthost) == "reconciled", "fdbsyncd to reconcile")
    r.rb.converge(CONVERGE)
    wait_remote_macs(r, CONVERGE, "rebuilding the rig after the warm boot")


def settle_after(r, ptfadapter):
    """The leaves' state back in the kernel, services, the finalizer (it ends with `config save`), the readings after
    fdbsyncd's reconcile; the tunnels and the leaves' state back where they were taken out."""
    duthost = r.duthost
    try:
        if r.tunnels_across and r.bgp_reapplied_s is not None:
            r.after = leaves_back(r)
        wait_critical_processes(duthost)
        wait_for(600, 10, lambda: finalizer_done(duthost), "the warmboot finalizer to finish")
        restore_config_file(duthost)
        if r.after is not None:
            after_reconcile(r, ptfadapter, r.after)
        if pid_of(duthost, "syncd") != r.syncd_post:
            raise AssertionError("syncd restarted while settling (pid {} -> {})".format(
                r.syncd_post, pid_of(duthost, "syncd")))
        if not r.tunnels_across:
            rebuild_after(r)
    except (Exception, pytest.fail.Exception) as e:
        r.errors.append("after the warm boot: {}: {}".format(type(e).__name__, e))
        logger.error("after the warm boot: %s", e)


def teardown(r, report):
    """Undo the rig in reverse (the static rows first, then the leaves' sessions and state, the VxLAN objects,
    VLANs, addresses and ports), and put back the config_db.json copied before the module touched anything (the warm
    boot's finalizer saved the rig into it); tests/vxlan/conftest.py's config reload then loads it. report=False (the
    rig or the boot failed): problems are logged, so that failure stays the verdict."""
    duthost = r.duthost
    step = Steps("warm-reboot rig teardown")

    def warm_state():
        if sh(duthost, "systemctl is-active warmboot-finalizer.service; true", check=False).strip() in (
                "active", "activating"):
            step.errors.append("warmboot-finalizer still running at teardown; stopped (it would save the rig)")
            sh(duthost, "sudo systemctl stop warmboot-finalizer.service", check=False)
        if sh(duthost, "sonic-db-cli STATE_DB HGET 'WARM_RESTART_ENABLE_TABLE|system' enable").strip() == "true":
            step.errors.append("the system warm-restart flag was still set (warm-reboot aborted?); cleared")
            sh(duthost, "sudo config warm_restart disable system")

    def config_file():
        restore_config_file(duthost)
        sh(duthost, "sudo rm -f {}".format(CFG_BACKUP))
    step("warm-boot state", warm_state)
    step("EVPN rig", r.rb.teardown)
    step("restoring config_db.json from {} (kept)".format(CFG_BACKUP), config_file)
    step.finish(report)


@pytest.fixture(autouse=True)
def ignore_known_harmless(duthost, loganalyzer):
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(KNOWN_HARMLESS_LOG)


# --------------------------------------------------------------------------------------------------------------------
# cases
# --------------------------------------------------------------------------------------------------------------------
def window(wb):
    if wb.window is None:
        pytest.fail("no readings right after orchagent reconciled: {}".format(wb.errors))
    if not wb.window.valid:
        pytest.fail(wb.window.invalid_why)
    return wb.window


def test_warm_reboot_was_warm(wb):
    """The reboot was a warm one end to end: new boot, warm kernel command line, SAI warm start, orchagent restored."""
    assert wb.warm_ok, "the warm reboot was not warm: {}".format(wb.warm_why)
    assert not wb.errors, "the warm boot was warm, but settling after it failed: {}".format(wb.errors)


def test_fdb_and_vlans_kept(wb):
    """ASIC_DB right after orchagent reconciled: tunnels, maps, VLANs, members, bridge ports and the learned MAC."""
    require_warm(wb)
    w = window(wb)
    counts = {t: (wb.counts_boot[t], w.counts[t]) for t in SNAP_TYPES if wb.counts_boot[t] != w.counts[t]}
    dips = {ip: (wb.dips_boot[ip], w.dips[ip]) for ip in set(wb.dips_boot) | set(w.dips)
            if wb.dips_boot[ip] != w.dips[ip]}
    assert not counts and not dips and wb.terms_boot == w.terms and w.learned_on == wb.h0, (
        "across the warm reboot (VxLAN tunnels across it: {}): ASIC_DB counts changed {} (before, after); VxLAN "
        "tunnels by destination changed {}; VxLAN termination entries {} -> {}; {} on '{}' (was {})".format(
            wb.tunnels_across, counts, dips, wb.terms_boot, w.terms, LEARNED, w.learned_on, wb.h0))


def test_tunnels_and_traffic_kept(wb):
    """The leaves' VTEPs and MACs kept across the warm boot and through fdbsyncd's reconcile; traffic both times."""
    if not wb.tunnels_across:
        pytest.fail("not read: this image's warm-reboot exits while any VxLAN tunnel exists without a control-plane "
                    "assistant, or whether it does could not be told ({}; sonic-net/sonic-buildimage#22560, "
                    "fixed by sonic-net/sonic-utilities#4902), so the module removed the VTEP before the "
                    "reboot".format(wb.refusal_verdict))
    require_warm(wb)
    w = window(wb)
    problems = []

    def check(when, appl, fdb, arms):
        if appl != wb.appl_boot:
            problems.append("{}: APPL_DB remote VTEPs / MACs {} (before the boot {})".format(when, appl, wb.appl_boot))
        moved = {m: fdb[m] for m, lf in wb.remote_macs.items() if fdb[m] != [lf.vtep]}
        if moved:
            problems.append("{}: remote MACs missing, duplicated or on another VTEP {} (endpoint IPs)".format(
                when, moved))
        problems.extend("{}: {}".format(when, d) for ok, d in arms if not ok)
    check("right after orchagent reconciled", w.appl, w.fdb, w.arms)
    a = wb.after
    note = ""
    if a is None:
        problems.append("no readings after fdbsyncd's reconcile")
    else:
        if not a.reconciled:
            problems.append("fdbsyncd did not reconcile within {} s".format(wb.bgp_timer + 300))
        if not all(a.sessions.values()):
            problems.append("l2vpn evpn sessions after the boot {}".format(a.sessions))
        if a.dips != wb.dips_boot or a.oids != w.oids:
            problems.append("after fdbsyncd's reconcile: ASIC_DB VxLAN tunnels {} (before the boot {}), objects {} "
                            "(right after orchagent reconciled {}): removed and created again?".format(
                                dict(a.dips), dict(wb.dips_boot), a.oids, w.oids))
        check("after fdbsyncd's reconcile", a.appl, a.fdb, a.arms)
        if not a.kernel_ok or a.fdbsyncd_at_kernel == "reconciled":
            note = (" (fdbsyncd keeps only the rows the kernel holds at its reconcile: the DUT's kernel {} the "
                    "leaves' MACs and flood list {} s after the reboot started, missing {}, fdbsyncd then '{}'; the "
                    "leaves' BGP config was put back at {} s, the reconcile delay is {} s)".format(
                        "held" if a.kernel_ok else "did NOT hold", a.kernel_s, a.kernel_missing,
                        a.fdbsyncd_at_kernel, wb.bgp_reapplied_s, wb.bgp_timer))
    assert not problems, "{}{}".format(" | ".join(problems), note)


def test_vxlan_tunnels_added_after_warm_reboot(wb, ptfadapter):
    """After the warm boot, 32 new remote VTEPs all get a tunnel, come up, and carry encap and decap."""
    require_warm(wb)
    duthost = wb.duthost
    try:
        add_vteps(duthost, POST_VTEPS)
        try:
            wait_vteps(wb, POST_VTEPS, 120, "{} new remote VTEPs after the warm boot".format(len(POST_VTEPS)))
        except AssertionError as e:
            pat = "Encountered failure in create operation, SAI API: SAI_API_TUNNEL"
            pytest.fail("{}. orchagent tunnel create failures since the reboot: {}".format(
                e, len(boot_log(wb, pat)[1])))
        if wb.vs:
            logger.info("virtual switch: static rows never reach the kernel dataplane; traffic not read")
            return
        time.sleep(3)
        learn_on_h0(wb, ptfadapter)
        # the leaves stay in the VLAN's flood list
        arms = ([her_arm(wb, ptfadapter, POST_VTEPS + wb.leaf_vteps, "N")] +
                [ucast_arm(wb, ptfadapter, POST_MAC[ip], ip, "N{}".format(i)) for i, ip in enumerate(POST_UCAST)] +
                [decap_arm(wb, ptfadapter, ip, wb.inj[ip], POST_MAC[ip], "N{}".format(i))
                 for i, ip in enumerate(POST_DECAP)])
        bad = [d for ok, d in arms if not ok]
        assert not bad, "traffic to the {} VTEPs added after the warm boot: {}".format(
            len(POST_VTEPS), " | ".join(bad))
    finally:
        remove_vteps(duthost, POST_VTEPS)


def test_high_vid_vlans_kept(wb, ptfadapter):
    """VLANs 3000, 3073-3080 and 4094 are still in ASIC_DB and forward after the warm boot; 3500 does not."""
    if wb.high_vid_pre:
        pytest.fail("before the warm boot: {}".format(wb.high_vid_pre))
    require_warm(wb)
    missing = sorted(set(wb.high_vids) - asic_vlan_ids(wb.duthost))
    assert not missing, "VLANs {} lost from ASIC_DB across the warm boot".format(missing)
    ok, d = high_vid_arms(wb, ptfadapter, wb.high_vids, "K")
    assert ok, "high VLAN IDs after the warm boot: {}".format(d)


def test_high_vid_vlan_after_warm_reboot(wb, ptfadapter):
    """A VLAN 3073+ created after the warm boot reaches ASIC_DB: it and every restored VLAN forward."""
    if wb.high_vid_pre:
        pytest.fail("before the warm boot: {}".format(wb.high_vid_pre))
    require_warm(wb)
    duthost = wb.duthost
    wb.rb.vlan(NEW_VID)
    if not wait_until(45, 5, 0, lambda: NEW_VID in asic_vlan_ids(duthost)):
        pytest.fail("VLAN {} created after the warm boot never reached ASIC_DB (it collided with a restored "
                    "VLAN's resources?)".format(NEW_VID))
    m0 = asic_count(duthost, "VLAN_MEMBER")
    for port in (wb.h1, wb.h2):
        wb.rb.member(NEW_VID, port, False)
    wait_for(60, 2, lambda: asic_count(duthost, "VLAN_MEMBER") >= m0 + 2, "VLAN {}'s members".format(NEW_VID))
    time.sleep(3)
    ok, d = high_vid_arms(wb, ptfadapter, wb.high_vids + [NEW_VID], "A")
    assert ok, "with VLAN {} created after the warm boot, {}".format(NEW_VID, d)


def test_no_crash_across_warm_reboot(wb):
    """No new syncd/orchagent core or restart, and no crash, abort or SAI-failure line since the reboot was started."""
    duthost = wb.duthost
    if not wb.marker:
        pytest.fail("the warm reboot did not run: {}".format(wb.warm_why))
    new = sorted(c for c in cores(duthost) - wb.cores_pre if re.search(r"syncd|orchagent|swss", c))
    found, lines = boot_log(wb, "|".join(CRASH_SIGNATURES))
    pids = {"syncd": (wb.syncd_post, pid_of(duthost, "syncd")), "orchagent": (wb.orch_post, pid_of(duthost,
                                                                                                   "orchagent"))}
    moved = {p: v for p, v in pids.items() if not v[0] or v[0] != v[1]}
    latched, err = orch_health(duthost)
    assert found and not new and not lines and not moved and not latched, (
        "across the warm reboot: marker in syslog {}; new cores {}; {} crash/abort/SAI-failure lines, first {}; "
        "restarted or not running since the boot (pid after it, now) {}; orchagent latched unhealthy: {} ({})".format(
            found, new, len(lines), lines[:5], moved, latched, err))
