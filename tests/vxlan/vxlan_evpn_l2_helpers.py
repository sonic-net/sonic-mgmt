"""Helpers for the EVPN-driven modules (tests/vxlan/test_vxlan_evpn_l2.py and the modules built on its rig): remote
FRR EVPN leaves on the test server, the DUT side of the rig, and the EVPN readers.

The leaves are FRR containers on the test server (the host of the PTF container), driven by
files/vxlan_evpn_l2_leaves.sh. Each one peers eBGP ipv4 + l2vpn evpn with the DUT over a DUT routed port whose PTF
port is joined to the leaf by tc redirects, so the PTF still sees every frame the DUT sends to that leaf and can
inject frames toward the DUT as if it were the leaf. Leaves may share a routed port (Leaf.plen: one subnet holds the
DUT's and their addresses); each is then a distinct BGP neighbour and next hop on that port. The frame counter is the
one in vxlan_l2_helpers.
"""

import collections
import json
import logging
import os
import re
import time
from types import SimpleNamespace

import ptf.testutils as testutils
import pytest

from tests.common.devices.base import AnsibleHostBase
from tests.common.devices.vmhost import VMHost
from tests.common.utilities import wait_until
from tests.vxlan.vxlan_l2_helpers import (
    BROADCAST_MAC,
    KNOWN_HARMLESS_LOG,
    AsicView,
    Steps,
    add_vxlan,
    asic_count,
    asic_counts,
    collect,
    counter_poll_s,
    db_hget,
    db_keys,
    delivered,
    flush_vlan_fdb,
    hold_arp_refresh,
    log_clean,
    loopback0_ipv4,
    native_on,
    port_counters,
    probe_frame,
    remove_vxlan,
    resume_arp_refresh,
    route_nexthop_ifaces,
    send_and_count,
    sh,
    summarize,
    vxlan_state_left,
    wait_for,
)

logger = logging.getLogger(__name__)

FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
LEAF_SCRIPT = os.path.join(FILES_DIR, "vxlan_evpn_l2_leaves.sh")
# Leaf image candidates, first usable wins (present on the test server, else the first that can be pulled, 300 s each;
# a name without a registry is a local build and is never pulled). The default is the stock FRR release image of the
# FRR release current SONiC images carry. VXLAN_EVPN_LEAF_IMAGE (space separated) replaces the list, e.g. with a local
# build or a mirror.
DEFAULT_LEAF_IMAGES = "quay.io/frrouting/frr:10.5.4"
# FRR bgpd without this fix advertises a sticky MAC whose MAC Mobility sequence number is above 0 without the sticky
# flag
STICKY_SEQ_FIX = "the FRR fix https://github.com/FRRouting/frr/pull/23629"
LEAF_IMAGE_ENV = "VXLAN_EVPN_LEAF_IMAGE"

DUT_RM_LOOPS = "VXLAN_EVPN_L2_LOOPS"     # DUT <-> leaves ipv4: only /32s in 10/8 (the VTEPs) either way
DUT_RM_EVPN = "VXLAN_EVPN_L2_EVPN"       # DUT <-> leaves l2vpn evpn: everything
DUT_PL_LOOPS = "VXLAN_EVPN_L2_LOOPS_PL"

# vids_vnis: [(vid, vni), ...]; the first one is untagged on the leaf's host port. plen: the prefix length of the
# subnet of ip and dut_ip on dut_port (31 for a port of its own; leaves that share dut_port share dut_ip and plen).
Leaf = collections.namedtuple("Leaf", "name ptf_if ptf_port dut_port asn vtep ip dut_ip vids_vnis plen")
Leaf.__new__.__defaults__ = (31,)


# --------------------------------------------------------------------------------------------------------------------
# remote leaves (test server side)
# --------------------------------------------------------------------------------------------------------------------
class _TestServerHost(VMHost):
    def __init__(self, ansible_adhoc, hostname, inventory):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname, inventory=inventory)


def _can_login(host):
    try:
        return host.shell("true", module_ignore_errors=True).get("rc") == 0
    except Exception as e:  # pytest_ansible raises AnsibleConnectionFailure for an unreachable host
        logger.info("test server %s: %s", getattr(host, "hostname", "?"), e)
        return False


def usable_test_server(vmhost, ansible_adhoc, inv_files):
    """The test server as an ansible host that can log in, or (None, why); why is '' when the testbed has none.

    The vmhost fixture resolves the server from the run's inventory, which may hold the host without its login
    variables; the sibling `veos` inventory carries them (group vm_host). Try the fixture's host first, then the same
    host name through each sibling `veos` inventory.
    """
    if not vmhost:
        return None, ""
    if _can_login(vmhost):
        return vmhost, ""
    tried = []
    for d in sorted({os.path.dirname(os.path.abspath(f)) for f in inv_files}):
        inv = os.path.join(d, "veos")
        if not os.path.exists(inv) or os.path.abspath(inv) in [os.path.abspath(f) for f in inv_files]:
            continue
        tried.append(inv)
        try:
            host = _TestServerHost(ansible_adhoc, vmhost.hostname, inv)
        except Exception as e:
            logger.info("test server %s via %s: %s", vmhost.hostname, inv, e)
            continue
        if _can_login(host):
            logger.info("test server %s reached through inventory %s", vmhost.hostname, inv)
            return host, ""
    return None, "cannot log in to test server {} (inventories {} + {})".format(vmhost.hostname, inv_files, tried)


class Leaves(object):
    """The remote leaves of one module run, on the test server that hosts the PTF container."""

    def __init__(self, vmhost, ptf_container, image, leaves, dut_asn, dut_vtep, rt_asn, tag):
        self.vmhost = vmhost
        self.ptf_container = ptf_container
        self.image = image
        self.leaves = {lf.name: lf for lf in leaves}
        self.dut_asn = dut_asn
        self.dut_vtep = dut_vtep
        self.rt_asn = rt_asn
        base = "/tmp/vxlan_evpn_l2_{}".format(tag)
        self.script = base + ".sh"
        self.env_file = base + ".env"
        self.work = base + ".d"
        self.prefix = "vxevpn_{}".format(tag)

    def env(self):
        lines = [
            "PTF={}".format(self.ptf_container), "IMAGES=\"{}\"".format(self.image), "WORK={}".format(self.work),
            "PREFIX={}".format(self.prefix), "DUT_ASN={}".format(self.dut_asn), "DUT_VTEP={}".format(self.dut_vtep),
            "RT_ASN={}".format(self.rt_asn), "LEAVES=\"{}\"".format(" ".join(self.leaves)),
        ]
        for lf in self.leaves.values():
            lines += ["{}_PTF_IF={}".format(lf.name, lf.ptf_if), "{}_ASN={}".format(lf.name, lf.asn),
                      "{}_VTEP={}".format(lf.name, lf.vtep), "{}_IP={}".format(lf.name, lf.ip),
                      "{}_PLEN={}".format(lf.name, lf.plen),
                      "{}_DUT_IP={}".format(lf.name, lf.dut_ip),
                      "{}_VNIS=\"{}\"".format(lf.name, " ".join("{}:{}".format(v, n) for v, n in lf.vids_vnis))]
        return "\n".join(lines) + "\n"

    def install(self):
        self.vmhost.copy(src=LEAF_SCRIPT, dest=self.script, mode="0755")
        self.vmhost.copy(content=self.env(), dest=self.env_file)

    def run(self, *args, **kwargs):
        check = kwargs.get("check", True)
        cmd = "sudo bash {} {} {}".format(self.script, self.env_file, " ".join(str(a) for a in args))
        res = self.vmhost.shell(cmd, module_ignore_errors=True)
        if check and res["rc"] != 0:
            raise RuntimeError("test server: {} (rc={})\n{}\n{}".format(
                cmd, res["rc"], res.get("stdout", ""), res.get("stderr", "")))
        return res.get("stdout", "")

    def resolve_image(self):
        """(image, '') with the first leaf image present or pullable on the test server, else ('', why)."""
        res = self.vmhost.shell("sudo bash {} {} image".format(self.script, self.env_file), module_ignore_errors=True)
        out = res.get("stdout", "")
        image = next((ln.split()[1] for ln in out.splitlines() if ln.startswith("LEAF_IMAGE ")), "")
        if res["rc"] == 0 and image:
            return image, ""
        return "", "{} (rc={}): {}".format(self.image, res["rc"], (res.get("stderr", "") or out).strip()[-300:])

    def up(self):
        out = self.run("up")
        if "LEAVES_UP" not in out:
            raise RuntimeError("leaves did not come up:\n" + out)
        logger.info("leaves up:\n%s", out)

    def remove_files(self):
        self.vmhost.shell("rm -f {} {}".format(self.script, self.env_file), module_ignore_errors=True)

    def down(self):
        out = self.run("down", check=False)
        logger.info("leaves down:\n%s", out)
        self.remove_files()
        return "LEAVES_DOWN" in out

    def uplink_mac(self, leaf):
        """The MAC of the leaf's uplink: the outer destination MAC of what the DUT sends to the leaf."""
        mac = self.run("ulmac", leaf).strip().lower()
        if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
            raise RuntimeError("leaf {}: no uplink MAC ('{}')".format(leaf, mac))
        return mac

    def fdb(self, op, leaf, mac, vid, dev="hb", static=False):
        """Add or remove a local MAC on the leaf; static=True adds it static and sticky (FRR advertises it with the
        MAC mobility sticky bit, and the receiving zebra installs it so that no local learning can move it)."""
        self.run("fdb", op, leaf, mac, vid, dev, *(["static"] if static else []))

    def vni(self, op, leaf, vni):
        self.run("vni", op, leaf, vni)

    def vni_add(self, leaf, vid, vni):
        """One more VNI on the leaf (tagged vid on its host), exported and imported with route target RT_ASN:vni."""
        self.run("vniadd", leaf, vid, vni)

    def vni_del(self, leaf, vid, vni, check=True):
        self.run("vnidel", leaf, vid, vni, check=check)

    def send(self, leaf, dst, src, count, tag):
        """count untagged frames from the leaf's host (its first VLAN)."""
        out = self.run("send", leaf, dst, src, count, tag)
        if "SENT {}".format(count) not in out:
            raise RuntimeError("leaf {} did not send {} frames: {}".format(leaf, count, out))

    def remote_mac_dst(self, leaf, mac):
        """The VTEP of the leaf's remote MAC mac (zebra installs a bridge entry on the vxlan device and the device's
        own entry with the VTEP), or None. A device entry with no bridge entry on that device is not one: zebra leaves
        it behind when the MAC becomes local on the leaf."""
        entries = [e for e in json.loads(self.run("fdbshow", leaf)) if e.get("mac", "").lower() == mac.lower()]
        bridged = {e.get("ifname") for e in entries if e.get("master")}
        for e in entries:
            if e.get("dst") and e.get("ifname", "").startswith("vx") and e["ifname"] in bridged:
                return e["dst"]
        return None

    def flood_dsts(self, leaf, vni):
        """The leaf's kernel head-end list for vni (all-zero MAC entries on vx<vni>)."""
        return {e["dst"] for e in json.loads(self.run("fdbshow", leaf))
                if e.get("mac") == "00:00:00:00:00:00" and e.get("ifname") == "vx{}".format(vni) and e.get("dst")}


# --------------------------------------------------------------------------------------------------------------------
# DUT side: BGP toward the leaves (vtysh: works the same in split and unified routing-config mode)
# --------------------------------------------------------------------------------------------------------------------
def dut_bgp_add_commands(dut_asn, leaves, rt_asn, vnis, add_advertise_all_vni=True):
    cmds = ["configure terminal",
            "ip prefix-list {} seq 10 permit 10.0.0.0/8 ge 32".format(DUT_PL_LOOPS),
            "route-map {} permit 10".format(DUT_RM_LOOPS),
            "match ip address prefix-list {}".format(DUT_PL_LOOPS),
            "exit",
            "route-map {} permit 10".format(DUT_RM_EVPN),
            "exit",
            "router bgp {}".format(dut_asn)]
    for lf in leaves:
        cmds += ["neighbor {} remote-as {}".format(lf.ip, lf.asn),
                 "neighbor {} description vxlan_evpn_l2_{}".format(lf.ip, lf.name)]
    cmds.append("address-family ipv4 unicast")
    for lf in leaves:
        cmds += ["neighbor {} activate".format(lf.ip),
                 "neighbor {} route-map {} in".format(lf.ip, DUT_RM_LOOPS),
                 "neighbor {} route-map {} out".format(lf.ip, DUT_RM_LOOPS)]
    cmds += ["exit-address-family", "address-family l2vpn evpn"]
    for lf in leaves:
        cmds += ["neighbor {} activate".format(lf.ip),
                 "neighbor {} route-map {} in".format(lf.ip, DUT_RM_EVPN),
                 "neighbor {} route-map {} out".format(lf.ip, DUT_RM_EVPN)]
    if add_advertise_all_vni:
        cmds.append("advertise-all-vni")
    for vni in vnis:
        cmds += ["vni {}".format(vni), "route-target import {}:{}".format(rt_asn, vni),
                 "route-target export {}:{}".format(rt_asn, vni), "exit-vni"]
    cmds += ["exit-address-family", "exit", "end"]
    return cmds


def dut_bgp_remove_commands(dut_asn, leaves, vnis, remove_advertise_all_vni=True):
    cmds = ["configure terminal", "router bgp {}".format(dut_asn)]
    cmds += ["no neighbor {}".format(lf.ip) for lf in leaves]
    cmds.append("address-family l2vpn evpn")
    cmds += ["no vni {}".format(vni) for vni in vnis]
    if remove_advertise_all_vni:
        cmds.append("no advertise-all-vni")
    cmds += ["exit-address-family", "exit",
             "no route-map {} permit 10".format(DUT_RM_LOOPS),
             "no route-map {} permit 10".format(DUT_RM_EVPN),
             "no ip prefix-list {} seq 10 permit 10.0.0.0/8 ge 32".format(DUT_PL_LOOPS),
             "end"]
    return cmds


def vtysh(duthost, cmds, check=True):
    return sh(duthost, "sudo vtysh " + " ".join("-c '{}'".format(c) for c in cmds), check=check)


def dut_has_advertise_all_vni(duthost):
    return "advertise-all-vni" in sh(duthost, "sudo vtysh -c 'show running-config'", check=False)


def evpn_peer_established(duthost, peer):
    """The DUT's l2vpn evpn session to peer is Established (a poll condition: wait_until treats a raise as False)."""
    out = sh(duthost, "sudo vtysh -c 'show bgp l2vpn evpn summary json'", check=False)
    return json.loads(out).get("peers", {}).get(peer, {}).get("state") == "Established"


def _bgp_paths(node):
    if isinstance(node, dict):
        for path in node.get("paths", []):
            for p in (path if isinstance(path, list) else [path]):
                yield p
        for key, value in node.items():
            if key != "paths":
                for p in _bgp_paths(value):
                    yield p


def received_mac_mobility(duthost, mac, vtep):
    """[(sequence, sticky), ...]: the MAC Mobility extended community of each Type-2 path for mac that the DUT's bgpd
    holds with next hop vtep, as the advertising VTEP sent it; (0, False) for a path without the community. [] when
    there is no such path or the output cannot be read."""
    out = sh(duthost, "sudo vtysh -c 'show bgp l2vpn evpn route rd all mac {} json'".format(mac.lower()), check=False)
    try:
        paths = list(_bgp_paths(json.loads(out)))
    except ValueError:
        logger.warning("no JSON from the DUT's bgpd for the EVPN routes of %s: %r", mac, out[-300:])
        return []
    mm = []
    for p in paths:
        if not any(nh.get("ip") == vtep for nh in p.get("nexthops", [])):
            continue
        m = re.search(r"MM:(\d+)(, sticky MAC)?", p.get("extendedCommunity", {}).get("string", ""))
        mm.append((int(m.group(1)), bool(m.group(2))) if m else (0, False))
    return mm


# --------------------------------------------------------------------------------------------------------------------
# DUT side: the rig (each module builds its own with a module fixture)
# --------------------------------------------------------------------------------------------------------------------
BASELINE_TYPES = ("TUNNEL", "TUNNEL_MAP_ENTRY", "VLAN", "VLAN_MEMBER", "BRIDGE_PORT")


def rig_preflight(vmhost, ansible_adhoc, inv_files):
    """Skip or fail before the rig changes anything: a test server for the leaves. Returns SimpleNamespace(server,
    image) with image the candidate list (Leaves.resolve_image picks one)."""
    server, why = usable_test_server(vmhost, ansible_adhoc, inv_files)
    if server is None and not why:
        pytest.skip("no test server (vmhost) in this testbed to run the remote leaves on")
    if server is None:
        pytest.fail("the remote leaves need the test server: {}".format(why))
    image = os.environ.get(LEAF_IMAGE_ENV) or DEFAULT_LEAF_IMAGES
    return SimpleNamespace(server=server, image=image)


def resolve_leaf_image(lv):
    """The leaf image (Leaves.resolve_image) before the rig changes the DUT; skip when the test server has none."""
    image, why = lv.resolve_image()
    if not image:
        lv.down()
        pytest.skip("no FRR leaf image on the test server: {}".format(why))
    return image


def pick_rig_ports(duthost, access):
    """Four access ports (vxlan_l2_helpers.access_ports with need=4: e.g. Vlan1000's members on a t0), and the DUT
    facts the rig needs. Returns SimpleNamespace(idx, base_vlan, base_vid, ports, lo, dut_asn, peer_asn): peer_asn is
    the AS the leaves peer with, the confederation identifier when the DUT is a confederation member (t2), else
    dut_asn."""
    mg = access.mg
    dut_asn = mg["minigraph_bgp_asn"]
    confed = duthost.get_bgp_confed_asn()
    return SimpleNamespace(idx=mg["minigraph_ptf_indices"], base_vlan=access.base_vlan,
                           base_vid=int(access.base_vlan.replace("Vlan", "")), ports=access.members[:4],
                           lo=loopback0_ipv4(mg), dut_asn=dut_asn, peer_asn=int(confed) if confed else dut_asn)


def check_leaf_vteps_unrouted(duthost, leaves):
    for lf in leaves:
        pfx, _ = route_nexthop_ifaces(duthost, lf.vtep)
        if pfx not in (None, "0.0.0.0/0"):
            pytest.fail("leaf VTEP {} is already routed on the DUT ({}); pick another address".format(lf.vtep, pfx))


def assert_clean_start(duthost, leaves, vlan_names, vnis, more=()):
    """Fail when a previous run left rig state behind. more: extra (db, key pattern) pairs that must be empty."""
    dirty = vxlan_state_left(duthost, vlan_names, more)
    for k in db_keys(duthost, "CONFIG_DB", "INTERFACE|*"):
        if any("|{}/".format(lf.dut_ip) in k for lf in leaves):
            dirty.append("CONFIG_DB " + k)
    running = sh(duthost, "sudo vtysh -c 'show running-config'", check=False)
    for lf in leaves:
        if "neighbor {} ".format(lf.ip) in running:
            dirty.append("FRR neighbor {}".format(lf.ip))
    for vni in vnis:
        if re.search(r"^\s*vni {}\s*$".format(vni), running, re.M):
            dirty.append("FRR vni {}".format(vni))
    if dirty:
        pytest.fail("DUT is not clean for the EVPN rig (a previous run left state?): {}".format("; ".join(dirty)))


def check_ingress_once(duthost, ptfadapter, senders, rig_ports, tag):
    """Each port the module sends on must deliver every PTF frame to the DUT exactly once, and to no other rig port
    (a testbed path that duplicates or loops frames corrupts every count this module reads). Broadcasts in the base
    VLAN, counted by the DUT's port RX counters. senders: {DUT port: PTF port}; tag: a prefix for the frames' tags.

    A virtual switch does not feed its port counters; there the base VLAN's flood of each broadcast is read at the
    PTF instead: every other sender port gets each frame once (9 in 10 at least, none twice), the sender none back."""
    n, slack, stat = 20, 4, ("SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS",)
    if duthost.facts.get("asic_type") == "vs":
        for port, ptf_port in senders.items():
            t = tag + port
            copies = send_and_count(ptfadapter, ptf_port, probe_frame(t, BROADCAST_MAC, "02:4c:45:00:00:0a"), n, t)
            got = {p: native_on(copies, pp) for p, pp in senders.items()}
            if got[port] or not all(delivered(got[p], n) for p in senders if p != port):
                pytest.fail("testbed: {} broadcasts sent on PTF port {} were flooded to the sender ports {} times "
                            "({} expected on each other one, none on {}; PTF copies): the path between the PTF and "
                            "the DUT does not deliver frames once, so every count here would be wrong. Copies: "
                            "{}".format(n, ptf_port, got, n, port, summarize(copies)))
        return
    poll = counter_poll_s(duthost)
    for port, ptf_port in senders.items():
        before = port_counters(duthost, rig_ports, stat)
        testutils.send(ptfadapter, ptf_port, probe_frame(tag + port, BROADCAST_MAC, "02:4c:45:00:00:0a"), count=n)
        end = time.time() + 10
        while time.time() < end and port_counters(duthost, [port], stat)[port] - before[port] < n:
            time.sleep(poll)
        time.sleep(poll + 0.5)   # one more poll, so copies beyond n are counted too
        after = port_counters(duthost, rig_ports, stat)
        got = {p: after[p] - before[p] for p in rig_ports}
        if not n <= got[port] <= n + slack or any(got[p] > slack for p in rig_ports if p != port):
            pytest.fail("testbed: {} broadcasts sent on PTF port {} reached the DUT's rig ports {} times ({} expected "
                        "on {}, at most {} elsewhere; DUT RX counters): the path between the PTF and the DUT does not "
                        "deliver frames once, so every count here would be wrong".format(
                            n, ptf_port, got, n, port, slack))


def baseline_counts(duthost):
    return asic_counts(duthost, BASELINE_TYPES)


class RigBuild(object):
    """The DUT side of an EVPN rig, built step by step and undone in reverse by teardown(): the leaves' sessions
    first (so the remote state goes before the tunnel), then the VxLAN objects, members, VLANs and IPs, and the ports
    back into their base VLAN, each step once orchagent has done the one before. Nothing is saved; the teardown proves
    the DUT is back to its ASIC_DB baseline, and tests/vxlan/conftest.py then reloads the saved config.

    Steps the generic order does not cover register an undo with on_teardown() once they are done: "first" hooks run
    before the BGP sessions are removed, "after_members" ones once the VLAN members are gone; within a phase the last
    registered runs first. baseline(duthost) is the ASIC_DB reading the teardown must return to; leftovers are extra
    (db, key pattern) pairs that must be empty after it.
    """

    def __init__(self, request, duthost, pick, leaves, lv, rt_asn, vlans_vnis, baseline=baseline_counts,
                 log_ignore=KNOWN_HARMLESS_LOG, leftovers=()):
        self.request, self.duthost = request, duthost
        self.base_vid, self.base_vlan, self.ports = pick.base_vid, pick.base_vlan, pick.ports
        self.dut_asn, self.dut_vtep = pick.dut_asn, pick.lo
        self.leaves, self.lv, self.rt_asn = leaves, lv, rt_asn
        self.vlans_vnis = list(vlans_vnis)
        self.vnis = [vni for _vid, vni in self.vlans_vnis]
        self.baseline, self.log_ignore, self.leftovers = baseline, log_ignore, tuple(leftovers)
        self.built = []
        self.hooks = {"first": [], "after_members": []}
        self.leaves_down = False
        self.arp_refresh_held = False
        self.base = baseline(duthost)

    def ports_out_of_base(self):
        for p in self.ports:
            sh(self.duthost, "sudo config vlan member del {} {}".format(self.base_vid, p))
            self.built.append(("member", p))

    def leaf_ips(self):
        """The DUT's address toward each leaf; once per port when leaves share one."""
        done = set()
        for lf in self.leaves:
            if lf.dut_port in done:
                continue
            done.add(lf.dut_port)
            sh(self.duthost, "sudo config interface ip add {} {}/{}".format(lf.dut_port, lf.dut_ip, lf.plen))
            self.built.append(("ip", lf))

    def vlans(self):
        for vid, _vni in self.vlans_vnis:
            sh(self.duthost, "sudo config vlan add {}".format(vid))
            self.built.append(("vlan", vid))

    def member(self, vid, port, untagged):
        sh(self.duthost, "sudo config vlan member add {}{} {}".format("-u " if untagged else "", vid, port))
        self.built.append(("vlanmember", vid, port))

    def vxlan(self):
        self.built.append(("vtep",))
        add_vxlan(self.duthost, self.dut_vtep, self.vlans_vnis)

    def wait_connected(self):
        for lf in self.leaves:
            wait_for(60, 2, lambda: route_nexthop_ifaces(self.duthost, lf.ip)[1] == {lf.dut_port},
                     "the connected /31 toward {} on {}".format(lf.name, lf.dut_port))

    def bgp(self, added_aav):
        self.built.append(("bgp", added_aav))    # first: a vtysh run that fails part-way still gets undone
        vtysh(self.duthost, dut_bgp_add_commands(self.dut_asn, self.leaves, self.rt_asn, self.vnis, added_aav))

    def leaves_up(self):
        self.built.append(("leaves",))
        self.lv.up()

    def expected_remote_vnis(self):
        return {("Vlan{}".format(vid), lf.vtep) for lf in self.leaves for vid, _vni in lf.vids_vnis}

    def converge(self, timeout):
        """Gates: each session up, each leaf VTEP routed via its port, APPL_DB's remote VNIs exactly the leaves'
        Type-3s, and each leaf holding the DUT's Type-3 for each of its VNIs."""
        d = self.duthost
        for lf in self.leaves:
            wait_for(timeout, 5, lambda: evpn_peer_established(d, lf.ip),
                     "l2vpn evpn session to {} ({})".format(lf.name, lf.ip))
            wait_for(timeout, 5, lambda: route_nexthop_ifaces(d, lf.vtep) == ("{}/32".format(lf.vtep), {lf.dut_port}),
                     "the DUT's route to {}'s VTEP {} via {}".format(lf.name, lf.vtep, lf.dut_port))
        want = self.expected_remote_vnis()
        wait_for(timeout, 5, lambda: appl_remote_vnis(d) == want,
                 "APPL_DB VXLAN_REMOTE_VNI_TABLE == {}".format(sorted(want)))
        for lf in self.leaves:
            for _vid, vni in lf.vids_vnis:
                wait_for(timeout, 5, lambda: self.dut_vtep in self.lv.flood_dsts(lf.name, vni),
                         "{} to hold the DUT's Type-3 for VNI {}".format(lf.name, vni))

    def hold_arp_refresh(self):
        """Stop swss's arp_update for the life of the rig (vxlan_l2_helpers.hold_arp_refresh); the teardown starts it
        again. Calling it again is cheap and stops arp_update once more if a swss restart brought it back."""
        if hold_arp_refresh(self.duthost):
            self.arp_refresh_held = True

    def on_teardown(self, phase, what, fn):
        self.hooks[phase].append((what, fn))

    def teardown(self):
        """Undo the rig in reverse order; pytest.fail with every step that failed."""
        step = Steps("EVPN rig teardown")
        try:
            step("teardown", lambda: self._undo(step))
        finally:
            if self.arp_refresh_held:
                resume_arp_refresh(self.duthost)
            # the leaves live on the test server, which no config reload reaches
            if ("leaves",) in self.built and not self.leaves_down:
                self.lv.down()
        step.finish()

    def _vlans_and_rifs_gone(self):
        view = AsicView(self.duthost, ("VLAN", "ROUTER_INTERFACE"))
        ports = {lf.dut_port for lf in self.leaves}
        rifs = [a for a in view.objs["ROUTER_INTERFACE"].values()
                if view.port_names.get(a.get("SAI_ROUTER_INTERFACE_ATTR_PORT_ID")) in ports]
        return len(view.objs["VLAN"]) == self.base["VLAN"] and not rifs

    def _undo(self, step):
        d, built = self.duthost, self.built
        with log_clean(self.request, d, "teardown", self.log_ignore):
            for what, fn in reversed(self.hooks["first"]):
                step(what, fn)
            bgp = [b for b in built if b[0] == "bgp"]
            if bgp:
                step("bgp remove", lambda: vtysh(d, dut_bgp_remove_commands(self.dut_asn, self.leaves, self.vnis,
                                                                            bgp[0][1])))
                step("remote state gone", lambda: wait_for(
                    90, 3, lambda: not appl_remote_vnis(d) and not db_keys(d, "APPL_DB", "VXLAN_FDB_TABLE:*"),
                    "APPL_DB remote VNIs / MACs to go after the sessions closed"))
            if ("leaves",) in built:
                def down():
                    if not self.lv.down():
                        raise RuntimeError("leaf teardown did not finish")
                    self.leaves_down = True
                step("leaves down", down)
            for vid in (b[1] for b in built if b[0] == "vlan"):
                step("fdb flush {}".format(vid), lambda v=vid: flush_vlan_fdb(d, v))
            if ("vtep",) in built:
                remove_vxlan(d, self.vlans_vnis, step)
            members = [b for b in reversed(built) if b[0] == "vlanmember"]
            for b in members:
                step("member del {} {}".format(b[1], b[2]), lambda v=b[1], p=b[2]: sh(
                    d, "sudo config vlan member del {} {}".format(v, p)))
            moved = len([b for b in built if b[0] == "member"])
            if members:
                step("members gone", lambda: wait_for(
                    60, 2, lambda: asic_count(d, "VLAN_MEMBER") == self.base["VLAN_MEMBER"] - moved,
                    "the rig VLANs' members to leave ASIC_DB"))
            for what, fn in reversed(self.hooks["after_members"]):
                step(what, fn)
            for b in reversed(built):
                if b[0] == "vlan":
                    step("vlan del {}".format(b[1]), lambda v=b[1]: sh(d, "sudo config vlan del {}".format(v)))
                elif b[0] == "ip":
                    lf = b[1]
                    step("ip remove {}".format(lf.dut_port), lambda lf=lf: sh(
                        d, "sudo config interface ip remove {} {}/{}".format(lf.dut_port, lf.dut_ip, lf.plen)))
            # a port rejoins its VLAN once its router interface is gone
            step("vlans and leaf RIFs gone", lambda: wait_for(
                60, 2, self._vlans_and_rifs_gone, "the rig VLANs and the leaf ports' router interfaces to leave "
                "ASIC_DB"))
            for b in built:
                if b[0] == "member":
                    step("{} back to {}".format(b[1], self.base_vlan), lambda p=b[1]: sh(
                        d, "sudo config vlan member add -u {} {}".format(self.base_vid, p)))
            if not wait_until(90, 5, 0, lambda: self.baseline(d) == self.base):
                step.errors.append("ASIC_DB not back to baseline: {} -> {}".format(self.base, self.baseline(d)))
            step.errors.extend("still holds " + x for x in vxlan_state_left(
                d, ["Vlan{}".format(vid) for vid, _vni in self.vlans_vnis], self.leftovers))


# --------------------------------------------------------------------------------------------------------------------
# DUT side: APPL_DB gates and ASIC_DB readers
# --------------------------------------------------------------------------------------------------------------------
def appl_remote_vnis(duthost):
    """{(vlan_name, vtep)} of VXLAN_REMOTE_VNI_TABLE (what fdbsyncd wrote from the Type-3 routes)."""
    out = set()
    for k in db_keys(duthost, "APPL_DB", "VXLAN_REMOTE_VNI_TABLE:*"):
        parts = k.split(":")
        if len(parts) == 3:
            out.add((parts[1], parts[2]))
    return out


def appl_remote_mac_vtep(duthost, vlan_name, mac):
    return db_hget(duthost, "APPL_DB", "VXLAN_FDB_TABLE:{}:{}".format(vlan_name, mac.lower()), "remote_vtep")


def asic_flood_members(duthost):
    return AsicView(duthost).flood_members()


def tunnel_bridge_port_learning(duthost):
    """{bridge port oid: FDB learning mode} of every TUNNEL bridge port in ASIC_DB (EVPN tunnels must not learn)."""
    return {oid: a.get("SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE", "")
            for ports in AsicView(duthost).tunnel_bridge_ports().values() for oid, a in ports}


# --------------------------------------------------------------------------------------------------------------------
# PTF side: count copies of a tag after an action that is not a PTF send (a leaf sending, for example)
# --------------------------------------------------------------------------------------------------------------------
def count_after(ptfadapter, action, tag):
    """Flush, run action(), then collect every copy of tag seen on any PTF port (vxlan_l2_helpers.collect).

    Frames that arrive while action() runs (an ansible round trip) wait in the PTF's per-port queues (100 deep), so
    an arm stays well under that.
    """
    needle = tag.encode()
    copies = [c for c, _m in collect(ptfadapter, action, lambda raw: needle in raw, quiet=2.0, max_wait=15.0)]
    logger.info("tag %s: captured %d copies: %s", tag, len(copies), summarize(copies))
    return copies
