"""Helpers shared by the L2 VxLAN modules in tests/vxlan (test_vxlan_l2.py, test_vxlan_evpn_l2.py and the modules
built on them).

* DUT side: static remote VTEPs and remote MACs written to APPL_DB through swssconfig (a plain HSET does not notify
  orchagent), the DUT's VxLAN config, and DB readers, among them AsicView, one snapshot of chosen ASIC_DB object types.
* Rig scaffolding: payload tags, the setup/teardown LogAnalyzer, the teardown step collector, the clean-start check
  and the underlay toward the remote VTEPs the PTF plays.
* PTF side: frame builders, the VxLAN expectation mask, and a per-port counter keyed on a payload tag.

The per-port counter is the instrument the modules rely on. ``verify_packet_any_port`` stops at the first match, so
duplicates, an echo back to the sending VTEP, or a re-flood to another VTEP are invisible to it. Every case sends N
tagged frames and counts every copy of that tag on every port.

Clean-up rule for the rigs: a rig undoes what it built and proves ASIC_DB is back to its baseline (the teardown is a
leak check in its own right); tests/vxlan/conftest.py reloads the saved config after every module, and a rig leaves to
that reload only what it could put back by hand only with a restart of its own (the warm-reboot module's VLANs across
the boot).
"""

import collections
import contextlib
import json
import logging
import random
import re
import time
from types import SimpleNamespace

import ptf.packet as packet
import ptf.testutils as testutils
import pytest
from natsort import natsorted
from ptf.mask import Mask
from scapy.packet import Raw

from tests.common.helpers.sonic_db import redis_hgetall
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

VXLAN_UDP_PORT = 4789
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
# Ethertype of the tagged probe frames: an unassigned value, so nothing on the DUT or the PTF consumes or answers
# them, and the switch floods a broadcast of it like any other L2 frame.
PROBE_ETHERTYPE = 0x0805
VTEP_NAME, NVO_NAME = "vtep1", "nvo1"

N = 40                     # frames per arm
GOOD = N * 9 // 10         # a delivered arm of N counts at least this many copies (and never more than N)

# orchagent/syncd log this on every remote-VTEP tunnel add on current images; it is not a failure.
KNOWN_HARMLESS_LOG = [
    r".*meta_sai_on_port_state_change_single.*unexpected type: SAI_OBJECT_TYPE_TUNNEL.*",
]
# fdbsyncd sends an L2_NEXTHOP_GROUP delete for every kernel nexthop id that goes (a PortChannel RIF flap removes the
# routed nexthops); orchagent logs ERR for the ids that were never L2 nexthop groups. No state is left behind.
L2NHG_DEL_NOISE_LOG = [
    r".*ERR swss#orchagent: :- deleteL2Nhg: Can't delete L2NHG '\d+': does not exist.*",
]


# --------------------------------------------------------------------------------------------------------------------
# DUT side
# --------------------------------------------------------------------------------------------------------------------
def sh(duthost, cmd, check=True):
    res = duthost.shell(cmd, module_ignore_errors=True)
    if check and res["rc"] != 0:
        raise RuntimeError("DUT command failed (rc={}): {}\n{}\n{}".format(
            res["rc"], cmd, res.get("stdout", ""), res.get("stderr", "")))
    return res["stdout"]


def db_keys(duthost, db, pattern):
    out = sh(duthost, "sonic-db-cli {} KEYS '{}'".format(db, pattern))
    return [k for k in out.splitlines() if k.strip()]


def db_hget(duthost, db, key, field):
    """Value of field, or '' when the key or field is missing (sonic-db-cli exits 0 either way)."""
    return sh(duthost, "sonic-db-cli {} HGET '{}' '{}'".format(db, key, field)).strip()


def asic_count(duthost, obj_type):
    return asic_counts(duthost, (obj_type,))[obj_type]


def asic_counts(duthost, types):
    """{object type: ASIC_DB object count} for each of types (one shell call)."""
    script = "; ".join(
        "echo {t} $(sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_{t}:*' | grep -c .)".format(t=t)
        for t in types)
    out = {}
    for line in sh(duthost, script).splitlines():
        toks = line.split()
        if len(toks) == 2 and toks[1].isdigit():
            out[toks[0]] = int(toks[1])
    if set(out) != set(types):
        raise AssertionError("ASIC_DB counts unreadable: {}".format(out))
    return out


def asic_objects_naming(duthost, obj_type, needle):
    """How many ASIC_DB objects of obj_type carry needle anywhere in their attributes (a substring match: not for IP
    addresses, where 10.1.0.3 also matches 10.1.0.32; use vxlan_tunnels_to for tunnel destinations)."""
    script = (
        "n=0; for k in $(sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_{t}:*'); do "
        "case \"$(sonic-db-cli ASIC_DB HGETALL \"$k\")\" in *'{n}'*) n=$((n+1));; esac; done; echo $n"
    ).format(t=obj_type, n=needle)
    return int(sh(duthost, script).strip().splitlines()[-1])


def asic_vlan_ids(duthost):
    script = ("for k in $(sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_VLAN:*'); do "
              "sonic-db-cli ASIC_DB HGET \"$k\" SAI_VLAN_ATTR_VLAN_ID; done")
    return {int(v) for v in sh(duthost, script).split() if v.isdigit()}


def swss_apply(duthost, entries, name="vxlan_l2"):
    """Write APPL_DB rows through swssconfig in the swss container (a plain HSET does not notify orchagent)."""
    path = "/tmp/{}_{}.json".format(name, int(time.time() * 1000))
    duthost.copy(content=json.dumps(entries, indent=1), dest=path)
    try:
        sh(duthost, "docker exec -i swss swssconfig /dev/stdin < {}".format(path))
    finally:
        sh(duthost, "rm -f {}".format(path), check=False)


def remote_vni_row(vlan, vtep, vni, op="SET"):
    key = "VXLAN_REMOTE_VNI_TABLE:{}:{}".format(vlan, vtep)
    return {key: {"vni": str(vni)} if op == "SET" else {}, "OP": op}


def remote_mac_row(vlan, mac, vtep, vni, op="SET", mac_type="static"):
    key = "VXLAN_FDB_TABLE:{}:{}".format(vlan, mac.lower())
    val = {"remote_vtep": vtep, "type": mac_type, "vni": str(vni)} if op == "SET" else {}
    return {key: val, "OP": op}


def swss_apply_later(duthost, batches, rounds, delay=2, gap=0.3, name="vxlan_l2_later"):
    """In the background on the DUT, starting `delay` seconds from now: write each batch of APPL_DB rows through
    swssconfig, one after the other, `rounds` times, `gap` seconds apart, so the writes land while the PTF is
    sending. Returns the path of a file that exists once the last write is done; swss_apply_later_done() reads and
    removes it."""
    base = "/tmp/{}_{}".format(name, int(time.time() * 1000))
    paths = []
    for i, entries in enumerate(batches):
        paths.append("{}.{}.json".format(base, i))
        duthost.copy(content=json.dumps(entries, indent=1), dest=paths[-1])
    script = ("sleep {delay}\nfor i in $(seq {rounds}); do for f in {files}; do\n"
              "  docker exec -i swss swssconfig /dev/stdin < $f || echo failed >> {base}.err; sleep {gap}\n"
              "done; done\nrm -f {files}\ntouch {base}.done\n").format(
                  delay=delay, rounds=rounds, files=" ".join(paths), gap=gap, base=base)
    duthost.copy(content=script, dest=base + ".sh")
    sh(duthost, "sudo sh -c 'nohup sh {b}.sh </dev/null >/dev/null 2>&1 &'".format(b=base))
    return base


def swss_apply_later_finished(duthost, base):
    """Whether a swss_apply_later run has made its last write."""
    return sh(duthost, "test -e {}.done && echo y; true".format(base)).strip() == "y"


def swss_apply_later_done(duthost, base, timeout=60):
    """Wait for a swss_apply_later run to finish and remove its files; fails when it did not finish or a write
    failed."""
    done = wait_until(timeout, 2, 0, lambda: swss_apply_later_finished(duthost, base))
    if not done:
        sh(duthost, "sudo pkill -f '^sh {}.sh' 2>/dev/null; true".format(base), check=False)
    failed = sh(duthost, "cat {b}.err 2>/dev/null | wc -l; sudo rm -f {b}.sh {b}.done {b}.err {b}.*.json".format(
        b=base)).strip()
    if not done or failed != "0":
        raise AssertionError("the background APPL_DB writes did not complete (finished: {}, failed writes: {})".format(
            done, failed))


def local_mac_row(vlan, mac, port, op="SET", mac_type="dynamic"):
    """An APPL_DB FDB_TABLE row: a MAC on a local port, as a static FDB configuration (static) and the FDB restore of
    a fast reboot (dynamic) write them."""
    key = "FDB_TABLE:{}:{}".format(vlan, mac.lower())
    return {key: {"port": port, "type": mac_type} if op == "SET" else {}, "OP": op}


SAIREDIS_REC = "/var/log/swss/sairedis.rec"


def sairedis_mark(duthost):
    """The current length of the sairedis recording, for sai_fdb_calls."""
    out = sh(duthost, "sudo cat {} | wc -l".format(SAIREDIS_REC)).strip()
    if not out.isdigit():
        raise AssertionError("the sairedis recording {} is unreadable: '{}'".format(SAIREDIS_REC, out))
    return int(out)


def sai_fdb_calls(duthost, mac, mark):
    """{"set": n, "set_type": n, "create": n, "remove": n}: the SAI calls on mac's FDB entries that orchagent made
    since mark, from the sairedis recording (the whole file when it was rotated since). set_type counts the SETs of
    SAI_FDB_ENTRY_ATTR_TYPE alone: orchagent sets one attribute per call, so one rewrite of an entry is several
    SETs and one of them is the type."""
    out = sh(duthost, "n=$(sudo cat {rec} | wc -l); [ \"$n\" -ge {mark} ] && from={next} || from=1; "
                      "sudo tail -n +$from {rec} | grep -a 'SAI_OBJECT_TYPE_FDB_ENTRY' | grep -a -i -F '{mac}' | "
                      "awk -F'|' '{{print $2; if ($2 == \"s\" && $0 ~ /SAI_FDB_ENTRY_ATTR_TYPE=/) print \"t\"}}' | "
                      "sort | uniq -c; true".format(rec=SAIREDIS_REC, mark=mark, next=mark + 1, mac=mac))
    seen = {toks[1]: int(toks[0]) for toks in (line.split() for line in out.splitlines()) if len(toks) == 2}
    return {"set": seen.get("s", 0) + seen.get("S", 0), "set_type": seen.get("t", 0),
            "create": seen.get("c", 0) + seen.get("C", 0), "remove": seen.get("r", 0) + seen.get("R", 0)}


def oper_up_vteps(duthost, ips):
    """The ips that `show vxlan remotevtep` lists as oper_up (one call)."""
    up = set()
    for line in sh(duthost, "show vxlan remotevtep", check=False).splitlines():
        toks = set(re.split(r"[|\s]+", line))
        if "oper_up" in toks:
            up |= toks & set(ips)
    return up


def remote_vtep_oper_up(duthost, ip):
    return ip in oper_up_vteps(duthost, [ip])


def add_remote_vtep(duthost, vlan, ip, vni, timeout=60):
    """Remote VTEP ip in vlan's flood list (an APPL_DB row), once it is oper_up with an ASIC_DB tunnel."""
    swss_apply(duthost, [remote_vni_row(vlan, ip, vni)])
    wait_for(timeout, 2, lambda: remote_vtep_oper_up(duthost, ip) and vxlan_tunnels_to(duthost, ip) >= 1,
             "remote VTEP {} oper_up with an ASIC_DB tunnel".format(ip))


def route_nexthop_ifaces(duthost, ip):
    """(prefix, {interface}) of the selected FRR route (default VRF, IPv4 or IPv6 by the address) that covers ip;
    (None, set()) if there is none."""
    out = sh(duthost, "sudo vtysh -c 'show {} route {} json'".format("ipv6" if ":" in ip else "ip", ip), check=False)
    try:
        data = json.loads(out or "{}")
    except ValueError:
        return None, set()
    for prefix, entries in data.items():
        for entry in entries:
            if not entry.get("selected"):
                continue
            ifaces = {nh["interfaceName"] for nh in entry.get("nexthops", [])
                      if nh.get("active") and nh.get("interfaceName")}
            return prefix, ifaces
    return None, set()


def fdb_port(duthost, vlan_id, mac):
    """The port `show mac` puts mac on in vlan_id, or None. show mac reads ASIC_DB, so this is what SONiC holds."""
    out = sh(duthost, "show mac -v {}".format(vlan_id), check=False)
    for line in out.splitlines():
        toks = line.split()
        if len(toks) >= 4 and toks[1] == str(vlan_id) and toks[2].lower() == mac.lower():
            return toks[3]
    return None


# fdbsyncd's delete of a local MAC that the kernel no longer holds on that port (the kernel saw a station move first)
MOVE_DEL_LOG = [r".*ERR swss#fdbsyncd: :- updateLocalMac: Failed cmd: bridge fdb del .* master dynamic extern_learn "
                r"vlan \d+(?: proto \w+)?, res=, ret=255.*"]


def kernel_fdb_entry(duthost, vlan_id, mac):
    """(netdev, flags) of the DUT kernel bridge's entry for mac in vlan_id, or None. On a virtual switch the kernel
    bridge is the dataplane and learns by itself, so the netdev is where its frames go."""
    out = sh(duthost, "sudo /sbin/bridge fdb show | grep -i '^{} '; true".format(mac), check=False)
    for line in out.splitlines():
        toks = line.split()
        if "vlan" in toks and "dev" in toks and toks[toks.index("vlan") + 1] == str(vlan_id):
            return toks[toks.index("dev") + 1], set(toks)
    return None


def kernel_fdb_port(duthost, vlan_id, mac):
    entry = kernel_fdb_entry(duthost, vlan_id, mac)
    return entry[0] if entry else None


def kernel_fdb_forget(duthost, vlan_id, macs):
    """Remove the kernel bridge's self-learned entries for macs in vlan_id: on a virtual switch a MAC the kernel took
    over from another port has no SAI entry, so no SONiC flush reaches it. Entries SONiC or zebra installed
    (extern_learn) are left to their owners."""
    for mac in macs:
        entry = kernel_fdb_entry(duthost, vlan_id, mac)
        if entry and "extern_learn" not in entry[1]:
            sh(duthost, "sudo /sbin/bridge fdb del {} dev {} master vlan {}".format(mac, entry[0], vlan_id),
               check=False)


def flush_fdb(duthost, scope, name, wait=0):
    """FdbOrch's dynamic flush of one PORT or VLAN (the SAI call a link-down flush makes).

    The request is asynchronous: orchagent runs it whenever its main loop gets to it, which can be seconds later,
    after MACs learned in the meantime, and the flush then removes them. With wait (seconds), return only once
    orchagent has logged that it ran the flush (its NOTICE after the SAI flush call returns), after a syslog marker
    written before the request. A failed SAI flush logs an ERR first, which fails the case in LogAnalyzer.
    """
    if wait:
        if scope not in ("PORT", "VLAN"):
            raise ValueError("flush_fdb waits only for a PORT or VLAN flush, not {}".format(scope))
        mark = "vxlan_l2 flush_fdb {} {} {}".format(scope, name, time.time_ns())
        since = log_marker(duthost, "vxlan_l2", mark)
    sh(duthost, "redis-cli -n 0 PUBLISH FLUSHFDBREQUEST '[\"{}\",\"{}\"]'".format(scope, name))
    if wait:
        # a port flush's line is not the port+vlan one, 'Clear fdb by port(X)+vlan(Y)'
        done = (r"Clear fdb by vlan\(Vlan{}\)".format(name) if scope == "VLAN" else
                r"Clear fdb by port\({}\)([^+]|$)".format(name))
        wait_for(wait, 1, lambda: log_since(duthost, mark, done, since)[1], "orchagent to run the {} {} FDB flush "
                 "request ('{}' in syslog after '{}')".format(scope, name, done, mark))


LOG_MARKER_FOUND = "VXLAN-LOG-MARKER-FOUND"


def log_marker(duthost, tag, text):
    """Log text in syslog under tag; returns the DUT's epoch at that point, the `since` of log_since."""
    return int(sh(duthost, "logger -t {} '{}'; date +%s".format(tag, text)).split()[-1])


def log_since(duthost, marker, pattern, since):
    """(marker found, syslog lines after marker that match the extended regex pattern), over every syslog file written
    since the DUT epoch `since` (syslog rotates, and the per-test LogAnalyzer rotates it before each case). The marker
    counts only on the logger's own line, and no line that logs a command (ansible, sudo's COMMAND=) is returned, so
    this very read cannot match. Neither marker nor pattern may hold a single quote."""
    out = sh(duthost, "sudo sh -c 'fs=$(find /var/log -maxdepth 1 -name \"syslog*\" -newermt @{t}); "
                      "[ -n \"$fs\" ] && for f in $(ls -1tr $fs); do zcat -f \"$f\"; done' | "
                      "awk '/{m}/ && !/ansible|COMMAND=/ && !f {{f=1; print \"{found}\"}} f' | "
                      "grep -a -v -E 'ansible|COMMAND=' | grep -a -E '{found}|{p}'; true".format(
                          t=int(since) - 120, m=marker, found=LOG_MARKER_FOUND, p=pattern),
             check=False).splitlines()
    return LOG_MARKER_FOUND in out, [x for x in out if x != LOG_MARKER_FOUND]


def flush_vlan_fdb(duthost, vlan_id, timeout=30):
    """Flush vlan_id's learned MACs until STATE_DB holds none (a PTF host's own frames can be learned again in
    between). Every flush is waited for (flush_fdb wait), so none is left queued to remove a MAC learned after this
    returns. Done while the VLAN members exist: once a member is gone, fdbsyncd's kernel delete of its MACs fails
    (ERR "updateLocalMac: Failed cmd: bridge fdb del"), because the kernel already dropped them."""
    key = "FDB_TABLE|Vlan{}:*".format(vlan_id)
    if not db_keys(duthost, "STATE_DB", key):
        return      # nothing learned, or a VLAN orchagent never had (it logs no flush for one)
    end = time.time() + timeout
    while True:
        flush_fdb(duthost, "VLAN", str(vlan_id), wait=max(5, end - time.time()))
        # orchagent logs the flush when the SAI call returns; STATE_DB follows with the flush notifications
        if wait_until(5, 1, 0, lambda: not db_keys(duthost, "STATE_DB", key)):
            return
        if time.time() >= end:
            raise AssertionError("timed out after {}s waiting for STATE_DB FDB of Vlan{} to empty: {}".format(
                timeout, vlan_id, db_keys(duthost, "STATE_DB", key)))


def kernel_rx_packets(duthost, netdev):
    if not netdev:
        return None
    out = sh(duthost, "cat /sys/class/net/{}/statistics/rx_packets 2>/dev/null; true".format(netdev)).strip()
    return int(out) if out.isdigit() else None


def kernel_vxlan_netdev(duthost, vni):
    """The kernel VxLAN netdev vxlanmgr made for vni (e.g. vtep1-2000), or None."""
    out = sh(duthost, "ip -d -o link show type vxlan 2>/dev/null; true")
    for line in out.splitlines():
        toks = line.split()
        for i in range(len(toks) - 1):
            if toks[i] == "id" and toks[i + 1] == str(vni) and i > 0 and toks[i - 1] == "vxlan":
                return toks[1].rstrip(":").split("@")[0]
    return None


def kernel_path(duthost, kvx, before, sent):
    """'' when a decap of `sent` frames stayed in hardware, else why the reading is not a hardware result.

    A decap that fell to the CPU is bridged by the kernel VxLAN netdev kvx and still reaches the access ports, so the
    netdev's rx counter (read as `before` ahead of the frames) must not move by the frames sent.
    """
    after = kernel_rx_packets(duthost, kvx)
    if before is None or after is None:
        return "kernel {} rx counter unreadable ({} -> {})".format(kvx, before, after)
    if after - before >= sent // 2:
        return "the decap took the kernel path: {} rx +{} for {} frames; not a hardware result".format(
            kvx, after - before, sent)
    return ""


def wait_for(timeout, interval, cond, what):
    if not wait_until(timeout, interval, 0, cond):
        raise AssertionError("timed out after {}s waiting for {}".format(timeout, what))


def wait_state(timeout, interval, cond, what, now):
    """wait_for, with now() (the state at the timeout) in the failure message."""
    try:
        wait_for(timeout, interval, cond, what)
    except AssertionError as e:
        raise AssertionError("{}; now: {}".format(e, now()))


def pid_of(duthost, name):
    out = sh(duthost, "pgrep -x {} | head -1; true".format(name), check=False).strip()
    return out if out.isdigit() else ""


def hold_arp_refresh(duthost):
    """Stop swss's arp_update; True when it was running, so the caller starts it again when done.

    Every 300 s it pings ff02::1 on each VLAN interface. The hosts' replies, and the neighbor probes either side sends
    afterwards, reach the VLAN's other members (flooded, or unicast to the DUT's MAC in a VLAN without a router
    interface): a few frames in a member port's TX counter inside a counting window. A DUT without it is left alone.
    """
    if not re.search("RUNNING|STARTING", sh(duthost, "docker exec swss supervisorctl status arp_update", check=False)):
        return False
    sh(duthost, "docker exec swss supervisorctl stop arp_update", check=False)
    return True


def resume_arp_refresh(duthost):
    sh(duthost, "docker exec swss supervisorctl start arp_update", check=False)


def orch_health(duthost):
    """(unhealthy, error) from STATE_DB PROCESS_HEALTH|orchagent: orchagent latches a SAI failure it could not handle
    there (saihelper.cpp) until it restarts; (None, '') when the image has no such key."""
    un = db_hget(duthost, "STATE_DB", "PROCESS_HEALTH|orchagent", "unhealthy")
    return (un == "true" if un else None), db_hget(duthost, "STATE_DB", "PROCESS_HEALTH|orchagent", "error")


def binary_has(duthost, container, path, needle):
    """Whether the file (a binary or a template) in the container carries the string: a table or field name is a
    literal in the program that uses it."""
    return duthost.shell("docker exec {} grep -a -q -F '{}' {}".format(container, needle, path),
                         module_ignore_errors=True)["rc"] == 0


def established_bgp_peers(duthost):
    return sorted(ip for ip, v in duthost.get_bgp_neighbors().items() if v.get("state") == "established")


def counter_poll_s(duthost):
    ms = db_hget(duthost, "CONFIG_DB", "FLEX_COUNTER_TABLE|PORT", "POLL_INTERVAL")
    return int(ms) / 1000.0 if ms.isdigit() else 1.0


def port_counters(duthost, ports, stats):
    """{port: the sum of the given SAI port counters} from COUNTERS_DB (one shell call)."""
    script = "; ".join(
        "o=$(sonic-db-cli COUNTERS_DB HGET COUNTERS_PORT_NAME_MAP {p}); echo {p} {v}".format(
            p=p, v=" ".join("$(sonic-db-cli COUNTERS_DB HGET \"COUNTERS:$o\" {})".format(st) for st in stats))
        for p in ports)
    vals = {}
    for line in sh(duthost, script).splitlines():
        toks = line.split()
        if len(toks) == 1 + len(stats) and all(x.isdigit() for x in toks[1:]):
            vals[toks[0]] = sum(int(x) for x in toks[1:])
    if set(vals) != set(ports):
        raise AssertionError("unreadable counters {} for {}: {}".format(stats, ports, vals))
    return vals


TX_UCAST = ("SAI_PORT_STAT_IF_OUT_UCAST_PKTS",)
TX_ALL = ("SAI_PORT_STAT_IF_OUT_UCAST_PKTS", "SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS")
TX_SLACK = 4               # other traffic a member port may transmit inside one counter window (LLDP, ND)
# probe_frame copies fall in this frame-size bucket (sizes with the FCS) however they leave the DUT (untagged, tagged
# or VxLAN encapsulated); the control frames a port sends by itself (LACP, LLDP, ARP, ND) are all smaller.
TX_PROBE = ("SAI_PORT_STAT_ETHER_OUT_PKTS_1024_TO_1518_OCTETS",)
_tx_probe_warned = set()


def tx_probe_stats(duthost, ports):
    """The TX counters that count probe_frame copies on ports: the probe's size bucket, or every transmitted packet
    where the bucket is not counted (a virtual switch's SAI counts transmitted packets but not their sizes) or is
    missing for any of the ports.

    Checked on every measurement: a reload or a swss restart flushes COUNTERS_DB, and a bucket read from a missing
    field would make a zero reading vacuous.
    """
    if duthost.facts.get("asic_type") == "vs":
        return TX_ALL
    cmd = "; ".join("sonic-db-cli COUNTERS_DB HEXISTS \"COUNTERS:$(sonic-db-cli COUNTERS_DB HGET "
                    "COUNTERS_PORT_NAME_MAP {})\" {}".format(p, TX_PROBE[0]) for p in ports)
    found = [line.strip() for line in sh(duthost, cmd, check=False).splitlines() if line.strip()]
    if len(found) == len(ports) and all(f in ("1", "True") for f in found):
        return TX_PROBE
    if duthost.hostname not in _tx_probe_warned:
        _tx_probe_warned.add(duthost.hostname)
        logger.warning("%s not published for all of %s on %s (%s): member TX is read from %s, which also counts the "
                       "ports' control traffic", TX_PROBE[0], list(ports), duthost.hostname, found, list(TX_ALL))
    return TX_ALL


def settled_delta(duthost, ports, max_window_s, fn, stats=None, quiet=None):
    """Counter deltas over ports for what fn() sends, measured until they are stable and past two poll periods.

    Both ends are taken once the quiet ports (default: all) read the same twice in a row, so traffic sent just before
    the window (a control, a learn) is not counted in it.
    """
    stats = stats or TX_UCAST
    quiet = quiet or ports
    poll = counter_poll_s(duthost)
    c0 = port_counters(duthost, ports, stats)
    for _ in range(5):
        time.sleep(max(1.0, poll))
        c = port_counters(duthost, ports, stats)
        if all(c[p] == c0[p] for p in quiet):
            break
        c0 = c
    else:
        logger.info("counters of %s still moving before the window; starting it anyway", quiet)
    t0 = time.time()
    result = fn()
    prev = None
    while True:
        time.sleep(max(1.0, poll))
        c1 = port_counters(duthost, ports, stats)
        if prev and all(c1[p] == prev[p] for p in quiet) and time.time() - t0 >= 2 * poll + 1:
            break
        if time.time() - t0 > max_window_s:
            logger.info("counter window hit its %ss cap before %s settled", max_window_s, quiet)
            break
        prev = c1
    return [c1[p] - c0[p] for p in ports], time.time() - t0, result


# --------------------------------------------------------------------------------------------------------------------
# DUT side: the access ports the rigs take their hosts from
# --------------------------------------------------------------------------------------------------------------------
ACCESS_VID = 1000
ACCESS_VLAN = "Vlan{}".format(ACCESS_VID)
ACCESS_BGP_BACK_S = 300


def oper_up(duthost, port):
    return db_hget(duthost, "APPL_DB", "PORT_TABLE:{}".format(port), "oper_status") == "up"


def interface_ips(duthost, port):
    return [k.split("|", 2)[2] for k in db_keys(duthost, "CONFIG_DB", "INTERFACE|{}|*".format(port))]


def interface_fields(duthost, port):
    """The fields of CONFIG_DB INTERFACE|port, or None when the key does not exist."""
    if not db_keys(duthost, "CONFIG_DB", "INTERFACE|{}".format(port)):
        return None
    return redis_hgetall(duthost, "CONFIG_DB", "INTERFACE|{}".format(port))


def peer_end(nbrhosts, nbr):
    """(host, interface) of the neighbor VM's end of a DUT port; nbr is the port's minigraph_neighbors entry."""
    dev = nbrhosts.get(nbr["name"])
    if dev is None:
        pytest.fail("no neighbor host {} to shut the far end of a borrowed port".format(nbr["name"]))
    port = nbr["port"]
    if dev.get("is_multi_vrf_peer", False):
        prefix, num = re.findall(r"(\D+)(\d+)", port)[0]
        port = prefix + str(int(num) + dev["multi_vrf_data"]["intf_offset"])
    return dev["host"], port


def vm_call(fn, iface):
    """fn(iface) on a neighbor host; raise if it reports a failure (some neighbor kinds ignore errors)."""
    res = fn(iface)
    if isinstance(res, dict) and (res.get("failed") or res.get("rc", 0)):
        raise RuntimeError("{}({}) failed: {}".format(getattr(fn, "__name__", fn), iface, res))
    return res


def linked_ptf_indices(duthost, tbinfo, mg):
    """mg's minigraph_ptf_indices without the ports the topology lists as disabled host interfaces of this DUT: those
    have no PTF link, even where the DUT port is up."""
    idx = mg["minigraph_ptf_indices"]
    try:
        dut = str(tbinfo["duts"].index(duthost.hostname))
    except (KeyError, ValueError):
        return dict(idx)
    off = {int(i) for i in tbinfo["topo"].get("ptf_map_disabled", {}).get(dut, {}).values()}
    return {p: i for p, i in idx.items() if int(i) not in off}


@contextlib.contextmanager
def access_ports(duthost, tbinfo, request, need, want):
    """The base VLAN a rig takes its host ports from: SimpleNamespace(mg, base_vlan, members, vlan_members, borrowed).

    members are oper-up untagged members of base_vlan that have PTF links (linked_ptf_indices), at least `need` of
    them; vlan_members is every port that is a host port rather than an uplink.

    t0: the first VLAN with `need` such members (e.g. Vlan1000), its members of that kind; nothing on the DUT
    changes.

    Other topologies (t2, lt2) have no VLAN, and every PTF port faces a neighbor VM, so ports are borrowed: whole
    PortChannels (or routed ports) until there are `want`, never one behind the default route (a t2's T3s, an lt2's
    UT2s), which stays the underlay. For each, the neighbor's end is shut (its LLDP, LACP and BGP would reach every
    port counter the rigs read), the port leaves its PortChannel, loses its addresses and joins a new Vlan1000
    untagged. Exiting undoes all of it in reverse, and waits for the BGP sessions that were up before, whether or not
    the rig or its cases failed. A run killed before its teardown leaves the neighbor ends shut and Vlan1000 behind;
    the next run then fails on Vlan1000.
    """
    mg = duthost.get_extended_minigraph_facts(tbinfo)
    idx = linked_ptf_indices(duthost, tbinfo, mg)
    if tbinfo["topo"]["type"] == "t0":
        for name, v in natsorted(mg["minigraph_vlans"].items()):
            members = [m for m in natsorted(v["members"]) if m in idx and oper_up(duthost, m) and db_hget(
                duthost, "CONFIG_DB", "VLAN_MEMBER|{}|{}".format(name, m), "tagging_mode") == "untagged"]
            if len(members) >= need:
                yield SimpleNamespace(mg=mg, base_vlan=name, members=members, borrowed=[],
                                      vlan_members={m for vl in mg["minigraph_vlans"].values() for m in vl["members"]})
                return
        pytest.skip("no VLAN with {} oper-up untagged members that have PTF ports".format(need))

    if duthost.is_multi_asic or len(tbinfo.get("duts", [])) > 1:
        pytest.skip("access ports are borrowed on single-DUT, single-ASIC testbeds only")
    if db_keys(duthost, "CONFIG_DB", "VLAN|{}".format(ACCESS_VLAN)):
        pytest.fail("{} already exists; a previous run may have left its borrowed access ports".format(ACCESS_VLAN))
    pfx, underlay = route_nexthop_ifaces(duthost, "0.0.0.0/0")
    if pfx != "0.0.0.0/0" or not underlay:
        pytest.fail("no default route to keep as the underlay ({} via {})".format(pfx, underlay))
    lag_of = {}
    for k in db_keys(duthost, "CONFIG_DB", "PORTCHANNEL_MEMBER|*"):
        _t, pc, port = k.split("|", 2)
        lag_of[port] = pc
    keep = set(underlay) | {p for p, pc in lag_of.items() if pc in underlay}
    in_vlan = {k.split("|", 2)[2] for k in db_keys(duthost, "CONFIG_DB", "VLAN_MEMBER|*")}
    subif_parents = {k.split("|", 1)[1].split(".")[0] for k in db_keys(duthost, "CONFIG_DB", "VLAN_SUB_INTERFACE|*")}
    nbrs = mg.get("minigraph_neighbors", {})
    groups = collections.OrderedDict()
    for port in natsorted(idx):
        if port in keep or port in in_vlan or port in subif_parents or port not in nbrs:
            continue
        if db_hget(duthost, "CONFIG_DB", "PORT|{}".format(port), "admin_status") != "up" or \
                db_hget(duthost, "CONFIG_DB", "INTERFACE|{}".format(port), "vrf_name") or not oper_up(duthost, port):
            continue
        groups.setdefault(lag_of.get(port, port), []).append(port)
    borrowed = []
    for ports in groups.values():
        if len(borrowed) >= want:
            break
        borrowed += ports
    if len(borrowed) < need:
        pytest.skip("{} oper-up PTF ports outside the default route's next hops {} ({}); the rig needs {}".format(
            len(borrowed), sorted(underlay), borrowed, need))
    nbrhosts = request.getfixturevalue("nbrhosts")
    ends = {p: peer_end(nbrhosts, nbrs[p]) for p in borrowed}
    bgp_up = established_bgp_peers(duthost)
    logger.info("borrowing access ports %s (PortChannels %s) into %s; underlay %s; BGP up %s", borrowed,
                {p: lag_of.get(p) for p in borrowed}, ACCESS_VLAN, sorted(underlay), bgp_up)

    undo = []
    ips = {}
    try:
        for p in borrowed:
            host, iface = ends[p]
            # registered first: a shutdown that raises may still have been applied, and no config reload undoes it
            undo.append(("{} {} no shutdown".format(nbrs[p]["name"], iface),
                         lambda h=host, i=iface: vm_call(h.no_shutdown, i)))
            vm_call(host.shutdown, iface)
        for p in borrowed:
            if p in lag_of:
                sh(duthost, "sudo config portchannel member del {} {}".format(lag_of[p], p))
                undo.append(("{} back into {}".format(p, lag_of[p]), lambda p=p: sh(
                    duthost, "sudo config portchannel member add {} {}".format(lag_of[p], p))))
        for p in borrowed:
            fields = interface_fields(duthost, p)
            ips[p] = interface_ips(duthost, p)
            for a in ips[p]:
                sh(duthost, "sudo config interface ip remove {} {}".format(p, a))
                undo.append(("{} {} back".format(p, a), lambda p=p, a=a: sh(
                    duthost, "sudo config interface ip add {} {}".format(p, a))))
            if fields is not None:
                if interface_fields(duthost, p) is not None:
                    sh(duthost, "sonic-db-cli CONFIG_DB DEL 'INTERFACE|{}'".format(p))
                undo.append(("INTERFACE|{} back".format(p), lambda p=p, f=fields: [sh(
                    duthost, "sonic-db-cli CONFIG_DB HSET 'INTERFACE|{}' '{}' '{}'".format(p, k, v))
                    for k, v in f.items()]))
        sh(duthost, "sudo config vlan add {}".format(ACCESS_VID))
        undo.append(("{} del".format(ACCESS_VLAN), lambda: sh(duthost, "sudo config vlan del {}".format(ACCESS_VID))))
        for p in borrowed:
            sh(duthost, "sudo config vlan member add -u {} {}".format(ACCESS_VID, p))
            undo.append(("{} out of every VLAN and rig address".format(p), lambda p=p: release_port(duthost, p,
                                                                                                    ips[p])))
        wait_for(60, 2, lambda: all(db_keys(duthost, "APPL_DB", "VLAN_MEMBER_TABLE:{}:{}".format(ACCESS_VLAN, p)) and
                                    oper_up(duthost, p) for p in borrowed),
                 "the borrowed ports {} oper-up in {}".format(borrowed, ACCESS_VLAN))
        time.sleep(5)
    except BaseException:
        restore_access(duthost, undo, bgp_up, report=False)
        raise
    try:
        yield SimpleNamespace(mg=mg, base_vlan=ACCESS_VLAN, members=list(borrowed), borrowed=list(borrowed),
                              vlan_members=set(borrowed))
    finally:
        restore_access(duthost, undo, bgp_up, report=True)


def rif_to_cycle(mg, avoid_ptf_ports, borrowed):
    """A PortChannel router interface with BGP neighbors for a case to remove and re-add: (name, ["addr/len", ...],
    [BGP neighbor, ...]) of the last PortChannel (natural order) with members, none of them borrowed or behind a PTF
    port in avoid_ptf_ports, and a local address of a BGP session. None when there is none."""
    idx = mg["minigraph_ptf_indices"]
    pcs = mg.get("minigraph_portchannels", {})
    for pc in reversed(natsorted(pcs)):
        members = pcs[pc]["members"]
        if not members or set(members) & set(borrowed) or {idx[m] for m in members if m in idx} & set(avoid_ptf_ports):
            continue
        intfs = [i for i in mg.get("minigraph_portchannel_interfaces", []) if i["attachto"] == pc]
        local = {i["addr"].lower() for i in intfs}
        neighbors = [b["addr"] for b in mg.get("minigraph_bgp", []) if b.get("peer_addr", "").lower() in local]
        if neighbors:
            return pc, ["{}/{}".format(i["addr"], i["prefixlen"]) for i in intfs], neighbors
    return None


def release_port(duthost, port, own_ips):
    """Take port out of every VLAN and PortChannel, and off every address it did not have before it was borrowed (a
    rig whose own teardown failed may have left any of them), so it can rejoin its own PortChannel."""
    for k in db_keys(duthost, "CONFIG_DB", "PORTCHANNEL_MEMBER|*|{}".format(port)):
        sh(duthost, "sudo config portchannel member del {} {}".format(k.split("|")[1], port))
    for k in db_keys(duthost, "CONFIG_DB", "VLAN_MEMBER|*|{}".format(port)):
        sh(duthost, "sudo config vlan member del {} {}".format(k.split("|")[1].replace("Vlan", ""), port))
    for a in interface_ips(duthost, port):
        if a not in own_ips:
            sh(duthost, "sudo config interface ip remove {} {}".format(port, a))


def restore_access(duthost, undo, bgp_up, report):
    """Run the undo steps last-first, each one even if an earlier one failed; then wait for bgp_up to be back.

    report=False (the borrowing itself failed): problems are logged, so the original failure stays the verdict.
    """
    errors, interrupted = [], None
    for what, fn in reversed(undo):
        try:
            fn()
        except KeyboardInterrupt as e:  # finish the restore first: the neighbor ends must come back up
            interrupted = e
        except Exception as e:  # every later step still runs
            errors.append("{}: {}".format(what, e))
            logger.error("access port restore, %s: %s", what, e)
    del undo[:]
    if interrupted:
        raise interrupted
    if bgp_up and not wait_until(ACCESS_BGP_BACK_S, 10, 0, lambda: duthost.check_bgp_session_state(bgp_up)):
        try:
            down = sorted(set(bgp_up) - set(established_bgp_peers(duthost)))
        except Exception as e:  # never replace the failure being reported
            down = "unreadable ({})".format(e)
        errors.append("BGP sessions not back after {}s: {}".format(ACCESS_BGP_BACK_S, down))
    if errors:
        if report:
            pytest.fail("access port restore NOT CLEAN: " + " | ".join(errors))
        logger.error("access port restore NOT CLEAN: %s", " | ".join(errors))


# --------------------------------------------------------------------------------------------------------------------


# --------------------------------------------------------------------------------------------------------------------
# ASIC_DB: one snapshot of chosen object types
# --------------------------------------------------------------------------------------------------------------------
# Runs on the DUT host (python3 reads it from stdin): {"objs": {key: attrs} of the ASIC_DB types in argv, "ports" and
# "lags": COUNTERS_DB's name -> oid maps}.
_ASIC_DUMP = """import json
import sys
from swsscommon.swsscommon import SonicV2Connector

db = SonicV2Connector(use_unix_socket_path=True)
out = dict(objs=dict(), ports=dict(), lags=dict())
db.connect("ASIC_DB")
for t in sys.argv[1:]:
    for k in db.keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_" + t + ":*") or []:
        out["objs"][k] = dict(db.get_all("ASIC_DB", k) or dict())
db.connect("COUNTERS_DB")
out["ports"] = dict(db.get_all("COUNTERS_DB", "COUNTERS_PORT_NAME_MAP") or dict())
out["lags"] = dict(db.get_all("COUNTERS_DB", "COUNTERS_LAG_NAME_MAP") or dict())
print(json.dumps(out))
"""
L2_ASIC_TYPES = ("BRIDGE_PORT", "VLAN", "VLAN_MEMBER", "TUNNEL", "FDB_ENTRY")
NULL_OID = "oid:0x0"
FdbEntry = collections.namedtuple("FdbEntry", "fdb_type bp_type port dip endpoint")


class AsicView(object):
    """A snapshot of the ASIC_DB objects of the given types (one DUT round trip), with the lookups the modules need."""

    def __init__(self, duthost, types=L2_ASIC_TYPES):
        out = sh(duthost, "sudo python3 - {} <<'EOF'\n{}EOF".format(" ".join(types), _ASIC_DUMP))
        raw = json.loads(out.strip().splitlines()[-1])
        self.port_names = {oid: name for name, oid in raw["ports"].items()}
        self.lags = raw["lags"]
        self.objs = {t: {} for t in types}
        self.fdb_keys = []
        for key, attrs in raw["objs"].items():
            _, otype, rest = key.split(":", 2)
            t = otype.replace("SAI_OBJECT_TYPE_", "")
            if t == "FDB_ENTRY":
                self.fdb_keys.append((json.loads(rest), attrs))
            else:
                self.objs[t][rest] = attrs

    def attrs(self, otype, oid):
        return self.objs[otype].get(oid, {})

    def vlan_oid(self, vid):
        for oid, a in self.objs["VLAN"].items():
            if a.get("SAI_VLAN_ATTR_VLAN_ID") == str(vid):
                return oid
        return None

    def tunnel_dip(self, bp_attrs):
        """The encap destination of a TUNNEL bridge port's tunnel ('' for none)."""
        return self.attrs("TUNNEL", bp_attrs.get("SAI_BRIDGE_PORT_ATTR_TUNNEL_ID", "")).get(
            "SAI_TUNNEL_ATTR_ENCAP_DST_IP", "")

    def tunnel_bridge_ports(self):
        """{remote VTEP: [(bridge port oid, attrs)]} of the TUNNEL bridge ports (by the tunnel's encap DIP)."""
        out = {}
        for oid, a in self.objs["BRIDGE_PORT"].items():
            if a.get("SAI_BRIDGE_PORT_ATTR_TYPE") == "SAI_BRIDGE_PORT_TYPE_TUNNEL":
                out.setdefault(self.tunnel_dip(a), []).append((oid, a))
        return out

    def flood_members(self):
        """Sorted [(vlan id, remote VTEP)], one per VLAN member on a TUNNEL bridge port.

        This is how orchagent's per-remote-VTEP tunnels hold a VLAN's head-end replication list (no L2MC group). A
        list, not a set, so a remote VTEP that is a member twice shows twice.
        """
        vids = {oid: a.get("SAI_VLAN_ATTR_VLAN_ID", "") for oid, a in self.objs["VLAN"].items()}
        out = []
        for a in self.objs["VLAN_MEMBER"].values():
            bp = self.attrs("BRIDGE_PORT", a.get("SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID", ""))
            vid = vids.get(a.get("SAI_VLAN_MEMBER_ATTR_VLAN_ID"), "")
            if bp.get("SAI_BRIDGE_PORT_ATTR_TYPE") == "SAI_BRIDGE_PORT_TYPE_TUNNEL" and vid.isdigit() and \
                    self.tunnel_dip(bp):
                out.append((int(vid), self.tunnel_dip(bp)))
        return sorted(out)

    def vxlan_tunnels(self):
        """Counter of the VxLAN tunnels by encap destination ('' = the P2MP source tunnel)."""
        return collections.Counter(a.get("SAI_TUNNEL_ATTR_ENCAP_DST_IP", "") for a in self.objs["TUNNEL"].values()
                                   if a.get("SAI_TUNNEL_ATTR_TYPE") == "SAI_TUNNEL_TYPE_VXLAN")

    def fdb_entries(self, mac, vid=None):
        """[(bridge port oid, bridge port attrs, entry attrs)] of the FDB entries for mac (in VLAN vid)."""
        vlan = self.vlan_oid(vid) if vid is not None else None
        if vid is not None and vlan is None:
            return []
        out = []
        for key, a in self.fdb_keys:
            if key.get("mac", "").upper() != mac.upper() or (vlan and key.get("bvid") != vlan):
                continue
            bp = a.get("SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID", "")
            out.append((bp, self.attrs("BRIDGE_PORT", bp), a))
        return out

    def fdb(self, mac, vid=None):
        """[FdbEntry] of mac's FDB entries: bridge port type, and the port name or the tunnel's encap DIP."""
        out = []
        for _bp, bpa, a in self.fdb_entries(mac, vid):
            bp_type = bpa.get("SAI_BRIDGE_PORT_ATTR_TYPE", "")
            port = dip = ""
            if bp_type == "SAI_BRIDGE_PORT_TYPE_TUNNEL":
                dip = self.tunnel_dip(bpa)
            elif bp_type == "SAI_BRIDGE_PORT_TYPE_PORT":
                oid = bpa.get("SAI_BRIDGE_PORT_ATTR_PORT_ID", "")
                port = self.port_names.get(oid, oid)
            out.append(FdbEntry(a.get("SAI_FDB_ENTRY_ATTR_TYPE", ""), bp_type, port, dip,
                                a.get("SAI_FDB_ENTRY_ATTR_ENDPOINT_IP", "")))
        return out


def vxlan_encap_attrs(duthost):
    """The distinct encap settings of the ASIC_DB VxLAN tunnels, as sorted [{attribute: value}] of the TTL, DSCP and
    ECN attributes each carries (an attribute orchagent did not set is absent: the SAI default applies)."""
    seen = set()
    for a in AsicView(duthost, ("TUNNEL",)).objs["TUNNEL"].values():
        if a.get("SAI_TUNNEL_ATTR_TYPE") == "SAI_TUNNEL_TYPE_VXLAN":
            seen.add(tuple(sorted((k.replace("SAI_TUNNEL_ATTR_ENCAP_", ""), v) for k, v in a.items() if k in (
                "SAI_TUNNEL_ATTR_ENCAP_TTL_MODE", "SAI_TUNNEL_ATTR_ENCAP_TTL_VAL", "SAI_TUNNEL_ATTR_ENCAP_DSCP_MODE",
                "SAI_TUNNEL_ATTR_ENCAP_DSCP_VAL", "SAI_TUNNEL_ATTR_ENCAP_ECN_MODE"))))
    return [dict(s) for s in sorted(seen)]


def vxlan_tunnels_to(duthost, ip):
    """How many ASIC_DB VxLAN tunnels have exactly ip as their encap destination."""
    return AsicView(duthost, ("TUNNEL",)).vxlan_tunnels()[ip]


def remote_fdb_dip(duthost, mac, vid):
    """The tunnel DIP of mac's single ASIC FDB entry in VLAN vid, '' if there is none, or 'MULTIPLE'/'NOT_TUNNEL'."""
    entries = AsicView(duthost).fdb(mac, vid)
    if not entries:
        return ""
    if len(entries) > 1:
        return "MULTIPLE"
    return entries[0].dip or "NOT_TUNNEL"


# --------------------------------------------------------------------------------------------------------------------
# DUT side: VxLAN config
# --------------------------------------------------------------------------------------------------------------------
def add_vxlan(duthost, dut_vtep, vlans_vnis):
    """VTEP vtep1 on dut_vtep, EVPN NVO nvo1, and a VNI map per (vlan id, vni), once vxlanmgr has the maps."""
    sh(duthost, "sudo config vxlan add {} {}".format(VTEP_NAME, dut_vtep))
    sh(duthost, "sudo config vxlan evpn_nvo add {} {}".format(NVO_NAME, VTEP_NAME))
    for vid, vni in vlans_vnis:
        sh(duthost, "sudo config vxlan map add {} {} {}".format(VTEP_NAME, vid, vni))
    for vid, vni in vlans_vnis:
        key = "VXLAN_TUNNEL_MAP_TABLE:{}:map_{}_Vlan{}".format(VTEP_NAME, vni, vid)
        wait_for(60, 2, lambda: bool(db_keys(duthost, "APPL_DB", key)), "APPL_DB " + key)


def map_entries_of(duthost, vnis):
    """ASIC_DB tunnel map entries that map any of vnis."""
    view = AsicView(duthost, ("TUNNEL_MAP_ENTRY",))
    vnis = {str(v) for v in vnis}
    return [k for k, a in view.objs["TUNNEL_MAP_ENTRY"].items()
            if a.get("SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY") in vnis or
            a.get("SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE") in vnis]


def remove_vxlan(duthost, vlans_vnis, step=None):
    """Undo add_vxlan in dependency order, each step once orchagent has done the one before: the maps' ASIC_DB tunnel
    map entries go before the NVO and the VTEP do, and the VTEP is gone once ASIC_DB holds no VxLAN tunnel (the
    remote VTEPs must be gone already). Only what CONFIG_DB holds is deleted, so after a failed add the teardown
    reports nothing about objects that were never made. step(what, fn) runs each part (a Steps collector keeps going
    past a failure); without it a failure raises."""
    step = step or (lambda what, fn: fn())

    def has(key):
        return bool(db_keys(duthost, "CONFIG_DB", key))
    for vid, vni in vlans_vnis:
        if has("VXLAN_TUNNEL_MAP|{}|map_{}_Vlan{}".format(VTEP_NAME, vni, vid)):
            step("map del {}".format(vni), lambda v=vid, n=vni: sh(
                duthost, "sudo config vxlan map del {} {} {}".format(VTEP_NAME, v, n)))
    if vlans_vnis:
        vnis = [vni for _vid, vni in vlans_vnis]
        step("maps gone", lambda: wait_for(60, 2, lambda: not map_entries_of(duthost, vnis),
                                           "the ASIC_DB tunnel map entries of VNIs {} to go".format(vnis)))
    if has("VXLAN_EVPN_NVO|{}".format(NVO_NAME)):
        step("nvo del", lambda: sh(duthost, "sudo config vxlan evpn_nvo del {}".format(NVO_NAME)))
    if has("VXLAN_TUNNEL|{}".format(VTEP_NAME)):
        step("vtep del", lambda: sh(duthost, "sudo config vxlan del {}".format(VTEP_NAME)))
    step("vtep gone", lambda: wait_state(
        90, 3, lambda: not AsicView(duthost, ("TUNNEL",)).vxlan_tunnels(), "no VxLAN tunnel left in ASIC_DB",
        lambda: dict(AsicView(duthost, ("TUNNEL",)).vxlan_tunnels())))


# --------------------------------------------------------------------------------------------------------------------
# rig scaffolding
# --------------------------------------------------------------------------------------------------------------------
def make_tagger(prefix):
    """tag(name): prefix + a per-run nonce + name, the payload tag the frame counter looks for. tag.nonce is the
    nonce (an int), for anything else that must not collide with an earlier run."""
    nonce = random.randint(0, 0xffff)

    def tag(name):
        return "{}{:04x}{}".format(prefix, nonce, name)
    tag.nonce = nonce
    return tag


def delivered(n, sent=N):
    """A delivered arm of `sent` frames: at least 9 in 10 of them arrived, and none twice."""
    return sent * 9 // 10 <= n <= sent


def raw_payloads(ptfadapter):
    """Turn off the ptfadapter plugin's payload rewrite (it replaces the Raw payload of every sent UDP frame, and so
    the tag inside an injected VxLAN frame). The adapter is module-scoped like the rigs, so nothing reads the pattern
    after the module and it is not put back."""
    ptfadapter.payload_pattern = ""


@contextlib.contextmanager
def log_clean(request, duthost, phase, ignore=KNOWN_HARMLESS_LOG):
    """LogAnalyzer around a module fixture's setup or teardown phase, which the per-test analyzer does not cover. Off
    when the run disables log analysis (--disable_loganalyzer)."""
    if request.config.getoption("--disable_loganalyzer"):
        yield
        return
    prev = getattr(duthost, "loganalyzer", None)
    la = LogAnalyzer(ansible_host=duthost,
                     marker_prefix="{}_{}".format(request.module.__name__.rsplit(".", 1)[-1], phase))
    la.load_common_config()
    la.ignore_regex.extend(ignore)
    marker = la.init()
    try:
        yield
        la.analyze(marker)
    finally:
        # the LogAnalyzer constructor makes itself duthost.loganalyzer
        duthost.loganalyzer = prev


class Steps(object):
    """Steps that keep going past a failure (a teardown, a `finally` restore): steps(what, fn) runs fn and returns
    its result, or records and logs its failure and returns None; finish() reports every failure at once."""

    def __init__(self, title):
        self.title, self.errors = title, []

    def __call__(self, what, fn):
        try:
            return fn()
        except (Exception, pytest.fail.Exception) as e:
            self.errors.append("{}: {}".format(what, e))
            logger.error("%s: %s failed: %s", self.title, what, e)
            return None

    def finish(self, report=True):
        """pytest.fail with every failed step. report=False (the setup or case already failed): only log them, so
        that failure stays the verdict."""
        if not self.errors:
            return
        msg = "{} NOT CLEAN: {}".format(self.title, " | ".join(self.errors))
        if report:
            pytest.fail(msg)
        logger.error("%s", msg)


def ptf_ports_of(mg, iface):
    """The PTF ports behind a DUT interface (a PortChannel's members, or the port itself)."""
    idx = mg["minigraph_ptf_indices"]
    if iface in mg.get("minigraph_portchannels", {}):
        return [idx[m] for m in natsorted(mg["minigraph_portchannels"][iface]["members"]) if m in idx]
    return [idx[iface]] if iface in idx else []


def loopback0_ipv4(mg):
    lo = [i["addr"] for i in mg["minigraph_lo_interfaces"] if i["name"] == "Loopback0" and ":" not in i["addr"]]
    if not lo:
        pytest.fail("no IPv4 Loopback0 in the minigraph")
    return lo[0]


def underlay_toward(duthost, mg, ip):
    """(prefix, {next-hop interface}, [PTF ports behind them]) of the DUT's route toward remote VTEP ip: VxLAN the
    PTF sends as that VTEP enters on one of those ports. Fails when there is no such route or port."""
    pfx, ifaces = route_nexthop_ifaces(duthost, ip)
    ports = [p for iface in natsorted(ifaces) for p in ptf_ports_of(mg, iface)]
    if not ports:
        pytest.fail("no underlay route with a PTF port toward {} ({} via {})".format(ip, pfx, sorted(ifaces)))
    return pfx, ifaces, ports


VXLAN_STATE = (("CONFIG_DB", "VXLAN_TUNNEL|*"), ("CONFIG_DB", "VXLAN_EVPN_NVO|*"), ("CONFIG_DB", "VXLAN_TUNNEL_MAP|*"),
               ("APPL_DB", "VXLAN_REMOTE_VNI_TABLE:*"), ("APPL_DB", "VXLAN_FDB_TABLE:*"))


def vxlan_state_left(duthost, vlan_names=(), more=()):
    """What a rig leaves if it is not undone: VxLAN config and remote state, the VLANs vlan_names, and each
    (db, key pattern) in more. One '<db> <keys>' string per pattern that has keys."""
    left = []
    for db, pat in VXLAN_STATE + tuple(("CONFIG_DB", "VLAN|" + n) for n in vlan_names) + tuple(more):
        keys = db_keys(duthost, db, pat)
        if keys:
            left.append("{} {}".format(db, keys[:4]))
    return left


def fail_unless_clean(rig, dirty):
    if dirty:
        pytest.fail("DUT is not clean for the {} (a previous run left state?): {}".format(rig, "; ".join(dirty)))


def learn_mac(ptfadapter, duthost, port, iface, vlan_id, mac, tag, vid=None):
    """Have the DUT learn mac on iface in vlan_id: three broadcasts sourced from it on PTF port (802.1Q-tagged vid
    when given), then wait for `show mac`."""
    testutils.send(ptfadapter, port, probe_frame(tag, BROADCAST_MAC, mac, vlan=vid), count=3)
    wait_for(20, 1, lambda: fdb_port(duthost, vlan_id, mac) == iface, "{} learned on {}".format(mac, iface))


def her_counts(copies, dut_vtep, vteps, vni):
    """({remote VTEP: DUT VxLAN copies to it in vni with an untagged inner frame}, every other DUT VxLAN copy)."""
    per = {v: len([c for c in vxlan_to(copies, dut_vtep, v, vni) if c.ivid is None]) for v in vteps}
    return per, len(vxlan_to(copies, dut_vtep)) - sum(per.values())


def unicast_counts(copies, dut_vtep, vtep, vni, mac):
    """(DUT VxLAN copies to vtep in vni with an untagged inner frame to mac, every other DUT VxLAN copy)."""
    good = len([c for c in vxlan_to(copies, dut_vtep, vtep, vni) if c.ivid is None and c.idst == mac])
    return good, len(vxlan_to(copies, dut_vtep)) - good


def vid_reading(copies, dst_port, h0_port, vid, configured):
    """(copies at dst_port tagged vid, problems) for broadcasts tagged vid between two tagged members of it.

    A copy at H0 (an untagged member of another VLAN) is a leak; for a VID that is not configured, any copy
    anywhere is a forward.
    """
    problems = []
    if native_on(copies, h0_port):
        problems.append("{} leaked to H0".format(vid))
    if not configured and copies:
        problems.append("{} forwarded: {}".format(vid, summarize(copies)))
    return native_on(copies, dst_port, vid), problems


# --------------------------------------------------------------------------------------------------------------------
# PTF side: frames
# --------------------------------------------------------------------------------------------------------------------
PROBE_PAYLOAD_LEN = 1086   # 1104 bytes untagged with the FCS: in TX_PROBE's bucket also tagged and encapsulated


def probe_frame(tag, dst, src, vlan=None):
    """An L2 frame with an unassigned ethertype and tag in its PROBE_PAYLOAD_LEN-byte payload; 802.1Q-tagged when vlan
    is given."""
    payload = tag.encode() + b"." * max(0, PROBE_PAYLOAD_LEN - len(tag))
    if vlan is None:
        return packet.Ether(dst=dst, src=src, type=PROBE_ETHERTYPE) / Raw(payload)
    return (packet.Ether(dst=dst, src=src) / packet.Dot1Q(vlan=vlan, type=PROBE_ETHERTYPE) /
            Raw(payload))


def vxlan_frame(inner, outer_dst_mac, outer_src_mac, src_vtep, dst_vtep, vni, ttl=64, tos=0, dport=VXLAN_UDP_PORT):
    """inner encapsulated as a remote VTEP would send it to the DUT; ttl and tos are the outer IPv4 header's."""
    return (packet.Ether(dst=outer_dst_mac, src=outer_src_mac) /
            packet.IP(src=src_vtep, dst=dst_vtep, ttl=ttl, tos=tos, id=0) /
            packet.UDP(sport=45000, dport=dport) /
            packet.VXLAN(vni=vni, flags=0x08) / inner)


FLOW_V4 = ("192.168.77.1", "192.168.77.2")
FLOW_V6 = ("2001:db8:77::1", "2001:db8:77::2")


def flow_frame(tag, dst, src, v6=False, tos=0, ttl=64, ips=None, sport=1111, dport=2222, vlan=None, size=None):
    """An IPv4 (v6: IPv6) UDP frame with tag in its payload: tos is the DSCP/ECN byte, ttl the TTL or hop limit.
    802.1Q-tagged when vlan is given; padded to size bytes (without the tag and the FCS) when size is given."""
    sip, dip = ips or (FLOW_V6 if v6 else FLOW_V4)
    eth = packet.Ether(dst=dst, src=src)
    ip = packet.IPv6(src=sip, dst=dip, tc=tos, hlim=ttl) if v6 else packet.IP(src=sip, dst=dip, tos=tos, ttl=ttl)
    l4 = packet.UDP(sport=sport, dport=dport)
    payload = tag.encode() + b"." * 40
    if size:
        payload += b"." * (size - len(bytes(eth / ip / l4 / Raw(payload))))
    if vlan is not None:
        eth = eth / packet.Dot1Q(vlan=vlan)
    return eth / ip / l4 / Raw(payload)


def inner_tos(frame):
    """The DSCP/ECN byte of an untagged frame's IPv4 or IPv6 header, None for anything else."""
    raw = bytearray(bytes(frame))
    etype = (raw[12] << 8) | raw[13]
    if etype == 0x0800:
        return raw[15]
    if etype == 0x86dd:
        return ((raw[14] & 0x0f) << 4) | (raw[15] >> 4)
    return None


def expect_vxlan(inner_frame, src_vtep, dst_vtep, vni, eth_src):
    """A Mask matching inner_frame encapsulated from src_vtep to dst_vtep, routed out with source MAC eth_src.

    Masked: outer destination MAC (the next hop's), outer IP id/ttl/checksum/flags/TOS, UDP source port and UDP
    checksum; outer_header() reads those for the cases that assert them. Not masked: outer source MAC (the DUT's
    router MAC), outer source and destination address, UDP destination port and the VNI. L2 does not decrement the
    inner TTL.
    """
    outer = testutils.simple_vxlan_packet(
        eth_src=eth_src, eth_dst="00:00:00:00:00:00",
        ip_src=src_vtep, ip_dst=dst_vtep,
        udp_dport=VXLAN_UDP_PORT, vxlan_vni=vni,
        inner_frame=inner_frame)
    mask = Mask(outer)
    mask.set_do_not_care_packet(packet.Ether, "dst")
    mask.set_do_not_care_packet(packet.IP, "id")
    mask.set_do_not_care_packet(packet.IP, "ttl")
    mask.set_do_not_care_packet(packet.IP, "chksum")
    mask.set_do_not_care_packet(packet.IP, "flags")
    mask.set_do_not_care_packet(packet.IP, "tos")
    mask.set_do_not_care_packet(packet.UDP, "sport")
    mask.set_do_not_care_packet(packet.UDP, "chksum")
    return mask


# --------------------------------------------------------------------------------------------------------------------
# PTF side: the per-port counter
# --------------------------------------------------------------------------------------------------------------------
# One observed copy of a tagged probe frame.
#   kind      "native" (plain L2) or "vxlan" (UDP 4789 in IPv4)
#   port      PTF port index it arrived on
#   vid       802.1Q VLAN of the frame itself (native) or None
#   osrc/odst outer IPv4 source/destination (vxlan)
#   vni       VNI (vxlan)
#   ivid      802.1Q VLAN of the inner frame, or None (vxlan)
#   idst      inner destination MAC (vxlan) or destination MAC (native)
Copy = collections.namedtuple("Copy", "kind port vid osrc odst vni ivid idst")


def _mac(b):
    return ":".join("{:02x}".format(x) for x in bytearray(b))


def _ip(b):
    return ".".join(str(x) for x in bytearray(b))


def parse_copy(port, raw, udp_port=VXLAN_UDP_PORT):
    """Decode one captured frame into a Copy; anything that is not IPv4 VxLAN (to udp_port) is a native copy."""
    raw = bytes(raw)
    dst = _mac(raw[0:6])
    etype = int.from_bytes(raw[12:14], "big")
    off, vid = 14, None
    if etype == 0x8100:
        vid = int.from_bytes(raw[14:16], "big") & 0x0fff
        etype = int.from_bytes(raw[16:18], "big")
        off = 18
    if etype == 0x0800 and len(raw) >= off + 20:
        ihl = (bytearray(raw)[off] & 0x0f) * 4
        proto = bytearray(raw)[off + 9]
        udp = off + ihl
        if proto == 17 and len(raw) >= udp + 16 and int.from_bytes(raw[udp + 2:udp + 4], "big") == udp_port:
            vni = int.from_bytes(raw[udp + 12:udp + 15], "big")
            inner = raw[udp + 16:]
            ivid = None
            if len(inner) >= 16 and int.from_bytes(inner[12:14], "big") == 0x8100:
                ivid = int.from_bytes(inner[14:16], "big") & 0x0fff
            return Copy("vxlan", port, vid, _ip(raw[off + 12:off + 16]), _ip(raw[off + 16:off + 20]), vni, ivid,
                        _mac(inner[0:6]))
    return Copy("native", port, vid, None, None, None, None, dst)


# The outer header of one VxLAN copy.
#   ttl dscp ecn        outer IPv4 TTL, DSCP and ECN
#   fragmented          more-fragments set or a fragment offset
#   df                  the don't-fragment flag
#   ip_ok               the IPv4 header checksum verifies and the total length is the frame's
#   sport dport         UDP ports
#   udp_ok              the UDP checksum is zero or verifies, and the UDP length is the frame's
#   flags reserved vni  VXLAN flags byte, its reserved bits (24 + 8, as one integer), VNI
#   inner               the encapsulated frame
Outer = collections.namedtuple(
    "Outer", "ttl dscp ecn fragmented df ip_ok sport dport udp_ok flags reserved vni inner")


def _ones_sum(data):
    data = bytes(data) + b"\x00" * (len(data) % 2)
    s = sum(int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return s


def outer_header(raw):
    """Decode the outer IPv4/UDP/VXLAN header of a frame that parse_copy read as a VxLAN copy."""
    raw = bytes(raw)
    off = 18 if int.from_bytes(raw[12:14], "big") == 0x8100 else 14
    b = bytearray(raw)
    ihl = (b[off] & 0x0f) * 4
    ip, udp = raw[off:off + ihl], off + ihl
    ip_len = int.from_bytes(ip[2:4], "big")
    udp_len = int.from_bytes(raw[udp + 4:udp + 6], "big")
    udp_csum = int.from_bytes(raw[udp + 6:udp + 8], "big")
    pseudo = ip[12:20] + bytes(bytearray([0, 17])) + raw[udp + 4:udp + 6]
    return Outer(
        ttl=b[off + 8], dscp=b[off + 1] >> 2, ecn=b[off + 1] & 3,
        fragmented=bool(int.from_bytes(ip[6:8], "big") & 0x3fff), df=bool(bytearray(ip)[6] & 0x40),
        ip_ok=_ones_sum(ip) == 0xffff and ip_len == len(raw) - off,
        sport=int.from_bytes(raw[udp:udp + 2], "big"), dport=int.from_bytes(raw[udp + 2:udp + 4], "big"),
        udp_ok=udp_len == ip_len - ihl and (udp_csum == 0 or _ones_sum(pseudo + raw[udp:udp + udp_len]) == 0xffff),
        flags=b[udp + 8], reserved=int.from_bytes(raw[udp + 9:udp + 12] + raw[udp + 15:udp + 16], "big"),
        vni=int.from_bytes(raw[udp + 12:udp + 15], "big"), inner=raw[udp + 16:])


SEND_QUIET_S = 1.5          # collect stops once no matching copy arrived for this long
SEND_MAX_WAIT_S = 10.0      # and in any case after this long


def collect(ptfadapter, action, match, quiet=SEND_QUIET_S, max_wait=SEND_MAX_WAIT_S, udp_port=VXLAN_UDP_PORT):
    """Flush the PTF queues, run action(), then return [(Copy, match result)] for every frame on any PTF port for
    which match(frame bytes) is truthy, until none arrived for `quiet` seconds (at most max_wait). udp_port is the
    VxLAN UDP port that parse_copy decodes.

    Frames the PTF itself transmitted are never captured; the DUT's VxLAN copies are told apart by their outer source
    (the DUT's VTEP), which an injected frame never carries.
    """
    ptfadapter.dataplane.flush()
    action()
    found = []
    start = last = time.time()
    while True:
        now = time.time()
        if now - start > max_wait or (now - last > quiet and now - start > quiet):
            break
        res = ptfadapter.dataplane.poll(device_number=0, timeout=0.2)
        if not isinstance(res, ptfadapter.dataplane.PollSuccess):
            continue
        m = match(bytes(res.packet))
        if m:
            last = time.time()
            found.append((parse_copy(res.port, res.packet, udp_port), m))
    return found


def send_and_count(ptfadapter, port, pkt, count, tag, udp_port=VXLAN_UDP_PORT):
    """Send count copies of pkt on port, then return every Copy of tag seen on any PTF port (VxLAN to udp_port)."""
    needle = tag.encode()
    copies = [c for c, _m in collect(ptfadapter, lambda: testutils.send(ptfadapter, port, pkt, count=count),
                                     lambda raw: needle in raw, udp_port=udp_port)]
    logger.info("tag %s: sent %d on ptf %s, captured %d copies: %s", tag, count, port, len(copies),
                summarize(copies))
    return copies


def send_and_read_outer(ptfadapter, port, pkt, count, tag, src_vtep):
    """Send count copies of pkt on port: [(Copy, Outer)] of every VxLAN copy of tag from src_vtep on any PTF port."""
    needle = tag.encode()
    got = collect(ptfadapter, lambda: testutils.send(ptfadapter, port, pkt, count=count),
                  lambda raw: raw if needle in raw else None)
    return [(c, outer_header(raw)) for c, raw in got if c.kind == "vxlan" and c.osrc == src_vtep]


def stream_and_count(ptfadapter, port, pkt, tag, seconds, burst=4, gap=0.05):
    """Send pkt on port in bursts for `seconds`, reading the PTF ports between the bursts (the PTF keeps only the
    last frames of each port, so a long stream cannot be read afterwards). Returns (frames sent, [(seconds since the
    start, Copy, frame bytes)] of every frame on any PTF port that carries tag)."""
    dataplane, needle = ptfadapter.dataplane, tag.encode()
    raw, sent, got = bytes(pkt), 0, []
    dataplane.flush()
    start = time.time()

    def drain(until):
        while True:
            res = dataplane.poll(device_number=0, timeout=max(0.0, min(0.02, until - time.time())))
            if isinstance(res, dataplane.PollSuccess):
                data = bytes(res.packet)
                if needle in data:
                    got.append((time.time() - start, parse_copy(res.port, data), data))
            elif time.time() >= until:
                return

    while time.time() - start < seconds:
        testutils.send(ptfadapter, port, raw, count=burst)
        sent += burst
        drain(time.time() + gap)
    drain(time.time() + SEND_QUIET_S)
    logger.info("tag %s: streamed %d on ptf %s for %ss, captured %d copies: %s", tag, sent, port, seconds, len(got),
                summarize([c for _t, c, _raw in got]))
    return sent, got


def summarize(copies):
    """Human-readable per-port breakdown, for logs and assertion messages."""
    agg = collections.Counter()
    for c in copies:
        if c.kind == "native":
            agg[("native", c.port, "tag={}".format(c.vid) if c.vid is not None else "untagged")] += 1
        else:
            agg[("vxlan", c.port, "{}->{} vni={} inner={}".format(
                c.osrc, c.odst, c.vni, "tag={}".format(c.ivid) if c.ivid is not None else "untagged"))] += 1
    return ", ".join("{}@{} {}: {}".format(k[0], k[1], k[2], n) for k, n in sorted(agg.items(), key=str)) or "none"


def native_on(copies, port, vid="any"):
    """Plain L2 copies on port; vid None = untagged only, an int = that tag only, "any" = either."""
    return sum(1 for c in copies if c.kind == "native" and c.port == port and (vid == "any" or c.vid == vid))


def vxlan_to(copies, src_vtep, dst_vtep=None, vni=None, port=None):
    """VxLAN copies from src_vtep (the DUT's VTEP: what the DUT emitted), optionally only to dst_vtep, in vni, or seen
    on PTF port."""
    return [c for c in copies if c.kind == "vxlan" and c.osrc == src_vtep and (dst_vtep is None or c.odst == dst_vtep)
            and (vni is None or c.vni == vni) and (port is None or c.port == port)]


# --------------------------------------------------------------------------------------------------------------------
# tagged members: read at the PTF, or from the DUT's TX counters where the fanout drops C-tagged DUT frames
#
# The readers take the rig namespace r with: duthost, tagged_hosts (the tagged members a case reads), port ({host:
# PTF port}), canary (a member of the hosts' other VLAN outside the rig, or None) and tagged_at_ptf (probe_tagged_path).
# --------------------------------------------------------------------------------------------------------------------
def tx_delivered(n):
    return GOOD <= n <= N + TX_SLACK


def members_tx(r, fn, hosts=None, live=()):
    """({host: DUT TX packets of probe_frame copies} for what fn() sends, fn's result). fn sends probe_frame frames.

    The hosts' TX is read in the probe's frame-size bucket (tx_probe_stats), which the port's own control traffic
    (LACP, LLDP, the DUT's ARP/ND refresh) does not reach. What else of that size reaches the hosts is subtracted:
    the TX of the canary, a member of the hosts' other VLAN outside the rig, or without one an idle window.
    live: ports whose TX must move by GOOD in the window (the counters poll and count the probe), for readings that
    expect zero on the hosts.
    """
    hosts = list(hosts or r.tagged_hosts)
    extra = [p for p in ([r.canary] if r.canary else []) + list(live) if p not in hosts]
    ports = hosts + extra
    stats = tx_probe_stats(r.duthost, ports)
    raw, took, result = settled_delta(r.duthost, ports, 20, fn, stats, quiet=hosts + ([r.canary] if r.canary else []))
    raw = dict(zip(ports, raw))
    if live and sum(raw[p] for p in live) < GOOD:
        raise AssertionError("the DUT TX counters {} of {} moved by {} for traffic that must leave there: the counters "
                             "do not poll or do not count the probe, so a zero on {} would be vacuous".format(
                                 list(stats), list(live), {p: raw[p] for p in live}, hosts))
    if r.canary:
        background = {h: raw[r.canary] for h in hosts}
    else:
        idle, _, _ = settled_delta(r.duthost, hosts, took + 2, lambda: time.sleep(max(0.0, took - 3)), stats)
        background = dict(zip(hosts, idle))
    tx = {h: max(0, raw[h] - background[h]) for h in hosts}
    logger.info("DUT TX on %s: %s (raw %s, background %s)", hosts, tx, raw, background)
    return tx, result


def capture(r, fn, live=()):
    """(copies, tx): fn() is a send_and_count; tx is None when the PTF sees tagged copies, else the tagged members'
    DUT TX."""
    if r.tagged_at_ptf:
        return fn(), None
    tx, copies = members_tx(r, fn, live=live)
    return copies, tx


def member_flood(r, copies, tx, hosts=None):
    """Copies to tagged members that should get none: the PTF count, or the TX counter excess over TX_SLACK."""
    hosts = hosts or r.tagged_hosts
    if tx is None:
        return sum(native_on(copies, r.port[h]) for h in hosts)
    return sum(max(0, tx[h] - TX_SLACK) for h in hosts)


def member_delivered(r, copies, tx, host):
    """(delivered?, reading) of one copy per frame to a tagged member, by the PTF or by the DUT TX counter."""
    if tx is None:
        n = native_on(copies, r.port[host])
        return delivered(n), n
    return tx_delivered(tx[host]), "DUT TX {}".format(tx[host])


def probe_tagged_path(r, ptfadapter, send_port, vlan_id, t, src):
    """(tagged_at_ptf, why): does the PTF see the C-tagged frames the DUT sends to the tagged members?

    A broadcast sent untagged on send_port in vlan_id before any VNI map is plain VLAN flooding: the DUT must transmit
    it on every tagged member (their TX counters), tagged. Only whether the PTF then sees it depends on the fanout.
    """
    hosts = r.tagged_hosts
    tx, copies = members_tx(r, lambda: send_and_count(
        ptfadapter, send_port, probe_frame(t, BROADCAST_MAC, src), N, t))
    seen = {h: native_on(copies, r.port[h], vlan_id) for h in hosts}
    other = {h: native_on(copies, r.port[h]) - seen[h] for h in hosts}
    state = "DUT TX on the tagged members {}, at the PTF tagged {} / other {} for {} sent".format(tx, seen, other, N)
    if not all(n >= GOOD for n in tx.values()) or any(other.values()):
        pytest.fail("rig: a broadcast in Vlan{} (no VNI map yet) on PTF port {}: {}; plain VLAN flooding is broken, "
                    "so no case can be read. Copies: {}".format(vlan_id, send_port, state, summarize(copies)))
    if any(seen.values()) and not all(delivered(n) for n in seen.values()):
        pytest.fail("rig: the PTF saw only some of the tagged copies ({}): neither the PTF nor the DUT counters can "
                    "be trusted for the tagged members".format(state))
    flush_fdb(r.duthost, "VLAN", str(vlan_id))
    wait_for(20, 1, lambda: fdb_port(r.duthost, vlan_id, src) is None,
             "the probe's MAC flushed from Vlan{}".format(vlan_id))
    if all(delivered(n) for n in seen.values()):
        return True, ""
    why = "{}: the fanout does not carry C-tagged frames from the DUT".format(state)
    logger.warning("tagged members will be read from the DUT TX counters: %s", why)
    return False, why
