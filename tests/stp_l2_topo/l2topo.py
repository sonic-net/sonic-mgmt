# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Driver for the three-bridge l2-topo.

Each node is a SONiC switch reached through a shell callable the caller
supplies. Capture is tcpdump on the port; injection is a raw socket on the
switch. Topology.from_duthosts builds the triangle from the sonic-mgmt topo
file and testbed.

Operational state lives under the `_` prefixed APPL_DB keys, because stpd
writes through a ProducerStateTable with no consumer.

"""
import logging
import shlex
import re
import threading
import time

logger = logging.getLogger(__name__)

PVST = "pvst"
MST = "mst"

# Destination addresses, from sonic-stp stp_pkt.c.
IEEE_BPDU_MAC = "01:80:c2:00:00:00"   # RSTP, MSTP, and PVST on the native VLAN
PVST_BPDU_MAC = "01:00:0c:cc:cc:cd"   # PVST on every other VLAN

# IEEE 802 local experimental ethertype: a probe must not claim to be IPv4,
# because a hardware switch checks the IP header of anything that does and
# drops a frame whose header is nonsense, even when it only has to flood it.
PROBE_ETHERTYPE = "88b5"


def tagged_broadcast(vlan, src_mac, tag=0xDEAD):
    """A broadcast frame on `vlan`, tagged with `tag` so one frame can be told
        from another.
    """
    body = "{:04x}".format(tag) + "00" * 44
    frame = ("ffffffffffff" + src_mac.replace(":", "")
             + "8100" + "{:04x}".format(vlan & 0x0FFF)
             + PROBE_ETHERTYPE + body)
    return frame + "00" * max(0, 60 - len(frame) // 2)


def _parse_bpdu_dump(raw):
    """Decode `tcpdump -v` output into one dict per BPDU.

        Carries the sender's bridge MAC, advertised root path cost and port id.
        For MSTP the CIST internal cost is used: the external cost is legitimately
        0 inside a region.

    """
    out, cur = [], None
    for ln in raw.splitlines():
        if "STP 802.1" in ln:
            cur = {"raw": [ln]}
            out.append(cur)
            m = re.search(r"\b(?:CIST )?bridge-id [0-9a-f]+\.([0-9a-f:]{17})", ln)
            if m:
                cur["bridge_mac"] = m.group(1).lower()
            continue
        if cur is None:
            continue
        cur["raw"].append(ln)
        m = re.search(r"(?<!CIST )bridge-id [0-9a-f]+\.([0-9a-f:]{17})", ln)
        if m and "bridge_mac" not in cur:
            cur["bridge_mac"] = m.group(1).lower()
        m = re.search(r"CIST bridge-id [0-9a-f]+\.([0-9a-f:]{17})", ln)
        if m:
            cur["bridge_mac"] = m.group(1).lower()
        m = re.search(r"CIST int-root-pathcost (\d+)", ln)
        if m:
            cur["root_path_cost"] = int(m.group(1))
        m = re.search(r"(?<!ext-)root-pathcost (\d+)", ln)
        if m and "CIST" not in ln.split("root-pathcost")[0][-20:]:
            cur.setdefault("root_path_cost", int(m.group(1)))
        m = re.search(r"\bport-id ([0-9a-f]{4})\b", ln)
        if m:
            cur["port_id"] = int(m.group(1), 16)
    return out


def capture_many(endpoints, bpf, seconds):
    """Capture on several legs at once and return {label: line count}.

        Every capture starts before any of them ends, so a frame cannot slip past
        while the next tcpdump is attaching. Captures run as background processes
        bounded by `timeout` on the far side. The first two seconds are attach
        time, so callers wait ~2.5s before generating traffic.

    """
    if not endpoints:
        return {}
    lines = []
    for ep in endpoints:
        label, node, port = ep[0], ep[1], ep[2]
        direction = ep[3] if len(ep) > 3 else None
        argv = ["timeout", str(seconds + 2),
                "tcpdump", "-i", port, "-nn", "-e", "-l"]
        if direction:
            # A leg carries the same frame both ways, so direction has to be
            # part of the filter to tell sent from received.
            argv += ["-Q", direction]
        argv.append(bpf)
        path = "/tmp/l2cap.{}".format(re.sub(r"[^A-Za-z0-9_.-]", "_", label))
        lines.append((node, "sudo {} > {} 2>/dev/null &".format(_join(argv), path), label, path))

    # One script per bridge, so every capture on a bridge starts before any of
    # them ends. Ordering across bridges does not matter.
    by_node = {}
    for node, cmd, label, path in lines:
        by_node.setdefault(id(node), (node, [], []))
        by_node[id(node)][1].append(cmd)
        by_node[id(node)][2].append((label, path))

    # The bridges run their scripts at the same time, so every capture in the
    # topology is open during the same window; run one after another and a
    # frame sent during the first bridge's window is gone before the next
    # bridge starts listening.
    scripts = []
    for node, cmds, labs in by_node.values():
        script = "\n".join(cmds) + "\nwait\n"
        for label, path in labs:
            script += "echo '{}{}'\ncat {} 2>/dev/null\nrm -f {}\n".format(
                _CAP_MARK, label, path, path)
        scripts.append((node, script))
    raws = [""] * len(scripts)
    errors = []

    def _run(i, node, script):
        # An exception in a thread would otherwise be printed and lost, and
        # that bridge's captures would silently read as zero.
        try:
            _, out, _ = node.run_argv(["bash", "-lc", script], timeout=seconds + 120)
            raws[i] = out
        except Exception as e:  # noqa: BLE001 - re-raised below
            errors.append((node.name, e))

    threads = [threading.Thread(target=_run, args=(i, node, script))
               for i, (node, script) in enumerate(scripts)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        raise RuntimeError("capture failed on {}".format(
            "; ".join("{}: {!r}".format(name, e) for name, e in errors)))
    out = "\n".join(raws)

    counts, cur = {}, None
    wanted = {ep[0] for ep in endpoints}
    for ln in out.splitlines():
        if ln.startswith(_CAP_MARK):
            cur = ln[len(_CAP_MARK):].strip()
            counts[cur] = 0
        elif cur is not None and ("ethertype" in ln or "802.1Q" in ln):
            counts[cur] += 1
    missing = wanted - set(counts)
    if missing:
        raise RuntimeError("no capture came back for {}".format(sorted(missing)))
    return counts


BLOCKING = "BLOCKING"
LISTENING = "LISTENING"
LEARNING = "LEARNING"
FORWARDING = "FORWARDING"
ROOT_INCONSISTENT = "ROOT-INC"   # PVST names a root-guarded port this; MSTP says DISCARDING


class CommandError(Exception):
    pass


# A leg is named by the two bridges it joins, never by its position in the
# topology file.
LEG_ROLES = {
    frozenset(("t0_1", "t1")): "uplink-a1",   # the switch under test's uplink
    frozenset(("t0_2", "t1")): "uplink-b",    # the other t0's uplink
    frozenset(("t0_1", "t0_2")): "cross",     # the t0 to t0 leg, the one expected to block
}
_CAP_MARK = "===L2CAP "


def _join(argv):
    return " ".join(shlex.quote(str(a)) for a in argv)


def wait_until(timeout, interval, predicate, description=""):
    """Poll `predicate` until it is truthy. Returns the value, or None on timeout."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    logger.debug("wait_until timed out after %ss: %s", timeout, description)
    return last if last else None


def wait_for_value(timeout, interval, producer):
    """Like wait_until but returns (ok, last_seen) so a failure can report what it saw."""
    deadline = time.time() + timeout
    seen = None
    while time.time() < deadline:
        ok, seen = producer()
        if ok:
            return True, seen
        time.sleep(interval)
    return False, seen


def is_blocked(state):
    """Not forwarding and not in transition.

        ROOT-INC counts: PVST spells a root-guarded port that way, MSTP spells it
        DISCARDING.

    """
    return state in (BLOCKING, "DISCARDING", ROOT_INCONSISTENT)


def leg_states(leg, mode, scope):
    """Both ends of a leg, in order, for one tree."""
    (a, _, a_port), (b, _, b_port) = leg.ends()
    return a.port_state(mode, scope, a_port), b.port_state(mode, scope, b_port)


def assert_boundary_legs(topo, odd):
    """Every leg touching `odd` is reported as a boundary at both ends, as the
        daemon publishes it per port; the leg that does not touch it is not.
    """
    for leg in topo.legs:
        want = "yes" if odd in (leg.a, leg.b) else "no"
        for node, _eth, port in leg.ends():
            ok, seen = wait_for_value(120, 3, lambda n=node, p=port: (
                n.mst_boundary(p) == want, n.mst_boundary(p)))
            assert ok, (
                "{}:{} on leg {} reports mst_boundary {!r}, expected {!r}".format(
                    node.name, port, leg.role, seen, want))


def forwarding_legs(topo, mode, scope):
    """Legs that forward at both ends, which are the edges of the tree."""
    return [leg for leg in topo.legs
            if all(s == FORWARDING for s in leg_states(leg, mode, scope))]


def blocked_end(topo, mode, scope):
    """The first (leg, node, eth, port) whose port is blocking, or None."""
    for leg in topo.legs:
        a_state, b_state = leg_states(leg, mode, scope)
        if is_blocked(b_state):
            return leg, leg.b, leg.b_eth, leg.b_port
        if is_blocked(a_state):
            return leg, leg.a, leg.a_eth, leg.a_port
    return None


def entry_point(topo, mode, scope):
    """A (leg, node, eth) to inject on whose receiving end is forwarding. A frame
        injected into a blocked port is dropped at ingress.
    """
    for leg in topo.legs:
        (a, a_eth, a_port), (b, b_eth, b_port) = leg.ends()
        # The sender needs a namespace to inject from; the receiver has to be
        # forwarding for the frame to enter the topology.
        if a.can_capture and b.port_state(mode, scope, b_port) == FORWARDING:
            return leg, a, a_eth
        if b.can_capture and a.port_state(mode, scope, a_port) == FORWARDING:
            return leg, b, b_eth
    return None, None, None


def capture_end(leg):
    """A (node, eth) on this leg that frames can be captured at. Either end sees
        the same wire.
    """
    for node, eth, _port in leg.ends():
        if node.can_capture:
            return node, eth
    return None, None


def all_endpoints(topo):
    """Every capturable leg end, labelled, for a capture of the whole topology.
        Hardware ends have no namespace on this host and are left out.
    """
    eps = []
    for leg in topo.legs:
        for node, eth, _port in leg.ends():
            if node.can_capture:
                eps.append(("{}/{}".format(leg.role, node.name), node, eth))
    return eps


class Node(object):
    """One bridge in the triangle, container or hardware.

        Everything below the plumbing is written against `exec` and `redis`, so
        the protocol cases do not know which they are talking to. Capture and
        injection need a namespace on this host, so the hardware subclass declines
        them.

    """

    kind = "container"

    def __init__(self, name, spec, sh):
        self.name = name
        self.mac = spec["mac"]
        self.ports = spec["ports"]                     # eth<N> -> Ethernet<M>
        self.eths = {v: k for k, v in self.ports.items()}  # Ethernet<M> -> eth<N>
        # How a shell command for this node runs: a (command, timeout) ->
        # (rc, stdout, stderr) callable, backed by the ansible host.
        self._sh = sh
        # Real silicon. Cases that assume the virtual MAC layout stand down.
        self.is_hardware = spec.get("kind") == "hardware"
        # Which `mst instance` grammar this build accepts; learned on first use.
        self._mst_grammar = None
        # Whether stpd runs in its own `stp` container; learned on first use.
        self._stp_in_docker = None

    def run_argv(self, argv, timeout=60, check=False):
        """Run argv where this node's commands belong, as (rc, stdout, stderr).
                Every shell call in this file goes through here, so only the transport
                changes between harnesses.
        """
        rc, out, err = self._sh(_join(argv), timeout)
        if check and rc != 0:
            raise CommandError("{}: {} failed rc={}: {}".format(
                self.name, _join(argv), rc, (err or out).strip()[:400]))
        return rc, (out or "").strip(), (err or "").strip()

    # ------------------------------------------------------------- plumbing
    @staticmethod
    def _sudo(cmd):
        # Config writes, docker and clear commands need root.
        if cmd.startswith(("config ", "docker ", "sonic-clear ")):
            return "sudo " + cmd
        return cmd

    def exec(self, cmd, check=False, timeout=180):
        """Run a command on this bridge. Returns stdout, stripped."""
        _, out, _ = self.run_argv(["bash", "-lc", self._sudo(cmd)],
                                  timeout=timeout, check=check)
        return out

    def exec_rc(self, cmd, timeout=180):
        return self.run_argv(["bash", "-lc", self._sudo(cmd)], timeout=timeout)

    def is_running(self):
        rc, out, _ = self.exec_rc("echo alive")
        return rc == 0 and "alive" in out

    # ------------------------------------------------------- wire and capture
    #
    # A port is a netdev in the switch's own namespace, so capture is tcpdump on
    # the port.

    def link_set(self, port, up):
        self.exec("config interface {} {}".format(
            "startup" if up else "shutdown", port), check=True)

    def link_is_up(self, port):
        """Oper status only. The row also has an Admin column, so a plain match
                on "up" reads an admin up, oper down port as up.
        """
        lines = self.exec("show interfaces status {}".format(port)).splitlines()
        header = next((ln.split() for ln in lines if ln.split()[:1] == ["Interface"]), None)
        row = next((ln.split() for ln in lines if ln.split()[:1] == [port]), None)
        if not header or not row or "Oper" not in header:
            return False
        # Columns are space separated and none of them hold spaces, so the
        # header and the row line up field by field.
        i = header.index("Oper")
        return len(row) > i and row[i] == "up"

    def port_rx_packets(self, port):
        """RX_OK for one port, as an integer. Counters print with separators."""
        out = self.exec("show interfaces counters | grep -w {}".format(port))
        fields = out.split()
        if len(fields) < 3:
            raise CommandError("no counter row for {} on {}: {!r}".format(
                port, self.name, out))
        return int(fields[2].replace(",", ""))

    def clear_counters(self):
        self.exec("sonic-clear counters")

    def capture_bpdus(self, port, seconds=12, count=0):
        """Capture BPDUs on one leg and classify them by destination address.

                Returns {"ieee": n, "pvst": n, "lines": [...]}.

        """
        argv = ["timeout", str(seconds + 2),
                "tcpdump", "-i", port, "-nn", "-e", "-l", "-Q", "inout",
                "ether dst {} or ether dst {}".format(IEEE_BPDU_MAC, PVST_BPDU_MAC)]
        if count:
            argv += ["-c", str(count)]
        else:
            argv += ["-G", str(seconds), "-W", "1"]
        _, out, _ = self.run_argv(["bash", "-lc", "sudo " + _join(argv)],
                                  timeout=seconds + 45)
        lines = [ln for ln in out.splitlines() if "80:c2" in ln or "0c:cc" in ln]
        return {
            "ieee": sum(1 for ln in lines if IEEE_BPDU_MAC in ln.lower()),
            "pvst": sum(1 for ln in lines if PVST_BPDU_MAC in ln.lower()),
            "lines": lines,
        }

    def capture_bpdu_details(self, port, seconds=10, direction="in"):
        """Decode the BPDUs a neighbour sends on this leg. Inbound only by default,
                so every frame seen belongs to the bridge at the far end.
        """
        argv = ["timeout", str(seconds + 2),
                "tcpdump", "-i", port, "-nn", "-v", "-l", "-Q", direction,
                "-G", str(seconds), "-W", "1",
                "ether dst {} or ether dst {}".format(IEEE_BPDU_MAC, PVST_BPDU_MAC)]
        _, raw, _ = self.run_argv(["bash", "-lc", "sudo " + _join(argv)],
                                  timeout=seconds + 45)
        return _parse_bpdu_dump(raw)

    def inject(self, port, frame_hex):
        """Put a raw frame onto a leg."""
        prog = (
            "import socket,sys\n"
            "s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)\n"
            "s.bind((sys.argv[1],0))\n"
            "s.send(bytes.fromhex(sys.argv[2]))\n"
        )
        return self.run_argv(
            ["bash", "-lc", "sudo " + _join(["python3", "-c", prog, port, frame_hex])],
            check=True)

    @property
    def can_capture(self):
        """Every bridge is a switch we can shell into, so every leg end can be
                captured at.
        """
        return True

    def bridge_mac(self):
        """The bridge's own MAC, from the manifest or from DEVICE_METADATA."""
        if self.mac:
            return self.mac.lower()
        m = self.redis(4, "HGET", "DEVICE_METADATA|localhost", "mac")
        return (m or "").lower()

    def redis(self, db, *args):
        quoted = " ".join("'{}'".format(a) for a in args)
        return self.exec("redis-cli -n {} {}".format(db, quoted))

    def hgetall(self, key, db=0):
        out = self.redis(db, "HGETALL", key).splitlines()
        return dict(zip(out[::2], out[1::2]))

    def config_db_ready(self):
        return self.exec("redis-cli -n 4 PING") in ("PONG", "True")

    def stp_available(self):
        """Whether this image can run spanning tree. On a single-container image
                the daemons are supervisord programs rather than an `stp` docker. Both
                stpd and stpmgrd have to be present.
        """
        if self.stp_in_docker():
            rc, _, _ = self.exec_rc("docker image inspect docker-stp >/dev/null")
            return rc == 0
        rc, _, _ = self.exec_rc("test -x /usr/bin/stpd && test -x /usr/bin/stpmgrd")
        return rc == 0

    def stp_in_docker(self):
        """Whether the daemons live in an `stp` container, as on a full SONiC
                image, rather than as supervisord programs on the node itself.
        """
        if self._stp_in_docker is None:
            rc, _, _ = self.exec_rc("test -x /usr/bin/stpd")
            self._stp_in_docker = rc != 0
        return self._stp_in_docker

    def _supervisorctl(self, args):
        if self.stp_in_docker():
            return self.exec("docker exec stp supervisorctl {}".format(args))
        return self.exec("supervisorctl {}".format(args))

    def stp_daemons_running(self):
        out = self._supervisorctl("status stpd stpmgrd 2>/dev/null")
        return out.count("RUNNING") == 2

    def enable_stp_feature(self):
        """Get stpd and stpmgrd running. Try the feature command first, then start
                the supervisord programs directly if it did not take.
        """
        self.exec("config feature state stp enabled")
        wait = 120 if self.stp_in_docker() else 30
        if wait_until(wait, 2, self.stp_daemons_running, "stpd and stpmgrd running"):
            return True
        self._supervisorctl("start stpd stpmgrd")
        return wait_until(60, 2, self.stp_daemons_running, "stpd and stpmgrd running")

    def restart_stp_daemons(self, settle=15):
        """Restart stpd and stpmgrd and wait until they can accept configuration.
                Supervisord reporting RUNNING is not the same as ready: stpmgrd drops
                configuration written before PORT_INIT_DONE, without reporting an error.
        """
        if self.stp_in_docker():
            self.exec("docker restart stp")
            settle = max(settle, 25)
        else:
            self.exec("supervisorctl restart stpd stpmgrd")
        if not wait_until(120, 2, self.stp_daemons_running, "stpd back up"):
            return False
        time.sleep(settle)
        return True

    def config(self, cmd):
        """Run a configuration command and fail loudly on a non-zero exit.
                This CLI can exit 0 having done nothing, but it does report a command
                that does not exist or arguments it rejects.
        """
        rc, out, err = self.exec_rc(cmd)
        if rc != 0:
            raise CommandError("{}: `{}` exited {}: {}".format(
                self.name, cmd, rc, (err or out).strip()[:400]))
        return out

    def apply_mode(self, mode):
        """Select `mode`, clearing whatever was active first. Enabling one mode
                hard-fails while the other is active.
        """
        # The disable fails for whichever mode is not active, so stay tolerant.
        # The enable is the one that has to work.
        self.exec("config spanning-tree disable mst")
        self.exec("config spanning-tree disable pvst")
        self.config("config spanning-tree enable {}".format(mode))
        return wait_until(30, 2,
                          lambda: self.redis(4, "HGET", "STP|GLOBAL", "mode") == mode,
                          "STP|GLOBAL mode -> {}".format(mode))

    def set_mode(self, mode):
        """Select `mode`, then restart the daemon so it starts in it.

                The order matters. A live mode change does not reach stpd, so the
                configuration has to be in place before the restart.

        """
        if not self.apply_mode(mode):
            return False
        return self.restart_stp_daemons()

    def has_operational_state(self, mode, scope):
        """Whether the daemon has published a tree for this scope yet."""
        return bool(self.bridge_data(mode, scope).get("root_port"))

    def msti_supported(self):
        """Whether this build can create an MST instance beyond the CIST.
                Setting a priority is what creates an instance, so that is the
                probe. A VLAN mapping would need a VLAN this topology may not
                have, and the refusal for a missing VLAN reads like a missing
                instance.
        """
        rc, _, _ = self.exec_rc("config spanning-tree mst instance 1 priority 32768")
        if rc != 0:
            return False
        self.mst_delete_instance(1)
        return True

    def mst_delete_instance(self, instance):
        """The CLI verb where the image has it, the CONFIG_DB row otherwise."""
        rc, _, _ = self.exec_rc("config spanning-tree mst instance {} delete".format(instance))
        if rc != 0:
            self.redis(4, "DEL", "STP_MST_INST|{}".format(instance))

    def disable_stp(self):
        self.exec("config spanning-tree disable mst")
        self.exec("config spanning-tree disable pvst")

    @property
    def mode(self):
        return self.redis(4, "HGET", "STP|GLOBAL", "mode")

    @staticmethod
    def bridge_key(mode, scope):
        if mode == MST:
            return "_STP_MST_INST_TABLE:{}".format(scope)
        return "_STP_VLAN_TABLE:Vlan{}".format(scope)

    @staticmethod
    def port_key(mode, scope, port):
        if mode == MST:
            return "_STP_MST_PORT_TABLE:{}:{}".format(scope, port)
        return "_STP_VLAN_PORT_TABLE:Vlan{}:{}".format(scope, port)

    def bridge_data(self, mode, scope):
        return self.hgetall(self.bridge_key(mode, scope))

    def port_data(self, mode, scope, port):
        return self.hgetall(self.port_key(mode, scope, port))

    def port_state(self, mode, scope, port):
        return self.port_data(mode, scope, port).get("port_state", "")

    def port_path_cost(self, mode, scope, port):
        """The port's path cost as the daemon publishes it, or None. Read rather
                than assumed, so teardown restores a real value.
        """
        raw = self.port_data(mode, scope, port).get("path_cost")
        return int(raw) if raw not in (None, "") else None

    def port_role(self, mode, scope, port):
        return self.port_data(mode, scope, port).get("role", "")

    def root_port(self, mode, scope):
        return self.bridge_data(mode, scope).get("root_port", "")

    def root_bridge_id(self, mode, scope):
        """The elected root's bridge id as published: priority and MAC concatenated.
                For PVST the priority carries the VLAN in its system id extension, so
                callers compare on the MAC.
        """
        data = self.bridge_data(mode, scope)
        return data.get("root_bridge_id") or data.get("root_address", "")

    def root_is(self, mode, scope, mac):
        """Whether this bridge has elected the bridge owning `mac` as root."""
        if not mac:
            raise ValueError("root_is needs a MAC to compare against; use bridge_mac()")
        rid = self.root_bridge_id(mode, scope).lower().replace(":", "").replace(".", "")
        return bool(rid) and rid.endswith(mac.lower().replace(":", ""))

    def is_self_root(self, mode, scope):
        """Whether this bridge is the root. The daemon signals it by writing
                root_port as the literal string Root. The address fields cannot be
                compared instead: on MST the priority nibble is zeroed on
                bridge_address but kept on root_address.
        """
        return self.root_port(mode, scope) == "Root"

    def enrol_ports(self, vlans):
        """Materialise per-port STP state. sonic-stp builds a port's operational
                state on a VLAN_MEMBER add, so members predating the mode enable need
                their membership bounced.
        """
        for vid in vlans:
            # The framework reloads config between modules, which drops a VLAN
            # the suite made, so make sure it is there each time.
            if self.redis(4, "EXISTS", "VLAN|Vlan{}".format(vid)) != "1":
                self.config("config vlan add {}".format(vid))
            for port in self.ports.values():
                # Bounce one membership at a time. A bridge with no members has
                # no tree to report, so a full sweep would look unconverged.
                self.exec("config vlan member del {} {}".format(vid, port))
                # Tagged is the default and there is no --tagged flag; passing
                # one would leave the port deleted and never re-added.
                rc, out, err = self.exec_rc(
                    "config vlan member add {} {}".format(vid, port))
                if rc != 0:
                    raise CommandError(
                        "{}: could not add {} to Vlan{}: {}".format(
                            self.name, port, vid, (err or out).strip()))
                # Wait for the re-add to reach APPL_DB. Until it does, fdborch
                # drops learn events while hardware keeps learning. Right after
                # a config reload vlanmgrd can still be catching up and the
                # first write is lost, so re-issue the add once before giving up.

                def in_appl(v=vid, p=port):
                    return self.redis(
                        0, "EXISTS", "VLAN_MEMBER_TABLE:Vlan{}:{}".format(v, p)) == "1"
                if not wait_until(30, 2, in_appl):
                    self.exec("config vlan member del {} {}".format(vid, port))
                    self.exec("config vlan member add {} {}".format(vid, port))
                    if not wait_until(60, 2, in_appl):
                        raise CommandError(
                            "{}: {} never reached APPL_DB as a member of Vlan{}".format(
                                self.name, port, vid))

    def set_bridge_priority(self, mode, scope, priority):
        if mode == MST:
            rc, out, err = self.exec_rc(
                "config spanning-tree mst instance {} priority {}".format(scope, priority))
            if rc == 0:
                return out
            return self.config("config spanning-tree mst instance priority {} {}".format(scope, priority))
        return self.config("config spanning-tree vlan priority {} {}".format(scope, priority))

    def _mst_instance_cmd(self, scope, port, leaf, value):
        """An `mst instance` command, in whichever grammar this build speaks.

                Two forms exist and a build accepts one: id first
                (`mst instance 0 interface Ethernet8 cost 200`) or subcommand first
                (`mst instance interface cost 0 Ethernet8 200`). The id-first form is
                tried first, and the result is cached per node.

        """
        documented = "config spanning-tree mst instance {} interface {} {} {}".format(
            scope, port, leaf, value)
        legacy = "config spanning-tree mst instance interface {} {} {} {}".format(
            leaf, scope, port, value)
        order = ([documented, legacy] if self._mst_grammar != "legacy"
                 else [legacy, documented])
        first_err = None
        for i, cmd in enumerate(order):
            rc, out, err = self.exec_rc(cmd)
            if rc == 0:
                grammar = ("legacy" if cmd is legacy else "documented")
                if self._mst_grammar is None:
                    logger.info("%s speaks the %s mst instance grammar",
                                self.name, grammar)
                self._mst_grammar = grammar
                return out
            if i == 0:
                first_err = (err or out).strip()
        raise CommandError("{}: neither mst instance grammar was accepted for "
                           "{} on {}: {}".format(self.name, leaf, port, first_err[:300]))

    def set_port_cost(self, mode, scope, port, cost):
        if mode == MST:
            return self._mst_instance_cmd(scope, port, "cost", cost)
        return self.config("config spanning-tree vlan interface cost {} {} {}".format(scope, port, cost))

    def set_port_priority(self, mode, scope, port, priority):
        if mode == MST:
            return self._mst_instance_cmd(scope, port, "priority", priority)
        return self.config("config spanning-tree vlan interface priority {} {} {}".format(
            scope, port, priority))

    def set_root_guard(self, port, enable):
        """Set root guard on a port. The daemon reads it as restrictedRole in MSTP
                and as root protect in PVST.
        """
        if enable:
            return self.config("config spanning-tree interface root_guard enable {}".format(port))
        # Some builds register the disable subcommand under the hyphenated
        # group only; try the documented spelling first, then that one.
        rc, out, err = self.exec_rc("config spanning-tree interface root_guard disable {}".format(port))
        if rc == 0:
            return out
        return self.config("config spanning-tree interface root-guard disable {}".format(port))

    def set_region(self, name, revision):
        self.config("config spanning-tree mst region-name {}".format(name))
        self.config("config spanning-tree mst revision {}".format(revision))

    def region_config(self):
        return self.hgetall("STP_MST|GLOBAL", db=4)

    def mst_map_vlan(self, instance, vid):
        # An instance exists once it has a priority; mapping a VLAN to one
        # that does not exist is refused. Both have to be reported, or a
        # refusal on one bridge shows up later as a region disagreement.
        self.config("config spanning-tree mst instance {} priority 32768".format(instance))
        return self.config("config spanning-tree mst instance {} vlan add {}".format(instance, vid))

    def mst_boundary(self, port):
        """Whether the daemon reports this port as an MST region boundary, as
                published on the port's row: "yes", "no", or "" before it is known.
        """
        row = self.hgetall("STP_PORT_TABLE:{}".format(port))
        if not row:
            row = self.hgetall("_STP_PORT_TABLE:{}".format(port))
        return row.get("mst_boundary", "")

    def mst_unmap_vlan(self, instance, vid):
        out = self.exec("config spanning-tree mst instance {} vlan del {}".format(instance, vid))
        self.mst_delete_instance(instance)
        return out

    def stop_stp_daemon(self):
        return self._supervisorctl("stop stpd")

    def start_stp_daemon(self):
        self._supervisorctl("start stpd")
        return wait_until(60, 2, self.stp_daemons_running, "stpd back up")

    def fdb_entries(self, vlan=None):
        out = self.exec("show mac 2>/dev/null")
        rows = []
        for line in out.splitlines():
            m = re.match(r"\s*\d+\s+(\d+)\s+([0-9A-Fa-f:]{17})\s+(\S+)", line)
            if m and (vlan is None or int(m.group(1)) == int(vlan)):
                rows.append({"vlan": int(m.group(1)), "mac": m.group(2), "port": m.group(3)})
        return rows

    def __repr__(self):
        return "<Node {}>".format(self.name)


class Leg(object):
    """One wire between two bridges, with both ends named."""

    def __init__(self, spec, nodes):
        self.role = spec["role"]
        self.a = nodes[spec["a_node"]]
        self.a_eth = spec["a_eth"]
        self.a_port = spec["a_port"]
        self.b = nodes[spec["b_node"]]
        self.b_eth = spec["b_eth"]
        self.b_port = spec["b_port"]

    def ends(self):
        return ((self.a, self.a_eth, self.a_port), (self.b, self.b_eth, self.b_port))

    def set_up(self, up):
        self.a.link_set(self.a_eth, up)

    def __repr__(self):
        return "<Leg {} {}:{} <-> {}:{}>".format(
            self.role, self.a.name, self.a_port, self.b.name, self.b_port)


class Topology(object):
    def __init__(self, manifest, runners=None):
        """`runners` maps a node name to a callable taking (command, timeout) and
                returning (rc, stdout, stderr).
        """
        runners = runners or {}
        self.vlans = manifest["vlans"]
        self.nodes = {n: Node(n, s, sh=runners[n])
                      for n, s in manifest["nodes"].items()}
        self.legs = [Leg(s, self.nodes) for s in manifest["legs"]]
        roles = manifest["roles"]
        self.t1 = self.nodes[roles["t1"]]
        self.t0_1 = self.nodes[roles["t0_1"]]     # the switch under test
        self.t0_2 = self.nodes[roles["t0_2"]]

    @classmethod
    def from_duthosts(cls, duthosts, tbinfo, vlans, runners=None, roles=None):
        """Build the triangle from the sonic-mgmt topology. Each numbered entry in
                `devices_interconnect_interfaces` is one leg, with both ends named as
                `dut.port@ptf`.
        """
        duts = tbinfo["duts"]
        links = tbinfo["topo"]["properties"]["topology"]["devices_interconnect_interfaces"]
        port_name = {}
        for host in duthosts:
            idx = duts.index(host.hostname)
            # Every port, not only the PTF facing ones, since the legs are not.
            mg = host.get_extended_minigraph_facts(tbinfo)
            port_name[idx] = {i: p for p, i in mg["minigraph_port_indices"].items()}

        def resolve(end):
            dut_i, rest = end.split(".", 1)
            port_i = int(rest.split("@", 1)[0])
            dut_i = int(dut_i)
            return duts[dut_i], port_name[dut_i][port_i]

        roles = roles or {"t0_1": duts[0], "t1": duts[1], "t0_2": duts[2]}
        role_of = {name: role for role, name in roles.items()}
        nodes, legs = {}, []
        # Real silicon is told apart by asic_type.
        asic_type = {h.hostname: (h.facts.get("asic_type") or "") for h in duthosts}
        for i, name in enumerate(duts):
            kind = "dut" if asic_type.get(name, "vs") == "vs" else "hardware"
            nodes[name] = {"kind": kind, "mac": "", "ports": {}}
        for order, (_, ends) in enumerate(sorted(links.items(), key=lambda kv: str(kv[0]))):
            (a_node, a_port), (b_node, b_port) = (resolve(e) for e in ends)
            nodes[a_node]["ports"][a_port] = a_port
            nodes[b_node]["ports"][b_port] = b_port
            pair = frozenset((role_of.get(a_node), role_of.get(b_node)))
            role = LEG_ROLES.get(pair, "leg-{}".format(order))
            legs.append({
                "role": role,
                "a_node": a_node, "a_eth": a_port, "a_port": a_port,
                "b_node": b_node, "b_eth": b_port, "b_port": b_port,
            })
        return cls({"vlans": vlans, "nodes": nodes, "legs": legs, "roles": roles},
                   runners=runners)

    def leg(self, role):
        for leg in self.legs:
            if leg.role == role:
                return leg
        raise KeyError(role)

    @property
    def parallel_legs(self):
        """The equal cost pair between the t1 and the switch under test. Empty or
                single on a topology without a pair.
        """
        return [leg for leg in self.legs if leg.role.startswith("uplink-a")]

    @property
    def has_parallel_pair(self):
        return len(self.parallel_legs) == 2

    @property
    def has_hardware(self):
        """Whether a bridge here is real silicon. A hardware bridge has a vendor MAC
                worse than any assigned one, so it blocks an uplink rather than the
                cross leg, and the cases that assume the virtual layout stand down.
        """
        return any(getattr(n, "is_hardware", False) for n in self.all_nodes())

    @property
    def cross_leg(self):
        """The redundant t0 to t0 leg, the one expected to block."""
        return self.leg("cross")

    def all_nodes(self):
        return list(self.nodes.values())

    def set_mode(self, mode, region=None, revision=None):
        """Put every bridge into `mode` and enrol its ports. Configuration is
                re-applied once if no tree appears, since a dropped write is not
                reported.
        """
        scope = 0 if mode == MST else self.vlans[0]

        def _configure(restart):
            for node in self.all_nodes():
                ok = node.set_mode(mode) if restart else node.apply_mode(mode)
                assert ok, "{} did not switch to {}".format(node.name, mode)
                if region:
                    node.set_region(region, revision)
            for node in self.all_nodes():
                node.enrol_ports(self.vlans)

        _configure(restart=True)
        settled = wait_until(60, 3, lambda: all(
            n.has_operational_state(mode, scope) for n in self.all_nodes()),
            "every bridge published a tree")
        if settled:
            return True
        logger.warning("no tree on every bridge after the mode change, re-applying "
                       "the configuration without restarting")
        _configure(restart=False)
        return wait_until(90, 3, lambda: all(
            n.has_operational_state(mode, scope) for n in self.all_nodes()),
            "every bridge published a tree")

    def converge(self, mode, scope, timeout=120, stable_for=3, interval=2):
        """Wait until the tree has stopped moving. A port sits in FORWARDING on its
                way to being blocked, so this requires the whole snapshot to be
                unchanged across consecutive polls rather than just free of transient
                states.
        """
        deadline = time.time() + timeout
        last, stable = None, 0
        while time.time() < deadline:
            snap = self.port_states(mode, scope)
            moving = any(s in (LISTENING, LEARNING, "") for s in snap.values())
            if not moving and snap == last:
                stable += 1
                if stable >= stable_for:
                    return True
            else:
                stable = 0
            last = snap
            time.sleep(interval)
        return False

    def settle_times(self, mode, before, start, timeout=180, stable_for=3, interval=1):
        """Seconds from `start` until each scope in `before` moved away from its
                snapshot and then held still, the same test converge() applies. All
                scopes are polled in one loop, so each figure is its own and not the
                sum of the ones waited on before it. A scope that never settles is
                left out.
        """
        deadline = start + timeout
        last, stable, moved, done = {}, {s: 0 for s in before}, set(), {}
        while len(done) < len(before) and time.time() < deadline:
            for scope in before:
                if scope in done:
                    continue
                snap = self.port_states(mode, scope)
                if snap != before[scope]:
                    moved.add(scope)
                settled = not any(s in (LISTENING, LEARNING, "") for s in snap.values())
                if scope in moved and settled and snap == last.get(scope):
                    stable[scope] += 1
                    if stable[scope] >= stable_for:
                        done[scope] = time.time() - start
                else:
                    stable[scope] = 0
                last[scope] = snap
            time.sleep(interval)
        return done

    def port_states(self, mode, scope):
        """Snapshot of every port on every bridge, for assertion messages."""
        return {
            "{}:{}".format(node.name, port): node.port_state(mode, scope, port)
            for node in self.all_nodes() for port in node.ports.values()
        }
