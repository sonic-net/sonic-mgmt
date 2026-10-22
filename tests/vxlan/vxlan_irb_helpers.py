"""Helpers of tests/vxlan/test_vxlan_irb.py, on top of vxlan_l2_helpers.py.

* PTF side: ARP, IPv6 neighbour discovery and ICMP echo frames, a paced sender, a capture that keeps the raw frames
  (the L2 modules' Copy has no layer 3), and the judgement of routed copies (native or VxLAN, TTL, MACs).
* DUT side: a remote host installed in the kernel the way zebra installs a type-2 route but in an order zebra never
  uses (the neighbour before the MAC), ASIC_DB neighbour / next hop / route readers, and the kernel netdev counters
  that tell a hardware-forwarded stream from one the kernel forwarded.
* Test server side: leaf commands run a few seconds later without waiting for them, so that a control-plane change
  lands while the PTF is sending, and their exit codes read back afterwards.
"""

import collections
import ipaddress
import json
import logging
import socket
import time

import ptf.testutils as testutils
from natsort import natsorted
from scapy.all import (ARP, ICMP, IP, UDP, VXLAN, Ether, ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ND_NA,
                       ICMPv6ND_NS, ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr, IPv6, Raw)

from tests.vxlan.vxlan_l2_helpers import (
    BROADCAST_MAC,
    N,
    VXLAN_UDP_PORT,
    AsicView,
    collect,
    db_keys,
    outer_header,
    parse_copy,
    ptf_ports_of,
    route_nexthop_ifaces,
    sh,
    summarize,
)

logger = logging.getLogger(__name__)

# A stream the kernel forwards moves the netdev counters below by its N frames. The same netdevs also carry the
# switch's own traffic (ARP and ND refresh, MLD, router advertisements: about two packets a second, 9 in one
# stream's window, measured on a t0), so a stream reads as kernel-forwarded only from half its frames up: a counter
# that moved by more than KERNEL_SLACK (19 for the 40 frames of a stream).
KERNEL_SLACK = N // 2 - 1
ZERO_MAC = "00:00:00:00:00:00"


def same_ip(a, b):
    try:
        return ipaddress.ip_address(str(a)) == ipaddress.ip_address(str(b))
    except ValueError:
        return False


def ip_bytes(ip):
    return socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)


def mac_bytes(mac):
    return bytes(bytearray(int(x, 16) for x in mac.split(":")))


# --------------------------------------------------------------------------------------------------------------------
# PTF side: frames
# --------------------------------------------------------------------------------------------------------------------
def solicited_node(ip6):
    """(solicited-node multicast group, its Ethernet group address) of an IPv6 address."""
    x = ipaddress.ip_address(ip6).exploded
    return "ff02::1:ff" + x[-7:], "33:33:ff:" + x[-7:-5] + ":" + x[-4:-2] + ":" + x[-2:]


def resolve_request(v, smac, sip, target, dmac=None):
    """An ARP request (v 4) or neighbour solicitation (v 6) for target from sip (smac): broadcast / solicited-node
    multicast, or unicast to dmac when given."""
    if v == 4:
        arp = ARP(op=1, hwsrc=smac, psrc=sip, hwdst=ZERO_MAC, pdst=target)
        return Ether(dst=dmac or BROADCAST_MAC, src=smac) / arp
    group, gmac = solicited_node(target)
    return (Ether(dst=dmac or gmac, src=smac) / IPv6(src=sip, dst=target if dmac else group, hlim=255) /
            ICMPv6ND_NS(tgt=target) / ICMPv6NDOptSrcLLAddr(lladdr=smac))


def resolve_reply(v, smac, sip, dmac, dip):
    """A unicast ARP reply (v 4) or solicited neighbour advertisement (v 6) for sip (smac) to dip (dmac)."""
    if v == 4:
        return Ether(dst=dmac, src=smac) / ARP(op=2, hwsrc=smac, psrc=sip, hwdst=dmac, pdst=dip)
    return (Ether(dst=dmac, src=smac) / IPv6(src=sip, dst=dip, hlim=255) /
            ICMPv6ND_NA(tgt=sip, R=0, S=1, O=1) / ICMPv6NDOptDstLLAddr(lladdr=smac))


def is_resolve_request(v, frame, target):
    if frame is None:
        return False
    if v == 4:
        return frame.haslayer(ARP) and frame[ARP].op == 1 and frame[ARP].pdst == target
    return frame.haslayer(ICMPv6ND_NS) and same_ip(frame[ICMPv6ND_NS].tgt, target)


def resolve_reply_mac(v, frame, target, to_mac):
    """The MAC a reply to to_mac advertises for target ('' when frame is not such a reply)."""
    if frame is None or frame.dst.lower() != to_mac.lower():
        return ""
    if v == 4:
        if frame.haslayer(ARP) and frame[ARP].op == 2 and frame[ARP].psrc == target:
            return frame[ARP].hwsrc.lower()
        return ""
    if frame.haslayer(ICMPv6ND_NA) and same_ip(frame[ICMPv6ND_NA].tgt, target):
        if frame.haslayer(ICMPv6NDOptDstLLAddr):
            return frame[ICMPv6NDOptDstLLAddr].lladdr.lower()
        return frame.src.lower()
    return ""


def echo_request(v, tag, dmac, smac, sip, dip):
    """An ICMP (v 4) or ICMPv6 (v 6) echo request with tag in its data; the reply carries the same data."""
    data = tag.encode() + b"." * 24
    if v == 4:
        return Ether(dst=dmac, src=smac) / IP(src=sip, dst=dip, ttl=64) / ICMP(type=8, id=0x4952, seq=1) / Raw(data)
    return Ether(dst=dmac, src=smac) / IPv6(src=sip, dst=dip, hlim=64) / ICMPv6EchoRequest(id=0x4952, seq=1, data=data)


def is_echo_reply(v, frame, to_mac):
    if frame is None or frame.dst.lower() != to_mac.lower():
        return False
    return (frame.haslayer(ICMP) and frame[ICMP].type == 0) if v == 4 else frame.haslayer(ICMPv6EchoReply)


def with_trailer(pkt, tag):
    """The frame's bytes with tag after its last header, as Ethernet trailer bytes: an ARP or ND frame has no payload
    to carry a tag, a bridge forwards the trailer untouched, and the frame is then at least 64 bytes long."""
    raw = bytes(pkt)
    return raw + tag.encode() + b"." * max(0, 64 - len(raw) - len(tag))


# --------------------------------------------------------------------------------------------------------------------
# PTF side: send and capture
# --------------------------------------------------------------------------------------------------------------------
def send_paced(ptfadapter, port, pkt, count=N, chunk=8, pause=0.12):
    """Send count copies of pkt in small bursts: control traffic the CPU must answer is policed per second."""
    raw, sent = bytes(pkt), 0
    while sent < count:
        n = min(chunk, count - sent)
        testutils.send(ptfadapter, port, raw, count=n)
        sent += n
        time.sleep(pause)


# One captured frame: PTF port, its bytes, the frame (scapy), and for a VxLAN frame the encapsulated frame (scapy) and
# its exact bytes (else None).
Frame = collections.namedtuple("Frame", "port raw outer inner inner_raw")


def decode(port, raw):
    outer = Ether(raw)
    if outer.haslayer(IP) and outer.haslayer(UDP) and outer[UDP].dport == VXLAN_UDP_PORT and outer.haslayer(VXLAN):
        inner_raw = outer_header(raw).inner
        return Frame(port, raw, outer, Ether(inner_raw), inner_raw)
    return Frame(port, raw, outer, None, None)


def capture_frames(ptfadapter, action, match, quiet=1.5, max_wait=12.0):
    """Flush the PTF queues, run action(), then return a Frame for every frame on any PTF port whose bytes match()
    accepts, until none arrived for `quiet` seconds (at most max_wait)."""
    got = collect(ptfadapter, action, lambda raw: raw if match(raw) else None, quiet=quiet, max_wait=max_wait)
    return [decode(c.port, raw) for c, raw in got]


def describe(frames):
    return summarize([parse_copy(f.port, f.raw) for f in frames])


def from_dut(frame, dut_vtep):
    """A VxLAN frame the DUT encapsulated (an injected frame is never captured, and has another outer source)."""
    return frame.inner is not None and frame.outer[IP].src == dut_vtep


def at_hop(frame, port, omac):
    """The frame left on PTF port `port` with outer destination MAC omac (None: not read). Remote VTEPs that share a
    DUT port are told apart by their next hop's MAC as well as their address."""
    return port in (None, frame.port) and omac in (None, frame.outer.dst.lower())


def encap_to(frame, dut_vtep, vtep, vni, port=None, omac=None):
    """A frame the DUT encapsulated to vtep with vni, toward the next hop (port, omac) (see at_hop)."""
    return (from_dut(frame, dut_vtep) and frame.outer[IP].dst == vtep and frame.outer[VXLAN].vni == vni and
            at_hop(frame, port, omac))


def l3_of(frame):
    if frame is None:
        return None
    if frame.haslayer(IP):
        return frame[IP]
    if frame.haslayer(IPv6):
        return frame[IPv6]
    return None


def hops(l3):
    return l3.ttl if isinstance(l3, IP) else l3.hlim


# Where routed frames must come out.
#   Native: on one of `ports`, destination MAC dmac (None: any, the next hop is a neighbour device), source MAC smac
#   Vxlan:  encapsulated by the DUT to vtep with vni, inner destination MAC dmac, inner source MAC smac, leaving on
#           PTF port `port` with outer destination MAC omac (the VTEP's next hop; None: not read, see at_hop)
# Either way with the TTL / hop limit decremented once.
Native = collections.namedtuple("Native", "ports dmac smac")
Vxlan = collections.namedtuple("Vxlan", "vtep vni dmac smac port omac")
Vxlan.__new__.__defaults__ = (None, None)


def judge_routed(frames, want, dst, dut_vtep, ttl=63):
    """(good, wrong, elsewhere) for the copies of one routed stream to dst: copies as `want` describes, descriptions
    of the copies in the right place with a wrong header, and the number of copies anywhere else."""
    good, wrong, elsewhere = 0, [], 0
    for f in frames:
        if isinstance(want, Native):
            l3 = l3_of(f.outer)
            if f.inner is not None or f.port not in want.ports or l3 is None or not same_ip(l3.dst, dst):
                elsewhere += 1
            elif hops(l3) == ttl and f.outer.src.lower() == want.smac and want.dmac in (None, f.outer.dst.lower()):
                good += 1
            else:
                wrong.append("ptf {} {}->{} ttl {}".format(f.port, f.outer.src, f.outer.dst, hops(l3)))
        else:
            l3 = l3_of(f.inner)
            if not from_dut(f, dut_vtep):
                elsewhere += 1
            elif (encap_to(f, dut_vtep, want.vtep, want.vni, want.port, want.omac) and
                  f.inner.dst.lower() == want.dmac and f.inner.src.lower() == want.smac and l3 is not None and
                  same_ip(l3.dst, dst) and hops(l3) == ttl):
                good += 1
            else:
                wrong.append("ptf {} to {} ({}) vni {} inner {}->{} ttl {}".format(
                    f.port, f.outer[IP].dst, f.outer.dst, f.outer[VXLAN].vni, f.inner.src, f.inner.dst,
                    hops(l3) if l3 is not None else "-"))
    return good, wrong, elsewhere


def want_text(want):
    if isinstance(want, Native):
        return "native on ptf {} to {} from {}".format(want.ports, want.dmac or "the next hop", want.smac)
    return "VxLAN to {} vni {} inner {} from {}{}".format(
        want.vtep, want.vni, want.dmac, want.smac,
        "" if want.port is None else " on ptf {} to next hop {}".format(want.port, want.omac))


# --------------------------------------------------------------------------------------------------------------------
# DUT side: kernel netdev counters
# --------------------------------------------------------------------------------------------------------------------
def kernel_counters(duthost, devs):
    """{netdev: (rx_packets, tx_packets)} in one DUT command."""
    out = sh(duthost, "for d in {}; do echo $d $(cat /sys/class/net/$d/statistics/rx_packets 2>/dev/null || echo x) "
                      "$(cat /sys/class/net/$d/statistics/tx_packets 2>/dev/null || echo x); done".format(
                          " ".join(devs)))
    k = {}
    for line in out.splitlines():
        t = line.split()
        if len(t) == 3 and t[1].isdigit() and t[2].isdigit():
            k[t[0]] = (int(t[1]), int(t[2]))
    missing = [d for d in devs if d not in k]
    if missing:
        raise AssertionError("kernel counters of {} unreadable: a kernel-forwarded stream could not be told from a "
                             "hardware one".format(missing))
    return k


def kernel_delta(k0, k1):
    return {d: (k1[d][0] - k0[d][0], k1[d][1] - k0[d][1]) for d in k1 if d in k0}


def kernel_forwarded(kd, flat_tx=(), flat_rx=(), ingress=None, sent=N):
    """'' when the kernel did not forward a stream of `sent` frames, else what shows that it did.

    The kernel netdevs count only what the CPU sends and receives. flat_tx: netdevs the kernel would transmit the
    stream on (the VLAN and VxLAN netdevs, a host port); flat_rx: netdevs it would receive it on after its own
    decapsulation (the VxLAN netdevs); ingress: the port the frames entered on, whose RX counter also carries that
    port's protocol traffic, so it reads as a CPU path only from half the stream up. When ingress is given and
    stayed under half the stream, the result is '' whatever flat_tx and flat_rx read.
    """
    why = []
    tx = {d: kd[d][1] for d in flat_tx if kd[d][1] > KERNEL_SLACK}
    rx = {d: kd[d][0] for d in flat_rx if kd[d][0] > KERNEL_SLACK}
    if tx:
        why.append("kernel TX {}".format(tx))
    if rx:
        why.append("kernel RX {}".format(rx))
    if ingress and kd[ingress][0] >= sent // 2:
        why.append("{} frames reached the CPU on {}".format(kd[ingress][0], ingress))
    elif ingress:
        # The kernel cannot forward frames it did not receive: with the ingress port's CPU counter under half the
        # stream, a burst on the other netdevs is the switch's own traffic (one neighbour refresh pass sends an ARP
        # or ND probe per neighbour of the VLAN, twice when unanswered, and the bridge floods each to every VTEP).
        return ""
    return "; ".join(why)


# --------------------------------------------------------------------------------------------------------------------
# DUT side: ASIC_DB and routes
# --------------------------------------------------------------------------------------------------------------------
def asic_l3(duthost, ips):
    """{ip: (the ASIC_DB neighbour entry's MAC or None, whether ASIC_DB has an IP next hop for it)}, one snapshot."""
    view = AsicView(duthost, ("NEIGHBOR_ENTRY", "NEXT_HOP"))
    out = {}
    for ip in ips:
        mac = None
        for key, attrs in view.objs["NEIGHBOR_ENTRY"].items():
            if same_ip(json.loads(key).get("ip", ""), ip):
                mac = attrs.get("SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS", "").lower()
        nh = any(a.get("SAI_NEXT_HOP_ATTR_TYPE") == "SAI_NEXT_HOP_TYPE_IP" and
                 same_ip(a.get("SAI_NEXT_HOP_ATTR_IP", ""), ip) for a in view.objs["NEXT_HOP"].values())
        out[ip] = (mac, nh)
    return out


def asic_route(duthost, prefix):
    return bool(db_keys(duthost, "ASIC_DB", 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:*"dest":"{}"*'.format(prefix)))


def route_ports(duthost, mg, ip):
    """Sorted PTF ports behind the next hops of the selected FRR route (default VRF) that covers ip; [] if none."""
    return sorted({p for i in natsorted(route_nexthop_ifaces(duthost, ip)[1]) for p in ptf_ports_of(mg, i)})


# --------------------------------------------------------------------------------------------------------------------
# DUT side: neighbours, and a remote host installed in the kernel as zebra installs a type-2 route
# --------------------------------------------------------------------------------------------------------------------
def _fam(ip):
    return "-6 " if ":" in ip else ""


def kernel_neigh(duthost, ip, dev):
    return sh(duthost, "ip {}neigh show {} dev {} 2>/dev/null; true".format(_fam(ip), ip, dev)).strip()


def neigh_resolved(line, mac):
    return mac.lower() in line.lower() and "FAILED" not in line and "INCOMPLETE" not in line


def remote_neigh_cmd(ip, mac, dev):
    """The neighbour of a type-2 MAC/IP route: externally learned, never probed."""
    return "sudo ip {}neigh replace {} lladdr {} dev {} nud noarp extern_learn".format(_fam(ip), ip, mac, dev)


def local_neigh_cmd(ip, mac, dev):
    return "sudo ip {}neigh replace {} lladdr {} dev {} nud permanent".format(_fam(ip), ip, mac, dev)


def neigh_del_cmd(ip, dev):
    return "sudo ip {}neigh del {} dev {} 2>/dev/null; true".format(_fam(ip), ip, dev)


def remote_mac_cmd(kvx, mac, vtep, vid):
    """The FDB entries of a type-2 MAC route on the VNI's kernel VxLAN netdev kvx."""
    return ("sudo bridge fdb replace {m} dev {k} dst {t} self static && "
            "{{ sudo bridge fdb replace {m} dev {k} master static vlan {v} 2>/dev/null; true; }}".format(
                m=mac, k=kvx, t=vtep, v=vid))


def remote_mac_del_cmd(kvx, mac, vid):
    return ("sudo bridge fdb del {m} dev {k} self 2>/dev/null; "
            "sudo bridge fdb del {m} dev {k} master vlan {v} 2>/dev/null; true".format(m=mac, k=kvx, v=vid))


# --------------------------------------------------------------------------------------------------------------------
# test server side
# --------------------------------------------------------------------------------------------------------------------
def leaf_later(lv, delay, commands):
    """Run each leaf script command (a list of arguments) in order on the test server `delay` seconds from now,
    without waiting for them (vxlan_evpn_l2_helpers.Leaves.run waits); a failing command does not stop the next.
    Each command's output and exit code go to a file; leaf_later_result(lv, job) reads them."""
    base = "{}.later{}".format(lv.script, int(time.time() * 1000))
    job = collections.namedtuple("LeafJob", "script out")(base + ".sh", base + ".out")
    lines = ["sleep {}".format(delay)]
    for args in commands:
        cmd = "bash {} {} {}".format(lv.script, lv.env_file, " ".join(str(a) for a in args))
        lines.append("{c} >>{o} 2>&1; echo \"RC $? {c}\" >>{o}".format(c=cmd, o=job.out))
    lines.append("echo DONE >>{}".format(job.out))
    lv.vmhost.copy(content="\n".join(lines) + "\n", dest=job.script)
    res = lv.vmhost.shell("sudo sh -c 'rm -f {o}; nohup sh {s} </dev/null >/dev/null 2>&1 &'".format(
        o=job.out, s=job.script), module_ignore_errors=True)
    if res["rc"] != 0:
        raise RuntimeError("test server: could not start {}: {}".format(job.script, res.get("stderr", "")))
    return job


def leaf_later_result(lv, job, timeout=60):
    """Wait for a leaf_later job to finish; raise unless every command of it exited 0."""
    end, out = time.time() + timeout, ""
    while True:
        out = lv.vmhost.shell("cat {} 2>/dev/null; true".format(job.out), module_ignore_errors=True).get("stdout", "")
        if "DONE" in out.splitlines() or time.time() > end:
            break
        time.sleep(1)
    lv.vmhost.shell("sudo rm -f {} {}".format(job.out, job.script), module_ignore_errors=True)
    if "DONE" not in out.splitlines():
        raise AssertionError("leaf commands did not finish in {} s: {}".format(timeout, out))
    failed = [ln for ln in out.splitlines() if ln.startswith("RC ") and ln.split()[1] != "0"]
    if failed:
        raise AssertionError("leaf commands failed: {}. Output: {}".format(failed, out))
