#!/usr/bin/env python3
"""Multi-route TX/RX probe for cold reboot convergence.

Sends one UDP probe per static route from the PTF TX port and timestamps every
packet the DUT forwards back out the RX PortChannel members. The destination IP
identifies which route forwarded it, so the log shows which routes are
programmed at any moment. Routes that are not programmed hit the /16 blackhole
and never arrive.

RX log line format (test host UTC time):
  2026-07-01 12:00:00.123456 route=47

Usage (inside the ptf container):
  python3 ptf_traffic_test.py --out /tmp/ptf_rx.log --num-routes 100 --base-net 172.16
"""

import sys
import time
import signal
import argparse
from datetime import datetime, timezone

try:
    from scapy.all import AsyncSniffer, sendp, Ether, IP, UDP, Raw
except ImportError:
    print("ERROR: scapy not installed")
    sys.exit(1)

# Defaults - all overridable from the CLI, so the caller stays the source of
# truth for the actual testbed values.
DUT_VLAN_MAC = '6c:4e:f6:41:67:fc'   # DUT system MAC (all L3 PortChannels share it)
TX_IFACE = 'eth4'                # PTF port facing the DUT TX interface
RX_IFACES = ['eth0', 'eth1']      # PTF ports on the RX PortChannel members
DPORT = 5000
SRC_MAC = '00:11:22:33:44:55'
SRC_IP = '192.168.0.2'
SWEEP_DELAY = 0.5                   # seconds between full sweeps of all routes
MAGIC = b'\xca\xfe\xba\xbe'   # marks our packets

# Global state
rx_log_fh = None
base_net = '172.16'                 # set from --base-net in main()


def rx_callback(pkt):
    """Log every DUT-forwarded probe with the route it came from (by dst IP)."""
    if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
        return
    dst = pkt[IP].dst                         # preserved through routing: 172.16.<route>.1
    octets = dst.split('.')
    if len(octets) != 4:
        return
    if '{}.{}'.format(octets[0], octets[1]) != base_net:
        return
    route = octets[2]
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')
    rx_log_fh.write('{} route={}\n'.format(ts, route))


def _read_entries(path):
    """Return sorted list of (datetime, route_int_or_None) from an RX log."""
    entries = []
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                ts_str = parts[0] + ' ' + parts[1]
                dt = None
                for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S'):
                    try:
                        dt = datetime.strptime(ts_str, fmt)
                        break
                    except ValueError:
                        pass  # timestamp is in the other format - try it next
                if dt is None:
                    continue
                route = None
                for tok in parts[2:]:
                    if tok.startswith('route='):
                        try:
                            route = int(tok.split('=', 1)[1])
                        except ValueError:
                            route = None
                entries.append((dt, route))
    except IOError as e:
        print('ERROR reading {}: {}'.format(path, e))
    entries.sort(key=lambda e: e[0])
    return entries


def analyze_log(path, num_routes, tx_sweeps):
    """Print an aggregate blackout summary (parse script does per-route detail)."""
    entries = _read_entries(path)
    distinct = set(r for _, r in entries if r is not None)
    print('PTF TX sweeps  : {} ({} probes/sweep)'.format(tx_sweeps, num_routes))
    print('PTF RX packets : {}  ({} distinct routes seen)'.format(len(entries), len(distinct)))

    if len(entries) < 2:
        print('PTF: not enough RX packets to find blackout')
        return

    times = [e[0] for e in entries]
    max_gap, gap_idx = 0.0, 1
    for i in range(1, len(times)):
        g = (times[i] - times[i - 1]).total_seconds()
        if g > max_gap:
            max_gap, gap_idx = g, i

    print('Blackout start : {}'.format(times[gap_idx - 1].strftime('%Y-%m-%d %H:%M:%S.%f')))
    print('Blackout end   : {}'.format(times[gap_idx].strftime('%Y-%m-%d %H:%M:%S.%f')))
    print('Blackout time  : {:.1f}s'.format(max_gap))

    missing = set(range(num_routes)) - distinct
    if missing:
        sample = sorted(missing)[:20]
        print('Routes never seen ({}): {}{}'.format(
            len(missing), sample, ' ...' if len(missing) > 20 else ''))


def main():
    global rx_log_fh, base_net

    ap = argparse.ArgumentParser(description="PTF multi-route traffic probe")
    ap.add_argument('out', nargs='?', default='/tmp/ptf_rx.log',
                    help='RX log output path (default: /tmp/ptf_rx.log)')
    ap.add_argument('--out', dest='out_opt', default=None, help='RX log output path (alt form)')
    ap.add_argument('--num-routes', type=int, default=100, help='Number of routes to probe')
    ap.add_argument('--base-net', default='172.16', help='First two octets of test prefixes')
    ap.add_argument('--tx-iface', default=TX_IFACE, help='TX interface (facing DUT Vlan)')
    ap.add_argument('--rx-ifaces', default=','.join(RX_IFACES),
                    help='Comma-separated RX interfaces (PortChannel members)')
    ap.add_argument('--dut-mac', default=DUT_VLAN_MAC, help='DUT Vlan interface MAC')
    args = ap.parse_args()

    out_file = args.out_opt or args.out
    base_net = args.base_net
    rx_ifaces = [i.strip() for i in args.rx_ifaces.split(',') if i.strip()]

    # 'with' guarantees the log is closed even if the sniffer fails to start
    with open(out_file, 'w', buffering=1) as rx_log_fh:  # line-buffered for live writes
        stop = [False]
        signal.signal(signal.SIGINT, lambda s, f: stop.__setitem__(0, True))
        signal.signal(signal.SIGTERM, lambda s, f: stop.__setitem__(0, True))

        # Build the probe packets once (they never change) for fast bursts
        pkts = []
        for i in range(args.num_routes):
            dst_ip = '{}.{}.1'.format(base_net, i)
            pkts.append(Ether(dst=args.dut_mac, src=SRC_MAC) /
                        IP(src=SRC_IP, dst=dst_ip) /
                        UDP(sport=1234, dport=DPORT) /
                        Raw(load=MAGIC))

        sniffer = AsyncSniffer(iface=rx_ifaces, filter='udp port {}'.format(DPORT), prn=rx_callback)
        sniffer.start()

        print('PTF probe: TX={} -> DUT -> RX={} | {} routes {}.0.0/24..{}.{}.0/24 -> {}'.format(
            args.tx_iface, rx_ifaces, args.num_routes, base_net, base_net,
            args.num_routes - 1, out_file), flush=True)

        sweeps = 0
        try:
            while not stop[0]:
                sendp(pkts, iface=args.tx_iface, verbose=0)   # one sweep = all routes
                sweeps += 1
                time.sleep(SWEEP_DELAY)
        finally:
            sniffer.stop()
    print('PTF probe stopped.', flush=True)
    analyze_log(out_file, args.num_routes, sweeps)


if __name__ == '__main__':
    main()
