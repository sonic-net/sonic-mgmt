#!/usr/bin/env python3
"""Cold reboot timing analyzer.

Correlates syslog, the serial console log and the PTF RX log onto a single
timeline and reports how long each recovery milestone took relative to the
reboot trigger. BIOS/GRUB markers exist only on the console, so the console log
must be captured from before the reboot is triggered.

Usage:
    python3 reboot_timing_parser.py --syslog syslog
    python3 reboot_timing_parser.py --syslog syslog --console-log console.log
    python3 reboot_timing_parser.py --syslog syslog --console-log console.log \\
        --ptf-log ptf_rx.log --console-offset <seconds>
"""

import re
import sys
import json
import argparse
from datetime import datetime, timedelta


# Timestamp parsers

# syslog format 1: 2026 Jun  2 19:21:03.123456 hostname ...
SYSLOG_TS_PAT1 = re.compile(r'^(\d{4} \w+\s+\d+ \d{2}:\d{2}:\d{2}\.\d+)')

# syslog format 2 (ISO8601): 2026-06-02T19:21:03.123456+00:00 hostname ...
SYSLOG_TS_PAT2 = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)\+\d{2}:\d{2}')


def parse_syslog_ts(line):
    m = SYSLOG_TS_PAT1.match(line)
    if m:
        try:
            return datetime.strptime(m.group(1).strip(), "%Y %b %d %H:%M:%S.%f")
        except ValueError:
            pass  # not this syslog timestamp format - try the next one
    m = SYSLOG_TS_PAT2.match(line)
    if m:
        try:
            return datetime.strptime(m.group(1).strip(), "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            pass  # unparsable timestamp - caller treats the line as untimed
    return None


# Config DB loader

def load_interfaces(config_db_path):
    """Return (admin-up portchannels, PortChannel member ports, Vlan member ports)."""
    portchannels = set()
    pc_members = set()
    vlan_members = set()

    try:
        with open(config_db_path) as f:
            db = json.load(f)
    except (IOError, ValueError) as e:
        print("[WARN] Could not load config_db: {}".format(e))
        return portchannels, pc_members, vlan_members

    # Admin-up PortChannels
    for key, val in db.get('PORTCHANNEL', {}).items():
        if val.get('admin_status', 'up') == 'up':
            portchannels.add(key)

    # Admin-up individual Ethernet ports (from PORT table)
    admin_up_ports = set()
    for key, val in db.get('PORT', {}).items():
        if val.get('admin_status', 'up') == 'up':
            admin_up_ports.add(key)

    # PortChannel members (only admin-up ports in admin-up PCs)
    for key in db.get('PORTCHANNEL_MEMBER', {}).keys():
        # key format: "PortChannel101|Ethernet0"
        parts = key.split('|')
        if len(parts) == 2 and parts[0] in portchannels and parts[1] in admin_up_ports:
            pc_members.add(parts[1])

    # Vlan members (server-facing, only admin-up ports)
    for key in db.get('VLAN_MEMBER', {}).keys():
        parts = key.split('|')
        if len(parts) == 2 and parts[1] in admin_up_ports:
            vlan_members.add(parts[1])

    print("[INFO] PortChannels      : {}".format(', '.join(sorted(portchannels))))
    print("[INFO] PC member ports   : {}".format(', '.join(sorted(pc_members))))
    print("[INFO] Vlan member ports : {}".format(', '.join(sorted(vlan_members))))
    print()
    return portchannels, pc_members, vlan_members


# Printed in this order so the most useful comparison keys come first.
DUT_INFO_FIELDS = [
    ('hostname',       'DUT'),
    ('image_version',  'Image'),
    ('sonic_release',  'Release'),
    ('kernel_version', 'Kernel'),
    ('platform',       'Platform'),
    ('hwsku',          'HwSKU'),
    ('platform_asic',  'ASIC'),
    ('num_asic',       'ASIC count'),
    ('topology',       'Topology'),
    ('topology_type',  'Topology type'),
    ('num_containers', 'Containers'),
]


def print_dut_info(path):
    """Print the DUT / image context block from a JSON file, if provided.

    Best-effort: a missing or unreadable file just skips the block.
    """
    if not path:
        return
    try:
        with open(path) as fh:
            info = json.load(fh)
    except (IOError, ValueError) as err:
        print("[WARN] Could not read DUT info from {}: {}".format(path, err))
        return
    if not info:
        return

    print("  DUT / IMAGE INFO")
    print("  " + "-" * 60)
    for key, label in DUT_INFO_FIELDS:
        if info.get(key):
            print("  {:<16}: {}".format(label, info[key]))
    if info.get('containers'):
        names = [n for n in info['containers'].split(',') if n]
        # Wrapped: the list is long and the point is to diff it between runs.
        for i in range(0, len(names), 6):
            label = 'Container list' if i == 0 else ''
            print("  {:<16}: {}".format(label, ', '.join(names[i:i + 6])))
    print()


# Syslog markers (name, regex pattern) - in expected boot order
SYSLOG_MARKERS = [
    # --- shutdown phase ---
    ("Reboot fired",                r'User requested rebooting device'),
    ("Shutdown initiated",          r'Initiate shutdown|systemd.*Reached target.*[Ss]hutdown'),

    # --- boot phase ---
    ("Kernel boot",                 r'kernel:.*Linux version'),
    ("SONiC starting up",           r'SONiC version.*starting up'),
    ("platform topology started",   r'Starting platform-topology\.service'),
    # The same bootstrap scripts log different progress lines per platform, so
    # each NPU marker also carries the G200 wording.
    ("NPU power on",                r'pz\.bootstrap.*Powering on NPU|pz\.bootstrap.*NPU powered on successfully'
                                    r'|npu-bootstrap:_power_npu'),
    ("NPU ready",                   r'npu-bootstrap.*NPU Initialization Success|NPU fsm complete'),
    ("platform topology ready",     r'Finished platform-topology\.service'),
    ("syncd started",               r'Started syncd service|Started syncd\.service'),
    ("bgp started",                 r'Started bgp service|Started bgp\.service'),
    ("lldp started",                r'Started lldp service|Started lldp\.service'),
    ("systemd multi-user target",   r'Reached target.*Multi-User'),
]

# PortChannel markers are tracked separately (first and last UP)

# Plane groupings: maps plane name -> list of marker names that belong to it.
# Plane convergence time = timestamp of the LAST marker in that group.
PLANE_GROUPS = [
    ("Management plane", [
        "Kernel boot",
        "systemd multi-user target",
    ]),
    ("Control plane", [
        "syncd started",
        "bgp started",
        "lldp started",
    ]),
    ("Data (Forwarding) plane", [
        "First port UP",
        "Last port UP",
        "First PortChannel UP",
        "Last PortChannel UP",
    ]),
    ("Traffic plane (static routes)", [
        "Traffic blackout start",
        "Traffic blackout end",
        "All static routes programmed",
    ]),
]


# Helpers

GREEN = '\033[1;92m'
RED = '\033[91m'
RESET = '\033[0m'


def colored(text):
    if text == 'PASS':
        return GREEN + text + RESET
    if text == 'FAIL':
        return RED + text + RESET
    return text


def fmt_delta(secs):
    if secs < 0:
        return "(pre-reboot)"
    m, s = divmod(int(secs), 60)
    return "+{:02d}m {:02d}s  ({:6.1f}s)".format(m, s, secs)


# Console log parser - BIOS/GRUB markers from the serial console capture

# Console log format: "<YYYY-MM-DD HH:MM:SS.ffffff> | <console text>"
CONSOLE_TS_PAT = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) \| ')


def parse_console_ts(line):
    m = CONSOLE_TS_PAT.match(line)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            pass  # unparsable timestamp - caller treats the line as untimed
    return None


def detect_console_clock_offset(console_path):
    """Read the CLOCK_PROBE line written by the console capture at startup.

    Format: CLOCK_PROBE | ws=<test host time> | dut=<DUT time>
    Returns offset in seconds: positive = test host clock ahead of DUT.
    """
    PROBE_PAT = re.compile(r'CLOCK_PROBE \| ws=(\S+ \S+) \| dut=(.+)')
    DUT_DATE_FMTS = [
        "%a %b %d %H:%M:%S %Y",     # Sun Jun 15 18:07:00 2026      (24h)
        "%a %b  %d %H:%M:%S %Y",    # Sun Jun  5 18:07:00 2026      (24h, single-digit day)
        "%a %b %d %I:%M:%S %p %Y",  # Mon Jun 15 08:00:46 PM 2026   (12h)
        "%a %b  %d %I:%M:%S %p %Y",  # Mon Jun  5 08:00:46 PM 2026   (12h, single-digit day)
        "%Y-%m-%d %H:%M:%S",
    ]
    try:
        with open(console_path) as f:
            for line in f:
                m = PROBE_PAT.search(line)
                if not m:
                    continue
                ws_str = m.group(1).strip()
                dut_str = m.group(2).strip()
                try:
                    ws_ts = datetime.strptime(ws_str, "%Y-%m-%d %H:%M:%S.%f")
                except ValueError:
                    continue
                dut_clean = re.sub(r'\s+UTC\s*', ' ', dut_str).strip()
                for fmt in DUT_DATE_FMTS:
                    try:
                        dut_ts = datetime.strptime(dut_clean, fmt)
                        offset = (ws_ts - dut_ts).total_seconds()
                        if abs(offset) > 7200:
                            break  # sanity check
                        print("[INFO] Clock offset from CLOCK_PROBE: {:.1f}s".format(offset))
                        return offset
                    except ValueError:
                        continue
    except IOError:
        # No console log for this run - platforms without a console entry in the
        # lab graph are supported, the caller falls back to a 0s offset.
        pass

    print("[WARN] No CLOCK_PROBE found in console log — clock offset defaulting to 0s.")
    print("[WARN] Console markers may be misplaced. Use --console-offset <seconds> to override.")
    return 0.0

# PTF traffic log parser - traffic blackout measurement


def parse_ptf_log(path, T0, clock_offset_secs, results, num_routes=100):
    """Parse ptf_rx.log for traffic blackout + per-route static-route convergence.

    Each RX line is 'YYYY-MM-DD HH:MM:SS.ffffff route=NN' in test host time, so
    clock_offset_secs is subtracted to line up with the syslog markers.
    Produces: blackout start, blackout end, all static routes programmed.
    """
    entries = []  # (dut_time, route_int_or_None)
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
                # convert test host -> DUT time
                entries.append((dt - timedelta(seconds=clock_offset_secs), route))
    except IOError as e:
        print("[WARN] Could not read PTF log: {}".format(e))
        return

    if len(entries) < 2:
        print("[WARN] PTF log: only {} packet(s) - not enough to analyze".format(len(entries)))
        return

    entries.sort(key=lambda e: e[0])
    times = [e[0] for e in entries]

    # Aggregate blackout = largest inter-packet gap across ALL routes
    max_gap, gap_idx = 0.0, 1
    for i in range(1, len(times)):
        g = (times[i] - times[i - 1]).total_seconds()
        if g > max_gap:
            max_gap, gap_idx = g, i
    blackout_start = times[gap_idx - 1]
    blackout_end = times[gap_idx]

    # Per-route recovery: first packet each route forwards AFTER the blackout starts
    routes_recovered = {}
    for dt, route in entries:
        if route is None:
            continue
        if dt > blackout_start and route not in routes_recovered:
            routes_recovered[route] = dt

    seen_ever = set(r for _, r in entries if r is not None)
    print("[INFO] PTF: {} packets, {} distinct routes seen, blackout {:.1f}s, {}/{} routes recovered".format(
        len(entries), len(seen_ever), max_gap, len(routes_recovered), num_routes))

    results.append((blackout_start, "Traffic blackout start", ""))
    results.append((blackout_end,   "Traffic blackout end (first route back)", ""))

    # Only a full set is a convergence milestone - a partial recovery must not
    # emit a marker claiming all num_routes routes came back.
    if len(routes_recovered) >= num_routes:
        last_ts = max(routes_recovered.values())
        last_route = [r for r, t in routes_recovered.items() if t == last_ts][0]
        print("[INFO] PTF: last static route to recover was 172.16.{}.0/24".format(last_route))
        results.append((last_ts, "All static routes programmed ({}/{})".format(
            len(routes_recovered), num_routes), ""))

    missing = set(range(num_routes)) - set(routes_recovered.keys())
    if missing:
        sample = sorted(missing)[:20]
        print("[WARN] {} static route(s) never forwarded after reboot: {}{}".format(
            len(missing), sample, ' ...' if len(missing) > 20 else ''))


# Console markers: (name, regex) searched in captured console output.
# Patterns verified against actual Cisco 8000 / SONiC console output.
CONSOLE_MARKERS = [
    # cisco-fpga-xil fires when FPGA physically cuts power = shutdown fully complete
    ("Shutdown complete",    r'cisco-fpga-xil.*user power cycle'),
    # Cisco 8000 BIOS first line
    ("BIOS init",           r'Cisco 8000.*BIOS|Cisco.*Series BIOS'),
    # Last BIOS POST line before handoff to bootloader (FPGA firmware info)
    ("BIOS POST complete",  r'X86FPGA.*TamLib'),
    # GRUB splash line
    ("GRUB start",          r'Welcome to GRUB'),
    # Kernel + ramdisk load
    ("GRUB kernel load",    r'Loading SONiC-OS OS (initial ramdisk|kernel)|Loading initial ramdisk'),
]


def parse_console_log(console_path, T0, results, manual_offset=None):
    """Parse timestamped console.log for BIOS/GRUB markers.

    Clock offset (test host vs DUT) comes from the CLOCK_PROBE line written by
    the console capture at startup. Use --console-offset to override.
    """
    from datetime import timedelta

    # --- Step 1: determine clock offset ---
    if manual_offset is not None:
        offset_secs = manual_offset
        # offset already printed by detect_console_clock_offset() or --console-offset in main()
    else:
        offset_secs = detect_console_clock_offset(console_path)
        if abs(offset_secs) > 1.0:
            print("[INFO] Console clock offset: {:.1f}s (test host {} DUT by {:.0f}s)".format(
                abs(offset_secs),
                'AHEAD of' if offset_secs > 0 else 'BEHIND',
                abs(offset_secs)))

    # --- Step 2: scan for markers, applying offset to each timestamp ---
    found_console = set()
    # Allow lines up to 120s before T0 (clock-adjusted) to catch edge cases
    earliest_ws = T0 - timedelta(seconds=120) + timedelta(seconds=offset_secs)

    try:
        with open(console_path) as f:
            for line in f:
                ws_ts = parse_console_ts(line)
                if not ws_ts or ws_ts < earliest_ws:
                    continue
                if '=== CONNECTED' in line or '=== CONNECTION CLOSED' in line:
                    continue
                # Adjust to DUT time
                dut_ts = ws_ts - timedelta(seconds=offset_secs)
                rest = CONSOLE_TS_PAT.sub('', line)
                rest = rest.replace('\r', '')
                for name, pat in CONSOLE_MARKERS:
                    if name not in found_console and re.search(pat, rest, re.IGNORECASE):
                        found_console.add(name)
                        results.append((dut_ts, name, rest.strip()[:120]))
    except IOError as e:
        print("[WARN] Could not read console log: {}".format(e))
        return

    if not found_console:
        print("[WARN] No console markers found in console log (check patterns or log content)")
    else:
        print("[INFO] Console markers found: {}".format(', '.join(sorted(found_console))))


# Auto-detect T0 from syslog (last reboot message)

REBOOT_PATTERNS = [
    r'User requested rebooting device',
    r'cold-reboot.*Rebooting',
    r'reboot.*requested COLD shutdown',
    r'Restarting system',
]


def auto_detect_t0(syslog_path):
    """Scan syslog for the last reboot trigger message and return its timestamp.
    Falls back to syslog.1 if not found in primary syslog (log rotation)."""
    candidates = [syslog_path, syslog_path + '.1']

    for path in candidates:
        last_ts = None
        last_line = None
        try:
            with open(path) as f:
                for line in f:
                    for pat in REBOOT_PATTERNS:
                        if re.search(pat, line, re.IGNORECASE):
                            ts = parse_syslog_ts(line)
                            if ts:
                                last_ts = ts
                                last_line = line.strip()[:120]
                            break
        except IOError:
            continue

        if last_ts:
            print("[INFO] Reboot marker found in: {}".format(path))
            print("[INFO] Reboot marker: {}".format(last_line))
            return last_ts

    print("[WARN] Reboot marker not found in {} or {}.1".format(syslog_path, syslog_path))
    return None


# Main

def main():
    parser = argparse.ArgumentParser(description="Cold reboot timing analyzer")
    parser.add_argument("--t0",         default=None,
                        help='Reboot trigger timestamp (auto-detected from syslog if not given)')
    parser.add_argument("--syslog",     default="/var/log/syslog", help="Path to syslog (default: /var/log/syslog)")
    parser.add_argument("--config-db",  default="/etc/sonic/config_db.json",
                        help="Path to config_db.json (default: /etc/sonic/config_db.json)")
    parser.add_argument("--portchannels", default=None,
                        help="Comma-separated PortChannels (overrides config-db auto-discovery)")
    parser.add_argument("--pc-members", default=None,
                        help="Comma-separated PortChannel member ports to expect UP "
                             "(use with --portchannels; normally the set that was "
                             "operationally up before the reboot)")
    parser.add_argument("--console-log", default=None,
                        help="Path to the serial console log for BIOS/GRUB markers (e.g. console.log)")
    parser.add_argument("--console-offset", type=float, default=None,
                        help="Manual clock offset in seconds: test_host_time - DUT_time "
                             "(use if auto-detect fails, e.g. --console-offset 728)")
    parser.add_argument("--ptf-log", default=None,
                        help="Path to ptf_rx.log from ptf_traffic_test.py for traffic blackout measurement")
    parser.add_argument("--ptf-num-routes", type=int, default=100,
                        help="Number of static routes probed by the PTF (default: 100)")
    parser.add_argument("--sla", type=float, default=300,
                        help="Pass/fail threshold in seconds (default: 300)")
    parser.add_argument("--dut-info", default=None,
                        help="Path to a JSON file of DUT/image facts (image version, platform, "
                             "running containers) to record alongside the timings")
    args = parser.parse_args()

    if args.t0:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                T0 = datetime.strptime(args.t0, fmt)
                break
            except ValueError:
                pass  # try the next accepted timestamp format
        else:
            print("[ERROR] --t0 must be 'YYYY-MM-DD HH:MM:SS' or 'YYYY-MM-DD HH:MM:SS.ffffff'")
            sys.exit(1)
    else:
        T0 = auto_detect_t0(args.syslog)
        if T0 is None:
            print("[ERROR] Could not auto-detect reboot time from syslog. Please provide --t0.")
            sys.exit(1)
        print("[INFO] Auto-detected T0: {} UTC".format(T0.strftime('%Y-%m-%d %H:%M:%S.%f')))
        print()

    results = []  # list of (datetime, marker_name, log_line)

    # DUT / image context, printed with the timings so two result.log files can
    # be compared.
    print_dut_info(args.dut_info)

    # Load interfaces from config_db or fall back to --portchannels
    if args.portchannels:
        expected_pcs = set(pc.strip() for pc in args.portchannels.split(','))
        # An explicit list is an oper-state baseline taken before the reboot, so
        # it already excludes links that were down anyway (absent peer etc).
        pc_members = set(p.strip() for p in args.pc_members.split(',')) \
            if args.pc_members else set()
        vlan_members = set()
        print("[INFO] Expecting {} PortChannel(s) and {} member port(s) back "
              "(pre-reboot oper-up baseline)".format(len(expected_pcs), len(pc_members)))
    else:
        expected_pcs, pc_members, vlan_members = load_interfaces(args.config_db)

    pc_up_times = {}  # portchannel  -> first UP timestamp
    pcm_up_times = {}  # pc member port -> first UP timestamp
    vlan_up_times = {}  # vlan member port -> first UP timestamp

    # Scan the rotated file first: if logrotate fires just after the trigger the
    # early markers land in syslog.1. Lines before T0 are skipped either way.
    found = set()
    kernel_found = False
    for syslog_path in [args.syslog + '.1', args.syslog]:
        try:
            fh = open(syslog_path)
        except IOError:
            continue
        with fh as f:
            for line in f:
                ts = parse_syslog_ts(line)
                if not ts or ts < T0:
                    continue

                # Standard markers
                for name, pat in SYSLOG_MARKERS:
                    if name not in found and re.search(pat, line, re.IGNORECASE):
                        found.add(name)
                        if name == "Kernel boot":
                            kernel_found = True
                        results.append((ts, name, line.strip()[:120]))

                # PortChannel UP tracking (only after kernel boot to avoid shutdown noise)
                if kernel_found and expected_pcs:
                    for pc in expected_pcs:
                        if pc not in pc_up_times:
                            if re.search(r'Port ' + pc + r'.*oper state set from down to up', line):
                                pc_up_times[pc] = ts

                # PortChannel member port UP tracking
                if kernel_found and pc_members:
                    for port in pc_members:
                        if port not in pcm_up_times:
                            if re.search(r'Port ' + port + r'.*oper state set from down to up', line):
                                pcm_up_times[port] = ts

                # Vlan member port UP tracking
                if kernel_found and vlan_members:
                    for port in vlan_members:
                        if port not in vlan_up_times:
                            if re.search(r'Port ' + port + r'.*oper state set from down to up', line):
                                vlan_up_times[port] = ts

    if not found:
        print("[WARN] No syslog markers found in {} or {}.1".format(
            args.syslog, args.syslog))

    # Add PortChannel first/last UP to results
    if expected_pcs:
        if pc_up_times:
            first_pc_ts = min(pc_up_times.values())
            last_pc_ts = max(pc_up_times.values())
            first_pc_name = [pc for pc, t in pc_up_times.items() if t == first_pc_ts][0]
            last_pc_name = [pc for pc, t in pc_up_times.items() if t == last_pc_ts][0]
            results.append((first_pc_ts, "First PortChannel UP ({})".format(first_pc_name), ""))
            results.append((last_pc_ts,  "Last PortChannel UP ({})".format(last_pc_name), ""))
            missing = expected_pcs - set(pc_up_times.keys())
            if missing:
                print("[WARN] These PortChannels never came up: {}".format(', '.join(sorted(missing))))
    else:
        print("[INFO] No --portchannels specified, skipping PortChannel UP tracking")

    # Warn if any PC member ports never came up (no output row, just warning)
    if pc_members:
        missing_pcm = pc_members - set(pcm_up_times.keys())
        if missing_pcm:
            print("[WARN] PC member ports never UP: {}".format(', '.join(sorted(missing_pcm))))

    # First/Last port UP across ALL tracked ports (pc members + vlan members)
    # These are exactly the admin-up ports we care about from config_db.
    all_port_up_times = {}
    all_port_up_times.update(vlan_up_times)
    all_port_up_times.update(pcm_up_times)
    if all_port_up_times:
        first_ts = min(all_port_up_times.values())
        last_ts = max(all_port_up_times.values())
        first_p = [p for p, t in all_port_up_times.items() if t == first_ts][0]
        last_p = [p for p, t in all_port_up_times.items() if t == last_ts][0]
        results.append((first_ts, "First port UP ({})".format(first_p), ""))
        results.append((last_ts,  "Last port UP ({})".format(last_p),  ""))
        missing_vlan = vlan_members - set(vlan_up_times.keys())
        if missing_vlan:
            print("[WARN] Vlan member ports never UP: {}".format(', '.join(sorted(missing_vlan))))

    # Determine clock offset — used for both console and PTF log timestamp conversion.
    # The PTF container shares the test host clock, i.e. the CLOCK_PROBE ws= clock
    clock_offset_secs = 0.0
    if args.console_offset is not None:
        clock_offset_secs = args.console_offset
        print("[INFO] Clock offset: {:.1f}s (manual --console-offset)".format(clock_offset_secs))
    elif args.console_log:
        clock_offset_secs = detect_console_clock_offset(args.console_log)
    elif args.ptf_log:
        print("[WARN] --ptf-log without --console-log: clock offset = 0s. "
              "Use --console-offset <N> to fix PTF timestamps.")

    # Parse console log if provided (BIOS/GRUB markers)
    if args.console_log:
        parse_console_log(args.console_log, T0, results,
                          manual_offset=clock_offset_secs)
    else:
        print("[INFO] No --console-log provided, skipping BIOS/GRUB markers")

    # Parse PTF traffic log if provided (traffic blackout markers)
    if args.ptf_log:
        parse_ptf_log(args.ptf_log, T0, clock_offset_secs, results,
                      num_routes=args.ptf_num_routes)

    # Sort by timestamp
    results.sort(key=lambda x: x[0])

    # --- Print report ---
    print()
    print("=" * 85)
    print("  COLD REBOOT TIMING ANALYSIS")
    print("  T0 (reboot triggered) : {} UTC".format(T0.strftime('%Y-%m-%d %H:%M:%S')))
    print("=" * 85)
    print("  {:<45} {:>20}   UTC TIME".format('MARKER', 'ELAPSED'))
    print("  {} {}   {}".format('-'*45, '-'*20, '--------'))

    for ts, name, _ in results:
        secs = (ts - T0).total_seconds()
        print("  {:<45} {:>20}   {}".format(name, fmt_delta(secs), ts.strftime('%H:%M:%S')))

    print("=" * 85)

    if results:
        last_ts = results[-1][0]
        total = (last_ts - T0).total_seconds()
        sla_pass = total <= args.sla
        print("\n  Total recovery time : {}".format(fmt_delta(total)))
        print("  SLA ({:.0f}s){:<9}: {} ({:.0f}s vs {:.0f}s limit)".format(
              args.sla, '', colored('PASS' if sla_pass else 'FAIL'), total, args.sla))
    # --- Plane convergence summary ---
    # For PortChannel markers, name includes the PC name so do prefix match

    def get_plane_ts(members):
        plane_ts = []
        for m in members:
            for ts, name, _ in results:
                if name == m or name.startswith(m.split(' (')[0]):
                    plane_ts.append(ts)
        return plane_ts

    print()
    print("=" * 85)
    print("  PLANE CONVERGENCE SUMMARY")
    print("=" * 85)
    print("  {:<30} {:>16}   {}".format(
        'PLANE', 'CONVERGED AT', 'SLA ({:.0f}s)'.format(args.sla)))
    print("  {} {} {}".format('-'*30, '-'*16, '-'*10))

    for plane, members in PLANE_GROUPS:
        plane_ts = get_plane_ts(members)
        if plane_ts:
            last = max(plane_ts)
            secs = (last - T0).total_seconds()
            sla = 'PASS' if secs <= args.sla else 'FAIL'
            print("  {:<30} {:>16}   {}".format(plane, fmt_delta(secs), colored(sla)))
        else:
            print("  {:<30} {:>16}   {}".format(plane, 'N/A (no markers)', '----'))
    print("=" * 85)
    print()


if __name__ == "__main__":
    main()
