"""Helpers for the cold-reboot recovery-time measurement test.

DUT/PTF access, topology discovery, route injection and console capture, all
derived from the standard sonic-mgmt fixtures rather than hardcoded values.
"""

import logging
import re
import telnetlib
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# --- Test route configuration (single source of truth) ---------------------
NUM_ROUTES = 100                 # 172.16.0.0/24 .. 172.16.<NUM_ROUTES-1>.0/24
BASE_NET = '172.16'              # first two octets of the test prefixes
BLACKHOLE = '172.16.0.0/16'      # backstop that shadows the BGP default
CFG_BACKUP = '/etc/sonic/config_db.json.creboot_bak'

PTF_SCRIPT_DST = '/tmp/ptf_traffic_test.py'
PTF_RX_LOG = '/tmp/ptf_rx.log'

# Strip ANSI/VT100 escapes and control chars from console output
ANSI_ESCAPE = re.compile(
    r'\x1b\[[?!>]?[0-9;]*[a-zA-Z@~`]'
    r'|\x1b[()][AB012]'
    r'|\x1b[=>78HMDc]'
    r'|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'
)


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')


# Topology discovery

def get_traffic_params(duthost, tbinfo):
    """Derive TX/RX PTF ports, DUT MAC and nexthop from minigraph facts.

    Returns dict: tx_iface, rx_ifaces, dut_mac, nexthop, tx_dut_port, rx_pc
    """
    mg = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_idx = mg['minigraph_ptf_indices']
    pcs = mg['minigraph_portchannels']

    # Pick the first non-backend PortChannel with an IPv4 peer address; its peer
    # is the nexthop and it becomes the RX side.
    rx_pc, nexthop = None, None
    for intf in mg.get('minigraph_portchannel_interfaces', []):
        peer = intf.get('peer_addr')
        name = intf.get('attachto')
        if not peer or ':' in peer or name not in pcs:
            continue
        if duthost.is_backend_portchannel(name, mg):
            continue
        rx_pc, nexthop = name, peer
        break
    if rx_pc is None:
        raise RuntimeError("No PortChannel with an IPv4 peer address found in minigraph")

    rx_members = pcs[rx_pc]['members']
    rx_ifaces = ['eth%d' % ptf_idx[p] for p in rx_members if p in ptf_idx]

    # TX must ingress on a different link than it egresses and accept routed
    # traffic - on T0 a Vlan member, on T1 (no Vlans) the later branches apply.
    all_pc_members = set()
    for pc in pcs.values():
        all_pc_members.update(pc['members'])
    vlan_member_ports = set()
    for vlan in mg.get('minigraph_vlans', {}).values():
        vlan_member_ports.update(vlan.get('members', []))
    ordered = sorted(ptf_idx, key=lambda p: ptf_idx[p])

    tx_dut_port = next((p for p in ordered if p in vlan_member_ports), None)
    if tx_dut_port is None:
        tx_dut_port = next((p for p in ordered if p not in all_pc_members), None)
    if tx_dut_port is None:
        tx_dut_port = next((p for p in ordered if p not in set(rx_members)), None)
    if tx_dut_port is None:
        raise RuntimeError("Could not find a DUT port outside %s for TX" % rx_pc)

    params = {
        'tx_iface': 'eth%d' % ptf_idx[tx_dut_port],
        'rx_ifaces': rx_ifaces,
        'dut_mac': duthost.facts['router_mac'],
        'nexthop': nexthop,
        'tx_dut_port': tx_dut_port,
        'rx_pc': rx_pc,
    }
    logger.info("Traffic params: %s", params)
    return params


# Static route injection / cleanup

def add_test_routes(duthost, nexthop):
    """Inject the test routes + blackhole into CONFIG_DB and persist them."""
    logger.info("Injecting %d static routes %s.0.0/24..%s.%d.0/24 -> %s (+ blackhole %s)",
                NUM_ROUTES, BASE_NET, BASE_NET, NUM_ROUTES - 1, nexthop, BLACKHOLE)
    script = "\n".join([
        "set -e",
        "[ -f {bak} ] || sudo cp /etc/sonic/config_db.json {bak}".format(bak=CFG_BACKUP),
        "for i in $(seq 0 {last}); do".format(last=NUM_ROUTES - 1),
        '  sonic-db-cli CONFIG_DB HSET "STATIC_ROUTE|{b}.$i.0/24" nexthop "{nh}" >/dev/null'.format(
            b=BASE_NET, nh=nexthop),
        "done",
        'sonic-db-cli CONFIG_DB HSET "STATIC_ROUTE|{bh}" blackhole "true" >/dev/null'.format(
            bh=BLACKHOLE),
        "sudo config save -y >/dev/null",
        'echo ADDED=$(sonic-db-cli CONFIG_DB KEYS "STATIC_ROUTE|{b}*" | grep -c STATIC_ROUTE || true)'.format(
            b=BASE_NET),
    ])
    out = duthost.shell(script, executable="/bin/bash")['stdout']
    added = _parse_kv(out, 'ADDED')
    expected = NUM_ROUTES + 1
    if added != expected:
        raise RuntimeError("Expected %d STATIC_ROUTE keys, DUT reports %s" % (expected, added))
    logger.info("Injected and saved: %d STATIC_ROUTE entries", added)


def del_test_routes(duthost):
    """Remove the test routes + blackhole and persist (restore DUT state)."""
    logger.info("Removing test static routes and restoring DUT config")
    script = "\n".join([
        "for i in $(seq 0 {last}); do".format(last=NUM_ROUTES - 1),
        '  sonic-db-cli CONFIG_DB DEL "STATIC_ROUTE|{b}.$i.0/24" >/dev/null'.format(b=BASE_NET),
        "done",
        'sonic-db-cli CONFIG_DB DEL "STATIC_ROUTE|{bh}" >/dev/null'.format(bh=BLACKHOLE),
        "sudo config save -y >/dev/null",
        'echo REMAINING=$(sonic-db-cli CONFIG_DB KEYS "STATIC_ROUTE|{b}*" | grep -c STATIC_ROUTE || true)'.format(
            b=BASE_NET),
    ])
    out = duthost.shell(script, executable="/bin/bash", module_ignore_errors=True)['stdout']
    remaining = _parse_kv(out, 'REMAINING')
    if remaining:
        logger.warning("%s test route key(s) still present after delete", remaining)
    else:
        logger.info("All test routes removed and config saved (DUT restored)")


def _parse_kv(output, key):
    for line in (output or '').splitlines():
        line = line.strip()
        if line.startswith(key + '='):
            try:
                return int(line.split('=', 1)[1])
            except ValueError:
                return None
    return None


# PTF probe control

def start_ptf_probe(ptfhost, script_src, params):
    """Copy and start the multi-route probe on the PTF host (background)."""
    ptfhost.copy(src=script_src, dest=PTF_SCRIPT_DST)
    cmd = ("nohup python3 {script} --out {out} --num-routes {n} --base-net {base} "
           "--tx-iface {tx} --rx-ifaces {rx} --dut-mac {mac} "
           ">/tmp/ptf_probe.out 2>&1 &").format(
        script=PTF_SCRIPT_DST, out=PTF_RX_LOG, n=NUM_ROUTES, base=BASE_NET,
        tx=params['tx_iface'], rx=','.join(params['rx_ifaces']), mac=params['dut_mac'])
    ptfhost.shell(cmd)
    time.sleep(2)   # let AsyncSniffer initialize
    logger.info("PTF probe started: TX=%s -> DUT -> RX=%s (%d routes)",
                params['tx_iface'], params['rx_ifaces'], NUM_ROUTES)


def stop_ptf_probe(ptfhost):
    ptfhost.shell("pkill -f ptf_traffic_test.py", module_ignore_errors=True)
    time.sleep(2)   # let the signal handler flush and close the log


def ptf_rx_log_lines(ptfhost):
    """Current line count of the RX log, used as a 'start of interest' marker."""
    out = ptfhost.shell("wc -l < {} 2>/dev/null || echo 0".format(PTF_RX_LOG),
                        module_ignore_errors=True)['stdout']
    try:
        return int(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return 0


def ptf_distinct_routes(ptfhost, from_line=0):
    """Count distinct routes forwarding, from the live RX log.

    from_line lets the caller ignore everything logged before the reboot.
    """
    out = ptfhost.shell(
        "tail -n +{start} {log} 2>/dev/null | grep -oE 'route=[0-9]+' | sort -u | wc -l".format(
            start=from_line + 1, log=PTF_RX_LOG),
        module_ignore_errors=True)['stdout']
    try:
        return int(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return 0


def wait_all_routes_recovered(ptfhost, timeout, from_line=0, poll=10):
    """Poll the PTF RX log until all NUM_ROUTES routes forward again.

    Only traffic logged after from_line counts.
    Returns (recovered_count, elapsed_seconds).
    """
    start = time.time()
    last = -1
    while time.time() - start < timeout:
        count = ptf_distinct_routes(ptfhost, from_line)
        if count != last:
            logger.info("PTF: %d/%d routes forwarding (%.0fs elapsed)",
                        count, NUM_ROUTES, time.time() - start)
            last = count
        if count >= NUM_ROUTES:
            return count, time.time() - start
        time.sleep(poll)
    logger.warning("Timed out after %ds with only %d/%d routes forwarding",
                   timeout, last, NUM_ROUTES)
    return last, time.time() - start


# Clock alignment and precise recovery time

def get_oper_up_interfaces(duthost):
    """Snapshot which PortChannels / ports are OPERATIONALLY up right now.

    config_db only knows admin state; a link with no peer stays admin-up but
    never comes up. Returns dict: portchannels (set), ports (set).
    """
    pcs, ports = set(), set()
    # "show int status" lists ports and PortChannels in one table; Oper is field
    # 7, Admin field 8. Index from the left - trailing Type may contain spaces.
    try:
        out = duthost.shell("show int status",
                            module_ignore_errors=True)['stdout']
    except Exception as err:
        logger.warning("Could not read interface status: %s", err)
        return {'portchannels': pcs, 'ports': ports}

    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 9 or fields[7] != 'up':
            continue                      # header, separator, or oper-down
        if fields[0].startswith('PortChannel'):
            pcs.add(fields[0])
        elif fields[0].startswith('Ethernet'):
            ports.add(fields[0])

    logger.info("Pre-reboot oper-up: %d PortChannels, %d ports",
                len(pcs), len(ports))
    return {'portchannels': pcs, 'ports': ports}


def get_dut_info(duthost, tbinfo=None):
    """Collect image / platform / container facts for the timing report.

    Best-effort: any field that cannot be read is omitted rather than failing.
    """
    info = {}

    for key, get in (
        ('image_version', lambda: duthost.os_version),
        ('sonic_release', lambda: duthost.sonic_release),
        ('kernel_version', lambda: duthost.kernel_version),
        ('hostname', lambda: duthost.hostname),
    ):
        try:
            value = get()
            if value:
                info[key] = str(value)
        except Exception as err:
            logger.warning("Could not read %s: %s", key, err)

    try:
        facts = duthost.facts or {}
        for key in ('platform', 'hwsku', 'asic_type', 'platform_asic',
                    'num_asic', 'router_type'):
            if facts.get(key):
                info[key] = str(facts[key])
    except Exception as err:
        logger.warning("Could not read DUT facts: %s", err)

    if tbinfo:
        topo = tbinfo.get('topo') or {}
        if topo.get('name'):
            info['topology'] = str(topo['name'])
        if topo.get('type'):
            info['topology_type'] = str(topo['type'])

    # Running containers: a differing set (or count) between two images is a
    # common reason for a differing control-plane recovery time.
    try:
        names = sorted(n.strip() for n in duthost.get_running_containers()
                       if n and n.strip())
        if names:
            info['num_containers'] = str(len(names))
            info['containers'] = ','.join(names)
    except Exception as err:
        logger.warning("Could not list docker containers: %s", err)

    logger.info("DUT info: image=%s platform=%s containers=%s",
                info.get('image_version', '?'), info.get('platform', '?'),
                info.get('num_containers', '?'))
    return info


def get_clock_offset(duthost):
    """Return (test_host_time - DUT_time) in seconds.

    syslog uses the DUT clock and the PTF RX log the test host clock; the parser
    needs this offset to place both on one timeline.
    """
    try:
        before = datetime.now(timezone.utc)
        dut_raw = duthost.shell("date -u '+%Y-%m-%d %H:%M:%S'")['stdout'].strip()
        after = datetime.now(timezone.utc)
        dut_time = datetime.strptime(dut_raw, '%Y-%m-%d %H:%M:%S')
        mid = (before + (after - before) / 2).replace(tzinfo=None)
        offset = (mid - dut_time).total_seconds()
        logger.info("Clock offset: %.1fs (test host %s DUT)", abs(offset),
                    'ahead of' if offset > 0 else 'behind')
        return offset
    except Exception as err:
        logger.warning("Could not determine clock offset (%s) - assuming 0s", err)
        return 0.0


def recovery_time_from_ptf_log(path, reboot_start, num_routes=NUM_ROUTES):
    """Seconds from the reboot trigger until the last route forwarded again.

    Measured from the end of the traffic blackout (the longest gap between
    packets), not from the trigger: the DUT keeps forwarding into the shutdown
    and that traffic would otherwise be mistaken for recovery. Returns None if
    the routes never all came back.
    """
    entries = []
    try:
        with open(path) as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3 or not parts[2].startswith('route='):
                    continue
                try:
                    ts = datetime.strptime(parts[0] + ' ' + parts[1],
                                           '%Y-%m-%d %H:%M:%S.%f')
                except ValueError:
                    continue
                entries.append((ts, parts[2].split('=', 1)[1]))
    except IOError as err:
        logger.warning("Could not read PTF log %s: %s", path, err)
        return None

    if len(entries) < 2:
        logger.warning("PTF log has too few packets to measure recovery")
        return None
    entries.sort(key=lambda e: e[0])

    # Longest silence between packets = the reboot blackout.
    gap_idx, gap = 1, 0.0
    for i in range(1, len(entries)):
        delta = (entries[i][0] - entries[i - 1][0]).total_seconds()
        if delta > gap:
            gap, gap_idx = delta, i
    logger.info("PTF traffic blackout: %.1fs (%s -> %s)", gap,
                entries[gap_idx - 1][0], entries[gap_idx][0])

    seen = set()
    for ts, route in entries[gap_idx:]:
        seen.add(route)
        if len(seen) >= num_routes:
            return (ts - reboot_start).total_seconds()
    logger.warning("PTF log shows only %d/%d routes recovered after the blackout",
                   len(seen), num_routes)
    return None


# Console capture

class ConsoleRecorder(object):
    """Passively record the DUT serial console, timestamping every line.

    Deliberately not create_duthost_console(): that logs in and waits for a
    prompt, but BIOS/GRUB/shutdown markers occur when there is no prompt.
    """

    def __init__(self, host, port, path, poll=0.2):
        self.host = host
        self.port = int(port)
        self.path = path
        self.poll = poll
        self._stop = threading.Event()
        self._thread = None
        self._fh = None
        self._buf = ''
        self._tn = None

    @staticmethod
    def from_conn_graph(conn_graph_facts, hostname, path):
        """Build a recorder from the lab graph, or None if the DUT has no console.

        Login-related columns are ignored - passive capture does not need them.
        """
        try:
            info = conn_graph_facts['device_console_info'][hostname]
            link = conn_graph_facts['device_console_link'][hostname]['ConsolePort']
        except (KeyError, TypeError):
            logger.warning("%s has no console entry in the lab graph", hostname)
            return None

        host = info.get('ManagementIp')
        port = link.get('peerport')
        if not host or not port:
            logger.warning("Incomplete console info for %s: ip=%s port=%s",
                           hostname, host, port)
            return None
        if '/' in host:
            host = host.split('/')[0]

        ctype = (link.get('type') or '').lower()
        if ctype and ctype != 'telnet':
            logger.warning("Console type '%s' for %s is not supported for passive "
                           "capture - skipping console markers", ctype, hostname)
            return None

        logger.info("Console for %s: %s:%s (telnet, passive capture)",
                    hostname, host, port)
        return ConsoleRecorder(host, port, path)

    def write_clock_probe(self, duthost):
        """Write the CLOCK_PROBE line the parser uses to align console vs DUT clocks."""
        try:
            before = datetime.now(timezone.utc)
            dut_time = duthost.shell("date -u")['stdout'].strip()
            after = datetime.now(timezone.utc)
            mid = before + (after - before) / 2
            self._fh.write("CLOCK_PROBE | ws={} | dut={}\n".format(
                mid.strftime('%Y-%m-%d %H:%M:%S.%f'), dut_time))
            self._fh.flush()
            logger.info("CLOCK_PROBE written (dut=%s)", dut_time)
        except Exception as err:
            logger.warning("CLOCK_PROBE failed: %s", err)

    def start(self, duthost=None):
        """Connect and begin recording. Returns True if capture started."""
        try:
            self._tn = telnetlib.Telnet(self.host, self.port, timeout=10)
        except Exception as err:
            logger.warning("Could not open console %s:%s (%s) - BIOS/GRUB markers "
                           "will be missing", self.host, self.port, err)
            return False
        self._fh = open(self.path, 'w', buffering=1)
        self._fh.write('{} | === CONNECTED to {}:{} ===\n'.format(
            _now(), self.host, self.port))
        if duthost is not None:
            self.write_clock_probe(duthost)
        self._thread = threading.Thread(target=self._run)
        self._thread.daemon = True
        self._thread.start()
        logger.info("Console capture started -> %s", self.path)
        return True

    def _run(self):
        """Read bytes, reconnecting as needed - the console server drops the
        session when the DUT power-cycles, which is expected mid-reboot."""
        while not self._stop.is_set():
            try:
                data = self._tn.read_very_eager().decode('utf-8', errors='replace')
            except Exception:
                # Connection dropped (DUT power cycle). Reconnect and keep going.
                self._fh.write('{} | === CONNECTION CLOSED (DUT rebooting?) ===\n'.format(_now()))
                self._reconnect()
                continue
            if data:
                self._buf += ANSI_ESCAPE.sub('', data).replace('\r', '')
                while '\n' in self._buf:
                    line, self._buf = self._buf.split('\n', 1)
                    self._fh.write('{} | {}\n'.format(_now(), line))
            time.sleep(self.poll)

    def _reconnect(self):
        try:
            self._tn.close()
        except Exception:
            # The connection is already broken - that is why we are
            # reconnecting, so a failure to close it is expected.
            pass
        while not self._stop.is_set():
            time.sleep(2)
            try:
                self._tn = telnetlib.Telnet(self.host, self.port, timeout=10)
                self._fh.write('{} | === RECONNECTED to {}:{} ===\n'.format(
                    _now(), self.host, self.port))
                return
            except Exception:
                continue

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        if self._buf and self._fh:
            self._fh.write('{} | {}\n'.format(_now(), self._buf))
        for closeable in (self._tn, self._fh):
            try:
                if closeable:
                    closeable.close()
            except Exception:
                # Best-effort teardown: a close error must never fail the run
                # or hide the timing results we just collected.
                pass
