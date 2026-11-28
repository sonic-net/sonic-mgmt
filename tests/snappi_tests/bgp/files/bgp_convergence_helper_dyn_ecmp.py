"""
Dynamic ECMP link-addition convergence helper.

Scenario (ECMP width N = ``multipath``, ingress = tgen_ports[0], egress = tgen_ports[1..N]):

* All N BGP sessions are brought up, then every route range is withdrawn.
* Egress links are added to the ECMP group one at a time (advertise routes on link k only).
  For every link k the traffic is (re)started so the IXIA CP/DP statistics belong to that link:

  1. traffic is stopped, the IXIA CP/DP data plane threshold is set to ``96/k`` percent
     (link 1 -> 96 %, link 2 -> 48 %, link 3 -> 32 %, ...), traffic is regenerated/applied and
     started. Routes of links 1..k-1 stay advertised, so traffic flows to them;
  2. (k > 1) wait until links 1..k-1 each carry Tx/(k-1) (within ``PRE_ADVERTISE_TOLERANCE_PCT``),
     fail the test after ``PRE_ADVERTISE_STABLE_TIMEOUT_SEC``;
  3. advertise the routes of link k and measure the time until link k reaches the threshold;
  4. record the results of link k once, settle, run the verification checks and stop traffic.

* After the last link: stop traffic, withdraw all routes and stop the protocols. The next
  iteration starts the protocols (BGP up) again.

Convergence is measured two ways so the results can be compared:

1. ``port_metrics`` polling (python timed). Resolution is bounded by the IXIA port statistics
   refresh interval (about 1 second), so treat it as an approximation (seconds resolution).
2. IXIA CP/DP ``convergence_metrics``. snappi returns one row per traffic item; the value of a
   link is taken from the row whose ``route_advertise`` event names the route range advertised on
   that link, and is stored once for that link.

Everything that is not specific to this scenario is shared with ``bgp_convergence_helper``: the DUT
side configuration (``duthost_bgp_config``), the TGEN BGP config builder (``build_tgen_bgp_config``,
which handles multi-asic / multi-DUT port settings and ASN resolution), the AS-SEQ workaround
(``set_bgp_as_path_segment_type_asseq``) and the cleanup.
"""
import datetime
import ipaddress
import json
import logging
import re
import time
from tabulate import tabulate

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait, wait_until
from tests.snappi_tests.bgp.files.bgp_convergence_helper import (
    TIMEOUT,
    V4_ROUTE_PREFIX_LEN,
    V4_ROUTE_START,
    V6_ROUTE_PREFIX_LEN,
    V6_ROUTE_START,
    _should_tag_tier2_leak_communities,
    build_tgen_bgp_config,
    cleanup_config,
    duthost_bgp_config,
    get_flow_stats,
    set_bgp_as_path_segment_type_asseq,
)

logger = logging.getLogger(__name__)

# Threshold (percent of Tx rate) for the first link; the k-th link uses BASE / k.
BASE_RX_THRESHOLD_PCT = 96.0
# Sleep after each link addition so routes are fully programmed and traffic is stable.
DEFAULT_SETTLE_SEC = 30
# Number of times the full link-addition sequence is repeated (results are averaged).
DEFAULT_ITERATIONS = 3
# Per-link convergence wait: the deadline starts at START and is extended by STEP each time it
# expires (progress/diagnostics are logged at every extension) until MAX is reached.
LINK_CONVERGENCE_TIMEOUT_START_SEC = 120
LINK_CONVERGENCE_TIMEOUT_STEP_SEC = 60
LINK_CONVERGENCE_TIMEOUT_MAX_SEC = 600
# Poll period for port_metrics (0 = back to back, bounded by REST round trip).
PORT_POLL_INTERVAL_SEC = 0.0
# Allowed deviation of a link's Rx share from tx/k, in percent of Tx rate (warn only).
BALANCE_TOLERANCE_PCT = 10.0
# Counter based ECMP distribution check: clear DUT counters, wait, snapshot, compare links.
ECMP_COUNTER_WINDOW_SEC = 30
ECMP_COUNTER_TOLERANCE_PCT = 2.0
# Wait for traffic to start/stop (ingress Tx rate becomes non-zero / zero).
TRAFFIC_POLL_TIMEOUT_SEC = 60
# Before advertising link k (k > 1): links 1..k-1 must each carry Tx/(k-1) within this tolerance
# (percent of Tx rate) within the timeout, otherwise the test fails.
PRE_ADVERTISE_STABLE_TIMEOUT_SEC = 60
PRE_ADVERTISE_TOLERANCE_PCT = 2.0
# Wait for the IXIA CP/DP convergence_metrics result of a link after port_metrics converged.
CPDP_RESULT_TIMEOUT_SEC = 120
CPDP_POLL_INTERVAL_SEC = 1
# Wait for "For Protocols To start" (other protocol/route waits use the ``timeout`` argument).
PROTOCOL_START_WAIT_SEC = 60
# Traffic converged check: |sum Tx - sum Rx| must be below this percent of the ingress line rate
# (frames per second, from the port speed and ``FRAME_SIZE_BYTES``).
TRAFFIC_CONVERGED_TOLERANCE_PCT = 1.0
FRAME_SIZE_BYTES = 1024
ETH_OVERHEAD_BYTES = 20     # preamble + SFD + inter-frame gap
# DUT interface counters need a moment to be refreshed after traffic stops.
COUNTER_REFRESH_WAIT_SEC = 10
# DUT route counts (display only): the CLIs are polled until the counts reach the number of routes,
# or this timeout expires (no failure; the last counts are shown either way).
ROUTE_COUNT_TIMEOUT_SEC = 60
ROUTE_COUNT_INTERVAL_SEC = 10
# After traffic stops (links 2 and 3): ingress RX_OK must not exceed the sum of egress TX_OK by more
# than this percent of RX_OK (control frames such as LACP/BGP/ARP make the counters differ slightly).
RX_TX_MARGIN_PCT = 0.1


def _dut_port_target(entry):
    """
    ``{'duthost', 'ns', 'name', 'ports'}`` for one ``tgen_ports`` entry, where ``ports`` are the
    physical DUT interfaces (PortChannel peer ports are resolved to their members).
    """
    dh = entry.get('duthost')
    ns = entry.get('asic_value') or None
    name = entry['peer_port']
    ports = [name]
    if name.startswith('PortChannel'):
        try:
            facts = dh.config_facts(host=dh.hostname, source='running',
                                    namespace=ns)['ansible_facts']
            members = []
            for key, value in (facts.get('PORTCHANNEL_MEMBER') or {}).items():
                if '|' in key:
                    pc, member = key.split('|', 1)
                    if pc == name:
                        members.append(member)
                elif key == name:
                    members.extend(value.keys() if isinstance(value, dict) else value)
            ports = members or [name]
        except Exception as exc:
            logger.warning('Unable to resolve members of %s on %s: %s', name, dh.hostname, exc)
    return {'duthost': dh, 'ns': ns, 'name': name, 'ports': ports}


def _dut_ecmp_targets(tgen_ports, multipath):
    """One ``_dut_port_target`` per egress link k=1..multipath."""
    return [_dut_port_target(tgen_ports[k]) for k in range(1, multipath + 1)]


def _read_dut_counters(target):
    """Return {port: (rx_ok, tx_ok)} for the target's physical ports via ``portstat -j``."""
    dh = target['duthost']
    cmd = 'portstat {} -j -i {}'.format(
        '-n {}'.format(target['ns']) if target['ns'] else '', ','.join(target['ports']))
    out = dh.shell(cmd, module_ignore_errors=True).get('stdout', '')
    counters = {}
    try:
        data = json.loads(out[out.index('{'):])
        for port in target['ports']:
            row = data.get(port, {})
            counters[port] = tuple(int(str(row.get(f, 0)).replace(',', '') or 0)
                                   for f in ('RX_OK', 'TX_OK'))
    except Exception as exc:
        logger.warning('Unable to parse portstat output on %s (%s): %s', dh.hostname, exc, out[:300])
    return counters


def _ixia_frames_rx(snappi_api):
    """Return {port_name: cumulative frames_rx} from snappi port_metrics."""
    request = snappi_api.metrics_request()
    return {pm.name: int(pm.frames_rx or 0) for pm in snappi_api.get_metrics(request).port_metrics}


def _spread(values):
    """Max deviation (percent) of any value from the mean; None when the mean is 0."""
    mean = sum(values) / float(len(values)) if values else 0
    if mean <= 0:
        return None
    return max(abs(v - mean) for v in values) * 100.0 / mean


def _check_ecmp_counter_balance(snappi_api, bgp_config, targets, k, iteration,
                                window_sec=ECMP_COUNTER_WINDOW_SEC,
                                tolerance_pct=ECMP_COUNTER_TOLERANCE_PCT):
    """
    Snapshot the DUT counters, wait ``window_sec`` and compare the egress counter deltas of the ``k``
    active ECMP links. Two independent views are checked against ``tolerance_pct``:

    * DUT egress ``TX_OK`` per link (== what each link delivers to the tester)
    * IXIA ``frames_rx`` delta per egress port over the same window

    Links k+1.. are not in ECMP yet and are reported only (expected ~0).
    """
    before_dut = [_read_dut_counters(t) for t in targets]
    before_ixia = _ixia_frames_rx(snappi_api)
    t0 = time.monotonic()
    logger.info('Counters snapshotted (iteration %d, %d link(s)); sampling for %ss',
                iteration, k, window_sec)
    time.sleep(window_sec)
    after_dut = [_read_dut_counters(t) for t in targets]
    after_ixia = _ixia_frames_rx(snappi_api)
    elapsed = time.monotonic() - t0

    rows, dut_tx, ixia_rx = [], [], []
    for j, t in enumerate(targets, start=1):
        tx = sum(after_dut[j - 1].get(p, (0, 0))[1] - before_dut[j - 1].get(p, (0, 0))[1]
                 for p in t['ports'])
        rx = sum(after_dut[j - 1].get(p, (0, 0))[0] - before_dut[j - 1].get(p, (0, 0))[0]
                 for p in t['ports'])
        port_name = bgp_config.ports[j].name
        ixia = after_ixia.get(port_name, 0) - before_ixia.get(port_name, 0)
        active = j <= k
        if active:
            dut_tx.append(tx)
            ixia_rx.append(ixia)
        rows.append([j, t['name'], ','.join(t['ports']), 'yes' if active else 'no', tx, rx, ixia])
    dut_dev = _spread(dut_tx)
    ixia_dev = _spread(ixia_rx)
    dut_ok = dut_dev is not None and dut_dev <= tolerance_pct
    ixia_ok = ixia_dev is not None and ixia_dev <= tolerance_pct
    logger.info(
        "\nECMP counter check, iteration %d, %d link(s) in ECMP, window %.1fs (tolerance %.1f%%)\n%s"
        "\nDUT TX_OK max deviation from mean: %s%% -> %s; IXIA frames_rx max deviation: %s%% -> %s",
        iteration, k, elapsed, tolerance_pct,
        tabulate(rows, headers=['Link', 'DUT port', 'Physical ports', 'In ECMP',
                                'DUT TX_OK delta', 'DUT RX_OK delta', 'IXIA frames_rx delta'],
                 tablefmt='psql'),
        _fmt_ms(dut_dev), 'OK' if dut_ok else 'IMBALANCED',
        _fmt_ms(ixia_dev), 'OK' if ixia_ok else 'IMBALANCED')
    if not (dut_ok and ixia_ok):
        logger.warning('Iteration %d, %d link(s): ECMP traffic NOT within %.1f%% across links',
                       iteration, k, tolerance_pct)
    return {'dut_dev_pct': dut_dev, 'ixia_dev_pct': ixia_dev,
            'counters_balanced': bool(dut_ok and ixia_ok)}


def _clear_dut_counters(targets):
    """
    Clear the interface counters (``sonic-clear counters``) on every DUT in ``targets``. Waits
    ``COUNTER_REFRESH_WAIT_SEC`` first so the last frames of the stopped traffic are already
    reflected in the counters that get cleared.
    """
    logger.info('Waiting %ss for DUT counters to refresh before clearing them', COUNTER_REFRESH_WAIT_SEC)
    time.sleep(COUNTER_REFRESH_WAIT_SEC)
    duts = {}
    for t in targets:
        duts[t['duthost'].hostname] = t['duthost']
    for hostname, dh in duts.items():
        logger.info('Clearing interface counters on %s', hostname)
        dh.shell('sudo sonic-clear counters', module_ignore_errors=True)


def _check_rx_le_tx(ingress_target, egress_targets, k, iteration,
                    margin_pct=RX_TX_MARGIN_PCT):
    """
    With traffic stopped, compare the DUT interface counters (cumulative since the clear done after
    link 1): ingress port ``RX_OK`` against the sum of ``TX_OK`` of egress links 1..k. Traffic
    entering the DUT must not exceed what leaves it, so ``RX_OK <= TX_OK + margin_pct`` percent of
    ``RX_OK`` is required. Returns ``(ok, rx_total, tx_total)``.
    """
    logger.info('Waiting %ss for DUT counters to refresh', COUNTER_REFRESH_WAIT_SEC)
    time.sleep(COUNTER_REFRESH_WAIT_SEC)
    rows = []
    ing = _read_dut_counters(ingress_target)
    rx_total = sum(v[0] for v in ing.values())
    for p, v in sorted(ing.items()):
        rows.append(['ingress', ingress_target['name'], p, v[0], v[1]])
    tx_total = 0
    for j, t in enumerate(egress_targets[:k], start=1):
        counters = _read_dut_counters(t)
        for p, v in sorted(counters.items()):
            rows.append(['egress %d' % j, t['name'], p, v[0], v[1]])
            tx_total += v[1]
    allowed = rx_total * margin_pct / 100.0
    ok = rx_total > 0 and rx_total <= tx_total + allowed
    logger.info('\nDUT counters with traffic stopped, iteration %d, %d link(s) in ECMP\n%s\n'
                'ingress RX_OK=%d, egress TX_OK (links 1..%d)=%d, RX_OK - TX_OK=%d, allowed margin '
                '%.0f (%.2f%% of RX_OK) -> %s', iteration, k,
                tabulate(rows, headers=['Role', 'DUT port', 'Physical port', 'RX_OK', 'TX_OK'],
                         tablefmt='psql'),
                rx_total, k, tx_total, rx_total - tx_total, allowed, margin_pct,
                'OK' if ok else 'FAIL')
    return ok, rx_total, tx_total


def _line_rate_fps(speed):
    """
    Line rate in frames per second of a port with ``speed`` (``'speed_100_gbps'`` or an integer in
    Mbps) for ``FRAME_SIZE_BYTES`` frames. Returns None when the speed cannot be parsed.
    """
    bps = None
    text = str(speed or '')
    m = re.match(r'speed_(\d+)_gbps$', text)
    if m:
        bps = int(m.group(1)) * 10 ** 9
    elif text.isdigit():
        bps = int(text) * 10 ** 6
    if not bps:
        return None
    return bps / 8.0 / (FRAME_SIZE_BYTES + ETH_OVERHEAD_BYTES)


def _traffic_converged_tolerance_fps(speed, tx_rate):
    """``TRAFFIC_CONVERGED_TOLERANCE_PCT`` of the ingress line rate (fallback: of ``tx_rate``)."""
    line_fps = _line_rate_fps(speed)
    if line_fps is None:
        logger.warning('Cannot derive line rate from port speed %r; using %.1f%% of the measured Tx '
                       'rate (%.1f fps) for the traffic converged check',
                       speed, TRAFFIC_CONVERGED_TOLERANCE_PCT, tx_rate)
        line_fps = tx_rate
    return line_fps * TRAFFIC_CONVERGED_TOLERANCE_PCT / 100.0


def _count_lines(duthost, cmd):
    """Run ``cmd`` (ends with ``wc -l``) on the DUT and return the number, or None."""
    out = duthost.shell(cmd, module_ignore_errors=True).get('stdout', '').strip()
    try:
        return int(out.split()[-1])
    except (ValueError, IndexError):
        logger.warning('Unexpected output of "%s" on %s: %r', cmd, duthost.hostname, out[:200])
        return None


def _show_dut_route_counts(tgen_ports, route_type, number_of_routes, k, iteration,
                           timeout_sec=ROUTE_COUNT_TIMEOUT_SEC,
                           interval_sec=ROUTE_COUNT_INTERVAL_SEC):
    """
    Display (no pass/fail) the number of routes the ingress DUT reports through two CLIs. They can
    take 5-10 s, so they are polled with ``wait_until`` until the counts reach
    ``number_of_routes`` or ``timeout_sec`` expires; the last counts are logged either way.

    * ``show ip[v6] route nexthop-group summary | wc -l``
    * ``sonic-db-dump -n ASIC_DB -y -k "*ROUTE*" | grep "oid:0x50000" | wc -l`` (ASIC_DB routes
      pointing to a next hop group; a link-1 route has a single next hop, so this may stay low
      there and is not waited for)

    Returns ``{'nhg_summary': n or None, 'asic_db': n or None}``.
    """
    ingress = tgen_ports[0]
    dh = ingress['duthost']
    ns = ingress.get('asic_value') or None
    ip = 'ipv6' if route_type == 'IPv6' else 'ip'
    nhg_cmd = 'show {} route {} nexthop-group summary | wc -l'.format(
        ip, '-n {}'.format(ns) if ns else '')
    nhg_cmd = ' '.join(nhg_cmd.split())
    asic_cmd = '{}sonic-db-dump -n ASIC_DB -y -k "*ROUTE*" | grep "oid:0x50000" | wc -l'.format(
        'sudo ip netns exec {} '.format(ns) if ns else '')
    counts = {'nhg_summary': None, 'asic_db': None}

    def _reached():
        counts['nhg_summary'] = _count_lines(dh, nhg_cmd)
        counts['asic_db'] = _count_lines(dh, asic_cmd)
        logger.info('Iteration %d, %d link(s): DUT route counts on %s: nexthop-group summary lines=%s, '
                    'ASIC_DB routes with next hop group=%s (routes advertised per link: %d)',
                    iteration, k, dh.hostname, counts['nhg_summary'], counts['asic_db'],
                    number_of_routes)
        ok = counts['nhg_summary'] is not None and counts['nhg_summary'] >= number_of_routes
        if k >= 2:
            ok = ok and counts['asic_db'] is not None and counts['asic_db'] >= number_of_routes
        return ok

    if not wait_until(timeout_sec, interval_sec, 0, _reached):
        logger.warning('Iteration %d, %d link(s): DUT route counts did not reach %d within %ss '
                       '(display only, not a failure)', iteration, k, number_of_routes, timeout_sec)
    logger.info('\nDUT route counts on %s, iteration %d, %d link(s) in ECMP\n%s',
                dh.hostname, iteration, k,
                tabulate([[nhg_cmd, counts['nhg_summary']], [asic_cmd, counts['asic_db']]],
                         headers=['CLI', 'Count'], tablefmt='psql'))
    return counts


def _route_probe_prefixes(route_type, number_of_routes):
    """
    First / middle / last prefix of the egress route range. Derived from the same start address and
    prefix length the TGEN config builder advertises (``V4_/V6_ROUTE_START`` and ``..._PREFIX_LEN`` in
    ``bgp_convergence_helper``), so it stays correct if the range definition changes. Consecutive
    routes are ``2 ** (address bits - prefix length)`` apart; host bits are masked off.
    """
    if route_type == 'IPv6':
        cls, start, plen, bits = ipaddress.IPv6Address, V6_ROUTE_START, V6_ROUTE_PREFIX_LEN, 128
    else:
        cls, start, plen, bits = ipaddress.IPv4Address, V4_ROUTE_START, V4_ROUTE_PREFIX_LEN, 32
    step = 1 << (bits - plen)
    base = int(cls(start))
    idxs = [0, number_of_routes // 2, number_of_routes - 1]
    return ['{}/{}'.format(cls((base + i * step) & ~(step - 1)), plen) for i in idxs]


def _check_last_prefix_ecmp(tgen_ports, route_type, last_prefix, k, iteration):
    """
    Run ``show ip route <last-prefix>`` (``show ipv6 route`` for IPv6) on the ingress DUT and
    verify that the next hop of each of the ``k`` active ECMP egress links is listed.

    Called once ``port_metrics`` reports convergence. The last prefix is the last route to be
    programmed, so seeing all ``k`` next hops there means the control plane has the full ECMP.
    Warn-only: returns ``{'ok': bool or None, 'found': [...], 'missing': [...]}``.
    """
    ingress = tgen_ports[0]
    dh = ingress['duthost']
    ns = ingress.get('asic_value') or None
    is_v6 = route_type == 'IPv6'
    cmd = 'show {} route {} {}'.format('ipv6' if is_v6 else 'ip',
                                       '-n {}'.format(ns) if ns else '', last_prefix)
    cmd = ' '.join(cmd.split())
    out = dh.shell(cmd, module_ignore_errors=True).get('stdout', '')
    expected = [(j, tgen_ports[j]['ipv6' if is_v6 else 'ip']) for j in range(1, k + 1)]
    found, missing = [], []
    for j, nh in expected:
        pattern = r'(?<![0-9A-Za-z:.]){}(?![0-9A-Za-z:])'.format(re.escape(nh))
        (found if re.search(pattern, out, re.IGNORECASE) else missing).append(nh)
    ok = not missing
    logger.info('Iteration %d, %d link(s): "%s" on %s -> next hops found %s, missing %s: %s\n%s',
                iteration, k, cmd, dh.hostname, found, missing, 'OK' if ok else 'ECMP INCOMPLETE', out)
    if not ok:
        logger.warning('Iteration %d: last prefix %s is missing next hop(s) %s although port_metrics '
                       'reports convergence', iteration, last_prefix, missing)
    return {'ok': ok, 'found': found, 'missing': missing}


# syncd route programming log, e.g.
# "2026 Oct 23 23:03:01.650484 H6-128-CL-01 NOTICE syncd#syncd: :- inc: 10000 (calls 10)
#  Syncd::syncUpdateRedisBulkQuadEvent op took: 80 ms"
# Only the functions listed below are parsed. The log of the first link may instead come from
# Syncd::processBulkCreateEntry(route_entry) CREATE op took: N ms; add 'processBulkCreateEntry'
# to the list to include it (the pattern below already accepts that format).
_SYNCD_ROUTE_FUNCS = ['syncUpdateRedisBulkQuadEvent']
_SYNCD_ROUTE_RE = re.compile(
    r'(\d{4} [A-Za-z]{3}\s+\d+ \d+:\d+:\d+\.\d+)\s+\S+\s+\w+\s+syncd\d*#syncd:\s+:-\s+'
    r'inc:\s+(\d+)\s+\(calls\s+(\d+)\)\s+Syncd::(?:' + '|'.join(_SYNCD_ROUTE_FUNCS) + r')'
    r'(?:\(\w+\))?\s+(?:[A-Z]+\s+)?op took:\s+(\d+)\s+ms')
_SYSLOG_TS_FMT = '%Y %b %d %H:%M:%S.%f'


def _parse_syslog_ts(text):
    return datetime.datetime.strptime(' '.join(text.split()), _SYSLOG_TS_FMT)


def _dut_now(duthost):
    """DUT wall clock (same timezone/format as syslog) or None."""
    try:
        out = duthost.shell("date '+%Y %b %d %H:%M:%S.%6N'", module_ignore_errors=True)['stdout']
        return _parse_syslog_ts(out.strip())
    except Exception as exc:
        logger.warning('Unable to read DUT time on %s: %s', duthost.hostname, exc)
        return None


def _syncd_route_op_stats(duthost, since):
    """
    Parse the syncd route programming ``op took`` syslog lines (``_SYNCD_ROUTE_FUNCS``) written on
    ``duthost`` at or after ``since`` (DUT clock). Returns None when no line matches, otherwise
    the timestamp of the first and last log and the time between them (``span_ms``).
    """
    out = duthost.shell('sudo grep -h -E "Syncd::({}).*op took" /var/log/syslog /var/log/syslog.1 '
                        '2>/dev/null'.format('|'.join(_SYNCD_ROUTE_FUNCS)),
                        module_ignore_errors=True).get('stdout', '')
    stamps = []
    for line in out.splitlines():
        m = _SYNCD_ROUTE_RE.search(line)
        if not m:
            continue
        ts = _parse_syslog_ts(m.group(1))
        if since is not None and ts < since:
            continue
        stamps.append(ts)
    if not stamps:
        return None
    first, last = min(stamps), max(stamps)
    return {'first_ts': first, 'last_ts': last,
            'span_ms': (last - first).total_seconds() * 1000.0}


def _log_syncd_route_stats(hosts_since, iteration, k):
    """
    For every DUT in ``hosts_since`` ({hostname: (duthost, since)}) read the syncd route
    programming logs written since the advertise request and log the first log, the last log and
    the time between them. Returns {hostname: stats or None}.
    """
    all_stats = {}
    for hostname, (dh, since) in hosts_since.items():
        s = _syncd_route_op_stats(dh, since)
        all_stats[hostname] = s
        rows = []
        if s is not None:
            rows.append([s['first_ts'].strftime('%H:%M:%S.%f'), s['last_ts'].strftime('%H:%M:%S.%f'),
                         '%.1f' % s['span_ms']])
        logger.info(
            '\nsyncd route programming (%s) on %s, iteration %d, %d link(s) in ECMP (logs since '
            'advertise at DUT time %s)\n%s', ','.join(_SYNCD_ROUTE_FUNCS), hostname, iteration, k,
            since,
            tabulate(rows, headers=['First log', 'Last log', 'Last-First (ms)'], tablefmt='psql')
            if rows else 'no matching syncd log found')
    return all_stats


def _syncd_result_fields(syncd_stats, preferred_host):
    """
    Pick the syncd stats reported in the tables: the ingress DUT (``preferred_host``) when it has
    logs, otherwise the first DUT that has. Returns a dict of result fields (values None if none).
    """
    hosts = [preferred_host] + [h for h in syncd_stats if h != preferred_host]
    for host in hosts:
        st = syncd_stats.get(host)
        if st:
            return {'syncd_host': host, 'syncd_first_ts': st['first_ts'],
                    'syncd_last_ts': st['last_ts'], 'syncd_span_ms': st['span_ms']}
    return {'syncd_host': None, 'syncd_first_ts': None, 'syncd_last_ts': None,
            'syncd_span_ms': None}


def _get_port_rates(snappi_api):
    """Return {port_name: (frames_rx_rate, frames_tx_rate)} from snappi port_metrics."""
    request = snappi_api.metrics_request()
    rates = {}
    for pm in snappi_api.get_metrics(request).port_metrics:
        rates[pm.name] = (float(pm.frames_rx_rate or 0), float(pm.frames_tx_rate or 0))
    return rates


def _log_bgp_diagnostics(snappi_api, route_type, context):
    """Best effort: log IXIA emulated BGP peer state and advertised/withdrawn route counters."""
    try:
        request = snappi_api.metrics_request()
        if route_type == 'IPv6':
            request.bgpv6.peer_names = []
            peers = snappi_api.get_metrics(request).bgpv6_metrics
        else:
            request.bgpv4.peer_names = []
            peers = snappi_api.get_metrics(request).bgpv4_metrics
        for peer in peers:
            logger.info('[%s] BGP peer %s: session_state=%s flaps=%s routes_advertised=%s '
                        'routes_withdrawn=%s', context, peer.name,
                        getattr(peer, 'session_state', None),
                        getattr(peer, 'session_flap_count', None),
                        getattr(peer, 'routes_advertised', None),
                        getattr(peer, 'routes_withdrawn', None))
    except Exception as exc:
        logger.warning('[%s] Unable to read IXIA BGP peer metrics: %s', context, exc)


def _wait_port_rx_threshold(snappi_api, port_name, tx_rate, threshold_pct, t_start,
                            start_timeout=LINK_CONVERGENCE_TIMEOUT_START_SEC,
                            step_timeout=LINK_CONVERGENCE_TIMEOUT_STEP_SEC,
                            max_timeout=LINK_CONVERGENCE_TIMEOUT_MAX_SEC,
                            on_extend=None):
    """
    Poll port_metrics until ``port_name`` Rx frame rate reaches ``threshold_pct`` percent of
    ``tx_rate``.

    The deadline starts at ``start_timeout`` seconds after ``t_start`` and is extended by
    ``step_timeout`` every time it expires, up to ``max_timeout`` seconds overall. At every
    extension the current per-port rates are logged and ``on_extend(elapsed_sec)`` is called.

    Args:
        t_start: ``time.monotonic()`` value taken immediately before the advertise request.
        on_extend: optional callback for extra diagnostics at each deadline extension.

    Returns:
        (elapsed_ms or None on timeout, last_rates)
    """
    target = tx_rate * threshold_pct / 100.0
    deadline = start_timeout
    rates = {}
    while True:
        rates = _get_port_rates(snappi_api)
        now = time.monotonic()
        elapsed = now - t_start
        rx = rates.get(port_name, (0.0, 0.0))[0]
        if rx >= target:
            return elapsed * 1000.0, rates
        if elapsed > deadline:
            if deadline >= max_timeout:
                logger.error('Timeout (%ss) waiting for %s Rx rate %.1f >= %.1f (%.2f%% of Tx %.1f); '
                             'per-port rates (rx, tx): %s',
                             max_timeout, port_name, rx, target, threshold_pct, tx_rate, rates)
                return None, rates
            logger.warning('%s has not reached %.2f%% of Tx after %ds (Rx %.1f fps, target %.1f fps); '
                           'per-port rates (rx, tx): %s; extending wait to %ds',
                           port_name, threshold_pct, deadline, rx, target, rates,
                           min(deadline + step_timeout, max_timeout))
            if on_extend is not None:
                on_extend(elapsed)
            deadline = min(deadline + step_timeout, max_timeout)
        if PORT_POLL_INTERVAL_SEC:
            time.sleep(PORT_POLL_INTERVAL_SEC)


def _set_ixia_dp_threshold(snappi_api, threshold_pct):
    """
    Best effort update of the IXIA CP/DP data plane rx-rate threshold (traffic is stopped).
    Returns True when the update was accepted.
    """
    try:
        ix = snappi_api._ixnetwork
        cpdp = ix.Traffic.find().Statistics.find().CpdpConvergence.find()
        logger.info('IXIA CP/DP DataPlaneThreshold before update: %s', cpdp.DataPlaneThreshold)
        cpdp.DataPlaneThreshold = threshold_pct
        logger.info('IXIA CP/DP DataPlaneThreshold after update: %s',
                    cpdp.find().DataPlaneThreshold)
        return True
    except Exception as exc:
        logger.warning('Unable to update IXIA CP/DP threshold to %.2f%% at runtime: %s',
                       threshold_pct, exc)
        return False


def _regenerate_and_apply_traffic(snappi_api):
    """
    Regenerate and apply the IXIA traffic items (needed after the CP/DP threshold changed, before
    the traffic is started). Best effort; returns True on success.
    """
    try:
        ix = snappi_api._ixnetwork
        logger.info('Regenerating traffic items')
        ix.Traffic.TrafficItem.find().Generate()
        logger.info('Applying traffic')
        ix.Traffic.Apply()
        return True
    except Exception as exc:
        logger.warning('Unable to regenerate/apply IXIA traffic: %s', exc)
        return False


def _set_traffic_state(snappi_api, start):
    cs = snappi_api.control_state()
    cs.traffic.flow_transmit.state = (cs.traffic.flow_transmit.START if start
                                      else cs.traffic.flow_transmit.STOP)
    snappi_api.set_control_state(cs)


def _wait_ingress_tx(snappi_api, ingress_port, started, timeout_sec=TRAFFIC_POLL_TIMEOUT_SEC):
    """
    Poll until the ingress Tx frame rate is non-zero (``started``) or zero (stopped).
    Returns ``(reached, last_tx_rate)``.
    """
    deadline = time.monotonic() + timeout_sec
    tx = 0.0
    while True:
        tx = _get_port_rates(snappi_api).get(ingress_port, (0.0, 0.0))[1]
        if (tx > 0) == started:
            return True, tx
        if time.monotonic() > deadline:
            return False, tx
        time.sleep(1)


def _wait_advertised_links_balanced(snappi_api, bgp_config, ingress_port, k,
                                    timeout_sec=PRE_ADVERTISE_STABLE_TIMEOUT_SEC,
                                    tolerance_pct=PRE_ADVERTISE_TOLERANCE_PCT):
    """
    Before link ``k`` is advertised links 1..k-1 are the only ones receiving traffic: wait until
    each of them carries ``Tx/(k-1)`` within ``tolerance_pct`` (percent of Tx rate).
    Returns ``(ok, tx_rate, rates, deviations_pct)`` from the last sample.
    """
    deadline = time.monotonic() + timeout_sec
    while True:
        rates = _get_port_rates(snappi_api)
        tx_rate = rates.get(ingress_port, (0.0, 0.0))[1]
        devs = []
        for j in range(1, k):
            rx = rates.get(bgp_config.ports[j].name, (0.0, 0.0))[0]
            devs.append(abs(rx - tx_rate / (k - 1)) * 100.0 / tx_rate if tx_rate > 0 else None)
        ok = tx_rate > 0 and all(d is not None and d <= tolerance_pct for d in devs)
        if ok or time.monotonic() > deadline:
            return ok, tx_rate, rates, [None if d is None else round(d, 2) for d in devs]
        time.sleep(1)


def _read_ixia_cpdp_rows(snappi_api, context):
    """
    Read IXIA CP/DP ``convergence_metrics``, log every row (``context`` labels the log lines)
    and return a list of dicts: ``idx``, ``detail`` (serialized row), ``cpdp_ms`` (CP/DP, None
    when the row has no value) and ``events`` (list of ``{'type', 'source', ...}``). snappi
    returns one row per traffic item; the ``events`` of the row name the route range (``source``)
    that triggered the measurement. Returns None when the metrics cannot be read.
    """
    try:
        request = snappi_api.metrics_request()
        request.convergence.flow_names = []
        raw_rows = list(snappi_api.get_metrics(request).convergence_metrics)
    except Exception as exc:
        logger.warning('%s: unable to read IXIA convergence metrics: %s', context, exc)
        return None
    rows = []
    for n, row in enumerate(raw_rows):
        try:
            detail = row.serialize(row.DICT)
        except Exception:
            detail = str(row)
        detail_dict = detail if isinstance(detail, dict) else {}
        cp_dp_us = getattr(row, 'control_plane_data_plane_convergence_us', None)
        rows.append({'idx': n, 'detail': detail,
                     'cpdp_ms': None if cp_dp_us is None else cp_dp_us / 1000.0,
                     'events': list(detail_dict.get('events') or [])})
        logger.info('%s: IXIA convergence metric row %d: %s', context, n, detail)
    return rows


def _wait_ixia_cpdp_result(snappi_api, link_idx, route_name,
                           timeout_sec=CPDP_RESULT_TIMEOUT_SEC):
    """
    Poll IXIA CP/DP ``convergence_metrics`` for the result of the link under test.

    A row is this link's result only if it has a non-zero CP/DP value and one of its ``events`` is
    a ``route_advertise`` whose ``source`` is ``route_name`` (the route range advertised on this
    link). Anything else (no event, other route range) is ignored. The caller stores the returned
    value for this link once and never reads it again, so rows shown while other links are tested
    cannot change it.

    Returns ``(cpdp_ms, status)``; status is ``'ok'``, ``'no_matching_event'`` (a CP/DP value was
    present but never for this route range; value is None) or ``'none'``.
    """
    context = 'Link %d CP/DP' % link_idx
    deadline = time.monotonic() + timeout_sec
    seen_other = False
    while True:
        rows = _read_ixia_cpdp_rows(snappi_api, context) or []
        for row in rows:
            if not row['cpdp_ms']:
                continue
            if any(ev.get('source') == route_name
                   and ev.get('type', 'route_advertise') == 'route_advertise'
                   for ev in row['events']):
                logger.info('%s: result CP/DP %.3f ms (event source %s)',
                            context, row['cpdp_ms'], route_name)
                return row['cpdp_ms'], 'ok'
            seen_other = True
        if time.monotonic() > deadline:
            break
        time.sleep(CPDP_POLL_INTERVAL_SEC)
    if seen_other:
        logger.warning('%s: CP/DP value present but no route_advertise event for %s within %ss; '
                       'ignoring it', context, route_name, timeout_sec)
        return None, 'no_matching_event'
    logger.warning('%s: no CP/DP convergence value within %ss', context, timeout_sec)
    return None, 'none'


def _fmt_ms(value):
    return 'n/a' if value is None else '%.1f' % value


def _mean(values):
    vals = [v for v in values if v is not None]
    return sum(vals) / len(vals) if vals else None


def _fmt_clock(ts):
    return 'n/a' if ts is None else ts.strftime('%H:%M:%S.%f')


def _log_iteration_table(iter_results, iteration, iterations, route_type, number_of_routes, multipath):
    rows = []
    for r in iter_results:
        delta = None
        if r['ixia_ms'] is not None and r['port_metrics_ms'] is not None:
            delta = r['ixia_ms'] - r['port_metrics_ms']
        rows.append([r['link'], r['port'], r['route_name'], '%.2f' % r['threshold_pct'],
                     _fmt_ms(r['ixia_ms']), _fmt_ms(r['port_metrics_ms']), _fmt_ms(delta),
                     _fmt_clock(r.get('syncd_first_ts')), _fmt_clock(r.get('syncd_last_ts')),
                     _fmt_ms(r.get('syncd_span_ms')),
                     (r.get('dut_route_counts') or {}).get('nhg_summary'),
                     (r.get('dut_route_counts') or {}).get('asic_db'),
                     'yes' if r['balanced'] else 'NO',
                     _fmt_ms(r.get('dut_dev_pct')), _fmt_ms(r.get('ixia_dev_pct')),
                     {None: 'n/a', True: 'yes', False: 'NO'}[r.get('counters_balanced')],
                     {None: 'n/a', True: 'yes', False: 'NO'}[r.get('last_prefix_ecmp_ok')]])
    columns = ['Links in ECMP', 'Port added', 'Route Group', 'Threshold %', 'IXIA CP/DP (ms)',
               'port_metrics (ms, ~1s resolution)', 'Delta (ms)', 'syncd first log',
               'syncd last log', 'syncd Last-First (ms)', 'nexthop-group summary lines',
               'ASIC_DB routes with NHG', 'ECMP balanced',
               'DUT TX dev %', 'IXIA Rx dev %', 'Counters within tol',
               'Last pfx all NHs']
    logger.info("\nDynamic ECMP link addition, iteration %d/%d (%s, %d routes, ECMP=%d)\n%s",
                iteration, iterations, route_type, number_of_routes, multipath,
                tabulate(rows, headers=columns, tablefmt="psql"))


def _log_summary(results, iterations, route_type, number_of_routes, multipath):
    """
    Log one SUMMARY table: for every link count and iteration the port_metrics convergence, the
    IXIA CP/DP convergence and the syncd first log / last log / Last-First, followed by an
    "average" row per link count (clock times are not averaged).
    """
    by_key = {(r['iteration'], r['link']): r for r in results}
    done_iterations = sorted({r['iteration'] for r in results})
    if not done_iterations:
        logger.warning('No dynamic ECMP results to summarize')
        return

    rows = []
    for k in range(1, multipath + 1):
        per_iter = [by_key.get((i, k)) for i in range(1, iterations + 1)]
        for i, r in enumerate(per_iter, start=1):
            if r is None:
                continue
            rows.append(['%d link(s)' % k, i, '%.2f' % (BASE_RX_THRESHOLD_PCT / k),
                         _fmt_ms(r['port_metrics_ms']), _fmt_ms(r['ixia_ms']),
                         _fmt_clock(r.get('syncd_first_ts')), _fmt_clock(r.get('syncd_last_ts')),
                         _fmt_ms(r.get('syncd_span_ms'))])
        done = [r for r in per_iter if r is not None]
        if done:
            rows.append(['%d link(s)' % k, 'average', '%.2f' % (BASE_RX_THRESHOLD_PCT / k),
                         _fmt_ms(_mean([r['port_metrics_ms'] for r in done])),
                         _fmt_ms(_mean([r['ixia_ms'] for r in done])), '', '',
                         _fmt_ms(_mean([r.get('syncd_span_ms') for r in done]))])
    columns = ['ECMP links', 'Iteration', 'Threshold %', 'port_metrics (ms, ~1s resolution)',
               'IXIA CP/DP (ms)', 'syncd first log (DUT clock)', 'syncd last log (DUT clock)',
               'syncd Last-First (ms)']
    logger.info("\nSUMMARY: %s, %d routes, ECMP=%d, completed iterations=%s/%d\n%s",
                route_type, number_of_routes, multipath, done_iterations, iterations,
                tabulate(rows, headers=columns, tablefmt="psql"))


def get_dynamic_ecmp_link_addition_convergence(snappi_api,
                                               bgp_config,
                                               ng_list,
                                               multipath,
                                               number_of_routes,
                                               route_type,
                                               timeout=None,
                                               settle_sec=DEFAULT_SETTLE_SEC,
                                               iterations=DEFAULT_ITERATIONS,
                                               mem_cpu_monitor=None,
                                               tgen_ports=None):
    """
    Add egress links to ECMP one at a time and measure convergence on each. For every link the
    traffic is stopped, the CP/DP threshold is set to ``96/k`` percent, the traffic is
    regenerated/applied and restarted (routes of earlier links stay advertised) before the routes
    of link k are advertised. The whole sequence is repeated ``iterations`` times; every iteration
    starts with the BGP sessions up and all routes withdrawn, and finishes by stopping traffic,
    withdrawing all routes and stopping the protocols.

    Args:
        snappi_api: snappi API
        bgp_config: config returned by ``build_tgen_bgp_config``
        ng_list: route range names, ng_list[k-1] belongs to egress link k
        multipath: ECMP width N (number of egress links)
        number_of_routes: routes per egress peer
        route_type: IPv4 or IPv6
        timeout: seconds for protocol/route steps
        settle_sec: sleep after each link addition before the steady-state checks
        iterations: number of times the full link-addition sequence is run
        mem_cpu_monitor: optional mem_cpu_monitor controller (snapshots only; test stops it)
        tgen_ports: tgen port mapping; enables the DUT counter based ECMP distribution check
            (clear counters, wait ``ECMP_COUNTER_WINDOW_SEC``, compare links) after each link

    Returns:
        list of per-link, per-iteration result dicts (key ``iteration`` is 1-based)
    """
    if timeout is None:
        timeout = TIMEOUT
    pytest_assert(iterations >= 1, 'iterations must be >= 1')
    pytest_assert(len(ng_list) == multipath,
                  'Expected {} route ranges, got {}'.format(multipath, len(ng_list)))
    all_route_names = list(ng_list)
    ingress_port = bgp_config.ports[0].name
    logger.info('Route list: %s', all_route_names)

    bgp_config.events.cp_events.enable = True
    bgp_config.events.dp_events.enable = True
    bgp_config.events.dp_events.rx_rate_threshold = BASE_RX_THRESHOLD_PCT
    snappi_api.set_config(bgp_config)

    # Outstanding sonic-mgmt issue 23744.
    set_bgp_as_path_segment_type_asseq(snappi_api)

    dut_targets = None
    ingress_target = None
    probe_prefixes = None
    if tgen_ports is not None:
        try:
            dut_targets = _dut_ecmp_targets(tgen_ports, multipath)
            ingress_target = _dut_port_target(tgen_ports[0])
            probe_prefixes = _route_probe_prefixes(route_type, number_of_routes)
            logger.info('ECMP counter check targets: %s; route prefixes (first/mid/last): %s',
                        [(t['duthost'].hostname, t['ns'], t['name'], t['ports'])
                         for t in dut_targets], probe_prefixes)
        except Exception:
            logger.exception('Unable to set up DUT counter check; it will be skipped')
            dut_targets = None
            ingress_target = None

    def _snapshot(event):
        if mem_cpu_monitor is not None:
            mem_cpu_monitor.snapshot(event=event)

    def _route_state(names, state_name):
        cs = snappi_api.control_state()
        cs.protocol.route.names = names
        cs.protocol.route.state = getattr(cs.protocol.route, state_name)
        snappi_api.set_control_state(cs)

    def _run_iteration(iteration):
        """Run one full link-addition sequence; return the per-link results."""
        iter_results = []
        tag = 'iter_{}'.format(iteration)
        traffic_started = False
        protocols_started = False
        try:
            logger.info('Starting all protocols ...')
            cs = snappi_api.control_state()
            cs.protocol.all.state = cs.protocol.all.START
            snappi_api.set_control_state(cs)
            protocols_started = True
            _snapshot('Protocols_Started_{}'.format(tag))
            wait(PROTOCOL_START_WAIT_SEC, "For Protocols To start")

            # Starting the protocols advertises every route range, so withdraw afterwards.
            logger.info('Withdraw routes on all %d egress links', multipath)
            _route_state(all_route_names, 'WITHDRAW')
            _snapshot('Route_Withdrawal_Start_{}'.format(tag))
            wait(timeout, "For Routes to be withdrawn")

            for k in range(1, multipath + 1):
                link_port = bgp_config.ports[k].name
                route_name = all_route_names[k - 1]
                threshold_pct = BASE_RX_THRESHOLD_PCT / k
                logger.info('|---- Iteration %d/%d: adding ECMP link %d/%d (%s, %s), '
                            'threshold %.2f%% ----|',
                            iteration, iterations, k, multipath, link_port, route_name,
                            threshold_pct)

                # Traffic is stopped here: update the CP/DP threshold, regenerate/apply the
                # traffic items, then (re)start traffic. Routes of links 1..k-1 stay advertised,
                # so traffic flows to them.
                ixia_threshold_ok = _set_ixia_dp_threshold(snappi_api, threshold_pct)
                _regenerate_and_apply_traffic(snappi_api)

                logger.info('Starting Traffic for link %d', k)
                _set_traffic_state(snappi_api, True)
                traffic_started = True
                _snapshot('Traffic_Started_link_{}_{}'.format(k, tag))
                started, tx_now = _wait_ingress_tx(snappi_api, ingress_port, True)
                pytest_assert(started, 'Traffic did not start: ingress {} Tx rate {}'.format(
                    ingress_port, tx_now))

                if k > 1:
                    ok, tx_rate, before, devs = _wait_advertised_links_balanced(
                        snappi_api, bgp_config, ingress_port, k)
                    logger.info('Link %d pre-advertise Rx split of advertised links (deviation %% of '
                                'Tx, tolerance %.1f%%): %s; per-port rates (rx, tx): %s',
                                k, PRE_ADVERTISE_TOLERANCE_PCT, devs, before)
                    pytest_assert(ok, 'Iteration {}: before advertising link {}, links 1..{} did not '
                                  'settle at Tx/{} within {}s (deviation % of Tx: {})'.format(
                                      iteration, k, k - 1, k - 1,
                                      PRE_ADVERTISE_STABLE_TIMEOUT_SEC, devs))
                else:
                    before = _get_port_rates(snappi_api)
                    tx_rate = before[ingress_port][1]
                pytest_assert(tx_rate > 0,
                              'Ingress port {} is not transmitting'.format(ingress_port))
                logger.info('Before advertise: ingress Tx rate %.1f fps, per-port rates '
                            '(rx, tx): %s', tx_rate, before)

                _log_bgp_diagnostics(snappi_api, route_type,
                                     'iter {} link {} before advertise'.format(iteration, k))
                syncd_since, syncd_stats = {}, {}   # keep: defaults when the syncd blocks are disabled
                # ---- syncd log window start (DUT clock): comment out together with the
                # "syncd route bulk-op timing" block after the settle sleep. ----
                if tgen_ports is not None:
                    for entry in tgen_ports[:multipath + 1]:
                        dh = entry['duthost']
                        if dh.hostname not in syncd_since:
                            syncd_since[dh.hostname] = (dh, _dut_now(dh))
                # ---- end of syncd log window start ----
                _snapshot('Before_Route_Advertise_link_{}_{}'.format(k, tag))
                t_start = time.monotonic()
                _route_state([route_name], 'ADVERTISE')
                port_ms, rates = _wait_port_rx_threshold(
                    snappi_api, link_port, tx_rate, threshold_pct, t_start,
                    on_extend=lambda elapsed, k=k: _log_bgp_diagnostics(
                        snappi_api, route_type,
                        'iter {} link {} waiting, {:.0f}s after advertise'.format(
                            iteration, k, elapsed)))
                _snapshot('After_Route_Advertise_link_{}_{}'.format(k, tag))
                if port_ms is None:
                    _log_bgp_diagnostics(snappi_api, route_type,
                                         'iter {} link {} timeout'.format(iteration, k))
                pytest_assert(port_ms is not None,
                              'Iteration {}: link {} ({}) did not reach {:.2f}% of Tx rate '
                              'within {}s'.format(iteration, k, link_port, threshold_pct,
                                                  LINK_CONVERGENCE_TIMEOUT_MAX_SEC))
                logger.info('Iteration %d link %d port_metrics convergence: %.1f ms '
                            '(rates at crossing: %s)', iteration, k, port_ms, rates)

                # IXIA CP/DP value of the link under test; stored once, never overwritten by rows
                # that show up while later links are tested (matched by route range event).
                ixia_ms, ixia_status = _wait_ixia_cpdp_result(snappi_api, k, route_name)
                if not ixia_threshold_ok:
                    logger.warning('Iteration %d link %d: IXIA threshold could not be updated; '
                                   'the IXIA value (%s ms) was evaluated against the previous '
                                   'threshold', iteration, k, ixia_ms)

                route_counts = {'nhg_summary': None, 'asic_db': None}   # keep: default when disabled
                # ---- DUT route counts (display only): comment out this block to disable. ----
                if tgen_ports is not None:
                    try:
                        route_counts = _show_dut_route_counts(
                            tgen_ports, route_type, number_of_routes, k, iteration)
                    except Exception:
                        logger.exception('DUT route count CLIs failed (iteration %d, link %d)',
                                         iteration, k)
                # ---- end of DUT route counts ----

                last_pfx_res = {'ok': None}   # keep: default used when the block below is disabled
                # ---- Last-prefix ECMP check: comment out this block to disable. ----
                if dut_targets is not None:
                    try:
                        last_pfx_res = _check_last_prefix_ecmp(
                            tgen_ports, route_type, probe_prefixes[-1], k, iteration)
                    except Exception:
                        logger.exception('Last prefix route check failed (iteration %d, link %d)',
                                         iteration, k)
                # ---- end of last-prefix ECMP check ----

                logger.info('Waiting %ss for link %d to settle', settle_sec, k)
                time.sleep(settle_sec)

                # ---- syncd route bulk-op timing: comment out this block to disable. ----
                if syncd_since:
                    try:
                        syncd_stats = _log_syncd_route_stats(syncd_since, iteration, k)
                    except Exception:
                        logger.exception('syncd route log parsing failed (iteration %d, link %d)',
                                         iteration, k)
                # ---- end of syncd route bulk-op timing ----

                flows = get_flow_stats(snappi_api)
                sum_tx = sum(f.frames_tx_rate for f in flows)
                sum_rx = sum(f.frames_rx_rate for f in flows)
                tol_fps = _traffic_converged_tolerance_fps(
                    tgen_ports[0].get('speed') if tgen_ports else None, tx_rate)
                pytest_assert(abs(sum_tx - sum_rx) < tol_fps,
                              "Traffic has not converged after adding link {}: TxFrameRate:{}, "
                              "RxFrameRate:{} (tolerance {:.0f} fps = {}% of line rate)".format(
                                  k, sum_tx, sum_rx, tol_fps, TRAFFIC_CONVERGED_TOLERANCE_PCT))

                settled = _get_port_rates(snappi_api)
                expected_share = tx_rate / k
                balanced = True
                for j in range(1, k + 1):
                    name = bgp_config.ports[j].name
                    rx = settled[name][0]
                    dev_pct = abs(rx - expected_share) * 100.0 / tx_rate
                    logger.info('Link %d/%d (%s): Rx %.1f fps, expected %.1f fps '
                                '(deviation %.2f%% of Tx)', j, k, name, rx, expected_share, dev_pct)
                    if dev_pct > BALANCE_TOLERANCE_PCT:
                        balanced = False
                        logger.warning('Link %s deviates %.2f%% of Tx from the expected ECMP '
                                       'share (tolerance %.1f%%)', name, dev_pct,
                                       BALANCE_TOLERANCE_PCT)

                counter_res = {'dut_dev_pct': None, 'ixia_dev_pct': None,
                               'counters_balanced': None}
                if dut_targets is not None:
                    try:
                        counter_res = _check_ecmp_counter_balance(
                            snappi_api, bgp_config, dut_targets, k, iteration)
                    except Exception:
                        logger.exception('ECMP counter check failed (iteration %d, link %d)',
                                         iteration, k)

                ingress_host = tgen_ports[0]['duthost'].hostname if tgen_ports else None
                iter_results.append({
                    'syncd_route_stats': syncd_stats,
                    'dut_route_counts': route_counts,
                    'last_prefix_ecmp_ok': last_pfx_res['ok'],
                    'dut_dev_pct': counter_res['dut_dev_pct'],
                    'ixia_dev_pct': counter_res['ixia_dev_pct'],
                    'counters_balanced': counter_res['counters_balanced'],
                    'iteration': iteration,
                    'link': k,
                    'port': link_port,
                    'route_name': route_name,
                    'threshold_pct': threshold_pct,
                    'port_metrics_ms': port_ms,
                    'ixia_ms': ixia_ms,
                    'ixia_cpdp_status': ixia_status,
                    'ixia_threshold_updated': ixia_threshold_ok,
                    'balanced': balanced,
                })
                iter_results[-1].update(_syncd_result_fields(syncd_stats, ingress_host))

                # Result recorded: stop traffic before the next link (routes stay advertised).
                logger.info('Stopping Traffic after link %d', k)
                _set_traffic_state(snappi_api, False)
                traffic_started = False
                _snapshot('Traffic_Stopped_link_{}_{}'.format(k, tag))
                stopped, tx_now = _wait_ingress_tx(snappi_api, ingress_port, False)
                if not stopped:
                    logger.warning('Ingress Tx rate still %.1f fps %ss after stopping traffic',
                                   tx_now, TRAFFIC_POLL_TIMEOUT_SEC)

                # DUT interface counters with traffic stopped: clear them after link 1; after
                # links 2 and 3 the ingress RX_OK must not exceed the egress TX_OK.
                if ingress_target is not None:
                    if k == 1:
                        _clear_dut_counters([ingress_target] + dut_targets)
                    elif k in (2, 3):
                        rx_ok, rx_total, tx_total = _check_rx_le_tx(
                            ingress_target, dut_targets, k, iteration)
                        pytest_assert(rx_ok,
                                      'Iteration {}: after link {} the DUT ingress RX_OK ({}) exceeds the '
                                      'egress TX_OK of links 1..{} ({}) by more than {}% (or no counters '
                                      'were read)'.format(iteration, k, rx_total, k, tx_total,
                                                          RX_TX_MARGIN_PCT))
                else:
                    logger.warning('DUT counter targets unavailable: counter clear / Rx<=Tx check skipped')
        finally:
            try:
                if traffic_started:
                    logger.info('Stopping Traffic')
                    _set_traffic_state(snappi_api, False)
                    _snapshot('Traffic_Stopped_{}'.format(tag))
                    _wait_ingress_tx(snappi_api, ingress_port, False)
                if protocols_started:
                    logger.info('Withdraw all routes and stop protocols')
                    _route_state(all_route_names, 'WITHDRAW')
                    wait(timeout, "For Routes to be withdrawn")
                    cs = snappi_api.control_state()
                    cs.protocol.all.state = cs.protocol.all.STOP
                    snappi_api.set_control_state(cs)
                    _snapshot('After_protocol_stop_{}'.format(tag))
                    wait(timeout, "For Protocols To STOP")
            except Exception:
                logger.exception('Error while tearing down traffic/protocols')
        return iter_results

    results = []
    try:
        for iteration in range(1, iterations + 1):
            logger.info('|======== Dynamic ECMP link addition: iteration %d/%d ========|',
                        iteration, iterations)
            iter_results = _run_iteration(iteration)
            results.extend(iter_results)
            _log_iteration_table(iter_results, iteration, iterations, route_type,
                                 number_of_routes, multipath)
    finally:
        # Also printed when an iteration fails, using the iterations completed so far.
        _log_summary(results, iterations, route_type, number_of_routes, multipath)
    return results


def run_dynamic_ecmp_link_addition_test(snappi_api,
                                        duthost,
                                        tgen_ports,
                                        multipath,
                                        number_of_routes,
                                        route_type,
                                        timeout=None,
                                        skip_cleanup=None,
                                        skip_duthost_bgp_config=False,
                                        settle_sec=DEFAULT_SETTLE_SEC,
                                        iterations=DEFAULT_ITERATIONS,
                                        mem_cpu_monitor=None):
    """
    Run the dynamic ECMP link addition test.

    Args:
        snappi_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): tgen port mapping; index 0 ingress, 1..multipath egress
        multipath: ECMP width N (egress links)
        number_of_routes: number of IPv4/IPv6 routes advertised by each egress peer
        route_type: IPv4 or IPv6
        timeout: seconds for protocol/route steps
        skip_cleanup: skip DUT config cleanup (the test fixture reverts config)
        skip_duthost_bgp_config: use existing DUT config (``--bgp_pc_config``)
        settle_sec: settle time after each link addition
        iterations: number of repetitions of the full link-addition sequence
        mem_cpu_monitor: optional mem_cpu_monitor fixture
    """
    if timeout is None:
        timeout = TIMEOUT
    pytest_assert(multipath >= 1, 'multipath must be >= 1')
    port_count = multipath + 1
    pytest_assert(len(tgen_ports) >= port_count,
                  'Need {} tgen_ports, have {}'.format(port_count, len(tgen_ports)))

    tag_tier2_leak = _should_tag_tier2_leak_communities(duthost, tgen_ports, port_count)

    if not skip_duthost_bgp_config:
        duthost_bgp_config(duthost, tgen_ports, port_count, route_type)

    try:
        tgen_config, ng_list = build_tgen_bgp_config(
            snappi_api, tgen_ports, port_count, number_of_routes, route_type,
            skip_duthost_bgp_config=skip_duthost_bgp_config,
            tag_tier2_leak_communities=tag_tier2_leak)

        results = get_dynamic_ecmp_link_addition_convergence(
            snappi_api, tgen_config, ng_list, multipath, number_of_routes, route_type,
            timeout=timeout, settle_sec=settle_sec, iterations=iterations,
            mem_cpu_monitor=mem_cpu_monitor, tgen_ports=tgen_ports)
    finally:
        if not skip_cleanup:
            cleanup_config(duthost)
    return results
