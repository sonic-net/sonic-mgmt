"""
Test utils used by the link flap tests.
"""
import json
import logging
import math
import os
import random
import re
import time
import yaml

from collections import defaultdict

from tests.common.platform.device_utils import fanout_switch_port_lookup, __get_dut_if_status
from tests.common.utilities import get_day_of_week_distributed_ports_from_buckets

logger = logging.getLogger(__name__)


def __build_candidate_list(candidates, fanout, fanout_port, dut_port, status):
    """
    Add candidates to list for link flap test.

    Args:
        candidates: List of tuple with DUT's port,
        fanout port and fanout
        fanout: Fanout host object
        fanout_port: Port of fanout
        dut_port: Port of DUT
        completeness_level: Completeness level.

    Returns:
        A list of tuple with DUT's port, fanout port
        and fanout
    """
    if not fanout or not fanout_port:
        logger.info("Skipping port {} that is not found in connection graph".format(dut_port))
    elif status[dut_port]['admin_state'] == 'down':
        logger.info("Skipping port {} that is admin down".format(dut_port))
    else:
        candidates.append((dut_port, fanout, fanout_port))


def build_test_candidates(dut, fanouthosts, port, completeness_level=None):
    """
    Find test candidates for link flap test.

    Args:
        dut: DUT host object
        fanouthosts: List of fanout switch instances.
        port: port, when port == 'unknown' or 'all_ports'
              candidate will be all ports. A warning  will
              be generated if the port == 'unknown'.
              caller can use 'all_ports' explicitly to mute
              the warning.
        completeness_level: Completeness level.

    Returns:
        A list of tuple with DUT's port, fanout port
        and fanout
    """
    candidates = []

    if port not in ['unknown', 'all_ports']:
        status = __get_dut_if_status(dut, port)
        fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, dut.hostname, port)
        __build_candidate_list(candidates, fanout, fanout_port, port, status)
    else:
        # Build the full list
        if port == 'unknown':
            logger.warning("Failed to get ports enumerated as parameter. Fall back to test all ports")
        status = __get_dut_if_status(dut)

        for dut_port in list(status.keys()):
            fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, dut.hostname, dut_port)
            __build_candidate_list(candidates, fanout, fanout_port, dut_port, status)

        if completeness_level == 'debug':
            candidates = random.sample(candidates, 1)
        elif completeness_level == 'confident':
            candidates = get_day_of_week_distributed_ports_from_buckets(candidates, 32)

    return candidates


def check_portchannel_status(dut, dut_port_channel, exp_state, verbose=False):
    """
    Check portchannel status on the DUT.

    Args:
        dut: DUT host object
        dut_port_channel: Portchannel of DUT
        exp_state: State of DUT's port ('up' or 'down')
        verbose: Logging port state.

    Returns:
        Bool value which confirm port state
    """
    status = __get_dut_if_status(dut, dut_port_channel)[dut_port_channel]
    if verbose:
        logger.debug("Portchannel status : %s", status)
    return status['oper_state'] == exp_state


def check_orch_cpu_utilization(dut, orch_cpu_threshold):
    """
    Compare orchagent CPU utilization

    Args:
        dut: DUT host object
        orch_cpu_threshold: orch cpu threshold
    """
    orch_cpu = dut.shell("COLUMNS=512 show processes cpu | grep orchagent | awk '{print $9}'")["stdout_lines"]
    for line in orch_cpu:
        if int(float(line)) > orch_cpu_threshold:
            return False
    return True


def check_bgp_routes(dut, start_time_ipv4_route_counts, start_time_ipv6_route_counts):
    """
    Make Sure all ip routes are relearned with jitter of ~MAX_DIFF

    Args:
        dut: DUT host object
        start_time_ipv4_route_counts: IPv4 route counts at start
        start_time_ipv6_route_counts: IPv6 route counts at start
    """
    MAX_DIFF = 5

    sumv4, sumv6 = dut.get_ip_route_summary(skip_kernel_tunnel=True, skip_kernel_linkdown=True)
    totalsv4 = sumv4.get('Totals', {})
    totalsv6 = sumv6.get('Totals', {})
    routesv4 = totalsv4.get('routes', 0)
    routesv6 = totalsv6.get('routes', 0)
    logger.info("IPv4 routes: start {} end {}, summary {}".format(start_time_ipv4_route_counts, routesv4, sumv4))
    logger.info("IPv6 routes: start {} end {}, summary {}".format(start_time_ipv6_route_counts, routesv6, sumv6))

    incr_ipv4_route_counts = abs(int(float(start_time_ipv4_route_counts)) - int(float(routesv4)))
    incr_ipv6_route_counts = abs(int(float(start_time_ipv6_route_counts)) - int(float(routesv6)))
    return incr_ipv4_route_counts < MAX_DIFF and incr_ipv6_route_counts < MAX_DIFF


def get_avg_redis_mem_usage(duthost, interval, num_times):
    """
        Redis memory usage is not a stable value. It's fluctuating even when the device is stable stage.
        202205 has larger redis memory usage (~ 5.5M) so the fluctuation of 0.2M is not an issue.
        With 202405 redis memory usage is optimized (~ 2.5M) and 0.2M usage could make the test fail
        if memory threshold is 5%.

        This API returns the average radis memory usage during a period.
        Args:
            duthost: DUT host object
            interval: time interval to wait for next query
            num_times: number of times to query
        """
    logger.info("Checking average redis memory usage")
    cmd = r"redis-cli info memory | grep used_memory_human | sed -e 's/.*:\(.*\)M/\1/'"
    redis_memory = 0.0
    for i in range(num_times):
        redis_memory += float(duthost.shell(cmd)["stdout"])
        time.sleep(interval)
    return float(redis_memory/num_times)


def _redis_info_field(info_output, key):
    """Extract `key:value` line from redis-cli INFO output."""
    m = re.search(r'^{}:(.+)$'.format(re.escape(key)), info_output, re.MULTILINE)
    return m.group(1).strip() if m else None


def _resolve_redis_clients_to_processes(duthost, redis_port=6379):
    """Map each redis client connection to its connecting process, handling
    tcp and unix-socket connections.
      - TCP clients (addr starts with 127.0.0.1: or [::1]:): use `ss -tnp` to
        look up the source-port -> (pid, command) mapping for established
        connections to the redis port.
      - Unix-socket clients (addr is the socket path): use `ss -xpn`. Each
        established u_str pair shows up as two rows -- one owned by
        redis-server with `fd=<server-side fd>` matching CLIENT LIST `fd=`,
        and one owned by the connecting process. The peer-inode column links
        them. Match the redis-server rows by fd to get the peer inode, then
        look up the peer inode in the inode->process map built from all other
        rows.

    Returns a list of dicts, one per redis client, with keys
      {id, addr, fd, tot_mem, omem, process}. `process` is the resolved name
      (e.g. 'tcp:bgpd', 'unix:xcvrd'). When the cross-reference fails (e.g.
      `ss` returned no users field because sudo isn't available, or the
      connection was created between the two shell calls), `process` is
      tagged 'tcp:<unknown>' or 'unix:<unknown>'.
    """
    client_list_raw = duthost.shell("redis-cli client list",
                                    module_ignore_errors=True)["stdout"]
    ss_tcp_raw = duthost.shell(
        f"sudo ss -tnp state established '( sport = :{redis_port} or dport = :{redis_port} )' 2>/dev/null || true",
        module_ignore_errors=True
    )["stdout"]
    ss_unix_raw = duthost.shell(
        "sudo ss -xpn 2>/dev/null || true",
        module_ignore_errors=True
    )["stdout"]

    # Map TCP source-port -> process command (for clients connecting to the redis port on loopback).
    tcp_port_to_proc = {}
    for line in ss_tcp_raw.splitlines():
        # Lines look like:
        #   ESTAB 0 0 127.0.0.1:<redis_port>  127.0.0.1:44374  users:(("orchagent",pid=123,fd=4))
        m_pair = re.search(r'127\.0\.0\.1:(\d+)\s+127\.0\.0\.1:(\d+)', line)
        m_proc = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        if not (m_pair and m_proc):
            continue
        # Filter out redis-server as it's not a client.
        if m_proc.group(1).startswith('redis-server'):
            continue
        # The client port is whichever side is not the redis port.
        if m_pair.group(1) == str(redis_port):
            client_port = m_pair.group(2)
        else:
            client_port = m_pair.group(1)
        tcp_port_to_proc[client_port] = m_proc.group(1)

    # Parse `ss -xpn` for unix-socket connections.
    # Column layout (whitespace-separated tokens, stable across iproute2 versions):
    #   $1 Netid    -- "u_str"
    #   $2 State    -- "ESTAB"
    #   $3 Recv-Q
    #   $4 Send-Q
    #   $5 Local Address    -- path (e.g. /var/run/redis/redis.sock) or "*"
    #   $6 Local inode      -- numeric
    #   $7 Peer Address     -- always "*"
    #   $8 Peer inode       -- numeric
    #   $9+ Process         -- users:(("<cmd>",pid=<pid>,fd=<fd>))
    ss_unix_re = re.compile(
        r'^u_str\s+ESTAB\s+\d+\s+\d+\s+(\S+)\s+(\d+)\s+\S+\s+(\d+)\s+'
        r'users:\(\("([^"]+)",pid=(\d+),fd=(\d+)'
    )
    # redis-server's server-side fd -> peer inode (the client-side socket inode).
    redis_fd_to_peer_inode = {}
    # local inode -> command for every owner row (used to resolve client side).
    inode_to_cmd = {}
    for line in ss_unix_raw.splitlines():
        m = ss_unix_re.match(line)
        if not m:
            continue
        _local_addr, local_inode, peer_inode, cmd, _pid, fd = m.groups()
        local_inode = int(local_inode)
        peer_inode = int(peer_inode)
        fd = int(fd)
        inode_to_cmd[local_inode] = cmd
        # ss truncates command to TASK_COMM_LEN-1 (15 chars), so 'redis-server'
        # may appear truncated; prefix-match to be safe.
        if cmd.startswith('redis-'):
            redis_fd_to_peer_inode[fd] = peer_inode

    per_client = []
    for line in client_list_raw.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = {}
        for kv in line.split():
            if '=' in kv:
                k, v = kv.split('=', 1)
                fields[k] = v
        if 'addr' not in fields or 'tot-mem' not in fields:
            continue
        try:
            tot_mem = int(fields['tot-mem'])
            omem = int(fields.get('omem', 0))
            client_fd = int(fields.get('fd', '-1'))
        except ValueError:
            continue
        addr = fields['addr']
        if addr.startswith('127.0.0.1:') or addr.startswith('[::1]:'):
            client_port = addr.rsplit(':', 1)[-1]
            proc = 'tcp:' + tcp_port_to_proc.get(client_port, '<unknown>')
        else:
            # Unix socket: resolve via the redis-server fd -> peer inode -> client cmd chain.
            peer_inode = redis_fd_to_peer_inode.get(client_fd)
            cmd = inode_to_cmd.get(peer_inode) if peer_inode is not None else None
            proc = 'unix:' + cmd if cmd else 'unix:<unknown>'
        per_client.append({
            'id': fields.get('id', '?'),
            'addr': addr,
            'fd': fields.get('fd', '?'),
            'tot_mem': tot_mem,
            'omem': omem,
            'process': proc,
        })

    return per_client


def _read_sonic_db_id_to_name(duthost):
    """Return a dict mapping numeric DB id -> SONiC DB name(s).

    Reads /var/run/redis/sonic-db/database_config.json. Several SONiC DB
    names can share the same id (e.g., PFC_WD_DB and FLEX_COUNTER_DB both
    live on db5); those are joined with '/' so the log line shows both.

    Returns an empty dict on any error -- callers should fall back to the
    raw 'db<N>' label.
    """
    raw = duthost.shell(
        "cat /var/run/redis/sonic-db/database_config.json",
        module_ignore_errors=True
    )["stdout"]
    try:
        cfg = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    id_to_names = defaultdict(list)
    for name, entry in cfg.get("DATABASES", {}).items():
        db_id = entry.get("id")
        if isinstance(db_id, int):
            id_to_names[db_id].append(name)
    return {db_id: "/".join(sorted(names)) for db_id, names in id_to_names.items()}


def log_redis_state(duthost, label):
    """Log Redis memory snapshot to narrow down source of increased memory usage
    when test fails. Includes number of keys in each DB, as well as memory usage
    in each client buffer.

    Args:
        duthost: DUT host object.
        label: short tag for log lines (e.g., "start", "end").

    Logged:
      - used_memory_human, used_memory_rss_human, mem_clients_normal
      - Per-DB key counts, with SONiC DB names (e.g., 'db0 APPL_DB keys=...')
      - Per-client tot_mem and omem, aggregated by resolved process name
        (e.g., 'tcp:bgpd', 'unix:xcvrd'); sorted by tot_mem descending.
    """
    info_memory = duthost.shell("redis-cli info memory",
                                module_ignore_errors=True)["stdout"]
    info_keyspace = duthost.shell("redis-cli info keyspace",
                                  module_ignore_errors=True)["stdout"]
    db_id_to_name = _read_sonic_db_id_to_name(duthost)

    used_human = _redis_info_field(info_memory, "used_memory_human") or "?"
    rss_human = _redis_info_field(info_memory, "used_memory_rss_human") or "?"
    mem_clients = _redis_info_field(info_memory, "mem_clients_normal") or "?"
    logger.info(
        "[redis %s] used_memory_human=%s rss=%s mem_clients_normal=%s bytes",
        label, used_human, rss_human, mem_clients)

    for line in info_keyspace.splitlines():
        m = re.match(r'^db(\d+):keys=(\d+)', line)
        if m:
            db_id = int(m.group(1))
            name = db_id_to_name.get(db_id, "<unknown>")
            logger.info("[redis %s] db%d %s keys=%s", label, db_id, name, m.group(2))

    per_client = _resolve_redis_clients_to_processes(duthost)

    # Aggregate per-client tot_mem and omem by resolved process name.
    # `omem` is per-client output buffer memory -- a high value flags a slow
    # consumer that's accumulating un-drained replies on the redis side.
    per_proc_mem = defaultdict(lambda: [0, 0, 0])  # process -> [count, tot_mem, omem]
    for c in per_client:
        per_proc_mem[c['process']][0] += 1
        per_proc_mem[c['process']][1] += c['tot_mem']
        per_proc_mem[c['process']][2] += c['omem']
    for proc, (count, mem, omem) in sorted(per_proc_mem.items(), key=lambda x: -x[1][1]):
        logger.info("[redis %s] client_mem %s: %d connections, tot_mem=%d bytes, omem=%d bytes",
                    label, proc, count, mem, omem)


_MEMORY_SETTLE_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), 'memory_settle.yml')


def _load_memory_settle_config():
    """Load the platform/topology -> max_wait config from memory_settle.yml."""
    with open(_MEMORY_SETTLE_CONFIG_PATH) as f:
        return yaml.safe_load(f)


def _memory_settle_max_wait(duthost, tbinfo):
    """Pick the upper bound on how long to poll for post-link-flap memory checks.

    High-port-density scale topologies need more time after a flap before
    COUNTERS_DB / FLEX_COUNTER state has been reclaimed, and FRR daemons
    (bgpd / zebra) also take longer to settle. The values are externalized
    to memory_settle.yml so new platforms / topologies can be added easily.

    Lookup is two-level:
      1. ONIE platform regex (e.g. 'x86_64-nexthop_.*') from duthost.facts.
      2. Topology-name regex (e.g. 't2_single_node_max.*') from tbinfo.

    Both levels accept a 'default' key. Last matching entry wins (regex order
    in the YAML file is significant: list more specific patterns after less
    specific ones).
    """
    platform = duthost.facts.get('platform', '') if hasattr(duthost, 'facts') else ''
    topo_name = tbinfo.get('topo', {}).get('name', '')

    try:
        config = _load_memory_settle_config()
    except (IOError, yaml.YAMLError) as exc:
        logger.warning("Failed to load %s: %s; falling back to 30s",
                       _MEMORY_SETTLE_CONFIG_PATH, exc)
        return 30

    def _lookup(table, key):
        """Walk a regex-keyed table; last match wins. 'default' is fallback only."""
        chosen = table.get('default')
        for pattern, value in table.items():
            if pattern == 'default':
                continue
            if re.match(pattern, key):
                chosen = value
        return chosen

    platform_entry = _lookup(config, platform)
    if not isinstance(platform_entry, dict):
        return 30
    max_wait = _lookup(platform_entry, topo_name)
    if not isinstance(max_wait, int):
        return 30
    return max_wait


def get_frr_daemon_memory_usage(duthost, daemon):
    frr_daemon_memory_per_asics = {}

    for asic in duthost.asics:
        frr_daemon_memory_output = duthost.shell(duthost.get_vtysh_cmd_for_namespace(
            f'vtysh -c "show memory {daemon}"', asic.namespace))["stdout"]
        logging.info(f"{daemon} memory status: \n%s", frr_daemon_memory_output)

        # Parse the output for the three memory values
        used_ordinary_blocks = 0
        used_small_blocks = 0
        holding_block_headers = 0
        for line in frr_daemon_memory_output.splitlines():
            if "Used ordinary blocks:" in line:
                used_ordinary_blocks = _parse_memory_value(line)
            elif "Used small blocks:" in line:
                used_small_blocks = _parse_memory_value(line)
            elif "Holding block headers:" in line:
                holding_block_headers = _parse_memory_value(line)

        total_memory = used_ordinary_blocks + used_small_blocks + holding_block_headers
        logging.info("{} total memory for asic{}: {} MiB; ordinary {}, small {}, holding {}".format(
            daemon, asic.asic_index, total_memory, used_ordinary_blocks, used_small_blocks, holding_block_headers))
        frr_daemon_memory_per_asics[asic.asic_index] = total_memory

    return frr_daemon_memory_per_asics


def _parse_memory_value(line):
    match = re.search(r':\s*([\d.]+)\s*(bytes|KiB|MiB)?', line)
    if not match:
        return 0
    value = float(match.group(1))
    unit = match.group(2)
    if unit == 'bytes' or unit is None:
        return value / (1024 * 1024)
    elif unit == 'KiB':
        return value / 1024
    elif unit == 'MiB':
        return value
    else:
        return value


def validate_frr_daemon_memory_increase(tbinfo, start_mem, end_mem):
    """Topology-aware FRR daemon memory increase check.

    Base threshold: 10% on m0/mx, 5% elsewhere. Floored to ceil(100/start_mem)%
    so a small daemon doesn't trip on single-MiB noise.

    Returns:
        (passed: bool, threshold_percent: int) -- threshold actually applied.
    """
    base_threshold = 10 if tbinfo["topo"]["type"] in ["m0", "mx"] else 5
    min_threshold_percent = 1 / float(start_mem) * 100
    threshold = max(base_threshold, int(math.ceil(min_threshold_percent)))
    incr = float(end_mem) - float(start_mem)
    if incr <= 0:
        return True, threshold
    percent_incr = (incr / float(start_mem)) * 100
    return percent_incr < threshold, threshold


def _check_frr_thresholds(tbinfo, frr_daemons, start_frr_memory, end_frr_memory):
    """Evaluate all FRR memory thresholds. Returns (all_passed, summary_list).

    summary_list is a list of
      (daemon, asic_index, passed, threshold, start_mem, end_mem, percent_incr)
    tuples for logging. Any field except daemon/asic_index can be None if no
    end-reading was available.
    """
    summary = []
    all_passed = True
    for daemon in frr_daemons:
        daemon_start = start_frr_memory.get(daemon, {})
        daemon_end = end_frr_memory.get(daemon, {}) if end_frr_memory else {}
        for asic_index, start_mem in daemon_start.items():
            end_mem = daemon_end.get(asic_index)
            if end_mem is None:
                summary.append((daemon, asic_index, False, None, start_mem, None, None))
                all_passed = False
                continue
            passed, threshold = validate_frr_daemon_memory_increase(tbinfo, start_mem, end_mem)
            incr = float(end_mem) - float(start_mem)
            percent_incr = (incr / float(start_mem)) * 100 if start_mem else 0
            summary.append((daemon, asic_index, passed, threshold,
                            float(start_mem), float(end_mem), percent_incr))
            if not passed:
                all_passed = False
    return all_passed, summary


def _redis_memory_threshold(tbinfo):
    """Return the redis memory increase threshold (%) that
    validate_redis_memory_increase will apply for this topology."""
    return 20 if tbinfo["topo"]["type"] in ["m0", "mx"] else 15


def wait_for_memory_to_settle(duthost, tbinfo, frr_daemons,
                              start_frr_memory, start_redis_memory,
                              max_wait=None,
                              window_interval=5, window_samples=5):
    """Poll FRR daemon memory and Redis memory until both satisfy thresholds.

    Bundles the two memory checks into a single topology-aware wait loop. Each
    iteration samples FRR (cheap, one vtysh per daemon per asic) and Redis
    (`window_samples` redis-cli reads spaced `window_interval` seconds apart,
    so ~25s per iteration with the defaults). Exits early when every FRR
    daemon and the Redis check satisfy their topology thresholds.

    The same topology mapping is used for both metrics
    (see _memory_settle_max_wait).

    Args:
        duthost: DUT host object.
        tbinfo: testbed info dict; drives topology thresholds and max_wait.
        frr_daemons: list of FRR daemon names to sample (e.g. ['bgpd', 'zebra']).
        start_frr_memory: {daemon: {asic_index: start_mem_mib}} from start of test.
        start_redis_memory: baseline Redis memory in MiB at start of test.
        max_wait: override the topology-derived cap (seconds).
        window_interval, window_samples: passed to get_avg_redis_mem_usage.

    Returns:
        (end_frr_memory, end_redis_memory): the final readings observed. Pass
        these to the validate_* predicates for hard assertions in the caller.
    """
    if max_wait is None:
        max_wait = _memory_settle_max_wait(duthost, tbinfo)
    logger.info(
        "Memory settle poll: platform=%s topology=%s max_wait=%ds",
        getattr(duthost, 'facts', {}).get('platform', '<unknown>'),
        tbinfo.get('topo', {}).get('name', '<unknown>'), max_wait)
    start_time = time.time()
    end_frr_memory = None
    end_redis_memory = None
    while time.time() - start_time < max_wait:
        end_frr_memory = {d: get_frr_daemon_memory_usage(duthost, d) for d in frr_daemons}
        end_redis_memory = get_avg_redis_mem_usage(duthost, window_interval, window_samples)
        elapsed = time.time() - start_time

        frr_pass, frr_summary = _check_frr_thresholds(
            tbinfo, frr_daemons, start_frr_memory, end_frr_memory)
        redis_pass = validate_redis_memory_increase(
            tbinfo, start_redis_memory, end_redis_memory)

        for daemon, asic_index, passed, threshold, start_mem, end_mem, percent_incr in frr_summary:
            if percent_incr is None:
                logger.info("Memory poll: %s-asic%s missing end reading (start=%s MiB)",
                            daemon, asic_index,
                            f"{start_mem:.3f}" if start_mem is not None else "?")
            else:
                logger.info(
                    "Memory poll: %s-asic%s start=%.3f MiB end=%.3f MiB "
                    "incr=%+.1f%% threshold=%d%% pass=%s",
                    daemon, asic_index, start_mem, end_mem, percent_incr, threshold, passed)
        redis_incr = end_redis_memory - start_redis_memory
        redis_percent = (redis_incr / start_redis_memory) * 100 if start_redis_memory else 0
        logger.info(
            "Memory poll: redis start=%.3f MiB end=%.3f MiB "
            "incr=%+.1f%% threshold=%d%% pass=%s after %.0fs",
            start_redis_memory, end_redis_memory, redis_percent,
            _redis_memory_threshold(tbinfo), redis_pass, elapsed)

        if frr_pass and redis_pass:
            logger.info("All memory checks pass after %.0fs", elapsed)
            return end_frr_memory, end_redis_memory

    logger.warning(
        "Memory checks still failing after %ds; using final readings", max_wait)
    return end_frr_memory, end_redis_memory


def validate_redis_memory_increase(tbinfo, start_mem, end_mem):
    # Calculate diff in Redis memory
    incr_redis_memory = end_mem - start_mem
    logging.info("Redis memory usage difference: %f", incr_redis_memory)

    # Check redis memory only if it is increased else default to pass
    if incr_redis_memory > 0.0:
        percent_incr_redis_memory = (incr_redis_memory / start_mem) * 100
        logging.info("Redis Memory percentage Increase: %d", percent_incr_redis_memory)
        incr_redis_memory_threshold = _redis_memory_threshold(tbinfo)
        if percent_incr_redis_memory >= incr_redis_memory_threshold:
            return False
    return True
