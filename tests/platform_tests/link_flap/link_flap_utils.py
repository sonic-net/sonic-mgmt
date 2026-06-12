"""
Test utils used by the link flap tests.
"""
import json
import logging
import random
import re
import time

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


def validate_redis_memory_increase(tbinfo, start_mem, end_mem):
    # Calculate diff in Redis memory
    incr_redis_memory = end_mem - start_mem
    logging.info("Redis memory usage difference: %f", incr_redis_memory)

    # Check redis memory only if it is increased else default to pass
    if incr_redis_memory > 0.0:
        percent_incr_redis_memory = (incr_redis_memory / start_mem) * 100
        logging.info("Redis Memory percentage Increase: %d", percent_incr_redis_memory)
        incr_redis_memory_threshold = 20 if tbinfo["topo"]["type"] in ["m0", "mx"] else 15
        if percent_incr_redis_memory >= incr_redis_memory_threshold:
            return False
    return True
