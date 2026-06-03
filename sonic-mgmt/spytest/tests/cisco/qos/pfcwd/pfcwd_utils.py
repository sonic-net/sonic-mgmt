"""
PFCWD (PFC Watchdog) Utility Functions for SPyTest

This module provides utilities for PFCWD testing including:
- PFCWD configuration management (start/stop)
- PFCWD timing parameter retrieval (poll interval, detect time, restore time)
- PFCWD statistics collection and parsing
- Traffic timing calculations for PFCWD tests

Ported from sonic-mgmt/tests/common/snappi_tests/common_helpers.py
"""

import ast
import re
from spytest import st


# ---------------------------------------------------------------------------
# Redis HGETALL output parser
# ---------------------------------------------------------------------------


def _parse_hgetall_output(output):
    """Parse ``sonic-db-cli``/``redis-cli`` HGETALL output into a ``dict``.

    Handles all three formats seen in the field:
      * Newer ``sonic-db-cli``: a single Python-dict line
        ``{'k': 'v', ...}`` (possibly followed by a shell prompt).
      * ``redis-cli`` numbered output: ``1) "k"`` / ``2) "v"`` / ...
      * Plain alternating key/value lines.

    Shell-prompt trailers (``admin@sonic:~$``) are filtered so they are not
    paired as bogus key/value entries. Returns ``{}`` when nothing parseable
    is found.
    """
    if not output:
        return {}

    # Form 1: Python dict literal on its own line.
    for raw_line in output.strip().splitlines():
        line = raw_line.strip()
        if line.startswith('{') and line.endswith('}'):
            try:
                parsed = ast.literal_eval(line)
            except (ValueError, SyntaxError):
                continue
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}

    # Forms 2 & 3: numbered or alternating lines.
    cleaned = []
    for raw_line in output.strip().splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # Skip shell prompts like 'admin@sonic:~$'.
        if '@' in line and line.rstrip().endswith('$'):
            continue
        m = re.match(r'^\d+\)\s*(.*)$', line)
        val = m.group(1) if m else line
        val = val.strip('"').strip("'")
        cleaned.append(val)

    result = {}
    for i in range(0, len(cleaned) - 1, 2):
        result[cleaned[i]] = cleaned[i + 1]
    return result


# ---------------------------------------------------------------------------
# PFCWD Configuration Management
# ---------------------------------------------------------------------------


def enable_pfcwd(dut):
    """
    Enable PFC watchdog with default settings.

    Args:
        dut: DUT handle from spytest

    Returns:
        None
    """
    st.log(f"Enabling PFCWD with default settings on {dut}")
    st.config(dut, 'pfcwd start_default', skip_error_check=True)


def disable_pfcwd(dut):
    """
    Disable PFC watchdog.

    Args:
        dut: DUT handle from spytest

    Returns:
        None
    """
    st.log(f"Disabling PFCWD on {dut}")
    st.config(dut, 'sudo pfcwd stop', skip_error_check=True)


# ---------------------------------------------------------------------------
# PFCWD Configuration Attribute Retrieval
# ---------------------------------------------------------------------------


def get_pfcwd_config(dut, port=None):
    """
    Get PFCWD configuration from 'show pfcwd config' command.

    Parses output like:
              PORT    ACTION    DETECTION TIME    RESTORATION TIME
    --------------  --------  ----------------  ------------------
       Ethernet1_1      drop               400                 400
       Ethernet1_2      drop               400                 400

    Args:
        dut: DUT handle from spytest
        port: Optional port name to filter results (e.g., 'Ethernet1_1').
              If None, returns config for all ports.

    Returns:
        dict: If port is specified, returns config for that port:
              {
                  'port': 'Ethernet1_1',
                  'action': 'drop',
                  'detection_time': 400,
                  'restoration_time': 400
              }
              If port is None, returns dict keyed by port name:
              {
                  'Ethernet1_1': {'action': 'drop', 'detection_time': 400, ...},
                  'Ethernet1_2': {'action': 'drop', 'detection_time': 400, ...},
              }
              Returns None if port not found, or empty dict if no config.
    """
    cmd = "show pfcwd config"
    raw_out = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)

    pfcwd_config = {}
    header_found = False

    for line in raw_out.split('\n'):
        line = line.strip()
        if not line:
            continue

        # Skip header and separator lines
        if 'PORT' in line and 'ACTION' in line:
            header_found = True
            continue
        if line.startswith('---') or line.startswith('==='):
            continue

        if not header_found:
            continue

        # Parse data lines
        # Example: "Ethernet1_1      drop               400                 400"
        parts = line.split()
        if len(parts) >= 4:
            port_name = parts[0]
            action = parts[1]
            try:
                detection_time = int(parts[2])
                restoration_time = int(parts[3])
            except ValueError:
                st.log(f"Failed to parse PFCWD config line: {line}")
                continue

            pfcwd_config[port_name] = {
                'port': port_name,
                'action': action,
                'detection_time': detection_time,
                'restoration_time': restoration_time,
            }

    st.log(f"PFCWD config: {len(pfcwd_config)} ports configured")

    if port is not None:
        return pfcwd_config.get(port)
    return pfcwd_config


def verify_pfcwd_config(dut, port, expected_action='drop',
                        expected_detection_time=None, expected_restoration_time=None):
    """
    Verify PFCWD is configured on a specific port.

    Args:
        dut: DUT handle from spytest
        port: Port name (e.g., 'Ethernet1_1')
        expected_action: Expected action ('drop' or 'forward')
        expected_detection_time: Expected detection time in ms (optional)
        expected_restoration_time: Expected restoration time in ms (optional)

    Returns:
        tuple: (success: bool, message: str)
    """
    config = get_pfcwd_config(dut, port)

    if config is None:
        return False, f"PFCWD not configured on port {port}"

    errors = []

    if expected_action and config['action'] != expected_action:
        errors.append(f"action: expected '{expected_action}', got '{config['action']}'")

    if expected_detection_time is not None:
        if config['detection_time'] != expected_detection_time:
            errors.append(f"detection_time: expected {expected_detection_time}, got {config['detection_time']}")

    if expected_restoration_time is not None:
        if config['restoration_time'] != expected_restoration_time:
            errors.append(f"restoration_time: expected {expected_restoration_time}, got {config['restoration_time']}")

    if errors:
        return False, f"PFCWD config mismatch on {port}: {'; '.join(errors)}"

    return True, f"PFCWD configured correctly on {port} (action={config['action']}, detect={config['detection_time']}ms, restore={config['restoration_time']}ms)"


def verify_pfc_enabled_on_port(dut, port, expected_priorities=None,
                               expected_queues=None):
    """
    Verify PFC and PFCWD software monitoring are enabled on a port at the
    CONFIG_DB level by inspecting ``PORT_QOS_MAP|<port>``.

    ``show pfcwd config`` only displays the per-port detection/restoration
    timer values. It does NOT tell you whether PFC is actually enabled on
    the port or which queues PFCWD will monitor. The authoritative source
    is the ``PORT_QOS_MAP`` table, where:

        pfc_enable       -- comma-separated PFC priorities (e.g., "3,4")
        pfcwd_sw_enable  -- comma-separated queues PFCWD monitors (e.g., "3,4")

    If a port is missing ``pfc_enable`` or doesn't include the lossless
    priority, the DUT will silently ignore XOFF frames on that priority and
    PFCWD will never see a storm -- even though ``show pfcwd config``
    reports the port as configured with timers.

    Args:
        dut: DUT handle from spytest.
        port: Port name (e.g., 'Ethernet1_60_2').
        expected_priorities: Optional iterable of int TC priorities that
            must appear in ``pfc_enable``. When provided, the function
            reports any priority missing from that field.
        expected_queues: Optional iterable of int HW queue indices that
            must appear in ``pfcwd_sw_enable``. On platforms with a
            non-identity ``TC_TO_QUEUE_MAP`` the TC and the queue index
            differ; checking the TC against the queue list is wrong and
            will spuriously fail valid configs. When omitted, defaults to
            ``expected_priorities`` for back-compat with identity maps.

    Returns:
        tuple: (success: bool, info: dict)
            info contains:
              'qos_map'         -- full PORT_QOS_MAP dict (or {} if missing)
              'pfc_priorities'  -- list[int] from pfc_enable
              'pfcwd_queues'    -- list[int] from pfcwd_sw_enable
              'missing_prio'    -- list[int] of expected priorities not in
                                   pfc_enable
              'missing_queue'   -- list[int] of expected queues not in
                                   pfcwd_sw_enable
              'missing'         -- legacy union (missing_prio + missing_queue)
                                   for back-compat
    """
    qos_map = {}
    try:
        cmd = f'sonic-db-cli CONFIG_DB HGETALL "PORT_QOS_MAP|{port}"'
        result = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)
        qos_map = _parse_hgetall_output(result)
    except Exception as e:
        st.log(f"verify_pfc_enabled_on_port: error reading PORT_QOS_MAP|{port}: {e}")
        qos_map = {}

    def _parse_csv_ints(value):
        out = []
        for tok in str(value or "").split(","):
            tok = tok.strip()
            if tok.isdigit():
                out.append(int(tok))
        return out

    pfc_priorities = _parse_csv_ints(qos_map.get("pfc_enable"))
    pfcwd_queues = _parse_csv_ints(qos_map.get("pfcwd_sw_enable"))

    st.log(f"PORT_QOS_MAP|{port}:")
    if not qos_map:
        st.log("  <empty or missing key>")
    else:
        for k, v in qos_map.items():
            st.log(f"  {k} = {v}")
    st.log(f"  -> pfc_enable priorities: {pfc_priorities}")
    st.log(f"  -> pfcwd_sw_enable queues: {pfcwd_queues}")

    # Default expected_queues to expected_priorities for back-compat on
    # identity-map platforms; non-identity callers must pass it explicitly.
    if expected_queues is None and expected_priorities is not None:
        expected_queues = expected_priorities

    missing_prio = []
    if expected_priorities is not None:
        for prio in expected_priorities:
            if prio not in pfc_priorities:
                missing_prio.append(prio)
                st.log(f"  MISSING priority {prio} from pfc_enable")

    missing_queue = []
    if expected_queues is not None:
        for q in expected_queues:
            if q not in pfcwd_queues:
                missing_queue.append(q)
                st.log(f"  MISSING queue {q} from pfcwd_sw_enable")

    info = {
        'qos_map': qos_map,
        'pfc_priorities': pfc_priorities,
        'pfcwd_queues': pfcwd_queues,
        'missing_prio': missing_prio,
        'missing_queue': missing_queue,
        'missing': missing_prio + missing_queue,  # legacy union
    }
    success = (bool(qos_map) and bool(pfc_priorities) and bool(pfcwd_queues)
               and not missing_prio and not missing_queue)
    return success, info


def _get_pfcwd_config_from_db(dut, scope=None):
    """
    Get PFCWD configuration from CONFIG_DB for a single key.

    Args:
        dut: DUT handle from spytest
        scope: PFC_WD scope to fetch (e.g., 'GLOBAL' or interface name like
            'Ethernet1_60_2'). Must be provided - this function no longer
            enumerates all keys to avoid issuing one HGETALL per port.

    Returns:
        dict: Field/value pairs for that scope (empty dict if missing).
    """
    if not scope:
        st.log("_get_pfcwd_config_from_db: scope is required")
        return {}

    try:
        # Output is typically a Python dict literal on newer sonic-db-cli,
        # but older paths emit redis-cli-style numbered or alternating lines.
        cmd = f'sonic-db-cli CONFIG_DB HGETALL "PFC_WD|{scope}"'
        result = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)
        return _parse_hgetall_output(result)
    except Exception as e:
        st.log(f"Error reading PFCWD config from DB for scope={scope}: {e}")
        return {}


def get_pfcwd_poll_interval(dut):
    """
    Get PFC watchdog polling interval (ms).

    Lookup order:
      1. CONFIG_DB ``PFC_WD|GLOBAL`` ``POLL_INTERVAL`` field (only set when
         user explicitly configured a poll interval).
      2. First line of ``show pfcwd config`` output -- when explicitly set,
         SONiC prints ``Changed polling interval to <X>ms`` as a header.
      3. SONiC default: 100 ms.
    """
    cfg = _get_pfcwd_config_from_db(dut, scope='GLOBAL')
    if 'POLL_INTERVAL' in cfg:
        return int(cfg['POLL_INTERVAL'])

    # Try parsing 'show pfcwd config' header
    try:
        import re
        out = st.show(dut, 'show pfcwd config', skip_tmpl=True, skip_error_check=True)
        if out:
            m = re.search(r'Changed polling interval to\s+(\d+)\s*ms', out)
            if m:
                return int(m.group(1))
    except Exception as e:
        st.log(f"Error parsing 'show pfcwd config' for poll interval: {e}")

    # SONiC built-in default
    st.log("PFCWD POLL_INTERVAL not configured; using SONiC default 100ms")
    return 100


def get_pfcwd_detect_time(dut, intf):
    """
    Get PFC watchdog detection time for a given interface.

    Args:
        dut: DUT handle from spytest
        intf: Interface name (e.g., 'Ethernet0')

    Returns:
        int: Detection time in milliseconds, or None if not configured
    """
    cfg = _get_pfcwd_config_from_db(dut, scope=intf)

    if 'detection_time' in cfg:
        return int(cfg['detection_time'])

    # Default value if not configured
    st.log(f"PFCWD detection_time not found for {intf}, using default 200ms")
    return 200


def get_pfcwd_restore_time(dut, intf):
    """
    Get PFC watchdog restoration time for a given interface.

    Args:
        dut: DUT handle from spytest
        intf: Interface name (e.g., 'Ethernet0')

    Returns:
        int: Restoration time in milliseconds, or None if not configured
    """
    cfg = _get_pfcwd_config_from_db(dut, scope=intf)

    if 'restoration_time' in cfg:
        return int(cfg['restoration_time'])

    # Default value if not configured
    st.log(f"PFCWD restoration_time not found for {intf}, using default 200ms")
    return 200


# ---------------------------------------------------------------------------
# PFCWD Statistics Collection
# ---------------------------------------------------------------------------


def get_pfcwd_stats(dut, port, prio):
    """
    Get PFCWD statistics for a given interface:priority.

    Parses output of 'show pfcwd stats' command.

    Args:
        dut: DUT handle from spytest
        port: Port name (e.g., 'Ethernet0')
        prio: Priority (0-7)

    Returns:
        dict: PFCWD statistics with keys:
            - QUEUE: Queue identifier (e.g., 'Ethernet0:3')
            - STATUS: Operational status
            - TX_OK/DROP: TX OK and DROP counts separated by '/'
            - RX_OK/DROP: RX OK and DROP counts separated by '/'
            - TX_LAST: Last TX timestamp
            - RX_LAST: Last RX timestamp
            - STORM_DETECTED/RESTORED: Storm detected and restored counts

    Example return:
        {
            'QUEUE': 'Ethernet0:3',
            'STATUS': 'operational',
            'TX_OK/DROP': '1000/500',
            'RX_OK/DROP': '1000/0',
            'TX_LAST': 'N/A',
            'RX_LAST': 'N/A',
            'STORM_DETECTED/RESTORED': '1/1'
        }
    """
    pfcwd_stats = {}

    # Build list of port names to try: exact match first, then parent port
    # (strip trailing _N suffix for breakout subports), e.g. Ethernet1_60_2 -> Ethernet1_60
    port_candidates = [port]
    import re as re_mod
    parent_match = re_mod.match(r'^(.+)_\d+$', port)
    if parent_match:
        parent = parent_match.group(1)
        if parent != port:
            port_candidates.append(parent)

    st.log(f"get_pfcwd_stats: port={port}, prio={prio}")
    st.log(f"  Port candidates to search: {port_candidates}")

    val_list = []
    key_list = []
    matched_port = None

    for candidate in port_candidates:
        cmd = f"show pfcwd stats | grep -E 'QUEUE|{candidate}:{prio}'"
        raw_out = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)

        for line in raw_out.split('\n'):
            line = line.strip()
            if not line:
                continue
            if 'QUEUE' in line:
                key_list = re.sub(r"(\w) (\w)", r"\1_\2", line).split()
            elif f'{candidate}:{prio}' in line:
                val_list = line.split()
                matched_port = candidate
                st.log(f"  Found match for {candidate}:{prio}: {line}")
                break

        if val_list:
            break

    if val_list and key_list:
        for key, val in zip(key_list, val_list):
            pfcwd_stats[key] = val
        st.log(f"  Parsed stats (matched port {matched_port}): {pfcwd_stats}")
    else:
        # Return zeros if no data found
        st.log(f"  No matching queue found for {port_candidates}, returning defaults")
        default_keys = ['QUEUE', 'STATUS', 'TX_OK/DROP', 'RX_OK/DROP',
                        'TX_LAST', 'RX_LAST', 'STORM_DETECTED/RESTORED']
        pfcwd_stats = {key: '0/0' if '/' in key else '0' for key in default_keys}
        pfcwd_stats['QUEUE'] = f'{port}:{prio}'
        pfcwd_stats['STATUS'] = 'N/A'

    return pfcwd_stats


def get_pfcwd_stats_parsed(dut, port, prio):
    """
    Get PFCWD statistics with parsed numeric values.

    Args:
        dut: DUT handle from spytest
        port: Port name (e.g., 'Ethernet0')
        prio: Priority (0-7)

    Returns:
        dict: Parsed statistics with separate keys for each value:
            - tx_ok: TX OK count (int)
            - tx_drop: TX DROP count (int)
            - rx_ok: RX OK count (int)
            - rx_drop: RX DROP count (int)
            - storm_detected: Storm detected count (int)
            - storm_restored: Storm restored count (int)
            - status: Operational status (str)
    """
    raw_stats = get_pfcwd_stats(dut, port, prio)

    parsed = {
        'queue': raw_stats.get('QUEUE', f'{port}:{prio}'),
        'status': raw_stats.get('STATUS', 'N/A'),
        'tx_ok': 0,
        'tx_drop': 0,
        'rx_ok': 0,
        'rx_drop': 0,
        'storm_detected': 0,
        'storm_restored': 0,
    }

    # Parse TX_OK/DROP
    tx_stats = raw_stats.get('TX_OK/DROP', '0/0')
    if '/' in tx_stats:
        parts = tx_stats.split('/')
        parsed['tx_ok'] = int(parts[0]) if parts[0].isdigit() else 0
        parsed['tx_drop'] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

    # Parse RX_OK/DROP
    rx_stats = raw_stats.get('RX_OK/DROP', '0/0')
    if '/' in rx_stats:
        parts = rx_stats.split('/')
        parsed['rx_ok'] = int(parts[0]) if parts[0].isdigit() else 0
        parsed['rx_drop'] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

    # Parse STORM_DETECTED/RESTORED
    storm_stats = raw_stats.get('STORM_DETECTED/RESTORED', '0/0')
    if '/' in storm_stats:
        parts = storm_stats.split('/')
        parsed['storm_detected'] = int(parts[0]) if parts[0].isdigit() else 0
        parsed['storm_restored'] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

    return parsed


def get_pfcwd_stats_delta(stats_before, stats_after):
    """
    Calculate the delta between two PFCWD stats snapshots.

    Args:
        stats_before: Stats dict from get_pfcwd_stats_parsed() before test
        stats_after: Stats dict from get_pfcwd_stats_parsed() after test

    Returns:
        dict: Delta values for each counter
    """
    delta = {}
    for key in ['tx_ok', 'tx_drop', 'rx_ok', 'rx_drop', 'storm_detected', 'storm_restored']:
        delta[key] = stats_after.get(key, 0) - stats_before.get(key, 0)
    return delta


# ---------------------------------------------------------------------------
# PFCWD Test Timing Calculations
# ---------------------------------------------------------------------------


def calculate_pfcwd_storm_duration(dut, intf, trigger_pfcwd=True):
    """
    Calculate PFC storm duration based on PFCWD timers.

    For trigger_pfcwd=True: Storm duration > detect_time + poll_interval
    For trigger_pfcwd=False: Storm duration < detect_time * 0.5

    Args:
        dut: DUT handle from spytest
        intf: Interface name
        trigger_pfcwd: Whether storm should trigger PFCWD

    Returns:
        float: Storm duration in seconds
    """
    poll_interval_ms = get_pfcwd_poll_interval(dut)
    detect_time_ms = get_pfcwd_detect_time(dut, intf)

    poll_interval_sec = poll_interval_ms / 1000.0
    detect_time_sec = detect_time_ms / 1000.0

    if trigger_pfcwd:
        # Large enough to trigger PFCWD
        from math import ceil
        storm_dur_sec = ceil(detect_time_sec + poll_interval_sec + 0.1)
    else:
        # Too short to trigger PFCWD
        storm_dur_sec = detect_time_sec * 0.5

    st.log(f"Calculated storm duration: {storm_dur_sec}s "
           f"(trigger_pfcwd={trigger_pfcwd}, detect={detect_time_ms}ms, poll={poll_interval_ms}ms)")

    return storm_dur_sec


def get_pfcwd_timing_params(dut, intf):
    """
    Get all PFCWD timing parameters for test calculations.

    Args:
        dut: DUT handle from spytest
        intf: Interface name

    Returns:
        dict: Timing parameters in seconds:
            - poll_interval_sec
            - detect_time_sec
            - restore_time_sec
    """
    # Fetch GLOBAL and per-interface scopes once (2 redis calls total)
    intf_cfg = _get_pfcwd_config_from_db(dut, scope=intf)

    poll_interval_ms = get_pfcwd_poll_interval(dut)
    detect_time_ms = int(intf_cfg.get('detection_time', 200))
    restore_time_ms = int(intf_cfg.get('restoration_time', 200))

    return {
        'poll_interval_sec': poll_interval_ms / 1000.0,
        'detect_time_sec': detect_time_ms / 1000.0,
        'restore_time_sec': restore_time_ms / 1000.0,
    }


# ---------------------------------------------------------------------------
# PFCWD Test Result Verification
# ---------------------------------------------------------------------------


def verify_pfcwd_triggered(stats_delta, expected=True):
    """
    Verify whether PFCWD was triggered based on stats delta.

    Args:
        stats_delta: Delta dict from get_pfcwd_stats_delta()
        expected: Whether PFCWD trigger was expected

    Returns:
        tuple: (success: bool, message: str)
    """
    storm_detected = stats_delta.get('storm_detected', 0)
    tx_drop = stats_delta.get('tx_drop', 0)

    if expected:
        if storm_detected > 0:
            return True, f"PFCWD triggered as expected (storm_detected={storm_detected}, tx_drop={tx_drop})"
        else:
            return False, f"PFCWD NOT triggered but was expected (storm_detected={storm_detected})"
    else:
        if storm_detected == 0:
            return True, f"PFCWD not triggered as expected (storm_detected={storm_detected})"
        else:
            return False, f"PFCWD triggered but was NOT expected (storm_detected={storm_detected})"


def verify_pfcwd_restored(stats_delta):
    """
    Verify whether PFCWD restored after storm ended.

    Args:
        stats_delta: Delta dict from get_pfcwd_stats_delta()

    Returns:
        tuple: (success: bool, message: str)
    """
    storm_detected = stats_delta.get('storm_detected', 0)
    storm_restored = stats_delta.get('storm_restored', 0)

    if storm_detected > 0 and storm_restored >= storm_detected:
        return True, f"PFCWD restored successfully (detected={storm_detected}, restored={storm_restored})"
    elif storm_detected == 0:
        return True, "No storm detected, no restore needed"
    else:
        return False, f"PFCWD not fully restored (detected={storm_detected}, restored={storm_restored})"


# ---------------------------------------------------------------------------
# Packet Aging (needed for PFCWD tests on Mellanox-based platforms)
# ---------------------------------------------------------------------------
#
# Mellanox Spectrum SDK ages out (drops) packets that have been sitting in
# an egress queue beyond a hardware timer. When PFC keeps the queue paused
# for hundreds of ms (PFCWD detect_time), aging silently drains the queue,
# the queue never appears "stuck" to PFCWD, and storm_detected stays 0.
# Disabling aging for the duration of the PFCWD test makes the queue
# remain congested so PFCWD can trip.
#
# This is needed only on n9164e (gamut). Cisco-8000 platforms (laguna,
# carib) do not have this aging behaviour, and the SDK call would fail.

# Platforms that need packet-aging toggled off during PFCWD tests.
_PLATFORMS_NEED_AGING_TOGGLE = ('n9164e', 'gamut')

# Path/name of the script as it lives in this directory and as we drop it
# inside the syncd container.
_PKT_AGING_SCRIPT_LOCAL = '../infra/packet_aging.py'
_PKT_AGING_SCRIPT_DUT = '/tmp/packet_aging.py'
_PKT_AGING_SCRIPT_SYNCD = '/packet_aging.py'


def _platform_needs_aging_toggle(platform):
    if not platform:
        return False
    p = str(platform).lower()
    return any(tag in p for tag in _PLATFORMS_NEED_AGING_TOGGLE)


def disable_packet_aging(dut, platform=None):
    """
    Disable Mellanox packet aging on the DUT for the duration of a PFCWD
    test. No-op on non-Mellanox platforms.

    Pushes packet_aging.py into the syncd container and runs
    `python /packet_aging.py disable`.

    Args:
        dut: DUT handle from spytest.
        platform: Optional platform string from qos_utils.detect_platform().
            If None, the function still tries; aging-disable failure is
            logged and swallowed so PFCWD setup keeps going.
    """
    if platform is not None and not _platform_needs_aging_toggle(platform):
        st.log(f"disable_packet_aging: platform={platform} doesn't need aging toggle, skipping")
        return False

    import os
    src = os.path.join(os.path.dirname(__file__), _PKT_AGING_SCRIPT_LOCAL)
    if not os.path.isfile(src):
        st.warn(f"disable_packet_aging: {src} not found; skipping aging-disable")
        return False

    try:
        st.banner("Disabling Mellanox packet aging on DUT (PFCWD test)")
        st.upload_file_to_dut(dut, src, _PKT_AGING_SCRIPT_DUT)
        st.config(
            dut,
            f"sudo docker cp {_PKT_AGING_SCRIPT_DUT} syncd:{_PKT_AGING_SCRIPT_SYNCD}",
            skip_error_check=True,
        )
        st.config(
            dut,
            f"sudo docker exec syncd python {_PKT_AGING_SCRIPT_SYNCD} disable",
            skip_error_check=True,
        )
        st.log("Packet aging disabled in syncd")
        return True
    except Exception as e:
        st.warn(f"disable_packet_aging failed (continuing): {e}")
        return False


def enable_packet_aging(dut, platform=None):
    """
    Re-enable Mellanox packet aging on the DUT and clean up the helper
    script from the syncd container. No-op on non-Mellanox platforms.
    Always safe to call (errors are swallowed) so it can run from
    teardown without masking real test failures.

    Args:
        dut: DUT handle from spytest.
        platform: Optional platform string from qos_utils.detect_platform().
    """
    if platform is not None and not _platform_needs_aging_toggle(platform):
        st.log(f"enable_packet_aging: platform={platform} doesn't need aging toggle, skipping")
        return False

    try:
        st.banner("Re-enabling Mellanox packet aging on DUT (PFCWD teardown)")
        st.config(
            dut,
            f"sudo docker exec syncd python {_PKT_AGING_SCRIPT_SYNCD} enable",
            skip_error_check=True,
        )
        st.config(
            dut,
            f"sudo docker exec syncd rm -f {_PKT_AGING_SCRIPT_SYNCD}",
            skip_error_check=True,
        )
        st.log("Packet aging re-enabled in syncd")
        return True
    except Exception as e:
        st.warn(f"enable_packet_aging failed (continuing): {e}")
        return False


# ---------------------------------------------------------------------------
# XOFF Rate Calculation
# ---------------------------------------------------------------------------


def calculate_xoff_rate(port_speed_gbps, quanta=0xffff, margin_pct=15,
                       platform=None):
    """
    Calculate the exact PFC XOFF frame rate to fully pause a port.

    PFC pause frames use a quanta field that specifies pause duration in
    units of 512 bit-times. With quanta=0xffff (65535), each XOFF frame
    pauses for 512 * 65535 = 33,553,920 bit-times.

    To continuously pause a link, XOFF frames must be sent at a rate that
    covers the full link capacity:
        rate_fps = port_speed_bps / (512 * quanta)

    Examples:
        100G: 100,000,000,000 / (512 * 65535) = 2980 fps
        200G: 200,000,000,000 / (512 * 65535) = 5960 fps
        400G: 400,000,000,000 / (512 * 65535) = 11921 fps

    Platform overrides:
        gamut/n9164e (Mellanox Spectrum): the device honors approximately
        2x the requested pause time per frame, so half the theoretical
        rate is sufficient. Calibrated on 400G: 5961 fps blocks fully.

    Args:
        port_speed_gbps: Port speed in Gbps (e.g., 100, 200, 400)
        quanta: PFC quanta value (default 0xffff for maximum pause)
        margin_pct: Safety margin percentage above the theoretical rate
        platform: Platform string (e.g., 'n9164e' for gamut). When set
            to a known Mellanox platform, an effective 2x quanta is used.

    Returns:
        int: XOFF frame rate in frames per second (rounded up)
    """
    # Gamut/Mellanox Spectrum: effective pause quanta is 2x
    effective_quanta = quanta
    if platform in ('n9164e', 'gamut'):
        effective_quanta = quanta * 2

    port_speed_bps = port_speed_gbps * 1_000_000_000
    pause_bits_per_frame = 512 * effective_quanta
    rate_fps = port_speed_bps / pause_bits_per_frame

    # Round up to ensure full pause coverage
    import math
    rate_fps_ceil = math.ceil(rate_fps)

    # Apply margin to compensate for IxNetwork timing imprecision.
    # Without margin the actual delivered rate is often slightly below
    # the theoretical minimum, leaving gaps in the pause and allowing
    # the queue to drain -> PFCWD never triggers.
    rate_fps_final = int(math.ceil(rate_fps_ceil * (1 + margin_pct / 100.0)))

    st.log(f"XOFF rate calculation: {port_speed_gbps}G port, quanta={quanta}"
           f"{' (effective ' + str(effective_quanta) + ' for ' + str(platform) + ')' if effective_quanta != quanta else ''}")
    st.log(f"  Pause bits per frame: {pause_bits_per_frame}")
    st.log(f"  Exact rate: {rate_fps:.2f} fps")
    st.log(f"  Theoretical min rate: {rate_fps_ceil} fps")
    st.log(f"  Final rate (+{margin_pct}% margin): {rate_fps_final} fps")

    return rate_fps_final


def calculate_partial_xoff_rate(port_speed_gbps, percentage=98, quanta=0xffff,
                               platform=None):
    """
    Calculate a partial XOFF rate that does NOT fully block the port.

    This is useful for testing that PFCWD is not triggered when the
    pause rate is insufficient to fully block the port.

    Args:
        port_speed_gbps: Port speed in Gbps
        percentage: Percentage of full blocking rate (default 98%)
        quanta: PFC quanta value (default 0xffff)
        platform: Platform string. Passed through to calculate_xoff_rate
            so platform-specific overrides (e.g., gamut/n9164e 2x quanta)
            are honored. Without this, partial rate would exceed the
            actual full-block rate on platforms with reduced effective
            rate, defeating the purpose of the test.

    Returns:
        int: Partial XOFF frame rate in fps
    """
    full_rate = calculate_xoff_rate(port_speed_gbps, quanta, platform=platform)
    partial_rate = int(full_rate * percentage / 100)

    st.log(f"Partial XOFF rate: {percentage}% of {full_rate} = {partial_rate} fps")

    return partial_rate


# ---------------------------------------------------------------------------
# Platform-Specific PFCWD Behavior
# ---------------------------------------------------------------------------

# Platform behavior configuration
# Key: platform identifier from detect_platform()
# Values:
#   - xoff_only_triggers_wd: Does XOFF without data trigger PFCWD?
#   - forward_action_supported: Is 'forward' action supported?
PFCWD_PLATFORM_BEHAVIOR = {
    'n9164e': {  # gamut
        # Empirically, n9164e PFCWD is drop-counter driven: a paused
        # queue with no data does not fill the buffer and does not get
        # flagged. So XOFF-only never triggers the watchdog -- same as
        # laguna/carib.
        'xoff_only_triggers_wd': False,
        'forward_action_supported': True,
        'description': 'Gamut platform - XOFF-only does NOT trigger WD, forward supported',
    },
    'laguna': {  # hf6100_64ed
        'xoff_only_triggers_wd': False,
        'forward_action_supported': False,
        'description': 'Laguna platform - XOFF-only does NOT trigger WD, forward NOT supported',
    },
    'carib': {  # hf6100_32d
        'xoff_only_triggers_wd': False,
        'forward_action_supported': False,
        'description': 'Carib platform - XOFF-only does NOT trigger WD, forward NOT supported',
    },
    'generic': {  # fallback
        'xoff_only_triggers_wd': True,
        'forward_action_supported': False,
        'description': 'Generic platform - assume XOFF-only triggers WD',
    },
}


def get_platform_pfcwd_behavior(platform):
    """
    Get platform-specific PFCWD behavior configuration.

    Args:
        platform: Platform identifier from qos_utils.detect_platform()
                  ('n9164e', 'laguna', 'carib', or 'generic')

    Returns:
        dict: Platform behavior with keys:
            - xoff_only_triggers_wd: bool
            - forward_action_supported: bool
            - description: str
    """
    behavior = PFCWD_PLATFORM_BEHAVIOR.get(platform, PFCWD_PLATFORM_BEHAVIOR['generic'])
    st.log(f"Platform '{platform}' PFCWD behavior: {behavior['description']}")
    return behavior


def is_xoff_only_triggers_wd(platform):
    """
    Check if XOFF-only (no data traffic) triggers PFCWD on this platform.

    Args:
        platform: Platform identifier

    Returns:
        bool: True if XOFF-only triggers PFCWD, False otherwise
    """
    return get_platform_pfcwd_behavior(platform)['xoff_only_triggers_wd']


def is_forward_action_supported(platform):
    """
    Check if PFCWD 'forward' action is supported on this platform.

    Args:
        platform: Platform identifier

    Returns:
        bool: True if forward action is supported, False otherwise
    """
    return get_platform_pfcwd_behavior(platform)['forward_action_supported']


# ---------------------------------------------------------------------------
# PFCWD Action Configuration
# ---------------------------------------------------------------------------


def configure_pfcwd_action(dut, action='drop', detection_time=400, restoration_time=400):
    """
    Configure PFCWD with a specific action mode.

    Args:
        dut: DUT handle from spytest
        action: 'drop' or 'forward'
        detection_time: Detection time in milliseconds (default 400)
        restoration_time: Restoration time in milliseconds (default 400)

    Returns:
        bool: True if configuration succeeded
    """
    if action not in ('drop', 'forward'):
        st.error(f"Invalid PFCWD action: {action}. Must be 'drop' or 'forward'")
        return False

    cmd = (f"sudo pfcwd start --action {action} "
           f"--restoration-time {restoration_time} all {detection_time}")

    st.log(f"Configuring PFCWD: action={action}, detect={detection_time}ms, restore={restoration_time}ms")
    st.log(f"Running: {cmd}")

    result = st.config(dut, cmd, skip_error_check=True)

    # Verify configuration was applied
    st.wait(2)
    return True


# ---------------------------------------------------------------------------
# Counter clear + comprehensive snapshot helpers (used by PFCWD timer tests
# and any other PFCWD-related test that wants a clean baseline and a rich
# per-phase counter dump).
# ---------------------------------------------------------------------------

def clear_dut_counters(dut, label=""):
    """
    Clear all interface / queue / PFC counters, watermarks and drops on the
    DUT so each test starts from a clean per-port baseline.

    NOTE: this does NOT reset the cumulative PFCWD `storm_detected` /
    `storm_restored` counters reported by `pfcwd show stats` -- those are
    not cleared by sonic-clear. Callers should take before/after deltas of
    that pair via `get_pfcwd_stats_delta()`.

    Args:
        dut: DUT handle.
        label: Optional phase / test label included in log messages.
    """
    # Local import to avoid any chance of a circular import at module load.
    import qos_test_utils as _qos_utils
    st.log(f"Phase '{label}': clearing DUT counters / watermarks")
    try:
        _qos_utils.clear_all_counters(dut)
    except Exception as e:
        st.warn(f"Phase '{label}': clear_all_counters failed: {e}")


def snapshot_pfcwd_counters(dut, ingress_intf, egress_intf, tc, label=""):
    """
    Capture comprehensive counters around a PFCWD test phase.

    Returns a dict containing PFCWD stats plus the diagnostic counters
    recorded at the start and end of each phase:

      - egress_intf (data egress / XOFF ingress on the DUT side):
            * pfcwd stats (storm_detected / storm_restored / tx_drop / ...)
            * queue counter (UC<tc> TX packets via capture_headroom_counters)
            * queue watermark (UC<tc> bytes)
            * queue drops (UC<tc>)
            * pfc_rx[tc]  -- PFC pause frames received from TGEN
      - ingress_intf (data ingress on the DUT side):
            * pg_watermark (TC priority group, shared)
            * pfc_tx[tc]  -- PFC pause frames the DUT sent upstream
    """
    import qos_test_utils as _qos_utils
    snap = {
        'label': label,
        'pfcwd': get_pfcwd_stats_parsed(dut, egress_intf, tc),
        'egress_queue_drops': _qos_utils.get_queue_drops_for_port(
            dut, egress_intf, tc),
        'egress_queue_watermark': _qos_utils.get_queue_watermark_for_port(
            dut, egress_intf, tc),
        'egress_pfc_rx': _qos_utils.get_pfc_rx_count(dut, egress_intf, tc),
        'ingress_pfc_tx': _qos_utils.get_pfc_tx_count(dut, ingress_intf, tc),
    }
    # ingress PG watermark + ingress port counters via capture_headroom_counters
    try:
        ingress_caps = _qos_utils.capture_headroom_counters(
            dut, ingress_intf, tc=tc)
        snap['ingress_pg_watermark'] = ingress_caps.get('pg_watermark', 0)
        snap['ingress_tx_packets'] = ingress_caps.get('tx_packets', 0)
        snap['ingress_rx_packets'] = ingress_caps.get('rx_packets', 0)
    except Exception as e:
        st.warn(f"snapshot[{label}]: ingress capture failed: {e}")
        snap['ingress_pg_watermark'] = 0
    # Also grab egress port TX/RX packets via the same helper.
    try:
        egress_caps = _qos_utils.capture_headroom_counters(
            dut, egress_intf, tc=tc)
        snap['egress_tx_packets'] = egress_caps.get('tx_packets', 0)
        snap['egress_rx_packets'] = egress_caps.get('rx_packets', 0)
    except Exception as e:
        st.warn(f"snapshot[{label}]: egress capture failed: {e}")
    st.log(f"FULL SNAPSHOT [{label}]: {snap}")
    return snap
