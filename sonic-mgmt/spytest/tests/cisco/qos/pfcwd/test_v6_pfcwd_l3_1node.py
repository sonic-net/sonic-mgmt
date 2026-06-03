"""
PFC Watchdog (PFCWD) L3 Single-Node Test

Validates PFC Watchdog detection and recovery on a single DUT with
3 TGEN ports using IPv6 L3 forwarding.

Topology:
    TGEN P1 (TX data 50%) --> D3 (egress port P3) --> TGEN P3
                                                        |
                                                        v
                                              (sends XOFF back to DUT)

Test Flow:
    1. Send data traffic at 50% line rate from P1 to P3
    2. TGEN P3 sends PFC XOFF frames to DUT to simulate a downstream pause
    3. Verify PFCWD detects the storm (STORM_DETECTED counter increments)
    4. Stop XOFF stream and verify PFCWD restores (STORM_RESTORED counter)
    5. Verify data traffic resumes without loss after restoration

Tests in this file:
    test_pfcwd_detection_and_recovery     -- T1: data + sustained XOFF storm; PFCWD MUST detect AND restore.
    test_pfcwd_xoff_only_no_data          -- XOFF-only (no data); should NOT trigger PFCWD on any platform.
    test_pfcwd_partial_xoff_no_trigger    -- T3/T4: data + ~80% XOFF rate (sub-block); PFCWD MUST NOT trigger, data keeps flowing.
    test_pfcwd_no_trigger                 -- T2: full-rate XOFF bursts shorter than detect_time; PFCWD MUST NOT trigger.
    test_pfcwd_drop_action                -- T5: action='drop'; storm detected, tx_drop > 0, then restored.
    test_pfcwd_forward_action             -- T6: action='forward'; on supported platforms storm detected with NO tx_drop.
    test_pfcwd_burst_storm                -- T7: N back-to-back single_burst storms; each must independently detect AND restore.
    test_pfcwd_many_to_one_trigger        -- T9: P1+P2 incast onto P3 (lossless+lossy mix) with long XOFF; PFCWD MUST detect & restore.
    test_pfcwd_many_to_one_no_trigger     -- T9: same M2O incast with sub-threshold XOFF burst; PFCWD MUST NOT trigger.

Platforms: Gamut (n9164e), Laguna, Carib
"""

import time
import pytest

from spytest import st, tgapi, SpyTestDict
import tests.cisco.tortuga.vxlan.vxlan_utils as vxlan_obj
import qos_test_utils as common_util
import traffic_stream_ixia_api as stream_api
import qos_test_utils as qos_utils
import pfcwd_utils

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
FRAME_SIZE = 1024
DATA_RATE_PERCENT = 50      # Data traffic rate as percentage of line rate
TRAFFIC_SETTLE_SECS = 5     # Time to let traffic settle before measurements
RESTORE_MARGIN_SECS = 2     # Extra time to wait after restore_time

# IPv6 addressing -- one /64 per DUT port
PORT_SUBNETS = {
    1: {'dut': '2001:db8:1::1', 'tgen': '2001:db8:1::2'},
    2: {'dut': '2001:db8:2::1', 'tgen': '2001:db8:2::2'},
    3: {'dut': '2001:db8:3::1', 'tgen': '2001:db8:3::2'},
}

# MAC addresses for TGEN NGPF device groups
TGEN_MACS = {
    1: '00:0a:01:00:01:01',
    2: '00:0a:01:00:02:01',
    3: '00:0a:01:00:03:01',
}

# Module-level state
data = SpyTestDict()


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def get_xoff_rate(port_speed_gbps, platform=None):
    """
    Calculate PFC XOFF frame rate based on port speed.

    Uses pfcwd_utils.calculate_xoff_rate() for accurate calculation.
    The formula: rate = port_speed_bps / (512 * 65535) ensures full pause.
    Gamut/n9164e applies an effective 2x pause quanta (half the rate).

    Args:
        port_speed_gbps: Port speed in Gbps
        platform: Platform string. Defaults to ``data.platform`` (set by
            the module-scope fixture) so callers don't have to thread it.

    Returns:
        int: XOFF frame rate in frames per second
    """
    if platform is None:
        platform = getattr(data, 'platform', None)
    return pfcwd_utils.calculate_xoff_rate(port_speed_gbps, platform=platform)


def is_pfcwd_default_disabled(config):
    """
    Check if PFCWD is disabled by default in DEVICE_METADATA.

    Args:
        config: CONFIG_DB dict from qos_utils.get_config_db()

    Returns:
        bool: True if default_pfcwd_status is "disable", False otherwise
    """
    device_meta = config.get("DEVICE_METADATA", {})
    localhost_meta = device_meta.get("localhost", {})
    pfcwd_status = localhost_meta.get("default_pfcwd_status", "enable")
    st.log(f"DEVICE_METADATA default_pfcwd_status: {pfcwd_status}")
    return pfcwd_status.lower() == "disable"


def configure_pfcwd(dut, config):
    """
    Configure PFCWD based on DEVICE_METADATA settings.

    If default_pfcwd_status is "disable", explicitly configure PFCWD with:
        sudo pfcwd start --action drop --restoration-time 400 all 400

    Otherwise, use the default PFCWD start command.

    Args:
        dut: DUT handle
        config: CONFIG_DB dict from qos_utils.get_config_db()
    """
    if is_pfcwd_default_disabled(config):
        st.banner("PFCWD default is disabled - configuring explicitly")
        cmd = "sudo pfcwd start --action drop --restoration-time 400 all 400"
        st.log(f"Running: {cmd}")
        st.config(dut, cmd, skip_error_check=True)
    else:
        st.banner("PFCWD default is enabled - using default start")
        pfcwd_utils.enable_pfcwd(dut)

    # Wait for PFCWD to be fully configured
    st.wait(3)


# ---------------------------------------------------------------------------
# Queue Counterpoll Utilities
# ---------------------------------------------------------------------------

def get_queue_counterpoll_interval(dut):
    """
    Get the current queue counterpoll interval in milliseconds.

    Args:
        dut: DUT handle

    Returns:
        int: Current interval in ms, or 10000 (default) if not found
    """
    raw = st.show(dut, "counterpoll show", skip_tmpl=True, skip_error_check=True)
    for line in (raw or '').split('\n'):
        if 'QUEUE_STAT' in line:
            parts = line.split()
            # Format: QUEUE_STAT     enable    10000
            for p in parts:
                if p.isdigit():
                    return int(p)
    return 10000  # Default


def set_queue_counterpoll_interval(dut, interval_ms):
    """
    Set the queue counterpoll interval.

    Args:
        dut: DUT handle
        interval_ms: Interval in milliseconds (e.g., 1000 for 1 second)

    Returns:
        int: Previous interval in ms (for restoration)
    """
    prev = get_queue_counterpoll_interval(dut)
    cmd = f"counterpoll queue interval {interval_ms}"
    st.log(f"Setting queue counterpoll interval: {cmd}")
    st.config(dut, cmd, skip_error_check=True)

    # If new interval is shorter than old, wait for old interval to ensure
    # the new polling cadence is active.
    if interval_ms < prev:
        wait_sec = (prev / 1000.0) + 1
        st.log(f"Waiting {wait_sec:.1f}s for new interval to take effect")
        st.wait(wait_sec)

    return prev


def get_queue_tx_packets(dut, intf, tc):
    """
    Get the TX packet count for a specific UC queue on an interface.

    Parses 'show queue counters <intf>' output for UC<tc> row.

    Args:
        dut: DUT handle
        intf: Interface name (e.g., 'Ethernet48')
        tc: Traffic class / queue number (e.g., 3)

    Returns:
        int: TX packet count, or 0 if not found
    """
    raw = st.show(dut, f"show queue counters {intf}",
                  skip_tmpl=True, skip_error_check=True) or ""
    uc_label = f"UC{tc}"

    for line in raw.split('\n'):
        parts = line.strip().split()
        if len(parts) >= 3 and parts[0] == intf and parts[1] == uc_label:
            try:
                return int(parts[2].replace(',', ''))
            except ValueError:
                pass
    return 0


def verify_pfcwd_config_on_port(dut, egress_intf):
    """
    Verify PFCWD is configured on the egress port.

    Args:
        dut: DUT handle
        egress_intf: Egress interface name

    Returns:
        bool: True if PFCWD is configured, False otherwise
    """
    st.banner(f"Verifying PFCWD configuration on {egress_intf}")

    # Show full PFCWD config for debugging
    st.log("Full PFCWD config output:")
    raw_config = st.show(dut, "show pfcwd config", skip_tmpl=True, skip_error_check=True)
    st.log(raw_config)

    # Get parsed config
    pfcwd_config = pfcwd_utils.get_pfcwd_config(dut)
    st.log(f"Parsed PFCWD config: {len(pfcwd_config)} ports configured")

    if not pfcwd_config:
        st.error("PFCWD is not configured on any ports!")
        return False

    # Check if egress port is in config
    if egress_intf in pfcwd_config:
        cfg = pfcwd_config[egress_intf]
        st.log(f"PFCWD on {egress_intf}: action={cfg['action']}, "
               f"detect={cfg['detection_time']}ms, restore={cfg['restoration_time']}ms")
        return True

    # Port not found - check if interface name format is different
    st.warn(f"Egress interface {egress_intf} not found in PFCWD config")
    st.log(f"Configured ports: {list(pfcwd_config.keys())[:10]}...")  # Show first 10

    # Try to find a matching port (in case of naming differences)
    # Extract port number from interface name
    import re
    match = re.search(r'(\d+)', egress_intf)
    if match:
        port_num = match.group(1)
        for port_name in pfcwd_config.keys():
            if port_num in port_name:
                st.log(f"Found similar port: {port_name}")

    return False


def discover_lossless_config(dut, egress_intf):
    """
    Discover lossless priority configuration from CONFIG_DB.

    Uses PORT_QOS_MAP to find PFC-enabled TCs and extracts the first one.
    Also discovers the corresponding DSCP value for traffic marking.

    Args:
        dut: DUT handle
        egress_intf: Egress interface name (e.g., 'Ethernet0')

    Returns:
        dict: Configuration with keys:
            - tc: First lossless traffic class
            - dscp: DSCP value mapping to that TC
            - queue: Queue number for the TC
            - all_lossless_tcs: List of all PFC-enabled TCs
            - port_speed: Interface speed in Gbps

    Raises:
        RuntimeError: If no PFC-enabled TCs found
    """
    config = qos_utils.get_config_db(dut)

    # Get PFC-enabled TCs from PORT_QOS_MAP
    port_qos = config["PORT_QOS_MAP"].get(egress_intf)
    if not port_qos:
        raise RuntimeError(f"PORT_QOS_MAP has no entry for {egress_intf}")

    pfc_enable = port_qos.get("pfc_enable", "")
    tc_list = [int(x) for x in pfc_enable.split(",") if x.strip()]
    if not tc_list:
        raise RuntimeError(f"No PFC-enabled (lossless) TCs on {egress_intf}")

    # Use the first lossless TC
    tc = tc_list[0]
    st.banner(f"Discovered lossless TCs: {tc_list} -- using TC {tc} for PFCWD test")

    # Get DSCP mapping for this TC
    dscp_map_ref = port_qos.get("dscp_to_tc_map")
    if not dscp_map_ref:
        raise RuntimeError(f"PORT_QOS_MAP[{egress_intf}] missing dscp_to_tc_map")
    map_name = dscp_map_ref.split("|")[-1].rstrip("]") if "|" in dscp_map_ref else dscp_map_ref
    dscp_table = config["DSCP_TO_TC_MAP"].get(map_name, {})

    dscp = None
    tc_str = str(tc)
    for dscp_val, mapped_tc in dscp_table.items():
        if str(mapped_tc) == tc_str:
            dscp = int(dscp_val)
            break
    if dscp is None:
        raise RuntimeError(f"No DSCP maps to TC {tc} in DSCP_TO_TC_MAP[{map_name}]")

    # Get queue mapping
    tc_q_map_ref = port_qos.get("tc_to_queue_map")
    if not tc_q_map_ref:
        raise RuntimeError(f"PORT_QOS_MAP[{egress_intf}] missing tc_to_queue_map")
    q_map_name = tc_q_map_ref.split("|")[-1].rstrip("]") if "|" in tc_q_map_ref else tc_q_map_ref
    q_table = config["TC_TO_QUEUE_MAP"].get(q_map_name, {})
    queue = q_table.get(tc_str)
    if queue is None:
        raise RuntimeError(f"TC_TO_QUEUE_MAP[{q_map_name}] has no entry for TC {tc}")
    queue = int(queue)

    speed = common_util.get_if_speed(dut, egress_intf)

    # ---- Derive a lossy TC + DSCP for background / mix traffic ----
    # Any DSCP whose TC is not in the lossless set is "lossy". Pick the
    # first lossy TC seen and its mapping DSCP; this avoids hardcoding 0
    # in case CONFIG_DB uses a non-standard map.
    lossy_tc = None
    lossy_dscp = None
    for dscp_val, mapped_tc in dscp_table.items():
        try:
            m_tc = int(mapped_tc)
        except (TypeError, ValueError):
            continue
        if m_tc in tc_list:
            continue
        lossy_tc = m_tc
        lossy_dscp = int(dscp_val)
        break
    if lossy_tc is None:
        # Fallback to TC 0 / DSCP 0 if the map is degenerate.
        lossy_tc = 0
        lossy_dscp = 0
        st.log("No lossy TC found in DSCP_TO_TC_MAP; falling back to "
               "TC=0 DSCP=0")

    result = {
        'tc': tc,
        'dscp': dscp,
        'queue': queue,
        'all_lossless_tcs': tc_list,
        'port_speed': speed,
        'lossy_tc': lossy_tc,
        'lossy_dscp': lossy_dscp,
    }

    st.log(f"Lossless config discovery results:")
    st.log(f"  TC: {tc} (all lossless TCs: {tc_list})")
    st.log(f"  DSCP: {dscp}")
    st.log(f"  Queue: {queue}")
    st.log(f"  Port Speed: {speed} Gbps")
    st.log(f"  Lossy TC: {lossy_tc}  Lossy DSCP: {lossy_dscp}")

    return result


def print_test_summary_counters(dut, dut_ports, egress_intf, tc=None):
    """
    Print a compact birdseye counter summary for the test:
      - PFC Rx/Tx for the lossless TC only, per port-of-interest
      - Interface RX_OK / TX_OK / TX_DRP, per port-of-interest
      - Egress queue counters for UC<tc> only

    Args:
        dut: DUT handle
        dut_ports: dict of {idx: port_name} for ports in the test
        egress_intf: egress interface (typically dut_ports[3])
        tc: lossless traffic class index (e.g. 3). If None, all PFC
            priorities and all queues are shown.
    """
    ports = [p for p in dut_ports.values() if p]
    if not ports:
        return

    st.banner("Test Summary: Birdseye counters")

    # ----- PFC Rx/Tx for the lossless TC -----
    try:
        raw = st.show(dut, "show pfc counters",
                      skip_tmpl=True, skip_error_check=True) or ""
        # The command emits two sections: header "Port Rx ..." then rows,
        # then header "Port Tx ..." then rows.
        section = None  # 'rx' or 'tx'
        rx_by_port = {}
        tx_by_port = {}
        for line in raw.split('\n'):
            s = line.strip()
            if not s:
                continue
            if s.startswith('Port Rx'):
                section = 'rx'
                continue
            if s.startswith('Port Tx'):
                section = 'tx'
                continue
            parts = s.split()
            if not parts or parts[0] not in ports:
                continue
            # parts: [Port, PFC0, PFC1, ..., PFC7]
            if len(parts) < 9 or tc is None:
                continue
            val = parts[1 + tc].replace(',', '')
            if section == 'rx':
                rx_by_port[parts[0]] = val
            elif section == 'tx':
                tx_by_port[parts[0]] = val

        tc_label = f"PFC{tc}" if tc is not None else "PFC*"
        st.log(f"--- PFC counters ({tc_label}) ---")
        st.log(f"  {'PORT':<20} {'RX_'+tc_label:>14} {'TX_'+tc_label:>14}")
        for p in ports:
            st.log(f"  {p:<20} {rx_by_port.get(p, '-'):>14} "
                   f"{tx_by_port.get(p, '-'):>14}")
    except Exception as e:
        st.log(f"Could not summarize PFC counters: {e}")

    # ----- Interface counters: RX_OK / TX_OK / TX_DRP -----
    try:
        port_filter = '|'.join(ports)
        raw = st.show(dut,
                      f"show interfaces counters | grep -E 'IFACE|{port_filter}'",
                      skip_tmpl=True, skip_error_check=True) or ""
        rows = {}
        for line in raw.split('\n'):
            s = line.strip()
            if not s or 'IFACE' in s:
                continue
            parts = s.split()
            if not parts or parts[0] not in ports:
                continue
            # Layout from right: TX_OK TX_BPS BPS_UNIT TX_UTIL% TX_ERR TX_DRP TX_OVR
            try:
                tx_ok = parts[-7].replace(',', '')
                tx_drp = parts[-2].replace(',', '')
            except IndexError:
                continue
            # RX_OK is 3rd column (after PORT, STATE)
            try:
                rx_ok = parts[2].replace(',', '')
            except IndexError:
                rx_ok = '-'
            rows[parts[0]] = (rx_ok, tx_ok, tx_drp)

        st.log("--- Interface counters ---")
        st.log(f"  {'PORT':<20} {'RX_OK':>16} {'TX_OK':>16} {'TX_DRP':>16}")
        for p in ports:
            rx_ok, tx_ok, tx_drp = rows.get(p, ('-', '-', '-'))
            st.log(f"  {p:<20} {rx_ok:>16} {tx_ok:>16} {tx_drp:>16}")
    except Exception as e:
        st.log(f"Could not summarize interface counters: {e}")

    # ----- Egress queue counters for the lossless UC<tc> -----
    if egress_intf:
        try:
            raw = st.show(dut, f"show queue counters {egress_intf}",
                          skip_tmpl=True, skip_error_check=True) or ""
            uc_label = f"UC{tc}" if tc is not None else None
            picked = None
            for line in raw.split('\n'):
                s = line.strip()
                if not s:
                    continue
                parts = s.split()
                if len(parts) >= 2 and parts[0] == egress_intf and (
                        uc_label is None or parts[1] == uc_label):
                    picked = parts
                    if uc_label is not None:
                        break

            st.log(f"--- Egress queue counters ({egress_intf} "
                   f"{uc_label or 'all'}) ---")
            if picked and len(picked) >= 6:
                st.log(f"  {'PORT':<20} {'TxQ':<5} {'PKTS':>16} "
                       f"{'BYTES':>20} {'DROP_PKTS':>16} {'DROP_BYTES':>20}")
                st.log(f"  {picked[0]:<20} {picked[1]:<5} "
                       f"{picked[2]:>16} {picked[3]:>20} "
                       f"{picked[4]:>16} {picked[5]:>20}")
            else:
                st.log(f"  (no {uc_label or 'queue'} row found for {egress_intf})")
        except Exception as e:
            st.log(f"Could not summarize queue counters: {e}")


# ---------------------------------------------------------------------------
# Per-test TGEN session helpers
# ---------------------------------------------------------------------------

def _reset_tgen_protocols(tg, settle_secs=8):
    """
    Force IxNetwork to re-resolve NGPF topology->port bindings by stopping
    and restarting all protocols. Workaround for cases where a previous
    test's traffic_control(reset)/regenerate sequence corrupts the
    topology->port binding (data egresses on the wrong tester port).
    """
    st.log("Restarting NGPF protocols to refresh topology->port bindings")
    try:
        tg.tg_topology_test_control(action='stop_all_protocols')
        st.wait(2)
    except Exception as e:
        st.log(f"  stop_all_protocols (non-fatal): {e}")
    try:
        tg.tg_topology_test_control(action='start_all_protocols')
    except Exception as e:
        st.log(f"  start_all_protocols failed: {e}")
        return False
    st.wait(settle_secs)
    return True


def _parse_iface_counters_row(line):
    """
    Parse a single 'show interfaces counters' data row.
    Layout: IFACE STATE RX_OK RX_BPS RX_UNIT RX_UTIL% RX_ERR RX_DRP RX_OVR
            TX_OK TX_BPS TX_UNIT TX_UTIL% TX_ERR TX_DRP TX_OVR
    Returns dict with int fields, or None on parse failure.
    """
    parts = line.split()
    if len(parts) < 16 or parts[0] == 'IFACE':
        return None
    try:
        return {
            'iface':  parts[0],
            'rx_ok':  int(parts[2].replace(',', '')),
            'rx_drp': int(parts[7].replace(',', '')),
            'tx_ok':  int(parts[9].replace(',', '')),
            'tx_drp': int(parts[14].replace(',', '')),
        }
    except (ValueError, IndexError):
        return None


def verify_data_ingress(dut, expected_ingress, off_ports, sample_secs=2):
    """
    Verify data is actually entering on the expected ingress port and NOT
    on any of the 'off_ports'. Catches IxNetwork topology->port rebinding
    bugs where a stream configured on tester port A actually transmits
    from tester port B.

    Args:
        dut: DUT name
        expected_ingress: DUT interface where data should be arriving
        off_ports: list of DUT interfaces that must remain idle
        sample_secs: wait between two snapshots to compute deltas

    Returns:
        (ok: bool, msg: str, snapshot: dict)
    """
    ports = [expected_ingress] + list(off_ports)
    grep_expr = '|'.join(['IFACE'] + ports)
    cmd = f"show interfaces counters | grep -E '{grep_expr}'"

    def _snapshot():
        out = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)
        snap = {}
        for line in (out or '').split('\n'):
            row = _parse_iface_counters_row(line)
            if row and row['iface'] in ports:
                snap[row['iface']] = row
        return snap

    s1 = _snapshot()
    st.wait(sample_secs)
    s2 = _snapshot()

    deltas = {}
    for p in ports:
        r1 = s1.get(p, {})
        r2 = s2.get(p, {})
        deltas[p] = {
            'rx_ok':  r2.get('rx_ok', 0)  - r1.get('rx_ok', 0),
            'rx_drp': r2.get('rx_drp', 0) - r1.get('rx_drp', 0),
        }
    st.log(f"verify_data_ingress: deltas over {sample_secs}s: {deltas}")

    ing_rx_ok  = deltas[expected_ingress]['rx_ok']
    ing_rx_drp = deltas[expected_ingress]['rx_drp']
    ing_total  = ing_rx_ok + ing_rx_drp
    if ing_total <= 0:
        return False, (
            f"No data ingressing on expected port {expected_ingress} "
            f"(delta rx_ok+rx_drp={ing_total}); deltas={deltas}"
        ), deltas

    # Catch "data arrives but is dropped at ingress" (no route / NDP not
    # resolved / ACL drop) -- otherwise PFCWD never sees backed-up data
    # and won't trigger.
    if ing_rx_ok == 0 and ing_rx_drp > 0:
        return False, (
            f"Data ingressing on {expected_ingress} but 100% dropped at "
            f"ingress (rx_ok=0, rx_drp={ing_rx_drp}); likely no route "
            f"or NDP not resolved. deltas={deltas}"
        ), deltas

    for p in off_ports:
        off_rx = deltas[p]['rx_ok'] + deltas[p]['rx_drp']
        if off_rx > 0:
            return False, (
                f"Data unexpectedly ingressing on {p} "
                f"(delta rx_ok+rx_drp={off_rx}); IxNetwork topology->port "
                f"binding likely corrupted. deltas={deltas}"
            ), deltas

    return True, (
        f"Data ingress OK on {expected_ingress} "
        f"(delta rx_ok={ing_rx_ok}, rx_drp={ing_rx_drp}); "
        f"off_ports {off_ports} idle"
    ), deltas


# ---------------------------------------------------------------------------
# Module-level Fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def pfcwd_module_setup(request):
    """
    Module fixture: configure DUT ports with IPv6, create TGEN NGPF
    device groups, enable PFCWD, discover lossless priority config.

    A test module may set ``SKIP_PFCWD_CONFIG = True`` at module scope
    to bypass the PFCWD enable/verify steps (used by the XOFF rate
    calibration test, which must run with PFCWD stopped).
    """
    skip_pfcwd = bool(getattr(request.module, 'SKIP_PFCWD_CONFIG', False))
    st.ensure_min_topology('T1D3:3')
    vars = st.get_testbed_vars()
    dut = vars.D3

    # Detect platform
    platform = qos_utils.detect_platform(dut)
    st.banner(f"Detected platform: {platform}")

    # Map DUT and TGEN port names
    dut_ports = {
        1: vars.D3T1P1,
        2: vars.D3T1P2,
        3: vars.D3T1P3,
    }
    tgen_ports = {
        1: 'T1D3P1',
        2: 'T1D3P2',
        3: 'T1D3P3',
    }

    # Verify all ports share the same speed
    speeds = {}
    for idx, port in dut_ports.items():
        speeds[idx] = common_util.get_if_speed(dut, port)
    if len(set(speeds.values())) != 1:
        st.report_fail('msg', f"Port speeds are not uniform: {speeds}")
    port_speed = list(speeds.values())[0]
    st.log(f"All 3 DUT ports are {port_speed}G")

    # QoS reload + IXIA PFC/FCoE L1 config
    stream_api.init_qos_on_dut(dut)
    qos_utils.load_config_db(dut)

    # Get CONFIG_DB for lossless config and PFCWD status check
    config = qos_utils.get_config_db(dut)

    # Discover lossless priority configuration on the egress port (P3)
    lossless_cfg = discover_lossless_config(dut, dut_ports[3])

    if skip_pfcwd:
        st.banner("SKIP_PFCWD_CONFIG=True - stopping PFCWD daemon for this module")
        pfcwd_utils.disable_pfcwd(dut)
        st.wait(2)
        pfcwd_timing = None
    else:
        # Configure PFCWD based on DEVICE_METADATA default_pfcwd_status
        configure_pfcwd(dut, config)

        # Verify PFCWD is configured on egress port
        if not verify_pfcwd_config_on_port(dut, dut_ports[3]):
            st.report_fail('msg', f"PFCWD not configured on egress port {dut_ports[3]}")

        # Get PFCWD timing parameters
        pfcwd_timing = pfcwd_utils.get_pfcwd_timing_params(dut, dut_ports[3])
        st.log(f"PFCWD timing parameters:")
        st.log(f"  Poll interval: {pfcwd_timing['poll_interval_sec']*1000:.0f} ms")
        st.log(f"  Detection time: {pfcwd_timing['detect_time_sec']*1000:.0f} ms")
        st.log(f"  Restore time: {pfcwd_timing['restore_time_sec']*1000:.0f} ms")

    # Store in module data
    data.dut = dut
    data.platform = platform
    data.dut_ports = dut_ports
    data.tgen_ports = tgen_ports
    data.port_speed = port_speed
    data.lossless_cfg = lossless_cfg
    data.pfcwd_timing = pfcwd_timing
    data.tc = lossless_cfg['tc']
    data.dscp = lossless_cfg['dscp']
    data.lossy_tc = lossless_cfg['lossy_tc']
    data.lossy_dscp = lossless_cfg['lossy_dscp']

    # Clean up any existing IP/VLAN config on the DUT
    st.banner("Cleaning up existing IP/VLAN configuration")
    qos_utils.cleanup_config(dut)

    # Ensure ports are in routed mode (not switchport/trunk mode) before
    # adding L3 addresses. Some testbeds have ports pre-configured as
    # trunk ports in VLANs, which must be changed to routed mode.
    # Use the helper which tries image-specific CLI variants and FAILS
    # LOUD if the mode change does not stick -- a silent failure here
    # leaves the port in access/trunk mode and the following
    # ``config interface ip add`` (skip_error_check=True) silently no-ops,
    # so traffic phases later fail with no usable diagnostic.
    st.banner("Setting DUT ports to routed mode")
    for idx in (1, 2, 3):
        port = dut_ports[idx]
        qos_utils.set_switchport_mode(dut, port, 'routed')
    st.wait(2)

    # Configure IPv6 on DUT ports (P1, P2 = ingress senders; P3 = egress).
    st.banner("Configuring IPv6 addresses on DUT ports")
    ip_cfg = ''
    for idx in (1, 2, 3):
        port = dut_ports[idx]
        ip_cfg += f'sudo config interface ip add {port} {PORT_SUBNETS[idx]["dut"]}/64\n'
    st.config(dut, ip_cfg, skip_tmpl=True, skip_error_check=True)
    st.wait(3)

    # Configure TGEN NGPF device groups (IPv6) for P1, P2, P3
    st.banner("Configuring TGEN NGPF IPv6 device groups")
    int_dict = {}
    for idx in (1, 2, 3):
        int_dict[tgen_ports[idx]] = {
            'host_ip': PORT_SUBNETS[idx]['tgen'],
            'gateway': PORT_SUBNETS[idx]['dut'],
            'mac': TGEN_MACS[idx],
        }
    handles = vxlan_obj.config_tgen_interface(int_dict, addr_family='ipv6')
    data.tgen_handles = handles
    data.int_dict = int_dict

    # Get tg handle (same object for all ports)
    tg = handles[tgen_ports[1]]['tg_handle']
    data.tg = tg

    # Get port handle for XOFF stream (P3)
    _, data.p3_port_handle = tgapi.get_handle_byname(tgen_ports[3])

    # Get MAC address of DUT port P3 for XOFF frames
    data.dut_p3_mac = common_util.get_if_mac(dut, dut_ports[3])
    st.log(f"DUT port {dut_ports[3]} MAC: {data.dut_p3_mac}")

    # Start all protocols so NDP resolves
    tg.tg_topology_test_control(action='start_all_protocols')
    st.wait(10)

    # Ping verify each TGEN endpoint -> DUT gateway
    for idx in (1, 2, 3):
        gw = PORT_SUBNETS[idx]['dut']
        int_h = handles[tgen_ports[idx]]['int_handle']
        ping_ok = vxlan_obj.ping_gateway(handles, tgen_ports[idx], gw, int_h)
        if not ping_ok:
            st.report_fail('msg', f"Ping failed: TGEN {tgen_ports[idx]} -> {gw}")

    # Disable Mellanox packet aging on platforms that need it (gamut/n9164e).
    # Without this, paused queues drain via the SDK aging timer and PFCWD
    # never sees a stuck queue, so storm_detected stays 0.
    pfcwd_utils.disable_packet_aging(dut, platform=platform)

    st.banner("PFCWD module setup complete")

    # ---- Yield to test(s) ----
    yield

    # ---- Teardown ----
    st.banner("PFCWD module teardown")
    tg.tg_traffic_control(action='stop')
    st.wait(2)

    # Re-enable Mellanox packet aging (no-op on other platforms).
    pfcwd_utils.enable_packet_aging(dut, platform=platform)

    # Disable PFCWD
    pfcwd_utils.disable_pfcwd(dut)

    # Destroy TGEN device groups
    for port_key, h in handles.items():
        try:
            tg.tg_interface_config(port_handle=h['port_handle'],
                                   handle=h['int_handle'], mode='destroy')
        except Exception as e:
            st.log(f"TGEN cleanup {port_key}: {e}")

    # Remove IPv6 from DUT
    ip_rm = ''
    for idx in (1, 2, 3):
        port = dut_ports[idx]
        ip_rm += f'sudo config interface ip remove {port} {PORT_SUBNETS[idx]["dut"]}/64\n'
    st.config(dut, ip_rm, skip_tmpl=True, skip_error_check=True)


@pytest.fixture(autouse=True)
def pfcwd_per_test_setup():
    """
    Per-test setup: refresh IxNetwork NGPF topology->port bindings before
    each test by stopping and restarting all protocols. Prevents bleed-over
    from a previous test where traffic_control(reset)/regenerate corrupted
    the binding (data egressing on the wrong tester port).
    """
    tg = data.get('tg') if hasattr(data, 'get') else getattr(data, 'tg', None)
    if tg is not None:
        try:
            tg.tg_traffic_control(action='stop')
        except Exception:
            pass
        _reset_tgen_protocols(tg)
    yield


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_pfcwd_detection_and_recovery():
    """
    Test PFCWD detection and recovery with a single lossless priority.

    Test Steps:
        1. Create data stream at 50% line rate from T1D3P1 -> T1D3P3
        2. Create PFC XOFF stream from T1D3P3 to DUT
        3. Capture PFCWD stats before traffic
        4. Start data traffic
        5. Start XOFF traffic (triggers PFCWD)
        6. Wait for detection_time + poll_interval
        7. Verify PFCWD storm detected (STORM_DETECTED > 0)
        8. Stop XOFF traffic
        9. Wait for restore_time + margin
        10. Verify PFCWD restored (STORM_RESTORED > 0)
        11. Stop data traffic and verify stats

    Pass Criteria:
        - STORM_DETECTED counter increments during XOFF storm
        - STORM_RESTORED counter increments after XOFF stops
        - TX_DROP counter shows drops during storm
    """
    dut = data.dut
    tg = data.tg
    tc = data.tc
    dscp = data.dscp
    port_speed = data.port_speed
    timing = data.pfcwd_timing
    egress_intf = data.dut_ports[3]
    tgen_ports = data.tgen_ports
    handles = data.tgen_handles

    st.banner(f"PFCWD Detection and Recovery Test")
    st.log(f"  TC: {tc}, DSCP: {dscp}, Port Speed: {port_speed}G")
    st.log(f"  Detection time: {timing['detect_time_sec']*1000:.0f} ms")
    st.log(f"  Poll interval: {timing['poll_interval_sec']*1000:.0f} ms")
    st.log(f"  Restore time: {timing['restore_time_sec']*1000:.0f} ms")

    # Calculate XOFF rate
    xoff_rate = get_xoff_rate(port_speed)
    st.log(f"  XOFF rate: {xoff_rate} fps")

    # Calculate storm duration (must exceed detection threshold).
    # Use generous duration to allow multiple detection polling cycles and
    # absorb IxNetwork rate ramp-up time. Minimum 5 sec.
    storm_duration_sec = max(
        5.0,
        (5 * timing['detect_time_sec']) + (3 * timing['poll_interval_sec']) + 1.0,
    )
    st.log(f"  Storm duration: {storm_duration_sec:.2f} seconds")

    # Calculate IP TOS byte (DSCP + ECN)
    ip_tos = dscp << 2  # DSCP is upper 6 bits, ECN is lower 2 bits (set to 0)

    xoff_stream_id = None
    data_stream_id = None

    try:
        # Step 1: Create PFC XOFF stream from T1D3P3
        st.banner(f"Creating PFC XOFF stream on T1D3P3 at {xoff_rate} fps for TC {tc}")
        xoff_stream_id = stream_api.create_pfc_xoff_stream(
            tg, tgen_ports[3], data.dut_p3_mac, xoff_rate, tc=tc
        )
        st.log(f"XOFF stream created: {xoff_stream_id}")

        # Apply XOFF stream configuration
        tg.tg_traffic_control(action='apply')
        st.wait(1)

        # Step 2: Create data stream from T1D3P1 -> T1D3P3
        st.banner(f"Creating data stream at {DATA_RATE_PERCENT}% from T1D3P1 to T1D3P3")
        tg_kwargs = dict(
            port_handle=handles[tgen_ports[1]]['port_handle'],
            port_handle2=handles[tgen_ports[3]]['port_handle'],
            mode='create',
            transmit_mode='continuous',
            rate_percent=DATA_RATE_PERCENT,
            frame_size=FRAME_SIZE,
            circuit_endpoint_type='ipv6',
            ipv6_traffic_class=ip_tos,
            emulation_src_handle=handles[tgen_ports[1]]['int_handle'],
            emulation_dst_handle=handles[tgen_ports[3]]['int_handle'],
        )
        data_result = tg.tg_traffic_config(**tg_kwargs)
        if data_result.get('status') != '1':
            st.report_fail('msg', f"Failed to create data stream: {data_result}")
        data_stream_id = data_result['stream_id']
        stream_api.set_pfc_priority_group(tg, data_result, tc)
        st.log(f"Data stream created: {data_stream_id}")

        # Apply all traffic configuration
        tg.tg_traffic_control(action='apply')
        st.wait(2)

        # Step 3: Clear all counters on DUT for a clean baseline
        st.banner("Clearing all counters on DUT for clean baseline")
        qos_utils.clear_all_counters(dut)

        # Step 4: Capture PFCWD stats before traffic
        st.banner("Capturing PFCWD stats before traffic")

        # Show full PFCWD stats for debugging
        st.log("Full PFCWD stats output:")
        raw_stats = st.show(dut, "show pfcwd stats", skip_tmpl=True, skip_error_check=True)
        st.log(raw_stats)

        # Find matching queue line for our port/TC
        st.log(f"Looking for queue: {egress_intf}:{tc}")
        for line in raw_stats.split('\n'):
            if egress_intf in line or f":{tc}" in line:
                st.log(f"  Match: {line.strip()}")

        stats_before = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats before: {stats_before}")

        # Step 4: Start data traffic only first
        st.banner("Starting data traffic")
        tg.tg_traffic_control(action='run', stream_handle=data_stream_id)
        st.wait(TRAFFIC_SETTLE_SECS)

        # Verify data is ingressing on expected port (P1) and NOT on P2;
        # catches IxNetwork topology->port rebinding bugs.
        ok_ing, msg_ing, _ = verify_data_ingress(
            dut,
            expected_ingress=data.dut_ports[1],
            off_ports=[data.dut_ports[2]],
        )
        st.log(f"Data ingress check: {msg_ing}")
        if not ok_ing:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_detection_and_recovery")
            st.report_fail('msg', f"Data ingress check failed: {msg_ing}")

        # Capture PFC RX counters before XOFF (to verify XOFF reception later)
        st.show(dut, f"show pfc counters | grep -E 'Port|{egress_intf}'",
                skip_tmpl=True, skip_error_check=True)

        # (legacy capture below removed; replaced by verify_data_ingress above)
        st.show(dut, f"show pfc counters | grep -E 'Port|{egress_intf}'",
                skip_tmpl=True, skip_error_check=True)

        # Step 5: Start XOFF traffic to trigger PFCWD
        st.banner(f"Starting XOFF traffic to trigger PFCWD storm")
        tg.tg_traffic_control(action='run', stream_handle=xoff_stream_id)

        # Step 6: Wait for detection
        wait_time = storm_duration_sec
        st.log(f"Waiting {wait_time:.2f} seconds for PFCWD detection...")
        st.wait(wait_time)

        # Verify XOFF was received by DUT
        st.banner("Verifying XOFF reception on DUT")
        st.show(dut, f"show pfc counters | grep -E 'Port|{egress_intf}'",
                skip_tmpl=True, skip_error_check=True)

        # Step 7: Check PFCWD storm detected
        st.banner("Checking PFCWD storm detection")
        stats_during = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats during storm: {stats_during}")

        delta_during = pfcwd_utils.get_pfcwd_stats_delta(stats_before, stats_during)
        st.log(f"PFCWD delta during storm: {delta_during}")

        # Verify storm detected
        detected_ok, detected_msg = pfcwd_utils.verify_pfcwd_triggered(delta_during, expected=True)
        st.log(f"Storm detection check: {detected_msg}")

        if not detected_ok:
            st.report_fail('msg', f"PFCWD storm not detected: {detected_msg}")

        st.log(f"PFCWD storm detected successfully!")
        st.log(f"  storm_detected: {delta_during['storm_detected']}")
        st.log(f"  tx_drop: {delta_during['tx_drop']}")

        # Step 8: Stop XOFF traffic
        st.banner("Stopping XOFF traffic to allow recovery")
        tg.tg_traffic_control(action='stop', stream_handle=xoff_stream_id)

        # Step 9: Wait for restoration
        restore_wait = timing['restore_time_sec'] + timing['poll_interval_sec'] + RESTORE_MARGIN_SECS
        st.log(f"Waiting {restore_wait:.2f} seconds for PFCWD restoration...")
        st.wait(restore_wait)

        # Step 10: Check PFCWD restored
        st.banner("Checking PFCWD restoration")
        stats_after = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats after restore: {stats_after}")

        delta_after = pfcwd_utils.get_pfcwd_stats_delta(stats_before, stats_after)
        st.log(f"PFCWD delta after restore: {delta_after}")

        # Verify restoration
        restored_ok, restored_msg = pfcwd_utils.verify_pfcwd_restored(delta_after)
        st.log(f"Restoration check: {restored_msg}")

        if not restored_ok:
            st.report_fail('msg', f"PFCWD not restored: {restored_msg}")

        st.log(f"PFCWD restored successfully!")
        st.log(f"  storm_detected: {delta_after['storm_detected']}")
        st.log(f"  storm_restored: {delta_after['storm_restored']}")

        # Step 11: Stop all traffic
        st.banner("Stopping all traffic")
        tg.tg_traffic_control(action='stop')
        st.wait(2)

        # Collect traffic stats
        st.banner("Collecting traffic statistics")
        try:
            stats = tg.tg_traffic_stats(mode='traffic_item')
            st.log(f"Traffic stats: {stats}")
        except Exception as e:
            st.log(f"Failed to collect traffic stats (non-fatal): {e}")

        # Report success

        st.banner("SUMMARY: TEST PASSED: test_pfcwd_detection_and_recovery")
        st.log(f"Summary:")
        st.log(f"  Platform: {data.platform}")
        st.log(f"  TC: {tc}, DSCP: {dscp}")
        st.log(f"  Storm detected: {delta_after['storm_detected']}")
        st.log(f"  Storm restored: {delta_after['storm_restored']}")
        st.log(f"  TX drops during storm: {delta_after['tx_drop']}")

        st.report_pass("test_case_passed", "test_pfcwd_detection_and_recovery passed")

    except Exception as e:
        st.banner("SUMMARY: TEST FAILED: test_pfcwd_detection_and_recovery")
        st.error(f"Test failed with exception: {e}")
        import traceback
        st.log(traceback.format_exc())
        st.report_fail('msg', f"Test failed: {e}")

    finally:
        # Print birdseye counter summary (always, even on failure)
        try:
            print_test_summary_counters(
                dut, data.dut_ports, egress_intf, tc=tc
            )
        except Exception as _e_summary:
            st.log(f"summary counters not captured: {_e_summary}")
        # Cleanup: stop all traffic
        try:
            tg.tg_traffic_control(action='stop')
        except Exception:
            pass

        # Remove traffic streams
        if data_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=data_stream_id)
            except Exception as e:
                st.log(f"Failed to remove data stream: {e}")

        if xoff_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
            except Exception as e:
                st.log(f"Failed to remove XOFF stream: {e}")


# ---------------------------------------------------------------------------
# T3: PFCWD with XOFF-only (no data) -- per-platform expectation
# ---------------------------------------------------------------------------

def test_pfcwd_xoff_only_no_data():
    """
    Send PFC XOFF frames only (no data traffic) and verify PFCWD does
    NOT trigger on any platform (paused queue with no data never fills
    the buffer, so the watchdog has nothing to flag).

    Expected per platform (see pfcwd_utils.PFCWD_PLATFORM_BEHAVIOR):
      - n9164e (gamut): XOFF-only does NOT trigger PFCWD storm
      - laguna / carib (cisco-8000): XOFF-only does NOT trigger PFCWD
    """
    dut = data.dut
    tg = data.tg
    tc = data.tc
    port_speed = data.port_speed
    timing = data.pfcwd_timing
    egress_intf = data.dut_ports[3]
    tgen_ports = data.tgen_ports
    platform = data.platform

    behavior = pfcwd_utils.get_platform_pfcwd_behavior(platform)
    expect_trigger = behavior['xoff_only_triggers_wd']

    st.banner("PFCWD XOFF-only (no data) Test")
    st.log(f"  Platform: {platform}")
    st.log(f"  Expect storm trigger (XOFF-only): {expect_trigger}")
    st.log(f"  TC: {tc}, Port Speed: {port_speed}G")

    xoff_rate = get_xoff_rate(port_speed)
    st.log(f"  XOFF rate: {xoff_rate} fps")

    storm_duration_sec = max(
        5.0,
        (5 * timing['detect_time_sec']) + (3 * timing['poll_interval_sec']) + 1.0,
    )
    st.log(f"  Storm duration: {storm_duration_sec:.2f} seconds")

    xoff_stream_id = None

    try:
        st.banner(f"Creating PFC XOFF stream on T1D3P3 at {xoff_rate} fps for TC {tc}")
        xoff_stream_id = stream_api.create_pfc_xoff_stream(
            tg, tgen_ports[3], data.dut_p3_mac, xoff_rate, tc=tc
        )
        st.log(f"XOFF stream created: {xoff_stream_id}")

        tg.tg_traffic_control(action='apply')
        st.wait(2)

        st.banner("Clearing all counters on DUT for clean baseline")
        qos_utils.clear_all_counters(dut)

        stats_before = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats before: {stats_before}")

        # Snapshot PFC RX before XOFF
        st.show(dut, f"show pfc counters | grep -E 'Port|{egress_intf}'",
                skip_tmpl=True, skip_error_check=True)

        st.banner("Starting XOFF traffic ONLY (no data)")
        tg.tg_traffic_control(action='run', stream_handle=xoff_stream_id)

        st.log(f"Waiting {storm_duration_sec:.2f} seconds...")
        st.wait(storm_duration_sec)

        st.banner("Verifying XOFF reception on DUT")
        st.show(dut, f"show pfc counters | grep -E 'Port|{egress_intf}'",
                skip_tmpl=True, skip_error_check=True)

        stats_during = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats during XOFF: {stats_during}")
        delta = pfcwd_utils.get_pfcwd_stats_delta(stats_before, stats_during)
        st.log(f"PFCWD delta: {delta}")

        st.banner("Stopping XOFF traffic")
        tg.tg_traffic_control(action='stop', stream_handle=xoff_stream_id)

        # Per-platform pass criteria
        triggered = delta['storm_detected'] > 0
        st.log(f"Storm detected delta: {delta['storm_detected']} (triggered={triggered})")

        if expect_trigger and not triggered:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_xoff_only_no_data")
            st.report_fail(
                'msg',
                f"Platform {platform} expected XOFF-only to trigger PFCWD, "
                f"but storm_detected={delta['storm_detected']}",
            )

        if (not expect_trigger) and triggered:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_xoff_only_no_data")
            st.report_fail(
                'msg',
                f"Platform {platform} expected XOFF-only NOT to trigger PFCWD, "
                f"but storm_detected={delta['storm_detected']}",
            )

        st.banner("SUMMARY: TEST PASSED: test_pfcwd_xoff_only_no_data")
        st.log(f"Summary:")
        st.log(f"  Platform: {platform}")
        st.log(f"  Expected trigger: {expect_trigger}, Got triggered: {triggered}")
        st.log(f"  storm_detected delta: {delta['storm_detected']}")
        st.report_pass("test_case_passed", "test_pfcwd_xoff_only_no_data passed")

    except Exception as e:
        st.banner("SUMMARY: TEST FAILED: test_pfcwd_xoff_only_no_data")
        st.error(f"Test failed with exception: {e}")
        import traceback
        st.log(traceback.format_exc())
        st.report_fail('msg', f"Test failed: {e}")

    finally:
        # Print birdseye counter summary (always, even on failure)
        try:
            print_test_summary_counters(
                dut, data.dut_ports, egress_intf, tc=tc
            )
        except Exception as _e_summary:
            st.log(f"summary counters not captured: {_e_summary}")
        try:
            tg.tg_traffic_control(action='stop')
        except Exception:
            pass

        if xoff_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
            except Exception as e:
                st.log(f"Failed to remove XOFF stream: {e}")


# ---------------------------------------------------------------------------
# T4: PFCWD with partial XOFF rate -- should NOT trigger
# ---------------------------------------------------------------------------

def test_pfcwd_partial_xoff_no_trigger():
    """
    Send data + a PARTIAL PFC XOFF rate (below the full-block threshold)
    and verify PFCWD does NOT trigger and data continues to flow.

    Pass criteria (all platforms):
      - storm_detected delta == 0
      - data traffic egress continues (TX_OK > 0 on egress port)
    """
    dut = data.dut
    tg = data.tg
    tc = data.tc
    dscp = data.dscp
    port_speed = data.port_speed
    timing = data.pfcwd_timing
    egress_intf = data.dut_ports[3]
    tgen_ports = data.tgen_ports
    handles = data.tgen_handles

    # Use ~80% of full XOFF rate -- well below the block threshold to leave
    # clear bandwidth for data, while still pausing intermittently.
    partial_pct = 80
    xoff_rate = pfcwd_utils.calculate_partial_xoff_rate(
        port_speed, percentage=partial_pct, platform=data.platform)

    st.banner("PFCWD Partial XOFF (no trigger) Test")
    st.log(f"  Platform: {data.platform}")
    st.log(f"  TC: {tc}, DSCP: {dscp}, Port Speed: {port_speed}G")
    st.log(f"  Partial XOFF rate: {xoff_rate} fps ({partial_pct}% of full)")

    storm_duration_sec = max(
        5.0,
        (5 * timing['detect_time_sec']) + (3 * timing['poll_interval_sec']) + 1.0,
    )
    st.log(f"  Run duration: {storm_duration_sec:.2f} seconds")

    ip_tos = dscp << 2
    xoff_stream_id = None
    data_stream_id = None

    try:
        st.banner(f"Creating partial PFC XOFF stream on T1D3P3 at {xoff_rate} fps")
        xoff_stream_id = stream_api.create_pfc_xoff_stream(
            tg, tgen_ports[3], data.dut_p3_mac, xoff_rate, tc=tc
        )
        tg.tg_traffic_control(action='apply')
        st.wait(1)

        st.banner(f"Creating data stream at {DATA_RATE_PERCENT}% from T1D3P1 -> T1D3P3")
        tg_kwargs = dict(
            port_handle=handles[tgen_ports[1]]['port_handle'],
            port_handle2=handles[tgen_ports[3]]['port_handle'],
            mode='create',
            transmit_mode='continuous',
            rate_percent=DATA_RATE_PERCENT,
            frame_size=FRAME_SIZE,
            circuit_endpoint_type='ipv6',
            ipv6_traffic_class=ip_tos,
            emulation_src_handle=handles[tgen_ports[1]]['int_handle'],
            emulation_dst_handle=handles[tgen_ports[3]]['int_handle'],
        )
        data_result = tg.tg_traffic_config(**tg_kwargs)
        if data_result.get('status') != '1':
            st.report_fail('msg', f"Failed to create data stream: {data_result}")
        data_stream_id = data_result['stream_id']
        stream_api.set_pfc_priority_group(tg, data_result, tc)

        tg.tg_traffic_control(action='apply')
        st.wait(2)

        st.banner("Clearing all counters on DUT for clean baseline")
        qos_utils.clear_all_counters(dut)

        stats_before = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats before: {stats_before}")

        st.banner("Starting data + partial XOFF traffic")
        tg.tg_traffic_control(action='run', stream_handle=data_stream_id)
        st.wait(TRAFFIC_SETTLE_SECS)

        ok_ing, msg_ing, _ = verify_data_ingress(
            dut,
            expected_ingress=data.dut_ports[1],
            off_ports=[data.dut_ports[2]],
        )
        st.log(f"Data ingress check: {msg_ing}")
        if not ok_ing:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_partial_xoff_no_trigger")
            st.report_fail('msg', f"Data ingress check failed: {msg_ing}")

        tg.tg_traffic_control(action='run', stream_handle=xoff_stream_id)
        st.log(f"Waiting {storm_duration_sec:.2f} seconds...")
        st.wait(storm_duration_sec)

        st.banner("Verifying egress + PFC counters during partial XOFF")
        st.show(dut, f"show interfaces counters | grep -E 'IFACE|{egress_intf}'",
                skip_tmpl=True, skip_error_check=True)
        st.show(dut, f"show pfc counters | grep -E 'Port|{egress_intf}'",
                skip_tmpl=True, skip_error_check=True)

        stats_during = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats during partial XOFF: {stats_during}")
        delta = pfcwd_utils.get_pfcwd_stats_delta(stats_before, stats_during)
        st.log(f"PFCWD delta: {delta}")

        st.banner("Stopping all traffic")
        tg.tg_traffic_control(action='stop')
        st.wait(2)

        # Pass criteria 1: PFCWD must NOT have triggered
        if delta['storm_detected'] != 0:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_partial_xoff_no_trigger")
            st.report_fail(
                'msg',
                f"PFCWD unexpectedly triggered with partial XOFF "
                f"({partial_pct}% of full): storm_detected={delta['storm_detected']}",
            )

        # Pass criteria 1b: lossless TC must have ZERO drops on egress queue
        # (no PFCWD action, no congestion drop on lossless queue).
        if delta['tx_drop'] != 0:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_partial_xoff_no_trigger")
            st.report_fail(
                'msg',
                f"Lossless TC{tc} had unexpected drops on {egress_intf} "
                f"with partial XOFF ({partial_pct}% of full): "
                f"tx_drop={delta['tx_drop']} (expected 0)",
            )

        # Pass criteria 2: data traffic should have egressed (TX_OK > 0)
        # The clear_all_counters at start gives a clean baseline.
        try:
            tx_ok = 0
            iface_out = st.show(
                dut,
                f"show interfaces counters | grep -E 'IFACE|{egress_intf}'",
                skip_tmpl=True, skip_error_check=True,
            )
            for line in iface_out.split('\n'):
                if egress_intf in line and 'IFACE' not in line:
                    parts = line.split()
                    # Layout from right: TX_OK TX_BPS BPS_UNIT TX_UTIL% TX_ERR TX_DRP TX_OVR
                    # TX_OK is always the 7th token from the end.
                    if len(parts) >= 7:
                        try:
                            tx_ok = int(parts[-7].replace(',', ''))
                        except ValueError:
                            pass
                    break
            st.log(f"Egress TX_OK on {egress_intf}: {tx_ok}")
            if tx_ok == 0:
                st.banner("SUMMARY: TEST FAILED: test_pfcwd_partial_xoff_no_trigger")
                st.report_fail(
                    'msg',
                    f"No data egressed on {egress_intf} with partial XOFF "
                    f"({partial_pct}% of full); expected traffic to continue flowing",
                )
        except Exception as e:
            st.log(f"Could not parse TX_OK (non-fatal): {e}")

        st.banner("SUMMARY: TEST PASSED: test_pfcwd_partial_xoff_no_trigger")
        st.log(f"Summary:")
        st.log(f"  Platform: {data.platform}")
        st.log(f"  Partial XOFF rate: {xoff_rate} fps ({partial_pct}% of full)")
        st.log(f"  storm_detected delta: {delta['storm_detected']} (expected 0)")
        st.report_pass("test_case_passed", "test_pfcwd_partial_xoff_no_trigger passed")

    except Exception as e:
        st.banner("SUMMARY: TEST FAILED: test_pfcwd_partial_xoff_no_trigger")
        st.error(f"Test failed with exception: {e}")
        import traceback
        st.log(traceback.format_exc())
        st.report_fail('msg', f"Test failed: {e}")

    finally:
        # Print birdseye counter summary (always, even on failure)
        try:
            print_test_summary_counters(
                dut, data.dut_ports, egress_intf, tc=tc
            )
        except Exception as _e_summary:
            st.log(f"summary counters not captured: {_e_summary}")
        try:
            tg.tg_traffic_control(action='stop')
        except Exception:
            pass

        if data_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=data_stream_id)
            except Exception as e:
                st.log(f"Failed to remove data stream: {e}")

        if xoff_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
            except Exception as e:
                st.log(f"Failed to remove XOFF stream: {e}")



# ---------------------------------------------------------------------------
# T2: PFCWD with SHORT XOFF storm -- should NOT trigger
# ---------------------------------------------------------------------------

def test_pfcwd_no_trigger():
    """
    Send a full-rate XOFF storm for a duration SHORTER than the PFCWD
    detection time, and verify PFCWD does NOT trigger.

    Pass criteria (all platforms):
      - storm_detected delta == 0 (storm too short to be detected)
    """
    dut = data.dut
    tg = data.tg
    tc = data.tc
    dscp = data.dscp
    port_speed = data.port_speed
    timing = data.pfcwd_timing
    egress_intf = data.dut_ports[3]
    tgen_ports = data.tgen_ports
    handles = data.tgen_handles

    # Each burst is just below detect_time (0.95x) so PFCWD should never
    # cross the threshold. Repeat several times with a quiet gap between
    # bursts so the PFCWD detection state resets.
    burst_duration_sec = max(0.05, timing['detect_time_sec'] * 0.95)
    burst_count = 3
    burst_gap_sec = 1.0

    st.banner("PFCWD No-Trigger (repeated short bursts) Test")
    st.log(f"  Platform: {data.platform}")
    st.log(f"  TC: {tc}, DSCP: {dscp}, Port Speed: {port_speed}G")
    st.log(f"  Detect time: {timing['detect_time_sec']*1000:.0f} ms")
    st.log(f"  Burst duration: {burst_duration_sec*1000:.0f} ms "
           f"(0.95 x detect_time, must NOT trigger)")
    st.log(f"  Burst count: {burst_count}, gap: {burst_gap_sec*1000:.0f} ms")

    xoff_rate = get_xoff_rate(port_speed)
    st.log(f"  XOFF rate: {xoff_rate} fps")

    # Use single_burst so each burst self-terminates after a fixed number
    # of frames. IxNetwork's stop on a continuous PFC stream can take
    # many seconds to take effect (observed ~30s), which would make each
    # "short" burst into a sustained storm and falsely trigger PFCWD.
    pkts_per_burst = max(1, int(round(xoff_rate * burst_duration_sec)))
    nominal_burst_ms = (pkts_per_burst / float(xoff_rate)) * 1000.0
    st.log(f"  pkts_per_burst: {pkts_per_burst} "
           f"(= {xoff_rate} fps * {burst_duration_sec:.3f} s)")
    st.log(f"  Nominal on-wire burst duration: {nominal_burst_ms:.1f} ms "
           f"@ {xoff_rate} fps (must stay < detect_time "
           f"{timing['detect_time_sec']*1000:.0f} ms)")

    ip_tos = dscp << 2
    xoff_stream_id = None
    data_stream_id = None

    try:
        st.banner(f"Creating PFC XOFF single_burst stream on T1D3P3 "
                  f"({pkts_per_burst} frames @ {xoff_rate} fps)")
        xoff_stream_id = stream_api.create_pfc_xoff_stream(
            tg, tgen_ports[3], data.dut_p3_mac, xoff_rate, tc=tc,
            frame_count=pkts_per_burst,
        )
        tg.tg_traffic_control(action='apply')
        st.wait(1)

        st.banner(f"Creating data stream at {DATA_RATE_PERCENT}% from T1D3P1 -> T1D3P3")
        tg_kwargs = dict(
            port_handle=handles[tgen_ports[1]]['port_handle'],
            port_handle2=handles[tgen_ports[3]]['port_handle'],
            mode='create',
            transmit_mode='continuous',
            rate_percent=DATA_RATE_PERCENT,
            frame_size=FRAME_SIZE,
            circuit_endpoint_type='ipv6',
            ipv6_traffic_class=ip_tos,
            emulation_src_handle=handles[tgen_ports[1]]['int_handle'],
            emulation_dst_handle=handles[tgen_ports[3]]['int_handle'],
        )
        data_result = tg.tg_traffic_config(**tg_kwargs)
        if data_result.get('status') != '1':
            st.report_fail('msg', f"Failed to create data stream: {data_result}")
        data_stream_id = data_result['stream_id']
        stream_api.set_pfc_priority_group(tg, data_result, tc)

        tg.tg_traffic_control(action='apply')
        st.wait(2)

        st.banner("Clearing all counters on DUT for clean baseline")
        qos_utils.clear_all_counters(dut)

        stats_before = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats before: {stats_before}")

        st.banner("Starting data traffic (will keep flowing throughout)")
        tg.tg_traffic_control(action='run', stream_handle=data_stream_id)
        st.wait(TRAFFIC_SETTLE_SECS)

        # Verify data is actually egressing on the right port before bursts.
        ok_ing, msg_ing, _ = verify_data_ingress(
            dut,
            expected_ingress=data.dut_ports[1],
            off_ports=[data.dut_ports[2]],
        )
        st.log(f"Data ingress check: {msg_ing}")
        if not ok_ing:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_burst_storm")
            st.report_fail('msg', f"Data ingress check failed: {msg_ing}")

        # Repeat sub-threshold bursts. Each burst is a single_burst stream
        # that self-terminates after pkts_per_burst frames, so we don't
        # need (and must not call) tg_traffic_control(stop) on it.
        for i in range(1, burst_count + 1):
            st.banner(f"Burst {i}/{burst_count}: XOFF single_burst "
                      f"({pkts_per_burst} frames, ~{burst_duration_sec*1000:.0f} ms)")
            tg.tg_traffic_control(action='run', stream_handle=xoff_stream_id)
            # Wait for the burst to complete (its nominal duration) plus
            # a small buffer, then the full quiet gap before the next burst.
            st.wait(burst_duration_sec + 0.1)
            if i < burst_count:
                st.log(f"  Quiet gap {burst_gap_sec*1000:.0f} ms before next burst")
                st.wait(burst_gap_sec)

        # Allow one full detect+poll cycle after the last burst to catch
        # any (unexpected) deferred detection.
        observe_wait = timing['detect_time_sec'] + timing['poll_interval_sec'] + 0.5
        st.log(f"Waiting {observe_wait:.2f}s for any (unexpected) detection...")
        st.wait(observe_wait)

        stats_after = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats after bursts: {stats_after}")
        delta = pfcwd_utils.get_pfcwd_stats_delta(stats_before, stats_after)
        st.log(f"PFCWD delta: {delta}")

        st.banner("Stopping all traffic")
        tg.tg_traffic_control(action='stop')
        st.wait(2)

        if delta['storm_detected'] != 0:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_no_trigger")
            st.report_fail(
                'msg',
                f"PFCWD unexpectedly triggered with {burst_count} sub-threshold bursts "
                f"({burst_duration_sec*1000:.0f} ms each < detect_time "
                f"{timing['detect_time_sec']*1000:.0f} ms): "
                f"storm_detected={delta['storm_detected']}",
            )

        # Lossless TC must have ZERO drops on egress queue throughout
        # the sub-threshold bursts (no PFCWD action, no congestion drop).
        if delta['tx_drop'] != 0:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_no_trigger")
            st.report_fail(
                'msg',
                f"Lossless TC{tc} had unexpected drops on {egress_intf} "
                f"during sub-threshold bursts: "
                f"tx_drop={delta['tx_drop']} (expected 0)",
            )

        st.banner("SUMMARY: TEST PASSED: test_pfcwd_no_trigger")
        st.log(f"Summary:")
        st.log(f"  Platform: {data.platform}")
        st.log(f"  Bursts: {burst_count} x {burst_duration_sec*1000:.0f} ms "
               f"(detect_time: {timing['detect_time_sec']*1000:.0f} ms, "
               f"gap: {burst_gap_sec*1000:.0f} ms)")
        st.log(f"  storm_detected delta: {delta['storm_detected']} (expected 0)")
        st.report_pass("test_case_passed", "test_pfcwd_no_trigger passed")

    except Exception as e:
        st.banner("SUMMARY: TEST FAILED: test_pfcwd_no_trigger")
        st.error(f"Test failed with exception: {e}")
        import traceback
        st.log(traceback.format_exc())
        st.report_fail('msg', f"Test failed: {e}")

    finally:
        # Print birdseye counter summary (always, even on failure)
        try:
            print_test_summary_counters(
                dut, data.dut_ports, egress_intf, tc=tc
            )
        except Exception as _e_summary:
            st.log(f"summary counters not captured: {_e_summary}")
        try:
            tg.tg_traffic_control(action='stop')
        except Exception:
            pass

        if data_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=data_stream_id)
            except Exception as e:
                st.log(f"Failed to remove data stream: {e}")

        if xoff_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
            except Exception as e:
                st.log(f"Failed to remove XOFF stream: {e}")


# ---------------------------------------------------------------------------
# T5: PFCWD DROP action -- verify packets are dropped during storm
# ---------------------------------------------------------------------------

def test_pfcwd_drop_action():
    """
    Configure PFCWD with action='drop' explicitly and verify that during
    a sustained XOFF storm:
      - PFCWD storm is detected
      - TX_DROP counter on the affected queue increments (drop action active)
      - After XOFF stops, storm is restored

    Pass criteria (all platforms supporting drop):
      - storm_detected delta > 0
      - tx_drop delta > 0
      - storm_restored delta > 0 after XOFF stops
    """
    dut = data.dut
    tg = data.tg
    tc = data.tc
    dscp = data.dscp
    port_speed = data.port_speed
    timing = data.pfcwd_timing
    egress_intf = data.dut_ports[3]
    tgen_ports = data.tgen_ports
    handles = data.tgen_handles

    detect_ms = int(timing['detect_time_sec'] * 1000)
    restore_ms = int(timing['restore_time_sec'] * 1000)

    st.banner("PFCWD DROP Action Test")
    st.log(f"  Platform: {data.platform}")
    st.log(f"  TC: {tc}, DSCP: {dscp}, Port Speed: {port_speed}G")
    st.log(f"  Configuring action=drop, detect={detect_ms}ms, restore={restore_ms}ms")

    # Explicitly enforce drop action.
    pfcwd_utils.configure_pfcwd_action(
        dut, action='drop',
        detection_time=detect_ms,
        restoration_time=restore_ms,
    )

    # Verify action='drop' is set on the egress port.
    ok, msg = pfcwd_utils.verify_pfcwd_config(
        dut, egress_intf,
        expected_action='drop',
        expected_detection_time=detect_ms,
        expected_restoration_time=restore_ms,
    )
    st.log(f"PFCWD config verification: {msg}")
    if not ok:
        st.banner("SUMMARY: TEST FAILED: test_pfcwd_drop_action")
        st.report_fail('msg', f"PFCWD drop action config not applied: {msg}")

    xoff_rate = get_xoff_rate(port_speed)
    st.log(f"  XOFF rate: {xoff_rate} fps")

    storm_duration_sec = max(
        5.0,
        (5 * timing['detect_time_sec']) + (3 * timing['poll_interval_sec']) + 1.0,
    )
    st.log(f"  Storm duration: {storm_duration_sec:.2f} seconds")

    ip_tos = dscp << 2
    xoff_stream_id = None
    data_stream_id = None

    try:
        st.banner(f"Creating PFC XOFF stream on T1D3P3 at {xoff_rate} fps")
        xoff_stream_id = stream_api.create_pfc_xoff_stream(
            tg, tgen_ports[3], data.dut_p3_mac, xoff_rate, tc=tc
        )
        tg.tg_traffic_control(action='apply')
        st.wait(1)

        st.banner(f"Creating data stream at {DATA_RATE_PERCENT}% from T1D3P1 -> T1D3P3")
        tg_kwargs = dict(
            port_handle=handles[tgen_ports[1]]['port_handle'],
            port_handle2=handles[tgen_ports[3]]['port_handle'],
            mode='create',
            transmit_mode='continuous',
            rate_percent=DATA_RATE_PERCENT,
            frame_size=FRAME_SIZE,
            circuit_endpoint_type='ipv6',
            ipv6_traffic_class=ip_tos,
            emulation_src_handle=handles[tgen_ports[1]]['int_handle'],
            emulation_dst_handle=handles[tgen_ports[3]]['int_handle'],
        )
        data_result = tg.tg_traffic_config(**tg_kwargs)
        if data_result.get('status') != '1':
            st.report_fail('msg', f"Failed to create data stream: {data_result}")
        data_stream_id = data_result['stream_id']
        stream_api.set_pfc_priority_group(tg, data_result, tc)

        tg.tg_traffic_control(action='apply')
        st.wait(2)

        st.banner("Clearing all counters on DUT for clean baseline")
        qos_utils.clear_all_counters(dut)

        stats_before = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats before: {stats_before}")

        st.banner("Starting data + XOFF storm")
        tg.tg_traffic_control(action='run', stream_handle=data_stream_id)
        st.wait(TRAFFIC_SETTLE_SECS)

        ok_ing, msg_ing, _ = verify_data_ingress(
            dut,
            expected_ingress=data.dut_ports[1],
            off_ports=[data.dut_ports[2]],
        )
        st.log(f"Data ingress check: {msg_ing}")
        if not ok_ing:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_drop_action")
            st.report_fail('msg', f"Data ingress check failed: {msg_ing}")

        tg.tg_traffic_control(action='run', stream_handle=xoff_stream_id)

        st.log(f"Waiting {storm_duration_sec:.2f}s for storm + drops...")
        st.wait(storm_duration_sec)

        stats_during = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats during storm: {stats_during}")
        delta_during = pfcwd_utils.get_pfcwd_stats_delta(stats_before, stats_during)
        st.log(f"PFCWD delta during storm: {delta_during}")

        # Validate storm detected and drops occurred.
        if delta_during['storm_detected'] == 0:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_drop_action")
            st.report_fail(
                'msg',
                f"PFCWD did not detect storm with drop action: "
                f"storm_detected={delta_during['storm_detected']}",
            )

        if delta_during['tx_drop'] == 0:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_drop_action")
            st.report_fail(
                'msg',
                f"PFCWD drop action did not produce any TX drops: "
                f"tx_drop={delta_during['tx_drop']}",
            )

        st.banner("Stopping XOFF, waiting for restoration")
        tg.tg_traffic_control(action='stop', stream_handle=xoff_stream_id)
        restore_wait = timing['restore_time_sec'] + timing['poll_interval_sec'] + RESTORE_MARGIN_SECS
        st.wait(restore_wait)

        stats_after = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats after restore: {stats_after}")
        delta_after = pfcwd_utils.get_pfcwd_stats_delta(stats_before, stats_after)
        st.log(f"PFCWD delta after restore: {delta_after}")

        restored_ok, restored_msg = pfcwd_utils.verify_pfcwd_restored(delta_after)
        st.log(f"Restoration check: {restored_msg}")
        if not restored_ok:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_drop_action")
            st.report_fail('msg', f"PFCWD not restored: {restored_msg}")

        st.banner("Stopping all traffic")
        tg.tg_traffic_control(action='stop')
        st.wait(2)

        st.banner("SUMMARY: TEST PASSED: test_pfcwd_drop_action")
        st.log(f"Summary:")
        st.log(f"  Platform: {data.platform}")
        st.log(f"  Action: drop")
        st.log(f"  storm_detected: {delta_after['storm_detected']}")
        st.log(f"  storm_restored: {delta_after['storm_restored']}")
        st.log(f"  tx_drop during storm: {delta_during['tx_drop']}")
        st.report_pass("test_case_passed", "test_pfcwd_drop_action passed")

    except Exception as e:
        st.banner("SUMMARY: TEST FAILED: test_pfcwd_drop_action")
        st.error(f"Test failed with exception: {e}")
        import traceback
        st.log(traceback.format_exc())
        st.report_fail('msg', f"Test failed: {e}")

    finally:
        # Print birdseye counter summary (always, even on failure)
        try:
            print_test_summary_counters(
                dut, data.dut_ports, egress_intf, tc=tc
            )
        except Exception as _e_summary:
            st.log(f"summary counters not captured: {_e_summary}")
        try:
            tg.tg_traffic_control(action='stop')
        except Exception:
            pass

        if data_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=data_stream_id)
            except Exception as e:
                st.log(f"Failed to remove data stream: {e}")

        if xoff_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
            except Exception as e:
                st.log(f"Failed to remove XOFF stream: {e}")


# ---------------------------------------------------------------------------
# Shared helpers used by the standalone XOFF-rate calibration test in
# test_port_pfc_xoff_rate.py (kept here so the calibration file can
# import them rather than duplicate).
# ---------------------------------------------------------------------------

def _check_traffic_blocked(dut, egress_intf, tc, sample_interval=3.0):
    """
    Check if traffic is blocked by comparing queue TX packet counts.

    Takes two samples `sample_interval` seconds apart and checks if the
    queue counter incremented. If it didn't increment, traffic is blocked.

    Args:
        dut: DUT handle
        egress_intf: Egress interface name
        tc: Traffic class (queue number)
        sample_interval: Time between samples in seconds

    Returns:
        tuple: (blocked: bool, count1: int, count2: int)
    """
    count1 = get_queue_tx_packets(dut, egress_intf, tc)
    st.log(f"    Queue UC{tc} TX count (sample 1): {count1}")

    st.wait(sample_interval)

    count2 = get_queue_tx_packets(dut, egress_intf, tc)
    st.log(f"    Queue UC{tc} TX count (sample 2): {count2}")

    blocked = (count2 <= count1)
    st.log(f"    Delta: {count2 - count1} -> "
           f"{'BLOCKED' if blocked else 'FLOWING'}")

    return blocked, count1, count2

# ---------------------------------------------------------------------------
# T6: PFCWD FORWARD action -- packets must NOT be dropped during storm
# ---------------------------------------------------------------------------

def test_pfcwd_forward_action():
    """
    Configure PFCWD with action='forward' and verify behaviour during a
    sustained XOFF storm.

    Configuration: ALL supported platforms accept the 'forward' config -
    so the readback MUST show action='forward' on every platform.

    Per-platform RUNTIME behaviour during a detected storm
    (see pfcwd_utils.PFCWD_PLATFORM_BEHAVIOR):
      - n9164e (gamut): forward IS honoured at the data plane.
          Pass: storm_detected > 0, tx_drop == 0, storm_restored > 0
      - laguna / carib: 'forward' config is accepted but the data plane
          still behaves as 'drop' during a storm.
          Pass: storm_detected > 0, tx_drop > 0, storm_restored > 0
    """
    dut = data.dut
    tg = data.tg
    tc = data.tc
    dscp = data.dscp
    port_speed = data.port_speed
    platform = data.platform
    timing = data.pfcwd_timing
    egress_intf = data.dut_ports[3]
    tgen_ports = data.tgen_ports
    handles = data.tgen_handles

    forward_supported = pfcwd_utils.is_forward_action_supported(platform)
    detect_ms = int(timing['detect_time_sec'] * 1000)
    restore_ms = int(timing['restore_time_sec'] * 1000)

    st.banner("PFCWD FORWARD Action Test")
    st.log(f"  Platform: {platform}")
    st.log(f"  Forward at data-plane supported: {forward_supported}")
    st.log(f"  TC: {tc}, DSCP: {dscp}, Port Speed: {port_speed}G")
    st.log(f"  Configuring action=forward, detect={detect_ms}ms, "
           f"restore={restore_ms}ms")

    # Configure forward action. ALL platforms accept the config.
    pfcwd_utils.configure_pfcwd_action(
        dut, action='forward',
        detection_time=detect_ms,
        restoration_time=restore_ms,
    )

    # Read back what is actually programmed on the egress port. All
    # platforms must accept the 'forward' config string even if the
    # data-plane behaviour differs.
    actual_cfg = pfcwd_utils.get_pfcwd_config(dut, port=egress_intf)
    actual_action = actual_cfg.get('action') if actual_cfg else None
    st.log(f"PFCWD on {egress_intf}: action={actual_action} "
           f"(expected: forward on all platforms)")

    if actual_action != 'forward':
        st.banner("SUMMARY: TEST FAILED: test_pfcwd_forward_action")
        st.report_fail(
            'msg',
            f"PFCWD config readback shows action={actual_action} on "
            f"{egress_intf}; expected 'forward' (all platforms accept "
            f"this config string).",
        )

    # Per-platform RUNTIME expectation:
    #   forward_supported = True (gamut):
    #       PFCWD detects storm (storm_detected > 0), but no drops.
    #   forward_supported = False (laguna/carib):
    #       PFCWD becomes inactive when action=forward (STATUS=N/A);
    #       storm_detected stays 0, and no drops occur. The data plane
    #       continues to forward without intervention.
    if forward_supported:
        expect_detected = True
        st.log("  Data-plane expectation: storm_detected > 0, tx_drop == 0 "
               "(forward honoured)")
    else:
        expect_detected = False
        st.log("  Data-plane expectation: storm_detected == 0, tx_drop == 0 "
               "(PFCWD silently disabled when action=forward not supported)")

    xoff_rate = get_xoff_rate(port_speed)
    st.log(f"  XOFF rate: {xoff_rate} fps")

    storm_duration_sec = max(
        5.0,
        (5 * timing['detect_time_sec']) + (3 * timing['poll_interval_sec']) + 1.0,
    )
    st.log(f"  Storm duration: {storm_duration_sec:.2f} seconds")

    ip_tos = dscp << 2
    xoff_stream_id = None
    data_stream_id = None

    try:
        st.banner(f"Creating PFC XOFF stream on T1D3P3 at {xoff_rate} fps")
        xoff_stream_id = stream_api.create_pfc_xoff_stream(
            tg, tgen_ports[3], data.dut_p3_mac, xoff_rate, tc=tc
        )
        tg.tg_traffic_control(action='apply')
        st.wait(1)

        st.banner(f"Creating data stream at {DATA_RATE_PERCENT}% from "
                  f"T1D3P1 -> T1D3P3")
        tg_kwargs = dict(
            port_handle=handles[tgen_ports[1]]['port_handle'],
            port_handle2=handles[tgen_ports[3]]['port_handle'],
            mode='create',
            transmit_mode='continuous',
            rate_percent=DATA_RATE_PERCENT,
            frame_size=FRAME_SIZE,
            circuit_endpoint_type='ipv6',
            ipv6_traffic_class=ip_tos,
            emulation_src_handle=handles[tgen_ports[1]]['int_handle'],
            emulation_dst_handle=handles[tgen_ports[3]]['int_handle'],
        )
        data_result = tg.tg_traffic_config(**tg_kwargs)
        if data_result.get('status') != '1':
            st.report_fail('msg', f"Failed to create data stream: {data_result}")
        data_stream_id = data_result['stream_id']
        stream_api.set_pfc_priority_group(tg, data_result, tc)
        tg.tg_traffic_control(action='apply')
        st.wait(2)

        st.banner("Clearing all counters on DUT for clean baseline")
        qos_utils.clear_all_counters(dut)

        stats_before = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats before: {stats_before}")

        st.banner("Starting data + XOFF storm")
        tg.tg_traffic_control(action='run', stream_handle=data_stream_id)
        st.wait(TRAFFIC_SETTLE_SECS)

        ok_ing, msg_ing, _ = verify_data_ingress(
            dut,
            expected_ingress=data.dut_ports[1],
            off_ports=[data.dut_ports[2]],
        )
        st.log(f"Data ingress check: {msg_ing}")
        if not ok_ing:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_forward_action")
            st.report_fail('msg', f"Data ingress check failed: {msg_ing}")

        tg.tg_traffic_control(action='run', stream_handle=xoff_stream_id)

        st.log(f"Waiting {storm_duration_sec:.2f}s for storm...")
        st.wait(storm_duration_sec)

        stats_during = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats during storm: {stats_during}")
        delta_during = pfcwd_utils.get_pfcwd_stats_delta(stats_before, stats_during)
        st.log(f"PFCWD delta during storm: {delta_during}")

        if expect_detected and delta_during['storm_detected'] == 0:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_forward_action")
            st.report_fail(
                'msg',
                f"Platform {platform} should detect storm with forward "
                f"action (storm_detected > 0), but storm_detected="
                f"{delta_during['storm_detected']}",
            )
        if (not expect_detected) and delta_during['storm_detected'] != 0:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_forward_action")
            st.report_fail(
                'msg',
                f"Platform {platform} should NOT detect storm with forward "
                f"action (PFCWD silently disabled), but storm_detected="
                f"{delta_during['storm_detected']}",
            )

        # Forward action MUST NOT generate drops on any platform.
        if delta_during['tx_drop'] != 0:
            st.banner("SUMMARY: TEST FAILED: test_pfcwd_forward_action")
            st.report_fail(
                'msg',
                f"PFCWD forward action on {platform} produced TX drops "
                f"(should be 0 on all platforms): "
                f"tx_drop={delta_during['tx_drop']}",
            )
        st.log(f"  tx_drop={delta_during['tx_drop']} == 0 -- OK "
               f"(forward action does not drop on any platform)")

        st.banner("Stopping XOFF, waiting for restoration")
        tg.tg_traffic_control(action='stop', stream_handle=xoff_stream_id)
        restore_wait = (timing['restore_time_sec']
                        + timing['poll_interval_sec'] + RESTORE_MARGIN_SECS)
        st.wait(restore_wait)

        stats_after = pfcwd_utils.get_pfcwd_stats_parsed(dut, egress_intf, tc)
        st.log(f"PFCWD stats after restore: {stats_after}")
        delta_after = pfcwd_utils.get_pfcwd_stats_delta(stats_before, stats_after)
        st.log(f"PFCWD delta after restore: {delta_after}")

        # Restoration check only meaningful when storm was detected.
        if expect_detected:
            restored_ok, restored_msg = pfcwd_utils.verify_pfcwd_restored(delta_after)
            st.log(f"Restoration check: {restored_msg}")
            if not restored_ok:
                st.banner("SUMMARY: TEST FAILED: test_pfcwd_forward_action")
                st.report_fail('msg', f"PFCWD not restored: {restored_msg}")
        else:
            st.log("Skipping restoration check (PFCWD inactive on this "
                   "platform with action=forward)")

        st.banner("Stopping all traffic")
        tg.tg_traffic_control(action='stop')
        st.wait(2)

        st.banner("SUMMARY: TEST PASSED: test_pfcwd_forward_action")
        st.log(f"Summary:")
        st.log(f"  Platform: {platform} (forward at data-plane: "
               f"{forward_supported})")
        st.log(f"  Action: forward")
        st.log(f"  storm_detected: {delta_after['storm_detected']} "
               f"(expected {'> 0' if expect_detected else '== 0'})")
        st.log(f"  storm_restored: {delta_after['storm_restored']}")
        st.log(f"  tx_drop during storm: {delta_during['tx_drop']} "
               f"(expected == 0)")
        st.report_pass("test_case_passed", "test_pfcwd_forward_action passed")

    except Exception as e:
        st.banner("SUMMARY: TEST FAILED: test_pfcwd_forward_action")
        st.error(f"Test failed with exception: {e}")
        import traceback
        st.log(traceback.format_exc())
        st.report_fail('msg', f"Test failed: {e}")

    finally:
        # Print birdseye counter summary (always, even on failure)
        try:
            print_test_summary_counters(
                dut, data.dut_ports, egress_intf, tc=tc
            )
        except Exception as _e_summary:
            st.log(f"summary counters not captured: {_e_summary}")
        try:
            tg.tg_traffic_control(action='stop')
        except Exception:
            pass
        if data_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=data_stream_id)
            except Exception as e:
                st.log(f"Failed to remove data stream: {e}")
        if xoff_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
            except Exception as e:
                st.log(f"Failed to remove XOFF stream: {e}")
        # Restore drop action so subsequent tests start from a known state.
        try:
            st.banner("Restoring action=drop after forward test")
            pfcwd_utils.configure_pfcwd_action(
                dut, action='drop',
                detection_time=detect_ms,
                restoration_time=restore_ms,
            )
        except Exception as e:
            st.log(f"Could not restore drop action: {e}")


# ---------------------------------------------------------------------------
# T7: PFCWD repeated burst storms -- each burst must independently trigger
# detection and then restoration.
# ---------------------------------------------------------------------------

def test_pfcwd_burst_storm():
    """
    Run N short XOFF bursts back-to-back. For each burst, the DUT must:
      * detect a PFCWD storm  (storm_detected delta >= 1)
      * restore after the burst ends  (storm_restored delta >= 1)

    Each burst uses single_burst so the XOFF stream self-terminates -- this
    avoids IxNetwork's multi-second stop latency on continuous PFC streams
    that previously turned short bursts into sustained storms.

    Bisection cal results (Tcal) feed the burst rate via get_xoff_rate
    (with the 15% safety margin already applied).
    """
    dut = data.dut
    tg = data.tg
    tc = data.tc
    dscp = data.dscp
    port_speed = data.port_speed
    timing = data.pfcwd_timing
    egress_intf = data.dut_ports[3]
    tgen_ports = data.tgen_ports
    handles = data.tgen_handles

    N_BURSTS = 3

    # Each storm needs to clearly exceed the detection threshold so the
    # counter increments deterministically; reuse the same formula as T1.
    storm_duration_sec = max(
        5.0,
        (5 * timing['detect_time_sec']) + (3 * timing['poll_interval_sec']) + 1.0,
    )
    inter_burst_wait = (
        timing['restore_time_sec'] + timing['poll_interval_sec']
        + RESTORE_MARGIN_SECS
    )

    xoff_rate = get_xoff_rate(port_speed)
    pkts_per_burst = max(1, int(round(xoff_rate * storm_duration_sec)))

    st.banner("PFCWD Burst Storm Test")
    st.log(f"  TC: {tc}, DSCP: {dscp}, Port Speed: {port_speed}G")
    st.log(f"  Bursts:               {N_BURSTS}")
    st.log(f"  Per-burst storm:      {storm_duration_sec:.2f} s")
    st.log(f"  Inter-burst wait:     {inter_burst_wait:.2f} s")
    st.log(f"  XOFF rate:            {xoff_rate} fps")
    st.log(f"  Pkts/burst:           {pkts_per_burst}")

    ip_tos = dscp << 2
    data_stream_id = None
    xoff_stream_id = None
    per_burst = []

    try:
        # One-time port reset on P3 before bringing up the data stream;
        # subsequent create_pfc_xoff_stream calls use reset_port=False so
        # the data stream's handle is preserved across bursts.
        st.log("Pre-cleaning XOFF port to remove any stale traffic items")
        tg.tg_traffic_control(
            action='reset',
            port_handle=handles[tgen_ports[3]]['port_handle'],
        )

        st.banner(
            f"Creating data stream at {DATA_RATE_PERCENT}% from "
            f"T1D3P1 -> T1D3P3"
        )
        tg_kwargs = dict(
            port_handle=handles[tgen_ports[1]]['port_handle'],
            port_handle2=handles[tgen_ports[3]]['port_handle'],
            mode='create',
            transmit_mode='continuous',
            rate_percent=DATA_RATE_PERCENT,
            frame_size=FRAME_SIZE,
            circuit_endpoint_type='ipv6',
            ipv6_traffic_class=ip_tos,
            emulation_src_handle=handles[tgen_ports[1]]['int_handle'],
            emulation_dst_handle=handles[tgen_ports[3]]['int_handle'],
        )
        data_result = tg.tg_traffic_config(**tg_kwargs)
        if data_result.get('status') != '1':
            st.report_fail(
                'msg', f"Failed to create data stream: {data_result}"
            )
        data_stream_id = data_result['stream_id']
        stream_api.set_pfc_priority_group(tg, data_result, tc)

        # Create the XOFF single_burst stream ONCE, before starting data.
        # Re-running a single_burst stream re-fires `pkts_per_burst`
        # frames, so we don't need to recreate it each iteration --
        # which is critical because create_pfc_xoff_stream internally
        # calls regenerate+apply (the L2 header fix), and any apply
        # between data-run and xoff-run stops the data stream and the
        # storm fires against an idle queue (PFCWD won't detect on
        # cisco-8000 platforms without backed-up data).
        st.banner(
            f"Creating XOFF single_burst stream "
            f"({pkts_per_burst} pkts/burst @ {xoff_rate} fps)"
        )
        xoff_stream_id = stream_api.create_pfc_xoff_stream(
            tg, tgen_ports[3], data.dut_p3_mac, xoff_rate, tc=tc,
            frame_count=pkts_per_burst, reset_port=False,
        )
        # Final apply now that BOTH streams exist; after this we won't
        # touch the IxNetwork config again until the loop is done.
        tg.tg_traffic_control(action='apply')
        st.wait(2)

        st.banner("Starting data traffic (runs for all bursts)")
        tg.tg_traffic_control(action='run', stream_handle=data_stream_id)
        st.wait(TRAFFIC_SETTLE_SECS)

        # Quick sanity check: data stream must be flowing on the egress
        # queue before we fire the first burst, otherwise PFCWD will not
        # detect anything (no backed-up data == no storm).
        sanity_q1 = get_queue_tx_packets(dut, egress_intf, tc)
        st.wait(2)
        sanity_q2 = get_queue_tx_packets(dut, egress_intf, tc)
        sanity_delta = sanity_q2 - sanity_q1
        st.log(f"Data flow sanity: queue UC{tc} delta over 2s = "
               f"{sanity_delta} pkts")
        if sanity_delta <= 0:
            st.report_fail(
                'msg',
                f"Data stream not flowing before burst loop: "
                f"queue UC{tc} on {egress_intf} did not increment "
                f"(q1={sanity_q1}, q2={sanity_q2}). PFCWD cannot trigger "
                f"without backed-up data.",
            )

        for i in range(1, N_BURSTS + 1):
            st.banner(f"Burst {i}/{N_BURSTS}")

            qos_utils.clear_all_counters(dut)
            st.wait(1)

            stats_before = pfcwd_utils.get_pfcwd_stats_parsed(
                dut, egress_intf, tc
            )
            st.log(f"  stats_before: {stats_before}")

            st.log(f"  Firing XOFF burst @ {xoff_rate} fps "
                   f"({pkts_per_burst} pkts, ~{storm_duration_sec:.1f}s)")
            tg.tg_traffic_control(
                action='run', stream_handle=xoff_stream_id
            )
            # Wait through the storm AND the restore window in one shot.
            st.wait(storm_duration_sec + inter_burst_wait)

            stats_after = pfcwd_utils.get_pfcwd_stats_parsed(
                dut, egress_intf, tc
            )
            st.log(f"  stats_after:  {stats_after}")

            delta = pfcwd_utils.get_pfcwd_stats_delta(
                stats_before, stats_after
            )
            st.log(f"  delta:        {delta}")
            per_burst.append(delta)

            detected_ok, det_msg = pfcwd_utils.verify_pfcwd_triggered(
                delta, expected=True
            )
            restored_ok, res_msg = pfcwd_utils.verify_pfcwd_restored(delta)
            st.log(f"  detect : {det_msg}")
            st.log(f"  restore: {res_msg}")

            if not detected_ok:
                st.report_fail(
                    'msg',
                    f"Burst {i}/{N_BURSTS}: storm NOT detected: {det_msg}",
                )
            if not restored_ok:
                st.report_fail(
                    'msg',
                    f"Burst {i}/{N_BURSTS}: storm NOT restored: {res_msg}",
                )

        st.banner("SUMMARY: TEST PASSED: test_pfcwd_burst_storm")
        st.log(f"  All {N_BURSTS} bursts detected AND restored:")
        for i, d in enumerate(per_burst, 1):
            st.log(
                f"   burst {i}: detected={d.get('storm_detected', 0)}, "
                f"restored={d.get('storm_restored', 0)}, "
                f"tx_drop={d.get('tx_drop', 0)}"
            )
        st.report_pass("test_case_passed", "test_pfcwd_burst_storm passed")

    except Exception as e:
        st.banner("SUMMARY: TEST FAILED: test_pfcwd_burst_storm")
        st.error(f"Test failed with exception: {e}")
        import traceback
        st.log(traceback.format_exc())
        st.report_fail('msg', f"Test failed: {e}")

    finally:
        # Print birdseye counter summary (always, even on failure)
        try:
            print_test_summary_counters(
                dut, data.dut_ports, egress_intf, tc=tc
            )
        except Exception as _e_summary:
            st.log(f"summary counters not captured: {_e_summary}")
        try:
            tg.tg_traffic_control(action='stop')
        except Exception:
            pass
        if data_stream_id:
            try:
                tg.tg_traffic_config(
                    mode='remove', stream_id=data_stream_id
                )
            except Exception as e:
                st.log(f"Failed to remove data stream: {e}")
        if xoff_stream_id:
            try:
                tg.tg_traffic_config(
                    mode='remove', stream_id=xoff_stream_id
                )
            except Exception as e:
                st.log(f"Failed to remove XOFF stream: {e}")


# ---------------------------------------------------------------------------
# T9: PFCWD many-to-one (incast) -- two ingress ports converge to one
# egress; PFC storm on the egress.
#
# Mirrors snappi: tests/snappi_tests/pfcwd/test_pfcwd_m2o_with_snappi.py.
# Implemented as two separate spytest functions (one per snappi
# parametrize value of trigger_pfcwd).
# ---------------------------------------------------------------------------

def _run_m2o(trigger_pfcwd):
    """
    Shared M2O driver.

      Ingress: P1 -> P3 and P2 -> P3.
        From each ingress port: 30% lossless (lossless TC/DSCP) +
                                15% lossy   (first lossy TC/DSCP).
        Combined offered load at P3 = 2 x (30% + 15%) = 90% line rate.
      XOFF:    storm on P3 (DUT egress) on the lossless TC.
      Storm duration:
        trigger_pfcwd=True  -> well above detect_time (storm MUST trigger)
        trigger_pfcwd=False -> well below detect_time (storm MUST NOT trigger)

    Pass criteria:
      trigger_pfcwd=True  -> storm_detected >= 1 AND tx_drop > 0
      trigger_pfcwd=False -> storm_detected == 0

      In both cases the test enforces the M2O property: combined data
      from both ingress ports converges on the egress.
    """
    dut = data.dut
    tg = data.tg
    tc = data.tc
    dscp = data.dscp
    lossy_tc = data.lossy_tc
    lossy_dscp = data.lossy_dscp
    port_speed = data.port_speed
    timing = data.pfcwd_timing
    egress_intf = data.dut_ports[3]
    tgen_ports = data.tgen_ports
    handles = data.tgen_handles

    LOSSLESS_RATE_PCT = 30
    LOSSY_RATE_PCT = 15

    test_name = (
        "test_pfcwd_many_to_one_trigger" if trigger_pfcwd
        else "test_pfcwd_many_to_one_no_trigger"
    )

    if trigger_pfcwd:
        # Long enough to deterministically trip PFCWD (same formula as T1).
        storm_duration_sec = max(
            5.0,
            (5 * timing['detect_time_sec'])
            + (3 * timing['poll_interval_sec']) + 1.0,
        )
    else:
        # Just under detect_time so the storm never crosses threshold.
        storm_duration_sec = max(0.05, timing['detect_time_sec'] * 0.95)

    xoff_rate = get_xoff_rate(port_speed)

    st.banner(f"PFCWD Many-to-One: trigger_pfcwd={trigger_pfcwd}")
    st.log(f"  Platform: {data.platform}")
    st.log(f"  Lossless TC={tc} DSCP={dscp} @ {LOSSLESS_RATE_PCT}% per ingress")
    st.log(f"  Lossy    TC={lossy_tc} DSCP={lossy_dscp} @ {LOSSY_RATE_PCT}% per ingress")
    st.log(f"  Port Speed: {port_speed}G")
    st.log(f"  Ingress: P1={tgen_ports[1]}, P2={tgen_ports[2]}; "
           f"Egress: P3={tgen_ports[3]} ({egress_intf})")
    st.log(f"  Detect time: {timing['detect_time_sec']*1000:.0f} ms")
    st.log(f"  Storm duration: {storm_duration_sec:.3f} s "
           f"({'>' if trigger_pfcwd else '<'} detect_time)")
    st.log(f"  XOFF rate: {xoff_rate} fps")

    ip_tos_lossless = dscp << 2
    ip_tos_lossy = lossy_dscp << 2
    data_stream_ids = []
    xoff_stream_id = None

    try:
        # Clean P3 once before creating peer streams that target it.
        st.log("Pre-cleaning XOFF port (P3) to remove any stale items")
        tg.tg_traffic_control(
            action='reset',
            port_handle=handles[tgen_ports[3]]['port_handle'],
        )

        # ---- Lossless + lossy streams from each ingress port to P3 ----
        flows = [
            # (label, tc_val, dscp_val, ip_tos_val, rate_pct, pfc_prio_set)
            ('lossless', tc, dscp, ip_tos_lossless, LOSSLESS_RATE_PCT, True),
            ('lossy', lossy_tc, lossy_dscp, ip_tos_lossy, LOSSY_RATE_PCT, False),
        ]
        for src_idx in (1, 2):
            for label, f_tc, f_dscp, f_tos, f_rate, set_prio in flows:
                st.banner(
                    f"Creating {label} stream at {f_rate}% from "
                    f"{tgen_ports[src_idx]} -> {tgen_ports[3]} "
                    f"(TC={f_tc}, DSCP={f_dscp})"
                )
                tg_kwargs = dict(
                    port_handle=handles[tgen_ports[src_idx]]['port_handle'],
                    port_handle2=handles[tgen_ports[3]]['port_handle'],
                    mode='create',
                    transmit_mode='continuous',
                    rate_percent=f_rate,
                    frame_size=FRAME_SIZE,
                    circuit_endpoint_type='ipv6',
                    ipv6_traffic_class=f_tos,
                    emulation_src_handle=handles[tgen_ports[src_idx]]['int_handle'],
                    emulation_dst_handle=handles[tgen_ports[3]]['int_handle'],
                )
                d_res = tg.tg_traffic_config(**tg_kwargs)
                if d_res.get('status') != '1':
                    st.report_fail(
                        'msg',
                        f"Failed to create {label} stream from "
                        f"{tgen_ports[src_idx]}: {d_res}",
                    )
                data_stream_ids.append(d_res['stream_id'])
                if set_prio:
                    stream_api.set_pfc_priority_group(tg, d_res, f_tc)
                st.log(f"  {label} stream id: {d_res['stream_id']}")

        # ---- XOFF stream on P3 ----
        if trigger_pfcwd:
            # Continuous storm; we stop it after storm_duration_sec.
            xoff_stream_id = stream_api.create_pfc_xoff_stream(
                tg, tgen_ports[3], data.dut_p3_mac, xoff_rate, tc=tc,
                reset_port=False,
            )
        else:
            # Single sub-threshold burst; self-terminates.
            pkts = max(1, int(round(xoff_rate * storm_duration_sec)))
            st.log(f"  XOFF single_burst pkts: {pkts} "
                   f"(~{(pkts/float(xoff_rate))*1000:.1f} ms on wire)")
            xoff_stream_id = stream_api.create_pfc_xoff_stream(
                tg, tgen_ports[3], data.dut_p3_mac, xoff_rate, tc=tc,
                frame_count=pkts, reset_port=False,
            )

        tg.tg_traffic_control(action='apply')
        st.wait(2)

        st.banner("Clearing all counters on DUT for clean baseline")
        qos_utils.clear_all_counters(dut)
        stats_before = pfcwd_utils.get_pfcwd_stats_parsed(
            dut, egress_intf, tc
        )
        st.log(f"PFCWD stats before: {stats_before}")

        st.banner("Starting both ingress data streams")
        for sid in data_stream_ids:
            tg.tg_traffic_control(action='run', stream_handle=sid)
        st.wait(TRAFFIC_SETTLE_SECS)

        # Verify data is ingressing on BOTH P1 and P2 (M2O has two senders);
        # there is no off-port to assert idle here.
        for ing in (data.dut_ports[1], data.dut_ports[2]):
            ok_ing, msg_ing, _ = verify_data_ingress(
                dut, expected_ingress=ing, off_ports=[],
            )
            st.log(f"Data ingress check ({ing}): {msg_ing}")
            if not ok_ing:
                st.banner("SUMMARY: TEST FAILED: M2O data ingress")
                st.report_fail('msg', f"M2O data ingress check failed: {msg_ing}")

        st.banner(f"Starting XOFF on P3 ({xoff_rate} fps)")
        tg.tg_traffic_control(action='run', stream_handle=xoff_stream_id)

        if trigger_pfcwd:
            st.log(f"Waiting {storm_duration_sec:.2f}s for PFCWD to detect...")
            st.wait(storm_duration_sec)
            st.banner("Stopping XOFF storm to allow restoration")
            try:
                tg.tg_traffic_control(
                    action='stop', stream_handle=xoff_stream_id
                )
            except Exception as e:
                st.log(f"XOFF stop warning (continuing): {e}")
            restore_wait = (
                timing['restore_time_sec']
                + timing['poll_interval_sec']
                + RESTORE_MARGIN_SECS
            )
            st.log(f"Waiting {restore_wait:.2f}s for PFCWD restoration...")
            st.wait(restore_wait)
        else:
            # Sub-threshold single_burst self-terminates; wait through
            # the burst and one detect+poll cycle to catch any (incorrect)
            # late detection.
            observe = (
                storm_duration_sec
                + timing['detect_time_sec']
                + timing['poll_interval_sec']
                + 0.5
            )
            st.log(f"Waiting {observe:.2f}s (burst + detect+poll observation)")
            st.wait(observe)

        stats_after = pfcwd_utils.get_pfcwd_stats_parsed(
            dut, egress_intf, tc
        )
        st.log(f"PFCWD stats after: {stats_after}")
        delta = pfcwd_utils.get_pfcwd_stats_delta(stats_before, stats_after)
        st.log(f"PFCWD delta: {delta}")

        st.banner("Stopping all traffic")
        tg.tg_traffic_control(action='stop')
        st.wait(2)

        # ---- Validate ----
        if trigger_pfcwd:
            det_ok, det_msg = pfcwd_utils.verify_pfcwd_triggered(
                delta, expected=True
            )
            res_ok, res_msg = pfcwd_utils.verify_pfcwd_restored(delta)
            st.log(f"detect : {det_msg}")
            st.log(f"restore: {res_msg}")
            if not det_ok:
                st.banner(f"SUMMARY: TEST FAILED: {test_name}")
                st.report_fail(
                    'msg',
                    f"M2O long storm did NOT trigger PFCWD: {det_msg}",
                )
            if not res_ok:
                st.banner(f"SUMMARY: TEST FAILED: {test_name}")
                st.report_fail(
                    'msg',
                    f"M2O long storm did NOT restore: {res_msg}",
                )
        else:
            if delta.get('storm_detected', 0) != 0:
                st.banner(f"SUMMARY: TEST FAILED: {test_name}")
                st.report_fail(
                    'msg',
                    f"M2O sub-threshold storm UNEXPECTEDLY triggered "
                    f"PFCWD: storm_detected={delta['storm_detected']}",
                )
            # Lossless TC must have ZERO drops on egress queue when
            # PFCWD did not trigger.
            if delta.get('tx_drop', 0) != 0:
                st.banner(f"SUMMARY: TEST FAILED: {test_name}")
                st.report_fail(
                    'msg',
                    f"Lossless TC{tc} had unexpected drops on {egress_intf} "
                    f"in M2O sub-threshold scenario: "
                    f"tx_drop={delta['tx_drop']} (expected 0)",
                )

        st.banner(f"SUMMARY: TEST PASSED: {test_name}")
        st.log(f"  Platform: {data.platform}")
        st.log(f"  trigger_pfcwd: {trigger_pfcwd}")
        st.log(f"  storm_duration_sec: {storm_duration_sec:.3f}")
        st.log(f"  storm_detected delta: {delta.get('storm_detected', 0)}")
        st.log(f"  storm_restored delta: {delta.get('storm_restored', 0)}")
        st.log(f"  tx_drop delta:        {delta.get('tx_drop', 0)}")
        st.report_pass("test_case_passed", f"{test_name} passed")

    except Exception as e:
        st.banner(f"SUMMARY: TEST FAILED: {test_name}")
        st.error(f"Test failed with exception: {e}")
        import traceback
        st.log(traceback.format_exc())
        st.report_fail('msg', f"Test failed: {e}")

    finally:
        # Print birdseye counter summary (always, even on failure)
        try:
            print_test_summary_counters(
                dut, data.dut_ports, egress_intf, tc=tc
            )
        except Exception as _e_summary:
            st.log(f"summary counters not captured: {_e_summary}")
        try:
            tg.tg_traffic_control(action='stop')
        except Exception:
            pass
        for sid in data_stream_ids:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=sid)
            except Exception as e:
                st.log(f"remove data stream {sid} warn: {e}")
        if xoff_stream_id:
            try:
                tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
            except Exception as e:
                st.log(f"remove XOFF stream warn: {e}")


def test_pfcwd_many_to_one_trigger():
    """M2O incast with long XOFF storm -- PFCWD MUST detect & restore."""
    _run_m2o(trigger_pfcwd=True)


def test_pfcwd_many_to_one_no_trigger():
    """M2O incast with sub-threshold XOFF burst -- PFCWD MUST NOT trigger."""
    _run_m2o(trigger_pfcwd=False)
