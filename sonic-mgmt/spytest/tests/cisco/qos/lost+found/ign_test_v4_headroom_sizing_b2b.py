"""
PFC Headroom Sizing Test (Back-to-Back Topology)

Empirically measures PFC headroom requirements per port speed by:
1. Setting headroom (xoff) to 0 on DUT2's ingress port (port-c)
   For Gamut: also sets size=xon to properly configure buffers
2. Sending continuous lossless data traffic through DUT1->DUT2
3. Sending PFC XOFF from TGEN2 at calculated rate for 1 second
4. Counting PFC TX on DUT2 port-c and PG drops on DUT2 port-c
5. Headroom = (pg_drops_packets / pfc_tx_count) * frame_size

Topology:
    TGEN1 --data (99%)--> DUT1[port-a]--[port-b]-->[port-c]--DUT2[port-d]--> TGEN2
                                           |            |
                                    PFC RX from     headroom=0
                                      DUT2         PFC TX to DUT1
                                                   measure pg_drop
"""

import time
import pytest
from spytest import st, tgapi, SpyTestDict

import qos_test_utils as qos_utils
import traffic_stream_ixia_api as stream_api
import qos_test_utils as common_util
import gamut_qos_utils as gamut_utils


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
XOFF_DURATION_SEC = 1        # Duration to send XOFF
XOFF_RATE_FPS = 100          # Fixed XOFF rate in frames per second
DATA_RATE_PERCENT = 99
DEFAULT_FRAME_SIZE = 1350
DEFAULT_ITERATIONS = 1       # Single iteration for now, increase later for accuracy
TC = 3

# IP map for b2b setup (reuse from stream_api)
B2B_IP_MAP = {
    'D3T1P1': '27.1.1.1',
    'D4T1P1': '35.1.1.1',
}

# B2B link IPs
B2B_LINK_IPS = {
    'D3D4P1': '192.168.100.1',
    'D4D3P1': '192.168.100.2',
}

# Speed to breakout mode mapping for n9164e (Gamut)
# Format: speed_gbps -> (breakout_mode, resulting_speed_per_port)
SPEED_BREAKOUT_MAP = {
    800: ('1x800G', 800),
    400: ('1x400G', 400),
    200: ('2x200G', 200),
    100: ('4x100G', 100),
    50: ('2x50G', 50),
    # Add more as needed for other platforms
}

# Default speeds to test in speed sweep (descending order)
DEFAULT_SPEED_SWEEP = [800, 400, 200, 100]

# Module-level state
vars = SpyTestDict()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """
    Set up b2b topology with 2 DUTs and TGEN ports.

    Topology: D3D4:1, D3T1:1, D4T1:1
    - DUT1 (D3): Ingress DUT where headroom is set to 0
    - DUT2 (D4): Egress DUT where XOFF is sent back
    """
    global vars

    # Require 2 DUTs connected b2b with TGEN ports on each
    tb_dict = st.ensure_min_topology("D3D4:1", "D3T1:1", "D4T1:1")
    vars = st.get_testbed_vars()

    # Store topology info
    vars.dut1 = vars.D3  # Ingress DUT
    vars.dut2 = vars.D4  # Egress DUT
    vars.b2b_link = {
        'dut1_port': vars.D3D4P1,  # DUT1 egress to DUT2
        'dut2_port': vars.D4D3P1,  # DUT2 ingress from DUT1
    }
    vars.tgen_ports = {
        'tgen1': 'T1D3P1',  # TGEN port connected to DUT1
        'tgen2': 'T1D4P1',  # TGEN port connected to DUT2
    }
    vars.dut_tgen_ports = {
        'dut1_tgen': vars.D3T1P1,  # DUT1 port to TGEN1
        'dut2_tgen': vars.D4T1P1,  # DUT2 port to TGEN2
    }

    # Detect platforms
    vars.platform1 = qos_utils.detect_platform(vars.dut1)
    vars.platform2 = qos_utils.detect_platform(vars.dut2)
    st.log(f"DUT1 platform: {vars.platform1}, DUT2 platform: {vars.platform2}")

    # Get current port speed for b2b link
    vars.b2b_speed = common_util.get_if_speed(vars.dut1, vars.b2b_link['dut1_port'])
    st.log(f"B2B link speed: {vars.b2b_speed}G")

    # Get TGEN port speed
    vars.tgen_speed = common_util.get_if_speed(vars.dut1, vars.dut_tgen_ports['dut1_tgen'])
    st.log(f"TGEN port speed: {vars.tgen_speed}G")

    # Cleanup existing IP configs
    common_util.cleanup_config(vars.dut1)
    common_util.cleanup_config(vars.dut2)

    # Initialize QoS on both DUTs
    stream_api.init_qos_on_dut(vars.dut1, tc_list=[TC])
    stream_api.init_qos_on_dut(vars.dut2, tc_list=[TC])

    # Configure IP addresses on b2b links
    _configure_b2b_ips()

    # Configure IP addresses on TGEN ports
    _configure_tgen_port_ips()

    # Store TGEN handles
    vars.tg, _ = tgapi.get_handle_byname('T1D3P1')
    _, vars.tgen1_handle = tgapi.get_handle_byname('T1D3P1')
    _, vars.tgen2_handle = tgapi.get_handle_byname('T1D4P1')

    # Get DUT2's MAC for PFC XOFF stream
    vars.dut2_tgen_mac = _get_port_mac(vars.dut2, vars.dut_tgen_ports['dut2_tgen'])

    yield

    # Cleanup
    st.log("Cleaning up b2b topology...")
    _cleanup_ips()


def _configure_b2b_ips():
    """
    Configure IP addresses on b2b links between DUTs and verify L3 reachability.

    Returns:
        True if a 3-packet ping from DUT1 -> DUT2 b2b IP gets at least one
        reply, False otherwise. Callers MUST check the return value and
        skip the measurement on False - running headroom traffic over a
        non-forwarding link produces zero drops / zero pfc_tx and would
        masquerade as a PASS (see laguna_hr_speeds_1F_8.log).
    """
    st.log("Configuring IP addresses on b2b links...")

    # DUT1 side (D3D4P1)
    st.config(vars.dut1,
              f"config interface ip add {vars.b2b_link['dut1_port']} "
              f"{B2B_LINK_IPS['D3D4P1']}/24",
              skip_tmpl=True)

    # DUT2 side (D4D3P1)
    st.config(vars.dut2,
              f"config interface ip add {vars.b2b_link['dut2_port']} "
              f"{B2B_LINK_IPS['D4D3P1']}/24",
              skip_tmpl=True)

    # Verify with ping. We treat any non-100% loss as success since a
    # single reply is enough to confirm the link is forwarding.
    st.wait(2)
    ping_out = st.config(vars.dut1,
                         f"ping -c 3 -W 2 {B2B_LINK_IPS['D4D3P1']}",
                         skip_tmpl=True, skip_error_check=True) or ''
    if '100% packet loss' in ping_out or 'Destination Host Unreachable' in ping_out:
        st.error(f"  b2b ping {B2B_LINK_IPS['D3D4P1']} -> "
                 f"{B2B_LINK_IPS['D4D3P1']} FAILED (no replies)")
        return False
    if ' 0 received' in ping_out:
        st.error(f"  b2b ping {B2B_LINK_IPS['D3D4P1']} -> "
                 f"{B2B_LINK_IPS['D4D3P1']} FAILED (0 received)")
        return False
    return True


def _configure_tgen_port_ips():
    """Configure IP addresses on TGEN-facing ports."""
    st.log("Configuring IP addresses on TGEN ports...")

    # DUT1 TGEN port
    st.config(vars.dut1,
              f"config interface ip add {vars.dut_tgen_ports['dut1_tgen']} "
              f"{B2B_IP_MAP['D3T1P1']}/24",
              skip_tmpl=True)

    # DUT2 TGEN port
    st.config(vars.dut2,
              f"config interface ip add {vars.dut_tgen_ports['dut2_tgen']} "
              f"{B2B_IP_MAP['D4T1P1']}/24",
              skip_tmpl=True)


def _cleanup_ips():
    """Remove configured IPs."""
    try:
        st.config(vars.dut1,
                  f"config interface ip remove {vars.b2b_link['dut1_port']} "
                  f"{B2B_LINK_IPS['D3D4P1']}/24",
                  skip_tmpl=True, skip_error_check=True)
        st.config(vars.dut1,
                  f"config interface ip remove {vars.dut_tgen_ports['dut1_tgen']} "
                  f"{B2B_IP_MAP['D3T1P1']}/24",
                  skip_tmpl=True, skip_error_check=True)
        st.config(vars.dut2,
                  f"config interface ip remove {vars.b2b_link['dut2_port']} "
                  f"{B2B_LINK_IPS['D4D3P1']}/24",
                  skip_tmpl=True, skip_error_check=True)
        st.config(vars.dut2,
                  f"config interface ip remove {vars.dut_tgen_ports['dut2_tgen']} "
                  f"{B2B_IP_MAP['D4T1P1']}/24",
                  skip_tmpl=True, skip_error_check=True)
    except Exception as e:
        st.log(f"Cleanup IP removal warning: {e}")


def _cleanup_b2b_ips():
    """Remove configured IPs on b2b ports only (not TGEN ports)."""
    try:
        st.config(vars.dut1,
                  f"config interface ip remove {vars.b2b_link['dut1_port']} "
                  f"{B2B_LINK_IPS['D3D4P1']}/24",
                  skip_tmpl=True, skip_error_check=True)
        st.config(vars.dut2,
                  f"config interface ip remove {vars.b2b_link['dut2_port']} "
                  f"{B2B_LINK_IPS['D4D3P1']}/24",
                  skip_tmpl=True, skip_error_check=True)
    except Exception as e:
        st.log(f"Cleanup b2b IP removal warning: {e}")


def _get_port_mac(dut, port):
    """Get the MAC address of a port."""
    # Use sysfs to get MAC address (most reliable method)
    result = st.show(dut, f"cat /sys/class/net/{port}/address",
                     skip_tmpl=True, skip_error_check=True)
    if result:
        mac = result.strip().splitlines()[0].strip()
        if len(mac) == 17 and mac.count(':') == 5:
            return mac

    # Fallback: use ip link show
    result = st.show(dut, f"ip link show {port}", skip_tmpl=True, skip_error_check=True)
    for line in result.splitlines():
        if 'ether' in line.lower() or 'link/ether' in line.lower():
            parts = line.split()
            for part in parts:
                if ':' in part and len(part) == 17 and part.count(':') == 5:
                    return part

    # Last resort fallback
    st.log(f"WARNING: Could not get MAC for {port}, using default")
    return '00:00:00:00:00:01'


def _get_base_port(port_name):
    """
    Get the base port name from a breakout port.

    Port naming convention on Gamut (n9164e):
    - Base port: Ethernet{slot}_{port} (e.g., 'Ethernet1_45')
    - Breakout port: Ethernet{slot}_{port}_{index} (e.g., 'Ethernet1_45_1')

    The breakout index is always 1-8 and is the LAST _N segment.
    """
    import re
    # Match breakout port pattern: base_port followed by _[1-8] at the end
    # E.g., 'Ethernet1_45_1' -> base is 'Ethernet1_45', index is '1'
    # But 'Ethernet1_45' should NOT match (the _45 is part of port name)
    # Key: breakout ports have format like XXX_NN_N where NN is port num, N is index
    match = re.match(r'^(.+_\d+)_([1-8])$', port_name)
    if match:
        return match.group(1)
    return port_name


def _perform_qos_cli(dut, port_list, op):
    """
    Perform 'config qos clear' or 'config qos reload' on the given port list.

    Mirrors perform_qos_cli() in test_v4_pfc_brkout_b2b.py. Must be invoked
    BEFORE breakout (op='clear', on pre-breakout port list) and AFTER breakout
    (op='reload', on post-breakout port list) so the buffer/QoS bindings line
    up with the new subport names in CONFIG_DB (BUFFER_PG, BUFFER_PROFILE etc.).
    """
    if not port_list:
        return
    if op == 'reload':
        cmd = f"config qos reload --ports {','.join(port_list)} --no-dynamic-buffer"
    else:
        cmd = f"config qos clear --ports {','.join(port_list)}"
    st.config(dut, cmd, skip_tmpl=True, skip_error_check=True)


def _collect_if_list(dut, base_port):
    """
    Return the parent port and/or all its breakout children currently visible
    in 'show interface status'.

    Mirrors collect_if_list() in test_v4_pfc_brkout_b2b.py. For a base port
    'Ethernet1_49' this returns:
      - ['Ethernet1_49']                          when port is unbroken
      - ['Ethernet1_49_1']                        for 1x modes that name the child _1
      - ['Ethernet1_49_1','Ethernet1_49_3', ...]  for Nx modes
    """
    if_list = []
    result = st.show(dut, f"show int status | grep {base_port}",
                     skip_tmpl=True, skip_error_check=True)
    for line in (result or '').splitlines():
        if 'Ethernet' not in line:
            continue
        port = line.split()[0]
        if port == base_port or port.startswith(f"{base_port}_"):
            if_list.append(port)
    # Keep deterministic order (subport indices ascending)
    if_list.sort()
    return if_list


def _wait_for_ports_up(dut, port_list, timeout=180):
    """
    Poll 'show interface status' until every port in port_list is BOTH
    admin=up AND oper=up, or until timeout.

    'show interfaces status' columns (current sonic output):
        Interface Lanes Speed MTU FEC Alias Vlan Oper Admin Type ...
                                                  ^7   ^8
    """
    if not port_list:
        return False
    grep_pattern = '|'.join(port_list)
    waited = 0
    while waited < timeout:
        result = st.show(dut, f"show int status | egrep '{grep_pattern}'",
                         skip_tmpl=True, skip_error_check=True)
        not_ready = 0
        seen = 0
        for line in (result or '').splitlines():
            if 'Ethernet' not in line:
                continue
            tokens = line.split()
            if tokens[0] not in port_list:
                continue
            seen += 1
            # Require BOTH oper (col 7) and admin (col 8) == 'up'.
            oper = tokens[7] if len(tokens) > 7 else ''
            admin = tokens[8] if len(tokens) > 8 else ''
            if oper != 'up' or admin != 'up':
                not_ready += 1
        if seen == len(port_list) and not_ready == 0:
            return True
        st.wait(5)
        waited += 5
    return False


def configure_breakout_for_speed(dut, port, target_speed):
    """
    Apply breakout mode to achieve target speed, following the
    test_v4_pfc_brkout_b2b.py recipe:

      1. Discover existing subports of the parent (pre-breakout if_list).
      2. 'config qos clear' on those subports.
      3. 'config interface breakout <parent> <mode> -yfl'.
      4. Discover new subports (post-breakout if_list).
      5. 'config qos reload --no-dynamic-buffer' on the new subports so
         BUFFER_PG/BUFFER_PROFILE entries are recreated for the new names.
      6. 'config interface startup' on every new subport.

    Does NOT wait for ports oper-up and does NOT reload the ConfigDb cache.
    The caller must invoke finalize_breakout_pair_and_load_cache() after
    BOTH peers of a b2b link have been broken out, because:
      - link-partner state is required for oper-up;
      - the buffer manager populates BUFFER_PG|<port>|<tc> only after the
        port reaches oper-up; querying the cache earlier captures an empty
        snapshot and HeadroomZeroContext fails with 'No BUFFER_PG profile'.

    Args:
        dut: DUT handle.
        port: Any port name belonging to the parent (base or one of its subports).
        target_speed: Target per-lane speed in Gbps (e.g., 100, 200, 400, 800).

    Returns:
        (success, first_subport_name, actual_speed, post_list_of_all_subports)
    """
    if target_speed not in SPEED_BREAKOUT_MAP:
        st.error(f"Unsupported speed: {target_speed}G")
        return False, None, None, []

    breakout_mode, actual_speed = SPEED_BREAKOUT_MAP[target_speed]
    base_port = _get_base_port(port)

    st.banner(f"Breakout: {base_port} -> {breakout_mode} ({actual_speed}G)")

    # 1+2: snapshot current subports and clear their QoS state
    pre_list = _collect_if_list(dut, base_port)
    st.log(f"  pre-breakout subports for {base_port}: {pre_list}")
    _perform_qos_cli(dut, pre_list, 'clear')

    # 3: change breakout
    cmd = f"config interface breakout {base_port} \"{breakout_mode}\" -yfl"
    result = st.config(dut, cmd, skip_tmpl=True, skip_error_check=True)
    if result and 'ERROR' in result:
        st.error(f"  breakout cli failed: {result.splitlines()[0]}")
        return False, None, None, []
    st.wait(5)

    # 4: snapshot new subports
    post_list = _collect_if_list(dut, base_port)
    st.log(f"  post-breakout subports for {base_port}: {post_list}")
    if not post_list:
        st.error(f"  no subports found for {base_port} after breakout")
        return False, None, None, []

    # 5: admin-up every new subport BEFORE qos reload. The buffer manager
    #    keys BUFFER_PG|<port>|<tc> population off port admin state, so
    #    running qos reload while ports are admin-down can leave the new
    #    subports without buffer bindings until they are toggled up later.
    #    Admin-up first ensures the subsequent qos reload sees the ports
    #    in the right state.
    for p in post_list:
        st.config(dut, f"config interface startup {p}",
                  skip_tmpl=True, skip_error_check=True)

    # 6: reload QoS so BUFFER_PG / BUFFER_PROFILE entries are created
    #    against the NEW (admin-up) subport names.
    _perform_qos_cli(dut, post_list, 'reload')
    st.wait(2)

    first_port = post_list[0]
    st.log(f"  first subport (deferred up-wait): {first_port} @ {actual_speed}G")
    return True, first_port, actual_speed, post_list


def finalize_breakout_pair_and_load_cache(dut1, ports1, dut2, ports2,
                                          timeout=180):
    """
    Wait for BOTH ends of a b2b link to reach admin+oper up, then refresh
    the qos_utils ConfigDb cache on both DUTs.

    Must be invoked after configure_breakout_for_speed() has been called on
    both sides of the b2b link. Reloading the cache only after the ports
    are fully up ensures BUFFER_PG|<port>|<tc> populated by the buffer
    manager is visible to subsequent get_buffer_pg_profile() / mmuconfig
    lookups.

    Returns:
        True if both sides came up within timeout, False otherwise.
    """
    st.banner(f"Waiting for b2b link to come up on both peers")
    up1 = _wait_for_ports_up(dut1, ports1, timeout=timeout)
    up2 = _wait_for_ports_up(dut2, ports2, timeout=timeout)
    if not up1:
        st.warn(f"  {dut1} subports {ports1} did not reach admin+oper up")
    if not up2:
        st.warn(f"  {dut2} subports {ports2} did not reach admin+oper up")

    # Cache reload MUST happen after ports are up. See docstring.
    qos_utils.load_config_db(dut1)
    qos_utils.load_config_db(dut2)
    return up1 and up2


def restore_original_breakout(dut, port, original_mode):
    """
    Restore original breakout configuration using the same clear/reload/
    startup recipe as configure_breakout_for_speed().

    Returns:
        list[str]: the post-restore subport list (so the caller can pair
        this DUT's restore with the peer's restore and then run
        finalize_breakout_pair_and_load_cache).
    """
    base_port = _get_base_port(port)
    st.banner(f"Restore breakout: {base_port} -> {original_mode}")

    pre_list = _collect_if_list(dut, base_port)
    _perform_qos_cli(dut, pre_list, 'clear')

    cmd = f"config interface breakout {base_port} \"{original_mode}\" -yfl"
    st.config(dut, cmd, skip_tmpl=True, skip_error_check=True)
    st.wait(5)

    post_list = _collect_if_list(dut, base_port)
    if post_list:
        # admin-up subports BEFORE qos reload (same rationale as
        # configure_breakout_for_speed step 5).
        for p in post_list:
            st.config(dut, f"config interface startup {p}",
                      skip_tmpl=True, skip_error_check=True)
        _perform_qos_cli(dut, post_list, 'reload')
        st.wait(2)
    return post_list


def get_current_breakout_mode(dut, port):
    """
    Get current breakout mode for a port.

    Args:
        dut: DUT handle
        port: Port name

    Returns:
        str: Current breakout mode (e.g., '1x800G', '4x100G')
    """
    base_port = _get_base_port(port)
    cmd = f"show interfaces breakout current-mode {base_port}"
    result = st.show(dut, cmd, skip_tmpl=True)

    # Parse the output to find the mode
    for line in result.splitlines():
        if base_port in line:
            # Look for mode pattern like 1x800G, 4x100G, etc.
            import re
            match = re.search(r'(\d+x\d+G)', line)
            if match:
                return match.group(1)

    # Default fallback based on current speed
    current_speed = common_util.get_if_speed(dut, port)
    return f"1x{current_speed}G"


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------
# XOFF Rate Calculation - using fixed rate (XOFF_RATE_FPS constant)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
def clear_all_counters_platform_aware(dut):
    """
    Clear all counters with platform-specific handling.

    For Gamut (n9164e): Also clear port counters via syncd API.
    """
    platform = qos_utils.detect_platform(dut)
    if platform == 'n9164e':
        st.log("Gamut platform detected, clearing port counters via syncd...")
        gamut_utils.gamut_clear_port_counters(dut)

    # Always clear standard counters
    qos_utils.clear_all_counters(dut)


def create_data_stream(tg, handles, frame_size, rate_pct):
    """
    Create continuous IPv4 data stream from TGEN1 to TGEN2.

    Args:
        tg: TGEN handle
        handles: Dict of TGEN port handles
        frame_size: Frame size in bytes
        rate_pct: Traffic rate as percentage of line rate

    Returns:
        dict: Traffic stream result including stream_id
    """
    st.banner(f"Creating data stream: frame_size={frame_size}B, rate={rate_pct}%")

    # Get DSCP for TC3
    dscp = common_util.convert_tc_to_dscp(vars.dut1, TC)
    ip_tos = int(dscp) << 2 if dscp else (TC << 2)

    # Create interface handles for TGEN1 and TGEN2
    # TGEN IP: change last octet from .1 to .2 (e.g., 27.1.1.1 -> 27.1.1.2)
    tgen1_ip = B2B_IP_MAP['D3T1P1'].rsplit('.', 1)[0] + '.2'
    tgen1_if_cfg = {
        'mode': 'config',
        'port_handle': vars.tgen1_handle,
        'intf_ip_addr': tgen1_ip,
        'gateway': B2B_IP_MAP['D3T1P1'],
        'netmask': '255.255.255.0',
        'arp_send_req': 1,
        'enable_ping_response': 1,
        'resolve_gateway_mac': 1,
    }
    tgen1_result = tg.tg_interface_config(**tgen1_if_cfg)
    if tgen1_result.get('status') != '1':
        st.error(f"Failed to configure TGEN1 interface: {tgen1_result}")
        return None
    src_handle = tgen1_result['handle']

    tgen2_ip = B2B_IP_MAP['D4T1P1'].rsplit('.', 1)[0] + '.2'
    tgen2_if_cfg = {
        'mode': 'config',
        'port_handle': vars.tgen2_handle,
        'intf_ip_addr': tgen2_ip,
        'gateway': B2B_IP_MAP['D4T1P1'],
        'netmask': '255.255.255.0',
        'arp_send_req': 1,
        'enable_ping_response': 1,
        'resolve_gateway_mac': 1,
    }
    tgen2_result = tg.tg_interface_config(**tgen2_if_cfg)
    if tgen2_result.get('status') != '1':
        st.error(f"Failed to configure TGEN2 interface: {tgen2_result}")
        return None
    dst_handle = tgen2_result['handle']

    # Add route on DUT1 to reach TGEN2 via DUT2
    dst_net = B2B_IP_MAP['D4T1P1'][:-1] + '0'
    st.config(vars.dut1,
              f"config route add prefix {dst_net}/24 nexthop {B2B_LINK_IPS['D4D3P1']}",
              skip_tmpl=True)

    # Add route on DUT2 to reach TGEN1 via DUT1
    src_net = B2B_IP_MAP['D3T1P1'][:-1] + '0'
    st.config(vars.dut2,
              f"config route add prefix {src_net}/24 nexthop {B2B_LINK_IPS['D3D4P1']}",
              skip_tmpl=True)

    st.wait(2)

    # Create traffic stream
    traffic_cfg = {
        'mode': 'create',
        'transmit_mode': 'continuous',
        'frame_size': frame_size,
        'l3_protocol': 'ipv4',
        'track_by': 'traffic_item',
        'enable_pgid': 1,
        'rate_percent': rate_pct,
        'ip_dscp': dscp if dscp else TC,
        'emulation_src_handle': src_handle,
        'emulation_dst_handle': dst_handle,
        'ip_src_addr': tgen1_if_cfg['intf_ip_addr'],
        'ip_dst_addr': tgen2_if_cfg['intf_ip_addr'],
    }

    result = tg.tg_traffic_config(**traffic_cfg)
    if result.get('status') != '1':
        st.error(f"Failed to create data stream: {result}")
        return None

    # Set PFC priority group
    stream_api.set_pfc_priority_group(tg, result, TC)

    st.log(f"Created data stream: {result.get('stream_id')}")
    return result


def create_xoff_burst_stream(tgen_port, dst_mac, frame_count, rate_fps):
    """
    Create PFC XOFF burst stream for single_burst mode.

    Args:
        tgen_port: TGEN port name (e.g., 'T1D4P1')
        dst_mac: Destination MAC (DUT port MAC)
        frame_count: Number of XOFF frames to send
        rate_fps: XOFF frame rate in frames per second

    Returns:
        str: Stream ID
    """
    st.banner(f"Creating XOFF burst stream: {frame_count} frames @ {rate_fps} fps")

    # Use reset_port=False to preserve any existing data stream destination
    xoff_stream_id = stream_api.create_pfc_xoff_stream(
        None,  # tg_unused
        tgen_port,
        dst_mac,
        rate_fps,
        tc=TC,
        frame_count=frame_count,
        reset_port=False,
    )

    return xoff_stream_id


def run_headroom_measurement(speed=None, frame_size=DEFAULT_FRAME_SIZE,
                             iterations=DEFAULT_ITERATIONS):
    """
    Core headroom measurement logic.

    Methodology:
    - Set xoff=0 on DUT2 port-c (b2b ingress from DUT1)
      For Gamut: also set size=xon to properly configure buffers
    - Send data traffic TGEN1 -> DUT1 -> DUT2 -> TGEN2
    - Send XOFF from TGEN2 at rate calculated from port-d speed
    - Count: PFC TX on DUT2 port-c, PG drops on DUT2 port-c
    - Headroom = (pg_drops_packets / pfc_tx_count) * frame_size

    Args:
        speed: Target speed in Gbps (None = use current speed)
        frame_size: Frame size in bytes
        iterations: Number of measurement iterations

    Returns:
        dict: Result dictionary with all measurement data
    """
    # Get port names for all 4 ports in the topology
    port_a = vars.dut_tgen_ports['dut1_tgen']  # DUT1 TGEN port - receives data from TGEN1
    port_b = vars.b2b_link['dut1_port']        # DUT1 b2b egress to DUT2 - captures PFC RX
    port_c = vars.b2b_link['dut2_port']        # DUT2 b2b ingress from DUT1 - set xoff=0, captures drops & PFC TX
    port_d = vars.dut_tgen_ports['dut2_tgen']  # DUT2 TGEN port - receives XOFF from TGEN2

    # Calculate XOFF parameters - use fixed 400 fps rate
    # Port-d is where TGEN2 sends XOFF to DUT2
    port_d_speed = common_util.get_if_speed(vars.dut2, port_d)
    platform = vars.platform2       # Platform of DUT2 (where XOFF is received)
    st.log(f"Port-d ({port_d}) speed: {port_d_speed}G (platform: {platform})")
    xoff_rate_fps = XOFF_RATE_FPS
    xoff_frame_count = xoff_rate_fps * XOFF_DURATION_SEC
    st.log(f"XOFF params: rate={xoff_rate_fps} fps, frames={xoff_frame_count}, duration={XOFF_DURATION_SEC}s")

    result = {
        'platform': vars.platform1,
        'speed_gbps': speed or vars.b2b_speed,
        'frame_size': frame_size,
        'iterations': iterations,
        'port_d_speed': port_d_speed,
        'xoff_rate_fps': xoff_rate_fps,
        'xoff_duration_sec': XOFF_DURATION_SEC,
        'xoff_frame_count': xoff_frame_count,
        # Port names for display
        'dut1': str(vars.dut1),
        'dut2': str(vars.dut2),
        'port_a': port_a,
        'port_b': port_b,
        'port_c': port_c,
        'port_d': port_d,
        # Per-iteration data
        'drops_per_iteration': [],
        'pfc_rx_per_iteration': [],
        'pfc_tx_per_iteration': [],
        'queue_wm_port_d_per_iteration': [],  # Queue watermark at port-d (DUT2 TGEN)
        'queue_wm_port_b_per_iteration': [],  # Queue watermark at port-b (DUT1 b2b egress)
        'queue_drops_port_d_per_iteration': [],  # Queue drops at port-d (DUT2 TGEN)
        'queue_drops_port_b_per_iteration': [],  # Queue drops at port-b (DUT1 b2b egress)
        'pg_wm_port_a_per_iteration': [],  # PG watermark at port-a (DUT1 TGEN ingress)
        'pg_wm_port_c_per_iteration': [],  # PG watermark at port-c (DUT2 b2b ingress) - xoff=0 port
        'pfc_rx_port_d_per_iteration': [],  # PFC RX at port-d (DUT2 TGEN port - receives XOFF from TGEN2)
        'pfc_tx_port_a_per_iteration': [],  # PFC TX at port-a (DUT1 TGEN ingress - propagated back to TGEN1)
        'pg_drops_total': 0,
        'pfc_rx_total': 0,
        'pfc_tx_total': 0,
        'headroom_bytes_measured': 0,
        'counters': {},
        'passed': False,
        'error': None,
    }

    dut1 = vars.dut1
    dut2 = vars.dut2
    tg = vars.tg

    data_stream = None
    xoff_stream_id = None

    try:
        st.banner(f"Starting headroom measurement: speed={result['speed_gbps']}G, "
                  f"frame={frame_size}B, iters={iterations}")

        # Print topology diagram for easy log analysis
        st.log("")
        st.log("=" * 80)
        st.log("TOPOLOGY DIAGRAM:")
        st.log("")
        st.log(f"  TGEN1 --data({DATA_RATE_PERCENT}%)--> [{port_a}]{dut1}[{port_b}] --b2b--> [{port_c}]{dut2}[{port_d}] <--XOFF-- TGEN2")
        st.log(f"                          (port-a)   (port-b)      (port-c)   (port-d)")
        st.log("")
        st.log(f"  DUT1 = {dut1} (platform: {vars.platform1})")
        st.log(f"  DUT2 = {dut2} (platform: {vars.platform2})")
        st.log(f"  port-a ({port_a}): DUT1 ingress from TGEN1")
        st.log(f"  port-b ({port_b}): DUT1 egress to DUT2 (PFC RX from DUT2)")
        st.log(f"  port-c ({port_c}): DUT2 ingress from DUT1 (xoff=0, PFC TX, pg_drop)")
        st.log(f"  port-d ({port_d}): DUT2 egress to TGEN2 (receives XOFF)")
        st.log("=" * 80)
        st.log("")

        st.log(f"Port-d speed: {port_d_speed}G, XOFF rate: {xoff_rate_fps} fps, "
               f"frames: {xoff_frame_count}")

        # Step 1: Clear all counters (platform-aware)
        st.log("Step 1: Clearing all counters...")
        clear_all_counters_platform_aware(dut1)
        clear_all_counters_platform_aware(dut2)

        # Step 2: Set headroom to 0 on DUT2 port-c (b2b ingress)
        st.log(f"Step 2: Setting headroom to 0 on DUT2 port-c ({port_c})...")
        with qos_utils.HeadroomZeroContext(dut2, port_c, TC) as ctx:
            st.log(f"Original xoff value: {ctx.original_xoff}")
            result['counters']['original_xoff'] = ctx.original_xoff
            result['counters']['profile_name'] = ctx.profile_name

            # Step 3: Create data stream
            st.log("Step 3: Creating data stream...")
            data_stream = create_data_stream(tg, None, frame_size, DATA_RATE_PERCENT)
            if not data_stream:
                result['error'] = "Failed to create data stream"
                return result

            # Step 4: Apply and start data traffic
            st.log("Step 4: Starting data traffic...")
            tg.tg_traffic_control(action='apply')
            st.wait(2)
            tg.tg_traffic_control(action='run', stream_handle=data_stream['stream_id'])
            st.wait(1)  # Let traffic stabilize

            # Step 5: Run measurement iterations
            st.log(f"Step 5: Running {iterations} measurement iterations...")
            for i in range(iterations):
                st.banner(f"Iteration {i + 1}/{iterations}")

                # Capture baseline counters on DUT2 port-c (drops, pfc_tx) and DUT1 port-b (pfc_rx)
                # Also capture DUT2 port-d for PFC RX (receives XOFF from TGEN2)
                # and DUT1 port-a for PFC TX (back-propagated PFC toward TGEN1).
                baseline_dut2_c = qos_utils.capture_headroom_counters(dut2, port_c, TC)
                baseline_dut1_b = qos_utils.capture_headroom_counters(dut1, port_b, TC)
                baseline_dut2_d = qos_utils.capture_headroom_counters(dut2, port_d, TC)
                baseline_dut1_a = qos_utils.capture_headroom_counters(dut1, port_a, TC)
                st.log(f"  Baseline DUT2 port-c pg_drop: {baseline_dut2_c['pg_drop']}, pfc_tx: {baseline_dut2_c['pfc_tx']}")
                st.log(f"  Baseline DUT1 port-b pfc_rx: {baseline_dut1_b['pfc_rx']}")
                st.log(f"  Baseline DUT2 port-d pfc_rx: {baseline_dut2_d['pfc_rx']}")
                st.log(f"  Baseline DUT1 port-a pfc_tx: {baseline_dut1_a['pfc_tx']}")

                # Create XOFF stream with calculated rate for port-d speed
                xoff_stream_id = create_xoff_burst_stream(
                    vars.tgen_ports['tgen2'],
                    vars.dut2_tgen_mac,
                    xoff_frame_count,
                    xoff_rate_fps,
                )

                tg.tg_traffic_control(action='apply')
                st.wait(1)

                # Restart data stream after apply (apply stops all traffic)
                tg.tg_traffic_control(action='run', stream_handle=data_stream['stream_id'])
                st.wait(0.5)

                # Start XOFF stream
                st.log(f"  Starting XOFF stream: {xoff_frame_count} frames @ {xoff_rate_fps} fps...")
                tg.tg_traffic_control(action='run', stream_handle=xoff_stream_id)

                # Wait for XOFF stream to complete (1 second + margin)
                st.wait(XOFF_DURATION_SEC + 0.5)

                # Stop XOFF stream
                try:
                    tg.tg_traffic_control(action='stop', stream_handle=xoff_stream_id)
                except Exception:
                    pass

                # Capture counters after XOFF burst
                after_dut2_c = qos_utils.capture_headroom_counters(dut2, port_c, TC)
                after_dut1_b = qos_utils.capture_headroom_counters(dut1, port_b, TC)
                after_dut2_d = qos_utils.capture_headroom_counters(dut2, port_d, TC)
                st.log(f"  After DUT2 port-c pg_drop: {after_dut2_c['pg_drop']}, pfc_tx: {after_dut2_c['pfc_tx']}")
                st.log(f"  After DUT1 port-b pfc_rx: {after_dut1_b['pfc_rx']}")
                st.log(f"  After DUT2 port-d pfc_rx: {after_dut2_d['pfc_rx']}")

                # Capture queue watermarks for port-d and port-b
                queue_wm_port_d = qos_utils.get_queue_watermark_for_port(dut2, port_d, TC)
                queue_wm_port_b = qos_utils.get_queue_watermark_for_port(dut1, port_b, TC)
                st.log(f"  Queue watermarks: port-d ({port_d})={queue_wm_port_d}, port-b ({port_b})={queue_wm_port_b}")

                # Capture queue drops for port-d and port-b
                queue_drops_port_d = qos_utils.get_queue_drops_for_port(dut2, port_d, TC)
                queue_drops_port_b = qos_utils.get_queue_drops_for_port(dut1, port_b, TC)
                st.log(f"  Queue drops: port-d ({port_d})={queue_drops_port_d}, port-b ({port_b})={queue_drops_port_b}")

                # Capture PG watermarks for port-a (DUT1 ingress) and port-c (DUT2 ingress, xoff=0).
                # Also re-read port-a so we get the pfc_tx delta back toward TGEN1.
                after_dut1_a = qos_utils.capture_headroom_counters(dut1, port_a, TC)
                pg_wm_port_a = after_dut1_a['pg_watermark']
                pg_wm_port_c = after_dut2_c['pg_watermark']  # Already captured above
                st.log(f"  PG watermarks: port-a ({port_a})={pg_wm_port_a}, port-c ({port_c})={pg_wm_port_c}")

                # PFC TX delta on port-a (DUT1 TGEN-facing). Non-zero means
                # the backpressure chain (DUT2 PFC -> DUT1 RX -> DUT1 PG fill
                # -> DUT1 PFC TX upstream) actually completed end-to-end.
                pfc_tx_port_a_delta = after_dut1_a['pfc_tx'] - baseline_dut1_a['pfc_tx']
                st.log(f"  PFC TX delta on port-a ({port_a}): {pfc_tx_port_a_delta} frames")

                # Calculate deltas
                pg_drop_delta = after_dut2_c['pg_drop'] - baseline_dut2_c['pg_drop']
                pfc_tx_delta = after_dut2_c['pfc_tx'] - baseline_dut2_c['pfc_tx']
                pfc_rx_delta = after_dut1_b['pfc_rx'] - baseline_dut1_b['pfc_rx']
                pfc_rx_port_d_delta = after_dut2_d['pfc_rx'] - baseline_dut2_d['pfc_rx']

                result['drops_per_iteration'].append(pg_drop_delta)
                result['pfc_tx_per_iteration'].append(pfc_tx_delta)
                result['pfc_rx_per_iteration'].append(pfc_rx_delta)
                result['queue_wm_port_d_per_iteration'].append(queue_wm_port_d)
                result['queue_wm_port_b_per_iteration'].append(queue_wm_port_b)
                result['queue_drops_port_d_per_iteration'].append(queue_drops_port_d)
                result['queue_drops_port_b_per_iteration'].append(queue_drops_port_b)
                result['pg_wm_port_a_per_iteration'].append(pg_wm_port_a)
                result['pg_wm_port_c_per_iteration'].append(pg_wm_port_c)
                result['pfc_tx_port_a_per_iteration'].append(pfc_tx_port_a_delta)
                result['pfc_rx_port_d_per_iteration'].append(pfc_rx_port_d_delta)

                st.log(f"  Deltas: pg_drop={pg_drop_delta}, pfc_tx={pfc_tx_delta}, pfc_rx={pfc_rx_delta}, pfc_rx_port_d={pfc_rx_port_d_delta}")
                st.log(f"  Queue drops: port-d={queue_drops_port_d}, port-b={queue_drops_port_b}")
                st.log(f"  PG watermarks: port-a={pg_wm_port_a}, port-c={pg_wm_port_c}")

                # CRITICAL CHECK: Queue tail drops indicate backpressure is not propagating
                # If we have queue tail drops but no PG drops, it means:
                # - Egress queue is overflowing (tail drops) but
                # - Ingress PG is NOT overflowing (no PG drops, no PFC)
                # This is a misconfiguration - the backpressure should reach ingress PG
                if queue_drops_port_d > 0 or queue_drops_port_b > 0:
                    st.error("=" * 70)
                    st.error("QUEUE TAIL DROPS DETECTED - Backpressure not propagating!")
                    st.error(f"  queue_drops_port_d ({port_d}): {queue_drops_port_d}")
                    st.error(f"  queue_drops_port_b ({port_b}): {queue_drops_port_b}")
                    st.error(f"  pg_drop on port-c: {pg_drop_delta}")
                    st.error(f"  pfc_rx on port-d:  {pfc_rx_port_d_delta}")
                    st.error("=" * 70)
                    st.error("Queue tail drops indicate egress congestion is NOT being")
                    st.error("communicated back to ingress via PFC. Check:")
                    st.error("  1. PFC is enabled on all ports in the path")
                    st.error("  2. TGEN2 is actually responding to XOFF frames")
                    st.error("  3. TGEN2 is sending XOFF frames (check pfc_rx_port_d)")
                    st.error("  4. Queue depth thresholds are correctly configured")
                    result['error'] = f"Queue tail drops detected: port-d={queue_drops_port_d}, port-b={queue_drops_port_b}"
                    # Don't fail immediately - collect all iterations for debugging
                    # pytest.fail("Queue tail drops indicate misconfiguration")

                # CRITICAL CHECK: If we have headroom drops, we MUST have generated PFC
                if pg_drop_delta > 0 and pfc_tx_delta == 0:
                    st.error("=" * 70)
                    st.error("UNEXPECTED BEHAVIOR: pg_drop > 0 but pfc_tx == 0")
                    st.error(f"  pg_drop_delta = {pg_drop_delta} bytes")
                    st.error(f"  pfc_tx_delta  = {pfc_tx_delta} frames")
                    st.error(f"  pfc_rx_delta  = {pfc_rx_delta} frames (DUT1 port-b)")
                    st.error("=" * 70)
                    st.error("If headroom drops occurred, PFC XOFF should have been generated.")
                    st.error("Collecting debug information...")
                    
                    # Collect debug info from DUT2 port-c (where xoff=0 is set)
                    debug_info_dut2_c = qos_utils.collect_pfc_debug_info(dut2, port_c, TC)
                    result['debug_info_dut2_port_c'] = debug_info_dut2_c
                    
                    # Also collect from DUT1 port-b for comparison
                    debug_info_dut1_b = qos_utils.collect_pfc_debug_info(dut1, port_b, TC)
                    result['debug_info_dut1_port_b'] = debug_info_dut1_b
                    
                    # Also check DUT2 port-d (TGEN port receiving XOFF)
                    debug_info_dut2_d = qos_utils.collect_pfc_debug_info(dut2, port_d, TC)
                    result['debug_info_dut2_port_d'] = debug_info_dut2_d
                    
                    # Stop traffic before failing
                    try:
                        tg.tg_traffic_control(action='stop', stream_handle=data_stream['stream_id'])
                    except Exception:
                        pass
                    #import pdb; pdb.set_trace()
                    
                    result['error'] = (f"PFC not generated despite headroom drops: "
                                       f"pg_drop={pg_drop_delta}, pfc_tx={pfc_tx_delta}")
                    result['passed'] = False
                    return result

                # Cleanup XOFF stream
                try:
                    tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
                except Exception as e:
                    st.log(f"  Warning: Could not remove XOFF stream: {e}")
                xoff_stream_id = None

                st.wait(0.5)  # Brief pause between iterations

            # Step 6: Stop data traffic
            st.log("Step 6: Stopping data traffic...")
            tg.tg_traffic_control(action='stop', stream_handle=data_stream['stream_id'])
            st.wait(1)

            # Step 7: Capture final counters and buffer pool watermarks
            st.log("Step 7: Capturing final counters and buffer pool watermarks...")
            final_dut1_b = qos_utils.capture_headroom_counters(dut1, port_b, TC)
            final_dut2_c = qos_utils.capture_headroom_counters(dut2, port_c, TC)
            result['counters']['final_dut1_port_b'] = final_dut1_b
            result['counters']['final_dut2_port_c'] = final_dut2_c

        # Context manager auto-restores xoff here

        # Step 8: Compute results
        st.log("Step 8: Computing results...")
        result['pg_drops_total'] = sum(result['drops_per_iteration'])
        result['pfc_tx_total'] = sum(result['pfc_tx_per_iteration'])
        result['pfc_rx_total'] = sum(result['pfc_rx_per_iteration'])

        # Headroom = (pg_drop_packets / pfc_tx_count) * frame_size
        # pg_drops is packet count, convert to bytes using frame_size
        if result['pfc_tx_total'] > 0:
            drops_per_pfc = result['pg_drops_total'] / result['pfc_tx_total']
            result['headroom_bytes_measured'] = int(drops_per_pfc * result['frame_size'])
            st.log(f"Headroom calculation: ({result['pg_drops_total']} packets / "
                   f"{result['pfc_tx_total']} pfc_tx) * {result['frame_size']}B = "
                   f"{result['headroom_bytes_measured']} bytes")
        else:
            st.warn("No PFC TX generated on DUT2 port-c, cannot calculate headroom")
            result['headroom_bytes_measured'] = 0

        # A valid measurement requires BOTH non-zero PFC TX (proving
        # backpressure was generated) AND non-zero PG drops (proving the
        # headroom-zero path was actually exercised). Any other combination
        # is either a non-forwarding link, an XOFF stream that never fired,
        # or PFC suppressing all overflow - none of which let us compute
        # the real headroom demand. Treat them as FAIL so they don't masquerade
        # as PASS in the summary table.
        if result['pfc_tx_total'] == 0:
            result['passed'] = False
            result['error'] = ("No PFC TX seen on DUT2 port-c; b2b link or "
                               "XOFF stimulus did not produce backpressure.")
            st.error(result['error'])
        elif result['pg_drops_total'] == 0:
            result['passed'] = False
            result['error'] = (f"PFC TX={result['pfc_tx_total']} but zero PG "
                               f"drops; xoff=0/dynamic_th=-7 likely throttled "
                               f"traffic before PG could overflow. Increase "
                               f"data rate or XOFF window.")
            st.error(result['error'])
        else:
            result['passed'] = True

    except Exception as e:
        st.error(f"Headroom measurement failed: {e}")
        import traceback
        st.log(traceback.format_exc())
        result['error'] = str(e)

        # Cleanup on error
        if xoff_stream_id:
            try:
                tg.tg_traffic_control(action='stop', stream_handle=xoff_stream_id)
                tg.tg_traffic_config(mode='remove', stream_id=xoff_stream_id)
            except Exception:
                pass

        if data_stream:
            try:
                tg.tg_traffic_control(action='stop',
                                      stream_handle=data_stream['stream_id'])
            except Exception:
                pass

    return result


def print_detailed_results(result):
    """
    Print detailed results for a single measurement.

    Args:
        result: Result dictionary from run_headroom_measurement()
    """
    st.banner(f"=== Speed: {result['speed_gbps']}G, Frame: {result['frame_size']}B ===")

    # Print topology diagram
    port_a = result.get('port_a', 'port-a')
    port_b = result.get('port_b', 'port-b')
    port_c = result.get('port_c', 'port-c')
    port_d = result.get('port_d', 'port-d')
    dut1 = result.get('dut1', 'DUT1')
    dut2 = result.get('dut2', 'DUT2')

    st.log("")
    st.log("TOPOLOGY:")
    st.log(f"  TGEN1 --> [{port_a}]{dut1}[{port_b}] --> [{port_c}]{dut2}[{port_d}] <--XOFF-- TGEN2")
    st.log(f"            (port-a)   (port-b)      (port-c)   (port-d)")
    st.log("")

    # Determine config label based on platform (Gamut/n9164e sets xoff=0, size=xon)
    is_gamut = result.get('platform', '') == 'n9164e'
    xoff_label = "xoff=0, size=xon" if is_gamut else "xoff=0"

    # Per-iteration breakdown with DUT/port info
    st.log("--- Per Iteration ---")
    for i in range(len(result.get('drops_per_iteration', []))):
        pg_drop = result['drops_per_iteration'][i]
        pfc_rx = result['pfc_rx_per_iteration'][i] if i < len(result.get('pfc_rx_per_iteration', [])) else 'N/A'
        pfc_tx = result['pfc_tx_per_iteration'][i] if i < len(result.get('pfc_tx_per_iteration', [])) else 'N/A'
        qwm_d = result['queue_wm_port_d_per_iteration'][i] if i < len(result.get('queue_wm_port_d_per_iteration', [])) else 'N/A'
        qwm_b = result['queue_wm_port_b_per_iteration'][i] if i < len(result.get('queue_wm_port_b_per_iteration', [])) else 'N/A'
        qdrops_d = result['queue_drops_port_d_per_iteration'][i] if i < len(result.get('queue_drops_port_d_per_iteration', [])) else 'N/A'
        qdrops_b = result['queue_drops_port_b_per_iteration'][i] if i < len(result.get('queue_drops_port_b_per_iteration', [])) else 'N/A'
        pg_wm_a = result['pg_wm_port_a_per_iteration'][i] if i < len(result.get('pg_wm_port_a_per_iteration', [])) else 'N/A'
        pg_wm_c = result['pg_wm_port_c_per_iteration'][i] if i < len(result.get('pg_wm_port_c_per_iteration', [])) else 'N/A'
        pfc_rx_d = result['pfc_rx_port_d_per_iteration'][i] if i < len(result.get('pfc_rx_port_d_per_iteration', [])) else 'N/A'
        pfc_tx_a = result['pfc_tx_port_a_per_iteration'][i] if i < len(result.get('pfc_tx_port_a_per_iteration', [])) else 'N/A'

        st.log(f"Iteration {i + 1}:")
        st.log(f"  {dut1} (port-a={port_a}):")
        st.log(f"    pfc_tx: {pfc_tx_a}, pg_watermark: {pg_wm_a}")
        st.log(f"  {dut1} (port-b={port_b}):")
        st.log(f"    pfc_rx: {pfc_rx}, queue_wm: {qwm_b}, queue_drops: {qdrops_b}")
        st.log(f"  {dut2} (port-c={port_c}) [{xoff_label}]:")
        st.log(f"    pg_drop: {pg_drop}, pfc_tx: {pfc_tx}, pg_watermark: {pg_wm_c}")
        st.log(f"  {dut2} (port-d={port_d}):")
        st.log(f"    pfc_rx: {pfc_rx_d}, queue_wm: {qwm_d}, queue_drops: {qdrops_d}")
        st.log("")

    # Totals
    st.log("--- Totals ---")
    st.log(f"PG Drops Total (TC{TC}) on {dut2} port-c: {result['pg_drops_total']} bytes")
    st.log(f"PFC RX Total on {dut1} port-b:           {result.get('pfc_rx_total', 'N/A')} frames")
    st.log(f"PFC TX Total on {dut2} port-c:           {result.get('pfc_tx_total', 'N/A')} frames")
    pfc_rx_d_total = sum(result.get('pfc_rx_port_d_per_iteration', []))
    st.log(f"PFC RX Total on {dut2} port-d:           {pfc_rx_d_total} frames")
    pfc_tx_a_total = sum(result.get('pfc_tx_port_a_per_iteration', []))
    st.log(f"PFC TX Total on {dut1} port-a:           {pfc_tx_a_total} frames")

    # Calculated headroom
    st.log("--- Calculated Headroom ---")
    st.log(f"Port-d Speed:                   {result.get('port_d_speed', 'N/A')}G")
    st.log(f"XOFF Rate:                      {result.get('xoff_rate_fps', 'N/A')} fps (fixed)")
    st.log(f"XOFF Duration:                  {result.get('xoff_duration_sec', XOFF_DURATION_SEC)} sec")
    st.log(f"XOFF Frames Sent:               {result.get('xoff_frame_count', 'N/A')}")
    st.log(f"Headroom = (drops/pfc_tx)*frame: {result['headroom_bytes_measured']} bytes")

    # Buffer pool watermarks
    st.log("--- Buffer Pool Watermarks ---")
    counters = result.get('counters', {})
    if 'final_dut1_port_b' in counters:
        dut1_wm = counters['final_dut1_port_b'].get('buffer_pool_watermark', {})
        st.log(f"{dut1} buffer pool watermarks:    {dut1_wm}")
    if 'final_dut2_port_c' in counters:
        dut2_wm = counters['final_dut2_port_c'].get('buffer_pool_watermark', {})
        st.log(f"{dut2} buffer pool watermarks:    {dut2_wm}")

    st.log(f"Platform:                       {result['platform']}")

    if result.get('error'):
        st.log(f"ERROR: {result['error']}")


def print_summary_table(all_results):
    """
    Print summary table for multiple measurements.

    Args:
        all_results: List of result dictionaries
    """
    st.banner("=== HEADROOM SIZING SUMMARY ===")

    # Header
    header = ("| Platform   | Speed | Frame | PG Drops | PFC TX | "
              "Headroom (bytes) |")
    separator = ("|------------|-------|-------|----------|--------|"
                 "------------------|")

    st.log(header)
    st.log(separator)

    for r in all_results:
        status = "PASS" if r['passed'] else "FAIL"
        row = (f"| {r['platform']:<10} | {r['speed_gbps']:>4}G | "
               f"{r['frame_size']:>5} | "
               f"{r['pg_drops_total']:>8} | {r.get('pfc_tx_total', 0):>6} | "
               f"{r['headroom_bytes_measured']:>16} | "
               f"{status}")
        st.log(row)


# ---------------------------------------------------------------------------
# Test Functions
# ---------------------------------------------------------------------------
def test_headroom_sizing_single_speed():
    """
    Quick headroom sizing test using current port speed.

    Uses default frame size and 2 iterations.
    No breakout changes - uses existing port configuration.
    """
    st.banner("TEST: test_headroom_sizing_single_speed")
    st.log(f"Platform: {vars.platform1}")
    st.log(f"Current B2B speed: {vars.b2b_speed}G")

    # Run measurement with current speed
    result = run_headroom_measurement(
        speed=vars.b2b_speed,
        frame_size=DEFAULT_FRAME_SIZE,
        iterations=DEFAULT_ITERATIONS,
    )

    # Print detailed results
    print_detailed_results(result)

    # Report result
    if result['passed']:
        st.banner("SUMMARY: TEST PASSED: test_headroom_sizing_single_speed")
        st.log(f"Measured headroom: {result['headroom_bytes_measured']} bytes "
               f"(pg_drops={result['pg_drops_total']} pkts / pfc_tx={result['pfc_tx_total']}) * "
               f"frame={result['frame_size']}B")
        st.report_pass(
            "test_case_passed",
            f"Headroom measurement completed: {result['headroom_bytes_measured']} bytes"
        )
    else:
        st.banner("SUMMARY: TEST FAILED: test_headroom_sizing_single_speed")
        st.report_fail('msg', f"Headroom measurement failed: {result.get('error')}")


def test_headroom_sizing_sweep():
    """
    Headroom sizing test sweeping multiple frame sizes.

    For each frame size, measures headroom with default iterations.
    Prints per-speed details and final summary table.

    Note: Speed breakout changes are not implemented in this version.
    To test different speeds, manually configure breakout before running.
    """
    st.banner("TEST: test_headroom_sizing_sweep")
    st.log(f"Platform: {vars.platform1}")
    st.log(f"Current B2B speed: {vars.b2b_speed}G")

    # Frame sizes to test
    frame_sizes = [64, 512, 1350, 4096, 9000]

    all_results = []

    for frame_size in frame_sizes:
        st.banner(f"Testing frame size: {frame_size}B")

        result = run_headroom_measurement(
            speed=vars.b2b_speed,
            frame_size=frame_size,
            iterations=DEFAULT_ITERATIONS,
        )

        all_results.append(result)
        print_detailed_results(result)

        # Brief pause between tests
        st.wait(2)

    # Print summary table
    print_summary_table(all_results)

    # Determine overall pass/fail
    all_passed = all(r['passed'] for r in all_results)

    if all_passed:
        st.banner("SUMMARY: TEST PASSED: test_headroom_sizing_sweep")
        st.report_pass(
            "test_case_passed",
            f"Headroom sweep completed for {len(frame_sizes)} frame sizes"
        )
    else:
        failed_count = sum(1 for r in all_results if not r['passed'])
        st.banner("SUMMARY: TEST FAILED: test_headroom_sizing_sweep")
        st.report_fail(
            'msg',
            f"Headroom sweep had {failed_count}/{len(frame_sizes)} failures"
        )


def test_headroom_sizing_extended():
    """
    Extended headroom sizing test with more iterations for accuracy.

    Uses 5 iterations per measurement for better statistical confidence.
    Single frame size (default 1350B).
    """
    st.banner("TEST: test_headroom_sizing_extended")
    st.log(f"Platform: {vars.platform1}")
    st.log(f"Current B2B speed: {vars.b2b_speed}G")

    EXTENDED_ITERATIONS = 5

    result = run_headroom_measurement(
        speed=vars.b2b_speed,
        frame_size=DEFAULT_FRAME_SIZE,
        iterations=EXTENDED_ITERATIONS,
    )

    print_detailed_results(result)

    # Calculate standard deviation for drops
    if len(result['drops_per_iteration']) > 1:
        import statistics
        try:
            stddev = statistics.stdev(result['drops_per_iteration'])
            st.log(f"Drops Std Dev: {stddev:.2f}")
        except Exception:
            pass

    if result['passed']:
        st.banner("SUMMARY: TEST PASSED: test_headroom_sizing_extended")
        st.report_pass(
            "test_case_passed",
            f"Extended headroom measurement: {result['headroom_bytes_measured']} bytes"
        )
    else:
        st.banner("SUMMARY: TEST FAILED: test_headroom_sizing_extended")
        st.report_fail('msg', f"Extended measurement failed: {result.get('error')}")


def test_headroom_sizing_speed_sweep():
    """
    Headroom sizing test sweeping multiple port speeds via breakout.

    For each speed in DEFAULT_SPEED_SWEEP:
    1. Configure breakout on b2b ports (DUT1 and DUT2)
    2. Configure IP on first breakout port
    3. Run headroom measurement
    4. Restore original breakout

    Note: This test modifies port breakout configuration.
    """
    st.banner("TEST: test_headroom_sizing_speed_sweep")
    st.log(f"Platform: {vars.platform1}")
    st.log(f"Original B2B speed: {vars.b2b_speed}G")

    all_results = []
    speeds_to_test = DEFAULT_SPEED_SWEEP

    # Save original breakout modes (only for b2b ports - TGEN ports stay unchanged)
    original_mode_dut1_b2b = get_current_breakout_mode(vars.dut1, vars.b2b_link['dut1_port'])
    original_mode_dut2_b2b = get_current_breakout_mode(vars.dut2, vars.b2b_link['dut2_port'])
    original_port_dut1_b2b = vars.b2b_link['dut1_port']
    original_port_dut2_b2b = vars.b2b_link['dut2_port']

    st.log(f"Original breakout modes:")
    st.log(f"  DUT1 B2B port: {original_mode_dut1_b2b}")
    st.log(f"  DUT2 B2B port: {original_mode_dut2_b2b}")
    st.log(f"  TGEN ports: kept unchanged (DUT1: {vars.dut_tgen_ports['dut1_tgen']}, DUT2: {vars.dut_tgen_ports['dut2_tgen']})")

    try:
        for target_speed in speeds_to_test:
            st.banner(f"=== Testing speed: {target_speed}G ===")

            if target_speed not in SPEED_BREAKOUT_MAP:
                st.warn(f"Speed {target_speed}G not in SPEED_BREAKOUT_MAP, skipping")
                continue

            # Pre-breakout housekeeping (mirrors test_v4_pfc_brkout_b2b.py):
            #   a) Stop and reset any TGEN traffic. Leaving traffic running
            #      while CONFIG_DB is being rewritten by 'config interface
            #      breakout' / 'config qos reload' leads to spurious drops and
            #      buffer-config inconsistencies in subsequent iterations.
            #   b) Tear down any IP currently on the (about-to-change) b2b ports
            #      so the breakout cli is not blocked by 'Cannot remove the last
            #      IP entry of interface ... A static ip route is still bound
            #      to the RIF.' (seen in laguna_hr_speeds_1F_4.log).
            try:
                vars.tg.tg_traffic_control(action='stop')
            except Exception as e:
                st.log(f"  pre-breakout traffic stop warning: {e}")
            try:
                vars.tg.tg_traffic_control(action='reset')
            except Exception as e:
                st.log(f"  pre-breakout traffic reset warning: {e}")
            _cleanup_b2b_ips()
            st.wait(1)

            # Configure breakout on both DUTs for b2b link.
            # configure_breakout_for_speed() runs the
            # qos clear -> breakout -> qos reload -> admin-up recipe and
            # returns the FIRST broken-out subport name (e.g. Ethernet1_49_1),
            # which is the only subport this test exercises. It does NOT
            # wait for oper-up and does NOT refresh the ConfigDb cache
            # because oper-up needs the peer to also be configured.
            st.log(f"Configuring breakout for {target_speed}G on b2b ports...")

            success1, port1_b2b, _, post_list1 = configure_breakout_for_speed(
                vars.dut1, vars.b2b_link['dut1_port'], target_speed)
            success2, port2_b2b, _, post_list2 = configure_breakout_for_speed(
                vars.dut2, vars.b2b_link['dut2_port'], target_speed)

            if not (success1 and success2):
                st.error(f"Failed to configure breakout for {target_speed}G")
                continue

            # Now that BOTH ends are admin-up, wait for the link to come up
            # on both peers, then refresh the per-DUT ConfigDb cache so
            # subsequent BUFFER_PG / BUFFER_PROFILE / mmuconfig lookups
            # (HeadroomZeroContext) see the populated buffer-manager state.
            link_up = finalize_breakout_pair_and_load_cache(
                vars.dut1, post_list1, vars.dut2, post_list2, timeout=180)
            if not link_up:
                # Record an explicit FAIL for this speed and skip the
                # measurement. Running it on a non-forwarding link produces
                # zero drops / zero pfc_tx, which the summary logic would
                # otherwise report as PASS.
                err = (f"B2B link did not reach admin+oper up at "
                       f"{target_speed}G after 180s; skipping measurement.")
                st.error(err)
                all_results.append({
                    'platform': vars.platform1,
                    'speed_gbps': target_speed,
                    'frame_size': DEFAULT_FRAME_SIZE,
                    'pg_drops_total': 0,
                    'pfc_tx_total': 0,
                    'pfc_rx_total': 0,
                    'headroom_bytes_measured': 0,
                    'passed': False,
                    'error': err,
                })
                continue

            # Note: TGEN ports are NOT changed - they stay at original breakout
            # The test rate will be limited by min(tgen_speed, b2b_speed)

            # Update vars with new port names for b2b only. Everything
            # downstream (IP assignment, HeadroomZeroContext BUFFER_PG lookup,
            # counter capture) reads these so they must point at the new
            # broken-out subport (e.g. Ethernet1_49_1) rather than the parent.
            vars.b2b_link['dut1_port'] = port1_b2b
            vars.b2b_link['dut2_port'] = port2_b2b
            vars.b2b_speed = target_speed
            # Keep tgen_speed unchanged - it's the original TGEN port speed

            # Configure IPs on the new b2b subports. _configure_b2b_ips()
            # uses vars.b2b_link[...], which now references the broken-out
            # subport names set just above. The helper now returns False
            # when L3 reachability cannot be verified - we fail the
            # iteration in that case instead of generating garbage data.
            if not _configure_b2b_ips():
                err = (f"B2B ping {B2B_LINK_IPS['D3D4P1']} -> "
                       f"{B2B_LINK_IPS['D4D3P1']} failed at "
                       f"{target_speed}G; skipping measurement.")
                st.error(err)
                all_results.append({
                    'platform': vars.platform1,
                    'speed_gbps': target_speed,
                    'frame_size': DEFAULT_FRAME_SIZE,
                    'pg_drops_total': 0,
                    'pfc_tx_total': 0,
                    'pfc_rx_total': 0,
                    'headroom_bytes_measured': 0,
                    'passed': False,
                    'error': err,
                })
                _cleanup_b2b_ips()
                continue

            # Note: TGEN port IPs are unchanged since we didn't change TGEN breakout

            # Note: We skip init_qos_on_dut since it checks all TGEN ports in testbed
            # QoS is already initialized from module_setup

            st.wait(5)  # Let ports stabilize

            # Run measurement at this speed
            result = run_headroom_measurement(
                speed=target_speed,
                frame_size=DEFAULT_FRAME_SIZE,
                iterations=DEFAULT_ITERATIONS,
            )

            all_results.append(result)
            print_detailed_results(result)

            # Clean up b2b IPs before next speed
            _cleanup_b2b_ips()

            st.wait(2)

    finally:
        # Restore original breakout modes for b2b ports only. Same pattern
        # as the sweep body: restore both sides FIRST (admin-up only) so the
        # link partner is present, then wait for the link and reload caches.
        st.banner("Restoring original breakout configuration...")
        restore_list1 = restore_original_breakout(
            vars.dut1, vars.b2b_link['dut1_port'], original_mode_dut1_b2b)
        restore_list2 = restore_original_breakout(
            vars.dut2, vars.b2b_link['dut2_port'], original_mode_dut2_b2b)
        finalize_breakout_pair_and_load_cache(
            vars.dut1, restore_list1, vars.dut2, restore_list2, timeout=180)
        # Restore original port names
        vars.b2b_link['dut1_port'] = original_port_dut1_b2b
        vars.b2b_link['dut2_port'] = original_port_dut2_b2b

    # Print summary
    if all_results:
        print_summary_table(all_results)

    # Determine overall pass/fail
    all_passed = all(r['passed'] for r in all_results) if all_results else False

    if all_passed:
        st.banner("SUMMARY: TEST PASSED: test_headroom_sizing_speed_sweep")
        st.report_pass(
            "test_case_passed",
            f"Speed sweep completed for {len(all_results)} speeds"
        )
    else:
        failed_count = sum(1 for r in all_results if not r['passed'])
        st.banner("SUMMARY: TEST FAILED: test_headroom_sizing_speed_sweep")
        st.report_fail(
            'msg',
            f"Speed sweep had {failed_count}/{len(all_results)} failures"
        )


# ---------------------------------------------------------------------------
# Main entry point for standalone execution
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    # This allows running with pytest
    pytest.main([__file__, '-v', '-s'])
