"""
Common QoS test utilities for PFC / congestion tests.

Shared helpers used across test_pfc_vxlan.py, test_pfc_l2vni.py, and other
QoS test files in a 2-spine + 2-leaf CLOS topology.

Functions:
    Topology:
        get_nodes()                          - Node name to DUT object mapping
        shutdown_leaf_to_leaf_links()         - Shut D3D4/D4D3 direct links
        startup_leaf_to_leaf_links()          - Bring them back up
        get_leaf_to_leaf_interfaces()         - Get leaf-to-leaf interface names

    Pre-flight checks:
        verify_pfc_priority_on_interfaces()  - Check PFC enabled on target TC
        verify_link_states()                 - Verify expected UP/DOWN states
        dump_qos_maps()                      - Dump DSCP-to-TC / TC-to-Queue maps

    PFC counters:
        get_raw_pfc_counters()               - Run 'show pfc counters' once
        parse_pfc_counters_all()             - Parse PFC counters for N interfaces
        capture_pfc_counters()               - Capture PFC counters across DUTs
        print_pfc_counter_deltas()           - Print before/after PFC deltas

    Drop counters:
        get_drop_count()                     - Get TX/RX drop count for one interface
        capture_drop_counters()              - Capture drop counters across DUTs
        print_drop_counter_deltas()          - Print before/after drop deltas

    Traffic cleanup:
        remove_traffic_streams()             - Remove IXIA traffic configs

    Speed query:
        get_link_speeds()                    - Query actual interface speeds from DUTs
"""

from spytest import st
from tests.cisco.tortuga.common import tortuga_common_utils as common_util

# Module-level cache for nodes dict
_nodes_cache = None


def get_nodes():
    """
    Get node name to DUT object mapping for 2-spine + 2-leaf topology.
    Caches the result to avoid repeated testbed var lookups.

    Returns:
        dict: {'spine0': D1, 'spine1': D2, 'leaf0': D3, 'leaf1': D4}
    """
    global _nodes_cache
    if _nodes_cache is None:
        vars = st.get_testbed_vars()
        _nodes_cache = {
            'spine0': vars.D1,
            'spine1': vars.D2,
            'leaf0': vars.D3,
            'leaf1': vars.D4
        }
    return _nodes_cache


# ---------------------------------------------------------------------------
# Leaf-to-leaf link management
# ---------------------------------------------------------------------------

def shutdown_leaf_to_leaf_links(nodes):
    """
    Shutdown direct Leaf0<->Leaf1 links (D3D4P1/D4D3P1) if they exist.

    In some testbeds, Leaf0 and Leaf1 have a direct back-to-back link.
    If left up, traffic can bypass the spine entirely, defeating congestion
    tests that rely on spine-link oversubscription to trigger PFC.

    Args:
        nodes: Dict mapping node names to DUT objects
    """
    vars = st.get_testbed_vars()

    shut_count = 0
    for var_name, node_name in [('D3D4P1', 'leaf0'), ('D4D3P1', 'leaf1')]:
        if hasattr(vars, var_name):
            intf = getattr(vars, var_name)
            peer = 'Leaf1' if node_name == 'leaf0' else 'Leaf0'
            st.log(f"Shutting down {intf} on {node_name} (direct link to {peer})")
            st.config(nodes[node_name], f"sudo config interface shutdown {intf}")
            shut_count += 1

    if shut_count > 0:
        st.log(f"Shut {shut_count} leaf-to-leaf link(s)")
        st.wait(2)
    else:
        st.log("No leaf-to-leaf links found in testbed (D3D4P1/D4D3P1) - skipping")


def startup_leaf_to_leaf_links(nodes):
    """
    Bring back up direct Leaf0<->Leaf1 links (D3D4P1/D4D3P1) if they exist.

    Args:
        nodes: Dict mapping node names to DUT objects
    """
    vars = st.get_testbed_vars()

    for var_name, node_name in [('D3D4P1', 'leaf0'), ('D4D3P1', 'leaf1')]:
        if hasattr(vars, var_name):
            intf = getattr(vars, var_name)
            peer = 'Leaf1' if node_name == 'leaf0' else 'Leaf0'
            st.log(f"Starting up {intf} on {node_name} (direct link to {peer})")
            st.config(nodes[node_name], f"sudo config interface startup {intf}")

    st.wait(2)


def get_leaf_to_leaf_interfaces():
    """
    Return leaf-to-leaf interface names if they exist in the testbed.

    Returns:
        dict: {'leaf0': [intf_list], 'leaf1': [intf_list]}
              Empty lists if no leaf-to-leaf links exist.
    """
    vars = st.get_testbed_vars()

    result = {'leaf0': [], 'leaf1': []}
    if hasattr(vars, 'D3D4P1'):
        result['leaf0'].append(vars.D3D4P1)
    if hasattr(vars, 'D4D3P1'):
        result['leaf1'].append(vars.D4D3P1)
    return result


# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

def verify_pfc_priority_on_interfaces(nodes, interfaces_map, tc):
    """
    Pre-flight check: verify PFC is enabled on the target TC for all interfaces
    in the traffic path. Parses 'show pfc priority' output.

    Output format:
        Interface       Lossless priorities
        --------------  ---------------------
        Ethernet1_1     3,4
        Ethernet1_57    3,4

    Args:
        nodes: Dict mapping node names to DUT objects
        interfaces_map: Dict mapping node names to list of interfaces
        tc: Traffic class to check (e.g. 3)

    Returns:
        bool: True if all interfaces have PFC enabled on the target TC
    """
    st.banner(f"PRE-FLIGHT: Verifying PFC priority enabled on TC {tc} for all traffic-path interfaces")
    all_ok = True
    tc_str = str(tc)

    for node_name, interfaces in interfaces_map.items():
        if node_name not in nodes:
            continue
        dut = nodes[node_name]

        grep_pattern = '|'.join(interfaces)
        output = st.show(dut, f"show pfc priority | egrep '{grep_pattern}'", skip_tmpl=True)
        st.log(f"=== {node_name.upper()} show pfc priority (filtered) ===")
        st.log(output)

        for intf in interfaces:
            found = False
            for line in output.splitlines():
                if intf in line:
                    found = True
                    parts = line.split()
                    if len(parts) >= 2:
                        lossless_str = parts[1]
                        lossless_tcs = [x.strip() for x in lossless_str.split(',')]
                        if tc_str in lossless_tcs:
                            st.log(f"  {node_name} {intf}: lossless priorities = {lossless_str} (TC {tc} present - good)")
                        else:
                            st.error(f"  {node_name} {intf}: lossless priorities = {lossless_str} (TC {tc} NOT in list)")
                            all_ok = False
                    else:
                        st.error(f"  {node_name} {intf}: no lossless priorities found (line: {line.strip()})")
                        all_ok = False
                    break
            if not found:
                st.error(f"  {node_name} {intf}: NOT FOUND in 'show pfc priority' output")
                all_ok = False

    if all_ok:
        st.log("PRE-FLIGHT PASSED: PFC priority enabled on all traffic-path interfaces")
    else:
        st.error("PRE-FLIGHT FAILED: PFC priority NOT enabled on one or more interfaces")
    return all_ok


def verify_link_states(nodes, expected_up, expected_down):
    """
    Verify interface oper states match expectations after link shutdown.

    Args:
        nodes: Dict mapping node names to DUT objects
        expected_up: Dict {node_name: [interfaces that should be UP]}
        expected_down: Dict {node_name: [interfaces that should be DOWN]}

    Returns:
        bool: True if all states match expectations
    """
    st.banner("Verifying interface oper states after link shutdown")
    all_ok = True

    for node_name, interfaces in expected_up.items():
        if node_name not in nodes:
            continue
        for intf in interfaces:
            output = st.show(nodes[node_name], f"show interfaces status {intf}", skip_tmpl=True)
            if 'up' in output.lower():
                st.log(f"  {node_name} {intf}: UP (expected)")
            else:
                st.error(f"  {node_name} {intf}: NOT UP (expected UP) - output: {output.strip()[:200]}")
                all_ok = False

    for node_name, interfaces in expected_down.items():
        if node_name not in nodes:
            continue
        for intf in interfaces:
            output = st.show(nodes[node_name], f"show interfaces status {intf}", skip_tmpl=True)
            if 'down' in output.lower() or 'disabled' in output.lower():
                st.log(f"  {node_name} {intf}: DOWN (expected)")
            else:
                st.error(f"  {node_name} {intf}: NOT DOWN (expected DOWN) - output: {output.strip()[:200]}")
                all_ok = False

    if all_ok:
        st.log("All interface states match expectations")
    else:
        st.error("WARNING: Some interface states do not match expectations")
    return all_ok


def dump_qos_maps(nodes, node_names):
    """
    Dump QoS DSCP-to-TC and TC-to-queue maps on specified nodes.
    Useful to confirm the DSCP used by IXIA actually maps to TC 3.
    """
    st.banner("PRE-FLIGHT: Dumping QoS maps on traffic-path DUTs")
    for name in node_names:
        if name not in nodes:
            continue
        dut = nodes[name]
        st.log(f"=== {name.upper()} QoS Maps ===")
        st.show(dut, "show dscp-to-tc-map", skip_tmpl=True)
        st.show(dut, "show tc-to-queue-map", skip_tmpl=True)


# ---------------------------------------------------------------------------
# PFC counter capture and reporting
# ---------------------------------------------------------------------------

def get_raw_pfc_counters(dut):
    """
    Run 'show pfc counters' once and return the raw output.
    Uses st.config to avoid verbose auto-logging of full counter table.

    Returns:
        str: Raw output from 'show pfc counters'
    """
    return st.config(dut, "show pfc counters", skip_error_check=True)


def parse_pfc_counters_all(raw_output, interfaces, tc):
    """
    Parse PFC TX and RX counts for multiple interfaces from raw 'show pfc counters' output.
    Scans the raw output only ONCE to extract counters for all requested interfaces.

    Args:
        raw_output: Raw string output from 'show pfc counters'
        interfaces: List of interface names like ['Ethernet1_48', 'Ethernet1_57']
        tc: Traffic class (queue number) for PFC counters (0-7)

    Returns:
        dict: {interface: {'tx': tx_count, 'rx': rx_count}}
    """
    counters = {intf: {'tx': 0, 'rx': 0} for intf in interfaces}
    interfaces_set = set(interfaces)

    current_direction = None

    for line in raw_output.splitlines():
        if 'Port Rx' in line:
            current_direction = 'rx'
            continue
        elif 'Port Tx' in line:
            current_direction = 'tx'
            continue

        if current_direction is None:
            continue
        if line.strip().startswith('-') or not line.strip():
            continue

        tokens = line.split()
        if len(tokens) < tc + 2:
            continue

        intf_name = tokens[0]
        if intf_name not in interfaces_set:
            continue

        try:
            count = int(tokens[1 + tc].replace(',', ''))
            counters[intf_name][current_direction] = count
        except (ValueError, IndexError):
            continue

    return counters


def capture_pfc_counters(nodes, interfaces_map, tc):
    """
    Capture PFC TX and RX counters for specified interfaces on each node.
    Runs 'show pfc counters' only ONCE per DUT, then parses all interfaces in one pass.

    Args:
        nodes: Dictionary mapping node names to DUT objects
        interfaces_map: Dict mapping node names to list of interfaces
        tc: Traffic class for PFC counters

    Returns:
        dict: Nested dict {node: {interface: {'tx': val, 'rx': val}}}
    """
    counters = {}
    for node_name, interfaces in interfaces_map.items():
        if node_name not in nodes:
            continue
        raw_output = get_raw_pfc_counters(nodes[node_name])
        counters[node_name] = parse_pfc_counters_all(raw_output, interfaces, tc)

    return counters


def print_pfc_counter_deltas(before, after, label="PFC Counter Deltas"):
    """
    Calculate and print PFC TX and RX counter deltas between before and after snapshots.
    Only prints interfaces where there is a non-zero delta.
    """
    st.banner(label)
    has_deltas = False

    for node_name in sorted(after.keys()):
        node_deltas = []
        for intf in sorted(after[node_name].keys()):
            before_tx = before.get(node_name, {}).get(intf, {}).get('tx', 0)
            before_rx = before.get(node_name, {}).get(intf, {}).get('rx', 0)
            after_tx = after[node_name][intf]['tx']
            after_rx = after[node_name][intf]['rx']

            delta_tx = after_tx - before_tx
            delta_rx = after_rx - before_rx

            if delta_tx != 0 or delta_rx != 0:
                node_deltas.append({
                    'intf': intf,
                    'delta_tx': delta_tx,
                    'delta_rx': delta_rx,
                    'before_tx': before_tx,
                    'after_tx': after_tx,
                    'before_rx': before_rx,
                    'after_rx': after_rx
                })

        if node_deltas:
            has_deltas = True
            st.log(f"=== {node_name.upper()} ===")
            for d in node_deltas:
                parts = []
                if d['delta_tx'] != 0:
                    parts.append(f"TX {d['before_tx']} -> {d['after_tx']} (delta: +{d['delta_tx']})")
                if d['delta_rx'] != 0:
                    parts.append(f"RX {d['before_rx']} -> {d['after_rx']} (delta: +{d['delta_rx']})")
                st.log(f"  {d['intf']}: PFC {', '.join(parts)}")

    if not has_deltas:
        st.log("No PFC counter changes detected on any interface.")


# ---------------------------------------------------------------------------
# Drop counter capture and reporting
# ---------------------------------------------------------------------------

def get_drop_count(dut, interface_name, direction):
    """
    Get drop count for an interface in specified direction.

    Args:
        dut: DUT object to run command on
        interface_name: Interface name like 'Ethernet1_48'
        direction: 'tx' or 'rx'

    Returns:
        int: Drop count for the specified direction
    """
    result = st.show(dut, f"show int count -i {interface_name}", skip_tmpl=True)
    # Output format (note: RX_BPS/TX_BPS like "0.00 B/s" splits into 2 tokens):
    #          IFACE    STATE    RX_OK  RX_BPS    RX_UTIL  RX_ERR  RX_DRP  RX_OVR
    #                                                                TX_OK  TX_BPS    TX_UTIL  TX_ERR  TX_DRP  TX_OVR
    # After split(): 0=IFACE, 1=STATE, 2=RX_OK, 3=0.00, 4=B/s, 5=RX_UTIL,
    #                6=RX_ERR, 7=RX_DRP, 8=RX_OVR,
    #                9=TX_OK, 10=0.00, 11=B/s, 12=TX_UTIL, 13=TX_ERR, 14=TX_DRP, 15=TX_OVR
    lines = result.strip().splitlines()
    for line in lines:
        if interface_name in line:
            tokens = line.split()
            if direction.lower() == 'rx':
                return int(tokens[7].replace(',', ''))
            else:  # tx
                return int(tokens[14].replace(',', ''))
    return 0


def capture_drop_counters(nodes, interfaces_map):
    """
    Capture TX and RX drop counts for specified interfaces on each node.

    Args:
        nodes: Dictionary mapping node names to DUT objects
        interfaces_map: Dict mapping node names to list of interfaces

    Returns:
        dict: Nested dict {node: {interface: {'tx_drop': val, 'rx_drop': val}}}
    """
    counters = {}
    for node_name, interfaces in interfaces_map.items():
        if node_name not in nodes:
            continue
        counters[node_name] = {}
        for intf in interfaces:
            tx_drop = get_drop_count(nodes[node_name], intf, 'tx')
            rx_drop = get_drop_count(nodes[node_name], intf, 'rx')
            counters[node_name][intf] = {'tx_drop': tx_drop, 'rx_drop': rx_drop}
    return counters


def print_drop_counter_deltas(before, after, label="Drop Counter Deltas"):
    """
    Calculate and print drop counter deltas between before and after snapshots.
    Only prints interfaces where there is a non-zero delta.
    """
    st.banner(label)
    has_deltas = False

    for node_name in sorted(after.keys()):
        node_deltas = []
        for intf in sorted(after[node_name].keys()):
            before_tx = before.get(node_name, {}).get(intf, {}).get('tx_drop', 0)
            before_rx = before.get(node_name, {}).get(intf, {}).get('rx_drop', 0)
            after_tx = after[node_name][intf]['tx_drop']
            after_rx = after[node_name][intf]['rx_drop']

            delta_tx = after_tx - before_tx
            delta_rx = after_rx - before_rx

            if delta_tx != 0 or delta_rx != 0:
                node_deltas.append({
                    'intf': intf,
                    'delta_tx': delta_tx,
                    'delta_rx': delta_rx,
                    'before_tx': before_tx,
                    'after_tx': after_tx,
                    'before_rx': before_rx,
                    'after_rx': after_rx
                })

        if node_deltas:
            has_deltas = True
            st.log(f"=== {node_name.upper()} ===")
            for d in node_deltas:
                parts = []
                if d['delta_tx'] != 0:
                    parts.append(f"TX_DRP {d['before_tx']} -> {d['after_tx']} (delta: +{d['delta_tx']})")
                if d['delta_rx'] != 0:
                    parts.append(f"RX_DRP {d['before_rx']} -> {d['after_rx']} (delta: +{d['delta_rx']})")
                st.log(f"  {d['intf']}: {', '.join(parts)}")

    if not has_deltas:
        st.log("No drop counter changes detected on any interface.")


# ---------------------------------------------------------------------------
# Traffic cleanup
# ---------------------------------------------------------------------------

def remove_traffic_streams(streams_dict):
    """
    Remove traffic item configurations from IXIA.
    Properly cleans up traffic configs using tg_traffic_config(mode='remove').

    Args:
        streams_dict: Dictionary of traffic streams from traffic setup
    """
    if not streams_dict:
        return
    st.banner("Removing traffic streams from IXIA")
    for traffic_item, values in streams_dict.items():
        tg = values['tg_handle']
        stream_id = values['stream_id']
        st.log(f"Removing traffic config: {traffic_item} -> {stream_id}")
        tg.tg_traffic_config(mode='remove', stream_id=stream_id)


def get_link_speeds(nodes, interfaces_by_node):
    """
    Query actual interface speeds (in Gbps) from DUTs.

    Args:
        nodes: dict mapping node names to DUT objects
        interfaces_by_node: dict mapping node name to list of interface names
            e.g. {'leaf0': ['Ethernet1_1_1', 'Ethernet1_2_1'], 'spine0': ['Ethernet1_3_1']}

    Returns:
        dict: {node_name: {interface: speed_gbps}} e.g. {'leaf0': {'Ethernet1_1_1': 400}}
    """
    speeds = {}
    for node_name, intf_list in interfaces_by_node.items():
        dut = nodes[node_name]
        speeds[node_name] = {}
        for intf in intf_list:
            speed = common_util.get_if_speed(dut, intf)
            speeds[node_name][intf] = speed
            st.log(f"  {node_name} {intf} speed: {speed}G")
    return speeds


def format_speed(gbps):
    """Format a speed in Gbps to a human-readable string (e.g. 400G, 1.6Tbps)."""
    if gbps >= 1000:
        return f"{gbps / 1000:.1f}Tbps"
    return f"{gbps}G"
